-- Load modules
local sqlite3 = require("lsqlite3")

local DB_PATH = "/var/lib/knot-resolver/leases.db"
local TTL = 60

local M = {}
local db
local sql_fwd
local sql_rev

local function log_error(s)
	print(s)
end

local function log_debug(s)
	print(s)
end

-- Initializes the module
function M.init()
	-- Open the database
	db = sqlite3.open(DB_PATH, sqlite3.OPEN_READONLY)

	-- Fail if we cannot open the database
	if not db then
		log_error("leases: Failed to open " .. DB_PATH)
		return -1
	end

	-- Don't ever block
	db:exec("PRAGMA query_only = 1")

	-- Prepare the forward lookup query
	sql_fwd = db:prepare(
		"SELECT address FROM leases WHERE hostname = ?1 COLLATE NOCASE LIMIT 1"
	)

	-- Prepare the reverse lookup query
	sql_rev = db:prepare(
		"SELECT hostname FROM leases WHERE address = ?1 LIMIT 1"
	)
end

-- Cleans up the module
function M.deinit()
	-- Cleanup the statements
	if sql_fwd then
		sql_fwd:finalize()
	end
	if sql_rev then
		sql_rev:finalize()
	end

	-- Close the database
	if db then
		db:close()
	end
end

-- Parses an IPv4 address from the reverse pointer query name
local function address_from_reverse_pointer(qname)
	local d, c, b, a = qname:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)%.in%-addr%.arpa%.$")

	-- Return nil if we could not parse the name
	if not a or not b or not c or not d then
		return
	end

	-- Concatenate the address
	return string.format("%s.%s.%s.%s", a, b, c, d)
end

local function lookup_fwd(hostname)
	-- Reset the statement
	sql_fwd:reset()

	-- Bind the query name
	sql_fwd:bind_values(hostname)

	-- Execute the statement
	if sql_fwd:step() == sqlite3.ROW then
		local address = sql_fwd:get_value(0)

		-- Convert the address to wire format
		if address then
			return kres.str2ip(address)
		end
        end
end

local function lookup_rev(qname)
	-- Parse the address from the query name
	local address = address_from_reverse_pointer(qname)

	-- Fail if we could not parse the address
	if not address then
		return
	end

	-- Reset the statement
	sql_rev:reset()

	-- Bind the address
	sql_rev:bind_values(address)

	-- Execute the statement
	if sql_rev:step() == sqlite3.ROW then
		local hostname = sql_rev:get_value(0)

		-- Convert the hostname to wire format
		if hostname then
			return todname(hostname)
		end
	end
end

-- Function that will try to answer the query
function M.answer()
	return function(state, req)
		-- Fetch the current query
		local query = req:current()

		-- Fetch the query name
		local qname = kres.dname2str(query.sname)

		-- Fetch the query type
		local qtype = query.stype

		-- Log action
		log_debug(
			string.format("Called for %s (%d)", qname, qtype)
		)

		local answer = {}

		-- Is this a forward lookup?
		if qtype == kres.type.A then
			-- Perform a forward lookup
			local address = lookup_fwd(qname)

			if address then
				answer[qtype] = { rdata = address, ttl = TTL }
			end

		-- Or is this a reverse lookup?
		elseif qtype == kres.type.PTR then
			-- Perform a reverse lookup
			local hostname = lookup_rev(qname)

			if hostname then
				answer[qtype] = { rdata = hostname, ttl = TTL }
			end
		end

		-- If we have an answer, use the policy module to send it
		if answer then
			answer = policy.ANSWER(answer)

		-- Otherwise we send NXDOMAIN
		else
			answer = policy.DENY
		end

		-- Pass the state and request
		return answer(state, req)
	end
end

return M
