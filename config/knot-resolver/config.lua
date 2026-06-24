--[[###########################################################################
#                                                                             #
# IPFire.org - An Open Source Firewall                                        #
# Copyright (C) 2026 - IPFire Team	<info@ipfire.org>                         #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.	If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###########################################################################]]--

local config = {}

-- Load required Lua modules
local bit = require("bit")
local csv = require("csv")
local ffi = require("ffi")
local notify = require("cqueues.notify")

-- Get access to the C interface
local C = ffi.C

-- Helper function to load a key/value configuration file
function config.load_settings(path)
	local settings = {}

	-- Read the file line by line
	for line in io.lines(path) do
		-- Skip comment and empty lines
		if not line:match('^%s*#') and not line:match('^%s*$') then
			-- Split the line
			local k, v = line:match('^%s*([^=%s]+)%s*=%s*(.-)%s*$')

			-- Store the key/value pair
			if k then
				settings[k] = v
			end
		end
	end

	return settings
end

--- Helper function which will call a function if a given file has been changed
local function call_on_change(paths, callback)
	for i, path in ipairs(paths) do
		-- Split the path into parent directory and filename
		local dir, file = string.match(path, "(.*)/([^/]+)")

		-- If we could not split the path (e.g. because it doesn't contain a /)
		-- we will assume the file is in the current working directory
		if not dir and not file then
			dir = "."
			file = path
		end

		-- Create a new watcher for the directory
		local watcher = notify.opendir(dir)

		-- Wake up when the file has changed
		watcher:add(file, bit.bxor(notify.CREATE, notify.MODIFY))

		-- Register a function that will call the callback on any changes
		worker.coroutine(function()
			for _, name in watcher:changes() do
				callback()
			end
		end)
	end

	-- Call the callback immediately to initialize the configuration
	callback()
end

local function netmask_to_prefix(netmask)
	-- Return nil on empty input
	if not netmask then
		return
	end

	local prefix = 0

	-- Iterate through octets
	for octet in netmask:gmatch("(%d+)") do
		local n = tonumber(octet)

		-- Count bits in each octet
		while n > 0 do
			if n % 2 == 1 then
				prefix = prefix + 1
			end
			n = math.floor(n / 2)
		end
	end

	return prefix
end

local function check_ipv4_address(address)
	local a, b, c, d = address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")

	-- Return if we could not parse the address
	if not a or not b or not c or not d then
		return false
	end

	-- Convert the octets into numbers
	a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)

	-- Check if all octets are in range
	for _, octet in ipairs({a, b, c, d}) do
		if octet > 255 then
			return false
		end
	end

	return true
end

local function reverse_zones(address, netmask)
	local a, b, c, d = address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")

	-- Return if we could not parse the address
	if not a or not b or not c or not d then
		return
	end

	-- Convert the octets into numbers
	a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)

	-- Convert the netmask into prefix
	local prefix = netmask_to_prefix(netmask)
	if not prefix then
		return
	end

	-- Round to to the nearest /8, /16, /24 or /32
	local p = math.floor(prefix / 8) * 8

	-- Fail if we would be generating all /8 zones
	if not p then
		return
	end

	-- Determine how many zones we need
	local n = 2 ^ (p - prefix)

	local zones = {}

	-- Generate all zones
	for i = 0, n - 1 do
		local zone, oa, ob, oc, od = nil, a, b, c, d

		-- /8
		if p == 8 then
			oa = a + i
			zone = string.format("%s.in-addr.arpa.", oa)

		-- /16
		elseif p == 16 then
			ob = b + i
			zone = string.format("%s.%s.in-addr.arpa.", ob, oa)

		-- /24
		elseif p == 24 then
			oc = c + i
			zone = string.format("%s.%s.%s.in-addr.arpa.", oc, ob, oa)

		-- /32
		elseif p == 32 then
			od = d + i
			zone = string.format("%s.%s.%s.%s.in-addr.arpa.", od, oc, ob, oa)
		end

		-- Append the zone
		if zone then
			table.insert(zones, kres.str2dname(zone))
		end
	end

	return zones
end

-- Setup DNS Forwarders
function config.load_forwarders(settings)
	-- Fetch the transport protocol
	local proto = settings["PROTO"]

	-- Collect all forwarders
	local forwarders = {}

	-- Add provider-assigned servers?
	if settings["USE_ISP_NAMESERVERS"] == "on" and proto ~= "TLS" then
		for i, path in ipairs({ "/var/run/dns1", "/var/run/dns2" }) do
			local f = io.open(path)

			if f then
				for address in f:lines() do
					if address ~= "" then
						table.insert(forwarders, {address})
					end
				end
			end
		end
	end

	-- Open the file
	local f = csv.open("/var/ipfire/dns/servers", { separator = "," })

	-- Add manually configured servers
	for fields in f:lines() do
		local id, address, hostname, status, comment = unpack(fields)

		if status == "enabled" then
			if proto == "TLS" then
				table.insert(forwarders, {
					address, tls=true, hostname=hostname,
				})
			else
				table.insert(forwarders, {address})
			end
		end
	end

	-- Don't configure anything if we don't have any forwarders
	if #forwarders == 0 then
		return
	end

	-- Use TCP?
	local tcp = (settings["PROTO"] == "TCP")

	-- Apply the forwarding rule
	policy.rule_forward_add(".", { dnssec=true, auth=false, tcp=tcp }, forwarders)
end

-- Load any hosts
function config.load_hosts()
	local path = "/var/ipfire/main/hosts"

	-- Log action
	log_debug(ffi.C.LOG_GRP_HINT, string.format("Loading hosts from %s", path))

	-- Load /etc/hosts
	hints.add_hosts("/etc/hosts")

	-- Set the TTL to one minute
	hints.ttl(60)

	-- Open the file
	local f = csv.open(path, { separator = "," })

	for fields in f:lines() do
		local status, address, hostname, domainname, ptr = unpack(fields)

		-- Add the entry
		if status == "on" then
			local hint = ""

			if domainname then
				hint = string.format("%s.%s %s",
					hostname, domainname, address)
			else
				hint = string.format("%s %s",
					hostname, address)
			end

			-- Add the hint
			hints.set(hint)
		end
	end
end

local GOOGLE_TLDS = {
	"com",

	-- ccTLDs
	"ad", "ae", "al", "am", "as", "at", "az", "ba", "be", "bf", "bg", "bi", "bj",
	"bs", "bt", "by", "ca", "cat", "cd", "cf", "cg", "ch", "ci", "cl", "cm", "cn",
	"cv", "cz", "de", "dj", "dk", "dm", "dz", "ee", "es", "fi", "fm", "fr", "ga",
	"ge", "gg", "gl", "gm", "gr", "gy", "hn", "hr", "ht", "hu", "ie", "im", "iq",
	"is", "it", "je", "jo", "kg", "ki", "kz", "la", "li", "lk", "lt", "lu", "lv",
	"md", "me", "mg", "mk", "ml", "mn", "mu", "mv", "mw", "ne", "nl", "no", "nr",
	"nu", "pl", "pn", "ps", "pt", "ro", "rs", "ru", "rw", "sc", "se", "sh", "si",
	"sk", "sm", "sn", "so", "sr", "st", "td", "tg", "tl", "tm", "tn", "to", "tt",
	"vu", "ws",

	-- co.*
	"co.ao", "co.bw", "co.ck", "co.cr", "co.id", "co.il", "co.in", "co.jp", "co.ke",
	"co.kr", "co.ls", "co.ma", "co.mz", "co.nz", "co.th", "co.tz", "co.ug", "co.uk",
	"co.uz", "co.ve", "co.vi", "co.za", "co.zm", "co.zw",

	-- com.*
	"com.af", "com.ag", "com.ar", "com.au", "com.bd", "com.bh", "com.bn", "com.bo",
	"com.br", "com.bz", "com.co", "com.cu", "com.cy", "com.do", "com.ec", "com.eg",
	"com.et", "com.fj", "com.gh", "com.gi", "com.gt", "com.hk", "com.jm", "com.kh",
	"com.kw", "com.lb", "com.ly", "com.mm", "com.mt", "com.mx", "com.my", "com.na",
	"com.ng", "com.ni", "com.np", "com.om", "com.pa", "com.pe", "com.pg", "com.ph",
	"com.pk", "com.pr", "com.py", "com.qa", "com.sa", "com.sb", "com.sg", "com.sl",
	"com.sv", "com.tj", "com.tr", "com.tw", "com.ua", "com.uy", "com.vc", "com.vn"
}

-- Loads the Safe Search rules
function config.load_safesearch(settings)
	-- Check if Safe Search is enabled
	if settings["ENABLE_SAFE_SEARCH"] ~= "on" then
		return
	end

	local zone = {}

	-- Adds an entry to the zone
	local function add(sources, target)
		for i, source in ipairs(sources) do
			local rr = string.format("%s. CNAME %s.", source, target)

			table.insert(zone, rr)
		end
	end

	-- Enable Googe Safe Search
	for i, tld in ipairs(GOOGLE_TLDS) do
		local name = string.format("google.%s", tld)

		add({ name, "www." .. name}, "forcesafesearch.google.com")
	end

	-- Enable Bing Strict Search
	add({ "bing.com", "www.bing.com" }, "strict.bing.com")

	-- Enable DuckDuckGo Safe Search
	add({ "duckduckgo.com", "www.duckduckgo.com" }, "safe.duckduckgo.com")

	-- Enable Yandex Family Search
	add({ "yandex.com", "www.yandex.com" }, "familysearch.yandex.com")
	add({ "yandex.ru", "www.yandex.ru" }, "familysearch.yandex.ru")

	-- Enable YouTube Safe Search
	if settings["ENABLE_SAFE_SEARCH_YOUTUBE"] == "on" then
		add({ "youtube.com", "www.youtube.com" }, "restrictmoderate.youtube.com")
	end

	-- Create a new zone
	rrs = ffi.new("struct kr_rule_zonefile_config")
	rrs.ttl = C.KR_RULE_TTL_DEFAULT
	rrs.tags = 0
	rrs.nodata = true
	rrs.is_rpz = false
	rrs.input_str = table.concat(zone, "\n")
	rrs.opts = C.KR_RULE_OPTS_DEFAULT

	assert(C.kr_rule_zonefile(rrs) == 0)
end

-- Loads the Forwarding Rules
function config.load_forwarding()
	local path = "/var/ipfire/dnsforward/config"

	local f = csv.open(path, { separator = "," })

	for fields in f:lines() do
		local status, name, address, comment, no_dnssec = unpack(fields)

		if status == "on" then
			local addresses = {}
			local dnssec = true

			-- Split multiple addresses
			for a in address:gmatch("[^|]+") do
				if check_ipv4_address(a) then
					table.insert(addresses, { a })
				end
			end

			-- Use a stub resolver if we don't want DNSSEC
			if no_dnssec == "on" then
				dnssec = false
			end

			-- Apply the forwarding rule
			if #addresses > 0 then
				policy.rule_forward_add(name,
					{ dnssec=dnssec, auth=false }, addresses)
			end
		end
	end
end

function config.load_leases()
	-- Load DHCP settings
	local settings = config.load_settings("/var/ipfire/dhcp/settings")

	-- Load Ethernet settings
	local ethernet = config.load_settings("/var/ipfire/ethernet/settings")

	-- Skip this if DNS UPDATE is being used instead
	if settings["DNS_UPDATE_ENABLED"] == "on" then
		return
	end

	-- Load the leases module
	modules.load("leases")

	-- Enabled on GREEN?
	if settings["ENABLE_GREEN"] == "on" then
		policy.add(
			policy.suffix(leases.answer(), {
				todname(settings["DOMAIN_NAME_GREEN"])
			})
		)

		-- Fetch subnet
		local netaddr = ethernet["GREEN_NETADDRESS"]
		local netmask = ethernet["GREEN_NETMASK"]

		-- Reverse lookup
		policy.add(
			policy.suffix(leases.answer(), reverse_zones(netaddr, netmask))
		)
	end

	-- Enabled on BLUE?
	if settings["ENABLE_BLUE"] == "on" then
		policy.add(
			policy.suffix(leases.answer(), {
				todname(settings["DOMAIN_NAME_BLUE"])
			})
		)

		-- Fetch subnet
		local netaddr = ethernet["BLUE_NETADDRESS"]
		local netmask = ethernet["BLUE_NETMASK"]

		-- Reverse lookup
		policy.add(
			policy.suffix(leases.answer(), reverse_zones(netaddr, netmask))
		)
	end
end

local function get_zone(name)
	local settings = config.load_settings("/var/ipfire/ethernet/settings")

	-- Fetch net address & mask
	local netaddr = settings[name .. "_NETADDRESS"]
	local netmask = settings[name .. "_NETMASK"]

	-- Convert the netmask into prefix notation
	local prefix = netmask_to_prefix(netmask)

	if netaddr and prefix then
		return string.format("%s/%s", netaddr, prefix)
	end
end

local function add_tag(views, subnet, tag)
	if views[subnet] then
		table.insert(views[subnet], tag)
	else
		views[subnet] = { tag }
	end
end

function config.load_rpzs()
	local zones

	-- Open the configuration
	local f = csv.open("/var/ipfire/dns/dnsbl", { separator = "," })

	local views = {}

	for fields in f:lines() do
		local name, status, comment, enabled_zones, custom_acl = unpack(fields)

		if status == "on" then
			local path = string.format("/var/lib/knot-resolver/zones/%s.zone", name)

			-- Fix buggy Perl CSV generator
			if not enabled_zones then
				enabled_zones = ""
			end

			if not custom_acl then
				custom_acl = ""
			end

			-- Ensure the zone exists
			if io.open(path) then
				-- Make the tag
				local tag = name:match("^([^.]+)"):lower()

				-- Load a new zone file
				local rpz = ffi.new("struct kr_rule_zonefile_config")
				rpz.nodata = true
				rpz.is_rpz = true

				-- Load the zone from path
				rpz.filename = path

				-- Set a default TTL
				rpz.ttl = C.KR_RULE_TTL_DEFAULT
				rpz.tags = policy.get_tagset({tag,})

				-- opts are complicated
				rpz.opts = C.KR_RULE_OPTS_DEFAULT
				rpz.opts.score = 9

				-- Enable logging
				rpz.opts.log_level = 3 -- NOTICE
				rpz.opts.log_ip = true
				rpz.opts.log_name = true

				-- Load the file
				assert(C.kr_rule_zonefile(rpz) == 0)

				-- Apply zone ACLs
				if enabled_zones then
					for zone in enabled_zones:gmatch("[^|]+") do
						local subnet = get_zone(zone)

						if subnet then
							add_tag(views, subnet, tag)
						end
					end
				end

				-- Apply custom ACLs
				if custom_acl then
					for subnet in custom_acl:gmatch("[^|]+") do
						if subnet then
							add_tag(views, subnet, tag)
						end
					end
				end

				-- Load it globally if no ACLs have been defined
				if enabled_zones == "" and custom_acl == "" then
					add_tag(views, "0.0.0.0/0", tag)
				end
			end
		end
	end

	-- Apply views
	for subnet, tags in pairs(views) do
		assert(C.kr_view_insert_action(subnet, "",
			0, policy.COMBINE({ policy.TAGS_ASSIGN(tags) })) == 0)
	end
end

local __policy_pass = {}
local __policy_deny = {}

function config.load_rpz_workaround()
	call_on_change({ "/var/ipfire/dns/custom_domains" }, function()
		local names_pass = {}
		local names_deny = {}

		-- Clear any previous rules
		if __policy_pass then
			policy.del(__policy_pass.id)
			__policy_pass = {}
		end

		if __policy_deny then
			policy.del(__policy_deny.id)
			__policy_deny = {}
		end

		local f = csv.open("/var/ipfire/dns/custom_domains", { separator = "," })
		if f then
			-- Append all entries
			for fields in f:lines() do
				local name, status = unpack(fields)

				if status == "allowed" then
					table.insert(names_pass, name)
				elseif status == "blocked" then
					table.insert(names_deny, name)
				end
			end

			-- Add allowed names
			if names_pass then
				__policy_pass = policy.add(
					policy.suffix(
						policy.PASS,
						policy.todnames(names_pass)
					)
				)
			end

			-- Add denied names
			if names_deny then
				__policy_deny = policy.add(
					policy.suffix(
						policy.DENY,
						policy.todnames(names_deny)
					)
				)
			end
		end
	end)
end

-- Clients should actually only send queries from port >= 1024, but
-- there seem to be too many broken implementations out there that
-- we have to relax this limit.
function config.reset_min_udp_source_port()
	C.the_network.min_udp_source_port = 0
end

return config
