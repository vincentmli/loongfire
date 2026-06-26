#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2007-2026  IPFire Team  <info@ipfire.org>                     #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

use strict;
use JSON::PP;
use Net::LibIDN2 ':all';

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require "${General::swroot}/network-functions.pl";

my %color = ();
my %mainsettings = ();
my %settings = ();
my %cgiparams = ();
my %custom_domains = ();
my %global_settings = ();
my $dnsbl;

# Arrays which contain the custom defined domain names.
my @custom_allowed_domains = ();
my @custom_blocked_domains = ();

# File which contains the available filtering categories.
my $dnsbl_json_file = "${General::swroot}/dns/dnsbl.json";

# File wich contains the configured filtering rules.
my $settings_file = "${General::swroot}/dns/dnsbl";

# File which contains the elements of the custom allow and block lists.
my $custom_domains_file = "${General::swroot}/dns/custom_domains";

# Global settings file (already exists with format KEY=VALUE)
my $global_settings_file = "${General::swroot}/dns/settings";

# Read-in main settings, for language, theme and colors.
&General::readhash("${General::swroot}/main/settings", \%mainsettings);
&General::readhash("/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color);

# Read global settings (existing format)
&read_global_settings() if (-f "$global_settings_file");

# Get the available network zones, based on the config type of the system and store
# the list of zones in an array.
my @network_zones = &Network::get_available_network_zones();

# Get the available filter categories.
#
# Open the JSON file.
open(DNSBL, $dnsbl_json_file);

# Read-in the dnsbl.json file content and append the lines to a string.
my $json_file = join("\n", <DNSBL>);

# Close file handle.
close(DNSBL);

# Call the JSON parser to parse the dnsbl.json file content.
if ($json_file) {
	$dnsbl = decode_json($json_file);
}

my @errormessages = ();

&Header::showhttpheaders();

#Get GUI values
&Header::getcgihash(\%cgiparams);

# Handle XDP setting save
if ($cgiparams{'ACTION'} eq "save_xdp") {
	# Update XDP setting - fix: handle unchecked checkbox properly
	if (defined($cgiparams{'ENABLE_XDP'}) && $cgiparams{'ENABLE_XDP'} eq "on") {
		$global_settings{'ENABLE_XDP'} = "on";
	} else {
		# Checkbox is unchecked or not present - set to off
		$global_settings{'ENABLE_XDP'} = "off";
	}
	
	# Write global settings preserving all existing settings
	&write_global_settings();
	
	# Restart DNS service to apply XDP settings
	&General::system("/usr/local/bin/dnsfwctrl", "restart");
}

# Save settings on main page.
if ($cgiparams{'ACTION'} eq "$Lang::tr{'save'}") {
	my %tmphash;

	# Read-in settings file.
	&readsettings("$settings_file", \%settings);

	# Loop through the list of known blocklists.
	foreach my $list (@{ $dnsbl }) {
		# Assign stored or default values.
		my $zone = $list->{'zone'};
		my $enabled = $cgiparams{$zone} || "";
		my $comment = $settings{$zone}[1] || "";
		my $enabled_zones = $settings{$zone}[2] || "";
		my $custom_acl = $settings{$zone}[3] || "";
		my $rest = $settings{$zone}[4] || "";

		# Store the current list and the assigned array values in the temporary hash.
		$tmphash{$zone} = [ "$enabled", "$comment", "$enabled_zones", "$custom_acl", "$rest" ];
	}

	# Write config hash.
	&writesettings("$settings_file", \%tmphash);

	if ($global_settings{'ENABLE_XDP'} eq "on") {
		&General::system("/usr/local/bin/dnsfwctrl", "sync");
	}

# Save changed zone ACL
} elsif ($cgiparams{'ACTION'} eq "$Lang::tr{'update'}") {
	my %tmphash;

	# Assign ACL to arrays.
	my @enabled_zones = split(/\|/, $cgiparams{'ENABLED_ZONES'});
	my @custom_acl = split(/\s+/, $cgiparams{'CUSTOM_ACL'});

	# Check if the given network zones are valid.
	foreach my $enabled_zone (@enabled_zones) {
		# Convert the current processed enabled zone into lower case format.
		my $enabled_zone_lc = lc($enabled_zone);

		# Check if the zone is known.
		unless (grep(/$enabled_zone_lc/, @network_zones)) {
			# Display error message about unknown network zone.
			push(@errormessages, "$enabled_zone - $Lang::tr{'unknown network zone'}");
		}
	}

	# Check if the given custom ACL addresses/networks are valid.
	foreach my $address (@custom_acl) {
		next unless($address);

		if ((!&Network::check_ip_address($address)) && (!&Network::check_subnet($address))) {
			push(@errormessages, "$address - $Lang::tr{'guardian invalid address or subnet'}");
		}
	}

	# Normalize all networks
	@custom_acl = &Network::normalize_networks(@custom_acl);

	# Only go further, if there was no error message.
	unless (scalar @errormessages) {
		# Read-in settings file.
		&readsettings("$settings_file", \%settings);

		# Assign nice human read-able variables.
		my $zone = $cgiparams{'ZONE'};
		my $enabled = $settings{$zone}[0];
		my $comment = $settings{$zone}[1];
		my $enabled_zones = join("|", @enabled_zones);
		my $custom_acl = join("|", @custom_acl);
		my $rest = $settings{$zone}[4];

		# Copy stored settings into temporary hash.
		%tmphash = %settings;

		# Update the values in the temporay hash.
		$tmphash{$zone} = [ "$enabled", "$comment", "$enabled_zones", "$custom_acl", "$rest" ];

		# Write the new ACL settings to settings file.
		&writesettings("$settings_file", \%tmphash);

		if ($global_settings{'ENABLE_XDP'} eq "on") {
			&General::system("/usr/local/bin/dnsfwctrl", "sync");
		}
	}

# Save changed custom domains to allow or block
} elsif ($cgiparams{'CUSTOM_DOMAINS'} eq "$Lang::tr{'save'}") {
	my @cgi_allowed_domains;
	my @cgi_blocked_domains;
	my @ascii_allowed_domains;
	my @ascii_blocked_domains;

	# Get the current configured custom domains to allow or block
	&readsettings("$custom_domains_file", \%custom_domains) if (-f "$custom_domains_file");

	# Grab custom configured domains and assign them to the corresponding arrays.
	@custom_allowed_domains = @{ $custom_domains{"CUSTOM_ALLOWED_DOMAINS"} } if ($custom_domains{"CUSTOM_ALLOWED_DOMAINS"});
	@custom_blocked_domains = @{ $custom_domains{"CUSTOM_BLOCKED_DOMAINS"} } if ($custom_domains{"CUSTOM_BLOCKED_DOMAINS"});

	# Assign the posted domains from cgi to the corresponding arrays.
	@cgi_allowed_domains = split(/\s+/, $cgiparams{"CUSTOM_ALLOWED_DOMAINS"});
	@cgi_blocked_domains = split(/\s+/, $cgiparams{"CUSTOM_BLOCKED_DOMAINS"});

	# Remove any duplicate entries from the arrays.
	@cgi_allowed_domains = &General::uniq(@cgi_allowed_domains);
	@cgi_blocked_domains = &General::uniq(@cgi_blocked_domains);

	# Check domains and convert into ascii format.
	@ascii_allowed_domains = &format_domains(\@cgi_allowed_domains, "ascii");
	@ascii_blocked_domains = &format_domains(\@cgi_blocked_domains, "ascii");

	# Merge temporary merge both arrays for duplicate and valid check.
	my @ascii_merged = (@ascii_allowed_domains, @ascii_blocked_domains);

	# Check if there are duplicate entries on the merged list.
	# This assumes a domain which has been entered on both
	my $dup = &check_for_duplicates(@ascii_merged);

	# If a duplicate has been found, raise an error
	if ($dup) {
		push(@errormessages, "$dup - $Lang::tr{'dnsbl error domain specified twice'}");
	}

	# Check allowed domains
	foreach my $domain (@ascii_allowed_domains) {
		unless (&General::validfqdn($domain)) {
			push(@errormessages, "$Lang::tr{'invalid domain name'}: ${domain}");
		}
	}

	# Check blocked domains
	foreach my $domain (@ascii_blocked_domains) {
		unless (&General::validfqdn($domain)) {
			push(@errormessages, "$Lang::tr{'invalid domain name'}: ${domain}");
		}
	}

	# Check if a domain from the posted blocked domains array is allready part of
	# the saved allowed domains array
	$dup = &compare_arrays(\@custom_allowed_domains, \@ascii_blocked_domains);
	if ($dup) {
		push(@errormessages, "$dup - $Lang::tr{'dnsbl error domain specified twice'}");
	}

	# Check if a domain from the posted allowed domains array is allready part of
	# the saved blocked domains array.
	$dup = &compare_arrays(\@custom_blocked_domains, \@ascii_allowed_domains);
	if ($dup) {
		push(@errormessages, "$dup - $Lang::tr{'dnsbl error domain specified twice'}");
	}

	unless (scalar @errormessages) {
		my %tmp;

		# Assign the allowed and blocked domain arrays to the temporary hash
		foreach my $domain (@ascii_allowed_domains) {
			$tmp{$domain} = [ "allowed" ];
		}

		foreach my $domain (@ascii_blocked_domains) {
			$tmp{$domain} = [ "blocked" ];
		}

		# Save the domains
		&writesettings("$custom_domains_file", \%tmp);

		if ($global_settings{'ENABLE_XDP'} eq "on") {
			&General::system("/usr/local/bin/dnsfwctrl", "custom-sync");
		}

	}
}

&Header::openpage($Lang::tr{"dnsbl dns firewall"}, 1, '');

&Header::openbigbox('100%', 'left');

# Display any error messages
&Header::errorbox(@errormessages);

# Decide which page should be displayed.
if ($cgiparams{'ACTION'} eq "$Lang::tr{'edit'}") {
	&show_edit_zone();
} else {
	&show_mainpage();
}

&Header::closebigbox();
&Header::closepage();

#
## Function to read global settings (KEY=VALUE format)
#
sub read_global_settings() {
	%global_settings = ();
	
	open(my $fh, '<', $global_settings_file) or return;
	
	while (my $line = <$fh>) {
		chomp($line);
		next if ($line =~ /^\s*$/);  # Skip empty lines
		next if ($line =~ /^\s*#/);   # Skip comments
		
		if ($line =~ /^([^=]+)=(.*)$/) {
			my $key = $1;
			my $value = $2;
			$global_settings{$key} = $value;
		}
	}
	
	close($fh);
}

#
## Function to write global settings preserving all existing settings
#
sub write_global_settings() {
	# Read existing settings first to preserve any that weren't modified
	%global_settings = ();
	&read_global_settings() if (-f "$global_settings_file");
	
	# Update XDP setting based on checkbox presence - FIXED
	if (defined($cgiparams{'ENABLE_XDP'}) && $cgiparams{'ENABLE_XDP'} eq "on") {
		$global_settings{'ENABLE_XDP'} = "on";
	} else {
		# Checkbox is unchecked or not present - set to off
		$global_settings{'ENABLE_XDP'} = "off";
	}
	
	# Write all settings back
	open(my $fh, '>', $global_settings_file) or die "Unable to write to $global_settings_file";
	
	foreach my $key (sort keys %global_settings) {
		print $fh "$key=$global_settings{$key}\n";
	}
	
	close($fh);
}

#
## Function to display the main page.
#
sub show_mainpage() {
	# Read-in settings file
	&readsettings("$settings_file", \%settings);
	
	# Get current XDP setting (default to off if not set)
	my $xdp_checked = "";
	if (exists($global_settings{'ENABLE_XDP'}) && $global_settings{'ENABLE_XDP'} eq "on") {
		$xdp_checked = "checked='checked'";
	}

	# Read-in custom allow and blocklist file.
	&readsettings("$custom_domains_file", \%custom_domains) if (-f "$custom_domains_file");

	# Grab the list elements and assign them to the corresponding arrays
	if (%custom_domains) {
		foreach my $domain (keys %custom_domains) {
			my $status = $custom_domains{$domain}[0];

			if ($status eq "allowed") {
				push(@custom_allowed_domains, &format_domain_to_unicode($domain));
			} elsif ($status eq "blocked") {
				push(@custom_blocked_domains, &format_domain_to_unicode($domain));
			}
		}
	}

	# XDP Settings Box
	&Header::openbox('100%', 'center', "XDP Acceleration Settings");
	
print <<END;
	<form method='post' action='$ENV{'SCRIPT_NAME'}'>
		<table width='100%' border='0' class='tbl'>
			<tr>
				<td width='5%' class="text-center">
					<input type='checkbox' name='ENABLE_XDP' id='ENABLE_XDP' value='on' $xdp_checked>
				</td>
				<td width='95%'>
					<strong>$Lang::tr{'dnsbl xdp enable'}</strong><br>
					<small>$Lang::tr{'dnsbl xdp description'}</small>
				</td>
			</tr>
			<tr>
				<td colspan='2' align='right'>
					<input type='submit' name='ACTION' value='save_xdp'>
					</form>
				</td>
			</tr>
			</form>
	</table>
END

	&Header::closebox();
	
	&Header::openbox('100%', 'center', $Lang::tr{"dnsbl lists"});

print <<END;
	<form id='main' method='post' action='$ENV{'SCRIPT_NAME'}'></form>
	<table width='100%' border='0' class='tbl'>
END
        	# Loop through the available blocklists.
        	foreach my $list (@{ $dnsbl }) {
                	my $name = $list->{"name"};
			my $description = $list->{"description"};
			my $zone = $list->{"zone"};
			my $checked;

			# Check if the list is enabled.
			if ($settings{$zone}[0] eq "on") {
				$checked = "checked='checked'";
			}

print <<END;
			<tr>
			<td width='5%' class="text-center">
				<input type='checkbox' form='main' name='$zone' id='$zone' value='on' $checked>
				</td>
			<td width='20%'>
				<strong>$name</strong>
				</td>
			<td width='70%'>$description</td>
			<td width='5%' align='center'>
				<form id='$name' method='post' action='$ENV{'SCRIPT_NAME'}'></form>
				<input type='hidden' form='$name' name='ACTION' value='$Lang::tr{'edit'}'>
				<input type='image' form='$name' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' alt='submit'>
				<input type='hidden' form='$name' name='ZONE' value='$zone'>
				</td>
			</tr>
END
		}

print <<END;

	</table>

	<br>

	<div align='right'>
		<input type='submit' form='main' name='ACTION' value='$Lang::tr{'save'}'>
	</div>
END

	&Header::closebox();

	# Section for custom allow and blocklist.
	&Header::openbox('100%', 'center', $Lang::tr{"dnsbl custom block and allow list"});

print <<END;
	<form method='post' action='$ENV{'SCRIPT_NAME'}'>
		<table class="form">
			<tr>
				<td>
					$Lang::tr{"urlfilter blocked domains"}
				</td>

				<td>
					<textarea name='CUSTOM_BLOCKED_DOMAINS' rows='8'
						>@{[ join("\n", @custom_blocked_domains) ]}</textarea>
				</td>
			</tr>

			<tr>
				<td>
					$Lang::tr{"urlfilter allowed domains"}
				</td>

				<td>
					<textarea name='CUSTOM_ALLOWED_DOMAINS' rows='8'
						>@{[ join("\n", @custom_allowed_domains) ]}</textarea>
				</td>
			</tr>

			<tr class="action">
				<td colspan="2">
					<input type='submit' name='CUSTOM_DOMAINS' value='$Lang::tr{'save'}'>
					</form>
				</td>
			</tr>
			</form>
	</table>
END

	&Header::closebox();
}

#
## Function to show section to edit the zone ACL.
#
sub show_edit_zone() {
	# Get the requested zone.
	my $zone = $cgiparams{'ZONE'};

	# Fetch the list
	my $list = &get_list($zone);

	# Fail if we could not find the list
	die "Unknown list: $zone" unless (defined $list);

	# Read-in settings file.
	&readsettings("$settings_file", \%settings);

	# Grab the configured ACL settings.
	my @enabled_zones = split(/\|/, $settings{$zone}[2]);
	my @custom_acl = split(/\|/, $settings{$zone}[3]);

	&Header::openbox('100%', 'center', $list->{"name"});

print <<END;
	<form method='post' action='$ENV{'SCRIPT_NAME'}'>
		<input type='hidden' name='ZONE' value='$zone'>

		<table class="form">
			<tr class="header">
				<td colspan="2">
					$Lang::tr{"dnsbl acl"}
					</form>
				</td>
			</tr>

			<tr>
				<td colspan="2">
					<p>
						$Lang::tr{'dnsbl acl explanation'}
					</p>
					</form>
				</td>
			</tr>

			<tr>
				<td>
					$Lang::tr{"network zone"}
					</form>
				</td>

				<td>
					<select name="ENABLED_ZONES" size='6' multiple>
END

					# Loop through the array of available network zones.
					foreach my $zone (@network_zones) {
						my $selected;

						# Skip the red network zone.
						next if ($zone) eq "red";

						# Convert zone name into upper case format.
						my $zone_uc = uc($zone);

						# Check if the current processed zone previously has been
						# selected.
						if ( grep( /$zone_uc/, @enabled_zones ) ) {
							$selected = "selected";
						}

						print "<option value='$zone_uc' $selected>$Lang::tr{$zone}</option>\n";
					}
print <<END;
					</select>
					</form>
				</td>
			</tr>

			<tr>
				<td>
					$Lang::tr{"dnsbl custom source"}
					</form>
				</td>

				<td>
					<textarea name='CUSTOM_ACL' rows='9' placeholder='1.2.3.4\n10.0.0.0/255.255.255.0\n192.168.0.0/24'
						>@{[ join("\n", @custom_acl) ]}</textarea>
					</form>
				</td>
			</tr>

			<tr class="action">
				<td colspan='2'>
					<input type='submit' value='$Lang::tr{'back'}'>
					<input type='submit' name='ACTION' value='$Lang::tr{'update'}'>
					</form>
				</td>
			</tr>
		</table>
	</form>
END

	&Header::closebox();
}

#
## Custom readsettings function to allow non numerical key instead an id.
#
sub readsettings {
	my ($filename, $hash) = @_;
	%$hash = ();

	open(FILE, $filename) or die "Unable to read file $filename";

	while (<FILE>) {
		my ($key, $rest, @temp);
		chomp;
		($key, $rest) = split (/,/, $_, 2);
		@temp = split (/,/, $rest);
		$hash->{$key} = \@temp;
	}
	close FILE;
	return;
}

#
## Custom writesettings function to allow a non numerical key instead an id.
#
sub writesettings {
	my ($filename, $hash) = @_;
	my ($key, @temp, $i);

	open(FILE, ">$filename") or die "Unable to write to file $filename";

	foreach $key (keys %$hash) {
		print FILE "$key";
		foreach $i (0 .. $#{$hash->{$key}}) {
			print FILE ",$hash->{$key}[$i]";
		}
		print FILE "\n";
	}
	close FILE;
	return;
}

sub get_list($) {
	my $zone = shift;

	foreach my $list (@{ $dnsbl }) {
		return $list if ($list->{"zone"} eq $zone);
	}

	return undef;
}

sub check_for_duplicates (@) {
	my @array = @_;
	my $lastelement;

	# Sort and loop through the given array.
	foreach my $element (sort(@array)) {
		# Check if the current element is the same than the last one.
		return $element if ($element eq $lastelement);

		# Store last processed element.
		$lastelement = $element;
	}
}

sub compare_arrays (\@\@) {
	my ($data, $test) = @_;

	my @data = @{ $data };
	my @test = @{ $test };

	# Early exit if there are no entries in one of the given arrays.
	return unless (@data);
	return unless (@test);

	# Loop through the content of the test array and check
	# if the current processed element is part of the data array.
	foreach my $element (@test) {
		if (grep(/$element/, @data)) {
			return "$element";
		}
	}
}

sub format_domains(\@$) {
	my ($arrayref, $format) = @_;
	my @formated_domains;

	# Deref and assign array.
	my @domains = @{ $arrayref };

	# Exit if not data passed.
	return unless (@domains);

	# Loop through the given domains array.
	foreach my $domain (@domains) {
		my $formated_domain;

		# Check the output format and convert the domain into requested format.
		if ($format eq "ascii") {
			$formated_domain = &format_domain_to_ascii($domain);
		} elsif ($format eq "unicode") {
			$formated_domain = &format_domain_to_unicode($domain);
		} else {
			# Unknown format requested.
			return;
		}

		# Check if the domain could be converted.
		if ($formated_domain) {
			# Add the converted domain to the array of ascii domains.
			push(@formated_domains, $formated_domain);
		} else {
			# Add the invalid domain to the array of error messages.
			push(@errormessages, "$domain - $Lang::tr{'invalid domain name'}");
		}
	}

	return @formated_domains;
}

sub format_domain_to_ascii($) {
	my ($domain) = @_;
	my $ascii;
	my $ret;

	# Early exit on empty input.
	return unless($domain);

	# Spit the given domain name into parts.
	my @parts = split(/\./, $domain);

	# Exit if the given domain does not contain at least one dot.
	return if(scalar(@parts) < 2);

	# Use the perl module to convert the domain into the idn ascii format.
	$ascii = &Net::LibIDN2::idn2_to_ascii_8($domain, "", $ret);

	# Check if an error occured.
	if ($ret) {
		# Get the error message.
		my $error = &Net::LibIDN2::idn2_strerror($ret);

		push(@errormessages, "$domain - LibIDN2: $error");
	}

	# Exit if the given domain could not be converted.
	return unless($ascii);

	# Return the converted domain.
	return $ascii;
}

sub format_domain_to_unicode($) {
	my ($ascii) = @_;
	my $unicode;
	my $ret;

	# Exit if no input has been given.
	return unless($ascii);

	# Convert the idn_ascii formated domain back to unicode and return it.
	$unicode = &Net::LibIDN2::idn2_to_unicode_88($ascii, $ret);

	# Check if an error occured.
	if ($ret) {
		# Get the error message.
		my $error = &Net::LibIDN2::idn2_strerror($ret);

		push(@errormessages, "$ascii - LibIDN2: $error");
	}

	return $unicode;
}
