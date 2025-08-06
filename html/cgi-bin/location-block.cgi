#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2007-2020  IPFire Team  <info@ipfire.org>                     #
# Copyright (C) 2024-2025  LoongFire Team  <vincent.mc.li@gmail.com>          #
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
# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/location-functions.pl";
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require "/usr/lib/firewall/firewall-lib.pl";

my $notice;
my $settingsfile = "${General::swroot}/firewall/locationblock";

my %color = ();
my %mainsettings = ();
my %settings = ();
my %cgiparams = ();
my $errormessage='';

# Read configuration file.
&General::readhash("$settingsfile", \%settings);

&General::readhash("${General::swroot}/main/settings", \%mainsettings);
&General::readhash("/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color);

&Header::showhttpheaders();

#Get GUI values
&Header::getcgihash(\%cgiparams);

# Call subfunction to get all available locations.
my @locations = &Location::Functions::get_locations();

if ($cgiparams{'ACTION'} eq $Lang::tr{'save'}) {
        # Check if we want to disable locationblock.
        if (exists $cgiparams{'LOCATIONBLOCK_ENABLED'}) {
                $settings{'LOCATIONBLOCK_ENABLED'} = "on";
        } else {
                $settings{'LOCATIONBLOCK_ENABLED'} = "off";
        }

        # Loop through our locations array to prevent from
        # non existing countries or code.
        foreach my $cn (@locations) {
                # Get the current setting for the country (on/off)
                my $current_status = $settings{$cn};

                # Determine if the country should be blocked based on CGI input
                my $new_status = exists $cgiparams{$cn} ? "on" : "off";

                # Update settings based on the user input
                $settings{$cn} = $new_status;

                # If the new status is "on" and the current status was "off", add the country's IPs
                if ($new_status eq "on" && $current_status eq "off") {
                # Call function to add IPs for this country to the eBPF map
                        &add_country_ips($cn);
                } # If the new status is "off" and the current status was "on", remove the country's IPs
                elsif ($new_status eq "off" && $current_status eq "on") {
                # Call function to remove IPs for this country from the eBPF map
                        &remove_country_ips($cn);
                }
        }

        &General::writehash("$settingsfile", \%settings);

        # Check if we want to disable locationblock.
        if ( $settings{'LOCATIONBLOCK_ENABLED'} eq "on" ) {
                &General::system('/usr/local/bin/xdpgeoipctrl', 'start');
        } else {
                &General::system('/usr/local/bin/xdpgeoipctrl', 'stop');
        }
}

&Header::openpage($Lang::tr{'locationblock configuration'}, 1, '');

&Header::openbigbox('100%', 'left', '', $errormessage);

if ($errormessage) {
        &Header::openbox('100%', 'left', $Lang::tr{'error messages'});
        print "<font class='base' color=red>$errormessage&nbsp;</font>\n";
        &Header::closebox();
}

# Checkbox pre-selection.
my $checked;
if ($settings{'LOCATIONBLOCK_ENABLED'} eq "on") {
	$checked = "checked='checked'";
}

# Print box to enable/disable locationblock.
print"<form method='POST' action='$ENV{'SCRIPT_NAME'}'>\n";

&Header::openbox('100%', 'center', $Lang::tr{'locationblock'});
print <<END;
	<table width='95%'>
		<tr>
			<td width='50%' class='base'>$Lang::tr{'locationblock enable feature'}
			<td><input type='checkbox' name='LOCATIONBLOCK_ENABLED' $checked></td>
		</tr>
		<tr>
			<td colspan='2'><br></td>
		</tr>
	</table>

	<hr>

	<table width='95%'>
		<tr>
			<td align='center'><input type='submit' name='ACTION' value='$Lang::tr{'save'}'></td>
		</tr>
	</table>
END

&Header::closebox();

&Header::openbox('100%', 'center', $Lang::tr{'locationblock block countries'});
### JAVA SCRIPT ###
print <<END;
<script>
	// Function to allow checking all checkboxes at once.
	function check_all() {
		\$("#countries").find(":checkbox").prop("checked", true);
	}

	function uncheck_all() {
		\$("#countries").find(":checkbox").prop("checked", false);
	}
</script>

<table width='95%' class='tbl' id="countries">
	<tr>
		<td width='5%' align='center' bgcolor='$color{'color20'}'></td>
		<td width='5%' align='center' bgcolor='$color{'color20'}'>
			<b>$Lang::tr{'flag'}</b>
		</td>
		<td width='5%' align='center' bgcolor='$color{'color20'}'>
			<b>$Lang::tr{'countrycode'}</b>
		</td>
		<td with='35%' align='left' bgcolor='$color{'color20'}'>
			<b>$Lang::tr{'country'}</b>
		</td>

		<td width='5%' bgcolor='$color{'color20'}'>&nbsp;</td>

		<td width='5%' align='center' bgcolor='$color{'color20'}'></td>
		<td width='5%' align='center' bgcolor='$color{'color20'}'>
			<b>$Lang::tr{'flag'}</b>
		</td>
		<td width='5%' align='center' bgcolor='$color{'color20'}'>
			<b>$Lang::tr{'countrycode'}</b>
		</td>
		<td with='35%' align='left' bgcolor='$color{'color20'}'>
			<b>$Lang::tr{'country'}</b>
		</td>
	</tr>
END

my $lines;
my $lines2;
my $col;
foreach my $location (@locations) {
	# Country code in upper case. (DE)
	my $ccode_uc = $location;

	# County code in lower case. (de)
	my $ccode_lc = lc($location);

	# Full name of the country based on the country code.
	my $cname = &Location::Functions::get_full_country_name($ccode_lc);

	# Get flag icon for of the country.
	my $flag_icon = &Location::Functions::get_flag_icon($ccode_uc);

	my $flag;
	# Check if a flag for the country is available.
	if ($flag_icon) {
		$flag="<img src='$flag_icon' alt='$ccode_uc' title='$ccode_uc'>";
	} else {
		$flag="<b>N/A</b>";
	}

	# Checkbox pre-selection.
	my $checked;
	if ($settings{$ccode_uc} eq "on") {
		$checked = "checked='checked'";
	}

	# Colour lines.
	if ($lines % 2) {
		$col="bgcolor='$color{'color20'}'";
	} else {
		$col="bgcolor='$color{'color22'}'";
	}

	# Grouping elements.
	my $line_start;
	my $line_end;
	if ($lines2 % 2) {
		# Increase lines (background color by once.
		$lines++;

		# Add empty column in front.
		$line_start="<td $col>&nbsp;</td>";

		# When the line number can be diveded by "2",
		# we are going to close the line.
		$line_end="</tr>";
	} else {
		# When the line number is  not divideable by "2",
		# we are starting a new line.
		$line_start="<tr>";
		$line_end;
	}

	print "$line_start<td align='center' $col><input type='checkbox' name='$ccode_uc' $checked></td>\n";
	print "<td align='center' $col>$flag</td>\n";
	print "<td align='center' $col>$ccode_uc</td>\n";
	print "<td align='left' $col>$cname</td>$line_end\n";

	# Finish column when the last element in the array has passed and we have an uneven amount of items.
	if(! ($lines2 % 2) && ($location eq $locations[-1] )) {
		print "<td $col>&nbsp;</td>\n";
		print "<td $col>&nbsp;</td>\n";
		print "<td $col>&nbsp;</td>\n";
		print "<td $col>&nbsp;</td>\n";
		print "<td $col>&nbsp;</td></tr>\n";
	}

$lines2++;
}

print <<END;
</table>

<table width='95%'>
	<tr>
		<td align='right'>
			<a href="javascript:check_all()">$Lang::tr{'check all'}</a> /
			<a href="javascript:uncheck_all()">$Lang::tr{'uncheck all'}</a>
		</td>
	</tr>
	<tr>
		<td align='center'><input type='submit' name='ACTION' value='$Lang::tr{'save'}'></td>
	</tr>
</table>

<hr>

<table width='70%'>
	<tr>
		<td width='5%'><img src='/images/on.gif'></td>
		<td>$Lang::tr{'locationblock country is blocked'}</td>
		<td width='5%'><img src='/images/off.gif'></td>
		<td>$Lang::tr{'locationblock country is allowed'}</td>
	</tr>
</table>
END

&Header::closebox();
print"</form>\n";

&Header::closebigbox();
&Header::closepage();

sub add_country_ips {

        my ($set) = @_;

        # Libloc adds the IP type (v4 or v6) as part of the set and file name.
        my $loc_set = "$set" . "v4";

        # The bare filename equals the set name.
        my $filename = $loc_set;

        # Libloc uses "ipset" as file extension.
        my $file_extension = "ipset";

        # Generate full path and filename for the ipset db file.
        my $db_file = "$Location::Functions::ipset_db_directory/$filename.$file_extension";

        my @options;
        my $command = 'xdp_geoip';
        push(@options, "add", $db_file, $set);
        &General::system_output($command, @options);
        #my @output = &General::system_output($command, @options);
        #$errormessage = join('', @output);
}

sub remove_country_ips {
        my ($set) = @_;

        # Libloc adds the IP type (v4 or v6) as part of the set and file name.
        my $loc_set = "$set" . "v4";

        # The bare filename equals the set name.
        my $filename = $loc_set;

        # Libloc uses "ipset" as file extension.
        my $file_extension = "ipset";

        # Generate full path and filename for the ipset db file.
        my $db_file = "$Location::Functions::ipset_db_directory/$filename.$file_extension";

        my @options;
        my $command = 'xdp_geoip';
        push(@options, "delete", $db_file, $set);
        &General::system_output($command, @options);
        #my @output = &General::system_output($command, @save_options);
        #$errormessage = join('', @output);
}
