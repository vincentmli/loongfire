#!/usr/bin/perl

###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# or (at your option) any later version.                                      #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
# Copyright (C) 2018 - 2020 The IPFire Team                                   #
#                                                                             #
###############################################################################

use strict;

# enable the following only for debugging purposes
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require "${General::swroot}/ipblocklist-functions.pl";

# Import blockist sources and settings file.
require "${General::swroot}/ipblocklist/sources";

###############################################################################
# Configuration variables
###############################################################################

my $settings      = "${General::swroot}/ipblocklist/settings";
my %cgiparams     = ('ACTION' => '');
my $xdp_program   = "/usr/sbin/xdp_ipblocklist";  # Path to XDP user space program
my $blocklist_dir = "/var/lib/ipblocklist";       # Directory with blocklist files
my $xdp_ctrl      = "/usr/local/bin/xdpipblocklistctrl";  # Secure wrapper for init script

###############################################################################
# Variables
###############################################################################

my $errormessage  = '';
my $headline = "$Lang::tr{'error message'}";
my $updating      = 0;
my %mainsettings;
my %color;
my %old_settings;  # To store previous settings for comparison
my $firewall_reload_needed = 0;  # Flag to track if firewall reload is needed

# Default settings - normally overwritten by settings file
my %settings = (
	'DEBUG'           => 0,
	'LOGGING'         => 'on',
	'ENABLE'          => 'off',
	'XDP_ACCEL'       => 'off'  # New: XDP acceleration enable/disable
);

# Read all parameters
&Header::getcgihash( \%cgiparams);
&General::readhash( "${General::swroot}/main/settings", \%mainsettings );
&General::readhash("/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color);

# Get list of supported blocklists.
my @blocklists = &IPblocklist::get_blocklists();

# Show Headers
&Header::showhttpheaders();

# Process actions
if ($cgiparams{'ACTION'} eq "$Lang::tr{'save'}") {
	# Assign checkbox values, in case they are not checked.
	$cgiparams{'ENABLE'} = "off" unless($cgiparams{'ENABLE'});
	$cgiparams{'LOGGING'} = "off" unless($cgiparams{'LOGGING'});
	$cgiparams{'XDP_ACCEL'} = "off" unless($cgiparams{'XDP_ACCEL'});  # New XDP acceleration checkbox
	
	# IMPORTANT: If XDP acceleration is enabled, force LOGGING to off
	# because XDP doesn't support iptables logging
	if ($cgiparams{'XDP_ACCEL'} eq 'on') {
		$cgiparams{'LOGGING'} = 'off';
		&General::log("IP Blocklist: XDP acceleration enabled, forcing LOGGING to off");
	}
	
	# Read current settings to compare with new ones
	&General::readhash($settings, \%old_settings) if (-r $settings);
	
	# Validate settings: XDP acceleration requires main feature to be enabled
	if ($cgiparams{'XDP_ACCEL'} eq 'on' && $cgiparams{'ENABLE'} eq 'off') {
		$headline = "$Lang::tr{'error message'}";
		$errormessage = "XDP acceleration requires IP blocklist feature to be enabled. Please enable IP blocklists first or disable XDP acceleration.";
	}
	
	# Array to store if blocklists are missing on the system
	# and needs to be downloaded first.
	my @missing_blocklists = ();

	# Only check for missing blocklists if the feature is enabled
	if ($cgiparams{'ENABLE'} eq 'on') {
		# Loop through the array of supported blocklists.
		foreach my $blocklist (@blocklists) {
			# Get the current and new state
			my $old_state = $old_settings{$blocklist} || 'off';
			my $new_state = $cgiparams{$blocklist} || 'off';
			
			# Skip the blocklist if it is not enabled.
			next if($cgiparams{$blocklist} ne "on");

			# Get the file name which keeps the converted blocklist.
			my $ipset_db_file = &IPblocklist::get_ipset_db_file($blocklist);

			# Check if the blocklist already has been downloaded.
			if(-f "$ipset_db_file") {
				# Blocklist already exits, we can skip it.
				next;
			} else {
				# Blocklist not present, store in array to download it.
				push(@missing_blocklists, $blocklist);
			}
		}
	}

	# Check if there was an error from validation
	unless($errormessage) {
		# Check if the red device is not active and blocklists are missing.
		if ((not -e "${General::swroot}/red/active") && (@missing_blocklists)) {
			# The system is offline, cannot download the missing blocklists.
			# Store an error message.
			$errormessage = "$Lang::tr{'system is offline'}";
		} else {
			# Loop over the array of missing blocklists.
			foreach my $missing_blocklist (@missing_blocklists) {
				# Call the download and convert function to get the missing blocklist.
				my $status = &IPblocklist::download_and_create_blocklist($missing_blocklist);

				# Check if there was an error during download.
				if ($status eq "dl_error") {
					$errormessage = "$Lang::tr{'ipblocklist could not download blocklist'} - $Lang::tr{'ipblocklist download error'}";
				} elsif ($status eq "empty_list") {
					$errormessage = "$Lang::tr{'ipblocklist could not download blocklist'} - $Lang::tr{'ipblocklist empty blocklist received'}";
				}
			}
		}
	}

	# Check if there was an error.
	unless($errormessage) {
		# Write configuration hash.
		&General::writehash($settings, \%cgiparams);

		# Get old and new states for comparison
		my $old_enable = $old_settings{'ENABLE'} || 'off';
		my $new_enable = $cgiparams{'ENABLE'} || 'off';
		my $old_xdp = $old_settings{'XDP_ACCEL'} || 'off';
		my $new_xdp = $cgiparams{'XDP_ACCEL'} || 'off';
		
		# Manage XDP program state
		&manage_xdp_state(\%old_settings, \%cgiparams);
		
		# Manage XDP blocklists when settings change
		&manage_xdp_blocklists(\%old_settings, \%cgiparams);
		
		# Determine if firewall reload is needed using clean logic:
		# Firewall reload is needed when:
		# 1. Using iptables mode (XDP_ACCEL='off') AND feature is enabled OR being disabled
		# 2. Switching between modes (to clean up old rules)
		
		if ($new_enable eq 'on' && $new_xdp eq 'off') {
			# Iptables mode is active - reload needed
			$firewall_reload_needed = 1;
			&General::log("IP Blocklist: Iptables mode active, firewall reload needed");
		}
		elsif ($old_enable eq 'on' && $new_enable eq 'off' && $old_xdp eq 'off') {
			# Disabling iptables mode - reload needed to clean up
			$firewall_reload_needed = 1;
			&General::log("IP Blocklist: Disabling iptables mode, firewall reload needed for cleanup");
		}
		elsif ($old_enable eq 'on' && $new_enable eq 'on' && $old_xdp ne $new_xdp) {
			# Switching between modes - reload needed to clean up old rules
			$firewall_reload_needed = 1;
			&General::log("IP Blocklist: Switching between XDP and iptables modes, firewall reload needed");
		}
		# Note: No firewall reload needed when:
		# 1. XDP mode is active (rules.pl will skip iptables rules)
		# 2. Feature is disabled with XDP (XDP program handles cleanup)

		# Call function to mark a required reload of the firewall if needed
		if ($firewall_reload_needed) {
			&General::firewall_config_changed();
			# Display notice about a required reload of the firewall.
			$headline = "$Lang::tr{'notice'}";
			$errormessage = "$Lang::tr{'fw rules reload notice'}";
		} else {
			# Display success message
			$headline = "$Lang::tr{'notice'}";
			$errormessage = "Settings saved successfully.";
			if ($cgiparams{'XDP_ACCEL'} eq 'on') {
				$errormessage .= " $Lang::tr{'ipblocklist xdp notice'}";
			}
		}
	}
}

# Show site
&Header::openpage($Lang::tr{'ipblocklist'}, 1, '');
&Header::openbigbox('100%', 'left');

# Display error message if there was one.
&error() if ($errormessage);

# Read-in ipblocklist settings.
&General::readhash( $settings, \%settings ) if (-r $settings);

# Display configuration section.
&configsite();

# End of page
&Header::closebigbox();
&Header::closepage();


#------------------------------------------------------------------------------
# sub configsite()
#
# Displays configuration
#------------------------------------------------------------------------------

sub configsite {
	# Find preselections
	my $enable = 'checked';

	&Header::openbox('100%', 'left', $Lang::tr{'settings'});

	# Enable checkbox
	$enable = ($settings{'ENABLE'} eq 'on') ? ' checked' : '';

print<<END;
	<form method='post' action='$ENV{'SCRIPT_NAME'}'>
		<table style='width:100%' border='0'>
			<tr>
				<td style='width:24em'>$Lang::tr{'ipblocklist use ipblocklists'}</td>
				<td><input type='checkbox' name='ENABLE' id='ENABLE'$enable 
					onchange="toggleXdpAccel(this.checked)" 
					title="Main switch for IP blocklist feature. Required for XDP acceleration."></td>
			</tr>
END

	# XDP Acceleration checkbox (new) - disabled if main feature is off
	my $xdp_enable = ($settings{'XDP_ACCEL'} eq 'on') ? ' checked' : '';
	my $xdp_disabled = ($settings{'ENABLE'} eq 'off') ? ' disabled' : '';
	my $xdp_title = ($settings{'ENABLE'} eq 'off') ? 
		"Enable IP blocklists first to use XDP acceleration" : 
		"Kernel-level acceleration for faster blocking (bypasses iptables)";
	
print<<END;
			<tr>
				<td style='width:24em'>$Lang::tr{'ipblocklist use xdp'}</td>
				<td><input type='checkbox' name='XDP_ACCEL' id='XDP_ACCEL'$xdp_enable$xdp_disabled 
					title="$xdp_title"></td>
			</tr>
END

	# JavaScript to enable/disable XDP checkbox based on main feature
print<<END;
		<script type="text/javascript">
		function toggleXdpAccel(enabled) {
			var xdpCheckbox = document.getElementById('XDP_ACCEL');
			if (enabled) {
				xdpCheckbox.disabled = false;
				xdpCheckbox.title = "Kernel-level acceleration for faster blocking (bypasses iptables)";
			} else {
				xdpCheckbox.disabled = true;
				xdpCheckbox.checked = false;
				xdpCheckbox.title = "Enable IP blocklists first to use XDP acceleration";
			}
		}
		</script>
END

	# Information about XDP acceleration vs traditional blocking
	my $info_message = "";
	if ($settings{'ENABLE'} eq 'on') {
		if ($settings{'XDP_ACCEL'} eq 'on') {
			$info_message = "<div style='color: green; margin: 10px 0; padding: 10px; background-color: #f0f8f0; border: 1px solid #90ee90;'>
				<strong>$Lang::tr{'ipblocklist xdp active'}</strong>$Lang::tr{'ipblocklist xdp blocking'}
				<br><em>Note: Logging is not available for XDP acceleration.</em>
				</div>";
		} else {
			$info_message = "<div style='color: blue; margin: 10px 0; padding: 10px; background-color: #f0f0ff; border: 1px solid #add8e6;'>
				<strong>$Lang::tr{'ipblocklist iptables active'}</strong>$Lang::tr{'ipblocklist iptables blocking'}
				</div>";
		}
	}
	
print<<END;
		$info_message
		</table><br>
		<div class='sources'>
END

	# Show LOGGING checkbox only when using traditional iptables/ipset path
	if ($settings{'ENABLE'} eq 'on' && $settings{'XDP_ACCEL'} ne 'on') {
		my $logging_checked = ($settings{'LOGGING'} eq 'on') ? ' checked' : '';
		
print<<END;
			<table style='width:100%' border='0'>
				<tr>
					<td style='width:24em'>$Lang::tr{'ipblocklist log'}</td>
					<td><input type='checkbox' name="LOGGING" id="LOGGING"$logging_checked 
						title="Log blocked connections to syslog (iptables/ipset path only)"></td>
				</tr>
			</table>
END
	} elsif ($settings{'ENABLE'} eq 'on' && $settings{'XDP_ACCEL'} eq 'on') {
		# Show info about logging not being available with XDP
print<<END;
			<div style='margin: 10px 0; padding: 8px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px;'>
				<strong>Note:</strong>$Lang::tr{'ipblocklist log option'}
			</div>
END
	}

print<<END;
			<br><br>
			<h2>$Lang::tr{'ipblocklist blocklist settings'}</h2>

			<table width='100%' cellspacing='1' class='tbl'>
				<tr>
					<th align='left'>$Lang::tr{'ipblocklist id'}</th>
					<th align='left'>$Lang::tr{'ipblocklist name'}</th>
					<th align='left'>$Lang::tr{'ipblocklist category'}</th>
					<th align='center'>$Lang::tr{'ipblocklist enable'}</th>
				</tr>
END

	# Iterate through the list of sources
	my $lines = 0;

	foreach my $blocklist (@blocklists) {
		# Display blocklist name or provide a link to the website if available.
		my $website = $blocklist;
		if ($IPblocklist::List::sources{$blocklist}{info}) {
			$website ="<a href='$IPblocklist::List::sources{$blocklist}{info}' target='_blank'>$blocklist</a>";
		}

		# Get the full name for the blocklist.
		require CGI;
		my $name = CGI::escapeHTML($IPblocklist::List::sources{$blocklist}{'name'});

		# Get category for this blocklist.
		my $category = $Lang::tr{"ipblocklist category $IPblocklist::List::sources{$blocklist}{'category'}"};

		# Determine if the blocklist is enabled.
		my $enable = '';
		$enable = 'checked' if ($settings{$blocklist} eq 'on');

		# Set colour for the table columns.
		my $col = ($lines++ % 2) ? "bgcolor='$color{'color20'}'" : "bgcolor='$color{'color22'}'";

print <<END;
				<tr $col>
					<td>$website</td>
					<td>$name</td>
					<td>$category</td>
					<td align='center'><input type='checkbox' name="$blocklist" id="$blocklist"$enable></td>
				</tr>
END
	}

# The save button at the bottom of the table
print <<END;
			</table>

		</div>

		<table style='width:100%;'>
			<tr>
				<td colspan='3' display:inline align='right'><input type='submit' name='ACTION' value='$Lang::tr{'save'}'></td>
			</tr>
		</table>
	</form>
END

	&Header::closebox();
}

#------------------------------------------------------------------------------
# sub manage_xdp_state()
#
# Manage XDP program state based on ENABLE and XDP_ACCEL settings
#------------------------------------------------------------------------------

sub manage_xdp_state {
    my ($old_settings_ref, $new_settings_ref) = @_;
    my %old_settings = %$old_settings_ref;
    my %new_settings = %$new_settings_ref;
    
    my $old_enable = $old_settings{'ENABLE'} || 'off';
    my $new_enable = $new_settings{'ENABLE'} || 'off';
    my $old_xdp = $old_settings{'XDP_ACCEL'} || 'off';
    my $new_xdp = $new_settings{'XDP_ACCEL'} || 'off';
    
    # Check if the secure wrapper exists
    unless (-x $xdp_ctrl) {
        &General::log("XDP Blocklist: Secure wrapper not found or not executable: $xdp_ctrl");
        return;
    }
    
    # Determine what action to take
    if ($new_enable eq 'on' && $new_xdp eq 'on') {
        # XDP should be running
        &General::log("XDP Blocklist: Feature enabled with XDP acceleration, starting/restarting service");
        my $output = &General::system_output($xdp_ctrl, 'restart');
        my $result = $?;
        if ($result == 0) {
            &General::log("XDP Blocklist: Service restarted successfully");
        } else {
            &General::log("XDP Blocklist: Failed to restart service: $output");
        }
    } elsif ($old_enable eq 'on' && $old_xdp eq 'on' && ($new_enable eq 'off' || $new_xdp eq 'off')) {
        # XDP was running but should now be stopped
        &General::log("XDP Blocklist: Feature disabled or XDP acceleration disabled, stopping service");
        my $output = &General::system_output($xdp_ctrl, 'stop');
        my $result = $?;
        if ($result == 0) {
            &General::log("XDP Blocklist: Service stopped successfully");
        } else {
            &General::log("XDP Blocklist: Failed to stop service: $output");
        }
    }
    # Note: If switching from iptables to XDP, XDP will be started above
    # If switching from XDP to iptables, XDP will be stopped above
}

#------------------------------------------------------------------------------
# sub manage_xdp_blocklists()
#
# Manage XDP blocklists based on settings changes
# Updates the BPF map directly (when XDP is loaded) or prepares for next load
#------------------------------------------------------------------------------

sub manage_xdp_blocklists {
	my ($old_settings_ref, $new_settings_ref) = @_;
	my %old_settings = %$old_settings_ref;
	my %new_settings = %$new_settings_ref;
	
	# Only manage XDP blocklists if main feature is enabled AND XDP acceleration is enabled
	if ($new_settings{'ENABLE'} ne 'on' || $new_settings{'XDP_ACCEL'} ne 'on') {
		if ($new_settings{'ENABLE'} ne 'on') {
			&General::log("XDP Blocklist: Main feature disabled, skipping XDP blocklist updates");
		} else {
			&General::log("XDP Blocklist: XDP acceleration disabled, skipping XDP blocklist updates");
		}
		return;
	}
	
	# Check if XDP is currently loaded
	my $xdp_loaded = &is_xdp_loaded();
	
	if (!$xdp_loaded) {
		&General::log("XDP Blocklist: XDP not loaded, blocklist updates will be applied when XDP starts");
		return;
	}
	
	# Loop through all blocklists
	foreach my $blocklist (@blocklists) {
		my $old_state = $old_settings{$blocklist} || 'off';
		my $new_state = $new_settings{$blocklist} || 'off';
		
		# Skip if state hasn't changed
		next if ($old_state eq $new_state);
		
		# Get the blocklist file name
		my $blocklist_file = "$blocklist_dir/$blocklist.conf";
		
		# Check if the blocklist file exists
		if (-f $blocklist_file) {
			# Determine action based on state
			my $action = ($new_state eq 'on') ? 'add' : 'delete';
			
			# Use General::system instead of General::system_output
			my $exit_code = &General::system($xdp_program, $action, $blocklist_file);
			
			if ($exit_code == 0) {
				&General::log("XDP Blocklist: Successfully ${action}ed $blocklist");
			} else {
				&General::log("XDP Blocklist: ${action} $blocklist returned exit code $exit_code");
			}	
		} else {
			# Blocklist file doesn't exist, might need to be downloaded first
			if ($new_state eq 'on') {
				&General::log("XDP Blocklist: File $blocklist_file not found for $blocklist");
			}
		}
	}
}

#------------------------------------------------------------------------------
# sub is_xdp_loaded()
#
# Check if XDP IP blocklist is currently loaded
#------------------------------------------------------------------------------

sub is_xdp_loaded {
    my @output = &General::system_output($xdp_ctrl, 'status');
    
    # Check if ANY element contains "not"
    if (grep { /not/i } @output) {
        &General::log("XDP Blocklist: Found 'not' -> NOT loaded");
        return 0;
    }
    
    &General::log("XDP Blocklist: program Found -> loaded");
    return 1;
}

#------------------------------------------------------------------------------
# sub error()
#
# Shows error messages
#------------------------------------------------------------------------------

sub error {
	&Header::openbox('100%', 'left', $headline);
		print "<class name='base'>$errormessage\n";
		print "&nbsp;</class>\n";
	&Header::closebox();
}
