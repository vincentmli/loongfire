#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2007-2020  IPFire Team  <info@ipfire.org>                     #
# Copyright (C) 2024  BPFire <vincent.mc.li@gmail.com>                     #
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

use IO::Socket;

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/location-functions.pl";
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";

#workaround to suppress a warning when a variable is used only once
my @dummy = ( ${Header::colouryellow} );
undef (@dummy);

my %color = ();
my %mainsettings = ();
my %settings=();
my %checked=();
my $errormessage='';
my $successmessage='';
my $setting = "${General::swroot}/main/settings";
my $xdpdnssettingfile = "${General::swroot}/xdpdns/settings";
my $xdpdnsdomainfile = "${General::swroot}/xdpdns/domainfile";
my $xdpdnsallowlistfile = "${General::swroot}/xdpdns/allowlist_file";  # Allowlist file

# Read configuration file.

&General::readhash("${General::swroot}/main/settings", \%mainsettings);
&General::readhash("/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color);

&Header::showhttpheaders();

$settings{'ENABLE_DNSBLOCK'} = 'off';
$settings{'ACTION'} = '';

$settings{'KEY1'} = '';                 # point record for ACTION
$settings{'domainName'} = '';
$settings{'listType'} = 'denylist';     # Track which list we're editing
my @nosaved=('domainName', 'KEY1', 'SORT_domainNameLIST', 'listType');

#Define each field that can be used to sort columns
my $sortstring='^domainName';
$settings{'SORT_domainNameLIST'} = 'domainName';

# Load multiline data for denylist
our @current = ();
if (open(FILE, "$xdpdnsdomainfile")) {
    @current = <FILE>;
    close (FILE);
}

# Load multiline data for allowlist
our @allowlist_current = ();
if (open(FILE, "$xdpdnsallowlistfile")) {
    @allowlist_current = <FILE>;
    close (FILE);
}

&Header::getcgihash(\%settings);

# FIX: Handle list type change before other actions
if ($settings{'ACTION'} eq 'change_list') {
    # Just keep the listType that was passed in
    # Nothing else to do - the listType will be preserved
}

if ($settings{'ACTION'} eq $Lang::tr{'save'})
{

	map (delete ($settings{$_}) ,(@nosaved));
	&General::writehash("$xdpdnssettingfile", \%settings);

	if ($settings{'ENABLE_DNSBLOCK'} eq 'on') {
		&General::system('/usr/bin/touch', "${General::swroot}/xdpdns/enablexdpdns");
		&General::system('/usr/local/bin/xdpdnsctrl', 'start');
		$successmessage = $Lang::tr{'xdpdns started'};
	} else {
		&General::system('/usr/local/bin/xdpdnsctrl', 'stop');
		unlink "${General::swroot}/xdpdns/enablexdpdns";
		$successmessage = $Lang::tr{'xdpdns stopped'};
	}

}

# Handle reload action
if ($settings{'ACTION'} eq $Lang::tr{'reload'}) {
    &General::system('/usr/local/bin/xdpdnsctrl', 'reload');
    &General::log($Lang::tr{'xdpdns reloaded'});
    $successmessage = $Lang::tr{'xdpdns reloaded'};
}

if ($settings{'ACTION'} eq $Lang::tr{'add'}) {
        my $list_ref = ($settings{'listType'} eq 'allowlist') ? \@allowlist_current : \@current;
        my $file = ($settings{'listType'} eq 'allowlist') ? $xdpdnsallowlistfile : $xdpdnsdomainfile;

        #Check for already existing entry
        foreach my $line (@$list_ref) {
                chomp($line);                           # remove newline
                #Same domain already used?
                if($line eq $settings{'domainName'} && $settings{'KEY1'} eq ''){
                        $errormessage = $Lang::tr{'ccd err loxilbconfigeexist'};
                        last;
                }
        }

    unless ($errormessage) {
        if ($settings{'KEY1'} eq '') { #add or edit ?
            unshift (@$list_ref, "$settings{'domainName'}\n");
            &General::log("$settings{'listType'}: $Lang::tr{'xdpdns domain added'}");
        } else {
            @$list_ref[$settings{'KEY1'}] = "$settings{'domainName'}\n";
            $settings{'KEY1'} = '';       # End edit mode
            &General::log("$settings{'listType'}: $Lang::tr{'xdpdns domain changed'}");
        }

        &CreateDomain(%settings);

        # Write changes to config file.
        &SortDataFile;                          # sort newly added/modified entry

        $successmessage = "Domain '$settings{'domainName'}' added to $settings{'listType'}";
        #map ($settings{$_}='' ,@nosaved);      # Clear fields
    }
}

if ($settings{'ACTION'} eq $Lang::tr{'remove'}) {
    my $list_ref = ($settings{'listType'} eq 'allowlist') ? \@allowlist_current : \@current;
    my $file = ($settings{'listType'} eq 'allowlist') ? $xdpdnsallowlistfile : $xdpdnsdomainfile;

    my $line = @$list_ref[$settings{'KEY1'}];     # KEY1 is the index in current
    chomp($line);
    $settings{'domainName'}=$line;

    &DeleteDomain(%settings);

    splice (@$list_ref,$settings{'KEY1'},1);              # Delete line
    open(FILE, ">$file") or die "$file open error";
    print FILE @$list_ref;
    close(FILE);
    $settings{'KEY1'} = '';                             # End remove mode
    
    $successmessage = "Domain '$line' removed from $settings{'listType'}";
}

##  Check if sorting is asked
# If same column clicked, reverse the sort.
if ($ENV{'QUERY_STRING'} =~ /$sortstring/ ) {
    my $newsort=$ENV{'QUERY_STRING'};
    my $actual=$settings{'SORT_domainNameLIST'};
    #Reverse actual sort ?
    if ($actual =~ $newsort) {
        my $Rev='';
        if ($actual !~ 'Rev') {
            $Rev='Rev';
        }
        $newsort.=$Rev;
    }
    $settings{'SORT_domainNameLIST'}=$newsort;
    map (delete ($settings{$_}) ,(@nosaved,'ACTION','KEY1'));# Must never be saved
    &General::writehash($setting, \%settings);
    &SortDataFile;
    $settings{'ACTION'} = 'SORT';                       # Create an 'ACTION'
    map ($settings{$_} = '' ,@nosaved,'KEY1');          # and reinit vars to empty
}

if ($settings{'ACTION'} eq '' ) { # First launch from GUI
    # Place here default value when nothing is initialized
    $settings{'domainName'} = '';
    $settings{'listType'} = 'denylist';
}

# FIX: Ensure listType is properly set after any action
# If listType is not set or empty, default to denylist
if (!$settings{'listType'} || $settings{'listType'} eq '') {
    $settings{'listType'} = 'denylist';
}

&Header::openpage($Lang::tr{'xdpdns'}, 1, '');

&Header::openbigbox('100%', 'left', '', $errormessage);

if ($errormessage) {
	&Header::openbox('100%', 'left', $Lang::tr{'error messages'});
	print "<font class='base' color=red>$errormessage&nbsp;</font>\n";
	&Header::closebox();
}

if ($successmessage) {
	&Header::openbox('100%', 'left', $Lang::tr{'success messages'});
	print "<font class='base' color=green>$successmessage&nbsp;</font>\n";
	&Header::closebox();
}

# Read configuration file.
&General::readhash("$xdpdnssettingfile", \%settings);

# Checkbox pre-selection.
my $checked;
if ($settings{'ENABLE_DNSBLOCK'} eq "on") {
        $checked = "checked='checked'";
}

my $sactive = "<table cellpadding='2' cellspacing='0' bgcolor='${Header::colourred}' width='50%'><tr><td align='center'><b><font color='#FFFFFF'>$Lang::tr{'stopped'}</font></b></td></tr></table>";

my @status = &General::system_output('/usr/local/bin/xdpdnsctrl', 'status');

if (grep(/is attached/, @status)){
        $sactive = "<table cellpadding='2' cellspacing='0' bgcolor='${Header::colourgreen}' width='50%'><tr><td align='center'><b><font color='#FFFFFF'>$Lang::tr{'running'}</font></b></td></tr></table>";
}

&Header::openbox('100%', 'center', $Lang::tr{'xdpdns status'});

print <<END;
        <table width='100%'>
	<form method='POST' action='$ENV{'SCRIPT_NAME'}'>
	<td width='25%'>&nbsp;</td>
	<td width='25%'>&nbsp;</td>
	<td width='25%'>&nbsp;</td>
	<tr><td class='boldbase'>$Lang::tr{'xdpdns status'}</td>
	<td align='left'>$sactive</td>
	</tr>
	<tr>
	<td width='50%' class='boldbase'>$Lang::tr{'xdpdns enable'}
	<td><input type='checkbox' name='ENABLE_DNSBLOCK' $checked></td>
	<td align='center'><input type='submit' name='ACTION' value='$Lang::tr{'save'}'></td>
	</tr>
END

print "</form> </table>\n";

&Header::closebox();

# List type selector
&Header::openbox('100%', 'left', $Lang::tr{'xdpdns list selection'});

# FIX: Properly set the selected option based on listType
my $denylist_selected = ($settings{'listType'} eq 'denylist') ? "selected='selected'" : "";
my $allowlist_selected = ($settings{'listType'} eq 'allowlist') ? "selected='selected'" : "";

print <<END;
<table width='100%'>
<tr>
    <td class='base'><b>$Lang::tr{'xdpdns select list'}:</b></td>
    <td>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='change_list' />
        <select name='listType' onchange='this.form.submit()'>
            <option value='denylist' $denylist_selected>$Lang::tr{'xdpdns denylist'}</option>
            <option value='allowlist' $allowlist_selected>$Lang::tr{'xdpdns allowlist'}</option>
        </select>
        </form>
    </td>
    <td align='right'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'reload'}' />
        <input type='hidden' name='listType' value='$settings{'listType'}' />
        <input type='submit' value='$Lang::tr{'reload'}' />
        </form>
    </td>
</tr>
</table>
END

&Header::closebox();

# Display domain list based on selected type
my $buttontext = $Lang::tr{'add'};
if ($settings{'KEY1'} ne '') {
    $buttontext = $Lang::tr{'update'};
    &Header::openbox('100%', 'left', "$Lang::tr{'xdpdns domain edit'} - $settings{'listType'}");
} else {
    &Header::openbox('100%', 'left', "$Lang::tr{'xdpdns domain add'} - $settings{'listType'}");
}

# Use the appropriate list reference for display
my $display_list_ref = ($settings{'listType'} eq 'allowlist') ? \@allowlist_current : \@current;

print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='KEY1' value='$settings{'KEY1'}' />
<input type='hidden' name='listType' value='$settings{'listType'}' />
<table width='100%'>
<tr>
    <td class='base'>$Lang::tr{'xdpdns domain name'}:&nbsp;</td>
    <td><input type='text' name='domainName' value='$settings{'domainName'}' size='25'/></td>
</tr>

</table>
<br>
<table width='100%'>
<tr>
    <td width='50%' align='right'><input type='hidden' name='ACTION' value='$Lang::tr{'add'}' /><input type='submit' name='SUBMIT' value='$buttontext' /></td>
</tr>
</table>
</form>
END

&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'xdpdns domain entries'} - $settings{'listType'}");

print <<END;

<table width='100%' class='tbl'>
<tr>
    <th width='10%' align='center'><a href='$ENV{'SCRIPT_NAME'}?domainName'><b>$Lang::tr{'xdpdns domain name'}</b></a></th>
    <th width='10%' colspan='3' class='boldbase' align='center'><b>$Lang::tr{'action'}</b></th>
</tr>
END

#
# Print each line of the selected list
#

my $key = 0;
my $col="";
foreach my $line (@$display_list_ref) {
    chomp($line);                               # remove newline

    #Skip empty lines
    next if ($line eq '');

    #Colorize each line
    if ($settings{'KEY1'} eq $key) {
        print "<tr bgcolor='${Header::colouryellow}'>";
    } elsif ($key % 2) {
        print "<tr>";
        $col="bgcolor='$color{'color20'}'";
    } else {
        print "<tr>";
        $col="bgcolor='$color{'color22'}'";
    }
    print <<END;
<td align='center' $col>$line</td>
<td align='center' $col>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
<input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
<input type='hidden' name='KEY1' value='$key' />
<input type='hidden' name='listType' value='$settings{'listType'}' />
</form>
</td>

<td align='center' $col>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
<input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
<input type='hidden' name='KEY1' value='$key' />
<input type='hidden' name='listType' value='$settings{'listType'}' />
</form>
</td>
</tr>
END

    $key++;
}
print "</table>";

# If table contains entries, print 'Key to action icons'
if ($key) {
print <<END;
<table>
<tr>
    <td class='boldbase'>&nbsp;<b>$Lang::tr{'legend'}:&nbsp;</b></td>
    <td><img src='/images/delete.gif' alt='$Lang::tr{'remove'}' /></td>
    <td class='base'>$Lang::tr{'remove'}</td>
</tr>
</table>
END
}

&Header::closebox();

&Header::closebigbox();

&Header::closepage();


## Ouf it's the end !

# Sort the "current" array according to choices
sub SortDataFile
{
    our %entries = ();

    # Sort pair of record received in $a $b special vars.
    # When IP is specified use numeric sort else alpha.
    # If sortname ends with 'Rev', do reverse sort.
    #
    sub fixedleasesort {
        my $qs='';             # The sort field specified minus 'Rev'
        if (rindex ($settings{'SORT_domainNameLIST'},'Rev') != -1) {
            $qs=substr ($settings{'SORT_domainNameLIST'},0,length($settings{'SORT_domainNameLIST'})-3);
            if ($qs eq 'domainName') {
                my @a = split(/\./,$entries{$a}->{$qs});
                my @b = split(/\./,$entries{$b}->{$qs});
                ($b[0]<=>$a[0]) ||
                ($b[1]<=>$a[1]) ||
                ($b[2]<=>$a[2]) ||
                ($b[3]<=>$a[3]);
            } else {
                $entries{$b}->{$qs} cmp $entries{$a}->{$qs};
            }
        } else { #not reverse
            $qs=$settings{'SORT_domainNameLIST'};
            if ($qs eq 'domainName') {
                my @a = split(/\./,$entries{$a}->{$qs});
                my @b = split(/\./,$entries{$b}->{$qs});
                ($a[0]<=>$b[0]) ||
                ($a[1]<=>$b[1]) ||
                ($a[2]<=>$b[2]) ||
                ($a[3]<=>$b[3]);
            } else {
                $entries{$a}->{$qs} cmp $entries{$b}->{$qs};
            }
        }
    }

    # Determine which file to sort based on listType
    my $file = ($settings{'listType'} eq 'allowlist') ? $xdpdnsallowlistfile : $xdpdnsdomainfile;
    my $list_ref = ($settings{'listType'} eq 'allowlist') ? \@allowlist_current : \@current;

    #Use an associative array (%entries)
    my $key = 0;
    foreach my $line (@$list_ref) {
        chomp( $line); #remove newline because can be on field 5 or 6 (addition of REMARK)

        # Build a pair 'Field Name',value for each of the data dataline.
        # Each SORTABLE field must have is pair.
        # Other data fields (non sortable) can be grouped in one

        my @record = ('KEY',$key++,'domainName',$line);
        my $record = {};                                # create a reference to empty hash
        %{$record} = @record;                           # populate that hash with @record
        $entries{$record->{KEY}} = $record;             # add this to a hash of hashes
    }

    open(FILE, ">$file") or die "$file open error";

    # Each field value is printed , with the newline ! Don't forget separator and order of them.
    foreach my $entry (sort fixedleasesort keys %entries) {
        print FILE "$entries{$entry}->{domainName}\n";
    }

    close(FILE);
    # Reload sorted list
    open (FILE, "$file");
    @$list_ref = <FILE>;
    close (FILE);
}

sub manageDomain {
    my ($action, %settings) = @_;
    my $map_path;

    # Determine which map to use based on listType
    if ($settings{'listType'} eq 'allowlist') {
        $map_path = "/sys/fs/bpf/xdp-dns-denylist/domain_allowlist";
    } else {
        $map_path = "/sys/fs/bpf/xdp-dns-denylist/domain_denylist";
    }

    # Initialize variables
    my $command = 'xdp_dns';
    my $domain = $settings{'domainName'};

    #debug and display output in UI
    #my @output  = &General::system_output($command, '-m', $map_path, $action, $domain);
    #$errormessage = join('', @output);
    &General::system($command, '-m', $map_path, $action, $domain);

}

sub CreateDomain {
    my (%settings) = @_;
    manageDomain("add", %settings);
}

sub DeleteDomain {
    my (%settings) = @_;
    manageDomain("delete", %settings);
}
