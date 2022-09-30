#-----------------------------------------------------------
# usrmgr.pl
# 
#
# Change history:
#   20220930 - updated to output system names
#   20220819 - added additional events
#   20220805 - created
#
# References:
#   https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package usrmgr;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse user mgmt events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

# 4720 - user account created
# 4722 - user account enabled
# 4724 - attempt to reset account's password
# 4728 - member added to security-enabled local group
# 4732 - member added to security-enabled global group
# 4756 - member added to security-enabled universal group

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching usrmgr v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname = ();
	
	my $count = 0;
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		my @elements = split(/,/,$str);

# https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720		
		if ($src eq "Microsoft-Windows-Security-Auditing") {
			$count = 1;
			
			if ($id eq "4720") {
				printf "%-20s  %-40s\n",::format8601Date($tags[0])."Z", $elements[0]." user account created";
			}
			
			if ($id eq "4722") {
				printf "%-20s  %-40s\n",::format8601Date($tags[0])."Z", $elements[0]." user account enabled";
			}
			
			if ($id eq "4724") {
				printf "%-20s  %-40s\n",::format8601Date($tags[0])."Z", "attempt to reset ".$elements[0]." account password";
			}
			
			if ($id eq "4726") {
				printf "%-20s  %-40s\n",::format8601Date($tags[0])."Z", $elements[0]." account deleted";
			}
			
#			if ($id eq "4732") {
#				printf "%-20s  %-40s\n",::format8601Date($tags[0])."Z", $elements[0]." user added to security-enabled local group";
#			}
						
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	print "No Security-Auditing events found.\n" if ($count == 0);
}
1;