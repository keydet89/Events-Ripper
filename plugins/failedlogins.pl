#-----------------------------------------------------------
# failedlogins.pl
# parse events file for failed login events
#
# Change history:
#   20220622 - created
#
# References:
#   https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package failedlogins;
use strict;

my %config = (version       => 20220622,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}
sub getShortDescr {
	return "Parse events file for failed login events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching failedlogins v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %types = ();
	my %type3IPs = ();
	my %type10IPs = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4625") {
			my @elements = split(/,/,$str);
			my $type = $elements[10];
			
			if (exists $types{$type}) {
				$types{$type}++;
			}
			else {
				$types{$type} = 1;
			}
			
			if ($type == 3) {
				$type3IPs{$elements[19]} = 1 unless ($elements[19] eq "-" || $elements[19] eq "::1");
			}
			
			if ($type == 10) {
				$type10IPs{$elements[19]} = 1;
			}

		}
	}
	close(FH);
	
	if (scalar (keys %types) > 0) {
	
		print "Failed Login Types\n";
		foreach my $t (keys %types) {
			printf "%-2d %-4d\n",$t,$types{$t};
		}
		
		if (scalar (keys %type3IPs) > 0) {
			print "\n";
			print "Type 3 Login IPs\n";
			foreach my $i (sort keys %type3IPs) {
				print "  ".$i."\n";
			}
			print "\n";
			print "Analysis Tip: Failed login attempts from public IP addresses indicates that SMB/NetBIOS is accessible from the Internet\.\n";
		}
		
		if (scalar (keys %type10IPs) > 0) {
			print "\n";
			print "Type 10 Login IPs\n";
			foreach my $i (keys %type10IPs) {
				print "  ".$i."\n";
			}
			print "\n";
			print "Analysis Tip: Failed login attempts from public IP addresses indicates that RDP/TermServ is accessible from the Internet\.\n";
		}
		
	}
	else {
		print "No failed logins found\.\n";
	}
}
1;