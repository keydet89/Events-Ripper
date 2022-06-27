#-----------------------------------------------------------
# logins.pl
# parse events file for login events
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
package logins;
use strict;

my %config = (version       => 20220622,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/4624 login events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching logins v.".$VERSION."\n";
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
		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4624") {
			
			my @elements = split(/,/,$str);
			my $type = $elements[8];
			
			if ($type == 3) {
				$type3IPs{$elements[18]} = 1 unless ($elements[18] eq "-" || $elements[18] eq "::1");
			}
			
			if ($type == 10) {
				$type10IPs{$elements[18]} = 1;
			}
			
			
			if (exists $types{$type}) {
				$types{$type}++;
			}
			else {
				$types{$type} = 1;
			}
		}
	}
	close(FH);
	
	if (scalar (keys %types) > 0) {
		printf "%-5s %-5s\n","Types","Count";
		foreach my $t (keys %types) {
			printf "%-5d %-5d\n",$t,$types{$t};
		}
	
		if (scalar (keys %type3IPs) > 0) {
			print "\n";
			print "Type 3 Login IPs\n";
			foreach my $i (keys %type3IPs) {
				print "  ".$i."\n";
			}
		}
	
		if (scalar (keys %type10IPs) > 0) {
			print "\n";
			print "Type 10 Login IPs\n";
			foreach my $i (keys %type10IPs) {
				print "  ".$i."\n";
			}
		}
	}
	else {
		print "\n";
		print "No logins found in events file\.\n";
	}
	
}
1;