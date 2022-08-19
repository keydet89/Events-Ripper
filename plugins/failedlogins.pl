#-----------------------------------------------------------
# failedlogins.pl
# parse events file for failed login events
#
# Change history:
#   20220818 - updated to add status codes; report on substatus
#   20220622 - created
#
# References:
#   https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events
#   https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package failedlogins;
use strict;

my %config = (version       => 20220818,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}
sub getShortDescr {
	return "Parse events file for failed login events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %status = ("0xc0000064" => "Logon w/ misspelled/bad account",
              "0xc000006a" => "Logon w/ misspelled/bad password",
              "0xc000006d" => "Bad username/authentication info",
              "0xc000006e" => "Logon restrictions apply",
              "0xc000006f" => "Logon outside auth. hours",
              "0xc0000070" => "Logon from unauth workstation",
              "0xc0000071" => "Logon w/ expired password",
              "0xc0000072" => "Logon to disabled account",
              "0xc00000dc" => "SAM server in incorrect state",
              "0xc0000133" => "Clocks out of sync",
              "0xc000015b" => "User not granted requested logon",
              "0xc000018c" => "Trust relationship failed",
              "0xc0000192" => "NetLogon service not started",
              "0xc0000193" => "User logon w/ expired account",
              "0xc0000224" => "User must change password at next logon",
              "0xc0000225" => "Windows bug",
              "0xc0000234" => "Account locked",
              "0xc00002ee" => "An error occurred",
              "0xc0000413" => "Auth firewall in use",
              "0xc000005e" => "No logon servers available");         

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching failedlogins v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %types = ();
	my %type3IPs = ();
	my %type10IPs = ();
	my %reasons = ();
	
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
			
			my $username = $elements[5];
			my $status = $elements[7];
			my $substatus = $elements[9];
			
			my $str = $username.":".$type.":".$substatus;
			
			if (exists $reasons{$str}){
				$reasons{$str}++;
			}
			else {
				$reasons{$str} = 1;
			}
			
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
	
		printf "%-4s %-5s\n","Type","Count";
		foreach my $t (keys %types) {
			printf "%-4d %-5d\n",$t,$types{$t};
		}
		print "\n";
		printf "%-5s %-16s %-4s %-40s\n","Count","Username","Type","Reason";
		foreach my $i (keys %reasons) {
			my ($u,$t,$s) = split(/:/,$i,3);
			my $r = "";
			
#			print "Status: ".$status{$s}."\n";
			
			if (exists $status{$s}) {
				$r = $status{$s};
			}
			else {
				$r = $s;
			}
				
			
			printf "%-5s %-16s %-4s %-40s\n",$reasons{$i},$u,$t,$r;			
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