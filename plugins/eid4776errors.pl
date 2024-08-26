#-----------------------------------------------------------
# eid4776errors
#
# Change history:
#   20240826 - created
#
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package eid4776errors;
use strict;

my %config = (version       => 20240826,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse event ID 4776 error codes";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching eid4776error v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname    = ();
	
# added 20240826
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776
	my %error = ("0xc0000064" => "Username does not exist",
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
			  "0xc0000371" => "local account store does not contain secret material for the specified account",
              "0xc0000413" => "Auth firewall in use",
              "0xc000005e" => "No logon servers available");
	
	my %auth    = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4776") {
			
			my @elements = split(/,/,$str);
			next if $elements[2] eq " " || $elements[2] eq "-";
			
			if ($elements[3] ne "0x0") {
				my $err = "";
				if (exists $error{$elements[3]}){
					$err = $error{$elements[3]};
				}
				else {
					$err = $elements[3];
				}
				my $str = $elements[1]."/".$elements[2]." - ".$err;
				push(@{$auth{$tags[0]}}, $str);
			}
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %auth) > 0) {
		print "\n";
		print "Validation Failures:\n";
		printf "%-25s %-60s\n","Time","Error";
		foreach my $n (reverse sort keys %auth) {
			printf "%-25s\n",::format8601Date($n)."Z";
			foreach my $i (@{$auth{$n}}) {
				printf "  EID4776           ".$i."\n";
			}
			print "\n";
		}
	}	
}
1;