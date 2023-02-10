#-----------------------------------------------------------
# localsessionips.pl
# parse IPs from LocalSessionManager events
#
# Change history:
#   20230209 - updated with intel
#   20220930 - updated to output system name
#   20220622 - created
#
# References:
#   https://twitter.com/malmoeb/status/1519710302820089857?lang=en-GB
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package localsessionips;
use strict;

my %config = (version       => 20230209,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse LocalSessionManager events for IP addrs";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching localsessionips v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %ips = ();
	my %sysname = ();

# Event IDs
# 21 - session login
# 22 - shell start
# 24 - session disconnect
# 25 - session reconnect

	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-TerminalServices-LocalSessionManager" && ($id eq "21" || $id eq "22" || $id eq "24" || $id eq "25")) {
			my @tags = split(/,/,$str);
			
			if (exists $ips{$tags[2]}) {
				$ips{$tags[2]}++;
			}
			else {
				$ips{$tags[2]} = 1;
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
	
	if (scalar (keys %ips) > 0) {
		printf "%-20s %-10s\n","IP Address","Count";
		foreach my $i (keys %ips) {
			printf "%-20s %-10d\n",$i,$ips{$i};
		}
		print "\n";
		print "Analysis Tip: A Source IP address of \":%16777216\" may indicate the use of ngrok tunneling.\n";
		print "\n";
		print "Ref: https://twitter.com/malmoeb/status/1519710302820089857?lang=en-GB\n";
	}
	else {
		print "No LocalSessionManager events with IP addresses found\.\n";
	}
}
1;