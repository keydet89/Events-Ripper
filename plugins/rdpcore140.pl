#-----------------------------------------------------------
# rdpcore140.pl
# Parse RdpCoreTS/140 events from the 
#   Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational Event Log
#
# Pivot Points/Analysis:
# 
#
#
# Change history:
#   20230203 - created
#
# References:
#   https://purerds.org/remote-desktop-security/auditing-remote-desktop-services-logon-failures-1/
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package rdpcore140;
use strict;

my %config = (version       => 20230203,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse RdpCoreTS/140 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching rdpcore140 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	my %sysname = ();
	my %sources = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS" && $id eq "140") {
			
#			my $t = ::format8601Date($tags[0])."Z";
			
			my $ip = (split(/,/,$str))[0];
			if (exists $sources{$ip}) {
				$sources{$ip}++;
			}
			else {
				$sources{$ip} = 1;
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
	
	if (scalar (keys %sources) > 0) {
		print "Source IP addresses for RDP failed login attempts\n";
		printf "%-20s %-10s\n","IP Address","# Occurred";
		foreach my $n (keys %sources) {
			printf "%-20s %-10s\n",$n,$sources{$n};
			
		}

		print "\n";
		print "Analysis Tip: RdpCoreTS/140 events are recorded for failed attempts to log into RDP\.\n";
		print "The events reportedly indicate when the username does NOT exist.\n\n";
		print "Ref: https://purerds.org/remote-desktop-security/auditing-remote-desktop-services-logon-failures-1/\n";
	}
	else {
		print "No RdpCoreTS/140 events found\.\n";
	}
}
1;