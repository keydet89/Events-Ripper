#-----------------------------------------------------------
# dcom10028.pl
# parse DCOM event ID 10028 events
#
# Msg strings: DCOM was unable to communicate with the computer %IP using any configured
#              protocols; requested by PID %pid (%app)
#
# Pivot Points/Analysis: 
#   - Map the PID and time stamp of the entry to process data
#   - Get list of applications used; may not be available in ShimCache, but may be 
#     available in AmCache.hve
#   - IP addresses will list targeted systems
#
#
# Change history:
#   20220930 - updated to output system name
#   20220622 - created
#
# References:
#   https://support.solarwinds.com/SuccessCenter/s/article/Event-10028-DCOM-was-unable-to-communicate-with-the-computer?language=en_US
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package dcom10028;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse DCOM/10028 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching dcom10028 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %dcom = ();
	my %ips = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "DCOM" && $id eq "10028") {
			
			my @s = split(/,/,$str);
			my $ip       = $s[0];
			my $app      = $s[2];
			$dcom{$app} = 1;
			$ips{$ip}   = 1;
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %dcom) > 0) {
		print "Applications\n";
		foreach my $d (keys %dcom) {
			print $d."\n";
		}
		print "\n";
		print "Remote Nodes\n";
		foreach my $i (sort keys %ips) {
			print $i."\n";
		}
		print "\n";
		print "Analysis Tip: A DCOM/10028 error record is generated when a request fails to communicate with a remote node due to\n";
		print "invalid credentials or an invalid WMI namespace\.\n";
		print "\n";
		print "Ref: https://support.solarwinds.com/SuccessCenter/s/article/Event-10028-DCOM-was-unable-to-communicate-with-the-computer?language=en_US\n";
	}
	else {	
		print "No DCOM/100128 events found\.\n";
	}
}
1;