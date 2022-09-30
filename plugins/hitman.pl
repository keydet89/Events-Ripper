#-----------------------------------------------------------
# hitman.pl
# parse Windows Defender event ID 2051 events
#
# Pivot Points/Analysis:
# HitmanPro is a Sophos app that appears to collect a LOT of info about files it
# detects. It also seems that, based on the event contents, it collects telemetry
# from the process, as well.
#
#
# Change history:
#   20220930 - updated to output system name
#   20220622 - created
#
# References:
#   https://www.sophos.com/en-us/products/free-tools/hitmanpro
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package hitman;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse HitmanPro\.Alert/911 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching hitman v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	my $count = 0;
	my %sysname = ();
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "HitmanPro\.Alert" && $id eq "911") {
			my @s = split(/,/,$str);
			print ::format8601Date($tags[0])."Z\n";
			print "  ".$s[9]."\n";		#Application
			print "  ".$s[3]."\n";		#Time stamp - should be the same as when event was generated
			print "  ".$s[10]."\n";		#File created time
			print "  ".$s[11]."\n";		#File modified time
			print "  ".$s[12]."\n";		#Description - from file version info??
#			print "  ".$s[20]."\n";
			print "  ".$s[21]."\n";		#SHA-256 hash
			print "  ".$s[22]."\n";		#SHA-1 hash
			print "  ".$s[23]."\n";		#MD5 hash
			print "\n";
			$count++;
		}

	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if ($count > 0) {
		print "\n";
		print "Analysis Tip: HitmanPro is a free AV product from Sophos, and can provide indications of pre-existing malware infections\.\n";
		
	}
	print "No HitmanPro\.Alert/911 events found\.\n" if ($count == 0);
}
1;