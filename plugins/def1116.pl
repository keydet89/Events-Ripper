#-----------------------------------------------------------
# def1116.pl
# parse Windows Defender event ID 1116/1117 events
#
# Pivot Points/Analysis:
# This message indicates that WinDefend attempted to upload a file for analysis,
#   but failed/was unable to do so
#
#
# Change history:
#   20230130 - created
#
# References:
#   https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package def1116;
use strict;

my %config = (version       => 20230130,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse WinDefend/1116, ../1117 detection events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching def1116 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	my %sysname = ();
	my %detections = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Windows Defender" && ($id eq "1116" || $id eq "1117")) {
			
#			my $t = ::format8601Date($tags[0])."Z";
			
			my @s = split(/,/,$str);
			my $detection = $s[7];
			
			$detections{$tags[0]} = $id.": ".$detection;
		}
		
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %detections) > 0) {
		
		foreach my $n (reverse sort {$a <=> $b} keys %detections) {
			printf "%-25s %-10s\n",::format8601Date($n),$detections{$n},
			
		}

		print "\n";
		print "Analysis Tip: Defender/1116 & 1117 events are generated when Windows Defender detects/takes action on malware\.\n\n";
		print "Microsoft-Windows-Windows Defender/1116 - malware detected\n";
		print "Microsoft-Windows-Windows Defender/1117 - action taken\n";
	}
	else {
		print "No Defender/1116, 1117 events found\.\n";
	}
}
1;