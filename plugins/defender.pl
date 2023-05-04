#-----------------------------------------------------------
# defender.pl
# parse multiple Windows Defender events
#
# Pivot Points/Analysis:
# This message indicates that WinDefend attempted to upload a file for analysis,
#   but failed/was unable to do so
#
#
# Change history:
#   20230503 - created
#
# References:
#   https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package defender;
use strict;

my %config = (version       => 20230503,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse multiple WinDefend events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching defender v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	my %sysname    = ();
	my %detections = ();
	my %files      = ();
	my %changes    = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Windows Defender") {
			if ($id eq "1116" || $id eq "1117") {
		
				my @s = split(/,/,$str);
				$detections{$tags[0]} = $id.": ".$s[7];
			
			}
			elsif ($id eq "2051") {
				my @s = split(/,/,$str);
# get file name and hash
				my $str = $tags[0]."|".$s[2]."|".$s[3];
				$files{$str} = 1;
			}
			elsif ($id eq "5007") {
				my @s = split(/,/,$str);
				$changes{$s[3]} = 1;
			}
			else {}
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
		print "No Defender/1116, 1117 detection events found\.\n";
	}
	
	print "\n";
	
	if (scalar (keys %files) > 0) {
		print "Files that could not be sent by WinDefend:\n";
		foreach my $i (keys %files) {
			my @f = split(/|/,$i,3);
			printf "%-25s %-50s SHA-256: %-40s\n",$f[0],$f[1],$f[2];
		}
		print "\n";
		print "Analysis Tip: Defender/2051 events are generated when Defender is unable to upload a sample for categorization\.\n";
		print "These events can provide an indication of a file's existence on the system at a date much earlier than a Defender/1116\n";
		print "detection\.\n";
	}
	else {
		print "No Defender/2051 events found\.\n";
	}
	print "\n";
	
	if (scalar (keys %changes) > 0) {
		print "Modifications to Windows Defender:\n";
		foreach my $m (keys %changes) {
			print $m."\n";
		}
		print "\n";
		print "Analysis Tip: Windows Defender/5007 events indicate changes made to Defender. These changes can include the state\n";
		print "of Defender functionality, exclusions, etc.\n";
	}
}
1;