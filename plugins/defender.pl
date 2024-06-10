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
#   20240610 - added event ID 1119 parsing, extracted files from 1116/1117/1119 events
#   20240112 - added event ID 5013 parsing
#   20230802 - added check for 2050 events
#   20230503 - created
#
# References:
#   https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package defender;
use strict;

my %config = (version       => 20240112,
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
	my %submit     = ();
	my %tamper     = ();
	my %failed     = ();
	my %files_1116 = ();
	my %files_1119 = ();
	
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
				$files_1116{$s[21]} = 1;
			
			}
# added 20240610			
			elsif ($id eq "1119") {
				my @s = split(/,/,$str);
				$failed{$tags[0]} = $id.": ".$s[7];
				$files_1119{$s[21]} = 1;
				
			}
# added 20230802			
			elsif ($id eq "2050") {
				my @s = split(/,/,$str);
				my $str = $s[2]."|".$s[3];
				$submit{$str} = 1;
			}
			elsif ($id eq "2051") {
				my @s = split(/,/,$str);
# get file name and hash
				my $str = $tags[0]."|".$s[2]."|".$s[3];
				$files{$str} = 1;
			}
			elsif ($id eq "5013") {
				my @s = split(/,/,$str);
				$tamper{$tags[0]}{$s[3]."|".$s[2]} = 1 unless ($s[2] eq "Ignored");
				
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
		
		if (scalar (keys %files_1116) > 0) {
			print "\n";
			print "Detected Files:\n";
			foreach my $i (keys %files_1116) {
				print $i."\n";
			}	
		}
	}
	else {
		print "No Defender/1116, 1117 detection events found\.\n";
	}
	
	print "\n";
	
	if (scalar (keys %failed) > 0) {
		print "Windows Defender Failures:\n";
		foreach my $n (reverse sort {$a <=> $b} keys %failed) {
			printf "%-25s %-10s\n",::format8601Date($n),$failed{$n},
		}
		print "\n";
		print "Failed Files:\n";
		foreach my $i (keys %files_1119) {
			print $i."\n";
		}	
		
	}
	else {
		print "No Defender/1119 failure events found.\n";
	}
	
	print "\n";
	
	if (scalar (keys %submit) > 0) {
		print "Files submitted by WinDefend:\n";
		foreach my $i (keys %submit) {
			my @f = split(/\|/,$i,2);
			printf "%-50s SHA-256: %-40s\n",$f[0],$f[1];
		}
		print "\n";
		print "Analysis Tip: Defender/2050 events are generated when Defender is uploads a sample for categorization\.\n";
	}
	else {
		print "No Defender/2050 events found\.\n";
	}
	print "\n";
	
	if (scalar (keys %files) > 0) {
		print "Files that could not be sent by WinDefend:\n";
		foreach my $i (keys %files) {
			my @f = split(/\|/,$i,3);
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
	
	if (scalar (keys %tamper) > 0) {
		print "Tamper Attempts: \n";
		foreach my $i (reverse sort keys %tamper) {
			printf "%-25s \n", ::format8601Date($i)."Z";
			
			foreach my $r (keys %{$tamper{$i}}) {
				my ($w, $v) = split(/\|/,$r);
				print "    ".$w." : ".$v."\n";
			}				
			
		}
		print "\n";
		print "Analysis Tip: Defender/5013 events are generated when attempts are made to modify Windows Defender with Tamper\n";
		print "Protection enabled.\n";
		print "Tamper attempts marked \"Ignored\" by Windows Defender are NOT included\.\n";
	}
	else {
		print "No Defender/5013 events found\.\n";
	}
	print "\n";
	
	
	if (scalar (keys %changes) > 0) {
		print "Modifications to Windows Defender:\n";
		foreach my $m (keys %changes) {
			next if ($m eq "");
			print $m."\n";
		}
		print "\n";
		print "Analysis Tip: Windows Defender/5007 events indicate changes made to Defender. These changes can include the state\n";
		print "of Defender functionality, exclusions, etc.\n";
	}
}
1;