#-----------------------------------------------------------
# def2051.pl
# parse Windows Defender event ID 2051 events
#
# Pivot Points/Analysis:
# This message indicates that WinDefend attempted to upload a file for analysis,
#   but failed/was unable to do so
#
#
# Change history:
#   20220930 - updated to output system name
#   20220622 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package def2051;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse WinDefend/2051 (failure to upload sample) events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching def2051 v.".$VERSION."\n";
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
		
		if ($src eq "Microsoft-Windows-Windows Defender" && $id eq "2051") {
			
			my $t = ::format8601Date($tags[0])."Z";
			
			my @s = split(/,/,$str);
			my $filename = $s[2];
			my $hash     = $s[3];
			
			print "Time: ".$t."\n";
			print "  Filename        : ".$filename."\n";
			print "  SHA-256 Hash    : ".$hash."\n";
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
		print "Analysis Tip: Defender/2051 events are generated when Defender is unable to upload a sample for categorization\.\n";
		print "These events can provide an indication of a file's existence on the system at a date much earlier than a Defender/1116\n";
		print "detection\.\n";
	}
	print "No Defender/2051 events found\.\n" if ($count == 0);
}
1;