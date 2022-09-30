#-----------------------------------------------------------
# osversion.pl
# determine OS version from EventLog/6009 event
#
# Pivot Points/Analysis:
# The Windows version can help you understand what to expect in various data
# sources, or why you're seeing/not seeing something
#
# Change history:
#		20220930 - updated to output system name
#   20220627 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package osversion;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Determine Windows version from EventLog/6009 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching osversion v.".$VERSION."\n";
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
		
		if ($src eq "EventLog" && $id eq "6009" && ($count == 0)) {
			my @s = split(/,/,$str,5);
			my $out = "Windows version ".$s[0]."".$s[1];
			$out .= " ".$s[2] if ($s[2] ne "");
			$out .= ", ".$s[3]."\n";
			print $out;
			
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
		print "Analysis Tip: Different version/builds of Windows include different information in various event records; knowing the \n";
		print "version helps level-set expectations as to what is and is not available in various data sources\.   \n";
		print "\n";
		print "Ref: https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions\n";
	}
	print "No EventLog/6009 events found\.\n" if ($count == 0);
}
1;