#-----------------------------------------------------------
# restarts.pl
# determine system shutdowns/starts from EventLog/6005 and /6006 events
#
# Pivot Points/Analysis:
# This message indicates that WinDefend attempted to upload a file for analysis,
#   but failed/was unable to do so
#
#
# Change history:
#   20220930 - updated to output system name
#   20220627 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package restarts;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Determine system restarts from EventLog/6006 & ../6005 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching restarts v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %restart = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "EventLog" && ($id eq "6006" || $id eq "6005")) {
			
			$restart{$tags[0]} = "EventLog Service started" if ($id eq "6005");
			$restart{$tags[0]} = "EventLog Service stopped" if ($id eq "6006");
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %restart) > 0) {
		
		foreach my $r (reverse sort keys %restart) {
			printf "%-30s %-30s\n",::format8601Date($r)."Z",$restart{$r};
		}
		
		print "\n";
		print "Analysis Tip: Mapping EventLog/6006 and ../6005 events allows us to see when the system was\n";
		print "shutdown and restarted\. \n";
		
	}
	
}
1;