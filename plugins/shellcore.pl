#-----------------------------------------------------------
# shellcore.pl
# parse Shell-Core event ID 9707 events to get a list of apps run via Run/RunOnce keys
#
# Pivot Points/Analysis: 
#   - look for unusual applications launched via Run/RunOnce keys
#
# 9705 - begin enumeration of <key>
# 9706 - completed enumeration of <key>
#
# Change history:
#   20220930 - updated to output system name
#   20220629 - created
#
# References:
#   https://nasbench.medium.com/finding-forensic-goodness-in-obscure-windows-event-logs-60e978ea45a3
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package shellcore;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Get apps run via Run/RunOnce keys";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching shellcore v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %apps = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Shell-Core" && $id eq "9707") {
			
			$apps{$str} = 1;
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %apps) > 0) {
		print "Applications launched via Run/RunOnce keys:\n";
		foreach my $a (keys %apps) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Microsoft-Windows-Shell-Core/9797 events provide a list of apps run via the Run/RunOnce keys.\n";
#		print "\.\n";
	}
	else {
		print "No Shell-Core/9707 events found\.\n";
	}
}
1;