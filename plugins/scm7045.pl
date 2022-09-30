#-----------------------------------------------------------
# scm7045.pl
# parse Service Control Manager event ID 7045 events
#
# 
# Pivot Points/Analysis: 
#   
#
#
# Change history:
#   20220930 - updated output for system name
#   20220622 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package scm7045;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse SCM/7045 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %apps = ();
my %sysmain = ();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching scm7045 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Service Control Manager" && $id eq "7045") {
			
			my @s = split(/,/,$str);
			my $app      = $s[1];
			$apps{$app} = 1;
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
		print "Installed Services\n";
		foreach my $a (keys %apps) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Installed services may provide indications of malicious persistence\.\n";
	}
	else {
		print "No installed service events found\.\n";
	}
}
1;