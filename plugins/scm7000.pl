#-----------------------------------------------------------
# scm7000.pl
# parse Service Control Manager event ID 7000 events
#
# 
# Pivot Points/Analysis: 
#   
#
#
# Change history:
#   20230424 - created
#
# References:
#   
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package scm7000;
use strict;

my %config = (version       => 20230424,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Service Control Manager/7000 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %apps = ();
my %sysname = ();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching scm7000 v.".$VERSION."\n";
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
		
		if ($src eq "Service Control Manager" && $id eq "7000") {
			
			my @s = split(/,/,$str);
			my $app      = $s[0];
			if (exists $apps{$app}) {
				$apps{$app}++;
			}
			else {
				$apps{$app} = 1;
			}
			
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
		print "Services That Have Failed To Start\n";
		printf "%-40s %-10s\n","Service Name","Frequency";
		foreach my $a (keys %apps) {
			printf "%-40s %-10s\n",$a,$apps{$a};
		}
		print "\n";
		print "Analysis Tip: SCM/7000 event records indicate that a service has failed to start\.\n";
	}
	else {
		print "No SCM/7000 events found\.\n";
	}
}
1;