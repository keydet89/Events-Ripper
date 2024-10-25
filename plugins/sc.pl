#-----------------------------------------------------------
# sc.pl
# parse events to create a list of ScreenConnect instances
#
# 
# Pivot Points/Analysis: 
#   
#
#
# Change history:
#   20241003 - created
#
# References:
#   
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sc;
use strict;

my %config = (version       => 20241003,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse events for ScreenConnect instances";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching sc v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname  = ();
	my %instance = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Service Control Manager") {
			if ($id eq "7045" || $id eq "7036") {
				my $sc = (split(/,/,$str))[0];
				my ($s,$i)  = (split(/ /,$sc))[0,2];
				if ($s eq "ScreenConnect") {
					$i =~ s/^\(//;
					$i =~ s/\)//;
					$instance{$i} = 1;
				}
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
	
	if (scalar (keys %instance) > 0) {
		print "ScreenConnect instance IDs:\n";
		foreach my $n (keys %instance) {
			print $n."\n";
		}
	}
	else {
		print "No Service Control Manager/7036 or ../7045 events found for ScreenConnect\.\n";
	}
	print "\n";

}
1;