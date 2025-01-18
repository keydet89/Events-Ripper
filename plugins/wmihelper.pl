#-----------------------------------------------------------
# wmihelper.pl
# Checks for wmihelper service events; useful for post-incident investigations
# 
# Change history:
#   20241211 - created
#
# References:
#  
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package wmihelper;
use strict;

my %config = (version       => 20241211,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Check for WMIHelper Service messages";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching wmihelper v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %wh   = ();
	my %sysname = ();
	
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "WMIHelper" && $id eq "0") {
			my @elements = split(/,/,$str);
			
			push(@{$wh{$tags[0]}}, $str);
		}
		else {}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}


	if (scalar (keys %wh) > 0) {
		print "\n";
		print "WMIHelper Messages:\n";
		printf "%-25s %-60s\n","Time","Message";
		foreach my $i (reverse sort keys %wh) {
			foreach my $x (@{$wh{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
	}
	else {
		print "No WEVTX WMIHelper events found.\n";	
	}

}
	
1;