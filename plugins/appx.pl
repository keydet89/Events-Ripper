#-----------------------------------------------------------
# appx.pl
# Requires Microsoft-Windows-AppXDeployment-Server%4Operational.evtx log file
#
# 
#
# Change history:
#   20240528 - created
#
# References:
#   
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package appx;
use strict;

my %config = (version       => 20240528,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "AppX Package Installation via MSIX";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching appx v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %appx     = ();
	my %sysname  = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-AppXDeployment-Server" && $id eq "400") {	
			my @items = split(/,/,$str);
			push(@{$appx{$tags[0]}}, $items[1]." - ".$items[22])
		}	
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %appx) > 0) {
		print "Installed MSIX Packages \n";
		printf "%-25s %-60s\n","Time","Package - File";
		foreach my $i (reverse sort keys %appx) {
			foreach my $x (@{$appx{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}	 
	}
	else {
		print "\n";
		print "No Microsoft-Windows-AppXDeployment-Server/400 events found in events file\.\n";
	}
}
	
1;