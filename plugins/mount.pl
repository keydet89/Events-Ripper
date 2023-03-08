#-----------------------------------------------------------
# mount.pl
# parse Microsoft-Windows-VHDMP events to get a list of surfaced drives
#
# 
# Change history:
#   20221010 - created
#
# References:
#  
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package mount;
use strict;

my %config = (version       => 20221010,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Get VHD[X]/ISO files mounted";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching mount v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %drives = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-VHDMP" && $id eq "1") {
			my $drv = (split(/,/,$str,3))[0];
			$drives{$drv} = 1;
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %drives) > 0) {
		print "Files mounted (VHD[X], ISO):\n";
		foreach my $a (keys %drives) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Microsoft-Windows-VHDMP/1 events provide a list of files mounted or \"surfaced\".\n";
#		print "\.\n";
	}
	else {
		print "No Microsoft-Windows-VHDMP/1 events found\.\n";
	}
}
1;