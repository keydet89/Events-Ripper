#-----------------------------------------------------------
# ntfs.pl
# parse Microsoft-Windows-Ntfs/Operational events to get a list of volumes
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
package ntfs;
use strict;

my %config = (version       => 20221010,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Get NTFS volumes";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching ntfs v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %volumes = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Ntfs" && $id eq "145") {
			my @s = split(/,/,$str);
			if ($s[2] == 2) {
				my $vol = $s[3]."\\ - ".$s[8]." ".$s[10];
				$volumes{$vol} = 1;
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
	
	if (scalar (keys %volumes) > 0) {
		print "Mounted Volumes:\n";
		foreach my $a (sort keys %volumes) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Microsoft-Windows-Ntfs/145 events provide a list of mounted volumes.\n";
	}
	else {
		print "No Microsoft-Windows-Ntfs/145 events found\.\n";
	}
}
1;