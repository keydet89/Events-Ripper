#-----------------------------------------------------------
# msi.pl
# requires SentinelOne/Operational Event Logs
#
# Change history:
#   20230504 - created
#
# References:
#   http://deusexmachina.uk/evdoco/event.php?event=194
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package msi;
use strict;

my %config = (version       => 20230504,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse MsiInstaller events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching msi v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname  = ();
	my %msi11707 = ();
	my %msi11724 = ();
		
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "MsiInstaller" && $id eq "11707") {
			my @s = split(/,/,$str);
			$msi11707{$tags[0].":".$s[0]} = 1;
			
		}
		elsif ($src eq "MsiInstaller" && $id eq "11724") {
			my @s = split(/,/,$str);
			$msi11724{$tags[0].":".$s[0]} = 1;
		}
# MsiInstaller/1034 events apply to removed applications		
		elsif ($src eq "MsiInstaller" && $id eq "1034") {
			my @s = split(/,/,$str);
			$s[0] =~ s/^"//;
			$msi11724{$tags[0].":".$s[0]." v\.".$s[1]} = 1;
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
	
	if (scalar (keys %msi11707) > 0) {
		print "Applications Installed:\n";
		foreach my $n (keys %msi11707) {
			my ($t,$s) = split(/:/,$n,2);
			printf "%-25s %-60s\n",::format8601Date($t)."Z",$s;
		}
		
	}
	print "\n";
	
	if (scalar (keys %msi11724) > 0) {
		print "Applications Removed:\n";
		foreach my $n (keys %msi11724) {
			my ($t,$s) = split(/:/,$n,2);
			printf "%-25s %-60s\n",::format8601Date($t)."Z",$s;
		}
		
	}
	
}
1;