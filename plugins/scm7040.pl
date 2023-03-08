#-----------------------------------------------------------
# scm7045.pl
# parse Service Control Manager event ID 7040 events, looking for
# services that have been disabled
#
# 
# Pivot Points/Analysis: 
#   
#
#
# Change history:
#   20230308 - created
#
# References:
#   https://www.linkedin.com/posts/john-dwyer-xforce_threathunting-threatdetection-malware-activity-7038997228815867904-F8wj
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package scm7040;
use strict;

my %config = (version       => 20230308,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse SCM/7040 events for disabled services";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %apps = ();
my %sysname = ();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching scm7040 v.".$VERSION."\n";
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
		
		if ($src eq "Service Control Manager" && $id eq "7040") {
			
			my @s = split(/,/,$str);
			if ($s[2] eq "disabled") {
				my $app = $tags[0].":".$s[0];
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
		print "Services with start type changed to \"disabled\":\n";
		foreach my $a (keys %apps) {
			my ($t0,$t1) = split(/:/,$a);
			printf "%-25s %-50s\n",::format8601Date($t0)."Z",$t1;
		}
		print "\n";
		print "Analysis Tip: SCM/7040 events provide indications of services that have been disabled\.\n";
	}
	else {
		print "No services whose start type was changed to \"disabled\" found\.\n";
	}
}
1;