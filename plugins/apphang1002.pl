#-----------------------------------------------------------
# apphang1002.pl
# parse Windows Error Reporting event ID 10028 events
#
# Pivot Points/Analysis: 
#   - look for unusual applications that have crashed 
#
# Change history:
#   20220930 - updated to output system name
#   20220622 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package apphang1002;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Application Hang/1002 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching apphang1002 v.".$VERSION."\n";
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
		
		if ($src eq "Application Hang" && $id eq "1002") {
			
			my @s = split(/,/,$str);
			my $app      = $s[5];
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
		print "Applications\n";
		foreach my $a (keys %apps) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Application Hang/1002 events can provide indications of processes that have crashed or had\n";
		print "issues on a system, and can provide an indication of the existence of malware\.\n";
	}
	else {
		print "No Application Hang/1002 events found\.\n";
	}

}
1;