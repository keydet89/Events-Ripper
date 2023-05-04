#-----------------------------------------------------------
# appissue.pl
# parse Application Hang/Error events
#
# Pivot Points/Analysis: 
#   - look for unusual applications that have crashed 
#
# Change history:
#   20230504 - updated to include Application Error/1000 events
#   20220930 - updated to output system name
#   20220622 - created
#
# References:
#   
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package appissue;
use strict;

my %config = (version       => 20230504,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Application Hang/Error events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching appissue v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname  = ();
	my %apps1002 = ();
	my %apps1000 = ();
	my %wer1001  = ();
	
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
			$apps1002{$s[5]} = 1;
		}
		elsif ($src eq "Application Error" && $id eq "1000") {
			my @s = split(/,/,$str);
			$apps1000{$s[10]} = 1;
		}
		elsif ($src eq "Windows Error Reporting" && $id eq "1001") {
			my @s = split(/,/,$str);
			$wer1001{$s[5]} = 1;
		}
		else {}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
	}
	print "\n";
	
	if (scalar (keys %apps1002) > 0) {
		print "Application Hang/1002 events:\n";
		foreach my $a (keys %apps1002) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Application Hang/1002 events can provide indications of processes that have crashed or had\n";
		print "issues on a system, and can provide an indication of the existence of malware\.\n";
	}
	else {
		print "No Application Hang/1002 events found\.\n";
	}
	print "\n";
	
	if (scalar (keys %apps1000) > 0) {
		print "Application Error/1000 events:\n";
		foreach my $a (keys %apps1000) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Application Error/1000 events can provide indications of processes that have crashed or had\n";
		print "issues on a system, and can provide an indication of the existence of malware\.\n";
	}
	else {
		print "No Application Error/1000 events found\.\n";
	}
	print "\n";
	
	if (scalar (keys %wer1001) > 0) {
		print "Windows Error Reporting/1001 events:\n";
		foreach my $a (keys %wer1001) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Windows Error Reporting/1001 events can provide indications of processes that have crashed or had\n";
		print "issues on a system, and can provide an indication of the existence of malware\.\n";
	}
	else {
		print "No Windows Error Reporting/1001 events found\.\n";
	}

}
1;