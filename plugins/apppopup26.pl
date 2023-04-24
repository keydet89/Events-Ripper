#-----------------------------------------------------------
# apppopup26.pl
# parse Application Popup/26 events
#
# Pivot Points/Analysis: 
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
package apppopup26;
use strict;

my %config = (version       => 20230424,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Application Popup/26 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching apppopup26 v.".$VERSION."\n";
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
		
		if ($src eq "Application Popup" && $id eq "26") {
			
			my @s = split(/,/,$str);
			my $app      = (split(/-/,$s[0],2))[0];
			$app =~ s/^\"//;
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
		print "Application Popups\n";
		foreach my $a (keys %apps) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: Application Popup/26 events can provide indications of processes that have crashed or had\n";
		print "issues on a system, and can provide an indication of the existence of malware\.\n";
	}
	else {
		print "No Application Popup/26 events found\.\n";
	}

}
1;