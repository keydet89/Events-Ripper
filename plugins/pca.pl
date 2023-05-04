#-----------------------------------------------------------
# pca.pl
# 
#
# 
#
# Change history:
#   20230303 - created
#
# References:
#   
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package pca;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Gets info from Program Compat Asst Event Log";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching pca v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %app = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Program-Compatibility-Assistant" && $id eq "17") {
			my @elements = split(/,/,$str);
			
			if (exists $app{$elements[0]}) {
				$app{$elements[0]}++;
			}
			else {
				$app{$elements[0]} = 1;
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
	
	if (scalar keys %app > 0) {
		print "Program Compatibility Assistant:\n";
		printf "%-5s %-50s\n","Freq","Program";
		printf "%-5s %-50s\n","----","-------";
		foreach my $i (keys %app) {
			printf "%-5s %-50s\n",$app{$i},$i;
		}
		print "\n";
	}
	else {
		 print "No Microsoft-Windows-Program-Compatibility-Assistant/17 events found in the events file\.\n";
	}
	
	print "\n";
	print "Analysis Tip: This plugin extracts names of programs processed by the Program Compatibility Assistant\.\n";
	print "This can be useful as a means for detecting malware, or potentially suspicious programs.\n";
	print "\n";
}
	
1;