#-----------------------------------------------------------
# sec4697.pl
# Checks for firewall rule deletion events
#
# 
#
# Change history:
#   20220930 - updated to output system names
#   20220928 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sec4697;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/4697 (service install) events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching sec4697 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %serv = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4697") {
			my @elements = split(/,/,$str);
			
			if (exists $serv{$elements[5]}) {
				$serv{$elements[5]}++;
			}
			else {
				$serv{$elements[5]} = 1;
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
	
	if (scalar (keys %serv) > 0) {
		print "Microsoft-Windows-Security-Auditing/4697 (service install) events\n";
		foreach my $n (keys %serv) {
			print $n."\n";
		}
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/4697 (service install) events found in events file\.\n";
	}
	
	print "\n";
	print "Analysis Tip: This plugin lists firewall rule deletion events\. These events may be accompanied by the use of netsh\.exe\.\n";
	print "Check Prefetch files\.\n";
	
}
	
1;