#-----------------------------------------------------------
# sec4688.pl
# parse login/logoff events to get session info
#
# 
#
# Change history:
#   20220930 - updated to output system name
#   20220928 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sec4688;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/4688 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching sec4688 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sess = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4688") {
			
			my @elements = split(/,/,$str);
			if (exists $sess{$elements[5]}) {
				$sess{$elements[5]}++;
			}
			else {
				$sess{$elements[5]} = 1;
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
	
	if (scalar (keys %sess) > 0) {
		print "Microsoft-Windows-Security-Auditing/4688 processes created\n";
		foreach my $i (keys %sess) {
			print $i."\n";
		}	 
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/4688 found in events file\.\n";
	}
	print "\n";
	print "Analysis Tip: This plugin lists processes created, but not parent processes, nor user context or login ID.\n";
	
}
	
1;