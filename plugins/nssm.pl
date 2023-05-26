#-----------------------------------------------------------
# nssm.pl
# parse nssm events
#
# 
#
# Change history:
#   20230525 - created
#
# References:
#   
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package nssm;
use strict;

my %config = (version       => 20230525,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse nssm events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching nssm v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %nssm = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "nssm") {
			
			push(@{$nssm{$tags[0]}}, $desc)
		}
	
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %nssm) > 0) {
		printf "%-25s %-40s \n","Time","Event ID & Description";
		foreach my $n (reverse sort {$a <=> $b} keys %nssm) {
			foreach my $x (@{$nssm{$n}}) {
				printf "%-25s %-40s\n",::format8601Date($n)."Z", $x;
			}
		}
	
	}
	else {
		print "\n";
		print "No nssm events found in events file\.\n";
	}
	print "\n";
	print "Analysis Tip: nssm is the \"non-sucking service managers\", used as an svrany replacement to create and manage \n";
	print "Windows services.\n";
	print "\n";
	print "Ref: https://nssm.cc/usage\n";

}
	
1;