#-----------------------------------------------------------
# sec4948.pl
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
package sec4948;
use strict;

my %config = (version       => 20220928,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/4948 (firewall rule deletion) events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching sec4948 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %rules = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4948") {
			$str =~ s/\"//g;
			my @elements = split(/,/,$str);
			
			my $profile = join(",",@elements[0..$#elements-2]);
			my $rulename = $elements[(scalar @elements - 1)];
			
			push(@{$rules{$tags[0]}}, $profile."|".$rulename);
			
#			printf "%-22s %-25s %-40s\n",::format8601Date($tags[0])."Z",$profile,$rulename;
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}

	if (scalar (keys %rules) > 0) {
		printf "%-22s %-25s %-40s\n","Date","Profile","Rule Deleted";
		foreach my $n (reverse sort {$a <=> $b} keys %rules) {
			foreach my $x (@{$rules{$n}}) {
				my @str = split(/\|/,$x);
#				next if ($str[0] =~ m/\$$/ || $str[0] eq "-\\-");
				printf "%-22s %-25s %-40s\n",::format8601Date($n)."Z", $str[0],$str[1];
			}
		}
	
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/4948 (firewall rule deletion) events found in events file\.\n";
	}
	
	print "\n";
	print "Analysis Tip: This plugin lists firewall rule deletion events\. These events may be accompanied by the use of netsh\.exe\.\n";
	print "Check Prefetch files\.\n";
	
}
	
1;