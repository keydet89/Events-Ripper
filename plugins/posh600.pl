#-----------------------------------------------------------
# posh600.pl
# parse Powershell/600 events for scripts
#
# Pivot Points/Analysis: 
#   
#
# Change history:
#   20230526 - created
#
# References:
#   
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package posh600;
use strict;

my %config = (version       => 20230526,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Powershell/600 events for scripts";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching posh600 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %scripts = ();
	my %sysname = ();
	my $cap     = 5;
	my %hash2   = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "PowerShell" && $id eq "600") {
			
			my @s = split(/,/,$str);
			my $str = $s[10];
			$str =~ s/^\s+//;
			$str =~ s/^HostApplication=//;
			
			my $i = 1;
			my $n = 10;
			while ($i) {
				$n++;
				my $t = $s[$n];
				$s[$n] =~ s/^\s+//;
				
				if ($s[$n] =~ m/^EngineVersion/) {
					$i = 0;
				}
				else {
					$str .= ", ".$s[$n];
				}
			}

			$scripts{$str}{$tags[0]} = 1;
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %scripts) > 0) {
#		print "PowerShell Scripts\n";
		foreach my $a (keys %scripts) {
			if (scalar keys %{$scripts{$a}} < $cap) {
				foreach my $t (keys %{$scripts{$a}}) {
					push (@{$hash2{$t}}, $a);
				}
			}
		}
		
		foreach my $n (reverse sort {$a <=> $b} keys %hash2) {
			foreach my $i (@{$hash2{$n}}) {
				printf "%-25s %-60s\n",::format8601Date($n)."Z", $i;
			}
		}

	}
	else {
		print "No PowerShell/600 events found\.\n";
	}
	print "\n";
	print "Analysis Tip: This plugin extracts PowerShell scripts from event ID 600 records in the Windows PowerShell\.evtx log file.\n";
	print "However, it does not display all of them; to reduce noise, it only displays those that appear at 5 different times or less\n";
	print "in the logs. This is done to prevent flooding the analyst with \"normal\" behaviour and prioritize showing those scripts that \n";
	print "appear less frequently. The value that controls this is \"\$cap\", found on line 42 of the plugin.\n";
#	print "\n";
}
1;

