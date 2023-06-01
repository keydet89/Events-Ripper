#-----------------------------------------------------------
# timechange.pl
# Check for Security-Auditing/4616 events indicating that the system clock was changed
#
# 
#
# Change history:
#   20230601 - created
#
# References:
#   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4616
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package timechange;
use strict;

my %config = (version       => 20230601,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/616 (system clock changed) events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching timechange v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname = ();
	my %u       = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4616") {
			my @s = split(/,/,$str);
			my $user = $s[2]."\\".$s[1];
			my $from = (split(/\./,$s[4],2))[0];
			my $to   = (split(/\./,$s[5],2))[0];
			my $proc = $s[7];
			
#			print "User: ".$user."\n";
			
			if ($from ne $to) {
				my $n = $user."|".$from."|".$to."|".$proc;
				$u{$tags[0]}{$n} = 1;
			}
			else {
# do nothing; the time change is too small to worth mentioning				
				
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
	
	if (scalar (keys %u) > 0) {
		printf "%-25s %-30s %-25s %-25s %-40s\n","Time of Event","User","Changed From","Changed To","Process";
		foreach my $n (reverse sort {$a <=> $b} keys %u) {
			
			foreach my $i (keys %{$u{$n}}) {
				my @r = split(/\|/,$i,4);
				$r[1] =~ s/T/ /;
				$r[1] .= "Z";
				$r[2] =~ s/T/ /;
				$r[2] .= "Z";
				printf "%-25s %-30s %-25s %-25s %-40s\n",::format8601Date($n)."Z",$r[0],$r[1],$r[2],$r[3];
			}
		}
		print "\n";
		print "Analysis Tip: Changes to the system clock can appear in the Security Event Log as event ID 4616 records. This plugin\n";
		print "oarses the events file for such events, bypassing sub-second clock adjustments, which are often normal activity. \n";
		print "Changes to the system clock are often made to obscure activity.\n";
		print "\n";
		print "Ref: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4616\n";
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/4616 events found in events file\.\n";
	}
	
}
	
1;