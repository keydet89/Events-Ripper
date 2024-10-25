#-----------------------------------------------------------
# cleared.pl
# Checks for cleared platform/firewall events
#
# 
# Change history:
#   20241025 - updated to include Security Event Log full & EventLog service stopped msgs
#   20241014 - updated to handle multiple events in one second
#   20230302 - created
#
# References:
#   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
#   https://kb.eventtracker.com/evtpass/evtpages/EventId_104_Microsoft-Windows-Eventlog_64337.asp
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package cleared;
use strict;

my %config = (version       => 20241014,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Check for important Microsoft-Windows-EventLog events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching cleared v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %clear   = ();
	my %sysname = ();
	my $cleared = 0;
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Eventlog" && ($id eq "1102" || $id eq "104")) {
			my @elements = split(/,/,$str);
			
			my $str = ();
			$str = "Security Event Log cleared by ".$elements[2]."\\".$elements[1] if ($id eq "1102");
			$str = $elements[2]." Event Log cleared by ".$elements[1]."\\".$elements[0] if ($id eq "104");

			push(@{$clear{$tags[0]}}, $str);
			
			$cleared = 1;
		}
		elsif ($src eq "Microsoft-Windows-Eventlog" && $id eq "1104"){
			my $str = "Security Event Log is Full";
			push(@{$clear{$tags[0]}}, $str);
		}
		elsif ($src eq "Microsoft-Windows-Eventlog" && $id eq "1100"){
			my $str = "EventLog Service has shutdown";
			push(@{$clear{$tags[0]}}, $str);
		}
		else {}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}


	if (scalar (keys %clear) > 0) {
		print "\n";
		print "Microsoft-Windows-EventLog Messages (Cleared, Full, Shutdown):\n";
		printf "%-25s %-60s\n","Time","Detection";
		foreach my $i (reverse sort keys %clear) {
			foreach my $x (@{$clear{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
	}
	else {
		print "No WEVTX cleared events found.\n";	
	}

}
	
1;