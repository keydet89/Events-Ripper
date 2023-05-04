#-----------------------------------------------------------
# cleared.pl
# Checks for cleared platform/firewall events
#
# 
# Change history:
#   20230302 - created
#
# References:
#   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
#   https://kb.eventtracker.com/evtpass/evtpages/EventId_104_Microsoft-Windows-Eventlog_64337.asp
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package cleared;
use strict;

my %config = (version       => 20230302,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Check for EventLog cleared events";	
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
			
			$clear{$tags[0]} = $str;
			
			$cleared = 1;
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}

	if ($cleared == 1) {
		foreach my $n (reverse sort keys %clear) {
			printf "%-25s %-40s\n",::format8601Date($n),$clear{$n};
		}
	}
	else {
		print "No Microsoft-Windows-Eventlog/1102 or ../104 events found.\n";
	}
}
	
1;