#-----------------------------------------------------------
# tsgateway.pl
# Parse Microsoft-Windows-TerminalServices-Gateway/Operational.evtx for 
#   event ID 200 and 303 events
#   
#
# Pivot Points/Analysis:
# 
#
#
# Change history:
#   20230209 - created
#
# References:
#   https://kb.eventtracker.com/evtpass/evtPages/EventId_200_Microsoft-Windows-TerminalServices-Gateway_67344.asp
#   https://kb.eventtracker.com/evtpass/evtpages/EventId_303_Microsoft-Windows-TerminalServices-Gateway_67337.asp
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package tsgateway;
use strict;

my %config = (version       => 20230209,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse TSGateway events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching tsgateway v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	my %sysname = ();
	my %sources = ();
	my %sessions = ();
	my $count = 0;
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-TerminalServices-Gateway" && $id eq "200") {
			
#			my $t = ::format8601Date($tags[0])."Z";			
			my $ip = (split(/,/,$str))[1];
			if (exists $sources{$ip}) {
				$sources{$ip}++;
			}
			else {
				$sources{$ip} = 1;
			}
			
		}
		elsif ($src eq "Microsoft-Windows-TerminalServices-Gateway" && $id eq "303") {
			$count++;
			my @items = split(/,/,$str);
			$sessions{$tags[0]} = "User: ".$items[0]."|".$items[1]."| Bytes sent: ".$items[5]."| Bytes rcvd: ".$items[4]."| Duration: ".$items[6]." sec";
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %sources) > 0) {
		print "Source IP addresses for RDP Gateway logins\n";
		printf "%-20s %-10s\n","IP Address","# Occurred";
		foreach my $n (sort {$a <=> $b} keys %sources) {
			printf "%-20s %-10s\n",$n,$sources{$n};
		}

		print "\n";
		print "Analysis Tip: TSGateway/200 events provide information about logins to the TS gateway\n";
		print "\n";
		print "Ref: https://kb.eventtracker.com/evtpass/evtPages/EventId_200_Microsoft-Windows-TerminalServices-Gateway_67344.asp\n";
	}
	else {
		print "No TSGateway/200 events found\.\n";
	}
	print "\n";
	
	if (scalar (keys %sessions) > 0) {
		
		printf "%-25s %-50s\n","Login Time","Session Info";
		foreach my $n (reverse sort {$a <=> $b} keys %sessions) {
			printf "%-25s %-50s\n",::format8601Date($n)."Z",$sessions{$n};
		}
		print "\n";
		print "Analysis Tip: TSGateway/303 events provide information about sessions on the TS gateway\n";
		print "\n";
		print "Ref: https://intelligentsystemsmonitoring.com/knowledgebase/windows-operating-system/event-id-rd-gateway-server-connections-13429/\n";
	}
	else {
		print "No TSGateway/303 events found\.\n";
	}
}
1;