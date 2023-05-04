#-----------------------------------------------------------
# filter.pl
# Parse Security-Auditing/5156, /5158 events
#
# 
#
# Change history:
#   20230503 - created
#
# References:
#   
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package filter;
use strict;

my %config = (version       => 20230503,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/5156, /5158 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching filter v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname = ();
	my %conn    = ();
	my %bind    =();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Security-Auditing") {
# Windows Filtering Platform permitted a connection
# https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156
			if ($id eq "5156") {
				my $i = (split(/,/,$str))[1];
				$conn{$i} = 1;
			
			}
# Windows Filtering Platform permitted a bind to a local port
# https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5158
			elsif ($id eq "5158") {
				my $i = (split(/,/,$str))[1];
				$bind{$i} = 1;
	
			}
			else {}
			
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}

	if (scalar (keys %conn) > 0) {
		printf "Windows Filtering Platform permitted a connection:\n";
		foreach my $n (keys %conn) {
			print $n."\n";
		}
		print "\n";
		print "Analysis Tip: Each of the listed applications was permitted by WFP to make a connection.\n";
	
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/5156 events found in events file\.\n";
	}
	
	print "\n";
	
	if (scalar (keys %bind) > 0) {
		printf "Windows Filtering Platform permitted an app to bind to a local port:\n";
		foreach my $n (keys %bind) {
			print $n."\n";
		}
		print "\n";
		print "Analysis Tip: Each of the listed applications was permitted by WFP to bind to a local port.\n";
	
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/5158 events found in events file\.\n";
	}
	
}
	
1;