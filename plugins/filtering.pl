#-----------------------------------------------------------
# filtering.pl
# Checks for filtering platform/firewall events
# 
#  Note: '%%14593' => Outbound, '%%14592' => Inbound
#
# 
# Change history:
#   20230302 - created
#
# References:
#   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157
#   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156
#   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5152
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package filtering;
use strict;

my %config = (version       => 20230302,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse filtering platform events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching filtering v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %apps    = ();
	my %source  = ();
	my %dest    = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

# Blocking events
# https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "5157") {
			my @elements = split(/,/,$str);

# Populate applications list			
			if (exists $apps{$elements[1]}) {
				$apps{$elements[1]}++;
			}
			else {
				$apps{$elements[1]} = 1;
			}
# Populate source IPs list
			if (exists $source{$elements[3]}) {
				$source{$elements[3]}++;
			}
			else {
				$source{$elements[3]} = 1;
			}

# Populate destination IPs list
			if (exists $dest{$elements[5]}) {
				$dest{$elements[5]}++;
			}
			else {
				$dest{$elements[5]} = 1;
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

# Print stats from Microsoft-Windows-Security-Auditing/5157 events
	if (scalar (keys %apps) > 0) {
		print "Microsoft-Windows-Security-Auditing/5157 (filtering blocked) events\n";
		printf "%-8s  %-40s\n","Freq","Application";
		printf "%-8s  %-40s\n","----","-----------";
		foreach my $n (keys %apps) {
			printf "%-8s  %-40s\n",$apps{$n},$n;
		}
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/5157 (filtering blocked) events found in events file\.\n";
	}
	print "\n";
	
	if (scalar (keys %source) > 0) {
		print "Source IP addresses\n";
		printf "%-8s  %-40s\n","Freq","Source IP";
		printf "%-8s  %-40s\n","----","---------";
		foreach my $n (keys %source) {
			printf "%-8s  %-40s\n",$source{$n},$n;
		}
	}
		print "\n";
	
	if (scalar (keys %dest) > 0) {
		print "Destination IP addresses\n";
		printf "%-8s  %-40s\n","Freq","Destination IP";
		printf "%-8s  %-40s\n","----","--------------";
		foreach my $n (keys %dest) {
			printf "%-8s  %-40s\n",$dest{$n},$n;
		}
	}
	
	print "\n";
	print "Analysis Tip: \n";
	print "\n";
	
}
	
1;