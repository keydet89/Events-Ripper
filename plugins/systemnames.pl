#-----------------------------------------------------------
# systemnames.pl
# parse events file for login events
#
# Change history:
#   20240708 - added RemoteConnectionManager events
#   20240515 - created
#
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package systemnames;
use strict;

my %config = (version       => 20240708,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse various events for remote/source endpoint names";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching systemnames v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %names      = ();
	my %fnames     = ();
	my %vnames     = ();
	my %snames     = ();
	my %rem        = ();
	my %splash     = ();
	my %sysname    = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4624") {
			
			my @elements = split(/,/,$str);
			my $type = $elements[8];
			
			if ($type == 3 || $type == 10) {
				next if ($elements[11] eq "-" || $elements[11] eq " ");
				if (exists $names{$elements[11]}) {
					$names{$elements[11]}++;
				}
				else {
					$names{$elements[11]} = 1;
				}
				
			}
		}
		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4625") {
			
			my @elements = split(/,/,$str);
			my $type = $elements[10];
			
			if ($type == 3 || $type == 10) {
				next if ($elements[13] eq "-" || $elements[13] eq " ");
				if (exists $fnames{$elements[13]}) {
					$fnames{$elements[13]}++;
				}
				else {
					$fnames{$elements[13]} = 1;
				}
			}
		}

# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4776") {
			
			my @elements = split(/,/,$str);
			next if $elements[2] eq " " || $elements[2] eq "-";
			if (exists $vnames{$elements[2]}) {
				$vnames{$elements[2]}++;
			}
			else {
				$vnames{$elements[2]} = 1;
			}
		}

# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779	
# event ID 4778 - session reconnect
# event ID 4779 - session disconnect
		if ($src eq "Microsoft-Windows-Security-Auditing" && ($id eq "4779" || $id eq "4778")) {
			
			my @elements = split(/,/,$str);
			next if $elements[4] eq " " || $elements[4] eq "-";
			if (exists $snames{$elements[4]}) {
				$snames{$elements[4]}++;
			}
			else {
				$snames{$elements[4]} = 1;
			}	
		}

# requires Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational Event Log		
		if ($src eq "Microsoft-Windows-TerminalServices-RemoteConnectionManager" && $id eq "1149") {
			my @elements = split(/,/,$str);
			next if $elements[1] eq " " || $elements[1] eq "-";
			if (exists $splash{$elements[1]}) {
				$rem{$elements[1]}++;
			}
			else {
				$rem{$elements[1]} = 1;
			}	
		}
		
# requires Splashtop-Splashtop Streamer-Remote Session Event Log
		if ($src eq "Splashtop-Splashtop Streamer-Remote Session" && $id eq "1000") {
			my @elements = split(/,/,$str);
			next if $elements[2] eq " " || $elements[2] eq "-";
			if (exists $splash{$elements[2]}) {
				$splash{$elements[2]}++;
			}
			else {
				$splash{$elements[2]} = 1;
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
	

	if (scalar (keys %names) > 0) {
		print "\n";
		print "System names (type 3 & 10 logins):\n";
		printf "%-20s %-5s\n","Name","Freq";
		foreach my $n (keys %names) {
			printf "%-20s %-5d\n", $n, $names{$n};
		}
	}
	
	if (scalar (keys %fnames) > 0) {
		print "\n";
		print "System names (type 3 & 10 failed login attempts):\n";
		printf "%-20s %-5s\n","Name","Freq";
		foreach my $n (keys %fnames) {
			printf "%-20s %-5d\n", $n, $fnames{$n};
		}
	}	
	
	if (scalar (keys %vnames) > 0) {
		print "\n";
		print "System names (computer attempts to validate credentials):\n";
		printf "%-20s %-5s\n","Name","Freq";
		foreach my $n (keys %vnames) {
			printf "%-20s %-5d\n", $n, $vnames{$n};
		}
	}	
	
	if (scalar (keys %snames) > 0) {
		print "\n";
		print "System names (session reconnect/disconnect):\n";
		printf "%-20s %-5s\n","Name","Freq";
		foreach my $n (keys %snames) {
			printf "%-20s %-5d\n", $n, $snames{$n};
		}
	}	
	
	if (scalar (keys %rem) > 0) {
		print "\n";
		print "RemoteConnectionManager domains/names:\n";
		printf "%-20s %-5s\n","Name","Freq";
		foreach my $n (keys %rem) {
			printf "%-20s %-5d\n", $n, $rem{$n};
		}
	}	
	
	
	if (scalar (keys %splash) > 0) {
		print "\n";
		print "SplashTop Remote Session endpoint names:\n";
		printf "%-20s %-5s\n","Name","Freq";
		foreach my $n (keys %splash) {
			printf "%-20s %-5d\n", $n, $splash{$n};
		}
	}	
	
	
# Now determine intersections between arrays/lists
	if ((scalar (keys %names) > 0) && (scalar (keys %fnames) > 0)) { 
		print "\n";
		my %orig = ();
		my @isect = ();
		map{$orig{$_} = 1} (keys %names);
		@isect = grep {$orig{$_}} (keys %fnames);
		
		if (scalar @isect > 0) {
			print "The intersection of names between successful logins and failed login attempts:\n";
			foreach (@isect) {
				print "$_\n";
			}
		}
	}
	
	if ((scalar (keys %names) > 0) && (scalar (keys %vnames) > 0)) { 
		print "\n";
		my %orig = ();
		my @isect = ();
		map{$orig{$_} = 1} (keys %names);
		@isect = grep {$orig{$_}} (keys %vnames);
		
		if (scalar @isect > 0) {
			print "The intersection of names between successful logins and attempts to validate credentials:\n";
			foreach (@isect) {
				print "$_\n";
			}
		}
	}

}
1;