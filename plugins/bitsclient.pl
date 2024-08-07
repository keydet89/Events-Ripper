#-----------------------------------------------------------
# bitsclient.pl
# Gets info from BITS-Client/3 and /59 events
#
# 
#
# Change history:
#	20240807 - updated to list job names
#   20230523 - updated filtering of known-good domains for event ID 59 events
#   20220930 - updated to display system name(s)
#   20220928 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package bitsclient;
use strict;

my %config = (version       => 20240807,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Gets info from BITS-Client/3 and /59 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching bitsclient v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %created_jobs = ();
	my %urls         = ();
	my %sysname      = ();
	my %names        = ();
	
	my @hosts = ("http://edgedl\.me\.gvt1\.com",
				 "http://redirector\.gvt1\.com",
				 "http://download\.windowsupdate\.com",
				 "http://storage\.googleapis\.com",
				 "http://msedge\.b\.tlu\.dl\.delivery\.mp\.microsoft\.com",
				 "https://g\.live\.com");
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Bits-Client" && $id eq "3") {
			my @elements = split(/,/,$str);
			$names{$elements[0]} = 1;
			if (exists $created_jobs{$elements[3]}) {
				$created_jobs{$elements[3]}++;
			}
			else {
				$created_jobs{$elements[3]} = 1;
			}
		}
		elsif ($src eq "Microsoft-Windows-Bits-Client" && $id eq "59") {
			my @elements = split(/,/,$str);
			$names{$elements[1]} = 1;
			my $count = 0;
			foreach my $h (@hosts) {
#				print "URL: ".$elements[3]." - Checked item: ".$h."\n";
				if ($elements[3] =~ m/^$h/) {
					$count = 1;
				}
			}
			

			if ($count == 0) {
			
				if (exists $urls{$elements[3]}) {
					$urls{$elements[3]}++;
				}
				else {
					$urls{$elements[3]} = 1;
				}
			}				
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
	
	if (scalar keys %created_jobs > 0) {
		print "BITS-Client/3 jobs\n";
		foreach my $i (keys %created_jobs) {
			print $i."\n";
		}
		print "\n";
	}
	else {
		 print "No Microsoft-Windows-Bits-Client/3 (job created) events found in the events file\.\n";
	}
	
	if (scalar keys %urls > 0) {
		print "URLs from BITS-Client/59 transfer jobs\n";
		foreach my $i (keys %urls) {
			print $i."\n";
		}
		print "\n";
		
	}
	else {
		 print "No Microsoft-Windows-Bits-Client/59 (transfer job started) events found in the events file\.\n";
	}
	
	if (scalar keys %names > 0) {
		print "BITS Client job names: \n";
		foreach (keys %names) {
			print $_."\n";
		}
	}
	else {
		print "No BITS Client jobs names found.\n";
	}
	
	print "\n";
	print "Analysis Tip: This plugin lists BITS Client jobs created, and URLs from BITS transfer jobs, filtering out known-good \n";
	print "domains\. Also, look for unusual job names, such as \"debjob\"\n";
	print "\n";
}
	
1;