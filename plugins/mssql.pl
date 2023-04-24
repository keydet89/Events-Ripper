#-----------------------------------------------------------
# mssql.pl
# parse MSSQL<instance>/18456 and ../15457 events
#
# Pivot Points/Analysis:
# Plugin is applied to Application Event Logs for systems with an MSSQL instance installed.
# Event ID 18456 records indicated failed login attempts to MSSQL
# Look to event ID 15457 records for indications of the use of the xp_cmdshell stored procedure
#
#
# Change history:
#   20230411 - created
#
# References:
#   
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package mssql;
use strict;

my %config = (version       => 20230411,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse MSSQL<instance>/18456 and ../15457 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching mssql v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	my $count = 0;
	my %sysname = ();
	my %failed = ();
	my %clients = ();
	my %events = ();
	my $count  = 0;
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		my $ms = "MSSQL";

# Start with failed login attempts to the MSSQL instance		
		if ($src =~ m/$ms/ && $id eq "18456") {
			
			my @s = split(/,/,$str);
			my $user = $s[0];
			my $client = $s[2];
# Clean up client IP addresses; messy, kludgy, but works			
			$client =~ s/\[CLIENT:\s//;
			$client =~ s/^\s//;
			$client =~ s/\]//;
			 
			if (exists $failed{$user}) {
				$failed{$user}++;
			}
			else {
				$failed{$user} = 1;
			}
			
			if (exists $clients{$client}) {
				$clients{$client}++;
			}
			else {
				$clients{$client} = 1;
			}
			
			$count++;
			
		}
		elsif ($src =~ m/$ms/ && $id eq "15457") {
			my @s = split(/,/,$str);
			my $e = $s[0];
			
			if (exists $events{$e}) {
				$events{$e}++;
			}
			else {
				$events{$e} = 1;
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
	
	if (scalar keys %failed > 0) {
		print "Failed Login Attempts\n";
		printf "%-20s %-5s\n","Username","Frequency";
		foreach (keys %failed) {
			printf "%-25s %-10s\n",$_,$failed{$_};
		}
		print "\n";
		
		print "Client IP Addresses:\n";
		printf "%-25s %-10s\n","IP Address","Frequency";
		foreach (keys %clients) {
			printf "%-25s %-10s\n",$_,$clients{$_};
		}
		print "\n";
		print "There were a total of ".$count." failed login attempts\.\n";
		print "\n";
		print "Analysis Tip: Repeated failed login attempts my indicate brute force password guessing attempts\.\n";
		print "If these are detected, and originate from public IP addresses, block access to TCP port 1433.\n";
	}
	else {
		print "No MSSQL event ID 18456 records found\.\n";
	}
	print "\n";
	
	if (scalar keys %events > 0) {
		print "MSSQL System Setting Changes\n";
		printf "%-25s %-10s\n","Item","Frequency";
		foreach (keys %events) {
			printf "%-25s %-10s\n",$_,$events{$_};	
		}
		print "\n";
		print "Analysis Tip: If \"xp_cmdshell\" is one of the system setting changes listed, this may indicate the use of\n";
		print "the stored procedure to execute commands on the endpoint, with SYSTEM level privileges\.\n";
		print "\n";
		print "Ref: https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/\n";
	}
	else {
		print "No MSSQL event ID 15457 records found\.\n";
	}
	
}
1;