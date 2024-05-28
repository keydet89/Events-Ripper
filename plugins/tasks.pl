#-----------------------------------------------------------
# tasks.pl
# 
#
# 
#
# Change history:
#   20230921 - created
#   20240528 - added TaskScheduler/322 events
#
# References:
#   https://kb.eventtracker.com/evtpass/evtpages/EventId_322_Microsoft-Windows-TaskScheduler_61819.asp
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package tasks;
use strict;

my %config = (version       => 20240528,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "SchedTask Registered, Deleted events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching tasks v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %reg      = ();
	my %del      = ();
	my %already  = ();
	my %sysname  = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-TaskScheduler" && $id eq "106") {	
			my ($task,$user) = split(/,/,$str,2);
			my $s = $tags[0]."|".$task."|".$user;
			if (exists $reg{$s}) {
				$reg{$s}++;
			}
			else {
				$reg{$s} = 1;
			}
		}
		elsif ($src eq "Microsoft-Windows-TaskScheduler" && $id eq "322") {
			my $task = (split(/,/,$str,2))[0];
			if (exists $already{$task}) {
				$already{$task}++;
			}
			else {
				$already{$task} = 1;
			}
		}
		elsif ($src eq "Microsoft-Windows-TaskScheduler" && $id eq "141") {
			my ($task,$user) = split(/,/,$str,2);
			my $s = $tags[0]."|".$task."|".$user;
			if (exists $del{$s}) {
				$del{$s}++;
			}
			else {
				$del{$s} = 1;
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
	
	if (scalar (keys %reg) > 0) {
		print "Microsoft-Windows-TaskScheduler/106 - Scheduled Task Registered\n";
		printf "%-25s %-60s %-20s\n","Time","Task","User";
		foreach my $i (reverse sort {$a <=> $b} keys %reg) {
			my @r = split(/\|/,$i,3);
			printf "%-25s %-60s %-20s\n",::format8601Date($r[0])."Z",$r[1],$r[2];
		}	 
	}
	else {
		print "\n";
		print "No Microsoft-Windows-TaskScheduler/106 events found in events file\.\n";
	}
	
	
	if (scalar (keys %del) > 0) {
		print "\n";
		print "Microsoft-Windows-TaskScheduler/141 - Scheduled Task Deleted\n";
		printf "%-25s %-60s %-20s\n","Time","Task","User";
		foreach my $i (reverse sort {$a <=> $b} keys %del) {
			my @r = split(/\|/,$i,3);
			printf "%-25s %-60s %-20s\n",::format8601Date($r[0])."Z",$r[1],$r[2];
		}

	}
	else {
		print "\n";
		print "No Microsoft-Windows-TaskScheduler/141 events found in events file\.\n";
	}
	
	if (scalar (keys %already) > 0) {
		print "\n";
		print "Microsoft-Windows-TaskScheduler/322 - Scheduled Task Already Running\n";
		printf "%-8s %-60s\n","Freq","Task";
		foreach my $i (reverse sort {$a <=> $b} keys %already) {
			printf "%-8d %-60s\n",$already{$i},$i;
		}
	}
	else {
	print "\n";
		print "No Microsoft-Windows-TaskScheduler/322 events found in events file\.\n";	
	}
# Intersection between data setservent
	if (scalar (keys %already) > 0 && scalar (keys %reg) > 0) {
		print "\n";
		print "Intersection between TaskScheduler/106 & TaskScheduler/322 events:\n";
		my @list1 = keys %already;
		my @list2 = ();
		foreach my $i (reverse sort {$a <=> $b} keys %reg) {
			my @r = split(/\|/,$i,3);
			push(@list2,$r[1]);
		}	
		my %orig = ();
		my @isect = ();
		map{$orig{$_} = 1}@list1;
		@isect = grep {$orig{$_}}@list2;
		
		foreach (@isect) {
			print $_."\n";
		}
	}
}
	
1;