#-----------------------------------------------------------
# splashtop.pl
# Checks splashtop records in the Application Event Log
#
# 
# Change history:
#   20250207 - created
#
#
# References:
#  requires  Application Event Log
#
# copyright 2025 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package splashtop;
use strict;

my %config = (version       => 20250207,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "splashtop records";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching splashtop v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %logon   = ();
	my %sysname = ();

	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Splashtop Streamer" && $id eq "1000") {
			$str =~ s/\"//g;
			my $tip1 = (split(/\,/,$str,2))[0];
			my @tap = split(/\s/,$tip1);
			my $session = $tap[4];
			$session =~ s/^\(//;
			$session =~ s/\)$//;
			
			my $source = $tap[15];
			$source =~ s/\.$//;
			
			push(@{$logon{$tags[0]}}, "Logon from device : ".$source." Session ID : ".$session);
		}
		elsif ($src eq "Splashtop Streamer" && $id eq "1001") {
			$str =~ s/\"//g;
			my $tip1 = (split(/\,/,$str,2))[0];
			my @tap = split(/\s/,$tip1);
			my $session = $tap[4];
			$session =~ s/^\(//;
			$session =~ s/\)$//;
			push(@{$logon{$tags[0]}}, "Splashtop session ended, Session ID  : ".$session);
		}
		elsif ($src eq "Splashtop Streamer" && $id eq "1101") {
			$str =~ s/\"//g;
			my @sec = split(/\,/,$str);
			my $session = (split(/\s/,$sec[0]))[9];
			$session =~ s/^\(//;
			$session =~ s/\.$//;
			$session =~ s/\)$//;
			
			my $file = (split(/\:/,$sec[2]))[1];
			$file =~ s/^\s//;
			$file =~ s/\s$//;
			my $source = (split(/\s/,$sec[3]))[1];
			my ($host,$path) = (split(/\s/,$sec[4]))[1,2];
			$path =~ s/^\(//;
			$path =~ s/\)$//;
			push(@{$logon{$tags[0]}}, "[Download] Splashtop session ID  : ".$session." : ".$path."\\".$file." transferred to ".$host);
	
		}
		elsif ($src eq "Splashtop Streamer" && $id eq "1100") {
			$str =~ s/\"//g;
			my @sec = split(/\,/,$str);
			my $session = (split(/\s/,$sec[0]))[9];
			$session =~ s/^\(//;
			$session =~ s/\.$//;
			$session =~ s/\)$//;
			
			my $file = (split(/\:/,$sec[2]))[1];
			$file =~ s/^\s//;
			$file =~ s/\s$//;
			my $source = (split(/\s/,$sec[4]))[1];
			my ($host,$path) = (split(/\s/,$sec[3]))[1,2];
			$path =~ s/^\(//;
			$path =~ s/\)$//;
			push(@{$logon{$tags[0]}}, "[Upload] Splashtop session ID  : ".$session." : ".$path."\\".$file." transferred to ".$source);
			
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

	if (scalar (keys %logon) > 0) {
		print "Splashtop logon/logoff Events:\n";
		printf "%-25s %-60s\n","Time","Message";
		foreach my $i (reverse sort keys %logon) {
			foreach my $x (@{$logon{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
		print "\n";
		print "Note: Plugin requires Application Event Log\n";
	}
	else {
		print "No Splashtop logon/logoff events found.\n";	
	}

}
	
1;