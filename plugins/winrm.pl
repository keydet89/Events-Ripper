#-----------------------------------------------------------
# winrm.pl
# Checks for logins via WinRM
#
# 
# Change history:
#   20241125 - created
#
# References:
#  requires  Microsoft-Windows-WinRM%4Operational Event Log
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package winrm;
use strict;

my %config = (version       => 20241125,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Check for logins via WinRM";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching winrm v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %login   = ();
	my %sysname = ();

	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-WinRM" && $id eq "91") {
			my @elements = split(/\s/,$str);
			
			my $account = $elements[1];
			$account =~ s/^\(//;
			
			my $ip = $elements[3];
			$ip =~ s/\)//;
			
			push(@{$login{$tags[0]}}, "WinRM login for ".$account." account from ".$ip);
			
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}

	if (scalar (keys %login) > 0) {
		print "\n";
		print "WinRM Login Events:\n";
		printf "%-25s %-60s\n","Time","Account + Source";
		foreach my $i (reverse sort keys %login) {
			foreach my $x (@{$login{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
		print "\n";
		print "Note: Plugin requires Microsoft-Windows-WinRM%4Operational Event Log\n";
	}
	else {
		print "No WinRM login events found.\n";	
	}
}
	
1;