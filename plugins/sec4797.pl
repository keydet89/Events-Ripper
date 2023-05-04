#-----------------------------------------------------------
# sec4797.pl
# Checks events indicating user accounts were checked for blank passwords
#
# 
#
# Change history:
#   20230504 - created
#
# References:
#   https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4797
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sec4797;
use strict;

my %config = (version       => 20230504,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/4797 (user account checked for blank passwd) events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching sec4797 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname = ();
	my %u       = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4797") {
			my @n = split(/,/,$str);
			$u{$tags[0].":".$n[1].":".$n[5]} = 1;
			
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %u) > 0) {
		print "Microsoft-Windows-Security-Auditing/4797 events\n";
		foreach my $n (keys %u) {
			my ($t,$a,$u) = split(/:/,$n,3);
			printf "%-25s ".$a." account checked to see if account ".$u." had a blank password\n",::format8601Date($t)."Z";
		}
		print "\n";
		print "Analysis Tip: Checking user accounts for blank passwords may not be \"normal\", and may be part of an attack.\n";
		print "Investigate the user account checking other accounts.\n";
		print "\n";
		print "Ref: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4797\n";
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/4797 events found in events file\.\n";
	}
	
}
	
1;