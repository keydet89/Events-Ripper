#-----------------------------------------------------------
# logmein.pl
# parse Windows Defender event ID 2051 events
#
#
#
# Change history:
#   20240610 - created
#
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package logmein;
use strict;

my %config = (version       => 20240610,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse LogMeIn/nnn events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %logmein = ();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching logmein v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	my $count = 0;
	my %sysname = ();
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "LogMeIn" && $id eq "102") {
			my @s = split(/,/,$str);
			
			push(@{$logmein{$tags[0]}}, $s[0]." ".$s[1]);
			
		}

	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %logmein) > 0) {
		print "\n";
		print "Logins via LogMeIn: \n";
		foreach my $i (reverse sort keys %logmein) {
			foreach my $x (@{$logmein{$i}}) {		
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}	 	
		print "\n";
		print "There are ".(scalar (keys %logmein))." login events.\n";
	}
	else {
		print "No LogMeIn/102 events found\.\n";
	}
	
}
1;