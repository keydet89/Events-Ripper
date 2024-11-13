#-----------------------------------------------------------
# comp_account.pl
# Looks for computer account creation events
#
# 
# Change history:
#   20241105 - created
#
# References:
#  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4741
#  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4742
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package comp_account;
use strict;

my %config = (version       => 20241105,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Look for computer account creation events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching comp_account v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %comp  = ();
	my %sysname = ();
	
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4741") {
			my @elements = split(/,/,$str);
			$elements[0] =~ s/^\"//;
			
			push(@{$comp{$tags[0]}}, $elements[0]." account created by ".$elements[4]);
		}
		elsif ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4742") {
			my @elements = split(/,/,$str);
			
			push(@{$comp{$tags[0]}}, $elements[1]." account changed by ".$elements[5]);
		}
		
		
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}

	if (scalar (keys %comp) > 0) {
		print "\n";
		print "Computer Account Events:\n";
		printf "%-25s %-60s\n","Time","Description";
		foreach my $i (reverse sort keys %comp) {
			foreach my $x (@{$comp{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
			
	}	
	else {
		print "No computer account creation events found.\n";	
	}
}
	
1;