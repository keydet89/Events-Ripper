#-----------------------------------------------------------
# sec4648.pl
# parse login/logoff events to get session info
#
# 
#
# Change history:
#   20220930 - updated to output system name
#   20220804 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sec4648;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/4648 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching sec4648 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sess = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4648") {
			
			my @elements = split(/,/,$str);
# user, creds, target, process, network
			my $str = $elements[2]."\\".$elements[1]."|".$elements[6]."\\".$elements[5]."|".$elements[8]."|".$elements[11]."|".$elements[12].":".$elements[13];
			push(@{$sess{$tags[0]}}, $str)
		}
	
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %sess) > 0) {
		printf "%-22s %-25s %-25s %-25s %-40s %-20s\n","Login Time","User","Credentials","Target","Process","Network";
		foreach my $n (sort {$a <=> $b} keys %sess) {
			foreach my $x (@{$sess{$n}}) {
				my @str = split(/\|/,$x);
				next if ($str[0] =~ m/\$$/ || $str[0] eq "-\\-");
				printf "%-22s %-25s %-25s %-25s %-40s %-20s\n",::format8601Date($n)."Z", $str[0],$str[1],$str[2],$str[3],$str[4];
			}
		}
	
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/4648 found in events file\.\n";
	}
	print "\n";
	print "Analysis Tip: This plugin displays Security-Auditing event ID 4648 data; service account names (end in \"\$\")\n";
	print "and blank subject user names are bypassed and not displayed. \n";
	print "\n";
	print "Ref: https://www.socinvestigation.com/threat-hunting-using-windows-eventid-4648-logon-logoff/\n";
	print "Ref: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648\n";
}
	
1;