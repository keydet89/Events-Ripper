#-----------------------------------------------------------
# sec5381.pl
# Checks events indicating user account enumerated vault credentials
# 
#
# Change history:
#   20230605 - created
#
# References:
#   https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5381
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sec5381;
use strict;

my %config = (version       => 20230605,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Security-Auditing/5381 (user enum. vault creds) events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching sec5381 v.".$VERSION."\n";
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

		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "5381") {
			my @n = split(/,/,$str);
			$u{$tags[0].":".$n[2]."\\".$n[1]." (".$n[0].")"} = 1;
			
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
		print "Microsoft-Windows-Security-Auditing/5381 events\n";
		foreach my $n (reverse sort {$a <=> $b} keys %u) {
			my ($t,$a) = split(/:/,$n,2);
			printf "%-25s ".$a." user enumerated vault credentials\n",::format8601Date($t)."Z";
		}
		print "\n";
		print "Analysis Tip: A user enumerating vault creds had been observed associated with the use of credential dumping\n";
		print "tools such as WebBrowserPassView and IEPV\.\n";
		print "\n";
		print "Ref: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5381\n";
	}
	else {
		print "\n";
		print "No Microsoft-Windows-Security-Auditing/5381 events found in events file\.\n";
	}
	
}
	
1;