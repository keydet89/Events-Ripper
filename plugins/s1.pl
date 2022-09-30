#-----------------------------------------------------------
# s1.pl
# requires SentinelOne/Operational Event Logs
#
# Change history:
#   20220930 - updated to output system name(s)
#   20220802 - created
#
# References:
#   https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package s1;
use strict;

my %config = (version       => 20220930,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse SentinelOne/31 and /32 events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching s1 v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %s1 = ();
	my %sysname = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "SentinelOne" && $id eq "31") {
			my @items = split(/,/,$str);
			$s1{$items[0]}{timestamp} = $tags[0];
			$s1{$items[0]}{file} = $items[2];
			$s1{$items[0]}{id} = $items[3];
		}

# Added items should be Kill and Quarantine, and their status		
		if ($src eq "SentinelOne" && $id eq "32") {
			my @items = split(/,/,$str);
			$s1{$items[0]}{$items[1]} = $items[2];
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	foreach my $k (keys %s1) {		
#		print "Timestamp     : ".::format8601Date($s1{$k}{timestamp})."Z\n";
#		print "File          : ".$s1{$k}{file}."\n";
#		print "SentinelOne ID: ".$s1{$k}{id}."\n";
#		print "Kill          : ".$s1{$k}{"Kill"}."\n" if exists($s1{$k}{"Kill"});
#		print "Quarantine    : ".$s1{$k}{"Quarantine"}."\n" if exists($s1{$k}{"Quarantine"});	
#		print "\n";
		
		my $str = ::format8601Date($s1{$k}{timestamp})."Z, ".$s1{$k}{file}.",".$s1{$k}{id};
		$str .= ", Kill: ".$s1{$k}{"Kill"} if exists($s1{$k}{"Kill"});
		$str .= ", Quarantine: ".$s1{$k}{"Quarantine"} if exists($s1{$k}{"Quarantine"});	
		
		print $str."\n";
	}
}
1;