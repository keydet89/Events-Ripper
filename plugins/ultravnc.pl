#-----------------------------------------------------------
# ultravnc.pl
# Checks UltraVNC records in the Application Event Log
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
package ultravnc;
use strict;

my %config = (version       => 20250207,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "UltraVNC records";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching ultravnc v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %logon   = ();
	my %failed  = ();
	my $count   = "";
	my %sysname = ();

	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "UltraVNC" && ($id eq "1" || $id eq "3")) {
			$str =~ s/\"//g;
			$str =~ s/$\,//;
			my @elements = split(/\t/,$str);
			my $tag = "";
			$tag = "Logon  : ".$elements[1] if ($id eq "1");
			$tag = "Logoff : ".$elements[1] if ($id eq "3");
			push(@{$logon{$tags[0]}}, $tag);
		}
		elsif ($src eq "UltraVNC" && $id eq "2") {
			$str =~ s/\"//g;	
			$str =~ s/$\,//;
			my @elements = split(/\t/,$str);
			my $source   = (split(/\s/,$elements[1]))[4];
			
			if (exists $failed{$source}) {
				$failed{$source}++;
			}
			else {
				$failed{$source} = 1;
			}
			$count++;
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
		print "\n";
		print "UltraVNC logon/logoff Events:\n";
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
		print "No UltraVNC logon/logoff events found.\n";	
	}
	
	if (scalar (keys %failed) > 0) {
		print "\n";
		print "UltraVNC failed login attempts [total: ".$count."]:\n";
		printf "%-25s %-6s\n","Source","Freq";
		foreach my $i (reverse sort keys %failed) {
			printf "%-25s %-6d\n",$i,$failed{$i};
		}
		print "\n";
		print "Note: Plugin requires Application Event Log\n";
	}
	else {
		print "No UltraVNC failed login attempts found.\n";	
	}
}
	
1;