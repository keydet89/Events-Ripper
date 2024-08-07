#-----------------------------------------------------------
# cylancesvc.pl
# parse events file for login events
#
# Change history:
#   20240807 - created
#
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package cylancesvc;
use strict;

my %config = (version       => 20240807,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse CylanceSvc/32";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching cylancesvc v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname      = ();
	my %files     = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "CylanceSvc" && $id eq "32") {
			
			my @elements = split(/,/,$str);
			my $msg = $elements[0];
			$msg =~ s/^\"//;
			my $fp = "File path: ";
			my $filepath = "";
			my $device = "Device: ";
			foreach my $i (0..((scalar @elements) - 1)) {
				
				if ($elements[$i] =~ m/^$device/ && $i > 1) {
#					print $device." found at item ".$i." - ".$elements[1]."\n";
					$msg = $elements[0]."".$elements[1];
					$msg =~ s/^\"//;
				}
				
				$filepath = $elements[$i] if ($elements[$i] =~ m/^$fp/);
			}
			$filepath =~ s/^$fp//;	
						
			push(@{$files{$tags[0]}}, $msg." - ".$filepath);
		}
	
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	

	if (scalar (keys %files) > 0) {
		print "\n";
		print "CylanceSvc/32 Detections:\n";
		printf "%-25s %-60s\n","Time","Detection";
		foreach my $i (reverse sort keys %files) {
			foreach my $x (@{$files{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
	}
	else {
		print "No CylanceSvc/32 events found.\n";	
	}
}
1;