#-----------------------------------------------------------
# apptelem.pl
# Gets info from BITS-Client/3 and /59 events
#
# event ID 505 - Compatibility fix applied to...
# event ID 500 - Application compatibility invoked for.. 
#
# Change history:
#   20220928 - created
#
# References:
#   https://www.hecfblog.com/2018/09/daily-blog-474-application-experience.html
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package apptelem;
use strict;

my %config = (version       => 20220928,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Gets info from when AppCompatibility is invoked/applied to";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching apptelem v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %app = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Application-Experience" && ($id eq "505" || $id eq "500")) {
			my @elements = split(/,/,$str);
			
			my $str = $elements[4]." - ".$elements[5];
			
			if (exists $app{$str}) {
				$app{$str}++;
			}
			else {
				$app{$str} = 1;
			}
		}
		
	}
	close(FH);
	
	if (scalar keys %app > 0) {
		print "Application compatibility was invoked for:\n";
		foreach my $i (keys %app) {
			print $i."\n";
		}
		print "\n";
	}
	else {
		 print "No Microsoft-Windows-Application-Experience/505 (app compatibility invoked) events found in the events file\.\n";
	}
	
	print "\n";
	print "Analysis Tip: This plugin lists BITS Client jobs created, and URLs from BITS transfer jobs\.\n";
	print "\n";
}
	
1;