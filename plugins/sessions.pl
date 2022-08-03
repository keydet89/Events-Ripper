#-----------------------------------------------------------
# sessions.pl
# parse login/logoff events to get session info
#
# To be clear, this plugin works by tracking login/logoff events based on the unique login 
# session ID.
#
# Change history:
#   20220803 - updated duration output
#   20220802 - created
#
# References:
#   
#
# copyright 2022 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sessions;
use strict;

my %config = (version       => 20220803,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse login/logoff events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching sessions v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sess = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4624") {
			
			my @elements = split(/,/,$str);
			my $type = $elements[8];
			
			if ($type == 3 || $type == 10 || $type == 2) {
				my $id = $elements[7];
				$sess{$id}{logon_time} = $tags[0];
				$sess{$id}{logon_type} = $type;
				$sess{$id}{logon_SID}  = $elements[4];
				$sess{$id}{logon_user} = $elements[6]."\\".$elements[5];
				$sess{$id}{logon_IP}   = $elements[18];
				$sess{$id}{logon_NetBIOS} = $elements[11];
				$sess{$id}{logon_protocol} = $elements[14];
			}
		}
		
		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4634") {
			
			my @elements = split(/,/,$str);
			my $type = $elements[4];
			
			if ($type == 3 || $type == 10 || $type == 2) {
				my $id = $elements[3];
				$sess{$id}{logoff_time} = $tags[0];
				$sess{$id}{logoff_SID}  = $elements[0];
				$sess{$id}{logoff_user} = $elements[2]."\\".$elements[1];
			}
		}
		
	}
	close(FH);
	
	if (scalar (keys %sess) > 0) {
		printf "%-25s %-40s %-4s %-10s\n","Login Time","User","Type","Duration";
		foreach my $i (keys %sess) {
			if (exists $sess{$i}{logon_time} && exists $sess{$i}{logoff_time}) {
#				print "ID  : ".$i."\n";
				next if ($sess{$i}{logon_user} =~ m/\$$/);
				printf "%-25s %-40s %-4s %-10s\n",::format8601Date($sess{$i}{logon_time})."Z", $sess{$i}{logon_user},$sess{$i}{logon_type},parse_duration($sess{$i}{logoff_time} - $sess{$i}{logon_time});
			}
		}
	}
	else {
		print "\n";
		print "No logins found in events file\.\n";
	}
	
}

# found this code on PerlMonks
sub parse_duration {
	my $seconds = shift;
	my $hours = int($seconds/(60*60));
	my $mins  = ($seconds/60)%60;
	my $secs  = $seconds % 60;
	return sprintf ("%02d:%02d:%02d",$hours,$mins,$secs);
}
	
1;