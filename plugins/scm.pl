#-----------------------------------------------------------
# scm.pl
# parse Service Control Manager events - /7000, /7009, /7024, /7040, /7045
#
# 
# Pivot Points/Analysis: 
#   
#
#
# Change history:
#   20230503 - created
#
# References:
#   https://social.technet.microsoft.com/wiki/contents/articles/13754.event-id-7024-service-terminated.aspx
#   Event ID 7040 -  https://www.linkedin.com/posts/john-dwyer-xforce_threathunting-threatdetection-malware-activity-7038997228815867904-F8wj
#
# copyright 2023 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package scm;
use strict;

my %config = (version       => 20230504,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Parse Service Control Manager events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching scm v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %sysname = ();
	my %i7000    = ();
	my %i7009    = ();
	my %i7024    = ();
	my %i7040    = ();
	my %i7045    = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);
		
		if ($src eq "Service Control Manager") {
			if ($id eq "7000") {
				my $app = (split(/,/,$str))[0];
				$i7000{$app} = 1;
			}
			elsif ($id eq "7009") {
				my $app = (split(/,/,$str))[1];
				$i7009{$app} = 1;
			}
			elsif ($id eq "7024") {
				my $app = (split(/,/,$str))[0];
				$i7024{$app} = 1;
			}
# Check for disabled services
# add $tags[0] for time stamp???
			elsif ($id eq "7040") {
				my @s = split(/,/,$str);
				$i7040{$tags[0].":".$s[0]} = 1 if ($s[2] eq "disabled");
			}
			elsif ($id eq "7045") {
				my @s = split(/,/,$str);
				my $app      = $tags[0].":".$s[0]." -> ".$s[1];
				$i7045{$app} = 1;
				
			}
			else {}
			
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}
	
	if (scalar (keys %i7000) > 0) {
		print "Services that failed to start:\n";
		foreach my $n (keys %i7000) {
			print $n."\n";
		}
		print "\n";
		print "Analysis Tip: Services that fail to start may be an indication of malware.\n";
	}
	else {
		print "No Service Control Manager/7000 events found\.\n";
	}
	print "\n";
	
	if (scalar (keys %i7009) > 0) {
		print "Services that timed out:\n";
		foreach my $n (keys %i7009) {
			print $n."\n";	
		}
		print "\n";
	}
	else {
		print "No Service Control Manager/7009 events found\.\n";
	}
	print "\n";
	
	if (scalar (keys %i7024) > 0) {
		print "Services That Were Terminated\n";
		foreach my $a (keys %i7024) {
			print $a."\n";
		}
		print "\n";
		print "Analysis Tip: SCM/7024 event records indicate that a service was terminated\.\n";
		print "\n";
		print "Ref: https://social.technet.microsoft.com/wiki/contents/articles/13754.event-id-7024-service-terminated.aspx\n";
	}
	else {
		print "No Service Control Manager/7024 events found\.\n";
	}
	print "\n";
# Services disabled
# https://kb.eventtracker.com/evtpass/evtpages/EventId_7040_ServiceControlManager_50628.asp
	if (scalar (keys %i7040) > 0) {
		print "Disabled Services\n";
		foreach my $n (keys %i7040) {
			my ($t, $s) = split(/:/,$n,2);
			printf "%-25s %-40s\n", ::format8601Date($t)."Z",$s;
		}
		print "\n";
		print "Analysis Tip: Disabled services may be an indication of a threat actor preparing the environment \n";
		print "as part of an attack.\n";
		print "\n";
		print "Ref: https://kb.eventtracker.com/evtpass/evtpages/EventId_7040_ServiceControlManager_50628.asp\n";
	}
	else {
		print "No Service Control Manager/7040 events found\.\n";
	}
	print "\n";
	
	if (scalar (keys %i7045) > 0) {
		print "Service Installation Events:\n";
		foreach my $n (keys %i7045) {
			my ($t,$s) = split(/:/,$n,2);
			printf "%-25s %-60s\n",::format8601Date($t)."Z",$s;
		}
		print "\n";
		print "Analysis Tip: A service installation may indicate persistence being created for malware, or as part of\n";
		print "an attack.\n";
		
	}
	else {
		print "No Service Control Manager45 events found\.\n";
	}
	
}
1;