#-----------------------------------------------------------
# resolver.pl
# Checks for app resolver cache events
#
# 
# Change history:
#   20241123 - updated detections
#   20241108 - created
#
# References:
#   https://nasbench.medium.com/finding-forensic-goodness-in-obscure-windows-event-logs-60e978ea45a3
#   https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/shell_core/win_shell_core_susp_packages_installed.yml
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package resolver;
use strict;

my %config = (version       => 20241123,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Check for app resolver cache events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching resolver v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %resolv   = ();
	my %sysname = ();
	my %detect  = ();
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Shell-Core" && $id eq "28115") {
			my @elements = split(/,/,$str);
			my $name = $elements[0];
			my $id   = $elements[1];
			
			if ($name eq "AnyDesk" && $id eq "prokzult ad") {
				push(@{$detect{$tags[0]}}, "Possible malicious ".$name.":".$id." installed");	
			}
			elsif ($name eq "PuTTY" && $id eq "SimonTatham.PuTTY") {
				push(@{$detect{$tags[0]}}, $name.":".$id." installed");	
			}
			elsif ($name eq "Advanced IP Scanner") {
				push(@{$detect{$tags[0]}}, $name." installed");	
			}
			elsif ($name eq "Splashtop Streamer") {
				push(@{$detect{$tags[0]}}, $name." installed");	
			}
			
			push(@{$resolv{$tags[0]}}, $name.":".$id);
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

	if (scalar (keys %detect) > 0) {
		print "\n";
		print "Possible App Resolver Detections:\n";
		printf "%-25s %-60s\n","Time","Message";
		foreach my $i (reverse sort keys %detect) {
			foreach my $x (@{$detect{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
		print "\n";
		print "Note: Detections based partially on:\n";
		print "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/shell_core/win_shell_core_susp_packages_installed.yml\n";
		print "\n";
	}

	if (scalar (keys %resolv) > 0) {
		print "\n";
		print "Microsoft-Windows-Shell-Core/28115 app resolver cache messages:\n";
		printf "%-25s %-60s\n","Time","Application:ID";
		foreach my $i (reverse sort keys %resolv) {
			foreach my $x (@{$resolv{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
	}
	else {
		print "No Microsoft-Windows-Shell-Core/28115 events found.\n";	
	}

}
	
1;