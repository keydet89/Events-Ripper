#-----------------------------------------------------------
# esent.pl
# Checks ESENT/327 records, which may illustrate attempts at NTDS.DIT file theft 
#
# 
# Change history:
#   20250114 - created
#
# Note: On the day that this plugin was created, the observed command line was:
# cmd.exe /Q /c powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\Windows\Temp\173683091' q q\" 1> \Windows\Temp\ocPGwK 2>&1
#
#
# References:
#  requires  Application Event Log
#
# copyright 2025 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package esent;
use strict;

my %config = (version       => 20250114,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Look for attempts at NTDS.DIT theft";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching esent v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %ntds   = ();
	my %sysname = ();

	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "ESENT" && $id eq "327") {
# database engine detached a database			
			my @elements = split(/,/,$str);
			my $engine = $elements[0];
			$engine =~ s/$\"//;
			next unless ($engine eq "NTDS");
			my $db     = $elements[4];
			push(@{$ntds{$tags[0]}}, $engine." database engine detached database ".$db);
		}
		elsif ($src eq "ESENT" && $id eq "326") {
# database engine attached a database				
			my @elements = split(/,/,$str);
			my $engine = $elements[0];
			$engine =~ s/$\"//;
			next unless ($engine eq "NTDS");
			my $db     = $elements[4];
			push(@{$ntds{$tags[0]}}, $engine." database engine attached database ".$db);
		}
		elsif ($src eq "ESENT" && $id eq "325") {
# database engine created a new database				
			my @elements = split(/,/,$str);
			my $engine = $elements[0];
			$engine =~ s/$\"//;
			next unless ($engine eq "NTDS");
			my $db     = $elements[4];
			push(@{$ntds{$tags[0]}}, $engine." database engine created a new database ".$db);	
		}
#		elsif ($src eq "ESENT" && $id eq "216") {
# database location change				
#			my @elements = split(/,/,$str);
#			my $engine = $elements[0];
#			next unless ($engine eq "lsass");
#			my $old_db     = $elements[3];
#			my @location = split(/\\/,$old_db);
#			next unless ($location[scalar(@location) - 1] eq "ntds\.dit");
#			my $new_db     = $elements[4];
#			push(@{$ntds{$tags[0]}}, "database ".$old_db." moved to ".$new_db);	
#		}
		else {}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}

	if (scalar (keys %ntds) > 0) {
		print "\n";
		print "ESENT Events:\n";
		printf "%-25s %-60s\n","Time","Message";
		foreach my $i (reverse sort keys %ntds) {
			foreach my $x (@{$ntds{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
		print "\n";
		print "Note: Plugin requires Application Event Log\n";
	}
	else {
		print "No ESENT/32* events found.\n";	
	}
}
	
1;