#! c:\perl\bin\perl.exe
#-------------------------------------------------------------------------
# ERip - Events Ripper
# Use this utility to run a plugins file or a single plugin against a Reg
# hive file.
# 
# Output goes to STDOUT
# Usage: see "_syntax()" function
#
# Change History
#   20220622 - created
#
# copyright 2022 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#
#-------------------------------------------------------------------------
use strict;
use Getopt::Long;
use Time::Local;
use File::Spec;

my %config;
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config,qw(file|f=s plugin|p=s profile|r=s list|l csv|c auto|a help|?|h));

my @path;
my $str = $0;
($^O eq "MSWin32") ? (@path = split(/\\/,$0))
                   : (@path = split(/\//,$0));
$str =~ s/($path[scalar(@path) - 1])//;

# Suggested addition by Hal Pomeranz for compatibility with Linux
#push(@INC,$str);
# code updated 20190318
my $plugindir;
($^O eq "MSWin32") ? ($plugindir = $str."plugins/")
                   : ($plugindir = File::Spec->catfile("plugins"));

# End code update
my $VERSION = "1\.0";
my @alerts = ();

if ($config{help} || !%config) {
	_syntax();
	exit;
}

#-------------------------------------------------------------
# 
#-------------------------------------------------------------
if ($config{list}) {
	my @plugins;
	opendir(DIR,$plugindir) || die "Could not open $plugindir: $!\n";
	@plugins = readdir(DIR);
	closedir(DIR);

	my $count = 1; 
	print "Plugin,Version,Description\n" if ($config{csv});
	foreach my $p (@plugins) {
		next unless ($p =~ m/\.pl$/);
		my $pkg = (split(/\./,$p,2))[0];
#		$p = $plugindir.$p;
		$p = File::Spec->catfile($plugindir,$p);
		eval {
			require $p;
			my $version = $pkg->getVersion();
			my $descr   = $pkg->getShortDescr();
			if ($config{csv}) {
				print $pkg.",".$version.",".$descr."\n";
			}
			else {
				print $count.". ".$pkg." v.".$version."\n";
#				printf "%-20s %-10s %-10s\n",$pkg,$version,$hive;
				print  "   - ".$descr."\n\n";
				$count++;
			}
		};
		print "Error: $@\n" if ($@);
	}
	exit;
}

#-------------------------------------------------------------
# 
#-------------------------------------------------------------
if ($config{auto}) {
	my $file = $config{file};
	my @plugins;
	opendir(DIR,$plugindir) || die "Could not open $plugindir: $!\n";
	@plugins = readdir(DIR);
	closedir(DIR);
	
	foreach my $p (@plugins) {
		next unless ($p =~ m/\.pl$/);
		my $pkg = (split(/\./,$p,2))[0];
	
#		$p = $plugindir.$p;
		$p = File::Spec->catfile($plugindir,$pkg."\.pl");
		eval {
			require $p;
			$pkg->pluginmain($file);
		};
		print "Error: $@\n" if ($@);
		print "-" x 40,"\n";
	}
	exit;
}


#-------------------------------------------------------------
# 
#-------------------------------------------------------------
if ($config{profile}) {
# First, check that a hive file was identified, and that the path is
# correct
	my $file = $config{file};
	die "You must enter an events file path/name.\n" if ($file eq "");

	my %plugins = parsePluginsFile($config{profile});
	if (%plugins) {
#		print "Parsed Plugins file.\n";
	}
	else {
		print "Plugins file not parsed.\n";
		exit;
	}
	foreach my $i (sort {$a <=> $b} keys %plugins) {
		eval {
#			require "plugins/".$plugins{$i}."\.pl";
			my $plugin_file = File::Spec->catfile($plugindir,$plugins{$i}.".pl");
			require $plugin_file;
			$plugins{$i}->pluginmain($file);
		};
		if ($@) {
			print "Error in ".$plugins{$i}.": ".$@."\n";
		}
		print $plugins{$i}." complete.\n";
		print "-" x 40,"\n";
	}

}

#-------------------------------------------------------------
# 
#-------------------------------------------------------------
if ($config{plugin}) {
# First, check that a hive file was identified, and that the path is
# correct
	my $file = $config{file};
	die "You must enter an events file path/name.\n" if ($file eq "");

# check to see if the plugin exists
	my $plugin = $config{plugin};
#	my $pluginfile = $plugindir.$config{plugin}."\.pl";
	my $pluginfile = File::Spec->catfile($plugindir,$config{plugin}."\.pl");
	die $pluginfile." not found.\n" unless (-e $pluginfile);
	
	eval {
		require $pluginfile;
		$plugin->pluginmain($file);
	};
	if ($@) {
		print "Error in ".$pluginfile.": ".$@."\n";
	}	
}

#-------------------------------------------------------------
# 
#-------------------------------------------------------------
sub _syntax {
	print<< "EOT";
eRip v.$VERSION - CLI events file ripper tool	
erip [-f events file] [-r profile] [-p plugin] [-a] [-l] [-h]
Parse timeline-format events file

  -f events file.....events file to parse
  -r profile.........use the profile (subset of plugins)
  -p plugin..........use only this module
  -a ................run all plugins
  -l ................list all plugins
  -c ................Output list in CSV format (use with -l)
  -h.................Help (print this information)
  
Ex: C:\\>erip -f c:\\case\\events.txt -a
    C:\\>erip -f c:\\case\\events.txt -p failedlogins
    C:\\>erip -l -c

All output goes to STDOUT; use redirection (ie, > or >>) to output to a file\.
  
copyright 2022 Quantum Analytics Research, LLC
EOT
}

#-------------------------------------------------------------
# parsePluginsFile()
# Parse the plugins file and get a list of plugins
#-------------------------------------------------------------
sub parsePluginsFile {
	my $file = $_[0];
	my %plugins;
# Parse a file containing a list of plugins
# Future versions of this tool may allow for the analyst to 
# choose different plugins files	
#	my $pluginfile = $plugindir.$file;
	my $pluginfile = File::Spec->catfile($plugindir,$file);
	if (-e $pluginfile) {
		open(FH,"<",$pluginfile);
		my $count = 1;
		while(<FH>) {
			chomp;
			next if ($_ =~ m/^#/ || $_ =~ m/^\s+$/);
#			next unless ($_ =~ m/\.pl$/);
			next if ($_ eq "");
			$_ =~ s/^\s+//;
			$_ =~ s/\s+$//;
			$plugins{$count++} = $_; 
		}
		close(FH);
		return %plugins;
	}
	else {
		return undef;
	}
}

#-----------------------------------------------------------
# format8601Date()
# Convert Unix epoch time to ISO8601-like format
# output date format in RFC 3339 profile of ISO 8601
#-----------------------------------------------------------
sub format8601Date {
	my $epoch = shift;
	my ($sec,$min,$hour,$mday,$mon,$year) = gmtime($epoch);
  return sprintf("%04d-%02d-%02d %02d:%02d:%02d",(1900 + $year),($mon + 1),$mday,$hour,$min,$sec);
}

1;