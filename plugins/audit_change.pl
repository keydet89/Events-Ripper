#-----------------------------------------------------------
# audit_change.pl
# Checks for cleared platform/firewall events
#
# 
# Change history:
#   20241025 - created
#
# References:
#  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
#
# copyright 2024 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package audit_change;
use strict;

my %config = (version       => 20241025,
              category      => "",
              MITRE         => "");

sub getConfig{return %config}

sub getShortDescr {
	return "Check for audit config change events";	
}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $file = shift;
	print "Launching audit_change v.".$VERSION."\n";
	print getShortDescr()."\n";
	print "\n";
	
	my %change   = ();
	my %sysname = ();
	my %subs = ("{0CCE921C-69AE-11D9-BED3-505054503030}" => "Other Logon/Logoff Events",
	            "{0CCE9227-69AE-11D9-BED3-505054503030}" => "Other Object Access",
	            "{0CCE921B-69AE-11D9-BED3-505054503030}" => "Special Logon",
				"{0CCE9222-69AE-11D9-BED3-505054503030}" => "Application Generated",
				"{0CCE9211-69AE-11D9-BED3-505054503030}" => "Security System Extension",
				"{0CCE9223-69AE-11D9-BED3-505054503030}" => "Handle Manipulation",
				"{0CCE9242-69AE-11D9-BED3-505054503030}" => "Kerberos Authentication Service",
				"{0CCE9216-69AE-11D9-BED3-505054503030}" => "Logoff",
				"{0CCE9215-69AE-11D9-BED3-505054503030}" => "Logon",
				"{0CCE923B-69AE-11D9-BED3-505054503030}" => "Directory Service Access",
				"{0CCE922B-69AE-11D9-BED3-505054503030}" => "Process Creation",
				"{0CCE922F-69AE-11D9-BED3-505054503030}" => "Audit Policy Change",
				"{0CCE923A-69AE-11D9-BED3-505054503030}" => "Other Account Management Events",
				"{0CCE9237-69AE-11D9-BED3-505054503030}" => "Security Group Management",
				"{0CCE9235-69AE-11D9-BED3-505054503030}" => "User Account Management",
				"{0CCE9241-69AE-11D9-BED3-505054503030}" => "Other Account Logon Events",
				"{0CCE9245-69AE-11D9-BED3-505054503030}" => "Removeable Storage",
				"{0cce9249-69ae-11d9-bed3-505054503030}" => "Group Membership");
	
	open(FH,'<',$file);
	while (<FH>) {
		chomp($_);
		my @tags = split(/\|/,$_,5);
		$sysname{$tags[2]} = 1;
		my $desc = $tags[4];
		
		my ($event, $str) = split(/;/,$desc,2);
		my ($src,$id) = split(/\//,$event,2);

		if ($src eq "Microsoft-Windows-Security-Auditing" && $id eq "4719") {
			my @elements = split(/,/,$str);
			my $subcat = $elements[6];
			$subcat =~ tr/a-z/A-Z/;
			my $tag = ();
			if (exists $subs{$subcat}) {
				$tag = $subs{$subcat};
			}
			else {
				$tag = $subcat;
			}
			

			push(@{$change{$tags[0]}}, $tag);
			
		}
	}
	close(FH);
	
	if (scalar keys %sysname > 0) {
		foreach my $i (keys %sysname) {
			print "System name: ".$i."\n";
		}
		print "\n";
	}


	if (scalar (keys %change) > 0) {
		print "\n";
		print "WEVTX Audit Change Events:\n";
		printf "%-25s %-60s\n","Time","Subcategory changed";
		foreach my $i (reverse sort keys %change) {
			foreach my $x (@{$change{$i}}) {
				printf "%-25s %-60s\n",::format8601Date($i)."Z",$x;
			}
		}
		print "\n";
		print "For a complete list of subcategory GUIDs, if any are not translated, or, if you'd like to see:\n";
		print "an explanation of the different subcategories:\n\n";
		print "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d\n";
	}
	else {
		print "No audit change events found.\n";	
	}

}
	
1;