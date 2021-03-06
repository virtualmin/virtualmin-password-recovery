use strict;
use warnings;
our (%text);
our $module_name;
our $config_directory;

require 'password-recovery-lib.pl';

sub module_install
{
# Grant anonymous access
&foreign_require("acl", "acl-lib.pl");
&acl::setup_anonymous_access("/$module_name", $module_name);

# Add 'forgot password' link to Webmin login form
my %clang;
&read_file("$config_directory/custom-lang", \%clang);
if (!$clang{'session_postfix'}) {
	$clang{'session_postfix'} =
	    "<center><a href=/$module_name/>$text{'login_forgot'}</a></center>";
	&write_file("$config_directory/custom-lang", \%clang);
	}

# Also add to Usermin login form
if (&foreign_installed("usermin")) {
	&foreign_require("usermin");
	&foreign_require("virtual-server");
	my %uclang;
	&read_file("$usermin::config{'usermin_dir'}/custom-lang", \%uclang);
	if (!$uclang{'session_postfix'}) {
		my %miniserv;
		&get_miniserv_config(\%miniserv);
		my $port = $miniserv{'port'};
		$uclang{'session_postfix'} =
		   "<center><a href=/$module_name/usermin.cgi ".
		   "onclick='javascript:event.target.port=$port'>".
		   "$text{'login_forgot2'}</a></center>";
		&write_file("$usermin::config{'usermin_dir'}/custom-lang",
			    \%uclang);
		}
	}
}
