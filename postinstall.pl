
require 'password-recovery-lib.pl';

sub module_install
{
# Grant anonymous access
&foreign_require("acl", "acl-lib.pl");
&acl::setup_anonymous_access("/$module_name", $module_name);

# Add 'forgot password' link to login form
my %clang;
&read_file("$config_directory/custom-lang", \%clang);
if (!$clang{'session_postfix'}) {
	$clang{'session_postfix'} = "<center><a href=/$module_name/>$text{'login_forgot'}</a></center>";
	&write_file("$config_directory/custom-lang", \%clang);
	}
}

