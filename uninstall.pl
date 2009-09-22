
require 'password-recovery-lib.pl';

sub module_uninstall
{
# Remove 'forgot password' link
my %clang;
&read_file("$config_directory/custom-lang", \%clang);
if ($clang{'session_postfix'} =~ /\Q$text{'login_forgot'}\E/) {
	delete($clang{'session_postfix'});
	&write_file("$config_directory/custom-lang", \%clang);
	}
}
