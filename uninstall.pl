use strict;
use warnings;
our %text;
our $config_directory;

require 'password-recovery-lib.pl';

sub module_uninstall
{
# Remove 'forgot password' link from Webmin login form
my %clang;
&read_file("$config_directory/custom-lang", \%clang);
if ($clang{'session_postfix'} =~ /\Q$text{'login_forgot'}\E/) {
	delete($clang{'session_postfix'});
	&write_file("$config_directory/custom-lang", \%clang);
	}

# Also remove from Usermin login form
if (&foreign_installed("usermin")) {
	&foreign_require("usermin");
	my %uclang;
	&read_file("$usermin::config{'usermin_dir'}/custom-lang", \%uclang);
	if ($uclang{'session_postfix'} =~ /\Q$text{'login_forgot2'}\E/) {
		delete($uclang{'session_postfix'});
		&write_file("$usermin::config{'usermin_dir'}/custom-lang", \%uclang);
		}
	}
}
