# log_parser.pl
# Functions for parsing this module's logs
use strict;
use warnings;
our %text;

do 'password-recovery-lib.pl';

# parse_webmin_log(user, script, action, type, object, &params)
# Converts logged information from this module into human-readable form
sub parse_webmin_log
{
my ($user, $script, $action, $type, $object, $p) = @_;
if ($action eq 'email' && !$p->{'vm2'}) {
	return &text('log_email', "<tt>$object</tt>", "<tt>$p->{'email'}</tt>");
	}
elsif ($action eq 'email' && $p->{'vm2'}) {
	return &text('log_email2', "<tt>$object</tt>","<tt>$p->{'email'}</tt>");
	}
else {
	return $text{'log_'.$action};
	}
}
