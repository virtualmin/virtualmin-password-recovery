# log_parser.pl
# Functions for parsing this module's logs

do 'password-recovery-lib.pl';

# parse_webmin_log(user, script, action, type, object, &params)
# Converts logged information from this module into human-readable form
sub parse_webmin_log
{
local ($user, $script, $action, $type, $object, $p) = @_;
if ($action eq 'email') {
	return &text('log_email', "<tt>$object</tt>", "<tt>$p->{'email'}</tt>");
	}
else {
	return $text{'log_'.$action};
	}
}

