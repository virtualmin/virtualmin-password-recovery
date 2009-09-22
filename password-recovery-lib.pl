# Functions for re-sending a virtualmin domain owner's password

BEGIN { push(@INC, ".."); };
eval "use WebminCore;";
&init_config();
&foreign_require("virtual-server", "virtual-server-lib.pl");

$custom_email_file = "$module_config_directory/email";

sub get_custom_email
{
if (open(CUSTOM, $custom_email_file)) {
	local $rv;
	while(<CUSTOM>) {
		$rv .= $_;
		}
	close(CUSTOM);
	return $rv;
	}
return undef;
}

sub save_custom_email
{
local ($email) = @_;
if (defined($email)) {
	open(CUSTOM, ">$custom_email_file");
	print CUSTOM $email;
	close(CUSTOM);
	}
else {
	unlink($custom_email_file);
	}
}

1;

