# Functions for re-sending a virtualmin domain owner or cloudmin system
# owner's password

BEGIN { push(@INC, ".."); };
eval "use WebminCore;";
&init_config();
if (&foreign_check("virtual-server")) {
	&foreign_require("virtual-server", "virtual-server-lib.pl");
	$has_virt = 1;
	}
if (&foreign_check("server-manager")) {
	&foreign_require("server-manager", "server-manager-lib.pl");
	$has_vm2 = 1;
	}

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

# check_rate_limit()
# Returns an error message if the IP is over it's reset rate limit
sub check_rate_limit
{
my $ratelimit_file = "$module_config_directory/ratelimit";
&lock_file($ratelimit_file);
&read_file($ratelimit_file, \%ratelimit);
my $ip = $ENV{'REMOTE_ADDR'};
my $now = time();
if ($ratelimit{$ip."_last"} < $now-5*60) {
	# More than 5 mins since the last try, so reset counter
	$ratelimit{$ip} = 1;
	}
else {
	# Recent, so up counter
	$ratelimit{$ip}++;
	}
$ratelimit{$ip."_last"} = $now;
&write_file($ratelimit_file, \%ratelimit);
&unlock_file($ratelimit_file);
if ($ratelimit{$ip} > 10) {
	return $text{'email_erate'};
	}
return undef;
}

1;

