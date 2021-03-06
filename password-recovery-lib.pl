# Functions for re-sending a virtualmin domain owner or cloudmin system
# owner's password
use strict;
use warnings;
our %text;
our $module_config_directory;
our ($has_virt, $has_vm2);

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

our $custom_email_file = "$module_config_directory/email";
our $recovery_link_dir = "$module_config_directory/links";

sub get_custom_email
{
if (open(my $CUSTOM, "<", $custom_email_file)) {
	my $rv;
	while(<$CUSTOM>) {
		$rv .= $_;
		}
	close($CUSTOM);
	return $rv;
	}
return undef;
}

sub save_custom_email
{
my ($email) = @_;
if (defined($email)) {
	open(my $CUSTOM, ">", "$custom_email_file");
	print $CUSTOM $email;
	close($CUSTOM);
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
my %ratelimit;
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

# generate_random_id()
# Generate an ID string that can be used for a password reset link
sub generate_random_id
{
if (open(my $RANDOM, "<", "/dev/urandom")) {
	my $sid;
	my $tmpsid;
	if (read($RANDOM, $tmpsid, 16) == 16) {
		$sid = lc(unpack('h*',$tmpsid));
		}
	close($RANDOM);
	return $sid;
	}
return undef;
}

1;
