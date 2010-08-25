#!/usr/local/bin/perl
# Find the domain, and send off email. Rate limiting is used to prevent too
# many requests from the same IP.

require './password-recovery-lib.pl';
&popup_header($text{'email_title'});
&ReadParse();
print "<center><h1>$text{'email_title'}</h1></center>\n";

# Check IP rate limit - allow no more than 10 tries in 5 minutes
$ratelimit_file = "$module_config_directory/ratelimit";
&lock_file($ratelimit_file);
&read_file($ratelimit_file, \%ratelimit);
$ip = $ENV{'REMOTE_ADDR'};
$now = time();
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
	&error_and_exit($text{'email_erate'});
	}

# Check for Virtualmin or Cloudmin
$has_virt || $has_vm2 || &error_and_exit($text{'email_eproduct'});

# Validate inputs
$in{'user'} || $in{'dom'} || &error_and_exit($text{'email_einput'});

if ($has_virt) {
	# Try to find the virtualmin domain
	if ($in{'user'}) {
		# Search by username
		$dom = &virtual_server::get_domain_by("user", $in{'user'},
						      "parent", "");
		}
	if ($in{'dom'} && !$dom) {
		# Search by domain name
		$dom = &virtual_server::get_domain_by("dom", $in{'dom'});
		if ($dom && $dom->{'parent'}) {
			# Find the parent domain
			$dom = &virtual_server::get_domain($dom->{'parent'});
			}
		}
	if ($dom) {
		$dom->{'emailto'} || &error_and_exit($text{'email_eto'});
		$url = uc($ENV{'HTTPS'}) eq "ON" ? "https" : "http";
		$url .= "://$dom->{'dom'}:$ENV{'SERVER_PORT'}";
		}
	}

if ($has_vm2 && !$dom) {
	# Try to find the Cloudmin system owner
	if ($in{'user'}) {
		# Search by system owner
		$owner = &server_manager::get_system_owner($in{'user'});
		}
	if ($in{'dom'} && !$owner) {
		# Search by host name
		$server = &server_manager::get_managed_system_by("host",
								 $in{'dom'});
		if ($server) {
			($owner) = &server_manager::get_server_owners($server);
			}
		}
	if ($owner) {
		$owner->{'acl'}->{'email'} ||
			&error_and_exit($text{'email_eto2'});
		$owner->{'acl'}->{'plainpass'} ||
			&error_and_exit($text{'email_eplainpass'});
		$url = uc($ENV{'HTTPS'}) eq "ON" ? "https" : "http";
		($host) = split(/:/, $ENV{'HTTP_HOST'});
		$url .= "://$host:$ENV{'SERVER_PORT'}";
		}
	}

# Make sure something was found
$dom || $owner ||
	&error_and_exit($has_virt && $has_vm2 ? $text{'email_edom3'} :
			$has_vm2 ? $text{'email_edom2'} :
				   $text{'email_edom'});

$msg = &get_custom_email();
if ($msg) {
	# Use custom email, with substitutions
	%hash = $dom ? %$dom : %$owner;
	$hash{'URL'} = $url;
	$hash{'CLIENTIP'} = $ENV{'REMOTE_HOST'};
	$hash{'USERAGENT'} = $ENV{'HTTP_USER_AGENT'};
	$msg = &substitute_template($msg, \%hash);
	}
elsif ($dom) {
	# Use default Virtualmin message
	$msg = &text('email_msg', $dom->{'dom'},
				  $dom->{'user'},
				  $dom->{'pass'},
				  $url,
				  $ENV{'REMOTE_HOST'},
				  $ENV{'HTTP_USER_AGENT'});
	$msg =~ s/\\n/\n/g;
	}
elsif ($owner) {
	# Use default Cloudmin message
	$msg = &text('email_msg2', $owner->{'name'},
				   $owner->{'acl'}->{'plainpass'},
				   $url,
				   $ENV{'REMOTE_HOST'},
				   $ENV{'HTTP_USER_AGENT'});
	$msg =~ s/\\n/\n/g;
	}

# Send email
&foreign_require("mailboxes", "mailboxes-lib.pl");
$msg = join("\n", &mailboxes::wrap_lines($msg, 70))."\n";
&mailboxes::send_text_mail($virtual_server::config{'from_addr'} ||
			     &mailboxes::get_from_address(),
			   $dom ? $dom->{'emailto'}
				: $owner->{'acl'}->{'email'},
			   undef,
			   $dom ? $text{'email_subject'}
				: $text{'email_subject2'},
			   $msg);

# Tell the user
if ($dom) {
	print "<p>",&text('email_done', "<tt>$dom->{'emailto'}</tt>",
					"<tt>$dom->{'dom'}</tt>"),"<p>\n";

	&popup_footer();
	&webmin_log("email", undef, $dom->{'dom'},
		    { 'email' => $dom->{'emailto'},
		      'virt' => 1 });
	}
elsif ($owner) {
	print "<p>",&text('email_done2', "<tt>$owner->{'acl'}->{'email'}</tt>",
					 "<tt>$owner->{'name'}</tt>"),"<p>\n";

	&popup_footer();
	&webmin_log("email", undef, $owner->{'name'},
		    { 'email' => $owner->{'acl'}->{'email'},
		      'vm2' => 1 });
	}

sub error_and_exit
{
print "<p><b>$text{'email_failed'} : $_[0]</b><p>\n";
&popup_footer();
exit;
}

