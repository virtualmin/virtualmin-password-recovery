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

# Validate inputs
$in{'user'} || $in{'dom'} || &error_and_exit($text{'email_einput'});

# Try to find the domain
if ($in{'user'}) {
	$dom = &virtual_server::get_domain_by("user", $in{'user'},
					      "parent", "");
	}
if ($in{'dom'} && !$dom) {
	$dom = &virtual_server::get_domain_by("dom", $in{'dom'});
	if ($dom && $dom->{'parent'}) {
		# Find the parent domain
		$dom = &virtual_server::get_domain($dom->{'parent'});
		}
	}
$dom || &error_and_exit($text{'email_edom'});
$dom->{'emailto'} || &error_and_exit($text{'email_eto'});

$msg = &get_custom_email();
$url = uc($ENV{'HTTPS'}) eq "ON" ? "https" : "http";
$url .= "://$dom->{'dom'}:$ENV{'SERVER_PORT'}";
if ($msg) {
	# Use custom email, with substitutions
	%hash = %$dom;
	$hash{'URL'} = $url;
	$hash{'CLIENTIP'} = $ENV{'REMOTE_HOST'};
	$hash{'USERAGENT'} = $ENV{'HTTP_USER_AGENT'};
	$msg = &substitute_template($msg, \%hash);
	}
else {
	# Use default
	$msg = &text('email_msg', $dom->{'dom'},
				  $dom->{'user'},
				  $dom->{'pass'},
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
			   $dom->{'emailto'},
			   undef,
			   $text{'email_subject'},
			   $msg);

# Tell the user
print "<p>",&text('email_done', "<tt>$dom->{'emailto'}</tt>",
				"<tt>$dom->{'dom'}</tt>"),"<p>\n";

&popup_footer();
&webmin_log("email", undef, $dom->{'dom'}, { 'email' => $dom->{'emailto'} });

sub error_and_exit
{
print "<p><b>$text{'email_failed'} : $_[0]</b><p>\n";
&popup_footer();
exit;
}

