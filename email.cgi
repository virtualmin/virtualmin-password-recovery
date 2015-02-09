#!/usr/local/bin/perl
# Find the domain, and send off email. Rate limiting is used to prevent too
# many requests from the same IP.

require './password-recovery-lib.pl';
&popup_header($text{'email_title'});
&ReadParse();
print "<center><h1>$text{'email_title'}</h1></center>\n";

# Check IP rate limit - allow no more than 10 tries in 5 minutes
$err = &check_rate_limit();
$err && &error_and_exit($err);

# Check for Virtualmin or Cloudmin
$has_virt || $has_vm2 || $in{'usermin'} ||
	&error_and_exit($text{'email_eproduct'});

# Validate inputs
$in{'user'} || $in{'dom'} || $in{'email'} ||
	&error_and_exit($text{'email_einput'});

# Figure out recovery mode
$mode = $config{'mode'} == 0 ? $in{'mode'} : $config{'mode'};

if ($in{'usermin'}) {
	# Try to find mailbox user
	if ($in{'user'}) {
		# Search by full username
		$userd = &virtual_server::get_user_domain($in{'user'});
		if ($userd) {
			my @users = &virtual_server::list_domain_users(
					$userd, 0, 1, 1, 1);
			($user) = grep {
				$_->{'user'} eq $in{'user'} ||
				&virtual_server::replace_atsign($_->{'user'})
				  eq $in{'user'}
				} @users;
			}
		}
	elsif ($in{'email'} =~ /^\S+\@\S+$/) {
		# Search by email
		($mb, $dname) = split(/\@/, $in{'email'});
		$userd = &virtual_server::get_domain_by("dom", $dname);
		if ($userd) {
			my @users = &virtual_server::list_domain_users(
					$userd, 0, 1, 1, 1);
			($user) = grep {
				&virtual_server::remove_userdom(
					$_->{'user'}, $userd) eq $mb
				} @users;
			}
		}
	if ($user) {
		# Work out Usermin URL
		&foreign_require("usermin");
		my %miniserv;
		&usermin::get_usermin_miniserv_config(\%miniserv);
		$url = $miniserv{'ssl'} ? "https" : "http";
		$url .= "://$userd->{'dom'}:$miniserv{'port'}";
		}
	}

if ($has_virt && !$user) {
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

if ($has_vm2 && !$dom && !$user) {
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
$dom || $owner || $user ||
	&error_and_exit($in{'usermin'} ? $text{'email_edom4'} :
			$has_virt && $has_vm2 ? $text{'email_edom3'} :
			$has_vm2 ? $text{'email_edom2'} :
				   $text{'email_edom'});

# Only allow reset if there is a recovery address
if ($mode == 1 && $dom) {
	$dom->{'email'} || &error_and_exit($text{'email_edomrandom'});
	}
if ($user) {
	$user->{'recovery'} || &error_and_exit($text{'email_euserrandom'});
	}

# Generate a new random password
if ($mode == 1) {
	if ($user) {
		# For Usermin user
		# XXX
		}
	elsif ($dom) {
		# For Virtualmin domain
		$randpass = &virtual_server::random_password();
		foreach my $d (&virtual_server::get_domain_by("user", $dom->{'user'})) {
			my $oldd = { %$d };
			$d->{'pass'} = $randpass;
			$d->{'pass_set'} = 1;
			&virtual_server::generate_domain_password_hashes($d, 0);
			if ($d->{'disabled'}) {
				# Clear any saved passwords, as they should
				# be reset at this point
				$d->{'disabled_mysqlpass'} = undef;
				$d->{'disabled_postgrespass'} = undef;
				}
			# Update all features
			foreach my $f (@virtual_server::features) {
				if ($virtual_server::config{$f} && $d->{$f}) {
					local $mfunc =
						"virtual_server::modify_".$f;
					&$mfunc($d, $oldd);
					}
				}
			# Update all plugins
			foreach my $f (&virtual_server::list_feature_plugins()) {
				if ($d->{$f}) {
					&virtual_server::plugin_call(
					    $f, "feature_modify", $d, $oldd);
					}
				}
			&virtual_server::save_domain($d);
			}
		}
	elsif ($owner) {
		# For Cloudmin owner
		$randpass = &server_manager::generate_random_password();
		my $old = { %$owner };
		$owner->{'pass'} = &acl::encrypt_password($randpass);
		&server_manager::save_system_owner($owner, $old);
		}
	}

$msg = &get_custom_email();
if ($msg) {
	# Use custom email, with substitutions
	%hash = $user ? %$user : $dom ? %$dom : %$owner;
	$hash{'PASS'} = $randpass if ($randpass);
	$hash{'URL'} = $url;
	$hash{'CLIENTIP'} = $ENV{'REMOTE_HOST'};
	$hash{'USERAGENT'} = $ENV{'HTTP_USER_AGENT'};
	$msg = &substitute_template($msg, \%hash);
	}
elsif ($user) {
	# Use default Usermin message
	$user->{'plainpass'} ||
		&error_and_exit(&text('email_euserpass', $user->{'user'}));
	$defemail = &virtual_server::remove_userdom($user->{'user'}, $userd).
		    "\@".$userd->{'dom'};
	$msg = &text('email_msg3', $user->{'user'},
				   $user->{'email'} || $defemail,
				   $randpass || $user->{'plainpass'},
				   $url,
				   $ENV{'REMOTE_HOST'},
				   $ENV{'HTTP_USER_AGENT'});
	$msg =~ s/\\n/\n/g;
	}
elsif ($dom) {
	# Use default Virtualmin message
	$dom->{'pass'} ||
		&error_and_exit(&text('email_edompass', $dom->{'user'}));
	$msg = &text('email_msg', $dom->{'dom'},
				  $dom->{'user'},
				  $randpass || $dom->{'pass'},
				  $url,
				  $ENV{'REMOTE_HOST'},
				  $ENV{'HTTP_USER_AGENT'});
	$msg =~ s/\\n/\n/g;
	}
elsif ($owner) {
	# Use default Cloudmin message
	$msg = &text('email_msg2', $owner->{'name'},
				   $randpass || $owner->{'acl'}->{'plainpass'},
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
			   $user ? $user->{'recovery'} :
			   $dom ? $dom->{'emailto'} :
				  $owner->{'acl'}->{'email'},
			   undef,
			   $user ? $text{'email_subject3'} :
			   $dom ? $text{'email_subject'} :
				  $text{'email_subject2'},
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
elsif ($user) {
        print "<p>",&text('email_done3', "<tt>$user->{'recovery'}</tt>",
                                         "<tt>$user->{'user'}</tt>"),"<p>\n";

        &popup_footer();
        &webmin_log("email", undef, $user->{'user'},
                    { 'email' => $user->{'recovery'},
                      'usermin' => 1 });
	}

sub error_and_exit
{
print "<p><b>$text{'email_failed'} : $_[0]</b><p>\n";
&popup_footer();
exit;
}

