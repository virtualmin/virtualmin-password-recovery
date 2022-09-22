#!/usr/local/bin/perl
# Find the domain, and send off email. Rate limiting is used to prevent too
# many requests from the same IP.
use strict;
use warnings;
our (%text, %in, %config);
our $module_name;
our ($has_virt, $has_vm2);

our $trust_unknown_referers = 1;
our $recovery_link_dir;
require './password-recovery-lib.pl';
&popup_header($text{'email_title'});
&ReadParse();
print "<center><h1>$text{'email_title'}</h1></center>\n";

# Check IP rate limit - allow no more than 10 tries in 5 minutes
my $err = &check_rate_limit();
$err && &error_and_exit($err);

# Check if this is a callback from an email
if ($in{'id'} && $in{'id'} =~ /^[a-z0-9]+$/i) {
	my %link;
	&read_file("$recovery_link_dir/$in{'id'}", \%link);
	($in{'id'} && $link{'id'} && $link{'id'} eq $in{'id'}) ||
		&error_and_exit(&text('email_eid', $in{'id'}));
	%in = %link;
	&unlink_file("$recovery_link_dir/$in{'id'}");
	if (time() - $link{'time'} > 86400) {
		&error_and_exit($text{'email_etime'});
		}
	}
elsif ($in{'id'} =~ /\S+/) {
	&error(&text('email_eid', $in{'id'}));
	}

# Check for Virtualmin or Cloudmin
$has_virt || $has_vm2 || $in{'usermin'} ||
	&error_and_exit($text{'email_eproduct'});

# Validate inputs
$in{'user'} || $in{'dom'} || $in{'email'} ||
	&error_and_exit($text{'email_einput'});

# Figure out recovery mode
my $mode = $config{'mode'} == 0 ? $in{'mode'} : $config{'mode'};

my ($user, $userd);
my ($urlhost, $url);
($urlhost) = split(/:/, $ENV{'HTTP_HOST'});
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
		my ($mb, $dname) = split(/\@/, $in{'email'});
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
		$urlhost = $userd->{'dom'};
		$url = $miniserv{'ssl'} ? "https" : "http";
		$url .= "://$urlhost:$miniserv{'port'}";
		}
	}

my $dom;
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
		$url = &virtual_server::get_virtualmin_url($dom);
		}
	}

my $owner;
if ($has_vm2 && !$dom && !$user) {
	# Try to find the Cloudmin system owner
	if ($in{'user'}) {
		# Search by system owner
		$owner = &server_manager::get_system_owner($in{'user'});
		}
	if ($in{'dom'} && !$owner) {
		# Search by host name
		my $server = &server_manager::get_managed_system_by("host",
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
		$url .= "://$urlhost:$ENV{'SERVER_PORT'}";
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
	if (!$user->{'recovery'}) {
		# Virtualmin versions before 4.15 don't set this field yet,
		# but we can read it manually
		my $rfile = "$user->{'home'}/.usermin/changepass/recovery";
		$user->{'recovery'} = &virtual_server::write_as_mailbox_user(
			$user, sub { &read_file_contents($rfile) });
		$user->{'recovert'} =~ s/\r|\n//g if ($user->{'recovert'});
		}
	$user->{'recovery'} || &error_and_exit($text{'email_euserrandom'});
	}

# Check if immediate change to a random password is possible
my $immediate = $config{'immediate'} || $in{'id'};

my $lurl;
my $randpass;
if ($mode == 1 && !$immediate) {
	# Password reset requires clicking on a link, sent via email

	# Generate an ID and save recovery details
	my %link = %in;
	$link{'id'} = &generate_random_id();
	$link{'id'} || &error_and_exit($text{'email_esid'});
	$link{'remote'} = $ENV{'REMOTE_ADDR'};
	$link{'time'} = time();
	&make_dir($recovery_link_dir, 0700);
	&write_file("$recovery_link_dir/$link{'id'}", \%link);

	# Work out link back to this page
	$lurl = uc($ENV{'HTTPS'}) eq "ON" ? "https" : "http";
	$lurl .= "://$urlhost:$ENV{'SERVER_PORT'}/$module_name/email.cgi".
		 "?id=".&urlize($link{'id'});
	}
elsif ($mode == 1 && $immediate) {
	# Generate a new random password
	if ($user) {
		# For Usermin user
		$randpass = &virtual_server::random_password();
		my $olduser = { %$user };
		$user->{'passmode'} = 3;
		$user->{'plainpass'} = $randpass;
		$user->{'pass'} = &virtual_server::encrypt_user_password(
					$user, $user->{'plainpass'});
		&virtual_server::modify_user($user, $olduser, $userd);

                # Call plugin save functions
                foreach my $f (&virtual_server::list_mail_plugins()) {
                	&virtual_server::plugin_call($f, "mailbox_modify",
				     $user, $olduser, $userd);
			}
		}
	elsif ($dom) {
		# For Virtualmin domain
		$randpass = &virtual_server::random_password();
		foreach my $d (&virtual_server::get_domain_by("user",
							      $dom->{'user'})) {
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
			no warnings "once";
			foreach my $f (@virtual_server::features) {
				if ($virtual_server::config{$f} && $d->{$f}) {
					no strict;
					my $mfunc =
						"virtual_server::modify_".$f;
					&$mfunc($d, $oldd);
					}
				}
			use warnings "once";
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

my $custommsg = &get_custom_email();
my $msg;
if ($mode == 1 && !$immediate) {
	# Message just contains a password reset link
	if ($user) {
		$msg = &text('email_msglink3', $lurl, $user->{'user'},
			     		       $ENV{'REMOTE_HOST'});
		}
	elsif ($dom) {
		$msg = &text('email_msglink', $lurl, $dom->{'dom'},
					      $ENV{'REMOTE_HOST'});
		}
	elsif ($owner) {
		$msg = &text('email_msglink2', $lurl, $owner->{'name'},
					       $ENV{'REMOTE_HOST'});
		}
	$msg =~ s/\\n/\n/g;
	}
elsif ($custommsg) {
	# Use custom email, with substitutions
	my %userdata = $user ? %$user : $dom ? %$dom : %$owner;
	$userdata{'PASS'} = $randpass if ($randpass);
	$userdata{'URL'} = $url;
	$userdata{'CLIENTIP'} = $ENV{'REMOTE_HOST'};
	$userdata{'USERAGENT'} = $ENV{'HTTP_USER_AGENT'};
	$msg = &substitute_template($custommsg, \%userdata);
	}
elsif ($user) {
	# Use default Usermin message
	$randpass || $user->{'plainpass'} ||
		&error_and_exit(&text('email_euserpass', $user->{'user'}));
	my $defemail = &virtual_server::remove_userdom($user->{'user'}, $userd).
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
	$randpass || $dom->{'pass'} ||
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
	$randpass || $owner->{'acl'}->{'plainpass'} ||
		&error_and_exit(&text('email_eownerpass', $dom->{'user'}));
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
my $emailto = $user ? $user->{'recovery'} :
	   $dom ? $dom->{'emailto'} :
		  $owner->{'acl'}->{'email'};
my $subject = $user ? $text{'email_subject3'} :
	   $dom ? $text{'email_subject'} :
		  $text{'email_subject2'};
if ($mode == 1 && !$immediate) {
	$subject = &text('email_linkfor', $subject);
	}
&mailboxes::send_text_mail($virtual_server::config{'from_addr'} ||
			     &mailboxes::get_from_address(),
			   $emailto,
			   undef,
			   $subject,
			   $msg);

# Tell the user
if ($mode == 1 && !$immediate) {
	print "<p>",&text('email_donelink', "<tt>$emailto</tt>"),"</p>\n";
	&popup_footer();
	}
elsif ($dom) {
	print "<p>",&text('email_done', "<tt>$emailto</tt>",
					"<tt>$dom->{'dom'}</tt>"),"<p>\n";
	print &text('email_return', "/"),"<p>\n";

	&popup_footer();
	&webmin_log("email", undef, $dom->{'dom'},
		    { 'email' => $emailto,
		      'virt' => 1 });
	}
elsif ($owner) {
	print "<p>",&text('email_done2', "<tt>$emailto</tt>",
					 "<tt>$owner->{'name'}</tt>"),"<p>\n";
	print &text('email_return', "/"),"<p>\n";

	&popup_footer();
	&webmin_log("email", undef, $owner->{'name'},
		    { 'email' => $emailto,
		      'vm2' => 1 });
	}
elsif ($user) {
        print "<p>",&text('email_done3', "<tt>$emailto</tt>",
                                         "<tt>$user->{'user'}</tt>"),"<p>\n";
	print &text('email_return', $url),"<p>\n";

        &popup_footer();
        &webmin_log("email", undef, $user->{'user'},
                    { 'email' => $emailto,
                      'usermin' => 1 });
	}

sub error_and_exit
{
print "<p><b>$text{'email_failed'} : $_[0]</b><p>\n";
&popup_footer();
exit;
}
