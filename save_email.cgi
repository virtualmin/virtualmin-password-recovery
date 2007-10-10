#!/usr/local/bin/perl
# Save custom recovery email

require './password-recovery-lib.pl';
&ReadParseMime();
&error_setup($text{'save_err'});
$ENV{"ANONYMOUS_USER"} && &error($text{'save_eanon'});

&lock_file($custom_email_file);
if ($in{'email_def'}) {
	&save_custom_email(undef);
	}
else {
	$in{'email'} =~ s/\r//g;
	$in{'email'} =~ /\S/ || &error($text{'save_eemail'});
	if ($in{'email'} !~ /\n$/) {
		$in{'email'} .= "\n";
		}
	&save_custom_email($in{'email'});
	}
&unlock_file($custom_email_file);

&webmin_log("save");
&redirect("");

