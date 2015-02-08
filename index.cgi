#!/usr/local/bin/perl
# Show a page for Virtualmin domain owners or Cloudmin system owners to use to
# retrieve their lost passwords via email.

$trust_unknown_referers = 1;
require './password-recovery-lib.pl';
$sfx = $has_virt && $has_vm2 ? "3" : $has_vm2 ? "2" : "";

if (!$ENV{"ANONYMOUS_USER"}) {
	# Being accessed non-anonymously .. tell the admin
	&ui_print_header(undef, $text{'index_title'.$sfx}, "", undef, 0, 1);

	$url = uc($ENV{'HTTPS'}) eq "ON" ? "https" : "http";
	$url .= "://$ENV{'SERVER_NAME'}:$ENV{'SERVER_PORT'}";
	$url .= "/$module_name/";
	print "<p>",&text('index_usage', "<a href='$url'>$url</a>"),"</p>\n";

	# Show form for editing email
	print "<hr>\n";
	print &ui_subheading($text{'index_emailheader'});
	print $text{'index_emaildesc'},"<p>\n";
	print &ui_form_start("save_email.cgi", "form-data");
	$email = &get_custom_email();
	print &ui_radio("email_def", $email ? 0 : 1,
			[ [ 1, $text{'index_emaildef'} ],
			  [ 0, $text{'index_emailset'} ] ]),"<br>\n";
	print &ui_textarea("email", $email, 10, 70);

	print &ui_form_end([ [ "save", $text{'save'} ] ]);

	&ui_print_footer("/", $text{'index'});
	}
else {
	# Show recovery form
	&popup_header($text{'index_title'});
	print "<center><h1>",$text{'index_title'.$sfx},"</h1></center>\n";

	print $text{'index_desc'.$sfx},"<p>\n";

	print &ui_form_start("email.cgi", "post");
	print &ui_table_start($text{'index_header'}, undef, 2);

	# Username or domain name
	print &ui_table_row($text{'index_user'.$sfx},
			    &ui_textbox("user", undef, 30));
	print &ui_table_row(" ", $text{'index_or'});
	print &ui_table_row($text{'index_dom'.$sfx},
			    &ui_textbox("dom", undef, 60));

	# Reset method (if allowed)
	if ($config{'mode'} == 0) {
		print &ui_table_row($text{'index_mode'},
			&ui_radio("mode", 1, [ [ 1, $text{'index_mode1'} ],
					       [ 2, $text{'index_mode2'} ] ]));
		}

	print &ui_table_end();
	print &ui_form_end([ [ undef, $text{'index_submit'} ] ]);

	&popup_footer();
	}

