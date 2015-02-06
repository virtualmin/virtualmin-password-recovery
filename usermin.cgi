#!/usr/local/bin/perl
# Show a page for Usermin users to use to retrieve their lost passwords via
# email.

$trust_unknown_referers = 1;
require './password-recovery-lib.pl';

# If logged in, just go to the setup form
if (!$ENV{"ANONYMOUS_USER"}) {
	&redirect("index.cgi");
	return;
	}

# Show recovery form
&popup_header($text{'index_title'});
print "<center><h1>",$text{'index_title4'},"</h1></center>\n";

print $text{'index_desc4'},"<p>\n";

print &ui_form_start("email.cgi", "post");
print &ui_hidden("usermin", 1);
print &ui_table_start($text{'index_header'}, undef, 2);

# Email address or username
print &ui_table_row($text{'index_user4'},
		    &ui_textbox("user", undef, 30));
print &ui_table_row(" ", $text{'index_or'});
print &ui_table_row($text{'index_email'},
		    &ui_textbox("email", undef, 60));

# Reset method (if allowed)
if ($config{'mode'} == 0) {
	print &ui_table_row($text{'index_mode'},
		&ui_radio("mode", 1, [ [ 1, $text{'index_mode1'} ],
				       [ 2, $text{'index_mode2'} ] ]));
	}

print &ui_table_end();
print &ui_form_end([ [ "email", $text{'index_submit'} ] ]);

&popup_footer();

