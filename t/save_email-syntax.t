use Test::Strict tests => 3;                      # last test to print

syntax_ok( 'save_email.cgi' );
strict_ok( 'save_email.cgi' );
warnings_ok( 'save_email.cgi' );
