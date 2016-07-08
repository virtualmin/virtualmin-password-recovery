use Test::Strict tests => 3;                      # last test to print

syntax_ok( 'email.cgi' );
strict_ok( 'email.cgi' );
warnings_ok( 'email.cgi' );
