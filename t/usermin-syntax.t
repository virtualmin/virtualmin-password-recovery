use Test::Strict tests => 3;                      # last test to print

syntax_ok( 'usermin.cgi' );
strict_ok( 'usermin.cgi' );
warnings_ok( 'usermin.cgi' );
