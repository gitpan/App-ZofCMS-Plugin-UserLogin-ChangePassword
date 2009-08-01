use Test::More tests => 5;

BEGIN {
    use_ok('App::ZofCMS::Plugin::Base');
    use_ok('DBI');
    use_ok('Digest::MD5');
    use_ok('HTML::Template');
	use_ok( 'App::ZofCMS::Plugin::UserLogin::ChangePassword' );
}

diag( "Testing App::ZofCMS::Plugin::UserLogin::ChangePassword $App::ZofCMS::Plugin::UserLogin::ChangePassword::VERSION, Perl $], $^X" );
