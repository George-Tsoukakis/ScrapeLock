<?php
/**
 * ScrapeLock 3.12.6 — no false "installed: not found" right after saving the Bots tab.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3126_status.php
 *
 * On the live site (aaPanel, part 2 installed, the check address answering its fingerprint) saving the Bots tab
 * showed "The server rules are out of date (installed: not found, …)". The save changed part 1 (a new bot); the
 * next self-check answer without the fingerprint header (a location with add_header lines of its own) then wrote
 * "installed" = '' because the kept answer of the check address was for the old fingerprint.
 *
 * B. The bug: the save keeps "installed", one answer without the header changes nothing, the notice names part 1.
 * P. Only part 2 differs: the notice names part 2; both differ: the message of 3.12.3.
 * G. "Not found" only after two fresh checks of the server at least 3 s apart; a check that could not reach the
 *    server never counts; a first one alone, or one too soon, does not; a fingerprint again clears it.
 * F. A fresh check through PNCP_Rules_Status (mocked answers): Nginx's own 404 is a failed check, a timeout is not.
 * H. Over HTTP: the dashboard notice after the save, the second check (admin-ajax, nonce, manage_options) and the
 *    script that asks for it only while it is due.
 *
 * Only on a test WordPress.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/screen.php';
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
}

$saved_settings = PNCP_Options::stored();
$saved_state    = get_option( PNCP_Rules_State::STATE, null );
register_shutdown_function(
	static function () use ( $saved_settings, $saved_state ) {
		update_option( PNCP_OPTION, $saved_settings );
		if ( null === $saved_state ) {
			delete_option( PNCP_Rules_State::STATE );
		} else {
			update_option( PNCP_Rules_State::STATE, $saved_state, false );
		}
		delete_transient( PNCP_Rules_Status::NGINX );
		delete_transient( PNCP_Rules_Status::APACHE );
	}
);

$admin = (int) wp_insert_user(
	array(
		'user_login' => 't3126-admin-' . wp_generate_password( 6, false ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'administrator',
	)
);
$sub   = (int) wp_insert_user(
	array(
		'user_login' => 't3126-sub-' . wp_generate_password( 6, false ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'subscriber',
	)
);
register_shutdown_function(
	static function () use ( $admin, $sub ) {
		wp_delete_user( $admin );
		wp_delete_user( $sub );
	}
);

$bots = (string) $saved_settings['bot_list'];
$bots = trim( (string) preg_replace( '/^BuiltWith$/mi', '', $bots ) );
settings(
	array(
		'block_bots'    => 1,
		'bot_list'      => $bots,
		'hide_versions' => 0,
	)
);
delete_option( PNCP_Rules_State::STATE );
delete_transient( PNCP_Rules_Status::NGINX );

/* ---------- B. The bug ---------- */

// The rules are installed and current: the check address answered them (kept, as the Server rules tab keeps it).
$fp = PNCP_Rules::nginx_fingerprint();
set_transient(
	PNCP_Rules_Status::NGINX,
	array(
		'want'  => $fp,
		'v'     => PNCP_Rules_Status::VERSION,
		'body'  => $fp,
		'error' => '',
		'via'   => 'origin',
		'ip'    => '127.0.0.1',
		'kind'  => 'fingerprint',
		'code'  => 200,
	),
	300
);
PNCP_Rules_State::from_status();
t( 'B the installed rules are the current ones', PNCP_Rules_State::in_use() && ! PNCP_Rules_State::is_stale() && $fp === PNCP_Rules_State::state()['installed'] );

// Saving the Bots tab: BuiltWith goes into the bot list (part 1 changes, part 2 does not).
settings( array( 'bot_list' => $bots . "\nBuiltWith" ) );
$new = PNCP_Rules::nginx_fingerprint();
$st  = PNCP_Rules_State::state();
t( 'B the save: only part 1 changed', strtok( $fp, ' ' ) !== strtok( $new, ' ' ) && substr( $fp, 13 ) === substr( $new, 13 ), $fp . ' / ' . $new );
t( 'B the save recomputes "current" only: "installed" stays as last seen', $fp === $st['installed'] && $new === $st['current'] && 0 === $st['gone'] && 0 === $st['miss'], wp_json_encode( $st ) );
// The next self-check's answer carries no fingerprint header (a PHP location with add_header lines of its own).
PNCP_Rules_State::record( '' );
$st  = PNCP_Rules_State::state();
$msg = PNCP_Rules_State::message();
t( 'B an answer without the header after the save: "installed" is not lost (was: "installed: not found")', $fp === $st['installed'] && false === strpos( $msg, 'not found' ), $msg );
t( 'B the notice names part 1 and keeps both fingerprints', PNCP_Rules_State::is_stale() && $msg === sprintf( 'The server rules are installed, but part 1 (http { }) is out of date (installed: %1$s, current: %2$s). Copy part 1 again from Server rules.', $fp, $new ), $msg );
t( 'B stale_parts(): http', array( 'http' ) === PNCP_Rules_State::stale_parts() );

/* ---------- P. Which part ---------- */

settings( array( 'bot_list' => $bots ) );
t( 'P the bot list back: up to date again', ! PNCP_Rules_State::is_stale() );
settings( array( 'hide_versions' => 1 ) );
$new2 = PNCP_Rules::nginx_fingerprint();
t( 'P only part 2 changed (hide versions)', strtok( $fp, ' ' ) === strtok( $new2, ' ' ) && substr( $fp, 13 ) !== substr( $new2, 13 ) );
t( 'P the notice names part 2', array( 'server' ) === PNCP_Rules_State::stale_parts() && false !== strpos( PNCP_Rules_State::message(), 'installed, but part 2 (server { }) is out of date' ), PNCP_Rules_State::message() );
settings( array( 'bot_list' => $bots . "\nBuiltWith" ) );
t( 'P both parts changed: the message of 3.12.3, both fingerprints', array( 'http', 'server' ) === PNCP_Rules_State::stale_parts() && PNCP_Rules_State::message() === sprintf( 'The server rules are out of date (installed: %1$s, current: %2$s). Copy them again from Server rules.', $fp, PNCP_Rules::nginx_fingerprint() ), PNCP_Rules_State::message() );
settings(
	array(
		'bot_list'      => $bots,
		'hide_versions' => 0,
	)
);

/* ---------- G. "Not found" only after two failed checks ---------- */

$now = time();
PNCP_Rules_State::checked( 'nginx', '', false, $now );
t( 'G a check that could not reach the server: never counted', 0 === PNCP_Rules_State::state()['miss'] && ! PNCP_Rules_State::recheck_due( $now ) );
PNCP_Rules_State::checked( 'nginx', '', true, $now );
$st = PNCP_Rules_State::state();
t( 'G a first failed check: only remembered, no notice, a second check is due', $now === $st['miss'] && 0 === $st['gone'] && ! PNCP_Rules_State::is_stale() && PNCP_Rules_State::recheck_due( $now ) );
PNCP_Rules_State::checked( 'nginx', '', true, $now + 1 );
t( 'G a second one within 3 s (the same reload): not yet', 0 === PNCP_Rules_State::state()['gone'] && ! PNCP_Rules_State::is_stale() );
PNCP_Rules_State::checked( 'apache', '', true, $now + 5 );
t( 'G an Apache check on a site with Nginx rules: not counted', 0 === PNCP_Rules_State::state()['gone'] );
PNCP_Rules_State::checked( 'nginx', '', true, $now + 5 );
$st = PNCP_Rules_State::state();
t( 'G a second failed check 5 s later: "not found"', $now + 5 === $st['gone'] && PNCP_Rules_State::is_stale() && false !== strpos( PNCP_Rules_State::message(), 'installed: not found' ) && ! PNCP_Rules_State::recheck_due( $now + 6 ), PNCP_Rules_State::message() );
t( 'G ...with the last seen fingerprint still kept', $fp === $st['installed'] && array() === PNCP_Rules_State::stale_parts() );
PNCP_Rules_State::checked( 'nginx', $fp, false, $now + 9 );
$st = PNCP_Rules_State::state();
t( 'G the fingerprint again: installed and current, nothing pending', ! PNCP_Rules_State::is_stale() && 0 === $st['gone'] && 0 === $st['miss'] );
PNCP_Rules_State::checked( 'nginx', '', true, $now - 2 * PNCP_Rules_State::MISS_WINDOW );
PNCP_Rules_State::checked( 'nginx', '', true, $now );
t( 'G a first failure long ago is forgotten: the next one is a first one again', $now === PNCP_Rules_State::state()['miss'] && 0 === PNCP_Rules_State::state()['gone'] );
PNCP_Rules_State::record( $fp );
delete_option( PNCP_Rules_State::STATE );
PNCP_Rules_State::checked( 'nginx', '', true, $now );
PNCP_Rules_State::checked( 'nginx', '', true, $now + 10 );
t( 'G a site that never had rules: never told anything', ! PNCP_Rules_State::is_stale() && ! PNCP_Rules_State::in_use() );

/* ---------- F. A fresh check through PNCP_Rules_Status (mocked answers) ---------- */

const NGINX_404 = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
$answer = null;
$mock   = static function ( $pre, $args, $url ) use ( &$answer ) {
	if ( null === $answer || false !== $pre ) {
		return $pre;
	}
	return $answer( $url );
};
add_filter( 'pre_http_request', $mock, 1, 3 );
add_filter(
	'pncp_selfcheck_origin_ips',
	static function () {
		return array( '127.0.0.1' );
	}
);
$reply = static function ( $code, $headers, $body ) {
	return array(
		'headers'  => $headers,
		'body'     => $body,
		'response' => array(
			'code'    => $code,
			'message' => '',
		),
		'cookies'  => array(),
		'filename' => null,
	);
};
PNCP_Rules_State::checked( 'nginx', $fp, false );
$answer = static function ( $url ) use ( $reply ) {
	return $reply( 404, array( 'server' => 'nginx' ), NGINX_404 );
};
PNCP_Rules_Status::nginx( true );
$st = PNCP_Rules_State::state();
t( 'F Nginx\'s own 404 at the check address: a first failed check, no notice yet', $st['miss'] > 0 && 0 === $st['gone'] && ! PNCP_Rules_State::is_stale(), wp_json_encode( $st ) );
$st['miss'] = time() - 5;
update_option( PNCP_Rules_State::STATE, $st, false );
$answer = static function () {
	return new WP_Error( 'http_request_failed', 'cURL error 28: Operation timed out' );
};
PNCP_Rules_Status::nginx( true );
t( 'F a timeout (Nginx reloading): not a failed check', 0 === PNCP_Rules_State::state()['gone'] );
$answer = static function ( $url ) use ( $reply ) {
	return $reply( 404, array( 'server' => 'nginx' ), NGINX_404 );
};
PNCP_Rules_Status::nginx( true );
t( 'F Nginx\'s own 404 again, seconds later: "not found"', PNCP_Rules_State::state()['gone'] > 0 && PNCP_Rules_State::is_stale() );
$answer = static function ( $url ) use ( $reply, $fp ) {
	return $reply( 200, array( 'server' => 'nginx' ), $fp . "\n" );
};
PNCP_Rules_Status::nginx( true );
t( 'F the check address answers the fingerprint: installed again', ! PNCP_Rules_State::is_stale() && $fp === PNCP_Rules_State::state()['installed'] );
$answer = null;
remove_filter( 'pre_http_request', $mock, 1 );
delete_transient( PNCP_Rules_Status::NGINX );

/* ---------- H. Over HTTP ---------- */

$cookies = static function ( $user ) {
	$expire = time() + HOUR_IN_SECONDS;
	$token  = WP_Session_Tokens::get_instance( $user )->create( $expire );
	$c      = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user, $expire, 'logged_in', $token ),
	);
	$_COOKIE[ LOGGED_IN_COOKIE ] = $c[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user );
	return AUTH_COOKIE . '=' . rawurlencode( $c[ AUTH_COOKIE ] ) . '; ' . LOGGED_IN_COOKIE . '=' . rawurlencode( $c[ LOGGED_IN_COOKIE ] );
};
$http = static function ( $path, $cookie, $post = null ) use ( $base ) {
	$ch = curl_init( $base . $path );
	$o  = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_COOKIE         => $cookie,
		CURLOPT_HTTPHEADER     => array( 'User-Agent: ' . BROWSER, 'Accept-Language: en' ),
		CURLOPT_TIMEOUT        => 60,
		CURLOPT_PROXY          => '',
	);
	if ( null !== $post ) {
		$o[ CURLOPT_POST ]       = true;
		$o[ CURLOPT_POSTFIELDS ] = http_build_query( $post );
	}
	curl_setopt_array( $ch, $o );
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	wp_cache_delete( PNCP_Rules_State::STATE, 'options' );
	return array( $code, $body );
};

// The bug, end to end: the save, an answer without the header, then the dashboard.
PNCP_Rules_State::checked( 'nginx', $fp, false );
settings( array( 'bot_list' => $bots . "\nBuiltWith" ) );
PNCP_Rules_State::record( '' );
$ac             = $cookies( $admin );
list( $c, $out ) = $http( '/wp-admin/index.php', $ac );
t( 'H the dashboard after the save: "installed, but part 1 is out of date", never "not found"', 200 === $c && false !== strpos( $out, 'installed, but part 1 (http { }) is out of date' ) && false === strpos( $out, 'installed: not found' ), $c . ' ' . substr( wp_strip_all_tags( $out ), 0, 200 ) );
t( 'H ...and no second check is asked for (nothing failed)', false === strpos( $out, 'pncp-rules-recheck' ) );

// A first failed check: the page asks for the second one, a few seconds later, with a nonce.
$st         = PNCP_Rules_State::state();
$st['miss'] = time() - 5;
update_option( PNCP_Rules_State::STATE, $st, false );
list( $c, $out ) = $http( '/wp-admin/index.php', $ac );
t( 'H a check is due: the dashboard has the script of the second check (after 4 s, admin-ajax, nonce)', false !== strpos( $out, 'id="pncp-rules-recheck"' ) && false !== strpos( $out, '"delay":4000' ) && false !== strpos( $out, PNCP_Rules_State::RECHECK ), substr( $out, 0, 200 ) );
$sc = $cookies( $sub );
list( $c, $out ) = $http( '/wp-admin/admin-ajax.php', $sc, array( 'action' => PNCP_Rules_State::RECHECK, '_wpnonce' => wp_create_nonce( PNCP_Rules_State::RECHECK ) ) );
t( 'H the second check: refused for a subscriber', 403 === $c && 0 === PNCP_Rules_State::state()['gone'], $c . ' ' . $out );
$ac = $cookies( $admin );
list( $c, $out ) = $http( '/wp-admin/admin-ajax.php', $ac, array( 'action' => PNCP_Rules_State::RECHECK, '_wpnonce' => 'bad' ) );
t( 'H the second check: refused without a valid nonce', 403 === $c && 0 === PNCP_Rules_State::state()['gone'], $c . ' ' . $out );
// The server's answers inside the web server's process (a single php -S cannot answer its own requests): Nginx's
// own 404 at the check address, as a server without the rules gives it. A temporary mu-plugin, removed at the end.
$mu = WP_CONTENT_DIR . '/mu-plugins/pncp-test-3126-status.php';
file_put_contents(
	$mu,
	'<?php // TESTS ONLY: written and removed by tests/t_3126_status.php.' . "\n"
	. 'if ( get_option( "pncp_test_3126_status" ) ) { add_filter( "pre_http_request", static function ( $pre, $args, $url ) {'
	. ' return false === strpos( $url, "/.well-known/scrapelock-nginx" ) && empty( $args["pncp_resolve"] ) && false === strpos( $url, "127.0.0.1" ) ? $pre : array( "headers" => array( "server" => "nginx" ), "body" => ' . var_export( NGINX_404, true ) . ', "response" => array( "code" => 404, "message" => "" ), "cookies" => array(), "filename" => null ); }, 1, 3 ); }' . "\n"
);
update_option( 'pncp_test_3126_status', 1, false );
register_shutdown_function(
	static function () use ( $mu ) {
		@unlink( $mu );
		delete_option( 'pncp_test_3126_status' );
	}
);
list( $c, $out ) = $http( '/wp-admin/admin-ajax.php', $ac, array( 'action' => PNCP_Rules_State::RECHECK, '_wpnonce' => wp_create_nonce( PNCP_Rules_State::RECHECK ) ) );
$json = json_decode( $out, true );
t( 'H the second check (administrator, nonce): the server asked again, "not found", the notice returned', 200 === $c && ! empty( $json['success'] ) && ! empty( $json['data']['stale'] ) && false !== strpos( (string) $json['data']['notice'], 'installed: not found' ) && PNCP_Rules_State::state()['gone'] > 0, $c . ' ' . substr( $out, 0, 300 ) );
list( $c, $out ) = $http( '/wp-admin/index.php', $ac );
t( 'H afterwards: the notice says "not found" and no further check is asked for', false !== strpos( $out, 'installed: not found' ) && false === strpos( $out, 'id="pncp-rules-recheck"' ) );
wp_set_current_user( 0 );
unset( $_COOKIE[ LOGGED_IN_COOKIE ] );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
