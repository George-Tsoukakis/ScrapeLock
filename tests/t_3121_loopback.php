<?php
/**
 * ScrapeLock 3.12.1 — the site's own requests to itself behind Bunny CDN without the CDN secret, in real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3121_loopback.php
 *
 * A live site behind Bunny ("Real visitor IP" = REMOTE_ADDR, "Only through the CDN" on, no CDN secret, "Browsers
 * only", headless check, human check and limits on): "Check again" in Vulnerable points said "the home page
 * answered HTTP 403 to the site itself". Its request leaves the server, passes Bunny and comes back from a Bunny
 * edge, whose address is never the server's: the headless check refused the self-test's Chrome User-Agent on
 * HTTPS ("fake_browser"), the Stealth test's "no_browser".
 *
 * S. The signature of the site's own requests (X-ScrapeLock-Sig): valid, expired, replayed, another path, method
 *    or host, forged; it passes every check in WordPress and the early check, also "Only through the CDN"; the
 *    WordPress User-Agent alone and X-Forwarded-For with the server's address do not.
 * R. Redirects: re-signed on the site's own host, never sent on to another host (stand-in server on 8953).
 * H. Vulnerable points "Check again" and the Stealth test's fetch through the "edge" get the real answers.
 *
 * The HTTP requests "come from the Bunny edge" with the harness's X-Test-Remote-Addr (REMOTE_ADDR in WordPress
 * and the early check) and X-Test-HTTPS. Only on a test WordPress.
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

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Ip::reset();
}

const EDGE      = '198.51.100.10'; // A Bunny edge (in the stored Bunny list below).
const SERVER    = '203.0.113.50';  // The server's public address, as the edge sees it.
const VISITOR   = '198.51.100.81';
const SELF_UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 ScrapeLock-Selftest';
const STEALTH_UA = 'Mozilla/5.0 (compatible; ScrapeLock self-test)';

$own_host = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
$http_host = (string) wp_parse_url( $base, PHP_URL_HOST ) . ( wp_parse_url( $base, PHP_URL_PORT ) ? ':' . wp_parse_url( $base, PHP_URL_PORT ) : '' );
$home_path = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );

/**
 * The $_SERVER of a request to this site over HTTPS (every HTTP_ header removed first): a new request, so the
 * signatures checked before are forgotten (the nonces used stay used).
 */
function as_request( $remote, $ua, $headers = array(), $path = '/', $method = 'GET' ) {
	global $http_host;
	foreach ( array_keys( $_SERVER ) as $k ) {
		if ( 0 === strpos( $k, 'HTTP_' ) ) {
			unset( $_SERVER[ $k ] );
		}
	}
	$_SERVER['REMOTE_ADDR']    = $remote;
	$_SERVER['REQUEST_METHOD'] = $method;
	$_SERVER['REQUEST_URI']    = $path;
	$_SERVER['HTTP_HOST']      = $http_host;
	$_SERVER['HTTPS']          = 'on';
	if ( '' !== $ua ) {
		$_SERVER['HTTP_USER_AGENT'] = $ua;
	}
	if ( SELF_UA === $ua ) {
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9'; // As PNCP_Hardening::fetch() sends it.
	}
	foreach ( $headers as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
	PNCP_Server_Ips::forget();
}

/** check() for a page, without counting. */
function verdict( $context = 'page' ) {
	$v = PNCP_Bots::check( $context, false );
	return is_array( $v ) ? $v['code'] . ' ' . $v['reason'] : 'pass';
}

/** A signature of this site for a path ($time: a moment other than now). */
function sig( $path = '/', $method = 'GET', $time = null ) {
	return PNCP_Server_Ips::sig_token( $method, home_url( $path ), $time );
}

/** An HTTP request "from the Bunny edge" over HTTPS: [code, lowercase headers, body]. */
function req( $path, $headers = array(), $method = 'GET' ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	if ( ! isset( $headers['User-Agent'] ) ) {
		$h[] = 'User-Agent:'; // curl sends none then.
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER         => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_CUSTOMREQUEST  => $method,
			CURLOPT_TIMEOUT        => 60,
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
}

/** The headers of the site's request to itself that came back through the edge. */
function from_edge( $ua = SELF_UA, $extra = array() ) {
	$h = array(
		'X-Test-Remote-Addr' => EDGE,
		'X-Test-HTTPS'       => '1',
		'X-Forwarded-For'    => SERVER,
		'Accept'             => 'text/html',
	);
	if ( SELF_UA === $ua ) {
		$h['Accept-Language'] = 'en-US,en;q=0.9';
	}
	if ( '' !== $ua ) {
		$h['User-Agent'] = $ua;
	}
	return array_merge( $h, $extra );
}

/* ---------- Setup ---------- */
$config_file = PNCP_Precheck::config_path();
$cache_file  = WP_CONTENT_DIR . '/advanced-cache.php';
$original    = (string) file_get_contents( $config_file );
$had_cache   = file_exists( $cache_file ) ? (string) file_get_contents( $cache_file ) : null;
$saved       = PNCP_Options::stored();
$saved_opts  = array();
foreach ( array( PNCP_Server_Ips::OPTION, 'pncp_ip_lists_bunny', 'pncp_ip_lists_cloudflare', PNCP_Ip::BUNNY_SUM, PNCP_Edge::CONFIG, PNCP_Edge::STATE, PNCP_Bunny::CONFIG, PNCP_Bunny::RULES, PNCP_Bunny::LOGIN_STRICT ) as $pncp_o ) {
	$saved_opts[ $pncp_o ] = get_option( $pncp_o, null );
}
$server_old = isset( $_SERVER['SERVER_ADDR'] ) ? $_SERVER['SERVER_ADDR'] : null;
register_shutdown_function(
	static function () use ( $config_file, $original, $cache_file, $had_cache, $saved, $saved_opts ) {
		file_put_contents( $config_file, $original );
		if ( null === $had_cache ) {
			@unlink( $cache_file );
		} else {
			file_put_contents( $cache_file, $had_cache );
		}
		update_option( PNCP_OPTION, $saved );
		PNCP_Options::flush();
		foreach ( $saved_opts as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value );
			}
		}
		delete_transient( 'pncp_server_outbound' );
		PNCP_Bunny::reset();
		PNCP_Early::sync();
		PNCP_Precheck::sync();
		PNCP_Log::unban_all();
	}
);

update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
PNCP_Log::unban_all();
// The stored Bunny list of the stage (an earlier test or WP cron may have changed it; put back at the end).
PNCP_Ip::store_list( 'bunny', array( EDGE, '198.51.100.11' ) );
PNCP_Ip::store_list( 'cloudflare', array( '104.16.0.0/13', '173.245.48.0/20' ) );
delete_option( PNCP_Server_Ips::OPTION );
delete_transient( 'pncp_server_outbound' );
$_SERVER['SERVER_ADDR'] = '10.66.0.5'; // NAT: the server's own interface has a private address.
// As the live site: "Real visitor IP" = REMOTE_ADDR, "Only through the CDN" without a secret, everything on.
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'block_bots'              => 1,
		'block_empty_ua'          => 1,
		'require_browser_headers' => 1,
		'block_headless'          => 1,
		'block_fake_crawlers'     => 1,
		'human_check'             => 1,
		'rate_limit'              => 60,
		'rate_limit_unverified'   => 20,
		'rate_limit_404'          => 30,
		'probe_ban'               => 1,
		'trap_enabled'            => 1,
		'ban_strikes'             => 3,
		'block_ips'               => '',
		'allow_ips'               => '',
		'trust_any_proxy'         => 0,
		'trusted_proxies'         => '',
		'trust_bunny'             => 1,
		'ip_header'               => 'remote_addr',
		'cdn_only'                => 1,
		'cdn_secret'              => '',
		'countries_block'         => '',
		'countries_strict'        => '',
		'auto_emergency'          => 0,
		'early_mode'              => 0,
		'precheck'                => 0,
		'block_ip_host'           => 0,
	)
);

/* ---------- S. The signature of the site's own requests ---------- */
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER ) );
t( 'S before: the self-test through the edge, unsigned: 403 fake_browser (the bug)', '403 fake_browser' === verdict(), verdict() );

$args = PNCP_Server_Ips::sign( array( 'headers' => array() ), home_url( '/' ) );
$tok  = isset( $args['headers'][ PNCP_Server_Ips::SIG_HEADER ] ) ? $args['headers'][ PNCP_Server_Ips::SIG_HEADER ] : '';
t( 'S: requests to the site\'s own address carry X-ScrapeLock-Sig (time.nonce.hmac)', 1 === preg_match( '/^\d{10}\.[0-9a-f]{24}\.[0-9a-f]{64}$/', $tok ), $tok );
t( 'S: ... and still the 3.11 header', isset( $args['headers'][ PNCP_Server_Ips::HEADER ] ) );
$other = PNCP_Server_Ips::sign( array( 'headers' => array() ), 'https://example.com/' );
t( 'S: requests to other sites are not signed', ! isset( $other['headers'][ PNCP_Server_Ips::SIG_HEADER ] ) && ! isset( $other['headers'][ PNCP_Server_Ips::HEADER ] ) );
$t2 = PNCP_Server_Ips::sign( array( 'headers' => array() ), home_url( '/' ) );
t( 'S: every signature has its own nonce', $t2['headers'][ PNCP_Server_Ips::SIG_HEADER ] !== $tok );

as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $tok ), $home_path );
t( 'S: signed, through the edge: passes', 'pass' === verdict(), verdict() );
t( 'S: ... the same request checked again (the early check, then WordPress): still valid', 'pass' === verdict(), verdict() );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $tok ), $home_path );
t( 'S: the same signature in another request (replayed): 403', '403 fake_browser' === verdict(), verdict() );

foreach (
	array(
		'no User-Agent'           => array( '', 'empty_ua' ),
		'WordPress User-Agent'    => array( 'WordPress/6.9; ' . home_url( '/' ), 'no_browser' ),
		'Stealth test User-Agent' => array( STEALTH_UA, 'no_browser' ),
		'python-requests'         => array( 'python-requests/2.32.3', 'no_browser' ),
	) as $label => $case
) {
	as_request( EDGE, $case[0], array( 'HTTP_X_FORWARDED_FOR' => SERVER ) );
	$before = verdict();
	as_request( EDGE, $case[0], array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ) ), $home_path );
	t( "S: $label through the edge: unsigned 403, signed passes", 0 === strpos( $before, '403' ) && 'pass' === verdict(), $before . ' / ' . verdict() );
}

// Countries, limits, bans, the block list: a signed request passes them all, from any address.
settings( array( 'countries_block' => 'ZZ,US,GR,XX', 'rate_limit' => 1, 'rate_limit_unverified' => 1, 'block_ips' => VISITOR ) );
PNCP_Log::ban( VISITOR, 10, 'test' );
as_request( VISITOR, SELF_UA );
t( 'S: a banned, blocked address, unsigned: 403', 0 === strpos( verdict(), '403' ), verdict() );
$v = array();
for ( $i = 0; $i < 3; $i++ ) {
	as_request( VISITOR, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ) ), $home_path );
	$v[] = PNCP_Bots::check( 'page', true ) ? 'refused' : 'pass';
}
t( 'S: signed from a blocked and banned address, page limit 1, three times: passes', array( 'pass', 'pass', 'pass' ) === $v, implode( ',', $v ) );
PNCP_Log::unban( VISITOR );
settings( array( 'countries_block' => '', 'rate_limit' => 60, 'rate_limit_unverified' => 20, 'block_ips' => '' ) );

// What does not pass.
$now = time();
$bad = array(
	'expired (2 minutes old)'           => array( sig( '/', 'GET', $now - 120 ), $home_path, 'GET', $http_host ),
	'from the future (2 minutes ahead)' => array( sig( '/', 'GET', $now + 120 ), $home_path, 'GET', $http_host ),
	'made for another path'             => array( sig( '/other/' ), $home_path, 'GET', $http_host ),
	'made for another method'           => array( sig( '/', 'POST' ), $home_path, 'GET', $http_host ),
	'sent to another host'              => array( sig( '/' ), $home_path, 'GET', 'evil.example' ),
	'made for another host'             => array( PNCP_Server_Ips::sig_token( 'GET', 'https://evil.example/' ), '/', 'GET', 'evil.example' ),
	'forged (another key)'              => array( $now . '.' . str_repeat( 'a', 24 ) . '.' . hash_hmac( 'sha256', 'pncp-sig|v1|GET|' . $own_host . '|/|' . $now . '|' . str_repeat( 'a', 24 ), 'not-the-key' ), $home_path, 'GET', $http_host ),
	'a 3.11 token in the new header'    => array( $args['headers'][ PNCP_Server_Ips::HEADER ], $home_path, 'GET', $http_host ),
	'garbage'                           => array( 'x' . $tok, $home_path, 'GET', $http_host ),
);
foreach ( $bad as $label => $case ) {
	as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $case[0], 'HTTP_HOST' => $case[3] ), $case[1], $case[2] );
	t( "S: a signature $label: refused (403)", '403 fake_browser' === verdict() && ! PNCP_Server_Ips::is_request(), verdict() );
}
// A visitor naming the server in X-Forwarded-For, through the edge or straight to the origin.
as_request( EDGE, 'WordPress/6.9; ' . home_url( '/' ), array( 'HTTP_X_FORWARDED_FOR' => SERVER ) );
t( 'S: X-Forwarded-For = the server, through the edge: not exempt (403)', '403 no_browser' === verdict(), verdict() );
as_request( VISITOR, 'WordPress/6.9; ' . home_url( '/' ), array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_REAL_IP' => SERVER ) );
t( 'S: X-Forwarded-For = the server, straight to the origin: not exempt (403)', '403 no_browser' === verdict(), verdict() );

// The early check.
settings( array( 'early_mode' => 1 ) );
as_request( EDGE, '', array( 'HTTP_X_FORWARDED_FOR' => SERVER ) );
$e = PNCP_Early::check();
t( 'S early check: no User-Agent through the edge, unsigned: 403 empty_ua', is_array( $e ) && 'empty_ua' === $e[1], wp_json_encode( $e ) );
as_request( EDGE, '', array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ) ), $home_path );
t( 'S early check: signed: passes', null === PNCP_Early::check() );
t( 'S early check: ... and WordPress after it, in the same request: passes', 'pass' === verdict(), verdict() );
settings( array( 'early_mode' => 0 ) );

// "Only through the CDN" (in effect with a secret only): a signed request reaching the server around the CDN.
settings( array( 'cdn_secret' => 'stage-secret-1234567890' ) );
as_request( SERVER, SELF_UA );
t( 'S cdn_only: the server\'s request straight to the origin, unsigned: not exempt', ! PNCP_Origin::exempt() );
as_request( SERVER, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ) ), $home_path );
t( 'S cdn_only: signed: exempt', PNCP_Origin::exempt() );
as_request( VISITOR, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => 'x' . sig( '/' ) ), $home_path );
t( 'S cdn_only: a forged signature: not exempt', ! PNCP_Origin::exempt() );
settings( array( 'cdn_secret' => '' ) );

// The trap and the probe ban: never for a signed request.
as_request( VISITOR, 'python-requests/2.32.3', array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/.env' ) ), '/.env' );
$m = new ReflectionMethod( 'PNCP_Bots', 'should_ban_on_sight' );
$m->setAccessible( true );
t( 'S: the trap and the probe ban never ban a signed request', false === $m->invoke( null, VISITOR, 'pncp_tr_' ) );

/* ---------- S over HTTP: WordPress and the early check, the request "from the edge" ---------- */
list( $code ) = req( '/', from_edge() );
t( 'S HTTP: the self-test through the edge, unsigned: 403 (the bug)', 403 === $code, (string) $code );
$tok = sig( '/' );
list( $code ) = req( '/', from_edge( SELF_UA, array( 'X-ScrapeLock-Sig' => $tok ) ) );
t( 'S HTTP: signed: 200', 200 === $code, (string) $code );
list( $code ) = req( '/', from_edge( SELF_UA, array( 'X-ScrapeLock-Sig' => $tok ) ) );
t( 'S HTTP: the same signature again (replayed): 403', 403 === $code, (string) $code );
list( $code ) = req( '/', from_edge( 'WordPress/6.9; ' . home_url( '/' ) ) );
t( 'S HTTP: the WordPress User-Agent alone: 403', 403 === $code, (string) $code );
settings( array( 'early_mode' => 1 ) );
PNCP_Early::sync();
sleep( 2 ); // OPcache of the server: the early check file.
list( $code, $h ) = req( '/', from_edge( '' ) );
t( 'S HTTP early check: no User-Agent, unsigned: 403 before the plugins load', 403 === $code && false === strpos( $h, 'x-test-muplugins-loaded' ), $code . ' ' . $h );
list( $code ) = req( '/', from_edge( '', array( 'X-ScrapeLock-Sig' => sig( '/' ) ) ) );
t( 'S HTTP early check: no User-Agent, signed: 200', 200 === $code, (string) $code );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();

/* ---------- R. Redirects ---------- */
// A stand-in server on 127.0.0.1 (one of the site's host names, as home_url() is here): /redirect-out sends the
// request on to localhost (another host), /redirect-in to /echo on 127.0.0.1, /echo answers with the headers.
$echo_dir = sys_get_temp_dir() . '/pncp-echo3121-' . getmypid();
wp_mkdir_p( $echo_dir );
file_put_contents(
	$echo_dir . '/router.php',
	'<?php $p = parse_url( $_SERVER["REQUEST_URI"], PHP_URL_PATH );' .
	' if ( "/redirect-out" === $p ) { header( "Location: http://localhost:8953/echo", true, 302 ); exit; }' .
	' if ( "/redirect-in" === $p ) { header( "Location: http://127.0.0.1:8953/echo", true, 302 ); exit; }' .
	' header( "Content-Type: application/json" ); echo json_encode( array_change_key_case( getallheaders(), CASE_LOWER ) );'
);
$echo_srv = proc_open( array( PHP_BINARY, '-S', '0.0.0.0:8953', $echo_dir . '/router.php' ), array( array( 'file', '/dev/null', 'r' ), array( 'file', '/dev/null', 'w' ), array( 'file', '/dev/null', 'w' ) ), $echo_pipes );
usleep( 700000 );
$echo = static function ( $url ) {
	$r = wp_remote_get( $url, array( 'timeout' => 10 ) );
	$h = is_wp_error( $r ) ? null : json_decode( wp_remote_retrieve_body( $r ), true );
	return is_array( $h ) ? $h : array( 'error' => is_wp_error( $r ) ? $r->get_error_message() : wp_remote_retrieve_body( $r ) );
};
$sig_name = strtolower( PNCP_Server_Ips::SIG_HEADER );
$valid_at = static function ( $h, $path ) use ( $sig_name, $own_host ) {
	if ( ! isset( $h[ $sig_name ] ) ) {
		return false;
	}
	as_request( SERVER, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => $h[ $sig_name ], 'HTTP_HOST' => $own_host . ':8953' ), $path );
	return PNCP_Server_Ips::sig_ok();
};
$h = $echo( 'http://127.0.0.1:8953/echo' );
t( 'R: a request to the site\'s own host carries a valid signature for its path', $valid_at( $h, '/echo' ), wp_json_encode( $h ) );
$h = $echo( 'http://127.0.0.1:8953/redirect-in' );
t( 'R: after a redirect on the site\'s own host: signed again, valid for the new path', $valid_at( $h, '/echo' ), wp_json_encode( $h ) );
$h = $echo( 'http://127.0.0.1:8953/redirect-out' );
t( 'R: after a redirect to another host: no signature at all (neither header)', ! isset( $h[ $sig_name ] ) && ! isset( $h[ strtolower( PNCP_Server_Ips::HEADER ) ] ) && ! isset( $h['error'] ), wp_json_encode( $h ) );
$h = $echo( 'http://localhost:8953/echo' );
t( 'R: never sent to another host', ! isset( $h[ $sig_name ] ) && ! isset( $h['error'] ), wp_json_encode( $h ) );
$headers = array( PNCP_Server_Ips::SIG_HEADER => sig( '/a' ), PNCP_Server_Ips::HEADER => 'x' );
$loc     = 'https://evil.example/steal';
$opts    = array( 'type' => 'GET' );
$none    = null;
PNCP_Server_Ips::unsign_redirect( $loc, $headers, $none, $opts );
t( 'R: unsign_redirect() to another host removes both headers', array() === $headers, wp_json_encode( $headers ) );
proc_terminate( $echo_srv );
proc_close( $echo_srv );
wp_delete_file( $echo_dir . '/router.php' );
rmdir( $echo_dir );

/* ---------- H. Vulnerable points "Check again", the Stealth test, Site Health: through the "edge" ---------- */
unset( $_SERVER['HTTPS'] ); // This process: home_url() as stored (the "edge" requests say HTTPS with X-Test-HTTPS).
$to_edge = static function ( $args, $url ) {
	if ( in_array( strtolower( (string) wp_parse_url( (string) $url, PHP_URL_HOST ) ), PNCP_Server_Ips::own_hosts(), true ) && is_array( $args ) ) {
		$args['headers'] = array_merge(
			isset( $args['headers'] ) && is_array( $args['headers'] ) ? $args['headers'] : array(),
			array(
				'X-Test-Remote-Addr' => EDGE,
				'X-Test-HTTPS'       => '1',
				'X-Forwarded-For'    => SERVER,
			)
		);
	}
	return $args;
};
$unsign = static function ( $args ) {
	unset( $args['headers'][ PNCP_Server_Ips::SIG_HEADER ] );
	return $args;
};
add_filter( 'http_request_args', $to_edge, 20, 2 );
add_filter( 'http_request_args', $unsign, 30 );
$live = PNCP_Hardening::live( true );
t( 'H before (no signature): "Security headers" says "the home page answered HTTP 403 to the site itself" (the bug)', isset( $live['headers'] ) && 'unknown' === $live['headers']['state'] && false !== strpos( $live['headers']['note'], '403' ), wp_json_encode( isset( $live['headers'] ) ? $live['headers'] : $live ) );
remove_filter( 'http_request_args', $unsign, 30 );
$live = PNCP_Hardening::live( true );
t( 'H: "Check again": Security headers has a real result', isset( $live['headers'] ) && in_array( $live['headers']['state'], array( 'on', 'partial', 'off' ), true ) && false === strpos( $live['headers']['note'], '403' ), wp_json_encode( isset( $live['headers'] ) ? $live['headers'] : $live ) );
t( 'H: "Check again": X-Frame-Options (framing) has a real result', isset( $live['framing'] ) && in_array( $live['framing']['state'], array( 'on', 'off' ), true ), wp_json_encode( isset( $live['framing'] ) ? $live['framing'] : $live ) );
$fetch = new ReflectionMethod( 'PNCP_Stealth', 'fetch' );
$fetch->setAccessible( true );
$r = $fetch->invoke( null, home_url( '/' ) );
t( 'H: the Stealth test\'s fetch through the edge: 200', ! is_wp_error( $r ) && 200 === $r['code'], is_wp_error( $r ) ? $r->get_error_message() : (string) $r['code'] );
add_filter( 'http_request_args', $unsign, 30 );
$r = $fetch->invoke( null, home_url( '/' ) );
t( 'H before: ... unsigned: 403', ! is_wp_error( $r ) && 403 === $r['code'], is_wp_error( $r ) ? $r->get_error_message() : (string) $r['code'] );
remove_filter( 'http_request_args', $unsign, 30 );
require_once ABSPATH . 'wp-admin/includes/class-wp-site-health.php';
$loop = WP_Site_Health::get_instance()->get_test_loopback_requests();
t( 'H: Site Health "Loopback request" through the edge: good', 'good' === $loop['status'], $loop['status'] . ' ' . wp_strip_all_tags( $loop['label'] ) );
$rest = wp_remote_get( rest_url( 'wp/v2/types/post' ), array( 'timeout' => 10 ) );
t( 'H: the REST API through the edge: 200', 200 === (int) wp_remote_retrieve_response_code( $rest ), is_wp_error( $rest ) ? $rest->get_error_message() : (string) wp_remote_retrieve_response_code( $rest ) );
remove_filter( 'http_request_args', $to_edge, 20 );

echo $fails ? "\n$fails FAILED\n" : "\nALL PASSED\n";
exit( $fails ? 1 : 0 );
