<?php
/**
 * ScrapeLock 3.12.2 — the site's own requests to itself behind a CDN that does not forward the Host header, an edge
 * or a firewall that refuses them, made visible and made to work, in real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI=wp] php t_3122_loopback.php
 *
 * 3.12.1 did not fix "Check again" on the live site (Bunny without "Forward Host Header": the origin gets the pull
 * zone's origin name as Host, and the signature was bound to the Host header). And nobody could see who refused.
 *
 * S. The signature: verified for the host it was signed for, whatever Host header arrives; each reason of a
 *    failure (expired, host_mismatch, path_mismatch, bad_mac, bad_format, no_key, nonce_reused); paths with "//",
 *    encoded characters and another query; a HEAD passed on as GET; the 3.12.1 format; the pre-cache check the same.
 * N. The nonce: once per request across the early check and WordPress, also with a persistent object cache, and
 *    the pre-cache check's own use of it never makes WordPress refuse the same request.
 * D. The diagnostics of the receiving side: ring buffer (not autoloaded, at most MAX, the minute's allowance), its
 *    contents and privacy (no IP, User-Agent, query or cookie).
 * M. The refusal header "X-ScrapeLock: refused …" (and "ok" for a valid signature), in WordPress, the pre-cache
 *    check and over HTTP.
 *
 * Self-requests are made from this test process to the test server, never from a page the single-process
 * server is serving (it would wait for itself). Only on a test WordPress.
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
	test_lists();
	PNCP_Ip::reset();
}

/** The stage's Bunny and Cloudflare lists, stored again (with internet, WP cron would download the real ones). */
function test_lists() {
	wp_unschedule_hook( PNCP_Ip::CRON );
	set_transient( 'pncp_lists_missing_try', 1, HOUR_IN_SECONDS );
	PNCP_Ip::store_list( 'bunny', array( EDGE, '198.51.100.11' ) );
	PNCP_Ip::store_list( 'cloudflare', array( '104.16.0.0/13', '173.245.48.0/20' ) );
}

const EDGE    = '198.51.100.10'; // A Bunny edge (in the stored Bunny list).
const SERVER  = '203.0.113.50';  // The server's public address, as the edge sees it.
const VISITOR = '198.51.100.81';
const SELF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 ScrapeLock-Selftest';
const ORIGIN_HOST = 'origin-1234.b-cdn.example'; // The Host header Bunny sends without "Forward Host Header".

$own_host  = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
$http_host = (string) wp_parse_url( $base, PHP_URL_HOST ) . ( wp_parse_url( $base, PHP_URL_PORT ) ? ':' . wp_parse_url( $base, PHP_URL_PORT ) : '' );
$home_path = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
$home_path = '' === $home_path ? '/' : $home_path;

/** The $_SERVER of a new request to this site over HTTPS (every HTTP_ header removed first). */
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
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9';
	}
	foreach ( $headers as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
	PNCP_Server_Ips::forget();
	if ( class_exists( 'PNCP_Self_Check' ) ) {
		PNCP_Self_Check::reset();
	}
	PNCP_Precheck_Runtime::$self_seen   = array();
	PNCP_Precheck_Runtime::$self_result = '';
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

/** An HTTP request to the test server: [code, lowercase headers, body]. */
function req( $path, $headers = array(), $method = 'GET' ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	if ( ! isset( $headers['User-Agent'] ) ) {
		$h[] = 'User-Agent:';
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER         => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_CUSTOMREQUEST  => $method,
			CURLOPT_TIMEOUT        => 60,
			CURLOPT_PROXY          => '',
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
}

/** The value of a response header in req()'s lowercase headers ('' when absent). */
function hdr( $headers, $name ) {
	return preg_match( '/^' . preg_quote( strtolower( $name ), '/' ) . ':\s*([^\r\n]*)/m', $headers, $m ) ? trim( $m[1] ) : '';
}

/** The site's own request coming back through the edge. */
function from_edge( $extra = array() ) {
	return array_merge(
		array(
			'X-Test-Remote-Addr' => EDGE,
			'X-Test-HTTPS'       => '1',
			'X-Forwarded-For'    => SERVER,
			'Accept'             => 'text/html',
			'Accept-Language'    => 'en-US,en;q=0.9',
			'User-Agent'         => SELF_UA,
		),
		$extra
	);
}

/** A mocked answer for pre_http_request. */
function answer( $code, $headers = array(), $body = '' ) {
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
}

/* ---------- Setup ---------- */
$saved      = PNCP_Options::stored();
$saved_opts = array();
foreach ( array( PNCP_Server_Ips::OPTION, 'pncp_ip_lists_bunny', 'pncp_ip_lists_cloudflare', PNCP_Ip::BUNNY_SUM, PNCP_Edge::CONFIG, PNCP_Edge::STATE, 'pncp_selfcheck_log', 'pncp_selfcheck_last' ) as $pncp_o ) {
	$saved_opts[ $pncp_o ] = get_option( $pncp_o, null );
}
register_shutdown_function(
	static function () use ( $saved, $saved_opts ) {
		update_option( PNCP_OPTION, $saved );
		PNCP_Options::flush();
		foreach ( $saved_opts as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value );
			}
		}
		delete_transient( PNCP_Server_Ips::OUTBOUND );
		delete_transient( 'pncp_selfcheck_route' );
		delete_transient( 'pncp_edge_spare' );
		wp_clear_scheduled_hook( PNCP_Edge::CRON );
		if ( ! wp_next_scheduled( PNCP_Ip::CRON ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', PNCP_Ip::CRON );
		}
		PNCP_Log::unban_all();
	}
);
update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
PNCP_Log::unban_all();
test_lists();
delete_option( PNCP_Server_Ips::OPTION );
delete_transient( PNCP_Server_Ips::OUTBOUND );
delete_transient( 'pncp_selfcheck_route' );
delete_option( 'pncp_selfcheck_log' );
$_SERVER['SERVER_ADDR'] = '10.66.0.5';
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
		'probe_ban'               => 1,
		'block_ips'               => '',
		'allow_ips'               => '',
		'trust_any_proxy'         => 0,
		'trusted_proxies'         => '',
		'trust_bunny'             => 1,
		'ip_header'               => 'remote_addr',
		'cdn_only'                => 1,
		'cdn_secret'              => '',
		'countries_block'         => '',
		'auto_emergency'          => 0,
		'early_mode'              => 0,
		'precheck'                => 0,
		'block_ip_host'           => 0,
	)
);
PNCP_Server_Ips::sig_key( true );

/* ---------- S. The signature, whatever Host header arrives ---------- */
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER ) );
t( 'S before: the self-test through the edge, unsigned: 403 fake_browser', '403 fake_browser' === verdict(), verdict() );

$tok = sig( '/' );
t( 'S: the header is time.nonce.hmac.hint (the host and path it was signed for)', 1 === preg_match( '/^\d{10}\.[0-9a-f]{24}\.[0-9a-f]{64}\.[0-9a-f]{16}$/', $tok ), $tok );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $tok, 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
$c = PNCP_Server_Ips::sig_check();
t( 'S: Host header = the CDN\'s origin name (Bunny without "Forward Host Header"): the signature is valid (the bug of 3.12.1)', 'ok' === $c['result'], wp_json_encode( $c ) );
t( 'S: ... verified for the site\'s own host, the received host noted', $own_host === $c['host'] && ORIGIN_HOST === $c['received'], wp_json_encode( $c ) );
t( 'S: ... and the request passes every check', 'pass' === verdict() && PNCP_Server_Ips::is_request(), verdict() );
as_request( EDGE, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ), 'HTTP_HOST' => '203.0.113.50:8443' ), $home_path );
t( 'S: Host = the server\'s address and a port: valid', PNCP_Server_Ips::sig_ok() );
as_request( EDGE, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ) ), $home_path );
unset( $_SERVER['HTTP_HOST'] );
t( 'S: no Host header at all: valid', PNCP_Server_Ips::sig_ok() );

$now  = time();
$hint = static function ( $host, $path ) {
	return PNCP_Server_Ips::hint( $host, PNCP_Server_Ips::sig_path( $path ) );
};
$bad = array(
	'expired'       => array( sig( '/', 'GET', $now - 120 ), $home_path, 'GET' ),
	'expired '      => array( sig( '/', 'GET', $now + 120 ), $home_path, 'GET' ),
	'host_mismatch' => array( PNCP_Server_Ips::sig_token( 'GET', 'https://evil.example/' ), '/', 'GET' ),
	'path_mismatch' => array( sig( '/other/' ), $home_path, 'GET' ),
	'bad_mac'       => array( $now . '.' . str_repeat( 'a', 24 ) . '.' . str_repeat( 'b', 64 ) . '.' . $hint( $own_host, $home_path ), $home_path, 'GET' ),
	'bad_mac '      => array( sig( '/', 'POST' ), $home_path, 'GET' ),
	'bad_format'    => array( 'x' . $tok, $home_path, 'GET' ),
);
foreach ( $bad as $want => $case ) {
	as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $case[0], 'HTTP_HOST' => ORIGIN_HOST ), $case[1], $case[2] );
	$c = PNCP_Server_Ips::sig_check();
	t( 'S: ' . trim( $want ) . ': refused with that reason, and the request is checked like a visitor', trim( $want ) === $c['result'] && '403 fake_browser' === verdict(), wp_json_encode( $c ) . ' ' . verdict() );
}
as_request( EDGE, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => $tok, 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
t( 'S: nonce_reused: the same signature in another request', 'nonce_reused' === PNCP_Server_Ips::sig_check()['result'] );
$key = get_option( PNCP_Server_Ips::KEY_OPTION );
$t2  = sig( '/' );
delete_option( PNCP_Server_Ips::KEY_OPTION );
as_request( EDGE, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => $t2 ), $home_path );
t( 'S: no_key: the site has no key (yet)', 'no_key' === PNCP_Server_Ips::sig_check()['result'] );
update_option( PNCP_Server_Ips::KEY_OPTION, $key, true );

// Paths and methods that a CDN passes on unchanged in meaning.
$ok_cases = array(
	'"//" in the path (a CDN joining its origin path)' => array( sig( '/a/b/' ), '/a//b/', 'GET' ),
	'an encoded path signed decoded'                   => array( sig( '/τ/' ), '/%CF%84/', 'GET' ),
	'another query string (never part of it)'         => array( sig( '/?a=1' ), $home_path . '?b=2', 'GET' ),
	'a HEAD passed on as GET'                          => array( sig( '/', 'HEAD' ), $home_path, 'GET' ),
);
foreach ( $ok_cases as $label => $case ) {
	as_request( EDGE, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => $case[0], 'HTTP_HOST' => ORIGIN_HOST ), $case[1], $case[2] );
	t( "S: $label: valid", PNCP_Server_Ips::sig_ok(), wp_json_encode( PNCP_Server_Ips::sig_check() ) );
}
// The 3.12.1 format (no hint), made by a site that was just upgraded: tried with each of the site's hosts.
$t3   = sig( '/' );
$old  = substr( $t3, 0, strrpos( $t3, '.' ) );
as_request( EDGE, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => $old, 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
t( 'S: the 3.12.1 format without the hint: still valid, also with another Host', PNCP_Server_Ips::sig_ok(), $old );

// The pre-cache check: the same steps with its own configuration and the key from wp-config.php.
$pc_dir = get_temp_dir() . 'pncp-t3122-' . wp_generate_password( 6, false, false );
wp_mkdir_p( $pc_dir );
$cfg             = json_decode( PNCP_Precheck::config_json(), true );
$cfg['dir']      = $pc_dir;
$cfg['self_key'] = PNCP_Server_Ips::sig_key();
t( 'P: the pre-cache configuration has the site\'s hosts', is_array( $cfg ) && in_array( $own_host, (array) $cfg['self_sig']['hosts'], true ), wp_json_encode( isset( $cfg['self_sig'] ) ? $cfg['self_sig'] : null ) );
$pt = sig( '/cached-page/' );
as_request( EDGE, '', array( 'HTTP_X_SCRAPELOCK_SIG' => $pt, 'HTTP_HOST' => ORIGIN_HOST ), '/cached-page/' );
t( 'P: Host = the CDN\'s origin name: valid in the pre-cache check', PNCP_Precheck_Runtime::self_signed( $cfg, time() ) && 'ok' === PNCP_Precheck_Runtime::$self_result );
foreach (
	array(
		'expired'       => array( sig( '/cached-page/', 'GET', time() - 120 ), '/cached-page/' ),
		'host_mismatch' => array( PNCP_Server_Ips::sig_token( 'GET', 'https://evil.example/cached-page/' ), '/cached-page/' ),
		'path_mismatch' => array( sig( '/other/' ), '/cached-page/' ),
		'bad_mac'       => array( time() . '.' . str_repeat( 'c', 24 ) . '.' . str_repeat( 'd', 64 ) . '.' . $hint( $own_host, '/cached-page/' ), '/cached-page/' ),
		'nonce_reused'  => array( $pt, '/cached-page/' ),
	) as $want => $case
) {
	as_request( EDGE, '', array( 'HTTP_X_SCRAPELOCK_SIG' => $case[0], 'HTTP_HOST' => ORIGIN_HOST ), $case[1] );
	t( "P: $want: refused with that reason", ! PNCP_Precheck_Runtime::self_signed( $cfg, time() ) && $want === PNCP_Precheck_Runtime::$self_result, PNCP_Precheck_Runtime::$self_result );
}
$no_key             = $cfg;
$no_key['self_key'] = '';
as_request( EDGE, '', array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/cached-page/' ) ), '/cached-page/' );
t( 'P: no_key: a line in wp-config.php without the key', ! PNCP_Precheck_Runtime::self_signed( $no_key, time() ) && 'no_key' === PNCP_Precheck_Runtime::$self_result );

/* ---------- N. One nonce per request across the layers ---------- */
settings( array( 'early_mode' => 1 ) );
$nt = sig( '/' );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $nt, 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
t( 'N: the early check lets the signed request pass', null === PNCP_Early::check() );
PNCP_Ip::reset();
t( 'N: ... and WordPress, in the same request, too (the nonce is used once for both)', 'pass' === verdict() && PNCP_Server_Ips::sig_ok() );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $nt, 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
$e = PNCP_Early::check(); // A browser's User-Agent: nothing for the early check to refuse.
t( 'N: the same signature in the next request: nonce_reused, checked like a visitor (403)', null === $e && 'nonce_reused' === PNCP_Server_Ips::sig_check()['result'] && '403 fake_browser' === verdict(), verdict() );
// The pre-cache check uses the nonce in its own folder; WordPress then still accepts the same request.
$nt = sig( '/' );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $nt, 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
$pre_ok = PNCP_Precheck_Runtime::self_signed( $cfg, time() );
t( 'N: pre-cache check, then the early check and WordPress in the same request: all pass', $pre_ok && null === PNCP_Early::check() && 'pass' === verdict() );
// With a persistent object cache (wp_cache_add() is where the nonces go, as with Redis).
$was_ext = wp_using_ext_object_cache( true );
$nt      = sig( '/' );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $nt, 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
$first = PNCP_Precheck_Runtime::self_signed( $cfg, time() ) && null === PNCP_Early::check() && 'pass' === verdict();
t( 'N: persistent object cache: the pre-cache check, the early check and WordPress pass the same request', $first );
t( 'N: ... the nonce is in the object cache', false !== wp_cache_get( 'pncp_sn_' . explode( '.', $nt )[1], 'pncp' ) );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $nt, 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
t( 'N: ... and a replay is refused by each layer', ! PNCP_Precheck_Runtime::self_signed( $cfg, time() ) && 'nonce_reused' === PNCP_Server_Ips::sig_check()['result'] && '403 fake_browser' === verdict() );
wp_using_ext_object_cache( $was_ext );
settings( array( 'early_mode' => 0 ) );

/* ---------- D. The receiving side's notes ---------- */
delete_option( PNCP_Self_Check::LOG );
$dt = sig( '/private-path/' );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $dt, 'HTTP_HOST' => ORIGIN_HOST, 'HTTP_COOKIE' => 'secret=cookievalue' ), '/private-path/?email=someone%40example.com' );
PNCP_Server_Ips::sig_check();
PNCP_Self_Check::flush();
$list  = PNCP_Self_Check::entries();
$entry = isset( $list[0] ) ? $list[0] : array();
t( 'D: a signed request is noted (side "in")', isset( $entry['side'] ) && 'in' === $entry['side'] && 'ok' === $entry['sig'] && 'passed' === $entry['verdict'], wp_json_encode( $entry ) );
t( 'D: ... with the host it got, the host it was signed for, the path and where it came from', ORIGIN_HOST === $entry['host'] && $own_host === $entry['sig_host'] && '/private-path/' === $entry['path'] && 'cdn' === $entry['from'], wp_json_encode( $entry ) );
t( 'D: ... and the id of its nonce (8 digits), as the sending side notes it', explode( '.', $dt )[1] !== $entry['id'] && 0 === strpos( explode( '.', $dt )[1], $entry['id'] ) && 8 === strlen( $entry['id'] ) );
$json = wp_json_encode( $list );
t( 'D: privacy: no IP address, User-Agent, query string, cookie or the full nonce in the notes', false === strpos( $json, SERVER ) && false === strpos( $json, EDGE ) && false === strpos( $json, 'ScrapeLock-Selftest' ) && false === strpos( $json, 'email' ) && false === strpos( $json, 'cookievalue' ) && false === strpos( $json, explode( '.', $dt )[1] ) && false === strpos( $json, explode( '.', $dt )[2] ), $json );
global $wpdb;
$autoload = (string) $wpdb->get_var( $wpdb->prepare( "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s", PNCP_Self_Check::LOG ) );
t( 'D: the notes are not autoloaded', in_array( $autoload, array( 'no', 'off' ), true ), $autoload );
// A refusal: the layer and the reason.
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => SERVER, 'HTTP_X_SCRAPELOCK_SIG' => $dt, 'HTTP_HOST' => ORIGIN_HOST ), '/private-path/' );
PNCP_Server_Ips::sig_check();
PNCP_Self_Check::refused( 'fake_browser', 403 );
PNCP_Self_Check::flush();
$entry = PNCP_Self_Check::entries()[0];
t( 'D: a refused replay: sig nonce_reused, refused by WordPress for fake_browser, 403', 'nonce_reused' === $entry['sig'] && 'refused' === $entry['verdict'] && 'fake_browser' === $entry['reason'] && 'wp' === $entry['layer'] && 403 === (int) $entry['code'], wp_json_encode( $entry ) );
// The pre-cache check's result reaches the note of WordPress.
as_request( EDGE, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/cached-page/' ), 'HTTP_HOST' => ORIGIN_HOST ), '/cached-page/' );
PNCP_Precheck_Runtime::self_signed( $cfg, time() );
PNCP_Server_Ips::sig_check();
PNCP_Self_Check::flush();
$entry = PNCP_Self_Check::entries()[0];
t( 'D: the pre-cache check\'s result is in the note', 'ok' === $entry['precache'] && 'ok' === $entry['sig'], wp_json_encode( $entry ) );
// The early check is named as the layer that decided.
settings( array( 'early_mode' => 1 ) );
as_request( EDGE, '', array( 'HTTP_X_SCRAPELOCK_SIG' => 'garbage' ), '/' );
PNCP_Self_Check::set_layer( 'early' );
$e = PNCP_Early::check();
if ( is_array( $e ) ) {
	PNCP_Log::add( $e[1], $e[0], $e[2] );
}
PNCP_Self_Check::set_layer( 'wp' );
PNCP_Self_Check::flush();
$entry = PNCP_Self_Check::entries()[0];
t( 'D: a garbage signature refused by the early check: noted with the layer "early" and bad_format', 'early' === $entry['layer'] && 'bad_format' === $entry['sig'] && 'empty_ua' === $entry['reason'], wp_json_encode( $entry ) );
settings( array( 'early_mode' => 0 ) );
// An unsigned request from the server's address: only a refusal is noted.
set_transient( PNCP_Server_Ips::OUTBOUND, array( SERVER => time() ), DAY_IN_SECONDS );
$count = count( PNCP_Self_Check::entries() );
as_request( SERVER, 'WordPress/6.9', array(), '/' );
PNCP_Self_Check::flush();
t( 'D: an unsigned request of the server that passes is not noted (cache preloads would fill the buffer)', count( PNCP_Self_Check::entries() ) === $count );
as_request( SERVER, 'WordPress/6.9', array(), '/xmlrpc.php', 'POST' );
PNCP_Self_Check::set_layer( 'hardening' );
PNCP_Self_Check::refused( 'harden_xmlrpc', 403, true );
PNCP_Self_Check::flush();
$entry = PNCP_Self_Check::entries()[0];
t( 'D: ... a refusal of it is (Vulnerable points, harden_xmlrpc)', 'hardening' === $entry['layer'] && 'harden_xmlrpc' === $entry['reason'] && 'server' === $entry['from'], wp_json_encode( $entry ) );
delete_transient( PNCP_Server_Ips::OUTBOUND );
// The minute's allowance for signatures that are not the site's (anyone can send a header).
$count = count( PNCP_Self_Check::entries() );
for ( $i = 0; $i < PNCP_Self_Check::LIMIT_OTHER + 3; $i++ ) {
	as_request( VISITOR, 'curl/8', array( 'HTTP_X_SCRAPELOCK_SIG' => 'forged-' . $i ), '/' );
	PNCP_Server_Ips::sig_check();
	PNCP_Self_Check::flush();
}
$added = count( PNCP_Self_Check::entries() ) - $count;
t( 'D: forged signatures: at most ' . PNCP_Self_Check::LIMIT_OTHER . ' notes a minute', $added <= PNCP_Self_Check::LIMIT_OTHER && $added >= 0, (string) $added );
for ( $i = 0; $i < PNCP_Self_Check::MAX + 5; $i++ ) {
	PNCP_Self_Check::add( array( 'side' => 'out', 'time' => time(), 'n' => $i ) );
}
t( 'D: the ring buffer keeps at most ' . PNCP_Self_Check::MAX . ' entries, newest first', PNCP_Self_Check::MAX === count( PNCP_Self_Check::entries() ) && PNCP_Self_Check::MAX + 4 === PNCP_Self_Check::entries()[0]['n'] );
delete_option( PNCP_Self_Check::LOG );

/* ---------- M. The refusal header ---------- */
unset( $_SERVER['HTTPS'] ); // This process: home_url() as stored (the requests "through the edge" say HTTPS themselves).
$origin_host = ORIGIN_HOST . ( wp_parse_url( $base, PHP_URL_PORT ) ? ':' . wp_parse_url( $base, PHP_URL_PORT ) : '' ); // Same port: no canonical redirect.
t( 'M: marker without a signature: "refused" (no reason for strangers)', 'refused' === PNCP_Self_Check::marker( 'fake_browser', '', false ) );
t( 'M: marker with a signature that is not the site\'s: the layer and the result only', 'refused layer=wp sig=bad_mac' === PNCP_Self_Check::marker( 'fake_browser', 'bad_mac', false ) );
t( 'M: marker of the site\'s own request: the reason too', 'refused fake_browser layer=wp sig=nonce_reused' === PNCP_Self_Check::marker( 'fake_browser', 'nonce_reused', true ) );
PNCP_Precheck_Runtime::$self_result = '';
t( 'M: the pre-cache check: "refused" without a signature', 'refused' === PNCP_Precheck_Runtime::refusal_marker( 'banned' ) );
PNCP_Precheck_Runtime::$self_result = 'nonce_reused';
t( 'M: ... with the site\'s replayed signature: reason, layer pre-cache and result', 'refused banned layer=pre-cache sig=nonce_reused' === PNCP_Precheck_Runtime::refusal_marker( 'banned' ) );
PNCP_Precheck_Runtime::$self_result = 'host_mismatch';
t( 'M: ... with a signature for another host: no reason', 'refused layer=pre-cache sig=host_mismatch' === PNCP_Precheck_Runtime::refusal_marker( 'banned' ) );
PNCP_Precheck_Runtime::$self_result = '';
// Over HTTP, against the test server, as the site's request coming back through the edge.
$ht = sig( '/' );
list( $code, $h ) = req( $home_path, from_edge( array( 'X-ScrapeLock-Sig' => $ht, 'Host' => $origin_host ) ) );
t( 'M HTTP: a valid signature with the CDN\'s Host header: 200 with "X-ScrapeLock: ok"', 200 === $code && 'ok' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
list( $code, $h ) = req( $home_path, from_edge( array( 'X-ScrapeLock-Sig' => $ht, 'Host' => $origin_host ) ) );
t( 'M HTTP: the same signature again: 403 "refused fake_browser layer=wp sig=nonce_reused"', 403 === $code && 'refused fake_browser layer=wp sig=nonce_reused' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
list( $code, $h ) = req( $home_path, array( 'X-Test-Remote-Addr' => VISITOR, 'User-Agent' => 'python-requests/2.32.3' ) );
t( 'M HTTP: a bot: 403 with just "refused"', 403 === $code && 'refused' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
list( $code, $h ) = req( $home_path, array( 'X-Test-Remote-Addr' => VISITOR, 'User-Agent' => SELF_UA, 'Accept-Language' => 'en', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document', 'Sec-CH-UA' => '"Chromium";v="130"' ) );
t( 'M HTTP: a visitor who passes gets no X-ScrapeLock header', '' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
$seen = PNCP_Self_Check::entries();
$hid  = substr( explode( '.', $ht )[1], 0, 8 );
$hits = array();
foreach ( $seen as $one ) {
	if ( isset( $one['id'] ) && $hid === $one['id'] ) {
		$hits[] = $one['verdict'] . ':' . $one['sig'];
	}
}
t( 'M HTTP: the server noted both requests (passed:ok, refused:nonce_reused)', in_array( 'passed:ok', $hits, true ) && in_array( 'refused:nonce_reused', $hits, true ), wp_json_encode( $hits ) );

// Clean up the temporary data folder.
foreach ( glob( $pc_dir . '/self/*' ) ?: array() as $pncp_f ) {
	@unlink( $pncp_f );
}
@rmdir( $pc_dir . '/self' );
@rmdir( $pc_dir );

echo $fails ? "\n$fails FAILED\n" : "\nALL PASSED\n";
exit( $fails ? 1 : 0 );
