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
 * C. Who answered (classify()): ScrapeLock, Bunny's edge, Cloudflare, Wordfence, WordPress, the web server.
 * F. The way straight to the server: answers mocked with pre_http_request (CURLOPT_RESOLVE entry, the route for the
 *    site's other requests), and over real HTTP against the test server (a host name that does not resolve).
 * H. Vulnerable points: the note names who refused, details folded, results checked at the server marked so.
 * E. A block of the server's address at the CDN is removed at once; the Bunny presets never match the home page.
 * O. "Only through the CDN" without a secret never refuses anything; with one, a signed request passes.
 * T. "Check a request": the preset "The site itself (loopback)", "Run a real self-check now" (nonce, capability).
 * K. Site Health "ScrapeLock self-request test"; "wp scrapelock selfcheck" (with WP_CLI).
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
t( 'M: ... with a signature for another host from the server\'s address: no reason', 'refused layer=pre-cache sig=host_mismatch' === PNCP_Precheck_Runtime::refusal_marker( 'banned', true ) );
t( 'M: ... the same from anyone else (a forged header): just "refused"', 'refused' === PNCP_Precheck_Runtime::refusal_marker( 'banned' ) && 'refused' === PNCP_Precheck_Runtime::refusal_marker( 'banned', false ) );
PNCP_Precheck_Runtime::$self_result = 'bad_mac';
t( 'M: ... a stranger\'s signature that does not match: just "refused"', 'refused' === PNCP_Precheck_Runtime::refusal_marker( 'not_via_cdn' ) );
PNCP_Precheck_Runtime::$self_result = '';
// Over HTTP, against the test server, as the site's request coming back through the edge.
$ht = sig( '/' );
list( $code, $h ) = req( $home_path, from_edge( array( 'X-ScrapeLock-Sig' => $ht, 'Host' => $origin_host ) ) );
t( 'M HTTP: a valid signature with the CDN\'s Host header: 200 with "X-ScrapeLock: ok"', 200 === $code && 'ok' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
list( $code, $h ) = req( $home_path, from_edge( array( 'X-ScrapeLock-Sig' => $ht, 'Host' => $origin_host ) ) );
t( 'M HTTP: the same signature again: 403 "refused fake_browser layer=wp sig=nonce_reused"', 403 === $code && 'refused fake_browser layer=wp sig=nonce_reused' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
list( $code, $h ) = req( $home_path, array( 'X-Test-Remote-Addr' => VISITOR, 'User-Agent' => 'python-requests/2.32.3' ) );
t( 'M HTTP: a bot: 403 with just "refused"', 403 === $code && 'refused' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
// Anyone can send an X-ScrapeLock-Sig header: a stranger's forged or replayed one learns neither the layer, the
// signature's result nor the reason.
list( $code, $h ) = req( $home_path, array( 'X-Test-Remote-Addr' => VISITOR, 'User-Agent' => 'python-requests/2.32.3', 'X-ScrapeLock-Sig' => time() . '.' . str_repeat( 'a', 24 ) . '.' . str_repeat( 'b', 64 ) ) );
t( 'M HTTP: a stranger with a forged signature: 403 with just "refused"', 403 === $code && 'refused' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
list( $code, $h ) = req( $home_path, array( 'X-Test-Remote-Addr' => VISITOR, 'User-Agent' => 'python-requests/2.32.3', 'X-ScrapeLock-Sig' => 'garbage' ) );
t( 'M HTTP: ... an unreadable one: just "refused"', 403 === $code && 'refused' === hdr( $h, 'x-scrapelock' ), $code . ' ' . hdr( $h, 'x-scrapelock' ) );
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

/* ---------- C. Who answered ---------- */
$cl = static function ( $code, $headers, $body = '' ) {
	return PNCP_Self_Check::classify( $code, $headers, $body )['who'];
};
t( 'C: 200: a page', 'page' === $cl( 200, array( 'server' => 'BunnyCDN-DE1-1080' ) ) );
t( 'C: ScrapeLock\'s header, with the reason, the layer and the signature', array( 'who' => 'scrapelock', 'reason' => 'fake_browser', 'layer' => 'wp', 'sig' => 'host_mismatch' ) === PNCP_Self_Check::classify( 403, array( 'x-scrapelock' => 'refused fake_browser layer=wp sig=host_mismatch', 'server' => 'BunnyCDN-DE1-1080' ), 'Access denied.' ) );
t( 'C: ScrapeLock\'s header through Bunny wins over Bunny\'s headers', 'scrapelock' === $cl( 403, array( 'x-scrapelock' => 'refused', 'server' => 'BunnyCDN-DE1-1080', 'cdn-requestid' => 'x' ) ) );
t( 'C: Bunny\'s edge (BunnyCDN Server, CDN-RequestId, no origin page)', 'bunny' === $cl( 403, array( 'server' => 'BunnyCDN-DE1-1080', 'cdn-requestid' => 'abc' ), '' ) );
t( 'C: Wordfence (its block page, through Bunny)', 'wordfence' === $cl( 403, array( 'server' => 'BunnyCDN-DE1-1080' ), '<h1>Your access to this site has been limited by the site owner</h1><p>Generated by Wordfence at …</p>' ) );
t( 'C: WordPress or another plugin (wp_die page)', 'wp' === $cl( 403, array( 'server' => 'nginx' ), '<body id="error-page"><div class="wp-die-message">Forbidden</div>' ) );
t( 'C: the web server (nginx\'s own page)', 'server' === $cl( 403, array( 'server' => 'nginx/1.24.0' ), '<center><h1>403 Forbidden</h1></center><hr><center>nginx</center>' ) );
t( 'C: Cloudflare', 'cloudflare' === $cl( 403, array( 'server' => 'cloudflare', 'cf-ray' => '1' ), 'Attention Required' ) );
t( 'C: unknown', 'unknown' === $cl( 403, array(), 'nope' ) );
t( 'C: no answer', 'none' === $cl( 0, array() ) );
t( 'C: a 401 of this WordPress ("X-ScrapeLock: ok") is the site\'s answer', 'page' === $cl( 401, array( 'x-scrapelock' => 'ok', 'server' => 'nginx' ) ) );
t( 'C: labels for people', 'Bunny CDN edge' === PNCP_Self_Check::who_label( array( 'who' => 'bunny', 'reason' => '' ) ) && false !== strpos( PNCP_Self_Check::who_label( array( 'who' => 'scrapelock', 'reason' => 'fake_browser' ) ), 'ScrapeLock (' ) );
t( 'C: what to check at Bunny, in one sentence naming its own security settings', false !== strpos( PNCP_Self_Check::advice( array( 'who' => 'bunny', 'reason' => '', 'sig' => '' ) ), 'Bunny' ) && 1 === substr_count( rtrim( PNCP_Self_Check::advice( array( 'who' => 'bunny', 'reason' => '', 'sig' => '' ) ), '.' ), '. ' ) + 1 );
t( 'C: retried at the server: ScrapeLock\'s checks for bots, Wordfence, any refusal of a page', PNCP_Self_Check::should_retry( answer( 403 ), array( 'who' => 'scrapelock', 'reason' => 'fake_browser' ), 'self' ) && PNCP_Self_Check::should_retry( answer( 403 ), array( 'who' => 'wordfence', 'reason' => '' ), 'self' ) && PNCP_Self_Check::should_retry( answer( 403 ), array( 'who' => 'bunny', 'reason' => '' ), 'page' ) && PNCP_Self_Check::should_retry( answer( 503 ), array( 'who' => 'unknown', 'reason' => '' ), 'page' ) );
t( 'C: never retried: a locked point\'s own answer (harden_*), a 404, the CDN refusing a file it should refuse', ! PNCP_Self_Check::should_retry( answer( 403 ), array( 'who' => 'scrapelock', 'reason' => 'harden_xmlrpc' ), 'page' ) && ! PNCP_Self_Check::should_retry( answer( 404 ), array( 'who' => 'page', 'reason' => '' ), 'page' ) && ! PNCP_Self_Check::should_retry( answer( 403 ), array( 'who' => 'bunny', 'reason' => '' ), 'self' ) && ! PNCP_Self_Check::should_retry( answer( 403 ), array( 'who' => 'bunny', 'reason' => '' ), 'public' ) );

/* ---------- F. Straight to the server (mocked answers) ---------- */
$calls   = array();
$edge403 = true;
$origin  = 'ok';
$mock    = static function ( $pre, $args, $url ) use ( &$calls, &$edge403, &$origin ) {
	if ( ! in_array( strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) ), PNCP_Server_Ips::own_hosts(), true ) ) {
		return $pre;
	}
	$calls[] = empty( $args['pncp_resolve'] ) ? 'public' : 'origin ' . $args['pncp_resolve'];
	$page    = array(
		'x-scrapelock'              => 'ok',
		'server'                    => 'nginx',
		'x-frame-options'           => 'SAMEORIGIN',
		'x-content-type-options'    => 'nosniff',
		'referrer-policy'           => 'strict-origin-when-cross-origin',
		'permissions-policy'        => 'camera=()',
		'strict-transport-security' => 'max-age=1',
	);
	if ( empty( $args['pncp_resolve'] ) ) {
		return $edge403 ? answer( 403, array( 'server' => 'BunnyCDN-DE1-1080', 'cdn-requestid' => 'r1', 'cdn-cache' => 'BYPASS' ), '' ) : answer( 200, array_merge( $page, array( 'server' => 'BunnyCDN-DE1-1080', 'cdn-requestid' => 'r2' ) ), '<html></html>' );
	}
	if ( 'error' === $origin ) {
		return new WP_Error( 'http_request_failed', 'Failed to connect to 127.0.0.1 port 443' );
	}
	return answer( 200, $page, '<html></html>' );
};
add_filter( 'pre_http_request', $mock, 5, 3 );
delete_transient( PNCP_Self_Check::ROUTE );
$r = PNCP_Self_Check::request( home_url( '/' ), array( 'timeout' => 5 ), 'page' );
$port     = (int) wp_parse_url( home_url( '/' ), PHP_URL_PORT );
$port     = $port ? $port : ( 'https' === wp_parse_url( home_url( '/' ), PHP_URL_SCHEME ) ? 443 : 80 );
$resolved = $own_host . ':' . $port . ':127.0.0.1';
t( 'F: the public way refused (Bunny\'s edge): asked once more straight at 127.0.0.1, Host and port kept (CURLOPT_RESOLVE entry)', array( 'public', 'origin ' . $resolved ) === $calls, wp_json_encode( $calls ) );
t( 'F: ... the server\'s answer is used, marked "origin", and who refused is kept', 'origin' === $r['via'] && '127.0.0.1' === $r['origin_ip'] && 'bunny' === $r['public']['who'] && 200 === (int) wp_remote_retrieve_response_code( $r['response'] ), wp_json_encode( array( $r['via'], $r['public'] ) ) );
t( 'F: ... both steps noted on the sending side', 'out' === PNCP_Self_Check::entries()[0]['side'] && 'origin' === PNCP_Self_Check::entries()[0]['via'] && 'public' === PNCP_Self_Check::entries()[1]['via'] && 'bunny' === PNCP_Self_Check::entries()[1]['who'], wp_json_encode( array_slice( PNCP_Self_Check::entries(), 0, 2 ) ) );
t( 'F: ... and the site\'s other requests to itself take that way for a while (the route)', '127.0.0.1' === get_transient( PNCP_Self_Check::ROUTE ) );
$calls = array();
$rr    = PNCP_Self_Check::route_request( false, array( 'method' => 'GET', 'headers' => array() ), home_url( '/wp-cron.php' ) );
t( 'F: route: another request of the site (WP cron, Site Health) goes straight to the server', ! is_wp_error( $rr ) && is_array( $rr ) && array( 'origin ' . $resolved ) === $calls, wp_json_encode( $calls ) );
t( 'F: route: never a request to another host', false === PNCP_Self_Check::route_request( false, array(), 'https://example.com/' ) );
$calls   = array();
$edge403 = false;
$r       = PNCP_Self_Check::request( home_url( '/' ), array(), 'page' );
t( 'F: the public way works again: one request, the route is forgotten', array( 'public' ) === $calls && 'public' === $r['via'] && false === get_transient( PNCP_Self_Check::ROUTE ), wp_json_encode( $calls ) );
$edge403 = true;
$calls   = array();
PNCP_Self_Check::request( home_url( '/' ), array(), 'self' );
t( 'F: mode "self" (files that may be refused on purpose): a refusal at the edge is the answer', array( 'public' ) === $calls, wp_json_encode( $calls ) );
t( 'F: the candidates: 127.0.0.1, then SERVER_ADDR (at most 3)', array( '127.0.0.1', '10.66.0.5' ) === array_slice( PNCP_Self_Check::origin_candidates(), 0, 2 ), wp_json_encode( PNCP_Self_Check::origin_candidates() ) );
t( 'F: the resolve entry of an IPv6 address is bracketed', $own_host . ':' . $port . ':[2001:db8::5]' === PNCP_Self_Check::resolve_entry( home_url( '/' ), '2001:db8::5' ) );
t( 'F: no resolve entry for another host', '' === PNCP_Self_Check::resolve_entry( 'https://example.com/', '127.0.0.1' ) );
delete_transient( PNCP_Self_Check::ROUTE );

/* ---------- H. Vulnerable points ---------- */
delete_transient( 'pncp_harden_live' );
$edge403 = true;
$origin  = 'ok';
$live    = PNCP_Hardening::live( true );
$hd      = isset( $live['headers'] ) ? $live['headers'] : array();
t( 'H: Security headers: a real result although the CDN refused the site\'s own request', isset( $hd['state'] ) && 'on' === $hd['state'], wp_json_encode( $hd ) );
t( 'H: ... marked "checked at the server", naming Bunny\'s edge and the status, in one sentence', false !== strpos( $hd['note'], 'Checked at the server' ) && false !== strpos( $hd['note'], 'Bunny CDN edge' ) && false !== strpos( $hd['note'], 'HTTP 403' ) && false === strpos( $hd['note'], 'the home page answered HTTP 403 to the site itself' ), $hd['note'] );
t( 'H: ... the details say what each side saw and what to check at Bunny', isset( $hd['details'] ) && false !== strpos( $hd['details'], 'Through the public address' ) && false !== strpos( $hd['details'], 'Straight to the server' ) && false !== strpos( $hd['details'], 'In the Bunny dashboard' ), isset( $hd['details'] ) ? $hd['details'] : '' );
t( 'H: X-Frame-Options (framing): a real result, marked as well', isset( $live['framing'] ) && 'on' === $live['framing']['state'] && false !== strpos( $live['framing']['note'], 'Checked at the server' ), wp_json_encode( isset( $live['framing'] ) ? $live['framing'] : null ) );
t( 'H: the other checks of the run are marked too (xmlrpc, hide_admin)', false !== strpos( $live['xmlrpc']['note'], 'Checked at the server' ) && false !== strpos( $live['hide_admin']['note'], 'Checked at the server' ), wp_json_encode( array( $live['xmlrpc'], $live['hide_admin'] ) ) );
wp_set_current_user( 1 );
ob_start();
PNCP_Hardening::render_card();
$card = (string) ob_get_clean();
t( 'H: the card shows the note and the details folded under "More" (details.pncp-more)', false !== strpos( $card, 'Checked at the server' ) && false !== strpos( $card, '<details class="pncp-more">' ) && false !== strpos( $card, 'In the Bunny dashboard' ), substr( wp_strip_all_tags( $card ), 0, 200 ) );
wp_set_current_user( 0 );
$origin = 'error';
delete_transient( PNCP_Self_Check::ROUTE );
$live = PNCP_Hardening::live( true );
t( 'H: the server cannot be asked either: "could not be checked", naming who refused instead of the bare 403', 'unknown' === $live['headers']['state'] && false !== strpos( $live['headers']['note'], 'Bunny CDN edge refused it' ), $live['headers']['note'] );
$origin  = 'ok';
$edge403 = false;
$live    = PNCP_Hardening::live( true );
t( 'H: through the public address: the answer visitors get, unmarked', 'on' === $live['headers']['state'] && false === strpos( $live['headers']['note'], 'Checked at the server' ) && empty( $live['headers']['details'] ), wp_json_encode( $live['headers'] ) );
remove_filter( 'pre_http_request', $mock, 5 );
delete_transient( 'pncp_harden_live' );
delete_transient( PNCP_Self_Check::ROUTE );

/* ---------- F (HTTP). Straight to the test server over real HTTP ---------- */
if ( ! function_exists( 'curl_init' ) || ! defined( 'CURLOPT_RESOLVE' ) ) {
	echo "SKIP F HTTP: no cURL with CURLOPT_RESOLVE\n";
} else {
	// The site's name does not resolve here (as when the server cannot reach its public address): only the way
	// straight to 127.0.0.1 with CURLOPT_RESOLVE reaches the test server.
	$fake    = 'pncp-origin.invalid';
	$rewrite = static function ( $value ) use ( $own_host, $fake ) {
		return str_replace( '//' . $own_host, '//' . $fake, (string) $value );
	};
	add_filter( 'option_home', $rewrite );
	add_filter( 'option_siteurl', $rewrite );
	$seen_resolve = array();
	$spy          = static function ( $handle, $args ) use ( &$seen_resolve ) {
		$seen_resolve[] = isset( $args['pncp_resolve'] ) ? (string) $args['pncp_resolve'] : '';
	};
	add_action( 'http_api_curl', $spy, 9, 2 );
	$r = PNCP_Self_Check::request( home_url( '/robots.txt' ), array( 'timeout' => 10 ), 'page' );
	t( 'F HTTP: the public address cannot be reached, straight to 127.0.0.1: 200 from the test server', 'origin' === $r['via'] && ! is_wp_error( $r['response'] ) && 200 === (int) wp_remote_retrieve_response_code( $r['response'] ), is_wp_error( $r['response'] ) ? $r['response']->get_error_message() : wp_json_encode( array( $r['via'], wp_remote_retrieve_response_code( $r['response'] ) ) ) );
	t( 'F HTTP: http_api_curl got the CURLOPT_RESOLVE entry for the site\'s host and port', in_array( $fake . ':' . $port . ':127.0.0.1', $seen_resolve, true ), wp_json_encode( $seen_resolve ) );
	t( 'F HTTP: ... the answer is the site\'s robots.txt (Host header kept)', false !== stripos( (string) wp_remote_retrieve_body( $r['response'] ), 'user-agent' ) );
	set_transient( PNCP_Self_Check::ROUTE, '127.0.0.1', 600 );
	$plain = wp_remote_get( home_url( '/robots.txt' ), array( 'timeout' => 10 ) );
	t( 'F HTTP: with the route, a plain wp_remote_get() of the site reaches it too', ! is_wp_error( $plain ) && 200 === (int) wp_remote_retrieve_response_code( $plain ), is_wp_error( $plain ) ? $plain->get_error_message() : '' );
	delete_transient( PNCP_Self_Check::ROUTE );
	remove_action( 'http_api_curl', $spy, 9 );
	remove_filter( 'option_home', $rewrite );
	remove_filter( 'option_siteurl', $rewrite );
	// A real self-check through the public address of the test server, with the receiving side's note.
	delete_option( PNCP_Self_Check::LOG );
	$trace = PNCP_Self_Check::run();
	t( 'F HTTP: run(): the site reaches itself (public address, HTTP 200)', ! empty( $trace['ok'] ) && 'public' === $trace['via'], PNCP_Self_Check::summary( $trace ) );
	t( 'F HTTP: run(): the receiving side\'s note is matched to the request (signature valid, passed)', isset( $trace['steps'][0]['in']['sig'] ) && 'ok' === $trace['steps'][0]['in']['sig'] && 'passed' === $trace['steps'][0]['in']['verdict'], wp_json_encode( $trace['steps'] ) );
	t( 'F HTTP: run(): the answer carried "X-ScrapeLock: ok"', 'ok' === $trace['steps'][0]['marker'], wp_json_encode( $trace['steps'][0] ) );
	t( 'F HTTP: run() is kept for Site Health and WP-CLI', is_array( PNCP_Self_Check::last() ) );
}

/* ---------- E. The CDN never refuses the server because of ScrapeLock ---------- */
set_transient( PNCP_Server_Ips::OUTBOUND, array( SERVER => time() ), DAY_IN_SECONDS );
update_option( PNCP_Edge::CONFIG, array( 'provider' => 'bunny', 'zone' => '4242', 'token' => 'g1-test-bunny-key-1234567890' ), false );
update_option(
	PNCP_Edge::STATE,
	array(
		'rules' => array(
			SERVER => array(
				'until'  => time() + DAY_IN_SECONDS,
				'own'    => true,
				'reason' => 'rate_page',
			),
		),
		'time'  => time(),
	),
	false
);
wp_clear_scheduled_hook( PNCP_Edge::CRON );
t( 'E: a block of the server\'s address sent to the CDN before: a run to remove it starts at once', PNCP_Edge::spare_server_ips( true ) && false !== wp_next_scheduled( PNCP_Edge::CRON ) );
t( 'E: ... on wp-admin pages at most every 10 minutes', false === PNCP_Edge::spare_server_ips() );
t( 'E: ... and the server\'s address is not among the blocks the run wants', ! isset( PNCP_Edge::wanted( 'bunny' )[ SERVER ] ) );
update_option( PNCP_Edge::STATE, array( 'rules' => array( '198.51.100.120' => array( 'until' => time() + 60, 'own' => true ) ) ), false );
wp_clear_scheduled_hook( PNCP_Edge::CRON );
t( 'E: a visitor\'s block: nothing to do', false === PNCP_Edge::spare_server_ips( true ) );
delete_option( PNCP_Edge::CONFIG );
delete_option( PNCP_Edge::STATE );
wp_clear_scheduled_hook( PNCP_Edge::CRON );
$home_match = array();
foreach ( PNCP_Bunny::presets() as $id => $preset ) {
	foreach ( (array) $preset['patterns'] as $pattern ) {
		$re = '#^' . str_replace( '\*', '.*', preg_quote( (string) $pattern, '#' ) ) . '$#i';
		foreach ( array( home_url( '/' ), home_url( '/hello-world/' ) ) as $u ) {
			if ( preg_match( $re, $u ) ) {
				$home_match[] = $id;
			}
		}
	}
}
t( 'E: no Bunny preset of ScrapeLock (login lock, xmlrpc, probes …) matches the home page or a post', ! $home_match, wp_json_encode( $home_match ) );
delete_transient( PNCP_Server_Ips::OUTBOUND );

/* ---------- O. "Only through the CDN" ---------- */
t( 'O: on without a secret: not in effect', ! PNCP_Origin::active() );
as_request( '192.0.2.44', SELF_UA, array(), '/' );
t( 'O: ... a request straight to the server is not refused by it', ! PNCP_Origin::active() );
$cfg2        = json_decode( PNCP_Precheck::config_json(), true );
$cfg2['dir'] = $pc_dir;
t( 'O: ... nor by the pre-cache check', '' === PNCP_Precheck_Runtime::not_via_cdn( $cfg2 ) );
settings( array( 'cdn_secret' => 'g1-secret-0123456789' ) );
t( 'O: with a secret it is in effect', PNCP_Origin::active() );
as_request( '192.0.2.44', SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ), 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
t( 'O: ... a signed request without the secret is exempt (another Host header too)', PNCP_Origin::exempt() );
$cfg2                = json_decode( PNCP_Precheck::config_json(), true );
$cfg2['dir']         = $pc_dir;
$cfg2['self_key']    = PNCP_Server_Ips::sig_key();
as_request( '192.0.2.44', SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ), 'HTTP_HOST' => ORIGIN_HOST ), $home_path );
// (verdict() itself never runs on the command line: its first step, the site's signature, is what lets it pass.)
t( 'O: ... and the pre-cache check knows it as the site\'s, the step before "not via the CDN"', PNCP_Precheck_Runtime::self_signed( $cfg2, time() ) );
as_request( '192.0.2.44', SELF_UA, array(), '/' );
t( 'O: ... an unsigned one is refused there (not via the CDN)', '192.0.2.44' === PNCP_Precheck_Runtime::not_via_cdn( $cfg2 ), PNCP_Precheck_Runtime::not_via_cdn( $cfg2 ) );
settings( array( 'cdn_secret' => '' ) );

/* ---------- T. "Check a request" ---------- */
$presets = PNCP_Tester::presets();
t( 'T: the preset "The site itself (loopback)"', isset( $presets['loopback'] ) && 'loopback' === $presets['loopback']['mode'] && '' !== $presets['loopback']['label'] );
$lb = PNCP_Tester::loopback( array( 'address' => '/' ) );
$by = array();
foreach ( isset( $lb['layers'] ) ? $lb['layers'] : array() as $row ) {
	$by[ $row['layer'] ] = $row['verdict'];
}
t( 'T: the loopback check: allowed, layer by layer (signature, pre-cache, Only through the CDN, early, WordPress)', 'allowed' === $lb['verdict'] && array( 'sig', 'pre-cache', 'origin', 'early', 'wp' ) === array_keys( $by ) && 'pass' === $by['sig'] && 'pass' === $by['wp'], wp_json_encode( $lb['layers'] ) );
t( 'T: ... "Only through the CDN" without a secret: off', 'off' === $by['origin'] );
t( 'T: ... as the server\'s own request: WordPress\'s User-Agent, signed, nothing sent', 0 === strpos( $lb['request']['ua'], 'WordPress/' ) && isset( $lb['request']['headers']->{'X-ScrapeLock-Sig'} ) && 'loopback' === $lb['request']['mode'] );
t( 'T: a bad address is refused', is_wp_error( PNCP_Tester::loopback( array( 'address' => 'https://example.com/' ) ) ) );
$js = (string) file_get_contents( dirname( __DIR__ ) . '/assets/js/tester.js' );
t( 'T: tester.js sends the loopback mode, draws the layers and has the self-check button', false !== strpos( $js, "'loopback' === mode" ) && false !== strpos( $js, 'data.layers' ) && false !== strpos( $js, 'pncp-tester-selfcheck' ) );
wp_set_current_user( 1 );
ob_start();
PNCP_Tester_View::render( PNCP_Options::get() );
$view = (string) ob_get_clean();
t( 'T: the card has "Run a real self-check now" and the loopback preset', false !== strpos( $view, 'id="pncp-tester-selfcheck"' ) && false !== strpos( $view, 'data-preset="loopback"' ) );
$data = PNCP_Tester::js_data();
t( 'T: the script gets the self-check action and its nonce', PNCP_Self_Check::ACTION === $data['selfcheck']['action'] && false !== wp_verify_nonce( $data['selfcheck']['nonce'], PNCP_Self_Check::ACTION ) );
wp_set_current_user( 0 );

/** Runs PNCP_Self_Check::ajax() as admin-ajax.php would: [status, decoded JSON]. */
function self_ajax( $user, $nonce ) {
	$_SERVER['REQUEST_METHOD'] = 'POST';
	$_POST                     = array( 'nonce' => $nonce );
	$_REQUEST                  = $_POST;
	wp_set_current_user( $user );
	$doing   = static function () {
		return true;
	};
	$handler = static function () {
		return static function ( $message, $title, $args ) {
			throw new RuntimeException( 'done' );
		};
	};
	add_filter( 'wp_doing_ajax', $doing );
	add_filter( 'wp_die_ajax_handler', $handler );
	$status = 200;
	$keep   = static function ( $header, $code ) use ( &$status ) {
		$status = (int) $code;
		return $header;
	};
	add_filter( 'status_header', $keep, 10, 2 );
	ob_start();
	try {
		PNCP_Self_Check::ajax();
	} catch ( RuntimeException $e ) {
		unset( $e );
	}
	$out = (string) ob_get_clean();
	remove_filter( 'wp_doing_ajax', $doing );
	remove_filter( 'wp_die_ajax_handler', $handler );
	remove_filter( 'status_header', $keep, 10 );
	wp_set_current_user( 0 );
	$_POST    = array();
	$_REQUEST = array();
	return array( $status, json_decode( $out, true ) );
}
list( $st, $j ) = self_ajax( 1, 'bad-nonce' );
// (The status line cannot be seen from the command line, where output has already started.)
t( 'T: "Run a real self-check now" without a valid nonce: refused', isset( $j['success'] ) && false === $j['success'] && false !== strpos( (string) $j['data']['message'], 'expired' ), $st . ' ' . wp_json_encode( $j ) );
$sub = get_user_by( 'login', 'g1-t3122-sub' );
$sub = $sub ? $sub->ID : wp_insert_user(
	array(
		'user_login' => 'g1-t3122-sub',
		'user_pass'  => wp_generate_password(),
		'role'       => 'subscriber',
	)
);
wp_set_current_user( $sub );
$sub_nonce = wp_create_nonce( PNCP_Self_Check::ACTION );
list( $st, $j ) = self_ajax( $sub, $sub_nonce );
t( 'T: ... a subscriber with a valid nonce: refused (manage_options)', isset( $j['success'] ) && false === $j['success'] && false !== strpos( (string) $j['data']['message'], 'not allowed' ), $st . ' ' . wp_json_encode( $j ) );
wp_set_current_user( 1 );
$admin_nonce = wp_create_nonce( PNCP_Self_Check::ACTION );
list( $st, $j ) = self_ajax( 1, $admin_nonce );
t( 'T: ... the administrator: a real self-check with its headline and trace', ! empty( $j['success'] ) && '' !== (string) $j['data']['headline'] && is_array( $j['data']['lines'] ) && $j['data']['lines'], wp_json_encode( $j ) );
require_once ABSPATH . 'wp-admin/includes/user.php';
wp_delete_user( $sub );

/* ---------- K. Site Health and WP-CLI ---------- */
add_filter( 'pre_http_request', $mock, 5, 3 );
$edge403 = false;
$res     = PNCP_Health::test_selfrequest();
t( 'K: Site Health "ScrapeLock self-request test": good when the public address answers', 'good' === $res['status'] && 'scrapelock_selfrequest' === $res['test'], wp_json_encode( $res ) );
$edge403 = true;
$origin  = 'ok';
$res     = PNCP_Health::test_selfrequest();
t( 'K: ... recommended, naming Bunny\'s edge, when it refuses and the server answers', 'recommended' === $res['status'] && false !== strpos( $res['description'], 'Bunny CDN edge' ) && false !== strpos( $res['description'], 'In the Bunny dashboard' ), wp_json_encode( $res ) );
$origin = 'error';
delete_transient( PNCP_Self_Check::ROUTE );
$res = PNCP_Health::test_selfrequest();
t( 'K: ... critical when the server cannot be reached either', 'critical' === $res['status'], wp_json_encode( $res ) );
remove_filter( 'pre_http_request', $mock, 5 );
delete_transient( PNCP_Self_Check::ROUTE );
$tests = PNCP_Health::tests( array( 'direct' => array(), 'async' => array() ) );
$src   = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-pncp-health.php' );
t( 'K: registered as an async test (one underscore: health-check-scrapelock-selfrequest)', isset( $tests['async']['scrapelock_selfrequest'] ) && false !== strpos( $src, "'wp_ajax_health-check-scrapelock-selfrequest'" ) );
$cli = getenv( 'WP_CLI' );
if ( $cli ) {
	$out = (string) shell_exec( $cli . ' scrapelock selfcheck 2>&1' );
	t( 'K: wp scrapelock selfcheck: the summary and the trace of both sides', false !== strpos( $out, 'reaches itself' ) && false !== strpos( $out, 'Through the public address' ) && false !== strpos( $out, 'signature: valid' ), $out );
	$out = (string) shell_exec( $cli . ' scrapelock selfcheck --log 2>&1' );
	t( 'K: wp scrapelock selfcheck --log: the notes of both sides', false !== strpos( $out, 'Notes of the site' ), $out );
} else {
	echo "SKIP K: wp scrapelock selfcheck (no WP_CLI)\n";
}

// Clean up the temporary data folder.
foreach ( glob( $pc_dir . '/self/*' ) ?: array() as $pncp_f ) {
	@unlink( $pncp_f );
}
@rmdir( $pc_dir . '/self' );
@rmdir( $pc_dir );

echo $fails ? "\n$fails FAILED\n" : "\nALL PASSED\n";
exit( $fails ? 1 : 0 );
