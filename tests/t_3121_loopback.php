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
 * P. The pre-cache check: the same signature, its key passed by the line in wp-config.php (never in the data
 *    folder in uploads), nonces used once (a file each).
 * I. The server's addresses: the outbound one, detected by the site's signed requests (24-hour transient; a
 *    stolen signature used first teaches nothing),
 *    and SCRAPELOCK_SERVER_IPS (a test mu-plugin defines it for the web server), in WordPress, the early check
 *    and the pre-cache check.
 * E. ScrapeLock's own rules at the CDN never block the server: temporary blocks (PNCP_Edge), Bunny's logs, the
 *    wp-login.php lock (stand-in Bunny API, within 5 entries per condition).
 * H. Vulnerable points "Check again" and the Stealth test's fetch through the "edge" get the real answers.
 *
 * The HTTP requests "come from the Bunny edge" with the harness's X-Test-Remote-Addr (REMOTE_ADDR in WordPress
 * and the early check) and X-Test-HTTPS. The pre-cache check is tested over HTTP with a stand-in page cache
 * (WP_CACHE + advanced-cache.php serving /cached-page/), as t_311_pipeline.php does; wp-config.php and
 * advanced-cache.php are put back at the end. Only on a test WordPress.
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
	test_lists(); // Saving the settings lets the next wp-admin page download the missing lists (with internet).
	PNCP_Ip::reset();
}

/**
 * The stage's Bunny and Cloudflare lists, stored again: with internet (CI), WP cron downloads the real lists (the
 * daily refresh, or the "missing lists" one a settings change allows), and the stand-in edge would no longer be one.
 */
function test_lists() {
	wp_unschedule_hook( PNCP_Ip::CRON );
	set_transient( 'pncp_lists_missing_try', 1, HOUR_IN_SECONDS );
	PNCP_Ip::store_list( 'bunny', array( EDGE, '198.51.100.11' ) );
	PNCP_Ip::store_list( 'cloudflare', array( '104.16.0.0/13', '173.245.48.0/20' ) );
}

const EDGE      = '198.51.100.10'; // A Bunny edge (in the stored Bunny list below).
const SERVER    = '203.0.113.50';  // The server's public address, as the edge sees it.
const VISITOR   = '198.51.100.81';
const BANNED    = '198.51.100.99';
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
	PNCP_Precheck_Runtime::$self_seen = array();
}

/** check() for a page, without counting. */
function verdict( $context = 'page' ) {
	$v = PNCP_Bots::check( $context, false );
	return is_array( $v ) ? $v['code'] . ' ' . $v['reason'] : 'pass';
}

/** Forgets the server's addresses learned so far (each signed request teaches the address it came from). */
function forget_server_ips() {
	delete_transient( PNCP_Server_Ips::OUTBOUND );
	delete_option( PNCP_Server_Ips::OPTION );
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
foreach ( array( PNCP_Server_Ips::OPTION, 'pncp_ip_lists_bunny', 'pncp_ip_lists_cloudflare', PNCP_Ip::BUNNY_SUM, PNCP_Edge::CONFIG, PNCP_Edge::STATE, PNCP_Edge::STAFF, PNCP_Bunny::CONFIG, PNCP_Bunny::RULES, PNCP_Bunny::LOGIN_STRICT ) as $pncp_o ) {
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
		if ( ! wp_next_scheduled( PNCP_Ip::CRON ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', PNCP_Ip::CRON ); // test_lists() unscheduled it.
		}
		PNCP_Bunny::reset();
		PNCP_Early::sync();
		PNCP_Precheck::sync();
		PNCP_Log::unban_all();
	}
);

update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
PNCP_Log::unban_all();
// The stored Bunny list of the stage (an earlier test or WP cron may have changed it; put back at the end).
test_lists();
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
t( 'S: requests to the site\'s own address carry X-ScrapeLock-Sig (time.nonce.hmac; 3.12.2: .hint)', 1 === preg_match( '/^\d{10}\.[0-9a-f]{24}\.[0-9a-f]{64}(?:\.[0-9a-f]{16})?$/', $tok ), $tok );
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
settings( array( 'countries_block' => 'ZZ,US,GR,XX', 'rate_limit' => 1, 'rate_limit_unverified' => 1, 'block_ips' => BANNED ) );
PNCP_Log::ban( BANNED, 10, 'test' );
as_request( BANNED, SELF_UA );
t( 'S: a banned, blocked address, unsigned: 403', 0 === strpos( verdict(), '403' ), verdict() );
$v = array();
for ( $i = 0; $i < 3; $i++ ) {
	as_request( BANNED, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ) ), $home_path );
	$v[] = PNCP_Bots::check( 'page', true ) ? 'refused' : 'pass';
}
t( 'S: signed from a blocked and banned address, page limit 1, three times: passes', array( 'pass', 'pass', 'pass' ) === $v, implode( ',', $v ) );
PNCP_Log::unban( BANNED );
forget_server_ips();
settings( array( 'countries_block' => '', 'rate_limit' => 60, 'rate_limit_unverified' => 20, 'block_ips' => '' ) );

// What does not pass.
$now = time();
$bad = array(
	'expired (2 minutes old)'           => array( sig( '/', 'GET', $now - 120 ), $home_path, 'GET', $http_host ),
	'from the future (2 minutes ahead)' => array( sig( '/', 'GET', $now + 120 ), $home_path, 'GET', $http_host ),
	'made for another path'             => array( sig( '/other/' ), $home_path, 'GET', $http_host ),
	'made for another method'           => array( sig( '/', 'POST' ), $home_path, 'GET', $http_host ),
	// 3.12.2: "sent to another host" (a Host header the CDN wrote) is the site's request: t_3122_loopback.php.
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
forget_server_ips();
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
forget_server_ips();
as_request( SERVER, SELF_UA );
t( 'S cdn_only: the server\'s request straight to the origin, unsigned: not exempt', ! PNCP_Origin::exempt() );
as_request( SERVER, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/' ) ), $home_path );
t( 'S cdn_only: signed: exempt', PNCP_Origin::exempt() );
forget_server_ips();
as_request( VISITOR, SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => 'x' . sig( '/' ) ), $home_path );
t( 'S cdn_only: a forged signature: not exempt', ! PNCP_Origin::exempt() );
settings( array( 'cdn_secret' => '' ) );

// The trap and the probe ban: never for a signed request.
as_request( VISITOR, 'python-requests/2.32.3', array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/.env' ) ), '/.env' );
$m = new ReflectionMethod( 'PNCP_Bots', 'should_ban_on_sight' );
$m->setAccessible( true );
t( 'S: the trap and the probe ban never ban a signed request', false === $m->invoke( null, VISITOR, 'pncp_tr_' ) );

/* ---------- S over HTTP: WordPress and the early check, the request "from the edge" ---------- */
test_lists();
forget_server_ips();
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
test_lists();
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

/* ---------- P. The pre-cache check ---------- */
test_lists();
forget_server_ips();
file_put_contents( $config_file, "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) );
file_put_contents( $cache_file, "<?php\nif ( isset( \$_SERVER['REQUEST_URI'] ) && 0 === strpos( \$_SERVER['REQUEST_URI'], '/cached-page/' ) ) {\n\theader( 'X-Test-Cache: HIT' );\n\techo 'CACHED PAGE';\n\texit;\n}\n" );
// The visitor through a proxy on the server (X-Real-IP from 127.0.0.1): the pre-cache check runs before the
// harness can change REMOTE_ADDR.
settings( array( 'precheck' => 1, 'ip_header' => 'x_real_ip' ) );
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
WP_Screen::get( 'settings_page_scrapelock' )->set_current_screen(); // wp-config.php is edited in wp-admin only.
$status = PNCP_Precheck::sync();
t( 'P: the pre-cache check is on', 'ok' === $status, (string) $status );
sleep( 2 ); // OPcache of the server: wp-config.php.
$pc_dir = PNCP_Precheck::dir();
$json   = (string) file_get_contents( $pc_dir . '/config.json' );
$key    = PNCP_Server_Ips::sig_key();
t( 'P: config.json has the site\'s host names and the window of the signature, never its key', false !== strpos( $json, '"self_sig"' ) && false !== strpos( $json, '"' . $own_host . '"' ) && '' !== $key && false === strpos( $json, $key ) );
$in_data = array();
foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $pc_dir, FilesystemIterator::SKIP_DOTS ) ) as $pncp_f ) {
	if ( false !== strpos( (string) file_get_contents( $pncp_f->getPathname() ), $key ) ) {
		$in_data[] = $pncp_f->getPathname();
	}
}
t( 'P: the key is in no file of the data folder (uploads: Nginx serves any file whose name is known)', ! $in_data, implode( ', ', $in_data ) );
t( 'P: the line in wp-config.php passes it to the check', false !== strpos( (string) file_get_contents( $config_file ), "PNCP_Precheck_Runtime::boot( '" . $pc_dir . "', '" . $key . "' );" ) );

$c             = PNCP_Precheck_Runtime::load( $pc_dir );
$c['self_key'] = $key; // As boot() adds it.
$tok           = sig( '/cached-page/' );
as_request( '127.0.0.1', '', array( 'HTTP_X_REAL_IP' => VISITOR, 'HTTP_X_SCRAPELOCK_SIG' => $tok ), '/cached-page/' );
t( 'P unit: a valid signature', is_array( $c ) && PNCP_Precheck_Runtime::self_signed( $c, time() ) );
t( 'P unit: ... checked again in the same request: still valid', PNCP_Precheck_Runtime::self_signed( $c, time() ) );
as_request( '127.0.0.1', '', array( 'HTTP_X_REAL_IP' => VISITOR, 'HTTP_X_SCRAPELOCK_SIG' => $tok ), '/cached-page/' );
t( 'P unit: the same signature in another request (replayed): refused', ! PNCP_Precheck_Runtime::self_signed( $c, time() ) );
t( 'P unit: its nonce is kept as a file of the folder "self"', is_file( $pc_dir . '/self/' . explode( '.', $tok )[1] ) );
$now = time();
foreach (
	array(
		'expired'               => array( sig( '/cached-page/', 'GET', $now - 120 ), '/cached-page/', $http_host ),
		'for another path'      => array( sig( '/other/' ), '/cached-page/', $http_host ),
		// 3.12.2: "sent to another host" passes now (t_3122_loopback.php).
		'forged'                => array( $now . '.' . str_repeat( 'b', 24 ) . '.' . str_repeat( 'c', 64 ), '/cached-page/', $http_host ),
	) as $label => $case
) {
	as_request( '127.0.0.1', '', array( 'HTTP_X_REAL_IP' => VISITOR, 'HTTP_X_SCRAPELOCK_SIG' => $case[0], 'HTTP_HOST' => $case[2] ), $case[1] );
	t( "P unit: a signature $label: refused", ! PNCP_Precheck_Runtime::self_signed( $c, $now ) );
}
$bad_c             = $c;
$bad_c['self_key'] = ''; // A line in wp-config.php of 3.12.0, without the key.
as_request( '127.0.0.1', '', array( 'HTTP_X_SCRAPELOCK_SIG' => sig( '/cached-page/' ) ), '/cached-page/' );
t( 'P unit: without the key (the line of 3.12.0) nothing is signed', ! PNCP_Precheck_Runtime::self_signed( $bad_c, time() ) );

// Over HTTP: a cached page, no User-Agent (refused by the pre-cache check before the page cache serves it).
$cached = static function ( $headers ) {
	list( $code, , $body ) = req( '/cached-page/', array_merge( array( 'X-Real-IP' => VISITOR ), $headers ) );
	return $code . ( false !== strpos( $body, 'CACHED PAGE' ) ? ' cached' : '' );
};
forget_server_ips();
PNCP_Precheck::sync();
// OPcache of the server keeps the previous wp-config.php for a few seconds: wait for the stand-in page cache.
for ( $i = 0; $i < 20 && '200 cached' !== $cached( array( 'User-Agent' => SELF_UA, 'Accept-Language' => 'en', 'X-Real-IP' => '198.51.100.9' . ( $i % 10 ) ) ); $i++ ) {
	usleep( 500000 );
}
t( 'P HTTP: no User-Agent, unsigned: 403 before the page cache', '403' === $cached( array() ), $cached( array() ) );
$tok = sig( '/cached-page/' );
$got = $cached( array( 'X-ScrapeLock-Sig' => $tok ) );
t( 'P HTTP: signed: the cached page', '200 cached' === $got, $got );
t( 'P HTTP: the same signature again (replayed): 403', '403' === $cached( array( 'X-ScrapeLock-Sig' => $tok ) ) );
t( 'P HTTP: expired: 403', '403' === $cached( array( 'X-ScrapeLock-Sig' => sig( '/cached-page/', 'GET', time() - 120 ) ) ) );
t( 'P HTTP: made for another path: 403', '403' === $cached( array( 'X-ScrapeLock-Sig' => sig( '/' ) ) ) );
$old = PNCP_Server_Ips::sign( array( 'headers' => array() ), home_url( '/cached-page/' ) );
$got = $cached( array( 'X-ScrapeLock-Self' => $old['headers'][ PNCP_Server_Ips::HEADER ] ) );
t( 'P HTTP: only the 3.11 header (X-ScrapeLock-Self), no User-Agent: 403', '403' === $got, $got );
// "Only through the CDN" (with a secret): the server's request straight to the origin.
settings( array( 'cdn_secret' => 'stage-secret-1234567890' ) );
PNCP_Precheck::sync();
$got = $cached( array( 'User-Agent' => SELF_UA ) );
t( 'P HTTP cdn_only: a request around the CDN, unsigned: 403', '403' === $got, $got );
t( 'P HTTP cdn_only: signed: the cached page', '200 cached' === $cached( array( 'User-Agent' => SELF_UA, 'X-ScrapeLock-Sig' => sig( '/cached-page/' ) ) ) );
t( 'P HTTP cdn_only: with the CDN secret (through the CDN): the cached page', '200 cached' === $cached( array( 'User-Agent' => SELF_UA, 'X-ScrapeLock-CDN' => 'stage-secret-1234567890', 'Accept-Language' => 'en' ) ) );
settings( array( 'cdn_secret' => '', 'precheck' => 0, 'ip_header' => 'remote_addr' ) );
PNCP_Precheck::sync();
file_put_contents( $config_file, $original );
sleep( 2 ); // OPcache of the server: wp-config.php.

/* ---------- I. The server's addresses: the detected outbound one and SCRAPELOCK_SERVER_IPS ---------- */
test_lists();
delete_transient( PNCP_Server_Ips::OUTBOUND );
delete_option( PNCP_Server_Ips::OPTION );
$wp_ua = 'WordPress/6.9; ' . home_url( '/' );
/** The site's own request that sent this signature got its answer (PNCP_Server_Ips::seen(), filter http_response). */
function answered( $tok ) {
	PNCP_Server_Ips::seen( array( 'response' => array( 'code' => 200 ) ), array( 'headers' => array( PNCP_Server_Ips::SIG_HEADER => $tok ) ), home_url( '/' ) );
}
// Through the edge without real_ip: the address the edge saw is the last of X-Forwarded-For.
$tok = sig( '/' );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => '192.0.2.200, 203.0.113.51', 'HTTP_X_SCRAPELOCK_SIG' => $tok ), $home_path );
t( 'I: a signed request through the edge passes', 'pass' === verdict(), verdict() );
t( 'I: ... the request that arrives learns nothing by itself', ! PNCP_Server_Ips::is_server_ip( '203.0.113.51' ) );
answered( $tok );
t( 'I: the site\'s request that sent it learns where it arrived from (the last of X-Forwarded-For): the outbound address', in_array( '203.0.113.51', PNCP_Server_Ips::outbound_ips(), true ) && PNCP_Server_Ips::is_server_ip( '203.0.113.51' ), wp_json_encode( get_transient( PNCP_Server_Ips::OUTBOUND ) ) );
t( 'I: ... not the address the client wrote before it', ! PNCP_Server_Ips::is_server_ip( '192.0.2.200' ) );
if ( ! wp_using_ext_object_cache() ) {
	$until = (int) get_option( '_transient_timeout_' . PNCP_Server_Ips::OUTBOUND );
	t( 'I: kept in a transient for 24 hours', abs( $until - ( time() + DAY_IN_SECONDS ) ) < 30, (string) ( $until - time() ) );
}
t( 'I: ... and in the pre-cache check\'s configuration', isset( PNCP_Precheck::config()['self_ips'][0]['203.0.113.51'] ) );
// With Nginx real_ip (REMOTE_ADDR is the address the edge saw).
$tok = sig( '/' );
as_request( '203.0.113.52', SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => $tok ), $home_path );
verdict();
answered( $tok );
t( 'I: with real_ip: the signed request\'s REMOTE_ADDR is detected', in_array( '203.0.113.52', PNCP_Server_Ips::outbound_ips(), true ) );
as_request( '203.0.113.52', $wp_ua );
t( 'I: then the WordPress User-Agent from that address, unsigned, passes (cron, preloads that are not WordPress\'s)', 'pass' === verdict(), verdict() );
as_request( VISITOR, $wp_ua );
t( 'I: the same User-Agent from another address: 403', '403 no_browser' === verdict(), verdict() );
as_request( EDGE, $wp_ua, array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.52' ) );
t( 'I: X-Forwarded-For = that address through the edge (unsigned): 403', '403 no_browser' === verdict(), verdict() );
// A signature someone else got hold of and used first: their request passes once, but teaches nothing.
$tok = sig( '/' );
as_request( '203.0.113.56', SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => $tok ), $home_path );
verdict();
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.51', 'HTTP_X_SCRAPELOCK_SIG' => $tok ), $home_path );
t( 'I: a stolen signature used first: the site\'s own request is then refused as a replay', '403 fake_browser' === verdict(), verdict() );
answered( $tok );
t( 'I: ... and the thief\'s address is never learned (the nonce was used twice)', ! PNCP_Server_Ips::is_server_ip( '203.0.113.56' ) );
// A forged or expired signature teaches nothing.
$tok = sig( '/' );
as_request( '203.0.113.53', SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => 'x' . $tok ), $home_path );
verdict();
answered( 'x' . $tok );
$old = sig( '/', 'GET', time() - 300 );
as_request( EDGE, SELF_UA, array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.54', 'HTTP_X_SCRAPELOCK_SIG' => $old ), $home_path );
verdict();
answered( $old );
t( 'I: a forged or expired signature teaches no address', ! PNCP_Server_Ips::is_server_ip( '203.0.113.53' ) && ! PNCP_Server_Ips::is_server_ip( '203.0.113.54' ) );
// The answer to a request to another host never teaches anything.
$tok = sig( '/' );
as_request( '203.0.113.57', SELF_UA, array( 'HTTP_X_SCRAPELOCK_SIG' => $tok ), $home_path );
verdict();
PNCP_Server_Ips::seen( array( 'response' => array( 'code' => 200 ) ), array( 'headers' => array( PNCP_Server_Ips::SIG_HEADER => $tok ) ), 'https://example.com/' );
t( 'I: the answer of another host teaches nothing', ! PNCP_Server_Ips::is_server_ip( '203.0.113.57' ) );
// An address seen more than 24 hours ago is forgotten.
set_transient( PNCP_Server_Ips::OUTBOUND, array( '203.0.113.55' => time() - DAY_IN_SECONDS - 60 ), DAY_IN_SECONDS );
t( 'I: an address last seen more than 24 hours ago no longer counts', ! in_array( '203.0.113.55', PNCP_Server_Ips::outbound_ips(), true ) );
delete_transient( PNCP_Server_Ips::OUTBOUND );
delete_option( PNCP_Server_Ips::OPTION );

// SCRAPELOCK_SERVER_IPS (wp-config.php): here and, through a test mu-plugin, in the web server's requests.
define( 'SCRAPELOCK_SERVER_IPS', '192.0.2.0/28, 10.77.0.9 2001:db8:5::/64;0.0.0.0/0, not-an-ip' );
$const_mu = WP_CONTENT_DIR . '/mu-plugins/pncp-t3121-server-ips.php';
file_put_contents( $const_mu, "<?php\n// TESTS ONLY: written and removed by tests/t_3121_loopback.php.\ndefined( 'SCRAPELOCK_SERVER_IPS' ) || define( 'SCRAPELOCK_SERVER_IPS', '192.0.2.0/28, 10.77.0.9' );\n" );
register_shutdown_function(
	static function () use ( $const_mu ) {
		@unlink( $const_mu );
	}
);
t( 'I SCRAPELOCK_SERVER_IPS: addresses and ranges, a range wider than /8 and a non-address left out', array( '192.0.2.0/28', '10.77.0.9', '2001:db8:5::/64' ) === PNCP_Server_Ips::const_ips(), wp_json_encode( PNCP_Server_Ips::const_ips() ) );
as_request( '192.0.2.5', $wp_ua );
t( 'I SCRAPELOCK_SERVER_IPS: the WordPress User-Agent from an address in its range: passes', 'pass' === verdict(), verdict() );
as_request( '2001:db8:5::77', '' );
t( 'I SCRAPELOCK_SERVER_IPS: no User-Agent from its IPv6 range: passes', 'pass' === verdict(), verdict() );
as_request( '10.77.0.9', $wp_ua );
t( 'I SCRAPELOCK_SERVER_IPS: its private address, straight from the server\'s network: passes', 'pass' === verdict(), verdict() );
as_request( '10.77.0.9', $wp_ua, array( 'HTTP_X_FORWARDED_FOR' => VISITOR ) );
t( 'I SCRAPELOCK_SERVER_IPS: that private address passing a visitor on (a proxy): 403', '403 no_browser' === verdict(), verdict() );
as_request( EDGE, $wp_ua, array( 'HTTP_X_FORWARDED_FOR' => '192.0.2.5' ) );
t( 'I SCRAPELOCK_SERVER_IPS: X-Forwarded-For with its address through the edge: 403', '403 no_browser' === verdict(), verdict() );
settings( array( 'early_mode' => 1 ) );
as_request( '192.0.2.5', '' );
t( 'I SCRAPELOCK_SERVER_IPS: the early check lets its address pass', null === PNCP_Early::check(), wp_json_encode( PNCP_Early::check() ) );
settings( array( 'early_mode' => 0 ) );
$c = PNCP_Precheck::config();
t( 'I SCRAPELOCK_SERVER_IPS: in the pre-cache check\'s configuration', isset( $c['self_ips'][1] ) && in_array( '192.0.2.0/28', $c['self_ips'][1], true ) && isset( $c['self_const'][0]['10.77.0.9'] ), wp_json_encode( array( $c['self_ips'], $c['self_const'] ) ) );
$c['dir'] = sys_get_temp_dir();
foreach (
	array(
		array( '192.0.2.5', array(), true, 'an address of its range' ),
		array( '10.77.0.9', array(), true, 'its private address from the server\'s network' ),
		array( '10.77.0.9', array( 'HTTP_X_FORWARDED_FOR' => VISITOR ), false, 'its private address passing a visitor on' ),
		array( VISITOR, array(), false, 'another address' ),
	) as $case
) {
	as_request( $case[0], '', $case[1] );
	$ip = PNCP_Precheck_Runtime::client_ip( $c, $reliable );
	t( 'I SCRAPELOCK_SERVER_IPS pre-cache check: ' . $case[3] . ( $case[2] ? ': the server' : ': not the server' ), $case[2] === PNCP_Precheck_Runtime::is_server_request( $c, $ip, $reliable ), $ip );
}
// A change of the constant reaches the stored fingerprint (and so the pre-cache check) on the next wp-admin page.
update_option( PNCP_Server_Ips::OPTION, array_merge( PNCP_Server_Ips::stored(), array( 'time' => time(), 'host' => implode( ',', PNCP_Server_Ips::own_hosts() ), 'const' => 'old' ) ) );
PNCP_Server_Ips::maybe_refresh();
t( 'I SCRAPELOCK_SERVER_IPS: a change is picked up by the next wp-admin page', md5( implode( ',', PNCP_Server_Ips::const_ips() ) ) === PNCP_Server_Ips::stored()['const'] );
// Over HTTP (the mu-plugin defines it in the web server's requests).
settings( array( 'early_mode' => 1 ) );
PNCP_Early::sync();
sleep( 2 ); // OPcache of the server: the new mu-plugins.
list( $code ) = req( '/', array( 'X-Test-Remote-Addr' => '192.0.2.6' ) );
t( 'I SCRAPELOCK_SERVER_IPS HTTP: no User-Agent from its range: 200 (early check and WordPress)', 200 === $code, (string) $code );
list( $code ) = req( '/', array( 'X-Test-Remote-Addr' => VISITOR ) );
t( 'I SCRAPELOCK_SERVER_IPS HTTP: no User-Agent from another address: 403', 403 === $code, (string) $code );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();
@unlink( $const_mu );

/* ---------- E. ScrapeLock's own rules at the CDN never block the server ---------- */
test_lists();
forget_server_ips();
set_transient( PNCP_Server_Ips::OUTBOUND, array( SERVER => time() ), DAY_IN_SECONDS ); // Detected (see I).
// Temporary blocks sent to the CDN (PNCP_Edge): a ban of the server's address is never one of them.
update_option( PNCP_Edge::CONFIG, array( 'provider' => 'bunny', 'zone' => '4242', 'token' => 'f1-test-bunny-key-1234567890' ), false );
delete_option( PNCP_Edge::STAFF );
settings( array( 'edge_send_blocks' => 1 ) );
PNCP_Bunny::reset();
PNCP_Log::ban( SERVER, 30, 'rate_page' );
PNCP_Log::ban( '192.0.2.7', 30, 'rate_page' ); // In SCRAPELOCK_SERVER_IPS (I).
PNCP_Log::ban( '198.51.100.120', 30, 'rate_page' );
PNCP_Log::reset_cache();
$wanted = PNCP_Edge::wanted( 'bunny' );
t( 'E: a banned visitor is sent to the CDN', isset( $wanted['198.51.100.120'] ), wp_json_encode( array_keys( $wanted ) ) );
t( 'E: a ban of the server\'s detected address is never sent to the CDN', ! isset( $wanted[ SERVER ] ), wp_json_encode( array_keys( $wanted ) ) );
t( 'E: nor one of SCRAPELOCK_SERVER_IPS', ! isset( $wanted['192.0.2.7'] ), wp_json_encode( array_keys( $wanted ) ) );
t( 'E: ... also for Cloudflare', ! isset( PNCP_Edge::wanted( 'cloudflare' )[ SERVER ] ) );
foreach ( array( SERVER, '192.0.2.7', '198.51.100.120' ) as $pncp_ip ) {
	PNCP_Log::unban( $pncp_ip );
}
delete_option( PNCP_Edge::CONFIG );
PNCP_Bunny::reset();

// Bunny's logs: the server's requests through Bunny are never counted (too fast, 4xx floods).
$new = new ReflectionMethod( 'PNCP_Bunny', 'new_analysis' );
$new->setAccessible( true );
$a = $new->invoke( null );
foreach ( array( SERVER, '198.51.100.121' ) as $pncp_ip ) {
	PNCP_Bunny::analyse(
		$a,
		array(
			'ip'     => $pncp_ip,
			'status' => 404,
			'ts'     => time() * 1000,
			'url'    => home_url( '/wp-config-sample.php' ),
			'path'   => '/wp-config-sample.php',
			'ua'     => 'WordPress/6.9',
			'cache'  => 'MISS',
		)
	);
}
t( 'E: Bunny log lines of the server are skipped (no flood, no "too fast", no ban)', 1 === (int) $a['skipped'] && ! isset( $a['errors'][ SERVER ] ) && isset( $a['errors']['198.51.100.121'] ), wp_json_encode( array( $a['skipped'], array_keys( (array) $a['errors'] ) ) ) );

// The wp-login.php lock at Bunny lets the server's addresses through, within Bunny's 5 entries per condition.
$bn_rules = array();
$bn_mock  = static function ( $pre, $args, $url ) use ( &$bn_rules ) {
	$api = PNCP_Bunny::base( 'api' ) . '/pullzone/4243';
	if ( 0 !== strpos( $url, $api ) ) {
		return $pre;
	}
	$reply  = static function ( $code, $data ) {
		return array( 'headers' => array( 'content-type' => 'application/json' ), 'body' => null === $data ? '' : wp_json_encode( $data ), 'response' => array( 'code' => $code, 'message' => '' ), 'cookies' => array(), 'filename' => null );
	};
	$method = isset( $args['method'] ) ? $args['method'] : 'GET';
	if ( 'POST' === $method && false !== strpos( $url, '/edgerules/addOrUpdate' ) ) {
		$body                   = json_decode( (string) $args['body'], true );
		$guid                   = isset( $body['Guid'] ) ? $body['Guid'] : wp_generate_uuid4();
		$body['Guid']           = $guid;
		$bn_rules[ $guid ]      = $body;
		return $reply( 200, array( 'Guid' => $guid ) );
	}
	if ( 'DELETE' === $method ) {
		unset( $bn_rules[ substr( (string) $url, strrpos( (string) $url, '/' ) + 1 ) ] );
		return $reply( 204, null );
	}
	return $reply( 200, array( 'EdgeRules' => array_values( $bn_rules ), 'BlockedIps' => array() ) );
};
add_filter( 'pre_http_request', $bn_mock, 5, 3 );
add_filter(
	'pncp_bunny_call_budget',
	static function () {
		return 100000;
	}
);
delete_option( PNCP_Bunny::RULES );
delete_option( PNCP_Bunny::LOGIN_STRICT );
update_option( PNCP_Bunny::CONFIG, array( 'zone' => '4243', 'token' => 'f1-test-bunny-key-1234567890' ), false );
settings( array( 'bunny_login_allow' => '198.51.100.30' ) );
PNCP_Bunny::reset();
wp_set_current_user( 1 );
as_request( '198.51.100.30', SELF_UA ); // The administrator who locks, from a listed IP.
$locked = PNCP_Bunny::lock_preset( 'login' );
t( 'E: wp-login.php locked at the (stand-in) Bunny', true === $locked, is_wp_error( $locked ) ? $locked->get_error_message() : '' );
$blocks = static function ( $url, $ip ) use ( &$bn_rules ) {
	foreach ( $bn_rules as $rule ) {
		$results = array();
		foreach ( $rule['Triggers'] as $tr ) {
			$any = false;
			foreach ( $tr['PatternMatches'] as $pattern ) {
				$any = $any || ( PNCP_Bunny::TRIGGER_IP === (int) $tr['Type'] ? PNCP_Ip::in_any( $ip, array( $pattern ) ) : 1 === preg_match( '#^' . str_replace( '\*', '.*', preg_quote( $pattern, '#' ) ) . '$#i', $url ) );
			}
			$results[] = 2 === (int) $tr['PatternMatchingType'] ? ! $any : $any;
		}
		$m  = (int) $rule['TriggerMatchingType'];
		$on = 0 === $m ? in_array( true, $results, true ) : ( 1 === $m ? ! in_array( false, $results, true ) : ! in_array( true, $results, true ) );
		if ( $on && ! empty( $rule['Enabled'] ) ) {
			return true;
		}
	}
	return false;
};
$login = home_url( '/wp-login.php' );
t( 'E: the login rule refuses a visitor', $blocks( $login, VISITOR ) );
t( 'E: ... lets the listed administrator in', ! $blocks( $login, '198.51.100.30' ) );
t( 'E: ... and the server\'s own addresses (detected, SCRAPELOCK_SERVER_IPS)', ! $blocks( $login, SERVER ) && ! $blocks( $login, '192.0.2.9' ), wp_json_encode( array_values( $bn_rules ) ) );
$sent = get_option( PNCP_Bunny::RULES )['preset_login']['allow'];
t( 'E: the server\'s addresses come after the listed ones', array( '198.51.100.30' ) === array_slice( $sent, 0, 1 ) && in_array( SERVER, $sent, true ), wp_json_encode( $sent ) );
t( 'E: the out-of-date notice sees the rule as current', get_option( PNCP_Bunny::RULES )['preset_login']['allow'] === PNCP_Bunny::login_rule_allow(), wp_json_encode( PNCP_Bunny::login_rule_allow() ) );
$every = true;
foreach ( $bn_rules as $rule ) {
	foreach ( $rule['Triggers'] as $tr ) {
		$every = $every && count( $tr['PatternMatches'] ) <= 5;
	}
	$every = $every && count( $rule['Triggers'] ) <= 5;
}
t( 'E: at most 5 entries in a condition and 5 conditions in a rule', $every );
// A full list: the listed IPs keep every place, and the rule still fits.
$full = array();
for ( $i = 1; $i <= PNCP_Bunny::login_allow_max(); $i++ ) {
	$full[] = '198.51.100.' . ( 29 + $i );
}
settings( array( 'bunny_login_allow' => implode( "\n", $full ) ) );
PNCP_Bunny::reset();
$with = PNCP_Bunny::login_rule_allow();
t( 'E: with a full list the listed IPs keep every place (no server address then)', $full === $with, wp_json_encode( $with ) );
t( 'E: ... and the rule still fits Bunny\'s limits', ! is_wp_error( PNCP_Bunny::plan( array( 'patterns' => array( '*/wp-login.php*' ), 'allow' => $with, 'except' => array( '*action=postpass*' ) ) ) ) );
// The next run (sync_rules()) keeps the rule on only for people, not for the server's addresses alone: a rule
// locked before 3.9 follows the administrators' IPs, and none is left.
wp_set_current_user( 0 );
delete_option( PNCP_Bunny::LOGIN_STRICT );
delete_option( PNCP_Edge::STAFF );
settings( array( 'bunny_login_allow' => '' ) );
PNCP_Bunny::reset();
$rules                          = get_option( PNCP_Bunny::RULES );
$rules['preset_login']['allow'] = array( SERVER );
update_option( PNCP_Bunny::RULES, $rules, false );
PNCP_Bunny::sync_rules( null, microtime( true ) + 8 );
$rules = get_option( PNCP_Bunny::RULES );
t( 'E: only server addresses left in the list: the rule is switched off at the next run (never the server alone)', empty( $rules['preset_login']['enabled'] ), wp_json_encode( $rules['preset_login'] ) );
remove_filter( 'pre_http_request', $bn_mock, 5 );
delete_option( PNCP_Bunny::RULES );
delete_option( PNCP_Bunny::CONFIG );
delete_option( PNCP_Bunny::LOGIN_STRICT );
settings( array( 'bunny_login_allow' => '', 'edge_send_blocks' => 0 ) );
PNCP_Bunny::reset();
wp_set_current_user( 0 );
forget_server_ips();

/* ---------- H. Vulnerable points "Check again", the Stealth test, Site Health: through the "edge" ---------- */
test_lists();
forget_server_ips();
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
t( 'H: the site\'s checks taught the server\'s outbound address (X-Forwarded-For the edge wrote)', in_array( SERVER, PNCP_Server_Ips::outbound_ips(), true ), wp_json_encode( get_transient( PNCP_Server_Ips::OUTBOUND ) ) );
t( 'H: the REST API through the edge: 200', 200 === (int) wp_remote_retrieve_response_code( $rest ), is_wp_error( $rest ) ? $rest->get_error_message() : (string) wp_remote_retrieve_response_code( $rest ) );
remove_filter( 'http_request_args', $to_edge, 20 );

echo $fails ? "\n$fails FAILED\n" : "\nALL PASSED\n";
exit( $fails ? 1 : 0 );
