<?php
/**
 * ScrapeLock 3.11 — the request pipeline (PNCP_Bots, the early check, the pre-cache check) in real WordPress,
 * from 7 days of logs of a live site behind Bunny CDN, Nginx and WP Rocket:
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_311_pipeline.php
 *
 * A1. The site's request to itself through the CDN (visitor IP = the server's public address): never checked;
 *     the same User-Agent from another address is checked as before (never by the User-Agent alone).
 * A2. WP Rocket's "WP-Rocket-SaaS" without browser headers while WP Rocket is active: passes in WordPress, the
 *     early check and the pre-cache check (stored list of the plugin bots for the checks before plugins load).
 * A3. /.well-known/* without browser headers / User-Agent, Google's and Apple's fetchers.
 * A4. Static files (images, video, fonts, css, js) that reach PHP do not count as pages.
 *
 * The pre-cache check is tested over HTTP with a stand-in page cache (WP_CACHE + advanced-cache.php serving
 * /cached-page/ before plugins load), as t_precheck.php does; wp-config.php and advanced-cache.php are put back
 * at the end. Only on a test WordPress.
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

/** Waits for the next minute when fewer than 20 seconds are left (the counters are per minute). */
function same_minute() {
	$left = 60 - time() % 60;
	if ( $left < 20 ) {
		sleep( $left + 1 );
	}
}

/** The $_SERVER of a request (every browser header removed first). */
function as_request( $remote, $ua, $headers = array(), $uri = '/' ) {
	foreach ( array_keys( $_SERVER ) as $k ) {
		if ( 0 === strpos( $k, 'HTTP_' ) ) {
			unset( $_SERVER[ $k ] );
		}
	}
	$_SERVER['REMOTE_ADDR']    = $remote;
	$_SERVER['REQUEST_METHOD'] = 'GET';
	$_SERVER['REQUEST_URI']    = $uri;
	if ( '' !== $ua ) {
		$_SERVER['HTTP_USER_AGENT'] = $ua;
	}
	foreach ( $headers as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
}

/** check() for a page, without counting (unless asked). */
function verdict( $count = false, $context = 'page' ) {
	$v = PNCP_Bots::check( $context, $count );
	return is_array( $v ) ? $v['code'] . ' ' . $v['reason'] : 'pass';
}

/** An HTTP request: [code, headers (lowercase), body]. */
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
			CURLOPT_NOBODY         => 'HEAD' === $method,
			CURLOPT_TIMEOUT        => 60,
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
}

/** Codes of $n requests. */
function codes( $path, $headers, $n ) {
	$out = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$out[] = req( $path, $headers )[0];
	}
	return $out;
}

/** A visitor through the "CDN": REMOTE_ADDR 127.0.0.1 (trusted for X-Real-IP), the visitor in X-Real-IP / X-Test-IP. */
function via_cdn( $ip, $ua, $extra = array() ) {
	$h = array(
		'X-Real-IP' => $ip,
		'X-Test-IP' => $ip,
	);
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
$saved_self  = get_option( PNCP_Server_Ips::OPTION, null );
$server_old  = isset( $_SERVER['SERVER_ADDR'] ) ? $_SERVER['SERVER_ADDR'] : null;
$plugin_dir  = WP_PLUGIN_DIR . '/wp-rocket';
$created     = ! is_dir( $plugin_dir );
$was_active  = is_plugin_active( 'wp-rocket/wp-rocket.php' );
register_shutdown_function(
	static function () use ( $config_file, $original, $cache_file, $had_cache, $saved, $saved_self, $plugin_dir, $created, $was_active ) {
		if ( ! $was_active ) {
			deactivate_plugins( 'wp-rocket/wp-rocket.php', true );
		}
		if ( $created ) {
			@unlink( $plugin_dir . '/wp-rocket.php' );
			@rmdir( $plugin_dir );
		}
		file_put_contents( $config_file, $original );
		if ( null === $had_cache ) {
			@unlink( $cache_file );
		} else {
			file_put_contents( $cache_file, $had_cache );
		}
		update_option( PNCP_OPTION, $saved );
		PNCP_Options::flush();
		if ( null === $saved_self ) {
			delete_option( PNCP_Server_Ips::OPTION );
		} else {
			update_option( PNCP_Server_Ips::OPTION, $saved_self );
		}
		PNCP_Early::sync();
		PNCP_Precheck::sync();
		PNCP_Log::unban_all();
	}
);

update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
PNCP_Log::unban_all();
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
		'probe_ban'               => 0,
		'rate_limit'              => 0,
		'rate_limit_search'       => 0,
		'rate_limit_404'          => 0,
		'rate_limit_unverified'   => 0,
		'rate_limit_datacenter'   => 0,
		'rate_limit_apionly'      => 0,
		'rate_limit_lowrep'       => 0,
		'human_check'             => 0,
		'ban_strikes'             => 0,
		'block_ips'               => '',
		'allow_ips'               => '',
		'trust_any_proxy'         => 0,
		'trusted_proxies'         => '',
		'ip_header'               => 'x_real_ip',
		'countries_block'         => '',
		'countries_strict'        => '',
		'auto_emergency'          => 0,
		'early_mode'              => 0,
		'precheck'                => 0,
		'block_ip_host'           => 0,
	)
);

$server_ip = '203.0.113.10'; // The server's public address (what Bunny sends back as the visitor IP).
$other_ip  = '198.51.100.71';
$wp_ua     = 'WordPress/6.8.1; ' . home_url( '/' );

/* ---------- A1. The site's request to itself through the CDN ---------- */
delete_option( PNCP_Server_Ips::OPTION );
$_SERVER['SERVER_ADDR'] = '10.0.0.5'; // NAT: the server's own interface has a private address.
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $server_ip ) );
t( 'A1 before: the server\'s public address is not known -> 403 no_browser (the bug)', '403 no_browser' === verdict(), verdict() );

// The lookup: the site's name and the server's name; CDN addresses (here a Cloudflare one) are left out.
$dns = static function ( $pre, $name ) use ( $server_ip ) {
	return array( $server_ip, '104.16.0.1', '2a01:4f8:10::10', 'not an ip' );
};
add_filter( 'pncp_server_dns', $dns, 10, 2 );
$found = PNCP_Server_Ips::refresh();
remove_filter( 'pncp_server_dns', $dns, 10 );
t( 'A1 refresh(): the resolved addresses are stored (IPv4 and IPv6)', in_array( $server_ip, $found, true ) && in_array( '2a01:4f8:10::10', $found, true ), wp_json_encode( $found ) );
t( 'A1 refresh(): a CDN address (Cloudflare) is never one of the server\'s', ! in_array( '104.16.0.1', PNCP_Server_Ips::stored_ips(), true ), wp_json_encode( PNCP_Server_Ips::stored_ips() ) );
$stored = get_option( PNCP_Server_Ips::OPTION );
t( 'A1 refresh(): stored with the time and the host names', is_array( $stored ) && (int) $stored['time'] > time() - 60 && false !== strpos( $stored['host'], (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) );

as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $server_ip ) );
t( 'A1: WordPress/6.x from the server\'s public address (through the CDN), no browser headers: passes', 'pass' === verdict(), verdict() );
as_request( '127.0.0.1', '', array( 'HTTP_X_REAL_IP' => $server_ip ) );
t( 'A1: no User-Agent at all from the server: passes (empty UA)', 'pass' === verdict(), verdict() );
as_request( '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36', array( 'HTTP_X_REAL_IP' => $server_ip, 'HTTP_SEC_CH_UA' => '"HeadlessChrome";v="120"' ) );
t( 'A1: headless browser from the server (a site health screenshot tool): passes', 'pass' === verdict(), verdict() );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => '2a01:4f8:10::10' ) );
t( 'A1: the server\'s IPv6 address: passes', 'pass' === verdict(), verdict() );
settings( array( 'countries_block' => 'ZZ', 'rate_limit' => 1 ) );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $server_ip ) );
$v = array( verdict( true ), verdict( true ), verdict( true ) );
t( 'A1: never limited (page limit 1, three requests)', array( 'pass', 'pass', 'pass' ) === $v, implode( ',', $v ) );
settings( array( 'countries_block' => '', 'rate_limit' => 0 ) );

as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $other_ip ) );
t( 'A1: the same WordPress User-Agent from another address: 403 no_browser as before (never by User-Agent)', '403 no_browser' === verdict(), verdict() );
as_request( '127.0.0.1', '', array( 'HTTP_X_REAL_IP' => $other_ip ) );
t( 'A1: no User-Agent from another address: 403 empty_ua as before', '403 empty_ua' === verdict(), verdict() );

// The address must come from the trusted proxy: the header from anyone else is ignored.
as_request( $other_ip, $wp_ua, array( 'HTTP_X_REAL_IP' => $server_ip ) );
t( 'A1: X-Real-IP = the server from an untrusted client: ignored, 403', '403 no_browser' === verdict(), verdict() );
// "Trust every proxy": the address may be forged.
settings( array( 'trust_any_proxy' => 1 ) );
as_request( $other_ip, $wp_ua, array( 'HTTP_X_REAL_IP' => $server_ip ) );
t( 'A1: with "trust every proxy" (spoofable address): not exempt', '403 no_browser' === verdict(), verdict() );
settings( array( 'trust_any_proxy' => 0 ) );
// A loopback "visitor" that came from far away (public hop) stays forged, as in 3.6.
settings( array( 'ip_header' => 'x_forwarded_for', 'trusted_proxies' => '198.51.100.0/24' ) );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 198.51.100.9' ) );
t( 'A1: 127.0.0.1 forwarded by an outside proxy: still checked', '403 no_browser' === verdict(), verdict() );
settings( array( 'ip_header' => 'x_real_ip', 'trusted_proxies' => '' ) );

// SERVER_ADDR itself, when it is a public address.
delete_option( PNCP_Server_Ips::OPTION );
$_SERVER['SERVER_ADDR'] = $server_ip;
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $server_ip ) );
t( 'A1: SERVER_ADDR as the visitor IP (through the CDN): passes', 'pass' === verdict(), verdict() );
$_SERVER['SERVER_ADDR'] = '10.0.0.5';

// The filter.
$extra = static function ( $ips ) {
	$ips[] = '192.0.2.0/28';
	$ips[] = '0.0.0.0/0'; // Too wide: ignored.
	return $ips;
};
add_filter( 'pncp_server_ips', $extra );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => '192.0.2.5' ) );
t( 'A1: filter pncp_server_ips adds a range', 'pass' === verdict(), verdict() );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $other_ip ) );
t( 'A1: a range wider than /8 from the filter is ignored', '403 no_browser' === verdict(), verdict() );
remove_filter( 'pncp_server_ips', $extra );

// Learned: the site signs its requests to its own address; the address a signed request comes from is kept.
$args = PNCP_Server_Ips::sign( array( 'headers' => array() ), home_url( '/' ) );
t( 'A1: requests to the site\'s own address are signed', isset( $args['headers'][ PNCP_Server_Ips::HEADER ] ) && preg_match( '/^\d+\.[0-9a-f]{40}$/', $args['headers'][ PNCP_Server_Ips::HEADER ] ) );
$other = PNCP_Server_Ips::sign( array( 'headers' => array() ), 'https://example.com/' );
t( 'A1: requests to other sites are not signed', ! isset( $other['headers'][ PNCP_Server_Ips::HEADER ] ) );
$token = $args['headers'][ PNCP_Server_Ips::HEADER ];
$learn = '203.0.113.12';
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $learn, 'HTTP_X_SCRAPELOCK_SELF' => 'x' . $token ) );
t( 'A1: a wrong signature teaches nothing (403)', '403 no_browser' === verdict() && ! in_array( $learn, PNCP_Server_Ips::stored_ips(), true ), verdict() );
list( $time, $mac ) = explode( '.', $token );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $learn, 'HTTP_X_SCRAPELOCK_SELF' => ( (int) $time - 3600 ) . '.' . $mac ) );
t( 'A1: an old signature (an hour) teaches nothing', '403 no_browser' === verdict(), verdict() );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $learn, 'HTTP_X_SCRAPELOCK_SELF' => $token ) );
t( 'A1: a signed request of the site passes and its address is learned', 'pass' === verdict() && in_array( $learn, PNCP_Server_Ips::stored_ips(), true ), verdict() );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => $learn ) );
t( 'A1: then the learned address passes without the signature', 'pass' === verdict(), verdict() );
as_request( '127.0.0.1', $wp_ua, array( 'HTTP_X_REAL_IP' => '104.16.0.9', 'HTTP_X_SCRAPELOCK_SELF' => $token ) );
t( 'A1: a CDN address is never learned', ! in_array( '104.16.0.9', PNCP_Server_Ips::stored_ips(), true ) );
$c = PNCP_Precheck::config();
t( 'A1: the pre-cache check\'s configuration carries the server addresses', isset( $c['self_ips'][0][ $learn ] ), wp_json_encode( $c['self_ips'] ) );

// Early check (unit).
settings( array( 'early_mode' => 1 ) );
as_request( '127.0.0.1', '', array( 'HTTP_X_REAL_IP' => $learn ) );
t( 'A1 early check: no User-Agent from the server: passes', null === PNCP_Early::check(), wp_json_encode( PNCP_Early::check() ) );
as_request( '127.0.0.1', '', array( 'HTTP_X_REAL_IP' => $other_ip ) );
$e = PNCP_Early::check();
t( 'A1 early check: no User-Agent from another address: 403 empty_ua', is_array( $e ) && 'empty_ua' === $e[1], wp_json_encode( $e ) );

// Over HTTP: WordPress and the early check (X-Test-IP is the visitor; the harness gives the address).
PNCP_Early::sync();
update_option( PNCP_Server_Ips::OPTION, array( 'ips' => array( $server_ip ), 'host' => '', 'time' => time(), 'learned' => array() ) );
list( $code, $h ) = req( '/', via_cdn( $server_ip, $wp_ua ) );
t( 'A1 HTTP: WordPress/6.x from the server\'s address, no browser headers: 200', 200 === $code, (string) $code );
list( $code, $h ) = req( '/', via_cdn( $server_ip, '' ) );
t( 'A1 HTTP: no User-Agent from the server\'s address: 200 (early check and WordPress)', 200 === $code, (string) $code );
list( $code, $h ) = req( '/', via_cdn( $other_ip, $wp_ua ) );
t( 'A1 HTTP: the same User-Agent from another address: 403', 403 === $code, (string) $code );
list( $code, $h ) = req( '/', via_cdn( $other_ip, '' ) );
t( 'A1 HTTP: no User-Agent from another address: 403 in the early check (before plugins)', 403 === $code && false === strpos( $h, 'x-test-muplugins-loaded' ), $code . ' ' . $h );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();

/* ---------- A2. WP Rocket's SaaS while WP Rocket is active ---------- */
$saas = 'Mozilla/5.0 (compatible; WP-Rocket-SaaS/1.0; +https://wp-rocket.me/bot/)';
if ( $created ) {
	mkdir( $plugin_dir );
	file_put_contents( $plugin_dir . '/wp-rocket.php', "<?php\n/*\nPlugin Name: WP Rocket (test stand-in)\nVersion: 0.0.1\n*/\n" );
}
deactivate_plugins( 'wp-rocket/wp-rocket.php', true );
PNCP_Plugin_Bots::reset();
as_request( '127.0.0.1', $saas, array( 'HTTP_X_REAL_IP' => $other_ip ) );
t( 'A2: WP Rocket inactive: the SaaS without Accept-Language gets 403 no_browser, as before', '403 no_browser' === verdict(), verdict() );
activate_plugin( 'wp-rocket/wp-rocket.php', '', false, false ); // Not silent: the hooks run, as in wp-admin.
PNCP_Plugin_Bots::reset();
$stored = get_option( PNCP_Plugin_Bots::AGENTS_OPTION );
t( 'A2: activating WP Rocket stores its bots for the checks before plugins load', is_array( $stored ) && in_array( 'wp-rocket-saas', wp_list_pluck( $stored, 'ua' ), true ), wp_json_encode( $stored ) );
as_request( '127.0.0.1', $saas, array( 'HTTP_X_REAL_IP' => $other_ip ) );
t( 'A2: WP Rocket active: that exact User-Agent without Accept-Language passes (WordPress)', 'pass' === verdict(), verdict() );
as_request( '127.0.0.1', $saas, array( 'HTTP_X_REAL_IP' => $other_ip, 'HTTP_ACCEPT_LANGUAGE' => 'en' ) );
t( 'A2: ... and with browser headers too', 'pass' === verdict(), verdict() );
// A bot list line that matches it: the allowance comes first, in WordPress and in the early check.
settings( array( 'bot_list' => $saved['bot_list'] . "\nwp-rocket.me/bot", 'early_mode' => 1 ) );
as_request( '127.0.0.1', $saas, array( 'HTTP_X_REAL_IP' => $other_ip ) );
t( 'A2: a bot list line "wp-rocket.me/bot" does not refuse it (WordPress)', 'pass' === verdict(), verdict() );
t( 'A2: ... nor the early check', null === PNCP_Early::check(), wp_json_encode( PNCP_Early::check() ) );
// A bot added by another plugin's filter is not known to the early check's registry (plugins load later): the
// stored list has it.
$filter = static function ( $known ) {
	$known['acme'] = array(
		'name'    => 'Acme',
		'plugins' => array( 'wp-rocket/wp-rocket.php' ),
		'agents'  => array( 'AcmeServiceBot' ),
	);
	return $known;
};
settings( array( 'bot_list' => $saved['bot_list'] . "\nAcmeServiceBot" ) );
add_filter( 'pncp_plugin_bots', $filter );
PNCP_Plugin_Bots::store();
remove_filter( 'pncp_plugin_bots', $filter );
PNCP_Plugin_Bots::reset();
as_request( '127.0.0.1', 'AcmeServiceBot/2.0', array( 'HTTP_X_REAL_IP' => $other_ip ) );
t( 'A2 early check: a plugin bot from another plugin\'s filter (stored list) passes before plugins load', null === PNCP_Early::check(), wp_json_encode( PNCP_Early::check() ) );
deactivate_plugins( 'wp-rocket/wp-rocket.php', false );
PNCP_Plugin_Bots::reset();
as_request( '127.0.0.1', 'AcmeServiceBot/2.0', array( 'HTTP_X_REAL_IP' => $other_ip ) );
$e = PNCP_Early::check();
t( 'A2 early check: ... and no longer once its plugin is inactive (403 bot_ua)', is_array( $e ) && 'bot_ua' === $e[1], wp_json_encode( $e ) );
t( 'A2: deactivating the plugin updates the stored list', ! in_array( 'wp-rocket-saas', wp_list_pluck( (array) get_option( PNCP_Plugin_Bots::AGENTS_OPTION ), 'ua' ), true ) );
activate_plugin( 'wp-rocket/wp-rocket.php', '', false, false ); // Not silent: the hooks run, as in wp-admin.
PNCP_Plugin_Bots::reset();
settings( array( 'bot_list' => $saved['bot_list'] . "\nwp-rocket.me/bot" ) );
PNCP_Early::sync();
list( $code, $h ) = req( '/', via_cdn( $other_ip, $saas ) );
t( 'A2 HTTP: the SaaS, no Accept-Language, bot list line, WP Rocket active: 200 (early check and WordPress)', 200 === $code, (string) $code );
list( $code, $h ) = req( '/', via_cdn( $other_ip, 'Mozilla/5.0 (compatible; SomeBot/1.0; +https://wp-rocket.me/bot/)' ) );
t( 'A2 HTTP: another User-Agent with the same bot list line: 403 in the early check', 403 === $code && false === strpos( $h, 'x-test-muplugins-loaded' ), $code . ' ' . $h );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();

/* ---------- The pre-cache check (stand-in page cache) ---------- */
file_put_contents( $config_file, "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) );
file_put_contents( $cache_file, "<?php\nif ( isset( \$_SERVER['REQUEST_URI'] ) && 0 === strpos( \$_SERVER['REQUEST_URI'], '/cached-page/' ) ) {\n\theader( 'X-Test-Cache: HIT' );\n\techo 'CACHED PAGE';\n\texit;\n}\n" );
settings( array( 'precheck' => 1, 'rate_limit' => 3 ) );
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
WP_Screen::get( 'settings_page_scrapelock' )->set_current_screen();
PNCP_Precheck::sync();
sleep( 3 ); // OPcache: the new wp-config.php.
t( 'pre-cache check active', PNCP_Precheck::active(), (string) get_option( PNCP_Precheck::STATUS ) );

same_minute();
$c = codes( '/cached-page/', via_cdn( $server_ip, $wp_ua ), 6 );
t( 'A1 pre-cache: the server\'s address is never limited (6 cached pages, limit 3)', array_fill( 0, 6, 200 ) === $c, implode( ',', $c ) );
list( $code ) = req( '/cached-page/', via_cdn( $server_ip, '' ) );
t( 'A1 pre-cache: no User-Agent from the server\'s address: 200', 200 === $code, (string) $code );
$c = codes( '/cached-page/', via_cdn( '198.51.100.72', $wp_ua ), 5 );
t( 'A1 pre-cache: the same User-Agent from another address is limited as before', in_array( 429, $c, true ), implode( ',', $c ) );
list( $code ) = req( '/cached-page/', via_cdn( '198.51.100.73', '' ) );
t( 'A1 pre-cache: no User-Agent from another address: 403', 403 === $code, (string) $code );

// A2: the SaaS on cached pages: the bot list line and the human check's stricter limit do not apply to it.
settings( array( 'human_check' => 1, 'rate_limit_unverified' => 1, 'rate_limit' => 20 ) );
PNCP_Precheck::sync();
sleep( 3 );
same_minute();
$c = codes( '/cached-page/', via_cdn( '198.51.100.74', $saas ), 4 );
t( 'A2 pre-cache: WP-Rocket-SaaS, no Accept-Language, bot list line, human check limit 1: all 200', array_fill( 0, 4, 200 ) === $c, implode( ',', $c ) );
$c = codes( '/cached-page/', via_cdn( '198.51.100.75', 'Mozilla/5.0 (compatible; SomeBot/1.0; +https://wp-rocket.me/bot/)' ), 1 );
t( 'A2 pre-cache: another User-Agent with the bot list line: 403', array( 403 ) === $c, implode( ',', $c ) );
deactivate_plugins( 'wp-rocket/wp-rocket.php', false ); // Rewrites the pre-cache check's configuration.
sleep( 3 );
$c = codes( '/cached-page/', via_cdn( '198.51.100.76', $saas ), 1 );
t( 'A2 pre-cache: WP Rocket deactivated: the SaaS is refused by the bot list line again', array( 403 ) === $c, implode( ',', $c ) );
settings( array( 'human_check' => 0, 'rate_limit_unverified' => 0, 'rate_limit' => 3, 'bot_list' => $saved['bot_list'] ) );
PNCP_Precheck::sync();
sleep( 3 );

if ( null === $server_old ) {
	unset( $_SERVER['SERVER_ADDR'] );
} else {
	$_SERVER['SERVER_ADDR'] = $server_old;
}

echo $fails ? "\n$fails FAIL\n" : "\nall PASS\n";
exit( $fails ? 1 : 0 );
