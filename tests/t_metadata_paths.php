<?php
/**
 * ScrapeLock 3.10 — site files read by services ("No browser headers" false positives) and the official lists of
 * Google's other fetchers, Applebot and DuckDuckBot. Lists are stored by the test (no network).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_metadata_paths.php
 *
 * Needs the plugin active and tests/lib/mu-test-harness.php in mu-plugins (X-Test-IP, X-Test-RDNS).
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

function req( $path, $headers = array(), $method = 'GET' ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => $h,
		CURLOPT_CUSTOMREQUEST  => $method,
		CURLOPT_TIMEOUT        => 30,
	);
	if ( 'HEAD' === $method ) {
		$opts[ CURLOPT_NOBODY ] = true;
	}
	curl_setopt_array( $ch, $opts );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return $code;
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
}

function fresh() {
	global $wpdb;
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_%pncp\_%' OR option_name LIKE '\_transient\_timeout\_%pncp\_%'" );
	PNCP_Log::unban_all();
	PNCP_Log::clear();
	wp_cache_flush();
	PNCP_Log::reset_cache();
}

$saved_settings = PNCP_Options::stored();
$saved_lists    = array();
foreach ( array( 'google', 'apple', 'duckduckgo' ) as $pncp_l ) {
	$saved_lists[ $pncp_l ] = get_option( 'pncp_ip_lists_' . $pncp_l, null );
}

update_option( 'pncp_emergency_until', 0 );
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'ip_header'               => 'remote_addr',
		'trust_any_proxy'         => 0,
		'allow_ips'               => '',
		'block_ips'               => '',
		'rate_limit'              => 0,
		'rate_limit_404'          => 0,
		'rate_limit_unverified'   => 0,
		'human_check'             => 0,
		'require_browser_headers' => 1,
		'block_headless'          => 0,
		'block_bots'              => 1,
		'block_empty_ua'          => 1,
		'block_fake_crawlers'     => 1,
		'ban_strikes'             => 0,
	)
);
fresh();

// Test copies of the official lists (documentation addresses, never real ones).
PNCP_Ip::store_list( 'google', array( '66.249.64.0/27', '192.178.5.0/27' ) );
PNCP_Ip::store_list( 'apple', array( '17.241.208.0/24' ) );
PNCP_Ip::store_list( 'duckduckgo', array( '20.191.45.212', '40.88.21.235' ) );

$post = get_posts( array( 'numberposts' => 1, 'post_type' => 'post' ) );
$page = $post ? wp_parse_url( get_permalink( $post[0] ), PHP_URL_PATH ) : '/';

/* ---------- Unit: the path matcher ---------- */
$yes = array( '/.well-known/assetlinks.json', '/.well-known/traffic-advice', '/.well-known/passkey-endpoints', '/.well-known/apple-app-site-association', '/favicon.ico', '/favicon-32x32.png', '/favicon.svg', '/apple-touch-icon.png', '/apple-touch-icon-precomposed.png', '/apple-touch-icon-120x120-precomposed.png', '/site.webmanifest', '/manifest.json', '/ads.txt', '/robots.txt', '/sellers.json', '/.well-known/acme-challenge/abc_DEF-1', '/llms.txt' );
foreach ( $yes as $p ) {
	t( "metadata path: $p", PNCP_Bots::is_metadata_request( $p, 'GET' ) );
}
t( 'metadata path: HEAD counts too', PNCP_Bots::is_metadata_request( '/.well-known/assetlinks.json', 'HEAD' ) );
$no = array(
	'/.well-known/../wp-config.php',
	'/.well-known/..%2fwp-config.php',
	'/.well-known//x',
	'/.well-known/',
	'/.env',
	'/wp-config.php',
	'/apple-touch-icon.php',
	'/favicon.ico/x',
	'/blog/favicon.ico',
	'/apple-touch-icon.png.php',
	'/' . 'shop/',
	'/.git/config',
	'/.well-known/a b',
);
foreach ( $no as $p ) {
	t( "not a metadata path: $p", ! PNCP_Bots::is_metadata_request( $p, 'GET' ) );
}
t( 'not metadata: POST to /.well-known/assetlinks.json', ! PNCP_Bots::is_metadata_request( '/.well-known/assetlinks.json', 'POST' ) );
$pncp_f = static function ( $paths ) {
	$paths['my_app'] = 'my-app\\.json';
	return $paths;
};
add_filter( 'pncp_site_metadata_paths', $pncp_f );
t( 'pncp_site_metadata_paths filter adds a path (one list with the attack record)', PNCP_Bots::is_metadata_request( '/my-app.json', 'GET' ) && PNCP_Paths::is_site_metadata( '/my-app.json' ) );
remove_filter( 'pncp_site_metadata_paths', $pncp_f );
t( 'pncp_site_metadata_paths filter removed again', ! PNCP_Bots::is_metadata_request( '/my-app.json', 'GET' ) );
t( 'one helper: PNCP_Bots::metadata_paths() is gone', ! method_exists( 'PNCP_Bots', 'metadata_paths' ) );

/* ---------- Uninstall removes every downloaded list (the data center lists by prefix) ---------- */
$pncp_un  = (string) file_get_contents( dirname( __DIR__ ) . '/uninstall.php' );
$pncp_mis = array();
foreach ( array_keys( PNCP_Ip::sources() ) as $pncp_name ) {
	if ( 0 !== strpos( $pncp_name, 'dc_' ) && false === strpos( $pncp_un, "'pncp_ip_lists_" . $pncp_name . "'" ) ) {
		$pncp_mis[] = $pncp_name;
	}
}
t( 'uninstall.php deletes every official list (apple, duckduckgo too)', ! $pncp_mis, implode( ',', $pncp_mis ) );

/* ---------- Unit: list parsing (Apple / DuckDuckGo shapes) ---------- */
$apple_json = '{"creationTime":"2025-01-01T00:00:00.000000","prefixes":[{"ipv6Prefix":"2a01:b747:3000:200::/56"},{"ipv4Prefix":"17.241.208.0/24"}]}';
$r          = PNCP_Ip::parse_ranges( $apple_json );
t( 'parse: Applebot JSON (prefixes / ipv4Prefix / ipv6Prefix)', in_array( '17.241.208.0/24', $r, true ) && in_array( '2a01:b747:3000:200::/56', $r, true ), wp_json_encode( $r ) );
$r = PNCP_Ip::parse_ranges( '{"prefixes":[{"ipv4Prefix":"20.191.45.212/32"}]}' );
t( 'parse: DuckDuckBot JSON, Google shape', array( '20.191.45.212/32' ) === $r, wp_json_encode( $r ) );
$r = PNCP_Ip::parse_ranges( '["20.191.45.212","40.88.21.235"]' );
t( 'parse: DuckDuckBot JSON, plain array', array( '20.191.45.212', '40.88.21.235' ) === $r, wp_json_encode( $r ) );
$r = PNCP_Ip::parse_ranges( '{"ips":["20.191.45.212"," 40.88.21.235 "],"meta":{"v6":["2001:db8::1"]},"note":"x"}' );
t( 'parse: DuckDuckBot JSON, other object shape', array( '20.191.45.212', '40.88.21.235', '2001:db8::1' ) === $r, wp_json_encode( $r ) );
$r = PNCP_Ip::parse_ranges( "20.191.45.212\n40.88.21.235\n" );
t( 'parse: DuckDuckBot plain text', array( '20.191.45.212', '40.88.21.235' ) === $r, wp_json_encode( $r ) );
$srcs = PNCP_Ip::sources();
t( 'sources: Applebot and DuckDuckBot official lists', isset( $srcs['apple'], $srcs['duckduckgo'] ) && 'https://search.developer.apple.com/applebot.json' === $srcs['apple'][0] && 'https://duckduckgo.com/duckduckbot.json' === $srcs['duckduckgo'][0] );
t( 'needed lists: apple + duckduckgo while protection is on', ! array_diff( array( 'apple', 'duckduckgo' ), PNCP_Ip::needed_lists() ) );
t( 'official owner: Apple / DuckDuckGo', 'Apple' === PNCP_Ip::official_owner( '17.241.208.9' ) && 'DuckDuckGo' === PNCP_Ip::official_owner( '20.191.45.212' ) );
t( 'is_official_crawler_ip: Apple / DuckDuckGo lists', PNCP_Bots::is_official_crawler_ip( '17.241.208.9' ) && PNCP_Bots::is_official_crawler_ip( '40.88.21.235' ) && ! PNCP_Bots::is_official_crawler_ip( '203.0.113.9' ) );

/* ---------- HTTP: "No browser headers" and the site files ---------- */
$gas   = 'GoogleAssociationService';
$pfp   = 'Chrome Privacy Preserving Prefetch Proxy';
$asa   = 'AuthenticationServicesAgent/1.0 CFNetwork/1568.200.51 Darwin/24.1.0';
$nex   = 'NetworkingExtension/8620.1.16.10.11 Network/4277.42.2 iOS/18.1';
$plain = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36';

// The real case of the report: Google's fetchers from a Google address on any path.
$code = req( '/.well-known/assetlinks.json', array( 'X-Test-IP' => '66.249.64.5', 'User-Agent' => $gas ) );
t( 'GoogleAssociationService from a Google address: not 403', 403 !== $code, (string) $code );
$code = req( '/.well-known/traffic-advice', array( 'X-Test-IP' => '192.178.5.9', 'User-Agent' => $pfp ) );
t( 'Chrome Privacy Preserving Prefetch Proxy from a Google address: not 403', 403 !== $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '66.249.64.5', 'User-Agent' => $gas ) );
t( 'GoogleAssociationService from a Google address, a page: 200', 200 === $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '66.249.64.6', 'User-Agent' => 'Google-Read-Aloud' ) );
t( 'Google-Read-Aloud from a Google address, a page: 200', 200 === $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '66.249.64.7', 'User-Agent' => 'SomeOtherGoogleTool/1.0' ) );
t( 'any User-Agent from a Google address: never the "no browser headers" 403', 200 === $code, (string) $code );
$reasons = $GLOBALS['wpdb']->get_col( "SELECT reason FROM {$GLOBALS['wpdb']->prefix}pncp_log" );
t( 'nothing logged as no_browser for Google addresses', ! in_array( 'no_browser', $reasons, true ), implode( ',', $reasons ) );

// Not from Google: a page still needs browser headers, a site file does not.
$code = req( $page, array( 'X-Test-IP' => '203.0.113.21', 'User-Agent' => $gas ) );
t( 'GoogleAssociationService from elsewhere, a page: 403 as before', 403 === $code, (string) $code );
$code = req( '/.well-known/assetlinks.json', array( 'X-Test-IP' => '203.0.113.21', 'User-Agent' => $gas ) );
t( 'GoogleAssociationService from elsewhere, /.well-known/assetlinks.json: not 403', 403 !== $code, (string) $code );
$code = req( '/.well-known/passkey-endpoints', array( 'X-Test-IP' => '203.0.113.22', 'User-Agent' => $asa ) );
t( 'Apple AuthenticationServicesAgent, /.well-known/passkey-endpoints: not 403', 403 !== $code, (string) $code );
$code = req( '/apple-touch-icon-precomposed.png', array( 'X-Test-IP' => '203.0.113.23', 'User-Agent' => $nex ) );
t( 'iOS NetworkingExtension, apple-touch-icon-precomposed.png: not 403', 403 !== $code, (string) $code );
$code = req( '/apple-touch-icon.png', array( 'X-Test-IP' => '203.0.113.23', 'User-Agent' => $nex ), 'HEAD' );
t( 'iOS NetworkingExtension, HEAD apple-touch-icon.png: not 403', 403 !== $code, (string) $code );
$code = req( '/favicon-32x32.png', array( 'X-Test-IP' => '203.0.113.24', 'User-Agent' => 'SomeFetcher/1.0' ) );
t( 'a favicon file: not 403', 403 !== $code, (string) $code );
$code = req( '/site.webmanifest', array( 'X-Test-IP' => '203.0.113.24', 'User-Agent' => 'SomeFetcher/1.0' ) );
t( 'site.webmanifest: not 403', 403 !== $code, (string) $code );

// Still checked: a POST, a traversal, the bot list, an empty User-Agent, a normal page.
$code = req( '/.well-known/assetlinks.json', array( 'X-Test-IP' => '203.0.113.25', 'User-Agent' => $gas ), 'POST' );
t( 'POST to /.well-known/assetlinks.json: 403 as before', 403 === $code, (string) $code );
$code = req( '/.well-known/x/../../' . ltrim( (string) $page, '/' ), array( 'X-Test-IP' => '203.0.113.25', 'User-Agent' => $gas ) );
t( '/.well-known/ with ../: checked as before (403)', 403 === $code, (string) $code );
$code = req( '/.well-known/%2e%2e/x', array( 'X-Test-IP' => '203.0.113.25', 'User-Agent' => $gas ) );
t( '/.well-known/%2e%2e/: checked as before (403)', 403 === $code, (string) $code );
$code = req( '/.well-known/assetlinks.json', array( 'X-Test-IP' => '203.0.113.26', 'User-Agent' => 'GPTBot/1.0' ) );
t( 'bot list still applies on site files (GPTBot): 403', 403 === $code, (string) $code );
$code = req( '/.well-known/assetlinks.json', array( 'X-Test-IP' => '203.0.113.27', 'User-Agent' => '' ) );
t( 'empty User-Agent still applies on site files: 403', 403 === $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '203.0.113.28', 'User-Agent' => $plain ) );
t( 'a page without Accept-Language: 403 as before', 403 === $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '203.0.113.28', 'User-Agent' => $plain, 'Accept-Language' => 'el' ) );
t( 'a browser: 200', 200 === $code, (string) $code );

// Headless check: skipped on the site files only.
settings( array( 'block_headless' => 1, 'require_browser_headers' => 0 ) );
fresh();
$code = req( '/.well-known/traffic-advice', array( 'X-Test-IP' => '203.0.113.30', 'User-Agent' => $plain, 'Sec-CH-UA' => '"HeadlessChrome";v="141"' ) );
t( 'headless check: skipped on /.well-known/', 403 !== $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '203.0.113.30', 'User-Agent' => $plain, 'Accept-Language' => 'el', 'Sec-CH-UA' => '"HeadlessChrome";v="141"' ) );
t( 'headless check: a page still 403', 403 === $code, (string) $code );
settings( array( 'block_headless' => 0, 'require_browser_headers' => 1 ) );

// The stricter limit for visitors without the human check: not on site files.
settings( array( 'human_check' => 1, 'rate_limit_unverified' => 1, 'rate_limit' => 0, 'require_browser_headers' => 0 ) );
fresh();
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$codes[] = req( '/apple-touch-icon.png', array( 'X-Test-IP' => '203.0.113.31', 'User-Agent' => $nex ) );
}
t( 'human-check limit: not on apple-touch-icon.png (3 with limit 1)', ! in_array( 429, $codes, true ), implode( ',', $codes ) );
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$codes[] = req( $page, array( 'X-Test-IP' => '203.0.113.32', 'User-Agent' => $plain, 'Accept-Language' => 'el' ) );
}
t( 'human-check limit: a page still limited', in_array( 429, $codes, true ), implode( ',', $codes ) );
settings( array( 'human_check' => 0, 'rate_limit_unverified' => 0, 'require_browser_headers' => 1 ) );
fresh();

/* ---------- HTTP: DuckDuckBot and Applebot by their lists ---------- */
$ddg = 'DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)';
$code = req( $page, array( 'X-Test-IP' => '20.191.45.212', 'User-Agent' => $ddg ) );
t( 'DuckDuckBot from its official list: 200 (no browser headers needed)', 200 === $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '203.0.113.40', 'User-Agent' => $ddg ) );
t( 'DuckDuckBot from elsewhere: checked as before (403 without browser headers)', 403 === $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '203.0.113.40', 'User-Agent' => 'Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)', 'Accept-Language' => 'en' ) );
t( 'DuckDuckBot from elsewhere is not refused as a fake crawler (no new block)', 403 !== $code, (string) $code );
settings( array( 'block_ips' => '20.191.45.212' ) );
fresh();
$code = req( $page, array( 'X-Test-IP' => '20.191.45.212', 'User-Agent' => $ddg ) );
t( 'DuckDuckBot: the always-blocked IPs still come first', 403 === $code, (string) $code );
settings( array( 'block_ips' => '', 'bot_list' => PNCP_Options::stored()['bot_list'] . "\nDuckDuckBot" ) );
fresh();
$code = req( $page, array( 'X-Test-IP' => '20.191.45.212', 'User-Agent' => $ddg ) );
t( 'DuckDuckBot in the administrator\'s bot list: still blocked', 403 === $code, (string) $code );
settings( array( 'bot_list' => $saved_settings['bot_list'] ) );
fresh();

$ab   = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)';
$code = req( $page, array( 'X-Test-IP' => '17.241.208.9', 'User-Agent' => $ab, 'X-Test-RDNS' => 'nxdomain' ) );
t( 'Applebot from its official list: 200 without reverse DNS', 200 === $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '203.0.113.41', 'User-Agent' => $ab, 'X-Test-RDNS' => 'nxdomain' ) );
t( 'fake Applebot (no PTR, off the list): 403 as before', 403 === $code, (string) $code );
$code = req( $page, array( 'X-Test-IP' => '17.58.1.2', 'User-Agent' => $ab, 'X-Test-RDNS' => '17-58-1-2.applebot.apple.com', 'X-Test-FDNS' => '17.58.1.2' ) );
t( 'Applebot off the list but with Apple reverse DNS: 200 as before', 200 === $code, (string) $code );

/* ---------- explain() ---------- */
$e = PNCP_Bots::explain( '203.0.113.50', $asa, home_url( '/.well-known/passkey-endpoints' ) );
t( 'explain: passkey-endpoints from an iPhone passes', 0 === $e['code'], wp_json_encode( $e ) );
$e = PNCP_Bots::explain( '203.0.113.50', $asa, home_url( '/' ) );
t( 'explain: the home page without browser headers is refused', 403 === $e['code'] && 'no_browser' === $e['reason'], wp_json_encode( $e ) );
$e = PNCP_Bots::explain( '66.249.64.9', $pfp, home_url( '/' ) );
t( 'explain: the Chrome prefetch proxy from Google passes as a search engine', 0 === $e['code'] && 'search_engine' === $e['pass'], wp_json_encode( $e ) );

/* ---------- Restore ---------- */
update_option( PNCP_OPTION, $saved_settings );
PNCP_Options::flush();
foreach ( $saved_lists as $pncp_l => $pncp_v ) {
	if ( null === $pncp_v ) {
		delete_option( 'pncp_ip_lists_' . $pncp_l );
	} else {
		update_option( 'pncp_ip_lists_' . $pncp_l, $pncp_v );
	}
}
fresh();
echo $fails ? "\n$fails FAIL\n" : "\nOK\n";
exit( $fails ? 1 : 0 );
