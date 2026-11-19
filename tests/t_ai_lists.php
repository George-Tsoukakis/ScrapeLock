<?php
/**
 * ScrapeLock — 3.10: the official lists of the AI search bots (Anthropic, OpenAI, Perplexity), in real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_ai_lists.php
 *
 * The lists are never downloaded here: the sources are answered with sample JSON through pre_http_request
 * (mock), or stored with PNCP_Ip::store_list(). The real sources: PNCP_Ip::sources() (claude.com/crawling/bots.json,
 * openai.com/searchbot.json, openai.com/chatgpt-user.json, perplexity.com/perplexitybot.json,
 * perplexity.com/perplexity-user.json) and Anthropic's outbound range from https://docs.anthropic.com/en/api/ip-addresses.
 * Same requirements as t_http.php (mu-test-harness.php, router.php). Changes the database: test sites only.
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

/** Request with curl: [code, headers, body]. */
function req( $path, $headers = array() ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER         => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_TIMEOUT        => 30,
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
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
	// No background download of the missing lists (Google, Bing) during the test: it would rewrite the list
	// dates (PNCP_Ip::LISTS_OPTION . '_updated') while the test changes them.
	set_transient( 'pncp_lists_missing_try', 1, HOUR_IN_SECONDS );
}

function log_reasons() {
	global $wpdb;
	return $wpdb->get_col( "SELECT reason FROM {$wpdb->prefix}pncp_log ORDER BY id" );
}

/** Marks a list as last updated $days days ago. */
function list_age( $name, $days ) {
	$updated          = get_option( PNCP_Ip::LISTS_OPTION . '_updated', array() );
	$updated[ $name ] = time() - (int) round( $days * DAY_IN_SECONDS );
	update_option( PNCP_Ip::LISTS_OPTION . '_updated', $updated, false );
}

$keep      = get_option( PNCP_OPTION );
$keep_ant  = get_option( PNCP_Ip::LISTS_OPTION . '_anthropic', null );
$keep_upd  = get_option( PNCP_Ip::LISTS_OPTION . '_updated', null );
$keep_oai  = get_option( PNCP_Ip::LISTS_OPTION . '_openai_user', null );
$keep_ppl  = get_option( PNCP_Ip::LISTS_OPTION . '_perplexity_user', null );
$claude_ua = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)';
$search_ua = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +Claude-SearchBot@anthropic.com)';

settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'allow_ai_search'         => 1,
		'verify_ai_bots'          => 1,
		'block_bots'              => 1,
		'rate_limit'              => 0,
		'require_browser_headers' => 0,
		'human_check'             => 0,
	)
);
update_option( 'pncp_emergency_until', 0 );

/* ---------- (a) parsing: the shapes the AI services publish ---------- */
$p = PNCP_Ip::parse_ranges( '{"creationTime":"2026-11-01T00:00:00Z","prefixes":[{"ipv4Prefix":"160.79.104.0/21"},{"ipv6Prefix":"2607:6bc0::/48"},{"ipv4Prefix":"34.162.230.222/32"}]}' );
t( 'parse: Google style prefixes (ipv4Prefix / ipv6Prefix), CIDR and IPv6 kept', array( '160.79.104.0/21', '2607:6bc0::/48', '34.162.230.222/32' ) === $p, wp_json_encode( $p ) );
$p = PNCP_Ip::parse_ranges( '{"prefixes":["160.79.104.0/21","2607:6bc0::/48"]}' );
t( 'parse: prefixes as plain strings (before 3.10: nothing read)', array( '160.79.104.0/21', '2607:6bc0::/48' ) === $p, wp_json_encode( $p ) );
$p = PNCP_Ip::parse_ranges( '{"prefixes":[{"ip_prefix":"160.79.104.0/21"},{"ipv6_prefix":"2607:6bc0::/48"}]}' );
t( 'parse: {"ip_prefix"} without an AWS "service" (before 3.10: dropped as non-EC2)', array( '160.79.104.0/21', '2607:6bc0::/48' ) === $p, wp_json_encode( $p ) );
$p = PNCP_Ip::parse_ranges( '{"ip_ranges":{"ipv4":["160.79.104.0/21"," 34.162.230.222 "],"ipv6":["2607:6bc0::/48"]},"updated":"2026-11-01"}' );
t( 'parse: nested "ip_ranges" / ipv4 / ipv6, spaces trimmed', array( '160.79.104.0/21', '34.162.230.222', '2607:6bc0::/48' ) === $p, wp_json_encode( $p ) );
$p = PNCP_Ip::parse_ranges( '[{"cidr":"160.79.104.0/21"},{"cidr":"2607:6bc0::/48"}]' );
t( 'parse: a JSON list of {"cidr"} objects', array( '160.79.104.0/21', '2607:6bc0::/48' ) === $p, wp_json_encode( $p ) );
$p = PNCP_Ip::parse_ranges( '{"prefixes":[{"ip_prefix":"3.5.140.0/22","service":"AMAZON"},{"ip_prefix":"3.2.34.0/26","service":"EC2"}]}' );
t( 'parse: AWS (with "service") still only EC2', array( '3.2.34.0/26' ) === $p, wp_json_encode( $p ) );
$p = PNCP_Ip::parse_ranges( '{"result":{"ipv4_cidrs":["173.245.48.0/20"],"ipv6_cidrs":["2400:cb00::/32"]}}' );
t( 'parse: Cloudflare unchanged', array( '173.245.48.0/20', '2400:cb00::/32' ) === $p, wp_json_encode( $p ) );
$p = PNCP_Ip::sane_ranges( PNCP_Ip::parse_ranges( '{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"},{"ipv4Prefix":"160.79.104.0/21"},{"ipv4Prefix":"10.0.0.0/4"},{"ipv4Prefix":"999.1.1.1/32"},{"ipv6Prefix":"::/0"}]}' ) );
t( 'parse + sane_ranges: too wide / invalid entries dropped, /21 kept', array( '160.79.104.0/21' ) === array_values( $p ), wp_json_encode( $p ) );
t( 'in_any: /21 covers 160.79.104.0–160.79.111.255', PNCP_Ip::in_any( '160.79.106.230', array( '160.79.104.0/21' ) ) && PNCP_Ip::in_any( '160.79.111.255', array( '160.79.104.0/21' ) ) && ! PNCP_Ip::in_any( '160.79.112.0', array( '160.79.104.0/21' ) ) && ! PNCP_Ip::in_any( '160.79.103.255', array( '160.79.104.0/21' ) ) );
t( 'in_any: IPv6 /48 and IPv4-mapped address', PNCP_Ip::in_any( '2607:6bc0:0:1::5', array( '2607:6bc0::/48' ) ) && PNCP_Ip::in_any( '::ffff:160.79.106.230', array( '160.79.104.0/21' ) ) );
t( 'in_any: a CIDR written with host bits set still matches its network', PNCP_Ip::in_any( '160.79.106.230', array( '160.79.106.1/21' ) ) );

/* ---------- refresh with mocked sources (OpenAI, Perplexity, Anthropic) ---------- */
$GLOBALS['pncp_mock_bodies'] = array(
	'claude.com/crawling/bots.json'      => '{"creationTime":"2026-11-01T00:00:00Z","prefixes":[{"ipv4Prefix":"34.162.230.222/32"},{"ipv4Prefix":"34.162.46.126/32"},{"ipv6Prefix":"2600:1900:4000::/44"}]}',
	'openai.com/searchbot.json'          => '{"creationTime":"2026-11-01","prefixes":[{"ipv4Prefix":"20.42.10.176/28"},{"ipv6Prefix":"2a01:111:f403::/48"}]}',
	'openai.com/chatgpt-user.json'       => '{"creationTime":"2026-11-01","prefixes":[{"ipv4Prefix":"23.98.142.176/28"}]}',
	'perplexity.com/perplexitybot.json'  => '{"creationTime":"2026-11-01","prefixes":[{"ipv4Prefix":"107.20.236.150/32"}]}',
	'perplexity.com/perplexity-user.json' => '{"prefixes":["44.208.221.197/32","2600:1f18::/36"]}',
);
$pncp_mock = static function ( $pre, $args, $url ) {
	foreach ( $GLOBALS['pncp_mock_bodies'] as $needle => $body ) {
		if ( false !== strpos( $url, $needle ) ) {
			return array(
				'headers'  => array(),
				'body'     => $body,
				'response' => array(
					'code'    => 200,
					'message' => 'OK',
				),
				'cookies'  => array(),
				'filename' => null,
			);
		}
	}
	return new WP_Error( 'pncp_test_offline', 'offline' );
};
add_filter( 'pre_http_request', $pncp_mock, 10, 3 );
$r = PNCP_Ip::refresh_lists();
t( 'refresh (mock): Anthropic 3 entries incl. IPv6', isset( $r['anthropic'] ) && 3 === $r['anthropic'] && in_array( '2600:1900:4000::/44', PNCP_Ip::list_of( 'anthropic' ), true ), wp_json_encode( $r ) );
t( 'refresh (mock): OpenAI lists with CIDR and IPv6', 2 === $r['openai_search'] && 1 === $r['openai_user'] && PNCP_Ip::in_any( '20.42.10.180', PNCP_Ip::list_of( 'openai_search' ) ) && PNCP_Ip::in_any( '2a01:111:f403:c000::1', PNCP_Ip::list_of( 'openai_search' ) ), wp_json_encode( $r ) );
t( 'refresh (mock): Perplexity, also prefixes as plain strings', 1 === $r['perplexity_bot'] && 2 === $r['perplexity_user'] && PNCP_Ip::in_any( '2600:1f18:1::1', PNCP_Ip::list_of( 'perplexity_user' ) ), wp_json_encode( $r ) );
$GLOBALS['pncp_mock_bodies']['claude.com/crawling/bots.json'] = '{"error":"maintenance"}';
$r = PNCP_Ip::refresh_lists();
t( 'refresh (mock): a source with nothing usable keeps the previous list', 0 === $r['anthropic'] && 3 === count( PNCP_Ip::list_of( 'anthropic' ) ), wp_json_encode( $r ) );
remove_filter( 'pre_http_request', $pncp_mock, 10 );

/* ---------- restore ---------- */
update_option( PNCP_OPTION, $keep );
foreach ( array( 'anthropic' => $keep_ant, 'updated' => $keep_upd, 'openai_user' => $keep_oai, 'perplexity_user' => $keep_ppl ) as $name => $value ) {
	if ( null === $value ) {
		delete_option( PNCP_Ip::LISTS_OPTION . '_' . $name );
	} else {
		update_option( PNCP_Ip::LISTS_OPTION . '_' . $name, $value, false );
	}
}
foreach ( array( 'openai_search', 'perplexity_bot' ) as $name ) {
	delete_option( PNCP_Ip::LISTS_OPTION . '_' . $name );
}
PNCP_Options::flush();
fresh();
echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
