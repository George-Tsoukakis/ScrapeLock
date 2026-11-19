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

/* ---------- (b) Anthropic's published outbound range ---------- */
t( 'extra ranges: Anthropic outbound 160.79.104.0/21 built in', array( '160.79.104.0/21' ) === PNCP_Ip::extra_ranges( 'anthropic' ) && array() === PNCP_Ip::extra_ranges( 'openai_user' ) );
$pncp_extra = static function ( $ranges, $name ) {
	return 'openai_user' === $name ? array( '0.0.0.0/0', '198.51.100.0/24', 42 ) : $ranges;
};
add_filter( 'pncp_ip_extra_ranges', $pncp_extra, 10, 2 );
t( 'extra ranges: filter per list, sanitized (no 0.0.0.0/0, no non-text)', array( '198.51.100.0/24' ) === PNCP_Ip::extra_ranges( 'openai_user' ) );
remove_filter( 'pncp_ip_extra_ranges', $pncp_extra, 10 );
// The owner's case: 14 single addresses in the list, Claude-User from 160.79.106.230.
$fourteen = array();
for ( $i = 1; $i <= 14; $i++ ) {
	$fourteen[] = '34.162.230.' . $i;
}
PNCP_Ip::store_list( 'anthropic', $fourteen );
t( 'ai_verdict: Claude-User from 160.79.106.230 with a 14-address list = verified', 'verified' === PNCP_Bots::ai_verdict( $claude_ua, '160.79.106.230', PNCP_Options::get() ) );
t( 'ai_verdict: Claude-User from an address of the list = verified', 'verified' === PNCP_Bots::ai_verdict( $claude_ua, '34.162.230.7', PNCP_Options::get() ) );
t( 'ai_verdict: Claude-User from elsewhere = fake (fresh list)', 'fake' === PNCP_Bots::ai_verdict( $claude_ua, '198.51.100.140', PNCP_Options::get() ) );
t( 'official_owner: 160.79.106.230 = Anthropic', 'Anthropic' === PNCP_Ip::official_owner( '160.79.106.230' ) && '' === PNCP_Ip::official_owner( '198.51.100.140' ) );
$pncp_no_extra = static function ( $ranges, $name ) {
	return 'anthropic' === $name ? array() : $ranges;
};
add_filter( 'pncp_ip_extra_ranges', $pncp_no_extra, 10, 2 );
t( 'extra ranges: removable with the filter (back to fake)', 'fake' === PNCP_Bots::ai_verdict( $claude_ua, '160.79.106.230', PNCP_Options::get() ) );
remove_filter( 'pncp_ip_extra_ranges', $pncp_no_extra, 10 );
delete_option( PNCP_Ip::LISTS_OPTION . '_anthropic' );
PNCP_Ip::reset();
t( 'ai_verdict: no list yet, outbound range still verified, others unchecked', 'verified' === PNCP_Bots::ai_verdict( $search_ua, '160.79.106.230', PNCP_Options::get() ) && '' === PNCP_Bots::ai_verdict( $search_ua, '198.51.100.140', PNCP_Options::get() ) );
t( 'ai_verdict: ClaudeBot (training crawler) is not an AI search bot: not verified', '' === PNCP_Bots::ai_verdict( 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)', '160.79.106.230', PNCP_Options::get() ) );

// End to end: the same over HTTP.
PNCP_Ip::store_list( 'anthropic', $fourteen );
fresh();
list( $code ) = req( '/', array( 'X-Test-IP' => '160.79.106.230', 'User-Agent' => $claude_ua ) );
t( 'HTTP: Claude-User from 160.79.106.230 = 200 (was 403 fake_ai_bot in 3.9.1)', 200 === $code && ! in_array( 'fake_ai_bot', log_reasons(), true ), $code . ' ' . implode( ',', log_reasons() ) );
list( $code ) = req( '/', array( 'X-Test-IP' => '198.51.100.141', 'User-Agent' => $claude_ua ) );
t( 'HTTP: Claude-User from an unknown address = 403 fake_ai_bot (fresh list)', 403 === $code && in_array( 'fake_ai_bot', log_reasons(), true ), $code . ' ' . implode( ',', log_reasons() ) );

/* ---------- stale list: fail open ---------- */
list_age( 'anthropic', 8 );
t( 'list_stale: 8 days old = stale', PNCP_Ip::list_stale( 'anthropic' ) );
fresh();
list( $code ) = req( '/', array( 'X-Test-IP' => '198.51.100.142', 'User-Agent' => $claude_ua ) );
t( 'HTTP: stale list (8 days): Claude-User from elsewhere not called fake (200)', 200 === $code && ! in_array( 'fake_ai_bot', log_reasons(), true ), $code . ' ' . implode( ',', log_reasons() ) );
t( 'ai_verdict: stale list still verifies its own addresses', 'verified' === PNCP_Bots::ai_verdict( $claude_ua, '34.162.230.3', PNCP_Options::get() ) && '' === PNCP_Bots::ai_verdict( $claude_ua, '198.51.100.142', PNCP_Options::get() ), PNCP_Bots::ai_verdict( $claude_ua, '34.162.230.3', PNCP_Options::get() ) . '/' . PNCP_Bots::ai_verdict( $claude_ua, '198.51.100.142', PNCP_Options::get() ) . '/' . wp_json_encode( PNCP_Ip::lists_updated() ) . time() );
$pncp_age = static function () {
	return 0;
};
add_filter( 'pncp_ip_list_max_age', $pncp_age );
t( 'list_stale: filter 0 = never stale', ! PNCP_Ip::list_stale( 'anthropic' ) && 'fake' === PNCP_Bots::ai_verdict( $claude_ua, '198.51.100.142', PNCP_Options::get() ) );
remove_filter( 'pncp_ip_list_max_age', $pncp_age );
list_age( 'anthropic', 2 );
t( 'list_stale: 2 days old = not stale', ! PNCP_Ip::list_stale( 'anthropic' ) );

/* ---------- (d) the explanation ---------- */
$note = PNCP_Ip::list_note( 'anthropic' );
t( 'list_note: 14 entries, date, plus the outbound range', 0 === strpos( $note, '14 entries, updated ' ) && false !== strpos( $note, '(plus 160.79.104.0/21)' ), $note );
$detail = PNCP_Tester::ai_list_detail( $claude_ua );
t( 'tester: "Fake AI search bot" names the list, its size and date', false !== strpos( $detail, 'claude.com/crawling/bots.json' ) && false !== strpos( $detail, '14 entries' ), $detail );
t( 'tester: nothing for another User-Agent', '' === PNCP_Tester::ai_list_detail( 'Mozilla/5.0 Chrome/141' ) );
$r = PNCP_Tester::run( array( 'mode' => 'custom', 'ip' => '198.51.100.143', 'ua' => $claude_ua, 'address' => '/' ) );
t( 'tester run(): fake_ai_bot with the list details in "why"', is_array( $r ) && 'fake_ai_bot' === $r['reason'] && false !== strpos( $r['why'], '14 entries' ), is_array( $r ) ? $r['why'] : 'error' );
$r = PNCP_Tester::run( array( 'mode' => 'custom', 'ip' => '160.79.106.230', 'ua' => $claude_ua, 'address' => '/' ) );
t( 'tester run(): Claude-User from 160.79.106.230 = allowed (ai_search)', is_array( $r ) && 'allowed' === $r['verdict'], is_array( $r ) ? wp_json_encode( array( $r['verdict'], $r['reason'], $r['pass'] ) ) : 'error' );

/* ---------- restore ---------- */
/* ---------- Site Health: the Apple and DuckDuckGo lists are checked too ---------- */
$upd_before = get_option( PNCP_Ip::LISTS_OPTION . '_updated', array() );
$upd        = is_array( $upd_before ) ? $upd_before : array();
foreach ( array( 'google', 'bing', 'apple', 'duckduckgo', 'cloudflare' ) as $name ) {
	$upd[ $name ] = time();
}
$upd_dd = $upd;
unset( $upd_dd['duckduckgo'] );
update_option( PNCP_Ip::LISTS_OPTION . '_updated', $upd_dd, false );
$health = PNCP_Health::test_ip_lists();
t( 'Site Health: a DuckDuckGo list never downloaded is named', 'good' !== $health['status'] && false !== strpos( $health['description'], 'DuckDuckGo' ), $health['status'] . ' ' . wp_strip_all_tags( $health['description'] ) );
$upd['apple'] = time() - 5 * DAY_IN_SECONDS;
update_option( PNCP_Ip::LISTS_OPTION . '_updated', $upd, false );
$health = PNCP_Health::test_ip_lists();
t( 'Site Health: an Apple list not refreshed for 5 days is named', 'good' !== $health['status'] && false !== strpos( $health['description'], 'Apple' ), $health['status'] );
$upd['apple'] = time();
update_option( PNCP_Ip::LISTS_OPTION . '_updated', $upd, false );
$health = PNCP_Health::test_ip_lists();
t( 'Site Health: all lists fresh = good', 'good' === $health['status'], wp_strip_all_tags( $health['description'] ) );
update_option( PNCP_Ip::LISTS_OPTION . '_updated', $upd_before, false );

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
