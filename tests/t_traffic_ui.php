<?php
/**
 * ScrapeLock 3.12 — the Traffic tab (PNCP_Admin_Traffic, PNCP_Traffic_Actions) on a real WordPress, through HTTP
 * with an administrator's (and an editor's) cookie.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_traffic_ui.php
 *
 * Seeds realistic requests (browsers, Googlebot from a stored Google list, a fake Googlebot, GPTBot, python-requests,
 * a WhatsApp preview, 404s linked from the site and from outside, scanner probes, 5xx, redirects, HIT / MISS, a
 * User-Agent and a path with <script> and quotes, a formula) with PNCP_Traffic::ingest() + flush() + rollup(), then:
 * every view answers 200 without PHP notices; the numbers on screen are the API's; filters, sort and pages through
 * the address; nothing unescaped; the CSV (headers, content, formulas); nonce and capability on every action (an
 * editor gets 403, a wrong nonce is refused); Block / Always allow write exactly one line after the confirmation and
 * save an earlier version; the search-engine and own-browser guards; Start collecting; Test this path; Delete
 * collected traffic; the settings form; the off state.
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
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? '  [' . substr( (string) $extra, 0, 400 ) . ']' : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	wp_cache_delete( 'alloptions', 'options' );
	PNCP_Options::flush();
	PNCP_Ip::reset();
	PNCP_Traffic::reset();
	PNCP_Traffic_Ua::reset();
}

function backups() {
	wp_cache_delete( 'pncp_settings_backups', 'options' );
	wp_cache_delete( 'notoptions', 'options' );
	return PNCP_Settings_Io::backups();
}

function stored() {
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_delete( PNCP_OPTION, 'options' );
	PNCP_Options::flush();
	return PNCP_Options::stored();
}

/** Cookies of a user. */
function cookies_for( $user_id ) {
	$expire = time() + DAY_IN_SECONDS;
	$token  = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	return array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
}

const T_UA = 'Mozilla/5.0 Chrome/141 TrafficTest';

/** A request: [code, body, location, headers]. */
function http( $path, $post = null, $who = 'admin' ) {
	global $base, $jars;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $jars[ $who ] as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.230', 'User-Agent: ' . T_UA, 'Accept-Language: en' ),
		CURLOPT_TIMEOUT        => 120,
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = http_build_query( $post );
	}
	curl_setopt_array( $ch, $opts );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	$head = substr( $out, 0, $hs );
	$loc  = preg_match( '/^location:\s*(\S+)/mi', $head, $m ) ? $m[1] : '';
	return array( $code, substr( $out, $hs ), html_entity_decode( $loc ), $head );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

function tab( $query = '' ) {
	return '/wp-admin/options-general.php?page=scrapelock&tab=traffic' . $query;
}

/** The Traffic part of a page. */
function part( $body ) {
	$i = strpos( $body, 'id="pncp-tr"' );
	return false === $i ? '' : substr( $body, $i );
}

function post_action( $fields, $who = 'admin', $nonce = null ) {
	$fields = array_merge(
		array(
			'action'   => PNCP_Traffic_Actions::ACTION,
			'_wpnonce' => null === $nonce ? wp_create_nonce( PNCP_Traffic_Actions::ACTION ) : $nonce,
		),
		$fields
	);
	return http( '/wp-admin/admin-post.php', $fields, $who );
}

function query_arg( $url, $name ) {
	$q = array();
	wp_parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $q );
	return isset( $q[ $name ] ) ? (string) $q[ $name ] : '';
}

function raw_count( $where = '1 = 1' ) {
	global $wpdb;
	return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . PNCP_Traffic::table( 'raw' ) . ' WHERE ' . $where ); // phpcs:ignore
}

/* ---------- Users ---------- */
$admin  = get_user_by( 'id', 1 );
$editor = get_user_by( 'login', 'tr_editor' );
if ( ! $editor ) {
	$editor = get_user_by( 'id', wp_insert_user( array( 'user_login' => 'tr_editor', 'user_pass' => wp_generate_password(), 'role' => 'editor', 'user_email' => 'tr_editor@example.invalid' ) ) );
}
$jars                        = array(
	'admin'  => cookies_for( $admin->ID ),
	'editor' => cookies_for( $editor->ID ),
);
$_COOKIE[ LOGGED_IN_COOKIE ] = $jars['admin'][ LOGGED_IN_COOKIE ];
wp_set_current_user( $admin->ID );

/* ---------- State ---------- */
$saved     = get_option( PNCP_OPTION );
$saved_bak = get_option( 'pncp_settings_backups', false );
$saved_g   = get_option( PNCP_Ip::LISTS_OPTION . '_google', false );
$saved_u   = get_option( PNCP_Ip::LISTS_OPTION . '_updated', false );
$saved_z   = get_option( 'timezone_string' );
$tmp       = rtrim( sys_get_temp_dir(), '/' ) . '/pncp-trui-' . getmypid();
@mkdir( $tmp, 0700, true );
update_option( 'timezone_string', 'Europe/Athens' );
delete_transient( PNCP_Traffic_Actions::TEST . $admin->ID );

settings(
	array(
		'enabled'          => 1,
		'monitor_mode'     => 0,
		'monitor_until'    => 0,
		'block_bots'       => 1,
		'block_http_libs'  => 0,
		'traffic'          => 1,
		'traffic_wp'       => 0,
		'traffic_log_path' => '',
		'traffic_raw_days' => 3,
		'traffic_days'     => 90,
		'traffic_ip_mode'  => 'full',
		'bot_list'         => PNCP_Options::default_bot_list(),
		'allow_list'       => '',
	)
);
PNCP_Traffic::maybe_schedule();
PNCP_Ip::store_list( 'google', array( '66.249.64.0/19' ) );
PNCP_Traffic_Ua::reset();
PNCP_Traffic::purge_all();

/* ---------- Seed ---------- */
$home   = home_url( '/' );
$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
$iphone = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
$gbot   = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
$gpt    = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';
$py     = 'python-requests/2.31.0';
$wa     = 'WhatsApp/2.23.20.0';
$xss_ua = '<script>alert("ua")</script> EvilBot/1.0 \'q\' "q"';
$xss_p  = '/"><script>alert("p")</script>';
$rows   = array();
$t      = time() - 30;
for ( $i = 0; $i < 60; $i++ ) {
	$rows[] = array( $t - $i * 600, '203.0.113.' . ( $i % 9 + 1 ), 200, '/product/vitamin-c/', $chrome, array( 'cache' => $i % 3 ? 'HIT' : 'MISS', 'bytes' => 52000, 'country' => 'GR', 'referer' => 'https://www.google.com/' ) );
}
for ( $i = 0; $i < 25; $i++ ) {
	$rows[] = array( $t - $i * 900, '198.51.100.' . ( $i % 5 + 1 ), 200, '/', $iphone, array( 'cache' => 'HIT', 'bytes' => 30000, 'country' => 'CY' ) );
}
for ( $i = 0; $i < 15; $i++ ) {
	$rows[] = array( $t - $i * 1000, '66.249.66.' . ( $i % 3 + 1 ), 200, '/category/c' . $i . '/', $gbot, array( 'cache' => 'MISS', 'bytes' => 40000, 'country' => 'US' ) );
}
for ( $i = 0; $i < 6; $i++ ) {
	$rows[] = array( $t - $i * 1200, '192.0.2.66', 200, '/', $gbot, array( 'cache' => 'MISS', 'country' => 'RU' ) );
}
for ( $i = 0; $i < 10; $i++ ) {
	$rows[] = array( $t - $i * 700, '20.171.207.' . ( $i % 2 + 1 ), 403, '/shop/', $gpt, array( 'cache' => 'MISS', 'country' => 'US' ) );
}
for ( $i = 0; $i < 8; $i++ ) {
	$rows[] = array( $t - $i * 300, '192.0.2.10', 200, '/wp-json/wp/v2/products', $py, array( 'cache' => 'MISS', 'country' => 'DE' ) );
}
for ( $i = 0; $i < 3; $i++ ) {
	$rows[] = array( $t - $i * 300, '157.240.1.1', 200, '/product/vitamin-c/', $wa, array( 'cache' => 'HIT', 'country' => 'IE' ) );
}
for ( $i = 0; $i < 7; $i++ ) {
	$rows[] = array( $t - $i * 400, '203.0.113.5', 404, '/old-page/', $chrome, array( 'referer' => $home . 'blog/post/', 'cache' => 'MISS', 'country' => 'GR' ) );
}
for ( $i = 0; $i < 4; $i++ ) {
	$rows[] = array( $t - $i * 400, '203.0.113.6', 404, '/missing-product/', $chrome, array( 'referer' => 'https://forum.example.org/t/1', 'cache' => 'MISS', 'country' => 'GR' ) );
}
for ( $i = 0; $i < 5; $i++ ) {
	$rows[] = array( $t - $i * 100, '192.0.2.99', 404, '/wp-config.php.bak', 'Mozilla/5.0', array( 'country' => 'CN' ) );
}
for ( $i = 0; $i < 3; $i++ ) {
	$rows[] = array( $t - $i * 800, '203.0.113.7', 502, '/checkout/', $chrome, array( 'country' => 'GR' ) );
}
for ( $i = 0; $i < 4; $i++ ) {
	$rows[] = array( $t - $i * 800, '203.0.113.8', 301, '/old-shop/', $chrome, array( 'referer' => $home, 'country' => 'GR' ) );
}
for ( $i = 0; $i < 2; $i++ ) {
	$rows[] = array( $t - $i * 100, '192.0.2.77', 404, $xss_p, $xss_ua, array( 'referer' => 'https://evil.example/"><img src=x onerror=alert(1)>', 'country' => 'NL' ) );
}
$rows[] = array( $t - 50, '192.0.2.88', 200, '/formula/', '=HYPERLINK("http://x","y")', array() );
$rows[] = array( $t - 40, '192.0.2.230', 200, '/', T_UA, array() ); // The administrator's own browser.
for ( $i = 0; $i < 55; $i++ ) {
	$rows[] = array( $t - 3000 - $i, '192.0.2.' . ( 100 + $i ), 200, '/feed/', 'FeedReader' . $i . '/1.0', array() ); // Many User-Agents: pages.
}
foreach ( $rows as $r ) {
	PNCP_Traffic::ingest( array_merge( array( 'ts' => $r[0], 'ip' => $r[1], 'status' => $r[2], 'path' => $r[3], 'ua' => $r[4], 'method' => 'GET' ), $r[5] ), 'bunny' );
}
for ( $d = 1; $d <= 2; $d++ ) {
	for ( $i = 0; $i < 20; $i++ ) {
		PNCP_Traffic::ingest( array( 'ts' => time() - $d * DAY_IN_SECONDS - 3600 - $i * 60, 'ip' => '203.0.113.' . ( $i + 20 ), 'status' => 200, 'path' => '/', 'ua' => $chrome, 'cache' => 'HIT', 'bytes' => 1000, 'country' => 'GR' ), 'bunny' );
	}
}
PNCP_Traffic::flush();
PNCP_Traffic::rollup();
t( 'seed: the requests are stored', raw_count() === count( $rows ) + 40, (string) raw_count() );
t( 'seed: the fake Googlebot is "fake_bot", the real one "verified_bot"', raw_count( "ip = '192.0.2.66' AND fam = 'fake_bot'" ) === 6 && raw_count( "ip LIKE '66.249.66.%' AND fam = 'verified_bot'" ) === 15 );

$f24 = PNCP_Admin_Traffic::filters( PNCP_Admin_Traffic::state( array() ) );

/* ---------- 1. Every view ---------- */
$views = array(
	''                                               => 'Overview',
	'&tr_view=agents'                                => 'User-Agents',
	'&tr_view=problems'                              => 'Problem URLs',
	'&tr_view=problems&tr_type=5xx'                  => 'Problem URLs',
	'&tr_view=problems&tr_type=3xx'                  => 'Problem URLs',
	'&tr_view=problems&tr_type=uncached'             => 'Problem URLs',
	'&tr_view=problems&tr_type=large'                => 'Problem URLs',
	'&tr_view=problems&tr_type=slow'                 => 'Problem URLs',
	'&tr_view=visitors'                              => 'Visitors',
	'&tr_view=log'                                   => 'Requests',
	'&tr_view=settings'                              => 'Sources and settings',
	'&tr_view=ua&tr_key=' . rawurlencode( $py )      => 'User-Agents',
	'&tr_view=ua&tr_key=' . rawurlencode( $xss_ua )  => 'User-Agents',
	'&tr_view=path&tr_key=' . rawurlencode( '/old-page/' ) => 'Problem URLs',
	'&tr_view=path&tr_key=' . rawurlencode( $xss_p ) => 'Problem URLs',
	'&tr_view=ip&tr_key=203.0.113.5'                 => 'Visitors',
	'&tr_period=7d'                                  => 'Overview',
	'&tr_period=30d&tr_view=agents'                  => 'User-Agents',
	'&tr_period=custom&tr_from=' . wp_date( 'Y-m-d', time() - 2 * DAY_IN_SECONDS ) . '&tr_to=' . wp_date( 'Y-m-d' ) => 'Overview',
	'&tr_period=90d&tr_view=problems'                => 'Problem URLs',
	'&tr_view=bogus&tr_period=bogus&tr_status=bogus&tr_src=bogus&tr_paged=-3' => 'Overview',
);
$pages = array();
foreach ( $views as $q => $nav ) {
	list( $code, $body ) = http( tab( $q ) );
	$pages[ $q ]         = $body;
	$current             = preg_match( '#<nav class="pncp-tr__nav".*?class="is-current" aria-current="page">([^<]+)</a>#s', $body, $m ) ? $m[1] : '';
	t( "view $q: 200, no PHP notice, the Traffic tab, “{$nav}” current", 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'pncp-admin--traffic' ) && $nav === $current, $code . ' ' . $current );
}
t( 'the stylesheet and script of the tab are loaded on it', false !== strpos( $pages[''], 'assets/css/traffic.css' ) && false !== strpos( $pages[''], 'assets/js/traffic.js' ) );
list( $code, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=log' );
t( 'not on another tab', 200 === $code && false === strpos( $body, 'assets/css/traffic.css' ) );
list( $code, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=visitors' );
t( 'alias tab=visitors opens Traffic', 200 === $code && false !== strpos( $body, 'pncp-admin--traffic' ) );
t( 'no external script or stylesheet on the tab', ! preg_match( '#<(?:script|link)[^>]+(?:src|href)="https?://(?!127\.0\.0\.1|localhost)[^"]+"#', part( $pages[''] ) ) );

/* ---------- 2. Numbers ---------- */
$ov   = PNCP_Traffic::overview( $f24 );
$kpis = preg_match_all( '#<span class="pncp-ar__kpi-value">([^<]+)</span> <span class="pncp-ar__kpi-label">([^<]+)</span>#', $pages[''], $m, PREG_SET_ORDER ) ? $m : array();
$kv   = array();
foreach ( $kpis as $k ) {
	$kv[ $k[2] ] = html_entity_decode( $k[1] );
}
t( 'overview: requests = overview() total', isset( $kv['requests'] ) && number_format_i18n( $ov['total'] ) === $kv['requests'], wp_json_encode( $kv ) . ' ' . $ov['total'] );
t( 'overview: unique IPs = overview() ips', isset( $kv['unique IPs'] ) && number_format_i18n( $ov['ips'] ) === $kv['unique IPs'], wp_json_encode( $kv ) );
t( 'overview: 4xx % from overview()', isset( $kv['4xx errors'] ) && number_format_i18n( 100 * $ov['s4xx'] / $ov['total'], 1 ) . '%' === $kv['4xx errors'] );
t( 'overview: cache hit ratio shown (Bunny HIT / MISS)', isset( $kv['served from cache'] ) && number_format_i18n( 100 * $ov['cache_hits'] / ( $ov['cache_hits'] + $ov['cache_misses'] ), 1 ) . '%' === $kv['served from cache'] );
t( 'overview: the chart is an SVG with a text alternative and the numbers as a table', false !== strpos( $pages[''], '<svg viewBox="0 0 1000 200"' ) && false !== strpos( $pages[''], 'role="img" aria-label="Requests per hour.' ) && false !== strpos( $pages[''], 'Show the numbers' ) );
$top404 = PNCP_Traffic::problems( '404', $f24, 5 );
t( 'overview: the top 404 is the API\'s, with its count', preg_match( '#Not found \(404\).*?<code>' . preg_quote( esc_html( $top404['rows'][0]['path'] ), '#' ) . '</code></a></td><td class="num">' . (int) $top404['rows'][0]['hits'] . '<#s', $pages[''] ), $top404['rows'][0]['path'] );
t( 'overview: links to every full view', false !== strpos( $pages[''], 'tr_view=agents' ) && false !== strpos( $pages[''], 'tr_view=problems&#038;tr_type=5xx' ) && false !== strpos( $pages[''], 'tr_view=visitors' ) );
$uas = PNCP_Traffic::top( 'ua', $f24, 50 );
$py_row = null;
foreach ( $uas['rows'] as $r ) {
	if ( $py === $r['key'] ) {
		$py_row = $r;
	}
}
t( 'agents: python-requests row with the API\'s hits and IPs', null !== $py_row && preg_match( '#tr_key=python-requests%2F2.31.0[^"]*" class="pncp-tr__link">.*?</a></td><td class="num">' . $py_row['hits'] . '</td><td class="num">' . $py_row['ips'] . '</td>#s', $pages['&tr_view=agents'] ) );
t( 'agents: family chips with counts from top(ua_family)', false !== strpos( $pages['&tr_view=agents'], 'Scripts and HTTP libraries <span class="pncp-tr__count">' ) );
t( 'agents: the family badge of a verified and a fake Googlebot', false !== strpos( $pages['&tr_view=agents'], 'pncp-tr__fam--verified_bot' ) && false !== strpos( $pages['&tr_view=agents'], 'pncp-tr__fam--fake_bot' ) );
t( 'agents: page links (more than 50 User-Agents)', $uas['total_rows'] > 50 && false !== strpos( $pages['&tr_view=agents'], 'tr_paged=2' ), (string) $uas['total_rows'] );
$p404 = $pages['&tr_view=problems'];
t( 'problems 404: internal referrer marked as a broken link on your site', false !== strpos( $p404, 'broken link on your site' ) && false !== strpos( $p404, 'external' ) );
t( 'problems 404: scanner noise hidden by default, with a link to show it', false === strpos( $p404, '/wp-config.php.bak' ) && false !== strpos( $p404, 'tr_scan=1' ) );
list( , $body ) = http( tab( '&tr_view=problems&tr_scan=1' ) );
t( 'problems 404 with tr_scan=1: the probe shows, marked as scanner noise', false !== strpos( $body, '/wp-config.php.bak' ) && false !== strpos( $body, 'scanner noise' ) );
t( 'problems 404: “Redirect” to copy without Rank Math', false !== strpos( $p404, 'pncp-copy' ) );
t( 'problems 5xx: statuses and sample User-Agent', false !== strpos( $pages['&tr_view=problems&tr_type=5xx'], '/checkout/' ) && false !== strpos( $pages['&tr_view=problems&tr_type=5xx'], 'pncp-tr__st--5">502' ) );
t( 'problems 3xx: a link on your site to a redirect', false !== strpos( $pages['&tr_view=problems&tr_type=3xx'], '/old-shop/' ) && false !== strpos( $pages['&tr_view=problems&tr_type=3xx'], 'link on your site' ) );
t( 'problems slow: says that the source has no response times', false !== strpos( $pages['&tr_view=problems&tr_type=slow'], 'no response times' ) );
$unc = PNCP_Traffic::problems( 'uncached', $f24, 50 );
t( 'problems uncached: the API\'s rows with the miss rate', $unc['rows'] && false !== strpos( $pages['&tr_view=problems&tr_type=uncached'], number_format_i18n( 100 * $unc['rows'][0]['miss_rate'], 1 ) . '%' ) );
$ipsr = PNCP_Traffic::top( 'ip', $f24, 50 );
t( 'visitors: top IP with its hits, country and main family', preg_match( '#tr_key=' . preg_quote( $ipsr['rows'][0]['key'], '#' ) . '" class="pncp-tr__link"><code>[^<]+</code></a></td><td><a class="pncp-ar__country"[^>]*>[A-Z]{2}</a></td><td><span class="pncp-tr__fam#', $pages['&tr_view=visitors'] ) );
$raw = PNCP_Traffic::raw( $f24, 50 );
t( 'log: 50 rows newest first, the first one the API\'s', 50 === substr_count( $pages['&tr_view=log'], '<tr class="pncp-tr__row--' ) && false !== strpos( $pages['&tr_view=log'], gmdate( 'c', $raw['rows'][0]['ts'] ) ) && $raw['has_more'] && false !== strpos( $pages['&tr_view=log'], 'tr_paged=2' ) );
$d = PNCP_Traffic::detail( 'ua', $py, $f24 );
t( 'UA detail: summary = detail()', false !== strpos( $pages[ '&tr_view=ua&tr_key=' . rawurlencode( $py ) ], '<span class="pncp-ar__kpi-value">' . $d['summary']['total'] . '</span> <span class="pncp-ar__kpi-label">requests' ) );
t( 'UA detail: what ScrapeLock does, and “Block” / “Always allow” as links to a confirmation', false !== strpos( $pages[ '&tr_view=ua&tr_key=' . rawurlencode( $py ) ], 'What ScrapeLock does with it' ) && false !== strpos( $pages[ '&tr_view=ua&tr_key=' . rawurlencode( $py ) ], 'tr_act=block' ) && false !== strpos( $pages[ '&tr_view=ua&tr_key=' . rawurlencode( $py ) ], 'tr_act=allow' ) );
list( , $body ) = http( tab( '&tr_view=ua&tr_key=' . rawurlencode( $gpt ) ) );
t( 'UA detail: GPTBot is blocked by the default bot list (no Block button)', false !== strpos( $body, 'Blocked by the bot list: matches' ) && false === strpos( $body, 'tr_act=block' ) );
list( , $body ) = http( tab( '&tr_view=ua&tr_key=' . rawurlencode( $gbot ) . '&tr_ip=192.0.2.66' ) );
t( 'UA detail: a fake Googlebot gets the hint that it is already refused', false !== strpos( $body, 'already refused while protection is on' ) );
$dp = PNCP_Traffic::detail( 'path', '/old-page/', $f24 );
t( 'path detail: total and the internal referrer', false !== strpos( $pages[ '&tr_view=path&tr_key=' . rawurlencode( '/old-page/' ) ], '<span class="pncp-ar__kpi-value">' . $dp['summary']['total'] . '</span>' ) && false !== strpos( $pages[ '&tr_view=path&tr_key=' . rawurlencode( '/old-page/' ) ], 'your site' ) );
t( 'IP detail: links to its requests, Check a request and Block permanently', false !== strpos( $pages['&tr_view=ip&tr_key=203.0.113.5'], 'tr_ip=203.0.113.5' ) && false !== strpos( $pages['&tr_view=ip&tr_key=203.0.113.5'], '#pncp-tester' ) && false !== strpos( $pages['&tr_view=ip&tr_key=203.0.113.5'], 'value="block_permanent"' ) );
t( 'settings: one line per source and which one “Auto” uses', 3 === substr_count( $pages['&tr_view=settings'], '<li class="pncp-tr__source' ) && false !== strpos( $pages['&tr_view=settings'], 'used by “Auto”' ) );
t( 'settings: the form posts the traffic section only', false !== strpos( $pages['&tr_view=settings'], 'name="' . PNCP_OPTION . '[_sections][]" value="traffic"' ) && false !== strpos( $pages['&tr_view=settings'], 'name="' . PNCP_OPTION . '[traffic_log_path]"' ) && false !== strpos( $pages['&tr_view=settings'], 'id="pncp-traffic_raw_days"' ) );
t( 'unknown values in the address fall back to the defaults', false !== strpos( $pages['&tr_view=bogus&tr_period=bogus&tr_status=bogus&tr_src=bogus&tr_paged=-3'], '<option value="24h" selected' ) );

/* ---------- 3. Filters, sort, pages ---------- */
list( , $body ) = http( tab( '&tr_view=log&tr_status=404' ) );
$st = preg_match_all( '#<td><span class="pncp-tr__st pncp-tr__st--\d">(\d+)</span>#', $body, $m ) ? array_unique( $m[1] ) : array();
t( 'log tr_status=404: only 404 rows', array( '404' ) === array_values( $st ), implode( ',', $st ) );
list( , $body ) = http( tab( '&tr_view=log&tr_q=old-page' ) );
t( 'log tr_q: the search', 7 === substr_count( $body, '<tr class="pncp-tr__row--' ) );
list( , $body ) = http( tab( '&tr_view=log&tr_ip=203.0.113.5' ) );
t( 'log tr_ip: one IP, shown as a removable filter', count( PNCP_Traffic::raw( array_merge( $f24, array( 'ip' => '203.0.113.5' ) ), 50 )['rows'] ) === substr_count( $body, '<tr class="pncp-tr__row--' ) && false !== strpos( $body, 'Remove the filter IP' ) );
list( , $body ) = http( tab( '&tr_view=log&tr_paged=2' ) );
$raw2 = PNCP_Traffic::raw( $f24, 50, 50 );
t( 'log page 2: the API\'s second page', false !== strpos( $body, gmdate( 'c', $raw2['rows'][0]['ts'] ) ) && false !== strpos( $body, 'rel="prev"' ) );
list( , $body ) = http( tab( '&tr_view=agents&tr_fam=script' ) );
t( 'agents tr_fam=script: only scripts', false !== strpos( $body, 'python-requests/2.31.0' ) && false === strpos( $body, 'Googlebot/2.1' ) && false !== strpos( $body, 'aria-current="true">Scripts and HTTP libraries' ) );
list( , $body ) = http( tab( '&tr_view=agents&tr_order=s4xx' ) );
$s4 = PNCP_Traffic::top( 'ua', $f24, 1, 0, 's4xx' );
t( 'agents tr_order=s4xx: sorted by 4xx, the heading marked', preg_match( '#<tbody><tr><td><span class="pncp-tr__fam[^"]*">[^<]+</span></td><td class="pncp-ar__ua"><a href="[^"]*tr_key=' . preg_quote( rawurlencode( $s4['rows'][0]['key'] ), '#' ) . '#', $body ) && false !== strpos( $body, 'aria-sort="descending"' ) );
list( , $body ) = http( tab( '&tr_view=agents&tr_paged=2' ) );
$page2 = PNCP_Traffic::top( 'ua', $f24, 50, 50 );
t( 'agents tr_paged=2: the API\'s second page', $page2['rows'] && count( $page2['rows'] ) === substr_count( $body, 'class="pncp-tr__link"' ) && false !== strpos( $body, 'Page 2 of' ), wp_json_encode( $page2['rows'][0] ) . ' ' . ( preg_match( '#pncp-tr__pageno">[^<]+#', $body, $mm ) ? $mm[0] : 'no pager' ) );
list( , $body ) = http( tab( '&tr_view=agents&tr_period=7d&tr_country=GR' ) );
t( 'clipped: a filter the daily figures cannot answer says so', false !== strpos( $body, 'pncp-tr__clipped' ) && false !== strpos( $body, 'This filter covers only the last 3 days' ) );
list( , $body ) = http( tab( '&tr_view=agents&tr_period=7d&tr_status=404' ) );
t( 'a status class over 7 days comes from the daily figures (no clipped notice)', false === strpos( $body, 'pncp-tr__clipped' ) && false !== strpos( $body, 'class="pncp-tr__link"' ) );
list( , $body ) = http( tab( '&tr_view=agents' ) );
t( 'no clipped notice for 24 hours', false === strpos( $body, 'pncp-tr__clipped' ) );
list( , $body ) = http( tab( '&tr_view=log&tr_src=wp' ) );
t( 'tr_src=wp: the source selected, no requests of it', false !== strpos( $body, '<option value="wp" selected' ) && false !== strpos( $body, 'No requests in this period' ) );
t( 'source drop-down: only the sources with data (+ Auto)', false === strpos( $pages[''], '<option value="server"' ) && false !== strpos( $pages[''], '<option value="bunny"' ) );
t( 'links keep the filters (bookmarkable)', false !== strpos( http( tab( '&tr_period=7d&tr_status=4xx' ) )[1], 'tr_view=agents&#038;tr_period=7d&#038;tr_status=4xx' ) );

// The links of the traffic alert emails: view, from / to (Unix), status, src, problem, ua.
$from_ts        = time() - 2 * HOUR_IN_SECONDS;
list( , $body ) = http( tab( '&view=raw&from=' . $from_ts . '&to=' . time() . '&status=404&src=bunny' ) );
$want           = PNCP_Traffic::raw( array( 'from' => $from_ts, 'to' => time(), 'status' => '404', 'src' => 'bunny' ), 50 );
t( 'alert link view=raw&from&to&status&src: the requests view with exactly that period', false !== strpos( $body, 'class="is-current" aria-current="page">Requests' ) && count( $want['rows'] ) === substr_count( $body, '<tr class="pncp-tr__row--4' ) && false !== strpos( $body, 'Exact period' ), (string) count( $want['rows'] ) );
list( , $body ) = http( tab( '&view=problems&problem=5xx' ) );
t( 'alert link view=problems&problem=5xx', false !== strpos( $body, 'aria-current="true">Server errors (5xx)' ) );
list( , $body ) = http( tab( '&view=sources' ) );
t( 'alert link view=sources: Sources and settings', false !== strpos( $body, 'class="is-current" aria-current="page">Sources and settings' ) );
list( , $body ) = http( tab( '&view=overview&ua=' . rawurlencode( $py ) ) );
t( 'alert link ua=: filtered by that User-Agent', false !== strpos( $body, 'Remove the filter User-Agent' ) && false !== strpos( $body, '<span class="pncp-ar__kpi-value">8</span> <span class="pncp-ar__kpi-label">requests' ) );

/* ---------- 4. Escaping ---------- */
$all = '';
foreach ( $pages as $body ) {
	$all .= part( $body );
}
foreach ( array( 'log', 'agents', 'problems', 'visitors' ) as $v ) {
	$all .= part( http( tab( '&tr_view=' . $v . '&tr_q=' . rawurlencode( '"><script>alert(9)</script>' ) ) )[1] );
}
t( 'no <script>alert or onerror from the data or the address anywhere', false === stripos( $all, '<script>alert' ) && false === stripos( $all, '<img src=x' ), (string) strpos( $all, '<script>alert' ) );
t( 'the User-Agent and path with <script> are shown escaped', false !== strpos( $all, '&lt;script&gt;alert(&quot;ua&quot;)&lt;/script&gt;' ) || false !== strpos( $all, '&lt;script&gt;alert(&#34;ua&#34;)' ) );
t( 'the escaped path is in the problems table', false !== strpos( $p404, '&lt;script&gt;alert(' ) );

/* ---------- 5. CSV ---------- */
$csv_nonce = wp_create_nonce( PNCP_Traffic_Actions::CSV );
list( $code, $body, , $head ) = http(
	'/wp-admin/admin-post.php',
	array(
		'action'   => PNCP_Traffic_Actions::CSV,
		'_wpnonce' => $csv_nonce,
	)
);
t( 'CSV: 200, text/csv; charset=utf-8', 200 === $code && preg_match( '#^content-type:\s*text/csv;\s*charset=utf-8#mi', $head ), $head );
t( 'CSV: attachment with a dated file name', preg_match( '#^content-disposition:\s*attachment;\s*filename="scrapelock-traffic-[^"]+-' . wp_date( 'Y-m-d' ) . '\.csv"#mi', $head ), $head );
t( 'CSV: no cache, nosniff', preg_match( '#^cache-control:.*no-cache#mi', $head ) && preg_match( '#^x-content-type-options:\s*nosniff#mi', $head ) );
$lines = array_values( array_filter( explode( "\n", trim( $body ) ) ) );
$csv   = array_map( 'str_getcsv', $lines );
$exp24 = 0;
foreach ( array( 1 ) as $unused ) {
	$exp24 = raw_count( 'ts >= ' . (int) $f24['from'] );
}
t( 'CSV: the header and one line per request of the period', 'time' === $csv[0][0] && 'user_agent' === $csv[0][9] && count( $csv ) - 1 >= $exp24 - 2 && count( $csv ) - 1 <= $exp24 + 2, ( count( $csv ) - 1 ) . ' vs ' . $exp24 );
$formula = false;
$xss_ok  = false;
foreach ( $csv as $row ) {
	if ( isset( $row[9] ) && "'=HYPERLINK(\"http://x\",\"y\")" === $row[9] ) {
		$formula = true;
	}
	if ( isset( $row[9] ) && $xss_ua === $row[9] ) {
		$xss_ok = true;
	}
}
t( 'CSV: a formula is neutralized with a leading quote', $formula );
t( 'CSV: the <script> User-Agent is plain data (text/csv, not HTML)', $xss_ok );
list( $code, $body ) = http(
	'/wp-admin/admin-post.php',
	array(
		'action'    => PNCP_Traffic_Actions::CSV,
		'_wpnonce'  => $csv_nonce,
		'tr_status' => '404',
	)
);
$only = array_map( 'str_getcsv', array_slice( array_values( array_filter( explode( "\n", trim( $body ) ) ) ), 1 ) );
t( 'CSV: with the filters of the screen (tr_status=404)', $only && array( '404' ) === array_values( array_unique( array_column( $only, 5 ) ) ) );
t( 'CSV: the export form carries the screen\'s filters', false !== strpos( http( tab( '&tr_view=log&tr_status=404&tr_period=7d' ) )[1], '<input type="hidden" name="tr_status" value="404">' ) );

/* ---------- 6. Nonce and capability ---------- */
list( $code ) = http( tab(), null, 'editor' );
t( 'editor: the tab is refused (403)', 403 === $code, (string) $code );
$ops = array(
	array( 'op' => 'start' ),
	array( 'op' => 'purge', 'confirm' => '1' ),
	array( 'op' => 'test_path', 'path' => '/var/log/nginx/access.log' ),
	array( 'op' => 'block', 'confirm' => '1', 'ua' => $py, 'pattern' => '=' . $py ),
	array( 'op' => 'allow', 'confirm' => '1', 'ua' => $wa, 'pattern' => $wa ),
);
$before = stored();
$count  = raw_count();
foreach ( $ops as $fields ) {
	list( $code ) = post_action( $fields, 'editor' );
	t( 'editor: ' . $fields['op'] . ' refused with 403', 403 === $code, (string) $code );
	list( $code ) = post_action( $fields, 'admin', 'bad-nonce' );
	t( 'admin, wrong nonce: ' . $fields['op'] . ' refused (403)', 403 === $code, (string) $code );
}
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => PNCP_Traffic_Actions::CSV, '_wpnonce' => $csv_nonce ), 'editor' );
t( 'editor: CSV refused with 403', 403 === $code, (string) $code );
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => PNCP_Traffic_Actions::CSV, '_wpnonce' => 'nope' ) );
t( 'admin, wrong nonce: CSV refused (403)', 403 === $code, (string) $code );
t( 'nothing changed by the refused requests', stored() === $before && raw_count() === $count );

/* ---------- 7. Block / Always allow ---------- */

list( , $body ) = http( tab( '&tr_view=ua&tr_key=' . rawurlencode( $py ) . '&tr_act=block' ) );
t( 'Block: the confirmation shows the exact line', false !== strpos( $body, '<code class="pncp-tr__line">=python-requests/2.31.0</code>' ) && false !== strpos( $body, 'name="confirm" value="1" required' ) && false !== strpos( $body, 'Earlier versions' ) );
list( , , $loc ) = post_action( array( 'op' => 'block', 'ua' => $py, 'pattern' => '=' . $py ) );
t( 'Block without the confirmation box: nothing written', 'block_unconfirmed' === query_arg( $loc, 'tr_msg' ) && stored()['bot_list'] === $before['bot_list'], $loc );
list( , , $loc ) = post_action( array( 'op' => 'block', 'confirm' => '1', 'ua' => $py, 'pattern' => 'python' ) );
t( 'Block with a line other than the one confirmed: nothing written', 'block_changed' === query_arg( $loc, 'tr_msg' ) && stored()['bot_list'] === $before['bot_list'], $loc );
list( , , $loc ) = post_action( array( 'op' => 'block', 'confirm' => '1', 'ua' => $py, 'pattern' => '=' . $py ) );
$after = PNCP_Options::parse_list( stored()['bot_list'] );
t( 'Block: exactly one line added, “=python-requests/2.31.0”', 'block_added' === query_arg( $loc, 'tr_msg' ) && count( $after ) === count( PNCP_Options::parse_list( $before['bot_list'] ) ) + 1 && '=python-requests/2.31.0' === end( $after ), $loc . ' ' . wp_json_encode( $after ) );
$baks = backups();
t( 'Block: an earlier version saved first (with the old bot list) and offered as Undo', 'traffic_block' === $baks[0]['reason'] && $baks[0]['settings']['bot_list'] === $before['bot_list'] && query_arg( $loc, 'pncp_undo' ) === $baks[0]['id'], $baks[0]['reason'] . ' ' . $loc . ' ' . (int) ( $baks[0]['settings']['bot_list'] === $before['bot_list'] ) );
t( 'Block: other settings unchanged', array_diff_key( stored(), array( 'bot_list' => 1 ) ) == array_diff_key( $before, array( 'bot_list' => 1 ) ) ); // phpcs:ignore Universal.Operators.StrictComparisons -- Same values.
list( , $body ) = http( tab( '&tr_view=ua&tr_key=' . rawurlencode( $py ) . '&tr_msg=block_added&pncp_undo=' . $baks[0]['id'] ) );
t( 'Block: the notice with Undo, and the User-Agent now shows as blocked', false !== strpos( $body, 'was added to the bot list' ) && false !== strpos( $body, 'value="restore"' ) && false !== strpos( $body, 'Blocked by the bot list: matches “python-requests/2.31.0”' ) );
list( , , $loc ) = post_action( array( 'op' => 'block', 'confirm' => '1', 'ua' => $py, 'pattern' => '=' . $py ) );
t( 'Block again: nothing added (already blocked)', 'block_exists' === query_arg( $loc, 'tr_msg' ) && count( PNCP_Options::parse_list( stored()['bot_list'] ) ) === count( $after ) );
// A search engine: the second confirmation.
list( , $body ) = http( tab( '&tr_view=ua&tr_key=' . rawurlencode( $gbot ) . '&tr_act=block' ) );
t( 'Block Googlebot: a warning and a second, required box', false !== strpos( $body, 'This is a search engine' ) && false !== strpos( $body, 'name="confirm_extra" value="1" required' ) );
$pattern = PNCP_Traffic_Actions::block_pattern( $gbot );
$list    = stored()['bot_list'];
list( , , $loc ) = post_action( array( 'op' => 'block', 'confirm' => '1', 'ua' => $gbot, 'pattern' => $pattern ) );
t( 'Block Googlebot without the second box: nothing written', 'block_extra' === query_arg( $loc, 'tr_msg' ) && stored()['bot_list'] === $list, $loc );
list( , $body ) = http( tab( '&tr_view=ua&tr_key=' . rawurlencode( $gbot ) ) );
t( 'Googlebot: no “Always allow” (search engines are let in from their addresses)', false === strpos( $body, 'tr_act=allow' ) );
list( , , $loc ) = post_action( array( 'op' => 'allow', 'confirm' => '1', 'ua' => $gbot, 'pattern' => $gbot ) );
t( 'Allow Googlebot by POST: refused', 'allow_crawler' === query_arg( $loc, 'tr_msg' ) && stored()['allow_list'] === $before['allow_list'] );
// The administrator's own browser.
list( , $body ) = http( tab( '&tr_view=ua&tr_key=' . rawurlencode( T_UA ) ) );
t( 'own browser: no Block button, and why', false === strpos( $body, 'tr_act=block' ) && false !== strpos( $body, 'would block your own browser' ) );
list( , , $loc ) = post_action( array( 'op' => 'block', 'confirm' => '1', 'confirm_extra' => '1', 'ua' => T_UA, 'pattern' => '=' . T_UA ) );
t( 'own browser: Block by POST refused', 'block_own' === query_arg( $loc, 'tr_msg' ) && stored()['bot_list'] === $list );
// The <script> User-Agent: a product name, never the markup.
$xp = PNCP_Traffic_Actions::block_pattern( $xss_ua );
t( 'Block of the <script> User-Agent: a safe product name (“EvilBot/” or similar), no markup', '' !== $xp && false === strpos( $xp, '<' ) && PNCP_Bots::ua_in_list( $xss_ua, array( $xp ) ) && ! PNCP_Bots::ua_in_list( $chrome, array( $xp ) ), $xp );
t( 'Block of a browser needs the second box; never a pattern that matches other browsers', 'browser' === PNCP_Traffic_Actions::block_check( $chrome )['extra'] && in_array( PNCP_Traffic_Actions::block_pattern( $chrome ), array( '', '=' . $chrome ), true ) && 'browser' === PNCP_Traffic_Actions::block_check( 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0' )['extra'] && '=Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0' === PNCP_Traffic_Actions::block_pattern( 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0' ) );
// Always allow.
$allow_before = PNCP_Options::parse_list( stored()['allow_list'] );
list( , $body ) = http( tab( '&tr_view=ua&tr_key=' . rawurlencode( $wa ) . '&tr_act=allow' ) );
t( 'Allow: the confirmation shows the exact line', false !== strpos( $body, '<code class="pncp-tr__line">WhatsApp/2.23.20.0</code>' ) );
list( , , $loc ) = post_action( array( 'op' => 'allow', 'confirm' => '1', 'ua' => $wa, 'pattern' => $wa ) );
$allow_after = PNCP_Options::parse_list( stored()['allow_list'] );
t( 'Allow: exactly one line added', 'allow_added' === query_arg( $loc, 'tr_msg' ) && count( $allow_after ) === count( $allow_before ) + 1 && $wa === end( $allow_after ), $loc );
t( 'Allow: an earlier version saved first', 'traffic_allow' === backups()[0]['reason'] );
list( , , $loc ) = post_action( array( 'op' => 'allow', 'confirm' => '1', 'ua' => $wa, 'pattern' => $wa ) );
t( 'Allow again: nothing added', 'allow_exists' === query_arg( $loc, 'tr_msg' ) && count( PNCP_Options::parse_list( stored()['allow_list'] ) ) === count( $allow_after ) );
list( , , $loc ) = post_action( array( 'op' => 'allow', 'confirm' => '1', 'ua' => $chrome, 'pattern' => PNCP_Bot_Match::service_pattern( $chrome ) ) );
t( 'Allow a browser: refused', 'allow_browser' === query_arg( $loc, 'tr_msg' ) );
// Undo puts the bot list back (the existing restore).
$undo = backups()[1]['id'];
http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_settings', 'op' => 'restore', 'id' => $undo, '_wpnonce' => wp_create_nonce( 'pncp_settings' ) ) );
t( 'Undo of the Block: the bot list as before', stored()['bot_list'] === $before['bot_list'] );

/* ---------- 8. Test this path ---------- */
list( , , $loc ) = post_action( array( 'op' => 'test_path', 'path' => 'relative/access.log' ) );
list( , $body )  = http( '/wp-admin/options-general.php?' . (string) wp_parse_url( $loc, PHP_URL_QUERY ) );
t( 'Test this path: a relative path is refused with the sentence', 'tested' === query_arg( $loc, 'tr_msg' ) && false !== strpos( $body, esc_html( PNCP_Traffic_Log::refusal_text( 'not_absolute' ) ) ) );
$log = $tmp . '/access.log';
$tz  = wp_date( 'd/M/Y:H:i:s O' );
file_put_contents( $log, '203.0.113.9 - - [' . $tz . '] "GET /hello/ HTTP/1.1" 200 512 "-" "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"' . "\n" . '203.0.113.9 - - [' . $tz . '] "GET /<b>x</b> HTTP/1.1" 404 10 "-" "curl/8.0"' . "\n" );
$direct = PNCP_Traffic::test_log_path( $log );
list( , , $loc ) = post_action( array( 'op' => 'test_path', 'path' => $log ) );
list( , $body )  = http( '/wp-admin/options-general.php?' . (string) wp_parse_url( $loc, PHP_URL_QUERY ) );
t( 'Test this path: a readable access log', 'ok' !== $direct['code'] || ( false !== strpos( $body, 'The access log can be read.' ) && false !== strpos( $body, '2 of 2 lines read as requests' ) ), $direct['code'] );
t( 'Test this path: the sample is escaped, nothing saved', false === strpos( part( $body ), '<b>x</b>' ) && '' === stored()['traffic_log_path'] );

/* ---------- 9. The settings form ---------- */
list( , , $loc ) = http(
	'/wp-admin/options.php',
	array(
		'option_page' => PNCP_Admin::GROUP,
		'action'      => 'update',
		'_wpnonce'    => wp_create_nonce( PNCP_Admin::GROUP . '-options' ),
		PNCP_OPTION   => array(
			'_sections'        => array( 'traffic' ),
			'traffic'          => '1',
			'traffic_raw_days' => '5',
			'traffic_days'     => '120',
			'traffic_ip_mode'  => 'masked',
			'traffic_log_path' => '',
		),
	)
);
$now = stored();
t( 'settings form: the traffic section saved', 5 === (int) $now['traffic_raw_days'] && 120 === (int) $now['traffic_days'] && 'masked' === $now['traffic_ip_mode'] && 0 === (int) $now['traffic_wp'], $loc );
t( 'settings form: nothing outside the section changed', $now['bot_list'] === $before['bot_list'] && (int) $now['enabled'] === (int) $before['enabled'] && $now['allow_list'] === stored()['allow_list'] );
settings( array( 'traffic_raw_days' => 3, 'traffic_days' => 90, 'traffic_ip_mode' => 'full' ) );

/* ---------- 10. Delete collected traffic ---------- */
list( , $body ) = http( tab( '&tr_view=settings&tr_confirm=purge' ) );
t( 'Delete: a confirmation step with a required box', false !== strpos( $body, 'name="confirm" value="1" required' ) && false !== strpos( $body, 'cannot be undone' ) );
$n = raw_count();
list( , , $loc ) = post_action( array( 'op' => 'purge' ) );
t( 'Delete without the box: nothing deleted', 'purge_unconfirmed' === query_arg( $loc, 'tr_msg' ) && raw_count() === $n && $n > 0 );
list( , , $loc ) = post_action( array( 'op' => 'purge', 'confirm' => '1' ) );
t( 'Delete with the box: every request deleted, collection stays on', 'purged' === query_arg( $loc, 'tr_msg' ) && 0 === raw_count() && ! empty( stored()['traffic'] ) );

/* ---------- 11. Off, and Start collecting ---------- */
settings( array( 'traffic' => 0, 'traffic_wp' => 0, 'traffic_log_path' => '' ) );
list( $code, $body ) = http( tab() );
$off = part( $body );
t( 'off: 200, the explanation, the sources found and one “Start collecting”', 200 === $code && ! php_errors( $body ) && false !== strpos( $off, 'id="pncp-tr-start"' ) && 1 === substr_count( $off, 'value="start"' ) && false !== strpos( $off, 'Sources found' ) && false !== strpos( $off, 'Each request is kept 3 days' ) );
t( 'off: no data views, but the settings form, Test this path and Delete', false === strpos( $off, 'pncp-tr__nav' ) && false !== strpos( $off, '[_sections][]" value="traffic"' ) && false !== strpos( $off, 'id="pncp-tr-test-path"' ) && false !== strpos( $off, 'Delete collected traffic' ) );
$rec  = PNCP_Traffic_Actions::recommended();
$prev = stored();
list( , , $loc ) = post_action( array( 'op' => 'start' ) );
$now  = stored();
$diff = array();
foreach ( $now as $k => $v ) {
	if ( ! array_key_exists( $k, $prev ) || $prev[ $k ] !== $v ) {
		$diff[] = $k;
	}
}
sort( $diff );
$want = array_merge( array( 'traffic' ), array_keys( $rec['changes'] ) );
sort( $want );
t( 'Start collecting: traffic on plus the recommended source, nothing else', 'started' === query_arg( $loc, 'tr_msg' ) && 1 === (int) $now['traffic'] && $want === $diff, wp_json_encode( $diff ) . ' ' . wp_json_encode( $rec ) );
t( 'Start collecting: without Bunny or a log, WordPress records', 'wp' !== $rec['source'] || 1 === (int) $now['traffic_wp'] );
t( 'Start collecting: the tables exist and the run is scheduled', PNCP_Traffic::ready() && false !== wp_next_scheduled( PNCP_Traffic::CRON ) );
list( $code, $body ) = http( tab( '&tr_msg=started' ) );
t( 'after Start: the views and the notice, no PHP notice on an empty store', 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'pncp-tr__nav' ) && false !== strpos( $body, 'Collecting traffic' ) );

/* ---------- Clean up ---------- */
PNCP_Traffic::purge_all();
update_option( PNCP_OPTION, $saved );
false === $saved_bak ? delete_option( 'pncp_settings_backups' ) : update_option( 'pncp_settings_backups', $saved_bak, false );
false === $saved_g ? delete_option( PNCP_Ip::LISTS_OPTION . '_google' ) : update_option( PNCP_Ip::LISTS_OPTION . '_google', $saved_g );
false === $saved_u ? delete_option( PNCP_Ip::LISTS_OPTION . '_updated' ) : update_option( PNCP_Ip::LISTS_OPTION . '_updated', $saved_u, false );
update_option( 'timezone_string', $saved_z );
delete_transient( PNCP_Traffic_Actions::TEST . $admin->ID );
@unlink( $log );
@rmdir( $tmp );
wp_delete_user( $editor->ID );
PNCP_Options::flush();

echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
