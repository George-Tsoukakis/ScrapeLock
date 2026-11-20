<?php
/**
 * ScrapeLock 3.12 — Traffic (PNCP_Traffic): the data layer, on a real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_traffic.php
 *
 * 1. Settings: defaults, ranges, the access log path refused when relative, with "..", a stream wrapper or not an
 *    access log; the upgrade adds the keys without changing any stored value; export / import keeps them.
 * 2. Off: no hook, no table, nothing stored.
 * 3. User-Agents: ~30 classified (browser, verified / fake search engine with a stored official list, AI, SEO,
 *    previews, services, scripts, empty, other).
 * 4. Bunny: a realistic line through PNCP_Bunny::parse_line() and ingest(), and the real import path
 *    (PNCP_Bunny::import() with a mocked log API, pre_http_request).
 * 5. The server log: combined / vhost / Nginx lines with the request time and X-Forwarded-For (behind a trusted
 *    proxy or a Cloudflare edge only), cursor resume, a line still being written, rotation to .1 and .1.gz, the
 *    path checks of "Test this path" (also with open_basedir and a symlink, in a child PHP).
 * 6. The WordPress source: a missing page records a 404 (HTTP), nothing when it is off, nothing for the loopback.
 * 7. Queries: overview, top (every dimension, filters, paging, order), problems (every type), detail, raw, CSV
 *    (formula injection neutralized), the aggregates over a range longer than the raw window (rows already
 *    deleted from the raw table), clipping of filters the aggregates cannot answer.
 * 8. Retention, caps (rows per run, raw rows, keys per day), masked IPs, sources, purge, uninstall.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/template.php'; // add_settings_error(), as on the settings page.

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** Stores settings as they are (no form checks), and forgets the request caches. */
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	wp_cache_delete( 'alloptions', 'options' );
	PNCP_Options::flush();
	PNCP_Ip::reset();
	PNCP_Traffic::reset();
}

/** A request with curl: [code, body]. */
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
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_TIMEOUT        => 30,
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $out );
}

function browser( $ip ) {
	return array(
		'X-Test-IP'       => $ip,
		'X-Forwarded-For' => $ip,
		'User-Agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36',
		'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language' => 'el-GR,el;q=0.9',
		'Accept-Encoding' => 'gzip, deflate, br',
	);
}

/** Raw rows of a source as arrays. */
function raw_rows( $where = '1 = 1' ) {
	global $wpdb;
	return (array) $wpdb->get_results( 'SELECT * FROM ' . PNCP_Traffic::table( 'raw' ) . ' WHERE ' . $where . ' ORDER BY id', ARRAY_A ); // phpcs:ignore
}

function raw_count( $where = '1 = 1' ) {
	global $wpdb;
	return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . PNCP_Traffic::table( 'raw' ) . ' WHERE ' . $where ); // phpcs:ignore
}

function table_exists( $table ) {
	global $wpdb;
	return 0 === strcasecmp( (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ), $table );
}

function no_file_sync() {
	delete_option( 'pncp_upgrade_files' );
	wp_clear_scheduled_hook( 'pncp_upgrade_files' );
}

/** A Bunny log line. */
function bunny_line( $cache, $status, $ts_ms, $bytes, $ip, $referer, $url, $ua, $country = 'GR', $id = 'id' ) {
	return implode( '|', array( $cache, $status, $ts_ms, $bytes, '4431349', $ip, $referer, $url, 'DE', $ua, $id, $country ) );
}

/** Takes rows into the store: [ts offset in seconds, ip, status, path, ua, extra fields]. */
function feed( $src, $rows ) {
	foreach ( $rows as $r ) {
		PNCP_Traffic::ingest( array_merge( array( 'ts' => time() - $r[0], 'ip' => $r[1], 'status' => $r[2], 'path' => $r[3], 'ua' => $r[4] ), isset( $r[5] ) ? $r[5] : array() ), $src );
	}
	PNCP_Traffic::flush();
}

// The SQLite drop-in of the CI cannot drop tables: there a table left by an earlier run may exist (empty).
$sqlite  = false !== stripos( get_class( $GLOBALS['wpdb'] ), 'sqlite' );
$chrome  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
$saved   = get_option( PNCP_OPTION );
$saved_v = get_option( 'pncp_version' );
$had_db  = get_option( PNCP_Traffic::DB_OPTION, false );
$saved_t = get_option( PNCP_Traffic::STATE, false );
$saved_b = get_option( 'pncp_bunny_state', false );
$saved_z = get_option( 'timezone_string' );
$lists   = array();
foreach ( array( 'google', 'bing', 'cloudflare', 'openai_search', 'anthropic' ) as $name ) {
	$lists[ $name ] = get_option( PNCP_Ip::LISTS_OPTION . '_' . $name, false );
}
$saved_u = get_option( PNCP_Ip::LISTS_OPTION . '_updated', false );
$tmp     = rtrim( sys_get_temp_dir(), '/' ) . '/pncp-traffic-' . getmypid();
@mkdir( $tmp, 0700, true );
update_option( 'timezone_string', 'Europe/Athens' );

/* ---------- 1. Settings ---------- */

$d = PNCP_Options::defaults();
t( 'defaults: traffic 0, traffic_wp 0, path "", raw days 3, days 90, ip mode full', 0 === $d['traffic'] && 0 === $d['traffic_wp'] && '' === $d['traffic_log_path'] && 3 === $d['traffic_raw_days'] && 90 === $d['traffic_days'] && 'full' === $d['traffic_ip_mode'] );
t( 'a new install also starts with traffic off', ! isset( PNCP_Options::new_install()['traffic'] ) );
t( 'every new key belongs to the "traffic" section and has a label', array( 'traffic', 'traffic_wp', 'traffic_log_path', 'traffic_raw_days', 'traffic_days', 'traffic_ip_mode', 'traffic_alerts', 'traffic_alert_email' ) === PNCP_Options::sections()['traffic'] && ! array_diff( PNCP_Options::sections()['traffic'], array_keys( PNCP_Setting_Labels::all() ) ) );
$clean = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic' => '1', 'traffic_raw_days' => '99', 'traffic_days' => '2', 'traffic_ip_mode' => 'weird' ) ) );
t( 'sanitize: ranges 1–14 and 7–365, an unknown IP mode is "full"', 1 === $clean['traffic'] && 14 === $clean['traffic_raw_days'] && 7 === $clean['traffic_days'] && 'full' === $clean['traffic_ip_mode'], wp_json_encode( array_intersect_key( $clean, $d ) ) );
$log = $tmp . '/access.log';
file_put_contents( $log, '' );
global $wp_settings_errors;
foreach ( array(
	'relative'  => 'logs/access.log',
	'dotdot'    => $tmp . '/../etc/access.log',
	'wrapper'   => 'php://filter/resource=' . $log,
	'phar'      => 'phar://' . $log,
	'not a log' => '/etc/passwd',
	'htaccess'  => $tmp . '/.htaccess',
	'php file'  => $tmp . '/access.php',
) as $what => $path ) {
	$wp_settings_errors = array();
	$clean              = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic_log_path' => $path ) ) );
	t( "sanitize: the access log path is not saved ($what), with a message", '' === $clean['traffic_log_path'] && $wp_settings_errors && 'pncp_traffic_log_path' === $wp_settings_errors[0]['code'], $clean['traffic_log_path'] );
}
$wp_settings_errors = array();
$clean              = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic_log_path' => $log ) ) );
t( 'sanitize: an absolute access.log path is saved', $log === $clean['traffic_log_path'] && ! $wp_settings_errors, wp_json_encode( $wp_settings_errors ) );
$clean = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic_log_path' => $tmp . '/nginx-access.log.1' ) ) );
t( 'sanitize: a rotated log name is fine too', $tmp . '/nginx-access.log.1' === $clean['traffic_log_path'] );
$wp_settings_errors = array();

// The upgrade from 3.11.0: the keys are added, nothing else changes.
$old = array_diff_key( PNCP_Options::stored(), array_flip( PNCP_Options::sections()['traffic'] ) );
$old['rate_limit'] = 77;
update_option( PNCP_OPTION, $old );
update_option( 'pncp_version', '3.11.0' );
PNCP_Options::flush();
// The other tables' dbDelta() on the SQLite drop-in prints errors about composite keys (not Traffic's: it does not
// run dbDelta() on a current schema); they are kept out of this test's output.
$level    = error_reporting( error_reporting() & ~E_DEPRECATED );
$suppress = $GLOBALS['wpdb']->suppress_errors( true );
ob_start();
pncp_upgrade();
ob_end_clean();
$GLOBALS['wpdb']->suppress_errors( $suppress );
error_reporting( $level );
no_file_sync();
wp_cache_delete( 'alloptions', 'options' );
$up   = get_option( PNCP_OPTION );
$diff = array();
foreach ( $old as $k => $v ) {
	if ( (string) $v !== (string) $up[ $k ] ) {
		$diff[] = $k;
	}
}
t( 'upgrade from 3.11.0: the traffic keys are stored, off', isset( $up['traffic'], $up['traffic_log_path'], $up['traffic_days'] ) && 0 === (int) $up['traffic'] && 3 === (int) $up['traffic_raw_days'], wp_json_encode( array_intersect_key( (array) $up, $d ) ) );
t( 'upgrade from 3.11.0: no stored value changed', ! $diff && 77 === (int) $up['rate_limit'], implode( ',', $diff ) );
if ( false === $had_db ) {
	t( 'upgrade with traffic off creates no table', ( ! table_exists( PNCP_Traffic::table( 'raw' ) ) || $sqlite ) && false === get_option( PNCP_Traffic::DB_OPTION, false ) );
}
update_option( PNCP_OPTION, $saved );
update_option( 'pncp_version', $saved_v );
PNCP_Options::flush();

// Export and import.
settings(
	array(
		'traffic'          => 0,
		'traffic_wp'       => 1,
		'traffic_log_path' => $log,
		'traffic_raw_days' => 5,
		'traffic_days'     => 30,
		'traffic_ip_mode'  => 'masked',
	)
);
$export = PNCP_Settings_Io::export();
t( 'export: the traffic keys are in the file', 1 === (int) $export['settings']['traffic_wp'] && $log === $export['settings']['traffic_log_path'] && 5 === (int) $export['settings']['traffic_raw_days'] && 'masked' === $export['settings']['traffic_ip_mode'] );
settings( array_fill_keys( array( 'traffic_wp' ), 0 ) + array( 'traffic_log_path' => '', 'traffic_raw_days' => 3, 'traffic_days' => 90, 'traffic_ip_mode' => 'full' ) );
$parsed   = PNCP_Settings_Io::parse( wp_json_encode( $export ) );
$prepared = PNCP_Settings_Io::prepare( $parsed['settings'] );
PNCP_Settings_Io::apply( $prepared, 'import' );
settings( array() );
$s = PNCP_Options::stored();
t( 'import: the traffic keys come back as exported', ! $parsed['ignored'] && 1 === (int) $s['traffic_wp'] && $log === $s['traffic_log_path'] && 5 === (int) $s['traffic_raw_days'] && 30 === (int) $s['traffic_days'] && 'masked' === $s['traffic_ip_mode'], wp_json_encode( $parsed['ignored'] ) );
$bad                             = $export;
$bad['settings']['traffic_log_path'] = 'php://input';
$prepared                        = PNCP_Settings_Io::prepare( PNCP_Settings_Io::parse( wp_json_encode( $bad ) )['settings'] );
t( 'import: a stream wrapper path is refused (the stored one stays), with a message', $log === $prepared['settings']['traffic_log_path'] && $prepared['messages'] );
update_option( PNCP_OPTION, $saved );
PNCP_Options::flush();

/* ---------- 2. Off ---------- */

settings( array( 'traffic' => 0, 'traffic_wp' => 1 ) );
remove_action( 'pncp_bunny_log_line', array( 'PNCP_Traffic', 'bunny_line' ) );
remove_action( 'shutdown', array( 'PNCP_Traffic', 'wp_shutdown' ), 5 );
PNCP_Traffic::init();
t( 'off: init() hooks neither the Bunny lines nor the shutdown writer', false === has_action( 'pncp_bunny_log_line', array( 'PNCP_Traffic', 'bunny_line' ) ) && false === has_action( 'shutdown', array( 'PNCP_Traffic', 'wp_shutdown' ) ) );
t( 'off: enabled() is false', ! PNCP_Traffic::enabled() );
if ( false === $had_db ) {
	t( 'off: no table exists', ( ! table_exists( PNCP_Traffic::table( 'raw' ) ) || $sqlite ) && ! PNCP_Traffic::ready() );
}

/* ---------- Turn it on ---------- */

settings(
	array(
		'traffic'          => 1,
		'traffic_wp'       => 0,
		'traffic_log_path' => '',
		'traffic_raw_days' => 3,
		'traffic_days'     => 90,
		'traffic_ip_mode'  => 'full',
	)
);
PNCP_Traffic::maybe_schedule();
t( 'on: the tables are created and the run is scheduled', PNCP_Traffic::ready() && table_exists( PNCP_Traffic::table( 'raw' ) ) && table_exists( PNCP_Traffic::table( 'hour' ) ) && table_exists( PNCP_Traffic::table( 'day' ) ) && table_exists( PNCP_Traffic::table( 'err' ) ) && wp_next_scheduled( PNCP_Traffic::CRON ) );
PNCP_Traffic::init();
t( 'on: init() hooks the Bunny lines', false !== has_action( 'pncp_bunny_log_line', array( 'PNCP_Traffic', 'bunny_line' ) ) );
PNCP_Traffic::purge_all();

/* ---------- 3. User-Agents ---------- */

PNCP_Ip::store_list( 'google', array( '66.249.64.0/19' ) );
PNCP_Ip::store_list( 'bing', array( '157.55.39.0/24' ) );
PNCP_Ip::store_list( 'openai_search', array( '20.42.10.176/28' ) );
PNCP_Ip::reset();
PNCP_Traffic_Ua::reset();
$cases = array(
	array( $chrome, '', 'browser', 'Chrome' ),
	array( 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1', '', 'browser', 'Safari' ),
	array( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0', '', 'browser', 'Firefox' ),
	array( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0', '', 'browser', 'Edge' ),
	array( 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36', '', 'browser', 'Samsung Internet' ),
	array( 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', '66.249.66.1', 'verified_bot', 'Googlebot' ),
	array( 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', '203.0.113.5', 'fake_bot', 'Googlebot' ),
	array( 'Googlebot-Image/1.0', '66.249.66.2', 'verified_bot', 'Googlebot-Image' ),
	array( 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', '157.55.39.10', 'verified_bot', 'bingbot' ),
	array( 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', '198.51.100.20', 'fake_bot', 'bingbot' ),
	array( 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)', '198.51.100.21', 'verified_bot', 'YandexBot' ),
	array( 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)', '198.51.100.22', 'ai_bot', 'GPTBot' ),
	array( 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)', '', 'ai_bot', 'ClaudeBot' ),
	array( 'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)', '20.42.10.180', 'ai_bot', 'OAI-SearchBot' ),
	array( 'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)', '198.51.100.23', 'fake_bot', 'OAI-SearchBot' ),
	array( 'Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)', '', 'ai_bot', 'Bytespider' ),
	array( 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)', '', 'seo_bot', 'AhrefsBot' ),
	array( 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)', '', 'seo_bot', 'SemrushBot' ),
	array( 'WhatsApp/2.23.20.0', '', 'preview', 'WhatsApp' ),
	array( 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)', '', 'preview', 'facebookexternalhit' ),
	array( 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Viber/20.3.0', '', 'preview', 'Viber' ),
	array( 'TelegramBot (like TwitterBot)', '', 'preview', 'TelegramBot' ),
	array( 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)', '', 'preview', 'Slackbot-LinkExpanding' ),
	array( 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)', '', 'preview', 'Discordbot' ),
	array( 'WP Rocket/Preload', '', 'service', 'WP Rocket' ),
	array( 'Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)', '', 'service', 'UptimeRobot' ),
	array( 'WordPress/6.7; https://pharmacyneeds.gr', '', 'service', 'WordPress' ),
	array( 'OneSignal/1.0', '', 'service', 'OneSignal' ),
	array( 'curl/8.5.0', '', 'script', 'curl' ),
	array( 'python-requests/2.31.0', '', 'script', 'python-requests' ),
	array( 'Go-http-client/2.0', '', 'script', 'Go-http-client' ),
	array( 'Wget/1.21.4', '', 'script', 'Wget' ),
	array( 'axios/1.6.2', '', 'script', 'axios' ),
	array( 'node-fetch/1.0 (+https://github.com/bitinn/node-fetch)', '', 'script', 'node-fetch' ),
	array( 'okhttp/4.12.0', '', 'script', 'okhttp' ),
	array( 'Java/17.0.2', '', 'script', 'Java' ),
	array( 'libwww-perl/6.72', '', 'script', 'libwww-perl' ),
	array( 'Scrapy/2.11.0 (+https://scrapy.org)', '', 'script', 'Scrapy' ),
	array( 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36', '', 'script', 'HeadlessChrome' ),
	array( '', '', 'empty', '' ),
	array( '-', '', 'empty', '' ),
	array( 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)', '', 'other', 'Baiduspider' ),
	array( 'SomeCustomCrawler/1.0', '', 'other', 'SomeCustomCrawler' ),
	array( 'MyApp/3.2 (iOS)', '', 'other', 'MyApp' ),
);
$wrong = array();
foreach ( $cases as $c ) {
	$got = PNCP_Traffic::classify_ua( $c[0], $c[1] );
	if ( $got['family'] !== $c[2] || $got['name'] !== $c[3] ) {
		$wrong[] = $c[0] . ' @' . $c[1] . ' => ' . $got['family'] . '/' . $got['name'] . ' (want ' . $c[2] . '/' . $c[3] . ')';
	}
}
t( 'classify_ua: ' . count( $cases ) . ' User-Agents', ! $wrong, implode( ' | ', $wrong ) );
$g = PNCP_Traffic::classify_ua( 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' );
t( 'classify_ua: without an IP a search engine counts as verified (no DNS)', 'verified_bot' === $g['family'] );
t( 'classify_ua: anonymized logs never call a crawler fake', 'verified_bot' === PNCP_Traffic_Ua::classify( 'Mozilla/5.0 (compatible; Googlebot/2.1)', '203.0.113.0', true )['family'] );
t( 'classify_ua: deterministic (same answer twice)', PNCP_Traffic::classify_ua( $chrome ) === PNCP_Traffic::classify_ua( $chrome ) );
t( 'family labels for every family', array() === array_diff( PNCP_Traffic_Ua::FAMILIES, array_keys( PNCP_Traffic_Ua::labels() ) ) );

/* ---------- 4. Bunny ---------- */

PNCP_Traffic::reset();
$now_ms = time() * 1000;
$sample = 'HIT|200|1732099200000|5120|4431349|198.51.100.7|https://www.google.com/|https://pharmacyneeds.gr/shop/|DE|' . $chrome . '|abc123|GR';
$row    = PNCP_Bunny::parse_line( $sample );
t( 'Bunny: the sample line from 2024 is refused (older than the raw window)', is_array( $row ) && false === PNCP_Traffic::ingest( $row, 'bunny' ) && 1 === PNCP_Traffic::dropped()['old'] );
$row = PNCP_Bunny::parse_line( bunny_line( 'HIT', 200, $now_ms, 5120, '198.51.100.7', 'https://www.google.com/search?q=pharmacy', 'https://pharmacyneeds.gr/shop/?utm_source=x', $chrome, 'GR', 'abc123' ) );
t( 'Bunny: a current line is taken', PNCP_Traffic::ingest( $row, 'bunny' ) );
$row = PNCP_Bunny::parse_line( bunny_line( 'MISS', 404, $now_ms, 0, '198.51.100.8', '-', 'https://pharmacyneeds.gr/no-such-page/?ref=feed', 'python-requests/2.31.0', 'US', 'abc124' ) );
PNCP_Traffic::ingest( $row, 'bunny' );
PNCP_Traffic::flush();
$rows = raw_rows( "src = 'bunny'" );
$a    = isset( $rows[0] ) ? $rows[0] : array();
$b    = isset( $rows[1] ) ? $rows[1] : array();
t( 'Bunny: the stored row: time, IP, country, edge, status, bytes, cache', $a && abs( (int) $a['ts'] - time() ) < 5 && '198.51.100.7' === $a['ip'] && 'GR' === $a['country'] && 'DE' === $a['edge'] && 200 === (int) $a['status'] && 5120 === (int) $a['bytes'] && 'HIT' === $a['cache'] && 1 === (int) $a['hit'], wp_json_encode( $a ) );
t( 'Bunny: the path without its query; the query dropped for a 200', '/shop/' === $a['path'] && '' === $a['query'] && PNCP_Traffic::hash( '/shop/' ) === $a['path_hash'] );
t( 'Bunny: the referrer is scheme, host and path only', 'https://www.google.com/search' === $a['referer'] );
t( 'Bunny: the User-Agent, its hash, its family, the page type', $chrome === $a['ua'] && PNCP_Traffic::hash( $chrome ) === $a['ua_hash'] && 'browser' === $a['fam'] && 'p' === $a['ptype'] );
t( 'Bunny: a 404 keeps its query, MISS is a miss', '/no-such-page/' === $b['path'] && 'ref=feed' === $b['query'] && 0 === (int) $b['hit'] && 'script' === $b['fam'] && '' === $b['referer'], wp_json_encode( $b ) );

// The real import path, with the log API mocked.
PNCP_Traffic::purge_all();
$zone  = '424242';
$lines = array();
for ( $i = 0; $i < 30; $i++ ) {
	$lines[] = bunny_line( 0 === $i % 3 ? 'MISS' : 'HIT', 0 === $i % 10 ? 404 : 200, $now_ms - $i * 1000, 1000 + $i, '45.159.10.' . ( $i % 5 + 1 ), 'https://www.google.com/', 'https://pharmacyneeds.gr/product-' . ( $i % 4 ) . '/', $chrome, 'GR', 'imp' . $i );
}
$lines[] = bunny_line( 'HIT', 200, 1732099200000, 100, '45.159.10.9', '-', 'https://pharmacyneeds.gr/old/', $chrome, 'GR', 'old' );
$mock    = static function ( $pre, $args, $url ) use ( $lines ) {
	if ( false === strpos( $url, 'mock-traffic-log.test' ) ) {
		return $pre;
	}
	parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $q );
	$start = isset( $q['start'] ) ? (int) $q['start'] : 0;
	$end   = isset( $q['end'] ) ? (int) $q['end'] : count( $lines );
	$part  = array_slice( $lines, $start, max( 0, $end - $start ) );
	return array(
		'headers'  => array(),
		'body'     => $part ? implode( "\n", $part ) . "\n" : '',
		'response' => array(
			'code'    => 200,
			'message' => 'OK',
		),
		'cookies'  => array(),
		'filename' => null,
	);
};
$log_base = static function () {
	return 'http://mock-traffic-log.test';
};
add_filter( 'pre_http_request', $mock, 10, 3 );
add_filter( 'pncp_bunny_log_base', $log_base );
delete_option( 'pncp_bunny_state' );
$res = PNCP_Bunny::import(
	array(
		'zone'  => $zone,
		'token' => 'test-key',
	),
	microtime( true ) + 20
);
t( 'import: the mocked log was read', '' === $res['error'] && $res['lines'] >= 30, wp_json_encode( $res ) );
t( 'import: every current line is in the traffic table (the old one is not)', 30 === raw_count( "src = 'bunny'" ) && 0 === raw_count( "path = '/old/'" ), (string) raw_count( "src = 'bunny'" ) );
t( 'import: 404s and misses as in the log', 3 === raw_count( "src = 'bunny' AND status = 404" ) && 10 === raw_count( "src = 'bunny' AND hit = 0" ) );
// Off: the same import stores nothing.
settings( array( 'traffic' => 0 ) );
remove_action( 'pncp_bunny_log_line', array( 'PNCP_Traffic', 'bunny_line' ) );
PNCP_Traffic::init();
delete_option( 'pncp_bunny_state' );
PNCP_Bunny::import(
	array(
		'zone'  => $zone,
		'token' => 'test-key',
	),
	microtime( true ) + 20
);
t( 'import with traffic off: nothing more is stored', 30 === raw_count( "src = 'bunny'" ) );
remove_filter( 'pre_http_request', $mock, 10 );
remove_filter( 'pncp_bunny_log_base', $log_base );
settings( array( 'traffic' => 1 ) );
PNCP_Traffic::init();

/* ---------- 5. The server log ---------- */

$tz   = new DateTimeZone( '+0200' );
$when = static function ( $ago ) use ( $tz ) {
	$d = new DateTime( '@' . ( time() - $ago ) );
	$d->setTimezone( $tz );
	return $d->format( 'd/M/Y:H:i:s O' );
};
$s  = PNCP_Options::get();
$p1 = PNCP_Traffic_Log::parse_line( '203.0.113.10 - - [' . $when( 30 ) . '] "GET /shop/?page=2 HTTP/1.1" 200 5120 "https://pharmacyneeds.gr/" "' . $chrome . '"', $s );
t( 'log: combined line', $p1 && '203.0.113.10' === $p1['ip'] && 'GET' === $p1['method'] && '/shop/?page=2' === $p1['url'] && 200 === $p1['status'] && 5120 === $p1['bytes'] && 'https://pharmacyneeds.gr/' === $p1['referer'] && $chrome === $p1['ua'] && abs( $p1['ts'] - ( time() - 30 ) ) < 2 && null === $p1['rt_ms'], wp_json_encode( $p1 ) );
$p2 = PNCP_Traffic_Log::parse_line( 'pharmacyneeds.gr:443 203.0.113.11 - - [' . $when( 30 ) . '] "POST /wp-login.php HTTP/2.0" 302 0 "-" "curl/8.5.0"', $s );
t( 'log: Apache vhost_combined (vhost:port in front)', $p2 && '203.0.113.11' === $p2['ip'] && 'POST' === $p2['method'] && 302 === $p2['status'] && '' === $p2['referer'] || ( $p2 && '-' === $p2['referer'] ), wp_json_encode( $p2 ) );
$p3 = PNCP_Traffic_Log::parse_line( '10.0.0.5 - - [' . $when( 30 ) . '] "GET /a HTTP/1.1" 504 0 "-" "Mozilla/5.0" "203.0.113.50, 10.0.0.4" rt=1.234 uct="0.000" urt="1.200"', $s );
t( 'log: Nginx with rt= and X-Forwarded-For behind a private proxy: the client and the time', $p3 && '203.0.113.50' === $p3['ip'] && 1234 === $p3['rt_ms'] && 504 === $p3['status'], wp_json_encode( $p3 ) );
$p4 = PNCP_Traffic_Log::parse_line( '198.51.100.30 - - [' . $when( 30 ) . '] "GET /b HTTP/1.1" 200 10 "-" "Mozilla/5.0" "1.2.3.4" 0.050 0.049', $s );
t( 'log: X-Forwarded-For from an untrusted peer is ignored; a bare request time is read', $p4 && '198.51.100.30' === $p4['ip'] && 50 === $p4['rt_ms'], wp_json_encode( $p4 ) );
PNCP_Ip::store_list( 'cloudflare', array( '173.245.48.0/20' ) );
settings( array( 'trust_cloudflare' => 1 ) );
$s  = PNCP_Options::get();
$p5 = PNCP_Traffic_Log::parse_line( '173.245.48.10 - - [' . $when( 30 ) . '] "GET /c HTTP/1.1" 200 10 "-" "Mozilla/5.0" "203.0.113.77"', $s );
t( 'log: behind a trusted CDN edge (Cloudflare) the visitor comes from X-Forwarded-For; the edge is noted', $p5 && '203.0.113.77' === $p5['ip'] && 'cdn' === $p5['edge'], wp_json_encode( $p5 ) );
settings( array( 'trust_cloudflare' => 0 ) );
$p6 = PNCP_Traffic_Log::parse_line( '173.245.48.10 - - [' . $when( 30 ) . '] "GET /c HTTP/1.1" 200 10 "-" "Mozilla/5.0" "203.0.113.77"', PNCP_Options::get() );
t( 'log: with "Trust Cloudflare addresses" off the edge is the client', $p6 && '173.245.48.10' === $p6['ip'], wp_json_encode( $p6 ) );
$p7 = PNCP_Traffic_Log::parse_line( '2001:db8::1 - - [' . $when( 30 ) . '] "\x16\x03\x01" 400 157 "-" "-"', $s );
t( 'log: IPv6, a garbage request counts on "/"', $p7 && '2001:db8::1' === $p7['ip'] && '/' === $p7['url'] && 400 === $p7['status'], wp_json_encode( $p7 ) );
t( 'log: not an access log line', null === PNCP_Traffic_Log::parse_line( 'PHP Warning: something in /var/www/x.php on line 3' ) && null === PNCP_Traffic_Log::parse_line( '' ) );

$line = static function ( $path, $status = 200, $ago = 10, $ip = '203.0.113.60' ) use ( $when, $chrome ) {
	return $ip . ' - - [' . $when( $ago ) . '] "GET ' . $path . ' HTTP/1.1" ' . $status . ' 100 "-" "' . $chrome . '" 0.010' . "\n";
};
PNCP_Traffic::purge_all();
file_put_contents( $log, $line( '/l1' ) . $line( '/l2' ) . $line( '/l3', 404 ) );
settings( array( 'traffic_log_path' => $log ) );
$state = PNCP_Traffic::state();
unset( $state['server'] );
PNCP_Traffic::save_state( $state );
$r = PNCP_Traffic_Log::run( microtime( true ) + 10 );
t( 'log run: the three lines are stored', 3 === $r['stored'] && 3 === raw_count( "src = 'server'" ) && 10 === (int) raw_rows( "src = 'server'" )[0]['rt_ms'], wp_json_encode( $r ) );
file_put_contents( $log, $line( '/l4' ) . $line( '/l5' ) . '203.0.113.60 - - [' . $when( 1 ) . '] "GET /half', FILE_APPEND );
$r = PNCP_Traffic_Log::run( microtime( true ) + 10 );
t( 'log run: resumes at the cursor (two new lines; the line still being written waits)', 2 === $r['stored'] && 5 === raw_count( "src = 'server'" ), wp_json_encode( $r ) );
file_put_contents( $log, ' HTTP/1.1" 200 1 "-" "x"' . "\n" . $line( '/l6' ), FILE_APPEND );
$r = PNCP_Traffic_Log::run( microtime( true ) + 10 );
t( 'log run: the finished line and the next one', 2 === $r['stored'] && 1 === raw_count( "path = '/half'" ), wp_json_encode( $r ) );
// Rotation: the last lines went into the old file, which became access.log.1; the new file starts over.
file_put_contents( $log, $line( '/l7' ), FILE_APPEND );
rename( $log, $log . '.1' );
file_put_contents( $log, $line( '/n1' ) . $line( '/n2' ) );
$r = PNCP_Traffic_Log::run( microtime( true ) + 10 );
t( 'log run: rotation: the rest of access.log.1, then the new file', 3 === $r['stored'] && 1 === raw_count( "path = '/l7'" ) && 1 === raw_count( "path = '/n1'" ) && 1 === raw_count( "path = '/n2'" ), wp_json_encode( $r ) );
$r = PNCP_Traffic_Log::run( microtime( true ) + 10 );
t( 'log run: nothing new, nothing stored twice', 0 === $r['stored'] && 10 === raw_count( "src = 'server'" ), wp_json_encode( $r ) );
// Truncated in place (copytruncate) and compressed at once (.1.gz).
if ( function_exists( 'gzopen' ) ) {
	file_put_contents( $log, $line( '/n3' ), FILE_APPEND );
	$gz = gzopen( $log . '.1.gz', 'wb' );
	gzwrite( $gz, (string) file_get_contents( $log ) );
	gzclose( $gz );
	unlink( $log . '.1' );
	$fh = fopen( $log, 'w' );
	fwrite( $fh, $line( '/t1' ) );
	fclose( $fh );
	$r = PNCP_Traffic_Log::run( microtime( true ) + 10 );
	t( 'log run: truncated in place: the rest from access.log.1.gz, then the file from its start', 2 === $r['stored'] && 1 === raw_count( "path = '/n3'" ) && 1 === raw_count( "path = '/t1'" ), wp_json_encode( $r ) );
	@unlink( $log . '.1.gz' );
}
$big = '';
for ( $i = 0; $i < 150; $i++ ) {
	$big .= $line( '/budget' . $i );
}
file_put_contents( $log, $big, FILE_APPEND );
$cap = static function () {
	return 100; // The minimum.
};
add_filter( 'pncp_traffic_log_lines', $cap );
$r = PNCP_Traffic_Log::run( microtime( true ) + 10 );
remove_filter( 'pncp_traffic_log_lines', $cap );
t( 'log run: within the line budget (100 lines), the rest in the next run', 100 === $r['stored'] && 50 === PNCP_Traffic_Log::run( microtime( true ) + 10 )['stored'], wp_json_encode( $r ) );
$st = PNCP_Traffic::state()['server'];
t( 'log run: the cursor (device, inode, offset, signature) and no error', isset( $st['ino'], $st['dev'], $st['sig'] ) && filesize( $log ) === (int) $st['offset'] && '' === $st['error'] && $st['last_ok'] > 0, wp_json_encode( $st ) );

// Test this path.
$codes = array(
	'not_set'        => '',
	'not_absolute'   => 'var/log/nginx/access.log',
	'not_allowed'    => '/var/log/../../etc/access.log',
	'not_access_log' => '/etc/passwd',
	'unreadable'     => $tmp . '/missing-access.log',
);
$bad = array();
foreach ( $codes as $want => $path ) {
	$got = PNCP_Traffic::test_log_path( $path )['code'];
	if ( $want !== $got ) {
		$bad[] = $path . ' => ' . $got;
	}
}
foreach ( array( 'php://stdin', 'phar:///tmp/x.phar/access.log', 'compress.zlib://' . $log, 'file:///etc/access.log', "/tmp/access.log\0.php" ) as $path ) {
	if ( 'not_allowed' !== PNCP_Traffic::test_log_path( $path )['code'] ) {
		$bad[] = $path;
	}
}
t( 'test_log_path(): not_set, not_absolute, "..", stream wrappers, not an access log, unreadable', ! $bad, implode( ' | ', $bad ) );
$test = PNCP_Traffic::test_log_path( $log );
t( 'test_log_path(): ok, with the lines that read as access log lines', 'ok' === $test['code'] && $test['parsed'] >= 100 && $test['parsed'] === $test['lines'] && '/budget149' === $test['sample']['url'], wp_json_encode( array_diff_key( $test, array( 'sample' => 1 ) ) ) );
file_put_contents( $tmp . '/error-access.log', "PHP Warning: one\nPHP Warning: two\n" );
t( 'test_log_path(): a file of other lines is not_access_log', 'not_access_log' === PNCP_Traffic::test_log_path( $tmp . '/error-access.log' )['code'] );
// open_basedir and a symlink, in a child PHP (open_basedir cannot be undone in this process).
$inside  = $tmp . '/inside';
$outside = $tmp . '/outside';
@mkdir( $inside );
@mkdir( $outside );
file_put_contents( $outside . '/access.log', $line( '/x' ) );
file_put_contents( $inside . '/access.log', $line( '/y' ) );
@symlink( $outside . '/access.log', $inside . '/link-access.log' );
$allowed = implode( PATH_SEPARATOR, array( $inside, realpath( $wp_dir ), realpath( dirname( __DIR__ ) ), sys_get_temp_dir() . '/pncp-none' ) );
$code    = 'define("WP_USE_THEMES", false); require ' . var_export( $wp_dir . '/wp-load.php', true ) . '; echo wp_json_encode( array( PNCP_Traffic::test_log_path( ' . var_export( $inside . '/access.log', true ) . ' )["code"], PNCP_Traffic::test_log_path( ' . var_export( $outside . '/access.log', true ) . ' )["code"], PNCP_Traffic::test_log_path( ' . var_export( $inside . '/link-access.log', true ) . ' )["code"] ) );';
$got     = shell_exec( escapeshellarg( PHP_BINARY ) . ' -d open_basedir=' . escapeshellarg( $allowed ) . ' -d display_errors=0 -r ' . escapeshellarg( $code ) . ' 2>/dev/null' );
$got     = json_decode( (string) preg_replace( '/^[^\[]*/', '', (string) $got ), true );
t( 'test_log_path() with open_basedir: inside ok, outside not_allowed, a symlink leading outside not_allowed', array( 'ok', 'not_allowed', 'not_allowed' ) === $got, wp_json_encode( $got ) );
settings( array( 'traffic_log_path' => '' ) );

/* ---------- 6. The WordPress source ---------- */

PNCP_Traffic::purge_all();
settings( array( 'traffic' => 1, 'traffic_wp' => 0 ) );
$miss = '/pncp-traffic-missing-' . wp_rand( 1000, 9999 ) . '/';
req( $miss, browser( '203.0.113.' . wp_rand( 10, 200 ) ) );
t( 'wp source off: a missing page records nothing', 0 === raw_count( "src = 'wp'" ) );
settings( array( 'traffic_wp' => 1 ) );
$vip            = '203.0.113.' . wp_rand( 10, 200 );
list( $code, ) = req( $miss . '?x=1', browser( $vip ) );
$rows           = raw_rows( "src = 'wp'" );
$w              = isset( $rows[0] ) ? $rows[0] : array();
t( 'wp source: a missing page records a 404 with path, query, IP, User-Agent, method and time taken', 404 === $code && 1 === count( $rows ) && 404 === (int) $w['status'] && $miss === $w['path'] && 'x=1' === $w['query'] && $vip === $w['ip'] && 'GET' === $w['method'] && 'browser' === $w['fam'] && null !== $w['rt_ms'], $code . ' ' . wp_json_encode( $rows ) );
req( '/', array( 'User-Agent' => 'WordPress/6.7; ' . home_url() ) );
t( 'wp source: the site\'s own loopback request is not recorded', 1 === raw_count( "src = 'wp'" ) );
req( '/wp-admin/admin-ajax.php?action=nothing', browser( $vip ) );
t( 'wp source: wp-admin / admin-ajax is not recorded', 1 === raw_count( "src = 'wp'" ) );
req( '/', browser( $vip ) );
t( 'wp source: a front page is recorded with 200', 1 === raw_count( "src = 'wp' AND status = 200 AND path = '/'" ) );
settings( array( 'traffic_wp' => 0 ) );

/* ---------- 7. Queries ---------- */

PNCP_Traffic::purge_all();
$gpt = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';
$own = home_url( '/category/' );
feed(
	'bunny',
	array(
		array( 100, '203.0.113.1', 200, '/', $chrome, array( 'cache' => 'HIT', 'bytes' => 1000, 'country' => 'GR', 'referer' => 'https://www.google.com/' ) ),
		array( 200, '203.0.113.1', 200, '/shop/', $chrome, array( 'cache' => 'MISS', 'bytes' => 2000, 'country' => 'GR' ) ),
		array( 300, '203.0.113.2', 404, '/old-page/', $chrome, array( 'cache' => 'MISS', 'bytes' => 300, 'country' => 'GR', 'referer' => $own, 'query' => 'a=1' ) ),
		array( 400, '203.0.113.3', 404, '/old-page/', $gpt, array( 'cache' => 'MISS', 'bytes' => 300, 'country' => 'US', 'referer' => 'https://other.example/links' ) ),
		array( 500, '203.0.113.3', 404, '/wp-login.php.bak', 'curl/8.5.0', array( 'cache' => 'MISS', 'bytes' => 100, 'country' => 'US' ) ),
		array( 600, '203.0.113.4', 500, '/checkout/', $chrome, array( 'cache' => 'MISS', 'bytes' => 50, 'country' => 'DE' ) ),
		array( 700, '203.0.113.4', 502, '/checkout/', $chrome, array( 'cache' => 'MISS', 'bytes' => 50, 'country' => 'DE' ) ),
		array( 800, '203.0.113.5', 301, '/old-shop/', $chrome, array( 'cache' => 'MISS', 'bytes' => 0, 'country' => 'GR' ) ),
		array( 900, '203.0.113.5', 304, '/style.css', $chrome, array( 'cache' => 'HIT', 'bytes' => 0, 'country' => 'GR' ) ),
		array( 1000, '203.0.113.6', 200, '/big.pdf', $gpt, array( 'cache' => 'HIT', 'bytes' => 9000000, 'country' => 'US' ) ),
		array( 1100, '203.0.113.6', 200, '/shop/', $gpt, array( 'cache' => 'MISS', 'bytes' => 2000, 'country' => 'US' ) ),
		array( 1200, '203.0.113.7', 200, '/shop/', $chrome, array( 'cache' => 'MISS', 'bytes' => 2000, 'country' => 'GR' ) ),
	)
);
feed(
	'server',
	array(
		array( 100, '203.0.113.9', 200, '/slow/', $chrome, array( 'rt_ms' => 2500 ) ),
		array( 200, '203.0.113.9', 200, '/fast/', $chrome, array( 'rt_ms' => 20 ) ),
	)
);
$f  = array( 'src' => 'bunny' );
$ov = PNCP_Traffic::overview( $f );
t( 'overview: totals', 12 === $ov['total'] && 7 === $ov['ips'] && 9007800 === $ov['bytes'] && 5 === $ov['s2xx'] && 2 === $ov['s3xx'] && 3 === $ov['s4xx'] && 2 === $ov['s5xx'] && 3 === $ov['cache_hits'] && 9 === $ov['cache_misses'], wp_json_encode( array_diff_key( $ov, array( 'series' => 1 ) ) ) );
t( 'overview: raw basis, bunny, hourly series that adds up', 'raw' === $ov['basis'] && 'bunny' === $ov['src_used'] && ! $ov['clipped'] && 'hour' === $ov['step'] && count( $ov['series'] ) >= 24 && 12 === array_sum( wp_list_pluck( $ov['series'], 'hits' ) ) && 3 === array_sum( wp_list_pluck( $ov['series'], 's4xx' ) ) );
t( 'overview: the server source is counted apart', 2 === PNCP_Traffic::overview( array( 'src' => 'server' ) )['total'] );
$checks = array(
	array( array( 'status' => 404 ), 3 ),
	array( array( 'status' => '5xx' ), 2 ),
	array( array( 'status' => '3xx' ), 2 ),
	array( array( 'ua' => $gpt ), 3 ),
	array( array( 'ua_family' => 'ai_bot' ), 3 ),
	array( array( 'ua_family' => 'script' ), 1 ),
	array( array( 'path' => '/shop/' ), 3 ),
	array( array( 'path' => '/shop/?utm=1' ), 3 ),
	array( array( 'path_like' => 'old' ), 3 ),
	array( array( 'ip' => '203.0.113.3' ), 2 ),
	array( array( 'country' => 'us' ), 4 ),
	array( array( 'cache' => 'HIT' ), 3 ),
	array( array( 'cache' => 'MISS' ), 9 ),
	array( array( 'search' => 'GPTBot' ), 3 ),
	array( array( 'search' => 'checkout' ), 2 ),
	array( array( 'status' => 404, 'country' => 'US' ), 2 ),
	array( array( 'from' => time() - 450 ), 4 ),
	array( array( 'from' => time() - 1000, 'to' => time() - 550 ), 5 ),
	array( array( 'search' => "x' OR '1'='1" ), 0 ),
);
$bad = array();
foreach ( $checks as $c ) {
	$n = PNCP_Traffic::overview( array_merge( $f, $c[0] ) )['total'];
	if ( $c[1] !== $n ) {
		$bad[] = wp_json_encode( $c[0] ) . ' => ' . $n;
	}
}
t( 'overview: each filter (and SQL in a filter is just text)', ! $bad, implode( ' | ', $bad ) );

$top = PNCP_Traffic::top( 'path', $f );
t( 'top path: order by hits, with total_rows', '/shop/' === $top['rows'][0]['key'] && 3 === $top['rows'][0]['hits'] && 3 === $top['rows'][0]['ips'] && 8 === $top['total_rows'] && 'raw' === $top['basis'], wp_json_encode( $top['rows'][0] ) . ' ' . $top['total_rows'] );
$p1 = PNCP_Traffic::top( 'path', $f, 2, 0 );
$p2 = PNCP_Traffic::top( 'path', $f, 2, 2 );
t( 'top path: paging', 2 === count( $p1['rows'] ) && 2 === count( $p2['rows'] ) && ! array_intersect( wp_list_pluck( $p1['rows'], 'key' ), wp_list_pluck( $p2['rows'], 'key' ) ) && 8 === $p2['total_rows'] );
t( 'top path: order by bytes', '/big.pdf' === PNCP_Traffic::top( 'path', $f, 5, 0, 'bytes' )['rows'][0]['key'] );
t( 'top: the limit is at most 500', 500 >= count( PNCP_Traffic::top( 'path', $f, 100000 )['rows'] ) );
$ua = PNCP_Traffic::top( 'ua', $f );
t( 'top ua: family and name', $chrome === $ua['rows'][0]['key'] && 'browser' === $ua['rows'][0]['family'] && 'Chrome' === $ua['rows'][0]['name'] && 'GPTBot' === $ua['rows'][1]['name'] && 'ai_bot' === $ua['rows'][1]['family'] && 3 === $ua['total_rows'], wp_json_encode( $ua['rows'] ) );
$fam = PNCP_Traffic::top( 'ua_family', $f );
t( 'top ua_family', 'browser' === $fam['rows'][0]['key'] && 8 === $fam['rows'][0]['hits'] && '' !== $fam['rows'][0]['name'] );
$st = PNCP_Traffic::top( 'status', $f );
t( 'top status', '200' === $st['rows'][0]['key'] && 5 === $st['rows'][0]['hits'] && 6 === $st['total_rows'], wp_json_encode( $st['rows'] ) );
$cn = PNCP_Traffic::top( 'country', $f );
t( 'top country', 'GR' === $cn['rows'][0]['key'] && 6 === $cn['rows'][0]['hits'] );
$ip = PNCP_Traffic::top( 'ip', $f, 50, 0, 's4xx' );
t( 'top ip by 4xx', '203.0.113.3' === $ip['rows'][0]['key'] && 2 === $ip['rows'][0]['s4xx'] );
$rf = PNCP_Traffic::top( 'referer', $f );
t( 'top referer ("" = none)', '' === $rf['rows'][0]['key'] && 9 === $rf['rows'][0]['hits'] && 4 === $rf['total_rows'] );
t( 'top with a filter', 2 === PNCP_Traffic::top( 'path', array_merge( $f, array( 'ua_family' => 'ai_bot', 'status' => 200 ) ) )['total_rows'] );

$pr = PNCP_Traffic::problems( '404', $f );
$old = $pr['rows'][0];
t( 'problems 404: the path, hits, IPs, statuses, a sample User-Agent', '/old-page/' === $old['path'] && 2 === $old['hits'] && 2 === $old['ips'] && array( '404' => 2 ) === $old['statuses'] && '' !== $old['sample_ua'] && 2 === $pr['total_rows'], wp_json_encode( $pr ) );
$refs = array();
foreach ( $old['top_referers'] as $r ) {
	$refs[ $r['referer'] ] = $r['internal'];
}
t( 'problems 404: the referrers, internal ones marked', 2 === count( $refs ) && true === $refs[ PNCP_Traffic::clean_referer( $own ) ] && false === $refs['https://other.example/links'], wp_json_encode( $old['top_referers'] ) );
$pr = PNCP_Traffic::problems( '5xx', $f );
t( 'problems 5xx: 500 and 502 of one path', 1 === count( $pr['rows'] ) && '/checkout/' === $pr['rows'][0]['path'] && array( '500' => 1, '502' => 1 ) == $pr['rows'][0]['statuses'], wp_json_encode( $pr['rows'] ) );
$pr = PNCP_Traffic::problems( '3xx', $f );
t( 'problems 3xx: the redirect, not the 304', 1 === count( $pr['rows'] ) && '/old-shop/' === $pr['rows'][0]['path'] );
$pr = PNCP_Traffic::problems( 'uncached', $f );
t( 'problems uncached: pages with misses (no static files), with the miss rate', '/shop/' === $pr['rows'][0]['path'] && 3 === $pr['rows'][0]['misses'] && 3 === $pr['rows'][0]['hits'] && 1.0 === (float) $pr['rows'][0]['miss_rate'] && ! in_array( '/style.css', wp_list_pluck( $pr['rows'], 'path' ), true ), wp_json_encode( $pr['rows'] ) );
$pr = PNCP_Traffic::problems( 'large', $f );
t( 'problems large: the biggest first', '/big.pdf' === $pr['rows'][0]['path'] && 9000000 === $pr['rows'][0]['bytes'] && 9000000 === $pr['rows'][0]['avg_bytes'] );
$pr = PNCP_Traffic::problems( 'slow', $f );
t( 'problems slow: not available where no time is logged (Bunny)', ! $pr['rows'] && false === $pr['available'] );
$pr = PNCP_Traffic::problems( 'slow', array( 'src' => 'server' ) );
t( 'problems slow: the slowest first (server log)', '/slow/' === $pr['rows'][0]['path'] && 2500 === $pr['rows'][0]['avg_rt_ms'] && $pr['available'] );
t( 'problems: paging', 1 === count( PNCP_Traffic::problems( '404', $f, 1, 1 )['rows'] ) && '/wp-login.php.bak' === PNCP_Traffic::problems( '404', $f, 1, 1 )['rows'][0]['path'] );

$dt = PNCP_Traffic::detail( 'ip', '203.0.113.3', $f );
t( 'detail ip: summary, paths, statuses, User-Agents', 2 === $dt['summary']['total'] && 2 === $dt['paths']['total_rows'] && '404' === $dt['statuses']['rows'][0]['key'] && 2 === $dt['uas']['total_rows'] && ! isset( $dt['ips'] ), wp_json_encode( array_keys( $dt ) ) );
$dt = PNCP_Traffic::detail( 'ua', $gpt, $f );
t( 'detail ua: name, family, paths, countries', 'GPTBot' === $dt['name'] && 'ai_bot' === $dt['family'] && 3 === $dt['summary']['total'] && 'US' === $dt['countries']['rows'][0]['key'] && 3 === $dt['paths']['total_rows'] );
$dt = PNCP_Traffic::detail( 'path', '/shop/?x=1', $f );
t( 'detail path: the query is dropped, IPs and referrers', '/shop/' === $dt['key'] && 3 === $dt['summary']['total'] && 3 === $dt['ips']['total_rows'] && isset( $dt['referers']['rows'] ) );

$raw = PNCP_Traffic::raw( $f, 5 );
t( 'raw: newest first, has_more', 5 === count( $raw['rows'] ) && $raw['has_more'] && '/' === $raw['rows'][0]['path'] && $raw['rows'][0]['ts'] >= $raw['rows'][1]['ts'] && 'browser' === $raw['rows'][0]['family'] );
$raw2 = PNCP_Traffic::raw( $f, 5, 10 );
t( 'raw: the last page', 2 === count( $raw2['rows'] ) && ! $raw2['has_more'] && '/shop/' === $raw2['rows'][1]['path'] );
t( 'raw: a filter', 1 === count( PNCP_Traffic::raw( array_merge( $f, array( 'status' => 301 ) ) )['rows'] ) );

// CSV, with formula injection.
feed(
	'bunny',
	array(
		array( 50, '203.0.113.99', 404, '/x', '=HYPERLINK("http://evil.example","click")', array( 'query' => '@SUM(1+1)' ) ),
		array( 51, '203.0.113.99', 404, '/y', '+cmd|calc', array( 'query' => '-2+3' ) ),
	)
);
$fh = fopen( 'php://memory', 'w+' );
$n  = PNCP_Traffic::export_csv( $f, $fh );
rewind( $fh );
$csv = array();
while ( ( $cells = fgetcsv( $fh, 0, ',', '"', '\\' ) ) !== false ) {
	$csv[] = $cells;
}
fclose( $fh );
t( 'csv: a header and every row', 14 === $n && 15 === count( $csv ) && 'time' === $csv[0][0] && 'user_agent' === $csv[0][9], $n . ' ' . count( $csv ) );
t( 'csv: cells starting with = + - @ get a quote', "'=HYPERLINK(\"http://evil.example\",\"click\")" === $csv[1][9] && "'@SUM(1+1)" === $csv[1][7] && "'+cmd|calc" === $csv[2][9] && "'-2+3" === $csv[2][7], wp_json_encode( array( $csv[1], $csv[2] ) ) );
$cap = static function () {
	return 3;
};
add_filter( 'pncp_traffic_csv_max_rows', $cap );
$fh = fopen( 'php://memory', 'w+' );
$n  = PNCP_Traffic::export_csv( $f, $fh );
fclose( $fh );
remove_filter( 'pncp_traffic_csv_max_rows', $cap );
t( 'csv: the hard cap', 3 === $n );

// The aggregates, over a range longer than the raw window.
settings( array( 'traffic_raw_days' => 14 ) );
feed(
	'bunny',
	array(
		array( 6 * DAY_IN_SECONDS, '198.51.100.40', 200, '/shop/', $chrome, array( 'cache' => 'HIT', 'bytes' => 10 ) ),
		array( 6 * DAY_IN_SECONDS + 60, '198.51.100.41', 404, '/gone/', $gpt, array( 'cache' => 'MISS', 'bytes' => 10, 'referer' => 'https://ref.example/a' ) ),
		array( 6 * DAY_IN_SECONDS + 120, '198.51.100.41', 404, '/gone/', $gpt, array( 'cache' => 'MISS', 'bytes' => 10 ) ),
	)
);
$days = PNCP_Traffic::rollup();
settings( array( 'traffic_raw_days' => 3 ) );
$del = PNCP_Traffic::cleanup();
t( 'retention: the raw rows older than the raw window are deleted; the days were counted first', $days >= 2 && 3 === $del['raw'] && 0 === raw_count( "ip LIKE '198.51.100.4%'" ), $days . ' ' . wp_json_encode( $del ) );
$lf = array(
	'src'  => 'bunny',
	'from' => time() - 10 * DAY_IN_SECONDS,
);
$ov = PNCP_Traffic::overview( $lf );
t( 'aggregates: overview of 10 days (the deleted rows too), daily series', 'agg' === $ov['basis'] && 17 === $ov['total'] && 7 === $ov['s4xx'] && 'day' === $ov['step'] && 17 === array_sum( wp_list_pluck( $ov['series'], 'hits' ) ) && $ov['ips_approx'], wp_json_encode( array_diff_key( $ov, array( 'series' => 1 ) ) ) );
$top = PNCP_Traffic::top( 'path', $lf );
$sh  = array();
foreach ( $top['rows'] as $r ) {
	$sh[ $r['key'] ] = $r['hits'];
}
t( 'aggregates: top paths add the days up', 'agg' === $top['basis'] && 4 === $sh['/shop/'] && 2 === $sh['/gone/'], wp_json_encode( $sh ) );
t( 'aggregates: top ua keeps the family', 'GPTBot' === PNCP_Traffic::top( 'ua', array_merge( $lf, array( 'ua_family' => 'ai_bot' ) ) )['rows'][0]['name'] );
t( 'aggregates: one key over 10 days (path)', 4 === PNCP_Traffic::overview( array_merge( $lf, array( 'path' => '/shop/' ) ) )['total'] && 'agg' === PNCP_Traffic::overview( array_merge( $lf, array( 'path' => '/shop/' ) ) )['basis'] );
t( 'aggregates: status filter', 7 === PNCP_Traffic::overview( array_merge( $lf, array( 'status' => 404 ) ) )['total'] && 7 === PNCP_Traffic::top( 'status', array_merge( $lf, array( 'status' => '4xx' ) ) )['rows'][0]['hits'] );
$pr = PNCP_Traffic::problems( '404', $lf );
$pp = array();
foreach ( $pr['rows'] as $r ) {
	$pp[ $r['path'] ] = $r;
}
t( 'aggregates: problems 404 with referrers', 'agg' === $pr['basis'] && isset( $pp['/gone/'] ) && 2 === $pp['/gone/']['hits'] && in_array( 'https://ref.example/a', wp_list_pluck( $pp['/gone/']['top_referers'], 'referer' ), true ) && isset( $pp['/old-page/'] ), wp_json_encode( array_keys( $pp ) ) );
t( 'aggregates: problems uncached / large from the day rows', 'agg' === PNCP_Traffic::problems( 'uncached', $lf )['basis'] && '/big.pdf' === PNCP_Traffic::problems( 'large', $lf )['rows'][0]['path'] );
$cl = PNCP_Traffic::top( 'path', array_merge( $lf, array( 'country' => 'US' ) ) );
t( 'aggregates: a filter on another dimension is answered from the raw window ("clipped")', 'raw' === $cl['basis'] && $cl['clipped'] && $cl['from'] === PNCP_Traffic::raw_floor() );
$rw = PNCP_Traffic::raw( $lf );
t( 'raw() never reads before the raw window', $rw['clipped'] && $rw['from'] >= PNCP_Traffic::raw_floor() && 14 === count( $rw['rows'] ) );
// 3.12 performance: a status class over the daily figures, the problems with the status of their type.
$s404 = PNCP_Traffic::top( 'ua', array_merge( $lf, array( 'status' => 404 ) ) );
$want = 2 + raw_count( $wpdb->prepare( "src = 'bunny' AND status = 404 AND ua = %s", $gpt ) ); // The 2 of 6 days ago are counted only in the daily figures.
$hits = 0;
$okay = true;
$gh   = 0;
foreach ( $s404['rows'] as $r ) {
	$hits += $r['hits'];
	$okay  = $okay && $r['s4xx'] === $r['hits'] && 0 === $r['s5xx'] && $r['ips'] <= $r['hits'] && $r['ips'] >= 1;
	$gh    = $gpt === $r['key'] ? $r['hits'] : $gh;
}
t( 'aggregates: top ua with status 404 over 10 days from the daily figures (not clipped), exact requests', 'agg' === $s404['basis'] && ! $s404['clipped'] && $okay && $hits === PNCP_Traffic::overview( array_merge( $lf, array( 'status' => 404 ) ) )['total'] && $want === $gh, wp_json_encode( $s404 ) );
$s4p = PNCP_Traffic::top( 'path', array_merge( $lf, array( 'status' => '4xx' ) ), 50, 0, 's4xx' );
t( 'aggregates: top path with status 4xx, the totals add up, total_rows', 'agg' === $s4p['basis'] && array_sum( wp_list_pluck( $s4p['rows'], 'hits' ) ) === $ov['s4xx'] && count( $s4p['rows'] ) === $s4p['total_rows'] && ! $s4p['has_more'] );
t( 'aggregates: a single code other than 404 still comes from the raw window', 'raw' === PNCP_Traffic::top( 'ua', array_merge( $lf, array( 'status' => 403 ) ) )['basis'] );
$p4 = PNCP_Traffic::problems( '404', array_merge( $lf, array( 'status' => '4xx' ) ) );
t( 'problems 404 with the status 4xx: the same as without it, from the daily figures', 'agg' === $p4['basis'] && wp_list_pluck( $p4['rows'], 'path' ) === wp_list_pluck( $pr['rows'], 'path' ) && wp_list_pluck( $p4['rows'], 'hits' ) === wp_list_pluck( $pr['rows'], 'hits' ) );
$p5 = PNCP_Traffic::problems( '404', array_merge( $lf, array( 'status' => '5xx' ) ) );
t( 'problems 404 with the status 5xx: nothing, without a query of the raw rows', array() === $p5['rows'] && 0 === $p5['total_rows'] && ! $p5['clipped'] );
// The detail reads the rows of its key once: the same breakdowns as top() with the key as filter.
$f24 = array( 'src' => 'bunny' );
$dg  = PNCP_Traffic::detail( 'ua', $gpt, $f24 );
$same = true;
foreach ( array( 'paths' => 'path', 'statuses' => 'status', 'countries' => 'country', 'referers' => 'referer', 'ips' => 'ip' ) as $part => $dim ) {
	$tq   = PNCP_Traffic::top( $dim, array_merge( $f24, array( 'ua' => $gpt ) ), 10 );
	$same = $same && wp_json_encode( $tq['rows'] ) === wp_json_encode( $dg[ $part ]['rows'] ) && $tq['total_rows'] === $dg[ $part ]['total_rows'];
}
t( 'detail ua: the breakdowns of the one pass are those of top()', $same && 'raw' === $dg['paths']['basis'], wp_json_encode( $dg['paths']['rows'] ) );
$few = static function () {
	return 2;
};
add_filter( 'pncp_traffic_detail_rows', $few );
$dc = PNCP_Traffic::detail( 'ua', $gpt, $f24 );
remove_filter( 'pncp_traffic_detail_rows', $few );
$newest = $wpdb->get_col( $wpdb->prepare( "SELECT ts FROM %i WHERE src = 'bunny' AND ua = %s ORDER BY ts DESC LIMIT 2", PNCP_Traffic::table( 'raw' ), $gpt ) );
t( 'detail ua of a very busy key: the breakdowns of its newest requests only, "clipped" to the first of them', $dc['paths']['clipped'] && (int) end( $newest ) === $dc['paths']['from'] && 2 === array_sum( wp_list_pluck( $dc['statuses']['rows'], 'hits' ) ), wp_json_encode( array( $dc['paths']['from'], $newest, $dc['statuses']['rows'] ) ) );
// More keys than one query reads (GROUPS): no second pass to count them, has_more for the pages.
$many = array();
for ( $i = 0; $i < PNCP_Traffic_Query::GROUPS + 20; $i++ ) {
	$many[] = array( 30 + $i % 600, '192.0.2.' . ( $i % 250 + 1 ), 200, '/many-' . $i . '/', $chrome );
}
feed( 'wp', $many );
$m1 = PNCP_Traffic::top( 'path', array( 'src' => 'wp' ), 50 );
$m2 = PNCP_Traffic::top( 'path', array( 'src' => 'wp' ), 50, PNCP_Traffic_Query::GROUPS );
t( 'more keys than GROUPS: total_rows -1, has_more, and the pages beyond GROUPS', -1 === $m1['total_rows'] && $m1['has_more'] && 50 === count( $m1['rows'] ) && 20 <= count( $m2['rows'] ) && ! $m2['has_more'] && ! array_intersect( wp_list_pluck( $m1['rows'], 'key' ), wp_list_pluck( $m2['rows'], 'key' ) ), $m1['total_rows'] . ' ' . count( $m2['rows'] ) );
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE src = %s', PNCP_Traffic::table( 'raw' ), 'wp' ) );

// Retention of the aggregates, caps.
global $wpdb;
$wpdb->insert( PNCP_Traffic::table( 'day' ), array( 'src' => 'bunny', 'dim' => 'path', 'day' => time() - 400 * DAY_IN_SECONDS, 'k' => 'aaaaaaaaaaaaaaaa', 'label' => '/ancient/', 'hits' => 1 ) );
$wpdb->insert( PNCP_Traffic::table( 'hour' ), array( 'src' => 'bunny', 'hour_ts' => time() - 400 * DAY_IN_SECONDS, 'hits' => 1 ) );
$del = PNCP_Traffic::cleanup();
t( 'retention: aggregates older than traffic_days are deleted', 2 <= $del['agg'] && 0 === (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . PNCP_Traffic::table( 'day' ) . " WHERE label = '/ancient/'" ) );
$cap = static function () {
	return 15;
};
add_filter( 'pncp_traffic_max_raw_rows', $cap );
$before = raw_count();
$del    = PNCP_Traffic::cleanup();
remove_filter( 'pncp_traffic_max_raw_rows', $cap );
t( 'cap: raw rows beyond the cap, oldest first', 15 === raw_count() && $before - 15 === $del['cap'] && 0 === raw_count( "src = 'bunny' AND path = '/'" ) && 1 === raw_count( "path = '/slow/'" ), $before . ' ' . wp_json_encode( $del ) );
PNCP_Traffic::reset();
$cap = static function () {
	return 5;
};
add_filter( 'pncp_traffic_max_rows_per_run', $cap );
$ok = 0;
for ( $i = 0; $i < 10; $i++ ) {
	$ok += PNCP_Traffic::ingest( array( 'ts' => time(), 'ip' => '203.0.113.200', 'status' => 200, 'path' => '/cap' . $i ), 'bunny' ) ? 1 : 0;
}
PNCP_Traffic::flush();
remove_filter( 'pncp_traffic_max_rows_per_run', $cap );
t( 'cap: rows per run', 5 === $ok && 5 === PNCP_Traffic::dropped()['cap'] && 5 === raw_count( "path LIKE '/cap%'" ) );
PNCP_Traffic::reset();
PNCP_Traffic::purge_all();
$rows = array();
for ( $i = 0; $i < 25; $i++ ) {
	$rows[] = array( 10 + $i, '203.0.113.' . ( 1 + $i ), 0 === $i % 12 ? 404 : 200, '/k' . $i, $chrome );
	$rows[] = array( 10 + $i, '203.0.113.' . ( 1 + $i ), 200, '/k' . ( $i < 15 ? 0 : $i ), $chrome );
}
feed( 'bunny', $rows );
$cap = static function () {
	return 10;
};
add_filter( 'pncp_traffic_keys_per_day', $cap );
PNCP_Traffic::rollup();
remove_filter( 'pncp_traffic_keys_per_day', $cap );
$day   = PNCP_Traffic::day_start( time() - 20 );
$prow  = $wpdb->get_results( $wpdb->prepare( 'SELECT k, label, hits, s4xx FROM %i WHERE src = %s AND dim = %s AND day = %d', PNCP_Traffic::table( 'day' ), 'bunny', 'path', $day ), ARRAY_A );
$sum   = array_sum( wp_list_pluck( $prow, 'hits' ) );
$other = wp_list_filter( $prow, array( 'k' => PNCP_Traffic::OTHER ) );
$labs  = wp_list_pluck( $prow, 'label' );
t( 'cap: keys per day: the busiest 10, rare keys with errors, one "other" row; the day still adds up', 50 === (int) $sum && 1 === count( $other ) && in_array( '/k12', $labs, true ) && in_array( '/k24', $labs, true ) && count( $prow ) <= 10 + 2 + 1, $sum . ' ' . count( $prow ) . ' ' . implode( ',', $labs ) );

// Masked IPs.
settings( array( 'traffic_ip_mode' => 'masked' ) );
PNCP_Traffic::purge_all();
feed(
	'bunny',
	array(
		array( 5, '203.0.113.77', 200, '/m', 'Mozilla/5.0 (compatible; Googlebot/2.1)' ),
		array( 5, '2001:db8:abcd:1234::1', 200, '/m', $chrome ),
	)
);
$ips = wp_list_pluck( raw_rows(), 'ip' );
t( 'masked: IPv4 /24, IPv6 /48', array( '203.0.113.0', '2001:db8:abcd::' ) === $ips, wp_json_encode( $ips ) );
t( 'masked: the family is decided on the full IP (fake Googlebot)', 'fake_bot' === raw_rows()[0]['fam'] );
t( 'masked: the ip filter masks too', 1 === PNCP_Traffic::overview( array( 'src' => 'bunny', 'ip' => '203.0.113.200' ) )['total'] );
settings( array( 'traffic_ip_mode' => 'full' ) );

/* ---------- 8. Sources, run, purge, uninstall ---------- */

// Schema 1 (the tables of a 3.12 development version) to 2: the covering index is added, without dbDelta().
function cover_index() {
	global $wpdb, $sqlite;
	$table = PNCP_Traffic::table( 'raw' );
	if ( $sqlite ) {
		return (bool) $wpdb->get_var( $wpdb->prepare( "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = %s AND sql LIKE %s", $table, '%ua_hash%path_hash%' ) );
	}
	return (bool) $wpdb->get_results( $wpdb->prepare( 'SHOW INDEX FROM %i WHERE Key_name = %s', $table, 'src_cover' ) );
}
t( 'schema 2: the covering index is there', cover_index() && PNCP_Traffic::DB_VERSION === (int) get_option( PNCP_Traffic::DB_OPTION ) );
$wpdb->suppress_errors( true );
if ( $sqlite ) {
	foreach ( (array) $wpdb->get_col( $wpdb->prepare( "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = %s AND sql LIKE %s", PNCP_Traffic::table( 'raw' ), '%ua_hash%path_hash%' ) ) as $name ) {
		$wpdb->query( 'DROP INDEX IF EXISTS ' . $name ); // phpcs:ignore
	}
} else {
	$wpdb->query( $wpdb->prepare( 'ALTER TABLE %i DROP INDEX src_cover', PNCP_Traffic::table( 'raw' ) ) );
}
$wpdb->suppress_errors( false );
update_option( PNCP_Traffic::DB_OPTION, 1, true );
$was_ready = PNCP_Traffic::ready();
ob_start();
PNCP_Traffic::maybe_install();
$printed = (string) ob_get_clean();
t( 'schema 1 -> 2: maybe_install() adds the index, the rows stay, nothing printed', ! $was_ready && cover_index() && PNCP_Traffic::ready() && '' === $printed, $printed );

PNCP_Traffic::purge_all();
settings( array( 'traffic_wp' => 1, 'traffic_log_path' => '' ) );
feed( 'wp', array( array( 5, '203.0.113.5', 200, '/', $chrome ) ) );
$ss = PNCP_Traffic::sources_status();
t( 'sources_status(): each source with on, last_ingest, error, lines_today; "auto" is wp here', isset( $ss['bunny']['on'], $ss['server']['error'], $ss['wp']['lines_today'] ) && 'not_set' === $ss['server']['error'] && true === $ss['wp']['on'] && 1 === $ss['wp']['lines_today'] && 'wp' === $ss['auto'] && $ss['enabled'], wp_json_encode( $ss ) );
t( 'auto: queries without src use the best source', 'wp' === PNCP_Traffic::overview()['src_used'] && 1 === PNCP_Traffic::overview()['total'] );
settings( array( 'traffic_log_path' => $log ) );
PNCP_Traffic_Log::run( microtime( true ) + 5 );
PNCP_Traffic::reset();
t( 'auto: a current server log wins over WordPress (no double counting)', 'server' === PNCP_Traffic::best_source() );
settings( array( 'traffic_log_path' => '/nope/access.log' ) );
PNCP_Traffic_Log::run( microtime( true ) + 5 );
t( 'sources_status(): the server error code', 'unreadable' === PNCP_Traffic::sources_status()['server']['error'] );
settings( array( 'traffic_log_path' => '' ) );
// The scheduled run.
PNCP_Log::cache_delete( 'pncp_traffic_lock' );
feed( 'wp', array( array( 1, '203.0.113.6', 404, '/run', $chrome ) ) );
$state              = PNCP_Traffic::state();
$state['rolled_at'] = 0;
PNCP_Traffic::save_state( $state );
PNCP_Traffic::run();
t( 'run(): counts the aggregates', PNCP_Traffic::state()['rolled_at'] >= time() - 5 && 0 < (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . PNCP_Traffic::table( 'hour' ) ) );
PNCP_Traffic::purge_all();
t( 'purge_all(): every table is empty', 0 === raw_count() && 0 === (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . PNCP_Traffic::table( 'day' ) ) && 0 === (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . PNCP_Traffic::table( 'hour' ) ) && 0 === PNCP_Traffic::overview( array( 'src' => 'wp' ) )['total'] );
feed( 'wp', array( array( 1, '203.0.113.6', 404, '/left', $chrome ) ) );
PNCP_Traffic::rollup();
PNCP_Traffic::uninstall();
// The SQLite drop-in answers DROP TABLE without doing it: there the tables stay, empty.
$gone = true;
foreach ( array( 'raw', 'hour', 'day', 'err' ) as $which ) {
	$name  = PNCP_Traffic::table( $which );
	$gone  = $gone && ( ! table_exists( $name ) || ( $sqlite && 0 === (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $name ) ) );
}
t( 'uninstall: tables (or, on SQLite, their rows), options and the event are gone', $gone && false === get_option( PNCP_Traffic::DB_OPTION, false ) && false === get_option( PNCP_Traffic::STATE, false ) && ! wp_next_scheduled( PNCP_Traffic::CRON ) );
$un = (string) file_get_contents( dirname( __DIR__ ) . '/uninstall.php' );
t( 'uninstall.php: drops the tables, the options and the event itself too', false !== strpos( $un, "'PNCP_Traffic'" ) && false !== strpos( $un, "'pncp_traffic_err'" ) && false !== strpos( $un, "'pncp_traffic_state'" ) && false !== strpos( $un, "'pncp_traffic_run'" ) );
t( 'queries with no tables answer empty, without errors', 0 === PNCP_Traffic::overview()['total'] && array() === PNCP_Traffic::top( 'ua' )['rows'] && array() === PNCP_Traffic::raw()['rows'] );

/* ---------- Clean up ---------- */

update_option( PNCP_OPTION, $saved );
update_option( 'pncp_version', $saved_v );
update_option( 'timezone_string', $saved_z );
foreach ( $lists as $name => $value ) {
	if ( false === $value ) {
		delete_option( PNCP_Ip::LISTS_OPTION . '_' . $name );
	} else {
		update_option( PNCP_Ip::LISTS_OPTION . '_' . $name, $value );
	}
}
if ( false === $saved_u ) {
	delete_option( PNCP_Ip::LISTS_OPTION . '_updated' );
} else {
	update_option( PNCP_Ip::LISTS_OPTION . '_updated', $saved_u, false );
}
if ( false === $saved_b ) {
	delete_option( 'pncp_bunny_state' );
} else {
	update_option( 'pncp_bunny_state', $saved_b, false );
}
PNCP_Options::flush();
if ( false !== $had_db ) {
	PNCP_Traffic::install();
	if ( false !== $saved_t ) {
		update_option( PNCP_Traffic::STATE, $saved_t, false );
	}
}
foreach ( array_merge( (array) glob( $tmp . '/*/*' ), (array) glob( $tmp . '/*' ) ) as $file ) {
	if ( is_link( $file ) || is_file( $file ) ) {
		@unlink( $file );
	}
}
foreach ( array( $inside, $outside, $tmp ) as $dir ) {
	@rmdir( $dir );
}

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
