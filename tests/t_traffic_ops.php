<?php
/**
 * ScrapeLock 3.12 — Traffic operations (PNCP_Traffic_Alerts, PNCP_Traffic_Cli), on a real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_traffic_ops.php
 *
 * 1. Settings: traffic_alerts / traffic_alert_email (defaults off / empty, labels, the "traffic" section, a bad
 *    address refused), export / import of both.
 * 2. Alerts on 8 days of seeded traffic (ingest() + flush() + rollup(), the usual level from raw rows and from the
 *    aggregates): server errors (below the minimum, below 3× the usual, below 2 % of the requests: none; above:
 *    one email with the numbers, the top paths and a link to the Traffic tab), 404 on real pages (probes and
 *    metadata files never count), a new heavy User-Agent (browsers, a User-Agent seen before and small ones never;
 *    by count and by share; masked IPs), a stopped source (once per stop; not for a quiet source), throttling,
 *    recipients, alerts off, traffic off, through PNCP_Traffic::run().
 * 3. The weekly email's and the dashboard widget's Traffic part (present when on, absent when off).
 * 4. Site Health: the test only when on; good, a source error, no source, the daily figures behind, near the cap,
 *    no recent data; the info lines.
 * 5. WP-CLI: every subcommand and format, bad options, export refusing to overwrite, purge needing --yes.
 * 6. Uninstall.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
if ( ! $wp_dir ) {
	fwrite( STDERR, "WP_DIR is required\n" );
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

$mails = array();
add_filter(
	'pre_wp_mail',
	static function ( $short, $atts ) {
		global $mails;
		$mails[] = $atts;
		return true;
	},
	10,
	2
);

/** The emails sent by $fn. */
function mails_of( $fn ) {
	global $mails;
	$mails = array();
	$fn();
	return $mails;
}

/** Adds rows: [seconds ago, ip, status, path, ua] × count. */
function feed( $src, $rows ) {
	foreach ( $rows as $r ) {
		PNCP_Traffic::ingest(
			array(
				'ts'     => time() - $r[0],
				'ip'     => $r[1],
				'status' => $r[2],
				'path'   => $r[3],
				'ua'     => $r[4],
			),
			$src
		);
	}
	PNCP_Traffic::flush();
}

/** $n rows spread over the last hour. */
function last_hour( $n, $status, $path, $ua, $ip_base = '198.51.100.', $src = 'wp' ) {
	$rows = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$rows[] = array( 30 + ( $i * 37 ) % 3500, $ip_base . ( 1 + $i % 50 ), $status, is_array( $path ) ? $path[ $i % count( $path ) ] : $path, $ua );
	}
	feed( $src, $rows );
}

/** Deletes the raw rows of the last $seconds (of one source, or all). */
function forget_recent( $seconds = 3600, $src = '' ) {
	global $wpdb;
	if ( '' === $src ) {
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ts >= %d', PNCP_Traffic::table( 'raw' ), time() - $seconds ) );
	} else {
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ts >= %d AND src = %s', PNCP_Traffic::table( 'raw' ), time() - $seconds, $src ) );
	}
	PNCP_Traffic::reset();
}

function clear_alerts() {
	delete_option( PNCP_Traffic_Alerts::OPTION );
}

function has( $haystack, $needle ) {
	return false !== strpos( (string) $haystack, (string) $needle );
}

$sqlite  = false !== stripos( get_class( $GLOBALS['wpdb'] ), 'sqlite' );
$chrome  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
$saved   = get_option( PNCP_OPTION );
$had_db  = get_option( PNCP_Traffic::DB_OPTION, false );
$saved_t = get_option( PNCP_Traffic::STATE, false );
$saved_a = get_option( PNCP_Traffic_Alerts::OPTION, false );
$saved_z = get_option( 'timezone_string' );
$saved_m = get_option( 'admin_email' );
$tmp     = rtrim( sys_get_temp_dir(), '/' ) . '/pncp-traffic-ops-' . getmypid();
@mkdir( $tmp, 0700, true );
update_option( 'timezone_string', 'Europe/Athens' );
update_option( 'admin_email', 'owner@example.com' );

/* ---------- 1. Settings ---------- */

$d = PNCP_Options::defaults();
t( 'defaults: traffic_alerts 0, traffic_alert_email ""', 0 === $d['traffic_alerts'] && '' === $d['traffic_alert_email'] );
t( 'new_in_3120(): both keys, off / empty (existing sites)', isset( PNCP_Options::new_in_3120()['traffic_alerts'] ) && 0 === PNCP_Options::new_in_3120()['traffic_alerts'] && '' === PNCP_Options::new_in_3120()['traffic_alert_email'] );
t( 'both keys are in the "traffic" section, with labels', in_array( 'traffic_alerts', PNCP_Options::sections()['traffic'], true ) && in_array( 'traffic_alert_email', PNCP_Options::sections()['traffic'], true ) && isset( PNCP_Setting_Labels::all()['traffic_alerts'], PNCP_Setting_Labels::all()['traffic_alert_email'] ) );
t( 'traffic_alerts is an on/off setting', in_array( 'traffic_alerts', PNCP_Options::bool_keys(), true ) );
settings( array( 'traffic_alert_email' => 'ops@example.com' ) );
$clean = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic_alert_email' => ' a@example.com ,b@example.com, a@example.com', 'traffic_alerts' => '1' ) ) );
t( 'sanitize: a list of addresses is kept, cleaned', 'a@example.com, b@example.com' === $clean['traffic_alert_email'] && 1 === $clean['traffic_alerts'], $clean['traffic_alert_email'] );
$clean = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic_alert_email' => 'a@example.com, not-an-email' ) ) );
$errs  = wp_list_pluck( get_settings_errors( PNCP_OPTION ), 'code' );
t( 'sanitize: an address that is not one keeps the stored value, with a message', 'ops@example.com' === $clean['traffic_alert_email'] && in_array( 'pncp_traffic_alert_email', $errs, true ), $clean['traffic_alert_email'] );
$clean = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic_alert_email' => '' ) ) );
t( 'sanitize: empty = the administration email', '' === $clean['traffic_alert_email'] );
$clean = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic_alerts' => '1', 'traffic_alert_email' => 'x@example.com', '_sections' => array( 'general' ) ) ) );
t( 'sanitize: another tab\'s form keeps both', (int) PNCP_Options::stored()['traffic_alerts'] === $clean['traffic_alerts'] && 'ops@example.com' === $clean['traffic_alert_email'] );

settings(
	array(
		'traffic_alerts'      => 1,
		'traffic_alert_email' => 'ops@example.com, sec@example.com',
	)
);
$export = PNCP_Settings_Io::export();
t( 'export: both keys are in the file', 1 === (int) $export['settings']['traffic_alerts'] && 'ops@example.com, sec@example.com' === $export['settings']['traffic_alert_email'] );
settings(
	array(
		'traffic_alerts'      => 0,
		'traffic_alert_email' => '',
	)
);
$parsed   = PNCP_Settings_Io::parse( wp_json_encode( $export ) );
$prepared = PNCP_Settings_Io::prepare( $parsed['settings'] );
PNCP_Settings_Io::apply( $prepared, 'import' );
settings( array() );
$s = PNCP_Options::stored();
t( 'import: both keys come back as exported', ! $parsed['ignored'] && 1 === (int) $s['traffic_alerts'] && 'ops@example.com, sec@example.com' === $s['traffic_alert_email'], wp_json_encode( $parsed['ignored'] ) );
update_option( PNCP_OPTION, $saved );
PNCP_Options::flush();

/* ---------- Seed 8 days ---------- */

settings(
	array(
		'enabled'             => 1,
		'traffic'             => 1,
		'traffic_wp'          => 1,
		'traffic_log_path'    => '',
		'traffic_raw_days'    => 14,
		'traffic_days'        => 90,
		'traffic_ip_mode'     => 'full',
		'traffic_alerts'      => 1,
		'traffic_alert_email' => '',
		'report_weekly'       => 0,
	)
);
PNCP_Traffic::maybe_schedule();
PNCP_Traffic::purge_all();
clear_alerts();
t( 'seed: the tables are there, the source is WordPress', PNCP_Traffic::ready() && 'wp' === PNCP_Traffic::best_source() );
$rows = array();
for ( $h = 2; $h < 8 * 24; $h++ ) {
	for ( $i = 0; $i < 12; $i++ ) {
		$rows[] = array( $h * 3600 + $i * 250, '203.0.113.' . ( 1 + ( $h + $i ) % 40 ), 200, '/post-' . ( $h % 20 ) . '/', $chrome );
	}
	for ( $i = 0; $i < 3; $i++ ) {
		$rows[] = array( $h * 3600 + 100 + $i * 900, '192.0.2.10', 200, '/feed/', 'OldBot/1.0 (+https://oldbot.example)' );
	}
	for ( $i = 0; $i < 8; $i++ ) {
		$rows[] = array( $h * 3600 + 50 + $i * 400, '203.0.113.' . ( 1 + $i ), 503, '/flaky/', $chrome );
	}
	$rows[] = array( $h * 3600 + 1800, '203.0.113.9', 404, '/old-page/', $chrome );
}
feed( 'wp', $rows );
$days = PNCP_Traffic::rollup();
t( 'seed: ' . count( $rows ) . ' rows over 8 days, ' . $days . ' days counted', $days >= 8 && count( $rows ) > 4000, (string) $days );
// The usual level now comes from the raw rows of the last 3 days and from the aggregates before them.
settings( array( 'traffic_raw_days' => 3 ) );
t( 'probe paths and metadata files are noise, real pages are not', PNCP_Traffic_Alerts::is_noise( '/.env' ) && PNCP_Traffic_Alerts::is_noise( '/wp-config.php.bak' ) && PNCP_Traffic_Alerts::is_noise( '/llms.txt' ) && ! PNCP_Traffic_Alerts::is_noise( '/missing-article/' ) );

/* ---------- 2. Alerts ---------- */

// Quiet hour: nothing.
last_hour( 100, 200, '/post-1/', $chrome );
last_hour( 5, 503, '/flaky/', $chrome );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
t( 'quiet hour: no alert, no email', ! PNCP_Traffic_Alerts::evaluate( time() ) && ! $sent, wp_json_encode( array_keys( PNCP_Traffic_Alerts::evaluate( time() ) ) ) );

// 22 server errors: above the minimum of 20, below 3 × the usual 8 an hour.
forget_recent();
last_hour( 100, 200, '/post-1/', $chrome );
last_hour( 22, 503, '/flaky/', $chrome );
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( '5xx: 22 against a usual 8 an hour (needs 24): no alert', ! isset( $found['5xx'] ), wp_json_encode( $found ) );

// 30 server errors among 2,000 requests: 1.5 %, below 2 %.
forget_recent();
last_hour( 2000, 200, '/post-1/', $chrome );
last_hour( 30, 503, '/flaky/', $chrome );
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( '5xx: 30 of 2,030 requests (1.5 %): no alert', ! isset( $found['5xx'] ), wp_json_encode( $found ) );

// 45 server errors among 145 requests: an alert.
forget_recent();
last_hour( 100, 200, '/post-1/', $chrome );
last_hour( 30, 500, '/api/broken/', $chrome );
last_hour( 15, 502, '/checkout/', $chrome );
clear_alerts();
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( '5xx: 45 against a usual ~8 an hour: alert, with the usual level from the aggregates', isset( $found['5xx'] ) && 45 === $found['5xx']['count'] && $found['5xx']['usual'] > 6 && $found['5xx']['usual'] < 10 && $found['5xx']['hours'] > 7 * 24 - 2, wp_json_encode( isset( $found['5xx'] ) ? array_diff_key( $found['5xx'], array( 'top' => 1 ) ) : $found ) );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
$m    = $sent ? $sent[0] : array(
	'to'      => array(),
	'subject' => '',
	'message' => '',
);
t( '5xx: exactly one email, to the administration email', 1 === count( $sent ) && array( 'owner@example.com' ) === (array) $m['to'], wp_json_encode( $sent ) );
t( '5xx email: subject and numbers', has( $m['subject'], '45 server errors (5xx)' ) && has( $m['message'], '45' ) && has( $m['message'], '145' ) && has( $m['message'], '31.0%' ), $m['subject'] . ' | ' . $m['message'] );
t( '5xx email: the top paths (/api/broken/ first, /checkout/)', has( $m['message'], '- /api/broken/: 30' ) && has( $m['message'], '/checkout/: 15' ) && strpos( $m['message'], '/api/broken/' ) < strpos( $m['message'], '/checkout/' ), $m['message'] );
preg_match( '#(https?://\S*options-general\.php\?\S+)#', $m['message'], $u );
$link = isset( $u[1] ) ? $u[1] : '';
parse_str( (string) wp_parse_url( $link, PHP_URL_QUERY ), $q );
t( '5xx email: link to the Traffic tab with view, from, to, status prefilled', isset( $q['page'], $q['tab'], $q['view'], $q['from'], $q['to'], $q['status'] ) && 'scrapelock' === $q['page'] && 'traffic' === $q['tab'] && 'problems' === $q['view'] && '5xx' === $q['status'] && (int) $q['to'] - (int) $q['from'] === 3600 && abs( (int) $q['to'] - time() ) < 120, $link );
t( '5xx email: plain text (no HTML)', $m['message'] === wp_strip_all_tags( $m['message'] ) );

// Throttling.
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
t( 'throttle: the same spike 15 minutes later sends nothing', ! $sent && isset( PNCP_Traffic_Alerts::state()['sent']['5xx'] ) );
$st                 = PNCP_Traffic_Alerts::state();
$st['sent']['5xx']  = time() - 7 * HOUR_IN_SECONDS;
update_option( PNCP_Traffic_Alerts::OPTION, $st, false );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
t( 'throttle: 7 hours later it is sent again', 1 === count( $sent ) );
add_filter( 'pncp_traffic_alert_interval', '__return_zero' );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
remove_filter( 'pncp_traffic_alert_interval', '__return_zero' );
t( 'throttle: filter pncp_traffic_alert_interval (0 = every run)', 1 === count( $sent ) );
$raise = static function ( $t ) {
	$t['min_5xx'] = 100;
	return $t;
};
add_filter( 'pncp_traffic_alert_thresholds', $raise );
t( 'filter pncp_traffic_alert_thresholds: a minimum of 100 silences it', ! isset( PNCP_Traffic_Alerts::evaluate( time() )['5xx'] ) );
remove_filter( 'pncp_traffic_alert_thresholds', $raise );

// Recipients.
clear_alerts();
settings( array( 'traffic_alert_email' => 'ops@example.com, sec@example.com' ) );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
t( 'traffic_alert_email: the alert goes to those addresses', $sent && array( 'ops@example.com', 'sec@example.com' ) === array_values( (array) $sent[0]['to'] ), $sent ? wp_json_encode( $sent[0]['to'] ) : '' );
settings( array( 'traffic_alert_email' => '' ) );

// Alerts off, traffic off.
clear_alerts();
settings( array( 'traffic_alerts' => 0 ) );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
t( 'alerts off: the spike sends nothing, stores nothing', ! $sent && false === get_option( PNCP_Traffic_Alerts::OPTION, false ) );
settings(
	array(
		'traffic_alerts' => 1,
		'traffic'        => 0,
	)
);
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
		PNCP_Log::cache_delete( 'pncp_traffic_lock' );
		PNCP_Traffic::run();
	}
);
t( 'traffic off: neither check() nor the run send anything or store anything', ! $sent && false === get_option( PNCP_Traffic_Alerts::OPTION, false ) );
settings( array( 'traffic' => 1 ) );

// Through the scheduled run.
PNCP_Log::cache_delete( 'pncp_traffic_lock' );
$sent = mails_of(
	static function () {
		PNCP_Traffic::run();
	}
);
t( 'PNCP_Traffic::run(): checks the alerts after the rollup and sends the 5xx one', 1 === count( $sent ) && has( $sent[0]['subject'], '5xx' ) && isset( PNCP_Traffic_Alerts::state()['sent']['5xx'] ) );

// 404: probes and metadata files never count.
forget_recent();
clear_alerts();
last_hour( 100, 200, '/post-1/', $chrome );
last_hour( 60, 404, array( '/.env', '/wp-config.php.bak', '/.git/config', '/llms.txt' ), 'Mozilla/5.0 zgrab/0.x' );
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( '404: 60 probes and metadata files: no alert', ! isset( $found['404'] ), wp_json_encode( $found ) );
last_hour( 15, 404, '/missing-article/', $chrome );
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( '404: 15 on a real page (below 20): no alert', ! isset( $found['404'] ), wp_json_encode( $found ) );
last_hour( 25, 404, '/missing-article/', $chrome );
last_hour( 6, 404, '/old-shop/', $chrome );
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( '404: 46 on real pages against a usual ~1: alert, probes not counted', isset( $found['404'] ) && 46 === $found['404']['count'] && $found['404']['usual'] < 2 && $found['404']['usual'] > 0.5, wp_json_encode( isset( $found['404'] ) ? array_diff_key( $found['404'], array( 'top' => 1 ) ) : $found ) );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
$m404 = '';
foreach ( $sent as $one ) {
	if ( has( $one['subject'], '404' ) ) {
		$m404 = $one['message'];
	}
}
t( '404 email: /missing-article/ first, no probe path, link with status=404', has( $m404, '- /missing-article/: 40' ) && has( $m404, '/old-shop/' ) && ! has( $m404, '- /.env' ) && ! has( $m404, '- /llms.txt' ) && ! has( $m404, '- /wp-config' ) && has( $m404, 'view=problems' ) && has( $m404, 'status=404' ), $m404 . wp_json_encode( wp_list_pluck( $sent, 'subject' ) ) );

// A new heavy User-Agent.
forget_recent();
clear_alerts();
last_hour( 400, 200, '/post-1/', $chrome );
last_hour( 600, 200, '/post-2/', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36' );
last_hour( 600, 200, '/feed/', 'OldBot/1.0 (+https://oldbot.example)', '192.0.2.' );
last_hour( 30, 200, '/post-3/', 'SmallBot/1.0' );
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( 'new UA: a new browser, a User-Agent seen before and a small one: no alert', ! isset( $found['ua'] ), wp_json_encode( isset( $found['ua'] ) ? $found['ua'] : $found ) );
last_hour( 520, 200, array( '/post-4/', '/post-5/' ), 'WeirdCrawler/2.0 (+http://weird.example)', '198.18.0.' );
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( 'new UA: 520 requests in the hour: alert', isset( $found['ua'] ) && 'WeirdCrawler/2.0 (+http://weird.example)' === $found['ua']['top'][0]['key'] && 520 === $found['ua']['top'][0]['hits'] && 1 === count( $found['ua']['top'] ), wp_json_encode( isset( $found['ua'] ) ? $found['ua'] : $found ) );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
$mua  = '';
foreach ( $sent as $one ) {
	if ( has( $one['subject'], 'User-Agent' ) ) {
		$mua = $one['message'];
	}
}
preg_match_all( '/198\.18\.0\.\d+/', $mua, $ipm );
t( 'new UA email: the User-Agent, its count, at most 5 IPs, link with view=raw and the User-Agent', has( $mua, 'WeirdCrawler/2.0' ) && has( $mua, '520' ) && count( $ipm[0] ) <= 5 && count( $ipm[0] ) > 0 && has( $mua, 'view=raw' ) && has( $mua, 'ua=WeirdCrawler%2F2.0%20%28%2Bhttp%3A%2F%2Fweird.example%29' ), $mua );
// By share, with masked IPs.
forget_recent();
clear_alerts();
settings( array( 'traffic_ip_mode' => 'masked' ) );
last_hour( 900, 200, '/post-1/', $chrome );
last_hour( 120, 200, '/post-6/', 'ShareBot/1.0', '198.18.7.' );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
$mua  = '';
foreach ( $sent as $one ) {
	if ( has( $one['subject'], 'User-Agent' ) ) {
		$mua = $one['message'];
	}
}
t( 'new UA: 120 of 1,020 requests (12 %): alert; IPs masked as stored', has( $mua, 'ShareBot/1.0' ) && has( $mua, '198.18.7.0' ) && ! preg_match( '/198\.18\.7\.[1-9]/', $mua ), $mua );
settings( array( 'traffic_ip_mode' => 'full' ) );
$short = static function ( $t ) {
	$t['history_hours'] = 10000;
	return $t;
};
add_filter( 'pncp_traffic_alert_thresholds', $short );
t( 'new UA: not before history_hours of data', ! isset( PNCP_Traffic_Alerts::evaluate( time() )['ua'] ) );
remove_filter( 'pncp_traffic_alert_thresholds', $short );

/* ---------- 3. Weekly email, dashboard ---------- */

$mail = PNCP_Attack_Report::email( 7 );
t( 'weekly email: a Traffic part with requests, 4xx / 5xx share, problem URLs, non-browser User-Agents', has( $mail['body'], 'Traffic:' ) && has( $mail['body'], 'Requests:' ) && has( $mail['body'], '/flaky/' ) && has( $mail['body'], 'OldBot/1.0' ) && ! has( $mail['body'], 'Chrome/131' ) && has( $mail['body'], 'tab=traffic' ), $mail['body'] );
wp_set_current_user( 1 );
PNCP_Log::cache_delete( PNCP_Traffic_Alerts::WIDGET_CACHE );
ob_start();
PNCP_Attack_Report::dashboard_widget();
$widget = ob_get_clean();
t( 'dashboard widget: one Traffic line with a link', has( $widget, 'Traffic, 7 days:' ) && has( $widget, 'tab=traffic' ), $widget );
settings( array( 'traffic' => 0 ) );
$mail_off = PNCP_Attack_Report::email( 7 );
ob_start();
PNCP_Attack_Report::dashboard_widget();
$widget = ob_get_clean();
t( 'traffic off: no Traffic part in the weekly email or the widget', ! has( $mail_off['body'], 'Traffic:' ) && ! has( $mail_off['body'], 'tab=traffic' ) && ! has( $widget, 'Traffic, 7 days' ) );

/* ---------- 4. Site Health ---------- */

$tests = PNCP_Health::tests( array() );
t( 'Site Health: no traffic test while off', ! isset( $tests['direct']['scrapelock_traffic'] ) );
$info = PNCP_Health::info( array() );
t( 'Site Health info while off: "Traffic statistics: No", no data line', isset( $info['scrapelock']['fields']['traffic'] ) && 'No' === $info['scrapelock']['fields']['traffic']['value'] && ! isset( $info['scrapelock']['fields']['traffic_data'] ) );
settings( array( 'traffic' => 1 ) );
$tests = PNCP_Health::tests( array() );
t( 'Site Health: the "ScrapeLock traffic statistics" test while on', isset( $tests['direct']['scrapelock_traffic'] ) && 'ScrapeLock traffic statistics' === $tests['direct']['scrapelock_traffic']['label'] );
PNCP_Traffic::rollup();
$r = PNCP_Traffic_Alerts::health_test();
t( 'Site Health: good (data in the last 3 hours), link to the Traffic tab', 'good' === $r['status'] && has( $r['actions'], 'tab=traffic' ), wp_json_encode( $r ) );
$info = PNCP_Health::info( array() );
$f    = $info['scrapelock']['fields'];
t( 'Site Health info: source and the rows stored, first and last day', has( $f['traffic']['value'], 'WordPress' ) && isset( $f['traffic_data'] ) && preg_match( '/requests stored; daily figures from \d{4}-\d{2}-\d{2} to \d{4}-\d{2}-\d{2}/', $f['traffic_data']['value'] ), wp_json_encode( array_intersect_key( $f, array_flip( array( 'traffic', 'traffic_data' ) ) ) ) );
$st            = PNCP_Traffic::state();
$st['pending'] = array( PNCP_Traffic::day_start( time() ) );
PNCP_Traffic::save_state( $st );
$r = PNCP_Traffic_Alerts::health_test();
t( 'Site Health: recommended while days wait to be counted', 'recommended' === $r['status'] && has( $r['description'], 'behind' ), wp_json_encode( $r ) );
$st['pending'] = array();
PNCP_Traffic::save_state( $st );
$cap = static function () {
	return 100;
};
add_filter( 'pncp_traffic_max_raw_rows', $cap );
$r = PNCP_Traffic_Alerts::health_test();
remove_filter( 'pncp_traffic_max_raw_rows', $cap );
t( 'Site Health: recommended near the cap on raw rows', 'recommended' === $r['status'] && has( $r['description'], 'at most 100' ), wp_json_encode( $r ) );
$log = $tmp . '/access.log';
file_put_contents( $log, '' );
settings( array( 'traffic_log_path' => $log ) );
$st           = PNCP_Traffic::state();
$st['server'] = array(
	'error'    => 'unreadable',
	'last_run' => time(),
);
PNCP_Traffic::save_state( $st );
$r = PNCP_Traffic_Alerts::health_test();
t( 'Site Health: recommended with the error of a source in words', 'recommended' === $r['status'] && has( $r['description'], esc_html( PNCP_Traffic_Log::refusal_text( 'unreadable' ) ) ), wp_json_encode( $r ) );
$st['server'] = array();
PNCP_Traffic::save_state( $st );
settings(
	array(
		'traffic_log_path' => '',
		'traffic_wp'       => 0,
	)
);
$r = PNCP_Traffic_Alerts::health_test();
t( 'Site Health: recommended when no source is set up', 'recommended' === $r['status'] && has( $r['description'], 'No source is set up' ), wp_json_encode( $r ) );
settings( array( 'traffic_wp' => 1 ) );

/* ---------- Stopped source ---------- */

// The access log brought 20 requests an hour for 8 days, then nothing for 4 hours.
clear_alerts();
$rows = array();
for ( $h = 4; $h < 8 * 24; $h++ ) {
	for ( $i = 0; $i < 20; $i++ ) {
		$rows[] = array( $h * 3600 + $i * 170, '203.0.113.' . ( 1 + $i ), 200, '/post-' . $i . '/', $chrome );
	}
}
settings( array( 'traffic_raw_days' => 14 ) );
feed( 'server', $rows );
PNCP_Traffic::rollup();
settings(
	array(
		'traffic_raw_days' => 3,
		'traffic_log_path' => $log,
	)
);
t( 'stopped: WordPress stays the source in use', 'wp' === PNCP_Traffic::best_source() );
$found = PNCP_Traffic_Alerts::evaluate( time() );
t( 'stopped: the access log, quiet for 4 hours, usually ~20 an hour: alert', isset( $found['stopped']['sources']['server'] ) && ! isset( $found['stopped']['sources']['wp'] ) && $found['stopped']['sources']['server']['usual'] > 15, wp_json_encode( isset( $found['stopped'] ) ? $found['stopped'] : $found ) );
$sent = mails_of(
	static function () {
		PNCP_Traffic_Alerts::check();
	}
);
$mst  = '';
foreach ( $sent as $one ) {
	if ( has( $one['subject'], 'stopped' ) ) {
		$mst = $one['message'];
	}
}
t( 'stopped email: names the source, the usual level and links to the sources', has( $mst, 'Web server access log' ) && has( $mst, 'view=sources' ), $mst );
$st                    = PNCP_Traffic_Alerts::state();
$st['sent']['stopped'] = 0;
update_option( PNCP_Traffic_Alerts::OPTION, $st, false );
t( 'stopped: the same stop is never reported twice', ! isset( PNCP_Traffic_Alerts::evaluate( time() )['stopped'] ) );
feed( 'server', array( array( 10, '203.0.113.5', 200, '/', $chrome ) ) );
PNCP_Traffic_Alerts::check();
t( 'stopped: data again clears the stop (the next one is reported)', ! isset( PNCP_Traffic_Alerts::state()['stopped']['server'] ) );
forget_recent( 5 * HOUR_IN_SECONDS, 'server' );
$quiet = static function ( $t ) {
	$t['stopped_min_hourly'] = 50;
	return $t;
};
add_filter( 'pncp_traffic_alert_thresholds', $quiet );
t( 'stopped: not for a source that usually brings little', ! isset( PNCP_Traffic_Alerts::evaluate( time() )['stopped'] ) );
remove_filter( 'pncp_traffic_alert_thresholds', $quiet );
settings( array( 'traffic_log_path' => '' ) );

// No recent data from the source in use.
forget_recent( 5 * HOUR_IN_SECONDS, 'wp' );
$r = PNCP_Traffic_Alerts::health_test();
t( 'Site Health: recommended when the source in use brought nothing for 3 hours', 'recommended' === $r['status'] && has( $r['description'], 'brought no request since' ), wp_json_encode( $r ) );

/* ---------- 5. WP-CLI ---------- */

if ( '' !== $wp_cli ) {
	$cli = static function ( $args ) use ( $wp_cli ) {
		exec( $wp_cli . ' scrapelock traffic ' . $args . ' 2>&1', $out, $rc );
		wp_cache_flush();
		return array( $rc, implode( "\n", $out ) );
	};
	$json = static function ( $out ) {
		$v = json_decode( (string) preg_replace( '/^[^\[\{]*/s', '', (string) $out ), true );
		return is_array( $v ) ? $v : null;
	};
	last_hour( 50, 200, '/cli-page/', $chrome );
	last_hour( 10, 404, '/cli-missing/', $chrome );
	list( $rc, $out ) = $cli( 'status --format=json' );
	$v                = $json( $out );
	t( 'CLI status --format=json: three sources, WordPress on and in use', 0 === $rc && is_array( $v ) && array( 'bunny', 'server', 'wp' ) === array_column( $v, 'source' ) && 'yes' === $v[2]['on'] && 'yes' === $v[2]['auto'], $out );
	list( $rc, $out ) = $cli( 'status' );
	t( 'CLI status (table): the sources and the daily figures', 0 === $rc && has( $out, 'wp' ) && has( $out, 'Daily figures counted' ), $out );
	list( $rc, $out ) = $cli( 'overview --from=24h --format=json' );
	$v                = $json( $out );
	$map              = is_array( $v ) ? array_column( $v, 'value', 'metric' ) : array();
	t( 'CLI overview --from=24h --format=json: totals', 0 === $rc && isset( $map['total'], $map['s4xx'] ) && (int) $map['total'] >= 60 && (int) $map['s4xx'] >= 10 && 'wp' === $map['src_used'], $out );
	list( $rc, $out ) = $cli( 'overview --from=2h --series --format=csv' );
	t( 'CLI overview --series --format=csv: a header and hourly rows', 0 === $rc && 0 === strpos( $out, 'time,hits,s4xx,s5xx' ) && substr_count( $out, "\n" ) >= 2, $out );
	list( $rc, $out ) = $cli( 'overview --from=7d --format=yaml' );
	t( 'CLI overview --from=7d --format=yaml', 0 === $rc && has( $out, 'metric: total' ), $out );
	list( $rc, $out ) = $cli( 'overview --from=' . wp_date( 'Y-m-d', time() - 2 * DAY_IN_SECONDS ) . ' --to=' . wp_date( 'Y-m-d' ) . ' --format=table' );
	t( 'CLI overview with dates (--from=YYYY-MM-DD --to=YYYY-MM-DD), table', 0 === $rc && has( $out, 'total' ), $out );
	list( $rc, $out ) = $cli( 'top path --from=1h --limit=3 --format=json' );
	$v                = $json( $out );
	t( 'CLI top path --limit=3: at most 3 rows, /cli-page/ first', 0 === $rc && is_array( $v ) && count( $v ) <= 3 && '/cli-page/' === $v[0]['key'], $out );
	list( $rc, $out ) = $cli( 'top ua --from=24h --format=json' );
	$v                = $json( $out );
	t( 'CLI top ua: rows with family and name', 0 === $rc && is_array( $v ) && isset( $v[0]['family'], $v[0]['name'] ), $out );
	list( $rc, $out ) = $cli( 'top nothing' );
	t( 'CLI top with an unknown dimension: error', 0 !== $rc, $out );
	list( $rc, $out ) = $cli( 'problems 404 --from=1h --format=json' );
	$v                = $json( $out );
	t( 'CLI problems 404: /cli-missing/ with its statuses', 0 === $rc && is_array( $v ) && in_array( '/cli-missing/', array_column( $v, 'path' ), true ) && has( wp_json_encode( $v ), '404:10' ), $out );
	list( $rc, $out ) = $cli( 'problems 5xx --from=7d --format=csv' );
	t( 'CLI problems 5xx --from=7d --format=csv: /flaky/', 0 === $rc && has( $out, '/flaky/' ), $out );
	list( $rc, $out ) = $cli( 'problems weird' );
	t( 'CLI problems with an unknown kind: error', 0 !== $rc, $out );
	list( $rc, $out ) = $cli( 'raw --page=/cli-missing/ --limit=5 --format=json' );
	$v                = $json( $out );
	t( 'CLI raw --page --limit=5: 5 rows of that path', 0 === $rc && is_array( $v ) && 5 === count( $v ) && array( '/cli-missing/' ) === array_values( array_unique( array_column( $v, 'path' ) ) ) && 404 === (int) $v[0]['status'], $out );
	list( $rc, $out ) = $cli( 'raw --status=404 --search=cli --limit=2 --format=yaml' );
	t( 'CLI raw --status --search --format=yaml', 0 === $rc && has( $out, '/cli-missing/' ), $out );
	list( $rc, $out ) = $cli( 'raw --ua=' . escapeshellarg( $chrome ) . ' --limit=1 --format=json' );
	$v                = $json( $out );
	t( 'CLI raw --ua (exact)', 0 === $rc && is_array( $v ) && 1 === count( $v ) && $chrome === $v[0]['ua'], $out );
	list( $rc, $out ) = $cli( 'raw --from=yesterday-ish' );
	t( 'CLI: a --from that is not understood is an error', 0 !== $rc && has( $out, 'not understood' ), $out );
	list( $rc, $out ) = $cli( 'raw --status=abc' );
	t( 'CLI: a bad --status is an error', 0 !== $rc, $out );
	list( $rc, $out ) = $cli( 'raw --format=xml' );
	t( 'CLI: an unknown --format is an error', 0 !== $rc, $out );
	$csv              = $tmp . '/export.csv';
	list( $rc, $out ) = $cli( 'export ' . escapeshellarg( $csv ) . ' --from=1h --page=/cli-missing/' );
	$lines            = is_readable( $csv ) ? file( $csv ) : array();
	t( 'CLI export: CSV with a header and the 10 rows', 0 === $rc && 11 === count( $lines ) && 0 === strpos( (string) $lines[0], 'time,source,ip' ), $out );
	file_put_contents( $csv, 'keep me' );
	list( $rc, $out ) = $cli( 'export ' . escapeshellarg( $csv ) . ' --from=1h' );
	t( 'CLI export: an existing file is not replaced without --force', 0 !== $rc && 'keep me' === file_get_contents( $csv ) && has( $out, '--force' ), $out );
	list( $rc, $out ) = $cli( 'export ' . escapeshellarg( $csv ) . ' --from=1h --force' );
	t( 'CLI export --force replaces it', 0 === $rc && 0 === strpos( (string) file_get_contents( $csv ), 'time,source' ), $out );
	list( $rc, $out ) = $cli( 'test-path /nonexistent/access.log --format=json' );
	$v                = $json( $out );
	t( 'CLI test-path: a missing file, its code and the sentence, exit 1', 1 === $rc && is_array( $v ) && 'unreadable' === $v[0]['value'], $out );
	file_put_contents( $log, '203.0.113.5 - - [' . gmdate( 'd/M/Y:H:i:s O' ) . '] "GET / HTTP/1.1" 200 512 "-" "' . $chrome . '"' . "\n" );
	list( $rc, $out ) = $cli( 'test-path ' . escapeshellarg( $log ) );
	t( 'CLI test-path: a real access log is ok', 0 === $rc && has( $out, 'ok' ), $out );
	clear_alerts();
	last_hour( 40, 500, '/cli-broken/', $chrome );
	// WP-CLI is another process: its mail is caught there too (WP_CLI::add_wp_hook() works before WordPress loads).
	list( $rc, $out ) = $cli( 'run --exec=' . escapeshellarg( 'WP_CLI::add_wp_hook( "pre_wp_mail", "__return_true" );' ) );
	t( 'CLI run: runs the job (and the alerts)', 0 === $rc && has( $out, 'The traffic job ran' ) && has( $out, 'Alerts sent: 5xx' ) && isset( PNCP_Traffic_Alerts::state()['sent']['5xx'] ), $out );
	list( $rc, $out ) = $cli( 'purge' );
	t( 'CLI purge without --yes: error, nothing deleted', 0 !== $rc && PNCP_Traffic::raw( array( 'from' => time() - 3600 ) )['rows'], $out );
	list( $rc, $out ) = $cli( 'purge --yes' );
	PNCP_Traffic::reset();
	t( 'CLI purge --yes: everything deleted', 0 === $rc && 0 === PNCP_Traffic::overview( array( 'from' => time() - 3600 ) )['total'], $out );
	list( $rc, $out ) = $cli( 'nonsense' );
	t( 'CLI: an unknown subcommand is an error', 0 !== $rc, $out );
} else {
	echo "SKIP WP-CLI checks (no WP_CLI)\n";
}

/* ---------- 6. Uninstall ---------- */

update_option( PNCP_Traffic_Alerts::OPTION, array( 'sent' => array( '5xx' => time() ) ), false );
PNCP_Traffic::uninstall();
t( 'PNCP_Traffic::uninstall(): the alert state is deleted too', false === get_option( PNCP_Traffic_Alerts::OPTION, false ) );
$un = (string) file_get_contents( dirname( __DIR__ ) . '/uninstall.php' );
t( 'uninstall.php: deletes pncp_traffic_alerts', has( $un, "'pncp_traffic_alerts'" ) );
settings( array( 'traffic' => 0 ) );
t( 'no cron event of its own (the alerts run in the traffic job)', ! wp_next_scheduled( 'pncp_traffic_alerts' ) );

/* ---------- Clean up ---------- */

update_option( PNCP_OPTION, $saved );
update_option( 'timezone_string', $saved_z );
update_option( 'admin_email', $saved_m );
PNCP_Options::flush();
if ( false !== $had_db ) {
	PNCP_Traffic::install();
	if ( false !== $saved_t ) {
		update_option( PNCP_Traffic::STATE, $saved_t, false );
	}
}
if ( false !== $saved_a ) {
	update_option( PNCP_Traffic_Alerts::OPTION, $saved_a, false );
}
foreach ( (array) glob( $tmp . '/*' ) as $file ) {
	@unlink( $file );
}
@rmdir( $tmp );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
