<?php
/**
 * ScrapeLock 3.12.1 — Traffic: safer defaults (GDPR), in real WordPress, over HTTP with an administrator's cookie.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3121_traffic.php
 *
 * D1. A brand-new install stores "traffic_ip_mode" = masked; an upgrade from 3.11 or 3.12.0 keeps what the site has
 *     (full stays full: no migration); defaults() (the fallback of a missing key) is unchanged.
 * D2. "Start collecting": the IP addresses choice with Masked chosen in advance on a site that has not collected yet
 *     (also when it stored "full"), one sentence for what each mode stores and the retention of single requests;
 *     a site that collected before keeps its own choice; the chosen mode is saved with the start (none sent = as
 *     stored, as in 3.12.0).
 * D3. Masked: requests from the WordPress source (HTTP), Bunny and the access log are stored with masked addresses
 *     only: the four tables, the Traffic options, raw / top / detail / problems, the CSV, the alert emails, the
 *     weekly report and dashboard lines, and "wp scrapelock traffic" (WP_CLI given) never hold a full address.
 * D4. The suggested privacy policy text names Traffic, its retention and the masking.
 *
 * Changes the database: test sites only. Settings and Traffic data are put back / emptied at the end.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
$wp_cli = (string) getenv( 'WP_CLI' );

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

function stored() {
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_delete( PNCP_OPTION, 'options' );
	PNCP_Options::flush();
	return PNCP_Options::stored();
}

/** pncp_upgrade() leaves the file sync (early check, pre-cache check) to the next request: not wanted here. */
function no_file_sync() {
	delete_option( 'pncp_upgrade_files' );
	wp_clear_scheduled_hook( 'pncp_upgrade_files' );
}

function cookies_for( $user_id ) {
	$expire = time() + DAY_IN_SECONDS;
	$token  = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	return array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
}

/** A request: [code, body, location]. $who: admin | '' (a visitor). */
function http( $path, $post = null, $who = 'admin', $ip = '192.0.2.241' ) {
	global $base, $jars;
	$ch  = curl_init( $base . $path );
	$jar = array();
	if ( '' !== $who ) {
		foreach ( $jars[ $who ] as $k => $v ) {
			$jar[] = $k . '=' . rawurlencode( $v );
		}
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: ' . $ip, 'X-Forwarded-For: ' . $ip, 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 Gdpr', 'Accept: text/html', 'Accept-Language: en', 'Sec-Fetch-Mode: navigate', 'Sec-Fetch-Dest: document' ),
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
	return array( $code, substr( $out, $hs ), html_entity_decode( $loc ) );
}

function tab() {
	return '/wp-admin/options-general.php?page=' . PNCP_Admin::PAGE . '&tab=traffic';
}

/** The "Start collecting" form's IP addresses choice: [value of the checked radio, the fieldset's text]. */
function ip_choice( $body ) {
	if ( ! preg_match( '#<fieldset class="pncp-tr__ipmode">(.*?)</fieldset>#s', $body, $m ) ) {
		return array( '', '' );
	}
	$checked = preg_match( '#<input type="radio" name="ip_mode" value="(\w+)"[^>]*checked#', $m[1], $c ) ? $c[1] : '';
	return array( $checked, trim( (string) preg_replace( '/\s+/', ' ', html_entity_decode( wp_strip_all_tags( $m[1] ), ENT_QUOTES ) ) ) );
}

function start( $mode = null ) {
	$post = array(
		'action'   => PNCP_Traffic_Actions::ACTION,
		'_wpnonce' => wp_create_nonce( PNCP_Traffic_Actions::ACTION ),
		'op'       => 'start',
	);
	if ( null !== $mode ) {
		$post['ip_mode'] = $mode;
	}
	return http( '/wp-admin/admin-post.php', $post );
}

/* ---------- Users and state ---------- */
$admin                       = get_user_by( 'id', 1 );
$jars                        = array( 'admin' => cookies_for( $admin->ID ) );
$_COOKIE[ LOGGED_IN_COOKIE ] = $jars['admin'][ LOGGED_IN_COOKIE ];
wp_set_current_user( $admin->ID );

$saved     = get_option( PNCP_OPTION );
$saved_ver = get_option( 'pncp_version' );
$saved_bak = get_option( 'pncp_settings_backups', false );
$tmp       = rtrim( sys_get_temp_dir(), '/' ) . '/pncp-gdpr-' . getmypid();
@mkdir( $tmp, 0700, true );
register_shutdown_function(
	static function () use ( $saved, $saved_ver, $saved_bak, $tmp ) {
		PNCP_Traffic::purge_all();
		update_option( PNCP_OPTION, $saved );
		update_option( 'pncp_version', $saved_ver );
		false === $saved_bak ? delete_option( 'pncp_settings_backups' ) : update_option( 'pncp_settings_backups', $saved_bak, false );
		PNCP_Options::flush();
		no_file_sync();
		foreach ( (array) glob( $tmp . '/*' ) as $file ) {
			@unlink( $file );
		}
		@rmdir( $tmp );
	}
);

/* ---------- D1. New installs only ---------- */
t( 'D1 defaults(): traffic_ip_mode stays "full" (the fallback of a site that has no value stored)', 'full' === PNCP_Options::defaults()['traffic_ip_mode'] );
t( 'D1 new-install defaults: traffic_ip_mode "masked"', 'masked' === PNCP_Options::install_defaults()['traffic_ip_mode'] && 'masked' === PNCP_Options::new_install()['traffic_ip_mode'] );
delete_option( PNCP_OPTION );
delete_option( 'pncp_version' );
PNCP_Options::flush();
pncp_upgrade();
no_file_sync();
t( 'D1 a brand-new install stores traffic_ip_mode "masked" (and Traffic off)', 'masked' === stored()['traffic_ip_mode'] && empty( stored()['traffic'] ), wp_json_encode( array_intersect_key( stored(), array_flip( array( 'traffic', 'traffic_ip_mode' ) ) ) ) );
foreach ( array( '3.11.2', '3.12.0' ) as $from ) {
	$old = $saved;
	if ( '3.11.2' === $from ) {
		$old = array_diff_key( $old, PNCP_Options::new_in_3120() ); // 3.11 had no Traffic keys.
	} else {
		$old['traffic_ip_mode'] = 'full';
	}
	update_option( PNCP_OPTION, $old );
	update_option( 'pncp_version', $from );
	PNCP_Options::flush();
	pncp_upgrade();
	no_file_sync();
	t( "D1 upgrade from $from: traffic_ip_mode \"full\" as the site had it (no migration)", 'full' === stored()['traffic_ip_mode'], (string) stored()['traffic_ip_mode'] );
}
update_option( PNCP_OPTION, $saved );
update_option( 'pncp_version', $saved_ver );
PNCP_Options::flush();
$saved_collecting = $saved;
$saved_collecting['traffic']         = 1;
$saved_collecting['traffic_ip_mode'] = 'full';
update_option( PNCP_OPTION, $saved_collecting );
update_option( 'pncp_version', '3.12.0' );
PNCP_Options::flush();
pncp_upgrade();
no_file_sync();
t( 'D1 a site that already collects with full addresses keeps them full after the upgrade', 'full' === stored()['traffic_ip_mode'] && 1 === (int) stored()['traffic'] );
update_option( 'pncp_version', $saved_ver );

/* ---------- D2. "Start collecting" ---------- */
settings(
	array(
		'enabled'          => 1,
		'monitor_mode'     => 0,
		'monitor_until'    => 0,
		'traffic'          => 0,
		'traffic_wp'       => 0,
		'traffic_log_path' => '',
		'traffic_raw_days' => 3,
		'traffic_days'     => 90,
		'traffic_ip_mode'  => 'full',
		'bunny_import'     => 0,
	)
);
PNCP_Traffic::install();
PNCP_Traffic::purge_all();
list( $code, $body ) = http( tab() );
$has_data = false;
$status   = PNCP_Traffic::sources_status();
foreach ( PNCP_Traffic::SOURCES as $src ) {
	$has_data = $has_data || (int) $status[ $src ]['last_ingest'] > 0;
}
list( $checked, $text ) = ip_choice( $body );
t( 'D2 off, never collected, "full" stored: the start screen asks how IPs are stored, Masked chosen in advance', 200 === $code && ! $has_data && 'masked' === $checked, $code . ' ' . $checked . ' ' . $text );
t( 'D2 the choice says in one sentence what each mode stores', false !== strpos( $text, 'Masked (recommended)' ) && false !== strpos( $text, 'Removes the last part of each address before storing it (IPv4 /24, IPv6 /48)' ) && false !== strpos( $text, 'Stores every address as it is' ), $text );
t( 'D2 the choice states the retention of single requests (3 days) and of the daily figures (90 days)', false !== strpos( $text, 'Single requests, with their address, are deleted after 3 days; daily figures after 90 days.' ), $text );
t( 'D2 the radios are inside the "Start collecting" form', (bool) preg_match( '#value="start">.*?<fieldset class="pncp-tr__ipmode">.*?id="pncp-tr-start"#s', $body ) );
settings( array( 'traffic_raw_days' => 7 ) );
list( , $body ) = http( tab() );
t( 'D2 the retention follows the setting (7 days)', false !== strpos( ip_choice( $body )[1], 'deleted after 7 days' ), ip_choice( $body )[1] );
settings( array( 'traffic_raw_days' => 3 ) );

list( , , $loc ) = start();
t( 'D2 "Start collecting" without a choice sent (as 3.12.0 did): the stored mode stays', 1 === (int) stored()['traffic'] && 'full' === stored()['traffic_ip_mode'], $loc );
settings( array( 'traffic' => 0, 'traffic_wp' => 0 ) );
start( 'masked' );
t( 'D2 "Start collecting" with Masked: collection on, IPs masked', 1 === (int) stored()['traffic'] && 'masked' === stored()['traffic_ip_mode'] );
settings( array( 'traffic' => 0, 'traffic_wp' => 0 ) );
start( 'full' );
t( 'D2 "Start collecting" with Full: full addresses, as chosen', 1 === (int) stored()['traffic'] && 'full' === stored()['traffic_ip_mode'] );
settings( array( 'traffic' => 0, 'traffic_wp' => 0, 'traffic_ip_mode' => 'masked' ) );
start( 'weird' );
t( 'D2 an unknown choice is ignored (the stored mode stays)', 'masked' === stored()['traffic_ip_mode'] );
// A site that collected before (and stopped) keeps its own choice on the start screen.
settings( array( 'traffic' => 1, 'traffic_ip_mode' => 'full' ) );
PNCP_Traffic::ingest( array( 'ts' => time() - 60, 'ip' => '198.51.100.40', 'status' => 200, 'path' => '/before/', 'ua' => 'Mozilla/5.0' ), 'wp' );
PNCP_Traffic::flush();
settings( array( 'traffic' => 0 ) );
list( , $body ) = http( tab() );
t( 'D2 off after collecting with Full: the start screen keeps Full chosen', 'full' === ip_choice( $body )[0], ip_choice( $body )[0] );
PNCP_Traffic::purge_all();

/* ---------- D3. Masked: no full address anywhere ---------- */
$full4 = array( '192.0.2.77', '198.51.100.123', '203.0.113.201' );
$full6 = '2001:db8:abcd:12::5';
settings( array( 'traffic' => 0, 'traffic_wp' => 0, 'traffic_ip_mode' => 'full' ) );
start( 'masked' );
settings( array( 'traffic_wp' => 1, 'traffic_log_path' => '' ) ); // The WordPress source, whatever "Start collecting" recommends here.
t( 'D3 collecting with Masked', 1 === (int) stored()['traffic'] && 'masked' === stored()['traffic_ip_mode'] );
// The WordPress source over HTTP (visitors).
foreach ( array( $full4[0], $full6 ) as $ip ) {
	http( '/?pncp_gdpr=' . wp_rand(), null, '', $ip );
	http( '/gdpr-missing-' . wp_rand() . '/', null, '', $ip );
}
// Bunny and the access log, as their imports hand the lines over, and more WordPress lines (the source the alerts
// read here: the one that collects).
$now = time();
for ( $i = 0; $i < 60; $i++ ) {
	PNCP_Traffic::ingest(
		array(
			'ts'      => $now - 1200 + $i,
			'ip'      => $full4[ $i % 3 ],
			'status'  => 0 === $i % 3 ? 404 : ( 1 === $i % 3 ? 500 : 200 ),
			'path'    => '/g-' . ( $i % 4 ) . '/',
			'ua'      => 'GdprBot/1.' . ( $i % 2 ),
			'referer' => 'https://example.org/x',
			'country' => 'DE',
		),
		$i < 30 ? 'bunny' : 'wp'
	);
}
$log = $tmp . '/access.log';
file_put_contents( $log, $full4[1] . ' - - [' . gmdate( 'd/M/Y:H:i:s O' ) . '] "GET /from-log/ HTTP/1.1" 200 512 "-" "Mozilla/5.0 LogAgent"' . "\n" . $full6 . ' - - [' . gmdate( 'd/M/Y:H:i:s O' ) . '] "GET /from-log/ HTTP/1.1" 404 12 "-" "Mozilla/5.0 LogAgent"' . "\n" );
$test = PNCP_Traffic::test_log_path( $log );
foreach ( array( array( $full4[1], 200 ), array( $full6, 404 ) ) as $j => $l ) {
	PNCP_Traffic::ingest(
		array(
			'ts'     => $now - 1500 + $j,
			'ip'     => $l[0],
			'status' => $l[1],
			'path'   => '/from-log/',
			'ua'     => 'Mozilla/5.0 LogAgent',
		),
		'server'
	);
}
PNCP_Traffic::flush();
PNCP_Traffic::rollup();
global $wpdb;
$dump = '';
foreach ( array( 'raw', 'hour', 'day', 'err' ) as $which ) {
	$dump .= wp_json_encode( $wpdb->get_results( 'SELECT * FROM ' . PNCP_Traffic::table( $which ), ARRAY_A ) ); // phpcs:ignore
}
$wp_rows = (int) $wpdb->get_var( "SELECT COUNT(*) FROM " . PNCP_Traffic::table( 'raw' ) . " WHERE src = 'wp'" ); // phpcs:ignore
t( 'D3 the WordPress source recorded the visitors over HTTP', $wp_rows >= 4, (string) $wp_rows );
$ips = $wpdb->get_col( 'SELECT DISTINCT ip FROM ' . PNCP_Traffic::table( 'raw' ) . ' ORDER BY ip' ); // phpcs:ignore
t( 'D3 the raw rows hold only masked addresses (IPv4 /24, IPv6 /48)', array( '192.0.2.0', '198.51.100.0', '2001:db8:abcd::', '203.0.113.0' ) === $ips, wp_json_encode( $ips ) );
$leaks = static function ( $text ) use ( $full4, $full6 ) {
	$found = array();
	foreach ( array_merge( $full4, array( $full6, '2001:db8:abcd:12:' ) ) as $ip ) {
		if ( false !== stripos( (string) $text, $ip ) ) {
			$found[] = $ip;
		}
	}
	return implode( ',', $found );
};
t( 'D3 the four Traffic tables (raw, hourly, daily with the per-IP figures, errors): no full address', '' === $leaks( $dump ), $leaks( $dump ) );
$opts = wp_json_encode( array( get_option( PNCP_Traffic::STATE ), get_option( PNCP_Traffic_Alerts::OPTION ), get_option( PNCP_Traffic::GEN_OPTION ) ) );
t( 'D3 the Traffic options (state, alerts): no full address', '' === $leaks( $opts ), $leaks( $opts ) );
t( 'D3 "Test this path" shows the sample masked', 'ok' === $test['code'] && in_array( $test['sample']['ip'], array( '198.51.100.0', '2001:db8:abcd::' ), true ), wp_json_encode( $test['sample'] ) );
$shown = '';
foreach ( array( 'bunny', 'wp', 'server' ) as $src ) {
	$f      = array( 'src' => $src );
	$shown .= wp_json_encode( array( PNCP_Traffic::raw( $f, 200 ), PNCP_Traffic::top( 'ip', $f, 50 ), PNCP_Traffic::detail( 'ua', 'GdprBot/1.0', $f ), PNCP_Traffic::problems( '404', $f ), PNCP_Traffic::problems( '5xx', $f ) ) );
	$csv    = fopen( 'php://memory', 'w+' );
	PNCP_Traffic::export_csv( $f, $csv );
	rewind( $csv );
	$shown .= stream_get_contents( $csv );
	fclose( $csv );
}
t( 'D3 raw(), top(ip), detail(), problems() and the CSV: no full address, the masked ones are there', '' === $leaks( $shown ) && false !== strpos( $shown, '203.0.113.0' ) && false !== strpos( $shown, '2001:db8:abcd::' ), $leaks( $shown ) );
// The alert emails (thresholds low enough for this hour), the weekly report and the dashboard widget.
add_filter(
	'pncp_traffic_alert_thresholds',
	static function ( $t ) {
		return array_merge( $t, array( 'min_5xx' => 3, 'min_404' => 3, 'ua_hits' => 3, 'ua_min' => 3, 'ua_share' => 0.01, 'history_hours' => 0 ) );
	}
);
$alerts = PNCP_Traffic_Alerts::evaluate( time() );
$mails  = '';
foreach ( $alerts as $type => $alert ) {
	$mail   = PNCP_Traffic_Alerts::email( $type, $alert );
	$mails .= $mail['subject'] . "\n" . $mail['body'] . "\n";
}
ob_start();
$widget = PNCP_Traffic_Alerts::widget_line();
$mails .= implode( "\n", (array) PNCP_Traffic_Alerts::report_lines( 7 ) ) . "\n" . ob_get_clean() . wp_json_encode( $widget );
t( 'D3 alert emails fired for this hour (' . implode( ', ', array_keys( $alerts ) ) . ')', count( $alerts ) >= 2, wp_json_encode( array_keys( $alerts ) ) );
t( 'D3 the alert emails, the weekly report lines and the dashboard line: no full address', '' === $leaks( $mails ), $leaks( $mails ) );
// The Traffic tab's views as the administrator.
$views = '';
foreach ( array( '', '&tr_view=log', '&tr_view=visitors', '&tr_view=agents', '&tr_view=problems' ) as $v ) {
	list( , $body ) = http( tab() . $v );
	$views         .= $body;
}
t( 'D3 the Traffic tab (overview, requests, visitors, User-Agents, problems): no full address', '' === $leaks( $views ), $leaks( $views ) );
if ( '' !== $wp_cli ) {
	$cli = '';
	foreach ( array( 'raw --limit=200 --format=json', 'top ip --from=24h --format=json', 'problems 404 --from=24h --format=json', 'export ' . escapeshellarg( $tmp . '/out.csv' ) . ' --from=24h' ) as $args ) {
		$cli .= (string) shell_exec( $wp_cli . ' scrapelock traffic ' . $args . ' 2>&1' );
	}
	$cli .= (string) @file_get_contents( $tmp . '/out.csv' );
	t( 'D3 wp scrapelock traffic raw / top ip / problems / export: no full address', '' === $leaks( $cli ) && false !== strpos( $cli, '203.0.113.0' ), $leaks( $cli ) . ' ' . substr( $cli, 0, 200 ) );
} else {
	echo "SKIP D3 wp scrapelock traffic: WP_CLI not given\n";
}

/* ---------- D4. The suggested privacy policy text ---------- */
$policy = PNCP_Traffic::privacy_text();
t( 'D4 the privacy text names Traffic, what a request holds and the retention of this site', false !== strpos( $policy, 'Traffic' ) && false !== strpos( $policy, 'IP address' ) && false !== strpos( $policy, 'after 3 days' ) && false !== strpos( $policy, 'after 90 days' ), $policy );
t( 'D4 with Masked: it says the addresses are stored masked (IPv4 /24, IPv6 /48)', false !== strpos( $policy, 'stored masked' ) && false !== strpos( $policy, 'IPv4 /24, IPv6 /48' ), $policy );
settings( array( 'traffic_ip_mode' => 'full' ) );
t( 'D4 with Full: it says they are stored in full', false !== strpos( PNCP_Traffic::privacy_text(), 'stored in full' ) );
require_once ABSPATH . 'wp-admin/includes/misc.php';
require_once ABSPATH . 'wp-admin/includes/class-wp-privacy-policy-content.php';
set_current_screen( 'options-privacy' );
$GLOBALS['wp_actions']['admin_init'] = 1; // wp_add_privacy_policy_content() wants admin_init to have run.
PNCP_Log::privacy_policy();
$suggested = wp_json_encode( WP_Privacy_Policy_Content::get_suggested_policy_text() );
t( 'D4 the ScrapeLock part of the suggested privacy policy includes the Traffic paragraph', false !== strpos( $suggested, 'If traffic statistics (Traffic) are turned on' ), substr( $suggested, 0, 200 ) );

echo $fails ? "\n$fails FAILED\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
