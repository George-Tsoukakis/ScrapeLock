<?php
/**
 * ScrapeLock 3.12 — Traffic: the security review (PNCP_Traffic, PNCP_Traffic_Actions, PNCP_Traffic_Query) on a
 * real WordPress, through HTTP with an administrator's cookie.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_traffic_sec.php
 *
 * 1. While the site is locked (Lockdown) the Traffic actions that only read are refused too (Lockdown takes
 *    manage_options away): the CSV export of the visitors and "Test this path".
 * 2. The WordPress source does not record the pages a signed-in administrator opens on the site (only visitors).
 * 3. "Masked" IPs turned on with full addresses already stored: the raw rows and the per-IP daily figures are
 *    masked (merged by masked address, the totals unchanged), also when it takes more than one run, and the
 *    queries, the CSV and the visitors view never show a full address meanwhile.
 * 4. "Test this path" with masked IPs shows the sample request's address masked (tab and WP-CLI).
 *
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

function cookies_for( $user_id ) {
	$expire = time() + DAY_IN_SECONDS;
	$token  = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	return array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
}

/** A request: [code, body, location, headers]. $who: admin | '' (a visitor). */
function http( $path, $post = null, $who = 'admin', $ip = '192.0.2.231' ) {
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
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: ' . $ip, 'X-Forwarded-For: ' . $ip, 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 TrafficSec', 'Accept: text/html', 'Accept-Language: en' ),
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

function query_arg( $url, $name ) {
	$q = array();
	wp_parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $q );
	return isset( $q[ $name ] ) ? (string) $q[ $name ] : '';
}

function raw_count( $where = '1 = 1' ) {
	global $wpdb;
	return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . PNCP_Traffic::table( 'raw' ) . ' WHERE ' . $where ); // phpcs:ignore
}

/* ---------- Users and state ---------- */
$admin                       = get_user_by( 'id', 1 );
$jars                        = array( 'admin' => cookies_for( $admin->ID ) );
$_COOKIE[ LOGGED_IN_COOKIE ] = $jars['admin'][ LOGGED_IN_COOKIE ];
wp_set_current_user( $admin->ID );

$saved      = get_option( PNCP_OPTION );
$saved_lock = get_site_option( PNCP_Lockdown::OPTION, null );
$saved_bak  = get_option( 'pncp_settings_backups', false );
$tmp        = rtrim( sys_get_temp_dir(), '/' ) . '/pncp-trsec-' . getmypid();
@mkdir( $tmp, 0700, true );
register_shutdown_function(
	static function () use ( $saved, $saved_lock, $saved_bak, $tmp ) {
		if ( null === $saved_lock ) {
			delete_site_option( PNCP_Lockdown::OPTION );
		} else {
			update_site_option( PNCP_Lockdown::OPTION, $saved_lock );
		}
		PNCP_Traffic::purge_all();
		update_option( PNCP_OPTION, $saved );
		if ( false === $saved_bak ) {
			delete_option( 'pncp_settings_backups' );
		} else {
			update_option( 'pncp_settings_backups', $saved_bak, false );
		}
		delete_transient( PNCP_Traffic_Actions::TEST . 1 );
		foreach ( (array) glob( $tmp . '/*' ) as $file ) {
			@unlink( $file );
		}
		@rmdir( $tmp );
	}
);

settings(
	array(
		'enabled'          => 1,
		'monitor_mode'     => 0,
		'monitor_until'    => 0,
		'traffic'          => 1,
		'traffic_wp'       => 0,
		'traffic_log_path' => '',
		'traffic_raw_days' => 3,
		'traffic_days'     => 90,
		'traffic_ip_mode'  => 'full',
	)
);
PNCP_Traffic::maybe_schedule();
PNCP_Traffic::purge_all();
$t0 = time() - 600;
foreach ( array( '203.0.113.7', '203.0.113.8', '2001:db8:1234:5678::9' ) as $i => $ip ) {
	PNCP_Traffic::ingest(
		array(
			'ts'      => $t0 + $i,
			'ip'      => $ip,
			'status'  => 404,
			'path'    => '/sec-' . $i . '/',
			'ua'      => 'SecBot/1.' . $i,
			'country' => 'GR',
		),
		'wp'
	);
}
PNCP_Traffic::flush();
PNCP_Traffic::rollup();

/* ---------- 1. Lockdown ---------- */
$log = $tmp . '/access.log';
file_put_contents( $log, '203.0.113.9 - - [' . gmdate( 'd/M/Y:H:i:s O' ) . '] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"' . "\n" );
update_site_option( PNCP_Lockdown::OPTION, array( 'locked' => 1, 'until' => 0 ) );
list( $code, $body, , $head ) = http(
	'/wp-admin/admin-post.php',
	array(
		'action'   => PNCP_Traffic_Actions::CSV,
		'_wpnonce' => wp_create_nonce( PNCP_Traffic_Actions::CSV ),
	)
);
t( 'locked: the CSV export is refused (no visitor data)', ! preg_match( '#^content-type:\s*text/csv#mi', $head ) && false === strpos( $body, '203.0.113.7' ), $code . ' ' . substr( $body, 0, 200 ) );
delete_transient( PNCP_Traffic_Actions::TEST . $admin->ID );
list( $code, , $loc ) = http(
	'/wp-admin/admin-post.php',
	array(
		'action'   => PNCP_Traffic_Actions::ACTION,
		'_wpnonce' => wp_create_nonce( PNCP_Traffic_Actions::ACTION ),
		'op'       => 'test_path',
		'path'     => $log,
	)
);
t( 'locked: "Test this path" is refused (no lines of the log read)', ( 403 === $code || 'locked' === query_arg( $loc, 'tr_msg' ) ) && false === get_transient( PNCP_Traffic_Actions::TEST . $admin->ID ), $code . ' ' . $loc );
if ( null === $saved_lock ) {
	delete_site_option( PNCP_Lockdown::OPTION );
} else {
	update_site_option( PNCP_Lockdown::OPTION, $saved_lock );
}
list( $code, $body, , $head ) = http(
	'/wp-admin/admin-post.php',
	array(
		'action'   => PNCP_Traffic_Actions::CSV,
		'_wpnonce' => wp_create_nonce( PNCP_Traffic_Actions::CSV ),
	)
);
t( 'unlocked: the CSV export works', preg_match( '#^content-type:\s*text/csv#mi', $head ) && false !== strpos( $body, '203.0.113.7' ), $code . ' ' . $head );

/* ---------- 2. The WordPress source and signed-in administrators ---------- */
settings( array( 'traffic_wp' => 1 ) );
PNCP_Traffic::purge_all();
list( $code ) = http( '/?pncp_sec=admin', null, 'admin', '192.0.2.232' );
t( 'wp source: a signed-in administrator\'s front page is not recorded', 200 === $code && 0 === raw_count( "src = 'wp' AND ip = '192.0.2.232'" ), $code . ' ' . raw_count() );
list( $code ) = http( '/?pncp_sec=visitor', null, '', '192.0.2.233' );
t( 'wp source: a visitor\'s front page is recorded', 200 === $code && 1 === raw_count( "src = 'wp' AND ip = '192.0.2.233'" ), $code . ' ' . raw_count() );
settings( array( 'traffic_wp' => 0 ) );

/* ---------- 3. Masked IPs with full addresses stored ---------- */
global $wpdb;
PNCP_Traffic::purge_all();
settings( array( 'traffic_ip_mode' => 'full' ) );
$full = array( '203.0.113.7', '203.0.113.8', '203.0.113.9', '2001:db8:1234:5678::9' );
for ( $i = 0; $i < 40; $i++ ) {
	PNCP_Traffic::ingest(
		array(
			'ts'     => time() - 900 + $i,
			'ip'     => $full[ $i % 4 ],
			'status' => $i % 5 ? 200 : 404,
			'path'   => '/m-' . ( $i % 3 ) . '/',
			'ua'     => 'MaskBot/1.' . ( $i % 2 ),
		),
		'bunny'
	);
}
PNCP_Traffic::flush();
PNCP_Traffic::rollup();
$f       = array( 'src' => 'bunny' );
$before  = PNCP_Traffic::overview( $f );
$ip_rows = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT SUM(hits) FROM %i WHERE dim = %s', PNCP_Traffic::table( 'day' ), 'ip' ) );
t( 'masked: seeded with 4 full addresses', 4 === (int) $wpdb->get_var( 'SELECT COUNT(DISTINCT ip) FROM ' . PNCP_Traffic::table( 'raw' ) ) && 40 === $ip_rows ); // phpcs:ignore
// Unmasked rows meanwhile: what every output shows.
$s                    = PNCP_Options::stored();
$s['traffic_ip_mode'] = 'masked';
remove_all_actions( 'update_option_' . PNCP_OPTION );
update_option( PNCP_OPTION, $s ); // Without the hook: the stored addresses are still full.
wp_cache_delete( 'alloptions', 'options' );
PNCP_Options::flush();
PNCP_Traffic::reset();
$shown = wp_json_encode( array( PNCP_Traffic::raw( $f, 100 ), PNCP_Traffic::top( 'ip', $f, 50 ), PNCP_Traffic::detail( 'ua', 'MaskBot/1.0', $f ) ) );
$csv   = fopen( 'php://memory', 'w+' );
PNCP_Traffic::export_csv( $f, $csv );
rewind( $csv );
$shown .= stream_get_contents( $csv );
fclose( $csv );
t( 'masked, not yet masked in the database: raw(), top(ip), detail() and the CSV show no full address', false === strpos( $shown, '203.0.113.7' ) && false === strpos( $shown, '203.0.113.8' ) && false === strpos( $shown, '2001:db8:1234:5678::9' ) && false !== strpos( $shown, '203.0.113.0' ) && false !== strpos( $shown, '2001:db8:1234::' ), substr( $shown, 0, 300 ) );
// Now through the settings, as a save does: full -> masked.
$s['traffic_ip_mode'] = 'full';
update_option( PNCP_OPTION, $s );
PNCP_Traffic::init();
settings( array( 'traffic_ip_mode' => 'masked' ) );
$left = PNCP_Traffic::state()['mask'];
$ips  = $wpdb->get_col( 'SELECT DISTINCT ip FROM ' . PNCP_Traffic::table( 'raw' ) . ' ORDER BY ip' ); // phpcs:ignore
t( 'masked on save: the raw rows hold only masked addresses', array( '2001:db8:1234::', '203.0.113.0' ) === $ips && array() === $left, wp_json_encode( array( $ips, $left ) ) );
$labels = $wpdb->get_col( $wpdb->prepare( 'SELECT label FROM %i WHERE dim = %s AND k <> %s ORDER BY label', PNCP_Traffic::table( 'day' ), 'ip', PNCP_Traffic::OTHER ) );
$sum    = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT SUM(hits) FROM %i WHERE dim = %s', PNCP_Traffic::table( 'day' ), 'ip' ) );
t( 'masked on save: the per-IP daily figures are merged by masked address, the requests unchanged', array( '2001:db8:1234::', '203.0.113.0' ) === $labels && 40 === $sum, wp_json_encode( array( $labels, $sum ) ) );
$after = PNCP_Traffic::overview( $f );
t( 'masked on save: the totals are the same', $before['total'] === $after['total'] && $before['s4xx'] === $after['s4xx'] );
t( 'masked on save: top(ip) has the two masked addresses', array( '203.0.113.0', '2001:db8:1234::' ) === array_column( PNCP_Traffic::top( 'ip', $f, 10 )['rows'], 'key' ) || array( '2001:db8:1234::', '203.0.113.0' ) === array_column( PNCP_Traffic::top( 'ip', $f, 10 )['rows'], 'key' ) );
// More than one run: a deadline in the past does nothing, the scheduled run finishes it.
settings( array( 'traffic_ip_mode' => 'full' ) );
for ( $i = 0; $i < 10; $i++ ) {
	PNCP_Traffic::ingest( array( 'ts' => time() - 100 + $i, 'ip' => '198.51.100.' . ( $i + 1 ), 'status' => 200, 'path' => '/n/', 'ua' => 'MaskBot/2' ), 'bunny' );
}
PNCP_Traffic::flush();
$state         = PNCP_Traffic::state();
$state['mask'] = array( 'id' => 0, 'days' => 0 );
PNCP_Traffic::save_state( $state );
settings( array( 'traffic_ip_mode' => 'masked' ) );
$state         = PNCP_Traffic::state();
$state['mask'] = array( 'id' => 0, 'days' => 0 );
PNCP_Traffic::save_state( $state );
$done = PNCP_Traffic::mask_stored( microtime( true ) - 1 );
t( 'masked: a run out of time leaves the rest for the next one', ! $done && array() !== PNCP_Traffic::state()['mask'] );
PNCP_Log::cache_delete( 'pncp_traffic_lock' );
PNCP_Traffic::run();
t( 'masked: the scheduled run finishes it', array() === PNCP_Traffic::state()['mask'] && 0 === (int) $wpdb->get_var( "SELECT COUNT(*) FROM " . PNCP_Traffic::table( 'raw' ) . " WHERE ip LIKE '198.51.100.%' AND ip <> '198.51.100.0'" ) ); // phpcs:ignore
settings( array( 'traffic_ip_mode' => 'full' ) );

/* ---------- 4. "Test this path" with masked IPs ---------- */
file_put_contents( $log, '198.51.100.77 - - [' . gmdate( 'd/M/Y:H:i:s O' ) . '] "GET /sample/ HTTP/1.1" 200 512 "-" "Mozilla/5.0"' . "\n" );
$full_test = PNCP_Traffic::test_log_path( $log );
settings( array( 'traffic_ip_mode' => 'masked' ) );
$masked_test = PNCP_Traffic::test_log_path( $log );
t( 'Test this path: the sample address as the record holds it (full, or masked)', 'ok' === $masked_test['code'] && '198.51.100.77' === $full_test['sample']['ip'] && '198.51.100.0' === $masked_test['sample']['ip'], wp_json_encode( array( $full_test['sample'], $masked_test['sample'] ) ) );
settings( array( 'traffic_ip_mode' => 'full' ) );

exit( $fails ? 1 : 0 );
