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

exit( $fails ? 1 : 0 );
