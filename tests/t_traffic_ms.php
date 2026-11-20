<?php
/**
 * ScrapeLock 3.12 — Traffic on a multisite network: the access log is the whole server's (the visitors of every
 * site), so only a network administrator may set it, test it ("Test this path") or have "Start collecting" pick
 * it. In-process, as the administrator of a sub-site and as the network administrator.
 *
 *   WP_DIR=/path/to/multisite BASE=http://127.0.0.1:8099 SITE=/two/ php t_traffic_ms.php
 *
 * SKIP on a single site. Needs a sub-site (SITE, default /two/) with an administrator who is not a network
 * administrator ("subadmin"): wp core multisite-convert; wp site create --slug=two;
 * wp user create subadmin sub@example.com --role=administrator --url=<home>/two/.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
$site                   = getenv( 'SITE' ) ? (string) getenv( 'SITE' ) : '/two/';
$_SERVER['HTTP_HOST']   = (string) wp_parse_url_host( $base );
$_SERVER['REQUEST_URI'] = $site . 'wp-admin/';
$_SERVER['SERVER_NAME'] = $_SERVER['HTTP_HOST'];
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

/** The host[:port] of a URL (before WordPress is loaded). */
function wp_parse_url_host( $url ) {
	$host = (string) parse_url( $url, PHP_URL_HOST ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Before WordPress.
	$port = parse_url( $url, PHP_URL_PORT ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Before WordPress.
	return $host . ( $port ? ':' . $port : '' );
}

if ( ! is_multisite() ) {
	echo "SKIP not a multisite network\n";
	exit( 0 );
}
$sub = get_user_by( 'login', 'subadmin' );
if ( ! $sub || 1 === (int) get_current_blog_id() || is_super_admin( $sub->ID ) ) {
	echo "SKIP no sub-site " . $site . " with a sub-site administrator \"subadmin\"\n";
	exit( 0 );
}

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? '  [' . substr( (string) $extra, 0, 400 ) . ']' : '' ) . "\n";
}

/** Runs the Traffic action handler with these fields; returns the address it redirects to. */
function action( $fields ) {
	$_POST    = array_merge(
		array(
			'action'   => PNCP_Traffic_Actions::ACTION,
			'_wpnonce' => wp_create_nonce( PNCP_Traffic_Actions::ACTION ),
		),
		$fields
	);
	$_REQUEST = $_POST;
	$catch    = static function ( $location ) {
		throw new RuntimeException( (string) $location );
	};
	add_filter( 'wp_redirect', $catch, PHP_INT_MAX );
	$loc = '';
	try {
		PNCP_Traffic_Actions::handle();
	} catch ( RuntimeException $e ) {
		$loc = $e->getMessage();
	}
	remove_filter( 'wp_redirect', $catch, PHP_INT_MAX );
	$_POST    = array();
	$_REQUEST = array();
	return $loc;
}

function query_arg( $url, $name ) {
	$q = array();
	wp_parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $q );
	return isset( $q[ $name ] ) ? (string) $q[ $name ] : '';
}

$saved = get_option( PNCP_OPTION );
$tmp   = rtrim( sys_get_temp_dir(), '/' ) . '/pncp-trms-' . getmypid();
@mkdir( $tmp, 0700, true );
$log = $tmp . '/access.log';
file_put_contents( $log, '203.0.113.9 - - [' . gmdate( 'd/M/Y:H:i:s O' ) . '] "GET /other-site/ HTTP/1.1" 200 512 "-" "Mozilla/5.0"' . "\n" );
register_shutdown_function(
	static function () use ( $saved, $tmp, $log, $sub ) {
		update_option( PNCP_OPTION, $saved );
		delete_transient( PNCP_Traffic_Actions::TEST . $sub->ID );
		delete_transient( PNCP_Traffic_Actions::TEST . 1 );
		@unlink( $log );
		@rmdir( $tmp );
	}
);
add_filter(
	'pncp_traffic_log_candidates',
	static function () use ( $log ) {
		return array( $log );
	}
);
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'traffic' => 0, 'traffic_wp' => 0, 'traffic_log_path' => '' ) ) );
PNCP_Options::flush();

/* ---------- The administrator of a sub-site ---------- */
wp_set_current_user( $sub->ID );
t( 'sub-site administrator: manage_options here, not a network administrator', current_user_can( 'manage_options' ) && ! current_user_can( 'manage_network_options' ) );
delete_transient( PNCP_Traffic_Actions::TEST . $sub->ID );
$loc = action( array( 'op' => 'test_path', 'path' => $log ) );
t( 'sub-site administrator: "Test this path" reads nothing of the server\'s log', 'network_only' === query_arg( $loc, 'tr_msg' ) && false === get_transient( PNCP_Traffic_Actions::TEST . $sub->ID ), $loc . ' ' . wp_json_encode( get_transient( PNCP_Traffic_Actions::TEST . $sub->ID ) ) );
$rec = PNCP_Traffic_Actions::recommended();
t( 'sub-site administrator: "Start collecting" does not pick the server\'s log', 'wp' === $rec['source'] && '' === $rec['path'], wp_json_encode( $rec ) );
$new = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'traffic_log_path' => $log, '_sections' => array( 'traffic' ) ) ) );
t( 'sub-site administrator: the path is not saved', '' === $new['traffic_log_path'] );

/* ---------- The network administrator ---------- */
wp_set_current_user( 1 );
delete_transient( PNCP_Traffic_Actions::TEST . 1 );
$loc  = action( array( 'op' => 'test_path', 'path' => $log ) );
$test = get_transient( PNCP_Traffic_Actions::TEST . 1 );
t( 'network administrator: "Test this path" reads it', 'tested' === query_arg( $loc, 'tr_msg' ) && is_array( $test ) && 'ok' === $test[1]['code'], $loc );
$rec = PNCP_Traffic_Actions::recommended();
t( 'network administrator: "Start collecting" picks it', 'server' === $rec['source'] && $log === $rec['path'], wp_json_encode( $rec ) );

exit( $fails ? 1 : 0 );
