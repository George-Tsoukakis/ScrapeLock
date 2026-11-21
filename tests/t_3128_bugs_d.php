<?php
/**
 * ScrapeLock 3.12.8 — fixes of the code of 3.12.0 to 3.12.7 (bug hunt D), each with its regression test.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3128_bugs_d.php
 *
 * U. uninstall.php deletes every option the plugin writes with update_option() / add_option() (a name or a
 *    class constant), unless a class's own uninstall() deletes it; only the clean images' index is kept on purpose.
 *    3.12.7 left pncp_fastcgi_last (the counts of the last fastcgi cache purge) behind.
 *
 * Only on a test WordPress.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
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

$tmp = sys_get_temp_dir() . '/pncp-t3128d-' . getmypid();
wp_mkdir_p( $tmp );
register_shutdown_function(
	static function () use ( $tmp ) {
		exec( 'rm -rf ' . escapeshellarg( $tmp ) );
	}
);

/* ---------- U. Uninstall ---------- */

$uninstall = (string) file_get_contents( PNCP_DIR . 'uninstall.php' );
$kept      = array( 'pncp_backup_dir' ); // The index of the clean image originals, kept on purpose (uninstall.php).
$left      = array();
foreach ( (array) glob( PNCP_DIR . 'includes/*.php' ) as $file ) {
	$src = (string) file_get_contents( (string) $file );
	preg_match_all( "/const ([A-Z_]+)\s*=\s*'([a-z0-9_]+)'/", $src, $m, PREG_SET_ORDER );
	$consts = array();
	foreach ( $m as $c ) {
		$consts[ $c[1] ] = $c[2];
	}
	$own = preg_match( '/function uninstall\(\)\s*\{(.*?)\n\t\}/s', $src, $u ) ? $u[1] : '';
	preg_match_all( "/(?:update|add)_(?:site_)?option\(\s*(?:self::([A-Z_]+)|'(pncp_[a-z0-9_]+)'\s*,)/", $src, $m, PREG_SET_ORDER );
	foreach ( $m as $w ) {
		$name = ! empty( $w[2] ) ? $w[2] : ( isset( $consts[ $w[1] ] ) ? $consts[ $w[1] ] : '' );
		if ( 0 !== strpos( $name, 'pncp_' ) || in_array( $name, $kept, true ) || false !== strpos( $uninstall, "'$name'" ) || preg_match( '/^pncp_(?:dc_|ip_lists_dc_)/', $name ) ) {
			continue; // Deleted by name, or by the LIKE rows of uninstall.php.
		}
		if ( ( ! empty( $w[1] ) && false !== strpos( $own, 'self::' . $w[1] ) ) || false !== strpos( $own, "'$name'" ) ) {
			continue; // The class's uninstall() (called by uninstall.php) deletes it.
		}
		$left[ $name ] = basename( (string) $file );
	}
}
t( 'U uninstall.php deletes every option the plugin writes (the clean images\' index kept on purpose)', ! $left, wp_json_encode( $left ) );
t( 'U ...among them pncp_fastcgi_last (3.12.7), and the scan sees it', false !== strpos( $uninstall, "delete_option( '" . PNCP_Fastcgi_Cache::LAST . "' )" ) );

exit( $fails ? 1 : 0 );
