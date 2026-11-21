<?php
/**
 * ScrapeLock 3.12.8 — fixes of the code of 3.12.0 to 3.12.7 (bug hunt D), each with its regression test.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3128_bugs_d.php
 *
 * U. uninstall.php deletes every option the plugin writes with update_option() / add_option() (a name or a
 *    class constant), unless a class's own uninstall() deletes it; only the clean images' index is kept on purpose.
 *    3.12.7 left pncp_fastcgi_last (the counts of the last fastcgi cache purge) behind.
 * I. rules install: the commands of a server whose configuration is read only at a reload (Nginx, an Apache
 *    .conf). 3.12.6 reported "installed" without any reload when the server's program was not found and only
 *    --test-cmd was given (the reload was skipped as for a .htaccess), and an Apache .conf without apachectl was
 *    only "tested" by asking the home page and never reloaded. Now: the reload falls back to systemctl, and with
 *    neither the command stops (every file put back) and asks for --test-cmd / --reload-cmd. A .htaccess alone
 *    still needs neither.
 * O. rules install as root (WP-CLI run with --allow-root, as on most servers; SKIP otherwise, or without WP_CLI):
 *    the new file keeps the owner and group of the file it replaces. 3.12.6 left a root-owned .htaccess that
 *    WordPress (the web server's user) could no longer write: permalinks, ScrapeLock's own .htaccess blocks.
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

/* ---------- I. rules install: test and reload commands ---------- */

$plan = static function ( $server, $htaccess, $assoc, $cmds ) {
	return method_exists( 'PNCP_Cli_Server', 'install_commands' ) ? PNCP_Cli_Server::install_commands( $server, $htaccess, $assoc, $cmds ) : null;
};
$none = array(
	'test'   => '',
	'reload' => '',
	'alt'    => '',
);
$sys  = array(
	'test'   => '',
	'reload' => '',
	'alt'    => "'/usr/bin/systemctl' reload nginx",
);
$all  = array(
	'test'   => "'/usr/sbin/nginx' -t",
	'reload' => "'/usr/sbin/nginx' -s reload",
	'alt'    => "'/usr/bin/systemctl' reload nginx",
);
$p = $plan( 'nginx', false, array(), $all );
t( 'I nginx found: nginx -t, nginx -s reload, systemctl as the fallback', is_array( $p ) && $all['test'] === $p['test'] && $all['reload'] === $p['reload'] && $all['alt'] === $p['alt'] && '' === $p['missing'], wp_json_encode( $p ) );
$p = $plan( 'nginx', false, array( 'test-cmd' => '/opt/nginx/sbin/nginx -t' ), $sys );
t( 'I nginx not found, only --test-cmd: the reload is systemctl reload nginx (3.12.6 skipped it)', is_array( $p ) && '/opt/nginx/sbin/nginx -t' === $p['test'] && $sys['alt'] === $p['reload'] && '' === $p['missing'], wp_json_encode( $p ) );
$p = $plan( 'nginx', false, array( 'test-cmd' => '/opt/nginx/sbin/nginx -t' ), $none );
t( 'I nginx not found, only --test-cmd, no systemctl: the reload is missing (the command stops)', is_array( $p ) && 'reload' === $p['missing'] && '' !== $p['message'], wp_json_encode( $p ) );
$p = $plan( 'nginx', false, array(), $none );
t( 'I nginx not found at all: the test is missing', is_array( $p ) && 'test' === $p['missing'] && false !== strpos( $p['message'], '--test-cmd' ), wp_json_encode( $p ) );
$p = $plan( 'apache', false, array(), $none );
t( 'I an Apache .conf without apachectl: the test is missing (3.12.6 asked the home page and never reloaded)', is_array( $p ) && 'test' === $p['missing'] && false !== strpos( $p['message'], '--reload-cmd' ), wp_json_encode( $p ) );
$p = $plan( 'apache', false, array( 'test-cmd' => 'true' ), $none );
t( 'I an Apache .conf with --test-cmd only: the reload is missing', is_array( $p ) && 'reload' === $p['missing'], wp_json_encode( $p ) );
$p = $plan( 'apache', true, array(), $none );
t( 'I a .htaccess alone: no command needed (the home page is asked; Apache reads it on every request)', is_array( $p ) && '' === $p['missing'] && '' === $p['test'] && '' === $p['reload'], wp_json_encode( $p ) );
$p = $plan( 'nginx', false, array( 'test-cmd' => 'a', 'reload-cmd' => 'b' ), $all );
t( 'I --test-cmd and --reload-cmd as given, no fallback', is_array( $p ) && 'a' === $p['test'] && 'b' === $p['reload'] && '' === $p['alt'] && '' === $p['missing'], wp_json_encode( $p ) );
$src = (string) file_get_contents( PNCP_DIR . 'includes/class-pncp-cli-server.php' );
t( 'I install() takes its commands from install_commands() and stops on a missing one', false !== strpos( $src, 'self::install_commands( $server, $htaccess, $assoc_args, self::commands( $server, $htaccess ) )' ) && false !== strpos( $src, "'' !== \$plan['missing']" ) );

/* ---------- O. rules install keeps the owner of the file it replaces ---------- */

if ( '' === $wp_cli || ! function_exists( 'posix_geteuid' ) || 0 !== posix_geteuid() ) {
	echo "SKIP O (needs WP_CLI and root)\n";
} else {
	$saved_paths = PNCP_Options::stored()['private_paths'];
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'private_paths' => '' ) ) ); // No token needed.
	PNCP_Options::flush();
	$ht = $tmp . '/site/.htaccess';
	wp_mkdir_p( dirname( $ht ) );
	file_put_contents( $ht, "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n" );
	chmod( $ht, 0664 );
	chown( $ht, 65534 );
	chgrp( $ht, 65534 );
	clearstatcache();
	exec( $wp_cli . ' scrapelock rules install --apache=' . escapeshellarg( $ht ) . ' --yes < /dev/null 2>&1', $out, $rc );
	clearstatcache();
	$text = (string) file_get_contents( $ht );
	t( 'O installed into the .htaccess (above # BEGIN WordPress)', 0 === $rc && false !== strpos( $text, '# BEGIN ScrapeLock' ) && strpos( $text, '# BEGIN ScrapeLock' ) < strpos( $text, '# BEGIN WordPress' ), implode( "\n", $out ) );
	t( 'O ...owned by the user and group of the file it replaced, not by root', 65534 === fileowner( $ht ) && 65534 === filegroup( $ht ), fileowner( $ht ) . ':' . filegroup( $ht ) );
	t( 'O ...with its permissions', 0664 === ( fileperms( $ht ) & 0777 ), decoct( fileperms( $ht ) & 0777 ) );
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'private_paths' => $saved_paths ) ) );
	PNCP_Options::flush();
}

exit( $fails ? 1 : 0 );
