<?php
/**
 * ScrapeLock 3.12.8 — the follow-ups of the release: how the parts of 3.12.8 work together.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3128_release.php
 *
 * S. PNCP_Edge::own_url() (wp scrapelock cache purge / cdn purge <path>): with WordPress in a folder of the
 *    host (home https://host/blog) a path is one of the home address ("/about/" → https://host/blog/about/;
 *    3.12.7 dropped the folder); a path that already starts with the folder, the verification files and
 *    /.well-known/ stay at the root; a site at the root of its host is unchanged.
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

/** Stores settings as they are. */
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	wp_cache_delete( 'alloptions', 'options' );
}

/** Stealth's Nginx rules applied to a path as Nginx applies them at server level (PCRE, in order, "last" stops). */
function nginx_apply( $rules, $path ) {
	foreach ( explode( "\n", $rules ) as $line ) {
		if ( ! preg_match( '/^rewrite "(.+)" (\S+?)( last)?;$/', trim( $line ), $m ) ) {
			continue;
		}
		$regex = $m[1];
		$flags = '';
		if ( 0 === strpos( $regex, '(?i)' ) ) {
			$regex = substr( $regex, 4 );
			$flags = 'i';
		}
		if ( preg_match( '#' . str_replace( '#', '\\#', $regex ) . '#' . $flags, $path, $g ) ) {
			$path = preg_replace_callback(
				'/\$(\d)/',
				static function ( $x ) use ( $g ) {
					return isset( $g[ (int) $x[1] ] ) ? $g[ (int) $x[1] ] : '';
				},
				$m[2]
			);
			if ( ! empty( $m[3] ) ) {
				return $path;
			}
		}
	}
	return $path;
}

/** The same for the Apache rules (RewriteBase /, paths without the leading slash). */
function apache_apply( $rules, $path ) {
	$rel = ltrim( $path, '/' );
	foreach ( explode( "\n", $rules ) as $line ) {
		if ( ! preg_match( '/^RewriteRule (\S+) (\S+) \[([A-Z,=0-9]+)\]$/', trim( $line ), $m ) || '-' === $m[2] ) {
			continue;
		}
		$flags = explode( ',', $m[3] );
		if ( preg_match( '#' . str_replace( '#', '\\#', $m[1] ) . '#' . ( in_array( 'NC', $flags, true ) ? 'i' : '' ), $rel, $g ) ) {
			$rel = preg_replace_callback(
				'/\$(\d)/',
				static function ( $x ) use ( $g ) {
					return isset( $g[ (int) $x[1] ] ) ? $g[ (int) $x[1] ] : '';
				},
				$m[2]
			);
			if ( in_array( 'L', $flags, true ) ) {
				return '/' . ltrim( $rel, '/' );
			}
		}
	}
	return '/' . ltrim( $rel, '/' );
}

/** Removes a folder and what is in it. */
function rmtree( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return;
	}
	$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
	foreach ( $it as $f ) {
		$f->isDir() ? rmdir( $f->getPathname() ) : unlink( $f->getPathname() );
	}
	rmdir( $dir );
}

$saved = array();
foreach ( array( PNCP_OPTION, PNCP_Stealth::OPTION, PNCP_Stealth_Status::SEEN, PNCP_Verify_Files::INDEX, PNCP_Verify_Files::DATA, 'active_plugins', 'cron' ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}
$demo      = WP_PLUGIN_DIR . '/pncpdemo';
$copy_dir  = WP_CONTENT_DIR . '/cache/min/1/wp-content/plugins/pncpdemo';
$cache_new = ! is_dir( WP_CONTENT_DIR . '/cache' );
$htaccess  = trailingslashit( ABSPATH ) . '.htaccess';
$ht_before = is_file( $htaccess ) ? (string) file_get_contents( $htaccess ) : null;
register_shutdown_function(
	static function () use ( $saved, $demo, $copy_dir, $cache_new, $htaccess, $ht_before ) {
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, PNCP_Stealth::OPTION === $name || PNCP_OPTION === $name || 'active_plugins' === $name );
			}
		}
		delete_transient( PNCP_Stealth_Status::STATUS );
		rmtree( $demo );
		rmtree( $cache_new ? WP_CONTENT_DIR . '/cache' : $copy_dir );
		if ( null === $ht_before ) {
			if ( is_file( $htaccess ) ) {
				unlink( $htaccess );
			}
		} else {
			file_put_contents( $htaccess, $ht_before );
		}
	}
);

/* ---------- S. own_url() with WordPress in a folder ---------- */

$home_root = home_url( '/' );
$scheme    = (string) wp_parse_url( $home_root, PHP_URL_SCHEME );
$authority = (string) wp_parse_url( $home_root, PHP_URL_HOST ) . ( wp_parse_url( $home_root, PHP_URL_PORT ) ? ':' . wp_parse_url( $home_root, PHP_URL_PORT ) : '' );
$origin    = $scheme . '://' . $authority;
t( 'S a site at the root: "/about/" and "/builtwith.txt" on the home address, as before', $origin . '/about/' === PNCP_Edge::own_url( '/about/' ) && $origin . '/builtwith.txt' === PNCP_Edge::own_url( '/builtwith.txt' ) );
$in_folder = static function () use ( $origin ) {
	return $origin . '/blog';
};
add_filter( 'pre_option_home', $in_folder );
update_option( PNCP_Verify_Files::INDEX, array( '/builtwith.txt' => array( 'until' => time() + HOUR_IN_SECONDS, 'disk' => 0 ) ) );
update_option( PNCP_Verify_Files::DATA, array( '/builtwith.txt' => array( 'content' => 'x', 'created' => time(), 'sha1' => '' ) ), false );
t( 'S WordPress in /blog: "/about/" is the page of the home address (/blog/about/)', $origin . '/blog/about/' === PNCP_Edge::own_url( '/about/' ), PNCP_Edge::own_url( '/about/' ) );
t( 'S ... "/" is the home page, "/x?y=1" keeps its query', $origin . '/blog/' === PNCP_Edge::own_url( '/' ) && $origin . '/blog/x?y=1' === PNCP_Edge::own_url( '/x?y=1' ) );
t( 'S ... a path that already starts with the folder is taken as it is (/blog/about/, /blog)', $origin . '/blog/about/' === PNCP_Edge::own_url( '/blog/about/' ) && $origin . '/blog' === PNCP_Edge::own_url( '/blog' ) );
t( 'S ... "/blogger/" is not the folder /blog: /blog/blogger/', $origin . '/blog/blogger/' === PNCP_Edge::own_url( '/blogger/' ) );
t( 'S ... a verification file stays at the root of the host (/builtwith.txt)', $origin . '/builtwith.txt' === PNCP_Edge::own_url( '/builtwith.txt' ) && PNCP_Verify_Files::url_of( '/builtwith.txt' ) === PNCP_Edge::own_url( '/builtwith.txt' ) );
t( 'S ... /.well-known/ stays at the root', $origin . '/.well-known/security.txt' === PNCP_Edge::own_url( '/.well-known/security.txt' ) );
t( 'S ... a full address is taken as it is; other hosts still refused', $origin . '/x/' === PNCP_Edge::own_url( $origin . '/x/' ) && '' === PNCP_Edge::own_url( 'https://other.example/x' ) && '' === PNCP_Edge::own_url( '//other.example/x' ) );
remove_filter( 'pre_option_home', $in_folder );
update_option( PNCP_Verify_Files::INDEX, null === $saved[ PNCP_Verify_Files::INDEX ] ? array() : $saved[ PNCP_Verify_Files::INDEX ] );

exit( $fails ? 1 : 0 );
