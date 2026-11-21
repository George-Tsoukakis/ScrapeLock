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
 * R. The Stealth rules write each word's rule twice on purpose (a word can be in an address two times, as in
 *    WP Rocket's copy of woocommerce/assets/css/woocommerce.css): said in a comment of the rules; an address
 *    with the word twice maps back with the Nginx and the Apache rules, and would not with one rule per word.
 * F. The fingerprint of the rules includes the rules for sibling folders (3.12.8): rules without them (as
 *    3.12.7 wrote them) are "stale", a map waiting for its rules is not taken up while the server has them,
 *    is taken up once it has the new ones; the notice and WP-CLI (stealth status, stealth check) say to copy
 *    the Stealth rules again with the command, and, once they are current, that the map is put into use.
 * H. Apache with the rules in .htaccess (written by ScrapeLock): the same map with other rules (an update of
 *    the plugin) is written into .htaccess again by the refresh the upgrade schedules; a .htaccess already
 *    current is not touched.
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

/* ---------- Stealth on (Nginx), with a plugin whose slug is a word ---------- */

wp_mkdir_p( $demo . '/assets' );
file_put_contents( $demo . '/pncpdemo.php', "<?php\n/*\nPlugin Name: PNCP demo (t_3128_release)\n*/\n" );
file_put_contents( $demo . '/assets/pncpdemo.css', '/* pncpdemo ' . wp_generate_password( 12, false ) . ' */' );
wp_mkdir_p( $copy_dir . '/assets' );
copy( $demo . '/assets/pncpdemo.css', $copy_dir . '/assets/pncpdemo.css' ); // As WP Rocket's minified copy.
$active = (array) get_option( 'active_plugins', array() );
if ( ! in_array( 'pncpdemo/pncpdemo.php', $active, true ) ) {
	$active[] = 'pncpdemo/pncpdemo.php';
	update_option( 'active_plugins', $active );
}
delete_transient( PNCP_Stealth_Status::STATUS );
delete_option( PNCP_Stealth_Status::SEEN );
settings(
	array(
		'enabled'             => 1,
		'monitor_mode'        => 0,
		'stealth_enabled'     => 1,
		'stealth_base'        => 'assets',
		'stealth_rest_prefix' => '',
		'stealth_sitemap'     => 0,
		'stealth_endpoints'   => 1,
		'stealth_block_files' => 1,
	)
);
$server = 'nginx';
add_filter(
	'pncp_stealth_server',
	static function () use ( &$server ) {
		return $server;
	}
);
add_filter( 'pncp_stealth_self_test', '__return_true' ); // The real self-test runs through Nginx in t_3126_stealth.
$rocket = static function ( $list ) {
	return array_values( array_unique( array_merge( (array) $list, array( 'wp-rocket' ) ) ) );
};
add_filter( 'pncp_stealth_optimizers', $rocket ); // WP Rocket's inner words.
$on = PNCP_Stealth::activate( false );
$st = PNCP_Stealth::state();
t( 'Stealth on (Nginx), the plugin\'s slug and wp-content are words', true === $on && in_array( 'pncpdemo', $st['words'], true ) && in_array( 'wp-content', $st['words'], true ), is_wp_error( $on ) ? $on->get_error_message() : implode( ',', $st['words'] ) );

/* ---------- R. Each word's rule twice, on purpose ---------- */

$nginx  = PNCP_Stealth::rules_text( 'nginx' );
$apache = PNCP_Stealth::rules_text( 'apache' );
$code   = (string) array_search( 'pncpdemo', $st['words'], true );
foreach ( array( 'nginx' => $nginx, 'apache' => $apache ) as $name => $rules ) {
	$pairs = true;
	foreach ( array_keys( $st['words'] ) as $token ) {
		$lines = array_values( preg_grep( '/' . preg_quote( $token, '/' ) . '\(\.\*\)\$/', explode( "\n", $rules ) ) );
		$pairs = $pairs && 2 === count( $lines ) && $lines[0] === $lines[1];
	}
	t( "R $name: each word's rule exactly twice, the comment says why", $pairs && 1 === substr_count( $rules, '# Each code twice on purpose: a word can be in an address two times' ) );
}
$html = PNCP_Stealth::rewrite( '<link rel="stylesheet" href="' . content_url( 'cache/min/1/wp-content/plugins/pncpdemo/assets/pncpdemo.css' ) . '?ver=1">' );
preg_match( '#href="https?://[^/"]+(/[^"?]+)#', $html, $m );
$new = isset( $m[1] ) ? $m[1] : '';
t( 'R WP Rocket\'s copy of a plugin file named after the plugin: the word coded twice in its new address', 2 === substr_count( $new, '/' . $code ) && 0 === substr_count( $html, 'pncpdemo' ) && 0 === substr_count( $html, 'wp-content' ), $html );
$real = '/' . ltrim( wp_make_link_relative( content_url( 'cache/min/1/wp-content/plugins/pncpdemo/assets/pncpdemo.css' ) ), '/' );
t( 'R ... maps back to the real file with the Nginx and with the Apache rules', $real === nginx_apply( $nginx, $new ) && $real === apache_apply( $apache, $new ), nginx_apply( $nginx, $new ) . ' ' . apache_apply( $apache, $new ) );
$single = static function ( $rules ) {
	$out  = array();
	$prev = null;
	foreach ( explode( "\n", $rules ) as $line ) {
		if ( $line !== $prev ) {
			$out[] = $line;
		}
		$prev = $line;
	}
	return implode( "\n", $out );
};
t( 'R ... and would not with one rule per word (the pair is needed)', $real !== nginx_apply( $single( $nginx ), $new ) && $real !== apache_apply( $single( $apache ), $new ) );

/* ---------- F. The fingerprint with the rules for sibling folders ---------- */

$lines   = PNCP_Stealth::rule_lines( 'nginx', 'assets', PNCP_Stealth::build() );
$sibling = preg_grep( '#^rewrite "\(\?i\)\^/?[^"]*assets/\((?:[A-Za-z0-9._-]+\|)+[A-Za-z0-9._-]+\)/#', $lines );
$body    = array_values(
	array_filter(
		$lines,
		static function ( $line ) use ( $sibling ) {
			return ! in_array( $line, $sibling, true ) && false === strpos( $line, PNCP_Stealth_Status::check_path() ) && 0 !== strpos( $line, '# Lets ScrapeLock' ) && 0 !== strpos( $line, '    ' ) && '}' !== $line;
		}
	)
);
$old_fp  = PNCP_Stealth_Status::fingerprint_in( implode( "\n", PNCP_Stealth_Status::with_fingerprint( 'nginx', $body ) ), 'nginx' );
$want    = PNCP_Stealth_Status::current( 'nginx' );
t( 'F the rules have sibling-folder rules (wp-content: uploads, plugins, themes), and the fingerprint changes with them', count( $sibling ) >= 1 && '' !== $old_fp && $old_fp !== $want, $old_fp . ' ' . $want . ' ' . implode( ' | ', $sibling ) );
$installed = $old_fp;
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) use ( &$installed ) {
		if ( false === strpos( (string) $url, PNCP_Stealth_Status::check_path() ) ) {
			return $pre;
		}
		return array(
			'headers'  => array( 'content-type' => 'text/plain' ),
			'body'     => $installed . "\n",
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	},
	10,
	3
);
$fresh = static function () {
	PNCP_Stealth_Status::reset();
	delete_transient( PNCP_Stealth_Status::STATUS );
	wp_clear_scheduled_hook( PNCP_Stealth::REFRESH );
};
$fresh();
$status = PNCP_Stealth_Status::status( true );
t( 'F the server has the rules as 3.12.7 wrote them (no sibling rules): stale, the notice says to copy the Stealth rules again', 'stale' === $status['state'] && 'changed' === PNCP_Stealth_Status::needs_copy() && false !== strpos( PNCP_Stealth_Status::message( 'changed' ), 'copy the Stealth rules again' ), $status['state'] . ' ' . PNCP_Stealth_Status::needs_copy() );
$next = PNCP_Stealth_Status::cli_next();
t( 'F ... WP-CLI says it with the commands (rules install --stealth=<file>, then stealth test)', false !== strpos( $next, 'copy the Stealth rules again' ) && false !== strpos( $next, 'wp scrapelock rules install --stealth=<file>' ) && false !== strpos( $next, 'wp scrapelock stealth test' ), $next );
$cli = PNCP_Stealth::cli_status();
t( 'F ... wp scrapelock stealth status: rules stale, the map in use, next = the same text', 'stale' === $cli['rules'] && 'in use' === $cli['map'] && $next === $cli['next'], wp_json_encode( $cli ) );
// A map that waits for its rules: the words of before (no WP Rocket), the new ones lack in the pages.
remove_filter( 'pncp_stealth_optimizers', $rocket );
add_filter( 'pncp_stealth_optimizers', '__return_empty_array' ); // As before WP Rocket was seen.
PNCP_Stealth::activate( false );
remove_filter( 'pncp_stealth_optimizers', '__return_empty_array' );
add_filter( 'pncp_stealth_optimizers', $rocket );
$fresh();
PNCP_Stealth::refresh();
$st = PNCP_Stealth::state();
t( 'F a new map (WP Rocket\'s inner words) while the server has the rules without sibling rules: waiting, the old words kept', '' !== (string) $st['pending'] && ! in_array( 'wp-content', $st['words'], true ) && 'waiting' === PNCP_Stealth::cli_status()['map'], wp_json_encode( array( $st['pending'], $st['words'], PNCP_Stealth::cli_status()['map'] ) ) );
t( 'F ... WP-CLI: copy the Stealth rules again', false !== strpos( PNCP_Stealth_Status::cli_next(), 'copy the Stealth rules again' ), PNCP_Stealth_Status::cli_next() );
if ( class_exists( 'PNCP_Stealth_Debug' ) ) {
	$check = PNCP_Stealth_Debug::check( home_url( '/' ) );
	t( 'F ... wp scrapelock stealth check: rules stale, "words not used" asks to copy the rules first, next', is_array( $check ) && 'stale' === $check['rules'] && false !== strpos( $check['words not used'], 'copy the Stealth rules again, then run wp scrapelock stealth test' ) && false !== strpos( $check['next'], 'copy the Stealth rules again' ), wp_json_encode( $check ) );
}
// The owner installs the new rules: the check address answers the current fingerprint.
$installed = PNCP_Stealth_Status::current( 'nginx' );
$fresh();
$status = PNCP_Stealth_Status::status( true );
t( 'F the new rules installed: current, nothing to copy, the refresh scheduled; WP-CLI says the map is put into use', 'current' === $status['state'] && '' === PNCP_Stealth_Status::needs_copy() && false !== wp_next_scheduled( PNCP_Stealth::REFRESH ) && false !== strpos( PNCP_Stealth_Status::cli_next(), 'within a minute' ), PNCP_Stealth_Status::cli_next() );
$fresh();
PNCP_Stealth::refresh(); // What the scheduled refresh (or the twice-daily check) runs.
$st = PNCP_Stealth::state();
t( 'F ... the refresh takes the new map up: the inner words in use, nothing waiting, nothing left to do', '' === (string) $st['pending'] && in_array( 'wp-content', $st['words'], true ) && '' === PNCP_Stealth_Status::cli_next() && 'in use' === PNCP_Stealth::cli_status()['map'] );

/* ---------- H. Apache: .htaccess written again for the same map with other rules ---------- */

if ( ! is_writable( ABSPATH ) && ! is_writable( $htaccess ) ) {
	echo "SKIP H .htaccess not writable\n";
} else {
	$server = 'apache';
	if ( ! is_file( $htaccess ) ) {
		file_put_contents( $htaccess, "# BEGIN WordPress\n# END WordPress\n" );
	}
	$on = PNCP_Stealth::activate( false );
	$st = PNCP_Stealth::state();
	$fp = static function () use ( $htaccess ) {
		$text = (string) file_get_contents( $htaccess );
		$at   = strpos( $text, '# BEGIN ScrapeLock Stealth' );
		return false === $at ? '' : PNCP_Stealth_Status::fingerprint_in( substr( $text, $at ), 'apache' );
	};
	t( 'H Apache: the rules written into .htaccess, current', true === $on && ! empty( $st['htaccess'] ) && $fp() === PNCP_Stealth_Status::current( 'apache' ), is_wp_error( $on ) ? $on->get_error_message() : $fp() );
	// As after an update: the same map, the .htaccess with the rules of before (another fingerprint, no sibling rules).
	$text = (string) file_get_contents( $htaccess );
	$text = (string) preg_replace( '/^RewriteRule \^assets\/\((?:[A-Za-z0-9._-]+\|)+[A-Za-z0-9._-]+\)\/.*\R/m', '', $text );
	$text = str_replace( '"' . PNCP_Stealth_Status::current( 'apache' ) . '"', '"aaaaaaaaaaaa"', $text );
	file_put_contents( $htaccess, $text );
	$sig = $st['sig'];
	$fresh();
	PNCP_Stealth::refresh();
	$st = PNCP_Stealth::state();
	t( 'H ... the same map, older rules in .htaccess: the refresh writes the current rules (sibling rules too), map unchanged', $fp() === PNCP_Stealth_Status::current( 'apache' ) && 1 === preg_match( '/^RewriteRule \^assets\/\(/m', (string) file_get_contents( $htaccess ) ) && $sig === $st['sig'] && '' === (string) $st['pending'] && PNCP_Stealth::active(), $fp() );
	$mtime = filemtime( $htaccess );
	$size  = md5( (string) file_get_contents( $htaccess ) );
	sleep( 1 );
	clearstatcache();
	PNCP_Stealth::refresh();
	clearstatcache();
	t( 'H ... a current .htaccess is not written again', md5( (string) file_get_contents( $htaccess ) ) === $size && filemtime( $htaccess ) === $mtime );
	$src = (string) file_get_contents( PNCP_DIR . 'scrapelock.php' );
	t( 'H ... the upgrade schedules that refresh (pncp_upgrade_files)', 1 === preg_match( '/function pncp_upgrade_files\(\).*?PNCP_Stealth::schedule_refresh\(\);.*?\n}/s', $src ) );
	$server = 'nginx';
	PNCP_Stealth::remove_htaccess();
}

exit( $fails ? 1 : 0 );
