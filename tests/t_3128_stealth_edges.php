<?php
/**
 * ScrapeLock 3.12.8 — Stealth: edge cases of the rewriting and of the server rules it generates.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3128_stealth_edges.php
 *
 * In-process (the self-test is decided by the filter; the rules are applied with PCRE as Nginx and Apache apply
 * them, see t_3127_stealth_cache.php). Every address Stealth writes on the site's host must map back, through the
 * generated rules, to the same existing file.
 *
 * B. A battery of realistic markup: src/srcset/sizes, data-src/data-srcset/data-bg/data-rocket-src, inline
 *    style url(), <style> with url() and @import, preload / modulepreload, the import map and JSON with escaped
 *    slashes, protocol-relative and https addresses, query and fragment, other hosts (unchanged), PHP (unchanged),
 *    rewriting twice (no change the second time); each new address maps back to its file.
 * X. Links to uploaded files whose type the rules do not serve (.zip, .docx, …) keep their real address (they
 *    used to get a neutral one that answered 404); the types the rules serve still get the neutral one.
 * Q. Root-relative addresses inside an attribute after an HTML-escaped quote (url(&quot;/wp-content/…&quot;),
 *    url(&#039;…&#039;)) are rewritten like those after a plain quote.
 *
 * Only on a test WordPress.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
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

/** The same for the Apache rules (RewriteBase of the home folder, paths without it). */
function apache_apply( $rules, $path ) {
	$home = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
	$rel  = 0 === strpos( $path, $home ) ? substr( $path, strlen( $home ) ) : ltrim( $path, '/' );
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
				return 0 === strpos( $rel, '/' ) ? $rel : $home . $rel;
			}
		}
	}
	return 0 === strpos( $rel, '/' ) ? $rel : $home . $rel;
}

/** The file a path of this site is, '' when there is none (paths of WordPress's own folders only). */
function file_of( $path ) {
	$path = rawurldecode( $path );
	$home = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
	$rel  = 0 === strpos( $path, $home ) ? substr( $path, strlen( $home ) ) : ltrim( $path, '/' );
	$file = ABSPATH . $rel;
	return is_file( $file ) ? realpath( $file ) : '';
}

/** Resolves a relative address against an absolute one, as a browser does (path only). */
function resolve( $from, $rel ) {
	$dir   = preg_replace( '#[^/]*$#', '', (string) wp_parse_url( $from, PHP_URL_PATH ) );
	$parts = array();
	foreach ( explode( '/', $dir . $rel ) as $p ) {
		if ( '..' === $p ) {
			array_pop( $parts );
		} elseif ( '.' !== $p ) {
			$parts[] = $p;
		}
	}
	return '/' . ltrim( implode( '/', $parts ), '/' );
}

/** Every address on this site's host in a text (plain or with JSON's escaped slashes). */
function own_addresses( $text ) {
	$host = preg_quote( (string) wp_parse_url( home_url(), PHP_URL_HOST ), '#' );
	$port = wp_parse_url( home_url(), PHP_URL_PORT );
	$host = $port ? $host . ':' . $port : $host;
	preg_match_all( '#(?:https?:)?\\\\?/\\\\?/' . $host . '((?:\\\\?/[^\s"\'<>(),?\#&\\\\]+)+)#', $text, $m );
	preg_match_all( '#(?<=["\'(=,\s])(/[a-z0-9_-]+/[0-9a-f]{6}/[^\s"\'<>(),?\#&\\\\]+)#i', $text, $r );
	return array_values( array_unique( array_merge( array_map( 'stripslashes', $m[1] ), $r[1] ) ) );
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

/** Writes a file, with its folders. */
function put( $file, $content ) {
	if ( ! is_dir( dirname( $file ) ) ) {
		mkdir( dirname( $file ), 0777, true );
	}
	file_put_contents( $file, $content );
}

$saved = array();
foreach ( array( PNCP_OPTION, PNCP_Stealth::OPTION, PNCP_Stealth_Status::SEEN, 'active_plugins', 'stylesheet', 'template' ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}
$uploads = wp_upload_dir( null, false );
$updir   = $uploads['basedir'] . '/pncp-t3128';
$made    = array(
	$updir,
	WP_PLUGIN_DIR . '/pncp-t3128-a',
	WP_PLUGIN_DIR . '/pncp-t3128-b',
	WP_PLUGIN_DIR . '/pncp t3128 (c)',
	get_theme_root() . '/pncp-t3128-parent',
	get_theme_root() . '/pncp-t3128-child',
);
register_shutdown_function(
	static function () use ( $saved, $made ) {
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, PNCP_Stealth::OPTION === $name || PNCP_OPTION === $name || 'active_plugins' === $name );
			}
		}
		foreach ( $made as $dir ) {
			rmtree( $dir );
		}
		wp_clean_themes_cache();
		delete_transient( PNCP_Stealth_Status::STATUS );
	}
);

// The folders and files of the test.
foreach ( array( 'a.jpg', 'b-300x200.jpg', 'c.JPG', 'd.pdf', 'e.webp', 'f.zip', 'g.docx', 'h.xlsx', 'i.tar.gz', 'j.epub', 'k.csv', 'l.png', 'bg.png' ) as $f ) {
	put( $updir . '/' . $f, 'pncp-t3128 ' . $f );
}
put( WP_PLUGIN_DIR . '/pncp-t3128-a/pncp-t3128-a.php', "<?php\n/* Plugin Name: T3128 A */\n" );
put( WP_PLUGIN_DIR . '/pncp-t3128-a/css/a.css', '.a{background:url(../../pncp-t3128-b/img/b.png)}' );
put( WP_PLUGIN_DIR . '/pncp-t3128-a/js/a.js', 'var a=1;' );
put( WP_PLUGIN_DIR . '/pncp-t3128-a/download.php', '<?php echo 1;' );
put( WP_PLUGIN_DIR . '/pncp-t3128-b/pncp-t3128-b.php', "<?php\n/* Plugin Name: T3128 B */\n" );
put( WP_PLUGIN_DIR . '/pncp-t3128-b/img/b.png', 'pncp-t3128 b.png' );
put( WP_PLUGIN_DIR . '/pncp t3128 (c)/c.php', "<?php\n/* Plugin Name: T3128 C */\n" );
put( WP_PLUGIN_DIR . '/pncp t3128 (c)/c.css', '.c{}' );
put( get_theme_root() . '/pncp-t3128-parent/style.css', "/*\nTheme Name: T3128 Parent\n*/\n.parent{}\n" );
put( get_theme_root() . '/pncp-t3128-parent/index.php', '<?php' );
put( get_theme_root() . '/pncp-t3128-parent/fonts/p.woff2', 'pncp-t3128 woff2' );
put( get_theme_root() . '/pncp-t3128-child/style.css', "/*\nTheme Name: T3128 Child\nTemplate: pncp-t3128-parent\n*/\n@import url(\"../pncp-t3128-parent/style.css\");\n@font-face{src:url(../pncp-t3128-parent/fonts/p.woff2)}\n" );
put( get_theme_root() . '/pncp-t3128-child/index.php', '<?php' );
wp_clean_themes_cache();
update_option( 'template', 'pncp-t3128-parent' );
update_option( 'stylesheet', 'pncp-t3128-child' );
$active = array_values( array_diff( (array) get_option( 'active_plugins', array() ), array( '' ) ) );
update_option( 'active_plugins', array_merge( $active, array( 'pncp-t3128-a/pncp-t3128-a.php', 'pncp-t3128-b/pncp-t3128-b.php', 'pncp t3128 (c)/c.php' ) ) );

add_filter( 'pncp_stealth_self_test', '__return_true' );
update_option(
	PNCP_OPTION,
	array_merge(
		PNCP_Options::stored(),
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
	)
);
PNCP_Options::flush();
$on = PNCP_Stealth::activate( false );
t( 'Stealth turns on (self-test by filter)', true === $on && PNCP_Stealth::active(), is_wp_error( $on ) ? $on->get_error_message() : '' );
$nginx  = PNCP_Stealth::rules_text( 'nginx' );
$apache = PNCP_Stealth::rules_text( 'apache' );

/**
 * Every own address of the rewritten text maps back to an existing file with both rule sets ([] = all do).
 *
 * @return string[]
 */
function unmapped( $text, $nginx, $apache ) {
	$bad = array();
	foreach ( own_addresses( $text ) as $path ) {
		if ( ! preg_match( '#/assets/#', $path ) ) {
			continue;
		}
		$n = file_of( nginx_apply( $nginx, $path ) );
		$a = file_of( apache_apply( $apache, $path ) );
		if ( '' === $n || '' === $a || $n !== $a ) {
			$bad[] = $path . ' → nginx ' . nginx_apply( $nginx, $path ) . ' / apache ' . apache_apply( $apache, $path );
		}
	}
	return $bad;
}

/* ---------- B. The battery ---------- */

$h  = home_url();
$u  = $uploads['baseurl'] . '/pncp-t3128';
$pu = plugins_url( '', WP_PLUGIN_DIR . '/pncp-t3128-a/x' );
$hj = str_replace( '/', '\\/', $h );
$uj = str_replace( '/', '\\/', $u );
$ur = (string) wp_parse_url( $u, PHP_URL_PATH );
$pr = (string) wp_parse_url( $pu, PHP_URL_PATH );
$pc = (string) wp_parse_url( $h, PHP_URL_HOST ) . ( wp_parse_url( $h, PHP_URL_PORT ) ? ':' . wp_parse_url( $h, PHP_URL_PORT ) : '' );

$cases = array(
	'srcset/sizes'            => '<img src="' . $u . '/a.jpg" srcset="' . $u . '/b-300x200.jpg 300w, ' . $u . '/a.jpg 1024w" sizes="(max-width: 300px) 100vw, 300px">',
	'data-* lazy attributes'  => '<img data-src="' . $ur . '/a.jpg" data-srcset="' . $ur . '/a.jpg 1x,' . $ur . '/b-300x200.jpg 2x" data-bg="url(' . $ur . '/bg.png)" data-rocket-src="' . $pu . '/js/a.js" data-lazy-src="' . $u . '/l.png">',
	'inline style url()'      => '<div style="background-image:url(' . $u . '/bg.png)"></div><div style="background:url(\'' . $ur . '/bg.png\')"></div>',
	'<style> url() / @import' => '<style>@import url("' . $pr . '/css/a.css");@import \'' . $pr . '/css/a.css\';body{background:url(' . $ur . '/bg.png)}</style>',
	'preload / modulepreload' => '<link rel="preload" href="' . $pr . '/js/a.js" as="script"><link rel="modulepreload" href="' . $pu . '/js/a.js?ver=1">',
	'import map / JSON \\/'   => '<script type="importmap">{"imports":{"a":"' . $hj . str_replace( '/', '\\/', $pr ) . '\\/js\\/a.js?ver=55"}}</script><script>var x={"u":"' . str_replace( '/', '\\/', $ur ) . '\\/a.jpg","i":"' . $uj . '\\/l.png"};</script>',
	'protocol-relative'       => '<script src="//' . $pc . $pr . '/js/a.js"></script>',
	'query and fragment'      => '<a href="' . $u . '/d.pdf?x=1&amp;y=2#page=3">d</a>',
	'upper-case file type'    => '<img src="' . $u . '/c.JPG">',
);
foreach ( $cases as $label => $in ) {
	$out = PNCP_Stealth::rewrite( $in );
	$bad = unmapped( $out, $nginx, $apache );
	t( 'B ' . $label . ': no WordPress folder left on this host', false === strpos( $out, '/wp-content/' ) && false === strpos( $out, '\\/wp-content\\/' ) && false === strpos( $out, '/wp-includes/' ), $out );
	t( 'B ' . $label . ': every new address maps back to its file (Nginx and Apache rules)', array() === $bad && array() !== own_addresses( $out ), implode( '; ', $bad ) . ' | ' . $out );
	t( 'B ' . $label . ': rewriting twice changes nothing', PNCP_Stealth::rewrite( $out ) === $out );
}
$q = PNCP_Stealth::rewrite( '<a href="' . $u . '/d.pdf?x=1&amp;y=2#page=3">d</a>' );
t( 'B the query and the fragment stay as they were', false !== strpos( $q, '/d.pdf?x=1&amp;y=2#page=3"' ), $q );
$keep = array(
	'other host'           => '<img src="https://cdn.example.org/wp-content/uploads/a.jpg"><a href="https://other.example/wp-content/uploads/x.pdf">x</a>',
	'PHP of a plugin'      => '<a href="' . $pu . '/download.php?f=1">get</a>',
	'admin-ajax.php/extra' => '<a href="' . $h . '/wp-admin/admin-ajax.php/extra">x</a>',
);
foreach ( $keep as $label => $in ) {
	t( 'B ' . $label . ' keeps its address', PNCP_Stealth::rewrite( $in ) === $in, PNCP_Stealth::rewrite( $in ) );
}

/* ---------- X. Types the rules do not serve ---------- */

$served = array( 'a.jpg', 'c.JPG', 'd.pdf', 'e.webp', 'l.png' );
$not    = array( 'f.zip', 'g.docx', 'h.xlsx', 'i.tar.gz', 'j.epub', 'k.csv' );
foreach ( array_merge( $served, $not ) as $f ) {
	$in  = '<a href="' . $u . '/' . $f . '">' . $f . '</a> <a href="' . $ur . '/' . $f . '?dl=1">' . $f . '</a>';
	$out = PNCP_Stealth::rewrite( $in );
	if ( in_array( $f, $not, true ) ) {
		t( 'X a link to an uploaded .' . pathinfo( $f, PATHINFO_EXTENSION ) . ' keeps its real address (the rules do not serve that type)', $out === $in, $out );
	} else {
		t( 'X an uploaded .' . pathinfo( $f, PATHINFO_EXTENSION ) . ' gets the neutral address', false === strpos( $out, '/wp-content/' ), $out );
	}
	t( 'X ' . $f . ': every address on this host is a file (none answers 404)', array() === unmapped( $out, $nginx, $apache ), implode( '; ', unmapped( $out, $nginx, $apache ) ) );
}
$dir = PNCP_Stealth::rewrite( '<script>var cfg={"base":"' . str_replace( '/', '\\/', $pr ) . '\\/js\\/","url":"' . $pr . '/js"};</script>' );
t( 'X folder addresses (a script adds the file name) still get the neutral address', false === strpos( $dir, 'wp-content' ), $dir );

/* ---------- Q. HTML-escaped quotes ---------- */

foreach ( array( '&quot;', '&#039;', '&#39;' ) as $quote ) {
	$in  = '<div style="background-image:url(' . $quote . $ur . '/bg.png' . $quote . ')"></div>';
	$out = PNCP_Stealth::rewrite( $in );
	t( 'Q url(' . $quote . '/…' . $quote . ') in an attribute is rewritten', false === strpos( $out, '/wp-content/' ) && false !== strpos( $out, 'url(' . $quote . '/assets/' ), $out );
	t( 'Q url(' . $quote . '/…' . $quote . ') maps back to its file', array() === unmapped( str_replace( $quote, '"', $out ), $nginx, $apache ), $out );
	$other = '<div style="background:url(' . $quote . 'https://other.example/wp-content/uploads/a.png' . $quote . ')"></div>';
	t( 'Q url(' . $quote . '…' . $quote . ') of another host stays', PNCP_Stealth::rewrite( $other ) === $other );
}
$text = '<p>Copy it to my-folder/wp-content/uploads or to x&amp;/wp-content/ please.</p>';
t( 'Q a path glued to other text is not rewritten', PNCP_Stealth::rewrite( $text ) === $text, PNCP_Stealth::rewrite( $text ) );

exit( $fails ? 1 : 0 );
