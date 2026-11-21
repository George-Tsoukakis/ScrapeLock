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
 * F. A plugin folder whose name has a space or another character the rules cannot carry: the rules stay valid
 *    (real nginx -t when nginx is on PATH, else SKIP for that part) and its files are served through the plugins
 *    address.
 * S. Stylesheets that reach a sibling folder with "../": a child theme's @import of its parent theme and a
 *    plugin's url() into another plugin resolve, in the browser, to /<base>/<folder>/…; the rules serve them.
 * E. Addresses URL-encoded inside another address (a share link's media=https%3A%2F%2F<host>%2Fwp-content%2F…)
 *    get the neutral address, encoded the same way; "+" and the other parameters stay; other hosts stay.
 * W. WooCommerce's cart fragments (/?wc-ajax=get_refreshed_fragments, a stand-in mu-plugin in WooCommerce's
 *    order: DOING_AJAX defined at init 0, the JSON sent at template_redirect 0): the HTML in them gets the neutral
 *    addresses for guests like the page it goes into. Through the test server (BASE).
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
$mu = WP_CONTENT_DIR . '/mu-plugins/pncp-t3128-wc-ajax.php';
register_shutdown_function(
	static function () use ( $saved, $made, $mu ) {
		if ( is_file( $mu ) ) {
			unlink( $mu );
		}
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

/* ---------- F. A folder name the rules cannot carry ---------- */

$bad_lines = array();
foreach ( explode( "\n", $nginx ) as $line ) {
	if ( 0 === strpos( $line, 'rewrite ' ) && ! preg_match( '/^rewrite "[^"]+" [^\s";{}]+( last)?;$/', $line ) ) {
		$bad_lines[] = $line;
	}
}
foreach ( explode( "\n", $apache ) as $line ) {
	if ( 0 === strpos( $line, 'RewriteRule ' ) && ! preg_match( '/^RewriteRule \S+ \S+ \[[A-Z,=0-9]+\]$/', $line ) ) {
		$bad_lines[] = $line;
	}
}
t( 'F every rewrite line has one pattern and one target (a plugin folder with a space in its name)', array() === $bad_lines, implode( ' | ', $bad_lines ) );
$c_url = plugins_url( 'c.css', WP_PLUGIN_DIR . '/pncp t3128 (c)/c.php' );
$c_out = PNCP_Stealth::rewrite( '<link rel="stylesheet" href="' . $c_url . '">' );
preg_match( '#href="([^"]+)"#', $c_out, $cm );
$c_path = isset( $cm[1] ) ? rawurldecode( (string) wp_parse_url( $cm[1], PHP_URL_PATH ) ) : '';
t( 'F that folder\'s file is served by the rules (Nginx)', '' !== $c_path && file_of( nginx_apply( $nginx, $c_path ) ) === realpath( WP_PLUGIN_DIR . '/pncp t3128 (c)/c.css' ), $c_out . ' → ' . nginx_apply( $nginx, $c_path ) );
t( 'F that folder\'s file is served by the rules (Apache)', '' !== $c_path && file_of( apache_apply( $apache, $c_path ) ) === realpath( WP_PLUGIN_DIR . '/pncp t3128 (c)/c.css' ), $c_out . ' → ' . apache_apply( $apache, $c_path ) );
$nginx_bin = '';
foreach ( explode( PATH_SEPARATOR, (string) getenv( 'PATH' ) ) as $p ) {
	if ( '' !== $p && is_executable( $p . '/nginx' ) ) {
		$nginx_bin = $p . '/nginx';
		break;
	}
}
if ( '' === $nginx_bin ) {
	echo "SKIP F real nginx -t (no nginx on PATH)\n";
} else {
	$tmp = sys_get_temp_dir() . '/pncp-t3128-' . getmypid();
	mkdir( $tmp );
	file_put_contents( $tmp . '/nginx.conf', "events {}\nhttp {\n server {\n  listen 127.0.0.1:1;\n  root " . $tmp . ";\n" . $nginx . "\n }\n}\n" );
	$cmd = escapeshellarg( $nginx_bin ) . ' -t -q -p ' . escapeshellarg( $tmp ) . ' -c ' . escapeshellarg( $tmp . '/nginx.conf' ) . ' -g ' . escapeshellarg( 'pid ' . $tmp . '/n.pid; error_log ' . $tmp . '/e.log;' ) . ' 2>&1';
	exec( $cmd, $o, $rc ); // phpcs:ignore -- Test.
	rmtree( $tmp );
	t( 'F real nginx -t accepts the Stealth rules', 0 === $rc, implode( ' ', $o ) );
}

/* ---------- S. "../" into a sibling folder ---------- */

$child_css = get_stylesheet_directory_uri() . '/style.css';
$out       = PNCP_Stealth::rewrite( '<link rel="stylesheet" href="' . $child_css . '">' );
preg_match( '#href="([^"]+)"#', $out, $sm );
$child_new = isset( $sm[1] ) ? $sm[1] : '';
t( 'S the child theme\'s stylesheet gets a neutral address', '' !== $child_new && false === strpos( $child_new, 'wp-content' ), $out );
foreach ( array(
	'@import of the parent theme'   => array( '../pncp-t3128-parent/style.css', get_theme_root() . '/pncp-t3128-parent/style.css' ),
	'a font of the parent theme'    => array( '../pncp-t3128-parent/fonts/p.woff2', get_theme_root() . '/pncp-t3128-parent/fonts/p.woff2' ),
) as $label => $how ) {
	$path = resolve( $child_new, $how[0] );
	t( 'S child theme: ' . $label . ' (' . $path . ') is served (Nginx)', file_of( nginx_apply( $nginx, $path ) ) === realpath( $how[1] ), nginx_apply( $nginx, $path ) );
	t( 'S child theme: ' . $label . ' is served (Apache)', file_of( apache_apply( $apache, $path ) ) === realpath( $how[1] ), apache_apply( $apache, $path ) );
}
$a_out = PNCP_Stealth::rewrite( '<link rel="stylesheet" href="' . $pu . '/css/a.css">' );
preg_match( '#href="([^"]+)"#', $a_out, $am );
$b_path = resolve( isset( $am[1] ) ? $am[1] : '', '../../pncp-t3128-b/img/b.png' );
t( 'S a plugin\'s url() into another plugin (' . $b_path . ') is served (Nginx)', file_of( nginx_apply( $nginx, $b_path ) ) === realpath( WP_PLUGIN_DIR . '/pncp-t3128-b/img/b.png' ), nginx_apply( $nginx, $b_path ) );
t( 'S a plugin\'s url() into another plugin is served (Apache)', file_of( apache_apply( $apache, $b_path ) ) === realpath( WP_PLUGIN_DIR . '/pncp-t3128-b/img/b.png' ), apache_apply( $apache, $b_path ) );
$php = '/assets/pncp-t3128-a/download.php';
t( 'S PHP is never served through a sibling address', file_of( nginx_apply( $nginx, $php ) ) === '' && file_of( apache_apply( $apache, $php ) ) === '', nginx_apply( $nginx, $php ) );
// A real folder of the site at the base address (e.g. a static /assets/ with its own uploads/ or a theme's name):
// the sibling rules would hide its files, so there are none then.
if ( ! function_exists( 'get_home_path' ) ) {
	require_once ABSPATH . 'wp-admin/includes/file.php';
}
$real_base = trailingslashit( get_home_path() ) . 'assets';
if ( is_dir( $real_base ) ) {
	echo "SKIP S a real folder at the base address (the test site has one already)\n";
} else {
	put( $real_base . '/uploads/pncp-t3128-real.png', 'pncp-t3128 real' );
	put( $real_base . '/pncp-t3128-parent/real.css', 'pncp-t3128 real' );
	PNCP_Stealth_Status::reset();
	$rn = PNCP_Stealth::rules_text( 'nginx' );
	$ra = PNCP_Stealth::rules_text( 'apache' );
	foreach ( array( '/assets/uploads/pncp-t3128-real.png', '/assets/pncp-t3128-parent/real.css' ) as $p ) {
		t( 'S a real file at ' . $p . ' is not hidden by the rules (Nginx)', nginx_apply( $rn, $p ) === $p, nginx_apply( $rn, $p ) );
		t( 'S a real file at ' . $p . ' is not hidden by the rules (Apache)', apache_apply( $ra, $p ) === $p, apache_apply( $ra, $p ) );
	}
	rmtree( $real_base );
}

/* ---------- E. URL-encoded addresses ---------- */

$enc   = rawurlencode( $u . '/a.jpg' );
$share = '<a href="https://share.example/pin/create/?url=' . rawurlencode( $h . '/a-post/' ) . '&amp;media=' . $enc . '&amp;description=Two+words">Pin</a>';
$out   = PNCP_Stealth::rewrite( $share );
preg_match( '#media=([^&"]+)#', $out, $em );
$media = isset( $em[1] ) ? rawurldecode( $em[1] ) : '';
t( 'E an encoded address of this host inside a share link gets the neutral address', false === stripos( $out, 'wp-content' ) && false !== strpos( $media, '/assets/' ), $out );
t( 'E it maps back to its file', array() === unmapped( $media, $nginx, $apache ) && array() !== own_addresses( $media ), $media );
t( 'E it stays encoded and the other parameters stay as they were', isset( $em[1] ) && rawurlencode( $media ) === $em[1] && false !== strpos( $out, '?url=' . rawurlencode( $h . '/a-post/' ) . '&amp;media=' ) && false !== strpos( $out, '&amp;description=Two+words"' ), $out );
t( 'E rewriting twice changes nothing', PNCP_Stealth::rewrite( $out ) === $out );
$plus = 'x?u=' . rawurlencode( $pu . '/js/a.js' ) . '%3Fa%3D1+2';
t( 'E a "+" right after the encoded address stays', 1 === preg_match( '#^x\?u=[^+]*%2Fassets%2F[0-9a-f]{6}%2Fjs%2Fa\.js%3Fa%3D1\+2$#', PNCP_Stealth::rewrite( $plus ) ), PNCP_Stealth::rewrite( $plus ) );
$keep_enc = array(
	'another host'     => '<a href="https://share.example/?media=' . rawurlencode( 'https://other.example/wp-content/uploads/a.jpg' ) . '">x</a>',
	'a type not served' => '<a href="https://share.example/?file=' . rawurlencode( $u . '/f.zip' ) . '">x</a>',
);
foreach ( $keep_enc as $label => $in ) {
	t( 'E encoded: ' . $label . ' keeps its address', PNCP_Stealth::rewrite( $in ) === $in, PNCP_Stealth::rewrite( $in ) );
}

/* ---------- W. WooCommerce cart fragments (wc-ajax) ---------- */

$standin = <<<'PHP'
<?php
/**
 * Test stand-in written by tests/t_3128_stealth_edges.php (removed after the test). Not WooCommerce's code: the
 * order in which WooCommerce answers /?wc-ajax=… (DOING_AJAX at init 0, the answer at template_redirect 0).
 */
add_action(
	'init',
	static function () {
		if ( ! empty( $_GET['wc-ajax'] ) && ! defined( 'DOING_AJAX' ) ) {
			define( 'DOING_AJAX', true );
		}
	},
	0
);
add_action(
	'template_redirect',
	static function () {
		if ( empty( $_GET['wc-ajax'] ) || 'get_refreshed_fragments' !== $_GET['wc-ajax'] ) {
			return;
		}
		$img = wp_upload_dir( null, false )['baseurl'] . '/pncp-t3128/a.jpg';
		wp_send_json(
			array(
				'fragments' => array( 'div.widget_shopping_cart_content' => '<div class="widget_shopping_cart_content"><img src="' . esc_url( $img ) . '" width="32"></div>' ),
				'cart_hash' => 'x',
			)
		);
	},
	0
);
PHP;
if ( ! is_dir( dirname( $mu ) ) ) {
	mkdir( dirname( $mu ), 0777, true );
}
file_put_contents( $mu, $standin );
$ch = curl_init( $base . '/?wc-ajax=get_refreshed_fragments' );
curl_setopt_array(
	$ch,
	array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_TIMEOUT        => 60,
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.238', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', 'Accept-Language: en', 'Accept: application/json' ),
	)
);
$body = (string) curl_exec( $ch );
$code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
curl_close( $ch );
$json = json_decode( $body, true );
$frag = is_array( $json ) && isset( $json['fragments'] ) ? implode( '', (array) $json['fragments'] ) : '';
t( 'W the cart fragments answer (stand-in)', 200 === $code && false !== strpos( $frag, 'pncp-t3128/a.jpg' ), $code . ' ' . substr( $body, 0, 200 ) );
t( 'W the HTML of the fragments has the neutral addresses for guests', '' !== $frag && false === strpos( $frag, 'wp-content' ) && false !== strpos( $frag, '/assets/' ), $frag );
t( 'W they map back to their file', array() === unmapped( $frag, $nginx, $apache ), implode( '; ', unmapped( $frag, $nginx, $apache ) ) );
unlink( $mu );

exit( $fails ? 1 : 0 );
