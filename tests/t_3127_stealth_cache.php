<?php
/**
 * ScrapeLock 3.12.7 — Stealth and the cached pages of a page cache (WP Rocket-like) and of an Nginx cache.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3127_stealth_cache.php
 *
 * Live (3.12.6, WP Rocket minify/combine + Nginx fastcgi cache): "/?nocache=<ts>" had 0 wp-content, "/" (an Nginx
 * cache HIT) still /assets/<alias>/cache/min/1/wp-content/themes/<coded theme>/…. The stand-in below follows WP
 * Rocket 3.x where it matters (read from its source, no code of it): the page cache buffer is started by
 * advanced-cache.php before the plugins load and writes the stored file (+ _gzip) in its callback, which gets
 * the output of every inner buffer; the stored file is served on the next request before WordPress (readfile,
 * exit); the optimization buffer starts at template_redirect 2 and applies rocket_buffer: minify CSS (16, its
 * URL through rocket_css_url with the original URL), combine JS (22, rocket_js_url), delay JS (26,
 * data-rocket-src), preload links in the head (100000), lazy-loaded background CSS (110000: cache/background-css/
 * <blog>/<host>/<path of the stylesheet as it is then, i.e. the minified copy>, only for a stylesheet whose URL
 * maps to a local file); neither buffer runs for a URL with a query string it does not know (?nocache=).
 *
 * C. Through the stand-in: the first request (MISS) and the stored page (HIT, served before WordPress), the file
 *    on disk and its _gzip copy: 0 wp-content / wp-includes in the asset addresses (and in the page); every asset
 *    address maps back to the real file with the Nginx and the Apache rules (PCRE, as the server applies them);
 *    WP Rocket's late stages still found the real files (background CSS made from the minified stylesheet).
 * Q. "?nocache=": not optimized at all (no cache/min address), so it never shows the minified addresses.
 * O. A page stored with the words of before 3.12.6 (no inner words): exactly the live leftover; the new map
 *    empties the stand-in's cache, the next MISS and HIT are clean. Stealth off: emptied, the real addresses;
 *    on again: emptied, clean MISS and HIT.
 * N. Real Nginx (SKIP without nginx on PATH) with the Stealth rules and a proxy cache standing in for
 *    fastcgi_cache: MISS then HIT, 0 wp-content / wp-includes, every asset 200 with the real bytes; a page the
 *    Nginx cache stored before the new map is served stale until that cache is emptied (the live HIT), after
 *    which MISS and HIT are clean.
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

/** Stores settings as they are. */
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	wp_cache_delete( 'alloptions', 'options' );
}

/** A guest's GET; [code, body, headers]. */
function http( $url, $gzip = false ) {
	$ch      = curl_init( $url );
	$headers = array();
	$send    = array( 'X-Test-IP: 192.0.2.237', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', 'Accept-Language: en', 'Accept: text/html' );
	if ( $gzip ) {
		$send[] = 'Accept-Encoding: gzip';
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => $send,
			CURLOPT_ENCODING       => $gzip ? 'gzip' : null,
			CURLOPT_TIMEOUT        => 90,
			CURLOPT_HEADERFUNCTION => static function ( $ch, $line ) use ( &$headers ) {
				$parts = explode( ':', $line, 2 );
				if ( 2 === count( $parts ) ) {
					$headers[ strtolower( trim( $parts[0] ) ) ] = trim( $parts[1] );
				}
				return strlen( $line );
			},
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
	curl_close( $ch );
	return array( $code, $body, $headers );
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

/** The local CSS / JS / image addresses of a page (src, href, data-rocket-src, data-lazy-src), unescaped. */
function asset_urls( $html ) {
	$out = array();
	preg_match_all( '#(?:src|href|data-lazy-src|data-rocket-src)=["\']([^"\']+\.(?:css|js|png|svg|jpe?g|webp|woff2?)(?:\?[^"\']*)?)["\']#i', $html, $m );
	foreach ( $m[1] as $url ) {
		$url = html_entity_decode( $url );
		if ( 0 === strpos( $url, 'data:' ) ) {
			continue;
		}
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		if ( '' === $path || ( '' !== $host && wp_parse_url( home_url(), PHP_URL_HOST ) !== $host ) ) {
			continue;
		}
		$out[ $path ] = $url;
	}
	return $out;
}

/** How many asset addresses still carry wp-content or wp-includes. */
function leaks( $html ) {
	$out = array();
	foreach ( asset_urls( $html ) as $path => $url ) {
		if ( false !== strpos( $path, 'wp-content' ) || false !== strpos( $path, 'wp-includes' ) ) {
			$out[] = $path;
		}
	}
	return $out;
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
foreach ( array( PNCP_OPTION, PNCP_Stealth::OPTION, PNCP_Stealth_Status::SEEN, 'pncp_t3127_rocket', 'pncp_t3127_purges' ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}
$mu       = WP_CONTENT_DIR . '/mu-plugins/pncp-t3127-rocket.php';
$png      = wp_upload_dir()['basedir'] . '/pncp-t3127.png';
$made_dir = array();
foreach ( array( 'min', 'background-css', 'pncp-t3127-rocket' ) as $d ) {
	$made_dir[ $d ] = ! is_dir( WP_CONTENT_DIR . '/cache/' . $d );
}
$cache_dir_made = ! is_dir( WP_CONTENT_DIR . '/cache' );
register_shutdown_function(
	static function () use ( $saved, $mu, $png, $made_dir, $cache_dir_made ) {
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, PNCP_Stealth::OPTION === $name || PNCP_OPTION === $name );
			}
		}
		delete_transient( PNCP_Stealth_Status::STATUS );
		foreach ( array( $mu, $png ) as $f ) {
			if ( is_file( $f ) ) {
				unlink( $f );
			}
		}
		foreach ( $made_dir as $d => $made ) {
			if ( $made ) {
				rmtree( WP_CONTENT_DIR . '/cache/' . $d );
			}
		}
		if ( $cache_dir_made && is_dir( WP_CONTENT_DIR . '/cache' ) && 2 === count( (array) scandir( WP_CONTENT_DIR . '/cache' ) ) ) {
			rmdir( WP_CONTENT_DIR . '/cache' );
		}
	}
);

$standin = <<<'PHP'
<?php
/**
 * Test stand-in written by tests/t_3127_stealth_cache.php (removed after the test). Not WP Rocket's code: the
 * order of its buffers and filters, the names and arguments of the filters and the shapes of its addresses.
 */
if ( ! function_exists( 'rocket_clean_domain' ) ) {
	function rocket_clean_domain() {
		update_option( 'pncp_t3127_purges', (int) get_option( 'pncp_t3127_purges', 0 ) + 1, false );
		$dir = WP_CONTENT_DIR . '/cache/pncp-t3127-rocket';
		if ( is_dir( $dir ) ) {
			foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST ) as $f ) {
				$f->isDir() ? rmdir( $f->getPathname() ) : unlink( $f->getPathname() );
			}
		}
	}
}
if ( 'cli' === PHP_SAPI || ! get_option( 'pncp_t3127_rocket' ) || 'GET' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || false !== strpos( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), '/wp-' ) ) {
	return;
}
// The tests of both buffers: no signed-in user, no query string it does not know (WP Rocket: lang, s, …).
foreach ( array_keys( $_COOKIE ) as $pncp_r_c ) {
	if ( 0 === strpos( $pncp_r_c, 'wordpress_logged_in' ) ) {
		return;
	}
}
if ( array_diff_key( $_GET, array( 'lang' => 1, 's' => 1 ) ) ) {
	header( 'X-Test-Rocket: query-string' );
	return;
}

// "advanced-cache.php": serve the stored page before WordPress, or start the outer buffer that stores it.
$pncp_r_host = preg_replace( '/[^a-z0-9.-]/', '_', strtolower( (string) ( $_SERVER['HTTP_HOST'] ?? '' ) ) );
$pncp_r_file = WP_CONTENT_DIR . '/cache/pncp-t3127-rocket/' . $pncp_r_host . rtrim( (string) strtok( (string) $_SERVER['REQUEST_URI'], '?' ), '/' ) . '/index.html';
if ( false !== strpos( (string) ( $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '' ), 'gzip' ) && is_readable( $pncp_r_file . '_gzip' ) ) {
	header( 'X-Test-Rocket: hit-gzip' );
	header( 'Content-Encoding: gzip' );
	readfile( $pncp_r_file . '_gzip' );
	exit;
}
if ( is_readable( $pncp_r_file ) ) {
	header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s', (int) filemtime( $pncp_r_file ) ) . ' GMT' );
	header( 'X-Test-Rocket: hit' );
	readfile( $pncp_r_file );
	exit;
}
header( 'X-Test-Rocket: miss' );
ob_start(
	static function ( $buffer ) use ( $pncp_r_file ) {
		if ( strlen( $buffer ) <= 255 || 200 !== http_response_code() || false === stripos( $buffer, '</html>' ) ) {
			return $buffer;
		}
		if ( ! is_dir( dirname( $pncp_r_file ) ) ) {
			mkdir( dirname( $pncp_r_file ), 0777, true );
		}
		$stored = $buffer . '<!-- stand-in page cache ' . time() . ' -->';
		file_put_contents( $pncp_r_file . '_temp', $stored );
		rename( $pncp_r_file . '_temp', $pncp_r_file );
		file_put_contents( $pncp_r_file . '_gzip', gzencode( $stored, 6 ) );
		return $buffer . '<!-- stand-in page cache -->';
	}
);

/** The local file of an address on this site ('' otherwise), as WP Rocket maps a URL to a path. */
function pncp_r_path( $url ) {
	$url  = html_entity_decode( $url );
	$host = (string) wp_parse_url( $url, PHP_URL_HOST );
	if ( '' !== $host && $host !== wp_parse_url( home_url(), PHP_URL_HOST ) ) {
		return '';
	}
	$path = (string) wp_parse_url( $url, PHP_URL_PATH );
	$file = ABSPATH . ltrim( $path, '/' );
	return '' !== $path && is_file( $file ) ? $file : '';
}
function pncp_r_put( $file, $content ) {
	if ( ! is_dir( dirname( $file ) ) ) {
		mkdir( dirname( $file ), 0777, true );
	}
	if ( ! is_file( $file ) ) {
		file_put_contents( $file, $content );
	}
	return (int) filemtime( $file );
}
add_action(
	'wp_enqueue_scripts',
	static function () {
		wp_enqueue_style( 'pncp-r-theme', get_stylesheet_directory_uri() . '/style.css', array(), '1' );
		wp_enqueue_style( 'pncp-r-core', includes_url( 'css/dashicons.min.css' ), array(), '1' );
		wp_enqueue_script( 'jquery' );
		wp_enqueue_script( 'pncp-r-plugin', plugins_url( 'scrapelock/assets/js/human.js' ), array(), '1', true );
	}
);
add_action(
	'wp_footer',
	static function () {
		echo '<img class="pncp-r-img" src="' . esc_url( wp_upload_dir()['baseurl'] . '/pncp-t3127.png' ) . '" alt="" width="1" height="1">';
	}
);
// The optimization buffer (template_redirect 2): rocket_buffer.
add_action(
	'template_redirect',
	static function () {
		ob_start(
			static function ( $buffer ) {
				return strlen( $buffer ) <= 255 || false === stripos( $buffer, '</html>' ) ? $buffer : (string) apply_filters( 'rocket_buffer', $buffer );
			}
		);
	},
	2
);
// Minify CSS (16): the copy keeps the original path, rocket_css_url gets the URL and the original URL.
add_filter(
	'rocket_buffer',
	static function ( $html ) {
		return preg_replace_callback(
			'#<link\b[^>]*\bhref=["\']([^"\']+\.css)(\?[^"\']*)?["\'][^>]*>#i',
			static function ( $m ) {
				$file = pncp_r_path( $m[1] );
				if ( '' === $file || false === stripos( $m[0], 'stylesheet' ) ) {
					return $m[0];
				}
				$rel = ltrim( (string) wp_parse_url( $m[1], PHP_URL_PATH ), '/' );
				$ver = pncp_r_put( WP_CONTENT_DIR . '/cache/min/1/' . $rel, '/*min*/' . file_get_contents( $file ) );
				$url = add_query_arg( 'ver', $ver, apply_filters( 'rocket_css_url', content_url( 'cache/min/1/' . $rel ), $m[1] ) );
				return str_replace( '<link', '<link data-minify="1"', str_replace( $m[1] . ( $m[2] ?? '' ), $url, $m[0] ) );
			},
			$html
		);
	},
	16
);
// Combine JS (22): one md5-named file, through rocket_js_url.
add_filter(
	'rocket_buffer',
	static function ( $html ) {
		$parts = array();
		$html  = preg_replace_callback(
			'#<script\b[^>]*\bsrc=["\']([^"\']+)["\'][^>]*></script>#i',
			static function ( $m ) use ( &$parts ) {
				$file = pncp_r_path( $m[1] );
				if ( '' === $file ) {
					return $m[0];
				}
				$parts[] = $file;
				return 1 === count( $parts ) ? '%%PNCP_R_COMBINED%%' : '';
			},
			$html
		);
		$all = '';
		foreach ( $parts as $p ) {
			$all .= file_get_contents( $p ) . ";\n";
		}
		$name = md5( $all ) . '.js';
		$ver  = pncp_r_put( WP_CONTENT_DIR . '/cache/min/1/' . $name, $all );
		$url  = add_query_arg( 'ver', $ver, apply_filters( 'rocket_js_url', content_url( 'cache/min/1/' . $name ), '' ) );
		return str_replace( '%%PNCP_R_COMBINED%%', '<script src="' . esc_url( $url ) . '" data-minify="1"></script>', $html );
	},
	22
);
// Delay JS (26).
add_filter(
	'rocket_buffer',
	static function ( $html ) {
		return preg_replace( '#<script\b([^>]*?)\ssrc=(["\'])([^"\']+)\2([^>]*)></script>#i', '<script type="rocketlazyloadscript"$1 data-rocket-src=$2$3$2$4></script>', $html );
	},
	26
);
// The head items (100000): a preload link for each minified stylesheet.
add_filter(
	'rocket_buffer',
	static function ( $html ) {
		preg_match_all( '#<link data-minify="1"[^>]*\bhref=["\']([^"\']+)["\']#i', $html, $m );
		$links = '';
		foreach ( $m[1] as $u ) {
			$links .= '<link rel="preload" data-rocket-preload as="style" href="' . $u . '">';
		}
		return preg_replace( '#<head>#i', '<head>' . $links, $html, 1 );
	},
	100000
);
// Lazyload background CSS (110000): the stylesheet as it is now (the minified copy) must map to a local file;
// its copy is at cache/background-css/<blog>/<host>/<that path>, the URL through rocket_css_url.
add_filter(
	'rocket_buffer',
	static function ( $html ) {
		return preg_replace_callback(
			'#(<link data-minify="1"[^>]*\bhref=["\'])([^"\']+)(["\'])#i',
			static function ( $m ) {
				$url  = html_entity_decode( $m[2] );
				$file = pncp_r_path( $url );
				if ( '' === $file ) {
					return $m[0];
				}
				$rel = (string) wp_parse_url( home_url(), PHP_URL_HOST ) . (string) wp_parse_url( $url, PHP_URL_PATH );
				pncp_r_put( WP_CONTENT_DIR . '/cache/background-css/1/' . $rel, '/*bg*/' . file_get_contents( $file ) );
				$new = add_query_arg( 'wpr_t', time(), apply_filters( 'rocket_css_url', content_url( 'cache/background-css/1/' . $rel ) ) );
				$q   = (string) wp_parse_url( $url, PHP_URL_QUERY );
				return $m[1] . esc_url( $new . ( '' !== $q ? '&' . $q : '' ) ) . $m[3];
			},
			$html
		);
	},
	110000
);
PHP;
file_put_contents( $mu, $standin );
require_once $mu; // rocket_clean_domain() in this process too (Stealth's purge runs here).
file_put_contents( $png, base64_decode( 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=' ) );
wp_mkdir_p( WP_CONTENT_DIR . '/cache/min' ); // WP Rocket's folder: Stealth sees an optimization plugin.
update_option( 'pncp_t3127_rocket', 1, false );
update_option( 'pncp_t3127_purges', 0, false );
delete_transient( PNCP_Stealth_Status::STATUS );
delete_option( PNCP_Stealth_Status::SEEN );

$clear = static function () {
	rmtree( WP_CONTENT_DIR . '/cache/pncp-t3127-rocket' );
	rmtree( WP_CONTENT_DIR . '/cache/min' );
	rmtree( WP_CONTENT_DIR . '/cache/background-css' );
	wp_mkdir_p( WP_CONTENT_DIR . '/cache/min' );
};
$stored = static function () {
	$host = preg_replace( '/[^a-z0-9.-]/', '_', strtolower( (string) wp_parse_url( $GLOBALS['base'], PHP_URL_HOST ) . ':' . (string) wp_parse_url( $GLOBALS['base'], PHP_URL_PORT ) ) );
	return WP_CONTENT_DIR . '/cache/pncp-t3127-rocket/' . $host . '/index.html';
};
$maps = static function ( $html ) {
	$nginx  = PNCP_Stealth::rules_text( 'nginx' );
	$apache = PNCP_Stealth::rules_text( 'apache' );
	$bad    = array();
	foreach ( asset_urls( $html ) as $p => $u ) {
		foreach ( array( 'nginx' => nginx_apply( $nginx, $p ), 'apache' => apache_apply( $apache, $p ) ) as $server => $real ) {
			if ( ! is_file( ABSPATH . ltrim( $real, '/' ) ) || '.php' === substr( $real, -4 ) ) {
				$bad[] = $server . ' ' . $p . ' → ' . $real;
			}
		}
	}
	return $bad;
};

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
add_filter( 'pncp_stealth_self_test', '__return_true' ); // The real self-test runs through Nginx in t_3126_stealth.
$on = PNCP_Stealth::activate( false );
t( 'C Stealth on, with WP Rocket\'s inner words (wp-content, wp-includes)', true === $on && PNCP_Stealth::active() && in_array( 'wp-content', PNCP_Stealth::state()['words'], true ) && in_array( 'wp-includes', PNCP_Stealth::state()['words'], true ), is_wp_error( $on ) ? $on->get_error_message() : implode( ',', PNCP_Stealth::state()['words'] ) );

/* ---------- C. MISS, stored file, HIT ---------- */

$clear();
list( $code, $miss, $h ) = http( $base . '/' );
t( 'C first request: a MISS, optimized (minified CSS, combined + delayed JS, preload, background CSS)', 200 === $code && 'miss' === ( $h['x-test-rocket'] ?? '' ) && false !== strpos( $miss, '/cache/min/1/' ) && false !== strpos( $miss, 'data-rocket-src=' ) && false !== strpos( $miss, 'data-rocket-preload' ) && false !== strpos( $miss, '/cache/background-css/1/' ), $code . ' ' . ( $h['x-test-rocket'] ?? '-' ) . ' ' . substr( $miss, 0, 200 ) );
t( 'C ... WP Rocket\'s late stage (110000) still found the real minified file: Stealth did not change the addresses earlier', is_dir( WP_CONTENT_DIR . '/cache/background-css/1' ) && false !== strpos( $miss, 'wpr_t=' ) );
t( 'C MISS: 0 wp-content / wp-includes in the asset addresses (' . count( asset_urls( $miss ) ) . ')', count( asset_urls( $miss ) ) >= 6 && ! leaks( $miss ), implode( ' | ', leaks( $miss ) ) );
t( 'C MISS: 0 wp-content / wp-includes in the whole page', 0 === substr_count( $miss, 'wp-content' ) && 0 === substr_count( $miss, 'wp-includes' ), preg_replace( '/.*?(.{80}wp-(?:content|includes).{60}).*/s', '$1', $miss ) );
$file = $stored();
$disk = is_file( $file ) ? (string) file_get_contents( $file ) : '';
$gz   = is_file( $file . '_gzip' ) ? (string) gzdecode( (string) file_get_contents( $file . '_gzip' ) ) : '';
t( 'C the page cache file written in the outer buffer: 0 wp-content / wp-includes (Stealth ran before it was written)', '' !== $disk && ! leaks( $disk ) && 0 === substr_count( $disk, 'wp-content' ) && 0 === substr_count( $disk, 'wp-includes' ) && false !== strpos( $disk, '/cache/min/1/' ), $file . ' ' . implode( ' | ', leaks( $disk ) ) );
t( 'C ... and its _gzip copy', '' !== $gz && $gz === $disk );
$bad = $maps( $miss );
t( 'C every asset address maps back to a real file with the Nginx and the Apache rules (no new rules)', ! $bad, implode( ' | ', $bad ) );
list( $code, $hit, $h ) = http( $base . '/' );
t( 'C second request: a HIT served before WordPress, 0 wp-content / wp-includes', 200 === $code && 'hit' === ( $h['x-test-rocket'] ?? '' ) && $hit === $disk && ! leaks( $hit ) && 0 === substr_count( $hit, 'wp-content' ), ( $h['x-test-rocket'] ?? '-' ) . ' ' . implode( ' | ', leaks( $hit ) ) );
list( $code, $hitz, $h ) = http( $base . '/', true );
t( 'C ... the gzip HIT too', 200 === $code && 'hit-gzip' === ( $h['x-test-rocket'] ?? '' ) && $hitz === $disk, ( $h['x-test-rocket'] ?? '-' ) );

/* ---------- Q. "?nocache=" ---------- */

list( $code, $q, $h ) = http( $base . '/?nocache=' . time() );
t( 'Q "/?nocache=": neither cached nor optimized (WP Rocket\'s query string test), so no cache/min address to compare', 200 === $code && 'query-string' === ( $h['x-test-rocket'] ?? '' ) && false === strpos( $q, '/cache/min/' ) && ! leaks( $q ), ( $h['x-test-rocket'] ?? '-' ) );

/* ---------- O. A page stored before the inner words, Stealth off and on ---------- */

$old_words = static function () {
	return array();
};
add_filter( 'pncp_stealth_optimizers', $old_words );
PNCP_Stealth::activate( false );
remove_filter( 'pncp_stealth_optimizers', $old_words );
$clear();
list( $code, $old ) = http( $base . '/' );
$theme_code         = array_search( get_stylesheet(), PNCP_Stealth::state()['words'], true );
$shape              = '#/assets/[a-z0-9]{6}/cache/min/1/wp-content/themes/' . preg_quote( false !== $theme_code ? $theme_code : get_stylesheet(), '#' ) . '/style\.css\?ver=#';
t( 'O the words of before 3.12.6: the stored page has the live leftover /assets/<alias>/cache/min/1/wp-content/themes/<code>/…', 1 === preg_match( $shape, $old ) && 1 === preg_match( $shape, (string) file_get_contents( $stored() ) ), substr( implode( ' | ', leaks( $old ) ), 0, 300 ) );
$purges = (int) get_option( 'pncp_t3127_purges', 0 );
PNCP_Stealth::activate( false );
t( 'O the new map (with the inner words) empties the page cache', (int) get_option( 'pncp_t3127_purges', 0 ) === $purges + 1 && ! is_file( $stored() ) );
list( , $m1, $h1 ) = http( $base . '/' );
list( , $m2, $h2 ) = http( $base . '/' );
t( 'O ... then MISS and HIT: 0 wp-content / wp-includes', 'miss' === ( $h1['x-test-rocket'] ?? '' ) && 'hit' === ( $h2['x-test-rocket'] ?? '' ) && ! leaks( $m1 ) && ! leaks( $m2 ) && 0 === substr_count( $m2, 'wp-content' ), implode( ' | ', leaks( $m2 ) ) );
$purges = (int) get_option( 'pncp_t3127_purges', 0 );
PNCP_Stealth::deactivate();
list( , $off, $ho ) = http( $base . '/' );
t( 'O Stealth off: the page cache is emptied, the next page has the real addresses (the rules are gone)', (int) get_option( 'pncp_t3127_purges', 0 ) === $purges + 1 && 'miss' === ( $ho['x-test-rocket'] ?? '' ) && false !== strpos( $off, '/wp-content/cache/min/1/wp-content/' ) && 0 === preg_match( '#/assets/[a-z0-9]{6}/#', $off ), ( $ho['x-test-rocket'] ?? '-' ) . ' ' . get_option( 'pncp_t3127_purges' ) . '/' . $purges . ' ' . preg_replace( '/.*?(.{60}cache\/min.{60}).*/s', '$1', $off ) );
PNCP_Stealth::activate( false );
list( , $on1, $hn1 ) = http( $base . '/' );
list( , $on2, $hn2 ) = http( $base . '/' );
t( 'O Stealth on again: emptied again, MISS and HIT clean', (int) get_option( 'pncp_t3127_purges', 0 ) === $purges + 2 && 'miss' === ( $hn1['x-test-rocket'] ?? '' ) && 'hit' === ( $hn2['x-test-rocket'] ?? '' ) && ! leaks( $on1 ) && ! leaks( $on2 ) && 0 === substr_count( $on2, 'wp-content' ) && ! $maps( $on2 ), implode( ' | ', leaks( $on2 ) ) );

/* ---------- N. Real Nginx with a cache in front ---------- */

$nginx_bin = trim( (string) shell_exec( 'command -v nginx 2>/dev/null' ) );
if ( '' === $nginx_bin ) {
	echo "SKIP N real Nginx (nginx not on PATH)\n";
} else {
	$dir  = sys_get_temp_dir() . '/pncp-t3127-nginx-' . getmypid();
	$port = 18000 + ( ( getmypid() + 500 ) % 1000 );
	foreach ( array( $dir, $dir . '/tmp', $dir . '/ext', $dir . '/pcache' ) as $d ) {
		wp_mkdir_p( $d );
	}
	$php_host = (string) wp_parse_url( $base, PHP_URL_HOST ) . ':' . (string) wp_parse_url( $base, PHP_URL_PORT );
	// aaPanel-like: the Stealth rules at the top of server { }, the server-level WordPress rewrite, and a page
	// cache in front of PHP (proxy_cache here, the same store-the-response behaviour as fastcgi_cache).
	$conf = ( function_exists( 'posix_geteuid' ) && 0 === posix_geteuid() ? 'user root; ' : '' ) . 'worker_processes 1; error_log ' . $dir . '/error.log; pid ' . $dir . '/nginx.pid; events { worker_connections 64; }' . "\n"
		. 'http { include /etc/nginx/mime.types; access_log off; client_body_temp_path ' . $dir . '/tmp; proxy_temp_path ' . $dir . '/tmp; fastcgi_temp_path ' . $dir . '/tmp; uwsgi_temp_path ' . $dir . '/tmp; scgi_temp_path ' . $dir . '/tmp;' . "\n"
		. 'proxy_cache_path ' . $dir . '/pcache levels=1:2 keys_zone=t3127:1m inactive=1h;' . "\n"
		. 'server { listen 127.0.0.1:' . $port . '; server_name _; root ' . ABSPATH . '; index index.php;' . "\n"
		. 'include ' . $dir . '/ext/*.conf;' . "\n"
		. 'location = / { proxy_pass http://' . $php_host . '; proxy_set_header Host ' . $php_host . '; proxy_set_header X-Test-IP $http_x_test_ip; proxy_set_header Accept-Encoding ""; proxy_cache t3127; proxy_cache_key $scheme$request_method$host$request_uri; proxy_cache_valid 200 1h; proxy_ignore_headers Cache-Control Expires Set-Cookie Vary; add_header X-Test-Nginx-Cache $upstream_cache_status always; }' . "\n"
		. 'location ~ [^/]\.php(/|$) { proxy_pass http://' . $php_host . '; proxy_set_header Host ' . $php_host . '; }' . "\n"
		. 'if (!-e $request_filename) { rewrite ^.+?(/wp-.*) $1 last; rewrite ^.+?(/.*\.php)$ $1 last; rewrite ^ /index.php last; }' . "\n"
		. 'location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$ { expires 30d; }' . "\n"
		. 'location ~ .*\.(js|css)?$ { expires 12h; }' . "\n"
		. '} }' . "\n";
	file_put_contents( $dir . '/nginx.conf', $conf );
	file_put_contents( $dir . '/ext/z-scrapelock-stealth.conf', PNCP_Stealth::rules_text( 'nginx' ) );
	$run = static function ( $args ) use ( $nginx_bin, $dir ) {
		$out = array();
		$rc  = 0;
		exec( escapeshellarg( $nginx_bin ) . ' ' . $args . ' -e ' . escapeshellarg( $dir . '/error.log' ) . ' -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' 2>&1', $out, $rc );
		return array( $rc, implode( ' ', $out ) );
	};
	$nurl = 'http://127.0.0.1:' . $port;
	$all  = static function ( $html ) use ( $nurl ) {
		$bad = array();
		$n   = 0;
		foreach ( asset_urls( $html ) as $p => $u ) {
			++$n;
			list( $ac, $ab ) = http( $nurl . $p );
			$real            = ABSPATH . ltrim( nginx_apply( PNCP_Stealth::rules_text( 'nginx' ), $p ), '/' );
			if ( 200 !== $ac || ! is_file( $real ) || md5( $ab ) !== md5( (string) file_get_contents( $real ) ) ) {
				$bad[] = $p . ' ' . $ac;
			}
		}
		return array( $n, $bad );
	};
	$empty_nginx_cache = static function () use ( $dir, $run ) {
		$run( '-s quit' );
		usleep( 400000 );
		rmtree( $dir . '/pcache' );
		wp_mkdir_p( $dir . '/pcache' );
		$run( '' );
		usleep( 400000 );
	};
	list( $rc, $msg ) = $run( '-t' );
	t( 'N nginx -t passes (Stealth rules + a page cache in front of PHP)', 0 === $rc, $msg );
	$run( '' );
	usleep( 400000 );
	$clear();
	list( $c1, $p1, $n1 ) = http( $nurl . '/' );
	list( $c2, $p2, $n2 ) = http( $nurl . '/' );
	t( 'N through Nginx: MISS then HIT of its cache, both 0 wp-content / wp-includes', 200 === $c1 && 200 === $c2 && 'MISS' === ( $n1['x-test-nginx-cache'] ?? '' ) && 'HIT' === ( $n2['x-test-nginx-cache'] ?? '' ) && false !== strpos( $p2, '/cache/min/1/' ) && ! leaks( $p1 ) && ! leaks( $p2 ) && 0 === substr_count( $p2, 'wp-content' ) && 0 === substr_count( $p2, 'wp-includes' ), $c1 . ' ' . ( $n1['x-test-nginx-cache'] ?? '-' ) . ' ' . ( $n2['x-test-nginx-cache'] ?? '-' ) . ' ' . implode( ' | ', leaks( $p2 ) ) );
	list( $n, $bad ) = $all( $p2 );
	t( "N every CSS / JS / image address of the cached page answers 200 with the real file through Nginx ($n)", $n >= 6 && ! $bad, implode( ' | ', $bad ) );

	// The live case: the Nginx cache holds a page made with the words of before 3.12.6.
	add_filter( 'pncp_stealth_optimizers', $old_words );
	PNCP_Stealth::activate( false );
	remove_filter( 'pncp_stealth_optimizers', $old_words );
	file_put_contents( $dir . '/ext/z-scrapelock-stealth.conf', PNCP_Stealth::rules_text( 'nginx' ) );
	$empty_nginx_cache();
	$clear();
	http( $nurl . '/' );
	PNCP_Stealth::activate( false ); // The new map: the stand-in's cache is emptied, the Nginx cache is not.
	file_put_contents( $dir . '/ext/z-scrapelock-stealth.conf', PNCP_Stealth::rules_text( 'nginx' ) );
	$run( '-s reload' );
	usleep( 500000 );
	list( , $stale, $ns ) = http( $nurl . '/' );
	list( , $fresh )      = http( $base . '/' );
	t( 'N a page the Nginx cache stored before the new map stays a HIT with the leftover while PHP gives a clean page', 'HIT' === ( $ns['x-test-nginx-cache'] ?? '' ) && 1 === preg_match( $shape, $stale ) && ! leaks( $fresh ) && false !== strpos( $fresh, '/cache/min/1/' ), ( $ns['x-test-nginx-cache'] ?? '-' ) );
	$empty_nginx_cache();
	list( , $p3, $n3 ) = http( $nurl . '/' );
	list( , $p4, $n4 ) = http( $nurl . '/' );
	list( $n, $bad )   = $all( $p4 );
	t( "N the Nginx cache emptied: MISS and HIT clean, every asset 200 ($n)", 'MISS' === ( $n3['x-test-nginx-cache'] ?? '' ) && 'HIT' === ( $n4['x-test-nginx-cache'] ?? '' ) && ! leaks( $p3 ) && ! leaks( $p4 ) && 0 === substr_count( $p4, 'wp-content' ) && $n >= 6 && ! $bad, implode( ' | ', array_merge( leaks( $p4 ), $bad ) ) );
	$run( '-s quit' );
	usleep( 300000 );
	rmtree( $dir );
}

exit( $fails ? 1 : 0 );
