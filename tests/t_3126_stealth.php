<?php
/**
 * ScrapeLock 3.12.6 — Stealth with optimization plugins.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3126_stealth.php
 *
 * On the live site (WP Rocket minify/combine) the minified files kept the original path inside their address:
 * /assets/<alias>/cache/min/1/wp-content/themes/<theme>/…, and Wappalyzer still saw WordPress.
 *
 * O. Which optimization plugins are seen (active plugin, WP Rocket's cache folders, the filter), and the inner
 *    words (wp-content, wp-includes, litespeed) only then: the rules of a site without one stay as they were.
 * W. The rewriting of the URL shapes of WP Rocket (cache/min/<blog>/<path>?ver=, combined <md5>.js,
 *    cache/busting/<blog>/<path>, cache/background-css/<blog>/<host>/<path>), Autoptimize, LiteSpeed Cache and
 *    W3 Total Cache, in tags, preload links, data-lazy-src, srcset, url() and JSON: no wp-content / wp-includes
 *    left, and the Nginx and Apache rules (applied here as the server applies them, PCRE) map each address back
 *    to the real file, also to a file created after the rules (pattern-based). The self-test file has the words.
 * B. The page through the stand-in optimizer (a WP Rocket-like mu-plugin written by this test: optimization
 *    buffer at template_redirect 2 filtering rocket_buffer, the page cache written by an outer buffer started
 *    before the plugins, served before WordPress on the next request): 0 wp-content / wp-includes in the HTML,
 *    also from its page cache, after clearing its cache and regenerating; the late rocket_buffer filter; the
 *    page cache is emptied when Stealth turns on or off.
 * R. Real Nginx (SKIP without nginx on PATH): an aaPanel-like server { } with the server-level WordPress rewrite;
 *    the Stealth rules in the extension include (top of server { }): nginx -t, every CSS/JS/image address of the
 *    page answers 200 with the real file, after clearing the stand-in's cache too; the real self-test passes.
 * A. Real Apache (SKIP without apache2): the Apache rules in <Directory>: the page's files answer 200.
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
require_once ABSPATH . 'wp-admin/includes/screen.php';
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';

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

/** A guest's GET of the test WordPress (php -S); [code, body, headers]. */
function http( $url ) {
	$ch      = curl_init( $url );
	$headers = array();
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.236', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', 'Accept-Language: el', 'Accept: text/html' ),
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

/** The response wp_remote_request() gives. */
function resp( $code, $headers = array(), $body = '' ) {
	return array(
		'headers'  => $headers,
		'body'     => $body,
		'response' => array(
			'code'    => $code,
			'message' => '',
		),
		'cookies'  => array(),
		'filename' => null,
	);
}

/**
 * Applies Stealth's Nginx rules to a path as Nginx does at server level: the rewrites in order (PCRE), "last"
 * stops; returns the new path (or the same one).
 */
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

/** The local CSS / JS / image addresses of a page (src, href, data-lazy-src, srcset), unescaped. */
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
		if ( '' === $path || ( '' !== $host && '127.0.0.1' !== $host && wp_parse_url( home_url(), PHP_URL_HOST ) !== $host ) ) {
			continue;
		}
		$out[ $path ] = $url;
	}
	return $out;
}

$saved        = array();
// The settings first: restoring them turns Stealth on or off (settings_changed()), then its state is put back.
foreach ( array( PNCP_OPTION, PNCP_Stealth::OPTION, 'pncp_test_optimizer', 'pncp_test_optimizer_purges' ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}
$mu       = WP_CONTENT_DIR . '/mu-plugins/pncp-test-optimizer.php';
$lazy_js  = WP_CONTENT_DIR . '/mu-plugins/pncp-test-optimizer-lazyload.js';
$png      = wp_upload_dir()['basedir'] . '/pncp-test-optimizer.png';
$made_dir = array();
foreach ( array( 'min', 'busting', 'background-css', 'pncp-test-page', 'autoptimize', 'minify' ) as $d ) {
	$made_dir[ $d ] = ! is_dir( WP_CONTENT_DIR . '/cache/' . $d );
}
$cache_dir_made = ! is_dir( WP_CONTENT_DIR . '/cache' );
$litespeed_made = ! is_dir( WP_CONTENT_DIR . '/litespeed' );

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

register_shutdown_function(
	static function () use ( $saved, $mu, $lazy_js, $png, $made_dir, $cache_dir_made, $litespeed_made ) {
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, PNCP_Stealth::OPTION === $name || PNCP_OPTION === $name );
			}
		}
		foreach ( array( $mu, $lazy_js, $png ) as $f ) {
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
		if ( $litespeed_made ) {
			rmtree( WP_CONTENT_DIR . '/litespeed' );
		}
	}
);

/* ---------- O. Which optimization plugins are seen ---------- */

foreach ( $made_dir as $d => $made ) {
	if ( $made && 'pncp-test-page' !== $d ) {
		rmtree( WP_CONTENT_DIR . '/cache/' . $d );
	}
}
$have_rocket_dirs = ! $made_dir['min'] || ! $made_dir['busting'] || ! $made_dir['background-css'];
if ( ! $have_rocket_dirs ) {
	t( 'O no optimization plugin: none seen, no inner words', array() === PNCP_Stealth::optimizers() && array() === PNCP_Stealth::cache_words(), implode( ',', PNCP_Stealth::optimizers() ) );
	$plain_rules = PNCP_Stealth::rules_text( 'nginx' );
	t( 'O no optimization plugin: the rules have no code for wp-content / wp-includes (unchanged for other sites)', false === strpos( $plain_rules, '$1wp-content$2' ) && false === strpos( $plain_rules, '$1wp-includes$2' ) );
} else {
	echo "SKIP O none seen (this WordPress has cache folders of WP Rocket)\n";
}
$active_filter = static function ( $plugins ) {
	return array_merge( (array) $plugins, array( 'wp-rocket/wp-rocket.php', 'litespeed-cache/litespeed-cache.php' ) );
};
add_filter( 'option_active_plugins', $active_filter );
$opt = PNCP_Stealth::optimizers();
t( 'O the active WP Rocket and LiteSpeed Cache plugins are seen', in_array( 'wp-rocket', $opt, true ) && in_array( 'litespeed', $opt, true ), implode( ',', $opt ) );
t( 'O their inner words: wp-content, wp-includes and litespeed', array( 'wp-content', 'wp-includes', 'litespeed' ) === PNCP_Stealth::cache_words(), implode( ',', PNCP_Stealth::cache_words() ) );
remove_filter( 'option_active_plugins', $active_filter );
wp_mkdir_p( WP_CONTENT_DIR . '/cache/min' );
t( 'O WP Rocket\'s cache folder wp-content/cache/min alone is enough (a plugin may be renamed)', array( 'wp-rocket' ) === PNCP_Stealth::optimizers() && array( 'wp-content', 'wp-includes' ) === PNCP_Stealth::cache_words(), implode( ',', PNCP_Stealth::optimizers() ) );
$f_opt = static function ( $o ) {
	return array_merge( $o, array( 'autoptimize', 'w3tc' ) );
};
add_filter( 'pncp_stealth_optimizers', $f_opt );
t( 'O the filter pncp_stealth_optimizers adds or removes', array( 'wp-rocket', 'autoptimize', 'w3tc' ) === PNCP_Stealth::optimizers() );
remove_filter( 'pncp_stealth_optimizers', $f_opt );

/* ---------- W. The URL shapes and the rules ---------- */

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
add_filter( 'pncp_stealth_self_test', '__return_true' ); // Until R: the settings changes below test and turn on again.
$on = PNCP_Stealth::activate( false );
t( 'W Stealth on (self-test skipped here; the real one runs through Nginx in R)', true === $on && PNCP_Stealth::active(), is_wp_error( $on ) ? $on->get_error_message() : '' );
$state = PNCP_Stealth::state();
t( 'W the tested words include the inner wp-content and wp-includes', in_array( 'wp-content', $state['words'], true ) && in_array( 'wp-includes', $state['words'], true ), implode( ',', $state['words'] ) );

$c       = content_url();
$i       = includes_url();
$host    = (string) wp_parse_url( home_url(), PHP_URL_HOST );
$theme   = get_stylesheet();
$t_path  = '/' . ltrim( (string) wp_parse_url( get_stylesheet_directory_uri(), PHP_URL_PATH ), '/' );
$c_path  = (string) wp_parse_url( $c, PHP_URL_PATH );
$i_path  = rtrim( (string) wp_parse_url( $i, PHP_URL_PATH ), '/' );
// The files behind the shapes, as the plugins write them (WP Rocket keeps the original path; the others neutral names).
$files = array(
	'rocket_min_theme'   => array( WP_CONTENT_DIR . '/cache/min/1' . $t_path . '/style.css', $c . '/cache/min/1' . $t_path . '/style.css?ver=1763700000' ),
	'rocket_min_include' => array( WP_CONTENT_DIR . '/cache/min/1' . $i_path . '/js/jquery/jquery-migrate.min.js', $c . '/cache/min/1' . $i_path . '/js/jquery/jquery-migrate.min.js?ver=1763700000' ),
	'rocket_combined'    => array( WP_CONTENT_DIR . '/cache/min/1/' . md5( 'combined' ) . '.js', $c . '/cache/min/1/' . md5( 'combined' ) . '.js?ver=1763700001' ),
	'rocket_busting'     => array( WP_CONTENT_DIR . '/cache/busting/1' . $c_path . '/plugins/scrapelock/assets/style.css', $c . '/cache/busting/1' . $c_path . '/plugins/scrapelock/assets/style.css' ),
	'rocket_bgcss'       => array( WP_CONTENT_DIR . '/cache/background-css/1/' . $host . $t_path . '/style.css', $c . '/cache/background-css/1/' . $host . $t_path . '/style.css?wpr_t=1763700002' ),
	'autoptimize'        => array( WP_CONTENT_DIR . '/cache/autoptimize/css/autoptimize_' . md5( 'ao' ) . '.css', $c . '/cache/autoptimize/css/autoptimize_' . md5( 'ao' ) . '.css' ),
	'litespeed'          => array( WP_CONTENT_DIR . '/litespeed/css/' . md5( 'ls' ) . '.css', $c . '/litespeed/css/' . md5( 'ls' ) . '.css?ver=a1b2c' ),
	'w3tc'               => array( WP_CONTENT_DIR . '/cache/minify/' . substr( md5( 'w3' ), 0, 5 ) . '.default.include.' . substr( md5( 'w3' ), 5, 6 ) . '.css', $c . '/cache/minify/' . substr( md5( 'w3' ), 0, 5 ) . '.default.include.' . substr( md5( 'w3' ), 5, 6 ) . '.css' ),
);
foreach ( $files as $key => $f ) {
	wp_mkdir_p( dirname( $f[0] ) );
	file_put_contents( $f[0], '/* ' . $key . ' */' );
}
$html  = '<html><head>';
$html .= '<link rel="preload" data-rocket-preload as="style" href="' . $files['rocket_min_theme'][1] . '">';
$html .= '<link rel="stylesheet" id="theme-css" href="' . $files['rocket_min_theme'][1] . '" media="all">';
$html .= "<link rel='stylesheet' href='" . $files['rocket_bgcss'][1] . "'>";
$html .= '<link rel="stylesheet" href="' . $files['autoptimize'][1] . '"><link rel="stylesheet" href="' . $files['litespeed'][1] . '"><link rel="stylesheet" href="' . $files['w3tc'][1] . '">';
$html .= '<style>.a{background:url(' . $files['rocket_busting'][1] . ')}</style></head><body>';
$html .= '<script src="' . $files['rocket_min_include'][1] . '" data-minify="1"></script>';
$html .= '<script type="rocketlazyloadscript" data-rocket-src="' . $files['rocket_combined'][1] . '" defer></script>';
$html .= '<img src="data:image/svg+xml,%3Csvg%3E%3C/svg%3E" data-lazy-src="' . $files['rocket_min_theme'][1] . '" data-lazy-srcset="' . $files['rocket_min_theme'][1] . ' 1x, ' . $files['rocket_bgcss'][1] . ' 2x">';
$html .= '<script>var cfg = ' . wp_json_encode( array( 'u' => $files['rocket_combined'][1] ) ) . ';</script>';
$html .= '</body></html>';
$out = PNCP_Stealth::rewrite( $html );
t( 'W WP Rocket, Autoptimize, LiteSpeed Cache and W3 Total Cache shapes: no wp-content or wp-includes left', false === strpos( $out, 'wp-content' ) && false === strpos( $out, 'wp-includes' ) && false === strpos( $out, 'wp-content', 0 ), preg_replace( '/.*?(.{60}wp-(?:content|includes).{40}).*/s', '$1', $out ) );
t( 'W ... nor the escaped form in JSON', false === strpos( $out, 'wp-content' ) && false !== strpos( $out, '\\/assets\\/' ) );
t( 'W ... the file names keep their shape (cache/min/1/…/style.css?ver=, cache/busting/1/…, background-css/1/<host>/…)', false !== strpos( $out, '/cache/min/1/' ) && false !== strpos( $out, '/cache/busting/1/' ) && false !== strpos( $out, '/cache/background-css/1/' . $host . '/' ) && false !== strpos( $out, 'style.css?ver=1763700000' ) );
t( 'W ... LiteSpeed Cache\'s folder name gets a code only with LiteSpeed Cache (not seen here)', false !== strpos( $out, '/litespeed/css/' ) );
$nginx  = PNCP_Stealth::rules_text( 'nginx' );
$apache = PNCP_Stealth::rules_text( 'apache' );
$bad_n  = array();
$bad_a  = array();
$n      = 0;
foreach ( asset_urls( $out ) as $path => $url ) {
	++$n;
	$real_n = nginx_apply( $nginx, $path );
	$real_a = apache_apply( $apache, $path );
	if ( ! is_file( ABSPATH . ltrim( $real_n, '/' ) ) ) {
		$bad_n[] = $path . ' → ' . $real_n;
	}
	if ( ! is_file( ABSPATH . ltrim( $real_a, '/' ) ) ) {
		$bad_a[] = $path . ' → ' . $real_a;
	}
}
t( "W the Nginx rules map every new address back to the real file ($n)", $n >= 7 && ! $bad_n, implode( ' | ', $bad_n ) );
t( "W the Apache rules map every new address back to the real file ($n)", $n >= 7 && ! $bad_a, implode( ' | ', $bad_a ) );
// A file that the plugin writes after the rules were made (e.g. after "Clear cache"): the same rules serve it.
$later = WP_CONTENT_DIR . '/cache/min/1' . $c_path . '/plugins/scrapelock/assets/js/later-' . wp_generate_password( 6, false, false ) . '.js';
wp_mkdir_p( dirname( $later ) );
file_put_contents( $later, '/* later */' );
$later_url  = $c . substr( $later, strlen( WP_CONTENT_DIR ) ) . '?ver=1';
$later_new  = PNCP_Stealth::rewrite( '<script src="' . $later_url . '"></script>' );
$later_path = (string) wp_parse_url( current( asset_urls( $later_new ) ), PHP_URL_PATH );
t( 'W a minified file created after the rules: no wp-content in its new address, and both rules reach it (no list of files)', false === strpos( $later_new, 'wp-content' ) && realpath( ABSPATH . ltrim( nginx_apply( $nginx, $later_path ), '/' ) ) === realpath( $later ) && realpath( ABSPATH . ltrim( apache_apply( $apache, $later_path ), '/' ) ) === realpath( $later ), $later_new );
t( 'W the rules stay a handful of patterns (two per word), not one line per file', substr_count( $nginx, '$1wp-content$2' ) === 2 && substr_count( $nginx, '$1wp-includes$2' ) === 2 && false === strpos( $nginx, 'later-' ) );
$seen_urls = array();
$cap       = static function ( $pre, $args, $url ) use ( &$seen_urls, $nginx ) {
	$seen_urls[] = $url;
	// Answers as the server with these rules would: the real file the address maps to.
	$real = ABSPATH . ltrim( nginx_apply( $nginx, (string) wp_parse_url( $url, PHP_URL_PATH ) ), '/' );
	return is_file( $real ) && '.php' !== substr( $real, -4 ) ? resp( 200, array(), (string) file_get_contents( $real ) ) : resp( 404 );
};
add_filter( 'pre_http_request', $cap, 10, 3 );
remove_filter( 'pncp_stealth_self_test', '__return_true' );
PNCP_Stealth::self_test( 'assets', PNCP_Stealth::build(), 0 );
add_filter( 'pncp_stealth_self_test', '__return_true' );
remove_filter( 'pre_http_request', $cap, 10 );
$test_url = '';
foreach ( $seen_urls as $u ) {
	if ( false !== strpos( $u, 'check-' ) ) {
		$test_url = $u;
	}
}
$words = array_flip( $state['words'] );
t( 'W the self-test\'s own file carries the inner words as codes (wp-content, wp-includes), so the test proves them', '' !== $test_url && false !== strpos( $test_url, $words['wp-content'] ) && false !== strpos( $test_url, $words['wp-includes'] ) && false === strpos( $test_url, 'wp-content' ), $test_url );

// The late filters of the optimization plugins (their final HTML, before they store it).
$late = PNCP_Stealth::optimized_html( '<link rel="stylesheet" href="' . $files['rocket_min_theme'][1] . '">' );
t( 'W the HTML an optimization plugin gives its last filter is rewritten', false === strpos( $late, 'wp-content' ) && false !== strpos( $late, '/assets/' ) );
$src = (string) file_get_contents( PNCP_DIR . 'includes/class-pncp-stealth.php' );
t( 'W ... hooked at PHP_INT_MAX on rocket_buffer, autoptimize_html_after_minify, litespeed_buffer_after, w3tc_process_content', false !== strpos( $src, "array( 'rocket_buffer', 'autoptimize_html_after_minify', 'litespeed_buffer_after', 'w3tc_process_content' ) as \$hook" ) && false !== strpos( $src, "add_filter( \$hook, array( __CLASS__, 'optimized_html' ), PHP_INT_MAX );" ) );
wp_set_current_user( 1 );
$late_admin = PNCP_Stealth::optimized_html( '<link href="' . $files['rocket_min_theme'][1] . '">' );
wp_set_current_user( 0 );
t( 'W ... never for signed-in users (their pages keep the real addresses)', false !== strpos( $late_admin, 'wp-content' ) );

/* ---------- B. The page through a WP Rocket-like optimizer ---------- */

$standin = <<<'PHP'
<?php
/**
 * Test stand-in written by tests/t_3126_stealth.php (removed after the test): a WP Rocket-like optimizer. Only the
 * URL shapes and the order of the buffers of WP Rocket 3.x are mimicked: minified copies at
 * wp-content/cache/min/<blog>/<original path>?ver=<mtime>, combined scripts at cache/min/<blog>/<md5>.js, dynamic
 * resources at cache/busting/<blog>/<path>, lazy-loaded background CSS at cache/background-css/<blog>/<host>/<path>,
 * preload links, lazyload (data-lazy-src + its script), the page cache: an outer buffer started before the plugins
 * (advanced-cache.php) writes the page, which is then served before WordPress; the optimization buffer starts at
 * template_redirect priority 2 and filters rocket_buffer.
 */
if ( ! function_exists( 'rocket_clean_domain' ) ) {
	function rocket_clean_domain() {
		update_option( 'pncp_test_optimizer_purges', (int) get_option( 'pncp_test_optimizer_purges', 0 ) + 1, false );
		foreach ( glob( WP_CONTENT_DIR . '/cache/pncp-test-page/*.html' ) ?: array() as $f ) {
			unlink( $f );
		}
	}
}
if ( ! get_option( 'pncp_test_optimizer' ) || 'GET' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || false !== strpos( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), 'wp-' ) || isset( $_GET['pncp_st'] ) ) {
	return;
}
foreach ( array_keys( $_COOKIE ) as $pncp_opt_c ) {
	if ( 0 === strpos( $pncp_opt_c, 'wordpress_logged_in' ) ) {
		return;
	}
}
$pncp_opt_page = WP_CONTENT_DIR . '/cache/pncp-test-page/' . md5( (string) $_SERVER['REQUEST_URI'] ) . '.html';
if ( is_readable( $pncp_opt_page ) ) {
	header( 'X-Test-Optimizer: hit' );
	readfile( $pncp_opt_page );
	exit;
}
ob_start(
	static function ( $buffer ) use ( $pncp_opt_page ) {
		if ( false !== stripos( $buffer, '</html>' ) && 200 === http_response_code() ) {
			if ( ! is_dir( dirname( $pncp_opt_page ) ) ) {
				mkdir( dirname( $pncp_opt_page ), 0777, true );
			}
			file_put_contents( $pncp_opt_page, $buffer . '<!-- optimized and cached by the test stand-in -->' );
		}
		return $buffer;
	}
);
function pncp_opt_local( $url ) {
	$url  = html_entity_decode( $url );
	$host = (string) wp_parse_url( $url, PHP_URL_HOST );
	if ( '' !== $host && $host !== wp_parse_url( home_url(), PHP_URL_HOST ) ) {
		return '';
	}
	$path = (string) wp_parse_url( $url, PHP_URL_PATH );
	return is_file( ABSPATH . ltrim( $path, '/' ) ) ? $path : '';
}
function pncp_opt_copy( $from, $to ) {
	if ( ! is_dir( dirname( $to ) ) ) {
		mkdir( dirname( $to ), 0777, true );
	}
	if ( ! is_file( $to ) ) {
		copy( $from, $to );
	}
	return filemtime( $to );
}
add_action(
	'wp_enqueue_scripts',
	static function () {
		wp_enqueue_style( 'pncp-opt-theme', get_stylesheet_directory_uri() . '/style.css', array(), '1' );
		wp_enqueue_script( 'jquery' );
		wp_enqueue_script( 'pncp-opt-plugin', plugins_url( 'scrapelock/assets/js/human.js' ), array(), '1', true );
	}
);
add_action(
	'wp_footer',
	static function () {
		echo '<img class="pncp-opt-img" src="' . esc_url( wp_upload_dir()['baseurl'] . '/pncp-test-optimizer.png' ) . '" alt="" width="1" height="1">';
	}
);
add_action(
	'template_redirect',
	static function () {
		ob_start(
			static function ( $buffer ) {
				return false === stripos( $buffer, '</html>' ) ? $buffer : (string) apply_filters( 'rocket_buffer', $buffer );
			}
		);
	},
	2
);
add_filter(
	'rocket_buffer',
	static function ( $html ) {
		$c       = content_url();
		$preload = '';
		$html    = preg_replace_callback(
			'#<link\b[^>]*\brel=["\']stylesheet["\'][^>]*>#i',
			static function ( $m ) use ( $c, &$preload ) {
				if ( ! preg_match( '#\bhref=["\']([^"\']+)["\']#', $m[0], $h ) || '' === ( $path = pncp_opt_local( $h[1] ) ) ) {
					return $m[0];
				}
				$ver      = pncp_opt_copy( ABSPATH . ltrim( $path, '/' ), WP_CONTENT_DIR . '/cache/min/1/' . ltrim( $path, '/' ) );
				$url      = $c . '/cache/min/1/' . ltrim( $path, '/' ) . '?ver=' . $ver;
				$preload .= '<link rel="preload" data-rocket-preload as="style" href="' . $url . '">';
				return str_replace( $h[1], $url, $m[0] );
			},
			$html
		);
		// Combine the scripts (jQuery from wp-includes, a plugin's script) into one file.
		$parts = array();
		$html  = preg_replace_callback(
			'#<script\b[^>]*\bsrc=["\']([^"\']+)["\'][^>]*></script>#i',
			static function ( $m ) use ( &$parts ) {
				$path = pncp_opt_local( $m[1] );
				if ( '' === $path || false !== strpos( $m[0], 'data-no-minify' ) ) {
					return $m[0];
				}
				$parts[] = $path;
				return 1 === count( $parts ) ? '%%PNCP_COMBINED%%' : '';
			},
			$html
		);
		$combined = '';
		foreach ( $parts as $p ) {
			$combined .= file_get_contents( ABSPATH . ltrim( $p, '/' ) ) . ";\n";
		}
		$name = md5( $combined ) . '.js';
		if ( ! is_dir( WP_CONTENT_DIR . '/cache/min/1' ) ) {
			mkdir( WP_CONTENT_DIR . '/cache/min/1', 0777, true );
		}
		file_put_contents( WP_CONTENT_DIR . '/cache/min/1/' . $name, $combined );
		$html = str_replace( '%%PNCP_COMBINED%%', '<script src="' . $c . '/cache/min/1/' . $name . '?ver=' . filemtime( WP_CONTENT_DIR . '/cache/min/1/' . $name ) . '" data-minify="1"></script>', $html );
		// A dynamic resource (busting) and a lazy-loaded background CSS file, with the inner path of the original.
		$inc  = '/' . trim( (string) wp_parse_url( includes_url(), PHP_URL_PATH ), '/' );
		pncp_opt_copy( ABSPATH . WPINC . '/js/jquery/jquery-migrate.min.js', WP_CONTENT_DIR . '/cache/busting/1' . $inc . '/js/jquery/jquery-migrate.min.js' );
		$theme = '/' . trim( (string) wp_parse_url( get_stylesheet_directory_uri(), PHP_URL_PATH ), '/' );
		$host  = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$bg    = pncp_opt_copy( get_stylesheet_directory() . '/style.css', WP_CONTENT_DIR . '/cache/background-css/1/' . $host . $theme . '/style.css' );
		$extra = '<script src="' . $c . '/cache/busting/1' . $inc . '/js/jquery/jquery-migrate.min.js"></script>'
			. '<link rel="stylesheet" id="pncp-opt-bg" href="' . $c . '/cache/background-css/1/' . $host . $theme . '/style.css?wpr_t=' . $bg . '">';
		// Lazyload: the images get data-lazy-src, and the lazyload script and its options are added.
		$html = preg_replace( '#<img\b([^>]*?)\ssrc=(["\'])([^"\']+)\2#i', '<img$1 src="data:image/svg+xml,%3Csvg%20xmlns=\'http://www.w3.org/2000/svg\'%20viewBox=\'0%200%201%201\'%3E%3C/svg%3E" data-lazy-src=$2$3$2', $html );
		$lazy = '<script>window.lazyLoadOptions={elements_selector:"img[data-lazy-src]",data_src:"lazy-src"};</script>'
			. '<script data-no-minify="1" async src="' . content_url( 'mu-plugins/pncp-test-optimizer-lazyload.js' ) . '"></script>';
		$html = preg_replace( '#<head>#i', '<head>' . $preload, $html, 1 );
		return str_ireplace( '</body>', $extra . $lazy . '</body>', $html );
	}
);
// Option 2: without Stealth's own page buffer (another order of buffers): only the late rocket_buffer filter is left.
if ( 2 === (int) get_option( 'pncp_test_optimizer' ) ) {
	add_action(
		'wp',
		static function () {
			remove_action( 'template_redirect', array( 'PNCP_Stealth', 'start_buffer' ), -9999 );
		}
	);
}
PHP;
file_put_contents( $mu, $standin );
file_put_contents( $lazy_js, 'document.querySelectorAll("img[data-lazy-src]").forEach(function(i){i.src=i.getAttribute("data-lazy-src");});' );
file_put_contents( $png, base64_decode( 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=' ) );
update_option( 'pncp_test_optimizer', 1, false );
update_option( 'pncp_test_optimizer_purges', 0, false );
rmtree( WP_CONTENT_DIR . '/cache/pncp-test-page' );
$clear = static function () {
	rmtree( WP_CONTENT_DIR . '/cache/pncp-test-page' );
	rmtree( WP_CONTENT_DIR . '/cache/min' );
	rmtree( WP_CONTENT_DIR . '/cache/busting' );
	rmtree( WP_CONTENT_DIR . '/cache/background-css' );
	wp_mkdir_p( WP_CONTENT_DIR . '/cache/min' ); // WP Rocket keeps its cache folder.
};
$clear();
list( $code, $page, $hdr ) = http( $base . '/' );
$assets                    = asset_urls( $page );
t( 'B the stand-in optimized the page: minified CSS, combined JS, busting, background CSS, preload, lazyload', 200 === $code && false !== strpos( $page, '/cache/min/1/' ) && false !== strpos( $page, '/cache/busting/1/' ) && false !== strpos( $page, '/cache/background-css/1/' ) && false !== strpos( $page, 'data-rocket-preload' ) && false !== strpos( $page, 'data-lazy-src=' ) && false !== strpos( $page, 'lazyLoadOptions' ), $code . ' ' . substr( $page, 0, 300 ) );
t( 'B with Stealth: 0 wp-content in the home page HTML', 0 === substr_count( $page, 'wp-content' ), preg_replace( '/.*?(.{80}wp-content.{60}).*/s', '$1', $page ) );
t( 'B with Stealth: 0 wp-includes in the home page HTML', 0 === substr_count( $page, 'wp-includes' ), preg_replace( '/.*?(.{80}wp-includes.{60}).*/s', '$1', $page ) );
$bad = array();
foreach ( $assets as $p => $u ) {
	$real = nginx_apply( $nginx, $p );
	if ( ! is_file( ABSPATH . ltrim( $real, '/' ) ) ) {
		$bad[] = $p . ' → ' . $real;
	}
}
t( 'B every CSS / JS / image address of the page maps back to a file (' . count( $assets ) . ')', count( $assets ) >= 5 && ! $bad, implode( ' | ', $bad ) );
list( $code2, $page2, $hdr2 ) = http( $base . '/' );
t( 'B the page from the stand-in\'s page cache (served before WordPress): still 0 wp-content / wp-includes', 'hit' === ( $hdr2['x-test-optimizer'] ?? '' ) && 0 === substr_count( $page2, 'wp-content' ) && 0 === substr_count( $page2, 'wp-includes' ) && false !== strpos( $page2, 'cached by the test stand-in' ) );
$clear();
list( $code3, $page3 ) = http( $base . '/' );
$assets3               = asset_urls( $page3 );
$bad                   = array();
foreach ( $assets3 as $p => $u ) {
	if ( ! is_file( ABSPATH . ltrim( nginx_apply( $nginx, $p ), '/' ) ) ) {
		$bad[] = $p;
	}
}
t( 'B "Clear cache", then the page again: new files, the same rules serve them, 0 wp-content / wp-includes', 200 === $code3 && 0 === substr_count( $page3, 'wp-content' ) && 0 === substr_count( $page3, 'wp-includes' ) && count( $assets3 ) >= 5 && ! $bad, implode( ' | ', $bad ) );
update_option( 'pncp_test_optimizer', 2, false );
$clear();
list( $code4, $page4 ) = http( $base . '/' );
t( 'B without Stealth\'s own page buffer (another order): the late rocket_buffer filter alone hides them', 200 === $code4 && false !== strpos( $page4, '/cache/min/1/' ) && 0 === substr_count( $page4, 'wp-content' ) && false !== strpos( $page4, '/assets/' ), preg_replace( '/.*?(.{80}wp-content.{60}).*/s', '$1', $page4 ) );
update_option( 'pncp_test_optimizer', 1, false );
$clear();
$purges = (int) get_option( 'pncp_test_optimizer_purges', 0 );
require_once $mu; // rocket_clean_domain() of the stand-in, in this process too.
PNCP_Stealth::deactivate();
$off_purges = (int) get_option( 'pncp_test_optimizer_purges', 0 );
PNCP_Stealth::activate( false );
t( 'B the page cache is emptied when Stealth turns off and on (no stored page with addresses the rules no longer serve)', $off_purges === $purges + 1 && (int) get_option( 'pncp_test_optimizer_purges', 0 ) === $purges + 2, $purges . ' ' . $off_purges . ' ' . get_option( 'pncp_test_optimizer_purges' ) );
wp_set_current_user( 1 );
$member = PNCP_Stealth::optimized_html( '<a href="' . content_url( 'x.css' ) . '">' );
wp_set_current_user( 0 );
t( 'B signed-in users: their pages keep the real addresses (not rewritten, not mixed into the guests\' cache)', false !== strpos( $member, 'wp-content' ) );

/* ---------- R. Real Nginx ---------- */

$nginx_bin = trim( (string) shell_exec( 'command -v nginx 2>/dev/null' ) );
if ( '' === $nginx_bin ) {
	echo "SKIP R real Nginx (nginx not on PATH)\n";
} else {
	$dir  = sys_get_temp_dir() . '/pncp-t3126-nginx-' . getmypid();
	$port = 18000 + ( getmypid() % 1000 );
	foreach ( array( $dir, $dir . '/tmp', $dir . '/ext' ) as $d ) {
		wp_mkdir_p( $d );
	}
	$php_host = (string) wp_parse_url( $base, PHP_URL_HOST ) . ':' . (string) wp_parse_url( $base, PHP_URL_PORT );
	/**
	 * An aaPanel-like nginx.conf: the extension include at the top of server { }, the PHP location, the
	 * server-level WordPress rewrite (aaPanel), location ~ \.well-known and the static locations. $below puts
	 * the Stealth rules after the rewrite instead.
	 */
	$write = static function ( $below = false ) use ( $dir, $port, $php_host ) {
		$ext  = 'include ' . $dir . '/ext/*.conf;';
		$conf = ( function_exists( 'posix_geteuid' ) && 0 === posix_geteuid() ? 'user root; ' : '' ) . 'worker_processes 1; error_log ' . $dir . '/error.log; pid ' . $dir . '/nginx.pid; events { worker_connections 64; }' . "\n"
			. 'http { include /etc/nginx/mime.types; access_log off; client_body_temp_path ' . $dir . '/tmp; proxy_temp_path ' . $dir . '/tmp; fastcgi_temp_path ' . $dir . '/tmp; uwsgi_temp_path ' . $dir . '/tmp; scgi_temp_path ' . $dir . '/tmp;' . "\n"
			. 'server { listen 127.0.0.1:' . $port . '; server_name _; root ' . ABSPATH . '; index index.php;' . "\n"
			. ( $below ? '' : $ext . "\n" )
			. 'location ~ [^/]\.php(/|$) { proxy_pass http://' . $php_host . '; proxy_set_header Host ' . $php_host . '; proxy_set_header X-Test-IP 127.0.0.1; }' . "\n"
			. 'if (!-e $request_filename) { rewrite ^.+?(/wp-.*) $1 last; rewrite ^.+?(/.*\.php)$ $1 last; rewrite ^ /index.php last; }' . "\n"
			. ( $below ? $ext . "\n" : '' )
			. 'location ~ \.well-known { allow all; }' . "\n"
			. 'location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$ { expires 30d; }' . "\n"
			. 'location ~ .*\.(js|css)?$ { expires 12h; }' . "\n"
			. '} }' . "\n";
		file_put_contents( $dir . '/nginx.conf', $conf );
	};
	$run   = static function ( $args ) use ( $nginx_bin, $dir ) {
		$out = array();
		$rc  = 0;
		exec( escapeshellarg( $nginx_bin ) . ' ' . $args . ' -e ' . escapeshellarg( $dir . '/error.log' ) . ' -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' 2>&1', $out, $rc );
		return array( $rc, implode( ' ', $out ) );
	};
	$get   = static function ( $path ) use ( $port ) {
		$ch = curl_init( 'http://127.0.0.1:' . $port . $path );
		curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_HTTPHEADER => array( 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0', 'X-Test-IP: 192.0.2.236' ) ) );
		$body = (string) curl_exec( $ch );
		$code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
		curl_close( $ch );
		return array( $code, $body );
	};
	file_put_contents( $dir . '/ext/scrapelock.conf', "# part 2 of the ScrapeLock rules would be here\n" );
	file_put_contents( $dir . '/ext/z-scrapelock-stealth.conf', PNCP_Stealth::rules_text( 'nginx' ) );
	$write();
	list( $rc, $msg ) = $run( '-t' );
	t( 'R nginx -t passes with the Stealth rules in the extension folder (z-scrapelock-stealth.conf after scrapelock.conf)', 0 === $rc, $msg );
	list( $rc, $msg ) = $run( '' );
	usleep( 400000 );
	$clear();
	list( $code, $page ) = http( $base . '/' );
	$bad                 = array();
	$n                   = 0;
	foreach ( asset_urls( $page ) as $p => $u ) {
		++$n;
		list( $ac, $ab ) = $get( $p );
		$real            = ABSPATH . ltrim( nginx_apply( $nginx, $p ), '/' );
		if ( 200 !== $ac || ! is_file( $real ) || md5( $ab ) !== md5( (string) file_get_contents( $real ) ) ) {
			$bad[] = $p . ' ' . $ac;
		}
	}
	t( "R every CSS / JS / image address of the page answers 200 with the real file through Nginx ($n)", $n >= 5 && ! $bad && 0 === substr_count( $page, 'wp-content' ), implode( ' | ', $bad ) );
	$clear();
	list( $code, $page ) = http( $base . '/' );
	$bad                 = array();
	$n                   = 0;
	foreach ( asset_urls( $page ) as $p => $u ) {
		++$n;
		list( $ac ) = $get( $p );
		if ( 200 !== $ac ) {
			$bad[] = $p . ' ' . $ac;
		}
	}
	t( "R after clearing the stand-in's cache and regenerating: every address still 200 ($n, no copy of the rules)", $n >= 5 && ! $bad, implode( ' | ', $bad ) );
	list( $vc, $vb ) = $get( '/assets/' . array_search( 'includes', wp_list_pluck( PNCP_Stealth::state()['map'], 'kind' ), true ) . '/version.php' );
	t( 'R a PHP file never runs through the new addresses (version.php is not served as PHP)', 200 !== $vc || '' !== trim( $vb ) );
	// The real self-test, with the site's address on this Nginx.
	$server_f = static function () {
		return 'nginx';
	};
	$nurl = 'http://127.0.0.1:' . $port;
	$opt  = static function () use ( $nurl ) {
		return $nurl;
	};
	add_filter( 'option_home', $opt, 99 );
	add_filter( 'option_siteurl', $opt, 99 );
	add_filter( 'pncp_stealth_server', $server_f );
	file_put_contents( $dir . '/ext/z-scrapelock-stealth.conf', PNCP_Stealth::rules_text( 'nginx' ) );
	$run( '-s reload' );
	usleep( 500000 );
	remove_filter( 'pncp_stealth_self_test', '__return_true' );
	$real_test = PNCP_Stealth::self_test( 'assets', PNCP_Stealth::build() );
	add_filter( 'pncp_stealth_self_test', '__return_true' );
	t( 'R the real self-test through Nginx passes (the file with the inner words, the endpoints, no PHP)', true === $real_test, is_wp_error( $real_test ) ? $real_test->get_error_message() : '' );
	remove_filter( 'option_home', $opt, 99 );
	remove_filter( 'option_siteurl', $opt, 99 );
	remove_filter( 'pncp_stealth_server', $server_f );
	$run( '-s quit' );
	usleep( 300000 );
	rmtree( $dir );
}

/* ---------- A. Real Apache ---------- */

$apache_bin = trim( (string) shell_exec( 'command -v apache2 2>/dev/null || command -v httpd 2>/dev/null' ) );
$mods       = '/usr/lib/apache2/modules';
if ( '' === $apache_bin || ! is_file( $mods . '/mod_rewrite.so' ) || ! is_file( $mods . '/mod_headers.so' ) ) {
	echo "SKIP A real Apache (apache2 with mod_rewrite and mod_headers not found)\n";
} else {
	$dir  = sys_get_temp_dir() . '/pncp-t3126-apache-' . getmypid();
	$port = 19000 + ( getmypid() % 1000 );
	wp_mkdir_p( $dir . '/logs' );
	$rules = PNCP_Stealth::rules_text( 'apache' );
	$conf  = 'ServerRoot ' . $dir . "\nListen 127.0.0.1:" . $port . "\nPidFile " . $dir . "/httpd.pid\nErrorLog " . $dir . "/logs/error.log\n"
		. "LoadModule mpm_event_module $mods/mod_mpm_event.so\nLoadModule authz_core_module $mods/mod_authz_core.so\nLoadModule rewrite_module $mods/mod_rewrite.so\n"
		. "LoadModule headers_module $mods/mod_headers.so\nLoadModule mime_module $mods/mod_mime.so\nLoadModule dir_module $mods/mod_dir.so\n"
		. "TypesConfig /etc/mime.types\nServerName localhost\nDocumentRoot " . rtrim( ABSPATH, '/' ) . "\n"
		. '<Directory ' . rtrim( ABSPATH, '/' ) . ">\nRequire all granted\nAllowOverride None\n" . $rules . "</Directory>\n";
	file_put_contents( $dir . '/httpd.conf', $conf );
	$out = array();
	exec( escapeshellarg( $apache_bin ) . ' -t -f ' . escapeshellarg( $dir . '/httpd.conf' ) . ' 2>&1', $out, $rc );
	t( 'A apache2 -t passes with the Stealth rules', 0 === $rc, implode( ' ', $out ) );
	exec( escapeshellarg( $apache_bin ) . ' -k start -f ' . escapeshellarg( $dir . '/httpd.conf' ) . ' 2>&1', $out, $rc );
	usleep( 800000 );
	$clear();
	list( $code, $page ) = http( $base . '/' );
	$bad                 = array();
	$n                   = 0;
	$hdr_fp              = '';
	foreach ( asset_urls( $page ) as $p => $u ) {
		++$n;
		$ch = curl_init( 'http://127.0.0.1:' . $port . $p );
		curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_HEADER => true, CURLOPT_HTTPHEADER => array( 'X-ScrapeLock-Sig: x' ) ) );
		$r  = (string) curl_exec( $ch );
		$ac = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
		curl_close( $ch );
		if ( preg_match( '/^X-ScrapeLock-Stealth: ([0-9a-f]{12})/mi', $r, $hm ) ) {
			$hdr_fp = $hm[1];
		}
		if ( 200 !== $ac ) {
			$bad[] = $p . ' ' . $ac;
		}
	}
	t( "A every CSS / JS / image address of the page answers 200 through Apache ($n)", $n >= 5 && ! $bad, implode( ' | ', $bad ) );
	exec( escapeshellarg( $apache_bin ) . ' -k stop -f ' . escapeshellarg( $dir . '/httpd.conf' ) . ' 2>&1' );
	usleep( 500000 );
	rmtree( $dir );
}

exit( $fails ? 1 : 0 );
