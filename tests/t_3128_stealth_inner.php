<?php
/**
 * ScrapeLock 3.12.8 — the inner wp-content of WP Rocket's minified addresses with Stealth.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3128_stealth_inner.php
 *
 * Live (3.12.7, the real WP Rocket: minify + combine CSS/JS + delay JS, Nginx): on a fresh page (MISS)
 * /assets/<alias>/cache/min/1/wp-content/themes/<coded theme>/….css?ver=… in href and data-rocket-src: the
 * outer wp-content and the slugs coded, the inner wp-content not, and its code (in the generated Stealth rules)
 * 0 times in the page. The cause: two sources of words. The rules (rules_text(), their fingerprint) are made
 * from build() now; the pages are rewritten with the words stored at the last "Test again" (state['words']).
 * On Nginx a new map (3.12.6's inner words, WP Rocket seen later, a new plugin) only became "pending": rules
 * copied or installed with `wp scrapelock rules install` were "installed and up to date", the pages kept the
 * old words. And an address made by a pass with the old words was never fixed by a later pass (the regex only
 * looks for the real addresses).
 *
 * A. rewrite() of the exact shapes (absolute http / https and protocol-relative, ?ver=, href, data-rocket-src,
 *    JSON-escaped): 0 wp-content, the inner code; twice = once.
 * B. An address already new with the inner word left (the live shape): coded by the next pass, idempotent;
 *    a word three times, a PHP file, another host: unchanged.
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
function http( $url ) {
	$ch      = curl_init( $url );
	$headers = array();
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.238', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', 'Accept-Language: en', 'Accept: text/html' ),
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

/** The local CSS / JS addresses of a page (href, src, data-rocket-src), as paths. */
function asset_paths( $html ) {
	$out = array();
	preg_match_all( '#(?:src|href|data-rocket-src)=["\']([^"\']+\.(?:css|js)(?:\?[^"\']*)?)["\']#i', $html, $m );
	foreach ( $m[1] as $url ) {
		$url  = html_entity_decode( $url );
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		if ( '' !== $path && ( '' === $host || wp_parse_url( home_url(), PHP_URL_HOST ) === $host ) ) {
			$out[ $path ] = $url;
		}
	}
	return array_keys( $out );
}

/** Asset paths that the Nginx or the Apache rules do not map to a real file. */
function unmapped( $html ) {
	$nginx  = PNCP_Stealth::rules_text( 'nginx' );
	$apache = PNCP_Stealth::rules_text( 'apache' );
	$bad    = array();
	foreach ( asset_paths( $html ) as $p ) {
		foreach ( array( 'nginx' => nginx_apply( $nginx, $p ), 'apache' => apache_apply( $apache, $p ) ) as $server => $real ) {
			if ( ! is_file( ABSPATH . ltrim( $real, '/' ) ) || '.php' === substr( $real, -4 ) ) {
				$bad[] = $server . ' ' . $p . ' → ' . $real;
			}
		}
	}
	return $bad;
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

/** Where the leftover is, for the message of a failure. */
function around( $html, $needle = 'wp-content' ) {
	$at = strpos( $html, $needle );
	return false === $at ? '' : substr( $html, max( 0, $at - 90 ), 180 );
}

$saved = array();
foreach ( array( PNCP_OPTION, PNCP_Stealth::OPTION, PNCP_Stealth_Status::SEEN, 'pncp_t3128_mode', 'cron' ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}
$mu        = WP_CONTENT_DIR . '/mu-plugins/pncp-t3128-rocket.php';
$min_made  = ! is_dir( WP_CONTENT_DIR . '/cache/min' );
$copy_made = ! is_dir( WP_CONTENT_DIR . '/cache/min/1/wp-content' );
$root_made = ! is_dir( WP_CONTENT_DIR . '/cache' );
register_shutdown_function(
	static function () use ( $saved, $mu, $min_made, $copy_made, $root_made ) {
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, PNCP_Stealth::OPTION === $name || PNCP_OPTION === $name );
			}
		}
		delete_transient( PNCP_Stealth_Status::STATUS );
		if ( is_file( $mu ) ) {
			unlink( $mu );
		}
		if ( $min_made ) {
			rmtree( WP_CONTENT_DIR . '/cache/min' );
		} elseif ( $copy_made ) {
			rmtree( WP_CONTENT_DIR . '/cache/min/1/wp-content' );
		}
		if ( $root_made && is_dir( WP_CONTENT_DIR . '/cache' ) && 2 === count( (array) scandir( WP_CONTENT_DIR . '/cache' ) ) ) {
			rmdir( WP_CONTENT_DIR . '/cache' );
		}
		if ( class_exists( 'PNCP_Stealth_Debug' ) ) {
			PNCP_Stealth_Debug::clear();
		}
	}
);

$standin = <<<'PHP'
<?php
/**
 * Test stand-in written by tests/t_3128_stealth_inner.php (removed after the test). Not WP Rocket's code: the
 * order of its buffer and filters and the shapes of its addresses (cache/min/<blog>/<original path>?ver=<mtime>,
 * delay JS: type="rocketlazyloadscript" data-rocket-src=…).
 */
$pncp_t_mode = (string) get_option( 'pncp_t3128_mode', '' );
if ( 'cli' === PHP_SAPI || '' === $pncp_t_mode || 'GET' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || false !== strpos( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), '/wp-' ) ) {
	return;
}
if ( get_option( 'pncp_t3128_debug' ) ) {
	add_filter( 'pncp_stealth_debug', '__return_true' );
}
/** The address of a minified copy, absolute, with the scheme given. */
function pncp_t_min( $url, $scheme = '' ) {
	$rel  = ltrim( (string) wp_parse_url( $url, PHP_URL_PATH ), '/' );
	$file = WP_CONTENT_DIR . '/cache/min/1/' . $rel;
	if ( ! is_file( $file ) ) {
		wp_mkdir_p( dirname( $file ) );
		copy( ABSPATH . $rel, $file );
	}
	$min = content_url( 'cache/min/1/' . $rel ) . '?ver=' . filemtime( $file );
	return '' === $scheme ? $min : preg_replace( '#^https?:#', $scheme . ':', $min );
}
$pncp_t_css = get_stylesheet_directory_uri() . '/style.css';
$pncp_t_js  = plugins_url( 'scrapelock/assets/js/human.js' );
if ( 'plain' === $pncp_t_mode ) {
	// No optimization plugin running: the theme prints the minified addresses itself (the plain Stealth buffer).
	add_action(
		'wp_footer',
		static function () use ( $pncp_t_css, $pncp_t_js ) {
			echo '<link rel="stylesheet" href="' . esc_url( pncp_t_min( $pncp_t_css ) ) . '">' . "\n";
			echo '<script type="rocketlazyloadscript" data-rocket-src="' . esc_url( pncp_t_min( $pncp_t_js ) ) . '"></script>' . "\n";
		}
	);
	return;
}
add_action(
	'wp_enqueue_scripts',
	static function () use ( $pncp_t_css, $pncp_t_js ) {
		wp_enqueue_style( 'pncp-t-theme', $pncp_t_css, array(), '1' );
		wp_enqueue_script( 'pncp-t-plugin', $pncp_t_js, array(), '1', true );
	}
);
// The optimization buffer (template_redirect 2): rocket_buffer.
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
// Minify CSS (16) and JS (22): the copy keeps the original path.
foreach ( array( 16 => 'css', 22 => 'js' ) as $pncp_t_prio => $pncp_t_ext ) {
	add_filter(
		'rocket_buffer',
		static function ( $html ) use ( $pncp_t_ext ) {
			return preg_replace_callback(
				'#(\s(?:href|src)=["\'])([^"\']+/wp-content/(?:themes|plugins)/[^"\']+\.' . $pncp_t_ext . ')(?:\?[^"\']*)?(["\'])#i',
				static function ( $m ) {
					return $m[1] . esc_url( pncp_t_min( html_entity_decode( $m[2] ) ) ) . $m[3];
				},
				$html
			);
		},
		$pncp_t_prio
	);
}
// Delay JS (26).
add_filter(
	'rocket_buffer',
	static function ( $html ) {
		return preg_replace( '#<script\b([^>]*?)\ssrc=(["\'])([^"\']+/cache/min/[^"\']+)\2([^>]*)></script>#i', '<script type="rocketlazyloadscript"$1 data-rocket-src=$2$3$2$4></script>', $html );
	},
	26
);
if ( 'late' === $pncp_t_mode ) {
	// A stage after Stealth's rocket_buffer pass (registered later at the same priority): a raw minified address,
	// one with https, and one a pass with the words of before left half-new (outer coded, inner wp-content).
	add_action(
		'template_redirect',
		static function () use ( $pncp_t_css, $pncp_t_js ) {
			add_filter(
				'rocket_buffer',
				static function ( $html ) use ( $pncp_t_css, $pncp_t_js ) {
					$half = (string) get_option( 'pncp_t3128_half', '' );
					$add  = '<link rel="preload" as="style" href="' . esc_url( pncp_t_min( $pncp_t_css, 'https' ) ) . '">'
						. '<script type="rocketlazyloadscript" data-rocket-src="' . esc_url( pncp_t_min( $pncp_t_js ) ) . '"></script>'
						. ( '' !== $half ? '<script type="rocketlazyloadscript" data-rocket-src="' . esc_url( $half ) . '"></script>' : '' );
					return str_replace( '</body>', $add . '</body>', $html );
				},
				PHP_INT_MAX
			);
		},
		PHP_INT_MAX
	);
}
PHP;
file_put_contents( $mu, $standin );
wp_mkdir_p( WP_CONTENT_DIR . '/cache/min' ); // WP Rocket's folder: Stealth sees an optimization plugin.
update_option( 'pncp_t3128_mode', '', false );
delete_option( 'pncp_t3128_debug' );
delete_option( 'pncp_t3128_half' );
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
$nginx = static function () {
	return 'nginx';
};
add_filter( 'pncp_stealth_server', $nginx ); // Rules by hand: no .htaccess written (the live server).
add_filter( 'pncp_stealth_self_test', '__return_true' ); // The real self-test runs through Nginx in t_3126_stealth.
$on = PNCP_Stealth::activate( false );
$st = PNCP_Stealth::state();
t( 'A Stealth on (Nginx), with WP Rocket\'s inner words', true === $on && PNCP_Stealth::active() && 'nginx' === $st['server'] && in_array( 'wp-content', $st['words'], true ), is_wp_error( $on ) ? $on->get_error_message() : implode( ',', $st['words'] ) );

$code    = (string) array_search( 'wp-content', $st['words'], true );
$theme   = get_stylesheet();
$alias   = (string) array_search( 'content', wp_list_pluck( $st['map'], 'kind' ), true );
$host    = (string) wp_parse_url( home_url(), PHP_URL_HOST ) . ( wp_parse_url( home_url(), PHP_URL_PORT ) ? ':' . wp_parse_url( home_url(), PHP_URL_PORT ) : '' );
$css_rel = 'cache/min/1/wp-content/themes/' . $theme . '/style.css';
$js_rel  = 'cache/min/1/wp-content/plugins/scrapelock/assets/js/human.js';

/* ---------- A. rewrite() of the exact shapes ---------- */

$shapes = array(
	'href https'          => '<link rel="stylesheet" href="https://' . $host . '/wp-content/' . $css_rel . '?ver=1795266660">',
	'href http'           => '<link rel="stylesheet" href="http://' . $host . '/wp-content/' . $css_rel . '?ver=1795266660">',
	'data-rocket-src'     => '<script type="rocketlazyloadscript" data-rocket-src="https://' . $host . '/wp-content/' . $js_rel . '?ver=1"></script>',
	'protocol-relative'   => '<link rel="preload" as="style" href="//' . $host . '/wp-content/' . $css_rel . '?ver=1">',
	'root-relative'       => '<script data-rocket-src="/wp-content/' . $js_rel . '?ver=1"></script>',
	'JSON-escaped'        => '{"src":"' . str_replace( '/', '\\/', 'https://' . $host . '/wp-content/' . $js_rel ) . '?ver=1"}',
	'&amp; in the query'  => '<link href="https://' . $host . '/wp-content/' . $css_rel . '?ver=1&amp;x=2" rel="stylesheet">',
);
foreach ( $shapes as $label => $html ) {
	$once  = PNCP_Stealth::rewrite( $html );
	$plain = str_replace( '\\/', '/', $once );
	t( "A $label: 0 wp-content, the inner code, the theme / plugin code", 0 === substr_count( $once, 'wp-content' ) && 1 === substr_count( $plain, '/assets/' . $alias . '/cache/min/1/' . $code . '/' ), $once );
	t( "A $label: a second pass changes nothing", PNCP_Stealth::rewrite( $once ) === $once );
}

/* ---------- B. An address already new with the inner word left ---------- */

$words      = $st['words'];
$theme_code = (string) array_search( $theme, $words, true );
$half_css   = 'https://' . $host . '/assets/' . $alias . '/cache/min/1/wp-content/themes/' . ( '' !== $theme_code ? $theme_code : $theme ) . '/style.css?ver=1795266660';
$half_js    = '/assets/' . $alias . '/cache/min/1/wp-content/plugins/scrapelock/assets/js/human.js?ver=1';
$half       = '<link rel="stylesheet" href="' . $half_css . '">' . "\n" . '<script type="rocketlazyloadscript" data-rocket-src="' . $half_js . '"></script>' . "\n" . '{"u":"' . str_replace( '/', '\\/', $half_css ) . '"}';
$fixed      = PNCP_Stealth::rewrite( $half );
t( 'B the live shape /assets/<alias>/cache/min/1/wp-content/themes/<code>/… (href, data-rocket-src, JSON): the inner word gets its code', 0 === substr_count( $fixed, 'wp-content' ) && 3 === substr_count( str_replace( '\\/', '/', $fixed ), '/cache/min/1/' . $code . '/' ), $fixed );
t( 'B ... the slug of the plugin too, the theme code kept, nothing coded twice', false === strpos( $fixed, '/scrapelock/' ) && ( '' === $theme_code || 2 === substr_count( str_replace( '\\/', '/', $fixed ), '/themes/' . $theme_code . '/' ) ) );
t( 'B ... idempotent', PNCP_Stealth::rewrite( $fixed ) === $fixed );
wp_mkdir_p( dirname( WP_CONTENT_DIR . '/' . $css_rel ) );
wp_mkdir_p( dirname( WP_CONTENT_DIR . '/' . $js_rel ) );
copy( get_stylesheet_directory() . '/style.css', WP_CONTENT_DIR . '/' . $css_rel );
copy( WP_PLUGIN_DIR . '/scrapelock/assets/js/human.js', WP_CONTENT_DIR . '/' . $js_rel );
t( 'B ... and every address maps back to the real file with the Nginx and the Apache rules', ! unmapped( $fixed ), implode( ' | ', unmapped( $fixed ) ) );
$three = '<script data-rocket-src="/assets/' . $alias . '/cache/min/1/wp-content/wp-content/wp-content/x.js"></script>';
t( 'B a word three times stays as it is (the rules turn a code back at most twice)', PNCP_Stealth::rewrite( $three ) === $three );
$other = '<link href="https://other.example/assets/' . $alias . '/cache/min/1/wp-content/x.css"><a href="/assets/' . $alias . '/wp-content/x.php">';
t( 'B another host and a PHP file: unchanged', PNCP_Stealth::rewrite( $other ) === $other, PNCP_Stealth::rewrite( $other ) );
$unknown = '<link href="/assets/abcdef/cache/min/1/wp-content/x.css">';
t( 'B an alias that is not in the map: unchanged', isset( $st['map']['abcdef'] ) || PNCP_Stealth::rewrite( $unknown ) === $unknown );


exit( $fails ? 1 : 0 );
