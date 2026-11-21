<?php
/**
 * ScrapeLock 3.12.8 — "cdn purge" also empties the cache plugins' page caches.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3128_purge.php
 *
 * P. pncp_purge_plugin_caches() with stand-ins for WP Rocket, LiteSpeed Cache, W3 Total Cache, WP Super Cache,
 *    WP Fastest Cache, Nginx Helper, Cache Enabler, SiteGround Optimizer and Autoptimize (a temporary mu-plugin
 *    whose functions and hooks record each call): --all calls each one's "everything" function; addresses call
 *    the per-address ones (and say which cannot); WP Rocket's minified files only with $minify, before the pages;
 *    Autoptimize only with $minify. pncp_purge_page_cache() returns the rows and its callers (settings saved)
 *    still empty WP Rocket.
 * C. WP-CLI (SKIP without WP_CLI): cdn purge --all: one line per cache plugin ("cleaned" / "not active"), then
 *    the fastcgi cache, then the CDN (a fake Bunny API), in that order (output and calls); --no-plugin-cache;
 *    --minify (rocket_clean_minify before rocket_clean_domain; Autoptimize); --minify refused for addresses and
 *    with --no-plugin-cache; addresses; the question names the plugins and nothing runs without an answer; help.
 * T. readme: the plugin caches and --minify.
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

$tmp = sys_get_temp_dir() . '/pncp-t3128-' . getmypid();
@mkdir( $tmp, 0700, true );
$log  = $tmp . '/calls.log';
$mock = WP_CONTENT_DIR . '/mu-plugins/pncp-test-3128-caches.php';
$keep = array();
foreach ( array( PNCP_Edge::CONFIG, PNCP_Bunny::CONFIG, PNCP_Edge::CALLS, PNCP_Bunny::CALLS, PNCP_Fastcgi_Cache::LAST ) as $name ) {
	$keep[ $name ] = get_option( $name, null );
}
register_shutdown_function(
	static function () use ( $tmp, $mock, $keep ) {
		@unlink( $mock );
		delete_option( 'pncp_test_3128' );
		foreach ( $keep as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, false );
			}
		}
		exec( 'rm -rf ' . escapeshellarg( $tmp ) );
	}
);

// The stand-ins, in every process while the option pncp_test_3128 exists. "set": rocket = WP Rocket only,
// all = every cache plugin. "fcgi": SCRAPELOCK_FASTCGI_CACHE_PATH. Each call appends a JSON line to "log".
@mkdir( dirname( $mock ), 0755, true );
file_put_contents(
	$mock,
	<<<'PHP'
<?php
// TESTS ONLY: written and removed by tests/t_3128_purge.php. Stand-ins for cache plugins that record each call.
$pncp_t = get_option( 'pncp_test_3128' );
if ( is_array( $pncp_t ) && ! function_exists( 'pncp_t3128_rec' ) ) {
	$GLOBALS['pncp_t3128_log'] = $pncp_t['log'];
	function pncp_t3128_rec( $what, $arg = null ) {
		file_put_contents( $GLOBALS['pncp_t3128_log'], json_encode( array( $what, $arg ) ) . "\n", FILE_APPEND );
	}
	if ( ! empty( $pncp_t['fcgi'] ) && ! defined( 'SCRAPELOCK_FASTCGI_CACHE_PATH' ) ) {
		define( 'SCRAPELOCK_FASTCGI_CACHE_PATH', $pncp_t['fcgi'] );
	}
	function rocket_clean_domain( $lang = '' ) { pncp_t3128_rec( 'rocket_clean_domain' ); }
	function rocket_clean_files( $urls ) { pncp_t3128_rec( 'rocket_clean_files', (array) $urls ); }
	function rocket_clean_minify( $ext = array( 'js', 'css' ) ) { pncp_t3128_rec( 'rocket_clean_minify' ); }
	function rocket_clean_cache_busting( $ext = array( 'js', 'css' ) ) { pncp_t3128_rec( 'rocket_clean_cache_busting' ); }
	if ( 'all' === $pncp_t['set'] ) {
		add_action( 'litespeed_purge_all', function () { pncp_t3128_rec( 'litespeed_purge_all' ); } );
		add_action( 'litespeed_purge_url', function ( $u ) { pncp_t3128_rec( 'litespeed_purge_url', $u ); } );
		function w3tc_flush_all() { pncp_t3128_rec( 'w3tc_flush_all' ); }
		function w3tc_flush_url( $u ) { pncp_t3128_rec( 'w3tc_flush_url', $u ); }
		function wp_cache_clear_cache( $blog = 0 ) { pncp_t3128_rec( 'wp_cache_clear_cache', $blog ); }
		function wpsc_delete_url_cache( $u ) { pncp_t3128_rec( 'wpsc_delete_url_cache', $u ); }
		function wpfc_clear_all_cache( $min = false ) { pncp_t3128_rec( 'wpfc_clear_all_cache', $min ); }
		add_action( 'rt_nginx_helper_purge_all', function () { pncp_t3128_rec( 'rt_nginx_helper_purge_all' ); } );
		$GLOBALS['nginx_purger'] = new class() {
			public function purge_url( $u, $feed = true ) { pncp_t3128_rec( 'nginx_purge_url', $u ); }
		};
		add_action( 'cache_enabler_clear_complete_cache', function () { pncp_t3128_rec( 'cache_enabler_all' ); } );
		add_action( 'cache_enabler_clear_page_cache_by_url', function ( $u ) { pncp_t3128_rec( 'cache_enabler_url', $u ); } );
		function sg_cachepress_purge_cache( $u = false ) { pncp_t3128_rec( 'sg_cachepress_purge_cache' ); }
		class autoptimizeCache {
			public static function clearall() { pncp_t3128_rec( 'autoptimize_clearall' ); }
		}
	}
	// A fake Bunny purge API (the CDN step).
	add_filter( 'pncp_bunny_api_base', function () { return 'https://bunny-3128.mock.test'; } );
	add_filter( 'pncp_edge_api_base', function () { return 'https://bunny-3128.mock.test'; } );
	add_filter(
		'pre_http_request',
		function ( $pre, $args, $url ) {
			if ( 0 !== strpos( $url, 'https://bunny-3128.mock.test/' ) ) {
				return $pre;
			}
			pncp_t3128_rec( 'cdn', $url );
			return array( 'headers' => array(), 'body' => '{}', 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => null );
		},
		1,
		3
	);
}
PHP
);

/** The calls recorded since the last reset: [ [what, arg], … ]. */
function calls() {
	global $log;
	$out = array();
	foreach ( file_exists( $log ) ? file( $log, FILE_IGNORE_NEW_LINES ) : array() as $line ) {
		$out[] = json_decode( $line, true );
	}
	return $out;
}
/** Only the names of the calls. */
function call_names() {
	return array_map(
		static function ( $c ) {
			return $c[0];
		},
		calls()
	);
}
/** Sets the stand-ins for the next processes and empties the record. */
function stand_ins( $set, $fcgi = '' ) {
	global $log;
	@unlink( $log );
	update_option(
		'pncp_test_3128',
		array(
			'set'  => $set,
			'log'  => $log,
			'fcgi' => $fcgi,
		),
		false
	);
}
/** Position of $needle in $haystack, or PHP_INT_MAX. */
function at( $haystack, $needle ) {
	$p = strpos( $haystack, $needle );
	return false === $p ? PHP_INT_MAX : $p;
}

/* ---------- P. In this process ---------- */

stand_ins( 'all' );
require $mock; // This process loaded WordPress before the mu-plugin existed.
$home = home_url( '/' );

$rows  = pncp_purge_plugin_caches();
$names = call_names();
$by    = array();
foreach ( $rows as $r ) {
	$by[ $r['name'] ] = $r['status'];
}
t( 'P --all: every cache plugin\'s "everything" call, once each', array( 'rocket_clean_domain', 'litespeed_purge_all', 'w3tc_flush_all', 'wp_cache_clear_cache', 'wpfc_clear_all_cache', 'rt_nginx_helper_purge_all', 'cache_enabler_all', 'sg_cachepress_purge_cache' ) === $names, wp_json_encode( $names ) );
t( 'P --all: each reported cleaned, WP Rocket\'s minified files kept, no Autoptimize call', 'cleaned' === $by['WP Rocket'] && 'cleaned' === $by['LiteSpeed Cache'] && 'cleaned' === $by['W3 Total Cache'] && 'cleaned' === $by['WP Super Cache'] && 'cleaned' === $by['WP Fastest Cache'] && 'cleaned' === $by['Nginx Helper'] && 'cleaned' === $by['Cache Enabler'] && 'cleaned' === $by['SiteGround Optimizer'] && 'kept' === $by['WP Rocket minified CSS/JS'] && ! isset( $by['Autoptimize minified CSS/JS'] ), wp_json_encode( $rows ) );
t( 'P WP Super Cache: this site only (0 on a single site)', array( 'wp_cache_clear_cache', is_multisite() ? get_current_blog_id() : 0 ) === wp_list_filter( calls(), array( 0 => 'wp_cache_clear_cache' ) )[3] );

stand_ins( 'all' );
$rows  = pncp_purge_plugin_caches( null, true );
$names = call_names();
t( 'P $minify: WP Rocket\'s minified files and cache-busting copies first, then its pages; Autoptimize last', array_slice( $names, 0, 3 ) === array( 'rocket_clean_minify', 'rocket_clean_cache_busting', 'rocket_clean_domain' ) && 'autoptimize_clearall' === end( $names ) && 'cleaned' === wp_list_filter( $rows, array( 'name' => 'WP Rocket minified CSS/JS' ) )[0]['status'], wp_json_encode( $names ) );

stand_ins( 'all' );
$urls  = array( home_url( '/p/' ), home_url( '/q/' ) );
$rows  = pncp_purge_plugin_caches( $urls );
$calls = calls();
$by    = array();
foreach ( $rows as $r ) {
	$by[ $r['name'] ] = $r['status'];
}
t( 'P addresses: rocket_clean_files( $urls ), and the per-address calls of LiteSpeed, W3TC, WP Super Cache, Nginx Helper, Cache Enabler', array( 'rocket_clean_files', $urls ) === $calls[0] && 2 === count( wp_list_filter( $calls, array( 0 => 'litespeed_purge_url' ) ) ) && 2 === count( wp_list_filter( $calls, array( 0 => 'w3tc_flush_url' ) ) ) && 2 === count( wp_list_filter( $calls, array( 0 => 'wpsc_delete_url_cache' ) ) ) && 2 === count( wp_list_filter( $calls, array( 0 => 'nginx_purge_url' ) ) ) && 2 === count( wp_list_filter( $calls, array( 0 => 'cache_enabler_url' ) ) ), wp_json_encode( $calls ) );
t( 'P addresses: nothing emptied whole (no "everything" call), WP Fastest Cache and SiteGround skipped, no minify row', ! array_intersect( array( 'rocket_clean_domain', 'litespeed_purge_all', 'w3tc_flush_all', 'wp_cache_clear_cache', 'wpfc_clear_all_cache', 'rt_nginx_helper_purge_all', 'cache_enabler_all', 'sg_cachepress_purge_cache' ), call_names() ) && 'skipped' === $by['WP Fastest Cache'] && 'skipped' === $by['SiteGround Optimizer'] && 'cleaned' === $by['WP Rocket'] && ! isset( $by['WP Rocket minified CSS/JS'] ), wp_json_encode( $rows ) );
stand_ins( 'all' );
pncp_purge_plugin_caches( $urls, true );
t( 'P $minify with addresses: never the minified files', ! in_array( 'rocket_clean_minify', call_names(), true ) && ! in_array( 'autoptimize_clearall', call_names(), true ) );

stand_ins( 'all' );
$rows = pncp_purge_page_cache();
t( 'P pncp_purge_page_cache(): returns the rows (the plugins, then the fastcgi cache)', is_array( $rows ) && 'WP Rocket' === $rows[0]['name'] && 'cleaned' === $rows[0]['status'] && 'Nginx fastcgi cache' === end( $rows )['name'] && in_array( 'rocket_clean_domain', call_names(), true ) && ! in_array( 'rocket_clean_minify', call_names(), true ), wp_json_encode( $rows ) );
stand_ins( 'all' );
$opts                   = get_option( PNCP_OPTION );
$opts2                  = is_array( $opts ) ? $opts : array();
$opts2['user_mark_opacity'] = ( isset( $opts2['user_mark_opacity'] ) ? (int) $opts2['user_mark_opacity'] : 0 ) + 1;
$cache_key              = in_array( 'user_mark_opacity', PNCP_Options::cache_keys(), true );
update_option( PNCP_OPTION, $opts2 );
$after_save = call_names();
update_option( PNCP_OPTION, $opts );
t( 'P its callers unchanged: saving a setting cached pages depend on empties WP Rocket and the others', $cache_key && ( in_array( 'rocket_clean_domain', $after_save, true ) && in_array( 'w3tc_flush_all', $after_save, true ) ), wp_json_encode( $after_save ) );

/* ---------- T. readme ---------- */

$readme = (string) file_get_contents( dirname( __DIR__ ) . '/readme.txt' );
t( 'T readme: the plugin caches, --no-plugin-cache and --minify', false !== strpos( $readme, '--no-plugin-cache' ) && false !== strpos( $readme, '--minify' ) && false !== strpos( $readme, 'then the server\'s fastcgi cache, then the CDN' ) );

/* ---------- C. WP-CLI ---------- */

/** Runs "wp scrapelock …" with $env before it: [exit code, output]. */
function cli( $args, $env = '' ) {
	global $wp_cli;
	exec( $env . ' ' . $wp_cli . ' scrapelock ' . $args . ' < /dev/null 2>&1', $out, $rc );
	wp_cache_flush();
	return array( $rc, implode( "\n", $out ) );
}

/** The bytes of an Nginx cache file (as in t_3127_fastcgi). */
function cache_bytes( $key ) {
	$head = pack( 'P', 5 ) . str_repeat( "\0", 40 ) . pack( 'V', 0 ) . pack( 'v', 0 ) . pack( 'v', 0 ) . pack( 'v', 0 );
	$head = str_pad( str_pad( $head, 316, "\0" ) . str_repeat( "\0", 16 ), 336, "\0" );
	return $head . "\nKEY: " . $key . "\n\x01\x06\0\x01\0\x0c\0\0Status: 200 OK\r\nContent-Type: text/html\r\n\r\ncached";
}
/** A cache folder with two pages of this site and one of another; returns [folder, a file of this site]. */
function cache_tree( $root ) {
	$host = PNCP_Edge::site_hosts()[0];
	exec( 'rm -rf ' . escapeshellarg( $root ) );
	$first = '';
	foreach ( array( 'httpsGET' . $host . '/', 'httpsGET' . $host . '/p', 'httpsGETother-3128.example/' ) as $key ) {
		$name = md5( $key );
		$dir  = $root . '/' . substr( $name, -1 ) . '/' . substr( $name, -3, 2 );
		@mkdir( $dir, 0700, true );
		file_put_contents( $dir . '/' . $name, cache_bytes( $key ) );
		$first = '' === $first ? $dir . '/' . $name : $first;
	}
	return array( $root, $first );
}

if ( '' === $wp_cli ) {
	echo "note: C skipped without WP_CLI\n";
} else {
	foreach ( array( PNCP_Edge::CONFIG, PNCP_Bunny::CONFIG ) as $name ) {
		delete_option( $name );
	}
	list( $root, $file ) = cache_tree( $tmp . '/fcgi' );

	// WP Rocket only, the fastcgi folder known, no CDN.
	stand_ins( 'rocket', $root );
	list( $rc, $out ) = cli( 'cdn purge --all --yes' );
	t( 'C --all: "WP Rocket page cache: cleaned", the others "not active", its minified files kept', 0 === $rc && false !== strpos( $out, 'WP Rocket page cache: cleaned' ) && false !== strpos( $out, 'LiteSpeed Cache page cache: not active' ) && false !== strpos( $out, 'W3 Total Cache page cache: not active' ) && false !== strpos( $out, 'WP Super Cache page cache: not active' ) && false !== strpos( $out, 'Nginx Helper page cache: not active' ) && false !== strpos( $out, 'WP Rocket minified CSS/JS: kept (--minify empties them)' ) && array( 'rocket_clean_domain' ) === call_names(), $out . ' ' . wp_json_encode( calls() ) );
	t( 'C --all: the plugin caches before the fastcgi cache (and that emptied), no CDN: a warning', at( $out, 'WP Rocket page cache: cleaned' ) < at( $out, 'Server cache (' ) && false !== strpos( $out, '2 files removed, 1 other files kept' ) && ! file_exists( $file ) && false !== strpos( $out, 'No CDN connection' ), $out );

	// With a CDN: plugin caches, then fastcgi, then the CDN.
	update_option(
		PNCP_Bunny::CONFIG,
		array(
			'zone'  => '4343',
			'token' => 'bunny-3128-key-abcdef0123456789',
		),
		false
	);
	list( $root, $file ) = cache_tree( $tmp . '/fcgi' );
	stand_ins( 'rocket', $root );
	list( $rc, $out ) = cli( 'cdn purge --all --yes' );
	$names            = call_names();
	t( 'C order: plugin page caches → fastcgi → CDN (the output)', 0 === $rc && at( $out, 'WP Rocket page cache: cleaned' ) < at( $out, 'Server cache (' ) && at( $out, 'Server cache (' ) < at( $out, 'Bunny CDN: the whole cache was purged.' ) && PHP_INT_MAX !== at( $out, 'Bunny CDN: the whole cache was purged.' ), $out );
	t( 'C order: WP Rocket emptied before the CDN call (the calls), the fastcgi files gone before', array( 'rocket_clean_domain', 'cdn' ) === $names && ! file_exists( $file ), wp_json_encode( calls() ) );

	stand_ins( 'rocket', $root );
	list( $rc, $out ) = cli( 'cdn purge --all --no-plugin-cache --yes' );
	t( 'C --no-plugin-cache: no cache plugin called or reported, the CDN still purged', 0 === $rc && array( 'cdn' ) === call_names() && false === strpos( $out, 'page cache:' ) && false !== strpos( $out, 'Bunny CDN: the whole cache was purged.' ), $out );

	stand_ins( 'rocket', $root );
	list( $rc, $out ) = cli( 'cdn purge --all --minify --yes' );
	$names            = call_names();
	t( 'C --minify: WP Rocket\'s minified files and cache-busting copies, then its pages, then the CDN', 0 === $rc && array( 'rocket_clean_minify', 'rocket_clean_cache_busting', 'rocket_clean_domain', 'cdn' ) === $names && false !== strpos( $out, 'WP Rocket minified CSS/JS: cleaned' ) && false !== strpos( $out, 'Autoptimize minified CSS/JS: not active' ), $out . ' ' . wp_json_encode( $names ) );
	stand_ins( 'rocket', $root );
	list( $rc, $out ) = cli( 'cdn purge /p --minify' );
	t( 'C --minify with addresses: refused (the CDN would keep the old files), nothing called', 0 !== $rc && false !== strpos( $out, '--minify needs --all' ) && array() === call_names(), $out );
	list( $rc, $out ) = cli( 'cdn purge --all --minify --no-plugin-cache --yes' );
	t( 'C --minify with --no-plugin-cache: refused', 0 !== $rc && array() === call_names(), $out );

	stand_ins( 'all', $root );
	list( $rc, $out ) = cli( 'cdn purge --all --minify --yes' );
	$names            = call_names();
	t( 'C every cache plugin active: each "cleaned", Autoptimize with --minify, all before the CDN', 0 === $rc && false !== strpos( $out, 'LiteSpeed Cache page cache: cleaned' ) && false !== strpos( $out, 'W3 Total Cache page cache: cleaned' ) && false !== strpos( $out, 'WP Super Cache page cache: cleaned' ) && false !== strpos( $out, 'WP Fastest Cache page cache: cleaned' ) && false !== strpos( $out, 'Nginx Helper page cache: cleaned' ) && false !== strpos( $out, 'Cache Enabler page cache: cleaned' ) && false !== strpos( $out, 'SiteGround Optimizer page cache: cleaned' ) && false !== strpos( $out, 'Autoptimize minified CSS/JS: cleaned' ) && 'cdn' === end( $names ) && 1 === count( array_keys( $names, 'cdn', true ) ), $out . ' ' . wp_json_encode( $names ) );

	stand_ins( 'all', $root );
	list( $rc, $out ) = cli( 'cdn purge /p' );
	$calls            = calls();
	t( 'C an address: WP Rocket\'s rocket_clean_files( [that address] ), the per-address calls, then the CDN', 0 === $rc && array( 'rocket_clean_files', array( home_url( '/p' ) ) ) === $calls[0] && false !== strpos( $out, 'WP Rocket page cache: cleaned' ) && false !== strpos( $out, 'WP Fastest Cache page cache: not cleaned (it cannot empty single addresses; use --all)' ) && ! in_array( 'rocket_clean_domain', call_names(), true ) && 'cdn' === end( $calls )[0], $out . ' ' . wp_json_encode( $calls ) );

	stand_ins( 'rocket', $root );
	list( $rc, $out ) = cli( 'cdn purge --all' );
	t( 'C --all without --yes: names the plugin caches it empties first, asks, empties nothing', false !== strpos( $out, 'First the page caches of: WP Rocket.' ) && false !== strpos( $out, 'Purge the whole CDN cache' ) && array() === call_names(), $out );
	list( $rc, $out ) = cli( 'cdn --help' );
	t( 'C cdn --help: --[no-]plugin-cache and --minify', false !== strpos( $out, '--[no-]plugin-cache' ) && false !== strpos( $out, '--minify' ), $out );
	delete_option( PNCP_Bunny::CONFIG );
}

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
