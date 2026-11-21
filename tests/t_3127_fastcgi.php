<?php
/**
 * ScrapeLock 3.12.7 — the Nginx fastcgi cache: found, and only this site's pages deleted from it.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3127_fastcgi.php
 *
 * F. Cache files: Nginx's header (version 5), "\nKEY: …\n", the name is the key's MD5 (or the key's MD5 is in
 *    the header: a Vary variant); anything else (another name, no header, a wrong MD5, a temporary file) is not one.
 * K. Keys: the site's host at the start after the scheme and the method (either order, separators, a port),
 *    never another host that ends with it, a host only in the query string, or a host after other text.
 * P. Purge of the whole site in a fake cache tree under /tmp: only this site's files removed, other hosts' kept,
 *    a file that only looks like one kept, a symbolic link to a file outside not followed (the file kept, the link
 *    kept), a linked folder not entered; the counts; --dry-run (dry) deletes nothing; the cap stops and says so.
 * U. Purge of addresses: the path (and its query strings), not a longer path; with a query, only that one.
 * D. Dangerous folders refused: "/", /tmp, /etc, /var/run, a home folder, WordPress's folders and a folder that
 *    holds them, a relative path, "..", a missing one.
 * N. Discovery: SCRAPELOCK_FASTCGI_CACHE_PATH (several, comma separated), Nginx Helper's constant and its
 *    settings (unlink_files only), the constant first; pncp_purge_page_cache() and Stealth's purge empty the
 *    folder (another PHP process with the constant); without one nothing is read (no command in a web request).
 * X. The Nginx configuration parser on sample "nginx -T" text: includes (globs, relative), comments, quotes, the
 *    zone of this site's server block (in a location, inherited from http { }), wildcards, a variable zone, an
 *    undefined zone, another site's zone never used.
 * R. Real Nginx with fastcgi_cache in a temporary prefix in front of a small FastCGI responder (SKIP without
 *    nginx): MISS, HIT, purge, MISS; another host sharing the zone stays HIT.
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

$tmp = sys_get_temp_dir() . '/pncp-t3127-' . getmypid();
@mkdir( $tmp, 0700, true );
$cleanup = array();
register_shutdown_function(
	static function () use ( $tmp, &$cleanup ) {
		foreach ( $cleanup as $fn ) {
			$fn();
		}
		exec( 'rm -rf ' . escapeshellarg( $tmp ) );
		delete_option( PNCP_Fastcgi_Cache::LAST );
	}
);

$host  = PNCP_Edge::site_hosts()[0];
$other = 'other-site.example';

/** The bytes of an Nginx cache file (64-bit header layout of Nginx 1.9+: KEY at offset 336). */
function cache_bytes( $key, $body = 'cached page', $variant = '' ) {
	$head = pack( 'P', 5 ) . str_repeat( "\0", 40 ) . pack( 'V', 0 ) . pack( 'v', 0 ) . pack( 'v', 0 ) . pack( 'v', 0 );
	$head = str_pad( $head, 316, "\0" ) . ( '' !== $variant ? $variant : str_repeat( "\0", 16 ) );
	$head = str_pad( $head, 336, "\0" );
	return $head . "\nKEY: " . $key . "\n" . "\x01\x06\0\x01\0\x0c\0\0Status: 200 OK\r\nContent-Type: text/html\r\n\r\n" . $body;
}

/** Writes a cache file under $root as Nginx does with levels=1:2; returns its path. */
function cache_file( $root, $key, $name = null, $bytes = null ) {
	$name = null === $name ? md5( $key ) : $name;
	$dir  = $root . '/' . substr( $name, -1 ) . '/' . substr( $name, -3, 2 );
	@mkdir( $dir, 0700, true );
	file_put_contents( $dir . '/' . $name, null === $bytes ? cache_bytes( $key ) : $bytes );
	return $dir . '/' . $name;
}

/** The cache tree of P and U: [root, paths by label]. */
function build_tree( $tmp, $host, $other ) {
	$root = $tmp . '/cache-' . wp_generate_password( 6, false );
	mkdir( $root, 0700, true );
	$f = array(
		'home'   => cache_file( $root, 'httpGET' . $host . '/' ),
		'p'      => cache_file( $root, 'httpsGET' . $host . '/p' ),
		'pq'     => cache_file( $root, 'httpsGET' . $host . '/p?ver=2' ),
		'p2'     => cache_file( $root, 'httpsGET' . $host . '/p2' ),
		'head'   => cache_file( $root, 'httpsHEAD' . $host . '/p' ),
		'o1'     => cache_file( $root, 'httpsGET' . $other . '/' ),
		'o2'     => cache_file( $root, 'httpsGET' . $other . '/p' ),
		'suffix' => cache_file( $root, 'httpsGETnot' . $host . '/p' ),
		'query'  => cache_file( $root, 'httpsGET' . $other . '/?u=' . $host ),
	);
	// Looks like a cache file of this site but is not one (no Nginx header).
	$f['fake'] = cache_file( $root, 'x', md5( 'plain' ), "plain text\nKEY: httpsGET" . $host . "/p\n" );
	// A link to a file outside the tree (a real cache file of this site), and a linked folder outside it.
	$out = $tmp . '/outside-' . basename( $root );
	mkdir( $out . '/z', 0700, true );
	$outside = $out . '/' . md5( 'httpsGET' . $host . '/outside' );
	file_put_contents( $outside, cache_bytes( 'httpsGET' . $host . '/outside' ) );
	$k = md5( 'httpsGET' . $host . '/outside' );
	symlink( $outside, $root . '/' . $k );
	$in = cache_file( $out . '/z', 'httpsGET' . $host . '/in-linked-dir' );
	symlink( $out . '/z', $root . '/linked' );
	$f['outside']    = $outside;
	$f['link']       = $root . '/' . $k;
	$f['linked_dir'] = $in;
	return array( $root, $f );
}

$dirs = static function ( $root ) {
	return array(
		array(
			'path'   => $root,
			'source' => 'test',
		),
	);
};

/* ---------- F. Cache files ---------- */

$key  = 'httpsGET' . $host . '/f';
$good = cache_bytes( $key );
t( 'F a real-format file: its key', $key === PNCP_Fastcgi_Cache::key_of( $good, md5( $key ) ) );
t( 'F another name (not the key\'s MD5): not one', null === PNCP_Fastcgi_Cache::key_of( $good, md5( 'other' ) ) );
t( 'F a Vary variant: the key\'s MD5 in the header', $key === PNCP_Fastcgi_Cache::key_of( cache_bytes( $key, 'x', md5( $key, true ) ), md5( $key . 'gzip' ) ) );
t( 'F no header (text): not one', null === PNCP_Fastcgi_Cache::key_of( str_pad( 'hello', 336, ' ' ) . "\nKEY: " . $key . "\n", md5( $key ) ) );
t( 'F a version that is no small number: not one', null === PNCP_Fastcgi_Cache::key_of( "\xff\xff" . substr( $good, 2 ), md5( $key ) ) );
t( 'F a KEY line that does not end: not one', null === PNCP_Fastcgi_Cache::key_of( substr( $good, 0, 336 ) . "\nKEY: " . $key, md5( $key ) ) );
$tf = cache_file( $tmp . '/f', $key );
t( 'F read_key() of a file', $key === PNCP_Fastcgi_Cache::read_key( $tf ) );
$long = 'httpsGET' . $host . '/' . str_repeat( 'a', 3000 );
t( 'F a key longer than the first 1 KB', $long === PNCP_Fastcgi_Cache::read_key( cache_file( $tmp . '/f', $long ) ) );
file_put_contents( $tmp . '/f/0000000012', $good );
t( 'F a temporary file (numbered name): not one', null === PNCP_Fastcgi_Cache::read_key( $tmp . '/f/0000000012' ) );

/* ---------- K. Keys ---------- */

$h = array( 'example.com' );
$k = static function ( $key ) use ( $h ) {
	$r = PNCP_Fastcgi_Cache::key_host( $key, $h );
	return null === $r ? null : $r[1];
};
t( 'K $scheme$request_method$host$request_uri', '/a?b' === $k( 'httpsGETexample.com/a?b' ) );
t( 'K with :// and a port ($http_host), the host in capitals', '/a' === $k( 'https://Example.COM:8443/a' ) );
t( 'K the method first, separators', '/a' === $k( 'GET|https|example.com|/a' ) && '/a' === $k( 'GET https example.com /a' ) );
t( 'K $host$request_uri alone', '/' === $k( 'example.com/' ) );
t( 'K another host ending with it: no', null === $k( 'httpsGETnotexample.com/a' ) && null === $k( 'httpsGEThttpexample.com/a' ) );
t( 'K a longer host starting with it: no', null === $k( 'httpsGETexample.com.evil.test/a' ) && null === $k( 'httpsGETexample.company/a' ) );
t( 'K the host only in the query string, or after other text: no', null === $k( 'httpsGETother.test/?u=example.com' ) && null === $k( 'mobilehttpsGETexample.com/a' ) );
t( 'K key_matches(): the whole site', PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/x', $h, '/' ) && ! PNCP_Fastcgi_Cache::key_matches( 'httpsGETother.test/x', $h, '/' ) );
t( 'K key_matches(): a site in a folder only its folder', PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/sub/x', $h, '/sub/' ) && PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/sub', $h, '/sub/' ) && ! PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/subway/', $h, '/sub/' ) && ! PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/', $h, '/sub/' ) );
$tg = PNCP_Fastcgi_Cache::targets( array( 'https://example.com/p' ) );
t( 'K an address: the path and its query strings, a cookie part after a separator; not a longer path', PNCP_Fastcgi_Cache::key_matches( 'httpGETexample.com/p', $h, '/', $tg ) && PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/p?x=1', $h, '/', $tg ) && PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/p|c=1', $h, '/', $tg ) && ! PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/p2', $h, '/', $tg ) && ! PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/p/q', $h, '/', $tg ) && ! PNCP_Fastcgi_Cache::key_matches( 'httpsGETother.test/p', $h, '/', $tg ) );
$tq = PNCP_Fastcgi_Cache::targets( array( 'https://example.com/p?x=1' ) );
t( 'K an address with a query: only that one', PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/p?x=1', $h, '/', $tq ) && ! PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/p?x=12', $h, '/', $tq ) && ! PNCP_Fastcgi_Cache::key_matches( 'httpsGETexample.com/p', $h, '/', $tq ) );

/* ---------- P. Purge of the whole site ---------- */

list( $root, $f ) = build_tree( $tmp, $host, $other );
$rows             = PNCP_Fastcgi_Cache::purge( $dirs( $root ), null, array( 'dry' => true ) );
t( 'P dry run: counted, nothing deleted', 1 === count( $rows ) && 5 === $rows[0]['matched'] && 0 === $rows[0]['removed'] && file_exists( $f['p'] ), wp_json_encode( $rows ) );
$rows = PNCP_Fastcgi_Cache::purge( $dirs( $root ) );
$r    = $rows[0];
t( 'P this site\'s pages removed (GET, HEAD, query strings)', ! file_exists( $f['home'] ) && ! file_exists( $f['p'] ) && ! file_exists( $f['pq'] ) && ! file_exists( $f['p2'] ) && ! file_exists( $f['head'] ) );
t( 'P other hosts kept (also one ending with this host, one naming it in the query)', file_exists( $f['o1'] ) && file_exists( $f['o2'] ) && file_exists( $f['suffix'] ) && file_exists( $f['query'] ) );
t( 'P a file that only looks like one kept', file_exists( $f['fake'] ) );
t( 'P a link to a file outside: not followed, the file and the link kept', file_exists( $f['outside'] ) && is_link( $f['link'] ) && file_exists( $f['linked_dir'] ) );
t( 'P the counts', 5 === $r['removed'] && 5 === $r['matched'] && 0 === $r['failed'] && 2 === $r['links'] && 5 === $r['other'] && ! $r['capped'] && '' === $r['error'] && realpath( $root ) === $r['path'], wp_json_encode( $r ) );
t( 'P the folders stay', is_dir( $root ) && is_dir( dirname( $f['p'] ) ) );

list( $root, $f ) = build_tree( $tmp, $host, $other );
$rows             = PNCP_Fastcgi_Cache::purge( $dirs( $root ), null, array( 'limit' => 3 ) );
t( 'P the cap: stops after the limit and says so', $rows[0]['capped'] && 3 === $rows[0]['files'] );
$rows = PNCP_Fastcgi_Cache::purge( array_merge( $dirs( $root ), $dirs( $root . '/' ) ) );
t( 'P the same folder twice: once', 1 === count( $rows ) );

/* ---------- U. Purge of addresses ---------- */

list( $root, $f ) = build_tree( $tmp, $host, $other );
$rows             = PNCP_Fastcgi_Cache::purge( $dirs( $root ), array( 'https://' . $host . '/p' ) );
t( 'U /p: its GET, HEAD and query-string files; not /p2, /, other hosts', ! file_exists( $f['p'] ) && ! file_exists( $f['pq'] ) && ! file_exists( $f['head'] ) && file_exists( $f['p2'] ) && file_exists( $f['home'] ) && file_exists( $f['o2'] ) && 3 === $rows[0]['removed'], wp_json_encode( $rows ) );
PNCP_Fastcgi_Cache::purge( $dirs( $root ), array( 'http://' . $host . '/' ) );
t( 'U /: only the home page (http or https alike)', ! file_exists( $f['home'] ) && file_exists( $f['p2'] ) );

/* ---------- D. Dangerous folders ---------- */

$refused = static function ( $dir ) {
	return is_wp_error( PNCP_Fastcgi_Cache::safe_root( $dir ) );
};
t( 'D "/", /tmp, /etc, /var/run, /usr, /home and a home folder refused', $refused( '/' ) && $refused( '/tmp' ) && $refused( '/tmp/' ) && $refused( '/etc' ) && $refused( '/var/run' ) && $refused( '/usr' ) && $refused( '/home' ) && ( ! is_dir( '/home/' . get_current_user() ) || $refused( '/home/' . get_current_user() ) ) );
t( 'D WordPress\'s folders, and a folder that holds them, refused', $refused( ABSPATH ) && $refused( WP_CONTENT_DIR ) && $refused( dirname( ABSPATH ) ) );
t( 'D a relative path, "..", a missing folder refused', $refused( 'cache' ) && $refused( $tmp . '/../' . basename( $tmp ) ) && $refused( $tmp . '/missing' ) );
t( 'D a cache folder under /tmp allowed', ! $refused( $root ) );
$rows = PNCP_Fastcgi_Cache::purge( $dirs( '/' ) );
t( 'D purge() of "/": an error row, nothing looked at', '' !== $rows[0]['error'] && 0 === $rows[0]['files'] );

/* ---------- N. Discovery ---------- */

$ho = get_option( PNCP_Fastcgi_Cache::HELPER_OPTION, null );
$cleanup[] = static function () use ( $ho ) {
	if ( null === $ho ) {
		delete_option( PNCP_Fastcgi_Cache::HELPER_OPTION );
	} else {
		update_option( PNCP_Fastcgi_Cache::HELPER_OPTION, $ho );
	}
};
delete_option( PNCP_Fastcgi_Cache::HELPER_OPTION );
t( 'N nothing set: no folder, purge_known() does nothing', array() === PNCP_Fastcgi_Cache::known_dirs() && array() === PNCP_Fastcgi_Cache::purge_known() );
update_option( PNCP_Fastcgi_Cache::HELPER_OPTION, array( 'enable_purge' => 1, 'cache_method' => 'enable_fastcgi', 'purge_method' => 'get_request' ) );
t( 'N Nginx Helper purging by request (ngx_cache_purge): no folder', '' === PNCP_Fastcgi_Cache::helper_dir() );
update_option( PNCP_Fastcgi_Cache::HELPER_OPTION, array( 'enable_purge' => 1, 'cache_method' => 'enable_redis', 'purge_method' => 'unlink_files' ) );
t( 'N Nginx Helper with Redis: no folder', '' === PNCP_Fastcgi_Cache::helper_dir() );
update_option( PNCP_Fastcgi_Cache::HELPER_OPTION, array( 'enable_purge' => 1, 'cache_method' => 'enable_fastcgi', 'purge_method' => 'unlink_files' ) );
t( 'N Nginx Helper deleting files: its default folder, only when it exists', ( is_dir( PNCP_Fastcgi_Cache::HELPER_DEFAULT ) ? PNCP_Fastcgi_Cache::HELPER_DEFAULT : '' ) === PNCP_Fastcgi_Cache::helper_dir() );
delete_option( PNCP_Fastcgi_Cache::HELPER_OPTION );
$src = file_get_contents( dirname( __DIR__ ) . '/includes/class-pncp-fastcgi-cache.php' );
t( 'N the cache class runs no command (nginx is read only from WP-CLI)', ! preg_match( '/\b(proc_open|exec|shell_exec|system|passthru|popen)\s*\(/', $src ) );

// Another PHP process with the constants set (as wp-config.php would): discovery and the automatic purges.
$child = $tmp . '/child.php';
file_put_contents(
	$child,
	'<?php
$c = json_decode( $argv[1], true );
foreach ( $c as $name => $value ) { define( $name, $value ); }
define( "WP_USE_THEMES", false );
require ' . var_export( $wp_dir . '/wp-load.php', true ) . ';
$out = array( "dirs" => PNCP_Fastcgi_Cache::known_dirs() );
if ( "purge" === $argv[2] ) { pncp_purge_page_cache(); }
if ( "stealth" === $argv[2] ) { $m = new ReflectionMethod( "PNCP_Stealth", "purge_page_cache" ); $m->setAccessible( true ); $m->invoke( null ); }
$out["last"] = get_option( PNCP_Fastcgi_Cache::LAST );
echo json_encode( $out );
'
);
$run = static function ( $consts, $what = '' ) use ( $child ) {
	exec( 'php ' . escapeshellarg( $child ) . ' ' . escapeshellarg( wp_json_encode( $consts ) ) . ' ' . escapeshellarg( $what ) . ' 2>&1', $o );
	$j = json_decode( (string) end( $o ), true );
	return is_array( $j ) ? $j : array( 'raw' => implode( "\n", $o ) );
};
list( $root, $f ) = build_tree( $tmp, $host, $other );
$root2            = $tmp . '/second';
$f2               = cache_file( $root2, 'httpsGET' . $host . '/second' );
$got              = $run( array( 'SCRAPELOCK_FASTCGI_CACHE_PATH' => $root . ', ' . $root2 ) );
t( 'N SCRAPELOCK_FASTCGI_CACHE_PATH: its folders (comma separated)', isset( $got['dirs'] ) && array( $root, $root2 ) === wp_list_pluck( $got['dirs'], 'path' ) && 'SCRAPELOCK_FASTCGI_CACHE_PATH' === $got['dirs'][0]['source'], wp_json_encode( $got ) );
$got = $run( array( 'RT_WP_NGINX_HELPER_CACHE_PATH' => $root2 ) );
t( 'N Nginx Helper\'s RT_WP_NGINX_HELPER_CACHE_PATH', isset( $got['dirs'] ) && array( $root2 ) === wp_list_pluck( $got['dirs'], 'path' ) && 'Nginx Helper' === $got['dirs'][0]['source'], wp_json_encode( $got ) );
$got = $run( array( 'RT_WP_NGINX_HELPER_CACHE_PATH' => $root2, 'SCRAPELOCK_FASTCGI_CACHE_PATH' => $root ) );
t( 'N the constant first', isset( $got['dirs'] ) && array( $root ) === wp_list_pluck( $got['dirs'], 'path' ) );
$got = $run( array( 'SCRAPELOCK_FASTCGI_CACHE_PATH' => $root ), 'purge' );
t( 'N pncp_purge_page_cache(): this site\'s pages deleted, the others kept, the counts kept', ! file_exists( $f['p'] ) && ! file_exists( $f['home'] ) && file_exists( $f['o1'] ) && file_exists( $f2 ) && isset( $got['last']['rows'][0]['removed'] ) && 5 === $got['last']['rows'][0]['removed'] && 'auto' === $got['last']['how'], wp_json_encode( $got ) );
$got = $run( array( 'RT_WP_NGINX_HELPER_CACHE_PATH' => $root2 ), 'stealth' );
t( 'N Stealth\'s purge (on, off, another map): through pncp_purge_page_cache()', ! file_exists( $f2 ), wp_json_encode( $got ) );
$got = $run( array( 'SCRAPELOCK_FASTCGI_CACHE_PATH' => '/' ), 'purge' );
t( 'N the constant set to "/": refused, nothing deleted', isset( $got['last']['rows'][0]['error'] ) && '' !== $got['last']['rows'][0]['error'] && 0 === $got['last']['rows'][0]['files'], wp_json_encode( $got ) );

/* ---------- X. The Nginx configuration parser ---------- */

$dump = "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
	. "# configuration file /etc/nginx/nginx.conf:\n"
	. "user www;\nevents { worker_connections 1024; }\nhttp {\n"
	. "    # fastcgi_cache_path /wrong keys_zone=site_a:1m;\n"
	. "    fastcgi_cache_path /data/cache/a levels=1:2 keys_zone=site_a:100m inactive=1d;\n"
	. "    fastcgi_cache_path \"/data/cache/b\" levels=1:2 keys_zone=site_b:10m;\n"
	. "    fastcgi_cache_path /data/cache/c keys_zone=site_c:10m;\n"
	. "    include vhost/*.conf;\n"
	. "}\n"
	. "# configuration file /etc/nginx/vhost/a.conf:\n"
	. "server {\n    listen 443 ssl;\n    server_name example.test www.example.test;\n    add_header X-Note \"{ not a block; }\";\n"
	. "    include /etc/nginx/ext/example.test/*.conf;\n"
	. "    location ~ [^/]\\.php(/|$) {\n        fastcgi_cache site_a; # fastcgi_cache site_b;\n        fastcgi_cache_key \"\$scheme\$request_method\$host\$request_uri\";\n    }\n}\n"
	. "# configuration file /etc/nginx/vhost/b.conf:\n"
	. "server { server_name other.test; location / { fastcgi_cache site_b; } }\n"
	. "server { server_name *.wild.test; location / { fastcgi_cache site_c; } }\n"
	. "server { server_name var.test; fastcgi_cache \$zone; }\n"
	. "server { server_name undef.test; fastcgi_cache nowhere; }\n"
	. "# configuration file /etc/nginx/ext/example.test/z.conf:\n"
	. "location /x { fastcgi_cache off; }\n";
$files = PNCP_Fastcgi_Cache::dump_files( $dump );
t( 'X nginx -T output split into its files, the main one first', array( '/etc/nginx/nginx.conf', '/etc/nginx/vhost/a.conf', '/etc/nginx/vhost/b.conf', '/etc/nginx/ext/example.test/z.conf' ) === array_keys( $files ), wp_json_encode( array_keys( $files ) ) );
$tree  = PNCP_Fastcgi_Cache::tree( '/etc/nginx/nginx.conf', $files, '/etc/nginx' );
$found = PNCP_Fastcgi_Cache::find_caches( $tree, array( 'example.test' ) );
t( 'X this site: the zone of its location, its folder and key (comments and quoted braces ignored)', array( array( 'zone' => 'site_a', 'path' => '/data/cache/a', 'key' => '$scheme$request_method$host$request_uri' ) ) === $found['caches'] && 1 === $found['servers'], wp_json_encode( $found ) );
$found = PNCP_Fastcgi_Cache::find_caches( $tree, array( 'other.test' ) );
t( 'X another site: its own zone (a quoted path), never site_a', array( 'site_b' ) === wp_list_pluck( $found['caches'], 'zone' ) && '/data/cache/b' === $found['caches'][0]['path'] );
$found = PNCP_Fastcgi_Cache::find_caches( $tree, array( 'shop.wild.test' ) );
t( 'X server_name *.wild.test', array( 'site_c' ) === wp_list_pluck( $found['caches'], 'zone' ) );
$found = PNCP_Fastcgi_Cache::find_caches( $tree, array( 'unknown.test' ) );
t( 'X a host no server block names: nothing (never guessed)', array() === $found['caches'] && 0 === $found['servers'] );
$found = PNCP_Fastcgi_Cache::find_caches( $tree, array( 'var.test' ) );
t( 'X a variable zone: nothing, a note', array() === $found['caches'] && 1 === count( $found['notes'] ) && false !== strpos( $found['notes'][0], '$zone' ) );
$found = PNCP_Fastcgi_Cache::find_caches( $tree, array( 'undef.test' ) );
t( 'X a zone no fastcgi_cache_path defines: nothing, a note', array() === $found['caches'] && false !== strpos( implode( ' ', $found['notes'] ), 'nowhere' ) );
$http_level = PNCP_Fastcgi_Cache::find_caches( PNCP_Fastcgi_Cache::tree( '', array( '' => "http { fastcgi_cache_path /c/h keys_zone=h:1m; fastcgi_cache h; fastcgi_cache_key \$host\$request_uri; server { server_name example.test; } }" ), '' ), array( 'example.test' ) );
t( 'X fastcgi_cache inherited from http { } (text without file headers)', array( array( 'zone' => 'h', 'path' => '/c/h', 'key' => '$host$request_uri' ) ) === $http_level['caches'], wp_json_encode( $http_level ) );
$loop = PNCP_Fastcgi_Cache::tree( '/a.conf', array( '/a.conf' => 'include /a.conf; x 1;' ), '/' );
t( 'X an include loop ends', is_array( $loop ) );
t( 'X server_name forms', PNCP_Fastcgi_Cache::server_matches( array( '.example.test' ), array( 'example.test' ) ) && PNCP_Fastcgi_Cache::server_matches( array( 'example.*' ), array( 'example.org' ) ) && ! PNCP_Fastcgi_Cache::server_matches( array( '*.example.test' ), array( 'example.test' ) ) && ! PNCP_Fastcgi_Cache::server_matches( array( '~^(?<s>.+)\.test$' ), array( 'example.test' ) ) );

/* ---------- R. Real Nginx ---------- */

$nginx = '';
foreach ( array( '/usr/sbin/nginx', '/usr/local/sbin/nginx' ) as $p ) {
	if ( is_executable( $p ) ) {
		$nginx = $p;
	}
}
if ( '' === $nginx ) {
	exec( 'command -v nginx', $o );
	$nginx = isset( $o[0] ) ? $o[0] : '';
}
if ( '' === $nginx ) {
	echo "note: R skipped without nginx\n";
} else {
	$pre   = $tmp . '/ngx';
	$port  = 20000 + wp_rand( 0, 9000 );
	$fport = $port + 1;
	// Nginx's workers run as another user when this runs as root: they must reach and write these folders.
	chmod( $tmp, 0711 );
	foreach ( array( 'logs', 'cache', 'tmp' ) as $d ) {
		mkdir( $pre . '/' . $d, 0700, true );
		chmod( $pre . '/' . $d, 0777 );
	}
	chmod( $pre, 0711 );
	$params = '';
	foreach ( array( 'REQUEST_METHOD $request_method', 'REQUEST_URI $request_uri', 'QUERY_STRING $query_string', 'HTTP_HOST $host', 'SCRIPT_NAME /index.php' ) as $pv ) {
		$params .= "fastcgi_param $pv; ";
	}
	file_put_contents(
		$pre . '/nginx.conf',
		"worker_processes 1; daemon on; pid $pre/nginx.pid; error_log $pre/logs/error.log;\nevents { worker_connections 64; }\nhttp {\n access_log off;\n"
		. " client_body_temp_path $pre/tmp/1; fastcgi_temp_path $pre/tmp/2; proxy_temp_path $pre/tmp/3; uwsgi_temp_path $pre/tmp/4; scgi_temp_path $pre/tmp/5;\n"
		. " fastcgi_cache_path $pre/cache levels=1:2 keys_zone=zr:1m inactive=1h;\n fastcgi_cache_key \"\$scheme\$request_method\$host\$request_uri\";\n"
		. " server { listen 127.0.0.1:$port; server_name $host;\n  location / { fastcgi_pass 127.0.0.1:$fport; $params fastcgi_cache zr; fastcgi_cache_valid 200 1h; add_header X-Cache \$upstream_cache_status; } }\n"
		. " server { listen 127.0.0.1:$port; server_name $other;\n  location / { fastcgi_pass 127.0.0.1:$fport; $params fastcgi_cache zr; fastcgi_cache_valid 200 1h; add_header X-Cache \$upstream_cache_status; } }\n}\n"
	);
	exec( 'php ' . escapeshellarg( __DIR__ . '/lib/fcgi-stub.php' ) . ' 127.0.0.1:' . $fport . ' > /dev/null 2>&1 & echo $!', $po );
	$stub = isset( $po[0] ) ? (int) $po[0] : 0;
	usleep( 400000 );
	exec( escapeshellarg( $nginx ) . ' -p ' . escapeshellarg( $pre ) . ' -c ' . escapeshellarg( $pre . '/nginx.conf' ) . ' 2>&1', $no, $nrc );
	$cleanup[] = static function () use ( $nginx, $pre, $stub ) {
		exec( escapeshellarg( $nginx ) . ' -p ' . escapeshellarg( $pre ) . ' -c ' . escapeshellarg( $pre . '/nginx.conf' ) . ' -s stop > /dev/null 2>&1' );
		if ( $stub ) {
			posix_kill( $stub, 15 );
		}
	};
	if ( 0 !== $nrc ) {
		echo 'note: R skipped: nginx did not start: ' . implode( ' ', $no ) . "\n";
	} else {
		usleep( 300000 );
		$get = static function ( $h, $path ) use ( $port ) {
			$ch = curl_init( 'http://127.0.0.1:' . $port . $path );
			curl_setopt_array(
				$ch,
				array(
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_HEADER         => true,
					CURLOPT_HTTPHEADER     => array( 'Host: ' . $h ),
					CURLOPT_TIMEOUT        => 10,
				)
			);
			$r = (string) curl_exec( $ch );
			curl_close( $ch );
			preg_match( '/X-Cache: (\w+)/i', $r, $c );
			preg_match( '/serial=(\d+)/', $r, $s );
			return array( isset( $c[1] ) ? $c[1] : '', isset( $s[1] ) ? (int) $s[1] : 0 );
		};
		$a1 = $get( $host, '/r?x=1' );
		$a2 = $get( $host, '/r?x=1' );
		$b1 = $get( $other, '/r?x=1' );
		$b2 = $get( $other, '/r?x=1' );
		$c1 = $get( $host, '/s' );
		$get( $host, '/s' );
		t( 'R real Nginx: MISS, then HIT (the same answer)', 'MISS' === $a1[0] && 'HIT' === $a2[0] && $a1[1] === $a2[1] && 'HIT' === $b2[0], wp_json_encode( array( $a1, $a2, $b1, $b2 ) ) . ' ' . @file_get_contents( $pre . '/logs/error.log' ) );
		$files = array();
		foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $pre . '/cache', FilesystemIterator::SKIP_DOTS ) ) as $file ) {
			$files[] = PNCP_Fastcgi_Cache::read_key( (string) $file );
		}
		sort( $files );
		t( 'R Nginx\'s own cache files are read: their keys', array( 'httpGET' . $host . '/r?x=1', 'httpGET' . $host . '/s', 'httpGET' . $other . '/r?x=1' ) === $files, wp_json_encode( $files ) );
		$rows = PNCP_Fastcgi_Cache::purge( $dirs( $pre . '/cache' ) );
		$a4   = $get( $host, '/r?x=1' );
		$a5   = $get( $host, '/r?x=1' );
		$b3   = $get( $other, '/r?x=1' );
		t( 'R purge of the whole site: MISS (a new answer), then HIT again; the other host still HIT with its old answer', $rows[0]['removed'] >= 1 && 'MISS' === $a4[0] && 'HIT' === $a5[0] && 'HIT' === $b3[0] && $b3[1] === $b1[1], wp_json_encode( array( $rows, $a4, $a5, $b3 ) ) );
	}
}

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
