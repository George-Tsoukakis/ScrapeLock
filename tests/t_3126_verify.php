<?php
/**
 * ScrapeLock 3.12.6 — "Verification files" (PNCP_Verify_Files): /builtwith.txt and the like, for every bot.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3126_verify.php
 *
 * On the live site BuiltWith (in the bot list) could not verify the site: the owner had to take it out of the bot
 * list, copy Nginx part 1 again, create /builtwith.txt by hand and purge it at Bunny.
 *
 * V. The path (one name at the root or under /.well-known/, text extensions only, no "..", no PHP-like name, no
 *    wp-* / uploads / robots.txt / the plugin's own addresses) and the content (text, at most 64 KB).
 * H. Over HTTP, with BuiltWith in the bot list: the file for BuiltWith (200, its type, no caching, nosniff, a
 *    sandbox for HTML), HEAD; the rest of the site still 403 for BuiltWith; POST not served; with the early check
 *    and with the pre-cache check on; a file whose time is over is never served.
 * R. The server rules: the Nginx map $pncp_open_path and the Apache conditions have the path, and the fingerprints
 *    do not change; the rules' evaluator lets BuiltWith read it; real Nginx (SKIP without nginx on PATH).
 * E. The end: 1 to 168 hours, the cron event, sweep() removes and purges, at most 10 files.
 * P. Purged at the CDN when added, removed and expired (fake Bunny API).
 * D. The root folder (only when asked): never over an existing file, removed only while unchanged.
 * A. The Server rules card and admin-post: nonce, manage_options; wp scrapelock verify-file add | list | remove.
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
require_once ABSPATH . 'wp-admin/includes/user.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? '  [' . substr( (string) $extra, 0, 400 ) . ']' : '' ) . "\n";
}

const BUILTWITH = 'Mozilla/5.0 (compatible; BuiltWith/1.0; +https://builtwith.com/biup)';
const BROWSER   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const VISITOR   = '198.51.100.161';
const BUNNY_KEY = 'bunny-3126-verify-key-1234567890';

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
}

/** A request with curl: [code, headers (lowercase), body]. */
function req( $path, $ua = BUILTWITH, $method = 'GET', $post = null, $cookie = '' ) {
	global $base;
	$ch   = curl_init( $base . $path );
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_TIMEOUT        => 30,
		CURLOPT_PROXY          => '',
		CURLOPT_CUSTOMREQUEST  => $method,
		CURLOPT_NOBODY         => 'HEAD' === $method,
		CURLOPT_HTTPHEADER     => array( 'User-Agent: ' . $ua, 'X-Forwarded-For: ' . VISITOR, 'Accept-Language: en' ),
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POSTFIELDS ] = http_build_query( $post );
	}
	if ( '' !== $cookie ) {
		$opts[ CURLOPT_COOKIE ] = $cookie;
	}
	curl_setopt_array( $ch, $opts );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	$headers = array();
	foreach ( explode( "\r\n", substr( $out, 0, $hs ) ) as $line ) {
		if ( false !== strpos( $line, ':' ) ) {
			list( $k, $v )                   = explode( ':', $line, 2 );
			$headers[ strtolower( trim( $k ) ) ] = trim( $v );
		}
	}
	wp_cache_flush();
	return array( $code, $headers, (string) substr( $out, $hs ) );
}

$saved_settings = PNCP_Options::stored();
$saved_opts     = array();
foreach ( array( PNCP_Verify_Files::INDEX, PNCP_Verify_Files::DATA, PNCP_Bunny::CONFIG, PNCP_Edge::CONFIG ) as $name ) {
	$saved_opts[ $name ] = get_option( $name, null );
}
$root = sys_get_temp_dir() . '/pncp-t3126-root-' . getmypid();
wp_mkdir_p( $root );
register_shutdown_function(
	static function () use ( $saved_settings, $saved_opts, $root ) {
		PNCP_Verify_Files::remove_all();
		update_option( PNCP_OPTION, $saved_settings );
		PNCP_Options::flush();
		foreach ( $saved_opts as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, false );
			}
		}
		exec( 'rm -rf ' . escapeshellarg( $root ) );
	}
);
add_filter(
	'pncp_site_files_root',
	static function () use ( $root ) {
		return $root . '/';
	}
);
PNCP_Log::unban_all();
PNCP_Verify_Files::remove_all();
delete_option( PNCP_Bunny::CONFIG );
delete_option( PNCP_Edge::CONFIG );
$bots = (string) $saved_settings['bot_list'];
if ( false === stripos( $bots, 'BuiltWith' ) ) {
	$bots .= "\nBuiltWith";
}
settings(
	array(
		'enabled'      => 1,
		'monitor_mode' => 0,
		'block_bots'   => 1,
		'bot_list'     => $bots,
		'early_mode'   => 0,
		'precheck'     => 0,
		// The visitor's address from X-Forwarded-For of the test server itself (else every request is "local").
		'ip_header'       => 'x_forwarded_for',
		'trusted_proxies' => '127.0.0.1',
		'allow_ips'       => '',
	)
);

/* ---------- V. The path and the content ---------- */

foreach ( array( '/builtwith.txt', '/google1234567890abcdef.html', '/BingSiteAuth.xml', '/yandex_0123456789abcdef.html', '/.well-known/apple-app-site-association', '/.well-known/brave-rewards-verification.txt', '/site.json' ) as $good ) {
	t( "V accepted: $good", $good === PNCP_Verify_Files::check_path( $good ) );
}
t( 'V a name without the leading slash: at the root', '/builtwith.txt' === PNCP_Verify_Files::check_path( 'builtwith.txt' ) );
foreach ( array( '', '/', '/../x.txt', '/a/b.txt', '/x..txt', '/x.php', '/x.php.txt', '/x.PHTML', '/x.phar', '/shell.php5', '/wp-config.txt', '/wp-content.txt', '/uploads.txt', '/robots.txt', '/llms.txt', '/.htaccess', '/.env', '/x', '/x.js', '/x.svg', '/.well-known/a/b.txt', '/.well-known/scrapelock-nginx', '/.well-known/tdmrep.json', '/sitemap.xml', '/index.html', '/x%2e%2e.txt', "/x\0.txt", '/a b.txt' ) as $bad ) {
	t( 'V refused: ' . wp_json_encode( $bad ), is_wp_error( PNCP_Verify_Files::check_path( $bad ) ) );
}
t( 'V content: text accepted', 'abc' === PNCP_Verify_Files::check_content( 'abc' ) );
t( 'V content: empty, over 64 KB, a NUL, invalid UTF-8, PHP: refused', is_wp_error( PNCP_Verify_Files::check_content( '  ' ) ) && is_wp_error( PNCP_Verify_Files::check_content( str_repeat( 'a', 65537 ) ) ) && is_wp_error( PNCP_Verify_Files::check_content( "a\0b" ) ) && is_wp_error( PNCP_Verify_Files::check_content( "\xC3\x28" ) ) && is_wp_error( PNCP_Verify_Files::check_content( '<?php echo 1;' ) ) );
foreach ( array( '<?= 1 ?>', '<? echo 1; ?>', '<?PHP echo 1;', 'a <% Response.Write(1) %>', "x\n<?\nphpinfo();" ) as $pncp_code ) {
	t( 'V content: no PHP or ASP opening tag of any kind: ' . wp_json_encode( $pncp_code ), is_wp_error( PNCP_Verify_Files::check_content( $pncp_code ) ) );
}
t( 'V content: the XML declaration and an XML stylesheet line accepted', ! is_wp_error( PNCP_Verify_Files::check_content( '<?xml version="1.0"?><users><user>ABC</user></users>' ) ) && ! is_wp_error( PNCP_Verify_Files::check_content( "<?xml version=\"1.0\"?>\n<?xml-stylesheet type=\"text/xsl\" href=\"a.xsl\"?><a/>" ) ) );
t( 'V content: exactly 64 KB accepted', ! is_wp_error( PNCP_Verify_Files::check_content( str_repeat( 'a', 65536 ) ) ) );
t( 'V hours: 0 and 169 refused', is_wp_error( PNCP_Verify_Files::add( '/a.txt', 'x', 0 ) ) && is_wp_error( PNCP_Verify_Files::add( '/a.txt', 'x', 169 ) ) && ! PNCP_Verify_Files::all() );

/* ---------- R. The server rules (before any HTTP) ---------- */

$fp_n = PNCP_Rules::nginx_fingerprint();
$fp_a = PNCP_Rules::apache_fingerprint();
$req  = static function ( $path ) {
	return array(
		'ua'      => BUILTWITH,
		'path'    => $path,
		'https'   => true,
		'method'  => 'GET',
		'remote'  => VISITOR,
		'headers' => array(),
	);
};
t( 'R before: BuiltWith is blocked by the rules at /builtwith.txt', null !== PNCP_Rules::evaluate( $req( '/builtwith.txt' ) ) );
$added = PNCP_Verify_Files::add( '/builtwith.txt', "builtwith-verify=3126abc\n", 24 );
t( 'R add(): the address, the time, nothing written to disk', is_array( $added ) && home_url( '/builtwith.txt' ) === $added['url'] && abs( $added['until'] - ( time() + DAY_IN_SECONDS ) ) < 5 && '' === $added['disk'] && array() === $added['purge'], wp_json_encode( $added ) );
$http = PNCP_Rules::nginx_http();
t( 'R Nginx part 1: the path in the map $pncp_open_path', (bool) preg_match( '/map \$uri \$pncp_open_path_[a-z0-9_]+ \{[^}]*\n    \/builtwith\.txt 1;\n/', $http ), $http );
t( 'R ...the fingerprints do not change (Nginx and Apache)', $fp_n === PNCP_Rules::nginx_fingerprint() && $fp_a === PNCP_Rules::apache_fingerprint() );
t( 'R Apache: a condition for the path after each open-path condition', 0 < substr_count( PNCP_Rules::apache(), "RewriteCond %{REQUEST_URI} !^(?:/builtwith\\.txt)$\n" ) && substr_count( PNCP_Rules::apache(), "RewriteCond %{REQUEST_URI} !^(?:/builtwith\\.txt)$\n" ) === substr_count( PNCP_Rules::apache(), 'tdmrep\\.json)$ [NC]' ), PNCP_Rules::apache() );
t( 'R the evaluator: BuiltWith may read /builtwith.txt, and is still blocked elsewhere', null === PNCP_Rules::evaluate( $req( '/builtwith.txt' ) ) && null !== PNCP_Rules::evaluate( $req( '/' ) ) );

/* ---------- H. Over HTTP ---------- */

list( $code, $h, $body ) = req( '/builtwith.txt' );
t( 'H BuiltWith (in the bot list) reads /builtwith.txt: 200, the content', 200 === $code && "builtwith-verify=3126abc\n" === $body, $code . ' ' . $body );
t( 'H ...text/plain, no caching, nosniff, noindex', 'text/plain; charset=utf-8' === ( $h['content-type'] ?? '' ) && false !== strpos( $h['cache-control'] ?? '', 'no-store' ) && 'no-store' === ( $h['cdn-cache-control'] ?? '' ) && 'nosniff' === ( $h['x-content-type-options'] ?? '' ) && 'noindex' === ( $h['x-robots-tag'] ?? '' ), wp_json_encode( $h ) );
list( $code, $h, $body ) = req( '/builtwith.txt', BUILTWITH, 'HEAD' );
t( 'H HEAD: 200, no body', 200 === $code && '' === $body && '25' === ( $h['content-length'] ?? '' ), $code . ' ' . wp_json_encode( $h ) );
list( $code ) = req( '/' );
t( 'H the rest of the site: BuiltWith still 403', 403 === $code, (string) $code );
list( $code, $h, $body ) = req( '/builtwith.txt', BUILTWITH, 'POST', array( 'a' => 1 ) );
t( 'H POST: not the file', false === strpos( $body, 'builtwith-verify' ), $code . ' ' . substr( $body, 0, 100 ) );
list( $code, $h, $body ) = req( '/builtwith.txt?x=1', BROWSER );
t( 'H a browser, with a query string: the file too', 200 === $code && "builtwith-verify=3126abc\n" === $body );
list( $code ) = req( '/BuiltWith.txt' );
t( 'H another case of the name: not the file (403 for BuiltWith)', 403 === $code, (string) $code );
PNCP_Verify_Files::add( '/google1234567890abcdef.html', 'google-site-verification: google1234567890abcdef.html', 24 );
list( $code, $h, $body ) = req( '/google1234567890abcdef.html', 'Mozilla/5.0 (compatible; Google-Site-Verification/1.0)' );
t( 'H an .html file: text/html, in a sandbox (no script runs)', 200 === $code && 'text/html; charset=utf-8' === ( $h['content-type'] ?? '' ) && "sandbox; default-src 'none'" === ( $h['content-security-policy'] ?? '' ), $code . ' ' . wp_json_encode( $h ) );
PNCP_Verify_Files::add( '/BingSiteAuth.xml', '<?xml version="1.0"?><users><user>ABC</user></users>', 24 );
list( $code, $h ) = req( '/BingSiteAuth.xml', 'Mozilla/5.0 (compatible; bingbot/2.0)' );
t( 'H an .xml file: application/xml', 200 === $code && 'application/xml; charset=utf-8' === ( $h['content-type'] ?? '' ), $code . ' ' . wp_json_encode( $h ) );
PNCP_Verify_Files::remove( '/BingSiteAuth.xml' );
PNCP_Verify_Files::remove( '/google1234567890abcdef.html' );

// The early check (mu-plugin, before the other plugins).
settings( array( 'early_mode' => 1 ) );
PNCP_Early::sync();
list( $code ) = req( '/' );
list( $code2, $h, $body ) = req( '/builtwith.txt' );
t( 'H with the early check on: / still 403, /builtwith.txt 200', PNCP_Early::installed() && 403 === $code && 200 === $code2 && "builtwith-verify=3126abc\n" === $body, $code . ' ' . $code2 );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();

// The pre-cache check (from wp-config.php, before WordPress).
$c    = PNCP_Precheck::config();
$keep = $_SERVER['REQUEST_URI'] ?? null;
$_SERVER['REQUEST_URI'] = '/builtwith.txt?x=1';
$open = PNCP_Precheck_Runtime::applies( $c );
$_SERVER['REQUEST_URI'] = '/some-page/';
$page = PNCP_Precheck_Runtime::applies( $c );
$c['open']['/builtwith.txt'] = time() - 1;
$_SERVER['REQUEST_URI'] = '/builtwith.txt';
$over = PNCP_Precheck_Runtime::applies( $c );
$_SERVER['REQUEST_URI'] = $keep;
t( 'H the pre-cache check: its configuration has the path; it leaves it to WordPress, checks the rest, and checks it again once its time is over', isset( PNCP_Precheck::config()['open']['/builtwith.txt'] ) && false === $open && true === $page && true === $over );
settings( array( 'precheck' => 1 ) );
PNCP_Precheck::sync();
list( $code ) = req( '/' );
list( $code2, $h, $body ) = req( '/builtwith.txt' );
t( 'H with the pre-cache check on: / still 403, /builtwith.txt 200', 403 === $code && 200 === $code2 && "builtwith-verify=3126abc\n" === $body, $code . ' ' . $code2 . ' ' . get_option( 'pncp_precheck_status' ) );
settings( array( 'precheck' => 0 ) );
PNCP_Precheck::sync();

// Its time over (the cron event late): never served.
$index                            = get_option( PNCP_Verify_Files::INDEX );
$index['/builtwith.txt']['until'] = time() - 1;
update_option( PNCP_Verify_Files::INDEX, $index, true );
list( $code, $h, $body ) = req( '/builtwith.txt' );
t( 'H its time over: no more served, BuiltWith 403 again (before the cron event)', 403 === $code && false === strpos( $body, 'builtwith-verify' ) && array() === PNCP_Verify_Files::paths(), (string) $code );
t( 'H ...and out of the rules', false === strpos( PNCP_Rules::nginx_http(), '/builtwith.txt' ) );

/* ---------- E. The end, P. purged at the CDN ---------- */

$calls = array();
add_filter(
	'pncp_bunny_api_base',
	static function () {
		return 'https://bunny-verify.mock.test';
	}
);
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) use ( &$calls ) {
		if ( 0 !== strpos( $url, 'https://bunny-verify.mock.test/' ) ) {
			return $pre;
		}
		$calls[] = $url;
		return array(
			'headers'  => array(),
			'body'     => '{}',
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	},
	1,
	3
);
update_option(
	PNCP_Bunny::CONFIG,
	array(
		'zone'  => '4242',
		'token' => BUNNY_KEY,
	),
	false
);
PNCP_Bunny::reset();
$purge_url = 'https://bunny-verify.mock.test/purge?url=' . rawurlencode( home_url( '/builtwith.txt' ) ) . '&async=false';
$swept     = PNCP_Verify_Files::sweep();
t( 'E sweep(): the file whose time is over is removed, and purged at Bunny', array( '/builtwith.txt' ) === $swept && ! PNCP_Verify_Files::all() && array( $purge_url ) === $calls && false === get_option( PNCP_Verify_Files::INDEX ), wp_json_encode( $calls ) );
$calls = array();
$r     = PNCP_Verify_Files::add( '/builtwith.txt', 'v2', 2 );
t( 'P add(): purged at Bunny (the address), the result says so', array( $purge_url ) === $calls && isset( $r['purge']['Bunny CDN'] ) && 'ok' === $r['purge']['Bunny CDN']['status'], wp_json_encode( $r ) );
$next = wp_next_scheduled( PNCP_Verify_Files::CRON );
t( 'E add(): its end is scheduled (single cron event)', $next && abs( $next - ( time() + 2 * HOUR_IN_SECONDS ) ) <= 10, (string) $next );
$calls = array();
$r     = PNCP_Verify_Files::add( '/builtwith.txt', 'v3', 3 );
t( 'E the same path again: replaced (one file, the new content and time)', 1 === count( PNCP_Verify_Files::all() ) && 'v3' === PNCP_Verify_Files::all()['/builtwith.txt']['content'] && 1 === count( $calls ) );
$calls = array();
t( 'E sweep() before its time: nothing removed', array() === PNCP_Verify_Files::sweep() && 1 === count( PNCP_Verify_Files::all() ) && ! $calls );
t( 'E sweep() after its time: removed and purged', array( '/builtwith.txt' ) === PNCP_Verify_Files::sweep( time() + 4 * HOUR_IN_SECONDS ) && array( $purge_url ) === $calls && false === wp_next_scheduled( PNCP_Verify_Files::CRON ) );
for ( $i = 0; $i < PNCP_Verify_Files::MAX_FILES; $i++ ) {
	PNCP_Verify_Files::add( '/v' . $i . '.txt', 'x', 1 );
}
$more = PNCP_Verify_Files::add( '/v99.txt', 'x', 1 );
t( 'E at most 10 files at once', is_wp_error( $more ) && PNCP_Verify_Files::MAX_FILES === count( PNCP_Verify_Files::all() ) );
$calls = array();
$r     = PNCP_Verify_Files::remove( '/v0.txt' );
t( 'P remove(): purged at Bunny', $r['removed'] && 1 === count( $calls ) && false !== strpos( $calls[0], rawurlencode( home_url( '/v0.txt' ) ) ) );
PNCP_Verify_Files::remove_all();
delete_option( PNCP_Bunny::CONFIG );
PNCP_Bunny::reset();

/* ---------- D. The root folder ---------- */

$r = PNCP_Verify_Files::add( '/builtwith.txt', 'on-disk', 1, true );
t( 'D asked: written to the root folder, recorded', 'written' === $r['disk'] && 'on-disk' === file_get_contents( $root . '/builtwith.txt' ) && 1 === PNCP_Verify_Files::all()['/builtwith.txt']['disk'] );
PNCP_Verify_Files::remove( '/builtwith.txt' );
t( 'D removed with it (unchanged)', ! file_exists( $root . '/builtwith.txt' ) );
file_put_contents( $root . '/builtwith.txt', 'the site\'s own' );
$r = PNCP_Verify_Files::add( '/builtwith.txt', 'mine', 1, true );
t( 'D a file already there: never replaced', 'exists' === $r['disk'] && 'the site\'s own' === file_get_contents( $root . '/builtwith.txt' ) );
PNCP_Verify_Files::remove( '/builtwith.txt' );
t( 'D ...and never removed', 'the site\'s own' === file_get_contents( $root . '/builtwith.txt' ) );
unlink( $root . '/builtwith.txt' );
$r = PNCP_Verify_Files::add( '/builtwith.txt', 'mine', 1, true );
file_put_contents( $root . '/builtwith.txt', 'changed by someone' );
$r = PNCP_Verify_Files::remove( '/builtwith.txt' );
t( 'D changed since it was written: left there', 'kept' === $r['disk'] && 'changed by someone' === file_get_contents( $root . '/builtwith.txt' ) );
unlink( $root . '/builtwith.txt' );
$r = PNCP_Verify_Files::add( '/.well-known/x.txt', 'wk', 1, true );
t( 'D /.well-known/ without that folder: not written (WordPress serves it)', 'notwritable' === $r['disk'] && ! file_exists( $root . '/.well-known' ) );
PNCP_Verify_Files::remove_all();

/* ---------- R. Real Nginx ---------- */

$nginx_bin = trim( (string) shell_exec( 'command -v nginx 2>/dev/null' ) );
if ( '' === $nginx_bin || ! function_exists( 'curl_init' ) ) {
	echo "SKIP R real Nginx (nginx not on PATH)\n";
} else {
	PNCP_Verify_Files::add( '/builtwith.txt', 'x', 1 );
	$dir  = $root . '/nginx';
	$port = 19900 + ( getmypid() % 90 );
	wp_mkdir_p( $dir . '/tmp' );
	wp_mkdir_p( $dir . '/www' );
	file_put_contents( $dir . '/www/builtwith.txt', 'static' );
	file_put_contents( $dir . '/www/index.html', 'home' );
	file_put_contents( $dir . '/http.conf', PNCP_Rules::nginx_http() );
	file_put_contents( $dir . '/server.conf', PNCP_Rules::nginx_server() );
	file_put_contents(
		$dir . '/nginx.conf',
		'worker_processes 1; error_log ' . $dir . '/error.log; pid ' . $dir . '/nginx.pid; events { worker_connections 64; }' . "\n"
		. 'http { access_log off; client_body_temp_path ' . $dir . '/tmp; proxy_temp_path ' . $dir . '/tmp; fastcgi_temp_path ' . $dir . '/tmp; uwsgi_temp_path ' . $dir . '/tmp; scgi_temp_path ' . $dir . '/tmp;' . "\n"
		. 'include ' . $dir . '/http.conf;' . "\n"
		. 'server { listen 127.0.0.1:' . $port . '; server_name localhost; root ' . $dir . '/www;' . "\n"
		. 'include ' . $dir . '/server.conf;' . "\n"
		. 'location / { try_files $uri $uri/ =404; }' . "\n"
		. '} }' . "\n"
	);
	exec( escapeshellarg( $nginx_bin ) . ' -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' -e ' . escapeshellarg( $dir . '/error.log' ) . ' 2>&1', $o, $rc );
	usleep( 500000 );
	$get = static function ( $path ) use ( $port ) {
		$ch = curl_init( 'http://127.0.0.1:' . $port . $path );
		curl_setopt_array(
			$ch,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_TIMEOUT        => 10,
				CURLOPT_PROXY          => '',
				// Through a proxy (as behind a CDN): 127.0.0.1 is then not "the server itself" for the rules.
				CURLOPT_HTTPHEADER     => array( 'User-Agent: ' . BUILTWITH, 'X-Forwarded-For: ' . VISITOR ),
			)
		);
		curl_exec( $ch );
		$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		curl_close( $ch );
		return $code;
	};
	t( 'R real Nginx with part 1 and 2: BuiltWith reads /builtwith.txt (200), the home page 403', 0 === $rc && 200 === $get( '/builtwith.txt' ) && 403 === $get( '/' ), implode( ' ', $o ) . ' ' . $get( '/builtwith.txt' ) . ' ' . $get( '/' ) );
	PNCP_Verify_Files::remove_all();
	file_put_contents( $dir . '/http.conf', PNCP_Rules::nginx_http() );
	exec( escapeshellarg( $nginx_bin ) . ' -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' -e ' . escapeshellarg( $dir . '/error.log' ) . ' -s reload 2>&1' );
	usleep( 800000 );
	t( 'R ...part 1 without the file (removed): BuiltWith 403 there again', 403 === $get( '/builtwith.txt' ), (string) $get( '/builtwith.txt' ) );
	if ( is_file( $dir . '/nginx.pid' ) ) {
		exec( 'kill ' . (int) file_get_contents( $dir . '/nginx.pid' ) );
		usleep( 300000 );
	}
	PNCP_Verify_Files::remove_all();
}

/* ---------- A. The card, admin-post and WP-CLI ---------- */

$admin = (int) wp_insert_user(
	array(
		'user_login' => 't3126v-admin-' . wp_generate_password( 6, false ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'administrator',
	)
);
$sub   = (int) wp_insert_user(
	array(
		'user_login' => 't3126v-sub-' . wp_generate_password( 6, false ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'subscriber',
	)
);
register_shutdown_function(
	static function () use ( $admin, $sub ) {
		wp_delete_user( $admin );
		wp_delete_user( $sub );
	}
);
$cookie = static function ( $user ) {
	$expire = time() + HOUR_IN_SECONDS;
	$token  = WP_Session_Tokens::get_instance( $user )->create( $expire );
	$auth   = wp_generate_auth_cookie( $user, $expire, 'auth', $token );
	$in     = wp_generate_auth_cookie( $user, $expire, 'logged_in', $token );
	$_COOKIE[ LOGGED_IN_COOKIE ] = $in;
	wp_set_current_user( $user );
	return AUTH_COOKIE . '=' . rawurlencode( $auth ) . '; ' . LOGGED_IN_COOKIE . '=' . rawurlencode( $in );
};
$ac = $cookie( $admin );
list( $code, $h, $body ) = req( '/wp-admin/options-general.php?page=' . PNCP_Admin::PAGE . '&tab=rules', BROWSER, 'GET', null, $ac );
t( 'A the Server rules tab: the "Verification files" card with its form (nonce)', 200 === $code && false !== strpos( $body, 'id="pncp-verify-files"' ) && false !== strpos( $body, 'name="op" value="add"' ) && false !== strpos( $body, 'name="disk"' ) && false !== strpos( $body, '_wpnonce' ), $code . ' ' . substr( wp_strip_all_tags( $body ), 0, 200 ) );
$add = array(
	'action'   => PNCP_Verify_Files::ACTION,
	'op'       => 'add',
	'path'     => '/builtwith.txt',
	'content'  => 'from-the-form',
	'hours'    => '5',
	'_wpnonce' => wp_create_nonce( PNCP_Verify_Files::ACTION . '_add' ),
);
$sc = $cookie( $sub );
$add['_wpnonce'] = wp_create_nonce( PNCP_Verify_Files::ACTION . '_add' );
list( $code ) = req( '/wp-admin/admin-post.php', BROWSER, 'POST', $add, $sc );
t( 'A admin-post: refused for a subscriber', 403 === $code && ! PNCP_Verify_Files::all(), (string) $code );
$ac              = $cookie( $admin );
$add['_wpnonce'] = 'bad';
list( $code ) = req( '/wp-admin/admin-post.php', BROWSER, 'POST', $add, $ac );
t( 'A admin-post: refused without a valid nonce', in_array( $code, array( 400, 403 ), true ) && ! PNCP_Verify_Files::all(), (string) $code );
$add['_wpnonce'] = wp_create_nonce( PNCP_Verify_Files::ACTION . '_add' );
list( $code, $h ) = req( '/wp-admin/admin-post.php', BROWSER, 'POST', $add, $ac );
$all = PNCP_Verify_Files::all();
t( 'A admin-post (administrator, nonce): added for 5 hours, back to the card', 302 === $code && isset( $all['/builtwith.txt'] ) && 'from-the-form' === $all['/builtwith.txt']['content'] && abs( $all['/builtwith.txt']['until'] - ( time() + 5 * HOUR_IN_SECONDS ) ) < 30 && false !== strpos( $h['location'] ?? '', '#pncp-verify-files' ), $code . ' ' . wp_json_encode( $h ) );
list( $code, $h, $body ) = req( '/wp-admin/options-general.php?page=' . PNCP_Admin::PAGE . '&tab=rules', BROWSER, 'GET', null, $ac );
t( 'A the card: what was done, the file with a Remove button', false !== strpos( $body, 'is served to every bot until' ) && false !== strpos( $body, '<code>/builtwith.txt</code>' ) && false !== strpos( $body, 'name="op" value="remove"' ) );
list( $code, $h, $body ) = req( '/builtwith.txt' );
t( 'A ...and BuiltWith reads it', 200 === $code && 'from-the-form' === $body );
$bad         = $add;
$bad['path'] = '/x.php';
list( $code ) = req( '/wp-admin/admin-post.php', BROWSER, 'POST', $bad, $ac );
list( $c2, $h, $body ) = req( '/wp-admin/options-general.php?page=' . PNCP_Admin::PAGE . '&tab=rules', BROWSER, 'GET', null, $ac );
t( 'A a PHP name from the form: refused, said on the card', 302 === $code && ! isset( PNCP_Verify_Files::all()['/x.php'] ) && false !== strpos( $body, 'no PHP-like' ) );
$rm = array(
	'action'   => PNCP_Verify_Files::ACTION,
	'op'       => 'remove',
	'path'     => '/builtwith.txt',
	'_wpnonce' => wp_create_nonce( PNCP_Verify_Files::ACTION . '_remove' ),
);
list( $code ) = req( '/wp-admin/admin-post.php', BROWSER, 'POST', $rm, $ac );
t( 'A Remove (administrator, nonce): removed', 302 === $code && ! PNCP_Verify_Files::all() );
wp_set_current_user( 0 );
unset( $_COOKIE[ LOGGED_IN_COOKIE ] );

if ( '' === $wp_cli ) {
	echo "SKIP A WP-CLI (no WP_CLI)\n";
} else {
	$cli = static function ( $args ) use ( $wp_cli ) {
		exec( $wp_cli . ' scrapelock verify-file ' . $args . ' < /dev/null 2>&1', $out, $rc );
		wp_cache_flush();
		return array( $rc, implode( "\n", $out ) );
	};
	list( $rc, $out ) = $cli( 'add /builtwith.txt --content=cli-content --hours=3' );
	t( 'A wp scrapelock verify-file add: added, the time said', 0 === $rc && 'cli-content' === ( PNCP_Verify_Files::all()['/builtwith.txt']['content'] ?? '' ) && false !== strpos( $out, 'is served to every bot until' ), $out );
	file_put_contents( $root . '/from.html', 'google-site-verification: google0123456789abcdef.html' );
	list( $rc, $out ) = $cli( 'add google0123456789abcdef.html --from=' . escapeshellarg( $root . '/from.html' ) );
	t( 'A ...--from=<file>, a name without the slash', 0 === $rc && isset( PNCP_Verify_Files::all()['/google0123456789abcdef.html'] ), $out );
	list( $rc, $out ) = $cli( 'add /x.php --content=a' );
	t( 'A ...a PHP name: an error', 0 !== $rc && false !== strpos( $out, 'no PHP-like' ), $out );
	list( $rc, $out ) = $cli( 'add /a.txt --content=a --hours=200' );
	t( 'A ...--hours over 168: an error', 0 !== $rc && ! isset( PNCP_Verify_Files::all()['/a.txt'] ), $out );
	list( $rc, $out ) = $cli( 'list --format=json' );
	$rows = json_decode( $out, true );
	t( 'A list: both, with address, until and size', 0 === $rc && is_array( $rows ) && 2 === count( $rows ) && home_url( '/builtwith.txt' ) === $rows[0]['url'] && 11 === (int) $rows[0]['bytes'], $out );
	list( $rc, $out ) = $cli( 'remove /builtwith.txt' );
	t( 'A remove: removed', 0 === $rc && ! isset( PNCP_Verify_Files::all()['/builtwith.txt'] ), $out );
	list( $rc, $out ) = $cli( 'remove /builtwith.txt' );
	t( 'A remove of a file that is not there: an error', 0 !== $rc );
	PNCP_Verify_Files::remove_all();
}

PNCP_Log::unban_all();
echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
