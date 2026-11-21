<?php
/**
 * ScrapeLock 3.12.6 — how the parts of 3.12.6 fit together (Stealth status, verification files, the profilers
 * switch, the CLI, the wizard), and the fixes found when they were put side by side.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3126_integration.php
 *
 * P. "Block technology profilers" on (BuiltWith not in the bot list): a BuiltWith verification file is served to
 *    BuiltWith (WordPress, the early check, the pre-cache check) while the rest of the site is 403, and robots.txt
 *    asks BuiltWith to stay away from everything but that file (Allow: /builtwith.txt before Disallow: /).
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
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? '  [' . substr( (string) $extra, 0, 500 ) . ']' : '' ) . "\n";
}

const BUILTWITH = 'Mozilla/5.0 (compatible; BuiltWith/1.0; +https://builtwith.com/biup)';
const BROWSER   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const VISITOR   = '198.51.100.171';

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
}

/** A request with curl: [code, headers (lowercase), body]. */
function req( $path, $ua = BUILTWITH, $method = 'GET', $cookie = '' ) {
	global $base;
	$ch   = curl_init( $base . $path );
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_TIMEOUT        => 60,
		CURLOPT_PROXY          => '',
		CURLOPT_CUSTOMREQUEST  => $method,
		CURLOPT_NOBODY         => 'HEAD' === $method,
		CURLOPT_HTTPHEADER     => array( 'User-Agent: ' . $ua, 'X-Forwarded-For: ' . VISITOR, 'Accept-Language: en' ),
	);
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
			list( $k, $v )                       = explode( ':', $line, 2 );
			$headers[ strtolower( trim( $k ) ) ] = trim( $v );
		}
	}
	wp_cache_flush();
	return array( $code, $headers, (string) substr( $out, $hs ) );
}

$saved_settings = PNCP_Options::stored();
$saved_opts     = array();
foreach ( array( PNCP_Verify_Files::INDEX, PNCP_Verify_Files::DATA, PNCP_Bunny::CONFIG, PNCP_Edge::CONFIG, PNCP_Stealth_Status::SEEN ) as $pncp_name ) {
	$saved_opts[ $pncp_name ] = get_option( $pncp_name, null );
}
$tmp = sys_get_temp_dir() . '/pncp-t3126-int-' . getmypid();
wp_mkdir_p( $tmp . '/root' );
register_shutdown_function(
	static function () use ( $saved_settings, $saved_opts, $tmp ) {
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
		PNCP_Early::sync();
		PNCP_Precheck::sync();
		exec( 'rm -rf ' . escapeshellarg( $tmp ) );
	}
);
add_filter(
	'pncp_site_files_root',
	static function () use ( $tmp ) {
		return $tmp . '/root/';
	}
);
PNCP_Log::unban_all();
PNCP_Verify_Files::remove_all();
delete_option( PNCP_Bunny::CONFIG );
delete_option( PNCP_Edge::CONFIG );

// BuiltWith only through the switch: taken out of the bot list (as the wizard's proposal does).
$pncp_bots = implode( "\n", array_diff( PNCP_Options::parse_list( (string) $saved_settings['bot_list'] ), PNCP_Wizard::profiler_lines( (string) $saved_settings['bot_list'] ) ) );
settings(
	array(
		'enabled'              => 1,
		'monitor_mode'         => 0,
		'block_bots'           => 1,
		'bot_list'             => $pncp_bots,
		'block_tech_profilers' => 1,
		'early_mode'           => 0,
		'precheck'             => 0,
		'ip_header'            => 'x_forwarded_for',
		'trusted_proxies'      => '127.0.0.1',
		'allow_ips'            => '',
	)
);

/* ---------- P. The profilers switch and a verification file ---------- */

t( 'P BuiltWith is not in the bot list, only in the switch\'s list', ! PNCP_Wizard::profiler_lines( (string) PNCP_Options::stored()['bot_list'] ) && in_array( 'BuiltWith', PNCP_Bots::tech_profiler_agents(), true ) );
list( $code ) = req( '/builtwith.txt' );
t( 'P before: BuiltWith gets 403 at /builtwith.txt (the switch blocks it)', 403 === $code, (string) $code );
$robots = PNCP_Bots::robots_txt( '', true );
t( 'P robots.txt without a verification file: the profilers\' group, Disallow: / and no Allow', false !== strpos( $robots, "User-agent: BuiltWith\n" ) && false === strpos( $robots, 'Allow: /builtwith.txt' ), $robots );
$added = PNCP_Verify_Files::add( '/builtwith.txt', "builtwith-site-verification-3126\n", 24 );
t( 'P add(): the file is open', is_array( $added ) && isset( PNCP_Verify_Files::paths()['/builtwith.txt'] ), wp_json_encode( $added ) );
list( $code, $h, $body ) = req( '/builtwith.txt' );
t( 'P BuiltWith (blocked by the switch) reads /builtwith.txt: 200, the content, text/plain', 200 === $code && "builtwith-site-verification-3126\n" === $body && 'text/plain; charset=utf-8' === ( $h['content-type'] ?? '' ), $code . ' ' . $body );
list( $code ) = req( '/' );
t( 'P ...the rest of the site: still 403 for BuiltWith', 403 === $code, (string) $code );
list( $code ) = req( '/', 'Mozilla/5.0 (compatible; Wappalyzer)' );
t( 'P ...and another profiler is still 403 too', 403 === $code, (string) $code );
$robots = PNCP_Bots::robots_txt( '', true );
t( 'P robots.txt: every ScrapeLock group that says Disallow: / allows the file first (Allow: /builtwith.txt)', 1 === preg_match( "/# ScrapeLock: technology profilers\n(?:User-agent: [^\n]+\n)+Allow: \\/builtwith\\.txt\nDisallow: \\/\n/", $robots ) && substr_count( $robots, "Allow: /builtwith.txt\nDisallow: /\n" ) === substr_count( $robots, "Disallow: /\n" ), $robots );
list( $code, $h, $body ) = req( '/robots.txt', BROWSER );
t( 'P robots.txt over HTTP: the same Allow line', 200 === $code && false !== strpos( $body, "User-agent: BuiltWith\n" ) && false !== strpos( $body, "Allow: /builtwith.txt\nDisallow: /" ), $code . ' ' . $body );
t( 'P the rules\' evaluator: BuiltWith may read the file, and nothing else', null === PNCP_Rules::evaluate(
	array(
		'ua'      => BUILTWITH,
		'path'    => '/builtwith.txt',
		'https'   => true,
		'method'  => 'GET',
		'remote'  => VISITOR,
		'headers' => array(),
	)
) && null !== PNCP_Rules::evaluate(
	array(
		'ua'      => BUILTWITH,
		'path'    => '/',
		'https'   => true,
		'method'  => 'GET',
		'remote'  => VISITOR,
		'headers' => array(),
	)
) );
t( 'P Nginx part 1: BuiltWith in the bot map, the file in $pncp_open_path', false !== stripos( PNCP_Rules::nginx_http(), 'builtwith' ) && (bool) preg_match( '/map \$uri \$pncp_open_path_[a-z0-9_]+ \{[^}]*\n    \/builtwith\.txt 1;\n/', PNCP_Rules::nginx_http() ) );

settings( array( 'early_mode' => 1 ) );
PNCP_Early::sync();
list( $code ) = req( '/' );
list( $code2, $h, $body ) = req( '/builtwith.txt' );
t( 'P with the early check: / 403, /builtwith.txt 200 for BuiltWith', PNCP_Early::installed() && 403 === $code && 200 === $code2 && "builtwith-site-verification-3126\n" === $body, $code . ' ' . $code2 );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();
settings( array( 'precheck' => 1 ) );
PNCP_Precheck::sync();
list( $code ) = req( '/' );
list( $code2, $h, $body ) = req( '/builtwith.txt' );
t( 'P with the pre-cache check: / 403, /builtwith.txt 200 for BuiltWith', 403 === $code && 200 === $code2 && "builtwith-site-verification-3126\n" === $body, $code . ' ' . $code2 . ' ' . get_option( 'pncp_precheck_status' ) );
settings( array( 'precheck' => 0 ) );
PNCP_Precheck::sync();
PNCP_Verify_Files::remove( '/builtwith.txt' );
list( $code ) = req( '/builtwith.txt' );
t( 'P removed: 403 again, and robots.txt without the Allow line', 403 === $code && false === strpos( PNCP_Bots::robots_txt( '', true ), 'Allow: /builtwith.txt' ), (string) $code );

exit( $fails ? 1 : 0 );
