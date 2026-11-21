<?php
/**
 * ScrapeLock 3.12.3 — the server rules never refuse the server itself, the self-checks no longer look like a fake
 * browser, the installed rules report their fingerprint, and a refusal by ScrapeLock's own server rule is named.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI=wp] php t_3123_rules.php
 *
 * On the live site (Nginx, Bunny in front with real_ip) the home page answered the site's own check with 403 from
 * ScrapeLock's own generated Nginx rules: the self-check sent a Chrome User-Agent without Sec-Fetch-Mode /
 * Sec-CH-UA over HTTPS, which the fake_browser map refuses before PHP ever sees the signature.
 *
 * U. Every self-check sends "ScrapeLock-Selftest/<version> (+home)" and the signature (requests captured with
 *    pre_http_request; wp scrapelock selfcheck with --require); ScrapeLock's PHP checks let it through signed.
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
require_once ABSPATH . 'wp-admin/includes/user.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	test_lists();
	PNCP_Ip::reset();
}

/** The stage's Bunny and Cloudflare lists (with internet, WP cron would download the real ones). */
function test_lists() {
	wp_unschedule_hook( PNCP_Ip::CRON );
	set_transient( 'pncp_lists_missing_try', 1, HOUR_IN_SECONDS );
	PNCP_Ip::store_list( 'bunny', array( EDGE, '198.51.100.11' ) );
	PNCP_Ip::store_list( 'cloudflare', array( '104.16.0.0/13', '173.245.48.0/20' ) );
}

const EDGE      = '198.51.100.10'; // A Bunny edge.
const SERVER    = '203.0.113.50';  // The server's public address.
const PRIV      = '10.20.30.40';   // A private address of the server.
const VISITOR   = '198.51.100.81';
const OLD_UA    = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 ScrapeLock-Selftest';
const BROWSER   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const CHATGPT   = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot';
const PERPLEXITY = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)';

$saved       = PNCP_Options::stored();
$saved_state = get_option( 'pncp_rules_state', null ); // PNCP_Rules_State::STATE
$saved_texts = get_option( 'pncp_rules_texts', null ); // PNCP_Rules_State::TEXTS
$saved_ips   = get_option( PNCP_Server_Ips::OPTION, null );
register_shutdown_function(
	static function () use ( $saved, $saved_state, $saved_texts, $saved_ips ) {
		update_option( PNCP_OPTION, $saved );
		if ( null === $saved_ips ) {
			delete_option( PNCP_Server_Ips::OPTION );
		} else {
			update_option( PNCP_Server_Ips::OPTION, $saved_ips );
		}
		delete_transient( PNCP_Server_Ips::OUTBOUND );
		foreach ( array( 'pncp_rules_state' => $saved_state, 'pncp_rules_texts' => $saved_texts ) as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, false );
			}
		}
		delete_transient( 'pncp_nginx_status' );
		PNCP_Options::flush();
	}
);
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'block_bots'              => 1,
		'block_headless'          => 1,
		'block_empty_ua'          => 1,
		'allow_ai_search'         => 1,
		'hide_versions'           => 1,
		'block_upload_php'        => 1,
		'require_browser_headers' => 0,
		'allow_ips'               => '',
		'bot_list'                => PNCP_Options::default_bot_list(),
	)
);
// The server's addresses as PNCP_Server_Ips finds them, plus entries that must never reach a configuration file.
$extra_ips = array( SERVER, PRIV, '2a01:4f8:5::/64', EDGE, '10.0.0.0/8', '192.168.7.0/24', '203.0.113.77/30', '::ffff:203.0.113.9', '0.0.0.0' );
add_filter(
	'pncp_server_ips',
	static function ( $ips ) use ( &$extra_ips ) {
		return array_merge( (array) $ips, $extra_ips );
	}
);
delete_transient( 'pncp_nginx_status' );
delete_option( 'pncp_rules_state' );
delete_option( 'pncp_rules_texts' );
// Only the addresses of this test: none learned by earlier tests (a signed request teaches its address).
delete_option( PNCP_Server_Ips::OPTION );
delete_transient( PNCP_Server_Ips::OUTBOUND );
$home = home_url();
$id   = PNCP_Rules::nginx_id();

/* ---------- U. One User-Agent for every self-check ---------- */

$want_ua = 'ScrapeLock-Selftest/' . PNCP_VERSION . ' (+' . $home . ')';
t( 'U the self-check User-Agent', PNCP_Self_Check::user_agent() === $want_ua, PNCP_Self_Check::user_agent() );
t( 'U it is no browser\'s (no "Mozilla/", no "Chrome/")', false === strpos( $want_ua, 'Mozilla/' ) && false === strpos( $want_ua, 'Chrome/' ) );

$captured = array();
$own_host = strtolower( (string) wp_parse_url( $home, PHP_URL_HOST ) );
$capture  = static function ( $pre, $args, $url ) use ( &$captured, $own_host ) {
	if ( false !== $pre || strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) ) !== $own_host ) {
		return $pre;
	}
	$sig        = isset( $args['headers']['X-ScrapeLock-Sig'] ) ? (string) $args['headers']['X-ScrapeLock-Sig'] : '';
	$captured[] = array(
		'url' => $url,
		'ua'  => isset( $args['user-agent'] ) ? (string) $args['user-agent'] : '',
		'sig' => $sig,
	);
	$id = PNCP_Self_Check::request_id( $sig );
	return array(
		'headers'  => array(
			'content-type' => 'text/html; charset=UTF-8',
			'x-scrapelock' => PNCP_Self_Check::ok_marker( $id ),
		),
		'body'     => '<!doctype html><html><head><title>t</title></head><body>page</body></html>',
		'response' => array(
			'code'    => 200,
			'message' => 'OK',
		),
		'cookies'  => array(),
		'filename' => null,
	);
};
add_filter( 'pre_http_request', $capture, 1, 3 );
$checks = array(
	'Vulnerable points (all live checks)' => static function () {
		PNCP_Hardening::live( true );
	},
	'Run a real self-check now'           => static function () {
		PNCP_Self_Check::run();
	},
	'Site Health self-request test'       => static function () {
		PNCP_Health::test_selfrequest();
	},
	'Site Health robots.txt test'         => static function () {
		$public = get_option( 'blog_public' );
		update_option( 'blog_public', 1 ); // The test asks for robots.txt only on a public site with ScrapeLock's lines.
		$lines = PNCP_Options::stored()['robots_ai_block'];
		settings( array( 'robots_ai_block' => 1 ) );
		delete_transient( PNCP_Health::ROBOTS_CACHE );
		PNCP_Health::test_robots();
		settings( array( 'robots_ai_block' => $lines ) );
		update_option( 'blog_public', $public );
	},
	'Site Health private folders test'    => static function () {
		PNCP_Watermark::backup_dir(); // A private folder to check.
		delete_transient( PNCP_Health::FOLDERS_CACHE );
		PNCP_Health::test_folders();
	},
	'Site Health site files'              => static function () {
		$icon = static function () {
			return 'https://example.test/icon.png';
		};
		add_filter( 'get_site_icon_url', $icon );
		delete_transient( PNCP_Site_Files::CACHE );
		PNCP_Site_Files::probe();
		remove_filter( 'get_site_icon_url', $icon );
	},
	'Stealth test (scan)'                 => static function () {
		PNCP_Stealth::scan();
	},
	'Server rules status check'           => static function () {
		PNCP_Rules::nginx_status( true );
	},
);
foreach ( $checks as $label => $run ) {
	$captured = array();
	$run();
	$bad = array();
	foreach ( $captured as $c ) {
		if ( $want_ua !== $c['ua'] || '' === $c['sig'] ) {
			$bad[] = $c['url'] . ' UA=' . $c['ua'] . ' sig=' . ( '' === $c['sig'] ? 'none' : 'yes' );
		}
	}
	t( "U $label: every request sends the ScrapeLock-Selftest User-Agent and the signature (" . count( $captured ) . ')', $captured && ! $bad, implode( ' | ', array_slice( $bad, 0, 3 ) ) );
}
remove_filter( 'pre_http_request', $capture, 1 );
delete_transient( PNCP_Hardening::LIVE );

$wp_cli = (string) getenv( 'WP_CLI' );
if ( '' !== $wp_cli ) {
	$dir  = sys_get_temp_dir() . '/pncp-t3123-' . getmypid();
	$file = $dir . '/capture.php';
	$log  = $dir . '/ua.log';
	wp_mkdir_p( $dir );
	file_put_contents(
		$file,
		'<?php WP_CLI::add_wp_hook( "pre_http_request", function ( $pre, $args, $url ) { file_put_contents( ' . var_export( $log, true ) . ', $url . "\t" . ( isset( $args["user-agent"] ) ? $args["user-agent"] : "" ) . "\t" . ( empty( $args["headers"]["X-ScrapeLock-Sig"] ) ? "" : "sig" ) . "\n", FILE_APPEND ); return $pre; }, 1, 3 );'
	);
	exec( $wp_cli . ' --require=' . escapeshellarg( $file ) . ' scrapelock selfcheck 2>&1', $out );
	$rows = file_exists( $log ) ? array_filter( explode( "\n", (string) file_get_contents( $log ) ) ) : array();
	$good = (bool) $rows;
	foreach ( $rows as $row ) {
		$parts = explode( "\t", $row );
		if ( 0 !== strpos( $parts[0], $home ) || false !== strpos( $parts[0], '/wp-cron.php' ) ) {
			continue; // WP cron's own spawn is not a self-check.
		}
		$good = $good && $want_ua === ( $parts[1] ?? '' ) && 'sig' === ( $parts[2] ?? '' );
	}
	t( 'U wp scrapelock selfcheck: the ScrapeLock-Selftest User-Agent and the signature', $good, implode( ' | ', array_slice( $rows, 0, 2 ) ) . ' ' . implode( ' ', array_slice( $out, 0, 2 ) ) );
	@unlink( $log );
	@unlink( $file );
	@rmdir( $dir );
} else {
	echo "SKIP U wp scrapelock selfcheck (no WP_CLI)\n";
}

// Signed, the User-Agent passes ScrapeLock's PHP checks at their strictest ("Browsers only", fake browsers, empty and
// unknown User-Agents), from a visitor's address (behind a CDN without real_ip); unsigned, the same name from that
// address is refused over HTTP (anyone can send it).
settings( array( 'require_browser_headers' => 1 ) );
$http_host = (string) wp_parse_url( $base, PHP_URL_HOST ) . ( wp_parse_url( $base, PHP_URL_PORT ) ? ':' . wp_parse_url( $base, PHP_URL_PORT ) : '' );
$keep      = $_SERVER;
foreach ( array_keys( $_SERVER ) as $k ) {
	if ( 0 === strpos( $k, 'HTTP_' ) ) {
		unset( $_SERVER[ $k ] );
	}
}
$_SERVER['REMOTE_ADDR']            = VISITOR;
$_SERVER['REQUEST_METHOD']         = 'GET';
$_SERVER['REQUEST_URI']            = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
$_SERVER['HTTP_HOST']              = $http_host;
$_SERVER['HTTPS']                  = 'on';
$_SERVER['HTTP_USER_AGENT']        = PNCP_Self_Check::user_agent();
$_SERVER['HTTP_X_SCRAPELOCK_SIG']  = PNCP_Server_Ips::sig_token( 'GET', home_url( '/' ) );
PNCP_Ip::reset();
PNCP_Server_Ips::forget();
PNCP_Self_Check::reset();
$v = PNCP_Bots::check( 'page', false );
t( 'U signed: ScrapeLock\'s PHP checks let the self-check User-Agent through ("Browsers only" on, a visitor\'s address)', ! is_array( $v ), wp_json_encode( $v ) );
unset( $_SERVER['HTTP_X_SCRAPELOCK_SIG'] );
PNCP_Ip::reset();
PNCP_Server_Ips::forget();
PNCP_Self_Check::reset();
$v = PNCP_Bots::check( 'page', false );
t( 'U unsigned: the same User-Agent from a visitor is refused ("Browsers only"; never trusted by its name)', is_array( $v ) && 403 === (int) $v['code'], wp_json_encode( $v ) );
$_SERVER = $keep;
PNCP_Ip::reset();
PNCP_Server_Ips::forget();
PNCP_Self_Check::reset();
settings( array( 'require_browser_headers' => 0 ) );

exit( $fails ? 1 : 0 );
