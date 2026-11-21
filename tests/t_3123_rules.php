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
 * A. The server's own addresses in the generated Nginx (geo) and Apache rules: the right ones, never a CDN edge,
 *    an invalid entry or a private range wider than needed.
 * B. The block decision is 0 for the server itself (a loopback / private address only without a proxy's header).
 * C. The fingerprint header: Nginx (only with X-ScrapeLock-Sig) and Apache (mod_headers).
 * S. Out of date: a settings change marks the rules stale at once; a matching header is fresh; no header on a site
 *    that never had rules is no nag; the rules of before 3.12.3 (check address only) are seen as installed.
 * N. The admin notice and Site Health (texts, manage_options, ScrapeLock pages, dismissed per fingerprint) and the
 *    diff view (nonce, manage_options; the text kept by the Server rules tab, or "not known").
 * E. The evaluator: a fake-Chrome request is "ScrapeLock's own server rule (fake browser)" for the self-check, and it
 *    agrees with the generated rules on a table of requests (with real Nginx when `nginx` is on PATH, else SKIP).
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

/* ---------- A. The server's own addresses in the rules ---------- */

$self = PNCP_Rules::self_addresses();
t( 'A loopback addresses first, as local', array_slice( $self['local'], 0, 2 ) === array( '127.0.0.1', '::1' ), wp_json_encode( $self ) );
t( 'A the public address, the private one (local), an IPv6 range', in_array( SERVER, $self['public'], true ) && in_array( PRIV, $self['local'], true ) && in_array( '2a01:4f8:5::/64', $self['public'], true ), wp_json_encode( $self ) );
t( 'A never the CDN edge', ! in_array( EDGE, array_merge( $self['public'], $self['local'] ), true ) );
t( 'A never a private range wider than /24 (10.0.0.0/8), a /24 is fine', ! in_array( '10.0.0.0/8', $self['local'], true ) && in_array( '192.168.7.0/24', $self['local'], true ) );
t( 'A a range by its network address, an IPv4-mapped address as IPv4, never 0.0.0.0', in_array( '203.0.113.76/30', $self['public'], true ) && in_array( '203.0.113.9', $self['public'], true ) && ! in_array( '0.0.0.0', $self['public'], true ) );
$entries = array(
	'1.2.3.4; deny all'  => null,
	'1.2.3.4 1; }'       => null,
	'1.2.3.4/33'         => null,
	'2001:db8::/129'     => null,
	'::'                 => null,
	'10.0.0.0/16'        => null,
	'fd00::/48'          => null,
	'fd00::/64'          => array( 'fd00::/64', 'local' ),
	'example.com'        => null,
	'1.0.0.0/7'          => null,
	EDGE                 => null,
	'173.245.48.5'       => null,
	'203.0.113.5'        => array( '203.0.113.5', 'public' ),
	'2A01:4F8:0:0::1'    => array( '2a01:4f8::1', 'public' ),
);
$bad = array();
foreach ( $entries as $in => $want ) {
	if ( PNCP_Rules::self_entry( $in ) !== $want ) {
		$bad[] = $in . ' → ' . wp_json_encode( PNCP_Rules::self_entry( $in ) );
	}
}
t( 'A self_entry(): only valid IPv4 / IPv6 addresses or CIDRs, canonical, never a CDN edge or a range too wide', ! $bad, implode( ' | ', $bad ) );

$http = PNCP_Rules::nginx_http();
preg_match( '/geo \$pncp_self_' . $id . ' \{\n(.*?)\n\}/s', $http, $geo );
$geo_lines = isset( $geo[1] ) ? array_map( 'trim', explode( "\n", $geo[1] ) ) : array();
t( 'A Nginx: geo $pncp_self_<site> with default 0, loopback / private as 2, public as 1', isset( $geo[1] ) && 'default 0;' === $geo_lines[0] && in_array( '127.0.0.1 2;', $geo_lines, true ) && in_array( '::1 2;', $geo_lines, true ) && in_array( PRIV . ' 2;', $geo_lines, true ) && in_array( SERVER . ' 1;', $geo_lines, true ) && in_array( '2a01:4f8:5::/64 1;', $geo_lines, true ), $geo[0] ?? $http );
$valid = true;
foreach ( array_slice( $geo_lines, 1 ) as $line ) {
	$valid = $valid && preg_match( '#^([0-9a-f:.]+(?:/\d+)?) [12];$#', $line, $m ) && null !== PNCP_Rules::self_entry( $m[1] );
}
t( 'A Nginx: every geo entry is a valid address or CIDR, never the edge', $valid && false === strpos( $geo[0] ?? '', EDGE ), $geo[0] ?? '' );
$ap = PNCP_Rules::apache();
t( 'A Apache: the public addresses exempt, the loopback / private ones only with no proxy header', false !== strpos( $ap, 'RewriteCond %{REMOTE_ADDR} ^(?:' . str_replace( '.', '\.', SERVER ) ) && false !== strpos( $ap, 'RewriteCond %{REMOTE_ADDR}%{HTTP:X-Forwarded-For}%{HTTP:X-Real-IP}%{HTTP:Forwarded}%{HTTP:CF-Connecting-IP} ^(?:127\.0\.0\.1|::1|' . str_replace( '.', '\.', PRIV ) ) && false !== strpos( $ap, 'RewriteRule .* - [E=PNCP_SELF:1]' ) && false === strpos( $ap, str_replace( '.', '\.', EDGE ) ) );
t( 'A Apache: ranges with Apache 2.4 expressions, not for LiteSpeed', false !== strpos( $ap, "<IfModule !LiteSpeed>\nRewriteCond expr \"-R '2a01:4f8:5::/64'\"" ) );
t( 'A Apache: every blocking group skips the server (bots, empty User-Agent, fake Chrome, fake Firefox)', 4 === substr_count( $ap, "RewriteCond %{ENV:PNCP_SELF} !^1$\n" ), (string) substr_count( $ap, 'PNCP_SELF} !^1$' ) );
$tab = (string) file_get_contents( PNCP_DIR . 'includes/class-pncp-admin.php' );
t( 'A the Server rules tab says the server\'s addresses are exempt, and names them', false !== strpos( $tab, 'The server\\\'s own addresses are never blocked by these rules: %s.' ) && false !== strpos( $tab, 'PNCP_Rules::self_addresses()' ) );

/* ---------- B. The block decision is 0 for the server itself ---------- */

t( 'B Nginx: the block map takes the server into account, and the self check wins over every block reason', false !== strpos( $http, ':$pncp_open_path_' . $id . ':$pncp_self_' . $id . '$pncp_fwd_' . $id . '" $pncp_block_' . $id . ' {' ) && false !== strpos( $http, '"~^[01]*1[01]*:0:(0[01]|21)$" 1;' ) );
t( 'B Nginx: the page limit keeps the key of its zone ($binary_remote_addr: Nginx refuses to reload a zone whose key changed)', false !== strpos( $http, 'limit_req_zone $binary_remote_addr zone=pncp_pages_' . $id . ':' ) && false === strpos( $http, '$pncp_limit_key_' ) );
settings( array( 'allow_ips' => '192.0.2.7' ) );
t( 'B Nginx: with always allowed IPs (key $pncp_limit_key since 3.4.3), the server is not counted either', (bool) preg_match( '/map "\$pncp_limit_exempt_' . $id . '\$pncp_self_' . $id . '\$pncp_fwd_' . $id . '" \$pncp_limit_key_' . $id . ' \{ default \$binary_remote_addr; "~\^1" ""; "~\^\.\(1\.\|20\)\$" ""; \}/', PNCP_Rules::nginx_http() ) && false !== strpos( PNCP_Rules::nginx_http(), 'limit_req_zone $pncp_limit_key_' . $id . ' zone=' ) );
settings( array( 'allow_ips' => '' ) );
foreach ( array( '0:0:00' => 0, '1:0:00' => 1, '01:0:01' => 1, '1:1:00' => 0, '1:0:10' => 0, '1:0:11' => 0, '1:0:20' => 0, '1:0:21' => 1, '0:0:21' => 0 ) as $key => $want ) {
	t( "B the block expression for \"$key\" → $want", ( 1 === preg_match( '#' . PNCP_Rules::BLOCK_REGEX . '#', $key ) ) === (bool) $want );
}

/* ---------- C. The fingerprint header ---------- */

$srv = PNCP_Rules::nginx_server();
t( 'C Nginx: the header only for the site\'s own signed requests', false !== strpos( $srv, "set \$pncp_rules_hdr_$id \"\";\nif (\$http_x_scrapelock_sig) { set \$pncp_rules_hdr_$id \"\$pncp_rules_$id " ) && false !== strpos( $srv, "add_header X-ScrapeLock-Rules \$pncp_rules_hdr_$id always;" ) );
$fp = PNCP_Rules::nginx_fingerprint();
t( 'C Nginx: the header value is "<http> <server>", the same as the check address answers', 'nginx' === PNCP_Rules_State::format_of( $fp ) && false !== strpos( $srv, '"$pncp_rules_' . $id . ' ' . explode( ' ', $fp )[1] . '"; }' ) && false !== strpos( $srv, 'return 200 "$pncp_rules_' . $id . ' ' . explode( ' ', $fp )[1] . '\n";' ) && false !== strpos( $http, 'map $host $pncp_rules_' . $id . ' { default "' . explode( ' ', $fp )[0] . '"; }' ) );
t( 'C Nginx: the header lines come before the block (set before any return)', strpos( $srv, 'add_header X-ScrapeLock-Rules' ) < strpos( $srv, 'if ($pncp_block_' ) );
t( 'C Nginx: the comment tells how add_header is inherited', false !== strpos( $srv, 'a location with add_header' ) );
$afp = PNCP_Rules::apache_fingerprint();
t( 'C Apache: Header always set with the fingerprint, only with X-ScrapeLock-Sig, guarded by mod_headers', 'apache' === PNCP_Rules_State::format_of( $afp ) && false !== strpos( $ap, "<IfModule mod_headers.c>\nHeader always set X-ScrapeLock-Rules \"$afp\" \"expr=-n %{HTTP:X-ScrapeLock-Sig}\"\n</IfModule>\n# END ScrapeLock" ) );
settings( array( 'rate_limit' => (int) PNCP_Options::stored()['rate_limit'] + 1 ) );
t( 'C another setting, other fingerprints (Nginx and Apache)', PNCP_Rules::nginx_fingerprint() !== $fp );
settings( array( 'rate_limit' => (int) PNCP_Options::stored()['rate_limit'] - 1 ) );
settings( array( 'block_empty_ua' => 0 ) );
t( 'C Apache: another setting, another fingerprint', PNCP_Rules::apache_fingerprint() !== $afp );
settings( array( 'block_empty_ua' => 1 ) );
$before = PNCP_Rules::nginx_fingerprint();
$extra_ips[] = '203.0.113.99';
t( 'C the server\'s addresses are not settings: another address, the same fingerprint (no "out of date")', PNCP_Rules::nginx_fingerprint() === $before && PNCP_Rules::apache_fingerprint() !== '' && false !== strpos( PNCP_Rules::nginx_http(), '203.0.113.99 1;' ) );
array_pop( $extra_ips );


/* ---------- S. Out of date ---------- */

delete_option( PNCP_Rules_State::STATE );
delete_transient( 'pncp_nginx_status' );
$no_rules = static function ( $pre, $args, $url ) {
	return false !== strpos( $url, '/.well-known/scrapelock-nginx' ) ? array(
		'headers'  => array(),
		'body'     => 'not found',
		'response' => array(
			'code'    => 404,
			'message' => 'Not Found',
		),
		'cookies'  => array(),
		'filename' => null,
	) : $pre;
};
add_filter( 'pre_http_request', $no_rules, 5, 3 );
PNCP_Rules_State::record( '' );
t( 'S no header on a site that never had rules: no nag', ! PNCP_Rules_State::is_stale() && ! PNCP_Rules_State::in_use() );
$fp = PNCP_Rules::nginx_fingerprint();
PNCP_Rules_State::record( $fp );
$st = PNCP_Rules_State::state();
t( 'S a matching header: fresh, kept with the time', ! PNCP_Rules_State::is_stale() && PNCP_Rules_State::in_use() && $fp === $st['installed'] && $fp === $st['current'] && 'nginx' === $st['format'] && $st['time'] >= time() - 5 );
settings( array( 'block_headless' => 0 ) );
t( 'S a setting that changes the rules: out of date at once, without a self-check', PNCP_Rules_State::is_stale() && PNCP_Rules::nginx_fingerprint() === PNCP_Rules_State::state()['current'] );
settings( array( 'traffic_days' => (int) PNCP_Options::stored()['traffic_days'] + 1 ) );
t( 'S a setting the rules do not read: the current fingerprint stays', PNCP_Rules::nginx_fingerprint() === PNCP_Rules_State::state()['current'] );
settings( array( 'block_headless' => 1 ) );
t( 'S the setting back: fresh again', ! PNCP_Rules_State::is_stale() );
PNCP_Rules_State::record( '' );
t( 'S the header gone while the site uses rules: out of date ("not found")', PNCP_Rules_State::is_stale() && false !== strpos( PNCP_Rules_State::message(), 'installed: not found' ) );
PNCP_Rules_State::record( $fp );
remove_filter( 'pre_http_request', $no_rules, 5 );

// The Nginx rules of before 3.12.3 have no header; their check address answers the old fingerprints.
delete_option( PNCP_Rules_State::STATE );
set_transient(
	'pncp_nginx_status',
	array(
		'want'  => PNCP_Rules::nginx_fingerprint(),
		'body'  => 'aaaaaaaaaaaa bbbbbbbbbbbb',
		'error' => '',
	),
	300
);
PNCP_Rules_State::record( '' );
$st = PNCP_Rules_State::state();
t( 'S rules of before 3.12.3 (check address only): seen as installed, and out of date', PNCP_Rules_State::is_stale() && 'aaaaaaaaaaaa bbbbbbbbbbbb' === $st['installed'] );
t( 'S the message names both fingerprints and the tab', PNCP_Rules_State::message() === 'The server rules are out of date (installed: aaaaaaaaaaaa bbbbbbbbbbbb, current: ' . PNCP_Rules::nginx_fingerprint() . '). Copy them again from Server rules.', PNCP_Rules_State::message() );
delete_transient( 'pncp_nginx_status' );

// observe(): only an answer this WordPress gave to that very request counts (not a CDN's cached copy).
delete_option( PNCP_Rules_State::STATE );
$sig  = PNCP_Server_Ips::sig_token( 'GET', home_url( '/' ) );
$rid  = PNCP_Self_Check::request_id( $sig );
$resp = static function ( $marker, $rules ) {
	return array(
		'headers'  => array_filter(
			array(
				'x-scrapelock'       => $marker,
				'x-scrapelock-rules' => $rules,
			)
		),
		'body'     => 'page',
		'response' => array(
			'code'    => 200,
			'message' => 'OK',
		),
		'cookies'  => array(),
		'filename' => null,
	);
};
PNCP_Rules_State::observe( $resp( '', $fp ), $rid );
t( 'S observe(): an answer WordPress did not mark for this request is ignored', ! PNCP_Rules_State::in_use() );
PNCP_Rules_State::observe( $resp( PNCP_Self_Check::ok_marker( $rid ), $fp ), $rid );
t( 'S observe(): this WordPress\'s answer with the header: noted', PNCP_Rules_State::in_use() && ! PNCP_Rules_State::is_stale() );
PNCP_Rules_State::observe( $resp( PNCP_Self_Check::ok_marker( $rid ), PNCP_Rules::apache_fingerprint() ), $rid );
t( 'S observe(): an Apache fingerprint is compared with the Apache rules', 'apache' === PNCP_Rules_State::state()['format'] && ! PNCP_Rules_State::is_stale() );

/* ---------- N. Notice, Site Health and the diff ---------- */

$admins = get_users(
	array(
		'role'   => 'administrator',
		'number' => 1,
	)
);
$admin  = $admins[0]->ID;
$sub    = wp_insert_user(
	array(
		'user_login' => 'pncp3123sub' . wp_rand( 1000, 9999 ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'subscriber',
	)
);
// Old rules shown in the Server rules tab and copied, then a setting changed.
settings( array( 'block_empty_ua' => 1 ) );
PNCP_Rules_State::remember_texts();
$old_fp   = PNCP_Rules::nginx_fingerprint();
$old_afp  = PNCP_Rules::apache_fingerprint();
$old_ap   = PNCP_Rules::apache();
$old_text = PNCP_Rules::nginx();
delete_option( PNCP_Rules_State::STATE );
PNCP_Rules_State::record( $old_fp );
settings( array( 'block_empty_ua' => 0 ) );
t( 'N the text of the shown rules is kept under its fingerprint (Nginx and Apache)', PNCP_Rules_State::text_of( 'nginx', $old_fp ) === $old_text && PNCP_Rules_State::text_of( 'apache', $old_afp ) === $old_ap );
$notice = static function ( $user, $screen ) {
	wp_set_current_user( $user );
	set_current_screen( $screen );
	ob_start();
	PNCP_Rules_State::notice();
	return (string) ob_get_clean();
};
$html = $notice( $admin, 'dashboard' );
t( 'N notice: administrator on the dashboard, with the message and "See what changed"', false !== strpos( $html, esc_html( PNCP_Rules_State::message() ) ) && false !== strpos( $html, 'See what changed' ) && false !== strpos( $html, 'pncp_rules_diff=1' ) && false !== strpos( $html, '_wpnonce=' ), $html );
t( 'N notice: also on ScrapeLock\'s settings page', '' !== $notice( $admin, 'settings_page_' . PNCP_Admin::PAGE ) );
t( 'N notice: not on other screens (Posts)', '' === $notice( $admin, 'edit-post' ) );
t( 'N notice: never for a subscriber', '' === $notice( $sub, 'dashboard' ) );
$st              = PNCP_Rules_State::state();
$st['dismissed'] = $st['installed'] . '|' . $st['current'];
update_option( PNCP_Rules_State::STATE, $st, false );
t( 'N notice: dismissed for these fingerprints', '' === $notice( $admin, 'dashboard' ) );
settings( array( 'block_headless' => 0 ) );
t( 'N notice: back with other fingerprints', '' !== $notice( $admin, 'dashboard' ) );
settings( array( 'block_headless' => 1 ) );
wp_set_current_user( $admin );
$ht = PNCP_Rules_State::health_test();
t( 'N Site Health: "recommended", with the message and the button', 'recommended' === $ht['status'] && 'scrapelock_server_rules' === $ht['test'] && false !== strpos( $ht['description'], esc_html( PNCP_Rules_State::message() ) ) && false !== strpos( $ht['actions'], 'See what changed' ) );
t( 'N Site Health: the test is registered', isset( PNCP_Health::tests( array() )['direct']['scrapelock_server_rules'] ) );
wp_set_current_user( $sub );
t( 'N Site Health: no button without manage_options', '' === PNCP_Rules_State::health_test()['actions'] );
$diff = static function ( $user, $nonce ) {
	wp_set_current_user( $user );
	$_GET = array( PNCP_Rules_State::DIFF => '1' );
	if ( null !== $nonce ) {
		$_GET['_wpnonce'] = $nonce;
	}
	$out  = PNCP_Rules_State::render_diff();
	$_GET = array();
	return $out;
};
wp_set_current_user( $admin );
$good = wp_create_nonce( PNCP_Rules_State::DIFF );
$d    = $diff( $admin, $good );
t( 'N diff: a line diff of the installed rules against the current ones', false !== strpos( $d, 'What changed in the server rules' ) && preg_match( '/<table class=["\']diff/', $d ) && false !== strpos( $d, 'Installed' ) && false !== strpos( $d, 'Current' ), substr( $d, 0, 300 ) );
t( 'N diff: without a valid nonce, nothing is shown', false === strpos( $diff( $admin, 'bad' ), '<table' ) && false === strpos( $diff( $admin, null ), '<table' ) );
t( 'N diff: never for a subscriber', '' === $diff( $sub, wp_create_nonce( PNCP_Rules_State::DIFF ) ) );
$st              = PNCP_Rules_State::state();
$st['installed'] = 'cccccccccccc dddddddddddd';
update_option( PNCP_Rules_State::STATE, $st, false );
wp_set_current_user( $admin );
$d = $diff( $admin, wp_create_nonce( PNCP_Rules_State::DIFF ) );
t( 'N diff: the installed text unknown: the current rules, and says so', false !== strpos( $d, 'The text of the installed rules is not known' ) && false !== strpos( $d, esc_textarea( PNCP_Rules::nginx() ) ) );
// The dismissal over HTTP: admin-post with nonce and manage_options.
$cookies = static function ( $user ) {
	$expire = time() + HOUR_IN_SECONDS;
	$token  = WP_Session_Tokens::get_instance( $user )->create( $expire );
	return array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user, $expire, 'logged_in', $token ),
		'cookie_line'    => '',
		'token'          => $token,
		'expire'         => $expire,
	);
};
$post = static function ( $user, $nonce ) use ( $base, $cookies ) {
	$c = $cookies( $user );
	$_COOKIE[ LOGGED_IN_COOKIE ] = $c[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user );
	$nonce = true === $nonce ? wp_create_nonce( PNCP_Rules_State::DISMISS ) : $nonce;
	$ch    = curl_init( $base . '/wp-admin/admin-post.php' );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => http_build_query(
				array(
					'action'   => PNCP_Rules_State::DISMISS,
					'_wpnonce' => $nonce,
				)
			),
			CURLOPT_COOKIE         => AUTH_COOKIE . '=' . rawurlencode( $c[ AUTH_COOKIE ] ) . '; ' . LOGGED_IN_COOKIE . '=' . rawurlencode( $c[ LOGGED_IN_COOKIE ] ),
			CURLOPT_HTTPHEADER     => array( 'User-Agent: ' . BROWSER, 'Accept-Language: en' ),
			CURLOPT_TIMEOUT        => 30,
			CURLOPT_PROXY          => '',
		)
	);
	curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	wp_cache_delete( PNCP_Rules_State::STATE, 'options' );
	return $code;
};
$st              = PNCP_Rules_State::state();
$st['dismissed'] = '';
update_option( PNCP_Rules_State::STATE, $st, false );
$code = $post( $sub, true );
t( 'N Dismiss: refused for a subscriber', 403 === $code && '' === PNCP_Rules_State::state()['dismissed'], (string) $code );
$code = $post( $admin, 'bad' );
t( 'N Dismiss: refused without a valid nonce', in_array( $code, array( 403, 400 ), true ) && '' === PNCP_Rules_State::state()['dismissed'], (string) $code );
$code = $post( $admin, true );
$st   = PNCP_Rules_State::state();
t( 'N Dismiss: an administrator with the nonce dismisses it for these fingerprints', 302 === $code && $st['installed'] . '|' . $st['current'] === $st['dismissed'], $code . ' ' . wp_json_encode( $st ) );
wp_set_current_user( 0 );
settings( array( 'block_empty_ua' => 1 ) );

/* ---------- E. The evaluator and the self-check ---------- */

$fake = array(
	'ua'      => OLD_UA,
	'headers' => array( 'Accept' => 'text/html' ),
	'https'   => true,
	'method'  => 'GET',
	'path'    => '/',
);
$cases = array(
	'a visitor'                                  => array( VISITOR, array(), 'fake_browser' ),
	'127.0.0.1 straight'                         => array( '127.0.0.1', array(), null ),
	'::1 straight'                               => array( '::1', array(), null ),
	'the private address straight'               => array( PRIV, array(), null ),
	'127.0.0.1 with X-Forwarded-For (a proxy)'   => array( '127.0.0.1', array( 'X-Forwarded-For' => VISITOR ), 'fake_browser' ),
	'the private address with CF-Connecting-IP'  => array( PRIV, array( 'CF-Connecting-IP' => VISITOR ), 'fake_browser' ),
	'the public address (real_ip behind a CDN)'  => array( SERVER, array( 'X-Forwarded-For' => SERVER ), null ),
	'an address of the IPv6 range'               => array( '2a01:4f8:5::7', array(), null ),
	'the CDN edge'                               => array( EDGE, array( 'X-Forwarded-For' => SERVER ), 'fake_browser' ),
);
foreach ( $cases as $label => $case ) {
	$req           = $fake;
	$req['remote'] = $case[0];
	$req['headers'] = array_merge( $req['headers'], $case[1] );
	$got           = PNCP_Rules::evaluate( $req );
	t( "E fake Chrome from $label → " . ( null === $case[2] ? 'passes' : $case[2] ), ( null === $got ? null : $got['rule'] ) === $case[2], wp_json_encode( $got ) );
}
$got = PNCP_Rules::evaluate( $fake + array( 'remote' => '' ) );
t( 'E a fake Chrome (HTTPS, no Sec-Fetch-Mode, no Sec-CH-UA): the fake browser rule', 'fake_browser' === ( $got['rule'] ?? '' ) && 403 === ( $got['code'] ?? 0 ), wp_json_encode( $got ) );
t( 'E the new self-check User-Agent: no rule refuses it', null === PNCP_Rules::evaluate( array_merge( $fake, array( 'ua' => PNCP_Self_Check::user_agent() ) ) ) );
// The self-check got a 403 of the web server that WordPress never saw.
$nginx403 = static function ( $pre, $args, $url ) {
	if ( false !== $pre || ! empty( $args['pncp_resolve'] ) ) {
		return $pre;
	}
	return array(
		'headers'  => array(
			'server'       => 'nginx',
			'content-type' => 'text/html',
		),
		'body'     => "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>",
		'response' => array(
			'code'    => 403,
			'message' => 'Forbidden',
		),
		'cookies'  => array(),
		'filename' => null,
	);
};
$https = static function ( $url ) {
	return set_url_scheme( $url, 'https' );
};
add_filter( 'pre_http_request', $nginx403, 1, 3 );
$cls = PNCP_Self_Check::rules_class( PNCP_Self_Check::classify( 403, array( 'server' => 'nginx' ), '<center>nginx</center>' ), $nginx403( false, array(), '' ), 'https://example.test/', array( 'user-agent' => OLD_UA ), '' );
t( 'E rules_class(): the old Chrome self-check → ScrapeLock\'s own server rule (fake browser)', 'rules' === $cls['who'] && 'fake_browser' === $cls['reason'] );
t( 'E who_label(): "ScrapeLock\'s own server rule (fake browser)"', 'ScrapeLock\'s own server rule (fake browser)' === PNCP_Self_Check::who_label( $cls ) );
t( 'E advice(): what to do, in one sentence', false !== strpos( PNCP_Self_Check::advice( $cls + array( 'sig' => '' ) ), 'Copy the server rules again' ) );
$cls2 = PNCP_Self_Check::rules_class( PNCP_Self_Check::classify( 403, array( 'server' => 'nginx' ), '<center>nginx</center>' ), $nginx403( false, array(), '' ), 'https://example.test/', array( 'user-agent' => PNCP_Self_Check::user_agent() ), '' );
t( 'E rules_class(): a 403 the rules would not give stays "web server"', 'server' === $cls2['who'] );
$marked = $nginx403( false, array(), '' );
$marked['headers']['x-scrapelock'] = 'refused';
$cls3 = PNCP_Self_Check::rules_class( PNCP_Self_Check::answer_class( $marked ), $marked, 'https://example.test/', array( 'user-agent' => OLD_UA ), '' );
t( 'E rules_class(): ScrapeLock\'s own PHP refusal (X-ScrapeLock) is never taken for a server rule', 'scrapelock' === $cls3['who'] );
// A whole self-check through request(): the public way refused by the rules, the server answers straight.
add_filter( 'home_url', $https, 99 );
add_filter(
	'pre_http_request',
	$origin_ok = static function ( $pre, $args, $url ) {
		if ( empty( $args['pncp_resolve'] ) ) {
			return $pre;
		}
		$id = PNCP_Self_Check::request_id( (string) ( $args['headers']['X-ScrapeLock-Sig'] ?? '' ) );
		return array(
			'headers'  => array( 'x-scrapelock' => PNCP_Self_Check::ok_marker( $id ) ),
			'body'     => 'page',
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	},
	0,
	3
);
$old_args = array(
	'user-agent' => OLD_UA,
	'headers'    => array( 'Accept' => 'text/html' ),
);
// request() sends the new User-Agent whatever it is given; a 3.12.2 request (old User-Agent) is classified here.
$public = PNCP_Self_Check::rules_class( PNCP_Self_Check::answer_class( $nginx403( false, array(), '' ) ), $nginx403( false, array(), '' ), home_url( '/' ), $old_args, '' );
$trace  = array(
	'public' => $public,
	'ok'     => false,
	'origin' => true,
	'steps'  => array(
		array(
			'via'    => 'public',
			'ip'     => '',
			'path'   => '/',
			'code'   => 403,
			'error'  => '',
			'server' => 'nginx',
			'cdn'    => '',
			'marker' => '',
			'who'    => $public['who'],
			'reason' => $public['reason'],
			'id'     => '',
		),
	),
);
$lines = implode( "\n", PNCP_Self_Check::lines( $trace ) );
t( 'E "Run a real self-check now": "Refused by ScrapeLock\'s own server rule (fake browser)" and what to do', false !== strpos( $lines, 'Refused by ScrapeLock\'s own server rule (fake browser)' ) && false !== strpos( $lines, 'Copy the server rules again' ), $lines );
t( 'E the summary names the rule', false !== strpos( PNCP_Self_Check::summary( $trace ), 'refused by ScrapeLock\'s own server rule (fake browser) (HTTP 403)' ), PNCP_Self_Check::summary( $trace ) );
$r = PNCP_Self_Check::request( home_url( '/' ), $old_args, 'page' );
t( 'E request(): the new User-Agent is not refused by the rules: the 403 stays the web server\'s', 'server' === $r['public']['who'] && 'origin' === $r['via'], wp_json_encode( $r['public'] ) );
settings( array( 'block_headless' => 1 ) );
PNCP_Rules_State::record( 'eeeeeeeeeeee ffffffffffff' );
$lines = implode( "\n", PNCP_Self_Check::lines( $trace ) );
t( 'E the self-check also says when the installed rules are out of date', false !== strpos( $lines, 'The server rules are out of date (installed: eeeeeeeeeeee ffffffffffff' ), $lines );
remove_filter( 'pre_http_request', $origin_ok, 0 );
remove_filter( 'pre_http_request', $nginx403, 1 );
remove_filter( 'home_url', $https, 99 );
delete_option( PNCP_Rules_State::STATE );
delete_transient( PNCP_Self_Check::ROUTE );

// The table: what the rules do, by the evaluator; with real Nginx, the same answers from Nginx.
$sec   = array(
	'Sec-Fetch-Mode' => 'navigate',
	'Sec-CH-UA'      => '"Chromium";v="141"',
);
$table = array(
	array( 'fake Chrome over HTTPS', VISITOR, OLD_UA, array(), true, '/', 'fake_browser' ),
	array( 'Chrome with browser headers', VISITOR, BROWSER, $sec, true, '/', null ),
	array( 'fake Chrome over HTTP', VISITOR, OLD_UA, array(), false, '/', null ),
	array( 'fake Chrome from 127.0.0.1', '127.0.0.1', OLD_UA, array(), true, '/', null ),
	array( 'fake Chrome from 127.0.0.1 via a proxy', '127.0.0.1', OLD_UA, array( 'X-Real-IP' => VISITOR ), true, '/', 'fake_browser' ),
	array( 'fake Chrome from the server\'s public address', SERVER, OLD_UA, array( 'X-Forwarded-For' => SERVER ), true, '/', null ),
	array( 'fake Chrome from the edge', EDGE, OLD_UA, array(), true, '/', 'fake_browser' ),
	array( 'HeadlessChrome (in the bot list too)', VISITOR, 'Mozilla/5.0 HeadlessChrome/120.0.0.0 Safari/537.36', $sec, true, '/', 'bad_bot' ),
	array( 'Firefox without Sec-Fetch-Mode', VISITOR, 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0', array(), true, '/', 'fake_browser' ),
	array( 'Android in-app browser', VISITOR, 'Mozilla/5.0 (Linux; Android 14; wv) AppleWebKit/537.36 Chrome/141.0.0.0 Mobile Safari/537.36', array(), true, '/', null ),
	array( 'Googlebot (Chrome in its User-Agent)', VISITOR, 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/141.0.0.0 Safari/537.36', array(), true, '/', null ),
	array( 'GPTBot', VISITOR, 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)', array(), true, '/', 'bad_bot' ),
	array( 'GPTBot on robots.txt', VISITOR, 'Mozilla/5.0 (compatible; GPTBot/1.2)', array(), true, '/robots.txt', null ),
	array( 'GPTBot from the server', SERVER, 'Mozilla/5.0 (compatible; GPTBot/1.2)', array(), true, '/', null ),
	array( 'ChatGPT-User (AI search allowed)', VISITOR, CHATGPT, array(), true, '/', null ),
	array( 'empty User-Agent', VISITOR, '', array(), true, '/', 'empty_ua' ),
	array( 'empty User-Agent from ::1', '::1', '', array(), true, '/', null ),
	array( 'Facebook preview (always allowed)', VISITOR, 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)', array(), true, '/', null ),
	array( 'the self-check User-Agent', VISITOR, PNCP_Self_Check::user_agent(), array(), true, '/', null ),
	array( 'readme.html', VISITOR, BROWSER, $sec, true, '/readme.html', 'version_file' ),
	array( 'PHP in uploads', VISITOR, BROWSER, $sec, true, wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH ) . '/x.php', 'upload_php' ),
	array( 'image from another site', VISITOR, BROWSER, $sec + array( 'Referer' => 'https://scraper.example/' ), true, wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH ) . '/a.jpg', 'hotlink' ),
	array( 'image from Google', VISITOR, BROWSER, $sec + array( 'Referer' => 'https://www.google.gr/' ), true, wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH ) . '/a.jpg', null ),
);
$bad = array();
foreach ( $table as $row ) {
	$got = PNCP_Rules::evaluate(
		array(
			'ua'      => $row[2],
			'headers' => $row[3],
			'https'   => $row[4],
			'path'    => $row[5],
			'remote'  => $row[1],
		)
	);
	if ( ( null === $got ? null : $got['rule'] ) !== $row[6] ) {
		$bad[] = $row[0] . ': ' . wp_json_encode( $got );
	}
}
t( 'E the evaluator on ' . count( $table ) . ' requests: the rule each one meets', ! $bad, implode( ' | ', $bad ) );

// Real Nginx (local only: CI has none).
$nginx_bin = trim( (string) shell_exec( 'command -v nginx 2>/dev/null' ) );
$openssl   = trim( (string) shell_exec( 'command -v openssl 2>/dev/null' ) );
if ( '' === $nginx_bin || '' === $openssl || ! function_exists( 'curl_init' ) ) {
	echo "SKIP E real Nginx (nginx or openssl not on PATH)\n";
} else {
	$dir = sys_get_temp_dir() . '/pncp-t3123-nginx-' . getmypid();
	$img = $dir . '/www' . wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH );
	wp_mkdir_p( $dir . '/tmp' );
	wp_mkdir_p( $img );
	file_put_contents( $img . '/a.jpg', 'jpeg' );
	exec( 'openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=pncp-test -keyout ' . escapeshellarg( $dir . '/k.pem' ) . ' -out ' . escapeshellarg( $dir . '/c.pem' ) . ' -days 1 2>/dev/null' );
	$port = 18000 + ( getmypid() % 1000 );
	file_put_contents( $dir . '/http.conf', PNCP_Rules::nginx_http() );
	file_put_contents( $dir . '/server.conf', PNCP_Rules::nginx_server() );
	$conf = 'worker_processes 1; error_log ' . $dir . '/error.log; pid ' . $dir . '/nginx.pid; events { worker_connections 64; }' . "\n"
		. 'http { access_log off; client_body_temp_path ' . $dir . '/tmp; proxy_temp_path ' . $dir . '/tmp; fastcgi_temp_path ' . $dir . '/tmp; uwsgi_temp_path ' . $dir . '/tmp; scgi_temp_path ' . $dir . '/tmp;' . "\n"
		. 'include ' . $dir . '/http.conf;' . "\n"
		. 'server { listen 127.0.0.1:' . $port . ' ssl; listen 127.0.0.1:' . ( $port + 1 ) . '; ssl_certificate ' . $dir . '/c.pem; ssl_certificate_key ' . $dir . '/k.pem; server_name _; root ' . $dir . '/www;' . "\n"
		// The address Nginx sees, set per request (as real_ip does behind a CDN).
		. 'set_real_ip_from 127.0.0.1; real_ip_header X-Test-Remote;' . "\n"
		. 'include ' . $dir . '/server.conf;' . "\n"
		. 'location / { return 200 "ok\n"; }' . "\n"
		. 'location /own-headers/ { add_header X-Own 1; return 200 "own\n"; } }' . "\n}\n";
	file_put_contents( $dir . '/nginx.conf', $conf );
	exec( escapeshellarg( $nginx_bin ) . ' -t -e ' . escapeshellarg( $dir . '/error.log' ) . ' -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' 2>&1', $tout, $rc );
	t( 'E real Nginx: nginx -t accepts both parts', 0 === $rc, implode( ' | ', $tout ) );
	exec( escapeshellarg( $nginx_bin ) . ' -e ' . escapeshellarg( $dir . '/error.log' ) . ' -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' 2>&1', $sout, $src );
	usleep( 500000 );
	$get = static function ( $https, $path, $remote, $ua, $headers ) use ( $port ) {
		$ch = curl_init( ( $https ? 'https' : 'http' ) . '://127.0.0.1:' . ( $https ? $port : $port + 1 ) . $path );
		$h  = array( 'User-Agent: ' . $ua, 'X-Test-Remote: ' . $remote );
		foreach ( $headers as $k => $v ) {
			$h[] = $k . ': ' . $v;
		}
		curl_setopt_array(
			$ch,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HEADER         => true,
				CURLOPT_HTTPHEADER     => $h,
				CURLOPT_SSL_VERIFYPEER => false,
				CURLOPT_SSL_VERIFYHOST => 0,
				CURLOPT_TIMEOUT        => 10,
				CURLOPT_PROXY          => '',
			)
		);
		$out  = (string) curl_exec( $ch );
		$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
		curl_close( $ch );
		return array( $code, strtolower( substr( $out, 0, $hs ) ) );
	};
	if ( 0 === $src ) {
		$codes = array(
			'fake_browser' => 403,
			'bad_bot'      => 403,
			'empty_ua'     => 403,
			'version_file' => 404,
			'upload_php'   => 403,
			'hotlink'      => 403,
		);
		$bad   = array();
		foreach ( $table as $row ) {
			list( $code ) = $get( $row[4], $row[5], $row[1], $row[2], $row[3] );
			$want         = null === $row[6] ? 200 : $codes[ $row[6] ];
			if ( $want !== $code ) {
				$bad[] = $row[0] . ': nginx ' . $code . ', evaluator ' . $want;
			}
		}
		t( 'E real Nginx agrees with the evaluator on ' . count( $table ) . ' requests', ! $bad, implode( ' | ', $bad ) );
		list( , $h1 ) = $get( true, '/', '127.0.0.1', BROWSER, $sec );
		list( , $h2 ) = $get( true, '/', '127.0.0.1', BROWSER, $sec + array( 'X-ScrapeLock-Sig' => 'x' ) );
		list( , $h3 ) = $get( true, '/own-headers/', '127.0.0.1', BROWSER, $sec + array( 'X-ScrapeLock-Sig' => 'x' ) );
		t( 'E real Nginx: no fingerprint header without X-ScrapeLock-Sig', false === strpos( $h1, 'x-scrapelock-rules' ) );
		t( 'E real Nginx: with X-ScrapeLock-Sig, the header is the current fingerprint', false !== strpos( $h2, 'x-scrapelock-rules: ' . PNCP_Rules::nginx_fingerprint() . "\r\n" ), $h2 );
		t( 'E real Nginx: a location with add_header of its own drops it (the documented limitation)', false === strpos( $h3, 'x-scrapelock-rules' ) && false !== strpos( $h3, 'x-own: 1' ) );
	} else {
		t( 'E real Nginx starts', false, implode( ' | ', $sout ) );
	}
	if ( is_file( $dir . '/nginx.pid' ) ) {
		exec( 'kill ' . (int) file_get_contents( $dir . '/nginx.pid' ) );
		usleep( 300000 );
	}
	@unlink( $img . '/a.jpg' );
	for ( $d = $img; strlen( $d ) > strlen( $dir ); $d = dirname( $d ) ) {
		@rmdir( $d );
	}
	foreach ( array( 'http.conf', 'server.conf', 'nginx.conf', 'c.pem', 'k.pem', 'error.log', 'nginx.pid' ) as $f ) {
		@unlink( $dir . '/' . $f );
	}
	@rmdir( $dir . '/tmp' );
	@rmdir( $dir );
}

wp_delete_user( $sub );
exit( $fails ? 1 : 0 );
