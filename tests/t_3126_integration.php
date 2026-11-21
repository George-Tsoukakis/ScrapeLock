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
 * U. uninstall.php deletes every option and event of 3.12.6; deactivation removes the verification files (a copy
 *    in the root folder would otherwise stay served after its time).
 * C. wp scrapelock rules status: the Stealth rules' fields from the real PNCP_Stealth_Status::status(true) (keys
 *    state, installed, want), only while Stealth is turned on.
 * A. The admin pages: the Server rules tab (Apache, Nginx, Stealth, fail2ban, Verification files, no PHP warnings),
 *    the main rules notice and the Stealth rules notice each once (dashboard, tab), the second check before "not
 *    found", a dismissed Stealth notice; the export and import carry block_tech_profilers.
 * W. A settings save before init (as pncp_upgrade() on plugins_loaded): the wizard's watcher loads no translation
 *    then (no "_load_textdomain_just_in_time" notice) and still notes the choice on init.
 * S. Security (static): proc_open() only in the CLI class, its entry points stop outside WP-CLI, the commands are
 *    built with escapeshellarg() or are --test-cmd / --reload-cmd (documented as run through the shell).
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

/* ---------- U. Uninstall and deactivation ---------- */

$pncp_uninstall = (string) file_get_contents( PNCP_DIR . 'uninstall.php' );
foreach ( array( PNCP_Verify_Files::INDEX, PNCP_Verify_Files::DATA, PNCP_Wizard::STATE, PNCP_Stealth_Status::SEEN, PNCP_Rules_State::STATE ) as $pncp_name ) {
	t( "U uninstall.php deletes the option $pncp_name", false !== strpos( $pncp_uninstall, "delete_option( '$pncp_name' )" ) );
}
t( 'U uninstall.php removes the verification files\' event (also when remove_all() fails)', (bool) preg_match( "/foreach \\( array\\([^)]*'" . PNCP_Verify_Files::CRON . "'[^)]*\\) as \\\$pncp_hook \\)/", $pncp_uninstall ) );
t( 'U uninstall.php: the Stealth status transient goes with every _transient_pncp_ row', 0 === strpos( PNCP_Stealth_Status::STATUS, 'pncp_' ) && false !== strpos( $pncp_uninstall, "esc_like( '_transient_pncp_' )" ) );
t( 'U uninstall.php: remove_all() first (only ScrapeLock\'s own files in the root folder)', false !== strpos( $pncp_uninstall, 'PNCP_Verify_Files::remove_all();' ) );
$pncp_main = (string) file_get_contents( PNCP_FILE );
t( 'U deactivation removes the verification files (nothing would remove them on time without the plugin)', (bool) preg_match( '/function pncp_deactivate_site\(\) \{.*?PNCP_Verify_Files::remove_all\(\);.*?\n\}/s', $pncp_main ) );
$added = PNCP_Verify_Files::add( '/BingSiteAuth.xml', '<?xml version="1.0"?><users><user>X3126</user></users>', 2, true );
$pncp_disk = $tmp . '/root/BingSiteAuth.xml';
t( 'U a file written to the root folder, with its event', is_array( $added ) && 'written' === $added['disk'] && is_file( $pncp_disk ) && false !== wp_next_scheduled( PNCP_Verify_Files::CRON ), wp_json_encode( $added ) );
PNCP_Verify_Files::remove_all();
t( 'U remove_all() (deactivation, uninstall): the file in the root folder, both options and the event go', ! is_file( $pncp_disk ) && false === get_option( PNCP_Verify_Files::INDEX ) && false === get_option( PNCP_Verify_Files::DATA ) && false === wp_next_scheduled( PNCP_Verify_Files::CRON ) );

/* ---------- C. wp scrapelock rules status and the Stealth rules' own status ---------- */

$pncp_status_keys = array( 'state', 'installed', 'want' );
$pncp_st          = PNCP_Stealth_Status::status( true );
t( 'C PNCP_Stealth_Status::status(true) has the keys "rules status" reads (state, installed, want), as strings', array() === array_diff( $pncp_status_keys, array_keys( $pncp_st ) ) && is_string( $pncp_st['state'] ) && is_string( $pncp_st['installed'] ) && is_string( $pncp_st['want'] ) && in_array( $pncp_st['state'], array( 'current', 'stale', 'unmarked', 'missing', 'error' ), true ), wp_json_encode( $pncp_st ) );
if ( '' === $wp_cli ) {
	echo "SKIP C wp scrapelock rules status (no WP_CLI)\n";
} else {
	$pncp_cli = static function ( $args ) use ( $wp_cli ) {
		exec( $wp_cli . ' scrapelock ' . $args . ' < /dev/null 2>/dev/null', $out, $rc );
		wp_cache_flush();
		return array( $rc, implode( "\n", $out ) );
	};
	settings( array( 'stealth_enabled' => 0 ) );
	list( $rc, $out ) = $pncp_cli( 'rules status --format=json' );
	$pncp_json        = json_decode( $out, true );
	t( 'C Stealth off: rules status has no stealth_ fields', 0 === $rc && is_array( $pncp_json ) && ! preg_grep( '/^stealth_/', array_keys( $pncp_json ) ), $out );
	settings( array( 'stealth_enabled' => 1 ) );
	PNCP_Stealth_Status::reset();
	$pncp_want        = PNCP_Stealth_Status::current( PNCP_Stealth_Status::format() );
	list( $rc, $out ) = $pncp_cli( 'rules status --format=json' );
	$pncp_json        = json_decode( $out, true );
	t( 'C Stealth on: stealth_state, stealth_installed and stealth_current from the real PNCP_Stealth_Status::status(true)', 0 === $rc && is_array( $pncp_json ) && isset( $pncp_json['stealth_state'], $pncp_json['stealth_installed'], $pncp_json['stealth_current'] ) && in_array( $pncp_json['stealth_state'], array( 'current', 'stale', 'unmarked', 'missing', 'error' ), true ) && $pncp_want === $pncp_json['stealth_current'] && (bool) preg_match( '/^[0-9a-f]{12}$/', $pncp_json['stealth_current'] ), $out . ' want ' . $pncp_want );
	t( 'C ...a fresh check: the kept Stealth status is the one the command just made', null !== PNCP_Stealth_Status::kept_status() && PNCP_Stealth_Status::kept_status()['state'] === $pncp_json['stealth_state'] );
	list( $rc, $out ) = $pncp_cli( 'rules status' );
	t( 'C the table has the same three rows', 0 === $rc && (bool) preg_match( '/stealth_state\s+\S+/', $out ) && (bool) preg_match( '/stealth_current\s+' . preg_quote( $pncp_want, '/' ) . '/', $out ), $out );
	settings( array( 'stealth_enabled' => 0 ) );
}

/* ---------- A. The admin pages: the Server rules tab, the notices, export ---------- */

$pncp_admin   = get_user_by( 'id', 1 );
$pncp_expire  = time() + DAY_IN_SECONDS;
$pncp_token   = WP_Session_Tokens::get_instance( $pncp_admin->ID )->create( $pncp_expire );
$pncp_cookies = 'wordpress_' . COOKIEHASH . '=' . rawurlencode( wp_generate_auth_cookie( $pncp_admin->ID, $pncp_expire, 'auth', $pncp_token ) ) . '; ' . LOGGED_IN_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( $pncp_admin->ID, $pncp_expire, 'logged_in', $pncp_token ) );
$pncp_page    = static function ( $path ) use ( $pncp_cookies ) {
	return req( $path, BROWSER, 'GET', $pncp_cookies );
};
$pncp_errors  = static function ( $body ) {
	return (bool) preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
};
// Each notice once: the main rules out of date (E4) and the Stealth rules to copy again (E5), both at once.
$pncp_saved_state = get_option( PNCP_Rules_State::STATE, null );
settings( array( 'stealth_enabled' => 1 ) );
PNCP_Stealth_Status::reset();
$pncp_now = PNCP_Rules::nginx_fingerprint();
update_option(
	PNCP_Rules_State::STATE,
	array(
		'installed' => 'aaaaaaaaaaaa bbbbbbbbbbbb',
		'format'    => 'nginx',
		'current'   => $pncp_now,
		'time'      => time(),
		'seen'      => time(),
		'dismissed' => '',
	),
	false
);
update_option(
	PNCP_Stealth_Status::SEEN,
	array(
		'installed' => 'cccccccccccc',
		'time'      => time(),
		'base'      => (string) PNCP_Stealth::settings()['stealth_base'],
		'folders'   => PNCP_Stealth_Status::folders(),
		'dismissed' => '',
	),
	false
);
t( 'A set up: main rules out of date and Stealth rules to copy again', PNCP_Rules_State::is_stale() && 'changed' === PNCP_Stealth_Status::needs_copy(), PNCP_Stealth_Status::needs_copy() );
list( $code, $h, $body ) = $pncp_page( '/wp-admin/index.php' );
t( 'A dashboard: 200, no PHP warnings', 200 === $code && ! $pncp_errors( $body ), (string) $code );
t( 'A dashboard: the main rules notice once, the Stealth rules notice once (two different files, two notices)', 1 === substr_count( $body, 'notice notice-warning pncp-rules-stale' ) && 1 === substr_count( $body, 'pncp-stealth-rules-stale' ), substr_count( $body, 'pncp-rules-stale' ) . ' ' . substr_count( $body, 'pncp-stealth-rules-stale' ) );
t( 'A dashboard: no second check due, so no recheck script', false === strpos( $body, 'pncp-rules-recheck' ) );
list( $code, $h, $body ) = $pncp_page( '/wp-admin/options-general.php?page=scrapelock&tab=hardening' );
t( 'A Vulnerable points → Stealth: one line about the Stealth server rules, not two', 200 === $code && ! $pncp_errors( $body ) && substr_count( $body, 'id="pncp-stealth-card-rules"' ) + substr_count( $body, 'A plugin or theme changed: copy the new server rules below' ) <= 1, (string) $code );
list( $code, $h, $body ) = $pncp_page( '/wp-admin/options-general.php?page=scrapelock&tab=rules' );
t( 'A Server rules tab: 200, no PHP warnings', 200 === $code && ! $pncp_errors( $body ), (string) $code );
$pncp_pos = array();
foreach ( array( 'id="pncp-rules-apache"', 'id="pncp-rules-nginx"', 'id="pncp-rules-stealth"', 'id="pncp-rules-fail2ban"', 'id="pncp-verify-files"' ) as $pncp_id ) {
	$pncp_pos[ $pncp_id ] = strpos( $body, $pncp_id );
}
$pncp_sorted = $pncp_pos;
asort( $pncp_sorted );
t( 'A Server rules tab: Apache, Nginx (parts 1 and 2), Stealth, fail2ban, Verification files, in that order', ! in_array( false, $pncp_pos, true ) && array_keys( $pncp_pos ) === array_keys( $pncp_sorted ), wp_json_encode( $pncp_pos ) );
t( 'A ...the Stealth card: its status, the aaPanel place and both rule sets', false !== strpos( $body, 'id="pncp-stealth-rules-status"' ) && false !== strpos( $body, 'z-scrapelock-stealth.conf' ) && false !== strpos( $body, 'id="pncp-stealth-nginx"' ) && false !== strpos( $body, 'id="pncp-stealth-apache"' ) );
t( 'A ...the Verification files card: the form with its nonce', false !== strpos( $body, 'name="op" value="add"' ) && (bool) preg_match( '/name="_wpnonce" value="[0-9a-f]{10}"/', $body ) );
t( 'A ...each notice once on the tab too', 1 === substr_count( $body, 'notice notice-warning pncp-rules-stale' ) && 1 === substr_count( $body, 'pncp-stealth-rules-stale' ) );
// "Not found" only after a second check: the first miss makes the page ask again, and only once.
$pncp_state         = PNCP_Rules_State::state();
$pncp_state['installed'] = $pncp_now;
$pncp_state['miss'] = time();
$pncp_state['gone'] = 0;
update_option( PNCP_Rules_State::STATE, $pncp_state, false );
delete_transient( 'pncp_nginx_status' );
list( $code, $h, $body ) = $pncp_page( '/wp-admin/index.php' );
t( 'A a first miss: no notice yet, the page asks again a few seconds later (one script)', 200 === $code && 0 === substr_count( $body, 'notice notice-warning pncp-rules-stale' ) && 1 === substr_count( $body, 'id="pncp-rules-recheck"' ), substr_count( $body, 'pncp-rules-stale' ) . ' ' . substr_count( $body, 'pncp-rules-recheck' ) );
// Dismissed Stealth notice: gone until the rules change again; the main one stays.
update_option( PNCP_Rules_State::STATE, array_merge( $pncp_state, array( 'installed' => 'aaaaaaaaaaaa bbbbbbbbbbbb', 'miss' => 0 ) ), false );
$pncp_seen              = PNCP_Stealth_Status::seen();
$pncp_seen['dismissed'] = 'changed|cccccccccccc|' . PNCP_Stealth_Status::current( PNCP_Stealth_Status::format() );
update_option( PNCP_Stealth_Status::SEEN, $pncp_seen, false );
list( $code, $h, $body ) = $pncp_page( '/wp-admin/index.php' );
t( 'A the Stealth notice dismissed: only the main rules notice is left', 1 === substr_count( $body, 'notice notice-warning pncp-rules-stale' ) && 0 === substr_count( $body, 'pncp-stealth-rules-stale' ) );
if ( null === $pncp_saved_state ) {
	delete_option( PNCP_Rules_State::STATE );
} else {
	update_option( PNCP_Rules_State::STATE, $pncp_saved_state, false );
}
delete_option( PNCP_Stealth_Status::SEEN );
settings( array( 'stealth_enabled' => 0 ) );

// The settings export and import carry the new switch; nothing of the new options goes into the export.
settings( array( 'block_tech_profilers' => 1 ) );
$pncp_export = PNCP_Settings_Io::export();
t( 'A export: block_tech_profilers is in it (1), and no option of the new parts (verification files, wizard state, Stealth status)', isset( $pncp_export['settings']['block_tech_profilers'] ) && 1 === (int) $pncp_export['settings']['block_tech_profilers'] && false === strpos( (string) wp_json_encode( $pncp_export ), 'pncp_verify_files' ) && false === strpos( (string) wp_json_encode( $pncp_export ), 'pncp_wizard_state' ), wp_json_encode( array_keys( $pncp_export ) ) );
t( 'A import: block_tech_profilers is a public key', in_array( 'block_tech_profilers', PNCP_Settings_Io::public_keys(), true ) );
settings( array( 'block_tech_profilers' => 0 ) );

/* ---------- W. A settings save before init (the upgrade on plugins_loaded) ---------- */

if ( '' === $wp_cli ) {
	echo "SKIP W a save before init (no WP_CLI)\n";
} else {
	// A temporary must-use plugin saves the settings on plugins_loaded, as pncp_upgrade() does on the first
	// request after an update (it adds block_tech_profilers): the wizard's watcher must not load translations
	// before init, and must still note a choice against a proposal once init has run.
	$pncp_mu = WP_CONTENT_DIR . '/mu-plugins/pncp-test-3126-early-save.php';
	file_put_contents(
		$pncp_mu,
		"<?php\n// TESTS ONLY: written and removed by tests/t_3126_integration.php.\n"
		. "add_action( 'plugins_loaded', static function () { if ( get_option( 'pncp_test_3126_early_save' ) ) { delete_option( 'pncp_test_3126_early_save' ); \$s = get_option( PNCP_OPTION ); \$s['bot_list'] = (string) \$s['bot_list'] . \"\\nEarlySave3126Bot\"; update_option( PNCP_OPTION, \$s ); } }, 99 );\n"
	);
	register_shutdown_function(
		static function () use ( $pncp_mu ) {
			if ( is_file( $pncp_mu ) ) {
				unlink( $pncp_mu );
			}
			delete_option( 'pncp_test_3126_early_save' );
		}
	);
	$pncp_wstate = get_option( PNCP_Wizard::STATE, null );
	delete_option( PNCP_Wizard::STATE );
	settings(
		array(
			'block_tech_profilers' => 0,
			'bot_list'             => $pncp_bots . "\nBuiltWith",
		)
	);
	t( 'W set up: the profilers proposal is there (BuiltWith in the bot list, the switch off)', isset( PNCP_Wizard::proposals()['block_tech_profilers'] ) );
	update_option( 'pncp_test_3126_early_save', 1, false );
	exec( $wp_cli . ' eval ' . escapeshellarg( 'echo did_action( "init" ) ? "init-done" : "no-init";' ) . ' < /dev/null 2>&1', $pncp_out, $pncp_rc );
	$pncp_out = implode( "\n", $pncp_out );
	wp_cache_flush();
	PNCP_Options::flush();
	t( 'W the save on plugins_loaded happened', false !== strpos( (string) PNCP_Options::stored()['bot_list'], 'EarlySave3126Bot' ) && false === get_option( 'pncp_test_3126_early_save' ), $pncp_out );
	t( 'W ...without "_load_textdomain_just_in_time was called incorrectly" (no translation before init)', 0 === $pncp_rc && false === strpos( $pncp_out, '_load_textdomain_just_in_time' ) && false !== strpos( $pncp_out, 'init-done' ), $pncp_out );
	t( 'W ...and the choice against the proposal is noted once init has run ("you chose this")', isset( PNCP_Wizard::state()['chosen']['block_tech_profilers'] ), wp_json_encode( PNCP_Wizard::state() ) );
	if ( null === $pncp_wstate ) {
		delete_option( PNCP_Wizard::STATE );
	} else {
		update_option( PNCP_Wizard::STATE, $pncp_wstate, false );
	}
	settings( array( 'bot_list' => $pncp_bots ) );
}

/* ---------- S. Security of the new code (static) ---------- */

$pncp_runs = array();
foreach ( array_merge( glob( PNCP_DIR . 'includes/*.php' ), array( PNCP_DIR . 'scrapelock.php', PNCP_DIR . 'uninstall.php' ) ) as $pncp_file ) {
	// The code only (no comments), each call of a function that starts a process.
	$pncp_tokens = token_get_all( (string) file_get_contents( $pncp_file ) );
	foreach ( $pncp_tokens as $pncp_i => $pncp_tok ) {
		if ( is_array( $pncp_tok ) && T_STRING === $pncp_tok[0] && in_array( strtolower( $pncp_tok[1] ), array( 'proc_open', 'shell_exec', 'passthru', 'popen', 'pcntl_exec', 'exec', 'system' ), true ) ) {
			$pncp_prev = $pncp_tokens[ $pncp_i - 1 ] ?? '';
			$pncp_prev = is_array( $pncp_prev ) && T_WHITESPACE === $pncp_prev[0] ? ( $pncp_tokens[ $pncp_i - 2 ] ?? '' ) : $pncp_prev;
			$pncp_next = $pncp_tokens[ $pncp_i + 1 ] ?? '';
			$pncp_next = is_array( $pncp_next ) && T_WHITESPACE === $pncp_next[0] ? ( $pncp_tokens[ $pncp_i + 2 ] ?? '' ) : $pncp_next;
			$pncp_meth = is_array( $pncp_prev ) && in_array( $pncp_prev[0], array( T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION ), true );
			if ( '(' === $pncp_next && ! $pncp_meth ) {
				$pncp_runs[ basename( $pncp_file ) ][] = strtolower( $pncp_tok[1] );
			}
		}
	}
}
t( 'S the only process call of the plugin: proc_open() in class-pncp-cli-server.php', array( 'class-pncp-cli-server.php' => array( 'proc_open' ) ) === $pncp_runs, wp_json_encode( $pncp_runs ) );
$pncp_srv = (string) file_get_contents( PNCP_DIR . 'includes/class-pncp-cli-server.php' );
t( 'S every command entry point stops outside WP-CLI first (rules, verify_file, cdn)', 3 === preg_match_all( '/public static function (?:rules|verify_file|cdn)\( \$args, \$assoc_args \) \{\n\t\tself::cli_only\(\);/', $pncp_srv ) );
preg_match( '/private static function commands\(.*?\n\t\}\n/s', $pncp_srv, $pncp_cmds );
t( 'S run() is called only with $test, $reload and the built-in alternative', 3 === substr_count( $pncp_srv, 'self::run( ' ) && 1 === substr_count( $pncp_srv, 'self::run( $test )' ) && 1 === substr_count( $pncp_srv, 'self::run( $reload )' ) && 1 === substr_count( $pncp_srv, "self::run( \$cmds['alt'] )" ) );
t( 'S ...the built-in commands: full paths through escapeshellarg(), nothing of the options', isset( $pncp_cmds[0] ) && 5 === substr_count( $pncp_cmds[0], 'escapeshellarg( $' ) && false === strpos( $pncp_cmds[0], '$assoc_args' ) && false === strpos( $pncp_cmds[0], '$_' ) );
t( 'S ...and $test / $reload are a built-in command unless --test-cmd / --reload-cmd was typed', 1 === substr_count( $pncp_srv, "\$test = isset( \$assoc_args['test-cmd'] ) ? (string) \$assoc_args['test-cmd'] : \$cmds['test'];" ) && 1 === substr_count( $pncp_srv, "\$reload = isset( \$assoc_args['reload-cmd'] ) ? (string) \$assoc_args['reload-cmd'] : \$cmds['reload'];" ) );
$pncp_help = (string) file_get_contents( PNCP_DIR . 'includes/class-pncp-cli.php' );
t( 'S --test-cmd and --reload-cmd say that they run through the shell as given', 2 === substr_count( $pncp_help, 'Run through the shell exactly as given' ) );

exit( $fails ? 1 : 0 );
