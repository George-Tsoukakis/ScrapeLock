<?php
/**
 * ScrapeLock 3.10 — the service bots of active plugins (PNCP_Plugin_Bots) in real WordPress: WP Rocket's
 * "WP-Rocket-SaaS" was refused ("No browser headers") while WP Rocket was active on the same site.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_plugin_bots.php
 *
 * 1. Plugin inactive: the bot is checked as before (403). Plugin active (a stand-in wp-rocket/wp-rocket.php
 *    written here): it passes the bot list, "Browsers only" and the headless check, in check() and over HTTP.
 * 2. Never exempt from: the page limit, the malicious User-Agent check, the probe ban, blocked IPs.
 * 3. "Stop allowing" / "Allow" (admin-post with nonce and manage_options), the panel and the notice of the Bots tab.
 * 4. The registry filter refuses generic User-Agent parts; an entry with an address list counts only from it.
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

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Ip::reset();
}

/** The $_SERVER of a request from $ip with these headers (everything else of a browser removed). */
function as_request( $ip, $ua, $headers = array() ) {
	foreach ( array( 'HTTP_X_TEST_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_SEC_CH_UA', 'HTTP_SEC_FETCH_MODE', 'HTTP_USER_AGENT' ) as $k ) {
		unset( $_SERVER[ $k ] );
	}
	$_SERVER['REMOTE_ADDR'] = $ip;
	if ( '' !== $ua ) {
		$_SERVER['HTTP_USER_AGENT'] = $ua;
	}
	foreach ( $headers as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
}

/** An HTTP request (as a visitor from $ip); [code, body, location]. */
function http( $path, $ip, $ua, $post = null, $cookies = array() ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: ' . $ip, 'User-Agent: ' . $ua ),
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_TIMEOUT        => 60,
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = http_build_query( $post );
	}
	curl_setopt_array( $ch, $opts );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	$loc = preg_match( '/^location:\s*(\S+)/mi', substr( $out, 0, $hs ), $m ) ? $m[1] : '';
	return array( $code, substr( $out, $hs ), $loc );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

/** check() for a page, without counting (unless asked). */
function verdict( $count = false ) {
	$v = PNCP_Bots::check( 'page', $count );
	return is_array( $v ) ? $v['code'] . ' ' . $v['reason'] : 'pass';
}

$saas    = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WP-Rocket-SaaS';
$preload = 'WP Rocket/Preload';
$visitor = '198.51.100.61';

// A stand-in for WP Rocket (only its header: activating it runs nothing).
$plugin_dir = WP_PLUGIN_DIR . '/wp-rocket';
$created    = ! is_dir( $plugin_dir );
if ( $created ) {
	mkdir( $plugin_dir );
	file_put_contents( $plugin_dir . '/wp-rocket.php', "<?php\n/*\nPlugin Name: WP Rocket (test stand-in)\nVersion: 0.0.1\n*/\n" );
}
$saved       = PNCP_Options::stored();
$saved_state = get_option( PNCP_Plugin_Bots::OPTION, null );
$server_old  = isset( $_SERVER['SERVER_ADDR'] ) ? $_SERVER['SERVER_ADDR'] : null;
register_shutdown_function(
	static function () use ( $plugin_dir, $created, $saved, $saved_state ) {
		deactivate_plugins( 'wp-rocket/wp-rocket.php', true );
		if ( $created ) {
			@unlink( $plugin_dir . '/wp-rocket.php' );
			@rmdir( $plugin_dir );
		}
		update_option( PNCP_OPTION, $saved );
		if ( null === $saved_state ) {
			delete_option( PNCP_Plugin_Bots::OPTION );
		} else {
			update_option( PNCP_Plugin_Bots::OPTION, $saved_state );
		}
	}
);

update_option( 'pncp_emergency_until', 0 );
delete_option( PNCP_Plugin_Bots::OPTION );
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'block_bots'              => 1,
		'require_browser_headers' => 1,
		'block_headless'          => 1,
		'probe_ban'               => 1,
		'rate_limit'              => 0,
		'rate_limit_search'       => 0,
		'rate_limit_404'          => 0,
		'rate_limit_unverified'   => 0,
		'rate_limit_datacenter'   => 0,
		'rate_limit_apionly'      => 0,
		'human_check'             => 0,
		'block_ips'               => '',
		'allow_ips'               => '',
		'trust_any_proxy'         => 0,
		'trusted_proxies'         => '',
		'ip_header'               => 'remote_addr',
		'countries_block'         => '',
		'countries_strict'        => '',
	)
);
deactivate_plugins( 'wp-rocket/wp-rocket.php', true );
PNCP_Plugin_Bots::reset();

/* ---------- 1. Plugin inactive / active ---------- */
as_request( $visitor, $saas );
t( 'WP Rocket inactive: WP-Rocket-SaaS without browser headers gets 403 no_browser, as before', '403 no_browser' === verdict(), verdict() );
t( 'WP Rocket inactive: no plugin bot match', null === PNCP_Plugin_Bots::match( $saas, $visitor ) );

$activated = activate_plugin( 'wp-rocket/wp-rocket.php', '', false, true );
t( 'the WP Rocket stand-in is active', null === $activated && is_plugin_active( 'wp-rocket/wp-rocket.php' ), is_wp_error( $activated ) ? $activated->get_error_message() : '' );

as_request( $visitor, $saas );
t( 'WP Rocket active: WP-Rocket-SaaS passes "Browsers only" (check())', 'pass' === verdict(), verdict() );
$m = PNCP_Plugin_Bots::match( $saas, $visitor );
t( 'WP Rocket active: match() names wp-rocket, not verified by address', is_array( $m ) && 'wp-rocket' === $m['id'] && false === $m['verified'], wp_json_encode( $m ) );
t( 'match() is case-insensitive', null !== PNCP_Plugin_Bots::match( 'wp-rocket-saas', $visitor ) );
t( 'an ordinary browser User-Agent is no plugin bot', null === PNCP_Plugin_Bots::match( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', $visitor ) );

as_request( $visitor, $preload );
t( 'WP Rocket active: "WP Rocket/Preload" passes too', 'pass' === verdict(), verdict() );
$_SERVER['SERVER_ADDR'] = $visitor; // The preload through a CDN: the site's own server address.
as_request( $visitor, $preload );
$m = PNCP_Plugin_Bots::match( $preload, $visitor );
t( 'preload from the server\'s own address: verified', is_array( $m ) && true === $m['verified'], wp_json_encode( $m ) );
$m = PNCP_Plugin_Bots::match( $saas, $visitor );
t( 'WP-Rocket-SaaS from the server\'s address is not "verified" (it comes from WP Rocket\'s servers)', is_array( $m ) && false === $m['verified'], wp_json_encode( $m ) );
if ( null === $server_old ) {
	unset( $_SERVER['SERVER_ADDR'] );
} else {
	$_SERVER['SERVER_ADDR'] = $server_old;
}

// The bot list: a line that would match WP Rocket's bot.
settings( array( 'bot_list' => $saved['bot_list'] . "\nRocket-SaaS" ) );
as_request( $visitor, $saas, array( 'HTTP_ACCEPT_LANGUAGE' => 'en' ) );
t( 'WP Rocket active: a bot list line "Rocket-SaaS" does not refuse it (bot_ua)', 'pass' === verdict(), verdict() );
settings( array( 'bot_list' => $saved['bot_list'] ) );

/* ---------- 2. Never exempt from limits and attack checks ---------- */
settings( array( 'block_ips' => '198.51.100.62' ) );
as_request( '198.51.100.62', $saas );
t( 'an always-blocked IP is still refused', '403 blocked_ip' === verdict(), verdict() );
settings( array( 'block_ips' => '' ) );

as_request( $visitor, $saas . ' <script>alert(1)</script>' );
t( 'an attack in the User-Agent is still refused (bad_ua)', '403 bad_ua' === verdict(), verdict() );

settings( array( 'rate_limit' => 3 ) );
$ratelimited = '198.51.100.' . wp_rand( 100, 199 );
as_request( $ratelimited, $saas );
$codes = array();
for ( $i = 0; $i < 4; $i++ ) {
	$codes[] = verdict( true );
}
t( 'the page limit still applies (4th of 3 per minute: 429)', 'pass' === $codes[2] && '429 rate_page' === $codes[3], implode( ', ', $codes ) );
settings( array( 'rate_limit' => 0 ) );

/* ---------- HTTP (the real request path) ---------- */
$ip_http = '198.51.100.' . wp_rand( 2, 99 );
list( $code ) = http( '/', $ip_http, $saas );
t( 'HTTP: WP-Rocket-SaaS gets 200 while WP Rocket is active', 200 === $code, (string) $code );
list( $code ) = http( '/', $ip_http, 'SomeScraper/1.0' );
t( 'HTTP: another script without browser headers still gets 403', 403 === $code, (string) $code );

$probe_ip     = '198.51.100.' . wp_rand( 200, 250 );
list( $code ) = http( '/.env', $probe_ip, 'WP-Rocket-SaaS' );
list( $after ) = http( '/', $probe_ip, 'WP-Rocket-SaaS' );
PNCP_Log::reset_cache();
t( 'HTTP: a scanner probe (/.env) with WP-Rocket-SaaS is still banned', 403 === $after && PNCP_Log::is_banned( $probe_ip ), $code . ' → ' . $after );
PNCP_Log::unban( $probe_ip );

/* ---------- 3. Stop allowing / Allow ---------- */
$admin   = get_user_by( 'id', 1 );
$expire  = time() + DAY_IN_SECONDS;
$token   = WP_Session_Tokens::get_instance( $admin->ID )->create( $expire );
$cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( $admin->ID, $expire, 'auth', $token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( $admin->ID, $expire, 'logged_in', $token ),
);
$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
wp_set_current_user( $admin->ID );
$browser = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
$page    = '/wp-admin/options-general.php?page=scrapelock&tab=bots';

list( $code, $body ) = http( $page, '192.0.2.200', $browser, null, $cookies );
t( 'Bots tab: 200 without PHP warnings', 200 === $code && ! php_errors( $body ), (string) $code );
t( 'Bots tab: "Allowed because WP Rocket is active" with a "Stop allowing" button', false !== strpos( $body, 'Allowed because WP Rocket is active.' ) && false !== strpos( $body, 'name="stop" value="wp-rocket"' ) );
t( 'Bots tab: the buttons have a form of their own, outside the settings form', 1 === substr_count( $body, 'id="pncp-plugin-bots-form"' ) && false !== strpos( $body, 'form="pncp-plugin-bots-form"' ) );
t( 'Bots tab: no warning while the bot is allowed', false === strpos( $body, 'pncp-plugin-bot-notice' ) );

list( $code ) = http( '/wp-admin/admin-post.php', '192.0.2.200', $browser, array( 'action' => PNCP_Plugin_Bots::ACTION, 'stop' => 'wp-rocket', '_wpnonce' => 'wrong' ), $cookies );
t( 'Stop allowing: a wrong nonce is refused and nothing changes', 403 === $code && ! in_array( 'wp-rocket', PNCP_Plugin_Bots::switched_off(), true ), (string) $code );

$sub_id = wp_insert_user(
	array(
		'user_login' => 'pncp_pb_sub_' . wp_rand( 1000, 9999 ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'subscriber',
	)
);
$sub_token   = WP_Session_Tokens::get_instance( $sub_id )->create( $expire );
$sub_cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( $sub_id, $expire, 'auth', $sub_token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( $sub_id, $expire, 'logged_in', $sub_token ),
);
$_COOKIE[ LOGGED_IN_COOKIE ] = $sub_cookies[ LOGGED_IN_COOKIE ];
wp_set_current_user( $sub_id );
$sub_nonce = wp_create_nonce( PNCP_Plugin_Bots::ACTION );
list( $code ) = http( '/wp-admin/admin-post.php', '192.0.2.201', $browser, array( 'action' => PNCP_Plugin_Bots::ACTION, 'stop' => 'wp-rocket', '_wpnonce' => $sub_nonce ), $sub_cookies );
t( 'Stop allowing: a subscriber (no manage_options) is refused', 403 === $code && ! in_array( 'wp-rocket', PNCP_Plugin_Bots::switched_off(), true ), (string) $code );
require_once ABSPATH . 'wp-admin/includes/user.php';
wp_delete_user( $sub_id );
$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
wp_set_current_user( $admin->ID );

list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.200', $browser, array( 'action' => PNCP_Plugin_Bots::ACTION, 'stop' => 'wp-rocket', '_wpnonce' => wp_create_nonce( PNCP_Plugin_Bots::ACTION ) ), $cookies );
wp_cache_delete( PNCP_Plugin_Bots::OPTION, 'options' );
wp_cache_delete( 'alloptions', 'options' );
wp_set_current_user( 0 ); // The checks below as a visitor (the administrator is exempt).
t( 'Stop allowing: saved, back to the Bots tab', 302 === $code && false !== strpos( $loc, 'pncp_message=plugin_bot_stopped' ) && in_array( 'wp-rocket', PNCP_Plugin_Bots::switched_off(), true ), $code . ' ' . $loc );

as_request( $visitor, $saas );
t( 'switched off: WP-Rocket-SaaS gets 403 no_browser again', '403 no_browser' === verdict(), verdict() );
list( $code ) = http( '/', $ip_http, $saas );
t( 'HTTP switched off: 403', 403 === $code, (string) $code );

// A refusal in the log (as the 7 days of the real site): the warning with an "Allow" button.
PNCP_Log::insert(
	array(
		'time'    => time(),
		'ip'      => '198.51.100.63',
		'reason'  => 'no_browser',
		'code'    => 403,
		'hits'    => 480,
		'path'    => '/',
		'ua'      => $saas,
	)
);
t( 'refused(): counts the log rows of the bot', PNCP_Plugin_Bots::refused( 'wp-rocket' ) >= 480, (string) PNCP_Plugin_Bots::refused( 'wp-rocket' ) );
wp_set_current_user( $admin->ID );
list( $code, $body ) = http( $page, '192.0.2.200', $browser, null, $cookies );
t( 'Bots tab switched off: warning about the refused requests while WP Rocket is active', false !== strpos( $body, 'pncp-plugin-bot-notice' ) && false !== strpos( $body, 'service bot (WP-Rocket-SaaS, WP Rocket/)' ) && ! php_errors( $body ) );
t( 'Bots tab switched off: "Allow" button and "Not allowed" in the panel', false !== strpos( $body, 'name="allow" value="wp-rocket"' ) && false !== strpos( $body, 'Not allowed: you stopped allowing it' ) );
list( $code, $notice ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=bots&pncp_message=plugin_bot_stopped&pncp_bot=wp-rocket', '192.0.2.200', $browser, null, $cookies );
t( 'the notice after "Stop allowing"', false !== strpos( $notice, 'The service bot of WP Rocket is no longer allowed' ) );

list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.200', $browser, array( 'action' => PNCP_Plugin_Bots::ACTION, 'allow' => 'wp-rocket', '_wpnonce' => wp_create_nonce( PNCP_Plugin_Bots::ACTION ) ), $cookies );
wp_cache_delete( PNCP_Plugin_Bots::OPTION, 'options' );
wp_cache_delete( 'alloptions', 'options' );
t( 'Allow: saved', 302 === $code && false !== strpos( $loc, 'pncp_message=plugin_bot_allowed' ) && ! in_array( 'wp-rocket', PNCP_Plugin_Bots::switched_off(), true ), $code . ' ' . $loc );
list( $code ) = http( '/', $ip_http, $saas );
t( 'HTTP allowed again: 200', 200 === $code, (string) $code );

list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.200', $browser, array( 'action' => PNCP_Plugin_Bots::ACTION, 'allow' => 'no-such-bot', '_wpnonce' => wp_create_nonce( PNCP_Plugin_Bots::ACTION ) ), $cookies );
t( 'Allow: an unknown bot is refused', false !== strpos( $loc, 'pncp_message=plugin_bot_error' ), $loc );

/* ---------- 4. The registry filter ---------- */
wp_set_current_user( 0 );
$filter = static function ( $bots ) {
	$bots['generic'] = array(
		'name'    => 'Generic',
		'plugins' => array( 'wp-rocket/wp-rocket.php' ),
		'agents'  => array( 'Mozilla', 'Chrome' ),
	);
	$bots['pinned']  = array(
		'name'    => 'Pinned',
		'plugins' => array( 'wp-rocket/wp-rocket.php' ),
		'agents'  => array( 'PinnedServiceBot' ),
		'ips'     => array( '203.0.113.0/24', '0.0.0.0/0' ),
	);
	return $bots;
};
add_filter( 'pncp_plugin_bots', $filter );
PNCP_Plugin_Bots::reset();
$registry = PNCP_Plugin_Bots::registry();
t( 'filter: an entry with only generic User-Agent parts (Mozilla, Chrome) is dropped', ! isset( $registry['generic'] ) );
t( 'filter: a too-wide range (0.0.0.0/0) is dropped from the address list', isset( $registry['pinned'] ) && array( '203.0.113.0/24' ) === $registry['pinned']['ips'], isset( $registry['pinned'] ) ? implode( ',', $registry['pinned']['ips'] ) : '' );
as_request( '203.0.113.9', 'PinnedServiceBot/1.0' );
$m = PNCP_Plugin_Bots::match( 'PinnedServiceBot/1.0', '203.0.113.9' );
t( 'filter: an entry with an address list is allowed and verified from it', is_array( $m ) && 'pinned' === $m['id'] && $m['verified'] && 'pass' === verdict(), wp_json_encode( $m ) . ' ' . verdict() );
as_request( '198.51.100.64', 'PinnedServiceBot/1.0' );
t( 'filter: ... and not from another address', null === PNCP_Plugin_Bots::match( 'PinnedServiceBot/1.0', '198.51.100.64' ) && '403 no_browser' === verdict(), verdict() );
remove_filter( 'pncp_plugin_bots', $filter );
PNCP_Plugin_Bots::reset();

/* ---------- Plugin deactivated again ---------- */
deactivate_plugins( 'wp-rocket/wp-rocket.php', true );
as_request( $visitor, $saas );
t( 'WP Rocket deactivated: its bot is checked like any other again', '403 no_browser' === verdict(), verdict() );
list( $code, $body ) = http( $page, '192.0.2.200', $browser, null, $cookies );
t( 'Bots tab without the plugin: "None of the plugins … is active"', false !== strpos( $body, 'None of the plugins whose service bots ScrapeLock knows (WP Rocket, Jetpack) is active here.' ) && ! php_errors( $body ) );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
