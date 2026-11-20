<?php
/**
 * ScrapeLock 3.11 — how the parts of 3.11 work together, in real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_311_integration.php
 *
 * - The pre-cache check is compiled from the settings it is written for: the allowed AI search bots and the bot
 *   list without them always agree (also when the request's settings cache is older).
 * - "For my site" (PNCP_Wizard) uses the FluentCommunity integration (its portal is counted already, so it is
 *   not proposed), every service bot of an active plugin, the status of the pre-cache check and the setting
 *   labels (never a bare key).
 * - The new tab layout (tab groups, the Bots tab accordion, the folded long lists) still shows the warnings and
 *   buttons of 3.11: the AI search warning with "Remove from the list" (and a link that opens the folded bot
 *   list), "Network and CDN" opened while one of its settings is set but not active, the badge link of "Only
 *   through the CDN", the "For my site" panel, the FluentCommunity note and "Allow this service" in the Log.
 *
 * Same requirements as t_http.php (mu-test-harness.php, router.php). Changes the database: test sites only.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
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
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Ip::reset();
}

/** Reads the settings again from the database (after a request of the web server changed them). */
function reread() {
	wp_cache_delete( PNCP_OPTION, 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_delete( PNCP_Settings_Io::BACKUPS, 'options' );
	PNCP_Options::flush();
	return PNCP_Options::stored();
}

/** The $_SERVER of a request from $ip (everything of a browser removed). */
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

/** check() for a page, without counting. */
function verdict() {
	$v = PNCP_Bots::check( 'page', false );
	return is_array( $v ) ? $v['code'] . ' ' . $v['reason'] : 'pass';
}

/** An HTTP request (as a visitor from $ip); [code, body, location]. */
function http( $path, $ip, $ua, $post = null, $cookies = array(), $headers = array() ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => array_merge( array( 'X-Test-IP: ' . $ip, 'User-Agent: ' . $ua ), $headers ),
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

/** Whether a request of the web server banned the IP (the caches of this process read again). */
function banned( $ip ) {
	wp_cache_flush();
	PNCP_Log::reset_cache();
	return PNCP_Log::is_banned( $ip );
}

/** Auth cookies of a user, and the user made current for nonces. */
function login_cookies( $user_id ) {
	$expire  = time() + DAY_IN_SECONDS;
	$token   = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	$cookies = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	return $cookies;
}

$saved         = PNCP_Options::stored();
$saved_backups = get_option( PNCP_Settings_Io::BACKUPS, null );
$saved_plugins = get_option( 'active_plugins', array() );
register_shutdown_function(
	static function () use ( $saved, $saved_backups, $saved_plugins ) {
		update_option( PNCP_OPTION, $saved );
		if ( null === $saved_backups ) {
			delete_option( PNCP_Settings_Io::BACKUPS );
		} else {
			update_option( PNCP_Settings_Io::BACKUPS, $saved_backups, false );
		}
		update_option( 'active_plugins', $saved_plugins );
		PNCP_Options::flush();
	}
);

/* ---------- The pre-cache check and "Allow AI search" ---------- */

settings(
	array(
		'block_bots'      => 1,
		'allow_ai_search' => 0,
		'bot_list'        => "GPTBot\nOAI-SearchBot",
	)
);
PNCP_Options::get(); // The request's settings cache, as a page that saves the settings has it.
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'allow_ai_search' => 1 ) ) ); // Not flushed.
$config = PNCP_Precheck::config();
$allow  = array_map(
	static function ( $e ) {
		return $e[0];
	},
	(array) $config['allow_ua']
);
t( 'pre-cache: an allowed AI search bot is not in its bot list', ! in_array( 'oai-searchbot', (array) $config['bots'], true ) && in_array( 'gptbot', (array) $config['bots'], true ) );
t( 'pre-cache: and is in its always-allowed User-Agents, from the same settings', in_array( 'oai-searchbot', $allow, true ) && in_array( 'chatgpt-user', $allow, true ), implode( ',', $allow ) );
PNCP_Options::flush();
settings( array( 'allow_ai_search' => 0 ) );
$config = PNCP_Precheck::config();
$allow  = array_map(
	static function ( $e ) {
		return $e[0];
	},
	(array) $config['allow_ua']
);
t( 'pre-cache: with AI search off it is in the bot list and not allowed', in_array( 'oai-searchbot', (array) $config['bots'], true ) && ! in_array( 'oai-searchbot', $allow, true ) );
t( 'allowed_ai_search() reads the settings it is given', array() === PNCP_Options::allowed_ai_search( array( 'allow_ai_search' => 0 ) ) && in_array( 'OAI-SearchBot', PNCP_Options::allowed_ai_search( array( 'allow_ai_search' => 1 ) ), true ) );

// The early check with a bot list entry that only contains an AI search bot's name ("ChatGPT"): the allowed bot
// passes, a training crawler with the same word does not.
settings(
	array(
		'enabled'         => 1,
		'early_mode'      => 1,
		'monitor_mode'    => 0,
		'monitor_until'   => 0,
		'block_bots'      => 1,
		'allow_ai_search' => 1,
		'bot_list'        => "ChatGPT\nGPTBot",
	)
);
as_request( '198.51.100.71', 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot' );
$e = PNCP_Early::check();
t( 'early check: an allowed AI search bot passes a bot list entry with its name in it', null === $e, wp_json_encode( $e ) );
$cfg = PNCP_Precheck::config();
t( 'pre-cache: the same, the allowed bot is in its always-allowed User-Agents', in_array( 'chatgpt-user', array_column( (array) $cfg['allow_ua'], 0 ), true ) && in_array( 'chatgpt', (array) $cfg['bots'], true ) );
as_request( '198.51.100.72', 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot' );
$e = PNCP_Early::check();
t( 'early check: a training crawler is still refused', is_array( $e ) && 'bot_ua' === $e[1], wp_json_encode( $e ) );
settings(
	array(
		'enabled'         => $saved['enabled'],
		'early_mode'      => $saved['early_mode'],
		'monitor_mode'    => $saved['monitor_mode'],
		'monitor_until'   => $saved['monitor_until'],
		'block_bots'      => $saved['block_bots'],
		'allow_ai_search' => $saved['allow_ai_search'],
		'bot_list'        => $saved['bot_list'],
	)
);

/* ---------- "For my site" and the other 3.11 parts ---------- */

$env_fc = static function ( $env ) {
	$env['fluentcommunity'] = true;
	return $env;
};
add_filter( 'pncp_fluent_community_active', '__return_true' );
add_filter( 'pncp_fluent_community_slug', $fc_slug = static function () {
	return 'hub';
} );
settings( array( 'content_paths' => '/shop-feed/' ) );
$env = PNCP_Wizard::detect();
t( 'wizard: FluentCommunity found through PNCP_Fluent_Community::active()', ! empty( $env['fluentcommunity'] ) );
t( 'wizard: its portal is the one the integration counts', 'hub' === PNCP_Wizard::fluent_slug() && array( '/hub' ) === PNCP_Fluent_Community::added_paths(), PNCP_Wizard::fluent_slug() );
$p = PNCP_Wizard::proposals( null, $env );
t( 'wizard: the portal is not proposed for "Content addresses" (already counted)', ! isset( $p['content_paths'] ), isset( $p['content_paths'] ) ? $p['content_paths']['proposed'] : '' );
$notes = PNCP_Wizard::notes( null, $env );
$fc    = array_values(
	array_filter(
		$notes,
		static function ( $n ) {
			return 'FluentCommunity' === $n['for'];
		}
	)
);
t( 'wizard: a note says the portal is counted automatically', $fc && false !== strpos( $fc[0]['text'], '/hub/' ), wp_json_encode( $fc ) );
remove_filter( 'pncp_fluent_community_active', '__return_true' );
add_filter( 'pncp_fluent_community_active', '__return_false' );
add_filter( 'pncp_wizard_environment', $env_fc );
$p = PNCP_Wizard::proposals();
t( 'wizard: proposed only when the integration does not count it', isset( $p['content_paths'] ) && "/shop-feed/\n/hub/" === $p['content_paths']['proposed'], isset( $p['content_paths'] ) ? $p['content_paths']['proposed'] : '' );
remove_filter( 'pncp_wizard_environment', $env_fc );
remove_filter( 'pncp_fluent_community_active', '__return_false' );
remove_filter( 'pncp_fluent_community_slug', $fc_slug );
settings( array( 'content_paths' => $saved['content_paths'] ) );

// A service bot added by another plugin (pncp_plugin_bots), of an active plugin, switched off.
$saved_bots = get_option( PNCP_Plugin_Bots::OPTION, null );
$acme       = static function ( $bots ) {
	$bots['acme-service'] = array(
		'name'    => 'Acme Service',
		'plugins' => array( 'scrapelock/scrapelock.php' ),
		'agents'  => array( 'AcmeServiceBot/' ),
	);
	return $bots;
};
add_filter( 'pncp_plugin_bots', $acme );
PNCP_Plugin_Bots::reset();
PNCP_Plugin_Bots::set_allowed( 'acme-service', false );
$for = wp_list_pluck( PNCP_Wizard::notes(), 'for' );
t( 'wizard: a note for any switched-off service bot of an active plugin, not only WP Rocket and Jetpack', in_array( 'Acme Service', $for, true ), implode( ',', $for ) );
PNCP_Plugin_Bots::set_allowed( 'acme-service', true );
$for = wp_list_pluck( PNCP_Wizard::notes(), 'for' );
t( 'wizard: no note while it is allowed', ! in_array( 'Acme Service', $for, true ), implode( ',', $for ) );
remove_filter( 'pncp_plugin_bots', $acme );
PNCP_Plugin_Bots::reset();
if ( null === $saved_bots ) {
	delete_option( PNCP_Plugin_Bots::OPTION );
} else {
	update_option( PNCP_Plugin_Bots::OPTION, $saved_bots, false );
}

// The pre-cache check on but not running: the same reason as the status badges, whatever the cache plugin.
$s_on  = array_merge(
	PNCP_Options::stored(),
	array(
		'enabled'  => 1,
		'precheck' => 1,
	)
);
$state = PNCP_Status_State::precheck( $s_on );
$pre   = array_values(
	array_filter(
		PNCP_Wizard::notes( $s_on, array_merge( PNCP_Wizard::detect(), array( 'wp_rocket' => false ) ) ),
		static function ( $n ) {
			return __( 'Pre-cache check', 'scrapelock' ) === $n['for'];
		}
	)
);
t( 'wizard: "on but not running" with the status reason', PNCP_Status_State::SET === $state['state'] && $pre && false !== strpos( $pre[0]['text'], $state['reason'] ), wp_json_encode( array( $state, $pre ) ) );

// Labels: a setting the assistant has no name for (e.g. proposed through its filter) is named in words.
t( 'wizard: a setting without a name of its own gets the settings page label, never the bare key', 'block_headless' !== PNCP_Wizard::label( 'block_headless' ) && PNCP_Setting_Labels::label( 'block_headless' ) === PNCP_Wizard::label( 'block_headless' ) && 'Trust Bunny CDN addresses' === PNCP_Wizard::label( 'trust_bunny' ), PNCP_Wizard::label( 'block_headless' ) );

/* ---------- The tab layout and the 3.11 warnings ---------- */

$fc_dir     = WP_PLUGIN_DIR . '/fluent-community';
$fc_created = ! file_exists( $fc_dir . '/fluent-community.php' );
if ( $fc_created ) {
	if ( ! is_dir( $fc_dir ) ) {
		mkdir( $fc_dir );
	}
	file_put_contents( $fc_dir . '/fluent-community.php', "<?php\n/*\nPlugin Name: fluent-community (test stand-in)\nVersion: 0.0.1\n*/\nif ( ! defined( 'FLUENT_COMMUNITY_PORTAL_SLUG' ) ) {\n\tdefine( 'FLUENT_COMMUNITY_PORTAL_SLUG', 'hub' );\n}\n" );
}
register_shutdown_function(
	static function () use ( $fc_dir, $fc_created ) {
		if ( $fc_created ) {
			@unlink( $fc_dir . '/fluent-community.php' );
			@rmdir( $fc_dir );
		}
	}
);
activate_plugin( 'fluent-community/fluent-community.php', '', false, true );
settings(
	array(
		'enabled'         => 1,
		'monitor_mode'    => 0,
		'monitor_until'   => 0,
		'block_bots'      => 1,
		'block_http_libs' => 1,
		'allow_ai_search' => 1,
		'bot_list'        => "GPTBot\nOAI-SearchBot\nCCBot",
		'cdn_only'        => 1,
		'cdn_secret'      => '',
	)
);
delete_option( 'pncp_upgrade_files' );
PNCP_Log::clear();
list( $code ) = http( '/', '198.51.100.181', 'python-requests/2.31.0' );
t( 'layout: python-requests refused (for the Log row)', 403 === $code, (string) $code );

$admin   = get_user_by( 'id', 1 );
$cookies = login_cookies( $admin->ID );
wp_set_current_user( 0 );
$browser = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36';
$page    = '/wp-admin/options-general.php?page=scrapelock';

list( $code, $body ) = http( $page . '&tab=bots', '192.0.2.212', $browser, null, $cookies );
$notice = strpos( $body, 'pncp-ai-search-list-notice' );
$form   = strpos( $body, 'action="options.php"' );
t( 'bots tab: 200, no PHP warnings, active inside its group', 200 === $code && ! php_errors( $body ) && 1 === preg_match( '#pncp-tab-group--bots.*?nav-tab-active" aria-current="page">(<span[^>]*></span>)?\s*Bots and limits</a>#s', $body ), (string) $code );
t( 'bots tab: the AI search warning and its button, before (outside) the settings form', false !== $notice && false !== $form && $notice < $form && false !== strpos( $body, 'id="pncp-ai-search-list-remove"' ) );
t( 'bots tab: the warning links to the folded bot list, which is on the page', false !== strpos( $body, 'href="#pncp-bot_list"' ) && false !== strpos( $body, 'id="pncp-bot_list"' ) && false !== strpos( $body, 'data-pncp-list' ) );
t( 'bots tab: "Network and CDN" is open while "Only through the CDN" is set but not active', 1 === preg_match( '/<details class="pncp-advanced" id="pncp-sec-network" open>/', $body ) );
t( 'status bar: "Only through the CDN" is "set", its link goes to its row', 1 === preg_match( '#<li class="pncp-pill [^"]*" data-pncp-state="set">\s*<a href="[^"]*tab=bots[^"]*\#pncp-sec-ip"[^>]*>[^<]*Only through the CDN#s', $body ) && false !== strpos( $body, 'id="pncp-sec-ip"' ) );

list( $code, $body ) = http( $page . '&tab=general', '192.0.2.212', $browser, null, $cookies );
$nav = strpos( $body, 'nav-tab-active' );
$wiz = strpos( $body, 'id="pncp-wizard"' );
t( 'first tab: the "For my site" panel, after the grouped tab bar', 200 === $code && ! php_errors( $body ) && false !== $nav && false !== $wiz && $nav < $wiz );

list( $code, $body ) = http( $page . '&tab=log', '192.0.2.212', $browser, null, $cookies );
t( 'log tab: the FluentCommunity note under "Content addresses"', 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'id="pncp-content_paths-added"' ) && false !== strpos( $body, '/hub/' ) );
t( 'log tab: the matched entry and "Allow this service" for the python-requests row', false !== strpos( $body, 'pncp-bot-match' ) && false !== strpos( $body, 'Allow this service' ) );

deactivate_plugins( 'fluent-community/fluent-community.php', true );
settings(
	array(
		'enabled'         => $saved['enabled'],
		'monitor_mode'    => $saved['monitor_mode'],
		'monitor_until'   => $saved['monitor_until'],
		'block_bots'      => $saved['block_bots'],
		'block_http_libs' => $saved['block_http_libs'],
		'allow_ai_search' => $saved['allow_ai_search'],
		'bot_list'        => $saved['bot_list'],
		'cdn_only'        => $saved['cdn_only'],
		'cdn_secret'      => $saved['cdn_secret'],
	)
);
PNCP_Log::clear();

// @@NEXT@@

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
