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
 * - The short help texts (one line, the rest under "More") also on what 3.11 added: those warnings, the
 *   assistant's intro, the FluentCommunity note, the "Advanced" intro, the probe list of "Ban scanners…".
 * - Vulnerable points: the server's own request through the CDN (PNCP_Server_Ips) still gets the real answer,
 *   but is not logged or counted, as a loopback request.
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

/** The .description texts over $max words outside the "More" folds (as t_311_texts.php counts them). */
function long_descriptions( $body, $max = 20 ) {
	$dom = new DOMDocument();
	libxml_use_internal_errors( true );
	$dom->loadHTML( '<?xml encoding="UTF-8">' . $body );
	libxml_clear_errors();
	$xp   = new DOMXPath( $dom );
	$long = array();
	foreach ( $xp->query( '//*[@id="wpbody-content"]//*[self::p or self::span][contains(concat(" ", normalize-space(@class), " "), " description ")][not(ancestor::details[contains(concat(" ", normalize-space(@class), " "), " pncp-more ")])][not(contains(@class, "pncp-requires-note"))]' ) as $el ) {
		$text = trim( preg_replace( '/\s+/u', ' ', $el->textContent ) );
		$n    = count( preg_split( '/\s+/u', $text, -1, PREG_SPLIT_NO_EMPTY ) );
		if ( $n > $max ) {
			$long[] = $n . ': ' . mb_substr( $text, 0, 80 );
		}
	}
	return $long;
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

$long = long_descriptions( $body );
t( 'texts: on the Bots tab with these warnings, no description over 20 words outside "More"', ! $long, implode( ' | ', $long ) );
t( 'texts: the AI search warning is one short sentence, the rest under "More"', 1 === preg_match( '#pncp-ai-search-list-notice"><p>([^<]*)</p><details class="pncp-more">#', $body, $m ) && count( preg_split( '/\s+/', trim( $m[1] ) ) ) <= 30, isset( $m[1] ) ? $m[1] : '' );
t( 'texts: "Ban scanners on their first probe" names the probes of other software (under "More")', false !== strpos( $body, 'Spring Boot /actuator' ) );

list( $code, $body ) = http( $page . '&tab=general', '192.0.2.212', $browser, null, $cookies );
$nav = strpos( $body, 'nav-tab-active' );
$wiz = strpos( $body, 'id="pncp-wizard"' );
t( 'first tab: the "For my site" panel, after the grouped tab bar', 200 === $code && ! php_errors( $body ) && false !== $nav && false !== $wiz && $nav < $wiz );

$long = long_descriptions( $body );
t( 'texts: the "For my site" panel has a short intro, the rest under "More"', ! $long && false !== strpos( $body, 'Settings that suit the plugins, CDN and server found here.' ), implode( ' | ', $long ) );

list( $code, $body ) = http( $page . '&tab=log', '192.0.2.212', $browser, null, $cookies );
t( 'log tab: the FluentCommunity note under "Content addresses"', 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'id="pncp-content_paths-added"' ) && false !== strpos( $body, '/hub/' ) );
$long = long_descriptions( $body );
t( 'texts: the FluentCommunity note is one short line, the rest under "More"', ! $long && 1 === preg_match( '#id="pncp-content_paths-added">Also counted: /hub/, because FluentCommunity is active\.</p><details class="pncp-more">#', $body ), implode( ' | ', $long ) );
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

/* ---------- Vulnerable points and the server's own address ---------- */

$saved_hs   = get_option( PNCP_Hardening::OPTION, null );
$saved_self = get_option( PNCP_Server_Ips::OPTION, null );
$applied    = PNCP_Hardening::is_applied( 'author_archives' );
if ( ! $applied ) {
	wp_set_current_user( 1 ); // Applying a point needs manage_options.
	PNCP_Hardening::apply( 'author_archives' );
	wp_set_current_user( 0 );
}
t( 'hardening: "author archives" applied for the test', PNCP_Hardening::is_applied( 'author_archives' ) );
settings(
	array(
		'enabled'       => 1,
		'monitor_mode'  => 0,
		'monitor_until' => 0,
	)
);
update_option(
	PNCP_Server_Ips::OPTION,
	array(
		'ips'     => array(),
		'host'    => implode( ',', PNCP_Server_Ips::own_hosts() ),
		'time'    => time(),
		'learned' => array( '203.0.113.77' => time() ), // A learned address: kept when the lookup runs again.
	)
);
PNCP_Log::clear();
$browser = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36';
list( $code ) = http( '/author/admin/', '203.0.113.77', $browser );
wp_cache_flush();
PNCP_Log::reset_cache();
$rows = PNCP_Log::recent( 20 );
t( 'hardening: the server\'s own address through the CDN gets the real answer (404), unlogged', 404 === $code && ! array_filter(
	(array) $rows,
	static function ( $r ) {
		return '203.0.113.77' === ( is_array( $r ) ? ( isset( $r['ip'] ) ? $r['ip'] : '' ) : ( isset( $r->ip ) ? $r->ip : '' ) );
	}
), $code . ' ' . wp_json_encode( $rows ) );
list( $code ) = http( '/author/admin/', '198.51.100.191', $browser );
wp_cache_flush();
PNCP_Log::reset_cache();
$rows = PNCP_Log::recent( 20 );
t( 'hardening: a visitor still gets 404 and a log row', 404 === $code && array_filter(
	(array) $rows,
	static function ( $r ) {
		return '198.51.100.191' === ( is_array( $r ) ? ( isset( $r['ip'] ) ? $r['ip'] : '' ) : ( isset( $r->ip ) ? $r->ip : '' ) );
	}
), $code . ' ' . wp_json_encode( $rows ) );
if ( null === $saved_hs ) {
	delete_option( PNCP_Hardening::OPTION );
} else {
	update_option( PNCP_Hardening::OPTION, $saved_hs, true );
}
if ( null === $saved_self ) {
	delete_option( PNCP_Server_Ips::OPTION );
} else {
	update_option( PNCP_Server_Ips::OPTION, $saved_self );
}
settings(
	array(
		'enabled'       => $saved['enabled'],
		'monitor_mode'  => $saved['monitor_mode'],
		'monitor_until' => $saved['monitor_until'],
	)
);
PNCP_Log::clear();

/* ---------- The site's signature never follows a redirect to another host ---------- */
// A stand-in server on 127.0.0.1 (one of the site's host names, as home_url() is here): /redirect-out sends the
// request on to localhost (another host), /redirect-in to 127.0.0.1, /echo answers with the headers it got.
$echo_dir = sys_get_temp_dir() . '/pncp-echo-' . getmypid();
wp_mkdir_p( $echo_dir );
file_put_contents(
	$echo_dir . '/router.php',
	'<?php $p = parse_url( $_SERVER["REQUEST_URI"], PHP_URL_PATH );' .
	' if ( "/redirect-out" === $p ) { header( "Location: http://localhost:8952/echo", true, 302 ); exit; }' .
	' if ( "/redirect-in" === $p ) { header( "Location: http://127.0.0.1:8952/echo", true, 302 ); exit; }' .
	' header( "Content-Type: application/json" ); echo json_encode( array_change_key_case( getallheaders(), CASE_LOWER ) );'
);
$echo_srv = proc_open( array( PHP_BINARY, '-S', '0.0.0.0:8952', $echo_dir . '/router.php' ), array( array( 'file', '/dev/null', 'r' ), array( 'file', '/dev/null', 'w' ), array( 'file', '/dev/null', 'w' ) ), $echo_pipes );
usleep( 700000 );
$echo = static function ( $url ) {
	$r = wp_remote_get( $url, array( 'timeout' => 10 ) );
	$h = is_wp_error( $r ) ? null : json_decode( wp_remote_retrieve_body( $r ), true );
	return is_array( $h ) ? $h : array( 'error' => is_wp_error( $r ) ? $r->get_error_message() : wp_remote_retrieve_body( $r ) );
};
$self = strtolower( PNCP_Server_Ips::HEADER );
$h    = $echo( 'http://127.0.0.1:8952/echo' );
t( 'signature: a request to the site\'s own host carries it', isset( $h[ $self ] ), wp_json_encode( $h ) );
$h = $echo( 'http://127.0.0.1:8952/redirect-in' );
t( 'signature: still there after a redirect to the site\'s own host', isset( $h[ $self ] ), wp_json_encode( $h ) );
$h = $echo( 'http://127.0.0.1:8952/redirect-out' );
t( 'signature: not sent on after a redirect to another host (it would make that host one of the server\'s)', ! isset( $h[ $self ] ) && ! isset( $h['error'] ), wp_json_encode( $h ) );
$h = $echo( 'http://localhost:8952/echo' );
t( 'signature: never sent to another host', ! isset( $h[ $self ] ) && ! isset( $h['error'] ), wp_json_encode( $h ) );
proc_terminate( $echo_srv );
proc_close( $echo_srv );
wp_delete_file( $echo_dir . '/router.php' );
rmdir( $echo_dir );

/* ---------- A probe refused for its User-Agent is still banned on the first probe ---------- */
$saved_probe = PNCP_Options::stored();
$google_list = get_option( 'pncp_ip_lists_google', null );
PNCP_Ip::store_list( 'google', array( '66.249.64.0/19' ) );
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'require_browser_headers' => 1,
		'block_headless'          => 1,
		'block_empty_ua'          => 1,
		'probe_ban'               => 1,
		'ban_strikes'             => 3,
		'early_mode'              => 0,
		'precheck'                => 0,
	)
);
$py = 'python-requests/2.32.3';
foreach ( array( '198.51.100.211', '198.51.100.212', '198.51.100.213', '198.51.100.214', '198.51.100.215', '198.51.100.216', '66.249.66.1' ) as $pip ) {
	PNCP_Log::unban( $pip );
}
list( $code ) = http( '/actuator/env', '198.51.100.211', $py );
t( 'probe refused by "Browsers only": still 403', 403 === $code, (string) $code );
t( '... and banned on the first probe (/actuator/env, python-requests)', banned( '198.51.100.211' ) );
$rows = (array) PNCP_Log::recent( 5 );
$last = $rows ? (array) $rows[0] : array();
t( '... logged as a probe', isset( $last['reason'] ) && 'probe' === $last['reason'], wp_json_encode( $last ) );
list( $code ) = http( '/.env', '198.51.100.212', '' );
t( '/.env without a User-Agent: 403 and banned', 403 === $code && banned( '198.51.100.212' ), (string) $code );
list( $code ) = http( '/arthro-not-a-probe/', '198.51.100.213', $py );
t( 'python-requests on a page that is not a probe: 403 as before, not banned', 403 === $code && ! banned( '198.51.100.213' ), (string) $code );
list( $code ) = http( '/actuator/env', '66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' );
t( 'Googlebot from Google\'s list asking for /actuator/env: not banned', ! banned( '66.249.66.1' ), (string) $code );
settings( array( 'probe_ban' => 0 ) );
list( $code ) = http( '/actuator/env', '198.51.100.214', $py );
t( '"Ban scanners on their first probe" off: 403 for the User-Agent, no ban', 403 === $code && ! banned( '198.51.100.214' ), (string) $code );
settings( array( 'probe_ban' => 1, 'monitor_mode' => 1 ) );
list( $code ) = http( '/actuator/env', '198.51.100.215', $py );
t( '"Monitor only": no ban', ! banned( '198.51.100.215' ), (string) $code );
settings( array( 'monitor_mode' => 0 ) );
$keep = static function ( $ban, $path, $ip ) {
	return '198.51.100.216' === $ip ? false : $ban;
};
add_filter( 'pncp_probe_ban', $keep, 10, 3 );
file_put_contents( WP_CONTENT_DIR . '/mu-plugins/pncp-t-probe-filter.php', "<?php add_filter( 'pncp_probe_ban', function ( \$b, \$p, \$ip ) { return '198.51.100.216' === \$ip ? false : \$b; }, 10, 3 );\n" );
list( $code ) = http( '/actuator/env', '198.51.100.216', $py );
t( 'filter pncp_probe_ban = false: no ban', ! banned( '198.51.100.216' ), (string) $code );
wp_delete_file( WP_CONTENT_DIR . '/mu-plugins/pncp-t-probe-filter.php' );
remove_filter( 'pncp_probe_ban', $keep, 10 );
foreach ( array( '198.51.100.211', '198.51.100.212', '198.51.100.213', '198.51.100.214', '198.51.100.215', '198.51.100.216', '66.249.66.1' ) as $pip ) {
	PNCP_Log::unban( $pip );
}
update_option( PNCP_OPTION, $saved_probe );
PNCP_Options::flush();
if ( null === $google_list ) {
	delete_option( 'pncp_ip_lists_google' );
} else {
	update_option( 'pncp_ip_lists_google', $google_list );
}

// @@NEXT@@

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
