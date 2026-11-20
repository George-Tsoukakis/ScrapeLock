<?php
/**
 * ScrapeLock 3.11 — status badges in three states, labels instead of setting keys, FluentCommunity, the
 * defaults of new installs (real WordPress).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_311_status.php
 *
 * 1. A7: every badge says "On", "Set but not active: <reason>" or "Off" from the real runtime state: the status
 *    bar, the "Network and CDN" summary, the Dashboard widget, Site Health, Stealth and the weekly email (live:
 *    "Pre-cache check: Off" with the setting on, "Only through the CDN: off" with the setting on and no secret).
 * 2. A8: no "setting_key: 1" in any rendered tab (live: "block_ip_host: 1" in the Emergency Mode box); the
 *    tables of "Reset this tab" name the settings in words.
 * 3. A9: FluentCommunity (a stand-in plugin written here): its portal is added to the content addresses at
 *    runtime (the stored setting stays), its REST reads by signed-in members do not count toward the REST limit;
 *    guests and other routes still count.
 * 4. Part Γ: new installs get probe_ban, block_ip_host, reputation on and ban_minutes 120; a 3.10.1 site that is
 *    upgraded keeps its values (also when it never stored them); the "Default" notes show the new-install values.
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

/** Stores settings as they are, without the form's checks (e.g. "Only through the CDN" without a secret). */
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	wp_cache_delete( 'alloptions', 'options' );
}

/** A session of a user: [cookies, X-WP-Nonce of that session]. */
function session_of( $user_id ) {
	$expire  = time() + DAY_IN_SECONDS;
	$token   = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	$cookies = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
	$prev_cookie                 = isset( $_COOKIE[ LOGGED_IN_COOKIE ] ) ? $_COOKIE[ LOGGED_IN_COOKIE ] : null;
	$prev_user                   = get_current_user_id();
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	$nonce = wp_create_nonce( 'wp_rest' );
	if ( null === $prev_cookie ) {
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	} else {
		$_COOKIE[ LOGGED_IN_COOKIE ] = $prev_cookie;
	}
	wp_set_current_user( $prev_user );
	return array( $cookies, $nonce );
}

/** pncp_upgrade() leaves the file sync (early check, pre-cache check) to the next request: not wanted here. */
function no_file_sync() {
	delete_option( 'pncp_upgrade_files' );
	wp_clear_scheduled_hook( 'pncp_upgrade_files' );
}

/** An HTTP request; [code, body]. */
function http( $path, $cookies = array(), $headers = array(), $ip = '192.0.2.211' ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_COOKIE         => implode( '; ', $jar ),
			CURLOPT_HTTPHEADER     => array_merge( array( 'X-Test-IP: ' . $ip, 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0 Safari/537.36', 'Accept-Language: el' ), $headers ),
			CURLOPT_TIMEOUT        => 90,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

/** The text of the status bar's pill for a label, with its state ('' = no such pill). */
function pill( $body, $label ) {
	if ( ! preg_match_all( '#<li class="pncp-pill [^"]*" data-pncp-state="(on|set|off)">(.*?)</li>#s', $body, $m, PREG_SET_ORDER ) ) {
		return '';
	}
	foreach ( $m as $x ) {
		$text = trim( preg_replace( '/\s+/', ' ', html_entity_decode( wp_strip_all_tags( $x[2] ) ) ) );
		if ( 0 === strpos( preg_replace( '/^(On|Off): /', '', $text ), $label ) ) {
			return $x[1] . ' | ' . $text;
		}
	}
	return '';
}

$admin       = get_user_by( 'id', 1 );
list( $admin_cookies ) = session_of( $admin->ID );
$page        = '/wp-admin/options-general.php?page=scrapelock';
$saved       = get_option( PNCP_OPTION );
$saved_ver   = get_option( 'pncp_version' );
$saved_cron  = wp_next_scheduled( PNCP_Attack_Report::CRON );
$plugin_dir  = WP_PLUGIN_DIR . '/fluent-community';
$created     = ! is_dir( $plugin_dir );
register_shutdown_function(
	static function () use ( $saved, $saved_ver, $plugin_dir, $created ) {
		deactivate_plugins( 'fluent-community/fluent-community.php', true );
		if ( $created ) {
			@unlink( $plugin_dir . '/fluent-community.php' );
			@rmdir( $plugin_dir );
		}
		update_option( PNCP_OPTION, $saved );
		update_option( 'pncp_version', $saved_ver );
		no_file_sync();
		delete_option( PNCP_Precheck::STATUS );
		delete_transient( PNCP_Precheck::RETRY );
		PNCP_Options::flush();
		PNCP_Precheck::sync();
		PNCP_Early::sync();
		$member = get_user_by( 'login', 'fc_member' );
		if ( $member ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
			wp_delete_user( $member->ID );
		}
	}
);
settings( array( 'enabled' => 1, 'monitor_mode' => 0, 'monitor_until' => 0 ) );
update_option( 'pncp_emergency_until', 0 );

/* ---------- 1. A7: three states ---------- */
// The states themselves.
$s = array_merge( PNCP_Options::stored(), array( 'precheck' => 1, 'cdn_only' => 1, 'cdn_secret' => '' ) );
$st = PNCP_Status_State::cdn_only( $s );
t( 'A7: «Only through the CDN» on without a secret: set but not active, «the CDN secret is missing»', 'set' === $st['state'] && false !== strpos( $st['reason'], 'CDN secret is missing' ), wp_json_encode( $st ) );
$st = PNCP_Status_State::cdn_only( array_merge( $s, array( 'cdn_secret' => 'abc123abc123abc123' ) ) );
t( 'A7: «Only through the CDN» with a secret: on', 'on' === $st['state'], wp_json_encode( $st ) );
$st = PNCP_Status_State::cdn_only( array_merge( $s, array( 'cdn_only' => 0 ) ) );
t( 'A7: «Only through the CDN» off: off', 'off' === $st['state'] );
$st = PNCP_Status_State::cdn_only( array_merge( $s, array( 'enabled' => 0 ) ) );
t( 'A7: protection off: set but not active, «protection is off»', 'set' === $st['state'] && 'protection is off' === $st['reason'], wp_json_encode( $st ) );
t( 'A7: badge text «Set but not active: …»', 'Set but not active: protection is off' === PNCP_Status_State::text( $st ) );
$st = PNCP_Status_State::precheck( array_merge( $s, array( 'precheck' => 0 ) ) );
t( 'A7: pre-cache check off: off', 'off' === $st['state'] );

// The pre-cache check on, but its line not in wp-config.php (a front-end save defers it; a failed write waits an hour).
settings( array( 'precheck' => 1, 'cdn_only' => 1, 'cdn_secret' => '', 'early_mode' => 0 ) );
update_option( PNCP_Precheck::STATUS, 'not_writable', false );
set_transient( PNCP_Precheck::RETRY, 1, HOUR_IN_SECONDS );
$st = PNCP_Status_State::precheck( PNCP_Options::stored() );
t( 'A7: pre-cache check on, line not in wp-config.php: «the loader is not in wp-config.php»', ! PNCP_Precheck::in_config() && 'set' === $st['state'] && false !== strpos( $st['reason'], 'loader is not in wp-config.php' ), wp_json_encode( $st ) );
list( $code, $body ) = http( $page . '&tab=bots', $admin_cookies );
t( 'A7: Bots tab loads without PHP warnings', 200 === $code && ! php_errors( $body ), (string) $code );
$p = pill( $body, 'Pre-cache check' );
t( 'A7: status bar: «Pre-cache check: Set but not active: the loader is not in wp-config.php» (not «Off»)', 0 === strpos( $p, 'set | ' ) && false !== strpos( $p, 'Set but not active: the loader is not in wp-config.php' ), $p );
$p = pill( $body, 'Only through the CDN' );
t( 'A7: status bar: «Only through the CDN: Set but not active: the CDN secret is missing»', 0 === strpos( $p, 'set | ' ) && false !== strpos( $p, 'the CDN secret is missing' ), $p );
$p = pill( $body, 'Protection' );
t( 'A7: status bar: «Protection» on', 0 === strpos( $p, 'on | ' ), $p );
$p = pill( $body, 'Human check' );
t( 'A7: status bar: «Human check» off (the setting is off)', 0 === strpos( $p, 'off | ' ), $p );
$text = html_entity_decode( wp_strip_all_tags( $body ) );
t( 'A7: «Network and CDN» summary: pre-cache check «set but not active», not «off»', false !== strpos( $text, 'Pre-cache check: set but not active: the loader is not in wp-config.php' ) );
t( 'A7: «Network and CDN» summary: «Only through the CDN: set but not active: the CDN secret is missing»', false !== strpos( $text, 'Only through the CDN: set but not active: the CDN secret is missing' ) );
t( 'A7: «Network and CDN» summary: early check off', false !== strpos( $text, 'Early check: off' ) );
$info = PNCP_Health::info( array() );
$rows = isset( $info['scrapelock']['fields'] ) ? $info['scrapelock']['fields'] : array();
t( 'A7: Site Health info: pre-cache check with the reason', isset( $rows['precheck'] ) && false !== strpos( (string) $rows['precheck']['value'], 'loader is not in wp-config.php' ), isset( $rows['precheck'] ) ? (string) $rows['precheck']['value'] : 'no row' );
t( 'A7: Site Health info: «Only through the CDN» with the reason (was «No»)', isset( $rows['cdn_only'] ) && false !== strpos( (string) $rows['cdn_only']['value'], 'CDN secret is missing' ), isset( $rows['cdn_only'] ) ? (string) $rows['cdn_only']['value'] : 'no row' );

// The pre-cache check running: on, everywhere.
delete_transient( PNCP_Precheck::RETRY );
update_option( PNCP_Precheck::STATUS, 'deferred', false );
list( , $body ) = http( $page . '&tab=bots', $admin_cookies ); // maybe_sync() adds the line from wp-admin.
wp_cache_delete( 'alloptions', 'options' );
$p = pill( $body, 'Pre-cache check' );
t( 'A7: pre-cache check running (line added from wp-admin): on', PNCP_Precheck::active() && 0 === strpos( $p, 'on | ' ), $p );
t( 'A7: «Network and CDN» summary: pre-cache check on', false !== strpos( html_entity_decode( wp_strip_all_tags( $body ) ), 'Pre-cache check: on' ) );

// The early check: on with its file, set but not active while protection is off.
settings( array( 'early_mode' => 1, 'precheck' => 0, 'cdn_only' => 0, 'trap_enabled' => 1, 'human_check' => 0 ) );
PNCP_Early::sync();
t( 'A7: early check on with its file: on', PNCP_Early::installed() && 'on' === PNCP_Status_State::early( PNCP_Options::stored() )['state'] );
settings( array( 'enabled' => 0 ) );
list( , $body ) = http( $page . '&tab=bots', $admin_cookies );
$p = pill( $body, 'Early check' );
t( 'A7: protection off: «Early check: Set but not active: protection is off»', 0 === strpos( $p, 'set | ' ) && false !== strpos( $p, 'protection is off' ), $p );
list( $code, $body ) = http( '/wp-admin/index.php', $admin_cookies );
$text = preg_replace( '/\s+/', ' ', html_entity_decode( wp_strip_all_tags( $body ) ) );
t( 'A7: Dashboard widget, protection off: the layers that are set read «Set but not active: protection is off»', 200 === $code && false !== strpos( $body, 'pncp-layer--set' ) && false !== strpos( $text, 'Bot trap (Set but not active: protection is off)' ) && ! php_errors( $body ), (string) $code );
settings( array( 'enabled' => 1 ) );
list( , $body ) = http( '/wp-admin/index.php', $admin_cookies );
t( 'A7: Dashboard widget, protection on: the bot trap on, a setting that is off off', false !== strpos( $body, 'pncp-layer pncp-layer--on' ) && false !== strpos( $body, 'pncp-layer pncp-layer--off' ) && false === strpos( $body, 'pncp-layer--set' ), preg_match( '#<li class="pncp-layer pncp-layer--set">.*?</li>#s', $body, $mm ) ? preg_replace( '/\s+/', ' ', wp_strip_all_tags( $mm[0] ) ) : '' );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();

// Stealth and the weekly email.
$st = PNCP_Status_State::stealth( array_merge( PNCP_Stealth::settings(), array( 'stealth_enabled' => 1 ) ) );
t( 'A7: Stealth on but not tested: set but not active (with the reason)', ! PNCP_Stealth::active() && 'set' === $st['state'] && '' !== $st['reason'], wp_json_encode( $st ) );
t( 'A7: Stealth off: off', 'off' === PNCP_Status_State::stealth( array_merge( PNCP_Stealth::settings(), array( 'stealth_enabled' => 0 ) ) )['state'] );
wp_clear_scheduled_hook( PNCP_Attack_Report::CRON );
$st = PNCP_Status_State::weekly_report( array_merge( PNCP_Options::stored(), array( 'report_weekly' => 1 ) ) );
t( 'A7: weekly email on, not scheduled: set but not active', 'set' === $st['state'] && false !== strpos( $st['reason'], 'not scheduled' ), wp_json_encode( $st ) );
wp_schedule_event( time() + HOUR_IN_SECONDS, 'weekly', PNCP_Attack_Report::CRON );
t( 'A7: weekly email on and scheduled: on', 'on' === PNCP_Status_State::weekly_report( array_merge( PNCP_Options::stored(), array( 'report_weekly' => 1 ) ) )['state'] );
wp_clear_scheduled_hook( PNCP_Attack_Report::CRON );
if ( $saved_cron ) {
	wp_schedule_event( $saved_cron, 'weekly', PNCP_Attack_Report::CRON );
}
t( 'A7: weekly email off: off', 'off' === PNCP_Status_State::weekly_report( array_merge( PNCP_Options::stored(), array( 'report_weekly' => 0 ) ) )['state'] );

/* ---------- 2. A8: no setting keys in the screens ---------- */
settings( array( 'block_ip_host' => 0, 'block_seo_crawlers' => 1 ) );
$changes = PNCP_Options::emergency_changes( PNCP_Options::stored() );
t( 'A8: Emergency Mode box: the IP-address line in words', in_array( 'Requests that open the site by its IP address instead of its name are refused', $changes, true ), implode( ' / ', $changes ) );
t( 'A8: Emergency Mode box: no «key: value» line', ! preg_grep( '/\b[a-z]+(_[a-z0-9]+)+: /', $changes ), implode( ' / ', preg_grep( '/\b[a-z]+(_[a-z0-9]+)+: /', $changes ) ) );
t( 'A8: a setting without a sentence: its label and value in words', 'Refuse requests that open the site by its IP address instead of its name: On' === PNCP_Setting_Labels::label( 'block_ip_host' ) . ': ' . PNCP_Setting_Labels::value( 'block_ip_host', '1' ) );
$missing = array();
foreach ( PNCP_Settings_Io::public_keys() as $key ) {
	if ( ! isset( PNCP_Setting_Labels::all()[ $key ] ) ) {
		$missing[] = $key;
	}
}
t( 'A8: every setting that can be exported or reset has a label', ! $missing, implode( ', ', $missing ) );
settings( array( 'feed_mode' => 'excerpt', 'exempt_cap' => 'edit_posts' ) );
$rows = PNCP_Health::info( array() )['scrapelock']['fields'];
t( 'A8: Site Health info: choices in words, the stored value only in the copied report', 'excerpt' !== $rows['feed_mode']['value'] && 'excerpt' === $rows['feed_mode']['debug'] && 'edit_posts' !== $rows['exempt_cap']['value'], wp_json_encode( array( $rows['feed_mode'], $rows['exempt_cap'] ) ) );
$raw = '/\b[a-z]+(?:_[a-z0-9]+)+: [01]\b/';
foreach ( array( 'general', 'bots', 'content', 'images', 'rules', 'log', 'attacks', 'hardening', 'lockdown' ) as $tab ) {
	list( $code, $body ) = http( $page . '&tab=' . $tab, $admin_cookies );
	$text = html_entity_decode( wp_strip_all_tags( preg_replace( '#<(script|style|textarea)\b.*?</\1>#is', '', $body ) ) );
	$hits = preg_match_all( $raw, $text, $m ) ? array_unique( $m[0] ) : array();
	t( "A8: tab $tab: no «setting_key: 0/1» in the page", 200 === $code && ! $hits && ! php_errors( $body ), $code . ' ' . implode( ', ', $hits ) );
	if ( 'general' === $tab ) {
		t( 'A8: Emergency Mode box on the page: the IP-address line in words', false !== strpos( $text, 'Requests that open the site by its IP address instead of its name are refused' ) && false === strpos( $text, 'block_ip_host' ) );
	}
}
list( , $body ) = http( '/wp-admin/index.php', $admin_cookies );
t( 'A8: Dashboard: no «setting_key: 0/1»', ! preg_match( $raw, html_entity_decode( wp_strip_all_tags( $body ) ) ) );
list( $code, $body ) = http( $page . '&tab=bots&pncp_reset=bots', $admin_cookies );
$flat = preg_replace( '/>\s+</', '><', $body );
t( 'A8: «Reset this tab»: the settings in words (Block SEO and marketing data crawlers: On → Off)', 200 === $code && false !== strpos( $flat, '<td title="block_seo_crawlers">Block SEO and marketing data crawlers (Ahrefs, Semrush, Majestic…)</td><td>On</td><td>Off</td>' ), $code . ' ' . ( preg_match( '#<table class="widefat striped pncp-changes">.{0,600}#s', $flat, $mm ) ? $mm[0] : 'no table' ) );
t( 'A8: «Reset this tab»: no bare key in a cell', false === strpos( $body, '<td><code>block_seo_crawlers</code></td>' ) );
settings( array( 'block_seo_crawlers' => 0 ) );

/* ---------- 3. A9: FluentCommunity ---------- */
if ( $created ) {
	mkdir( $plugin_dir );
}
// A stand-in: its header, its constant and one REST route of its namespace (GET, open to everyone, as the portal's feeds).
file_put_contents(
	$plugin_dir . '/fluent-community.php',
	"<?php\n/*\nPlugin Name: FluentCommunity (test stand-in)\nVersion: 0.0.1\n*/\n"
	. "defined( 'FLUENT_COMMUNITY_PLUGIN_VERSION' ) || define( 'FLUENT_COMMUNITY_PLUGIN_VERSION', '0.0.1' );\n"
	. "add_action( 'rest_api_init', function () { register_rest_route( 'fluent-community/v2', '/feeds', array( 'methods' => 'GET', 'permission_callback' => '__return_true', 'callback' => function () { return array( 'feeds' => array(), 'user' => get_current_user_id() ); } ) ); } );\n"
);
settings( array( 'content_paths' => "/forum/\n", 'rate_limit_rest' => 3, 'rate_limit_apionly' => 0, 'ban_strikes' => 0, 'reputation' => 0 ) );
t( 'A9: FluentCommunity not active: nothing added', ! PNCP_Fluent_Community::active() && array( '/forum' ) === PNCP_Log::content_paths(), wp_json_encode( PNCP_Log::content_paths() ) );
activate_plugin( PNCP_Fluent_Community::BASENAME );
wp_cache_delete( 'alloptions', 'options' );
t( 'A9: active (by the list of active plugins): detected', PNCP_Fluent_Community::active() );
t( 'A9: the portal /hub added to the content addresses', array( '/forum', '/hub' ) === PNCP_Log::content_paths(), wp_json_encode( PNCP_Log::content_paths() ) );
t( 'A9: the stored setting is not changed', "/forum/\n" === PNCP_Options::stored()['content_paths'] || '/forum/' === trim( PNCP_Options::stored()['content_paths'] ), wp_json_encode( PNCP_Options::stored()['content_paths'] ) );
t( 'A9: a portal address counts as a page of the site in the log', PNCP_Log::is_site_content( '/hub/space/greek-pharmacists/home' ) );
add_filter(
	'pncp_fluent_community_slug',
	static function () {
		return 'community';
	}
);
t( 'A9: the slug configured in FluentCommunity is used', array( '/forum', '/community' ) === PNCP_Log::content_paths(), wp_json_encode( PNCP_Log::content_paths() ) );
remove_all_filters( 'pncp_fluent_community_slug' );
settings( array( 'content_paths' => "/hub/\n" ) );
t( 'A9: already in the list: not added twice', array( '/hub' ) === PNCP_Log::content_paths(), wp_json_encode( PNCP_Log::content_paths() ) );
settings( array( 'content_paths' => "/forum/\n" ) );
list( , $body ) = http( $page . '&tab=log', $admin_cookies );
t( 'A9: Log tab: «added because FluentCommunity is active»', false !== strpos( $body, 'id="pncp-content_paths-added"' ) && false !== strpos( $body, 'added because FluentCommunity is active' ) && false !== strpos( $body, '/hub/' ) );
t( 'A9: Log tab: the field still holds only the stored list', (bool) preg_match( '#<textarea[^>]*name="pncp_settings\[content_paths\]"[^>]*>\s*/forum/\s*</textarea>#', $body ) );

// The REST limit (3 per minute). Addresses of their own on every run (the counters last a minute).
$net = '203.0.' . mt_rand( 1, 250 ) . '.';
$member = wp_insert_user( array( 'user_login' => 'fc_member', 'user_pass' => wp_generate_password(), 'user_email' => 'fc_member@example.com', 'role' => 'subscriber' ) );
list( $m_cookies, $m_nonce ) = session_of( $member );
$codes = array();
for ( $i = 0; $i < 6; $i++ ) {
	list( $c, $b ) = http( '/wp-json/fluent-community/v2/feeds', $m_cookies, array( 'X-WP-Nonce: ' . $m_nonce ), $net . '81' );
	$codes[] = $c;
}
t( 'A9: signed-in member, 6 portal reads in a minute with a limit of 3: all 200', array( 200, 200, 200, 200, 200, 200 ) === $codes && false !== strpos( $b, '"user":' . $member ), implode( ',', $codes ) . ' ' . substr( $b, 0, 120 ) );
$codes = array();
for ( $i = 0; $i < 5; $i++ ) {
	list( $c ) = http( '/wp-json/fluent-community/v2/feeds', array(), array(), $net . '82' );
	$codes[] = $c;
}
t( 'A9: guest: the 4th portal read in a minute gets 429', array( 200, 200, 200, 429, 429 ) === $codes, implode( ',', $codes ) );
$codes = array();
for ( $i = 0; $i < 5; $i++ ) {
	list( $c ) = http( '/wp-json/fluent-community/v2/feeds', $m_cookies, array(), $net . '83' );
	$codes[] = $c;
}
t( 'A9: the member\'s cookie without the session nonce: counted (429 on the 4th)', array( 200, 200, 200, 429, 429 ) === $codes, implode( ',', $codes ) );
$codes = array();
for ( $i = 0; $i < 5; $i++ ) {
	list( $c ) = http( '/wp-json/wp/v2/posts', $m_cookies, array( 'X-WP-Nonce: ' . $m_nonce ), $net . '84' );
	$codes[] = $c;
}
t( 'A9: the member on another route (/wp/v2/posts): counted (429 on the 4th)', array( 200, 200, 200, 429, 429 ) === $codes, implode( ',', $codes ) );
settings( array( 'block_ips' => $net . '85' ) );
list( $c ) = http( '/wp-json/fluent-community/v2/feeds', $m_cookies, array( 'X-WP-Nonce: ' . $m_nonce ), $net . '85' );
t( 'A9: an always-blocked IP is still refused, signed in or not', 403 === $c, (string) $c );
settings( array( 'block_ips' => '' ) );

deactivate_plugins( PNCP_Fluent_Community::BASENAME, true );
wp_cache_delete( 'alloptions', 'options' );
// Asked over HTTP: this process loaded the stand-in (its constant stays defined here).
list( , $body ) = http( $page . '&tab=log', $admin_cookies );
t( 'A9: deactivated: the portal is no longer added (Log tab)', ! in_array( PNCP_Fluent_Community::BASENAME, (array) get_option( 'active_plugins' ), true ) && false === strpos( $body, 'id="pncp-content_paths-added"' ) && false !== strpos( $body, 'pncp-sec-content-paths' ) );
$codes = array();
for ( $i = 0; $i < 5; $i++ ) {
	list( $c ) = http( '/wp-json/scrapelock-none/v1/x', $m_cookies, array( 'X-WP-Nonce: ' . $m_nonce ), $net . '86' );
	$codes[] = $c;
}
t( 'A9: deactivated: the member\'s REST reads count again (429 on the 4th)', 429 === $codes[3], implode( ',', $codes ) );

/* ---------- 4. Part Γ: defaults of new installs only ---------- */
$new = PNCP_Options::new_install();
t( 'Γ: new install: probe_ban 1, block_ip_host 1, reputation 1, ban_minutes 120', 1 === $new['probe_ban'] && 1 === $new['block_ip_host'] && 1 === $new['reputation'] && 120 === $new['ban_minutes'], wp_json_encode( $new ) );
$d = PNCP_Options::defaults();
t( 'Γ: defaults() (missing keys of existing sites) keep the values before 3.11', 0 === (int) $d['probe_ban'] && 0 === (int) $d['block_ip_host'] && 0 === (int) $d['reputation'] && 60 === (int) $d['ban_minutes'] );
t( 'Γ: unchanged defaults: blur_on_capture 0, block_devtools 0, user_mark_guests 0, ban_strikes 3', 0 === (int) $d['blur_on_capture'] && 0 === (int) $d['block_devtools'] && 0 === (int) $d['user_mark_guests'] && 3 === (int) $d['ban_strikes'] );

// A fresh install.
delete_option( PNCP_OPTION );
delete_option( 'pncp_version' );
PNCP_Options::flush();
pncp_upgrade();
no_file_sync();
wp_cache_delete( 'alloptions', 'options' );
PNCP_Options::flush();
$s = PNCP_Options::stored();
t( 'Γ: fresh install stores the new values', 1 === (int) $s['probe_ban'] && 1 === (int) $s['block_ip_host'] && 1 === (int) $s['reputation'] && 120 === (int) $s['ban_minutes'] && 3 === (int) $s['ban_strikes'] && 0 === (int) $s['blur_on_capture'] && 0 === (int) $s['block_devtools'] && 0 === (int) $s['user_mark_guests'], wp_json_encode( array_intersect_key( $s, $new ) ) );

// A 3.10.1 site: its settings as 3.10.1 stored them (the defaults of 3.10.1), upgraded.
$old = PNCP_Options::defaults();
update_option( PNCP_OPTION, $old );
update_option( 'pncp_version', '3.10.1' );
PNCP_Options::flush();
pncp_upgrade();
no_file_sync();
wp_cache_delete( 'alloptions', 'options' );
PNCP_Options::flush();
$s = PNCP_Options::stored();
t( 'Γ: a 3.10.1 site upgraded: its values unchanged', 0 === (int) $s['probe_ban'] && 0 === (int) $s['block_ip_host'] && 0 === (int) $s['reputation'] && 60 === (int) $s['ban_minutes'] && empty( $s['monitor_mode'] ), wp_json_encode( array_intersect_key( $s, $new ) ) );
$diff = array();
foreach ( $old as $k => $v ) {
	if ( (string) $v !== (string) $s[ $k ] ) {
		$diff[] = $k;
	}
}
t( 'Γ: a 3.10.1 site upgraded: no setting changed at all', ! $diff, implode( ', ', $diff ) );

// A site that never stored the 3.5 / 3.7 keys (settings of an older version).
$older = array_diff_key( $old, array_flip( array( 'probe_ban', 'block_ip_host', 'reputation' ) ) );
update_option( PNCP_OPTION, $older );
update_option( 'pncp_version', '3.4.0' );
PNCP_Options::flush();
pncp_upgrade();
no_file_sync();
wp_cache_delete( 'alloptions', 'options' );
PNCP_Options::flush();
$s = PNCP_Options::stored();
t( 'Γ: an upgraded site without those keys gets the old values, not the new-install ones', 0 === (int) $s['probe_ban'] && 0 === (int) $s['block_ip_host'] && 0 === (int) $s['reputation'] && 60 === (int) $s['ban_minutes'], wp_json_encode( array_intersect_key( $s, $new ) ) );

// The "Default" notes: the new-install values, and the old value of sites installed before 3.11.
update_option( PNCP_OPTION, array_merge( $saved, array( 'probe_ban' => 0, 'ban_minutes' => 60, 'block_ip_host' => 1 ) ) );
update_option( 'pncp_version', $saved_ver );
PNCP_Options::flush();
$note = wp_strip_all_tags( PNCP_Admin_Fields::default_note( 'probe_ban', PNCP_Options::stored() ) );
t( 'Γ: «Default» note: on for new installs, off on sites installed before 3.11', false !== strpos( $note, 'Default on new installs: on' ) && false !== strpos( $note, '3.11' ), $note );
$note = wp_strip_all_tags( PNCP_Admin_Fields::default_note( 'ban_minutes', PNCP_Options::stored() ) );
t( 'Γ: «Default» note of the block duration: 120 for new installs, 60 before 3.11', false !== strpos( $note, '120' ) && false !== strpos( $note, '60' ) && false !== strpos( $note, '3.11' ), $note );
t( 'Γ: the new-install value: no note', '' === PNCP_Admin_Fields::default_note( 'block_ip_host', PNCP_Options::stored() ) );
t( 'Γ: «Reset this tab» uses the new-install values', 1 === (int) PNCP_Settings_Io::section_defaults( 'bots' )['probe_ban'] && 120 === (int) PNCP_Settings_Io::section_defaults( 'bots' )['ban_minutes'] );
list( $code, $body ) = http( $page . '&tab=bots', $admin_cookies );
t( 'Γ: Bots tab shows the note next to the field', 200 === $code && false !== strpos( $body, 'id="pncp-probe_ban-default"' ) && ! php_errors( $body ), (string) $code );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
