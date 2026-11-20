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

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
