<?php
/**
 * ScrapeLock 3.12.1 — "For my site" (PNCP_Wizard) also checks sensible values (real WordPress, stand-in plugins:
 * WooCommerce, FluentCommunity, OneSignal, MemberPress; only their header).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3121_wizard.php
 *
 * 1. Every proposal at its boundary values (proposals() with given settings and environment): probe_ban,
 *    block_ip_host, reputation; temporary blocks (ban_strikes + ban_minutes in one row); rate_limit with the human
 *    check; rate_limit_rest with FluentCommunity / WooCommerce; rate_limit_account with FluentCommunity or a
 *    membership plugin; blur_on_capture, block_devtools, user_mark_guests; OneSignal in "Always allowed".
 *    "Off" (0) of a limit is never proposed away. A filter's row with an unknown 'also' setting is dropped.
 * 2. Detection of membership plugins by their main file (stand-in MemberPress), named in "Found on this site".
 * 3. The panel: one row each, ticked, a one-line reason, the diff (Now / Proposed) also for the two-setting row and
 *    the list; settings that suit → "Nothing to change".
 * 4. "Apply selected": wrong nonce, a subscriber and an editor refused (403); only the ticked rows change, both
 *    settings of the block row; posted values and keys that are not proposed are ignored; a proposal that is no
 *    longer valid when the form is sent is not applied (recomputed on the server); a saved version first, with the
 *    old values; while the site is locked nothing changes.
 * 5. WP-CLI: the same rows, --apply --yes applies them.
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
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/template.php';
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

function fresh() {
	wp_cache_delete( PNCP_OPTION, 'options' );
	wp_cache_delete( PNCP_Settings_Io::BACKUPS, 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_delete( 'notoptions', 'options' );
	PNCP_Options::flush();
	return PNCP_Options::stored();
}

/** An HTTP request; [code, body, location]. */
function http( $path, $post = null, $cookies = array() ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.214', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 'Accept-Language: en' ),
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_TIMEOUT        => 90,
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = preg_replace( '/%5B[0-9]+%5D/', '%5B%5D', http_build_query( $post ) );
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

function cookies_for( $user_id ) {
	$expire = time() + DAY_IN_SECONDS;
	$token  = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	return array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
}

function nonce_for( $user_id, $cookies, $action ) {
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	return wp_create_nonce( $action );
}

function cli( $args ) {
	global $wp_cli;
	exec( $wp_cli . ' scrapelock ' . $args . ' 2>&1', $out, $rc );
	return array( $rc, implode( "\n", $out ) );
}

/* ---------- Stand-in plugins ---------- */
$stand_ins = array(
	'woocommerce/woocommerce.php'                         => '',
	'fluent-community/fluent-community.php'               => '',
	'onesignal-free-web-push-notifications/onesignal.php' => '',
	'memberpress/memberpress.php'                         => '',
);
$created   = array();
foreach ( $stand_ins as $file => $body ) {
	$dir = WP_PLUGIN_DIR . '/' . dirname( $file );
	if ( ! file_exists( WP_PLUGIN_DIR . '/' . $file ) ) {
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir );
			$created[ $file ] = 'dir';
		} else {
			$created[ $file ] = 'file';
		}
		file_put_contents( WP_PLUGIN_DIR . '/' . $file, "<?php\n/*\nPlugin Name: " . dirname( $file ) . " (test stand-in)\nVersion: 0.0.1\n*/\n" . $body );
	}
}
$saved         = PNCP_Options::stored();
$saved_backups = get_option( PNCP_Settings_Io::BACKUPS, null );
$users         = array();
register_shutdown_function(
	static function () use ( $stand_ins, $created, $saved, $saved_backups, &$users ) {
		deactivate_plugins( array_keys( $stand_ins ), true );
		foreach ( $created as $file => $what ) {
			@unlink( WP_PLUGIN_DIR . '/' . $file );
			if ( 'dir' === $what ) {
				@rmdir( WP_PLUGIN_DIR . '/' . dirname( $file ) );
			}
		}
		foreach ( $users as $id ) {
			wp_delete_user( $id );
		}
		update_option( PNCP_OPTION, $saved );
		if ( null === $saved_backups ) {
			delete_option( PNCP_Settings_Io::BACKUPS );
		} else {
			update_option( PNCP_Settings_Io::BACKUPS, $saved_backups, false );
		}
	}
);
deactivate_plugins( array_keys( $stand_ins ), true );
unset( $_SERVER['HTTP_VIA'], $_SERVER['HTTP_CDN_SERVERID'], $_SERVER['HTTP_CF_CONNECTING_IP'] );

// Settings that suit: the check of sensible values proposes nothing, and the 3.11 proposals neither.
$good = array(
	'probe_ban'          => 1,
	'block_ip_host'      => 1,
	'reputation'         => 1,
	'ban_strikes'        => 3,
	'ban_minutes'        => 120,
	'human_check'        => 0,
	'rate_limit'         => 60,
	'rate_limit_rest'    => 60,
	'rate_limit_account' => 60,
	'blur_on_capture'    => 0,
	'block_devtools'     => 0,
	'user_mark_guests'   => 0,
	'allow_list'         => PNCP_Options::default_allow_list(),
	'skip_woo_pages'     => 1,
	'rate_limit_cart'    => 60,
	'rate_limit_coupon'  => 10,
	'precheck'           => 0,
	'edge_send_blocks'   => 0,
	'monitor_mode'       => 0,
	'monitor_until'      => 0,
);
settings( $good );
$base_s   = PNCP_Options::stored();
$base_env = PNCP_Wizard::detect();
foreach ( array( 'woocommerce', 'fluentcommunity', 'onesignal', 'bunny', 'cloudflare', 'wp_rocket' ) as $k ) {
	$base_env[ $k ] = false;
}
$base_env['membership'] = '';

/** The proposals for these settings and this environment (on top of the good ones). */
function p( $changes = array(), $env = array() ) {
	global $base_s, $base_env;
	return PNCP_Wizard::proposals( array_merge( $base_s, $changes ), array_merge( $base_env, $env ) );
}

/* ---------- 1. Boundaries ---------- */
t( 'settings that suit, nothing detected: no proposal at all', array() === p(), implode( ',', array_keys( p() ) ) );
foreach ( array( 'probe_ban', 'block_ip_host', 'reputation' ) as $key ) {
	$r = p( array( $key => 0 ) );
	t( "$key 0 → 1, ticked (blocks nothing a visitor does), a short reason", isset( $r[ $key ] ) && 1 === (int) $r[ $key ]['proposed'] && 'none' === $r[ $key ]['risk'] && str_word_count( $r[ $key ]['reason'] ) <= 14 && 1 === count( $r ), wp_json_encode( $r ) );
	t( "$key 1: not proposed", ! isset( p( array( $key => 1 ) )[ $key ] ) );
}
// Temporary blocks: one row, two settings.
t( 'blocks: 3 violations, 240 min: not proposed', ! isset( p( array( 'ban_minutes' => 240 ) )['ban_strikes'] ) );
$r = p( array( 'ban_minutes' => 241 ) );
t( 'blocks: 241 min → one row, 3 violations / 120 min, ticked', isset( $r['ban_strikes'] ) && 3 === (int) $r['ban_strikes']['proposed'] && array( 'ban_minutes' => 120 ) === $r['ban_strikes']['also'] && 'none' === $r['ban_strikes']['risk'] && ! isset( $r['ban_minutes'] ), wp_json_encode( $r ) );
t( 'blocks: the reason names the shared mobile IP', isset( $r['ban_strikes'] ) && false !== strpos( $r['ban_strikes']['reason'], 'shared mobile IP' ) );
t( 'blocks: the row\'s diff texts', isset( $r['ban_strikes'] ) && array( 'after 3 violations, for 241 min', 'after 3 violations, for 120 min' ) === PNCP_Wizard::row_texts( $r['ban_strikes'] ), isset( $r['ban_strikes'] ) ? wp_json_encode( PNCP_Wizard::row_texts( $r['ban_strikes'] ) ) : '' );
$r = p( array( 'ban_strikes' => 2, 'ban_minutes' => 60 ) );
t( 'blocks: 2 violations → 3, and 60 min is not made longer', isset( $r['ban_strikes'] ) && 3 === (int) $r['ban_strikes']['proposed'] && 60 === (int) $r['ban_strikes']['also']['ban_minutes'], wp_json_encode( $r ) );
$r = p( array( 'ban_strikes' => 1, 'ban_minutes' => 200 ) );
t( 'blocks: 1 violation, 200 min → 3 / 120', isset( $r['ban_strikes'] ) && 3 === (int) $r['ban_strikes']['proposed'] && 120 === (int) $r['ban_strikes']['also']['ban_minutes'] );
t( 'blocks: 3 violations: not proposed (lower boundary)', ! isset( p( array( 'ban_strikes' => 3, 'ban_minutes' => 60 ) )['ban_strikes'] ) );
t( 'blocks: 0 violations (never block) with 60 min: not proposed', ! isset( p( array( 'ban_strikes' => 0, 'ban_minutes' => 60 ) )['ban_strikes'] ) );
$r = p( array( 'ban_strikes' => 0, 'ban_minutes' => 600 ) );
t( 'blocks: never block, 600 min → only the duration (0 stays 0)', isset( $r['ban_strikes'] ) && 0 === (int) $r['ban_strikes']['proposed'] && 120 === (int) $r['ban_strikes']['also']['ban_minutes'] );
// Page limit with the human check.
$r = p( array( 'human_check' => 1, 'rate_limit' => 39 ) );
t( 'rate_limit 39 with the human check → 45, ticked', isset( $r['rate_limit'] ) && 45 === (int) $r['rate_limit']['proposed'] && 'none' === $r['rate_limit']['risk'], wp_json_encode( $r ) );
t( 'rate_limit 40 with the human check: not proposed', ! isset( p( array( 'human_check' => 1, 'rate_limit' => 40 ) )['rate_limit'] ) );
t( 'rate_limit 20 without the human check: not proposed', ! isset( p( array( 'human_check' => 0, 'rate_limit' => 20 ) )['rate_limit'] ) );
t( 'rate_limit 0 (off) with the human check: not proposed', ! isset( p( array( 'human_check' => 1, 'rate_limit' => 0 ) )['rate_limit'] ) );
// REST limit.
$r = p( array( 'rate_limit_rest' => 59 ), array( 'woocommerce' => true ) );
t( 'rate_limit_rest 59 with WooCommerce → 60, reason names WooCommerce', isset( $r['rate_limit_rest'] ) && 60 === (int) $r['rate_limit_rest']['proposed'] && false !== strpos( $r['rate_limit_rest']['reason'], 'WooCommerce' ), wp_json_encode( $r ) );
$r = p( array( 'rate_limit_rest' => 30 ), array( 'fluentcommunity' => true ) );
t( 'rate_limit_rest 30 with FluentCommunity → 60', isset( $r['rate_limit_rest'] ) && 60 === (int) $r['rate_limit_rest']['proposed'] && false !== strpos( $r['rate_limit_rest']['reason'], 'FluentCommunity' ) );
t( 'rate_limit_rest 60 with WooCommerce: not proposed', ! isset( p( array( 'rate_limit_rest' => 60 ), array( 'woocommerce' => true ) )['rate_limit_rest'] ) );
t( 'rate_limit_rest 30 without WooCommerce / FluentCommunity: not proposed', ! isset( p( array( 'rate_limit_rest' => 30 ) )['rate_limit_rest'] ) );
t( 'rate_limit_rest 0 (off) with WooCommerce: not proposed', ! isset( p( array( 'rate_limit_rest' => 0 ), array( 'woocommerce' => true ) )['rate_limit_rest'] ) );
// Per-account limit.
$r = p( array( 'rate_limit_account' => 0 ), array( 'fluentcommunity' => true ) );
t( 'rate_limit_account 0 with FluentCommunity → 60', isset( $r['rate_limit_account'] ) && 60 === (int) $r['rate_limit_account']['proposed'] && 'none' === $r['rate_limit_account']['risk'] );
$r = p( array( 'rate_limit_account' => 0 ), array( 'membership' => 'MemberPress' ) );
t( 'rate_limit_account 0 with MemberPress → 60, reason names it', isset( $r['rate_limit_account'] ) && false !== strpos( $r['rate_limit_account']['reason'], 'MemberPress' ) );
t( 'rate_limit_account 0 with neither: not proposed', ! isset( p( array( 'rate_limit_account' => 0 ) )['rate_limit_account'] ) );
t( 'rate_limit_account 1 with FluentCommunity: not proposed (already on)', ! isset( p( array( 'rate_limit_account' => 1 ), array( 'fluentcommunity' => true ) )['rate_limit_account'] ) );
// Low-value front-end protections: one row each.
$r = p( array( 'blur_on_capture' => 1, 'block_devtools' => 1, 'user_mark_guests' => 1 ) );
t( 'blur_on_capture, block_devtools, user_mark_guests 1 → 0: three rows, ticked, "annoys visitors"', 3 === count( $r ) && 0 === (int) $r['blur_on_capture']['proposed'] && 0 === (int) $r['block_devtools']['proposed'] && 0 === (int) $r['user_mark_guests']['proposed'] && 'none' === $r['block_devtools']['risk'] && false !== strpos( $r['user_mark_guests']['reason'], 'annoys visitors' ), wp_json_encode( $r ) );
t( 'the three at 0: not proposed', array() === p( array( 'blur_on_capture' => 0, 'block_devtools' => 0, 'user_mark_guests' => 0 ) ) );
// OneSignal.
$list = "facebookexternalhit\nUptimeRobot";
$r    = p( array( 'allow_list' => $list ), array( 'onesignal' => true ) );
t( 'OneSignal active, not in "Always allowed" → the line OneSignal added at the end', isset( $r['allow_list'] ) && $list . "\nOneSignal" === $r['allow_list']['proposed'] && 'none' === $r['allow_list']['risk'], wp_json_encode( $r ) );
t( 'OneSignal: the diff shows only the line', isset( $r['allow_list'] ) && array( 'without OneSignal', '+ OneSignal' ) === PNCP_Wizard::row_texts( $r['allow_list'] ) );
t( 'OneSignal already there (any case): not proposed', ! isset( p( array( 'allow_list' => $list . "\nonesignal" ), array( 'onesignal' => true ) )['allow_list'] ) );
t( 'OneSignal there, tied to an IP: not proposed', ! isset( p( array( 'allow_list' => $list . "\nOneSignal@192.0.2.1" ), array( 'onesignal' => true ) )['allow_list'] ) );
t( 'OneSignal not active: not proposed', ! isset( p( array( 'allow_list' => $list ) )['allow_list'] ) );
t( 'the names exist in PNCP_Options::defaults()', ! array_diff( array( 'probe_ban', 'block_ip_host', 'reputation', 'ban_strikes', 'ban_minutes', 'rate_limit', 'human_check', 'rate_limit_rest', 'rate_limit_account', 'blur_on_capture', 'block_devtools', 'user_mark_guests', 'allow_list' ), array_keys( PNCP_Options::defaults() ) ) );
// A filter's row with a setting in 'also' that does not exist: the whole row is dropped.
$bad = static function ( $out ) {
	$out['probe_ban'] = array( 'proposed' => 1, 'reason' => 'x', 'risk' => 'none', 'also' => array( 'no_such_setting' => 1 ) );
	return $out;
};
add_filter( 'pncp_wizard_proposals', $bad );
$r = p( array( 'probe_ban' => 0 ) );
remove_filter( 'pncp_wizard_proposals', $bad );
t( 'filter: a row whose "also" names an unknown setting is dropped', ! isset( $r['probe_ban'] ), wp_json_encode( $r ) );

/* ---------- 2. Membership plugins ---------- */
t( 'detect(): no membership plugin before', '' === PNCP_Wizard::detect()['membership'] );
activate_plugin( 'memberpress/memberpress.php', '', false, true );
$env = PNCP_Wizard::detect();
t( 'detect(): MemberPress by its main file', 'MemberPress' === $env['membership'], wp_json_encode( $env['membership'] ) );
t( 'detected_names(): MemberPress', in_array( 'MemberPress', PNCP_Wizard::detected_names( $env ), true ) );
t( 'membership_plugins(): the list (MemberPress, Paid Memberships Pro, WooCommerce Memberships, Restrict Content Pro, Ultimate Member, BuddyPress, BuddyBoss)', 7 === count( PNCP_Wizard::membership_plugins() ) && isset( PNCP_Wizard::membership_plugins()['BuddyBoss'] ) );
deactivate_plugins( 'memberpress/memberpress.php', true );

/* ---------- 3. The panel ---------- */
$admin   = get_user_by( 'id', 1 );
$cookies = cookies_for( $admin->ID );
$panel   = '/wp-admin/options-general.php?page=scrapelock&tab=general';
list( $code, $body ) = http( $panel, null, $cookies );
t( 'settings that suit, no stand-in: "Nothing to change"', 200 === $code && false !== strpos( $body, 'pncp-wizard-none' ) && false === strpos( $body, 'class="pncp-wizard-form"' ), (string) $code );

activate_plugin( 'fluent-community/fluent-community.php', '', false, true );
activate_plugin( 'onesignal-free-web-push-notifications/onesignal.php', '', false, true );
$bad_values = array(
	'probe_ban'          => 0,
	'block_ip_host'      => 0,
	'reputation'         => 0,
	'ban_strikes'        => 3,
	'ban_minutes'        => 600,
	'human_check'        => 1,
	'rate_limit'         => 20,
	'rate_limit_rest'    => 30,
	'rate_limit_account' => 0,
	'blur_on_capture'    => 1,
	'block_devtools'     => 1,
	'user_mark_guests'   => 1,
	'allow_list'         => $list,
);
settings( $bad_values );
$new_rows = array( 'probe_ban', 'block_ip_host', 'reputation', 'ban_strikes', 'rate_limit', 'rate_limit_rest', 'rate_limit_account', 'blur_on_capture', 'block_devtools', 'user_mark_guests', 'allow_list' );
$keys     = array_keys( PNCP_Wizard::proposals() );
t( 'every sensible-values row is proposed', ! array_diff( $new_rows, $keys ), implode( ',', $keys ) );
list( $code, $body ) = http( $panel, null, $cookies );
t( 'panel: 200 without PHP warnings, open', 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'id="pncp-wizard" open' ), (string) $code );
$ticked = true;
foreach ( $new_rows as $key ) {
	$ticked = $ticked && 1 === preg_match( '/value="' . $key . '" id="pncp-wizard-' . $key . '" checked/', $body );
}
t( 'panel: one row each, all ticked', $ticked );
t( 'panel: the block row shows both settings and the diff', false !== strpos( $body, '<code>ban_strikes, ban_minutes</code>' ) && false !== strpos( $body, '<td>after 3 violations, for 600 min</td>' ) && false !== strpos( $body, '<td>after 3 violations, for 120 min</td>' ) );
t( 'panel: the OneSignal row shows only the line', false !== strpos( $body, '<td>without OneSignal</td>' ) && false !== strpos( $body, '<td>+ OneSignal</td>' ) );
t( 'panel: "Found on this site" names FluentCommunity and OneSignal', 1 === preg_match( '/Found on this site:.*FluentCommunity.*OneSignal/s', $body ) );
t( 'panel: no row marked "Blocks more"', false === strpos( $body, 'pncp-wizard-row is-risky' ) );

/* ---------- 4. Apply selected ---------- */
$post = static function ( $nonce, $keys, $more = array() ) {
	return array_merge( array( 'action' => 'pncp_wizard', '_wpnonce' => $nonce, 'pncp_wizard_keys' => $keys ), $more );
};
$backups_before = count( PNCP_Settings_Io::backups() );
list( $code ) = http( '/wp-admin/admin-post.php', $post( 'wrong', array( 'probe_ban' ) ), $cookies );
t( 'wrong nonce: 403, nothing changes, no saved version', 403 === $code && 0 === (int) fresh()['probe_ban'] && count( PNCP_Settings_Io::backups() ) === $backups_before, (string) $code );
foreach ( array( 'subscriber', 'editor' ) as $role ) {
	$uid             = wp_insert_user( array( 'user_login' => 'pncp_w3121_' . $role . '_' . wp_rand( 1000, 9999 ), 'user_pass' => wp_generate_password(), 'role' => $role ) );
	$users[]         = $uid;
	$uc              = cookies_for( $uid );
	list( $code )    = http( '/wp-admin/admin-post.php', $post( nonce_for( $uid, $uc, 'pncp_wizard' ), array( 'probe_ban' ) ), $uc );
	t( "$role (no manage_options) with its own nonce: 403, nothing changes", 403 === $code && 0 === (int) fresh()['probe_ban'], (string) $code );
}

// Locked: apply() refuses (the site's real lock needs the authenticator app; the flag that says "locked elsewhere").
$elsewhere = new ReflectionProperty( 'PNCP_Lockdown', 'elsewhere' );
$elsewhere->setAccessible( true );
$elsewhere->setValue( null, true );
$locked = PNCP_Lockdown::is_locked() ? PNCP_Wizard::apply( array( 'probe_ban' ) ) : null;
$elsewhere->setValue( null, false );
t( 'locked: apply() refuses, nothing changes', is_wp_error( $locked ) && 'pncp_locked' === $locked->get_error_code() && 0 === (int) fresh()['probe_ban'] );

// The form was shown with rate_limit proposed (human check on); the human check is turned off before it is sent.
settings( array( 'human_check' => 0 ) );
$nonce = nonce_for( $admin->ID, $cookies, 'pncp_wizard' );
list( $code, , $loc ) = http(
	'/wp-admin/admin-post.php',
	$post(
		$nonce,
		array( 'probe_ban', 'ban_strikes', 'blur_on_capture', 'allow_list', 'rate_limit', 'ban_minutes', 'enabled' ),
		array(
			'pncp_settings' => array( 'probe_ban' => 0, 'ban_minutes' => 9999 ),
			'proposed'      => array( 'ban_strikes' => 1 ),
		)
	),
	$cookies
);
$s = fresh();
t( 'Apply selected: back with "applied" and the saved version', 302 === $code && false !== strpos( $loc, 'pncp_wizard=applied' ) && false !== strpos( $loc, 'pncp_wizard_undo=' ), $code . ' ' . $loc );
t( 'ticked rows applied: probe_ban 1, blocks 3 / 120 (both settings), blur_on_capture 0, OneSignal added', 1 === (int) $s['probe_ban'] && 3 === (int) $s['ban_strikes'] && 120 === (int) $s['ban_minutes'] && 0 === (int) $s['blur_on_capture'] && $list . "\nOneSignal" === $s['allow_list'], wp_json_encode( array( $s['probe_ban'], $s['ban_strikes'], $s['ban_minutes'], $s['blur_on_capture'], $s['allow_list'] ) ) );
t( 'unticked rows unchanged: block_ip_host, reputation, block_devtools, user_mark_guests, rate_limit_rest, rate_limit_account', 0 === (int) $s['block_ip_host'] && 0 === (int) $s['reputation'] && 1 === (int) $s['block_devtools'] && 1 === (int) $s['user_mark_guests'] && 30 === (int) $s['rate_limit_rest'] && 0 === (int) $s['rate_limit_account'] );
t( 'recomputed on the server: rate_limit, no longer proposed when sent, unchanged (20)', 20 === (int) $s['rate_limit'] );
t( 'posted values ignored, keys not proposed ignored (enabled)', (int) $saved['enabled'] === (int) $s['enabled'] && 120 === (int) $s['ban_minutes'] );
$backups = PNCP_Settings_Io::backups();
t( 'a saved version first ("wizard"), with the old values', 'wizard' === $backups[0]['reason'] && 0 === (int) $backups[0]['settings']['probe_ban'] && 600 === (int) $backups[0]['settings']['ban_minutes'] && 1 === (int) $backups[0]['settings']['blur_on_capture'] && $list === $backups[0]['settings']['allow_list'] && false !== strpos( $loc, 'pncp_wizard_undo=' . $backups[0]['id'] ) );
list( $code, $body ) = http( $panel, null, $cookies );
t( 'panel after: the applied rows are gone, the others are still there', 200 === $code && false === strpos( $body, 'value="probe_ban" id="pncp-wizard' ) && false === strpos( $body, 'value="ban_strikes" id="pncp-wizard' ) && false !== strpos( $body, 'value="block_devtools" id="pncp-wizard' ) );

/* ---------- 5. WP-CLI ---------- */
if ( '' !== $wp_cli ) {
	list( $rc, $out ) = cli( 'wizard --format=json' );
	$rows             = json_decode( $out, true );
	$by               = is_array( $rows ) ? array_column( $rows, null, 'setting' ) : array();
	t( 'cli wizard --format=json: the remaining rows, with the diff texts', 0 === $rc && isset( $by['block_devtools'], $by['rate_limit_account'] ) && 'On' === $by['block_devtools']['now'] && 'Off' === $by['block_devtools']['proposed'], $out );
	list( $rc, $out ) = cli( 'wizard --apply --yes' );
	$s                = fresh();
	t( 'cli wizard --apply --yes: the ticked-by-default rows applied', 0 === $rc && 1 === (int) $s['block_ip_host'] && 1 === (int) $s['reputation'] && 0 === (int) $s['block_devtools'] && 60 === (int) $s['rate_limit_rest'] && 60 === (int) $s['rate_limit_account'], $out );
	list( $rc, $out ) = cli( 'wizard' );
	t( 'cli: afterwards, nothing to change', 0 === $rc && false !== strpos( $out, 'Nothing to change' ), $out );
} else {
	echo "skip WP-CLI part (no WP_CLI)\n";
}

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
