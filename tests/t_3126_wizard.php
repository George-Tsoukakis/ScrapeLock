<?php
/**
 * ScrapeLock 3.12.6 — "For my site" (PNCP_Wizard): "Dismiss" a proposal, "Show dismissed (N)" with "Restore", and
 * "you chose this", in real WordPress:
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3126_wizard.php
 *
 * O. The owner's case: blur_on_capture = 1 and block_devtools = 1 kept on purpose → both dismissed → the count on
 *    the panel drops by 2 → "Apply selected" (also when the form or the command line sends them) never changes
 *    them → block_devtools 0 and back to 1: the same values and the same proposal, so it stays dismissed, and says
 *    "you chose this".
 * H. The hash: id + values now + proposed values. Another value now (rate_limit 30 → 35) or another proposal (a
 *    pncp_wizard_proposals filter) brings it back; the row of two settings (ban_strikes + ban_minutes) changes with
 *    either. Restore shows it again.
 * C. "you chose this": after a dismiss (in the dismissed list and when it comes back), after a settings save of
 *    another value than the one proposed, after "Apply selected" and a later save of the old value; not for a
 *    proposal nobody decided on, not after "Apply selected" itself.
 * S. Storage: one option for the site (not per user), not autoloaded, small (every proposal dismissed < 4 KB),
 *    cut to STATE_MAX entries, removed by uninstall.php, nothing in the settings or their export.
 * P. The panel over HTTP: the count without the dismissed ones, a "Dismiss" button per row (in its own form, so
 *    "Apply selected" stays the form's default button), "Show dismissed (N)" with "Restore" and the labels only
 *    (keys in tooltips); "Dismiss" / "Restore" through admin-post: wrong nonce and a subscriber refused (403),
 *    the notices; locked: dismiss() and restore() refuse.
 * L. wp scrapelock wizard (WP_CLI given): dismiss <id> / restore <id>, the "N dismissed" line, --include-dismissed
 *    with the state column, --apply never applies a dismissed one, --only=<dismissed> is refused.
 *
 * Settings, saved versions and the wizard state are put back at the end. Only on a test WordPress.
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
require_once ABSPATH . 'wp-admin/includes/user.php';
if ( ! function_exists( 'add_settings_error' ) ) {
	require_once ABSPATH . 'wp-admin/includes/template.php';
}

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** Saves settings as the settings form does (update_option, so the wizard's watch sees it). */
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Ip::reset();
	wp_cache_delete( 'alloptions', 'options' );
}

function fresh() {
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_delete( PNCP_OPTION, 'options' );
	wp_cache_delete( PNCP_Wizard::STATE, 'options' );
	PNCP_Options::flush();
	return PNCP_Options::stored();
}

/** [shown, dismissed] proposals now. */
function now_split() {
	fresh();
	return PNCP_Wizard::split( PNCP_Wizard::proposals() );
}

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
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.226', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 'Accept-Language: en' ),
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
	exec( $wp_cli . ' scrapelock ' . $args . ' 2>&1 </dev/null', $out, $rc );
	return array( $rc, implode( "\n", $out ) );
}

/** The wizard panel of a page ('' when there is none), with its nested <details>. */
function panel_of( $body ) {
	$start = strpos( $body, '<details class="pncp-card pncp-wizard"' );
	if ( false === $start ) {
		return '';
	}
	$depth = 0;
	$pos   = $start;
	while ( preg_match( '#<details\b|</details>#i', $body, $m, PREG_OFFSET_CAPTURE, $pos ) ) {
		$depth += '</details>' === strtolower( $m[0][0] ) ? -1 : 1;
		$pos    = $m[0][1] + strlen( $m[0][0] );
		if ( 0 === $depth ) {
			return substr( $body, $start, $pos - $start );
		}
	}
	return '';
}

/** The number in the panel's "N suggestions" tag (0 without one). */
function badge( $panel ) {
	return preg_match( '#<h2 id="pncp-wizard-title">.*?(\d+) suggestions?#s', $panel, $m ) ? (int) $m[1] : 0;
}

$saved         = get_option( PNCP_OPTION );
$saved_backups = get_option( PNCP_Settings_Io::BACKUPS, null );
$saved_state   = get_option( PNCP_Wizard::STATE, null );
$users         = array();
delete_option( PNCP_Wizard::STATE );
// The settings are saved in this script as WP-CLI and wp-admin save them: the wizard watches them there.
PNCP_Wizard::watch();
$admin   = get_user_by( 'id', 1 );
$cookies = cookies_for( $admin->ID );
$panel   = '/wp-admin/options-general.php?page=' . PNCP_Admin::PAGE . '&tab=general';

// The live site's settings that matter here: three sensible proposals stay (probe_ban, rate_limit with the human
// check, and the two the owner keeps on).
settings(
	array(
		'enabled'          => 1,
		'monitor_mode'     => 0,
		'probe_ban'        => 0,
		'block_ip_host'    => 1,
		'reputation'       => 1,
		'ban_strikes'      => 3,
		'ban_minutes'      => 120,
		'human_check'      => 1,
		'rate_limit'       => 30,
		'blur_on_capture'  => 1,
		'block_devtools'   => 1,
		'user_mark_guests' => 0,
	)
);
delete_option( PNCP_Wizard::STATE ); // The save above is the test's own set-up, not a choice.

/* ---------- O. The owner's case ---------- */

list( $shown ) = now_split();
t( 'O: blur_on_capture and block_devtools are proposed (On → Off), with probe_ban and rate_limit', isset( $shown['blur_on_capture'], $shown['block_devtools'], $shown['probe_ban'], $shown['rate_limit'] ), implode( ',', array_keys( $shown ) ) );
$count_before = count( $shown );
list( $code, $body ) = http( $panel, null, $cookies );
$p = panel_of( $body );
t( 'O: the panel counts them', 200 === $code && badge( $p ) === $count_before, $code . ' ' . badge( $p ) . '/' . $count_before );
t( 'O: dismiss blur_on_capture', true === PNCP_Wizard::dismiss( 'blur_on_capture' ) );
t( 'O: dismiss block_devtools', true === PNCP_Wizard::dismiss( 'block_devtools' ) );
list( $shown, $gone ) = now_split();
t( 'O: both are dismissed, the others still shown', isset( $gone['blur_on_capture'], $gone['block_devtools'] ) && ! isset( $shown['blur_on_capture'] ) && ! isset( $shown['block_devtools'] ) && isset( $shown['probe_ban'] ) );
list( $code, $body ) = http( $panel, null, $cookies );
$p = panel_of( $body );
t( 'O: the count drops by 2', badge( $p ) === $count_before - 2, badge( $p ) . ' vs ' . $count_before );
$r = PNCP_Wizard::apply( array( 'blur_on_capture', 'block_devtools', 'probe_ban' ) );
$s = fresh();
t( 'O: "Apply selected" with them sent anyway: only probe_ban changes', is_array( $r ) && '' !== $r['id'] && 1 === (int) $s['probe_ban'] && 1 === (int) $s['blur_on_capture'] && 1 === (int) $s['block_devtools'], wp_json_encode( $r ) );
$only = PNCP_Wizard::apply( array( 'blur_on_capture', 'block_devtools' ) );
$s    = fresh();
t( 'O: only dismissed ones sent: nothing changes, no saved version', is_array( $only ) && '' === $only['id'] && 1 === (int) $s['blur_on_capture'] && 1 === (int) $s['block_devtools'] );
settings( array( 'block_devtools' => 0 ) );
list( $shown, $gone ) = now_split();
t( 'O: block_devtools 0: not proposed at all', ! isset( $shown['block_devtools'] ) && ! isset( $gone['block_devtools'] ) );
settings( array( 'block_devtools' => 1 ) );
list( $shown, $gone ) = now_split();
$state = PNCP_Wizard::state();
t( 'O: back to 1: the same values and proposal → still dismissed', isset( $gone['block_devtools'] ) && ! isset( $shown['block_devtools'] ) );
t( 'O: … and it says "you chose this"', isset( $gone['block_devtools'] ) && PNCP_Wizard::is_chosen( 'block_devtools', $gone['block_devtools'], $state ) );

/* ---------- H. The hash ---------- */

t( 'H: rate_limit 30 → 45 proposed', isset( $shown['rate_limit'] ) && 45 === (int) $shown['rate_limit']['proposed'] );
t( 'H: dismiss rate_limit', true === PNCP_Wizard::dismiss( 'rate_limit' ) );
list( $shown, $gone ) = now_split();
t( 'H: dismissed while 30', isset( $gone['rate_limit'] ) && ! isset( $shown['rate_limit'] ) );
$filter = static function ( $out ) {
	if ( isset( $out['rate_limit'] ) ) {
		$out['rate_limit']['proposed'] = 50;
	}
	return $out;
};
add_filter( 'pncp_wizard_proposals', $filter );
list( $shown, $gone ) = now_split();
t( 'H: the proposal changes (45 → 50): it comes back', isset( $shown['rate_limit'] ) && ! isset( $gone['rate_limit'] ) );
$state = PNCP_Wizard::state();
t( 'H: … saying "you chose this" (the value is still the one kept)', isset( $shown['rate_limit'] ) && PNCP_Wizard::is_chosen( 'rate_limit', $shown['rate_limit'], $state ) );
remove_filter( 'pncp_wizard_proposals', $filter );
settings( array( 'rate_limit' => 35 ) );
list( $shown, $gone ) = now_split();
$state = PNCP_Wizard::state();
t( 'H: the setting changes (30 → 35): it comes back', isset( $shown['rate_limit'] ) && ! isset( $gone['rate_limit'] ) );
t( 'H: … saying "you chose this" (35 was saved after 45 was proposed)', isset( $shown['rate_limit'] ) && PNCP_Wizard::is_chosen( 'rate_limit', $shown['rate_limit'], $state ) );
settings( array( 'rate_limit' => 30 ) );
list( , $gone ) = now_split();
t( 'H: back to 30: dismissed again (same values, same proposal)', isset( $gone['rate_limit'] ) );
t( 'H: restore rate_limit', true === PNCP_Wizard::restore( 'rate_limit' ) );
list( $shown, $gone ) = now_split();
t( 'H: restored: shown and counted again', isset( $shown['rate_limit'] ) && ! isset( $gone['rate_limit'] ) );
t( 'H: restore of something not dismissed: an error, nothing stored', is_wp_error( PNCP_Wizard::restore( 'rate_limit' ) ) );
t( 'H: dismiss of something not proposed: an error', is_wp_error( PNCP_Wizard::dismiss( 'enabled' ) ) && is_wp_error( PNCP_Wizard::dismiss( 'no_such_key' ) ) );
// The row of two settings: either one is part of it.
settings( array( 'ban_minutes' => 600 ) );
list( $shown ) = now_split();
t( 'H: ban_strikes row (3 / 600 → 3 / 120) proposed and dismissed', isset( $shown['ban_strikes'] ) && true === PNCP_Wizard::dismiss( 'ban_strikes' ) );
settings( array( 'ban_minutes' => 300 ) );
list( $shown, $gone ) = now_split();
t( 'H: ban_minutes 600 → 300 (the other setting of the row): it comes back', isset( $shown['ban_strikes'] ) && ! isset( $gone['ban_strikes'] ) );
settings( array( 'ban_minutes' => 120 ) );

/* ---------- C. "you chose this" ---------- */

list( $shown ) = now_split();
$state = PNCP_Wizard::state();
t( 'C: not for a proposal nobody decided on (probe_ban is applied; rate_limit restored but kept: yes)', ! isset( $shown['probe_ban'] ) && isset( $shown['rate_limit'] ) && PNCP_Wizard::is_chosen( 'rate_limit', $shown['rate_limit'], $state ) );
// Applied, then the old value saved again.
settings( array( 'probe_ban' => 0 ) );
list( $shown ) = now_split();
$state = PNCP_Wizard::state();
t( 'C: probe_ban applied by the wizard, then saved back to 0: proposed again, "you chose this"', isset( $shown['probe_ban'] ) && PNCP_Wizard::is_chosen( 'probe_ban', $shown['probe_ban'], $state ) );
$r     = PNCP_Wizard::apply( array( 'probe_ban' ) );
$state = PNCP_Wizard::state();
t( 'C: "Apply selected" forgets the choice', is_array( $r ) && ! isset( $state['chosen']['probe_ban'] ) && isset( $state['applied']['probe_ban'] ) );
// A setting changed on its own (no proposal before): not a choice against the wizard.
settings( array( 'user_mark_guests' => 1 ) );
list( $shown ) = now_split();
$state = PNCP_Wizard::state();
t( 'C: user_mark_guests turned on (it was not proposed before): proposed, no "you chose this"', isset( $shown['user_mark_guests'] ) && ! PNCP_Wizard::is_chosen( 'user_mark_guests', $shown['user_mark_guests'], $state ) );
settings( array( 'user_mark_guests' => 0 ) );

/* ---------- S. Storage ---------- */

global $wpdb;
$autoload = $wpdb->get_var( $wpdb->prepare( "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s", PNCP_Wizard::STATE ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
t( 'S: one option for the site, not autoloaded', null !== $autoload && in_array( $autoload, array( 'no', 'off' ), true ), (string) $autoload );
t( 'S: nothing in the settings or their export', ! array_key_exists( 'pncp_wizard_state', PNCP_Options::stored() ) && false === strpos( wp_json_encode( PNCP_Settings_Io::export() ), 'dismissed' ) );
list( $shown ) = now_split();
foreach ( array_keys( $shown ) as $id ) {
	PNCP_Wizard::dismiss( $id );
}
$size = strlen( maybe_serialize( get_option( PNCP_Wizard::STATE ) ) );
t( 'S: every proposal dismissed: still small (< 4 KB)', $size < 4096, (string) $size );
list( $shown, $gone ) = now_split();
t( 'S: nothing left to count', ! $shown && count( $gone ) >= 3, count( $shown ) . '/' . count( $gone ) );
$many = PNCP_Wizard::state();
for ( $i = 0; $i < PNCP_Wizard::STATE_MAX + 15; $i++ ) {
	$many['dismissed'][ 'x' . $i ] = array(
		'hash' => md5( (string) $i ),
		'at'   => 1000 + $i,
	);
}
update_option( PNCP_Wizard::STATE, $many, false );
PNCP_Wizard::dismiss( 'blur_on_capture' );
$cut = PNCP_Wizard::state();
t( 'S: cut to STATE_MAX dismissed entries, the oldest first', PNCP_Wizard::STATE_MAX === count( $cut['dismissed'] ) && isset( $cut['dismissed']['blur_on_capture'] ) && ! isset( $cut['dismissed']['x0'] ) );
update_option( PNCP_Wizard::STATE, array( 'dismissed' => 'broken', 'chosen' => array( 'a' => array() ) ), false );
wp_cache_delete( PNCP_Wizard::STATE, 'options' );
t( 'S: a damaged option reads as empty, no warning', array( 'dismissed' => array(), 'chosen' => array(), 'applied' => array() ) === PNCP_Wizard::state() );
t( 'S: uninstall.php removes it', false !== strpos( (string) file_get_contents( PNCP_DIR . 'uninstall.php' ), "delete_option( 'pncp_wizard_state' )" ) );
delete_option( PNCP_Wizard::STATE );

/* ---------- P. The panel over HTTP ---------- */

PNCP_Wizard::dismiss( 'blur_on_capture' );
PNCP_Wizard::dismiss( 'block_devtools' );
list( $shown ) = now_split();
list( $code, $body ) = http( $panel, null, $cookies );
$p = panel_of( $body );
t( 'P: the panel: count without the dismissed ones', 200 === $code && badge( $p ) === count( $shown ), badge( $p ) . ' ' . count( $shown ) );
t( 'P: a "Dismiss" button on every row, in the dismiss form', count( $shown ) === preg_match_all( '#<button type="submit" class="button button-small pncp-wizard-dismiss" form="pncp-wizard-dismiss-form" name="pncp_wizard_dismiss" value="[a-z_]+" aria-label="Dismiss: [^"]+">Dismiss</button>#', $p ) );
t( 'P: the dismiss form has the action and a nonce', 1 === preg_match( '#<form method="post" action="[^"]*admin-post\.php" id="pncp-wizard-dismiss-form"[^>]*>\s*<input type="hidden" name="action" value="pncp_wizard">\s*<input type="hidden" name="_wpnonce" value="[0-9a-f]+"#', $p ) );
$apply_form = preg_match( '#<form method="post"[^>]*class="pncp-wizard-form">.*?</form>#s', $p, $fm ) ? $fm[0] : '';
$own_submit = preg_match_all( '#<button\b[^>]*type="submit"[^>]*>#', (string) preg_replace( '#<button[^>]*form="pncp-wizard-dismiss-form"[^>]*>.*?</button>#s', '', $apply_form ), $bm ) ? $bm[0] : array();
t( 'P: "Apply selected" is the only submit button of its form (the Dismiss buttons belong to the other form)', '' !== $apply_form && 1 === count( $own_submit ) && false !== strpos( $own_submit[0], 'id="pncp-submit-wizard"' ), wp_json_encode( $own_submit ) );
t( 'P: no row for a dismissed proposal', false === strpos( $apply_form, 'value="blur_on_capture"' ) && false === strpos( $apply_form, 'value="block_devtools"' ) );
t( 'P: "Show dismissed (2)" with "Restore" for each', false !== strpos( $p, 'Show dismissed (2)' ) && 2 === preg_match_all( '#name="pncp_wizard_restore" value="(blur_on_capture|block_devtools)">Restore</button>#', $p ) );
$list = preg_match( '#<ul class="pncp-wizard-dismissed-list">.*?</ul>#s', $p, $lm ) ? $lm[0] : '';
$text = trim( (string) preg_replace( '/\s+/', ' ', wp_strip_all_tags( $list ) ) );
t( 'P: the dismissed list: labels and "Now … proposed …", "you chose this", no bare key', false !== strpos( $text, 'Block the developer tools shortcuts' ) && false !== strpos( $text, 'Now On, proposed Off.' ) && 2 === substr_count( $text, 'you chose this' ) && false === strpos( $text, 'block_devtools' ), $text );
t( 'P: the keys are in the tooltips', false !== strpos( $list, 'title="block_devtools"' ) && false !== strpos( $list, 'title="blur_on_capture"' ) );
t( 'P: the help line and its "More"', false !== strpos( $p, 'Not counted and never applied. One comes back if its setting changes.' ) && false !== strpos( $p, 'Changing the setting and putting the same value back keeps it dismissed.' ) );
t( 'P: no PHP warnings', ! preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:/', $body ) );

$post = static function ( $nonce, $more ) {
	return array_merge(
		array(
			'action'   => 'pncp_wizard',
			'_wpnonce' => $nonce,
		),
		$more
	);
};
list( $code ) = http( '/wp-admin/admin-post.php', $post( 'wrong', array( 'pncp_wizard_dismiss' => 'probe_ban' ) ), $cookies );
list( $shown ) = now_split();
t( 'P: Dismiss with a wrong nonce: 403, nothing dismissed', 403 === $code && isset( $shown['rate_limit'] ) && ! isset( PNCP_Wizard::state()['dismissed']['rate_limit'] ), (string) $code );
$uid     = wp_insert_user(
	array(
		'user_login' => 'pncp_w3126_sub_' . wp_rand( 1000, 9999 ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'subscriber',
	)
);
$users[] = $uid;
$uc      = cookies_for( $uid );
list( $code ) = http( '/wp-admin/admin-post.php', $post( nonce_for( $uid, $uc, 'pncp_wizard' ), array( 'pncp_wizard_dismiss' => 'rate_limit' ) ), $uc );
t( 'P: a subscriber with its own nonce: 403, nothing dismissed', 403 === $code && ! isset( PNCP_Wizard::state()['dismissed']['rate_limit'] ), (string) $code );
$nonce = nonce_for( $admin->ID, $cookies, 'pncp_wizard' );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', $post( $nonce, array( 'pncp_wizard_dismiss' => 'rate_limit' ) ), $cookies );
list( $shown, $gone ) = now_split();
t( 'P: Dismiss: back with "dismissed", the row is dismissed', 302 === $code && false !== strpos( $loc, 'pncp_wizard=dismissed' ) && isset( $gone['rate_limit'] ) && ! isset( $shown['rate_limit'] ), $code . ' ' . $loc );
list( , $body ) = http( (string) wp_parse_url( $loc, PHP_URL_PATH ) . '?' . (string) wp_parse_url( $loc, PHP_URL_QUERY ), null, $cookies );
t( 'P: the notice says where it went', false !== strpos( $body, 'Dismissed. It is under “Show dismissed” and comes back only if its setting or the suggestion changes.' ) && false !== strpos( panel_of( $body ), 'Show dismissed (3)' ) );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', $post( $nonce, array( 'pncp_wizard_dismiss' => 'enabled' ) ), $cookies );
t( 'P: Dismiss of something not proposed: "gone", nothing stored', 302 === $code && false !== strpos( $loc, 'pncp_wizard=gone' ) && ! isset( PNCP_Wizard::state()['dismissed']['enabled'] ) );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', $post( $nonce, array( 'pncp_wizard_keys' => array( 'rate_limit', 'blur_on_capture' ) ) ), $cookies );
$s = fresh();
t( 'P: "Apply selected" with dismissed rows posted: nothing applied', 302 === $code && false !== strpos( $loc, 'pncp_wizard=none' ) && 30 === (int) $s['rate_limit'] && 1 === (int) $s['blur_on_capture'], $code . ' ' . $loc );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', $post( $nonce, array( 'pncp_wizard_restore' => 'rate_limit' ) ), $cookies );
list( $shown ) = now_split();
t( 'P: Restore: back with "restored", shown again', 302 === $code && false !== strpos( $loc, 'pncp_wizard=restored' ) && isset( $shown['rate_limit'] ), $code . ' ' . $loc );
list( , $body ) = http( $panel, null, $cookies );
$p   = panel_of( $body );
$row = preg_match( '#<tr class="pncp-wizard-row[^"]*">(?:(?!</tr>).)*value="rate_limit"(?:(?!</tr>).)*</tr>#s', $p, $rm ) ? $rm[0] : '';
t( 'P: the restored row says "you chose this" next to the value now', false !== strpos( $row, '<td>30 <span class="pncp-tag pncp-tag--default pncp-wizard-chosen">you chose this</span></td>' ), $row );
$elsewhere = new ReflectionProperty( 'PNCP_Lockdown', 'elsewhere' );
$elsewhere->setAccessible( true );
$elsewhere->setValue( null, true );
$locked_d = PNCP_Lockdown::is_locked() ? PNCP_Wizard::dismiss( 'rate_limit' ) : null;
$locked_r = PNCP_Lockdown::is_locked() ? PNCP_Wizard::restore( 'blur_on_capture' ) : null;
$elsewhere->setValue( null, false );
$state = PNCP_Wizard::state();
t( 'P: locked: dismiss() and restore() refuse, nothing changes', is_wp_error( $locked_d ) && 'pncp_locked' === $locked_d->get_error_code() && is_wp_error( $locked_r ) && ! isset( $state['dismissed']['rate_limit'] ) && isset( $state['dismissed']['blur_on_capture'] ) );

/* ---------- L. WP-CLI ---------- */

if ( '' !== $wp_cli ) {
	list( $rc, $out ) = cli( 'wizard' );
	t( 'L: wizard: the dismissed ones not listed, a line says how many', 0 === $rc && false === strpos( $out, 'blur_on_capture' ) && false !== strpos( $out, '2 dismissed proposals are not listed (--include-dismissed lists them).' ), $out );
	list( $rc, $out ) = cli( 'wizard --include-dismissed --format=json' );
	$rows             = json_decode( $out, true );
	$by               = is_array( $rows ) ? array_column( $rows, null, 'setting' ) : array();
	t( 'L: --include-dismissed: a state column, "you chose this" with the value now', 0 === $rc && isset( $by['blur_on_capture'], $by['rate_limit'] ) && 'dismissed' === $by['blur_on_capture']['state'] && 'proposed' === $by['rate_limit']['state'] && 'On (you chose this)' === $by['blur_on_capture']['now'], $out );
	list( $rc, $out ) = cli( 'wizard --format=json' );
	$rows             = json_decode( $out, true );
	t( 'L: without it: the same columns as before (no state)', 0 === $rc && is_array( $rows ) && $rows && array( 'setting', 'now', 'proposed', 'risk', 'reason' ) === array_keys( $rows[0] ), $out );
	list( $rc, $out ) = cli( 'wizard --apply --only=blur_on_capture --yes' );
	t( 'L: --apply --only=<dismissed>: refused, nothing changes', 0 !== $rc && false !== strpos( $out, 'is dismissed' ) && 1 === (int) fresh()['blur_on_capture'], $out );
	list( $rc, $out ) = cli( 'wizard dismiss rate_limit' );
	t( 'L: wizard dismiss rate_limit', 0 === $rc && isset( PNCP_Wizard::state()['dismissed']['rate_limit'] ), $out );
	list( $rc, $out ) = cli( 'wizard --apply --all --yes' );
	$s                = fresh();
	t( 'L: --apply --all: the dismissed ones untouched', 1 === (int) $s['blur_on_capture'] && 1 === (int) $s['block_devtools'] && 30 === (int) $s['rate_limit'], $out );
	list( $rc, $out ) = cli( 'wizard restore rate_limit' );
	t( 'L: wizard restore rate_limit', 0 === $rc && ! isset( PNCP_Wizard::state()['dismissed']['rate_limit'] ), $out );
	list( $rc, $out ) = cli( 'wizard restore rate_limit' );
	t( 'L: restore of one not dismissed: an error', 0 !== $rc && false !== strpos( $out, 'is not dismissed' ), $out );
	list( $rc, $out ) = cli( 'wizard dismiss' );
	t( 'L: dismiss without a setting: the usage', 0 !== $rc && false !== strpos( $out, 'wizard dismiss <setting>' ), $out );
} else {
	echo "skip WP-CLI part (no WP_CLI)\n";
}

/* ---------- Clean-up ---------- */
foreach ( $users as $uid ) {
	wp_delete_user( $uid );
}
update_option( PNCP_OPTION, $saved );
if ( null === $saved_backups ) {
	delete_option( PNCP_Settings_Io::BACKUPS );
} else {
	update_option( PNCP_Settings_Io::BACKUPS, $saved_backups, false );
}
if ( null === $saved_state ) {
	delete_option( PNCP_Wizard::STATE );
} else {
	update_option( PNCP_Wizard::STATE, $saved_state, false );
}
PNCP_Options::flush();
echo $fails ? "\n$fails FAIL\n" : "\nall PASS\n";
exit( $fails ? 1 : 0 );
