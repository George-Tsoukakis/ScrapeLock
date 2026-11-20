<?php
/**
 * ScrapeLock 3.11 — δομή της σελίδας ρυθμίσεων: οι καρτέλες σε τέσσερις ομάδες (κάθε παλιά διεύθυνση και τα
 * aliases της 3.10 ανοίγουν τη σωστή καρτέλα), η καρτέλα Bots ως accordion (ανοιχτά μόνο Bots, Limits, Sign-in,
 * «Advanced» για τα προχωρημένα) και οι μακριές λίστες με «N entries» + «Edit» (το textarea με όλη την τιμή).
 * Σε πραγματικό WordPress μέσα από HTTP (με cookie διαχειριστή).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_311_ui.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

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
	wp_cache_delete( 'alloptions', 'options' );
}

$admin   = get_user_by( 'id', 1 );
$expire  = time() + DAY_IN_SECONDS;
$token   = WP_Session_Tokens::get_instance( $admin->ID )->create( $expire );
$cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( $admin->ID, $expire, 'auth', $token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( $admin->ID, $expire, 'logged_in', $token ),
);
$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
wp_set_current_user( $admin->ID );

function http( $path, $post = null ) {
	global $base, $cookies;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.210', 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: en' ),
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

// The tab the page shows (pncp-admin--<tab>).
function shown_tab( $body ) {
	return preg_match( '/class="wrap pncp-admin pncp-admin--([a-z0-9_-]+)/', $body, $m ) ? $m[1] : '';
}

$saved = PNCP_Options::stored();
settings( array( 'enabled' => 1, 'monitor_mode' => 0, 'monitor_until' => 0 ) );
$page = '/wp-admin/options-general.php?page=scrapelock';

/* ---------- Καρτέλες σε ομάδες ---------- */
$groups = array(
	'content'  => array( 'general', 'images', 'content' ),
	'bots'     => array( 'bots' ),
	'security' => array( 'hardening', 'rules', 'lockdown' ),
	'records'  => array( 'log', 'attacks' ),
);
$tabs   = array( 'general', 'bots', 'content', 'images', 'rules', 'log', 'attacks', 'hardening', 'lockdown' );
$all    = array();
foreach ( PNCP_Admin_Tabs::grouped( array_fill_keys( $tabs, 'x' ) ) as $key => $group ) {
	$all[ $key ] = array_keys( $group['tabs'] );
}
t( 'grouped(): οι 4 ομάδες με τις 9 καρτέλες, καθεμία μία φορά', $groups === $all, wp_json_encode( $all ) );
$extra = PNCP_Admin_Tabs::grouped( array( 'general' => 'A', 'newtab' => 'B' ) );
t( 'grouped(): καρτέλα χωρίς ομάδα στο «More», χωρίς άδειες ομάδες', array( 'content', 'more' ) === array_keys( $extra ) && isset( $extra['more']['tabs']['newtab'] ), wp_json_encode( $extra ) );
t( 'group_of(): Lockdown στο Security, Attacks στο Records', 'security' === PNCP_Admin_Tabs::group_of( 'lockdown', array_fill_keys( $tabs, 'x' ) ) && 'records' === PNCP_Admin_Tabs::group_of( 'attacks', array_fill_keys( $tabs, 'x' ) ) );

foreach ( $tabs as $tab ) {
	list( $code, $body ) = http( $page . '&tab=' . $tab );
	$nav = preg_match( '#<nav class="nav-tab-wrapper pncp-tabs pncp-tabs--grouped".*?</nav>#s', $body, $m ) ? $m[0] : '';
	$ok  = 200 === $code && ! php_errors( $body ) && $tab === shown_tab( $body ) && '' !== $nav;
	foreach ( $groups as $g => $members ) {
		$ok = $ok && false !== strpos( $nav, 'pncp-tab-group--' . $g );
	}
	// The active tab is inside its own group, and that group is the current one.
	$group = PNCP_Admin_Tabs::group_of( $tab, array_fill_keys( $tabs, 'x' ) );
	$ok    = $ok && (bool) preg_match( '#pncp-tab-group--' . $group . ' is-current".*?tab=' . $tab . '" class="nav-tab nav-tab-active#s', $nav );
	$ok    = $ok && 9 === preg_match_all( '/class="nav-tab[ "]/', $nav ) && 1 === substr_count( $nav, 'nav-tab-active' );
	t( "tab=$tab: η σωστή καρτέλα, ενεργή μέσα στην ομάδα της, όλες οι ομάδες", $ok, $code . ' ' . shown_tab( $body ) );
}
foreach ( array( 'vulnerable' => 'hardening', 'server' => 'rules', 'attack' => 'attacks', 'logs' => 'log', 'cdn' => 'bots', 'feeds' => 'content', 'watermark' => 'images', 'page' => 'general', 'lock' => 'lockdown' ) as $alias => $want ) {
	list( $code, $body ) = http( $page . '&tab=' . $alias );
	t( "3.10 alias tab=$alias → $want, χωρίς ειδοποίηση", 200 === $code && $want === shown_tab( $body ) && false === strpos( $body, 'pncp-unknown-tab' ), shown_tab( $body ) );
}
list( $code, $body ) = http( $page . '&tab=nosuchtab' );
t( 'άγνωστη καρτέλα: η πρώτη καρτέλα με την ειδοποίηση της 3.10', 200 === $code && 'general' === shown_tab( $body ) && false !== strpos( $body, 'pncp-unknown-tab' ) && false !== strpos( $body, 'Unknown tab “nosuchtab”' ) );
list( $code, $body ) = http( $page );
t( 'χωρίς tab: η πρώτη καρτέλα (On the page)', 200 === $code && 'general' === shown_tab( $body ) && false === strpos( $body, 'pncp-unknown-tab' ) );

/* ---------- Bots: accordion ---------- */
function part_open( $body, $id ) {
	return (bool) preg_match( '/<details class="[^"]*pncp-acc[^"]*" id="' . preg_quote( $id, '/' ) . '" open>/', $body );
}
function part_closed( $body, $id ) {
	return (bool) preg_match( '/<details class="[^"]*" id="' . preg_quote( $id, '/' ) . '">/', $body );
}
list( $code, $body ) = http( $page . '&tab=bots' );
$parts = array( 'monitor', 'bots', 'ai', 'allowed', 'blocked', 'login', 'login_slug', 'limits', 'human', 'reputation', 'countries', 'ban', 'crowdsec' );
$ok    = 200 === $code && ! php_errors( $body );
foreach ( $parts as $id ) {
	$ok = $ok && 1 === substr_count( $body, 'id="pncp-sec-' . $id . '"' ) && ( part_open( $body, 'pncp-sec-' . $id ) || part_closed( $body, 'pncp-sec-' . $id ) );
}
t( 'bots: κάθε μέρος είναι <details> με το παλιό id', $ok, $code );
t( 'bots: ανοιχτά μόνο Bots, Limits, Sign-in', part_open( $body, 'pncp-sec-bots' ) && part_open( $body, 'pncp-sec-limits' ) && part_open( $body, 'pncp-sec-login' ) && 3 === preg_match_all( '/<details class="[^"]*pncp-acc[^"]*" id="[^"]+" open>/', $body ) );
t( 'bots: Network and CDN, Blocking at the CDN κλειστά όπως πριν', part_closed( $body, 'pncp-sec-network' ) && part_closed( $body, 'pncp-sec-edge' ) && part_closed( $body, 'pncp-acc-lists' ) );
$adv = strpos( $body, 'id="pncp-group-advanced"' );
t(
	'bots: «Advanced» πριν από CrowdSec, Network and CDN, Blocking at the CDN, Official IP lists, μετά το Temporary block',
	false !== $adv && $adv > strpos( $body, 'id="pncp-sec-ban"' ) && $adv < strpos( $body, 'id="pncp-sec-crowdsec"' ) && $adv < strpos( $body, 'id="pncp-sec-network"' ) && $adv < strpos( $body, 'id="pncp-sec-edge"' ) && $adv < strpos( $body, 'id="pncp-sec-lists"' )
);
$form = preg_match( '#<form method="post" action="options.php" class="pncp-settings-form".*?</form>#s', $body, $m ) ? $m[0] : '';
t( 'bots: CrowdSec και Temporary block μέσα στη φόρμα της καρτέλας (ίδια πεδία)', false !== strpos( $form, 'name="pncp_settings[crowdsec_mode]"' ) && false !== strpos( $form, 'name="pncp_settings[ban_minutes]"' ) && false !== strpos( $form, 'name="pncp_settings[bot_list]"' ) && false !== strpos( $form, 'name="pncp_settings[ip_header]"' ) );
t( 'bots: γρήγοροι σύνδεσμοι στα μέρη', false !== strpos( $body, 'href="#pncp-sec-human"' ) && false !== strpos( $body, 'href="#pncp-sec-lists"' ) );
list( , $body ) = http( $page . '&tab=bots&pncp_sections=pncp-sec-human,pncp-sec-network,pncp-acc-lists' );
t( 'bots μετά από Save: ανοιχτά όσα ήταν ανοιχτά (Human check, Network, IP lists), κλειστά τα υπόλοιπα', part_open( $body, 'pncp-sec-human' ) && (bool) preg_match( '/id="pncp-sec-network" open>/', $body ) && part_open( $body, 'pncp-acc-lists' ) && part_closed( $body, 'pncp-sec-bots' ) && part_closed( $body, 'pncp-sec-limits' ) );
list( , $body ) = http( $page . '&tab=bots&pncp_message=lists' );
t( 'bots μετά από «Refresh lists now»: το Official IP lists ανοιχτό', part_open( $body, 'pncp-acc-lists' ) );
list( $code, $body ) = http( $page . '&tab=content' );
t( 'άλλες καρτέλες: χωρίς accordion (πίνακας ρυθμίσεων όπως πριν)', 200 === $code && false === strpos( $body, 'pncp-acc' ) && false !== strpos( $body, '<table class="form-table"' ) );

/* __MORE__ */

update_option( PNCP_OPTION, $saved );
PNCP_Options::flush();
echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
