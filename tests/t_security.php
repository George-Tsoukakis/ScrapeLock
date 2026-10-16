<?php
/**
 * ScrapeLock — αυτοματοποιημένες δοκιμές ασφαλείας (επιθέσεις από έξω και από χρήστες χωρίς δικαίωμα).
 *
 *   WP_DIR=/srv/wpt BASE=http://127.0.0.1:8080 php t_security.php
 *
 * CSRF / δικαιώματα σε κάθε ενέργεια διαχείρισης, XSS και SQL injection μέσα από ό,τι καταγράφεται,
 * open redirect, παρακάμψεις των προστατευμένων feeds, άμεση πρόσβαση στα αρχεία του plugin.
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
}
function req( $path, $method = 'GET', $body = null, $headers = array(), $cookie = '' ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	$o = array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_HTTPHEADER => $h, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_TIMEOUT => 60, CURLOPT_PATH_AS_IS => true );
	if ( null !== $body ) {
		$o[ CURLOPT_POSTFIELDS ] = is_array( $body ) ? http_build_query( $body ) : $body;
	}
	if ( $cookie ) {
		$o[ CURLOPT_COOKIE ] = $cookie;
	}
	curl_setopt_array( $ch, $o );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, substr( $out, 0, $hs ), substr( $out, $hs ) );
}
function login( $user_id ) {
	$exp = time() + HOUR_IN_SECONDS;
	$tok = WP_Session_Tokens::get_instance( $user_id )->create( $exp );
	$c   = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $exp, 'auth', $tok ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $exp, 'logged_in', $tok ),
	);
	$_COOKIE[ LOGGED_IN_COOKIE ] = $c[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	$parts = array();
	foreach ( $c as $k => $v ) {
		$parts[] = $k . '=' . rawurlencode( $v );
	}
	return implode( '; ', $parts );
}
function test_user( $login, $role ) {
	$u = get_user_by( 'login', $login );
	return $u ? $u->ID : wp_insert_user( array( 'user_login' => $login, 'user_pass' => wp_generate_password(), 'role' => $role ) );
}
$b = array( 'User-Agent' => 'Mozilla/5.0 Chrome/141', 'Accept-Language' => 'el', 'X-Test-IP' => '192.0.2.10' );

PNCP_Log::unban_all();
settings( array( 'enabled' => 1, 'exempt_cap' => 'edit_posts', 'private_paths' => '/skroutz.xml', 'rate_limit' => 0, 'ban_strikes' => 3 ) );
$enabled_before = PNCP_Options::stored()['enabled'];

/* ---------- CSRF: ενέργειες χωρίς σωστό nonce (διαχειριστής συνδεδεμένος) ---------- */
$admin_cookie = login( 1 );
$actions      = array(
	array( 'pncp_toggle', array( 'state' => 'off' ) ),
	array( 'pncp_emergency', array( 'hours' => 24 ) ),
	array( 'pncp_profile', array( 'profile' => 'maximum' ) ),
	array( 'pncp_token', array( 'op' => 'rotate', 'grace' => 0 ) ),
	array( 'pncp_log', array( 'op' => 'unban_all' ) ),
	array( 'pncp_log', array( 'op' => 'clear_log' ) ),
);
$token_before = PNCP_Private_Urls::token_data()['hash'];
foreach ( $actions as $a ) {
	list( $code ) = req( '/wp-admin/admin-post.php', 'POST', array_merge( array( 'action' => $a[0], '_wpnonce' => 'invalid' ), $a[1] ), $b, $admin_cookie );
	t( "CSRF {$a[0]}" . ( isset( $a[1]['op'] ) ? " ({$a[1]['op']})" : '' ) . ': χωρίς σωστό nonce απορρίπτεται', in_array( $code, array( 403, 400 ), true ) || 200 === $code, (string) $code );
}
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'CSRF: τίποτα δεν άλλαξε (προστασία, Emergency, token, προφίλ)', (int) $enabled_before === (int) PNCP_Options::stored()['enabled'] && 0 === PNCP_Options::emergency_until() && $token_before === PNCP_Private_Urls::token_data()['hash'] && 'maximum' !== PNCP_Options::current_profile( PNCP_Options::stored() ) );
list( $code ) = req( '/wp-admin/options.php', 'POST', array( 'option_page' => 'pncp_settings_group', 'action' => 'update', '_wpnonce' => 'invalid', 'pncp_settings' => array( '_sections' => array( 'general' ), 'enabled' => '' ) ), $b, $admin_cookie );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'CSRF: φόρμα ρυθμίσεων χωρίς nonce δεν σβήνει την προστασία', ! empty( PNCP_Options::stored()['enabled'] ), (string) $code );

/* ---------- Δικαιώματα: συνδρομητής με έγκυρα nonces ---------- */
$sub        = test_user( 'pncp_sub', 'subscriber' );
$sub_cookie = login( $sub );
foreach ( array( 'pncp_toggle' => array( 'state' => 'off' ), 'pncp_emergency' => array( 'hours' => 24 ), 'pncp_profile' => array( 'profile' => 'maximum' ), 'pncp_token' => array( 'op' => 'rotate' ), 'pncp_log' => array( 'op' => 'unban_all' ) ) as $action => $extra ) {
	list( $code ) = req( '/wp-admin/admin-post.php', 'POST', array_merge( array( 'action' => $action, '_wpnonce' => wp_create_nonce( $action ) ), $extra ), $b, $sub_cookie );
	t( "συνδρομητής με δικό του nonce: $action → 403", 403 === $code, (string) $code );
}
list( $code ) = req( '/wp-admin/admin-ajax.php', 'POST', array( 'action' => 'pncp_wm_batch', 'nonce' => wp_create_nonce( 'pncp_wm_batch' ), 'mode' => 'remove' ), $b, $sub_cookie );
t( 'συνδρομητής: εργαλείο εικόνων (AJAX) → 403', 403 === $code, (string) $code );
list( $code ) = req( '/wp-admin/admin-ajax.php', 'POST', array( 'action' => 'pncp_wm_batch', 'mode' => 'remove' ), $b );
t( 'επισκέπτης: εργαλείο εικόνων (AJAX) → απορρίπτεται', in_array( $code, array( 400, 403 ), true ), (string) $code );
list( $code, , $body ) = req( '/wp-admin/options-general.php?page=scrapelock', 'GET', null, $b, $sub_cookie );
t( 'συνδρομητής: η σελίδα ρυθμίσεων δεν ανοίγει', 200 !== $code || false === strpos( $body, 'pncp-admin' ), (string) $code );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'δικαιώματα: τίποτα δεν άλλαξε', ! empty( PNCP_Options::stored()['enabled'] ) && 0 === PNCP_Options::emergency_until() && $token_before === PNCP_Private_Urls::token_data()['hash'] );

/* ---------- Open redirect ---------- */
$admin_cookie = login( 1 );
foreach ( array( 'https://evil.example/phish', '//evil.example/x', 'https://127.0.0.1:8080.evil.example/' ) as $target ) {
	list( $code, $hdr ) = req( '/wp-admin/admin-post.php?action=pncp_toggle&state=on&_wpnonce=' . wp_create_nonce( 'pncp_toggle' ) . '&redirect=' . rawurlencode( $target ), 'GET', null, $b, $admin_cookie );
	$loc = preg_match( '/^location:\s*(\S+)/mi', $hdr, $m ) ? $m[1] : '';
	t( "open redirect προς $target: όχι", 302 === $code && false === stripos( $loc, 'evil.example' ), $loc );
}

/* ---------- XSS / SQL injection μέσα από το αρχείο ---------- */
PNCP_Log::clear();
$xss = '"><script>alert(1)</script><img src=x onerror=alert(2)>';
req( '/hello-world/?<script>alert(3)</script>', 'GET', null, array( 'X-Test-IP' => '198.51.100.40', 'User-Agent' => 'GPTBot ' . $xss ) );
$sqli = "GPTBot' OR '1'='1'; DROP TABLE wp_pncp_log; -- ";
req( '/hello-world/', 'GET', null, array( 'X-Test-IP' => '198.51.100.41', 'User-Agent' => $sqli ) );
global $wpdb;
$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}pncp_log WHERE ip = %s", '198.51.100.41' ), ARRAY_A );
t( 'SQL injection στο User-Agent: αποθηκεύεται ως κείμενο, ο πίνακας υπάρχει', $row && false !== strpos( $row['ua'], "OR '1'='1'" ) );
list( , , $body ) = req( '/wp-admin/options-general.php?page=scrapelock&tab=log', 'GET', null, $b, $admin_cookie );
t( 'XSS: το αρχείο δείχνει το User-Agent escaped', false !== strpos( $body, 'GPTBot' ) && false === strpos( $body, '<script>alert(1)' ) && false === strpos( $body, '<img src=x onerror' ) && false === strpos( $body, '<script>alert(3)' ) );

/* ---------- XSS / header injection μέσα από τις ρυθμίσεις ---------- */
$clean = PNCP_Options::sanitize(
	array(
		'_sections'      => array( 'general', 'bots' ),
		'message'        => '<script>alert(4)</script>Μήνυμα',
		'tdm_policy_url' => "javascript:alert(5)",
		'bot_list'       => "</textarea><script>alert(6)</script>\nGPTBot",
		'excluded_ids'   => '1, 2; DROP TABLE x',
	)
);
t( 'ρυθμίσεις: μήνυμα χωρίς HTML', false === strpos( $clean['message'], '<script' ) );
t( 'ρυθμίσεις: URL javascript: απορρίπτεται', '' === $clean['tdm_policy_url'], $clean['tdm_policy_url'] );
t( 'ρυθμίσεις: λίστα bots χωρίς tags', false === strpos( $clean['bot_list'], '<' ) );
t( 'ρυθμίσεις: IDs μόνο αριθμοί', '1, 2' === $clean['excluded_ids'], $clean['excluded_ids'] );
$crlf = PNCP_Options::sanitize( array( '_sections' => array( 'general' ), 'tdm_policy_url' => "https://example.test/terms\r\nSet-Cookie: x=1" ) );
t( 'ρυθμίσεις: URL με CRLF (header injection) καθαρίζεται', false === strpos( $crlf['tdm_policy_url'], "\n" ) && false === strpos( $crlf['tdm_policy_url'], "\r" ) );

/* ---------- Παρακάμψεις των προστατευμένων feeds ---------- */
PNCP_Private_Urls::rotate( 0 );
$variants = array( '/skroutz.xml', '/SKROUTZ.XML', '/skroutz.xml/', '/index.php/skroutz.xml', '/skroutz%2Exml', '/./skroutz.xml', '/skroutz.xml?cp_token[]=x', '/skroutz.xml?cp_token=', '/skroutz.xml?CP_TOKEN=x' );
foreach ( $variants as $v ) {
	list( $code, , $body ) = req( $v, 'GET', null, $b + array( 'X-Test-IP' => '203.0.113.50' ) );
	t( "feed χωρίς token, μορφή $v: όχι το περιεχόμενο", false === strpos( $body, 'ΤΙΜΟΚΑΤΑΛΟΓΟΣ' ), (string) $code );
}
list( , , $body ) = req( '/skroutz.xml', 'GET', null, $b + array( 'X-Test-IP' => '203.0.113.51', 'Authorization' => 'Basic ' . base64_encode( 'a:b' ) ) );
t( 'feed: Authorization Basic (όχι Bearer) δεν δίνει πρόσβαση', false === strpos( $body, 'ΤΙΜΟΚΑΤΑΛΟΓΟΣ' ) );
list( , , $body ) = req( '/skroutz.xml', 'GET', null, $b + array( 'X-Test-IP' => '203.0.113.52', 'X-Forwarded-For' => '127.0.0.1', 'X-Real-IP' => '127.0.0.1', 'CF-Connecting-IP' => '127.0.0.1' ) );
t( 'feed: πλαστό X-Forwarded-For / CF-Connecting-IP = 127.0.0.1 δεν δίνει πρόσβαση', false === strpos( $body, 'ΤΙΜΟΚΑΤΑΛΟΓΟΣ' ) );

/* ---------- Άμεση πρόσβαση στα αρχεία του plugin ---------- */
foreach ( array( 'includes/class-pncp-admin.php', 'includes/class-pncp-bots.php', 'uninstall.php', 'scrapelock.php' ) as $f ) {
	list( $code, , $body ) = req( '/wp-content/plugins/scrapelock/' . $f, 'GET', null, $b );
	t( "άμεσο άνοιγμα του $f: καμία έξοδος / σφάλμα", '' === trim( $body ) && 500 !== $code, $code . ' ' . substr( $body, 0, 80 ) );
}
list( $code, , $body ) = req( '/wp-content/plugins/scrapelock/includes/', 'GET', null, $b );
t( 'λίστα αρχείων του φακέλου includes: όχι', false === strpos( $body, 'class-pncp' ), (string) $code );

/* ---------- Καθαρά πρωτότυπα: δεν βρίσκονται ---------- */
$dir = basename( PNCP_Watermark::backup_dir() );
t( 'φάκελος πρωτοτύπων: τυχαίο όνομα 12 χαρακτήρων', (bool) preg_match( '/^pncp-originals-[a-z0-9]{12}$/', $dir ) );
list( $code, , $body ) = req( wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH ) . '/', 'GET', null, $b );
t( 'uploads: χωρίς λίστα αρχείων που θα αποκάλυπτε τον φάκελο', false === strpos( $body, $dir ), (string) $code );
t( 'backup_path: δεν δέχεται διαδρομές εκτός uploads (..)', '' === PNCP_Watermark::backup_path( ABSPATH . 'wp-config.php' ) && '' === PNCP_Watermark::backup_path( wp_get_upload_dir()['basedir'] . '/../../wp-config.php' ) );

/* ---------- Χρονική επίθεση στο token ---------- */
$src = file_get_contents( WP_PLUGIN_DIR . '/scrapelock/includes/class-pncp-private-urls.php' );
t( 'token: σύγκριση με hash_equals (σταθερός χρόνος)', 2 <= substr_count( $src, 'hash_equals(' ) );

PNCP_Log::unban_all();
settings( array( 'enabled' => 1 ) );
echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
