<?php
/**
 * ScrapeLock — δοκιμές των νέων της 3.6 σε πραγματικό WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_360.php
 *
 * Υδατογράφημα αναγνώστη, όριο ανά λογαριασμό, κοινός λογαριασμός, απόκρυψη αποτυπώματος WordPress, αόρατο
 * ίχνος στο κείμενο, εξαιρέσεις της παγίδας (DuckDuckBot κ.λπ.) και φόρτωση κλάσεων μόνο όταν χρειάζονται.
 * (Τα πρότυπα του Site Editor στο Lockdown είναι στο t_lockdown.php, όπου το site είναι κλειδωμένο.)
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR και BASE απαιτούνται\n" );
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
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** Αίτημα με curl: [code, headers (πεζά), body]. */
function req( $path, $headers = array() ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER         => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_TIMEOUT        => 30,
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
}

function browser( $ip, $extra = array() ) {
	return array_merge(
		array(
			'X-Test-IP'       => $ip,
			'User-Agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36',
			'Accept-Language' => 'el-GR,el;q=0.9',
		),
		$extra
	);
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
}

function test_user( $login, $role ) {
	$u = get_user_by( 'login', $login );
	return $u ? $u->ID : wp_insert_user( array( 'user_login' => $login, 'user_pass' => wp_generate_password(), 'role' => $role ) );
}

function login_cookie( $user_id ) {
	$exp = time() + HOUR_IN_SECONDS;
	$tok = WP_Session_Tokens::get_instance( $user_id )->create( $exp );
	return LOGGED_IN_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( $user_id, $exp, 'logged_in', $tok ) );
}

function same_minute() {
	$left = 60 - time() % 60;
	if ( $left < 15 ) {
		sleep( $left + 1 );
	}
}

function fresh() {
	global $wpdb;
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_%pncp\_%' OR option_name LIKE '\_transient\_timeout\_%pncp\_%'" );
	PNCP_Log::unban_all();
	PNCP_Log::clear();
	wp_cache_flush();
	PNCP_Log::reset_cache();
}

$pncp_saved = PNCP_Options::stored();
update_option( 'pncp_emergency_until', 0 );
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'rate_limit'              => 0,
		'rate_limit_search'       => 0,
		'rate_limit_rest'         => 0,
		'rate_limit_unverified'   => 0,
		'rate_limit_datacenter'   => 0,
		'require_browser_headers' => 0,
		'human_check'             => 0,
		'block_headless'          => 0,
		'ban_strikes'             => 3,
		// 3.11: νέα εγκατάσταση με ban σαρωτών και φήμη IP· εδώ όπως ένα site πριν από την 3.11.
		'probe_ban'               => 0,
		'reputation'              => 0,
		'ip_header'               => 'remote_addr',
		'exempt_cap'              => 'edit_posts',
		'scope_posts'             => 1,
		'user_mark'               => 0,
		'user_mark_guests'        => 0,
		'text_trace'              => 0,
		'rate_limit_account'      => 0,
		'shared_alert'            => 0,
		'hide_fingerprint'        => 0,
		'hide_versions'           => 0,
		'disable_pingback'        => 0,
		'hide_rest_discovery'     => 0,
	)
);
fresh();
$post   = get_posts( array( 'numberposts' => 1, 'post_type' => 'post' ) )[0];
$url    = wp_parse_url( get_permalink( $post ), PHP_URL_PATH );
$member = test_user( 'pncp_reader360', 'subscriber' );
$editor = test_user( 'pncp_editor360', 'editor' );
// Το κείμενο της δοκιμής με δύο παραγράφους (για το ίχνος).
wp_update_post( array( 'ID' => $post->ID, 'post_content' => "Πρώτη παράγραφος με κείμενο.\n\nΔεύτερη παράγραφος εδώ." ) );

/* ---------- Υδατογράφημα αναγνώστη ---------- */
list( $code, $hdr, $body ) = req( $url, browser( '203.0.113.60', array( 'Cookie' => login_cookie( $member ) ) ) );
t( 'υδατογράφημα κλειστό: τίποτα στη σελίδα', 200 === $code && false === strpos( $body, 'pncpMark' ), (string) $code );
settings( array( 'user_mark' => 1 ) );
list( $code, $hdr, $body ) = req( $url, browser( '203.0.113.61', array( 'Cookie' => login_cookie( $member ) ) ) );
t( 'υδατογράφημα: ο συνδεδεμένος βλέπει το όνομα χρήστη του και την ώρα', 200 === $code && false !== strpos( $body, 'window.pncpMark' ) && false !== strpos( $body, 'pncp_reader360 \\u00b7 ' . wp_date( 'Y-m-d' ) ), substr( (string) strstr( $body, 'pncpMark' ), 0, 160 ) );
t( 'υδατογράφημα: η σελίδα με το όνομα δεν κρατιέται σε cache (Cache-Control: private, no-store)', false !== strpos( $hdr, 'cache-control: private, no-store' ), $hdr );
t( 'υδατογράφημα: το script μπαίνει στο <head>', false !== strpos( (string) strstr( $body, '</head>', true ), 'id="pncp-mark-js-after"' ) );
list( , , $body ) = req( $url, browser( '203.0.113.62' ) );
t( 'υδατογράφημα: επισκέπτης χωρίς λογαριασμό, «και για επισκέπτες» κλειστό: τίποτα', false === strpos( $body, 'pncpMark' ) );
list( , , $body ) = req( $url, browser( '203.0.113.63', array( 'Cookie' => login_cookie( $editor ) ) ) );
t( 'υδατογράφημα: το προσωπικό που εξαιρείται δεν το βλέπει', false === strpos( $body, 'pncpMark' ) );
settings( array( 'user_mark_guests' => 1 ) );
list( , $hdr, $body ) = req( $url, browser( '203.0.113.64' ) );
t( 'υδατογράφημα επισκέπτη: η σελίδα δεν έχει IP (cache), μόνο τη διεύθυνση του admin-ajax', false !== strpos( $body, 'pncpMark' ) && false === strpos( $body, '203.0.113.64' ) && false !== strpos( $body, 'action=pncp_mark' ) && false === strpos( $hdr, 'cache-control: private, no-store' ) );
list( $code, $hdr, $body ) = req( '/wp-admin/admin-ajax.php?action=pncp_mark', browser( '203.0.113.65' ) );
$pncp_j = json_decode( $body, true );
t( 'υδατογράφημα επισκέπτη: το admin-ajax δίνει IP και ώρα, χωρίς cache', 200 === $code && ! empty( $pncp_j['success'] ) && 0 === strpos( (string) $pncp_j['data']['text'], '203.0.113.65 · ' ) && false !== strpos( $hdr, 'no-cache' ), $body );
settings( array( 'user_mark_guests' => 0 ) );
list( $code ) = req( '/wp-admin/admin-ajax.php?action=pncp_mark', browser( '203.0.113.66' ) );
t( 'υδατογράφημα επισκέπτη κλειστό: το admin-ajax δεν δίνει τίποτα', 404 === $code, (string) $code );
settings( array( 'user_mark_opacity' => 999 ) );
t( 'υδατογράφημα: η διαφάνεια μένει μέσα στα όρια (2–60)', 60 === (int) PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'user_mark_opacity' => 999 ) ) )['user_mark_opacity'] );
settings( array( 'user_mark' => 0, 'user_mark_opacity' => 10 ) );

/* ---------- Όριο σελίδων ανά λογαριασμό ---------- */
fresh();
settings( array( 'rate_limit_account' => 2 ) );
same_minute();
$pncp_codes = array();
foreach ( array( '198.51.100.81', '198.51.100.82', '198.51.100.83' ) as $pncp_ip ) {
	$pncp_codes[] = req( $url, browser( $pncp_ip, array( 'Cookie' => login_cookie( $member ) ) ) )[0];
}
t( 'όριο ανά λογαριασμό 2: τρεις σελίδες από τρεις IP → 200,200,429', array( 200, 200, 429 ) === $pncp_codes, implode( ',', $pncp_codes ) );
t( 'όριο ανά λογαριασμό: στο αρχείο ως rate_account, χωρίς αποκλεισμό IP', in_array( 'rate_account', $wpdb->get_col( "SELECT reason FROM {$wpdb->prefix}pncp_log" ), true ) && array() === PNCP_Log::active_bans() );
list( $code ) = req( $url, browser( '198.51.100.84' ) );
t( 'όριο ανά λογαριασμό: επισκέπτης χωρίς λογαριασμό δεν επηρεάζεται', 200 === $code, (string) $code );
$pncp_codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$pncp_codes[] = req( $url, browser( '198.51.100.85', array( 'Cookie' => login_cookie( $editor ) ) ) )[0];
}
t( 'όριο ανά λογαριασμό: το προσωπικό που εξαιρείται δεν μετριέται', array( 200, 200, 200 ) === $pncp_codes, implode( ',', $pncp_codes ) );
settings( array( 'rate_limit_account' => 0 ) );

/* ---------- Κοινός λογαριασμός ---------- */
fresh();
$pncp_mails = array();
$pncp_mail  = static function ( $r, $atts ) use ( &$pncp_mails ) {
	$pncp_mails[] = $atts;
	return true;
};
add_filter( 'pre_wp_mail', $pncp_mail, 10, 2 );
settings( array( 'shared_alert' => 1, 'shared_ips' => 3, 'shared_logout' => 0 ) );
$pncp_obs = static function ( $user_id, $ip ) {
	wp_set_current_user( $user_id );
	$_SERVER['REMOTE_ADDR'] = $ip;
	PNCP_Ip::reset();
	return PNCP_Accounts::observe();
};
$pncp_r1 = $pncp_obs( $member, '198.51.100.91' );
$pncp_r2 = $pncp_obs( $member, '198.51.100.92' );
t( 'κοινός λογαριασμός: δύο διευθύνσεις, όριο 3 → τίποτα', array( 2, false ) === $pncp_r2 && array() === $pncp_mails, wp_json_encode( $pncp_r2 ) );
$pncp_r3 = $pncp_obs( $member, '198.51.100.93' );
t( 'κοινός λογαριασμός: τρίτη διεύθυνση μέσα σε 10 λεπτά → εντοπίζεται', array( 3, true ) === $pncp_r3, wp_json_encode( $pncp_r3 ) );
t( 'κοινός λογαριασμός: email στη διεύθυνση διαχείρισης με το όνομα και τις διευθύνσεις', 1 === count( $pncp_mails ) && false !== strpos( (string) $pncp_mails[0]['message'], 'pncp_reader360' ) && false !== strpos( (string) $pncp_mails[0]['message'], '198.51.100.93' ) && get_option( 'admin_email' ) === $pncp_mails[0]['to'] );
$pncp_obs( $member, '198.51.100.94' );
t( 'κοινός λογαριασμός: το πολύ ένα email την ημέρα ανά λογαριασμό', 1 === count( $pncp_mails ) );
t( 'κοινός λογαριασμός: η ίδια διεύθυνση στο ίδιο λεπτό δεν γράφει ξανά', array( 4, false ) === $pncp_obs( $member, '198.51.100.94' ) );
t( 'κοινός λογαριασμός: το προσωπικό δεν παρακολουθείται', null === $pncp_obs( $editor, '198.51.100.95' ) );
// «Αποσύνδεση από παντού αλλού»: μένει μόνο η συνεδρία του τρέχοντος αιτήματος.
fresh();
settings( array( 'shared_logout' => 1 ) );
$pncp_tokens = WP_Session_Tokens::get_instance( $member );
$pncp_tokens->destroy_all();
foreach ( array( 1, 2, 3 ) as $pncp_i ) {
	$pncp_tokens->create( time() + HOUR_IN_SECONDS );
}
$pncp_keep = $pncp_tokens->create( time() + HOUR_IN_SECONDS );
$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $member, time() + HOUR_IN_SECONDS, 'logged_in', $pncp_keep );
foreach ( array( '198.51.100.96', '198.51.100.97', '198.51.100.98' ) as $pncp_ip ) {
	$pncp_obs( $member, $pncp_ip );
}
t( 'κοινός λογαριασμός + αποσύνδεση: μένει μόνο η τρέχουσα συνεδρία', 1 === count( WP_Session_Tokens::get_instance( $member )->get_all() ) && null !== WP_Session_Tokens::get_instance( $member )->get( $pncp_keep ), (string) count( WP_Session_Tokens::get_instance( $member )->get_all() ) );
unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
wp_set_current_user( 0 );
remove_filter( 'pre_wp_mail', $pncp_mail, 10 );
settings( array( 'shared_alert' => 0, 'shared_logout' => 0 ) );
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
PNCP_Ip::reset();

/* ---------- Απόκρυψη αποτυπώματος WordPress ---------- */
list( , $hdr, $body ) = req( $url, browser( '203.0.113.70' ) );
t( 'αποτύπωμα κλειστό: τα σημάδια του WordPress υπάρχουν (σημείο αναφοράς)', false !== strpos( $body, 'https://api.w.org/' ) && false !== strpos( $body, 'EditURI' ) );
settings( array( 'hide_fingerprint' => 1 ) );
list( , $hdr, $body ) = req( $url, browser( '203.0.113.71' ) );
t( 'αποτύπωμα: χωρίς generator, REST/oEmbed/RSD/shortlink στο <head>', false === strpos( $body, 'name="generator"' ) && false === strpos( $body, 'https://api.w.org/' ) && false === strpos( $body, 'EditURI' ) && false === strpos( $body, 'rel=\'shortlink\'' ) && false === strpos( $body, 'application/json+oembed' ) );
t( 'αποτύπωμα: χωρίς το emoji script', false === strpos( $body, 'wp-emoji' ) && false === strpos( $body, '_wpemojiSettings' ) );
t( 'αποτύπωμα: χωρίς Link api.w.org και X-Pingback στα headers', false === strpos( $hdr, 'api.w.org' ) && false === strpos( $hdr, 'x-pingback' ), $hdr );
t( 'αποτύπωμα: ?ver= χωρίς την έκδοση του WordPress (όπως «Hide versions»)', false === strpos( $body, 'ver=' . get_bloginfo( 'version' ) ) );
t( 'αποτύπωμα: «X-Redirect-By: WordPress» φεύγει', false === apply_filters( 'x_redirect_by', 'WordPress', 302, '/' ) );
list( , , $body ) = req( $url, browser( '203.0.113.72', array( 'Cookie' => login_cookie( $editor ) ) ) );
t( 'αποτύπωμα: ο συνδεδεμένος κρατά τους συνδέσμους (editor, admin bar)', false !== strpos( $body, 'https://api.w.org/' ) );
t( 'αποτύπωμα: οι κανόνες Nginx / Apache αρνούνται readme.html και license.txt', false !== strpos( PNCP_Rules::nginx_server(), 'readme' ) && false !== strpos( PNCP_Rules::apache(), 'readme' ) );
list( $code, , $body ) = req( '/wp-json/', browser( '203.0.113.73' ) );
t( 'αποτύπωμα: το REST API δουλεύει κανονικά', 200 === $code && false !== strpos( $body, '"namespaces"' ), (string) $code );
settings( array( 'hide_fingerprint' => 0 ) );

/* ---------- Αόρατο ίχνος στο κείμενο ---------- */
settings( array( 'text_trace' => 1 ) );
list( , $hdr, $body ) = req( $url, browser( '203.0.113.80', array( 'Cookie' => login_cookie( $member ) ) ) );
$pncp_found = PNCP_Trace::find( $body );
t( 'ίχνος: ο συνδεδεμένος παίρνει το κείμενο με το ίχνος του λογαριασμού του', 1 === count( $pncp_found ) && (int) $member === $pncp_found[0]['user_id'] && $pncp_found[0]['valid'] && $pncp_found[0]['count'] >= 2, wp_json_encode( $pncp_found ) );
t( 'ίχνος: η σελίδα δεν κρατιέται σε cache', false !== strpos( $hdr, 'cache-control: private, no-store' ) );
t( 'ίχνος: το ορατό κείμενο μένει ίδιο (χωρίς τους αόρατους χαρακτήρες)', false !== strpos( str_replace( array( PNCP_Trace::ZERO, PNCP_Trace::ONE, "\u{2060}", "\u{200D}" ), '', $body ), 'Πρώτη παράγραφος με κείμενο.' ) );
list( , , $body ) = req( $url, browser( '203.0.113.81' ) );
t( 'ίχνος: επισκέπτης χωρίς λογαριασμό (και μηχανές αναζήτησης) χωρίς ίχνος', array() === PNCP_Trace::find( $body ) );
list( , , $body ) = req( $url, browser( '203.0.113.82', array( 'Cookie' => login_cookie( $editor ) ) ) );
t( 'ίχνος: το προσωπικό που εξαιρείται χωρίς ίχνος', array() === PNCP_Trace::find( $body ) );
$pncp_fake = str_replace( PNCP_Trace::ZERO, PNCP_Trace::ONE, PNCP_Trace::token( 5 ) );
$pncp_ff   = PNCP_Trace::find( 'κείμενο ' . $pncp_fake );
t( 'ίχνος: πλαστό ίχνος (χωρίς τα κλειδιά του site) → «όχι του site»', 1 === count( $pncp_ff ) && false === $pncp_ff[0]['valid'] );
// Το εργαλείο στην καρτέλα Log: επικόλληση → ο λογαριασμός.
wp_set_current_user( 1 );
$_POST = array(
	'pncp_trace_text' => 'Αντιγραμμένο: Πρώτη ' . PNCP_Trace::token( $member ) . 'παράγραφος',
	'_pncp_trace'     => wp_create_nonce( PNCP_Trace::ACTION ),
);
ob_start();
PNCP_Trace::render();
$pncp_html = (string) ob_get_clean();
t( 'ίχνος: «Find whose copy this is» δείχνει τον λογαριασμό', false !== strpos( $pncp_html, 'pncp_reader360' ) && false !== strpos( $pncp_html, 'user-edit.php?user_id=' . $member ) );
$_POST['_pncp_trace'] = 'wrong';
ob_start();
PNCP_Trace::render();
$pncp_html = (string) ob_get_clean();
t( 'ίχνος: χωρίς σωστό nonce δεν ψάχνει', false === strpos( $pncp_html, 'pncp_reader360' ) );
$_POST = array();
wp_set_current_user( $member );
ob_start();
PNCP_Trace::render();
t( 'ίχνος: το εργαλείο μόνο για διαχειριστές', '' === (string) ob_get_clean() );
wp_set_current_user( 0 );
settings( array( 'text_trace' => 0 ) );

/* ---------- Εξαιρέσεις της παγίδας: όχι μόνο με το όνομα στο User-Agent ---------- */
$pncp_ban = static function ( $ip, $ua, $rdns = null, $fdns = null ) {
	$_SERVER['REMOTE_ADDR']         = $ip;
	$_SERVER['HTTP_USER_AGENT']     = $ua;
	$_SERVER['HTTP_SEC_FETCH_SITE'] = 'none'; // As a bot or a typed address (not an old browser).
	PNCP_Ip::reset();
	$r = $rdns;
	$f = $fdns;
	$rd = static function () use ( $r ) {
		return $r;
	};
	$fd = static function () use ( $f ) {
		return $f;
	};
	add_filter( 'pncp_reverse_dns', $rd, 30 );
	add_filter( 'pncp_forward_dns', $fd, 30 );
	$out = ( function ( $ip ) {
		return self::should_ban_on_sight( $ip, 'pncp_t360_' );
	} )->bindTo( null, 'PNCP_Bots' )( $ip );
	remove_filter( 'pncp_reverse_dns', $rd, 30 );
	remove_filter( 'pncp_forward_dns', $fd, 30 );
	return $out;
};
PNCP_Ip::store_list( 'dc_aws', array( '198.18.250.0/24' ) );
t( 'παγίδα: «DuckDuckBot» από data center → αποκλείεται (πριν: ποτέ)', $pncp_ban( '198.18.250.7', 'DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)' ) );
t( 'παγίδα: «DuckDuckBot» εκτός data center → εξαιρείται, όπως πριν', ! $pncp_ban( '203.0.113.90', 'DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)' ) );
t( 'παγίδα: Baiduspider με reverse DNS στο baidu.com που δείχνει πίσω → εξαιρείται', ! $pncp_ban( '198.18.250.8', 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)', 'baiduspider-198-18-250-8.crawl.baidu.com', array( '198.18.250.8' ) ) );
t( 'παγίδα: «Baiduspider» με ξένο reverse DNS → αποκλείεται', $pncp_ban( '203.0.113.91', 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)', 'scanner.example.net', array( '203.0.113.91' ) ) );
delete_option( PNCP_Ip::LISTS_OPTION . '_dc_aws' );
PNCP_Ip::reset();
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
unset( $_SERVER['HTTP_USER_AGENT'], $_SERVER['HTTP_SEC_FETCH_SITE'] );

/* ---------- Φόρτωση κλάσεων μόνο όταν χρειάζονται ---------- */
t( 'autoload: PNCP_Settings_Io → class-pncp-settings-io.php', class_exists( 'PNCP_Settings_Io' ) );
t( 'autoload: άγνωστη κλάση PNCP_ → κανένα σφάλμα', ! class_exists( 'PNCP_Does_Not_Exist' ) );
list( $code, , $body ) = req( $url, browser( '203.0.113.95' ) );
t( 'σελίδα επισκέπτη μετά την αλλαγή φόρτωσης: 200 χωρίς PHP σφάλματα', 200 === $code && false === stripos( $body, 'Fatal error' ) && false === stripos( $body, 'Warning:' ) );

/* ---------- Καθάρισμα ---------- */
wp_update_post( array( 'ID' => $post->ID, 'post_content' => 'Test content.' ) );
update_option( PNCP_OPTION, $pncp_saved );
PNCP_Options::flush();
fresh();

exit( $fails ? 1 : 0 );
