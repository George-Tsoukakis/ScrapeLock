<?php
/**
 * ScrapeLock — συνεργασία με πραγματικό WP Super Cache (page cache της PHP).
 *
 *   WP_DIR=/srv/wpt BASE=http://127.0.0.1:8080 php t_cache.php
 *
 * Απαιτεί WP Super Cache ενεργό, με $cache_enabled = true και $super_cache_enabled = true (simple mode).
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

if ( ! function_exists( 'wp_cache_setting' ) ) {
	echo "SKIP χωρίς WP Super Cache\n";
	exit( 0 );
}

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
function req( $path, $ua, $ip, $extra = array() ) {
	global $base;
	$h  = array( 'User-Agent: ' . $ua, 'Accept: text/html', 'Accept-Language: el', 'X-Test-IP: ' . $ip );
	foreach ( $extra as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	$ch = curl_init( $base . $path );
	curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $h, CURLOPT_TIMEOUT => 30 ) );
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}
$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36';

PNCP_Log::unban_all();
settings( array( 'enabled' => 1, 'block_bots' => 1, 'rate_limit' => 0, 'bot_list' => PNCP_Options::default_bot_list(), 'private_paths' => '/skroutz.xml' ) );
wp_cache_clear_cache();

/* ---------- Bots και σελίδες από την cache: μόνο οι κανόνες server τα σταματούν ---------- */
// Το WP Super Cache σερβίρει τις σελίδες του πριν φορτωθούν τα plugins, και τα «Rejected User Agents»
// του σταματούν μόνο τη δημιουργία νέας cache, όχι το σερβίρισμα. Γι' αυτό το plugin δίνει κανόνες server.
$post = wp_insert_post( array( 'post_title' => 'Cache ' . wp_generate_password( 6, false ), 'post_content' => 'ΠΕΡΙΕΧΟΜΕΝΟ_CACHE', 'post_status' => 'publish' ) );
$url  = wp_parse_url( get_permalink( $post ), PHP_URL_PATH );
req( $url, $chrome, '203.0.113.230' );
list( $code, $body ) = req( $url, $chrome, '203.0.113.231' );
t( 'browser: η σελίδα σερβίρεται από την cache', 200 === $code && false !== strpos( $body, 'WP-Super-Cache' ) );
if ( is_writable( '/etc/nginx' ) ) {
	file_put_contents( '/etc/nginx/conf.d/pncp-http.conf', PNCP_Rules::nginx_http() );
	file_put_contents( '/etc/nginx/pncp-rules.conf', PNCP_Rules::nginx_server() );
	exec( 'nginx -t 2>&1 && nginx -s reload 2>&1', $out, $rc );
	usleep( 700000 );
	foreach ( array( 'Mozilla/5.0 HeadlessChrome/141.0', 'python-requests/2.32', 'Mozilla/5.0 (compatible; GPTBot/1.2)' ) as $ua ) {
		list( $code, $body ) = req( $url, $ua, '198.51.100.230' );
		t( "με τους κανόνες Nginx: «{$ua}» 403, ακόμη και για σελίδα στην cache", 0 === $rc && 403 === $code && false === strpos( $body, 'ΠΕΡΙΕΧΟΜΕΝΟ_CACHE' ), (string) $code );
	}
	list( $code ) = req( $url, $chrome, '203.0.113.236' );
	t( 'με τους κανόνες Nginx: ο browser παίρνει κανονικά τη σελίδα από την cache', 200 === $code, (string) $code );
	file_put_contents( '/etc/nginx/pncp-rules.conf', "# empty\n" );
	@unlink( '/etc/nginx/conf.d/pncp-http.conf' );
	exec( 'nginx -s reload 2>&1' );
	usleep( 500000 );
} else {
	echo "SKIP κανόνες Nginx (χρειάζεται root)\n";
}

/* ---------- Το 403 δεν μπαίνει ποτέ στην cache ---------- */
$post2 = wp_insert_post( array( 'post_title' => 'Cache2 ' . wp_generate_password( 6, false ), 'post_content' => 'ΔΕΥΤΕΡΟ', 'post_status' => 'publish' ) );
$url2  = wp_parse_url( get_permalink( $post2 ), PHP_URL_PATH );
PNCP_Log::ban( '198.51.100.231', 10, 'trap' );
list( $code ) = req( $url2, $chrome, '198.51.100.231' );
list( $code2, $body2 ) = req( $url2, $chrome, '203.0.113.232' );
t( 'αποκλεισμένη IP με browser (περνά την cache) → 403, και μετά ο επισκέπτης παίρνει τη σελίδα, όχι 403', 403 === $code && 200 === $code2 && false !== strpos( $body2, 'ΔΕΥΤΕΡΟ' ), "$code/$code2" );

/* ---------- Feed με token δεν μπαίνει στην cache ---------- */
$token = PNCP_Private_Urls::rotate( 0 );
list( $code, $body ) = req( '/skroutz.xml', $chrome, '203.0.113.233', array( 'X-Content-Protect-Token' => $token ) );
t( 'feed με token στο header: 200', 200 === $code && false !== strpos( $body, 'ΤΙΜΟΚΑΤΑΛΟΓΟΣ' ), (string) $code );
list( $code, $body ) = req( '/skroutz.xml', $chrome, '203.0.113.234' );
t( 'αμέσως μετά, χωρίς token: 403 (το feed δεν σερβίρεται από την cache)', 403 === $code && false === strpos( $body, 'ΤΙΜΟΚΑΤΑΛΟΓΟΣ' ), (string) $code );

/* ---------- Αλλαγή ρυθμίσεων = καθάρισμα cache ---------- */
req( $url, $chrome, '203.0.113.235' );
$dir    = WP_CONTENT_DIR . '/cache/supercache/' . wp_parse_url( home_url(), PHP_URL_HOST );
$before = (int) trim( (string) shell_exec( 'find ' . escapeshellarg( $dir ) . ' -name "index*.html*" 2>/dev/null | wc -l' ) );
settings( array( 'attribution_min_chars' => wp_rand( 100, 999 ) ) );
$after = (int) trim( (string) shell_exec( 'find ' . escapeshellarg( $dir ) . ' -name "index*.html*" 2>/dev/null | wc -l' ) );
t( 'αποθήκευση ρυθμίσεων: η cache αδειάζει (WP Super Cache)', $before > 0 && 0 === $after, "$before → $after" );

PNCP_Log::unban_all();
wp_delete_post( $post, true );
wp_delete_post( $post2, true );
echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
