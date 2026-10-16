<?php
/**
 * Content Protect — πραγματικό WPGraphQL και REST API (κείμενο, bots, όρια, method override, πιστοποίηση).
 *
 *   WP_DIR=/srv/wpt BASE=http://127.0.0.1:8080 php t_graphql_rest.php
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
function req( $path, $method = 'GET', $body = null, $headers = array() ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $h, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_TIMEOUT => 60 ) );
	if ( null !== $body ) {
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $body );
	}
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	$json = json_decode( $out, true );
	// Το JSON γράφει τα ελληνικά ως \uXXXX: για αναζήτηση κειμένου, χωρίς escaping.
	return array( $code, null !== $json ? wp_json_encode( $json, JSON_UNESCAPED_UNICODE ) : $out, $json );
}
function browser( $ip, $extra = array() ) {
	return array_merge( array( 'X-Test-IP' => $ip, 'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0', 'Accept-Language' => 'el' ), $extra );
}

if ( ! class_exists( 'WPGraphQL' ) ) {
	echo "SKIP χωρίς WPGraphQL\n";
	exit( 0 );
}

PNCP_Log::unban_all();
settings( array( 'enabled' => 1, 'rest_hide_content' => 1, 'graphql_hide_content' => 1, 'rate_limit_rest' => 0, 'ban_strikes' => 3, 'exempt_cap' => 'edit_posts', 'excluded_ids' => '' ) );
$post_id = (int) get_option( 'pncp_test_post' );
if ( ! $post_id || ! get_post( $post_id ) ) {
	$post_id = wp_insert_post( array( 'post_title' => 'Οδηγός βιταμινών', 'post_content' => '<p>ΜΥΣΤΙΚΟ_ΚΕΙΜΕΝΟ πλήρες άρθρο.</p>', 'post_excerpt' => 'ΜΥΣΤΙΚΗ_ΠΕΡΙΛΗΨΗ', 'post_status' => 'publish' ) );
	update_option( 'pncp_test_post', $post_id );
}
// Application password για τον διαχειριστή (πιστοποίηση χωρίς cookie, όπως ένα εργαλείο ή εφαρμογή).
list( $app_pass ) = WP_Application_Passwords::create_new_application_password( 1, array( 'name' => 'pncp-test-' . wp_generate_password( 4, false ) ) );
$admin_auth       = array( 'Authorization' => 'Basic ' . base64_encode( 'admin:' . $app_pass ) );

$query = wp_json_encode( array( 'query' => '{ post(id: ' . $post_id . ', idType: DATABASE_ID) { title content excerpt } }' ) );
$json  = array( 'Content-Type' => 'application/json' );

/* ---------- GraphQL ---------- */
list( $code, $raw, $res ) = req( '/graphql', 'POST', $query, browser( '203.0.113.201' ) + $json );
$p = isset( $res['data']['post'] ) ? $res['data']['post'] : array();
t( 'GraphQL POST επισκέπτης: τίτλος ναι, content/excerpt κενά', 200 === $code && 'Οδηγός βιταμινών' === $p['title'] && '' === (string) $p['content'] && '' === (string) $p['excerpt'], $code . ' ' . substr( $raw, 0, 160 ) );
t( 'GraphQL: το κείμενο δεν υπάρχει πουθενά στην απάντηση', false === strpos( $raw, 'ΜΥΣΤΙΚΟ' ) );
list( $code, $raw ) = req( '/graphql?query=' . rawurlencode( '{ posts(first: 5) { nodes { title content } } }' ), 'GET', null, browser( '203.0.113.202' ) );
t( 'GraphQL GET (λίστα): χωρίς το κείμενο', 200 === $code && false === strpos( $raw, 'ΜΥΣΤΙΚΟ' ) && false !== strpos( $raw, 'Οδηγός βιταμινών' ), $code . ' ' . substr( $raw, 0, 120 ) );
list( $code, $raw ) = req( '/graphql', 'POST', $query, browser( '203.0.113.203' ) + $json + $admin_auth );
t( 'GraphQL διαχειριστής (application password): βλέπει το κείμενο', 200 === $code && false !== strpos( $raw, 'ΜΥΣΤΙΚΟ_ΚΕΙΜΕΝΟ' ), $code . ' ' . substr( $raw, 0, 160 ) );
list( $code, $raw, $res ) = req( '/graphql', 'POST', $query, array( 'X-Test-IP' => '198.51.100.210', 'User-Agent' => 'Mozilla/5.0 (compatible; GPTBot/1.2)' ) + $json );
t( 'GraphQL GPTBot: 403 σε μορφή GraphQL (errors)', 403 === $code && ! empty( $res['errors'] ), $code . ' ' . substr( $raw, 0, 100 ) );
settings( array( 'rate_limit_rest' => 2, 'ban_strikes' => 0 ) );
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$codes[] = req( '/graphql', 'POST', $query, browser( '203.0.113.204' ) + $json )[0];
}
t( 'GraphQL όριο 2/λεπτό: μετρούν και τα POST (200,200,429)', array( 200, 200, 429 ) === $codes, implode( ',', $codes ) );
settings( array( 'rate_limit_rest' => 0, 'ban_strikes' => 3 ) );
PNCP_Log::ban( '203.0.113.205', 10, 'trap' );
list( $code ) = req( '/graphql', 'POST', $query, browser( '203.0.113.205' ) + $json );
t( 'GraphQL αποκλεισμένη IP: 403', 403 === $code, (string) $code );

/* ---------- REST ---------- */
list( $code, $raw, $res ) = req( '/wp-json/wp/v2/posts/' . $post_id, 'GET', null, browser( '203.0.113.206' ) );
t( 'REST επισκέπτης: content/excerpt κενά, τίτλος ναι', 200 === $code && '' === $res['content']['rendered'] && '' === $res['excerpt']['rendered'] && false === strpos( $raw, 'ΜΥΣΤΙΚΟ' ), (string) $code );
list( $code, $raw ) = req( '/wp-json/wp/v2/posts/' . $post_id . '?context=edit', 'GET', null, browser( '203.0.113.207' ) + $admin_auth );
t( 'REST διαχειριστής (application password): βλέπει το κείμενο', 200 === $code && false !== strpos( $raw, 'ΜΥΣΤΙΚΟ_ΚΕΙΜΕΝΟ' ), $code . ' ' . substr( $raw, 0, 120 ) );
list( $code, $raw ) = req( '/wp-json/wp/v2/posts?_embed=1&search=' . rawurlencode( 'βιταμινών' ), 'GET', null, browser( '203.0.113.208' ) );
t( 'REST αναζήτηση με _embed: χωρίς το κείμενο', 200 === $code && false === strpos( $raw, 'ΜΥΣΤΙΚΟ' ), (string) $code );
list( $code, $raw ) = req( '/?rest_route=/wp/v2/posts/' . $post_id, 'GET', null, browser( '203.0.113.209' ) );
t( 'REST μέσω ?rest_route= (χωρίς permalinks): χωρίς το κείμενο', 200 === $code && false === strpos( $raw, 'ΜΥΣΤΙΚΟ' ), (string) $code );
$bot = array( 'X-Test-IP' => '198.51.100.211', 'User-Agent' => 'python-requests/2.32' );
list( $code ) = req( '/wp-json/wp/v2/posts?_method=GET', 'POST', '', $bot );
t( 'REST POST με _method=GET (παράκαμψη μεθόδου) από bot: 403', 403 === $code, (string) $code );
list( $code ) = req( '/wp-json/wp/v2/posts', 'POST', '', $bot + array( 'X-HTTP-Method-Override' => 'GET' ) );
t( 'REST POST με X-HTTP-Method-Override: GET από bot: 403', 403 === $code, (string) $code );
list( $code ) = req( '/wp-json/wp/v2/posts', 'HEAD', null, $bot );
t( 'REST HEAD από bot: 403', 403 === $code, (string) $code );
list( $code ) = req( '/wp-json/oembed/1.0/embed?url=' . rawurlencode( get_permalink( $post_id ) ), 'GET', null, browser( '203.0.113.212' ) );
t( 'REST oEmbed για επισκέπτη: δουλεύει (200)', 200 === $code, (string) $code );

/* ---------- Feeds RSS ---------- */
settings( array( 'feed_mode' => 'excerpt' ) );
list( $code, $raw ) = req( '/feed/', 'GET', null, browser( '203.0.113.213' ) );
t( 'RSS: χωρίς το πλήρες κείμενο, με σύνδεσμο στο άρθρο', 200 === $code && false === strpos( $raw, 'ΜΥΣΤΙΚΟ_ΚΕΙΜΕΝΟ' ) && false !== strpos( $raw, 'Διαβάστε το πλήρες άρθρο' ), (string) $code );
list( $code, $raw ) = req( '/feed/atom/', 'GET', null, browser( '203.0.113.214' ) );
t( 'Atom: χωρίς το πλήρες κείμενο', 200 === $code && false === strpos( $raw, 'ΜΥΣΤΙΚΟ_ΚΕΙΜΕΝΟ' ), (string) $code );

PNCP_Log::unban_all();
WP_Application_Passwords::delete_all_application_passwords( 1 );
echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
