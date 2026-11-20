<?php
/**
 * ScrapeLock 3.12.1 — how the parts of 3.12.1 fit together (the loopback signature, FluentCommunity per account,
 * the tester, AI search, Traffic), in real WordPress:
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3121_integration.php
 *
 * R. A FluentCommunity member over the per-account limit (rate_member) says nothing about the IP: no reputation
 *    event, like rate_account; the label of every log reason is translated text, never the key.
 * A. The attack record keeps nothing of the site's own requests: a signed request (X-ScrapeLock-Sig) to
 *    /xmlrpc.php that came back from a public address (through a CDN) and a CDN log line of an address of
 *    SCRAPELOCK_SERVER_IPS (defined by this test) are not recorded; a visitor's are.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
define( 'SCRAPELOCK_SERVER_IPS', '203.0.113.50' ); // Only this test process (A).
require $wp_dir . '/wp-load.php';

$fails = 0;
/** A request to the test site from a visitor address (X-Forwarded-For, 127.0.0.1 trusted): [code, body]. */
function http( $path, $ip, $headers = array() ) {
	global $base;
	$ch = curl_init( $base . $path );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 30,
			CURLOPT_HTTPHEADER     => array_merge( array( 'X-Forwarded-For: ' . $ip, 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36', 'Accept: text/html', 'Accept-Language: en' ), $headers ),
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	wp_cache_delete( 'alloptions', 'options' );
}

/** The attack record's per-minute budget (rows lose their IP past it): reset, so earlier tests do not matter. */
function attack_budget() {
	$minute = (int) floor( time() / MINUTE_IN_SECONDS );
	foreach ( array( 'pncp_at_n_', 'pncp_at_w_' ) as $prefix ) {
		PNCP_Log::cache_delete( $prefix . $minute );
		PNCP_Log::cache_delete( $prefix . ( $minute + 1 ) );
	}
}

function attack_rows( $ip ) {
	global $wpdb;
	return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE ip = %s', PNCP_Attacks::table(), $ip ) );
}

function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

$pncp_saved = get_option( PNCP_OPTION );

/* ---------- R. rate_member and the reputation ---------- */
t( 'R: rate_member is no reputation event of the IP (per account, like rate_account)', '' === PNCP_Reputation::event_of( 'rate_member' ) && '' === PNCP_Reputation::event_of( 'rate_account' ) );
t( 'R: the per-IP REST limit still is one', 'limit' === PNCP_Reputation::event_of( 'rate_rest' ) );
$pncp_keys = array();
foreach ( PNCP_Log::reasons() as $pncp_key => $pncp_label ) {
	if ( $pncp_key === $pncp_label || '' === trim( (string) $pncp_label ) ) {
		$pncp_keys[] = $pncp_key;
	}
}
t( 'R: every log reason has a label (rate_member too)', ! $pncp_keys && isset( PNCP_Log::reasons()['rate_member'] ) && 'FluentCommunity REST reads per minute per member' === PNCP_Log::reason_label( 'rate_member' ), implode( ',', $pncp_keys ) );
t( 'R: an unknown reason gets a generic label, never its key', 'Another check of ScrapeLock' === PNCP_Log::reason_label( 'rate_from_2099' ) );

/* ---------- A. The attack record and the site's own requests ---------- */
settings(
	array(
		'enabled'         => 1,
		'monitor_mode'    => 0,
		'attack_record'   => 1,
		'ip_header'       => 'x_forwarded_for',
		'trusted_proxies' => '127.0.0.1',
	)
);
global $wpdb;
$pncp_visitor = '198.51.100.78';
$pncp_self    = '198.51.100.77';
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ip IN (%s, %s, %s, %s)', PNCP_Attacks::table(), $pncp_visitor, $pncp_self, '203.0.113.50', '198.51.100.79' ) );
attack_budget();
http( '/xmlrpc.php', $pncp_visitor );
t( 'A: a visitor\'s GET /xmlrpc.php is in the attack record', attack_rows( $pncp_visitor ) > 0 );
attack_budget();
$pncp_sig = PNCP_Server_Ips::sig_token( 'GET', home_url( '/xmlrpc.php' ) );
list( $pncp_code ) = http( '/xmlrpc.php', $pncp_self, array( PNCP_Server_Ips::SIG_HEADER . ': ' . $pncp_sig ) );
t( 'A: the site\'s own signed GET /xmlrpc.php, back from a public address: answered, not recorded', $pncp_code > 0 && 403 !== $pncp_code && 0 === attack_rows( $pncp_self ), $pncp_code . ' / ' . attack_rows( $pncp_self ) );
t( 'A: SCRAPELOCK_SERVER_IPS is one of the server\'s addresses', PNCP_Server_Ips::is_server_ip( '203.0.113.50' ) );
attack_budget();
PNCP_Attacks::record( 'edge', '/xmlrpc.php', '203.0.113.50', true, 'POST' );
PNCP_Attacks::record( 'edge', '/xmlrpc.php', '198.51.100.79', true, 'POST' );
PNCP_Attacks::flush();
t( 'A: a CDN log line of the server\'s address is not recorded, a visitor\'s is', 0 === attack_rows( '203.0.113.50' ) && 1 === attack_rows( '198.51.100.79' ), attack_rows( '203.0.113.50' ) . ' / ' . attack_rows( '198.51.100.79' ) );
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ip IN (%s, %s, %s, %s)', PNCP_Attacks::table(), $pncp_visitor, $pncp_self, '203.0.113.50', '198.51.100.79' ) );
PNCP_Log::unban( $pncp_visitor );

update_option( PNCP_OPTION, $pncp_saved );
PNCP_Options::flush();
echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
