<?php
/**
 * ScrapeLock 3.12.1 — how the parts of 3.12.1 fit together (the loopback signature, FluentCommunity per account,
 * the tester, AI search, Traffic), in real WordPress:
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3121_integration.php
 *
 * R. A FluentCommunity member over the per-account limit (rate_member) says nothing about the IP: no reputation
 *    event, like rate_account; the label of every log reason is translated text, never the key.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
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

update_option( PNCP_OPTION, $pncp_saved );
PNCP_Options::flush();
echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
