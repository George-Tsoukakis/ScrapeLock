<?php
/**
 * ScrapeLock — εντολές WP-CLI (wp scrapelock …), μέσα από το πραγματικό wp.
 *
 *   WP_DIR=/path/to/wordpress WP_CLI="wp --path=…" php t_cli.php
 */

$wp_dir = getenv( 'WP_DIR' );
$wp_cli = (string) getenv( 'WP_CLI' );
if ( '' === $wp_cli ) {
	echo "SKIP χωρίς WP_CLI\n";
	exit( 0 );
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

/** Τρέχει «wp scrapelock …»: [κωδικός εξόδου, stdout + stderr]. */
function cli( $args ) {
	global $wp_cli;
	exec( $wp_cli . ' scrapelock ' . $args . ' 2>&1', $out, $rc );
	PNCP_Log::reset_cache();
	wp_cache_flush();
	return array( $rc, implode( "\n", $out ) );
}

PNCP_Log::unban_all();

list( $rc, $out ) = cli( 'status --format=json' );
$rows = json_decode( $out, true );
$map  = is_array( $rows ) ? array_column( $rows, 'value', 'setting' ) : array();
t( 'status: JSON με έκδοση και Lockdown', 0 === $rc && isset( $map['Version'], $map['Lockdown'] ) && PNCP_VERSION === $map['Version'], $out );

list( $rc, $out ) = cli( 'block 203.0.113.61 --minutes=5' );
t( 'block: η IP μπλοκάρεται (όπως το προσωρινό μπλοκ)', 0 === $rc && PNCP_Log::is_banned( '203.0.113.61' ), $out );
$bans = PNCP_Log::active_bans( 0 );
t( 'block: αιτία «manual», λήξη σε ~5 λεπτά', isset( $bans['203.0.113.61'] ) && 'manual' === $bans['203.0.113.61']['reason'] && abs( $bans['203.0.113.61']['until'] - ( time() + 300 ) ) < 30 );
list( $rc, $out ) = cli( 'block 2001:db8:5:6::7' );
t( 'block IPv6: όλο το /64', 0 === $rc && PNCP_Log::is_banned( '2001:db8:5:6::abcd' ) && false !== strpos( $out, '2001:db8:5:6::/64' ), $out );
list( $rc ) = cli( 'block not-an-ip' );
t( 'block: λάθος IP → σφάλμα', 0 !== $rc );
list( $rc ) = cli( 'block 203.0.113.62 --minutes=0' );
t( 'block: --minutes εκτός ορίων → σφάλμα, χωρίς μπλοκ', 0 !== $rc && ! PNCP_Log::is_banned( '203.0.113.62' ) );
$google = PNCP_Ip::list_of( 'google' );
PNCP_Ip::store_list( 'google', array( '66.249.64.0/19' ) );
list( $rc ) = cli( 'block 66.249.66.1' );
t( 'block: IP της Google → ποτέ', 0 !== $rc && ! PNCP_Log::is_banned( '66.249.66.1' ) );
PNCP_Ip::store_list( 'google', $google );

list( $rc, $out ) = cli( 'blocked --format=count' );
t( 'blocked: 2 μπλοκ', 0 === $rc && '2' === trim( $out ), $out );
list( $rc, $out ) = cli( 'unblock 2001:db8:5:6::99' );
t( 'unblock IPv6 με μια άλλη διεύθυνση του /64: ξεμπλοκάρει το /64', 0 === $rc && ! PNCP_Log::is_banned( '2001:db8:5:6::7' ), $out );
list( $rc ) = cli( 'unblock --all' );
t( 'unblock --all: κανένα μπλοκ', 0 === $rc && 0 === PNCP_Log::count_bans() );

list( $rc, $out ) = cli( 'emergency on --hours=2' );
$until = (int) get_option( PNCP_Options::EMERGENCY_OPTION );
t( 'emergency on --hours=2', 0 === $rc && abs( $until - ( time() + 2 * HOUR_IN_SECONDS ) ) < 30, $out );
list( $rc ) = cli( 'emergency on --hours=73' );
t( 'emergency: πάνω από 72 ώρες → σφάλμα, η λήξη μένει', 0 !== $rc && (int) get_option( PNCP_Options::EMERGENCY_OPTION ) === $until );
list( $rc, $out ) = cli( 'emergency off' );
t( 'emergency off', 0 === $rc && 0 === PNCP_Options::emergency_until() && false !== strpos( $out, 'off' ), $out );

PNCP_Log::add( 'trap', 403, '198.51.100.140' );
list( $rc, $out ) = cli( 'log --limit=5 --format=json' );
$rows = json_decode( $out, true );
t( 'log: οι τελευταίες εγγραφές, με την παγίδα', 0 === $rc && is_array( $rows ) && count( $rows ) <= 5 && in_array( '198.51.100.140', array_column( $rows, 'ip' ), true ), $out );
list( $rc, $out ) = cli( 'log --top --format=json' );
$rows = json_decode( $out, true );
t( 'log --top: σύνολα ανά αιτία και IP', 0 === $rc && is_array( $rows ) && in_array( 'Bot trap', array_column( $rows, 'value' ), true ) && in_array( 'ip', array_column( $rows, 'group' ), true ), $out );
list( $rc ) = cli( 'log --format=xml' );
t( 'log: άγνωστο --format → σφάλμα', 0 !== $rc );

list( $rc, $out ) = cli( '--help' );
t( 'καμία εντολή ξεκλειδώματος του Lockdown', false === stripos( $out, 'unlock' ) && false === stripos( $out, 'lockdown' ), $out );

PNCP_Log::unban_all();
echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
