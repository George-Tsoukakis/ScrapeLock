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
// 3.4: μια νέα εγκατάσταση ξεκινά σε «Monitor only» για 7 ημέρες· οι δοκιμές μπλοκάρουν όπως ένα υπάρχον site.
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'monitor_mode' => 0, 'monitor_until' => 0 ) ) );
PNCP_Options::flush();

list( $rc, $out ) = cli( 'status --format=json' );
$rows = json_decode( $out, true );
$map  = is_array( $rows ) ? array_column( $rows, 'value', 'setting' ) : array();
t( 'status: JSON με έκδοση και Lockdown', 0 === $rc && isset( $map['Version'], $map['Lockdown'] ) && PNCP_VERSION === $map['Version'], $out );

list( $rc, $out ) = cli( 'block 203.0.113.61 --minutes=5' );
t( 'block: η IP μπλοκάρεται (όπως το προσωρινό μπλοκ)', 0 === $rc && PNCP_Log::is_banned( '203.0.113.61' ), $out );
$bans = PNCP_Log::active_bans( 0 );
t( 'block: αιτία «manual», λήξη σε ~5 λεπτά', isset( $bans['203.0.113.61'] ) && 'manual' === $bans['203.0.113.61']['reason'] && abs( $bans['203.0.113.61']['until'] - ( time() + 300 ) ) < 30 );
// 3.4: ιδιωτικές / δεσμευμένες IP δεν μπλοκάρονται ποτέ· το 2001:db8::/32 είναι δεσμευμένο για την PHP,
// οπότε η δοκιμή IPv6 χρησιμοποιεί το δημόσιο εύρος τεκμηρίωσης 3fff::/20 (RFC 9637).
list( $rc, $out ) = cli( 'block 2001:db8:5:6::7' );
t( 'block IPv6 δεσμευμένη (2001:db8::/32): ποτέ, χωρίς μπλοκ (3.4)', 0 !== $rc && ! PNCP_Log::is_banned( '2001:db8:5:6::7' ), $out );
list( $rc, $out ) = cli( 'block 10.1.2.3' );
t( 'block ιδιωτική IP (10.1.2.3): ποτέ (3.4)', 0 !== $rc && ! PNCP_Log::is_banned( '10.1.2.3' ), $out );
list( $rc, $out ) = cli( 'block 3fff:5:6:7::7' );
t( 'block IPv6 (3fff::/20): όλο το /64', 0 === $rc && PNCP_Log::is_banned( '3fff:5:6:7::abcd' ) && false !== strpos( $out, '3fff:5:6:7::/64' ), $out );
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
list( $rc, $out ) = cli( 'unblock 3fff:5:6:7::99' );
t( 'unblock IPv6 με μια άλλη διεύθυνση του /64: ξεμπλοκάρει το /64', 0 === $rc && ! PNCP_Log::is_banned( '3fff:5:6:7::7' ), $out );
list( $rc, $out ) = cli( 'unblock 203.0.113.99' );
t( 'unblock IP χωρίς μπλοκ: προειδοποίηση «nothing was lifted» (3.4)', false !== strpos( $out, 'nothing was lifted' ), $out );
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

// 3.4: νέες εντολές «settings» και «lockdown status» (μόνο ανάγνωση). Καμία εντολή δεν ξεκλειδώνει το Lockdown.
list( $rc, $out ) = cli( '--help' );
$pncp_subs = preg_match( '/^SUBCOMMANDS\s*\n(.*?)\n\s*\n\s*\n/sm', $out, $m ) && preg_match_all( '/^  ([a-z][a-z-]*)\s/m', $m[1], $mm ) ? $mm[1] : array();
t( 'εντολές (3.4): block, blocked, check, emergency, lockdown, log, settings, status, unblock', array( 'block', 'blocked', 'check', 'emergency', 'lockdown', 'log', 'settings', 'status', 'unblock' ) === $pncp_subs, implode( ',', $pncp_subs ) );
t( 'καμία εντολή ξεκλειδώματος του Lockdown (καμία εντολή «unlock»)', ! preg_grep( '/unlock/i', $pncp_subs ), implode( ',', $pncp_subs ) );
list( $rc, $out ) = cli( 'lockdown --help' );
t( 'lockdown (3.4): μόνη ενέργεια το «status»', 0 === $rc && preg_match( '/options:\s*\n\s*- status\s*\n(?!\s*- )/', $out ), $out );
$pncp_state = wp_json_encode( get_option( PNCP_Lockdown::OPTION, '' ) );
list( $rc, $out ) = cli( 'lockdown unlock' );
$pncp_after = wp_json_encode( get_option( PNCP_Lockdown::OPTION, '' ) );
t( 'lockdown unlock: σφάλμα, τίποτα δεν αλλάζει (3.4)', 0 !== $rc && $pncp_state === $pncp_after, $out );
list( $rc, $out ) = cli( 'lockdown status --format=json' );
$rows = json_decode( $out, true );
t( 'lockdown status (3.4, μόνο ανάγνωση): JSON με την κατάσταση', 0 === $rc && is_array( $rows ) && in_array( 'Lockdown', array_column( $rows, 'setting' ), true ), $out );
list( $rc, $out ) = cli( 'settings get rate_limit' );
t( 'settings get (3.4): η τιμή της ρύθμισης', 0 === $rc && false !== strpos( $out, (string) PNCP_Options::stored()['rate_limit'] ), $out );

PNCP_Log::unban_all();
echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
