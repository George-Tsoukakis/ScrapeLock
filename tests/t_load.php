<?php
/**
 * ScrapeLock — δοκιμή φόρτου: επιβάρυνση ανά αίτημα, ακρίβεια ορίου υπό ταυτόχρονα αιτήματα,
 * πλημμύρα από bots, «καταιγίδα» αποκλεισμών, με και χωρίς Redis object cache.
 *
 *   WP_DIR=/srv/wpt BASE=http://127.0.0.1:8080 [REDIS_DROPIN=/path/object-cache.php] php t_load.php
 *
 * Χρειάζεται server με πολλούς PHP workers (π.χ. Nginx + PHP-FPM, pm.max_children ≥ 8): με τον built-in
 * server της PHP τα αιτήματα εκτελούνται ένα-ένα και η δοκιμή δεν σημαίνει τίποτα.
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
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra ? "  [$extra]" : '' ) . "\n";
}
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	redis_sync();
}
/** Με Redis ο server κρατά τα options στη cache: ό,τι αλλάζει το CLI (χωρίς Redis) πρέπει να φανεί εκεί. */
function redis_sync() {
	if ( file_exists( WP_CONTENT_DIR . '/object-cache.php' ) ) {
		shell_exec( 'redis-cli flushall >/dev/null 2>&1' );
	}
}
function burst( $path, $n, $c, $ip, $ua = null ) {
	global $base;
	$cmd = 'php ' . escapeshellarg( __DIR__ . '/lib/burst.php' ) . ' ' . escapeshellarg( $base . $path ) . ' ' . (int) $n . ' ' . (int) $c . ' ' . escapeshellarg( $ip ) . ( $ua ? ' ' . escapeshellarg( $ua ) : '' );
	return json_decode( (string) shell_exec( $cmd ), true );
}
function wait_minute_start() {
	$s = (int) gmdate( 's' );
	if ( $s > 5 ) {
		sleep( 61 - $s );
	}
}
function code_count( $r, $code ) {
	return isset( $r['codes'][ $code ] ) ? (int) $r['codes'][ $code ] : 0;
}

$page = wp_parse_url( get_permalink( get_posts( array( 'numberposts' => 1 ) )[0] ), PHP_URL_PATH ) . '?nocache=1';
global $wpdb;

function scenario( $label, $redis ) {
	global $page, $wpdb, $fails;
	echo "\n== $label ==\n";
	PNCP_Log::unban_all();
	PNCP_Log::clear();
	redis_sync();

	/* Επιβάρυνση: ίδιο φορτίο με το plugin ανενεργό και ενεργό (επισκέπτες από διαφορετικές IP). */
	settings( array( 'enabled' => 0 ) );
	burst( $page, 40, 10, 'random2' ); // ζέσταμα
	$off = burst( $page, 400, 20, 'random2' );
	settings( array( 'enabled' => 1, 'rate_limit' => 60, 'rate_limit_search' => 20, 'rate_limit_rest' => 60, 'ban_strikes' => 3, 'trap_enabled' => 1, 'block_bots' => 1, 'require_browser_headers' => 0 ) );
	burst( $page, 40, 10, 'random2' );
	$on = burst( $page, 400, 20, 'random2' );
	t( "$label: επιβάρυνση του plugin μικρή (αιτήματα/δευτ. ≥ 80% του ανενεργού)", $on['rps'] >= 0.8 * $off['rps'] && 400 === code_count( $on, 200 ), sprintf( 'ανενεργό %.1f/s p95 %sms · ενεργό %.1f/s p95 %sms', $off['rps'], $off['p95'], $on['rps'], $on['p95'] ) );

	/* Ακρίβεια ορίου: 200 ταυτόχρονα αιτήματα από μία IP, όριο 50. */
	settings( array( 'rate_limit' => 50, 'ban_strikes' => 0 ) );
	$ok = true;
	$detail = array();
	for ( $i = 0; $i < 2; $i++ ) {
		wait_minute_start();
		$r        = burst( $page, 200, 40, '203.0.113.' . ( 60 + $i + ( $redis ? 10 : 0 ) ) );
		$detail[] = code_count( $r, 200 ) . '/' . code_count( $r, 429 );
		$ok       = $ok && 50 === code_count( $r, 200 ) && 150 === code_count( $r, 429 );
	}
	t( "$label: όριο 50 με 200 ταυτόχρονα αιτήματα → ακριβώς 50 περνούν (2 επαναλήψεις)", $ok, implode( ' · ', $detail ) );

	/* Πλημμύρα από bot: 3000 αιτήματα, 50 ταυτόχρονα. */
	$ip = $redis ? '198.51.100.71' : '198.51.100.70';
	$r  = burst( $page, 3000, 50, $ip, 'Mozilla/5.0 (compatible; GPTBot/1.2)' );
	$rows = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}pncp_log WHERE ip = %s", $ip ) );
	$hits = (int) $wpdb->get_var( $wpdb->prepare( "SELECT SUM(hits) FROM {$wpdb->prefix}pncp_log WHERE ip = %s", $ip ) );
	t( "$label: πλημμύρα 3000 αιτημάτων bot → όλα 403", 3000 === code_count( $r, 403 ), sprintf( '%.0f/s p95 %sms', $r['rps'], $r['p95'] ) );
	t( "$label: το αρχείο μένει μικρό (μία γραμμή ανά λεπτό με μετρητή)", $rows <= 4 && $hits >= 2900, "γραμμές $rows, μετρητής $hits" );

	/* «Καταιγίδα» αποκλεισμών: 1500 διαφορετικές IP ανοίγουν την παγίδα. */
	settings( array( 'ban_strikes' => 3 ) );
	$trap = wp_parse_url( home_url( PNCP_Bots::trap_path() ), PHP_URL_PATH );
	burst( $trap, 1500, 50, 'random', 'python-requests/2.32' );
	wp_cache_flush(); PNCP_Log::reset_cache();
	$bans = PNCP_Log::count_bans();
	t( "$label: 1500 ταυτόχρονοι αποκλεισμοί → κανένας δεν χάνεται", $bans >= 1500, "$bans αποκλεισμοί" );
	$r = burst( $page, 200, 20, 'random2' );
	t( "$label: με 1500 αποκλεισμούς οι υπόλοιποι επισκέπτες σερβίρονται κανονικά", 200 === code_count( $r, 200 ) && $r['rps'] >= 0.7 * $on['rps'], sprintf( '%.1f/s p95 %sms', $r['rps'], $r['p95'] ) );
	$r = burst( $page, 100, 20, 'random', 'Mozilla/5.0 Chrome/141' );
	t( "$label: οι αποκλεισμένες IP παίρνουν 403 ακόμη και με browser", 100 === code_count( $r, 403 ), wp_json_encode( $r['codes'] ) );

	PNCP_Log::cleanup();
	$opts = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_%pncp\\_%'" );
	echo "INFO $label: transients του plugin στη βάση μετά το καθάρισμα (μένουν όσα δεν έληξαν): $opts\n";
	PNCP_Log::unban_all();
	return $fails;
}

// Η δοκιμή μετρά την PHP: ένα plugin page cache (WP Super Cache) θα σέρβιρε τις σελίδες χωρίς να φτάσουν στο plugin.
$wpsc_was = function_exists( 'wp_cache_setting' ) ? (bool) $GLOBALS['cache_enabled'] : null;
if ( null !== $wpsc_was ) {
	wp_cache_setting( 'cache_enabled', false );
}

$dropin = getenv( 'REDIS_DROPIN' );
@unlink( WP_CONTENT_DIR . '/object-cache.php' );
scenario( 'χωρίς object cache', false );
if ( $dropin && is_readable( $dropin ) && class_exists( 'Redis' ) ) {
	copy( $dropin, WP_CONTENT_DIR . '/object-cache.php' );
	usleep( 300000 );
	// Το CLI έχει ήδη φορτώσει το WordPress χωρίς Redis: οι ρυθμίσεις γράφονται στη βάση, οι μετρητές στο Redis.
	scenario( 'με Redis object cache', true );
	unlink( WP_CONTENT_DIR . '/object-cache.php' );
} else {
	echo "SKIP Redis (REDIS_DROPIN ή phpredis λείπει)\n";
}

settings( array( 'rate_limit' => 0, 'rate_limit_search' => 0, 'rate_limit_rest' => 0, 'ban_strikes' => 3 ) );
if ( null !== $wpsc_was ) {
	wp_cache_setting( 'cache_enabled', $wpsc_was );
}
echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
