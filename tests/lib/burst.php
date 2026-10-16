<?php
/**
 * Ταυτόχρονα αιτήματα (curl_multi), για δοκιμές φόρτου και ορίων.
 *
 *   php burst.php URL ΠΛΗΘΟΣ ΤΑΥΤΟΧΡΟΝΑ [IP|random] [User-Agent] [header: τιμή ...]
 *
 * Τυπώνει JSON: πλήθος ανά HTTP κωδικό, αιτήματα/δευτερόλεπτο, p50 / p95 / max σε ms.
 * IP: τιμή για το X-Test-IP (mu-test-harness). «random» / «random2» = διαφορετική IP σε κάθε αίτημα (δύο ξεχωριστά σύνολα).
 */

$url    = $argv[1];
$total  = (int) $argv[2];
$conc   = (int) $argv[3];
$ip     = isset( $argv[4] ) ? $argv[4] : '203.0.113.200';
$ua     = isset( $argv[5] ) ? $argv[5] : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36';
$extra  = array_slice( $argv, 6 );
$codes  = array();
$times  = array();
$queue  = range( 1, $total );
$mh     = curl_multi_init();
$active = array();

$make = static function ( $n ) use ( $url, $ip, $ua, $extra ) {
	$h  = array_merge( array( 'User-Agent: ' . $ua, 'Accept-Language: el-GR,el;q=0.9', 'Accept: text/html' ), $extra );
	// random: 10.x.x.x · random2: 100.64.x.x (άλλοι «επισκέπτες» από τους random).
	if ( 'random' === $ip || 'random2' === $ip ) {
		$prefix = 'random' === $ip ? '10.' . ( ( $n >> 16 ) & 255 ) : '100.' . ( 64 + ( ( $n >> 16 ) & 63 ) );
		$h[]    = 'X-Test-IP: ' . $prefix . '.' . ( ( $n >> 8 ) & 255 ) . '.' . ( $n & 255 );
	} else {
		$h[] = 'X-Test-IP: ' . $ip;
	}
	$ch = curl_init( $url );
	curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $h, CURLOPT_TIMEOUT => 60 ) );
	return $ch;
};

$start = microtime( true );
while ( $queue || $active ) {
	while ( $queue && count( $active ) < $conc ) {
		$n  = array_shift( $queue );
		$ch = $make( $n );
		curl_multi_add_handle( $mh, $ch );
		$active[ (int) $ch ] = $ch;
	}
	curl_multi_exec( $mh, $running );
	curl_multi_select( $mh, 0.05 );
	while ( $info = curl_multi_info_read( $mh ) ) {
		$ch     = $info['handle'];
		$code   = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		$times[] = curl_getinfo( $ch, CURLINFO_TOTAL_TIME ) * 1000;
		$codes[ $code ] = isset( $codes[ $code ] ) ? $codes[ $code ] + 1 : 1;
		curl_multi_remove_handle( $mh, $ch );
		curl_close( $ch );
		unset( $active[ (int) $ch ] );
	}
}
$elapsed = microtime( true ) - $start;
sort( $times );
$pct = static function ( $p ) use ( $times ) {
	return $times ? round( $times[ (int) floor( ( count( $times ) - 1 ) * $p ) ], 1 ) : 0;
};
ksort( $codes );
echo json_encode(
	array(
		'codes' => $codes,
		'rps'   => round( $total / max( $elapsed, 0.001 ), 1 ),
		'p50'   => $pct( 0.5 ),
		'p95'   => $pct( 0.95 ),
		'max'   => $pct( 1 ),
	)
), "\n";
