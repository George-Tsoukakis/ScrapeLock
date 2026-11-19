<?php
/**
 * ScrapeLock 3.10 — Vulnerable points → "Security headers" / "Framing": the check reads the public home page
 * (GET, after its redirects, headers in any letter case, through a CDN), says where it looked, and says
 * "could not be checked" instead of "missing" when it cannot see the answer that visitors get.
 * Without network: every request of the check is answered by a pre_http_request mock.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_harden_headers.php
 */

$wp_dir = getenv( 'WP_DIR' );
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

if ( ! class_exists( 'PNCP_Hardening' ) ) {
	echo "SKIP PNCP_Hardening missing\n";
	exit( 0 );
}

$pncp_home  = home_url( '/' );
$pncp_scene = array();   // URL => array( code, headers ) or WP_Error.
$pncp_seen  = array();   // Requests made to the scene: "METHOD URL".
$pncp_reply = static function ( $code, $headers = array() ) {
	return array( 'headers' => $headers, 'body' => '<html><body>ok</body></html>', 'response' => array( 'code' => $code, 'message' => '' ), 'cookies' => array(), 'filename' => null );
};
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) use ( &$pncp_scene, &$pncp_seen, $pncp_reply ) {
		$method = isset( $args['method'] ) ? $args['method'] : 'GET';
		if ( isset( $pncp_scene[ $url ] ) ) {
			$pncp_seen[] = $method . ' ' . $url;
			$r           = $pncp_scene[ $url ];
			return is_wp_error( $r ) ? $r : $pncp_reply( $r[0], $r[1] );
		}
		return $pncp_reply( 404 ); // Every other self-check address: refused, no network.
	},
	1,
	3
);

$pncp_full = array(
	'X-Content-Type-Options' => 'nosniff',
	'referrer-policy'        => 'strict-origin-when-cross-origin',
	'PERMISSIONS-POLICY'     => array( 'camera=()', 'microphone=(), geolocation=()' ), // Two header lines.
	'x-frame-options'        => 'SAMEORIGIN',
);
$pncp_edge_before = get_option( PNCP_Edge::CONFIG, null );
delete_option( PNCP_Edge::CONFIG );

$run = static function ( $scene ) use ( &$pncp_scene, &$pncp_seen ) {
	$pncp_scene = $scene;
	$pncp_seen  = array();
	return PNCP_Hardening::live( true );
};
$note = static function ( $live, $id = 'headers' ) {
	return isset( $live[ $id ]['note'] ) ? (string) $live[ $id ]['note'] : '';
};

// 1. Headers present, in any letter case and on several lines: Locked; GET, not HEAD; where it looked.
$live = $run( array( $pncp_home => array( 200, $pncp_full ) ) );
t( 'headers in any letter case: Locked', 'on' === $live['headers']['state'], wp_json_encode( $live['headers'] ) );
t( 'headers: framing seen too', 'on' === $live['framing']['state'], wp_json_encode( $live['framing'] ) );
t( 'headers: home asked with GET, not HEAD', in_array( 'GET ' . $pncp_home, $pncp_seen, true ) && ! in_array( 'HEAD ' . $pncp_home, $pncp_seen, true ), implode( ', ', $pncp_seen ) );
t( 'headers: says which address and status it read', false !== strpos( $note( $live ), $pncp_home . ' (HTTP 200)' ), $note( $live ) );

// 2. Redirect (http → https, www) without headers, then 200 with headers: read the final answer.
$final = 'https://www.example.test/';
$live  = $run(
	array(
		$pncp_home => array( 301, array( 'Location' => $final ) ),
		$final     => array( 200, $pncp_full ),
	)
);
t( 'redirect then 200: Locked (not the headers of the 301)', 'on' === $live['headers']['state'], wp_json_encode( $live['headers'] ) );
t( 'redirect then 200: shows both steps', false !== strpos( $note( $live ), '(HTTP 301)' ) && false !== strpos( $note( $live ), $final . ' (HTTP 200)' ), $note( $live ) );

// 2b. Relative redirect (trailing slash, language).
$rel  = home_url( '/el/' );
$live = $run(
	array(
		$pncp_home => array( 302, array( 'location' => '/el/' ) ),
		$rel       => array( 200, $pncp_full ),
	)
);
t( 'relative redirect followed', 'on' === $live['headers']['state'] && false !== strpos( $note( $live ), $rel ), wp_json_encode( $live['headers'] ) );

// 2c. Redirect loop: could not be checked, not missing.
$live = $run( array( $pncp_home => array( 301, array( 'Location' => $pncp_home ) ) ) );
t( 'redirect loop: could not be checked', 'unknown' === $live['headers']['state'] && false === strpos( $note( $live ), 'Missing' ), wp_json_encode( $live['headers'] ) );

// 3. Headers added by the CDN (Bunny, Cloudflare) on the public answer.
$live = $run( array( $pncp_home => array( 200, array_merge( $pncp_full, array( 'Server' => 'BunnyCDN-DE1-1084', 'CDN-PullZone' => '123456' ) ) ) ) );
t( 'Bunny-added headers: Locked, through Bunny CDN', 'on' === $live['headers']['state'] && false !== strpos( $note( $live ), 'Bunny CDN' ), wp_json_encode( $live['headers'] ) );
$st = PNCP_Hardening::status( 'headers' );
t( 'Bunny-added headers: card says it is done by the server/CDN', 'on' === $st['state'] && false !== strpos( $st['note'], 'Bunny CDN' ), wp_json_encode( $st ) );
$live = $run( array( $pncp_home => array( 200, array_merge( $pncp_full, array( 'cf-ray' => '8f00aa-ATH' ) ) ) ) );
t( 'Cloudflare-added headers: through Cloudflare', 'on' === $live['headers']['state'] && false !== strpos( $note( $live ), 'Cloudflare' ), wp_json_encode( $live['headers'] ) );

// 3b. Really missing, no CDN set up: still reported as missing.
$live = $run( array( $pncp_home => array( 200, array( 'x-content-type-options' => 'nosniff' ) ) ) );
t( 'missing without CDN: Partly + missing names', 'partial' === $live['headers']['state'] && false !== strpos( $note( $live ), 'Missing on the home page: Referrer-Policy, Permissions-Policy' ), wp_json_encode( $live['headers'] ) );
$live = $run( array( $pncp_home => array( 200, array( 'X-Content-Type-Options' => '' ) ) ) );
t( 'empty header value counts as missing', 'off' === $live['headers']['state'], wp_json_encode( $live['headers'] ) );

// 3c. Through the CDN but missing: the public answer, so missing is real.
$live = $run( array( $pncp_home => array( 200, array( 'server' => 'BunnyCDN-DE1-1084' ) ) ) );
t( 'through Bunny and missing: Open (real)', 'off' === $live['headers']['state'] && false !== strpos( $note( $live ), 'Missing' ), wp_json_encode( $live['headers'] ) );

// 3d. Bunny set up in ScrapeLock, but the answer came straight from the origin: could not be checked.
update_option( PNCP_Edge::CONFIG, array( 'provider' => 'bunny', 'zone' => '123456', 'token' => 'test-token-not-real-0000' ) );
$live = $run( array( $pncp_home => array( 200, array( 'server' => 'nginx' ) ) ) );
t( 'origin answer behind Bunny: could not be checked', 'unknown' === $live['headers']['state'] && false !== strpos( $note( $live ), 'Could not be checked' ) && false === strpos( $note( $live ), 'Missing' ), wp_json_encode( $live['headers'] ) );
t( 'origin answer behind Bunny: framing not claimed open', 'unknown' === $live['framing']['state'], wp_json_encode( $live['framing'] ) );
$st = PNCP_Hardening::status( 'headers' );
t( 'origin answer behind Bunny: the card shows why', false !== strpos( $st['note'], 'Could not be checked' ) && false !== strpos( $st['note'], 'Bunny CDN' ), wp_json_encode( $st ) );
t( 'no API key in the note', false === strpos( wp_json_encode( $live ), 'test-token-not-real' ) );
$live = $run( array( $pncp_home => array( 200, array_merge( $pncp_full, array( 'server' => 'nginx' ) ) ) ) );
t( 'origin answer behind Bunny with headers: Locked', 'on' === $live['headers']['state'], wp_json_encode( $live['headers'] ) );
update_option( PNCP_Edge::CONFIG, array( 'provider' => 'cloudflare', 'zone' => '0123456789abcdef0123456789abcdef', 'token' => 'x' ) );
$live = $run( array( $pncp_home => array( 200, array() ) ) );
t( 'origin answer behind Cloudflare: could not be checked', 'unknown' === $live['headers']['state'] && false !== strpos( $note( $live ), 'Cloudflare' ), wp_json_encode( $live['headers'] ) );
delete_option( PNCP_Edge::CONFIG );

// 4. Unreachable: could not be checked, never "missing".
$live = $run( array( $pncp_home => new WP_Error( 'http_request_failed', 'cURL error 7: Failed to connect' ) ) );
t( 'unreachable: could not be checked', 'unknown' === $live['headers']['state'] && false === strpos( $note( $live ), 'Missing' ), wp_json_encode( $live['headers'] ) );
$st = PNCP_Hardening::status( 'headers' );
t( 'unreachable: the card says why', false !== strpos( $st['note'], 'Failed to connect' ) && false === strpos( $st['note'], 'Missing' ), wp_json_encode( $st ) );
$live = $run(
	array(
		$pncp_home => array( 301, array( 'Location' => $final ) ),
		$final     => new WP_Error( 'http_request_failed', 'cURL error 6: Could not resolve host' ),
	)
);
t( 'unreachable after a redirect: could not be checked, with the step', 'unknown' === $live['headers']['state'] && false !== strpos( $note( $live ), '(HTTP 301)' ), wp_json_encode( $live['headers'] ) );
$live = $run( array( $pncp_home => array( 403, array() ) ) );
t( 'home refused (403): could not be checked', 'unknown' === $live['headers']['state'] && false !== strpos( $note( $live ), '403' ), wp_json_encode( $live['headers'] ) );

// Restore.
if ( null === $pncp_edge_before ) {
	delete_option( PNCP_Edge::CONFIG );
} else {
	update_option( PNCP_Edge::CONFIG, $pncp_edge_before );
}
delete_transient( PNCP_Hardening::LIVE );

echo $fails ? "\n$fails FAIL\n" : "\nOK\n";
exit( $fails ? 1 : 0 );
