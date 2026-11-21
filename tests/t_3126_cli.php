<?php
/**
 * ScrapeLock 3.12.6 — WP-CLI for the server: wp scrapelock cdn purge (C).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 WP_CLI="wp --path=…" php t_3126_cli.php
 *
 * C. cdn purge: with fake Bunny and Cloudflare APIs (a temporary mu-plugin, so that WP-CLI, another process, talks
 *    to them): one address, a path on the home address, several, --all (only with --yes), an address of another
 *    host (nothing purged), Bunny's 429 and Cloudflare's refusal (the other CDN still purged, exit code 1), no
 *    connection; the keys never printed.
 *
 * Only on a test WordPress.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
if ( '' === $wp_cli ) {
	echo "SKIP without WP_CLI\n";
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

/** Runs "wp scrapelock …": [exit code, stdout + stderr]. */
function cli( $args, $stdin = '/dev/null' ) {
	global $wp_cli;
	exec( $wp_cli . ' scrapelock ' . $args . ' < ' . escapeshellarg( $stdin ) . ' 2>&1', $out, $rc );
	wp_cache_flush();
	return array( $rc, implode( "\n", $out ) );
}

const BUNNY_KEY = 'bunny-3126-key-1234567890abcdef';
const CF_TOKEN  = 'cf3126token_ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CF_ZONE   = '0123456789abcdef0123456789abcdef';

$saved = array();
foreach ( array( PNCP_Edge::CONFIG, PNCP_Bunny::CONFIG, PNCP_Edge::CALLS, PNCP_Bunny::CALLS ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}

// The fake APIs, in every process while the option pncp_test_3126_cdn exists; removed at the end.
$mock = WP_CONTENT_DIR . '/mu-plugins/pncp-test-3126-cdn.php';
file_put_contents(
	$mock,
	<<<'PHP'
<?php
// TESTS ONLY: written and removed by tests/t_3126_cli.php. Fake Bunny and Cloudflare purge APIs.
if ( is_array( get_option( 'pncp_test_3126_cdn' ) ) ) {
	add_filter( 'pncp_bunny_api_base', static function () { return 'https://bunny-3126.mock.test'; } );
	add_filter( 'pncp_edge_api_base', static function ( $base, $provider ) { return 'cloudflare' === $provider ? 'https://cf-3126.mock.test/client/v4' : 'https://bunny-3126.mock.test'; }, 10, 2 );
	add_filter(
		'pre_http_request',
		static function ( $pre, $args, $url ) {
			$bunny = 0 === strpos( $url, 'https://bunny-3126.mock.test/' );
			$cf    = 0 === strpos( $url, 'https://cf-3126.mock.test/' );
			if ( ! $bunny && ! $cf ) {
				return $pre;
			}
			wp_cache_delete( 'pncp_test_3126_cdn', 'options' );
			$db       = get_option( 'pncp_test_3126_cdn' ) + array( 'calls' => array(), 'fail' => array() );
			$headers  = isset( $args['headers'] ) ? $args['headers'] : array();
			$db['calls'][] = array(
				'cdn'    => $bunny ? 'bunny' : 'cf',
				'method' => isset( $args['method'] ) ? $args['method'] : 'GET',
				'url'    => $url,
				'body'   => isset( $args['body'] ) ? json_decode( (string) $args['body'], true ) : null,
				'key'    => $bunny ? ( isset( $headers['AccessKey'] ) ? $headers['AccessKey'] : '' ) : ( isset( $headers['Authorization'] ) ? $headers['Authorization'] : '' ),
			);
			update_option( 'pncp_test_3126_cdn', $db, false );
			$reply = static function ( $code, $data ) {
				return array( 'headers' => array( 'content-type' => 'application/json' ), 'body' => wp_json_encode( $data ), 'response' => array( 'code' => $code, 'message' => '' ), 'cookies' => array(), 'filename' => null );
			};
			$fail = $bunny ? ( $db['fail']['bunny'] ?? 0 ) : ( $db['fail']['cf'] ?? 0 );
			if ( $bunny ) {
				return $fail ? $reply( $fail, array( 'Message' => 'Too many requests for key ' . $headers['AccessKey'] ) ) : $reply( 200, array() );
			}
			return $fail ? $reply( $fail, array( 'success' => false, 'errors' => array( array( 'code' => 10000, 'message' => 'Authentication error for ' . $headers['Authorization'] ) ) ) ) : $reply( 200, array( 'success' => true, 'result' => array( 'id' => 'x' ) ) );
		},
		1,
		3
	);
}
PHP
);
register_shutdown_function(
	static function () use ( $mock, $saved ) {
		@unlink( $mock );
		delete_option( 'pncp_test_3126_cdn' );
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, false );
			}
		}
	}
);
function mock_db( $fail = array() ) {
	update_option(
		'pncp_test_3126_cdn',
		array(
			'calls' => array(),
			'fail'  => $fail,
		),
		false
	);
}
function mock_calls() {
	wp_cache_delete( 'pncp_test_3126_cdn', 'options' );
	$db = get_option( 'pncp_test_3126_cdn' );
	return is_array( $db ) ? $db['calls'] : array();
}

/* ---------- C. cdn purge ---------- */

$home = home_url( '/' );
t( 'C own_url(): a path is on the home address', home_url( '/builtwith.txt' ) === PNCP_Edge::own_url( '/builtwith.txt' ) );
t( 'C own_url(): another host, a protocol-relative address, credentials, ftp: refused', '' === PNCP_Edge::own_url( 'https://example.org/x' ) && '' === PNCP_Edge::own_url( '//example.org/x' ) && '' === PNCP_Edge::own_url( str_replace( '://', '://u:p@', $home ) ) && '' === PNCP_Edge::own_url( 'ftp://' . wp_parse_url( $home, PHP_URL_HOST ) . '/x' ) );

delete_option( PNCP_Edge::CONFIG );
delete_option( PNCP_Bunny::CONFIG );
mock_db();
list( $rc, $out ) = cli( 'cdn purge /builtwith.txt' );
t( 'C no CDN connection: an error, no call', 0 !== $rc && false !== strpos( $out, 'No CDN connection' ) && ! mock_calls(), $out );

update_option(
	PNCP_Edge::CONFIG,
	array(
		'provider' => 'cloudflare',
		'zone'     => CF_ZONE,
		'token'    => CF_TOKEN,
	),
	false
);
update_option(
	PNCP_Bunny::CONFIG,
	array(
		'zone'  => '4242',
		'token' => BUNNY_KEY,
	),
	false
);
mock_db();
$url              = home_url( '/builtwith.txt' );
list( $rc, $out ) = cli( 'cdn purge ' . escapeshellarg( $url ) );
$calls            = mock_calls();
$bunny            = array_values( wp_list_filter( $calls, array( 'cdn' => 'bunny' ) ) );
$cf               = array_values( wp_list_filter( $calls, array( 'cdn' => 'cf' ) ) );
t( 'C one address: Bunny\'s purge API with the stored key (POST /purge?url=…&async=false)', 0 === $rc && 1 === count( $bunny ) && 'POST' === $bunny[0]['method'] && 'https://bunny-3126.mock.test/purge?url=' . rawurlencode( $url ) . '&async=false' === $bunny[0]['url'] && BUNNY_KEY === $bunny[0]['key'], $out . ' ' . wp_json_encode( $calls ) );
t( 'C ...and Cloudflare\'s purge_cache with files, the stored token', 1 === count( $cf ) && 'https://cf-3126.mock.test/client/v4/zones/' . CF_ZONE . '/purge_cache' === $cf[0]['url'] && array( 'files' => array( $url ) ) === $cf[0]['body'] && 'Bearer ' . CF_TOKEN === $cf[0]['key'], wp_json_encode( $cf ) );
t( 'C ...the output: status and counts only, never a key', false !== strpos( $out, 'Bunny CDN: 1 address purged.' ) && false !== strpos( $out, 'Cloudflare: 1 address purged.' ) && false === strpos( $out, BUNNY_KEY ) && false === strpos( $out, CF_TOKEN ), $out );

mock_db();
list( $rc, $out ) = cli( 'cdn purge /builtwith.txt /robots.txt' );
$cf               = array_values( wp_list_filter( mock_calls(), array( 'cdn' => 'cf' ) ) );
t( 'C paths: on the home address; Bunny one call per address, Cloudflare one call for both', 0 === $rc && 2 === count( wp_list_filter( mock_calls(), array( 'cdn' => 'bunny' ) ) ) && 1 === count( $cf ) && array( home_url( '/builtwith.txt' ), home_url( '/robots.txt' ) ) === $cf[0]['body']['files'] && false !== strpos( $out, 'Bunny CDN: 2 addresses purged.' ), $out );

mock_db();
list( $rc, $out ) = cli( 'cdn purge /ok.txt https://example.org/x.txt' );
t( 'C an address of another host: refused, nothing purged (not even the good one)', 0 !== $rc && ! mock_calls() && false !== strpos( $out, 'example.org' ), $out );
list( $rc, $out ) = cli( 'cdn purge' );
t( 'C no address and no --all: an error', 0 !== $rc && ! mock_calls() );
list( $rc, $out ) = cli( 'cdn purge /x.txt --all --yes' );
t( 'C addresses and --all: an error', 0 !== $rc && ! mock_calls() );

list( $rc, $out ) = cli( 'cdn purge --all' );
t( 'C --all without --yes (no answer): asks, purges nothing', ! mock_calls() && false !== strpos( $out, 'Purge the whole CDN cache' ), $out );
list( $rc, $out ) = cli( 'cdn purge --all --yes' );
$calls            = mock_calls();
$bunny            = array_values( wp_list_filter( $calls, array( 'cdn' => 'bunny' ) ) );
$cf               = array_values( wp_list_filter( $calls, array( 'cdn' => 'cf' ) ) );
t( 'C --all --yes: Bunny purgeCache of the pull zone, Cloudflare purge_everything', 0 === $rc && 1 === count( $bunny ) && 'https://bunny-3126.mock.test/pullzone/4242/purgeCache' === $bunny[0]['url'] && 1 === count( $cf ) && array( 'purge_everything' => true ) === $cf[0]['body'] && false !== strpos( $out, 'Bunny CDN: the whole cache was purged.' ), $out . ' ' . wp_json_encode( $calls ) );

mock_db( array( 'bunny' => 429 ) );
list( $rc, $out ) = cli( 'cdn purge /a.txt /b.txt' );
t( 'C Bunny\'s 429: stops at the first address, says so, the key not printed; Cloudflare still purged; exit 1', 1 === $rc && 1 === count( wp_list_filter( mock_calls(), array( 'cdn' => 'bunny' ) ) ) && false !== strpos( $out, 'Bunny asked to slow down' ) && false !== strpos( $out, 'Cloudflare: 2 addresses purged.' ) && false === strpos( $out, BUNNY_KEY ), $out );
mock_db( array( 'cf' => 403 ) );
list( $rc, $out ) = cli( 'cdn purge /a.txt' );
t( 'C Cloudflare refuses the token: a warning without the token, exit 1', 1 === $rc && false !== strpos( $out, 'Cloudflare: not purged' ) && false === strpos( $out, CF_TOKEN ) && false !== strpos( $out, 'Bunny CDN: 1 address purged.' ), $out );

// Bunny as the CDN of "Blocking at the CDN" (no own card): its pull zone and key.
delete_option( PNCP_Bunny::CONFIG );
update_option(
	PNCP_Edge::CONFIG,
	array(
		'provider' => 'bunny',
		'zone'     => '777',
		'token'    => BUNNY_KEY,
	),
	false
);
mock_db();
list( $rc, $out ) = cli( 'cdn purge --all --yes' );
$calls            = mock_calls();
t( 'C Bunny under "Blocking at the CDN": its pull zone, no Cloudflare call', 0 === $rc && 1 === count( $calls ) && 'https://bunny-3126.mock.test/pullzone/777/purgeCache' === $calls[0]['url'], $out . ' ' . wp_json_encode( $calls ) );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
