<?php
/**
 * ScrapeLock 3.10 — site-metadata files are never scanner probes (PNCP_Paths::is_site_metadata()).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_metadata.php
 *
 * /llms.txt, /ai.txt, /robots.txt, /.well-known/* (assetlinks.json, traffic-advice, passkey-endpoints…),
 * favicon / apple-touch-icon, manifests and service workers (OneSignalSDKWorker.js): not "Scanner probe" in the
 * attack record (also as a 404), not a probe in the log's groups, never banned by "Ban scanners on their first
 * probe", not "scanner" or part of a 4xx flood in the Bunny log import (log served by a mock), and the rows
 * stored by 3.9.1 are deleted once. Real probes (/.env, /.git/config, /.well-known/x.php, /.well-known/../)
 * still count.
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

/** A request with curl: [code, body]. */
function req( $path, $headers = array() ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_TIMEOUT        => 30,
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $out );
}

function browser( $ip ) {
	return array(
		'X-Test-IP'       => $ip,
		'X-Forwarded-For' => $ip,
		'User-Agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36',
		'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language' => 'el-GR,el;q=0.9',
		'Accept-Encoding' => 'gzip, deflate, br',
	);
}

/** Rows of the attack record for an IP: category|path|detail => hits. */
function attack_rows( $ip ) {
	global $wpdb;
	$out = array();
	foreach ( (array) $wpdb->get_results( $wpdb->prepare( 'SELECT category, path, detail, SUM(hits) AS n FROM %i WHERE ip = %s GROUP BY category, path, detail', PNCP_Attacks::table(), $ip ), ARRAY_A ) as $row ) {
		$out[ $row['category'] . '|' . $row['path'] . '|' . $row['detail'] ] = (int) $row['n'];
	}
	return $out;
}

function has_row( $rows, $category, $path ) {
	foreach ( $rows as $key => $n ) {
		list( $c, $p ) = explode( '|', $key );
		if ( $c === $category && $p === $path ) {
			return true;
		}
	}
	return false;
}

$saved = get_option( PNCP_OPTION );
register_shutdown_function(
	static function () use ( $saved ) {
		update_option( PNCP_OPTION, $saved );
	}
);

/* ---------- 1. PNCP_Paths::is_site_metadata() ---------- */

$meta = array(
	'/llms.txt',
	'/llms-full.txt',
	'/ai.txt',
	'/robots.txt',
	'/ads.txt',
	'/app-ads.txt',
	'/security.txt',
	'/humans.txt',
	'/sitemap.xml',
	'/sitemap_index.xml',
	'/wp-sitemap-posts-post-1.xml',
	'/product-sitemap2.xml',
	'/.well-known/assetlinks.json',
	'/.well-known/traffic-advice',
	'/.well-known/passkey-endpoints',
	'/.well-known/apple-app-site-association',
	'/.well-known/security.txt',
	'/.well-known/acme-challenge/AbC_123-xyz',
	'/.well-known/openid-configuration',
	'/favicon.ico',
	'/favicon-32x32.png',
	'/apple-touch-icon.png',
	'/apple-touch-icon-180x180-precomposed.png',
	'/site.webmanifest',
	'/manifest.json',
	'/OneSignalSDKWorker.js',
	'/OneSignalSDKUpdaterWorker.js',
	'/sw.js',
	'/service-worker.js',
	'/firebase-messaging-sw.js',
	'/llms.txt?x=1',
	'/%2Ewell-known/traffic-advice',
);
$bad = array();
foreach ( $meta as $path ) {
	if ( ! PNCP_Paths::is_site_metadata( $path ) ) {
		$bad[] = $path;
	}
}
t( 'is_site_metadata: llms/ai/robots/ads/security/sitemaps/.well-known/icons/manifests/service workers', ! $bad, implode( ', ', $bad ) );

$probes = array(
	'/.env',
	'/.git/config',
	'/wp-config.php.bak',
	'/backup.zip',
	'/dump.sql',
	'/.well-known/../wp-config.php',
	'/.well-known/%2e%2e/wp-config.php',
	'/.well-known/%252e%252e/wp-config.php',
	'/.well-known/.env',
	'/.well-known/shell.php',
	'/.well-known/acme-challenge/x.php',
	'/.well-known/pki-validation/backup.zip',
	'/.well-known//x',
	'/.well-known\\x',
	'/wp-content/llms.txt',
	'/foo/robots.txt',
	'/phpmyadmin/',
	'/llms.txt.bak',
);
$bad = array();
foreach ( $probes as $path ) {
	if ( PNCP_Paths::is_site_metadata( $path ) ) {
		$bad[] = $path;
	}
}
t( 'is_site_metadata: secrets, traversal, scripts under /.well-known/ and nested copies are not metadata', ! $bad, implode( ', ', $bad ) );

// Filter: an entry can be added; one that would match a secret file is dropped.
$add = static function ( $p ) {
	$p['custom'] = 'my-feed\.json';
	$p['broad']  = '.*';
	$p['badrx']  = '(';
	return $p;
};
add_filter( 'pncp_site_metadata_paths', $add );
$keys = array_keys( PNCP_Paths::site_metadata_patterns() );
t( 'pncp_site_metadata_paths: a custom entry is used', PNCP_Paths::is_site_metadata( '/my-feed.json' ) );
t( 'pncp_site_metadata_paths: ".*" and an invalid pattern are dropped', in_array( 'custom', $keys, true ) && ! in_array( 'broad', $keys, true ) && ! in_array( 'badrx', $keys, true ) && ! PNCP_Paths::is_site_metadata( '/.env' ), implode( ',', $keys ) );
remove_filter( 'pncp_site_metadata_paths', $add );
t( 'pncp_site_metadata_paths: removed again', ! PNCP_Paths::is_site_metadata( '/my-feed.json' ) );

/* ---------- 2. Probe list, log groups, Bunny classify ---------- */

t( 'PNCP_Log::is_probe_path: metadata files are not probes', ! PNCP_Log::is_probe_path( '/llms.txt' ) && ! PNCP_Log::is_probe_path( '/.well-known/assetlinks.json' ) && ! PNCP_Log::is_probe_path( '/OneSignalSDKWorker.js' ) && ! PNCP_Log::is_probe_path( '/ai.txt' ) );
t( 'PNCP_Log::is_probe_path: /.env, /.well-known/x.php, /.well-known/.env still are', PNCP_Log::is_probe_path( '/.env' ) && PNCP_Log::is_probe_path( '/.well-known/x.php' ) && PNCP_Log::is_probe_path( '/.well-known/.env' ) );

$trap = static function ( $p ) {
	$p['too_wide'] = '(?:ai|ads|secrets)\.txt|\.well-known/traffic-advice';
	return $p;
};
add_filter( 'pncp_probe_trap_paths', $trap );
$rc = new ReflectionProperty( 'PNCP_Probe', 'paths' );
$rc->setAccessible( true );
$rc->setValue( null, array() );
t( 'PNCP_Probe::matches: an added probe entry never matches /ai.txt, /ads.txt or /.well-known/traffic-advice', ! PNCP_Probe::matches( '/ai.txt' ) && ! PNCP_Probe::matches( '/ads.txt' ) && ! PNCP_Probe::matches( '/.well-known/traffic-advice' ) && PNCP_Probe::matches( '/secrets.txt' ) );
remove_filter( 'pncp_probe_trap_paths', $trap );
$rc->setValue( null, array() );
t( 'PNCP_Probe::matches: /.env and /.git/config still match', PNCP_Probe::matches( '/.env' ) && PNCP_Probe::matches( '/.git/config' ) );

function bunny_row( $path, $status = 404 ) {
	return array(
		'path'   => $path,
		'query'  => '',
		'status' => $status,
		'ua'     => 'Mozilla/5.0',
	);
}
t( 'PNCP_Bunny::classify: /llms.txt, /.well-known/traffic-advice, /OneSignalSDKWorker.js are normal', '' === PNCP_Bunny::classify( bunny_row( '/llms.txt' ) ) && '' === PNCP_Bunny::classify( bunny_row( '/.well-known/traffic-advice' ) ) && '' === PNCP_Bunny::classify( bunny_row( '/OneSignalSDKWorker.js' ) ) );
t( 'PNCP_Bunny::classify: /.env, /.well-known/../.git/config are still "scanner"', 'scanner' === PNCP_Bunny::classify( bunny_row( '/.env' ) ) && 'scanner' === PNCP_Bunny::classify( bunny_row( '/.well-known/../.git/config' ) ) && 'scanner' === PNCP_Bunny::classify( bunny_row( '/.well-known/%2e%2e/.env' ) ) );

/* ---------- 3. HTTP: the attack record ---------- */

$s                  = $saved;
$s['enabled']       = 1;
$s['monitor_mode']  = 0;
$s['attack_record'] = 1;
$s['probe_ban']     = 1;
update_option( PNCP_OPTION, $s );
PNCP_Options::flush();

$ip = '45.155.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 );
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ip = %s', PNCP_Attacks::table(), $ip ) );
$codes = array();
foreach ( array( '/llms.txt', '/llms-full.txt', '/ai.txt', '/.well-known/assetlinks.json', '/.well-known/traffic-advice', '/.well-known/passkey-endpoints', '/OneSignalSDKWorker.js', '/apple-touch-icon-precomposed.png', '/sw.js' ) as $path ) {
	list( $code ) = req( $path, browser( $ip ) );
	$codes[]      = $path . '=' . $code;
}
t( 'HTTP: metadata files are answered (404 for the missing ones, never 403 / ban)', ! preg_grep( '/=(?:403|429|0)$/', $codes ), implode( ' ', $codes ) );
list( $code ) = req( '/', browser( $ip ) );
t( 'HTTP: the visitor was not banned by the probe guard', 200 === $code, (string) $code );

$rows = attack_rows( $ip );
t( 'Attack record: no "Scanner probe" row for /llms.txt, /ai.txt, /.well-known/*, /OneSignalSDKWorker.js', ! has_row( $rows, 'scanner', '/llms.txt' ) && ! has_row( $rows, 'scanner', '/ai.txt' ) && ! has_row( $rows, 'scanner', '/.well-known/assetlinks.json' ) && ! has_row( $rows, 'scanner', '/.well-known/traffic-advice' ) && ! has_row( $rows, 'scanner', '/OneSignalSDKWorker.js' ), wp_json_encode( $rows ) );
t( 'Attack record: nothing recorded at all for these requests', ! $rows, wp_json_encode( $rows ) );

// Real probes still count (another IP: the probe ban bans on the first one).
$ip2 = '45.156.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 );
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ip = %s', PNCP_Attacks::table(), $ip2 ) );
$s['probe_ban'] = 0;
update_option( PNCP_OPTION, $s );
PNCP_Options::flush();
req( '/.well-known/shell.php', browser( $ip2 ) );
req( '/backup-old.tar.gz', browser( $ip2 ) );
$rows = attack_rows( $ip2 );
t( 'Attack record: /.well-known/shell.php (404) is still a scanner probe', has_row( $rows, 'scanner', '/.well-known/shell.php' ), wp_json_encode( $rows ) );

$s['probe_ban'] = 1;
update_option( PNCP_OPTION, $s );
PNCP_Options::flush();
$ip3 = '45.157.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 );
list( $code ) = req( '/.env', browser( $ip3 ) );
t( 'Probe ban: /.env is still refused', 403 === $code || 404 === $code, (string) $code );
$rows = attack_rows( $ip3 );
t( 'Attack record: /.env is still a scanner probe', has_row( $rows, 'scanner', '/.env' ), wp_json_encode( $rows ) );
PNCP_Log::unban( $ip3 );

/* ---------- 4. Rows stored by 3.9.1 are deleted once ---------- */

$old  = '45.158.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 );
$hour = (int) ( floor( time() / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
foreach ( array( array( 'scanner', '/llms.txt', '' ), array( 'scanner', '/.well-known/traffic-advice', '' ), array( 'scanner', '/OneSignalSDKWorker.js', '' ), array( 'edge', '/.well-known/assetlinks.json', 'scanner' ), array( 'edge', '/llms.txt', '4xx flood' ), array( 'scanner', '/.env', '' ), array( 'edge', '/.env', 'scanner' ), array( 'injection', '/llms.txt', 'xss' ) ) as $r ) {
	$wpdb->insert(
		PNCP_Attacks::table(),
		array(
			'hour_ts'  => $hour,
			'k'        => md5( implode( '|', $r ) . '|' . $old ),
			'category' => $r[0],
			'path'     => $r[1],
			'ip'       => $old,
			'detail'   => $r[2],
			'hits'     => 5,
			'blocked'  => 0,
			'last_ts'  => time(),
		)
	);
}
$deleted = PNCP_Attacks::purge_site_metadata( true );
$rows    = attack_rows( $old );
t( 'Purge: the 3.9.1 rows of /llms.txt, /.well-known/*, /OneSignalSDKWorker.js are deleted', $deleted >= 5 && ! has_row( $rows, 'scanner', '/llms.txt' ) && ! has_row( $rows, 'scanner', '/.well-known/traffic-advice' ) && ! has_row( $rows, 'edge', '/.well-known/assetlinks.json' ) && ! has_row( $rows, 'edge', '/llms.txt' ) && ! has_row( $rows, 'scanner', '/OneSignalSDKWorker.js' ), $deleted . ' ' . wp_json_encode( $rows ) );
t( 'Purge: /.env rows and an injection on /llms.txt stay', has_row( $rows, 'scanner', '/.env' ) && has_row( $rows, 'edge', '/.env' ) && has_row( $rows, 'injection', '/llms.txt' ), wp_json_encode( $rows ) );
t( 'Purge: runs once (marker set)', -1 === PNCP_Attacks::purge_site_metadata() && false !== get_option( PNCP_Attacks::META_PURGED_OPTION, false ) );
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ip = %s', PNCP_Attacks::table(), $old ) );

/* ---------- 5. Bunny log import (log API mocked with pre_http_request) ---------- */

$zone  = '424242';
$bip   = '45.159.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 );
$sip   = '45.160.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 );
$now   = (int) ( microtime( true ) * 1000 );
$lines = array();
$host  = 'https://example.test';
for ( $i = 0; $i < 40; $i++ ) {
	foreach ( array( '/llms.txt', '/ai.txt', '/.well-known/assetlinks.json', '/.well-known/traffic-advice', '/OneSignalSDKWorker.js' ) as $path ) {
		$lines[] = implode( '|', array( 'HIT', '404', $now, '0', $zone, $bip, '-', $host . $path, 'DE', 'Mozilla/5.0 (compatible; Test)', 'id' . $i, 'DE' ) );
	}
}
$lines[] = implode( '|', array( 'HIT', '404', $now, '0', $zone, $sip, '-', $host . '/.env', 'DE', 'curl/8', 'idx', 'DE' ) );
$lines[] = implode( '|', array( 'HIT', '404', $now, '0', $zone, $sip, '-', $host . '/.well-known/../.git/config', 'DE', 'curl/8', 'idy', 'DE' ) );
$seen    = array();
$mock    = static function ( $pre, $args, $url ) use ( $lines, &$seen ) {
	if ( false === strpos( $url, 'mock-bunny-log.test' ) ) {
		return $pre;
	}
	$seen[] = $url;
	parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $q );
	$start = isset( $q['start'] ) ? (int) $q['start'] : 0;
	$end   = isset( $q['end'] ) ? (int) $q['end'] : count( $lines );
	$part  = array_slice( $lines, $start, max( 0, $end - $start ) );
	return array(
		'headers'  => array(),
		'body'     => $part ? implode( "\n", $part ) . "\n" : '',
		'response' => array(
			'code'    => 200,
			'message' => 'OK',
		),
		'cookies'  => array(),
		'filename' => null,
	);
};
$log_base = static function () {
	return 'http://mock-bunny-log.test';
};
add_filter( 'pre_http_request', $mock, 10, 3 );
add_filter( 'pncp_bunny_log_base', $log_base );
$s                    = $saved;
$s['enabled']         = 1;
$s['attack_record']   = 1;
$s['bunny_flood_4xx'] = 30;
update_option( PNCP_OPTION, $s );
PNCP_Options::flush();
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ip IN (%s, %s)', PNCP_Attacks::table(), $bip, $sip ) );
$state_before = get_option( 'pncp_bunny_state', false );
delete_option( 'pncp_bunny_state' );
$res = PNCP_Bunny::import(
	array(
		'zone'  => $zone,
		'token' => 'test-key',
	),
	microtime( true ) + 20
);
PNCP_Attacks::flush();
remove_filter( 'pre_http_request', $mock, 10 );
remove_filter( 'pncp_bunny_log_base', $log_base );
t( 'Bunny import: the mocked log was read', $seen && $res['lines'] >= count( $lines ) && '' === $res['error'], wp_json_encode( $res ) );
$rows = attack_rows( $bip );
t( 'Bunny import: 200 lines of /llms.txt, /ai.txt, /.well-known/*, /OneSignalSDKWorker.js record nothing (no scanner, no 4xx flood)', ! $rows, wp_json_encode( $rows ) );
$rows = attack_rows( $sip );
t( 'Bunny import: /.env and /.well-known/../.git/config are still attacks seen at the CDN', isset( $rows['edge|/.env|scanner'] ) && count( $rows ) >= 2, wp_json_encode( $rows ) );
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ip IN (%s, %s)', PNCP_Attacks::table(), $bip, $sip ) );
if ( false === $state_before ) {
	delete_option( 'pncp_bunny_state' );
} else {
	update_option( 'pncp_bunny_state', $state_before, false );
}

exit( $fails ? 1 : 0 );
