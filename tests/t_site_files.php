<?php
/**
 * ScrapeLock 3.10.1 — Site Health «ScrapeLock site files» (apple-touch-icon.png από το Site Icon,
 * OneSignalSDKWorker.js όσο το OneSignal είναι ενεργό): έλεγχος μέσω HTTP, «Create it» / «Remove» μόνο με nonce
 * και manage_options, ποτέ αντικατάσταση ξένου αρχείου, αφαίρεση μόνο αρχείων του ScrapeLock. Και ο έλεγχος
 * «Wordfence and the visitor address» πίσω από CDN (ψεύτικο wfUtils / wfConfig μέσα στη διεργασία).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_site_files.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );

define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
require_once ABSPATH . 'wp-admin/includes/image.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

if ( ! class_exists( 'PNCP_Site_Files' ) ) {
	echo "SKIP PNCP_Site_Files missing\n";
	exit( 0 );
}

/** An HTTP request; [code, body, location, content-type]. */
function http( $path, $post = null, $cookies = array() ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.210', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 'Accept-Language: en' ),
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_TIMEOUT        => 60,
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = http_build_query( $post );
	}
	curl_setopt_array( $ch, $opts );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	$type = (string) curl_getinfo( $ch, CURLINFO_CONTENT_TYPE );
	curl_close( $ch );
	$loc = preg_match( '/^location:\s*(\S+)/mi', substr( $out, 0, $hs ), $m ) ? $m[1] : '';
	return array( $code, substr( $out, $hs ), $loc, $type );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

$root        = PNCP_Site_Files::root_dir();
$names       = array( 'apple-touch-icon.png', 'apple-touch-icon-precomposed.png', 'OneSignalSDKWorker.js' );
$pre_exist   = array();
foreach ( $names as $name ) {
	$pre_exist[ $name ] = is_file( $root . $name );
}
$saved_icon  = get_option( 'site_icon' );
$attachment  = 0;
$onesignal   = false;
add_filter(
	'pncp_onesignal_active',
	static function () use ( &$onesignal ) {
		return $onesignal;
	}
);
register_shutdown_function(
	static function () use ( $root, $names, $pre_exist, $saved_icon, &$attachment ) {
		foreach ( $names as $name ) {
			if ( ! $pre_exist[ $name ] && is_file( $root . $name ) ) {
				unlink( $root . $name );
			}
		}
		if ( $attachment ) {
			wp_delete_attachment( $attachment, true );
		}
		update_option( 'site_icon', $saved_icon );
		delete_option( PNCP_Site_Files::RECORD );
		delete_transient( PNCP_Site_Files::CACHE );
	}
);
if ( array_filter( $pre_exist ) ) {
	echo "SKIP the site root already has one of the test files\n";
	exit( 0 );
}

/* ---------- 1. Registration ---------- */
$tests = PNCP_Site_Files::tests( array() );
t( 'Site Health: async test scrapelock_sitefiles registered (one underscore in the key)', isset( $tests['async']['scrapelock_sitefiles'] ) && 1 === substr_count( 'scrapelock_sitefiles', '_' ) );
t( 'Site Health: no Wordfence test while Wordfence is not active', ! isset( $tests['direct']['scrapelock_wordfence'] ) );
t( 'files(): the icon (both Apple names) and the OneSignal worker', array( 'apple-touch-icon.png', 'apple-touch-icon-precomposed.png' ) === PNCP_Site_Files::files()['icon'] && array( 'OneSignalSDKWorker.js' ) === PNCP_Site_Files::files()['onesignal'] );
t( 'OneSignal worker: exactly the one importScripts line of the v16 SDK (slashes not escaped)', "importScripts(\"https://cdn.onesignal.com/sdks/web/v16/OneSignalSDK.sw.js\");\n" === PNCP_Site_Files::onesignal_worker(), PNCP_Site_Files::onesignal_worker() );

/* ---------- 2. No Site Icon, OneSignal not active ---------- */
$admin = get_user_by( 'id', 1 );
wp_set_current_user( $admin->ID );
delete_option( 'site_icon' );
delete_transient( PNCP_Site_Files::CACHE );
$r = PNCP_Site_Files::test();
t( 'no Site Icon: recommended, with a link to choose one', 'recommended' === $r['status'] && false !== strpos( $r['description'], 'customize.php' ), $r['status'] );
t( 'no Site Icon: no "Create it" for the icon (nothing to make it from)', false === strpos( $r['description'], 'value="icon"' ) );
t( 'OneSignal not active: its worker is not asked for', ! array_key_exists( 'onesignal', PNCP_Site_Files::probe() ) );
t( 'create(onesignal) refused while OneSignal is not active', 'unknown' === PNCP_Site_Files::create( 'onesignal' ) && ! is_file( $root . 'OneSignalSDKWorker.js' ) );

/* ---------- 3. Site Icon set, OneSignal active: both answer "not found" ---------- */
$up  = wp_upload_dir();
$src = $up['path'] . '/pncp-test-site-icon.png';
$img = imagecreatetruecolor( 600, 600 );
imagefill( $img, 0, 0, imagecolorallocate( $img, 30, 120, 200 ) );
imagepng( $img, $src );
imagedestroy( $img );
$attachment = wp_insert_attachment(
	array(
		'post_mime_type' => 'image/png',
		'post_title'     => 'pncp test site icon',
		'post_status'    => 'inherit',
	),
	$src
);
wp_update_attachment_metadata( $attachment, wp_generate_attachment_metadata( $attachment, $src ) );
update_option( 'site_icon', $attachment );
$onesignal = true;
delete_transient( PNCP_Site_Files::CACHE );
$probe = PNCP_Site_Files::probe();
t( 'probe: apple-touch-icon.png missing over HTTP', isset( $probe['icon'] ) && 'missing' === $probe['icon'], wp_json_encode( $probe ) );
t( 'probe: OneSignalSDKWorker.js missing over HTTP', isset( $probe['onesignal'] ) && 'missing' === $probe['onesignal'], wp_json_encode( $probe ) );
$r = PNCP_Site_Files::test();
t( 'test: recommended with a "Create it" button for each (nonce in the form)', 'recommended' === $r['status'] && false !== strpos( $r['description'], 'value="icon"' ) && false !== strpos( $r['description'], 'value="onesignal"' ) && false !== strpos( $r['description'], '_wpnonce' ), $r['status'] );
t( 'test: says these are not security problems', false !== strpos( $r['description'], 'not a security problem' ) );
$refuse = static function ( $pre, $args, $url ) {
	return 0 === strpos( $url, home_url( '/' ) ) ? new WP_Error( 'http_request_failed', 'cURL error 7: Failed to connect' ) : $pre;
};
add_filter( 'pre_http_request', $refuse, 10, 3 );
delete_transient( PNCP_Site_Files::CACHE );
$r = PNCP_Site_Files::test();
t( 'site cannot ask itself (loopback refused): "could not be checked", still a "Create it" for files not in the folder', 'recommended' === $r['status'] && false !== strpos( $r['description'], 'Could not be checked over the web' ) && 2 === substr_count( $r['description'], 'value="create"' ), wp_strip_all_tags( $r['description'] ) );
remove_filter( 'pre_http_request', $refuse, 10 );
delete_transient( PNCP_Site_Files::CACHE );

/* ---------- 4. Create / Remove over HTTP: nonce and capability ---------- */
$expire  = time() + DAY_IN_SECONDS;
$token   = WP_Session_Tokens::get_instance( $admin->ID )->create( $expire );
$cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( $admin->ID, $expire, 'auth', $token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( $admin->ID, $expire, 'logged_in', $token ),
);
$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];

list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => PNCP_Site_Files::ACTION, 'op' => 'create', 'file' => 'icon', '_wpnonce' => 'wrong' ), $cookies );
t( 'Create with a wrong nonce: refused, nothing written', 403 === $code && ! is_file( $root . 'apple-touch-icon.png' ), (string) $code );

$sub_id      = wp_insert_user(
	array(
		'user_login' => 'pncp_sf_editor',
		'user_pass'  => wp_generate_password(),
		'role'       => 'editor',
	)
);
$sub_token   = WP_Session_Tokens::get_instance( $sub_id )->create( $expire );
$sub_cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( $sub_id, $expire, 'auth', $sub_token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( $sub_id, $expire, 'logged_in', $sub_token ),
);
wp_set_current_user( $sub_id );
$_COOKIE[ LOGGED_IN_COOKIE ] = $sub_cookies[ LOGGED_IN_COOKIE ];
$sub_nonce                   = wp_create_nonce( PNCP_Site_Files::ACTION . '_create_icon' );
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => PNCP_Site_Files::ACTION, 'op' => 'create', 'file' => 'icon', '_wpnonce' => $sub_nonce ), $sub_cookies );
t( 'Create as an editor (valid nonce of the editor): 403, nothing written', 403 === $code && ! is_file( $root . 'apple-touch-icon.png' ), (string) $code );
require_once ABSPATH . 'wp-admin/includes/user.php';
wp_delete_user( $sub_id );

wp_set_current_user( $admin->ID );
$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array( 'action' => PNCP_Site_Files::ACTION, 'op' => 'create', 'file' => 'icon', '_wpnonce' => wp_create_nonce( PNCP_Site_Files::ACTION . '_create_icon' ) ), $cookies );
$png = is_file( $root . 'apple-touch-icon.png' ) ? file_get_contents( $root . 'apple-touch-icon.png' ) : '';
$dim = '' !== $png ? getimagesizefromstring( $png ) : false;
t( 'Create icon as admin: back to Site Health with "created"', 302 === $code && false !== strpos( $loc, 'site-health.php' ) && false !== strpos( $loc, 'pncp_site_files=created' ), $code . ' ' . $loc );
t( 'Create icon: apple-touch-icon.png is a 180 × 180 PNG', is_array( $dim ) && 180 === $dim[0] && 180 === $dim[1] && 'image/png' === $dim['mime'] );
t( 'Create icon: apple-touch-icon-precomposed.png too, same content', is_file( $root . 'apple-touch-icon-precomposed.png' ) && file_get_contents( $root . 'apple-touch-icon-precomposed.png' ) === $png );
list( $code, $body, , $type ) = http( '/apple-touch-icon.png' );
t( 'HTTP: /apple-touch-icon.png answers 200 image/png', 200 === $code && false !== strpos( $type, 'image/png' ) && $body === $png, $code . ' ' . $type );

list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array( 'action' => PNCP_Site_Files::ACTION, 'op' => 'create', 'file' => 'onesignal', '_wpnonce' => wp_create_nonce( PNCP_Site_Files::ACTION . '_create_onesignal' ) ), $cookies );
// The HTTP server runs without this process's filter: OneSignal counts as active there only with the plugin.
if ( false !== strpos( $loc, 'pncp_site_files=unknown' ) ) {
	t( 'Create worker over HTTP (OneSignal not active in the server): refused as unknown', ! is_file( $root . 'OneSignalSDKWorker.js' ) );
	wp_cache_flush(); // The server wrote the record of the icon: read it again.
	$done = PNCP_Site_Files::create( 'onesignal' );
} else {
	$done = 'created';
}
t( 'Create worker: written with the importScripts line', 'created' === $done && PNCP_Site_Files::onesignal_worker() === (string) @file_get_contents( $root . 'OneSignalSDKWorker.js' ), $done );
list( $code, $body, , $type ) = http( '/OneSignalSDKWorker.js' );
t( 'HTTP: /OneSignalSDKWorker.js answers 200 JavaScript', 200 === $code && false !== strpos( $type, 'javascript' ) && false !== strpos( $body, 'importScripts' ), $code . ' ' . $type );

// The server deleted the cached check (Create): this process still holds it in its own cache.
wp_cache_flush();
delete_transient( PNCP_Site_Files::CACHE );
$r = PNCP_Site_Files::test();
t( 'test after Create: good, both files named', 'good' === $r['status'] && false !== strpos( $r['description'], 'apple-touch-icon.png' ) && false !== strpos( $r['description'], 'OneSignalSDKWorker.js' ), $r['status'] . ' ' . wp_strip_all_tags( $r['description'] ) );
t( 'test after Create: a Remove button for each file ScrapeLock created', 2 === substr_count( $r['actions'], 'value="remove"' ) );
t( 'Create again: nothing written over the files ("exists")', 'exists' === PNCP_Site_Files::create( 'icon' ) );

/* ---------- 5. Never over, never removing, a file of the site ---------- */
file_put_contents( $root . 'OneSignalSDKWorker.js', "// the site's own worker\n" );
t( 'a changed file is no longer counted as ScrapeLock\'s', ! PNCP_Site_Files::ours( 'OneSignalSDKWorker.js' ) );
t( 'Remove of a changed file: refused ("notours"), the file stays', 'notours' === PNCP_Site_Files::remove( 'onesignal' ) && "// the site's own worker\n" === file_get_contents( $root . 'OneSignalSDKWorker.js' ) );
unlink( $root . 'OneSignalSDKWorker.js' );
file_put_contents( $root . 'OneSignalSDKWorker.js', "// the site's own worker\n" );
delete_option( PNCP_Site_Files::RECORD );
t( 'Create over a file of the site: "exists", the file unchanged', 'exists' === PNCP_Site_Files::create( 'onesignal' ) && "// the site's own worker\n" === file_get_contents( $root . 'OneSignalSDKWorker.js' ) );
unlink( $root . 'OneSignalSDKWorker.js' );
PNCP_Site_Files::create( 'icon' ); // The icon record was dropped with the option above: written again? (files exist → "exists").
update_option( PNCP_Site_Files::RECORD, array( 'apple-touch-icon.png' => sha1( $png ), 'apple-touch-icon-precomposed.png' => sha1( $png ) ), false );

list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array( 'action' => PNCP_Site_Files::ACTION, 'op' => 'remove', 'file' => 'icon', '_wpnonce' => wp_create_nonce( PNCP_Site_Files::ACTION . '_remove_icon' ) ), $cookies );
t( 'Remove icon as admin: both files gone, "removed"', false !== strpos( $loc, 'pncp_site_files=removed' ) && ! is_file( $root . 'apple-touch-icon.png' ) && ! is_file( $root . 'apple-touch-icon-precomposed.png' ), $loc );

list( $code, $body ) = http( '/wp-admin/site-health.php?pncp_site_files=removed', null, $cookies );
t( 'Site Health with the notice: 200, the message shown, no PHP warnings', 200 === $code && false !== strpos( $body, 'The file created by ScrapeLock was removed.' ) && ! php_errors( $body ), (string) $code );
list( $code, $body ) = http( '/wp-admin/admin-ajax.php', array( 'action' => 'health-check-scrapelock-sitefiles', '_wpnonce' => wp_create_nonce( 'health-check-site-status' ) ), $cookies );
$json = json_decode( $body, true );
t( 'Site Health AJAX test: success with a result', 200 === $code && ! empty( $json['success'] ) && isset( $json['data']['status'] ), substr( $body, 0, 200 ) );
list( $code ) = http( '/wp-admin/admin-ajax.php', array( 'action' => 'health-check-scrapelock-sitefiles', '_wpnonce' => 'wrong' ), $cookies );
t( 'Site Health AJAX test with a wrong nonce: refused', 403 === $code || 400 === $code, (string) $code );

/* ---------- 6. Wordfence behind the CDN ---------- */
// Declared only now (a class declared in the file would exist from the start: PHP hoists it).
// phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test stand-ins for Wordfence.
eval( 'class wfUtils { public static $ip = ""; public static function getIP() { return self::$ip; } }
class wfConfig { public static $how = ""; public static function get( $key, $default = false ) { return "howGetIPs" === $key ? self::$how : $default; } }' );
$tests = PNCP_Site_Files::tests( array() );
t( 'Site Health: Wordfence test registered once Wordfence is active', isset( $tests['direct']['scrapelock_wordfence'] ) );

$edge     = '203.0.113.10';
$visitor  = '198.51.100.7';
$s_before = PNCP_Options::stored();
$l_before = get_option( 'pncp_ip_lists_bunny', null );
PNCP_Ip::store_list( 'bunny', array( $edge, '203.0.113.64/26' ) );
update_option( PNCP_OPTION, array_merge( $s_before, array( 'ip_header' => 'x_forwarded_for', 'trusted_proxies' => $edge ) ) );
PNCP_Options::flush();
$as = static function ( $remote, $xff ) {
	$_SERVER['REMOTE_ADDR'] = $remote;
	unset( $_SERVER['HTTP_X_TEST_IP'] );
	if ( '' === $xff ) {
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
	} else {
		$_SERVER['HTTP_X_FORWARDED_FOR'] = $xff;
	}
	PNCP_Ip::reset();
};

$as( $edge, $visitor );
wfUtils::$ip = $edge;
$r           = PNCP_Site_Files::test_wordfence();
t( 'Wordfence reads the Bunny edge: critical, both addresses named', 'critical' === $r['status'] && false !== strpos( $r['description'], $edge ) && false !== strpos( $r['description'], $visitor ), $r['status'] . ' ' . wp_strip_all_tags( $r['description'] ) );
t( 'Wordfence fix: X-Forwarded-For and Trusted Proxies, with Bunny\'s list to copy', false !== strpos( $r['description'], 'X-Forwarded-For' ) && false !== strpos( $r['description'], 'Trusted Proxies' ) && false !== strpos( $r['description'], '203.0.113.64/26' ) );

wfUtils::$ip = $visitor;
$r           = PNCP_Site_Files::test_wordfence();
t( 'Wordfence reads the visitor: good', 'good' === $r['status'] && false !== strpos( $r['description'], $visitor ), $r['status'] );

wfUtils::$ip = '192.0.2.99';
$r           = PNCP_Site_Files::test_wordfence();
t( 'Wordfence reads a third address: recommended', 'recommended' === $r['status'], $r['status'] );

$as( $visitor, '' );
wfUtils::$ip  = $visitor;
wfConfig::$how = 'HTTP_X_FORWARDED_FOR';
$r            = PNCP_Site_Files::test_wordfence();
t( 'a visit not through the CDN: good (same address), no false alarm', 'good' === $r['status'], $r['status'] );

update_option( PNCP_OPTION, $s_before );
PNCP_Options::flush();
if ( null === $l_before ) {
	delete_option( 'pncp_ip_lists_bunny' );
} else {
	update_option( 'pncp_ip_lists_bunny', $l_before );
}
PNCP_Ip::reset();

/* ---------- 7. Uninstall ---------- */
t( 'uninstall.php removes the files ScrapeLock created and its record', false !== strpos( (string) file_get_contents( PNCP_DIR . 'uninstall.php' ), 'PNCP_Site_Files::remove_all()' ) );
PNCP_Site_Files::create( 'icon' );
PNCP_Site_Files::remove_all();
t( 'remove_all(): the icon files and the record are gone', ! is_file( $root . 'apple-touch-icon.png' ) && false === get_option( PNCP_Site_Files::RECORD ) );

echo $fails ? "\n$fails FAIL\n" : "\nOK\n";
exit( $fails ? 1 : 0 );
