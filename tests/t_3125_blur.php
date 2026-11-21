<?php
/**
 * ScrapeLock 3.12.5 — "Blur the page on screenshot shortcuts" → "Applies to: Everyone / Only visitors who are not
 * signed in" (blur_on_capture_scope), decided in the browser so that cached pages work.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3125_blur.php
 *
 * S. The setting: default "all" (also on a new install), the form's checks (anything else → "all"), the "On the page"
 *    section, its label, the "requires" note under the blur, the page-cache keys.
 * U. Upgrade 3.12.4 → 3.12.5: every stored value stays, blur_on_capture_scope = "all"; a stored "guests" stays.
 * E. Export / import: the value goes out and comes back; an unknown value is left out.
 * A. The settings form: two radio buttons under the blur, dimmed with the note while the blur is off.
 *
 * Only on a test WordPress.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** Stores settings as they are. */
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	wp_cache_delete( 'alloptions', 'options' );
}

/** Runs pncp_upgrade() as t_311_status.php does (no file sync, without the SQLite drop-in's own notices). */
function upgrade() {
	global $wpdb;
	$er       = error_reporting( error_reporting() & ~E_DEPRECATED );
	$suppress = $wpdb->suppress_errors( true );
	pncp_upgrade();
	$wpdb->suppress_errors( $suppress );
	error_reporting( $er );
	delete_option( 'pncp_upgrade_files' );
	wp_clear_scheduled_hook( 'pncp_upgrade_files' );
	wp_cache_delete( 'alloptions', 'options' );
	PNCP_Options::flush();
}

/** A session of a user: [cookies, log-out nonce of that session]. */
function session_of( $user_id ) {
	$expire  = time() + DAY_IN_SECONDS;
	$token   = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	$cookies = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	$nonce = wp_create_nonce( 'log-out' );
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	wp_set_current_user( 0 );
	return array( $cookies, $nonce );
}

/**
 * An HTTP request: [code, headers (lower-case name => values), body].
 *
 * @param string     $path    Path.
 * @param array      $cookies Cookies.
 * @param array|null $post    POST fields.
 * @param string     $ip      Visitor IP (X-Test-IP).
 */
function http( $path, $cookies = array(), $post = null, $ip = '192.0.2.231' ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$headers = array();
	$opts    = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: ' . $ip, 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', 'Accept-Language: el', 'Accept: text/html' ),
		CURLOPT_TIMEOUT        => 90,
		CURLOPT_HEADERFUNCTION => static function ( $ch, $line ) use ( &$headers ) {
			$parts = explode( ':', $line, 2 );
			if ( 2 === count( $parts ) ) {
				$headers[ strtolower( trim( $parts[0] ) ) ][] = trim( $parts[1] );
			}
			return strlen( $line );
		},
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = http_build_query( $post );
	}
	curl_setopt_array( $ch, $opts );
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $headers, $body );
}

$saved     = get_option( PNCP_OPTION );
$saved_ver = get_option( 'pncp_version' );
$users     = array();
register_shutdown_function(
	static function () use ( $saved, $saved_ver, &$users ) {
		update_option( PNCP_OPTION, $saved );
		update_option( 'pncp_version', $saved_ver );
		foreach ( $users as $id ) {
			wp_delete_user( $id );
		}
		PNCP_Options::flush();
	}
);

/* ---------- S. The setting ---------- */

$d = PNCP_Options::defaults();
t( 'S: default blur_on_capture_scope = all', isset( $d['blur_on_capture_scope'] ) && 'all' === $d['blur_on_capture_scope'] );
$inst = PNCP_Options::install_defaults();
t( 'S: a new install also gets "all" (no new-install value)', 'all' === $inst['blur_on_capture_scope'] && ! isset( PNCP_Options::new_install()['blur_on_capture_scope'] ) );
t( 'S: blur_on_capture stays off by default', 0 === (int) $d['blur_on_capture'] && 0 === (int) $inst['blur_on_capture'] );
t( 'S: choices are all / guests', array( 'all', 'guests' ) === PNCP_Options::choices()['blur_on_capture_scope'] );
$cases = array(
	'guests'      => 'guests',
	'all'         => 'all',
	'GUESTS'      => 'guests',
	'members'     => 'all',
	''            => 'all',
	'guests<b>'   => 'all',
	'1'           => 'all',
);
$bad = array();
foreach ( $cases as $in => $want ) {
	$out = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'blur_on_capture_scope' => (string) $in ) ) );
	if ( $want !== $out['blur_on_capture_scope'] ) {
		$bad[] = $in . ' → ' . $out['blur_on_capture_scope'];
	}
}
$missing = PNCP_Options::stored();
unset( $missing['blur_on_capture_scope'] );
$out = PNCP_Options::sanitize( $missing );
t( 'S: sanitize keeps the two values and turns anything else (or nothing) into "all"', ! $bad && 'all' === $out['blur_on_capture_scope'], implode( ', ', $bad ) );
$out = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'blur_on_capture_scope' => array( 'guests' ) ) ) );
t( 'S: a list instead of a value → "all"', 'all' === $out['blur_on_capture_scope'] );
$sections = PNCP_Options::sections();
$in       = array();
foreach ( $sections as $name => $keys ) {
	if ( in_array( 'blur_on_capture_scope', $keys, true ) ) {
		$in[] = $name;
	}
	if ( in_array( 'blur_on_capture', $keys, true ) ) {
		$in[] = 'blur:' . $name;
	}
}
t( 'S: in the same section as blur_on_capture ("On the page")', array( 'general', 'blur:general' ) === $in, implode( ',', $in ) );
t( 'S: "Reset this tab" of On the page puts back "all"', 'all' === ( PNCP_Settings_Io::section_defaults( 'general' )['blur_on_capture_scope'] ?? '' ) );
$label = PNCP_Setting_Labels::label( 'blur_on_capture_scope' );
t( 'S: label in words', 'Screenshot blur applies to' === $label, $label );
$req = PNCP_Admin_Fields::requires();
t( 'S: requires the blur ("Takes effect only when … is on")', isset( $req['blur_on_capture_scope'] ) && 'blur_on_capture' === $req['blur_on_capture_scope']['on'] && 'on' === $req['blur_on_capture_scope']['mode'] );
t( 'S: a page-cache key (printed into the page)', in_array( 'blur_on_capture_scope', PNCP_Options::cache_keys(), true ) );
t( 'S: a public key (export, import, wp scrapelock settings)', in_array( 'blur_on_capture_scope', PNCP_Settings_Io::public_keys(), true ) );
t( 'S: the presets leave it alone', ! array_filter( PNCP_Options::profiles(), static function ( $p ) { return isset( $p['blur_on_capture_scope'] ); } ) );

/* ---------- U. Upgrade 3.12.4 → 3.12.5 ---------- */

// A 3.12.4 site with every setting as it stored them (some changed by hand), without the new key.
$old = array_merge(
	PNCP_Options::defaults(),
	array(
		'blur_on_capture' => 1,
		'rate_limit'      => 77,
		'copy_mode'       => 'block',
		'monitor_mode'    => 0,
	)
);
unset( $old['blur_on_capture_scope'] );
update_option( PNCP_OPTION, $old );
update_option( 'pncp_version', '3.12.4' );
PNCP_Options::flush();
upgrade();
$after = get_option( PNCP_OPTION );
$diff  = array();
foreach ( $old as $k => $v ) {
	if ( ! array_key_exists( $k, $after ) || (string) $v !== (string) $after[ $k ] ) {
		$diff[] = $k;
	}
}
t( 'U: 3.12.4 → 3.12.5: every stored value unchanged', ! $diff, implode( ', ', $diff ) );
t( 'U: 3.12.4 → 3.12.5: blur_on_capture_scope stored as "all"', isset( $after['blur_on_capture_scope'] ) && 'all' === $after['blur_on_capture_scope'] );
t( 'U: nothing else added', array( 'blur_on_capture_scope' ) === array_values( array_diff( array_keys( $after ), array_keys( $old ) ) ), implode( ',', array_diff( array_keys( $after ), array_keys( $old ) ) ) );
t( 'U: version stored', PNCP_VERSION === get_option( 'pncp_version' ) );
t( 'U: new_in_3125() = the default', array( 'blur_on_capture_scope' => 'all' ) === PNCP_Options::new_in_3125() );

// A stored "guests" (a 3.12.5 export imported before the upgrade ran) is not replaced.
update_option( PNCP_OPTION, array_merge( $old, array( 'blur_on_capture_scope' => 'guests' ) ) );
update_option( 'pncp_version', '3.12.4' );
PNCP_Options::flush();
upgrade();
t( 'U: a stored "guests" stays', 'guests' === get_option( PNCP_OPTION )['blur_on_capture_scope'] );

// A site whose upgrade could not store it (e.g. locked): the default fills in.
update_option( PNCP_OPTION, $old );
PNCP_Options::flush();
t( 'U: not stored → "all" in effect', 'all' === PNCP_Options::get()['blur_on_capture_scope'] );
update_option( PNCP_OPTION, $saved );
update_option( 'pncp_version', $saved_ver );
PNCP_Options::flush();

/* ---------- E. Export / import ---------- */

settings( array( 'blur_on_capture' => 1, 'blur_on_capture_scope' => 'guests' ) );
$export = json_decode( PNCP_Settings_Io::export_json(), true );
t( 'E: the export holds blur_on_capture_scope', isset( $export['settings']['blur_on_capture_scope'] ) && 'guests' === $export['settings']['blur_on_capture_scope'] );
settings( array( 'blur_on_capture_scope' => 'all' ) );
$parsed = PNCP_Settings_Io::parse( (string) wp_json_encode( $export ) );
t( 'E: the file is read', is_array( $parsed ) && 'guests' === $parsed['settings']['blur_on_capture_scope'] );
if ( is_array( $parsed ) ) {
	PNCP_Settings_Io::apply( PNCP_Settings_Io::prepare( $parsed['settings'] ), 'import' );
	wp_cache_delete( 'alloptions', 'options' );
	PNCP_Options::flush();
}
t( 'E: import puts "guests" back', 'guests' === PNCP_Options::stored()['blur_on_capture_scope'] );
$again = json_decode( PNCP_Settings_Io::export_json(), true );
t( 'E: export → import → export: the same settings', $export['settings'] === $again['settings'] );
$parsed = PNCP_Settings_Io::parse( '{"blur_on_capture_scope":"members","rate_limit":61}' );
t( 'E: an unknown value is left out and named', is_array( $parsed ) && ! isset( $parsed['settings']['blur_on_capture_scope'] ) && in_array( 'blur_on_capture_scope', $parsed['ignored'], true ) );
$old_export = json_decode( (string) file_get_contents( __DIR__ . '/fixtures/settings-export-3.10.1.json' ), true );
$parsed     = PNCP_Settings_Io::parse( (string) wp_json_encode( $old_export ) );
$prepared   = is_array( $parsed ) ? PNCP_Settings_Io::prepare( $parsed['settings'] ) : array();
t( 'E: an older export (without the key) keeps the current value', isset( $prepared['settings'] ) && 'guests' === $prepared['settings']['blur_on_capture_scope'] );
update_option( PNCP_OPTION, $saved );
PNCP_Options::flush();

/* ---------- A. The settings form ---------- */

$admin_id                  = 1;
list( $admin_cookies )     = session_of( $admin_id );
settings( array( 'blur_on_capture' => 0, 'blur_on_capture_scope' => 'all' ) );
list( $code, , $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=general', $admin_cookies, null, '192.0.2.232' );
t( 'A: the On the page tab opens', 200 === $code, (string) $code );
t( 'A: no PHP messages', ! preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:/', $body ) );
$blur_at  = strpos( $body, 'name="pncp_settings[blur_on_capture]"' );
$scope_at = strpos( $body, 'name="pncp_settings[blur_on_capture_scope]"' );
t( 'A: "Applies to:" right under the blur toggle', false !== $blur_at && false !== $scope_at && $scope_at > $blur_at && false === strpos( substr( $body, $blur_at, $scope_at - $blur_at ), 'pncp_settings[block_' ) );
t( 'A: two radio buttons, "Everyone" checked', 1 === preg_match( '#<input type="radio" id="pncp-blur_on_capture_scope-all" name="pncp_settings\[blur_on_capture_scope\]" value="all" checked=\'checked\'#', $body ) && 1 === preg_match( '#id="pncp-blur_on_capture_scope-guests" name="pncp_settings\[blur_on_capture_scope\]" value="guests"[^>]*>\s*Only visitors who are not signed in#', $body ) );
t( 'A: "Applies to:" and "Everyone" with its Default badge', false !== strpos( $body, 'Applies to:' ) && 1 === preg_match( '#value="all"[^>]*> Everyone <span class="pncp-tag pncp-tag--default">#', $body ) );
t( 'A: one help line, the details under "More"', false !== strpos( $body, 'id="pncp-blur_on_capture_scope-help">Members can then take screenshots' ) && 1 === preg_match( '#blur_on_capture_scope-help.{0,400}<details class="pncp-more">#s', $body ) );
t( 'A: blur off → dimmed, with the "requires" note', 1 === preg_match( '#<fieldset data-pncp-requires="blur_on_capture" aria-disabled="true"><legend class="screen-reader-text">Screenshot blur applies to</legend>#', $body ) && 1 === preg_match( '#<p class="description pncp-requires-note" id="pncp-blur_on_capture_scope-requires">Takes effect only when “Blur the page when Print Screen or a screenshot shortcut is pressed” is on\.</p>#u', $body ) );
settings( array( 'blur_on_capture' => 1, 'blur_on_capture_scope' => 'guests' ) );
list( , , $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=general', $admin_cookies, null, '192.0.2.232' );
t( 'A: blur on → not dimmed, note hidden, "guests" checked', false !== strpos( $body, '<fieldset data-pncp-requires="blur_on_capture"><legend' ) && false !== strpos( $body, 'id="pncp-blur_on_capture_scope-requires" hidden>' ) && 1 === preg_match( '#value="guests" checked=\'checked\'#', $body ) );
update_option( PNCP_OPTION, $saved );
PNCP_Options::flush();

update_option( PNCP_OPTION, $saved );
PNCP_Options::flush();
echo $fails ? "\n$fails FAIL\n" : "\nall PASS\n";
exit( $fails ? 1 : 0 );
