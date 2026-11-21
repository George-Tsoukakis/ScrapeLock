<?php
/**
 * ScrapeLock 3.11 — nothing removed, and a 3.10.1 settings export imports without loss, in real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_311_compat.php
 *
 * Fixtures (generated on a 3.10.1 site, tests/fixtures/):
 * - settings-export-3.10.1.json: "Export settings" of a 3.10.1 site with every public setting changed from its
 *   default (except the switches that change what a test site does: protection, early and pre-cache checks,
 *   "Only through the CDN", "Monitor only").
 * - keys-3.10.1.json: the keys of PNCP_Options::defaults(), the tabs, and the form field names that 3.10.1
 *   renders on every settings tab with those settings, as an administrator.
 *
 * Checks: every 3.10.1 settings key and tab is still there; the export is read with nothing ignored and imports
 * with every value kept (a saved version first, as a normal import); a 3.11 export of it gives the same values in
 * the same format; every field name of 3.10.1 is still rendered on its tab.
 *
 * Same requirements as t_http.php (mu-test-harness.php, router.php). Changes the database: test sites only.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
if ( ! function_exists( 'add_settings_error' ) ) {
	require_once ABSPATH . 'wp-admin/includes/template.php'; // The settings checks report through it.
}

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** An admin page (as the administrator); [code, body]. */
function admin_page( $path, $cookies ) {
	global $base;
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$ch = curl_init( $base . $path );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_COOKIE         => implode( '; ', $jar ),
			CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.251', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', 'Accept-Language: el' ),
			CURLOPT_TIMEOUT        => 120,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

$dir    = __DIR__ . '/fixtures/';
$json   = (string) file_get_contents( $dir . 'settings-export-3.10.1.json' );
$export = json_decode( $json, true );
$keys   = json_decode( (string) file_get_contents( $dir . 'keys-3.10.1.json' ), true );
if ( ! is_array( $export ) || ! is_array( $keys ) ) {
	t( 'fixtures readable', false );
	exit( 1 );
}

$saved         = PNCP_Options::stored();
$saved_backups = get_option( PNCP_Settings_Io::BACKUPS, null );
register_shutdown_function(
	static function () use ( $saved, $saved_backups ) {
		update_option( PNCP_OPTION, $saved );
		if ( null === $saved_backups ) {
			delete_option( PNCP_Settings_Io::BACKUPS );
		} else {
			update_option( PNCP_Settings_Io::BACKUPS, $saved_backups, false );
		}
		PNCP_Options::flush();
	}
);

/* ---------- Settings keys ---------- */

$now     = array_keys( PNCP_Options::defaults() );
$missing = array_values( array_diff( $keys['defaults'], $now ) );
// 3.12 adds the Traffic keys (PNCP_Options::new_in_3120()), 3.12.5 blur_on_capture_scope (new_in_3125()), 3.12.6
// block_tech_profilers (new_in_3126()); 3.11 itself added none.
$added   = array_values( array_diff( $now, $keys['defaults'], array_keys( PNCP_Options::new_in_3120() ), array_keys( PNCP_Options::new_in_3125() ), array_keys( PNCP_Options::new_in_3126() ) ) );
t( 'every settings key of 3.10.1 is still in PNCP_Options::defaults() (' . count( $keys['defaults'] ) . ' keys)', ! $missing, implode( ',', $missing ) );
t( 'no new settings key in 3.11, only the 3.12 Traffic keys, the 3.12.5 blur scope and the 3.12.6 profilers switch (' . count( $now ) . ' keys)', ! $added, implode( ',', $added ) );
$public  = PNCP_Settings_Io::public_keys();
$missing = array_values( array_diff( array_keys( $export['settings'] ), $public ) );
t( 'every exported setting of 3.10.1 can still be imported (public_keys())', ! $missing, implode( ',', $missing ) );
t( 'secrets and site state stay out of export and import as before', array( 'cdn_secret', 'crowdsec_key' ) === PNCP_Settings_Io::secret_keys() && array( 'monitor_until' ) === PNCP_Settings_Io::internal_keys() );

/* ---------- Import of the 3.10.1 export ---------- */

$parsed = PNCP_Settings_Io::parse( $json );
t( 'the 3.10.1 file is read: nothing ignored', is_array( $parsed ) && ! $parsed['ignored'] && count( $parsed['settings'] ) === count( $export['settings'] ), is_wp_error( $parsed ) ? $parsed->get_error_message() : wp_json_encode( $parsed['ignored'] ) );
$prepared = PNCP_Settings_Io::prepare( $parsed['settings'] );
$lost     = array();
foreach ( $export['settings'] as $key => $value ) {
	if ( ! array_key_exists( $key, $prepared['settings'] ) || (string) $prepared['settings'][ $key ] !== (string) $value ) {
		$lost[] = $key . ': ' . wp_json_encode( $value ) . ' -> ' . ( array_key_exists( $key, $prepared['settings'] ) ? wp_json_encode( $prepared['settings'][ $key ] ) : 'missing' );
	}
}
t( 'every value of the file survives the settings checks of 3.11', ! $lost, implode( ' | ', $lost ) );
t( 'the checks have nothing to say about it', ! $prepared['messages'], wp_json_encode( $prepared['messages'] ) );
$before = count( PNCP_Settings_Io::backups() );
$id     = PNCP_Settings_Io::apply( $prepared, 'import' );
PNCP_Options::flush();
$stored = PNCP_Options::stored();
$lost   = array();
foreach ( $export['settings'] as $key => $value ) {
	if ( (string) $stored[ $key ] !== (string) $value ) {
		$lost[] = $key;
	}
}
t( 'imported: every value stored as in the file', ! $lost, implode( ',', $lost ) );
t( 'imported: the settings before were saved under "Earlier versions" first', ( '' === $id && ! $prepared['changes'] ) || ( is_string( $id ) && '' !== $id && count( PNCP_Settings_Io::backups() ) === min( PNCP_Settings_Io::KEEP, $before + 1 ) ), is_wp_error( $id ) ? $id->get_error_message() : (string) $id );

$again = PNCP_Settings_Io::export();
$diff  = array();
foreach ( $export['settings'] as $key => $value ) {
	if ( ! array_key_exists( $key, $again['settings'] ) || (string) $again['settings'][ $key ] !== (string) $value ) {
		$diff[] = $key;
	}
}
t( 'a 3.11 export of it: the same format and the same values', $export['format'] === $again['format'] && 'scrapelock' === $again['plugin'] && ! $diff && $export['excluded'] === $again['excluded'], implode( ',', $diff ) );
$reparsed = PNCP_Settings_Io::parse( PNCP_Settings_Io::export_json() );
t( 'and the 3.11 export reads back with nothing ignored', is_array( $reparsed ) && ! $reparsed['ignored'] );

/* ---------- Tabs and fields ---------- */

$expire  = time() + DAY_IN_SECONDS;
$token   = WP_Session_Tokens::get_instance( 1 )->create( $expire );
$cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( 1, $expire, 'auth', $token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( 1, $expire, 'logged_in', $token ),
);
// The Log's row buttons (ua, ip) need a row, as on the 3.10.1 site.
$_SERVER['HTTP_USER_AGENT'] = 'CompatTestBot/1.0';
PNCP_Log::add( 'bot_ua', 403, '198.51.100.250' );
$seen   = array();
$fields = array();
foreach ( $keys['tabs'] as $tab ) {
	list( $code, $body ) = admin_page( '/wp-admin/options-general.php?page=scrapelock&tab=' . $tab, $cookies );
	t( "tab $tab: still there (200, active, no PHP warnings)", 200 === $code && ! php_errors( $body ) && 1 === preg_match( '#nav-tab-active[^"]*" aria-current="page"#', $body ) && false === strpos( $body, 'pncp-unknown-tab' ), (string) $code );
	preg_match_all( '#<(?:input|select|textarea|button)\b[^>]*\bname="([^"]+)"#i', $body, $m );
	foreach ( $m[1] as $name ) {
		$fields[ $tab ][ $name ] = true;
	}
	preg_match_all( '#\bname="' . preg_quote( PNCP_OPTION, '#' ) . '\[([a-z0-9_]+)\]#', $body, $m2 );
	foreach ( $m2[1] as $key ) {
		$seen[ $key ] = true;
	}
}
$missing = array_values( array_diff( $keys['setting_fields'], array_keys( $seen ) ) );
t( 'every setting field of 3.10.1 is still on the settings page (' . count( $keys['setting_fields'] ) . ')', ! $missing, implode( ',', $missing ) );
$gone = array();
foreach ( $keys['fields'] as $name => $tabs ) {
	foreach ( $tabs as $tab ) {
		if ( empty( $fields[ $tab ][ $name ] ) ) {
			$gone[] = $tab . ':' . $name;
		}
	}
}
t( 'every form field of 3.10.1 is still on its own tab (' . count( $keys['fields'] ) . ' names)', ! $gone, implode( ',', $gone ) );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
