<?php
/**
 * "Nothing removed" lister: the keys of PNCP_Options::defaults() and the form field names rendered on every
 * settings tab (as an administrator, over HTTP). Usage: WP_DIR=… BASE=… php tests/lib/keys-fields.php > out.json (tests/fixtures/keys-3.10.1.json was made with it on 3.10.1)
 */
define( 'WP_USE_THEMES', false );
require getenv( 'WP_DIR' ) . '/wp-load.php';
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$expire = time() + 3600;
$token  = WP_Session_Tokens::get_instance( 1 )->create( $expire );
$cookie = AUTH_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( 1, $expire, 'auth', $token ) ) . '; ' . LOGGED_IN_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( 1, $expire, 'logged_in', $token ) );
$m_tabs = new ReflectionMethod( 'PNCP_Admin', 'tabs' );
$m_tabs->setAccessible( true );
$tabs = array_keys( $m_tabs->invoke( null ) );
$fields = array();
$ids    = array();
foreach ( $tabs as $tab ) {
	$ch = curl_init( $base . '/wp-admin/options-general.php?page=scrapelock&tab=' . $tab );
	curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIE => $cookie, CURLOPT_TIMEOUT => 120, CURLOPT_HTTPHEADER => array( 'X-Test-IP: 192.0.2.250', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', 'Accept-Language: el' ) ) );
	$body = (string) curl_exec( $ch );
	preg_match_all( '#<(?:input|select|textarea|button)\b[^>]*\bname="([^"]+)"#i', $body, $m );
	foreach ( array_unique( $m[1] ) as $name ) {
		if ( in_array( $name, array( '_wpnonce', '_wp_http_referer' ), true ) ) {
			continue;
		}
		$fields[ $name ][] = $tab;
	}
	preg_match_all( '#\bname="pncp_settings\[([a-z0-9_]+)\]#', $body, $m2 );
	foreach ( array_unique( $m2[1] ) as $key ) {
		$ids[ $key ] = true;
	}
}
ksort( $fields );
ksort( $ids );
$defaults = array_keys( PNCP_Options::defaults() );
sort( $defaults );
echo wp_json_encode(
	array(
		'version'        => PNCP_VERSION,
		'tabs'           => $tabs,
		'defaults'       => $defaults,
		'setting_fields' => array_keys( $ids ),
		'fields'         => array_map( 'array_values', array_map( 'array_unique', $fields ) ),
	),
	JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . "\n";
