<?php
/**
 * ScrapeLock 3.12.1 — FluentCommunity: a signed-in member's REST reads of /wp-json/fluent-community/* count per
 * account (user ID, not IP), at 4 × "REST API requests per minute", and toward the per-account page limit (real
 * WordPress, a stand-in plugin with one REST route of the namespace).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3121_fluent.php
 *
 * 1. The log table has the account column (PNCP_Log::account_column()).
 * 2. With a REST limit of 3: a member gets 12 reads (4 × 3), the 13th is a 429 for that account only; another
 *    member on the same address still reads; guests keep the per-IP limit (429 on the 4th), also on the members'
 *    address; the member's cookie without the session nonce counts per IP; no violation is counted.
 * 3. The 429 leaves a log row "rate_member" with the member's username.
 * 4. "Pages per minute per signed-in account" counts these reads together with the member's pages, four reads as
 *    one page (a portal screen is several reads), with the username in its log row.
 * 5. The early check and the pre-cache check leave these requests to WordPress (no limit before the session is
 *    known); FluentCommunity deactivated: the reads count per IP again.
 * 6. The texts: the note under the REST limit (Bots tab), the "Content addresses" note, the "For my site" note.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

$fails = 0;
/**
 * Runs an upgrade step as the plugin does, without the SQLite drop-in's own "Deprecated" notices and database
 * errors inside dbDelta() (CI runs on SQLite; they are the drop-in's, not the plugin's), as t_admin.php does.
 */
function quiet( $step ) {
	global $wpdb;
	$er       = error_reporting( error_reporting() & ~E_DEPRECATED );
	$suppress = $wpdb->suppress_errors( true );
	call_user_func( $step );
	$wpdb->suppress_errors( $suppress );
	error_reporting( $er );
}

function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	wp_cache_delete( 'alloptions', 'options' );
}

/** A session of a user: [cookies, X-WP-Nonce of that session]. */
function session_of( $user_id ) {
	$expire  = time() + DAY_IN_SECONDS;
	$token   = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	$cookies = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	$nonce = wp_create_nonce( 'wp_rest' );
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	wp_set_current_user( 0 );
	return array( $cookies, $nonce );
}

/** An HTTP request; [code, body]. */
function http( $path, $cookies = array(), $headers = array(), $ip = '192.0.2.212' ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_COOKIE         => implode( '; ', $jar ),
			CURLOPT_HTTPHEADER     => array_merge( array( 'X-Test-IP: ' . $ip, 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0 Safari/537.36', 'Accept-Language: el', 'Accept: application/json' ), $headers ),
			CURLOPT_TIMEOUT        => 90,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

/** $n requests, their status codes. */
function codes( $n, $path, $cookies = array(), $headers = array(), $ip = '192.0.2.212' ) {
	$out = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$out[] = http( $path, $cookies, $headers, $ip )[0];
	}
	return $out;
}

/** The counters are per minute: a sequence starts early in a minute, so it never crosses into the next one. */
function fresh_minute() {
	$s = (int) gmdate( 's' );
	if ( $s > 40 ) {
		sleep( 61 - $s );
	}
}

function log_rows( $reason, $ip ) {
	global $wpdb;
	return (array) $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE reason = %s AND ip = %s ORDER BY id DESC', PNCP_Log::table(), $reason, $ip ), ARRAY_A );
}

$feeds      = '/wp-json/fluent-community/v2/feeds';
$saved      = get_option( PNCP_OPTION );
$plugin_dir = WP_PLUGIN_DIR . '/fluent-community';
$plugin     = $plugin_dir . '/fluent-community.php';
$created    = ! is_dir( $plugin_dir );
$old_file   = is_file( $plugin ) ? file_get_contents( $plugin ) : null;
$users      = array();
register_shutdown_function(
	static function () use ( $saved, $plugin_dir, $plugin, $created, $old_file, &$users ) {
		deactivate_plugins( 'fluent-community/fluent-community.php', true );
		if ( null !== $old_file ) {
			file_put_contents( $plugin, $old_file );
		} else {
			@unlink( $plugin );
		}
		if ( $created ) {
			@rmdir( $plugin_dir );
		}
		foreach ( $users as $id ) {
			wp_delete_user( $id );
		}
		update_option( PNCP_OPTION, $saved );
		PNCP_Options::flush();
	}
);

if ( $created ) {
	mkdir( $plugin_dir );
}
// A stand-in: its header, its constant and one REST route of its namespace (GET, open to everyone, as the portal's feeds).
file_put_contents(
	$plugin,
	"<?php\n/*\nPlugin Name: FluentCommunity (test stand-in)\nVersion: 0.0.1\n*/\n"
	. "defined( 'FLUENT_COMMUNITY_PLUGIN_VERSION' ) || define( 'FLUENT_COMMUNITY_PLUGIN_VERSION', '0.0.1' );\n"
	. "add_action( 'rest_api_init', function () { register_rest_route( 'fluent-community/v2', '/feeds', array( 'methods' => 'GET', 'permission_callback' => '__return_true', 'callback' => function () { return array( 'feeds' => array(), 'user' => get_current_user_id() ); } ) ); } );\n"
);
activate_plugin( PNCP_Fluent_Community::BASENAME );
wp_cache_delete( 'alloptions', 'options' );
settings(
	array(
		'enabled'            => 1,
		'monitor_mode'       => 0,
		'monitor_until'      => 0,
		'rate_limit_rest'    => 3,
		'rate_limit_account' => 0,
		'rate_limit_apionly' => 0,
		'ban_strikes'        => 3,
		'reputation'         => 0,
		'human_check'        => 0,
		'block_ips'          => '',
		'early_mode'         => 0,
		'precheck'           => 0,
	)
);

/* ---------- 1. The log column ---------- */
quiet( array( 'PNCP_Log', 'install' ) ); // As the upgrade does (also when the table was made by an older version).
t( 'log table: the account column is there', PNCP_Log::account_column() && (int) PNCP_Log::DB_VERSION === (int) get_option( 'pncp_db_version' ), (string) get_option( 'pncp_db_version' ) );
t( 'log reasons: rate_member has a name', isset( PNCP_Log::reasons()['rate_member'] ) );
t( 'FluentCommunity active (stand-in)', PNCP_Fluent_Community::active() );

$run = wp_rand( 1000, 9999 );
foreach ( array( 'a', 'b', 'c', 'd' ) as $who ) {
	$users[ $who ] = wp_insert_user(
		array(
			'user_login' => 'fc3121_' . $who . '_' . $run,
			'user_pass'  => wp_generate_password(),
			'user_email' => 'fc3121_' . $who . '_' . $run . '@example.com',
			'role'       => 'subscriber',
		)
	);
}
list( $a_cookies, $a_nonce ) = session_of( $users['a'] );
list( $b_cookies, $b_nonce ) = session_of( $users['b'] );
$net = '203.0.' . wp_rand( 1, 250 ) . '.';
$ip  = $net . '91'; // The members' address (shared: a mobile network, an office).

/* ---------- 2. Members per account, guests per IP ---------- */
fresh_minute();
$codes = codes( 14, $feeds, $a_cookies, array( 'X-WP-Nonce: ' . $a_nonce ), $ip );
t( 'member A, REST limit 3: 12 portal reads pass (4 × 3), the 13th and 14th get 429', array_merge( array_fill( 0, 12, 200 ), array( 429, 429 ) ) === $codes, implode( ',', $codes ) );
list( $c, $body ) = http( $feeds, $a_cookies, array( 'X-WP-Nonce: ' . $a_nonce ), $ip );
$json             = json_decode( $body, true );
t( 'the 429 is the REST error "Too many requests" with retry_after', 429 === $c && is_array( $json ) && 'pncp_rate_limited' === $json['code'] && ! empty( $json['data']['retry_after'] ), substr( $body, 0, 200 ) );
$codes = codes( 5, $feeds, $b_cookies, array( 'X-WP-Nonce: ' . $b_nonce ), $ip );
t( 'member B on the same address: not affected (5 × 200)', array( 200, 200, 200, 200, 200 ) === $codes, implode( ',', $codes ) );
$codes = codes( 5, $feeds, array(), array(), $ip );
t( 'guest on the members\' address: the per-IP REST limit, untouched by the members (429 on the 4th)', array( 200, 200, 200, 429, 429 ) === $codes, implode( ',', $codes ) );
$codes = codes( 5, $feeds, array(), array(), $net . '92' );
t( 'guest on another address: 429 on the 4th', array( 200, 200, 200, 429, 429 ) === $codes, implode( ',', $codes ) );
$codes = codes( 5, $feeds, $b_cookies, array(), $net . '93' );
t( 'a member\'s cookie without the session nonce: a guest, counted per IP (429 on the 4th)', array( 200, 200, 200, 429, 429 ) === $codes, implode( ',', $codes ) );
t( 'no temporary block of the members\' address (no violation for a per-account limit)', ! PNCP_Log::is_banned( $ip ) );

/* ---------- 3. The log row ---------- */
$rows = log_rows( 'rate_member', $ip );
$a    = get_userdata( $users['a'] )->user_login;
t( 'log: a "rate_member" row with member A\'s username, 429, the portal address', $rows && $a === $rows[0]['account'] && 429 === (int) $rows[0]['code'] && 0 === strpos( (string) $rows[0]['path'], '/wp-json/fluent-community/' ), wp_json_encode( $rows ) );
t( 'log: only member A has such a row (B was never over)', 1 === count( array_unique( wp_list_pluck( $rows, 'account' ) ) ) );
t( 'log: the guest\'s 429 is the normal REST limit, without a username', (bool) array_filter(
	log_rows( 'rate_rest', $net . '92' ),
	static function ( $r ) {
		return '' === (string) $r['account'];
	}
) );
$admin   = get_user_by( 'id', 1 );
list( $admin_cookies ) = session_of( $admin->ID );
list( $c, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=log', $admin_cookies, array(), '192.0.2.213' );
t( 'Log tab: the row shows "Account: <username>"', 200 === $c && false !== strpos( $body, 'Account: ' . $a ), (string) $c );

/* ---------- 4. The per-account page limit counts them ---------- */
settings(
	array(
		'rate_limit_rest'    => 100,
		'rate_limit_account' => 5,
	)
);
list( $c_cookies, $c_nonce ) = session_of( $users['c'] );
list( $d_cookies, $d_nonce ) = session_of( $users['d'] );
fresh_minute();
$codes = codes( 22, $feeds, $c_cookies, array( 'X-WP-Nonce: ' . $c_nonce ), $net . '94' );
t( 'member C, 5 pages per minute per account: 20 portal reads (four as one page), the 21st gets 429', array_merge( array_fill( 0, 20, 200 ), array( 429, 429 ) ) === $codes, implode( ',', $codes ) );
$rows = log_rows( 'rate_account', $net . '94' );
t( 'log: a "rate_account" row with member C\'s username', $rows && get_userdata( $users['c'] )->user_login === $rows[0]['account'], wp_json_encode( $rows ) );
fresh_minute();
$codes = array_merge( codes( 3, '/', $d_cookies, array(), $net . '95' ), codes( 10, $feeds, $d_cookies, array( 'X-WP-Nonce: ' . $d_nonce ), $net . '96' ) );
t( 'member D: 3 pages and then portal reads from another address share one count (8 reads left, 429 on the 9th)', array_merge( array_fill( 0, 11, 200 ), array( 429, 429 ) ) === $codes, implode( ',', $codes ) );
$codes = codes( 2, '/', $d_cookies, array(), $net . '95' );
t( 'member D: then a page is over the limit too (one count)', array( 429, 429 ) === $codes, implode( ',', $codes ) );
settings( array( 'rate_limit_account' => 0 ) );

/* ---------- 5. Early check, pre-cache check, deactivated ---------- */
require_once PNCP_DIR . 'includes/class-pncp-precheck-runtime.php';
$pncp_server = $_SERVER;
$pncp_cookie = $_COOKIE;
$conf        = PNCP_Precheck::config();
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI']    = $feeds;
t( 'pre-cache check: /wp-json/fluent-community/… is left to WordPress', ! PNCP_Precheck_Runtime::applies( $conf ) );
$_SERVER['REQUEST_URI'] = '/?rest_route=/fluent-community/v2/feeds';
t( 'pre-cache check: ?rest_route=/fluent-community/… too', ! PNCP_Precheck_Runtime::applies( $conf ) );
$_COOKIE = array( 'wordpress_logged_in_x' => 'member' );
$skip    = new ReflectionMethod( 'PNCP_Early', 'skip_request' );
$skip->setAccessible( true );
$_SERVER['REQUEST_URI'] = $feeds;
t( 'early check: a request with a sign-in cookie is left to WordPress (it counts no limit anyway)', true === $skip->invoke( null ) );
$_SERVER = $pncp_server;
$_COOKIE = $pncp_cookie;

/* ---------- 6. The texts ---------- */
list( , $bots ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=bots', $admin_cookies, array(), '192.0.2.213' );
t( 'Bots tab: the note under the REST limit, short line + "More"', 1 === preg_match( '#<p class="description pncp-fluent-rest-note">FluentCommunity: members(&\#039;|\'|&\#8217;)? portal reads count per account, at 4× this limit\.</p>\s*<details class="pncp-more"#u', $bots ), preg_match( '#pncp-fluent-rest-note">[^<]*#', $bots, $m ) ? $m[0] : 'none' );
$note = PNCP_Fluent_Community::note();
t( 'Content addresses / "For my site" note: per account, no longer "do not count"', false !== strpos( $note, 'count per account' ) && false === strpos( $note, 'do not count' ), $note );
$wiz = wp_list_pluck( array_filter( PNCP_Wizard::notes(), static function ( $n ) {
	return 'FluentCommunity' === $n['for'];
} ), 'text' );
t( '"For my site": the FluentCommunity note says the same', $wiz && false !== strpos( implode( ' ', $wiz ), 'count per account' ), implode( ' | ', $wiz ) );

deactivate_plugins( PNCP_Fluent_Community::BASENAME, true );
wp_cache_delete( 'alloptions', 'options' );
settings( array( 'rate_limit_rest' => 3 ) );
fresh_minute();
$codes = codes( 5, $feeds, $b_cookies, array( 'X-WP-Nonce: ' . $b_nonce ), $net . '97' );
t( 'FluentCommunity deactivated: its routes are gone and a member\'s REST reads count per IP (429 on the 4th)', 429 === $codes[3], implode( ',', $codes ) );
list( , $bots ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=bots', $admin_cookies, array(), '192.0.2.213' );
t( 'deactivated: no note under the REST limit', false === strpos( $bots, 'pncp-fluent-rest-note' ) );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
