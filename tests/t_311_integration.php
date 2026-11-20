<?php
/**
 * ScrapeLock 3.11 — how the parts of 3.11 work together, in real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_311_integration.php
 *
 * - The pre-cache check is compiled from the settings it is written for: the allowed AI search bots and the bot
 *   list without them always agree (also when the request's settings cache is older).
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
require_once ABSPATH . 'wp-admin/includes/user.php';

$fails = 0;
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
	PNCP_Ip::reset();
}

/** Reads the settings again from the database (after a request of the web server changed them). */
function reread() {
	wp_cache_delete( PNCP_OPTION, 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_delete( PNCP_Settings_Io::BACKUPS, 'options' );
	PNCP_Options::flush();
	return PNCP_Options::stored();
}

/** The $_SERVER of a request from $ip (everything of a browser removed). */
function as_request( $ip, $ua, $headers = array() ) {
	foreach ( array( 'HTTP_X_TEST_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_SEC_CH_UA', 'HTTP_SEC_FETCH_MODE', 'HTTP_USER_AGENT' ) as $k ) {
		unset( $_SERVER[ $k ] );
	}
	$_SERVER['REMOTE_ADDR'] = $ip;
	if ( '' !== $ua ) {
		$_SERVER['HTTP_USER_AGENT'] = $ua;
	}
	foreach ( $headers as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
}

/** check() for a page, without counting. */
function verdict() {
	$v = PNCP_Bots::check( 'page', false );
	return is_array( $v ) ? $v['code'] . ' ' . $v['reason'] : 'pass';
}

/** An HTTP request (as a visitor from $ip); [code, body, location]. */
function http( $path, $ip, $ua, $post = null, $cookies = array(), $headers = array() ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => array_merge( array( 'X-Test-IP: ' . $ip, 'User-Agent: ' . $ua ), $headers ),
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
	curl_close( $ch );
	$loc = preg_match( '/^location:\s*(\S+)/mi', substr( $out, 0, $hs ), $m ) ? $m[1] : '';
	return array( $code, substr( $out, $hs ), $loc );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

/** Whether a request of the web server banned the IP (the caches of this process read again). */
function banned( $ip ) {
	wp_cache_flush();
	PNCP_Log::reset_cache();
	return PNCP_Log::is_banned( $ip );
}

/** Auth cookies of a user, and the user made current for nonces. */
function login_cookies( $user_id ) {
	$expire  = time() + DAY_IN_SECONDS;
	$token   = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	$cookies = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	return $cookies;
}

$saved         = PNCP_Options::stored();
$saved_backups = get_option( PNCP_Settings_Io::BACKUPS, null );
$saved_plugins = get_option( 'active_plugins', array() );
register_shutdown_function(
	static function () use ( $saved, $saved_backups, $saved_plugins ) {
		update_option( PNCP_OPTION, $saved );
		if ( null === $saved_backups ) {
			delete_option( PNCP_Settings_Io::BACKUPS );
		} else {
			update_option( PNCP_Settings_Io::BACKUPS, $saved_backups, false );
		}
		update_option( 'active_plugins', $saved_plugins );
		PNCP_Options::flush();
	}
);

/* ---------- The pre-cache check and "Allow AI search" ---------- */

settings(
	array(
		'block_bots'      => 1,
		'allow_ai_search' => 0,
		'bot_list'        => "GPTBot\nOAI-SearchBot",
	)
);
PNCP_Options::get(); // The request's settings cache, as a page that saves the settings has it.
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'allow_ai_search' => 1 ) ) ); // Not flushed.
$config = PNCP_Precheck::config();
$allow  = array_map(
	static function ( $e ) {
		return $e[0];
	},
	(array) $config['allow_ua']
);
t( 'pre-cache: an allowed AI search bot is not in its bot list', ! in_array( 'oai-searchbot', (array) $config['bots'], true ) && in_array( 'gptbot', (array) $config['bots'], true ) );
t( 'pre-cache: and is in its always-allowed User-Agents, from the same settings', in_array( 'oai-searchbot', $allow, true ) && in_array( 'chatgpt-user', $allow, true ), implode( ',', $allow ) );
PNCP_Options::flush();
settings( array( 'allow_ai_search' => 0 ) );
$config = PNCP_Precheck::config();
$allow  = array_map(
	static function ( $e ) {
		return $e[0];
	},
	(array) $config['allow_ua']
);
t( 'pre-cache: with AI search off it is in the bot list and not allowed', in_array( 'oai-searchbot', (array) $config['bots'], true ) && ! in_array( 'oai-searchbot', $allow, true ) );
t( 'allowed_ai_search() reads the settings it is given', array() === PNCP_Options::allowed_ai_search( array( 'allow_ai_search' => 0 ) ) && in_array( 'OAI-SearchBot', PNCP_Options::allowed_ai_search( array( 'allow_ai_search' => 1 ) ), true ) );

// The early check with a bot list entry that only contains an AI search bot's name ("ChatGPT"): the allowed bot
// passes, a training crawler with the same word does not.
settings(
	array(
		'enabled'         => 1,
		'early_mode'      => 1,
		'monitor_mode'    => 0,
		'monitor_until'   => 0,
		'block_bots'      => 1,
		'allow_ai_search' => 1,
		'bot_list'        => "ChatGPT\nGPTBot",
	)
);
as_request( '198.51.100.71', 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot' );
$e = PNCP_Early::check();
t( 'early check: an allowed AI search bot passes a bot list entry with its name in it', null === $e, wp_json_encode( $e ) );
$cfg = PNCP_Precheck::config();
t( 'pre-cache: the same, the allowed bot is in its always-allowed User-Agents', in_array( 'chatgpt-user', array_column( (array) $cfg['allow_ua'], 0 ), true ) && in_array( 'chatgpt', (array) $cfg['bots'], true ) );
as_request( '198.51.100.72', 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot' );
$e = PNCP_Early::check();
t( 'early check: a training crawler is still refused', is_array( $e ) && 'bot_ua' === $e[1], wp_json_encode( $e ) );
settings(
	array(
		'enabled'         => $saved['enabled'],
		'early_mode'      => $saved['early_mode'],
		'monitor_mode'    => $saved['monitor_mode'],
		'monitor_until'   => $saved['monitor_until'],
		'block_bots'      => $saved['block_bots'],
		'allow_ai_search' => $saved['allow_ai_search'],
		'bot_list'        => $saved['bot_list'],
	)
);

// @@NEXT@@

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
