<?php
/**
 * ScrapeLock 3.12.1 — AI search bots: ignored while "Allow AI search" is on, blocked again from the built-in list
 * when it is turned off, never written back into the stored bot list. In real WordPress, the early check and the
 * pre-cache check:
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3121_ai_search.php
 *
 * C1. A bot list as the 3.11 upgrade left it (the AI search bots removed), "Allow AI search" on: OAI-SearchBot from
 *     its official address (a stored test list, PNCP_Ip::store_list( 'openai_search' )) passes in WordPress, the
 *     early check and the pre-cache check; from another address it is a "Fake AI search bot" (403).
 * C2. Allow AI search 1 -> 0: the same request gets 403 in WordPress, the early check and the pre-cache check
 *     (its configuration carries the built-in list); every AI search bot is blocked; the bot list is untouched.
 * C3. 0 -> 1: it passes again everywhere; the bot list is untouched.
 * C4. The 3.11 migration does not run again (upgrade from 3.11.x / 3.12.0) and changes nothing; the warning of the
 *     Bots tab and its button still make sense.
 *
 * The pre-cache check runs over HTTP with a stand-in page cache (WP_CACHE + advanced-cache.php serving /cached-page/
 * before plugins load), as t_311_pipeline.php does; wp-config.php and advanced-cache.php are put back at the end.
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
	wp_cache_delete( 'alloptions', 'options' );
}

/** The $_SERVER of a request (every browser header removed first). */
function as_request( $remote, $ua, $headers = array(), $uri = '/' ) {
	foreach ( array_keys( $_SERVER ) as $k ) {
		if ( 0 === strpos( $k, 'HTTP_' ) ) {
			unset( $_SERVER[ $k ] );
		}
	}
	$_SERVER['REMOTE_ADDR']    = $remote;
	$_SERVER['REQUEST_METHOD'] = 'GET';
	$_SERVER['REQUEST_URI']    = $uri;
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

/** The early check as text. */
function early() {
	// As a visitor's request: not in wp-admin (the screen set for PNCP_Precheck::sync() makes is_admin() true).
	$screen = isset( $GLOBALS['current_screen'] ) ? $GLOBALS['current_screen'] : null;
	unset( $GLOBALS['current_screen'] );
	$e = PNCP_Early::check();
	$GLOBALS['current_screen'] = $screen;
	return is_array( $e ) ? $e[0] . ' ' . $e[1] : 'pass';
}

/** An HTTP request: [code, headers (lowercase), body]. */
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
			CURLOPT_HEADER         => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_TIMEOUT        => 60,
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
}

/** A visitor through the "CDN": REMOTE_ADDR 127.0.0.1 (trusted for X-Real-IP), the visitor in X-Real-IP / X-Test-IP. */
function via_cdn( $ip, $ua ) {
	return array(
		'X-Real-IP'  => $ip,
		'X-Test-IP'  => $ip,
		'User-Agent' => $ua,
	);
}

/** The settings change of the Bots tab form: through the plugin's own sanitize(), as options.php saves them. */
function save_allow( $on ) {
	$new = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'allow_ai_search' => $on ? 1 : 0 ) ) );
	update_option( PNCP_OPTION, $new );
	PNCP_Options::flush();
	PNCP_Ip::reset();
	PNCP_Early::sync();
	PNCP_Precheck::sync();
}

/** The lists of the test, stored again (WP cron may have downloaded the real ones meanwhile, with internet). */
function test_lists() {
	wp_unschedule_hook( PNCP_Ip::CRON );
	set_transient( 'pncp_lists_missing_try', 1, HOUR_IN_SECONDS );
	PNCP_Ip::store_list( 'openai_search', array( '20.42.10.176/28' ) );
	PNCP_Ip::reset();
}

/* ---------- Setup ---------- */
$config_file = PNCP_Precheck::config_path();
$cache_file  = WP_CONTENT_DIR . '/advanced-cache.php';
$original    = (string) file_get_contents( $config_file );
$had_cache   = file_exists( $cache_file ) ? (string) file_get_contents( $cache_file ) : null;
$saved       = PNCP_Options::stored();
$version     = get_option( 'pncp_version' );
$list_saved  = get_option( PNCP_Ip::LISTS_OPTION . '_openai_search', null );
register_shutdown_function(
	static function () use ( $config_file, $original, $cache_file, $had_cache, $saved, $version, $list_saved ) {
		file_put_contents( $config_file, $original );
		if ( null === $had_cache ) {
			@unlink( $cache_file );
		} else {
			file_put_contents( $cache_file, $had_cache );
		}
		update_option( PNCP_OPTION, $saved );
		update_option( 'pncp_version', $version );
		PNCP_Options::flush();
		if ( null === $list_saved ) {
			delete_option( PNCP_Ip::LISTS_OPTION . '_openai_search' );
		} else {
			update_option( PNCP_Ip::LISTS_OPTION . '_openai_search', $list_saved );
		}
		PNCP_Early::sync();
		PNCP_Precheck::sync();
		PNCP_Log::unban_all();
	}
);
test_lists();
update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
PNCP_Log::unban_all();
// The bot list as the 3.11 upgrade left it on a site that allowed AI search: the default list without its bots.
$migrated = PNCP_Options::without_ai_search_in_bot_list(
	array(
		'allow_ai_search' => 1,
		'bot_list'        => PNCP_Options::default_bot_list(),
	)
)['bot_list'];
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'block_bots'              => 1,
		'block_empty_ua'          => 1,
		'require_browser_headers' => 1,
		'block_headless'          => 1,
		'block_fake_crawlers'     => 1,
		'allow_ai_search'         => 1,
		'verify_ai_bots'          => 1,
		'bot_list'                => $migrated,
		'allow_list'              => PNCP_Options::default_allow_list(),
		'probe_ban'               => 0,
		'rate_limit'              => 0,
		'rate_limit_search'       => 0,
		'rate_limit_404'          => 0,
		'rate_limit_unverified'   => 0,
		'rate_limit_datacenter'   => 0,
		'rate_limit_apionly'      => 0,
		'rate_limit_lowrep'       => 0,
		'human_check'             => 0,
		'ban_strikes'             => 0,
		'block_ips'               => '',
		'allow_ips'               => '',
		'trust_any_proxy'         => 0,
		'trusted_proxies'         => '',
		'ip_header'               => 'x_real_ip',
		'countries_block'         => '',
		'countries_strict'        => '',
		'auto_emergency'          => 0,
		'early_mode'              => 1,
		'precheck'                => 0,
		'block_ip_host'           => 0,
		'reputation'              => 0,
	)
);
$ai_bots = array( 'OAI-SearchBot', 'ChatGPT-User', 'PerplexityBot', 'Perplexity-User', 'DuckAssistBot', 'MistralAI-User' );
foreach ( $ai_bots as $bot ) {
	t( "setup: $bot is not in the stored bot list (as the 3.11 upgrade left it)", false === stripos( PNCP_Options::stored()['bot_list'], $bot ) );
}

// The stand-in page cache for the pre-cache check.
file_put_contents( $config_file, "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) );
file_put_contents( $cache_file, "<?php\nif ( isset( \$_SERVER['REQUEST_URI'] ) && 0 === strpos( \$_SERVER['REQUEST_URI'], '/cached-page/' ) ) {\n\theader( 'X-Test-Cache: HIT' );\n\techo 'CACHED PAGE';\n\texit;\n}\n" );
settings( array( 'precheck' => 1 ) );
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
WP_Screen::get( 'settings_page_scrapelock' )->set_current_screen();
PNCP_Early::sync();
PNCP_Precheck::sync();
sleep( 3 ); // OPcache: the new wp-config.php and the early check file.
t( 'pre-cache check active', PNCP_Precheck::active(), (string) get_option( PNCP_Precheck::STATUS ) );

$oai      = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.3; +https://openai.com/searchbot';
$official = '20.42.10.180';
$fake_ip  = '198.51.100.93';
$list     = PNCP_Options::stored()['bot_list'];

/**
 * The OAI-SearchBot request from its official address in every layer: [WordPress, early, HTTP WordPress,
 * HTTP pre-cache]. The test lists are stored again first (CI has internet).
 */
function layers( $ip, $ua ) {
	test_lists();
	as_request( '127.0.0.1', $ua, array( 'HTTP_X_REAL_IP' => $ip ) );
	$wp    = verdict();
	$early = early();
	$page  = req( '/', via_cdn( $ip, $ua ) );
	$cache = req( '/cached-page/', via_cdn( $ip, $ua ) );
	return array( $wp, $early, $page[0], $cache[0] );
}

/* ---------- C1. Allow AI search on ---------- */
$l = layers( $official, $oai );
t( 'C1 on: OAI-SearchBot from its official address passes in WordPress (verified)', 'pass' === $l[0] && 'ai_search' === PNCP_Bots::explain( $official, $oai, home_url( '/' ) )['pass'], $l[0] );
t( 'C1 on: ... and in the early check', 'pass' === $l[1], $l[1] );
t( 'C1 on: ... over HTTP (early check and WordPress): 200', 200 === $l[2], (string) $l[2] );
t( 'C1 on: ... on a cached page (pre-cache check): 200', 200 === $l[3], (string) $l[3] );
as_request( '127.0.0.1', $oai, array( 'HTTP_X_REAL_IP' => $fake_ip ) );
t( 'C1 on: OAI-SearchBot from an address not on its official list: 403 fake_ai_bot in WordPress', '403 fake_ai_bot' === verdict(), verdict() );
list( $code ) = req( '/', via_cdn( $fake_ip, $oai ) );
t( 'C1 on: ... over HTTP: 403', 403 === $code, (string) $code );
$cfg = json_decode( (string) file_get_contents( PNCP_Precheck::config_file() ), true );
t( 'C1 on: the pre-cache configuration does not block it (allowed, counted like a visitor)', is_array( $cfg ) && ! in_array( 'oai-searchbot', (array) $cfg['bots'], true ), is_array( $cfg ) ? 'bots: ' . count( (array) $cfg['bots'] ) : 'no config' );

/* ---------- C2. Allow AI search 1 -> 0 ---------- */
save_allow( false );
sleep( 3 ); // OPcache: the early check file and the pre-cache configuration.
t( 'C2 1 -> 0: the stored bot list is untouched (nothing written back into it)', PNCP_Options::stored()['bot_list'] === $list );
$l = layers( $official, $oai );
t( 'C2 off: OAI-SearchBot from its official address: 403 bot_ua in WordPress (built-in list)', '403 bot_ua' === $l[0], $l[0] );
t( 'C2 off: ... 403 in the early check', '403 bot_ua' === $l[1], $l[1] );
t( 'C2 off: ... over HTTP: 403', 403 === $l[2], (string) $l[2] );
t( 'C2 off: ... on a cached page (pre-cache check): 403', 403 === $l[3], (string) $l[3] );
$cfg = json_decode( (string) file_get_contents( PNCP_Precheck::config_file() ), true );
t( 'C2 off: the pre-cache configuration carries the built-in AI search bots', is_array( $cfg ) && ! array_diff( array_map( 'strtolower', $ai_bots ), (array) $cfg['bots'] ), is_array( $cfg ) ? implode( ',', array_diff( array_map( 'strtolower', $ai_bots ), (array) $cfg['bots'] ) ) : 'no config' );
foreach ( $ai_bots as $bot ) {
	as_request( '127.0.0.1', 'Mozilla/5.0 (compatible; ' . $bot . '/1.0)', array( 'HTTP_X_REAL_IP' => '198.51.100.94' ) );
	t( "C2 off: $bot: 403 bot_ua in WordPress and in the early check", '403 bot_ua' === verdict() && '403 bot_ua' === early(), verdict() . ' / ' . early() );
}
$entry = PNCP_Bot_Match::entry( $oai, PNCP_Options::get() );
t( 'C2 off: the log says where the match comes from: the built-in AI search bots', is_array( $entry ) && 'ai_search' === $entry['source'], wp_json_encode( $entry ) );
t( 'C2 off: the built-in list is the plugin\'s AI search bot list (filter pncp_ai_search_agents)', PNCP_Options::ai_search_agents() === PNCP_Options::ai_search_blocked( PNCP_Options::get() ) );
// An "Always allowed" entry still wins over the built-in list, as over the bot list.
settings( array( 'allow_list' => PNCP_Options::default_allow_list() . "\nChatGPT-User" ) );
as_request( '127.0.0.1', 'Mozilla/5.0 (compatible; ChatGPT-User/1.0)', array( 'HTTP_X_REAL_IP' => '198.51.100.95', 'HTTP_ACCEPT_LANGUAGE' => 'en' ) );
t( 'C2 off: ChatGPT-User in "Always allowed" still passes (the allow list comes first)', 'pass' === verdict(), verdict() );
settings( array( 'allow_list' => PNCP_Options::default_allow_list() ) );

/* ---------- C3. Allow AI search 0 -> 1 ---------- */
save_allow( true );
sleep( 3 );
t( 'C3 0 -> 1: the stored bot list is untouched', PNCP_Options::stored()['bot_list'] === $list );
$l = layers( $official, $oai );
t( 'C3 on again: OAI-SearchBot from its official address passes in WordPress', 'pass' === $l[0], $l[0] );
t( 'C3 on again: ... in the early check', 'pass' === $l[1], $l[1] );
t( 'C3 on again: ... over HTTP: 200', 200 === $l[2], (string) $l[2] );
t( 'C3 on again: ... on a cached page (pre-cache check): 200', 200 === $l[3], (string) $l[3] );
as_request( '127.0.0.1', $oai, array( 'HTTP_X_REAL_IP' => $fake_ip ) );
t( 'C3 on again: from another address it is still a fake AI search bot (403)', '403 fake_ai_bot' === verdict(), verdict() );

/* ---------- C4. The 3.11 migration and the Bots tab warning ---------- */
// A list that names the bots again (typed in by hand) while AI search is allowed.
settings( array( 'bot_list' => $list . "\nOAI-SearchBot\nPerplexityBot" ) );
$typed = PNCP_Options::stored()['bot_list'];
foreach ( array( '3.11.0', '3.11.2', '3.12.0' ) as $from ) {
	update_option( 'pncp_version', $from );
	pncp_upgrade();
	t( "C4 upgrade from $from: the 3.11 migration does not run again (the bot list is unchanged)", PNCP_Options::stored()['bot_list'] === $typed );
}
// The warning of the Bots tab names them and says they are blocked again on their own when AI search is off.
ob_start();
PNCP_Ai_Search_List::render_notice( PNCP_Options::get() );
$notice = (string) ob_get_clean();
t( 'C4 Bots tab: the warning names the bots and keeps "Remove from the list"', false !== strpos( $notice, 'OAI-SearchBot' ) && false !== strpos( $notice, 'Remove from the list' ) );
t( 'C4 Bots tab: the warning says they are blocked again from the built-in list when AI search is off', false !== strpos( $notice, 'blocks these bots again on its own, from its built-in list' ) );
settings( array( 'allow_ai_search' => 0 ) );
ob_start();
PNCP_Ai_Search_List::render_notice( PNCP_Options::get() );
t( 'C4 Bots tab: no warning while AI search is off (the list blocks them, as intended)', '' === (string) ob_get_clean() );
pncp_upgrade();
t( 'C4 upgrade with AI search off: the bot list is unchanged', PNCP_Options::stored()['bot_list'] === $typed );
// "Remove from the list" removes only what the list names, and nothing is ever added back by turning the option off.
settings( array( 'allow_ai_search' => 1 ) );
wp_set_current_user( 1 );
$removed = PNCP_Ai_Search_List::remove();
wp_set_current_user( 0 );
t( 'C4 "Remove from the list": the two typed lines go, the rest stays', 2 === $removed && PNCP_Options::stored()['bot_list'] === $list, (string) $removed );
save_allow( false );
t( 'C4 then AI search off: the bot list is still without them', PNCP_Options::stored()['bot_list'] === $list );
as_request( '127.0.0.1', $oai, array( 'HTTP_X_REAL_IP' => $official ) );
t( 'C4 ... and OAI-SearchBot is blocked all the same (403 bot_ua)', '403 bot_ua' === verdict(), verdict() );

echo $fails ? "\n$fails FAILED\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
