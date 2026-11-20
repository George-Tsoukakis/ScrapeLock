<?php
/**
 * ScrapeLock 3.11 — the bot list, the scanner probes and the log attribution, in real WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_311_lists.php
 *
 * A5. "Allow AI search" wins over a bot list that still names its bots (OAI-SearchBot, ChatGPT-User…): never in
 *     PNCP_Options::blocked_agents() (WordPress, early and pre-cache checks, server rules, Bunny log import), the
 *     Bots tab warning with "Remove from the list" (nonce, manage_options, Lockdown, Earlier versions) and the
 *     one-time upgrade. Training crawlers stay.
 * A6. "Ban scanners on their first probe" for the non-WordPress probes (filter pncp_probe_paths).
 * A10. The Log names the bot list entry (generic HTTP library) that blocked a request, "Allow this service".
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
$saved_lock    = get_site_option( PNCP_Lockdown::OPTION, null );
$editor_id     = 0;
register_shutdown_function(
	static function () use ( $saved, $saved_backups, $saved_lock, &$editor_id ) {
		update_option( PNCP_OPTION, $saved );
		if ( null === $saved_backups ) {
			delete_option( PNCP_Settings_Io::BACKUPS );
		} else {
			update_option( PNCP_Settings_Io::BACKUPS, $saved_backups, false );
		}
		if ( null === $saved_lock ) {
			delete_site_option( PNCP_Lockdown::OPTION );
		} else {
			update_site_option( PNCP_Lockdown::OPTION, $saved_lock );
		}
		if ( $editor_id ) {
			wp_delete_user( $editor_id );
		}
		PNCP_Log::unban_all();
	}
);

update_option( 'pncp_emergency_until', 0 );
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'block_bots'              => 1,
		'require_browser_headers' => 0,
		'block_headless'          => 0,
		'verify_ai_bots'          => 0,
		'rate_limit'              => 0,
		'rate_limit_search'       => 0,
		'rate_limit_404'          => 0,
		'rate_limit_unverified'   => 0,
		'rate_limit_datacenter'   => 0,
		'rate_limit_apionly'      => 0,
		'human_check'             => 0,
		'block_ips'               => '',
		'allow_ips'               => '',
		'allow_list'              => '',
		'trust_any_proxy'         => 0,
		'trusted_proxies'         => '',
		'ip_header'               => 'remote_addr',
		'countries_block'         => '',
		'countries_strict'        => '',
		'block_http_libs'         => 0,
	)
);

$admin    = get_user_by( 'id', 1 );
$browser  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
$bots_tab = '/wp-admin/options-general.php?page=scrapelock&tab=bots';
$log_tab  = '/wp-admin/options-general.php?page=scrapelock&tab=log';
$editor_id = wp_insert_user(
	array(
		'user_login' => 'pncp_311_ed_' . wp_rand( 1000, 9999 ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'editor',
	)
);

/* ---------- A5. Allow AI search over the bot list ---------- */
$search_bots = array( 'OAI-SearchBot', 'ChatGPT-User', 'PerplexityBot', 'Perplexity-User', 'DuckAssistBot', 'MistralAI-User' );
$training    = array( 'GPTBot', 'ClaudeBot', 'CCBot', 'Google-Extended', 'Bytespider' );
$list        = implode( "\n", array_merge( $training, $search_bots, array( 'Claude-SearchBot', 'SomeScraper' ) ) );

settings(
	array(
		'bot_list'        => $list,
		'allow_ai_search' => 1,
	)
);
$s       = PNCP_Options::get();
$blocked = array_map( 'strtolower', PNCP_Options::blocked_agents( $s ) );
foreach ( $search_bots as $bot ) {
	t( "A5 precedence: $bot (in the bot list, AI search allowed) is not in blocked_agents()", ! in_array( strtolower( $bot ), $blocked, true ) );
	as_request( '198.51.100.31', 'Mozilla/5.0 (compatible; ' . $bot . '/1.0)' );
	t( "A5 precedence: $bot passes check()", 'pass' === verdict(), verdict() );
}
foreach ( $training as $bot ) {
	t( "A5 precedence: training crawler $bot stays blocked", in_array( strtolower( $bot ), $blocked, true ) );
}
as_request( '198.51.100.31', 'Mozilla/5.0 (compatible; GPTBot/1.2)' );
t( 'A5: GPTBot still gets 403 bot_ua', '403 bot_ua' === verdict(), verdict() );
t( 'A5: ai_search_in_bot_list() names the allowed bots in the list, not the training crawlers', array_merge( $search_bots, array( 'Claude-SearchBot' ) ) === PNCP_Options::ai_search_in_bot_list( $s ), implode( ',', PNCP_Options::ai_search_in_bot_list( $s ) ) );
$bunny = PNCP_Bunny::classify(
	array(
		'path'   => '/',
		'query'  => '',
		'status' => 200,
		'ua'     => 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot',
	),
	PNCP_Options::blocked_agents( $s )
);
t( 'A5: the Bunny log import no longer calls ChatGPT-User a "bad bot"', '' === $bunny, $bunny );
$nginx = PNCP_Rules::nginx_http();
t( 'A5: the Nginx bot map blocks GPTBot but not ChatGPT-User as a bot', preg_match( '/"~\*\([^"]*GPTBot[^"]*\)" 1;/', $nginx ) && ! preg_match( '/"~\*\([^"]*ChatGPT\\\\?-User[^"]*\)" 1;/', $nginx ) );
$pre = PNCP_Precheck::config();
t( 'A5: the pre-cache check gets no allowed AI search bot to block', isset( $pre['bots'] ) && ! array_intersect( array_map( 'strtolower', $search_bots ), (array) $pre['bots'] ) && in_array( 'gptbot', (array) $pre['bots'], true ) );

settings( array( 'allow_ai_search' => 0 ) );
$s = PNCP_Options::get();
t( 'A5: AI search off: the list blocks them again (ChatGPT-User in blocked_agents())', in_array( 'chatgpt-user', array_map( 'strtolower', PNCP_Options::blocked_agents( $s ) ), true ) );
t( 'A5: AI search off: nothing to remove', array() === PNCP_Options::ai_search_in_bot_list( $s ) );
as_request( '198.51.100.31', 'Mozilla/5.0 (compatible; ChatGPT-User/1.0)' );
t( 'A5: AI search off: ChatGPT-User gets 403 bot_ua', '403 bot_ua' === verdict(), verdict() );

// The Bots tab warning and the button.
settings( array( 'allow_ai_search' => 1 ) );
$cookies          = login_cookies( $admin->ID );
list( $code, $body ) = http( $bots_tab, '192.0.2.210', $browser, null, $cookies );
t( 'A5 UI: Bots tab 200 without PHP warnings', 200 === $code && ! php_errors( $body ), (string) $code );
t( 'A5 UI: the warning with the bots and the "Remove from the list" button', false !== strpos( $body, 'These AI search bots are in the bot list but AI search is allowed: they are let through' ) && false !== strpos( $body, 'OAI-SearchBot, ChatGPT-User, PerplexityBot' ) && false !== strpos( $body, 'id="pncp-ai-search-list-remove"' ) );

list( $code ) = http( '/wp-admin/admin-post.php', '192.0.2.210', $browser, array( 'action' => PNCP_Ai_Search_List::ACTION, '_wpnonce' => 'wrong' ), $cookies );
t( 'A5 UI: a wrong nonce is refused, the list stays', 403 === $code && PNCP_Options::ai_search_in_bot_list( reread() ), (string) $code );

$ed_cookies = login_cookies( $editor_id );
list( $code ) = http( '/wp-admin/admin-post.php', '192.0.2.211', $browser, array( 'action' => PNCP_Ai_Search_List::ACTION, '_wpnonce' => wp_create_nonce( PNCP_Ai_Search_List::ACTION ) ), $ed_cookies );
t( 'A5 UI: an editor (no manage_options) is refused, the list stays', 403 === $code && PNCP_Options::ai_search_in_bot_list( reread() ), (string) $code );

$cookies = login_cookies( $admin->ID );
/** A locked site for the requests between lock_site() and unlock_site() (the raw option: no authenticator needed). */
function lock_site() {
	update_site_option( PNCP_Lockdown::OPTION, array( 'locked' => 1, 'until' => 0 ) );
}
function unlock_site() {
	global $saved_lock;
	if ( null === $saved_lock ) {
		delete_site_option( PNCP_Lockdown::OPTION );
	} else {
		update_site_option( PNCP_Lockdown::OPTION, $saved_lock );
	}
}
lock_site();
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.210', $browser, array( 'action' => PNCP_Ai_Search_List::ACTION, '_wpnonce' => wp_create_nonce( PNCP_Ai_Search_List::ACTION ) ), $cookies );
unlock_site();
t( 'A5 UI: while the site is locked nothing changes', ( 403 === $code || false !== strpos( $loc, 'pncp_message=ai_search_list_error' ) ) && PNCP_Options::ai_search_in_bot_list( reread() ), $code . ' ' . $loc );

$backups_before = count( PNCP_Settings_Io::backups() );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.210', $browser, array( 'action' => PNCP_Ai_Search_List::ACTION, '_wpnonce' => wp_create_nonce( PNCP_Ai_Search_List::ACTION ) ), $cookies );
$after = reread();
t( 'A5 UI: "Remove from the list" removes them and goes back to the Bots tab', 302 === $code && false !== strpos( $loc, 'pncp_message=ai_search_list_removed' ) && array() === PNCP_Options::ai_search_in_bot_list( $after ), $code . ' ' . $loc );
t( 'A5 UI: the training crawlers and other lines stay, in order', implode( "\n", array_merge( $training, array( 'SomeScraper' ) ) ) === $after['bot_list'], $after['bot_list'] );
$backups = PNCP_Settings_Io::backups();
t( 'A5 UI: an earlier version was saved first (with the old list)', count( $backups ) === min( 5, $backups_before + 1 ) && PNCP_Ai_Search_List::BACKUP_REASON === $backups[0]['reason'] && $list === $backups[0]['settings']['bot_list'] );
t( 'A5 UI: the earlier version has a readable label', 'Before removing the allowed AI search bots from the bot list' === PNCP_Settings_Io::reason_label( $backups[0] ) );
list( $code, $body ) = http( $bots_tab . '&pncp_message=ai_search_list_removed', '192.0.2.210', $browser, null, $cookies );
t( 'A5 UI: no warning any more, and the notice', false === strpos( $body, 'pncp-ai-search-list-notice' ) && false !== strpos( $body, 'The AI search bots were removed from the bot list.' ) && ! php_errors( $body ) );

// The one-time upgrade (pncp_upgrade() from a version before 3.11.0).
wp_set_current_user( 0 );
settings(
	array(
		'bot_list'        => $list,
		'allow_ai_search' => 1,
	)
);
$version = get_option( 'pncp_version' );
update_option( 'pncp_version', '3.10.1' );
pncp_upgrade();
$after = reread();
t( 'A5 upgrade from 3.10.1 with AI search on: removed from the stored list', array() === PNCP_Options::ai_search_in_bot_list( $after ) && false === stripos( $after['bot_list'], 'ChatGPT-User' ), $after['bot_list'] );
t( 'A5 upgrade: the training crawlers stay', false !== strpos( $after['bot_list'], 'GPTBot' ) && false !== strpos( $after['bot_list'], 'Bytespider' ) && false !== strpos( $after['bot_list'], 'Google-Extended' ) );
settings(
	array(
		'bot_list'        => $list,
		'allow_ai_search' => 0,
	)
);
update_option( 'pncp_version', '3.10.1' );
pncp_upgrade();
$after = reread();
t( 'A5 upgrade with AI search off: the list is left as it is', $list === $after['bot_list'], $after['bot_list'] );
update_option( 'pncp_version', $version );
settings(
	array(
		'bot_list'        => $saved['bot_list'],
		'allow_ai_search' => $saved['allow_ai_search'],
	)
);

/* ---------- A6. Scanner probes of other software ---------- */
// The filter first (the list is built once per request).
$extra_probe = static function ( $paths ) {
	$paths[] = '/pncp-test-probe.cfg';
	$paths[] = '/*';
	return $paths;
};
add_filter( 'pncp_probe_paths', $extra_probe );
t( 'A6 filter: an added path is on the list', PNCP_Probe::matches( '/pncp-test-probe.cfg' ) );
t( 'A6 filter: a too broad path ("/*") is dropped, not the whole list', ! PNCP_Probe::matches( '/hello-world/' ) && ! PNCP_Probe::matches( '/' ) && PNCP_Probe::matches( '/Dockerfile' ) );

$new_probes = array( '/actuator/env', '/actuator/health', '/admin/auth.json', '/Dockerfile', '/railway.toml', '/payment_gateways/stripe.yaml', '/config/parameters.yml', '/credentials.yml', '/credentials.json', '/secrets', '/www.git/config', '/wp-conflg.php', '/.env.production' );
foreach ( $new_probes as $p ) {
	t( "A6: $p is a probe (PNCP_Probe and the Log / attack record)", PNCP_Probe::matches( $p ) && PNCP_Log::is_probe_path( $p ) );
}
foreach ( array( '/', '/hello-world/', '/actuators-guide/', '/secrets-of-greek-cooking/', '/wp-config.php', '/.well-known/security.txt', '/favicon.ico', '/apple-touch-icon.png' ) as $p ) {
	t( "A6: $p is not a probe", ! PNCP_Probe::matches( $p ) );
}

settings(
	array(
		'probe_ban'   => 1,
		'ban_strikes' => 3,
		'ban_minutes' => 60,
		'bot_list'    => $saved['bot_list'],
	)
);
PNCP_Log::unban_all();
$scanner = 'zgrab/0.x'; // Not "Mozilla/": a browser without Sec-Fetch is banned only on its third probe.
$n       = 10;
foreach ( $new_probes as $p ) {
	$ip = '198.51.100.' . ( 100 + ( ++$n ) );
	list( $code ) = http( $p, $ip, $scanner );
		t( "A6 HTTP: $p (404 on this site) gets 403 and a ban", 403 === $code && banned( $ip ), $code . ' ' . ( banned( $ip ) ? 'banned' : 'not banned' ) );
	PNCP_Log::unban( $ip );
}

// A page at that address: WordPress answers 200, nothing is banned.
$page_id = wp_insert_post(
	array(
		'post_type'    => 'page',
		'post_status'  => 'publish',
		'post_title'   => 'Secrets',
		'post_name'    => 'secrets',
		'post_content' => 'Our secrets page.',
	)
);
$ip           = '198.51.100.150';
list( $code ) = http( '/secrets/', $ip, $scanner );
t( 'A6 HTTP: /secrets/ when the site has that page: 200, no ban', 200 === $code && ! banned( $ip ), $code . ( banned( $ip ) ? ' banned' : '' ) );
t( 'A6: /secrets/ with a page there is not a probe in the Log', ! PNCP_Log::is_probe_path( '/secrets/' ) );
wp_delete_post( $page_id, true );

// A real file of that name: never banned.
$real = ABSPATH . 'railway.toml';
$made = ! file_exists( $real ) && false !== file_put_contents( $real, "[build]\n" );
$ip           = '198.51.100.151';
list( $code ) = http( '/railway.toml', $ip, $scanner );
t( 'A6 HTTP: /railway.toml that exists: no ban', $made && ! banned( $ip ), $code . ( banned( $ip ) ? ' banned' : '' ) );
if ( $made ) {
	unlink( $real );
}

// Staff and verified search engines.
$cookies      = login_cookies( $admin->ID );
$ip           = '198.51.100.152';
list( $code ) = http( '/actuator/env', $ip, $browser, null, $cookies );
t( 'A6 HTTP: staff asking for /actuator/env: not banned', ! banned( $ip ), (string) $code );
wp_set_current_user( 0 );
$google_list = get_option( PNCP_Ip::LISTS_OPTION . '_google', null );
PNCP_Ip::store_list( 'google', array( '66.249.64.0/27' ) );
$ip           = '66.249.64.9';
list( $code ) = http( '/Dockerfile', $ip, 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' );
t( 'A6 HTTP: verified Googlebot asking for /Dockerfile: not banned', ! banned( $ip ), (string) $code );
if ( null === $google_list ) {
	delete_option( PNCP_Ip::LISTS_OPTION . '_google' );
} else {
	update_option( PNCP_Ip::LISTS_OPTION . '_google', $google_list );
}
settings( array( 'probe_ban' => 0 ) );
$ip           = '198.51.100.153';
list( $code ) = http( '/Dockerfile', $ip, $scanner );
t( 'A6 HTTP: with "Ban scanners on their first probe" off: no ban (404)', 404 === $code && ! banned( $ip ), (string) $code );
settings(
	array(
		'probe_ban'   => $saved['probe_ban'],
		'ban_strikes' => $saved['ban_strikes'],
		'ban_minutes' => $saved['ban_minutes'],
	)
);
PNCP_Log::unban_all();

/* ---------- A10. The bot list entry in the Log, "Allow this service" ---------- */
settings(
	array(
		'block_http_libs' => 1,
		'bot_list'        => $saved['bot_list'],
		'allow_list'      => '',
	)
);
PNCP_Log::clear();
$py   = 'python-requests/2.31.0';
$ok   = 'MyShopApp/3.2 okhttp/4.9.2';
$ip   = '198.51.100.160';
list( $code ) = http( '/', $ip, $py );
t( 'A10: python-requests with "Also block generic HTTP libraries": 403', 403 === $code, (string) $code );
$s     = PNCP_Options::get();
$entry = PNCP_Bot_Match::entry( $py, $s );
t( 'A10: entry() names the library token and its source', is_array( $entry ) && 'python-requests' === $entry['token'] && 'http_libs' === $entry['source'] && $entry['http_lib'], wp_json_encode( $entry ) );
$entry = PNCP_Bot_Match::entry( $ok, $s );
t( 'A10: entry() for okhttp inside an app User-Agent', is_array( $entry ) && 'okhttp' === strtolower( rtrim( $entry['token'], '/' ) ) && $entry['http_lib'], wp_json_encode( $entry ) );
$entry = PNCP_Bot_Match::entry( 'Mozilla/5.0 (compatible; GPTBot/1.2)', $s );
t( 'A10: entry() for GPTBot: not a library', is_array( $entry ) && 'GPTBot' === $entry['token'] && ! $entry['http_lib'], wp_json_encode( $entry ) );
foreach ( array( $ok => '198.51.100.161', 'Mozilla/5.0 (compatible; GPTBot/1.2)' => '198.51.100.162' ) as $row_ua => $row_ip ) {
	PNCP_Log::insert(
		array(
			'time'   => time(),
			'ip'     => $row_ip,
			'reason' => 'bot_ua',
			'code'   => 403,
			'hits'   => 3,
			'path'   => '/',
			'ua'     => $row_ua,
		)
	);
}
$cookies          = login_cookies( $admin->ID );
list( $code, $body ) = http( $log_tab, '192.0.2.210', $browser, null, $cookies );
t( 'A10 UI: Log tab 200 without PHP warnings', 200 === $code && ! php_errors( $body ), (string) $code );
t( 'A10 UI: the reason is kept ("User-Agent in the bot list")', false !== strpos( $body, 'User-Agent in the bot list (403)' ) );
t( 'A10 UI: the library that matched is named', false !== strpos( $body, 'Matched “python-requests”: a generic HTTP library (“Also block generic HTTP libraries”)' ) && false !== strpos( $body, 'data-token="okhttp' ) );
t( 'A10 UI: GPTBot is named as a bot list entry, not a library', false !== strpos( $body, 'Matched “GPTBot” (your bot list)' ) );
t( 'A10 UI: "Allow this service" for the library rows only (2), with the whole User-Agent', 2 === substr_count( $body, 'pncp-allow-service-form' ) && false !== strpos( $body, 'name="ua" value="' . esc_attr( $py ) . '"' ) && false !== strpos( $body, 'name="ua" value="' . esc_attr( $ok ) . '"' ) );
t( 'A10 UI: the existing "Always allow this User-Agent" button stays', false !== strpos( $body, 'Always allow this User-Agent' ) );

$post = array(
	'action'   => PNCP_Bot_Match::ACTION,
	'ua'       => $py,
	'_wpnonce' => 'wrong',
);
list( $code ) = http( '/wp-admin/admin-post.php', '192.0.2.210', $browser, $post, $cookies );
t( 'A10 security: a wrong nonce is refused, nothing added', 403 === $code && '' === reread()['allow_list'], (string) $code );
$ed_cookies       = login_cookies( $editor_id );
$post['_wpnonce'] = wp_create_nonce( PNCP_Bot_Match::ACTION );
list( $code ) = http( '/wp-admin/admin-post.php', '192.0.2.211', $browser, $post, $ed_cookies );
t( 'A10 security: an editor (no manage_options) is refused, nothing added', 403 === $code && '' === reread()['allow_list'], (string) $code );
$cookies          = login_cookies( $admin->ID );
$post['_wpnonce'] = wp_create_nonce( PNCP_Bot_Match::ACTION );
lock_site();
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.210', $browser, $post, $cookies );
unlock_site();
t( 'A10 security: while the site is locked nothing is added', ( 403 === $code || false !== strpos( $loc, 'allow_service_locked' ) ) && '' === reread()['allow_list'], $code . ' ' . $loc );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.210', $browser, array_merge( $post, array( 'ua' => 'Mozilla/5.0 (compatible; GPTBot/1.2)' ) ), $cookies );
t( 'A10: a User-Agent not blocked by a library is refused', false !== strpos( $loc, 'pncp_message=allow_service_refused' ) && '' === reread()['allow_list'], $loc );

$backups_before = count( PNCP_Settings_Io::backups() );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.210', $browser, $post, $cookies );
$after = reread();
t( 'A10: "Allow this service" adds the whole User-Agent', 302 === $code && false !== strpos( $loc, 'pncp_message=allow_service_added' ) && $py === $after['allow_list'], $code . ' ' . $loc . ' ' . $after['allow_list'] );
$backups = PNCP_Settings_Io::backups();
t( 'A10: an earlier version was saved first', count( $backups ) === min( 5, $backups_before + 1 ) && PNCP_Bot_Match::BACKUP_REASON === $backups[0]['reason'] && '' === $backups[0]['settings']['allow_list'] && 'Before allowing a service from the Log' === PNCP_Settings_Io::reason_label( $backups[0] ) );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', '192.0.2.210', $browser, $post, $cookies );
t( 'A10: a second click: "already allowed", no second line', false !== strpos( $loc, 'pncp_message=allow_service_exists' ) && $py === reread()['allow_list'], $loc );
list( $code, $body ) = http( $log_tab . '&pncp_message=allow_service_added', '192.0.2.210', $browser, null, $cookies );
t( 'A10 UI: the notice, and no button any more for the allowed User-Agent', false !== strpos( $body, 'The service&#039;s User-Agent was added' ) && false === strpos( $body, 'name="ua" value="' . esc_attr( $py ) . '"' ) && ! php_errors( $body ) );
wp_set_current_user( 0 );
list( $code ) = http( '/', '198.51.100.163', $py );
t( 'A10: that service passes now', 200 === $code, (string) $code );
list( $code ) = http( '/', '198.51.100.164', 'python-requests/2.30.0' );
t( 'A10: another python-requests client is still blocked', 403 === $code, (string) $code );
settings(
	array(
		'block_http_libs' => $saved['block_http_libs'],
		'allow_list'      => $saved['allow_list'],
	)
);
PNCP_Log::clear();

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
