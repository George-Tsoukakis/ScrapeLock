<?php
/**
 * ScrapeLock 3.12.1 — "Check a request" (PNCP_Tester) and the reason labels everywhere in wp-admin, in real
 * WordPress:
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3121_tester.php
 *
 * B1. An image (and video, font, CSS, JS) is "Checked as: Media", allowed as "image or file; counted in the media
 *     limit, not as a page", with the media counter and its limit (MEDIA_FACTOR × the page limit) as
 *     "N of M this minute"; over that limit it is "Limited (429)" with the media limit's own label.
 * B2. A page, a feed, a REST call and every pass / refuse reason the check can produce: the answer, drawn as
 *     assets/js/tester.js draws it, never shows a raw snake_case reason key; an unknown reason gets a label too.
 * B3. Over HTTP: the AJAX answer for an image, and every wp-admin tab with log rows and bans of every reason (and
 *     one stored by another version): no raw reason key in the visible text, no "Allowed: media", no "/ media".
 * B4. "wp scrapelock check" (WP_CLI given): Media, the label and the counter for an image.
 *
 * Settings, lists, the log and the bans are put back at the end. Only on a test WordPress.
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

/** Waits for the next minute when fewer than 20 seconds are left (the counters are per minute). */
function same_minute() {
	$left = 60 - time() % 60;
	if ( $left < 20 ) {
		sleep( $left + 1 );
	}
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

/** The answer of the check drawn as assets/js/tester.js draws it (every value as text). */
function draw( $d ) {
	$e   = static function ( $v ) {
		return htmlspecialchars( (string) $v, ENT_QUOTES );
	};
	$out = '<p class="pncp-tester__headline"><span>' . $e( $d['badge'] ) . '</span> <strong>' . $e( $d['headline'] ) . '</strong></p>';
	$out .= '<p class="pncp-tester__why">' . $e( $d['why'] ) . ( ! empty( $d['link']['label'] ) ? ' <a>' . $e( $d['link']['label'] ) . '</a>' : '' ) . '</p>';
	if ( $d['notes'] ) {
		$out .= '<ul>';
		foreach ( $d['notes'] as $n ) {
			$out .= '<li>' . $e( $n ) . '</li>';
		}
		$out .= '</ul>';
	}
	$out .= '<table><tr><th>Checked as</th><td>' . $e( $d['checked_as_label'] ) . '</td></tr>';
	if ( ! empty( $d['counter'] ) ) {
		$out .= '<tr><th>' . $e( $d['counter']['label'] ) . '</th><td>' . $e( $d['counter']['text'] ) . '</td></tr>';
	}
	$out .= '<tr><th>IP</th><td>' . $e( $d['request']['ip'] ) . '</td></tr><tr><th>User-Agent</th><td>' . $e( $d['request']['ua'] ) . '</td></tr>';
	$out .= '<tr><th>Address</th><td>' . $e( $d['request']['address'] ) . '</td></tr></table>';
	return $out;
}

/** The visible text of an HTML page: no scripts, styles, tags or attributes. */
function visible( $html ) {
	$html = (string) preg_replace( '#<(script|style|textarea|template)\b[^>]*>.*?</\1>#is', ' ', (string) $html );
	return html_entity_decode( (string) preg_replace( '/\s+/', ' ', wp_strip_all_tags( $html ) ), ENT_QUOTES );
}

/** The internal keys that must never be shown: every reason, pass and limit key with an underscore. */
function raw_keys() {
	$keys = array_merge( array_keys( PNCP_Log::reasons() ), array_keys( PNCP_Tester::pass_reasons() ), array( 'future_reason_x' ) );
	return array_values(
		array_filter(
			array_unique( $keys ),
			static function ( $k ) {
				return false !== strpos( $k, '_' );
			}
		)
	);
}

/** The raw keys found in a text ('' = none). */
function raw_in( $text, $any = true ) {
	$found = array();
	foreach ( raw_keys() as $k ) {
		if ( preg_match( '/(?<![A-Za-z0-9_-])' . preg_quote( $k, '/' ) . '(?![A-Za-z0-9_-])/', $text ) ) {
			$found[] = $k;
		}
	}
	// Any other snake_case word, except the names of filters (pncp_…) a text may name for developers.
	if ( $any && preg_match_all( '/(?<![A-Za-z0-9_\/.-])[a-z]+_[a-z0-9_]+(?![A-Za-z0-9_\/.-])/', $text, $m ) ) {
		foreach ( $m[0] as $w ) {
			if ( 0 !== strpos( $w, 'pncp_' ) ) {
				$found[] = $w;
			}
		}
	}
	return implode( ',', array_unique( $found ) );
}

/** A session of a user: cookies and the "Check a request" nonce of that session. */
function session_of( $user_id ) {
	$expire  = time() + DAY_IN_SECONDS;
	$token   = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	$cookies = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
	$prev                        = isset( $_COOKIE[ LOGGED_IN_COOKIE ] ) ? $_COOKIE[ LOGGED_IN_COOKIE ] : null;
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	$nonce = wp_create_nonce( PNCP_Tester::ACTION );
	if ( null === $prev ) {
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	} else {
		$_COOKIE[ LOGGED_IN_COOKIE ] = $prev;
	}
	wp_set_current_user( 0 );
	return array( $cookies, $nonce );
}

/** An HTTP request as a signed-in user: [code, body]. */
function http( $path, $cookies, $post = null ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.212', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0 Safari/537.36', 'Accept-Language: en' ),
		CURLOPT_TIMEOUT        => 90,
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = http_build_query( $post );
	}
	curl_setopt_array( $ch, $opts );
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

/* ---------- Setup ---------- */
$saved     = PNCP_Options::stored();
$lists     = array();
$list_keys = array( 'google', 'openai_search' );
foreach ( $list_keys as $l ) {
	$lists[ $l ] = get_option( PNCP_Ip::LISTS_OPTION . '_' . $l, null );
}
register_shutdown_function(
	static function () use ( $saved, $lists ) {
		update_option( PNCP_OPTION, $saved );
		PNCP_Options::flush();
		foreach ( $lists as $l => $v ) {
			if ( null === $v ) {
				delete_option( PNCP_Ip::LISTS_OPTION . '_' . $l );
			} else {
				update_option( PNCP_Ip::LISTS_OPTION . '_' . $l, $v );
			}
		}
		PNCP_Log::unban_all();
		PNCP_Log::clear();
	}
);
// WP cron (internet on in CI) must not download the real lists over the test lists.
wp_unschedule_hook( PNCP_Ip::CRON );
set_transient( 'pncp_lists_missing_try', 1, HOUR_IN_SECONDS );
PNCP_Ip::store_list( 'google', array( '66.249.64.0/19' ) );
PNCP_Ip::store_list( 'openai_search', array( '20.42.10.176/28' ) );

update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
PNCP_Log::unban_all();
PNCP_Log::clear();
$base_settings = array(
	'enabled'                 => 1,
	'monitor_mode'            => 0,
	'monitor_until'           => 0,
	'block_bots'              => 1,
	'bot_list'                => PNCP_Options::default_bot_list(), // An earlier test may have changed it.
	'allow_list'              => PNCP_Options::default_allow_list(),
	'block_empty_ua'          => 1,
	'require_browser_headers' => 1,
	'block_headless'          => 1,
	'block_fake_crawlers'     => 1,
	'block_http_libs'         => 0,
	'allow_ai_search'         => 1,
	'verify_ai_bots'          => 1,
	'rate_limit'              => 60,
	'rate_limit_search'       => 30,
	'rate_limit_rest'         => 60,
	'rate_limit_sitemap'      => 0,
	'rate_limit_404'          => 0,
	'rate_limit_unverified'   => 0,
	'rate_limit_datacenter'   => 0,
	'rate_limit_apionly'      => 0,
	'rate_limit_lowrep'       => 0,
	'human_check'             => 0,
	'reputation'              => 0,
	'ban_strikes'             => 0,
	'block_ips'               => '198.51.100.66',
	'block_referrers'         => 'spam.example',
	'allow_ips'               => '198.51.100.77',
	'trust_any_proxy'         => 0,
	'countries_block'         => '',
	'countries_strict'        => '',
	'crowdsec_mode'           => 'off',
	'private_paths'           => '',
	'auto_emergency'          => 0,
	'block_ip_host'           => 0,
);
settings( $base_settings );
wp_set_current_user( 1 );

$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
$check  = static function ( $ip, $ua, $address, $browser = true, $extra = array() ) {
	return PNCP_Tester::run(
		array_merge(
			array(
				'mode'    => 'custom',
				'ip'      => $ip,
				'ua'      => $ua,
				'address' => $address,
				'browser' => $browser ? '1' : '',
			),
			$extra
		)
	);
};

/* ---------- B1: static files ---------- */
same_minute();
$img = $check( '198.51.100.11', $chrome, '/wp-content/uploads/2026/11/photo.webp' );
t( 'B1 image: allowed', 'allowed' === $img['verdict'] && 'media' === $img['pass'], $img['verdict'] . ' ' . $img['pass'] );
t( 'B1 image: "Allowed: image or file; counted in the media limit, not as a page"', 'Allowed: image or file; counted in the media limit, not as a page' === $img['headline'], $img['headline'] );
t( 'B1 image: checked as Media, not Page', 'media' === $img['checked_as'] && 'Media' === $img['checked_as_label'], $img['checked_as'] . ' / ' . $img['checked_as_label'] );
$want = PNCP_Bots::MEDIA_FACTOR * 60;
t( 'B1 image: the media counter and its limit (MEDIA_FACTOR x the page limit): "1 of ' . $want . ' this minute"', is_array( $img['counter'] ) && 'rate_media' === $img['counter']['bucket'] && $want === $img['counter']['limit'] && 1 === $img['counter']['count'] && '1 of ' . number_format_i18n( $want ) . ' this minute' === $img['counter']['text'] && PNCP_Log::reasons()['rate_media'] === $img['counter']['label'], wp_json_encode( $img['counter'] ) );
t( 'B1 image: the why names the media limit, not "media"', 'media' !== $img['why'] && false !== strpos( $img['why'], (string) PNCP_Bots::MEDIA_FACTOR . ' times the page limit' ), $img['why'] );
foreach ( array( '/v.mp4', '/song.mp3', '/f/font.woff2', '/wp-includes/css/x.css', '/wp-includes/js/x.js' ) as $file ) {
	$r = $check( '198.51.100.11', $chrome, $file );
	t( "B1 $file: checked as Media", 'media' === $r['checked_as'] && 'media' === $r['pass'], $r['checked_as'] . ' ' . $r['pass'] );
}
// The filter of the static extensions decides too.
add_filter(
	'pncp_static_extensions',
	static function ( $ext ) {
		$ext[] = 'jxr';
		return $ext;
	}
);
$r = $check( '198.51.100.11', $chrome, '/x/photo.jxr' );
t( 'B1 an extension added by pncp_static_extensions: Media', 'media' === $r['checked_as'], $r['checked_as'] );
remove_all_filters( 'pncp_static_extensions' );
// Counted media files of this minute show in the counter; over the limit: 429 with the media limit's label.
settings( array( 'rate_limit' => 1 ) );
same_minute();
// Counted as a visitor (logged out) would be: REMOTE_ADDR is the visitor (a new one each run: the counters last a minute).
$cip = '198.51.100.' . wp_rand( 130, 250 );
as_request( $cip, $chrome, array( 'HTTP_ACCEPT_LANGUAGE' => 'en' ), '/wp-content/uploads/p.webp' );
wp_set_current_user( 0 );
for ( $i = 0; $i < 4; $i++ ) {
	PNCP_Bots::check( 'page', true );
}
wp_set_current_user( 1 );
$r = $check( $cip, $chrome, '/wp-content/uploads/p.webp' );
t( 'B1 four images counted: "5 of 10 this minute"', is_array( $r['counter'] ) && 5 === $r['counter']['count'] && 10 === $r['counter']['limit'], wp_json_encode( $r['counter'] ) );
wp_set_current_user( 0 );
for ( $i = 0; $i < 6; $i++ ) {
	PNCP_Bots::check( 'page', true );
}
wp_set_current_user( 1 );
$r = $check( $cip, $chrome, '/wp-content/uploads/p.webp' );
t( 'B1 over the media limit: Limited (429) with the media limit\'s label', 'limited' === $r['verdict'] && 'rate_media' === $r['reason'] && false !== strpos( $r['headline'], PNCP_Log::reasons()['rate_media'] ), $r['headline'] );
t( 'B1 over the media limit: the counter "11 of 10" and a why about static files', is_array( $r['counter'] ) && 11 === $r['counter']['count'] && false !== strpos( $r['why'], 'static files' ), wp_json_encode( $r['counter'] ) . ' ' . $r['why'] );
$page = $check( $cip, $chrome, '/' );
t( 'B1 the images did not count as pages: a page still passes, "1 of 1"', 'passed' === $page['pass'] && 'rate_page' === $page['counter']['bucket'] && 1 === $page['counter']['count'], wp_json_encode( $page['counter'] ) );
$drawn = array( 'image' => draw( $img ), 'image over the limit' => draw( $r ) );
settings( array( 'rate_limit' => 60 ) );

/* ---------- B2: page, feed, REST and every reason ---------- */
// With internet (CI), WP cron may have downloaded the real lists meanwhile: the test lists again.
wp_unschedule_hook( PNCP_Ip::CRON );
set_transient( 'pncp_lists_missing_try', 1, HOUR_IN_SECONDS );
PNCP_Ip::store_list( 'google', array( '66.249.64.0/19' ) );
PNCP_Ip::store_list( 'openai_search', array( '20.42.10.176/28' ) );
PNCP_Ip::reset();
PNCP_Log::ban( '198.51.100.55', 30, 'rate_page' );
$cases = array(
	// label => [ settings, ip, ua, address, browser, extra headers, expected pass or reason ].
	'page'          => array( array(), '198.51.100.20', $chrome, '/', true, array(), 'passed' ),
	'feed'          => array( array(), '198.51.100.20', 'Feedly/1.0', '/feed/', false, array(), 'passed' ),
	'REST call'     => array( array(), '198.51.100.20', 'python-requests/2.32.3', '/wp-json/wp/v2/posts', false, array(), 'passed' ),
	'search'        => array( array(), '198.51.100.20', $chrome, '/?s=shoes', true, array(), 'passed' ),
	'off'           => array( array( 'enabled' => 0 ), '198.51.100.20', 'GPTBot/1.2', '/', false, array(), 'off' ),
	'open_path'     => array( array(), '198.51.100.20', 'GPTBot/1.2', '/robots.txt', false, array(), 'open_path' ),
	'local'         => array( array(), '127.0.0.1', 'GPTBot/1.2', '/', false, array(), 'local' ),
	'allow_ip'      => array( array( 'trusted_proxies' => '' ), '198.51.100.77', 'GPTBot/1.2', '/', false, array(), 'allow_ip' ),
	'search_engine' => array( array(), '66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', '/', false, array(), 'search_engine' ),
	'ai_search'     => array( array(), '20.42.10.180', 'Mozilla/5.0; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot', '/', false, array(), 'ai_search' ),
	'bot_ua'        => array( array(), '198.51.100.21', 'Mozilla/5.0; compatible; GPTBot/1.2; +https://openai.com/gptbot', '/', false, array(), 'bot_ua' ),
	'empty_ua'      => array( array(), '198.51.100.21', '', '/', false, array(), 'empty_ua' ),
	'fake_crawler'  => array( array(), '198.51.100.21', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', '/', false, array(), 'fake_crawler' ),
	'fake_ai_bot'   => array( array(), '198.51.100.21', 'Mozilla/5.0; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot', '/', false, array(), 'fake_ai_bot' ),
	'no_browser'    => array( array(), '198.51.100.21', 'python-requests/2.32.3', '/', false, array(), 'no_browser' ),
	// "Your own request": the headers of this request (Sec-CH-UA, Accept-Language) are the ones checked.
	'headless'      => array( array(), '198.51.100.21', $chrome, '/', false, array( 'HTTP_ACCEPT_LANGUAGE' => 'en', 'HTTP_SEC_CH_UA' => '"HeadlessChrome";v="131"', 'HTTP_SEC_FETCH_MODE' => 'cors' ), 'headless' ),
	'fake_browser'  => array( array(), '198.51.100.21', $chrome, home_url( '/', 'https' ), false, array( 'HTTP_ACCEPT_LANGUAGE' => 'en' ), 'fake_browser' ),
	'blocked_ip'    => array( array(), '198.51.100.66', $chrome, '/', true, array(), 'blocked_ip' ),
	'blocked_ref'   => array( array(), '198.51.100.21', $chrome, '/', true, array( 'Referer' => 'https://spam.example/x' ), 'blocked_ref' ),
	'banned'        => array( array(), '198.51.100.55', $chrome, '/', true, array(), 'banned' ),
	'bad_ua'        => array( array(), '198.51.100.21', 'Mozilla/5.0 <script>alert(1)</script>', '/', true, array(), 'bad_ua' ),
);
foreach ( $cases as $label => $c ) {
	settings( array_merge( $base_settings, $c[0] ) );
	$extra = array();
	if ( isset( $c[5]['Referer'] ) ) {
		$extra['referer'] = $c[5]['Referer'];
	}
	if ( $c[5] && ! isset( $c[5]['Referer'] ) ) {
		as_request( $c[1], $c[2], $c[5], '/wp-admin/admin-ajax.php' );
		$extra['mode'] = 'self';
	}
	$d   = $check( $c[1], $c[2], $c[3], $c[4], $extra );
	$got = $d['code'] ? $d['reason'] : $d['pass'];
	t( "B2 $label: the check gives $c[6]", $got === $c[6], $got . ' ' . $d['headline'] );
	$drawn[ $label ] = draw( $d );
}
settings( $base_settings );
// The limits and the other refusals the check can give have a label for people too.
$labels = PNCP_Log::reasons();
foreach ( array( 'headless', 'fake_browser', 'country', 'crowdsec', 'host_ip', 'rate_page', 'rate_media', 'rate_search', 'rate_rest', 'rate_prefetch', 'rate_unverified', 'rate_country', 'rate_datacenter', 'rate_lowrep', 'rate_apionly', 'rate_crowdsec', 'rate_page56', 'rate_account', 'rate_404' ) as $reason ) {
	t( "B2 $reason: a label for people", isset( $labels[ $reason ] ) && PNCP_Log::reason_label( $reason ) === $labels[ $reason ], PNCP_Log::reason_label( $reason ) );
}
t( 'B2 a reason stored by another version: a generic label, not the key', 'Another check of ScrapeLock' === PNCP_Log::reason_label( 'future_reason_x' ), PNCP_Log::reason_label( 'future_reason_x' ) );
// Every pass reason of the card has a label, and so has every reason of the log.
$passes = PNCP_Tester::pass_reasons();
t( 'B2 the card has a label for every pass of explain(), "media" included', isset( $passes['media'], $passes['passed'], $passes['prefetch'], $passes['ai_search'] ), implode( ',', array_keys( $passes ) ) );
$bad = array();
foreach ( $drawn as $label => $html ) {
	$found = raw_in( visible( $html ) );
	if ( '' !== $found || false !== stripos( visible( $html ), 'Allowed: media' ) || preg_match( '#/ media\b#', visible( $html ) ) ) {
		$bad[] = $label . ': ' . $found . ' ' . substr( visible( $html ), 0, 160 );
	}
}
t( 'B2 ' . count( $drawn ) . ' answers drawn (image, page, feed, REST, every reason): no raw snake_case reason key, no "Allowed: media", no "/ media"', ! $bad && count( $drawn ) >= 18, implode( ' | ', $bad ) );

/* ---------- B3: over HTTP ---------- */
list( $cookies, $nonce ) = session_of( 1 );
same_minute();
list( $code, $body ) = http(
	'/wp-admin/admin-ajax.php',
	$cookies,
	array(
		'action'  => PNCP_Tester::ACTION,
		'nonce'   => $nonce,
		'mode'    => 'custom',
		'ip'      => '198.51.100.13',
		'ua'      => $chrome,
		'address' => '/wp-content/uploads/a.jpg',
		'browser' => '1',
	)
);
$json = json_decode( $body, true );
$data = is_array( $json ) && ! empty( $json['success'] ) ? $json['data'] : array();
t( 'B3 AJAX: an image is checked as Media with the media counter', 200 === $code && isset( $data['checked_as_label'] ) && 'Media' === $data['checked_as_label'] && 'rate_media' === $data['counter']['bucket'], $code . ' ' . substr( $body, 0, 300 ) );
t( 'B3 AJAX: drawn, no raw key', $data && '' === raw_in( visible( draw( $data ) ) ), $data ? raw_in( visible( draw( $data ) ) ) : '' );
// The tester's script draws the counter row.
$js = (string) file_get_contents( dirname( __DIR__ ) . '/assets/js/tester.js' );
t( 'B3 tester.js draws the counter row (its label and "N of M this minute")', false !== strpos( $js, 'data.counter.label' ) && false !== strpos( $js, 'data.counter.text' ) );

// A log row and a ban of every reason (and one stored by another version), then every tab as the administrator.
PNCP_Log::clear();
$now = time();
$i   = 0;
foreach ( array_merge( array_keys( PNCP_Log::reasons() ), array( 'future_reason_x' ) ) as $reason ) {
	++$i;
	PNCP_Log::insert(
		array(
			'time'   => $now - $i,
			'code'   => 0 === strpos( $reason, 'rate_' ) ? 429 : 403,
			'reason' => $reason,
			'ip'     => '203.0.113.' . ( $i % 250 + 1 ),
			'path'   => '/p-' . $i . '/',
			'ua'     => 'TestAgent/' . $i,
			'hits'   => 1,
		)
	);
}
foreach ( array( 'rate_page', 'rate_media', 'fake_ai_bot', 'edge_rate', 'login', 'future_reason_x' ) as $k => $reason ) {
	PNCP_Log::import_ban( '192.0.2.' . ( 100 + $k ), $now + HOUR_IN_SECONDS, $reason, $now );
}
PNCP_Log::flush_aggregates();
$tabs = array( 'general', 'bots', 'content', 'images', 'rules', 'log', 'traffic', 'attacks', 'hardening', 'lockdown' );
$bad  = array();
$ok   = 0;
foreach ( $tabs as $tab ) {
	list( $code, $body ) = http( '/wp-admin/options-general.php?page=' . PNCP_Admin::PAGE . '&tab=' . $tab, $cookies );
	if ( 200 !== $code ) {
		$bad[] = $tab . ' ' . $code;
		continue;
	}
	++$ok;
	$text  = visible( $body );
	// The tabs name filters, cookies, PHP settings and REST arguments for developers: only the reason keys here.
	$found = raw_in( $text, false );
	if ( '' !== $found || false !== stripos( $text, 'Allowed: media' ) || preg_match( '#/ media\b#', $text ) ) {
		$bad[] = $tab . ': ' . $found;
	}
	if ( 'log' === $tab ) {
		t( 'B3 Log tab: the labels of the reasons are shown (media limit, fake AI search bot, a generic one for an unknown reason)', false !== strpos( $text, PNCP_Log::reasons()['rate_media'] ) && false !== strpos( $text, PNCP_Log::reasons()['fake_ai_bot'] ) && false !== strpos( $text, 'Another check of ScrapeLock' ), '' );
	}
}
t( 'B3 every tab (' . $ok . ' of ' . count( $tabs ) . ') with log rows and bans of every reason: no raw reason key in the visible text', ! $bad && count( $tabs ) === $ok, implode( ' | ', $bad ) );

/* ---------- B4: wp scrapelock check ---------- */
$cli = getenv( 'WP_CLI' );
if ( $cli ) {
	$out = (string) shell_exec( $cli . ' scrapelock check --ip=198.51.100.14 --ua=' . escapeshellarg( $chrome ) . ' --browser --address=/wp-content/uploads/b.png --format=json 2>/dev/null' );
	$rows = json_decode( $out, true );
	$map  = array();
	foreach ( is_array( $rows ) ? $rows : array() as $row ) {
		$map[ $row['check'] ] = $row['value'];
	}
	t( 'B4 wp scrapelock check: an image is checked as Media', isset( $map['Checked as'] ) && 'Media' === $map['Checked as'], $out );
	t( 'B4 wp scrapelock check: "Allowed: image or file; counted in the media limit, not as a page"', isset( $map['Verdict'] ) && 'Allowed: image or file; counted in the media limit, not as a page' === $map['Verdict'], isset( $map['Verdict'] ) ? $map['Verdict'] : '' );
	$label = PNCP_Log::reasons()['rate_media'];
	t( 'B4 wp scrapelock check: the media counter "N of M this minute"', isset( $map[ $label ] ) && preg_match( '/^\d+ of [\d,.]+ this minute$/', $map[ $label ] ), $out );
} else {
	echo "SKIP B4 wp scrapelock check: WP_CLI not given\n";
}

echo $fails ? "\n$fails FAILED\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
