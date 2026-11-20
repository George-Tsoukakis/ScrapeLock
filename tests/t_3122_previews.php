<?php
/**
 * ScrapeLock 3.12.2 — link previews of the "Always allowed" list never count toward the media limit, in real
 * WordPress:
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3122_previews.php
 *
 * P1. WordPress (PNCP_Bots::check()): the real User-Agents of Viber, WhatsApp, Facebook, Telegram, Slack, X,
 *     LinkedIn and Discord on a .webp / .jpg, 30 times in a minute with a page limit of 1 (media limit 10): never
 *     429; a normal browser, a link preview that is NOT in the list and an allowed name that is not a link preview
 *     (Pinterest) still count (429 rate_media on the 11th); on a page the page limit still applies to them.
 * P2. The entry forms of the "Always allowed" list: part of the User-Agent (any case), "=" the whole User-Agent,
 *     "@" pinned to addresses (only from them), in WordPress and in the pre-cache check's own matcher.
 * P3. The early check: the link previews pass 30 times (it has no counters); over HTTP with the early check on,
 *     30 missing .webp / .jpg that reach WordPress: never 429; a browser gets 429.
 * P4. The pre-cache check over HTTP (stand-in page cache, as t_311_pipeline.php): 30 cached .webp / .jpg per
 *     link preview: all 200; a browser and a link preview not in the list: 429; an "=" entry passes there too.
 * P5. "Check a request" and "wp scrapelock check": an allowed link preview on a static file says
 *     "Not counted: link preview in the “Always allowed” list" instead of "N of M this minute"; a browser, a link
 *     preview not in the list and the same preview on a page still show "N of M"; no raw key in what is drawn.
 *
 * wp-config.php, advanced-cache.php and the settings are put back at the end. Only on a test WordPress.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once PNCP_DIR . 'includes/class-pncp-precheck-runtime.php';

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

/** Waits for the next minute when fewer than 25 seconds are left (the counters are per minute). */
function same_minute() {
	$left = 60 - time() % 60;
	if ( $left < 25 ) {
		sleep( $left + 1 );
	}
}

/** The $_SERVER of a request through the trusted proxy (every browser header removed first). */
function as_request( $ip, $ua, $uri, $headers = array() ) {
	foreach ( array_keys( $_SERVER ) as $k ) {
		if ( 0 === strpos( $k, 'HTTP_' ) ) {
			unset( $_SERVER[ $k ] );
		}
	}
	$_SERVER['REMOTE_ADDR']    = '127.0.0.1';
	$_SERVER['REQUEST_METHOD'] = 'GET';
	$_SERVER['REQUEST_URI']    = $uri;
	$_SERVER['HTTP_X_REAL_IP'] = $ip;
	if ( '' !== $ua ) {
		$_SERVER['HTTP_USER_AGENT'] = $ua;
	}
	foreach ( $headers as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
}

/** check() for a page, counted, $n times: the verdicts ("pass" or "code reason"). */
function verdicts( $n ) {
	$out = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$v     = PNCP_Bots::check( 'page', true );
		$out[] = is_array( $v ) ? $v['code'] . ' ' . $v['reason'] : 'pass';
	}
	return $out;
}

/** An HTTP request: its status code. */
function code_of( $path, $headers ) {
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
			CURLOPT_TIMEOUT        => 60,
		)
	);
	curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return $code;
}

/** Codes of $n requests. */
function codes( $path, $headers, $n ) {
	$out = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$out[] = code_of( $path, $headers );
	}
	return $out;
}

/** A visitor through the "CDN": REMOTE_ADDR 127.0.0.1 (trusted for X-Real-IP), the visitor in X-Real-IP / X-Test-IP. */
function via_cdn( $ip, $ua, $extra = array() ) {
	return array_merge(
		array(
			'X-Real-IP'  => $ip,
			'X-Test-IP'  => $ip,
			'User-Agent' => $ua,
		),
		$extra
	);
}

/** A fresh visitor address in a /24 of its own. */
function fresh_ip( $net ) {
	return $net . '.' . wp_rand( 2, 250 );
}

/** The 3.12.2 runtime of the pre-cache check reads its configuration file: written again, then a moment for OPcache. */
function precheck_sync() {
	PNCP_Precheck::sync();
	sleep( 2 );
}

/* ---------- Setup ---------- */
$config_file = PNCP_Precheck::config_path();
$cache_file  = WP_CONTENT_DIR . '/advanced-cache.php';
$original    = (string) file_get_contents( $config_file );
$had_cache   = file_exists( $cache_file ) ? (string) file_get_contents( $cache_file ) : null;
$saved       = PNCP_Options::stored();
register_shutdown_function(
	static function () use ( $config_file, $original, $cache_file, $had_cache, $saved ) {
		file_put_contents( $config_file, $original );
		if ( null === $had_cache ) {
			@unlink( $cache_file );
		} else {
			file_put_contents( $cache_file, $had_cache );
		}
		update_option( PNCP_OPTION, $saved );
		PNCP_Options::flush();
		PNCP_Early::sync();
		PNCP_Precheck::sync();
		PNCP_Log::unban_all();
	}
);
update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
PNCP_Log::unban_all();
$allow = PNCP_Options::default_allow_list();
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'block_bots'              => 1,
		'bot_list'                => PNCP_Options::default_bot_list(),
		'allow_list'              => $allow,
		'block_empty_ua'          => 1,
		'block_http_libs'         => 1,
		'require_browser_headers' => 1,
		'block_headless'          => 1,
		'block_fake_crawlers'     => 1,
		'probe_ban'               => 0,
		'rate_limit'              => 1, // Media limit: MEDIA_FACTOR (10) a minute.
		'rate_limit_search'       => 0,
		'rate_limit_404'          => 0,
		'rate_limit_unverified'   => 0,
		'rate_limit_datacenter'   => 0,
		'rate_limit_apionly'      => 0,
		'rate_limit_lowrep'       => 0,
		'human_check'             => 0,
		'reputation'              => 0,
		'ban_strikes'             => 0,
		'block_ips'               => '',
		'allow_ips'               => '',
		'trust_any_proxy'         => 0,
		'trusted_proxies'         => '',
		'ip_header'               => 'x_real_ip',
		'countries_block'         => '',
		'countries_strict'        => '',
		'crowdsec_mode'           => 'off',
		'private_paths'           => '',
		'auto_emergency'          => 0,
		'early_mode'              => 0,
		'precheck'                => 0,
		'block_ip_host'           => 0,
	)
);
wp_set_current_user( 0 );

$previews = array(
	'Viber'               => 'Viber/22.4.0.0 (Android 14; SM-S918B)',
	'WhatsApp'            => 'WhatsApp/2.24.10.80 A',
	'facebookexternalhit' => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
	'TelegramBot'         => 'TelegramBot (like TwitterBot)',
	'Slackbot'            => 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
	'Twitterbot'          => 'Twitterbot/1.0',
	'LinkedInBot'         => 'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)',
	'Discordbot'          => 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)',
);
$mobile    = 'Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36';
$browser_h = array(
	'HTTP_ACCEPT_LANGUAGE' => 'el-GR,el;q=0.9',
	'HTTP_SEC_FETCH_MODE'  => 'no-cors',
	'HTTP_SEC_CH_UA'       => '"Chromium";v="141"',
);
$browser_http = array(
	'Accept-Language' => 'el-GR,el;q=0.9',
	'Sec-Fetch-Mode'  => 'no-cors',
	'Sec-CH-UA'       => '"Chromium";v="141"',
);
$no_whatsapp = implode( "\n", array_diff( PNCP_Options::parse_list( $allow ), array( 'WhatsApp' ) ) );
$all_pass    = array_fill( 0, 30, 'pass' );

/* ---------- P1. WordPress ---------- */
foreach ( $previews as $name => $ua ) {
	foreach ( array( '.webp', '.jpg' ) as $ext ) {
		as_request( fresh_ip( '94.66.1' ), $ua, '/wp-content/uploads/2026/11/photo' . $ext );
		$v = verdicts( 30 );
		t( "P1 WordPress: $name on a $ext, 30 times (media limit 10): never 429", $all_pass === $v, implode( ',', array_unique( $v ) ) );
	}
}
same_minute();
as_request( fresh_ip( '94.66.2' ), $mobile, '/wp-content/uploads/2026/11/photo.webp', $browser_h );
$v = verdicts( 11 );
t( 'P1 WordPress: a normal browser still counts (11th: 429 rate_media)', 'pass' === $v[9] && '429 rate_media' === $v[10], implode( ',', $v ) );
// A link preview NOT in the list: counted (without "Browsers only" / headless, which would refuse it first).
settings( array( 'allow_list' => $no_whatsapp, 'require_browser_headers' => 0, 'block_headless' => 0 ) );
same_minute();
as_request( fresh_ip( '94.66.3' ), $previews['WhatsApp'], '/wp-content/uploads/2026/11/photo.webp' );
$v = verdicts( 11 );
t( 'P1 WordPress: WhatsApp NOT in the always-allowed list is counted (11th: 429 rate_media)', 'pass' === $v[9] && '429 rate_media' === $v[10], implode( ',', $v ) );
settings( array( 'allow_list' => $allow ) );
// An always-allowed name that is not a link preview (Pinterest): counted on media as everyone.
same_minute();
as_request( fresh_ip( '94.66.4' ), 'Pinterestbot/1.0 (+http://www.pinterest.com/bot.html)', '/wp-content/uploads/2026/11/photo.webp' );
$v = verdicts( 11 );
t( 'P1 WordPress: an allowed name that is not a link preview (Pinterest) is counted on media', '429 rate_media' === $v[10], implode( ',', $v ) );
settings( array( 'require_browser_headers' => 1, 'block_headless' => 1 ) );
// On a page the page limit still applies to a link preview.
same_minute();
as_request( fresh_ip( '94.66.5' ), $previews['Viber'], '/a-page/' );
$v = verdicts( 2 );
t( 'P1 WordPress: Viber on a page: the page limit still applies (2nd: 429 rate_page)', array( 'pass', '429 rate_page' ) === $v, implode( ',', $v ) );

/* ---------- P2. The entry forms of the "Always allowed" list ---------- */
$viber = $previews['Viber'];
$forms = array(
	// label => [ allow list, visitor network, counted? ].
	'part of the User-Agent, lowercase ("viber")'         => array( 'viber', '94.66.10', false ),
	'"=" the whole User-Agent'                            => array( '=' . $viber, '94.66.11', false ),
	'"=" the whole User-Agent, other case'                => array( '=' . strtoupper( $viber ), '94.66.12', false ),
	'"=" only part of the User-Agent (no match)'          => array( '=Viber/22', '94.66.13', true ),
	'"@" pinned, from its address'                        => array( 'Viber@94.66.14.0/24', '94.66.14', false ),
	'"@" pinned, from another address (no match)'         => array( 'Viber@198.51.100.0/24', '94.66.15', true ),
	'"=" and "@" together, from its address'              => array( '=' . $viber . '@94.66.16.0/24', '94.66.16', false ),
);
settings( array( 'require_browser_headers' => 0, 'block_headless' => 0 ) );
foreach ( $forms as $label => $form ) {
	settings( array( 'allow_list' => $form[0] ) );
	same_minute();
	as_request( fresh_ip( $form[1] ), $viber, '/wp-content/uploads/2026/11/photo.webp' );
	$v = verdicts( 11 );
	t( "P2 WordPress: $label: " . ( $form[2] ? 'counted (11th: 429)' : 'not counted (11 pass)' ), $form[2] ? '429 rate_media' === $v[10] : array_fill( 0, 11, 'pass' ) === $v, implode( ',', $v ) );
	// The pre-cache check's own matcher, from its configuration (lowercase User-Agent, as it reads it).
	$cfg      = PNCP_Precheck::config();
	$ip       = $form[1] . '.9';
	$reliable = true;
	t( "P2 pre-cache matcher: $label", ! $form[2] === PNCP_Precheck_Runtime::ua_allowed( $cfg, strtolower( $viber ), $ip, $reliable ) );
}
// "=" as the whole User-Agent also lets it past "Browsers only" (it matched nothing until 3.12.1).
settings( array( 'allow_list' => '=' . $viber, 'require_browser_headers' => 1, 'block_headless' => 1 ) );
as_request( fresh_ip( '94.66.17' ), $viber, '/a-page/' );
$v = verdicts( 1 );
t( 'P2 WordPress: an "=" entry is always allowed ("Browsers only" does not refuse it)', array( 'pass' ) === $v, implode( ',', $v ) );
as_request( fresh_ip( '94.66.17' ), $viber . ' extra', '/a-page/' );
$v = verdicts( 1 );
t( 'P2 WordPress: ... but not a longer User-Agent (403 no_browser)', array( '403 no_browser' ) === $v, implode( ',', $v ) );
settings( array( 'allow_list' => $allow ) );

/* ---------- P3. The early check ---------- */
settings( array( 'early_mode' => 1, 'bot_list' => PNCP_Options::default_bot_list() . "\nAndroid 14" ) );
foreach ( $previews as $name => $ua ) {
	as_request( fresh_ip( '94.66.20' ), $ua, '/wp-content/uploads/2026/11/photo.webp' );
	$e = array();
	for ( $i = 0; $i < 30; $i++ ) {
		$e[] = wp_json_encode( PNCP_Early::check() );
	}
	t( "P3 early check: $name on a .webp, 30 times: passes", array_fill( 0, 30, 'null' ) === $e, implode( ',', array_unique( $e ) ) );
}
settings( array( 'allow_list' => $no_whatsapp, 'bot_list' => PNCP_Options::default_bot_list() . "\nWhatsApp/" ) );
as_request( fresh_ip( '94.66.21' ), $previews['WhatsApp'], '/wp-content/uploads/2026/11/photo.webp' );
$e = PNCP_Early::check();
t( 'P3 early check: a link preview NOT in the list and in the bot list: 403 bot_ua', is_array( $e ) && 'bot_ua' === $e[1], wp_json_encode( $e ) );
settings( array( 'allow_list' => $allow, 'bot_list' => PNCP_Options::default_bot_list() ) );
// Over HTTP: missing files reach WordPress (404 handler), with the early check on. Not under /wp-content/uploads/:
// the built-in server of PHP redirects an address under an existing folder to its trailing slash.
PNCP_Early::sync();
sleep( 3 ); // OPcache of the server: the early check file.
foreach ( $previews as $name => $ua ) {
	foreach ( array( '.webp', '.jpg' ) as $ext ) {
		$c = codes( '/img/missing-' . wp_rand() . $ext, via_cdn( fresh_ip( '94.66.22' ), $ua ), 30 );
		t( "P3 HTTP (early check + WordPress): $name, 30 missing $ext: all reach WordPress (404), never 429 or 403", array_fill( 0, 30, 404 ) === $c, implode( ',', array_unique( $c ) ) );
	}
}
same_minute();
$c = codes( '/img/missing-' . wp_rand() . '.webp', via_cdn( fresh_ip( '94.66.23' ), $mobile, $browser_http ), 12 );
t( 'P3 HTTP: a normal browser on missing .webp is counted (429 after 10)', 404 === $c[9] && 429 === $c[11], implode( ',', $c ) );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();

/* ---------- P5. "Check a request" and wp scrapelock check ---------- */
settings( array( 'rate_limit' => 60 ) );
wp_set_current_user( 1 );
$check = static function ( $ip, $ua, $address, $browser = false ) {
	return PNCP_Tester::run(
		array(
			'mode'    => 'custom',
			'ip'      => $ip,
			'ua'      => $ua,
			'address' => $address,
			'browser' => $browser ? '1' : '',
		)
	);
};
$not_counted = 'Not counted: link preview in the “Always allowed” list';
$media_label = PNCP_Log::reasons()['rate_media'];
foreach ( $previews as $name => $ua ) {
	$r = $check( fresh_ip( '94.66.40' ), $ua, '/wp-content/uploads/2026/11/photo.webp' );
	t(
		"P5 Check a request: $name on a .webp: \"$not_counted\", not \"N of M\"",
		is_array( $r ) && 'allowed' === $r['verdict'] && 'media_preview' === $r['pass'] && is_array( $r['counter'] ) && false === $r['counter']['counted'] && $not_counted === $r['counter']['text'] && $media_label === $r['counter']['label'] && false === strpos( $r['counter']['text'], ' of ' ),
		wp_json_encode( is_array( $r ) ? array( $r['pass'], $r['counter'] ) : $r )
	);
}
$r = $check( fresh_ip( '94.66.41' ), $previews['Viber'], '/wp-content/uploads/2026/11/photo.jpg' );
t( 'P5 Check a request: the verdict and the why say it is not counted, with no internal key', 'Allowed: a link preview in the “Always allowed” list; its images and files are not counted' === $r['headline'] && false !== strpos( $r['why'], 'not counted toward any limit' ) && false === strpos( $r['headline'] . $r['why'], 'media_preview' ), $r['headline'] . ' | ' . $r['why'] );
t( 'P5 Check a request: checked as Media', 'media' === $r['checked_as'] && 'Media' === $r['checked_as_label'], $r['checked_as_label'] );
$r = $check( fresh_ip( '94.66.42' ), $mobile, '/wp-content/uploads/2026/11/photo.webp', true );
t( 'P5 Check a request: a normal browser on a .webp still shows "1 of 600 this minute"', is_array( $r['counter'] ) && true === $r['counter']['counted'] && '1 of 600 this minute' === $r['counter']['text'] && 'media' === $r['pass'], wp_json_encode( $r['counter'] ) );
$r = $check( fresh_ip( '94.66.43' ), $previews['Viber'], '/a-page/' );
t( 'P5 Check a request: Viber on a page still shows the page counter "1 of 60 this minute"', 'passed' === $r['pass'] && 'rate_page' === $r['counter']['bucket'] && '1 of 60 this minute' === $r['counter']['text'], wp_json_encode( $r['counter'] ) );
settings( array( 'allow_list' => $no_whatsapp, 'require_browser_headers' => 0, 'block_headless' => 0 ) );
$r = $check( fresh_ip( '94.66.44' ), $previews['WhatsApp'], '/wp-content/uploads/2026/11/photo.webp' );
t( 'P5 Check a request: WhatsApp NOT in the list on a .webp: "1 of 600 this minute"', 'media' === $r['pass'] && '1 of 600 this minute' === $r['counter']['text'], wp_json_encode( $r['counter'] ) );
settings( array( 'allow_list' => '=' . $viber, 'require_browser_headers' => 1, 'block_headless' => 1 ) );
$r = $check( fresh_ip( '94.66.45' ), $viber, '/wp-content/uploads/2026/11/photo.webp' );
t( 'P5 Check a request: an "=" entry: not counted', 'media_preview' === $r['pass'] && $not_counted === $r['counter']['text'], wp_json_encode( $r['counter'] ) );
settings( array( 'allow_list' => $allow ) );
// The card's script draws label and text as they are (assets/js/tester.js): the text has no internal key.
$js = (string) file_get_contents( PNCP_DIR . 'assets/js/tester.js' );
t( 'P5 tester.js draws the counter row from its label and text', false !== strpos( $js, 'data.counter.label' ) && false !== strpos( $js, 'data.counter.text' ) );
$cli = getenv( 'WP_CLI' );
if ( $cli ) {
	$out  = (string) shell_exec( $cli . ' scrapelock check --ip=94.66.46.9 --ua=' . escapeshellarg( $previews['WhatsApp'] ) . ' --address=/wp-content/uploads/2026/11/b.webp --format=json 2>/dev/null' );
	$rows = json_decode( $out, true );
	$map  = array();
	foreach ( is_array( $rows ) ? $rows : array() as $row ) {
		$map[ $row['check'] ] = $row['value'];
	}
	t( 'P5 wp scrapelock check: an allowed link preview on a .webp: "' . $not_counted . '"', isset( $map[ $media_label ] ) && $not_counted === $map[ $media_label ], $out );
	t( 'P5 wp scrapelock check: its verdict by label, no internal key', isset( $map['Verdict'] ) && 'Allowed: a link preview in the “Always allowed” list; its images and files are not counted' === $map['Verdict'], $out );
	$out  = (string) shell_exec( $cli . ' scrapelock check --ip=94.66.47.9 --ua=' . escapeshellarg( $mobile ) . ' --browser --address=/wp-content/uploads/2026/11/b.webp --format=json 2>/dev/null' );
	$rows = json_decode( $out, true );
	$map  = array();
	foreach ( is_array( $rows ) ? $rows : array() as $row ) {
		$map[ $row['check'] ] = $row['value'];
	}
	t( 'P5 wp scrapelock check: a browser on a .webp still shows "N of M this minute"', isset( $map[ $media_label ] ) && preg_match( '/^\d+ of [\d,.]+ this minute$/', $map[ $media_label ] ), $out );
} else {
	echo "SKIP P5 wp scrapelock check: WP_CLI not given\n";
}
settings( array( 'rate_limit' => 1 ) );
wp_set_current_user( 0 );

/* ---------- P4. The pre-cache check over HTTP ---------- */
file_put_contents( $config_file, "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) );
file_put_contents( $cache_file, "<?php\nif ( isset( \$_SERVER['REQUEST_URI'] ) && 0 === strpos( \$_SERVER['REQUEST_URI'], '/cached-page/' ) ) {\n\theader( 'X-Test-Cache: HIT' );\n\techo 'CACHED PAGE';\n\texit;\n}\n" );
settings( array( 'precheck' => 1 ) );
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
WP_Screen::get( 'settings_page_scrapelock' )->set_current_screen();
precheck_sync();
sleep( 1 ); // OPcache: the new wp-config.php.
t( 'P4 pre-cache check active', PNCP_Precheck::active(), (string) get_option( PNCP_Precheck::STATUS ) );
$cfg = json_decode( (string) file_get_contents( PNCP_Precheck::config_file() ), true );
t( 'P4 pre-cache: its configuration (key "media") carries the link previews', isset( $cfg['media']['preview'] ) && in_array( 'viber', $cfg['media']['preview'], true ) && in_array( 'discordbot', $cfg['media']['preview'], true ), wp_json_encode( isset( $cfg['media'] ) ? $cfg['media'] : null ) );
foreach ( $previews as $name => $ua ) {
	foreach ( array( '.webp', '.jpg' ) as $ext ) {
		$c = codes( '/cached-page/photo' . $ext, via_cdn( fresh_ip( '94.66.30' ), $ua ), 30 );
		t( "P4 pre-cache: $name, 30 cached $ext: all 200", array_fill( 0, 30, 200 ) === $c, implode( ',', array_unique( $c ) ) );
	}
}
same_minute();
$c = codes( '/cached-page/photo.webp', via_cdn( fresh_ip( '94.66.31' ), $mobile, $browser_http ), 11 );
t( 'P4 pre-cache: a normal browser is counted (11th: 429)', 200 === $c[9] && 429 === $c[10], implode( ',', $c ) );
settings( array( 'allow_list' => $no_whatsapp ) );
precheck_sync();
same_minute();
$c = codes( '/cached-page/photo.webp', via_cdn( fresh_ip( '94.66.32' ), $previews['WhatsApp'] ), 11 );
t( 'P4 pre-cache: WhatsApp NOT in the always-allowed list is counted (11th: 429)', 200 === $c[9] && 429 === $c[10], implode( ',', $c ) );
settings( array( 'allow_list' => '=' . $viber ) );
precheck_sync();
$c = codes( '/cached-page/photo.webp', via_cdn( fresh_ip( '94.66.33' ), $viber ), 30 );
t( 'P4 pre-cache: an "=" entry (the whole User-Agent): 30 cached .webp, all 200', array_fill( 0, 30, 200 ) === $c, implode( ',', array_unique( $c ) ) );
settings( array( 'allow_list' => $allow, 'precheck' => 0 ) );
PNCP_Precheck::sync();
file_put_contents( $config_file, $original );

echo $fails ? "\n$fails FAIL\n" : "\nall PASS\n";
exit( $fails ? 1 : 0 );
