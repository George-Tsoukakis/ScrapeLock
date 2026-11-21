<?php
/**
 * ScrapeLock 3.12.6 — "Block technology profilers" (block_tech_profilers), in real WordPress:
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3126_profilers.php
 *
 * S. The setting: off by default (new installs and new_in_3126() for existing sites), a switch of the Bots tab, a
 *    page-cache key, its label, in export / import; the form's check (anything else → 0).
 * L. The list: one place (PNCP_Bots::tech_profiler_agents()) with the filter pncp_tech_profiler_agents (added and
 *    removed names count everywhere below); no name of it already in the default lists.
 * B. Every layer that honours "Block SEO and marketing data crawlers" honours it: the blocked User-Agents
 *    (PNCP_Options::blocked_agents()), WordPress over HTTP (403 bot_ua, 200 while off), the early check, the
 *    pre-cache check's configuration, the generated Nginx and Apache rules, robots.txt (its own group), the log's
 *    "Matched … (technology profilers)" line, the Traffic "Explain" check, Site Health's summary.
 * A. The Bots tab: the switch right after the SEO crawlers one, its help line and the list in "More".
 *
 * Only on a test WordPress. The settings are put back at the end.
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

/** Stores settings as they are. */
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	wp_cache_delete( 'alloptions', 'options' );
}

/** [code, body] of a request with this User-Agent. */
function http( $path, $ua, $ip, $cookies = array() ) {
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
			CURLOPT_HTTPHEADER     => array( 'X-Test-IP: ' . $ip, 'User-Agent: ' . $ua, 'Accept-Language: en', 'Accept: text/html' ),
			CURLOPT_TIMEOUT        => 90,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

$saved   = get_option( PNCP_OPTION );
$browser = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36';
$names   = array( 'BuiltWith', 'Wappalyzer', 'WhatCMS', 'Netcraft', 'W3Techs', 'IsItWP', 'WPThemeDetector', 'WhatRuns', 'SimilarTech' );
$uas     = array(
	'Wappalyzer'          => 'Mozilla/5.0 (compatible; Wappalyzer/6.10; +https://www.wappalyzer.com)',
	'NetcraftSurveyAgent' => 'Mozilla/5.0 (compatible; NetcraftSurveyAgent/1.0; +info@netcraft.com)',
	'BuiltWith'           => 'Mozilla/5.0 (compatible; BuiltWith/1.0; +http://builtwith.com/biup)',
);

/* ---------- S. The setting ---------- */

$defaults = PNCP_Options::defaults();
t( 'S: off by default', array_key_exists( 'block_tech_profilers', $defaults ) && 0 === $defaults['block_tech_profilers'] );
t( 'S: off on a new install', 0 === PNCP_Options::install_defaults()['block_tech_profilers'] );
t( 'S: existing sites get it off (new_in_3126())', array( 'block_tech_profilers' => 0 ) === PNCP_Options::new_in_3126() );
t( 'S: a switch (bool key) of the Bots tab, next to the SEO crawlers', in_array( 'block_tech_profilers', PNCP_Options::bool_keys(), true ) && in_array( 'block_tech_profilers', PNCP_Options::sections()['bots'], true ) );
t( 'S: a page-cache key, like block_seo_crawlers (robots.txt, the never-cached User-Agents)', in_array( 'block_tech_profilers', PNCP_Options::cache_keys(), true ) && in_array( 'block_seo_crawlers', PNCP_Options::cache_keys(), true ) );
t( 'S: its label is not the key', 'block_tech_profilers' !== PNCP_Setting_Labels::label( 'block_tech_profilers' ) && false !== strpos( PNCP_Setting_Labels::label( 'block_tech_profilers' ), 'technology profilers' ) );
t( 'S: exported and imported (public key, not secret)', in_array( 'block_tech_profilers', PNCP_Settings_Io::public_keys(), true ) && ! in_array( 'block_tech_profilers', PNCP_Settings_Io::secret_keys(), true ) );
if ( ! function_exists( 'add_settings_error' ) ) {
	require_once ABSPATH . 'wp-admin/includes/template.php';
}
$p = PNCP_Settings_Io::prepare( array( 'block_tech_profilers' => 1 ) );
t( 'S: the form check keeps 1', 1 === (int) $p['settings']['block_tech_profilers'] );
$p = PNCP_Settings_Io::prepare( array( 'block_tech_profilers' => 0 ) );
t( 'S: the form check keeps 0', 0 === (int) $p['settings']['block_tech_profilers'] );
settings( array( 'block_tech_profilers' => 1 ) );
$export = PNCP_Settings_Io::export();
t( 'S: the export carries the value', isset( $export['settings']['block_tech_profilers'] ) && 1 === (int) $export['settings']['block_tech_profilers'] );
settings( array( 'block_tech_profilers' => 0 ) );

/* ---------- L. The list ---------- */

$list = PNCP_Bots::tech_profiler_agents();
t( 'L: the built-in list names every profiler asked for', ! array_diff( $names, $list ), implode( ',', array_diff( $names, $list ) ) );
t( 'L: no duplicates, no empty names', count( $list ) === count( array_unique( array_map( 'strtolower', $list ) ) ) && ! in_array( '', $list, true ) );
$off   = PNCP_Options::blocked_agents( array_merge( PNCP_Options::defaults(), array( 'block_tech_profilers' => 0 ) ) );
$clash = array();
foreach ( $list as $name ) {
	if ( PNCP_Bots::ua_in_list( 'x ' . $name . ' x', $off ) ) {
		$clash[] = $name;
	}
}
t( 'L: none of them is blocked by the default lists while the switch is off', ! $clash, implode( ',', $clash ) );
$filter = static function ( $agents ) {
	$agents   = array_diff( $agents, array( 'WhatRuns' ) );
	$agents[] = 'ExampleProfiler';
	return $agents;
};
add_filter( 'pncp_tech_profiler_agents', $filter );
$filtered = PNCP_Bots::tech_profiler_agents();
t( 'L: pncp_tech_profiler_agents adds and removes names', in_array( 'ExampleProfiler', $filtered, true ) && ! in_array( 'WhatRuns', $filtered, true ) );
add_filter( 'pncp_tech_profiler_agents', '__return_false' );
t( 'L: a broken filter gives an empty list, no warning', array() === PNCP_Bots::tech_profiler_agents() );
remove_filter( 'pncp_tech_profiler_agents', '__return_false' );

/* ---------- B. Every layer ---------- */

$on_s  = array_merge( PNCP_Options::stored(), array( 'block_tech_profilers' => 1, 'block_bots' => 1 ) );
$off_s = array_merge( $on_s, array( 'block_tech_profilers' => 0 ) );
PNCP_Options::flush();
$on  = PNCP_Options::blocked_agents( $on_s );
PNCP_Options::flush();
$off = PNCP_Options::blocked_agents( $off_s );
t( 'B: blocked_agents(): the profilers with the switch on (and the filter)', in_array( 'ExampleProfiler', $on, true ) && ! in_array( 'WhatRuns', $on, true ) && in_array( 'Wappalyzer', $on, true ) );
t( 'B: blocked_agents(): none while off', ! array_intersect( array_map( 'strtolower', $filtered ), array_map( 'strtolower', $off ) ) );
t( 'B: blocked_agents() is rebuilt when only the switch changes (request memo)', PNCP_Options::blocked_agents( $on_s ) !== PNCP_Options::blocked_agents( $off_s ) );
remove_filter( 'pncp_tech_profiler_agents', $filter );
PNCP_Options::flush();

// Log line and Traffic "Explain".
$m = PNCP_Bot_Match::entry( $uas['NetcraftSurveyAgent'], $on_s );
t( 'B: the log names the source: technology profilers (Netcraft covers NetcraftSurveyAgent)', null !== $m && 'tech' === $m['source'] && 'Netcraft' === $m['token'], wp_json_encode( $m ) );
t( 'B: no match while off', null === PNCP_Bot_Match::entry( $uas['NetcraftSurveyAgent'], $off_s ) );
ob_start();
PNCP_Bot_Match::render_reason(
	array(
		'reason' => 'bot_ua',
		'ua'     => $uas['Wappalyzer'],
	),
	$on_s
);
$line = (string) ob_get_clean();
t( 'B: the log row says “Matched “Wappalyzer” (technology profilers)”', false !== strpos( $line, 'Matched “Wappalyzer” (technology profilers)' ), $line );

// Pre-cache check configuration, Nginx and Apache rules, robots.txt (from the stored settings).
settings( array( 'block_tech_profilers' => 1, 'block_bots' => 1 ) );
$config = PNCP_Precheck::config();
t( 'B: pre-cache check: the profilers are in its blocked User-Agents', isset( $config['bots'] ) && in_array( 'wappalyzer', $config['bots'], true ) && in_array( 'builtwith', $config['bots'], true ) );
$nginx  = PNCP_Rules::nginx_http() . PNCP_Rules::nginx_server();
$apache = PNCP_Rules::apache();
t( 'B: Nginx rules name the profilers', false !== stripos( $nginx, 'wappalyzer' ) && false !== stripos( $nginx, 'whatcms' ) );
t( 'B: Apache rules name the profilers', false !== stripos( $apache, 'wappalyzer' ) && false !== stripos( $apache, 'whatcms' ) );
$robots = PNCP_Bots::robots_txt( '', true );
t( 'B: robots.txt: a group of its own with every profiler and Disallow: /', 1 === preg_match( "/# ScrapeLock: technology profilers\n((?:User-agent: [^\n]+\n)+)Disallow: \\/\n/", $robots, $rm ) && 0 === count( array_diff( PNCP_Bots::tech_profiler_agents(), array_map( 'trim', explode( 'User-agent:', str_replace( "\n", '', $rm[1] ) ) ) ) ), $robots );
$info  = PNCP_Health::info( array() );
$field = isset( $info['scrapelock']['fields']['tech_profilers'] ) ? $info['scrapelock']['fields']['tech_profilers'] : null;
t( 'B: Site Health info: “Technology profilers blocked”: Yes', is_array( $field ) && 'Technology profilers blocked' === $field['label'] && __( 'Yes' ) === $field['value'], wp_json_encode( $field ) );

// The early check, as WordPress runs it before the other plugins.
settings( array( 'early_mode' => 1 ) );
$keep_server                = $_SERVER;
$_SERVER['REMOTE_ADDR']     = '198.51.100.77';
$_SERVER['HTTP_USER_AGENT'] = $uas['Wappalyzer'];
$_SERVER['REQUEST_URI']     = '/';
$early_on                   = PNCP_Early::check();
settings( array( 'block_tech_profilers' => 0 ) );
$early_off = PNCP_Early::check();
$_SERVER   = $keep_server;
t( 'B: early check: 403 bot_ua with the switch on', is_array( $early_on ) && 'bot_ua' === $early_on[1], wp_json_encode( $early_on ) );
t( 'B: early check: passes while off', null === $early_off || 'bot_ua' !== $early_off[1], wp_json_encode( $early_off ) );
settings( array( 'early_mode' => (int) ( is_array( $saved ) && ! empty( $saved['early_mode'] ) ) ) );

// WordPress over HTTP.
settings( array( 'block_tech_profilers' => 0, 'block_bots' => 1, 'monitor_mode' => 0 ) );
list( $code_off ) = http( '/', $uas['BuiltWith'], '198.51.100.81' );
list( $robots_off_code, $robots_off ) = http( '/robots.txt', $browser, '198.51.100.82' );
settings( array( 'block_tech_profilers' => 1 ) );
list( $code_on ) = http( '/', $uas['BuiltWith'], '198.51.100.83' );
list( $code_wap ) = http( '/', $uas['Wappalyzer'], '198.51.100.84' );
list( $code_browser ) = http( '/', $browser, '198.51.100.85' );
list( $robots_on_code, $robots_on ) = http( '/robots.txt', $browser, '198.51.100.86' );
t( 'B: HTTP: BuiltWith passes while off', 200 === $code_off, (string) $code_off );
t( 'B: HTTP: BuiltWith and Wappalyzer get 403 with the switch on', 403 === $code_on && 403 === $code_wap, $code_on . ' ' . $code_wap );
t( 'B: HTTP: a browser still passes', 200 === $code_browser, (string) $code_browser );
t( 'B: HTTP robots.txt: the group only with the switch on', 200 === $robots_on_code && false !== strpos( $robots_on, "# ScrapeLock: technology profilers\nUser-agent: BuiltWith" ) && false === strpos( $robots_off, 'technology profilers' ), $robots_on_code . ' ' . $robots_off_code );
$explain = PNCP_Traffic_Actions::block_check( $uas['Wappalyzer'] );
t( 'B: Traffic “Explain”: matched “Wappalyzer”', 'Wappalyzer' === $explain['matched'], wp_json_encode( $explain ) );

/* ---------- A. The Bots tab ---------- */

$admin   = get_user_by( 'id', 1 );
$expire  = time() + DAY_IN_SECONDS;
$token   = WP_Session_Tokens::get_instance( $admin->ID )->create( $expire );
$cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( $admin->ID, $expire, 'auth', $token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( $admin->ID, $expire, 'logged_in', $token ),
);
$path              = (string) wp_parse_url( PNCP_Status::settings_url( array( 'tab' => 'bots' ) ), PHP_URL_PATH ) . '?' . (string) wp_parse_url( PNCP_Status::settings_url( array( 'tab' => 'bots' ) ), PHP_URL_QUERY );
list( $code, $tab ) = http( $path, $browser, '192.0.2.31', $cookies );
$seo  = strpos( $tab, 'name="pncp_settings[block_seo_crawlers]"' );
$tech = strpos( $tab, 'name="pncp_settings[block_tech_profilers]"' );
$ip   = strpos( $tab, 'name="pncp_settings[block_ip_host]"' );
t( 'A: the Bots tab has the switch, checked (stored on)', 200 === $code && false !== $tech && 1 === preg_match( '#name="pncp_settings\[block_tech_profilers\]"[^>]*checked#', $tab ), (string) $code );
t( 'A: right after “Block SEO and marketing data crawlers”', false !== $seo && false !== $ip && $seo < $tech && $tech < $ip );
t( 'A: its label and help line', false !== strpos( $tab, 'Block technology profilers (BuiltWith, Wappalyzer, WhatCMS…)' ) && false !== strpos( $tab, 'Services that list the CMS, theme and plugins a site runs.' ) );
t( 'A: the whole list in “More”', false !== strpos( $tab, implode( ', ', PNCP_Bots::tech_profiler_agents() ) ) );
t( 'A: no PHP warnings', ! preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:/', $tab ) );

update_option( PNCP_OPTION, $saved );
PNCP_Options::flush();
echo $fails ? "\n$fails FAIL\n" : "\nall PASS\n";
exit( $fails ? 1 : 0 );
