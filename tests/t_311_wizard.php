<?php
/**
 * ScrapeLock 3.11 — "For my site" (PNCP_Wizard) in real WordPress, with stand-in plugins (only their header;
 * the FluentCommunity stand-in also defines its portal address, /hub/, as the real site has it).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_311_wizard.php
 *
 * 1. Detection: nothing before, WooCommerce / FluentCommunity / WP Rocket / OneSignal / Wordfence / Bunny after.
 * 2. Proposals: only existing settings, a reason each, "blocks more" ones marked; notes with links.
 * 3. The panel on the first tab: table, ticked / not ticked, no PHP warnings.
 * 4. "Apply selected": wrong nonce and a subscriber refused; only the ticked settings change, an unknown or
 *    unproposed key does nothing; a saved version ("Before the “For my site” assistant") is made first and
 *    "Undo" restores it; nothing ticked = nothing changes, no saved version.
 * 5. Idempotence: after applying everything, nothing is proposed and a second apply saves nothing.
 * 6. WP-CLI: wp scrapelock wizard (--format=json, --apply --yes, --only).
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/template.php';

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

function fresh() {
	wp_cache_delete( PNCP_OPTION, 'options' );
	wp_cache_delete( PNCP_Settings_Io::BACKUPS, 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_delete( 'notoptions', 'options' );
	PNCP_Options::flush();
	return PNCP_Options::stored();
}

/** An HTTP request; [code, body, location]. */
function http( $path, $post = null, $cookies = array(), $headers = array() ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => array_merge( array( 'X-Test-IP: 192.0.2.210', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 'Accept-Language: en' ), $headers ),
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_TIMEOUT        => 90,
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = preg_replace( '/%5B[0-9]+%5D/', '%5B%5D', http_build_query( $post ) );
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

function cookies_for( $user_id ) {
	$expire = time() + DAY_IN_SECONDS;
	$token  = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	return array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $user_id, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token ),
	);
}

/** A nonce as the given user's browser would get it. */
function nonce_for( $user_id, $cookies, $action ) {
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	return wp_create_nonce( $action );
}

function cli( $args ) {
	global $wp_cli;
	exec( $wp_cli . ' scrapelock ' . $args . ' 2>&1', $out, $rc );
	return array( $rc, implode( "\n", $out ) );
}

/* ---------- Stand-in plugins ---------- */
$stand_ins = array(
	'woocommerce/woocommerce.php'                         => '',
	'fluent-community/fluent-community.php'               => "if ( ! defined( 'FLUENT_COMMUNITY_PORTAL_SLUG' ) ) {\n\tdefine( 'FLUENT_COMMUNITY_PORTAL_SLUG', 'hub' );\n}\n",
	'wp-rocket/wp-rocket.php'                             => '',
	'onesignal-free-web-push-notifications/onesignal.php' => '',
	'wordfence/wordfence.php'                             => '',
);
$created = array();
foreach ( $stand_ins as $file => $body ) {
	$dir = WP_PLUGIN_DIR . '/' . dirname( $file );
	if ( ! file_exists( WP_PLUGIN_DIR . '/' . $file ) ) {
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir );
			$created[ $file ] = 'dir';
		} else {
			$created[ $file ] = 'file';
		}
		file_put_contents( WP_PLUGIN_DIR . '/' . $file, "<?php\n/*\nPlugin Name: " . dirname( $file ) . " (test stand-in)\nVersion: 0.0.1\n*/\n" . $body );
	}
}
$saved         = PNCP_Options::stored();
$saved_backups = get_option( PNCP_Settings_Io::BACKUPS, null );
$saved_bots    = get_option( PNCP_Plugin_Bots::OPTION, null );
register_shutdown_function(
	static function () use ( $stand_ins, $created, $saved, $saved_backups, $saved_bots ) {
		deactivate_plugins( array_keys( $stand_ins ), true );
		foreach ( $created as $file => $what ) {
			@unlink( WP_PLUGIN_DIR . '/' . $file );
			if ( 'dir' === $what ) {
				@rmdir( WP_PLUGIN_DIR . '/' . dirname( $file ) );
			}
		}
		update_option( PNCP_OPTION, $saved );
		foreach ( array( PNCP_Settings_Io::BACKUPS => $saved_backups, PNCP_Plugin_Bots::OPTION => $saved_bots ) as $option => $value ) {
			if ( null === $value ) {
				delete_option( $option );
			} else {
				update_option( $option, $value, false );
			}
		}
	}
);
deactivate_plugins( array_keys( $stand_ins ), true );
delete_option( PNCP_Plugin_Bots::OPTION );
// A site that predates these defaults: the settings the assistant should notice.
$start = array(
	'skip_woo_pages'    => 0,
	'rate_limit_cart'   => 0,
	'rate_limit_coupon' => 0,
	'content_paths'     => '/hub/space',
	'precheck'          => 0,
	'trust_bunny'       => 0,
	'edge_send_blocks'  => 0,
	'monitor_mode'      => 0,
	'monitor_until'     => 0,
);
settings( $start );
unset( $_SERVER['HTTP_VIA'], $_SERVER['HTTP_CDN_SERVERID'], $_SERVER['HTTP_CF_CONNECTING_IP'] );

/* ---------- 1. Detection ---------- */
$env = PNCP_Wizard::detect();
t( 'detect(): nothing of the stand-ins before they are active', ! $env['woocommerce'] && ! $env['fluentcommunity'] && ! $env['wp_rocket'] && ! $env['onesignal'] && ! $env['wordfence'] && ! $env['bunny'], wp_json_encode( $env ) );
t( 'proposals(): nothing about WooCommerce, FluentCommunity or WP Rocket while they are not active', ! array_intersect( array( 'skip_woo_pages', 'rate_limit_cart', 'content_paths', 'precheck' ), array_keys( PNCP_Wizard::proposals() ) ), implode( ',', array_keys( PNCP_Wizard::proposals() ) ) );

foreach ( array_keys( $stand_ins ) as $file ) {
	$r = activate_plugin( $file, '', false, true );
	if ( is_wp_error( $r ) ) {
		echo 'activate ' . $file . ': ' . $r->get_error_message() . "\n";
	}
}
if ( ! defined( 'FLUENT_COMMUNITY_PORTAL_SLUG' ) ) {
	define( 'FLUENT_COMMUNITY_PORTAL_SLUG', 'hub' ); // As the stand-in does on the next requests.
}
$_SERVER['HTTP_VIA'] = '1.1 BunnyCDN'; // As Bunny sends it.
$env                 = PNCP_Wizard::detect();
t( 'detect(): WooCommerce, FluentCommunity, WP Rocket, OneSignal, Wordfence, Bunny CDN', $env['woocommerce'] && $env['fluentcommunity'] && $env['wp_rocket'] && $env['onesignal'] && $env['wordfence'] && $env['bunny'], wp_json_encode( $env ) );
$names = PNCP_Wizard::detected_names( $env );
t( 'detected_names(): names for the panel', in_array( 'WooCommerce', $names, true ) && in_array( 'Bunny CDN', $names, true ) && in_array( 'FluentCommunity', $names, true ), implode( ', ', $names ) );
t( 'fluent_slug(): FLUENT_COMMUNITY_PORTAL_SLUG', 'hub' === PNCP_Wizard::fluent_slug(), PNCP_Wizard::fluent_slug() );

/* ---------- 2. Proposals ---------- */
$p = PNCP_Wizard::proposals();
t( 'proposals: skip_woo_pages, rate_limit_cart, rate_limit_coupon, precheck, trust_bunny', array( 'precheck', 'rate_limit_cart', 'rate_limit_coupon', 'skip_woo_pages', 'trust_bunny' ) === ( static function ( $k ) {
	sort( $k );
	return $k;
} )( array_keys( $p ) ), implode( ',', array_keys( $p ) ) );
$defaults = PNCP_Options::defaults();
$ok       = true;
foreach ( $p as $key => $row ) {
	$ok = $ok && array_key_exists( $key, $defaults ) && $key === $row['key'] && '' !== trim( $row['reason'] ) && (string) $row['current'] !== (string) $row['proposed'] && in_array( $row['risk'], array( 'none', 'more' ), true );
}
t( 'every proposal: an existing setting, a reason, a real change, a risk', $ok );
t( 'content_paths: not proposed, FluentCommunity\'s portal is already counted (PNCP_Fluent_Community)', ! isset( $p['content_paths'] ) && array( '/hub' ) === PNCP_Fluent_Community::added_paths(), isset( $p['content_paths'] ) ? $p['content_paths']['proposed'] : '' );
// FluentCommunity reported by the environment filter while the integration does not count it (switched off with
// its own filter): then the portal is proposed, after the existing line.
$env_on  = static function ( $env ) {
	$env['fluentcommunity'] = true;
	return $env;
};
add_filter( 'pncp_wizard_environment', $env_on );
add_filter( 'pncp_fluent_community_active', '__return_false' );
$pc = PNCP_Wizard::proposals();
remove_filter( 'pncp_fluent_community_active', '__return_false' );
remove_filter( 'pncp_wizard_environment', $env_on );
t( 'content_paths: /hub/ proposed after the existing line when the integration does not count it', isset( $pc['content_paths'] ) && "/hub/space\n/hub/" === $pc['content_paths']['proposed'] && 'none' === $pc['content_paths']['risk'], isset( $pc['content_paths'] ) ? $pc['content_paths']['proposed'] : '' );
t( 'blocks more (not ticked): rate_limit_cart, rate_limit_coupon, precheck', 'more' === $p['rate_limit_cart']['risk'] && 'more' === $p['rate_limit_coupon']['risk'] && 'more' === $p['precheck']['risk'] );
t( 'blocks nothing more (ticked): skip_woo_pages, trust_bunny', 'none' === $p['skip_woo_pages']['risk'] && 'none' === $p['trust_bunny']['risk'] );
t( 'content_path_covered(): /hub/ covers /hub/space, not the other way round', PNCP_Wizard::content_path_covered( "/hub/\n", '/hub/space' ) && ! PNCP_Wizard::content_path_covered( '/hub/space', '/hub' ) && PNCP_Wizard::content_path_covered( 'https://example.com/hub', '/hub' ) );

$filter = static function ( $out, $s ) {
	$out['no_such_setting'] = array( 'proposed' => 1, 'reason' => 'x' );
	$out['cdn_secret']      = array( 'proposed' => 'abc', 'reason' => 'x' );
	$out['block_bots']      = array( 'proposed' => empty( $s['block_bots'] ) ? 1 : 0, 'reason' => 'from a filter' );
	return $out;
};
add_filter( 'pncp_wizard_proposals', $filter, 10, 2 );
$pf = PNCP_Wizard::proposals();
remove_filter( 'pncp_wizard_proposals', $filter );
t( 'filter: unknown and secret settings are dropped; another one without a risk counts as "blocks more"', ! isset( $pf['no_such_setting'] ) && ! isset( $pf['cdn_secret'] ) && isset( $pf['block_bots'] ) && 'more' === $pf['block_bots']['risk'] );

$notes = wp_list_pluck( PNCP_Wizard::notes(), 'for' );
t( 'notes: WooCommerce, OneSignal and Wordfence (Site Health)', in_array( 'WooCommerce', $notes, true ) && in_array( 'OneSignal', $notes, true ) && in_array( 'Wordfence', $notes, true ), implode( ',', $notes ) );
t( 'notes: FluentCommunity\'s portal is counted automatically', in_array( 'FluentCommunity', $notes, true ), implode( ',', $notes ) );
PNCP_Plugin_Bots::set_allowed( 'wp-rocket', false );
$notes = PNCP_Wizard::notes();
t( 'notes: WP Rocket\'s service bot switched off → a note with a link to "Bots and limits"', (bool) array_filter( $notes, static function ( $n ) {
	return 'WP Rocket' === $n['for'] && false !== strpos( $n['url'], 'tab=bots' );
} ) );
PNCP_Plugin_Bots::set_allowed( 'wp-rocket', true );
t( 'value_text(): on/off, header names, lists', 'On' === PNCP_Wizard::value_text( 'trust_bunny', 1 ) && 'Off' === PNCP_Wizard::value_text( 'precheck', 0 ) && 'X-Real-IP' === PNCP_Wizard::value_text( 'ip_header', 'x_real_ip' ) && '/a, /b' === PNCP_Wizard::value_text( 'content_paths', "/a\n/b" ) && 'Off' === PNCP_Wizard::value_text( 'rate_limit_cart', 0 ) );
unset( $_SERVER['HTTP_VIA'] );

/* ---------- 3. The panel ---------- */
$admin   = get_user_by( 'id', 1 );
$cookies = cookies_for( $admin->ID );
$bunny   = array( 'Via: 1.1 BunnyCDN' );
list( $code, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=general', null, $cookies, $bunny );
t( 'first tab: 200 without PHP warnings, with the "For my site" panel open', 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'id="pncp-wizard" open' ) && false !== strpos( $body, 'For my site' ), (string) $code );
t( 'panel: "Found on this site" names the stand-ins and Bunny CDN', 1 === preg_match( '/Found on this site:.*WooCommerce.*FluentCommunity.*WP Rocket.*Bunny CDN/s', $body ) );
t( 'panel: skip_woo_pages and trust_bunny ticked', 1 === preg_match( '/value="skip_woo_pages" id="pncp-wizard-skip_woo_pages" checked/', $body ) && 1 === preg_match( '/value="trust_bunny" id="pncp-wizard-trust_bunny" checked/', $body ) );
t( 'panel: precheck and rate_limit_cart not ticked, marked "Blocks more"', 1 === preg_match( '/value="precheck" id="pncp-wizard-precheck">/', $body ) && 1 === preg_match( '/value="rate_limit_cart" id="pncp-wizard-rate_limit_cart">/', $body ) && substr_count( $body, 'Blocks more: not ticked' ) >= 3 );
t( 'panel: "Apply selected" posts to admin-post with the pncp_wizard action and a nonce', false !== strpos( $body, 'name="action" value="pncp_wizard"' ) && false !== strpos( $body, 'Apply selected' ) && 1 === preg_match( '/class="pncp-wizard-form">.*?name="_wpnonce" value="[0-9a-f]{10}"/s', $body ) );
t( 'panel: the advice links to Site Health', false !== strpos( $body, 'pncp-wizard-notes' ) && false !== strpos( $body, 'site-health.php' ) );

/* ---------- 4. Apply selected ---------- */
$backups_before = count( PNCP_Settings_Io::backups() );
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_wizard', '_wpnonce' => 'wrong', 'pncp_wizard_keys' => array( 'skip_woo_pages' ) ), $cookies, $bunny );
$s = fresh();
t( 'wrong nonce: refused (403), nothing changes, no saved version', 403 === $code && 0 === (int) $s['skip_woo_pages'] && count( PNCP_Settings_Io::backups() ) === $backups_before, (string) $code );

$sub_id      = wp_insert_user(
	array(
		'user_login' => 'pncp_wiz_sub_' . wp_rand( 1000, 9999 ),
		'user_pass'  => wp_generate_password(),
		'role'       => 'subscriber',
	)
);
$sub_cookies = cookies_for( $sub_id );
$sub_nonce   = nonce_for( $sub_id, $sub_cookies, 'pncp_wizard' );
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_wizard', '_wpnonce' => $sub_nonce, 'pncp_wizard_keys' => array( 'skip_woo_pages' ) ), $sub_cookies, $bunny );
$s = fresh();
t( 'subscriber (no manage_options) with its own nonce: refused (403), nothing changes', 403 === $code && 0 === (int) $s['skip_woo_pages'], (string) $code );
require_once ABSPATH . 'wp-admin/includes/user.php';
wp_delete_user( $sub_id );

$nonce = nonce_for( $admin->ID, $cookies, 'pncp_wizard' );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_wizard', '_wpnonce' => $nonce ), $cookies, $bunny );
$s = fresh();
t( 'nothing ticked: back with "none", nothing changes, no saved version', 302 === $code && false !== strpos( $loc, 'pncp_wizard=none' ) && 0 === (int) $s['skip_woo_pages'] && count( PNCP_Settings_Io::backups() ) === $backups_before, $code . ' ' . $loc );

list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_wizard', '_wpnonce' => $nonce, 'pncp_wizard_keys' => array( 'skip_woo_pages', 'content_paths', 'enabled', 'block_bots' ) ), $cookies, $bunny );
$s = fresh();
t( 'Apply selected: back to the first tab, at the panel, with "applied" and the saved version', 302 === $code && false !== strpos( $loc, 'pncp_wizard=applied' ) && false !== strpos( $loc, 'pncp_wizard_undo=' ) && false !== strpos( $loc, '#pncp-wizard' ), $code . ' ' . $loc );
t( 'Apply selected: the ticked settings changed (content_paths was not proposed: unchanged)', 1 === (int) $s['skip_woo_pages'] && '/hub/space' === $s['content_paths'], wp_json_encode( array( $s['skip_woo_pages'], $s['content_paths'] ) ) );
t( 'Apply selected: the unticked proposals did not change (trust_bunny, rate_limit_cart, rate_limit_coupon, precheck)', 0 === (int) $s['trust_bunny'] && 0 === (int) $s['rate_limit_cart'] && 0 === (int) $s['rate_limit_coupon'] && 0 === (int) $s['precheck'] );
t( 'Apply selected: keys that were not proposed (enabled, block_bots) are ignored', (int) $saved['enabled'] === (int) $s['enabled'] && (int) $saved['block_bots'] === (int) $s['block_bots'] );
$backups = PNCP_Settings_Io::backups();
t( 'a saved version was made first ("Before the “For my site” assistant"), with the old values', count( $backups ) === min( PNCP_Settings_Io::KEEP, $backups_before + 1 ) && 'wizard' === $backups[0]['reason'] && 0 === (int) $backups[0]['settings']['skip_woo_pages'] && '/hub/space' === $backups[0]['settings']['content_paths'] && 'Before the “For my site” assistant' === PNCP_Settings_Io::reason_label( $backups[0] ), isset( $backups[0] ) ? $backups[0]['reason'] : '' );
t( 'the saved version\'s id is the one in the redirect', false !== strpos( $loc, 'pncp_wizard_undo=' . $backups[0]['id'] ) );

$result_url = '/wp-admin/options-general.php?page=scrapelock&tab=general&pncp_wizard=applied&pncp_wizard_undo=' . $backups[0]['id'];
list( $code, $body ) = http( $result_url, null, $cookies, $bunny );
t( 'result: "applied" notice with an "Undo" form (restore of that version)', 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'The selected changes were applied.' ) && false !== strpos( $body, 'name="op" value="restore"' ) && false !== strpos( $body, 'name="id" value="' . $backups[0]['id'] . '"' ) );
t( 'result: the applied settings are no longer proposed, the unticked ones still are', false === strpos( $body, 'value="skip_woo_pages" id="pncp-wizard' ) && false !== strpos( $body, 'value="trust_bunny" id="pncp-wizard' ) && false !== strpos( $body, 'value="precheck" id="pncp-wizard' ) );
t( '"Earlier versions" lists it', false !== strpos( $body, 'Before the “For my site” assistant' ) );

$snonce = nonce_for( $admin->ID, $cookies, 'pncp_settings' );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_settings', 'op' => 'restore', 'id' => $backups[0]['id'], 'tab' => 'general', '_wpnonce' => $snonce ), $cookies );
$s = fresh();
t( 'Undo (restore of "Earlier versions"): the settings are back', 302 === $code && false !== strpos( $loc, 'pncp_message=restored' ) && 0 === (int) $s['skip_woo_pages'] && '/hub/space' === $s['content_paths'], $code . ' ' . $loc );

/* ---------- 5. Idempotence ---------- */
// Without WP Rocket (its proposal, the pre-cache check, writes wp-config.php).
deactivate_plugins( 'wp-rocket/wp-rocket.php', true );
$_SERVER['HTTP_VIA'] = '1.1 BunnyCDN';
$all                 = array_keys( PNCP_Wizard::proposals() );
$r1                  = PNCP_Wizard::apply( $all );
$s                   = fresh();
t( 'apply all: every proposal applied', is_array( $r1 ) && '' !== $r1['id'] && 1 === (int) $s['skip_woo_pages'] && 1 === (int) $s['trust_bunny'] && 60 === (int) $s['rate_limit_cart'] && 10 === (int) $s['rate_limit_coupon'] && '/hub/space' === $s['content_paths'], is_wp_error( $r1 ) ? $r1->get_error_message() : wp_json_encode( $r1 ) );
$count = count( PNCP_Settings_Io::backups() );
t( 'second run: nothing is proposed', array() === PNCP_Wizard::proposals(), implode( ',', array_keys( PNCP_Wizard::proposals() ) ) );
$r2 = PNCP_Wizard::apply( $all );
t( 'second apply: nothing saved, no new saved version', is_array( $r2 ) && '' === $r2['id'] && count( PNCP_Settings_Io::backups() ) === $count );
unset( $_SERVER['HTTP_VIA'] );
list( $code, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=general', null, $cookies, $bunny );
t( 'panel after: "Nothing to change", closed, no form', 200 === $code && false !== strpos( $body, 'pncp-wizard-none' ) && false === strpos( $body, 'id="pncp-wizard" open' ) && false === strpos( $body, 'class="pncp-wizard-form"' ) );

/* ---------- 6. WP-CLI ---------- */
if ( '' !== $wp_cli ) {
	settings( $start );
	activate_plugin( 'wp-rocket/wp-rocket.php', '', false, true );
	list( $rc, $out ) = cli( 'wizard --format=json' );
	$rows             = json_decode( $out, true );
	$keys             = is_array( $rows ) ? array_column( $rows, 'setting' ) : array();
	sort( $keys );
	t( 'cli wizard --format=json: the same proposals (no Bunny header in the CLI)', 0 === $rc && array( 'precheck', 'rate_limit_cart', 'rate_limit_coupon', 'skip_woo_pages' ) === $keys, $out );
	list( $rc, $out ) = cli( 'wizard' );
	t( 'cli wizard: table with the reasons and the notes, nothing saved', 0 === $rc && false !== strpos( $out, 'Found on this site:' ) && false !== strpos( $out, 'skip_woo_pages' ) && false !== strpos( $out, '- OneSignal:' ) && 0 === (int) fresh()['skip_woo_pages'], $out );
	$count = count( PNCP_Settings_Io::backups() );
	list( $rc, $out ) = cli( 'wizard --apply --yes' );
	$s                = fresh();
	t( 'cli wizard --apply --yes: only those that block nothing more', 0 === $rc && 1 === (int) $s['skip_woo_pages'] && '/hub/space' === $s['content_paths'] && 0 === (int) $s['precheck'] && 0 === (int) $s['rate_limit_cart'], $out );
	t( 'cli: a saved version first', count( PNCP_Settings_Io::backups() ) === min( PNCP_Settings_Io::KEEP, $count + 1 ) && 'wizard' === PNCP_Settings_Io::backups()[0]['reason'] );
	list( $rc, $out ) = cli( 'wizard --apply --yes' );
	t( 'cli: again → nothing to change', 0 === $rc && false !== strpos( $out, 'Nothing to change' ), $out );
	list( $rc, $out ) = cli( 'wizard --apply --yes --only=rate_limit_coupon' );
	$s                = fresh();
	t( 'cli --only=rate_limit_coupon: only that one', 0 === $rc && 10 === (int) $s['rate_limit_coupon'] && 0 === (int) $s['rate_limit_cart'], $out );
	list( $rc ) = cli( 'wizard --apply --yes --only=enabled' );
	t( 'cli --only with a setting that is not proposed: error', 0 !== $rc );
} else {
	echo "skip WP-CLI part (no WP_CLI)\n";
}

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
