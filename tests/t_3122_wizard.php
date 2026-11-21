<?php
/**
 * ScrapeLock 3.12.2 — "For my site" (PNCP_Wizard) shows settings by their label only, in real WordPress (stand-in
 * WooCommerce, only its header; Bunny CDN by its Via header):
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_3122_wizard.php
 *
 * 1. The panel with the 3.11 proposals (Bunny, WooCommerce) and the 3.12.1 sensible values (probe_ban,
 *    block_ip_host, reputation, the two-setting block row, rate_limit, blur_on_capture…): no setting key in its
 *    visible text, each row's label is shown, each key is in the
 *    title and the aria-label of a "?" button of its row (type="button", keyboard-reachable, not disabled), and
 *    both keys of the block row; the Now / Proposed cells have no key either.
 * 2. "Apply selected" over HTTP, then the page it goes back to: the success notice lists every changed setting by
 *    its label with "before → after" in words, the keys only in tooltips.
 * 3. Every admin tab: no setting key (any key of the settings with "_") in the visible text outside code, pre and
 *    form fields, with the proposals and the notice on screen.
 * 4. wp scrapelock wizard (WP_CLI given): still prints the keys (scripts read them), in table and JSON.
 *
 * Settings, saved versions and stand-ins are put back at the end. Only on a test WordPress.
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

/** An HTTP request as a signed-in user; [code, body, location]. */
function http( $path, $post = null, $cookies = array(), $extra = array() ) {
	global $base;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => array_merge( array( 'X-Test-IP: 192.0.2.215', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 'Accept-Language: en' ), $extra ),
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

function nonce_for( $user_id, $cookies, $action ) {
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $user_id );
	return wp_create_nonce( $action );
}

/** The visible text of some HTML: no scripts, styles, form fields, code or attributes. */
function visible( $html, $keep_code = false ) {
	$drop = $keep_code ? 'script|style|textarea|select|template' : 'script|style|textarea|select|template|code|pre|kbd';
	$html = (string) preg_replace( '#<(' . $drop . ')\b[^>]*>.*?</\1>#is', ' ', (string) $html );
	return html_entity_decode( (string) preg_replace( '/\s+/', ' ', wp_strip_all_tags( $html ) ), ENT_QUOTES );
}

/** The wizard panel of a page ('' when there is none). */
function panel_of( $body ) {
	$start = strpos( $body, '<details class="pncp-card pncp-wizard"' );
	if ( false === $start ) {
		return '';
	}
	// Its own </details>: the help texts inside it fold under "More" (<details> too).
	$depth = 0;
	$pos   = $start;
	while ( preg_match( '#<details\b|</details>#i', $body, $m, PREG_OFFSET_CAPTURE, $pos ) ) {
		$depth += '</details>' === strtolower( $m[0][0] ) ? -1 : 1;
		$pos    = $m[0][1] + strlen( $m[0][0] );
		if ( 0 === $depth ) {
			return substr( $body, $start, $pos - $start );
		}
	}
	return '';
}

/** The setting keys found as words in a text. */
function keys_in( $text, $keys ) {
	$found = array();
	foreach ( $keys as $k ) {
		if ( preg_match( '/(?<![A-Za-z0-9_-])' . preg_quote( $k, '/' ) . '(?![A-Za-z0-9_-])/', $text ) ) {
			$found[] = $k;
		}
	}
	return $found;
}

/* ---------- Setup ---------- */
$stand_ins = array( 'woocommerce/woocommerce.php' );
$created   = array();
foreach ( $stand_ins as $file ) {
	$dir = WP_PLUGIN_DIR . '/' . dirname( $file );
	if ( ! file_exists( WP_PLUGIN_DIR . '/' . $file ) ) {
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir );
			$created[ $file ] = 'dir';
		} else {
			$created[ $file ] = 'file';
		}
		file_put_contents( WP_PLUGIN_DIR . '/' . $file, "<?php\n/*\nPlugin Name: " . dirname( $file ) . " (test stand-in)\nVersion: 0.0.1\n*/\n" );
	}
}
$saved         = PNCP_Options::stored();
$saved_backups = get_option( PNCP_Settings_Io::BACKUPS, null );
register_shutdown_function(
	static function () use ( $stand_ins, $created, $saved, $saved_backups ) {
		deactivate_plugins( $stand_ins, true );
		foreach ( $created as $file => $what ) {
			@unlink( WP_PLUGIN_DIR . '/' . $file );
			if ( 'dir' === $what ) {
				@rmdir( WP_PLUGIN_DIR . '/' . dirname( $file ) );
			}
		}
		update_option( PNCP_OPTION, $saved );
		PNCP_Options::flush();
		if ( null === $saved_backups ) {
			delete_option( PNCP_Settings_Io::BACKUPS );
		} else {
			update_option( PNCP_Settings_Io::BACKUPS, $saved_backups, false );
		}
	}
);
activate_plugin( 'woocommerce/woocommerce.php', '', false, true );
$bad = array(
	'enabled'          => 1,
	'monitor_mode'     => 0,
	'probe_ban'        => 0,
	'block_ip_host'    => 0,
	'reputation'       => 0,
	'ban_strikes'      => 3,
	'ban_minutes'      => 600,
	'human_check'      => 1,
	'rate_limit'       => 20,
	'blur_on_capture'  => 1,
	'block_devtools'   => 1,
	'user_mark_guests' => 1,
	'skip_woo_pages'   => 0,
	'rate_limit_cart'  => 0,
	'trust_bunny'      => 0,
	'ip_header'        => 'remote_addr',
	'precheck'         => 0,
	'early_mode'       => 0,
);
settings( $bad );
$bunny = array( 'Via: 1.1 BunnyCDN' );

// The keys of the settings with "_" (a key without one, such as "reputation", is also a word of its label: those are
// checked by their tooltip).
$snake_keys = array_values(
	array_filter(
		array_keys( PNCP_Options::defaults() ),
		static function ( $k ) {
			return false !== strpos( $k, '_' );
		}
	)
);

/* ---------- 1. The panel ---------- */
$admin   = get_user_by( 'id', 1 );
$cookies = cookies_for( $admin->ID );
$page    = '/wp-admin/options-general.php?page=scrapelock&tab=general';
$_SERVER['HTTP_VIA'] = '1.1 BunnyCDN'; // The same environment for proposals() here as for the page.
$proposals           = PNCP_Wizard::proposals( null, PNCP_Wizard::detect() );
unset( $_SERVER['HTTP_VIA'] );
$want = array( 'probe_ban', 'block_ip_host', 'reputation', 'ban_strikes', 'rate_limit', 'blur_on_capture', 'skip_woo_pages', 'trust_bunny' );
t( 'proposals: the sensible values and the plugin / CDN rows are proposed', ! array_diff( $want, array_keys( $proposals ) ), implode( ',', array_keys( $proposals ) ) );
list( $code, $body ) = http( $page, null, $cookies, $bunny );
$panel = panel_of( $body );
t( 'panel: 200, no PHP warnings, with rows', 200 === $code && ! php_errors( $body ) && false !== strpos( $panel, 'pncp-wizard-row' ), (string) $code );
$text = visible( $panel, true );
$hits = keys_in( $text, $snake_keys );
t( 'panel: no setting key in the visible text (code included)', ! $hits, implode( ', ', $hits ) );
t( 'panel: no snake_case word at all in the visible text', ! preg_match( '/\b[a-z]+(?:_[a-z0-9]+)+\b/', $text, $m ), isset( $m[0] ) ? $m[0] : '' );
t( 'panel: no <code> with a key', ! preg_match( '#<code>[a-z_, ]+</code>#', $panel ) );
preg_match_all( '#<tr class="pncp-wizard-row[^"]*">.*?</tr>#s', $panel, $trs );
foreach ( $proposals as $key => $row ) {
	$names = implode( ', ', array_merge( array( $key ), array_keys( isset( $row['also'] ) ? $row['also'] : array() ) ) );
	$label = PNCP_Wizard::label( $key );
	$tr = '';
	foreach ( $trs[0] as $one ) {
		if ( false !== strpos( $one, 'value="' . $key . '"' ) ) {
			$tr = $one;
		}
	}
	if ( '' === $tr ) {
		t( "panel: row $key", false, 'no row' );
		continue;
	}
	$btn = preg_match( '#<button type="button" class="pncp-key-hint" title="([^"]*)" aria-label="([^"]*)" data-key="([^"]*)">#', $tr, $bm ) ? $bm : array();
	t(
		"panel: row $key: the label \"$label\", the key only in the title and aria-label of its \"?\" button",
		false !== strpos( visible( $tr ), $label ) && $btn && $names === html_entity_decode( $btn[1] ) && false !== strpos( html_entity_decode( $btn[2] ), $names ) && ( false === strpos( $key, '_' ) || ! keys_in( visible( $tr, true ), array( $key ) ) ),
		$btn ? $btn[0] : substr( $tr, 0, 400 )
	);
}
t( 'panel: the block row has both keys in its tooltip', false !== strpos( $panel, 'title="ban_strikes, ban_minutes"' ) && false !== strpos( $panel, 'aria-label="Internal names of these settings: ban_strikes, ban_minutes"' ) );
t( 'panel: a single key is named in the singular', false !== strpos( $panel, 'aria-label="Internal name of this setting: probe_ban"' ) );
t( 'panel: the "?" buttons are reachable by keyboard (no tabindex="-1", not disabled) and do not submit', 0 === preg_match( '#<button[^>]*pncp-key-hint[^>]*(tabindex="-1"|disabled)#', $panel ) && 0 === preg_match( '#<button(?![^>]*type="button")[^>]*pncp-key-hint#', $panel ) );
t( 'panel: the "?" itself is hidden from screen readers (the aria-label is read)', false !== strpos( $panel, '<span aria-hidden="true">?</span></button>' ) );
// The Now / Proposed cells.
preg_match_all( '#<tr class="pncp-wizard-row[^"]*">.*?</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>#s', $panel, $cells );
$cell_hits = keys_in( implode( ' | ', array_merge( $cells[1], $cells[2] ) ), $snake_keys );
t( 'panel: the Now / Proposed cells: values in words, no key', count( $cells[1] ) === count( $proposals ) && ! $cell_hits, count( $cells[1] ) . ' ' . implode( ',', $cell_hits ) );
$css = (string) file_get_contents( PNCP_DIR . 'assets/css/admin.css' );
t( 'admin.css: the tooltip also on keyboard focus', false !== strpos( $css, '.pncp-key-hint:focus-visible::after' ) && false !== strpos( $css, 'attr(data-key)' ) );

/* ---------- 2. Apply selected, and the notice ---------- */
$nonce = nonce_for( $admin->ID, $cookies, PNCP_Wizard::ACTION );
$keys  = array( 'probe_ban', 'reputation', 'ban_strikes', 'blur_on_capture', 'skip_woo_pages' );
list( $code, , $loc ) = http(
	'/wp-admin/admin-post.php',
	array(
		'action'           => PNCP_Wizard::ACTION,
		'_wpnonce'         => $nonce,
		'pncp_wizard_keys' => $keys,
	),
	$cookies,
	$bunny
);
t( 'Apply selected: back to the panel with "applied"', 302 === $code && false !== strpos( $loc, 'pncp_wizard=applied' ), $code . ' ' . $loc );
$path = (string) wp_parse_url( $loc, PHP_URL_PATH ) . '?' . (string) wp_parse_url( $loc, PHP_URL_QUERY );
list( $code, $body ) = http( $path, null, $cookies, $bunny );
$notice = preg_match( '#<div class="notice notice-success inline pncp-wizard-result">.*?</div>#s', $body, $nm ) ? $nm[0] : '';
$ntext  = visible( $notice, true );
t( 'notice: shown, without PHP warnings', 200 === $code && '' !== $notice && ! php_errors( $body ), (string) $code );
$changed = array( 'probe_ban', 'reputation', 'ban_minutes', 'blur_on_capture', 'skip_woo_pages' );
$listed  = true;
foreach ( $changed as $key ) {
	$listed = $listed && false !== strpos( $ntext, PNCP_Wizard::label( $key ) ) && false !== strpos( $notice, 'title="' . $key . '"' );
}
t( 'notice: every changed setting by its label, its key in the tooltip', $listed, $ntext );
$li = static function ( $key ) use ( $notice ) {
	return preg_match( '#<li>[^<]*<button[^>]*title="' . preg_quote( $key, '#' ) . '".*?</li>#s', $notice, $lm ) ? visible( $lm[0], true ) : '';
};
t( 'notice: before → after in words (Off → On; 600 → 120)', PNCP_Wizard::label( 'probe_ban' ) . ' ?: Off → On' === $li( 'probe_ban' ) && false !== strpos( $li( 'ban_minutes' ), '600 → 120' ), $li( 'probe_ban' ) . ' | ' . $li( 'ban_minutes' ) );
$nhits = keys_in( $ntext, $snake_keys );
t( 'notice: no setting key in its visible text', ! $nhits, implode( ', ', $nhits ) );
t( 'notice: shown once (the list is not kept)', false === strpos( http( $path, null, $cookies, $bunny )[1], 'pncp-wizard-done' ) );

/* ---------- 3. Every admin tab ---------- */
settings( $bad );
$bad_tabs = array();
foreach ( array( 'general', 'bots', 'content', 'images', 'rules', 'log', 'traffic', 'attacks', 'hardening', 'lockdown' ) as $tab ) {
	list( $code, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=' . $tab, null, $cookies, $bunny );
	$found = keys_in( visible( $body ), $snake_keys );
	if ( 200 !== $code || $found ) {
		$bad_tabs[] = $tab . ' ' . $code . ': ' . implode( ', ', $found );
	}
}
t( 'every tab: no setting key in the visible text (outside code and form fields)', ! $bad_tabs, implode( ' | ', $bad_tabs ) );

/* ---------- 4. WP-CLI ---------- */
if ( '' !== $wp_cli ) {
	settings( $bad );
	$out  = (string) shell_exec( $wp_cli . ' scrapelock wizard --format=json 2>/dev/null' );
	$rows = json_decode( $out, true );
	$cli  = is_array( $rows ) ? array_column( $rows, 'setting' ) : array();
	t( 'wp scrapelock wizard --format=json: the keys in "setting"', in_array( 'probe_ban', $cli, true ) && in_array( 'ban_strikes', $cli, true ) && in_array( 'reputation', $cli, true ), $out );
	$out = (string) shell_exec( $wp_cli . ' scrapelock wizard 2>/dev/null' );
	t( 'wp scrapelock wizard (table): the keys', false !== strpos( $out, 'probe_ban' ) && false !== strpos( $out, 'block_ip_host' ), $out );
} else {
	echo "SKIP 4 wp scrapelock wizard: WP_CLI not given\n";
}

echo $fails ? "\n$fails FAIL\n" : "\nall PASS\n";
exit( $fails ? 1 : 0 );
