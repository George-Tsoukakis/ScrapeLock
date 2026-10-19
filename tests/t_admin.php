<?php
/**
 * ScrapeLock — σελίδα ρυθμίσεων, διακόπτης, προφίλ, token, αρχείο, εργαλείο εικόνων, κανόνες,
 * GraphQL και διαγραφή, σε πραγματικό WordPress μέσα από HTTP (με cookie διαχειριστή).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_admin.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
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
}

/* ---------- Σύνδεση διαχειριστή ---------- */
$admin   = get_user_by( 'id', 1 );
$expire  = time() + DAY_IN_SECONDS;
$manager = WP_Session_Tokens::get_instance( $admin->ID );
$token   = $manager->create( $expire );
$cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( $admin->ID, $expire, 'auth', $token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( $admin->ID, $expire, 'logged_in', $token ),
);
// Ίδια συνεδρία και στο CLI, ώστε τα nonces να ταιριάζουν με τον server.
$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
wp_set_current_user( $admin->ID );

function http( $path, $post = null, $follow = false, $headers = null ) {
	global $base, $cookies;
	$ch   = curl_init( $base . $path );
	$jar  = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_HTTPHEADER     => null !== $headers ? $headers : array( 'X-Test-IP: 192.0.2.200', 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: el' ),
		CURLOPT_FOLLOWLOCATION => $follow,
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
	$headers = substr( $out, 0, $hs );
	$loc     = preg_match( '/^location:\s*(\S+)/mi', $headers, $m ) ? $m[1] : '';
	return array( $code, substr( $out, $hs ), $loc );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

settings( array( 'enabled' => 1, 'private_paths' => '/skroutz.xml' ) );
update_option( 'pncp_emergency_until', 0 );

/* ---------- Όλες οι καρτέλες ---------- */
$page = '/wp-admin/options-general.php?page=scrapelock';
foreach ( array( 'general', 'bots', 'content', 'images', 'rules', 'log' ) as $tab ) {
	list( $code, $body ) = http( $page . '&tab=' . $tab );
	t( "καρτέλα $tab: 200 χωρίς PHP warnings", 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'nav-tab-active' ), (string) $code );
}
list( , $body ) = http( $page . '&tab=general' );
t( 'προφίλ: τρία κουμπιά', 3 === substr_count( $body, 'name="profile"' ) );
t( 'Emergency Mode: φόρμα έναρξης', false !== strpos( $body, 'value="pncp_emergency"' ) );
list( , $body ) = http( '/wp-admin/index.php' );
t( 'Πίνακας ελέγχου: widget με σύνοψη 24ώρου', false !== strpos( $body, 'pncp-summary' ) && ! php_errors( $body ) );
t( 'Πίνακας ελέγχου: μήνυμα Trusted Proxy όταν ισχύει η συμπεριφορά της 1.4', ! empty( PNCP_Options::stored()['trust_any_proxy'] ) === ( false !== strpos( $body, 'Trusted Proxy settings' ) ) );

/* ---------- Απενεργοποίηση: πάντα με επιβεβαίωση ---------- */
$toggle = html_entity_decode( wp_nonce_url( admin_url( 'admin-post.php?action=pncp_toggle&state=off' ), 'pncp_toggle' ) );
list( $code, , $loc ) = http( wp_parse_url( $toggle, PHP_URL_PATH ) . '?' . wp_parse_url( $toggle, PHP_URL_QUERY ) );
PNCP_Options::flush();
wp_cache_delete( 'alloptions', 'options' );
t( 'GET απενεργοποίησης (π.χ. κλικ στη μπάρα): πάει σε επιβεβαίωση, η προστασία μένει', 302 === $code && false !== strpos( $loc, 'pncp_confirm=disable' ) && ! empty( PNCP_Options::stored()['enabled'] ), "$code $loc" );
list( , $body ) = http( $page . '&pncp_confirm=disable' );
t( 'σελίδα επιβεβαίωσης με κουμπί POST', false !== strpos( $body, 'Yes, disable' ) && false !== strpos( $body, 'name="state" value="off"' ) );
list( $code ) = http(
	'/wp-admin/admin-post.php',
	array(
		'action'   => 'pncp_toggle',
		'state'    => 'off',
		'_wpnonce' => wp_create_nonce( 'pncp_toggle' ),
	)
);
wp_cache_delete( 'alloptions', 'options' );
t( 'POST με nonce: απενεργοποίηση', 302 === $code && empty( PNCP_Options::stored()['enabled'] ), (string) $code );
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_toggle', 'state' => 'on', '_wpnonce' => 'wrong' ) );
wp_cache_delete( 'alloptions', 'options' );
t( 'λάθος nonce: τίποτα δεν αλλάζει', empty( PNCP_Options::stored()['enabled'] ), (string) $code );
$on = html_entity_decode( wp_nonce_url( admin_url( 'admin-post.php?action=pncp_toggle&state=on' ), 'pncp_toggle' ) );
http( wp_parse_url( $on, PHP_URL_PATH ) . '?' . wp_parse_url( $on, PHP_URL_QUERY ) );
wp_cache_delete( 'alloptions', 'options' );
t( 'ενεργοποίηση με ένα κλικ', ! empty( PNCP_Options::stored()['enabled'] ) );

/* ---------- Φόρμα καρτέλας: αλλάζουν μόνο τα πεδία της ---------- */
settings( array( 'rate_limit' => 77, 'block_selection' => 1, 'watermark_enabled' => 0 ) );
list( $code ) = http(
	'/wp-admin/options.php',
	array(
		'option_page'  => 'pncp_settings_group',
		'action'       => 'update',
		'_wpnonce'     => wp_create_nonce( 'pncp_settings_group' . '-options' ),
		'pncp_settings' => array(
			'_sections'          => array( 'images' ),
			'watermark_enabled'  => '1',
			'watermark_position' => 'tiled',
			'watermark_size'     => '30',
		),
	)
);
wp_cache_delete( 'alloptions', 'options' );
$s = PNCP_Options::stored();
t( 'φόρμα «Εικόνες»: αποθηκεύει τα δικά της πεδία', 302 === $code && 1 === (int) $s['watermark_enabled'] && 'tiled' === $s['watermark_position'] && 30 === (int) $s['watermark_size'], wp_json_encode( array( $code, $s['watermark_enabled'], $s['watermark_position'] ) ) );
t( 'φόρμα «Εικόνες»: δεν μηδενίζει τα checkbox άλλων καρτελών', 1 === (int) $s['block_selection'] && 1 === (int) $s['enabled'] && 77 === (int) $s['rate_limit'] );
settings( array( 'watermark_enabled' => 0, 'watermark_position' => 'br', 'watermark_size' => 25 ) );
$all = array();
foreach ( PNCP_Options::sections() as $keys ) {
	$all = array_merge( $all, $keys );
}
t( 'κάθε ρύθμιση ανήκει σε μία καρτέλα', array() === array_diff( array_keys( PNCP_Options::defaults() ), $all ) && count( $all ) === count( array_unique( $all ) ), implode( ',', array_diff( array_keys( PNCP_Options::defaults() ), $all ) ) );
$bad = PNCP_Options::sanitize(
	array(
		'_sections'       => array( 'bots' ),
		'trust_any_proxy' => '1',
		'allow_ips'       => "1.2.3.4\nnot-an-ip\n10.0.0.0/33\n2001:db8::/32",
		'ban_minutes'     => '-5',
		'log_retention'   => '365',
	)
);
t( 'sanitize: «εμπιστοσύνη σε κάθε proxy» δεν ανοίγει από τη φόρμα', empty( PNCP_Options::stored()['trust_any_proxy'] ) ? 0 === $bad['trust_any_proxy'] : true );
t( 'sanitize: μόνο έγκυρες IP/CIDR', "1.2.3.4\n2001:db8::/32" === $bad['allow_ips'], $bad['allow_ips'] );
t( 'sanitize: όρια αριθμών και επιλογών', 1 === $bad['ban_minutes'] && '7' === $bad['log_retention'] );

/* ---------- Προφίλ ---------- */
foreach ( array( 'strict', 'maximum', 'balanced' ) as $profile ) {
	http(
		'/wp-admin/admin-post.php',
		array(
			'action'   => 'pncp_profile',
			'profile'  => $profile,
			'_wpnonce' => wp_create_nonce( 'pncp_profile' ),
		)
	);
	wp_cache_delete( 'alloptions', 'options' );
	t( "προφίλ $profile: εφαρμόζεται και αναγνωρίζεται", PNCP_Options::current_profile( PNCP_Options::stored() ) === $profile );
}
t( 'προφίλ: δεν αγγίζει λίστες και feeds', '/skroutz.xml' === PNCP_Options::stored()['private_paths'] );

/* ---------- Token ---------- */
list( $code, , $loc ) = http(
	'/wp-admin/admin-post.php',
	array(
		'action'   => 'pncp_token',
		'op'       => 'rotate',
		'grace'    => '7',
		'_wpnonce' => wp_create_nonce( 'pncp_token' ),
	)
);
list( , $body ) = http( $page . '&tab=content' );
$shown = preg_match( '/id="pncp-token-value"[^>]*>([A-Za-z0-9]{40})</', $body, $m ) ? $m[1] : '';
t( 'νέο token: εμφανίζεται μία φορά', '' !== $shown && PNCP_Private_Urls::token_valid( $shown ) );
t( 'νέο token: URL για Skroutz με cp_token', false !== strpos( $body, 'skroutz.xml?cp_token=' . $shown ) );
list( , $body ) = http( $page . '&tab=content' );
t( 'νέο token: δεύτερη φορά δεν εμφανίζεται', '' !== $shown && false === strpos( $body, $shown ) );
t( 'νέο token: φαίνονται μόνο οι 4 τελευταίοι χαρακτήρες', false !== strpos( $body, '…' . substr( $shown, -4 ) ) );
t( 'περίοδος χάριτος: ειδοποίηση για το προηγούμενο', false !== strpos( $body, 'revoke_prev' ) );

/* ---------- Αρχείο, αποκλεισμοί, λίστες IP ---------- */
PNCP_Log::ban( '198.51.100.77', 30, 'trap' );
list( , $body ) = http( $page . '&tab=log' );
t( 'αρχείο: φαίνεται ο αποκλεισμός', false !== strpos( $body, '198.51.100.77' ) && false !== strpos( $body, 'Bot trap' ) );
http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_log', 'op' => 'unban', 'ip' => '198.51.100.77', '_wpnonce' => wp_create_nonce( 'pncp_log' ) ) );
wp_cache_flush(); PNCP_Log::reset_cache(); // Το CLI κρατά στη μνήμη ό,τι διάβασε πριν το αίτημα.
t( 'αρχείο: άρση ενός αποκλεισμού', ! PNCP_Log::is_banned( '198.51.100.77' ) && ! isset( PNCP_Log::active_bans()['198.51.100.77'] ) );
PNCP_Log::add( 'bot_ua', 403, '198.51.100.78' );
PNCP_Log::add( 'bot_ua', 403, '198.51.100.78' );
$sum = PNCP_Log::summary( 24 );
t( 'σύνοψη 24ώρου: ίδια IP και λόγος στο ίδιο λεπτό = μία γραμμή με μετρητή', isset( $sum['ips']['198.51.100.78'] ) && 2 === $sum['ips']['198.51.100.78'] );
global $wpdb;
$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->prefix}pncp_log SET created = %s WHERE ip = '198.51.100.78'", gmdate( 'Y-m-d H:i:s', time() - 8 * DAY_IN_SECONDS ) ) );
settings( array( 'log_retention' => '7' ) );
PNCP_Log::cleanup();
t( 'διατήρηση 7 ημερών: η εγγραφή 8 ημερών σβήστηκε', 0 === (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}pncp_log WHERE ip = '198.51.100.78'" ) );
PNCP_Ip::store_list( 'google', array( '66.249.64.0/27' ) );
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) {
		if ( false !== strpos( $url, 'api.cloudflare.com/client/v4/ips' ) ) {
			return array( 'response' => array( 'code' => 200 ), 'body' => '{"result":{"ipv4_cidrs":["173.245.48.0/20","103.21.244.0/22"],"ipv6_cidrs":["2400:cb00::/32"]},"success":true}' );
		}
		if ( false !== strpos( $url, 'bingbot.json' ) ) {
			return array( 'response' => array( 'code' => 200 ), 'body' => '{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"},{"ipv6Prefix":"2a01:111::/32"}]}' );
		}
		return new WP_Error( 'down', 'down' );
	},
	1,
	3
);
$prev_ip = PNCP_Options::get();
settings( array( 'ip_header' => 'remote_addr' ) );
t( 'λίστες IP: χωρίς Cloudflare proxy δεν κατεβαίνει η λίστα του Cloudflare', ! in_array( 'cloudflare', PNCP_Ip::needed_lists(), true ) );
settings( array( 'ip_header' => 'cf_connecting_ip', 'trust_cloudflare' => 1 ) );
$res = PNCP_Ip::refresh_lists();
PNCP_Ip::reset();
settings( array( 'ip_header' => $prev_ip['ip_header'], 'trust_cloudflare' => $prev_ip['trust_cloudflare'] ) );
t( 'λίστες IP: Cloudflare και Bing κατέβηκαν', 3 === $res['cloudflare'] && 2 === $res['bing'], wp_json_encode( $res ) );
t( 'λίστες IP: η Google απέτυχε και κράτησε την προηγούμενη', 0 === $res['google'] && array( '66.249.64.0/27' ) === PNCP_Ip::list_of( 'google' ) );
t( 'Bingbot από τη λίστα: επαληθευμένο', PNCP_Bots::is_verified_crawler( 'bing', '157.55.39.12' ) );

/* ---------- Εργαλείο εικόνων (AJAX) ---------- */
list( $code, $body ) = http( '/wp-admin/admin-ajax.php', array( 'action' => 'pncp_wm_batch', 'nonce' => 'bad', 'mode' => 'remove' ) );
t( 'εργαλείο: λάθος nonce 403', 403 === $code, (string) $code );
$cursor = 0;
$loops  = 0;
do {
	list( $code, $body ) = http( '/wp-admin/admin-ajax.php', array( 'action' => 'pncp_wm_batch', 'nonce' => wp_create_nonce( 'pncp_wm_batch' ), 'mode' => 'remove', 'cursor' => $cursor ) );
	$json   = json_decode( $body, true );
	$cursor = isset( $json['data']['cursor'] ) ? $json['data']['cursor'] : $cursor;
	++$loops;
} while ( ! empty( $json['success'] ) && empty( $json['data']['done'] ) && $loops < 100 );
t( 'εργαλείο «Αφαίρεση»: ολοκληρώνεται σε παρτίδες', ! empty( $json['data']['done'] ) && $loops > 1, $body );
t( 'εργαλείο «Αφαίρεση»: καμία εικόνα με υδατογράφημα μετά', 0 === (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->postmeta} WHERE meta_key = '_pncp_wm'" ) );
update_option( 'pncp_wm_cursor_remove', 5, false );
list( , $body ) = http( '/wp-admin/admin-ajax.php', array( 'action' => 'pncp_wm_batch', 'nonce' => wp_create_nonce( 'pncp_wm_batch' ), 'mode' => 'remove', 'cursor' => 0 ) );
$json = json_decode( $body, true );
t( 'εργαλείο: μετά από διακοπή συνεχίζει από εκεί που σταμάτησε', $json['data']['cursor'] > 5 );
delete_option( 'pncp_wm_cursor_remove' );

/* ---------- Κανόνες server ---------- */
$nginx = PNCP_Rules::nginx();
$cf    = PNCP_Rules::cloudflare();
t( 'Nginx: map για bots και limit_req_zone', false !== strpos( $nginx, 'map $http_user_agent $pncp_bad_bot' ) && false !== strpos( $nginx, 'limit_req_zone' ) );
t( 'Nginx: μπλοκάρει τον φάκελο πρωτοτύπων', false !== strpos( $nginx, (string) get_option( 'pncp_backup_dir' ) ) );
t( 'Nginx: hotlink με skroutz', false !== strpos( $nginx, 'valid_referers' ) && false !== strpos( $nginx, 'skroutz\.gr' ) );
t( 'Cloudflare rate limit: μόνο σελίδες, όχι αρχεία / καλάθι', false !== strpos( $cf['rate']['expression'], 'http.request.uri.path.extension in {"" "php" "html" "xml"}' ) && false !== strpos( $cf['rate']['expression'], 'wc-ajax=' ) );
t( 'Nginx: τα πάντα επιτρεπτά (previews) πριν από τη λίστα bots', strpos( $nginx, 'facebookexternalhit' ) < strpos( $nginx, 'GPTBot' ) );
t( 'Nginx: «curl/» με την κάθετο (ίδιο με το PHP)', false !== strpos( $nginx, 'curl/' ) );
t( 'Cloudflare: εξαιρεί τα επαληθευμένα bots', false !== strpos( $cf['bots']['expression'], 'not cf.client.bot' ) );
t( 'Cloudflare: έκφραση κάτω από 4096 χαρακτήρες', strlen( $cf['bots']['expression'] ) < 4096, (string) strlen( $cf['bots']['expression'] ) );
t( 'Cloudflare: δεν υπάρχει πουθενά token', false === strpos( wp_json_encode( $cf ) . $nginx . PNCP_Rules::apache(), $shown ) );
$regex = '';
foreach ( explode( "\n", $nginx ) as $line ) {
	if ( preg_match( '/^\s*"~\*(.+)" 1;$/', $line, $m ) ) {
		$regex = $m[1];
	}
}
t( 'Nginx: το regex των bots είναι έγκυρο και πιάνει GPTBot, όχι Chrome', '' !== $regex && preg_match( '#' . $regex . '#i', 'Mozilla/5.0 GPTBot/1.1' ) && ! preg_match( '#' . $regex . '#i', 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36' ) );

/* ---------- AI αναζήτηση χωριστά από την εκπαίδευση (2.2.1) ---------- */
$rx_of = function ( $conf, $flag ) {
	foreach ( explode( "\n", $conf ) as $line ) {
		if ( preg_match( '/^\s*"~\*(.+)" ' . $flag . ';$/', $line, $m ) ) {
			return $m[1];
		}
	}
	return '';
};
$oai = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.3; +https://openai.com/searchbot';
settings( array( 'allow_ai_search' => 0 ) );
$allow_rx = $rx_of( PNCP_Rules::nginx(), 0 );
t( 'AI αναζήτηση ανενεργή (προεπιλογή): OAI-SearchBot όχι στα επιτρεπτά του Nginx', '' === $allow_rx || ! preg_match( '#' . $allow_rx . '#i', $oai ) );
t( 'AI αναζήτηση: η επιλογή αποθηκεύεται από τη φόρμα (καρτέλα bots)', in_array( 'allow_ai_search', PNCP_Options::sections()['bots'], true ) );
settings( array( 'allow_ai_search' => 1 ) );
$nginx2   = PNCP_Rules::nginx();
$allow_rx = $rx_of( $nginx2, 0 );
t( 'AI αναζήτηση ενεργή: OAI-SearchBot στα επιτρεπτά του Nginx', '' !== $allow_rx && preg_match( '#' . $allow_rx . '#i', $oai ) );
t( 'AI αναζήτηση ενεργή: GPTBot όχι στα επιτρεπτά του Nginx', ! preg_match( '#' . $allow_rx . '#i', 'Mozilla/5.0 (compatible; GPTBot/1.2)' ) );
t( 'AI αναζήτηση ενεργή: Apache εξαιρεί το OAI-SearchBot', false !== strpos( PNCP_Rules::apache(), 'OAI\-SearchBot' ) || false !== strpos( PNCP_Rules::apache(), 'OAI-SearchBot' ) );
$rocket = PNCP_Bots::rocket_reject_ua( array() );
t( 'AI αναζήτηση ενεργή: WP Rocket δεν απορρίπτει το OAI-SearchBot, απορρίπτει το GPTBot', ! in_array( preg_quote( 'OAI-SearchBot', '#' ), $rocket, true ) && in_array( 'GPTBot', $rocket, true ) );
settings( array( 'allow_ai_search' => 0 ) );

/* ---------- Token της 1.x: ποτέ σε καθαρή μορφή (2.2.1) ---------- */
$hash_before = get_option( PNCP_Private_Urls::TOKEN_OPTION );
delete_option( 'pncp_legacy_token_notice' );
delete_option( 'pncp_legacy_token_migrated' );
$migrated = pncp_migrate_from_1x( array( 'private_token' => 'Old1xPlainToken0987654321', 'private_paths' => '/skroutz.xml' ) );
global $wpdb;
$plain = count( preg_grep( '/Old1xPlainToken0987654321/', (array) $wpdb->get_col( "SELECT option_value FROM {$wpdb->options}" ) ) );
t( 'Μετάβαση 1.x: το token δεν υπάρχει πουθενά στη βάση σε καθαρή μορφή', 0 === $plain && ! isset( $migrated['private_token'] ), "εγγραφές: $plain" );
t( 'Μετάβαση 1.x: το παλιό token ισχύει (hash)', PNCP_Private_Urls::token_valid( 'Old1xPlainToken0987654321' ) );
t( 'Μετάβαση 1.x: σημαία για το μήνυμα, όχι το token', '1' === (string) get_option( 'pncp_legacy_token_migrated' ) && false === get_option( 'pncp_legacy_token_notice' ) );
// Εγκατάσταση που αναβαθμίστηκε σε 2.1 / 2.2.0 και ο διαχειριστής δεν είδε ακόμη το μήνυμα.
delete_option( 'pncp_legacy_token_migrated' );
update_option( 'pncp_legacy_token_notice', 'Old1xPlainToken0987654321', false );
// Το drop-in της SQLite βγάζει Deprecated μέσα στο dbDelta (δικό του σφάλμα, όχι του plugin).
$er = error_reporting( error_reporting() & ~E_DEPRECATED );
pncp_upgrade();
error_reporting( $er );
t( 'Αναβάθμιση από 2.2.0: σβήνει το token που είχε μείνει σε καθαρή μορφή', false === get_option( 'pncp_legacy_token_notice' ) && '1' === (string) get_option( 'pncp_legacy_token_migrated' ) );
list( , $body ) = http( '/wp-admin/options-general.php?page=scrapelock' );
t( 'Μήνυμα: «δεν μπορεί πλέον να εμφανιστεί», χωρίς το token', false !== strpos( $body, 'can no longer be shown' ) && false === strpos( $body, 'Old1xPlainToken0987654321' ) );
t( 'Μήνυμα: εμφανίζεται μία φορά', null === $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name = 'pncp_legacy_token_migrated'" ) );
update_option( PNCP_Private_Urls::TOKEN_OPTION, $hash_before, false );

/* ---------- 2.4: νέα πεδία, Cloudflare ---------- */
$keep = PNCP_Options::stored();
list( , $body ) = http( $page . '&tab=bots' );
$missing = array();
foreach ( array( 'block_ips', 'block_referrers', 'block_user_enum', 'rate_limit_404', 'early_mode', 'content_signal', 'verify_ai_bots', 'block_headless', 'human_check', 'rate_limit_unverified', 'rate_limit_sitemap', 'geo_db', 'countries_block', 'countries_strict', 'rate_limit_country' ) as $key ) {
	if ( false === strpos( $body, 'name="pncp_settings[' . $key . ']"' ) ) {
		$missing[] = $key;
	}
}
t( 'καρτέλα bots: τα νέα πεδία της 2.4', ! $missing, implode( ',', $missing ) );
list( , $body ) = http( $page . '&tab=content' );
t( 'καρτέλα feeds: «first appeared on»', false !== strpos( $body, 'name="pncp_settings[feed_source_link]"' ) );
settings( array( 'feed_source_link' => 1 ) );
list( $code ) = http(
	'/wp-admin/options.php',
	array(
		'option_page'   => 'pncp_settings_group',
		'action'        => 'update',
		'_wpnonce'      => wp_create_nonce( 'pncp_settings_group' . '-options' ),
		'pncp_settings' => array(
			'_sections'       => array( 'bots' ),
			'block_bots'      => '1',
			'block_ips'       => "203.0.113.0/24\nόχι-IP",
			'block_referrers' => "Copy-Site.example\ncopy-site.example",
			'block_user_enum' => '1',
			'rate_limit_404'  => '99999',
			'ip_header'       => 'remote_addr',
		),
	)
);
wp_cache_delete( 'alloptions', 'options' );
$s = PNCP_Options::stored();
t( 'φόρμα bots: αποθηκεύει τα νέα πεδία (έγκυρες IP, χωρίς διπλά, όριο στο μέγιστο)', 302 === $code && '203.0.113.0/24' === $s['block_ips'] && 'copy-site.example' === strtolower( $s['block_referrers'] ) && 1 === (int) $s['block_user_enum'] && 10000 === (int) $s['rate_limit_404'], wp_json_encode( array( $code, $s['block_ips'], $s['block_referrers'], $s['rate_limit_404'] ) ) );
t( 'φόρμα bots: δεν αγγίζει τη γραμμή πηγής RSS (καρτέλα feeds)', 1 === (int) $s['feed_source_link'] );
update_option( PNCP_OPTION, $keep );
PNCP_Options::flush();

settings( array( 'ip_header' => 'remote_addr', 'trust_cloudflare' => 0 ) );
$cf_headers = array( 'X-Test-Remote-Addr: 173.245.48.10', 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: el' );
list( , $body ) = http( $page . '&tab=bots', null, false, $cf_headers );
t( 'Cloudflare χωρίς σωστή ρύθμιση IP: προειδοποίηση με κουμπί', false !== strpos( $body, 'value="pncp_cf_ip"' ) && ! php_errors( $body ) );
list( , $body ) = http( $page . '&tab=bots' );
t( 'χωρίς Cloudflare: καμία προειδοποίηση', false === strpos( $body, 'value="pncp_cf_ip"' ) );
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_cf_ip', '_wpnonce' => 'wrong' ), false, $cf_headers );
wp_cache_delete( 'alloptions', 'options' );
t( 'ένα κλικ Cloudflare: λάθος nonce, τίποτα δεν αλλάζει', 'remote_addr' === PNCP_Options::stored()['ip_header'], (string) $code );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_cf_ip', '_wpnonce' => wp_create_nonce( 'pncp_cf_ip' ) ), false, $cf_headers );
wp_cache_delete( 'alloptions', 'options' );
$s = PNCP_Options::stored();
t( 'ένα κλικ Cloudflare: CF-Connecting-IP και εμπιστοσύνη μόνο στην Cloudflare', 302 === $code && 'cf_connecting_ip' === $s['ip_header'] && 1 === (int) $s['trust_cloudflare'] && false !== strpos( $loc, 'pncp_message=cf_ip' ), "$code $loc" );
list( , $body ) = http( $page . '&tab=bots&pncp_message=cf_ip', null, false, array_merge( $cf_headers, array( 'CF-Connecting-IP: 198.51.100.99' ) ) );
t( 'ένα κλικ Cloudflare: μήνυμα επιτυχίας, η προειδοποίηση φεύγει, φαίνεται η IP του επισκέπτη', false !== strpos( $body, 'only for requests from Cloudflare' ) && false === strpos( $body, 'value="pncp_cf_ip"' ) && false !== strpos( $body, '<code>198.51.100.99</code>' ) );
list( , $body ) = http( $page . '&tab=rules', null, false, array_merge( $cf_headers, array( 'CF-Connecting-IP: 198.51.100.99' ) ) );
t( 'καρτέλα κανόνων πίσω από Cloudflare: σημείωση για APO', false !== strpos( $body, 'APO' ) );
list( , $body ) = http( $page . '&tab=rules' );
t( 'καρτέλα κανόνων χωρίς Cloudflare: χωρίς σημείωση APO', false === strpos( $body, 'APO and' ) );
update_option( PNCP_OPTION, $keep );
PNCP_Options::flush();

// 2.6: Bunny CDN. Οι κεφαλίδες CDN-ServerId / Via δείχνουν ότι το αίτημα ήρθε μέσω Bunny.
settings( array( 'ip_header' => 'remote_addr', 'trust_bunny' => 0 ) );
delete_option( PNCP_Ip::LISTS_OPTION . '_bunny' );
$bunny_headers = array( 'X-Test-Remote-Addr: 89.187.162.1', 'CDN-ServerId: 1330', 'Via: 1.1 BunnyCDN-DE1-1330', 'X-Real-IP: 198.51.100.77', 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: el', 'X-Test-Bunny-List: ["89.187.162.1","89.187.162.2"]' );
list( , $body ) = http( $page . '&tab=bots', null, false, $bunny_headers );
t( 'Bunny χωρίς σωστή ρύθμιση IP: προειδοποίηση με κουμπί', false !== strpos( $body, 'value="pncp_bunny_ip"' ) && ! php_errors( $body ) );
t( 'Bunny: η επιλογή «Trust Bunny CDN addresses» υπάρχει', false !== strpos( $body, 'name="pncp_settings[trust_bunny]"' ) );
list( , $body ) = http( $page . '&tab=bots' );
t( 'χωρίς Bunny: καμία προειδοποίηση', false === strpos( $body, 'value="pncp_bunny_ip"' ) );
list( , $body ) = http( $page . '&tab=bots', null, false, array( 'X-Test-Remote-Addr: 198.51.100.77', 'CDN-ServerId: 1330', 'X-Real-IP: 198.51.100.77' ) );
t( 'Bunny με real_ip στο nginx: σημείωση ότι το REMOTE_ADDR είναι σωστό, χωρίς κουμπί', false !== strpos( $body, 'Bunny CDN detected' ) && false === strpos( $body, 'value="pncp_bunny_ip"' ) );
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_bunny_ip', '_wpnonce' => 'wrong' ), false, $bunny_headers );
wp_cache_delete( 'alloptions', 'options' );
t( 'ένα κλικ Bunny: λάθος nonce, τίποτα δεν αλλάζει', 'remote_addr' === PNCP_Options::stored()['ip_header'], (string) $code );
list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_bunny_ip', '_wpnonce' => wp_create_nonce( 'pncp_bunny_ip' ) ), false, $bunny_headers );
wp_cache_delete( 'alloptions', 'options' );
$s = PNCP_Options::stored();
t( 'ένα κλικ Bunny: X-Real-IP, εμπιστοσύνη στο Bunny και λίστα που κατέβηκε', 302 === $code && 'x_real_ip' === $s['ip_header'] && 1 === (int) $s['trust_bunny'] && false !== strpos( $loc, 'pncp_message=bunny_ip' ) && false === strpos( $loc, 'bunny_ip_failed' ) && array( '89.187.162.1', '89.187.162.2', '2400:52e0:1a00::1' ) === get_option( PNCP_Ip::LISTS_OPTION . '_bunny' ), "$code $loc" );
list( , $body ) = http( $page . '&tab=bots&pncp_message=bunny_ip', null, false, $bunny_headers );
t( 'ένα κλικ Bunny: μήνυμα επιτυχίας, η προειδοποίηση φεύγει, φαίνεται η IP του επισκέπτη', false !== strpos( $body, 'only for requests from Bunny CDN' ) && false === strpos( $body, 'value="pncp_bunny_ip"' ) && false !== strpos( $body, '<code>198.51.100.77</code>' ) );
t( 'Bunny: η λίστα φαίνεται στις επίσημες λίστες', false !== strpos( $body, 'Bunny CDN:</strong>' ) );
delete_option( PNCP_Ip::LISTS_OPTION . '_bunny' );
update_option( PNCP_OPTION, $keep );
PNCP_Options::flush();

/* ---------- 2.6: νέα σελίδα ρυθμίσεων ---------- */
list( , $body ) = http( $page . '&tab=bots' );
t( 'bots: γρήγοροι σύνδεσμοι στις ενότητες', false !== strpos( $body, 'pncp-section-nav' ) && false !== strpos( $body, 'href="#pncp-sec-human"' ) && false !== strpos( $body, 'id="pncp-sec-human"' ) && false !== strpos( $body, 'id="pncp-sec-countries"' ) && false !== strpos( $body, 'id="pncp-sec-lists"' ) );
t( 'bots: διακόπτες (toggle) αντί για απλά κουτάκια', false !== strpos( $body, 'class="pncp-toggle" id="pncp-block_bots"' ) );
t( 'bots: η λίστα bots διπλωμένη, με αριθμό γραμμών', 1 === preg_match( '#<details class="pncp-fold"><summary>[^<]*<span class="pncp-badge">\d+ (entry|entries)#', $body ) );
t( 'bots: κατάσταση χωρών και αναφορά στη DB-IP', false !== strpos( $body, 'Country of this request' ) && false !== strpos( $body, 'https://db-ip.com' ) );
t( 'κάθε καρτέλα: κατάσταση προστασίας πάνω', false !== strpos( $body, 'pncp-status-bar' ) && false !== strpos( $body, 'pncp-pill' ) );
t( 'bots: το κουμπί αποθήκευσης μέσα στη φόρμα ρυθμίσεων', false !== strpos( $body, 'class="pncp-settings-form"' ) );
settings( array( 'geo_db' => 0 ) );
list( , $body ) = http( $page . '&tab=bots' );
t( 'βάση χωρών ανενεργή: χωρίς κουμπί λήψης', false === strpos( $body, 'value="refresh_geo"' ) );
settings( array( 'geo_db' => 1 ) );
list( , $body ) = http( $page . '&tab=bots' );
t( 'βάση χωρών ενεργή: κουμπί «Download now»', false !== strpos( $body, 'value="refresh_geo"' ) );
settings( array( 'geo_db' => 0 ) );
list( $code ) = http( '/wp-admin/options.php', array( 'option_page' => 'pncp_settings_group', 'action' => 'update', '_wpnonce' => wp_create_nonce( 'pncp_settings_group-options' ), 'pncp_settings' => array( '_sections' => array( 'bots' ), 'countries_block' => 'cn, ru;xx1 GR gr', 'human_check' => '1', 'rate_limit_unverified' => '15', 'ip_header' => 'remote_addr' ) ) );
wp_cache_delete( 'alloptions', 'options' );
$s = PNCP_Options::stored();
t( 'φόρμα bots: χώρες καθαρές, επαλήθευση ανθρώπου', 302 === $code && "CN\nRU\nGR" === $s['countries_block'] && 1 === (int) $s['human_check'] && 15 === (int) $s['rate_limit_unverified'], wp_json_encode( array( $code, $s['countries_block'], $s['human_check'] ) ) );
update_option( PNCP_OPTION, $keep );
PNCP_Options::flush();
list( , $body ) = http( $page . '&tab=log' );
t( 'Log: αναφορά «τι προσπαθούν να αντιγράψουν» για 24 ώρες και 7 ημέρες', false !== strpos( $body, 'What they try to copy' ) && false !== strpos( $body, 'Last 7 days' ) && ! php_errors( $body ) );
foreach ( array( 'general', 'content', 'images', 'rules' ) as $tab ) {
	list( $code, $body ) = http( $page . '&tab=' . $tab );
	t( "καρτέλα $tab: νέα εμφάνιση χωρίς PHP warnings", 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'pncp-status-bar' ), (string) $code );
}

/* ---------- Κανόνας 11 του WordPress.org: μόνιμες ειδοποιήσεις μόνο στον Πίνακα ελέγχου και στη σελίδα του plugin ---------- */
$keep_notice = PNCP_Options::stored();
PNCP_Options::set_emergency( 1 );
settings( array( 'trust_any_proxy' => 1 ) );
list( , $body ) = http( '/wp-admin/index.php' );
t( 'ειδοποιήσεις: στον Πίνακα ελέγχου εμφανίζονται', false !== strpos( $body, 'Emergency Mode is on.' ) && false !== strpos( $body, 'without checking the proxy' ) );
list( , $body ) = http( $page . '&tab=general' );
t( 'ειδοποιήσεις: στη σελίδα του ScrapeLock εμφανίζονται', false !== strpos( $body, 'Emergency Mode is on.' ) && false !== strpos( $body, 'without checking the proxy' ) );
list( , $body ) = http( '/wp-admin/edit.php' );
t( 'ειδοποιήσεις: στα Άρθρα δεν εμφανίζονται', false === strpos( $body, 'Emergency Mode is on.' ) && false === strpos( $body, 'without checking the proxy' ) && ! php_errors( $body ) );
list( , $body ) = http( '/wp-admin/plugins.php' );
t( 'ειδοποιήσεις: στα Πρόσθετα δεν εμφανίζονται', false === strpos( $body, 'Emergency Mode is on.' ) && false === strpos( $body, 'without checking the proxy' ) );
PNCP_Options::set_emergency( 0 );
update_option( PNCP_OPTION, $keep_notice );
PNCP_Options::flush();

/* ---------- GraphQL (χωρίς το plugin: με ψεύτικο μοντέλο) ---------- */
eval( 'namespace WPGraphQL\\Model; class Post { public $databaseId; public function __construct( $id ) { $this->databaseId = $id; } }' );
wp_set_current_user( 0 );
$src = new WPGraphQL\Model\Post( 5 );
t( 'GraphQL: content κενό για επισκέπτη', '' === PNCP_Graphql::resolve_field( '<p>κείμενο</p>', $src, array(), null, null, 'Post', 'content' ) );
t( 'GraphQL: title δεν αλλάζει', 'Τίτλος' === PNCP_Graphql::resolve_field( 'Τίτλος', $src, array(), null, null, 'Post', 'title' ) );
t( 'GraphQL: περιγραφή όρου (όχι άρθρο) δεν αλλάζει', 'x' === PNCP_Graphql::resolve_field( 'x', new stdClass(), array(), null, null, 'Category', 'description' ) );
settings( array( 'excluded_ids' => '5' ) );
t( 'GraphQL: εξαιρεμένο ID', '<p>κείμενο</p>' === PNCP_Graphql::resolve_field( '<p>κείμενο</p>', $src, array(), null, null, 'Post', 'content' ) );
settings( array( 'excluded_ids' => '' ) );
wp_set_current_user( 1 );
t( 'GraphQL: διαχειριστής βλέπει το κείμενο', '<p>κείμενο</p>' === PNCP_Graphql::resolve_field( '<p>κείμενο</p>', $src, array(), null, null, 'Post', 'content' ) );

echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
