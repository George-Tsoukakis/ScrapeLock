<?php
/**
 * ScrapeLock — Κλείδωμα (Lockdown) με εφαρμογή authenticator, σε πραγματικό WordPress μέσα από HTTP
 * (διαχειριστής, editor, πελάτης) και από τον κώδικα (ό,τι κι αν προσπαθήσει ένα άλλο plugin).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_lockdown.php
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

/* ---------- Χρήστες και συνδέσεις ---------- */
foreach ( array( 'ld_editor', 'ld_customer', 'ld_newadmin', 'ld_shopper', 'ld_member', 'ld_member2' ) as $login ) {
	$old = get_user_by( 'login', $login );
	if ( $old ) {
		require_once ABSPATH . 'wp-admin/includes/user.php';
		wp_delete_user( $old->ID );
	}
}
$editor_id   = wp_insert_user( array( 'user_login' => 'ld_editor', 'user_pass' => wp_generate_password(), 'user_email' => 'ld_editor@example.com', 'role' => 'editor' ) );
$customer_id = wp_insert_user( array( 'user_login' => 'ld_customer', 'user_pass' => wp_generate_password(), 'user_email' => 'ld_customer@example.com', 'role' => 'subscriber' ) );
// Μέλος που ανεβάζει μόνο του περιεχόμενο (π.χ. αγγελίες, Hub): subscriber με δικαιώματα δημοσίευσης.
remove_role( 'ld_member' );
add_role( 'ld_member', 'LD Member', array( 'read' => true, 'level_0' => true, 'edit_posts' => true, 'publish_posts' => true, 'upload_files' => true, 'delete_posts' => true ) );
$member_id = wp_insert_user( array( 'user_login' => 'ld_member', 'user_pass' => wp_generate_password(), 'user_email' => 'ld_member@example.com', 'role' => 'ld_member' ) );

$sessions = array();
/** Σύνδεση χρήστη: cookies για το HTTP και ίδια συνεδρία στο CLI, ώστε τα nonces να ταιριάζουν. */
function as_user( $id ) {
	global $sessions, $cookies;
	if ( ! isset( $sessions[ $id ] ) ) {
		$expire           = time() + DAY_IN_SECONDS;
		$token            = WP_Session_Tokens::get_instance( $id )->create( $expire );
		$sessions[ $id ] = array(
			AUTH_COOKIE      => wp_generate_auth_cookie( $id, $expire, 'auth', $token ),
			LOGGED_IN_COOKIE => wp_generate_auth_cookie( $id, $expire, 'logged_in', $token ),
		);
	}
	$cookies                     = $sessions[ $id ];
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $id );
}

function http( $path, $post = null, $extra = array() ) {
	global $base, $cookies;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_HTTPHEADER     => array_merge( array( 'X-Test-IP: 192.0.2.201', 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: el' ), $extra ),
		CURLOPT_TIMEOUT        => 60,
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = is_array( $post ) ? http_build_query( $post ) : $post;
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

/** Ενέργεια της σελίδας Lockdown: επιστρέφει το μήνυμα της ανακατεύθυνσης (pncp_ld=…). */
function ld( $op, $fields = array() ) {
	list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array_merge( array( 'action' => 'pncp_lockdown', 'op' => $op, '_wpnonce' => wp_create_nonce( 'pncp_lockdown' ) ), $fields ) );
	fresh();
	return 302 === $code && preg_match( '/pncp_ld=(\w+)/', $loc, $m ) ? $m[1] : "http $code";
}

/** Ξαναδιαβάζει την κατάσταση (ο server την άλλαξε) — όπως ένα νέο αίτημα. */
function fresh() {
	wp_cache_flush();
	( function () {
		self::$state = null;
		self::$staff = array();
	} )->bindTo( null, 'PNCP_Lockdown' )();
}

/** Αλλάζει την κατάσταση από το test (π.χ. «το προηγούμενο βήμα του κωδικού δεν χρησιμοποιήθηκε»). */
function state_set( $changes ) {
	fresh();
	( function ( $changes ) {
		self::save( array_merge( self::state(), $changes ) );
	} )->bindTo( null, 'PNCP_Lockdown' )( $changes );
	fresh();
}

/** Ο τρέχων κωδικός της εφαρμογής, για νέο βήμα κάθε φορά (το test δεν περιμένει 30″). */
function app_code( $secret ) {
	state_set( array( 'last_step' => 0 ) );
	return PNCP_Totp::code( $secret, PNCP_Totp::step() );
}

function reset_fails( $ids ) {
	foreach ( $ids as $id ) {
		delete_site_transient( 'pncp_ld_fail_' . $id );
	}
	delete_site_transient( 'pncp_ld_fail_all' );
}

/* ---------- Καθαρή αρχή ---------- */
delete_site_option( PNCP_Lockdown::OPTION );
delete_site_option( PNCP_Lockdown::LOG_OPTION );
delete_metadata( 'user', 0, PNCP_Lockdown::PENDING_META, '', true );
reset_fails( array( 1, $editor_id ) );
fresh();
$page = '/wp-admin/options-general.php?page=scrapelock&tab=lockdown';

/* ---------- TOTP (RFC 6238, παράρτημα B) ---------- */
$rfc = PNCP_Totp::base32_encode( '12345678901234567890' );
t( 'TOTP: τα διανύσματα του RFC 6238', '287082' === PNCP_Totp::code( $rfc, PNCP_Totp::step( 59 ) ) && '081804' === PNCP_Totp::code( $rfc, PNCP_Totp::step( 1111111109 ) ) && '005924' === PNCP_Totp::code( $rfc, PNCP_Totp::step( 1234567890 ) ) && '353130' === PNCP_Totp::code( $rfc, PNCP_Totp::step( 20000000000 ) ) );
t( 'TOTP: ±1 βήμα (ρολόι κινητού), όχι ±2', false !== PNCP_Totp::verify( $rfc, PNCP_Totp::code( $rfc, 100 ), 0, 101 * 30 ) && false === PNCP_Totp::verify( $rfc, PNCP_Totp::code( $rfc, 100 ), 0, 102 * 30 ) );
t( 'TOTP: ο ίδιος κωδικός δεύτερη φορά απορρίπτεται', false === PNCP_Totp::verify( $rfc, PNCP_Totp::code( $rfc, 100 ), 100, 100 * 30 ) );

/* ---------- Σύνδεση εφαρμογής ---------- */
as_user( 1 );
list( $code, $body ) = http( $page );
t( 'καρτέλα Lockdown στις ρυθμίσεις του ScrapeLock: 200 χωρίς PHP warnings, κουμπί σύνδεσης', 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'Connect the app' ) && false !== strpos( $body, 'nav-tab nav-tab-active pncp-tab-lockdown' ), (string) $code );
t( 'καρτέλα Lockdown: προειδοποίηση «μόνο ένας τρόπος ξεκλειδώματος»', false !== strpos( $body, 'there is only one way to unlock' ) && false !== strpos( $body, 'wp-config.php' ) );
t( 'καρτέλα Lockdown: πλήρης αναφορά (τι κλειδώνει, τι δουλεύει, ποιοι λογαριασμοί)', false !== strpos( $body, 'What exactly is locked' ) && false !== strpos( $body, 'What keeps working' ) && 1 === preg_match( '/Staff accounts that keep only &quot;read&quot; while locked: [^<]*Administrator: \d+[^<]*Editor: \d+/', $body ) && 1 === preg_match( '/Accounts that keep working as usual while locked: [^<]*Subscriber: \d+[^<]*LD Member: 1/', $body ), preg_match( '/Staff accounts[^<]*|Accounts that keep[^<]*/', $body, $pncp_m ) ? $pncp_m[0] : '' );
t( 'ρόλοι: προεπιλογή = διαχείριση και περιεχόμενο site, όχι μέλη / συνδρομητές', array( 'administrator', 'editor', 'author', 'contributor' ) === array_values( array_intersect( array( 'administrator', 'editor', 'author', 'contributor', 'subscriber', 'ld_member' ), PNCP_Lockdown::frozen_roles() ) ) );
t( 'όχι ξεχωριστό μενού Lockdown', false === strpos( $body, 'toplevel_page_scrapelock-lockdown' ) );
list( , $body ) = http( '/' );
t( 'μπάρα: «Protection: ON» → «Lockdown»', 1 === preg_match( '/id=.wp-admin-bar-pncp-lockdown..*?dashicons-unlock[^<]*<\/span>Lockdown</s', $body ) && false !== strpos( $body, 'wp-admin-bar-pncp-toggle' ) );
as_user( $editor_id );
list( $code, $body ) = http( $page );
t( 'editor: χωρίς πρόσβαση στη σελίδα', false === strpos( $body, 'Connect the app' ) && false === strpos( $body, 'What exactly is locked' ), (string) $code );
t( 'editor: δεν μπορεί να συνδέσει εφαρμογή', 'http 403' === ld( 'setup' ) );

as_user( 1 );
t( 'έναρξη σύνδεσης', 'setup' === ld( 'setup' ) );
list( , $body ) = http( $page );
$secret = preg_match( '/<code class="pncp-ld-secret">([A-Z2-7 ]+)<\/code>/', $body, $m ) ? str_replace( ' ', '', $m[1] ) : '';
t( 'QR (otpauth://) και κλειδί για πληκτρολόγηση', 32 === strlen( $secret ) && false !== strpos( $body, 'data-pncp-qr="otpauth://totp/ScrapeLock:' ) && false !== strpos( $body, 'vendor/qrcode.js' ) );
t( 'το κλειδί στη βάση είναι κρυπτογραφημένο', false === strpos( (string) get_user_meta( 1, PNCP_Lockdown::PENDING_META, true ), $secret ) );
t( 'λάθος κωδικός: όχι σύνδεση', 'wrong' === ld( 'confirm', array( 'code' => '000000' ) ) && ! PNCP_Lockdown::configured() );
t( 'σωστός κωδικός: η εφαρμογή συνδέεται', 'connected' === ld( 'confirm', array( 'code' => PNCP_Totp::code( $secret, PNCP_Totp::step() ) ) ) && PNCP_Lockdown::configured() && ! PNCP_Lockdown::is_locked() );
list( , $body ) = http( $page );
preg_match_all( '/<li><code>([a-z0-9]{4}-[a-z0-9]{4})<\/code><\/li>/', $body, $m );
$recovery = $m[1];
t( '10 κωδικοί ανάκτησης, μία φορά', 10 === count( $recovery ) && false !== strpos( $body, 'Lock the site' ) );
t( 'ρόλοι: λίστα με κουτάκια, ο διαχειριστής πάντα (κλειδωμένο κουτάκι)', 1 === preg_match( '/value="administrator" checked=\'checked\' disabled=\'disabled\'/', $body ) && 1 === preg_match( '/value="ld_member"\s*>/', $body ) && 1 === preg_match( '/value="editor" checked=\'checked\'\s*>/', $body ) );
list( , $body ) = http( $page );
t( '… δεύτερη φορά δεν φαίνονται', false === strpos( $body, 'Your recovery codes' ) );
t( 'οι κωδικοί ανάκτησης αποθηκεύονται μόνο ως hash', false === strpos( wp_json_encode( get_site_option( PNCP_Lockdown::OPTION ) ), $recovery[0] ) );
reset_fails( array( 1 ) );

/* ---------- Κλείδωμα ---------- */
$used = PNCP_Totp::step();
state_set( array( 'last_step' => $used ) );
list( , $body ) = http( $page );
t( 'πρώτο κλείδωμα: κουτάκι «αποθήκευσα τους κωδικούς»', false !== strpos( $body, 'name="ack" value="1" required' ) );
$before = PNCP_Lockdown::state()['last_step'];
t( 'πρώτο κλείδωμα χωρίς το κουτάκι: όχι, και ο κωδικός δεν «καίγεται»', 'ack' === ld( 'lock', array( 'code' => PNCP_Totp::code( $secret, PNCP_Totp::step() + 1 ) ) ) && ! PNCP_Lockdown::is_locked() && PNCP_Lockdown::state()['last_step'] === $before );
t( 'κλείδωμα με κωδικό που χρησιμοποιήθηκε ήδη: όχι', 'wrong' === ld( 'lock', array( 'code' => PNCP_Totp::code( $secret, $used ), 'ack' => 1 ) ) && ! PNCP_Lockdown::is_locked() );
reset_fails( array( 1 ) );
t( 'κλείδωμα με τον κωδικό της εφαρμογής', 'locked' === ld( 'lock', array( 'code' => app_code( $secret ), 'ack' => 1 ) ) && PNCP_Lockdown::is_locked() && PNCP_Lockdown::state()['ack'] );

/* ---------- Κλειδωμένο: ο διαχειριστής δεν αλλάζει τίποτα ---------- */
foreach ( array( 'plugins.php', 'plugin-install.php', 'update-core.php', 'theme-editor.php', 'options-general.php', 'post-new.php', 'edit.php', 'users.php', 'user-new.php' ) as $screen ) {
	list( $code, $body ) = http( '/wp-admin/' . $screen );
	t( "κλειδωμένο: /wp-admin/$screen απαγορεύεται", 403 === $code || false !== strpos( $body, 'not allowed' ), (string) $code );
}
list( $code, $body ) = http( '/wp-admin/index.php' );
t( 'κλειδωμένο: ο Πίνακας ελέγχου ανοίγει, με ειδοποίηση', 200 === $code && false !== strpos( $body, 'This site is locked.' ) && ! php_errors( $body ), (string) $code );
list( $code, $body ) = http( $page );
t( 'κλειδωμένο: η καρτέλα Lockdown ανοίγει, με ξεκλείδωμα', 200 === $code && false !== strpos( $body, 'Until I lock it again' ) && ! php_errors( $body ), (string) $code );
t( 'κλειδωμένο: η αναφορά φαίνεται και τώρα, όχι η προειδοποίηση', false !== strpos( $body, 'What exactly is locked' ) && false === strpos( $body, 'there is only one way to unlock' ) && false !== strpos( $body, 'Lost your phone?' ) );
list( $code, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=bots' );
t( 'κλειδωμένο: κάθε άλλη καρτέλα δείχνει το Lockdown (οι άλλες γκρίζες)', 200 === $code && false !== strpos( $body, 'Until I lock it again' ) && false === strpos( $body, 'name="pncp_settings[rate_limit]"' ) && false !== strpos( $body, 'pncp-tab-locked' ) && false === strpos( $body, 'pncp-status-bar' ), (string) $code );
t( 'κλειδωμένο: Ρυθμίσεις → ScrapeLock υπάρχει στο μενού', false !== strpos( $body, 'options-general.php?page=scrapelock' ) );
t( 'κλειδωμένο: μπάρα «Protection: ON · Locked» με μόνο το Lockdown', false !== strpos( $body, 'Protection: ON · Locked' ) && 1 === preg_match( '/id=.wp-admin-bar-pncp-lockdown..*?dashicons-lock[^<]*<\/span>Lockdown</s', $body ) && false === strpos( $body, 'wp-admin-bar-pncp-toggle' ) && false === strpos( $body, 'wp-admin-bar-pncp-settings' ) );
list( $code ) = http( '/wp-admin/options.php', array( 'option_page' => 'general', 'action' => 'update', '_wpnonce' => wp_create_nonce( 'general-options' ), 'blogname' => 'Hacked' ) );
wp_cache_flush();
t( 'κλειδωμένο: Ρυθμίσεις → Γενικές δεν αποθηκεύονται', 'Hacked' !== get_option( 'blogname' ), (string) $code );
list( $code ) = http( '/wp-admin/admin-post.php', array( 'action' => 'pncp_toggle', 'state' => 'off', '_wpnonce' => wp_create_nonce( 'pncp_toggle' ) ) );
wp_cache_flush();
PNCP_Options::flush();
t( 'κλειδωμένο: η προστασία του ScrapeLock δεν απενεργοποιείται', ! empty( PNCP_Options::stored()['enabled'] ), (string) $code );
list( $code, $body ) = http( '/wp-json/wp/v2/posts', array( 'title' => 'x', 'status' => 'publish' ), array( 'X-WP-Nonce: ' . wp_create_nonce( 'wp_rest' ) ) );
t( 'κλειδωμένο: REST POST άρθρου απορρίπτεται', in_array( $code, array( 401, 403 ), true ), "$code " . substr( $body, 0, 80 ) );
list( $code, $body ) = http( '/wp-json/wp/v2/users/me', array( 'email' => 'evil@example.com' ), array( 'X-WP-Nonce: ' . wp_create_nonce( 'wp_rest' ) ) );
wp_cache_flush();
t( 'κλειδωμένο: REST αλλαγή email διαχειριστή απορρίπτεται', in_array( $code, array( 401, 403 ), true ) && 'evil@example.com' !== get_userdata( 1 )->user_email, (string) $code );
list( $code ) = http( '/', null, array( 'Sec-Fetch-Mode: navigate', 'Sec-Fetch-Dest: document' ) );
t( 'κλειδωμένο: το site ανοίγει κανονικά για τον διαχειριστή', 200 === $code, (string) $code );

/* ---------- Κλειδωμένο: τίποτα και από τον κώδικα (π.χ. ένα plugin που παραβιάστηκε) ---------- */
wp_set_current_user( 0 );
fresh();
$plugins = get_option( 'active_plugins' );
update_option( 'active_plugins', array() );
update_option( 'admin_email', 'evil@example.com' );
update_option( 'default_role', 'administrator' );
update_option( 'users_can_register', 1 );
wp_cache_flush();
t( 'κώδικας: τα ενεργά plugins δεν αλλάζουν', get_option( 'active_plugins' ) === $plugins );
t( 'κώδικας: email διαχείρισης, προεπιλεγμένος ρόλος, εγγραφές ίδια', 'evil@example.com' !== get_option( 'admin_email' ) && 'administrator' !== get_option( 'default_role' ) && ! get_option( 'users_can_register' ) );
$before = get_option( PNCP_OPTION );
update_option( PNCP_OPTION, array_merge( $before, array( 'enabled' => 0 ) ) );
wp_cache_flush();
t( 'κώδικας: οι ρυθμίσεις του ScrapeLock δεν αλλάζουν', get_option( PNCP_OPTION ) == $before );
$lock = get_site_option( PNCP_Lockdown::OPTION );
update_site_option( PNCP_Lockdown::OPTION, array_merge( $lock, array( 'locked' => false ) ) );
fresh();
t( 'κώδικας: το ίδιο το κλείδωμα δεν ανοίγει', PNCP_Lockdown::is_locked() );
( new WP_User( $customer_id ) )->set_role( 'administrator' );
fresh();
t( 'κώδικας: ένας πελάτης δεν γίνεται διαχειριστής', ! in_array( 'administrator', get_userdata( $customer_id )->roles, true ) );
( new WP_User( 1 ) )->set_role( 'subscriber' );
fresh();
t( 'κώδικας: ο διαχειριστής δεν υποβιβάζεται', in_array( 'administrator', get_userdata( 1 )->roles, true ) );
$new = wp_insert_user( array( 'user_login' => 'ld_newadmin', 'user_pass' => wp_generate_password(), 'user_email' => 'ld_newadmin@example.com', 'role' => 'administrator' ) );
fresh();
t( 'κώδικας: νέος διαχειριστής δεν δημιουργείται (ο χρήστης μένει χωρίς ρόλο)', ! is_wp_error( $new ) && ! in_array( 'administrator', get_userdata( $new )->roles, true ) && ! PNCP_Lockdown::is_staff( $new ) );
$shopper = wp_insert_user( array( 'user_login' => 'ld_shopper', 'user_pass' => wp_generate_password(), 'user_email' => 'ld_shopper@example.com', 'role' => 'subscriber' ) );
fresh();
t( 'κώδικας: εγγραφή πελάτη γίνεται κανονικά', ! is_wp_error( $shopper ) && in_array( 'subscriber', get_userdata( $shopper )->roles, true ) );
$member2 = wp_insert_user( array( 'user_login' => 'ld_member2', 'user_pass' => wp_generate_password(), 'user_email' => 'ld_member2@example.com', 'role' => 'ld_member' ) );
fresh();
t( 'κώδικας: νέο μέλος (ρόλος με δικαίωμα δημοσίευσης, όχι διαχείρισης) δημιουργείται κανονικά', ! is_wp_error( $member2 ) && in_array( 'ld_member', get_userdata( $member2 )->roles, true ) );
( new WP_User( $shopper ) )->set_role( 'ld_member' );
fresh();
t( 'κώδικας: συνδρομητής → μέλος (π.χ. από το plugin αγγελιών) επιτρέπεται', in_array( 'ld_member', get_userdata( $shopper )->roles, true ) );
( new WP_User( $member2 ) )->set_role( 'editor' );
fresh();
t( 'κώδικας: μέλος → editor όχι', ! in_array( 'editor', get_userdata( $member2 )->roles, true ) );
$hash   = get_userdata( $editor_id )->user_pass;
$mails  = array();
$record = function ( $pre, $atts ) use ( &$mails ) {
	$mails[] = $atts['to'];
	return false; // Χωρίς πραγματική αποστολή.
};
add_filter( 'pre_wp_mail', $record, 10, 2 );
wp_update_user( array( 'ID' => $editor_id, 'user_email' => 'evil2@example.com', 'user_pass' => 'NewPass123!' ) );
wp_cache_flush();
t( 'κώδικας: email και κωδικός του προσωπικού δεν αλλάζουν', 'ld_editor@example.com' === get_userdata( $editor_id )->user_email && get_userdata( $editor_id )->user_pass === $hash );
t( '… και κανένα παραπλανητικό email «άλλαξε»', array() === $mails, implode( ',', $mails ) );
wp_update_user( array( 'ID' => $customer_id, 'user_email' => 'ld_customer2@example.com' ) );
wp_cache_flush();
remove_filter( 'pre_wp_mail', $record, 10 );
t( 'κώδικας: ο πελάτης αλλάζει κανονικά το email του (και ενημερώνεται)', 'ld_customer2@example.com' === get_userdata( $customer_id )->user_email && in_array( 'ld_customer@example.com', $mails, true ), implode( ',', $mails ) );
t( 'κώδικας: «ξέχασα τον κωδικό» όχι για το προσωπικό, ναι για πελάτες', ! apply_filters( 'allow_password_reset', true, $editor_id ) && apply_filters( 'allow_password_reset', true, $customer_id ) );
t( 'κώδικας: κανένα application password για το προσωπικό', ! wp_is_application_passwords_available_for_user( get_userdata( 1 ) ) );
t( 'κώδικας: εγκαταστάσεις / ενημερώσεις / επεξεργασία αρχείων κλειστά', ! wp_is_file_mod_allowed( 'capability_update_core' ) && apply_filters( 'automatic_updater_disabled', false ) );
wp_set_current_user( $customer_id );
t( 'πελάτης: τα δικαιώματά του δεν αλλάζουν (read, το προφίλ του)', current_user_can( 'read' ) && current_user_can( 'edit_user', $customer_id ) );
wp_set_current_user( 1 );
t( 'διαχειριστής: μόνο read', current_user_can( 'read' ) && ! current_user_can( 'manage_options' ) && ! current_user_can( 'edit_posts' ) && ! current_user_can( 'edit_user', 1 ) );
t( 'διαχειριστής: το ScrapeLock τον βλέπει ακόμη ως διαχειριστή (εξαιρέσεις)', PNCP_Lockdown::can( 'manage_options' ) );

/* ---------- Κλειδωμένο: μέλος που ανεβάζει περιεχόμενο (π.χ. αγγελίες) ---------- */
fresh();
t( 'μέλος: δεν είναι «προσωπικό»', ! PNCP_Lockdown::is_staff( $member_id ) );
wp_set_current_user( $member_id );
t( 'μέλος: κρατά τα δικαιώματά του (δημοσίευση, ανέβασμα αρχείων)', current_user_can( 'edit_posts' ) && current_user_can( 'publish_posts' ) && current_user_can( 'upload_files' ) );
wp_set_current_user( 0 );
t( 'μέλος: «ξέχασα τον κωδικό» δουλεύει', apply_filters( 'allow_password_reset', true, $member_id ) );
as_user( $member_id );
list( $code, $body ) = http( '/wp-json/wp/v2/posts', array( 'title' => 'Αγγελία μέλους', 'status' => 'publish' ), array( 'X-WP-Nonce: ' . wp_create_nonce( 'wp_rest' ) ) );
$pncp_post = json_decode( $body, true );
t( 'μέλος: δημοσιεύει περιεχόμενο με το site κλειδωμένο (REST 201)', 201 === $code, "$code " . substr( $body, 0, 100 ) );
if ( isset( $pncp_post['id'] ) ) {
	wp_delete_post( (int) $pncp_post['id'], true );
}
list( , $body ) = http( '/wp-admin/index.php' );
t( 'μέλος: χωρίς ειδοποίηση «κλειδωμένο» στο wp-admin', false === strpos( $body, 'This site is locked.' ) );
add_filter( 'pre_wp_mail', '__return_false' );
wp_update_user( array( 'ID' => $member_id, 'user_email' => 'ld_member_new@example.com' ) );
remove_filter( 'pre_wp_mail', '__return_false' );
wp_cache_flush();
t( 'μέλος: αλλάζει το email του', 'ld_member_new@example.com' === get_userdata( $member_id )->user_email );

/* ---------- Κλειδωμένο: editor ---------- */
as_user( $editor_id );
list( $code, $body ) = http( '/wp-admin/edit.php' );
t( 'editor: δεν επεξεργάζεται άρθρα', 403 === $code || false !== strpos( $body, 'not allowed' ), (string) $code );
list( , $body ) = http( '/wp-admin/index.php' );
t( 'editor: βλέπει ότι το site είναι κλειδωμένο, χωρίς σύνδεσμο ξεκλειδώματος', false !== strpos( $body, 'This site is locked.' ) && false === strpos( $body, 'tab=lockdown' ) && false === strpos( $body, 'wp-admin-bar-pncp-status' ) );
list( $code, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=lockdown' );
t( 'editor: η σελίδα του ScrapeLock δεν ανοίγει', false === strpos( $body, 'Until I lock it again' ), (string) $code );
t( 'editor: δεν ξεκλειδώνει', 'http 403' === ld( 'unlock', array( 'code' => app_code( $secret ) ) ) && PNCP_Lockdown::is_locked() );

/* ---------- Ξεκλείδωμα ---------- */
as_user( 1 );
reset_fails( array( 1 ) );
t( 'ξεκλείδωμα με λάθος κωδικό: όχι', 'wrong' === ld( 'unlock', array( 'code' => '123456', 'minutes' => 15 ) ) && PNCP_Lockdown::is_locked() );
t( 'ξεκλείδωμα με κωδικό ανάκτησης για 15 λεπτά', 'unlocked' === ld( 'unlock', array( 'code' => strtoupper( $recovery[0] ), 'minutes' => 15 ) ) && ! PNCP_Lockdown::is_locked() && PNCP_Lockdown::unlocked_until() > time() + 14 * 60 );
t( '… ο κωδικός ανάκτησης χρησιμοποιείται μία φορά (9 μένουν)', 9 === count( PNCP_Lockdown::state()['codes'] ) );
list( $code ) = http( '/wp-admin/plugins.php' );
t( 'ξεκλείδωτο: τα plugins ανοίγουν', 200 === $code, (string) $code );
t( 'ξανά κλείδωμα αμέσως, χωρίς κωδικό', 'locked' === ld( 'relock' ) && PNCP_Lockdown::is_locked() );
t( 'ο ίδιος κωδικός ανάκτησης δεύτερη φορά: όχι', 'wrong' === ld( 'unlock', array( 'code' => $recovery[0] ) ) && PNCP_Lockdown::is_locked() );
state_set( array( 'until' => time() - 1 ) );
t( 'το προσωρινό ξεκλείδωμα λήγει και ξανακλειδώνει μόνο του', PNCP_Lockdown::is_locked() );

/* ---------- Ταυτόχρονα αιτήματα με τον ίδιο κωδικό ---------- */
// Το αίτημα Α έχει ήδη διαβάσει την κατάσταση· στο μεταξύ το αίτημα Β (server) χρησιμοποιεί τον κωδικό· μετά το Α
// δοκιμάζει τον ίδιο κωδικό με ό,τι είχε διαβάσει. Πρέπει να απορριφθεί.
$check = function ( $code, $recovery ) {
	return self::check_code( $code, $recovery );
};
$check = $check->bindTo( null, 'PNCP_Lockdown' );
reset_fails( array( 1 ) );
$same = app_code( $secret );
PNCP_Lockdown::state(); // Α: διάβασε.
t( 'ταυτόχρονα: το αίτημα Β ξεκλειδώνει με τον κωδικό', 'unlocked' === ld( 'unlock', array( 'code' => $same, 'minutes' => 15 ) ) );
state_set( array( 'until' => 0 ) ); // Ξανά κλειδωμένο, χωρίς να πειραχτεί το last_step.
$stale = PNCP_Lockdown::state();
( function ( $s ) {
	self::$state = $s; // Α: κρατά την παλιά κατάσταση, όπως ένα αίτημα που ξεκίνησε πριν από το Β.
} )->bindTo( null, 'PNCP_Lockdown' )( array_merge( $stale, array( 'last_step' => 0 ) ) );
t( 'ταυτόχρονα: το αίτημα Α με τον ίδιο κωδικό απορρίπτεται', '' === $check( $same, false ) );
fresh();
$codes_before = count( PNCP_Lockdown::state()['codes'] );
t( 'ταυτόχρονα: το αίτημα Β χρησιμοποιεί κωδικό ανάκτησης', 'unlocked' === ld( 'unlock', array( 'code' => $recovery[1], 'minutes' => 15 ) ) );
state_set( array( 'until' => 0 ) );
( function ( $s ) {
	self::$state = $s;
} )->bindTo( null, 'PNCP_Lockdown' )( $stale ); // Α: η παλιά λίστα έχει ακόμη τον κωδικό.
t( 'ταυτόχρονα: το αίτημα Α με τον ίδιο κωδικό ανάκτησης απορρίπτεται', '' === $check( $recovery[1], true ) );
fresh();
t( '… ο κωδικός ανάκτησης μετρήθηκε μία φορά', $codes_before - 1 === count( PNCP_Lockdown::state()['codes'] ) );
// Όσο ένα άλλο αίτημα ελέγχει κωδικό (κρατά το κλείδωμα), το δεύτερο περιμένει και δεν ελέγχει τίποτα.
$lock    = ( function () {
	return self::lock();
} )->bindTo( null, 'PNCP_Lockdown' );
$release = ( function () {
	self::release();
} )->bindTo( null, 'PNCP_Lockdown' );
t( 'κλείδωμα ελέγχου: ένα αίτημα το παίρνει', $lock() );
$t0 = microtime( true );
t( 'κλείδωμα ελέγχου: το δεύτερο δεν ελέγχει τον κωδικό όσο κρατιέται', 'error' === ld( 'unlock', array( 'code' => app_code( $secret ) ) ) && PNCP_Lockdown::is_locked(), round( microtime( true ) - $t0, 1 ) . 's' );
$release();
t( 'κλείδωμα ελέγχου: μετά ξανά κανονικά', 'unlocked' === ld( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 15 ) ) );
state_set( array( 'until' => 0 ) );
global $wpdb;
$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", (string) ( time() - 1 ), 'pncp_lockdown_mutex' ) );
t( 'κλείδωμα ελέγχου: ένα αίτημα που «πέθανε» κρατώντας το δεν το μπλοκάρει για πάντα (λήγει σε 10″)', $lock() );
$release();

/* ---------- Όριο λάθος κωδικών ---------- */
reset_fails( array( 1 ) );
for ( $i = 0; $i < PNCP_Lockdown::MAX_FAILS; $i++ ) {
	ld( 'unlock', array( 'code' => '000000' ) );
}
t( 'μετά από 5 λάθος κωδικούς, ούτε ο σωστός (15 λεπτά αναμονή)', 'wait' === ld( 'unlock', array( 'code' => app_code( $secret ) ) ) && PNCP_Lockdown::is_locked() );
reset_fails( array( 1 ) );

t( 'ξεκλείδωμα «μέχρι να το κλειδώσω ξανά»', 'unlocked' === ld( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 0 ) ) && ! PNCP_Lockdown::is_locked() && ! PNCP_Lockdown::unlocked_until() );
wp_set_current_user( 1 );
t( 'ξεκλείδωτο: ο διαχειριστής έχει ξανά όλα τα δικαιώματα', current_user_can( 'manage_options' ) && wp_is_file_mod_allowed( 'x' ) );
update_option( 'blogname', 'Test' );
t( 'ξεκλείδωτο: οι ρυθμίσεις αλλάζουν', 'Test' === get_option( 'blogname' ) );

/* ---------- Επιλογή ρόλων που παγώνουν ---------- */
t( 'ρόλοι: αποθήκευση χωρίς κωδικό: όχι', 'wrong' === ld( 'roles', array( 'roles' => array( 'editor', 'ld_member' ), 'code' => '' ) ) );
reset_fails( array( 1 ) );
t( 'ρόλοι: το μέλος παγώνει όταν το τσεκάρετε (και ο διαχειριστής μένει, ας μην τσεκαρίστηκε)', 'roles' === ld( 'roles', array( 'roles' => array( 'editor', 'ld_member' ), 'code' => app_code( $secret ) ) ) && in_array( 'ld_member', PNCP_Lockdown::frozen_roles(), true ) && in_array( 'administrator', PNCP_Lockdown::frozen_roles(), true ) && ! in_array( 'author', PNCP_Lockdown::frozen_roles(), true ) );
t( 'ρόλοι: κλειδωμένο → το μέλος κρατά μόνο read', 'locked' === ld( 'lock', array( 'code' => app_code( $secret ) ) ) && PNCP_Lockdown::is_staff( $member_id ) && ( function () use ( $member_id ) {
	wp_set_current_user( $member_id );
	$ok = current_user_can( 'read' ) && ! current_user_can( 'edit_posts' );
	wp_set_current_user( 1 );
	return $ok;
} )() );
t( 'ρόλοι: όσο είναι κλειδωμένο δεν αλλάζουν', 'error' === ld( 'roles', array( 'roles' => array(), 'code' => app_code( $secret ) ) ) && in_array( 'ld_member', PNCP_Lockdown::frozen_roles(), true ) );
reset_fails( array( 1 ) );
t( 'ρόλοι: ξεκλείδωμα και επιστροφή στην προεπιλογή', 'unlocked' === ld( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 0 ) ) && 'roles' === ld( 'roles', array( 'roles' => array( 'editor', 'author', 'contributor' ), 'code' => app_code( $secret ) ) ) && ! PNCP_Lockdown::is_staff( $member_id ) );
t( 'νέοι κωδικοί ανάκτησης με τον κωδικό της εφαρμογής', 'codes' === ld( 'codes', array( 'code' => app_code( $secret ) ) ) && 10 === count( PNCP_Lockdown::state()['codes'] ) );
list( , $body ) = http( $page );
t( 'αρχείο: συμβάντα στη σελίδα (κλείδωμα, κωδικός ανάκτησης, λάθος, άρνηση αλλαγής)', false !== strpos( $body, 'Recovery code used' ) && false !== strpos( $body, 'Wrong code' ) && false !== strpos( $body, 'Change refused' ) && ! php_errors( $body ) );

/* ---------- Αφαίρεση εφαρμογής ---------- */
t( 'αφαίρεση χωρίς κωδικό: όχι', 'wrong' === ld( 'remove', array( 'code' => '' ) ) && PNCP_Lockdown::configured() );
reset_fails( array( 1 ) );
t( 'αφαίρεση με κωδικό: η εφαρμογή φεύγει', 'removed' === ld( 'remove', array( 'code' => app_code( $secret ) ) ) && ! PNCP_Lockdown::configured() && ! PNCP_Lockdown::is_locked() );
t( '… και με νέα εφαρμογή ξαναζητείται το κουτάκι', empty( PNCP_Lockdown::state()['ack'] ) );

/* ---------- Ξεκλείδωμα από τον server (wp-config.php) ---------- */
state_set( array( 'secret' => 'p:' . $secret, 'locked' => true, 'until' => 0 ) );
t( 'κλειδωμένο πριν από τη γραμμή του wp-config.php', PNCP_Lockdown::is_locked() );

/* ---------- Site Health (2.8) ---------- */
// Οι πληροφορίες ενημερώσεων του WordPress αλλάζουν μόνο εδώ και επιστρέφουν όπως ήταν (αλλιώς η επόμενη
// σελίδα του wp-admin θα ξαναρωτούσε το wordpress.org).
$pncp_saved = array();
foreach ( array( 'update_plugins', 'update_themes', 'update_core' ) as $pncp_name ) {
	$pncp_saved[ $pncp_name ] = get_site_transient( $pncp_name );
	set_site_transient( $pncp_name, (object) array( 'response' => array(), 'updates' => array(), 'last_checked' => time() ) );
}
set_site_transient( 'update_plugins', (object) array( 'response' => array( 'hello.php' => (object) array( 'new_version' => '9.9' ) ), 'last_checked' => time() ) );
$pncp_h = PNCP_Health::test_lockdown();
t( 'Site Health: κλειδωμένο με ενημέρωση σε αναμονή → recommended, 1 update', 'recommended' === $pncp_h['status'] && false !== strpos( $pncp_h['label'], '1 update' ) && 'scrapelock_lockdown' === $pncp_h['test'], $pncp_h['label'] );
set_site_transient( 'update_plugins', (object) array( 'response' => array(), 'last_checked' => time() ) );
$pncp_h = PNCP_Health::test_lockdown();
t( 'Site Health: κλειδωμένο χωρίς ενημερώσεις → good', 'good' === $pncp_h['status'] && false !== strpos( $pncp_h['label'], 'locked' ), $pncp_h['status'] );
foreach ( $pncp_saved as $pncp_name => $pncp_value ) {
	if ( false === $pncp_value ) {
		delete_site_transient( $pncp_name );
	} else {
		set_site_transient( $pncp_name, $pncp_value );
	}
}
$pncp_info = PNCP_Health::info( array() );
t( 'Site Health Info: Lockdown «Locked» και οι παγωμένοι ρόλοι', 'Locked' === $pncp_info['scrapelock']['fields']['lockdown']['value'] && false !== strpos( $pncp_info['scrapelock']['fields']['lockdown_roles']['value'], 'administrator' ) );
t( 'Site Health Info: κανένα μυστικό (ούτε το secret της εφαρμογής)', false === strpos( wp_json_encode( $pncp_info ), $secret ) );

define( 'SCRAPELOCK_UNLOCK', true );
t( 'SCRAPELOCK_UNLOCK: το κλείδωμα δεν εφαρμόζεται', ! PNCP_Lockdown::is_locked() && current_user_can( 'manage_options' ) );
$pncp_h = PNCP_Health::test_lockdown();
t( 'Site Health: SCRAPELOCK_UNLOCK → critical', 'critical' === $pncp_h['status'] && 'red' === $pncp_h['badge']['color'] );

/* ---------- Καθάρισμα ---------- */
delete_site_option( PNCP_Lockdown::OPTION );
delete_site_option( PNCP_Lockdown::LOG_OPTION );
delete_site_option( PNCP_Lockdown::MUTEX );
fresh();
require_once ABSPATH . 'wp-admin/includes/user.php';
foreach ( array( $editor_id, $customer_id, $new, $shopper, $member_id, $member2 ) as $id ) {
	if ( $id && ! is_wp_error( $id ) ) {
		wp_delete_user( $id );
	}
}
reset_fails( array( 1, $editor_id ) );
remove_role( 'ld_member' );

echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
