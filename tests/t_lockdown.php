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

// Ο φύλακας (3.3) και η κατάσταση από προηγούμενη εκτέλεση θα κρατούσαν το site κλειδωμένο (και οι ρόλοι της
// δοκιμής δεν θα γράφονταν): σβήνονται πρώτα απ' όλα.
// 3.4.1: και το υπογεγραμμένο αρχείο κλειδώματος (χωρίς φύλακα), το αντίγραφο των μετρητών λάθος κωδικών στο
// mu-plugins/scrapelock-lockdown-data/ και οι μετρητές / τα κλειδώματα ελέγχου κωδικού στη βάση.
PNCP_Seal::remove_guard();
PNCP_Seal::remove_beacon();
PNCP_Lockdown::fails_remove();
foreach ( array( PNCP_Seal::SNAP, PNCP_Seal::DIGESTS, PNCP_Seal::WINDOW ) as $pncp_o ) {
	delete_option( $pncp_o );
}
foreach ( array( PNCP_Lockdown::OPTION, PNCP_Lockdown::FAILS_OPTION, PNCP_Lockdown::MUTEX, PNCP_Lockdown::MUTEX_PRI, PNCP_Lockdown::DB_FOREIGN ) as $pncp_o ) {
	delete_site_option( $pncp_o );
}
( function () {
	self::$state   = null;
	self::$tamper  = '';
	self::$sig_ok  = true;
} )->bindTo( null, 'PNCP_Lockdown' )();
( function () {
	self::$current = self::record( false, 0 );
	self::$copy    = false;
} )->bindTo( null, 'PNCP_Seal' )();
// 3.4: νέα εγκατάσταση = «Μόνο παρακολούθηση» για 7 ημέρες (η μπάρα γράφει «MONITOR ONLY»): κλειστό, όπως σε site
// που ήδη υπήρχε.
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'monitor_mode' => 0, 'monitor_until' => 0 ) ) );
PNCP_Options::flush();

/* ---------- Χρήστες και συνδέσεις ---------- */
foreach ( array( 'ld_editor', 'ld_customer', 'ld_newadmin', 'ld_shopper', 'ld_member', 'ld_member2', 'ld_shop', 'ld_evil' ) as $login ) {
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
		self::$state        = null;
		self::$staff        = array();
		self::$limited_caps = null; // 3.4.2
		self::$session_ok   = array();
	} )->bindTo( null, 'PNCP_Lockdown' )();
	// Ο φύλακας (3.3): η διεργασία των δοκιμών ζει πολύ (σε ένα πραγματικό αίτημα ο φύλακας διαβάζεται στην
	// αρχή του), οπότε διαβάζεται ξανά από το αρχείο, όπως είναι τώρα: 3.4 με τις γενιές (gen, snap) και το
	// υπογεγραμμένο αντίγραφο των προστατευμένων ρυθμίσεων (PNCP_LOCKDOWN_SNAP_COPY). 3.4.1: χωρίς φύλακα, το
	// υπογεγραμμένο αρχείο κλειδώματος διαβάζεται ξανά.
	clearstatcache();
	( function () {
		$guard = is_readable( self::path() ) ? (string) file_get_contents( self::path() ) : '';
		$json  = '' !== $guard ? self::guard_json() : null;
		if ( null !== $json ) {
			$record        = self::guard_record( $json );
			self::$current = null !== $record ? $record : self::record( false, 0 );
			self::$copy    = false;
			if ( preg_match( "/define\\( '" . self::COPY . "', '([A-Za-z0-9+\\/=]+)' \\)/", $guard, $m ) ) {
				$data       = @unserialize( (string) base64_decode( $m[1], true ), array( 'allowed_classes' => false ) );
				self::$copy = is_array( $data ) ? $data : false;
			}
		} elseif ( defined( 'PNCP_LOCKDOWN_BEACON' ) ) {
			// Ο φύλακας υπήρχε όταν ξεκίνησε η δοκιμή και σβήστηκε: όπως ένα αίτημα χωρίς φύλακα που δεν βρίσκει αρχείο.
			self::$current = self::record( false, 0 );
			self::$copy    = false;
		} else {
			self::$current = null;
			self::$copy    = null;
		}
		self::$file          = null;
		self::$file_at_start = false;
		self::$config        = null;
		self::$net_digests   = null;
	} )->bindTo( null, 'PNCP_Seal' )();
}

/** Αλλάζει την κατάσταση από το test (π.χ. «το προηγούμενο βήμα του κωδικού δεν χρησιμοποιήθηκε»). */
function state_set( $changes ) {
	fresh();
	( function ( $changes ) {
		self::save( array_merge( self::state(), $changes ) );
	} )->bindTo( null, 'PNCP_Lockdown' )( $changes );
	fresh();
}

/** Γράφει μια επιλογή κατευθείαν στη βάση, όπως ένα SQL injection σε άλλο plugin (χωρίς τα φίλτρα του WordPress). */
function raw_set( $option, $value ) {
	global $wpdb;
	if ( null === $value ) {
		$wpdb->delete( $wpdb->options, array( 'option_name' => $option ) );
	} elseif ( ! $wpdb->update( $wpdb->options, array( 'option_value' => maybe_serialize( $value ) ), array( 'option_name' => $option ) ) ) {
		$wpdb->insert( $wpdb->options, array( 'option_name' => $option, 'option_value' => maybe_serialize( $value ), 'autoload' => 'off' ) );
	}
	fresh();
}

/** Η επιλογή όπως είναι στη βάση. */
function raw_get( $option ) {
	global $wpdb;
	$v = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $option ) );
	return null === $v ? null : maybe_unserialize( $v );
}

/** Ο τρέχων κωδικός της εφαρμογής, για νέο βήμα κάθε φορά (το test δεν περιμένει 30″). */
function app_code( $secret ) {
	state_set( array( 'last_step' => 0 ) );
	return PNCP_Totp::code( $secret, PNCP_Totp::step() );
}

/**
 * Μηδενίζει τους μετρητές λάθος κωδικών. 3.4: υπογεγραμμένη επιλογή (FAILS_OPTION) αντί για transients, και όσο
 * υπάρχει ο φύλακας ένα αντίγραφο στο mu-plugins/scrapelock-lockdown-data/ (3.4.1), που μετρά αν είναι πιο μπροστά.
 */
/**
 * 3.4.2: οι επίσημες λίστες (checksums) του WordPress.org μένουν υπογεγραμμένες σε site transients (μια εβδομάδα, μια
 * μέρα μια αποτυχία). Η σύγκριση μετά το κλείδωμα τρέχει στον server από το cron (χωρίς τις λίστες της δοκιμής): ό,τι
 * κράτησε εκεί σβήνεται, ώστε η δοκιμή να ρωτήσει ξανά.
 */
function forget_checksums() {
	global $wpdb;
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( '_site_transient_pncp_cs_' ) . '%', $wpdb->esc_like( '_site_transient_timeout_pncp_cs_' ) . '%' ) );
	wp_cache_flush();
}

/** Οι ειδοποιήσεις «άλλαξε έξω από το WordPress» στέλνονται μία φορά την ώρα ανά είδος (3.4: υπογεγραμμένο transient). */
function forget_alerts() {
	global $wpdb;
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( '_site_transient_pncp_ld_tamper_' ) . '%', $wpdb->esc_like( '_site_transient_timeout_pncp_ld_tamper_' ) . '%' ) );
	wp_cache_flush();
}

function reset_fails( $ids ) {
	foreach ( $ids as $id ) {
		delete_site_transient( 'pncp_ld_fail_' . $id );
	}
	delete_site_transient( 'pncp_ld_fail_all' );
	PNCP_Lockdown::fails_remove();
	delete_site_option( PNCP_Lockdown::FAILS_OPTION );
}

/* ---------- Ο server απαντά; ---------- */
// Χωρίς server κανένα κλείδωμα δεν γίνεται, και οι δοκιμές «από τον κώδικα» θα άλλαζαν στ' αλήθεια το WordPress των
// δοκιμών (ενεργά plugins, ρόλος και email του διαχειριστή, ρυθμίσεις). Σταματάμε πριν από οτιδήποτε.
$cookies = array(); // Χωρίς σύνδεση ακόμη.
if ( 0 === http( '/' )[0] ) {
	echo "FAIL ο server των δοκιμών δεν απαντά ($base): καμία δοκιμή δεν έτρεξε\n";
	exit( 1 );
}

/* ---------- Καθαρή αρχή ---------- */
forget_alerts();
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
list( $code, $body ) = http( '/wp-admin/profile.php' );
t( 'κλειδωμένο (2.8.1): αντί για «not allowed», σελίδα «The site is locked» με κουμπί ξεκλειδώματος', 403 === $code && false !== strpos( $body, '<title>The site is locked</title>' ) && false !== strpos( $body, 'class="pncp-locked"' ) && 1 === preg_match( '/<a class="pncp-locked-btn" href="[^"]*page=scrapelock(&#038;|&amp;|&)tab=lockdown"/', $body ) && false !== strpos( $body, 'Back to the Dashboard' ) && ! php_errors( $body ), (string) $code );
t( 'κλειδωμένο (3.3.1): το στυλ της σελίδας από το καταχωρημένο assets/css/locked.css, όχι από <style> του plugin', 1 === preg_match( '#<link rel=.stylesheet. id=.pncp-locked-css. href=.[^\'"]*assets/css/locked\.css#', $body ) && false === strpos( $body, '.pncp-locked{' ) );
t( 'κλειδωμένο (2.8.1): το μήνυμα του WordPress μόνο στην «Technical detail»', 1 === preg_match( '#<details><summary>Technical detail</summary><p>[^<]*not allowed to edit this user#', $body ) && 1 === substr_count( $body, 'not allowed to edit this user' ) );
list( $code, $body ) = http( '/wp-admin/plugin-install.php' );
t( 'κλειδωμένο (2.8.1): και σε άλλη σελίδα «not allowed» (plugin-install.php)', false !== strpos( $body, 'class="pncp-locked"' ) && false !== strpos( $body, 'tab=lockdown' ), (string) $code );
list( $code, $body ) = http( '/wp-admin/admin-ajax.php', array( 'action' => 'pncp_no_such_action' ) );
t( 'κλειδωμένο (2.8.1): οι απαντήσεις AJAX μένουν ίδιες', false === strpos( $body, 'pncp-locked' ), (string) $code );
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
update_option( PNCP_Edge::CONFIG, array( 'provider' => 'bunny', 'zone' => '1', 'token' => 'evil-key-12345678901234' ), false );
t( 'κώδικας: ο αποκλεισμός στο CDN δεν αλλάζει (3.1)', ! is_array( get_option( PNCP_Edge::CONFIG ) ) || 'evil-key-12345678901234' !== get_option( PNCP_Edge::CONFIG )['token'] );
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
t( 'editor (2.8.1): σελίδα «The site is locked», «ask an administrator», χωρίς σύνδεσμο ξεκλειδώματος', false !== strpos( $body, 'class="pncp-locked"' ) && false !== strpos( $body, 'ask an administrator' ) && false === strpos( $body, 'tab=lockdown' ) && false === strpos( $body, '<a class="pncp-locked-btn"' ) );
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
t( '3.3: το προσωρινό ξεκλείδωμα σημειώνει ποιος ξεκλείδωσε', 1 === (int) PNCP_Lockdown::state()['unlocked_by'] );
list( $code ) = http( '/wp-admin/plugins.php' );
t( 'ξεκλείδωτο: τα plugins ανοίγουν', 200 === $code, (string) $code );
t( 'ξανά κλείδωμα αμέσως, χωρίς κωδικό', 'locked' === ld( 'relock' ) && PNCP_Lockdown::is_locked() );
t( 'ο ίδιος κωδικός ανάκτησης δεύτερη φορά: όχι', 'wrong' === ld( 'unlock', array( 'code' => $recovery[0] ) ) && PNCP_Lockdown::is_locked() );
state_set( array( 'until' => time() - 1 ) );
t( 'το προσωρινό ξεκλείδωμα λήγει και ξανακλειδώνει μόνο του', PNCP_Lockdown::is_locked() );

/* ---------- 3.3: σφραγίδα (υπογραφές, φύλακας, αντίγραφο ρυθμίσεων) ---------- */
// Κάποιος που γράφει στη βάση (όχι στα αρχεία) δεν ξεκλειδώνει το site ούτε αλλάζει ρυθμίσεις.
foreach ( array( 'state', 'snapshot', 'options', 'admin' ) as $pncp_k ) {
	delete_site_transient( 'pncp_ld_tamper_' . $pncp_k );
}
add_filter( 'pre_wp_mail', '__return_false' );
$pncp_guard = (string) @file_get_contents( PNCP_Seal::path() );
// 3.4: ο φύλακας κρατά τα ενεργά plugins και το θέμα με ένα φίλτρο για τις τρεις επιλογές ('option_' . $option) και έχει
// και υπογεγραμμένο αντίγραφο των προστατευμένων ρυθμίσεων (PNCP_LOCKDOWN_SNAP_COPY).
t( 'σφραγίδα: κλειδωμένο → ο φύλακας (mu-plugin) υπάρχει, υπογεγραμμένος, κρατά plugins και θέμα (3.4)', PNCP_Seal::guard_installed() && false !== strpos( $pncp_guard, 'PNCP_LOCKDOWN_BEACON' ) && false !== strpos( $pncp_guard, "add_filter( 'option_' . \$option" ) && false !== strpos( $pncp_guard, "foreach ( array( 'active_plugins', 'template', 'stylesheet' ) as \$option )" ) && '' === PNCP_Lockdown::tampered(), PNCP_Lockdown::tampered() );
t( 'σφραγίδα (3.4): ο φύλακας έχει υπογεγραμμένο αντίγραφο των προστατευμένων ρυθμίσεων', false !== strpos( $pncp_guard, "define( 'PNCP_LOCKDOWN_SNAP_COPY'" ) && ( function () {
	return null !== self::guard_copy();
} )->bindTo( null, 'PNCP_Seal' )() );
t( 'σφραγίδα: η κατάσταση στη βάση έχει υπογραφή', 64 === strlen( (string) ( raw_get( PNCP_Lockdown::OPTION )['sig'] ?? '' ) ) );
t( 'σφραγίδα: αντίγραφο των προστατευμένων ρυθμίσεων και των διαχειριστών', is_array( PNCP_Seal::snapshot() ) && in_array( 1, PNCP_Seal::snapshot()['admins'], true ) && array_key_exists( 'admin_email', PNCP_Seal::snapshot()['values'] ) );
$pncp_raw = raw_get( PNCP_Lockdown::OPTION );
raw_set( PNCP_Lockdown::OPTION, array_merge( $pncp_raw, array( 'locked' => false ) ) );
t( 'σφραγίδα: «ξεκλείδωμα» από τη βάση (χωρίς σωστή υπογραφή) → μένει κλειδωμένο', PNCP_Lockdown::is_locked() && 'replay' === PNCP_Lockdown::tampered() );
t( '… και ειδοποίηση στο ημερολόγιο', false !== strpos( wp_json_encode( get_site_option( PNCP_Lockdown::LOG_OPTION ) ), 'tampered' ) );
as_user( 1 );
reset_fails( array( 1 ) );
t( 'σφραγίδα: ξεκλείδωμα από τη σελίδα όσο η βάση είναι πλαστή: όχι', 'tampered' === ( $pncp_r = ld( 'unlock', array( 'code' => PNCP_Totp::code( $secret, PNCP_Totp::step() ), 'minutes' => 15 ) ) ) && PNCP_Lockdown::is_locked(), $pncp_r );
raw_set( PNCP_Lockdown::OPTION, null );
t( 'σφραγίδα: σβήσιμο της κατάστασης από τη βάση → μένει κλειδωμένο', PNCP_Lockdown::is_locked() && 'replay' === PNCP_Lockdown::tampered() );
// Παλιό αντίγραφο της βάσης (σωστή υπογραφή) με «ξεκλείδωτο για ώρες»: ο φύλακας λέει κλειδωμένο.
$pncp_old          = $pncp_raw;
unset( $pncp_old['sig'] );
$pncp_old['until'] = time() + 3 * HOUR_IN_SECONDS;
$pncp_old['sig']   = PNCP_Seal::sign( $pncp_old );
raw_set( PNCP_Lockdown::OPTION, $pncp_old );
t( 'σφραγίδα: παλιό υπογεγραμμένο αντίγραφο με «ξεκλείδωτο» → μένει κλειδωμένο', PNCP_Lockdown::is_locked() && 'replay' === PNCP_Lockdown::tampered() && 0 === PNCP_Lockdown::unlocked_until() );
raw_set( PNCP_Lockdown::OPTION, $pncp_raw );
t( 'σφραγίδα: η σωστή κατάσταση πίσω → όλα κανονικά', PNCP_Lockdown::is_locked() && '' === PNCP_Lockdown::tampered() );
// Ρυθμίσεις που αλλάζουν κατευθείαν στη βάση επιστρέφουν.
$pncp_mail = get_option( 'admin_email' );
raw_set( 'admin_email', 'attacker@example.com' );
raw_set( 'users_can_register', '1' === (string) get_option( 'users_can_register' ) ? '0' : '1' );
$pncp_reg = raw_get( 'users_can_register' );
PNCP_Seal::verify_options();
fresh();
t( 'σφραγίδα: email διαχειριστή και εγγραφές αλλαγμένα στη βάση → επιστρέφουν', $pncp_mail === raw_get( 'admin_email' ) && $pncp_reg !== raw_get( 'users_can_register' ) );
// Λογαριασμός που έγινε διαχειριστής πίσω από την πλάτη του WordPress δεν συνδέεται.
global $wpdb;
$pncp_pw   = wp_generate_password();
$pncp_evil = wp_insert_user( array( 'user_login' => 'ld_evil', 'user_pass' => $pncp_pw, 'user_email' => 'ld_evil@example.com', 'role' => 'subscriber' ) );
$wpdb->update( $wpdb->usermeta, array( 'meta_value' => serialize( array( 'administrator' => true ) ) ), array( 'user_id' => $pncp_evil, 'meta_key' => $wpdb->get_blog_prefix() . 'capabilities' ) );
clean_user_cache( $pncp_evil );
fresh();
$pncp_auth = wp_authenticate( 'ld_evil', $pncp_pw );
t( 'σφραγίδα: νέος διαχειριστής από τη βάση → δεν συνδέεται', is_wp_error( $pncp_auth ) && 'pncp_locked' === $pncp_auth->get_error_code() );
delete_site_transient( 'pncp_ld_tamper_admin' );
PNCP_Seal::check_admins();
t( '… και αναφέρεται στον ωριαίο έλεγχο', false !== strpos( wp_json_encode( get_site_option( PNCP_Lockdown::LOG_OPTION ) ), 'ld_evil' ) );
$pncp_auth = wp_authenticate( 'ld_editor', 'wrong-password' );
t( 'σφραγίδα: οι υπόλοιποι λογαριασμοί δεν επηρεάζονται', is_wp_error( $pncp_auth ) && 'pncp_locked' !== $pncp_auth->get_error_code() );
require_once ABSPATH . 'wp-admin/includes/user.php';
wp_delete_user( $pncp_evil );
// Αλλοιωμένο αντίγραφο: ειδοποίηση, όχι «επαναφορά» από αυτό.
$pncp_snap = raw_get( PNCP_Seal::SNAP );
$pncp_bad  = $pncp_snap;
$pncp_bad['values']['admin_email'] = 'attacker@example.com';
raw_set( PNCP_Seal::SNAP, $pncp_bad );
PNCP_Seal::verify_options();
fresh();
// 3.4: το υπογεγραμμένο αντίγραφο του φύλακα ισχύει αντί για το πλαστό (πριν: κανένα αντίγραφο, snapshot() = null).
t( 'σφραγίδα: πλαστό αντίγραφο ρυθμίσεων → αγνοείται· ισχύει το αντίγραφο του φύλακα (3.4)', is_array( PNCP_Seal::snapshot() ) && $pncp_mail === PNCP_Seal::snapshot()['values']['admin_email'] && $pncp_mail === raw_get( 'admin_email' ), wp_json_encode( PNCP_Seal::snapshot()['values']['admin_email'] ?? null ) );
raw_set( PNCP_Seal::SNAP, $pncp_snap );
remove_filter( 'pre_wp_mail', '__return_false' );
foreach ( array( 'state', 'snapshot', 'options', 'admin' ) as $pncp_k ) {
	delete_site_transient( 'pncp_ld_tamper_' . $pncp_k );
}

/* ---------- Ταυτόχρονα αιτήματα με τον ίδιο κωδικό ---------- */
// Το αίτημα Α έχει ήδη διαβάσει την κατάσταση· στο μεταξύ το αίτημα Β (server) χρησιμοποιεί τον κωδικό· μετά το Α
// δοκιμάζει τον ίδιο κωδικό με ό,τι είχε διαβάσει. Πρέπει να απορριφθεί.
// 3.4: το check_code() έγινε attempt() (κλείδωμα ελέγχου, μετρητές λάθος κωδικών) + check_code_locked().
$check = function ( $code, $recovery ) {
	return self::attempt(
		static function () use ( $code, $recovery ) {
			return self::check_code_locked( $code, $recovery );
		},
		$recovery
	);
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
// 3.4.2: σε MySQL / MariaDB το κλείδωμα του server της βάσης (GET_LOCK)· αλλιώς (SQLite) ένα αρχείο κλειδώματος
// (mu-plugins/scrapelock-lockdown.lock, flock) και η υπογεγραμμένη γραμμή στη βάση.
if ( PNCP_Lockdown::db_lock_usable() ) {
	t( 'κλείδωμα ελέγχου (3.4.2): GET_LOCK του server της βάσης', null !== $wpdb->get_var( $wpdb->prepare( 'SELECT IS_USED_LOCK(%s)', PNCP_Lockdown::db_lock_name() ) ) );
} else {
	$pncp_row = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", PNCP_Lockdown::MUTEX ) );
	t( 'κλείδωμα ελέγχου (3.4.2, χωρίς GET_LOCK): αρχείο κλειδώματος στο mu-plugins και υπογεγραμμένη γραμμή στη βάση', is_file( PNCP_Lockdown::local_lock_file() ) && wp_normalize_path( WPMU_PLUGIN_DIR . '/scrapelock-lockdown.lock' ) === wp_normalize_path( PNCP_Lockdown::local_lock_file() ) && 1 === preg_match( '/^\d+:[A-Za-z0-9-]+:[0-9a-f]{64}$/', $pncp_row ), $pncp_row );
}
$t0 = microtime( true );
// 3.4: απάντηση «busy» (πριν «error»)· 3.4.2: ένας σωστός κωδικός περιμένει έως PRI_TTL − 1 = 8″ πριν απαντήσει.
t( 'κλείδωμα ελέγχου: το δεύτερο δεν ελέγχει τον κωδικό όσο κρατιέται («busy», 3.4)', 'busy' === ( $pncp_r = ld( 'unlock', array( 'code' => app_code( $secret ) ) ) ) && PNCP_Lockdown::is_locked(), $pncp_r . ' ' . round( microtime( true ) - $t0, 1 ) . 's' );
$release();
t( 'κλείδωμα ελέγχου: μετά ξανά κανονικά', 'unlocked' === ld( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 15 ) ) );
state_set( array( 'until' => 0 ) );
global $wpdb;
$pncp_until = time() - 1;
$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", $pncp_until . ':deadrequest1234:' . PNCP_Seal::sign( array( 'mutex', $pncp_until, 'deadrequest1234' ) ), PNCP_Lockdown::MUTEX ) );
t( 'κλείδωμα ελέγχου: ένα αίτημα που «πέθανε» κρατώντας το δεν το μπλοκάρει για πάντα (3.4: λήγει σε 5″, ήταν 10″)', 5 === PNCP_Lockdown::MUTEX_TTL && $lock() );
$release();
// 3.4: η γραμμή είναι υπογεγραμμένη: μια τιμή γραμμένη στη βάση (π.χ. «κρατημένο για χρόνια») δεν κρατά κανέναν.
$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", (string) ( time() + YEAR_IN_SECONDS ), PNCP_Lockdown::MUTEX ) );
t( 'κλείδωμα ελέγχου (3.4): τιμή γραμμένη στη βάση χωρίς υπογραφή δεν το κρατά', $lock() );
$release();

/* ---------- Όριο λάθος κωδικών ---------- */
reset_fails( array( 1 ) );
for ( $i = 0; $i < PNCP_Lockdown::MAX_FAILS; $i++ ) {
	ld( 'unlock', array( 'code' => '000000' ) );
}
t( 'μετά από 5 λάθος κωδικούς, ούτε ο σωστός (15 λεπτά αναμονή)', 'wait' === ld( 'unlock', array( 'code' => app_code( $secret ) ) ) && PNCP_Lockdown::is_locked() );
// 3.4: οι μετρητές είναι υπογεγραμμένοι, με αντίγραφο δίπλα στον φύλακα: 3.4.1 αρχείο PHP που σταματά στην πρώτη
// γραμμή, στον δικό του φάκελο mu-plugins/scrapelock-lockdown-data/ (με index.php), όχι .json που σερβίρεται.
$pncp_ff = PNCP_Lockdown::fails_file();
t( 'μετρητές (3.4): υπογεγραμμένοι στη βάση', is_array( get_site_option( PNCP_Lockdown::FAILS_OPTION ) ) && isset( get_site_option( PNCP_Lockdown::FAILS_OPTION )['sig'] ) );
t( 'μετρητές (3.4.1): αντίγραφο στο mu-plugins/scrapelock-lockdown-data/fails.php, που σταματά στην πρώτη γραμμή', wp_normalize_path( WPMU_PLUGIN_DIR . '/scrapelock-lockdown-data/fails.php' ) === wp_normalize_path( $pncp_ff ) && is_file( $pncp_ff ) && 0 === strpos( (string) file_get_contents( $pncp_ff ), "<?php exit; ?>\n" ) && is_file( dirname( $pncp_ff ) . '/index.php' ) && ! file_exists( PNCP_Lockdown::fails_file_legacy() ) );
delete_site_option( PNCP_Lockdown::FAILS_OPTION );
fresh();
t( 'μετρητές (3.4): σβησμένοι στη βάση → μετρά το αντίγραφο, η αναμονή συνεχίζεται', 'wait' === ld( 'unlock', array( 'code' => app_code( $secret ) ) ) && PNCP_Lockdown::is_locked() && false !== strpos( wp_json_encode( get_site_option( PNCP_Lockdown::LOG_OPTION ) ), 'fails' ) );
reset_fails( array( 1 ) );

t( 'ξεκλείδωμα «μέχρι να το κλειδώσω ξανά»', 'unlocked' === ld( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 0 ) ) && ! PNCP_Lockdown::is_locked() && ! PNCP_Lockdown::unlocked_until() );
list( $code, $body ) = http( '/wp-admin/profile.php' );
t( 'ξεκλείδωτο (2.8.1): το προφίλ ανοίγει κανονικά', 200 === $code && false === strpos( $body, 'This site is locked.' ) && false === strpos( $body, 'pncp-locked' ), (string) $code );
as_user( $editor_id );
list( , $body ) = http( '/wp-admin/plugins.php' );
t( 'ξεκλείδωτο (2.8.1): το «not allowed» του editor μένει όπως του WordPress', false !== strpos( $body, 'not allowed' ) && false === strpos( $body, 'pncp-locked' ) );
as_user( 1 );
wp_set_current_user( 1 );
t( 'ξεκλείδωτο: ο διαχειριστής έχει ξανά όλα τα δικαιώματα', current_user_can( 'manage_options' ) && wp_is_file_mod_allowed( 'x' ) );
update_option( 'blogname', 'Test' );
t( 'ξεκλείδωτο: οι ρυθμίσεις αλλάζουν', 'Test' === get_option( 'blogname' ) );

/* ---------- Επιλογή ρόλων που παγώνουν ---------- */
t( 'ρόλοι: αποθήκευση χωρίς κωδικό: όχι', 'wrong' === ld( 'roles', array( 'roles' => array( 'editor', 'ld_member' ), 'code' => '' ) ) );
reset_fails( array( 1 ) );
t( 'ρόλοι: το μέλος παγώνει όταν το τσεκάρετε (και ο διαχειριστής μένει, ας μην τσεκαρίστηκε)', 'roles' === ld( 'roles', array( 'roles' => array( 'editor', 'ld_member' ), 'code' => app_code( $secret ) ) ) && in_array( 'ld_member', PNCP_Lockdown::frozen_roles(), true ) && in_array( 'administrator', PNCP_Lockdown::frozen_roles(), true ) && ! in_array( 'author', PNCP_Lockdown::frozen_roles(), true ) );
// 3.4.2: ρόλος καταστήματος (όπως ο shop manager του WooCommerce, με edit_theme_options) που δεν τσεκαρίστηκε: κρατά
// τη δουλειά του (παραγγελίες, προϊόντα, περιεχόμενο) χωρίς ό,τι παίρνει το site (θέματα, ρυθμίσεις, HTML με scripts).
// Φτιάχνεται πριν από το κλείδωμα (όσο είναι κλειδωμένο δεν γίνεται νέο «προσωπικό»).
remove_role( 'ld_shop' );
add_role( 'ld_shop', 'LD Shop', array( 'read' => true, 'edit_posts' => true, 'edit_others_posts' => true, 'upload_files' => true, 'edit_theme_options' => true, 'unfiltered_html' => true, 'manage_woocommerce' => true, 'edit_shop_orders' => true, 'edit_others_shop_orders' => true, 'edit_products' => true, 'view_woocommerce_reports' => true ) );
$pncp_shop = wp_insert_user( array( 'user_login' => 'ld_shop', 'user_pass' => wp_generate_password(), 'user_email' => 'ld_shop@example.com', 'role' => 'ld_shop' ) );
fresh();
t( 'ρόλοι (3.4.2): ο ρόλος καταστήματος δεν τσεκάρεται από προεπιλογή, κρατά τη δουλειά του', ! in_array( 'ld_shop', PNCP_Lockdown::frozen_roles(), true ) && in_array( 'ld_shop', PNCP_Lockdown::limited_roles(), true ) && ! in_array( 'author', PNCP_Lockdown::limited_roles(), true ) );
t( 'ρόλοι: κλειδωμένο → το μέλος κρατά μόνο read', 'locked' === ld( 'lock', array( 'code' => app_code( $secret ) ) ) && PNCP_Lockdown::is_staff( $member_id ) && ( function () use ( $member_id ) {
	wp_set_current_user( $member_id );
	$ok = current_user_can( 'read' ) && ! current_user_can( 'edit_posts' );
	wp_set_current_user( 1 );
	return $ok;
} )() );
fresh();
t( 'ρόλοι (3.4.2): κλειδωμένο → ο ρόλος καταστήματος είναι «προσωπικό» που κρατά τη δουλειά του (επίπεδο 1)', PNCP_Lockdown::is_staff( $pncp_shop ) && 1 === PNCP_Lockdown::staff_level( $pncp_shop ) && 2 === PNCP_Lockdown::staff_level( $editor_id ) );
t( 'ρόλοι (3.4.2): κλειδωμένο → παραγγελίες, προϊόντα, περιεχόμενο ναι· θέματα / μενού, ρυθμίσεις WooCommerce, HTML με scripts όχι', ( function () use ( $pncp_shop ) {
	wp_set_current_user( $pncp_shop );
	$ok = current_user_can( 'edit_posts' ) && current_user_can( 'edit_shop_orders' ) && current_user_can( 'edit_products' ) && current_user_can( 'upload_files' ) && ! current_user_can( 'edit_theme_options' ) && ! current_user_can( 'manage_woocommerce' ) && ! current_user_can( 'unfiltered_html' ) && ! current_user_can( 'customize' );
	wp_set_current_user( 1 );
	return $ok;
} )() );
add_filter( 'pre_wp_mail', '__return_false' );
wp_update_user( array( 'ID' => $pncp_shop, 'user_email' => 'evil3@example.com' ) );
remove_filter( 'pre_wp_mail', '__return_false' );
wp_cache_flush();
t( 'ρόλοι (3.4.2): κλειδωμένο → το email του λογαριασμού καταστήματος δεν αλλάζει (όπως του προσωπικού)', 'ld_shop@example.com' === get_userdata( $pncp_shop )->user_email );
t( 'ρόλοι: όσο είναι κλειδωμένο δεν αλλάζουν', 'error' === ld( 'roles', array( 'roles' => array(), 'code' => app_code( $secret ) ) ) && in_array( 'ld_member', PNCP_Lockdown::frozen_roles(), true ) );
reset_fails( array( 1 ) );
t( 'ρόλοι: ξεκλείδωμα και επιστροφή στην προεπιλογή', 'unlocked' === ld( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 0 ) ) && 'roles' === ld( 'roles', array( 'roles' => array( 'editor', 'author', 'contributor' ), 'code' => app_code( $secret ) ) ) && ! PNCP_Lockdown::is_staff( $member_id ) );
require_once ABSPATH . 'wp-admin/includes/user.php';
wp_delete_user( $pncp_shop );
remove_role( 'ld_shop' );
t( 'νέοι κωδικοί ανάκτησης με τον κωδικό της εφαρμογής', 'codes' === ld( 'codes', array( 'code' => app_code( $secret ) ) ) && 10 === count( PNCP_Lockdown::state()['codes'] ) );
list( , $body ) = http( $page );
t( 'αρχείο: συμβάντα στη σελίδα (κλείδωμα, κωδικός ανάκτησης, λάθος, άρνηση αλλαγής)', false !== strpos( $body, 'Recovery code used' ) && false !== strpos( $body, 'Wrong code' ) && false !== strpos( $body, 'Change refused' ) && ! php_errors( $body ) );

/* ---------- 3.0: έλεγχος ακεραιότητας αρχείων ---------- */
// Ένα «plugin» για τη δοκιμή, ένα email που δεν φεύγει (καταγράφεται), και οι επίσημες λίστες του WordPress.org
// από τη δοκιμή (χωρίς δίκτυο): ο πυρήνας με ένα αρχείο «αλλαγμένο», το plugin με ένα αρχείο του.
$pncp_pdir = WP_PLUGIN_DIR . '/pncp-dummy';
$pncp_up   = wp_get_upload_dir()['basedir'];
// Ό,τι μπορεί να άφησε μια εκτέλεση που διακόπηκε: πρέπει να μην υπάρχει πριν από το κλείδωμα.
foreach ( array( '/2026/pncp-test-shell.php', '/2026/pncp-test-shell.php.pncp-quarantine', '/.user.ini' ) as $pncp_f ) {
	@unlink( $pncp_up . $pncp_f );
}
delete_option( 'pncp_integrity_alerted' );
wp_mkdir_p( $pncp_pdir );
file_put_contents( $pncp_pdir . '/pncp-dummy.php', "<?php\n/**\n * Plugin Name: PNCP Dummy\n * Version: 1.0\n */\n" );
file_put_contents( $pncp_pdir . '/extra.php', "<?php // original\n" );
activate_plugin( 'pncp-dummy/pncp-dummy.php' );
$pncp_mails = array();
add_filter(
	'pre_wp_mail',
	static function ( $r, $atts ) use ( &$pncp_mails ) {
		$pncp_mails[] = $atts;
		return true;
	},
	10,
	2
);
$pncp_core_file = 'wp-includes/version.php';
// Η επίσημη λίστα του πυρήνα: όλα τα αρχεία του, με ένα «αλλαγμένο».
$pncp_core_sums = array();
foreach ( array_keys( PNCP_Integrity::collect()['files'] ) as $pncp_f ) {
	$pncp_rel = PNCP_Integrity::relative( $pncp_f );
	if ( preg_match( '#^(?:wp-admin/|wp-includes/|[^/]+\.php$)#', $pncp_rel ) && 'wp-config.php' !== $pncp_rel ) {
		$pncp_core_sums[ $pncp_rel ] = md5_file( $pncp_f );
	}
}
$pncp_core_sums[ $pncp_core_file ] = md5( 'not the real file' );
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) use ( $pncp_core_sums, $pncp_pdir ) {
		if ( false !== strpos( $url, 'api.wordpress.org/core/checksums' ) ) {
			return array( 'response' => array( 'code' => 200 ), 'body' => wp_json_encode( array( 'checksums' => $pncp_core_sums ) ) );
		}
		if ( false !== strpos( $url, 'plugin-checksums/pncp-dummy/1.0.json' ) ) {
			return array( 'response' => array( 'code' => 200 ), 'body' => wp_json_encode( array( 'files' => array( 'pncp-dummy.php' => array( 'md5' => md5_file( $pncp_pdir . '/pncp-dummy.php' ) ) ) ) ) );
		}
		if ( false !== strpos( $url, 'plugin-checksums/' ) ) {
			return array( 'response' => array( 'code' => 404 ), 'body' => '' );
		}
		return $pre;
	},
	20,
	3
);
reset_fails( array( 1 ) );
t( 'ακεραιότητα: καραντίνα αποθηκεύεται με τον κωδικό, μόνο ξεκλείδωτο', 'wrong' === ld( 'quarantine', array( 'quarantine' => 1, 'code' => '' ) ) && ( reset_fails( array( 1 ) ) || true ) && 'quarantine' === ld( 'quarantine', array( 'quarantine' => 1, 'code' => app_code( $secret ) ) ) && PNCP_Lockdown::quarantine_on() );
t( 'ακεραιότητα: κλείδωμα → αποτύπωμα (WordPress, plugins, wp-config.php, uploads)', 'locked' === ld( 'lock', array( 'code' => app_code( $secret ) ) ) && ( function () use ( $pncp_pdir ) {
	wp_cache_flush();
	$b = PNCP_Integrity::baseline();
	$f = $b['files'];
	return $b['time'] > time() - 120 && ! $b['stale'] && isset( $f[ wp_normalize_path( ABSPATH . 'wp-includes/version.php' ) ] ) && isset( $f[ wp_normalize_path( $pncp_pdir . '/extra.php' ) ] ) && isset( $f[ wp_normalize_path( WP_PLUGIN_DIR . '/' . plugin_basename( PNCP_FILE ) ) ] ) && ( isset( $f[ wp_normalize_path( ABSPATH . 'wp-config.php' ) ] ) || isset( $f[ wp_normalize_path( dirname( ABSPATH ) . '/wp-config.php' ) ] ) );
} )() );
t( 'ακεραιότητα: αμέσως μετά το κλείδωμα τίποτα αλλαγμένο', array() === array_intersect( PNCP_Integrity::findings( PNCP_Integrity::check() ), array( 'added', 'changed', 'removed' ) ) );
// 3.4: οι φάκελοι cache διαβάζονται: ένα αρχείο δεδομένων της cache που σταματά στην πρώτη γραμμή (exit) δεν
// σημειώνεται, ένα νέο αρχείο κώδικα σημειώνεται (ως «αλλάζει μόνο του»: αναφέρεται όταν είναι καινούργιο).
t( 'ακεραιότητα: φάκελοι cache: τα αρχεία δεδομένων τους εκτός, νέος κώδικας μέσα μετρά (3.4)', ( function () {
	wp_mkdir_p( WP_CONTENT_DIR . '/cache/pncp' );
	file_put_contents( WP_CONTENT_DIR . '/cache/pncp/page.php', '<?php exit; // cache' );
	file_put_contents( WP_CONTENT_DIR . '/cache/pncp/code.php', '<?php // cache' );
	$c = PNCP_Integrity::collect();
	unlink( WP_CONTENT_DIR . '/cache/pncp/code.php' );
	return ! isset( $c['files'][ wp_normalize_path( WP_CONTENT_DIR . '/cache/pncp/page.php' ) ] ) && isset( $c['files'][ wp_normalize_path( WP_CONTENT_DIR . '/cache/pncp/code.php' ) ] );
} )() );
// Ό,τι κάνει ένα ευάλωτο plugin: backdoor στα uploads, αλλαγή σε αρχείο plugin, .user.ini.
$pncp_shell  = wp_normalize_path( $pncp_up . '/2026/pncp-test-shell.php' );
wp_mkdir_p( dirname( $pncp_shell ) );
file_put_contents( $pncp_shell, '<?php // test' );
file_put_contents( $pncp_up . '/.user.ini', 'auto_prepend_file=x' );
file_put_contents( $pncp_pdir . '/extra.php', "<?php // changed\n" );
$pncp_mails = array();
// Οι επίσημες λίστες ελέγχονται μία φορά την ημέρα: εδώ ξανά, με τις λίστες της δοκιμής.
update_option( PNCP_Integrity::REPORT, array_merge( PNCP_Integrity::report(), array( 'official' => array() ) ), false );
forget_checksums();
$pncp_rep   = PNCP_Integrity::check();
$pncp_found = PNCP_Integrity::findings( $pncp_rep );
t( 'ακεραιότητα: νέο PHP στα uploads, .user.ini και αλλαγμένο αρχείο plugin', isset( $pncp_found[ $pncp_shell ] ) && 'added' === $pncp_found[ $pncp_shell ] && 'added' === $pncp_found[ wp_normalize_path( $pncp_up . '/.user.ini' ) ] && 'changed' === $pncp_found[ wp_normalize_path( $pncp_pdir . '/extra.php' ) ], wp_json_encode( array_map( array( 'PNCP_Integrity', 'relative' ), array_keys( $pncp_found ) ) ) );
t( 'ακεραιότητα: email στη διεύθυνση διαχείρισης, με τα αρχεία', 1 === count( $pncp_mails ) && false !== strpos( $pncp_mails[0]['message'], 'pncp-test-shell.php' ) && get_option( 'admin_email' ) === $pncp_mails[0]['to'] );
$pncp_mails = array();
PNCP_Integrity::check();
t( 'ακεραιότητα: ίδια ευρήματα → όχι δεύτερο email', array() === $pncp_mails );
wp_cache_flush();
t( 'ακεραιότητα: καραντίνα → το plugin απενεργοποιήθηκε (και κλειδωμένο), το PHP των uploads μετονομάστηκε', ! is_plugin_active( 'pncp-dummy/pncp-dummy.php' ) && ! file_exists( $pncp_shell ) && file_exists( $pncp_shell . '.pncp-quarantine' ) && is_plugin_active( plugin_basename( PNCP_FILE ) ) );
$pncp_off = PNCP_Integrity::report()['official'];
t( 'ακεραιότητα: επίσημες λίστες: αλλαγμένο αρχείο πυρήνα και αρχείο που δεν είναι στην επίσημη έκδοση του plugin', 'official_modified' === ( PNCP_Integrity::findings( PNCP_Integrity::report() )[ wp_normalize_path( ABSPATH . $pncp_core_file ) ] ?? '' ) && array( wp_normalize_path( ABSPATH . $pncp_core_file ) ) === $pncp_off['modified'] && array( wp_normalize_path( $pncp_pdir . '/extra.php' ) ) === $pncp_off['unknown'] && in_array( 'akismet', $pncp_off['unverified'], true ), wp_json_encode( $pncp_off ) );
$pncp_hh = PNCP_Health::test_integrity();
t( 'ακεραιότητα: Site Health → critical', 'critical' === $pncp_hh['status'] && 'scrapelock_integrity' === $pncp_hh['test'] );
list( , $body ) = http( $page );
t( 'ακεραιότητα: η καρτέλα Lockdown δείχνει τα αρχεία, χωρίς PHP warnings', false !== strpos( $body, 'id="pncp-integrity"' ) && false !== strpos( $body, 'pncp-test-shell.php' ) && false !== strpos( $body, 'Check now' ) && ! php_errors( $body ) );
list( , $body ) = http( '/wp-admin/index.php' );
t( 'ακεραιότητα: ειδοποίηση στον πίνακα ελέγχου', false !== strpos( $body, 'ScrapeLock found changed code files.' ) );
$pncp_log_events = wp_list_pluck( (array) get_site_option( PNCP_Lockdown::LOG_OPTION ), 'event' );
t( 'ακεραιότητα: στο αρχείο του Κλειδώματος (ευρήματα, καραντίνα)', in_array( 'integrity', $pncp_log_events, true ) && in_array( 'quarantine', $pncp_log_events, true ) );
// Προσωρινό ξεκλείδωμα: οι ενημερώσεις επιτρέπονται, άρα νέο αποτύπωμα στον επόμενο έλεγχο, όχι συναγερμός.
reset_fails( array( 1 ) );
t( 'ακεραιότητα: ξεκλείδωμα → το αποτύπωμα σημειώνεται παλιό', 'unlocked' === ld( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 15 ) ) && ( wp_cache_flush() || true ) && PNCP_Integrity::baseline()['stale'] );
@unlink( $pncp_shell . '.pncp-quarantine' );
@unlink( $pncp_up . '/.user.ini' );
file_put_contents( $pncp_pdir . '/extra.php', "<?php // updated while open\n" );
state_set( array( 'until' => time() - 1 ) );
remove_all_filters( 'pre_http_request' );
add_filter( 'pre_http_request', static function () {
	return new WP_Error( 'test', 'offline' );
} );
$pncp_rep = PNCP_Integrity::check();
// 3.4: η σύγκριση με τις επίσημες λίστες γίνεται αμέσως μετά, από προγραμματισμένη εκτέλεση («pending» ως τότε).
t( 'ακεραιότητα: μετά το ξεκλείδωμα νέο αποτύπωμα, χωρίς ευρήματα, επίσημες λίστες σε αναμονή (3.4)', PNCP_Lockdown::is_locked() && array() === PNCP_Integrity::findings( $pncp_rep ) && ! PNCP_Integrity::baseline()['stale'] && ! empty( $pncp_rep['official']['pending'] ) && wp_next_scheduled( PNCP_Integrity::OFFICIAL ), wp_json_encode( $pncp_rep['official'] ) );
forget_checksums();
PNCP_Integrity::run_official();
$pncp_rep = PNCP_Integrity::report();
t( '… η προγραμματισμένη σύγκριση χωρίς δίκτυο: τίποτα συγκρίσιμο, κανένα εύρημα', array() === PNCP_Integrity::findings( $pncp_rep ) && false === $pncp_rep['official']['core'] && empty( $pncp_rep['official']['pending'] ), wp_json_encode( $pncp_rep['official'] ) );
$pncp_hh = PNCP_Health::test_integrity();
t( 'ακεραιότητα: Site Health → good', 'good' === $pncp_hh['status'] );
// 3.3: το αποτύπωμα είναι υπογεγραμμένο και η ώρα του σημειώνεται στην (υπογεγραμμένη) κατάσταση.
$pncp_fp  = raw_get( PNCP_Integrity::BASELINE );
$pncp_fp2 = $pncp_fp;
$pncp_fp2['files'] = base64_encode( gzcompress( '{}' ) );
raw_set( PNCP_Integrity::BASELINE, $pncp_fp2 );
t( 'ακεραιότητα (3.3): αποτύπωμα αλλαγμένο στη βάση → παραποιημένο', true === PNCP_Integrity::baseline()['tampered'] );
raw_set( PNCP_Integrity::BASELINE, null );
t( 'ακεραιότητα (3.3): σβησμένο αποτύπωμα → παραποιημένο', true === PNCP_Integrity::baseline()['tampered'] );
t( '… Site Health → critical', 'critical' === PNCP_Health::test_integrity()['status'] );
raw_set( PNCP_Integrity::BASELINE, $pncp_fp );
t( 'ακεραιότητα (3.3): το σωστό αποτύπωμα πίσω → εντάξει', false === PNCP_Integrity::baseline()['tampered'] );
// Χωρίς PHP στα uploads: το .htaccess του φακέλου (Apache) και οι κανόνες Nginx / Apache.
$pncp_ht = $pncp_up . '/.htaccess';
$pncp_s  = PNCP_Options::stored();
reset_fails( array( 1 ) );
ld( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 0 ) );
update_option( PNCP_OPTION, array_merge( $pncp_s, array( 'block_upload_php' => 1 ) ) );
t( 'uploads: .htaccess με το μπλοκ του ScrapeLock', file_exists( $pncp_ht ) && false !== strpos( (string) file_get_contents( $pncp_ht ), '# BEGIN ScrapeLock' ) && false !== strpos( (string) file_get_contents( $pncp_ht ), 'Require all denied' ) );
t( 'uploads: κανόνες Nginx / Apache', false !== strpos( PNCP_Rules::nginx_server(), '/.*\.(?:php[0-9]?|phtml|phar)$ { deny all; }' ) && false !== strpos( PNCP_Rules::apache(), '\.(?:php[0-9]?|phtml|phar)$ - [F,NC,L]' ) );
file_put_contents( $pncp_ht, "# other plugin\n" . file_get_contents( $pncp_ht ) );
update_option( PNCP_OPTION, array_merge( $pncp_s, array( 'block_upload_php' => 0 ) ) );
t( 'uploads: κλειστό → το μπλοκ φεύγει, τα υπόλοιπα του αρχείου μένουν', false === strpos( (string) file_get_contents( $pncp_ht ), 'Require all denied' ) && false !== strpos( (string) file_get_contents( $pncp_ht ), '# other plugin' ) && false === strpos( PNCP_Rules::nginx_server(), 'deny all; }' ) );
@unlink( $pncp_ht );
update_option( PNCP_OPTION, $pncp_s );
// Καθάρισμα της δοκιμής.
deactivate_plugins( 'pncp-dummy/pncp-dummy.php', true );
foreach ( array( '/extra.php', '/pncp-dummy.php' ) as $pncp_f ) {
	@unlink( $pncp_pdir . $pncp_f );
}
@rmdir( $pncp_pdir );
@unlink( WP_CONTENT_DIR . '/cache/pncp/page.php' );
@rmdir( WP_CONTENT_DIR . '/cache/pncp' );
delete_option( PNCP_Integrity::BASELINE );
delete_option( PNCP_Integrity::REPORT );
delete_option( 'pncp_integrity_alerted' );
state_set( array( 'quarantine' => false ) );
remove_all_filters( 'pre_wp_mail' ); // pre_http_request: μένει «χωρίς δίκτυο», όπως με το mu-plugin των δοκιμών.

/* ---------- 3.3 / 3.4.1 / 3.4.2: χωρίς εγγράψιμο φάκελο για τον φύλακα ---------- */
// Η ενέργεια της σελίδας μέσα στη διεργασία της δοκιμής, με τα φίλτρα της δοκιμής (εδώ: WordPress χωρίς άμεση
// εγγραφή αρχείων, FS_METHOD ≠ direct): η ανακατεύθυνση στο τέλος γίνεται εξαίρεση. Κανένα αίτημα HTTP σε αυτό το
// κομμάτι: ο server γράφει κανονικά αρχεία.
function ld_here( $op, $fields = array() ) {
	$_POST    = array_merge( array( 'action' => 'pncp_lockdown', 'op' => $op, '_wpnonce' => wp_create_nonce( 'pncp_lockdown' ) ), $fields );
	$_REQUEST = $_POST;
	$stop     = static function ( $location ) {
		throw new RuntimeException( (string) $location );
	};
	add_filter( 'wp_redirect', $stop, 1 );
	$out = 'none';
	try {
		PNCP_Lockdown::handle();
	} catch ( RuntimeException $e ) {
		$out = preg_match( '/pncp_ld=(\w+)/', $e->getMessage(), $m ) ? $m[1] : $e->getMessage();
	}
	remove_filter( 'wp_redirect', $stop, 1 );
	$_POST    = array();
	$_REQUEST = array();
	fresh();
	return $out;
}
if ( defined( 'PNCP_LOCKDOWN_BEACON' ) ) {
	// Ο φύλακας υπήρχε όταν ξεκίνησε η διεργασία: δεν μπορεί να δει το αρχείο κλειδώματος όπως ένα νέο αίτημα.
	t( 'χωρίς φύλακα: η διεργασία της δοκιμής ξεκίνησε χωρίς φύλακα', false );
} else {
	as_user( 1 );
	reset_fails( array( 1 ) );
	add_filter( 'pre_wp_mail', '__return_false' );
	$pncp_fs = static function () {
		return 'ftpext';
	};
	add_filter( 'filesystem_method', $pncp_fs );
	t( 'χωρίς άμεση εγγραφή αρχείων: ο φύλακας δεν γράφεται', ! PNCP_Lockdown::is_locked() && ! PNCP_Seal::can_write_guard() );
	t( 'κλείδωμα χωρίς φύλακα και χωρίς το κουτάκι «weaker»: όχι («noguard»)', 'noguard' === ( $pncp_r = ld_here( 'lock', array( 'code' => app_code( $secret ) ) ) ) && ! PNCP_Lockdown::is_locked(), $pncp_r );
	reset_fails( array( 1 ) );
	t( 'κλείδωμα χωρίς φύλακα με το κουτάκι (3.4.1): υπογεγραμμένο αρχείο κλειδώματος στο uploads/scrapelock-lockdown/', 'locked' === ( $pncp_r = ld_here( 'lock', array( 'code' => app_code( $secret ), 'weak' => 1 ) ) ) && PNCP_Lockdown::is_locked() && ! PNCP_Seal::guard_installed() && 0 === strpos( PNCP_Seal::beacon_path(), untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) . '/uploads/scrapelock-lockdown/' ), $pncp_r . ' ' . PNCP_Seal::beacon_path() );
	$pncp_bp = PNCP_Seal::beacon_path();
	t( 'αρχείο κλειδώματος (3.4.1): σταματά στην πρώτη γραμμή, ο φάκελος με index.php και .htaccess που αρνείται', '' !== $pncp_bp && 0 === strpos( (string) file_get_contents( $pncp_bp ), "<?php exit; ?>\n" ) && is_file( dirname( $pncp_bp ) . '/index.php' ) && false !== strpos( (string) @file_get_contents( dirname( $pncp_bp ) . '/.htaccess' ), 'Require all denied' ) );
	t( 'αρχείο κλειδώματος (3.4.1): στο αρχείο του Κλειδώματος «without the guard file, with the signed lock file»', false !== strpos( wp_json_encode( get_site_option( PNCP_Lockdown::LOG_OPTION ) ), 'with the signed lock file' ) );
	$pncp_ld = raw_get( PNCP_Lockdown::OPTION );
	raw_set( PNCP_Lockdown::OPTION, null );
	t( 'χωρίς φύλακα (3.4.1): σβήσιμο της κατάστασης από τη βάση → το αρχείο κλειδώματος το κρατά κλειδωμένο', PNCP_Lockdown::is_locked() && 'replay' === PNCP_Lockdown::tampered() );
	raw_set( PNCP_Lockdown::OPTION, $pncp_ld );
	t( '… η σωστή κατάσταση πίσω → όλα κανονικά', PNCP_Lockdown::is_locked() && '' === PNCP_Lockdown::tampered() );
	// Μετρητές λάθος κωδικών: αντίγραφο δίπλα στο αρχείο κλειδώματος (3.4.1).
	ld_here( 'unlock', array( 'code' => '000000', 'minutes' => 0 ) );
	t( 'χωρίς φύλακα (3.4.1): οι μετρητές λάθος κωδικών έχουν αντίγραφο δίπλα στο αρχείο κλειδώματος', '' !== PNCP_Seal::beacon_fails_path() && is_file( PNCP_Seal::beacon_fails_path() ) && 0 === strpos( (string) file_get_contents( PNCP_Seal::beacon_fails_path() ), "<?php exit; ?>\n" ) );
	reset_fails( array( 1 ) );
	t( 'χωρίς φύλακα: ξεκλείδωμα «μέχρι να το κλειδώσω ξανά» → το αρχείο κλειδώματος φεύγει', 'unlocked' === ( $pncp_r = ld_here( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 0 ) ) ) && ! PNCP_Lockdown::is_locked() && '' === PNCP_Seal::beacon_path() && ! file_exists( $pncp_bp ), $pncp_r );
	// 3.4.2: κανένας φάκελος για το αρχείο κλειδώματος (εδώ: αρχεία κάποιου άλλου με το όνομα των φακέλων).
	$pncp_dirs = PNCP_Seal::beacon_dirs();
	foreach ( $pncp_dirs as $pncp_d ) {
		if ( ! file_exists( $pncp_d ) ) {
			file_put_contents( $pncp_d, 'not a folder' );
		}
	}
	reset_fails( array( 1 ) );
	t( 'κανένας εγγράψιμος φάκελος: κλείδωμα με το κουτάκι, μόνο στη βάση ως τη γραμμή του wp-config.php (3.4.2)', '' === PNCP_Seal::beacon_writable_dir() && 'locked' === ( $pncp_r = ld_here( 'lock', array( 'code' => app_code( $secret ), 'weak' => 1 ) ) ) && PNCP_Lockdown::is_locked() && PNCP_Seal::needs_config() && false !== strpos( wp_json_encode( get_site_option( PNCP_Lockdown::LOG_OPTION ) ), 'SCRAPELOCK_LOCKED' ), $pncp_r );
	$pncp_line = PNCP_Seal::current_config_line();
	ob_start();
	( function () {
		self::render_config();
	} )->bindTo( null, 'PNCP_Lockdown' )();
	$pncp_html = (string) ob_get_clean();
	t( 'γραμμή SCRAPELOCK_LOCKED (3.4.2): υπογεγραμμένη, στη σελίδα με κουμπί αντιγραφής', 1 === preg_match( "/^define\\( 'SCRAPELOCK_LOCKED', 'sl1[^']+' \\);$/", $pncp_line ) && false !== strpos( $pncp_html, 'add this line to wp-config.php' ) && false !== strpos( $pncp_html, esc_textarea( $pncp_line ) ) && false !== strpos( $pncp_html, 'pncp-copy' ), $pncp_line );
	reset_fails( array( 1 ) );
	t( 'κανένας εγγράψιμος φάκελος: ξεκλείδωμα «μέχρι να το κλειδώσω ξανά»', 'unlocked' === ( $pncp_r = ld_here( 'unlock', array( 'code' => app_code( $secret ), 'minutes' => 0 ) ) ) && ! PNCP_Lockdown::is_locked(), $pncp_r );
	foreach ( $pncp_dirs as $pncp_d ) {
		if ( is_file( $pncp_d ) && 'not a folder' === file_get_contents( $pncp_d ) ) {
			unlink( $pncp_d );
		}
	}
	remove_filter( 'filesystem_method', $pncp_fs );
	remove_filter( 'pre_wp_mail', '__return_false' );
	reset_fails( array( 1 ) );
	fresh();
}

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

/* ---------- Abilities API (2.8) κλειδωμένο ---------- */
if ( function_exists( 'wp_get_ability' ) ) {
	as_user( 1 );
	$pncp_sum = wp_get_ability( 'scrapelock/get-summary' )->execute( array() );
	t( 'ability get-summary κλειδωμένο: διαβάζεται, «locked»', is_array( $pncp_sum ) && 'locked' === $pncp_sum['lockdown'] );
	$pncp_res = wp_get_ability( 'scrapelock/block-ip' )->execute( array( 'ip' => '203.0.113.91' ) );
	PNCP_Log::reset_cache();
	t( 'ability block-ip κλειδωμένο: όχι', is_wp_error( $pncp_res ) && ! PNCP_Log::is_banned( '203.0.113.91' ) );
	$pncp_res = wp_get_ability( 'scrapelock/emergency-mode' )->execute( array( 'hours' => 2 ) );
	t( 'ability emergency-mode κλειδωμένο: όχι', is_wp_error( $pncp_res ) && ! PNCP_Options::emergency_until() );
}

define( 'SCRAPELOCK_UNLOCK', true );
t( 'SCRAPELOCK_UNLOCK: το κλείδωμα δεν εφαρμόζεται', ! PNCP_Lockdown::is_locked() && current_user_can( 'manage_options' ) );
$pncp_h = PNCP_Health::test_lockdown();
t( 'Site Health: SCRAPELOCK_UNLOCK → critical', 'critical' === $pncp_h['status'] && 'red' === $pncp_h['badge']['color'] );

/* ---------- 3.3: αναβάθμιση από παλιότερη έκδοση (χωρίς υπογραφές) ---------- */
add_filter( 'pre_wp_mail', '__return_false' ); // Οι ειδοποιήσεις «άλλαξε έξω από το WordPress» δεν φεύγουν.
$pncp_ver = get_option( 'pncp_version' );
raw_set( PNCP_Lockdown::OPTION, array( 'secret' => 'p:' . $secret, 'locked' => true, 'until' => 0, 'codes' => array() ) );
update_option( 'pncp_version', '3.2.0' );
fresh();
// 3.4: η έκδοση στη βάση δεν αρκεί: όσο υπάρχει κάτι που γράφει μόνο η 3.3 και μετά (φύλακας, αντίγραφο ρυθμίσεων,
// υπογεγραμμένο αποτύπωμα), η έκδοση γυρίστηκε πίσω στη βάση και η κατάσταση χωρίς υπογραφή δεν γίνεται δεκτή.
t( 'αναβάθμιση (3.4): έκδοση «3.2.0» με τον φύλακα στη θέση του → η κατάσταση χωρίς υπογραφή δεν γίνεται δεκτή', PNCP_Seal::guard_installed() && '' !== PNCP_Lockdown::tampered() );
// Ένα πραγματικό site πριν από την 3.3: χωρίς φύλακα, αντίγραφο ρυθμίσεων ή υπογεγραμμένα αποτυπώματα.
PNCP_Seal::remove_guard();
foreach ( array( PNCP_Seal::SNAP, PNCP_Seal::DIGESTS, PNCP_Integrity::BASELINE ) as $pncp_o ) {
	delete_option( $pncp_o );
}
fresh();
t( 'αναβάθμιση: η κατάσταση χωρίς υπογραφή γίνεται δεκτή πριν την αναβάθμιση', '' === PNCP_Lockdown::tampered() );
PNCP_Lockdown::upgrade_seal();
update_option( 'pncp_version', $pncp_ver );
fresh();
t( 'αναβάθμιση: υπογράφεται, φύλακας και αντίγραφο ρυθμίσεων', 64 === strlen( (string) ( raw_get( PNCP_Lockdown::OPTION )['sig'] ?? '' ) ) && '' === PNCP_Lockdown::tampered() && ( PNCP_Lockdown::server_unlocked() || PNCP_Seal::guard_installed() ) && is_array( PNCP_Seal::snapshot() ) );
raw_set( PNCP_Lockdown::OPTION, array( 'secret' => 'p:' . $secret, 'locked' => true, 'until' => 0, 'codes' => array() ) );
t( 'μετά την αναβάθμιση: κατάσταση χωρίς υπογραφή → παραποιημένη', '' !== PNCP_Lockdown::tampered() );

/* ---------- Καθάρισμα ---------- */
remove_filter( 'pre_wp_mail', '__return_false' );
PNCP_Seal::remove_guard(); // 3.4.1: με το αρχείο κλειδώματος και το αντίγραφο των μετρητών.
PNCP_Lockdown::fails_remove();
foreach ( array( PNCP_Seal::SNAP, PNCP_Seal::DIGESTS, PNCP_Seal::WINDOW ) as $pncp_o ) {
	delete_option( $pncp_o );
}
foreach ( array( PNCP_Lockdown::OPTION, PNCP_Lockdown::LOG_OPTION, PNCP_Lockdown::MUTEX, PNCP_Lockdown::MUTEX_PRI, PNCP_Lockdown::FAILS_OPTION, PNCP_Lockdown::DB_FOREIGN ) as $pncp_o ) {
	delete_site_option( $pncp_o );
}
wp_clear_scheduled_hook( PNCP_Integrity::OFFICIAL ); // 3.4: η σύγκριση με τις επίσημες λίστες μετά από κάθε αποτύπωμα.
forget_checksums();
forget_alerts();
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
