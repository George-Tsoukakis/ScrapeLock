<?php
/**
 * ScrapeLock — αποκλεισμός στο CDN (Cloudflare, Bunny) με ψεύτικο API (tests/lib/mu-test-harness.php): οι
 * προσωρινοί αποκλεισμοί φτάνουν στο CDN, φεύγουν όταν λήξουν, σφάλματα, όρια, εναλλαγή CDN, φόρμα ρυθμίσεων.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_edge.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );

// 3.4.2: ο έλεγχος σύνδεσης ρωτά και το /user/tokens/verify, τα στοιχεία της ζώνης και τις κεφαλίδες Ratelimit,
// που το ψεύτικο API του tests/lib/mu-test-harness.php δεν ξέρει. Συμπλήρωμα του ψεύτικου API, ως προσωρινό
// mu-plugin (το διαβάζουν και η δοκιμή και ο server των δοκιμών)· σβήνεται στο τέλος. Τα υπόλοιπα τα απαντά το
// harness όπως πριν.
$pncp_mock = $wp_dir . '/wp-content/mu-plugins/pncp-test-edge-api.php';
file_put_contents(
	$pncp_mock,
	<<<'PHP'
<?php
// ΜΟΝΟ ΓΙΑ ΔΟΚΙΜΕΣ: γράφεται και σβήνεται από το tests/t_edge.php. Τρέχει μετά το ψεύτικο API του harness
// (προτεραιότητα 10, που απαντά κάθε κλήση στο api.cloudflare.com) και συμπληρώνει ή αλλάζει την απάντησή του.
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) {
		$db = get_option( 'pncp_test_cdn' );
		if ( ! is_array( $pre ) || ! is_array( $db ) || 0 !== strpos( $url, 'https://api.cloudflare.com/' ) ) {
			return $pre;
		}
		$method  = isset( $args['method'] ) ? $args['method'] : 'GET';
		$headers = isset( $args['headers'] ) ? $args['headers'] : array();
		$good    = isset( $headers['Authorization'] ) && 'Bearer cf-good-token-1234567890' === $headers['Authorization'];
		$api     = 'https://api.cloudflare.com/client/v4';
		$zone    = '0123456789abcdef0123456789abcdef';
		$reply   = static function ( $code, $data, $type = 'application/json' ) {
			return array( 'headers' => array( 'content-type' => $type ), 'body' => is_string( $data ) ? $data : wp_json_encode( $data ), 'response' => array( 'code' => $code, 'message' => '' ), 'cookies' => array(), 'filename' => null );
		};
		// Σελίδα HTML (σφάλμα του edge της Cloudflare, proxy, firewall) ή κενή απάντηση αντί για απάντηση του API.
		if ( ! empty( $db['html'] ) ) {
			return $reply( (int) $db['html'], ! empty( $db['html_empty'] ) ? '' : '<!DOCTYPE html><html><body>Access denied</body></html>', 'text/html' );
		}
		if ( ! empty( $db['fail'] ) ) {
			return $pre; // Το σφάλμα του harness.
		}
		$rate = array( 'ratelimit' => '"default";r=1150;t=200', 'ratelimit-policy' => '"default";q=1200;w=300' );
		if ( 'GET' === $method && $api . '/user/tokens/verify' === $url ) {
			$pre = $good
				? $reply( 200, array( 'success' => true, 'errors' => array(), 'result' => array( 'id' => 'tok1', 'status' => 'active' ) ) )
				: $reply( 401, array( 'success' => false, 'errors' => array( array( 'code' => 1000, 'message' => 'Invalid API Token' ) ) ) );
		} elseif ( 'GET' === $method && $api . '/zones/' . $zone === $url ) {
			$pre = $good
				? $reply( 200, array( 'success' => true, 'errors' => array(), 'result' => array( 'id' => $zone, 'name' => 'example.test', 'status' => 'active', 'paused' => false, 'plan' => array( 'name' => 'Free Website' ), 'account' => array( 'id' => str_repeat( 'a', 32 ) ) ) ) )
				: $reply( 403, array( 'success' => false, 'errors' => array( array( 'code' => 10000, 'message' => 'Authentication error' ) ) ) );
		} elseif ( 'DELETE' === $method ) {
			// Το σώμα κάθε DELETE (3.4.1: JSON {}).
			$db['delete_bodies'][] = isset( $args['body'] ) ? (string) $args['body'] : null;
			update_option( 'pncp_test_cdn', $db, false );
		} elseif ( 'GET' === $method && false !== strpos( $url, '/firewall/access_rules/rules?' ) ) {
			$json = json_decode( (string) $pre['body'], true );
			if ( is_array( $json ) && ! empty( $json['success'] ) ) {
				// Με τη σημείωση κάθε κανόνα, όπως η Cloudflare (από αυτήν ξέρει το ScrapeLock ποιοι κανόνες είναι δικοί του).
				foreach ( $json['result'] as $i => $rule ) {
					$json['result'][ $i ]['notes'] = isset( $db['cf'][ $rule['id'] ]['notes'] ) ? $db['cf'][ $rule['id'] ]['notes'] : '';
				}
				$json['result_info'] = array( 'page' => 1, 'per_page' => 50, 'total_pages' => 1, 'total_count' => count( $db['cf'] ) );
				$pre['body']         = wp_json_encode( $json );
			}
		}
		// Οι κεφαλίδες Ratelimit της Cloudflare.
		$pre['headers'] = (array) $pre['headers'] + $rate;
		return $pre;
	},
	11,
	3
);
PHP
);
register_shutdown_function(
	static function () use ( $pncp_mock ) {
		if ( is_file( $pncp_mock ) ) {
			unlink( $pncp_mock );
		}
	}
);

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

const CF_ZONE  = '0123456789abcdef0123456789abcdef';
const CF_TOKEN = 'cf-good-token-1234567890';
const BN_ZONE  = '12345';
const BN_KEY   = 'bunny-good-key-1234567890';

function cdn() {
	wp_cache_delete( 'pncp_test_cdn', 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	return get_option( 'pncp_test_cdn' ) + array( 'cf' => array(), 'bunny' => array(), 'calls' => array() );
}
function cdn_set( $changes ) {
	update_option( 'pncp_test_cdn', array_merge( cdn(), $changes ), false );
}
function cf_values() {
	$out = array_column( cdn()['cf'], 'value' );
	sort( $out );
	return $out;
}
function calls() {
	return count( cdn()['calls'] );
}
/**
 * Μία εκτέλεση του cron, όπως θα γινόταν στο επόμενο αίτημα. Όπως το cron του WordPress, η προγραμματισμένη εκτέλεση
 * φεύγει πριν τρέξει (3.4: μια εκτέλεση δεν μεταθέτει πια αργότερα μια ήδη προγραμματισμένη, π.χ. από ban στο μεταξύ).
 */
function run() {
	wp_clear_scheduled_hook( PNCP_Edge::CRON );
	PNCP_Log::reset_cache();
	PNCP_Edge::sync();
}
function ban( $ip, $minutes = 60 ) {
	PNCP_Log::ban( $ip, $minutes, 'rate_page' );
}
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
}

/* ---------- Καθαρή αρχή ---------- */
$saved_settings = PNCP_Options::stored();
// 3.4: νέα εγκατάσταση = «Μόνο παρακολούθηση» για 7 ημέρες, που δεν στέλνει τίποτα ούτε στο CDN: κλειστό, όπως σε site
// που ήδη υπήρχε.
settings( array( 'enabled' => 1, 'trust_any_proxy' => 0, 'ban_strikes' => 3, 'monitor_mode' => 0, 'monitor_until' => 0 ) );
// 3.4.1: και το όριο κλήσεων ανά 5 λεπτά (CALLS), η αναμονή μετά από 429 / λάθος token (NOT_BEFORE) και η κλειδαριά.
foreach ( array( PNCP_Edge::CONFIG, PNCP_Edge::STATE, PNCP_Edge::RETIRE, PNCP_Edge::STAFF, PNCP_Edge::CALLS, PNCP_Edge::NOT_BEFORE, PNCP_Edge::DIRTY, PNCP_Edge::LOCK ) as $pncp_o ) {
	delete_option( $pncp_o );
}
// 3.4.1: το πολύ 300 κλήσεις στο API ανά 5 λεπτά. Η δοκιμή κάνει περισσότερες μέσα σε λίγα δευτερόλεπτα: χωρίς όριο
// εδώ, και το όριο ελέγχεται χωριστά πιο κάτω.
$pncp_budget = static function () {
	return 100000;
};
add_filter( 'pncp_edge_call_budget', $pncp_budget );
wp_clear_scheduled_hook( PNCP_Edge::CRON );
PNCP_Log::unban_all();
update_option( 'pncp_test_cdn', array( 'cf' => array(), 'bunny' => array(), 'calls' => array(), 'fail' => 0, 'next' => 1, 'refuse' => '' ), false );

/* ---------- Ρύθμιση ---------- */
t( 'αρχικά κλειστό: καμία ρύθμιση, κανένα cron μετά από αποκλεισμό', ! PNCP_Edge::usable() && ( ban( '5.6.7.1' ) || true ) && ! wp_next_scheduled( PNCP_Edge::CRON ) );
t( 'zone ID: Cloudflare 32 hex, Bunny αριθμός', CF_ZONE === PNCP_Edge::clean_zone( 'cloudflare', strtoupper( CF_ZONE ) ) && '' === PNCP_Edge::clean_zone( 'cloudflare', '12345' ) && BN_ZONE === PNCP_Edge::clean_zone( 'bunny', BN_ZONE ) && '' === PNCP_Edge::clean_zone( 'bunny', CF_ZONE ) && '' === PNCP_Edge::clean_zone( 'bunny', '1/../2' ) );
t( 'token: μόνο γράμματα, ψηφία, - και _', CF_TOKEN === PNCP_Edge::clean_token( ' ' . CF_TOKEN . ' ' ) && '' === PNCP_Edge::clean_token( 'short' ) && '' === PNCP_Edge::clean_token( "abc\ndef-ghijklmnopqrs" ) && '' === PNCP_Edge::clean_token( 'a b c d e f g h i j k l' ) );
$cf  = array( 'provider' => 'cloudflare', 'zone' => CF_ZONE, 'token' => CF_TOKEN );
$bad = array( 'provider' => 'cloudflare', 'zone' => CF_ZONE, 'token' => 'cf-wrong-token-1234567890' );
$pncp_ok  = PNCP_Edge::test( $cf );
$pncp_bad = PNCP_Edge::test( $bad );
// 3.4.2: η δοκιμή σύνδεσης είναι ο πλήρης έλεγχος (token, ζώνη, δικαιώματα, δοκιμαστικός αποκλεισμός), με μήνυμα ανά
// είδος άρνησης: άγνωστο token (κωδικός 1000 στο /user/tokens/verify) → «does not know this API token».
t( 'δοκιμή σύνδεσης (3.4.2: πλήρης έλεγχος): σωστό token → εντάξει, λάθος → «does not know this API token»', '' === $pncp_ok && false !== strpos( $pncp_bad, 'does not know this API token' ), $pncp_ok . ' | ' . $pncp_bad );
t( 'δοκιμή σύνδεσης: άγνωστη ζώνη → «does not know this zone»', false !== strpos( PNCP_Edge::test( array( 'provider' => 'cloudflare', 'zone' => str_repeat( 'f', 32 ), 'token' => CF_TOKEN ) ), 'does not know this zone' ) );

PNCP_Edge::save_config( $cf );
t( 'αποθήκευση: χρήσιμο, ενεργό, προγραμματίζεται εκτέλεση τώρα', PNCP_Edge::usable() && PNCP_Edge::active() && wp_next_scheduled( PNCP_Edge::CRON ) <= time() + 30 );
t( 'η ρύθμιση δεν φορτώνεται σε κάθε σελίδα (autoload off)', in_array( $GLOBALS['wpdb']->get_var( $GLOBALS['wpdb']->prepare( "SELECT autoload FROM {$GLOBALS['wpdb']->options} WHERE option_name = %s", PNCP_Edge::CONFIG ) ), array( 'no', 'off' ), true ) );

/* ---------- Cloudflare: προσθήκη ---------- */
ban( '5.6.7.2' );
ban( '2a01:4f8:1:2::5' );
// Διαχειριστής που μπήκε στο wp-admin από αυτή την IP: ποτέ στο CDN.
update_option( PNCP_Edge::STAFF, array( '5.6.7.9' => time() ), false );
ban( '5.6.7.9' );
// Διεύθυνση της Cloudflare (ενσωματωμένη λίστα): ποτέ στο CDN.
ban( '173.245.48.5' );
// 3.4.1: Googlebot και Bingbot (οι βασικές περιοχές τους, και όσο η επίσημη λίστα δεν έχει κατέβει): ποτέ στο CDN.
// Το ban() δεν τους αποκλείει καν όταν η λίστα υπάρχει· εδώ γράφονται κατευθείαν, όπως ένας παλιός αποκλεισμός.
foreach ( array( '66.249.66.1', '157.55.39.10' ) as $pncp_ip ) {
	$GLOBALS['wpdb']->replace( PNCP_Log::bans_table(), array( 'ip' => $pncp_ip, 'until_ts' => time() + HOUR_IN_SECONDS, 'since_ts' => time(), 'reason' => 'rate_page' ) );
}
PNCP_Log::reset_cache();
run();
t( 'Cloudflare: οι αποκλεισμοί έφτασαν (IPv4 ως ip, IPv6 ως /64 ip_range)', array( '2a01:4f8:1:2::/64', '5.6.7.1', '5.6.7.2' ) === cf_values(), implode( ',', cf_values() ) );
$pncp_rules = cdn()['cf'];
$pncp_r     = reset( $pncp_rules );
t( 'Cloudflare: mode block, σημείωση «ScrapeLock: …, until … UTC»', 'block' === $pncp_r['mode'] && 1 === preg_match( '/^ScrapeLock: rate_page, until \d{4}-\d\d-\d\d \d\d:\d\d UTC$/', $pncp_r['notes'] ) && in_array( 'ip_range', array_column( $pncp_rules, 'target' ), true ), $pncp_r['notes'] );
t( 'ποτέ: η IP διαχειριστή και η διεύθυνση της Cloudflare', ! in_array( '5.6.7.9', cf_values(), true ) && ! in_array( '173.245.48.5', cf_values(), true ) && PNCP_Log::is_banned( '5.6.7.9' ) );
t( 'ποτέ (3.4.1): Googlebot και Bingbot', ! array_intersect( array( '66.249.66.1', '157.55.39.10' ), cf_values() ) && ! array_intersect( array( '66.249.66.1', '157.55.39.10' ), array_keys( PNCP_Edge::wanted( 'cloudflare' ) ) ), implode( ',', cf_values() ) );
$GLOBALS['wpdb']->query( $GLOBALS['wpdb']->prepare( 'DELETE FROM %i WHERE ip IN (%s, %s)', PNCP_Log::bans_table(), '66.249.66.1', '157.55.39.10' ) );
PNCP_Log::reset_cache();
t( 'κατάσταση: 3 δικοί μας, χωρίς σφάλμα, επόμενη εκτέλεση στη λήξη', 3 === PNCP_Edge::count() && '' === PNCP_Edge::state()['error'] && wp_next_scheduled( PNCP_Edge::CRON ) > time() + 50 * MINUTE_IN_SECONDS, PNCP_Edge::count() . ' | ' . PNCP_Edge::state()['error'] . ' | ' . ( wp_next_scheduled( PNCP_Edge::CRON ) - time() ) );
$pncp_before = calls();
run();
t( 'δεύτερη εκτέλεση χωρίς αλλαγές: καμία κλήση στο API', calls() === $pncp_before );

// Κανόνας που ο ιδιοκτήτης είχε ήδη στην Cloudflare: μένει δικός του.
cdn_set( array( 'cf' => cdn()['cf'] + array( 'own1' => array( 'value' => '5.6.7.3', 'target' => 'ip', 'mode' => 'block', 'notes' => 'mine' ) ) ) );
ban( '5.6.7.3' );
run();
t( 'υπάρχων κανόνας του ιδιοκτήτη: δεν διπλασιάζεται, δεν μετράει ως δικός μας', 1 === count( array_keys( cf_values(), '5.6.7.3', true ) ) && 3 === PNCP_Edge::count() );

/* ---------- Αφαίρεση ---------- */
PNCP_Log::unban( '5.6.7.2' );
PNCP_Log::unban( '5.6.7.3' );
t( 'άρση αποκλεισμού: εκτέλεση τώρα', wp_next_scheduled( PNCP_Edge::CRON ) <= time() + 30 );
run();
t( 'άρση: φεύγει από την Cloudflare· ο κανόνας του ιδιοκτήτη μένει', ! in_array( '5.6.7.2', cf_values(), true ) && in_array( '5.6.7.3', cf_values(), true ) && 2 === PNCP_Edge::count() );
$GLOBALS['wpdb']->update( PNCP_Log::bans_table(), array( 'until_ts' => time() - 5 ), array( 'ip' => '5.6.7.1' ) );
run();
t( 'λήξη αποκλεισμού: φεύγει από την Cloudflare', ! in_array( '5.6.7.1', cf_values(), true ) && 1 === PNCP_Edge::count() );
// Κανόνας που σβήστηκε με το χέρι στην Cloudflare: 404 = εντάξει.
cdn_set( array( 'cf' => array_filter( cdn()['cf'], function ( $r ) { return '2a01:4f8:1:2::/64' !== $r['value']; } ) ) );
PNCP_Log::unban( '2a01:4f8:1:2::5' );
run();
t( 'σβησμένος με το χέρι (404): δεν μένει «κολλημένος»', 0 === PNCP_Edge::count() && '' === PNCP_Edge::state()['error'] );
$pncp_bodies = isset( cdn()['delete_bodies'] ) ? cdn()['delete_bodies'] : array();
t( 'αφαίρεση (3.4.1): το DELETE στέλνει σώμα JSON «{}», όπως το ζητά η περιγραφή του API', count( $pncp_bodies ) >= 3 && array( '{}' ) === array_values( array_unique( $pncp_bodies, SORT_REGULAR ) ), wp_json_encode( $pncp_bodies ) );

/* ---------- Σφάλματα ---------- */
cdn_set( array( 'fail' => 429 ) );
ban( '5.6.7.4' );
run();
$pncp_next = wp_next_scheduled( PNCP_Edge::CRON );
t( '429: σφάλμα «slow down», ξανά σε ~5 λεπτά, τίποτα δεν χάνεται', false !== strpos( PNCP_Edge::state()['error'], 'slow down' ) && $pncp_next >= time() + 250 && $pncp_next <= time() + 310 && 0 === PNCP_Edge::count() );
cdn_set( array( 'fail' => 500 ) );
run();
t( '500: σφάλμα «HTTP 500», ξανά σε ~5 λεπτά', false !== strpos( PNCP_Edge::state()['error'], 'HTTP 500' ) && wp_next_scheduled( PNCP_Edge::CRON ) >= time() + 250 );
cdn_set( array( 'fail' => 0 ) );
run();
t( 'μετά το σφάλμα: ο αποκλεισμός φτάνει, το σφάλμα σβήνει', in_array( '5.6.7.4', cf_values(), true ) && '' === PNCP_Edge::state()['error'] );
cdn_set( array( 'refuse' => '5.6.7.5' ) );
ban( '5.6.7.5' );
ban( '5.6.7.6' );
run();
t( 'διεύθυνση που η Cloudflare δεν δέχεται: οι άλλες συνεχίζουν, δεν ξαναδοκιμάζεται', in_array( '5.6.7.6', cf_values(), true ) && ! in_array( '5.6.7.5', cf_values(), true ) && false !== strpos( PNCP_Edge::state()['error'], 'HTTP 400' ) && ( ( $pncp_before = calls() ) || true ) && ( run() || true ) && calls() === $pncp_before );
update_option( PNCP_Edge::CONFIG, array( 'provider' => 'cloudflare', 'zone' => CF_ZONE, 'token' => 'cf-wrong-token-1234567890' ), false );
ban( '5.6.7.7' );
run();
// 3.4.2: το 403 με κωδικό 10000 (Authentication error) είναι «token χωρίς το δικαίωμα»: «Cloudflare refused the request».
t( 'λάθος token: σφάλμα «Cloudflare refused the request» (3.4.2), ξανά σε μία ώρα', false !== strpos( PNCP_Edge::state()['error'], 'Cloudflare refused the request' ) && wp_next_scheduled( PNCP_Edge::CRON ) >= time() + 55 * MINUTE_IN_SECONDS, PNCP_Edge::state()['error'] );
update_option( PNCP_Edge::CONFIG, $cf, false );
run();
t( 'σωστό token ξανά (ίδια ζώνη): συνεχίζει με τους ίδιους κανόνες', in_array( '5.6.7.7', cf_values(), true ) && 3 === PNCP_Edge::count() );

// 3.4.2: σελίδα HTML ή κενή απάντηση αντί για απάντηση του API: ούτε «λάθος token» (παύση μίας ώρας) ούτε «η διεύθυνση
// δεν γίνεται δεκτή» (εγκατάλειψη του αποκλεισμού): ξανά σε λίγα λεπτά.
ban( '5.6.7.8' );
cdn_set( array( 'html' => 403 ) );
run();
$pncp_next = wp_next_scheduled( PNCP_Edge::CRON );
t( 'HTML 403 αντί για API (3.4.2): «web page that refuses access», ξανά σε ~5 λεπτά, όχι σε μία ώρα', false !== strpos( PNCP_Edge::state()['error'], 'web page that refuses access' ) && $pncp_next >= time() + 250 && $pncp_next <= time() + 310, PNCP_Edge::state()['error'] );
cdn_set( array( 'html' => 401, 'html_empty' => 1 ) );
run();
$pncp_next = wp_next_scheduled( PNCP_Edge::CRON );
t( 'κενή απάντηση 401 (3.4.2): «not an API answer», όχι «refused», ξανά σε ~5 λεπτά', false !== strpos( PNCP_Edge::state()['error'], 'not an API answer' ) && false === stripos( PNCP_Edge::state()['error'], 'refused' ) && $pncp_next >= time() + 250 && $pncp_next <= time() + 310, PNCP_Edge::state()['error'] );
cdn_set( array( 'html' => 0, 'html_empty' => 0 ) );
run();
// Ο κανόνας είχε γίνει πριν από τη σελίδα HTML: η επόμενη εκτέλεση τον βρίσκει (σημείωση «ScrapeLock») και τον κρατά ως δικό της.
t( 'μετά την HTML απάντηση: ο αποκλεισμός φτάνει κανονικά, μία φορά, ως δικός μας', 1 === count( array_keys( cf_values(), '5.6.7.8', true ) ) && 4 === PNCP_Edge::count() && '' === PNCP_Edge::state()['error'], implode( ',', cf_values() ) );
cdn_set( array( 'html' => 403 ) );
$pncp_r = PNCP_Edge::test( $cf );
cdn_set( array( 'html' => 0 ) );
t( 'δοκιμή σύνδεσης με HTML απάντηση (3.4.2): αποτυχία στο βήμα «Connection to Cloudflare»', 0 === strpos( $pncp_r, 'Connection to Cloudflare:' ) && false !== strpos( $pncp_r, 'web page' ), $pncp_r );

// 3.4.2: άγνωστη ζώνη («could not route», 7003) σταματά την εκτέλεση όπως ένα λάθος token· ο αποκλεισμός δεν
// εγκαταλείπεται και φτάνει όταν διορθωθεί η ζώνη.
update_option( PNCP_Edge::CONFIG, array( 'provider' => 'cloudflare', 'zone' => str_repeat( 'f', 32 ), 'token' => CF_TOKEN ), false );
ban( '5.6.7.10' );
ban( '5.6.7.11' );
$pncp_before = calls();
run();
t( 'άγνωστη ζώνη (3.4.2): μία κλήση και σταματά, «does not know this zone ID», ξανά σε μία ώρα', 1 === calls() - $pncp_before && false !== strpos( PNCP_Edge::state()['error'], 'does not know this zone ID' ) && wp_next_scheduled( PNCP_Edge::CRON ) >= time() + 55 * MINUTE_IN_SECONDS, ( calls() - $pncp_before ) . ' | ' . PNCP_Edge::state()['error'] );
update_option( PNCP_Edge::CONFIG, $cf, false );
run();
t( 'σωστή ζώνη ξανά: οι αποκλεισμοί φτάνουν (δεν εγκαταλείφθηκαν)', in_array( '5.6.7.10', cf_values(), true ) && in_array( '5.6.7.11', cf_values(), true ) && 6 === PNCP_Edge::count() && '' === PNCP_Edge::state()['error'], implode( ',', cf_values() ) );

// 3.4.1: το πολύ 300 κλήσεις στο API ανά 5 λεπτά (φίλτρο pncp_edge_call_budget).
remove_filter( 'pncp_edge_call_budget', $pncp_budget );
update_option( PNCP_Edge::CALLS, array( time(), PNCP_Edge::CALL_BUDGET ), false );
ban( '5.6.7.12' );
$pncp_before = calls();
run();
$pncp_next = wp_next_scheduled( PNCP_Edge::CRON );
t( 'όριο 300 κλήσεων / 5 λεπτά (3.4.1): καμία κλήση, «many calls», ξανά σε ~5 λεπτά', 300 === PNCP_Edge::CALL_BUDGET && calls() === $pncp_before && false !== strpos( PNCP_Edge::state()['error'], 'many calls' ) && $pncp_next >= time() + 250 && $pncp_next <= time() + 310, PNCP_Edge::state()['error'] );
update_option( PNCP_Edge::CALLS, array( time(), 0 ), false );
run();
t( 'όριο κλήσεων: κάθε κλήση μετρά, μετά το παράθυρο συνεχίζει', in_array( '5.6.7.12', cf_values(), true ) && get_option( PNCP_Edge::CALLS )[1] === calls() - $pncp_before, wp_json_encode( get_option( PNCP_Edge::CALLS ) ) );
add_filter( 'pncp_edge_call_budget', $pncp_budget );

// 3.4.2: μια εκτέλεση ξεκινά νέες κλήσεις το πολύ για 15 δευτερόλεπτα (ήταν 20) και νωρίτερα όταν ο χρόνος του
// αιτήματος τελειώνει (max_execution_time): τα υπόλοιπα τα κάνει η επόμενη, σε ένα λεπτό.
ban( '5.6.7.13' );
$pncp_rt = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ? $_SERVER['REQUEST_TIME_FLOAT'] : null;
$_SERVER['REQUEST_TIME_FLOAT'] = microtime( true ) - 990;
ini_set( 'max_execution_time', '1000' );
$pncp_before = calls();
run();
ini_set( 'max_execution_time', '0' );
$_SERVER['REQUEST_TIME_FLOAT'] = $pncp_rt;
$pncp_next = wp_next_scheduled( PNCP_Edge::CRON );
t( 'χρόνος εκτέλεσης (3.4.2): 15 s, και χωρίς χρόνο στο αίτημα καμία κλήση, η επόμενη σε ένα λεπτό', 15 === PNCP_Edge::BUDGET && calls() === $pncp_before && $pncp_next <= time() + 65 && ! in_array( '5.6.7.13', cf_values(), true ), ( calls() - $pncp_before ) . ' | ' . ( $pncp_next - time() ) );
run();
t( 'χρόνος εκτέλεσης: η επόμενη εκτέλεση τον στέλνει', in_array( '5.6.7.13', cf_values(), true ) );
foreach ( array( '5.6.7.8', '5.6.7.10', '5.6.7.11', '5.6.7.12', '5.6.7.13' ) as $pncp_ip ) {
	PNCP_Log::unban( $pncp_ip );
}
run();
t( 'οι πρόσθετοι αποκλεισμοί των δοκιμών 3.4 φεύγουν ξανά', 3 === PNCP_Edge::count(), (string) PNCP_Edge::count() );

/* ---------- Όρια ---------- */
for ( $pncp_i = 10; $pncp_i < 40; $pncp_i++ ) {
	ban( '5.6.8.' . $pncp_i );
}
$pncp_before = calls();
run();
t( 'πολλοί μαζί: το πολύ 25 κλήσεις ανά εκτέλεση, η επόμενη σε ένα λεπτό', calls() - $pncp_before <= 25 && wp_next_scheduled( PNCP_Edge::CRON ) <= time() + 65 && PNCP_Edge::count() < 33 );
run();
t( 'πολλοί μαζί: η δεύτερη εκτέλεση τελειώνει', 33 === PNCP_Edge::count(), (string) PNCP_Edge::count() );
add_filter( 'pncp_edge_max', function () { return 5; } );
run();
run(); // 28 αφαιρέσεις: δύο εκτελέσεις των 25.

t( 'pncp_edge_max = 5: μένουν μόνο οι 5 νεότεροι', 5 === count( PNCP_Edge::state()['rules'] ) && 5 === count( PNCP_Edge::wanted( 'cloudflare' ) ) && PNCP_Edge::count() + 1 === count( cf_values() ), implode( ',', array_keys( PNCP_Edge::state()['rules'] ) ) );
remove_all_filters( 'pncp_edge_max' );
run();

/* ---------- Χωρίς προστασία / IP χωρίς έλεγχο proxy ---------- */
settings( array( 'trust_any_proxy' => 1 ) );
t( '«εμπιστοσύνη σε κάθε αίτημα»: παύση (όποιος γράφει την IP θα έβαζε οποιονδήποτε στο CDN)', ! PNCP_Edge::active() && wp_next_scheduled( PNCP_Edge::CRON ) <= time() + 30 );
for ( $pncp_i = 0; $pncp_i < 3; $pncp_i++ ) {
	run();
}
t( '«εμπιστοσύνη σε κάθε αίτημα»: όλοι οι δικοί μας φεύγουν από την Cloudflare', 0 === PNCP_Edge::count() && array( '5.6.7.3' ) === cf_values(), implode( ',', cf_values() ) );
settings( array( 'trust_any_proxy' => 0 ) );
for ( $pncp_i = 0; $pncp_i < 3; $pncp_i++ ) {
	run();
}
$pncp_count = PNCP_Edge::count();
settings( array( 'enabled' => 0 ) );
for ( $pncp_i = 0; $pncp_i < 3; $pncp_i++ ) {
	run();
}
t( 'προστασία κλειστή: οι δικοί μας φεύγουν, ξανανοίγει: επιστρέφουν', $pncp_count > 30 && 0 === PNCP_Edge::count() && ( settings( array( 'enabled' => 1 ) ) || true ) && ( run() || run() || true ) && PNCP_Edge::count() > 30, $pncp_count . '/' . PNCP_Edge::count() );

/* ---------- «Μόνο παρακολούθηση» (3.4) ---------- */
// Η πρώτη εβδομάδα μιας νέας εγκατάστασης: δεν αποκλείει τίποτα, ούτε στο CDN.
$pncp_count = PNCP_Edge::count();
settings( array( 'monitor_mode' => 1, 'monitor_until' => time() + 7 * DAY_IN_SECONDS ) );
for ( $pncp_i = 0; $pncp_i < 3; $pncp_i++ ) {
	run();
}
t( '«Μόνο παρακολούθηση» (3.4): τίποτα στο CDN, οι δικοί μας φεύγουν, του ιδιοκτήτη μένει', PNCP_Options::monitoring() && array() === PNCP_Edge::wanted( 'cloudflare' ) && 0 === PNCP_Edge::count() && array( '5.6.7.3' ) === cf_values(), implode( ',', cf_values() ) );
settings( array( 'monitor_mode' => 0, 'monitor_until' => 0 ) );
for ( $pncp_i = 0; $pncp_i < 3; $pncp_i++ ) {
	run();
}
t( '«Μόνο παρακολούθηση» κλειστή: επιστρέφουν', $pncp_count > 30 && $pncp_count === PNCP_Edge::count(), $pncp_count . '/' . PNCP_Edge::count() );

/* ---------- Αλλαγή σε Bunny ---------- */
PNCP_Log::unban_all();
run();
run();
ban( '5.6.9.1' );
ban( '2a01:4f8:9:9::1' );
run();
cdn_set( array( 'bunny' => array( '5.6.9.2' ) ) ); // Του ιδιοκτήτη.
ban( '5.6.9.2' );
PNCP_Edge::save_config( array( 'provider' => 'bunny', 'zone' => BN_ZONE, 'token' => BN_KEY ) );
t( 'αλλαγή CDN: οι κανόνες της Cloudflare μπαίνουν σε ουρά αφαίρεσης (με τα παλιά στοιχεία)', 2 === count( get_option( PNCP_Edge::RETIRE )[0]['items'] ) && CF_TOKEN === get_option( PNCP_Edge::RETIRE )[0]['token'] );
run();
t( 'Cloudflare: οι δικοί μας σβήστηκαν, του ιδιοκτήτη έμεινε· η ουρά άδειασε', array( '5.6.7.3' ) === cf_values() && false === get_option( PNCP_Edge::RETIRE ), implode( ',', cf_values() ) );
t( 'Bunny: μόνο IPv4/μεμονωμένες (όχι /64), του ιδιοκτήτη όχι διπλός', array( '5.6.9.2', '5.6.9.1' ) === cdn()['bunny'] && 1 === PNCP_Edge::count(), implode( ',', cdn()['bunny'] ) );
PNCP_Log::unban( '5.6.9.1' );
PNCP_Log::unban( '5.6.9.2' );
run();
t( 'Bunny: η άρση σβήνει μόνο τη δική μας', array( '5.6.9.2' ) === cdn()['bunny'] && 0 === PNCP_Edge::count() );
t( 'Bunny: λάθος κλειδί → «refused the token»', false !== strpos( PNCP_Edge::test( array( 'provider' => 'bunny', 'zone' => BN_ZONE, 'token' => 'bunny-wrong-key-123456789' ) ), 'refused the token' ) );

/* ---------- Απενεργοποίηση του plugin ---------- */
ban( '5.6.9.3' );
ban( '5.6.9.4' );
run();
PNCP_Edge::remove_all( 5 );
t( 'απενεργοποίηση: οι δικοί μας σβήνονται αμέσως, κανένα cron', array( '5.6.9.2' ) === cdn()['bunny'] && 0 === PNCP_Edge::count() && ! wp_next_scheduled( PNCP_Edge::CRON ), implode( ',', cdn()['bunny'] ) );

/* ---------- Φόρμα ρυθμίσεων (HTTP, ως διαχειριστής) ---------- */
$pncp_exp   = time() + DAY_IN_SECONDS;
$pncp_tok   = WP_Session_Tokens::get_instance( 1 )->create( $pncp_exp );
$pncp_jar   = LOGGED_IN_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( 1, $pncp_exp, 'logged_in', $pncp_tok ) ) . '; ' . AUTH_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( 1, $pncp_exp, 'auth', $pncp_tok ) );
$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( 1, $pncp_exp, 'logged_in', $pncp_tok );
wp_set_current_user( 1 );
function http( $path, $post = null ) {
	global $base, $pncp_jar;
	$ch   = curl_init( $base . $path );
	$opts = array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_COOKIE => $pncp_jar, CURLOPT_HTTPHEADER => array( 'X-Test-IP: 5.6.10.1', 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: el' ), CURLOPT_TIMEOUT => 60 );
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = http_build_query( $post );
	}
	curl_setopt_array( $ch, $opts );
	$out = (string) curl_exec( $ch );
	$hs  = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	$res = array( (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE ), substr( $out, $hs ), preg_match( '/^location:\s*(\S+)/mi', substr( $out, 0, $hs ), $m ) ? $m[1] : '' );
	curl_close( $ch );
	return $res;
}
function form( $fields ) {
	list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array_merge( array( 'action' => 'pncp_edge', '_wpnonce' => wp_create_nonce( 'pncp_edge' ) ), $fields ) );
	wp_cache_flush();
	return 302 === $code && preg_match( '/pncp_message=(\w+)/', $loc, $m ) ? $m[1] : "http $code";
}
// Ο server των δοκιμών δεν έχει το φίλτρο του ορίου κλήσεων: οι κλήσεις ως εδώ δεν μετράνε. Και κανένας αποκλεισμός
// σε αναμονή: μια εκτέλεση του cron του WordPress στον server (όπου δεν είναι κλειστό) δεν προσθέτει κλήσεις στις
// μετρήσεις της φόρμας.
delete_option( PNCP_Edge::CALLS );
PNCP_Log::unban_all();
wp_clear_scheduled_hook( PNCP_Edge::CRON );
if ( 0 === http( '/' )[0] ) {
	t( 'φόρμα: ο server των δοκιμών απαντά', false, $base );
} else {
	list( $pncp_code, $pncp_body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=bots' );
	t( 'καρτέλα Bots: ενότητα «Blocking at the CDN», 200 χωρίς PHP warnings, το token δεν φαίνεται', 200 === $pncp_code && false !== strpos( $pncp_body, 'id="pncp-sec-edge"' ) && false !== strpos( $pncp_body, 'Saved. Leave empty to keep it.' ) && false === strpos( $pncp_body, BN_KEY ) && ! preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:/', $pncp_body ), (string) $pncp_code );
	wp_cache_flush();
	t( 'η IP του διαχειριστή που άνοιξε το wp-admin καταγράφηκε', isset( PNCP_Edge::staff()['5.6.10.1'] ) );
	t( 'φόρμα: λάθος zone ID → «edge_zone», τίποτα δεν αλλάζει', 'edge_zone' === form( array( 'provider' => 'cloudflare', 'zone' => 'xyz', 'token' => CF_TOKEN ) ) && 'bunny' === PNCP_Edge::config()['provider'] );
	t( 'φόρμα: άλλο CDN χωρίς token → «edge_token»', 'edge_token' === form( array( 'provider' => 'cloudflare', 'zone' => CF_ZONE, 'token' => '' ) ) && 'bunny' === PNCP_Edge::config()['provider'] );
	t( 'φόρμα: λάθος token → «edge_failed», δεν αποθηκεύεται', 'edge_failed' === form( array( 'provider' => 'cloudflare', 'zone' => CF_ZONE, 'token' => 'cf-wrong-token-1234567890' ) ) && 'bunny' === PNCP_Edge::config()['provider'] );
	list( , $pncp_body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=bots&pncp_message=edge_failed' );
	t( 'φόρμα: το μήνυμα λέει γιατί (3.4.2: «does not know this API token»)', false !== strpos( $pncp_body, 'The connection test failed' ) && false !== strpos( $pncp_body, 'does not know this API token' ) );
	$pncp_n = count( cdn()['calls'] );
	t( 'φόρμα: σωστά στοιχεία → «edge_ok», αποθηκεύεται', 'edge_ok' === form( array( 'provider' => 'cloudflare', 'zone' => CF_ZONE, 'token' => CF_TOKEN ) ) && $cf === PNCP_Edge::config() );
	$pncp_new = implode( "\n", array_slice( cdn()['calls'], $pncp_n ) );
	t( 'φόρμα (3.4.2): η αποθήκευση ελέγχει token και ζώνη και κάνει ένα δοκιμαστικό αποκλεισμό (ένα POST, ένα DELETE)', false !== strpos( $pncp_new, 'GET https://api.cloudflare.com/client/v4/user/tokens/verify' ) && false !== strpos( $pncp_new, 'GET https://api.cloudflare.com/client/v4/zones/' . CF_ZONE . "\n" ) && 1 === preg_match_all( '#^POST https://api\.cloudflare\.com/.*/rules$#m', $pncp_new ) && 1 === preg_match_all( '#^DELETE https://api\.cloudflare\.com/.*/rules/r\d+$#m', $pncp_new ) && ! preg_grep( '/^203\.0\.113\./', cf_values() ), $pncp_new );
	// 3.4.2: το κουμπί «Test blocking at the CDN» (op=test_block) έγινε «Test connection» (op=diagnose), που κάνει όλο
	// τον έλεγχο μαζί με τον δοκιμαστικό αποκλεισμό· το op=test_block γίνεται ακόμη δεκτό.
	$pncp_n = count( cdn()['calls'] );
	t( 'κουμπί «Test connection» (3.4.2, πριν «Test blocking at the CDN»): «edge_test_ok», τίποτα δεν μένει στην Cloudflare', 'edge_test_ok' === form( array( 'op' => 'diagnose' ) ) && ! preg_grep( '/^203\.0\.113\./', cf_values() ) && 1 === preg_match( '#^POST https://api\.cloudflare\.com/.*/rules$#m', implode( "\n", array_slice( cdn()['calls'], $pncp_n ) ) ), implode( ',', cf_values() ) );
	list( , $pncp_body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=bots&pncp_message=edge_test_ok' );
	t( 'κουμπί δοκιμής: το μήνυμα λέει τι έγινε, τα βήματα του ελέγχου φαίνονται, το κουμπί φαίνεται (3.4.2: «Test connection»)', false !== strpos( $pncp_body, 'Connection test passed: blocking at the CDN works.' ) && 1 === preg_match( '/The test address 203\.0\.113\.\d+ was blocked at Cloudflare, found there and removed again\./', $pncp_body ) && 7 === substr_count( $pncp_body, 'pncp-edge-check--ok' ) && false !== strpos( $pncp_body, 'value="diagnose"' ) && false !== strpos( $pncp_body, 'Test connection' ) && false === strpos( $pncp_body, CF_TOKEN ) && ! preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:/', $pncp_body ) );
	t( 'κουμπί δοκιμής: το παλιό op=test_block γίνεται ακόμη δεκτό', 'edge_test_ok' === form( array( 'op' => 'test_block' ) ) && ! preg_grep( '/^203\.0\.113\./', cf_values() ) );
	t( 'φόρμα: κενό token, ίδιο CDN → κρατά το αποθηκευμένο', 'edge_ok' === form( array( 'provider' => 'cloudflare', 'zone' => CF_ZONE, 'token' => '' ) ) && CF_TOKEN === PNCP_Edge::config()['token'] );
	t( 'φόρμα: «Off» → κλειστό', 'edge_off' === form( array( 'provider' => '' ) ) && ! PNCP_Edge::usable() );
	$pncp_ed = wp_insert_user( array( 'user_login' => 'edge_editor', 'user_pass' => wp_generate_password(), 'user_email' => 'edge_editor@example.com', 'role' => 'editor' ) );
	$pncp_tok2 = WP_Session_Tokens::get_instance( $pncp_ed )->create( $pncp_exp );
	$pncp_jar  = LOGGED_IN_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( $pncp_ed, $pncp_exp, 'logged_in', $pncp_tok2 ) ) . '; ' . AUTH_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( $pncp_ed, $pncp_exp, 'auth', $pncp_tok2 ) );
	$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $pncp_ed, $pncp_exp, 'logged_in', $pncp_tok2 );
	wp_set_current_user( $pncp_ed );
	t( 'φόρμα: editor → 403, τίποτα δεν αλλάζει', 'http 403' === form( array( 'provider' => 'cloudflare', 'zone' => CF_ZONE, 'token' => CF_TOKEN ) ) && ! PNCP_Edge::usable() );
	require_once ABSPATH . 'wp-admin/includes/user.php';
	wp_delete_user( $pncp_ed );
}

/* ---------- Δοκιμή αποκλεισμού στο CDN (3.2) ---------- */
cdn_set( array( 'cf' => array(), 'bunny' => array( '5.6.9.2' ), 'fail' => 0, 'refuse' => '' ) );
$pncp_r = PNCP_Edge::test_block( $cf );
t( 'δοκιμή Cloudflare: προστέθηκε, βρέθηκε, αφαιρέθηκε', $pncp_r['ok'] && array() === cf_values() && 1 === preg_match( '#^DELETE https://api\.cloudflare\.com/.*/rules/r\d+$#m', implode( "\n", cdn()['calls'] ) ), $pncp_r['message'] . ' | ' . implode( ',', cf_values() ) );
$pncp_r = PNCP_Edge::test_block( array( 'provider' => 'bunny', 'zone' => BN_ZONE, 'token' => BN_KEY ) );
t( 'δοκιμή Bunny: προστέθηκε, βρέθηκε, αφαιρέθηκε· η IP του ιδιοκτήτη μένει', $pncp_r['ok'] && array( '5.6.9.2' ) === cdn()['bunny'], $pncp_r['message'] );
$pncp_r = PNCP_Edge::test_block( $bad );
t( 'δοκιμή με λάθος token: αποτυχία, λέει σε ποιο βήμα και γιατί (3.4.2: «Cloudflare refused the request»)', ! $pncp_r['ok'] && 0 === strpos( $pncp_r['message'], 'Connection failed' ) && false !== strpos( $pncp_r['message'], 'Cloudflare refused the request' ) && array() === cf_values(), $pncp_r['message'] );
cdn_set( array( 'fail' => 500 ) );
$pncp_r = PNCP_Edge::test_block( $cf );
cdn_set( array( 'fail' => 0 ) );
t( 'δοκιμή με σφάλμα του CDN (500): αποτυχία με «HTTP 500»', ! $pncp_r['ok'] && false !== strpos( $pncp_r['message'], 'HTTP 500' ), $pncp_r['message'] );
t( 'δοκιμή: καμία αλλαγή στην κατάσταση του αποκλεισμού στο CDN', 0 === PNCP_Edge::count() );

/* ---------- Μόνο μέσω CDN (3.2) ---------- */
$pncp_sec = 'test-secret-1234';
$pncp_form = array_merge( PNCP_Options::stored(), array( 'cdn_only' => 1, 'cdn_secret' => $pncp_sec, '_sections' => array( 'bots' ) ) );
unset( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] );
t( 'ενεργοποίηση από αίτημα χωρίς το μυστικό: δεν ανάβει', 0 === PNCP_Options::sanitize( $pncp_form )['cdn_only'] );
t( 'ενεργοποίηση χωρίς μυστικό: δεν ανάβει', 0 === PNCP_Options::sanitize( array_merge( $pncp_form, array( 'cdn_secret' => '' ) ) )['cdn_only'] );
$_SERVER['HTTP_X_SCRAPELOCK_CDN'] = 'wrong-secret-0000';
t( 'ενεργοποίηση με λάθος μυστικό: δεν ανάβει', 0 === PNCP_Options::sanitize( $pncp_form )['cdn_only'] );
$_SERVER['HTTP_X_SCRAPELOCK_CDN'] = $pncp_sec;
t( 'ενεργοποίηση από αίτημα που έφερε το μυστικό: ανάβει', 1 === PNCP_Options::sanitize( $pncp_form )['cdn_only'] );
settings( array( 'cdn_only' => 1, 'cdn_secret' => $pncp_sec ) );
unset( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] );
t( 'αποθηκευμένο και ενεργό', PNCP_Origin::active() );
t( 'άλλη καρτέλα αποθηκεύεται χωρίς το μυστικό: μένει ενεργό', 1 === PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( '_sections' => array( 'content' ) ) ) )['cdn_only'] );
function raw( $path, $headers ) {
	global $base;
	$ch = curl_init( $base . $path );
	curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => array_merge( array( 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: el' ), $headers ), CURLOPT_TIMEOUT => 60 ) );
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}
if ( 0 !== raw( '/', array() )[0] ) {
	list( $pncp_code, $pncp_body ) = raw( '/', array( 'X-Test-Remote-Addr: 5.6.20.1', 'X-Test-IP: 5.6.20.1' ) );
	t( 'κατευθείαν στον server (χωρίς μυστικό): 403 «Access denied.»', 403 === $pncp_code && 'Access denied.' === $pncp_body, $pncp_code . ' ' . substr( $pncp_body, 0, 80 ) );
	t( 'κατευθείαν στον server: και το wp-login.php και το REST', 403 === raw( '/wp-login.php', array( 'X-Test-Remote-Addr: 5.6.20.1' ) )[0] && 403 === raw( '/wp-json/', array( 'X-Test-Remote-Addr: 5.6.20.1' ) )[0] );
	t( 'κατευθείαν στον server με λάθος μυστικό: 403', 403 === raw( '/', array( 'X-Test-Remote-Addr: 5.6.20.1', 'X-ScrapeLock-CDN: wrong-secret-0000' ) )[0] );
	t( 'μέσω CDN (με το μυστικό): 200', 200 === raw( '/', array( 'X-Test-Remote-Addr: 5.6.20.1', 'X-Test-IP: 5.6.20.1', 'X-ScrapeLock-CDN: ' . $pncp_sec ) )[0] );
	t( 'ο ίδιος ο server (127.0.0.1, cron, preload): 200 χωρίς μυστικό', 200 === raw( '/', array() )[0] );
	t( 'στο Αρχείο: «Not through the CDN»', (bool) $GLOBALS['wpdb']->get_var( $GLOBALS['wpdb']->prepare( 'SELECT COUNT(*) FROM %i WHERE reason = %s AND ip = %s', PNCP_Log::table(), 'not_via_cdn', '5.6.20.1' ) ) );
} else {
	t( 'μόνο μέσω CDN: ο server των δοκιμών απαντά', false, $base );
}
// Πριν από την cache: ο έλεγχος που τρέχει από το wp-config.php, με τις ίδιες ρυθμίσεις.
require_once PNCP_DIR . 'includes/class-pncp-precheck-runtime.php';
$pncp_c                 = PNCP_Precheck::config();
$pncp_server            = $_SERVER;
$pncp_cookie            = $_COOKIE;
$_COOKIE                = array(); // Επισκέπτης, όχι συνδεδεμένος διαχειριστής.
$_SERVER['REMOTE_ADDR'] = '5.6.20.3';
$_SERVER['REQUEST_URI'] = '/cached-page/';
$_SERVER['REQUEST_METHOD'] = 'GET';
// Το verdict() δεν τρέχει από τη γραμμή εντολών (PHP_SAPI cli): ελέγχονται τα δύο κομμάτια του με τη σειρά τους.
$pncp_v = function () use ( $pncp_c ) {
	return PNCP_Precheck_Runtime::applies( $pncp_c ) ? PNCP_Precheck_Runtime::not_via_cdn( $pncp_c ) : 'skip';
};
t( 'πριν από την cache: σελίδα χωρίς μυστικό → 403 «not_via_cdn»', ! empty( $pncp_c['cdn_only'] ) && '5.6.20.3' === $pncp_v(), (string) $pncp_v() );
$_SERVER['HTTP_X_SCRAPELOCK_CDN'] = $pncp_sec;
t( 'πριν από την cache: με το μυστικό → περνά', '' === $pncp_v() );
unset( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] );
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
t( 'πριν από την cache: ο ίδιος ο server → περνά', '' === $pncp_v() );
$_SERVER['REMOTE_ADDR'] = '5.6.20.3';
$_SERVER['REQUEST_URI'] = '/wp-admin/';
t( 'πριν από την cache: το wp-admin το αφήνει (ο έλεγχος του WordPress αποφασίζει, με το SCRAPELOCK_CDN_ONLY)', 'skip' === $pncp_v() );
$_SERVER = $pncp_server;
$_COOKIE = $pncp_cookie;
settings( array( 'cdn_only' => 0, 'cdn_secret' => '' ) );
t( 'κλειστό: ο έλεγχος πριν από την cache δεν το έχει', empty( PNCP_Precheck::config()['cdn_only'] ) && ! PNCP_Origin::active() );

/* ---------- Τέλος ---------- */
PNCP_Edge::remove_all( 5 );
foreach ( array( PNCP_Edge::CONFIG, PNCP_Edge::STATE, PNCP_Edge::RETIRE, PNCP_Edge::STAFF, 'pncp_test_cdn' ) as $pncp_o ) {
	delete_option( $pncp_o );
}
PNCP_Log::unban_all();
wp_clear_scheduled_hook( PNCP_Edge::CRON );
update_option( PNCP_OPTION, $saved_settings );
echo $fails ? "FAILED $fails\n" : "OK\n";
exit( $fails ? 1 : 0 );
