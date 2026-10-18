<?php
/**
 * ScrapeLock — δοκιμές HTTP σε πραγματικό WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_http.php
 *
 * Προϋποθέσεις: το plugin ενεργό, το tests/lib/mu-test-harness.php στα mu-plugins, και ο server
 * (π.χ. php -S 127.0.0.1:8099 -t $WP_DIR router.php). Η βάση του WordPress αλλάζει: μόνο για δοκιμές.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR και BASE απαιτούνται\n" );
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

/** Αίτημα με curl: επιστρέφει [code, headers, body]. */
function req( $path, $headers = array(), $method = 'GET' ) {
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
			CURLOPT_HEADER         => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_CUSTOMREQUEST  => $method,
			CURLOPT_TIMEOUT        => 30,
		)
	);
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
}

function browser( $ip, $extra = array() ) {
	return array_merge(
		array(
			'X-Test-IP'       => $ip,
			'User-Agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36',
			'Accept-Language' => 'el-GR,el;q=0.9',
		),
		$extra
	);
}

function settings( $changes ) {
	$s = array_merge( PNCP_Options::stored(), $changes );
	update_option( PNCP_OPTION, $s );
	PNCP_Options::flush();
	// The limit counters reset every minute: a limit test must not straddle a minute boundary.
	foreach ( array( 'rate_limit', 'rate_limit_search', 'rate_limit_rest', 'rate_limit_404' ) as $key ) {
		if ( ! empty( $changes[ $key ] ) ) {
			same_minute();
			break;
		}
	}
}

/** Waits for the next minute if fewer than 15 seconds are left in the current one. */
function same_minute() {
	$left = 60 - time() % 60;
	if ( $left < 15 ) {
		sleep( $left + 1 );
	}
}

function fresh() {
	global $wpdb;
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_%pncp\_%' OR option_name LIKE '\_transient\_timeout\_%pncp\_%'" );
	PNCP_Log::unban_all();
	PNCP_Log::clear();
	wp_cache_flush(); PNCP_Log::reset_cache();
}

function log_reasons() {
	global $wpdb;
	return $wpdb->get_col( "SELECT reason FROM {$wpdb->prefix}pncp_log ORDER BY id" );
}

update_option( 'pncp_emergency_until', 0 );
settings(
	array(
		'enabled'                 => 1,
		'rate_limit'              => 0,
		'rate_limit_search'       => 0,
		'rate_limit_rest'         => 0,
		'require_browser_headers' => 0,
		'ban_strikes'             => 3,
		'ban_minutes'             => 60,
		'trust_any_proxy'         => 0,
		'ip_header'               => 'remote_addr',
		'private_paths'           => '/skroutz.xml',
		'allow_ips'               => '',
	)
);
fresh();
// Αφετηρία: το token της 1.4 (όπως μετά την αναβάθμιση), ώστε το script να τρέχει ξανά όσες φορές χρειαστεί.
PNCP_Private_Urls::import_plain( 'Legacy1234567890Token' );
delete_option( PNCP_Private_Urls::STATS_OPTION );
$post = get_posts( array( 'numberposts' => 1, 'post_type' => 'post' ) )[0];
$url  = wp_parse_url( get_permalink( $post ), PHP_URL_PATH );

/* ---------- Κανονικός επισκέπτης ---------- */
list( $code, $hdr, $body ) = req( $url, browser( '203.0.113.10' ) );
t( 'browser: 200', 200 === $code, (string) $code );
t( 'browser: X-Frame-Options SAMEORIGIN', false !== strpos( $hdr, 'x-frame-options: sameorigin' ) );
t( "browser: CSP frame-ancestors 'self'", false !== strpos( $hdr, "content-security-policy: frame-ancestors 'self'" ) );
t( 'browser: tdm-reservation header', false !== strpos( $hdr, 'tdm-reservation: 1' ) );
t( 'browser: meta tdm-reservation', false !== strpos( $body, '<meta name="tdm-reservation" content="1">' ) );
t( 'browser: robots noai', (bool) preg_match( '/<meta name=.robots.[^>]*noai/', $body ) );
$head = (string) strstr( $body, '</head>', true );
t( 'browser: protect.js μέσα στο <head>', false !== strpos( $head, 'assets/js/protect.js' ) );
$first_src = preg_match( '/<script[^>]*\bsrc=[\'"]([^\'"]+)/', $head, $m ) ? $m[1] : '';
t( 'browser: protect.js είναι το πρώτο εξωτερικό script', false !== strpos( $first_src, 'protect.js' ), $first_src );
t( 'browser: data-cfasync=false (Rocket Loader)', (bool) preg_match( '/<script[^>]*data-cfasync="false"[^>]*protect\.js/', $head ) || (bool) preg_match( '/<script[^>]*protect\.js[^>]*data-cfasync="false"/', $head ) );
t( 'browser: παγίδα στη σελίδα με aria-hidden', false !== strpos( $body, PNCP_Bots::trap_path() ) && false !== strpos( $body, 'aria-hidden="true"' ) );
t( 'browser: η παγίδα κρύβεται με CSS στο <head>, χωρίς inline style', false !== strpos( $head, '.pncp-hp{position:absolute' ) && ! preg_match( '/class="pncp-hp"[^>]*style=/', $body ) );
t( 'browser: τίποτα στο αρχείο', array() === log_reasons(), implode( ',', log_reasons() ) );

/* ---------- Bots ---------- */
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.1', 'User-Agent' => 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' ) );
t( 'GPTBot: 403', 403 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.2', 'User-Agent' => 'Mozilla/5.0 HeadlessChrome/141.0' ) );
t( 'HeadlessChrome (νέο στη λίστα): 403', 403 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.3', 'User-Agent' => '' ) );
t( 'χωρίς User-Agent: 403', 403 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.4', 'User-Agent' => 'facebookexternalhit/1.1' ) );
t( 'facebookexternalhit (πάντα επιτρεπτό): 200', 200 === $code, (string) $code );
t( 'αρχείο: bot_ua, bot_ua, empty_ua', array( 'bot_ua', 'bot_ua', 'empty_ua' ) === log_reasons(), implode( ',', log_reasons() ) );

/* ---------- 2.3: προεπιλογές νέων εγκαταστάσεων, «πάντα επιτρεπτοί» δεμένοι σε IP ---------- */
$d = PNCP_Options::defaults();
t( 'νέα εγκατάσταση: όρια ενεργά (60 / 20 / 60), DevTools ανενεργό', 60 === $d['rate_limit'] && 20 === $d['rate_limit_search'] && 60 === $d['rate_limit_rest'] && 0 === $d['block_devtools'] );
$p = PNCP_Options::profiles();
t( 'προφίλ: DevTools μόνο σε Αυστηρό / Μέγιστο', ! isset( $p['balanced']['block_devtools'] ) && 1 === $p['strict']['block_devtools'] && 1 === $p['maximum']['block_devtools'] );
fresh();
settings( array( 'require_browser_headers' => 1, 'allow_list' => "PriceBot@198.51.100.50, 198.51.100.60/31\nSkroutz\nBadEntry@not-an-ip" ) );
$pb = array( 'User-Agent' => 'PriceBot/1.0' );
list( $code ) = req( $url, $pb + array( 'X-Test-IP' => '198.51.100.50' ) );
t( 'PriceBot@IP από τη σωστή IP: 200', 200 === $code, (string) $code );
list( $code ) = req( $url, $pb + array( 'X-Test-IP' => '198.51.100.61' ) );
t( 'PriceBot@IP από IP μέσα στο CIDR: 200', 200 === $code, (string) $code );
list( $code ) = req( $url, $pb + array( 'X-Test-IP' => '198.51.100.70' ) );
t( 'PriceBot@IP από άλλη IP: 403 (Μόνο browsers)', 403 === $code, (string) $code );
list( $code ) = req( $url, array( 'User-Agent' => 'Skroutz/2.0', 'X-Test-IP' => '198.51.100.71' ) );
t( 'Skroutz χωρίς @: από οποιαδήποτε IP, όπως πριν', 200 === $code, (string) $code );
list( $code ) = req( $url, array( 'User-Agent' => 'BadEntry/1.0', 'X-Test-IP' => '198.51.100.72' ) );
t( 'γραμμή με @ χωρίς έγκυρη IP: δεν γίνεται ποτέ δεκτή', 403 === $code, (string) $code );
t( 'κανόνες server: οι γραμμές με @ δεν μπαίνουν στη λίστα επιτρεπτών', false === strpos( PNCP_Rules::nginx() . PNCP_Rules::apache() . wp_json_encode( PNCP_Rules::cloudflare() ), 'PriceBot' ) && false !== strpos( PNCP_Rules::nginx(), 'Skroutz' ) );
settings( array( 'require_browser_headers' => 0, 'allow_list' => PNCP_Options::default_allow_list() ) );
fresh();

/* ---------- Ψεύτικο / πραγματικό Googlebot ---------- */
$gb = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
list( $code ) = req( $url, array( 'X-Test-IP' => '45.1.2.3', 'User-Agent' => $gb, 'X-Test-RDNS' => 'scraper.example.net' ) );
t( 'ψεύτικο Googlebot: 403', 403 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '45.1.2.4', 'User-Agent' => $gb, 'X-Test-RDNS' => 'evil.googlebot.com.example.net' ) );
t( 'ψεύτικο Googlebot (rDNS που απλώς περιέχει googlebot.com): 403', 403 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '66.249.66.1', 'User-Agent' => $gb, 'X-Test-RDNS' => 'crawl-66-249-66-1.googlebot.com', 'X-Test-FDNS' => '66.249.66.1' ) );
t( 'πραγματικό Googlebot (rDNS + forward DNS): 200', 200 === $code, (string) $code );
PNCP_Ip::store_list( 'google', array( '66.249.64.0/27' ) );
settings( array( 'rate_limit' => 1 ) );
$ok = true;
for ( $i = 0; $i < 4; $i++ ) {
	list( $code ) = req( $url, array( 'X-Test-IP' => '66.249.64.5', 'User-Agent' => $gb ) );
	$ok = $ok && 200 === $code;
}
t( 'Googlebot από επίσημη λίστα IP: ποτέ όριο (4 σελίδες με όριο 1)', $ok );
settings( array( 'rate_limit' => 0 ) );

/* ---------- Όριο, παραβάσεις, αποκλεισμός ---------- */
fresh();
settings( array( 'rate_limit' => 2, 'ban_strikes' => 1, 'ban_minutes' => 30 ) );
$codes = array();
for ( $i = 0; $i < 4; $i++ ) {
	$codes[] = req( $url, browser( '203.0.113.20' ) )[0];
}
t( 'όριο 2/λεπτό με 1 παράβαση: 200,200,429,403', array( 200, 200, 429, 403 ) === $codes, implode( ',', $codes ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'η IP μπήκε στους αποκλεισμούς', isset( PNCP_Log::active_bans()['203.0.113.20'] ) );
list( $code ) = req( $url, browser( '203.0.113.21' ) );
t( 'άλλη IP δεν επηρεάζεται', 200 === $code, (string) $code );
PNCP_Log::unban( '203.0.113.20' );
fresh();
settings( array( 'rate_limit' => 0, 'rate_limit_search' => 1, 'ban_strikes' => 0 ) );
$codes = array( req( '/?s=test', browser( '203.0.113.22' ) )[0], req( '/?s=test2', browser( '203.0.113.22' ) )[0], req( $url, browser( '203.0.113.22' ) )[0] );
t( 'όριο αναζήτησης 1: 200,429 και η σελίδα περνά', array( 200, 429, 200 ) === $codes, implode( ',', $codes ) );
settings( array( 'rate_limit_search' => 0, 'rate_limit_rest' => 2 ) );
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$codes[] = req( '/wp-json/wp/v2/posts', browser( '203.0.113.23' ) )[0];
}
t( 'όριο REST 2: 200,200,429', array( 200, 200, 429 ) === $codes, implode( ',', $codes ) );
settings( array( 'rate_limit_rest' => 0, 'ban_strikes' => 3 ) );

/* ---------- IPv6: όριο ανά δίκτυο /64 ---------- */
fresh();
settings( array( 'rate_limit' => 2, 'ban_strikes' => 0 ) );
$codes = array();
foreach ( array( '2001:db8:5:6::1', '2001:db8:5:6::2', '2001:db8:5:6:aaaa::3' ) as $v6 ) {
	$codes[] = req( $url, browser( $v6 ) )[0];
}
t( 'IPv6: νέα διεύθυνση στο ίδιο /64 δεν παρακάμπτει το όριο (200,200,429)', array( 200, 200, 429 ) === $codes, implode( ',', $codes ) );
list( $code ) = req( $url, browser( '2001:db8:5:7::1' ) );
t( 'IPv6: άλλο /64 δεν επηρεάζεται', 200 === $code, (string) $code );
t( 'IPv6: ::ffff:198.51.100.7 μετρά ως 198.51.100.7', '198.51.100.7' === PNCP_Ip::limit_key( '::ffff:198.51.100.7' ) );
settings( array( 'rate_limit' => 0, 'ban_strikes' => 3 ) );

/* ---------- Applebot / YandexBot: χωρίς αποκλεισμό όταν το DNS δεν δίνει απάντηση ---------- */
$ab = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)';
fresh();
settings( array( 'ban_strikes' => 1, 'ban_minutes' => 30 ) );
// Ο προϋπολογισμός DNS εξαντλημένος (π.χ. από ψεύτικα «Applebot» άλλων IP), και για το επόμενο λεπτό.
$minute = (int) floor( time() / MINUTE_IN_SECONDS );
PNCP_Log::cache_set( 'pncp_dns_' . $minute, 1000, 2 * MINUTE_IN_SECONDS );
PNCP_Log::cache_set( 'pncp_dns_' . ( $minute + 1 ), 1000, 2 * MINUTE_IN_SECONDS );
$codes = array();
for ( $i = 0; $i < 2; $i++ ) {
	$codes[] = req( $url, array( 'X-Test-IP' => '17.58.101.10', 'User-Agent' => $ab, 'X-Test-RDNS' => '17-58-101-10.applebot.apple.com', 'X-Test-FDNS' => '17.58.101.10' ) )[0];
}
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'Applebot χωρίς διαθέσιμο DNS: 403 αλλά χωρίς αποκλεισμό', array( 403, 403 ) === $codes && ! isset( PNCP_Log::active_bans()['17.58.101.10'] ), implode( ',', $codes ) );
fresh();
list( $code ) = req( $url, array( 'X-Test-IP' => '17.58.101.11', 'User-Agent' => $ab, 'X-Test-RDNS' => '17.58.101.11' ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'Applebot χωρίς reverse DNS: 403 αλλά χωρίς αποκλεισμό', 403 === $code && ! isset( PNCP_Log::active_bans()['17.58.101.11'] ), (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '17.58.101.11', 'User-Agent' => $ab, 'X-Test-RDNS' => '17.58.101.11' ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'Applebot χωρίς reverse DNS, 2ο αίτημα (από την cache): πάλι χωρίς αποκλεισμό', 403 === $code && ! isset( PNCP_Log::active_bans()['17.58.101.11'] ), (string) $code );
fresh();
list( $code ) = req( $url, array( 'X-Test-IP' => '17.58.101.12', 'User-Agent' => $ab, 'X-Test-RDNS' => '17-58-101-12.applebot.apple.com', 'X-Test-FDNS' => '17.58.101.12' ) );
t( 'πραγματικό Applebot (rDNS + forward DNS): 200', 200 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '45.1.2.9', 'User-Agent' => $ab, 'X-Test-RDNS' => 'scraper.example.net' ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'ψεύτικο Applebot (λάθος rDNS): 403 και αποκλεισμός, όπως πριν', 403 === $code && isset( PNCP_Log::active_bans()['45.1.2.9'] ), (string) $code );
fresh();
settings( array( 'ban_strikes' => 3, 'ban_minutes' => 60 ) );

/* ---------- Άλλες μέθοδοι ---------- */
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.11', 'User-Agent' => 'GPTBot/1.2' ), 'POST' );
t( 'POST σελίδας από GPTBot: 403 (στην 1.4 περνούσε)', 403 === $code, (string) $code );
list( $code ) = req( $url . '?wc-ajax=1', array( 'X-Test-IP' => '198.51.100.12', 'User-Agent' => 'GPTBot/1.2' ) );
t( '?wc-ajax χωρίς WooCommerce δεν παρακάμπτει τον έλεγχο', 403 === $code, (string) $code );
list( $code, , $body ) = req( '/wp-json/wp/v2/comments', array( 'X-Test-IP' => '198.51.100.13', 'User-Agent' => 'Go-http-client/1.1' ), 'POST' );
t( 'REST POST (π.χ. webhook πληρωμής με Go-http-client): δεν μπλοκάρεται από το plugin', false === strpos( $body, 'pncp_' ), $code . ' ' . substr( $body, 0, 100 ) );
settings( array( 'rate_limit' => 1, 'ban_strikes' => 0 ) );
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$codes[] = req( $url, browser( '203.0.113.25', array( 'Sec-Purpose' => 'prefetch' ) ) )[0];
}
t( 'prefetch δεν μετρά στο όριο σελίδων', array( 200, 200, 200 ) === $codes, implode( ',', $codes ) );
settings( array( 'rate_limit' => 0, 'ban_strikes' => 3 ) );

/* ---------- 2.1.1: συνδεδεμένοι χρήστες, page builders, wc-ajax ---------- */
fresh();
function test_user( $login, $role ) {
	$u = get_user_by( 'login', $login );
	return $u ? $u->ID : wp_insert_user( array( 'user_login' => $login, 'user_pass' => wp_generate_password(), 'role' => $role ) );
}
function login_cookie( $user_id ) {
	$exp = time() + HOUR_IN_SECONDS;
	$tok = WP_Session_Tokens::get_instance( $user_id )->create( $exp );
	return LOGGED_IN_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( $user_id, $exp, 'logged_in', $tok ) );
}
$customer = test_user( 'pncp_customer', 'subscriber' );
$editor   = test_user( 'pncp_editor', 'editor' );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.70', 'User-Agent' => 'GPTBot/1.2', 'Cookie' => login_cookie( $customer ) ) );
t( 'πελάτης με λογαριασμό και User-Agent bot: 403 (πριν περνούσε κάθε συνδεδεμένος)', 403 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.71', 'User-Agent' => 'GPTBot/1.2', 'Cookie' => login_cookie( $editor ) ) );
t( 'συντάκτης (ρόλος που εξαιρείται): περνά', 200 === $code, (string) $code );
settings( array( 'rate_limit' => 2, 'ban_strikes' => 0 ) );
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$codes[] = req( $url, browser( '203.0.113.72', array( 'Cookie' => login_cookie( $customer ) ) ) )[0];
}
t( 'πελάτης με λογαριασμό: μετρά στο όριο σελίδων', array( 200, 200, 429 ) === $codes, implode( ',', $codes ) );
// Με πραγματικό WooCommerce: η δηλωμένη ενέργεια get_refreshed_fragments· αλλιώς η test_ok του harness.
$wc_action = class_exists( 'WooCommerce' ) ? 'get_refreshed_fragments' : 'test_ok';
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$codes[] = req( $url . '?wc-ajax=' . $wc_action, browser( '203.0.113.73', array( 'X-Test-WC' => '1' ) ) )[0];
}
t( 'δηλωμένο wc-ajax του WooCommerce: δεν μετρά στο όριο', ! in_array( 429, $codes, true ), implode( ',', $codes ) );
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	$codes[] = req( $url . '?wc-ajax=bogus', browser( '203.0.113.74', array( 'X-Test-WC' => '1' ) ) )[0];
}
t( 'άγνωστο wc-ajax: μετρά όπως κάθε σελίδα', 429 === end( $codes ), implode( ',', $codes ) );
list( $code ) = req( $url . '?wc-ajax=' . $wc_action, array( 'X-Test-IP' => '198.51.100.75', 'User-Agent' => 'GPTBot/1.2', 'X-Test-WC' => '1' ) );
t( 'δηλωμένο wc-ajax από bot: 403', 403 === $code, (string) $code );
settings( array( 'rate_limit' => 0, 'ban_strikes' => 3 ) );
list( , , $body ) = req( $url . '?elementor-preview=1', browser( '203.0.113.76' ) );
t( '?elementor-preview=1 από επισκέπτη: η προστασία φορτώνεται κανονικά', false !== strpos( $body, 'assets/js/protect.js' ) );
list( , , $body ) = req( $url . '?fl_builder', browser( '203.0.113.77', array( 'Cookie' => login_cookie( $customer ) ) ) );
t( 'builder flag από πελάτη χωρίς δικαίωμα επεξεργασίας: η προστασία φορτώνεται', false !== strpos( $body, 'assets/js/protect.js' ) );
settings( array( 'exempt_cap' => 'none' ) );
list( , , $body ) = req( $url, browser( '203.0.113.78', array( 'Cookie' => login_cookie( $editor ) ) ) );
$base_ok = false !== strpos( $body, 'assets/js/protect.js' );
list( , , $body ) = req( $url . '?elementor-preview=1', browser( '203.0.113.78', array( 'Cookie' => login_cookie( $editor ) ) ) );
t( '?elementor-preview=1 από συντάκτη: χωρίς την προστασία (λειτουργεί ο builder)', $base_ok && false === strpos( $body, 'assets/js/protect.js' ) );
settings( array( 'exempt_cap' => 'edit_posts' ) );

/* ---------- REST χωρίς κείμενο ---------- */
list( $code, , $body ) = req( '/wp-json/wp/v2/posts/' . $post->ID, browser( '203.0.113.24' ) );
$json = json_decode( $body, true );
t( 'REST: content.rendered κενό για επισκέπτη', 200 === $code && isset( $json['content']['rendered'] ) && '' === $json['content']['rendered'], substr( $body, 0, 120 ) );
list( $code ) = req( '/wp-json/wp/v2/posts', array( 'X-Test-IP' => '198.51.100.9', 'User-Agent' => 'python-requests/2.32' ) );
t( 'REST: python-requests 403 (στην 1.4 περνούσε)', 403 === $code, (string) $code );

/* ---------- Παγίδα ---------- */
fresh();
$trap = wp_parse_url( home_url( PNCP_Bots::trap_path() ), PHP_URL_PATH );
list( $code ) = req( $trap, browser( '203.0.113.30', array( 'Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Dest' => 'image' ) ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'παγίδα από <img> ξένου site: 403 χωρίς αποκλεισμό', 403 === $code && ! PNCP_Log::is_banned( '203.0.113.30' ) );
list( $code ) = req( $trap, browser( '203.0.113.30', array( 'Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Dest' => 'document' ) ) );
t( 'παγίδα από σύνδεσμο ξένου site: χωρίς αποκλεισμό', ! PNCP_Log::is_banned( '203.0.113.30' ) );
list( $code ) = req( $trap, browser( '203.0.113.30', array( 'Sec-Purpose' => 'prefetch', 'Sec-Fetch-Site' => 'same-origin' ) ) );
t( 'παγίδα από prefetch: χωρίς αποκλεισμό', ! PNCP_Log::is_banned( '203.0.113.30' ) );
list( $code ) = req( $trap, browser( '203.0.113.31', array( 'Sec-Fetch-Site' => 'same-origin', 'Sec-Fetch-Dest' => 'document' ) ) );
wp_cache_flush(); PNCP_Log::reset_cache(); // Οι αποκλεισμοί είναι option με autoload: το CLI κρατά ό,τι διάβασε.
t( 'παγίδα από headless browser στο site: αποκλεισμός', PNCP_Log::is_banned( '203.0.113.31' ) );
list( $code ) = req( $trap, array( 'X-Test-IP' => '203.0.113.32', 'User-Agent' => 'Mozilla/5.0 Chrome' ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'παγίδα από «browser» χωρίς Sec-Fetch (παλιό Safari;): όχι αποκλεισμός την πρώτη φορά', ! PNCP_Log::is_banned( '203.0.113.32' ) );
list( $code ) = req( $trap, array( 'X-Test-IP' => '203.0.113.32', 'User-Agent' => 'Mozilla/5.0 Chrome' ) );
list( $code2 ) = req( $url, browser( '203.0.113.32' ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( '… αποκλεισμός τη δεύτερη φορά και 403 μετά', PNCP_Log::is_banned( '203.0.113.32' ) && 403 === $code2, (string) $code2 );
req( $trap, array( 'X-Test-IP' => '203.0.113.34', 'User-Agent' => 'python-requests/2.32' ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'παγίδα από script με μη-browser User-Agent: αποκλεισμός αμέσως', PNCP_Log::is_banned( '203.0.113.34' ) );
req( $trap, browser( '203.0.113.35', array( 'Sec-Fetch-Site' => 'same-origin', 'Sec-Fetch-Dest' => 'document', 'Sec-Fetch-User' => '?1' ) ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'παγίδα από κλικ ανθρώπου (σύνδεσμος σε σχόλιο): όχι αποκλεισμός', ! PNCP_Log::is_banned( '203.0.113.35' ) );
req( $trap, array( 'X-Test-IP' => '66.249.64.9', 'User-Agent' => 'python-requests/2.32' ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'παγίδα με πλαστή IP της Google (άλλο User-Agent): όχι αποκλεισμός', ! PNCP_Log::is_banned( '66.249.64.9' ) );
PNCP_Log::ban( '66.249.64.10', 60, 'trap' );
t( 'IP της Google δεν αποκλείεται ποτέ', ! PNCP_Log::is_banned( '66.249.64.10' ) );
req( $trap, array( 'X-Test-IP' => '203.0.113.36', 'User-Agent' => 'Mozilla/5.0 (compatible; DuckDuckBot/1.1)' ) );
req( $trap, array( 'X-Test-IP' => '203.0.113.36', 'User-Agent' => 'Mozilla/5.0 (compatible; DuckDuckBot/1.1)' ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'παγίδα από DuckDuckBot: όχι αποκλεισμός', ! PNCP_Log::is_banned( '203.0.113.36' ) );
list( $code ) = req( $trap, array( 'X-Test-IP' => '66.249.64.7', 'User-Agent' => $gb ) );
t( 'παγίδα από πραγματικό Googlebot: χωρίς αποκλεισμό', ! PNCP_Log::is_banned( '66.249.64.7' ) );
PNCP_Log::unban_all();
t( '«Άρση όλων»', ! PNCP_Log::is_banned( '203.0.113.31' ) && ! PNCP_Log::is_banned( '203.0.113.32' ) && array() === PNCP_Log::active_bans() );

/* ---------- robots.txt και TDMRep ---------- */
list( $code, , $body ) = req( '/robots.txt', browser( '203.0.113.33' ) );
t( 'robots.txt: Disallow της παγίδας', false !== strpos( $body, 'Disallow: ' . $trap ) );
t( 'robots.txt: GPTBot και Google-Extended', false !== strpos( $body, 'User-agent: GPTBot' ) && false !== strpos( $body, 'User-agent: Google-Extended' ) );
t( 'robots.txt: όχι Googlebot', false === stripos( $body, 'User-agent: Googlebot' ) );
t( 'robots.txt: OAI-SearchBot δηλώνεται (AI αναζήτηση μπλοκαρισμένη από προεπιλογή)', false !== strpos( $body, 'User-agent: OAI-SearchBot' ) );
$oai = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.3; +https://openai.com/searchbot';
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.81', 'User-Agent' => $oai ) );
t( 'OAI-SearchBot (προεπιλογή): 403', 403 === $code, (string) $code );
settings( array( 'allow_ai_search' => 1 ) );
list( $code, , $body ) = req( '/robots.txt', browser( '203.0.113.33' ) );
t( 'AI αναζήτηση ενεργή: robots.txt χωρίς OAI-SearchBot / PerplexityBot, με GPTBot', false === strpos( $body, 'User-agent: OAI-SearchBot' ) && false === strpos( $body, 'User-agent: PerplexityBot' ) && false !== strpos( $body, 'User-agent: GPTBot' ) );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.82', 'User-Agent' => $oai ) );
t( 'AI αναζήτηση ενεργή: OAI-SearchBot 200', 200 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.83', 'User-Agent' => 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' ) );
t( 'AI αναζήτηση ενεργή: GPTBot (εκπαίδευση) ακόμη 403', 403 === $code, (string) $code );
settings( array( 'allow_ai_search' => 0 ) );
list( $code, $hdr, $body ) = req( '/.well-known/tdmrep.json', browser( '203.0.113.33' ) );
$json = json_decode( $body, true );
t( 'tdmrep.json', 200 === $code && isset( $json[0]['tdm-reservation'] ) && 1 === $json[0]['tdm-reservation'], $body );

/* ---------- Προστατευμένα feeds ---------- */
fresh();
list( $code ) = req( '/skroutz.xml', browser( '203.0.113.40' ) );
t( 'feed χωρίς token: 403', 403 === $code, (string) $code );
$java = array( 'X-Test-IP' => '203.0.113.41', 'User-Agent' => 'Java/1.8.0_401' );
list( $code ) = req( '/skroutz.xml?cp_token=Legacy1234567890Token', $java );
t( 'feed με το token της 1.4 στο URL, ακόμη και με User-Agent «Java/» της λίστας: όχι 403', 403 !== $code, (string) $code );
$new = PNCP_Private_Urls::rotate( 7 );
list( $code ) = req( '/skroutz.xml', array_merge( $java, array( 'X-ScrapeLock-Token' => $new ) ) );
t( 'νέο token στο header X-ScrapeLock-Token', 403 !== $code, (string) $code );
list( $code ) = req( '/skroutz.xml', array_merge( $java, array( 'X-Content-Protect-Token' => $new ) ) );
t( 'header με το παλιό όνομα X-Content-Protect-Token: ισχύει ακόμη', 403 !== $code, (string) $code );
list( $code ) = req( '/skroutz.xml', array_merge( $java, array( 'Authorization' => 'Bearer ' . $new ) ) );
t( 'νέο token στο Authorization: Bearer', 403 !== $code, (string) $code );
list( $code ) = req( '/skroutz.xml?cp_token=Legacy1234567890Token', $java );
t( 'παλιό token μέσα στην περίοδο χάριτος', 403 !== $code, (string) $code );
PNCP_Private_Urls::revoke_previous();
list( $code ) = req( '/skroutz.xml?cp_token=Legacy1234567890Token', $java );
t( 'παλιό token μετά την ακύρωση: 403', 403 === $code, (string) $code );
list( $code ) = req( '/skroutz.xml?cp_token=' . substr( $new, 0, 20 ), $java );
t( 'μισό token: 403', 403 === $code, (string) $code );
$opt = get_option( PNCP_Private_Urls::TOKEN_OPTION );
t( 'στη βάση δεν υπάρχει το token σε καθαρή μορφή', false === strpos( serialize( $opt ), $new ) && false === strpos( serialize( PNCP_Options::stored() ), $new ) );
$stats = PNCP_Private_Urls::stats()['/skroutz.xml'];
t( 'στατιστικά feed: επιτυχίες και αρνήσεις (οι αρνήσεις γράφονται το πολύ μία φορά το λεπτό)', $stats['ok'] >= 4 && $stats['denied'] >= 1 && in_array( $stats['last_via'], array( 'url', 'header' ), true ), wp_json_encode( $stats ) );
list( $code, $hdr ) = req( '/skroutz.xml?cp_token=' . $new, $java );
t( 'feed: Cache-Control private, no-store', false !== strpos( $hdr, 'no-store' ) );
t( 'feed: Referrer-Policy no-referrer και nosniff', false !== strpos( $hdr, 'referrer-policy: no-referrer' ) && false !== strpos( $hdr, 'x-content-type-options: nosniff' ) );

/* ---------- Emergency Mode ---------- */
fresh();
PNCP_Options::set_emergency( 1 );
list( $code ) = req( $url, array( 'X-Test-IP' => '203.0.113.50', 'User-Agent' => 'Mozilla/5.0 Chrome/141' ) );
t( 'emergency: χωρίς Accept-Language 403', 403 === $code, (string) $code );
list( $code ) = req( $url, browser( '203.0.113.51' ) );
t( 'emergency: browser 200', 200 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '203.0.113.52', 'User-Agent' => 'WhatsApp/2.23' ) );
t( 'emergency: preview του WhatsApp περνά', 200 === $code, (string) $code );
t( 'emergency: οι αποθηκευμένες ρυθμίσεις δεν άλλαξαν', 0 === (int) PNCP_Options::stored()['require_browser_headers'] );
PNCP_Options::set_emergency( 0 );
list( $code ) = req( $url, array( 'X-Test-IP' => '203.0.113.53', 'User-Agent' => 'Mozilla/5.0 Chrome/141' ) );
t( 'μετά το emergency: χωρίς Accept-Language ξανά 200', 200 === $code, (string) $code );

/* ---------- Trusted proxy (μέσα από HTTP: X-Test-IP σβήνεται, ελέγχεται το πραγματικό header) ---------- */
remove_all_filters( 'pncp_client_ip' );
$_SERVER['REMOTE_ADDR']           = '8.8.8.8';
$_SERVER['HTTP_CF_CONNECTING_IP'] = '1.2.3.4';
settings( array( 'ip_header' => 'cf_connecting_ip', 'trust_cloudflare' => 1 ) );
PNCP_Ip::reset();
t( 'CF-Connecting-IP από μη-Cloudflare IP: αγνοείται', '8.8.8.8' === PNCP_Ip::client_ip(), PNCP_Ip::client_ip() );
$_SERVER['REMOTE_ADDR'] = '173.245.48.10';
PNCP_Ip::reset();
t( 'CF-Connecting-IP από IP του Cloudflare: γίνεται δεκτό', '1.2.3.4' === PNCP_Ip::client_ip(), PNCP_Ip::client_ip() );
settings( array( 'trust_cloudflare' => 0 ) );
PNCP_Ip::reset();
t( 'Cloudflare όχι αξιόπιστο: αγνοείται', '173.245.48.10' === PNCP_Ip::client_ip() );
$_SERVER['REMOTE_ADDR']    = '173.245.48.10';
$_SERVER['HTTP_X_REAL_IP'] = '1.2.3.4';
settings( array( 'ip_header' => 'x_real_ip', 'trust_cloudflare' => 1 ) );
PNCP_Ip::reset();
t( 'X-Real-IP μέσω Cloudflare (το περνά όπως το έστειλε ο επισκέπτης): αγνοείται', '173.245.48.10' === PNCP_Ip::client_ip(), PNCP_Ip::client_ip() );
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
PNCP_Ip::reset();
t( 'X-Real-IP από Nginx στον ίδιο server: γίνεται δεκτό', '1.2.3.4' === PNCP_Ip::client_ip(), PNCP_Ip::client_ip() );
settings( array( 'ip_header' => 'cf_connecting_ip' ) );
$_SERVER['HTTP_CF_CONNECTING_IP'] = '1.2.3.4';
PNCP_Ip::reset();
t( 'CF-Connecting-IP από ιδιωτική IP (όχι Cloudflare): αγνοείται', '127.0.0.1' === PNCP_Ip::client_ip(), PNCP_Ip::client_ip() );
unset( $_SERVER['HTTP_X_REAL_IP'] );
settings( array( 'ip_header' => 'x_forwarded_for', 'trusted_proxies' => "10.0.0.0/8\n52.1.1.0/24" ) );
$_SERVER['REMOTE_ADDR']          = '52.1.1.7';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '6.6.6.6, 9.9.9.9, 10.0.0.5';
PNCP_Ip::reset();
t( 'X-Forwarded-For: παραλείπει αξιόπιστους proxies από το τέλος', '9.9.9.9' === PNCP_Ip::client_ip(), PNCP_Ip::client_ip() );
$_SERVER['REMOTE_ADDR'] = '5.5.5.5';
PNCP_Ip::reset();
t( 'X-Forwarded-For από άγνωστο proxy: αγνοείται', '5.5.5.5' === PNCP_Ip::client_ip() );
settings( array( 'trust_any_proxy' => 1, 'allow_ips' => '10.0.0.5' ) );
PNCP_Ip::reset();
t( 'trust_any_proxy (1.4): τελευταία τιμή', '10.0.0.5' === PNCP_Ip::client_ip(), PNCP_Ip::client_ip() );
t( 'trust_any_proxy: η IP θεωρείται αναξιόπιστη (δεν ανοίγει επιτρεπόμενες IP / feeds)', ! PNCP_Ip::reliable() );
settings( array( 'allow_ips' => '' ) );
settings( array( 'trust_any_proxy' => 0, 'ip_header' => 'remote_addr', 'trusted_proxies' => '' ) );
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );
PNCP_Ip::reset();

/* ---------- 2.4: όριο 404, ονόματα χρηστών, πάντα αποκλεισμένα ---------- */
settings( array( 'rate_limit' => 0, 'rate_limit_404' => 3, 'ban_strikes' => 0, 'require_browser_headers' => 0, 'block_bots' => 1 ) );
fresh();
$codes = array();
for ( $i = 1; $i <= 4; $i++ ) {
	list( $codes[] ) = req( '/den-yparxei-' . $i . '/', browser( '198.51.100.81' ) );
}
t( 'όριο 404 = 3: 404,404,404,429', array( 404, 404, 404, 429 ) === $codes, implode( ',', $codes ) );
t( 'όριο 404: αιτία rate_404 στο αρχείο', in_array( 'rate_404', log_reasons(), true ), implode( ',', log_reasons() ) );
$codes = array();
foreach ( array( '/x1.png', '/wp-content/missing.css', '/favicon.ico', '/apple-touch-icon.png', '/.well-known/x', '/x2.jpg' ) as $p ) {
	list( $codes[] ) = req( $p, browser( '198.51.100.82' ) );
}
t( 'όριο 404: εικόνες, CSS, favicon, apple-touch-icon, .well-known δεν μετρούν', ! in_array( 429, $codes, true ), implode( ',', $codes ) );
list( $code ) = req( $url, browser( '198.51.100.81' ) );
t( 'όριο 404: οι υπάρχουσες σελίδες περνούν κανονικά', 200 === $code, (string) $code );
settings( array( 'rate_limit_404' => 0 ) );
fresh();
$codes = array();
for ( $i = 1; $i <= 5; $i++ ) {
	list( $codes[] ) = req( '/den-yparxei-b' . $i . '/', browser( '198.51.100.81' ) );
}
t( 'όριο 404 = 0: ανενεργό', array( 404, 404, 404, 404, 404 ) === $codes, implode( ',', $codes ) );

settings( array( 'block_user_enum' => 0 ) );
list( $code, $hdr ) = req( '/?author=1', browser( '198.51.100.83' ) );
t( '?author=1 χωρίς προστασία: ανακατεύθυνση στο /author/…', in_array( $code, array( 301, 302 ), true ) && false !== strpos( $hdr, '/author/' ), (string) $code );
list( $code ) = req( '/wp-json/wp/v2/users', browser( '198.51.100.83' ) );
t( 'REST users χωρίς προστασία: 200', 200 === $code, (string) $code );
settings( array( 'block_user_enum' => 1 ) );
list( $code, $hdr ) = req( '/?author=1', browser( '198.51.100.83' ) );
t( '?author=1 με προστασία: 404, χωρίς ανακατεύθυνση', 404 === $code && false === strpos( $hdr, 'location:' ), (string) $code );
list( $code ) = req( '/?author=1abc', browser( '198.51.100.83' ) );
t( '?author=1abc: επίσης 404', 404 === $code, (string) $code );
list( $code ) = req( '/wp-json/wp/v2/users', browser( '198.51.100.83' ) );
t( 'REST /wp/v2/users με προστασία: 401', 401 === $code, (string) $code );
list( $code ) = req( '/wp-json/wp/v2/users/1', browser( '198.51.100.83' ) );
t( 'REST /wp/v2/users/1 με προστασία: 401', 401 === $code, (string) $code );
list( $code ) = req( '/?rest_route=/wp/v2/users', browser( '198.51.100.83' ) );
t( '?rest_route=/wp/v2/users με προστασία: 401', 401 === $code, (string) $code );
list( $code ) = req( '/wp-json/wp/v2/posts', browser( '198.51.100.83' ) );
t( 'REST posts: ανεπηρέαστο', 200 === $code, (string) $code );
list( $code, $hdr, $body ) = req( '/wp-sitemap.xml', browser( '198.51.100.83' ) );
t( 'sitemap: χωρίς τον χάρτη χρηστών', 200 === $code && false === strpos( $body, 'wp-sitemap-users' ), (string) $code );
list( $code ) = req( '/wp-json/wp/v2/users', browser( '198.51.100.83', array( 'Cookie' => 'wordpress_logged_in_x=1' ) ) );
t( 'ψεύτικο cookie σύνδεσης: δεν ξεκλειδώνει τη λίστα χρηστών', 401 === $code, (string) $code );

settings( array( 'block_ips' => "198.51.100.0/28\n2001:db8:dead::/48", 'allow_ips' => '198.51.100.9' ) );
fresh();
list( $code ) = req( $url, browser( '198.51.100.7' ) );
t( 'πάντα αποκλεισμένη IP (CIDR): 403', 403 === $code, (string) $code );
list( $code ) = req( $url, browser( '2001:db8:dead:1::5' ) );
t( 'πάντα αποκλεισμένη IPv6 (CIDR): 403', 403 === $code, (string) $code );
list( $code ) = req( $url, browser( '198.51.100.9' ) );
t( 'πάντα επιτρεπτή IP μέσα στο ίδιο CIDR: 200 (προηγείται)', 200 === $code, (string) $code );
list( $code ) = req( $url, browser( '198.51.100.20' ) );
t( 'IP εκτός CIDR: 200', 200 === $code, (string) $code );
t( 'αρχείο: blocked_ip', in_array( 'blocked_ip', log_reasons(), true ), implode( ',', log_reasons() ) );
settings( array( 'block_ips' => '', 'allow_ips' => '', 'block_referrers' => "copy-site.example\nhttps://other.example/path" ) );
fresh();
list( $code ) = req( $url, browser( '198.51.100.30', array( 'Referer' => 'https://www.copy-site.example/a' ) ) );
t( 'αποκλεισμένος referrer (υποτομέας): 403', 403 === $code, (string) $code );
list( $code ) = req( $url, browser( '198.51.100.30', array( 'Referer' => 'https://other.example/' ) ) );
t( 'αποκλεισμένος referrer γραμμένος ως URL: 403', 403 === $code, (string) $code );
list( $code ) = req( $url, browser( '198.51.100.30', array( 'Referer' => 'https://notcopy-site.example/' ) ) );
t( 'referrer που απλώς τελειώνει με το ίδιο κείμενο: 200', 200 === $code, (string) $code );
list( $code ) = req( $url, browser( '198.51.100.30', array( 'Referer' => 'https://copy-site.example.evil.test/' ) ) );
t( 'referrer με το όνομα στη μέση: 200', 200 === $code, (string) $code );
t( 'αρχείο: blocked_ref', in_array( 'blocked_ref', log_reasons(), true ), implode( ',', log_reasons() ) );
settings( array( 'block_referrers' => '' ) );

/* ---------- 2.4: Content Signals, πηγή στο RSS, Cloudflare ---------- */
settings( array( 'content_signal' => 1, 'allow_ai_search' => 0 ) );
list( $code, $hdr, $body ) = req( '/robots.txt', browser( '198.51.100.40' ) );
t( 'robots.txt: Content-Signal ai-input=no', false !== strpos( $body, 'Content-Signal: search=yes, ai-input=no, ai-train=no' ), $body );
settings( array( 'allow_ai_search' => 1 ) );
list( $code, $hdr, $body ) = req( '/robots.txt', browser( '198.51.100.40' ) );
t( 'robots.txt: με AI search ai-input=yes', false !== strpos( $body, 'Content-Signal: search=yes, ai-input=yes, ai-train=no' ), $body );
settings( array( 'content_signal' => 0, 'allow_ai_search' => 0 ) );
list( $code, $hdr, $body ) = req( '/robots.txt', browser( '198.51.100.40' ) );
t( 'robots.txt: χωρίς Content-Signal όταν είναι ανενεργό', false === strpos( $body, 'Content-Signal' ) );

settings( array( 'feed_mode' => 'full', 'feed_source_link' => 1 ) );
list( $code, $hdr, $body ) = req( '/feed/', browser( '198.51.100.41' ) );
t( 'RSS πλήρες: γραμμή πηγής με σύνδεσμο', 200 === $code && false !== strpos( $body, 'first appeared on' ) && false !== strpos( $body, htmlspecialchars( home_url( '/' ) ) ), (string) $code );
settings( array( 'feed_source_link' => 0 ) );
list( $code, $hdr, $body ) = req( '/feed/', browser( '198.51.100.41' ) );
t( 'RSS πλήρες χωρίς τη ρύθμιση: χωρίς γραμμή πηγής', 200 === $code && false === strpos( $body, 'first appeared on' ), (string) $code );
settings( array( 'feed_mode' => 'excerpt', 'feed_source_link' => 1 ) );
list( $code, $hdr, $body ) = req( '/feed/', browser( '198.51.100.41' ) );
t( 'RSS περίληψη: μόνο ο σύνδεσμος «Read the full article», όχι διπλή γραμμή', 200 === $code && false === strpos( $body, 'first appeared on' ), (string) $code );

fresh();
list( $code, $hdr ) = req( $url, array( 'X-Test-IP' => '198.51.100.42', 'User-Agent' => 'GPTBot' ) );
t( '403: cf-edge-cache: no-cache (Cloudflare APO)', 403 === $code && false !== strpos( $hdr, 'cf-edge-cache: no-cache' ), $hdr );
list( $code, $hdr ) = req( $url, browser( '198.51.100.43' ) );
t( '200: χωρίς cf-edge-cache από το ScrapeLock', 200 === $code && false === strpos( $hdr, 'cf-edge-cache' ) );
t( 'cloudflare_use_cache: ανεπηρέαστο σε κανονική σελίδα', true === apply_filters( 'cloudflare_use_cache', true ) );

/* ---------- 2.4: πρώιμος έλεγχος (mu-plugin) ---------- */
settings( array( 'early_mode' => 1, 'block_bots' => 1, 'block_empty_ua' => 1 ) );
t( 'πρώιμος έλεγχος: το αρχείο γράφτηκε', PNCP_Early::installed() && PNCP_Early::ours( PNCP_Early::path() ), PNCP_Early::path() );
fresh();
list( $code, $hdr ) = req( $url, array( 'X-Test-IP' => '198.51.100.50', 'User-Agent' => 'GPTBot' ) );
t( 'πρώιμος έλεγχος: GPTBot 403 πριν φορτώσουν τα plugins', 403 === $code && false === strpos( $hdr, 'x-test-muplugins-loaded' ), $code . ' ' . $hdr );
t( 'πρώιμος έλεγχος: γράφεται στο αρχείο (bot_ua)', in_array( 'bot_ua', log_reasons(), true ), implode( ',', log_reasons() ) );
list( $code, $hdr ) = req( $url, browser( '198.51.100.51' ) );
t( 'πρώιμος έλεγχος: browser 200', 200 === $code && false !== strpos( $hdr, 'x-test-muplugins-loaded' ), (string) $code );
list( $code, $hdr ) = req( $url, array( 'X-Test-IP' => '66.249.66.1', 'User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'X-Test-RDNS' => 'crawl-66-249-66-1.googlebot.com', 'X-Test-FDNS' => '66.249.66.1' ) );
t( 'πρώιμος έλεγχος: το Googlebot περνά στον κανονικό έλεγχο', 200 === $code && false !== strpos( $hdr, 'x-test-muplugins-loaded' ), (string) $code );
list( $code, $hdr ) = req( $url, array( 'X-Test-IP' => '198.51.100.52', 'User-Agent' => 'GPTBot' ), 'POST' );
t( 'πρώιμος έλεγχος: POST αφήνεται στον κανονικό (που μπλοκάρει)', 403 === $code && false !== strpos( $hdr, 'x-test-muplugins-loaded' ), $code . ' ' . $hdr );
PNCP_Log::ban( '198.51.100.53', 10, 'trap' );
list( $code, $hdr ) = req( $url, browser( '198.51.100.53' ) );
t( 'πρώιμος έλεγχος: προσωρινά αποκλεισμένη IP 403', 403 === $code && false === strpos( $hdr, 'x-test-muplugins-loaded' ), (string) $code );
list( $code, $hdr ) = req( $url, browser( '198.51.100.53', array( 'Cookie' => 'wordpress_logged_in_abc=x' ) ) );
t( 'πρώιμος έλεγχος: με cookie σύνδεσης αφήνεται στον κανονικό', false !== strpos( $hdr, 'x-test-muplugins-loaded' ), (string) $code );
list( $code, $hdr ) = req( '/skroutz.xml?token=wrong', array( 'X-Test-IP' => '198.51.100.54', 'User-Agent' => 'GPTBot' ) );
t( 'πρώιμος έλεγχος: τα ιδιωτικά feeds αφήνονται στον κανονικό', false !== strpos( $hdr, 'x-test-muplugins-loaded' ), (string) $code );
list( $code, $hdr ) = req( '/wp-login.php', array( 'X-Test-IP' => '198.51.100.55', 'User-Agent' => 'GPTBot' ) );
t( 'πρώιμος έλεγχος: wp-login.php αφήνεται', false !== strpos( $hdr, 'x-test-muplugins-loaded' ), (string) $code );
settings( array( 'block_ips' => '173.245.48.10' ) );
$_SERVER['REMOTE_ADDR'] = '173.245.48.10';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 Chrome';
putenv( 'PNCP_TEST_IP' );
PNCP_Ip::reset();
t( 'πρώιμος έλεγχος: IP της Cloudflare (λάθος ρύθμιση IP): όχι απόφαση με βάση την IP', null === PNCP_Early::check(), wp_json_encode( PNCP_Early::check() ) );
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
unset( $_SERVER['HTTP_USER_AGENT'] );
PNCP_Ip::reset();
settings( array( 'block_ips' => '', 'early_mode' => 0 ) );
t( 'πρώιμος έλεγχος ανενεργός: το αρχείο αφαιρέθηκε', ! file_exists( PNCP_Early::path() ) );
file_put_contents( PNCP_Early::path(), "<?php\n// someone else's file\n" );
settings( array( 'early_mode' => 1 ) );
t( 'πρώιμος έλεγχος: ξένο αρχείο με το ίδιο όνομα δεν αντικαθίσταται', ! PNCP_Early::installed() && false !== strpos( (string) file_get_contents( PNCP_Early::path() ), 'someone else' ) );
settings( array( 'early_mode' => 0 ) );
t( 'πρώιμος έλεγχος: ξένο αρχείο δεν σβήνεται', file_exists( PNCP_Early::path() ) );
unlink( PNCP_Early::path() );
PNCP_Log::unban_all();

/* ---------- 2.5: επαλήθευση AI bots με τις επίσημες λίστες IP ---------- */
$oai = 'Mozilla/5.0 (compatible; OAI-SearchBot/1.3; +https://openai.com/searchbot)';
$cgu = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot';
$pxb = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)';
PNCP_Ip::store_list( 'openai_search', array( '198.51.100.200/29' ) );
PNCP_Ip::store_list( 'openai_user', array( '2001:db8:a1::/48' ) );
delete_option( PNCP_Ip::LISTS_OPTION . '_perplexity_bot' );
$pncp_bot_list = PNCP_Options::default_bot_list(); // Restored at the end of the section.
settings( array( 'block_bots' => 1, 'bot_list' => "GPTBot\nOAI-SearchBot\nChatGPT-User\nPerplexityBot", 'allow_ai_search' => 1, 'verify_ai_bots' => 1, 'rate_limit' => 1, 'ban_strikes' => 2, 'require_browser_headers' => 0 ) );
PNCP_Ip::reset();
t( 'λίστες AI: κατεβαίνουν μόνο με AI αναζήτηση + επαλήθευση', array() === array_diff( array( 'openai_search', 'openai_user', 'perplexity_bot', 'perplexity_user' ), PNCP_Ip::needed_lists() ) );
fresh();
$codes = array();
for ( $i = 0; $i < 3; $i++ ) {
	list( $codes[] ) = req( $url, array( 'X-Test-IP' => '198.51.100.201', 'User-Agent' => $oai ) );
}
t( 'πραγματικό OAI-SearchBot: ποτέ όριο (3 σελίδες με όριο 1)', array( 200, 200, 200 ) === $codes, implode( ',', $codes ) );
list( $code ) = req( $url, array( 'X-Test-IP' => '2001:db8:a1:5::9', 'User-Agent' => $cgu ) );
t( 'πραγματικό ChatGPT-User (IPv6 από τη λίστα του): 200', 200 === $code, (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '203.0.113.77', 'User-Agent' => $oai ) );
t( 'ψεύτικο OAI-SearchBot: 403', 403 === $code, (string) $code );
t( 'αρχείο: fake_ai_bot', in_array( 'fake_ai_bot', log_reasons(), true ), implode( ',', log_reasons() ) );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.201', 'User-Agent' => $cgu ) );
t( 'ChatGPT-User από IP του OAI-SearchBot (όχι της δικής του λίστας): 403', 403 === $code, (string) $code );
req( $url, array( 'X-Test-IP' => '203.0.113.77', 'User-Agent' => $oai ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'ψεύτικο AI bot: μετρά ως παράβαση (αποκλεισμός μετά από 2)', PNCP_Log::is_banned( '203.0.113.77' ) );
PNCP_Log::ban( '198.51.100.202', 10, 'trap' );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.202', 'User-Agent' => $oai ) );
t( 'πραγματικό OAI-SearchBot περνά και από αποκλεισμένη IP (όπως το Googlebot)', 200 === $code, (string) $code );
fresh();
$trap = wp_parse_url( home_url( PNCP_Bots::trap_path() ), PHP_URL_PATH );
req( $trap, array( 'X-Test-IP' => '198.51.100.203', 'User-Agent' => $oai ) );
wp_cache_flush(); PNCP_Log::reset_cache();
t( 'πραγματικό OAI-SearchBot στην παγίδα: χωρίς αποκλεισμό', ! PNCP_Log::is_banned( '198.51.100.203' ) );
list( $code ) = req( $url, array( 'X-Test-IP' => '203.0.113.78', 'User-Agent' => $pxb ) );
t( 'PerplexityBot χωρίς κατεβασμένη λίστα: όπως πριν (επιτρεπτό)', 200 === $code, (string) $code );
settings( array( 'verify_ai_bots' => 0 ) );
fresh();
list( $code ) = req( $url, array( 'X-Test-IP' => '203.0.113.79', 'User-Agent' => $oai ) );
t( 'επαλήθευση ανενεργή: OAI-SearchBot από οποιαδήποτε IP, όπως πριν', 200 === $code, (string) $code );
PNCP_Ip::reset();
t( 'επαλήθευση ανενεργή: οι λίστες AI δεν κατεβαίνουν', ! in_array( 'openai_search', PNCP_Ip::needed_lists(), true ) );
settings( array( 'verify_ai_bots' => 1, 'allow_ai_search' => 0 ) );
fresh();
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.201', 'User-Agent' => $oai ) );
t( 'AI αναζήτηση ανενεργή: και το πραγματικό OAI-SearchBot μπλοκάρεται από τη λίστα bots', 403 === $code && in_array( 'bot_ua', log_reasons(), true ), (string) $code );
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.201', 'User-Agent' => 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' ) );
t( 'GPTBot (εκπαίδευση): πάντα 403', 403 === $code, (string) $code );
PNCP_Ip::reset();
t( 'AI αναζήτηση ανενεργή: οι λίστες AI δεν κατεβαίνουν', ! in_array( 'openai_search', PNCP_Ip::needed_lists(), true ) );
foreach ( array_values( PNCP_Bots::ai_bot_lists() ) as $pncp_list ) {
	delete_option( PNCP_Ip::LISTS_OPTION . '_' . $pncp_list );
}
settings( array( 'rate_limit' => 0, 'ban_strikes' => 3, 'allow_ai_search' => 0, 'bot_list' => $pncp_bot_list ) );
PNCP_Log::unban_all();
PNCP_Ip::reset();

/* ---------- 2.5: headless και ψεύτικοι browsers ---------- */
$chrome  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
$hints   = '"Google Chrome";v="141", "Chromium";v="141", "Not.A/Brand";v="24"';
$real    = array( 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document', 'Sec-Fetch-Site' => 'none', 'Sec-CH-UA' => $hints );
$hb      = static function ( $ip, $ua, $extra = array() ) {
	return array_merge( array( 'X-Test-IP' => $ip, 'User-Agent' => $ua, 'Accept-Language' => 'el-GR,el;q=0.9' ), $extra );
};
settings( array( 'block_headless' => 1, 'require_browser_headers' => 0, 'rate_limit' => 0, 'block_bots' => 1 ) );
fresh();
list( $code ) = req( $url, $hb( '198.51.100.110', $chrome, array( 'Sec-Fetch-Mode' => 'navigate', 'Sec-CH-UA' => '"HeadlessChrome";v="141", "Chromium";v="141"' ) ) );
t( 'headless Chrome με κανονικό User-Agent (Sec-CH-UA: HeadlessChrome): 403', 403 === $code, (string) $code );
t( 'αρχείο: headless', in_array( 'headless', log_reasons(), true ), implode( ',', log_reasons() ) );
list( $code ) = req( $url, $hb( '198.51.100.111', $chrome, array( 'X-Test-HTTPS' => '1' ) ) );
t( 'HTTPS: «Chrome» χωρίς Sec-Fetch και Sec-CH-UA (script): 403', 403 === $code, (string) $code );
t( 'αρχείο: fake_browser', in_array( 'fake_browser', log_reasons(), true ), implode( ',', log_reasons() ) );
list( $code ) = req( $url, $hb( '198.51.100.112', $chrome, array_merge( $real, array( 'X-Test-HTTPS' => '1' ) ) ) );
t( 'HTTPS: πραγματικός Chrome (Sec-Fetch + Sec-CH-UA): 200', 200 === $code, (string) $code );
list( $code ) = req( $url, $hb( '198.51.100.113', $chrome ) );
t( 'HTTP: «Chrome» χωρίς τα headers: 200 (σε HTTP οι browsers δεν τα στέλνουν πάντα)', 200 === $code, (string) $code );
list( $code ) = req( $url, $hb( '198.51.100.114', 'Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36 [FBAN/EMA]', array( 'X-Test-HTTPS' => '1' ) ) );
t( 'HTTPS: in-app browser (Android WebView) χωρίς headers: 200', 200 === $code, (string) $code );
list( $code ) = req( $url, $hb( '198.51.100.115', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0', array( 'X-Test-HTTPS' => '1' ) ) );
t( 'HTTPS: «Firefox» χωρίς Sec-Fetch: 403', 403 === $code, (string) $code );
list( $code ) = req( $url, $hb( '198.51.100.116', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0', array( 'X-Test-HTTPS' => '1', 'Sec-Fetch-Mode' => 'navigate' ) ) );
t( 'HTTPS: πραγματικός Firefox (Sec-Fetch, χωρίς client hints): 200', 200 === $code, (string) $code );
list( $code ) = req( $url, $hb( '198.51.100.117', 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1', array( 'X-Test-HTTPS' => '1' ) ) );
t( 'HTTPS: παλιό Safari χωρίς Sec-Fetch: 200 (δεν ελέγχεται)', 200 === $code, (string) $code );
list( $code ) = req( $url, $hb( '198.51.100.118', 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.0 Safari/537.36', array( 'X-Test-HTTPS' => '1' ) ) );
t( 'HTTPS: Chrome 80 (πριν τα client hints): 200', 200 === $code, (string) $code );
list( $code ) = req( $url, $hb( '198.51.100.119', 'facebookexternalhit/1.1 Chrome/141.0.0.0', array( 'X-Test-HTTPS' => '1' ) ) );
t( 'HTTPS: preview της λίστας «Πάντα επιτρεπτά»: 200', 200 === $code, (string) $code );
list( $code ) = req( $url, $hb( '66.249.66.1', 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', array( 'X-Test-HTTPS' => '1', 'X-Test-RDNS' => 'crawl-66-249-66-1.googlebot.com', 'X-Test-FDNS' => '66.249.66.1' ) ) );
t( 'HTTPS: πραγματικό Googlebot smartphone χωρίς Sec-Fetch: 200', 200 === $code, (string) $code );
settings( array( 'block_headless' => 0 ) );
fresh();
list( $code ) = req( $url, $hb( '198.51.100.120', $chrome, array( 'X-Test-HTTPS' => '1', 'Sec-CH-UA' => '"HeadlessChrome";v="141"' ) ) );
t( 'ρύθμιση ανενεργή: όπως πριν', 200 === $code, (string) $code );

/* ---------- 2.4: αναβάθμιση και νέα εγκατάσταση ---------- */
// Το dbDelta του PNCP_Log::install() βγάζει Deprecated μέσα στο SQLite drop-in (wp-sqlite-db), όχι στο plugin.
$pncp_upgrade = static function () {
	$level = error_reporting( E_ALL & ~E_DEPRECATED );
	pncp_upgrade();
	error_reporting( $level );
};
$keep    = get_option( PNCP_OPTION );
$keep_v  = get_option( 'pncp_version' );
$new_240 = array_keys( PNCP_Options::new_in_240() );
update_option( PNCP_OPTION, array_diff_key( $keep, array_flip( $new_240 ) ) );
update_option( 'pncp_version', '2.3.0' );
$pncp_upgrade();
$after = get_option( PNCP_OPTION );
t( 'αναβάθμιση από 2.3.0: τα νέα μένουν ανενεργά', 0 === $after['rate_limit_404'] && 0 === $after['block_user_enum'] && 0 === $after['feed_source_link'] && 0 === $after['content_signal'] && 0 === $after['early_mode'], wp_json_encode( array_intersect_key( $after, array_flip( $new_240 ) ) ) );
t( 'αναβάθμιση από 2.3.0: οι υπόλοιπες ρυθμίσεις δεν άλλαξαν', array_diff_key( $after, array_flip( $new_240 ) ) == array_diff_key( $keep, array_flip( $new_240 ) ) );
update_option( PNCP_OPTION, array_merge( $after, array( 'block_user_enum' => 1 ) ) );
update_option( 'pncp_version', '2.3.0' );
$pncp_upgrade();
t( 'αναβάθμιση: μια τιμή που υπάρχει ήδη δεν αλλάζει', 1 === (int) get_option( PNCP_OPTION )['block_user_enum'] );
update_option( PNCP_OPTION, array_diff_key( $keep, array( 'verify_ai_bots' => 1, 'block_headless' => 1 ) ) );
update_option( 'pncp_version', '2.4.0' );
$pncp_upgrade();
$after = get_option( PNCP_OPTION );
t( 'αναβάθμιση από 2.4.0: τα νέα της 2.5 μένουν ανενεργά, τα υπόλοιπα ίδια', 0 === $after['verify_ai_bots'] && 0 === $after['block_headless'] && array_diff_key( $after, array( 'verify_ai_bots' => 1, 'block_headless' => 1 ) ) == array_diff_key( $keep, array( 'verify_ai_bots' => 1, 'block_headless' => 1 ) ) );
update_option( PNCP_OPTION, array_diff_key( $keep, array_flip( $new_240 ), array( 'verify_ai_bots' => 1 ) ) );
update_option( 'pncp_version', '2.3.0' );
$pncp_upgrade();
$after = get_option( PNCP_OPTION );
t( 'αναβάθμιση από 2.3.0 κατευθείαν: ανενεργά και τα νέα της 2.4 και της 2.5', 0 === $after['verify_ai_bots'] && 0 === $after['rate_limit_404'] && 0 === $after['block_user_enum'] );
delete_option( PNCP_OPTION );
$pncp_upgrade();
$fresh = PNCP_Options::stored();
t( 'νέα εγκατάσταση: επαλήθευση AI bots ενεργή', 1 === $fresh['verify_ai_bots'] );
t( 'νέα εγκατάσταση: όριο 404 30, ονόματα χρηστών κρυφά, πηγή RSS, Content-Signal, πρώιμος έλεγχος ανενεργός', 30 === $fresh['rate_limit_404'] && 1 === $fresh['block_user_enum'] && 1 === $fresh['feed_source_link'] && 1 === $fresh['content_signal'] && 0 === $fresh['early_mode'] );
update_option( PNCP_OPTION, $keep );
update_option( 'pncp_version', $keep_v );
PNCP_Options::flush();
PNCP_Options::set_emergency( 1 );
t( 'emergency: κρύβει τα ονόματα χρηστών και όριο 404 το πολύ 10', 1 === PNCP_Options::get()['block_user_enum'] && PNCP_Options::get()['rate_limit_404'] <= 10 && PNCP_Options::get()['rate_limit_404'] > 0 );
PNCP_Options::set_emergency( 0 );
PNCP_Options::flush();
PNCP_Bots::no_cache();
t( 'cloudflare_use_cache: false μετά από no_cache()', false === apply_filters( 'cloudflare_use_cache', true ) );

/* ---------- Απενεργοποίηση: ποτέ με ένα κλικ ---------- */
settings( array( 'enabled' => 1 ) );
fresh();
list( $code ) = req( $url, array( 'X-Test-IP' => '198.51.100.60', 'User-Agent' => 'GPTBot' ) );
settings( array( 'enabled' => 0 ) );
list( $code2 ) = req( $url, array( 'X-Test-IP' => '198.51.100.60', 'User-Agent' => 'GPTBot' ) );
t( 'ανενεργό plugin: τίποτα δεν μπλοκάρεται', 403 === $code && 200 === $code2, "$code/$code2" );
settings( array( 'enabled' => 1 ) );

echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
