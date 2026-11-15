<?php
/**
 * ScrapeLock — δοκιμές των διορθώσεων της 3.6 σε πραγματικό WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_fixes351.php
 *
 * 1. Πλαστή τοπική IP (127.0.0.1, η IP του server) στο header του «Real visitor IP» από edge του CDN: δεν
 *    περνά πια ως «ο ίδιος ο server». Header χωρίς IP από edge: μετριέται, δεν εξαιρείται ως κοινό edge.
 * 2. fresh_option(): το «alloptions» γράφεται στο object cache μόνο όταν η τιμή άλλαξε.
 * 3. Ο προϋπολογισμός των αναζητήσεων DNS παίρνεται με ατομική αύξηση.
 * 4. Crawler με αναπάντητο DNS: όχι 403 «no_browser» (ούτε σε Emergency Mode).
 * (Η 5., ο ωριαίος έλεγχος του Lockdown, είναι στο t_lockdown.php, όπου το site είναι κλειδωμένο.)
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

/** Αίτημα με curl: επιστρέφει [code, body]. */
function req( $path, $headers = array() ) {
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
			CURLOPT_TIMEOUT        => 30,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Ip::reset();
}

/** Το $_SERVER ενός αιτήματος: REMOTE_ADDR και τα headers IP, όλα τα άλλα σβήνονται. */
function request_from( $remote, $headers = array() ) {
	foreach ( array( 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_SCRAPELOCK_CDN' ) as $k ) {
		unset( $_SERVER[ $k ] );
	}
	$_SERVER['REMOTE_ADDR'] = $remote;
	foreach ( $headers as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
}

$pncp_server_old = isset( $_SERVER['SERVER_ADDR'] ) ? $_SERVER['SERVER_ADDR'] : null;
$pncp_saved      = PNCP_Options::stored();
$pncp_bunny_old  = get_option( PNCP_Ip::LISTS_OPTION . '_bunny', null );
update_option( 'pncp_emergency_until', 0 );
settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'rate_limit'              => 0,
		'rate_limit_search'       => 0,
		'rate_limit_rest'         => 0,
		'rate_limit_404'          => 0,
		'rate_limit_unverified'   => 0,
		'rate_limit_datacenter'   => 0,
		'human_check'             => 0,
		'require_browser_headers' => 0,
		'block_headless'          => 0,
		'block_ips'               => '',
		'allow_ips'               => '',
		'cdn_secret'              => '',
		'trust_any_proxy'         => 0,
		'trusted_proxies'         => '',
	)
);
PNCP_Ip::store_list( 'bunny', array( '89.187.162.1' ) );
$_SERVER['SERVER_ADDR'] = '198.51.100.7';

/* ---------- 1. Πλαστή τοπική IP από edge του Bunny (χωρίς CDN secret) ---------- */
settings( array( 'ip_header' => 'x_real_ip', 'trust_bunny' => 1 ) );

request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '127.0.0.1' ) );
t( 'Bunny edge + X-Real-IP 127.0.0.1: η IP διαβάζεται, αλλά δεν είναι αξιόπιστη', '127.0.0.1' === PNCP_Ip::client_ip() && ! PNCP_Ip::reliable(), PNCP_Ip::client_ip() );
t( 'Bunny edge + X-Real-IP 127.0.0.1: όχι «ο ίδιος ο server»', ! PNCP_Ip::is_local_request() );

request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '198.51.100.7' ) );
t( 'Bunny edge + X-Real-IP = η IP του server: όχι «ο ίδιος ο server»', '198.51.100.7' === PNCP_Ip::client_ip() && ! PNCP_Ip::is_local_request() );

request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '::1' ) );
t( 'Bunny edge + X-Real-IP ::1: όχι «ο ίδιος ο server»', ! PNCP_Ip::is_local_request() );

// Στο check(): με την IP στη λίστα αποκλεισμού, το αίτημα πριν περνούσε ως «local» πριν από κάθε έλεγχο.
settings( array( 'block_ips' => "127.0.0.1\n198.51.100.7" ) );
request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '127.0.0.1' ) );
$pncp_v = PNCP_Bots::check( 'page', false );
t( 'check(): Bunny edge + X-Real-IP 127.0.0.1 φτάνει στους ελέγχους (λίστα αποκλεισμού: 403)', is_array( $pncp_v ) && 403 === $pncp_v['code'] && 'blocked_ip' === $pncp_v['reason'], wp_json_encode( $pncp_v ) );
request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '198.51.100.7' ) );
$pncp_v = PNCP_Bots::check( 'page', false );
t( 'check(): Bunny edge + X-Real-IP = IP του server: 403', is_array( $pncp_v ) && 'blocked_ip' === $pncp_v['reason'], wp_json_encode( $pncp_v ) );
t( 'early check: Bunny edge + X-Real-IP 127.0.0.1 δεν περνά ως local', null !== ( function () {
	settings( array( 'early_mode' => 1 ) );
	request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '127.0.0.1' ) );
	$r = PNCP_Early::check();
	settings( array( 'early_mode' => 0 ) );
	return $r;
} )() );

// Το πραγματικό localhost (cron, cache preload) περνά όπως πριν, ακόμη και στη λίστα αποκλεισμού.
request_from( '127.0.0.1' );
t( 'localhost χωρίς header: «ο ίδιος ο server»', PNCP_Ip::is_local_request() && null === PNCP_Bots::check( 'page', false ) );
request_from( '198.51.100.7' );
t( 'η IP του server χωρίς header: «ο ίδιος ο server»', PNCP_Ip::is_local_request() && null === PNCP_Bots::check( 'page', false ) );
request_from( '127.0.0.1', array( 'HTTP_X_REAL_IP' => '127.0.0.1' ) );
t( 'Nginx στον ίδιο server (X-Real-IP 127.0.0.1 από 127.0.0.1): «ο ίδιος ο server»', PNCP_Ip::is_local_request() && null === PNCP_Bots::check( 'page', false ) );
request_from( '10.0.0.5', array( 'HTTP_X_REAL_IP' => '127.0.0.1' ) );
t( 'proxy στο ιδιωτικό δίκτυο (10.0.0.5) με X-Real-IP 127.0.0.1: «ο ίδιος ο server»', PNCP_Ip::is_local_request() );

// Πίσω από Nginx στον ίδιο server: το edge του Bunny είναι ένα βήμα πιο πέρα στο X-Forwarded-For.
settings( array( 'ip_header' => 'x_forwarded_for', 'block_ips' => '' ) );
request_from( '127.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 89.187.162.1' ) );
t( 'Nginx → Bunny edge → X-Forwarded-For 127.0.0.1: όχι «ο ίδιος ο server»', '127.0.0.1' === PNCP_Ip::client_ip() && ! PNCP_Ip::is_local_request(), PNCP_Ip::client_ip() );
request_from( '127.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.9, 89.187.162.1' ) );
t( 'Nginx → Bunny edge → επισκέπτης: η IP του επισκέπτη, όπως πριν', '203.0.113.9' === PNCP_Ip::client_ip() && ! PNCP_Ip::is_local_request() );

// «Trust every proxy» (1.4): η IP από το header δεν είναι αξιόπιστη, άρα δεν περνά ως server.
settings( array( 'ip_header' => 'x_forwarded_for', 'trust_any_proxy' => 1 ) );
request_from( '203.0.113.50', array( 'HTTP_X_FORWARDED_FOR' => '127.0.0.1' ) );
t( '«Trust every proxy» + X-Forwarded-For 127.0.0.1: όχι «ο ίδιος ο server»', '127.0.0.1' === PNCP_Ip::client_ip() && ! PNCP_Ip::is_local_request() );
settings( array( 'trust_any_proxy' => 0 ) );

/* ---------- 1β. Edge του CDN χωρίς IP επισκέπτη στο header ---------- */
settings( array( 'ip_header' => 'x_real_ip' ) );
request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => 'σκουπίδι' ) );
t( 'Bunny edge + X-Real-IP χωρίς IP: η IP του edge, αλλά όχι «κοινό edge» (μετριέται)', '89.187.162.1' === PNCP_Ip::client_ip() && ! PNCP_Ip::is_cdn_edge( '89.187.162.1' ) );
request_from( '89.187.162.1' );
t( 'Bunny edge χωρίς X-Real-IP: όχι «κοινό edge» (μετριέται)', '89.187.162.1' === PNCP_Ip::client_ip() && ! PNCP_Ip::is_cdn_edge( '89.187.162.1' ) );
settings( array( 'block_ips' => '89.187.162.1' ) );
request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => 'σκουπίδι' ) );
$pncp_v = PNCP_Bots::check( 'page', false );
t( 'check(): Bunny edge με άκυρο X-Real-IP: οι έλεγχοι ανά IP ισχύουν (λίστα αποκλεισμού: 403)', is_array( $pncp_v ) && 'blocked_ip' === $pncp_v['reason'], wp_json_encode( $pncp_v ) );
settings( array( 'block_ips' => '' ) );
// Χωρίς ρύθμιση «Real visitor IP» (remote_addr) το edge είναι κοινό για όλους τους επισκέπτες, όπως πριν.
settings( array( 'ip_header' => 'remote_addr' ) );
request_from( '89.187.162.1' );
t( 'Bunny edge με «Real visitor IP» = REMOTE_ADDR: κοινό edge, όπως πριν', PNCP_Ip::is_cdn_edge( '89.187.162.1' ) );
// Με τη ρύθμιση για άλλο CDN (CF-Connecting-IP), το edge του Bunny δεν είναι αξιόπιστο γι' αυτήν: κοινό, όπως πριν.
settings( array( 'ip_header' => 'cf_connecting_ip' ) );
request_from( '89.187.162.1' );
t( 'Bunny edge με CF-Connecting-IP επιλεγμένο: κοινό edge, όπως πριν', PNCP_Ip::is_cdn_edge( '89.187.162.1' ) );
settings( array( 'ip_header' => 'x_real_ip' ) );
request_from( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '203.0.113.9' ) );
t( 'Bunny edge με σωστό X-Real-IP: ο επισκέπτης, όπως πριν', '203.0.113.9' === PNCP_Ip::client_ip() && ! PNCP_Ip::is_cdn_edge( '203.0.113.9' ) );

/* ---------- 1γ. Το ίδιο στον έλεγχο πριν από την cache (χωρίς WordPress) ---------- */
require_once PNCP_DIR . 'includes/class-pncp-precheck-runtime.php';
$pncp_set = static function ( $list ) {
	$exact = array();
	$cidr  = array();
	foreach ( $list as $r ) {
		if ( false !== strpos( $r, '/' ) ) {
			$cidr[] = $r;
		} else {
			$exact[ $r ] = true;
		}
	}
	return array( $exact, $cidr );
};
$pncp_c = array(
	'header'          => 'HTTP_X_REAL_IP',
	'trust_any'       => 0,
	'format'          => 3,
	'cdn_secret_hash' => '',
	'proxies_cdn'     => array( 'bunny' => true, 'cf' => true ),
	'cdn_bunny'       => $pncp_set( array( '89.187.162.1' ) ),
	'cdn_cf'          => $pncp_set( array() ),
	'proxies'         => $pncp_set( array() ),
	'private'         => 1,
);
$pncp_rt = static function ( $remote, $headers, $c ) {
	request_from( $remote, $headers );
	$reliable = true;
	$ip       = PNCP_Precheck_Runtime::client_ip( $c, $reliable );
	return array( $ip, PNCP_Precheck_Runtime::is_local_request( $ip, $reliable ), PNCP_Precheck_Runtime::$no_visitor_ip );
};
list( $pncp_ip, $pncp_local ) = $pncp_rt( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '127.0.0.1' ), $pncp_c );
t( 'pre-cache: Bunny edge + X-Real-IP 127.0.0.1: όχι «ο ίδιος ο server»', '127.0.0.1' === $pncp_ip && ! $pncp_local, $pncp_ip );
list( $pncp_ip, $pncp_local ) = $pncp_rt( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '198.51.100.7' ), $pncp_c );
t( 'pre-cache: Bunny edge + X-Real-IP = IP του server: όχι «ο ίδιος ο server»', ! $pncp_local );
list( $pncp_ip, $pncp_local ) = $pncp_rt( '127.0.0.1', array(), $pncp_c );
t( 'pre-cache: localhost χωρίς header: «ο ίδιος ο server»', $pncp_local );
list( $pncp_ip, $pncp_local ) = $pncp_rt( '127.0.0.1', array( 'HTTP_X_REAL_IP' => '127.0.0.1' ), $pncp_c );
t( 'pre-cache: Nginx στον ίδιο server με X-Real-IP 127.0.0.1: «ο ίδιος ο server»', $pncp_local );
list( $pncp_ip, , $pncp_nov ) = $pncp_rt( '89.187.162.1', array( 'HTTP_X_REAL_IP' => 'σκουπίδι' ), $pncp_c );
t( 'pre-cache: Bunny edge με άκυρο X-Real-IP: σημειώνεται «χωρίς IP επισκέπτη»', '89.187.162.1' === $pncp_ip && $pncp_nov );
list( $pncp_ip, , $pncp_nov ) = $pncp_rt( '89.187.162.1', array(), $pncp_c );
t( 'pre-cache: Bunny edge χωρίς X-Real-IP: σημειώνεται «χωρίς IP επισκέπτη»', $pncp_nov );
list( $pncp_ip, , $pncp_nov ) = $pncp_rt( '89.187.162.1', array( 'HTTP_X_REAL_IP' => '203.0.113.9' ), $pncp_c );
t( 'pre-cache: Bunny edge με σωστό X-Real-IP: ο επισκέπτης', '203.0.113.9' === $pncp_ip && ! $pncp_nov );
$pncp_c['header'] = 'HTTP_X_FORWARDED_FOR';
list( $pncp_ip, $pncp_local ) = $pncp_rt( '127.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 89.187.162.1' ), $pncp_c );
t( 'pre-cache: Nginx → Bunny edge → X-Forwarded-For 127.0.0.1: όχι «ο ίδιος ο server»', '127.0.0.1' === $pncp_ip && ! $pncp_local, $pncp_ip );

/* ---------- 1δ. Μέσα από HTTP (πραγματικό αίτημα) ---------- */
// Ο server των δοκιμών δίνει πάντα 127.0.0.1· το X-Test-Remote-Addr του mu-plugin ορίζει το REMOTE_ADDR.
settings( array( 'ip_header' => 'x_real_ip', 'block_ips' => '127.0.0.1' ) );
wp_cache_flush();
$pncp_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36';
list( $pncp_code ) = req( '/', array( 'X-Test-Remote-Addr' => '89.187.162.1', 'X-Real-IP' => '127.0.0.1', 'User-Agent' => $pncp_ua, 'Accept-Language' => 'el' ) );
t( 'HTTP: Bunny edge + X-Real-IP 127.0.0.1 στη λίστα αποκλεισμού: 403 (πριν: 200)', 403 === $pncp_code, (string) $pncp_code );
list( $pncp_code ) = req( '/', array( 'X-Test-Remote-Addr' => '89.187.162.1', 'X-Real-IP' => '203.0.113.9', 'User-Agent' => $pncp_ua, 'Accept-Language' => 'el' ) );
t( 'HTTP: Bunny edge + κανονικός επισκέπτης: 200', 200 === $pncp_code, (string) $pncp_code );
settings( array( 'ip_header' => 'remote_addr', 'block_ips' => '' ) );

/* ---------- 2. fresh_option(): το alloptions γράφεται μόνο όταν η τιμή άλλαξε ---------- */
class PNCP_Test_Counting_Cache extends WP_Object_Cache {
	public $alloptions_sets = 0;
	public function set( $key, $data, $group = 'default', $expire = 0 ) {
		if ( 'alloptions' === $key && 'options' === $group ) {
			++$this->alloptions_sets;
		}
		return parent::set( $key, $data, $group, $expire );
	}
}
$pncp_old_cache = $GLOBALS['wp_object_cache'];
$GLOBALS['wp_object_cache'] = new PNCP_Test_Counting_Cache();
$pncp_ext = wp_using_ext_object_cache( true );
update_option( 'pncp_test_fresh', 'one', true );
wp_load_alloptions( true );
$GLOBALS['wp_object_cache']->alloptions_sets = 0;
$pncp_val = PNCP_Seal::fresh_option( 'pncp_test_fresh' );
t( 'fresh_option(): η τιμή από τη βάση', 'one' === $pncp_val, (string) $pncp_val );
t( 'fresh_option(): ίδια τιμή με το cache: το alloptions ΔΕΝ ξαναγράφεται', 0 === $GLOBALS['wp_object_cache']->alloptions_sets, (string) $GLOBALS['wp_object_cache']->alloptions_sets );
$wpdb->update( $wpdb->options, array( 'option_value' => 'two' ), array( 'option_name' => 'pncp_test_fresh' ) );
$pncp_val = PNCP_Seal::fresh_option( 'pncp_test_fresh' );
$pncp_all = wp_cache_get( 'alloptions', 'options' );
t( 'fresh_option(): η γραμμή άλλαξε στη βάση: το cache ενημερώνεται μία φορά', 'two' === $pncp_val && 1 === $GLOBALS['wp_object_cache']->alloptions_sets && 'two' === $pncp_all['pncp_test_fresh'] );
$wpdb->delete( $wpdb->options, array( 'option_name' => 'pncp_test_fresh' ) );
PNCP_Seal::fresh_option( 'pncp_test_fresh' );
$pncp_all = wp_cache_get( 'alloptions', 'options' );
t( 'fresh_option(): η γραμμή σβήστηκε: βγαίνει και από το cache', ! array_key_exists( 'pncp_test_fresh', $pncp_all ) );
wp_using_ext_object_cache( $pncp_ext );
$GLOBALS['wp_object_cache'] = $pncp_old_cache;
wp_cache_flush();

/* ---------- 3. Προϋπολογισμός DNS: ατομική αύξηση ---------- */
$pncp_dns_calls = 0;
$pncp_dns       = static function ( $host, $ip ) use ( &$pncp_dns_calls ) {
	++$pncp_dns_calls;
	return $ip; // Το όνομα = η IP: «δεν απάντησε» (inconclusive).
};
$pncp_max = static function () {
	return 3;
};
add_filter( 'pncp_reverse_dns', $pncp_dns, 20, 2 );
add_filter( 'pncp_dns_lookups_per_minute', $pncp_max );
$pncp_budget_key = 'pncp_dns_apple_' . (int) floor( time() / MINUTE_IN_SECONDS );
if ( 55 <= time() % 60 ) {
	sleep( 6 );
	$pncp_budget_key = 'pncp_dns_apple_' . (int) floor( time() / MINUTE_IN_SECONDS );
}
PNCP_Log::cache_delete( $pncp_budget_key );
for ( $pncp_i = 1; $pncp_i <= 5; $pncp_i++ ) {
	PNCP_Bots::is_verified_crawler( 'apple', '198.18.7.' . $pncp_i );
}
t( 'DNS: από 5 διαφορετικές IP μόνο 3 αναζητήσεις (το όριο)', 3 === $pncp_dns_calls, (string) $pncp_dns_calls );
// Άλλο αίτημα πήρε στο μεταξύ μία θέση: η αύξηση ξεκινά από εκεί, όχι από την τιμή που διαβάστηκε πριν.
PNCP_Log::cache_set( $pncp_budget_key, 2, 120 );
$pncp_dns_calls = 0;
$pncp_take      = static function ( $key ) {
	return ( function ( $key ) {
		return self::dns_budget_take( $key );
	} )->bindTo( null, 'PNCP_Bots' )( $key );
};
t( 'DNS: η θέση παίρνεται με αύξηση (2 → 3 → 4)', 3 === $pncp_take( $pncp_budget_key ) && 4 === $pncp_take( $pncp_budget_key ) );
PNCP_Bots::is_verified_crawler( 'apple', '198.18.7.20' );
t( 'DNS: πάνω από το όριο καμία αναζήτηση', 0 === $pncp_dns_calls, (string) $pncp_dns_calls );
remove_filter( 'pncp_dns_lookups_per_minute', $pncp_max );

/* ---------- 4. Crawler με αναπάντητο DNS: όχι 403 «no_browser» ---------- */
PNCP_Log::cache_delete( 'pncp_dns_apple_' . (int) floor( time() / MINUTE_IN_SECONDS ) );
$pncp_apple = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)';
$pncp_check = static function ( $ip, $ua ) {
	request_from( $ip );
	$_SERVER['HTTP_USER_AGENT'] = $ua;
	unset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] );
	return PNCP_Bots::check( 'page', false );
};
settings( array( 'require_browser_headers' => 1, 'block_fake_crawlers' => 1 ) );
$pncp_v = $pncp_check( '198.18.8.1', $pncp_apple );
t( 'Applebot με αναπάντητο DNS, «Browsers only» ανοιχτό: περνά (πριν: 403 no_browser)', null === $pncp_v, wp_json_encode( $pncp_v ) );
update_option( 'pncp_emergency_until', time() + HOUR_IN_SECONDS );
PNCP_Options::flush();
$pncp_v = $pncp_check( '198.18.8.2', $pncp_apple );
t( 'Applebot με αναπάντητο DNS σε Emergency Mode: όχι 403 no_browser', ! is_array( $pncp_v ) || 'no_browser' !== $pncp_v['reason'], wp_json_encode( $pncp_v ) );
update_option( 'pncp_emergency_until', 0 );
PNCP_Options::flush();
// Script χωρίς όνομα crawler: εξακολουθεί να παίρνει 403.
$pncp_v = $pncp_check( '198.18.8.3', 'python-requests/2.32' );
t( 'script χωρίς headers browser: 403 όπως πριν', is_array( $pncp_v ) && 403 === $pncp_v['code'], wp_json_encode( $pncp_v ) );
// Applebot που το DNS λέει ότι είναι ψεύτικο: 403 fake_crawler όπως πριν.
remove_filter( 'pncp_reverse_dns', $pncp_dns, 20 );
$pncp_fake = static function () {
	return 'scraper.example.net';
};
add_filter( 'pncp_reverse_dns', $pncp_fake, 20 );
$pncp_v = $pncp_check( '198.18.8.4', $pncp_apple );
t( 'Applebot με λάθος όνομα στο DNS: 403 fake_crawler όπως πριν', is_array( $pncp_v ) && 'fake_crawler' === $pncp_v['reason'], wp_json_encode( $pncp_v ) );
remove_filter( 'pncp_reverse_dns', $pncp_fake, 20 );

/* ---------- 6. Pre-cache check χωρίς APCu: όριο νέων αρχείων ανά λεπτό ---------- */
$pncp_tmp = get_temp_dir() . 'pncp-t351-' . wp_generate_password( 8, false );
wp_mkdir_p( $pncp_tmp );
$pncp_cc  = array(
	'dir'       => $pncp_tmp,
	'apcu'      => false,
	'new_files' => 3,
);
$pncp_now = time();
if ( 57 <= $pncp_now % 60 ) {
	sleep( 4 );
	$pncp_now = time();
}
for ( $pncp_i = 1; $pncp_i <= 5; $pncp_i++ ) {
	PNCP_Precheck_Runtime::hit( $pncp_cc, 'k' . $pncp_i, $pncp_now );
}
$pncp_hdir  = $pncp_tmp . '/hits/' . (int) floor( $pncp_now / 60 );
$pncp_files = array_values( array_diff( (array) scandir( $pncp_hdir ), array( '.', '..', '.new' ) ) );
t( 'pre-cache: 5 νέες διευθύνσεις με όριο 3: μόνο 3 αρχεία μετρητών', 3 === count( $pncp_files ), (string) count( $pncp_files ) );
t( 'pre-cache: πάνω από το όριο η νέα διεύθυνση μετρά ως 1η σελίδα (χωρίς αρχείο)', 1 === PNCP_Precheck_Runtime::hit( $pncp_cc, 'k9', $pncp_now ) && ! is_file( $pncp_hdir . '/' . md5( 'k9' ) ) );
t( 'pre-cache: μια διεύθυνση που ήδη μετριέται συνεχίζει κανονικά', 2 === PNCP_Precheck_Runtime::hit( $pncp_cc, 'k1', $pncp_now ) );
$pncp_cc['new_files'] = 0;
t( 'pre-cache: όριο 0 = χωρίς όριο', 1 === PNCP_Precheck_Runtime::hit( $pncp_cc, 'k10', $pncp_now ) && is_file( $pncp_hdir . '/' . md5( 'k10' ) ) );
foreach ( (array) glob( $pncp_hdir . '/{,.}*', GLOB_BRACE ) as $pncp_f ) {
	if ( is_file( $pncp_f ) ) {
		unlink( $pncp_f );
	}
}
@rmdir( $pncp_hdir );
@rmdir( $pncp_tmp . '/hits' );
@rmdir( $pncp_tmp );
t( 'pre-cache: η ρύθμιση γράφεται στο αρχείο ρυθμίσεων (φίλτρο pncp_precheck_new_files_per_minute)', ( function () {
	$f = static function () {
		return 77;
	};
	add_filter( 'pncp_precheck_new_files_per_minute', $f );
	$c = PNCP_Precheck::config();
	remove_filter( 'pncp_precheck_new_files_per_minute', $f );
	return is_array( $c ) && isset( $c['new_files'] ) && 77 === $c['new_files'];
} )() );

/* ---------- 7. Applebot / YandexBot από IP χωρίς εγγραφή PTR ---------- */
$pncp_none = static function () {
	return false; // Καμία εγγραφή PTR (απάντηση του DNS, όχι αποτυχία).
};
add_filter( 'pncp_reverse_dns', $pncp_none, 20 );
t( 'Applebot χωρίς PTR: όχι επαληθευμένος, και όχι «αναπάντητο» (ψεύτικος)', ! PNCP_Bots::is_verified_crawler( 'apple', '198.18.10.1' ) && ! ( function () {
	return self::$verify_inconclusive;
} )->bindTo( null, 'PNCP_Bots' )() );
t( 'YandexBot χωρίς PTR: ψεύτικος', ! PNCP_Bots::is_verified_crawler( 'yandex', '198.18.10.2' ) && ! ( function () {
	return self::$verify_inconclusive;
} )->bindTo( null, 'PNCP_Bots' )() );
settings( array( 'block_fake_crawlers' => 1, 'require_browser_headers' => 0 ) );
$pncp_v = $pncp_check( '198.18.10.3', $pncp_apple );
t( 'check(): Applebot χωρίς PTR → 403 fake_crawler', is_array( $pncp_v ) && 'fake_crawler' === $pncp_v['reason'], wp_json_encode( $pncp_v ) );
remove_filter( 'pncp_reverse_dns', $pncp_none, 20 );

/* ---------- Καθάρισμα ---------- */
update_option( PNCP_OPTION, $pncp_saved );
PNCP_Options::flush();
if ( null === $pncp_bunny_old ) {
	delete_option( PNCP_Ip::LISTS_OPTION . '_bunny' );
} else {
	update_option( PNCP_Ip::LISTS_OPTION . '_bunny', $pncp_bunny_old );
}
if ( null === $pncp_server_old ) {
	unset( $_SERVER['SERVER_ADDR'] );
} else {
	$_SERVER['SERVER_ADDR'] = $pncp_server_old;
}
PNCP_Log::unban_all();
PNCP_Log::clear();
request_from( '127.0.0.1' );

exit( $fails ? 1 : 0 );
