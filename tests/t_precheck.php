<?php
/**
 * ScrapeLock — έλεγχος πριν από το cache (2.6), σε πραγματικό WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_precheck.php
 *
 * Προσομοιώνει cache σελίδων όπως του WP Rocket: WP_CACHE στο wp-config.php και ένα advanced-cache.php που
 * σερβίρει τη /cached-page/ χωρίς να φορτώσει plugins. Το wp-config.php και το advanced-cache.php
 * επανέρχονται στο τέλος (και σε σφάλμα). Μόνο σε WordPress δοκιμών.
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

/** Αίτημα με curl: [code, headers, body]. */
function req( $path, $headers = array(), $method = 'GET', $cookie = '' ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => $h,
		CURLOPT_CUSTOMREQUEST  => $method,
		CURLOPT_TIMEOUT        => 30,
	);
	if ( 'HEAD' === $method ) {
		$opts[ CURLOPT_NOBODY ] = true;
	}
	if ( '' !== $cookie ) {
		$opts[ CURLOPT_COOKIE ] = $cookie;
	}
	curl_setopt_array( $ch, $opts );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
}

/** Επισκέπτης με browser: η IP στο X-Real-IP (ο server των tests είναι το 127.0.0.1, δηλαδή «Nginx μπροστά»). */
function visitor( $ip, $extra = array() ) {
	return array_merge(
		array(
			'X-Real-IP'       => $ip,
			'X-Test-IP'       => $ip,
			'User-Agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36',
			'Accept-Language' => 'el-GR,el;q=0.9',
		),
		$extra
	);
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Ip::reset();
	// Το run.php ξαναγράφεται από το CLI: το OPcache του server το ξαναδιαβάζει μετά από revalidate_freq (2 s).
	// (Από τη σελίδα ρυθμίσεων το plugin καλεί opcache_invalidate στον ίδιο server.)
	sleep( 3 );
}

/** Περιμένει το επόμενο λεπτό αν μένουν λιγότερα από 20 δευτερόλεπτα (οι μετρητές είναι ανά λεπτό). */
function same_minute() {
	$left = 60 - time() % 60;
	if ( $left < 20 ) {
		sleep( $left + 1 );
	}
}

/** Πόσα αιτήματα από τα $n πέρασαν (κωδικοί). */
function codes( $path, $headers, $n, $method = 'GET', $cookie = '' ) {
	$out = array();
	for ( $i = 0; $i < $n; $i++ ) {
		list( $code ) = req( $path, $headers, $method, $cookie );
		$out[]        = $code;
	}
	return $out;
}

$config_file = PNCP_Precheck::config_path();
$cache_file  = WP_CONTENT_DIR . '/advanced-cache.php';
$original    = (string) file_get_contents( $config_file );
$had_cache   = file_exists( $cache_file ) ? (string) file_get_contents( $cache_file ) : null;
$keep        = PNCP_Options::stored();
register_shutdown_function(
	static function () use ( $config_file, $original, $cache_file, $had_cache, $keep ) {
		file_put_contents( $config_file, $original );
		if ( null === $had_cache ) {
			@unlink( $cache_file );
		} else {
			file_put_contents( $cache_file, $had_cache );
		}
		update_option( PNCP_OPTION, $keep );
		PNCP_Precheck::sync();
	}
);
t( 'wp-config.php βρέθηκε', '' !== $config_file && 0 === strpos( $original, "<?php\n" ) );

// «WP Rocket»: WP_CACHE και advanced-cache.php που σερβίρει τη /cached-page/ πριν από τα plugins.
file_put_contents( $config_file, "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) );
file_put_contents( $cache_file, "<?php\nif ( isset( \$_SERVER['REQUEST_URI'] ) && 0 === strpos( \$_SERVER['REQUEST_URI'], '/cached-page/' ) ) {\n\theader( 'X-Test-Cache: HIT' );\n\techo 'CACHED PAGE';\n\texit;\n}\n" );
// OPcache ξαναδιαβάζει τα αλλαγμένα αρχεία μετά από opcache.revalidate_freq δευτερόλεπτα (προεπιλογή 2).
sleep( 3 );

global $wpdb;
PNCP_Log::unban_all();
PNCP_Log::clear();
settings(
	array(
		'enabled'                 => 1,
		'precheck'                => 0,
		'rate_limit'              => 5,
		'ban_strikes'             => 0,
		'ban_minutes'             => 5,
		'ip_header'               => 'x_real_ip',
		'block_bots'              => 1,
		'require_browser_headers' => 0,
		'human_check'             => 0,
		'allow_ips'               => '',
		'block_ips'               => '',
	)
);

/* ---------- Χωρίς τον έλεγχο: η σελίδα από το cache δεν έχει όριο ---------- */
same_minute();
$c = codes( '/cached-page/', visitor( '203.0.113.10' ), 8 );
t( 'χωρίς τον έλεγχο: 8 σελίδες από το cache, όλες 200 (το κενό που κλείνει)', array_fill( 0, 8, 200 ) === $c, implode( ',', $c ) );
t( 'χωρίς τον έλεγχο: καμία γραμμή στο wp-config.php', ! PNCP_Precheck::in_config() );

/* ---------- Ενεργοποίηση ---------- */
settings( array( 'precheck' => 1 ) );
sleep( 3 ); // OPcache: το νέο wp-config.php.
t( 'ενεργοποίηση: κατάσταση ok', 'ok' === get_option( PNCP_Precheck::STATUS ), (string) get_option( PNCP_Precheck::STATUS ) );
t( 'ενεργοποίηση: η γραμμή μπαίνει αμέσως μετά το <?php', 0 === strpos( (string) file_get_contents( $config_file ), "<?php\n" . PNCP_Precheck::block() . "define( 'WP_CACHE'" ) );
t( 'ενεργοποίηση: τρέχει (loader + wp-config)', PNCP_Precheck::active() );
t( 'ενεργοποίηση: το υπόλοιπο wp-config.php δεν άλλαξε', PNCP_Precheck::without_block( (string) file_get_contents( $config_file ) ) === "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) );
settings( array( 'precheck' => 1 ) );
t( 'δεύτερη αποθήκευση: η γραμμή μία φορά', 1 === substr_count( (string) file_get_contents( $config_file ), 'BEGIN ScrapeLock pre-cache check' ) );
t( 'φάκελος δεδομένων προστατευμένος (index.php, .htaccess)', file_exists( PNCP_Precheck::dir() . '/index.php' ) && file_exists( PNCP_Precheck::dir() . '/.htaccess' ) );

/* ---------- Όριο σε σελίδες από το cache ---------- */
same_minute();
list( $code, $h, $body ) = req( '/cached-page/', visitor( '203.0.113.11' ) );
t( 'cache: η σελίδα σερβίρεται ακόμη από το cache', 200 === $code && 'CACHED PAGE' === $body, "$code $body" );
$c = codes( '/cached-page/', visitor( '203.0.113.11' ), 5 );
t( 'cache: πάνω από 5/λεπτό → 429', array( 200, 200, 200, 200, 429 ) === $c, implode( ',', $c ) );
list( $code, $h, $body ) = req( '/cached-page/', visitor( '203.0.113.11' ) );
t( 'cache: 429 χωρίς WordPress, με Retry-After και no-store', 429 === $code && 'Too many requests.' === $body && false !== strpos( $h, 'retry-after: 60' ) && false !== strpos( $h, 'no-store' ), "$code $body" );
list( $code ) = req( '/cached-page/', visitor( '203.0.113.12' ) );
t( 'cache: άλλη IP δεν επηρεάζεται', 200 === $code );
list( $code, $h ) = req( '/cached-page/', visitor( '203.0.113.11' ), 'HEAD' );
t( 'cache: HEAD μετράει και αυτό, χωρίς σώμα', 429 === $code );

/* ---------- Τι δεν μετράει ---------- */
same_minute();
$c = codes( '/cached-page/', visitor( '203.0.113.20' ), 8, 'GET', 'wordpress_logged_in_abc=x' );
t( 'συνδεδεμένοι (cookie wordpress_logged_in_): δεν μετρούν εδώ', ! in_array( 429, $c, true ), implode( ',', $c ) );
$c = codes( '/cached-page/', visitor( '203.0.113.21', array( 'Sec-Purpose' => 'prefetch' ) ), 8 );
t( 'prefetch: δεν μετράει', ! in_array( 429, $c, true ), implode( ',', $c ) );
$c = codes( '/wp-json/', visitor( '203.0.113.22' ), 7 );
t( 'REST (/wp-json/): αφήνεται στον κανονικό έλεγχο (δικό του όριο)', ! in_array( 429, $c, true ), implode( ',', $c ) );
$c = codes( '/wp-login.php', visitor( '203.0.113.23' ), 7 );
t( 'wp-login.php: δεν μετράει', ! in_array( 429, $c, true ), implode( ',', $c ) );
$c = codes( '/cached-page/', visitor( '203.0.113.24' ), 7, 'POST' );
t( 'POST: δεν μετράει', ! in_array( 429, $c, true ), implode( ',', $c ) );
$c = codes( '/cached-page/', array( 'User-Agent' => 'curl/8' ), 8 );
t( 'ο ίδιος ο server (127.0.0.1, χωρίς X-Real-IP): δεν μετράει', ! in_array( 429, $c, true ), implode( ',', $c ) );

/* ---------- Μηχανές αναζήτησης ---------- */
PNCP_Ip::store_list( 'google', array( '66.249.64.0/19' ) );
PNCP_Precheck::refresh();
sleep( 3 );
same_minute();
$c = codes( '/cached-page/', visitor( '66.249.66.1', array( 'User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' ) ), 8 );
t( 'Googlebot από IP της επίσημης λίστας: δεν μετράει', ! in_array( 429, $c, true ), implode( ',', $c ) );
$c = codes( '/cached-page/', visitor( '198.51.100.30', array( 'User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' ) ), 6 );
t( 'ψεύτικο Googlebot (άλλη IP): μετράει όπως όλοι', in_array( 429, $c, true ), implode( ',', $c ) );
$c = codes( '/cached-page/', visitor( '198.51.100.31', array( 'User-Agent' => 'Mozilla/5.0 (Macintosh) Applebot/0.1' ) ), 8 );
t( 'Applebot (χωρίς επίσημη λίστα): αφήνεται στον κανονικό έλεγχο (DNS)', ! in_array( 429, $c, true ), implode( ',', $c ) );
t( 'WP Rocket: το Applebot δεν παίρνει σελίδες από το cache όσο ο έλεγχος είναι ενεργός', in_array( 'applebot', (array) apply_filters( 'rocket_cache_reject_ua', array() ), true ) );
delete_option( PNCP_Ip::LISTS_OPTION . '_google' );

/* ---------- Λίστες IP του διαχειριστή ---------- */
settings( array( 'allow_ips' => '198.51.100.40', 'block_ips' => "198.51.100.41\n198.51.100.128/25" ) );
same_minute();
$c = codes( '/cached-page/', visitor( '198.51.100.40' ), 8 );
t( 'πάντα επιτρεπτή IP: χωρίς όριο', ! in_array( 429, $c, true ), implode( ',', $c ) );
list( $code, , $body ) = req( '/cached-page/', visitor( '198.51.100.41' ) );
t( 'πάντα αποκλεισμένη IP: 403 πριν από το cache', 403 === $code && 'Access denied.' === $body, "$code $body" );
list( $code ) = req( '/cached-page/', visitor( '198.51.100.200' ) );
t( 'πάντα αποκλεισμένο CIDR: 403', 403 === $code );
settings( array( 'allow_ips' => '', 'block_ips' => '' ) );

/* ---------- Αποκλεισμοί: από τον κανονικό έλεγχο και από τον ίδιο ---------- */
PNCP_Log::ban( '198.51.100.50', 5, 'trap' );
list( $code, , $body ) = req( '/cached-page/', visitor( '198.51.100.50' ) );
t( 'αποκλεισμός του κανονικού ελέγχου: ισχύει και στο cache', 403 === $code && 'Access denied.' === $body, "$code $body" );
PNCP_Log::unban( '198.51.100.50' );
list( $code ) = req( '/cached-page/', visitor( '198.51.100.50' ) );
t( 'άρση αποκλεισμού: ξανά 200', 200 === $code );

settings( array( 'ban_strikes' => 1, 'ban_minutes' => 5 ) );
PNCP_Log::clear();
same_minute();
$c = codes( '/cached-page/', visitor( '198.51.100.60' ), 7 );
t( 'όριο + 1 παράβαση = αποκλεισμός: 429 και μετά 403', array( 200, 200, 200, 200, 200, 429, 403 ) === $c, implode( ',', $c ) );
t( 'αρχείο συμβάντων προστατευμένο («<?php exit;»)', 0 === strpos( (string) file_get_contents( PNCP_Precheck::dir() . '/events.php' ), '<?php exit; ?>' ) );
list( $code, , $body ) = req( '/wp-content/scrapelock-precheck/events.php', visitor( '198.51.100.61' ) );
t( 'αρχείο συμβάντων από το web: τίποτα δεν φαίνεται', '' === trim( $body ) || 403 === $code || 404 === $code, "$code " . substr( $body, 0, 60 ) );
$imported = PNCP_Precheck::import_events();
t( 'εισαγωγή συμβάντων στο αρχείο καταγραφής', $imported >= 3, (string) $imported );
$rows = $wpdb->get_results( $wpdb->prepare( "SELECT reason, code, hits, path FROM {$wpdb->prefix}pncp_log WHERE ip = %s ORDER BY id", '198.51.100.60' ), ARRAY_A );
$by   = array();
foreach ( $rows as $row ) {
	$by[ $row['reason'] ] = $row;
}
t( 'καταγραφή: όριο, αποκλεισμός, αποκλεισμένη IP, με τη διαδρομή', isset( $by['rate_page'], $by['ban'], $by['banned'] ) && '/cached-page/' === $by['rate_page']['path'], wp_json_encode( $rows ) );
PNCP_Log::reset_cache();
t( 'ο αποκλεισμός του ελέγχου φαίνεται στα «Αποκλεισμένα» (βάση)', PNCP_Log::is_banned( '198.51.100.60' ) && isset( PNCP_Log::active_bans()['198.51.100.60'] ) );
t( 'δεύτερη εισαγωγή: τίποτα διπλό', 0 === PNCP_Precheck::import_events() );
PNCP_Log::unban( '198.51.100.60' );
list( $code ) = req( '/cached-page/', visitor( '198.51.100.60' ) );
t( 'άρση από τη σελίδα: ισχύει και πριν από το cache (μένει μόνο το όριο του λεπτού)', 403 !== $code && ! file_exists( PNCP_Precheck::dir() . '/bans/' . md5( '198.51.100.60' ) ), (string) $code );
settings( array( 'ban_strikes' => 0 ) );

/* ---------- Ασφάλεια ---------- */
list( $code, , $body ) = req( '/wp-content/scrapelock-precheck/run.php', visitor( '198.51.100.70' ) );
t( 'run.php από το web: δεν τρέχει τίποτα, δεν βγάζει τίποτα', '' === trim( $body ), "$code " . substr( $body, 0, 80 ) );
list( $code, , $body ) = req( '/wp-content/plugins/scrapelock/includes/precheck-runtime.php', visitor( '198.51.100.71' ) );
t( 'precheck-runtime.php από το web: μόνο ορισμοί συναρτήσεων', '' === trim( $body ), "$code " . substr( $body, 0, 80 ) );
same_minute();
$c = codes( '/cached-page/', visitor( '198.51.100.72', array( 'X-Forwarded-For' => '10.9.9.9' ) ), 6 );
t( 'ψεύτικο X-Forwarded-For δεν αλλάζει την IP (μετράει η X-Real-IP)', in_array( 429, $c, true ), implode( ',', $c ) );
settings( array( 'ip_header' => 'remote_addr' ) );
$c = codes( '/cached-page/', visitor( '198.51.100.73' ), 8 );
t( 'REMOTE_ADDR: η X-Real-IP αγνοείται, όλα από 127.0.0.1 (ο server) = χωρίς όριο', ! in_array( 429, $c, true ), implode( ',', $c ) );
settings( array( 'ip_header' => 'x_real_ip' ) );

/* ---------- Σπασμένα αρχεία δεν ρίχνουν το site ---------- */
file_put_contents( PNCP_Precheck::dir() . '/hits/x', 'not a folder' );
@chmod( PNCP_Precheck::dir() . '/hits', 0555 );
list( $code ) = req( '/cached-page/', visitor( '198.51.100.80' ) );
@chmod( PNCP_Precheck::dir() . '/hits', 0755 );
t( 'φάκελος μετρητών που δεν γράφεται: το αίτημα περνά', 200 === $code, (string) $code );

/* ---------- wp-config.php που δεν γράφεται ---------- */
settings( array( 'precheck' => 0 ) );
chmod( $config_file, 0444 );
clearstatcache();
if ( ! is_writable( $config_file ) ) {
	settings( array( 'precheck' => 1 ) );
	t( 'wp-config.php μόνο για ανάγνωση: κατάσταση not_writable, το αρχείο δεν άλλαξε', 'not_writable' === get_option( PNCP_Precheck::STATUS ) && ! PNCP_Precheck::in_config(), (string) get_option( PNCP_Precheck::STATUS ) );
} else {
	echo "SKIP wp-config.php μόνο για ανάγνωση (ως root γράφεται πάντα)\n";
}
chmod( $config_file, 0644 );
clearstatcache();

/* ---------- Απενεργοποίηση ---------- */
settings( array( 'precheck' => 1 ) );
settings( array( 'precheck' => 0 ) );
t( 'απενεργοποίηση: η γραμμή φεύγει, το wp-config.php όπως ήταν', "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) === (string) file_get_contents( $config_file ) );
t( 'απενεργοποίηση: ο φάκελος δεδομένων σβήνεται', ! file_exists( PNCP_Precheck::dir() ) );
same_minute();
$c = codes( '/cached-page/', visitor( '203.0.113.90' ), 7 );
t( 'απενεργοποίηση: ξανά χωρίς όριο στο cache', ! in_array( 429, $c, true ), implode( ',', $c ) );
settings( array( 'precheck' => 1 ) );
settings( array( 'enabled' => 0 ) );
t( 'προστασία κλειστή: ο έλεγχος αφαιρείται', ! PNCP_Precheck::in_config() );
settings( array( 'enabled' => 1, 'precheck' => 1 ) );
pncp_deactivate();
t( 'απενεργοποίηση plugin: γραμμή και αρχεία φεύγουν', ! PNCP_Precheck::in_config() && ! file_exists( PNCP_Precheck::dir() ) );
$level = error_reporting( E_ALL & ~E_DEPRECATED ); // Το db.php του SQLite βγάζει Deprecated στο CREATE TABLE.
pncp_upgrade();
error_reporting( $level );
t( 'ενεργοποίηση plugin (upgrade): ο έλεγχος επανέρχεται με τη ρύθμιση', PNCP_Precheck::active() );

/* ---------- Ελέγχει τον κώδικα του loader ---------- */
$loader = (string) file_get_contents( PNCP_Precheck::loader() );
$tmp    = tempnam( sys_get_temp_dir(), 'pncp' );
file_put_contents( $tmp, $loader );
exec( escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( $tmp ) . ' 2>&1', $lint, $rc );
unlink( $tmp );
t( 'ο loader είναι έγκυρη PHP', 0 === $rc, implode( ' ', $lint ) );

echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
