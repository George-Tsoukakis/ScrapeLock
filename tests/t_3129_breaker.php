<?php
/**
 * ScrapeLock 3.12.9 — circuit breaker (PNCP_Breaker): μια αργή λειτουργία μέτρησης/αποθήκευσης (> 200 ms) σταματά
 * τη μέτρηση για 10 λεπτά (τα αιτήματα περνούν, οι αποκλεισμοί ισχύουν), επανέρχεται μετά (ρολόι που ορίζει η
 * δοκιμή), Site Health / ειδοποίηση / `wp scrapelock status` και `breaker reset`, κόστος < 5 µs ανά έλεγχο, χαλασμένο
 * ή κλειδωμένο αρχείο κατάστασης χωρίς σφάλμα και χωρίς αναμονή, APCu (stub), δικός του store (όπως μια σύνδεση
 * Redis), πραγματικός Redis όταν υπάρχει, και ο έλεγχος πριν από το cache μέσα από HTTP (wp-config.php +
 * advanced-cache.php όπως στο t_precheck.php, επανέρχονται στο τέλος). Μόνο σε WordPress δοκιμών.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 WP_CLI="wp --path=…" php t_3129_breaker.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
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

/** Αίτημα με curl: [code, headers, body, seconds]. */
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
			CURLOPT_HEADER         => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_TIMEOUT        => 30,
		)
	);
	$start = microtime( true );
	$out   = (string) curl_exec( $ch );
	$took  = microtime( true ) - $start;
	$code  = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs    = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ), $took );
}

function visitor( $ip ) {
	return array(
		'X-Real-IP'       => $ip,
		'X-Test-IP'       => $ip,
		'User-Agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36',
		'Accept-Language' => 'en-US,en;q=0.9',
	);
}

function codes( $path, $headers, $n ) {
	$out = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$out[] = req( $path, $headers )[0];
	}
	return $out;
}

function same_minute() {
	$left = 60 - time() % 60;
	if ( $left < 20 ) {
		sleep( $left + 1 );
	}
}

/** Runs «wp scrapelock …»: [exit code, output]. */
function cli( $args ) {
	global $wp_cli;
	exec( $wp_cli . ' scrapelock ' . $args . ' 2>&1', $out, $rc );
	return array( $rc, implode( "\n", $out ) );
}

/** Deletes a folder. */
function rrmdir( $dir ) {
	foreach ( (array) glob( $dir . '/{,.}[!.]*', GLOB_BRACE ) as $f ) {
		is_dir( $f ) ? rrmdir( $f ) : unlink( $f );
	}
	@rmdir( $dir );
}

// Every PHP warning / notice of the breaker counts as a failure.
$pncp_warnings = array();
set_error_handler(
	static function ( $no, $str, $file ) use ( &$pncp_warnings ) {
		if ( ( error_reporting() & $no ) && ( false !== strpos( (string) $file, 'class-pncp-breaker' ) || false !== strpos( (string) $file, 'class-pncp-precheck-runtime' ) ) ) {
			$pncp_warnings[] = $str;
		}
		return false;
	}
);

/* ---------- Μονάδα: ρολόι, αργή λειτουργία, παράθυρο, επαναφορά ---------- */
$tmp = sys_get_temp_dir() . '/pncp-brk-' . getmypid();
@mkdir( $tmp, 0755, true );
$now                          = 1800000000;
PNCP_Breaker::$clock          = static function () use ( &$now ) {
	return $now;
};
PNCP_Breaker::$redis_config   = ''; // Without Redis for the unit part (the Redis part is below).
PNCP_Breaker::forget();
PNCP_Breaker::setup( $tmp );
t( 'store χωρίς APCu / Redis: αρχεία', 'files' === PNCP_Breaker::kind(), PNCP_Breaker::kind() );
t( 'κλειστό από την αρχή, χωρίς αρχείο', ! PNCP_Breaker::open( 'unit_slow' ) && ! is_dir( $tmp . '/breaker' ) );
t( 'προεπιλογές: 200 ms, 10 λεπτά (DNS 1000 ms)', 200.0 === PNCP_Breaker::threshold( 'unit_slow' ) && 10 === PNCP_Breaker::minutes( 'unit_slow' ) && 1000.0 === PNCP_Breaker::threshold( 'dns' ) );

$ran    = 0;
$result = PNCP_Breaker::guard(
	'unit_slow',
	static function () use ( &$ran ) {
		++$ran;
		usleep( 250000 ); // 250 ms: a stalled disk.
		return 'value';
	},
	'fallback',
	'unit op'
);
t( 'αργή λειτουργία (250 ms): η τιμή της επιστρέφει', 'value' === $result && 1 === $ran );
t( 'αργή λειτουργία: ανοίγει (σταματά)', PNCP_Breaker::open( 'unit_slow' ) );
$hist = PNCP_Breaker::history();
t( 'ιστορικό: μία εγγραφή, όνομα, ώρα, διάρκεια ≥ 250 ms, όριο, περιγραφή', 1 === count( $hist ) && 'unit_slow' === $hist[0]['name'] && $now === (int) $hist[0]['at'] && $hist[0]['ms'] >= 250 && 200.0 === (float) $hist[0]['limit'] && 'unit op' === $hist[0]['what'], wp_json_encode( $hist ) );
t( 'κατάσταση σε αρχείο που γράφτηκε ατομικά (χωρίς .tmp)', is_file( $tmp . '/breaker/unit_slow.json' ) && ! glob( $tmp . '/breaker/*.tmp' ) );
$start  = hrtime( true );
$result = PNCP_Breaker::guard(
	'unit_slow',
	static function () use ( &$ran ) {
		++$ran;
		usleep( 250000 );
		return 'value';
	},
	'fallback'
);
t( 'μέσα στο παράθυρο: η λειτουργία παραλείπεται (fallback, < 5 ms)', 'fallback' === $result && 1 === $ran && hrtime( true ) - $start < 5e6 );
$now += 9 * 60;
PNCP_Breaker::forget();
PNCP_Breaker::setup( $tmp );
t( 'νέο αίτημα, 9 λεπτά μετά: ακόμη ανοιχτό', PNCP_Breaker::open( 'unit_slow' ) );
$now += 61;
PNCP_Breaker::forget();
PNCP_Breaker::setup( $tmp );
t( 'μετά από 10 λεπτά: κλειστό ξανά', ! PNCP_Breaker::open( 'unit_slow' ) );
$result = PNCP_Breaker::guard(
	'unit_slow',
	static function () use ( &$ran ) {
		++$ran;
		return 'quick';
	},
	'fallback'
);
t( 'μετά: η λειτουργία τρέχει πάλι, γρήγορη δεν ανοίγει', 'quick' === $result && 2 === $ran && ! PNCP_Breaker::open( 'unit_slow' ) );
$rep = PNCP_Breaker::report( 24 );
t( 'report: 1 φορά στο 24ωρο, κλειστό', isset( $rep['unit_slow'] ) && 1 === $rep['unit_slow']['count'] && false === $rep['unit_slow']['open'], wp_json_encode( $rep ) );

// Errors pass through, the time still counts.
$threw = false;
try {
	PNCP_Breaker::guard(
		'unit_throw',
		static function () {
			usleep( 220000 );
			throw new RuntimeException( 'x' );
		}
	);
} catch ( RuntimeException $e ) {
	$threw = true;
}
t( 'εξαίρεση: περνά στον καλούντα και ανοίγει (μετρήθηκε)', $threw && PNCP_Breaker::open( 'unit_throw' ) );

// Thresholds and minutes via filters.
add_filter(
	'pncp_breaker_ms',
	static function ( $ms, $name ) {
		return 'unit_strict' === $name ? 30 : $ms;
	},
	10,
	2
);
add_filter(
	'pncp_breaker_minutes',
	static function ( $m, $name ) {
		return 'unit_strict' === $name ? 2 : $m;
	},
	10,
	2
);
PNCP_Breaker::guard(
	'unit_strict',
	static function () {
		usleep( 50000 );
	}
);
$st = PNCP_Breaker::states();
t( 'φίλτρα pncp_breaker_ms / pncp_breaker_minutes: 50 ms > 30 ms ανοίγει για 2 λεπτά', isset( $st['unit_strict'] ) && $now + 120 === (int) $st['unit_strict']['until'] && 30.0 === (float) $st['unit_strict']['limit'] );
PNCP_Breaker::guard(
	'unit_fast',
	static function () {
		usleep( 20000 );
	}
);
t( 'κάτω από το όριο (20 ms): κλειστό, χωρίς εγγραφή', ! PNCP_Breaker::open( 'unit_fast' ) && ! isset( PNCP_Breaker::states()['unit_fast'] ) );

// Several requests trip at once: one entry.
$before = count( PNCP_Breaker::history() );
PNCP_Breaker::forget();
PNCP_Breaker::setup( $tmp );
PNCP_Breaker::trip( 'unit_strict', 999 );
t( 'δεύτερο trip όσο είναι ανοιχτό (άλλο αίτημα): καμία νέα εγγραφή', count( PNCP_Breaker::history() ) === $before );
for ( $i = 0; $i < 30; $i++ ) {
	$now += 700;
	PNCP_Breaker::trip( 'unit_many', 300 );
}
t( 'ιστορικό: το πολύ 20 εγγραφές, νεότερη πρώτη', 20 === count( PNCP_Breaker::history() ) && $now === (int) PNCP_Breaker::history()[0]['at'] );

/* ---------- Κόστος όσο είναι κλειστό ---------- */
PNCP_Breaker::forget();
PNCP_Breaker::setup( $tmp );
$start = hrtime( true );
for ( $i = 0; $i < 10000; $i++ ) {
	PNCP_Breaker::open( 'unit_fast' );
}
$memo_ms = ( hrtime( true ) - $start ) / 1e6;
$start   = hrtime( true );
for ( $i = 0; $i < 10000; $i++ ) {
	PNCP_Breaker::open( 'cold_' . $i ); // A first read every time: one stat() of a missing file.
}
$cold_ms = ( hrtime( true ) - $start ) / 1e6;
t( 'κόστος: 10.000 έλεγχοι στο ίδιο αίτημα < 50 ms', $memo_ms < 50, round( $memo_ms, 2 ) . ' ms' );
t( 'κόστος: 10.000 πρώτοι έλεγχοι (stat χωρίς αρχείο) < 50 ms', $cold_ms < 50, round( $cold_ms, 2 ) . ' ms' );
$start = hrtime( true );
for ( $i = 0; $i < 10000; $i++ ) {
	PNCP_Breaker::guard(
		'unit_fast',
		static function () {
			return 1;
		}
	);
}
$guard_ms = ( hrtime( true ) - $start ) / 1e6;
t( 'κόστος: 10.000 guard() γύρω από μια άμεση λειτουργία < 50 ms', $guard_ms < 50, round( $guard_ms, 2 ) . ' ms' );

/* ---------- Χαλασμένο / κλειδωμένο αρχείο κατάστασης ---------- */
file_put_contents( $tmp . '/breaker/unit_bad.json', "{\"until\":\x00\xff garbage" );
file_put_contents( $tmp . '/breaker/_names.json', 'not json' );
PNCP_Breaker::forget();
PNCP_Breaker::setup( $tmp );
$pncp_warnings = array();
t( 'χαλασμένη κατάσταση: κλειστό (η μέτρηση συνεχίζει), χωρίς σφάλμα', ! PNCP_Breaker::open( 'unit_bad' ) && array() === PNCP_Breaker::states() && ! $pncp_warnings, implode( '; ', $pncp_warnings ) );
PNCP_Breaker::trip( 'unit_bad', 300 );
t( 'χαλασμένη κατάσταση: ένα νέο trip τη γράφει από την αρχή', PNCP_Breaker::open( 'unit_bad' ) && isset( PNCP_Breaker::states()['unit_bad'] ) );
file_put_contents( $tmp . '/breaker/precheck_files.json', wp_json_encode( array( 'until' => $now + 600 ) ) );
touch( $tmp . '/breaker/precheck_files.json', $now + 600 ); // 3.12.9: its time is the end (PNCP_Breaker::open()).
// Another process holds an exclusive lock on the state files for 3 seconds.
$locker = proc_open(
	array( PHP_BINARY, '-r', '$a = fopen( $argv[1], "c+" ); $b = fopen( $argv[2], "c+" ); flock( $a, LOCK_EX ); flock( $b, LOCK_EX ); echo "locked\n"; sleep( 3 );', $tmp . '/breaker/precheck_files.json', $tmp . '/breaker/_history.json' ),
	array( 1 => array( 'pipe', 'w' ) ),
	$pipes
);
fgets( $pipes[1] );
PNCP_Breaker::forget();
PNCP_Breaker::setup( $tmp );
$start  = hrtime( true );
$is     = PNCP_Breaker::open( 'precheck_files' );
$now   += 601;
PNCP_Breaker::forget();
PNCP_Breaker::setup( $tmp );
PNCP_Breaker::trip( 'precheck_files', 300 );
$locked = ( hrtime( true ) - $start ) / 1e6;
t( 'κλειδωμένο αρχείο από άλλη διεργασία: ανάγνωση και trip χωρίς αναμονή (< 500 ms, η κλειδαριά κρατά 3 s)', $is && $locked < 500 && PNCP_Breaker::open( 'precheck_files' ), round( $locked, 2 ) . ' ms' );
proc_close( $locker );

/* ---------- Ο έλεγχος πριν από το cache (χωρίς HTTP): οι μετρητές σταματούν ---------- */
PNCP_Breaker::reset( '', true );
PNCP_Breaker::forget();
$pc = array(
	'dir'         => $tmp,
	'apcu'        => false,
	'ban_strikes' => 1,
	'breaker'     => array(
		'ms'      => 200,
		'minutes' => 10,
	),
);
t( 'runtime::breaker(): «precheck_files» όσο είναι κλειστό, μετρά', 'precheck_files' === PNCP_Precheck_Runtime::breaker( $pc ) && ! PNCP_Precheck_Runtime::$count_off );
t( 'runtime: hit() μετρά κανονικά', 1 === PNCP_Precheck_Runtime::hit( $pc, 'k', $now ) && 2 === PNCP_Precheck_Runtime::hit( $pc, 'k', $now ) );
PNCP_Breaker::observe( 'precheck_files', 250e6, 'pre-cache check' );
PNCP_Breaker::forget();
$name = PNCP_Precheck_Runtime::breaker( $pc );
t( 'runtime: έλεγχος 250 ms → επόμενα αιτήματα χωρίς μέτρηση ($count_off, τίποτα να χρονομετρηθεί)', '' === $name && PNCP_Precheck_Runtime::$count_off );
$files = count( (array) glob( $tmp . '/hits/*/*' ) );
t( 'runtime: hit() = 1 χωρίς αρχείο, strike() false, new_file_ok() false', 1 === PNCP_Precheck_Runtime::hit( $pc, 'k', $now ) && 1 === PNCP_Precheck_Runtime::hit( $pc, 'other', $now ) && ! PNCP_Precheck_Runtime::strike( $pc, 'k', $now ) && ! PNCP_Precheck_Runtime::new_file_ok( $pc, $now ) && count( (array) glob( $tmp . '/hits/*/*' ) ) === $files );
PNCP_Precheck_Runtime::ban( $tmp, '198.51.100.9', $now + 600 );
t( 'runtime: οι αποκλεισμοί που γράφτηκαν ισχύουν', PNCP_Precheck_Runtime::banned( $tmp, '198.51.100.9', time() ) );
$now += 601;
PNCP_Breaker::forget();
t( 'runtime: μετά από 10 λεπτά μετρά ξανά', 'precheck_files' === PNCP_Precheck_Runtime::breaker( $pc ) && 3 === PNCP_Precheck_Runtime::hit( $pc, 'k', $now - 601 ) );
PNCP_Precheck_Runtime::$count_off = false;

/* ---------- Site Health, πληροφορίες, ειδοποίηση ---------- */
PNCP_Breaker::reset( '', true );
$health = PNCP_Breaker_Status::health_test();
t( 'Site Health: good όσο τίποτα δεν άνοιξε', 'good' === $health['status'] && 'scrapelock_breaker' === $health['test'] );
PNCP_Breaker::trip( 'precheck_files', 1234.5, 'pre-cache check' );
$health = PNCP_Breaker_Status::health_test();
$desc   = wp_strip_all_tags( $health['description'] );
t( 'Site Health: critical όσο είναι ανοιχτό', 'critical' === $health['status'] && 'red' === $health['badge']['color'], $health['status'] );
t( 'Site Health: τι (Pre-cache check counters (files)), πόσο (1,234.5 ms), όριο, μέχρι πότε, πόσες φορές στο 24ωρο', false !== strpos( $desc, 'Pre-cache check counters (files)' ) && false !== strpos( $desc, '1,234.5 ms' ) && false !== strpos( $desc, 'limit 200 ms' ) && false !== strpos( $desc, 'Suspended until' ) && false !== strpos( $desc, 'Tripped 1 time in the last 24 hours' ), $desc );
t( 'Site Health: συμβουλή (APCu, iowait, pm.max_children)', false !== strpos( $desc, 'APCu' ) && false !== strpos( $desc, 'iowait' ) && false !== strpos( $desc, 'pm.max_children' ) );
$first = trim( wp_strip_all_tags( (string) preg_replace( '#</p>.*#s', '', $health['description'] ) ) );
t( 'Site Health: η πρώτη γραμμή ≤ 20 λέξεις', str_word_count( $first ) <= 20, $first );
wp_set_current_user( 1 );
$health = PNCP_Breaker_Status::health_test();
t( 'Site Health: «Resume counting now» με nonce για διαχειριστή', false !== strpos( $health['actions'], 'pncp_breaker_reset' ) && false !== strpos( $health['actions'], '_wpnonce' ) );
$info = PNCP_Health::info( array() );
t( 'Site Health info: γραμμή «Circuit breaker» με το ανοιχτό', isset( $info['scrapelock']['fields']['breaker'] ) && false !== strpos( $info['scrapelock']['fields']['breaker']['value'], 'precheck_files suspended until' ), wp_json_encode( $info['scrapelock']['fields']['breaker'] ?? null ) );
$tests = PNCP_Health::tests( array() );
t( 'Site Health: το test είναι καταχωρημένο', isset( $tests['direct']['scrapelock_breaker'] ) );
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
require_once ABSPATH . 'wp-admin/includes/screen.php';
WP_Screen::get( 'dashboard' )->set_current_screen();
ob_start();
PNCP_Breaker_Status::notice();
$notice = (string) ob_get_clean();
$line   = trim( wp_strip_all_tags( (string) preg_replace( '#<details.*#s', '', $notice ) ) );
t( 'ειδοποίηση: στον Πίνακα ελέγχου, μία γραμμή ≤ 20 λέξεις, λεπτομέρειες στο «More»', false !== strpos( $notice, 'pncp-breaker' ) && str_word_count( $line ) <= 20 && false !== strpos( $notice, 'class="pncp-more"' ) && false !== strpos( $notice, '1,234.5 ms' ), $line );
$now += 601;
PNCP_Breaker::forget();
$health = PNCP_Breaker_Status::health_test();
t( 'Site Health: μετά το παράθυρο recommended («Working again»)', 'recommended' === $health['status'] && false !== strpos( $health['description'], 'Working again' ) );
ob_start();
PNCP_Breaker_Status::notice();
t( 'ειδοποίηση: όχι όταν δεν είναι πια ανοιχτό', '' === ob_get_clean() );
$now += 86400;
PNCP_Breaker::forget();
t( 'Site Health: μετά από 24 ώρες good ξανά', 'good' === PNCP_Breaker_Status::health_test()['status'] );
PNCP_Breaker::tidy();
t( 'tidy(): η κατάσταση που έληξε πριν από > 1 ημέρα σβήνει (ο έλεγχος ξανά ένα stat χωρίς αρχείο)', ! is_file( $tmp . '/breaker/precheck_files.json' ) );

/* ---------- DNS κάτω από τον breaker ---------- */
PNCP_Breaker::trip( 'dns', 1500 );
remove_all_filters( 'pncp_forward_dns' ); // The test harness answers forward lookups itself.
$m       = new ReflectionMethod( 'PNCP_Bots', 'reverse_dns' );
$m->setAccessible( true );
$start   = hrtime( true );
$rdns    = $m->invoke( null, '192.0.2.1' );
$fm      = new ReflectionMethod( 'PNCP_Bots', 'forward_ips' );
$fm->setAccessible( true );
$forward = $fm->invoke( null, 'unknown.invalid' );
t( 'DNS ανοιχτό: reverse_dns() = \'\' (χωρίς απόφαση), forward_ips() = null, χωρίς αναζήτηση', '' === $rdns && null === $forward && hrtime( true ) - $start < 5e6 );
PNCP_Breaker::reset( 'dns' );

/* ---------- 3.12.9: η μέτρηση σελίδων όλου του site (automatic Emergency Mode) κάτω από τον breaker ---------- */
$one = static function () {
	return 1;
};
add_filter( 'pncp_surge_sample', $one ); // Every page counted (without an object cache: 1 in 10 otherwise).
$sm = new ReflectionMethod( 'PNCP_Bots', 'surge' );
$sm->setAccessible( true );
$pk = new ReflectionMethod( 'PNCP_Bots', 'peek' );
$pk->setAccessible( true );
$sv = new ReflectionMethod( 'PNCP_Surge', 'save' );
$sv->setAccessible( true );
$sminute = (int) floor( time() / MINUTE_IN_SECONDS );
$before  = (int) $pk->invoke( null, 'surge', 'site', $sminute );
PNCP_Breaker::trip( 'surge', 300 );
$sm->invoke( null, PNCP_Options::stored() );
$sm->invoke( null, PNCP_Options::stored() );
t( 'surge ανοιχτό: η σελίδα δεν μετριέται (fail open, χωρίς Emergency Mode από μισή μέτρηση)', $before === (int) $pk->invoke( null, 'surge', 'site', $sminute ) && PNCP_Breaker::open( 'surge' ) );
$saved_state = get_option( 'pncp_surge', null );
$sv->invoke( null, array( 'minute' => 42, 'avg' => 1.5, 'samples' => 3, 'streak' => 0 ) );
t( 'surge ανοιχτό: η κατάσταση δεν γράφεται (update_option παραλείπεται)', get_option( 'pncp_surge', null ) === $saved_state );
PNCP_Breaker::reset( 'surge' );
$sm->invoke( null, PNCP_Options::stored() );
t( 'surge κλειστό: μετρά ξανά', (int) $pk->invoke( null, 'surge', 'site', $sminute ) > $before );
$sv->invoke( null, array( 'minute' => 42, 'avg' => 1.5, 'samples' => 3, 'streak' => 0 ) );
$written = get_option( 'pncp_surge', array() );
t( 'surge κλειστό: η κατάσταση γράφεται', is_array( $written ) && 42 === (int) $written['minute'] );
$tiny = static function ( $ms, $name ) {
	return 'surge' === $name ? 0.000001 : $ms;
};
add_filter( 'pncp_breaker_ms', $tiny, 10, 2 );
$sm->invoke( null, PNCP_Options::stored() );
remove_filter( 'pncp_breaker_ms', $tiny, 10 );
t( 'αργή μέτρηση surge (όριο 0.000001 ms): ανοίγει «surge» με την περιγραφή της', PNCP_Breaker::open( 'surge' ) && 'site-wide page count' === ( PNCP_Breaker::states()['surge']['what'] ?? '' ), wp_json_encode( PNCP_Breaker::states() ) );
PNCP_Breaker::reset( 'surge', true );
remove_filter( 'pncp_surge_sample', $one );
if ( null === $saved_state ) {
	delete_option( 'pncp_surge' );
} else {
	update_option( 'pncp_surge', $saved_state, false );
}

/* ---------- Δικός του store (όπως η σύνδεση Redis των μετρητών) ---------- */
$mem = array();
PNCP_Breaker::use_store(
	static function ( $k ) use ( &$mem ) {
		return isset( $mem[ $k ] ) ? $mem[ $k ] : null;
	},
	static function ( $k, $v, $ttl ) use ( &$mem ) {
		$mem[ $k ] = $v;
		return true;
	},
	static function ( $k ) use ( &$mem ) {
		unset( $mem[ $k ] );
	}
);
$files_before = glob( $tmp . '/breaker/*' );
PNCP_Breaker::trip( 'precheck_redis', 400 );
t( 'use_store(): η κατάσταση στο store του καλούντα, κανένα αρχείο', 'custom' === PNCP_Breaker::kind() && isset( $mem['state_precheck_redis'], $mem['history'] ) && glob( $tmp . '/breaker/*' ) === $files_before );
PNCP_Breaker::forget();
PNCP_Breaker::use_store(
	static function ( $k ) use ( &$mem ) {
		return isset( $mem[ $k ] ) ? $mem[ $k ] : null;
	},
	static function ( $k, $v, $ttl ) use ( &$mem ) {
		$mem[ $k ] = $v;
		return true;
	},
	static function ( $k ) use ( &$mem ) {
		unset( $mem[ $k ] );
	}
);
t( 'use_store(): νέο αίτημα το βλέπει ανοιχτό· reset το κλείνει', PNCP_Breaker::open( 'precheck_redis' ) && 1 === PNCP_Breaker::reset() && ! PNCP_Breaker::open( 'precheck_redis' ) );

/* ---------- Redis (phpredis), αν υπάρχουν η επέκταση και redis-server ---------- */
$redis_bin = trim( (string) shell_exec( 'command -v redis-server 2>/dev/null' ) );
if ( class_exists( 'Redis', false ) && '' !== $redis_bin ) {
	$port  = 16391;
	$rproc = proc_open( array( $redis_bin, '--port', (string) $port, '--save', '', '--appendonly', 'no' ), array( 1 => array( 'file', '/dev/null', 'w' ) ), $rp );
	usleep( 500000 );
	PNCP_Breaker::forget();
	PNCP_Breaker::$redis_config = array(
		'host' => '127.0.0.1',
		'port' => $port,
	);
	PNCP_Breaker::setup( $tmp );
	$files_before = glob( $tmp . '/breaker/*' );
	PNCP_Breaker::trip( 'precheck_files', 333 );
	t( 'Redis: η κατάσταση στον Redis, κανένα αρχείο στον δίσκο', 'redis' === PNCP_Breaker::kind() && glob( $tmp . '/breaker/*' ) === $files_before, PNCP_Breaker::kind() );
	PNCP_Breaker::forget();
	PNCP_Breaker::setup( $tmp );
	t( 'Redis: νέο αίτημα το βλέπει ανοιχτό· reset', PNCP_Breaker::open( 'precheck_files' ) && 1 === PNCP_Breaker::reset( '', true ) );
	proc_terminate( $rproc );
	proc_close( $rproc );
	usleep( 200000 );
	PNCP_Breaker::forget();
	PNCP_Breaker::setup( $tmp );
	$start = hrtime( true );
	$is    = PNCP_Breaker::open( 'precheck_files' );
	PNCP_Breaker::trip( 'precheck_files', 300 );
	$took = ( hrtime( true ) - $start ) / 1e6;
	t( 'Redis ρυθμισμένος αλλά κάτω: κλειστό, ποτέ ο δίσκος, < 100 ms', ! $is && 'none' === PNCP_Breaker::kind() && glob( $tmp . '/breaker/*' ) === $files_before && $took < 100, PNCP_Breaker::kind() . ' ' . round( $took, 1 ) . ' ms' );
} else {
	echo "skip Redis (χωρίς phpredis ή redis-server)\n";
}
PNCP_Breaker::$redis_config = '';

/* ---------- APCu (stub): πρώτα από τον δίσκο, και η γέφυρα προς το WP-CLI ---------- */
if ( ! extension_loaded( 'apcu' ) && ! function_exists( 'apcu_enabled' ) ) {
	$GLOBALS['pncp_t_apcu'] = array();
	// Declared at run time (eval), only when APCu is not there.
	eval(
		'function apcu_enabled() { return ! empty( $GLOBALS["pncp_t_apcu_on"] ); }
		function apcu_fetch( $k, &$ok = null ) { $ok = isset( $GLOBALS["pncp_t_apcu"][ $k ] ); return $ok ? $GLOBALS["pncp_t_apcu"][ $k ] : false; }
		function apcu_store( $k, $v, $ttl = 0 ) { $GLOBALS["pncp_t_apcu"][ $k ] = $v; return true; }
		function apcu_delete( $k ) { unset( $GLOBALS["pncp_t_apcu"][ $k ] ); return true; }'
	);
	$GLOBALS['pncp_t_apcu_on'] = true;
	PNCP_Breaker::forget();
	PNCP_Breaker::setup( $tmp );
	$files_before = glob( $tmp . '/breaker/*' );
	PNCP_Breaker::trip( 'precheck_files', 444 );
	t( 'APCu: η κατάσταση στο APCu, κανένα αρχείο', 'apcu' === PNCP_Breaker::kind() && glob( $tmp . '/breaker/*' ) === $files_before && PNCP_Breaker::open( 'precheck_files' ) );
	PNCP_Breaker::reset( '', true );
	$sapis = static function () {
		return array( PHP_SAPI ); // As PHP-FPM.
	};
	add_filter( 'pncp_precheck_apcu_sapis', $sapis );
	$hc = PNCP_Breaker_Status::health_counters();
	remove_filter( 'pncp_precheck_apcu_sapis', $sapis );
	t( 'Site Health «ScrapeLock counters»: APCu ενεργό (στο FPM) → good, «APCu (inferred)»', 'good' === $hc['status'] && false !== strpos( $hc['description'], 'APCu (inferred)' ) && false !== strpos( $hc['label'], 'APCu' ), wp_json_encode( $hc ) );
	PNCP_Breaker::record_backend( 'redis' );
	$hc = PNCP_Breaker_Status::health_counters();
	t( 'record_backend( redis ) από τους μετρητές: Site Health «Redis» χωρίς «inferred», με τη γραμμή του breaker', 'good' === $hc['status'] && false !== strpos( $hc['description'], 'Counters: Redis.' ) && false !== strpos( $hc['description'], 'Circuit breaker: Nothing tripped' ), wp_json_encode( $hc ) );
	$GLOBALS['pncp_t_apcu'] = array();
	$GLOBALS['pncp_t_apcu_on'] = false;
	PNCP_Breaker::forget();
	PNCP_Breaker::setup( $tmp );
	PNCP_Breaker::record_backend( 'apcu' );
	t( 'record_backend(): ποτέ στον δίσκο (store αρχείων)', array() === PNCP_Breaker::recorded_backend() && ! is_file( $tmp . '/breaker/_backend.json' ) );
} else {
	echo "skip APCu stub (το APCu υπάρχει)\n";
}
if ( ! defined( 'WP_REDIS_HOST' ) && ! defined( 'WP_REDIS_VERSION' ) && ! ( function_exists( 'apcu_enabled' ) && apcu_enabled() ) ) {
	$hc = PNCP_Breaker_Status::health_counters();
	t( 'Site Health «ScrapeLock counters»: αρχεία → recommended, «Install APCu or a Redis object cache…»', 'recommended' === $hc['status'] && false !== strpos( $hc['description'], 'Install APCu or a Redis object cache so ScrapeLock never touches the disk' ) && false !== strpos( $hc['description'], 'files (inferred)' ), wp_json_encode( $hc ) );
	$first = trim( wp_strip_all_tags( (string) preg_replace( '#</p>.*#s', '', $hc['description'] ) ) );
	t( 'Site Health «ScrapeLock counters»: πρώτη γραμμή ≤ 20 λέξεις', str_word_count( $first ) <= 20, $first );
	t( 'Site Health: το test «scrapelock_counters» είναι καταχωρημένο', isset( PNCP_Health::tests( array() )['direct']['scrapelock_counters'] ) );
}
PNCP_Breaker::$clock   = null;
PNCP_Breaker::$ms      = array();
PNCP_Breaker::$minutes = array();
rrmdir( $tmp );

/* ---------- HTTP: ο έλεγχος πριν από το cache ---------- */
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
		PNCP_Breaker::$clock = null;
		PNCP_Breaker::forget();
		PNCP_Breaker::$dir = PNCP_Precheck::dir();
		PNCP_Breaker::reset( '', true );
		foreach ( array( '_snapshot.json', '_reset.json' ) as $name ) {
			@unlink( PNCP_Precheck::dir() . '/breaker/' . $name );
		}
		update_option( PNCP_OPTION, $keep );
		PNCP_Options::flush();
		PNCP_Precheck::sync();
	}
);
file_put_contents( $config_file, "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) );
file_put_contents( $cache_file, "<?php\nif ( isset( \$_SERVER['REQUEST_URI'] ) && 0 === strpos( \$_SERVER['REQUEST_URI'], '/cached-page/' ) ) {\n\theader( 'X-Test-Cache: HIT' );\n\techo 'CACHED PAGE';\n\texit;\n}\n" );
PNCP_Log::unban_all();
update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
update_option(
	PNCP_OPTION,
	array_merge(
		PNCP_Options::stored(),
		array(
			'monitor_mode'            => 0,
			'monitor_until'           => 0,
			'enabled'                 => 1,
			'precheck'                => 1,
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
	)
);
PNCP_Options::flush();
PNCP_Ip::reset();
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
WP_Screen::get( 'settings_page_scrapelock' )->set_current_screen();
$strict = static function ( $ms, $name ) {
	return 'precheck' === $name ? 0.001 : $ms;
};
PNCP_Precheck::sync();
PNCP_Precheck::maybe_sync();
sleep( 3 ); // OPcache: the new wp-config.php.
$pdir = PNCP_Precheck::dir();
PNCP_Breaker::forget();
PNCP_Breaker::$dir = $pdir;
PNCP_Breaker::reset( '', true );
$cfg = json_decode( (string) file_get_contents( $pdir . '/config.json' ), true );
t( 'HTTP: ο έλεγχος τρέχει, config.json με «breaker» (200 ms, 10 λεπτά)', PNCP_Precheck::active() && isset( $cfg['breaker']['ms'], $cfg['breaker']['minutes'] ) && 200.0 === (float) $cfg['breaker']['ms'] && 10 === (int) $cfg['breaker']['minutes'], wp_json_encode( $cfg['breaker'] ?? null ) );
// Does the test server have APCu? Then the precheck keeps the state there (never the disk), invisible to this
// process and to WP-CLI: what it did is read through an admin page (Site Health) and WP-CLI's copy (snapshot).
file_put_contents( ABSPATH . 'pncp-t-apcu.php', '<?php echo function_exists( "apcu_enabled" ) && apcu_enabled() ? "1" : "0";' );
$server_apcu = '1' === req( '/pncp-t-apcu.php' )[2];
unlink( ABSPATH . 'pncp-t-apcu.php' );
echo 'info: store of the test server: ' . ( $server_apcu ? 'APCu' : 'files' ) . "\n";

/** Site Health of the test server (its direct tests, as an administrator sees them): test => result. */
function site_health() {
	global $base;
	$admin   = get_user_by( 'id', 1 );
	$expire  = time() + DAY_IN_SECONDS;
	$token   = WP_Session_Tokens::get_instance( $admin->ID )->create( $expire );
	$cookies = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( $admin->ID, $expire, 'auth', $token ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( $admin->ID, $expire, 'logged_in', $token ),
	);
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$ch = curl_init( $base . '/wp-admin/site-health.php' );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_COOKIE         => implode( '; ', $jar ),
			CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 127.0.0.1', 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: en' ),
			CURLOPT_TIMEOUT        => 120,
		)
	);
	$body = (string) curl_exec( $ch );
	curl_close( $ch );
	$out = array();
	if ( preg_match( '/var SiteHealth = (\{.*?\});\s*\n/s', $body, $m ) ) {
		$js = json_decode( $m[1], true );
		foreach ( (array) ( $js['site_status']['direct'] ?? array() ) as $row ) {
			if ( isset( $row['test'] ) ) {
				$out[ $row['test'] ] = $row;
			}
		}
	}
	return $out;
}

/** The breaker's rows from WP-CLI (feature => row), or null without WP-CLI. */
function cli_rows() {
	global $wp_cli;
	if ( '' === $wp_cli ) {
		return null;
	}
	list( , $out ) = cli( 'breaker --format=json' );
	$rows = json_decode( $out, true );
	$by   = array();
	foreach ( (array) $rows as $row ) {
		$by[ $row['feature'] ] = $row;
	}
	return $by;
}

if ( $server_apcu && '' !== $wp_cli ) {
	// A state left in the server's APCu by an earlier run: cleared through WP-CLI's request and an admin page.
	site_health();
	cli( 'breaker reset --history' );
	site_health();
}
// A threshold no check can meet: the next request trips (as a stalled disk would). Written right before it: an
// admin page or WP-CLI in between would write config.json again without this process's filter.
add_filter( 'pncp_breaker_ms', $strict, 20, 2 );
PNCP_Precheck::sync();
$cfg = json_decode( (string) file_get_contents( $pdir . '/config.json' ), true );
t( 'HTTP: config.json με «breaker» (ms από το φίλτρο, minutes)', isset( $cfg['breaker']['ms'], $cfg['breaker']['minutes'] ) && 0.001 === (float) $cfg['breaker']['ms'] && 10 === (int) $cfg['breaker']['minutes'], wp_json_encode( $cfg['breaker'] ?? null ) );
sleep( 1 );
same_minute();
list( $code ) = req( '/cached-page/', visitor( '203.0.113.70' ) );
t( 'HTTP: ο «αργός» έλεγχος (όριο 0.001 ms): η σελίδα σερβίρεται', 200 === $code, (string) $code );
if ( $server_apcu ) {
	t( 'HTTP με APCu: καμία κατάσταση στον δίσκο (ούτε φάκελος breaker/ με αρχείο κατάστασης)', ! is_file( $pdir . '/breaker/precheck_files.json' ) && ! is_file( $pdir . '/breaker/precheck_apcu.json' ), implode( ' ', array_map( 'basename', (array) glob( $pdir . '/breaker/*' ) ) ) . ' ' . @file_get_contents( $pdir . '/breaker/precheck_files.json' ) );
} else {
	$state = json_decode( (string) @file_get_contents( $pdir . '/breaker/precheck_files.json' ), true );
	t( 'HTTP με αρχεία: precheck_files ανοιχτό για 10 λεπτά, «pre-cache check»', is_array( $state ) && (int) $state['until'] > time() + 500 && 'pre-cache check' === $state['what'], wp_json_encode( $state ) );
}
remove_filter( 'pncp_breaker_ms', $strict, 20 );
PNCP_Precheck::sync();
$cfg = json_decode( (string) file_get_contents( $pdir . '/config.json' ), true );
t( 'HTTP: πίσω στα 200 ms', 200.0 === (float) $cfg['breaker']['ms'] );
$c = codes( '/cached-page/', visitor( '203.0.113.70' ), 8 );
t( 'HTTP: όσο είναι ανοιχτό, 8 σελίδες πάνω από το όριο 5 περνούν (χωρίς μέτρηση)', array_fill( 0, 8, 200 ) === $c, implode( ',', $c ) );
PNCP_Log::ban( '198.51.100.71', 5, 'trap' );
list( $code, , $body ) = req( '/cached-page/', visitor( '198.51.100.71' ) );
t( 'HTTP: οι αποκλεισμοί ισχύουν όσο είναι ανοιχτό (403)', 403 === $code && 'Access denied.' === $body, "$code $body" );
PNCP_Log::unban( '198.51.100.71' );
$feature = 'precheck_files'; // The test server is cli-server: APCu (if any) is not used for the counters there.
$sh      = site_health();
$brk     = $sh['scrapelock_breaker'] ?? array();
t( 'HTTP → Site Health του server: critical, τι, πόσο, μέχρι πότε, 24ωρο, συμβουλή', 'critical' === ( $brk['status'] ?? '' ) && false !== strpos( (string) $brk['description'], PNCP_Breaker_Status::label( $feature ) ) && false !== strpos( (string) $brk['description'], 'Suspended until' ) && false !== strpos( (string) $brk['description'], 'Tripped 1 time in the last 24 hours' ) && false !== strpos( (string) $brk['description'], 'iowait' ), wp_json_encode( $brk ) );
$cnt = $sh['scrapelock_counters'] ?? array();
// 3.12.9: the check records the store it used (PNCP_Precheck_Runtime::breaker_hooks()) where the breaker has a memory
// store, so "files" may be recorded rather than inferred.
t( 'HTTP → Site Health «ScrapeLock counters»: files (cli-server) → recommended, με τη γραμμή του breaker', 'recommended' === ( $cnt['status'] ?? '' ) && preg_match( '/Counters: files[. ]/', (string) $cnt['description'] ) && false !== strpos( (string) $cnt['description'], 'Circuit breaker: ' . $feature . ' suspended until' ), wp_json_encode( $cnt ) );
if ( '' !== $wp_cli ) {
	list( $rc, $out ) = cli( 'status --format=json' );
	$rows  = json_decode( $out, true );
	$line  = '';
	$cline = '';
	foreach ( (array) $rows as $row ) {
		if ( 0 === strpos( (string) $row['setting'], 'Circuit breaker' ) ) {
			$line = (string) $row['value'];
		}
		if ( 0 === strpos( (string) $row['setting'], 'Counters stored in' ) ) {
			$cline = (string) $row['value'];
		}
	}
	t( 'wp scrapelock status: «Circuit breaker» ' . $feature . ' suspended until …', 0 === $rc && false !== strpos( $line, $feature . ' suspended until' ), $line ?: $out );
	t( 'wp scrapelock status: «Counters stored in» με τη σημείωση ότι το WP-CLI δεν βλέπει το APCu', false !== strpos( $cline, 'files (inferred)' ) && false !== strpos( $cline, 'WP-CLI cannot see' ), $cline );
	$rows = cli_rows();
	$row  = $rows[ $feature ] ?? array();
	t( 'wp scrapelock breaker: open, όριο, trips24 = 1, συμβουλή', 'open' === ( $row['state'] ?? '' ) && '1' === (string) $row['trips24'] && false !== strpos( (string) $row['advice'], 'iowait' ), wp_json_encode( $rows ) );
	list( $rc, $out ) = cli( 'breaker' );
	t( 'wp scrapelock breaker (πίνακας)' . ( $server_apcu ? ': «PHP-FPM\'s state (APCu) as of»' : '' ), 0 === $rc && false !== strpos( $out, $feature ) && ( ! $server_apcu || false !== strpos( $out, 'as of' ) ), $out );
	list( $rc, $out ) = cli( 'breaker reset bad-name' );
	t( 'wp scrapelock breaker reset με άκυρο όνομα: σφάλμα', 0 !== $rc );
	list( $rc, $out ) = cli( 'breaker reset' );
	if ( $server_apcu ) {
		t( 'wp scrapelock breaker reset (APCu): «Asked», το κάνει η επόμενη σελίδα διαχείρισης', 0 === $rc && false !== strpos( $out, 'Asked' ), $out );
		site_health();
	} else {
		t( 'wp scrapelock breaker reset: «Counting resumed (1 feature…)»', 0 === $rc && false !== strpos( $out, 'Counting resumed (1 feature' ), $out );
	}
	$rows = cli_rows();
	t( 'μετά το reset: κλειστό (το ιστορικό μένει)', 'closed' === ( $rows[ $feature ]['state'] ?? '' ), wp_json_encode( $rows ) );
	cli( 'breaker reset --history' );
	if ( $server_apcu ) {
		site_health();
	}
	list( $rc, $out ) = cli( 'breaker' );
	t( 'reset --history: «Nothing tripped in the last 24 hours»', 0 === $rc && false !== strpos( $out, 'Nothing tripped in the last 24 hours' ), $out );
} else {
	echo "skip WP-CLI (χωρίς WP_CLI)\n";
}
if ( '' !== $wp_cli ) {
	same_minute();
	$c = codes( '/cached-page/', visitor( '203.0.113.72' ), 6 );
	t( 'HTTP: μετά το reset μετρά ξανά (429 πάνω από 5)', in_array( 429, $c, true ), implode( ',', $c ) );
}
if ( ! $server_apcu ) {
	// A damaged state file: no error, counting goes on.
	@mkdir( $pdir . '/breaker' );
	file_put_contents( $pdir . '/breaker/precheck_files.json', "{\"until\": 99999999999 garbage \xff" );
	same_minute();
	list( $code, , $body ) = req( '/cached-page/', visitor( '203.0.113.73' ) );
	$c = codes( '/cached-page/', visitor( '203.0.113.73' ), 5 );
	t( 'HTTP: χαλασμένο αρχείο κατάστασης: 200 χωρίς PHP σφάλμα, μετρά κανονικά', 200 === $code && 'CACHED PAGE' === $body && in_array( 429, $c, true ), "$code $body " . implode( ',', $c ) );
	// Locked by another process.
	file_put_contents( $pdir . '/breaker/precheck_files.json', wp_json_encode( array( 'until' => time() + 600 ) ) );
	touch( $pdir . '/breaker/precheck_files.json', time() + 600 ); // 3.12.9: its time is the end (PNCP_Breaker::open()).
	$locker = proc_open(
		array( PHP_BINARY, '-r', '$a = fopen( $argv[1], "c+" ); flock( $a, LOCK_EX ); echo "locked\n"; sleep( 4 );', $pdir . '/breaker/precheck_files.json' ),
		array( 1 => array( 'pipe', 'w' ) ),
		$pipes
	);
	fgets( $pipes[1] );
	list( $code, , , $took ) = req( '/cached-page/', visitor( '203.0.113.74' ) );
	$c = codes( '/cached-page/', visitor( '203.0.113.74' ), 7 );
	t( 'HTTP: αρχείο κατάστασης κλειδωμένο από άλλη διεργασία: απάντηση χωρίς αναμονή (< 1 s), ανοιχτό (χωρίς μέτρηση)', 200 === $code && $took < 1 && array_fill( 0, 7, 200 ) === $c, round( $took, 3 ) . ' s ' . implode( ',', $c ) );
	proc_close( $locker );
	@unlink( $pdir . '/breaker/precheck_files.json' );
}

t( 'καμία PHP προειδοποίηση από τον breaker / τον έλεγχο', ! $pncp_warnings, implode( '; ', $pncp_warnings ) );
restore_error_handler();
exit( $fails ? 1 : 0 );
