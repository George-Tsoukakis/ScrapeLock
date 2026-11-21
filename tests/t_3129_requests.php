<?php
/**
 * ScrapeLock 3.12.9 — what a visitor's request costs: database queries and file access of ScrapeLock's own code
 * (lib/probe-3129.php, an mu-plugin copied in for the test, notes them for requests with the header X-PNCP-Probe).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [REDIS_DROPIN=/path/object-cache.php] php t_3129_requests.php
 *
 * A. Without a persistent object cache: a known visitor's page views (after the first one) write nothing but the
 *    per-minute counters of the limits (pncp_rl_*, the only place all PHP workers share), and the surge state at
 *    most once a minute.
 * B. With a persistent object cache (REDIS_DROPIN, else lib/object-cache-stub.php, a small one on files): no query
 *    (read or write) and no file access of ScrapeLock in steady state: page views of a known and of a new visitor,
 *    a refused bot, a ban (the trap), the Traffic rows of WordPress, an AI referral. The scheduled event
 *    (PNCP_Defer::flush()) then writes the log rows, the ban, the Traffic rows and the referral to the database.
 * S. The automatic Emergency Mode (PNCP_Surge) with the object cache, in a visitor's request: 3 minutes over the
 *    threshold start it at once (PNCP_Options::emergency_until()), with no query; the scheduled event stores it
 *    (option, last starts). Each minute's closing takes < 5 ms. Without the cache it starts at once, as before.
 *
 * Only on a test WordPress. The drop-in, the probe and the settings are put back at the end.
 */

$wp_dir = rtrim( (string) getenv( 'WP_DIR' ), '/' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
$content = $wp_dir . '/wp-content';
$oc      = $content . '/object-cache.php';
if ( file_exists( $oc ) ) {
	echo "SKIP an object cache drop-in is installed already (the test installs its own)\n";
	exit( 0 );
}

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( '' !== (string) $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

$tmp = sys_get_temp_dir() . '/pncp-t3129-' . getmypid();
@mkdir( $tmp, 0700, true );

/**
 * Runs PHP code in a WordPress loaded as a scheduled event would load it (DOING_CRON: ScrapeLock writes, never
 * queues), in its own process (this one never loads WordPress: the drop-in comes and goes). Returns what the code
 * returns, through JSON.
 *
 * @param string $code PHP code (a function body).
 * @return mixed
 */
function wp_run( $code ) {
	global $wp_dir, $tmp, $base;
	$file = $tmp . '/run-' . md5( $code . microtime() ) . '.php';
	$host = (string) parse_url( $base, PHP_URL_HOST ) . ( parse_url( $base, PHP_URL_PORT ) ? ':' . parse_url( $base, PHP_URL_PORT ) : '' );
	file_put_contents(
		$file,
		"<?php\ndefine( 'DOING_CRON', true );\n\$_SERVER['HTTP_HOST'] = " . var_export( $host, true ) . ";\n\$_SERVER['REQUEST_URI'] = '/';\nrequire " . var_export( $wp_dir . '/wp-load.php', true ) . ";\n\$pncp_fn = function () {\n" . $code . "\n};\necho \"\\n@@PNCP@@\" . json_encode( \$pncp_fn() );\n"
	);
	$out = (string) shell_exec( ( getenv( 'PHP' ) ?: 'php' ) . ' ' . escapeshellarg( $file ) . ' 2>&1' );
	unlink( $file );
	$at = strrpos( $out, '@@PNCP@@' );
	if ( false === $at ) {
		fwrite( STDERR, "wp_run failed: $out\n" );
		return null;
	}
	if ( '' !== trim( substr( $out, 0, $at ) ) ) {
		echo trim( substr( $out, 0, $at ) ) . "\n"; // Warnings of the helper: run-all.sh counts them.
	}
	return json_decode( substr( $out, $at + 8 ), true );
}

/**
 * A request through the web server with the probe on: [status, probe record].
 *
 * @param string               $path    Path.
 * @param string               $ip      Visitor IP (X-Test-IP).
 * @param string|null          $ua      User-Agent ('' = a browser's, null = none).
 * @param array<string,string> $headers More headers.
 * @return array{0:int, 1:array<string,mixed>}
 */
function visit( $path, $ip, $ua = '', $headers = array() ) {
	global $base, $content;
	static $n = 0;
	$id = 'r' . getmypid() . '-' . ( ++$n );
	$h  = array(
		'X-PNCP-Probe: ' . $id,
		'X-Test-IP: ' . $ip,
		'Accept: text/html,application/xhtml+xml',
		'Accept-Language: en-US,en;q=0.9',
	);
	if ( null !== $ua ) {
		$h[] = 'User-Agent: ' . ( '' !== $ua ? $ua : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36' );
	} // null: no User-Agent at all.
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	$ch = curl_init( $base . $path );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_TIMEOUT        => 30,
		)
	);
	curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	$file = $content . '/pncp-probe/' . $id . '.json';
	$rec  = is_file( $file ) ? json_decode( (string) file_get_contents( $file ), true ) : null;
	@unlink( $file );
	return array( $code, is_array( $rec ) ? $rec : array( 'db' => array( 'no probe record' ), 'io' => array(), 'total' => 0, 'ext' => null ) );
}

/** The write queries of a probe record. */
function writes( $rec ) {
	return array_values( array_filter( $rec['db'], static function ( $q ) {
		return (bool) preg_match( '/^\S+\s+(INSERT|UPDATE|REPLACE|DELETE)\b/i', $q );
	} ) );
}

/* ---------- Setup ---------- */

$saved = wp_run(
	'$post = get_posts( array( "numberposts" => 1, "post_status" => "publish" ) );
	return array(
		"settings" => base64_encode( serialize( get_option( PNCP_OPTION ) ) ),
		"surge"    => base64_encode( serialize( get_option( PNCP_Surge::STATE, null ) ) ),
		"last"     => base64_encode( serialize( get_option( PNCP_Surge::LAST, null ) ) ),
		"path"     => $post ? (string) wp_parse_url( get_permalink( $post[0] ), PHP_URL_PATH ) : "/",
		"plugin"   => PNCP_DIR,
	);'
);
if ( ! is_array( $saved ) ) {
	echo "FAIL WordPress could not be loaded\n";
	exit( 1 );
}
$page  = $saved['path'];
$probe = $content . '/mu-plugins/0-pncp-probe-3129.php';
@mkdir( $content . '/mu-plugins', 0755, true );
copy( __DIR__ . '/lib/probe-3129.php', $probe );

$ours_oc = false;
$restore = static function () use ( $saved, $probe, $oc, $content, $tmp, &$ours_oc ) {
	static $done = false;
	if ( $done ) {
		return;
	}
	$done = true;
	if ( $ours_oc && is_file( $oc ) ) {
		wp_run( 'PNCP_Defer::flush(); return true;' ); // Nothing left waiting in a cache that goes away.
		unlink( $oc );
	}
	exec( 'rm -rf ' . escapeshellarg( $content . '/pncp-test-cache' ) . ' ' . escapeshellarg( $content . '/pncp-probe' ) );
	wp_run(
		'update_option( PNCP_OPTION, unserialize( base64_decode( ' . var_export( $saved['settings'], true ) . ' ) ) );
		foreach ( array( PNCP_Surge::STATE => ' . var_export( $saved['surge'], true ) . ', PNCP_Surge::LAST => ' . var_export( $saved['last'], true ) . ' ) as $name => $value ) {
			$value = unserialize( base64_decode( $value ) );
			null === $value ? delete_option( $name ) : update_option( $name, $value, false );
		}
		PNCP_Options::set_emergency( 0 );
		delete_option( PNCP_Surge::ALERT );
		wp_unschedule_hook( PNCP_Surge::MAIL );
		wp_unschedule_hook( PNCP_Defer::CRON );
		PNCP_Log::unban( "198.51.100.93" );
		PNCP_Log::unban( "198.51.100.96" );
		return true;'
	);
	@unlink( $probe );
	exec( 'rm -rf ' . escapeshellarg( $tmp ) );
};
register_shutdown_function( $restore );

/**
 * Changes settings (in a WordPress loaded as a scheduled event; the drop-in, when there is one, sees the change).
 *
 * @param array<string, mixed> $changes Settings.
 */
function settings( $changes ) {
	wp_run( '$s = array_merge( get_option( PNCP_OPTION ), ' . var_export( $changes, true ) . ' ); update_option( PNCP_OPTION, $s ); return true;' );
}

settings( array( 'enabled' => 1, 'monitor_mode' => 0, 'monitor_until' => 0, 'rate_limit' => 60, 'block_bots' => 1, 'trap_enabled' => 1, 'ban_strikes' => 3, 'traffic' => 0, 'traffic_wp' => 0, 'ai_referrals' => 1, 'human_check' => 0, 'require_browser_headers' => 0, 'auto_emergency' => 1, 'auto_emergency_mode' => 'notify', 'auto_emergency_min' => 100000, 'block_empty_ua' => 1 ) );
wp_run( 'PNCP_Options::set_emergency( 0 ); return true;' );

/**
 * The automatic Emergency Mode over three minutes of 500 pages (threshold 100), in minutes far from now. With
 * $visitor, as in a visitor's request (PNCP_Defer::active()). Counts the queries and times each closing.
 */
$surge_code = static function ( $visitor ) {
	return '$visitor = ' . ( $visitor ? 'true' : 'false' ) . ';
	if ( $visitor ) {
		add_filter( "pncp_defer_writes", "__return_true" );
	}
	PNCP_Defer::reset();
	$m0 = (int) floor( time() / 60 ) + 100000 + wp_rand( 0, 100000 );
	$st = array( "minute" => $m0, "avg" => 0.0, "samples" => 0, "streak" => 0 );
	update_option( PNCP_Surge::STATE, $st, false );
	PNCP_Defer::set( PNCP_Surge::CACHED, $st, 0 );
	$s  = array_merge( PNCP_Options::stored(), array( "auto_emergency" => 1, "auto_emergency_min" => 100, "auto_emergency_mode" => "start" ) );
	$q  = 0;
	add_filter( "query", function ( $sql ) use ( &$q ) { ++$q; return $sql; } );
	$ms = array();
	for ( $k = 2; $k <= 4; $k++ ) {
		$t0   = microtime( true );
		PNCP_Surge::observe( 1, $m0 + $k, 500, $s );
		$ms[] = round( ( microtime( true ) - $t0 ) * 1000, 3 );
	}
	$out = array(
		"queries" => $q,
		"ms"      => $ms,
		"until"   => PNCP_Options::emergency_until(),
		"stored"  => (int) get_option( PNCP_Options::EMERGENCY_OPTION, 0 ),
		"streak"  => PNCP_Surge::state()["streak"],
		"last"    => count( PNCP_Surge::last() ),
	);
	if ( $visitor ) {
		remove_all_filters( "pncp_defer_writes" );
		PNCP_Defer::reset();
		PNCP_Defer::flush();
		$out["after_stored"] = (int) get_option( PNCP_Options::EMERGENCY_OPTION, 0 );
		$out["after_auto"]   = PNCP_Defer::get( PNCP_Surge::AUTO_UNTIL );
		$out["after_last"]   = PNCP_Surge::last();
		$out["after_state"]  = get_option( PNCP_Surge::STATE );
		$out["mail"]         = (bool) wp_next_scheduled( PNCP_Surge::MAIL, array( 500, $out["after_last"] ? (int) $out["after_last"][0]["threshold"] : 0, 1 ) );
	}
	PNCP_Defer::delete( PNCP_Surge::CACHED );
	PNCP_Options::set_emergency( 0 );
	return $out;';
};

/* ---------- A. Without an object cache ---------- */

$ip = '198.51.100.90';
visit( $page, $ip ); // The visitor's first request (its counters and reputation are created).
$total  = 0;
$other  = array();
$counts = 0;
$surge  = 0;
$io     = array();
$steps  = 6;
for ( $i = 0; $i < $steps; $i++ ) {
	list( $code, $rec ) = visit( $page, $ip );
	$total += (int) $rec['total'];
	$io     = array_merge( $io, $rec['io'] );
	foreach ( writes( $rec ) as $q ) {
		if ( false !== strpos( $q, 'pncp_rl_' ) ) {
			++$counts;
		} elseif ( 0 === strpos( $q, 'includes/class-pncp-surge.php:' ) ) {
			++$surge;
		} else {
			$other[] = $q;
		}
	}
}
t( 'A the probe sees the queries of the page views (WordPress\'s own), and ScrapeLock\'s counters among them', $total > 0 && $counts > 0, $total . ' / ' . $counts );
t( 'A without an object cache a known visitor\'s page views write only the counters of the limits', array() === $other, implode( ' | ', $other ) );
t( 'A ...a few per request (the page limit, the sampled surge counter; with transients a value and its expiry each)', $counts <= 4 * $steps, (string) $counts );
t( 'A ...and the surge state at most once a minute', $surge <= 2, (string) $surge );
echo "     (A: {$counts} counter writes in {$steps} page views, " . count( $io ) . " file accesses of ScrapeLock)\n";

$r = wp_run( $surge_code( false ) );
t( 'S without an object cache: 3 minutes over the threshold start Emergency Mode at once (option, last starts)', is_array( $r ) && $r['until'] > time() && $r['stored'] > time() && 3 === $r['streak'] && $r['last'] >= 1, wp_json_encode_safe( $r ) );

/* ---------- B. With a persistent object cache ---------- */

$dropin = (string) getenv( 'REDIS_DROPIN' );
$kind   = '' !== $dropin && is_readable( $dropin ) && class_exists( 'Redis' ) ? 'Redis drop-in' : 'stub';
copy( 'stub' === $kind ? __DIR__ . '/lib/object-cache-stub.php' : $dropin, $oc );
$ours_oc = true;
echo "     (B: $kind)\n";
wp_run( 'PNCP_Defer::flush(); return true;' ); // The scheduled event's first run (it puts the bans into the cache).

$trap    = (string) wp_run( 'return PNCP_Bots::trap_path();' );
$t_start = time();
$bot     = null; // No User-Agent: refused by "Block empty User-Agent" whatever the bot list holds.
// Warm-up: WordPress fills the cache (options, the visitor's counters).
visit( $page, '198.51.100.91' );
visit( $page, '198.51.100.91' );
visit( $page, '198.51.100.95' );
visit( $page, '198.51.100.94', $bot );
for ( $i = 0; $i < 3; $i++ ) {
	visit( $trap, '198.51.100.96' ); // A ban (3 violations): the official crawler lists are read into the cache.
}

$clean = static function ( $label, $rec, $status = null, $code = null ) {
	$ok = array() === $rec['db'] && array() === $rec['io'] && true === $rec['ext'];
	if ( null !== $status ) {
		$ok = $ok && $status === $code;
	}
	t( $label, $ok, ( null !== $code ? 'HTTP ' . $code . ' ' : '' ) . implode( ' | ', array_merge( $rec['db'], $rec['io'] ) ) . ( true !== $rec['ext'] ? ' (no object cache in the request)' : '' ) );
};
for ( $i = 1; $i <= 3; $i++ ) {
	list( $code, $rec ) = visit( $page, '198.51.100.91' );
	$clean( "B page view $i of a known visitor: no query (read or write) and no file access of ScrapeLock", $rec, 200, $code );
}
list( $code, $rec ) = visit( $page, '198.51.100.92' );
$clean( 'B the first page view of a new visitor: none either (bans, counters, reputation in the cache)', $rec, 200, $code );
list( $code, $rec ) = visit( $page, '198.51.100.94', $bot );
$clean( 'B a refused bot (no User-Agent: 403, logged): none either', $rec, 403, $code );
for ( $i = 1; $i <= 3; $i++ ) {
	list( $code, $rec ) = visit( $trap, '198.51.100.93' );
	$clean( "B the trap, violation $i (403" . ( 3 === $i ? ', a new ban' : '' ) . '): none either', $rec, 403, $code );
}
list( $code, $rec ) = visit( $page, '198.51.100.93' );
$clean( 'B ...the ban is in effect at once (403), with none either', $rec, 403, $code );
$count_code = '$since = ' . (int) $t_start . '; global $wpdb;
	return array(
		"ban"     => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM " . PNCP_Log::bans_table() . " WHERE ip = %s", "198.51.100.93" ) ),
		"log"     => (int) $wpdb->get_var( $wpdb->prepare( "SELECT SUM(hits) FROM " . PNCP_Log::table() . " WHERE ip = %s AND created >= %s", "198.51.100.94", gmdate( "Y-m-d H:i:s", $since - 60 ) ) ),
		"traffic" => PNCP_Traffic::ready() ? (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM " . PNCP_Traffic::table() . " WHERE ip LIKE %s AND src = %s AND ts >= %d", "198.51.100.%", "wp", $since ) ) : -1,
		"air"     => (int) $wpdb->get_var( $wpdb->prepare( "SELECT SUM(hits) FROM " . PNCP_Ai_Referrals::table() . " WHERE platform = %s", "chatgpt" ) ),
	);';
$before = wp_run( $count_code );
t( 'B before the scheduled event: the ban is not in the database yet', is_array( $before ) && 0 === $before['ban'], wp_json_encode_safe( $before ) );
$after = wp_run( 'add_filter( "pncp_defer_ready", "__return_true" ); PNCP_Defer::flush(); ' . $count_code );
t( 'B after it: the ban is in the table', is_array( $after ) && 1 === $after['ban'], wp_json_encode_safe( $after ) );
t( 'B ...the refused bot\'s log row, with its hits', is_array( $after ) && $after['log'] >= 2 && $after['log'] > $before['log'], wp_json_encode_safe( array( $before, $after ) ) );

$r = wp_run( $surge_code( true ) );
t( 'S with an object cache, in a visitor\'s request: 3 minutes over the threshold, Emergency Mode in effect at once', is_array( $r ) && $r['until'] > time() && 3 === $r['streak'], wp_json_encode_safe( $r ) );
t( 'S ...with no database query (the state, the claim of the minute and the start in the cache)', is_array( $r ) && 0 === $r['queries'] && $r['stored'] <= time(), wp_json_encode_safe( $r ) );
if ( is_array( $r ) ) {
	$ms = $r['ms'];
	sort( $ms );
}
t( 'S ...a minute closed in < 5 ms (the median of the three)', is_array( $r ) && $ms[1] < 5, wp_json_encode_safe( $r['ms'] ) );
t( 'S the scheduled event stores it: the option, the last starts, the email event, the state', is_array( $r ) && $r['after_stored'] > time() && false === $r['after_auto'] && isset( $r['after_last'][0]['count'] ) && 500 === (int) $r['after_last'][0]['count'] && $r['mail'] && is_array( $r['after_state'] ) && 3 === (int) $r['after_state']['streak'], wp_json_encode_safe( $r ) );

$restore();
echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );

/**
 * JSON for a failure message (this process has no WordPress).
 *
 * @param mixed $v Value.
 * @return string
 */
function wp_json_encode_safe( $v ) {
	return (string) json_encode( $v );
}
