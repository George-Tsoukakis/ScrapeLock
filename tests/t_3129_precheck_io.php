<?php
/**
 * ScrapeLock 3.12.9 — the pre-cache check never waits for the disk in a visitor's request.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3129_precheck_io.php
 *
 * The check runs here in PHP servers of its own (php -S, the plugin's runtime file and a data folder in the temp
 * folder, the configuration the plugin writes for this WordPress), never through the site of WP_DIR:
 *   a) a counter file / events.log / strike file locked by another process: the request is answered at once;
 *   b) 50 processes on one counter at the same time: none waits, no count lost, exactly one violation, and a
 *      file replaced whole (ban, strike) is never read empty;
 *   c) no cleanup in a visitor's request (the source, and old minutes left in place), the sweep without WP-Cron
 *      only within its budget;
 *   d) thousands of old minute files: the request stays fast;
 *   e) Redis (a redis-server of the test on a Unix socket; SKIP without redis-server or the PHP extension): limit,
 *      ban, events, configuration in Redis, no file of the data folder touched (strace, when there is one), Redis
 *      stopped mid-run (the files take over, the ban written there holds), Redis back empty (the bans copied in);
 *   f) APCu (SKIP without the extension): the counters as before (same names), bans, strikes, events, nonces and
 *      the configuration in APCu, no file touched (strace) and the check working with the data folder gone;
 *   g) WordPress: the Redis connection in the line of wp-config.php (password masked), WP-CLI's ban changes reach
 *      the web server's APCu through the signed request (ops.log, serve_sync()), events drained from the store.
 * Only on a test WordPress: its settings change during the test and are put back at the end.
 */

$wp_dir = getenv( 'WP_DIR' );
if ( ! $wp_dir ) {
	fwrite( STDERR, "WP_DIR is required\n" );
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
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( '' !== (string) $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}
function skip( $label ) {
	echo 'SKIP ' . $label . "\n";
}

PNCP_Precheck::load_runtime();
$runtime = PNCP_Precheck::runtime_file();
$tmp     = rtrim( get_temp_dir(), '/' ) . '/pncp-t3129-' . wp_generate_password( 8, false, false );
wp_mkdir_p( $tmp );
$servers = array();
$redis   = null;
$saved   = get_option( PNCP_OPTION );
register_shutdown_function(
	static function () use ( &$servers, &$redis, $tmp, $saved ) {
		foreach ( $servers as $proc ) {
			stop_server( $proc );
		}
		if ( is_array( $redis ) ) {
			stop_redis( $redis );
		}
		update_option( PNCP_OPTION, $saved );
		exec( 'rm -rf ' . escapeshellarg( $tmp ) );
	}
);

// The settings of t_precheck.php: 5 pages a minute, a ban on the first violation, the visitor in X-Real-IP (the
// servers of the test are 127.0.0.1: "Nginx in front").
update_option(
	PNCP_OPTION,
	array_merge(
		PNCP_Options::stored(),
		array(
			'monitor_mode'            => 0,
			'monitor_until'           => 0,
			'enabled'                 => 1,
			'rate_limit'              => 5,
			'ban_strikes'             => 1,
			'ban_minutes'             => 5,
			'ip_header'               => 'x_real_ip',
			'block_bots'              => 1,
			'require_browser_headers' => 0,
			'human_check'             => 0,
			'allow_ips'               => '',
			'block_ips'               => '',
			'probe_ban'               => 0,
		)
	)
);
PNCP_Options::flush();
$base_config = PNCP_Precheck::config();
$sig_key     = PNCP_Server_Ips::sig_key( true );

/** A data folder with the configuration (and changes to it). */
function data_dir( $name, $changes = array() ) {
	global $tmp, $base_config;
	$dir = $tmp . '/' . $name;
	wp_mkdir_p( $dir );
	file_put_contents( $dir . '/config.json', wp_json_encode( array_merge( $base_config, $changes ), JSON_UNESCAPED_SLASHES ) . "\n" );
	file_put_contents( $dir . '/crawlers.json', PNCP_Precheck::crawlers_json() );
	touch( $dir . '/.cleaned' ); // As after the hourly cleanup.
	return $dir;
}

function free_port() {
	$s    = stream_socket_server( 'tcp://127.0.0.1:0' );
	$name = stream_socket_get_name( $s, false );
	fclose( $s );
	return (int) substr( (string) strrchr( (string) $name, ':' ), 1 );
}

/**
 * A PHP server that runs the check, then answers "PAGE". ?__dump=1 lists the APCu names (before the check).
 * $strace: the server runs under strace, its file and read/write calls in $strace.
 */
function start_server( $dir, $ini, $redis_conf = array(), $strace = '' ) {
	global $runtime, $sig_key, $servers;
	$front = $dir . '-front';
	wp_mkdir_p( $front );
	file_put_contents(
		$front . '/index.php',
		"<?php\n"
		. "if ( isset( \$_GET['__dump'] ) ) { header( 'Content-Type: application/json' ); \$o = array(); if ( class_exists( 'APCUIterator' ) && apcu_enabled() ) { foreach ( new APCUIterator( '/^pncp_pc_/', APC_ITER_KEY | APC_ITER_VALUE ) as \$i ) { \$o[ \$i['key'] ] = is_scalar( \$i['value'] ) ? \$i['value'] : 'array'; } } echo json_encode( \$o ); exit; }\n"
		. 'require ' . var_export( $runtime, true ) . ";\n"
		. 'PNCP_Precheck_Runtime::boot( ' . var_export( $dir, true ) . ', ' . var_export( $sig_key, true ) . ', ' . var_export( $redis_conf, true ) . " );\n"
		. "echo 'PAGE';\n"
	);
	$port = free_port();
	$cmd  = ( '' !== $strace ? 'exec strace -f -qq -y -e trace=%file,read,write,pread64,pwrite64 -o ' . escapeshellarg( $strace ) . ' ' : 'exec ' )
		. escapeshellarg( PHP_BINARY ) . ' ' . $ini . ' -d display_errors=0 -d log_errors=0 -S 127.0.0.1:' . $port . ' -t ' . escapeshellarg( $front ) . ' ' . escapeshellarg( $front . '/index.php' );
	$proc = proc_open( $cmd, array( array( 'file', '/dev/null', 'r' ), array( 'file', '/dev/null', 'w' ), array( 'file', '/dev/null', 'w' ) ), $pipes );
	for ( $i = 0; $i < 100; $i++ ) {
		$s = @fsockopen( '127.0.0.1', $port, $errno, $errstr, 0.1 );
		if ( $s ) {
			fclose( $s );
			break;
		}
		usleep( 50000 );
	}
	$server    = array(
		'proc' => $proc,
		'url'  => 'http://127.0.0.1:' . $port,
	);
	$servers[] = $server;
	return $server;
}

function stop_server( $server ) {
	if ( is_resource( $server['proc'] ) ) {
		$status = proc_get_status( $server['proc'] );
		if ( ! empty( $status['running'] ) ) {
			exec( 'pkill -KILL -P ' . (int) $status['pid'] . ' 2>/dev/null' ); // The PHP under strace.
			proc_terminate( $server['proc'], 9 );
		}
		proc_close( $server['proc'] );
	}
}

/** One request as a visitor: [code, ms, body]. */
function visit( $server, $ip, $path = '/page/', $method = 'GET', $headers = array() ) {
	$ch = curl_init( $server['url'] . $path );
	$h  = array(
		'X-Real-IP: ' . $ip,
		'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36',
		'Accept-Language: en-US,en;q=0.9',
	);
	foreach ( $headers as $name => $value ) {
		$h[] = $name . ': ' . $value;
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_CUSTOMREQUEST  => $method,
			CURLOPT_TIMEOUT        => 20,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$ms   = 1000 * (float) curl_getinfo( $ch, CURLINFO_TOTAL_TIME );
	curl_close( $ch );
	return array( $code, $ms, $body );
}

/** n requests: the codes and the slowest time. */
function visits( $server, $ip, $n ) {
	$codes = array();
	$max   = 0.0;
	for ( $i = 0; $i < $n; $i++ ) {
		list( $code, $ms ) = visit( $server, $ip );
		$codes[]           = $code;
		$max               = max( $max, $ms );
	}
	return array( $codes, $max );
}

/** Waits for the next minute when fewer than $need seconds of this one are left (the counters are per minute). */
function same_minute( $need = 20 ) {
	$left = 60 - time() % 60;
	if ( $left < $need ) {
		sleep( $left + 1 );
	}
}

/** The lines of an strace log after $offset that touch $dir (open, stat, read, write, rename, unlink, ...). */
function traced( $log, $offset, $dir ) {
	clearstatcache();
	$text = (string) file_get_contents( $log, false, null, $offset );
	return array_values(
		array_filter(
			explode( "\n", $text ),
			static function ( $line ) use ( $dir ) {
				return false !== strpos( $line, $dir . '/' ) || false !== strpos( $line, $dir . '>' ) || false !== strpos( $line, '"' . $dir . '"' );
			}
		)
	);
}

function start_redis() {
	global $tmp;
	if ( ! class_exists( 'Redis' ) || '' === trim( (string) shell_exec( 'command -v redis-server 2>/dev/null' ) ) ) {
		return null;
	}
	$sock = $tmp . '/redis.sock';
	exec( 'redis-server --port 0 --unixsocket ' . escapeshellarg( $sock ) . ' --unixsocketperm 700 --save "" --appendonly no --daemonize yes --pidfile ' . escapeshellarg( $tmp . '/redis.pid' ) . ' --dir ' . escapeshellarg( $tmp ) . ' >/dev/null 2>&1' );
	for ( $i = 0; $i < 50 && ! file_exists( $sock ); $i++ ) {
		usleep( 100000 );
	}
	return file_exists( $sock ) ? array(
		'sock' => $sock,
		'pid'  => $tmp . '/redis.pid',
	) : null;
}

function stop_redis( $r ) {
	$pid = (int) @file_get_contents( $r['pid'] );
	if ( $pid > 0 ) {
		posix_kill( $pid, 15 );
		for ( $i = 0; $i < 50 && file_exists( $r['sock'] ); $i++ ) {
			usleep( 100000 );
		}
	}
}

function redis_client( $sock ) {
	$r = new Redis();
	$r->connect( $sock );
	return $r;
}

$minute = static function () {
	return (int) floor( time() / 60 );
};
$has_strace = '' !== trim( (string) shell_exec( 'command -v strace 2>/dev/null' ) ) && 0 === (int) shell_exec( 'strace -qq -o /dev/null true >/dev/null 2>&1; echo $?' );
$files_ini  = '-d apc.enabled=0 -d apc.enable_cli=0';

/* ---------- c) static: nothing in a visitor's request cleans up, locks or waits ---------- */
$src = (string) file_get_contents( $runtime );
preg_match_all( '/public static function (\w+)\(/', $src, $m, PREG_OFFSET_CAPTURE );
$bodies = array();
foreach ( $m[1] as $i => $hit ) {
	$close             = strpos( $src, "\n\t}\n", $hit[1] );
	$bodies[ $hit[0] ] = substr( $src, $hit[1], ( false === $close ? strlen( $src ) : $close ) - $hit[1] );
}
$request_path = array( 'boot', 'load', 'run', 'verdict', 'hit', 'increment', 'new_file_ok', 'strike', 'banned', 'ban', 'probe_seen', 'self_signed', 'event', 'crossed', 'maybe_sweep' );
$bad          = array();
foreach ( $request_path as $fn ) {
	if ( isset( $bodies[ $fn ] ) && preg_match( '/self::cleanup\(|scandir\(|ftruncate\(|LOCK_EX(?! \| LOCK_NB)/', $bodies[ $fn ] ) ) {
		$bad[] = $fn;
	}
}
t( 'c) static: no cleanup(), scandir(), ftruncate() or waiting LOCK_EX in the request path', ! $bad && 13 <= count( array_intersect( $request_path, array_keys( $bodies ) ) ), implode( ',', $bad ) );
preg_match_all( '/flock\(\s*\$\w+,\s*([A-Z_| ]+)\)/', $src, $locks );
t( 'c) static: every flock() of the check is LOCK_EX | LOCK_NB (or an unlock)', $locks[1] && ! array_diff( array_map( 'trim', $locks[1] ), array( 'LOCK_EX | LOCK_NB', 'LOCK_UN' ) ), implode( ',', $locks[1] ) );
t( 'c) static: events.log is appended without LOCK_EX', false === strpos( (string) $bodies['event'], 'LOCK_EX' ) );

/* ---------- a) a lock held by another process: never waited for ---------- */
$dir_a  = data_dir( 'files-a', array( 'apcu' => false ) );
$srv_a  = start_server( $dir_a, $files_ini );
same_minute( 25 );
list( $code ) = visit( $srv_a, '198.51.100.20' );
$hdir   = $dir_a . '/hits/' . $minute();
$locked = array();
foreach ( array( $hdir . '/' . md5( '198.51.100.20' ), $hdir . '/.new', $dir_a . '/events.log' ) as $file ) {
	touch( $file );
	$h = fopen( $file, 'c+' );
	flock( $h, LOCK_EX );
	$locked[] = $h;
}
list( $c2, $ms2 )  = visit( $srv_a, '198.51.100.20' );
list( $c3, $ms3 )  = visit( $srv_a, '198.51.100.21' ); // A new key: the locked .new counter.
list( $codes, $max ) = visits( $srv_a, '198.51.100.20', 5 );
t( 'a) counter, .new and events.log locked by another process: answered in < 100 ms', 200 === $code && 200 === $c2 && 200 === $c3 && $ms2 < 100 && $ms3 < 100 && $max < 100, sprintf( '%d %d %.1f %.1f %.1f', $c2, $c3, $ms2, $ms3, $max ) );
t( 'a) …and still counted: the 6th page is 429, the 7th a ban (403)', array( 200, 200, 200, 429, 403 ) === $codes, implode( ',', $codes ) );
t( 'a) the ban file holds the expiry (written whole, without a lock)', (int) @file_get_contents( $dir_a . '/bans/' . md5( '198.51.100.20' ) ) > time() );
foreach ( $locked as $h ) {
	flock( $h, LOCK_UN );
	fclose( $h );
}
$timing_a = $max;

/* ---------- b) 50 processes on one counter ---------- */
same_minute( 30 );
$dir_b  = data_dir( 'files-b', array( 'apcu' => false ) );
$worker = $tmp . '/worker.php';
file_put_contents(
	$worker,
	'<?php require ' . var_export( $runtime, true ) . ";\n"
	. '$c = array( "dir" => ' . var_export( $dir_b, true ) . ', "apcu" => false, "new_files" => 0 ); $now = (int) $argv[1]; $all = array(); $over = 0;' . "\n"
	// Each count timed; the ban file is rewritten in between (not timed: a reader checks it is never empty).
	. 'for ( $i = 0; $i < 20; $i++ ) { $t = hrtime( true ); $n = PNCP_Precheck_Runtime::hit( $c, "same", $now ); if ( PNCP_Precheck_Runtime::crossed( $c, "same", $now, $n, 500 ) ) { $over++; } $all[] = ( hrtime( true ) - $t ) / 1e6; PNCP_Precheck_Runtime::ban( ' . var_export( $dir_b, true ) . ', "x", $now + $i + 100 ); }' . "\n"
	. 'echo json_encode( array( $all, $over ) );' . "\n"
);
$reader = $tmp . '/reader.php';
file_put_contents(
	$reader,
	'<?php $f = ' . var_export( $dir_b . '/bans/' . md5( 'x' ), true ) . '; $empty = 0; $reads = 0; $end = microtime( true ) + 2;' . "\n"
	. 'while ( microtime( true ) < $end ) { if ( is_file( $f ) ) { clearstatcache(); $v = @file_get_contents( $f ); if ( false !== $v ) { $reads++; if ( "" === $v || ! ctype_digit( $v ) ) { $empty++; } } } }' . "\n"
	. 'echo json_encode( array( $reads, $empty ) );' . "\n"
);
$now   = time();
$procs = array();
$rp    = proc_open( array( PHP_BINARY, $reader ), array( 1 => array( 'pipe', 'w' ) ), $rpipes );
for ( $i = 0; $i < 50; $i++ ) {
	$procs[] = array( proc_open( array( PHP_BINARY, '-d', 'apc.enabled=0', $worker, (string) $now ), array( 1 => array( 'pipe', 'w' ) ), $pipes ), $pipes );
}
$times = array();
$overs = 0;
foreach ( $procs as $p ) {
	$out    = json_decode( (string) stream_get_contents( $p[1][1] ), true );
	$times  = array_merge( $times, is_array( $out ) ? (array) $out[0] : array( 999 ) );
	$overs += is_array( $out ) ? (int) $out[1] : 0;
	proc_close( $p[0] );
}
sort( $times );
$p99     = $times[ (int) floor( count( $times ) * 0.99 ) ];
$slowest = end( $times );
$rout = json_decode( (string) stream_get_contents( $rpipes[1] ), true );
proc_close( $rp );
clearstatcache();
$total = (int) @filesize( $dir_b . '/hits/' . (int) floor( $now / 60 ) . '/' . md5( 'same' ) );
// No lock is waited for: 99% of the counts take well under a millisecond. The slowest one is preemption with 50
// processes on a few CPUs (and the kernel's own inode lock while its holder waits for a CPU): held to 100 ms
// only when the machine is not overloaded by other work.
$load = sys_getloadavg();
$cpus = max( 1, (int) shell_exec( 'nproc 2>/dev/null' ) );
t( 'b) 50 processes × 20 counts: 99% under 5 ms (nobody waits for a lock)', $p99 < 5, sprintf( 'p99 %.2f ms', $p99 ) );
if ( is_array( $load ) && $load[0] < $cpus ) {
	t( 'b) …and none took 100 ms', $slowest < 100, sprintf( '%.1f ms', $slowest ) );
} else {
	skip( sprintf( 'b) slowest count %.1f ms not checked: load %.1f on %d CPUs', $slowest, is_array( $load ) ? $load[0] : 0, $cpus ) );
}
printf( "timings: 50 processes: p99 %.3f ms, slowest %.1f ms\n", $p99, $slowest );
t( 'b) the count is exact (append-only: tolerance 0 on a local file system)', 1000 === $total, (string) $total );
t( 'b) exactly one process took the count over the limit (one violation per key and minute)', 1 === $overs, (string) $overs );
t( 'b) the ban file rewritten by 50 processes was never read empty or half-written', is_array( $rout ) && $rout[0] > 10 && 0 === $rout[1], wp_json_encode( $rout ) );

/* ---------- c) and d) no cleanup in the request; thousands of old files ---------- */
same_minute( 25 );
$dir_c = data_dir( 'files-c', array( 'apcu' => false ) );
$old   = $minute() - 5;
for ( $m5 = 0; $m5 < 5; $m5++ ) {
	wp_mkdir_p( $dir_c . '/hits/' . ( $old - $m5 ) );
	for ( $i = 0; $i < 1000; $i++ ) {
		file_put_contents( $dir_c . '/hits/' . ( $old - $m5 ) . '/' . md5( $m5 . '-' . $i ), '1' );
	}
}
$srv_c                 = start_server( $dir_c, $files_ini );
list( $code, $ms_c )   = visit( $srv_c, '198.51.100.30' ); // The first request of the minute: creates its folder.
list( $codes, $max_c ) = visits( $srv_c, '198.51.100.31', 3 );
$left                  = count( (array) glob( $dir_c . '/hits/' . $old . '/*' ) );
t( 'c) with the hourly cleanup running: the old minutes stay (no cleanup in the request)', 200 === $code && 1000 === $left, (string) $left );
t( 'd) 5,000 old counter files: the request still < 100 ms', $ms_c < 100 && $max_c < 100, sprintf( '%.1f %.1f', $ms_c, $max_c ) );
// Without WP-Cron (.cleaned older than 2 hours): the sweep at the end of the minute's first request, in budget.
touch( $dir_c . '/.cleaned', time() - 3 * 3600 );
same_minute( 0 );
$wait = 60 - time() % 60;
sleep( $wait + 1 );
list( $code, $ms_s ) = visit( $srv_c, '198.51.100.32' );
$left2               = 0;
foreach ( (array) glob( $dir_c . '/hits/*', GLOB_ONLYDIR ) as $folder ) {
	if ( (int) basename( $folder ) < $minute() - 1 ) {
		$left2 += count( (array) glob( $folder . '/*' ) );
	}
}
t( 'c) without WP-Cron: the sweep removed old files at the end of one request, which still took < 100 ms', 200 === $code && $left2 < 5000 && $ms_s < 100, sprintf( 'left %d, %.1f ms', $left2, $ms_s ) );
$removed = PNCP_Precheck_Runtime::sweep( $dir_c, $minute(), 1 );
t( 'c) sweep(): a budget of 1 ms is kept (it stops, the rest stays for the next one)', $removed < 5000 );
$lock = fopen( $dir_c . '/.sweep.lock', 'c' );
flock( $lock, LOCK_EX );
$t0 = hrtime( true );
$r0 = PNCP_Precheck_Runtime::sweep( $dir_c, $minute(), 25 );
t( 'c) sweep(): another sweep holds the lock: returns at once (LOCK_NB)', 0 === $r0 && ( hrtime( true ) - $t0 ) / 1e6 < 5 );
flock( $lock, LOCK_UN );
fclose( $lock );
PNCP_Precheck_Runtime::cleanup( $dir_c . '/hits', $minute(), 0 );
t( 'c) the hourly cleanup removes everything old and marks .cleaned', array() === array_filter( (array) glob( $dir_c . '/hits/*', GLOB_ONLYDIR ), static function ( $f ) use ( $minute ) { return (int) basename( $f ) < $minute() - 1; } ) && filemtime( $dir_c . '/.cleaned' ) >= time() - 5 );

/* ---------- f) APCu ---------- */
$apcu_ini = '-d apc.enabled=1 -d apc.enable_cli=1 -d opcache.enable_cli=1';
$probe    = trim( (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' ' . $apcu_ini . ' -r ' . escapeshellarg( 'echo function_exists("apcu_enabled") && apcu_enabled() ? "yes" : "no";' ) . ' 2>/dev/null' ) );
if ( 'yes' !== $probe ) {
	skip( 'f) APCu: the extension is not installed' );
} else {
	same_minute( 30 );
	$dir_f  = data_dir( 'apcu-f', array( 'apcu_sapis' => array( 'cli-server' ) ) );
	$log_f  = $has_strace ? $tmp . '/strace-apcu.log' : '';
	$srv_f  = start_server( $dir_f, $apcu_ini, array(), $log_f );
	visit( $srv_f, '198.51.100.40' ); // Warm-up: the configuration read once into APCu.
	usleep( 200000 );
	$offset = $log_f ? (int) @filesize( $log_f ) : 0;
	list( $codes, $max_f ) = visits( $srv_f, '198.51.100.41', 7 );
	list( $c_other )       = visit( $srv_f, '198.51.100.42' );
	t( 'f) APCu: 5 pages, the 6th 429, then the ban (403); another IP 200; all < 100 ms', array( 200, 200, 200, 200, 200, 429, 403 ) === $codes && 200 === $c_other && $max_f < 100, implode( ',', $codes ) . sprintf( ' %.1f ms', $max_f ) );
	$dump = json_decode( (string) visit( $srv_f, '0', '/?__dump=1' )[2], true );
	$dump = is_array( $dump ) ? $dump : array();
	$hitk = 'pncp_pc_' . md5( $dir_f . '|198.51.100.41|' . $minute() );
	$ns   = 'pncp_pc_' . md5( $dir_f ) . '_';
	t( 'f) APCu: the page counter has the name it had before 3.12.9 (unchanged path)', isset( $dump[ $hitk ] ) && (int) $dump[ $hitk ] >= 6, wp_json_encode( array_slice( $dump, 0, 8 ) ) );
	t( 'f) APCu: the ban is in APCu with its expiry', isset( $dump[ $ns . 'b:' . md5( '198.51.100.41' ) ] ) && (int) $dump[ $ns . 'b:' . md5( '198.51.100.41' ) ] > time() );
	$events = array_filter(
		$dump,
		static function ( $v, $k ) use ( $ns ) {
			return 0 === strpos( $k, $ns . 'ev:' ) && is_string( $v ) && false !== strpos( $v, "\t198.51.100.41\t" );
		},
		ARRAY_FILTER_USE_BOTH
	);
	t( 'f) APCu: the events (429, ban, banned) queued in APCu, no events.log', count( $events ) >= 3 && ! file_exists( $dir_f . '/events.log' ), (string) count( $events ) );
	t( 'f) APCu: the configuration is cached for every request (no stat of config.json)', isset( $dump[ PNCP_Precheck_Runtime::cfg_key( $dir_f ) ] ) );
	t( 'f) APCu: which store the check used is noted for WordPress', isset( $dump[ $ns . 'bk:' . $minute() ] ) && 0 === strpos( (string) $dump[ $ns . 'bk:' . $minute() ], 'apcu|' ) );
	if ( $log_f ) {
		usleep( 300000 );
		$touched = traced( $log_f, $offset, $dir_f );
		t( 'f) APCu: 8 requests (count, limit, strike, ban, events) touched no file of the data folder (strace)', array() === $touched, implode( ' | ', array_slice( $touched, 0, 4 ) ) );
	} else {
		skip( 'f) APCu: strace is not available for the syscall check' );
	}
	// The disk gone: the data folder renamed away. Limits and bans still work from APCu.
	rename( $dir_f, $dir_f . '-gone' );
	list( $codes, $max_g ) = visits( $srv_f, '198.51.100.43', 7 );
	list( $c_banned )      = visit( $srv_f, '198.51.100.41' );
	t( 'f) APCu with the data folder gone: limit, ban and the earlier ban still work, < 100 ms', array( 200, 200, 200, 200, 200, 429, 403 ) === $codes && 403 === $c_banned && $max_g < 100, implode( ',', $codes ) . " $c_banned" );
	rename( $dir_f . '-gone', $dir_f );
	// A signed request of the site (self_signed()): its nonce in APCu, used once.
	$url  = $srv_f['url'] . '/signed/';
	$host = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST );
	$sig  = PNCP_Server_Ips::sig_token( 'GET', 'http://' . $host . '/signed/' );
	list( $s1 ) = visit( $srv_f, '198.51.100.41', '/signed/', 'GET', array( 'X-ScrapeLock-Sig' => $sig, 'Host' => $host ) );
	list( $s2 ) = visit( $srv_f, '198.51.100.41', '/signed/', 'GET', array( 'X-ScrapeLock-Sig' => $sig, 'Host' => $host ) );
	t( 'f) APCu: the site\'s signed request passes the ban once; its nonce is kept in APCu (no file)', 200 === $s1 && 403 === $s2 && ! is_dir( $dir_f . '/self' ), "$s1 $s2" );

	/* ---------- g) WP-CLI's ban changes reach the web server's APCu ---------- */
	$c_wp = array(
		'dir'  => $dir_f,
		'apcu' => true,
	);
	file_put_contents( $dir_f . '/ops.log', "ban\t" . md5( '198.51.100.44' ) . "\t" . ( time() + 600 ) . "\nunban\t" . md5( '198.51.100.41' ) . "\t0\n" );
	$ch = curl_init( $srv_f['url'] . '/?pncp_precheck_sync=1' );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => '',
			CURLOPT_TIMEOUT        => 20,
			CURLOPT_HTTPHEADER     => array( 'X-ScrapeLock-Sig: ' . PNCP_Server_Ips::sig_token( 'POST', 'http://' . $host . '/' ), 'Host: ' . $host ),
		)
	);
	$answer = json_decode( (string) curl_exec( $ch ), true );
	curl_close( $ch );
	list( $g1 ) = visit( $srv_f, '198.51.100.44' );
	list( $g2 ) = visit( $srv_f, '198.51.100.41' );
	t( 'g) ops.log (WP-CLI) applied by the signed sync request: the new ban holds, the lifted one is gone', is_array( $answer ) && 2 === (int) $answer['ops'] && 'apcu' === $answer['store'] && 403 === $g1 && 403 !== $g2 && ! file_exists( $dir_f . '/ops.log' ), wp_json_encode( $answer ) . " $g1 $g2" );
	unset( $c_wp );
	stop_server( $srv_f );
}

/* ---------- e) Redis ---------- */
$redis = start_redis();
if ( null === $redis ) {
	skip( 'e) Redis: redis-server or the PHP Redis extension is not installed' );
} else {
	same_minute( 40 );
	$dir_e = data_dir( 'redis-e', array( 'apcu' => false ) );
	$conf  = array(
		'path'   => $redis['sock'],
		'prefix' => 'site1:',
	);
	$log_e = $has_strace ? $tmp . '/strace-redis.log' : '';
	$srv_e = start_server( $dir_e, $files_ini . ' -d opcache.enable_cli=1', $conf, $log_e );
	$cli   = redis_client( $redis['sock'] );
	visit( $srv_e, '198.51.100.50' ); // Warm-up: the configuration read once into Redis.
	usleep( 200000 );
	$offset = $log_e ? (int) @filesize( $log_e ) : 0;
	list( $codes, $max_e ) = visits( $srv_e, '198.51.100.51', 7 );
	$ns = 'site1:pncp:pc:' . substr( md5( $dir_e ), 0, 12 ) . ':';
	t( 'e) Redis: 5 pages, the 6th 429, then the ban (403); all < 100 ms', array( 200, 200, 200, 200, 200, 429, 403 ) === $codes && $max_e < 100, implode( ',', $codes ) . sprintf( ' %.1f ms', $max_e ) );
	t( 'e) Redis: counter (with its expiry), ban, events and configuration are in Redis, with the object cache\'s prefix', (int) $cli->get( $ns . 'h:' . md5( '198.51.100.51' ) . ':' . $minute() ) >= 6 && $cli->ttl( $ns . 'h:' . md5( '198.51.100.51' ) . ':' . $minute() ) > 0 && (int) $cli->get( $ns . 'b:' . md5( '198.51.100.51' ) ) > time() && $cli->lLen( $ns . 'ev' ) >= 3 && '' !== (string) $cli->get( $ns . 'cfg' ) );
	t( 'e) Redis: no events.log, no ban, strike or counter file', ! file_exists( $dir_e . '/events.log' ) && ! is_dir( $dir_e . '/bans' ) && ! is_dir( $dir_e . '/strikes' ) && ! is_dir( $dir_e . '/hits' ) );
	if ( $log_e ) {
		usleep( 300000 );
		$touched = traced( $log_e, $offset, $dir_e );
		t( 'e) Redis: 7 requests touched no file of the data folder (strace)', array() === $touched, implode( ' | ', array_slice( $touched, 0, 4 ) ) );
	} else {
		skip( 'e) Redis: strace is not available for the syscall check' );
	}
	// The hourly copy (PNCP_Precheck::sync_store()): the ban reaches the file, for the time without Redis.
	$c_e    = array(
		'dir'   => $dir_e,
		'apcu'  => false,
		'redis' => $conf,
	);
	$copied = PNCP_Precheck_Runtime::sync_bans( $c_e, time() );
	t( 'e) the hourly copy writes the ban from Redis to its file', $copied >= 1 && (int) @file_get_contents( $dir_e . '/bans/' . md5( '198.51.100.51' ) ) > time() );
	// Redis stopped: the check falls back to the files at once; the copied ban still holds.
	stop_redis( $redis );
	list( $b1, $ms_b1 )  = visit( $srv_e, '198.51.100.51' );
	list( $codes, $max_d ) = visits( $srv_e, '198.51.100.52', 7 );
	t( 'e) Redis stopped: answered from the files in < 150 ms, the ban holds, the limit and a new ban work', 403 === $b1 && $ms_b1 < 150 && array( 200, 200, 200, 200, 200, 429, 403 ) === $codes && $max_d < 150, "$b1 " . implode( ',', $codes ) . sprintf( ' %.1f %.1f', $ms_b1, $max_d ) );
	t( 'e) Redis stopped: the events go to events.log', false !== strpos( (string) @file_get_contents( $dir_e . '/events.log' ), "\t198.51.100.52\t" ) );
	// Redis back, empty (restarted): the first request copies the files' bans in (sync_later()).
	$redis = start_redis();
	$cli   = redis_client( $redis['sock'] );
	visit( $srv_e, '198.51.100.53' );
	usleep( 300000 );
	list( $b2 ) = visit( $srv_e, '198.51.100.52' );
	t( 'e) Redis back without its data: the bans of the files are copied in, and hold', (int) $cli->get( $ns . 'b:' . md5( '198.51.100.52' ) ) > time() && '' !== (string) $cli->get( $ns . 'sync' ) && 403 === $b2, (string) $b2 );
	// A Redis that does not answer (a socket nobody reads): connect and read time out within REDIS_TIMEOUT.
	$dead  = $tmp . '/dead.sock';
	$block = stream_socket_server( 'unix://' . $dead );
	$dir_h = data_dir( 'redis-h', array( 'apcu' => false ) );
	$srv_h = start_server( $dir_h, $files_ini, array( 'path' => $dead ) );
	list( $h1, $ms_h ) = visit( $srv_h, '198.51.100.54' );
	t( 'e) a Redis that accepts but never answers: the request waits at most ~2 × 50 ms, then the files', 200 === $h1 && $ms_h < 200, sprintf( '%.1f ms', $ms_h ) );
	fclose( $block );
	stop_server( $srv_h );
	stop_server( $srv_e );

	/* ---------- g) WordPress: the connection in wp-config.php, the store from WordPress ---------- */
	$filter = static function () use ( $redis ) {
		return array(
			'path'     => $redis['sock'],
			'password' => 'S3cret-pass',
			'prefix'   => 'site1:',
		);
	};
	add_filter( 'pncp_precheck_redis', $filter );
	$settings = PNCP_Precheck::redis_settings();
	$block    = PNCP_Precheck::block();
	t( 'g) the line of wp-config.php passes the Redis connection, the password masked', false !== strpos( $block, "'path' => " . var_export( $redis['sock'], true ) ) && false === strpos( $block, 'S3cret-pass' ) && isset( $settings['auth'] ) && 'S3cret-pass' === PNCP_Precheck_Runtime::redis_password( $settings + array( 'sk' => $sig_key ) ) );
	remove_filter( 'pncp_precheck_redis', $filter );
	$open = static function () use ( $redis ) {
		return array(
			'path'   => $redis['sock'],
			'prefix' => 'site1:',
		);
	};
	add_filter( 'pncp_precheck_redis', $open );
	$wpc = PNCP_Precheck::runtime_config();
	t( 'g) WordPress uses the same store from WP-CLI (Redis; APCu is never WP-CLI\'s)', 'redis' === PNCP_Precheck_Runtime::backend( $wpc ) && 'redis' === PNCP_Precheck_Runtime::store( $wpc ), PNCP_Precheck_Runtime::backend( $wpc ) );
	remove_filter( 'pncp_precheck_redis', $open );
	add_filter( 'pncp_precheck_redis', '__return_false' );
	t( 'g) off (filter false): no Redis in the line', array() === PNCP_Precheck::redis_settings() && false === strpos( PNCP_Precheck::block(), "'path'" ) );
	remove_filter( 'pncp_precheck_redis', '__return_false' );
	t( 'g) auto without a Redis object cache: off (the line exactly as before 3.12.9)', wp_using_ext_object_cache() || array() === PNCP_Precheck::redis_settings() );
	// Events queued in Redis are drained once.
	$c_q = array(
		'dir'   => $dir_e,
		'apcu'  => false,
		'redis' => $conf + array( 'timeout' => 0.05 ), // A new connection: the one above went with the first Redis.
	);
	PNCP_Precheck_Runtime::mem_drain( $c_q ); // The events of the requests above.
	PNCP_Precheck_Runtime::event( $c_q, 429, 'rate_page', '198.51.100.60' );
	$lines = PNCP_Precheck_Runtime::mem_drain( $c_q );
	t( 'g) events queued in Redis are taken out once (for the hourly import)', 1 === count( $lines ) && false !== strpos( $lines[0], "\t198.51.100.60\t" ) && array() === PNCP_Precheck_Runtime::mem_drain( $c_q ) );
}

printf( "timings: lock held %.1f ms max\n", $timing_a );
echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
