<?php
/**
 * ScrapeLock 3.12.9 — a guest's request with APCu, and with a Redis object cache (phpredis, no APCu), on Nginx +
 * PHP-FPM, as on a live server: with the pre-cache check and the early check on, ScrapeLock makes no system call
 * on its data folder (uploads/scrapelock: strace of the PHP-FPM worker) and no database query of its own
 * (lib/probe-3129.php), for page views of new and known visitors, a visitor over the limit (429, then the ban:
 * 403) and the banned visitor. A run without either store is the control (the files and the database are used
 * there, as before).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3129_strace.php
 *
 * Its own Nginx and PHP-FPM on a free port (as the user running it; root or not), redis-server on a Unix socket
 * of its own. SKIP without php-fpm, nginx or a working strace (APCu / Redis parts: without the extension or
 * redis-server). Only on a test WordPress: settings, wp-config.php, the early check's file and the drop-in are put
 * back at the end.
 */

$wp_dir = rtrim( (string) getenv( 'WP_DIR' ), '/' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
$content = $wp_dir . '/wp-content';
$oc      = $content . '/object-cache.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( '' !== (string) $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** The first of these programs found in PATH, or ''. */
function find_bin( $names ) {
	foreach ( $names as $name ) {
		$path = trim( (string) shell_exec( 'command -v ' . escapeshellarg( $name ) . ' 2>/dev/null' ) );
		if ( '' !== $path ) {
			return $path;
		}
	}
	return '';
}

$fpm    = find_bin( array( 'php-fpm' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION, 'php-fpm' ) );
$nginx  = find_bin( array( 'nginx' ) );
$strace = find_bin( array( 'strace' ) );
if ( '' === $fpm || '' === $nginx || '' === $strace ) {
	echo 'SKIP php-fpm, nginx or strace is not installed' . "\n";
	exit( 0 );
}
if ( 0 !== (int) shell_exec( escapeshellarg( $strace ) . ' -f -qq -o /dev/null true >/dev/null 2>&1; echo $?' ) ) {
	echo "SKIP strace cannot trace here (ptrace not allowed)\n";
	exit( 0 );
}
if ( file_exists( $oc ) ) {
	echo "SKIP an object cache drop-in is installed already (the test installs its own)\n";
	exit( 0 );
}
$root = function_exists( 'posix_geteuid' ) && 0 === posix_geteuid();
$tmp  = sys_get_temp_dir() . '/pncp-t3129s-' . getmypid();
@mkdir( $tmp . '/logs', 0755, true );
@mkdir( $tmp . '/run', 0755, true );
chmod( $tmp, 0755 );

/**
 * PHP code in a WordPress loaded as a scheduled event loads it (DOING_CRON), in its own process: what it returns.
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
	$out = (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $file ) . ' 2>&1' );
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

function free_port() {
	$s    = stream_socket_server( 'tcp://127.0.0.1:0' );
	$name = stream_socket_get_name( $s, false );
	fclose( $s );
	return (int) substr( (string) strrchr( (string) $name, ':' ), 1 );
}

/* ---------- Setup: the live-like settings (pre-cache check, early check, limits, a ban on the first violation) ---------- */
$saved = wp_run(
	'$post = get_posts( array( "numberposts" => 1, "post_status" => "publish" ) );
	return array(
		"settings" => base64_encode( serialize( get_option( PNCP_OPTION ) ) ),
		"config"   => base64_encode( (string) file_get_contents( PNCP_Precheck::config_path() ) ),
		"wpconfig" => PNCP_Precheck::config_path(),
		"early"    => PNCP_Early::installed(),
		"path"     => $post ? (string) wp_parse_url( get_permalink( $post[0] ), PHP_URL_PATH ) : "/",
		"data"     => PNCP_Precheck::dir(),
		"host"     => (string) wp_parse_url( home_url( "/" ), PHP_URL_HOST ) . ( wp_parse_url( home_url( "/" ), PHP_URL_PORT ) ? ":" . wp_parse_url( home_url( "/" ), PHP_URL_PORT ) : "" ),
	);'
);
if ( ! is_array( $saved ) || '' === (string) $saved['data'] ) {
	echo "FAIL WordPress could not be loaded\n";
	exit( 1 );
}
$probe = $content . '/mu-plugins/0-pncp-probe-3129.php';
@mkdir( $content . '/mu-plugins', 0755, true );
copy( __DIR__ . '/lib/probe-3129.php', $probe );
$procs   = array();
$redis   = null;
$restore = static function () use ( $saved, $probe, $oc, $content, $tmp, &$procs, &$redis ) {
	foreach ( $procs as $p ) {
		stop_stack( $p );
	}
	if ( $redis ) {
		$pid = (int) @file_get_contents( $tmp . '/run/redis.pid' );
		$pid > 0 && posix_kill( $pid, 15 );
	}
	@unlink( $oc );
	@unlink( $probe );
	wp_run(
		'update_option( PNCP_OPTION, unserialize( base64_decode( ' . var_export( $saved['settings'], true ) . ' ) ) );
		PNCP_Options::flush();
		PNCP_Precheck::sync();
		' . ( $saved['early'] ? '' : 'PNCP_Early::remove();' ) . '
		return true;'
	);
	file_put_contents( $saved['wpconfig'], base64_decode( $saved['config'] ) );
	exec( 'rm -rf ' . escapeshellarg( $tmp ) . ' ' . escapeshellarg( $content . '/pncp-probe' ) );
};
register_shutdown_function( $restore );

/** Puts the settings and the store in place, as an admin page after an update would (line in wp-config.php). */
function prepare() {
	return wp_run(
		'$s = array_merge(
			PNCP_Options::stored(),
			array(
				"enabled" => 1, "monitor_mode" => 0, "monitor_until" => 0, "precheck" => 1, "early_mode" => 1,
				"rate_limit" => 20, "ban_strikes" => 1, "ban_minutes" => 5, "ip_header" => "x_real_ip",
				"block_bots" => 1, "require_browser_headers" => 0, "human_check" => 0, "allow_ips" => "", "block_ips" => "",
			)
		);
		update_option( PNCP_OPTION, $s );
		PNCP_Options::flush();
		PNCP_Precheck::sync();
		PNCP_Early::sync();
		PNCP_Log::unban_all();
		foreach ( array( "hits", "strikes", "bans", "breaker", "self", "probes" ) as $f ) {
			if ( is_dir( PNCP_Precheck::dir() . "/" . $f ) ) {
				exec( "rm -rf " . escapeshellarg( PNCP_Precheck::dir() . "/" . $f ) );
			}
		}
		return array( "line" => PNCP_Precheck::in_config(), "early" => PNCP_Early::installed(), "block" => PNCP_Precheck::block() );'
	);
}

/**
 * Starts PHP-FPM (one worker, under strace) and Nginx on a free port: [port, procs...].
 *
 * @param bool $apcu APCu on in PHP-FPM.
 * @return array<string, mixed>
 */
function start_stack( $apcu, $label ) {
	global $fpm, $nginx, $strace, $tmp, $wp_dir, $root;
	$port = free_port();
	$pool = 'pncpst' . getmypid() . $label;
	$conf = "[global]\npid = $tmp/run/fpm-$label.pid\nerror_log = $tmp/logs/fpm-$label.log\ndaemonize = no\n[$pool]\n"
		. ( $root ? "user = root\ngroup = root\n" : '' )
		. "listen = $tmp/run/fpm-$label.sock\nlisten.mode = 0666\npm = static\npm.max_children = 1\ncatch_workers_output = yes\n"
		. 'php_admin_value[apc.enabled] = ' . ( $apcu ? 1 : 0 ) . "\nphp_admin_value[apc.shm_size] = 32M\nphp_admin_value[error_log] = $tmp/logs/php-$label.log\nphp_admin_flag[log_errors] = on\n";
	file_put_contents( "$tmp/fpm-$label.conf", $conf );
	$log  = "$tmp/strace-$label.txt";
	$fpmp = proc_open(
		escapeshellarg( $strace ) . ' -f -qq -y -e trace=%file,%desc -o ' . escapeshellarg( $log ) . ' ' . escapeshellarg( $fpm ) . ( $root ? ' -R' : '' ) . ' -F -y ' . escapeshellarg( "$tmp/fpm-$label.conf" ),
		array( array( 'file', '/dev/null', 'r' ), array( 'file', "$tmp/logs/fpm-$label.out", 'w' ), array( 'file', "$tmp/logs/fpm-$label.out", 'a' ) ),
		$pipes
	);
	$fp   = 'include /etc/nginx/fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass unix:' . "$tmp/run/fpm-$label.sock;";
	$ngx  = ( $root ? "user root;\n" : '' ) . "worker_processes 1;\ndaemon off;\npid $tmp/run/nginx-$label.pid;\nerror_log $tmp/logs/nginx-$label.log warn;\nevents { worker_connections 64; }\nhttp {\n"
		. ( is_readable( '/etc/nginx/fastcgi_params' ) ? '' : '' )
		. "access_log off;\nclient_body_temp_path $tmp/run/body; fastcgi_temp_path $tmp/run/fcgi; proxy_temp_path $tmp/run/proxy; uwsgi_temp_path $tmp/run/uwsgi; scgi_temp_path $tmp/run/scgi;\n"
		. "server { listen 127.0.0.1:$port; root $wp_dir; index index.php;\n location / { try_files \$uri \$uri/ /index.php?\$args; }\n location ~ \\.php\$ { $fp } }\n}\n";
	file_put_contents( "$tmp/nginx-$label.conf", $ngx );
	$ngxp = proc_open(
		escapeshellarg( $nginx ) . ' -e ' . escapeshellarg( "$tmp/logs/nginx-$label.log" ) . ' -c ' . escapeshellarg( "$tmp/nginx-$label.conf" ),
		array( array( 'file', '/dev/null', 'r' ), array( 'file', "$tmp/logs/nginx-$label.out", 'w' ), array( 'file', "$tmp/logs/nginx-$label.out", 'a' ) ),
		$pipes
	);
	$stack = array(
		'port'  => $port,
		'pool'  => $pool,
		'log'   => $log,
		'procs' => array( $fpmp, $ngxp ),
		'label' => $label,
	);
	for ( $i = 0; $i < 100; $i++ ) {
		usleep( 100000 );
		$s = @fsockopen( '127.0.0.1', $port, $errno, $errstr, 0.1 );
		if ( $s && file_exists( "$tmp/run/fpm-$label.sock" ) ) {
			fclose( $s );
			return $stack;
		}
	}
	$stack['port'] = 0;
	return $stack;
}

function stop_stack( $stack ) {
	global $tmp;
	foreach ( array( 'nginx', 'fpm' ) as $name ) {
		$pid = (int) @file_get_contents( "$tmp/run/$name-{$stack['label']}.pid" );
		if ( $pid > 0 ) {
			posix_kill( $pid, 15 );
		}
	}
	usleep( 300000 );
	foreach ( $stack['procs'] as $p ) {
		if ( is_resource( $p ) ) {
			$st = proc_get_status( $p );
			if ( ! empty( $st['running'] ) ) {
				proc_terminate( $p, 9 );
			}
			proc_close( $p );
		}
	}
}

/** The PIDs of the pool's worker. */
function worker_pids( $stack ) {
	$out = array();
	foreach ( explode( "\n", (string) shell_exec( 'ps -eo pid=,args= 2>/dev/null' ) ) as $line ) {
		if ( preg_match( '/^\s*(\d+)\s+php-fpm: pool ' . preg_quote( $stack['pool'], '/' ) . '\s*$/', $line, $m ) ) {
			$out[] = (int) $m[1];
		}
	}
	return $out;
}

/**
 * The one-minute scheduled event in this PHP-FPM (PNCP_Defer::flush()), through wp-cron.php signed as PNCP_Defer
 * asks for it: no wait for WP-Cron's lock, which the test server may hold.
 */
function flush_in_fpm( $stack ) {
	$sig = wp_run( '$m = new ReflectionMethod( "PNCP_Defer", "signature" ); $m->setAccessible( true ); return $m->invoke( null, (int) floor( time() / MINUTE_IN_SECONDS ) );' );
	visit( $stack, '/wp-cron.php?pncp_flush=' . rawurlencode( (string) $sig ), '127.0.0.1' );
	sleep( 1 );
}

/** One guest request through Nginx with the probe on: [status, probe record]. */
function visit( $stack, $path, $ip ) {
	global $content, $saved;
	static $n = 0;
	$id = 's' . getmypid() . '-' . ( ++$n );
	$ch = curl_init( 'http://127.0.0.1:' . $stack['port'] . $path );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 30,
			CURLOPT_HTTPHEADER     => array(
				'Host: ' . $saved['host'],
				'X-Real-IP: ' . $ip,
				'X-Test-IP: ' . $ip,
				'X-PNCP-Probe: ' . $id,
				'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36',
				'Accept: text/html,application/xhtml+xml',
				'Accept-Language: en-US,en;q=0.9',
			),
		)
	);
	curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	$file = $content . '/pncp-probe/' . $id . '.json';
	$rec  = is_file( $file ) ? json_decode( (string) file_get_contents( $file ), true ) : null;
	@unlink( $file );
	return array( $code, is_array( $rec ) ? $rec : null );
}

/**
 * Warm-up, then the measured requests: [codes, ScrapeLock's queries, syscalls on the data folder, probe records].
 */
function measure( $stack, $tag ) {
	global $saved;
	$path = $saved['path'] . ( false === strpos( $saved['path'], '?' ) ? '?' : '&' );
	for ( $i = 1; $i <= 8; $i++ ) {
		visit( $stack, $path . 'pncp_w=' . $i, '198.18.' . $tag . '.' . $i ); // opcache, object cache, the check's copy.
	}
	// As on a live site, the one-minute scheduled event has run (in PHP-FPM, whose APCu it fills): it keeps every
	// ban in effect in the store, so a visitor's request asks the database for none (PNCP_Log::keep_bans()).
	flush_in_fpm( $stack );
	clearstatcache();
	$offset  = (int) @filesize( $stack['log'] );
	$codes   = array();
	$queries = array();
	$records = 0;
	for ( $i = 1; $i <= 30; $i++ ) {
		$ip = 0 === $i % 5 ? '198.19.' . $tag . '.250' : '198.19.' . $tag . '.' . $i; // New visitors, one known one.
		list( $code, $rec ) = visit( $stack, $path . 'pncp_v=' . $i, $ip );
		$codes['views'][] = $code;
		if ( $rec ) {
			++$records;
			$queries = array_merge( $queries, (array) $rec['db'] );
		}
	}
	for ( $i = 1; $i <= 24; $i++ ) {
		list( $code, $rec ) = visit( $stack, $path . 'pncp_r=' . $i, '198.20.' . $tag . '.7' ); // Over the limit of 20.
		$codes['over'][] = $code;
		if ( $rec ) {
			++$records;
			$queries = array_merge( $queries, (array) $rec['db'] );
		}
	}
	usleep( 500000 );
	clearstatcache();
	$pids = worker_pids( $stack );
	$ops  = array();
	foreach ( explode( "\n", (string) file_get_contents( $stack['log'], false, null, $offset ) ) as $line ) {
		if ( preg_match( '/^(\d+)\s/', $line, $m ) && in_array( (int) $m[1], $pids, true ) && false !== strpos( $line, $saved['data'] ) ) {
			$ops[] = $line;
		}
	}
	return array( $codes, $queries, $ops, $records, $pids );
}

$apcu_ok  = false !== strpos( (string) shell_exec( escapeshellarg( $fpm ) . ' -m 2>/dev/null' ), 'apcu' );
$redis_ok = class_exists( 'Redis' ) && '' !== find_bin( array( 'redis-server' ) );
$tag      = 0;
foreach ( array( 'apcu', 'redis', 'files' ) as $mode ) {
	++$tag;
	if ( 'apcu' === $mode && ! $apcu_ok ) {
		echo "SKIP APCu: the extension is not loaded in PHP-FPM\n";
		continue;
	}
	if ( 'redis' === $mode ) {
		if ( ! $redis_ok ) {
			echo "SKIP Redis: phpredis or redis-server is not installed\n";
			continue;
		}
		$sock = $tmp . '/run/redis.sock';
		exec( 'redis-server --port 0 --unixsocket ' . escapeshellarg( $sock ) . ' --unixsocketperm 777 --save "" --appendonly no --daemonize yes --pidfile ' . escapeshellarg( $tmp . '/run/redis.pid' ) . ' --dir ' . escapeshellarg( $tmp . '/run' ) . ' >/dev/null 2>&1' );
		for ( $i = 0; $i < 50 && ! file_exists( $sock ); $i++ ) {
			usleep( 100000 );
		}
		$redis = true;
		file_put_contents(
			$oc,
			"<?php\n// t_3129_strace.php: removed at the end of the test.\ndefined( 'WP_REDIS_SCHEME' ) || define( 'WP_REDIS_SCHEME', 'unix' );\ndefined( 'WP_REDIS_PATH' ) || define( 'WP_REDIS_PATH', " . var_export( $sock, true ) . " );\ndefined( 'WP_CACHE_KEY_SALT' ) || define( 'WP_CACHE_KEY_SALT', 't3129s:' );\nrequire " . var_export( __DIR__ . '/lib/object-cache-redis.php', true ) . ";\n"
		);
	} else {
		@unlink( $oc );
	}
	$ready = prepare();
	t( "$mode: the pre-cache check's line in wp-config.php and the early check are in place" . ( 'redis' === $mode ? ', the line with the Redis socket' : '' ), is_array( $ready ) && $ready['line'] && $ready['early'] && ( 'redis' !== $mode || false !== strpos( (string) $ready['block'], "'path' => " ) ), json_encode( $ready ) );
	$stack   = start_stack( 'apcu' === $mode, $mode );
	$procs[] = $stack;
	if ( ! $stack['port'] ) {
		t( "$mode: Nginx and PHP-FPM start", false, (string) @file_get_contents( "$tmp/logs/fpm-$mode.out" ) . (string) @file_get_contents( "$tmp/logs/nginx-$mode.log" ) );
		continue;
	}
	list( $codes, $queries, $ops, $records, $pids ) = measure( $stack, $tag );
	$views = array_count_values( $codes['views'] );
	$over  = $codes['over'];
	t( "$mode: 30 page views answered 200 (with a known visitor among them)", array( 200 => 30 ) === $views, json_encode( $views ) );
	t( "$mode: over the limit 20 pages, then 429 and the ban (403)", array_fill( 0, 20, 200 ) === array_slice( $over, 0, 20 ) && 429 === $over[20] && 403 === $over[21] && 403 === $over[23], implode( ',', $over ) );
	t( "$mode: the probe saw WordPress's requests ($records)", $records >= 50 && $pids, (string) $records );
	if ( 'files' === $mode ) {
		// The control: without APCu or an object cache the files of the data folder and the database are used.
		t( 'files (control): strace sees the data folder in the same requests', count( $ops ) > 50, (string) count( $ops ) );
		t( 'files (control): the probe sees ScrapeLock\'s queries', count( $queries ) > 0, (string) count( $queries ) );
	} else {
		t( "$mode: no system call on ScrapeLock's data folder (strace of the PHP-FPM worker, 54 requests)", array() === $ops, count( $ops ) . ': ' . implode( ' | ', array_slice( $ops, 0, 3 ) ) );
		t( "$mode: no database query of ScrapeLock (54 requests)", array() === $queries, count( $queries ) . ': ' . implode( ' | ', array_slice( $queries, 0, 3 ) ) );
	}
	if ( 'apcu' === $mode ) {
		// A minute later (the copies of the first requests have ended; the one-minute event ran in between, as
		// with WP-Cron on a live site): still no query of ScrapeLock.
		sleep( 62 );
		flush_in_fpm( $stack );
		$later = array();
		for ( $i = 1; $i <= 10; $i++ ) {
			list( , $rec ) = visit( $stack, $saved['path'] . '?pncp_l=' . $i, '198.21.' . $tag . '.' . $i );
			$later         = array_merge( $later, $rec ? (array) $rec['db'] : array( 'no probe record' ) );
		}
		t( 'apcu: a minute later, after the scheduled event, still no database query of ScrapeLock', array() === $later, count( $later ) . ': ' . implode( ' | ', array_slice( $later, 0, 3 ) ) );
	}
	$php_log = (string) @file_get_contents( "$tmp/logs/php-$mode.log" );
	t( "$mode: no PHP warning, notice or error", ! preg_match( '/PHP (Warning|Notice|Deprecated|Fatal)/', $php_log ), substr( $php_log, 0, 400 ) );
	stop_stack( $stack );
	$procs = array();
}

echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
