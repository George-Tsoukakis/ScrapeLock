<?php
/**
 * ScrapeLock 3.13.0 — WP-CLI as root (--allow-root) never takes the site down.
 *
 * In 3.12.9 a settings change made as root rewrote wp-config.php (temp file + rename): it became root:root 0640,
 * PHP-FPM (the site's user) failed with "Failed opening required wp-config.php" and the site answered 500. The
 * same happened to mu-plugins/scrapelock-early.php and to uploads/scrapelock/.
 *
 *   WP_DIR=/path/to/wordpress WP_CLI="php …/boot-fs.php" php t_3130_root_wpcli.php
 *
 * As root, a WordPress site of its own (a copy of WP_DIR's WordPress and SQLite drop-in, the plugin copied from
 * this checkout) in a folder owned by the web server's user (www-data, else nobody), wp-config.php 0640 of that
 * user; its own PHP-FPM (pool of that user) and Nginx on a free port. Then, as root with --allow-root, every
 * command that makes ScrapeLock write files: precheck and early_mode on through "wp scrapelock settings set",
 * "precheck sync" and "cleanup", "breaker reset", both off and on again through "wp option update pncp_settings",
 * "wp plugin deactivate" / "activate scrapelock". After each one: a guest gets 200 (not 500 "Failed opening
 * required"), wp-config.php keeps its owner, group and mode, the early check's mu-plugin and every file and
 * folder under uploads/scrapelock belong to the site's user, no .tmp file is left, and the command printed
 * ScrapeLock's root warning (not "plugin activate": ScrapeLock is not loaded before that command runs). The
 * warning is not printed with --quiet, with --format=json, or when WP-CLI runs as the site's user.
 *
 * SKIP when not root, without nginx, php-fpm, WP_CLI or the SQLite drop-in in WP_DIR. WP_DIR is only read.
 */

$wp_dir = rtrim( (string) getenv( 'WP_DIR' ), '/' );
$cli    = trim( (string) getenv( 'WP_CLI' ) );
if ( ! $wp_dir ) {
	fwrite( STDERR, "WP_DIR is required\n" );
	exit( 2 );
}

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

if ( ! function_exists( 'posix_geteuid' ) || 0 !== posix_geteuid() ) {
	echo "SKIP not root (the test runs WP-CLI as root against a site of another user)\n";
	exit( 0 );
}
$fpm   = find_bin( array( 'php-fpm' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION, 'php-fpm' ) );
$nginx = find_bin( array( 'nginx' ) );
if ( '' === $fpm || '' === $nginx ) {
	echo "SKIP php-fpm or nginx is not installed\n";
	exit( 0 );
}
if ( '' === $cli ) {
	echo "SKIP WP_CLI is not set\n";
	exit( 0 );
}
if ( ! is_file( $wp_dir . '/wp-content/db.php' ) || ! is_file( $wp_dir . '/wp-settings.php' ) ) {
	echo "SKIP the test site is built from WP_DIR's WordPress and its SQLite drop-in (wp-content/db.php)\n";
	exit( 0 );
}
$pw = posix_getpwnam( 'www-data' );
if ( ! $pw ) {
	$pw = posix_getpwnam( 'nobody' );
}
if ( ! $pw || 0 === (int) $pw['uid'] ) {
	echo "SKIP no www-data or nobody user\n";
	exit( 0 );
}
$user  = (string) $pw['name'];
$uid   = (int) $pw['uid'];
$gid   = (int) $pw['gid'];
$gr    = posix_getgrgid( $gid );
$group = $gr ? (string) $gr['name'] : '#' . $gid;

// WP-CLI without its own --path / --allow-root: this test chooses them.
$cli  = trim( (string) preg_replace( '/\s--(?:path=\S+|allow-root)(?=\s|$)/', '', ' ' . $cli ) );
$tmp  = ( is_dir( '/tmp' ) ? '/tmp' : sys_get_temp_dir() ) . '/pncp-t3130r-' . getmypid();
$site = $tmp . '/site';
foreach ( array( $tmp, $site, "$tmp/run", "$tmp/logs", "$tmp/home" ) as $d ) {
	@mkdir( $d, 0755, true );
	chmod( $d, 0755 );
}

/**
 * WP-CLI on the test site: [exit code, stdout, stderr]. As root with --allow-root, or as the site's user.
 *
 * @param string[] $args    Arguments.
 * @param bool     $as_root As root.
 * @return array{0:int,1:string,2:string}
 */
function wp( $args, $as_root = true ) {
	global $cli, $site, $user, $tmp;
	$cmd = $cli . ' --path=' . escapeshellarg( $site ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) );
	$cmd = $as_root ? $cmd . ' --allow-root' : 'runuser -u ' . escapeshellarg( $user ) . ' -- env HOME=' . escapeshellarg( "$tmp/home" ) . ' ' . $cmd;
	$p   = proc_open( $cmd, array( array( 'file', '/dev/null', 'r' ), array( 'pipe', 'w' ), array( 'pipe', 'w' ) ), $pipes, null, array( 'HOME' => $as_root ? (string) getenv( 'HOME' ) : "$tmp/home", 'PATH' => (string) getenv( 'PATH' ) ) );
	$out = (string) stream_get_contents( $pipes[1] );
	$err = (string) stream_get_contents( $pipes[2] );
	fclose( $pipes[1] );
	fclose( $pipes[2] );
	return array( proc_close( $p ), $out, $err );
}

function free_port() {
	$s    = stream_socket_server( 'tcp://127.0.0.1:0' );
	$name = stream_socket_get_name( $s, false );
	fclose( $s );
	return (int) substr( (string) strrchr( (string) $name, ':' ), 1 );
}

$port  = free_port();
$procs = array();
register_shutdown_function(
	static function () use ( $tmp, &$procs ) {
		foreach ( array( 'nginx', 'fpm' ) as $name ) {
			$pid = (int) @file_get_contents( "$tmp/run/$name.pid" );
			$pid > 0 && posix_kill( $pid, 15 );
		}
		usleep( 300000 );
		foreach ( $procs as $p ) {
			if ( is_resource( $p ) ) {
				$st = proc_get_status( $p );
				! empty( $st['running'] ) && proc_terminate( $p, 9 );
				proc_close( $p );
			}
		}
		exec( 'rm -rf ' . escapeshellarg( $tmp ) );
	}
);

/* ---------- The site: WordPress of WP_DIR, SQLite, the plugin of this checkout, all owned by the site's user ---------- */
exec( 'cd ' . escapeshellarg( $wp_dir ) . ' && tar --exclude=./wp-config.php --exclude=./wp-content --exclude=./.git -cf - . | tar -C ' . escapeshellarg( $site ) . ' -xf - 2>&1', $o, $rc1 );
@mkdir( "$site/wp-content/plugins", 0755, true );
@mkdir( "$site/wp-content/mu-plugins", 0755, true );
copy( "$wp_dir/wp-content/db.php", "$site/wp-content/db.php" );
exec( 'cp -a ' . escapeshellarg( "$wp_dir/wp-content/themes" ) . ' ' . escapeshellarg( "$site/wp-content/themes" ) . ' 2>&1', $o, $rc2 );
@mkdir( "$site/wp-content/plugins/scrapelock", 0755, true );
@mkdir( "$tmp/wlog", 0755 );
exec( 'cd ' . escapeshellarg( dirname( __DIR__ ) ) . ' && tar --exclude=./.git --exclude=./tests --exclude="./*.zip" -cf - . | tar -C ' . escapeshellarg( "$site/wp-content/plugins/scrapelock" ) . ' -xf - 2>&1', $o, $rc3 );
$url   = 'http://127.0.0.1:' . $port;
$setup = array(
	array( 'config', 'create', '--dbname=wp', '--dbuser=x', '--dbpass=x', '--skip-check' ),
	array( 'config', 'set', 'WP_DEBUG', 'true', '--raw' ),
	array( 'config', 'set', 'WP_DEBUG_DISPLAY', 'false', '--raw' ),
	array( 'config', 'set', 'WP_DEBUG_LOG', "$tmp/wlog/debug.log" ),
	array( 'config', 'set', 'WP_HTTP_BLOCK_EXTERNAL', 'true', '--raw' ),
	array( 'config', 'set', 'DISABLE_WP_CRON', 'true', '--raw' ),
	array( 'core', 'install', '--url=' . $url, '--title=T3130', '--admin_user=admin', '--admin_password=admin', '--admin_email=admin@example.com', '--skip-email' ),
	array( 'rewrite', 'structure', '/%postname%/' ),
	array( 'post', 'create', '--post_status=publish', '--post_title=T3130', '--post_content=Test content for the root WP-CLI test.' ),
	array( 'plugin', 'activate', 'scrapelock' ),
	array( 'scrapelock', 'settings', 'set', 'monitor_mode', '0', '--yes' ),
);
$setup_ok = 0 === $rc1 + $rc2 + $rc3;
$setup_er = '';
foreach ( $setup as $args ) {
	list( $rc, $out, $err ) = wp( $args );
	if ( 0 !== $rc ) {
		$setup_ok  = false;
		$setup_er .= implode( ' ', $args ) . ': ' . trim( $out . ' ' . $err ) . ' | ';
	}
}
// The site belongs to its user, as a live site does; wp-config.php readable by that user only (and its group).
exec( 'chown -R ' . $uid . ':' . $gid . ' ' . escapeshellarg( $site ) . ' ' . escapeshellarg( "$tmp/wlog" ) . ' ' . escapeshellarg( "$tmp/home" ) . ' ' . escapeshellarg( "$tmp/run" ) );
chmod( "$site/wp-config.php", 0640 );
t( "the test site in $site, owned by $user:$group, wp-config.php 0640", $setup_ok && is_file( "$site/wp-config.php" ), $setup_er );
if ( ! $setup_ok ) {
	exit( 1 );
}

/* ---------- PHP-FPM (pool of the site's user) and Nginx in front ---------- */
$sock = "$tmp/run/fpm.sock";
file_put_contents(
	"$tmp/fpm.conf",
	"[global]\npid = $tmp/run/fpm.pid\nerror_log = $tmp/logs/fpm.log\ndaemonize = no\n[t3130]\nuser = $user\ngroup = $group\nlisten = $sock\nlisten.mode = 0666\npm = static\npm.max_children = 2\ncatch_workers_output = yes\nphp_admin_value[error_log] = $tmp/wlog/php.log\nphp_admin_flag[log_errors] = on\nphp_admin_value[opcache.enable] = 0\n"
);
$procs[] = proc_open( escapeshellarg( $fpm ) . ' -R -F -y ' . escapeshellarg( "$tmp/fpm.conf" ), array( array( 'file', '/dev/null', 'r' ), array( 'file', "$tmp/logs/fpm.out", 'w' ), array( 'file', "$tmp/logs/fpm.out", 'a' ) ), $pipes );
$fcgi    = 'include /etc/nginx/fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass unix:' . $sock . ';';
file_put_contents(
	"$tmp/nginx.conf",
	"user $user $group;\nworker_processes 1;\ndaemon off;\npid $tmp/run/nginx.pid;\nerror_log $tmp/logs/nginx.log warn;\nevents { worker_connections 64; }\nhttp {\naccess_log off;\n"
	. "client_body_temp_path $tmp/run/body; fastcgi_temp_path $tmp/run/fcgi; proxy_temp_path $tmp/run/proxy; uwsgi_temp_path $tmp/run/uwsgi; scgi_temp_path $tmp/run/scgi;\n"
	. "server { listen 127.0.0.1:$port; root $site; index index.php;\n location / { try_files \$uri \$uri/ /index.php?\$args; }\n location ~ \\.php\$ { $fcgi } }\n}\n"
);
$procs[] = proc_open( escapeshellarg( $nginx ) . ' -e ' . escapeshellarg( "$tmp/logs/nginx.log" ) . ' -c ' . escapeshellarg( "$tmp/nginx.conf" ), array( array( 'file', '/dev/null', 'r' ), array( 'file', "$tmp/logs/nginx.out", 'w' ), array( 'file', "$tmp/logs/nginx.out", 'a' ) ), $pipes );
$up = false;
for ( $i = 0; $i < 100 && ! $up; $i++ ) {
	usleep( 100000 );
	$s = @fsockopen( '127.0.0.1', $port, $errno, $errstr, 0.1 );
	if ( $s && file_exists( $sock ) ) {
		fclose( $s );
		$up = true;
	}
}
t( "PHP-FPM (pool user $user) and Nginx on port $port", $up, (string) @file_get_contents( "$tmp/logs/fpm.out" ) . (string) @file_get_contents( "$tmp/logs/nginx.log" ) );
if ( ! $up ) {
	exit( 1 );
}

/** A guest's page view through Nginx: [status, body]. */
function guest() {
	global $url;
	static $n = 0;
	$ch = curl_init( $url . '/?pncp_t3130=' . ( ++$n ) );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 30,
			CURLOPT_HTTPHEADER     => array(
				'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36',
				'Accept: text/html,application/xhtml+xml',
				'Accept-Language: en-US,en;q=0.9',
			),
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

/** Files and folders under $dir (itself included) not owned by uid:gid. */
function not_owned( $dir, $uid, $gid ) {
	if ( ! file_exists( $dir ) ) {
		return array();
	}
	$out = array();
	$all = array( $dir );
	if ( is_dir( $dir ) ) {
		$iter = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST );
		foreach ( $iter as $f ) {
			$all[] = $f->getPathname();
		}
	}
	clearstatcache();
	foreach ( $all as $path ) {
		$st = lstat( $path );
		if ( $st && ( $uid !== (int) $st['uid'] || $gid !== (int) $st['gid'] ) ) {
			$pwd   = posix_getpwuid( (int) $st['uid'] );
			$out[] = substr( $path, strlen( $dir ) ) . ' (' . ( $pwd ? $pwd['name'] : $st['uid'] ) . ' ' . sprintf( '%o', $st['mode'] & 07777 ) . ')';
		}
	}
	return $out;
}

/** ScrapeLock's temp files left anywhere in the site. */
function leftovers() {
	global $site;
	$out = array();
	foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $site, FilesystemIterator::SKIP_DOTS ) ) as $f ) {
		if ( '.tmp' === substr( $f->getFilename(), -4 ) ) {
			$out[] = substr( $f->getPathname(), strlen( $site ) );
		}
	}
	return $out;
}

$uploads = "$site/wp-content/uploads/scrapelock";
$early   = "$site/wp-content/mu-plugins/scrapelock-early.php";
$config  = "$site/wp-config.php";
$warning = 'WP-CLI runs as root.';

/** The checks after one command. */
function after( $label, $res, $expect_warning ) {
	global $uid, $gid, $user, $group, $uploads, $early, $config, $warning, $tmp, $site;
	list( $rc, $out, $err ) = $res;
	t( "$label: the command succeeds", 0 === $rc, trim( substr( $out . ' ' . $err, 0, 400 ) ) );
	list( $code, $body ) = guest();
	$php = (string) @file_get_contents( "$tmp/wlog/php.log" );
	t( "$label: a guest gets 200 (not 500 \"Failed opening required\")", 200 === $code && false === strpos( $body, 'Failed opening required' ), "HTTP $code " . strtok( (string) strstr( $php, 'Failed opening' ), "\n" ) );
	clearstatcache();
	$st = stat( $config );
	t( "$label: wp-config.php is still $user:$group 0640", $st && $uid === (int) $st['uid'] && $gid === (int) $st['gid'] && 0640 === ( $st['mode'] & 07777 ), $st ? ( ( posix_getpwuid( (int) $st['uid'] )['name'] ?? $st['uid'] ) . ':' . ( posix_getgrgid( (int) $st['gid'] )['name'] ?? $st['gid'] ) . ' ' . sprintf( '%o', $st['mode'] & 07777 ) ) : 'missing' );
	$bad = file_exists( $early ) ? not_owned( $early, $uid, $gid ) : array();
	t( "$label: mu-plugins/scrapelock-early.php (when there) belongs to $user:$group", array() === $bad, implode( ', ', $bad ) );
	$bad = not_owned( $uploads, $uid, $gid );
	t( "$label: every file and folder under uploads/scrapelock belongs to $user:$group", array() === $bad, count( $bad ) . ': ' . implode( ', ', array_slice( $bad, 0, 4 ) ) );
	$left = leftovers();
	t( "$label: no .tmp file left", array() === $left, implode( ', ', $left ) );
	if ( $expect_warning ) {
		t( "$label: ScrapeLock's root warning in stderr, with $user:$group and sudo -u $user", false !== strpos( $err, $warning ) && false !== strpos( $err, "($user:$group)" ) && false !== strpos( $err, "sudo -u $user wp" ), trim( substr( $err, 0, 300 ) ) );
		t( "$label: the warning once", 1 === substr_count( $err, $warning ), (string) substr_count( $err, $warning ) );
	}
	// Each command is judged alone: what a failed one changed is given back to the site's user before the next.
	exec( 'chown -R ' . $uid . ':' . $gid . ' ' . escapeshellarg( $site ) );
	chmod( $config, 0640 );
}

list( $code ) = guest();
t( 'before any command: a guest gets 200', 200 === $code, "HTTP $code" );

$settings = static function ( $changes ) {
	list( , $json ) = wp( array( 'option', 'get', 'pncp_settings', '--format=json' ) );
	$s              = json_decode( $json, true );
	return wp( array( 'option', 'update', 'pncp_settings', (string) json_encode( array_merge( is_array( $s ) ? $s : array(), $changes ) ), '--format=json' ) );
};

after( 'settings set precheck 1', wp( array( 'scrapelock', 'settings', 'set', 'precheck', '1', '--yes' ) ), true );
t( 'the pre-cache check\'s line is in wp-config.php', false !== strpos( (string) file_get_contents( $config ), 'scrapelock' ) );
after( 'settings set early_mode 1', wp( array( 'scrapelock', 'settings', 'set', 'early_mode', '1', '--yes' ) ), true );
t( 'the early check\'s mu-plugin is installed', is_file( $early ) );
after( 'precheck sync', wp( array( 'scrapelock', 'precheck', 'sync' ) ), true );
after( 'precheck cleanup', wp( array( 'scrapelock', 'precheck', 'cleanup' ) ), true );
after( 'breaker reset', wp( array( 'scrapelock', 'breaker', 'reset' ) ), true );
after(
	'option update pncp_settings (precheck and early_mode off)',
	$settings(
		array(
			'precheck'   => 0,
			'early_mode' => 0,
		)
	),
	true
);
after(
	'option update pncp_settings (precheck and early_mode on again)',
	$settings(
		array(
			'precheck'   => 1,
			'early_mode' => 1,
		)
	),
	true
);
after( 'settings set precheck 0', wp( array( 'scrapelock', 'settings', 'set', 'precheck', '0', '--yes' ) ), true );
after( 'settings set precheck 1 (again)', wp( array( 'scrapelock', 'settings', 'set', 'precheck', '1', '--yes' ) ), true );
after( 'plugin deactivate scrapelock', wp( array( 'plugin', 'deactivate', 'scrapelock' ) ), true );
// ScrapeLock is not loaded before "plugin activate" runs: no warning of its own there.
after( 'plugin activate scrapelock', wp( array( 'plugin', 'activate', 'scrapelock' ) ), false );
after( 'precheck sync after activation', wp( array( 'scrapelock', 'precheck', 'sync' ) ), true );

// No warning: --quiet, --format=json, an option that is not ScrapeLock's, WP-CLI as the site's user.
list( , , $err ) = wp( array( 'scrapelock', 'breaker', '--quiet' ) );
t( 'no root warning with --quiet', false === strpos( $err, $warning ), trim( $err ) );
list( , $out, $err ) = wp( array( 'scrapelock', 'breaker', '--format=json' ) );
t( 'no root warning with --format=json (and the output is JSON)', false === strpos( $err, $warning ) && null !== json_decode( $out ), trim( $err . ' ' . substr( $out, 0, 200 ) ) );
list( , , $err ) = wp( array( 'option', 'update', 'blogdescription', 'T3130' ) );
t( 'no root warning for an option that is not ScrapeLock\'s', false === strpos( $err, $warning ), trim( $err ) );
list( $rc, $out, $err ) = wp( array( 'scrapelock', 'breaker' ), false );
if ( false !== strpos( $out . $err, 'Could not open input file' ) || false !== strpos( $out . $err, 'Permission denied' ) ) {
	echo "SKIP as $user: WP-CLI (WP_CLI) cannot be read by that user\n";
} else {
	t( "no root warning when WP-CLI runs as $user", 0 === $rc && false === strpos( $err, $warning ), trim( substr( $out . ' ' . $err, 0, 300 ) ) );
}

$php = (string) @file_get_contents( "$tmp/wlog/php.log" ) . (string) @file_get_contents( "$tmp/wlog/debug.log" );
t( 'no PHP fatal error in the site\'s log', ! preg_match( '/PHP Fatal|Failed opening required/', $php ), substr( $php, 0, 400 ) );

echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
