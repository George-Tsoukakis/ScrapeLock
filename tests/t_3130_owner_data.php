<?php
/**
 * ScrapeLock 3.12.10 — files written as root (WP-CLI --allow-root, root's cron) keep the site's owner.
 *
 *   WP_DIR=/path/to/wordpress php t_3130_owner_data.php        (as root; otherwise SKIP)
 *
 * The test builds a fake WordPress folder (ABSPATH) owned by a non-root uid/gid (4242:4243): symbolic links to the
 * files of WP_DIR, an uploads folder of its own (UPLOADS) with uploads/scrapelock owned by that user. In it, a data
 * folder as 3.12.9 left it after a run as root (the folder and strikes/ root's, 0700, a strike file root's 0600)
 * and a ban file of the site's owner with 0640. Then, in child processes as root with umask 077 (WordPress loaded
 * on the fake folder):
 *   - the pre-cache check (PNCP_Precheck_Runtime): hit() (the minute's folder, the counter, .new, .net-), crossed()
 *     (.over), strike(), ban() (new and replaced), probe_seen(), event() (events.log), sync_bans() with APCu (bans
 *     copied into the files), sweep() (.sweep.lock), the hourly cleanup() (.cleaned and the repair of 3.12.9's root
 *     files);
 *   - the circuit breaker in files mode (PNCP_Breaker): trip, reset, trip (breaker/), and PNCP_Breaker_Status's
 *     _reset.json and _snapshot.json;
 *   - the geo database (PNCP_Geo), the Stealth debug log, uploads/.htaccess (PNCP_Rules), the watermark's backup
 *     folder and a backup (PNCP_Watermark), a file of "Verify files" in the site's root folder (PNCP_Verify_Files)
 *     and, when the site is known as Apache, the Stealth block in a new .htaccess.
 * Every file and folder created or replaced must belong to 4242:4243, with 0755 (folders), 0644 (new files) or the
 * replaced file's own mode (0640), and no temporary file may be left.
 */

const T3130_UID = 4242;
const T3130_GID = 4243;

/* ---------- Child: runs the writers as root on the fake WordPress folder ---------- */

if ( isset( $argv[1] ) && '--child' === $argv[1] ) {
	$fake = (string) $argv[2];
	$part = (string) $argv[3];
	umask( 077 ); // root's restrictive umask: before 3.12.10 the files became root:root 0600 / 0700.
	define( 'ABSPATH', $fake . '/' );
	define( 'UPLOADS', 'up' );
	define( 'WP_USE_THEMES', false );
	require $fake . '/wp-load.php';
	$out  = array();
	$call = static function ( $class, $method, ...$args ) {
		$m = new ReflectionMethod( $class, $method );
		$m->setAccessible( true );
		return $m->invoke( null, ...$args );
	};
	$data = PNCP_Precheck::dir();
	$now  = time();
	$min  = (int) floor( $now / 60 );
	if ( 'runtime' === $part ) {
		PNCP_Precheck::load_runtime();
		$c = array(
			'dir'         => $data,
			'ban_strikes' => 2,
			'new_files'   => 2000,
		);
		$count = 0;
		for ( $i = 0; $i < 6; $i++ ) {
			$count = PNCP_Precheck_Runtime::hit( $c, '203.0.113.7', $now, '203.0.113.7' );
		}
		$out['hit']     = $count >= 6;
		$out['crossed'] = PNCP_Precheck_Runtime::crossed( $c, '203.0.113.7', $now, 6, 5 );
		PNCP_Precheck_Runtime::strike( $c, 'k1', $now );
		PNCP_Precheck_Runtime::ban( $c, '203.0.113.8', $now + 600 );
		PNCP_Precheck_Runtime::ban( $c, '203.0.113.9', $now + 900 ); // Replaces the seeded file (0640).
		$out['banned']  = PNCP_Precheck_Runtime::banned( $data, '203.0.113.9', $now );
		$out['probe']   = false === PNCP_Precheck_Runtime::probe_seen( $c, 'probe-key', $now );
		PNCP_Precheck_Runtime::event( $c, 403, 'test', '203.0.113.7' );
		$apcu = $c + array(
			'apcu'       => 1,
			'apcu_sapis' => array( 'cli' ),
		);
		if ( 'apcu' === PNCP_Precheck_Runtime::store( $apcu ) ) {
			PNCP_Precheck_Runtime::mem_set( $apcu, 'b:' . md5( '203.0.113.10' ), (string) ( $now + 1200 ), 1300 );
			$copied           = PNCP_Precheck_Runtime::sync_bans( $apcu, $now );
			$out['sync_bans'] = $copied >= 1 && is_file( $data . '/bans/' . md5( '203.0.113.10' ) );
		} else {
			$out['sync_bans'] = 'skip';
		}
		PNCP_Precheck_Runtime::sweep( $data, $min, 25 );
		PNCP_Precheck_Runtime::cleanup( $data . '/hits', $min, 0 );
	} elseif ( 'breaker' === $part ) {
		PNCP_Breaker::forget();
		PNCP_Breaker::setup( $data );
		$out['kind'] = PNCP_Breaker::kind();
		PNCP_Breaker::trip( 'precheck_files', 300, 'test' );
		$out['reset'] = PNCP_Breaker::reset( '', false );
		PNCP_Breaker::trip( 'precheck_files', 300, 'test' );
		$out['open'] = PNCP_Breaker::open( 'precheck_files' );
		$call( 'PNCP_Breaker_Status', 'write', $data . '/breaker', '_reset.json', array( 'name' => '' ) );
		$call( 'PNCP_Breaker_Status', 'write', $data . '/breaker', '_reset.json', array( 'name' => 'x' ) ); // Replaced.
		$call( 'PNCP_Breaker_Status', 'write', $data . '/breaker', '_snapshot.json', array( 'rows' => array() ) );
	} elseif ( 'wp' === $part ) {
		$out['geo']           = $call( 'PNCP_Geo', 'write', 't3130.csv', "1.0.0.0,1.0.0.255,AU\n" );
		$out['geo_replace']   = $call( 'PNCP_Geo', 'write', 't3130.csv', "1.0.0.0,1.0.0.255,NZ\n" );
		$call( 'PNCP_Stealth_Debug', 'write', "a line\n" );
		$call( 'PNCP_Stealth_Debug', 'write', "a second line\n" );
		PNCP_Rules::sync_uploads_htaccess( true );
		$backup_dir           = PNCP_Watermark::backup_dir();
		$out['backup_dir']    = '' !== $backup_dir;
		$out['backup']        = $call( 'PNCP_Watermark', 'ensure_backup', $fake . '/up/2026/t3130.jpg' );
		$out['verify_file']   = $call( 'PNCP_Verify_Files', 'write_disk', '/pncp-t3130-verify.txt', 'test' );
		$GLOBALS['is_apache'] = true;
		$GLOBALS['is_nginx']  = false;
		if ( PNCP_Stealth::htaccess_writable() ) {
			$out['stealth_htaccess'] = $call( 'PNCP_Stealth', 'write_htaccess', array( '# t3130' ) );
		} else {
			$out['stealth_htaccess'] = 'skip';
		}
	}
	echo 'RESULT ' . wp_json_encode( $out ) . "\n";
	exit( 0 );
}

/* ---------- Parent ---------- */

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

$wp_dir = getenv( 'WP_DIR' );
if ( ! $wp_dir ) {
	fwrite( STDERR, "WP_DIR is required\n" );
	exit( 2 );
}
if ( ! function_exists( 'posix_geteuid' ) || 0 !== posix_geteuid() ) {
	skip( 'not root: the owner checks of files written as root need root' );
	exit( 0 );
}
$wp_dir = rtrim( (string) realpath( $wp_dir ), '/' );
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

$key  = basename( PNCP_Precheck::dir() ); // precheck-RANDOM, the same in the child (same database).
$fake = rtrim( sys_get_temp_dir(), '/' ) . '/pncp-t3130-' . wp_generate_password( 8, false, false );
register_shutdown_function(
	static function () use ( $fake ) {
		exec( 'rm -rf ' . escapeshellarg( $fake ) );
	}
);
mkdir( $fake, 0755 );
foreach ( (array) scandir( $wp_dir ) as $name ) {
	if ( '.' !== $name && '..' !== $name && '.htaccess' !== $name ) {
		symlink( $wp_dir . '/' . $name, $fake . '/' . $name );
	}
}
$up   = $fake . '/up';
$data = $up . '/scrapelock/' . $key;
mkdir( $up . '/2026', 0755, true );
mkdir( $up . '/scrapelock', 0755 );
file_put_contents( $up . '/2026/t3130.jpg', 'not really a jpeg' );
chmod( $up . '/2026/t3130.jpg', 0644 );
foreach ( array( $fake, $up, $up . '/2026', $up . '/2026/t3130.jpg', $up . '/scrapelock' ) as $path ) {
	chown( $path, T3130_UID );
	chgrp( $path, T3130_GID );
}
// What 3.12.9 left after `wp scrapelock precheck cleanup` as root: the data folder and strikes/ root's, 0700.
mkdir( $data . '/strikes', 0700, true );
chmod( $data, 0700 );
file_put_contents( $data . '/strikes/' . md5( 'old' ), time() . '|1' );
chmod( $data . '/strikes/' . md5( 'old' ), 0600 );
// A ban file of the site's owner with its own mode: replaced, it keeps both.
mkdir( $data . '/bans', 0755 );
file_put_contents( $data . '/bans/' . md5( '203.0.113.9' ), (string) ( time() + 60 ) );
chmod( $data . '/bans/' . md5( '203.0.113.9' ), 0640 );
foreach ( array( $data . '/bans', $data . '/bans/' . md5( '203.0.113.9' ) ) as $path ) {
	chown( $path, T3130_UID );
	chgrp( $path, T3130_GID );
}
$seeded_0640 = $data . '/bans/' . md5( '203.0.113.9' );

$results = array();
foreach ( array( 'runtime', 'breaker', 'wp' ) as $part ) {
	$ini = 'runtime' === $part ? '-d apc.enable_cli=1' : '-d apc.enable_cli=0';
	$out = array();
	exec( escapeshellarg( PHP_BINARY ) . ' ' . $ini . ' ' . escapeshellarg( __FILE__ ) . ' --child ' . escapeshellarg( $fake ) . ' ' . $part . ' 2>&1', $out, $rc );
	$text = implode( "\n", $out );
	$res  = preg_match( '/^RESULT (.*)$/m', $text, $m ) ? json_decode( $m[1], true ) : null;
	t( "$part: the writers ran as root without an error or a warning", 0 === $rc && is_array( $res ) && ! preg_match( '/(Warning|Notice|Deprecated|Fatal error):/', $text ), substr( $text, 0, 600 ) );
	$results[ $part ] = is_array( $res ) ? $res : array();
}
$r = $results['runtime'];
t( 'runtime: the counter, its violation, the ban read back and the first probe work as root', ! empty( $r['hit'] ) && ! empty( $r['crossed'] ) && ! empty( $r['banned'] ) && ! empty( $r['probe'] ), wp_json_encode( $r ) );
if ( isset( $r['sync_bans'] ) && 'skip' === $r['sync_bans'] ) {
	skip( 'runtime: sync_bans() (APCu is not available to the command line)' );
} else {
	t( 'runtime: sync_bans() copied the ban of APCu into the files', ! empty( $r['sync_bans'] ) );
}
$b = $results['breaker'];
t( 'breaker: files mode, tripped, reset and tripped again', isset( $b['kind'] ) && 'files' === $b['kind'] && ! empty( $b['open'] ) && 1 === ( $b['reset'] ?? null ), wp_json_encode( $b ) );
$w = $results['wp'];
t( 'geo, watermark and Verify files wrote their files', ! empty( $w['geo'] ) && ! empty( $w['geo_replace'] ) && ! empty( $w['backup_dir'] ) && ! empty( $w['backup'] ) && 'written' === ( $w['verify_file'] ?? '' ), wp_json_encode( $w ) );

clearstatcache();
$minute   = (int) floor( time() / 60 );
$expected = array(
	$data,
	$data . '/hits',
	$data . '/events.log',
	$data . '/.cleaned',
	$data . '/.sweep.lock',
	$data . '/strikes/' . md5( 'k1' ),
	$data . '/strikes/' . md5( 'old' ),
	$data . '/bans/' . md5( '203.0.113.8' ),
	$seeded_0640,
	$data . '/probes/' . md5( 'probe-key' ),
	$data . '/breaker',
	$data . '/breaker/precheck_files.json',
	$data . '/breaker/_history.json',
	$data . '/breaker/_reset.json',
	$data . '/breaker/_snapshot.json',
	$up . '/scrapelock-geo',
	$up . '/scrapelock-geo/t3130.csv',
	$up . '/scrapelock-geo/index.html',
	$up . '/scrapelock-geo/.htaccess',
	$up . '/.htaccess',
	$up . '/scrapelock/index.html',
	$fake . '/pncp-t3130-verify.txt',
);
foreach ( (array) glob( $up . '/scrapelock/stealth-debug-*.log' ) as $log ) {
	$expected[] = $log;
}
foreach ( (array) glob( $up . '/pncp-originals-*' ) as $dir ) {
	$expected[] = $dir;
	$expected[] = $dir . '/.htaccess';
	$expected[] = $dir . '/index.html';
	$expected[] = $dir . '/2026/t3130.jpg';
}
if ( isset( $w['stealth_htaccess'] ) && 'skip' !== $w['stealth_htaccess'] ) {
	$expected[] = $fake . '/.htaccess';
} else {
	skip( 'Stealth: .htaccess of the site not writable here' );
}
$missing = array_values( array_filter( $expected, static function ( $p ) {
	return ! file_exists( $p );
} ) );
t( 'every expected file and folder is there (' . count( $expected ) . ', the stealth debug log, the watermark backup)', array() === $missing && glob( $up . '/scrapelock/stealth-debug-*.log' ) && glob( $up . '/pncp-originals-*' ), implode( ', ', $missing ) );
t( 'the minute\'s counters were written as files (hits/<minute>/: counter, .new, .net-, .over)', count( (array) glob( $data . '/hits/*/{,.}[!.]*', GLOB_BRACE ) ) >= 4, implode( ',', (array) glob( $data . '/hits/*/{,.}[!.]*', GLOB_BRACE ) ) );

// Every entry under the fake uploads folder, plus the files written into the site's root folder.
$all = array();
$it  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $up, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST );
foreach ( $it as $info ) {
	$all[] = $info->getPathname();
}
foreach ( array( $fake . '/pncp-t3130-verify.txt', $fake . '/.htaccess' ) as $extra ) {
	if ( file_exists( $extra ) && ! is_link( $extra ) ) {
		$all[] = $extra;
	}
}
$wrong_owner = array();
$wrong_mode  = array();
foreach ( $all as $path ) {
	$st   = stat( $path );
	$mode = $st['mode'] & 07777;
	$want = $path === $seeded_0640 ? 0640 : ( is_dir( $path ) ? 0755 : 0644 );
	if ( T3130_UID !== (int) $st['uid'] || T3130_GID !== (int) $st['gid'] ) {
		$wrong_owner[] = substr( $path, strlen( $fake ) ) . ' ' . $st['uid'] . ':' . $st['gid'];
	}
	if ( $mode !== $want ) {
		$wrong_mode[] = substr( $path, strlen( $fake ) ) . ' ' . decoct( $mode );
	}
}
t( 'every file and folder created or replaced as root belongs to ' . T3130_UID . ':' . T3130_GID . ' (' . count( $all ) . ' entries)', count( $all ) > 25 && array() === $wrong_owner, implode( ', ', array_slice( $wrong_owner, 0, 12 ) ) );
t( 'modes: 0755 folders, 0644 new files, the replaced ban file kept 0640 (umask 077 in the writers)', array() === $wrong_mode, implode( ', ', array_slice( $wrong_mode, 0, 12 ) ) );
t( '3.12.9\'s root files repaired by the hourly cleanup (data folder, strikes/ and its old file)', T3130_UID === fileowner( $data ) && T3130_UID === fileowner( $data . '/strikes' ) && T3130_UID === fileowner( $data . '/strikes/' . md5( 'old' ) ) );
$tmp_left = array_values( array_filter( $all, static function ( $p ) {
	return '.tmp' === substr( $p, -4 );
} ) );
t( 'no temporary file (.tmp) left', array() === $tmp_left, implode( ', ', $tmp_left ) );

echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
