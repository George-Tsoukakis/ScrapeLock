<?php
/**
 * ScrapeLock 3.12.10 — the files ScrapeLock writes in the WordPress folder and in wp-content keep their owner, group
 * and mode, also when WP-CLI runs as root (--allow-root). In 3.12.9 a rewritten wp-config.php became root:root 0640
 * and PHP-FPM (www-data) could no longer load it: the site was down.
 *
 * As root, a fake WordPress folder owned by uid 33 (www-data) in the temp folder, and the test WordPress's own folder
 * (only the folder itself, put back at the end) handed to uid 33, so that new files have an owner to go to:
 *   A. wp-config.php (PNCP_Precheck::write_config()) at 0640, 0644 and 0440: owner, group and mode unchanged, the
 *      contents written, no temporary copy left; the same on the test site's real wp-config.php through
 *      PNCP_Precheck::sync() (the pre-cache check turned on and off again), with its data folder in uploads
 *      (config.json, crawlers.json, index.html: new and rewritten) and ops.log;
 *   B. the early mu-plugin (PNCP_Early::sync()): new: the owner of the WordPress folder, 0644 (FS_CHMOD_FILE);
 *      rewritten: its owner and mode (0640) kept;
 *   C. the Lockdown guard (PNCP_Seal::write_guard(), a lock that is open for the next hour, so it does nothing): new
 *      and rewritten as above; the lock file (beacon_put()) and its folder, index.php and .htaccess;
 *   D. the guard's counters (fails_file_put()) and lock file (local_lock()): created as root, handed over, 0644;
 *   E. .htaccess (PNCP_Hardening::put_htaccess()): an existing one keeps owner and mode, a new one 0644 with the
 *      folder's owner, a symlinked one is written through the link;
 *   F. WP-CLI (SKIP without WP_CLI): rules install into a file of the fake folder (kept), a new .htaccess inside
 *      the WordPress folder (handed over, 0644) and a new .conf (stays root's); cache status
 *      --save-constant on a copy of wp-config.php at 0440 (kept);
 *   and no *.tmp file left anywhere.
 * As root on a site whose files belong to another user, WordPress itself would not write (no "direct" method):
 * first checked that wp-config.php is then left alone, then FS_METHOD 'direct' is set for the rest, as on the
 * servers where 3.12.9's failure showed up. Not as root: the modes are checked, the owner checks are SKIP.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 WP_CLI="wp --path=… --allow-root" php t_3130_owner_files.php
 *
 * Only on a test WordPress: its settings, wp-config.php and folder owner change during the test and are put back.
 */

$wp_dir = getenv( 'WP_DIR' );
$wp_cli = (string) getenv( 'WP_CLI' );
if ( ! $wp_dir ) {
	fwrite( STDERR, "WP_DIR is required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/file.php';

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

/** Owner, group and mode of a file: "uid:gid 0640". */
function meta( $path ) {
	clearstatcache( true, $path );
	$s = @stat( $path );
	return false === $s ? 'missing' : $s['uid'] . ':' . $s['gid'] . ' ' . sprintf( '%04o', $s['mode'] & 07777 );
}

/** Checks a file: its mode always, its owner and group only as root. */
function same( $label, $path, $uid, $gid, $mode ) {
	global $root;
	clearstatcache( true, $path );
	$s = @stat( $path );
	if ( false === $s ) {
		t( $label, false, 'missing: ' . $path );
		return;
	}
	t( $label . ' (mode ' . sprintf( '%04o', $mode ) . ')', ( $s['mode'] & 07777 ) === $mode, meta( $path ) );
	if ( $root ) {
		t( $label . ' (owner ' . $uid . ':' . $gid . ')', $s['uid'] === $uid && $s['gid'] === $gid, meta( $path ) );
	} else {
		skip( $label . ': owner (not root)' );
	}
}

/** Files ending in .tmp, or a temporary copy of wp-config.php, under a folder (not recursive into WordPress). */
function leftovers( $dir, $deep = true ) {
	$out = array();
	if ( ! is_dir( $dir ) ) {
		return $out;
	}
	$it = $deep ? new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) ) : new FilesystemIterator( $dir );
	foreach ( $it as $f ) {
		$name = $f->getFilename();
		if ( preg_match( '/\.tmp$|\.scrapelock-[A-Za-z0-9]{8}\.php$|\.new$|\.old$/', $name ) ) {
			$out[] = $f->getPathname();
		}
	}
	return $out;
}

function call( $class, $method, ...$args ) {
	$m = new ReflectionMethod( $class, $method );
	$m->setAccessible( true );
	return $m->invoke( null, ...$args );
}

/** Runs "wp scrapelock …": [exit code, stdout + stderr]. */
function cli( $args, $env = '' ) {
	global $wp_cli;
	exec( $env . ' ' . $wp_cli . ' scrapelock ' . $args . ' < /dev/null 2>&1', $out, $rc );
	wp_cache_flush();
	return array( $rc, implode( "\n", $out ) );
}

$root = PNCP_File_Owner::is_root();
// WordPress writes files itself only with the "direct" method: a file it creates must have the owner of its own
// files (get_filesystem_method()). As root on a site owned by another user (here, or PHP-FPM's www-data), it is
// not, and ScrapeLock refuses to write, as WordPress does (checked in A). The 3.12.9 failure needs a site where
// root may write, as with FS_METHOD 'direct' in wp-config.php (common) or a site owned by root: the test sets that.
$direct = 'direct' === get_filesystem_method( array(), ABSPATH );
if ( ! $direct && ! defined( 'FS_METHOD' ) ) {
	echo '# WordPress would not write here as uid ' . ( function_exists( 'posix_geteuid' ) ? posix_geteuid() : getmyuid() ) . " (its files belong to another user): FS_METHOD 'direct' set for the test\n";
}
// The mode WordPress gives new files (WP_Filesystem() defines it; not yet when nothing was written).
if ( ! defined( 'FS_CHMOD_FILE' ) ) {
	define( 'FS_CHMOD_FILE', ( fileperms( ABSPATH . 'index.php' ) & 0777 | 0644 ) );
}
$me   = function_exists( 'posix_geteuid' ) ? posix_geteuid() : getmyuid();
$mg   = function_exists( 'posix_getegid' ) ? posix_getegid() : getmygid();
// As root: everything belongs to uid/gid 33 (www-data), as on a server where PHP-FPM runs as www-data.
$uid = $root ? 33 : $me;
$gid = $root ? 33 : $mg;

$core      = rtrim( ABSPATH, '/' );
$core_meta = PNCP_File_Owner::capture( $core );
$config    = PNCP_Paths::config();
$conf_meta = '' !== $config ? PNCP_File_Owner::capture( $config ) : null;
$conf_text = '' !== $config ? (string) file_get_contents( $config ) : '';
$saved     = get_option( PNCP_OPTION );
$fake      = rtrim( get_temp_dir(), '/' ) . '/pncp-t3130-' . wp_generate_password( 8, false, false );
$in_core   = $core . '/pncp-t3130-' . wp_generate_password( 8, false, false );
$mu        = PNCP_Paths::mu_plugins();
$lock      = PNCP_Lockdown::local_lock_file();
$had_lock  = file_exists( $lock );
register_shutdown_function(
	static function () use ( $core, $core_meta, $config, $conf_meta, $conf_text, $saved, $fake, $in_core, $root, $lock, $had_lock ) {
		update_option( PNCP_OPTION, $saved );
		PNCP_Options::flush();
		PNCP_Early::sync();
		PNCP_Precheck::sync();
		PNCP_Seal::remove_guard();
		PNCP_Seal::remove_beacon();
		PNCP_Lockdown::fails_remove();
		if ( '' !== $config && null !== $conf_meta ) {
			if ( (string) file_get_contents( $config ) !== $conf_text ) {
				file_put_contents( $config, $conf_text );
			}
			PNCP_File_Owner::restore( $config, $conf_meta );
		}
		if ( $root && null !== $core_meta ) {
			PNCP_File_Owner::restore( $core, $core_meta );
		}
		if ( ! $had_lock && file_exists( $lock ) ) {
			unlink( $lock );
		}
		exec( 'rm -rf ' . escapeshellarg( $fake ) . ' ' . escapeshellarg( $in_core ) );
	}
);

function settings( $values ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $values ) );
	PNCP_Options::flush();
}

/** A file of the fake folder with owner $u:$g and $mode. */
function seed( $path, $text, $mode ) {
	global $uid, $gid, $root;
	file_put_contents( $path, $text );
	chmod( $path, $mode );
	if ( $root ) {
		chown( $path, $uid );
		chgrp( $path, $gid );
	}
}

mkdir( $fake, 0755 );
if ( $root ) {
	chown( $fake, $uid );
	chgrp( $fake, $gid );
	// The test site's folder too (only the folder itself): new files go to its owner (PNCP_File_Owner::base()).
	chown( $core, $uid );
	chgrp( $core, $gid );
	echo "# as root: the fake WordPress folder and the test site's folder belong to $uid:$gid\n";
} else {
	echo "# not root (uid $me): modes only\n";
}
$base_uid = $root ? $uid : $me;
$base_gid = $root ? $gid : $mg;

/* ---------- A. wp-config.php ---------- */

if ( ! $direct && ! defined( 'FS_METHOD' ) ) {
	// Without FS_METHOD: refused, as WordPress itself would not write here, and the file left as it was.
	$file = $fake . '/wp-config.php';
	$orig = "<?php\ndefine( 'DB_NAME', 'x' );\n";
	seed( $file, $orig, 0640 );
	$ok = call( 'PNCP_Precheck', 'write_config', $file, PNCP_Precheck::block() . $orig, $orig );
	t( 'A WordPress would not write here: wp-config.php left as it was', ! $ok && $orig === file_get_contents( $file ) );
	same( 'A WordPress would not write here: wp-config.php kept', $file, $uid, $gid, 0640 );
	unlink( $file );
	define( 'FS_METHOD', 'direct' );
}

foreach ( array( 0640, 0644, 0440 ) as $mode ) {
	$file = $fake . '/wp-config.php';
	$orig = "<?php\ndefine( 'DB_NAME', 'x' );\nrequire_once ABSPATH . 'wp-settings.php';\n";
	seed( $file, $orig, $mode );
	$want = PNCP_Precheck::block() . $orig;
	$ok   = call( 'PNCP_Precheck', 'write_config', $file, $want, $orig );
	if ( ! $root && 0 === ( $mode & 0200 ) ) {
		t( sprintf( 'A wp-config.php %04o, not root: not writable, left as it was', $mode ), ! $ok && $orig === file_get_contents( $file ) && sprintf( '%04o', $mode ) === substr( meta( $file ), -4 ) );
		unlink( $file );
		continue;
	}
	t( sprintf( 'A wp-config.php %04o: written', $mode ), $ok && $want === file_get_contents( $file ) );
	same( sprintf( 'A wp-config.php %04o: kept', $mode ), $file, $uid, $gid, $mode );
	$ok = call( 'PNCP_Precheck', 'write_config', $file, $orig, $want );
	t( sprintf( 'A wp-config.php %04o: the line removed again', $mode ), $ok && $orig === file_get_contents( $file ) );
	same( sprintf( 'A wp-config.php %04o: still kept', $mode ), $file, $uid, $gid, $mode );
	t( sprintf( 'A wp-config.php %04o: no temporary copy left', $mode ), array() === leftovers( $fake ), implode( ' ', leftovers( $fake ) ) );
	unlink( $file );
}
// A symlinked wp-config.php: written where it points, the link and the target's owner and mode kept.
seed( $fake . '/shared-config.php', "<?php\n// shared\n", 0640 );
symlink( $fake . '/shared-config.php', $fake . '/wp-config.php' );
$ok = call( 'PNCP_Precheck', 'write_config', $fake . '/wp-config.php', "<?php\n// shared 2\n", "<?php\n// shared\n" );
t( 'A symlinked wp-config.php: written through the link, still a link', $ok && is_link( $fake . '/wp-config.php' ) && "<?php\n// shared 2\n" === file_get_contents( $fake . '/shared-config.php' ) );
same( 'A symlinked wp-config.php: the target kept', $fake . '/shared-config.php', $uid, $gid, 0640 );
unlink( $fake . '/wp-config.php' );

if ( '' === $config || null === $conf_meta ) {
	t( 'A the test site\'s wp-config.php found', false );
} else {
	$mode = $root ? 0440 : 0640;
	chmod( $config, $mode );
	if ( $root ) {
		chown( $config, $uid );
		chgrp( $config, $gid );
	}
	// As on the settings page (wp-admin): outside it the line waits ("deferred", see t_precheck.php).
	require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
	WP_Screen::get( 'settings_page_scrapelock' )->set_current_screen();
	settings( array( 'precheck' => 1 ) );
	$pdir_was_new = ! is_dir( PNCP_Precheck::dir() );
	PNCP_Precheck::sync();
	t( sprintf( 'A sync(): the line is in the site\'s wp-config.php (%04o)', $mode ), PNCP_Precheck::in_config(), (string) get_option( PNCP_Precheck::STATUS ) );
	same( 'A sync(): the site\'s wp-config.php kept', $config, $uid, $gid, $mode );
	// The data folder in uploads (new here: the check was off), its files, and the queue of WP-CLI's changes.
	$pdir    = PNCP_Precheck::dir();
	if ( $pdir_was_new ) {
		same( 'A sync(): the new data folder belongs to the WordPress folder\'s owner', $pdir, $base_uid, $base_gid, fileperms( $pdir ) & 07777 );
	}
	same( 'A sync(): config.json', PNCP_Precheck::config_file(), $base_uid, $base_gid, FS_CHMOD_FILE );
	same( 'A sync(): crawlers.json', $pdir . '/crawlers.json', $base_uid, $base_gid, FS_CHMOD_FILE );
	same( 'A sync(): the folder\'s index.html', $pdir . '/index.html', $base_uid, $base_gid, FS_CHMOD_FILE );
	chmod( PNCP_Precheck::config_file(), 0640 );
	file_put_contents( PNCP_Precheck::config_file(), "{}\n" ); // Not current any more: written again.
	PNCP_Precheck::sync();
	same( 'A sync(): config.json rewritten, owner and mode kept', PNCP_Precheck::config_file(), $base_uid, $base_gid, 0640 );
	@unlink( $pdir . '/ops.log' );
	call( 'PNCP_Precheck', 'queue_op', 'unban', md5( '192.0.2.1' ), 0 );
	same( 'A ops.log: new, the WordPress folder\'s owner', $pdir . '/ops.log', $base_uid, $base_gid, 0644 );
	t( 'A no temporary file left in the data folder', array() === leftovers( $pdir ), implode( ' ', leftovers( $pdir ) ) );
	settings( array( 'precheck' => 0 ) );
	PNCP_Precheck::sync();
	t( 'A sync() off: the line removed', ! PNCP_Precheck::in_config() );
	same( 'A sync() off: the site\'s wp-config.php kept', $config, $uid, $gid, $mode );
	t( 'A sync(): no temporary copy next to wp-config.php', array() === leftovers( dirname( $config ), false ), implode( ' ', leftovers( dirname( $config ), false ) ) );
	PNCP_File_Owner::restore( $config, $conf_meta );
}

/* ---------- B. the early mu-plugin ---------- */

$early = PNCP_Early::path();
if ( file_exists( $early ) ) {
	unlink( $early );
}
settings( array( 'early_mode' => 1 ) );
t( 'B early: written', PNCP_Early::sync() && PNCP_Early::installed() );
same( 'B early: a new mu-plugin belongs to the WordPress folder\'s owner', $early, $base_uid, $base_gid, FS_CHMOD_FILE );
file_put_contents( $early, "\n", FILE_APPEND ); // Not current any more: written again.
chmod( $early, 0640 );
t( 'B early: written again', PNCP_Early::sync() && PNCP_Early::installed() );
same( 'B early: rewritten, owner and mode kept', $early, $base_uid, $base_gid, 0640 );
t( 'B early: no temporary file left in mu-plugins', array() === leftovers( $mu, false ), implode( ' ', leftovers( $mu, false ) ) );
settings( array( 'early_mode' => 0 ) );
PNCP_Early::sync();
t( 'B early off: removed', ! file_exists( $early ) );

/* ---------- C. the Lockdown guard and the lock file ---------- */

$guard = PNCP_Seal::path();
PNCP_Seal::remove_guard();
if ( ! PNCP_Seal::can_write_guard() ) {
	skip( 'C the guard cannot be written here' );
} else {
	// Locked, but open for the next hour: the guard does nothing in the meantime.
	t( 'C guard: written', PNCP_Seal::write_guard( true, time() + 3600 ) && is_file( $guard ) );
	same( 'C guard: a new guard belongs to the WordPress folder\'s owner', $guard, $base_uid, $base_gid, FS_CHMOD_FILE );
	chmod( $guard, 0640 );
	t( 'C guard: written again', PNCP_Seal::write_guard( true, time() + 3500 ) );
	same( 'C guard: rewritten, owner and mode kept', $guard, $base_uid, $base_gid, 0640 );
	t( 'C guard: no temporary file left in mu-plugins', array() === leftovers( $mu, false ), implode( ' ', leftovers( $mu, false ) ) );
	PNCP_Seal::remove_guard();
	t( 'C guard: removed', ! file_exists( $guard ) );
}
$bdir = $fake . '/scrapelock-lockdown';
t( 'C lock file: written', call( 'PNCP_Seal', 'beacon_put', $bdir, 'lock-test.php', "<?php exit; ?>\n{}" ) );
same( 'C lock file: its new folder', $bdir, $base_uid, $base_gid, 0755 );
same( 'C lock file: index.php', $bdir . '/index.php', $base_uid, $base_gid, 0644 );
same( 'C lock file: .htaccess', $bdir . '/.htaccess', $base_uid, $base_gid, 0644 );
same( 'C lock file: new, 0644', $bdir . '/lock-test.php', $base_uid, $base_gid, 0644 );
chmod( $bdir . '/lock-test.php', 0600 );
t( 'C lock file: written again', call( 'PNCP_Seal', 'beacon_put', $bdir, 'lock-test.php', "<?php exit; ?>\n{\"a\":1}" ) );
same( 'C lock file: rewritten, owner and mode kept', $bdir . '/lock-test.php', $base_uid, $base_gid, 0600 );

/* ---------- D. the guard's counters and lock file ---------- */

PNCP_Lockdown::fails_remove();
$ffile = PNCP_Lockdown::fails_file();
$ok    = call(
	'PNCP_Lockdown',
	'fails_file_put',
	array(
		'seq'  => 1,
		'rows' => array(),
	),
	$ffile
);
t( 'D counters: written', $ok && is_file( $ffile ) );
same( 'D counters: the new folder', dirname( $ffile ), $base_uid, $base_gid, fileperms( dirname( $ffile ) ) & 07777 );
same( 'D counters: index.php', dirname( $ffile ) . '/index.php', $base_uid, $base_gid, $root ? 0644 : ( 0666 & ~umask() ) );
same( 'D counters: fails.php', $ffile, $base_uid, $base_gid, $root ? 0644 : ( 0666 & ~umask() ) );
PNCP_Lockdown::fails_remove();
if ( file_exists( $lock ) ) {
	unlink( $lock );
}
call( 'PNCP_Lockdown', 'local_lock', 0.0 );
call( 'PNCP_Lockdown', 'local_unlock' );
same( 'D lock file: a new one', $lock, $base_uid, $base_gid, $root ? 0644 : ( 0666 & ~umask() ) );

/* ---------- E. .htaccess ---------- */

$ht = $fake . '/.htaccess';
seed( $ht, "# BEGIN WordPress\n# END WordPress\n", 0640 );
t( 'E .htaccess: written', call( 'PNCP_Hardening', 'put_htaccess', $ht, "# x\n# BEGIN WordPress\n# END WordPress\n" ) && "# x\n# BEGIN WordPress\n# END WordPress\n" === file_get_contents( $ht ) );
same( 'E .htaccess: owner and mode kept', $ht, $uid, $gid, 0640 );
mkdir( $fake . '/sub' );
t( 'E .htaccess: a new one written', call( 'PNCP_Hardening', 'put_htaccess', $fake . '/sub/.htaccess', "# x\n" ) );
same( 'E .htaccess: a new one is 0644, the WordPress folder\'s owner', $fake . '/sub/.htaccess', $base_uid, $base_gid, 0644 );
seed( $fake . '/shared.htaccess', "# shared\n", 0640 );
symlink( $fake . '/shared.htaccess', $fake . '/sub2.htaccess' );
t( 'E .htaccess: a symlinked one is written through the link', call( 'PNCP_Hardening', 'put_htaccess', $fake . '/sub2.htaccess', "# shared 2\n" ) && is_link( $fake . '/sub2.htaccess' ) && "# shared 2\n" === file_get_contents( $fake . '/shared.htaccess' ) );
same( 'E .htaccess: the link\'s target kept', $fake . '/shared.htaccess', $uid, $gid, 0640 );

/* ---------- F. WP-CLI: rules install and --save-constant ---------- */

if ( '' === $wp_cli ) {
	skip( 'F without WP_CLI' );
} else {
	settings( array( 'private_paths' => '' ) );
	$conf = $fake . '/scrapelock.conf';
	seed( $conf, "# old\n", 0640 );
	list( $rc, $out ) = cli( 'rules install --nginx-server=' . escapeshellarg( $conf ) . ' --yes --test-cmd=true --reload-cmd=true' );
	t( 'F rules install: written', 0 === $rc && PNCP_Rules::nginx_server() === file_get_contents( $conf ), $out );
	same( 'F rules install: owner and mode kept', $conf, $uid, $gid, 0640 );

	mkdir( $in_core, 0755 );
	list( $rc, $out ) = cli( 'rules install --apache=' . escapeshellarg( $in_core . '/.htaccess' ) . ' --yes --test-cmd=true --reload-cmd=true' );
	t( 'F rules install: a new .htaccess in the WordPress folder', 0 === $rc && is_file( $in_core . '/.htaccess' ), $out );
	same( 'F rules install: the new .htaccess is 0644, the WordPress folder\'s owner', $in_core . '/.htaccess', $base_uid, $base_gid, 0644 );

	mkdir( $fake . '/etc' );
	list( $rc, $out ) = cli( 'rules install --nginx-server=' . escapeshellarg( $fake . '/etc/new.conf' ) . ' --yes --test-cmd=true --reload-cmd=true' );
	clearstatcache();
	t( 'F rules install: a new server file (.conf)', 0 === $rc && is_file( $fake . '/etc/new.conf' ), $out );
	if ( $root ) {
		t( 'F rules install: ...stays root\'s (never handed to the web server\'s user)', 0 === fileowner( $fake . '/etc/new.conf' ), meta( $fake . '/etc/new.conf' ) );
	}
	t( 'F rules install: no .new / .old left', array() === leftovers( $fake ) && array() === leftovers( $in_core ), implode( ' ', array_merge( leftovers( $fake ), leftovers( $in_core ) ) ) );

	if ( '' === $config ) {
		skip( 'F --save-constant: no wp-config.php' );
	} else {
		$copy = $fake . '/site/wp-config.php';
		mkdir( dirname( $copy ), 0755 );
		mkdir( $fake . '/fcgi', 0755 );
		$mode = $root ? 0440 : 0640;
		seed( $copy, $conf_text, $mode );
		list( $rc, $out ) = cli( 'cache status --save-constant --yes --cache-dir=' . escapeshellarg( $fake . '/fcgi' ), 'WP_CONFIG_PATH=' . escapeshellarg( $copy ) );
		t( 'F --save-constant: added to the copy of wp-config.php', 0 === $rc && false !== strpos( (string) file_get_contents( $copy ), 'SCRAPELOCK_FASTCGI_CACHE_PATH' ), $out );
		same( 'F --save-constant: owner and mode kept', $copy, $uid, $gid, $mode );
	}
}

t( 'no *.tmp file left in the fake folder, mu-plugins or the WordPress folder', array() === leftovers( $fake ) && array() === leftovers( $mu, false ) && array() === leftovers( $core, false ), implode( ' ', array_merge( leftovers( $fake ), leftovers( $mu, false ), leftovers( $core, false ) ) ) );

exit( $fails ? 1 : 0 );
