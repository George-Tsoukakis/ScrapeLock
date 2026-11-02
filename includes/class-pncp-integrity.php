<?php
/**
 * Lockdown, file integrity: what the code of the site looked like when it was locked, and what changed since.
 *
 * While the site is locked nobody may install or update anything, so a new or changed PHP file means that
 * something wrote it on its own: usually a vulnerable plugin used to upload a backdoor. The fingerprint is
 * taken when the site is locked (and again after a temporary unlock, when updates are allowed) and checked
 * every hour. The core files and the plugins hosted on WordPress.org are also compared with their official
 * checksums, which catches a change made before the site was locked.
 *
 * A limit, said plainly: code that already runs on the server can also stop ScrapeLock. The check finds the
 * change and tells you; the server rule that refuses PHP in the uploads folder is what stops most backdoors
 * from running at all.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Fingerprint, hourly check, official checksums, report and optional quarantine.
 */
final class PNCP_Integrity {

	const BASELINE = 'pncp_integrity';
	const REPORT   = 'pncp_integrity_report';
	const ACTION   = 'pncp_integrity_check';
	const OFFICIAL = 'pncp_integrity_official';

	/**
	 * Most seconds spent on the official checksums in one run: what is left is checked on the next run.
	 */
	const OFFICIAL_SECONDS = 60;

	/**
	 * Most files read in one pass, and most seconds spent: on a very large site the pass stops and says so.
	 */
	const MAX_FILES   = 60000;
	const MAX_SECONDS = 25;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( PNCP_Log::CRON, array( __CLASS__, 'cron' ), 20 );
		add_action( self::OFFICIAL, array( __CLASS__, 'run_official' ) );
		add_action( 'init', array( __CLASS__, 'ensure_cron' ) );
		if ( is_admin() ) {
			add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
			add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
			add_action( 'network_admin_notices', array( __CLASS__, 'notice' ) );
		}
	}

	/* ---------- Which files ---------- */

	/**
	 * Is it a file that can run code or change how code runs? PHP of every kind, and the .htaccess and
	 * .user.ini files that can make other files run as PHP or load one before every request.
	 *
	 * @param string $name File name.
	 * @return bool
	 */
	public static function is_code( $name ) {
		$name = strtolower( basename( (string) $name ) );
		return '.htaccess' === $name || '.user.ini' === $name || (bool) preg_match( '/\.(?:php[0-9]?|phtml|phar|inc)$/', $name );
	}

	/**
	 * Folders that change by themselves and are left out: caches, the updater's work folders, the logs of
	 * other security plugins and the pre-cache check's own files. Filter `pncp_integrity_exclude`
	 * (paths relative to wp-content, or folder names that are skipped anywhere).
	 *
	 * @return array{paths:string[], names:string[]}
	 */
	private static function excluded() {
		return (array) apply_filters(
			'pncp_integrity_exclude',
			array(
				'paths' => array( 'upgrade', 'upgrade-temp-backup', 'wflogs', 'et-cache', 'litespeed', 'w3tc-config' ),
				'names' => array( 'cache', '.git', 'node_modules' ),
			)
		);
	}

	/**
	 * Where this site keeps its files, found with WordPress' functions (PNCP_Paths, wp_get_upload_dir(),
	 * search_theme_directories()). The check reads them only (the optional quarantine renames a new PHP file
	 * in uploads).
	 *
	 * @return array{core:string, content:string, plugins:string, mu_plugins:string, uploads:string, themes:string[], config:string}
	 */
	public static function locations() {
		$uploads = wp_get_upload_dir();
		$themes  = array();
		foreach ( (array) search_theme_directories() as $theme ) {
			if ( ! empty( $theme['theme_root'] ) ) {
				$themes[ self::path( $theme['theme_root'] ) ] = true;
			}
		}
		$themes[ self::path( get_theme_root() ) ] = true;
		$config                                   = PNCP_Paths::config();
		return array(
			'core'       => PNCP_Paths::core(),
			'content'    => PNCP_Paths::content(),
			'plugins'    => PNCP_Paths::plugins(),
			'mu_plugins' => PNCP_Paths::mu_plugins(),
			'uploads'    => ! empty( $uploads['basedir'] ) ? self::path( $uploads['basedir'] ) : '',
			'themes'     => array_keys( $themes ),
			'config'     => '' !== $config ? self::path( $config ) : '',
		);
	}

	/**
	 * A path with forward slashes and without a trailing slash.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	private static function path( $path ) {
		return untrailingslashit( wp_normalize_path( (string) $path ) );
	}

	/**
	 * The folders read: the WordPress folder (only its own files), wp-admin, wp-includes, wp-content (all of it,
	 * uploads included: a PHP file there is the first thing to look for) and, when they live elsewhere, the
	 * plugin, must-use plugin, theme and uploads folders.
	 *
	 * @return array<int, array{0:string, 1:bool}> Folder => read subfolders.
	 */
	private static function roots() {
		$where = self::locations();
		$roots = array(
			array( $where['core'], false ),
			array( $where['core'] . '/wp-admin', true ),
			array( $where['core'] . '/' . WPINC, true ),
			array( $where['content'], true ),
		);
		foreach ( array_merge( array( $where['plugins'], $where['mu_plugins'], $where['uploads'] ), $where['themes'] ) as $dir ) {
			if ( '' !== $dir && 0 !== strpos( $dir . '/', $where['content'] . '/' ) ) {
				$roots[] = array( $dir, true );
			}
		}
		return $roots;
	}

	/**
	 * Reads the code files and their SHA-256.
	 *
	 * @param bool $quick Reuse the hash of a file whose size, times and inode have not changed since the last
	 *                    pass (the hourly check). The change time (ctime) is set by the system on every write
	 *                    and cannot be set back by a script, so a changed file is never missed; a full pass
	 *                    still runs once a day.
	 * @return array{files: array<string, string>, md5: array<string, string>, complete: bool}
	 */
	public static function collect( $quick = false ) {
		$known = $quick ? self::stat_cache() : null;
		$stats = array();
		$start    = microtime( true );
		$files    = array();
		$md5      = array(); // Kept for this request only: the official checksums are MD5.
		$complete = true;
		$seen     = array();
		$where    = self::locations();
		$content  = $where['content'];
		$skip     = self::excluded();
		$paths    = array();
		foreach ( (array) $skip['paths'] as $path ) {
			$paths[] = $content . '/' . trim( wp_normalize_path( (string) $path ), '/' ) . '/';
		}
		$names = array_map( 'strtolower', (array) $skip['names'] );

		// wp-config.php one level above the WordPress folder is not in any folder that is read.
		$config = $where['config'];
		if ( '' !== $config && dirname( $config ) !== $where['core'] && is_readable( $config ) ) {
			$files[ $config ] = (string) hash_file( 'sha256', $config );
		}

		foreach ( self::roots() as list( $root, $deep ) ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			$stack = array( $root );
			while ( $stack ) {
				$dir  = array_pop( $stack );
				$real = realpath( $dir );
				if ( false === $real || isset( $seen[ $real ] ) ) {
					continue; // A folder reached twice (symbolic links) is read once.
				}
				$seen[ $real ] = true;
				$entries       = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- An unreadable folder is skipped.
				if ( false === $entries ) {
					continue;
				}
				foreach ( $entries as $entry ) {
					if ( '.' === $entry || '..' === $entry ) {
						continue;
					}
					$path = $dir . '/' . $entry;
					if ( is_dir( $path ) ) {
						// The WordPress root is read without its subfolders: wp-admin, wp-includes and wp-content are roots of their own.
						if ( $deep && ! in_array( strtolower( $entry ), $names, true ) && ! self::starts_with_any( $path . '/', $paths ) ) {
							$stack[] = $path;
						}
						continue;
					}
					if ( ! self::is_code( $entry ) || ! is_readable( $path ) ) {
						continue;
					}
					if ( count( $files ) >= self::MAX_FILES || microtime( true ) - $start > self::MAX_SECONDS ) {
						$complete = false;
						break 3;
					}
					$stat = @stat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable = hashed below.
					$sig  = false !== $stat ? $stat['size'] . ':' . $stat['mtime'] . ':' . $stat['ctime'] . ':' . $stat['ino'] : '';
					if ( '' !== $sig && null !== $known && isset( $known[ $path ] ) && $known[ $path ][0] === $sig ) {
						$files[ $path ] = $known[ $path ][1];
						$stats[ $path ] = $known[ $path ];
						continue;
					}
					$hashes = self::hash_both( $path );
					if ( null === $hashes ) {
						// Cannot be read now (e.g. its permissions were changed): it stays in the list with an empty
						// hash, so the change is reported instead of the file silently leaving the fingerprint.
						$files[ $path ] = '';
						continue;
					}
					$files[ $path ] = $hashes[0];
					$md5[ $path ]   = $hashes[1];
					if ( '' !== $sig ) {
						$stats[ $path ] = array( $sig, $hashes[0] );
					}
				}
			}
		}
		ksort( $files );
		if ( $complete ) {
			self::save_stat_cache( $stats, null === $known );
		}
		return array(
			'files'    => $files,
			'md5'      => $md5,
			'complete' => $complete,
		);
	}

	/**
	 * The size, times and inode of each file at the last pass, with its hash: null when there is none, when it
	 * does not match its signature, or when the last full pass is more than a day old (then a full pass runs).
	 *
	 * @return array<string, array{0:string, 1:string}>|null
	 */
	private static function stat_cache() {
		$stored = get_option( 'pncp_integrity_stat' );
		if ( ! is_array( $stored ) || ! isset( $stored['full'], $stored['data'], $stored['sig'] ) || time() - (int) $stored['full'] > DAY_IN_SECONDS ) {
			return null;
		}
		$sig = $stored['sig'];
		unset( $stored['sig'] );
		if ( ! PNCP_Seal::valid( $stored, $sig ) ) {
			return null;
		}
		$raw  = base64_decode( (string) $stored['data'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Our own compressed data.
		$json = false !== $raw ? @gzuncompress( $raw ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Damaged = full pass.
		$data = false !== $json ? json_decode( $json, true ) : null;
		return is_array( $data ) ? $data : null;
	}

	/**
	 * Stores the file details of this pass (signed, not autoloaded).
	 *
	 * @param array<string, array{0:string, 1:string}> $stats Path => [size:mtime:ctime:inode, SHA-256].
	 * @param bool                                     $full  Whether every file was read in this pass.
	 */
	private static function save_stat_cache( $stats, $full ) {
		$old    = get_option( 'pncp_integrity_stat' );
		$record = array(
			'full' => $full || ! is_array( $old ) || ! isset( $old['full'] ) ? time() : (int) $old['full'],
			'data' => base64_encode( (string) gzcompress( (string) wp_json_encode( $stats ), 6 ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Compressed data stored as text.
		);
		$record['sig'] = PNCP_Seal::sign( $record );
		if ( false === $old ) {
			add_option( 'pncp_integrity_stat', $record, '', false );
		} else {
			update_option( 'pncp_integrity_stat', $record, false );
		}
	}

	/**
	 * SHA-256 (the fingerprint) and MD5 (what WordPress.org publishes) of a file, from a single read.
	 *
	 * @param string $path File.
	 * @return array{0:string, 1:string}|null Null if it cannot be read.
	 */
	private static function hash_both( $path ) {
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Reading a local file; unreadable = skipped.
		if ( false === $handle ) {
			return null;
		}
		$sha = hash_init( 'sha256' );
		$md5 = hash_init( 'md5' );
		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, 1048576 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Local file.
			if ( false === $chunk ) {
				break;
			}
			hash_update( $sha, $chunk );
			hash_update( $md5, $chunk );
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Local file.
		return array( hash_final( $sha ), hash_final( $md5 ) );
	}

	/**
	 * Does the path start with any of the prefixes?
	 *
	 * @param string   $path     Path.
	 * @param string[] $prefixes Prefixes.
	 * @return bool
	 */
	private static function starts_with_any( $path, $prefixes ) {
		foreach ( $prefixes as $prefix ) {
			if ( 0 === strpos( $path, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/* ---------- Storage ---------- */

	/**
	 * Reads a stored value (a site option on multisite).
	 *
	 * @param string $name Option.
	 * @return mixed
	 */
	private static function get( $name ) {
		return is_multisite() ? get_site_option( $name, array() ) : get_option( $name, array() );
	}

	/**
	 * Stores a value, never autoloaded: the fingerprint of a large site is big and is needed once an hour.
	 *
	 * @param string $name  Option.
	 * @param mixed  $value Value.
	 */
	private static function put( $name, $value ) {
		if ( is_multisite() ) {
			update_site_option( $name, $value );
			return;
		}
		if ( false === get_option( $name, false ) ) {
			add_option( $name, $value, '', false );
		} else {
			update_option( $name, $value, false );
		}
	}

	/**
	 * The stored fingerprint.
	 *
	 * @return array{time:int, files:array<string,string>, complete:bool, stale:bool}
	 */
	public static function baseline() {
		$stored   = self::get( self::BASELINE );
		$files    = array();
		$tampered = false;
		if ( is_array( $stored ) && $stored ) {
			$sig = isset( $stored['sig'] ) ? $stored['sig'] : null;
			unset( $stored['sig'] );
			$tampered = null === $sig ? ! PNCP_Seal::legacy() : ! PNCP_Seal::valid( $stored, $sig );
		}
		// The signed lock state notes the time of the fingerprint: a fingerprint that was removed, or put back
		// from an older copy, no longer matches it.
		$fp = (int) PNCP_Lockdown::state()['fp'];
		if ( $fp > 0 && ( ! is_array( $stored ) || ! isset( $stored['time'] ) || (int) $stored['time'] !== $fp ) ) {
			$tampered = true;
		}
		if ( is_array( $stored ) && ! empty( $stored['files'] ) ) {
			$raw   = base64_decode( (string) $stored['files'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Our own compressed list of file hashes.
			$json  = false !== $raw ? @gzuncompress( $raw ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Damaged data = no fingerprint.
			$files = false !== $json ? json_decode( $json, true ) : array();
		}
		return array(
			'time'     => is_array( $stored ) && isset( $stored['time'] ) ? (int) $stored['time'] : 0,
			'files'    => is_array( $files ) ? $files : array(),
			'complete' => ! is_array( $stored ) || ! isset( $stored['complete'] ) || ! empty( $stored['complete'] ),
			'stale'    => is_array( $stored ) && ! empty( $stored['stale'] ),
			'tampered' => $tampered,
		);
	}

	/**
	 * Stores the fingerprint with its signature.
	 *
	 * @param array<string, mixed> $value Fingerprint.
	 */
	private static function put_baseline( $value ) {
		unset( $value['sig'] );
		$value['sig'] = PNCP_Seal::sign( $value );
		self::put( self::BASELINE, $value );
	}

	/**
	 * The upgrade to 3.3: signs a fingerprint stored before signatures existed.
	 *
	 * @return int Its time (0 = none).
	 */
	public static function resign() {
		$stored = self::get( self::BASELINE );
		if ( ! is_array( $stored ) || empty( $stored['time'] ) ) {
			return 0;
		}
		self::put_baseline( $stored );
		return (int) $stored['time'];
	}

	/**
	 * The last report.
	 *
	 * @return array<string, mixed>
	 */
	public static function report() {
		$report = self::get( self::REPORT );
		return array_merge(
			array(
				'time'     => 0,
				'added'    => array(),
				'changed'  => array(),
				'removed'  => array(),
				'complete' => true,
				'official' => array(),
				'handled'  => array(),
				'tampered' => false,
			),
			is_array( $report ) ? $report : array()
		);
	}

	/**
	 * Takes a new fingerprint (when the site is locked, and again after a temporary unlock) and checks the
	 * official checksums.
	 */
	public static function snapshot() {
		self::more_time();
		$now  = self::collect();
		$raw  = gzcompress( (string) wp_json_encode( $now['files'] ), 6 );
		$time = time();
		self::put_baseline(
			array(
				'time'     => $time,
				'files'    => base64_encode( (string) $raw ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Compressed list of file hashes, stored as text.
				'complete' => $now['complete'],
				'stale'    => false,
			)
		);
		PNCP_Lockdown::note_fingerprint( $time );
		$report             = self::report();
		$report['tampered'] = false;
		$report['time']     = time();
		$report['added']    = array();
		$report['changed']  = array();
		$report['removed']  = array();
		$report['complete'] = $now['complete'];
		$report['handled']  = array();
		// The official checksums (one request to WordPress.org per plugin) are compared right after, from a
		// scheduled event: locking the site does not wait for them. Until then the report says "pending".
		$report['official'] = array( 'pending' => true );
		self::put( self::REPORT, $report );
		delete_option( 'pncp_integrity_alerted' ); // A new fingerprint: what is flagged from now on is new.
		self::schedule_official();
	}

	/**
	 * Schedules the comparison with the official checksums, to run in the background now.
	 */
	public static function schedule_official() {
		if ( ! wp_next_scheduled( self::OFFICIAL ) ) {
			wp_schedule_single_event( time(), self::OFFICIAL );
		}
		if ( function_exists( 'spawn_cron' ) ) {
			spawn_cron();
		}
	}

	/**
	 * The scheduled comparison with the official checksums (after a new fingerprint): fills in the report and
	 * emails what it finds.
	 */
	public static function run_official() {
		self::more_time();
		$base   = self::baseline();
		$report = self::report();
		if ( $base['tampered'] || ! $base['files'] ) {
			return;
		}
		$report['official'] = self::official( $base['files'] );
		self::put( self::REPORT, $report );
		self::alert( $report );
	}

	/**
	 * More time for the PHP request that reads the files (where the host allows it), so that a large site is not
	 * cut off half-way by max_execution_time.
	 */
	private static function more_time() {
		if ( function_exists( 'set_time_limit' ) && false === strpos( (string) ini_get( 'disable_functions' ), 'set_time_limit' ) ) {
			@set_time_limit( 300 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Not allowed on every host.
		}
	}

	/**
	 * After an unlock, updates may change files on purpose: the next check takes a new fingerprint instead of
	 * reporting them.
	 */
	public static function mark_stale() {
		$stored = self::get( self::BASELINE );
		if ( is_array( $stored ) && $stored && ! self::baseline()['tampered'] ) {
			$stored['stale'] = true;
			self::put_baseline( $stored );
		}
	}

	/* ---------- The check ---------- */

	/**
	 * The hourly check, only while the site is locked.
	 */
	public static function cron() {
		if ( PNCP_Lockdown::is_locked() ) {
			self::check();
			PNCP_Seal::check_admins();
		}
	}

	/**
	 * While locked, the hourly check must keep running: if its scheduled event is gone (removed by other code,
	 * or lost), it is scheduled again.
	 */
	public static function ensure_cron() {
		if ( PNCP_Lockdown::is_locked() && ! wp_next_scheduled( PNCP_Log::CRON ) ) {
			wp_schedule_event( time() + 5 * MINUTE_IN_SECONDS, 'hourly', PNCP_Log::CRON );
		}
	}

	/**
	 * Compares the files now with the fingerprint. Without one, or after a temporary unlock, it takes one.
	 *
	 * @return array<string, mixed> The report.
	 */
	public static function check() {
		self::more_time();
		$base = self::baseline();
		if ( $base['tampered'] ) {
			// Never a new fingerprint here: it would accept whatever was hidden. Reported until the site is
			// locked again (which takes a new one).
			$report             = self::report();
			$report['time']     = time();
			$report['tampered'] = true;
			self::put( self::REPORT, $report );
			PNCP_Lockdown::tamper_alert( 'fingerprint' );
			return self::report();
		}
		if ( ! $base['time'] || $base['stale'] ) {
			self::snapshot();
			return self::report();
		}
		$now     = self::collect( true );
		$added   = array_keys( array_diff_key( $now['files'], $base['files'] ) );
		$removed = $now['complete'] ? array_keys( array_diff_key( $base['files'], $now['files'] ) ) : array();
		$changed = array();
		foreach ( array_intersect_key( $now['files'], $base['files'] ) as $path => $hash ) {
			if ( $base['files'][ $path ] !== $hash ) {
				$changed[] = $path;
			}
		}
		$report             = self::report();
		$report['time']     = time();
		$report['added']    = $added;
		$report['changed']  = $changed;
		$report['removed']  = $removed;
		$report['complete'] = $now['complete'] && $base['complete'];
		// The official checksums once a day: each plugin is one request to WordPress.org.
		if ( empty( $report['official']['time'] ) || time() - (int) $report['official']['time'] > DAY_IN_SECONDS ) {
			$report['official'] = self::official( $now['files'], $now['md5'] );
		}
		self::put( self::REPORT, $report );
		self::alert( $report );
		if ( self::findings( $report ) && PNCP_Lockdown::quarantine_on() ) {
			self::quarantine();
		}
		return self::report();
	}

	/**
	 * Every file the report flags, with what it is: added, changed, removed while locked, or different from
	 * WordPress.org.
	 *
	 * @param array<string, mixed> $report Report.
	 * @return array<string, string> Path => kind.
	 */
	public static function findings( $report ) {
		$out = array();
		foreach ( array( 'added', 'changed', 'removed' ) as $kind ) {
			foreach ( (array) $report[ $kind ] as $path ) {
				$out[ (string) $path ] = $kind;
			}
		}
		$official = (array) $report['official'];
		foreach ( array( 'modified', 'unknown' ) as $kind ) {
			foreach ( isset( $official[ $kind ] ) ? (array) $official[ $kind ] : array() as $path ) {
				if ( ! isset( $out[ (string) $path ] ) ) {
					$out[ (string) $path ] = 'official_' . $kind;
				}
			}
		}
		return $out;
	}

	/**
	 * Emails the administration address and logs the event when a file is flagged that was not flagged before
	 * (since the last fingerprint): not again every hour for the same files, nor when some of them are gone.
	 *
	 * @param array<string, mixed> $report Report.
	 */
	private static function alert( $report ) {
		$found = self::findings( $report );
		$sent  = get_option( 'pncp_integrity_alerted', array() );
		$sent  = is_array( $sent ) ? $sent : array();
		$keys  = array();
		foreach ( $found as $path => $kind ) {
			$keys[] = md5( $path . '|' . $kind );
		}
		if ( ! array_diff( $keys, $sent ) ) {
			return;
		}
		update_option( 'pncp_integrity_alerted', array_slice( array_values( array_unique( array_merge( $sent, $keys ) ) ), -5000 ), false );
		$lines = array();
		foreach ( array_slice( $found, 0, 50, true ) as $path => $kind ) {
			$lines[] = '- ' . self::kind_label( $kind ) . ': ' . self::relative( $path );
		}
		if ( count( $found ) > 50 ) {
			/* translators: %d: number of files */
			$lines[] = sprintf( __( '… and %d more.', 'scrapelock' ), count( $found ) - 50 );
		}
		PNCP_Lockdown::record( 'integrity', (string) count( $found ) );
		$to = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
		if ( is_email( $to ) ) {
			wp_mail(
				$to,
				'[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] ScrapeLock: ' . __( 'Changed files found', 'scrapelock' ),
				__( 'ScrapeLock found code files that were added or changed while the site was locked, or that differ from the official copies on WordPress.org. Nobody can install or update anything while the site is locked, so check them: a file you do not recognise is often a backdoor uploaded through a vulnerable plugin.', 'scrapelock' ) . "\n\n" . implode( "\n", $lines ) . "\n\n" . PNCP_Lockdown::page_url()
			);
		}
	}

	/**
	 * Readable name of a kind of finding.
	 *
	 * @param string $kind Kind.
	 * @return string
	 */
	public static function kind_label( $kind ) {
		$labels = array(
			'added'             => __( 'New while locked', 'scrapelock' ),
			'changed'           => __( 'Changed while locked', 'scrapelock' ),
			'removed'           => __( 'Removed while locked', 'scrapelock' ),
			'official_modified' => __( 'Differs from WordPress.org', 'scrapelock' ),
			'official_unknown'  => __( 'Not part of the WordPress.org copy', 'scrapelock' ),
		);
		return isset( $labels[ $kind ] ) ? $labels[ $kind ] : $kind;
	}

	/**
	 * A path relative to the WordPress folder, for reading.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function relative( $path ) {
		$base = trailingslashit( self::locations()['core'] );
		$path = wp_normalize_path( (string) $path );
		return 0 === strpos( $path, $base ) ? substr( $path, strlen( $base ) ) : $path;
	}

	/* ---------- Official checksums ---------- */

	/**
	 * Compares WordPress itself and the plugins hosted on WordPress.org with their official checksums (the same
	 * lists "wp core verify-checksums" and "wp plugin verify-checksums" use). Only code files are compared.
	 * Plugins that are not on WordPress.org (premium, custom) cannot be checked and are listed as such.
	 *
	 * @param array<string, string>      $files Code files found now (path => SHA-256).
	 * @param array<string, string>|null $md5   Their MD5, if already read (otherwise read here).
	 * @return array{time:int, modified:string[], unknown:string[], unverified:string[], core:bool}
	 */
	public static function official( $files, $md5 = null ) {
		$md5   = is_array( $md5 ) ? $md5 : array();
		$start = microtime( true );
		$sum   = static function ( $path ) use ( $md5 ) {
			return isset( $md5[ $path ] ) ? $md5[ $path ] : (string) md5_file( $path );
		};
		$out   = array(
			'time'       => time(),
			'modified'   => array(),
			'unknown'    => array(),
			'unverified' => array(),
			'core'       => false,
		);
		$where = self::locations();
		$base  = trailingslashit( $where['core'] );

		// WordPress itself: wp-admin, wp-includes and the files in its root folder.
		$core = self::core_checksums( get_bloginfo( 'version' ), get_locale() );
		if ( null === $core && 'en_US' !== get_locale() ) {
			$core = self::core_checksums( get_bloginfo( 'version' ), 'en_US' );
		}
		if ( is_array( $core ) && $core ) {
			$out['core'] = true;
			foreach ( $core as $rel => $expected ) {
				if ( 0 === strpos( $rel, 'wp-content/' ) || ! self::is_code( $rel ) || ! file_exists( $base . $rel ) ) {
					continue;
				}
				if ( $sum( $base . $rel ) !== $expected ) {
					$out['modified'][] = $base . $rel;
				}
			}
			foreach ( array_keys( $files ) as $path ) {
				$rel = 0 === strpos( $path, $base ) ? substr( $path, strlen( $base ) ) : '';
				if ( '' !== $rel && preg_match( '#^wp-(?:admin|includes)/#', $rel ) && ! isset( $core[ $rel ] ) ) {
					$out['unknown'][] = $path;
				}
			}
		}

		// Plugins hosted on WordPress.org.
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugin_dir = trailingslashit( $where['plugins'] );
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' === $slug || empty( $data['Version'] ) ) {
				continue;
			}
			if ( microtime( true ) - $start > self::OFFICIAL_SECONDS ) {
				$out['unverified'][] = $slug; // Out of time for this run: checked on the next one.
				continue;
			}
			$sums = self::plugin_checksums( $slug, (string) $data['Version'] );
			if ( null === $sums ) {
				$out['unverified'][] = $slug;
				continue;
			}
			$dir = $plugin_dir . $slug . '/';
			foreach ( $sums as $rel => $sum_data ) {
				if ( ! self::is_code( $rel ) || ! file_exists( $dir . $rel ) ) {
					continue;
				}
				$expected = isset( $sum_data['md5'] ) ? (array) $sum_data['md5'] : array();
				if ( $expected && ! in_array( $sum( $dir . $rel ), $expected, true ) ) {
					$out['modified'][] = $dir . $rel;
				}
			}
			foreach ( array_keys( $files ) as $path ) {
				if ( 0 === strpos( $path, $dir ) && ! isset( $sums[ substr( $path, strlen( $dir ) ) ] ) ) {
					$out['unknown'][] = $path;
				}
			}
		}
		foreach ( array( 'modified', 'unknown' ) as $kind ) {
			$out[ $kind ] = array_slice( array_values( array_unique( $out[ $kind ] ) ), 0, 500 );
		}
		return $out;
	}

	/**
	 * The official checksums of a WordPress version (the list get_core_checksums() reads, without its PHP
	 * warning when WordPress.org cannot be reached: this runs every day from cron).
	 *
	 * @param string $version WordPress version.
	 * @param string $locale  Locale.
	 * @return array<string, string>|null Path => MD5, or null.
	 */
	private static function core_checksums( $version, $locale ) {
		// The checksums of a release never change: kept for a week (a missing answer for a day).
		$key    = 'pncp_cs_core_' . md5( $version . '|' . $locale );
		$cached = get_site_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached ? $cached : null;
		}
		$sums = self::fetch_core_checksums( $version, $locale );
		set_site_transient( $key, null === $sums ? array() : $sums, null === $sums ? DAY_IN_SECONDS : WEEK_IN_SECONDS );
		return $sums;
	}

	/**
	 * Downloads the official checksums of a WordPress version.
	 *
	 * @param string $version WordPress version.
	 * @param string $locale  Locale.
	 * @return array<string, string>|null Path => MD5, or null.
	 */
	private static function fetch_core_checksums( $version, $locale ) {
		$response = wp_remote_get(
			'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
				array(
					'version' => $version,
					'locale'  => $locale,
				),
				'',
				'&'
			),
			array( 'timeout' => 10 )
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		$sums = is_array( $data ) && isset( $data['checksums'] ) && is_array( $data['checksums'] ) ? $data['checksums'] : array();
		// Asked for several versions, the API answers per version.
		if ( isset( $sums[ $version ] ) && is_array( $sums[ $version ] ) ) {
			$sums = $sums[ $version ];
		}
		return $sums ? $sums : null;
	}

	/**
	 * The official checksums of a plugin version on WordPress.org (null = not available: not hosted there,
	 * or no answer).
	 *
	 * @param string $slug    Plugin folder.
	 * @param string $version Version.
	 * @return array<string, array<string, mixed>>|null
	 */
	private static function plugin_checksums( $slug, $version ) {
		// A plugin version's checksums never change: kept for a week, so locking again after an unlock only asks
		// for the plugins that were updated. "Not on WordPress.org" (premium, custom) is kept for a day.
		$key    = 'pncp_cs_' . md5( $slug . '|' . $version );
		$cached = get_site_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached ? $cached : null;
		}
		$sums = self::fetch_plugin_checksums( $slug, $version );
		set_site_transient( $key, null === $sums ? array() : $sums, null === $sums ? DAY_IN_SECONDS : WEEK_IN_SECONDS );
		return $sums;
	}

	/**
	 * Downloads the official checksums of a plugin version.
	 *
	 * @param string $slug    Plugin folder.
	 * @param string $version Version.
	 * @return array<string, array<string, mixed>>|null
	 */
	private static function fetch_plugin_checksums( $slug, $version ) {
		$response = wp_remote_get( 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json', array( 'timeout' => 10 ) );
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		return is_array( $data ) && isset( $data['files'] ) && is_array( $data['files'] ) ? $data['files'] : null;
	}

	/* ---------- Quarantine ---------- */

	/**
	 * Optional ("Quarantine" on the Lockdown tab): a plugin with new or changed files while locked is
	 * deactivated, and a new PHP file in the uploads folder is renamed so the server no longer runs it. Nothing
	 * is deleted. ScrapeLock itself is never deactivated here.
	 */
	private static function quarantine() {
		$report  = self::report();
		$handled = (array) $report['handled'];
		$where   = self::locations();
		$plugins = trailingslashit( $where['plugins'] );
		$uploads = trailingslashit( $where['uploads'] );
		$slugs   = array();
		foreach ( array_merge( (array) $report['added'], (array) $report['changed'] ) as $path ) {
			$path = wp_normalize_path( (string) $path );
			if ( 0 === strpos( $path, $plugins ) ) {
				$slugs[ strtok( substr( $path, strlen( $plugins ) ), '/' ) ] = true;
			} elseif ( '/' !== $uploads && 0 === strpos( $path, $uploads ) && in_array( $path, (array) $report['added'], true ) && file_exists( $path ) && preg_match( '/\.(?:php[0-9]?|phtml|phar)$/i', $path ) ) {
				$fs = self::filesystem( dirname( $path ) );
				if ( $fs && $fs->move( $path, $path . '.pncp-quarantine' ) ) {
					$handled[] = sprintf( /* translators: %s: file */ __( 'Renamed %s', 'scrapelock' ), self::relative( $path ) );
				}
			}
		}
		$own = dirname( plugin_basename( PNCP_FILE ) );
		unset( $slugs[ $own ] );
		$active = array();
		foreach ( (array) get_option( 'active_plugins', array() ) as $file ) {
			if ( isset( $slugs[ dirname( (string) $file ) ] ) ) {
				$active[] = (string) $file;
			}
		}
		if ( $active ) {
			PNCP_Lockdown::deactivate_for_quarantine( $active );
			foreach ( $active as $file ) {
				$handled[] = sprintf( /* translators: %s: plugin file */ __( 'Deactivated %s', 'scrapelock' ), $file );
			}
		}
		if ( $handled !== (array) $report['handled'] ) {
			$report['handled'] = array_values( array_unique( $handled ) );
			self::put( self::REPORT, $report );
			PNCP_Lockdown::record( 'quarantine', implode( ', ', array_slice( $report['handled'], 0, 5 ) ) );
		}
	}

	/**
	 * WP_Filesystem with direct access (cron cannot ask for FTP credentials), or null.
	 *
	 * @param string $dir Folder it will write to.
	 * @return WP_Filesystem_Base|null
	 */
	private static function filesystem( $dir ) {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( 'direct' !== get_filesystem_method( array(), $dir ) || ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof WP_Filesystem_Base ? $wp_filesystem : null;
	}

	/* ---------- wp-admin ---------- */

	/**
	 * "Check now" on the Lockdown tab (administrators, while locked or not).
	 */
	public static function handle() {
		if ( ! PNCP_Lockdown::is_owner( get_current_user_id() ) ) {
			wp_die( esc_html__( 'Only administrators can lock and unlock the site.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		if ( PNCP_Lockdown::is_locked() ) {
			self::check();
		} else {
			self::snapshot();
		}
		wp_safe_redirect( PNCP_Lockdown::page_url( array( 'pncp_ld' => 'integrity' ) ) . '#pncp-integrity' );
		exit;
	}

	/**
	 * A notice on every wp-admin page while files are flagged (administrators).
	 */
	public static function notice() {
		if ( ! PNCP_Lockdown::is_owner( get_current_user_id() ) || PNCP_Lockdown::on_tab() ) {
			return;
		}
		$report = self::report();
		if ( ! empty( $report['tampered'] ) ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'ScrapeLock: the fingerprint of the code files was changed outside WordPress.', 'scrapelock' ) . '</strong> ' . esc_html__( 'New or changed files might have been hidden. Check the site with a security scanner; a new fingerprint is taken the next time you lock the site.', 'scrapelock' ) . ' <a href="' . esc_url( PNCP_Lockdown::page_url() . '#pncp-integrity' ) . '">' . esc_html__( 'Lockdown', 'scrapelock' ) . '</a></p></div>';
		}
		$found = self::findings( $report );
		if ( ! $found ) {
			return;
		}
		echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'ScrapeLock found changed code files.', 'scrapelock' ) . '</strong> ';
		/* translators: %d: number of files */
		echo esc_html( sprintf( _n( '%d file was added or changed while the site was locked, or differs from WordPress.org.', '%d files were added or changed while the site was locked, or differ from WordPress.org.', count( $found ), 'scrapelock' ), count( $found ) ) );
		echo ' <a href="' . esc_url( PNCP_Lockdown::page_url() . '#pncp-integrity' ) . '">' . esc_html__( 'See the files', 'scrapelock' ) . '</a></p></div>';
	}

	/**
	 * The "File integrity" box on the Lockdown tab.
	 *
	 * @param string $fmt Date format.
	 */
	public static function render( $fmt ) {
		$base   = self::baseline();
		$report = self::report();
		$found  = self::findings( $report );
		$off    = (array) $report['official'];
		?>
		<div class="pncp-ld-box pncp-ld-integrity" id="pncp-integrity">
			<h2><?php esc_html_e( 'File integrity', 'scrapelock' ); ?></h2>
			<p><?php esc_html_e( 'While the site is locked nobody can install or update anything, so a new or changed code file means that something wrote it by itself, usually through a vulnerable plugin. ScrapeLock keeps a fingerprint of every PHP, .htaccess and .user.ini file when you lock the site (and again after a temporary unlock), checks it every hour and emails the administration address about anything new. WordPress and the plugins from WordPress.org are also compared with their official copies, which finds a change made before you locked. Caches and the updater\'s folders are left out.', 'scrapelock' ); ?></p>
			<p>
				<?php
				if ( $base['time'] ) {
					/* translators: 1: date, 2: number of files */
					echo esc_html( sprintf( __( 'Fingerprint: %1$s, %2$d files.', 'scrapelock' ), wp_date( $fmt, $base['time'] ), count( $base['files'] ) ) ) . ' ';
				} else {
					echo esc_html__( 'No fingerprint yet: it is taken when you lock the site.', 'scrapelock' ) . ' ';
				}
				if ( $report['time'] ) {
					/* translators: %s: date */
					echo esc_html( sprintf( __( 'Last check: %s.', 'scrapelock' ), wp_date( $fmt, (int) $report['time'] ) ) );
				}
				if ( empty( $report['complete'] ) ) {
					echo ' <strong>' . esc_html__( 'The last pass stopped early (very many files): it is not complete.', 'scrapelock' ) . '</strong>';
				}
				?>
			</p>
			<?php if ( $base['tampered'] ) : ?>
				<div class="notice notice-error inline"><p><strong><?php esc_html_e( 'The fingerprint was changed or removed outside WordPress: new or changed files might have been hidden.', 'scrapelock' ); ?></strong> <?php esc_html_e( 'Check the site with a security scanner. A new fingerprint is taken the next time you lock the site (unlock for a while, then lock again).', 'scrapelock' ); ?></p></div>
			<?php endif; ?>
			<?php if ( $found ) : ?>
				<div class="notice notice-error inline"><p><strong><?php esc_html_e( 'Check these files. Nobody should have changed code while the site was locked; a file you do not recognise is often a backdoor.', 'scrapelock' ); ?></strong></p></div>
				<table class="widefat striped">
					<thead><tr><th><?php esc_html_e( 'File', 'scrapelock' ); ?></th><th><?php esc_html_e( 'What', 'scrapelock' ); ?></th></tr></thead>
					<tbody>
						<?php foreach ( array_slice( $found, 0, 100, true ) as $path => $kind ) : ?>
							<tr><td><code><?php echo esc_html( self::relative( $path ) ); ?></code></td><td><?php echo esc_html( self::kind_label( $kind ) ); ?></td></tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php elseif ( $report['time'] ) : ?>
				<p class="pncp-ld-ok"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span> <?php esc_html_e( 'No changed files.', 'scrapelock' ); ?></p>
			<?php endif; ?>
			<?php if ( ! empty( $report['handled'] ) ) : ?>
				<p><strong><?php esc_html_e( 'Quarantine:', 'scrapelock' ); ?></strong> <?php echo esc_html( implode( '; ', (array) $report['handled'] ) ); ?></p>
			<?php endif; ?>
			<?php if ( ! empty( $off['pending'] ) ) : ?>
				<p class="description"><?php esc_html_e( 'The comparison with the official copies on WordPress.org is running in the background; you are emailed if it finds anything.', 'scrapelock' ); ?></p>
			<?php endif; ?>
			<?php if ( ! empty( $off['time'] ) ) : ?>
				<p class="description">
					<?php
					echo esc_html( ! empty( $off['core'] ) ? __( 'WordPress was compared with its official checksums.', 'scrapelock' ) : __( 'The official WordPress checksums could not be downloaded.', 'scrapelock' ) );
					if ( ! empty( $off['unverified'] ) ) {
						/* translators: %s: list of plugins */
						echo ' ' . esc_html( sprintf( __( 'Plugins that cannot be compared (not on WordPress.org, or no answer): %s.', 'scrapelock' ), implode( ', ', (array) $off['unverified'] ) ) );
					}
					?>
				</p>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION ); ?>">
				<?php wp_nonce_field( self::ACTION ); ?>
				<?php submit_button( PNCP_Lockdown::is_locked() ? __( 'Check now', 'scrapelock' ) : __( 'Take a new fingerprint', 'scrapelock' ), 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
	}
}
