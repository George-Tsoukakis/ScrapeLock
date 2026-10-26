<?php
/**
 * Pre-cache check: the setting, its data folder, the line in wp-config.php and the import of its events
 * into the log. The check itself is in includes/class-pncp-precheck-runtime.php.
 *
 * Page caches such as WP Rocket serve stored pages before any plugin loads, so the normal check never sees
 * those requests: a bot that looks like a browser could read cached pages without a limit. With this setting
 * on, one line at the top of wp-config.php loads the check from the plugin folder (always-blocked IPs, bans,
 * page limit per IP), before the cache. Its configuration, counters and events are data files (no PHP) in
 * a folder of the uploads directory, uploads/scrapelock/precheck-RANDOM. Off by default; turned off, the
 * line and the files are removed.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Installs, updates and removes the pre-cache check.
 */
final class PNCP_Precheck {

	const DIR    = 'scrapelock';
	const BEGIN  = '// BEGIN ScrapeLock pre-cache check';
	const END    = '// END ScrapeLock pre-cache check';
	const STATUS = 'pncp_precheck_status';
	const KEY    = 'pncp_precheck_key';

	/**
	 * Version of the configuration file; the runtime ignores any other.
	 */
	const FORMAT = 2;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( PNCP_Log::CRON, array( __CLASS__, 'import_events' ), 5 );
		add_action( PNCP_Ip::CRON, array( __CLASS__, 'refresh' ), 30 );
		// If the wp-config.php line could not be added during a front-end request (it is never edited there),
		// finish it on the next admin page load, where editing the config file is safe.
		add_action( 'admin_init', array( __CLASS__, 'maybe_sync' ), 1 );
	}

	/**
	 * Re-runs sync() in wp-admin when the pre-cache check is wanted but not yet fully in place (e.g. the
	 * wp-config.php line was deferred from a front-end upgrade request).
	 */
	public static function maybe_sync() {
		if ( self::wanted() && 'ok' !== get_option( self::STATUS ) ) {
			self::sync();
		}
	}

	/**
	 * The data folder (configuration, counters, bans, events): uploads/scrapelock/precheck-RANDOM. The
	 * random part keeps it from being guessed on servers that ignore .htaccess (Nginx). '' when the
	 * uploads directory is not available.
	 *
	 * @return string
	 */
	public static function dir() {
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}
		return untrailingslashit( $uploads['basedir'] ) . '/' . self::DIR . '/precheck-' . self::key();
	}

	/**
	 * The random part of the folder name (created once).
	 *
	 * @return string
	 */
	private static function key() {
		$key = (string) get_option( self::KEY, '' );
		if ( ! preg_match( '/^[a-z0-9]{20}$/', $key ) ) {
			$key = strtolower( wp_generate_password( 20, false, false ) );
			update_option( self::KEY, $key, false );
		}
		return $key;
	}

	/**
	 * Has the check ever had a data folder? (Bans and their removal touch the files only then.)
	 *
	 * @return bool
	 */
	private static function has_dir() {
		return '' !== (string) get_option( self::KEY, '' ) && '' !== self::dir() && is_dir( self::dir() );
	}

	/**
	 * The configuration file that the check reads.
	 *
	 * @return string
	 */
	public static function config_file() {
		return self::dir() . '/config.json';
	}

	/**
	 * The check itself, in the plugin folder: the line in wp-config.php includes it.
	 *
	 * @return string
	 */
	public static function runtime_file() {
		return plugin_dir_path( PNCP_FILE ) . 'includes/class-pncp-precheck-runtime.php';
	}

	/**
	 * Is the setting on? Never on multisite: wp-config.php is shared by every site of the network.
	 *
	 * @return bool
	 */
	public static function wanted() {
		$s = PNCP_Options::stored();
		return ! is_multisite() && ! empty( $s['enabled'] ) && ! empty( $s['precheck'] );
	}

	/**
	 * The wp-config.php that WordPress loads (in the WordPress folder or the one above it), or ''.
	 *
	 * @return string
	 */
	public static function config_path() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		$up = dirname( ABSPATH ) . '/wp-config.php';
		return file_exists( $up ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ? $up : '';
	}

	/**
	 * The lines added to wp-config.php.
	 *
	 * @return string
	 */
	public static function block() {
		$runtime = var_export( self::runtime_file(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the path as PHP code.
		$data    = var_export( self::dir(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the path as PHP code.
		return self::BEGIN . " (added and removed by the plugin's \"Pre-cache check\" setting)\n"
			. 'if ( is_file( ' . $runtime . ' ) ) { include_once ' . $runtime . '; PNCP_Precheck_Runtime::boot( ' . $data . " ); }\n"
			. self::END . "\n";
	}

	/**
	 * Is the line in wp-config.php?
	 *
	 * @return bool
	 */
	public static function in_config() {
		$path = self::config_path();
		if ( '' === $path || ! is_readable( $path ) ) {
			return false;
		}
		return false !== strpos( (string) file_get_contents( $path ), self::block() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Is the check running, i.e. its configuration is current and wp-config.php includes it?
	 *
	 * @return bool
	 */
	public static function active() {
		return is_readable( self::config_file() ) && self::config_json() === (string) file_get_contents( self::config_file() ) && self::in_config(); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Brings everything in line with the setting (on save, upgrade, activation and deactivation).
	 * The result is kept for the settings page: ok | no_files | no_config | not_writable | off.
	 *
	 * @return string
	 */
	public static function sync() {
		self::remove_legacy();
		if ( ! self::wanted() ) {
			self::remove();
			update_option( self::STATUS, 'off', false );
			return 'off';
		}
		$status = self::write_files() ? self::add_to_config() : 'no_files';
		update_option( self::STATUS, $status, false );
		return $status;
	}

	/**
	 * Rewrites the configuration when the lists change (daily), so that it has the current Google / Bing / CDN lists.
	 */
	public static function refresh() {
		if ( self::wanted() && is_readable( self::config_file() ) ) {
			self::write_files();
		}
	}

	/**
	 * Removes the line from wp-config.php and the files.
	 *
	 * @param bool $import Move the remaining events into the log first (not on uninstall: the log goes too).
	 */
	public static function remove( $import = true ) {
		self::remove_legacy( $import );
		self::remove_from_config();
		if ( '' === (string) get_option( self::KEY, '' ) ) {
			return;
		}
		$dir = self::dir();
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}
		if ( $import ) {
			self::import_events();
		}
		self::delete_folder( $dir, $dir );
		// uploads/scrapelock goes too when nothing else is left in it.
		$parent = dirname( $dir );
		$left   = array_diff( (array) scandir( $parent ), array( '.', '..', 'index.html', '.htaccess' ) );
		if ( ! $left ) {
			self::delete_folder( $parent, $parent );
		}
	}

	/**
	 * Before 3.3.1 the check kept a generated run.php and its data in a folder of its own next to the
	 * plugins (scrapelock-precheck). Its events are moved into the log and the folder is deleted. The folder
	 * is the one the old line in wp-config.php names, and only if it holds ScrapeLock's run.php. The old line
	 * itself is replaced by sync() (or stays harmless: it includes a file that no longer exists).
	 *
	 * @param bool $import Move its events into the log first.
	 */
	private static function remove_legacy( $import = true ) {
		$path = self::config_path();
		if ( '' === $path || ! is_readable( $path ) ) {
			return;
		}
		$code = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( ! preg_match( "#include_once '([^']+)/scrapelock-precheck/run\\.php'#", $code, $m ) ) {
			return;
		}
		$dir = $m[1] . '/scrapelock-precheck';
		$run = $dir . '/run.php';
		if ( ! is_file( $run ) || false === strpos( (string) file_get_contents( $run, false, null, 0, 300 ), 'ScrapeLock pre-cache check' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			return;
		}
		if ( $import ) {
			self::import_events( $dir . '/events.php' );
		}
		self::delete_folder( $dir, $dir );
	}

	/* ---------- Configuration ---------- */

	/**
	 * The configuration of the check, from the current settings and lists.
	 *
	 * @return array<string, mixed>
	 */
	public static function config() {
		$s       = PNCP_Options::stored();
		$headers = PNCP_Ip::ip_headers();
		$setting = (string) $s['ip_header'];
		$proxies = PNCP_Options::parse_list( $s['trusted_proxies'] );
		if ( ! empty( $s['trust_cloudflare'] ) && in_array( $setting, array( 'cf_connecting_ip', 'x_forwarded_for' ), true ) ) {
			$proxies = array_merge( $proxies, PNCP_Ip::list_of( 'cloudflare' ) );
		}
		if ( ! empty( $s['trust_bunny'] ) && in_array( $setting, array( 'x_real_ip', 'x_forwarded_for' ), true ) ) {
			$proxies = array_merge( $proxies, PNCP_Ip::list_of( 'bunny' ) );
		}
		$crawlers = array();
		foreach ( PNCP_Bots::crawler_families() as $family => $def ) {
			$ips        = '' !== $def['list'] ? PNCP_Ip::list_of( $def['list'] ) : array();
			$crawlers[] = array(
				'ua'  => array_map( 'strtolower', $def['ua'] ),
				// Without a list (Applebot, YandexBot, or a list not downloaded yet) the normal check decides.
				'ips' => $ips ? self::set( $ips ) : null,
			);
		}
		$home   = rtrim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
		$secret = isset( $s['cdn_secret'] ) ? trim( (string) $s['cdn_secret'] ) : '';
		$config = array(
			'format'          => self::FORMAT,
			'v'               => PNCP_VERSION,
			'home'            => $home,
			'limit'           => (int) $s['rate_limit'],
			'ban_strikes'     => (int) $s['ban_strikes'],
			'ban_minutes'     => (int) $s['ban_minutes'],
			'v6_prefix'       => (int) apply_filters( 'pncp_ipv6_prefix', 64 ),
			'v6_wide'         => ! empty( $s['ipv6_wide'] ),
			'header'          => isset( $headers[ $setting ] ) ? $headers[ $setting ] : '',
			'private'         => in_array( $setting, array( 'x_real_ip', 'x_forwarded_for' ), true ),
			'trust_any'       => ! empty( $s['trust_any_proxy'] ),
			'proxies'         => self::set( $proxies ),
			// Explicit "Trusted proxies" only (no CDN edge lists): used when a CDN secret is set but the
			// request does not carry it, so a spoofed CDN edge IP is not trusted for the real-IP header.
			'proxies_base'    => self::set( PNCP_Options::parse_list( $s['trusted_proxies'] ) ),
			// Only a hash of the CDN secret is written to the file.
			'cdn_secret_hash' => '' !== $secret ? hash( 'sha256', $secret ) : '',
			// "Only through the CDN": cached pages are refused here too, before the page cache serves them.
			'cdn_only'        => PNCP_Origin::active( $s ),
			'cdn'             => self::set( array_merge( PNCP_Ip::list_of( 'cloudflare' ), PNCP_Ip::list_of( 'bunny' ) ) ),
			'allow'           => self::set( PNCP_Options::parse_list( $s['allow_ips'] ) ),
			'block'           => self::set( PNCP_Options::parse_list( $s['block_ips'] ) ),
			'crawlers'        => $crawlers,
			'apcu'            => (bool) apply_filters( 'pncp_precheck_apcu', true ),
		);
		/**
		 * Filters the configuration of the pre-cache check before it is written to config.json.
		 *
		 * @param array<string, mixed> $config Configuration.
		 */
		return (array) apply_filters( 'pncp_precheck_config', $config );
	}

	/**
	 * A set for the check: [ exact addresses (normalised) => true, CIDRs ].
	 *
	 * @param string[] $ranges IPs and CIDRs.
	 * @return array{0:array<string, bool>, 1:string[]}
	 */
	public static function set( $ranges ) {
		$exact = array();
		$cidrs = array();
		foreach ( $ranges as $range ) {
			$range = trim( (string) $range );
			if ( ! PNCP_Ip::valid_range( $range ) ) {
				continue;
			}
			if ( false === strpos( $range, '/' ) ) {
				$exact[ (string) inet_ntop( (string) inet_pton( $range ) ) ] = true;
			} else {
				$cidrs[] = $range;
			}
		}
		return array( $exact, array_values( array_unique( $cidrs ) ) );
	}

	/**
	 * The configuration as it is written to config.json.
	 *
	 * @return string
	 */
	public static function config_json() {
		return (string) wp_json_encode( self::config(), JSON_UNESCAPED_SLASHES ) . "\n";
	}

	/**
	 * Writes the folder (protected from direct access) and the configuration. The folder holds data only:
	 * the check is the plugin's own file.
	 *
	 * @return bool
	 */
	private static function write_files() {
		$filesystem = self::filesystem();
		$dir        = self::dir();
		if ( ! $filesystem || '' === $dir || ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) ) {
			return false;
		}
		// Apache: no access at all. Elsewhere the random folder name and the empty index keep it hidden.
		$deny = "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n";
		foreach ( array( dirname( $dir ), $dir ) as $folder ) {
			if ( ! $filesystem->exists( $folder . '/index.html' ) ) {
				$filesystem->put_contents( $folder . '/index.html', '', FS_CHMOD_FILE );
			}
			if ( ! $filesystem->exists( $folder . '/.htaccess' ) ) {
				$filesystem->put_contents( $folder . '/.htaccess', $deny, FS_CHMOD_FILE );
			}
		}
		$json = self::config_json();
		if ( "\n" === $json ) {
			return false;
		}
		$file = self::config_file();
		if ( is_readable( $file ) && (string) file_get_contents( $file ) === $json ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			return true;
		}
		return (bool) $filesystem->put_contents( $file, $json, FS_CHMOD_FILE );
	}

	/**
	 * OPcache would keep running the previous version of a rewritten file (for opcache.revalidate_freq
	 * seconds, or until a restart when timestamps are not checked).
	 *
	 * @param string $path File.
	 */
	private static function opcache_forget( $path ) {
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $path, true );
		}
	}

	/* ---------- wp-config.php ---------- */

	/**
	 * Adds the line right after "<?php" at the top of wp-config.php (before anything else runs). The file
	 * is read back; if it is not exactly as expected, the original is written back. No backup copy is
	 * kept anywhere: wp-config.php holds the database password.
	 *
	 * @return string ok | no_config | not_writable
	 */
	private static function add_to_config() {
		$path = self::config_path();
		if ( '' === $path || ! is_readable( $path ) ) {
			return 'no_config';
		}
		$original = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$clean    = self::without_block( $original );
		if ( ! preg_match( '/\A<\?php[ \t]*\r?\n/', $clean, $m ) ) {
			return 'not_writable'; // Unusual start (BOM, comment before <?php): left to the administrator.
		}
		$rest = substr( $clean, strlen( $m[0] ) );
		// declare(strict_types=1) or namespace must stay the file's first statement; our line right after
		// "<?php" would make it a fatal error. Left to the administrator in that case.
		if ( preg_match( '/\A\s*(?:#[^\n]*\n|\/\/[^\n]*\n|\/\*.*?\*\/\s*)*\s*(?:declare|namespace)\b/s', $rest ) ) {
			return 'not_writable';
		}
		$wanted = $m[0] . self::block() . $rest;
		if ( $wanted === $original ) {
			return 'ok';
		}
		// Never rewrite wp-config.php during a normal front-end request (the upgrade can run there): only in
		// wp-admin, WP-CLI or cron. Otherwise it waits for the next admin page load (maybe_sync on admin_init),
		// so a visitor's request never touches the site's main config file.
		if ( ! is_admin() && ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! wp_doing_cron() ) {
			return 'deferred';
		}
		return self::write_config( $path, $wanted, $original ) ? 'ok' : 'not_writable';
	}

	/**
	 * Removes the line from wp-config.php, if it is there.
	 */
	private static function remove_from_config() {
		$path = self::config_path();
		if ( '' === $path || ! is_readable( $path ) ) {
			return;
		}
		$original = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$clean    = self::without_block( $original );
		if ( $clean !== $original ) {
			self::write_config( $path, $clean, $original );
		}
	}

	/**
	 * The file without our lines (from BEGIN to END, whatever the path in between).
	 *
	 * @param string $code wp-config.php.
	 * @return string
	 */
	public static function without_block( $code ) {
		return (string) preg_replace( '#' . preg_quote( self::BEGIN, '#' ) . '[^\n]*\n.*?' . preg_quote( self::END, '#' ) . '[^\n]*\n#s', '', $code );
	}

	/**
	 * Writes wp-config.php and checks it; on any difference the original goes back.
	 *
	 * @param string $path     File.
	 * @param string $wanted   New contents.
	 * @param string $original Previous contents.
	 * @return bool
	 */
	private static function write_config( $path, $wanted, $original ) {
		$filesystem = self::filesystem( dirname( $path ) );
		if ( ! $filesystem || ! $filesystem->is_writable( $path ) || ! $filesystem->is_writable( dirname( $path ) ) ) {
			return false;
		}
		$mode = fileperms( $path ) & 0777;
		if ( ! $mode ) {
			$mode = FS_CHMOD_FILE;
		}
		// Write a temporary file in the same folder, then rename it over wp-config.php. rename() is atomic
		// on one filesystem, so a concurrent request always reads either the whole old file or the whole new
		// one, never a half-written one; and if the write fails (disk full, quota) the original stays in
		// place, so there is no risk window and no "restore" step that could also fail.
		$tmp = $path . '.scrapelock-' . wp_generate_password( 8, false ) . '.tmp';
		if ( ! $filesystem->put_contents( $tmp, $wanted, $mode ) || (string) file_get_contents( $tmp ) !== $wanted ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			$filesystem->delete( $tmp );
			return false;
		}
		// Do not clobber a change another process (e.g. another plugin) made to wp-config.php meanwhile.
		if ( (string) file_get_contents( $path ) !== $original ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			$filesystem->delete( $tmp );
			return false;
		}
		if ( ! @rename( $tmp, $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic replace in the same folder; WP_Filesystem has no atomic move.
			$filesystem->delete( $tmp );
			return false;
		}
		self::opcache_forget( $path );
		return (string) file_get_contents( $path ) === $wanted; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/* ---------- Bans and events ---------- */

	/**
	 * A ban from the normal check also applies before the cache.
	 *
	 * @param string $ip    IP.
	 * @param int    $until Expiry.
	 */
	public static function mirror_ban( $ip, $until ) {
		if ( ! self::has_dir() ) {
			return;
		}
		$filesystem = self::filesystem();
		if ( $filesystem && ( is_dir( self::dir() . '/bans' ) || wp_mkdir_p( self::dir() . '/bans' ) ) ) {
			$filesystem->put_contents( self::dir() . '/bans/' . md5( $ip ), (string) (int) $until, FS_CHMOD_FILE );
		}
	}

	/**
	 * Lifts a ban before the cache too.
	 *
	 * @param string $ip IP.
	 */
	public static function forget_ban( $ip ) {
		if ( ! self::has_dir() ) {
			return;
		}
		$file = self::dir() . '/bans/' . md5( $ip );
		if ( file_exists( $file ) ) {
			wp_delete_file( $file );
		}
	}

	/**
	 * Lifts every ban before the cache.
	 */
	public static function forget_all_bans() {
		if ( self::has_dir() ) {
			self::delete_folder( self::dir() . '/bans', self::dir() );
		}
	}

	/**
	 * Moves the events of the check into the log (hourly, when the log tab opens, and on removal). Same IP,
	 * reason and minute become one row with a counter; a ban it decided becomes a ban in the database too,
	 * so that it shows under "Blocked IPs" and can be lifted there.
	 *
	 * @param string $file An events file of the folder used before 3.3.1 ('' = the current one).
	 * @return int Number of events imported.
	 */
	public static function import_events( $file = '' ) {
		if ( '' !== $file ) {
			// The old folder, about to be deleted: read in place.
			$lines = is_file( $file ) ? (array) file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) : array();
			return self::import_lines( $lines );
		}
		if ( ! self::has_dir() ) {
			return 0;
		}
		$file = self::dir() . '/events.log';
		if ( ! is_file( $file ) ) {
			return 0;
		}
		// Renamed first: the check keeps writing to a new file meanwhile.
		$work = self::dir() . '/events-' . wp_generate_password( 8, false ) . '.tmp';
		if ( ! @rename( $file, $work ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic move inside the plugin's folder in uploads.
			return 0;
		}
		$lines = (array) file( $work, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		wp_delete_file( $work );
		return self::import_lines( $lines );
	}

	/**
	 * Writes event lines (time, code, reason, IP, path, User-Agent, tab-separated) into the log.
	 *
	 * @param string[] $lines Lines.
	 * @return int Number of lines.
	 */
	private static function import_lines( $lines ) {
		$rows = array();
		$bans = array();
		foreach ( $lines as $line ) {
			$parts = explode( "\t", (string) $line );
			if ( count( $parts ) < 6 || ! ctype_digit( $parts[0] ) || ! filter_var( $parts[3], FILTER_VALIDATE_IP ) ) {
				continue; // Anything damaged (and the first line of the files written before 3.3.1).
			}
			list( $time, $code, $reason, $ip, $path, $ua ) = $parts;
			if ( ! isset( PNCP_Log::reasons()[ $reason ] ) ) {
				continue;
			}
			if ( 'ban' === $reason ) {
				$bans[ $ip ] = (int) $time;
			}
			$key = $ip . '|' . $reason . '|' . (int) floor( (int) $time / MINUTE_IN_SECONDS );
			if ( isset( $rows[ $key ] ) ) {
				++$rows[ $key ]['hits'];
				$rows[ $key ]['seen'][ md5( $ua ) ] = true;
				$rows[ $key ]['uas']                = count( $rows[ $key ]['seen'] );
				continue;
			}
			$rows[ $key ] = array(
				'time'   => (int) $time,
				'code'   => (int) $code,
				'reason' => $reason,
				'ip'     => $ip,
				'path'   => sanitize_text_field( $path ),
				'ua'     => sanitize_text_field( $ua ),
				'hits'   => 1,
				'uas'    => 1,
				'seen'   => array( md5( $ua ) => true ),
			);
		}
		foreach ( $rows as $row ) {
			PNCP_Log::insert( $row );
		}
		$minutes = max( 1, (int) PNCP_Options::stored()['ban_minutes'] );
		foreach ( $bans as $ip => $since ) {
			PNCP_Log::import_ban( $ip, $since + $minutes * MINUTE_IN_SECONDS, 'rate_page', $since );
		}
		return count( $lines );
	}

	/* ---------- Files ---------- */

	/**
	 * Deletes a folder with its files and folders, only inside the given base folder.
	 *
	 * @param string $path Folder.
	 * @param string $base The folder it must be in (or be).
	 */
	private static function delete_folder( $path, $base ) {
		if ( '' === $base || ( $path !== $base && 0 !== strpos( $path, $base . '/' ) ) || ! is_dir( $path ) ) {
			return;
		}
		$filesystem = self::filesystem();
		if ( $filesystem ) {
			$filesystem->rmdir( $path, true );
		}
	}

	/**
	 * WP_Filesystem with direct access, or null. Never asks for FTP details.
	 *
	 * @param string $context Folder to check.
	 * @return WP_Filesystem_Base|null
	 */
	private static function filesystem( $context = '' ) {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( '' === $context ) {
			$context = (string) wp_upload_dir( null, false )['basedir'];
		}
		if ( 'direct' !== get_filesystem_method( array(), $context ) || ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof WP_Filesystem_Base ? $wp_filesystem : null;
	}
}
