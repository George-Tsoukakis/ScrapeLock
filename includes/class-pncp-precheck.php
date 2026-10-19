<?php
/**
 * Pre-cache check: the setting, the generated loader, the line in wp-config.php and the import of its
 * events into the log. The check itself is in includes/precheck-runtime.php.
 *
 * Page caches such as WP Rocket serve stored pages before any plugin loads, so the normal check never sees
 * those requests: a bot that looks like a browser could read cached pages without a limit. With this setting
 * on, one line at the top of wp-config.php loads a small check (always-blocked IPs, bans, page limit per IP)
 * that runs before the cache. Off by default; turned off, the line and the files are removed.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Installs, updates and removes the pre-cache check.
 */
final class PNCP_Precheck {

	const DIR    = 'scrapelock-precheck';
	const BEGIN  = '// BEGIN ScrapeLock pre-cache check';
	const END    = '// END ScrapeLock pre-cache check';
	const STATUS = 'pncp_precheck_status';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( PNCP_Log::CRON, array( __CLASS__, 'import_events' ), 5 );
		add_action( PNCP_Ip::CRON, array( __CLASS__, 'refresh' ), 30 );
	}

	/**
	 * The data folder (counters, bans, events, the loader).
	 *
	 * @return string
	 */
	public static function dir() {
		return untrailingslashit( WP_CONTENT_DIR ) . '/' . self::DIR;
	}

	/**
	 * The generated loader that wp-config.php includes.
	 *
	 * @return string
	 */
	public static function loader() {
		return self::dir() . '/run.php';
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
		$loader = var_export( self::loader(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the path as PHP code.
		return self::BEGIN . " (added and removed by the plugin's \"Pre-cache check\" setting)\n"
			. 'if ( is_file( ' . $loader . ' ) ) { include_once ' . $loader . "; }\n"
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
	 * Is the check running, i.e. the loader is current and wp-config.php includes it?
	 *
	 * @return bool
	 */
	public static function active() {
		return is_readable( self::loader() ) && self::loader_code() === (string) file_get_contents( self::loader() ) && self::in_config(); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Brings everything in line with the setting (on save, upgrade, activation and deactivation).
	 * The result is kept for the settings page: ok | no_files | no_config | not_writable | off.
	 *
	 * @return string
	 */
	public static function sync() {
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
	 * Rewrites the loader when the lists change (daily), so that it has the current Google / Bing / CDN lists.
	 */
	public static function refresh() {
		if ( self::wanted() && is_readable( self::loader() ) ) {
			self::write_files();
		}
	}

	/**
	 * Removes the line from wp-config.php and the files.
	 *
	 * @param bool $import Move the remaining events into the log first (not on uninstall: the log goes too).
	 */
	public static function remove( $import = true ) {
		self::remove_from_config();
		$dir = self::dir();
		if ( ! is_dir( $dir ) ) {
			return;
		}
		if ( $import ) {
			self::import_events();
		}
		foreach ( array( 'hits', 'strikes', 'bans' ) as $sub ) {
			self::delete_tree( $dir . '/' . $sub );
		}
		foreach ( array( 'run.php', 'events.php', 'index.php', '.htaccess' ) as $file ) {
			if ( file_exists( $dir . '/' . $file ) ) {
				wp_delete_file( $dir . '/' . $file );
			}
		}
		$filesystem = self::filesystem();
		if ( $filesystem ) {
			$filesystem->rmdir( $dir );
		}
	}

	/* ---------- Configuration and loader ---------- */

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
		$config = array(
			'v'           => PNCP_VERSION,
			'dir'         => self::dir(),
			'home'        => $home,
			'limit'       => (int) $s['rate_limit'],
			'ban_strikes' => (int) $s['ban_strikes'],
			'ban_minutes' => (int) $s['ban_minutes'],
			'v6_prefix'   => (int) apply_filters( 'pncp_ipv6_prefix', 64 ),
			'header'      => isset( $headers[ $setting ] ) ? $headers[ $setting ] : '',
			'private'     => in_array( $setting, array( 'x_real_ip', 'x_forwarded_for' ), true ),
			'trust_any'   => ! empty( $s['trust_any_proxy'] ),
			'proxies'     => self::set( $proxies ),
			'cdn'         => self::set( array_merge( PNCP_Ip::list_of( 'cloudflare' ), PNCP_Ip::list_of( 'bunny' ) ) ),
			'allow'       => self::set( PNCP_Options::parse_list( $s['allow_ips'] ) ),
			'block'       => self::set( PNCP_Options::parse_list( $s['block_ips'] ) ),
			'crawlers'    => $crawlers,
			'apcu'        => (bool) apply_filters( 'pncp_precheck_apcu', true ),
		);
		/**
		 * Filters the configuration of the pre-cache check before it is written to the loader.
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
	 * The loader: refuses to run when opened from the web, then runs the check with the configuration.
	 * If the plugin folder disappears, it does nothing.
	 *
	 * @return string
	 */
	public static function loader_code() {
		$runtime = var_export( trailingslashit( PNCP_DIR ) . 'includes/precheck-runtime.php', true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the path as PHP code.
		$config  = var_export( self::config(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the configuration as PHP code.
		return "<?php\n"
			. "// ScrapeLock pre-cache check: written by the plugin, do not edit. Removed when the setting is turned off.\n"
			. "if ( isset( \$_SERVER['SCRIPT_FILENAME'] ) && realpath( (string) \$_SERVER['SCRIPT_FILENAME'] ) === __FILE__ ) {\n\texit;\n}\n"
			. 'if ( ! function_exists( \'pncp_precheck_run\' ) && is_file( ' . $runtime . " ) ) {\n"
			. "\trequire_once " . $runtime . ";\n"
			. "\tpncp_precheck_run( " . $config . " );\n"
			. "}\n";
	}

	/**
	 * Writes the folder (with protection for Apache) and the loader.
	 *
	 * @return bool
	 */
	private static function write_files() {
		$filesystem = self::filesystem();
		$dir        = self::dir();
		if ( ! $filesystem || ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) ) {
			return false;
		}
		if ( ! $filesystem->exists( $dir . '/index.php' ) ) {
			$filesystem->put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n", FS_CHMOD_FILE );
			$filesystem->put_contents( $dir . '/.htaccess', "Require all denied\n", FS_CHMOD_FILE );
		}
		$code = self::loader_code();
		if ( is_readable( self::loader() ) && (string) file_get_contents( self::loader() ) === $code ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			return true;
		}
		$ok = (bool) $filesystem->put_contents( self::loader(), $code, FS_CHMOD_FILE );
		self::opcache_forget( self::loader() );
		return $ok;
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
		$wanted = $m[0] . self::block() . substr( $clean, strlen( $m[0] ) );
		if ( $wanted === $original ) {
			return 'ok';
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
		if ( ! $filesystem || ! $filesystem->is_writable( $path ) ) {
			return false;
		}
		$mode = fileperms( $path ) & 0777;
		if ( $filesystem->put_contents( $path, $wanted, $mode ) && (string) file_get_contents( $path ) === $wanted ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			self::opcache_forget( $path );
			return true;
		}
		$filesystem->put_contents( $path, $original, $mode );
		self::opcache_forget( $path );
		return false;
	}

	/* ---------- Bans and events ---------- */

	/**
	 * A ban from the normal check also applies before the cache.
	 *
	 * @param string $ip    IP.
	 * @param int    $until Expiry.
	 */
	public static function mirror_ban( $ip, $until ) {
		if ( ! is_dir( self::dir() ) ) {
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
		$file = self::dir() . '/bans/' . md5( $ip );
		if ( file_exists( $file ) ) {
			wp_delete_file( $file );
		}
	}

	/**
	 * Lifts every ban before the cache.
	 */
	public static function forget_all_bans() {
		self::delete_tree( self::dir() . '/bans' );
	}

	/**
	 * Moves the events of the check into the log (hourly, when the log tab opens, and on removal). Same IP,
	 * reason and minute become one row with a counter; a ban it decided becomes a ban in the database too,
	 * so that it shows under "Blocked IPs" and can be lifted there.
	 *
	 * @return int Number of events imported.
	 */
	public static function import_events() {
		$file = self::dir() . '/events.php';
		if ( ! is_file( $file ) ) {
			return 0;
		}
		// Renamed first: the check keeps writing to a new file meanwhile.
		$work = self::dir() . '/events-' . wp_generate_password( 8, false ) . '.tmp';
		if ( ! @rename( $file, $work ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic move in our own folder.
			return 0;
		}
		$lines = (array) file( $work, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		wp_delete_file( $work );

		$rows = array();
		$bans = array();
		foreach ( $lines as $line ) {
			$parts = explode( "\t", (string) $line );
			if ( count( $parts ) < 6 || ! ctype_digit( $parts[0] ) || ! filter_var( $parts[3], FILTER_VALIDATE_IP ) ) {
				continue; // The "<?php exit;" line and anything damaged.
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
	 * Deletes a folder with its files and folders (only inside ours).
	 *
	 * @param string $path Folder.
	 */
	private static function delete_tree( $path ) {
		if ( 0 !== strpos( $path, self::dir() . '/' ) || ! is_dir( $path ) ) {
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
		if ( 'direct' !== get_filesystem_method( array(), '' !== $context ? $context : WP_CONTENT_DIR ) || ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof WP_Filesystem_Base ? $wp_filesystem : null;
	}
}
