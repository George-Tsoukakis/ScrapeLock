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
 * line and the files are removed. 3.12.9: with APCu or Redis the check keeps all of it in memory instead
 * (PNCP_Precheck_Runtime::store()); this class puts the configuration there (push_config(), push_web()) and
 * copies bans and events between memory, the files and the log (sync_store()).
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
	 * 3.4.3: option with the key of the human check cookie for cached pages (see human()).
	 */
	const HUMAN_KEY = 'pncp_precheck_hv_key';

	/**
	 * Version of the configuration file; the runtime ignores any other.
	 */
	const FORMAT = 3;

	/**
	 * 3.12.9: the admin-ajax action of the signed request that runs sync_store() in the web server's PHP (fpm_sync()).
	 */
	const SYNC_ACTION = 'pncp_precheck_sync';

	/**
	 * 3.12.9: transient: when the last admin page copied the store (admin_sync()).
	 */
	const SYNC_SEEN = 'pncp_precheck_synced';

	/**
	 * 3.12.9: option: md5 of the wp-config.php line last written (maybe_sync() writes it again when it changes,
	 * e.g. when the site gets a Redis object cache).
	 */
	const BLOCK_HASH = 'pncp_precheck_block';

	/**
	 * 3.12.9: option (autoloaded): the Redis connection of the line last written to wp-config.php, so that
	 * WordPress uses the same store as the check (runtime_config()) without looking for it in a visitor's request.
	 */
	const REDIS_OPTION = 'pncp_precheck_redis_conn';

	/**
	 * 3.12.9: fpm_sync() is running (no second one from inside it).
	 *
	 * @var bool
	 */
	private static $in_fpm_sync = false;

	/**
	 * 3.6.1: transient set for an hour after maybe_sync() could not finish (see there).
	 */
	const RETRY = 'pncp_precheck_retry';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( PNCP_Log::CRON, array( __CLASS__, 'import_events' ), 5 );
		add_action( PNCP_Log::CRON, array( __CLASS__, 'cleanup_hits' ), 6 );
		add_action( PNCP_Ip::CRON, array( __CLASS__, 'refresh' ), 30 );
		// If the wp-config.php line could not be added during a front-end request (it is never edited there),
		// finish it on the next admin page load, where editing the config file is safe.
		add_action( 'admin_init', array( __CLASS__, 'maybe_sync' ), 1 );
		// 3.12.9: APCu lives in the PHP-FPM (or Apache) processes only: WP-CLI and a system cron's `wp cron event
		// run` cannot see it. Their changes reach it through a signed request to the site (fpm_sync()), and an admin
		// page copies it every few minutes (admin_sync()).
		add_action( 'wp_ajax_nopriv_' . self::SYNC_ACTION, array( __CLASS__, 'ajax_sync' ) );
		add_action( 'wp_ajax_' . self::SYNC_ACTION, array( __CLASS__, 'ajax_sync' ) );
		add_action( 'admin_init', array( __CLASS__, 'admin_sync' ), 20 );
	}

	/**
	 * Re-runs sync() in wp-admin when the pre-cache check is wanted but not yet fully in place (e.g. the
	 * wp-config.php line was deferred from a front-end upgrade request).
	 */
	public static function maybe_sync() {
		// 3.6.1: not on admin-ajax.php (every visitor's human check goes through it), and after a failed attempt at
		// most once an hour: with a wp-config.php that cannot be changed (read-only, declare(strict_types=1)) the
		// status stays "not_writable", and every admin request rebuilt the configuration, started WP_Filesystem and
		// read wp-config.php twice. A "deferred" line (from a front-end upgrade) is still finished on the next
		// admin page, and saving the settings always runs sync() itself.
		if ( wp_doing_ajax() || ! self::wanted() ) {
			return;
		}
		$status = get_option( self::STATUS );
		// 3.12.9: a line that changed (the Redis connection of a new object cache) is written again.
		if ( 'ok' === $status && md5( self::block() ) !== (string) get_option( self::BLOCK_HASH, '' ) && ! get_transient( self::RETRY ) ) {
			$status = 'changed';
		}
		if ( 'ok' === $status || ( 'deferred' !== $status && get_transient( self::RETRY ) ) ) {
			return;
		}
		if ( 'ok' !== self::sync() ) {
			set_transient( self::RETRY, 1, HOUR_IN_SECONDS );
		}
	}

	/**
	 * The hourly cleanup of the per-minute counter files left by the check (all of them, not just a few).
	 */
	public static function cleanup_hits() {
		$dir = self::dir();
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}
		self::load_runtime();
		if ( is_dir( $dir . '/hits' ) ) {
			PNCP_Precheck_Runtime::cleanup( $dir . '/hits', (int) floor( time() / 60 ), 0 );
		} else {
			@touch( $dir . '/.cleaned' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- The mark of the hourly cleanup (PNCP_Precheck_Runtime::maybe_sweep()).
		}
		// 3.12.9: the bans between APCu / Redis and the files, the configuration into the store.
		self::sync_store();
		if ( defined( 'WP_CLI' ) && WP_CLI && self::wanted() && self::in_config() ) {
			self::fpm_sync(); // A system cron's `wp cron event run`: APCu is only in the web server's PHP.
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
		return PNCP_Paths::config();
	}

	/**
	 * The lines added to wp-config.php.
	 *
	 * @return string
	 */
	public static function block() {
		$runtime = var_export( self::runtime_file(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the path as PHP code.
		$data    = var_export( self::dir(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the path as PHP code.
		// 3.12.1: and the key of the site's signed requests to itself (PNCP_Precheck_Runtime::self_signed()). Only
		// here, in wp-config.php, which the web server never shows: the data folder is in uploads, where a server
		// without .htaccess (Nginx) serves any file whose name is known.
		$key = var_export( PNCP_Server_Ips::sig_key( true ), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the key as PHP code.
		// 3.12.9: the Redis server of the object cache, when there is one (redis_settings()): the check runs before
		// the rest of wp-config.php defines WP_REDIS_*, and must not read a file to find it.
		$redis = self::php_array( self::redis_settings() );
		return self::BEGIN . " (added and removed by the plugin's \"Pre-cache check\" setting)\n"
			. 'if ( is_file( ' . $runtime . ' ) ) { include_once ' . $runtime . '; PNCP_Precheck_Runtime::boot( ' . $data . ', ' . $key . ( '' !== $redis ? ', ' . $redis : '' ) . " ); }\n"
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
	 * 3.12.9: wp-config.php has the check's lines, but not the current ones (an earlier version's, e.g. without
	 * the Redis connection), and they could not be replaced.
	 *
	 * @return bool
	 */
	public static function line_outdated() {
		$path = self::config_path();
		if ( '' === $path || ! is_readable( $path ) ) {
			return false;
		}
		$text = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return false !== strpos( $text, self::BEGIN ) && false === strpos( $text, self::block() );
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
		if ( 'ok' === $status ) {
			self::push_web( true ); // 3.12.9: from WP-CLI, the web server's APCu gets this configuration now.
		}
		return $status;
	}

	/**
	 * Rewrites the configuration when the lists change (daily), so that it has the current Google / Bing / CDN lists.
	 * Also when the server's addresses change (PNCP_Server_Ips::changed()).
	 */
	public static function refresh() {
		if ( self::wanted() && is_readable( self::config_file() ) ) {
			self::write_files();
			// 3.12.1: the line in wp-config.php waits for a new key (PNCP_Server_Ips::key()): written here when this
			// runs in WP cron, otherwise on the next wp-admin page (maybe_sync()).
			if ( 'deferred' === get_option( self::STATUS ) ) {
				update_option( self::STATUS, self::add_to_config(), false );
			}
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
		$crawlers = array();
		foreach ( PNCP_Bots::crawler_families() as $family => $def ) {
			$ips        = '' !== $def['list'] ? PNCP_Ip::list_of( $def['list'] ) : array();
			$crawlers[] = array(
				'ua'  => array_map( 'strtolower', $def['ua'] ),
				// Without a list (Applebot, YandexBot, or a list not downloaded yet) the normal check decides.
				// The lists themselves are in crawlers.json, read only when a request claims to be a crawler.
				'ips' => $ips ? true : null,
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
			// The explicit "Trusted proxies"; the CDN edges are trusted by the flags below, from their own sets
			// (each list is written once). With a CDN secret set but not on the request, only these are trusted.
			'proxies'         => self::set( PNCP_Ip::trusted_ranges( $s ) ),
			'proxies_cdn'     => array(
				'cf'    => ! empty( $s['trust_cloudflare'] ) && in_array( $setting, array( 'cf_connecting_ip', 'x_forwarded_for' ), true ),
				'bunny' => ! empty( $s['trust_bunny'] ) && in_array( $setting, array( 'x_real_ip', 'x_forwarded_for' ), true ),
			),
			// 3.4.1: "Real visitor IP" at the default (REMOTE_ADDR) with Cloudflare trusted: CF-Connecting-IP from a
			// Cloudflare edge is the visitor, as in PNCP_Ip::client_ip().
			'cf_auto'         => ! empty( $s['trust_cloudflare'] ) && 'remote_addr' === $setting,
			// Only a hash of the CDN secret is written to the file.
			'cdn_secret_hash' => '' !== $secret ? hash( 'sha256', $secret ) : '',
			// "Only through the CDN": cached pages are refused here too, before the page cache serves them.
			'cdn_only'        => PNCP_Origin::active( $s ),
			'cdn_cf'          => self::set( PNCP_Ip::list_of( 'cloudflare' ) ),
			'cdn_bunny'       => self::set( PNCP_Ip::list_of( 'bunny' ) ),
			'allow'           => self::set( PNCP_Options::parse_list( $s['allow_ips'] ) ),
			// 3.11: the server's own addresses (PNCP_Server_Ips): the site's requests to itself through the CDN.
			'self_ips'        => self::set( PNCP_Server_Ips::ips() ),
			// 3.12.1: SCRAPELOCK_SERVER_IPS: its private addresses count too, when they came no further than the
			// server's network (PNCP_Precheck_Runtime::is_server_request()).
			'self_const'      => self::set( PNCP_Server_Ips::const_ips() ),
			// 3.12.1: the site's signed requests to itself (PNCP_Server_Ips::sig_ok()): its host names and the window.
			// The key is never in this folder: the line in wp-config.php passes it (block()).
			'self_sig'        => array(
				'hosts'  => PNCP_Server_Ips::own_hosts(),
				'window' => PNCP_Server_Ips::SIG_WINDOW,
			),
			'block'           => self::set( PNCP_Options::parse_list( $s['block_ips'] ) ),
			'crawlers'        => $crawlers,
			'apcu'            => (bool) apply_filters( 'pncp_precheck_apcu', true ),
			// 3.6.1: the PHP SAPIs where APCu is shared by every process (as PNCP_Log::apcu_ok()); elsewhere (CGI,
			// LiteSpeed LSAPI) the page counters use the files, or each process would count on its own.
			'apcu_sapis'      => array_values( array_map( 'strval', (array) apply_filters( 'pncp_precheck_apcu_sapis', array( 'fpm-fcgi', 'apache2handler' ) ) ) ),
			// 3.6: most new files a minute without APCu (PNCP_Precheck_Runtime::NEW_FILES, new_file_ok()).
			'new_files'       => max( 0, (int) apply_filters( 'pncp_precheck_new_files_per_minute', 2000 ) ),
			// 3.6.1: new counter files one network (/24, /48) may take from them (PNCP_Precheck_Runtime::hit()).
			'net_files'       => max( 1, (int) apply_filters( 'pncp_new_counters_per_network', PNCP_Bots::NET_NEW_KEYS_PER_MINUTE ) ),
			// "Monitor only": log what would be refused, refuse nothing (with the end of the first-week monitoring).
			'monitor'         => ! empty( $s['monitor_mode'] ),
			'monitor_until'   => (int) $s['monitor_until'],
			// 3.4: Emergency Mode (until when, and its stricter limits): while it lasts, cached pages get the same
			// page limit and bans as pages WordPress builds, and "Monitor only" is paused here too. It ends at its
			// time without the file being written again.
			'emergency_until' => PNCP_Options::emergency_until(),
			'emergency'       => self::emergency_limits( $s ),
			// 3.4.1: WooCommerce cart, checkout and My account (with their endpoints below them): never counted,
			// as in the normal check (PNCP_Bots::is_shop_transaction_page()). Bans and the block list still apply.
			'shop'            => self::shop_pages( $home ),
			// 3.4.3: the bot list on cached pages too. WP Super Cache, W3 Total Cache, Cache Enabler and the like
			// served GPTBot & co. their stored pages: only WP Rocket was told to skip them (rocket_cache_reject_ua).
			'bots'            => self::bot_needles( $s ),
			'empty_ua'        => ! empty( $s['block_bots'] ) && ! empty( $s['block_empty_ua'] ),
			'allow_ua'        => self::allow_entries( $s ),
			// 3.11: /.well-known/*: the services that read it count as allowed there (PNCP_Bots::well_known_agents()),
			// and an empty User-Agent is not refused there, nor from Google's or Apple's official addresses (their
			// sets in crawlers.json, at these positions).
			'wk_agents'       => array_values( array_filter( array_map( 'strtolower', PNCP_Bots::well_known_agents() ) ) ),
			'official'        => self::official_sets(),
			// 3.11: static files (PNCP_Bots::is_static_request()): their own counter, "factor" times the page limit,
			// never a violation; the link previews of the always-allowed list are not counted on them.
			'media'           => array(
				'ext'     => PNCP_Bots::static_extensions(),
				'factor'  => PNCP_Bots::MEDIA_FACTOR,
				'preview' => array_values( array_filter( array_map( 'strtolower', PNCP_Bots::link_preview_agents() ) ) ),
			),
			// 3.4.3: the stricter limit of visitors who have not passed the human check (see human()).
			'human'           => self::human( $s ),
			// 3.12.9: the circuit breaker (PNCP_Breaker): a check slower than "ms" suspends the counters for
			// "minutes"; its state in this Redis server when there is one (never a password), else APCu or files.
			'breaker'         => array(
				'ms'      => PNCP_Breaker::threshold( 'precheck' ),
				'minutes' => PNCP_Breaker::minutes( 'precheck' ),
				'redis'   => PNCP_Breaker::wp_redis_config(),
			),
		);
		// 3.12.6: the verification files (PNCP_Verify_Files), path => until: every bot may read them. Absent when
		// there is none, so config.json stays as it was.
		$open = PNCP_Verify_Files::paths();
		if ( $open ) {
			$config['open'] = $open;
		}
		// 3.5: "Ban scanners on their first probe": only the entries that can never be a WordPress page (see
		// PNCP_Probe::RUNTIME_KEYS). Absent when the setting is off, so config.json stays exactly as in 3.4.3.
		if ( ! empty( $s['enabled'] ) && ! empty( $s['probe_ban'] ) ) {
			$body = PNCP_Probe::body( 'runtime' );
			if ( '' !== $body ) {
				$config['probe'] = array(
					're'      => '^/' . $body . '$',
					/** This filter is documented in includes/class-pncp-bots.php */
					'first'   => (int) apply_filters( 'pncp_probe_first_ban_minutes', 10 ),
					'skip_ua' => array_values( array_filter( array_map( 'strtolower', PNCP_Bots::trap_exempt_agents() ) ) ),
				);
			}
		}
		/**
		 * Filters the configuration of the pre-cache check before it is written to config.json.
		 *
		 * @param array<string, mixed> $config Configuration.
		 */
		return (array) apply_filters( 'pncp_precheck_config', $config );
	}

	/**
	 * 3.4.3: the blocked User-Agents (PNCP_Options::blocked_agents()), lowercase, as the normal check matches
	 * them ("=name" = the whole User-Agent). Without the allowed AI search bots, as for WP Rocket: those are
	 * counted like any visitor here, and verified by the normal check.
	 *
	 * @param array<string, mixed> $s Stored settings.
	 * @return string[]
	 */
	private static function bot_needles( $s ) {
		if ( empty( $s['block_bots'] ) ) {
			return array();
		}
		$search = array_map( 'strtolower', PNCP_Options::allowed_ai_search( $s ) );
		$out    = array();
		foreach ( PNCP_Options::blocked_agents( $s ) as $needle ) {
			$needle = strtolower( (string) $needle );
			if ( '' !== $needle && '=' !== $needle && ! in_array( $needle, $search, true ) ) {
				$out[] = $needle;
			}
		}
		return $out;
	}

	/**
	 * 3.4.3: the "always allowed" User-Agents (PNCP_Bots::allow_list_match()) and the allowed AI search bots:
	 * [ lowercase User-Agent, null or the set of IPs an entry is pinned to ].
	 *
	 * @param array<string, mixed> $s Stored settings.
	 * @return array<int, array{0:string, 1:mixed}>
	 */
	private static function allow_entries( $s ) {
		$out = array();
		foreach ( PNCP_Options::parse_list( $s['allow_list'] ) as $entry ) {
			$entry = PNCP_Options::split_allow_entry( $entry );
			if ( '' !== $entry['ua'] ) {
				$out[] = array( strtolower( $entry['ua'] ), $entry['pinned'] ? self::set( $entry['ips'] ) : null );
			}
		}
		foreach ( PNCP_Options::allowed_ai_search( $s ) as $ua ) {
			if ( '' !== (string) $ua ) {
				$out[] = array( strtolower( (string) $ua ), null );
			}
		}
		// 3.11: the service bots of active plugins (WP Rocket's "WP-Rocket-SaaS"), as in the normal check; rewritten
		// when a plugin is activated or deactivated (PNCP_Plugin_Bots::plugins_changed()).
		foreach ( PNCP_Plugin_Bots::allowed_agents() as $bot ) {
			$out[] = array( $bot['ua'], $bot['ips'] ? self::set( $bot['ips'] ) : null );
		}
		return $out;
	}

	/**
	 * 3.4.3: the human check on cached pages. The check cannot verify the human check's own cookie (signed with
	 * the WordPress salts, which wp-config.php defines after the check has run), so the human check also sets a
	 * second cookie (PNCP_Human::PC_COOKIE), signed with a key of this folder's configuration. A leaked key
	 * would only let a script pass as verified: it would still get the normal page limit.
	 *
	 * @param array<string, mixed> $s Stored settings.
	 * @return array{limit:int, key:string, cookie:string}
	 */
	private static function human( $s ) {
		return array(
			'limit'  => ! empty( $s['human_check'] ) ? (int) $s['rate_limit_unverified'] : 0,
			'key'    => self::human_key(),
			'cookie' => PNCP_Human::PC_COOKIE,
		);
	}

	/**
	 * 3.4.3: the key of the human check cookie for cached pages (created once).
	 *
	 * @return string
	 */
	public static function human_key() {
		$key = (string) get_option( self::HUMAN_KEY, '' );
		if ( strlen( $key ) < 32 ) {
			$key = wp_generate_password( 40, false, false );
			update_option( self::HUMAN_KEY, $key, false );
		}
		return $key;
	}

	/**
	 * The WooCommerce cart, checkout and My account pages: their paths below the home path (lowercase, without
	 * the trailing slash) and their page IDs (for ?page_id= without pretty permalinks). Never the home page itself.
	 *
	 * @param string $home The home path, without the trailing slash.
	 * @return array{paths:string[], ids:int[]}
	 */
	private static function shop_pages( $home ) {
		$out = array(
			'paths' => array(),
			'ids'   => array(),
		);
		if ( ! function_exists( 'wc_get_page_id' ) ) {
			return $out;
		}
		$front = 'page' === get_option( 'show_on_front' ) ? (int) get_option( 'page_on_front' ) : 0;
		foreach ( array( 'cart', 'checkout', 'myaccount' ) as $name ) {
			$id = (int) wc_get_page_id( $name );
			if ( $id < 1 || $id === $front || 'publish' !== get_post_status( $id ) ) {
				continue;
			}
			$out['ids'][] = $id;
			$path         = rawurldecode( (string) wp_parse_url( (string) get_permalink( $id ), PHP_URL_PATH ) );
			if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
				$path = substr( $path, strlen( $home ) );
			}
			$path = strtolower( rtrim( '/' . ltrim( $path, '/' ), '/' ) );
			if ( '' !== $path && '/index.php' !== $path ) {
				$out['paths'][] = $path;
			}
		}
		return $out;
	}

	/**
	 * The limits of Emergency Mode that the pre-cache check applies (see PNCP_Options::emergency_overlay()).
	 *
	 * @param array<string, mixed> $s Stored settings.
	 * @return array{limit:int, ban_strikes:int, ban_minutes:int, v6_wide:bool, human:int}
	 */
	private static function emergency_limits( $s ) {
		$overlay = PNCP_Options::emergency_overlay( $s );
		return array(
			'limit'       => (int) $overlay['rate_limit'],
			'ban_strikes' => (int) $overlay['ban_strikes'],
			'ban_minutes' => (int) $overlay['ban_minutes'],
			// 3.4.3: also the /56 limit and the human check's stricter limit, which Emergency Mode turns on.
			'v6_wide'     => ! empty( $overlay['ipv6_wide'] ),
			'human'       => ! empty( $overlay['human_check'] ) ? (int) $overlay['rate_limit_unverified'] : 0,
		);
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
			$range = PNCP_Options::unmap_range( $range ); // 3.4: ::ffff:198.51.100.7 is compared as 198.51.100.7.
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
	 * The official crawler lists (Google, Bing) as they are written to crawlers.json: one set per crawler
	 * family, in the order of the configuration (null where there is no list).
	 *
	 * @return string
	 */
	public static function crawlers_json() {
		$sets = array();
		foreach ( PNCP_Bots::crawler_families() as $def ) {
			$ips    = '' !== $def['list'] ? PNCP_Ip::list_of( $def['list'] ) : array();
			$sets[] = $ips ? self::set( $ips ) : null;
		}
		// 3.11: Apple's list after the families (its crawler is verified by DNS, so it has no family list).
		$apple  = PNCP_Ip::list_of( 'apple' );
		$sets[] = $apple ? self::set( $apple ) : null;
		return (string) wp_json_encode( $sets, JSON_UNESCAPED_SLASHES ) . "\n";
	}

	/**
	 * 3.11: the positions in crawlers.json of Google's list and of Apple's (written last by crawlers_json()).
	 *
	 * @return int[]
	 */
	private static function official_sets() {
		$out = array();
		$i   = 0;
		foreach ( PNCP_Bots::crawler_families() as $def ) {
			if ( 'google' === $def['list'] ) {
				$out[] = $i;
			}
			++$i;
		}
		$out[] = $i; // Apple.
		return $out;
	}

	/**
	 * Writes a data file of the check: next to it first, then renamed over it, so a request reading it meanwhile
	 * gets the whole old or the whole new file, never half of one (which would let everything through).
	 *
	 * @param WP_Filesystem_Base $filesystem Filesystem.
	 * @param string             $file       File.
	 * @param string             $contents   Contents.
	 * @return bool
	 */
	private static function write_data_file( $filesystem, $file, $contents ) {
		if ( is_readable( $file ) && (string) file_get_contents( $file ) === $contents ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			return true;
		}
		$tmp = $file . '.' . wp_generate_password( 8, false ) . '.tmp';
		if ( ! $filesystem->put_contents( $tmp, $contents, FS_CHMOD_FILE ) ) {
			$filesystem->delete( $tmp ); // A write cut short (disk full, quota) may have left part of it.
			return false;
		}
		if ( ! @rename( $tmp, $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic replace in the same folder.
			$filesystem->delete( $tmp );
			return false;
		}
		return true;
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
		// The crawler lists first: a new config.json never points to lists that are not there yet.
		$crawlers = self::crawlers_json();
		if ( ! self::write_data_file( $filesystem, $dir . '/crawlers.json', $crawlers ) ) {
			return false;
		}
		$changed = ! is_readable( self::config_file() ) || (string) file_get_contents( self::config_file() ) !== $json; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( ! self::write_data_file( $filesystem, self::config_file(), $json ) ) {
			return false;
		}
		// 3.12.9: the check reads its configuration from APCu or Redis, not from the file (PNCP_Precheck_Runtime::
		// load()). WP-CLI cannot reach the web server's APCu: a signed request to the site puts it there.
		self::push_config( $json, $crawlers );
		if ( $changed ) {
			self::push_web();
		}
		return true;
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
		$block  = self::block();
		$wanted = $m[0] . $block . $rest;
		if ( $wanted === $original ) {
			self::written( $block );
			return 'ok';
		}
		// Never rewrite wp-config.php during a normal front-end request (the upgrade can run there): only in
		// wp-admin, WP-CLI or cron. Otherwise it waits for the next admin page load (maybe_sync on admin_init),
		// so a visitor's request never touches the site's main config file.
		if ( ! is_admin() && ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! wp_doing_cron() ) {
			return 'deferred';
		}
		if ( ! self::write_config( $path, $wanted, $original ) ) {
			return 'not_writable';
		}
		self::written( $block );
		return 'ok';
	}

	/**
	 * 3.12.9: notes the line now in wp-config.php: its hash (maybe_sync()) and its Redis connection (runtime_config()).
	 *
	 * @param string $block The line (block()).
	 */
	private static function written( $block ) {
		if ( md5( $block ) !== (string) get_option( self::BLOCK_HASH, '' ) ) {
			update_option( self::BLOCK_HASH, md5( $block ), false );
		}
		$redis = self::redis_settings();
		if ( get_option( self::REDIS_OPTION, null ) !== $redis ) {
			update_option( self::REDIS_OPTION, $redis, true );
		}
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
		// 3.6.1: a symlinked wp-config.php (Deployer, Capistrano, some managed hosts link it to a shared file) is
		// written where the link points. rename() replaces the link itself, so the release folder would get a
		// private copy and stop following the shared file (rotated database credentials).
		if ( is_link( $path ) ) {
			$real = realpath( $path );
			if ( false === $real || ! is_file( $real ) ) {
				return false;
			}
			$path = $real;
		}
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
		// The temporary copy ends in .php: if PHP stopped before the rename and the copy were left behind, the
		// web server would run it (no output, like wp-config.php itself) instead of sending the database
		// password as plain text.
		$tmp = preg_replace( '/\.php$/i', '', $path ) . '.scrapelock-' . wp_generate_password( 8, false ) . '.php';
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
	 * 3.12.9: into APCu or Redis when the check keeps its bans there (PNCP_Precheck_Runtime::store()): in a visitor's
	 * request only there (the hourly sync_store() copies it to the file); in wp-admin, WP-Cron and WP-CLI the file
	 * too. From WP-CLI, which cannot see the web server's APCu, the ban waits in ops.log for fpm_sync().
	 *
	 * @param string $ip    IP.
	 * @param int    $until Expiry.
	 */
	public static function mirror_ban( $ip, $until ) {
		if ( '' === (string) get_option( self::KEY, '' ) ) {
			return;
		}
		$c = self::runtime_config();
		// 3.6.1: never shorter than the ban the check already holds (a trap hit of an IP banned for longer, or
		// the import of a longer Emergency Mode ban with the normal duration); an unban deletes the file.
		if ( self::mirrored_until( $ip ) >= (int) $until ) {
			return;
		}
		$stored = '' !== PNCP_Precheck_Runtime::store( $c ) && PNCP_Precheck_Runtime::mem_set( $c, 'b:' . md5( (string) $ip ), (string) (int) $until, max( 60, (int) $until - time() + 60 ) );
		if ( $stored && ! self::back_office() ) {
			return;
		}
		self::queue_op( 'ban', md5( (string) $ip ), (int) $until );
		self::push_web();
		// Written directly, as the check itself writes its files: starting WP_Filesystem (with its test file in
		// uploads) costs more than the write.
		$dir = self::dir() . '/bans';
		if ( is_dir( self::dir() ) && ( is_dir( $dir ) || wp_mkdir_p( $dir ) ) ) {
			$file = $dir . '/' . md5( (string) $ip );
			if ( ( is_file( $file ) ? (int) @file_get_contents( $file ) : 0 ) < (int) $until ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A tiny data file in the plugin's own folder.
				PNCP_Precheck_Runtime::put_atomic( $file, (string) (int) $until );
			}
		}
	}

	/**
	 * 3.6.1: the expiry of the check's ban of a ban key (0 = none). 3.12.9: from APCu or Redis when the check keeps
	 * its bans there, else the file.
	 *
	 * @param string $ip Ban key.
	 * @return int
	 */
	public static function mirrored_until( $ip ) {
		if ( '' === (string) get_option( self::KEY, '' ) ) {
			return 0;
		}
		$c      = self::runtime_config();
		$stored = PNCP_Precheck_Runtime::mem_get( $c, 'b:' . md5( (string) $ip ) );
		if ( null !== $stored && ! self::back_office() ) {
			return (int) $stored;
		}
		$file = self::dir() . '/bans/' . md5( (string) $ip );
		$from = is_file( $file ) ? (int) @file_get_contents( $file ) : 0; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A local file of the plugin's folder; removed in between = none.
		return max( $from, (int) $stored );
	}

	/**
	 * Lifts a ban before the cache too.
	 *
	 * @param string $ip IP.
	 */
	public static function forget_ban( $ip ) {
		if ( '' === (string) get_option( self::KEY, '' ) ) {
			return;
		}
		$c = self::runtime_config();
		// 3.5: the probe ban's 24-hour memory too: a lifted IP starts clean.
		PNCP_Precheck_Runtime::mem_del( $c, array( 'b:' . md5( (string) $ip ), 'p:' . md5( (string) $ip ) ) );
		self::queue_op( 'unban', md5( (string) $ip ) );
		foreach ( array( 'bans', 'probes' ) as $folder ) {
			$file = self::dir() . '/' . $folder . '/' . md5( (string) $ip );
			if ( file_exists( $file ) ) {
				wp_delete_file( $file );
			}
		}
		self::push_web();
	}

	/**
	 * 3.5: the 24-hour probe memory of the check (PNCP_Precheck_Runtime::probe_seen(), same store and format), for
	 * a probe WordPress bans: true when the check (or WordPress) remembers a probe of this IP key within 24
	 * hours; otherwise the time of this probe is written. False without a data folder. Only called on a ban.
	 *
	 * @param string $key The IP's key (PNCP_Ip::limit_key()).
	 * @return bool
	 */
	public static function probe_seen( $key ) {
		if ( '' === (string) get_option( self::KEY, '' ) ) {
			return false;
		}
		$c = self::runtime_config();
		if ( '' === PNCP_Precheck_Runtime::store( $c ) && ! self::has_dir() ) {
			return false;
		}
		return PNCP_Precheck_Runtime::probe_seen( $c, (string) $key, time() );
	}

	/**
	 * Lifts every ban before the cache.
	 */
	public static function forget_all_bans() {
		if ( '' === (string) get_option( self::KEY, '' ) ) {
			return;
		}
		$c = self::runtime_config();
		foreach ( array( 'b:', 'p:' ) as $prefix ) {
			$names = array();
			foreach ( array_keys( (array) PNCP_Precheck_Runtime::mem_list( $c, $prefix ) ) as $hash ) {
				$names[] = $prefix . $hash;
			}
			if ( $names ) {
				PNCP_Precheck_Runtime::mem_del( $c, $names );
			}
		}
		self::queue_op( 'unban_all' );
		if ( self::has_dir() ) {
			self::delete_folder( self::dir() . '/bans', self::dir() );
			self::delete_folder( self::dir() . '/probes', self::dir() ); // 3.5: the probe ban's memory.
		}
		self::push_web();
	}

	/* ---------- 3.12.9: APCu and Redis ---------- */

	/**
	 * Loads the check's class (it is only loaded by wp-config.php while the check is on).
	 */
	public static function load_runtime() {
		if ( ! class_exists( 'PNCP_Precheck_Runtime' ) ) {
			require_once self::runtime_file();
		}
	}

	/**
	 * The part of the check's configuration that says where it keeps its data: the folder, APCu and the Redis
	 * connection, as the line in wp-config.php gives it to the check.
	 *
	 * @return array<string, mixed>
	 */
	public static function runtime_config() {
		self::load_runtime();
		$key = PNCP_Server_Ips::sig_key();
		// The connection the check got with its line; WP-CLI, cron and wp-admin look for it themselves. A visitor's
		// request never reads the object cache's drop-in for it.
		$redis = self::back_office() ? self::redis_settings() : get_option( self::REDIS_OPTION, array() );
		$redis = is_array( $redis ) ? $redis : array();
		return array(
			'dir'        => self::dir(),
			'apcu'       => (bool) apply_filters( 'pncp_precheck_apcu', true ),
			/** This filter is documented in includes/class-pncp-precheck.php */
			'apcu_sapis' => array_values( array_map( 'strval', (array) apply_filters( 'pncp_precheck_apcu_sapis', array( 'fpm-fcgi', 'apache2handler' ) ) ) ),
			'redis'      => $redis ? $redis + array( 'sk' => $key ) : array(),
			'self_key'   => $key,
		);
	}

	/**
	 * Is this request wp-admin (not admin-ajax), WP-Cron or WP-CLI? There the files are written too; a visitor's
	 * request only uses APCu or Redis when the check has one.
	 *
	 * @return bool
	 */
	private static function back_office() {
		return ( defined( 'WP_CLI' ) && WP_CLI ) || 'cli' === PHP_SAPI || wp_doing_cron() || ( is_admin() && ! wp_doing_ajax() );
	}

	/**
	 * The connection to the Redis server of the site's persistent object cache, for the line in wp-config.php ([]
	 * = none). Setting: the constant SCRAPELOCK_PRECHECK_REDIS or the filter `pncp_precheck_redis`: 'auto' (the
	 * default: when the PHP Redis extension is there and the site's object cache is Redis, from the WP_REDIS_*
	 * constants of the Redis Object Cache plugin or WP_REDIS_CONFIG), false (never), or an array with host, port,
	 * path (a Unix socket), scheme (tcp, tls, unix), db, user, password and prefix. Never with Redis Cluster,
	 * Sentinel, shards or replication (WP_REDIS_CLUSTER, WP_REDIS_SENTINEL, WP_REDIS_SHARDS, WP_REDIS_SERVERS):
	 * the check talks to one server. The password goes into the line masked (PNCP_Precheck_Runtime::mask()).
	 *
	 * @return array<string, mixed>
	 */
	public static function redis_settings() {
		$want = defined( 'SCRAPELOCK_PRECHECK_REDIS' ) ? constant( 'SCRAPELOCK_PRECHECK_REDIS' ) : 'auto';
		/**
		 * Filters whether and how the pre-cache check uses Redis: 'auto', false, or the connection (array).
		 *
		 * @param mixed $want 'auto' (default), false or an array (host, port, path, scheme, db, user, password, prefix).
		 */
		$want = apply_filters( 'pncp_precheck_redis', $want );
		if ( ! $want || 'off' === $want || ! class_exists( 'Redis' ) ) {
			return array();
		}
		if ( is_array( $want ) ) {
			$p = $want;
		} else {
			foreach ( array( 'WP_REDIS_CLUSTER', 'WP_REDIS_SENTINEL', 'WP_REDIS_SHARDS', 'WP_REDIS_SERVERS' ) as $name ) {
				if ( defined( $name ) && constant( $name ) ) {
					return array();
				}
			}
			$cfg = defined( 'WP_REDIS_CONFIG' ) && is_array( constant( 'WP_REDIS_CONFIG' ) ) ? (array) constant( 'WP_REDIS_CONFIG' ) : array();
			foreach ( array( 'cluster', 'servers', 'sentinels', 'shards' ) as $name ) {
				if ( ! empty( $cfg[ $name ] ) ) {
					return array();
				}
			}
			$redis_cache = $cfg || defined( 'WP_REDIS_HOST' ) || defined( 'WP_REDIS_PATH' ) || defined( 'WP_REDIS_PORT' ) || defined( 'WP_REDIS_SCHEME' ) || defined( 'WP_REDIS_DATABASE' ) || defined( 'WP_REDIS_PASSWORD' );
			if ( ! $redis_cache && wp_using_ext_object_cache() ) {
				$dropin      = WP_CONTENT_DIR . '/object-cache.php';
				$redis_cache = is_readable( $dropin ) && false !== stripos( (string) file_get_contents( $dropin, false, null, 0, 16384 ), 'redis' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- The start of the local drop-in.
			}
			if ( ! wp_using_ext_object_cache() || ! $redis_cache ) {
				return array();
			}
			$const = static function ( $name, $fallback ) {
				return defined( $name ) ? constant( $name ) : $fallback;
			};
			$p = array(
				'scheme'   => $const( 'WP_REDIS_SCHEME', isset( $cfg['scheme'] ) ? $cfg['scheme'] : 'tcp' ),
				'host'     => $const( 'WP_REDIS_HOST', isset( $cfg['host'] ) ? $cfg['host'] : '127.0.0.1' ),
				'port'     => $const( 'WP_REDIS_PORT', isset( $cfg['port'] ) ? $cfg['port'] : 6379 ),
				'path'     => $const( 'WP_REDIS_PATH', '' ),
				'db'       => $const( 'WP_REDIS_DATABASE', isset( $cfg['database'] ) ? $cfg['database'] : 0 ),
				'password' => $const( 'WP_REDIS_PASSWORD', isset( $cfg['password'] ) ? $cfg['password'] : '' ),
				'prefix'   => $const( 'WP_REDIS_PREFIX', isset( $cfg['prefix'] ) ? $cfg['prefix'] : $const( 'WP_CACHE_KEY_SALT', '' ) ),
			);
			if ( isset( $cfg['username'] ) && is_string( $cfg['username'] ) && ! is_array( $p['password'] ) ) {
				$p['password'] = array( $cfg['username'], (string) $p['password'] );
			}
		}
		$out    = array();
		$scheme = isset( $p['scheme'] ) ? strtolower( (string) $p['scheme'] ) : 'tcp';
		$host   = isset( $p['host'] ) ? trim( (string) $p['host'] ) : '';
		$path   = isset( $p['path'] ) ? trim( (string) $p['path'] ) : '';
		if ( 0 === strpos( $host, 'unix://' ) ) {
			$path = substr( $host, 7 );
		} elseif ( 'unix' === $scheme && '' === $path && '/' === substr( $host, 0, 1 ) ) {
			$path = $host;
		}
		if ( '' !== $path ) {
			$out['path'] = $path;
		} else {
			$out['host'] = '' !== $host ? $host : '127.0.0.1';
			$out['port'] = isset( $p['port'] ) && (int) $p['port'] > 0 ? (int) $p['port'] : 6379;
			if ( in_array( $scheme, array( 'tls', 'rediss', 'ssl' ), true ) ) {
				$out['scheme'] = 'tls';
			}
		}
		if ( isset( $p['db'] ) && (int) $p['db'] > 0 ) {
			$out['db'] = (int) $p['db'];
		}
		$password = isset( $p['password'] ) ? $p['password'] : '';
		if ( isset( $p['user'] ) && '' !== (string) $p['user'] ) {
			$password = array( (string) $p['user'], is_array( $password ) ? (string) end( $password ) : (string) $password );
		}
		if ( is_array( $password ) ) {
			$password = array_values( $password );
			if ( isset( $password[1] ) && '' !== (string) $password[0] ) {
				$out['user'] = (string) $password[0];
			}
			$password = (string) end( $password );
		}
		if ( '' !== (string) $password ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- The masked password (see the docblock).
			$out['auth'] = base64_encode( PNCP_Precheck_Runtime::mask( (string) $password, PNCP_Server_Ips::sig_key( true ) ) );
		}
		if ( isset( $p['prefix'] ) && '' !== (string) $p['prefix'] ) {
			$out['prefix'] = substr( (string) preg_replace( '/[^\x21-\x7e]/', '', (string) $p['prefix'] ), 0, 100 );
		}
		self::load_runtime();
		return $out;
	}

	/**
	 * A flat array of strings and integers as PHP code on one line ('' for an empty array).
	 *
	 * @param array<string, mixed> $values Values.
	 * @return string
	 */
	private static function php_array( $values ) {
		if ( ! $values ) {
			return '';
		}
		$parts = array();
		foreach ( $values as $name => $value ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the values as PHP code.
			$parts[] = var_export( (string) $name, true ) . ' => ' . ( is_int( $value ) ? (string) $value : var_export( (string) $value, true ) );
		}
		return 'array( ' . implode( ', ', $parts ) . ' )';
	}

	/**
	 * Puts the configuration where the check reads it without the disk (PNCP_Precheck_Runtime::load()): Redis from
	 * any context, APCu only from the web server's PHP (WP-CLI has an APCu of its own, if any: fpm_sync()).
	 *
	 * @param string|null $json     config.json (null: read it).
	 * @param string|null $crawlers crawlers.json (null: read it).
	 * @return string Where it went: 'apcu', 'redis' or ''.
	 */
	public static function push_config( $json = null, $crawlers = null ) {
		$c = self::runtime_config();
		if ( '' === $c['dir'] ) {
			return '';
		}
		if ( null === $json ) {
			$json = is_readable( self::config_file() ) ? (string) file_get_contents( self::config_file() ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		}
		$config = json_decode( (string) $json, true );
		if ( ! PNCP_Precheck_Runtime::cfg_ok( $config ) || ( 'cli' === PHP_SAPI && ! $c['redis'] ) ) {
			return '';
		}
		$redis = $c;
		unset( $redis['apcu'] );
		// WP-CLI (its APCu, with apc.enable_cli, is not the web server's): Redis only; push_web() does APCu.
		$web   = 'cli' !== PHP_SAPI;
		$where = PNCP_Precheck_Runtime::cache_config( $c, (array) $config, (string) $json, $crawlers, $web );
		// The Redis copy too while APCu holds it: a check without APCu (another PHP) reads it there.
		if ( 'apcu' === $where && $c['redis'] ) {
			PNCP_Precheck_Runtime::cache_config( $redis, (array) $config, (string) $json, $crawlers, false );
		}
		return $where;
	}

	/**
	 * Brings the store and the files in line (hourly, from fpm_sync(), from an admin page every few minutes): the
	 * changes WP-CLI queued (ops.log), the bans both ways (PNCP_Precheck_Runtime::sync_bans()), the configuration,
	 * the queued events into the log.
	 *
	 * @return array<string, mixed> What was done.
	 */
	public static function sync_store() {
		$c   = self::runtime_config();
		$out = array(
			'backend' => '',
			'ops'     => 0,
			'bans'    => null,
			'config'  => '',
			'events'  => 0,
		);
		if ( '' === $c['dir'] || ! is_dir( $c['dir'] ) ) {
			return $out;
		}
		$out['backend'] = PNCP_Precheck_Runtime::backend( $c );
		$out['ops']     = self::apply_ops( $c );
		$out['bans']    = PNCP_Precheck_Runtime::sync_bans( $c, time() );
		$out['config']  = self::wanted() ? self::push_config() : '';
		$out['events']  = self::import_events();
		set_transient( self::SYNC_SEEN, time(), HOUR_IN_SECONDS );
		return $out;
	}

	/**
	 * From WP-CLI (whose PHP cannot see the web server's APCu): remembers a change of the bans in ops.log, which the
	 * next sync_store() in the web server's PHP applies to APCu. Nothing elsewhere.
	 *
	 * @param string $op    ban, unban or unban_all.
	 * @param string $hash  md5 of the ban key.
	 * @param int    $until Expiry (ban).
	 */
	private static function queue_op( $op, $hash = '', $until = 0 ) {
		if ( 'cli' !== PHP_SAPI || ! is_dir( self::dir() ) ) {
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- A small queue in the plugin's own folder, read by sync_store().
		@file_put_contents( self::dir() . '/ops.log', $op . "\t" . $hash . "\t" . (int) $until . "\n", FILE_APPEND );
	}

	/**
	 * Applies the queued changes (queue_op()) to APCu, in the web server's PHP. In WP-CLI they stay queued.
	 *
	 * @param array<string, mixed> $c Configuration (runtime_config()).
	 * @return int Changes applied.
	 */
	private static function apply_ops( $c ) {
		return 'cli' === PHP_SAPI ? 0 : PNCP_Precheck_Runtime::apply_ops( $c );
	}

	/**
	 * From WP-CLI, after a change of the configuration or the bans: asks the web server's PHP, through the check
	 * itself (PNCP_Precheck_Runtime::serve_sync(), before WordPress loads: no WP-Cron, a few milliseconds), to take
	 * them into its APCu. Only while the line in wp-config.php is there. Its answer, or null.
	 *
	 * @param bool $wait The line was just added: when WordPress answers instead of the check (the web server's
	 *                   OPcache has the previous wp-config.php for opcache.revalidate_freq seconds), ask again once.
	 * @return array<string, mixed>|null
	 */
	public static function push_web( $wait = false ) {
		if ( self::$in_fpm_sync || 'cli' !== PHP_SAPI || ! self::wanted() || ! self::in_config() ) {
			return null;
		}
		self::$in_fpm_sync = true;
		$body              = null;
		$home              = home_url( '/' );
		// The site's address, then over plain HTTP: a server without a certificate for its own name (a stage).
		$args              = array(
			'timeout'     => 5,
			'redirection' => 0,
			'sslverify'   => false, // The site itself, often by its local address or a certificate for another name.
		);
		foreach ( array_unique( array( $home, (string) set_url_scheme( $home, 'http' ) ) ) as $url ) {
			$response = wp_remote_post( add_query_arg( 'pncp_precheck_sync', '1', $url ), $args );
			if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
				$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
				if ( is_array( $body ) && isset( $body['sapi'] ) ) {
					break;
				}
				// WordPress answered: the web server's OPcache still runs the wp-config.php without the new line.
				if ( $wait ) {
					$wait = false;
					sleep( max( 1, (int) ini_get( 'opcache.revalidate_freq' ) ) + 1 );
					$response = wp_remote_post( add_query_arg( 'pncp_precheck_sync', '1', $url ), $args );
					$body     = is_wp_error( $response ) ? null : json_decode( (string) wp_remote_retrieve_body( $response ), true );
					break;
				}
			}
		}
		self::$in_fpm_sync = false;
		return is_array( $body ) && isset( $body['sapi'] ) ? $body : null;
	}

	/**
	 * From WP-CLI: runs sync_store() in the web server's PHP, through a request to the site signed with the site's
	 * key (PNCP_Server_Ips::sign(), checked by ajax_sync()). Its answer, or null when the request failed.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function fpm_sync() {
		if ( self::$in_fpm_sync || '' === (string) get_option( self::KEY, '' ) ) {
			return null;
		}
		self::$in_fpm_sync = true;
		$response          = wp_remote_post(
			admin_url( 'admin-ajax.php' ),
			array(
				'timeout'   => 10,
				'sslverify' => false, // The site itself, often by its local address or a certificate for another name.
				'body'      => array( 'action' => self::SYNC_ACTION ),
			)
		);
		self::$in_fpm_sync = false;
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		return is_array( $body ) && isset( $body['data'] ) && is_array( $body['data'] ) ? $body['data'] : null;
	}

	/**
	 * The admin-ajax answer to fpm_sync(): only for the site's own signed request.
	 */
	public static function ajax_sync() {
		if ( ! PNCP_Server_Ips::sig_ok() ) {
			wp_send_json_error( null, 403 );
		}
		$out          = self::sync_store();
		$out['sapi']  = PHP_SAPI;
		$out['seen']  = self::seen_backend();
		$out['store'] = PNCP_Precheck_Runtime::backend( self::runtime_config() );
		wp_send_json_success( $out );
	}

	/**
	 * On admin pages (the web server's PHP), sync_store() every 5 minutes: the store reaches the files and the log
	 * even when WP-Cron runs from WP-CLI only.
	 */
	public static function admin_sync() {
		if ( wp_doing_ajax() || ! self::wanted() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( (int) get_transient( self::SYNC_SEEN ) > time() - 5 * MINUTE_IN_SECONDS ) {
			return;
		}
		self::sync_store();
	}

	/**
	 * Which store the check used in the last minutes ('apcu', 'redis'), from its note (PNCP_Precheck_Runtime::
	 * note_backend()): '' when there is no note this PHP can see (the files, no request yet, or WP-CLI, which
	 * cannot see the web server's APCu).
	 *
	 * @return string
	 */
	public static function seen_backend() {
		$c      = self::runtime_config();
		$minute = (int) floor( time() / 60 );
		foreach ( array( $minute, $minute - 1, $minute - 2 ) as $m ) {
			$note = (string) PNCP_Precheck_Runtime::mem_get( $c, 'bk:' . $m );
			if ( '' !== $note ) {
				return (string) strtok( $note, '|' );
			}
		}
		return '';
	}

	/**
	 * WP-CLI: `wp scrapelock precheck [status|sync|cleanup]`.
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cli( $args, $assoc_args ) {
		$action = isset( $args[0] ) ? (string) $args[0] : 'status';
		if ( 'cleanup' === $action ) {
			self::cleanup_hits();
			WP_CLI::success( 'Old counters, strikes, nonces and expired bans removed; the bans copied between the store and the files.' );
			return;
		}
		if ( 'sync' === $action ) {
			$here = self::sync_store();
			$web  = self::fpm_sync();
			WP_CLI::log( 'Here (WP-CLI): ' . wp_json_encode( $here ) );
			if ( null === $web ) {
				WP_CLI::warning( 'The request to the site that syncs APCu failed: APCu is only visible to the web server\'s PHP. An admin page or WP-Cron through the web does the same within minutes.' );
				return;
			}
			WP_CLI::success( 'Web server (' . ( isset( $web['sapi'] ) ? (string) $web['sapi'] : '?' ) . '): ' . wp_json_encode( $web ) );
			return;
		}
		if ( 'status' !== $action ) {
			WP_CLI::error( 'Unknown action: status, sync or cleanup.' );
		}
		$c     = self::runtime_config();
		$redis = $c['redis'];
		$rows  = array(
			'pre-cache check' => self::wanted() ? ( self::in_config() ? 'on' : ( self::line_outdated() ? 'on, with the line of an earlier version (wp-config.php could not be changed: see the settings page)' : 'on, line not in wp-config.php yet' ) ) : 'off',
			'APCu'            => function_exists( 'apcu_enabled' ) ? ( 'cli' === PHP_SAPI ? 'cannot be seen from WP-CLI (each PHP has its own; the web server\'s is used by the check when it has one)' : ( apcu_enabled() ? 'on' : 'off' ) ) : 'no extension here',
			'Redis'           => $redis ? ( isset( $redis['path'] ) ? 'unix:' . $redis['path'] : $redis['host'] . ':' . $redis['port'] ) . ( isset( $redis['db'] ) ? ' db ' . $redis['db'] : '' ) . ( isset( $redis['auth'] ) ? ', password set' : '' ) : 'not used (no Redis object cache, or turned off)',
		);
		if ( $redis ) {
			$t     = hrtime( true );
			$probe = $c;
			unset( $probe['apcu'] );
			$ok                     = false !== PNCP_Precheck_Runtime::redis( $probe );
			$rows['Redis answer'] = $ok ? sprintf( 'ok in %.1f ms', ( hrtime( true ) - $t ) / 1e6 ) : 'no connection (the check uses APCu or the files)';
		}
		$web = 'cli' === PHP_SAPI ? self::fpm_sync() : null;
		if ( null !== $web ) {
			$rows['web server store'] = isset( $web['store'] ) ? (string) $web['store'] : '?';
			$rows['seen in requests'] = isset( $web['seen'] ) && '' !== $web['seen'] ? (string) $web['seen'] : 'no note yet (files, or no request in the last 3 minutes)';
		} else {
			$seen                     = self::seen_backend();
			$rows['seen in requests'] = '' !== $seen ? $seen : 'unknown here';
		}
		foreach ( $rows as $name => $value ) {
			WP_CLI::log( str_pad( $name . ':', 20 ) . $value );
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
		// 3.12.9: the events the check queued in APCu or Redis.
		$queued = PNCP_Precheck_Runtime::mem_drain( self::runtime_config() );
		$done   = $queued ? self::import_lines( $queued ) : 0;
		$file   = self::dir() . '/events.log';
		if ( ! is_file( $file ) ) {
			return $done;
		}
		// Renamed first: the check keeps writing to a new file meanwhile.
		$work = self::dir() . '/events-' . wp_generate_password( 8, false ) . '.tmp';
		if ( ! @rename( $file, $work ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic move inside the plugin's folder in uploads.
			return $done;
		}
		$lines = (array) file( $work, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		wp_delete_file( $work );
		return $done + self::import_lines( $lines );
	}

	/**
	 * Writes event lines (time, code, reason, IP, path, User-Agent, tab-separated) into the log.
	 *
	 * @param string[] $lines Lines.
	 * @return int Number of lines.
	 */
	private static function import_lines( $lines ) {
		$rows   = array();
		$bans   = array();
		$probes = array();
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
			if ( 'probe' === $reason && 403 === (int) $code ) {
				$probes[ $ip ] = (int) $time; // 3.5: a probe ban the runtime decided (code 0 = "Monitor only": none).
			}
			// The code is part of the key, as in PNCP_Log::add(): "would block" (0) and real blocks stay apart.
			$key = $ip . '|' . $reason . '|' . (int) $code . '|' . (int) floor( (int) $time / MINUTE_IN_SECONDS );
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
			// 3.5: an escalated probe ban (the second probe within 24 hours) is labelled as a probe.
			// 3.6.1: with the expiry the check wrote, when that is later (Emergency Mode bans for longer than the
			// stored duration): the stored one alone shortened the ban in the database and, mirrored back, in the check.
			$until = max( $since + $minutes * MINUTE_IN_SECONDS, self::mirrored_until( PNCP_Ip::limit_key( (string) $ip ) ) );
			PNCP_Log::import_ban( $ip, $until, isset( $probes[ $ip ] ) ? 'probe' : 'rate_page', $since );
		}
		// 3.5: the short first probe bans (only those without a full ban here: store_ban() mirrors the given expiry
		// to the runtime's file, so a short one imported after a full one would shorten it).
		if ( (int) PNCP_Options::stored()['ban_strikes'] > 0 ) {
			foreach ( $probes as $ip => $since ) {
				if ( ! isset( $bans[ $ip ] ) ) {
					PNCP_Log::import_ban( $ip, $since + PNCP_Bots::probe_first_minutes( $minutes ) * MINUTE_IN_SECONDS, 'probe', $since );
				}
			}
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
		// The test file needs a folder that exists (uploads is created only with the first upload).
		while ( '' !== $context && ! is_dir( $context ) && dirname( $context ) !== $context ) {
			$context = dirname( $context );
		}
		if ( 'direct' !== get_filesystem_method( array(), $context ) || ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof WP_Filesystem_Base ? $wp_filesystem : null;
	}
}
