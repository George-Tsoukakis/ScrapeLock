<?php
/**
 * Early check: a small must-use plugin that blocks the obvious cases (bot User-Agent, blocked IP or
 * referrer, temporarily blocked IP) before the theme and the other plugins load. Optional, off by default.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Writes / removes the mu-plugin and runs the early check from it.
 *
 * Everything that needs WordPress to be fully loaded (verification of search engines, limits, logged-in
 * users and their roles, private feeds, the trap) stays in the normal check, which runs afterwards anyway.
 * Here, when in doubt, the request passes.
 */
final class PNCP_Early {

	const FILE   = 'scrapelock-early.php';
	const MARKER = 'ScrapeLock early check';

	/**
	 * Runs from the mu-plugin, before the other plugins load.
	 *
	 * @param string $dir      The plugin's folder (with a trailing slash).
	 * @param string $basename The plugin's basename (scrapelock/scrapelock.php), to check that it is active.
	 */
	public static function run( $dir, $basename ) {
		if ( ! self::plugin_active( $basename ) ) {
			return;
		}
		defined( 'PNCP_OPTION' ) || define( 'PNCP_OPTION', 'pncp_settings' );
		foreach ( array( 'options', 'ip', 'log', 'private-urls', 'bots' ) as $name ) {
			require_once $dir . 'includes/class-pncp-' . $name . '.php';
		}

		$verdict = self::check();
		// The normal check reads the settings and the IP again, after translations and the other plugins' filters.
		PNCP_Options::flush();
		PNCP_Ip::reset();
		if ( $verdict ) {
			PNCP_Log::add( $verdict[1], $verdict[0], $verdict[2] );
			PNCP_Bots::no_cache();
			// The plugin's translations load later (WordPress 6.7+ warns about earlier use): the same text
			// as die_html(), untranslated.
			wp_die( esc_html( 'Access denied.' ), esc_html( (string) $verdict[0] ), array( 'response' => (int) $verdict[0] ) );
		}
	}

	/**
	 * Is ScrapeLock active on this site (or network-wide)?
	 *
	 * @param string $basename Basename.
	 * @return bool
	 */
	private static function plugin_active( $basename ) {
		if ( in_array( $basename, (array) get_option( 'active_plugins', array() ), true ) ) {
			return true;
		}
		return is_multisite() && isset( ( (array) get_site_option( 'active_sitewide_plugins', array() ) )[ $basename ] );
	}

	/**
	 * The early check.
	 *
	 * @return array{0:int, 1:string, 2:string}|null [code, reason, IP], or null if the request passes.
	 */
	public static function check() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['early_mode'] ) || self::skip_request() ) {
			return null;
		}

		$ip = PNCP_Ip::client_ip();
		if ( '' === $ip || PNCP_Ip::is_local( $ip ) ) {
			return null;
		}
		if ( PNCP_Ip::reliable() && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['allow_ips'] ) ) ) {
			return null;
		}
		/** This filter is documented in includes/class-pncp-bots.php. Only mu-plugins can use it here. */
		if ( apply_filters( 'pncp_skip_guard', false, 'early', $ip ) ) {
			return null;
		}

		// A Cloudflare address means "Real visitor IP" is not set: no IP-based decision then, or a single
		// block would hit every visitor that comes through the same Cloudflare server.
		$per_ip = ! PNCP_Ip::in_any( $ip, PNCP_Ip::list_of( 'cloudflare' ) );

		if ( $per_ip && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['block_ips'] ) ) ) {
			return array( 403, 'blocked_ip', $ip );
		}
		if ( PNCP_Bots::referrer_blocked( $s ) ) {
			return array( 403, 'blocked_ref', $ip );
		}

		// Googlebot, Bingbot etc. are verified with DNS in the normal check: here they always pass.
		$ua = PNCP_Bots::user_agent();
		if ( '' !== PNCP_Bots::claimed_crawler( $ua ) ) {
			return null;
		}
		if ( $per_ip && PNCP_Log::is_banned( $ip ) ) {
			return array( 403, 'banned', $ip );
		}

		$allowed_ua = '' !== $ua && ( PNCP_Bots::allow_list_match( $ua, $ip, $s ) || PNCP_Bots::ua_in_list( $ua, PNCP_Options::allowed_ai_search() ) );
		if ( ! empty( $s['block_bots'] ) && ! $allowed_ua ) {
			if ( '' === trim( $ua ) && ! empty( $s['block_empty_ua'] ) ) {
				return array( 403, 'empty_ua', $ip );
			}
			if ( '' !== $ua && PNCP_Bots::ua_in_list( $ua, PNCP_Options::blocked_agents( $s ) ) ) {
				return array( 403, 'bot_ua', $ip );
			}
		}
		return null;
	}

	/**
	 * Requests left entirely to the normal check: wp-admin, AJAX, cron, WP-CLI, XML-RPC, login, forms
	 * (anything but GET / HEAD), logged-in users, the trap and the private feeds.
	 *
	 * @return bool
	 */
	private static function skip_request() {
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			return true;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) ) {
			return true;
		}
		// The cookie names are defined after the mu-plugins load: any wordpress_logged_in_* cookie is enough.
		foreach ( array_keys( $_COOKIE ) as $name ) {
			if ( 0 === strpos( (string) $name, 'wordpress_logged_in_' ) || ( defined( 'LOGGED_IN_COOKIE' ) && LOGGED_IN_COOKIE === $name ) ) {
				return true;
			}
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = PNCP_Private_Urls::relative_path( rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) ) );
		if ( preg_match( '#^/(?:index\.php/)?(?:wp-login\.php|cp-[0-9a-f]{10}(?:/|$))#i', $path ) || PNCP_Bots::is_open_path( $path ) ) {
			return true;
		}
		$s = PNCP_Options::get();
		return '' !== trim( (string) $s['private_paths'] ) && PNCP_Private_Urls::path_matches( preg_replace( '#^/index\.php(?=/)#i', '', $path ), PNCP_Options::parse_list( $s['private_paths'] ) );
	}

	/* ---------- The mu-plugin file ---------- */

	/**
	 * Path of the mu-plugin.
	 *
	 * @return string
	 */
	public static function path() {
		return trailingslashit( WPMU_PLUGIN_DIR ) . self::FILE;
	}

	/**
	 * Is our mu-plugin in place, pointing to this copy of the plugin?
	 *
	 * @return bool
	 */
	public static function installed() {
		$path = self::path();
		if ( ! is_readable( $path ) ) {
			return false;
		}
		$code = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return self::code() === $code;
	}

	/**
	 * The mu-plugin code. Only paths, written with var_export; if the plugin folder disappears, it does nothing.
	 *
	 * @return string
	 */
	public static function code() {
		$dir      = trailingslashit( PNCP_DIR );
		$basename = plugin_basename( PNCP_FILE );
		return "<?php\n"
			. "/**\n"
			. ' * Plugin Name: ' . self::MARKER . "\n"
			. " * Description: Created by ScrapeLock (setting \"Early check\"). Blocks known bots before the theme and the other plugins load. It is removed when the setting is turned off or ScrapeLock is deactivated.\n"
			. " *\n"
			. " * @package ScrapeLock\n"
			. " */\n\n"
			. "defined( 'ABSPATH' ) || exit;\n\n"
			. '$pncp_early_dir = ' . var_export( $dir, true ) . ";\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the path as PHP code.
			. "if ( is_readable( \$pncp_early_dir . 'includes/class-pncp-early.php' ) ) {\n"
			. "\trequire_once \$pncp_early_dir . 'includes/class-pncp-early.php';\n"
			. "\tPNCP_Early::run( \$pncp_early_dir, " . var_export( $basename, true ) . " );\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the basename as PHP code.
			. "}\n"
			. "unset( \$pncp_early_dir );\n";
	}

	/**
	 * Brings the mu-plugin in line with the setting: writes it when "Early check" is on, removes it when off.
	 * On multisite it is shared by all sites, so it is only written there (each site checks its own setting).
	 *
	 * @return bool Whether the file is now as it should be.
	 */
	public static function sync() {
		$s = PNCP_Options::stored();
		if ( ! empty( $s['early_mode'] ) ) {
			return self::installed() || self::write();
		}
		if ( is_multisite() ) {
			return true;
		}
		self::remove();
		return ! file_exists( self::path() );
	}

	/**
	 * Writes the mu-plugin. Only with direct file access: never asks for FTP details.
	 *
	 * @return bool
	 */
	private static function write() {
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return false;
		}
		$dir = trailingslashit( WPMU_PLUGIN_DIR );
		if ( ! $filesystem->is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		$path = self::path();
		if ( $filesystem->exists( $path ) && ! self::ours( $path ) ) {
			return false; // Someone else's file with the same name: never overwritten.
		}
		return $filesystem->put_contents( $path, self::code(), FS_CHMOD_FILE ) && self::installed();
	}

	/**
	 * Removes the mu-plugin, only if it is ours.
	 */
	public static function remove() {
		$path = self::path();
		if ( file_exists( $path ) && self::ours( $path ) ) {
			wp_delete_file( $path );
		}
	}

	/**
	 * Was the file written by ScrapeLock?
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	public static function ours( $path ) {
		if ( ! is_readable( $path ) ) {
			return false;
		}
		$head = (string) file_get_contents( $path, false, null, 0, 200 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return false !== strpos( $head, 'Plugin Name: ' . self::MARKER );
	}

	/**
	 * WP_Filesystem with direct access, or null.
	 *
	 * @return WP_Filesystem_Base|null
	 */
	private static function filesystem() {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( 'direct' !== get_filesystem_method( array(), WPMU_PLUGIN_DIR ) || ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof WP_Filesystem_Base ? $wp_filesystem : null;
	}
}
