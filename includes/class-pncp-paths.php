<?php
/**
 * Where this site keeps its files, found with WordPress' functions: the WordPress folder (get_home_path()),
 * wp-content (get_theme_root()), the plugins folder (plugin_dir_path( __FILE__ ) of this plugin), the
 * must-use plugins folder (wp_get_mu_plugins()) and wp-config.php. Used by the file integrity check, the
 * pre-cache check, the Lockdown guard, the early check and the uninstaller, so that no path is hardcoded and
 * none is built from WordPress' internal constants.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The locations of the site's files.
 */
final class PNCP_Paths {

	/**
	 * The WordPress folder (where wp-settings.php, wp-admin and wp-includes are). get_home_path() gives the
	 * site's home folder; when WordPress is in a subfolder of it (siteurl /wordpress, home /), that subfolder
	 * is added. If neither holds wp-settings.php (e.g. an unusual SCRIPT_FILENAME on the command line), the
	 * folder of the wp-settings.php this request loaded is used.
	 *
	 * @return string Without a trailing slash.
	 */
	public static function core() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$home = self::clean( get_home_path() );
		$site = untrailingslashit( (string) wp_parse_url( site_url(), PHP_URL_PATH ) );
		$base = untrailingslashit( (string) wp_parse_url( home_url(), PHP_URL_PATH ) );
		$sub  = '' !== $site && $site !== $base && 0 === strpos( $site . '/', $base . '/' ) ? substr( $site, strlen( $base ) ) : '';
		foreach ( array( $home . $sub, $home ) as $dir ) {
			if ( '' !== $dir && is_file( $dir . '/wp-settings.php' ) ) {
				return $dir;
			}
		}
		foreach ( get_included_files() as $file ) {
			$file = wp_normalize_path( $file );
			if ( '/wp-settings.php' === substr( $file, -16 ) ) {
				return dirname( $file );
			}
		}
		return $home;
	}

	/**
	 * The content folder (wp-content, or wherever the site moved it): the folder of the themes folder.
	 *
	 * @return string Without a trailing slash.
	 */
	public static function content() {
		return self::clean( dirname( get_theme_root() ) );
	}

	/**
	 * The plugins folder: the folder this plugin is in. When the plugin folder is a symbolic link, the
	 * linked path WordPress registered for it (as plugin_basename() does), not the target.
	 *
	 * @return string Without a trailing slash.
	 */
	public static function plugins() {
		global $wp_plugin_paths;
		$own = self::clean( plugin_dir_path( PNCP_FILE ) );
		if ( is_array( $wp_plugin_paths ) ) {
			$link = array_search( $own, array_map( array( __CLASS__, 'clean' ), $wp_plugin_paths ), true );
			if ( false !== $link ) {
				$own = self::clean( (string) $link );
			}
		}
		return dirname( $own );
	}

	/**
	 * The must-use plugins folder: the folder of the must-use plugins WordPress loads, or, when there is
	 * none yet, its usual place in the content folder.
	 *
	 * @return string Without a trailing slash.
	 */
	public static function mu_plugins() {
		$loaded = wp_get_mu_plugins();
		return $loaded ? self::clean( dirname( (string) reset( $loaded ) ) ) : self::content() . '/mu-plugins';
	}

	/**
	 * The wp-config.php that WordPress loads: in the WordPress folder, or in the folder above it when that
	 * one is not another WordPress install (the same rule as WordPress' wp-load.php). '' when not found.
	 *
	 * @return string
	 */
	public static function config() {
		$core = self::core();
		if ( file_exists( $core . '/wp-config.php' ) ) {
			return $core . '/wp-config.php';
		}
		$up = dirname( $core );
		return file_exists( $up . '/wp-config.php' ) && ! file_exists( $up . '/wp-settings.php' ) ? $up . '/wp-config.php' : '';
	}

	/**
	 * A path with forward slashes and without a trailing slash.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function clean( $path ) {
		return untrailingslashit( wp_normalize_path( (string) $path ) );
	}
}
