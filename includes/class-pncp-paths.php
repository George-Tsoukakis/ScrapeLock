<?php
/**
 * Where this site keeps its files, found with WordPress' functions: the WordPress folder (get_home_path()),
 * wp-content (get_theme_root()), the plugins folder (plugin_dir_path( __FILE__ ) of this plugin), the
 * must-use plugins folder (wp_get_mu_plugins()) and wp-config.php. Used by the file integrity check, the
 * pre-cache check, the Lockdown guard, the early check and the uninstaller, so that no path is hardcoded and
 * none is built from WordPress' internal constants. 3.10: also the site-metadata files (/llms.txt, /robots.txt,
 * /.well-known/*, icons, service workers…) that are never a scanner probe (is_site_metadata()).
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
	 * 3.10: the site-metadata files that crawlers, browsers, apps and other services ask for by themselves, key =>
	 * PCRE body matched as #^/(?:BODY)$# against the lower-case path relative to the home path. They are never a
	 * scanner probe, also when the site has no such file (a 404 for /llms.txt is not an attack): /llms.txt and
	 * /llms-full.txt, /ai.txt, /robots.txt, /humans.txt, /ads.txt and /app-ads.txt, /security.txt, the
	 * sitemaps, the favicon and the app icons (apple-touch-icon…), the web app manifests, service workers
	 * (OneSignalSDKWorker.js, sw.js, service-worker.js…) and /.well-known/* (RFC 8615: assetlinks.json,
	 * apple-app-site-association, traffic-advice, passkey-endpoints, security.txt, acme-challenge…). Under
	 * /.well-known/ no segment may start with a dot and no file may be a script, an archive or a dump, so
	 * /.well-known/../, /.well-known/.env and a /.well-known/x.php shell stay probes. Filter
	 * `pncp_site_metadata_paths` (entries that would match a secret file are dropped).
	 *
	 * @return array<string, string>
	 */
	public static function site_metadata_patterns() {
		static $memo = array();
		$id          = home_url( '/' ) . '|' . (int) has_filter( 'pncp_site_metadata_paths' );
		if ( isset( $memo[ $id ] ) ) {
			return $memo[ $id ];
		}
		$segment  = '[a-z0-9_-][a-z0-9._~-]*';
		$patterns = array(
			'llms'           => 'llms(?:-full)?\.txt',
			'ai_txt'         => 'ai\.txt',
			'robots'         => 'robots\.txt',
			'humans'         => 'humans\.txt',
			'ads'            => '(?:app-)?ads\.txt',
			'sellers'        => 'sellers\.json',
			'security_txt'   => 'security\.txt',
			'sitemap'        => '(?:wp-sitemap[a-z0-9_-]*|sitemaps?(?:_index|-index)?|sitemap[0-9]+|sitemap-[a-z0-9_-]+|[a-z0-9_-]+-sitemap[0-9]*|[a-z0-9_-]+_sitemap)\.(?:xml|xml\.gz|xsl)',
			'icons'          => '(?:favicon(?:-[0-9x]+)?\.(?:ico|png|svg|gif|webp)|apple-touch-icon(?:-[0-9x]+)?(?:-precomposed)?\.png|android-chrome-[0-9x]+\.png|mstile-[0-9x]+\.png|safari-pinned-tab\.svg)',
			'manifest'       => '(?:manifest\.json|site\.webmanifest|manifest\.webmanifest|browserconfig\.xml)',
			'service_worker' => '(?:[a-z0-9_-]*sdk[a-z0-9_-]*worker|sw|service-?worker|firebase-messaging-sw|[a-z0-9_-]+-sw)\.js',
			'well_known'     => '\.well-known/(?!(?:.*/)?[^/]*\.(?:php[0-9]?|phtml|phar|asp|aspx|jsp|cgi|pl|py|sh|env|sql|bak|old|swp|zip|tar|gz|tgz|rar|7z)$)' . $segment . '(?:/' . $segment . ')*/?',
		);
		/**
		 * 3.10: the site-metadata files that are never a scanner probe, key => PCRE body matched as
		 * #^/(?:BODY)$# against the lower-case path relative to the home path. Escape #. Entries that are not
		 * valid, or that would match a secret file (/.env, /.git/config, /wp-config.php, /backup.zip, a PHP
		 * file), are dropped.
		 *
		 * @param array<string, string> $patterns Key => body.
		 */
		$filtered = apply_filters( 'pncp_site_metadata_paths', $patterns );
		$valid    = array();
		foreach ( is_array( $filtered ) ? $filtered : array() as $key => $body ) {
			if ( ! is_string( $body ) || '' === $body || false !== strpos( $body, '#' ) ) {
				continue;
			}
			$regex = '#^/(?:' . $body . ')$#';
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A filtered pattern may be invalid.
			if ( false === @preg_match( $regex, '' ) ) {
				continue;
			}
			foreach ( array( '/.env', '/.git/config', '/wp-config.php', '/backup.zip', '/dump.sql', '/x.php', '/.well-known/x.php', '/.well-known/../wp-config.php' ) as $secret ) {
				if ( preg_match( $regex, $secret ) ) {
					continue 2;
				}
			}
			$valid[ (string) $key ] = $body;
		}
		$memo[ $id ] = $valid;
		return $valid;
	}

	/**
	 * 3.10: is the path a site-metadata file (site_metadata_patterns())? Never a scanner probe, in the attack
	 * record, the Bunny log import, the log's groups and "Ban scanners on their first probe".
	 *
	 * @param string $path Request path: percent-encoded or decoded once, with or without the home path and the query.
	 * @return bool
	 */
	public static function is_site_metadata( $path ) {
		$path = (string) $path;
		$path = substr( $path, 0, strcspn( $path, '?#' ) );
		$path = rawurldecode( $path );
		// Still encoded (double encoding), a backslash or a control character: never metadata.
		if ( '' === $path || preg_match( '/[%\\\\\x00-\x1F\x7F]/', $path ) ) {
			return false;
		}
		$path = strtolower( '/' . ltrim( $path, '/' ) );
		$home = strtolower( rtrim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' ) );
		if ( '' !== $home && 0 === strpos( $path, $home . '/' ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		if ( preg_match( '#(?:^|/)\.\.?(?:/|$)|//#', $path ) ) {
			return false; // A "." or ".." segment, or an empty one.
		}
		foreach ( self::site_metadata_patterns() as $body ) {
			if ( preg_match( '#^/(?:' . $body . ')$#', $path ) ) {
				return true;
			}
		}
		return false;
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
