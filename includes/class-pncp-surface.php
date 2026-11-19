<?php
/**
 * What WordPress shows to everyone about itself: pingbacks over XML-RPC, the REST API map and the links
 * that point to it, and the versions of WordPress, PHP and the plugins. Pingbacks and the REST map are off by
 * default; the audit of public REST routes is only a report.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Optional pingback removal, optional hiding of the REST map from visitors, and the list of REST routes
 * anyone can call.
 */
final class PNCP_Surface {

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'xmlrpc_methods', array( __CLASS__, 'xmlrpc_methods' ) );
		add_filter( 'wp_headers', array( __CLASS__, 'headers' ) );
		add_action( 'init', array( __CLASS__, 'discovery_links' ), 20 );
		add_filter( 'rest_index', array( __CLASS__, 'rest_index' ), 99 );
		add_filter( 'rest_namespace_index', array( __CLASS__, 'rest_index' ), 99 );
		add_filter( 'the_generator', array( __CLASS__, 'generator' ), 99 );
		add_filter( 'style_loader_src', array( __CLASS__, 'asset_version' ), 99 );
		add_filter( 'script_loader_src', array( __CLASS__, 'asset_version' ), 99 );
		add_action( 'init', array( __CLASS__, 'powered_by' ) );
		// 3.6: fewer signs of WordPress (hide_fingerprint).
		add_action( 'init', array( __CLASS__, 'fingerprint' ), 20 );
		add_filter( 'x_redirect_by', array( __CLASS__, 'redirect_by' ), 99 );
	}

	/**
	 * Is a setting on (and the protection enabled)?
	 *
	 * @param string $key Setting.
	 * @return bool
	 */
	private static function on( $key ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) ) {
			return false;
		}
		// 3.8: Stealth (PNCP_Stealth) includes both: it removes the rest of the signs of WordPress.
		if ( ( 'hide_versions' === $key || 'hide_fingerprint' === $key ) && class_exists( 'PNCP_Stealth' ) && PNCP_Stealth::active() ) {
			return true;
		}
		// 3.6: "Hide that the site runs on WordPress" includes hiding the versions.
		return ! empty( $s[ $key ] ) || ( 'hide_versions' === $key && ! empty( $s['hide_fingerprint'] ) );
	}

	/* ---------- Pingbacks ---------- */

	/**
	 * Without pingbacks: pingback.ping stays open even with XML-RPC "disabled" (the xmlrpc_enabled filter
	 * only turns off the methods that need a login) and is used to make the site send requests to other
	 * sites, or to check that a page exists. Other XML-RPC methods (e.g. Jetpack) are not affected.
	 *
	 * @param array<string, mixed> $methods XML-RPC methods.
	 * @return array<string, mixed>
	 */
	public static function xmlrpc_methods( $methods ) {
		if ( self::on( 'disable_pingback' ) ) {
			unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		}
		return $methods;
	}

	/**
	 * Without pingbacks there is no X-Pingback header pointing to xmlrpc.php.
	 *
	 * @param array<string, string> $headers Headers.
	 * @return array<string, string>
	 */
	public static function headers( $headers ) {
		if ( self::on( 'disable_pingback' ) || ( self::on( 'hide_fingerprint' ) && ! is_user_logged_in() ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/* ---------- REST map ---------- */

	/**
	 * Hide the REST map from this request? Only for visitors: the editor, wp-admin and logged-in users need it.
	 *
	 * @return bool
	 */
	private static function hides_map() {
		return self::on( 'hide_rest_discovery' ) && ! is_user_logged_in();
	}

	/**
	 * No links to the REST API and to oEmbed in the page head and the Link header, for visitors. The REST
	 * API itself keeps working.
	 */
	public static function discovery_links() {
		if ( ! self::hides_map() ) {
			return;
		}
		remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
		remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );
		remove_action( 'template_redirect', 'rest_output_link_header', 11 );
	}

	/**
	 * /wp-json/ and /wp-json/{namespace} list every namespace and route: a map of the plugins on the site and
	 * of what can be read. For visitors the lists are empty; each route still works when called.
	 *
	 * @param WP_REST_Response $response Index response.
	 * @return WP_REST_Response
	 */
	public static function rest_index( $response ) {
		if ( ! $response instanceof WP_REST_Response || ! self::hides_map() ) {
			return $response;
		}
		$data = $response->get_data();
		if ( is_array( $data ) ) {
			foreach ( array( 'namespaces', 'routes' ) as $key ) {
				if ( isset( $data[ $key ] ) ) {
					$data[ $key ] = array();
				}
			}
			$response->set_data( $data );
		}
		return $response;
	}

	/* ---------- Versions ---------- */

	/**
	 * Scanners read the version of WordPress and of each plugin and look it up in the lists of known
	 * vulnerabilities. Without "generator" (page head, feeds, and the tags of plugins that use it, e.g.
	 * WooCommerce) the version is not given away.
	 *
	 * @param string $tag Generator tag.
	 * @return string
	 */
	public static function generator( $tag ) {
		return self::on( 'hide_versions' ) ? '' : $tag;
	}

	/**
	 * "?ver=7.1.3" on the site's own CSS and JS gives the version of WordPress or of the plugin away. It is
	 * replaced with a hash of it, tied to this site's keys: the same version keeps the same address, so browser
	 * and CDN caches work and a new version still loads fresh files. Addresses of other sites are not changed.
	 *
	 * @param string $src Address of the file.
	 * @return string
	 */
	public static function asset_version( $src ) {
		if ( ! self::on( 'hide_versions' ) || is_admin() || ! is_string( $src ) || false === strpos( $src, 'ver=' ) ) {
			return $src;
		}
		$host = wp_parse_url( $src, PHP_URL_HOST );
		if ( $host && strtolower( (string) $host ) !== strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) ) {
			return $src;
		}
		$query = (string) wp_parse_url( $src, PHP_URL_QUERY );
		parse_str( $query, $args );
		if ( ! isset( $args['ver'] ) || '' === (string) $args['ver'] ) {
			return $src;
		}
		return add_query_arg( 'ver', substr( wp_hash( 'pncp-ver|' . $args['ver'] ), 0, 10 ), $src );
	}

	/**
	 * "X-Powered-By: PHP/8.x" gives the PHP version away (expose_php in php.ini). Removed when the versions
	 * are hidden.
	 */
	public static function powered_by() {
		if ( self::on( 'hide_versions' ) && ! headers_sent() ) {
			header_remove( 'X-Powered-By' );
		}
	}

	/* ---------- 3.6: signs of WordPress ---------- */

	/**
	 * For visitors who are not signed in: no links and scripts in the page head that only WordPress prints (the
	 * REST API and oEmbed links, RSD, Windows Live Writer, the shortlink, the emoji script and styles) and no
	 * Link headers for them. Tools that tell what a site is built with (BuiltWith, Wappalyzer) and scanners look
	 * for these first. Everything keeps working: the REST API, oEmbed and emoji (browsers show them by themselves).
	 * It cannot hide everything: the addresses of themes and plugins (/wp-content/) still show it, and the site's
	 * hosting and DNS are public anyway.
	 */
	public static function fingerprint() {
		if ( ! self::on( 'hide_fingerprint' ) || is_admin() || is_user_logged_in() ) {
			return;
		}
		remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
		remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );
		remove_action( 'template_redirect', 'rest_output_link_header', 11 );
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
		remove_action( 'wp_head', 'wp_shortlink_wp_head', 10 );
		remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
		remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
		remove_action( 'wp_print_styles', 'print_emoji_styles' );
		remove_action( 'wp_enqueue_scripts', 'wp_enqueue_emoji_styles' );
		remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
		remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );
		remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );
	}

	/**
	 * "X-Redirect-By: WordPress" on redirects gives the site away too.
	 *
	 * @param string|false $by Who redirects.
	 * @return string|false
	 */
	public static function redirect_by( $by ) {
		return self::on( 'hide_fingerprint' ) && 'WordPress' === $by ? false : $by;
	}

	/* ---------- Public REST routes ---------- */

	/**
	 * REST routes anyone can call without logging in: those whose permission is __return_true or missing.
	 * Routes with their own permission check (e.g. posts, which are public only when published) are not
	 * listed; their text is covered by "Hide the text" for posts, pages and products.
	 *
	 * @return array<string, array<string, string[]>> namespace => route => methods
	 */
	public static function public_routes() {
		$open   = array();
		$server = rest_get_server();
		foreach ( $server->get_routes() as $route => $handlers ) {
			// The namespace the route was registered with (e.g. "wp/v2", "oembed/1.0"), not only its first part.
			$options = $server->get_route_options( $route );
			foreach ( (array) $handlers as $handler ) {
				$check = isset( $handler['permission_callback'] ) ? $handler['permission_callback'] : null;
				if ( null !== $check && '__return_true' !== $check ) {
					continue;
				}
				if ( is_array( $options ) && ! empty( $options['namespace'] ) ) {
					$namespace = '/' . trim( (string) $options['namespace'], '/' );
				} else {
					$namespace = '/' === $route ? '/' : '/' . strtok( ltrim( $route, '/' ), '/' );
				}
				foreach ( array_keys( array_filter( isset( $handler['methods'] ) ? (array) $handler['methods'] : array() ) ) as $method ) {
					$open[ $namespace ][ $route ][] = (string) $method;
				}
			}
		}
		ksort( $open );
		foreach ( $open as $namespace => $routes ) {
			ksort( $routes );
			foreach ( $routes as $route => $methods ) {
				$routes[ $route ] = array_values( array_unique( $methods ) );
			}
			$open[ $namespace ] = $routes;
		}
		return $open;
	}
}
