<?php
/**
 * Frontend: decides whether the current page is protected, loads JS/CSS before any other script,
 * sends the anti-iframe headers and the AI-training opt-out declaration (TDM).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Protection on the public site.
 */
final class PNCP_Frontend {

	/**
	 * Cache of the decision for the current request.
	 *
	 * @var bool|null
	 */
	private static $protect = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'register' ), 0 );
		// Right after wp_enqueue_scripts (priority 1) and before the other scripts are printed (priority 9).
		add_action( 'wp_head', array( __CLASS__, 'print_early' ), 2 );
		add_action( 'wp_head', array( __CLASS__, 'tdm_meta' ), 1 );
		add_filter( 'body_class', array( __CLASS__, 'body_class' ) );
		add_action( 'template_redirect', array( __CLASS__, 'send_headers' ), 1 );
		add_filter( 'wp_robots', array( __CLASS__, 'robots_meta' ) );
		add_filter( 'wp_script_attributes', array( __CLASS__, 'script_attributes' ) );
		add_filter( 'wp_inline_script_attributes', array( __CLASS__, 'script_attributes' ) );
		add_action( 'init', array( __CLASS__, 'tdmrep_json' ), 1 );
	}

	/**
	 * Is the current page protected?
	 *
	 * @return bool
	 */
	public static function should_protect() {
		if ( null !== self::$protect ) {
			return self::$protect;
		}

		self::$protect = (bool) apply_filters( 'pncp_should_protect', self::decide(), PNCP_Options::get() );
		return self::$protect;
	}

	/**
	 * Forgets the decision (for tests).
	 */
	public static function reset() {
		self::$protect = null;
	}

	/**
	 * The decision logic, without the filter.
	 *
	 * @return bool
	 */
	private static function decide() {
		$s = PNCP_Options::get();

		if ( empty( $s['enabled'] ) || is_admin() || is_feed() || is_preview() || is_customize_preview() || is_embed() ) {
			return false;
		}

		if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return false;
		}

		// Page builders in edit mode. Only for a user who can actually edit: otherwise
		// an ?elementor-preview=1 in the URL would turn protection off for any visitor.
		if ( self::is_builder_request() ) {
			return false;
		}

		if ( PNCP_Options::user_is_exempt( $s ) ) {
			return false;
		}

		$queried = get_queried_object_id();
		if ( ! $queried && function_exists( 'is_shop' ) && is_shop() ) {
			// The Shop page is an archive, so the queried object has no page ID.
			$queried = wc_get_page_id( 'shop' );
		}
		if ( $queried && in_array( (int) $queried, PNCP_Options::excluded_ids( $s ), true ) ) {
			return false;
		}

		// Cart, checkout and account: the customer must be able to copy order numbers, coupon codes etc.
		if ( ! empty( $s['skip_woo_pages'] ) && function_exists( 'is_woocommerce' ) ) {
			if ( is_cart() || is_checkout() || is_account_page() ) {
				return false;
			}
		}

		if ( function_exists( 'is_product' ) && is_product() ) {
			return ! empty( $s['scope_products'] );
		}

		if ( is_singular( 'post' ) ) {
			return ! empty( $s['scope_posts'] );
		}

		if ( is_page() && ! is_front_page() ) {
			return ! empty( $s['scope_pages'] );
		}

		if ( is_front_page() || is_home() || is_archive() || is_search() || is_404() ) {
			return ! empty( $s['scope_home'] );
		}

		// Other singulars (custom post types): follow the posts setting.
		if ( is_singular() ) {
			return ! empty( $s['scope_posts'] );
		}

		return false;
	}

	/**
	 * Page builder (Elementor, Beaver, Divi, SiteOrigin, Bricks, Oxygen) or preview request, from a
	 * logged-in user who can edit the page.
	 *
	 * @return bool
	 */
	public static function is_builder_request() {
		$found = false;
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Existence check only; the capability is checked below.
		foreach ( array( 'elementor-preview', 'fl_builder', 'et_fb', 'siteorigin_panels_live_editor', 'preview_id', 'bricks', 'ct_builder' ) as $flag ) {
			if ( isset( $_GET[ $flag ] ) ) {
				$found = true;
				break;
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		if ( ! $found || ! is_user_logged_in() ) {
			return false;
		}
		$id = get_queried_object_id();
		return $id ? PNCP_Lockdown::can( 'edit_post', $id ) : PNCP_Lockdown::can( 'edit_posts' );
	}

	/**
	 * Registers the files and the script settings.
	 */
	public static function register() {
		if ( ! self::should_protect() ) {
			return;
		}

		$s = PNCP_Options::get();

		wp_enqueue_style( 'pncp-protect', PNCP_URL . 'assets/css/protect.css', array(), PNCP_VERSION );
		wp_register_script( 'pncp-protect', PNCP_URL . 'assets/js/protect.js', array(), PNCP_VERSION, false );

		$title = is_singular() ? get_the_title() : wp_get_document_title();

		$config = array(
			'selection'   => (bool) $s['block_selection'],
			'contextMenu' => (bool) $s['block_context_menu'],
			'shortcuts'   => (bool) $s['block_shortcuts'],
			'devtools'    => (bool) $s['block_devtools'],
			'imageDrag'   => (bool) $s['block_image_drag'],
			'textDrag'    => (bool) $s['block_text_drag'],
			'blur'        => (bool) $s['blur_on_capture'],
			'copyMode'    => $s['copy_mode'],
			'minChars'    => (int) $s['attribution_min_chars'],
			'printMode'   => $s['print_mode'],
			'showMessage' => (bool) $s['show_message'],
			'message'     => $s['message'],
			'sourceTitle' => wp_strip_all_tags( html_entity_decode( $title, ENT_QUOTES, get_bloginfo( 'charset' ) ) ),
			'sourceUrl'   => esc_url_raw( self::current_url() ),
			'siteName'    => wp_strip_all_tags( get_bloginfo( 'name' ) ),
			'i18n'        => array(
				'source'     => __( 'Source', 'scrapelock' ),
				'printBlock' => __( 'Printing this page is not allowed.', 'scrapelock' ),
			),
		);

		wp_add_inline_script( 'pncp-protect', 'window.pncpConfig = ' . wp_json_encode( $config ) . ';', 'before' );
	}

	/**
	 * Prints the script in <head>, before the scripts of the theme and other plugins. Its listeners
	 * are added first on window (capture), so no other script can bypass them.
	 */
	public static function print_early() {
		if ( wp_script_is( 'pncp-protect', 'registered' ) && ! wp_script_is( 'pncp-protect', 'done' ) ) {
			wp_print_scripts( array( 'pncp-protect' ) );
		}
	}

	/**
	 * Optimization tools (Cloudflare Rocket Loader, LiteSpeed, Autoptimize, WP Rocket) must not
	 * delay or combine the protection script.
	 *
	 * @param array<string, string> $attributes Attributes.
	 * @return array<string, string>
	 */
	public static function script_attributes( $attributes ) {
		if ( isset( $attributes['id'] ) && in_array( $attributes['id'], array( 'pncp-protect-js', 'pncp-protect-js-before' ), true ) ) {
			$attributes['data-cfasync']            = 'false';
			$attributes['data-no-optimize']        = '1';
			$attributes['data-no-defer']           = '1';
			$attributes['data-no-minify']          = '1';
			$attributes['data-pagespeed-no-defer'] = '';
		}
		return $attributes;
	}

	/**
	 * Headers: the page does not open inside another site's iframe, plus the TDM declaration.
	 */
	public static function send_headers() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || headers_sent() || is_admin() ) {
			return;
		}
		// Excluded: embed pages (oEmbed), which exist to be placed in iframes, and the checkout / order
		// page, which some banks open inside their own iframe.
		$checkout = function_exists( 'is_checkout' ) && ( is_checkout() || ( function_exists( 'is_wc_endpoint_url' ) && is_wc_endpoint_url( 'order-received' ) ) );
		if ( ! empty( $s['block_framing'] ) && ! is_embed() && ! $checkout && apply_filters( 'pncp_block_framing', true ) ) {
			$sent = strtolower( implode( "\n", headers_list() ) );
			// We do not replace security headers set by another plugin or the server (e.g. X-Frame-Options: DENY).
			if ( false === strpos( $sent, 'x-frame-options:' ) ) {
				header( 'X-Frame-Options: SAMEORIGIN' );
			}
			if ( false === strpos( $sent, 'frame-ancestors' ) ) {
				// Second CSP header (replace = false): browsers apply both, the existing one stays.
				header( "Content-Security-Policy: frame-ancestors 'self'", false );
			}
		}
		if ( ! empty( $s['tdm_reservation'] ) ) {
			header( 'tdm-reservation: 1' );
			if ( '' !== $s['tdm_policy_url'] ) {
				header( 'tdm-policy: ' . esc_url_raw( $s['tdm_policy_url'] ) );
			}
		}
	}

	/**
	 * TDM meta tags (Text and Data Mining, EU Directive 2019/790 Article 4 and the W3C TDMRep standard).
	 */
	public static function tdm_meta() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['tdm_reservation'] ) ) {
			return;
		}
		echo '<meta name="tdm-reservation" content="1">' . "\n";
		if ( '' !== $s['tdm_policy_url'] ) {
			echo '<meta name="tdm-policy" content="' . esc_url( $s['tdm_policy_url'] ) . '">' . "\n";
		}
	}

	/**
	 * noai / noimageai directives in the robots meta (read by several AI tools; search engines ignore them).
	 *
	 * @param array<string, bool|string> $robots Directives.
	 * @return array<string, bool|string>
	 */
	public static function robots_meta( $robots ) {
		$s = PNCP_Options::get();
		if ( ! empty( $s['enabled'] ) && ! empty( $s['tdm_reservation'] ) ) {
			$robots['noai']      = true;
			$robots['noimageai'] = true;
		}
		return $robots;
	}

	/**
	 * /.well-known/tdmrep.json (TDMRep). Works when the web server passes the request to WordPress
	 * (there is no physical file with that name).
	 */
	public static function tdmrep_json() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['tdm_reservation'] ) ) {
			return;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		if ( '/.well-known/tdmrep.json' !== $path ) {
			return;
		}
		$rule = array(
			'location'        => '/*',
			'tdm-reservation' => 1,
		);
		if ( '' !== $s['tdm_policy_url'] ) {
			$rule['tdm-policy'] = esc_url_raw( $s['tdm_policy_url'] );
		}
		status_header( 200 );
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: public, max-age=86400' );
		echo wp_json_encode( array( $rule ) );
		exit;
	}

	/**
	 * The page URL, without query string (for a clean source reference).
	 *
	 * @return string
	 */
	private static function current_url() {
		if ( is_singular() ) {
			return (string) get_permalink();
		}
		global $wp;
		return home_url( isset( $wp->request ) ? user_trailingslashit( $wp->request ) : '/' );
	}

	/**
	 * Body classes that enable the CSS.
	 *
	 * @param string[] $classes Classes.
	 * @return string[]
	 */
	public static function body_class( $classes ) {
		if ( ! self::should_protect() ) {
			return $classes;
		}

		$s         = PNCP_Options::get();
		$classes[] = 'pncp-protected';

		if ( ! empty( $s['block_selection'] ) ) {
			$classes[] = 'pncp-no-select';
		}
		if ( ! empty( $s['block_image_drag'] ) ) {
			$classes[] = 'pncp-no-img-save';
		}
		if ( 'block' === $s['print_mode'] ) {
			$classes[] = 'pncp-print-block';
		} elseif ( 'source' === $s['print_mode'] ) {
			$classes[] = 'pncp-print-source';
		}

		return $classes;
	}
}
