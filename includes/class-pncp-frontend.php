<?php
/**
 * Frontend: αποφασίζει αν η τρέχουσα σελίδα προστατεύεται, φορτώνει JS/CSS πριν από κάθε άλλο script,
 * στέλνει τα headers κατά του iframe και τη δήλωση εξαίρεσης από εκπαίδευση AI (TDM).
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Η προστασία στο δημόσιο site.
 */
final class PNCP_Frontend {

	/**
	 * Cache της απόφασης για το τρέχον request.
	 *
	 * @var bool|null
	 */
	private static $protect = null;

	/**
	 * Δένει τα hooks.
	 */
	public static function init() {
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'register' ), 0 );
		// Αμέσως μετά το wp_enqueue_scripts (priority 1) και πριν τυπωθούν τα υπόλοιπα scripts (priority 9).
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
	 * Προστατεύεται η τρέχουσα σελίδα;
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
	 * Ξεχνά την απόφαση (για tests).
	 */
	public static function reset() {
		self::$protect = null;
	}

	/**
	 * Η λογική της απόφασης, χωρίς το filter.
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

		// Page builders σε λειτουργία επεξεργασίας. Μόνο για χρήστη που μπορεί πράγματι να επεξεργαστεί: αλλιώς
		// ένα ?elementor-preview=1 στο URL θα έκλεινε την προστασία για οποιονδήποτε επισκέπτη.
		if ( self::is_builder_request() ) {
			return false;
		}

		if ( PNCP_Options::user_is_exempt( $s ) ) {
			return false;
		}

		$queried = get_queried_object_id();
		if ( ! $queried && function_exists( 'is_shop' ) && is_shop() ) {
			// Η σελίδα Καταστήματος είναι archive, οπότε το queried object δεν έχει ID σελίδας.
			$queried = wc_get_page_id( 'shop' );
		}
		if ( $queried && in_array( (int) $queried, PNCP_Options::excluded_ids( $s ), true ) ) {
			return false;
		}

		// Καλάθι, ταμείο και λογαριασμός: ο πελάτης πρέπει να αντιγράφει αριθμούς παραγγελίας, κωδικούς κουπονιών κ.λπ.
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

		// Άλλα singular (custom post types): ακολουθούν τη ρύθμιση των άρθρων.
		if ( is_singular() ) {
			return ! empty( $s['scope_posts'] );
		}

		return false;
	}

	/**
	 * Αίτημα page builder (Elementor, Beaver, Divi, SiteOrigin, Bricks, Oxygen) ή προεπισκόπησης, από
	 * συνδεδεμένο χρήστη που μπορεί να επεξεργαστεί τη σελίδα.
	 *
	 * @return bool
	 */
	public static function is_builder_request() {
		$found = false;
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Μόνο έλεγχος ύπαρξης· η άδεια ελέγχεται παρακάτω.
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
		return $id ? current_user_can( 'edit_post', $id ) : current_user_can( 'edit_posts' );
	}

	/**
	 * Καταχωρεί τα αρχεία και τις ρυθμίσεις του script.
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
				'source'     => __( 'Πηγή', 'content-protect' ),
				'printBlock' => __( 'Η εκτύπωση αυτής της σελίδας δεν επιτρέπεται.', 'content-protect' ),
			),
		);

		wp_add_inline_script( 'pncp-protect', 'window.pncpConfig = ' . wp_json_encode( $config ) . ';', 'before' );
	}

	/**
	 * Τυπώνει το script στο <head>, πριν από τα scripts του θέματος και των άλλων plugins. Οι listeners του
	 * μπαίνουν πρώτοι στο window (capture), οπότε κανένα άλλο script δεν μπορεί να τους παρακάμψει.
	 */
	public static function print_early() {
		if ( wp_script_is( 'pncp-protect', 'registered' ) && ! wp_script_is( 'pncp-protect', 'done' ) ) {
			wp_print_scripts( array( 'pncp-protect' ) );
		}
	}

	/**
	 * Τα εργαλεία βελτιστοποίησης (Cloudflare Rocket Loader, LiteSpeed, Autoptimize, WP Rocket) δεν πρέπει να
	 * καθυστερούν ή να ενώνουν το script της προστασίας.
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
	 * Headers: η σελίδα δεν ανοίγει μέσα σε iframe άλλου site, και δήλωση TDM.
	 */
	public static function send_headers() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || headers_sent() || is_admin() ) {
			return;
		}
		// Εξαιρούνται: οι σελίδες embed (oEmbed), που υπάρχουν για να μπαίνουν σε iframe, και το ταμείο / η
		// σελίδα παραγγελίας, που κάποιες τράπεζες ανοίγουν μέσα στο δικό τους iframe.
		$checkout = function_exists( 'is_checkout' ) && ( is_checkout() || ( function_exists( 'is_wc_endpoint_url' ) && is_wc_endpoint_url( 'order-received' ) ) );
		if ( ! empty( $s['block_framing'] ) && ! is_embed() && ! $checkout && apply_filters( 'pncp_block_framing', true ) ) {
			$sent = strtolower( implode( "\n", headers_list() ) );
			// Δεν αντικαθιστούμε headers ασφαλείας άλλου plugin ή του server (π.χ. X-Frame-Options: DENY).
			if ( false === strpos( $sent, 'x-frame-options:' ) ) {
				header( 'X-Frame-Options: SAMEORIGIN' );
			}
			if ( false === strpos( $sent, 'frame-ancestors' ) ) {
				// Δεύτερο header CSP (replace = false): οι browsers εφαρμόζουν και τα δύο, το υπάρχον μένει.
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
	 * Meta tags TDM (Text and Data Mining, Οδηγία ΕΕ 2019/790 άρθρο 4 και πρότυπο TDMRep του W3C).
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
	 * Οδηγίες noai / noimageai στο robots meta (τις διαβάζουν αρκετά AI εργαλεία· οι μηχανές αναζήτησης τις αγνοούν).
	 *
	 * @param array<string, bool|string> $robots Οδηγίες.
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
	 * /.well-known/tdmrep.json (TDMRep). Λειτουργεί όταν ο web server περνά το αίτημα στο WordPress
	 * (δεν υπάρχει φυσικό αρχείο με αυτό το όνομα).
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
	 * Το URL της σελίδας, χωρίς query string (για καθαρή αναφορά πηγής).
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
	 * Κλάσεις στο body, που ενεργοποιούν το CSS.
	 *
	 * @param string[] $classes Κλάσεις.
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
