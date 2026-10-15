<?php
/**
 * Frontend: αποφασίζει αν η τρέχουσα σελίδα προστατεύεται και φορτώνει JS/CSS.
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
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_filter( 'body_class', array( __CLASS__, 'body_class' ) );
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

		// Page builders σε λειτουργία επεξεργασίας: μόνο έλεγχος ύπαρξης, δεν διαβάζεται τιμή.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		foreach ( array( 'elementor-preview', 'fl_builder', 'et_fb', 'siteorigin_panels_live_editor', 'preview_id', 'bricks', 'ct_builder' ) as $flag ) {
			if ( isset( $_GET[ $flag ] ) ) {
				return false;
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( 'none' !== $s['exempt_cap'] && is_user_logged_in() && current_user_can( $s['exempt_cap'] ) ) {
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
	 * Φορτώνει τα αρχεία μόνο όπου υπάρχει προστασία.
	 */
	public static function enqueue() {
		if ( ! self::should_protect() ) {
			return;
		}

		$s = PNCP_Options::get();

		wp_enqueue_style( 'pncp-protect', PNCP_URL . 'assets/css/protect.css', array(), PNCP_VERSION );
		wp_enqueue_script( 'pncp-protect', PNCP_URL . 'assets/js/protect.js', array(), PNCP_VERSION, true );

		$title = is_singular() ? get_the_title() : wp_get_document_title();

		$config = array(
			'selection'   => (bool) $s['block_selection'],
			'contextMenu' => (bool) $s['block_context_menu'],
			'shortcuts'   => (bool) $s['block_shortcuts'],
			'devtools'    => (bool) $s['block_devtools'],
			'imageDrag'   => (bool) $s['block_image_drag'],
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
		if ( 'block' === $s['print_mode'] ) {
			$classes[] = 'pncp-print-block';
		} elseif ( 'source' === $s['print_mode'] ) {
			$classes[] = 'pncp-print-source';
		}

		return $classes;
	}
}
