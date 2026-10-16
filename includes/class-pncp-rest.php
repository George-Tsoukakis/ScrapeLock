<?php
/**
 * REST API: κρύβει το κείμενο των άρθρων από επισκέπτες, χωρίς να κλείνει το REST.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Αδειάζει τα `content` και `excerpt` στα δημόσια post types για όσους δεν μπορούν να επεξεργαστούν περιεχόμενο.
 * Τα υπόλοιπα endpoints (φόρμες, oEmbed, SEO plugins, δικά σας namespaces) δεν επηρεάζονται.
 */
final class PNCP_Rest {

	/**
	 * Δένει τα hooks.
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_filters' ), 99 );
	}

	/**
	 * Τα post types που φιλτράρονται: δημόσια, με REST, εκτός από τα συνημμένα.
	 *
	 * @return string[]
	 */
	public static function post_types() {
		$types = get_post_types(
			array(
				'public'       => true,
				'show_in_rest' => true,
			)
		);
		unset( $types['attachment'] );

		/**
		 * Φίλτρο για να προσθέσετε ή να αφαιρέσετε post types.
		 *
		 * @param string[] $types Post types.
		 */
		return (array) apply_filters( 'pncp_rest_post_types', array_values( $types ) );
	}

	/**
	 * Προσθέτει ένα filter ανά post type.
	 */
	public static function register_filters() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['rest_hide_content'] ) ) {
			return;
		}
		foreach ( self::post_types() as $type ) {
			add_filter( 'rest_prepare_' . $type, array( __CLASS__, 'strip' ), 99, 3 );
		}
		// Το δημόσιο Store API του WooCommerce (/wc/store/v1/products) δίνει περιγραφές προϊόντων χωρίς σύνδεση.
		// Μόνο τα products: το καλάθι και το ταμείο δεν πειράζονται.
		add_filter( 'rest_post_dispatch', array( __CLASS__, 'strip_store_api' ), 99, 3 );
	}

	/**
	 * Αδειάζει τα description / short_description στο WooCommerce Store API για επισκέπτες.
	 *
	 * @param WP_HTTP_Response $result  Η απάντηση.
	 * @param WP_REST_Server   $server  Ο server.
	 * @param WP_REST_Request  $request Το αίτημα.
	 * @return WP_HTTP_Response
	 */
	public static function strip_store_api( $result, $server, $request ) {
		if ( ! $result instanceof WP_HTTP_Response || ! preg_match( '#^/wc/store(/v\d+)?/products#', (string) $request->get_route() ) ) {
			return $result;
		}
		if ( current_user_can( 'edit_posts' ) || PNCP_Options::user_is_exempt( PNCP_Options::get() ) ) {
			return $result;
		}
		if ( ! apply_filters( 'pncp_rest_hide_content', true, null ) ) {
			return $result;
		}

		$data = $result->get_data();
		if ( ! is_array( $data ) ) {
			return $result;
		}
		$strip = static function ( $item ) {
			if ( is_array( $item ) ) {
				foreach ( array( 'description', 'short_description' ) as $field ) {
					if ( isset( $item[ $field ] ) && is_string( $item[ $field ] ) ) {
						$item[ $field ] = '';
					}
				}
			}
			return $item;
		};
		// Λίστα προϊόντων ή ένα προϊόν.
		$data = isset( $data['id'] ) ? $strip( $data ) : array_map( $strip, $data );
		$result->set_data( $data );

		return $result;
	}

	/**
	 * Πρέπει να κρυφτεί το κείμενο για τον τρέχοντα χρήστη;
	 *
	 * @param WP_Post $post Το άρθρο.
	 * @return bool
	 */
	private static function should_strip( $post ) {
		// Όσοι γράφουν περιεχόμενο το χρειάζονται (block editor, εφαρμογές).
		if ( current_user_can( 'edit_posts' ) || PNCP_Options::user_is_exempt( PNCP_Options::get() ) ) {
			return false;
		}
		if ( in_array( (int) $post->ID, PNCP_Options::excluded_ids( PNCP_Options::get() ), true ) ) {
			return false;
		}

		/**
		 * Φίλτρο για εξαιρέσεις από κώδικα (π.χ. ένα δικό σας εργαλείο που διαβάζει άρθρα μέσω REST).
		 *
		 * @param bool         $strip Αν θα κρυφτεί το κείμενο.
		 * @param WP_Post|null $post  Το άρθρο (null για το WooCommerce Store API).
		 */
		return (bool) apply_filters( 'pncp_rest_hide_content', true, $post );
	}

	/**
	 * Αδειάζει το κείμενο στην απάντηση.
	 *
	 * @param WP_REST_Response $response Η απάντηση.
	 * @param WP_Post          $post     Το άρθρο.
	 * @param WP_REST_Request  $request  Το αίτημα.
	 * @return WP_REST_Response
	 */
	public static function strip( $response, $post, $request ) {
		if ( ! $response instanceof WP_REST_Response || ! $post instanceof WP_Post || ! self::should_strip( $post ) ) {
			return $response;
		}

		$data = $response->get_data();
		foreach ( array( 'content', 'excerpt' ) as $field ) {
			if ( isset( $data[ $field ] ) && is_array( $data[ $field ] ) ) {
				$data[ $field ]['rendered'] = '';
				unset( $data[ $field ]['raw'] );
			}
		}
		$response->set_data( $data );

		return $response;
	}
}
