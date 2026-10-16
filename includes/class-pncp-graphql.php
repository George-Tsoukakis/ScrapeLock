<?php
/**
 * WPGraphQL (/graphql): ίδια προστασία με το REST API, αν το plugin WPGraphQL είναι εγκατεστημένο.
 *
 * - Κρύβει από επισκέπτες το κείμενο (content, excerpt) των άρθρων/σελίδων και την περιγραφή των
 *   προϊόντων (WooGraphQL: description, shortDescription).
 * - Εφαρμόζει τον έλεγχο bots, τους αποκλεισμούς και το όριο REST / GraphQL.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Ενσωμάτωση με το WPGraphQL.
 */
final class PNCP_Graphql {

	/**
	 * Πεδία που αδειάζουν.
	 *
	 * @var string[]
	 */
	private static $fields = array( 'content', 'excerpt', 'description', 'shortDescription' );

	/**
	 * Δένει τα hooks (δεν κάνουν τίποτα αν δεν υπάρχει το WPGraphQL).
	 */
	public static function init() {
		add_action( 'do_graphql_request', array( __CLASS__, 'guard' ), 0 );
		add_filter( 'graphql_resolve_field', array( __CLASS__, 'resolve_field' ), 99, 9 );
	}

	/**
	 * Είναι ενεργό το WPGraphQL;
	 *
	 * @return bool
	 */
	public static function active() {
		return class_exists( 'WPGraphQL' ) || defined( 'WPGRAPHQL_VERSION' );
	}

	/**
	 * Έλεγχος bots / ορίου στην αρχή κάθε αιτήματος GraphQL.
	 */
	public static function guard() {
		$verdict = PNCP_Bots::check( 'graphql' );
		if ( ! $verdict ) {
			return;
		}
		PNCP_Bots::no_cache();
		status_header( $verdict['code'] );
		if ( 429 === $verdict['code'] ) {
			header( 'Retry-After: 60' );
		}
		header( 'Content-Type: application/json; charset=utf-8' );
		echo wp_json_encode(
			array(
				'errors' => array(
					array(
						'message' => 429 === $verdict['code'] ? __( 'Πάρα πολλά αιτήματα. Δοκιμάστε ξανά σε ένα λεπτό.', 'content-protect' ) : __( 'Η πρόσβαση δεν επιτρέπεται.', 'content-protect' ),
					),
				),
			)
		);
		exit;
	}

	/**
	 * Αδειάζει το κείμενο για επισκέπτες.
	 *
	 * @param mixed  $result         Η τιμή του πεδίου.
	 * @param mixed  $source         Το αντικείμενο (Model\Post, Model\Product…).
	 * @param mixed  $args           Ορίσματα.
	 * @param mixed  $context        Context.
	 * @param mixed  $info           ResolveInfo.
	 * @param string $type_name      Τύπος.
	 * @param string $field_key      Πεδίο.
	 * @param mixed  $field          Ορισμός πεδίου.
	 * @param mixed  $field_resolver Resolver.
	 * @return mixed
	 */
	public static function resolve_field( $result, $source, $args, $context, $info, $type_name, $field_key, $field = null, $field_resolver = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter -- Υπογραφή του φίλτρου.
		if ( ! in_array( $field_key, self::$fields, true ) || ! is_string( $result ) || '' === $result ) {
			return $result;
		}
		if ( ! is_object( $source ) || ! self::is_content_model( $source ) ) {
			return $result;
		}
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['graphql_hide_content'] ) ) {
			return $result;
		}
		if ( current_user_can( 'edit_posts' ) || PNCP_Options::user_is_exempt( $s ) ) {
			return $result;
		}
		$id = isset( $source->databaseId ) ? (int) $source->databaseId : ( isset( $source->ID ) ? (int) $source->ID : 0 ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Πεδίο του WPGraphQL.
		if ( $id && in_array( $id, PNCP_Options::excluded_ids( $s ), true ) ) {
			return $result;
		}
		/** This filter is documented in includes/class-pncp-rest.php */
		if ( ! apply_filters( 'pncp_rest_hide_content', true, $id ? get_post( $id ) : null ) ) {
			return $result;
		}
		return '';
	}

	/**
	 * Είναι άρθρο / σελίδα / προϊόν; (όχι όροι, χρήστες, μενού)
	 *
	 * @param object $source Αντικείμενο.
	 * @return bool
	 */
	private static function is_content_model( $source ) {
		$class = get_class( $source );
		return false !== strpos( $class, 'Model\\Post' ) || false !== strpos( $class, 'Model\\Product' ) || $source instanceof WP_Post;
	}
}
