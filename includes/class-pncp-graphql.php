<?php
/**
 * WPGraphQL (/graphql): same protection as the REST API, if the WPGraphQL plugin is installed.
 *
 * - Hides from visitors the text (content, excerpt) of posts/pages and the description of
 *   products (WooGraphQL: description, shortDescription).
 * - Applies the bot check, the blocks and the REST / GraphQL limit.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Integration with WPGraphQL.
 */
final class PNCP_Graphql {

	/**
	 * Fields that are emptied.
	 *
	 * @var string[]
	 */
	private static $fields = array( 'content', 'excerpt', 'description', 'shortDescription' );

	/**
	 * Registers the hooks (they do nothing if WPGraphQL is not present).
	 */
	public static function init() {
		add_action( 'do_graphql_request', array( __CLASS__, 'guard' ), 0 );
		add_filter( 'graphql_resolve_field', array( __CLASS__, 'resolve_field' ), 99, 9 );
	}

	/**
	 * Is WPGraphQL active?
	 *
	 * @return bool
	 */
	public static function active() {
		return class_exists( 'WPGraphQL' ) || defined( 'WPGRAPHQL_VERSION' );
	}

	/**
	 * Bot / limit check at the start of every GraphQL request.
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
						'message' => 429 === $verdict['code'] ? __( 'Too many requests. Please try again in a minute.', 'scrapelock' ) : __( 'Access denied.', 'scrapelock' ),
					),
				),
			)
		);
		exit;
	}

	/**
	 * Empties the text for visitors.
	 *
	 * @param mixed  $result         The field value.
	 * @param mixed  $source         The object (Model\Post, Model\Product…).
	 * @param mixed  $args           Arguments.
	 * @param mixed  $context        Context.
	 * @param mixed  $info           ResolveInfo.
	 * @param string $type_name      Type.
	 * @param string $field_key      Field.
	 * @param mixed  $field          Field definition.
	 * @param mixed  $field_resolver Resolver.
	 * @return mixed
	 */
	public static function resolve_field( $result, $source, $args, $context, $info, $type_name, $field_key, $field = null, $field_resolver = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter -- Filter signature.
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
		if ( PNCP_Lockdown::can( 'edit_posts' ) || PNCP_Options::user_is_exempt( $s ) ) {
			return $result;
		}
		$id = isset( $source->databaseId ) ? (int) $source->databaseId : ( isset( $source->ID ) ? (int) $source->ID : 0 ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- WPGraphQL field.
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
	 * Is it a post / page / product? (not terms, users, menus)
	 *
	 * @param object $source Object.
	 * @return bool
	 */
	private static function is_content_model( $source ) {
		$class = get_class( $source );
		return false !== strpos( $class, 'Model\\Post' ) || false !== strpos( $class, 'Model\\Product' ) || $source instanceof WP_Post;
	}
}
