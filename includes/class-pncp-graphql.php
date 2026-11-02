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
	 * Fields of blocks that hold the text: the whole HTML of a block (WPGraphQL Content Blocks: renderedHtml;
	 * WPGraphQL Gutenberg: saveContent, dynamicContent, originalContent, innerHTML, blocksJSON) and the text
	 * attributes of the common blocks (paragraph and heading content, quote value and citation, list values,
	 * captions). Without them, editorBlocks / blocks gave the full article although content was hidden.
	 *
	 * @var string[]
	 */
	private static $block_fields = array( 'renderedHtml', 'saveContent', 'dynamicContent', 'originalContent', 'innerHTML', 'innerHtml', 'blocksJSON', 'content', 'value', 'values', 'citation', 'caption', 'text' );

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
		if ( ! is_string( $result ) || '' === $result ) {
			return $result;
		}
		if ( self::is_block( $source ) ) {
			// A block of a post (its parent post is not known here: the exclusions by ID do not apply).
			return in_array( $field_key, self::$block_fields, true ) && self::hide_for_visitor( 0 ) ? '' : $result;
		}
		if ( 'blocksJSON' === $field_key && is_object( $source ) && self::is_content_model( $source ) ) {
			return self::hide_for_visitor( self::source_id( $source ) ) ? '' : $result;
		}
		if ( ! in_array( $field_key, self::$fields, true ) || ! is_object( $source ) || ! self::is_content_model( $source ) ) {
			return $result;
		}
		return self::hide_for_visitor( self::source_id( $source ) ) ? '' : $result;
	}

	/**
	 * The post ID of a content model (0 when unknown).
	 *
	 * @param object $source Model.
	 * @return int
	 */
	private static function source_id( $source ) {
		return isset( $source->databaseId ) ? (int) $source->databaseId : ( isset( $source->ID ) ? (int) $source->ID : 0 ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- WPGraphQL field.
	}

	/**
	 * Is the source a block (a parsed block array, as WPGraphQL Content Blocks passes it, or a block object of
	 * WPGraphQL Gutenberg)?
	 *
	 * @param mixed $source Source.
	 * @return bool
	 */
	private static function is_block( $source ) {
		if ( is_array( $source ) ) {
			return array_key_exists( 'blockName', $source );
		}
		return is_object( $source ) && false !== strpos( get_class( $source ), 'Block' ) && ! $source instanceof WP_Post;
	}

	/**
	 * Should the text be hidden from the current visitor?
	 *
	 * @param int $id Post ID (0 = unknown).
	 * @return bool
	 */
	private static function hide_for_visitor( $id ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['graphql_hide_content'] ) ) {
			return false;
		}
		if ( PNCP_Lockdown::can( 'edit_posts' ) || PNCP_Options::user_is_exempt( $s ) ) {
			return false;
		}
		if ( $id && in_array( $id, PNCP_Options::excluded_ids( $s ), true ) ) {
			return false;
		}
		/** This filter is documented in includes/class-pncp-rest.php */
		return (bool) apply_filters( 'pncp_rest_hide_content', true, $id ? get_post( $id ) : null );
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
