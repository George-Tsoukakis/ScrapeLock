<?php
/**
 * REST API: hides post text from visitors, without shutting down REST.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Empties `content` and `excerpt` in public post types for users who cannot edit content.
 * Other endpoints (forms, oEmbed, SEO plugins, your own namespaces) are not affected.
 */
final class PNCP_Rest {

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_filters' ), 99 );
	}

	/**
	 * The post types that are filtered: public, with REST, except attachments.
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
		 * Filter to add or remove post types.
		 *
		 * @param string[] $types Post types.
		 */
		return (array) apply_filters( 'pncp_rest_post_types', array_values( $types ) );
	}

	/**
	 * Adds one filter per post type.
	 */
	public static function register_filters() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['rest_hide_content'] ) ) {
			return;
		}
		foreach ( self::post_types() as $type ) {
			add_filter( 'rest_prepare_' . $type, array( __CLASS__, 'strip' ), 99, 3 );
		}
		// WooCommerce's public Store API serves product descriptions without login, in /products, in the cart
		// line items and in /batch. The long description is stripped for visitors; the rest is left.
		add_filter( 'rest_post_dispatch', array( __CLASS__, 'strip_store_api' ), 99, 3 );
	}

	/**
	 * Empties the long product description in the WooCommerce Store API for visitors: in the product routes, the
	 * cart line items (so the catalogue text cannot be read through "add to cart, then read the cart") and the
	 * batch route. The short description stays: the shop's own blocks (All Products, Product Summary, cart and
	 * checkout) show it, and it is already public on the shop pages. Only product objects are touched (they
	 * carry "prices"), never category or attribute terms.
	 *
	 * @param WP_HTTP_Response $result  The response.
	 * @param WP_REST_Server   $server  The server.
	 * @param WP_REST_Request  $request The request.
	 * @return WP_HTTP_Response
	 */
	public static function strip_store_api( $result, $server, $request ) {
		$route = (string) $request->get_route();
		if ( ! $result instanceof WP_HTTP_Response || ! preg_match( '#^/wc/store(/v\d+)?/(products|cart|batch)#', $route, $m ) ) {
			return $result;
		}
		if ( PNCP_Lockdown::can( 'edit_posts' ) || PNCP_Options::user_is_exempt( PNCP_Options::get() ) ) {
			return $result;
		}
		if ( ! apply_filters( 'pncp_rest_hide_content', true, null ) ) {
			return $result;
		}
		$data = $result->get_data();
		if ( ! is_array( $data ) ) {
			return $result;
		}
		if ( 'batch' === $m[2] ) {
			// { responses: [ { body: … }, … ] }: each answer as if it had been asked for on its own.
			if ( isset( $data['responses'] ) && is_array( $data['responses'] ) ) {
				foreach ( $data['responses'] as $i => $response ) {
					if ( is_array( $response ) && isset( $response['body'] ) && is_array( $response['body'] ) ) {
						$data['responses'][ $i ]['body'] = self::strip_store_data( $response['body'] );
					}
				}
			}
		} else {
			$data = self::strip_store_data( $data );
		}
		$result->set_data( $data );
		return $result;
	}

	/**
	 * Store API data with the long description of every product in it emptied: a product, a list of products,
	 * a cart (its line items) or a list of line items.
	 *
	 * @param array<int|string, mixed> $data Data.
	 * @return array<int|string, mixed>
	 */
	private static function strip_store_data( $data ) {
		$strip = static function ( $item ) {
			if ( is_array( $item ) && isset( $item['prices'] ) && isset( $item['description'] ) && is_string( $item['description'] ) ) {
				$item['description'] = '';
			}
			return $item;
		};
		if ( isset( $data['items'] ) && is_array( $data['items'] ) ) {
			// A cart: its line items, and the cross-sell products it suggests.
			$data['items'] = array_map( $strip, $data['items'] );
			if ( isset( $data['cross_sells'] ) && is_array( $data['cross_sells'] ) ) {
				$data['cross_sells'] = array_map( $strip, $data['cross_sells'] );
			}
			return $data;
		}
		if ( isset( $data['prices'] ) ) {
			return $strip( $data );
		}
		return array_map( $strip, $data );
	}

	/**
	 * Should the text be hidden for the current user?
	 *
	 * @param WP_Post $post The post.
	 * @return bool
	 */
	private static function should_strip( $post ) {
		// Content authors need it (block editor, apps).
		if ( PNCP_Lockdown::can( 'edit_posts' ) || PNCP_Options::user_is_exempt( PNCP_Options::get() ) ) {
			return false;
		}
		if ( in_array( (int) $post->ID, PNCP_Options::excluded_ids( PNCP_Options::get() ), true ) ) {
			return false;
		}

		/**
		 * Filter for exceptions from code (e.g. your own tool that reads posts via REST).
		 *
		 * @param bool         $strip Whether the text will be hidden.
		 * @param WP_Post|null $post  The post (null for the WooCommerce Store API).
		 */
		return (bool) apply_filters( 'pncp_rest_hide_content', true, $post );
	}

	/**
	 * Empties the text in the response.
	 *
	 * @param WP_REST_Response $response The response.
	 * @param WP_Post          $post     The post.
	 * @param WP_REST_Request  $request  The request.
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
