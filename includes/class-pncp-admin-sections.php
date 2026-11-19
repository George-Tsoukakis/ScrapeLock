<?php
/**
 * 3.10: the folded parts (<details>) of the settings page stay open after a Save. Every form of the page
 * (the tab's settings form through options.php, and the action forms through admin-post.php: Blocking at the
 * CDN, the Bunny card, the hardening cards…) posts which parts are open and where its clicked button is
 * (assets/js/admin-sections.js); the redirect back to the settings page carries both as query arguments, the
 * parts open again and the page scrolls back to the button. The browser also keeps the last state for a
 * minute or two (localStorage), for a handler that returns to an address of its own.
 *
 * Display state only: nothing is stored on the server and no setting changes.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Open folded parts across a Save.
 */
final class PNCP_Admin_Sections {

	/**
	 * Form field and query argument: the keys of the open parts, comma separated.
	 */
	const FIELD = 'pncp_sections';

	/**
	 * Form field and query argument: the element to scroll to (the clicked button or its part).
	 */
	const FOCUS = 'pncp_focus';

	/**
	 * At most this many open parts are carried.
	 */
	const MAX = 60;

	/**
	 * Registers the hooks (admin only).
	 */
	public static function init() {
		add_filter( 'wp_redirect', array( __CLASS__, 'carry' ), 20 );
		add_filter( 'removable_query_args', array( __CLASS__, 'removable' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
	}

	/**
	 * The keys of open parts from a posted or query value: element ids or the keys the script makes for
	 * parts without an id (letters, digits, "_", "-" and ".").
	 *
	 * @param mixed $raw Comma-separated keys.
	 * @return string[]
	 */
	public static function keys( $raw ) {
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array();
		}
		$keys = array();
		foreach ( explode( ',', $raw ) as $key ) {
			$key = self::key( $key );
			if ( '' !== $key && ! in_array( $key, $keys, true ) ) {
				$keys[] = $key;
			}
			if ( count( $keys ) >= self::MAX ) {
				break;
			}
		}
		return $keys;
	}

	/**
	 * One key, or '' when it is not a valid key.
	 *
	 * @param mixed $raw Key.
	 * @return string
	 */
	public static function key( $raw ) {
		$key = is_string( $raw ) ? trim( $raw ) : '';
		return '' !== $key && strlen( $key ) <= 100 && preg_match( '/^[A-Za-z0-9_.-]+$/', $key ) ? $key : '';
	}

	/**
	 * Whether an address is the ScrapeLock settings page (options-general.php?page=scrapelock).
	 *
	 * @param string $url Address (absolute or relative).
	 * @return bool
	 */
	public static function is_settings_url( $url ) {
		$path = (string) wp_parse_url( (string) $url, PHP_URL_PATH );
		if ( 'options-general.php' !== wp_basename( $path ) ) {
			return false;
		}
		$query = array();
		wp_parse_str( (string) wp_parse_url( (string) $url, PHP_URL_QUERY ), $query );
		return isset( $query['page'] ) && PNCP_Status::SETTINGS_PAGE === $query['page'];
	}

	/**
	 * An address with the open parts and the element to scroll to (replacing any earlier ones).
	 *
	 * @param string   $url   Address.
	 * @param string[] $keys  Open parts.
	 * @param string   $focus Element to scroll to.
	 * @return string
	 */
	public static function with_state( $url, $keys, $focus ) {
		$url  = remove_query_arg( array( self::FIELD, self::FOCUS ), (string) $url );
		$args = array();
		if ( $keys ) {
			$args[ self::FIELD ] = implode( ',', $keys );
		}
		if ( '' !== $focus ) {
			$args[ self::FOCUS ] = $focus;
		}
		return $args ? add_query_arg( $args, $url ) : $url;
	}

	/**
	 * wp_redirect: after a form of the settings page, the way back to the settings page carries the open parts
	 * and the clicked button. Any other redirect is left as it is.
	 *
	 * @param string $location Redirect address.
	 * @return string
	 */
	public static function carry( $location ) {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Display state only: the handler of the form checks its own nonce.
		if ( ! isset( $_POST[ self::FIELD ] ) || ! is_string( $location ) || ! self::is_settings_url( $location ) ) {
			return $location;
		}
		if ( ! PNCP_Lockdown::can( 'manage_options' ) ) {
			return $location;
		}
		$keys  = self::keys( is_string( $_POST[ self::FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::FIELD ] ) ) : '' );
		$focus = isset( $_POST[ self::FOCUS ] ) && is_string( $_POST[ self::FOCUS ] ) ? self::key( sanitize_text_field( wp_unslash( $_POST[ self::FOCUS ] ) ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		return self::with_state( $location, $keys, $focus );
	}

	/**
	 * The arguments are removed from the address bar once the page has loaded (like "settings-updated").
	 *
	 * @param string[] $args Removable arguments.
	 * @return string[]
	 */
	public static function removable( $args ) {
		$args   = (array) $args;
		$args[] = self::FIELD;
		$args[] = self::FOCUS;
		return $args;
	}

	/**
	 * The open parts asked for by this page load.
	 *
	 * @return string[]
	 */
	public static function requested_keys() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only decides which parts are shown open.
		return isset( $_GET[ self::FIELD ] ) && is_string( $_GET[ self::FIELD ] ) ? self::keys( sanitize_text_field( wp_unslash( $_GET[ self::FIELD ] ) ) ) : array();
	}

	/**
	 * Whether this page load asks for a part to be open (after a Save with that part open).
	 *
	 * @param string $id Element id of the <details>.
	 * @return bool
	 */
	public static function requested( $id ) {
		return in_array( (string) $id, self::requested_keys(), true );
	}

	/**
	 * The script, with the state of this page load, on the settings page only.
	 *
	 * @param string $hook Page hook.
	 */
	public static function assets( $hook ) {
		if ( 'settings_page_' . PNCP_Status::SETTINGS_PAGE !== $hook || ! wp_script_is( 'pncp-admin', 'enqueued' ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Display state only.
		$returned = isset( $_GET[ self::FIELD ] ) || isset( $_GET[ self::FOCUS ] );
		$focus    = isset( $_GET[ self::FOCUS ] ) && is_string( $_GET[ self::FOCUS ] ) ? self::key( sanitize_text_field( wp_unslash( $_GET[ self::FOCUS ] ) ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		wp_enqueue_script( 'pncp-admin-sections', PNCP_URL . 'assets/js/admin-sections.js', array( 'pncp-admin' ), PNCP_VERSION, true );
		wp_localize_script(
			'pncp-admin-sections',
			'pncpSections',
			array(
				'field'    => self::FIELD,
				'focusArg' => self::FOCUS,
				'returned' => $returned ? 1 : 0,
				'open'     => self::requested_keys(),
				'focus'    => $focus,
				// Per user and site: two administrators sharing a browser profile do not get each other's state.
				'store'    => 'pncp_sections_' . get_current_blog_id() . '_' . get_current_user_id(),
			)
		);
	}
}
