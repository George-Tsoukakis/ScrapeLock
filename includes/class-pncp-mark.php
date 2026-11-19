<?php
/**
 * 3.6: the reader's mark. A faint line repeated over protected pages with who is reading and when, so a
 * screenshot, a screen recording or a photo of the screen shows where it came from. Nothing on a web page can
 * stop those; this makes them traceable.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The reader's mark.
 */
final class PNCP_Mark {

	/**
	 * The admin-ajax action that gives a visitor who is not signed in their line (IP and time).
	 */
	const ACTION = 'pncp_mark';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'register' ), 1 );
		add_action( 'wp_head', array( __CLASS__, 'print_script' ), 3 );
		add_action( 'template_redirect', array( __CLASS__, 'private_page' ), 2 );
		add_action( 'wp_ajax_nopriv_' . self::ACTION, array( __CLASS__, 'ajax' ) );
		add_action( 'wp_ajax_' . self::ACTION, array( __CLASS__, 'ajax' ) );
	}

	/**
	 * Is the mark shown on this page, and to whom: 'user' (a signed-in account that the protection applies to),
	 * 'guest' (a visitor who is not signed in, with "Also for visitors" on), or '' (none). Only on the pages
	 * the protection covers (PNCP_Frontend::should_protect()), so never to exempt staff.
	 *
	 * @return string
	 */
	public static function mode() {
		$s = PNCP_Options::get();
		if ( empty( $s['user_mark'] ) || ! PNCP_Frontend::should_protect() ) {
			return '';
		}
		if ( is_user_logged_in() ) {
			return 'user';
		}
		return ! empty( $s['user_mark_guests'] ) ? 'guest' : '';
	}

	/**
	 * The line of a signed-in user: the user name and the date and time in the site's time zone.
	 *
	 * @param WP_User $user User.
	 * @return string
	 */
	public static function user_line( $user ) {
		$line = $user->user_login . ' · ' . wp_date( 'Y-m-d H:i' );
		/**
		 * Filters the line shown over the page to a signed-in user.
		 *
		 * @param string  $line Line.
		 * @param WP_User $user User.
		 */
		return wp_strip_all_tags( (string) apply_filters( 'pncp_mark_user_line', $line, $user ) );
	}

	/**
	 * The line of a visitor who is not signed in: the IP and the date and time.
	 *
	 * @return string
	 */
	public static function guest_line() {
		$line = PNCP_Ip::client_ip() . ' · ' . wp_date( 'Y-m-d H:i' );
		/**
		 * Filters the line shown over the page to a visitor who is not signed in.
		 *
		 * @param string $line Line.
		 */
		return wp_strip_all_tags( (string) apply_filters( 'pncp_mark_guest_line', $line ) );
	}

	/**
	 * Registers the script with its settings. A signed-in user's line is in the page (such pages are not shared
	 * through a page cache, and private_page() asks every cache not to keep them); a visitor's line is asked for
	 * with admin-ajax, so a cached page never carries one visitor's IP to another.
	 */
	public static function register() {
		$mode = self::mode();
		if ( '' === $mode ) {
			return;
		}
		$s      = PNCP_Options::get();
		$config = array(
			'opacity'        => max( 2, min( 60, (int) $s['user_mark_opacity'] ) ) / 100,
			/**
			 * Filters the mark's opacity (percent, 2 to 60) while the page is blurred for a screenshot attempt:
			 * over the blurred page the line is the only readable thing, so it is drawn stronger.
			 *
			 * @param int $percent Opacity in percent.
			 */
			'blurredOpacity' => max( 2, min( 60, (int) apply_filters( 'pncp_mark_blurred_opacity', 35 ) ) ) / 100,
		);
		if ( 'user' === $mode ) {
			$config['text'] = self::user_line( wp_get_current_user() );
		} else {
			$config['url'] = add_query_arg( 'action', self::ACTION, admin_url( 'admin-ajax.php' ) );
		}
		wp_register_script( 'pncp-mark', false, array(), PNCP_VERSION, false );
		$js = (string) file_get_contents( PNCP_DIR . 'assets/js/mark.js' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- The plugin's own file.
		wp_add_inline_script( 'pncp-mark', 'window.pncpMark = ' . wp_json_encode( $config ) . ';', 'before' );
		wp_add_inline_script( 'pncp-mark', $js, 'after' );
	}

	/**
	 * Prints the script in <head>, right after the protection script.
	 */
	public static function print_script() {
		if ( wp_script_is( 'pncp-mark', 'registered' ) && ! wp_script_is( 'pncp-mark', 'done' ) ) {
			wp_print_scripts( array( 'pncp-mark' ) );
		}
	}

	/**
	 * A page with a signed-in user's name in it must not be kept by a browser, proxy or CDN cache.
	 */
	public static function private_page() {
		if ( 'user' === self::mode() && ! headers_sent() ) {
			header( 'Cache-Control: private, no-store, max-age=0' );
		}
	}

	/**
	 * The line of a visitor who is not signed in (admin-ajax, GET). Never cached. Only while the option is on.
	 */
	public static function ajax() {
		nocache_headers();
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['user_mark'] ) ) {
			wp_send_json_error( null, 404 );
		}
		if ( is_user_logged_in() ) {
			wp_send_json_success( array( 'text' => self::user_line( wp_get_current_user() ) ) );
		}
		if ( empty( $s['user_mark_guests'] ) ) {
			wp_send_json_error( null, 404 );
		}
		wp_send_json_success( array( 'text' => self::guest_line() ) );
	}
}
