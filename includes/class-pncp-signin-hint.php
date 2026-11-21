<?php
/**
 * 3.12.5: a small cookie that tells the page's own script that this browser is signed in, for "Applies to: only
 * visitors who are not signed in" of the screenshot blur.
 *
 * The blur is decided in the browser, never in the PHP of the page: a page cache (WP Rocket, a CDN such as Bunny)
 * serves the same HTML to everyone, so a page made for a guest may well reach a signed-in member. WordPress's own
 * logged_in cookie is HttpOnly (JavaScript cannot read it), so ScrapeLock sets a second one, readable by the
 * page: "pncp_si=1". It holds no personal data and no secret (no user ID, no token), only that some account is
 * signed in in this browser. Forging it turns the blur off in the forger's own browser only, which the blur, a
 * client-side deterrent, could never prevent anyway.
 *
 * Set when WordPress sets the logged_in cookie (same paths, domain, Secure flag and expiry), removed when it
 * clears the auth cookies (sign-out), and set on an ordinary request of a signed-in browser that lacks it (accounts
 * signed in before 3.12.5, or after the browser dropped a session cookie). A browser that is no longer signed in
 * but still sends it gets it removed on its next request that reaches WordPress. Set whatever the blur settings,
 * so changing them takes effect at once; never while ScrapeLock's protection is off.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The signed-in hint cookie.
 */
final class PNCP_Signin_Hint {

	/**
	 * The cookie's name, also read by assets/js/protect.js.
	 */
	const COOKIE = 'pncp_si';

	/**
	 * Hooks.
	 */
	public static function init() {
		add_action( 'set_logged_in_cookie', array( __CLASS__, 'on_login' ), 10, 4 );
		add_action( 'clear_auth_cookie', array( __CLASS__, 'on_logout' ) );
		// After WordPress has read the auth cookie (the current user is known on init).
		add_action( 'init', array( __CLASS__, 'refresh' ), 20 );
	}

	/**
	 * Whether ScrapeLock may set the cookie at all: only while its protection is on.
	 *
	 * @return bool
	 */
	public static function active() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] );
	}

	/**
	 * WordPress sets the logged_in cookie (sign-in, "Remember me", a refreshed session): the hint goes with it, with
	 * the same expiry (0 = until the browser is closed, as the logged_in cookie without "Remember me").
	 *
	 * @param string $cookie     The logged_in cookie (not used: nothing of it goes into the hint).
	 * @param int    $expire     When the browser drops the cookie (0 for a session cookie).
	 * @param int    $expiration When the sign-in expires (not used).
	 * @param int    $user_id    User ID (not used: the hint names no one).
	 */
	public static function on_login( $cookie, $expire, $expiration, $user_id ) {
		unset( $cookie, $expiration, $user_id );
		if ( self::active() ) {
			self::send( '1', (int) $expire );
		}
	}

	/**
	 * WordPress clears the auth cookies (sign-out, a session that ended): the hint goes too. Also while the
	 * protection is off, so a sign-out never leaves a hint behind.
	 */
	public static function on_logout() {
		if ( isset( $_COOKIE[ self::COOKIE ] ) || self::active() ) {
			self::send( '', time() - YEAR_IN_SECONDS );
		}
	}

	/**
	 * An ordinary request that reaches WordPress: a signed-in browser without the hint gets it (accounts signed in
	 * before 3.12.5; the expiry of their logged_in cookie is not known here, so it lasts until the browser is
	 * closed and comes back with the next such request), a browser that is no longer signed in loses it.
	 */
	public static function refresh() {
		if ( 'cli' === PHP_SAPI || headers_sent() || ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) || ! self::active() ) {
			return;
		}
		$has = isset( $_COOKIE[ self::COOKIE ] );
		if ( is_user_logged_in() ) {
			if ( ! $has ) {
				self::send( '1', 0 );
			}
		} elseif ( $has ) {
			self::send( '', time() - YEAR_IN_SECONDS );
		}
	}

	/**
	 * The cookie options as WordPress sets the logged_in cookie: the site's cookie domain, Secure on an https site
	 * reached over https, SameSite=Lax, and readable by JavaScript (not HttpOnly: that is the point of it).
	 *
	 * @param int $expire Expiry (0 = session cookie).
	 * @return array{expires: int, path: string, domain: string, secure: bool, httponly: bool, samesite: string}
	 */
	public static function options( $expire ) {
		return array(
			'expires'  => (int) $expire,
			'path'     => COOKIEPATH,
			'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? (string) COOKIE_DOMAIN : '',
			'secure'   => is_ssl() && 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME ),
			'httponly' => false,
			'samesite' => 'Lax',
		);
	}

	/**
	 * Sends the cookie on the paths WordPress uses for logged_in (COOKIEPATH, and SITECOOKIEPATH when WordPress
	 * lives in a subfolder of the site address).
	 *
	 * @param string $value  '1', or '' to remove it.
	 * @param int    $expire Expiry (0 = session cookie, in the past = remove).
	 */
	private static function send( $value, $expire ) {
		if ( headers_sent() ) {
			return;
		}
		$options = self::options( $expire );
		$paths   = array_unique( array( COOKIEPATH, SITECOOKIEPATH ) );
		foreach ( $paths as $path ) {
			$options['path'] = $path;
			setcookie( self::COOKIE, $value, $options );
		}
		if ( '' === $value ) {
			unset( $_COOKIE[ self::COOKIE ] );
		} else {
			$_COOKIE[ self::COOKIE ] = $value;
		}
	}
}
