<?php
/**
 * Human check: a signed cookie that only a real browser with a person behind it gets without effort.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * A small script waits for the first real interaction (scroll, tap, key, mouse movement), asks the server
 * for a challenge, solves a light proof of work and receives a signed cookie, tied to the IP (IPv6: its /64)
 * and the browser. Visitors without the cookie get the stricter "unverified" page limit.
 *
 * No nonce is involved, so it works with page caches (WP Rocket etc.). It is not a captcha: nobody is asked
 * anything. A determined scraper can copy the steps, but every IP has to do the work, and plain scripts
 * (curl, python) never do it.
 */
final class PNCP_Human {

	const COOKIE = 'pncp_hv';

	/**
	 * Seconds a challenge stays valid.
	 */
	const CHALLENGE_TTL = 300;

	/**
	 * Days the cookie stays valid.
	 */
	const COOKIE_DAYS = 7;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_action( 'wp_ajax_nopriv_pncp_hv', array( __CLASS__, 'ajax' ) );
		add_action( 'wp_ajax_pncp_hv', array( __CLASS__, 'ajax' ) );
	}

	/**
	 * Is the human check on?
	 *
	 * @return bool
	 */
	public static function enabled() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && ! empty( $s['human_check'] );
	}

	/**
	 * Loads the script on every public page (in the footer, after the content).
	 */
	public static function enqueue() {
		if ( ! self::enabled() || is_admin() ) {
			return;
		}
		wp_enqueue_script(
			'pncp-human',
			PNCP_URL . 'assets/js/human.js',
			array(),
			PNCP_VERSION,
			array(
				'in_footer' => true,
				'strategy'  => 'defer',
			)
		);
		wp_localize_script(
			'pncp-human',
			'pncpHuman',
			array(
				'url'    => admin_url( 'admin-ajax.php' ),
				'cookie' => self::COOKIE,
			)
		);
	}

	/**
	 * Proof-of-work difficulty: leading zero hex digits of sha256( challenge . answer ). 3 = about 4,000
	 * attempts, a fraction of a second in a browser. Filter `pncp_human_difficulty` (1–5).
	 *
	 * @return int
	 */
	public static function difficulty() {
		return max( 1, min( 5, (int) apply_filters( 'pncp_human_difficulty', 3 ) ) );
	}

	/**
	 * Signature tied to this site, the IP and the browser.
	 *
	 * @param string $data Data.
	 * @param string $ip   IP.
	 * @return string
	 */
	private static function sign( $data, $ip ) {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		return hash_hmac( 'sha256', $data . '|' . PNCP_Ip::limit_key( $ip ) . '|' . md5( $ua ), wp_salt( 'auth' ) . 'pncp-human' );
	}

	/**
	 * A new challenge: "time.random.signature".
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function challenge( $ip ) {
		$data = time() . '.' . wp_generate_password( 16, false );
		return $data . '.' . self::sign( 'c|' . $data, $ip );
	}

	/**
	 * Checks a solved challenge.
	 *
	 * @param string $challenge Challenge.
	 * @param string $answer    Answer.
	 * @param string $ip        IP.
	 * @return bool
	 */
	public static function check_answer( $challenge, $answer, $ip ) {
		$parts = explode( '.', $challenge );
		if ( 3 !== count( $parts ) || ! ctype_digit( $parts[0] ) || ! preg_match( '/^[0-9]{1,12}$/', $answer ) ) {
			return false;
		}
		$age = time() - (int) $parts[0];
		if ( $age < 0 || $age > self::CHALLENGE_TTL ) {
			return false;
		}
		if ( ! hash_equals( self::sign( 'c|' . $parts[0] . '.' . $parts[1], $ip ), $parts[2] ) ) {
			return false;
		}
		return 0 === strpos( hash( 'sha256', $challenge . $answer ), str_repeat( '0', self::difficulty() ) );
	}

	/**
	 * The cookie value: "expiry.signature".
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function cookie_value( $ip ) {
		$expires = time() + self::COOKIE_DAYS * DAY_IN_SECONDS;
		return $expires . '.' . self::sign( 'v|' . $expires, $ip );
	}

	/**
	 * Does the request carry a valid cookie for this IP and browser?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function verified( $ip ) {
		if ( '' === $ip || empty( $_COOKIE[ self::COOKIE ] ) ) {
			return false;
		}
		$parts = explode( '.', sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) || (int) $parts[0] < time() ) {
			return false;
		}
		return hash_equals( self::sign( 'v|' . $parts[0], $ip ), $parts[1] );
	}

	/**
	 * Deletes a cookie that is no longer valid (e.g. the visitor moved from Wi-Fi to mobile data and the IP
	 * changed). The script sees no cookie and checks again at the next interaction, instead of keeping the
	 * stricter limit for up to 7 days.
	 */
	public static function forget_invalid() {
		if ( empty( $_COOKIE[ self::COOKIE ] ) || headers_sent() ) {
			return;
		}
		setcookie(
			self::COOKIE,
			'',
			array(
				'expires'  => time() - YEAR_IN_SECONDS,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'secure'   => is_ssl(),
				'httponly' => false,
				'samesite' => 'Lax',
			)
		);
		unset( $_COOKIE[ self::COOKIE ] );
	}

	/**
	 * admin-ajax: GET = new challenge, POST = answer (sets the cookie). Never cached.
	 */
	public static function ajax() {
		nocache_headers();
		$ip = PNCP_Ip::client_ip();
		if ( ! self::enabled() || '' === $ip ) {
			wp_send_json_error( null, 404 );
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'POST' !== $method ) {
			wp_send_json_success(
				array(
					'c' => self::challenge( $ip ),
					'd' => self::difficulty(),
				)
			);
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Proof of work instead of a nonce, so cached pages work.
		$challenge = isset( $_POST['c'] ) ? sanitize_text_field( wp_unslash( $_POST['c'] ) ) : '';
		$answer    = isset( $_POST['n'] ) ? sanitize_text_field( wp_unslash( $_POST['n'] ) ) : '';
		// phpcs:enable
		if ( ! self::check_answer( $challenge, $answer, $ip ) ) {
			wp_send_json_error( null, 403 );
		}
		setcookie(
			self::COOKIE,
			self::cookie_value( $ip ),
			array(
				'expires'  => time() + self::COOKIE_DAYS * DAY_IN_SECONDS,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'secure'   => is_ssl(),
				'httponly' => false, // The script reads it, so it does not repeat the check on every page.
				'samesite' => 'Lax',
			)
		);
		wp_send_json_success();
	}
}
