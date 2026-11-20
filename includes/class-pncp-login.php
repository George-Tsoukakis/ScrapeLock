<?php
/**
 * 3.8: the sign-in (wp-login.php, wp-admin, XML-RPC and application passwords).
 *
 * - Failed sign-ins are counted per IP (IPv6: per /64): past "login_max" within "login_window" minutes the IP is
 *   blocked for "login_ban_minutes" (PNCP_Log::ban(), reason "login"). Counted on wp-login.php (and wherever a
 *   form calls wp_signon()), on XML-RPC (each call of a system.multicall: WordPress stops checking passwords after
 *   the first wrong one of a request, so the others are counted from the "xmlrpc_login_error" filter) and on the
 *   REST API with application passwords.
 * - Failed sign-ins are also counted per username: past "login_user_max" the username is paused for
 *   "login_user_minutes". The real person is never locked out: the IPs that already signed in to the account are
 *   not paused (a hash of each is kept in the user's meta), and the account's email gets a one-time link that
 *   lets this browser sign in at once. Usernames that do not exist are paused the same way, so the answer does
 *   not tell which ones exist.
 * - One error message for an unknown username, an unknown email and a wrong password, and "Lost your password"
 *   answers the same whether the account exists or not.
 * - Optional custom sign-in address ("login_slug"): wp-login.php and /wp-admin/ answer "page not found" to
 *   visitors who are not signed in, and every link WordPress makes (wp_login_url(), site_url(), emails,
 *   redirects) points to the new address. define( 'SCRAPELOCK_LOGIN_SLUG_OFF', true ) in wp-config.php turns it
 *   off if the address is forgotten.
 *
 * Nothing here reads or writes the database on a normal page view: the counters are written only when a
 * sign-in fails, and the slug check is a string comparison of the request path.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Sign-in protection.
 */
final class PNCP_Login {

	/**
	 * Usernames paused now (written only when one is paused or unlocked; not autoloaded).
	 */
	const LOCKS_OPTION = 'pncp_login_locks';

	/**
	 * User meta: hashes of the IP keys this user signed in from, with the time.
	 */
	const KNOWN_META = 'pncp_login_known';

	/**
	 * User meta: the hash of the emailed unlock link and its expiry.
	 */
	const UNLOCK_META = 'pncp_login_unlock';

	/**
	 * Cookie set by the unlock link: this browser may sign in to that account during a pause.
	 */
	const UNLOCK_COOKIE = 'pncp_login_unlock';

	/**
	 * The admin-post.php action of the status card.
	 */
	const ACTION = 'pncp_login';

	/**
	 * At most this many usernames counted per request (a multicall can carry hundreds).
	 */
	const MAX_USERS_PER_REQUEST = 20;

	/**
	 * At most this many usernames kept in LOCKS_OPTION.
	 */
	const MAX_LOCKS = 200;

	/**
	 * At most this many IPs remembered per user.
	 */
	const MAX_KNOWN = 10;

	/**
	 * The unlock link is valid this long.
	 */
	const UNLOCK_TTL = DAY_IN_SECONDS;

	/**
	 * The cookie of the unlock link is valid this long.
	 */
	const UNLOCK_COOKIE_TTL = 30 * DAY_IN_SECONDS;

	/**
	 * This request is the custom sign-in address.
	 *
	 * @var bool
	 */
	private static $slug_request = false;

	/**
	 * The sign-in that just failed was refused by this class (a pause or a block): not counted again.
	 *
	 * @var bool
	 */
	private static $own_refusal = false;

	/**
	 * Failures of this request, not counted yet: username (as typed) => count.
	 *
	 * @var array<string, int>
	 */
	private static $pending = array();

	/**
	 * The shutdown writer is hooked.
	 *
	 * @var bool
	 */
	private static $hooked = false;

	/**
	 * The usernames of the calls of this XML-RPC request (null = not read yet).
	 *
	 * @var string[]|null
	 */
	private static $xmlrpc_users = null;

	/**
	 * How many XML-RPC sign-in checks of this request failed so far.
	 *
	 * @var int
	 */
	private static $xmlrpc_index = 0;

	/**
	 * Settings of this request.
	 *
	 * @var array<string, mixed>|null
	 */
	private static $settings = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );

		// Counting and pausing.
		add_filter( 'authenticate', array( __CLASS__, 'authenticate' ), 99, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_failed' ), 20, 1 );
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 10, 2 );
		add_filter( 'xmlrpc_login_error', array( __CLASS__, 'on_xmlrpc_login_error' ), 10, 2 );
		add_action( 'init', array( __CLASS__, 'xmlrpc_gate' ), 3 );
		add_filter( 'application_password_is_api_request', array( __CLASS__, 'app_password_gate' ), 99 );
		add_action( 'application_password_failed_authentication', array( __CLASS__, 'on_app_password_failed' ) );
		add_action( 'login_init', array( __CLASS__, 'login_gate' ), 1 );
		add_filter( 'login_message', array( __CLASS__, 'login_message' ) );
		add_action( 'lostpassword_post', array( __CLASS__, 'lostpassword_post' ), 99, 2 );
		add_filter( 'shake_error_codes', array( __CLASS__, 'shake_codes' ) );

		if ( '' === self::slug() ) {
			if ( defined( 'SCRAPELOCK_LOGIN_SLUG_OFF' ) && SCRAPELOCK_LOGIN_SLUG_OFF ) {
				add_action( 'init', array( __CLASS__, 'slug_off_recovery' ), 20 );
			}
			return;
		}
		// The custom sign-in address. Its request is recognised once the plugins are loaded (the permalink
		// setting is known) and served after WordPress has loaded (wp_loaded), before the main query.
		add_action( 'plugins_loaded', array( __CLASS__, 'detect' ), 9999 );
		add_action( 'init', array( __CLASS__, 'hide_gate' ), 0 );
		add_action( 'wp_loaded', array( __CLASS__, 'serve' ), 99 );
		add_filter( 'site_url', array( __CLASS__, 'filter_url' ), 99, 3 );
		add_filter( 'network_site_url', array( __CLASS__, 'filter_url' ), 99, 3 );
		add_filter( 'wp_redirect', array( __CLASS__, 'filter_redirect' ), 99, 1 );
		add_filter( 'login_url', array( __CLASS__, 'filter_redirect' ), 99, 1 );
		add_filter( 'lostpassword_url', array( __CLASS__, 'filter_redirect' ), 99, 1 );
		add_filter( 'register_url', array( __CLASS__, 'filter_redirect' ), 99, 1 );
		add_filter( 'logout_url', array( __CLASS__, 'filter_redirect' ), 99, 1 );
		// /login, /admin and /dashboard lead to the sign-in page: not for visitors while it is moved.
		add_action( 'template_redirect', array( __CLASS__, 'no_admin_shortcuts' ), 0 );
	}

	/* ---------- Settings ---------- */

	/**
	 * The default values of the settings of this class.
	 *
	 * @return array<string, int|string>
	 */
	public static function defaults() {
		return array(
			'login_limit'          => 1,
			'login_max'            => 5,
			'login_window'         => 15,
			'login_ban_minutes'    => 30,
			'login_user_max'       => 10,
			'login_user_minutes'   => 15,
			'login_user_email'     => 1,
			'login_generic_errors' => 1,
			'login_slug'           => '',
		);
	}

	/**
	 * The ranges of the number settings.
	 *
	 * @return array<string, array{0:int, 1:int}>
	 */
	public static function int_ranges() {
		return array(
			'login_max'          => array( 2, 100 ),
			'login_window'       => array( 1, 1440 ),
			'login_ban_minutes'  => array( 1, 10080 ),
			'login_user_max'     => array( 0, 1000 ),
			'login_user_minutes' => array( 1, 1440 ),
		);
	}

	/**
	 * The settings in effect, with the defaults for those not stored yet.
	 *
	 * @return array<string, mixed>
	 */
	public static function settings() {
		if ( null === self::$settings ) {
			$s   = PNCP_Options::get();
			$out = array();
			foreach ( self::defaults() as $key => $default ) {
				$out[ $key ] = isset( $s[ $key ] ) && is_scalar( $s[ $key ] ) ? $s[ $key ] : $default;
			}
			foreach ( self::int_ranges() as $key => $range ) {
				$out[ $key ] = max( $range[0], min( $range[1], (int) $out[ $key ] ) );
			}
			$out['enabled'] = ! empty( $s['enabled'] );
			self::$settings = $out;
		}
		return self::$settings;
	}

	/**
	 * Forgets the settings of this request (after a change, and in tests).
	 */
	public static function flush() {
		self::$settings = null;
	}

	/**
	 * Is the limit of failed sign-ins on?
	 *
	 * @return bool
	 */
	public static function is_protected() {
		$s = self::settings();
		return $s['enabled'] && ! empty( $s['login_limit'] );
	}

	/**
	 * The custom sign-in address without slashes, e.g. "my-login" ('' = not moved, or turned off).
	 *
	 * @return string
	 */
	public static function slug() {
		if ( defined( 'SCRAPELOCK_LOGIN_SLUG_OFF' ) && SCRAPELOCK_LOGIN_SLUG_OFF ) {
			return '';
		}
		$s = self::settings();
		if ( ! $s['enabled'] ) {
			return '';
		}
		$slug = self::clean_slug( (string) $s['login_slug'] );
		return self::reserved( $slug ) ? '' : $slug;
	}

	/**
	 * SCRAPELOCK_LOGIN_SLUG_OFF is set while an address is stored: the sign-in page is at wp-login.php again, so
	 * a login rule at Bunny CDN must let the administrators in (at most once every 5 minutes, only in this case).
	 */
	public static function slug_off_recovery() {
		$stored = PNCP_Options::stored();
		if ( empty( $stored['login_slug'] ) || ! class_exists( 'PNCP_Bunny' ) || ! method_exists( 'PNCP_Bunny', 'login_changed' ) || ! PNCP_Bunny::preset_locked( 'login' ) ) {
			return;
		}
		if ( PNCP_Log::cache_add( 'pncp_login_slug_off', time(), 5 * MINUTE_IN_SECONDS ) ) {
			PNCP_Bunny::login_changed();
		}
	}

	/**
	 * Are wp-login.php and /wp-admin/ hidden from visitors (the address is moved and nothing turns it off)?
	 *
	 * @return bool
	 */
	public static function hides_login() {
		return '' !== self::slug() && ! PNCP_Options::monitoring();
	}

	/**
	 * Lower case letters, digits, "-" and "_", without slashes.
	 *
	 * @param string $raw Text.
	 * @return string
	 */
	private static function clean_slug( $raw ) {
		$slug = strtolower( trim( (string) $raw, " \t\n\r\0\x0B/" ) );
		return (string) preg_replace( '/[^a-z0-9_-]/', '', $slug );
	}

	/**
	 * Is the slug unusable (too short or too long, or an address WordPress already uses)?
	 *
	 * @param string $slug Clean slug.
	 * @return bool
	 */
	private static function reserved( $slug ) {
		if ( strlen( $slug ) < 3 || strlen( $slug ) > 50 ) {
			return true;
		}
		$taken = array( 'wp-admin', 'wp-login', 'wp-login-php', 'login', 'admin', 'dashboard', 'wp-json', 'wp-content', 'wp-includes', 'feed', 'xmlrpc', 'wp-cron', 'wp-signup', 'wp-activate', 'wp-register', 'register', 'signup', 'logout', 'comments', 'search', 'page', 'author', 'embed', 'trackback', 'sitemap', 'robots', 'index', 'index-php', 'rest-route' );
		return in_array( $slug, $taken, true );
	}

	/**
	 * Sanitizes the "login_slug" setting (for PNCP_Options::sanitize()): '' when empty or unusable. An address
	 * that a page, a post or a category already has is refused too.
	 *
	 * @param mixed       $raw     Value sent.
	 * @param string|null $reason  Set to why it was refused ('' = it was not).
	 * @param-out string  $reason
	 * @param string      $current The address stored now: sent again unchanged, it is not checked against the content.
	 * @return string
	 */
	public static function sanitize_slug( $raw, &$reason = null, $current = '' ) {
		$reason = '';
		$slug   = self::clean_slug( is_scalar( $raw ) ? (string) $raw : '' );
		if ( '' === $slug ) {
			return '';
		}
		if ( self::reserved( $slug ) ) {
			$reason = __( 'Use 3 to 50 letters, digits, “-” or “_”, and not an address WordPress already uses (login, admin, wp-admin, dashboard…).', 'scrapelock' );
			return '';
		}
		// The address in use is kept as it is: a page or tag made later with the same address must not open
		// wp-login.php again at the next save (slug_taken() then only warns).
		if ( '' !== $current && self::clean_slug( (string) $current ) === $slug ) {
			return $slug;
		}
		if ( self::slug_taken( $slug ) ) {
			$reason = __( 'A page, post or category already has this address: choose another one.', 'scrapelock' );
			return '';
		}
		return $slug;
	}

	/**
	 * A usable slug without looking at the content (format and reserved names only), '' when unusable. For the
	 * address already stored, which is kept when a new one is refused.
	 *
	 * @param mixed $raw Value.
	 * @return string
	 */
	public static function usable_slug( $raw ) {
		$slug = self::clean_slug( is_scalar( $raw ) ? (string) $raw : '' );
		return '' === $slug || self::reserved( $slug ) ? '' : $slug;
	}

	/**
	 * Does a public page or post, or a term of any taxonomy, already have this address?
	 *
	 * @param string $slug Clean slug.
	 * @return bool
	 */
	public static function slug_taken( $slug ) {
		if ( '' === $slug || ! function_exists( 'get_page_by_path' ) ) {
			return false;
		}
		return get_page_by_path( $slug, OBJECT, get_post_types( array( 'public' => true ) ) ) || term_exists( $slug );
	}

	/**
	 * The address of the sign-in page: the custom one, or wp-login.php.
	 *
	 * @param string|null $scheme URL scheme (as site_url(): null, 'login', 'login_post', 'https'…).
	 * @return string
	 */
	public static function login_url( $scheme = null ) {
		$slug = self::slug();
		if ( '' === $slug ) {
			return site_url( 'wp-login.php', null === $scheme ? 'login' : $scheme );
		}
		$home_scheme = null;
		if ( in_array( $scheme, array( 'http', 'https', 'relative' ), true ) ) {
			$home_scheme = $scheme;
		} elseif ( force_ssl_admin() || is_ssl() ) {
			$home_scheme = 'https';
		}
		if ( self::pretty() ) {
			$path = '/' . $slug . ( '/' === substr( (string) get_option( 'permalink_structure' ), -1 ) ? '/' : '' );
			return home_url( $path, $home_scheme );
		}
		return home_url( '/', $home_scheme ) . '?' . $slug;
	}

	/**
	 * Pretty permalinks (the server sends any address to index.php)?
	 *
	 * @return bool
	 */
	private static function pretty() {
		return '' !== (string) get_option( 'permalink_structure' );
	}

	/* ---------- The custom sign-in address ---------- */

	/**
	 * The request path, decoded, lower case, without the query string.
	 *
	 * @return string
	 */
	private static function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared.
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		return strtolower( rawurldecode( '' === $path ? '/' : $path ) );
	}

	/**
	 * The path of the home page without the trailing slash ('' at the root of the domain).
	 *
	 * @return string
	 */
	private static function home_path() {
		return strtolower( untrailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ) );
	}

	/**
	 * Is this request the custom sign-in address?
	 *
	 * @return bool
	 */
	public static function is_slug_request() {
		$slug = self::slug();
		if ( '' === $slug ) {
			return false;
		}
		$path = self::request_path();
		$home = self::home_path();
		if ( untrailingslashit( $path ) === $home . '/' . $slug ) {
			return true;
		}
		// Plain permalinks: /?my-login (also accepted with pretty permalinks, the server may not rewrite).
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only the presence of the key.
		return isset( $_GET[ $slug ] ) && in_array( untrailingslashit( $path ), array( $home, $home . '/index.php' ), true );
	}

	/**
	 * Recognises the custom sign-in address (plugins_loaded): WordPress and the other plugins then see the
	 * request as the sign-in page ($pagenow).
	 */
	public static function detect() {
		global $pagenow;
		if ( ! self::is_slug_request() ) {
			return;
		}
		self::$slug_request = true;
		$pagenow            = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- The request is the sign-in page.
	}

	/**
	 * Serves wp-login.php at the custom address (wp_loaded), then ends the request.
	 */
	public static function serve() {
		if ( ! self::$slug_request ) {
			return;
		}
		// wp-login.php keeps its state in these globals (login_header() reads them).
		global $error, $interim_login, $action, $user_login;
		if ( class_exists( 'PNCP_Bots' ) ) {
			PNCP_Bots::no_cache();
		}
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Hides wp-login.php and /wp-admin/: "page not found" for visitors who are not signed in, while the address is
	 * moved (init, 0). admin-ajax.php and admin-post.php stay open, and so does the password form of protected
	 * posts. In Monitor only they keep working and the request is logged as "would hide".
	 */
	public static function hide_gate() {
		global $pagenow;
		if ( self::$slug_request || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$which = '';
		if ( 'wp-login.php' === $pagenow || 'wp-login.php' === basename( self::request_path() ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only the action name.
			$act = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
			if ( '' !== $act && in_array( $act, self::open_actions(), true ) ) {
				return;
			}
			$which = 'login';
		} elseif ( ! is_multisite() && in_array( basename( self::request_path() ), array( 'wp-signup.php', 'wp-register.php' ), true ) ) {
			// On a single site these only redirect to the registration form, at the new address.
			$which = 'login';
		} elseif ( is_admin() && ! wp_doing_ajax() ) {
			/**
			 * Filters the wp-admin files that stay open to visitors while the sign-in page is moved.
			 *
			 * @param string[] $files File names.
			 */
			$open = (array) apply_filters( 'pncp_login_admin_open', array( 'admin-ajax.php', 'admin-post.php' ) );
			if ( in_array( (string) $pagenow, $open, true ) ) {
				return;
			}
			$which = 'admin';
		}
		// Asked only here, so a normal page view does not work out the current user this early.
		if ( '' === $which || is_user_logged_in() ) {
			return;
		}
		$ip    = PNCP_Ip::client_ip();
		$local = '' === $ip || PNCP_Ip::is_local_request();
		if ( PNCP_Options::monitoring() ) {
			if ( ! $local ) {
				PNCP_Log::add( 'login_hidden', PNCP_Log::MONITOR_CODE, $ip );
			}
			return;
		}
		if ( ! $local ) {
			PNCP_Log::add( 'login_hidden', 404, $ip );
			if ( 'login' === $which && class_exists( 'PNCP_Attacks' ) ) {
				$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
				$file   = basename( self::request_path() );
				$file   = in_array( $file, array( 'wp-signup.php', 'wp-register.php' ), true ) ? $file : 'wp-login.php';
				PNCP_Attacks::record( 'login_probe', '/' . $file, $ip, true, $method . ' (moved)' );
			}
		}
		self::not_found();
	}

	/**
	 * The wp-login.php actions that stay open at the old address while the sign-in page is moved.
	 *
	 * @return string[]
	 */
	public static function open_actions() {
		/**
		 * Filters the wp-login.php actions that stay open at the old address while the sign-in page is moved.
		 *
		 * @param string[] $actions Actions (default: postpass, the password form of protected posts).
		 */
		return array_map( 'strval', (array) apply_filters( 'pncp_login_open_actions', array( 'postpass' ) ) );
	}

	/**
	 * Ends the request with a bare "page not found" that does not say which software runs the site.
	 */
	private static function not_found() {
		if ( ! headers_sent() ) {
			status_header( 404 );
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
			header_remove( 'X-Pingback' );
			header_remove( 'X-Powered-By' );
		}
		echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
		exit;
	}

	/**
	 * Would a link to wp-login.php made now give the new address away? In a request for /wp-admin/ by a visitor
	 * who is not signed in (only in Monitor only does it get this far), WordPress redirects to the sign-in page:
	 * that redirect keeps going to wp-login.php.
	 *
	 * @return bool
	 */
	private static function keep_old_url() {
		global $pagenow;
		return is_admin() && ! wp_doing_ajax() && ! in_array( (string) $pagenow, array( 'admin-ajax.php', 'admin-post.php' ), true )
			&& did_action( 'init' ) && ! is_user_logged_in();
	}

	/**
	 * Filters site_url and network_site_url: a link to wp-login.php goes to the custom address.
	 *
	 * @param string      $url    URL.
	 * @param string      $path   Path asked for.
	 * @param string|null $scheme Scheme.
	 * @return string
	 */
	public static function filter_url( $url, $path = '', $scheme = null ) {
		return self::rewrite( (string) $url, $scheme );
	}

	/**
	 * Filters wp_redirect, login_url, lostpassword_url, register_url and logout_url, as filter_url().
	 *
	 * @param string $url URL.
	 * @return string
	 */
	public static function filter_redirect( $url ) {
		return self::rewrite( (string) $url, null );
	}

	/**
	 * A URL of wp-login.php (absolute, or relative as wp-login.php's own redirects) with the custom address
	 * instead, keeping its query string and fragment.
	 *
	 * @param string      $url    URL.
	 * @param string|null $scheme Scheme.
	 * @return string
	 */
	public static function rewrite( $url, $scheme = null ) {
		if ( false === stripos( $url, 'wp-login.php' ) || '' === self::slug() || self::keep_old_url() ) {
			return $url;
		}
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || ! isset( $parts['path'] ) || 'wp-login.php' !== strtolower( basename( (string) $parts['path'] ) ) ) {
			return $url;
		}
		// The actions that stay open at wp-login.php (the password form of protected posts) keep the old
		// address: their links are in public pages, and the new address must not be shown there.
		if ( isset( $parts['query'] ) ) {
			wp_parse_str( (string) $parts['query'], $query );
			$act = isset( $query['action'] ) && is_string( $query['action'] ) ? sanitize_key( $query['action'] ) : '';
			if ( '' !== $act && in_array( $act, self::open_actions(), true ) ) {
				return $url;
			}
		}
		// Redirects and the registration link made for visitors who are not signed in, outside the new address
		// (e.g. wp-signup.php sending to the registration form), would tell anyone where it is.
		if ( ! self::$slug_request && in_array( current_filter(), array( 'wp_redirect', 'register_url' ), true )
			&& ( ! did_action( 'init' ) || ! is_user_logged_in() ) ) {
			return $url;
		}
		if ( isset( $parts['host'] ) && strtolower( (string) $parts['host'] ) !== strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) ) {
			return $url; // Another site of the network (subdomains) or another host: its own setting applies there.
		}
		if ( null === $scheme && isset( $parts['scheme'] ) ) {
			$scheme = strtolower( (string) $parts['scheme'] );
		}
		$new = self::login_url( $scheme );
		if ( isset( $parts['query'] ) && '' !== $parts['query'] ) {
			$new .= ( false === strpos( $new, '?' ) ? '?' : '&' ) . $parts['query'];
		}
		if ( isset( $parts['fragment'] ) && '' !== $parts['fragment'] ) {
			$new .= '#' . $parts['fragment'];
		}
		return $new;
	}

	/**
	 * /login, /admin and /dashboard: no redirect to the sign-in page for visitors while it is moved.
	 */
	public static function no_admin_shortcuts() {
		if ( ! is_user_logged_in() ) {
			remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
		}
	}

	/* ---------- Counting and pausing ---------- */

	/**
	 * Is the IP one whose sign-ins are not counted (the server itself, an always-allowed IP)?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private static function not_counted( $ip ) {
		if ( '' === $ip || PNCP_Ip::is_local_request() || PNCP_Ip::is_cdn_edge( $ip ) ) {
			return true;
		}
		$s = PNCP_Options::get();
		return PNCP_Ip::reliable() && isset( $s['allow_ips'] ) && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['allow_ips'] ) );
	}

	/**
	 * May the IP be refused now? Not in Monitor only, not for the server itself and not when the IP may be
	 * spoofed (a refusal would then hit someone else).
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private static function may_refuse( $ip ) {
		return self::is_protected() && ! PNCP_Options::monitoring() && PNCP_Ip::reliable() && ! self::not_counted( $ip );
	}

	/**
	 * The user a username or email stands for, or null.
	 *
	 * @param string $username Username or email as typed.
	 * @return WP_User|null
	 */
	private static function user_of( $username ) {
		$username = trim( (string) $username );
		if ( '' === $username ) {
			return null;
		}
		$user = get_user_by( 'login', $username );
		if ( ! $user && is_email( $username ) ) {
			$user = get_user_by( 'email', $username );
		}
		return $user instanceof WP_User ? $user : null;
	}

	/**
	 * The key under which a username is counted: the account (login and email count together), or the text
	 * typed when no account has it.
	 *
	 * @param string       $username Username as typed.
	 * @param WP_User|null $user     Its user.
	 * @return string
	 */
	private static function user_key( $username, $user ) {
		return $user ? 'id:' . (int) $user->ID : 'n:' . md5( strtolower( trim( (string) $username ) ) );
	}

	/**
	 * The hash under which an IP is remembered for a user (no IP is stored).
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private static function ip_hash( $ip ) {
		return substr( hash_hmac( 'sha256', PNCP_Ip::limit_key( $ip ), wp_salt( 'auth' ) ), 0, 20 );
	}

	/**
	 * Did this user sign in from this IP before (within 180 days)?
	 *
	 * @param WP_User|null $user User.
	 * @param string       $ip   IP.
	 * @return bool
	 */
	private static function known_ip( $user, $ip ) {
		if ( ! $user || '' === $ip || ! PNCP_Ip::reliable() ) {
			return false;
		}
		$known = get_user_meta( $user->ID, self::KNOWN_META, true );
		$hash  = self::ip_hash( $ip );
		return is_array( $known ) && isset( $known[ $hash ] ) && (int) $known[ $hash ] > time() - 180 * DAY_IN_SECONDS;
	}

	/**
	 * Does this browser carry a valid unlock cookie for the user?
	 *
	 * @param WP_User|null $user User.
	 * @return bool
	 */
	private static function has_unlock_cookie( $user ) {
		if ( ! $user || empty( $_COOKIE[ self::UNLOCK_COOKIE ] ) ) {
			return false;
		}
		$parts = explode( '|', sanitize_text_field( wp_unslash( $_COOKIE[ self::UNLOCK_COOKIE ] ) ) );
		if ( 3 !== count( $parts ) || (int) $parts[0] !== (int) $user->ID || (int) $parts[1] < time() ) {
			return false;
		}
		return hash_equals( self::cookie_mac( (int) $parts[0], (int) $parts[1] ), (string) $parts[2] );
	}

	/**
	 * The signature of an unlock cookie.
	 *
	 * @param int $user_id User.
	 * @param int $until   Expiry.
	 * @return string
	 */
	private static function cookie_mac( $user_id, $until ) {
		return hash_hmac( 'sha256', 'pncp-unlock|' . $user_id . '|' . $until, wp_salt( 'auth' ) );
	}

	/**
	 * The usernames paused now: key => array{u:string, until:int, user:int}.
	 *
	 * @return array<string, array{u:string, until:int, user:int}>
	 */
	public static function locks() {
		$locks = get_option( self::LOCKS_OPTION, array() );
		$out   = array();
		foreach ( is_array( $locks ) ? $locks : array() as $key => $lock ) {
			if ( is_array( $lock ) && isset( $lock['until'] ) && (int) $lock['until'] > time() ) {
				$out[ (string) $key ] = array(
					'u'     => isset( $lock['u'] ) ? (string) $lock['u'] : '',
					'until' => (int) $lock['until'],
					'user'  => isset( $lock['user'] ) ? (int) $lock['user'] : 0,
				);
			}
		}
		return $out;
	}

	/**
	 * Until when is the username paused (0 = it is not)?
	 *
	 * @param string $key User key (user_key()).
	 * @return int
	 */
	private static function locked_until( $key ) {
		$locks = self::locks();
		return isset( $locks[ $key ] ) ? $locks[ $key ]['until'] : 0;
	}

	/**
	 * Filters authenticate (99, after WordPress has checked the password): refuses a blocked IP and a paused username,
	 * and gives one message for every wrong username, email or password.
	 *
	 * @param WP_User|WP_Error|null $user     Result so far.
	 * @param string                $username Username or email.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error|null
	 */
	public static function authenticate( $user, $username = '', $password = '' ) {
		self::$own_refusal = false;
		$username          = is_string( $username ) ? $username : '';
		if ( '' === trim( $username ) && '' === (string) $password ) {
			return $user; // The form opened, nothing sent.
		}
		$ip = PNCP_Ip::client_ip();
		if ( self::may_refuse( $ip ) ) {
			$account = self::user_of( $username );
			if ( PNCP_Log::is_banned( $ip ) && ! self::known_ip( $account, $ip ) && ! self::has_unlock_cookie( $account ) ) {
				self::$own_refusal = true;
				PNCP_Log::add( 'banned', 403, $ip );
				return self::locked_error();
			}
			$until = self::locked_until( self::user_key( $username, $account ) );
			if ( $until > time() && ! self::known_ip( $account, $ip ) && ! self::has_unlock_cookie( $account ) ) {
				self::$own_refusal = true;
				PNCP_Log::add( 'login_user', 403, $ip );
				return self::locked_error( $until );
			}
		}
		$s = self::settings();
		if ( $s['enabled'] && ! empty( $s['login_generic_errors'] ) && is_wp_error( $user ) && array_intersect( $user->get_error_codes(), array( 'invalid_username', 'invalid_email', 'incorrect_password' ) ) ) {
			return self::generic_error();
		}
		return $user;
	}

	/**
	 * The message for a wrong username, email or password.
	 *
	 * @return WP_Error
	 */
	public static function generic_error() {
		return new WP_Error(
			'pncp_invalid_login',
			sprintf(
				/* translators: %s: URL of the "lost password" page */
				__( '<strong>Error:</strong> The username, email address or password is not correct. <a href="%s">Lost your password?</a>', 'scrapelock' ),
				esc_url( wp_lostpassword_url() )
			)
		);
	}

	/**
	 * The message for a refused sign-in (blocked IP or paused username). The same words for usernames that exist
	 * and those that do not, so it does not say which accounts exist.
	 *
	 * @param int $until End of the username's pause (0 = the IP's block: not said).
	 * @return WP_Error
	 */
	private static function locked_error( $until = 0 ) {
		$minutes = $until > time() ? (int) ceil( ( $until - time() ) / MINUTE_IN_SECONDS ) : 0;
		$text    = $minutes > 0
			? sprintf(
				/* translators: %s: number of minutes */
				_n( 'Too many failed sign-ins. Please try again in %s minute.', 'Too many failed sign-ins. Please try again in %s minutes.', $minutes, 'scrapelock' ),
				number_format_i18n( $minutes )
			)
			: __( 'Too many failed sign-ins. Please try again later.', 'scrapelock' );
		if ( $until > 0 && ! empty( self::settings()['login_user_email'] ) ) {
			$text .= ' ' . __( 'If this is your account, its email address has been sent a link that lets you sign in now.', 'scrapelock' );
		}
		return new WP_Error( 'pncp_login_locked', '<strong>' . esc_html__( 'Error:', 'scrapelock' ) . '</strong> ' . esc_html( $text ) );
	}

	/**
	 * A sign-in failed (wp_login_failed): counted at the end of the request.
	 *
	 * @param string $username Username or email.
	 */
	public static function on_failed( $username ) {
		if ( self::$own_refusal ) {
			self::$own_refusal = false;
			return; // Refused by the pause or the block: not counted again.
		}
		self::fail( (string) $username );
	}

	/**
	 * The usernames of the calls of this XML-RPC request, in order (a system.multicall has many). Read from the
	 * request body only after a sign-in failed, once.
	 *
	 * @return string[]
	 */
	private static function xmlrpc_usernames() {
		if ( null !== self::$xmlrpc_users ) {
			return self::$xmlrpc_users;
		}
		self::$xmlrpc_users = array();
		// Read only: WordPress's xmlrpc.php fills this global from php://input.
		$raw_post = isset( $GLOBALS['HTTP_RAW_POST_DATA'] ) ? $GLOBALS['HTTP_RAW_POST_DATA'] : null;
		if ( ! is_string( $raw_post ) || '' === $raw_post || ! class_exists( 'IXR_Message' ) ) {
			return self::$xmlrpc_users;
		}
		$message = new IXR_Message( $raw_post );
		if ( ! $message->parse() ) {
			return self::$xmlrpc_users;
		}
		$calls = array(
			array(
				'methodName' => (string) $message->methodName, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- IXR property.
				'params'     => (array) $message->params,
			),
		);
		if ( 'system.multicall' === strtolower( $calls[0]['methodName'] ) ) {
			$calls = isset( $message->params[0] ) && is_array( $message->params[0] ) ? $message->params[0] : array();
		}
		foreach ( array_slice( $calls, 0, 5000 ) as $call ) {
			if ( ! is_array( $call ) || empty( $call['methodName'] ) || 0 === strpos( strtolower( (string) $call['methodName'] ), 'system.' ) ) {
				continue; // system.* methods do not sign in.
			}
			$params = isset( $call['params'] ) ? array_values( (array) $call['params'] ) : array();
			// wp.getUsersBlogs( username, password ); the others: ( blog or post id, or app key, username, password, … ).
			$pos                  = 'wp.getusersblogs' === strtolower( (string) $call['methodName'] ) ? 0 : 1;
			self::$xmlrpc_users[] = isset( $params[ $pos ] ) && is_scalar( $params[ $pos ] ) ? substr( (string) $params[ $pos ], 0, 100 ) : '';
		}
		return self::$xmlrpc_users;
	}

	/**
	 * The username of the next XML-RPC sign-in check of this request ('' = unknown).
	 *
	 * @return string
	 */
	private static function next_xmlrpc_username() {
		$users = self::xmlrpc_usernames();
		$name  = isset( $users[ self::$xmlrpc_index ] ) ? $users[ self::$xmlrpc_index ] : '';
		++self::$xmlrpc_index;
		return $name;
	}

	/**
	 * Filters xmlrpc_login_error: after the first wrong password of a request WordPress stops checking (and does not
	 * fire wp_login_failed again), so each further call of a system.multicall is counted here.
	 *
	 * @param IXR_Error $error Error.
	 * @param WP_Error  $user  Why the sign-in failed.
	 * @return IXR_Error
	 */
	public static function on_xmlrpc_login_error( $error, $user = null ) {
		if ( ! $user instanceof WP_Error ) {
			return $error;
		}
		if ( 'login_prevented' !== $user->get_error_code() ) {
			++self::$xmlrpc_index; // The first failure: counted by wp_login_failed.
			return $error;
		}
		$username = self::next_xmlrpc_username();
		if ( class_exists( 'PNCP_Attacks' ) ) {
			PNCP_Attacks::record( 'login_fail', self::attack_path(), PNCP_Ip::client_ip(), false, $username );
		}
		self::fail( $username );
		return $error;
	}

	/**
	 * XML-RPC from a blocked IP: refused before any method runs (init, 3).
	 */
	public static function xmlrpc_gate() {
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return;
		}
		$ip = PNCP_Ip::client_ip();
		if ( ! self::may_refuse( $ip ) || ! PNCP_Log::is_banned( $ip ) ) {
			return;
		}
		PNCP_Log::add( 'banned', 403, $ip );
		if ( class_exists( 'PNCP_Bots' ) ) {
			PNCP_Bots::no_cache();
		}
		if ( ! headers_sent() ) {
			status_header( 403 );
			header( 'Content-Type: text/xml; charset=UTF-8' );
		}
		echo '<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>403</int></value></member><member><name>faultString</name><value><string>' . esc_html__( 'Access denied.', 'scrapelock' ) . '</string></value></member></struct></value></fault></methodResponse>';
		exit;
	}

	/**
	 * Filters application_password_is_api_request: no application-password check for a blocked IP or a paused username.
	 *
	 * @param bool $is_api Whether this is an API request.
	 * @return bool
	 */
	public static function app_password_gate( $is_api ) {
		if ( ! $is_api || empty( $_SERVER['PHP_AUTH_USER'] ) ) {
			return $is_api;
		}
		$ip = PNCP_Ip::client_ip();
		if ( ! self::may_refuse( $ip ) ) {
			return $is_api;
		}
		$username = sanitize_user( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitize_user().
		$account  = self::user_of( $username );
		if ( self::known_ip( $account, $ip ) ) {
			return $is_api;
		}
		if ( PNCP_Log::is_banned( $ip ) ) {
			PNCP_Log::add( 'banned', 403, $ip );
			return false;
		}
		if ( self::locked_until( self::user_key( $username, $account ) ) > time() ) {
			PNCP_Log::add( 'login_user', 403, $ip );
			return false;
		}
		return $is_api;
	}

	/**
	 * Action application_password_failed_authentication: a wrong application password (REST API, XML-RPC).
	 *
	 * @param WP_Error $error Error.
	 */
	public static function on_app_password_failed( $error ) {
		$username = isset( $_SERVER['PHP_AUTH_USER'] ) ? sanitize_user( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitize_user().
		if ( $error instanceof WP_Error && 'application_passwords_disabled' === $error->get_error_code() ) {
			return;
		}
		if ( class_exists( 'PNCP_Attacks' ) ) {
			PNCP_Attacks::record( 'login_fail', self::attack_path(), PNCP_Ip::client_ip(), false, $username );
		}
		self::fail( $username );
	}

	/**
	 * The request path for the attack record.
	 *
	 * @return string
	 */
	private static function attack_path() {
		$uri  = class_exists( 'PNCP_Log' ) ? PNCP_Log::request_uri() : '/';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		return '' === $path ? '/' : $path;
	}

	/**
	 * Notes a failure of this request; the counters are written once, at shutdown.
	 *
	 * @param string $username Username or email tried.
	 */
	private static function fail( $username ) {
		if ( ! self::is_protected() ) {
			return;
		}
		$username = substr( trim( (string) $username ), 0, 100 );
		if ( isset( self::$pending[ $username ] ) ) {
			++self::$pending[ $username ];
		} elseif ( count( self::$pending ) < self::MAX_USERS_PER_REQUEST ) {
			self::$pending[ $username ] = 1;
		} else {
			self::$pending[''] = isset( self::$pending[''] ) ? self::$pending[''] + 1 : 1; // Counted for the IP only.
		}
		if ( ! self::$hooked ) {
			self::$hooked = true;
			add_action( 'shutdown', array( __CLASS__, 'flush_pending' ), 0 );
		}
	}

	/**
	 * Adds $step to a counter and returns the new count.
	 *
	 * @param string $key  Key.
	 * @param int    $step Step.
	 * @param int    $ttl  Seconds.
	 * @return int
	 */
	private static function add_count( $key, $step, $ttl ) {
		$count = PNCP_Log::cache_incr( $key, $ttl );
		if ( $step > 1 ) {
			$count += $step - 1;
			PNCP_Log::cache_set( $key, $count, $ttl );
		}
		return $count;
	}

	/**
	 * Writes the failures of this request: the IP's counter (and its block), and each username's (and its pause).
	 */
	public static function flush_pending() {
		$pending       = self::$pending;
		self::$pending = array();
		if ( ! $pending || ! self::is_protected() ) {
			return;
		}
		$s     = self::settings();
		$ip    = PNCP_Ip::client_ip();
		$total = array_sum( $pending );
		if ( ! class_exists( 'PNCP_Attacks' ) ) {
			// Day counts for the status card when there is no attack record.
			self::add_count( 'pncp_lfd_' . wp_date( 'Ymd' ), $total, 8 * DAY_IN_SECONDS );
		}
		if ( self::not_counted( $ip ) ) {
			return;
		}

		// Failures with the username of an account that already signed in from this IP are the person who
		// forgot the password: they count toward that username, not toward a block of the IP.
		$for_ip   = 0;
		$accounts = array();
		foreach ( $pending as $username => $n ) {
			$account                        = '' === (string) $username ? null : self::user_of( (string) $username );
			$accounts[ (string) $username ] = $account;
			if ( ! self::known_ip( $account, $ip ) ) {
				$for_ip += $n;
			}
		}

		if ( $for_ip > 0 ) {
			$key   = 'pncp_lfi_' . md5( PNCP_Ip::limit_key( $ip ) );
			$count = self::add_count( $key, $for_ip, (int) $s['login_window'] * MINUTE_IN_SECONDS );
			if ( $count >= (int) $s['login_max'] ) {
				if ( PNCP_Options::monitoring() ) {
					PNCP_Log::add( 'login', PNCP_Log::MONITOR_CODE, $ip );
				} elseif ( PNCP_Ip::reliable() ) {
					PNCP_Log::cache_delete( $key );
					PNCP_Log::ban( $ip, (int) $s['login_ban_minutes'], 'login' );
				}
				if ( class_exists( 'PNCP_Reputation' ) ) {
					PNCP_Reputation::record( $ip, 'limit' );
				}
			}
		}

		if ( (int) $s['login_user_max'] < 1 ) {
			return;
		}
		foreach ( $pending as $username => $n ) {
			$username = (string) $username;
			if ( '' === $username ) {
				continue;
			}
			$account = $accounts[ $username ];
			$ukey    = self::user_key( $username, $account );
			$ttl     = (int) $s['login_user_minutes'] * MINUTE_IN_SECONDS;
			$count   = self::add_count( 'pncp_lfu_' . md5( $ukey ), $n, $ttl );
			if ( $count < (int) $s['login_user_max'] || self::locked_until( $ukey ) > time() ) {
				continue;
			}
			if ( PNCP_Options::monitoring() ) {
				PNCP_Log::add( 'login_user', PNCP_Log::MONITOR_CODE, $ip );
				continue;
			}
			PNCP_Log::cache_delete( 'pncp_lfu_' . md5( $ukey ) );
			self::lock_user( $ukey, $account ? $account->user_login : $username, $account, time() + $ttl );
			if ( class_exists( 'PNCP_Reputation' ) ) {
				PNCP_Reputation::record( $ip, 'limit' );
			}
		}
	}

	/**
	 * Pauses a username, and emails the account the link that lets its owner sign in now.
	 *
	 * @param string       $key     User key.
	 * @param string       $label   Username shown in the status card.
	 * @param WP_User|null $account User.
	 * @param int          $until   Until when.
	 */
	private static function lock_user( $key, $label, $account, $until ) {
		$locks = self::locks();
		if ( count( $locks ) >= self::MAX_LOCKS ) {
			uasort(
				$locks,
				static function ( $a, $b ) {
					return $a['until'] <=> $b['until'];
				}
			);
			$locks = array_slice( $locks, 1 - self::MAX_LOCKS, null, true );
		}
		$locks[ $key ] = array(
			'u'     => substr( sanitize_text_field( $label ), 0, 60 ),
			'until' => (int) $until,
			'user'  => $account ? (int) $account->ID : 0,
		);
		if ( ! add_option( self::LOCKS_OPTION, $locks, '', false ) ) {
			update_option( self::LOCKS_OPTION, $locks, false );
		}
		if ( $account && ! empty( self::settings()['login_user_email'] ) ) {
			self::email_unlock( $account, $until );
		}
	}

	/**
	 * Emails the unlock link (once per pause).
	 *
	 * @param WP_User $user  User.
	 * @param int     $until End of the pause.
	 * @return bool Whether it was sent.
	 */
	public static function email_unlock( $user, $until ) {
		if ( ! $user instanceof WP_User || ! is_email( $user->user_email ) ) {
			return false;
		}
		$token = wp_generate_password( 32, false, false );
		update_user_meta(
			$user->ID,
			self::UNLOCK_META,
			array(
				'hash'  => hash_hmac( 'sha256', $token, wp_salt( 'auth' ) ),
				'until' => time() + self::UNLOCK_TTL,
			)
		);
		$url  = add_query_arg(
			array(
				'pncp_unlock' => $token,
				'u'           => (int) $user->ID,
			),
			self::login_url()
		);
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$body = sprintf(
			/* translators: 1: username, 2: site name, 3: time, 4: unlock URL */
			__( "Hello,\n\nSomeone tried to sign in to your account “%1\$s” on %2\$s with wrong passwords, many times. To protect it, sign-ins to the account are paused until %3\$s, except from where you signed in before.\n\nIf it was you, open this link to sign in from this browser now (it works once, for 24 hours):\n%4\$s\n\nIf it was not you, your password was not guessed and you need not do anything. If your password is short or used on other sites, change it.\n", 'scrapelock' ),
			$user->user_login,
			$site,
			wp_date( (string) get_option( 'time_format' ), $until ),
			$url
		);
		/* translators: %s: site name */
		return (bool) wp_mail( $user->user_email, sprintf( __( '[%s] Sign-ins to your account are paused', 'scrapelock' ), $site ), $body );
	}

	/**
	 * Action login_init (1): the unlock link, then a blocked IP is refused.
	 */
	public static function login_gate() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- The token is the proof.
		if ( isset( $_GET['pncp_unlock'], $_GET['u'] ) ) {
			$ok = self::redeem( absint( $_GET['u'] ), sanitize_text_field( wp_unslash( $_GET['pncp_unlock'] ) ) );
			wp_safe_redirect( add_query_arg( 'pncp_unlocked', $ok ? '1' : '0', self::login_url() ) );
			exit;
		}
		// phpcs:enable
		$ip = PNCP_Ip::client_ip();
		if ( ! self::may_refuse( $ip ) || ! PNCP_Log::is_banned( $ip ) || is_user_logged_in() || ! empty( $_COOKIE[ self::UNLOCK_COOKIE ] ) ) {
			return;
		}
		PNCP_Log::add( 'banned', 403, $ip );
		if ( class_exists( 'PNCP_Bots' ) ) {
			PNCP_Bots::die_html( 403 );
		}
		wp_die( esc_html__( 'Access denied.', 'scrapelock' ), '403', array( 'response' => 403 ) );
	}

	/**
	 * Uses an unlock link: this browser may sign in to the account during the pause (cookie), the username's
	 * pause ends, and the IP's block for failed sign-ins is lifted.
	 *
	 * @param int    $user_id User.
	 * @param string $token   Token.
	 * @return bool
	 */
	public static function redeem( $user_id, $token ) {
		$user = get_user_by( 'id', (int) $user_id );
		if ( ! $user || '' === $token ) {
			return false;
		}
		$meta = get_user_meta( $user->ID, self::UNLOCK_META, true );
		if ( ! is_array( $meta ) || empty( $meta['hash'] ) || (int) $meta['until'] < time() || ! hash_equals( (string) $meta['hash'], hash_hmac( 'sha256', $token, wp_salt( 'auth' ) ) ) ) {
			return false;
		}
		delete_user_meta( $user->ID, self::UNLOCK_META );
		$until = time() + self::UNLOCK_COOKIE_TTL;
		$value = $user->ID . '|' . $until . '|' . self::cookie_mac( (int) $user->ID, $until );
		if ( ! headers_sent() ) {
			setcookie( self::UNLOCK_COOKIE, $value, $until, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, is_ssl(), true );
		}
		$_COOKIE[ self::UNLOCK_COOKIE ] = $value;
		self::unlock_user( 'id:' . (int) $user->ID );
		$ip = PNCP_Ip::client_ip();
		if ( '' !== $ip && PNCP_Ip::reliable() ) {
			$bans = PNCP_Log::active_bans( 0 );
			$key  = PNCP_Ip::limit_key( $ip );
			if ( isset( $bans[ $key ] ) && 'login' === $bans[ $key ]['reason'] ) {
				PNCP_Log::unban( $ip );
			}
			PNCP_Log::cache_delete( 'pncp_lfi_' . md5( $key ) );
		}
		return true;
	}

	/**
	 * Ends the pause of a username.
	 *
	 * @param string $key User key (or the username: its key is worked out).
	 * @return bool Whether it was paused.
	 */
	public static function unlock_user( $key ) {
		$key   = (string) $key;
		$locks = self::locks();
		if ( ! isset( $locks[ $key ] ) && 0 !== strpos( $key, 'id:' ) && 0 !== strpos( $key, 'n:' ) ) {
			$key = self::user_key( $key, self::user_of( $key ) );
		}
		PNCP_Log::cache_delete( 'pncp_lfu_' . md5( $key ) );
		if ( ! isset( $locks[ $key ] ) ) {
			return false;
		}
		unset( $locks[ $key ] );
		update_option( self::LOCKS_OPTION, $locks, false );
		return true;
	}

	/**
	 * The message on the sign-in page after an unlock link.
	 *
	 * @param string $message Message.
	 * @return string
	 */
	public static function login_message( $message ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only which message to show.
		if ( ! isset( $_GET['pncp_unlocked'] ) ) {
			return $message;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- As above.
		$ok   = '1' === sanitize_key( wp_unslash( $_GET['pncp_unlocked'] ) );
		$text = $ok ? __( 'Your account is unlocked for this browser: you can sign in now.', 'scrapelock' ) : __( 'This link has expired or was already used. Wait until the pause ends, or reset your password.', 'scrapelock' );
		return $message . '<p class="message">' . esc_html( $text ) . '</p>';
	}

	/**
	 * A sign-in worked (wp_login): the IP is remembered for the account, and its failures are forgotten.
	 *
	 * @param string  $login Username.
	 * @param WP_User $user  User.
	 */
	public static function on_login( $login, $user = null ) {
		$ip = PNCP_Ip::client_ip();
		if ( ! $user instanceof WP_User || '' === $ip || ! PNCP_Ip::reliable() ) {
			return;
		}
		PNCP_Log::cache_delete( 'pncp_lfi_' . md5( PNCP_Ip::limit_key( $ip ) ) );
		$known = get_user_meta( $user->ID, self::KNOWN_META, true );
		$known = is_array( $known ) ? $known : array();
		$hash  = self::ip_hash( $ip );
		if ( isset( $known[ $hash ] ) && (int) $known[ $hash ] > time() - DAY_IN_SECONDS ) {
			return; // Written at most once a day per IP.
		}
		$known[ $hash ] = time();
		arsort( $known );
		$known = array_slice( $known, 0, self::MAX_KNOWN, true );
		update_user_meta( $user->ID, self::KNOWN_META, $known );
	}

	/**
	 * Action lostpassword_post: "Lost your password" answers the same for an account that does not exist.
	 *
	 * @param WP_Error           $errors    Errors so far.
	 * @param WP_User|false|null $user_data The account found.
	 */
	public static function lostpassword_post( $errors, $user_data = null ) {
		$s = self::settings();
		if ( ! $s['enabled'] || empty( $s['login_generic_errors'] ) || ! did_action( 'login_init' ) || $user_data instanceof WP_User ) {
			return;
		}
		if ( ! $errors instanceof WP_Error || $errors->has_errors() ) {
			return; // Empty field, or an error of another plugin (a captcha): shown as usual.
		}
		wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', self::login_url() ) );
		exit;
	}

	/**
	 * The sign-in form shakes for these errors too, as for WordPress's own.
	 *
	 * @param string[] $codes Error codes.
	 * @return string[]
	 */
	public static function shake_codes( $codes ) {
		$codes[] = 'pncp_invalid_login';
		$codes[] = 'pncp_login_locked';
		return $codes;
	}

	/* ---------- Vulnerable points (PNCP_Hardening) ---------- */

	/**
	 * The state of the login point: on (limit and address), partial (one of them), off.
	 *
	 * @return string
	 */
	public static function hardening_status() {
		$s     = self::settings();
		$limit = ! empty( $s['login_limit'] );
		$slug  = '' !== self::clean_slug( (string) $s['login_slug'] ) && ! self::reserved( self::clean_slug( (string) $s['login_slug'] ) );
		if ( $limit && $slug ) {
			return 'on';
		}
		return $limit || $slug ? 'partial' : 'off';
	}

	/**
	 * Locks the login point: the limit on, and a new sign-in address (a random one when none is set). The
	 * administrator is emailed the new address.
	 *
	 * @return true|WP_Error
	 */
	public static function hardening_apply() {
		$s    = self::settings();
		$slug = self::clean_slug( (string) $s['login_slug'] );
		if ( '' === $slug || self::reserved( $slug ) ) {
			$slug = 'login-' . strtolower( wp_generate_password( 8, false, false ) );
		}
		$result = self::save(
			array(
				'login_limit' => 1,
				'login_slug'  => $slug,
			)
		);
		if ( true === $result ) {
			self::email_new_address();
		}
		return $result;
	}

	/**
	 * Opens the login point again: the address goes back to wp-login.php. The limit of failed sign-ins stays as
	 * it is (turn it off on the Bots tab), so opening the old address never removes the protection against
	 * password guessing without saying so.
	 *
	 * @return true|WP_Error
	 */
	public static function hardening_revert() {
		return self::save( array( 'login_slug' => '' ) );
	}

	/**
	 * Changes settings of this class, through the same sanitizing as the settings form.
	 *
	 * @param array<string, mixed> $changes Key => value.
	 * @return true|WP_Error
	 */
	public static function save( $changes ) {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked with Lockdown: unlock it to change the sign-in protection.', 'scrapelock' ) );
		}
		$stored = PNCP_Options::stored();
		foreach ( (array) $changes as $key => $value ) {
			if ( array_key_exists( $key, self::defaults() ) ) {
				$stored[ $key ] = $value;
			}
		}
		// In wp-admin the option is registered with PNCP_Options::sanitize() as its sanitize callback; elsewhere
		// (WP-CLI) it is sanitized here.
		if ( ! has_filter( 'sanitize_option_' . PNCP_OPTION ) ) {
			$stored = PNCP_Options::sanitize( $stored );
		}
		update_option( PNCP_OPTION, $stored );
		PNCP_Options::flush();
		self::flush();
		$now = self::settings();
		foreach ( (array) $changes as $key => $value ) {
			if ( array_key_exists( $key, self::defaults() ) && (string) $now[ $key ] !== (string) $value ) {
				return new WP_Error( 'pncp_setting', __( 'The setting could not be changed.', 'scrapelock' ) );
			}
		}
		return true;
	}

	/**
	 * Emails the administrator the sign-in address (after it was moved).
	 *
	 * @return bool
	 */
	public static function email_new_address() {
		$slug = self::slug();
		if ( '' === $slug ) {
			return false;
		}
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$body = sprintf(
			/* translators: 1: site name, 2: new sign-in URL */
			__( "The sign-in page of %1\$s has moved. Sign in here from now on, and keep this address:\n\n%2\$s\n\nwp-login.php and /wp-admin/ now answer “page not found” to visitors who are not signed in.\nIf you lose the address, add this line to wp-config.php to turn the new address off:\ndefine( 'SCRAPELOCK_LOGIN_SLUG_OFF', true );\n", 'scrapelock' ),
			$site,
			self::login_url()
		);
		/* translators: %s: site name */
		return (bool) wp_mail( (string) get_option( 'admin_email' ), sprintf( __( '[%s] New sign-in address', 'scrapelock' ), $site ), $body );
	}

	/* ---------- Status ---------- */

	/**
	 * The numbers of the status card.
	 *
	 * @return array{today:int, week:int, xmlrpc:int, ips:array<string, array<string, mixed>>, locks:array<string, array{u:string, until:int, user:int}>, users:array<int, array{detail:string, hits:int, ips:int}>}
	 */
	public static function stats() {
		$today = 0;
		$week  = 0;
		$users = array();
		$xml   = 0;
		if ( class_exists( 'PNCP_Attacks' ) ) {
			$days  = PNCP_Attacks::per_day( 7, 'login_fail' );
			$week  = (int) array_sum( $days );
			$today = (int) ( isset( $days[ wp_date( 'Y-m-d' ) ] ) ? $days[ wp_date( 'Y-m-d' ) ] : 0 );
			$users = PNCP_Attacks::top_details( 7, 'login_fail', 10 );
			$xml   = PNCP_Attacks::count( 7, 'xmlrpc' );
		} else {
			for ( $i = 0; $i < 7; $i++ ) {
				$n     = (int) PNCP_Log::cache_get( 'pncp_lfd_' . wp_date( 'Ymd', time() - $i * DAY_IN_SECONDS ) );
				$week += $n;
				$today = 0 === $i ? $n : $today;
			}
		}
		$ips = array();
		foreach ( PNCP_Log::active_bans( 0 ) as $ip => $ban ) {
			if ( 'login' === $ban['reason'] ) {
				$ips[ $ip ] = $ban;
			}
		}
		return array(
			'today'  => $today,
			'week'   => $week,
			'xmlrpc' => (int) $xml,
			'ips'    => $ips,
			'locks'  => self::locks(),
			'users'  => $users,
		);
	}

	/**
	 * Card: failed sign-ins, blocked IPs, paused usernames, the usernames tried and the sign-in address.
	 */
	public static function render_status_card() {
		$st  = self::stats();
		$s   = self::settings();
		$fmt = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only which notice to show.
		$msg = isset( $_GET['pncp_login_msg'] ) ? sanitize_key( wp_unslash( $_GET['pncp_login_msg'] ) ) : '';
		?>
		<section class="pncp-card pncp-card--wide pncp-login-status" aria-labelledby="pncp-login-status-title">
			<h2 id="pncp-login-status-title"><?php esc_html_e( 'Sign-in protection', 'scrapelock' ); ?></h2>
			<?php if ( 'unblocked' === $msg || 'unlocked' === $msg ) : ?>
				<div class="notice notice-success inline"><p><?php echo esc_html( 'unblocked' === $msg ? __( 'The IP can sign in again.', 'scrapelock' ) : __( 'The username can sign in again.', 'scrapelock' ) ); ?></p></div>
			<?php endif; ?>
			<?php if ( ! $s['enabled'] ) : ?>
				<p class="description"><?php esc_html_e( 'ScrapeLock\'s protection is turned off: failed sign-ins are not limited and the sign-in address is not moved.', 'scrapelock' ); ?></p>
			<?php elseif ( empty( $s['login_limit'] ) ) : ?>
				<p class="description"><?php esc_html_e( 'The limit of failed sign-ins is off: anyone can try passwords without limit.', 'scrapelock' ); ?></p>
			<?php elseif ( PNCP_Options::monitoring() ) : ?>
				<p class="description"><?php esc_html_e( 'Monitor only is on: failed sign-ins are counted and logged as “Would block”, but no IP is blocked, no username is paused and wp-login.php stays open.', 'scrapelock' ); ?></p>
			<?php endif; ?>

			<ul class="pncp-login-status__numbers">
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'Failed sign-ins today: %s', 'scrapelock' ), number_format_i18n( $st['today'] ) ) ); ?></li>
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'Failed sign-ins in the last 7 days: %s', 'scrapelock' ), number_format_i18n( $st['week'] ) ) ); ?></li>
				<?php if ( class_exists( 'PNCP_Attacks' ) ) : ?>
					<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'XML-RPC calls in the last 7 days: %s', 'scrapelock' ), number_format_i18n( $st['xmlrpc'] ) ) ); ?></li>
				<?php endif; ?>
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'IPs blocked for failed sign-ins now: %s', 'scrapelock' ), number_format_i18n( count( $st['ips'] ) ) ) ); ?></li>
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'Usernames paused now: %s', 'scrapelock' ), number_format_i18n( count( $st['locks'] ) ) ) ); ?></li>
			</ul>

			<h3><?php esc_html_e( 'Sign-in address', 'scrapelock' ); ?></h3>
			<?php if ( defined( 'SCRAPELOCK_LOGIN_SLUG_OFF' ) && SCRAPELOCK_LOGIN_SLUG_OFF ) : ?>
				<p class="description"><?php esc_html_e( 'SCRAPELOCK_LOGIN_SLUG_OFF is set in wp-config.php: the custom address is turned off and wp-login.php is open. Remove the line to move it again.', 'scrapelock' ); ?></p>
			<?php elseif ( '' !== self::slug() ) : ?>
				<p><code><?php echo esc_html( self::login_url() ); ?></code></p>
				<p class="description">
					<?php
					echo esc_html(
						self::hides_login()
							? __( 'wp-login.php and /wp-admin/ answer “page not found” to visitors who are not signed in. Bookmark this address. If you lose it, add define( \'SCRAPELOCK_LOGIN_SLUG_OFF\', true ); to wp-config.php.', 'scrapelock' )
							: __( 'The new address works; in Monitor only wp-login.php stays open too, so nobody is locked out while you check.', 'scrapelock' )
					);
					?>
				</p>
			<?php else : ?>
				<p class="description"><?php esc_html_e( 'Not moved: the sign-in page is wp-login.php, where every password-guessing bot looks first.', 'scrapelock' ); ?></p>
			<?php endif; ?>

			<?php if ( $st['ips'] ) : ?>
				<h3><?php esc_html_e( 'IPs blocked for failed sign-ins', 'scrapelock' ); ?></h3>
				<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
					<th scope="col"><?php esc_html_e( 'IP', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Blocked until', 'scrapelock' ); ?></th>
					<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'scrapelock' ); ?></span></th>
				</tr></thead><tbody>
				<?php foreach ( array_slice( $st['ips'], 0, 50, true ) as $ip => $ban ) : ?>
					<tr>
						<td><code><?php echo esc_html( (string) $ip ); ?></code></td>
						<td><?php echo esc_html( wp_date( $fmt, (int) $ban['until'] ) ); ?></td>
						<td><?php self::action_button( 'unban_ip', (string) $ip, __( 'Unblock', 'scrapelock' ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody></table></div>
			<?php endif; ?>

			<?php if ( $st['locks'] ) : ?>
				<h3><?php esc_html_e( 'Paused usernames', 'scrapelock' ); ?></h3>
				<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
					<th scope="col"><?php esc_html_e( 'Username', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Account', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Paused until', 'scrapelock' ); ?></th>
					<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'scrapelock' ); ?></span></th>
				</tr></thead><tbody>
				<?php foreach ( $st['locks'] as $key => $lock ) : ?>
					<tr>
						<td><code><?php echo esc_html( $lock['u'] ); ?></code></td>
						<td><?php echo esc_html( $lock['user'] ? __( 'Exists', 'scrapelock' ) : __( 'No such account', 'scrapelock' ) ); ?></td>
						<td><?php echo esc_html( wp_date( $fmt, $lock['until'] ) ); ?></td>
						<td><?php self::action_button( 'unlock_user', (string) $key, __( 'Unlock', 'scrapelock' ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody></table></div>
				<p class="description"><?php esc_html_e( 'A paused username can still sign in from an IP it signed in from before, and with the link emailed to the account.', 'scrapelock' ); ?></p>
			<?php endif; ?>

			<?php if ( $st['users'] ) : ?>
				<h3><?php esc_html_e( 'Usernames tried in the last 7 days', 'scrapelock' ); ?></h3>
				<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
					<th scope="col"><?php esc_html_e( 'Username', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'Failed sign-ins', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Account', 'scrapelock' ); ?></th>
				</tr></thead><tbody>
				<?php foreach ( $st['users'] as $row ) : ?>
					<tr>
						<td><code><?php echo esc_html( '' !== $row['detail'] ? $row['detail'] : '—' ); ?></code></td>
						<td class="num"><?php echo esc_html( number_format_i18n( (int) $row['hits'] ) ); ?></td>
						<td class="num"><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?></td>
						<td><?php echo esc_html( self::user_of( (string) $row['detail'] ) ? __( 'Exists: make sure its password is strong', 'scrapelock' ) : __( 'No such account', 'scrapelock' ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody></table></div>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * A small form button of the status card.
	 *
	 * @param string $op    Operation.
	 * @param string $value IP or username key.
	 * @param string $label Label.
	 */
	private static function action_button( $op, $value, $label ) {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION ); ?>">
			<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
			<input type="hidden" name="value" value="<?php echo esc_attr( $value ); ?>">
			<?php wp_nonce_field( self::ACTION ); ?>
			<button type="submit" class="button button-small"><?php echo esc_html( $label ); ?></button>
		</form>
		<?php
	}

	/**
	 * Handles admin-post.php?action=pncp_login: unblock an IP, unlock a username.
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$op    = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$value = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
		$msg   = '';
		if ( 'unban_ip' === $op && '' !== $value ) {
			PNCP_Log::unban( $value );
			$norm = PNCP_Ip::normalize( $value );
			// The counter is kept per PNCP_Ip::limit_key() (an IPv6 address counts for its /64 network).
			PNCP_Log::cache_delete( 'pncp_lfi_' . md5( PNCP_Ip::limit_key( '' !== $norm ? $norm : $value ) ) );
			$msg = 'unblocked';
		} elseif ( 'unlock_user' === $op && '' !== $value ) {
			self::unlock_user( $value );
			$msg = 'unlocked';
		}
		$back = wp_get_referer();
		$back = $back ? $back : PNCP_Status::settings_url();
		wp_safe_redirect( add_query_arg( 'pncp_login_msg', $msg, remove_query_arg( 'pncp_login_msg', $back ) ) );
		exit;
	}

	/* ---------- Site Health, WP-CLI, privacy, uninstall ---------- */

	/**
	 * Site Health test.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_test() {
		$s      = self::settings();
		$result = array(
			'label'       => __( 'Failed sign-ins are limited', 'scrapelock' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html__( 'ScrapeLock blocks an IP after repeated wrong passwords on wp-login.php, XML-RPC (each call of a system.multicall) and application passwords, and pauses usernames that are attacked.', 'scrapelock' ) . '</p>',
			'actions'     => '',
			'test'        => 'pncp_login',
		);
		if ( ! self::is_protected() ) {
			$result['status']      = 'recommended';
			$result['label']       = __( 'Failed sign-ins are not limited', 'scrapelock' );
			$result['description'] = '<p>' . esc_html__( 'Bots can try passwords on wp-login.php and XML-RPC without limit. Turn on “Limit failed sign-ins” in ScrapeLock.', 'scrapelock' ) . '</p>';
		} elseif ( defined( 'SCRAPELOCK_LOGIN_SLUG_OFF' ) && SCRAPELOCK_LOGIN_SLUG_OFF && '' !== self::clean_slug( (string) $s['login_slug'] ) ) {
			$result['status']      = 'recommended';
			$result['label']       = __( 'The custom sign-in address is turned off in wp-config.php', 'scrapelock' );
			$result['description'] = '<p>' . esc_html__( 'SCRAPELOCK_LOGIN_SLUG_OFF is set, so wp-login.php is open again. Remove the line from wp-config.php once you can sign in.', 'scrapelock' ) . '</p>';
		}
		return $result;
	}

	/**
	 * WP-CLI: wp scrapelock login <status|unlock|url> [<ip-or-username>].
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cli( $args, $assoc_args = array() ) {
		$sub = isset( $args[0] ) ? (string) $args[0] : 'status';
		if ( 'url' === $sub ) {
			WP_CLI::line( self::login_url() );
			return;
		}
		if ( 'unlock' === $sub ) {
			$what = isset( $args[1] ) ? (string) $args[1] : '';
			if ( '' === $what ) {
				WP_CLI::error( 'Give an IP or a username.' );
			}
			if ( filter_var( $what, FILTER_VALIDATE_IP ) || false !== strpos( $what, '/' ) ) {
				PNCP_Log::unban( $what );
				PNCP_Log::cache_delete( 'pncp_lfi_' . md5( false === strpos( $what, '/' ) ? PNCP_Ip::limit_key( $what ) : $what ) );
				WP_CLI::success( sprintf( 'Unblocked %s.', $what ) );
				return;
			}
			$was = self::unlock_user( $what );
			WP_CLI::success( $was ? sprintf( 'Unlocked %s.', $what ) : sprintf( '%s was not paused (its counter was reset).', $what ) );
			return;
		}
		if ( 'status' !== $sub ) {
			WP_CLI::error( 'Unknown subcommand. Use status, unlock or url.' );
		}
		$st   = self::stats();
		$rows = array(
			array(
				'item'  => 'limit',
				'value' => self::is_protected() ? 'on' : 'off',
			),
			array(
				'item'  => 'monitor_only',
				'value' => PNCP_Options::monitoring() ? 'yes' : 'no',
			),
			array(
				'item'  => 'login_url',
				'value' => self::login_url(),
			),
			array(
				'item'  => 'hides_wp_login',
				'value' => self::hides_login() ? 'yes' : 'no',
			),
			array(
				'item'  => 'failed_today',
				'value' => (string) $st['today'],
			),
			array(
				'item'  => 'failed_7_days',
				'value' => (string) $st['week'],
			),
			array(
				'item'  => 'blocked_ips',
				'value' => implode( ', ', array_keys( $st['ips'] ) ),
			),
			array(
				'item'  => 'paused_usernames',
				'value' => implode( ', ', wp_list_pluck( $st['locks'], 'u' ) ),
			),
		);
		WP_CLI\Utils\format_items( isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table', $rows, array( 'item', 'value' ) );
	}

	/**
	 * Text for the privacy policy.
	 *
	 * @return string
	 */
	public static function privacy_text() {
		return __( 'When a sign-in to this site fails, the IP address and the username or email address that was tried are counted for a few minutes, to block password guessing. An IP that fails too often is blocked for a while. For each account, a keyed hash of the IP addresses it signed in from (not the addresses themselves) is kept for up to 180 days, so that its owner is not locked out by an attack on the account. When an account is paused, its owner is emailed a one-time link; using it sets a cookie that lets that browser sign in for 30 days.', 'scrapelock' );
	}

	/**
	 * Removes what this class stored (uninstall).
	 */
	public static function uninstall() {
		delete_option( self::LOCKS_OPTION );
		delete_metadata( 'user', 0, self::KNOWN_META, '', true );
		delete_metadata( 'user', 0, self::UNLOCK_META, '', true );
	}
}
