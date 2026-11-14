<?php
/**
 * Server-side protection: scrapers and AI bots, fake search engines, per-endpoint limits,
 * temporary IP blocking, a bot trap and robots.txt.
 *
 * Applies only to requests that reach PHP. Pages served from a page cache
 * (Nginx FastCGI, WP Rocket, etc.) do not pass through here: see the server rules in the settings.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Bots, limits and blocks.
 */
final class PNCP_Bots {

	/**
	 * 3.4.3: without an object cache or APCu, the site-wide surge counter is written on 1 page in this many,
	 * adding this many each time (see surge()).
	 *
	 * @var int
	 */
	const SURGE_SAMPLE = 10;

	/**
	 * 3.4.3: without an object cache or APCu, how many new per-IP counter rows wp_options may get per minute,
	 * site-wide (see db_incr_capped()).
	 *
	 * @var int
	 */
	const DB_NEW_KEYS_PER_MINUTE = 2000;

	/**
	 * Verifiable search engines: User-Agent patterns, reverse DNS domains and official IP list.
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private static $crawlers = array(
		'google' => array(
			'ua'   => array( 'googlebot', 'google-inspectiontool', 'storebot-google', 'adsbot-google', 'mediapartners-google', 'googleother', 'feedfetcher-google', 'google-read-aloud', 'apis-google', 'google-site-verification', 'google-safety' ),
			'dns'  => array( '.googlebot.com', '.google.com' ),
			'list' => 'google',
		),
		'bing'   => array(
			'ua'   => array( 'bingbot', 'adidxbot', 'bingpreview', 'msnbot' ),
			'dns'  => array( '.search.msn.com' ),
			'list' => 'bing',
		),
		'apple'  => array(
			'ua'   => array( 'applebot' ),
			'dns'  => array( '.applebot.apple.com' ),
			'list' => '',
		),
		'yandex' => array(
			'ua'   => array( 'yandexbot', 'yandeximages', 'yandexmobilebot', 'yandexmetrika' ),
			'dns'  => array( '.yandex.ru', '.yandex.net', '.yandex.com' ),
			'list' => '',
		),
	);

	/**
	 * Whether the last crawler verification could not reach a verdict (DNS budget used up or
	 * reverse DNS failed). Such a request is refused, but it is not counted as a violation.
	 *
	 * @var bool
	 */
	private static $verify_inconclusive = false;

	/**
	 * Whether this response must not be cached anywhere (set by no_cache()).
	 *
	 * @var bool
	 */
	private static $uncacheable = false;

	/**
	 * Whether this request is a sitemap that sitemap_guard() already checked.
	 *
	 * @var bool
	 */
	private static $sitemap = false;

	/**
	 * A request that is only explained, not acted on (explain(), for "wp scrapelock check"): its IP, User-Agent
	 * and whether it is a feed, and what check() found. Null for every real request, so nothing changes for them.
	 *
	 * @var array<string, mixed>|null
	 */
	private static $dry = null;

	/**
	 * 3.5: seconds after a first trap hit or probe in which another one of the same IP key is part of the same
	 * first burst (first_ban_claim(); PNCP_Precheck_Runtime::BURST for the pre-cache check).
	 */
	const FIRST_BAN_BURST = 10;

	/**
	 * 3.5: is a request only being explained (explain())? Other classes then leave their caches alone: a check
	 * counts, logs, bans and caches nothing.
	 *
	 * @return bool
	 */
	public static function explaining() {
		return null !== self::$dry;
	}

	/**
	 * 3.5: whether a REST dispatch was already checked in this PHP request. WordPress dispatches each _embed
	 * link (and some plugins their own reads, e.g. WooCommerce Admin while the index is built) inside the
	 * visitor's request; only the first dispatch is the visitor's.
	 *
	 * @var bool
	 */
	private static $rest_seen = false;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'trap_guard' ), 0 );
		add_action( 'init', array( __CLASS__, 'sitemap_guard' ), 1 );
		add_action( 'template_redirect', array( __CLASS__, 'probe_guard' ), 11 ); // 3.5: after WordPress's redirects (priority 10).
		add_filter( 'redirect_canonical', array( __CLASS__, 'probe_no_canonical' ), 99 ); // 3.5: see there.
		add_action( 'template_redirect', array( __CLASS__, 'page_guard' ), 0 );
		// Before WooCommerce handles the classic cart forms (wp_loaded, 20) and wc-ajax (template_redirect).
		add_action( 'wp_loaded', array( __CLASS__, 'cart_guard' ), 0 );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'rest_guard' ), 0, 3 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'trap_style' ) );
		add_action( 'wp_footer', array( __CLASS__, 'trap_link' ), 99 );
		add_filter( 'wp_speculation_rules_href_exclude_paths', array( __CLASS__, 'speculation_exclude' ) );
		add_filter( 'robots_txt', array( __CLASS__, 'robots_txt' ), 99, 2 );
		// Blocked User-Agents do not get pages from WP Rocket's cache, so that they reach this point.
		add_filter( 'rocket_cache_reject_ua', array( __CLASS__, 'rocket_reject_ua' ) );
		// Cloudflare plugin (APO): never cache at the edge what must not be cached.
		add_filter( 'cloudflare_use_cache', array( __CLASS__, 'cloudflare_use_cache' ), 99 );
		// Usernames are not given to visitors (?author=N, REST /wp/v2/users, users sitemap, oEmbed).
		add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'sitemaps_provider' ), 10, 2 );
		add_filter( 'oembed_response_data', array( __CLASS__, 'oembed_author' ), 20 );
	}

	/**
	 * Tells the Cloudflare plugin not to cache this response at the edge (APO), when no_cache() was called:
	 * 403 / 429, the trap and the private feeds. The plugin asks on init, after the feeds check.
	 *
	 * @param bool $use_cache Whether the Cloudflare plugin would cache the response.
	 * @return bool
	 */
	public static function cloudflare_use_cache( $use_cache ) {
		return self::$uncacheable ? false : $use_cache;
	}

	/**
	 * The visitor's IP (for compatibility with code that called 1.4).
	 *
	 * @return string
	 */
	public static function client_ip() {
		return PNCP_Ip::client_ip();
	}

	/**
	 * The request User-Agent.
	 *
	 * @return string
	 */
	public static function user_agent() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
	}

	/**
	 * Page views and search.
	 */
	public static function page_guard() {
		if ( is_robots() || is_favicon() || self::$sitemap || self::is_open_path() ) {
			return;
		}
		if ( self::is_author_scan() ) {
			self::not_found(); // Then checked like every page, also toward the "page not found" limit.
		}
		$verdict = self::check( is_search() ? 'search' : 'page' );
		if ( $verdict ) {
			self::die_html( $verdict['code'] );
		}
	}

	/**
	 * robots.txt, llms.txt and llms-full.txt are never blocked: every bot, also a blocked one, must be able to
	 * read the rules it is asked to follow. (robots.txt is also recognised by is_robots(); llms.txt may be a
	 * static file or come from an SEO plugin.)
	 *
	 * @param string|null $path Path relative to the site (null = this request).
	 * @return bool
	 */
	public static function is_open_path( $path = null ) {
		$raw = '';
		if ( null === $path ) {
			$raw  = '/' . ltrim( self::request_path(), '/' );
			$path = PNCP_Private_Urls::relative_path( $raw );
		} else {
			$raw = '/' . ltrim( (string) $path, '/' );
		}
		if ( in_array( strtolower( (string) $path ), self::open_paths(), true ) ) {
			return true;
		}
		// Also match the raw request path directly (independent of the home path / subfolder handling), so a
		// blocked bot can always read robots.txt, llms.txt and the TDM opt-out even if the relative path
		// resolves oddly. These files are only ever served from the domain root.
		return (bool) preg_match( '#^/(?:robots\.txt|llms\.txt|llms-full\.txt|\.well-known/tdmrep\.json)$#i', $raw );
	}

	/**
	 * 3.4.3: the path of this request, decoded (/%CF%84.xml: /τ.xml). Decoded first, then only checked for valid
	 * UTF-8, with control characters taken out: sanitize_text_field() before rawurldecode() removed every %XX
	 * octet, so a percent-encoded path (Greek letters, an encoded dot) was never the path it is compared to.
	 *
	 * @return string
	 */
	public static function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Decoded and cleaned below, only compared against paths.
		$path = wp_check_invalid_utf8( rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) ) );
		return (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $path );
	}

	/**
	 * The paths that are never blocked (see is_open_path()).
	 *
	 * @return string[]
	 */
	public static function open_paths() {
		// /.well-known/tdmrep.json is the opt-out declaration itself: the AI and TDM bots meant to read it
		// must never be blocked from it, exactly like robots.txt.
		return array( '/robots.txt', '/llms.txt', '/llms-full.txt', '/.well-known/tdmrep.json' );
	}

	/**
	 * Sitemaps (WordPress, Rank Math, Yoast, SEOPress…): scrapers read them first to find every page.
	 * Checked on init, because some SEO plugins print the sitemap before template_redirect. Only with a sitemap
	 * limit: with 0 (off) sitemaps are checked as before (the WordPress ones as pages, on template_redirect).
	 */
	public static function sitemap_guard() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || (int) $s['rate_limit_sitemap'] <= 0 || ! self::is_sitemap_request() ) {
			return;
		}
		self::$sitemap = true;
		$verdict       = self::check( 'sitemap' );
		if ( $verdict ) {
			self::die_html( $verdict['code'] );
		}
	}

	/**
	 * Is this a sitemap request? wp-sitemap*.xml, sitemap.xml, sitemap_index.xml, *-sitemap.xml, *-sitemap2.xml,
	 * or ?sitemap= (WordPress without pretty permalinks). The .xsl stylesheets do not count.
	 *
	 * @return bool
	 */
	public static function is_sitemap_request() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only checks that the parameter exists.
		if ( isset( $_GET['sitemap'] ) ) {
			return true;
		}
		$path = PNCP_Private_Urls::relative_path( self::request_path() );
		return (bool) preg_match( '#^/(?:wp-sitemap[a-z0-9_-]*|sitemap(?:_index)?|[a-z0-9_-]+-sitemap[0-9]*)\.xml$#i', $path );
	}

	/**
	 * REST API (/wp-json/): only for read requests from visitors.
	 *
	 * @param mixed           $result  Result (null = continue).
	 * @param WP_REST_Server  $server  Server.
	 * @param WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function rest_guard( $result, $server, $request ) {
		if ( null !== $result || ! $request instanceof WP_REST_Request ) {
			return $result;
		}
		$first           = ! self::$rest_seen; // 3.5: see $rest_seen.
		self::$rest_seen = true;
		if ( self::blocks_user_enum() && preg_match( '#^/wp/v2/users(?:/|$)#i', (string) $request->get_route() ) ) {
			return self::rest_error( new WP_Error( 'rest_user_cannot_view', __( 'Sorry, you are not allowed to list users.', 'scrapelock' ), array( 'status' => rest_authorization_required_code() ) ) );
		}
		$route = (string) $request->get_route();
		// Writes (forms, payment webhooks, other plugins' callbacks) are not checked: they come from servers
		// that send no browser headers. The WooCommerce Store API is the exception: only the shop's own pages
		// call it, and its cart answers carry the product data, so an always-blocked IP, a banned IP or a
		// blocked bot must not add items and read them back with POST. Its writes never count toward a limit.
		$cart = '';
		if ( ! in_array( strtoupper( (string) $request->get_method() ), array( 'GET', 'HEAD' ), true ) ) {
			if ( ! preg_match( '#^/wc/store(?:/v\d+)?/#i', $route ) ) {
				return $result;
			}
			$count = false;
			// Cart and checkout writes have a limit of their own (each one inside a Store API batch is checked
			// on its own too, since WordPress runs this filter for every request of a batch).
			$cart = self::store_api_cart_kind( (string) $request->get_method(), $route );
		} else {
			// Only the transactional Store API routes (cart, checkout, batch) are called from every page and are
			// exempt from the limit. The product catalogue (/wc/store/.../products) is scrapable data and counts
			// toward the REST limit like any other read.
			$count = ! preg_match( '#^/wc/store(?:/v\d+)?/(?:cart|checkout|batch)(?:/|$)#i', $route );
			// 3.5: only the first dispatch of a request counts (and is weighted): the reads WordPress makes for
			// _embed, or another plugin inside the same request, are still checked for blocks and bans but count
			// nothing. Batch requests hold only writes, so this opens no way around the limit.
			if ( ! $first ) {
				$count = false;
			}
		}
		$cost    = $count ? self::rest_cost( $request ) : 1; // 3.5: weighted by list size (see rest_cost()).
		$verdict = self::check( 'rest', $count, $cart, $cost );
		if ( ! $verdict ) {
			return $result;
		}
		// The 403 / 429 must not end up in a REST cache (e.g. LiteSpeed Cache).
		self::no_cache();
		do_action( 'litespeed_control_set_nocache', 'scrapelock' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- LiteSpeed Cache hook.
		$cart_limit = in_array( $verdict['reason'], array( 'rate_cart', 'rate_coupon' ), true );
		// 3.5: every 429 says when the per-minute counters start again, in the header and in the body (retry_after).
		$retry = self::retry_after();
		if ( 429 === $verdict['code'] ) {
			$server->send_header( 'Retry-After', (string) $retry );
		}
		if ( $cart_limit ) {
			$error = new WP_Error(
				'pncp_rate_limited',
				self::cart_message( $verdict['reason'] ),
				array(
					'status'      => 429,
					'retry_after' => $retry,
				)
			);
		} elseif ( 429 === $verdict['code'] ) {
			$error = new WP_Error(
				'pncp_rate_limited',
				__( 'Too many requests. Please try again in a minute.', 'scrapelock' ),
				array(
					'status'      => 429,
					'retry_after' => $retry,
				)
			);
		} else {
			$error = new WP_Error( 'pncp_forbidden', __( 'Access denied.', 'scrapelock' ), array( 'status' => $verdict['code'] ) );
		}
		$response = self::rest_error( $error );
		if ( 429 === $verdict['code'] ) {
			$response->header( 'Retry-After', (string) $retry );
		}
		return $response;
	}

	/**
	 * 3.5: how many units an anonymous REST read counts toward "REST API requests per minute". One
	 * ?per_page=100 answer holds ten times what a default one does, so a list of up to 20 items counts 1, 21-50
	 * counts 2, and more than 50 (or per_page <= 0, "all" in some APIs) counts 3. Single items, other routes and
	 * logged-in users count 1, as before. The route's default per_page is not applied yet at rest_pre_dispatch,
	 * so no per_page is "none" (1); core validates the value only later, so garbage (an array, "abc") counts 1.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return int 1..10
	 */
	public static function rest_cost( $request ) {
		if ( is_user_logged_in() ) {
			return 1; // Authenticated: never weighted, and the filter does not run.
		}
		$per_page = null;
		$cost     = 1;
		$raw = $request->get_param( 'per_page' );
		// 3.5: per_page first, so the registered routes are looked up (is_rest_collection()) only when it is given.
		if ( is_scalar( $raw ) && is_numeric( trim( (string) $raw ) ) && self::is_rest_collection( (string) $request->get_route() ) ) {
			$per_page = (int) ( 0 + trim( (string) $raw ) ); // "1e3" -> 1000; (int) of INF / NAN is 0, so 3.
			$cost     = ( $per_page <= 0 || $per_page > 50 ) ? 3 : ( $per_page > 20 ? 2 : 1 );
		}
		/**
		 * Filter: the units an anonymous REST read counts toward the REST limit (clamped to 1-10, and to the
		 * limit itself, so the first request of a minute always passes).
		 *
		 * @since 3.5.0
		 * @param int             $cost     Units (1 = one request).
		 * @param WP_REST_Request $request  The request.
		 * @param int|null        $per_page The per_page asked for on a collection route (null = none, or not a collection).
		 */
		$cost = (int) apply_filters( 'pncp_rest_cost', $cost, $request, $per_page );
		return max( 1, min( 10, $cost ) );
	}

	/**
	 * 3.5: whether a REST route is a list whose size per_page sets: every top-level wp/v2 collection (posts,
	 * pages, media, comments, terms, search, any post type's rest_base; not users), the WooCommerce Store API
	 * product lists and their term lists (not collection-data, single products, cart, checkout or batch), and
	 * the WooCommerce REST product lists.
	 *
	 * @param string $route Route (e.g. /wp/v2/posts).
	 * @return bool
	 */
	private static function is_rest_collection( $route ) {
		// 3.5: a wp/v2 route only when its GET handler takes per_page (not types, taxonomies, statuses, settings...).
		return ( (bool) preg_match( '#^/wp/v2/(?!users(?:/|$))[a-z0-9_-]+/?$#i', $route ) && self::rest_route_has_per_page( $route ) )
			|| (bool) preg_match( '#^/wc/store(?:/v\d+)?/products(?:/(?:categories|tags|brands|reviews|attributes(?:/\d+/terms)?))?/?$#i', $route )
			|| (bool) preg_match( '#^/wc/v\d+/products(?:/(?:categories|tags|reviews|attributes))?/?$#i', $route );
	}

	/**
	 * 3.5: whether the registered GET handler of a route declares a per_page argument. Only looked up for an
	 * anonymous read of a top-level wp/v2 route that asks for per_page.
	 *
	 * @param string $route Route (e.g. /wp/v2/posts).
	 * @return bool
	 */
	private static function rest_route_has_per_page( $route ) {
		$routes = rest_get_server()->get_routes();
		$route  = untrailingslashit( $route );
		foreach ( array( $route, strtolower( $route ) ) as $key ) {
			if ( ! isset( $routes[ $key ] ) || ! is_array( $routes[ $key ] ) ) {
				continue;
			}
			foreach ( $routes[ $key ] as $handler ) {
				if ( is_array( $handler ) && ! empty( $handler['methods']['GET'] ) && isset( $handler['args']['per_page'] ) ) {
					return true;
				}
			}
			return false;
		}
		return false;
	}

	/**
	 * A REST error as a response object, with the same JSON body and status as the WP_Error. Inside a batch
	 * (Store API /wc/store/v1/batch, /batch/v1) WordPress hands what rest_pre_dispatch returns, unconverted, to
	 * rest_post_dispatch, whose callbacks may only accept a WP_REST_Response: WordPress 7's own connectors
	 * callback stopped such a batch with a fatal error (HTTP 500) when it got a WP_Error.
	 *
	 * @param WP_Error $error Error.
	 * @return WP_REST_Response
	 */
	private static function rest_error( $error ) {
		return rest_convert_error_to_response( $error );
	}

	/**
	 * Which cart limit a write to the WooCommerce Store API counts toward: 'coupon' (a coupon code tried, which
	 * also counts as a cart action), 'cart' (an item added, changed or removed, a coupon removed, an order placed
	 * or paid) or '' (not limited: the customer's address, the shipping rate, extensions' data, the outer batch,
	 * whose requests are checked one by one). The block checkout updates the address and shipping rate as the
	 * shopper types, so those never count.
	 *
	 * @param string $method HTTP method.
	 * @param string $route  REST route, e.g. /wc/store/v1/cart/add-item.
	 * @return string cart | coupon | ''
	 */
	public static function store_api_cart_kind( $method, $route ) {
		$method = strtoupper( (string) $method );
		if ( in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true ) || ! preg_match( '#^/wc/store(?:/v\d+)?/(.+)$#i', (string) $route, $m ) ) {
			return '';
		}
		$path = strtolower( trim( $m[1], '/' ) );
		if ( 'cart/apply-coupon' === $path || ( 'cart/coupons' === $path && 'POST' === $method ) ) {
			return 'coupon';
		}
		if ( in_array( $path, array( 'cart/add-item', 'cart/update-item', 'cart/remove-item', 'cart/remove-coupon' ), true ) || preg_match( '#^cart/(?:items|coupons)(?:/|$)#', $path ) ) {
			return 'cart';
		}
		// Placing the order (POST /checkout) and paying for an existing one (POST /checkout/{id}). PUT /checkout
		// only saves fields while the shopper types: not counted.
		if ( 'POST' === $method && preg_match( '#^checkout(?:/\d+)?$#', $path ) ) {
			return 'cart';
		}
		return '';
	}

	/**
	 * Which cart limit this front-end request counts toward (see store_api_cart_kind()): the wc-ajax cart actions
	 * (add to cart, remove, coupon, place the order) and the classic forms WooCommerce handles on every page
	 * (?add-to-cart=, the cart page coupon form, removing an item, the checkout form sent without JavaScript).
	 * Not the requests a page makes on its own (cart fragments, order review, shipping method).
	 *
	 * @return string cart | coupon | ''
	 */
	public static function front_cart_kind() {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return '';
		}
		$actions = array(
			'add_to_cart'      => 'cart',
			'remove_from_cart' => 'cart',
			'apply_coupon'     => 'coupon',
			'remove_coupon'    => 'cart',
			'checkout'         => 'cart',
		);
		// 3.4.2: the same actions through admin-ajax.php (action=woocommerce_apply_coupon and so on), which
		// WooCommerce still answers for visitors too: a bot that switched to it was not limited at all.
		$admin = self::wc_admin_ajax_action();
		if ( '' !== $admin ) {
			$admin = substr( $admin, strlen( 'woocommerce_' ) );
			return isset( $actions[ $admin ] ) ? $actions[ $admin ] : '';
		}
		// phpcs:disable WordPress.Security.NonceVerification -- Only reads which action this is; WooCommerce checks the nonces.
		$ajax = isset( $_GET['wc-ajax'] ) ? sanitize_key( wp_unslash( $_GET['wc-ajax'] ) ) : '';
		if ( '' !== $ajax ) {
			return isset( $actions[ $ajax ] ) && self::is_wc_ajax() ? $actions[ $ajax ] : '';
		}
		$post = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) );
		// 3.4.2: only the form's "Apply coupon" button tries a code (WooCommerce applies one only then). The cart
		// page's script reloads the cart form right after wc-ajax=apply_coupon with the typed code still in it;
		// that reload (and "Update cart") is not a second coupon attempt.
		if ( $post && isset( $_POST['apply_coupon'] ) ) {
			$kind = 'coupon';
		} elseif ( ! empty( $_REQUEST['add-to-cart'] ) || ! empty( $_GET['remove_item'] ) || ( $post && ( isset( $_POST['update_cart'] ) || isset( $_POST['woocommerce-process-checkout-nonce'] ) ) ) ) {
			$kind = 'cart';
		} else {
			$kind = '';
		}
		// phpcs:enable
		return $kind;
	}

	/**
	 * The cart limits, before WooCommerce adds anything to the cart (its forms run on wp_loaded, wc-ajax on
	 * template_redirect). Every other check runs here as well for these requests, so a blocked bot is refused
	 * before the cart changes; page_guard() checks the page itself afterwards, as before.
	 */
	public static function cart_guard() {
		if ( ( is_admin() && '' === self::wc_admin_ajax_action() ) || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}
		$kind = self::front_cart_kind();
		if ( '' === $kind ) {
			return;
		}
		$verdict = self::check( 'page', false, $kind );
		if ( ! $verdict ) {
			return;
		}
		if ( self::is_wc_ajax() || '' !== self::wc_admin_ajax_action() ) {
			// wc-ajax (and admin-ajax.php) answers JSON: the shop's scripts show the message instead of a broken page.
			self::no_cache();
			$limited = in_array( $verdict['reason'], array( 'rate_cart', 'rate_coupon' ), true );
			$retry   = self::retry_after(); // 3.5: the same value in the header and in the JSON.
			if ( 429 === $verdict['code'] && ! headers_sent() ) {
				header( 'Retry-After: ' . $retry );
			}
			$message = $limited ? self::cart_message( $verdict['reason'] ) : ( 429 === $verdict['code'] ? __( 'Too many requests. Please try again in a minute.', 'scrapelock' ) : __( 'Access denied.', 'scrapelock' ) );
			$body    = array(
				'error'    => true,
				'code'     => 429 === $verdict['code'] ? 'pncp_rate_limited' : 'pncp_forbidden',
				'message'  => $message,
				'messages' => '<ul class="woocommerce-error" role="alert"><li>' . esc_html( $message ) . '</li></ul>',
			);
			if ( 429 === $verdict['code'] ) {
				$body['retry_after'] = $retry; // 3.5: only on a 429; the 403 JSON is unchanged.
			}
			wp_send_json( $body, (int) $verdict['code'] );
		}
		self::die_html( $verdict['code'] );
	}

	/**
	 * Seconds until the per-minute counters start again (for Retry-After).
	 * 3.5: public, for the retry_after field of the GraphQL and human-check 429s.
	 *
	 * @return int
	 */
	public static function retry_after() {
		return max( 1, MINUTE_IN_SECONDS - ( time() % MINUTE_IN_SECONDS ) );
	}

	/**
	 * The message for a request over a cart limit.
	 *
	 * @param string $reason rate_cart | rate_coupon.
	 * @return string
	 */
	private static function cart_message( $reason ) {
		return 'rate_coupon' === $reason
			? __( 'Too many coupon attempts. Please try again in a minute.', 'scrapelock' )
			: __( 'Too many cart requests. Please try again in a minute.', 'scrapelock' );
	}

	/**
	 * The main check.
	 *
	 * Bots, fake search engines and blocks apply to every method (a page can also be served via
	 * POST), and so do the limits. WooCommerce AJAX and the cart / checkout pages do not count; a prefetch has
	 * a larger limit of its own.
	 *
	 * @param string $context page | search | rest | graphql | sitemap.
	 * @param bool   $count   Whether to count toward the limit.
	 * @param string $cart    WooCommerce cart write: 'cart' or 'coupon' counts toward the cart limits ('' = not one).
	 * @param int    $cost    3.5: units this request counts toward the REST / GraphQL limit (1 = one request).
	 * @return array{code:int, reason:string}|null Null if the request passes (always in "Monitor only", see verdict()).
	 */
	public static function check( $context, $count = true, $cart = '', $cost = 1 ) {
		$s = PNCP_Options::get();
		// No exemption for wp_doing_ajax(): WooCommerce defines DOING_AJAX on wc-ajax, so every bot would
		// get through (confirmed with real WooCommerce). On admin-ajax.php only WooCommerce's cart actions get
		// here (cart_guard(), 3.4.2).
		if ( empty( $s['enabled'] ) ) {
			return self::pass( 'off' );
		}
		if ( wp_doing_cron() ) {
			return self::pass( 'cron' );
		}
		// Only the roles in the "Who is exempt" setting are exempt, not every logged-in user: a
		// WooCommerce customer account can be created by anyone. On REST / GraphQL, those who
		// write content are also exempt, because the block editor makes dozens of requests per minute.
		if ( PNCP_Options::user_is_exempt( $s ) || ( in_array( $context, array( 'rest', 'graphql' ), true ) && PNCP_Lockdown::can( 'edit_posts' ) ) ) {
			return self::pass( 'exempt' );
		}
		// robots.txt, llms.txt and the TDM opt-out are never blocked, whatever the bot: a blocked bot must
		// still be able to read the rules it is asked to follow. page_guard already skips them; this is a
		// safety net so no caller of check() can ever return a 403 for them.
		if ( in_array( $context, array( 'page', 'search' ), true ) && self::is_open_path() ) {
			return self::pass( 'open_path' );
		}
		// Every request that gets a page counts, whatever its method and cookies: a "wordpress_logged_in_" or
		// "woocommerce_" cookie name is sent by any script, so an exemption based on it let a single IP scrape
		// without limit (2.8.2 and earlier). Logged-in staff are exempt above, by their verified role. A prefetch
		// has its own, larger limit below.
		// WooCommerce AJAX (cart, checkout): does not count toward the page limit, but bots, fake crawlers and
		// blocks are checked as usual. Only for actions registered by WooCommerce (or an extension of it).
		if ( self::is_wc_ajax() || '' !== self::wc_admin_ajax_action() || ( 'page' === $context && self::is_shop_transaction_page() ) ) {
			$count = false;
		}
		// Private URL (XML feed) with a valid token: the service may use any User-Agent.
		if ( PNCP_Private_Urls::granted() ) {
			return self::pass( 'private_url' );
		}

		// An explained request (explain()) brings its own IP and User-Agent.
		$ua = null !== self::$dry ? (string) self::$dry['ua'] : self::user_agent();
		$ip = null !== self::$dry ? (string) self::$dry['ip'] : PNCP_Ip::client_ip();

		if ( '' === $ip || PNCP_Ip::is_local( $ip ) ) {
			return self::pass( 'local' );
		}
		// Always-allowed IPs: only if the IP cannot be spoofed (not "trust every proxy").
		if ( PNCP_Ip::reliable() && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['allow_ips'] ) ) ) {
			return self::pass( 'allow_ip' );
		}

		/**
		 * Filter to let a request skip all checks.
		 *
		 * @param bool   $skip    Whether the check will be skipped.
		 * @param string $context page | search | rest | graphql.
		 * @param string $ip      IP.
		 */
		if ( apply_filters( 'pncp_skip_guard', false, $context, $ip ) ) {
			return self::pass( 'filter' );
		}

		// A CDN edge (Cloudflare, Bunny) still seen as the visitor: many visitors share that one address, so
		// nothing here is decided per IP (block list, bans, limits, strikes), as in the early check. The checks
		// on the request itself (User-Agent, browser headers) still apply.
		$per_ip = ! PNCP_Ip::is_cdn_edge( $ip );

		// The administrator's lists: always blocked, before everything else.
		if ( $per_ip && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['block_ips'] ) ) ) {
			return self::verdict( 403, 'blocked_ip', $ip );
		}
		if ( self::referrer_blocked( $s ) ) {
			return self::verdict( 403, 'blocked_ref', $ip );
		}

		// Verification first: a real search engine gets through even if someone managed to
		// get its IP blocked. Not for a shared CDN edge: its address is never the crawler's own, so a DNS lookup
		// would only use up the budget, and the real Googlebot behind it must not be refused as a fake one.
		$family = self::claimed_crawler( $ua );
		if ( '' !== $family && $per_ip && self::is_verified_crawler( $family, $ip ) ) {
			return self::pass( 'search_engine' ); // Verified search engines: never blocked, never limited.
		}
		$ai = self::ai_verdict( $ua, $ip, $s );
		if ( 'verified' === $ai ) {
			return self::pass( 'ai_search' ); // Verified AI search bots, as above.
		}

		// With the automatic Emergency Mode on, every page that reaches this point counts toward the site's pages
		// per minute (verified search engines and exempt staff do not), blocked or not: what matters is how hard
		// the site is being hit. One counter write per page, so only when the option is on.
		if ( $count && in_array( $context, array( 'page', 'search' ), true ) && ! empty( $s['auto_emergency'] ) && null === self::$dry ) {
			self::surge( $s );
		}

		if ( ! $per_ip ) {
			$count = false; // No per-IP limits for a shared CDN address (the site-wide surge counter above still counts).
		} elseif ( PNCP_Log::is_banned( $ip ) ) {
			return self::verdict( 403, 'banned', $ip );
		}

		if ( 'fake' === $ai ) {
			self::strike_once_a_minute( $ip, 'fake_ai_bot' );
			return self::verdict( 403, 'fake_ai_bot', $ip );
		}

		if ( '' !== $family && $per_ip && ! empty( $s['block_fake_crawlers'] ) && ! self::$verify_inconclusive ) {
			self::strike_once_a_minute( $ip, 'fake_crawler' );
			return self::verdict( 403, 'fake_crawler', $ip );
		}
		// When verification could not finish (DNS budget used up, a temporary DNS failure, or a shared CDN edge) the request is
		// NOT blocked as a fake crawler: otherwise a flood of fake "Applebot" requests from many IPs could
		// exhaust the shared DNS budget and make the real Applebot / YandexBot get a 403. It falls through to
		// the normal per-minute limits instead, so a real crawler passes and a fake one is still rate-limited.

		$allowed_ua = '' !== $ua && ( self::allow_list_match( $ua, $ip, $s ) || self::ua_in_list( $ua, PNCP_Options::allowed_ai_search() ) );

		if ( ! empty( $s['block_bots'] ) && ! $allowed_ua ) {
			if ( '' === trim( $ua ) && ! empty( $s['block_empty_ua'] ) ) {
				return self::verdict( 403, 'empty_ua', $ip );
			}
			if ( '' !== $ua && self::ua_in_list( $ua, PNCP_Options::blocked_agents( $s ) ) ) {
				return self::verdict( 403, 'bot_ua', $ip );
			}
		}

		// Blocked countries. Link previews and AI search in the allowed lists are not affected (they come from
		// abroad by nature); verified search engines never get here.
		// Country blocking exempts only entries verified by IP (a pinned allow entry or a verified AI search
		// bot), not a User-Agent-only allow match, which anyone can spoof. A legitimate same-country bot is
		// unaffected; to fully exempt one, pin it to its IP range in the allow list (UA@CIDR).
		$country         = '';
		$country_exempt  = $allowed_ua && ( self::allow_list_match_pinned( $ua, $ip, $s ) || self::ua_in_list( $ua, PNCP_Options::allowed_ai_search() ) );
		if ( ! $country_exempt && ( '' !== $s['countries_block'] || '' !== $s['countries_strict'] ) ) {
			$country = PNCP_Geo::country( $ip );
			if ( '' !== $country && in_array( $country, PNCP_Options::parse_countries( $s['countries_block'] ), true ) ) {
				return self::verdict( 403, 'country', $ip );
			}
		}

		// Feeds (RSS / Atom, podcasts) are read by feed readers and podcast apps, which are not browsers: they
		// send no Accept-Language and no browser headers. "Browsers only" and the headless check would refuse
		// every one of them (also in Emergency Mode, which turns both on), so feeds skip these two checks. The
		// bot list, the limits and the other checks still apply to them.
		$feed = 'page' === $context && ( null !== self::$dry ? ! empty( self::$dry['feed'] ) : did_action( 'parse_query' ) && is_feed() );

		// Every browser sends Accept-Language and "Mozilla/" in the User-Agent; most scripts do not.
		// Not on wc-ajax: some payment gateways / extensions call them server-side, without Accept-Language.
		if ( ! empty( $s['require_browser_headers'] ) && ! $allowed_ua && ! $feed && in_array( $context, array( 'page', 'search' ), true ) && ! self::is_wc_ajax() && '' === self::wc_admin_ajax_action() && ! self::looks_like_browser( $ua ) ) {
			return self::verdict( 403, 'no_browser', $ip );
		}

		// Headless and fake browsers: what the browser itself sends does not match the User-Agent.
		// Not for anyone claiming to be a search engine: those are verified (or blocked as fake) above.
		if ( ! empty( $s['block_headless'] ) && ! $allowed_ua && ! $feed && '' === $family && in_array( $context, array( 'page', 'search' ), true ) && ! self::is_wc_ajax() && '' === self::wc_admin_ajax_action() ) {
			$fake = self::fake_browser( $ua );
			if ( '' !== $fake ) {
				return self::verdict( 403, $fake, $ip );
			}
		}

		// WooCommerce cart and checkout writes: a limit of their own, far above what a shopper does, for bots that
		// fill carts, test stolen cards on the checkout or guess coupon codes. They never count toward the page or
		// REST limits. Staff who edit posts or run the shop are never limited here (orders by phone, tests).
		if ( '' !== $cart && $per_ip && ! PNCP_Lockdown::can( 'edit_posts' ) && ! PNCP_Lockdown::can( 'manage_woocommerce' ) ) {
			$buckets = array( 'rate_cart' => (int) $s['rate_limit_cart'] );
			if ( 'coupon' === $cart ) {
				$buckets = array( 'rate_coupon' => (int) $s['rate_limit_coupon'] ) + $buckets;
			}
			foreach ( $buckets as $bucket => $limit ) {
				if ( $limit <= 0 ) {
					continue;
				}
				$current = self::hit( $ip, $bucket );
				if ( $current > $limit ) {
					if ( $current === $limit + 1 ) {
						self::strike( $ip, $bucket );
					}
					return self::verdict( 429, $bucket, $ip );
				}
			}
		}

		$limits = array(
			'page'    => array( 'rate_limit', 'rate_page' ),
			'search'  => array( 'rate_limit_search', 'rate_search' ),
			'rest'    => array( 'rate_limit_rest', 'rate_rest' ),
			'graphql' => array( 'rate_limit_rest', 'rate_rest' ),
			'sitemap' => array( 'rate_limit_sitemap', 'rate_sitemap' ),
		);
		// Prefetch / prerender: a limit of its own, three times the page limit, never a violation. Speed plugins
		// (Flying Pages, instant.page, speculative loading) prefetch many links of each page a visitor reads, so
		// with the page limit a real visitor could be stopped and even banned. Its headers are sent by any script
		// too, so it is not free either (up to 2.8.2 it was not counted at all): a script that sends them gets at
		// most three times the page limit per minute, and the trap and the other checks still apply to it.
		if ( $count && 'page' === $context && self::is_prefetch() ) {
			$limit = 3 * (int) $s['rate_limit'];
			if ( $limit > 0 && self::hit( $ip, 'rate_prefetch' ) > $limit ) {
				return self::verdict( 429, 'rate_prefetch', $ip );
			}
			return self::pass( 'prefetch' );
		}

		// Stricter page limits: visitors without the human-check cookie, and countries in the "stricter" list.
		if ( $count && 'page' === $context ) {
			$stricter = array();
			// Not for the always-allowed User-Agents and the allowed AI search bots: they cannot run the
			// script, so they keep the normal page limit.
			if ( ! empty( $s['human_check'] ) && ! $allowed_ua && (int) $s['rate_limit_unverified'] > 0 && ! PNCP_Human::verified( $ip ) ) {
				$stricter['rate_unverified'] = (int) $s['rate_limit_unverified'];
				if ( null === self::$dry ) {
					PNCP_Human::forget_invalid();
				}
			}
			if ( '' !== $country && (int) $s['rate_limit_country'] > 0 && in_array( $country, PNCP_Options::parse_countries( $s['countries_strict'] ), true ) ) {
				$stricter['rate_country'] = (int) $s['rate_limit_country'];
			}
			// Data centers (AWS, Google Cloud, Oracle, DigitalOcean, Linode): people rarely browse from a server,
			// scrapers very often run on one. Not for the always-allowed User-Agents (monitoring, price platforms).
			// A User-Agent alone ("WhatsApp", "Skroutz") is easy to fake: from a data center it is exempt only when
			// the allow entry is pinned to the service's IPs (UA@CIDR), or it is a verified AI search bot.
			$dc_exempt = $allowed_ua && ( self::allow_list_match_pinned( $ua, $ip, $s ) || self::ua_in_list( $ua, PNCP_Options::allowed_ai_search() ) );
			if ( ! $dc_exempt && (int) $s['rate_limit_datacenter'] > 0 && '' !== PNCP_Ip::datacenter( $ip ) ) {
				$stricter['rate_datacenter'] = (int) $s['rate_limit_datacenter'];
			}
			foreach ( $stricter as $bucket => $limit ) {
				$current = self::hit( $ip, $bucket );
				if ( $current > $limit ) {
					if ( $current === $limit + 1 ) {
						self::strike( $ip, $bucket );
					}
					return self::verdict( 429, $bucket, $ip );
				}
			}
		}
		// Separate limit for "page not found": guessing URLs (?p=1, 2, 3…, old product slugs) to find content.
		// Missing images, CSS and the like do not count; neither do favicon, apple-touch-icon and /.well-known/.
		if ( $count && 'page' === $context && (int) $s['rate_limit_404'] > 0 && is_404() && ! self::is_exempt_404() ) {
			$limit   = (int) $s['rate_limit_404'];
			$current = self::hit( $ip, 'rate_404' );
			if ( $current > $limit ) {
				if ( $current === $limit + 1 ) {
					self::strike( $ip, 'rate_404' );
				}
				return self::verdict( 429, 'rate_404', $ip );
			}
		}
		// IPv6: also the /56 the /64 belongs to, at four times the page limit. One connection or server usually has a
		// whole /56 or /48, so a new /64 for every request would otherwise get past the per-/64 limit. No violation:
		// bans are per /64, and neighbouring phones of a mobile network may share a /56.
		if ( $count && 'page' === $context && ! empty( $s['ipv6_wide'] ) && (int) $s['rate_limit'] > 0 && false !== strpos( $ip, ':' ) ) {
			$wide = PNCP_Ip::limit_key( $ip, 56 );
			if ( PNCP_Ip::limit_key( $ip ) !== $wide && false !== strpos( $wide, '/56' ) && self::hit( $ip, 'rate_page56', $wide ) > 4 * (int) $s['rate_limit'] ) {
				return self::verdict( 429, 'rate_page56', $ip );
			}
		}
		if ( $count && isset( $limits[ $context ] ) ) {
			$limit = (int) $s[ $limits[ $context ][0] ];
			if ( $limit > 0 ) {
				// 3.5: a REST list counts by size (rest_cost()); never more than the limit, so the first request of a minute always passes.
				$units = 'rest' === $context ? max( 1, min( (int) $cost, $limit ) ) : 1;
				$count = self::hit( $ip, $limits[ $context ][1], null, $units );
				if ( $count > $limit ) {
					// One "violation" per minute in which the limit was exceeded, not one per request (3.5: on the
					// request that crossed it; with weighted units the count may jump past limit + 1).
					if ( $count - $units <= $limit ) {
						self::strike( $ip, $limits[ $context ][1] );
					}
					return self::verdict( 429, $limits[ $context ][1], $ip );
				}
			}
		}

		return self::pass( 'passed' );
	}

	/**
	 * A request that passes: null, as before. For an explained request (explain()) it also remembers why.
	 *
	 * @param string $why Why it passes (PNCP_Cli::pass_reasons() lists them).
	 * @return null
	 */
	private static function pass( $why ) {
		if ( null !== self::$dry && ! isset( self::$dry['pass'] ) ) {
			self::$dry['pass'] = $why;
		}
		return null;
	}

	/**
	 * A violation toward the temporary block (PNCP_Log::strike()); none for an explained request.
	 *
	 * @param string $ip     IP.
	 * @param string $reason Reason.
	 */
	private static function strike( $ip, $reason ) {
		if ( null === self::$dry ) {
			PNCP_Log::strike( $ip, $reason );
		}
	}

	/**
	 * What check() would answer to a request with this IP, User-Agent and address, without acting on it: nothing
	 * is counted (the per-minute counters are only read, and this request is added to what they hold), nothing
	 * is logged, no violation or temporary block is added, and no DNS verdict or DNS budget is stored. For
	 * "wp scrapelock check" and, 3.5, the "Check a request" card (PNCP_Tester).
	 *
	 * Taken into account: the settings in effect now (also Emergency Mode), the headers given (e.g.
	 * Accept-Language, Sec-Fetch-Mode, Sec-CH-UA, Referer), the kind of address (page, search, REST API,
	 * GraphQL, sitemap, feed) and HTTPS from the address. Not simulated: the human-check cookie (never present,
	 * as for a script), "page not found" (404), private URL tokens, WooCommerce cart and checkout pages, and the
	 * early and pre-cache checks, which run before WordPress with fewer checks.
	 *
	 * @param string                $ip      IP address.
	 * @param string                $ua      User-Agent ('' = none).
	 * @param string                $url     Address on this site ('' = the home page).
	 * @param array<string, string> $headers More request headers, name => value (e.g. "Accept-Language" => "en").
	 * @return array{context:string, feed:bool, code:int, reason:string, pass:string, monitor:bool, inconclusive:bool}
	 */
	public static function explain( $ip, $ua, $url = '', $headers = array() ) {
		$url    = '' === trim( (string) $url ) ? home_url( '/' ) : (string) $url;
		$parts  = wp_parse_url( $url );
		$parts  = is_array( $parts ) ? $parts : array();
		$path   = isset( $parts['path'] ) ? (string) $parts['path'] : '/';
		$query  = isset( $parts['query'] ) ? (string) $parts['query'] : '';
		$scheme = isset( $parts['scheme'] ) ? strtolower( (string) $parts['scheme'] ) : (string) wp_parse_url( home_url(), PHP_URL_SCHEME );
		$args   = array();
		wp_parse_str( $query, $args );

		// The request as the checks read it: the given headers, every other one absent.
		$server = array(
			'HTTP_USER_AGENT'      => (string) $ua,
			'REQUEST_URI'          => $path . ( '' !== $query ? '?' . $query : '' ),
			'HTTPS'                => 'https' === $scheme ? 'on' : null,
			'HTTP_ACCEPT_LANGUAGE' => null,
			'HTTP_REFERER'         => null,
			'HTTP_SEC_FETCH_MODE'  => null,
			'HTTP_SEC_FETCH_DEST'  => null,
			'HTTP_SEC_CH_UA'       => null,
			'HTTP_SEC_PURPOSE'     => null,
			'HTTP_PURPOSE'         => null,
			'HTTP_X_MOZ'           => null,
			'HTTP_X_PURPOSE'       => null,
			// 3.5: the admin's own country from the CDN edge (admin-ajax behind Cloudflare / Bunny) must not be
			// taken as the country of the IP checked: without them the country database decides.
			'HTTP_CF_IPCOUNTRY'           => null,
			'HTTP_CDN_REQUESTCOUNTRYCODE' => null,
		);
		foreach ( (array) $headers as $name => $value ) {
			$key = 'HTTP_' . strtoupper( str_replace( '-', '_', trim( (string) $name ) ) );
			if ( preg_match( '/^HTTP_[A-Z0-9_]+$/', $key ) ) {
				$server[ $key ] = (string) $value;
			}
		}
		$saved = array();
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- Only kept and put back exactly as they were.
		foreach ( $server as $key => $value ) {
			$saved[ $key ] = isset( $_SERVER[ $key ] ) ? $_SERVER[ $key ] : null;
			if ( null === $value ) {
				unset( $_SERVER[ $key ] );
			} else {
				$_SERVER[ $key ] = $value;
			}
		}
		// phpcs:enable

		$relative = strtolower( PNCP_Private_Urls::relative_path( rawurldecode( $path ) ) );
		$feed     = isset( $args['feed'] ) || (bool) preg_match( '#/feed(?:/[a-z0-9_-]*)?/?$#', $relative );
		$s        = PNCP_Options::get();
		if ( 0 === strpos( $relative, '/' . rest_get_url_prefix() . '/' ) || isset( $args['rest_route'] ) ) {
			$context = 'rest';
		} elseif ( '/graphql' === untrailingslashit( $relative ) ) {
			$context = 'graphql';
		} elseif ( (int) $s['rate_limit_sitemap'] > 0 && ( isset( $args['sitemap'] ) || self::is_sitemap_request() ) ) {
			$context = 'sitemap';
		} elseif ( isset( $args['s'] ) ) {
			$context = 'search';
		} else {
			$context = 'page';
		}

		// 3.5: a stale flag of an earlier verification in this PHP request must not leak into this one.
		self::$verify_inconclusive = false;
		self::$dry                 = array(
			'ip'   => (string) $ip,
			'ua'   => (string) $ua,
			'feed' => $feed,
		);
		// 3.5: a REST list counts by size, as rest_guard() counts it (rest_cost(); the caller is logged out).
		$cost = 'rest' === $context ? self::explain_rest_cost( $relative, $args ) : 1;
		PNCP_Geo::reset(); // 3.5: no country cached earlier in this PHP request (e.g. the admin's own IP).
		try {
			$verdict      = self::check( $context, true, '', $cost );
			$dry          = self::$dry;
			$inconclusive = self::$verify_inconclusive;
		} finally {
			self::$dry = null;
			PNCP_Geo::reset();
			foreach ( $saved as $key => $value ) {
				if ( null === $value ) {
					unset( $_SERVER[ $key ] );
				} else {
					$_SERVER[ $key ] = $value; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Put back as it was.
				}
			}
		}
		return array(
			'context'      => $context,
			'feed'         => $feed,
			'code'         => $verdict ? (int) $verdict['code'] : 0,
			'reason'       => $verdict ? (string) $verdict['reason'] : '',
			'pass'         => $verdict ? '' : ( isset( $dry['pass'] ) ? (string) $dry['pass'] : 'passed' ),
			// In "Monitor only" a real request with this verdict is let through and logged as "Would block".
			'monitor'      => $verdict && PNCP_Options::monitoring(),
			// 3.5: for the "Check a request" card: a claimed search engine whose DNS check could not finish.
			'inconclusive' => $inconclusive,
		);
	}

	/**
	 * 3.5: the units a REST read of explain() counts (rest_cost()), from the address: the route of ?rest_route=
	 * or the path after the REST prefix, and the query arguments.
	 *
	 * @param string               $relative Path relative to home, decoded and lowercase.
	 * @param array<string, mixed> $args     Query arguments.
	 * @return int
	 */
	private static function explain_rest_cost( $relative, $args ) {
		if ( isset( $args['rest_route'] ) && is_string( $args['rest_route'] ) ) {
			$route = $args['rest_route'];
		} else {
			$route = (string) substr( $relative, strlen( '/' . rest_get_url_prefix() ) );
		}
		$route = '/' . ltrim( $route, '/' );
		unset( $args['rest_route'] );
		$request = new WP_REST_Request( 'GET', $route );
		$request->set_query_params( $args );
		return self::rest_cost( $request );
	}

	/**
	 * AI search bots and assistants that publish their IPs: User-Agent => list (PNCP_Ip::sources()).
	 *
	 * @return array<string, string>
	 */
	public static function ai_bot_lists() {
		return array(
			'OAI-SearchBot'    => 'openai_search',
			'ChatGPT-User'     => 'openai_user',
			'PerplexityBot'    => 'perplexity_bot',
			'Perplexity-User'  => 'perplexity_user',
			// Anthropic publishes one list for all its bots (since 2.6.2).
			'Claude-SearchBot' => 'anthropic',
			'Claude-User'      => 'anthropic',
		);
	}

	/**
	 * Is a request that says it is an AI search bot real? Only for the bots the site allows ("Allow AI search")
	 * with "Verify AI search bots" on, and only once their official list has been downloaded: otherwise
	 * nothing changes and the bot list decides, as before.
	 *
	 * @param string               $ua User-Agent.
	 * @param string               $ip IP.
	 * @param array<string, mixed> $s  Settings.
	 * @return string verified | fake | '' (not checked).
	 */
	public static function ai_verdict( $ua, $ip, $s ) {
		if ( empty( $s['verify_ai_bots'] ) || '' === $ua || '' === $ip ) {
			return '';
		}
		foreach ( self::ai_bot_lists() as $agent => $list ) {
			if ( false === stripos( $ua, $agent ) ) {
				continue;
			}
			if ( ! self::ua_in_list( $ua, PNCP_Options::allowed_ai_search() ) ) {
				return '';
			}
			$ranges = PNCP_Ip::list_of( $list );
			if ( ! $ranges ) {
				return '';
			}
			return PNCP_Ip::in_any( $ip, $ranges ) ? 'verified' : 'fake';
		}
		return '';
	}

	/**
	 * A 404 that does not count toward the "page not found" limit: static files (a missing image or
	 * script is the site's problem, not the visitor's) and paths browsers ask for by themselves.
	 * Filter `pncp_404_exempt`.
	 *
	 * @return bool
	 */
	public static function is_exempt_404() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = strtolower( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		$home = strtolower( rtrim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' ) );
		if ( '' !== $home && 0 === strpos( $path, $home . '/' ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		$exempt = (bool) preg_match( '#\.(?:css|js|mjs|map|json|png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|zip|gz|txt|xml)$#', $path )
			|| (bool) preg_match( '#^/(?:favicon|apple-touch-icon|android-chrome|mstile|browserconfig|site\.webmanifest|manifest\.json|ads\.txt|app-ads\.txt|\.well-known/)#', $path )
			// 3.4.3: a WooCommerce Store API address that a script of the shop built wrong. WooCommerce 11.2 asks
			// /cart/undefinedwc/store/v1/cart after every change in the block cart (Mini-Cart in a block theme):
			// in Emergency Mode (10 a minute, block after 2 violations) that banned real shoppers for hours.
			|| false !== strpos( $path, 'wc/store/' )
			|| self::same_origin_fetch();
		return (bool) apply_filters( 'pncp_404_exempt', $exempt, $path );
	}

	/**
	 * 3.4.3: a request made by a script of the site itself (fetch / XMLHttpRequest), as the browser marks it:
	 * Sec-Fetch-Site same-origin and a Sec-Fetch-Dest other than a page. A 404 from it is a broken script of a
	 * theme or plugin, not someone guessing addresses. Only the 404 limit skips it (the headers can be faked):
	 * the request still counts towards the page limit.
	 *
	 * @return bool
	 */
	private static function same_origin_fetch() {
		$site = isset( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ? strtolower( sanitize_key( wp_unslash( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ) ) : '';
		$dest = isset( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ? strtolower( sanitize_key( wp_unslash( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ) ) : '';
		return 'same-origin' === $site && '' !== $dest && ! in_array( $dest, array( 'document', 'iframe', 'frame', 'embed', 'object' ), true );
	}

	/**
	 * Does the Referer belong to a domain in the "always blocked" list? An entry also covers its subdomains
	 * (example.com: also www.example.com). Hotlinking scraper sites and their proxies send their own domain.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return bool
	 */
	public static function referrer_blocked( $s ) {
		$list = PNCP_Options::parse_list( $s['block_referrers'] );
		if ( ! $list || empty( $_SERVER['HTTP_REFERER'] ) ) {
			return false;
		}
		$host = strtolower( (string) wp_parse_url( sanitize_text_field( wp_unslash( $_SERVER['HTTP_REFERER'] ) ), PHP_URL_HOST ) );
		if ( '' === $host ) {
			return false;
		}
		foreach ( $list as $entry ) {
			$entry = strtolower( trim( $entry ) );
			if ( false !== strpos( $entry, '/' ) ) {
				$entry = (string) wp_parse_url( false === strpos( $entry, '://' ) ? 'http://' . $entry : $entry, PHP_URL_HOST );
			}
			$entry = ltrim( $entry, '*.' );
			if ( '' !== $entry && ( $host === $entry || substr( $host, -strlen( $entry ) - 1 ) === '.' . $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/* ---------- Usernames ---------- */

	/**
	 * Is "Hide usernames" on for this request? Not for logged-in users, so the editor and wp-admin work.
	 *
	 * @return bool
	 */
	public static function blocks_user_enum() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && ! empty( $s['block_user_enum'] ) && ! is_user_logged_in();
	}

	/**
	 * ?author=1, 2, 3… redirects to /author/username/: the usual way to collect the site's usernames.
	 *
	 * @return bool
	 */
	public static function is_author_scan() {
		// 3.4.3: WordPress also takes the query var from POST (before GET), and turns any value with a digit in it
		// ("+1", "x1") into an author archive that shows the username (body class, author feed link): only
		// "?author=1" was caught, so "POST author=1" or "?author=%2B1" still listed the usernames.
		// phpcs:disable WordPress.Security.NonceVerification -- Read-only check of a public parameter.
		if ( isset( $_POST['author'] ) ) {
			$author = sanitize_text_field( wp_unslash( $_POST['author'] ) );
		} else {
			$author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : '';
		}
		// phpcs:enable
		return '' !== $author && ! is_admin() && preg_match( '/\d/', $author ) && self::blocks_user_enum();
	}

	/**
	 * Turns the request into a normal 404 page of the theme, without the redirect to /author/username/.
	 */
	private static function not_found() {
		global $wp_query;
		remove_action( 'template_redirect', 'redirect_canonical' );
		if ( $wp_query instanceof WP_Query ) {
			$wp_query->set_404();
		}
		status_header( 404 );
		nocache_headers();
	}

	/**
	 * oEmbed (/wp-json/oembed/1.0/embed?url=…) gives the author's /author/username/ address and display name,
	 * which is the username unless it was changed: one request per post collects them. With usernames
	 * hidden, visitors get what WordPress gives for a post without an author: the site's name and address.
	 *
	 * @param array<string, mixed> $data oEmbed response data.
	 * @return array<string, mixed>
	 */
	public static function oembed_author( $data ) {
		if ( is_array( $data ) && self::blocks_user_enum() ) {
			$data['author_name'] = get_bloginfo( 'name' );
			$data['author_url']  = get_home_url();
		}
		return $data;
	}

	/**
	 * Removes the users sitemap (wp-sitemap-users-1.xml) when usernames are hidden.
	 *
	 * @param WP_Sitemaps_Provider|false $provider Provider.
	 * @param string                     $name     Provider name.
	 * @return WP_Sitemaps_Provider|false
	 */
	public static function sitemaps_provider( $provider, $name ) {
		if ( 'users' !== $name ) {
			return $provider;
		}
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && ! empty( $s['block_user_enum'] ) ? false : $provider;
	}

	/**
	 * Logs and returns the decision.
	 *
	 * In "Monitor only" (PNCP_Options::monitoring()) the verdict is logged as "would block" and the request
	 * passes: every caller of check() then simply carries on, as for a request that passed. The violations
	 * that lead to a ban are not counted either (PNCP_Log::strike()).
	 *
	 * @param int    $code   HTTP status code.
	 * @param string $reason Reason.
	 * @param string $ip     IP.
	 * @return array{code:int, reason:string}|null Null in "Monitor only".
	 */
	private static function verdict( $code, $reason, $ip ) {
		if ( null !== self::$dry ) {
			// Explained, not acted on: the verdict as it is (explain() adds what "Monitor only" would do), no log.
			return array(
				'code'   => $code,
				'reason' => $reason,
			);
		}
		if ( PNCP_Options::monitoring() ) {
			PNCP_Log::add( $reason, PNCP_Log::MONITOR_CODE, $ip );
			return null;
		}
		PNCP_Log::add( $reason, $code, $ip );
		return array(
			'code'   => $code,
			'reason' => $reason,
		);
	}

	/**
	 * Is it a real wc-ajax request? WooCommerce must be active and the action registered
	 * (`wc_ajax_{action}`), otherwise a bare ?wc-ajax=x in the URL would be enough.
	 *
	 * @return bool
	 */
	public static function is_wc_ajax() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only the action name.
		$action = isset( $_GET['wc-ajax'] ) ? sanitize_key( wp_unslash( $_GET['wc-ajax'] ) ) : '';
		return '' !== $action && class_exists( 'WooCommerce' ) && has_action( 'wc_ajax_' . $action );
	}

	/**
	 * The WooCommerce cart action of an admin-ajax.php request (3.4.2): woocommerce_apply_coupon,
	 * woocommerce_remove_coupon, woocommerce_add_to_cart, woocommerce_remove_from_cart or woocommerce_checkout,
	 * only when WooCommerce (or an extension) has registered it, as with is_wc_ajax().
	 *
	 * @return string The action, or '' when this is not one.
	 */
	public static function wc_admin_ajax_action() {
		if ( ! wp_doing_ajax() || ! is_admin() || ! class_exists( 'WooCommerce' ) ) {
			return '';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only the action name; WooCommerce checks the nonce.
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		$known  = array( 'woocommerce_add_to_cart', 'woocommerce_remove_from_cart', 'woocommerce_apply_coupon', 'woocommerce_remove_coupon', 'woocommerce_checkout' );
		if ( ! in_array( $action, $known, true ) || ( ! has_action( 'wp_ajax_nopriv_' . $action ) && ! has_action( 'wp_ajax_' . $action ) ) ) {
			return '';
		}
		return $action;
	}

	/**
	 * WooCommerce transaction page (cart, checkout, "Thank you", "My account"). Does not count
	 * toward the page limit: a customer making a purchase opens 4–5 such pages within a minute.
	 * Bots and blocks are checked as usual.
	 *
	 * @return bool
	 */
	public static function is_shop_transaction_page() {
		if ( ! function_exists( 'is_cart' ) || ! did_action( 'wp' ) ) {
			return false;
		}
		// Not plain is_wc_endpoint_url(): it is true for any URL with ?orders=1 etc., so it would disable the limit everywhere.
		// The "Thank you" page and account pages are covered by is_checkout() / is_account_page().
		return is_cart() || is_checkout() || is_account_page();
	}

	/**
	 * Prefetch / prerender (browser, extension or speculative loading). It has its own page limit (check())
	 * and does not get a visitor banned by the trap. Every header here can be sent by a script, so it is never
	 * a reason to skip the limits altogether.
	 *
	 * @return bool
	 */
	public static function is_prefetch() {
		if ( empty( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ) {
			return false;
		}
		foreach ( array( 'HTTP_SEC_PURPOSE', 'HTTP_PURPOSE', 'HTTP_X_MOZ', 'HTTP_X_PURPOSE' ) as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) && false !== stripos( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ), 'prefetch' ) ) {
				return true;
			}
		}
		return ! empty( $_SERVER['HTTP_SEC_PURPOSE'] ) && false !== stripos( sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_PURPOSE'] ) ), 'prerender' );
	}

	/**
	 * Does it look like a browser?
	 *
	 * @param string $ua User-Agent.
	 * @return bool
	 */
	private static function looks_like_browser( $ua ) {
		$lang = isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ) : '';
		return '' !== trim( $lang ) && 0 === strpos( $ua, 'Mozilla/' );
	}

	/**
	 * A headless or fake browser? Only signals a real browser never gives:
	 * - headless: Chrome without a window says so in its client hints (Sec-CH-UA: "HeadlessChrome"), even
	 *   when the script changed the User-Agent.
	 * - fake_browser: on HTTPS, Chrome / Edge / Opera from version 90 always send Sec-Fetch-Mode and Sec-CH-UA, and
	 *   Firefox from version 90 Sec-Fetch-Mode. A script that only copies their User-Agent sends neither.
	 *   Android WebView (in-app browsers) and plain HTTP are not checked, because there the headers may be missing.
	 *
	 * @param string $ua User-Agent.
	 * @return string headless | fake_browser | '' (nothing found).
	 */
	public static function fake_browser( $ua ) {
		$hints = isset( $_SERVER['HTTP_SEC_CH_UA'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_CH_UA'] ) ) : '';
		if ( false !== stripos( $hints, 'HeadlessChrome' ) ) {
			return 'headless';
		}
		if ( ! is_ssl() || false !== strpos( $ua, '; wv)' ) || ! empty( $_SERVER['HTTP_SEC_FETCH_MODE'] ) ) {
			return '';
		}
		if ( preg_match( '#\b(?:Chrome|Chromium)/(\d+)#', $ua, $m ) ) {
			return (int) $m[1] >= 90 && '' === $hints ? 'fake_browser' : '';
		}
		if ( preg_match( '#\bFirefox/(\d+)#', $ua, $m ) ) {
			return (int) $m[1] >= 90 ? 'fake_browser' : '';
		}
		return '';
	}

	/**
	 * Does the User-Agent match any item in the list? (substring, case-insensitive). An item that starts with
	 * "=" must be the whole User-Agent: "=node" is what Node.js fetch() sends, but "node" alone would also match
	 * longer names.
	 *
	 * @param string   $ua   User-Agent.
	 * @param string[] $needles List.
	 * @return bool
	 */
	public static function ua_in_list( $ua, $needles ) {
		foreach ( $needles as $needle ) {
			$needle = (string) $needle;
			if ( '' === $needle || '=' === $needle ) {
				continue;
			}
			if ( '=' === $needle[0] ? 0 === strcasecmp( trim( $ua ), substr( $needle, 1 ) ) : false !== stripos( $ua, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Does the request match an "always allowed" entry? An entry tied to IPs ("Skroutz@203.0.113.0/24")
	 * counts only from those IPs, and only when the IP cannot be spoofed (not "trust every proxy").
	 *
	 * @param string               $ua User-Agent.
	 * @param string               $ip IP.
	 * @param array<string, mixed> $s  Settings.
	 * @return bool
	 */
	public static function allow_list_match( $ua, $ip, $s ) {
		foreach ( PNCP_Options::parse_list( $s['allow_list'] ) as $entry ) {
			$entry = PNCP_Options::split_allow_entry( $entry );
			if ( '' === $entry['ua'] || false === stripos( $ua, $entry['ua'] ) ) {
				continue;
			}
			if ( ! $entry['pinned'] || ( PNCP_Ip::reliable() && PNCP_Ip::in_any( $ip, $entry['ips'] ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Like allow_list_match(), but true only for an entry pinned to an IP range (UA@CIDR) that the request's
	 * IP matches. A User-Agent-only entry can be spoofed by anyone, so it earns the bot-list / headless
	 * bypass but not a pass from country blocking; a pinned entry is verified by IP and is fully exempt.
	 *
	 * @param string               $ua User-Agent.
	 * @param string               $ip IP.
	 * @param array<string, mixed> $s  Settings.
	 * @return bool
	 */
	public static function allow_list_match_pinned( $ua, $ip, $s ) {
		foreach ( PNCP_Options::parse_list( $s['allow_list'] ) as $entry ) {
			$entry = PNCP_Options::split_allow_entry( $entry );
			if ( '' === $entry['ua'] || false === stripos( $ua, $entry['ua'] ) ) {
				continue;
			}
			if ( $entry['pinned'] && PNCP_Ip::reliable() && PNCP_Ip::in_any( $ip, $entry['ips'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The search engines: family => User-Agents, DNS domains and official IP list ('' = none).
	 *
	 * @return array<string, array{ua:string[], dns:string[], list:string}>
	 */
	public static function crawler_families() {
		return self::$crawlers;
	}

	/**
	 * Which search engine the User-Agent claims to be ('' = none).
	 *
	 * @param string $ua User-Agent.
	 * @return string
	 */
	public static function claimed_crawler( $ua ) {
		foreach ( self::$crawlers as $family => $def ) {
			if ( self::ua_in_list( $ua, $def['ua'] ) ) {
				return $family;
			}
		}
		return '';
	}

	/**
	 * Is it a real search engine? First the official IP list (Google, Bing), then reverse DNS
	 * and forward DNS, which must return the same IP. Positive result cached 24 hours, negative 1 hour,
	 * failed reverse DNS 5 minutes. Without a verdict (DNS budget used up, reverse DNS failed) it returns
	 * false and the request is refused, but not counted as a violation.
	 * 3.4.3: for Google and Bing, once their list is loaded, an IP outside it with no PTR record is a verdict
	 * ("no"), not a failed lookup.
	 *
	 * @param string $family google | bing | apple | yandex.
	 * @param string $ip     IP.
	 * @return bool
	 */
	public static function is_verified_crawler( $family, $ip ) {
		self::$verify_inconclusive = false;
		if ( ! isset( self::$crawlers[ $family ] ) || '' === $ip ) {
			return false;
		}
		$def = self::$crawlers[ $family ];
		if ( '' !== $def['list'] && PNCP_Ip::in_any( $ip, PNCP_Ip::list_of( $def['list'] ) ) ) {
			return true;
		}

		$key    = 'pncp_se_' . md5( $family . '|' . $ip );
		$cached = PNCP_Log::cache_get( $key );
		if ( false !== $cached ) {
			self::$verify_inconclusive = 'unknown' === $cached;
			return 'yes' === $cached;
		}

		// DNS blocks the PHP worker: up to 20 checks per minute, per crawler family (a separate budget each,
		// so a flood of one fake family cannot starve verification of another). Beyond that, treated as
		// unverified (Google and Bing are already verified via the IP lists, without DNS).
		$budget = 'pncp_dns_' . $family . '_' . (int) floor( time() / MINUTE_IN_SECONDS );
		$used   = (int) PNCP_Log::cache_get( $budget );
		if ( $used >= (int) apply_filters( 'pncp_dns_lookups_per_minute', 20 ) ) {
			self::$verify_inconclusive = true;
			return false;
		}
		// An explained request (explain()) looks the name up, but stores nothing: no budget, no verdict.
		$store = null === self::$dry;
		if ( $store ) {
			PNCP_Log::cache_set( $budget, $used + 1, 2 * MINUTE_IN_SECONDS );
		}

		// 3.4.3: a family with an official IP list that is loaded (Google: its crawlers, special crawlers and
		// user-triggered fetchers, all three in one list; Bing) has every real crawler IP on it. An IP outside the
		// list whose reverse DNS answers "no such name" is then a fake, not a "perhaps": before, a fake Googlebot
		// from a server without a PTR record was never blocked, never banned by the trap. Only a real DNS failure
		// (timeout, server error) stays inconclusive; so does a family without a list, or a list not loaded yet.
		$listed   = '' !== $def['list'] && array() !== PNCP_Ip::list_of( $def['list'] );
		$verified = false;
		$pre      = apply_filters( 'pncp_reverse_dns', null, $ip ); // 3.4.3: false = "no PTR record" (a definite answer).
		$host     = is_string( $pre ) ? $pre : '';
		if ( false === $pre ) {
			$host = null;
		} elseif ( '' === $host ) {
			$host = $listed ? self::reverse_dns( $ip ) : (string) gethostbyaddr( $ip );
		}
		if ( null === $host && $listed ) {
			// 3.4.3: no PTR record at all, and not on the official list: fake (cached like any "no", 1 hour).
			if ( $store ) {
				PNCP_Log::cache_set( $key, 'no', HOUR_IN_SECONDS );
			}
			return false;
		}
		if ( null === $host || '' === $host || $host === $ip ) {
			// No PTR record or DNS failure: perhaps temporary, so it is retried in 5 minutes.
			self::$verify_inconclusive = true;
			if ( $store ) {
				PNCP_Log::cache_set( $key, 'unknown', 5 * MINUTE_IN_SECONDS );
			}
			return false;
		}
		$host_lc = strtolower( rtrim( $host, '.' ) );
		foreach ( $def['dns'] as $domain ) {
			if ( substr( $host_lc, -strlen( $domain ) ) === $domain ) {
				$forward = self::forward_ips( $host_lc );
				if ( null === $forward ) {
					// The name is right but its forward lookup failed (timeout, resolver hiccup): not a verdict.
					// Retried in 5 minutes, and the request is not counted as a fake crawler meanwhile.
					self::$verify_inconclusive = true;
					if ( $store ) {
						PNCP_Log::cache_set( $key, 'unknown', 5 * MINUTE_IN_SECONDS );
					}
					return false;
				}
				$verified = in_array( PNCP_Ip::normalize( $ip ), $forward, true );
				break;
			}
		}

		if ( $store ) {
			PNCP_Log::cache_set( $key, $verified ? 'yes' : 'no', $verified ? DAY_IN_SECONDS : HOUR_IN_SECONDS );
		}
		return $verified;
	}

	/**
	 * 3.4.3: reverse DNS that tells "no PTR record" apart from a failed lookup (gethostbyaddr() returns the IP
	 * for both). Used only for the families with an official IP list, where "no PTR" is a verdict.
	 *
	 * @param string $ip IP.
	 * @return string|null The hostname; null when DNS answered that there is no PTR record; '' when the lookup
	 *                     failed (timeout, server error), which is no verdict.
	 */
	private static function reverse_dns( $ip ) {
		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid IP = no lookup.
		if ( false === $packed ) {
			return '';
		}
		if ( 4 === strlen( $packed ) ) {
			$name = implode( '.', array_reverse( explode( '.', $ip ) ) ) . '.in-addr.arpa';
		} else {
			$name = implode( '.', array_reverse( str_split( bin2hex( $packed ) ) ) ) . '.ip6.arpa';
		}
		// dns_get_record() returns false on a failed lookup, and an empty array for NXDOMAIN / no data.
		$records = @dns_get_record( $name, DNS_PTR ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- DNS failure = no verdict.
		if ( false === $records ) {
			return '';
		}
		foreach ( (array) $records as $record ) {
			if ( ! empty( $record['target'] ) ) {
				return (string) $record['target'];
			}
		}
		return null;
	}

	/**
	 * Is the IP in Google's or Bing's official lists? (such IPs are never blocked)
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_official_crawler_ip( $ip ) {
		return PNCP_Ip::in_any( $ip, PNCP_Ip::list_of( 'google' ) ) || PNCP_Ip::in_any( $ip, PNCP_Ip::list_of( 'bing' ) );
	}

	/**
	 * The IPv4/IPv6 addresses of a hostname.
	 *
	 * @param string $host Hostname.
	 * @return string[]|null The addresses (normalised), or null when the lookup failed or returned nothing.
	 */
	private static function forward_ips( $host ) {
		$pre = apply_filters( 'pncp_forward_dns', null, $host );
		if ( is_array( $pre ) ) {
			return array_values( array_filter( array_map( array( 'PNCP_Ip', 'normalize' ), $pre ) ) );
		}
		$ips     = array();
		$records = @dns_get_record( $host, DNS_A | DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- DNS failure = no verdict.
		if ( is_array( $records ) ) {
			foreach ( $records as $record ) {
				foreach ( array( 'ip', 'ipv6' ) as $field ) {
					$ip = ! empty( $record[ $field ] ) ? PNCP_Ip::normalize( (string) $record[ $field ] ) : '';
					if ( '' !== $ip ) {
						$ips[] = $ip;
					}
				}
			}
		}
		// A real crawler's hostname always has an address: an empty answer is a failed lookup, not proof.
		return $ips ? $ips : null;
	}

	/**
	 * A violation for a request that is refused on every try (fake crawler, fake AI bot): counted at most once
	 * per minute per IP, like the rate limits, so a few requests in a row are not already a ban.
	 *
	 * @param string $ip     IP.
	 * @param string $reason Reason.
	 */
	private static function strike_once_a_minute( $ip, $reason ) {
		if ( null !== self::$dry ) {
			return; // Explained, not acted on.
		}
		$key = 'pncp_sk_' . md5( $reason . '|' . PNCP_Ip::limit_key( $ip ) . '|' . (int) floor( time() / MINUTE_IN_SECONDS ) );
		// 3.4.3: an atomic add, so parallel requests of the same minute cannot both count.
		if ( ! PNCP_Log::cache_add( $key, 1, 2 * MINUTE_IN_SECONDS ) ) {
			return;
		}
		PNCP_Log::strike( $ip, $reason );
	}

	/**
	 * Counts the IP's requests in the current minute, per type (IPv6: per /64, see PNCP_Ip::limit_key()).
	 * Object cache if available, otherwise a transient.
	 *
	 * @param string      $ip     IP.
	 * @param string      $bucket Type (rate_page, rate_search, rate_rest).
	 * @param string|null $net    Key to count under instead of the IP's own (e.g. its IPv6 /56).
	 * @param int         $step   3.5: how much to add, in every backend (REST cost; the sampled surge counter, see surge()).
	 * @return int
	 */
	private static function hit( $ip, $bucket, $net = null, $step = 1 ) {
		$net    = null === $net ? PNCP_Ip::limit_key( $ip ) : $net;
		$minute = (int) floor( time() / MINUTE_IN_SECONDS );
		$step   = max( 1, (int) $step );
		if ( null !== self::$dry ) {
			// Explained, not counted: what the counter holds, plus this request.
			return self::peek( $bucket, $net, $minute ) + $step;
		}
		$key = self::counter_key( $bucket, $net, $minute );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_add( $key, 0, 'pncp', 2 * MINUTE_IN_SECONDS );
			return (int) wp_cache_incr( $key, $step, 'pncp' );
		}
		if ( PNCP_Log::apcu_ok() ) {
			// Shared memory of PHP: atomic, and no database write on every page.
			$name = PNCP_Log::apcu_key( $key );
			apcu_add( $name, 0, 2 * MINUTE_IN_SECONDS );
			$count = apcu_inc( $name, $step );
			if ( false !== $count ) {
				return (int) $count;
			}
		}
		// 3.4.3: per-IP counters are capped in how many new rows they may add to wp_options each minute (see
		// db_incr_capped()); the site-wide surge counter is one row, sampled instead.
		$count = 'site' === $net ? self::db_incr( $key, 2 * MINUTE_IN_SECONDS, $step ) : self::db_incr_capped( $key, 2 * MINUTE_IN_SECONDS, $minute, $step );
		if ( null !== $count ) {
			return $count;
		}
		// Database without ON DUPLICATE KEY (e.g. SQLite): plain transient, not atomic.
		$count = (int) get_transient( $key ) + $step;
		set_transient( $key, $count, 2 * MINUTE_IN_SECONDS );
		return $count;
	}

	/**
	 * The storage key of a per-minute counter.
	 *
	 * @param string $bucket Type.
	 * @param string $net    What is counted (an IP key, or "site").
	 * @param int    $minute Minute (Unix time / 60).
	 * @return string
	 */
	private static function counter_key( $bucket, $net, $minute ) {
		return 'pncp_rl_' . md5( $bucket . '|' . $net ) . '_' . (int) $minute;
	}

	/**
	 * Reads a per-minute counter without adding to it (0 if there is none, or it has expired).
	 *
	 * @param string $bucket Type.
	 * @param string $net    What is counted.
	 * @param int    $minute Minute.
	 * @return int
	 */
	private static function peek( $bucket, $net, $minute ) {
		$key = self::counter_key( $bucket, $net, $minute );
		if ( wp_using_ext_object_cache() ) {
			return (int) wp_cache_get( $key, 'pncp' );
		}
		if ( PNCP_Log::apcu_ok() ) {
			return (int) apcu_fetch( PNCP_Log::apcu_key( $key ) );
		}
		return (int) get_transient( $key );
	}

	/**
	 * Pages per minute of the whole site, for the automatic Emergency Mode (PNCP_Surge).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function surge( $s ) {
		$minute = (int) floor( time() / MINUTE_IN_SECONDS );
		$step   = 1;
		if ( ! wp_using_ext_object_cache() && ! PNCP_Log::apcu_ok() ) {
			// 3.4.3: in the database, every page of the site wrote the same row, so under attack all PHP workers
			// queued on its row lock. Now 1 page in SURGE_SAMPLE adds SURGE_SAMPLE: the same count on average
			// (the thresholds keep working), a tenth of the writes. A quiet minute may then read as 0.
			$step = (int) apply_filters( 'pncp_surge_sample', self::SURGE_SAMPLE );
			if ( $step > 1 && 1 !== wp_rand( 1, $step ) ) {
				return;
			}
			$step = max( 1, $step );
		}
		$count = self::hit( '', 'surge', 'site', $step );
		if ( $step === $count ) {
			// The first count of this minute (3.4.3: the first sample): it closes the previous minute.
			PNCP_Surge::observe( 1, $minute, self::peek( 'surge', 'site', $minute - 1 ), $s );
		}
	}

	/**
	 * Atomic counter in the database, for sites without an object cache. With concurrent requests, the "read +1
	 * write" of transients loses counts (confirmed: limit 50, up to 65 got through). Here the increment
	 * happens inside MySQL and the new value is read with LAST_INSERT_ID() on the same connection.
	 * It is stored as a regular transient (with timeout), so WordPress cleans it up like all transients.
	 *
	 * @param string $key  Transient key.
	 * @param int    $ttl  Seconds.
	 * @param int    $step 3.4.3: how much to add (1, or the sample size of the surge counter).
	 * @return int|null Null if the database does not support it.
	 */
	private static function db_incr( $key, $ttl, $step = 1 ) {
		global $wpdb;
		$step = max( 1, (int) $step );
		if ( ! ( $wpdb instanceof wpdb ) || ! ( $wpdb->dbh instanceof mysqli ) ) {
			return null;
		}
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Atomic counter: not possible with the options API.
		$rows = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'off')
				ON DUPLICATE KEY UPDATE option_value = LAST_INSERT_ID(option_value + %d)",
				'_transient_' . $key,
				(string) $step,
				$step
			)
		);
		if ( false === $rows ) {
			$wpdb->suppress_errors( $suppress );
			return null;
		}
		$insert_id = (int) $wpdb->insert_id; // mysqli_insert_id() of the same (write) connection: = option_value + 1.
		if ( 1 === (int) $rows ) {
			// New row: the expiry, for transient cleanup.
			$wpdb->query(
				$wpdb->prepare(
					"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'off')",
					'_transient_timeout_' . $key,
					(string) ( time() + (int) $ttl )
				)
			);
			$count = $step;
		} else {
			// No separate SELECT LAST_INSERT_ID(): with HyperDB / read-write split it would go to a replica.
			$count = $insert_id;
			if ( $count < $step + 1 ) {
				$wpdb->suppress_errors( $suppress );
				return null; // Unexpected: fall back to the transient.
			}
		}
		// phpcs:enable
		$wpdb->suppress_errors( $suppress );
		return $count;
	}

	/**
	 * 3.4.3: a per-IP counter in the database, with a cap on new rows. Without an object cache or APCu, every
	 * IP seen in a minute added two rows to wp_options (the counter and its timeout), per type: a crawl from
	 * thousands of addresses wrote thousands of rows a minute. An IP already counted this minute is counted as
	 * before (one UPDATE, as the INSERT it replaces). A new one takes a row from a site-wide budget of
	 * DB_NEW_KEYS_PER_MINUTE; once that is used up, IPs not seen yet this minute are not stored, and count as
	 * their first request of the minute (no per-IP limit for them until the next minute; the site-wide surge
	 * counter, bans and every other check still apply).
	 *
	 * @param string $key    Transient key.
	 * @param int    $ttl    Seconds.
	 * @param int    $minute Minute (Unix time / 60).
	 * @param int    $step   3.5: how much to add (the REST cost).
	 * @return int|null Null if the database does not support it.
	 */
	private static function db_incr_capped( $key, $ttl, $minute, $step = 1 ) {
		global $wpdb;
		if ( ! ( $wpdb instanceof wpdb ) || ! ( $wpdb->dbh instanceof mysqli ) ) {
			return null;
		}
		$step     = max( 1, (int) $step );
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Atomic counter: not possible with the options API.
		$rows = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = LAST_INSERT_ID(option_value + %d) WHERE option_name = %s",
				$step,
				'_transient_' . $key
			)
		);
		if ( false === $rows ) {
			$wpdb->suppress_errors( $suppress );
			return null;
		}
		if ( 1 === (int) $rows ) {
			// wpdb reads insert_id only after an INSERT: LAST_INSERT_ID(expr) of the same (write) connection.
			$count = (int) mysqli_insert_id( $wpdb->dbh ); // phpcs:ignore WordPress.DB.RestrictedFunctions -- LAST_INSERT_ID() of the UPDATE just run; wpdb has no accessor for it.
			$wpdb->suppress_errors( $suppress );
			return $count >= $step + 1 ? $count : null; // Unexpected: fall back to the transient, as db_incr() does.
		}
		// A new row: within this minute's budget? Read first, so that past the budget nothing is written at all.
		$limit  = (int) apply_filters( 'pncp_db_new_counters_per_minute', self::DB_NEW_KEYS_PER_MINUTE );
		$budget = self::counter_key( 'db_new_keys', 'site', $minute );
		if ( $limit > 0 ) {
			$used = (int) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", '_transient_' . $budget ) );
			if ( $used >= $limit ) {
				$wpdb->suppress_errors( $suppress );
				return $step; // Not stored: counted as this IP's first request of the minute (3.5: of $step units).
			}
		}
		// phpcs:enable
		$wpdb->suppress_errors( $suppress );
		if ( $limit > 0 ) {
			self::db_incr( $budget, $ttl );
		}
		return self::db_incr( $key, $ttl, $step );
	}

	/**
	 * The response is not stored in any cache: headers for browsers / CDN, DONOTCACHEPAGE for PHP
	 * cache plugins (WP Super Cache, W3TC, WP Rocket, etc.) and X-LiteSpeed-Cache-Control for LiteSpeed.
	 * Otherwise a 403 for a bot would later be served to visitors, or a token feed to everyone.
	 * Cloudflare APO: cf-edge-cache: no-cache, which replaces the "cache" the Cloudflare plugin may have sent.
	 */
	public static function no_cache() {
		self::$uncacheable = true;
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Cache plugins constant.
		}
		if ( ! headers_sent() ) {
			nocache_headers();
			header( 'X-LiteSpeed-Cache-Control: no-cache' );
			header( 'cf-edge-cache: no-cache' );
		}
	}

	/**
	 * Ends the request with 403 or 429, without it being cached.
	 *
	 * @param int $code HTTP status code.
	 */
	public static function die_html( $code ) {
		self::no_cache();
		if ( 429 === $code ) {
			header( 'Retry-After: 60' );
			$message = __( 'Too many requests. Please try again in a minute.', 'scrapelock' );
		} else {
			$message = __( 'Access denied.', 'scrapelock' );
		}
		wp_die( esc_html( $message ), esc_html( (string) $code ), array( 'response' => (int) $code ) );
	}

	/* ---------- Bot trap ---------- */

	/**
	 * The trap path: fixed for the site, different on every site.
	 *
	 * @return string e.g. /cp-a1b2c3d4e5/
	 */
	public static function trap_path() {
		return '/cp-' . substr( hash_hmac( 'sha256', 'pncp-trap', wp_salt( 'nonce' ) ), 0, 10 ) . '/';
	}

	/**
	 * Whether the trap link is printed on this page.
	 *
	 * @return bool
	 */
	private static function trap_shown() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && ! empty( $s['trap_enabled'] ) && ! PNCP_Options::user_is_exempt( $s );
	}

	/**
	 * Hides the trap link with CSS through wp_add_inline_style() (no extra file, no inline style attribute).
	 */
	public static function trap_style() {
		if ( ! self::trap_shown() ) {
			return;
		}
		wp_register_style( 'pncp-trap', false, array(), PNCP_VERSION );
		wp_enqueue_style( 'pncp-trap' );
		wp_add_inline_style( 'pncp-trap', '.pncp-hp{position:absolute!important;left:-10000px!important;top:auto!important;width:1px!important;height:1px!important;overflow:hidden!important}' );
	}

	/**
	 * Invisible link at the end of every page: humans do not see it (CSS of trap_style()), screen readers
	 * ignore it (aria-hidden, tabindex=-1), search engines ignore it (robots.txt, nofollow).
	 */
	public static function trap_link() {
		if ( ! self::trap_shown() ) {
			return;
		}
		printf(
			'<a href="%s" rel="nofollow noindex" tabindex="-1" aria-hidden="true" class="pncp-hp">%s</a>',
			esc_url( home_url( self::trap_path() ) ),
			esc_html__( 'Archive', 'scrapelock' )
		);
	}

	/**
	 * WordPress's speculative loading never preloads the trap.
	 *
	 * @param string[] $paths Paths.
	 * @return string[]
	 */
	public static function speculation_exclude( $paths ) {
		$paths   = (array) $paths;
		$paths[] = self::trap_path() . '*';
		return $paths;
	}

	/**
	 * Whoever opens the trap gets blocked (3.4.3: 10 minutes the first time, the full ban the second time
	 * within 24 hours, see trap_ban_minutes()).
	 *
	 * A third-party site cannot get your visitors blocked (e.g. with <img src="…trap">):
	 * browsers send Sec-Fetch-Site/Sec-Fetch-Dest, and blocking happens only for navigation
	 * from the site itself or for requests without these headers (bots). Prefetch does not count.
	 */
	public static function trap_guard() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['trap_enabled'] ) ) {
			return;
		}
		$path = PNCP_Private_Urls::relative_path( self::request_path() );
		if ( 0 !== stripos( trailingslashit( $path ), self::trap_path() ) ) {
			return;
		}

		self::no_cache();
		header( 'X-Robots-Tag: noindex, nofollow' );

		$ip = PNCP_Ip::client_ip();
		// "Monitor only": logged as "would block", no ban, and the request goes on (to the "page not found" page).
		if ( PNCP_Options::monitoring( $s ) ) {
			if ( self::trap_should_ban( $ip ) ) {
				PNCP_Log::add( 'trap', PNCP_Log::MONITOR_CODE, $ip );
			}
			return;
		}
		if ( self::trap_should_ban( $ip ) ) {
			PNCP_Log::add( 'trap', 403, $ip );
			// "Block after 0 violations" = never block: log only.
			if ( (int) $s['ban_strikes'] > 0 ) {
				PNCP_Log::ban( $ip, self::trap_ban_minutes( $ip, (int) $s['ban_minutes'] ), 'trap' );
			}
		}

		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo 'Forbidden';
		exit;
	}

	/**
	 * 3.4.3: how long the trap bans. One trap hit banned the IP (IPv6: the /64) for the full time, which locked
	 * out a whole office, school or mobile carrier NAT because of one bad client behind it. Now the first hit
	 * is a short ban (10 minutes) and a strike kept for 24 hours; a second hit from the same IP key within those
	 * 24 hours gets the full ban, as before. A scraper that comes back after the short ban is banned in full.
	 *
	 * @param string $ip      IP.
	 * @param int    $minutes The configured ban, in minutes.
	 * @return int Minutes.
	 */
	private static function trap_ban_minutes( $ip, $minutes ) {
		$minutes = max( 1, (int) $minutes );
		$key     = 'pncp_tk_' . md5( PNCP_Ip::limit_key( $ip ) );
		if ( ! self::first_ban_claim( $key ) ) {
			return $minutes; // Second hit within 24 hours: the full ban.
		}
		$first = (int) apply_filters( 'pncp_trap_first_ban_minutes', 10 );
		return $first > 0 ? min( $first, $minutes ) : $minutes;
	}

	/**
	 * 3.5: "Ban scanners on their first probe" (opt-in). A request for a path only attack scanners ask for
	 * (PNCP_Probe: .env, .git, wp-config.php backups, dumps and archives at the top of the site, SSH keys,
	 * phpMyAdmin, Adminer, PHP in uploads) that WordPress answers with a 404 and that is not a real file gets a
	 * 403 and a short ban (like the bot trap: probe_ban_minutes()). Same exemptions as the trap
	 * (should_ban_on_sight()), plus the always-allowed User-Agents on any network (as the pre-cache check).
	 * 3.5: runs on template_redirect after WordPress's own redirects (old slugs, redirect_canonical(), priority
	 * 10), so a 404 that WordPress turns into a 301 is never acted on (3.5: except redirect_canonical()'s for a
	 * path on the list: probe_no_canonical()). With plain permalinks WordPress answers an unknown path with the
	 * home page, not a 404: then the list match and the file check decide alone.
	 * Every match is refused with the same 403, also a real file and an exempt visitor (only logged and banned
	 * when not exempt): a 404 for a real file and a 403 for a missing one would tell a scanner which secrets
	 * are on disk. In "Monitor only" every match gets WordPress's normal 404 page instead.
	 * Nothing before the list match touches the database, a transient or the file system.
	 */
	public static function probe_guard() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['probe_ban'] ) || ! ( is_404() || '' === (string) get_option( 'permalink_structure' ) ) ) {
			return;
		}
		$path = PNCP_Probe::request_path();
		if ( ! PNCP_Probe::matches( $path ) ) {
			return;
		}
		if ( '' !== trim( (string) $s['private_paths'] ) && '' !== PNCP_Private_Urls::matching_pattern( $path, PNCP_Options::parse_list( $s['private_paths'] ) ) ) {
			return; // A Private URL has its own answer.
		}
		// 3.5: before any exemption (as trap_guard()): a cached 404 for /.env would keep every later scanner from
		// reaching PHP at all.
		self::no_cache();
		header( 'X-Robots-Tag: noindex, nofollow' );
		$monitor = PNCP_Options::monitoring( $s );
		$ban     = false;
		// A real file is never logged or banned.
		if ( ! PNCP_Probe::file_exists( $path ) ) {
			$ip  = PNCP_Ip::client_ip();
			$ua  = self::user_agent();
			$ban = '' !== $ip && ! PNCP_Ip::is_cdn_edge( $ip ) && ! PNCP_Log::is_banned( $ip )
				// 3.5: an always-allowed User-Agent (site managers, uptime monitors) on any network, as the pre-cache
				// check: they run from data centers and may look for an exposed .env as a security check.
				&& ! ( '' !== $ua && self::allow_list_match( $ua, $ip, $s ) )
				&& self::should_ban_on_sight( $ip, 'pncp_pr_' );
			/**
			 * 3.5: last word before a scanner probe is logged and banned by WordPress (not applied by the pre-cache
			 * check). The request is refused either way.
			 *
			 * @param bool   $ban  Whether to log and ban.
			 * @param string $path The path asked for, relative to the home path (decoded).
			 * @param string $ip   Visitor IP.
			 */
			$ban = $ban && apply_filters( 'pncp_probe_ban', true, $path, $ip );
		}
		// "Monitor only": logged as "would block", no ban and no memory, and the request goes on to the 404 page.
		if ( $monitor ) {
			if ( $ban ) {
				PNCP_Log::add( 'probe', PNCP_Log::MONITOR_CODE, $ip );
			}
			return;
		}
		if ( $ban ) {
			PNCP_Log::add( 'probe', 403, $ip );
			// "Block after 0 violations" = never block: log only (as the trap).
			if ( (int) $s['ban_strikes'] > 0 ) {
				PNCP_Log::ban( $ip, self::probe_ban_minutes( $ip, (int) $s['ban_minutes'] ), 'probe' );
			}
		}
		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo 'Forbidden';
		exit;
	}

	/**
	 * 3.5: redirect_canonical() answers a 404 for /phpmyadmin/index.php or /index.php/.env with a 301 to the same
	 * address without index.php, before probe_guard() runs, and most scanners do not follow it. A 404 whose path
	 * is on the probe list is not redirected, so probe_guard() refuses it. Runs only when WordPress has a
	 * redirect to make; other redirects (old slugs, real pages) are left alone.
	 *
	 * @param string|false $redirect_url The address WordPress redirects to.
	 * @return string|false
	 */
	public static function probe_no_canonical( $redirect_url ) {
		if ( ! is_string( $redirect_url ) || '' === $redirect_url || ! is_404() ) {
			return $redirect_url;
		}
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['probe_ban'] ) ) {
			return $redirect_url;
		}
		$path = PNCP_Probe::request_path();
		if ( ! PNCP_Probe::matches( $path ) ) {
			return $redirect_url;
		}
		if ( '' !== trim( (string) $s['private_paths'] ) && '' !== PNCP_Private_Urls::matching_pattern( $path, PNCP_Options::parse_list( $s['private_paths'] ) ) ) {
			return $redirect_url; // A Private URL has its own answer (as probe_guard()).
		}
		return false;
	}

	/**
	 * 3.5: how long a probe bans: like the trap (trap_ban_minutes()), the first probe a short ban and a memory kept
	 * for 24 hours; a second probe from the same IP key within those 24 hours gets the full ban.
	 *
	 * @param string $ip      IP.
	 * @param int    $minutes The configured ban, in minutes.
	 * @return int Minutes.
	 */
	private static function probe_ban_minutes( $ip, $minutes ) {
		$minutes = max( 1, (int) $minutes );
		$key     = PNCP_Log::probe_memory_key( $ip ); // 3.5: with the WP-CLI stamp (see there).
		// 3.5: the pre-cache check's memory too (and this probe written to it), so a probe answered there and one
		// answered here count as two, in either order.
		$runtime = PNCP_Precheck::probe_seen( PNCP_Ip::limit_key( $ip ) );
		if ( ! self::first_ban_claim( $key ) || $runtime ) {
			return $minutes; // Second probe within 24 hours: the full ban.
		}
		return self::probe_first_minutes( $minutes );
	}

	/**
	 * 3.5: the 24-hour memory of a first ban (trap, probe), claimed in one atomic step (with an object cache or
	 * APCu): true for the first hit, false for a later one (then the full ban). A scanner sends its first
	 * requests in parallel, and several of them pass the ban check before the first ban is stored; reading and
	 * then writing the memory gave the later ones the full ban, which wins (store_ban() keeps the longest). The
	 * memory holds the time of the first hit, and a hit within FIRST_BAN_BURST seconds of it counts as the same
	 * first hit. (A memory written by an older version holds 1: a later hit, as before.)
	 *
	 * @param string $key Cache key.
	 * @return bool
	 */
	private static function first_ban_claim( $key ) {
		$now = time();
		if ( PNCP_Log::cache_add( $key, $now, DAY_IN_SECONDS ) ) {
			return true;
		}
		return (int) PNCP_Log::cache_get( $key ) > $now - self::FIRST_BAN_BURST;
	}

	/**
	 * 3.5: the first probe ban: filter pncp_probe_first_ban_minutes (10), never longer than the full ban.
	 *
	 * @param int $minutes The configured ban, in minutes.
	 * @return int Minutes.
	 */
	public static function probe_first_minutes( $minutes ) {
		$minutes = max( 1, (int) $minutes );
		/**
		 * 3.5: minutes of the first scanner probe ban (0 or less: the full ban at once). Never longer than
		 * "Block for N minutes". Read by the pre-cache check when its configuration is written.
		 *
		 * @param int $minutes Minutes (10).
		 */
		$first = (int) apply_filters( 'pncp_probe_first_ban_minutes', 10 );
		return $first > 0 ? min( $first, $minutes ) : $minutes;
	}

	/**
	 * Search engines without verification (they publish no IP / DNS lists we check). If they did not see
	 * the Disallow (e.g. a physical robots.txt or a stale copy), they are not blocked by the trap.
	 *
	 * @return string[]
	 */
	public static function trap_exempt_agents() {
		return (array) apply_filters( 'pncp_trap_exempt_agents', array( 'DuckDuckBot', 'Baiduspider', 'SeznamBot', 'PetalBot', 'Sogou', 'Yeti', 'Qwantbot', 'MojeekBot', 'Ecosia' ) );
	}

	/**
	 * Should the IP that opened the trap be blocked?
	 *
	 * Never: logged-in users, the server, always-allowed IPs, Google / Bing IPs, search engines,
	 * IPs that may be spoofed (trust every proxy), prefetch, requests from a third-party site or
	 * that are not navigation, and human clicks (Sec-Fetch-User, e.g. a link in a comment).
	 * Browser without Sec-Fetch (old Safari / Firefox): blocked only on the second hit within 10 minutes.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private static function trap_should_ban( $ip ) {
		return self::should_ban_on_sight( $ip, 'pncp_tr_' );
	}

	/**
	 * 3.5: the exemptions of the bot trap (trap_should_ban()), shared with the scanner probe ban (probe_guard()).
	 * Unchanged code; only the cache-key prefix of the counter for browsers without Sec-Fetch is a parameter, so
	 * the trap and the probe ban count separately.
	 *
	 * @param string $ip   IP.
	 * @param string $seen Cache-key prefix of the "old browser" counter ('pncp_tr_' for the trap).
	 * @return bool
	 */
	private static function should_ban_on_sight( $ip, $seen ) {
		$s = PNCP_Options::get();
		if ( '' === $ip || PNCP_Options::user_is_exempt( $s ) || PNCP_Ip::is_local( $ip ) || ! PNCP_Ip::reliable() || self::is_official_crawler_ip( $ip ) ) {
			return false;
		}
		if ( PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['allow_ips'] ) ) ) {
			return false;
		}
		$ua     = self::user_agent();
		$family = self::claimed_crawler( $ua );
		if ( 'verified' === self::ai_verdict( $ua, $ip, $s ) ) {
			return false; // A verified AI search bot is treated like a search engine.
		}
		if ( ( '' !== $family && ( self::is_verified_crawler( $family, $ip ) || self::$verify_inconclusive ) ) || self::ua_in_list( $ua, self::trap_exempt_agents() ) ) {
			return false; // Verified, or not verifiable right now: a real search engine is never banned.
		}
		// Allowed bots (link previews such as facebookexternalhit, price-comparison, monitoring) and allowed
		// AI search bots are never banned by the trap: a page elsewhere embedding the trap URL (e.g. a link
		// shared on a chat app) must not get the real preview bot banned.
		if ( '' !== $ua && ( self::allow_list_match_pinned( $ua, $ip, $s ) || self::ua_in_list( $ua, PNCP_Options::allowed_ai_search() ) ) ) {
			return false;
		}
		// An unpinned allow entry matches on the User-Agent alone, which anyone can copy: it protects from the
		// trap only outside data centers (link previews come from the chat apps' own networks; a scraper that
		// adds "WhatsApp" to its User-Agent usually runs on a cloud server).
		if ( '' !== $ua && self::allow_list_match( $ua, $ip, $s ) && '' === PNCP_Ip::datacenter( $ip ) ) {
			return false;
		}
		if ( self::is_prefetch() ) {
			return false;
		}
		$header = static function ( $name ) {
			return isset( $_SERVER[ $name ] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER[ $name ] ) ) ) : '';
		};
		$site   = $header( 'HTTP_SEC_FETCH_SITE' );
		$dest   = $header( 'HTTP_SEC_FETCH_DEST' );
		if ( '' !== $site && ! in_array( $site, array( 'same-origin', 'none' ), true ) ) {
			return false; // From another site (cross-site / same-site): no block.
		}
		if ( '' !== $dest && 'document' !== $dest ) {
			return false; // Image, iframe, script, etc.: not navigation.
		}
		if ( '?1' === $header( 'HTTP_SEC_FETCH_USER' ) ) {
			return false; // Human click on a link (e.g. someone posted the address in a comment).
		}
		if ( '' === $site && 0 === strpos( $ua, 'Mozilla/' ) ) {
			// Browser without Sec-Fetch: perhaps an old browser that loaded another site's <img>. Only after
			// repeated hits (3rd within 10 minutes) is it treated as a bot, so a one-off cross-site <img> on
			// someone else's page does not get an old-browser visitor banned.
			$key  = $seen . md5( PNCP_Ip::limit_key( $ip ) );
			$seen = (int) PNCP_Log::cache_get( $key );
			PNCP_Log::cache_set( $key, $seen + 1, 10 * MINUTE_IN_SECONDS );
			return $seen >= 2;
		}
		return true;
	}

	/* ---------- robots.txt and WP Rocket ---------- */

	/**
	 * The AI crawlers listed in robots.txt.
	 *
	 * @return string[]
	 */
	public static function robots_agents() {
		$agents = array_merge(
			array( 'GPTBot', 'ChatGPT-User', 'OAI-SearchBot', 'CCBot', 'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'anthropic-ai', 'PerplexityBot', 'Perplexity-User', 'Bytespider', 'Google-Extended', 'Google-CloudVertexBot', 'Applebot-Extended', 'meta-externalagent', 'meta-externalfetcher', 'FacebookBot', 'Amazonbot', 'Diffbot', 'cohere-ai', 'cohere-training-data-crawler', 'AI2Bot', 'Ai2Bot-Dolma', 'YouBot', 'DuckAssistBot', 'MistralAI-User', 'PanguBot', 'Timpibot', 'omgili', 'Webzio-Extended', 'ImagesiftBot', 'img2dataset', 'TikTokSpider' ),
			self::known_ai_agents(),
			// Asked in robots.txt only, not blocked: names too generic to match a User-Agent safely, and bots
			// that act for the site's own visitors or tools (shopping agents, link previews in Jira /
			// Confluence, social publishing, a search engine).
			array( 'PetalBot', 'AmazonBuyForMe', 'atlassian-bot', 'EchoboxBot', 'Google-Firebase', 'Operator', 'Devin', 'Cursor', 'Codex' )
		);
		$out = array();
		foreach ( $agents as $agent ) {
			$out[ strtolower( $agent ) ] = $agent;
		}
		return (array) apply_filters( 'pncp_robots_ai_agents', array_values( $out ) );
	}

	/**
	 * Web archive crawlers (the Internet Archive's Wayback Machine). What they store is public for good and can be
	 * copied from the archive without ever reaching the site, so "Block web archives" blocks them and asks them in
	 * robots.txt. Off by default: many sites want to be archived. Filter `pncp_archive_agents`.
	 *
	 * @return string[]
	 */
	public static function archive_agents() {
		return (array) apply_filters( 'pncp_archive_agents', array( 'ia_archiver', 'archive.org_bot', 'heritrix' ) );
	}

	/**
	 * AI crawlers, data scrapers and agents blocked by name (when "Block bots" is on), in addition to the editable
	 * bot list. Built into the plugin and updated with each version, so the settings list keeps its 200 lines
	 * for the site's own entries. Sources: ai.robots.txt and the operators' own pages; only names that appear in
	 * the User-Agent and are specific enough not to match a browser or a tool the site uses. An entry in the
	 * "always allowed" list, or an allowed AI search bot, still passes. Filter `pncp_known_ai_agents`.
	 *
	 * @return string[]
	 */
	public static function known_ai_agents() {
		return (array) apply_filters(
			'pncp_known_ai_agents',
			array(
				// AI search crawlers and assistants (blocked unless "Allow AI search" lists them).
				'AddSearchBot',
				'AIWebIndex',
				'Amzn-SearchBot',
				'Amzn-User',
				'AzureAI-SearchBot',
				'Channel3Bot',
				'ExaSearchBot',
				'ExaUser',
				'GrokBot',
				'Grok Bot',
				'GrokAppAndroid',
				'xAI-Grok',
				'KeenableBot',
				'Kimi-SearchBot',
				'Kimi-User',
				'Kimi-Agent',
				'LinkupBot',
				'ZanistaBot',
				'Andibot',
				'Aranet-SearchBot',
				'iAskBot',
				'Gemini-Deep-Research',
				'Google-NotebookLM',
				'NotebookLM',
				'GoogleAgent-URLContext',
				'GoogleAgent-Mariner',
				'Google-Agent',
				'kagi-fetcher',
				'meta-webindexer',
				'PhindBot',
				'Poggio-Citations',
				'Shap-User',
				'TongyiBot',
				'YiyanBot',
				'LinerBot',
				'GeistHaus-PageFetcher',
				'bigsur.ai',
				'Manus-User',
				'NovaAct',
				'TwinAgent',
				'MistralAI-Index',
				'Anomura',
				'Cloudflare-AutoRAG',
				'amazon-kendra',
				'amazon-QBusiness',
				'BuddyBot',
				'Querit-SearchBot',
				'QueritBot',
				'KlaviyoAIBot',
				'UseAI',
				// Training crawlers and AI data providers.
				'DeepSeekBot',
				'QwenBot',
				'DoubaoBot',
				'ERNIEBot',
				'Hunyuan',
				'KimiBot',
				'MoonshotBot',
				'ChatGLM-Spider',
				'MistralAI-Training',
				'YandexAdditional',
				'Cotoyogi',
				'SBIntuitionsBot',
				'YiBot',
				'CloudVertexBot',
				'laion-huggingface-processor',
				'LAIONDownloader',
				'FriendlyCrawler',
				'Factset_spyderbot',
				'ISSCyberRiskCrawler',
				'Poseidon Research Crawler',
				'MyCentralAIScraperBot',
				'NagetBot',
				'newsai',
				'aiHitBot',
				'AgentDataBot',
				'BixelBot',
				'Bravebot',
				'CloudflareBrowserRenderingCrawler',
				'CragCrawler',
				'Crawlspace',
				'HenkBot',
				'Mozilla-Tabstack',
				'ShapBot',
				'TavilyBot',
				'TerraCotta',
				'Terra Cotta',
				'ExaBot',
				'Awario',
				'Datenbank Crawler',
				'Echobot Bot',
				'imageSpider',
				'KunatoCrawler',
				'Reflectionbot',
				'WRTNBot',
				'netEstate Imprint Crawler',
				'WARDBot',
				'bedrockbot',
				'Panscient',
				'Thinkbot',
				'AgentTimes',
				'Linguee Bot',
				'QuillBot',
				'SemrushBot-OCOB',
				'SemrushBot-SWA',
				'OAI-AdsBot',
				'Lightpanda',
				// AI coding agents that fetch pages.
				'Claude-Code',
				'Google-Gemini-CLI',
				'opencode',
				'qodercli',
			)
		);
	}

	/**
	 * Disallow for AI crawlers and for the trap in the virtual robots.txt. Does not affect search engines.
	 *
	 * @param string $output    The robots.txt.
	 * @param bool   $is_public Whether the site allows indexing.
	 * @return string
	 */
	public static function robots_txt( $output, $is_public ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || ! $is_public ) {
			return $output;
		}

		// The rules for every bot go into the robots.txt's existing "User-agent: *" group: one group, since simple
		// parsers read only the first one (Google merges them).
		$star = array();
		if ( ! empty( $s['trap_enabled'] ) ) {
			$star[] = '# ScrapeLock';
			$star[] = 'Disallow: ' . wp_parse_url( home_url( self::trap_path() ), PHP_URL_PATH );
		}
		if ( ! empty( $s['content_signal'] ) ) {
			// contentsignals.org: what the content may be used for, after it is fetched. Does not block anything.
			$star[] = '# ScrapeLock: Content Signals (contentsignals.org). search = search index and links,';
			$star[] = '# ai-input = use in AI answers, ai-train = training or fine-tuning AI models.';
			$star[] = 'Content-Signal: search=yes, ai-input=' . ( empty( $s['allow_ai_search'] ) ? 'no' : 'yes' ) . ', ai-train=no';
		}
		$output = $star ? self::add_to_star_group( $output, $star ) : $output;

		if ( ! empty( $s['robots_ai_block'] ) ) {
			$block  = "\n# ScrapeLock: AI crawlers\n";
			$search = array_map( 'strtolower', PNCP_Options::allowed_ai_search() );
			foreach ( self::robots_agents() as $agent ) {
				if ( in_array( strtolower( $agent ), $search, true ) ) {
					continue; // AI search allowed: no Disallow is added.
				}
				$block .= 'User-agent: ' . $agent . "\n";
			}
			$output = rtrim( $output ) . "\n" . $block . "Disallow: /\n";
		}
		if ( ! empty( $s['block_archivers'] ) ) {
			$block = "\n# ScrapeLock: web archives\n";
			foreach ( self::archive_agents() as $agent ) {
				$block .= 'User-agent: ' . $agent . "\n";
			}
			$output = rtrim( $output ) . "\n" . $block . "Disallow: /\n";
		}
		return $output;
	}

	/**
	 * Adds lines to the first "User-agent: *" group of a robots.txt, after its last rule; without one, a new group.
	 *
	 * @param string   $output The robots.txt.
	 * @param string[] $lines  Lines.
	 * @return string
	 */
	public static function add_to_star_group( $output, $lines ) {
		$rows  = '' === trim( $output ) ? array() : preg_split( '/\r\n|\r|\n/', rtrim( $output ) );
		$count = count( $rows );
		$start = null;
		foreach ( $rows as $i => $row ) {
			if ( preg_match( '/^\s*user-agent\s*:\s*\*\s*(?:#.*)?$/i', $row ) ) {
				$start = $i;
				break;
			}
		}
		if ( null === $start ) {
			$rules = preg_grep( '/^\s*(?:dis)?allow\s*:/i', $lines );
			$group = array_merge( array( 'User-agent: *' ), $lines, $rules ? array() : array( 'Allow: /' ) );
			return ( $rows ? implode( "\n", $rows ) . "\n\n" : '' ) . implode( "\n", $group ) . "\n";
		}
		// The group: its User-agent lines, then its rules up to a blank line, the next group or a Sitemap line.
		$end = $start;
		$i   = $start + 1;
		while ( $i < $count && preg_match( '/^\s*user-agent\s*:/i', $rows[ $i ] ) ) {
			$end = $i++;
		}
		for ( ; $i < $count; $i++ ) {
			$row = trim( $rows[ $i ] );
			if ( '' === $row || preg_match( '/^(?:user-agent|sitemap)\s*:/i', $row ) ) {
				break;
			}
			$end = $i;
		}
		array_splice( $rows, $end + 1, 0, $lines );
		return implode( "\n", $rows ) . "\n";
	}

	/**
	 * Tells WP Rocket not to serve cache to blocked User-Agents.
	 *
	 * @param string[] $uas User-Agents.
	 * @return string[]
	 */
	public static function rocket_reject_ua( $uas ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) ) {
			return $uas;
		}
		$uas = (array) $uas;
		// With the pre-cache check, search engines without an official IP list (Applebot, YandexBot) get no
		// cached pages: the check lets them through, so the normal check must verify them with DNS.
		if ( ! empty( $s['precheck'] ) ) {
			foreach ( self::$crawlers as $def ) {
				if ( '' === $def['list'] ) {
					foreach ( $def['ua'] as $needle ) {
						$uas[] = preg_quote( $needle, '#' );
					}
				}
			}
		}
		if ( empty( $s['block_bots'] ) ) {
			return $uas;
		}
		$search = array_map( 'strtolower', PNCP_Options::allowed_ai_search() );
		foreach ( PNCP_Options::blocked_agents( $s ) as $needle ) {
			if ( in_array( strtolower( $needle ), $search, true ) ) {
				continue;
			}
			// "=node" (the whole User-Agent) as an anchored pattern.
			$uas[] = '=' === $needle[0] ? '^' . preg_quote( substr( $needle, 1 ), '#' ) . '$' : preg_quote( $needle, '#' );
		}
		return $uas;
	}
}
