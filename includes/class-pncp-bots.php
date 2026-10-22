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
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'trap_guard' ), 0 );
		add_action( 'init', array( __CLASS__, 'sitemap_guard' ), 1 );
		add_action( 'template_redirect', array( __CLASS__, 'page_guard' ), 0 );
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
			$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			$raw  = '/' . ltrim( rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) ), '/' );
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
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = PNCP_Private_Urls::relative_path( rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) ) );
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
		if ( self::blocks_user_enum() && preg_match( '#^/wp/v2/users(?:/|$)#i', (string) $request->get_route() ) ) {
			return new WP_Error( 'rest_user_cannot_view', __( 'Sorry, you are not allowed to list users.', 'scrapelock' ), array( 'status' => rest_authorization_required_code() ) );
		}
		// Read-only: cart, checkout, forms and payment webhooks (POST) are not checked.
		if ( ! in_array( strtoupper( (string) $request->get_method() ), array( 'GET', 'HEAD' ), true ) ) {
			return $result;
		}
		// Only the transactional Store API routes (cart, checkout, batch) are called from every page and are
		// exempt from the limit. The product catalogue (/wc/store/.../products) is scrapable data and counts
		// toward the REST limit like any other read.
		$route   = (string) $request->get_route();
		$count   = ! preg_match( '#^/wc/store(?:/v\d+)?/(?:cart|checkout|batch)(?:/|$)#i', $route );
		$verdict = self::check( 'rest', $count );
		if ( ! $verdict ) {
			return $result;
		}
		// The 403 / 429 must not end up in a REST cache (e.g. LiteSpeed Cache).
		self::no_cache();
		do_action( 'litespeed_control_set_nocache', 'scrapelock' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- LiteSpeed Cache hook.
		if ( 429 === $verdict['code'] ) {
			$server->send_header( 'Retry-After', '60' );
		}
		return new WP_Error(
			429 === $verdict['code'] ? 'pncp_rate_limited' : 'pncp_forbidden',
			429 === $verdict['code'] ? __( 'Too many requests. Please try again in a minute.', 'scrapelock' ) : __( 'Access denied.', 'scrapelock' ),
			array( 'status' => $verdict['code'] )
		);
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
	 * @return array{code:int, reason:string}|null Null if the request passes.
	 */
	public static function check( $context, $count = true ) {
		$s = PNCP_Options::get();
		// No exemption for wp_doing_ajax(): WooCommerce defines DOING_AJAX on wc-ajax, so every bot would
		// get through (confirmed with real WooCommerce). admin-ajax.php does not reach this point anyway.
		if ( empty( $s['enabled'] ) || wp_doing_cron() ) {
			return null;
		}
		// Only the roles in the "Who is exempt" setting are exempt, not every logged-in user: a
		// WooCommerce customer account can be created by anyone. On REST / GraphQL, those who
		// write content are also exempt, because the block editor makes dozens of requests per minute.
		if ( PNCP_Options::user_is_exempt( $s ) || ( in_array( $context, array( 'rest', 'graphql' ), true ) && PNCP_Lockdown::can( 'edit_posts' ) ) ) {
			return null;
		}
		// robots.txt, llms.txt and the TDM opt-out are never blocked, whatever the bot: a blocked bot must
		// still be able to read the rules it is asked to follow. page_guard already skips them; this is a
		// safety net so no caller of check() can ever return a 403 for them.
		if ( in_array( $context, array( 'page', 'search' ), true ) && self::is_open_path() ) {
			return null;
		}
		// Every request that gets a page counts, whatever its method and cookies: a "wordpress_logged_in_" or
		// "woocommerce_" cookie name is sent by any script, so an exemption based on it let a single IP scrape
		// without limit (2.8.2 and earlier). Logged-in staff are exempt above, by their verified role. A prefetch
		// has its own, larger limit below.
		// WooCommerce AJAX (cart, checkout): does not count toward the page limit, but bots, fake crawlers and
		// blocks are checked as usual. Only for actions registered by WooCommerce (or an extension of it).
		if ( self::is_wc_ajax() || ( 'page' === $context && self::is_shop_transaction_page() ) ) {
			$count = false;
		}
		// Private URL (XML feed) with a valid token: the service may use any User-Agent.
		if ( PNCP_Private_Urls::granted() ) {
			return null;
		}

		$ua = self::user_agent();
		$ip = PNCP_Ip::client_ip();

		if ( '' === $ip || PNCP_Ip::is_local( $ip ) ) {
			return null;
		}
		// Always-allowed IPs: only if the IP cannot be spoofed (not "trust every proxy").
		if ( PNCP_Ip::reliable() && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['allow_ips'] ) ) ) {
			return null;
		}

		/**
		 * Filter to let a request skip all checks.
		 *
		 * @param bool   $skip    Whether the check will be skipped.
		 * @param string $context page | search | rest | graphql.
		 * @param string $ip      IP.
		 */
		if ( apply_filters( 'pncp_skip_guard', false, $context, $ip ) ) {
			return null;
		}

		// The administrator's lists: always blocked, before everything else.
		if ( PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['block_ips'] ) ) ) {
			return self::verdict( 403, 'blocked_ip', $ip );
		}
		if ( self::referrer_blocked( $s ) ) {
			return self::verdict( 403, 'blocked_ref', $ip );
		}

		// Verification first: a real search engine gets through even if someone managed to
		// get its IP blocked.
		$family = self::claimed_crawler( $ua );
		if ( '' !== $family && self::is_verified_crawler( $family, $ip ) ) {
			return null; // Verified search engines: never blocked, never limited.
		}
		$ai = self::ai_verdict( $ua, $ip, $s );
		if ( 'verified' === $ai ) {
			return null; // Verified AI search bots, as above.
		}

		if ( PNCP_Log::is_banned( $ip ) ) {
			return self::verdict( 403, 'banned', $ip );
		}

		if ( 'fake' === $ai ) {
			PNCP_Log::strike( $ip, 'fake_ai_bot' );
			return self::verdict( 403, 'fake_ai_bot', $ip );
		}

		if ( '' !== $family && ! empty( $s['block_fake_crawlers'] ) && ! self::$verify_inconclusive ) {
			PNCP_Log::strike( $ip, 'fake_crawler' );
			return self::verdict( 403, 'fake_crawler', $ip );
		}
		// When verification could not finish (DNS budget used up, or a temporary DNS failure) the request is
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

		// Every browser sends Accept-Language and "Mozilla/" in the User-Agent; most scripts do not.
		// Not on wc-ajax: some payment gateways / extensions call them server-side, without Accept-Language.
		if ( ! empty( $s['require_browser_headers'] ) && ! $allowed_ua && in_array( $context, array( 'page', 'search' ), true ) && ! self::is_wc_ajax() && ! self::looks_like_browser( $ua ) ) {
			return self::verdict( 403, 'no_browser', $ip );
		}

		// Headless and fake browsers: what the browser itself sends does not match the User-Agent.
		// Not for anyone claiming to be a search engine: those are verified (or blocked as fake) above.
		if ( ! empty( $s['block_headless'] ) && ! $allowed_ua && '' === $family && in_array( $context, array( 'page', 'search' ), true ) && ! self::is_wc_ajax() ) {
			$fake = self::fake_browser( $ua );
			if ( '' !== $fake ) {
				return self::verdict( 403, $fake, $ip );
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
			return null;
		}

		// Stricter page limits: visitors without the human-check cookie, and countries in the "stricter" list.
		if ( $count && 'page' === $context ) {
			$stricter = array();
			// Not for the always-allowed User-Agents and the allowed AI search bots: they cannot run the
			// script, so they keep the normal page limit.
			if ( ! empty( $s['human_check'] ) && ! $allowed_ua && (int) $s['rate_limit_unverified'] > 0 && ! PNCP_Human::verified( $ip ) ) {
				$stricter['rate_unverified'] = (int) $s['rate_limit_unverified'];
				PNCP_Human::forget_invalid();
			}
			if ( '' !== $country && (int) $s['rate_limit_country'] > 0 && in_array( $country, PNCP_Options::parse_countries( $s['countries_strict'] ), true ) ) {
				$stricter['rate_country'] = (int) $s['rate_limit_country'];
			}
			foreach ( $stricter as $bucket => $limit ) {
				$current = self::hit( $ip, $bucket );
				if ( $current > $limit ) {
					if ( $current === $limit + 1 ) {
						PNCP_Log::strike( $ip, $bucket );
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
					PNCP_Log::strike( $ip, 'rate_404' );
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
				$count = self::hit( $ip, $limits[ $context ][1] );
				if ( $count > $limit ) {
					// One "violation" per minute in which the limit was exceeded, not one per request.
					if ( $count === $limit + 1 ) {
						PNCP_Log::strike( $ip, $limits[ $context ][1] );
					}
					return self::verdict( 429, $limits[ $context ][1], $ip );
				}
			}
		}

		return null;
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
			|| (bool) preg_match( '#^/(?:favicon|apple-touch-icon|android-chrome|mstile|browserconfig|site\.webmanifest|manifest\.json|ads\.txt|app-ads\.txt|\.well-known/)#', $path );
		return (bool) apply_filters( 'pncp_404_exempt', $exempt, $path );
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
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check of a public parameter.
		$author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : '';
		return '' !== $author && ! is_admin() && preg_match( '/^-?\d/', $author ) && self::blocks_user_enum();
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
	 * @param int    $code   HTTP status code.
	 * @param string $reason Reason.
	 * @param string $ip     IP.
	 * @return array{code:int, reason:string}
	 */
	private static function verdict( $code, $reason, $ip ) {
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
		PNCP_Log::cache_set( $budget, $used + 1, 2 * MINUTE_IN_SECONDS );

		$verified = false;
		$host     = (string) apply_filters( 'pncp_reverse_dns', null, $ip );
		if ( '' === $host ) {
			$host = (string) gethostbyaddr( $ip );
		}
		if ( '' === $host || $host === $ip ) {
			// No PTR record or DNS failure: perhaps temporary, so it is retried in 5 minutes.
			self::$verify_inconclusive = true;
			PNCP_Log::cache_set( $key, 'unknown', 5 * MINUTE_IN_SECONDS );
			return false;
		}
		$host_lc = strtolower( rtrim( $host, '.' ) );
		foreach ( $def['dns'] as $domain ) {
			if ( substr( $host_lc, -strlen( $domain ) ) === $domain ) {
				$verified = in_array( $ip, self::forward_ips( $host_lc ), true );
				break;
			}
		}

		PNCP_Log::cache_set( $key, $verified ? 'yes' : 'no', $verified ? DAY_IN_SECONDS : HOUR_IN_SECONDS );
		return $verified;
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
	 * @return string[]
	 */
	private static function forward_ips( $host ) {
		$pre = apply_filters( 'pncp_forward_dns', null, $host );
		if ( is_array( $pre ) ) {
			return $pre;
		}
		$ips     = array();
		$records = @dns_get_record( $host, DNS_A | DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- DNS failure = unverified.
		if ( is_array( $records ) ) {
			foreach ( $records as $record ) {
				if ( ! empty( $record['ip'] ) ) {
					$ips[] = $record['ip'];
				}
				if ( ! empty( $record['ipv6'] ) ) {
					$ips[] = inet_ntop( inet_pton( $record['ipv6'] ) );
				}
			}
		}
		return $ips;
	}

	/**
	 * Counts the IP's requests in the current minute, per type (IPv6: per /64, see PNCP_Ip::limit_key()).
	 * Object cache if available, otherwise a transient.
	 *
	 * @param string      $ip     IP.
	 * @param string      $bucket Type (rate_page, rate_search, rate_rest).
	 * @param string|null $net    Key to count under instead of the IP's own (e.g. its IPv6 /56).
	 * @return int
	 */
	private static function hit( $ip, $bucket, $net = null ) {
		$key = 'pncp_rl_' . md5( $bucket . '|' . ( null === $net ? PNCP_Ip::limit_key( $ip ) : $net ) ) . '_' . (int) floor( time() / MINUTE_IN_SECONDS );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_add( $key, 0, 'pncp', 2 * MINUTE_IN_SECONDS );
			return (int) wp_cache_incr( $key, 1, 'pncp' );
		}
		$count = self::db_incr( $key, 2 * MINUTE_IN_SECONDS );
		if ( null !== $count ) {
			return $count;
		}
		// Database without ON DUPLICATE KEY (e.g. SQLite): plain transient, not atomic.
		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, 2 * MINUTE_IN_SECONDS );
		return $count;
	}

	/**
	 * Atomic counter in the database, for sites without an object cache. With concurrent requests, the "read +1
	 * write" of transients loses counts (confirmed: limit 50, up to 65 got through). Here the increment
	 * happens inside MySQL and the new value is read with LAST_INSERT_ID() on the same connection.
	 * It is stored as a regular transient (with timeout), so WordPress cleans it up like all transients.
	 *
	 * @param string $key Transient key.
	 * @param int    $ttl Seconds.
	 * @return int|null Null if the database does not support it.
	 */
	private static function db_incr( $key, $ttl ) {
		global $wpdb;
		if ( ! ( $wpdb instanceof wpdb ) || ! ( $wpdb->dbh instanceof mysqli ) ) {
			return null;
		}
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Atomic counter: not possible with the options API.
		$rows = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, '1', 'off')
				ON DUPLICATE KEY UPDATE option_value = LAST_INSERT_ID(option_value + 1)",
				'_transient_' . $key
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
			$count = 1;
		} else {
			// No separate SELECT LAST_INSERT_ID(): with HyperDB / read-write split it would go to a replica.
			$count = $insert_id;
			if ( $count < 2 ) {
				$wpdb->suppress_errors( $suppress );
				return null; // Unexpected: fall back to the transient.
			}
		}
		// phpcs:enable
		$wpdb->suppress_errors( $suppress );
		return $count;
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
	 * Whoever opens the trap gets blocked.
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
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = PNCP_Private_Urls::relative_path( rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) ) );
		if ( 0 !== stripos( trailingslashit( $path ), self::trap_path() ) ) {
			return;
		}

		self::no_cache();
		header( 'X-Robots-Tag: noindex, nofollow' );

		$ip = PNCP_Ip::client_ip();
		if ( self::trap_should_ban( $ip ) ) {
			PNCP_Log::add( 'trap', 403, $ip );
			// "Block after 0 violations" = never block: log only.
			if ( (int) $s['ban_strikes'] > 0 ) {
				PNCP_Log::ban( $ip, (int) $s['ban_minutes'], 'trap' );
			}
		}

		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo 'Forbidden';
		exit;
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
		if ( '' !== $ua && ( self::allow_list_match( $ua, $ip, $s ) || self::ua_in_list( $ua, PNCP_Options::allowed_ai_search() ) ) ) {
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
			$key  = 'pncp_tr_' . md5( PNCP_Ip::limit_key( $ip ) );
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
