<?php
/**
 * Protected feeds: product XML (Skroutz, BestPrice, Google Merchant, etc.) and anything else that serves the full
 * text in a single file. Access only with a secret token or from allowed IPs.
 *
 * The token is accepted:
 * - in the X-ScrapeLock-Token or Authorization: Bearer … header (for ERPs and your own integrations);
 * - in the URL, ?cp_token=… (for Skroutz, BestPrice, Google Merchant, which accept only a URL).
 *
 * Only the token's SHA-256 is stored in the database. The token is shown once, when it is created.
 * On rotation, the old token stays valid for a few more days (grace period).
 *
 * Applies to URLs served by PHP. Static files (e.g. .xml inside uploads) are served
 * directly by the web server; for those see the server rules.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Access control for URLs in the list.
 */
final class PNCP_Private_Urls {

	const QUERY_ARG = 'cp_token';

	/**
	 * Option holding the token hashes (not autoloaded).
	 */
	const TOKEN_OPTION = 'pncp_feed_token';

	/**
	 * Option holding the per-pattern statistics (not autoloaded).
	 */
	const STATS_OPTION = 'pncp_feed_stats';

	/**
	 * 3.4.3: transient holding the query variables that the rewrite rules behind the patterns with * set,
	 * with the hash of the patterns and rules they were computed from.
	 */
	const VARS_TRANSIENT = 'pncp_private_vars';

	/**
	 * Core query variables that ordinary pages also use: a rule that sets only these is not a feed of its own.
	 */
	const CORE_VARS = array( 'p', 'page_id', 'name', 'pagename', 'attachment', 'attachment_id', 'subpost', 'subpost_id', 'paged', 'page', 'cpage', 'year', 'monthnum', 'day', 'hour', 'minute', 'second', 'w', 'm', 'author', 'author_name', 'cat', 'category_name', 'tag', 'tag_id', 'taxonomy', 'term', 's', 'search', 'post_type', 'post_format', 'feed', 'embed', 'tb', 'withcomments', 'withoutcomments', 'preview', 'static', 'error', 'order', 'orderby' );

	/**
	 * Whether the current request passed the check (so the bot check does not block it afterwards).
	 *
	 * @var bool
	 */
	private static $granted = false;

	/**
	 * Attaches the hooks. Runs early, before the feed plugins output the XML.
	 */
	public static function init() {
		add_action( 'plugins_loaded', array( __CLASS__, 'guard' ), 0 );
		add_action( 'parse_request', array( __CLASS__, 'guard_resolved' ), 0 );
	}

	/**
	 * Did the current request pass the private URL check?
	 *
	 * @return bool
	 */
	public static function granted() {
		return self::$granted;
	}

	/**
	 * Blocks (403) when the URL is in the list and there is no valid token or allowed IP.
	 */
	public static function guard() {
		self::$granted = false;
		$s             = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || '' === trim( (string) $s['private_paths'] ) ) {
			return;
		}

		$path    = self::request_path();
		$pattern = '' === $path ? '' : self::matching_pattern( $path, PNCP_Options::parse_list( $s['private_paths'] ) );
		if ( '' === $pattern ) {
			return;
		}
		self::protect( $pattern, $s );
	}

	/**
	 * Lets the request through (valid token or allowed IP) or stops it with a 403.
	 *
	 * @param string               $pattern The pattern the request matched.
	 * @param array<string, mixed> $s       Settings.
	 */
	private static function protect( $pattern, $s ) {
		// Not even the successful response goes into a shared cache: many CDNs ignore the query string,
		// so the feed with the token would afterwards be served without a token too.
		PNCP_Bots::no_cache();
		header( 'Cache-Control: private, no-store, max-age=0' );
		header( 'X-Robots-Tag: noindex, nofollow' );
		// The token may be in the URL: it must not leak via Referer to other sites.
		header( 'Referrer-Policy: no-referrer' );
		header( 'X-Content-Type-Options: nosniff' );

		$via = self::access_via( $s );
		self::record( $pattern, $via );
		if ( '' !== $via ) {
			self::$granted = true;
			return;
		}

		PNCP_Log::add( 'feed_denied', 403, PNCP_Ip::client_ip() );
		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		// No translation: runs before translations are loaded (init).
		echo 'Forbidden';
		exit;
	}

	/**
	 * How access is granted: 'header', 'url', 'ip', 'admin' or '' (not allowed).
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	public static function access_via( $s ) {
		$header = self::header_token();
		if ( '' !== $header && self::token_valid( $header ) ) {
			return 'header';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Access token, not a form.
		$query = isset( $_GET[ self::QUERY_ARG ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::QUERY_ARG ] ) ) : '';
		if ( '' !== $query && self::token_valid( $query ) ) {
			return 'url';
		}

		$ip = PNCP_Ip::client_ip();
		if ( '' !== $ip && PNCP_Ip::reliable() && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['private_ips'] ) ) ) {
			return 'ip';
		}

		return PNCP_Lockdown::can( 'manage_options' ) ? 'admin' : '';
	}

	/**
	 * The token from X-ScrapeLock-Token or Authorization: Bearer. The header of the old name
	 * (X-Content-Protect-Token) is still accepted, so existing integrations keep working.
	 * Apache with PHP-FPM/CGI hides Authorization: see the rule in the README.
	 *
	 * @return string
	 */
	private static function header_token() {
		foreach ( array( 'HTTP_X_SCRAPELOCK_TOKEN', 'HTTP_X_CONTENT_PROTECT_TOKEN' ) as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				return trim( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) );
			}
		}
		foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$value = trim( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) );
				if ( 0 === stripos( $value, 'Bearer ' ) ) {
					return trim( substr( $value, 7 ) );
				}
			}
		}
		return '';
	}

	/* ---------- Tokens ---------- */

	/**
	 * The stored token data.
	 *
	 * @return array{hash:string, hint:string, created:int, prev_hash:string, prev_hint:string, prev_until:int}
	 */
	public static function token_data() {
		$data = get_option( self::TOKEN_OPTION, array() );
		$data = is_array( $data ) ? $data : array();
		return array(
			'hash'       => isset( $data['hash'] ) ? (string) $data['hash'] : '',
			'hint'       => isset( $data['hint'] ) ? (string) $data['hint'] : '',
			'created'    => isset( $data['created'] ) ? (int) $data['created'] : 0,
			'prev_hash'  => isset( $data['prev_hash'] ) ? (string) $data['prev_hash'] : '',
			'prev_hint'  => isset( $data['prev_hint'] ) ? (string) $data['prev_hint'] : '',
			'prev_until' => isset( $data['prev_until'] ) ? (int) $data['prev_until'] : 0,
		);
	}

	/**
	 * Hash of a token.
	 *
	 * @param string $token Token.
	 * @return string
	 */
	public static function hash( $token ) {
		return hash( 'sha256', (string) $token );
	}

	/**
	 * Is the token valid? (the current one, or the previous one within the grace period)
	 *
	 * @param string $token Token.
	 * @return bool
	 */
	public static function token_valid( $token ) {
		$token = (string) $token;
		if ( strlen( $token ) < 16 ) {
			return false;
		}
		$data = self::token_data();
		$hash = self::hash( $token );
		if ( '' !== $data['hash'] && hash_equals( $data['hash'], $hash ) ) {
			return true;
		}
		return '' !== $data['prev_hash'] && $data['prev_until'] > time() && hash_equals( $data['prev_hash'], $hash );
	}

	/**
	 * New token. The previous one stays valid for $grace_days more days (0 = revoked immediately).
	 *
	 * @param int $grace_days Grace days.
	 * @return string The new token (not stored anywhere in plain form).
	 */
	public static function rotate( $grace_days ) {
		$old        = self::token_data();
		$token      = wp_generate_password( 40, false, false );
		$data       = array(
			'hash'       => self::hash( $token ),
			'hint'       => substr( $token, -4 ),
			'created'    => time(),
			'prev_hash'  => '',
			'prev_hint'  => '',
			'prev_until' => 0,
		);
		$grace_days = max( 0, min( 90, (int) $grace_days ) );
		if ( '' !== $old['hash'] && $grace_days > 0 ) {
			$data['prev_hash']  = $old['hash'];
			$data['prev_hint']  = $old['hint'];
			$data['prev_until'] = time() + $grace_days * DAY_IN_SECONDS;
		}
		update_option( self::TOKEN_OPTION, $data, false );
		return $token;
	}

	/**
	 * Stores an existing token (migration from 1.4, where the token was in plain form).
	 *
	 * @param string $token Token.
	 */
	public static function import_plain( $token ) {
		$token = (string) $token;
		if ( strlen( $token ) < 16 ) {
			return;
		}
		update_option(
			self::TOKEN_OPTION,
			array(
				'hash'       => self::hash( $token ),
				'hint'       => substr( $token, -4 ),
				'created'    => time(),
				'prev_hash'  => '',
				'prev_hint'  => '',
				'prev_until' => 0,
			),
			false
		);
	}

	/**
	 * Revokes the previous token immediately.
	 */
	public static function revoke_previous() {
		$data               = self::token_data();
		$data['prev_hash']  = '';
		$data['prev_hint']  = '';
		$data['prev_until'] = 0;
		update_option( self::TOKEN_OPTION, $data, false );
	}

	/* ---------- Statistics ---------- */

	/**
	 * Records access to the pattern: counters, last successful access and method.
	 *
	 * @param string $pattern Pattern from the list.
	 * @param string $via     Access method ('' = denied).
	 */
	private static function record( $pattern, $via ) {
		$stats = self::stats();
		$key   = strtolower( $pattern );
		$row   = isset( $stats[ $key ] ) ? $stats[ $key ] : array(
			'ok'        => 0,
			'denied'    => 0,
			'last_ok'   => 0,
			'last_via'  => '',
			'last_ip'   => '',
			'last_deny' => 0,
		);
		if ( '' === $via ) {
			// Denials can be caused by anyone: write to the database at most once a minute per path.
			$throttle = 'pncp_fd_' . md5( $key );
			if ( PNCP_Log::cache_get( $throttle ) ) {
				return;
			}
			PNCP_Log::cache_set( $throttle, 1, MINUTE_IN_SECONDS );
			++$row['denied'];
			$row['last_deny'] = time();
		} else {
			++$row['ok'];
			$row['last_ok']  = time();
			$row['last_via'] = $via;
			// Stored anonymised (IPv4: last octet zeroed, IPv6: last 80 bits), so no full personal IP is kept
			// indefinitely in an option (GDPR). It is only a hint of which network last used the feed.
			$ip             = PNCP_Ip::client_ip();
			$row['last_ip'] = ( '' !== $ip && function_exists( 'wp_privacy_anonymize_ip' ) ) ? wp_privacy_anonymize_ip( $ip ) : '';
		}
		$stats[ $key ] = $row;
		update_option( self::STATS_OPTION, array_slice( $stats, 0, 200, true ), false );
	}

	/**
	 * The statistics: pattern (lowercase) => data.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function stats() {
		$stats = get_option( self::STATS_OPTION, array() );
		return is_array( $stats ) ? $stats : array();
	}

	/* ---------- Paths ---------- */

	/**
	 * The request path, relative to the site root (e.g. /skroutz.xml).
	 *
	 * @return string
	 */
	private static function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared against patterns.
		// A request line that starts with // (//skroutz.xml) would be read as a host by wp_parse_url(), with no path
		// at all, while WordPress still serves the page: the leading slashes count as one.
		$uri  = preg_replace( '#^/{2,}#', '/', (string) $uri );
		$path = wp_parse_url( (string) $uri, PHP_URL_PATH );
		if ( false === $path ) {
			// 3.4.3: wp_parse_url() gives up on some request targets (http://host:99999/feeds/x.xml, http:///feeds/x.xml),
			// while the web server may still hand them to WordPress. Split by hand: no query, no fragment,
			// no scheme and host.
			$path = substr( (string) $uri, 0, strcspn( (string) $uri, '?#' ) );
			$path = preg_replace( '#^[a-z][a-z0-9+.-]*://[^/]*#i', '', $path );
		}
		$path = rawurldecode( (string) $path );
		// Repeated slashes inside the path (/feeds//skroutz.xml) are one, as for the web server and WordPress.
		$path = (string) preg_replace( '#/{2,}#', '/', $path );
		// 3.4: what comes after a ";" (path parameters, e.g. /skroutz.xml;x) or an encoded NUL (%00) is not part of
		// the path to compare: code that matches the address loosely may still answer such a request.
		$cut = strcspn( $path, ";\0" );
		if ( $cut < strlen( $path ) ) {
			$path = substr( $path, 0, $cut );
		}
		// Trailing spaces, control characters and dots (/skroutz.xml%20, /skroutz.xml.) are not part of it either,
		// nor extra trailing slashes (/skroutz.xml//): WordPress trims them all before it matches its rewrite rules.
		$path = rtrim( $path, " ./\t\n\r\0\x0B\x0C" );
		$path = self::relative_path( $path );
		// WordPress also accepts the /index.php/path form.
		if ( 0 === stripos( $path, '/index.php/' ) ) {
			$path = substr( $path, strlen( '/index.php' ) );
		} elseif ( 0 === strcasecmp( $path, '/index.php' ) ) {
			$path = '/'; // 3.4.1: /index.php?feed=x is the homepage with that query.
		}
		return $path;
	}

	/**
	 * Strips the installation subfolder (e.g. /blog) from a path.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function relative_path( $path ) {
		$path = '/' . ltrim( (string) $path, '/' );
		$home = rtrim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		return $path;
	}

	/**
	 * A pattern split into the path to match and the query arguments the request must carry. A pattern with
	 * only a query (e.g. https://site/?feed=skroutz) is that query on the homepage. A pattern without a query
	 * that would match the homepage or every page ("/", "*", "/*") is refused: it would lock the whole site.
	 *
	 * @param string $pattern Pattern (path or full URL).
	 * @return array{path:string, query:array<string, string>}|null Null when the pattern is not usable.
	 */
	public static function parse_pattern( $pattern ) {
		$pattern = (string) $pattern;
		$path    = (string) wp_parse_url( $pattern, PHP_URL_PATH );
		$raw     = (string) wp_parse_url( $pattern, PHP_URL_QUERY );
		$query   = array();
		if ( '' !== $raw ) {
			parse_str( $raw, $args );
			foreach ( (array) $args as $key => $value ) {
				if ( self::QUERY_ARG !== (string) $key && is_scalar( $value ) ) {
					$query[ (string) $key ] = (string) $value;
				}
			}
		}
		if ( '' === $path && ! $query ) {
			return null;
		}
		$path = self::relative_path( '' === $path ? '/' : $path );
		if ( ! $query && '' === trim( $path, '/*' ) ) {
			return null;
		}
		return array(
			'path'  => $path,
			'query' => $query,
		);
	}

	/**
	 * The first pattern that matches the request ('' = none). * means "anything" in the path. A query argument
	 * in a pattern must be in the request with the same value (* = any value).
	 *
	 * @param string                    $path     Path.
	 * @param string[]                  $patterns Patterns (paths or full URLs).
	 * @param array<string, mixed>|null $query    The request's query arguments (null = this request's).
	 * @return string
	 */
	public static function matching_pattern( $path, $patterns, $query = null ) {
		if ( null === $query ) {
			$query = wp_unslash( $_GET ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only compared against the patterns.
		}
		foreach ( $patterns as $pattern ) {
			$parsed = self::parse_pattern( $pattern );
			if ( null === $parsed ) {
				continue;
			}
			// With or without a trailing / (WordPress accepts both for most paths).
			$regex = '#^' . str_replace( '\*', '.*', preg_quote( untrailingslashit( $parsed['path'] ), '#' ) ) . '/?$#i';
			if ( ! preg_match( $regex, $path ) ) {
				continue;
			}
			foreach ( $parsed['query'] as $key => $value ) {
				if ( ! isset( $query[ $key ] ) || ! self::same_value( $key, $query[ $key ], $value ) ) {
					continue 2;
				}
			}
			return $pattern;
		}
		return '';
	}

	/**
	 * Does a query value ask for the same thing as the pattern's value? For "feed", WordPress drops leading
	 * underscores before it runs the feed (do_feed()), so ?feed=_skroutz is the same feed as ?feed=skroutz.
	 *
	 * 3.4.3: a value of 1 is a flag (a rewrite rule sets skroutz_feed=1), and the code that serves the feed reads it
	 * as a boolean (if ( get_query_var( 'skroutz_feed' ) )): ?skroutz_feed=01, =yes, =1%20 or skroutz_feed[]=1 is
	 * the same feed, so any value PHP reads as true matches it.
	 *
	 * @param string $key   Query variable.
	 * @param mixed  $got   Value in the request.
	 * @param string $value Value in the pattern (* = any).
	 * @return bool
	 */
	private static function same_value( $key, $got, $value ) {
		if ( '1' === $value && ( is_scalar( $got ) || is_array( $got ) ) ) {
			return (bool) $got;
		}
		if ( ! is_scalar( $got ) ) {
			return false;
		}
		$got = (string) $got;
		if ( '*' === $value ) {
			return true;
		}
		if ( 'feed' === $key ) {
			return ltrim( $got, '_' ) === ltrim( $value, '_' );
		}
		return $got === $value;
	}

	/**
	 * The query variables a pattern resolves to through the rewrite rules (e.g. /skroutz.xml =>
	 * skroutz_feed=1), so that the same feed asked for as /?skroutz_feed=1 is protected too. Only for
	 * patterns without * and without a query of their own.
	 *
	 * 3.4.1: a pattern that is only a query on the homepage (https://site/?feed=skroutz) resolves to that query
	 * itself, so the same feed at its pretty addresses (/feed/skroutz/, /shop/feed/skroutz/, …) is protected
	 * too. A value of * then means any value.
	 *
	 * @param string $pattern Pattern.
	 * @return array<string, string>
	 */
	private static function resolved_vars( $pattern ) {
		global $wp_rewrite;
		$parsed = self::parse_pattern( $pattern );
		if ( null !== $parsed && $parsed['query'] && '/' === $parsed['path'] ) {
			return $parsed['query'];
		}
		if ( null === $parsed || $parsed['query'] || false !== strpos( $parsed['path'], '*' ) || ! $wp_rewrite instanceof WP_Rewrite ) {
			return array();
		}
		$rules = $wp_rewrite->wp_rewrite_rules();
		if ( ! is_array( $rules ) ) {
			return array();
		}
		$request = ltrim( $parsed['path'], '/' );
		foreach ( $rules as $match => $target ) {
			if ( preg_match( '#^' . $match . '#', $request, $matches ) || preg_match( '#^' . $match . '#', urldecode( $request ), $matches ) ) {
				$query = preg_replace( '!^.+\?!', '', (string) $target );
				$query = class_exists( 'WP_MatchesMapRegex' ) ? WP_MatchesMapRegex::apply( $query, $matches ) : $query;
				parse_str( (string) $query, $vars );
				$out = array();
				foreach ( (array) $vars as $key => $value ) {
					if ( is_scalar( $value ) && '' !== (string) $value ) {
						$out[ (string) $key ] = (string) $value;
					}
				}
				return $out;
			}
		}
		return array();
	}

	/**
	 * After WordPress has read the request: a protected feed reached by its query variables instead of its
	 * address (/?feed_var=1 for /feed.xml) gets the same check as the address.
	 *
	 * @param WP $wp The request.
	 */
	public static function guard_resolved( $wp ) {
		if ( self::$granted || ! $wp instanceof WP ) {
			return;
		}
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || '' === trim( (string) $s['private_paths'] ) ) {
			return;
		}
		$vars = (array) $wp->query_vars;
		foreach ( PNCP_Options::parse_list( $s['private_paths'] ) as $pattern ) {
			$want = self::resolved_vars( $pattern );
			if ( ! $want ) {
				continue;
			}
			foreach ( $want as $key => $value ) {
				if ( ! isset( $vars[ $key ] ) || ! self::same_value( $key, $vars[ $key ], $value ) ) {
					continue 2;
				}
			}
			self::protect( $pattern, $s );
			return;
		}
		// 3.4.3: patterns with * (/feeds/*.xml) through the query variables of the rewrite rules that serve them
		// (/?skroutz_feed=abc for ^feeds/([a-z]+)\.xml$ => skroutz_feed=$matches[1]). A request that came through
		// the pretty address was already checked by guard(); this catches the same feed asked for by its variables,
		// on any path (/, /index.php, /some-post/).
		foreach ( self::wildcard_vars( PNCP_Options::parse_list( $s['private_paths'] ) ) as $pattern => $sets ) {
			foreach ( $sets as $want ) {
				foreach ( $want as $key => $value ) {
					if ( ! isset( $vars[ $key ] ) || ! self::wildcard_value( $key, $vars[ $key ], $value ) ) {
						continue 2;
					}
				}
				self::protect( $pattern, $s );
				return;
			}
		}
	}

	/**
	 * 3.4.3: does a query value match a value of wildcard_vars()? * = any non-empty value.
	 *
	 * @param string $key   Query variable.
	 * @param mixed  $got   Value in the request.
	 * @param string $value Value the rule sets (* = from the address).
	 * @return bool
	 */
	private static function wildcard_value( $key, $got, $value ) {
		if ( '*' !== $value ) {
			return self::same_value( $key, $got, $value );
		}
		return is_array( $got ) ? ! empty( $got ) : ( is_scalar( $got ) && '' !== (string) $got );
	}

	/**
	 * 3.4.3: for each pattern with * (and no query of its own), the query variables of the rewrite rules whose
	 * address falls under the pattern: pattern => list of (variable => value, * = taken from the address).
	 * A rule's address is its regex with every group, class and quantifier replaced by a probe
	 * (^feeds/([a-z]+)\.xml$ => /feeds/x.xml). Rules that set only core variables (pagename, paged, feed, …)
	 * are left out: those are ordinary pages, and the pattern still protects their address.
	 *
	 * Computed once per set of patterns and rules, and kept in a transient.
	 *
	 * @param string[] $patterns Patterns.
	 * @return array<string, array<int, array<string, string>>>
	 */
	private static function wildcard_vars( $patterns ) {
		global $wp_rewrite;
		$wild = array();
		foreach ( $patterns as $pattern ) {
			$parsed = self::parse_pattern( $pattern );
			if ( null !== $parsed && ! $parsed['query'] && false !== strpos( $parsed['path'], '*' ) ) {
				$wild[] = (string) $pattern;
			}
		}
		if ( ! $wild || ! $wp_rewrite instanceof WP_Rewrite ) {
			return array();
		}
		$rules = $wp_rewrite->wp_rewrite_rules();
		if ( ! is_array( $rules ) || ! $rules ) {
			return array();
		}
		$hash   = md5( serialize( array( $wild, $rules ) ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Only hashed.
		$cached = get_transient( self::VARS_TRANSIENT );
		if ( is_array( $cached ) && isset( $cached['hash'], $cached['vars'] ) && $hash === $cached['hash'] && is_array( $cached['vars'] ) ) {
			return $cached['vars'];
		}

		$out = array();
		foreach ( $rules as $match => $target ) {
			$sample = self::rule_sample( (string) $match );
			$query  = preg_replace( '!^.+\?!', '', (string) $target );
			parse_str( (string) $query, $args );
			$set = array();
			foreach ( (array) $args as $key => $value ) {
				if ( ! is_scalar( $value ) || '' === (string) $value ) {
					continue;
				}
				$set[ (string) $key ] = false !== strpos( (string) $value, '$matches[' ) ? '*' : (string) $value;
			}
			if ( ! $set || ! array_diff( array_keys( $set ), self::CORE_VARS ) ) {
				continue;
			}
			foreach ( $wild as $pattern ) {
				if ( '' !== self::matching_pattern( $sample, array( $pattern ), array() ) && ( ! isset( $out[ $pattern ] ) || ! in_array( $set, $out[ $pattern ], true ) ) ) {
					$out[ $pattern ][] = $set;
				}
			}
		}
		// No expiration: one autoloaded row, replaced when the patterns or the rules change.
		set_transient(
			self::VARS_TRANSIENT,
			array(
				'hash' => $hash,
				'vars' => $out,
			)
		);
		return $out;
	}

	/**
	 * 3.4.3: a sample address of a rewrite rule's regex (^feeds/([a-z]+)\.xml$ => /feeds/x.xml).
	 *
	 * @param string $regex Rule regex.
	 * @return string
	 */
	private static function rule_sample( $regex ) {
		$sample = (string) preg_replace( '#^\^|\$$#', '', $regex );
		// Escaped characters are set aside first, so the steps below do not read them as syntax.
		// \d, \w, … (classes) become the probe, \. and the like the character itself.
		$escaped = array();
		$sample  = (string) preg_replace_callback(
			'#\\\\(.)#s',
			function ( $m ) use ( &$escaped ) {
				$escaped[] = preg_match( '#^[a-z0-9]$#i', $m[1] ) ? 'x' : $m[1];
				return "\0" . ( count( $escaped ) - 1 ) . "\1";
			},
			$sample
		);
		$sample = (string) preg_replace( '#\[\^?\]?[^\]]*\]#', 'x', $sample );
		$sample = str_replace( '.', 'x', $sample );
		do {
			$sample = (string) preg_replace( '#\([^()]*\)#', 'x', $sample, -1, $count );
		} while ( $count > 0 );
		$sample = (string) preg_replace( '#\{\d*,?\d*\}|[?*+]#', '', $sample );
		$sample = (string) preg_replace_callback(
			'#\x00(\d+)\x01#',
			function ( $m ) use ( $escaped ) {
				return isset( $escaped[ (int) $m[1] ] ) ? $escaped[ (int) $m[1] ] : '';
			},
			$sample
		);
		return '/' . ltrim( $sample, '/' );
	}

	/**
	 * Does the path match any pattern?
	 *
	 * @param string   $path     Path.
	 * @param string[] $patterns Patterns.
	 * @return bool
	 */
	public static function path_matches( $path, $patterns ) {
		return '' !== self::matching_pattern( $path, $patterns );
	}

	/**
	 * Does the IP belong to an IP or CIDR? (for compatibility with 1.4)
	 *
	 * @param string $ip    IP.
	 * @param string $range IP or CIDR.
	 * @return bool
	 */
	public static function ip_in_range( $ip, $range ) {
		return PNCP_Ip::in_range( $ip, $range );
	}

	/**
	 * The URL of a pattern with the token, for the settings page.
	 *
	 * @param string $pattern Pattern.
	 * @param string $token   Token.
	 * @return string
	 */
	public static function example_url( $pattern, $token ) {
		$parsed = self::parse_pattern( $pattern );
		$path   = null === $parsed ? '/feed.xml' : $parsed['path'];
		if ( false !== strpos( $path, '*' ) ) {
			$path = '/feed.xml'; // Pattern with *: we show a generic example.
		}
		$url = home_url( $path );
		if ( null !== $parsed && $parsed['query'] ) {
			$url = add_query_arg( array_map( 'rawurlencode', $parsed['query'] ), $url );
		}
		return add_query_arg( self::QUERY_ARG, rawurlencode( $token ), $url );
	}
}
