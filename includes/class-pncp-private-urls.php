<?php
/**
 * Protected feeds: product XML (Skroutz, BestPrice, Google Merchant, etc.) and anything else that serves the full
 * text in a single file. Access only with a secret token or from allowed IPs.
 *
 * The token is accepted:
 * - in the X-Content-Protect-Token or Authorization: Bearer … header (for ERPs and your own integrations);
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

		return current_user_can( 'manage_options' ) ? 'admin' : '';
	}

	/**
	 * The token from X-Content-Protect-Token or Authorization: Bearer.
	 * Apache with PHP-FPM/CGI hides Authorization: see the rule in the README.
	 *
	 * @return string
	 */
	private static function header_token() {
		foreach ( array( 'HTTP_X_CONTENT_PROTECT_TOKEN' ) as $key ) {
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
			$row['last_ip']  = PNCP_Ip::client_ip();
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
		$path = self::relative_path( rawurldecode( (string) wp_parse_url( (string) $uri, PHP_URL_PATH ) ) );
		// WordPress also accepts the /index.php/path form.
		if ( 0 === stripos( $path, '/index.php/' ) ) {
			$path = substr( $path, strlen( '/index.php' ) );
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
	 * The first pattern that matches the path ('' = none). * means "anything".
	 *
	 * @param string   $path     Path.
	 * @param string[] $patterns Patterns (paths or full URLs).
	 * @return string
	 */
	public static function matching_pattern( $path, $patterns ) {
		foreach ( $patterns as $pattern ) {
			$p = (string) wp_parse_url( $pattern, PHP_URL_PATH );
			if ( '' === $p ) {
				continue;
			}
			$p = self::relative_path( $p );
			// With or without a trailing / (WordPress accepts both for most paths).
			$regex = '#^' . str_replace( '\*', '.*', preg_quote( untrailingslashit( $p ), '#' ) ) . '/?$#i';
			if ( preg_match( $regex, $path ) ) {
				return $pattern;
			}
		}
		return '';
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
		$path = self::relative_path( (string) wp_parse_url( $pattern, PHP_URL_PATH ) );
		if ( false !== strpos( $path, '*' ) ) {
			$path = '/feed.xml'; // Pattern with *: we show a generic example.
		}
		return add_query_arg( self::QUERY_ARG, rawurlencode( $token ), home_url( $path ) );
	}
}
