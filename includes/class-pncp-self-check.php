<?php
/**
 * 3.12.2: the site's requests to itself, made visible.
 *
 * Behind Bunny the site's own checks ("Check again" in Vulnerable points, Site Health, the Stealth test) leave
 * the server, pass the CDN and come back. When something on that way refuses them, the owner only saw "the home
 * page answered HTTP 403 to the site itself", and could not tell who refused: ScrapeLock, the CDN's edge, a
 * firewall plugin (Wordfence) or the web server.
 *
 * - Receiving side: every request that carries the site's signature (X-ScrapeLock-Sig, valid or not) and every
 *   refused request from one of the server's addresses is noted in a small ring buffer (option LOG, not
 *   autoloaded, at most MAX entries, a few writes a minute at most): the layer that decided (early check,
 *   pre-cache check, WordPress, "Only through the CDN", Vulnerable points), the verdict and its reason, and the
 *   result of the signature check with its reason (PNCP_Server_Ips::sig_check()). Never an IP address, a
 *   User-Agent, a cookie or a query string: the host, the path, the method and whether it came from the server,
 *   a CDN edge or elsewhere.
 * - ScrapeLock's own refusals carry the header "X-ScrapeLock: refused" (marker()); for a request that carries the
 *   signature also the layer and the signature's result, and for the site's own request (its MAC matched) the
 *   reason. A request with a valid signature that passes gets "X-ScrapeLock: ok", so the sending side knows the
 *   answer came from this WordPress.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Diagnostics of the site's requests to itself.
 */
final class PNCP_Self_Check {

	/**
	 * Option (not autoloaded): the ring buffer of the site's own requests, newest first.
	 */
	const LOG = 'pncp_selfcheck_log';

	/**
	 * Most entries kept.
	 */
	const MAX = 30;

	/**
	 * The response header of ScrapeLock's refusals and of the answers to the site's signed requests.
	 */
	const HEADER = 'X-ScrapeLock';

	/**
	 * Entries written in a minute at most (for a signature that is not the site's own: LIMIT_OTHER).
	 */
	const LIMIT = 60;

	/**
	 * Entries written in a minute at most for requests whose signature is not the site's (anyone can send one).
	 */
	const LIMIT_OTHER = 5;

	/**
	 * The receiving side's entry of this request, or null.
	 *
	 * @var array<string, mixed>|null
	 */
	private static $entry = null;

	/**
	 * The layer that is checking this request now.
	 *
	 * @var string
	 */
	private static $layer = 'wp';

	/**
	 * Whether the refusal header was sent in this request.
	 *
	 * @var bool
	 */
	private static $marked = false;

	/**
	 * The layer that checks the request from now on (early, wp = ScrapeLock in WordPress, origin, hardening).
	 *
	 * @param string $layer Layer.
	 */
	public static function set_layer( $layer ) {
		self::$layer = sanitize_key( (string) $layer );
	}

	/**
	 * The signature of this request was checked (PNCP_Server_Ips::sig_check()): starts this request's entry, and
	 * marks the answer to a valid one ("X-ScrapeLock: ok").
	 *
	 * @param array{result:string, host:string, received:string, authentic:bool} $check The check.
	 */
	public static function note_sig( $check ) {
		if ( 'none' === $check['result'] ) {
			return;
		}
		$entry = self::entry();
		if ( '' === $entry['sig'] ) {
			$entry['sig']       = (string) $check['result'];
			$entry['sig_host']  = (string) $check['host'];
			$entry['authentic'] = (bool) $check['authentic'];
			$entry['checked']   = self::$layer;
		}
		self::$entry = $entry;
		if ( 'ok' === $check['result'] && ! self::$marked && ! headers_sent() ) {
			header( self::HEADER . ': ok' );
		}
	}

	/**
	 * A request was refused by ScrapeLock (PNCP_Log::add() of a 403 / 429, or a refusal of the server's own
	 * request that is not logged): sends the refusal header once and notes the reason in the entry of a request
	 * that carries the signature or comes from one of the server's addresses.
	 *
	 * @param string    $reason Reason key.
	 * @param int       $code   Status code.
	 * @param bool|null $own    Whether the request is the site's own (null = from its signature).
	 */
	public static function refused( $reason, $code, $own = null ) {
		$code = (int) $code;
		if ( ! in_array( $code, array( 403, 429 ), true ) || ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) || ( class_exists( 'PNCP_Bots', false ) && PNCP_Bots::explaining() ) ) {
			return;
		}
		$sig  = null !== self::$entry ? (string) self::$entry['sig'] : '';
		$mine = null === $own ? null !== self::$entry && ! empty( self::$entry['authentic'] ) : (bool) $own;
		if ( ! self::$marked && ! headers_sent() ) {
			header_remove( self::HEADER );
			header( self::HEADER . ': ' . self::marker( (string) $reason, $sig, $mine ) );
			self::$marked = true;
		}
		$server = class_exists( 'PNCP_Server_Ips', false ) && class_exists( 'PNCP_Ip', false ) && PNCP_Server_Ips::is_server_ip( PNCP_Ip::client_ip() );
		if ( null === self::$entry && ! $server && ! $mine ) {
			return;
		}
		$entry = self::entry();
		if ( '' === $entry['reason'] ) {
			$entry['verdict'] = 'refused';
			$entry['reason']  = sanitize_key( (string) $reason );
			$entry['code']    = $code;
			$entry['layer']   = self::$layer;
		}
		self::$entry = $entry;
	}

	/**
	 * The value of the refusal header: "refused"; with a signature also its layer and result ("refused layer=wp
	 * sig=host_mismatch"); for the site's own request also the reason ("refused fake_browser layer=wp sig=
	 * nonce_reused"). The pre-cache check makes the same (PNCP_Precheck_Runtime::refusal_marker()). Free of personal
	 * data: no address, User-Agent or path.
	 *
	 * @param string $reason Reason key.
	 * @param string $sig    Result of the signature check ('' = no signature).
	 * @param bool   $own    Whether the request is the site's own.
	 * @return string
	 */
	public static function marker( $reason, $sig, $own ) {
		$out = 'refused';
		if ( $own && preg_match( '/^[a-z0-9_]{1,40}$/', (string) $reason ) ) {
			$out .= ' ' . $reason;
		}
		if ( '' !== (string) $sig ) {
			$out .= ' layer=' . self::$layer . ' sig=' . sanitize_key( (string) $sig );
		}
		return $out;
	}

	/**
	 * This request's entry (started when missing).
	 *
	 * @return array<string, mixed>
	 */
	private static function entry() {
		if ( null !== self::$entry ) {
			return self::$entry;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only its path is kept, cleaned below.
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$path = (string) preg_replace( '/[^\x21-\x7E]/', '', $path );
		$from = 'other';
		if ( class_exists( 'PNCP_Ip', false ) ) {
			$remote = PNCP_Ip::remote_addr();
			if ( PNCP_Ip::is_local( $remote ) ) {
				$from = 'local';
			} elseif ( PNCP_Ip::is_cdn( $remote ) ) {
				$from = 'cdn';
			} elseif ( class_exists( 'PNCP_Server_Ips', false ) && PNCP_Server_Ips::is_server_ip( $remote ) ) {
				$from = 'server';
			}
		}
		$pre         = class_exists( 'PNCP_Precheck_Runtime', false ) && property_exists( 'PNCP_Precheck_Runtime', 'self_result' ) ? (string) PNCP_Precheck_Runtime::$self_result : '';
		$method      = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		self::$entry = array(
			'side'      => 'in',
			'time'      => time(),
			'id'        => self::request_id(),
			'method'    => substr( $method, 0, 8 ),
			'host'      => class_exists( 'PNCP_Server_Ips', false ) ? substr( PNCP_Server_Ips::request_host(), 0, 100 ) : '',
			'path'      => substr( '' === $path ? '/' : $path, 0, 120 ),
			'from'      => $from,
			'sig'       => '',
			'sig_host'  => '',
			'authentic' => false,
			'checked'   => '',
			'precache'  => $pre,
			'verdict'   => 'passed',
			'reason'    => '',
			'code'      => 0,
			'layer'     => '',
		);
		if ( ! has_action( 'shutdown', array( __CLASS__, 'flush' ) ) ) {
			add_action( 'shutdown', array( __CLASS__, 'flush' ), 1 );
		}
		return self::$entry;
	}

	/**
	 * The first 8 digits of the nonce of this request's signature: the same on the sending side's entry.
	 *
	 * @param string|null $sent The header (null = this request's).
	 * @return string
	 */
	public static function request_id( $sent = null ) {
		if ( null === $sent ) {
			$sent = isset( $_SERVER['HTTP_X_SCRAPELOCK_SIG'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SCRAPELOCK_SIG'] ) ) : '';
		}
		return preg_match( '/^\d{9,11}\.([0-9a-f]{8})/', (string) $sent, $m ) ? $m[1] : '';
	}

	/**
	 * At the end of the request: writes this request's entry, within the minute's allowance.
	 */
	public static function flush() {
		if ( null === self::$entry ) {
			return;
		}
		$entry       = self::$entry;
		self::$entry = null;
		if ( 'passed' === $entry['verdict'] ) {
			$entry['code'] = function_exists( 'http_response_code' ) ? (int) http_response_code() : 0;
		}
		// A request from the server's address without a signature is noted only when it was refused (cache
		// preloads and cron would fill the buffer otherwise).
		if ( '' === $entry['sig'] && 'refused' !== $entry['verdict'] ) {
			return;
		}
		$limit = $entry['authentic'] ? self::LIMIT : self::LIMIT_OTHER;
		if ( PNCP_Log::cache_incr( 'pncp_scl_' . ( $entry['authentic'] ? 'a' : 'o' ) . (int) floor( time() / 60 ), 120 ) > $limit ) {
			return;
		}
		self::add( $entry );
	}

	/**
	 * Adds an entry to the ring buffer.
	 *
	 * @param array<string, mixed> $entry Entry.
	 */
	public static function add( $entry ) {
		self::uncache();
		$list = get_option( self::LOG, array() );
		$list = is_array( $list ) ? $list : array();
		array_unshift( $list, $entry );
		$list = array_slice( $list, 0, self::MAX );
		if ( false === get_option( self::LOG, false ) ) {
			add_option( self::LOG, $list, '', false );
		} else {
			update_option( self::LOG, $list, false );
		}
	}

	/**
	 * Forgets what this request read of the ring buffer (other requests write it), also that it did not exist.
	 */
	private static function uncache() {
		wp_cache_delete( self::LOG, 'options' );
		$missing = wp_cache_get( 'notoptions', 'options' );
		if ( is_array( $missing ) && isset( $missing[ self::LOG ] ) ) {
			unset( $missing[ self::LOG ] );
			wp_cache_set( 'notoptions', $missing, 'options' );
		}
	}

	/**
	 * The ring buffer, newest first.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function entries() {
		self::uncache();
		$list = get_option( self::LOG, array() );
		return is_array( $list ) ? array_values( array_filter( $list, 'is_array' ) ) : array();
	}

	/**
	 * Forgets this request's entry and layer (tests).
	 */
	public static function reset() {
		self::$entry  = null;
		self::$layer  = 'wp';
		self::$marked = false;
	}

	/**
	 * This request's entry so far (tests, "Check a request").
	 *
	 * @return array<string, mixed>|null
	 */
	public static function current() {
		return self::$entry;
	}
}
