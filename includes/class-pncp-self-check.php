<?php
/**
 * 3.12.2: the site's requests to itself, made visible and made to work behind a CDN that refuses them.
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
 * - ScrapeLock's own refusals carry the header "X-ScrapeLock: refused" (marker()); for the site's own request or
 *   one from the server's addresses that carries a signature also the layer and the signature's result, and for
 *   the site's own request (its MAC matched) the reason. A request with a valid signature that passes gets
 *   "X-ScrapeLock: ok id=…" (the id of its signature), so the sending side knows this WordPress answered it.
 * - Sending side: request() makes a self-check request, classifies the answer (classify(): a normal page,
 *   ScrapeLock and its reason, Bunny CDN's edge, Cloudflare, Wordfence, WordPress or another plugin, the web
 *   server, unknown) and notes it in the same buffer. When the public way refuses the site (a 403 / 429 / 5xx
 *   that is not the page, or no connection at all), the request is made once more straight to the server: the
 *   site's own host name and port pinned to 127.0.0.1, SERVER_ADDR or SCRAPELOCK_SERVER_IPS with CURLOPT_RESOLVE
 *   (action http_api_curl), so the Host header and TLS name stay the site's (only the site's own host and port,
 *   only to those addresses). While the public way refuses it and this WordPress itself answered straight at the
 *   server ("ok" with the request's id), the site's other requests to itself (Site Health's loopback, WP cron) go
 *   that way too (route_request(), for ROUTE_TTL, until the public way answers or the server stops answering).
 * - run() is a real self-check now (the "Run a real self-check now" button of "Check a request", the Site Health
 *   test, "wp scrapelock selfcheck"): the home page through the public address, then the server if needed, with
 *   what each side saw.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Diagnostics of the site's requests to itself, and the way straight to the server when the public one refuses.
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
	 * Option (not autoloaded): the trace of the last run().
	 */
	const LAST = 'pncp_selfcheck_last';

	/**
	 * Transient: the server address the site's requests to itself go to while the public way refuses them.
	 */
	const ROUTE = 'pncp_selfcheck_route';

	/**
	 * How long the way straight to the server is used after a self-check found the public one refused (seconds).
	 */
	const ROUTE_TTL = 21600;

	/**
	 * The response header of ScrapeLock's refusals and of the answers to the site's signed requests.
	 */
	const HEADER = 'X-ScrapeLock';

	/**
	 * AJAX action and nonce action of "Run a real self-check now".
	 */
	const ACTION = 'pncp_selfcheck';

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
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'http_api_curl', array( __CLASS__, 'curl_resolve' ), 10, 3 );
		add_filter( 'pre_http_request', array( __CLASS__, 'route_request' ), 1000, 3 );
		add_action( 'wp_ajax_' . self::ACTION, array( __CLASS__, 'ajax' ) );
	}

	/* ---------- Receiving side ---------- */

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
	 * marks the answer to a valid one ("X-ScrapeLock: ok id=…", ok_marker()).
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
			header( self::HEADER . ': ' . self::ok_marker( self::request_id() ) );
		}
	}

	/**
	 * The header value of the answer to the site's valid signature: "ok id=<request_id()>". Only a server that
	 * verified the signature with the site's key says it, and the id ties it to the one request that carried the
	 * signature (a cached copy of an earlier answer carries another one): is_own_answer().
	 *
	 * @param string $id request_id() of the signature.
	 * @return string
	 */
	public static function ok_marker( $id ) {
		return 'ok' . ( preg_match( '/^[0-9a-f]{8}$/', (string) $id ) ? ' id=' . $id : '' );
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
		$sig    = null !== self::$entry ? (string) self::$entry['sig'] : '';
		$mine   = null === $own ? null !== self::$entry && ! empty( self::$entry['authentic'] ) : (bool) $own;
		$server = class_exists( 'PNCP_Server_Ips', false ) && class_exists( 'PNCP_Ip', false ) && PNCP_Server_Ips::is_server_ip( PNCP_Ip::client_ip() );
		if ( ! self::$marked && ! headers_sent() ) {
			header_remove( self::HEADER );
			// The layer and the signature's result only for the site's own request or one from the server's
			// addresses: anyone can send an X-ScrapeLock-Sig header, and a stranger learns nothing but "refused".
			header( self::HEADER . ': ' . self::marker( (string) $reason, $mine || $server ? $sig : '', $mine ) );
			self::$marked = true;
		}
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
	 * data: no address, User-Agent or path. refused() passes the signature's result only for the site's own request
	 * or one from the server's addresses, so a stranger's forged header gets just "refused".
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
	 * The id of this request's signature: 8 hex digits of a hash of its nonce (never the nonce or part of it, which
	 * the notes do not keep), the same on the sending side's entry. The pre-cache check makes the same
	 * (PNCP_Precheck_Runtime::self_id()).
	 *
	 * @param string|null $sent The header (null = this request's).
	 * @return string
	 */
	public static function request_id( $sent = null ) {
		if ( null === $sent ) {
			$sent = isset( $_SERVER['HTTP_X_SCRAPELOCK_SIG'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SCRAPELOCK_SIG'] ) ) : '';
		}
		return preg_match( '/^\d{9,11}\.([0-9a-f]{24})\./', (string) $sent, $m ) ? substr( md5( 'id|' . $m[1] ), 0, 8 ) : '';
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
		if ( isset( $entry['side'] ) && 'out' === $entry['side'] ) {
			// No address in the notes, not even the server's own: the step's address and any address or query
			// string in a transport error stay in the trace of run() (option LAST) only.
			unset( $entry['ip'] );
			$entry['error'] = isset( $entry['error'] ) ? self::scrub( (string) $entry['error'] ) : '';
		}
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
	 * A text without IP addresses and query strings (a transport error names the address it could not reach).
	 *
	 * @param string $text Text.
	 * @return string
	 */
	public static function scrub( $text ) {
		$text = (string) preg_replace( '/\?\S*/', '', (string) $text );
		$text = (string) preg_replace( '/\[?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?|\b\d{1,3}(?:\.\d{1,3}){3}\b/i', '[address]', $text );
		return substr( $text, 0, 160 );
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

	/* ---------- Sending side ---------- */

	/**
	 * 3.12.3: the User-Agent of every self-check: "ScrapeLock-Selftest/<version> (+<home address>)". Not a browser's
	 * (before 3.12.3 it was a Chrome User-Agent, which ScrapeLock's own generated Nginx rules refused as a fake
	 * browser before PHP could see the signature): it names itself and the site, so no server rule takes it for a
	 * browser, and ScrapeLock's PHP checks let it through by its signature (X-ScrapeLock-Sig), never by its name.
	 *
	 * @return string
	 */
	public static function user_agent() {
		return 'ScrapeLock-Selftest/' . PNCP_VERSION . ' (+' . home_url() . ')';
	}

	/**
	 * Who answered, from an answer's status, headers and body.
	 *
	 * @param int                   $code    Status (0 = no answer).
	 * @param array<string, string> $headers Lowercase headers.
	 * @param string                $body    Body (its start is enough).
	 * @return array{who:string, reason:string, layer:string, sig:string}
	 *         who: page (a normal answer), scrapelock, bunny, cloudflare, wordfence, wp (WordPress or another plugin), server, unknown, none.
	 */
	public static function classify( $code, $headers, $body ) {
		$code    = (int) $code;
		$headers = array_change_key_case( array_map( 'strval', (array) $headers ), CASE_LOWER );
		$body    = substr( (string) $body, 0, 20000 );
		$out     = array(
			'who'    => 'unknown',
			'reason' => '',
			'layer'  => '',
			'sig'    => '',
		);
		$mark    = isset( $headers['x-scrapelock'] ) ? trim( $headers['x-scrapelock'] ) : '';
		if ( preg_match( '/^refused(?: ([a-z0-9_]+))?(?: layer=([a-z0-9_-]+))?(?: sig=([a-z0-9_]+))?/', $mark, $m ) ) {
			$out['who']    = 'scrapelock';
			$out['reason'] = isset( $m[1] ) ? $m[1] : '';
			$out['layer']  = isset( $m[2] ) ? $m[2] : '';
			$out['sig']    = isset( $m[3] ) ? $m[3] : '';
			return $out;
		}
		if ( 0 === $code ) {
			$out['who'] = 'none';
			return $out;
		}
		// This WordPress answered the site's signed request (its 401 / 404 is the answer, not a refusal of the site).
		if ( $code < 400 || preg_match( '/^ok(?:\s|$)/', $mark ) ) {
			$out['who'] = 'page';
			return $out;
		}
		$server = isset( $headers['server'] ) ? strtolower( $headers['server'] ) : '';
		$bunny  = 0 === strpos( $server, 'bunnycdn' ) || isset( $headers['cdn-requestid'] ) || isset( $headers['cdn-pullzone'] );
		if ( false !== stripos( $body, 'wordfence' ) || false !== stripos( $body, 'wfls-' ) ) {
			$out['who'] = 'wordfence';
		} elseif ( false !== strpos( $body, 'id="error-page"' ) || false !== strpos( $body, 'wp-die-message' ) ) {
			$out['who'] = 'wp';
		} elseif ( preg_match( '#<center>\s*(?:nginx|openresty)|<address>\s*Apache|LiteSpeed Web Server|Microsoft-IIS#i', $body ) ) {
			$out['who'] = 'server';
		} elseif ( $bunny ) {
			$out['who'] = 'bunny';
		} elseif ( isset( $headers['cf-ray'] ) || false !== strpos( $server, 'cloudflare' ) ) {
			$out['who'] = 'cloudflare';
		} elseif ( preg_match( '/^(?:nginx|apache|litespeed|openresty|microsoft-iis)/', $server ) ) {
			$out['who'] = 'server';
		}
		return $out;
	}

	/**
	 * Who answered, for people.
	 *
	 * @param array{who:string, reason:string} $class What classify() returned.
	 * @return string
	 */
	public static function who_label( $class ) {
		switch ( $class['who'] ) {
			case 'page':
				return __( 'the site (a normal answer)', 'scrapelock' );
			case 'scrapelock':
				/* translators: %s: why ScrapeLock refused the request */
				return '' !== $class['reason'] ? sprintf( __( 'ScrapeLock (%s)', 'scrapelock' ), PNCP_Log::reason_label( $class['reason'] ) ) : __( 'ScrapeLock', 'scrapelock' );
			case 'rules':
				/* translators: %s: the rule, e.g. "fake browser" */
				return sprintf( __( 'ScrapeLock\'s own server rule (%s)', 'scrapelock' ), PNCP_Rules::rule_label( $class['reason'] ) );
			case 'bunny':
				return __( 'Bunny CDN edge', 'scrapelock' );
			case 'cloudflare':
				return __( 'Cloudflare', 'scrapelock' );
			case 'wordfence':
				return __( 'Wordfence', 'scrapelock' );
			case 'wp':
				return __( 'WordPress or another plugin', 'scrapelock' );
			case 'server':
				return __( 'web server', 'scrapelock' );
			case 'none':
				return __( 'nobody (no connection)', 'scrapelock' );
		}
		return __( 'unknown', 'scrapelock' );
	}

	/**
	 * What the owner should check, in one sentence, for who refused the site's own request.
	 *
	 * @param array{who:string, reason:string, sig:string} $class What classify() returned.
	 * @return string
	 */
	public static function advice( $class ) {
		$ips = self::outbound_text();
		switch ( $class['who'] ) {
			case 'bunny':
				/* translators: %s: the server's addresses */
				return sprintf( __( 'In the Bunny dashboard, open the pull zone and check its own security settings (Bunny Shield or WAF, bot protection, blocked IPs and countries, Edge Rules that block): one of them refuses the server\'s own address (%s).', 'scrapelock' ), $ips );
			case 'cloudflare':
				/* translators: %s: the server's addresses */
				return sprintf( __( 'In Cloudflare, check Security → Events for the server\'s own address (%s) and allow it.', 'scrapelock' ), $ips );
			case 'wordfence':
				/* translators: %s: the server's addresses */
				return sprintf( __( 'In Wordfence, check Firewall → Blocking and Live Traffic, and add the server\'s own address (%s) to the allowlisted IPs.', 'scrapelock' ), $ips );
			case 'wp':
				return __( 'Another plugin refused it: the security or maintenance plugins are the usual cause.', 'scrapelock' );
			case 'server':
				return __( 'The web server refused it before WordPress: check its deny rules and its own firewall for the server\'s address.', 'scrapelock' );
			case 'scrapelock':
				return self::sig_advice( $class['sig'] );
			case 'rules':
				return __( 'Copy the server rules again from the Server rules tab (since 3.12.3 they never refuse the server\'s own addresses), run nginx -t and reload; behind a CDN, Nginx needs real_ip so that the server\'s own requests keep its address.', 'scrapelock' );
		}
		return __( 'Something between the server and the site refused it: check the CDN, the hosting firewall and the security plugins.', 'scrapelock' );
	}

	/**
	 * What a failed signature means.
	 *
	 * @param string $sig Result of the signature check ('' = unknown).
	 * @return string
	 */
	public static function sig_advice( $sig ) {
		switch ( (string) $sig ) {
			case 'ok':
			case '':
				return __( 'ScrapeLock refused the site\'s own request: open "Check a request" on the Log tab and choose "The site itself (loopback)" to see which check.', 'scrapelock' );
			case 'no_key':
				return __( 'The pre-cache check does not have the signature key yet: open any wp-admin page once, so its line in wp-config.php is written again.', 'scrapelock' );
			case 'expired':
				return __( 'The signature arrived too late: the server\'s clock or a very slow proxy delays the request by more than a minute.', 'scrapelock' );
			case 'host_mismatch':
				return __( 'The signature was made for a host name that is not this site\'s: check the WordPress Address and Site Address in Settings → General.', 'scrapelock' );
			case 'path_mismatch':
				return __( 'Something on the way changed the address of the request (a CDN or proxy path rewrite): the signature holds for the address it was made for only.', 'scrapelock' );
			case 'bad_mac':
				return __( 'The signature did not match: the pre-cache check\'s line in wp-config.php has an old key. Open any wp-admin page once, so it is written again.', 'scrapelock' );
			case 'nonce_reused':
				return __( 'The same request arrived twice (a CDN or proxy retried it): the second copy was refused as a replay.', 'scrapelock' );
		}
		return __( 'The request did not carry a readable signature of the site: a proxy may have removed the X-ScrapeLock-Sig header.', 'scrapelock' );
	}

	/**
	 * The server's outbound addresses ScrapeLock knows, for the texts.
	 *
	 * @return string
	 */
	private static function outbound_text() {
		$ips = array_merge( PNCP_Server_Ips::outbound_ips(), PNCP_Server_Ips::const_ips() );
		$ips = array_slice( array_values( array_unique( $ips ) ), 0, 3 );
		return $ips ? implode( ', ', $ips ) : __( 'not known yet: see SCRAPELOCK_SERVER_IPS', 'scrapelock' );
	}

	/**
	 * Is an answer a refusal of the site's own request, after which the server is asked directly?
	 *
	 * @param array<string, mixed>|WP_Error $response The answer.
	 * @param array{who:string, reason:string} $class What classify() returned.
	 * @param string                           $mode    page (a page is expected: any refusal), self (only
	 *                                                  ScrapeLock's checks for bots and Wordfence), public (never).
	 * @return bool
	 */
	public static function should_retry( $response, $class, $mode ) {
		if ( 'public' === $mode ) {
			return false;
		}
		if ( is_wp_error( $response ) ) {
			return true; // The public address cannot be reached from the server at all.
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 'scrapelock' === $class['who'] ) {
			// Vulnerable points' own refusals (harden_*) are the answer a locked point gives.
			return 0 !== strpos( $class['reason'], 'harden_' );
		}
		if ( 'rules' === $class['who'] ) {
			return true; // 3.12.3: ScrapeLock's own server rule refused the site's own request.
		}
		if ( 'wordfence' === $class['who'] ) {
			return true;
		}
		// While the public way is known to refuse the site's own requests (route()), any refusal is retried.
		if ( 'page' !== $mode && false === get_transient( self::ROUTE ) ) {
			return false;
		}
		return 429 === $code || 403 === $code || $code >= 500;
	}

	/**
	 * A request of the site to itself, with the way straight to the server when the public one refuses it.
	 *
	 * @param string               $url  Address on the site.
	 * @param array<string, mixed> $args Arguments of wp_remote_request().
	 * @param string               $mode page, self, public (see should_retry()), or origin (only the server).
	 * @return array{response:array<string, mixed>|WP_Error, via:string, public:array{who:string, reason:string, layer:string, sig:string}, origin_ip:string, steps:array<int, array<string, mixed>>}
	 */
	public static function request( $url, $args = array(), $mode = 'page' ) {
		$args               = is_array( $args ) ? $args : array();
		$args['user-agent'] = self::user_agent(); // 3.12.3: every self-check, whatever the caller set.
		$steps              = array();
		$out   = array(
			'response'  => new WP_Error( 'pncp_selfcheck', __( 'not requested', 'scrapelock' ) ),
			'via'       => 'public',
			'public'    => array(
				'who'    => 'none',
				'reason' => '',
				'layer'  => '',
				'sig'    => '',
			),
			'origin_ip' => '',
			'steps'     => array(),
		);
		if ( 'origin' !== $mode ) {
			$public                = $args;
			$public['pncp_public'] = true; // Never through route_request(): this is the check of the public way.
			$before                = PNCP_Server_Ips::last_sent();
			$response              = wp_remote_request( $url, $public );
			$sent                  = self::sent_since( $before );
			$class                 = self::rules_class( self::answer_class( $response ), $response, $url, $args, $sent );
			$steps[]               = self::step( 'public', $url, $sent, $response, $class, '' );
			PNCP_Rules_State::observe( $response, self::request_id( $sent ) );
			$out['response']       = $response;
			$out['public']         = $class;
			if ( ! self::should_retry( $response, $class, $mode ) ) {
				if ( 'page' === $class['who'] && false !== get_transient( self::ROUTE ) ) {
					delete_transient( self::ROUTE ); // The public way works again: the site's requests go that way.
				}
				$out['steps'] = $steps;
				self::note_steps( $steps );
				return $out;
			}
		}
		foreach ( self::origin_candidates() as $ip ) {
			$before   = PNCP_Server_Ips::last_sent();
			$response = self::origin_request( $url, $args, $ip );
			if ( null === $response ) {
				break; // Not possible here (no cURL, an address that is not the site's).
			}
			$sent    = self::sent_since( $before );
			$class   = self::rules_class( self::answer_class( $response ), $response, $url, $args, $sent );
			$steps[] = self::step( 'origin', $url, $sent, $response, $class, $ip );
			PNCP_Rules_State::observe( $response, self::request_id( $sent ) );
			if ( is_wp_error( $response ) ) {
				continue;
			}
			$out['response']  = $response;
			$out['via']       = 'origin';
			$out['origin_ip'] = $ip;
			$out['public']    = self::refine( $out['public'], $steps, $response );
			if ( isset( $steps[0] ) && 'public' === $steps[0]['via'] ) {
				$steps[0]['who'] = $out['public']['who'];
			}
			// The route for the site's other requests only when this WordPress itself answered this very request
			// (it verified the signature: "ok" with this request's id), never for any server that answers there.
			$last = end( $steps );
			if ( 'origin' !== $mode && is_array( $last ) && self::is_own_answer( $response, (string) $last['id'] ) ) {
				set_transient( self::ROUTE, $ip, self::ROUTE_TTL );
			}
			break;
		}
		$out['steps'] = $steps;
		self::note_steps( $steps );
		return $out;
	}

	/**
	 * 3.12.3: a 403 of the web server that ScrapeLock's PHP never saw (no X-ScrapeLock header, nothing in the ring
	 * buffer for its signature): when ScrapeLock's own generated server rules, with the current settings, refuse
	 * the very request that was sent (PNCP_Rules::evaluate()), they did it: who "rules", the rule as the reason.
	 *
	 * @param array{who:string, reason:string, layer:string, sig:string} $class    What classify() returned.
	 * @param array<string, mixed>|WP_Error                              $response The answer.
	 * @param string                                                     $url      Address.
	 * @param array<string, mixed>                                       $args     The request's arguments.
	 * @param string                                                     $sent     Its signature ('' = none).
	 * @return array{who:string, reason:string, layer:string, sig:string}
	 */
	public static function rules_class( $class, $response, $url, $args, $sent ) {
		if ( is_wp_error( $response ) || 403 !== (int) wp_remote_retrieve_response_code( $response ) || ! in_array( $class['who'], array( 'server', 'unknown' ), true ) ) {
			return $class;
		}
		if ( isset( self::headers_of( $response )[ strtolower( self::HEADER ) ] ) ) {
			return $class;
		}
		$id = '' !== $sent ? self::request_id( $sent ) : '';
		if ( '' !== $id ) {
			foreach ( self::entries() as $entry ) {
				if ( isset( $entry['side'], $entry['id'] ) && 'in' === $entry['side'] && $id === $entry['id'] ) {
					return $class; // WordPress saw it.
				}
			}
		}
		$rule = PNCP_Rules::evaluate( self::sent_request( $url, $args ) );
		if ( null === $rule || 403 !== $rule['code'] ) {
			return $class;
		}
		return array(
			'who'    => 'rules',
			'reason' => $rule['rule'],
			'layer'  => '',
			'sig'    => '',
		);
	}

	/**
	 * 3.12.3: a request of the site to itself as the web server gets it, for PNCP_Rules::evaluate(): User-Agent,
	 * headers, scheme, method and path. Its address is not known here: not one of the server's (the case in which
	 * the rules refuse it).
	 *
	 * @param string               $url  Address.
	 * @param array<string, mixed> $args The request's arguments.
	 * @return array<string, mixed>
	 */
	public static function sent_request( $url, $args ) {
		$parts   = wp_parse_url( (string) $url );
		$headers = isset( $args['headers'] ) && is_array( $args['headers'] ) ? $args['headers'] : array();
		return array(
			'ua'      => isset( $args['user-agent'] ) ? (string) $args['user-agent'] : self::user_agent(),
			'headers' => $headers,
			'https'   => is_array( $parts ) && isset( $parts['scheme'] ) && 'https' === strtolower( (string) $parts['scheme'] ),
			'method'  => isset( $args['method'] ) ? strtoupper( (string) $args['method'] ) : 'GET',
			'path'    => is_array( $parts ) && isset( $parts['path'] ) ? (string) $parts['path'] : '/',
			'remote'  => '',
		);
	}

	/**
	 * After the server answered directly: a refusal on the public way that came through Bunny, looked like a web
	 * server's page and never reached this WordPress (no note of the receiving side for its signature) was made by
	 * the CDN's edge (its own block pages are plain), not by this server, which just answered the same request.
	 *
	 * @param array{who:string, reason:string, layer:string, sig:string} $public The public answer's classification.
	 * @param array<int, array<string, mixed>>                           $steps  The steps so far.
	 * @param array<string, mixed>|WP_Error                              $origin The server's answer.
	 * @return array{who:string, reason:string, layer:string, sig:string}
	 */
	private static function refine( $public, $steps, $origin ) {
		if ( ! in_array( $public['who'], array( 'server', 'unknown' ), true ) || ! isset( $steps[0] ) || 'public' !== $steps[0]['via'] || 0 !== strpos( (string) $steps[0]['cdn'], 'bunny' ) ) {
			return $public;
		}
		if ( is_wp_error( $origin ) || (int) wp_remote_retrieve_response_code( $origin ) >= 400 ) {
			return $public;
		}
		$id = (string) $steps[0]['id'];
		foreach ( self::entries() as $entry ) {
			if ( '' !== $id && isset( $entry['side'], $entry['id'] ) && 'in' === $entry['side'] && $id === $entry['id'] ) {
				return $public; // This WordPress saw it: not the edge.
			}
		}
		$public['who'] = 'bunny';
		return $public;
	}

	/**
	 * The classification of an answer of wp_remote_request().
	 *
	 * @param array<string, mixed>|WP_Error $response The answer.
	 * @return array{who:string, reason:string, layer:string, sig:string}
	 */
	public static function answer_class( $response ) {
		if ( is_wp_error( $response ) ) {
			return self::classify( 0, array(), '' );
		}
		return self::classify( (int) wp_remote_retrieve_response_code( $response ), self::headers_of( $response ), (string) wp_remote_retrieve_body( $response ) );
	}

	/**
	 * Did this WordPress answer this request: "X-ScrapeLock: ok id=…" (ok_marker()) with the id of the signature
	 * it was sent with? Only a server holding the site's key verifies it, and the id ties it to this request.
	 *
	 * @param array<string, mixed>|WP_Error $response The answer.
	 * @param string                        $id       request_id() of the signature the request was sent with.
	 * @return bool
	 */
	public static function is_own_answer( $response, $id ) {
		if ( is_wp_error( $response ) || ! preg_match( '/^[0-9a-f]{8}$/', (string) $id ) ) {
			return false;
		}
		$h = self::headers_of( $response );
		return isset( $h['x-scrapelock'] ) && self::ok_marker( $id ) === trim( $h['x-scrapelock'] );
	}

	/**
	 * The lowercase headers of an answer, each as one string.
	 *
	 * @param array<string, mixed> $response The answer.
	 * @return array<string, string>
	 */
	public static function headers_of( $response ) {
		$raw = wp_remote_retrieve_headers( $response );
		$raw = is_object( $raw ) && method_exists( $raw, 'getAll' ) ? $raw->getAll() : (array) $raw;
		$out = array();
		foreach ( $raw as $name => $value ) {
			$out[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', array_map( 'strval', $value ) ) : (string) $value;
		}
		return $out;
	}

	/**
	 * One step of a self-check, as noted and shown (no body, no cookie, no address but the server's own).
	 *
	 * @param string                        $via      public or origin.
	 * @param string                        $url      Address.
	 * @param string                        $sig      The signature it was sent with ('' = none).
	 * @param array<string, mixed>|WP_Error $response The answer.
	 * @param array<string, string>         $class    What classify() returned.
	 * @param string                        $ip       The server address (origin).
	 * @return array<string, mixed>
	 */
	private static function step( $via, $url, $sig, $response, $class, $ip ) {
		$h = is_wp_error( $response ) ? array() : self::headers_of( $response );
		return array(
			'side'      => 'out',
			'time'      => time(),
			'via'       => $via,
			'ip'        => (string) $ip,
			'path'      => substr( (string) preg_replace( '/[^\x21-\x7E]/', '', (string) wp_parse_url( $url, PHP_URL_PATH ) ), 0, 120 ),
			'code'      => is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response ),
			'error'     => is_wp_error( $response ) ? substr( $response->get_error_message(), 0, 160 ) : '',
			'server'    => isset( $h['server'] ) ? substr( $h['server'], 0, 60 ) : '',
			'marker'    => isset( $h['x-scrapelock'] ) ? substr( $h['x-scrapelock'], 0, 80 ) : '',
			'cdn'       => isset( $h['cdn-requestid'] ) ? 'bunny' . ( isset( $h['cdn-cache'] ) ? ' ' . substr( $h['cdn-cache'], 0, 12 ) : '' ) : ( isset( $h['cf-ray'] ) ? 'cloudflare' : '' ),
			'who'       => $class['who'],
			'reason'    => $class['reason'],
			'sig_reply' => $class['sig'],
			'id'        => '' !== $sig ? self::request_id( $sig ) : '',
		);
	}

	/**
	 * The signature the last request was sent with, when it is a new one.
	 *
	 * @param string $before PNCP_Server_Ips::last_sent() before the request.
	 * @return string
	 */
	private static function sent_since( $before ) {
		$now = PNCP_Server_Ips::last_sent();
		return $now !== $before ? $now : '';
	}

	/**
	 * Notes the steps of a self-check in the ring buffer.
	 *
	 * @param array<int, array<string, mixed>> $steps Steps.
	 */
	private static function note_steps( $steps ) {
		foreach ( $steps as $step ) {
			self::add( $step );
		}
	}

	/**
	 * The server addresses the site's requests can be sent to directly: 127.0.0.1, SERVER_ADDR, then
	 * SCRAPELOCK_SERVER_IPS (single addresses). Filter `pncp_selfcheck_origin_ips`.
	 *
	 * @return string[]
	 */
	public static function origin_candidates() {
		$ips    = array( '127.0.0.1' );
		$server = isset( $_SERVER['SERVER_ADDR'] ) ? PNCP_Ip::normalize( sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) ) : '';
		if ( '' !== $server && ! PNCP_Ip::is_cdn( $server ) ) {
			$ips[] = $server;
		}
		foreach ( PNCP_Server_Ips::const_ips() as $range ) {
			if ( false === strpos( $range, '/' ) ) {
				$ips[] = $range;
			}
		}
		/**
		 * 3.12.2: the addresses of this server that the site's requests to itself are sent to when its public
		 * address refuses them (first that answers). Single addresses only.
		 *
		 * @param string[] $ips 127.0.0.1, SERVER_ADDR and the single addresses of SCRAPELOCK_SERVER_IPS.
		 */
		$ips = (array) apply_filters( 'pncp_selfcheck_origin_ips', $ips );
		$out = array();
		foreach ( $ips as $ip ) {
			$ip = PNCP_Ip::normalize( is_string( $ip ) ? $ip : '' );
			if ( '' !== $ip && ! in_array( $ip, $out, true ) ) {
				$out[] = $ip;
			}
		}
		return array_slice( $out, 0, 3 );
	}

	/**
	 * The request straight to the server: the site's host and port pinned to the address (CURLOPT_RESOLVE in
	 * curl_resolve()), the Host header and the TLS name unchanged. Null when it cannot be made here.
	 *
	 * @param string               $url  Address on the site.
	 * @param array<string, mixed> $args Arguments.
	 * @param string               $ip   Server address.
	 * @return array<string, mixed>|WP_Error|null
	 */
	public static function origin_request( $url, $args, $ip ) {
		$resolve = self::resolve_entry( $url, $ip );
		if ( '' === $resolve || ! function_exists( 'curl_init' ) || ! defined( 'CURLOPT_RESOLVE' ) ) {
			return null;
		}
		$args                 = is_array( $args ) ? $args : array();
		$args['pncp_resolve'] = $resolve;
		$args['timeout']      = min( isset( $args['timeout'] ) ? (float) $args['timeout'] : 5, 5 );
		unset( $args['pncp_public'] );
		return wp_remote_request( $url, $args );
	}

	/**
	 * The CURLOPT_RESOLVE entry "host:port:address" for an address on the site ('' for another host or port, or an
	 * address that is not one of origin_candidates()).
	 *
	 * @param string $url Address.
	 * @param string $ip  Server address.
	 * @return string
	 */
	public static function resolve_entry( $url, $ip ) {
		$parts = wp_parse_url( (string) $url );
		$host  = is_array( $parts ) && isset( $parts['host'] ) ? strtolower( (string) $parts['host'] ) : '';
		$ip    = PNCP_Ip::normalize( (string) $ip );
		if ( '' === $host || '' === $ip || ! in_array( $ip, self::origin_candidates(), true ) ) {
			return '';
		}
		$scheme = isset( $parts['scheme'] ) ? strtolower( (string) $parts['scheme'] ) : 'http';
		$port   = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
		if ( ! in_array( $host . ':' . $port, self::own_origins(), true ) ) {
			return '';
		}
		return $host . ':' . $port . ':' . ( false !== strpos( $ip, ':' ) ? '[' . $ip . ']' : $ip );
	}

	/**
	 * The site's own "host:port" pairs (home and site address): their port, and both 80 and 443 for an address on
	 * a default port (the site's http and https). Never another port of the same host (a control panel, a mail
	 * server's web interface).
	 *
	 * @return string[]
	 */
	public static function own_origins() {
		$out = array();
		foreach ( array( home_url( '/' ), site_url( '/' ) ) as $address ) {
			$parts = wp_parse_url( $address );
			$host  = is_array( $parts ) && isset( $parts['host'] ) ? strtolower( (string) $parts['host'] ) : '';
			if ( '' === $host ) {
				continue;
			}
			$scheme = isset( $parts['scheme'] ) ? strtolower( (string) $parts['scheme'] ) : 'http';
			$port   = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
			$ports  = in_array( $port, array( 80, 443 ), true ) ? array( 80, 443 ) : array( $port );
			foreach ( $ports as $one ) {
				$out[] = $host . ':' . $one;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Action http_api_curl: pins the site's host to the server address of a request made by origin_request(), and
	 * sends it without a proxy.
	 *
	 * @param resource|object      $handle cURL handle.
	 * @param array<string, mixed> $args   Arguments.
	 * @param string               $url    Address.
	 */
	public static function curl_resolve( $handle, $args, $url ) {
		if ( ! is_array( $args ) || empty( $args['pncp_resolve'] ) || ! is_string( $args['pncp_resolve'] ) || ! defined( 'CURLOPT_RESOLVE' ) ) {
			return;
		}
		// Only the entry resolve_entry() makes for this very address: the site's own host and port, pinned to one of
		// the server's addresses (whoever passed the argument).
		$parts = explode( ':', $args['pncp_resolve'], 3 );
		$ip    = isset( $parts[2] ) ? trim( $parts[2], '[]' ) : '';
		if ( '' === $ip || self::resolve_entry( (string) $url, $ip ) !== $args['pncp_resolve'] ) {
			return;
		}
		curl_setopt( $handle, CURLOPT_RESOLVE, array( $args['pncp_resolve'] ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- The handle of WordPress's own request (http_api_curl).
		// Straight to this server: never through a proxy (WP_PROXY_HOST or the environment's), which could not
		// reach the server's own address.
		curl_setopt( $handle, CURLOPT_PROXY, '' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- As above.
	}

	/**
	 * Filter pre_http_request: while the public way refuses the site's own requests and the server answers them
	 * (ROUTE, set by request()), the site's other requests to itself (Site Health's loopback, WP cron, other
	 * plugins) go straight to the server as well.
	 *
	 * @param false|array<string, mixed>|WP_Error $pre  An answer already given.
	 * @param array<string, mixed>                $args Arguments.
	 * @param string                              $url  Address.
	 * @return false|array<string, mixed>|WP_Error
	 */
	public static function route_request( $pre, $args, $url ) {
		if ( false !== $pre || ! is_array( $args ) || ! empty( $args['pncp_public'] ) || ! empty( $args['pncp_resolve'] ) ) {
			return $pre;
		}
		$ip = get_transient( self::ROUTE );
		if ( ! is_string( $ip ) || '' === $ip || '' === self::resolve_entry( $url, $ip ) ) {
			return $pre;
		}
		$response = self::origin_request( $url, $args, $ip );
		if ( is_wp_error( $response ) ) {
			// The server does not answer there any more: the route goes, and this request takes the public way.
			delete_transient( self::ROUTE );
		}
		return null === $response || is_wp_error( $response ) ? $pre : $response;
	}

	/* ---------- The self-check now ---------- */

	/**
	 * A real self-check now: the home page as the Vulnerable points check asks for it, through the public address
	 * and, when refused, straight to the server; with what the receiving side noted for each request.
	 *
	 * @return array<string, mixed> steps (each with "in": the receiving side's entry when found), via, public
	 *                              (classification), ok (the public way answered a page), time.
	 */
	public static function run() {
		// 3.12.3: the check address of the Nginx rules (kept 5 minutes), for the rules of before 3.12.3, which send
		// no fingerprint header (PNCP_Rules_State::record()).
		PNCP_Rules::nginx_status();
		$url    = home_url( '/' );
		$result = self::request(
			$url,
			array(
				'timeout'             => 6,
				'redirection'         => 3,
				'sslverify'           => (bool) apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter.
				'limit_response_size' => 65536,
				'user-agent'          => self::user_agent(), // 3.12.3: not a browser's (see user_agent()).
				'headers'             => array(
					'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
					'Accept-Language' => 'en-US,en;q=0.9',
					'Cache-Control'   => 'no-cache',
				),
			),
			'page'
		);
		$seen   = self::entries();
		foreach ( $result['steps'] as $i => $step ) {
			$result['steps'][ $i ]['in'] = null;
			foreach ( $seen as $entry ) {
				if ( 'in' === ( isset( $entry['side'] ) ? $entry['side'] : '' ) && '' !== $step['id'] && isset( $entry['id'] ) && $entry['id'] === $step['id'] ) {
					$result['steps'][ $i ]['in'] = $entry;
					break;
				}
			}
		}
		$trace = array(
			'time'   => time(),
			'url'    => $url,
			'via'    => $result['via'],
			'public' => $result['public'],
			'ok'     => 'page' === $result['public']['who'],
			'origin' => 'origin' === $result['via'] && ! is_wp_error( $result['response'] ) && (int) wp_remote_retrieve_response_code( $result['response'] ) < 400,
			'steps'  => $result['steps'],
		);
		update_option( self::LAST, $trace, false );
		return $trace;
	}

	/**
	 * The last run(), or null.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last() {
		$t = get_option( self::LAST, null );
		return is_array( $t ) && isset( $t['steps'] ) ? $t : null;
	}

	/**
	 * One sentence about a self-check.
	 *
	 * @param array<string, mixed> $trace What run() returned.
	 * @return string
	 */
	public static function summary( $trace ) {
		$public = (array) $trace['public'];
		$code   = isset( $trace['steps'][0]['code'] ) ? (int) $trace['steps'][0]['code'] : 0;
		if ( ! empty( $trace['ok'] ) ) {
			/* translators: %d: HTTP status code */
			return sprintf( __( 'The site reaches itself through its public address (HTTP %d).', 'scrapelock' ), $code );
		}
		if ( 'none' === $public['who'] ) {
			$error = isset( $trace['steps'][0]['error'] ) ? (string) $trace['steps'][0]['error'] : '';
			return ! empty( $trace['origin'] )
				/* translators: %s: error message */
				? sprintf( __( 'The site could not reach its public address (%s); straight to the server it works, and ScrapeLock\'s checks use that way.', 'scrapelock' ), $error )
				/* translators: %s: error message */
				: sprintf( __( 'The site could not reach its public address (%s), nor the server directly.', 'scrapelock' ), $error );
		}
		$who = self::who_label(
			array(
				'who'    => (string) $public['who'],
				'reason' => (string) $public['reason'],
			)
		);
		if ( ! empty( $trace['origin'] ) ) {
			/* translators: 1: who refused (e.g. "Bunny CDN edge"), 2: HTTP status code */
			return sprintf( __( 'The site\'s own request through its public address was refused by %1$s (HTTP %2$d); straight to the server it works, and ScrapeLock\'s checks use that way.', 'scrapelock' ), $who, $code );
		}
		/* translators: 1: who refused, 2: HTTP status code */
		return sprintf( __( 'The site\'s own request through its public address was refused by %1$s (HTTP %2$d), and the server could not be reached directly either.', 'scrapelock' ), $who, $code );
	}

	/**
	 * The details of a self-check, one line each: what each request got back and what the receiving side saw.
	 *
	 * @param array<string, mixed> $trace What run() returned (or steps of request()).
	 * @return string[]
	 */
	public static function lines( $trace ) {
		$lines = array();
		foreach ( (array) $trace['steps'] as $step ) {
			$lines[] = self::step_line( $step );
			$in      = isset( $step['in'] ) && is_array( $step['in'] ) ? $step['in'] : null;
			if ( $in ) {
				$lines[] = '  ' . self::entry_line( $in );
			} elseif ( 'rules' === $step['who'] ) {
				/* translators: %s: the rule, e.g. "fake browser" */
				$lines[] = '  ' . sprintf( __( 'Refused by ScrapeLock\'s own server rule (%s): the web server refused it before WordPress.', 'scrapelock' ), PNCP_Rules::rule_label( (string) $step['reason'] ) );
			} elseif ( 'page' !== $step['who'] && 'scrapelock' !== $step['who'] && 'none' !== $step['who'] ) {
				$lines[] = '  ' . __( 'WordPress on this server never saw this request: it was refused before it reached WordPress.', 'scrapelock' );
			}
		}
		$public = isset( $trace['public'] ) ? (array) $trace['public'] : array();
		if ( isset( $public['who'] ) && ! in_array( $public['who'], array( 'page', 'none' ), true ) ) {
			$lines[] = self::advice(
				array(
					'who'    => (string) $public['who'],
					'reason' => (string) $public['reason'],
					'sig'    => isset( $public['sig'] ) ? (string) $public['sig'] : '',
				)
			);
		}
		// 3.12.3: the installed server rules are not the current ones.
		if ( PNCP_Rules_State::is_stale() ) {
			$lines[] = PNCP_Rules_State::message();
		}
		// 3.12.4: the check address of the Nginx rules names what is wrong (run() asked it).
		$nginx = PNCP_Rules_Status::nginx_kept();
		if ( null !== $nginx && PNCP_Rules_Status::worth_telling( $nginx ) ) {
			$text    = PNCP_Rules_Status::nginx_text( $nginx );
			$lines[] = trim( 'Nginx: ' . $text['line'] . ' ' . $text['more'] );
		}
		return $lines;
	}

	/**
	 * A sending side's step, in words.
	 *
	 * @param array<string, mixed> $step Step.
	 * @return string
	 */
	public static function step_line( $step ) {
		if ( 'origin' !== $step['via'] ) {
			$via = __( 'Through the public address', 'scrapelock' );
		} elseif ( empty( $step['ip'] ) ) {
			$via = __( 'Straight to the server', 'scrapelock' ); // A note of the ring buffer, which keeps no address.
		} else {
			/* translators: %s: server address */
			$via = sprintf( __( 'Straight to the server (%s)', 'scrapelock' ), $step['ip'] );
		}
		$parts = array();
		if ( '' !== (string) $step['error'] ) {
			$parts[] = (string) $step['error'];
		} else {
			$parts[] = 'HTTP ' . (int) $step['code'];
		}
		$parts[] = sprintf(
			/* translators: %s: who answered */
			__( 'answered by: %s', 'scrapelock' ),
			self::who_label(
				array(
					'who'    => (string) $step['who'],
					'reason' => (string) $step['reason'],
				)
			)
		);
		if ( '' !== (string) $step['server'] ) {
			$parts[] = 'Server: ' . $step['server'];
		}
		if ( '' !== (string) $step['cdn'] ) {
			$parts[] = 'CDN: ' . $step['cdn'];
		}
		if ( '' !== (string) $step['marker'] ) {
			$parts[] = self::HEADER . ': ' . $step['marker'];
		}
		return $via . ' ' . $step['path'] . ': ' . implode( '; ', $parts );
	}

	/**
	 * A receiving side's entry, in words.
	 *
	 * @param array<string, mixed> $in Entry.
	 * @return string
	 */
	public static function entry_line( $in ) {
		$layers = self::layers();
		$sigs   = self::sig_results();
		$sig    = isset( $in['sig'] ) ? (string) $in['sig'] : '';
		$parts  = array();
		/* translators: %s: host name */
		$parts[] = sprintf( __( 'WordPress got it for host %s', 'scrapelock' ), '' !== (string) $in['host'] ? $in['host'] : '-' );
		if ( '' !== $sig ) {
			/* translators: %s: result of the signature check */
			$parts[] = sprintf( __( 'signature: %s', 'scrapelock' ), isset( $sigs[ $sig ] ) ? $sigs[ $sig ] : $sig );
			if ( '' !== (string) $in['sig_host'] && (string) $in['sig_host'] !== (string) $in['host'] ) {
				/* translators: %s: host name */
				$parts[] = sprintf( __( 'signed for %s', 'scrapelock' ), $in['sig_host'] );
			}
		}
		if ( '' !== (string) $in['precache'] ) {
			/* translators: %s: result of the signature check */
			$parts[] = sprintf( __( 'pre-cache check: %s', 'scrapelock' ), isset( $sigs[ $in['precache'] ] ) ? $sigs[ $in['precache'] ] : $in['precache'] );
		}
		if ( 'refused' === $in['verdict'] ) {
			/* translators: 1: layer, 2: reason */
			$parts[] = sprintf( __( 'refused by %1$s: %2$s', 'scrapelock' ), isset( $layers[ $in['layer'] ] ) ? $layers[ $in['layer'] ] : $in['layer'], PNCP_Log::reason_label( (string) $in['reason'] ) );
		} else {
			/* translators: %d: HTTP status code */
			$parts[] = sprintf( __( 'passed every check (HTTP %d)', 'scrapelock' ), (int) $in['code'] );
		}
		return implode( '; ', $parts );
	}

	/**
	 * The layers, for people.
	 *
	 * @return array<string, string>
	 */
	public static function layers() {
		return array(
			'early'     => __( 'the early check', 'scrapelock' ),
			'pre-cache' => __( 'the pre-cache check', 'scrapelock' ),
			'wp'        => __( 'ScrapeLock in WordPress', 'scrapelock' ),
			'origin'    => __( '“Only through the CDN”', 'scrapelock' ),
			'hardening' => __( 'Vulnerable points', 'scrapelock' ),
		);
	}

	/**
	 * The results of the signature check, for people.
	 *
	 * @return array<string, string>
	 */
	public static function sig_results() {
		return array(
			'ok'            => __( 'valid', 'scrapelock' ),
			'bad_format'    => __( 'unreadable', 'scrapelock' ),
			'no_key'        => __( 'no key here', 'scrapelock' ),
			'expired'       => __( 'expired', 'scrapelock' ),
			'host_mismatch' => __( 'made for another host', 'scrapelock' ),
			'path_mismatch' => __( 'made for another address', 'scrapelock' ),
			'bad_mac'       => __( 'does not match', 'scrapelock' ),
			'nonce_reused'  => __( 'used twice', 'scrapelock' ),
		);
	}

	/**
	 * The AJAX action of "Run a real self-check now": POST, nonce, manage_options.
	 */
	public static function ajax() {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		if ( 'POST' !== $method ) {
			wp_send_json_error( array( 'message' => __( 'The check must be sent with POST.', 'scrapelock' ) ), 405 );
		}
		if ( false === check_ajax_referer( self::ACTION, 'nonce', false ) ) {
			wp_send_json_error( array( 'message' => __( 'This page has expired. Reload it and try again.', 'scrapelock' ) ), 403 );
		}
		if ( ! current_user_can( 'manage_options' ) || PNCP_Lockdown::is_locked() ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'scrapelock' ) ), 403 );
		}
		wp_send_json_success( self::view( self::run() ) );
	}

	/**
	 * What the card shows of a self-check.
	 *
	 * @param array<string, mixed> $trace What run() returned.
	 * @return array{ok:bool, origin:bool, headline:string, lines:string[]}
	 */
	public static function view( $trace ) {
		return array(
			'ok'       => ! empty( $trace['ok'] ),
			'origin'   => ! empty( $trace['origin'] ),
			'headline' => self::summary( $trace ),
			'lines'    => self::lines( $trace ),
		);
	}
}
