<?php
/**
 * 3.11: the site's own server addresses. Behind a CDN the site's requests to itself (Site Health, the
 * "Security headers" check of Vulnerable points, cron and cache preloads that go through the public address)
 * leave the server, pass through the CDN and come back with the server's PUBLIC address as the visitor IP,
 * not 127.0.0.1: the checks for bots refused the site itself (403 "No browser headers" for
 * "WordPress/6.x; https://site").
 *
 * A request whose verified visitor IP (PNCP_Ip::client_ip(), so only from a trusted proxy's header) is one of
 * the server's addresses is exempt from every check, like 127.0.0.1 already was. Never by the User-Agent alone,
 * which anyone can send. The addresses:
 * - 127.0.0.1, ::1 and SERVER_ADDR (loopback and private addresses only as before: PNCP_Ip::is_local_request());
 * - the addresses the site's own host name (home and site address) and the server's host name resolve to,
 *   without CDN addresses (behind a CDN the site's name resolves to the CDN, whose edges are never the server),
 *   looked up by WP cron and in wp-admin once a day, never during a visitor's request;
 * - the addresses the site's own requests to itself were seen coming from (learned): WordPress signs each of
 *   its requests to its own address with a short-lived HMAC header (key in an option, never sent elsewhere),
 *   and the address such a signed request arrives from is remembered for 30 days (at most 8 addresses);
 * - filter `pncp_server_ips`.
 *
 * Everything is stored in one option (not a setting of pncp_settings), which the early check reads as it is
 * and the pre-cache check gets in its configuration (PNCP_Precheck::config(), "self_ips").
 *
 * 3.12.1: behind Bunny without the CDN secret the visitor IP of the site's request to itself is the edge (or an
 * address that cannot be trusted), so no address told it apart from a visitor, and "Check again" in Vulnerable
 * points got a 403 from the headless check ("fake_browser" on HTTPS). WordPress now also signs every request to
 * its own address with SIG_HEADER: an HMAC-SHA256 of the method, host, path, time and a random nonce, valid for
 * 60 seconds and once (sig_ok()). A request that carries a valid signature passes every check, from any address.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The server's own addresses and the requests that come from them.
 */
final class PNCP_Server_Ips {

	/**
	 * Option: array{ips: string[], host: string, time: int, learned: array<string, int>, const: string}
	 * (autoloaded: the early check reads it on every request). 3.12.1: "const" is a fingerprint of
	 * SCRAPELOCK_SERVER_IPS, so a change in wp-config.php reaches the pre-cache check.
	 */
	const OPTION = 'pncp_server_ips';

	/**
	 * Option: the key of the signature of the site's requests to itself.
	 */
	const KEY_OPTION = 'pncp_server_key';

	/**
	 * The request header WordPress adds to its requests to its own address.
	 */
	const HEADER = 'X-ScrapeLock-Self';

	/**
	 * How long a signature is valid, in seconds.
	 */
	const WINDOW = 600;

	/**
	 * How long a learned address is kept, in seconds (30 days).
	 */
	const KEEP = 2592000;

	/**
	 * Most learned addresses kept.
	 */
	const MAX_LEARNED = 8;

	/**
	 * Single event that rewrites the pre-cache check's configuration after an address was learned.
	 */
	const CHANGED = 'pncp_server_ips_changed';

	/**
	 * 3.12.1: transient: the addresses the server's own requests were seen leaving from (address => time), found
	 * from the answers to the site's signed requests (seen()), each kept 24 hours after it was last seen.
	 */
	const OUTBOUND = 'pncp_server_outbound';

	/**
	 * 3.12.1: how long a detected outbound address is kept after it was last seen, in seconds (24 hours).
	 */
	const OUTBOUND_KEEP = 86400;

	/**
	 * 3.12.1: transient prefix (+ nonce): the address a signed request arrived from ("x": its nonce was used twice),
	 * for the request of the site that sent it (seen()).
	 */
	const SEEN = 'pncp_seen_';

	/**
	 * 3.12.1: the request header ScrapeLock adds to the site's requests to itself: a signature of the method, the
	 * host, the path, the time and a random nonce ("time.nonce.hmac"). A request that carries a valid one passes
	 * every check (sig_ok()).
	 */
	const SIG_HEADER = 'X-ScrapeLock-Sig';

	/**
	 * 3.12.1: how long a signature of SIG_HEADER is valid, in seconds (either way, for clocks a little apart).
	 */
	const SIG_WINDOW = 60;

	/**
	 * 3.12.1: the signatures checked in this request: "header|method|host|path" => the result of sig_check(). The
	 * early check and the normal check of one request see the same signature, whose nonce can be used only once.
	 *
	 * @var array<string, array{result:string, host:string, received:string, authentic:bool}>
	 */
	private static $sig_seen = array();

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( PNCP_Ip::CRON, array( __CLASS__, 'refresh' ), 5, 0 ); // Before the pre-cache check is rewritten (30).
		add_action( 'admin_init', array( __CLASS__, 'maybe_refresh' ) );
		add_action( self::CHANGED, array( __CLASS__, 'changed' ) );
		add_filter( 'http_request_args', array( __CLASS__, 'sign' ), 10, 2 );
		add_filter( 'http_response', array( __CLASS__, 'seen' ), 10, 3 );
		add_action( 'requests-requests.before_redirect', array( __CLASS__, 'unsign_redirect' ), 10, 4 );
		// 3.12.2: a request that carries the site's signature is checked once, also when it comes from the loopback
		// (which every check exempts before asking for the signature): its diagnostics and the answer's header
		// "X-ScrapeLock: ok" tell the site's own request that this WordPress answered it (PNCP_Self_Check).
		if ( ! empty( $_SERVER['HTTP_X_SCRAPELOCK_SIG'] ) && 'cli' !== PHP_SAPI ) {
			self::sig_check();
		}
	}

	/**
	 * The stored state, cleaned.
	 *
	 * @return array{ips: string[], host: string, time: int, learned: array<string, int>, const: string}
	 */
	public static function stored() {
		$raw = get_option( self::OPTION, array() );
		$raw = is_array( $raw ) ? $raw : array();
		$out = array(
			'ips'     => array(),
			'host'    => isset( $raw['host'] ) && is_string( $raw['host'] ) ? $raw['host'] : '',
			'time'    => isset( $raw['time'] ) ? (int) $raw['time'] : 0,
			'learned' => array(),
			'const'   => isset( $raw['const'] ) && is_string( $raw['const'] ) ? $raw['const'] : '',
		);
		foreach ( isset( $raw['ips'] ) && is_array( $raw['ips'] ) ? $raw['ips'] : array() as $ip ) {
			$ip = PNCP_Ip::normalize( is_string( $ip ) ? $ip : '' );
			if ( '' !== $ip ) {
				$out['ips'][] = $ip;
			}
		}
		$now = time();
		foreach ( isset( $raw['learned'] ) && is_array( $raw['learned'] ) ? $raw['learned'] : array() as $ip => $seen ) {
			$ip = PNCP_Ip::normalize( (string) $ip );
			if ( '' !== $ip && (int) $seen > $now - self::KEEP ) {
				$out['learned'][ $ip ] = (int) $seen;
			}
		}
		return $out;
	}

	/**
	 * The stored addresses (resolved and learned), without the filter and without SERVER_ADDR.
	 *
	 * @return string[]
	 */
	public static function stored_ips() {
		$state = self::stored();
		return array_values( array_unique( array_merge( $state['ips'], array_keys( $state['learned'] ) ) ) );
	}

	/**
	 * Every address of the server: loopback, SERVER_ADDR, 3.12.1: the detected outbound ones (outbound_ips()) and
	 * SCRAPELOCK_SERVER_IPS (const_ips()), the stored ones and the filter's.
	 *
	 * @return string[] Addresses and CIDRs.
	 */
	public static function ips() {
		$ips    = array( '127.0.0.1', '::1' );
		$server = isset( $_SERVER['SERVER_ADDR'] ) ? PNCP_Ip::normalize( sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) ) : '';
		if ( '' !== $server ) {
			$ips[] = $server;
		}
		// 3.12.1: the addresses the server's requests leave from (detected, 24 hours) and SCRAPELOCK_SERVER_IPS.
		$ips = array_merge( $ips, self::outbound_ips(), self::const_ips() );
		/**
		 * 3.11: the server's own addresses. A request whose verified visitor IP is one of them (loopback and
		 * private addresses only when they did not come from far away) is never checked: Site Health, cron,
		 * cache preloads and the site's other requests to itself through the CDN.
		 * Read by the early check (only mu-plugins can add to it there) and written into the pre-cache check's
		 * configuration. Addresses or CIDRs (no wider than /8, IPv6 /16).
		 *
		 * @param string[] $ips Addresses: 127.0.0.1, ::1, SERVER_ADDR, the detected outbound ones, those of
		 *                      SCRAPELOCK_SERVER_IPS, the resolved and learned ones.
		 */
		$filtered = apply_filters( 'pncp_server_ips', array_merge( $ips, self::stored_ips() ) );
		$out      = array();
		foreach ( is_array( $filtered ) ? $filtered : array() as $range ) {
			$range = is_string( $range ) ? trim( $range ) : '';
			if ( '' === $range || ! PNCP_Ip::valid_range( $range ) || PNCP_Options::range_too_wide( $range ) ) {
				continue;
			}
			$out[] = false === strpos( $range, '/' ) ? PNCP_Ip::normalize( $range ) : $range;
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Is the address one of the server's?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_server_ip( $ip ) {
		$ip = PNCP_Ip::normalize( (string) $ip );
		return '' !== $ip && PNCP_Ip::in_any( $ip, self::ips() );
	}

	/**
	 * 3.12.1: the addresses and ranges of SCRAPELOCK_SERVER_IPS in wp-config.php (comma- or space-separated, e.g.
	 * define( 'SCRAPELOCK_SERVER_IPS', '203.0.113.50, 2001:db8:5::/64' );): the addresses the server's own
	 * requests leave from, when ScrapeLock cannot find them itself. Read by the early check as well; written into
	 * the pre-cache check's configuration. A range wider than /8 (IPv6 /16) is ignored. List only the server: a
	 * proxy or load balancer in front of the site is not the server, and every visitor would pass through it.
	 *
	 * @return string[]
	 */
	public static function const_ips() {
		if ( ! defined( 'SCRAPELOCK_SERVER_IPS' ) ) {
			return array();
		}
		$raw = constant( 'SCRAPELOCK_SERVER_IPS' );
		$raw = is_array( $raw ) ? implode( ',', array_map( 'strval', $raw ) ) : ( is_scalar( $raw ) ? (string) $raw : '' );
		$out = array();
		foreach ( (array) preg_split( '/[\s,;]+/', $raw, -1, PREG_SPLIT_NO_EMPTY ) as $range ) {
			$range = trim( (string) $range );
			if ( ! PNCP_Ip::valid_range( $range ) || PNCP_Options::range_too_wide( $range ) ) {
				continue;
			}
			$range = false === strpos( $range, '/' ) ? PNCP_Ip::normalize( $range ) : $range;
			if ( '' !== $range ) {
				$out[] = $range;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * 3.12.1: the addresses the server's own requests were seen leaving from in the last 24 hours (OUTBOUND).
	 *
	 * @return string[]
	 */
	public static function outbound_ips() {
		$list = get_transient( self::OUTBOUND );
		$out  = array();
		foreach ( is_array( $list ) ? $list : array() as $ip => $seen ) {
			$ip = PNCP_Ip::normalize( (string) $ip );
			if ( '' !== $ip && (int) $seen > time() - self::OUTBOUND_KEEP ) {
				$out[] = $ip;
			}
		}
		return $out;
	}

	/**
	 * 3.12.1: the address a request arrived from, as the first proxy in front of the site saw it: behind a CDN edge
	 * (REMOTE_ADDR on its list) the last address of X-Forwarded-For, which the edge appends itself (Cloudflare:
	 * CF-Connecting-IP); otherwise the visitor IP, when it can be trusted. Only for a request the site signed
	 * (sig_ok(), seen()): for anyone else these headers say whatever they like. '' for a private or CDN address.
	 *
	 * @return string
	 */
	public static function arrived_from() {
		$remote = PNCP_Ip::remote_addr();
		$ip     = '';
		if ( '' !== $remote && PNCP_Ip::is_cdn( $remote ) ) {
			$cf = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '';
			if ( '' !== $cf && PNCP_Ip::in_any( $remote, PNCP_Ip::list_of( 'cloudflare' ) ) ) {
				$ip = $cf;
			} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
				$ip    = (string) end( $parts );
			}
		} elseif ( PNCP_Ip::reliable() ) {
			$ip = PNCP_Ip::client_ip();
		}
		$ip = PNCP_Ip::normalize( $ip );
		return '' === $ip || PNCP_Ip::is_private( $ip ) || PNCP_Ip::is_cdn( $ip ) ? '' : $ip;
	}

	/**
	 * 3.12.1: the answer to one of the site's own signed requests (filter http_response): the address that request
	 * arrived from (sig_ok() noted it under its nonce) is the server's outbound address. Only here, in the request
	 * that sent it: someone who got hold of a signature and used it first would otherwise make their own address
	 * the server's; then the nonce was used twice ("x") and nothing is learned.
	 *
	 * @param array<string, mixed>|WP_Error $response The answer.
	 * @param array<string, mixed>          $args     The request arguments.
	 * @param string                        $url      Address.
	 * @return array<string, mixed>|WP_Error The answer, unchanged.
	 */
	public static function seen( $response, $args, $url ) {
		$sent = is_array( $args ) && isset( $args['headers'] ) && is_array( $args['headers'] ) && isset( $args['headers'][ self::SIG_HEADER ] ) ? (string) $args['headers'][ self::SIG_HEADER ] : '';
		if ( '' === $sent || is_wp_error( $response ) || ! preg_match( '/^\d{9,11}\.([0-9a-f]{24})\.[0-9a-f]{64}(?:\.[0-9a-f]{16})?$/', $sent, $m ) ) {
			return $response;
		}
		$host = strtolower( (string) wp_parse_url( (string) $url, PHP_URL_HOST ) );
		if ( '' === $host || ! in_array( $host, self::own_hosts(), true ) ) {
			return $response;
		}
		$from = get_transient( self::SEEN . $m[1] );
		if ( false === $from ) {
			return $response;
		}
		delete_transient( self::SEEN . $m[1] );
		$ip = PNCP_Ip::normalize( is_string( $from ) ? $from : '' );
		if ( '' !== $ip && ! PNCP_Ip::is_private( $ip ) && ! PNCP_Ip::is_cdn( $ip ) ) {
			self::note_outbound( $ip );
		}
		return $response;
	}

	/**
	 * 3.12.1: the server's own request left it from this address (seen()): one of the server's, kept 24 hours after
	 * it was last seen (OUTBOUND; at most 4, written at most once an hour per address) and among the learned
	 * addresses of 3.11 (30 days). A new one goes into the pre-cache check's configuration.
	 *
	 * @param string $ip The address.
	 */
	public static function note_outbound( $ip ) {
		$ip = PNCP_Ip::normalize( (string) $ip );
		if ( '' === $ip ) {
			return;
		}
		$list  = get_transient( self::OUTBOUND );
		$list  = is_array( $list ) ? array_map( 'intval', $list ) : array();
		$known = isset( $list[ $ip ] ) && $list[ $ip ] > time() - self::OUTBOUND_KEEP;
		if ( ! $known || $list[ $ip ] < time() - HOUR_IN_SECONDS ) {
			$list[ $ip ] = time();
			arsort( $list );
			set_transient( self::OUTBOUND, array_slice( $list, 0, 4, true ), self::OUTBOUND_KEEP );
		}
		if ( ! $known ) {
			self::changed_later();
		}
		self::remember( $ip );
	}

	/**
	 * Does this request come from the server itself, through a proxy or CDN in front of the site? Its visitor IP
	 * (client_ip(): only from a trusted proxy's header) is a public address of the server and can be trusted.
	 * Loopback and private addresses are left to PNCP_Ip::is_local_request() (every hop must be local): a
	 * "127.0.0.1" that came from far away is a forged one. A CDN edge standing in for its visitors is never the
	 * server. A request signed by the site (sign()) teaches its address (learn()). 3.12.1: a request with a
	 * valid signature of SIG_HEADER (sig_ok()) is the server's own, from any address.
	 *
	 * @return bool
	 */
	public static function is_request() {
		// 3.12.1: the site's own request, signed (SIG_HEADER): whatever address it came back from. Behind Bunny
		// without the CDN secret the visitor IP is the edge, or an address that cannot be trusted, so the address
		// alone never told it apart from a visitor (the "Security headers" check got a 403 from its own site).
		if ( self::sig_ok() ) {
			return true;
		}
		$ip = PNCP_Ip::client_ip();
		if ( '' === $ip || ! PNCP_Ip::reliable() ) {
			return false;
		}
		// 3.12.1: a private address only from SCRAPELOCK_SERVER_IPS, the administrator's own word, and only when it
		// came no further than the server's network and is not a proxy passing visitors on.
		if ( PNCP_Ip::is_private( $ip ) ) {
			return PNCP_Ip::in_any( $ip, self::const_ips() ) && PNCP_Ip::came_from_near() && ! PNCP_Ip::untrusted_proxy_peer();
		}
		if ( PNCP_Ip::is_cdn_edge( $ip ) || PNCP_Ip::is_cdn( $ip ) ) {
			return false;
		}
		return self::is_server_ip( $ip ) || self::learn( $ip );
	}

	/**
	 * The signature of the site's requests to itself: "time.hmac".
	 *
	 * @param int    $time Time.
	 * @param string $key  Key.
	 * @return string
	 */
	private static function token( $time, $key ) {
		return (int) $time . '.' . substr( hash_hmac( 'sha256', 'pncp-self|' . (int) $time, $key ), 0, 40 );
	}

	/**
	 * The signature key ('' when there is none yet; created only by sign()).
	 *
	 * @param bool $create Create it when missing.
	 * @return string
	 */
	private static function key( $create = false ) {
		$key = (string) get_option( self::KEY_OPTION, '' );
		if ( strlen( $key ) < 32 && $create && function_exists( 'wp_generate_password' ) ) {
			$key = wp_generate_password( 48, false, false );
			update_option( self::KEY_OPTION, $key, true );
			// 3.12.1: the pre-cache check gets the new key with its line in wp-config.php (PNCP_Precheck::block()),
			// rewritten by WP cron or the next wp-admin page (never during a visitor's request).
			if ( class_exists( 'PNCP_Precheck' ) && PNCP_Precheck::wanted() ) {
				update_option( PNCP_Precheck::STATUS, 'deferred', false );
				if ( ! wp_next_scheduled( self::CHANGED ) ) {
					wp_schedule_single_event( time(), self::CHANGED );
				}
			}
		}
		return strlen( $key ) < 32 ? '' : $key;
	}

	/**
	 * Does this request carry a valid signature of the site?
	 *
	 * @return bool
	 */
	public static function signed() {
		$name = 'HTTP_' . strtoupper( str_replace( '-', '_', self::HEADER ) );
		$sent = isset( $_SERVER[ $name ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $name ] ) ) : '';
		if ( '' === $sent || ! preg_match( '/^(\d{9,11})\.[0-9a-f]{40}$/', $sent, $m ) ) {
			return false;
		}
		$time = (int) $m[1];
		$key  = self::key();
		return '' !== $key && abs( time() - $time ) <= self::WINDOW && hash_equals( self::token( $time, $key ), $sent );
	}

	/**
	 * Remembers the address of a signed request (once a day per address): it is the server's.
	 *
	 * @param string $ip The verified visitor IP.
	 * @return bool Whether the request is signed.
	 */
	private static function learn( $ip ) {
		if ( ! self::signed() ) {
			return false;
		}
		// 3.12.1: each signature teaches once. Seen by someone else (a log, a proxy on the way), it could otherwise
		// be sent again from their own address within the 10 minutes and make that address one of the server's.
		$name = 'HTTP_' . strtoupper( str_replace( '-', '_', self::HEADER ) );
		$sent = isset( $_SERVER[ $name ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $name ] ) ) : '';
		if ( ! PNCP_Log::cache_add( 'pncp_sl_' . md5( $sent . '|' . $ip ), 1, 2 * self::WINDOW + 60 ) && ! isset( self::stored()['learned'][ $ip ] ) ) {
			return false;
		}
		return self::remember( $ip );
	}

	/**
	 * Remembers an address of the server (once a day per address) among the learned ones.
	 *
	 * @param string $ip The address.
	 * @return bool True.
	 */
	private static function remember( $ip ) {
		$state = self::stored();
		$known = isset( $state['learned'][ $ip ] );
		if ( ! $known || $state['learned'][ $ip ] < time() - DAY_IN_SECONDS ) {
			$state['learned'][ $ip ] = time();
			arsort( $state['learned'] );
			$state['learned'] = array_slice( $state['learned'], 0, self::MAX_LEARNED, true );
			update_option( self::OPTION, $state, true );
			if ( ! $known ) {
				self::changed_later();
			}
		}
		return true;
	}

	/**
	 * The pre-cache check gets a new address in this request, once every plugin has loaded (its configuration also
	 * holds what other plugins add with filters): until then its configuration was out of date, and Site Health
	 * called the check "on but not running" until WP cron ran.
	 */
	private static function changed_later() {
		if ( did_action( 'wp_loaded' ) ) {
			self::changed();
		} elseif ( ! has_action( 'wp_loaded', array( __CLASS__, 'changed' ) ) ) {
			add_action( 'wp_loaded', array( __CLASS__, 'changed' ) );
		}
		if ( function_exists( 'wp_schedule_single_event' ) && ! wp_next_scheduled( self::CHANGED ) ) {
			wp_schedule_single_event( time(), self::CHANGED ); // In case this request ends before wp_loaded.
		}
	}

	/**
	 * Adds the signature to WordPress's requests to the site's own address (filter http_request_args).
	 *
	 * @param array<string, mixed> $args Request arguments.
	 * @param string               $url  Address.
	 * @return array<string, mixed>
	 */
	public static function sign( $args, $url ) {
		if ( ! is_array( $args ) || ( isset( $args['headers'] ) && ! is_array( $args['headers'] ) ) ) {
			return $args;
		}
		$host = strtolower( (string) wp_parse_url( (string) $url, PHP_URL_HOST ) );
		if ( '' === $host || ! in_array( $host, self::own_hosts(), true ) ) {
			return $args;
		}
		$key = self::key( true );
		if ( '' !== $key ) {
			$method                              = isset( $args['method'] ) && is_string( $args['method'] ) ? $args['method'] : 'GET';
			$args['headers']                     = isset( $args['headers'] ) ? $args['headers'] : array();
			$args['headers'][ self::HEADER ]     = self::token( time(), $key );
			$args['headers'][ self::SIG_HEADER ] = self::sig_token( $method, (string) $url );
		}
		return $args;
	}

	/**
	 * 3.12.1: the key of SIG_HEADER, made from the server key (the option the early check can read: it runs before
	 * wp_salt() exists). '' when there is no server key yet.
	 *
	 * @param bool $create Create the server key when missing.
	 * @return string
	 */
	public static function sig_key( $create = false ) {
		$key = self::key( $create );
		return '' === $key ? '' : hash_hmac( 'sha256', 'pncp-sig-key|v1', $key );
	}

	/**
	 * 3.12.1: the signature of one request. The pre-cache check computes the same (PNCP_Precheck_Runtime::self_signed()).
	 *
	 * @param string $method Method (uppercase).
	 * @param string $host   Host (lowercase, without the port).
	 * @param string $path   Path (decoded).
	 * @param int    $time   Time.
	 * @param string $nonce  Nonce.
	 * @param string $key    Key (sig_key()).
	 * @return string
	 */
	public static function sig_mac( $method, $host, $path, $time, $nonce, $key ) {
		return hash_hmac( 'sha256', 'pncp-sig|v1|' . $method . '|' . $host . '|' . $path . '|' . (int) $time . '|' . $nonce, $key );
	}

	/**
	 * 3.12.1: the value of SIG_HEADER for a request. 3.12.2: "time.nonce.hmac.hint": the hint names the host and the
	 * path it was signed for (hint()), so the check knows which of the site's hosts to verify it with whatever
	 * Host header reached the server (a CDN that does not forward it), and can say why a signature failed.
	 * '' without a key.
	 *
	 * @param string   $method Method.
	 * @param string   $url    Address.
	 * @param int|null $time   Time (null = now; tests).
	 * @return string
	 */
	public static function sig_token( $method, $url, $time = null ) {
		$key = self::sig_key( true );
		if ( '' === $key ) {
			return '';
		}
		$time  = null === $time ? time() : (int) $time;
		$nonce = bin2hex( random_bytes( 12 ) );
		$host  = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		$path  = self::sig_path( (string) wp_parse_url( $url, PHP_URL_PATH ) );
		return $time . '.' . $nonce . '.' . self::sig_mac( strtoupper( trim( (string) $method ) ), $host, $path, $time, $nonce, $key ) . '.' . self::hint( $host, $path );
	}

	/**
	 * 3.12.2: the hint of a signature: 8 hex digits of the host it was signed for and 8 of its path (MD5, not
	 * secret: both are in the request anyway). The pre-cache check computes the same.
	 *
	 * @param string $host Host (lowercase, without the port).
	 * @param string $path Path (sig_path()).
	 * @return string
	 */
	public static function hint( $host, $path ) {
		return substr( md5( 'h|' . $host ), 0, 8 ) . substr( md5( 'p|' . $path ), 0, 8 );
	}

	/**
	 * 3.12.1: a path as it is signed: decoded, '/' when empty. 3.12.2: repeated slashes as one (a CDN or proxy that
	 * joins its origin path and the request's path may send "//").
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function sig_path( $path ) {
		$path = (string) preg_replace( '#/{2,}#', '/', rawurldecode( (string) $path ) );
		return '' === $path ? '/' : $path;
	}

	/**
	 * 3.12.1: the host this request was sent to: lowercase, without the port ('' when there is none).
	 *
	 * @return string
	 */
	public static function request_host() {
		$host = isset( $_SERVER['HTTP_HOST'] ) ? strtolower( trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) ) ) : '';
		return (string) preg_replace( '/:\d+$/', '', $host );
	}

	/**
	 * 3.12.1: does this request carry a valid signature of the site (SIG_HEADER)? See sig_check().
	 *
	 * @return bool
	 */
	public static function sig_ok() {
		return 'ok' === self::sig_check()['result'];
	}

	/**
	 * 3.12.2: the check of SIG_HEADER, with the reason when it fails. The signature must be made with the site's
	 * key for one of the site's own hosts (3.12.1 required the Host header to be one: behind a CDN that does not
	 * forward it, e.g. Bunny's default, the server gets the pull zone's origin name, and the site's own request
	 * was refused), for this method and path, within SIG_WINDOW, and its nonce never seen before (kept for twice
	 * the window, atomically: PNCP_Log::cache_add()). The answer is kept for the rest of the request, so the early
	 * check and the normal check use the nonce once. The address a valid signature arrived from is noted for the
	 * site's request that sent it (seen()): the address the server's requests leave from.
	 *
	 * Results: ok, none (no header), bad_format, no_key (the site has no key yet), expired (outside the window),
	 * host_mismatch (signed for a host that is not the site's), path_mismatch (signed for another path), bad_mac
	 * (another key or method, or changed), nonce_reused. "host" is the site host it was signed for (when known),
	 * "received" the Host header that reached the server.
	 *
	 * @return array{result:string, host:string, received:string, authentic:bool}
	 */
	public static function sig_check() {
		$name = 'HTTP_' . strtoupper( str_replace( '-', '_', self::SIG_HEADER ) );
		$sent = isset( $_SERVER[ $name ] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER[ $name ] ) ) ) : '';
		$out  = array(
			'result'    => 'none',
			'host'      => '',
			'received'  => self::request_host(),
			'authentic' => false,
		);
		if ( '' === $sent ) {
			return $out;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only its path is hashed and compared.
		$path   = self::sig_path( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		$memo   = $sent . '|' . $method . '|' . $out['received'] . '|' . $path;
		if ( isset( self::$sig_seen[ $memo ] ) ) {
			return self::$sig_seen[ $memo ];
		}
		$check = self::verify( $sent, $method, $path, self::own_hosts(), self::sig_key(), time() );
		$out   = array_merge( $out, $check );
		if ( 'ok' === $out['result'] && ! PNCP_Log::cache_add( 'pncp_sn_' . $check['nonce'], 1, 2 * self::SIG_WINDOW + 10 ) ) {
			$out['result'] = 'nonce_reused';
		}
		unset( $out['nonce'] );
		self::$sig_seen[ $memo ] = $out;
		if ( $out['authentic'] && in_array( $out['result'], array( 'ok', 'nonce_reused' ), true ) ) {
			// For the site's request that sent it (seen()): the address it arrived from, or "x" when the nonce was
			// used twice (someone else had the signature too, and either address may be theirs).
			$from = 'ok' === $out['result'] ? self::arrived_from() : 'x';
			if ( '' !== $from ) {
				set_transient( self::SEEN . $check['nonce'], $from, 2 * self::SIG_WINDOW + 10 );
			}
		}
		if ( class_exists( 'PNCP_Self_Check' ) ) {
			PNCP_Self_Check::note_sig( $out );
		}
		return $out;
	}

	/**
	 * 3.12.2: verifies a value of SIG_HEADER (without using its nonce). The same steps as the pre-cache check
	 * (PNCP_Precheck_Runtime::self_signed()). A signature without the hint of 3.12.2 is tried with each host.
	 * A HEAD request that a CDN passed on as GET still matches.
	 *
	 * @param string   $sent   The header.
	 * @param string   $method Method of the request.
	 * @param string   $path   Path of the request (sig_path()).
	 * @param string[] $hosts  The site's hosts.
	 * @param string   $key    Key (sig_key()).
	 * @param int      $now    Time.
	 * @return array{result:string, host:string, authentic:bool, nonce:string}
	 */
	public static function verify( $sent, $method, $path, $hosts, $key, $now ) {
		$out = array(
			'result'    => 'bad_format',
			'host'      => '',
			'authentic' => false,
			'nonce'     => '',
		);
		if ( ! preg_match( '/^(\d{9,11})\.([0-9a-f]{24})\.([0-9a-f]{64})(?:\.([0-9a-f]{8})([0-9a-f]{8}))?$/', (string) $sent, $m ) ) {
			return $out;
		}
		$out['nonce'] = $m[2];
		if ( '' === (string) $key ) {
			$out['result'] = 'no_key';
			return $out;
		}
		$time = (int) $m[1];
		if ( abs( (int) $now - $time ) > self::SIG_WINDOW ) {
			$out['result'] = 'expired';
			return $out;
		}
		$try = array_values( array_filter( array_map( 'strval', (array) $hosts ) ) );
		if ( isset( $m[4] ) && '' !== $m[4] ) {
			$found = array();
			foreach ( $try as $host ) {
				if ( substr( md5( 'h|' . $host ), 0, 8 ) === $m[4] ) {
					$found[] = $host;
				}
			}
			if ( ! $found ) {
				$out['result'] = 'host_mismatch';
				return $out;
			}
			$try         = $found;
			$out['host'] = $found[0];
			if ( substr( md5( 'p|' . $path ), 0, 8 ) !== $m[5] ) {
				$out['result'] = 'path_mismatch';
				return $out;
			}
		}
		$methods = 'GET' === $method ? array( 'GET', 'HEAD' ) : array( $method );
		foreach ( $try as $host ) {
			foreach ( $methods as $verb ) {
				if ( hash_equals( self::sig_mac( $verb, $host, $path, $time, $m[2], $key ), $m[3] ) ) {
					$out['result']    = 'ok';
					$out['host']      = $host;
					$out['authentic'] = true;
					return $out;
				}
			}
		}
		$out['result'] = 'bad_mac';
		return $out;
	}

	/**
	 * 3.12.1: forgets the signatures checked in this request (tests).
	 */
	public static function forget() {
		self::$sig_seen = array();
	}

	/**
	 * A signed request that is redirected to another host does not take the signature there: Requests sends the
	 * same headers to the new address, so a redirect from the site to someone else's server (an open redirect of
	 * a plugin, a moved page) would hand them a signature that makes their address one of the server's for 30
	 * days (learn()). Action requests-requests.before_redirect.
	 *
	 * 3.12.1: also SIG_HEADER. A redirect on the site's own host (http to https, a trailing slash) gets a new one
	 * for its address and method, since a signature holds only for the path it was made for.
	 *
	 * @param string               $location The new address.
	 * @param array<string, mixed> $headers  The request headers.
	 * @param mixed                $data     The request body.
	 * @param array<string, mixed> $options  The request options (type: the method of the redirected request).
	 */
	public static function unsign_redirect( &$location, &$headers, &$data = null, &$options = null ) {
		if ( ! is_array( $headers ) ) {
			return;
		}
		$host = strtolower( (string) wp_parse_url( (string) $location, PHP_URL_HOST ) );
		$own  = '' !== $host && in_array( $host, self::own_hosts(), true );
		$sig  = false;
		foreach ( array_keys( $headers ) as $name ) {
			if ( 0 === strcasecmp( (string) $name, self::SIG_HEADER ) ) {
				$sig = true;
				unset( $headers[ $name ] );
			} elseif ( ! $own && 0 === strcasecmp( (string) $name, self::HEADER ) ) {
				unset( $headers[ $name ] );
			}
		}
		if ( $own && $sig ) {
			$method = is_array( $options ) && isset( $options['type'] ) && is_string( $options['type'] ) ? $options['type'] : 'GET';
			$token  = self::sig_token( $method, (string) $location );
			if ( '' !== $token ) {
				$headers[ self::SIG_HEADER ] = $token;
			}
		}
	}

	/**
	 * The site's own host names (home and site address), lowercase.
	 *
	 * @return string[]
	 */
	public static function own_hosts() {
		$hosts = array();
		foreach ( array( home_url( '/' ), site_url( '/' ) ) as $address ) {
			$host = strtolower( (string) wp_parse_url( $address, PHP_URL_HOST ) );
			if ( '' !== $host ) {
				$hosts[] = $host;
			}
		}
		return array_values( array_unique( $hosts ) );
	}

	/**
	 * In wp-admin: looks the addresses up again once a day, or when the site's address changed.
	 */
	public static function maybe_refresh() {
		if ( wp_doing_ajax() ) {
			return;
		}
		$state = self::stored();
		// 3.12.1: and when SCRAPELOCK_SERVER_IPS was changed in wp-config.php (the pre-cache check gets it at once).
		if ( $state['time'] < time() - DAY_IN_SECONDS || $state['time'] > time() + HOUR_IN_SECONDS || implode( ',', self::own_hosts() ) !== $state['host'] || md5( implode( ',', self::const_ips() ) ) !== $state['const'] ) {
			self::refresh();
		}
	}

	/**
	 * Looks up the addresses of the site's host names and of the server's own name (WP cron, wp-admin), without
	 * CDN addresses, and stores them with the learned ones. Rewrites the pre-cache check's configuration when
	 * they changed.
	 *
	 * @return string[] The resolved addresses.
	 */
	public static function refresh() {
		$state = self::stored();
		$names = self::own_hosts();
		if ( function_exists( 'gethostname' ) ) {
			$names[] = strtolower( (string) gethostname() );
		}
		$ips = array();
		foreach ( array_unique( array_filter( $names ) ) as $name ) {
			foreach ( self::resolve( $name ) as $ip ) {
				if ( ! PNCP_Ip::is_cdn( $ip ) ) {
					$ips[] = $ip;
				}
			}
		}
		$ips      = array_values( array_unique( $ips ) );
		$const    = md5( implode( ',', self::const_ips() ) );
		$changed  = $ips !== $state['ips'] || $const !== $state['const'];
		$new      = array(
			'ips'     => $ips,
			'host'    => implode( ',', self::own_hosts() ),
			'time'    => time(),
			'learned' => $state['learned'],
			'const'   => $const,
		);
		update_option( self::OPTION, $new, true );
		if ( $changed ) {
			self::changed();
		}
		return $ips;
	}

	/**
	 * The addresses (IPv4 and IPv6) a host name resolves to. Filter `pncp_server_dns` (an array short-circuits
	 * the lookup; tests).
	 *
	 * @param string $name Host name or address.
	 * @return string[]
	 */
	public static function resolve( $name ) {
		$name = trim( (string) $name, " \t\n\r\0\x0B[]" );
		/**
		 * 3.11: the addresses of one of the server's names, instead of a DNS lookup (null = look up).
		 *
		 * @param string[]|null $ips  Addresses.
		 * @param string        $name Host name.
		 */
		$pre = apply_filters( 'pncp_server_dns', null, $name );
		if ( is_array( $pre ) ) {
			$found = $pre;
		} elseif ( '' !== PNCP_Ip::normalize( $name ) ) {
			$found = array( $name );
		} elseif ( '' === $name || ! preg_match( '/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/i', $name ) || 'localhost' === $name ) {
			$found = array();
		} else {
			$found = array();
			$v4    = @gethostbynamel( $name ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- No answer = false.
			if ( is_array( $v4 ) ) {
				$found = $v4;
			}
			if ( function_exists( 'dns_get_record' ) ) {
				$v6 = @dns_get_record( $name, DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- No answer = false.
				foreach ( is_array( $v6 ) ? $v6 : array() as $record ) {
					if ( isset( $record['ipv6'] ) ) {
						$found[] = (string) $record['ipv6'];
					}
				}
			}
		}
		$out = array();
		foreach ( $found as $ip ) {
			$ip = PNCP_Ip::normalize( is_string( $ip ) ? $ip : '' );
			if ( '' !== $ip ) {
				$out[] = $ip;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * The addresses changed: the pre-cache check gets them in its configuration.
	 */
	public static function changed() {
		if ( class_exists( 'PNCP_Precheck' ) ) {
			PNCP_Precheck::refresh();
		}
	}
}
