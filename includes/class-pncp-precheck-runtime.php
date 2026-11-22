<?php
/**
 * Pre-cache check: runs from wp-config.php, before WordPress and before the page cache (WP Rocket,
 * WP Super Cache, …) can serve a stored page. Without WordPress: no database, no hooks, no translations.
 *
 * It only does what can be decided cheaply: always-blocked IPs, active bans and the page limit per IP.
 * Everything else (bots, verification of search engines, countries, the trap, logged-in users) stays with
 * the normal check, which runs for every request that is not served from the cache. Counters live in APCu
 * when available, otherwise in small files in the plugin's data folder (uploads/scrapelock/precheck-RANDOM).
 * When in doubt, the request passes: any error here must never take the site down.
 *
 * 3.12.9: with APCu or Redis (the object cache's server, see store()) everything the check keeps (counters, bans,
 * strikes, probe memory, nonces, events, its configuration) is in memory, and a visitor's request reads and writes
 * no file of the data folder: a stalled disk (the live slow logs of 3.12.8: ftruncate(), fclose(), scandir() and
 * unlink() of this file in requests of more than 30 s) does not stall the check. The files remain for servers
 * without either, written without waiting: counters appended (increment()), other files replaced whole
 * (put_atomic()), no lock that waits, and the old minutes removed by the hourly cleanup, not by visitors.
 *
 * The line in wp-config.php includes this file and calls PNCP_Precheck_Runtime::boot() with the data folder;
 * the configuration is read from config.json there, written by PNCP_Precheck (includes/class-pncp-precheck.php).
 * This file only defines the class: opened directly, it does nothing.
 *
 * It is the only file wp-config.php includes, before WordPress, so it loads no other file of the plugin: the
 * address and User-Agent helpers (client_ip(), normalize_ip(), in_any(), is_local(), ua_listed(), limit_key())
 * repeat PNCP_Ip and PNCP_Bots on purpose. Those need WordPress, and a second file missing during a plugin update
 * would be a fatal error in wp-config.php for every page. A change to one side must be made on the other too
 * (tests/t_fixes351.php and t_311_integration.php send the same requests to both). 3.12.9: the one exception is
 * the circuit breaker (class-pncp-breaker.php), loaded only when it is there and readable (breaker()).
 *
 * @package ScrapeLock
 */

// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors.Discouraged -- Runs before WordPress: its functions do not exist yet; every value is validated below.

/**
 * The check that runs before the page cache.
 */
final class PNCP_Precheck_Runtime {

	/**
	 * 3.5: seconds after a first probe in which another probe of the same IP key is part of the same first
	 * burst (probe_seen()); PNCP_Bots::FIRST_BAN_BURST is the same for WordPress.
	 */
	const BURST = 10;

	/**
	 * 3.6: at most this many new files a minute (counters, probe memory, probe bans) without APCu, as
	 * PNCP_Bots::DB_NEW_KEYS_PER_MINUTE for the database. Filter `pncp_precheck_new_files_per_minute` (0 = no cap).
	 */
	const NEW_FILES = 2000;

	/**
	 * 3.6.1: new counter files one network (IPv4 /24, IPv6 /48) may take from NEW_FILES each minute, and how many
	 * times the page limit its shared counter allows (see hit(); PNCP_Bots::NET_NEW_KEYS_PER_MINUTE).
	 */
	const NET_FILES = 64;

	/**
	 * 3.6.1: see NET_FILES.
	 */
	const NET_FACTOR = 4;

	/**
	 * 3.12.9: seconds to connect to Redis, and to wait for each of its answers (redis()).
	 */
	const REDIS_TIMEOUT = 0.05;

	/**
	 * 3.12.9: milliseconds a request may spend on sweep() or sync_later() (at its end, after the page).
	 */
	const SWEEP_MS = 25;

	/**
	 * 3.12.9: seconds between two comparisons of the cached configuration with config.json (load()).
	 */
	const CFG_CHECK = 10;

	/**
	 * 3.12.9: how long one comparison (load()) holds off the others: while its stat() waits for a stalled disk, no
	 * other request starts one (at most one PHP worker waits, once in this many seconds).
	 */
	const CFG_HOLD = 300;

	/**
	 * 3.12.9: a copy of the configuration WordPress put in the store this recently is not compared with config.json
	 * at all (load()): every change of the file is pushed (PNCP_Precheck::push_config(), push_web()), and WordPress
	 * pushes it again every hour (PNCP_Precheck::sync_store()), so a visitor's request does not even stat() it.
	 */
	const CFG_FRESH = 7200;

	/**
	 * 3.12.9: a counter file stops growing at this many bytes (increment()).
	 */
	const MAX_COUNT = 100000;

	/**
	 * 3.12.9: most event lines queued in APCu or Redis between two imports (the oldest go first).
	 */
	const EVENTS_MAX = 10000;

	/**
	 * 3.12.9: whether the last hit() count came from APCu or Redis, which give each request its own number
	 * (crossed()).
	 *
	 * @var bool
	 */
	public static $exact = true;

	/**
	 * 3.12.9: milliseconds spent on Redis in this request (connecting and every call), for the diagnostics.
	 *
	 * @var float
	 */
	public static $redis_ms = 0.0;

	/**
	 * 3.12.9: the Redis connections of this request (false: none or failed), see redis().
	 *
	 * @var array<string, mixed>
	 */
	private static $conns = array();

	/**
	 * 3.12.9: whether sync_later() has been queued in this request.
	 *
	 * @var bool
	 */
	private static $sync_queued = false;

	/**
	 * Whether this request was logged here as "would block" ("Monitor only"): WordPress's own log then does
	 * not log it a second time (PNCP_Log::add()).
	 *
	 * @var bool
	 */
	public static $monitored = false;

	/**
	 * 3.6: the addresses the request passed through (REMOTE_ADDR and the trusted proxies after the visitor), as
	 * found by client_ip(). See is_local_request().
	 *
	 * @var string[]
	 */
	public static $hops = array();

	/**
	 * 3.6: a trusted CDN edge connected without a usable "Real visitor IP" header, as in PNCP_Ip::is_cdn_edge().
	 *
	 * @var bool
	 */
	public static $no_visitor_ip = false;

	/**
	 * 3.6.1: whether the last hit() was counted under its network's shared counter (see hit()): such a count
	 * limits, but earns no violation.
	 *
	 * @var bool
	 */
	public static $shared_hit = false;

	/**
	 * 3.12.1: the signatures of the site's own requests checked in this request ("header|method|host|path" =>
	 * valid), see self_signed().
	 *
	 * @var array<string, bool>
	 */
	public static $self_seen = array();

	/**
	 * 3.12.2: the result of the last check of the site's signature in this request (self_signed()): '' (none sent),
	 * ok, bad_format, no_key, expired, host_mismatch, path_mismatch, bad_mac or nonce_reused. Read by WordPress
	 * (PNCP_Self_Check) for the diagnostics of the site's own requests.
	 *
	 * @var string
	 */
	public static $self_result = '';

	/**
	 * 3.12.2: the nonce of the site's signature that self_signed() accepted in this request ('' = none): its id
	 * (as PNCP_Self_Check::request_id()) goes into the answer's "X-ScrapeLock: ok id=…".
	 *
	 * @var string
	 */
	public static $self_nonce = '';

	/**
	 * 3.12.9: the circuit breaker has the counters of this check suspended (PNCP_Breaker): hit() counts nothing,
	 * strike() records nothing and no new file is created, so the request passes; bans already written still apply.
	 *
	 * @var bool
	 */
	public static $count_off = false;

	/**
	 * Called by the line in wp-config.php: reads the configuration from the data folder and runs the check.
	 *
	 * @param string               $dir   The data folder.
	 * @param string               $key   3.12.1: the key of the site's signed requests to itself (see self_signed()).
	 * @param array<string, mixed> $redis 3.12.9: the connection to the Redis server of the site's object cache
	 *                                    (PNCP_Precheck::redis_settings()), [] = none.
	 */
	public static function boot( $dir, $key = '', $redis = array() ) {
		try {
			$redis = is_array( $redis ) && $redis ? $redis + array( 'sk' => (string) $key ) : array();
			$c     = self::load( (string) $dir, $redis );
		} catch ( Throwable $e ) {
			return;
		}
		if ( null !== $c ) {
			$c['self_key'] = (string) $key; // Never in config.json, nor in APCu.
			self::run( $c );
		}
	}

	/**
	 * The configuration in config.json, or null.
	 *
	 * 3.12.9: from APCu, or else from Redis: WordPress puts every new configuration there itself (PNCP_Precheck::
	 * push_config(), also from WP-CLI through PNCP_Precheck::push_web()), so a visitor's request reads nothing from
	 * the disk. Before 3.12.9 APCu held it per change of the file, which cost a stat() of config.json in every
	 * request. Now a copy WordPress pushed in the last CFG_FRESH seconds is used as it is (no stat() at all). An
	 * older one (WordPress's hourly push missing, e.g. WP-Cron run from WP-CLI with APCu) is compared with the
	 * file's stat() by one request in CFG_CHECK seconds (the one that adds the "_chk" value), for a change
	 * WordPress could not push (the web server unreachable from WP-CLI): a metadata look-up of a file the kernel
	 * has cached, never a read unless it changed; no other request starts one before it returns (CFG_HOLD), so a
	 * stalled disk holds at most that one PHP worker. Only when the store holds no copy (empty after a restart) is
	 * the file read, and put there for the next requests.
	 *
	 * @param string               $dir   The data folder.
	 * @param array<string, mixed> $redis 3.12.9: the Redis connection (see boot()).
	 * @return array<string, mixed>|null
	 */
	public static function load( $dir, $redis = array() ) {
		if ( '' === $dir ) {
			return null;
		}
		$base = array(
			'dir'   => $dir,
			'redis' => $redis,
		);
		$file = $dir . '/config.json';
		$name = self::cfg_key( $dir );
		if ( function_exists( 'apcu_enabled' ) && apcu_enabled() ) {
			$cached = apcu_fetch( $name );
			if ( is_array( $cached ) && isset( $cached[1], $cached[2] ) && is_array( $cached[1] ) && 'mem' === $cached[0] ) {
				if ( ( isset( $cached[3] ) && (int) $cached[3] > time() - self::CFG_FRESH ) || ! apcu_add( $name . '_chk', 1, self::CFG_HOLD ) ) {
					return array_merge( $cached[1], $base );
				}
				$version = self::file_version( $file );
				apcu_store( $name . '_chk', 1, self::CFG_CHECK ); // The stat() returned: the next one in CFG_CHECK.
				if ( in_array( $version, array( '', $cached[2] ), true ) ) {
					return array_merge( $cached[1], $base );
				}
			}
		} elseif ( $redis ) {
			$keys = array( self::mem_key( $base, 'redis', 'cfg' ), self::mem_key( $base, 'redis', 'cfgv' ), self::mem_key( $base, 'redis', 'cfgchk' ), self::mem_key( $base, 'redis', 'cfgt' ) );
			$got  = self::redis_call(
				$base,
				static function ( $redis ) use ( $keys ) {
					$out = $redis->multi( Redis::PIPELINE )->get( $keys[0] )->get( $keys[1] )->get( $keys[3] )->exec();
					return is_array( $out ) && 3 === count( $out ) ? $out : false;
				}
			);
			$c = is_array( $got ) && is_string( $got[0] ) ? json_decode( $got[0], true ) : null;
			if ( self::cfg_ok( $c ) && ( (int) $got[2] > time() - self::CFG_FRESH || true !== self::mem_add( $base, 'cfgchk', '1', self::CFG_HOLD ) ) ) {
				return array_merge( (array) $c, $base );
			}
			if ( self::cfg_ok( $c ) ) {
				$version = self::file_version( $file );
				self::mem_set( $base, 'cfgchk', '1', self::CFG_CHECK ); // The stat() returned: the next one in CFG_CHECK.
				if ( in_array( $version, array( '', (string) $got[1] ), true ) ) {
					return array_merge( (array) $c, $base );
				}
			}
		}
		$json = (string) @file_get_contents( $file );
		$c    = json_decode( $json, true );
		if ( ! self::cfg_ok( $c ) ) {
			return null;
		}
		self::cache_config( $base, $c, $json );
		return array_merge( $c, $base );
	}

	/**
	 * 3.12.9: the version of config.json for the copy in APCu / Redis: modification time, size and inode ('' when
	 * it cannot be read: the copy is then kept).
	 *
	 * @param string $file File.
	 * @return string
	 */
	public static function file_version( $file ) {
		clearstatcache( true, $file );
		$stat = @stat( $file );
		return false === $stat ? '' : $stat['mtime'] . '|' . $stat['size'] . '|' . $stat['ino'];
	}

	/**
	 * 3.12.9: the APCu name of a data folder's configuration.
	 *
	 * @param string $dir The data folder.
	 * @return string
	 */
	public static function cfg_key( $dir ) {
		return 'pncp_pc_cfg_' . md5( $dir . '/config.json' );
	}

	/**
	 * 3.12.9: is this a configuration of a format this file reads?
	 *
	 * @param mixed $c Decoded configuration.
	 * @return bool
	 */
	public static function cfg_ok( $c ) {
		return is_array( $c ) && isset( $c['format'] ) && in_array( $c['format'], array( 2, 3 ), true );
	}

	/**
	 * 3.12.9: keeps a configuration in APCu (when it allows it) or else in Redis, with the crawler lists, until the
	 * next one replaces it (no expiry: a stale copy is replaced by PNCP_Precheck::push_config()).
	 *
	 * @param array<string, mixed> $base     The data folder and Redis connection.
	 * @param array<string, mixed> $c        Configuration.
	 * @param string               $json     Its JSON.
	 * @param string|null          $crawlers The crawler lists' JSON (null: read crawlers.json).
	 * @param bool                 $apcu     Into APCu when it is there (false: Redis only).
	 * @return string Where: 'apcu', 'redis' or ''.
	 */
	public static function cache_config( $base, $c, $json, $crawlers = null, $apcu = true ) {
		$dir = (string) $base['dir'];
		if ( null === $crawlers ) {
			$crawlers = (string) @file_get_contents( $dir . '/crawlers.json' );
		}
		if ( $apcu && function_exists( 'apcu_enabled' ) && apcu_enabled() ) {
			if ( empty( $c['apcu'] ) ) {
				return '';
			}
			$sets = json_decode( $crawlers, true );
			apcu_store( self::cfg_key( $dir ), array( 'mem', $c, self::file_version( $dir . '/config.json' ), time() ) );
			apcu_add( self::cfg_key( $dir ) . '_chk', 1, self::CFG_CHECK );
			apcu_store( self::cfg_key( $dir ) . '_crawlers', is_array( $sets ) ? $sets : array() );
			return 'apcu';
		}
		if ( ! empty( $base['redis'] ) && self::mem_set( $base, 'cfg', $json, 0 ) ) {
			self::mem_set( $base, 'cfgv', self::file_version( $dir . '/config.json' ), 0 );
			self::mem_set( $base, 'cfgt', (string) time(), 0 );
			self::mem_set( $base, 'crawlers', $crawlers, 0 );
			return 'redis';
		}
		return '';
	}

	/**
	 * Runs the check. Ends the request with 403 / 429 when it must be refused, otherwise returns.
	 *
	 * @param array<string, mixed> $c Configuration (see PNCP_Precheck::config()).
	 */
	public static function run( $c ) {
		// A run.php written before 3.3.1 passes its own configuration: it does nothing until wp-admin
		// replaces its line in wp-config.php.
		if ( ! is_array( $c ) || ! isset( $c['format'] ) || ! in_array( $c['format'], array( 2, 3 ), true ) ) {
			return;
		}
		// 3.12.9: the check is timed; one that took longer than the breaker's threshold (200 ms: a stalled disk or
		// counter store) suspends the counters for 10 minutes (breaker()).
		$breaker = 'cli' === PHP_SAPI ? '' : self::breaker( $c );
		$start   = hrtime( true );
		try {
			$verdict = self::verdict( $c, time() );
		} catch ( Throwable $e ) {
			$verdict = null;
		}
		if ( '' !== $breaker ) {
			PNCP_Breaker::observe( $breaker, hrtime( true ) - $start, 'pre-cache check' );
		}
		if ( null === $verdict ) {
			return;
		}
		list( $code, $reason, $ip ) = $verdict;
		// "Monitor only": the verdict is logged as "would block" (code 0) and the request goes on, to the page
		// cache or WordPress.
		if ( self::monitoring( $c, time() ) ) {
			self::event( $c, 0, $reason, $ip );
			self::$monitored = true;
			return;
		}
		self::event( $c, $code, $reason, $ip );
		if ( ! headers_sent() ) {
			http_response_code( $code );
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'X-Robots-Tag: noindex' );
			$from_server = false;
			$server_ip   = self::client_ip( $c, $from_server );
			$from_server = self::is_server_request( $c, $server_ip, $from_server );
			header( 'X-ScrapeLock: ' . self::refusal_marker( $reason, $from_server ) ); // 3.12.2: who refused (PNCP_Self_Check).
			if ( 429 === $code ) {
				header( 'Retry-After: 60' );
			}
		}
		if ( 'HEAD' !== self::method() ) {
			echo 429 === $code ? 'Too many requests.' : 'Access denied.';
		}
		exit;
	}

	/**
	 * 3.12.9: loads the circuit breaker (includes/class-pncp-breaker.php, the one other file this check reads: when
	 * it is missing or broken, e.g. halfway through a plugin update, the check runs without it) and sets
	 * $count_off. Returns the breaker's name for the counters' store (breaker_name(): "precheck_apcu",
	 * "precheck_redis" or "precheck_files"), or '' when there is nothing to time: no breaker, or already suspended.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return string
	 */
	public static function breaker( $c ) {
		self::$count_off = false;
		try {
			if ( ! class_exists( 'PNCP_Breaker', false ) ) {
				$file = __DIR__ . '/class-pncp-breaker.php';
				if ( ! is_file( $file ) ) {
					return '';
				}
				include_once $file;
				if ( ! class_exists( 'PNCP_Breaker', false ) ) {
					return '';
				}
			}
			PNCP_Breaker::setup( (string) $c['dir'], isset( $c['breaker'] ) && is_array( $c['breaker'] ) ? $c['breaker'] : array() );
			// Before the state is read: with the Redis store the breaker keeps it in the counters' connection, so
			// it never looks for a file of the data folder (breaker_hooks()).
			self::breaker_hooks( $c );
			$name            = self::breaker_name( $c );
			self::$count_off = PNCP_Breaker::open( $name );
			return self::$count_off ? '' : $name;
		} catch ( Throwable $e ) {
			return '';
		}
	}

	/**
	 * 3.12.2: the value of the X-ScrapeLock header of this check's 403 / 429, as PNCP_Self_Check::marker() makes it
	 * in WordPress: "refused"; for a request that carries the site's signature also the layer and the signature's
	 * result, and the reason only when the signature is the site's own (its MAC matched). No address or other data
	 * of the visitor. The layer and the signature's result only for the site's own signature or a request from the
	 * server's addresses: anyone can send the header, and a stranger gets just "refused".
	 *
	 * @param string $reason      The reason of the refusal.
	 * @param bool   $from_server Whether the request came from one of the server's addresses (is_server_request()).
	 * @return string
	 */
	public static function refusal_marker( $reason, $from_server = false ) {
		if ( '' === self::$self_result ) {
			return 'refused';
		}
		$own = in_array( self::$self_result, array( 'ok', 'nonce_reused' ), true );
		if ( ! $own && ! $from_server ) {
			return 'refused';
		}
		return 'refused' . ( $own && preg_match( '/^[a-z0-9_]{1,40}$/', (string) $reason ) ? ' ' . $reason : '' ) . ' layer=pre-cache sig=' . self::$self_result;
	}

	/**
	 * The decision: null (passes) or [code, reason, IP].
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 * @return array{0:int, 1:string, 2:string}|null
	 */
	public static function verdict( $c, $now ) {
		if ( 'cli' === PHP_SAPI || ! self::applies( $c ) ) {
			return null;
		}
		self::note_backend( $c, $now );
		if ( self::emergency( $c, $now ) ) {
			// 3.4: Emergency Mode's stricter page limit and bans (never looser than the stored ones).
			// 3.4.3: the stricter of the two also here, as in PNCP_Options::emergency_overlay(), so a configuration
			// written before 3.4.3 (always 2 violations) does not loosen a stored 1 or 0 (0 = never ban stays 0).
			// The ban duration is the file's: the overlay has always taken the longer one.
			$e     = (array) $c['emergency'];
			$limit = (int) $c['limit'];
			if ( isset( $e['limit'] ) && (int) $e['limit'] > 0 ) {
				$c['limit'] = $limit > 0 ? min( $limit, (int) $e['limit'] ) : (int) $e['limit'];
			}
			$strikes = (int) $c['ban_strikes'];
			if ( isset( $e['ban_strikes'] ) && $strikes > 0 ) {
				$c['ban_strikes'] = (int) $e['ban_strikes'] > 0 ? min( $strikes, (int) $e['ban_strikes'] ) : $strikes;
			}
			$c['ban_minutes'] = isset( $e['ban_minutes'] ) ? (int) $e['ban_minutes'] : (int) $c['ban_minutes'];
			// 3.4.3: the /56 limit and the human check's stricter limit, which Emergency Mode turns on.
			if ( ! empty( $e['v6_wide'] ) ) {
				$c['v6_wide'] = true;
			}
			if ( ! empty( $e['human'] ) && isset( $c['human'] ) && is_array( $c['human'] ) ) {
				$own                 = (int) $c['human']['limit'];
				$c['human']['limit'] = $own > 0 ? min( $own, (int) $e['human'] ) : (int) $e['human'];
			}
		}
		// 3.12.1: the site's own request, signed by WordPress (PNCP_Server_Ips::sig_ok()): from any address, before
		// "Only through the CDN" and every other check (Vulnerable points, Site Health, the Stealth test).
		if ( self::self_signed( $c, $now ) ) {
			// 3.12.9: WordPress (from WP-CLI) asks this PHP to take the new configuration and queued ban changes into
			// its APCu (PNCP_Precheck::push_web()). Answered here, before WordPress loads.
			if ( isset( $_GET['pncp_precheck_sync'] ) && 'POST' === self::method() ) {
				self::serve_sync( $c );
			}
			if ( ! headers_sent() ) {
				// 3.12.2: this server answered the site's own request, with the id of its signature
				// (PNCP_Self_Check::ok_marker(), is_own_answer()).
				header( 'X-ScrapeLock: ok id=' . substr( md5( 'id|' . self::$self_nonce ), 0, 8 ) );
			}
			return null;
		}
		$direct = self::not_via_cdn( $c );
		if ( '' !== $direct ) {
			return array( 403, 'not_via_cdn', $direct );
		}
		$ip = self::client_ip( $c, $reliable );
		if ( '' === $ip || self::is_local_request( $ip, $reliable ) || self::is_server_request( $c, $ip, $reliable ) ) {
			return null;
		}
		if ( $reliable && self::in_any( $ip, $c['allow'] ) ) {
			return null;
		}
		// A CDN address means "Real visitor IP" is not set: then one decision would hit many visitors at once.
		// 3.4: not without the CDN shared secret, when one is set: such a request came through someone else's
		// account at the CDN, and is limited like any other address.
		// 3.4.1: only the edge that connected (REMOTE_ADDR). A Cloudflare address from the real-IP header is a client of
		// its own (a Cloudflare Worker, which a scraper can rent), as in PNCP_Ip::is_cdn_edge().
		// 3.6: not when the edge sent no visitor IP: this site's own CDN always does.
		if ( ! self::$no_visitor_ip && self::is_cdn( $ip, $c ) && self::cdn_trust_ok( $c ) && self::normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '' ) === $ip ) {
			return null;
		}
		// 3.6.1: behind a proxy that "Real visitor IP" does not trust, every visitor has the proxy's (private) address:
		// a block, ban or limit on it would hit the whole site. Only the User-Agent checks below apply then;
		// WordPress warns the administrator (PNCP_Origin::notice(), Site Health).
		$per_ip = ! self::untrusted_proxy_peer( $ip );
		if ( $per_ip && self::in_any( $ip, $c['block'] ) ) {
			return array( 403, 'blocked_ip', $ip );
		}

		// Search engines: Google and Bing are verified with their official lists. The others (Applebot,
		// YandexBot) are verified with DNS by the normal check, so they are left to it.
		// A crawler that cannot be verified here (no list) still gets the ban check below: otherwise a banned
		// scraper only had to put "Applebot" in its User-Agent to read every cached page. 3.4.3: it gets a larger
		// limit of its own (below) instead of none.
		$ua         = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( (string) $_SERVER['HTTP_USER_AGENT'] ) : '';
		$unverified = false;
		foreach ( $c['crawlers'] as $i => $crawler ) {
			if ( self::ua_in( $ua, $crawler['ua'] ) ) {
				$ips = true === $crawler['ips'] ? self::crawler_set( $c, $i ) : $crawler['ips'];
				if ( null === $ips ) {
					$unverified = true;
				} elseif ( self::in_any( $ip, $ips ) ) {
					return null;
				}
				break; // Claims to be Google / Bing from another address: counted like everyone else.
			}
		}

		$dir    = (string) $c['dir'];
		$bankey = self::limit_key( $ip, (int) $c['v6_prefix'] ); // IPv6: the /64, so a ban is not dodged by rotating addresses.
		if ( $per_ip && self::banned( $c, $bankey, $now ) ) {
			return array( 403, 'banned', $ip );
		}
		// 3.4.3: the bot list (and an empty User-Agent), as the normal check, unless "always allowed".
		$allowed = self::ua_allowed( $c, $ua, $ip, $reliable );
		// 3.11: /.well-known/*, as the normal check: its services count as allowed there, and no User-Agent is no
		// reason to refuse it; nor from an address on Google's or Apple's official lists.
		$well_known = self::is_well_known( $c );
		if ( ! $allowed && $well_known && '' !== $ua && ! empty( $c['wk_agents'] ) && self::ua_in( $ua, array_filter( array_map( 'strval', (array) $c['wk_agents'] ) ) ) ) {
			$allowed = true;
		}
		if ( ! $allowed ) {
			if ( '' === trim( $ua ) && ! empty( $c['empty_ua'] ) && ! $well_known && ! ( $per_ip && self::official_ip( $c, $ip ) ) ) {
				return array( 403, 'empty_ua', $ip );
			}
			if ( '' !== $ua && ! empty( $c['bots'] ) && self::ua_listed( $ua, (array) $c['bots'] ) ) {
				return array( 403, 'bot_ua', $ip );
			}
		}
		if ( ! $per_ip ) {
			return null;
		}
		// 3.5: a scanner probe (.env, .git, wp-config.php backups, dumps, backup archives at the top of the site):
		// the configured paths can never be a WordPress page, so no 404 is needed to know. Only when the file does
		// not exist, and never for what the normal check exempts and this one cannot verify (a login cookie, a
		// crawler without a list, an allowed User-Agent, an IP that may be forged): those are left to WordPress.
		if ( isset( $c['probe'] ) && is_array( $c['probe'] ) && self::probe( $c, $ua, $ip, $bankey, $reliable, $allowed, $unverified ) ) {
			// 3.6: a new probe memory and ban only within the cap on new files (new_file_ok()); the 403 stays.
			// 3.12.9: with APCu or Redis no file is created, so no cap.
			$known = '' !== self::store( $c ) || is_file( $dir . '/probes/' . md5( $bankey ) ) || is_file( $dir . '/bans/' . md5( $bankey ) );
			if ( ! self::monitoring( $c, $now ) && (int) $c['ban_strikes'] > 0 && ( $known || self::new_file_ok( $c, $now ) ) ) {
				$full    = self::probe_seen( $c, $bankey, $now );
				$minutes = max( 1, (int) $c['ban_minutes'] );
				$first   = isset( $c['probe']['first'] ) ? (int) $c['probe']['first'] : 10;
				self::ban( $c, $bankey, $now + ( $full || $first <= 0 ? $minutes : min( $first, $minutes ) ) * 60 );
				if ( $full ) {
					self::event( $c, 403, 'ban', $ip ); // The full ban, as for the page limit; the first one is the 'probe' event.
				}
			}
			return array( 403, 'probe', $ip );
		}
		// Up to here (always-blocked IPs and temporary bans) every request is checked, even a POST: otherwise
		// a cached page could be served to an IP that is already blocked or banned. The rate limit below
		// counts the GET / HEAD views; the normal check counts the rest.
		if ( ! self::countable() || self::shop_page( $c ) ) {
			return null;
		}
		$limit = (int) $c['limit'];
		if ( $limit < 1 ) {
			return null;
		}
		// 3.11: a static file is not a page: its own counter, never a violation (as the normal check).
		if ( isset( $c['media'] ) && is_array( $c['media'] ) && self::is_media( $c ) ) {
			$preview = isset( $c['media']['preview'] ) ? array_filter( array_map( 'strval', (array) $c['media']['preview'] ) ) : array();
			if ( $allowed && '' !== $ua && $preview && self::ua_in( $ua, $preview ) ) {
				return null;
			}
			$factor = isset( $c['media']['factor'] ) ? max( 1, (int) $c['media']['factor'] ) : 10;
			return self::hit( $c, $bankey . '|media', $now, $ip ) > $factor * $limit ? array( 429, 'rate_media', $ip ) : null;
		}
		// 3.4.3: a crawler that cannot be verified here (Applebot, YandexBot: DNS, which the normal check does)
		// was not counted at all, so "Applebot" in the User-Agent read every cached page without limit. It now has
		// four times the page limit, never a violation: far above what the real crawler asks of one site.
		if ( $unverified ) {
			return self::hit( $c, $bankey . '|crawler', $now, $ip ) > 4 * $limit ? array( 429, 'rate_page', $ip ) : null;
		}
		// 3.4.3: a login cookie skipped this whole check before. Its name is public (a hash of the site address),
		// and a page cache that serves stored pages to logged-in users (WP Super Cache "cache for known users")
		// then served them without any limit. The check cannot verify the cookie, so it gets the blocks above
		// and four times the page limit, never a violation; staff get their own rules from the normal check.
		if ( self::login_cookie() ) {
			return self::hit( $c, $bankey . '|login', $now, $ip ) > 4 * $limit ? array( 429, 'rate_page', $ip ) : null;
		}
		// Prefetch: its own limit, three times the page limit, never a violation (as in the normal check).
		if ( self::is_prefetch() ) {
			return self::hit( $c, $bankey . '|prefetch', $now, $ip ) > 3 * $limit ? array( 429, 'rate_prefetch', $ip ) : null;
		}
		// IPv6: also the /56, at four times the limit, without a violation (as in the normal check).
		if ( ! empty( $c['v6_wide'] ) && false !== strpos( $ip, ':' ) && (int) $c['v6_prefix'] > 56 ) {
			$wide = self::limit_key( $ip, 56 );
			if ( false !== strpos( $wide, '/56' ) && self::hit( $c, $wide . '|56', $now, $ip ) > 4 * $limit ) {
				return array( 429, 'rate_page56', $ip );
			}
		}
		// 3.4.3: the human check's stricter limit for visitors without its cookie, as in the normal check.
		$human = isset( $c['human'] ) && is_array( $c['human'] ) ? (int) $c['human']['limit'] : 0;
		if ( $human > 0 && ! $allowed && ! self::human_ok( $c, $ip, $bankey ) ) {
			$unv = self::hit( $c, $bankey . '|unverified', $now, $ip );
			if ( $unv > $human ) {
				// 3.6.1: no violation for an IP that may be spoofed, or for a count shared by a network (as the normal check).
				// 3.12.9: crossed() instead of `$unv === $human + 1` (a file count may skip that value).
				if ( $reliable && ! self::$shared_hit && ! self::monitoring( $c, $now ) && self::crossed( $c, $bankey . '|unverified', $now, $unv, $human ) && self::strike( $c, $bankey, $now ) ) {
					self::ban( $c, $bankey, $now + max( 1, (int) $c['ban_minutes'] ) * 60 );
					self::event( $c, 403, 'ban', $ip );
				}
				return array( 429, 'rate_unverified', $ip );
			}
		}
		$count = self::hit( $c, $bankey, $now, $ip );
		if ( $count <= $limit ) {
			return null;
		}
		// One "violation" per minute over the limit, as in the normal check; enough of them = a ban. Not in
		// "Monitor only", which never bans. 3.6.1: never for an IP that may be spoofed (the normal check's
		// PNCP_Ip::reliable(): a CDN edge without the CDN secret, "trust every proxy"), as the probe ban already
		// did, and not for a count shared by a whole network (hit()).
		if ( $reliable && ! self::$shared_hit && ! self::monitoring( $c, $now ) && self::crossed( $c, $bankey, $now, $count, $limit ) && self::strike( $c, $bankey, $now ) ) {
			self::ban( $c, $bankey, $now + max( 1, (int) $c['ban_minutes'] ) * 60 );
			self::event( $c, 403, 'ban', $ip ); // The event keeps the exact IP for the log.
		}
		return array( 429, 'rate_page', $ip );
	}

	/**
	 * 3.5: is this request a scanner probe to refuse and ban here ("Ban scanners on their first probe")? Only the
	 * paths of the configuration (PNCP_Probe::RUNTIME_KEYS, never a WordPress page), only for a file that does
	 * not exist, and only when the exemptions of the normal check (PNCP_Bots::should_ban_on_sight()) can be
	 * decided here; anything in doubt goes on to WordPress, which decides with the full check.
	 *
	 * @param array<string, mixed> $c          Configuration.
	 * @param string               $ua         User-Agent (lowercase).
	 * @param string               $ip         IP.
	 * @param string               $bankey     The IP's key (IPv6: the /64).
	 * @param bool                 $reliable   Whether the IP can be trusted.
	 * @param bool                 $allowed    Whether the User-Agent is always allowed.
	 * @param bool                 $unverified Whether it claims to be a crawler this check cannot verify.
	 * @return bool
	 */
	public static function probe( $c, $ua, $ip, $bankey, $reliable, $allowed, $unverified ) {
		if ( ! $reliable || $allowed || $unverified || '' === $bankey || self::login_cookie() || self::is_prefetch() ) {
			return false;
		}
		$re = isset( $c['probe']['re'] ) ? (string) $c['probe']['re'] : '';
		if ( '' === $re ) {
			return false;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$full = '/' . ltrim( rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ), '/' );
		if ( false !== strpos( $full, "\0" ) || preg_match( '#(?:^|[/\\\\])\.\.(?:[/\\\\]|$)#', $full ) ) {
			return false; // Never a file look-up outside the site: WordPress decides.
		}
		$full = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $full );
		$path = $full;
		$home = (string) $c['home'];
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		$path = (string) preg_replace( '#^/index\.php(?=/)#i', '', $path );
		if ( 1 !== @preg_match( '#' . $re . '#i', $path ) ) {
			return false;
		}
		// Sec-Fetch, as the normal check: another site's <img>, a sub-resource or a human click never bans.
		$site = isset( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ? strtolower( trim( (string) $_SERVER['HTTP_SEC_FETCH_SITE'] ) ) : '';
		$dest = isset( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ? strtolower( trim( (string) $_SERVER['HTTP_SEC_FETCH_DEST'] ) ) : '';
		$user = isset( $_SERVER['HTTP_SEC_FETCH_USER'] ) ? trim( (string) $_SERVER['HTTP_SEC_FETCH_USER'] ) : '';
		if ( ( '' !== $site && ! in_array( $site, array( 'same-origin', 'none' ), true ) ) || ( '' !== $dest && 'document' !== $dest ) || '?1' === $user ) {
			return false;
		}
		if ( '' === $site && 0 === strpos( $ua, 'mozilla/' ) ) {
			return false; // A browser without Sec-Fetch: the normal check counts its probes (3rd within 10 minutes).
		}
		if ( isset( $c['probe']['skip_ua'] ) && '' !== $ua && self::ua_in( $ua, array_filter( array_map( 'strval', (array) $c['probe']['skip_ua'] ) ) ) ) {
			return false; // Search engines without verification (pncp_trap_exempt_agents).
		}
		foreach ( (array) $c['crawlers'] as $i => $crawler ) {
			if ( is_array( $crawler ) && isset( $crawler['ips'] ) && true === $crawler['ips'] ) {
				$set = self::crawler_set( $c, $i );
				if ( is_array( $set ) && isset( $set[1] ) && self::in_any( $ip, $set ) ) {
					return false; // An official crawler address (Google, Bing), whatever its User-Agent.
				}
			}
		}
		// Only a file that does not exist; without any place to look, WordPress decides.
		$candidates = array();
		$root       = isset( $_SERVER['DOCUMENT_ROOT'] ) ? (string) $_SERVER['DOCUMENT_ROOT'] : '';
		if ( '' !== $root ) {
			$candidates[] = rtrim( $root, '/\\' ) . $full;
		}
		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
		if ( '' !== $script && 'index.php' === basename( $script ) ) {
			$candidates[] = dirname( $script ) . $path;
		}
		if ( ! $candidates ) {
			return false;
		}
		foreach ( $candidates as $file ) {
			if ( @file_exists( $file ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 3.5: the 24-hour memory of the probe ban: true when this IP key already probed within 24 hours (then the
	 * full ban); otherwise the time of this probe is written and false is returned (the short first ban). Any
	 * failure is false, never an error. 3.12.9: in APCu or Redis when the check has either; the file is written
	 * whole (put_atomic()).
	 *
	 * @param array<string, mixed>|string $c   Configuration (or, as before 3.12.9, the data folder).
	 * @param string                      $key The IP's key (IPv6: the /64).
	 * @param int                         $now Time.
	 * @return bool
	 */
	public static function probe_seen( $c, $key, $now ) {
		if ( is_array( $c ) ) {
			$time = self::mem_get( $c, 'p:' . md5( $key ) );
			if ( null !== $time ) {
				if ( (int) $time > $now - 86400 ) {
					// 3.5: a probe within BURST seconds of the first one is part of the same first burst (parallel
					// requests that passed the ban check before the first ban was stored): the short ban too.
					return (int) $time <= $now - self::BURST;
				}
				if ( self::mem_set( $c, 'p:' . md5( $key ), (string) (int) $now, 86400 ) ) {
					return false;
				}
			}
			$c = (string) $c['dir'];
		}
		$folder = $c . '/probes';
		if ( ! is_dir( $folder ) ) {
			@mkdir( $folder, 0755, true );
		}
		$file = $folder . '/' . md5( $key );
		$time = is_file( $file ) ? (int) @file_get_contents( $file ) : 0;
		if ( $time > $now - 86400 ) {
			return $time <= $now - self::BURST;
		}
		self::put_atomic( $file, (string) (int) $now );
		return false;
	}

	/**
	 * Is "Monitor only" in effect (as PNCP_Options::monitoring())? The first-week monitoring of a new install
	 * ends at its time here too, even before WordPress rewrites the configuration.
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 * @return bool
	 */
	public static function monitoring( $c, $now ) {
		if ( self::emergency( $c, $now ) ) {
			return false; // 3.4: Emergency Mode really blocks, also while "Monitor only" is on (as in WordPress).
		}
		return ! empty( $c['monitor'] ) && ( empty( $c['monitor_until'] ) || $now < (int) $c['monitor_until'] );
	}

	/**
	 * Is Emergency Mode on (3.4: its end time is in the configuration)?
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 * @return bool
	 */
	public static function emergency( $c, $now ) {
		return ! empty( $c['emergency_until'] ) && $now < (int) $c['emergency_until'] && isset( $c['emergency'] ) && is_array( $c['emergency'] );
	}

	/**
	 * "Only through the CDN": a page request without the CDN's secret went straight to the server.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return string The address it came from, or '' when it may pass.
	 */
	public static function not_via_cdn( $c ) {
		if ( empty( $c['cdn_only'] ) || self::cdn_trust_ok( $c ) ) {
			return '';
		}
		$remote = self::normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '' );
		if ( '' === $remote ) {
			return '';
		}
		if ( ! self::is_local( $remote ) ) {
			// 3.12.1: the server's own address (PNCP_Server_Ips): its request reached it around the CDN.
			$ip = self::client_ip( $c, $reliable );
			return self::is_server_request( $c, $ip, $reliable ) ? '' : $remote;
		}
		// The server itself only when no proxy passed the request on: behind a local reverse proxy (Nginx in
		// front of Apache, Varnish) every request comes from 127.0.0.1, also the ones that went around the CDN.
		// Those are judged by the visitor's address, as PNCP_Origin::exempt() does.
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP' ) as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = self::client_ip( $c, $reliable );
				return '' !== $ip && ! self::is_local_request( $ip, $reliable ) ? $ip : '';
			}
		}
		return '';
	}

	/**
	 * The request method.
	 *
	 * @return string
	 */
	public static function method() {
		return isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) $_SERVER['REQUEST_METHOD'] ) : 'GET';
	}

	/**
	 * Is this a page request the check is for? Not: forms (anything but GET / HEAD, counted by the normal
	 * check), logged-in users, wp-admin, login, cron, REST, XML-RPC, AJAX and the trap; those go to the normal check anyway.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function applies( $c ) {
		$uri   = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$query = (string) parse_url( $uri, PHP_URL_QUERY );
		// Not doing_wp_cron: the cron loopback goes to wp-cron.php (excluded below), and on any other path it is a
		// page like the others (ALTERNATE_WP_CRON's redirect), counted by the normal check too. Left out, any
		// ?doing_wp_cron=1 added to a page skipped the bans and the page limit here.
		if ( '' !== $query && preg_match( '/(?:^|&)(?:rest_route|wc-ajax)=/i', $query ) ) {
			return false;
		}
		$path = '/' . ltrim( rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ), '/' );
		$home = (string) $c['home'];
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		// robots.txt, llms.txt and the TDM opt-out: every bot must be able to read them.
		if ( preg_match( '#^/(?:robots|llms|llms-full)\.txt$#i', $path ) || 0 === strcasecmp( $path, '/.well-known/tdmrep.json' ) ) {
			return false;
		}
		// 3.12.6: a verification file (path from the root of the host => until), while it is there.
		$raw = rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) );
		if ( ! empty( $c['open'] ) && is_array( $c['open'] ) && isset( $c['open'][ $raw ] ) && (int) $c['open'][ $raw ] > time() ) {
			return false;
		}
		return ! preg_match( '#^/(?:index\.php/)?(?:wp-admin|wp-login\.php|wp-cron\.php|xmlrpc\.php|wp-json|wp-signup\.php|wp-activate\.php|wp-trackback\.php|wp-comments-post\.php|cp-[0-9a-f]{10})(?:/|$)#i', $path );
	}

	/**
	 * Does this request count toward the page limit here? Every GET/HEAD view; a prefetch toward its own,
	 * larger limit (verdict()). The prefetch headers (Sec-Fetch-Dest, Sec-Purpose) can be sent by any script,
	 * so not counting them let a single IP scrape cached pages without limit (2.8.2 and earlier). A form
	 * (POST etc.) is never served from the cache: the normal check counts it. The always-blocked list and the temporary bans in verdict() run
	 * regardless of this.
	 *
	 * @return bool
	 */
	public static function countable() {
		return in_array( self::method(), array( 'GET', 'HEAD' ), true );
	}

	/**
	 * 3.4.1: a WooCommerce cart, checkout or My account page (or an endpoint below it, such as the order received
	 * page or My account > Orders)? These never count toward the page limit, as in the normal check: a shopper
	 * reloads them many times. The paths and page IDs come from the configuration (PNCP_Precheck::config()).
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function shop_page( $c ) {
		if ( empty( $c['shop'] ) || ! is_array( $c['shop'] ) ) {
			return false;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$ids  = isset( $c['shop']['ids'] ) ? array_map( 'intval', (array) $c['shop']['ids'] ) : array();
		$args = array();
		parse_str( (string) parse_url( $uri, PHP_URL_QUERY ), $args );
		if ( isset( $args['page_id'] ) && is_scalar( $args['page_id'] ) && in_array( (int) $args['page_id'], $ids, true ) ) {
			return true;
		}
		$path = '/' . ltrim( rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ), '/' );
		$home = (string) $c['home'];
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		$path = strtolower( (string) preg_replace( '#^/index\.php(?=/)#i', '', $path ) );
		foreach ( isset( $c['shop']['paths'] ) ? (array) $c['shop']['paths'] : array() as $shop ) {
			$shop = (string) $shop;
			if ( '' !== $shop && '/' !== $shop && ( rtrim( $path, '/' ) === $shop || 0 === strpos( $path, $shop . '/' ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Prefetch / prerender, as PNCP_Bots::is_prefetch() sees it.
	 *
	 * @return bool
	 */
	public static function is_prefetch() {
		if ( empty( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ) {
			return false;
		}
		foreach ( array( 'HTTP_SEC_PURPOSE', 'HTTP_PURPOSE', 'HTTP_X_MOZ', 'HTTP_X_PURPOSE' ) as $header ) {
			if ( isset( $_SERVER[ $header ] ) && ( false !== stripos( (string) $_SERVER[ $header ], 'prefetch' ) || ( 'HTTP_SEC_PURPOSE' === $header && false !== stripos( (string) $_SERVER[ $header ], 'prerender' ) ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The visitor's IP, as PNCP_Ip::client_ip() finds it: the selected header only from a trusted proxy.
	 *
	 * @param array<string, mixed> $c        Configuration.
	 * @param bool                 $reliable Set to false when the IP may be spoofed ("trust every proxy").
	 * @return string
	 */
	public static function client_ip( $c, &$reliable ) {
		$reliable            = true;
		$remote              = self::normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '' );
		$ip                  = $remote;
		$header              = (string) $c['header'];
		self::$hops          = array( $remote );
		self::$no_visitor_ip = false;
		if ( '' !== $header && empty( $_SERVER[ $header ] ) && self::trusted( $remote, $c ) && self::is_cdn( $remote, $c ) ) {
			self::$no_visitor_ip = true; // 3.6: a trusted CDN edge without the header (see PNCP_Ip::client_ip()).
		}
		if ( '' !== $header && ! empty( $_SERVER[ $header ] ) ) {
			$trusted = self::trusted( $remote, $c );
			$legacy  = ! empty( $c['trust_any'] ) && ! $trusted;
			if ( $trusted || $legacy ) {
				$chain = array_map( 'trim', explode( ',', (string) $_SERVER[ $header ] ) );
				$hops  = array( $remote ); // 3.4.3: the trusted proxies the address passed through.
				// 3.6.1: stop at a Cloudflare edge and take CF-Connecting-IP, as PNCP_Ip::client_ip() does.
				$cf_hop = ! $legacy && 'HTTP_X_FORWARDED_FOR' === $header && self::cf_hop( $remote, $c );
				$i      = count( $chain ) - 1;
				for ( ; ! $cf_hop && $i >= 0; $i-- ) {
					$candidate = self::normalize_ip( $chain[ $i ] );
					if ( '' === $candidate ) {
						break;
					}
					$ip = $candidate;
					if ( $legacy || 'HTTP_X_FORWARDED_FOR' !== $header || ! self::trusted( $ip, $c ) ) {
						break;
					}
					$hops[] = $ip;
					if ( self::cf_hop( $ip, $c ) ) {
						$cf_hop = true;
					}
				}
				if ( $cf_hop ) {
					$xff = $i >= 0 && isset( $chain[ $i ] ) ? self::normalize_ip( $chain[ $i ] ) : '';
					$cf  = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? self::normalize_ip( (string) $_SERVER['HTTP_CF_CONNECTING_IP'] ) : '';
					$own = ! empty( $c['cdn_secret_hash'] ) && self::cdn_trust_ok( $c );
					if ( ! $own && ( '' === $cf || $xff !== $cf ) ) {
						$reliable = false;
					}
					$ip = '' !== $cf ? $cf : ( '' !== $xff ? $xff : $ip );
				}
				if ( $legacy && $ip !== $remote ) {
					$reliable = false;
				}
				self::$hops = $hops;
				if ( ! $legacy && $ip === $remote && self::is_cdn( $remote, $c ) ) {
					self::$no_visitor_ip = true; // 3.6: the header held no IP.
				}
				// 3.4.3: a Bunny CDN edge without the CDN secret, as in PNCP_Ip::client_ip(): counted, but not trusted
				// for the always-allowed IPs. Also behind a local proxy (Nginx in front of PHP: REMOTE_ADDR is
				// 127.0.0.1 and the Bunny edge is a hop further in X-Forwarded-For), so every hop is looked at.
				if ( ! $legacy && $ip !== $remote && 3 === $c['format'] && empty( $c['cdn_secret_hash'] ) && ! empty( $c['proxies_cdn']['bunny'] ) ) {
					foreach ( $hops as $hop ) {
						if ( $hop !== $ip && self::in_any( $hop, $c['cdn_bunny'] ) && ! self::in_any( $hop, $c['proxies'] )
							&& ! ( ! empty( $c['private'] ) && ! filter_var( $hop, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) ) {
							$reliable = false;
						}
					}
				}
			}
		} elseif ( '' === $header && ! empty( $c['cf_auto'] ) && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::cf_edge( $remote, $c ) ) {
			// 3.4.1: "Real visitor IP" left at the default, but the request comes from a Cloudflare edge: Cloudflare
			// always writes CF-Connecting-IP itself, so it is the visitor (as in PNCP_Ip::client_ip()). Otherwise
			// every visitor, banned or not, would pass here as the shared edge address.
			$candidate = self::normalize_ip( (string) $_SERVER['HTTP_CF_CONNECTING_IP'] );
			if ( '' !== $candidate ) {
				$ip = $candidate;
			}
		}
		return $ip;
	}

	/**
	 * May this address set CF-Connecting-IP (PNCP_Ip::is_trusted_proxy() for that header)? An explicit trusted proxy,
	 * or a Cloudflare edge when the CDN secret, if one is set, is on the request.
	 *
	 * @param string               $ip IP.
	 * @param array<string, mixed> $c  Configuration.
	 * @return bool
	 */
	public static function cf_edge( $ip, $c ) {
		if ( '' === $ip || 3 !== $c['format'] ) {
			return false;
		}
		return self::in_any( $ip, $c['proxies'] ) || ( self::cdn_trust_ok( $c ) && self::in_any( $ip, $c['cdn_cf'] ) );
	}

	/**
	 * 3.6.1: a Cloudflare edge (not a private address), as PNCP_Ip::cloudflare_hop().
	 *
	 * @param string               $ip IP.
	 * @param array<string, mixed> $c  Configuration.
	 * @return bool
	 */
	public static function cf_hop( $ip, $c ) {
		return '' !== $ip && isset( $c['cdn_cf'] ) && is_array( $c['cdn_cf'] ) && self::in_any( $ip, $c['cdn_cf'] )
			&& false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * 3.6.1: does the request come from a reverse proxy that "Real visitor IP" does not trust (REMOTE_ADDR on the
	 * server or a private network, a forwarding header naming an outside client, and the visitor IP still
	 * REMOTE_ADDR)? As PNCP_Ip::untrusted_proxy_peer(): every visitor shares that address, so nothing is decided
	 * per IP. Call after client_ip().
	 *
	 * @param string $ip The visitor IP from client_ip().
	 * @return bool
	 */
	public static function untrusted_proxy_peer( $ip ) {
		$remote = self::normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '' );
		if ( '' === $remote || $ip !== $remote ) {
			return false;
		}
		if ( ! self::is_local( $remote ) && false !== filter_var( $remote, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;
		}
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP' ) as $header ) {
			if ( empty( $_SERVER[ $header ] ) ) {
				continue;
			}
			$value = (string) $_SERVER[ $header ];
			if ( 'HTTP_FORWARDED' === $header ) {
				$value = preg_match_all( '/for\s*=\s*"?([^";,\s]+)/i', $value, $found ) ? (string) end( $found[1] ) : '';
			} else {
				$parts = explode( ',', $value );
				$value = (string) end( $parts );
			}
			$client = self::normalize_ip( $value );
			if ( '' !== $client && ! self::is_local( $client ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The same spelling as PNCP_Ip::normalize() (no port or brackets, short IPv6, IPv4-mapped as IPv4), without
	 * WordPress, which is not loaded yet here.
	 *
	 * @param string $ip IP as received.
	 * @return string The IP, or ''.
	 */
	public static function normalize_ip( $ip ) {
		$ip = trim( (string) $ip );
		if ( '' === $ip ) {
			return '';
		}
		if ( '[' === $ip[0] ) {
			$end = strpos( $ip, ']' );
			$ip  = false === $end ? '' : substr( $ip, 1, $end - 1 );
		} elseif ( 1 === substr_count( $ip, ':' ) ) {
			$ip = substr( $ip, 0, (int) strpos( $ip, ':' ) );
		}
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $bin ) {
			return '';
		}
		if ( 16 === strlen( $bin ) && 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$bin = substr( $bin, 12 );
		}
		return (string) inet_ntop( $bin );
	}

	/**
	 * Is the address a proxy trusted for the selected header?
	 *
	 * @param string               $ip IP.
	 * @param array<string, mixed> $c  Configuration.
	 * @return bool
	 */
	public static function trusted( $ip, $c ) {
		if ( '' === $ip ) {
			return false;
		}
		if ( ! empty( $c['private'] ) && filter_var( $ip, FILTER_VALIDATE_IP ) && ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return true;
		}
		// With a CDN secret set but not present on the request, only the explicit "Trusted proxies" are
		// trusted, not the CDN edge lists (so a spoofed CDN edge IP cannot set the real-IP header).
		if ( 3 === $c['format'] ) {
			if ( self::in_any( $ip, $c['proxies'] ) ) {
				return true;
			}
			if ( ! self::cdn_trust_ok( $c ) ) {
				return false;
			}
			return ( ! empty( $c['proxies_cdn']['cf'] ) && self::in_any( $ip, $c['cdn_cf'] ) ) || ( ! empty( $c['proxies_cdn']['bunny'] ) && self::in_any( $ip, $c['cdn_bunny'] ) );
		}
		$set = self::cdn_trust_ok( $c ) ? $c['proxies'] : ( isset( $c['proxies_base'] ) ? $c['proxies_base'] : $c['proxies'] );
		return self::in_any( $ip, $set );
	}

	/**
	 * Is the address a CDN edge (Cloudflare, Bunny)?
	 *
	 * @param string               $ip IP.
	 * @param array<string, mixed> $c  Configuration.
	 * @return bool
	 */
	public static function is_cdn( $ip, $c ) {
		if ( 3 === $c['format'] ) {
			return self::in_any( $ip, $c['cdn_cf'] ) || self::in_any( $ip, $c['cdn_bunny'] );
		}
		return self::in_any( $ip, $c['cdn'] );
	}

	/**
	 * The official list of a crawler family, from crawlers.json: read only when a request claims to be a
	 * crawler (most requests do not), once per request.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @param int                  $i The family's position.
	 * @return array{0:array<string, bool>, 1:string[]}|null Null = no list: the normal check decides.
	 */
	public static function crawler_set( $c, $i ) {
		static $sets = null;
		if ( null === $sets ) {
			// 3.12.9: from APCu or Redis, where load() / PNCP_Precheck::push_config() put them with the configuration.
			$store = self::store( $c );
			if ( 'apcu' === $store ) {
				$sets = apcu_fetch( self::cfg_key( (string) $c['dir'] ) . '_crawlers' );
			} elseif ( 'redis' === $store ) {
				$json = (string) self::mem_get( $c, 'crawlers' );
				$sets = '' !== $json ? json_decode( $json, true ) : null;
			}
			if ( ! is_array( $sets ) ) {
				$sets = json_decode( (string) @file_get_contents( $c['dir'] . '/crawlers.json' ), true );
			}
			$sets = is_array( $sets ) ? $sets : array();
		}
		return isset( $sets[ $i ] ) && is_array( $sets[ $i ] ) ? $sets[ $i ] : null;
	}

	/**
	 * Is the CDN shared secret satisfied for this request? (true when none is configured).
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function cdn_trust_ok( $c ) {
		$hash = isset( $c['cdn_secret_hash'] ) ? (string) $c['cdn_secret_hash'] : '';
		if ( '' === $hash ) {
			return true;
		}
		$sent = isset( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] ) ? trim( (string) $_SERVER['HTTP_X_SCRAPELOCK_CDN'] ) : '';
		return '' !== $sent && hash_equals( $hash, hash( 'sha256', $sent ) );
	}

	/**
	 * The server itself (cron, cache preload, loopback)?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_local( $ip ) {
		return in_array( $ip, array( '127.0.0.1', '::1' ), true ) || ( isset( $_SERVER['SERVER_ADDR'] ) && (string) $_SERVER['SERVER_ADDR'] === $ip );
	}

	/**
	 * 3.6: the server itself, as in PNCP_Ip::is_local_request(): a local address that can be trusted and came
	 * only through addresses on the server or its private network (REMOTE_ADDR included). Call after client_ip().
	 *
	 * @param string $ip       The visitor IP from client_ip().
	 * @param bool   $reliable The reliability client_ip() gave.
	 * @return bool
	 */
	public static function is_local_request( $ip, $reliable ) {
		if ( '' === $ip || ! self::is_local( $ip ) ) {
			return false;
		}
		if ( ! $reliable ) {
			return false;
		}
		foreach ( self::$hops as $hop ) {
			if ( ! self::is_local( $hop ) && false !== filter_var( $hop, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 3.11: a static file, by the extension of the last part of the path (PNCP_Bots::is_static_request())?
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function is_media( $c ) {
		$ext = isset( $c['media']['ext'] ) ? (array) $c['media']['ext'] : array();
		if ( ! $ext ) {
			return false;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$path = strtolower( rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ) );
		$dot  = strrpos( $path, '.' );
		if ( false === $dot || false !== strpos( substr( $path, $dot ), '/' ) ) {
			return false;
		}
		return in_array( substr( $path, $dot + 1 ), array_map( 'strval', $ext ), true );
	}

	/**
	 * 3.11: a GET / HEAD of a file under /.well-known/ (relative to the home path), as PNCP_Bots::is_well_known_request()
	 * sees it: letters, digits, dots, hyphens, underscores and slashes only, no "..", no empty part.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function is_well_known( $c ) {
		if ( ! in_array( self::method(), array( 'GET', 'HEAD' ), true ) ) {
			return false;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$path = '/' . ltrim( rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ), '/' );
		$home = isset( $c['home'] ) ? (string) $c['home'] : '';
		if ( '' !== $home && 0 === stripos( $path, $home . '/' ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		$path = strtolower( $path );
		return 0 === strpos( $path, '/.well-known/' ) && false === strpos( $path, '..' ) && false === strpos( $path, '//' ) && ! preg_match( '#[^a-z0-9._/-]|/$|\.(?:php[0-9]?|phtml|phar)$#', $path );
	}

	/**
	 * 3.11: is the address on Google's or Apple's official list (crawlers.json, the positions in "official")?
	 *
	 * @param array<string, mixed> $c  Configuration.
	 * @param string               $ip IP.
	 * @return bool
	 */
	public static function official_ip( $c, $ip ) {
		foreach ( isset( $c['official'] ) ? (array) $c['official'] : array() as $i ) {
			$set = self::crawler_set( $c, (int) $i );
			if ( is_array( $set ) && isset( $set[1] ) && self::in_any( $ip, $set ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.12.1: does the request carry a valid signature of the site (header X-ScrapeLock-Sig, as
	 * PNCP_Server_Ips::sig_ok() checks it in WordPress)? The HMAC-SHA256 of method, host, path, time and nonce, with
	 * the key the line in wp-config.php passes to boot() ("self_key"; never in the data folder, which is in uploads).
	 * The time must be within its window, and the nonce new: it is kept as a file in the folder "self" (created
	 * with "x", so two requests with the same nonce cannot both pass). Anything missing or unreadable: not signed.
	 *
	 * 3.12.2: signed for one of the site's hosts ("self_sig" in the configuration), whatever Host header reached
	 * the server (a CDN that does not forward it sends its origin's name): the hint at the end of the header names
	 * the host and path it was made for (PNCP_Server_Ips::verify(), the same steps). The result and its reason are
	 * kept in $self_result for WordPress's diagnostics and the refusal header. The nonce file of this check is its
	 * own: WordPress keeps its nonces apart (PNCP_Log::cache_add()), so the request is not refused there as a replay.
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 * @return bool
	 */
	public static function self_signed( $c, $now ) {
		$sent = isset( $_SERVER['HTTP_X_SCRAPELOCK_SIG'] ) ? trim( (string) $_SERVER['HTTP_X_SCRAPELOCK_SIG'] ) : '';
		if ( '' === $sent ) {
			return false;
		}
		$method = self::method();
		$host   = isset( $_SERVER['HTTP_HOST'] ) ? (string) preg_replace( '/:\d+$/', '', strtolower( trim( (string) $_SERVER['HTTP_HOST'] ) ) ) : '';
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$path   = (string) preg_replace( '#/{2,}#', '/', rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ) );
		$path   = '' === $path ? '/' : $path;
		$memo   = $sent . '|' . $method . '|' . $host . '|' . $path;
		if ( isset( self::$self_seen[ $memo ] ) ) {
			return self::$self_seen[ $memo ];
		}
		self::$self_seen[ $memo ] = false;
		self::$self_result        = 'bad_format';
		if ( empty( $c['self_sig'] ) || ! is_array( $c['self_sig'] ) || ! preg_match( '/^(\d{9,11})\.([0-9a-f]{24})\.([0-9a-f]{64})(?:\.([0-9a-f]{8})([0-9a-f]{8}))?$/', $sent, $m ) ) {
			return false;
		}
		$hosts  = isset( $c['self_sig']['hosts'] ) ? array_values( array_filter( array_map( 'strval', (array) $c['self_sig']['hosts'] ) ) ) : array();
		$window = isset( $c['self_sig']['window'] ) ? max( 1, (int) $c['self_sig']['window'] ) : 60;
		$time   = (int) $m[1];
		$key    = isset( $c['self_key'] ) ? (string) $c['self_key'] : '';
		if ( ! preg_match( '/^[0-9a-f]{64}$/', $key ) ) {
			self::$self_result = 'no_key';
			return false;
		}
		if ( abs( $now - $time ) > $window ) {
			self::$self_result = 'expired';
			return false;
		}
		if ( isset( $m[4] ) && '' !== $m[4] ) {
			$found = array();
			foreach ( $hosts as $one ) {
				if ( substr( md5( 'h|' . $one ), 0, 8 ) === $m[4] ) {
					$found[] = $one;
				}
			}
			if ( ! $found ) {
				self::$self_result = 'host_mismatch';
				return false;
			}
			if ( substr( md5( 'p|' . $path ), 0, 8 ) !== $m[5] ) {
				self::$self_result = 'path_mismatch';
				return false;
			}
			$hosts = $found;
		}
		$valid = false;
		foreach ( $hosts as $one ) {
			foreach ( 'GET' === $method ? array( 'GET', 'HEAD' ) : array( $method ) as $verb ) {
				$valid = $valid || hash_equals( hash_hmac( 'sha256', 'pncp-sig|v1|' . $verb . '|' . $one . '|' . $path . '|' . $time . '|' . $m[2], $key ), $m[3] );
			}
		}
		if ( ! $valid ) {
			self::$self_result = 'bad_mac';
			return false;
		}
		// Used once: the nonce's file is created only if it is not there yet. 3.12.9: in APCu or Redis when the check
		// has either (kept as long as the file, see cleanup()).
		$added = self::mem_add( $c, 'n:' . $m[2], (string) $now, 300 );
		if ( null === $added ) {
			$folder = (string) $c['dir'] . '/self';
			if ( ! is_dir( $folder ) ) {
				@mkdir( $folder, 0755, true );
			}
			$handle = @fopen( $folder . '/' . $m[2], 'x' );
			$added  = false !== $handle;
			if ( false !== $handle ) {
				fwrite( $handle, (string) $now );
				fclose( $handle );
			}
		}
		if ( ! $added ) {
			self::$self_result = 'nonce_reused';
			return false;
		}
		self::$self_result        = 'ok';
		self::$self_nonce         = $m[2];
		self::$self_seen[ $memo ] = true;
		return true;
	}

	/**
	 * 3.11: the server's public address (SERVER_ADDR, or one of the configuration's "self_ips", PNCP_Server_Ips),
	 * as the visitor IP the trusted proxy or CDN gave: the site's request to itself came back through the CDN.
	 * Loopback and private addresses only through is_local_request(); never a CDN edge; never when the IP may be
	 * spoofed.
	 *
	 * @param array<string, mixed> $c        Configuration.
	 * @param string               $ip       The visitor IP from client_ip().
	 * @param bool                 $reliable The reliability client_ip() gave.
	 * @return bool
	 */
	public static function is_server_request( $c, $ip, $reliable ) {
		if ( ! $reliable || '' === $ip ) {
			return false;
		}
		// 3.12.1: a private address of SCRAPELOCK_SERVER_IPS ("self_const"), as PNCP_Server_Ips::is_request(): only
		// when every hop was on the server's network and it is not a proxy passing visitors on.
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			if ( empty( $c['self_const'] ) || ! is_array( $c['self_const'] ) || ! isset( $c['self_const'][1] ) || ! self::in_any( $ip, $c['self_const'] ) || self::untrusted_proxy_peer( $ip ) ) {
				return false;
			}
			foreach ( self::$hops as $hop ) {
				if ( ! self::is_local( $hop ) && false !== filter_var( $hop, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
					return false;
				}
			}
			return true;
		}
		if ( self::is_cdn( $ip, $c ) ) {
			return false;
		}
		if ( isset( $_SERVER['SERVER_ADDR'] ) && self::normalize_ip( (string) $_SERVER['SERVER_ADDR'] ) === $ip ) {
			return true;
		}
		return isset( $c['self_ips'] ) && is_array( $c['self_ips'] ) && isset( $c['self_ips'][1] ) && self::in_any( $ip, $c['self_ips'] );
	}

	/**
	 * Does the IP belong to a set? A set is [ exact addresses (address => true), CIDRs ].
	 *
	 * @param string                                  $ip  IP.
	 * @param array{0:array<string, bool>, 1:string[]} $set Set.
	 * @return bool
	 */
	public static function in_any( $ip, $set ) {
		$packed = @inet_pton( $ip );
		if ( false === $packed ) {
			return false;
		}
		if ( isset( $set[0][ (string) inet_ntop( $packed ) ] ) ) {
			return true;
		}
		foreach ( $set[1] as $range ) {
			list( $subnet, $bits ) = explode( '/', $range, 2 );
			$net                   = @inet_pton( $subnet );
			if ( false === $net || strlen( $net ) !== strlen( $packed ) ) {
				continue;
			}
			$bits  = (int) $bits;
			$bytes = intdiv( $bits, 8 );
			if ( substr( $packed, 0, $bytes ) !== substr( $net, 0, $bytes ) ) {
				continue;
			}
			$rest = $bits % 8;
			if ( 0 === $rest ) {
				return true;
			}
			$mask = 0xFF << ( 8 - $rest ) & 0xFF;
			if ( ( ord( $packed[ $bytes ] ) & $mask ) === ( ord( $net[ $bytes ] ) & $mask ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.4.3: does the request carry a WordPress login cookie (any; the check cannot verify it)?
	 *
	 * @return bool
	 */
	public static function login_cookie() {
		foreach ( array_keys( $_COOKIE ) as $name ) {
			if ( 0 === strpos( (string) $name, 'wordpress_logged_in_' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.4.3: is the (lowercase) User-Agent in the list? "=name" = the whole User-Agent, as
	 * PNCP_Bots::ua_in_list().
	 *
	 * @param string   $ua      User-Agent (lowercase).
	 * @param string[] $needles Lowercase needles.
	 * @return bool
	 */
	public static function ua_listed( $ua, $needles ) {
		foreach ( $needles as $needle ) {
			$needle = (string) $needle;
			if ( '' === $needle || '=' === $needle ) {
				continue;
			}
			if ( '=' === $needle[0] ? trim( $ua ) === substr( $needle, 1 ) : false !== strpos( $ua, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.4.3: does the User-Agent match an "always allowed" entry (one pinned to IPs only from them, and only
	 * when the IP is reliable), as PNCP_Bots::allow_list_match()?
	 *
	 * @param array<string, mixed> $c        Configuration.
	 * @param string               $ua       User-Agent (lowercase).
	 * @param string               $ip       IP.
	 * @param bool                 $reliable Whether the IP can be trusted.
	 * @return bool
	 */
	public static function ua_allowed( $c, $ua, $ip, $reliable ) {
		if ( '' === $ua || empty( $c['allow_ua'] ) || ! is_array( $c['allow_ua'] ) ) {
			return false;
		}
		foreach ( $c['allow_ua'] as $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry[0] ) || '' === (string) $entry[0] || '=' === (string) $entry[0] ) {
				continue;
			}
			// 3.12.2: "=name" = the whole User-Agent, as PNCP_Bots::allow_list_match() (it matched nothing before).
			$needle = (string) $entry[0];
			if ( '=' === $needle[0] ? trim( $ua ) !== trim( substr( $needle, 1 ) ) : false === strpos( $ua, $needle ) ) {
				continue;
			}
			if ( ! isset( $entry[1] ) || ( $reliable && is_array( $entry[1] ) && self::in_any( $ip, $entry[1] ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.4.3: does the visitor have a valid human check cookie for cached pages (PNCP_Human::pc_value())?
	 *
	 * @param array<string, mixed> $c      Configuration.
	 * @param string               $ip     IP.
	 * @param string               $bankey The IP's key (IPv6: the /64).
	 * @return bool
	 */
	public static function human_ok( $c, $ip, $bankey ) {
		$name = isset( $c['human']['cookie'] ) ? (string) $c['human']['cookie'] : '';
		$key  = isset( $c['human']['key'] ) ? (string) $c['human']['key'] : '';
		if ( '' === $name || strlen( $key ) < 32 || empty( $_COOKIE[ $name ] ) || ! is_string( $_COOKIE[ $name ] ) ) {
			return false;
		}
		$parts = explode( '.', (string) $_COOKIE[ $name ] );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) || (int) $parts[0] < time() ) {
			return false;
		}
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		return hash_equals( hash_hmac( 'sha256', $parts[0] . '|' . $bankey . '|' . md5( $ua ), $key ), $parts[1] );
	}

	/**
	 * Does the (lowercase) User-Agent contain one of the (lowercase) needles?
	 *
	 * @param string   $ua      User-Agent.
	 * @param string[] $needles Needles.
	 * @return bool
	 */
	public static function ua_in( $ua, $needles ) {
		foreach ( $needles as $needle ) {
			if ( false !== strpos( $ua, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The key an IP is counted under, as PNCP_Ip::limit_key(): IPv6 per network (/64 by default).
	 *
	 * @param string $ip     IP.
	 * @param int    $prefix IPv6 prefix.
	 * @return string
	 */
	public static function limit_key( $ip, $prefix ) {
		$bin = @inet_pton( $ip );
		if ( false === $bin || 16 !== strlen( $bin ) ) {
			return $ip;
		}
		if ( 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			return (string) inet_ntop( substr( $bin, 12 ) );
		}
		$prefix = max( 48, min( 128, $prefix ) );
		if ( 128 === $prefix ) {
			return (string) inet_ntop( $bin );
		}
		$bytes = intdiv( $prefix, 8 );
		$net   = substr( $bin, 0, $bytes );
		if ( $prefix % 8 ) {
			$net .= chr( ord( $bin[ $bytes ] ) & ( 0xFF << ( 8 - $prefix % 8 ) & 0xFF ) );
		}
		return inet_ntop( str_pad( $net, 16, "\0" ) ) . '/' . $prefix;
	}

	/**
	 * Counts a page for the key in the current minute and returns the count.
	 *
	 * 3.6.1: without APCu a new key needs a new file, and new files are capped per minute (new_file_ok()). Past
	 * the cap an address not seen yet that minute was not counted at all, so a burst of new addresses at the
	 * start of each minute (cheap with IPv6) switched the page limit off for everyone. Now one network (IPv4 /24,
	 * IPv6 /48) takes at most NET_FILES new files a minute, and its further new addresses, like every new address
	 * once the cap is used up, are counted together under one file of their network, held to NET_FACTOR times
	 * the limit (no violation: see $shared_hit). As PNCP_Bots::db_incr_capped().
	 *
	 * 3.12.9: APCu first (unchanged), then Redis (store()), and the files only without either. The files no longer
	 * clean up the old minutes here (cleanup() runs from WP-Cron or WP-CLI; maybe_sweep() only without them).
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param string               $key Key.
	 * @param int                  $now Time.
	 * @param string               $ip  3.6.1: the visitor IP ('' = no network fallback).
	 * @return int
	 */
	public static function hit( $c, $key, $now, $ip = '' ) {
		self::$shared_hit = false;
		self::$exact      = true;
		if ( self::$count_off ) {
			return 1; // 3.12.9: suspended by the circuit breaker (breaker()).
		}
		$minute = (int) floor( $now / 60 );
		if ( self::apcu_usable( $c ) ) {
			$name = 'pncp_pc_' . md5( $c['dir'] . '|' . $key . '|' . $minute );
			apcu_add( $name, 0, 120 );
			$count = apcu_inc( $name );
			if ( false !== $count ) {
				return (int) $count;
			}
		} elseif ( 'redis' === self::store( $c ) ) {
			$count = self::mem_incr( $c, 'h:' . md5( $key ) . ':' . $minute, 120 );
			if ( false !== $count ) {
				return $count;
			}
		}
		self::$exact = false; // A file count may skip a value under contention (increment()): see crossed().
		$dir         = $c['dir'] . '/hits/' . $minute;
		if ( ! is_dir( $dir ) && @mkdir( $dir, 0755, true ) ) {
			self::maybe_sweep( $c, $now );
		}
		$file = $dir . '/' . md5( $key );
		if ( is_file( $file ) ) {
			return self::increment( $file );
		}
		$net = '' !== $ip && ( ! isset( $c['new_files'] ) || (int) $c['new_files'] > 0 ) ? self::network_key( $ip ) : '';
		if ( '' === $net ) {
			return self::new_file_ok( $c, $now ) ? self::increment( $file ) : 1;
		}
		// The network's share of new files this minute (its own small file counts as one of them).
		$share_file = $dir . '/.net-' . md5( $net );
		$share      = is_file( $share_file ) || self::new_file_ok( $c, $now ) ? self::increment( $share_file ) : PHP_INT_MAX;
		$per_net    = isset( $c['net_files'] ) ? max( 1, (int) $c['net_files'] ) : self::NET_FILES;
		if ( $share <= $per_net && self::new_file_ok( $c, $now ) ) {
			return self::increment( $file );
		}
		// Counted with the other new addresses of its network (per kind of count: the key's "|..." part).
		$suffix = strstr( $key, '|' );
		$shared = $dir . '/' . md5( 'net|' . $net . ( false === $suffix ? '' : $suffix ) );
		if ( ! is_file( $shared ) && ! self::new_file_ok( $c, $now, 2 ) ) {
			return 1; // Too many networks at once: as before 3.6.1, counted as the first page, nothing written.
		}
		$count = self::increment( $shared );
		if ( $count < 1 ) {
			return 1;
		}
		self::$shared_hit = true;
		return (int) ceil( $count / self::NET_FACTOR );
	}

	/**
	 * 3.12.9: is this the request that took the key's count over the limit this minute (one violation per key and
	 * minute, as `$count === $limit + 1` before)? APCu and Redis give every request its own number, so that test
	 * stays. A count from the files (increment()) can give two requests the same number under contention, or skip
	 * one: there the first request over the limit creates a marker next to the counter (fopen 'x', which only one
	 * process can do) and only that one counts the violation.
	 *
	 * @param array<string, mixed> $c     Configuration.
	 * @param string               $key   The key given to hit().
	 * @param int                  $now   Time.
	 * @param int                  $count What hit() returned.
	 * @param int                  $limit The limit.
	 * @return bool
	 */
	public static function crossed( $c, $key, $now, $count, $limit ) {
		if ( self::$exact ) {
			return $count === $limit + 1;
		}
		if ( $count <= $limit ) {
			return false;
		}
		$handle = @fopen( $c['dir'] . '/hits/' . (int) floor( $now / 60 ) . '/' . md5( $key ) . '.over', 'x' );
		if ( false === $handle ) {
			return false;
		}
		fclose( $handle );
		return true;
	}
	/**
	 * 3.6.1: the network of an address (IPv4 /24, IPv6 /48), as PNCP_Ip::network_key().
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function network_key( $ip ) {
		$bin = @inet_pton( (string) $ip );
		if ( false === $bin ) {
			return '';
		}
		if ( 16 === strlen( $bin ) && 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$bin = substr( $bin, 12 );
		}
		if ( 4 === strlen( $bin ) ) {
			return inet_ntop( substr( $bin, 0, 3 ) . "\0" ) . '/24';
		}
		return inet_ntop( substr( $bin, 0, 6 ) . str_repeat( "\0", 10 ) ) . '/48';
	}

	/**
	 * 3.6.1: may the page counters use APCu? Only where APCu is shared by every PHP process of the site (PHP-FPM,
	 * Apache mod_php), as PNCP_Log::apcu_ok(): under CGI or LiteSpeed LSAPI each process may have its own, and a
	 * scraper spread over N processes got N times the page limit. The SAPIs come from the configuration
	 * (filter `pncp_precheck_apcu_sapis`).
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function apcu_usable( $c ) {
		if ( empty( $c['apcu'] ) || ! function_exists( 'apcu_enabled' ) || ! apcu_enabled() ) {
			return false;
		}
		$sapis = isset( $c['apcu_sapis'] ) && is_array( $c['apcu_sapis'] ) ? $c['apcu_sapis'] : array( 'fpm-fcgi', 'apache2handler' );
		return in_array( PHP_SAPI, $sapis, true );
	}

	/**
	 * 3.6: may one more new file be created this minute? Without a cap, an attack that changes address on every
	 * request (an IPv6 /48 holds 65,536 /64 keys) created a counter file per address, millions an hour, enough to
	 * use up the inodes or the disk quota of a shared host. The count is kept in the minute's hits folder, so it
	 * is removed with it. A failure to count allows the file, as before.
	 *
	 * @param array<string, mixed> $c     Configuration.
	 * @param int                  $now   Time.
	 * @param int                  $times 3.6.1: allow up to this many times the cap (2: the shared network
	 *                                    counters' own allowance once the cap is used up, see hit()).
	 * @return bool
	 */
	public static function new_file_ok( $c, $now, $times = 1 ) {
		if ( self::$count_off ) {
			return false; // 3.12.9: suspended by the circuit breaker (breaker()).
		}
		$cap = isset( $c['new_files'] ) ? (int) $c['new_files'] : self::NEW_FILES;
		if ( $cap <= 0 ) {
			return true;
		}
		$dir = $c['dir'] . '/hits/' . (int) floor( $now / 60 );
		if ( ! is_dir( $dir ) ) {
			@mkdir( $dir, 0755, true );
		}
		$count = self::increment( $dir . '/.new' );
		return 0 === $count || $count <= $cap * max( 1, (int) $times );
	}

	/**
	 * Adds 1 to a counter file and returns the new value (0 if the file cannot be written: the request then passes).
	 *
	 * 3.12.9: one byte appended (O_APPEND), the count is the file's size. Before, the file was locked (flock()
	 * without LOCK_NB), read, truncated and written again: a visitor waited for every other request on the same
	 * counter, and on ext4 a file truncated to 0 and written again is flushed to the disk when it is closed
	 * (auto_da_alloc), so ftruncate() and fclose() waited for the disk on every page (the live slow logs: ftruncate()
	 * and fclose() of this function at the top of requests that took more than 30 s while the disk stalled).
	 * Rewriting through a temporary file and rename() has the same flush on ext4. An append needs no lock, no
	 * truncation and no rename: the kernel appends each write() under the inode's lock, so no count is lost and
	 * the file is never empty or half written. The value returned is the size after this request's byte: under
	 * contention two requests may read the same size (both bytes written, then both fstat()), so a value can repeat
	 * or be skipped, never lost from the total; crossed() makes the violation exact anyway. On NFS, appends are
	 * not atomic between machines: a count can be lost there (the limits are approximate anyway). Past MAX_COUNT
	 * bytes (an attack of more than 100,000 requests a minute on one key) nothing more is written.
	 *
	 * @param string $file File.
	 * @return int
	 */
	public static function increment( $file ) {
		$size = @filesize( $file );
		if ( false !== $size && $size >= self::MAX_COUNT ) {
			return (int) $size + 1;
		}
		$handle = @fopen( $file, 'ab' );
		if ( false === $handle ) {
			return 0;
		}
		$written = fwrite( $handle, '1' );
		$stat    = fstat( $handle );
		fclose( $handle );
		return 1 === $written && is_array( $stat ) ? max( 1, (int) $stat['size'] ) : 0;
	}

	/**
	 * Removes the counters of past minutes. 3.12.9: only from the hourly cleanup (PNCP_Precheck::cleanup_hits(),
	 * WP-Cron, `wp scrapelock precheck cleanup`): no longer by the first request of each minute, which read and
	 * deleted up to 300 files of an old minute (scandir(), unlink()) in a visitor's request (the live slow logs:
	 * scandir() and unlink() of this function). Without WP-Cron, maybe_sweep() does a little of it at the end of
	 * one request a minute, within a time budget.
	 *
	 * @param string $base   The hits folder.
	 * @param int    $minute Current minute.
	 * @param int    $max    Most files removed in this call (0 = no limit, and the other folders too).
	 */
	public static function cleanup( $base, $minute, $max = 300 ) {
		$left = (int) $max > 0 ? (int) $max : PHP_INT_MAX;
		foreach ( (array) @scandir( $base ) as $name ) {
			if ( ctype_digit( (string) $name ) && (int) $name < $minute - 1 ) {
				foreach ( (array) @scandir( $base . '/' . $name ) as $file ) {
					if ( '.' !== $file && '..' !== $file ) {
						if ( $left-- <= 0 ) {
							return;
						}
						@unlink( $base . '/' . $name . '/' . $file );
					}
				}
				@rmdir( $base . '/' . $name );
			}
		}
		// 3.4.3: the hourly cleanup (no limit) also removes the strikes older than their 10-minute window and the
		// expired bans. Nothing else did: one file of each stayed behind for every IP that ever hit the limit.
		if ( (int) $max <= 0 ) {
			$now  = (int) $minute * 60;
			$data = dirname( $base );
			// 3.12.1: the nonces of the site's signed requests (self_signed()), kept twice the signature's window.
			// 3.5: the probe ban's 24-hour memory.
			foreach ( array(
				'strikes' => 600,
				'self'    => 300,
				'probes'  => 86400,
				'bans'    => 60,
			) as $folder => $age ) {
				foreach ( (array) @scandir( $data . '/' . $folder ) as $file ) {
					$path = $data . '/' . $folder . '/' . $file;
					if ( '.' === $file || '..' === $file || ! is_file( $path ) || (int) @filemtime( $path ) >= $now - $age ) {
						continue;
					}
					// A ban only once it has expired (and not one written in the last minute: a new ban may have just
					// replaced an expired one). 3.12.9: a temporary file left by put_atomic() goes after a minute.
					if ( 'bans' !== $folder || '.tmp' === substr( $file, -4 ) || (int) @file_get_contents( $path ) <= $now ) {
						@unlink( $path );
					}
				}
			}
			@touch( $data . '/.cleaned' ); // 3.12.9: for maybe_sweep().
		}
	}

	/**
	 * 3.12.9: without the hourly cleanup (DISABLE_WP_CRON without a real cron job), the old minutes would pile up in
	 * the hits folder. Then, once a minute (called by the request that creates the minute's folder), sweep() runs at
	 * the end of that request: never while the hourly cleanup has run within 2 hours, and never with APCu or Redis
	 * (they keep no files).
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 * @return bool Whether a sweep was scheduled.
	 */
	public static function maybe_sweep( $c, $now ) {
		$cleaned = @filemtime( $c['dir'] . '/.cleaned' );
		if ( false !== $cleaned && $cleaned > $now - 7200 ) {
			return false;
		}
		register_shutdown_function( array( __CLASS__, 'sweep' ), (string) $c['dir'], (int) floor( $now / 60 ), self::SWEEP_MS );
		return true;
	}

	/**
	 * 3.12.9: removes the counters of past minutes, and strikes and nonces past their time, for at most $budget
	 * milliseconds (hrtime()), one entry at a time (readdir(), never a whole listing), and only in the one request
	 * that gets the lock of .sweep.lock (LOCK_NB: the others never wait for it).
	 *
	 * @param string $dir    Data folder.
	 * @param int    $minute Current minute.
	 * @param int    $budget Milliseconds.
	 * @return int Files removed.
	 */
	public static function sweep( $dir, $minute, $budget = self::SWEEP_MS ) {
		$lock = @fopen( $dir . '/.sweep.lock', 'c' );
		if ( false === $lock ) {
			return 0;
		}
		if ( ! flock( $lock, LOCK_EX | LOCK_NB ) ) {
			fclose( $lock );
			return 0;
		}
		$end     = hrtime( true ) + max( 1, (int) $budget ) * 1000000;
		$removed = 0;
		$base    = $dir . '/hits';
		$top     = @opendir( $base );
		if ( false !== $top ) {
			$name = readdir( $top );
			while ( false !== $name && hrtime( true ) < $end ) {
				if ( ctype_digit( (string) $name ) && (int) $name < $minute - 1 ) {
					$removed += self::sweep_folder( $base . '/' . $name, $end, 0, true );
				}
				$name = readdir( $top );
			}
			closedir( $top );
		}
		foreach ( array(
			'strikes' => 600,
			'self'    => 300,
		) as $folder => $age ) {
			if ( hrtime( true ) < $end ) {
				$removed += self::sweep_folder( $dir . '/' . $folder, $end, $minute * 60 - $age, false );
			}
		}
		flock( $lock, LOCK_UN );
		fclose( $lock );
		return $removed;
	}

	/**
	 * 3.12.9: removes the files of a folder (older than $before when it is not 0) until hrtime() reaches $end; the
	 * folder too when it is emptied and $rmdir.
	 *
	 * @param string $folder Folder.
	 * @param int    $end    hrtime() limit.
	 * @param int    $before Only files last changed before this time (0 = all).
	 * @param bool   $rmdir  Remove the emptied folder.
	 * @return int Files removed.
	 */
	private static function sweep_folder( $folder, $end, $before, $rmdir ) {
		$handle = @opendir( $folder );
		if ( false === $handle ) {
			return 0;
		}
		$removed = 0;
		$done    = true;
		$file    = readdir( $handle );
		while ( false !== $file ) {
			if ( hrtime( true ) >= $end ) {
				$done = false;
				break;
			}
			if ( '.' !== $file && '..' !== $file ) {
				$path = $folder . '/' . $file;
				if ( ( 0 === $before || (int) @filemtime( $path ) < $before ) && @unlink( $path ) ) {
					++$removed;
				}
			}
			$file = readdir( $handle );
		}
		closedir( $handle );
		if ( $done && $rmdir ) {
			@rmdir( $folder );
		}
		return $removed;
	}

	/**
	 * Records a violation; true when they reach the configured number within 10 minutes.
	 *
	 * 3.12.9: in APCu or Redis (a counter that lives 10 minutes from the first violation, as the file's window).
	 * The file is read, then replaced whole (put_atomic()), without a lock: a reader never sees half of it, and
	 * two violations of one key in the same instant (which crossed() makes very unlikely: one per key and minute)
	 * may count as one.
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param string               $key Key.
	 * @param int                  $now Time.
	 * @return bool
	 */
	public static function strike( $c, $key, $now ) {
		$needed = (int) $c['ban_strikes'];
		if ( $needed < 1 || self::$count_off ) {
			return false;
		}
		if ( '' !== self::store( $c ) ) {
			$count = self::mem_incr( $c, 's:' . md5( $key ), 600 );
			if ( false !== $count ) {
				if ( $count >= $needed ) {
					self::mem_del( $c, 's:' . md5( $key ) );
					return true;
				}
				return false;
			}
		}
		$dir = $c['dir'] . '/strikes';
		if ( ! is_dir( $dir ) ) {
			@mkdir( $dir, 0755, true );
		}
		$file  = $dir . '/' . md5( $key );
		$parts = explode( '|', is_file( $file ) ? (string) @file_get_contents( $file ) : '' );
		$first = isset( $parts[1] ) ? (int) $parts[0] : 0;
		$count = isset( $parts[1] ) ? (int) $parts[1] : 0;
		if ( $now - $first > 600 ) {
			$first = $now;
			$count = 0;
		}
		++$count;
		$banned = $count >= $needed;
		self::put_atomic( $file, $banned ? '' : $first . '|' . $count );
		return $banned;
	}

	/**
	 * Is the IP banned? (A file per IP with the expiry; written here and by the normal check.) 3.12.9: in APCu or
	 * Redis when the check has either: then no file is read (PNCP_Precheck::cleanup_hits() copies the bans between
	 * the two every hour, and sync_later() copies the files' bans in once after Redis or APCu lost its data).
	 *
	 * @param array<string, mixed>|string $c   Configuration (or, as before 3.12.9, the data folder).
	 * @param string                      $ip  IP.
	 * @param int                         $now Time.
	 * @return bool
	 */
	public static function banned( $c, $ip, $now ) {
		if ( is_array( $c ) ) {
			$values = self::mem_get_many( $c, array( 'b:' . md5( $ip ), 'sync' ) );
			if ( null !== $values ) {
				if ( '' === $values[1] ) {
					self::sync_later( $c );
				}
				return (int) $values[0] > $now;
			}
			$c = (string) $c['dir'];
		}
		$file = $c . '/bans/' . md5( $ip );
		if ( ! is_file( $file ) ) {
			return false;
		}
		return (int) @file_get_contents( $file ) > $now;
	}

	/**
	 * Bans an IP until a time. 3.12.9: in APCu or Redis when the check has either, otherwise the file, written
	 * whole through a temporary file (put_atomic()): a request reading it never sees it empty.
	 *
	 * @param array<string, mixed>|string $c     Configuration (or, as before 3.12.9, the data folder).
	 * @param string                      $ip    IP.
	 * @param int                         $until Expiry.
	 */
	public static function ban( $c, $ip, $until ) {
		if ( is_array( $c ) ) {
			if ( self::mem_set( $c, 'b:' . md5( $ip ), (string) (int) $until, max( 60, (int) $until - time() + 60 ) ) ) {
				return;
			}
			$c = (string) $c['dir'];
		}
		if ( ! is_dir( $c . '/bans' ) ) {
			@mkdir( $c . '/bans', 0755, true );
		}
		self::put_atomic( $c . '/bans/' . md5( $ip ), (string) (int) $until );
	}

	/**
	 * 3.12.9: writes a small file whole: into a temporary file in the same folder, then rename() over it (atomic on
	 * a local file system), so a reader gets the old or the new contents, never an empty or half-written file.
	 *
	 * @param string $file     File.
	 * @param string $contents Contents.
	 * @return bool
	 */
	public static function put_atomic( $file, $contents ) {
		$tmp = dirname( $file ) . '/.' . basename( $file ) . '.' . substr( md5( uniqid( (string) mt_rand(), true ) ), 0, 10 ) . '.tmp';
		if ( strlen( $contents ) !== @file_put_contents( $tmp, $contents ) || ! @rename( $tmp, $file ) ) {
			@unlink( $tmp );
			return false;
		}
		return true;
	}

	/**
	 * Appends an event for the plugin's log (imported into the database by WordPress later): one line of
	 * tab-separated text in events.log. Capped at 2 MB. 3.12.9: in APCu or Redis when the check has either (the
	 * hourly import drains them, PNCP_Precheck::import_events()); the file without LOCK_EX: one write() of a line
	 * to a file opened for appending is not mixed with another's.
	 *
	 * @param array<string, mixed> $c      Configuration.
	 * @param int                  $code   HTTP status code.
	 * @param string               $reason Reason.
	 * @param string               $ip     IP.
	 */
	public static function event( $c, $code, $reason, $ip ) {
		$clean = static function ( $value, $max ) {
			return substr( (string) preg_replace( '/[\x00-\x1F\x7F<>]+/', ' ', (string) $value ), 0, $max );
		};
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) parse_url( (string) $_SERVER['REQUEST_URI'], PHP_URL_PATH ) : '';
		$ua   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		$line = implode( "\t", array( time(), (int) $code, $clean( $reason, 20 ), $clean( $ip, 45 ), $clean( $uri, 255 ), $clean( $ua, 255 ) ) );
		if ( self::mem_push( $c, $line ) ) {
			return;
		}
		$file = $c['dir'] . '/events.log';
		// Silenced: WordPress may move the file away for its import (PNCP_Precheck) between the two calls.
		if ( is_file( $file ) && @filesize( $file ) > 2 * 1024 * 1024 ) {
			return;
		}
		@file_put_contents( $file, $line . "\n", FILE_APPEND );
	}

	/* ---------- 3.12.9: APCu and Redis ---------- */

	/**
	 * 3.12.9: the answer to the site's own signed request of PNCP_Precheck::push_web(): reads config.json and
	 * crawlers.json into APCu (or Redis), applies the ban changes WP-CLI queued in ops.log (apply_ops()), answers
	 * JSON and ends the request. Only after self_signed() accepted the request.
	 *
	 * @param array<string, mixed> $c Configuration.
	 */
	public static function serve_sync( $c ) {
		$base = array(
			'dir'   => (string) $c['dir'],
			'redis' => isset( $c['redis'] ) && is_array( $c['redis'] ) ? $c['redis'] : array(),
		);
		$json = (string) @file_get_contents( $base['dir'] . '/config.json' );
		$new  = json_decode( $json, true );
		$out  = array(
			'sapi'   => PHP_SAPI,
			'config' => self::cfg_ok( $new ) ? self::cache_config( $base, (array) $new, $json ) : '',
		);
		$c          = self::cfg_ok( $new ) ? array_merge( (array) $new, $base ) : $c;
		$out['ops'] = self::apply_ops( $c );
		$out['store'] = self::backend( $c );
		if ( ! headers_sent() ) {
			header( 'Content-Type: application/json' );
			header( 'Cache-Control: no-store' );
		}
		echo json_encode( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Before WordPress.
		exit;
	}

	/**
	 * 3.12.9: applies the ban changes that WP-CLI, which cannot reach the web server's APCu, queued in ops.log
	 * (PNCP_Precheck::queue_op(): "ban <md5> <until>", "unban <md5>", "unban_all"). Only with a store.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return int Changes applied.
	 */
	public static function apply_ops( $c ) {
		$file = (string) $c['dir'] . '/ops.log';
		if ( '' === self::store( $c ) || ! is_file( $file ) ) {
			return 0;
		}
		$work = $file . '.' . substr( md5( uniqid( (string) mt_rand(), true ) ), 0, 10 ) . '.tmp';
		if ( ! @rename( $file, $work ) ) {
			return 0;
		}
		$lines = (array) @file( $work, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		@unlink( $work );
		$done = 0;
		$now  = time();
		foreach ( $lines as $line ) {
			$parts = explode( "\t", (string) $line );
			$hash  = isset( $parts[1] ) && preg_match( '/^[0-9a-f]{32}$/', $parts[1] ) ? $parts[1] : '';
			if ( 'ban' === $parts[0] && '' !== $hash && isset( $parts[2] ) && (int) $parts[2] > $now ) {
				if ( (int) self::mem_get( $c, 'b:' . $hash ) < (int) $parts[2] ) {
					$done += (int) self::mem_set( $c, 'b:' . $hash, (string) (int) $parts[2], (int) $parts[2] - $now + 60 );
				}
			} elseif ( 'unban' === $parts[0] && '' !== $hash ) {
				$done += (int) self::mem_del( $c, array( 'b:' . $hash, 'p:' . $hash ) );
			} elseif ( 'unban_all' === $parts[0] ) {
				foreach ( array( 'b:', 'p:' ) as $prefix ) {
					$names = array();
					foreach ( array_keys( (array) self::mem_list( $c, $prefix ) ) as $name ) {
						$names[] = $prefix . $name;
					}
					if ( $names ) {
						self::mem_del( $c, $names );
					}
				}
				++$done;
			}
		}
		return $done;
	}

	/**
	 * Where the check keeps its counters, bans, strikes, probes, nonces and events in this request: 'apcu' (shared
	 * by the site's PHP processes, apcu_usable()), 'redis' (the server of the site's persistent object cache, whose
	 * connection the line in wp-config.php passes, see redis()) or '' (the files of the data folder). With APCu
	 * or Redis, a visitor's request reads and writes no file of the plugin (the configuration too, see load()):
	 * when the disk stalls, the check does not.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return string
	 */
	public static function store( $c ) {
		if ( self::apcu_usable( $c ) ) {
			return 'apcu';
		}
		return false !== self::redis( $c ) ? 'redis' : '';
	}

	/**
	 * 3.12.9: the store of the check by its name for people: 'apcu', 'redis' or 'files' (Site Health, WP-CLI).
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return string
	 */
	public static function backend( $c ) {
		$store = self::store( $c );
		return '' === $store ? 'files' : $store;
	}

	/**
	 * 3.12.9: notes in APCu or Redis which store the check used this minute (one add per request, nothing when
	 * the value is there already), for WordPress (PNCP_Precheck::seen_backend()). Nothing with the files: WordPress
	 * then finds no note and knows the check had neither (or did not run).
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 */
	public static function note_backend( $c, $now ) {
		self::breaker_hooks( $c );
		if ( '' !== self::store( $c ) ) {
			self::mem_add( $c, 'bk:' . (int) floor( $now / 60 ), self::backend( $c ) . '|' . (int) $now, 180 );
		}
	}

	/**
	 * 3.12.9: tells the circuit breaker (PNCP_Breaker, when it is loaded) the store chosen: its own state goes into
	 * the same Redis connection (use_redis()), and the backend is recorded for Site Health (record_backend(), which
	 * writes only to a memory store, at most once a minute). Its timer's name for this store: breaker_name().
	 *
	 * @param array<string, mixed> $c Configuration.
	 */
	public static function breaker_hooks( $c ) {
		if ( ! class_exists( 'PNCP_Breaker', false ) ) {
			return;
		}
		$use_redis = array( 'PNCP_Breaker', 'use_redis' );
		$record    = array( 'PNCP_Breaker', 'record_backend' );
		if ( 'redis' === self::store( $c ) && is_callable( $use_redis ) ) {
			call_user_func( $use_redis, self::redis( $c ) );
		}
		if ( is_callable( $record ) ) {
			call_user_func( $record, self::backend( $c ) );
		}
	}

	/**
	 * 3.12.9: the circuit breaker's name for the store in use: precheck_apcu, precheck_redis or precheck_files.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return string
	 */
	public static function breaker_name( $c ) {
		return 'precheck_' . self::backend( $c );
	}

	/**
	 * The connection to Redis for this request (false: none). Connected once per request, with REDIS_TIMEOUT to
	 * connect and to read; any error (refused, timeout, wrong password) is false for the rest of the request, and
	 * the check uses the files then. The next request tries again: a refused connection fails at once, and a Redis
	 * that does not answer costs at most twice REDIS_TIMEOUT. There is no "pause" flag: it would have to live on
	 * the disk, which every request would read.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return mixed A Redis object or false.
	 */
	public static function redis( $c ) {
		$r = isset( $c['redis'] ) && is_array( $c['redis'] ) ? $c['redis'] : array();
		if ( ! $r || ! class_exists( 'Redis', false ) ) {
			return false;
		}
		$id = md5( (string) $c['dir'] . '|' . serialize( $r ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- A cache key only.
		if ( isset( self::$conns[ $id ] ) ) {
			return self::$conns[ $id ];
		}
		self::$conns[ $id ] = false;
		$timeout            = isset( $r['timeout'] ) ? min( self::REDIS_TIMEOUT, max( 0.005, (float) $r['timeout'] ) ) : self::REDIS_TIMEOUT;
		$started            = hrtime( true );
		try {
			$redis = new Redis();
			$path  = isset( $r['path'] ) ? (string) $r['path'] : '';
			$host  = isset( $r['host'] ) && '' !== (string) $r['host'] ? (string) $r['host'] : '127.0.0.1';
			if ( isset( $r['scheme'] ) && 'tls' === $r['scheme'] && false === strpos( $host, '://' ) ) {
				$host = 'tls://' . $host;
			}
			$ok = '' !== $path
				? $redis->connect( $path, 0, $timeout, null, 0, $timeout )
				: $redis->connect( $host, isset( $r['port'] ) && (int) $r['port'] > 0 ? (int) $r['port'] : 6379, $timeout, null, 0, $timeout );
			if ( ! $ok ) {
				return false;
			}
			$auth = self::redis_password( $r );
			if ( '' !== $auth ) {
				$user = isset( $r['user'] ) ? (string) $r['user'] : '';
				if ( ! $redis->auth( '' !== $user ? array( $user, $auth ) : $auth ) ) {
					return false;
				}
			}
			if ( isset( $r['db'] ) && (int) $r['db'] > 0 && ! $redis->select( (int) $r['db'] ) ) {
				return false;
			}
		} catch ( Throwable $e ) {
			return false;
		} finally {
			self::$redis_ms += ( hrtime( true ) - $started ) / 1e6;
		}
		self::$conns[ $id ] = $redis;
		return $redis;
	}

	/**
	 * The Redis password of the connection settings: kept masked in the line of wp-config.php (mask(), with the key
	 * that line passes), so that the line shown on the settings page for a manual install does not show it.
	 *
	 * @param array<string, mixed> $r Connection settings.
	 * @return string
	 */
	public static function redis_password( $r ) {
		if ( empty( $r['auth'] ) ) {
			return '';
		}
		$raw = base64_decode( (string) $r['auth'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- The masked password (mask()).
		return false === $raw ? '' : self::mask( $raw, isset( $r['sk'] ) ? (string) $r['sk'] : '' );
	}

	/**
	 * XOR with a key stream from HMAC-SHA256 of the key: masks the Redis password in wp-config.php (which holds
	 * WP_REDIS_PASSWORD in plain text already; this only keeps it off the screen). The same call unmasks it.
	 *
	 * @param string $text Text.
	 * @param string $key  Key.
	 * @return string
	 */
	public static function mask( $text, $key ) {
		$stream = '';
		$length = strlen( $text );
		for ( $i = 0; $i * 32 < $length; $i++ ) {
			$stream .= hash_hmac( 'sha256', 'pncp-redis-auth|' . $i, $key, true );
		}
		return (string) ( $text ^ (string) substr( $stream, 0, $length ) );
	}

	/**
	 * The name of a value in the store: one namespace per data folder, after the object cache's own prefix in Redis.
	 *
	 * @param array<string, mixed> $c     Configuration.
	 * @param string               $store 'apcu' or 'redis'.
	 * @param string               $name  Name.
	 * @return string
	 */
	public static function mem_key( $c, $store, $name ) {
		if ( 'redis' === $store ) {
			$prefix = isset( $c['redis']['prefix'] ) ? (string) $c['redis']['prefix'] : '';
			return $prefix . 'pncp:pc:' . substr( md5( (string) $c['dir'] ), 0, 12 ) . ':' . $name;
		}
		return 'pncp_pc_' . md5( (string) $c['dir'] ) . '_' . $name;
	}

	/**
	 * Runs a Redis call; false (and no Redis for the rest of the request) on any error.
	 *
	 * @param array<string, mixed> $c  Configuration.
	 * @param callable             $fn Gets the connection.
	 * @return mixed
	 */
	private static function redis_call( $c, $fn ) {
		$redis = self::redis( $c );
		if ( false === $redis ) {
			return false;
		}
		$started = hrtime( true );
		try {
			$result = $fn( $redis );
		} catch ( Throwable $e ) {
			$result = false;
		}
		self::$redis_ms += ( hrtime( true ) - $started ) / 1e6;
		if ( false === $result ) {
			self::$conns[ md5( (string) $c['dir'] . '|' . serialize( $c['redis'] ) ) ] = false; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- A cache key only.
		}
		return $result;
	}

	/**
	 * The options of a Redis SET: only if not there yet (NX) and with an expiry (EX).
	 *
	 * @param bool $nx  NX.
	 * @param int  $ttl Seconds.
	 * @return array<int|string, mixed>
	 */
	private static function set_options( $nx, $ttl ) {
		$options       = $nx ? array( 'nx' ) : array();
		$options['ex'] = (int) $ttl;
		return $options;
	}

	/**
	 * Adds 1 to a counter that lives $ttl seconds from its first count. False when there is no store or it failed.
	 *
	 * @param array<string, mixed> $c    Configuration.
	 * @param string               $name Name.
	 * @param int                  $ttl  Seconds.
	 * @return int|false
	 */
	public static function mem_incr( $c, $name, $ttl ) {
		$store = self::store( $c );
		if ( 'apcu' === $store ) {
			$key = self::mem_key( $c, $store, $name );
			apcu_add( $key, 0, $ttl );
			$count = apcu_inc( $key );
			return false === $count ? false : (int) $count;
		}
		if ( 'redis' !== $store ) {
			return false;
		}
		$key = self::mem_key( $c, $store, $name );
		$res = self::redis_call(
			$c,
			static function ( $redis ) use ( $key, $ttl ) {
				$out = $redis->multi( Redis::PIPELINE )->set( $key, '0', self::set_options( true, $ttl ) )->incr( $key )->exec();
				return is_array( $out ) && isset( $out[1] ) && is_int( $out[1] ) ? $out[1] : false;
			}
		);
		return false === $res ? false : (int) $res;
	}

	/**
	 * Reads values: '' for a value that is not there; null when there is no store or it failed.
	 *
	 * @param array<string, mixed> $c     Configuration.
	 * @param string[]             $names Names.
	 * @return string[]|null In the order of $names.
	 */
	public static function mem_get_many( $c, $names ) {
		$store = self::store( $c );
		if ( '' === $store ) {
			return null;
		}
		$keys = array();
		foreach ( $names as $name ) {
			$keys[] = self::mem_key( $c, $store, $name );
		}
		if ( 'apcu' === $store ) {
			$found = apcu_fetch( $keys );
			$found = is_array( $found ) ? $found : array();
			$out   = array();
			foreach ( $keys as $key ) {
				$out[] = isset( $found[ $key ] ) && is_scalar( $found[ $key ] ) ? (string) $found[ $key ] : '';
			}
			return $out;
		}
		$res = self::redis_call(
			$c,
			static function ( $redis ) use ( $keys ) {
				$out = $redis->mget( $keys );
				return is_array( $out ) && count( $out ) === count( $keys ) ? $out : false;
			}
		);
		if ( false === $res ) {
			return null;
		}
		$out = array();
		foreach ( $res as $value ) {
			$out[] = is_string( $value ) ? $value : '';
		}
		return $out;
	}

	/**
	 * Reads one value ('' = not there; null = no store, or it failed).
	 *
	 * @param array<string, mixed> $c    Configuration.
	 * @param string               $name Name.
	 * @return string|null
	 */
	public static function mem_get( $c, $name ) {
		$values = self::mem_get_many( $c, array( $name ) );
		return null === $values ? null : $values[0];
	}

	/**
	 * Writes a value for $ttl seconds (0 = no expiry). False when there is no store or it failed.
	 *
	 * @param array<string, mixed> $c     Configuration.
	 * @param string               $name  Name.
	 * @param string               $value Value.
	 * @param int                  $ttl   Seconds.
	 * @return bool
	 */
	public static function mem_set( $c, $name, $value, $ttl ) {
		$store = self::store( $c );
		if ( 'apcu' === $store ) {
			return (bool) apcu_store( self::mem_key( $c, $store, $name ), (string) $value, max( 0, (int) $ttl ) );
		}
		if ( 'redis' !== $store ) {
			return false;
		}
		$key = self::mem_key( $c, $store, $name );
		return true === self::redis_call(
			$c,
			static function ( $redis ) use ( $key, $value, $ttl ) {
				return $ttl > 0 ? $redis->set( $key, (string) $value, array( 'ex' => (int) $ttl ) ) : $redis->set( $key, (string) $value );
			}
		);
	}

	/**
	 * Writes a value only if it is not there yet: true (written), false (it was there), null (no store, or failed).
	 *
	 * @param array<string, mixed> $c     Configuration.
	 * @param string               $name  Name.
	 * @param string               $value Value.
	 * @param int                  $ttl   Seconds.
	 * @return bool|null
	 */
	public static function mem_add( $c, $name, $value, $ttl ) {
		$store = self::store( $c );
		if ( 'apcu' === $store ) {
			return (bool) apcu_add( self::mem_key( $c, $store, $name ), (string) $value, max( 1, (int) $ttl ) );
		}
		if ( 'redis' !== $store ) {
			return null;
		}
		$key = self::mem_key( $c, $store, $name );
		$res = self::redis_call(
			$c,
			static function ( $redis ) use ( $key, $value, $ttl ) {
				// SET NX answers false when the value is there: kept apart from an error.
				return array( $redis->set( $key, (string) $value, self::set_options( true, max( 1, (int) $ttl ) ) ) );
			}
		);
		return is_array( $res ) ? true === $res[0] : null;
	}

	/**
	 * Removes values.
	 *
	 * @param array<string, mixed> $c     Configuration.
	 * @param string|string[]      $names Name(s).
	 * @return bool
	 */
	public static function mem_del( $c, $names ) {
		$store = self::store( $c );
		$keys  = array();
		foreach ( (array) $names as $name ) {
			$keys[] = self::mem_key( $c, $store, (string) $name );
		}
		if ( 'apcu' === $store ) {
			apcu_delete( $keys );
			return true;
		}
		return 'redis' === $store && false !== self::redis_call(
			$c,
			static function ( $redis ) use ( $keys ) {
				return $redis->del( $keys );
			}
		);
	}

	/**
	 * The values whose name starts with $prefix: name (without the prefix) => value. For the hourly copy of the
	 * bans (sync_bans()), never in a visitor's request.
	 *
	 * @param array<string, mixed> $c      Configuration.
	 * @param string               $prefix Prefix of the names.
	 * @return array<string, string>|null Null: no store, or it failed.
	 */
	public static function mem_list( $c, $prefix ) {
		$store = self::store( $c );
		if ( '' === $store ) {
			return null;
		}
		$start = self::mem_key( $c, $store, $prefix );
		$out   = array();
		if ( 'apcu' === $store ) {
			if ( ! class_exists( 'APCUIterator' ) ) {
				return null;
			}
			foreach ( new APCUIterator( '/^' . preg_quote( $start, '/' ) . '/', APC_ITER_KEY | APC_ITER_VALUE ) as $item ) {
				if ( is_array( $item ) && isset( $item['key'], $item['value'] ) && is_scalar( $item['value'] ) ) {
					$out[ substr( (string) $item['key'], strlen( $start ) ) ] = (string) $item['value'];
				}
			}
			return $out;
		}
		$res = self::redis_call(
			$c,
			static function ( Redis $redis ) use ( $start ) {
				$found = array();
				$it    = null;
				do {
					$keys = $redis->scan( $it, str_replace( array( '*', '?', '[' ), array( '\*', '\?', '\[' ), $start ) . '*', 1000 );
					if ( is_array( $keys ) && $keys ) {
						$values = $redis->mget( $keys );
						foreach ( $keys as $i => $key ) {
							if ( is_array( $values ) && isset( $values[ $i ] ) && is_string( $values[ $i ] ) ) {
								$found[ substr( (string) $key, strlen( $start ) ) ] = $values[ $i ];
							}
						}
					}
				} while ( $it > 0 );
				return $found;
			}
		);
		return is_array( $res ) ? $res : null;
	}

	/**
	 * Adds an event line to the store's queue (at most EVENTS_MAX, the oldest go first). False: no store / failed.
	 *
	 * @param array<string, mixed> $c    Configuration.
	 * @param string               $line The line (no newline).
	 * @return bool
	 */
	public static function mem_push( $c, $line ) {
		$store = self::store( $c );
		if ( 'apcu' === $store ) {
			$seq = self::mem_key( $c, $store, 'ev:seq' );
			apcu_add( $seq, 0 );
			$n = apcu_inc( $seq );
			return false !== $n && (bool) apcu_store( self::mem_key( $c, $store, 'ev:' . $n ), $line, 7 * 86400 );
		}
		if ( 'redis' !== $store ) {
			return false;
		}
		$key = self::mem_key( $c, $store, 'ev' );
		return false !== self::redis_call(
			$c,
			static function ( $redis ) use ( $key, $line ) {
				$out = $redis->multi( Redis::PIPELINE )->rPush( $key, $line )->lTrim( $key, -self::EVENTS_MAX, -1 )->expire( $key, 7 * 86400 )->exec();
				return is_array( $out ) && is_int( $out[0] ) ? true : false;
			}
		);
	}

	/**
	 * Takes every queued event line out of the store (for PNCP_Precheck::import_events()).
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return string[]
	 */
	public static function mem_drain( $c ) {
		$store = self::store( $c );
		if ( 'apcu' === $store ) {
			$seq  = (int) apcu_fetch( self::mem_key( $c, $store, 'ev:seq' ) );
			$done = (int) apcu_fetch( self::mem_key( $c, $store, 'ev:done' ) );
			$out  = array();
			for ( $n = max( $done + 1, $seq - self::EVENTS_MAX + 1 ); $n <= $seq; $n++ ) {
				$key  = self::mem_key( $c, $store, 'ev:' . $n );
				$line = apcu_fetch( $key );
				if ( is_string( $line ) ) {
					$out[] = $line;
				}
				apcu_delete( $key );
			}
			apcu_store( self::mem_key( $c, $store, 'ev:done' ), $seq );
			return $out;
		}
		if ( 'redis' !== $store ) {
			return array();
		}
		$key = self::mem_key( $c, $store, 'ev' );
		$res = self::redis_call(
			$c,
			static function ( $redis ) use ( $key ) {
				$out = $redis->multi()->lRange( $key, 0, -1 )->del( $key )->exec();
				return is_array( $out ) && is_array( $out[0] ) ? $out[0] : false;
			}
		);
		return is_array( $res ) ? array_values( array_map( 'strval', $res ) ) : array();
	}

	/**
	 * Copies the bans between the files and the store: each side gets the other's bans that last longer than its
	 * own. With $files_only, only the files into the store (sync_later()). Marks the store as filled ('sync').
	 *
	 * @param array<string, mixed> $c          Configuration.
	 * @param int                  $now        Time.
	 * @param bool                 $files_only Only from the files to the store.
	 * @param int                  $budget     Milliseconds (0 = no limit); past it the store is not marked.
	 * @return int|null Bans copied; null without a store.
	 */
	public static function sync_bans( $c, $now, $files_only = false, $budget = 0 ) {
		if ( '' === self::store( $c ) ) {
			return null;
		}
		$end    = $budget > 0 ? hrtime( true ) + $budget * 1000000 : 0;
		$folder = (string) $c['dir'] . '/bans';
		$copied = 0;
		$stored = $files_only ? array() : self::mem_list( $c, 'b:' );
		if ( is_array( $stored ) && $stored ) {
			if ( ! is_dir( $folder ) ) {
				@mkdir( $folder, 0755, true );
			}
			foreach ( $stored as $hash => $until ) {
				$file = $folder . '/' . $hash;
				if ( preg_match( '/^[0-9a-f]{32}$/', (string) $hash ) && (int) $until > $now && ( is_file( $file ) ? (int) @file_get_contents( $file ) : 0 ) < (int) $until ) {
					$copied += (int) self::put_atomic( $file, (string) (int) $until );
				}
			}
		}
		$handle   = @opendir( $folder );
		$complete = true;
		if ( false !== $handle ) {
			$name = readdir( $handle );
			while ( false !== $name ) {
				if ( $end && hrtime( true ) >= $end ) {
					$complete = false;
					break;
				}
				if ( preg_match( '/^[0-9a-f]{32}$/', $name ) ) {
					$until = (int) @file_get_contents( $folder . '/' . $name );
					if ( $until > $now && ( isset( $stored[ $name ] ) ? (int) $stored[ $name ] : (int) self::mem_get( $c, 'b:' . $name ) ) < $until ) {
						$copied += (int) self::mem_set( $c, 'b:' . $name, (string) $until, $until - $now + 60 );
					}
				}
				$name = readdir( $handle );
			}
			closedir( $handle );
		}
		if ( $complete ) {
			self::mem_set( $c, 'sync', (string) $now, 0 );
		}
		return $copied;
	}

	/**
	 * The store has no 'sync' mark: it is new, or lost its data (Redis restarted or flushed, PHP-FPM restarted for
	 * APCu), so the bans of the files are not in it. One request (the 'syncing' value, 60 seconds) copies them in at
	 * its end, within SWEEP_MS: the only reading of the disk in a request with a store, once after such a loss.
	 *
	 * @param array<string, mixed> $c Configuration.
	 */
	public static function sync_later( $c ) {
		if ( self::$sync_queued || true !== self::mem_add( $c, 'syncing', '1', 60 ) ) {
			return;
		}
		self::$sync_queued = true;
		register_shutdown_function(
			static function () use ( $c ) {
				self::sync_bans( $c, time(), true, self::SWEEP_MS );
			}
		);
	}
}
