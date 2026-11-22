<?php
/**
 * 3.12.9: the circuit breaker. A counting or storage operation in a visitor's request that takes longer than its
 * threshold (200 ms) suspends that feature for a while (10 minutes): requests then pass without it (fail open;
 * bans already written still apply), so a frozen disk, a slow Redis or resolver cannot hold every PHP worker.
 *
 * The pre-cache check loads this file before WordPress (PNCP_Precheck_Runtime::breaker()), so it uses no
 * WordPress function unless it exists. The state is kept, in this order, in:
 * - a store given with use_store() / use_redis() (the counters' own connection);
 * - Redis (phpredis), when a server is configured (setup() 'redis', or WordPress's WP_REDIS_* constants; at most
 *   50 ms to connect and to answer). Shared by PHP-FPM and WP-CLI;
 * - APCu, when enabled;
 * - only when neither exists, small files in the pre-cache check's data folder (breaker/), written to a temporary
 *   file renamed over the old one: never a lock. When Redis is configured but does not answer, nothing is stored
 *   (the breaker works within the request only): never the disk.
 * A check reads the state once per request (one APCu / Redis read, or one stat() of the state file: a file's
 * modification time is the end of its suspension, so a closed breaker never opens a file). Writes happen only when
 * a feature trips. WordPress shows what tripped in Site Health, on the ScrapeLock page and in
 * `wp scrapelock breaker` (PNCP_Breaker_Status).
 *
 * @package ScrapeLock
 */

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors.Discouraged -- Also runs before WordPress: its functions do not exist yet.

/**
 * Trips, state and history of the circuit breaker.
 */
final class PNCP_Breaker {

	/**
	 * Default threshold in milliseconds (filter `pncp_breaker_ms`, per feature).
	 */
	const MS = 200;

	/**
	 * Default threshold of the DNS lookups ("dns_*"): a cold lookup can take a few hundred ms on a healthy server.
	 */
	const DNS_MS = 1000;

	/**
	 * Default minutes a tripped feature stays suspended (filter `pncp_breaker_minutes`, per feature).
	 */
	const MINUTES = 10;

	/**
	 * Trips kept in the history (newest first).
	 */
	const HISTORY = 20;

	/**
	 * How long the stored state and history are kept (seconds), so the last 24 hours can be shown.
	 */
	const KEEP = 172800;

	/**
	 * Redis: most seconds to connect and to wait for an answer.
	 */
	const REDIS_TIMEOUT = 0.05;

	/**
	 * The data folder for the file store ('' = none; null = not resolved yet: PNCP_Precheck::dir() on first use).
	 *
	 * @var string|null
	 */
	public static $dir = null;

	/**
	 * Thresholds in ms by feature or family (the part before the first "_"), set by the pre-cache check from its
	 * configuration; used only before WordPress has loaded (then the filter decides).
	 *
	 * @var array<string, float>
	 */
	public static $ms = array();

	/**
	 * Minutes by feature or family, as $ms.
	 *
	 * @var array<string, int>
	 */
	public static $minutes = array();

	/**
	 * The clock (tests): a callable that returns the Unix time, or null for time().
	 *
	 * @var callable|null
	 */
	public static $clock = null;

	/**
	 * The Redis server: host, port, path (unix socket), db, prefix ('' = none; null = WordPress's WP_REDIS_*).
	 *
	 * @var array<string, mixed>|string|null
	 */
	public static $redis_config = null;

	/**
	 * The store in use: apcu, redis, files, custom or none ('' = not chosen yet).
	 *
	 * @var string
	 */
	private static $kind = '';

	/**
	 * The Redis connection (kind "redis").
	 *
	 * @var object|null
	 */
	private static $redis = null;

	/**
	 * A store given with use_store(): get( key ), set( key, value, ttl ), delete( key ) callables.
	 *
	 * @var array<string, callable>
	 */
	private static $custom = array();

	/**
	 * "Suspended until" by feature, read once per request.
	 *
	 * @var array<string, int>
	 */
	private static $memo = array();

	/**
	 * Sets the data folder and the limits of the pre-cache check (its config.json "breaker").
	 *
	 * @param string               $dir    The data folder.
	 * @param array<string, mixed> $limits Optional: 'ms' and 'minutes' for the family 'precheck', 'redis' (see
	 *                                     $redis_config).
	 */
	public static function setup( $dir, $limits = array() ) {
		if ( self::$dir !== $dir ) {
			self::$memo = array();
		}
		self::$dir = (string) $dir;
		if ( ! is_array( $limits ) ) {
			return;
		}
		if ( isset( $limits['ms'] ) ) {
			self::$ms['precheck'] = (float) $limits['ms'];
		}
		if ( isset( $limits['minutes'] ) ) {
			self::$minutes['precheck'] = (int) $limits['minutes'];
		}
		if ( isset( $limits['redis'] ) && null === self::$redis_config ) {
			self::$redis_config = is_array( $limits['redis'] ) ? $limits['redis'] : '';
		}
	}

	/**
	 * Uses a store of the caller's (e.g. the pre-cache counters' Redis connection).
	 *
	 * @param callable $get    function ( string $key ): mixed|null.
	 * @param callable $set    function ( string $key, mixed $value, int $ttl ): bool.
	 * @param callable $delete function ( string $key ): void.
	 */
	public static function use_store( $get, $set, $delete ) {
		self::$custom = array(
			'get'    => $get,
			'set'    => $set,
			'delete' => $delete,
		);
		self::$kind   = 'custom';
		self::$memo   = array();
	}

	/**
	 * Uses an open phpredis connection (the object cache's, or the counters').
	 *
	 * @param object $redis A Redis instance.
	 */
	public static function use_redis( $redis ) {
		if ( 'redis' === self::$kind && self::$redis === $redis ) {
			return; // The same connection again (the check tells it once per request): what was read stays.
		}
		self::$redis = $redis;
		self::$kind  = 'redis';
		self::$memo  = array();
	}

	/**
	 * Chooses the store again on next use (tests, after a change of configuration).
	 */
	public static function forget() {
		self::$memo   = array();
		self::$kind   = '';
		self::$redis  = null;
		self::$custom = array();
	}

	/**
	 * The store in use: redis, apcu, files, custom or none.
	 *
	 * @return string
	 */
	public static function kind() {
		if ( '' !== self::$kind ) {
			return self::$kind;
		}
		$config = self::redis_config();
		// In WordPress the object cache's own connection comes first, also when its server has a password (which
		// config.json never holds): the pre-cache check then keeps the state in the same server, through the
		// connection of its counters (use_redis()).
		$redis = self::wp_redis();
		if ( null === $redis && $config ) {
			$redis = self::connect( $config );
		}
		$counters = null === $redis ? self::precheck_redis() : null;
		if ( null === $redis && is_object( $counters ) ) {
			$redis = $counters;
		}
		if ( null !== $redis ) {
			self::$redis = $redis;
			self::$kind  = 'redis';
			return self::$kind;
		}
		// Not WP-CLI's APCu: it belongs to one process and is gone when the command ends (filter
		// `pncp_breaker_apcu`).
		$apcu = function_exists( 'apcu_enabled' ) && apcu_enabled() && 'cli' !== PHP_SAPI;
		if ( function_exists( 'apply_filters' ) ) {
			$apcu = (bool) apply_filters( 'pncp_breaker_apcu', $apcu );
		}
		if ( $apcu ) {
			self::$kind = 'apcu';
		} elseif ( $config || false === $counters ) {
			self::$kind = 'none'; // Redis is there but does not answer: never the disk instead.
		} else {
			self::$kind = '' !== self::dir() ? 'files' : 'none';
		}
		return self::$kind;
	}

	/**
	 * The data folder ('' = none).
	 *
	 * @return string
	 */
	public static function dir() {
		if ( null === self::$dir ) {
			self::$dir = function_exists( 'wp_upload_dir' ) && class_exists( 'PNCP_Precheck' ) ? (string) PNCP_Precheck::dir() : '';
		}
		return self::$dir;
	}

	/**
	 * The Redis server to use (empty = none): $redis_config, or in WordPress the constants of the Redis object
	 * cache plugins (WP_REDIS_HOST, WP_REDIS_PORT, WP_REDIS_PATH, WP_REDIS_DATABASE; filter `pncp_breaker_redis`),
	 * only while the phpredis extension is loaded.
	 *
	 * @return array<string, mixed>
	 */
	public static function redis_config() {
		if ( ! class_exists( 'Redis', false ) ) {
			return array();
		}
		if ( null === self::$redis_config ) {
			self::$redis_config = function_exists( 'apply_filters' ) ? self::wp_redis_config() : '';
		}
		return is_array( self::$redis_config ) ? self::$redis_config : array();
	}

	/**
	 * WordPress: the Redis server of the object cache, as written to the pre-cache check's configuration (never a
	 * password: config.json is a file in uploads).
	 *
	 * @return array<string, mixed>|string
	 */
	public static function wp_redis_config() {
		$config = '';
		// A server with a password is left out (it would have to be written to config.json): WordPress then uses
		// the object cache's own connection, the pre-cache check APCu or its files.
		$used = defined( 'WP_REDIS_HOST' ) || defined( 'WP_REDIS_PATH' ) || defined( 'WP_REDIS_SCHEME' ) || defined( 'WP_REDIS_VERSION' );
		if ( $used && ! defined( 'WP_REDIS_PASSWORD' ) ) {
			$unix   = defined( 'WP_REDIS_SCHEME' ) && 'unix' === constant( 'WP_REDIS_SCHEME' );
			$config = array(
				'host' => defined( 'WP_REDIS_HOST' ) ? (string) constant( 'WP_REDIS_HOST' ) : '127.0.0.1',
				'port' => defined( 'WP_REDIS_PORT' ) ? (int) constant( 'WP_REDIS_PORT' ) : 6379,
				'path' => $unix && defined( 'WP_REDIS_PATH' ) ? (string) constant( 'WP_REDIS_PATH' ) : '',
				'db'   => defined( 'WP_REDIS_DATABASE' ) ? (int) constant( 'WP_REDIS_DATABASE' ) : 0,
			);
		}
		$config = apply_filters( 'pncp_breaker_redis', $config );
		return is_array( $config ) ? $config : '';
	}

	/**
	 * Now.
	 *
	 * @return int
	 */
	public static function now() {
		return null !== self::$clock ? (int) call_user_func( self::$clock ) : time();
	}

	/**
	 * Is the name usable (also as a file name)?
	 *
	 * @param mixed $name Feature.
	 * @return bool
	 */
	public static function valid( $name ) {
		return is_string( $name ) && 1 === preg_match( '/^[a-z0-9_]{1,40}$/', $name );
	}

	/**
	 * The feature's family: "precheck" for "precheck_files".
	 *
	 * @param string $name Feature.
	 * @return string
	 */
	private static function group( $name ) {
		$cut = strpos( $name, '_' );
		return false === $cut ? $name : substr( $name, 0, $cut );
	}

	/**
	 * The threshold of a feature in milliseconds (0 or less = never trips).
	 *
	 * @param string $name Feature.
	 * @return float
	 */
	public static function threshold( $name ) {
		$group = self::group( $name );
		// In WordPress the filter decides (the pre-cache check's values come from it, in config.json).
		if ( function_exists( 'apply_filters' ) ) {
			$ms = apply_filters( 'pncp_breaker_ms', 'dns' === $group ? self::DNS_MS : self::MS, $name );
			return is_numeric( $ms ) ? (float) $ms : (float) self::MS;
		}
		if ( isset( self::$ms[ $name ] ) ) {
			return (float) self::$ms[ $name ];
		}
		if ( isset( self::$ms[ $group ] ) ) {
			return (float) self::$ms[ $group ];
		}
		return 'dns' === $group ? (float) self::DNS_MS : (float) self::MS;
	}

	/**
	 * How many minutes a feature stays suspended once tripped (at least 1).
	 *
	 * @param string $name Feature.
	 * @return int
	 */
	public static function minutes( $name ) {
		$group = self::group( $name );
		if ( function_exists( 'apply_filters' ) ) {
			return max( 1, (int) apply_filters( 'pncp_breaker_minutes', self::MINUTES, $name ) );
		}
		if ( isset( self::$minutes[ $name ] ) ) {
			return max( 1, (int) self::$minutes[ $name ] );
		}
		if ( isset( self::$minutes[ $group ] ) ) {
			return max( 1, (int) self::$minutes[ $group ] );
		}
		return self::MINUTES;
	}

	/**
	 * Is the feature suspended now? Read once per request; never waits for a lock, and a missing, unreadable or
	 * damaged state counts as "not suspended".
	 *
	 * @param string $name Feature.
	 * @return bool
	 */
	public static function open( $name ) {
		if ( ! isset( self::$memo[ $name ] ) ) {
			if ( ! self::valid( $name ) ) {
				self::$memo[ $name ] = 0;
			} elseif ( 'files' === self::kind() ) {
				// One stat(): the state file's modification time is the end of the suspension (set()); a file
				// whose time has passed (or a missing one) means closed, and is never opened here.
				$until               = @filemtime( self::file( 'state_' . $name ) );
				self::$memo[ $name ] = false === $until ? 0 : (int) $until;
			} else {
				$state               = self::get( 'state_' . $name );
				self::$memo[ $name ] = isset( $state['until'] ) ? (int) $state['until'] : 0;
			}
		}
		return self::$memo[ $name ] > self::now();
	}

	/**
	 * Runs an operation under the breaker: while the feature is suspended it is skipped ($fallback is returned);
	 * when it takes longer than the threshold the feature trips. Errors of the operation are passed on.
	 *
	 * @param string   $name     Feature.
	 * @param callable $fn       The operation.
	 * @param mixed    $fallback What a skipped operation returns.
	 * @param string   $what     Short description of the operation, for the history.
	 * @return mixed
	 */
	public static function guard( $name, $fn, $fallback = null, $what = '' ) {
		if ( self::open( $name ) ) {
			return $fallback;
		}
		$start = hrtime( true );
		try {
			return call_user_func( $fn );
		} finally {
			self::observe( $name, hrtime( true ) - $start, $what );
		}
	}

	/**
	 * Reports how long an operation took; trips the feature when that is over its threshold.
	 *
	 * @param string    $name Feature.
	 * @param int|float $ns   Duration in nanoseconds (hrtime()).
	 * @param string    $what Short description of the operation.
	 * @return bool Whether the feature tripped now.
	 */
	public static function observe( $name, $ns, $what = '' ) {
		$ms    = $ns / 1e6;
		$limit = self::threshold( $name );
		if ( $limit <= 0 || $ms <= $limit || ! self::valid( $name ) || self::open( $name ) ) {
			return false;
		}
		self::trip( $name, $ms, $what );
		return true;
	}

	/**
	 * Suspends a feature for its minutes and adds the trip to the history.
	 *
	 * @param string    $name Feature.
	 * @param int|float $ms   How long the operation took.
	 * @param string    $what Short description of the operation.
	 */
	public static function trip( $name, $ms, $what = '' ) {
		if ( ! self::valid( $name ) ) {
			return;
		}
		$now                 = self::now();
		$until               = $now + 60 * self::minutes( $name );
		self::$memo[ $name ] = $until;
		// Another request tripped it a moment ago (stalled requests often end together): once is enough.
		$known = self::get( 'state_' . $name );
		if ( isset( $known['until'] ) && (int) $known['until'] > $now ) {
			self::$memo[ $name ] = (int) $known['until'];
			return;
		}
		$entry = array(
			'name'  => $name,
			'at'    => $now,
			'until' => $until,
			'ms'    => round( (float) $ms, 1 ),
			'limit' => self::threshold( $name ),
			'what'  => substr( (string) preg_replace( '/[^A-Za-z0-9 _.:\/-]+/', '', (string) $what ), 0, 60 ),
			'store' => self::kind(),
		);
		self::set( 'state_' . $name, $entry );
		$names = self::names();
		if ( ! in_array( $name, $names, true ) ) {
			$names[] = $name;
			self::set( 'names', $names );
		}
		$history = self::history();
		array_unshift( $history, $entry );
		self::set( 'history', array_slice( $history, 0, self::HISTORY ) );
	}

	/**
	 * Ends the suspension of one feature, or of all (''). The history stays unless $history.
	 *
	 * @param string $name    Feature ('' = all).
	 * @param bool   $history Also clear the history.
	 * @return int How many features were suspended.
	 */
	public static function reset( $name = '', $history = false ) {
		$count = 0;
		$now   = self::now();
		foreach ( self::states() as $key => $state ) {
			if ( '' !== $name && $key !== $name ) {
				continue;
			}
			if ( (int) $state['until'] > $now ) {
				++$count;
			}
			self::delete( 'state_' . $key );
		}
		if ( '' !== $name ) {
			unset( self::$memo[ $name ] );
		} else {
			self::$memo = array();
		}
		if ( $history ) {
			self::delete( 'history' );
			self::delete( 'names' );
		}
		return $count;
	}

	/**
	 * The names that ever tripped (kept KEEP seconds).
	 *
	 * @return string[]
	 */
	private static function names() {
		return array_values( array_filter( self::get( 'names' ), array( __CLASS__, 'valid' ) ) );
	}

	/**
	 * The last trip of every feature that has a state (name => entry), suspended or not.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function states() {
		$out = array();
		foreach ( self::names() as $name ) {
			$state = self::get( 'state_' . $name );
			if ( isset( $state['until'] ) ) {
				$out[ $name ] = $state + array(
					'name' => $name,
					'at'   => 0,
					'ms'   => 0,
					'what' => '',
				);
			}
		}
		ksort( $out );
		return $out;
	}

	/**
	 * The last trips, newest first (at most HISTORY).
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function history() {
		$out = array();
		foreach ( self::get( 'history' ) as $entry ) {
			if ( is_array( $entry ) && isset( $entry['name'], $entry['at'] ) && self::valid( $entry['name'] ) ) {
				$out[] = $entry;
			}
		}
		return array_slice( $out, 0, self::HISTORY );
	}

	/**
	 * What tripped in the last $hours or is suspended now, by feature: the last trip, whether it is still
	 * suspended ('open'), and how many times it tripped in that time ('count').
	 *
	 * @param int $hours Hours.
	 * @return array<string, array<string, mixed>>
	 */
	public static function report( $hours = 24 ) {
		$now   = self::now();
		$since = $now - 3600 * max( 1, (int) $hours );
		$out   = array();
		$states = self::states();
		foreach ( $states as $name => $state ) {
			if ( (int) $state['until'] > $now || (int) $state['at'] >= $since ) {
				$out[ $name ] = array( 'count' => 0 ) + $state;
			}
		}
		foreach ( self::history() as $entry ) {
			if ( (int) $entry['at'] < $since ) {
				continue;
			}
			$name = (string) $entry['name'];
			if ( ! isset( $out[ $name ] ) ) {
				$out[ $name ] = array( 'count' => 0 ) + $entry;
			}
			$out[ $name ]['count'] = (int) $out[ $name ]['count'] + 1;
		}
		foreach ( $out as $name => $row ) {
			// Only the current state says "suspended" (after a reset the history still has the old "until").
			$out[ $name ]['open']  = isset( $states[ $name ] ) && (int) $states[ $name ]['until'] > $now;
			$out[ $name ]['count'] = max( 1, (int) $row['count'] );
		}
		return $out;
	}

	/**
	 * Hourly (WordPress): forgets the states of suspensions that ended more than a day ago, so a check is back
	 * to reading a missing state.
	 */
	public static function tidy() {
		$now  = self::now();
		$keep = array();
		foreach ( self::states() as $name => $state ) {
			if ( (int) $state['until'] < $now - 86400 ) {
				self::delete( 'state_' . $name );
			} else {
				$keep[] = $name;
			}
		}
		if ( self::names() !== $keep ) {
			if ( $keep ) {
				self::set( 'names', $keep );
			} else {
				self::delete( 'names' );
			}
		}
	}

	/**
	 * The counters' backend the pre-cache check last recorded (record_backend()), or array().
	 *
	 * @return array<string, mixed> kind (redis, apcu, files), at.
	 */
	public static function recorded_backend() {
		$seen = self::get( 'backend' );
		return isset( $seen['kind'], $seen['at'] ) && is_string( $seen['kind'] ) ? $seen : array();
	}

	/**
	 * For the counters' code: records the backend it used (redis, apcu, files), for Site Health. Only in a memory
	 * store (never the disk), and at most once a minute per process: call it freely.
	 *
	 * @param string $kind redis, apcu or files.
	 */
	public static function record_backend( $kind ) {
		static $done = array();
		$now = self::now();
		if ( ! in_array( self::kind(), array( 'redis', 'apcu', 'custom' ), true ) || ( isset( $done[ $kind ] ) && $done[ $kind ] > $now - 60 ) ) {
			return;
		}
		$done[ $kind ] = $now;
		self::set(
			'backend',
			array(
				'kind' => (string) $kind,
				'at'   => $now,
			)
		);
	}

	/* ---------- The store ---------- */

	/**
	 * A stored array (empty when missing, unreadable or damaged).
	 *
	 * @param string $key Key (letters, digits, "_").
	 * @return array<mixed>
	 */
	private static function get( $key ) {
		$value = null;
		try {
			switch ( self::kind() ) {
				case 'custom':
					$value = call_user_func( self::$custom['get'], $key );
					break;
				case 'redis':
					$raw   = call_user_func( array( self::$redis, 'get' ), self::redis_key( $key ) );
					$value = is_string( $raw ) ? json_decode( $raw, true ) : null;
					break;
				case 'apcu':
					$hit   = false;
					$value = apcu_fetch( self::apcu_key( $key ), $hit );
					break;
				case 'files':
					$file = self::file( $key );
					if ( @is_file( $file ) ) {
						$raw   = @file_get_contents( $file );
						$value = is_string( $raw ) ? json_decode( $raw, true ) : null;
					}
					break;
			}
		} catch ( Throwable $e ) {
			$value = null;
		}
		return is_array( $value ) ? $value : array();
	}

	/**
	 * Stores an array (kept KEEP seconds). Never a lock: a file is written to a temporary one, then renamed.
	 *
	 * @param string       $key   Key.
	 * @param array<mixed> $value Value.
	 */
	private static function set( $key, $value ) {
		try {
			switch ( self::kind() ) {
				case 'custom':
					call_user_func( self::$custom['set'], $key, $value, self::KEEP );
					break;
				case 'redis':
					call_user_func( array( self::$redis, 'setex' ), self::redis_key( $key ), self::KEEP, (string) json_encode( $value ) );
					break;
				case 'apcu':
					apcu_store( self::apcu_key( $key ), $value, self::KEEP );
					break;
				case 'files':
					$file   = self::file( $key );
					$folder = dirname( $file );
					if ( ! is_dir( $folder ) && ! @mkdir( $folder, 0755, true ) && ! is_dir( $folder ) ) {
						return;
					}
					$tmp = $file . '.' . getmypid() . '-' . mt_rand() . '.tmp';
					if ( false === @file_put_contents( $tmp, (string) json_encode( $value ) ) ) {
						@unlink( $tmp );
						return;
					}
					// A state's file carries the end of its suspension as its modification time: open() reads
					// only that (one stat()), never the file.
					if ( 0 === strpos( $key, 'state_' ) && isset( $value['until'] ) ) {
						@touch( $tmp, (int) $value['until'] );
					}
					if ( ! @rename( $tmp, $file ) ) {
						@unlink( $tmp );
					}
					break;
			}
		} catch ( Throwable $e ) {
			return;
		}
	}

	/**
	 * Removes a stored value.
	 *
	 * @param string $key Key.
	 */
	private static function delete( $key ) {
		try {
			switch ( self::kind() ) {
				case 'custom':
					call_user_func( self::$custom['delete'], $key );
					break;
				case 'redis':
					call_user_func( array( self::$redis, 'del' ), self::redis_key( $key ) );
					break;
				case 'apcu':
					apcu_delete( self::apcu_key( $key ) );
					break;
				case 'files':
					@unlink( self::file( $key ) );
					break;
			}
		} catch ( Throwable $e ) {
			return;
		}
	}

	/**
	 * The site's part of the APCu and Redis keys: the plugin folder, the same for the pre-cache check and for
	 * WordPress (no database needed to know it).
	 *
	 * @return string
	 */
	private static function ns() {
		return substr( md5( __DIR__ ), 0, 12 );
	}

	/**
	 * The APCu key.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	private static function apcu_key( $key ) {
		return 'pncp_brk_' . self::ns() . '_' . $key;
	}

	/**
	 * The Redis key.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	private static function redis_key( $key ) {
		$config = self::redis_config();
		$prefix = isset( $config['prefix'] ) ? (string) $config['prefix'] : '';
		return $prefix . 'pncp:breaker:' . self::ns() . ':' . $key;
	}

	/**
	 * The file of a key: breaker/<feature>.json for a state, breaker/<key>.json otherwise.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	private static function file( $key ) {
		return self::dir() . '/breaker/' . ( 0 === strpos( $key, 'state_' ) ? substr( $key, 6 ) : '_' . $key ) . '.json';
	}

	/**
	 * WordPress: the Redis connection of the object cache (Redis Object Cache), when there is one.
	 *
	 * @return object|null
	 */
	private static function wp_redis() {
		global $wp_object_cache;
		if ( ! is_object( $wp_object_cache ) || ! method_exists( $wp_object_cache, 'redis_instance' ) ) {
			return null;
		}
		try {
			$redis = $wp_object_cache->redis_instance();
		} catch ( Throwable $e ) {
			return null;
		}
		return $redis instanceof Redis ? $redis : null;
	}

	/**
	 * WordPress: the Redis connection of the pre-cache check's counters (PNCP_Precheck::runtime_config(), the
	 * server of the object cache as written into its line in wp-config.php), for an object cache without
	 * redis_instance(). Null when the check has no Redis server, false when it has one that does not answer.
	 *
	 * @return object|false|null
	 */
	private static function precheck_redis() {
		if ( ! function_exists( 'get_option' ) || ! class_exists( 'PNCP_Precheck', false ) || ! class_exists( 'Redis', false ) ) {
			return null;
		}
		try {
			$c = PNCP_Precheck::runtime_config();
			if ( empty( $c['redis'] ) || ! class_exists( 'PNCP_Precheck_Runtime', false ) ) {
				return null;
			}
			$redis = PNCP_Precheck_Runtime::redis( $c );
		} catch ( Throwable $e ) {
			return false;
		}
		return $redis instanceof Redis ? $redis : false;
	}

	/**
	 * A phpredis connection (persistent, at most REDIS_TIMEOUT to connect and per answer), or null.
	 *
	 * @param array<string, mixed> $config Server.
	 * @return object|null
	 */
	private static function connect( $config ) {
		try {
			$redis = new Redis();
			$path  = isset( $config['path'] ) ? (string) $config['path'] : '';
			$ok    = '' !== $path
				? $redis->pconnect( $path, 0, self::REDIS_TIMEOUT, 'pncp_breaker' )
				: $redis->pconnect( isset( $config['host'] ) ? (string) $config['host'] : '127.0.0.1', isset( $config['port'] ) ? (int) $config['port'] : 6379, self::REDIS_TIMEOUT, 'pncp_breaker' );
			if ( ! $ok ) {
				return null;
			}
			$redis->setOption( Redis::OPT_READ_TIMEOUT, self::REDIS_TIMEOUT );
			if ( ! empty( $config['db'] ) && ! $redis->select( (int) $config['db'] ) ) {
				return null;
			}
			return $redis;
		} catch ( Throwable $e ) {
			return null;
		}
	}
}
