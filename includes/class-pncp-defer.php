<?php
/**
 * 3.12.9: nothing on the disk or in the database during a visitor's request, where the site has a persistent object
 * cache (Redis, Memcached) or APCu. A server whose disk stalls (iowait) made every request that touched it wait,
 * and PHP workers ran out. Where such a store exists, what a visitor's request has to keep (log events, new bans,
 * the Traffic rows of WordPress, AI referrals, attack records, the state of the automatic Emergency Mode) goes to a
 * queue in that store, and a scheduled event writes it to the database once a minute, in its own request (WP-Cron's
 * loopback, a real cron job or WP-CLI), never in a visitor's. Without such a store nothing changes: the database is
 * the only place shared by all PHP workers.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Queues in the object cache or APCu, written to the database by a scheduled event.
 */
final class PNCP_Defer {

	const CRON     = 'pncp_defer_flush';

	/**
	 * The automatic Emergency Mode's end, decided in a visitor's request (PNCP_Surge), until the scheduled event
	 * stores it (read by PNCP_Options::emergency_until(), also in the early check).
	 */
	const EMERGENCY = 'pncp_emergency_auto';
	const SCHEDULE = 'pncp_minute';

	/**
	 * At most this many rows wait in one queue; past it new rows are dropped (and counted): a flood never fills the
	 * cache's memory. Rows wait at most a day.
	 */
	const MAX_QUEUE = 20000;
	const TTL       = DAY_IN_SECONDS;

	/**
	 * Rows written per queue and run, and the time a run may take.
	 */
	const BATCH   = 5000;
	const SECONDS = 20;

	/**
	 * The queues: what writes their rows (callable( array $rows ): void) and what says a row may be written now.
	 *
	 * @var array<string, array{0: callable, 1: callable|null}>
	 */
	private static $handlers = array();

	/**
	 * This request's answer of active() (null = not asked yet).
	 *
	 * @var bool|null
	 */
	private static $active = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		if ( 'apcu' === self::store() ) {
			// Without a persistent object cache WordPress asks the database again on every request for an option
			// that is not autoloaded, or not there at all (an unlocked site has no Lockdown state): see pre_option().
			if ( self::active() ) {
				add_filter( 'pre_option', array( __CLASS__, 'pre_option' ), 10, 3 );
				foreach ( self::TRANSIENTS as $transient ) {
					add_filter( 'pre_transient_' . $transient, array( __CLASS__, 'pre_transient' ), 10, 2 );
				}
			}
			foreach ( array( 'added_option', 'updated_option', 'deleted_option' ) as $hook ) {
				add_action( $hook, array( __CLASS__, 'forget_option' ) );
			}
			add_action( 'setted_transient', array( __CLASS__, 'forget_transient' ) );
			add_action( 'deleted_transient', array( __CLASS__, 'forget_transient' ) );
		}
		add_filter( 'cron_schedules', array( __CLASS__, 'schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval -- One minute, only where a persistent store holds the queues.
		add_action( self::CRON, array( __CLASS__, 'flush' ) );
		add_action( PNCP_Log::CRON, array( __CLASS__, 'flush' ), 5 ); // The hourly task as a safety net.
		add_action( PNCP_Log::CRON, array( __CLASS__, 'ensure_cron' ), 6 );
		add_action( 'admin_init', array( __CLASS__, 'admin' ) );
		// APCu belongs to PHP-FPM: a cron job run by WP-CLI cannot see it. With DISABLE_WP_CRON a visitor's request
		// that queued something asks wp-cron.php (in PHP-FPM, not waited for) to write it, at most once a minute.
		if ( isset( $_GET['pncp_flush'] ) && function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checked against its signature in flush_signed().
			add_action( 'wp_loaded', array( __CLASS__, 'flush_signed' ) );
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			// WP-CLI reads the log, the bans and the traffic straight from the database: what is waiting is written first.
			add_action( 'init', array( __CLASS__, 'flush' ), 99 );
		}
	}

	/**
	 * The one-minute schedule.
	 *
	 * @param array<string, array{interval:int, display:string}> $schedules Schedules.
	 * @return array<string, array{interval:int, display:string}>
	 */
	public static function schedules( $schedules ) {
		$schedules[ self::SCHEDULE ] = array(
			'interval' => MINUTE_IN_SECONDS,
			'display'  => 'ScrapeLock: every minute',
		);
		return $schedules;
	}

	/**
	 * Where the queues live: 'object' (a persistent object cache), 'apcu' (PNCP_Log::apcu_ok()), or '' (neither).
	 *
	 * @return string
	 */
	public static function store() {
		if ( wp_using_ext_object_cache() ) {
			return 'object';
		}
		return PNCP_Log::apcu_ok() ? 'apcu' : '';
	}

	/**
	 * Is this a visitor's request on a site with a persistent store? Then ScrapeLock queues instead of writing, and
	 * reads what it needs from the store. Not in scheduled events, WP-CLI and wp-admin pages (admin-ajax is a
	 * visitor's request: the human check of every visitor goes through it). Filter `pncp_defer_writes`.
	 *
	 * @return bool
	 */
	public static function active() {
		if ( null === self::$active ) {
			$visitor      = ! ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) && ! ( defined( 'WP_CLI' ) && WP_CLI ) && ( ! is_admin() || wp_doing_ajax() );
			self::$active = (bool) apply_filters( 'pncp_defer_writes', $visitor && '' !== self::store() );
		}
		return self::$active;
	}

	/**
	 * Forgets this request's answer of active() (tests, WP-CLI).
	 */
	public static function reset() {
		self::$active = null;
	}

	/**
	 * Registers what writes the rows of a queue.
	 *
	 * @param string        $queue   Queue name (a few letters).
	 * @param callable      $handler Receives the rows, oldest first.
	 * @param callable|null $ready   Optional: false for a row that must wait for a later run (see take()).
	 */
	public static function handle( $queue, $handler, $ready = null ) {
		self::$handlers[ (string) $queue ] = array( $handler, $ready );
	}

	/**
	 * 3.12.9: sends the visitor the end of the response before ScrapeLock's own work at the end of the request (a
	 * row written to the database where no persistent store exists): PHP-FPM's fastcgi_finish_request() or
	 * LiteSpeed's litespeed_finish_request(). Only from shutdown priority 2 on, once WordPress has emptied the
	 * output buffers (wp_ob_end_flush_all() at priority 1, where page caches store the page), and only once.
	 * Filter `pncp_finish_request` (false: never).
	 *
	 * @return bool Whether the response was finished.
	 */
	public static function finish_request() {
		static $done = false;
		if ( $done || ! doing_action( 'shutdown' ) || ( defined( 'WP_CLI' ) && WP_CLI ) || ! (bool) apply_filters( 'pncp_finish_request', true ) ) {
			return $done;
		}
		$fn = function_exists( 'fastcgi_finish_request' ) && 'fpm-fcgi' === PHP_SAPI ? 'fastcgi_finish_request' : ( function_exists( 'litespeed_finish_request' ) ? 'litespeed_finish_request' : '' );
		if ( '' === $fn ) {
			return false;
		}
		while ( ob_get_level() > 0 && @ob_end_flush() ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A buffer that cannot be removed ends the loop.
			continue;
		}
		$done = (bool) call_user_func( $fn );
		return $done;
	}

	/* ---------- APCu without an object cache: ScrapeLock's options and transients ---------- */

	/**
	 * The transients ScrapeLock reads on (nearly) every request.
	 */
	const TRANSIENTS = array( 'pncp_server_outbound', 'pncp_selfcheck_route' );

	/**
	 * How long APCu keeps a copy of an option or transient (a change made in this server's PHP-FPM replaces it at
	 * once; one made from WP-CLI, whose APCu is another, is seen after this).
	 */
	const OPTION_TTL = 300;

	/**
	 * Filter pre_option, in a visitor's request with APCu and no persistent object cache: one of ScrapeLock's
	 * options that is not autoloaded (or not there) comes from a copy in APCu. A missing one is noted as missing
	 * for WordPress (its "notoptions"), so get_option() answers with its default without a query.
	 *
	 * @param mixed  $pre     Value from an earlier filter (false: none).
	 * @param string $option  Option.
	 * @param mixed  $default Default.
	 * @return mixed
	 */
	public static function pre_option( $pre, $option, $default = false ) {
		if ( false !== $pre || 0 !== strpos( (string) $option, 'pncp_' ) ) {
			return $pre;
		}
		$all = wp_load_alloptions();
		if ( isset( $all[ $option ] ) ) {
			return $pre; // Autoloaded: WordPress has it without a query.
		}
		$key  = 'pncp_opt_' . md5( (string) $option );
		$kept = apcu_fetch( PNCP_Log::apcu_key( $key ) );
		if ( ! is_array( $kept ) ) {
			remove_filter( 'pre_option', array( __CLASS__, 'pre_option' ), 10 );
			$none  = new stdClass();
			$value = get_option( $option, $none );
			add_filter( 'pre_option', array( __CLASS__, 'pre_option' ), 10, 3 );
			$kept = $value === $none ? array( 'missing' => true ) : array( 'value' => $value );
			apcu_store( PNCP_Log::apcu_key( $key ), $kept, self::OPTION_TTL );
		}
		if ( ! empty( $kept['missing'] ) ) {
			self::not_there( array( (string) $option ) );
			return false !== $default ? $default : $pre;
		}
		return false === $kept['value'] ? $pre : $kept['value'];
	}

	/**
	 * Filter pre_transient_{name}: the same for the transients ScrapeLock reads on every request (TRANSIENTS).
	 *
	 * @param mixed  $pre       Value from an earlier filter (false: none).
	 * @param string $transient Transient.
	 * @return mixed
	 */
	public static function pre_transient( $pre, $transient ) {
		if ( false !== $pre ) {
			return $pre;
		}
		$key  = 'pncp_tr_' . md5( (string) $transient );
		$kept = apcu_fetch( PNCP_Log::apcu_key( $key ) );
		if ( ! is_array( $kept ) ) {
			remove_filter( 'pre_transient_' . $transient, array( __CLASS__, 'pre_transient' ), 10 );
			$value = get_transient( $transient );
			add_filter( 'pre_transient_' . $transient, array( __CLASS__, 'pre_transient' ), 10, 2 );
			$kept = array( 'value' => $value );
			apcu_store( PNCP_Log::apcu_key( $key ), $kept, MINUTE_IN_SECONDS );
		}
		if ( false === $kept['value'] ) {
			self::not_there( array( '_transient_' . $transient, '_transient_timeout_' . $transient ) );
			return $pre;
		}
		return $kept['value'];
	}

	/**
	 * Notes options as missing for this request (WordPress's "notoptions"): get_option() then needs no query.
	 *
	 * @param string[] $names Options.
	 */
	private static function not_there( $names ) {
		$not = wp_cache_get( 'notoptions', 'options' );
		$not = is_array( $not ) ? $not : array();
		foreach ( $names as $name ) {
			$not[ $name ] = true;
		}
		wp_cache_set( 'notoptions', $not, 'options' );
	}

	/**
	 * An option was added, changed or deleted: its copy in APCu goes.
	 *
	 * @param string $option Option.
	 */
	public static function forget_option( $option ) {
		if ( 0 === strpos( (string) $option, 'pncp_' ) ) {
			apcu_delete( PNCP_Log::apcu_key( 'pncp_opt_' . md5( (string) $option ) ) );
		}
	}

	/**
	 * A transient was set or deleted: its copy in APCu goes.
	 *
	 * @param string $transient Transient.
	 */
	public static function forget_transient( $transient ) {
		if ( in_array( (string) $transient, self::TRANSIENTS, true ) ) {
			apcu_delete( PNCP_Log::apcu_key( 'pncp_tr_' . md5( (string) $transient ) ) );
		}
	}

	/* ---------- The store: the object cache (group "pncp") or APCu ---------- */

	/**
	 * Reads a value from the store (false when there is none, or there is no store).
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	public static function get( $key ) {
		$store = self::store();
		if ( 'object' === $store ) {
			return wp_cache_get( $key, 'pncp' );
		}
		return 'apcu' === $store ? apcu_fetch( PNCP_Log::apcu_key( $key ) ) : false;
	}

	/**
	 * Writes a value to the store.
	 *
	 * @param string $key   Key.
	 * @param mixed  $value Value.
	 * @param int    $ttl   Seconds (0 = as long as the store keeps it).
	 * @return bool
	 */
	public static function set( $key, $value, $ttl = 0 ) {
		$store = self::store();
		if ( 'object' === $store ) {
			return (bool) wp_cache_set( $key, $value, 'pncp', max( 0, (int) $ttl ) );
		}
		return 'apcu' === $store && apcu_store( PNCP_Log::apcu_key( $key ), $value, max( 0, (int) $ttl ) );
	}

	/**
	 * Writes a value only when there is none (atomic): true for the one caller that wrote it. Never waits.
	 *
	 * @param string $key   Key.
	 * @param mixed  $value Value.
	 * @param int    $ttl   Seconds.
	 * @return bool
	 */
	public static function add( $key, $value, $ttl = 0 ) {
		$store = self::store();
		if ( 'object' === $store ) {
			return (bool) wp_cache_add( $key, $value, 'pncp', max( 0, (int) $ttl ) );
		}
		return 'apcu' === $store && apcu_add( PNCP_Log::apcu_key( $key ), $value, max( 0, (int) $ttl ) );
	}

	/**
	 * Adds $step to a counter (created at 0 when there is none) and returns the new count; 0 when it cannot.
	 *
	 * @param string $key  Key.
	 * @param int    $step How much to add.
	 * @param int    $ttl  Seconds, from its creation.
	 * @return int
	 */
	public static function incr( $key, $step = 1, $ttl = 0 ) {
		$store = self::store();
		if ( 'object' === $store ) {
			wp_cache_add( $key, 0, 'pncp', max( 0, (int) $ttl ) );
			return (int) wp_cache_incr( $key, max( 1, (int) $step ), 'pncp' );
		}
		if ( 'apcu' === $store ) {
			$name = PNCP_Log::apcu_key( $key );
			apcu_add( $name, 0, max( 0, (int) $ttl ) );
			return (int) apcu_inc( $name, max( 1, (int) $step ) );
		}
		return 0;
	}

	/**
	 * Deletes a value from the store.
	 *
	 * @param string $key Key.
	 */
	public static function delete( $key ) {
		$store = self::store();
		if ( 'object' === $store ) {
			wp_cache_delete( $key, 'pncp' );
		} elseif ( 'apcu' === $store ) {
			apcu_delete( PNCP_Log::apcu_key( $key ) );
		}
	}

	/* ---------- Queues ---------- */

	/**
	 * Adds a row to a queue: a slot number from an atomic counter, and the row under it. Two or three calls to
	 * the store, no lock, no wait.
	 *
	 * @param string $queue Queue.
	 * @param mixed  $row   Row.
	 * @return bool Whether it was queued (false: no store, or the queue is full).
	 */
	public static function push( $queue, $row ) {
		if ( '' === self::store() ) {
			return false;
		}
		$base = 'pncp_dq_' . $queue;
		$slot = self::incr( $base . '_n', 1, 0 );
		if ( $slot < 1 ) {
			return false;
		}
		if ( $slot - (int) self::get( $base . '_d' ) > self::MAX_QUEUE ) {
			self::incr( $base . '_x', 1, 0 ); // Dropped: shown by pending().
			return false;
		}
		$done = self::set( $base . '_' . $slot, $row, self::TTL );
		if ( $done && 'apcu' === self::store() && defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON && ! has_action( 'shutdown', array( __CLASS__, 'nudge' ) ) ) {
			add_action( 'shutdown', array( __CLASS__, 'nudge' ), 99 );
		}
		return $done;
	}

	/**
	 * The signature of a request to wp-cron.php that writes the queues (nudge()), valid for this minute and the last.
	 *
	 * @param int $minute Minute (Unix time / 60).
	 * @return string
	 */
	private static function signature( $minute ) {
		return substr( hash_hmac( 'sha256', 'pncp_flush|' . (int) $minute . '|' . home_url(), wp_salt( 'nonce' ) ), 0, 32 );
	}

	/**
	 * APCu with DISABLE_WP_CRON: asks wp-cron.php to write the queues (flush_signed()), a request in PHP-FPM that
	 * nobody waits for (as WordPress's own spawn_cron()), at most once a minute.
	 */
	public static function nudge() {
		if ( ! self::add( 'pncp_dq_nudge', 1, MINUTE_IN_SECONDS ) ) {
			return;
		}
		$url = add_query_arg( 'pncp_flush', self::signature( (int) floor( time() / MINUTE_IN_SECONDS ) ), site_url( 'wp-cron.php' ) );
		wp_remote_post(
			$url,
			array(
				'timeout'   => 0.01,
				'blocking'  => false,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress's own filter, as spawn_cron() uses it.
			)
		);
	}

	/**
	 * wp-cron.php asked by nudge(): writes the queues when the signature is this minute's or the last one's.
	 */
	public static function flush_signed() {
		$sig    = isset( $_GET['pncp_flush'] ) ? sanitize_key( wp_unslash( $_GET['pncp_flush'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- The signature is the check.
		$minute = (int) floor( time() / MINUTE_IN_SECONDS );
		if ( hash_equals( self::signature( $minute ), $sig ) || hash_equals( self::signature( $minute - 1 ), $sig ) ) {
			self::flush();
			// The circuit breaker's state lives in this PHP-FPM's APCu too: its copy for WP-CLI, and a reset that
			// WP-CLI asked for, are done here as well when no admin page or WP-Cron event of PHP-FPM comes by.
			PNCP_Breaker_Status::sync();
		}
	}

	/**
	 * How many rows wait in a queue, and how many were dropped since the last run.
	 *
	 * @param string $queue Queue.
	 * @return array{waiting:int, dropped:int}
	 */
	public static function pending( $queue ) {
		$base = 'pncp_dq_' . $queue;
		return array(
			'waiting' => max( 0, (int) self::get( $base . '_n' ) - (int) self::get( $base . '_d' ) ),
			'dropped' => (int) self::get( $base . '_x' ),
		);
	}

	/**
	 * Takes up to $max rows from a queue, oldest first. A slot that is still empty near the end of the queue (a
	 * request that took its number a moment ago and has not written its row yet) ends the batch, once: on the
	 * next run it is skipped (the store lost it).
	 *
	 * @param string        $queue Queue.
	 * @param int           $max   Rows.
	 * @param callable|null $ready Optional: false for a row that must wait for the next run (it ends the batch).
	 * @return array<int, mixed>
	 */
	public static function take( $queue, $max = self::BATCH, $ready = null ) {
		$base = 'pncp_dq_' . $queue;
		$last = (int) self::get( $base . '_n' );
		$done = (int) self::get( $base . '_d' );
		if ( $done > $last ) {
			$done = 0; // The counter was lost (the store was emptied): it starts again at 1.
		}
		$rows  = array();
		$taken = 0;
		$stop  = (int) self::get( $base . '_s' );
		for ( $i = $done + 1; $i <= $last && $taken < $max; $i++ ) {
			$row = self::get( $base . '_' . $i );
			if ( false === $row ) {
				if ( $i > $last - 50 && $stop !== $i ) {
					self::set( $base . '_s', $i, self::TTL );
					break;
				}
				$done = $i; // Lost.
				continue;
			}
			/**
			 * 3.12.9: may this queued row be written now? (A log row waits for the end of its minute.)
			 *
			 * @param bool   $ready Whether it may.
			 * @param string $queue Queue.
			 * @param mixed  $row   Row.
			 */
			if ( ! apply_filters( 'pncp_defer_ready', null === $ready || call_user_func( $ready, $row ), $queue, $row ) ) {
				break;
			}
			$rows[] = $row;
			++$taken;
			self::delete( $base . '_' . $i );
			$done = $i;
		}
		self::set( $base . '_d', $done, 0 );
		self::delete( $base . '_x' );
		return $rows;
	}

	/**
	 * Writes what waits in every queue to the database (the scheduled event, the hourly task, WP-CLI, wp-admin).
	 * One run at a time (an atomic add, never a wait).
	 *
	 * @return int Rows written.
	 */
	public static function flush() {
		if ( '' === self::store() || self::active() ) {
			return 0; // Never in a visitor's request.
		}
		if ( ! self::add( 'pncp_dq_lock', time(), 2 * self::SECONDS + 10 ) ) {
			return 0;
		}
		$written = 0;
		$until   = microtime( true ) + self::SECONDS;
		try {
			/**
			 * 3.12.9: before the queues are written (e.g. the automatic Emergency Mode's state and start).
			 */
			do_action( 'pncp_defer_flush' );
			foreach ( self::$handlers as $queue => $handler ) {
				if ( microtime( true ) > $until ) {
					break;
				}
				$rows = self::take( $queue, self::BATCH, $handler[1] );
				if ( $rows ) {
					call_user_func( $handler[0], $rows );
					$written += count( $rows );
				}
			}
		} finally {
			self::delete( 'pncp_dq_lock' );
		}
		return $written;
	}

	/**
	 * Keeps the one-minute event scheduled while a persistent store exists, and removes it otherwise (from the
	 * hourly task and wp-admin, never from a visitor's request).
	 */
	public static function ensure_cron() {
		if ( self::active() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return; // WP-CLI cannot see PHP-FPM's APCu: it never removes the event.
		}
		$next = wp_next_scheduled( self::CRON );
		if ( '' !== self::store() && ! $next ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, self::SCHEDULE, self::CRON );
		} elseif ( '' === self::store() && $next ) {
			wp_clear_scheduled_hook( self::CRON );
		}
	}

	/**
	 * wp-admin (not admin-ajax): the event is kept scheduled, and the administrator sees what waits in the queues
	 * (the Log, the bans, Traffic) without waiting for the next run.
	 */
	public static function admin() {
		if ( wp_doing_ajax() ) {
			return;
		}
		self::ensure_cron();
		if ( current_user_can( 'manage_options' ) ) {
			self::flush();
		}
	}
}
