<?php
/**
 * 3.12: Traffic. Every request the site answers, from three sources: the Bunny CDN logs (also the pages served
 * from the CDN's cache), the web server's access log, and WordPress itself (the responses PHP serves, at shutdown).
 * Off until the owner turns it on ("traffic"); while off nothing is read, written or scheduled on the request path.
 *
 * Storage (see install()):
 * - {prefix}pncp_traffic: one row per request, kept "traffic_raw_days" whole days (in the site's time zone) plus
 *   today. Rows older than that are not stored at all.
 * - {prefix}pncp_traffic_hour: totals per source and hour.
 * - {prefix}pncp_traffic_day: per source, day and dimension (User-Agent, family, path, referrer, country, status,
 *   IP) the top keys of the day with hits, bytes, errors, cache misses, unique IPs, first and last request.
 * - {prefix}pncp_traffic_err: per source and day the 3xx (not 304), 4xx and 5xx answers by path, status and
 *   referrer (the "problems" over long ranges).
 * The three aggregate tables are kept "traffic_days" days. They are computed from the raw rows by the hourly run
 * (rollup()): each day that received rows is counted again from scratch, so late lines (a Bunny log that arrives
 * later, a server log read after a pause) are never counted twice and the unique IPs of a day are exact. Raw rows
 * of a day are deleted only once the day is older than "traffic_raw_days", so a day is always complete when it is
 * counted. Plain INSERT, DELETE and SELECT only: the same on MySQL / MariaDB and the SQLite drop-in.
 *
 * Reading: PNCP_Traffic_Query (overview, top, problems, detail, raw rows, CSV). A range within the raw window is
 * answered from the raw rows (exact, every filter); a longer one from the aggregates.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Traffic collection: settings, ingestion, storage, the scheduled run and the public API.
 */
final class PNCP_Traffic {

	/**
	 * Option with the schema version of the tables (autoloaded: the WordPress source checks it at shutdown).
	 */
	const DB_OPTION = 'pncp_traffic_db';

	/**
	 * Schema version.
	 */
	const DB_VERSION = 1;

	/**
	 * Option with the run's state: the rollup cursor, the days left to count, the server log cursor and the last
	 * errors (not autoloaded: only the scheduled run and the admin screens read it).
	 */
	const STATE = 'pncp_traffic_state';

	/**
	 * Option bumped when everything is deleted, so cached figures are counted again.
	 */
	const GEN_OPTION = 'pncp_traffic_gen';

	/**
	 * The scheduled run (every 15 minutes while collection is on): reads the server log, counts the aggregates
	 * (hourly) and deletes what is too old (hourly).
	 */
	const CRON = 'pncp_traffic_run';

	/**
	 * The sources.
	 */
	const SOURCES = array( 'bunny', 'server', 'wp' );

	/**
	 * Rows written by one INSERT.
	 */
	const INSERT_BATCH = 500;

	/**
	 * Default most rows one run (one request, one cron run) stores (filter `pncp_traffic_max_rows_per_run`).
	 */
	const MAX_ROWS_PER_RUN = 100000;

	/**
	 * Default most raw rows kept (filter `pncp_traffic_max_raw_rows`): the oldest go first beyond it.
	 */
	const MAX_RAW_ROWS = 1000000;

	/**
	 * Default most keys per source, day and dimension in the aggregates (filter `pncp_traffic_keys_per_day`); the
	 * rest is added up in one "other" row, so the day's totals stay right.
	 */
	const KEYS_PER_DAY = 2000;

	/**
	 * Default most rows per source and day in the problems table (filter `pncp_traffic_errors_per_day`).
	 */
	const ERRORS_PER_DAY = 5000;

	/**
	 * Rows one DELETE of the cleanup removes.
	 */
	const DELETE_BATCH = 5000;

	/**
	 * The key of the "other" row of a dimension (keys beyond KEYS_PER_DAY).
	 */
	const OTHER = '~other';

	/**
	 * A source counts as current ("auto") when it stored a row or ran without an error this recently.
	 */
	const RECENT = 7200;

	/**
	 * Dimensions of the day table.
	 */
	const DIMENSIONS = array( 'ua', 'ua_family', 'path', 'referer', 'country', 'status', 'ip' );

	/**
	 * Rows waiting to be written.
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private static $buffer = array();

	/**
	 * Rows accepted in this request (for the per-run cap).
	 *
	 * @var int
	 */
	private static $run_rows = 0;

	/**
	 * Rows refused in this request: too old, from the future, over the cap.
	 *
	 * @var array{old:int, future:int, cap:int}
	 */
	private static $dropped = array(
		'old'    => 0,
		'future' => 0,
		'cap'    => 0,
	);

	/**
	 * Whether the shutdown writer is attached.
	 *
	 * @var bool
	 */
	private static $hooked = false;

	/**
	 * The raw window's first second (per request).
	 *
	 * @var int|null
	 */
	private static $floor = null;

	/**
	 * best_source() of this request.
	 *
	 * @var string|null
	 */
	private static $source = null;

	/**
	 * The Bunny logs are anonymized (read once per import run).
	 *
	 * @var bool|null
	 */
	private static $bunny_anon = null;

	/**
	 * Registers the hooks. With collection off only the scheduled run (which deletes what is left and then stops)
	 * and the settings hooks are added: no query, no write.
	 */
	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'run' ) );
		add_action( 'update_option_' . PNCP_OPTION, array( __CLASS__, 'settings_changed' ), 30, 2 );
		$s = PNCP_Options::get();
		if ( empty( $s['traffic'] ) ) {
			return;
		}
		add_action( 'admin_init', array( __CLASS__, 'maybe_schedule' ) );
		add_action( 'pncp_bunny_log_line', array( __CLASS__, 'bunny_line' ) );
		add_action( 'pncp_bunny_log_read', array( __CLASS__, 'bunny_read' ) );
		if ( ! empty( $s['traffic_wp'] ) ) {
			add_action( 'shutdown', array( __CLASS__, 'wp_shutdown' ), 5 );
		}
	}

	/* ---------- Settings ---------- */

	/**
	 * Is collection on ("traffic")?
	 *
	 * @return bool
	 */
	public static function enabled() {
		$s = PNCP_Options::get();
		return ! empty( $s['traffic'] );
	}

	/**
	 * The settings of this component, normalized.
	 *
	 * @return array{on:bool, wp:bool, log_path:string, raw_days:int, days:int, ip_mode:string}
	 */
	public static function settings() {
		$s = PNCP_Options::get();
		return array(
			'on'       => ! empty( $s['traffic'] ),
			'wp'       => ! empty( $s['traffic_wp'] ),
			'log_path' => isset( $s['traffic_log_path'] ) ? (string) $s['traffic_log_path'] : '',
			'raw_days' => isset( $s['traffic_raw_days'] ) ? max( 1, min( 14, (int) $s['traffic_raw_days'] ) ) : 3,
			'days'     => isset( $s['traffic_days'] ) ? max( 7, min( 365, (int) $s['traffic_days'] ) ) : 90,
			'ip_mode'  => isset( $s['traffic_ip_mode'] ) && 'masked' === $s['traffic_ip_mode'] ? 'masked' : 'full',
		);
	}

	/**
	 * The settings were saved: collection turned on creates the tables and schedules the run.
	 *
	 * @param mixed $old   Settings before.
	 * @param mixed $value Settings after.
	 */
	public static function settings_changed( $old, $value ) {
		self::$floor  = null;
		self::$source = null;
		if ( is_array( $value ) && ! empty( $value['traffic'] ) ) {
			self::maybe_schedule();
		}
		unset( $old );
	}

	/**
	 * While collection is on: the tables exist and the run is scheduled (wp-admin, settings saved, upgrade). Reads
	 * only the cron option and the schema option, which WordPress has loaded anyway.
	 */
	public static function maybe_schedule() {
		if ( ! self::enabled() ) {
			return;
		}
		if ( ! self::ready() ) {
			self::install();
		}
		if ( ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, self::schedule(), self::CRON );
		}
	}

	/**
	 * The schedule of the run: Bunny's 15 minutes (registered by PNCP_Bunny::init()), else hourly.
	 *
	 * @return string
	 */
	private static function schedule() {
		$schedules = wp_get_schedules();
		return isset( $schedules[ PNCP_Bunny::SCHEDULE ] ) ? PNCP_Bunny::SCHEDULE : 'hourly';
	}

	/* ---------- Tables ---------- */

	/**
	 * A table of this component.
	 *
	 * @param string $which raw | hour | day | err.
	 * @return string
	 */
	public static function table( $which = 'raw' ) {
		global $wpdb;
		$names = array(
			'raw'  => 'pncp_traffic',
			'hour' => 'pncp_traffic_hour',
			'day'  => 'pncp_traffic_day',
			'err'  => 'pncp_traffic_err',
		);
		return $wpdb->prefix . ( isset( $names[ $which ] ) ? $names[ $which ] : $names['raw'] );
	}

	/**
	 * Creates or updates the tables (dbDelta). The long text columns (path, User-Agent) are found through short
	 * hashes, so every index stays small on every database.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$raw     = self::table( 'raw' );
		$hour    = self::table( 'hour' );
		$day     = self::table( 'day' );
		$err     = self::table( 'err' );
		$tables  = array( $raw, $hour, $day, $err );
		if ( false === get_option( self::DB_OPTION, false ) && count( array_filter( array_map( array( __CLASS__, 'table_exists' ), $tables ) ) ) === count( $tables ) ) {
			// The tables of this schema are there but their option is not (an uninstall on a database layer that
			// cannot drop tables, a copy of the database without the options): no dbDelta(), which fails on the
			// composite keys on the SQLite drop-in.
			update_option( self::DB_OPTION, self::DB_VERSION, true );
			return true;
		}
		dbDelta(
			"CREATE TABLE {$raw} (
			id bigint(20) unsigned NOT NULL auto_increment,
			ts int(10) unsigned NOT NULL DEFAULT 0,
			src varchar(8) NOT NULL DEFAULT '',
			ip varchar(45) NOT NULL DEFAULT '',
			country char(2) NOT NULL DEFAULT '',
			method varchar(8) NOT NULL DEFAULT '',
			status smallint(5) unsigned NOT NULL DEFAULT 0,
			path varchar(512) NOT NULL DEFAULT '',
			query varchar(255) NOT NULL DEFAULT '',
			referer varchar(255) NOT NULL DEFAULT '',
			ua varchar(255) NOT NULL DEFAULT '',
			fam varchar(16) NOT NULL DEFAULT '',
			ptype char(1) NOT NULL DEFAULT '',
			ua_hash char(16) NOT NULL DEFAULT '',
			path_hash char(16) NOT NULL DEFAULT '',
			bytes int(10) unsigned NOT NULL DEFAULT 0,
			cache varchar(10) NOT NULL DEFAULT '',
			hit tinyint(3) unsigned NOT NULL DEFAULT 2,
			edge varchar(16) NOT NULL DEFAULT '',
			rt_ms int(10) unsigned DEFAULT NULL,
			PRIMARY KEY  (id),
			KEY src_ts (src,ts),
			KEY status_ts (status,ts),
			KEY ua_ts (ua_hash,ts),
			KEY path_ts (path_hash,ts),
			KEY ip_ts (ip,ts)
			) {$charset};
			CREATE TABLE {$hour} (
			src varchar(8) NOT NULL DEFAULT '',
			hour_ts int(10) unsigned NOT NULL DEFAULT 0,
			hits int(10) unsigned NOT NULL DEFAULT 0,
			s2xx int(10) unsigned NOT NULL DEFAULT 0,
			s3xx int(10) unsigned NOT NULL DEFAULT 0,
			s4xx int(10) unsigned NOT NULL DEFAULT 0,
			s5xx int(10) unsigned NOT NULL DEFAULT 0,
			bytes bigint(20) unsigned NOT NULL DEFAULT 0,
			chits int(10) unsigned NOT NULL DEFAULT 0,
			misses int(10) unsigned NOT NULL DEFAULT 0,
			ips int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (src,hour_ts)
			) {$charset};
			CREATE TABLE {$day} (
			src varchar(8) NOT NULL DEFAULT '',
			dim varchar(10) NOT NULL DEFAULT '',
			day int(10) unsigned NOT NULL DEFAULT 0,
			k char(16) NOT NULL DEFAULT '',
			label varchar(512) NOT NULL DEFAULT '',
			fam varchar(16) NOT NULL DEFAULT '',
			ptype char(1) NOT NULL DEFAULT '',
			hits int(10) unsigned NOT NULL DEFAULT 0,
			bytes bigint(20) unsigned NOT NULL DEFAULT 0,
			s2xx int(10) unsigned NOT NULL DEFAULT 0,
			s3xx int(10) unsigned NOT NULL DEFAULT 0,
			s4xx int(10) unsigned NOT NULL DEFAULT 0,
			s404 int(10) unsigned NOT NULL DEFAULT 0,
			s5xx int(10) unsigned NOT NULL DEFAULT 0,
			chits int(10) unsigned NOT NULL DEFAULT 0,
			misses int(10) unsigned NOT NULL DEFAULT 0,
			ips int(10) unsigned NOT NULL DEFAULT 0,
			rt_sum bigint(20) unsigned NOT NULL DEFAULT 0,
			rt_n int(10) unsigned NOT NULL DEFAULT 0,
			first_ts int(10) unsigned NOT NULL DEFAULT 0,
			last_ts int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (src,dim,day,k),
			KEY dim_k (dim,k,day)
			) {$charset};
			CREATE TABLE {$err} (
			src varchar(8) NOT NULL DEFAULT '',
			day int(10) unsigned NOT NULL DEFAULT 0,
			k char(16) NOT NULL DEFAULT '',
			status smallint(5) unsigned NOT NULL DEFAULT 0,
			rk char(16) NOT NULL DEFAULT '',
			path varchar(512) NOT NULL DEFAULT '',
			referer varchar(255) NOT NULL DEFAULT '',
			ua varchar(255) NOT NULL DEFAULT '',
			hits int(10) unsigned NOT NULL DEFAULT 0,
			ips int(10) unsigned NOT NULL DEFAULT 0,
			last_ts int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (src,day,k,status,rk)
			) {$charset};"
		);
		$ok = true;
		foreach ( $tables as $table ) {
			$ok = $ok && self::table_exists( $table );
		}
		if ( $ok ) {
			update_option( self::DB_OPTION, self::DB_VERSION, true );
		}
		return $ok;
	}

	/**
	 * Does a table exist (compared without regard to case, as MySQL with lower_case_table_names=1 answers)?
	 *
	 * @param string $table Table.
	 * @return bool
	 */
	public static function table_exists( $table ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema check.
		$found = (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( (string) $table ) ) );
		return 0 === strcasecmp( $found, (string) $table );
	}

	/**
	 * The upgrade (pncp_upgrade()): creates the tables when collection is on, or updates them when an older schema
	 * version is stored. Nothing on sites that never turned collection on, and nothing when the schema is current
	 * (dbDelta() on an existing table with a composite key fails on the SQLite drop-in).
	 */
	public static function maybe_install() {
		$stored = PNCP_Options::stored();
		$have   = get_option( self::DB_OPTION, false );
		if ( ( ! empty( $stored['traffic'] ) || false !== $have ) && (int) $have < self::DB_VERSION ) {
			self::install();
		}
	}

	/**
	 * Are the tables there (at the current schema version)?
	 *
	 * @return bool
	 */
	public static function ready() {
		return (int) get_option( self::DB_OPTION, 0 ) >= self::DB_VERSION;
	}

	/* ---------- Time ---------- */

	/**
	 * The start of the site-time-zone day that holds a moment.
	 *
	 * @param int $ts Unix time.
	 * @return int
	 */
	public static function day_start( $ts ) {
		$d = new DateTime( '@' . (int) $ts );
		$d->setTimezone( wp_timezone() );
		$d->setTime( 0, 0, 0 );
		return $d->getTimestamp();
	}

	/**
	 * The start of the next day after the day that starts at $day (23, 24 or 25 hours later).
	 *
	 * @param int $day Start of a day.
	 * @param int $n   Days to move (negative = back).
	 * @return int
	 */
	public static function add_days( $day, $n = 1 ) {
		$d = new DateTime( '@' . (int) $day );
		$d->setTimezone( wp_timezone() );
		$d->setTime( 0, 0, 0 );
		$d->modify( ( $n >= 0 ? '+' : '' ) . (int) $n . ' day' );
		$d->setTime( 0, 0, 0 );
		return $d->getTimestamp();
	}

	/**
	 * The first second of the raw window: the start of the day "traffic_raw_days" days before today. Older rows
	 * are not stored and are deleted.
	 *
	 * @return int
	 */
	public static function raw_floor() {
		if ( null === self::$floor ) {
			self::$floor = self::add_days( self::day_start( time() ), -self::settings()['raw_days'] );
		}
		return self::$floor;
	}

	/**
	 * The first day kept in the aggregates.
	 *
	 * @return int
	 */
	public static function agg_floor() {
		return self::add_days( self::day_start( time() ), -self::settings()['days'] );
	}

	/* ---------- Ingestion ---------- */

	/**
	 * Takes one request into the buffer (written by flush(), at the latest at shutdown). Public for the tests and
	 * for other code that brings lines of its own.
	 *
	 * Accepted fields (all optional except a time and a path or URL): ts (Unix seconds or milliseconds), ip,
	 * country, method, status, path, query, url (path and query are taken from it when missing), referer, ua,
	 * bytes, cache (HIT, MISS…), edge, rt_ms. The IP is used as given (the caller resolved the real visitor IP).
	 *
	 * @param array<string, mixed> $row A request.
	 * @param string               $src bunny | server | wp.
	 * @return bool Whether it was accepted (false: unknown source, older than the raw window, from the future, or
	 *              over the per-run cap).
	 */
	public static function ingest( array $row, $src ) {
		$src = (string) $src;
		if ( ! in_array( $src, self::SOURCES, true ) ) {
			return false;
		}
		$ts = isset( $row['ts'] ) && is_numeric( $row['ts'] ) ? (int) $row['ts'] : time();
		if ( $ts > 100000000000 ) {
			$ts = (int) floor( $ts / 1000 ); // Milliseconds.
		}
		if ( $ts < self::raw_floor() ) {
			++self::$dropped['old'];
			return false;
		}
		if ( $ts > time() + 600 ) {
			++self::$dropped['future'];
			return false;
		}
		/**
		 * Filters the most rows one request (a cron run, an import) stores.
		 *
		 * @since 3.12.0
		 * @param int $rows Rows (default 100,000).
		 */
		$cap = (int) apply_filters( 'pncp_traffic_max_rows_per_run', self::MAX_ROWS_PER_RUN );
		if ( $cap > 0 && self::$run_rows >= $cap ) {
			++self::$dropped['cap'];
			return false;
		}
		$clean = self::clean_row( $row, $src, $ts );
		if ( null === $clean ) {
			return false;
		}
		++self::$run_rows;
		self::$buffer[] = $clean;
		if ( count( self::$buffer ) >= self::INSERT_BATCH ) {
			self::flush();
		} elseif ( ! self::$hooked ) {
			self::$hooked = true;
			add_action( 'shutdown', array( __CLASS__, 'flush' ), 20 );
		}
		return true;
	}

	/**
	 * A request as it is stored, or null when it has neither a path nor a URL.
	 *
	 * @param array<string, mixed> $row Fields (see ingest()).
	 * @param string               $src Source.
	 * @param int                  $ts  Unix time.
	 * @return array<string, mixed>|null
	 */
	private static function clean_row( $row, $src, $ts ) {
		$get   = static function ( $key ) use ( $row ) {
			return isset( $row[ $key ] ) && is_scalar( $row[ $key ] ) ? trim( (string) $row[ $key ] ) : '';
		};
		$path  = $get( 'path' );
		$query = $get( 'query' );
		if ( '' === $path ) {
			$url = $get( 'url' );
			if ( '' === $url ) {
				return null;
			}
			$parts = wp_parse_url( preg_match( '#^[a-z][a-z0-9+.\-]*://#i', $url ) ? $url : 'http://x' . ( '/' === $url[0] ? '' : '/' ) . $url );
			$path  = is_array( $parts ) && isset( $parts['path'] ) ? (string) $parts['path'] : '/';
			if ( '' === $query && is_array( $parts ) && isset( $parts['query'] ) ) {
				$query = (string) $parts['query'];
			}
		}
		$q = strpos( $path, '?' );
		if ( false !== $q ) {
			$query = '' === $query ? (string) substr( $path, $q + 1 ) : $query;
			$path  = (string) substr( $path, 0, $q );
		}
		$path   = self::text( '/' === substr( $path, 0, 1 ) ? $path : '/' . $path, 512 );
		$status = (int) $get( 'status' );
		$status = $status >= 0 && $status <= 999 ? $status : 0;
		$ua     = $get( 'ua' );
		$ua     = '-' === $ua ? '' : self::text( $ua, 255 );
		$ip     = PNCP_Ip::normalize( $get( 'ip' ) );
		$fam    = PNCP_Traffic_Ua::classify( $ua, $ip, 'bunny' === $src && self::bunny_anonymized() );
		if ( '' !== $ip && 'masked' === self::settings()['ip_mode'] ) {
			$ip = self::mask_ip( $ip );
		}
		$cache   = strtoupper( (string) preg_replace( '/[^A-Za-z_]/', '', $get( 'cache' ) ) );
		$cache   = substr( $cache, 0, 10 );
		$country = strtoupper( $get( 'country' ) );
		$method  = strtoupper( (string) preg_replace( '/[^A-Za-z]/', '', $get( 'method' ) ) );
		$bytes   = $get( 'bytes' );
		$rt      = isset( $row['rt_ms'] ) && is_numeric( $row['rt_ms'] ) && $row['rt_ms'] >= 0 ? (int) min( 4294967295, (float) $row['rt_ms'] ) : null;
		return array(
			'ts'        => $ts,
			'src'       => $src,
			'ip'        => $ip,
			'country'   => preg_match( '/^[A-Z]{2}$/', $country ) && 'XX' !== $country ? $country : '',
			'method'    => substr( $method, 0, 8 ),
			'status'    => $status,
			'path'      => $path,
			'query'     => $status >= 400 && '' !== $query ? self::text( $query, 255 ) : '',
			'referer'   => self::clean_referer( $get( 'referer' ) ),
			'ua'        => $ua,
			'fam'       => $fam['family'],
			'ptype'     => self::path_type( $path ),
			'ua_hash'   => self::hash( $ua ),
			'path_hash' => self::hash( $path ),
			'bytes'     => ctype_digit( $bytes ) ? (int) min( 4294967295, (float) $bytes ) : 0,
			'cache'     => $cache,
			'hit'       => self::hit_flag( $cache ),
			'edge'      => self::text( $get( 'edge' ), 16 ),
			'rt_ms'     => $rt,
		);
	}

	/**
	 * Text as stored: without control characters, cut to a number of characters.
	 *
	 * @param string $text Text.
	 * @param int    $max  Characters.
	 * @return string
	 */
	public static function text( $text, $max ) {
		$text = (string) preg_replace( '/[\x00-\x1f\x7f]/', '', (string) $text );
		if ( function_exists( 'mb_substr' ) ) {
			$text = (string) mb_substr( $text, 0, $max, 'UTF-8' );
		} else {
			$text = (string) substr( $text, 0, $max );
		}
		// A cut (or a log line) can leave an invalid UTF-8 sequence, which MySQL would refuse.
		return function_exists( 'wp_check_invalid_utf8' ) ? (string) wp_check_invalid_utf8( $text, true ) : $text;
	}

	/**
	 * The referrer as stored: scheme, host and path only ('' for none, "-" or a value that is not a URL).
	 *
	 * @param string $referer Referrer.
	 * @return string
	 */
	public static function clean_referer( $referer ) {
		$referer = trim( (string) $referer );
		if ( '' === $referer || '-' === $referer ) {
			return '';
		}
		$parts = wp_parse_url( $referer );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}
		$scheme = isset( $parts['scheme'] ) ? strtolower( (string) $parts['scheme'] ) : 'http';
		$scheme = in_array( $scheme, array( 'http', 'https', 'android-app' ), true ) ? $scheme : 'http';
		$path   = isset( $parts['path'] ) ? (string) $parts['path'] : '/';
		return self::text( $scheme . '://' . strtolower( (string) $parts['host'] ) . ( '' === $path ? '/' : $path ), 255 );
	}

	/**
	 * Short hash of a text, for the indexes.
	 *
	 * @param string $text Text.
	 * @return string 16 hex characters.
	 */
	public static function hash( $text ) {
		return substr( md5( (string) $text ), 0, 16 );
	}

	/**
	 * What a path is: p (a page or anything else WordPress answers), s (a static file: image, style, script, font,
	 * media), f (a feed, sitemap or other XML / JSON / text file).
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function path_type( $path ) {
		$path = strtolower( (string) $path );
		if ( preg_match( '#\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|woff2?|ttf|otf|eot|mp4|webm|mov|mp3|ogg|wav|m4a|pdf|zip|gz)$#', $path ) ) {
			return 's';
		}
		if ( preg_match( '#(?:\.(?:xml|json|txt|rss|atom)$|/feed/?$|/wp-json/)#', $path ) ) {
			return 'f';
		}
		return 'p';
	}

	/**
	 * Whether a cache status is a hit (1), a miss (0) or not known (2).
	 *
	 * @param string $cache Cache status.
	 * @return int
	 */
	public static function hit_flag( $cache ) {
		if ( '' === $cache || '-' === $cache ) {
			return 2;
		}
		return in_array( $cache, array( 'HIT', 'STALE', 'UPDATING', 'REVALIDATED' ), true ) ? 1 : 0;
	}

	/**
	 * An IP with the last part hidden ("traffic_ip_mode" = masked): IPv4 /24, IPv6 /48.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function mask_ip( $ip ) {
		$bin = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $bin ) {
			return '';
		}
		if ( 4 === strlen( $bin ) ) {
			$bin = substr( $bin, 0, 3 ) . "\0";
		} else {
			$bin = substr( $bin, 0, 6 ) . str_repeat( "\0", 10 );
		}
		return (string) inet_ntop( $bin );
	}

	/**
	 * Writes the buffer: one multi-row INSERT per INSERT_BATCH rows.
	 *
	 * @return int Rows written.
	 */
	public static function flush() {
		global $wpdb;
		if ( ! self::$buffer ) {
			return 0;
		}
		$rows         = self::$buffer;
		self::$buffer = array();
		if ( ! self::ready() ) {
			return 0;
		}
		$written  = 0;
		$suppress = $wpdb->suppress_errors( true );
		foreach ( array_chunk( $rows, self::INSERT_BATCH ) as $chunk ) {
			$values = array();
			foreach ( $chunk as $r ) {
				$tuple = $wpdb->prepare(
					'(%d, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %d, %s, ',
					$r['ts'],
					$r['src'],
					$r['ip'],
					$r['country'],
					$r['method'],
					$r['status'],
					$r['path'],
					$r['query'],
					$r['referer'],
					$r['ua'],
					$r['fam'],
					$r['ptype'],
					$r['ua_hash'],
					$r['path_hash'],
					$r['bytes'],
					$r['cache'],
					$r['hit'],
					$r['edge']
				);
				$values[] = $tuple . ( null === $r['rt_ms'] ? 'NULL' : (string) (int) $r['rt_ms'] ) . ')';
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Plugin table; each row is prepared above.
			$done = $wpdb->query( $wpdb->prepare( 'INSERT INTO %i (ts, src, ip, country, method, status, path, query, referer, ua, fam, ptype, ua_hash, path_hash, bytes, cache, hit, edge, rt_ms) VALUES ', self::table( 'raw' ) ) . implode( ', ', $values ) );
			if ( false !== $done ) {
				$written += count( $chunk );
			}
		}
		$wpdb->suppress_errors( $suppress );
		return $written;
	}

	/**
	 * Rows refused in this request (too old, from the future, over the per-run cap).
	 *
	 * @return array{old:int, future:int, cap:int}
	 */
	public static function dropped() {
		return self::$dropped;
	}

	/**
	 * Forgets the per-request state (tests; a long WP-CLI run between imports).
	 */
	public static function reset() {
		self::$buffer     = array();
		self::$run_rows   = 0;
		self::$floor      = null;
		self::$bunny_anon = null;
		self::$source     = null;
		self::$dropped    = array(
			'old'    => 0,
			'future' => 0,
			'cap'    => 0,
		);
		PNCP_Traffic_Ua::reset();
	}

	/* ---------- Source: Bunny CDN logs ---------- */

	/**
	 * One parsed line of the Bunny log import (action `pncp_bunny_log_line`, PNCP_Bunny::import()).
	 *
	 * @param mixed $row PNCP_Bunny::parse_line() result.
	 */
	public static function bunny_line( $row ) {
		if ( ! is_array( $row ) ) {
			return;
		}
		self::ingest( $row, 'bunny' );
	}

	/**
	 * The Bunny import read its lines (action `pncp_bunny_log_read`): the rest of the buffer is written.
	 */
	public static function bunny_read() {
		self::flush();
		self::$bunny_anon = null;
	}

	/**
	 * Are the Bunny logs anonymized (IPs ending in .0)? Then no address can verify or unmask a crawler.
	 *
	 * @return bool
	 */
	private static function bunny_anonymized() {
		if ( null === self::$bunny_anon ) {
			self::$bunny_anon = PNCP_Bunny::logs_anonymized();
		}
		return self::$bunny_anon;
	}

	/**
	 * Is the Bunny import on (a pull zone connected, "Import attacks from Bunny CDN's logs" on, protection on)?
	 *
	 * @return bool
	 */
	public static function bunny_on() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && PNCP_Bunny::settings()['import'] && null !== PNCP_Bunny::credentials();
	}

	/* ---------- Source: WordPress ---------- */

	/**
	 * Should this request be recorded by the WordPress source? Not wp-admin (nor admin-ajax), cron, WP-CLI, a
	 * signed-in administrator (the pages and the REST API they open while working on the site), or the site's own
	 * requests to itself (the loopback, or its own address through the CDN: PNCP_Server_Ips).
	 *
	 * @return bool
	 */
	public static function wp_records_request() {
		if ( is_admin() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || empty( $_SERVER['REQUEST_METHOD'] ) ) {
			return false;
		}
		if ( current_user_can( 'manage_options' ) ) {
			return false;
		}
		if ( PNCP_Ip::is_local_request() || PNCP_Server_Ips::is_request() ) {
			return false;
		}
		return true;
	}

	/**
	 * At shutdown: the response WordPress served, as one row (one INSERT).
	 */
	public static function wp_shutdown() {
		if ( ! self::ready() || ! self::wp_records_request() ) {
			return;
		}
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Cut and cleaned by clean_row().
		$parts  = explode( '?', $uri, 2 );
		$status = function_exists( 'http_response_code' ) ? http_response_code() : 200;
		$ip     = PNCP_Ip::client_ip();
		$start  = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) && is_numeric( $_SERVER['REQUEST_TIME_FLOAT'] ) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : 0.0;
		self::ingest(
			array(
				'ts'      => time(),
				'ip'      => $ip,
				'country' => '' !== $ip ? PNCP_Geo::country( $ip ) : '',
				'method'  => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
				'status'  => is_int( $status ) && $status > 0 ? $status : 200,
				'path'    => $parts[0],
				'query'   => isset( $parts[1] ) ? $parts[1] : '',
				'referer' => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
				'ua'      => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
				'bytes'   => 0,
				'rt_ms'   => $start > 0 ? (int) round( ( microtime( true ) - $start ) * 1000 ) : null,
			),
			'wp'
		);
		self::flush();
	}

	/* ---------- The scheduled run ---------- */

	/**
	 * The state of the run, with every field present.
	 *
	 * @return array<string, mixed>
	 */
	public static function state() {
		$s        = get_option( self::STATE, array() );
		$s        = is_array( $s ) ? $s : array();
		$defaults = array(
			'cursor'     => 0,
			'pending'    => array(),
			'rolled_at'  => 0,
			'cleaned_at' => 0,
			'server'     => array(),
		);
		$s        = array_merge( $defaults, array_intersect_key( $s, $defaults ) );
		$s['pending'] = is_array( $s['pending'] ) ? array_values( array_map( 'intval', $s['pending'] ) ) : array();
		$s['server']  = is_array( $s['server'] ) ? $s['server'] : array();
		return $s;
	}

	/**
	 * Saves the state (not autoloaded).
	 *
	 * @param array<string, mixed> $state State.
	 */
	public static function save_state( $state ) {
		if ( false === get_option( self::STATE, false ) ) {
			add_option( self::STATE, $state, '', false );
		} else {
			update_option( self::STATE, $state, false );
		}
	}

	/**
	 * The scheduled run: the server log, then (hourly) the aggregates and the cleanup. With collection off it only
	 * deletes what is too old, and stops being scheduled once nothing is left.
	 */
	public static function run() {
		if ( ! PNCP_Log::cache_add( 'pncp_traffic_lock', time(), 10 * MINUTE_IN_SECONDS ) ) {
			return;
		}
		try {
			if ( ! self::enabled() ) {
				if ( self::ready() ) {
					self::cleanup();
				}
				if ( ! self::ready() || self::is_empty() ) {
					wp_clear_scheduled_hook( self::CRON );
				}
				return;
			}
			if ( ! self::ready() && ! self::install() ) {
				return;
			}
			if ( '' !== self::settings()['log_path'] ) {
				PNCP_Traffic_Log::run( PNCP_Time::deadline( 20 ) );
			}
			self::flush();
			$state = self::state();
			if ( (int) $state['rolled_at'] < time() - 50 * MINUTE_IN_SECONDS || $state['pending'] ) {
				self::rollup( PNCP_Time::deadline( 20 ) );
			}
			$state = self::state();
			if ( (int) $state['cleaned_at'] < time() - 50 * MINUTE_IN_SECONDS ) {
				self::cleanup();
			}
			// The alerts (unusual errors, a new heavy User-Agent, a stopped source), on the counted figures.
			PNCP_Traffic_Alerts::check();
		} finally {
			PNCP_Log::cache_delete( 'pncp_traffic_lock' );
		}
	}

	/**
	 * Are all the tables empty?
	 *
	 * @return bool
	 */
	private static function is_empty() {
		global $wpdb;
		foreach ( array( 'raw', 'hour', 'day', 'err' ) as $which ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
			if ( null !== $wpdb->get_var( $wpdb->prepare( 'SELECT 1 FROM %i LIMIT 1', self::table( $which ) ) ) ) {
				return false;
			}
		}
		return true;
	}

	/* ---------- Aggregates ---------- */

	/**
	 * Counts the aggregates of every day that received rows since the last time (and the days left over then),
	 * from the raw rows, from scratch. Days older than the raw window cannot be counted again and are skipped.
	 *
	 * @param float|null $deadline microtime( true ) to stop at (null = 20 s).
	 * @return int Days counted.
	 */
	public static function rollup( $deadline = null ) {
		global $wpdb;
		if ( ! self::ready() ) {
			return 0;
		}
		$deadline = null === $deadline ? microtime( true ) + 20 : (float) $deadline;
		$state    = self::state();
		$raw      = self::table( 'raw' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$max  = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MAX(id) FROM %i', $raw ) );
		$days = $state['pending'];
		if ( $max < (int) $state['cursor'] ) {
			$state['cursor'] = 0; // The table was emptied (TRUNCATE starts the ids again): every row is new.
		}
		if ( $max > (int) $state['cursor'] ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, range of the primary key.
			$span = $wpdb->get_row( $wpdb->prepare( 'SELECT MIN(ts) AS a, MAX(ts) AS b FROM %i WHERE id > %d AND id <= %d', $raw, (int) $state['cursor'], $max ), ARRAY_A );
			if ( is_array( $span ) && null !== $span['a'] ) {
				$day  = self::day_start( (int) $span['a'] );
				$last = self::day_start( (int) $span['b'] );
				for ( $i = 0; $day <= $last && $i < 400; $i++ ) {
					$days[] = $day;
					$day    = self::add_days( $day );
				}
			}
		}
		$days  = array_values( array_unique( array_map( 'intval', $days ) ) );
		$floor = self::raw_floor();
		sort( $days );
		$done = 0;
		$left = array();
		foreach ( $days as $day ) {
			if ( $day < $floor ) {
				continue; // Its raw rows are gone: the aggregates keep what was counted.
			}
			if ( microtime( true ) >= $deadline ) {
				$left[] = $day;
				continue;
			}
			self::rollup_day( $day );
			++$done;
		}
		$state['cursor']    = $max;
		$state['pending']   = $left;
		$state['rolled_at'] = time();
		self::save_state( $state );
		return $done;
	}

	/**
	 * Counts one day of every source again: its hours, its dimensions and its problems.
	 *
	 * @param int $day Start of the day.
	 */
	public static function rollup_day( $day ) {
		global $wpdb;
		$end      = self::add_days( $day );
		$raw      = self::table( 'raw' );
		$suppress = $wpdb->suppress_errors( true );
		foreach ( self::SOURCES as $src ) {
			// The hours, aligned to the local day (a day of 23 or 25 hours keeps whole hours).
			$hours = self::rows(
				$wpdb->prepare(
					'SELECT ts - ((ts - %d) %% 3600) AS h, COUNT(*) AS hits, ' . self::status_sums() . ', SUM(bytes) AS bytes, SUM(CASE WHEN hit = 1 THEN 1 ELSE 0 END) AS chits, SUM(CASE WHEN hit = 0 THEN 1 ELSE 0 END) AS misses, COUNT(DISTINCT ip) AS ips FROM %i WHERE src = %s AND ts >= %d AND ts < %d GROUP BY h', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Fixed SQL from status_sums().
					$day,
					$raw,
					$src,
					$day,
					$end
				)
			);
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table; the day is counted again.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE src = %s AND hour_ts >= %d AND hour_ts < %d', self::table( 'hour' ), $src, $day, $end ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE src = %s AND day = %d', self::table( 'day' ), $src, $day ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE src = %s AND day = %d', self::table( 'err' ), $src, $day ) );
			if ( ! $hours ) {
				continue;
			}
			$total = array_fill_keys( array( 'hits', 'bytes', 's2xx', 's3xx', 's4xx', 's404', 's5xx', 'chits', 'misses' ), 0 );
			$out   = array();
			foreach ( $hours as $h ) {
				$out[] = $wpdb->prepare( '(%s, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d)', $src, (int) $h['h'], (int) $h['hits'], (int) $h['s2xx'], (int) $h['s3xx'], (int) $h['s4xx'], (int) $h['s5xx'], (int) $h['bytes'], (int) $h['chits'], (int) $h['misses'], (int) $h['ips'] );
				foreach ( $total as $key => $n ) {
					$total[ $key ] = $n + ( isset( $h[ $key ] ) ? (int) $h[ $key ] : 0 );
				}
			}
			self::insert( 'hour', '(src, hour_ts, hits, s2xx, s3xx, s4xx, s5xx, bytes, chits, misses, ips)', $out );
			foreach ( self::DIMENSIONS as $dim ) {
				self::rollup_dimension( $src, $dim, $day, $end, $total );
			}
			self::rollup_errors( $src, $day, $end );
		}
		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * The SQL of the status counts (s2xx, s3xx, s4xx, s404, s5xx).
	 *
	 * @return string
	 */
	public static function status_sums() {
		return 'SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) AS s2xx, SUM(CASE WHEN status >= 300 AND status < 400 THEN 1 ELSE 0 END) AS s3xx, SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) AS s4xx, SUM(CASE WHEN status = 404 THEN 1 ELSE 0 END) AS s404, SUM(CASE WHEN status >= 500 AND status < 600 THEN 1 ELSE 0 END) AS s5xx';
	}

	/**
	 * The raw column (SQL) a dimension groups by.
	 *
	 * @param string $dim Dimension.
	 * @return string
	 */
	public static function dimension_column( $dim ) {
		$columns = array(
			'ua'        => 'ua_hash',
			'ua_family' => 'fam',
			'path'      => 'path_hash',
			'referer'   => 'referer',
			'country'   => 'country',
			'status'    => 'status',
			'ip'        => 'ip',
		);
		return isset( $columns[ $dim ] ) ? $columns[ $dim ] : 'path_hash';
	}

	/**
	 * The raw column (SQL) that holds a dimension's text.
	 *
	 * @param string $dim Dimension.
	 * @return string
	 */
	public static function label_column( $dim ) {
		$columns = array(
			'ua'   => 'ua',
			'path' => 'path',
		);
		return isset( $columns[ $dim ] ) ? $columns[ $dim ] : self::dimension_column( $dim );
	}

	/**
	 * One dimension of one source and day: the KEYS_PER_DAY busiest keys, plus the keys with errors among the
	 * next ones, and one "other" row with the rest (so the day adds up).
	 *
	 * @param string             $src   Source.
	 * @param string             $dim   Dimension.
	 * @param int                $day   Start of the day.
	 * @param int                $end   Start of the next day.
	 * @param array<string, int> $total The day's totals.
	 */
	private static function rollup_dimension( $src, $dim, $day, $end, $total ) {
		global $wpdb;
		/**
		 * Filters the most keys stored per source, day and dimension (User-Agent, path, referrer, country, status,
		 * IP); the rest is added up in one row.
		 *
		 * @since 3.12.0
		 * @param int    $keys Keys (default 2,000).
		 * @param string $dim  Dimension.
		 */
		$cap    = max( 10, (int) apply_filters( 'pncp_traffic_keys_per_day', self::KEYS_PER_DAY, $dim ) );
		$col    = self::dimension_column( $dim );
		$label  = self::label_column( $dim );
		$group  = 'ua' === $dim ? $col . ', fam' : $col;
		$select = 'SELECT ' . $col . ' AS g, MAX(' . $label . ') AS label, MAX(fam) AS fam, MAX(ptype) AS ptype, COUNT(*) AS hits, SUM(bytes) AS bytes, ' . self::status_sums() . ', SUM(CASE WHEN hit = 1 THEN 1 ELSE 0 END) AS chits, SUM(CASE WHEN hit = 0 THEN 1 ELSE 0 END) AS misses, COUNT(DISTINCT ip) AS ips, SUM(rt_ms) AS rt_sum, COUNT(rt_ms) AS rt_n, MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM %i WHERE src = %s AND ts >= %d AND ts < %d GROUP BY ' . $group;
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Fixed column names from dimension_column().
		$rows = self::rows( $wpdb->prepare( $select . ' ORDER BY hits DESC LIMIT %d', self::table( 'raw' ), $src, $day, $end, $cap + 1 ) );
		if ( count( $rows ) > $cap ) {
			$rows = array_slice( $rows, 0, $cap );
			// Rare keys with errors (a 404 path with 3 hits) are kept too, up to half the cap more.
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Fixed column names from dimension_column().
			$extra = self::rows( $wpdb->prepare( $select . ' HAVING SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) > 0 ORDER BY hits DESC LIMIT %d', self::table( 'raw' ), $src, $day, $end, $cap + (int) ( $cap / 2 ) ) );
			$seen  = array();
			foreach ( $rows as $r ) {
				$seen[ (string) $r['g'] . '|' . (string) $r['fam'] ] = true;
			}
			foreach ( $extra as $r ) {
				if ( ! isset( $seen[ (string) $r['g'] . '|' . (string) $r['fam'] ] ) ) {
					$rows[] = $r;
				}
			}
			$other = $total;
			foreach ( $rows as $r ) {
				foreach ( $other as $key => $n ) {
					$other[ $key ] = $n - (int) $r[ $key ];
				}
			}
			if ( $other['hits'] > 0 ) {
				$rows[] = array_merge(
					array_map(
						static function ( $n ) {
							return max( 0, (int) $n );
						},
						$other
					),
					array(
						'g'        => self::OTHER,
						'label'    => '',
						'fam'      => '',
						'ptype'    => '',
						'ips'      => 0,
						'rt_sum'   => 0,
						'rt_n'     => 0,
						'first_ts' => $day,
						'last_ts'  => $end - 1,
					)
				);
			}
		}
		$out = array();
		foreach ( $rows as $r ) {
			$g = (string) $r['g'];
			if ( self::OTHER === $g ) {
				$k = self::OTHER;
			} elseif ( 'ua' === $dim ) {
				$k = self::hash( $g . '|' . (string) $r['fam'] );
			} elseif ( 'path' === $dim ) {
				$k = $g;
			} else {
				$k = self::hash( $g );
			}
			$out[] = $wpdb->prepare(
				'(%s, %s, %d, %s, %s, %s, %s, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d)',
				$src,
				$dim,
				$day,
				$k,
				self::text( (string) $r['label'], 512 ),
				(string) $r['fam'],
				(string) $r['ptype'],
				(int) $r['hits'],
				(int) $r['bytes'],
				(int) $r['s2xx'],
				(int) $r['s3xx'],
				(int) $r['s4xx'],
				(int) $r['s404'],
				(int) $r['s5xx'],
				(int) $r['chits'],
				(int) $r['misses'],
				(int) $r['ips'],
				(int) $r['rt_sum'],
				(int) $r['rt_n'],
				(int) $r['first_ts'],
				(int) $r['last_ts']
			);
		}
		self::insert( 'day', '(src, dim, day, k, label, fam, ptype, hits, bytes, s2xx, s3xx, s4xx, s404, s5xx, chits, misses, ips, rt_sum, rt_n, first_ts, last_ts)', $out );
	}

	/**
	 * The problems of one source and day: 3xx (not 304), 4xx and 5xx answers by path, status and referrer.
	 *
	 * @param string $src Source.
	 * @param int    $day Start of the day.
	 * @param int    $end Start of the next day.
	 */
	private static function rollup_errors( $src, $day, $end ) {
		global $wpdb;
		/**
		 * Filters the most problem rows (path, status, referrer) stored per source and day.
		 *
		 * @since 3.12.0
		 * @param int $rows Rows (default 5,000).
		 */
		$cap  = max( 10, (int) apply_filters( 'pncp_traffic_errors_per_day', self::ERRORS_PER_DAY ) );
		$rows = self::rows( $wpdb->prepare( 'SELECT path_hash AS k, MAX(path) AS path, status, referer, MAX(ua) AS ua, COUNT(*) AS hits, COUNT(DISTINCT ip) AS ips, MAX(ts) AS last_ts FROM %i WHERE src = %s AND ts >= %d AND ts < %d AND status >= 300 AND status <> 304 GROUP BY path_hash, status, referer ORDER BY hits DESC LIMIT %d', self::table( 'raw' ), $src, $day, $end, $cap ) );
		$out  = array();
		foreach ( $rows as $r ) {
			$out[] = $wpdb->prepare( '(%s, %d, %s, %d, %s, %s, %s, %s, %d, %d, %d)', $src, $day, (string) $r['k'], (int) $r['status'], self::hash( (string) $r['referer'] ), self::text( (string) $r['path'], 512 ), (string) $r['referer'], (string) $r['ua'], (int) $r['hits'], (int) $r['ips'], (int) $r['last_ts'] );
		}
		self::insert( 'err', '(src, day, k, status, rk, path, referer, ua, hits, ips, last_ts)', $out );
	}

	/**
	 * Writes prepared value tuples into a table, INSERT_BATCH per statement.
	 *
	 * @param string   $which   Table (see table()).
	 * @param string   $columns Column list.
	 * @param string[] $values  Prepared "(…)" tuples.
	 */
	private static function insert( $which, $columns, $values ) {
		global $wpdb;
		foreach ( array_chunk( $values, self::INSERT_BATCH ) as $chunk ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Plugin table; fixed columns, tuples prepared by the caller.
			$wpdb->query( $wpdb->prepare( 'INSERT INTO %i ', self::table( $which ) ) . $columns . ' VALUES ' . implode( ', ', $chunk ) );
		}
	}

	/**
	 * Runs a read query with errors suppressed (a missing table is "nothing").
	 *
	 * @param string $sql Prepared SQL.
	 * @return array<int, array<string, mixed>>
	 */
	public static function rows( $sql ) {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- Plugin tables; $sql is prepared by the caller.
		$rows = $wpdb->get_results( $sql, ARRAY_A );
		$wpdb->suppress_errors( $suppress );
		return is_array( $rows ) ? $rows : array();
	}

	/* ---------- Cleanup ---------- */

	/**
	 * Deletes raw rows older than the raw window and aggregates older than "traffic_days", in batches, and the
	 * oldest raw rows beyond the cap on raw rows (filter `pncp_traffic_max_raw_rows`).
	 *
	 * @param int $seconds Time budget.
	 * @return array{raw:int, agg:int, cap:int} Rows deleted.
	 */
	public static function cleanup( $seconds = 15 ) {
		global $wpdb;
		$out = array(
			'raw' => 0,
			'agg' => 0,
			'cap' => 0,
		);
		if ( ! self::ready() ) {
			return $out;
		}
		$budget   = microtime( true ) + max( 1, (int) $seconds );
		$suppress = $wpdb->suppress_errors( true );
		$raw      = self::table( 'raw' );
		// Old raw rows, from the lowest id up (rows are written roughly in time order).
		$before = self::raw_floor();
		while ( microtime( true ) < $budget ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, primary key.
			$cut = $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i ORDER BY id LIMIT 1 OFFSET %d', $raw, self::DELETE_BATCH - 1 ) );
			$cut = null === $cut ? PHP_INT_MAX : (int) $cut;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, batched delete on the primary key.
			$n           = (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE id <= %d AND ts < %d', $raw, $cut, $before ) );
			$out['raw'] += max( 0, $n );
			if ( $n < self::DELETE_BATCH || PHP_INT_MAX === $cut ) {
				break;
			}
		}
		// The few rows written out of order (a late log line) that are older still: one sweep per source.
		if ( microtime( true ) < $budget ) {
			foreach ( self::SOURCES as $src ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, (src, ts) index.
				$out['raw'] += max( 0, (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE src = %s AND ts < %d', $raw, $src, $before ) ) );
			}
		}
		// The cap: the oldest rows go first.
		/**
		 * Filters the most raw rows (one per request) kept; beyond it the oldest are deleted.
		 *
		 * @since 3.12.0
		 * @param int $rows Rows (default 1,000,000).
		 */
		$max = (int) apply_filters( 'pncp_traffic_max_raw_rows', self::MAX_RAW_ROWS );
		if ( $max > 0 ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
			$count = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $raw ) );
			while ( $count > $max && microtime( true ) < $budget ) {
				$batch = min( self::DELETE_BATCH * 4, $count - $max );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, primary key.
				$cut = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i ORDER BY id LIMIT 1 OFFSET %d', $raw, $batch - 1 ) );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, batched delete on the primary key.
				$n = (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE id <= %d', $raw, $cut ) );
				if ( $n <= 0 ) {
					break;
				}
				$out['cap'] += $n;
				$count      -= $n;
			}
		}
		// Aggregates.
		$agg = self::agg_floor();
		foreach ( array(
			'hour' => 'hour_ts',
			'day'  => 'day',
			'err'  => 'day',
		) as $which => $column ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table; fixed column name.
			$out['agg'] += max( 0, (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE %i < %d', self::table( $which ), $column, $agg ) ) );
		}
		$wpdb->suppress_errors( $suppress );
		$state               = self::state();
		$state['cleaned_at'] = time();
		self::save_state( $state );
		return $out;
	}

	/**
	 * Deletes everything collected ("Delete collected traffic"). The cursors of the sources stay, so nothing that
	 * was already read is read again.
	 */
	public static function purge_all() {
		global $wpdb;
		if ( self::ready() ) {
			$suppress = $wpdb->suppress_errors( true );
			foreach ( array( 'raw', 'hour', 'day', 'err' ) as $which ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
				$done = $wpdb->query( $wpdb->prepare( 'TRUNCATE TABLE %i', self::table( $which ) ) );
				if ( false === $done ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table; a database without TRUNCATE.
					$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::table( $which ) ) );
				}
			}
			$wpdb->suppress_errors( $suppress );
		}
		self::$buffer       = array();
		$state              = self::state();
		$state['cursor']    = 0;
		$state['pending']   = array();
		$state['rolled_at'] = 0;
		self::save_state( $state );
		update_option( self::GEN_OPTION, (int) get_option( self::GEN_OPTION, 0 ) + 1, false );
	}

	/**
	 * Drops the tables, the options and the event (uninstall).
	 */
	public static function uninstall() {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		foreach ( array( 'raw', 'hour', 'day', 'err' ) as $which ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall.
			$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', self::table( $which ) ) );
			if ( self::table_exists( self::table( $which ) ) ) {
				// A database layer that ignores DROP TABLE (the SQLite drop-in answers "done" and does nothing): at
				// least nothing collected is left.
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Uninstall.
				$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::table( $which ) ) );
			}
		}
		$wpdb->suppress_errors( $suppress );
		delete_option( self::DB_OPTION );
		delete_option( self::STATE );
		delete_option( self::GEN_OPTION );
		PNCP_Traffic_Alerts::uninstall();
		wp_unschedule_hook( self::CRON );
	}

	/* ---------- Sources ---------- */

	/**
	 * The newest row and the rows of today of one source.
	 *
	 * @param string $src Source.
	 * @return array{last:int, today:int}
	 */
	private static function source_counts( $src ) {
		global $wpdb;
		if ( ! self::ready() ) {
			return array(
				'last'  => 0,
				'today' => 0,
			);
		}
		$raw  = self::table( 'raw' );
		$last = self::rows( $wpdb->prepare( 'SELECT MAX(ts) AS t FROM %i WHERE src = %s', $raw, $src ) );
		$day  = self::rows( $wpdb->prepare( 'SELECT COUNT(*) AS n FROM %i WHERE src = %s AND ts >= %d', $raw, $src, self::day_start( time() ) ) );
		return array(
			'last'  => isset( $last[0]['t'] ) ? (int) $last[0]['t'] : 0,
			'today' => isset( $day[0]['n'] ) ? (int) $day[0]['n'] : 0,
		);
	}

	/**
	 * What each source is doing.
	 *
	 * Each source: on (bool: it collects now), last_ingest (Unix time of its newest stored request, 0 = none),
	 * last_run (Unix time it last ran, 0 = unknown), error (a code, '' = none), lines_today (requests stored
	 * since local midnight). Error codes: bunny: not_connected, import_off, logging_off, api_error (message in
	 * error_message); server: not_set and the codes of test_log_path(), read_error; wp: '' only.
	 * Plus "auto" (the source the queries use by default, see best_source()) and "rollup" (when the aggregates
	 * were last counted, and the days still waiting).
	 *
	 * @return array{bunny: array<string, mixed>, server: array<string, mixed>, wp: array<string, mixed>, auto: string, enabled: bool, rollup: array{rolled_at:int, pending:int}}
	 */
	public static function sources_status() {
		$on    = self::enabled();
		$state = self::state();
		$out   = array();

		$bunny_state = PNCP_Bunny::state();
		$counts      = self::source_counts( 'bunny' );
		$error       = '';
		if ( null === PNCP_Bunny::credentials() ) {
			$error = 'not_connected';
		} elseif ( ! self::bunny_on() ) {
			$error = 'import_off';
		} elseif ( isset( $bunny_state['logging']['enabled'] ) && false === $bunny_state['logging']['enabled'] ) {
			$error = 'logging_off';
		} elseif ( '' !== (string) $bunny_state['error'] ) {
			$error = 'api_error';
		}
		$out['bunny'] = array(
			'on'            => $on && self::bunny_on(),
			'last_ingest'   => $counts['last'],
			'last_run'      => (int) $bunny_state['last_run'],
			'error'         => $error,
			'error_message' => 'api_error' === $error ? (string) $bunny_state['error'] : '',
			'lines_today'   => $counts['today'],
			'anonymized'    => PNCP_Bunny::logs_anonymized( $bunny_state ),
		);

		$path   = self::settings()['log_path'];
		$server = $state['server'];
		$counts = self::source_counts( 'server' );
		$out['server'] = array(
			'on'          => $on && '' !== $path,
			'path'        => $path,
			'last_ingest' => $counts['last'],
			'last_run'    => isset( $server['last_run'] ) ? (int) $server['last_run'] : 0,
			'error'       => '' === $path ? 'not_set' : ( isset( $server['error'] ) ? (string) $server['error'] : '' ),
			'lines_today' => $counts['today'],
		);

		$counts    = self::source_counts( 'wp' );
		$out['wp'] = array(
			'on'          => $on && self::settings()['wp'],
			'last_ingest' => $counts['last'],
			'last_run'    => $counts['last'],
			'error'       => '',
			'lines_today' => $counts['today'],
		);
		$out['auto']    = self::best_source( $out );
		$out['enabled'] = $on;
		$out['rollup']  = array(
			'rolled_at' => (int) $state['rolled_at'],
			'pending'   => count( $state['pending'] ),
		);
		return $out;
	}

	/**
	 * The source the queries use by default ("auto"): Bunny when its import is on and recent (its logs also hold
	 * the pages served from the CDN's cache, which the other two never see), else the server log when it is set
	 * and recent, else WordPress when it is on; failing all that, the source with the newest row. Only one source
	 * is ever counted at a time, so a request seen by two sources is never counted twice.
	 *
	 * @param array<string, mixed>|null $status sources_status() (null = work it out).
	 * @return string bunny | server | wp.
	 */
	public static function best_source( $status = null ) {
		if ( null === $status && null !== self::$source ) {
			return self::$source;
		}
		$memo = null === $status;
		if ( $memo ) {
			$status = array();
			$state  = self::state();
			$bunny  = PNCP_Bunny::state();
			foreach ( self::SOURCES as $src ) {
				$status[ $src ] = array( 'last_ingest' => self::source_counts( $src )['last'] );
			}
			$status['bunny']['on']       = self::bunny_on();
			$status['bunny']['last_run'] = (int) $bunny['last_ok'];
			$status['server']['on']      = '' !== self::settings()['log_path'];
			$status['server']['last_run'] = isset( $state['server']['last_ok'] ) ? (int) $state['server']['last_ok'] : 0;
			$status['wp']['on']           = self::settings()['wp'];
		}
		$recent = time() - self::RECENT;
		$pick   = '';
		foreach ( array( 'bunny', 'server' ) as $src ) {
			if ( ! empty( $status[ $src ]['on'] ) && ( (int) $status[ $src ]['last_ingest'] >= $recent || (int) $status[ $src ]['last_run'] >= $recent ) ) {
				$pick = $src;
				break;
			}
		}
		if ( '' === $pick && ! empty( $status['wp']['on'] ) ) {
			$pick = 'wp';
		}
		if ( '' === $pick ) {
			$newest = 0;
			foreach ( self::SOURCES as $src ) {
				if ( (int) $status[ $src ]['last_ingest'] > $newest ) {
					$newest = (int) $status[ $src ]['last_ingest'];
					$pick   = $src;
				}
			}
		}
		$pick = '' === $pick ? 'bunny' : $pick;
		if ( $memo ) {
			self::$source = $pick;
		}
		return $pick;
	}

	/* ---------- Public API (delegates) ---------- */

	/**
	 * Is this a path the server log source may read, and does it read like an access log?
	 *
	 * @param string $path Absolute path.
	 * @return array{code:string, lines:int, parsed:int, sample:array<string, mixed>|null}
	 */
	public static function test_log_path( $path ) {
		return PNCP_Traffic_Log::test_path( $path );
	}

	/**
	 * What a User-Agent is (see PNCP_Traffic_Ua::classify()).
	 *
	 * @param string $ua User-Agent.
	 * @param string $ip IP ('' = by the User-Agent alone: a search engine counts as verified).
	 * @return array{family:string, name:string}
	 */
	public static function classify_ua( $ua, $ip = '' ) {
		return PNCP_Traffic_Ua::classify( $ua, $ip );
	}

	/**
	 * See PNCP_Traffic_Query::overview().
	 *
	 * @param array<string, mixed> $filters Filters.
	 * @return array<string, mixed>
	 */
	public static function overview( $filters = array() ) {
		return PNCP_Traffic_Query::overview( $filters );
	}

	/**
	 * See PNCP_Traffic_Query::top().
	 *
	 * @param string               $dimension ua | ua_family | path | referer | ip | country | status.
	 * @param array<string, mixed> $filters   Filters.
	 * @param int                  $limit     Rows (at most 500).
	 * @param int                  $offset    Rows to skip.
	 * @param string               $order     hits | ips | bytes | s4xx | s5xx | misses | last.
	 * @return array<string, mixed>
	 */
	public static function top( $dimension, $filters = array(), $limit = 50, $offset = 0, $order = 'hits' ) {
		return PNCP_Traffic_Query::top( $dimension, $filters, $limit, $offset, $order );
	}

	/**
	 * See PNCP_Traffic_Query::problems().
	 *
	 * @param string               $type    404 | 5xx | 3xx | uncached | large | slow.
	 * @param array<string, mixed> $filters Filters.
	 * @param int                  $limit   Rows (at most 500).
	 * @param int                  $offset  Rows to skip.
	 * @return array<string, mixed>
	 */
	public static function problems( $type, $filters = array(), $limit = 50, $offset = 0 ) {
		return PNCP_Traffic_Query::problems( $type, $filters, $limit, $offset );
	}

	/**
	 * See PNCP_Traffic_Query::detail().
	 *
	 * @param string               $kind    ua | path | ip.
	 * @param string               $key     The User-Agent, path or IP.
	 * @param array<string, mixed> $filters Filters.
	 * @return array<string, mixed>
	 */
	public static function detail( $kind, $key, $filters = array() ) {
		return PNCP_Traffic_Query::detail( $kind, $key, $filters );
	}

	/**
	 * See PNCP_Traffic_Query::raw().
	 *
	 * @param array<string, mixed> $filters Filters.
	 * @param int                  $limit   Rows (at most 500).
	 * @param int                  $offset  Rows to skip.
	 * @return array<string, mixed>
	 */
	public static function raw( $filters = array(), $limit = 100, $offset = 0 ) {
		return PNCP_Traffic_Query::raw( $filters, $limit, $offset );
	}

	/**
	 * See PNCP_Traffic_Query::export_csv().
	 *
	 * @param array<string, mixed> $filters Filters.
	 * @param resource             $handle  Stream to write to (php://output, a file).
	 * @return int Rows written.
	 */
	public static function export_csv( $filters, $handle ) {
		return PNCP_Traffic_Query::export_csv( $filters, $handle );
	}
}
