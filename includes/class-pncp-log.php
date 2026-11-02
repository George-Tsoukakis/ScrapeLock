<?php
/**
 * Block log (table {prefix}pncp_log) and temporary IP bans.
 *
 * The log stores IP and User-Agent, i.e. personal data: it is deleted automatically after 1, 7 or 30 days.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Logging and bans.
 */
final class PNCP_Log {

	/**
	 * Table schema version. 3 (3.4.0): index (created, reason) for the summaries of the Log tab.
	 */
	const DB_VERSION = '3';

	/**
	 * The lowest schema version whose tables can be used as they are: 2 has both tables and every column the
	 * code writes. A site that runs the new code before its tables were upgraded (the upgrade runs on the next
	 * request, or on the next admin page) keeps logging and blocking meanwhile.
	 */
	const DB_USABLE = 2;

	/**
	 * How many old log rows one DELETE removes. A single DELETE of a few million rows locks the table for
	 * minutes; batches keep every lock short.
	 */
	const DELETE_BATCH = 5000;

	/**
	 * Option with the time of the last log cleanup (autoloaded, read on admin pages).
	 */
	const CLEANED_OPTION = 'pncp_log_cleaned';

	/**
	 * Option with the latest expiry of any ban ever stored, as a 10-digit number (autoloaded). When it lies in
	 * the past no ban can be in effect, and is_banned() answers without a database query.
	 */
	const BANS_UNTIL_OPTION = 'pncp_bans_until';

	/**
	 * How long the summaries of the Log tab and the Dashboard widget are kept before they are counted again.
	 */
	const AGGREGATE_TTL = 300;

	/**
	 * Option where 2.1 kept the bans (moved to the table on upgrade).
	 */
	const BANS_OPTION = 'pncp_bans';

	/**
	 * How many bans are shown on the settings page (the table keeps all of them).
	 */
	const MAX_BANS = 500;

	/**
	 * The status code stored for a "would block" entry of "Monitor only" (PNCP_Options::monitoring()): the
	 * request was let through. A real block always has 403 or 429, so no new column is needed.
	 */
	const MONITOR_CODE = 0;

	/**
	 * Whether this request already has its "would block" entry. The early check, the pre-cache check and the
	 * normal check may all judge the same request; when they let it through, it is logged once.
	 *
	 * @var bool
	 */
	private static $monitored = false;

	/**
	 * Per-request cache of is_banned.
	 *
	 * @var array<string, bool>
	 */
	private static $banned = array();

	/**
	 * Cron hook for the cleanup.
	 */
	const CRON = 'pncp_log_cleanup';

	/**
	 * Attaches the hooks.
	 */
	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'cleanup' ) );
		add_action( self::CRON . '_more', array( __CLASS__, 'cleanup' ) );
		add_action( 'admin_init', array( __CLASS__, 'privacy_policy' ) );
		add_action( 'admin_init', array( __CLASS__, 'admin_maintenance' ) );
	}

	/**
	 * Are the tables there and usable? (Every read and write of the log and the bans checks this first.)
	 *
	 * @return bool
	 */
	public static function ready() {
		return (int) get_option( 'pncp_db_version', 0 ) >= self::DB_USABLE;
	}

	/**
	 * On admin pages: upgrades the tables if the plugin's upgrade has not done it yet, and deletes old log
	 * entries when the hourly task has not run for 2 hours. WP-Cron only runs when the site has visitors (or
	 * not at all, with DISABLE_WP_CRON and no real cron job), and log entries kept longer than the retention
	 * period are personal data kept longer than the privacy policy says.
	 */
	public static function admin_maintenance() {
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return; // Not in admin-ajax: the human check of every visitor goes through it.
		}
		$version = (int) get_option( 'pncp_db_version', 0 );
		if ( $version < (int) self::DB_VERSION && ! get_transient( 'pncp_db_install_tried' ) ) {
			// At most once an hour, in case the database user cannot create or alter tables.
			set_transient( 'pncp_db_install_tried', 1, HOUR_IN_SECONDS );
			self::install();
		}
		$last = (int) get_option( self::CLEANED_OPTION, 0 );
		if ( $last < time() - 2 * HOUR_IN_SECONDS ) {
			// Saved first: two admin pages opened at the same moment do not both run it.
			update_option( self::CLEANED_OPTION, time(), true );
			self::cleanup( 5 );
		}
	}

	/**
	 * The table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'pncp_log';
	}

	/**
	 * The bans table. One row per IP, with an atomic INSERT … ON DUPLICATE KEY UPDATE: 2.1
	 * kept them in an option that was rewritten in full, and with 1500 concurrent bans
	 * only ~150 were kept (confirmed in a load test).
	 *
	 * @return string
	 */
	public static function bans_table() {
		global $wpdb;
		return $wpdb->prefix . 'pncp_bans';
	}

	/**
	 * Creates or updates the table.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created datetime NOT NULL,
			ip varchar(45) NOT NULL DEFAULT '',
			reason varchar(20) NOT NULL DEFAULT '',
			code smallint(5) unsigned NOT NULL DEFAULT 0,
			hits int(10) unsigned NOT NULL DEFAULT 1,
			path varchar(255) NOT NULL DEFAULT '',
			ua varchar(255) NOT NULL DEFAULT '',
			uas smallint(5) unsigned NOT NULL DEFAULT 1,
			PRIMARY KEY  (id),
			KEY created (created),
			KEY ip (ip),
			KEY created_reason (created,reason)
			) {$charset};"
		);
		$bans = self::bans_table();
		dbDelta(
			"CREATE TABLE {$bans} (
			ip varchar(45) NOT NULL,
			until_ts int(10) unsigned NOT NULL DEFAULT 0,
			since_ts int(10) unsigned NOT NULL DEFAULT 0,
			reason varchar(20) NOT NULL DEFAULT '',
			PRIMARY KEY  (ip),
			KEY until_ts (until_ts)
			) {$charset};"
		);
		// Only if the tables were actually created (e.g. the database user may lack CREATE).
		foreach ( array( $table, $bans ) as $name ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema check on install.
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $name ) ) ) !== $name ) {
				return;
			}
		}
		update_option( 'pncp_db_version', self::DB_VERSION, true ); // Autoloaded: read on every request by is_banned().
		// The latest ban expiry, for the quick "no ban in effect" answer of is_banned(). Taken from the table, so
		// bans stored before this version count too.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Once, on install / upgrade.
		self::raise_bans_until( (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MAX(until_ts) FROM %i', $bans ) ) );
		// Since 2.6.2: the number of different User-Agents of a grouped event. Only used when the column exists
		// (a database that could not add it keeps logging as before).
		// A plain SELECT works on every database (SHOW COLUMNS does not, e.g. on SQLite).
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema check on install.
		$has_uas = false !== $wpdb->query( $wpdb->prepare( 'SELECT uas FROM %i LIMIT 1', $table ) );
		$wpdb->suppress_errors( $suppress );
		update_option( 'pncp_log_uas', $has_uas ? 1 : 0, true );

		// 2.1 bans (option) → table.
		$old = get_option( self::BANS_OPTION );
		if ( is_array( $old ) ) {
			foreach ( $old as $ip => $ban ) {
				if ( is_array( $ban ) && isset( $ban['until'] ) && (int) $ban['until'] > time() && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					self::store_ban( PNCP_Ip::limit_key( (string) $ip ), (int) $ban['until'], isset( $ban['reason'] ) ? (string) $ban['reason'] : 'ban', isset( $ban['since'] ) ? (int) $ban['since'] : time() );
				}
			}
		}
		delete_option( self::BANS_OPTION );
	}

	/**
	 * The ban reasons with their descriptions.
	 *
	 * @return array<string, string>
	 */
	public static function reasons() {
		return array(
			'bot_ua'          => __( 'User-Agent in the bot list', 'scrapelock' ),
			'empty_ua'        => __( 'No User-Agent', 'scrapelock' ),
			'fake_crawler'    => __( 'Fake search engine', 'scrapelock' ),
			'fake_ai_bot'     => __( 'Fake AI search bot', 'scrapelock' ),
			'no_browser'      => __( 'No browser headers', 'scrapelock' ),
			'headless'        => __( 'Headless browser', 'scrapelock' ),
			'fake_browser'    => __( 'Fake browser', 'scrapelock' ),
			// The limits are named after their settings ("Pages per minute", "Searches per minute"…).
			'rate_page'       => __( 'Pages per minute', 'scrapelock' ),
			'rate_prefetch'   => __( 'Prefetches per minute', 'scrapelock' ),
			'rate_page56'     => __( 'Pages per minute for the IPv6 network (/56)', 'scrapelock' ),
			'rate_datacenter' => __( 'Pages per minute from data centers', 'scrapelock' ),
			'rate_search'     => __( 'Searches per minute', 'scrapelock' ),
			'rate_rest'       => __( 'REST / GraphQL requests per minute', 'scrapelock' ),
			'rate_sitemap'    => __( 'Sitemaps per minute', 'scrapelock' ),
			'rate_unverified' => __( 'Pages per minute without the human check', 'scrapelock' ),
			'country'         => __( 'Blocked country', 'scrapelock' ),
			'rate_country'    => __( 'Pages per minute for the stricter countries', 'scrapelock' ),
			'rate_404'        => __( '“Page not found” (404) per minute', 'scrapelock' ),
			'blocked_ip'      => __( 'IP in the always-blocked list', 'scrapelock' ),
			'blocked_ref'     => __( 'Referrer in the always-blocked list', 'scrapelock' ),
			'trap'            => __( 'Bot trap', 'scrapelock' ),
			'ban'             => __( 'New temporary block', 'scrapelock' ),
			'manual'          => __( 'Blocked by hand', 'scrapelock' ),
			'banned'          => __( 'Request from a blocked IP', 'scrapelock' ),
			'feed_denied'     => __( 'Private URL without token', 'scrapelock' ),
			'not_via_cdn'     => __( 'Not through the CDN (straight to the server)', 'scrapelock' ),
		);
	}

	/**
	 * The request URI as the browser sent it, percent-encoded, as the pre-cache check also logs it.
	 * sanitize_text_field() is not used: it removes "%ce%ac" and the like, so a Greek address such as
	 * /άρθρο-8/ was logged as /-8/ (2.8.2 and earlier). Any byte outside printable ASCII is encoded.
	 *
	 * @return string
	 */
	public static function request_uri() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Every byte outside printable ASCII is percent-encoded below; the value is escaped on output.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		return (string) preg_replace_callback(
			'/[^\x21-\x7E]/',
			static function ( $m ) {
				return rawurlencode( $m[0] );
			},
			$uri
		);
	}

	/**
	 * A logged path, readable: /%ce%ac%cf%81… is shown as /άρ…. Invalid UTF-8 stays encoded.
	 *
	 * @param string $path Logged path.
	 * @return string
	 */
	public static function display_path( $path ) {
		$decoded = rawurldecode( (string) $path );
		return wp_check_invalid_utf8( $decoded ) === $decoded && ! preg_match( '/[\x00-\x1F\x7F]/', $decoded ) ? $decoded : (string) $path;
	}

	/**
	 * Logs an event. Same IP and reason within the same minute become one row with a counter,
	 * so that a persistent bot does not fill up the database.
	 *
	 * A "would block" entry of "Monitor only" has the code MONITOR_CODE, and is written once per request (the
	 * pre-cache check marks the requests it has already logged).
	 *
	 * An attack from thousands of addresses would still add one row per address, reason and minute. So each
	 * minute only a limited number of new rows is written (filter `pncp_log_rows_per_minute`, default 300);
	 * beyond that the events of that minute are added up in one row per reason, with no IP ("Many IPs").
	 * New temporary blocks are always logged on their own: the list of persistent IPs counts them.
	 *
	 * @param string $reason Reason (key of reasons()).
	 * @param int    $code   HTTP status code (MONITOR_CODE = would have been blocked, let through).
	 * @param string $ip     IP.
	 */
	public static function add( $reason, $code, $ip ) {
		global $wpdb;
		if ( ! self::ready() ) {
			return;
		}
		if ( self::MONITOR_CODE === (int) $code ) {
			if ( self::$monitored || ( class_exists( 'PNCP_Precheck_Runtime', false ) && property_exists( 'PNCP_Precheck_Runtime', 'monitored' ) && PNCP_Precheck_Runtime::$monitored ) ) {
				return;
			}
			self::$monitored = true;
		}

		// The code is part of the key: a "would block" entry and a real block are never counted in the same row.
		$minute = (int) floor( time() / MINUTE_IN_SECONDS );
		$key    = 'pncp_lg_' . md5( $ip . '|' . $reason . '|' . (int) $code . '|' . $minute );
		$id     = (int) self::cache_get( $key );
		$ua     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( $id <= 0 && 'ban' !== $reason && 'manual' !== $reason && self::rows_this_minute( $minute ) >= self::rows_per_minute() ) {
			// Over the budget: this minute's row of the reason (and code) for "Many IPs".
			$ip  = '';
			$ua  = '';
			$key = 'pncp_lo_' . md5( $reason . '|' . (int) $code . '|' . $minute );
			$id  = (int) self::cache_get( $key );
			if ( $id > 0 ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Counter, no cache.
				$wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = hits + 1 WHERE id = %d', self::table(), $id ) );
				return;
			}
		} elseif ( $id <= 0 ) {
			self::count_row( $minute );
		}
		if ( $id > 0 ) {
			// The row keeps the first User-Agent and counts how many different ones there were (bots that rotate it).
			$seen = self::uas_column() ? self::cache_get( $key . '_u' ) : false;
			if ( is_array( $seen ) && count( $seen ) < 50 && ! in_array( md5( $ua ), $seen, true ) ) {
				$seen[] = md5( $ua );
				self::cache_set( $key . '_u', $seen, 2 * MINUTE_IN_SECONDS );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Counter, no cache.
				$wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = hits + 1, uas = uas + 1 WHERE id = %d', self::table(), $id ) );
				return;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Counter, no cache.
			$wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = hits + 1 WHERE id = %d', self::table(), $id ) );
			return;
		}

		$path = '' !== $ip ? (string) wp_parse_url( self::request_uri(), PHP_URL_PATH ) : '';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->insert(
			self::table(),
			array(
				'created' => gmdate( 'Y-m-d H:i:s' ),
				'ip'      => substr( $ip, 0, 45 ),
				'reason'  => substr( $reason, 0, 20 ),
				'code'    => (int) $code,
				'hits'    => 1,
				'path'    => mb_substr( $path, 0, 255 ),
				'ua'      => mb_substr( $ua, 0, 255 ),
			),
			array( '%s', '%s', '%s', '%d', '%d', '%s', '%s' )
		);
		if ( $wpdb->insert_id ) {
			self::cache_set( $key, (int) $wpdb->insert_id, 2 * MINUTE_IN_SECONDS );
			if ( '' !== $ip && self::uas_column() ) {
				self::cache_set( $key . '_u', array( md5( $ua ) ), 2 * MINUTE_IN_SECONDS );
			}
		}
	}

	/**
	 * How many new log rows may be written per minute before events are added up per reason.
	 *
	 * @return int
	 */
	public static function rows_per_minute() {
		return max( 10, (int) apply_filters( 'pncp_log_rows_per_minute', 300 ) );
	}

	/**
	 * How many new rows add() wrote in this minute. Counted in the object cache or APCu where there is one;
	 * otherwise the rows of the minute are counted in the table itself (one query on the "created" index,
	 * with no write, so a counter does not add to the load it is meant to limit).
	 *
	 * @param int $minute Minute (Unix time / 60).
	 * @return int
	 */
	private static function rows_this_minute( $minute ) {
		global $wpdb;
		$key = 'pncp_lr_' . $minute;
		if ( wp_using_ext_object_cache() ) {
			return (int) wp_cache_get( $key, 'pncp' );
		}
		if ( self::apcu_ok() ) {
			return (int) apcu_fetch( self::apcu_key( $key ) );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bounded count on an index; caching it would defeat its purpose.
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE created >= %s', self::table(), gmdate( 'Y-m-d H:i:s', $minute * MINUTE_IN_SECONDS ) ) );
	}

	/**
	 * Counts a new row of this minute (object cache or APCu; the table counts itself otherwise).
	 *
	 * @param int $minute Minute (Unix time / 60).
	 */
	private static function count_row( $minute ) {
		$key = 'pncp_lr_' . $minute;
		if ( wp_using_ext_object_cache() ) {
			wp_cache_add( $key, 0, 'pncp', 2 * MINUTE_IN_SECONDS );
			wp_cache_incr( $key, 1, 'pncp' );
		} elseif ( self::apcu_ok() ) {
			apcu_add( self::apcu_key( $key ), 0, 2 * MINUTE_IN_SECONDS );
			apcu_inc( self::apcu_key( $key ) );
		}
	}

	/**
	 * Does the log table have the "uas" column (different User-Agents of a grouped event)?
	 *
	 * @return bool
	 */
	public static function uas_column() {
		return 1 === (int) get_option( 'pncp_log_uas', 0 );
	}

	/**
	 * Stores an event that happened elsewhere (the pre-cache check), with its own time, path and User-Agent.
	 *
	 * @param array{time:int, code:int, reason:string, ip:string, path:string, ua:string, hits:int, uas?:int} $row Event.
	 */
	public static function insert( $row ) {
		global $wpdb;
		if ( ! self::ready() ) {
			return;
		}
		$data    = array(
			'created' => gmdate( 'Y-m-d H:i:s', (int) $row['time'] ),
			'ip'      => substr( (string) $row['ip'], 0, 45 ),
			'reason'  => substr( (string) $row['reason'], 0, 20 ),
			'code'    => (int) $row['code'],
			'hits'    => max( 1, (int) $row['hits'] ),
			'path'    => mb_substr( (string) $row['path'], 0, 255 ),
			'ua'      => mb_substr( (string) $row['ua'], 0, 255 ),
		);
		$formats = array( '%s', '%s', '%s', '%d', '%d', '%s', '%s' );
		if ( self::uas_column() ) {
			$data['uas'] = max( 1, min( 65535, isset( $row['uas'] ) ? (int) $row['uas'] : 1 ) );
			$formats[]   = '%d';
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->insert( self::table(), $data, $formats );
	}

	/**
	 * Deletes everything older than the retention period and the expired bans.
	 *
	 * The old log rows go in batches of DELETE_BATCH, so the table is never locked for long, until none are
	 * left or the time is up (what is left goes on the next run).
	 *
	 * @param int $seconds Time budget in seconds (default 20; the hourly task passes nothing).
	 */
	public static function cleanup( $seconds = 20 ) {
		global $wpdb;
		$days   = max( 1, (int) PNCP_Options::stored()['log_retention'] );
		$before = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		$budget = microtime( true ) + max( 1, is_numeric( $seconds ) ? (int) $seconds : 20 );
		if ( self::ready() ) {
			do {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, batched delete.
				$deleted = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created < %s LIMIT %d', self::table(), $before, self::DELETE_BATCH ) );
				if ( false === $deleted ) {
					// A database without DELETE … LIMIT: one DELETE, as before 3.4.
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
					$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created < %s', self::table(), $before ) );
					break;
				}
				// A full batch means there may be more. A database that ignores the LIMIT deletes them all at once,
				// which is more than a batch, and the loop ends.
			} while ( self::DELETE_BATCH === (int) $deleted && microtime( true ) < $budget );
			if ( false !== $deleted && self::DELETE_BATCH === (int) $deleted && ! wp_next_scheduled( self::CRON . '_more' ) ) {
				// The time ran out with old rows still there: the rest in a minute, not in an hour.
				wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::CRON . '_more' );
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE until_ts < %d', self::bans_table(), time() ) );
		}
		self::purge_expired_transients();
		update_option( self::CLEANED_OPTION, time(), true );
	}

	/**
	 * Deletes the plugin's expired transients (rate-limit counters per IP and minute, violations). WordPress
	 * deletes them once a day; an attack from thousands of IPs piles up thousands of rows, so here it runs hourly.
	 */
	public static function purge_expired_transients() {
		global $wpdb;
		if ( wp_using_ext_object_cache() ) {
			return;
		}
		$suppress = $wpdb->suppress_errors( true ); // MySQL syntax; on another database it simply does nothing (WordPress does it once a day).
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Bulk cleanup, like WordPress's delete_expired_transients().
		$wpdb->query(
			$wpdb->prepare(
				"DELETE a, b FROM {$wpdb->options} a, {$wpdb->options} b
				WHERE a.option_name LIKE %s
				AND a.option_name NOT LIKE %s
				AND b.option_name = CONCAT( '_transient_timeout_', SUBSTRING( a.option_name, 12 ) )
				AND b.option_value < %d",
				$wpdb->esc_like( '_transient_pncp_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_' ) . '%',
				time()
			)
		);
		// phpcs:enable
		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * Deletes the whole log.
	 */
	public static function clear() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::table() ) );
		self::flush_aggregates();
	}

	/**
	 * The latest entries.
	 *
	 * @param int    $limit Count.
	 * @param string $which all | blocked | monitor (see codes()).
	 * @return array<int, array<string, mixed>>
	 */
	public static function recent( $limit = 100, $which = 'all' ) {
		global $wpdb;
		if ( ! self::ready() ) {
			return array();
		}
		list( $min, $max ) = self::codes( $which );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Admin screen.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE code >= %d AND code <= %d ORDER BY id DESC LIMIT %d', self::table(), $min, $max, max( 1, (int) $limit ) ), ARRAY_A );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * The range of status codes for a view of the log: "blocked" (real blocks, 403 / 429 and the like),
	 * "monitor" (the "would block" entries of "Monitor only") or "all".
	 *
	 * @param string $which all | blocked | monitor.
	 * @return int[] [lowest, highest].
	 */
	public static function codes( $which ) {
		if ( 'monitor' === $which ) {
			return array( self::MONITOR_CODE, self::MONITOR_CODE );
		}
		return array( 'blocked' === $which ? self::MONITOR_CODE + 1 : self::MONITOR_CODE, 65535 );
	}

	/**
	 * Is a log row a "would block" entry of "Monitor only"?
	 *
	 * @param array<string, mixed> $row Row.
	 * @return bool
	 */
	public static function is_monitor_row( $row ) {
		return isset( $row['code'] ) && self::MONITOR_CODE === (int) $row['code'];
	}

	/**
	 * Summary of a period: totals per reason, top IPs and User-Agents.
	 *
	 * @param int    $hours Hours back.
	 * @param string $which blocked (default: real blocks only) | monitor ("would block") | all.
	 * @return array<string, mixed>
	 */
	public static function summary( $hours = 24, $which = 'blocked' ) {
		global $wpdb;
		$empty = array(
			'total'      => 0,
			'reasons'    => array(),
			'ips'        => array(),
			'uas'        => array(),
			'ua_reasons' => array(),
		);
		if ( ! self::ready() ) {
			return $empty;
		}
		$since             = gmdate( 'Y-m-d H:i:s', time() - (int) $hours * HOUR_IN_SECONDS );
		$table             = self::table();
		list( $min, $max ) = self::codes( $which );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Admin screen / widget.
		$reasons = $wpdb->get_results( $wpdb->prepare( 'SELECT reason, SUM(hits) AS n FROM %i WHERE created >= %s AND code >= %d AND code <= %d GROUP BY reason ORDER BY n DESC', $table, $since, $min, $max ), ARRAY_A );
		$ips     = $wpdb->get_results( $wpdb->prepare( "SELECT ip, SUM(hits) AS n FROM %i WHERE created >= %s AND code >= %d AND code <= %d AND ip <> '' GROUP BY ip ORDER BY n DESC LIMIT 10", $table, $since, $min, $max ), ARRAY_A );
		$uas     = $wpdb->get_results( $wpdb->prepare( "SELECT ua, SUM(hits) AS n FROM %i WHERE created >= %s AND code >= %d AND code <= %d AND ua <> '' GROUP BY ua ORDER BY n DESC LIMIT 10", $table, $since, $min, $max ), ARRAY_A );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		$out = $empty;
		foreach ( (array) $reasons as $row ) {
			$out['reasons'][ $row['reason'] ] = (int) $row['n'];
			$out['total']                    += (int) $row['n'];
		}
		foreach ( (array) $ips as $row ) {
			$out['ips'][ $row['ip'] ] = (int) $row['n'];
		}
		foreach ( (array) $uas as $row ) {
			$out['uas'][ $row['ua'] ] = (int) $row['n'];
		}
		// Why each of the top User-Agents was blocked (e.g. a "Googlebot" that was a fake one).
		if ( $out['uas'] ) {
			$list = implode( ', ', array_fill( 0, count( $out['uas'] ), '%s' ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Admin screen; $list holds only %s placeholders, one per value.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT ua, reason, SUM(hits) AS n FROM %i WHERE created >= %s AND code >= %d AND code <= %d AND ua IN ($list) GROUP BY ua, reason ORDER BY n DESC", array_merge( array( $table, $since, $min, $max ), array_keys( $out['uas'] ) ) ), ARRAY_A );
			foreach ( (array) $rows as $row ) {
				$out['ua_reasons'][ $row['ua'] ][ $row['reason'] ] = (int) $row['n'];
			}
		}
		return $out;
	}

	/**
	 * The number of blocked requests of a period: one SUM, kept for 5 minutes (the Dashboard widget shows only
	 * this, and summary() runs four grouped queries).
	 *
	 * @param int    $hours Hours back.
	 * @param string $which blocked (default) | monitor | all, as in summary().
	 * @return int
	 */
	public static function total( $hours = 24, $which = 'blocked' ) {
		$hours = max( 1, (int) $hours );
		$which = (string) $which;
		return (int) self::aggregate(
			'total_' . $which,
			$hours,
			static function () use ( $hours, $which ) {
				global $wpdb;
				if ( ! self::ready() ) {
					return 0;
				}
				list( $min, $max ) = self::codes( $which );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Cached by aggregate().
				return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT SUM(hits) FROM %i WHERE created >= %s AND code >= %d AND code <= %d', self::table(), gmdate( 'Y-m-d H:i:s', time() - $hours * HOUR_IN_SECONDS ), $min, $max ) );
			}
		)['value'];
	}

	/**
	 * A summary of the log, counted at most once every 5 minutes. The Log tab runs several grouped queries over
	 * up to 7 days of rows (COUNT(DISTINCT ip) among them): on a large log that is seconds of database work on
	 * every visit. The "Refresh" button of the Log tab counts again (flush_aggregates()).
	 *
	 * @param string   $what  Name (summary, top_paths, repeat_offenders, total).
	 * @param int      $hours Period in hours.
	 * @param callable $count Counts it when there is no fresh copy.
	 * @return array{value: mixed, time: int} The figures and when they were counted.
	 */
	public static function aggregate( $what, $hours, $count ) {
		$generation = (string) self::cache_get( 'pncp_agg_gen' );
		// The content addresses setting changes how top_paths() groups the paths: a new setting counts again.
		$key    = 'pncp_agg_' . md5( $what . '|' . (int) $hours . '|' . $generation . '|' . PNCP_Options::stored()['content_paths'] );
		$cached = self::cache_get( $key );
		if ( is_array( $cached ) && isset( $cached['time'] ) && array_key_exists( 'value', $cached ) && (int) $cached['time'] > time() - self::AGGREGATE_TTL ) {
			return $cached;
		}
		$out = array(
			'value' => call_user_func( $count ),
			'time'  => time(),
		);
		self::cache_set( $key, $out, self::AGGREGATE_TTL );
		return $out;
	}

	/**
	 * Forgets the cached summaries: the next view counts them again.
	 */
	public static function flush_aggregates() {
		self::cache_set( 'pncp_agg_gen', uniqid( '', true ), DAY_IN_SECONDS );
	}

	/**
	 * The summary(), cached for 5 minutes (see aggregate()).
	 *
	 * @param int    $hours Hours back.
	 * @param string $which blocked (default) | monitor | all, as in summary().
	 * @return array{value: array<string, mixed>, time: int}
	 */
	public static function summary_cached( $hours = 24, $which = 'blocked' ) {
		$hours = max( 1, (int) $hours );
		$which = (string) $which;
		return self::aggregate(
			'summary_' . $which,
			$hours,
			static function () use ( $hours, $which ) {
				return self::summary( $hours, $which );
			}
		);
	}

	/**
	 * The top_paths(), cached for 5 minutes (see aggregate()).
	 *
	 * @param int    $hours Period in hours.
	 * @param string $which blocked (default) | monitor | all, as in summary().
	 * @return array{value: array<string, array<int, array{path:string, hits:int, ips:int}>>, time: int}
	 */
	public static function top_paths_cached( $hours = 24, $which = 'blocked' ) {
		$hours = max( 1, (int) $hours );
		$which = (string) $which;
		return self::aggregate(
			'top_paths_' . $which,
			$hours,
			static function () use ( $hours, $which ) {
				return self::top_paths( $hours, 10, $which );
			}
		);
	}

	/**
	 * The repeat_offenders() with its defaults, cached for 5 minutes (see aggregate()).
	 *
	 * @return array{value: array<int, array{ip:string, bans:int, total:int, last:string, reason:string}>, time: int}
	 */
	public static function repeat_offenders_cached() {
		return self::aggregate(
			'repeat_offenders',
			168,
			static function () {
				return self::repeat_offenders();
			}
		);
	}

	/**
	 * The paths blocked most often: what scrapers try to copy (content) and what scanners look for (files).
	 * Three groups: "content" (addresses that exist on the site: what scrapers were after), "unknown" (addresses
	 * that do not exist: random strings and guesses) and "probes" (files and admin paths: scanners).
	 *
	 * @param int    $hours Period in hours.
	 * @param int    $limit Rows per group.
	 * @param string $which blocked (default) | monitor | all, as in summary().
	 * @return array{content: array<int, array{path:string, hits:int, ips:int}>, unknown: array<int, array{path:string, hits:int, ips:int}>, probes: array<int, array{path:string, hits:int, ips:int}>}
	 */
	public static function top_paths( $hours = 24, $limit = 10, $which = 'blocked' ) {
		global $wpdb;
		$out = array(
			'content' => array(),
			'unknown' => array(),
			'probes'  => array(),
		);
		if ( ! self::ready() ) {
			return $out;
		}
		$since             = gmdate( 'Y-m-d H:i:s', time() - (int) $hours * HOUR_IN_SECONDS );
		list( $min, $max ) = self::codes( $which );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Admin screen.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT path, SUM(hits) AS n, COUNT(DISTINCT ip) AS ips FROM %i WHERE created >= %s AND code >= %d AND code <= %d AND path <> '' GROUP BY path ORDER BY n DESC LIMIT 300", self::table(), $since, $min, $max ), ARRAY_A );
		foreach ( (array) $rows as $row ) {
			if ( self::is_probe_path( (string) $row['path'] ) ) {
				$group = 'probes';
			} else {
				// Checked only while there is room in the groups: each check may look up the address on the site.
				if ( count( $out['content'] ) >= $limit && count( $out['unknown'] ) >= $limit ) {
					continue;
				}
				$group = self::is_site_content( (string) $row['path'] ) ? 'content' : 'unknown';
			}
			if ( count( $out[ $group ] ) < $limit ) {
				$out[ $group ][] = array(
					'path' => (string) $row['path'],
					'hits' => (int) $row['n'],
					'ips'  => (int) $row['ips'],
				);
			}
		}
		return $out;
	}

	/**
	 * Persistent IPs: temporarily blocked again and again, or blocked many times without ever getting a temporary
	 * block (e.g. a User-Agent in the bot list is refused on every request but never "violates" a limit).
	 * Candidates for the always-blocked list.
	 *
	 * @param int $hours    Period in hours.
	 * @param int $min      Minimum number of temporary blocks.
	 * @param int $requests Minimum number of blocked requests (filter `pncp_persistent_requests`, default 100).
	 * @param int $limit    Rows.
	 * @return array<int, array{ip:string, bans:int, total:int, last:string, reason:string}>
	 */
	public static function repeat_offenders( $hours = 168, $min = 2, $requests = 0, $limit = 20 ) {
		global $wpdb;
		if ( ! self::ready() ) {
			return array();
		}
		$requests = $requests > 0 ? (int) $requests : max( 1, (int) apply_filters( 'pncp_persistent_requests', 100 ) );
		$since    = gmdate( 'Y-m-d H:i:s', time() - (int) $hours * HOUR_IN_SECONDS );
		$table    = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Admin screen.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT ip, SUM(CASE WHEN reason = 'ban' THEN hits ELSE 0 END) AS bans, SUM(hits) AS total, MAX(created) AS last FROM %i WHERE created >= %s AND code > %d AND ip <> '' GROUP BY ip HAVING SUM(CASE WHEN reason = 'ban' THEN hits ELSE 0 END) >= %d OR SUM(hits) >= %d ORDER BY total DESC LIMIT %d", $table, $since, self::MONITOR_CODE, max( 1, (int) $min ), $requests, max( 1, (int) $limit ) ), ARRAY_A );
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$out[ (string) $row['ip'] ] = array(
				'ip'     => (string) $row['ip'],
				'bans'   => (int) $row['bans'],
				'total'  => (int) $row['total'],
				'last'   => (string) $row['last'],
				'reason' => '',
			);
		}
		if ( $out ) {
			// The main reason of each IP (not counting the "new temporary block" events).
			$list = implode( ', ', array_fill( 0, count( $out ), '%s' ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Admin screen; $list holds only %s placeholders, one per value.
			$reasons = $wpdb->get_results( $wpdb->prepare( "SELECT ip, reason, SUM(hits) AS n FROM %i WHERE created >= %s AND code > %d AND reason <> 'ban' AND ip IN ($list) GROUP BY ip, reason ORDER BY n DESC", array_merge( array( $table, $since, self::MONITOR_CODE ), array_keys( $out ) ) ), ARRAY_A );
			foreach ( (array) $reasons as $row ) {
				if ( isset( $out[ $row['ip'] ] ) && '' === $out[ $row['ip'] ]['reason'] ) {
					$out[ $row['ip'] ]['reason'] = (string) $row['reason'];
				}
			}
		}
		return array_values( $out );
	}

	/**
	 * A path that looks for files or admin areas (scanners), not for content.
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	public static function is_probe_path( $path ) {
		$path = strtolower( $path );
		if ( preg_match( '#(?:^|/)(?:wp-sitemap[a-z0-9_-]*|sitemap(?:_index)?|[a-z0-9_-]+-sitemap[0-9]*)\.xml$#', $path ) || 0 === strpos( $path, '/wp-json/' ) ) {
			return false; // Sitemaps and the REST API lead to content.
		}
		// The site's own GraphQL endpoint (WPGraphQL) is content; any other GraphQL path is a scanner.
		if ( preg_match( '#(?:^|/)graphql(?:/|$)#', $path ) ) {
			return ! ( class_exists( 'WPGraphQL', false ) && '/graphql' === untrailingslashit( $path ) );
		}
		// Private keys, credentials and common admin / login panels of other software, unless the site has a
		// page at that address (e.g. its own /login/ page).
		if ( preg_match( '#(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|authorized_keys|known_hosts|credentials|secrets?|passwd|shadow|htpasswd|login|signin|sign-in|admin|administrator|user/login|phpmyadmin|pma|adminer|manager/html|actuator|server-status|server-info|solr|jenkins|owa|ecp|autodiscover|boaform|hnap1|telescope|_profiler|debug|console|api/v[0-9]+|v[0-9]+/api)(?:/|$)#', $path ) ) {
			return ! self::is_site_page( $path );
		}
		return (bool) preg_match( '#\.(?:php\d?|env|ini|conf|cfg|config|json|ya?ml|xml|sql|bak|old|orig|swp|zip|tar|gz|rar|7z|log|txt|tfvars|map|mjs|js|asp|aspx|jsp|cgi|sh|py|rb|pl)$|/\.|/@|\.\.|^/(?:wp-admin|wp-includes|wp-content/(?:plugins|themes|uploads)|cgi-bin|vendor|node_modules|cp-[0-9a-f]{10})(?:/|$)#', $path );
	}

	/**
	 * Does the address exist on the site? The home page, posts, pages, products and attachments, their
	 * pagination / feeds, date archives, post type archives, category / tag / other term archives, author
	 * archives, sitemaps and the REST API. Cached for 6 hours (admin screen only).
	 *
	 * @param string $path Logged path (the full request path).
	 * @return bool
	 */
	public static function is_site_content( $path ) {
		static $seen = array();
		$path        = '/' . ltrim( (string) $path, '/' );
		$key         = 'pncp_pc_' . md5( $path . '|' . PNCP_Options::stored()['content_paths'] ); // A new prefix asks again.
		if ( isset( $seen[ $key ] ) ) {
			return $seen[ $key ];
		}
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			$seen[ $key ] = 'yes' === $cached;
			return $seen[ $key ];
		}
		$found        = self::find_site_content( $path );
		$seen[ $key ] = $found;
		set_transient( $key, $found ? 'yes' : 'no', 6 * HOUR_IN_SECONDS );
		return $found;
	}

	/**
	 * The actual check of is_site_content().
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	private static function find_site_content( $path ) {
		$lower = strtolower( $path );
		if ( preg_match( '#(?:^|/)(?:wp-sitemap[a-z0-9_-]*|sitemap(?:_index)?|[a-z0-9_-]+-sitemap[0-9]*)\.xml$#', $lower ) || false !== strpos( $lower, '/wp-json/' ) ) {
			return true;
		}
		$rel = PNCP_Private_Urls::relative_path( $path );
		// Pagination, feeds, AMP and embeds of an address count as the address itself.
		$rel = (string) preg_replace( '#/(?:page/[0-9]+|feed(?:/(?:rss2?|atom|rdf))?|amp|embed|comment-page-[0-9]+)/?$#i', '/', $rel );
		if ( '/' === $rel || '' === trim( $rel, '/' ) ) {
			return true;
		}
		if ( self::is_site_page( $path ) || self::is_site_page( (string) wp_parse_url( home_url( $rel ), PHP_URL_PATH ) ) ) {
			return true;
		}
		foreach ( self::content_paths() as $prefix ) {
			if ( 0 === stripos( trailingslashit( $rel ), trailingslashit( $prefix ) ) ) {
				return true;
			}
		}
		if ( self::is_plugin_route( $rel ) ) {
			return true;
		}
		if ( preg_match( '#^/[0-9]{4}(?:/[0-9]{2}(?:/[0-9]{2})?)?/?$#', $rel ) ) {
			return true; // Date archive.
		}
		$parts = array_values( array_filter( explode( '/', trim( $rel, '/' ) ), 'strlen' ) );
		$last  = (string) end( $parts );
		foreach ( get_post_types( array( 'public' => true ), 'objects' ) as $type ) {
			$link = $type->has_archive ? get_post_type_archive_link( $type->name ) : '';
			if ( $link && trailingslashit( PNCP_Private_Urls::relative_path( (string) wp_parse_url( $link, PHP_URL_PATH ) ) ) === trailingslashit( $rel ) ) {
				return true;
			}
		}
		foreach ( get_taxonomies( array( 'public' => true ), 'objects' ) as $taxonomy ) {
			$slug = ! empty( $taxonomy->rewrite['slug'] ) ? trim( (string) $taxonomy->rewrite['slug'], '/' ) : '';
			if ( '' !== $slug && 0 === stripos( ltrim( $rel, '/' ), $slug . '/' ) && get_term_by( 'slug', sanitize_title( $last ), $taxonomy->name ) ) {
				return true;
			}
		}
		if ( 2 === count( $parts ) && 'author' === strtolower( $parts[0] ) && get_user_by( 'slug', $last ) ) {
			return true;
		}
		return false;
	}

	/**
	 * The "Content addresses" setting: path prefixes of content that WordPress itself does not know, e.g. the
	 * pages of a community or forum plugin (/hub/space/).
	 *
	 * @return string[] E.g. /hub/space.
	 */
	public static function content_paths() {
		$out = array();
		foreach ( PNCP_Options::parse_list( PNCP_Options::stored()['content_paths'] ) as $entry ) {
			$path = (string) wp_parse_url( $entry, PHP_URL_PATH ); // A full address is accepted too.
			$path = '/' . trim( PNCP_Private_Urls::relative_path( '' !== $path ? $path : $entry ), '/' );
			if ( '/' !== $path ) {
				$out[] = $path;
			}
		}
		return (array) apply_filters( 'pncp_content_paths', $out );
	}

	/**
	 * Is the path a route of another plugin? The first rewrite rule that matches decides, as in WordPress: a rule
	 * with only its own query variables (e.g. index.php?fcom_route=…) belongs to a plugin that shows content
	 * WordPress cannot find by itself. Rules for posts, pages, terms and authors were already checked.
	 *
	 * @param string $rel Path within the site.
	 * @return bool
	 */
	private static function is_plugin_route( $rel ) {
		global $wp_rewrite;
		if ( ! $wp_rewrite instanceof WP_Rewrite || ! $wp_rewrite->using_permalinks() ) {
			return false;
		}
		$rules = $wp_rewrite->wp_rewrite_rules();
		if ( ! is_array( $rules ) || ! $rules ) {
			return false;
		}
		$request = trim( $rel, '/' );
		$decoded = rawurldecode( $request );
		foreach ( $rules as $match => $query ) {
			if ( ! preg_match( '#^' . $match . '#', $request ) && ! preg_match( '#^' . $match . '#', $decoded ) ) {
				continue;
			}
			preg_match_all( '/[?&]([^=&]+)=/', (string) $query, $vars );
			$vars = array_diff( $vars[1], array( 'paged', 'page', 'feed', 'cpage', 'embed' ) );
			return $vars && ! array_intersect( $vars, self::core_query_vars() );
		}
		return false;
	}

	/**
	 * The query variables of WordPress itself and of the post types and taxonomies.
	 *
	 * @return string[]
	 */
	private static function core_query_vars() {
		static $vars = null;
		if ( null === $vars ) {
			$wp   = new WP(); // A fresh object: its lists do not include what plugins add with the query_vars filter.
			$vars = array_merge( $wp->public_query_vars, $wp->private_query_vars, array( 'rest_route', 'sitemap', 'sitemap-subtype', 'sitemap-stylesheet', 'favicon' ) );
			foreach ( get_post_types( array(), 'objects' ) as $type ) {
				if ( is_string( $type->query_var ) && '' !== $type->query_var ) {
					$vars[] = $type->query_var;
				}
			}
			foreach ( get_taxonomies( array(), 'objects' ) as $taxonomy ) {
				if ( is_string( $taxonomy->query_var ) && '' !== $taxonomy->query_var ) {
					$vars[] = $taxonomy->query_var;
				}
			}
		}
		return $vars;
	}

	/**
	 * Is there a post or page of the site at this path? (Only for paths that look like probes, on the admin screen.)
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	private static function is_site_page( $path ) {
		if ( ! function_exists( 'url_to_postid' ) ) {
			return false;
		}
		// The logged path is the full request path (with the folder of a site in a subfolder): it goes after
		// the scheme, host and port of the site address.
		$home   = untrailingslashit( home_url( '/' ) );
		$folder = untrailingslashit( (string) wp_parse_url( $home . '/', PHP_URL_PATH ) );
		$origin = '' !== $folder ? substr( $home, 0, -strlen( $folder ) ) : $home;
		return url_to_postid( $origin . $path ) > 0;
	}

	/* ---------- Bans ---------- */

	/**
	 * Is the IP banned? Runs on every request, so it avoids the database where it can: when no ban can be in
	 * effect (the latest expiry ever stored has passed) the answer is known without a query; otherwise the
	 * object cache or APCu keeps the answer per IP, and only then one query on the PRIMARY KEY.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_banned( $ip ) {
		global $wpdb;
		if ( '' === $ip || ! self::ready() ) {
			return false;
		}
		// Bans are stored per ban key (IPv6: the /64, like the limits and strikes), so a client cannot dodge
		// a ban by moving to another address in the same /64.
		$bankey = PNCP_Ip::limit_key( $ip );
		if ( isset( self::$banned[ $bankey ] ) ) {
			return self::$banned[ $bankey ];
		}
		// No ban stored by anyone can still be in effect. (Missing on a site whose tables were not upgraded yet:
		// then the table is asked.) Not with an object cache: there the per-IP answer below is just as cheap, and a
		// copy of the settings kept in the cache could be older than the database.
		if ( ! wp_using_ext_object_cache() ) {
			$latest = get_option( self::BANS_UNTIL_OPTION, false );
			if ( false !== $latest && (int) $latest <= time() ) {
				self::$banned[ $bankey ] = false;
				return false;
			}
		}
		$key = 'pncp_ban_' . md5( $bankey );
		if ( wp_using_ext_object_cache() ) {
			$until = wp_cache_get( $key, 'pncp' );
			if ( false !== $until ) {
				self::$banned[ $bankey ] = (int) $until > time();
				return self::$banned[ $bankey ];
			}
		} elseif ( self::apcu_ok() ) {
			$found = false;
			$until = apcu_fetch( self::apcu_key( $key ), $found );
			if ( $found ) {
				self::$banned[ $bankey ] = (int) $until > time();
				return self::$banned[ $bankey ];
			}
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table; the cache is above.
		$until = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT until_ts FROM %i WHERE ip = %s', self::bans_table(), $bankey ) );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $until, 'pncp', $until > time() ? $until - time() : 5 * MINUTE_IN_SECONDS );
		} elseif ( self::apcu_ok() ) {
			// At most a minute: APCu belongs to one server, and a ban or an unblock made on another server of the
			// same site reaches this one only through the table.
			apcu_store( self::apcu_key( $key ), $until, self::apcu_ban_ttl( $until ) );
		}
		self::$banned[ $bankey ] = $until > time();
		return self::$banned[ $bankey ];
	}

	/**
	 * How long APCu keeps a ban answer: a minute, or less when the ban ends sooner.
	 *
	 * @param int $until Ban expiry (0 = not banned).
	 * @return int Seconds.
	 */
	private static function apcu_ban_ttl( $until ) {
		return $until > time() ? max( 1, min( MINUTE_IN_SECONDS, $until - time() ) ) : MINUTE_IN_SECONDS;
	}

	/**
	 * Raises the latest ban expiry (BANS_UNTIL_OPTION) to $until if that is later. Atomic, so two bans stored
	 * at the same moment cannot leave the earlier expiry behind: the value is a 10-digit number, so comparing
	 * it as text is comparing it as a number, on any database. It is never lowered (an unblock leaves it, and
	 * it simply passes).
	 *
	 * @param int $until Ban expiry.
	 */
	private static function raise_bans_until( $until ) {
		global $wpdb;
		$until = max( 0, min( 9999999999, (int) $until ) );
		$value = sprintf( '%010d', $until );
		if ( add_option( self::BANS_UNTIL_OPTION, $value, '', true ) ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Atomic compare-and-raise; the options API cannot do it.
		$changed = $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value < %s", $value, self::BANS_UNTIL_OPTION, $value ) );
		if ( $changed ) {
			wp_cache_delete( self::BANS_UNTIL_OPTION, 'options' );
			$all = wp_cache_get( 'alloptions', 'options' );
			if ( is_array( $all ) && isset( $all[ self::BANS_UNTIL_OPTION ] ) ) {
				$all[ self::BANS_UNTIL_OPTION ] = $value;
				wp_cache_set( 'alloptions', $all, 'options' );
			}
		}
	}

	/**
	 * Forgets the request's ban cache (in long-running processes, e.g. WP-CLI and tests).
	 */
	public static function reset_cache() {
		self::$banned = array();
	}

	/**
	 * Bans the IP for a number of minutes.
	 *
	 * @param string $ip      IP.
	 * @param int    $minutes Minutes.
	 * @param string $reason  Reason (key of reasons()).
	 */
	public static function ban( $ip, $minutes, $reason ) {
		// Never the Google / Bing IPs, whoever tried to "trap" them, and never the CDN edge that stands in for
		// the visitors (a ban on a Cloudflare edge would block every visitor behind it).
		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) || PNCP_Bots::is_official_crawler_ip( $ip ) || PNCP_Ip::is_cdn_edge( $ip ) ) {
			return;
		}
		$until = time() + max( 1, (int) $minutes ) * MINUTE_IN_SECONDS;
		// Stored under the ban key (IPv6: the /64); the log entry keeps the exact IP that tripped it.
		self::store_ban( PNCP_Ip::limit_key( $ip ), $until, $reason, time() );
		self::add( 'ban', 403, $ip );
	}

	/**
	 * Writes (or renews) a ban, atomically.
	 *
	 * @param string $ip     IP.
	 * @param int    $until  Expiry.
	 * @param string $reason Reason.
	 * @param int    $since  Since when.
	 */
	private static function store_ban( $ip, $until, $reason, $since ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Atomic write to the plugin table.
		$ok = $wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (ip, until_ts, since_ts, reason) VALUES (%s, %d, %d, %s) ON DUPLICATE KEY UPDATE since_ts = IF(until_ts <= UNIX_TIMESTAMP(), VALUES(since_ts), since_ts), until_ts = GREATEST(until_ts, VALUES(until_ts)), reason = VALUES(reason)',
				self::bans_table(),
				$ip,
				$until,
				$since,
				substr( (string) $reason, 0, 20 )
			)
		);
		if ( false === $ok ) {
			// Database without ON DUPLICATE KEY / GREATEST (e.g. SQLite): REPLACE.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
			$wpdb->replace(
				self::bans_table(),
				array(
					'ip'       => $ip,
					'until_ts' => $until,
					'since_ts' => $since,
					'reason'   => substr( (string) $reason, 0, 20 ),
				),
				array( '%s', '%d', '%d', '%s' )
			);
		}
		self::raise_bans_until( $until );
		self::$banned[ $ip ] = true;
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( 'pncp_ban_' . md5( $ip ), $until, 'pncp', max( 1, $until - time() ) );
		} elseif ( self::apcu_ok() ) {
			apcu_store( self::apcu_key( 'pncp_ban_' . md5( $ip ) ), $until, self::apcu_ban_ttl( $until ) );
		}
		PNCP_Precheck::mirror_ban( $ip, $until );
		/**
		 * A ban was added or renewed (blocking at the CDN follows it).
		 *
		 * @param string $ip    Ban key (IPv6: the /64).
		 * @param int    $until Expiry.
		 */
		do_action( 'pncp_bans_changed', $ip, $until );
	}

	/**
	 * A ban decided by the pre-cache check: stored like the others, so that it shows under "Blocked IPs"
	 * and can be lifted there. Expired ones are skipped.
	 *
	 * @param string $ip     IP.
	 * @param int    $until  Expiry.
	 * @param string $reason Reason.
	 * @param int    $since  Since when.
	 */
	public static function import_ban( $ip, $until, $reason, $since ) {
		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) || $until <= time() || PNCP_Bots::is_official_crawler_ip( $ip ) ) {
			return;
		}
		self::store_ban( PNCP_Ip::limit_key( $ip ), (int) $until, $reason, (int) $since );
	}

	/**
	 * Lifts the ban on an IP.
	 *
	 * @param string $ip IP, or the ban key as stored (IPv6: e.g. 2001:db8:1:2::/64).
	 */
	public static function unban( $ip ) {
		global $wpdb;
		// An IPv6 address is banned under its /64 (see ban()): lift that, not the exact address.
		$ip = false === strpos( (string) $ip, '/' ) ? PNCP_Ip::limit_key( (string) $ip ) : (string) $ip;
		self::cache_delete( 'pncp_st_' . md5( PNCP_Ip::limit_key( $ip ) ) );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_delete( 'pncp_ban_' . md5( $ip ), 'pncp' );
		} elseif ( self::apcu_ok() ) {
			apcu_delete( self::apcu_key( 'pncp_ban_' . md5( $ip ) ) );
		}
		unset( self::$banned[ $ip ] );
		PNCP_Precheck::forget_ban( $ip );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->delete( self::bans_table(), array( 'ip' => $ip ), array( '%s' ) );
		/** This action is documented in includes/class-pncp-log.php */
		do_action( 'pncp_bans_changed', $ip, 0 );
	}

	/**
	 * Lifts all bans.
	 */
	public static function unban_all() {
		global $wpdb;
		foreach ( array_keys( self::active_bans( 0 ) ) as $ip ) {
			self::cache_delete( 'pncp_st_' . md5( PNCP_Ip::limit_key( (string) $ip ) ) );
			if ( wp_using_ext_object_cache() ) {
				wp_cache_delete( 'pncp_ban_' . md5( (string) $ip ), 'pncp' );
			} elseif ( self::apcu_ok() ) {
				apcu_delete( self::apcu_key( 'pncp_ban_' . md5( (string) $ip ) ) );
			}
		}
		self::$banned = array();
		PNCP_Precheck::forget_all_bans();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::bans_table() ) );
		/** This action is documented in includes/class-pncp-log.php */
		do_action( 'pncp_bans_changed', '', 0 );
	}

	/**
	 * The active bans, most recent first.
	 *
	 * @param int $limit Maximum count (0 = all).
	 * @return array<string, array<string, mixed>>
	 */
	public static function active_bans( $limit = self::MAX_BANS ) {
		global $wpdb;
		if ( ! self::ready() ) {
			return array();
		}
		$sql = $wpdb->prepare( 'SELECT ip, until_ts, since_ts, reason FROM %i WHERE until_ts > %d ORDER BY since_ts DESC', self::bans_table(), time() );
		if ( (int) $limit > 0 ) {
			$sql .= $wpdb->prepare( ' LIMIT %d', (int) $limit );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- Plugin table; prepared above.
		$rows = (array) $wpdb->get_results( $sql, ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ (string) $row['ip'] ] = array(
				'until'  => (int) $row['until_ts'],
				'since'  => (int) $row['since_ts'],
				'reason' => (string) $row['reason'],
			);
		}
		return $out;
	}

	/**
	 * How many bans are currently in effect.
	 *
	 * @return int
	 */
	public static function count_bans() {
		global $wpdb;
		if ( ! self::ready() ) {
			return 0;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE until_ts > %d', self::bans_table(), time() ) );
	}

	/**
	 * Records a "violation". When they reach the limit within 10 minutes, the IP is banned.
	 *
	 * @param string $ip     IP.
	 * @param string $reason Reason.
	 * @return bool Whether the IP was just banned.
	 */
	public static function strike( $ip, $reason ) {
		$s       = PNCP_Options::get();
		$strikes = (int) $s['ban_strikes'];
		// "Monitor only" never leads to a ban: nothing is counted toward one either, so switching to blocking
		// starts with a clean slate.
		if ( $strikes < 1 || '' === $ip || PNCP_Ip::is_cdn_edge( $ip ) || PNCP_Options::monitoring( $s ) ) {
			return false;
		}
		$key = 'pncp_st_' . md5( PNCP_Ip::limit_key( $ip ) ); // IPv6: per /64, like the limits.
		if ( wp_using_ext_object_cache() ) {
			// Atomic: two concurrent violations cannot both read the same value and lose a strike.
			wp_cache_add( $key, 0, 'pncp', 10 * MINUTE_IN_SECONDS );
			$count = (int) wp_cache_incr( $key, 1, 'pncp' );
		} elseif ( self::apcu_ok() ) {
			// Atomic too, in PHP's shared memory (bots that send requests in parallel would otherwise lose strikes).
			$name = self::apcu_key( $key );
			apcu_add( $name, 0, 10 * MINUTE_IN_SECONDS );
			$count = (int) apcu_inc( $name );
		} else {
			$count = (int) self::cache_get( $key ) + 1;
			self::cache_set( $key, $count, 10 * MINUTE_IN_SECONDS );
		}
		if ( $count >= $strikes ) {
			self::cache_delete( $key );
			if ( self::apcu_ok() ) {
				apcu_delete( self::apcu_key( $key ) );
			}
			self::ban( $ip, (int) $s['ban_minutes'], $reason );
			return true;
		}
		return false;
	}

	/**
	 * Can the per-minute counters live in APCu (PHP's shared memory) instead of the database? Only where APCu is
	 * shared by all PHP workers of the site (PHP-FPM, Apache mod_php); under CGI or LSAPI each process may
	 * have its own, and the counts would be split. Filter `pncp_use_apcu`.
	 *
	 * @return bool
	 */
	public static function apcu_ok() {
		static $ok = null;
		if ( null === $ok ) {
			$ok = function_exists( 'apcu_enabled' ) && apcu_enabled() && in_array( PHP_SAPI, array( 'fpm-fcgi', 'apache2handler' ), true );
			$ok = (bool) apply_filters( 'pncp_use_apcu', $ok );
		}
		return $ok;
	}

	/**
	 * An APCu key for this site (several sites may share one server and its APCu).
	 *
	 * @param string $key Key.
	 * @return string
	 */
	public static function apcu_key( $key ) {
		static $prefix = null;
		if ( null === $prefix ) {
			$prefix = 'pncp_' . substr( md5( ABSPATH . '|' . get_current_blog_id() ), 0, 8 ) . '_';
		}
		return $prefix . $key;
	}

	/* ---------- Cache: object cache if present, otherwise APCu (see apcu_ok()), otherwise transients ---------- */

	/**
	 * Read.
	 *
	 * @param string $key Key.
	 * @return mixed False when there is nothing.
	 */
	public static function cache_get( $key ) {
		if ( wp_using_ext_object_cache() ) {
			return wp_cache_get( $key, 'pncp' );
		}
		if ( self::apcu_ok() ) {
			// No database query and no row in wp_options (log grouping, the human check throttle and the like).
			return apcu_fetch( self::apcu_key( $key ) );
		}
		return get_transient( $key );
	}

	/**
	 * Write.
	 *
	 * @param string $key   Key.
	 * @param mixed  $value Value.
	 * @param int    $ttl   Seconds.
	 */
	public static function cache_set( $key, $value, $ttl ) {
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $value, 'pncp', max( 1, (int) $ttl ) );
		} elseif ( self::apcu_ok() ) {
			apcu_store( self::apcu_key( $key ), $value, max( 1, (int) $ttl ) );
		} else {
			set_transient( $key, $value, max( 1, (int) $ttl ) );
		}
	}

	/**
	 * Delete.
	 *
	 * @param string $key Key.
	 */
	public static function cache_delete( $key ) {
		if ( wp_using_ext_object_cache() ) {
			wp_cache_delete( $key, 'pncp' );
		} elseif ( self::apcu_ok() ) {
			apcu_delete( self::apcu_key( $key ) );
		} else {
			delete_transient( $key );
		}
	}

	/**
	 * Suggested text for the Privacy Policy.
	 */
	public static function privacy_policy() {
		if ( ! is_admin() || ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		wp_add_privacy_policy_content(
			__( 'ScrapeLock', 'scrapelock' ),
			'<p>' . esc_html__( 'To protect content from automated copying, when a request is blocked we record the IP address, the browser\'s User-Agent, the page and the time. This data is deleted automatically after a few days and is not used for any other purpose.', 'scrapelock' ) . '</p>'
			. '<p>' . esc_html__( 'If blocking at the CDN is turned on, the IP addresses that are blocked temporarily are also sent to our CDN provider (Cloudflare or Bunny CDN), with a short note that gives the reason and the end of the block, so the CDN can refuse them before they reach our server. Each one is removed from the CDN when the block ends. Nothing else about visitors is sent.', 'scrapelock' ) . '</p>'
			. '<p>' . esc_html__( 'So that administrators are never blocked by mistake, the IP addresses from which administrators used the site\'s dashboard in the last 30 days are kept; older ones are deleted automatically.', 'scrapelock' ) . '</p>'
		);
	}
}
