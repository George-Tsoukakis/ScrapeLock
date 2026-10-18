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
	 * Table schema version.
	 */
	const DB_VERSION = '2';

	/**
	 * Option where 2.1 kept the bans (moved to the table on upgrade).
	 */
	const BANS_OPTION = 'pncp_bans';

	/**
	 * How many bans are shown on the settings page (the table keeps all of them).
	 */
	const MAX_BANS = 500;

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
		add_action( 'admin_init', array( __CLASS__, 'privacy_policy' ) );
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
			PRIMARY KEY  (id),
			KEY created (created),
			KEY ip (ip)
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
		update_option( 'pncp_db_version', self::DB_VERSION, false );

		// 2.1 bans (option) → table.
		$old = get_option( self::BANS_OPTION );
		if ( is_array( $old ) ) {
			foreach ( $old as $ip => $ban ) {
				if ( is_array( $ban ) && isset( $ban['until'] ) && (int) $ban['until'] > time() && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					self::store_ban( (string) $ip, (int) $ban['until'], isset( $ban['reason'] ) ? (string) $ban['reason'] : 'ban', isset( $ban['since'] ) ? (int) $ban['since'] : time() );
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
			'bot_ua'       => __( 'User-Agent in the bot list', 'scrapelock' ),
			'empty_ua'     => __( 'No User-Agent', 'scrapelock' ),
			'fake_crawler' => __( 'Fake search engine', 'scrapelock' ),
			'fake_ai_bot'  => __( 'Fake AI search bot', 'scrapelock' ),
			'no_browser'   => __( 'No browser headers', 'scrapelock' ),
			'rate_page'    => __( 'Page limit', 'scrapelock' ),
			'rate_search'  => __( 'Search limit', 'scrapelock' ),
			'rate_rest'    => __( 'REST / GraphQL limit', 'scrapelock' ),
			'rate_404'     => __( '“Page not found” limit', 'scrapelock' ),
			'blocked_ip'   => __( 'IP in the always-blocked list', 'scrapelock' ),
			'blocked_ref'  => __( 'Referrer in the always-blocked list', 'scrapelock' ),
			'trap'         => __( 'Bot trap', 'scrapelock' ),
			'ban'          => __( 'New temporary block', 'scrapelock' ),
			'banned'       => __( 'Request from a blocked IP', 'scrapelock' ),
			'feed_denied'  => __( 'Private URL without token', 'scrapelock' ),
		);
	}

	/**
	 * Logs an event. Same IP and reason within the same minute become one row with a counter,
	 * so that a persistent bot does not fill up the database.
	 *
	 * @param string $reason Reason (key of reasons()).
	 * @param int    $code   HTTP status code.
	 * @param string $ip     IP.
	 */
	public static function add( $reason, $code, $ip ) {
		global $wpdb;
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return;
		}

		$key = 'pncp_lg_' . md5( $ip . '|' . $reason . '|' . (int) floor( time() / MINUTE_IN_SECONDS ) );
		$id  = (int) self::cache_get( $key );
		if ( $id > 0 ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Counter, no cache.
			$wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = hits + 1 WHERE id = %d', self::table(), $id ) );
			return;
		}

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$ua   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );

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
		}
	}

	/**
	 * Deletes everything older than the retention period and the expired bans.
	 */
	public static function cleanup() {
		global $wpdb;
		$days   = max( 1, (int) PNCP_Options::stored()['log_retention'] );
		$before = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		if ( get_option( 'pncp_db_version' ) === self::DB_VERSION ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created < %s', self::table(), $before ) );
		}
		if ( get_option( 'pncp_db_version' ) === self::DB_VERSION ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE until_ts < %d', self::bans_table(), time() ) );
		}
		self::purge_expired_transients();
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
	}

	/**
	 * The latest entries.
	 *
	 * @param int $limit Count.
	 * @return array<int, array<string, mixed>>
	 */
	public static function recent( $limit = 100 ) {
		global $wpdb;
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return array();
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Admin screen.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY id DESC LIMIT %d', self::table(), max( 1, (int) $limit ) ), ARRAY_A );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Summary of a period: totals per reason, top IPs and User-Agents.
	 *
	 * @param int $hours Hours back.
	 * @return array<string, mixed>
	 */
	public static function summary( $hours = 24 ) {
		global $wpdb;
		$empty = array(
			'total'   => 0,
			'reasons' => array(),
			'ips'     => array(),
			'uas'     => array(),
		);
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return $empty;
		}
		$since = gmdate( 'Y-m-d H:i:s', time() - (int) $hours * HOUR_IN_SECONDS );
		$table = self::table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Admin screen / widget.
		$reasons = $wpdb->get_results( $wpdb->prepare( 'SELECT reason, SUM(hits) AS n FROM %i WHERE created >= %s GROUP BY reason ORDER BY n DESC', $table, $since ), ARRAY_A );
		$ips     = $wpdb->get_results( $wpdb->prepare( 'SELECT ip, SUM(hits) AS n FROM %i WHERE created >= %s GROUP BY ip ORDER BY n DESC LIMIT 10', $table, $since ), ARRAY_A );
		$uas     = $wpdb->get_results( $wpdb->prepare( "SELECT ua, SUM(hits) AS n FROM %i WHERE created >= %s AND ua <> '' GROUP BY ua ORDER BY n DESC LIMIT 10", $table, $since ), ARRAY_A );
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
		return $out;
	}

	/* ---------- Bans ---------- */

	/**
	 * Is the IP banned? One query on the PRIMARY KEY (or the object cache, if present).
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_banned( $ip ) {
		global $wpdb;
		if ( '' === $ip || get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return false;
		}
		if ( isset( self::$banned[ $ip ] ) ) {
			return self::$banned[ $ip ];
		}
		$key = 'pncp_ban_' . md5( $ip );
		if ( wp_using_ext_object_cache() ) {
			$until = wp_cache_get( $key, 'pncp' );
			if ( false !== $until ) {
				self::$banned[ $ip ] = (int) $until > time();
				return self::$banned[ $ip ];
			}
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table; the cache is above.
		$until = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT until_ts FROM %i WHERE ip = %s', self::bans_table(), $ip ) );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $until, 'pncp', $until > time() ? $until - time() : 5 * MINUTE_IN_SECONDS );
		}
		self::$banned[ $ip ] = $until > time();
		return self::$banned[ $ip ];
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
		// Never the Google / Bing IPs, whoever tried to "trap" them.
		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) || PNCP_Bots::is_official_crawler_ip( $ip ) ) {
			return;
		}
		$until = time() + max( 1, (int) $minutes ) * MINUTE_IN_SECONDS;
		self::store_ban( $ip, $until, $reason, time() );
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
		self::$banned[ $ip ] = true;
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( 'pncp_ban_' . md5( $ip ), $until, 'pncp', max( 1, $until - time() ) );
		}
	}

	/**
	 * Lifts the ban on an IP.
	 *
	 * @param string $ip IP.
	 */
	public static function unban( $ip ) {
		global $wpdb;
		self::cache_delete( 'pncp_st_' . md5( PNCP_Ip::limit_key( $ip ) ) );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_delete( 'pncp_ban_' . md5( $ip ), 'pncp' );
		}
		unset( self::$banned[ $ip ] );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->delete( self::bans_table(), array( 'ip' => $ip ), array( '%s' ) );
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
			}
		}
		self::$banned = array();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::bans_table() ) );
	}

	/**
	 * The active bans, most recent first.
	 *
	 * @param int $limit Maximum count (0 = all).
	 * @return array<string, array<string, mixed>>
	 */
	public static function active_bans( $limit = self::MAX_BANS ) {
		global $wpdb;
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
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
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
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
		if ( $strikes < 1 || '' === $ip ) {
			return false;
		}
		$key   = 'pncp_st_' . md5( PNCP_Ip::limit_key( $ip ) ); // IPv6: per /64, like the limits.
		$count = (int) self::cache_get( $key ) + 1;
		self::cache_set( $key, $count, 10 * MINUTE_IN_SECONDS );
		if ( $count >= $strikes ) {
			self::cache_delete( $key );
			self::ban( $ip, (int) $s['ban_minutes'], $reason );
			return true;
		}
		return false;
	}

	/* ---------- Cache: object cache if present, otherwise transients ---------- */

	/**
	 * Read.
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	public static function cache_get( $key ) {
		return wp_using_ext_object_cache() ? wp_cache_get( $key, 'pncp' ) : get_transient( $key );
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
		);
	}
}
