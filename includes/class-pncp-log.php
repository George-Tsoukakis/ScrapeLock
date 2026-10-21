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
			uas smallint(5) unsigned NOT NULL DEFAULT 1,
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
		update_option( 'pncp_db_version', self::DB_VERSION, true ); // Autoloaded: read on every request by is_banned().
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
		$ua  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
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

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
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
			if ( self::uas_column() ) {
				self::cache_set( $key . '_u', array( md5( $ua ) ), 2 * MINUTE_IN_SECONDS );
			}
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
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
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
			'total'      => 0,
			'reasons'    => array(),
			'ips'        => array(),
			'uas'        => array(),
			'ua_reasons' => array(),
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
		// Why each of the top User-Agents was blocked (e.g. a "Googlebot" that was a fake one).
		if ( $out['uas'] ) {
			$list = implode( ', ', array_fill( 0, count( $out['uas'] ), '%s' ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Admin screen; $list holds only %s placeholders, one per value.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT ua, reason, SUM(hits) AS n FROM %i WHERE created >= %s AND ua IN ($list) GROUP BY ua, reason ORDER BY n DESC", array_merge( array( $table, $since ), array_keys( $out['uas'] ) ) ), ARRAY_A );
			foreach ( (array) $rows as $row ) {
				$out['ua_reasons'][ $row['ua'] ][ $row['reason'] ] = (int) $row['n'];
			}
		}
		return $out;
	}

	/**
	 * The paths blocked most often: what scrapers try to copy (content) and what scanners look for (files).
	 *
	 * @param int $hours Period in hours.
	 * @param int $limit Rows per group.
	 * Three groups: "content" (addresses that exist on the site: what scrapers were after), "unknown" (addresses
	 * that do not exist: random strings and guesses) and "probes" (files and admin paths: scanners).
	 *
	 * @return array{content: array<int, array{path:string, hits:int, ips:int}>, unknown: array<int, array{path:string, hits:int, ips:int}>, probes: array<int, array{path:string, hits:int, ips:int}>}
	 */
	public static function top_paths( $hours = 24, $limit = 10 ) {
		global $wpdb;
		$out = array(
			'content' => array(),
			'unknown' => array(),
			'probes'  => array(),
		);
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return $out;
		}
		$since = gmdate( 'Y-m-d H:i:s', time() - (int) $hours * HOUR_IN_SECONDS );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Admin screen.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT path, SUM(hits) AS n, COUNT(DISTINCT ip) AS ips FROM %i WHERE created >= %s AND path <> '' GROUP BY path ORDER BY n DESC LIMIT 300", self::table(), $since ), ARRAY_A );
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
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return array();
		}
		$requests = $requests > 0 ? (int) $requests : max( 1, (int) apply_filters( 'pncp_persistent_requests', 100 ) );
		$since    = gmdate( 'Y-m-d H:i:s', time() - (int) $hours * HOUR_IN_SECONDS );
		$table    = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Admin screen.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT ip, SUM(CASE WHEN reason = 'ban' THEN hits ELSE 0 END) AS bans, SUM(hits) AS total, MAX(created) AS last FROM %i WHERE created >= %s GROUP BY ip HAVING SUM(CASE WHEN reason = 'ban' THEN hits ELSE 0 END) >= %d OR SUM(hits) >= %d ORDER BY total DESC LIMIT %d", $table, $since, max( 1, (int) $min ), $requests, max( 1, (int) $limit ) ), ARRAY_A );
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
			$reasons = $wpdb->get_results( $wpdb->prepare( "SELECT ip, reason, SUM(hits) AS n FROM %i WHERE created >= %s AND reason <> 'ban' AND ip IN ($list) GROUP BY ip, reason ORDER BY n DESC", array_merge( array( $table, $since ), array_keys( $out ) ) ), ARRAY_A );
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
		// Bans are stored per ban key (IPv6: the /64, like the limits and strikes), so a client cannot dodge
		// a ban by moving to another address in the same /64.
		$bankey = PNCP_Ip::limit_key( $ip );
		if ( isset( self::$banned[ $bankey ] ) ) {
			return self::$banned[ $bankey ];
		}
		$key = 'pncp_ban_' . md5( $bankey );
		if ( wp_using_ext_object_cache() ) {
			$until = wp_cache_get( $key, 'pncp' );
			if ( false !== $until ) {
				self::$banned[ $bankey ] = (int) $until > time();
				return self::$banned[ $bankey ];
			}
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table; the cache is above.
		$until = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT until_ts FROM %i WHERE ip = %s', self::bans_table(), $bankey ) );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $until, 'pncp', $until > time() ? $until - time() : 5 * MINUTE_IN_SECONDS );
		}
		self::$banned[ $bankey ] = $until > time();
		return self::$banned[ $bankey ];
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
		self::$banned[ $ip ] = true;
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( 'pncp_ban_' . md5( $ip ), $until, 'pncp', max( 1, $until - time() ) );
		}
		PNCP_Precheck::mirror_ban( $ip, $until );
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
		}
		unset( self::$banned[ $ip ] );
		PNCP_Precheck::forget_ban( $ip );
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
		PNCP_Precheck::forget_all_bans();
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
		$key = 'pncp_st_' . md5( PNCP_Ip::limit_key( $ip ) ); // IPv6: per /64, like the limits.
		if ( wp_using_ext_object_cache() ) {
			// Atomic: two concurrent violations cannot both read the same value and lose a strike.
			wp_cache_add( $key, 0, 'pncp', 10 * MINUTE_IN_SECONDS );
			$count = (int) wp_cache_incr( $key, 1, 'pncp' );
		} else {
			$count = (int) self::cache_get( $key ) + 1;
			self::cache_set( $key, $count, 10 * MINUTE_IN_SECONDS );
		}
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
