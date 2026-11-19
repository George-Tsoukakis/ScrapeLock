<?php
/**
 * 3.7: the CrowdSec blocklist. CrowdSec is a free, open source security engine whose users share the IPs that
 * attack them; its community blocklist holds the addresses of scanners, brute-forcers and scrapers seen on many
 * sites, residential proxies among them, which per-IP limits on one site cannot recognise in time.
 *
 * Two ways to get the list, both off by default:
 * - "lapi": a CrowdSec agent of your own (usually on the same server, http://127.0.0.1:8080) with a bouncer key
 *   ("cscli bouncers add scrapelock"). ScrapeLock asks it every 15 minutes for the decisions that changed
 *   (GET /v1/decisions/stream). The agent subscribes to the community blocklist and adds what it sees itself.
 * - "list": a plain-text list, one IP or CIDR per line, from an address with optional Basic authentication
 *   ("user:password" in the key field): a CrowdSec Console blocklist integration, or another provider's list.
 *   Downloaded once an hour and replaced as a whole.
 *
 * A listed IP gets either a stricter page limit ("limit", the default: a shared or recycled address keeps working,
 * just slowly) or a 403 ("block"). Verified search engines, exempt staff, the always-allowed IPs and the private
 * feeds are never affected (they pass PNCP_Bots::check() before this). The lists are kept in the plugin's own
 * table (exact addresses) and an option (ranges); nothing is sent to CrowdSec or anyone else by ScrapeLock.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * CrowdSec blocklist.
 */
final class PNCP_Crowdsec {

	/**
	 * Cron hook.
	 */
	const CRON = 'pncp_crowdsec_sync';

	/**
	 * Cron schedule: every 15 minutes.
	 */
	const SCHEDULE = 'pncp_quarter_hour';

	/**
	 * Option: the ranges (CIDR => until).
	 */
	const RANGES = 'pncp_crowdsec_ranges';

	/**
	 * Option: the state (last sync, count, last error, whether the LAPI stream was started).
	 */
	const STATE = 'pncp_crowdsec_state';

	/**
	 * At most this many addresses are kept (filter `pncp_crowdsec_max`), so a huge list cannot fill the database.
	 */
	const MAX = 200000;

	/**
	 * At most this many ranges (they are checked one by one on each request).
	 */
	const MAX_RANGES = 5000;

	/**
	 * Rows per INSERT.
	 */
	const CHUNK = 500;

	/**
	 * A list download is valid this long: an address that is no longer in it is removed by the next complete sync;
	 * if syncs stop (the list's server is down), the addresses expire on their own after this.
	 */
	const LIST_TTL = 6 * HOUR_IN_SECONDS;

	/**
	 * Answers already found in this PHP request: IP => listed.
	 *
	 * @var array<string, bool>
	 */
	private static $memo = array();

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'cron_schedules', array( __CLASS__, 'schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval -- 15 minutes, only while CrowdSec is on.
		add_action( self::CRON, array( __CLASS__, 'sync' ) );
		add_action( 'init', array( __CLASS__, 'ensure_cron' ), 20 );
	}

	/**
	 * The 15-minute schedule.
	 *
	 * @param array<string, array<string, mixed>> $schedules Schedules.
	 * @return array<string, array<string, mixed>>
	 */
	public static function schedules( $schedules ) {
		$schedules[ self::SCHEDULE ] = array(
			'interval' => 15 * MINUTE_IN_SECONDS,
			'display'  => __( 'Every 15 minutes (ScrapeLock)', 'scrapelock' ),
		);
		return $schedules;
	}

	/**
	 * Keeps the sync scheduled while CrowdSec is on, and unscheduled (with its data removed) when it is off.
	 */
	public static function ensure_cron() {
		$on   = self::enabled();
		$next = wp_next_scheduled( self::CRON );
		if ( $on && ! $next ) {
			wp_schedule_event( time() + 30, self::SCHEDULE, self::CRON );
		} elseif ( ! $on && $next ) {
			wp_clear_scheduled_hook( self::CRON );
			self::clear();
		}
	}

	/**
	 * Is the blocklist in use?
	 *
	 * @param array<string, mixed>|null $s Settings.
	 * @return bool
	 */
	public static function enabled( $s = null ) {
		$s = null === $s ? PNCP_Options::get() : $s;
		return ! empty( $s['enabled'] ) && in_array( (string) $s['crowdsec_mode'], array( 'lapi', 'list' ), true ) && '' !== (string) $s['crowdsec_url'];
	}

	/**
	 * The key: from wp-config.php (SCRAPELOCK_CROWDSEC_KEY) if defined, otherwise the setting.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	public static function key( $s ) {
		if ( defined( 'SCRAPELOCK_CROWDSEC_KEY' ) && '' !== (string) SCRAPELOCK_CROWDSEC_KEY ) {
			return (string) SCRAPELOCK_CROWDSEC_KEY;
		}
		return (string) $s['crowdsec_key'];
	}

	/**
	 * The table of listed addresses.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'pncp_crowdsec';
	}

	/**
	 * Creates the table (PNCP_Log::install() calls it).
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
			ip varchar(45) NOT NULL,
			until_ts int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (ip),
			KEY until_ts (until_ts)
			) {$charset};"
		);
	}

	/**
	 * Is the IP in the blocklist now?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function listed( $ip ) {
		$ip = PNCP_Ip::normalize( (string) $ip );
		if ( '' === $ip || ! self::enabled() ) {
			return false;
		}
		if ( isset( self::$memo[ $ip ] ) ) {
			return self::$memo[ $ip ];
		}
		$now   = time();
		$found = false;
		$state = self::state();
		if ( ! empty( $state['count'] ) ) {
			global $wpdb;
			$suppress = $wpdb->suppress_errors( true );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, one indexed lookup.
			$until = $wpdb->get_var( $wpdb->prepare( 'SELECT until_ts FROM %i WHERE ip = %s', self::table(), $ip ) );
			$wpdb->suppress_errors( $suppress );
			$found = null !== $until && (int) $until > $now;
		}
		if ( ! $found && ! empty( $state['ranges'] ) ) {
			$ranges = get_option( self::RANGES, array() );
			if ( is_array( $ranges ) && $ranges ) {
				$live = array();
				foreach ( $ranges as $range => $until ) {
					if ( (int) $until > $now ) {
						$live[] = (string) $range;
					}
				}
				$found = $live && PNCP_Ip::in_any( $ip, $live );
			}
		}
		/**
		 * Filter: is this IP in the CrowdSec blocklist? (E.g. to exempt your own monitoring.)
		 *
		 * @param bool   $found Listed.
		 * @param string $ip    IP.
		 */
		$found             = (bool) apply_filters( 'pncp_crowdsec_listed', $found, $ip );
		self::$memo[ $ip ] = $found;
		return $found;
	}

	/**
	 * The state: last successful sync, number of addresses and ranges, last error, LAPI stream started.
	 *
	 * @return array{synced:int, count:int, ranges:int, error:string, error_at:int, started:bool, mode:string, url:string}
	 */
	public static function state() {
		$state = get_option( self::STATE, array() );
		return array_merge(
			array(
				'synced'   => 0,
				'count'    => 0,
				'ranges'   => 0,
				'error'    => '',
				'error_at' => 0,
				'started'  => false,
				'mode'     => '',
				'url'      => '',
			),
			is_array( $state ) ? $state : array()
		);
	}

	/**
	 * Saves the state.
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function save_state( $state ) {
		update_option( self::STATE, $state, true ); // Autoloaded: listed() reads it on every request while CrowdSec is on.
	}

	/**
	 * The scheduled sync (and "Sync now"). A changed mode or address starts over from an empty list.
	 *
	 * @param bool $force Download the list even if the last one is less than an hour old.
	 * @return true|WP_Error
	 */
	public static function sync( $force = false ) {
		$s = PNCP_Options::get();
		if ( ! self::enabled( $s ) ) {
			return new WP_Error( 'pncp_crowdsec_off', __( 'CrowdSec is off.', 'scrapelock' ) );
		}
		$state = self::state();
		if ( $state['mode'] !== $s['crowdsec_mode'] || $state['url'] !== $s['crowdsec_url'] ) {
			self::clear();
			$state         = self::state();
			$state['mode'] = (string) $s['crowdsec_mode'];
			$state['url']  = (string) $s['crowdsec_url'];
			self::save_state( $state );
		}
		if ( 'list' === $s['crowdsec_mode'] && ! $force && time() - (int) $state['synced'] < HOUR_IN_SECONDS - MINUTE_IN_SECONDS ) {
			return true; // A list is downloaded once an hour.
		}
		$result = 'lapi' === $s['crowdsec_mode'] ? self::sync_lapi( $s, $state ) : self::sync_list( $s, $state );
		$state  = self::state();
		if ( is_wp_error( $result ) ) {
			$state['error']    = $result->get_error_message();
			$state['error_at'] = time();
		} else {
			$state['error']  = '';
			$state['synced'] = time();
		}
		$state['count']  = self::count_rows();
		$state['ranges'] = count( (array) get_option( self::RANGES, array() ) );
		self::save_state( $state );
		self::$memo = array();
		return $result;
	}

	/**
	 * LAPI: the decisions that changed since the last call (all of them on the first call, or after an error).
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param array<string, mixed> $state State.
	 * @return true|WP_Error
	 */
	private static function sync_lapi( $s, $state ) {
		$startup  = empty( $state['started'] );
		$url      = add_query_arg(
			array(
				'startup' => $startup ? 'true' : 'false',
				'scopes'  => 'ip,range',
			),
			untrailingslashit( (string) $s['crowdsec_url'] ) . '/v1/decisions/stream'
		);
		$response = wp_remote_get(
			$url,
			array(
				'timeout'             => 20,
				'headers'             => array(
					'X-Api-Key' => self::key( $s ),
					'Accept'    => 'application/json',
				),
				'user-agent'          => 'ScrapeLock/' . PNCP_VERSION,
				'limit_response_size' => 50 * MB_IN_BYTES,
			)
		);
		$body     = self::body( $response );
		if ( is_wp_error( $body ) ) {
			return $body;
		}
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'pncp_crowdsec_json', __( 'The CrowdSec agent did not answer with JSON.', 'scrapelock' ) );
		}
		if ( $startup ) {
			self::clear_rows(); // A full list follows: start from nothing.
		}
		$now     = time();
		$add     = array();
		$ranges  = $startup ? array() : (array) get_option( self::RANGES, array() );
		$removed = array();
		foreach ( isset( $data['new'] ) && is_array( $data['new'] ) ? $data['new'] : array() as $decision ) {
			if ( ! is_array( $decision ) || ! isset( $decision['value'] ) ) {
				continue;
			}
			$seconds = self::duration( isset( $decision['duration'] ) ? (string) $decision['duration'] : '' );
			if ( $seconds <= 0 ) {
				continue;
			}
			$value = (string) $decision['value'];
			$scope = strtolower( isset( $decision['scope'] ) ? (string) $decision['scope'] : 'ip' );
			if ( 'range' === $scope || false !== strpos( $value, '/' ) ) {
				if ( self::usable_range( $value ) && count( $ranges ) < self::MAX_RANGES ) {
					$ranges[ $value ] = max( isset( $ranges[ $value ] ) ? (int) $ranges[ $value ] : 0, $now + $seconds );
				}
			} else {
				$ip = self::usable_ip( $value );
				if ( '' !== $ip ) {
					$add[ $ip ] = max( isset( $add[ $ip ] ) ? $add[ $ip ] : 0, $now + $seconds );
				}
			}
		}
		foreach ( isset( $data['deleted'] ) && is_array( $data['deleted'] ) ? $data['deleted'] : array() as $decision ) {
			if ( ! is_array( $decision ) || ! isset( $decision['value'] ) ) {
				continue;
			}
			$value = (string) $decision['value'];
			if ( false !== strpos( $value, '/' ) ) {
				unset( $ranges[ $value ] );
			} else {
				$ip = PNCP_Ip::normalize( $value );
				if ( '' !== $ip && ! isset( $add[ $ip ] ) ) {
					$removed[] = $ip;
				}
			}
		}
		self::store( $add );
		self::remove( $removed );
		update_option( self::RANGES, self::live_ranges( $ranges ), false );
		$state            = self::state();
		$state['started'] = true;
		self::save_state( $state );
		return true;
	}

	/**
	 * A plain-text list, replaced as a whole.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param array<string, mixed> $state State.
	 * @return true|WP_Error
	 */
	private static function sync_list( $s, $state ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Same signature as sync_lapi().
		$headers = array( 'Accept' => 'text/plain' );
		$key     = self::key( $s );
		if ( '' !== $key ) {
			// "user:password" → Basic authentication (CrowdSec Console integrations); anything else is sent as a key.
			if ( false !== strpos( $key, ':' ) ) {
				$headers['Authorization'] = 'Basic ' . base64_encode( $key ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- HTTP Basic authentication.
			} else {
				$headers['X-Api-Key'] = $key;
			}
		}
		$response = wp_remote_get(
			(string) $s['crowdsec_url'],
			array(
				'timeout'             => 30,
				'headers'             => $headers,
				'user-agent'          => 'ScrapeLock/' . PNCP_VERSION,
				'limit_response_size' => 50 * MB_IN_BYTES,
			)
		);
		$body     = self::body( $response );
		if ( is_wp_error( $body ) ) {
			return $body;
		}
		$until  = time() + self::LIST_TTL;
		$add    = array();
		$ranges = array();
		$max    = (int) apply_filters( 'pncp_crowdsec_max', self::MAX );
		foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
			$line = trim( preg_replace( '/[#;].*$/', '', $line ) ); // Comments ("# …", "; …") are allowed.
			if ( '' === $line ) {
				continue;
			}
			$line = strtok( $line, " \t," ); // The first field, for lists with more columns.
			if ( false !== strpos( $line, '/' ) ) {
				if ( self::usable_range( $line ) && count( $ranges ) < self::MAX_RANGES ) {
					$ranges[ $line ] = $until;
				}
				continue;
			}
			$ip = self::usable_ip( $line );
			if ( '' !== $ip && count( $add ) < $max ) {
				$add[ $ip ] = $until;
			}
		}
		if ( ! $add && ! $ranges ) {
			// An empty answer keeps the previous list (a server error page, a list being rebuilt).
			return new WP_Error( 'pncp_crowdsec_empty', __( 'The list was empty or held no IP addresses; the previous list is kept.', 'scrapelock' ) );
		}
		self::store( $add );
		// Addresses that were not in this download go now: every row of this list got $until above.
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE until_ts < %d', self::table(), $until ) );
		update_option( self::RANGES, $ranges, false );
		return true;
	}

	/**
	 * The body of a successful answer, or the error.
	 *
	 * @param array<string, mixed>|WP_Error $response Response.
	 * @return string|WP_Error
	 */
	private static function body( $response ) {
		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'pncp_crowdsec_http', $response->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 401 === $code || 403 === $code ) {
			return new WP_Error( 'pncp_crowdsec_auth', __( 'The key was refused (401/403). Check the bouncer key or the user name and password.', 'scrapelock' ) );
		}
		if ( 200 !== $code ) {
			/* translators: %d: HTTP status code */
			return new WP_Error( 'pncp_crowdsec_status', sprintf( __( 'Unexpected answer: HTTP %d.', 'scrapelock' ), $code ) );
		}
		return (string) wp_remote_retrieve_body( $response );
	}

	/**
	 * An address that may be listed: valid, public, never this server, a CDN edge or an official crawler.
	 *
	 * @param string $value Value.
	 * @return string The normalised IP, or ''.
	 */
	private static function usable_ip( $value ) {
		$ip = PNCP_Ip::normalize( trim( (string) $value ) );
		if ( '' === $ip || PNCP_Ip::is_private( $ip ) || PNCP_Ip::is_local( $ip ) || PNCP_Ip::is_cdn( $ip ) || PNCP_Bots::is_official_crawler_ip( $ip ) ) {
			return '';
		}
		return $ip;
	}

	/**
	 * A range that may be listed: valid, not private or reserved, and no wider than an IPv4 /16 or an IPv6 /32
	 * (filter `pncp_crowdsec_range_ok`). Some public lists hold whole /8 networks or the private ranges, which
	 * would refuse real visitors, a reverse proxy or the server itself.
	 *
	 * @param string $range CIDR.
	 * @return bool
	 */
	private static function usable_range( $range ) {
		$range = trim( (string) $range );
		if ( ! PNCP_Ip::valid_range( $range ) ) {
			return false;
		}
		list( $net, $bits ) = array_pad( explode( '/', $range, 2 ), 2, '' );
		$v6                 = false !== strpos( $net, ':' );
		$bits               = '' === $bits ? ( $v6 ? 128 : 32 ) : (int) $bits;
		$ok                 = $bits >= ( $v6 ? 32 : 16 ) && ! PNCP_Ip::is_private( $net );
		return (bool) apply_filters( 'pncp_crowdsec_range_ok', $ok, $range );
	}

	/**
	 * Adds or renews addresses (IP => until), in chunks.
	 *
	 * @param array<string, int> $rows Rows.
	 */
	private static function store( $rows ) {
		global $wpdb;
		if ( ! $rows ) {
			return;
		}
		$table = self::table();
		foreach ( array_chunk( $rows, self::CHUNK, true ) as $chunk ) {
			$values = array();
			$args   = array( $table );
			foreach ( $chunk as $ip => $until ) {
				$values[] = '(%s, %d)';
				$args[]   = (string) $ip;
				$args[]   = (int) $until;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders -- Plugin table; placeholders built above.
			$wpdb->query( $wpdb->prepare( 'INSERT INTO %i (ip, until_ts) VALUES ' . implode( ', ', $values ) . ' ON DUPLICATE KEY UPDATE until_ts = VALUES(until_ts)', $args ) );
		}
	}

	/**
	 * Removes addresses.
	 *
	 * @param string[] $ips IPs.
	 */
	private static function remove( $ips ) {
		global $wpdb;
		foreach ( array_chunk( array_values( array_unique( $ips ) ), self::CHUNK ) as $chunk ) {
			$marks = implode( ', ', array_fill( 0, count( $chunk ), '%s' ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders -- Plugin table; placeholders built above.
			$wpdb->query( $wpdb->prepare( "DELETE FROM %i WHERE ip IN ({$marks})", array_merge( array( self::table() ), $chunk ) ) );
		}
	}

	/**
	 * Ranges that have not expired.
	 *
	 * @param array<string, int> $ranges Ranges.
	 * @return array<string, int>
	 */
	private static function live_ranges( $ranges ) {
		$now = time();
		return array_filter(
			(array) $ranges,
			static function ( $until ) use ( $now ) {
				return (int) $until > $now;
			}
		);
	}

	/**
	 * Removes expired addresses (hourly, with the log cleanup).
	 */
	public static function cleanup() {
		global $wpdb;
		$state = self::state();
		if ( empty( $state['count'] ) ) {
			return;
		}
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE until_ts <= %d LIMIT 20000', self::table(), time() ) );
		$wpdb->suppress_errors( $suppress );
		update_option( self::RANGES, self::live_ranges( get_option( self::RANGES, array() ) ), false );
	}

	/**
	 * Number of addresses in the table.
	 *
	 * @return int
	 */
	public static function count_rows() {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$count = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE until_ts > %d', self::table(), time() ) );
		$wpdb->suppress_errors( $suppress );
		return $count;
	}

	/**
	 * Empties the table.
	 */
	private static function clear_rows() {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::table() ) );
		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * Forgets everything (CrowdSec turned off, or another source chosen).
	 */
	public static function clear() {
		self::clear_rows();
		delete_option( self::RANGES );
		delete_option( self::STATE );
		self::$memo = array();
	}

	/**
	 * Seconds of a Go duration as CrowdSec writes it ("3h59m58.913s", "167h", "45m", "-2s" for an expired one).
	 *
	 * @param string $text Duration.
	 * @return int
	 */
	public static function duration( $text ) {
		$text = trim( (string) $text );
		if ( '' === $text || '-' === $text[0] ) {
			return 0;
		}
		if ( ! preg_match_all( '/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/', $text, $m, PREG_SET_ORDER ) ) {
			return 0;
		}
		$units   = array(
			'h'  => 3600,
			'm'  => 60,
			's'  => 1,
			'ms' => 0.001,
			'us' => 0.000001,
			'µs' => 0.000001,
			'ns' => 0.000000001,
		);
		$seconds = 0.0;
		foreach ( $m as $part ) {
			$seconds += (float) $part[1] * $units[ $part[2] ];
		}
		return (int) ceil( $seconds );
	}
}
