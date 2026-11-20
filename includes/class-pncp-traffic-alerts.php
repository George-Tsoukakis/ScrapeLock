<?php
/**
 * 3.12: what Traffic (PNCP_Traffic) tells the owner without being asked: an email when something unusual
 * happens (server errors or missing pages far above the usual, a new User-Agent that suddenly sends a lot, a
 * source that stopped delivering), a short "Traffic" part in the weekly attack report email and the dashboard
 * widget, and the Site Health test and info lines.
 *
 * The alerts are checked at the end of the scheduled run (PNCP_Traffic::run(), every 15 minutes), only while
 * collection ("traffic") and the alerts ("traffic_alerts") are on. Each kind of alert is sent at most once every
 * 6 hours (filter `pncp_traffic_alert_interval`); a stopped source once per stop. The thresholds can be changed
 * with the filter `pncp_traffic_alert_thresholds`. The emails are plain text and hold at most five paths,
 * User-Agents or IPs (the IPs as stored: masked with "traffic_ip_mode" masked).
 *
 * The usual level is the hourly average of the 7 days before the last hour, from the raw rows where they are
 * still kept and from the aggregates (hourly totals, daily keys) before that. Plain SELECTs only (MySQL / MariaDB
 * and the SQLite drop-in alike).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Traffic alerts, the weekly report part, Site Health.
 */
final class PNCP_Traffic_Alerts {

	/**
	 * Option with when each kind of alert was last sent, and the stops already reported (not autoloaded).
	 */
	const OPTION = 'pncp_traffic_alerts';

	/**
	 * The kinds of alert.
	 */
	const TYPES = array( '5xx', '404', 'ua', 'stopped' );

	/**
	 * Cache key of the dashboard widget's line.
	 */
	const WIDGET_CACHE = 'pncp_tr_widget';

	/**
	 * Default seconds between two emails of the same kind.
	 */
	const INTERVAL = 21600;

	/**
	 * Hours without data after which a source counts as stopped, and Site Health stops calling it current.
	 */
	const STOPPED_HOURS = 3;

	/**
	 * The alerts sent by the last check() of this request (for WP-CLI "run").
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private static $last = array();

	/**
	 * Probe verdicts of this request (path => bool).
	 *
	 * @var array<string, bool>
	 */
	private static $probe = array();

	/* ---------- Settings ---------- */

	/**
	 * Are the alerts on (collection and "traffic_alerts" both)?
	 *
	 * @return bool
	 */
	public static function enabled() {
		$s = PNCP_Options::get();
		return ! empty( $s['traffic'] ) && ! empty( $s['traffic_alerts'] );
	}

	/**
	 * Who gets the alerts: "traffic_alert_email" (addresses separated by commas), else the administration email,
	 * as the weekly attack report (filter `pncp_traffic_alert_recipients`).
	 *
	 * @return string[]
	 */
	public static function recipients() {
		$s    = PNCP_Options::get();
		$list = isset( $s['traffic_alert_email'] ) ? array_map( 'trim', explode( ',', (string) $s['traffic_alert_email'] ) ) : array();
		$list = array_values( array_filter( $list, 'strlen' ) );
		if ( ! $list ) {
			$list = array( (string) get_option( 'admin_email' ) );
		}
		/**
		 * Filters who gets the Traffic alert emails.
		 *
		 * @since 3.12.0
		 * @param string[] $to Email addresses.
		 */
		$to = (array) apply_filters( 'pncp_traffic_alert_recipients', $list );
		return array_values( array_unique( array_filter( array_map( 'sanitize_email', array_map( 'strval', $to ) ), 'is_email' ) ) );
	}

	/**
	 * The thresholds (filter `pncp_traffic_alert_thresholds`):
	 * - min_5xx, min_404: at least this many in the last hour (20);
	 * - factor: and this many times the usual hourly number (3);
	 * - share: and at least this part of all requests of the hour (0.02);
	 * - ua_hits: a new User-Agent with this many requests in the last hour (500), or
	 * - ua_share: this part of all requests (0.05), with at least ua_min requests (50);
	 * - new_hours: "new" = not seen in the 7 days before the last new_hours hours (3);
	 * - history_hours: the new User-Agent check needs this much history first (24);
	 * - stopped_hours: a source with no data for this long counts as stopped (3);
	 * - stopped_min_hourly: only when it usually brings at least this many requests an hour (10);
	 * - days: days of the usual level (7).
	 *
	 * @return array<string, float|int>
	 */
	public static function thresholds() {
		$defaults = array(
			'min_5xx'            => 20,
			'min_404'            => 20,
			'factor'             => 3,
			'share'              => 0.02,
			'ua_hits'            => 500,
			'ua_share'           => 0.05,
			'ua_min'             => 50,
			'new_hours'          => 3,
			'history_hours'      => 24,
			'stopped_hours'      => self::STOPPED_HOURS,
			'stopped_min_hourly' => 10,
			'days'               => 7,
		);
		/**
		 * Filters the thresholds of the Traffic alerts.
		 *
		 * @since 3.12.0
		 * @param array<string, float|int> $thresholds See PNCP_Traffic_Alerts::thresholds().
		 */
		$t   = (array) apply_filters( 'pncp_traffic_alert_thresholds', $defaults );
		$out = array();
		foreach ( $defaults as $key => $default ) {
			$value       = isset( $t[ $key ] ) && is_numeric( $t[ $key ] ) ? 0 + $t[ $key ] : $default;
			$out[ $key ] = max( 0, is_float( $default ) ? (float) $value : (int) round( (float) $value ) );
		}
		$out['days'] = max( 1, min( 60, (int) $out['days'] ) );
		return $out;
	}

	/**
	 * Seconds between two emails of one kind (filter `pncp_traffic_alert_interval`, default 6 hours).
	 *
	 * @param string $type Kind of alert.
	 * @return int
	 */
	public static function interval( $type ) {
		/**
		 * Filters how long after an alert email no other one of the same kind is sent.
		 *
		 * @since 3.12.0
		 * @param int    $seconds Seconds (default 6 hours).
		 * @param string $type    5xx | 404 | ua | stopped.
		 */
		return max( 0, (int) apply_filters( 'pncp_traffic_alert_interval', self::INTERVAL, $type ) );
	}

	/**
	 * The stored state, with every field present.
	 *
	 * @return array{sent: array<string, int>, stopped: array<string, int>}
	 */
	public static function state() {
		$s       = get_option( self::OPTION, array() );
		$s       = is_array( $s ) ? $s : array();
		$sent    = isset( $s['sent'] ) && is_array( $s['sent'] ) ? array_map( 'intval', $s['sent'] ) : array();
		$stopped = isset( $s['stopped'] ) && is_array( $s['stopped'] ) ? array_map( 'intval', $s['stopped'] ) : array();
		return array(
			'sent'    => $sent,
			'stopped' => $stopped,
		);
	}

	/**
	 * Saves the state (not autoloaded).
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function save_state( $state ) {
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, $state, '', false );
		} else {
			update_option( self::OPTION, $state, false );
		}
	}

	/**
	 * The Traffic tab, with filters filled in.
	 *
	 * Arguments the Traffic screen reads: view (overview | top | problems | raw | sources), from and to (Unix
	 * time), status (404, 5xx…), src, dim (with view=top), problem (with view=problems), ua, path.
	 *
	 * @param array<string, scalar> $args Arguments.
	 * @return string
	 */
	public static function tab_url( $args = array() ) {
		$args = array_map( 'strval', (array) $args );
		$args = array_merge(
			array( 'tab' => 'traffic' ),
			array_filter(
				$args,
				static function ( $value ) {
					return '' !== $value;
				}
			)
		);
		// add_query_arg() does not encode the values (a User-Agent has spaces, slashes, semicolons).
		$args = array_map( 'rawurlencode', $args );
		return class_exists( 'PNCP_Status' ) ? PNCP_Status::settings_url( $args ) : add_query_arg( $args, admin_url( 'options-general.php?page=scrapelock' ) );
	}

	/* ---------- The check ---------- */

	/**
	 * Checks every alert and emails those that fire (called by PNCP_Traffic::run(), after the rollup).
	 *
	 * @param int|null $now Unix time (tests; default now).
	 * @return array<string, array<string, mixed>> The alerts sent (kind => figures).
	 */
	public static function check( $now = null ) {
		self::$last = array();
		if ( ! self::enabled() || ! PNCP_Traffic::ready() ) {
			return array();
		}
		$now   = null === $now ? time() : (int) $now;
		$state = self::state();
		$found = self::evaluate( $now, $state );
		$sent  = array();
		foreach ( $found as $type => $alert ) {
			$type = (string) $type; // "404" is an integer key in a PHP array.
			$last = isset( $state['sent'][ $type ] ) ? (int) $state['sent'][ $type ] : 0;
			if ( $last > $now - self::interval( $type ) ) {
				continue;
			}
			if ( self::send( $type, $alert ) ) {
				$state['sent'][ $type ] = $now;
				if ( 'stopped' === $type ) {
					foreach ( $alert['sources'] as $src => $row ) {
						$state['stopped'][ $src ] = (int) $row['last'];
					}
				}
				$sent[ $type ] = $alert;
			}
		}
		// A source that delivers again may be reported again the next time it stops.
		foreach ( array_keys( $state['stopped'] ) as $src ) {
			if ( ! in_array( $src, PNCP_Traffic::SOURCES, true ) || self::last_row( $src ) > $state['stopped'][ $src ] ) {
				unset( $state['stopped'][ $src ] );
			}
		}
		self::save_state( $state );
		self::$last = $sent;
		return $sent;
	}

	/**
	 * The alerts sent by the last check() of this request.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function last_sent() {
		return self::$last;
	}

	/**
	 * Works out which alerts fire now, without sending anything.
	 *
	 * @param int                       $now   Unix time.
	 * @param array<string, mixed>|null $state state() (null = read it).
	 * @return array<string, array<string, mixed>> kind => figures.
	 */
	public static function evaluate( $now, $state = null ) {
		$state = null === $state ? self::state() : $state;
		$t     = self::thresholds();
		$src   = PNCP_Traffic::best_source();
		$out   = array();
		$from  = $now - HOUR_IN_SECONDS;
		$hour  = self::hour_counts( $src, $from, $now );
		$base  = self::baseline( $src, $from, $t['days'] );

		// Server errors.
		$need5 = max( (float) $t['min_5xx'], $t['factor'] * $base['avg_5xx'], $t['share'] * $hour['total'] );
		if ( $hour['total'] > 0 && $hour['s5xx'] > 0 && $hour['s5xx'] >= $need5 ) {
			$out['5xx'] = array(
				'src'     => $src,
				'from'    => $from,
				'to'      => $now,
				'count'   => $hour['s5xx'],
				'total'   => $hour['total'],
				'usual'   => $base['avg_5xx'],
				'hours'   => $base['hours'],
				'top'     => self::top_paths( $src, $from, $now, 500, 599 ),
				'percent' => 100 * $hour['s5xx'] / $hour['total'],
			);
		}

		// Pages not found, without the probes of scanners and the site's metadata files.
		$miss  = self::not_found( $src, $from, $now );
		$avg   = self::baseline_404( $src, $from, $t['days'], $base['first'] );
		$need4 = max( (float) $t['min_404'], $t['factor'] * $avg, $t['share'] * $hour['total'] );
		if ( $hour['total'] > 0 && $miss['count'] > 0 && $miss['count'] >= $need4 ) {
			$out['404'] = array(
				'src'     => $src,
				'from'    => $from,
				'to'      => $now,
				'count'   => $miss['count'],
				'total'   => $hour['total'],
				'usual'   => $avg,
				'hours'   => $base['hours'],
				'top'     => array_slice( $miss['paths'], 0, 5 ),
				'percent' => 100 * $miss['count'] / $hour['total'],
			);
		}

		// A new User-Agent that sends a lot.
		if ( $hour['total'] > 0 && $base['hours'] >= $t['history_hours'] ) {
			$uas = self::new_agents( $src, $from, $now, $hour['total'], $t );
			if ( $uas ) {
				$out['ua'] = array(
					'src'   => $src,
					'from'  => $from,
					'to'    => $now,
					'total' => $hour['total'],
					'top'   => array_slice( $uas, 0, 5 ),
				);
			}
		}

		// A source that stopped.
		$stopped = self::stopped_sources( $now, $t, $state );
		if ( $stopped ) {
			$out['stopped'] = array(
				'from'    => $now - (int) $t['stopped_hours'] * HOUR_IN_SECONDS,
				'to'      => $now,
				'sources' => $stopped,
			);
		}
		return $out;
	}

	/**
	 * Requests and server errors of one source in a range (raw rows).
	 *
	 * @param string $src  Source.
	 * @param int    $from Start.
	 * @param int    $to   End.
	 * @return array{total:int, s5xx:int}
	 */
	private static function hour_counts( $src, $from, $to ) {
		global $wpdb;
		$rows = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT COUNT(*) AS n, SUM(CASE WHEN status >= 500 AND status < 600 THEN 1 ELSE 0 END) AS s5 FROM %i WHERE src = %s AND ts >= %d AND ts <= %d', PNCP_Traffic::table( 'raw' ), $src, $from, $to ) );
		return array(
			'total' => isset( $rows[0]['n'] ) ? (int) $rows[0]['n'] : 0,
			's5xx'  => isset( $rows[0]['s5'] ) ? (int) $rows[0]['s5'] : 0,
		);
	}

	/**
	 * The usual hourly number of server errors before a moment: the days before it (raw rows inside the raw
	 * window, the hourly totals before it), divided by the hours since the source's first data in that range.
	 *
	 * @param string $src  Source.
	 * @param int    $end  End of the range (the start of the hour checked).
	 * @param int    $days Days.
	 * @return array{avg_5xx:float, hits:int, hours:float, first:int}
	 */
	private static function baseline( $src, $end, $days ) {
		global $wpdb;
		$start = $end - $days * DAY_IN_SECONDS;
		$floor = PNCP_Traffic::raw_floor();
		$s5    = 0;
		$hits  = 0;
		$first = 0;
		$a     = max( $start, $floor );
		if ( $a < $end ) {
			$r = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT COUNT(*) AS n, SUM(CASE WHEN status >= 500 AND status < 600 THEN 1 ELSE 0 END) AS s5, MIN(ts) AS f FROM %i WHERE src = %s AND ts >= %d AND ts < %d', PNCP_Traffic::table( 'raw' ), $src, $a, $end ) );
			if ( isset( $r[0]['n'] ) && (int) $r[0]['n'] > 0 ) {
				$hits += (int) $r[0]['n'];
				$s5   += (int) $r[0]['s5'];
				$first = (int) $r[0]['f'];
			}
		}
		if ( $start < $floor ) {
			$r = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT SUM(hits) AS n, SUM(s5xx) AS s5, MIN(hour_ts) AS f FROM %i WHERE src = %s AND hour_ts >= %d AND hour_ts < %d', PNCP_Traffic::table( 'hour' ), $src, $start, min( $floor, $end ) ) );
			if ( isset( $r[0]['n'] ) && (int) $r[0]['n'] > 0 ) {
				$hits += (int) $r[0]['n'];
				$s5   += (int) $r[0]['s5'];
				$first = (int) $r[0]['f']; // Earlier than any raw row.
			}
		}
		$hours = $first > 0 ? max( 1.0, ( $end - max( $start, $first ) ) / HOUR_IN_SECONDS ) : 0.0;
		return array(
			'avg_5xx' => $hours > 0 ? $s5 / $hours : 0.0,
			'hits'    => $hits,
			'hours'   => $hours,
			'first'   => $first,
		);
	}

	/**
	 * Is a path a probe of a scanner or one of the site's metadata files (never a "real page" that is missing)?
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	public static function is_noise( $path ) {
		$path = (string) $path;
		if ( ! isset( self::$probe[ $path ] ) ) {
			if ( count( self::$probe ) > 5000 ) {
				self::$probe = array();
			}
			self::$probe[ $path ] = PNCP_Paths::is_site_metadata( $path ) || PNCP_Log::is_probe_path( $path );
		}
		return self::$probe[ $path ];
	}

	/**
	 * The 404 answers of one source in a range on real pages (not probes, not metadata files), and the busiest
	 * paths.
	 *
	 * @param string $src  Source.
	 * @param int    $from Start.
	 * @param int    $to   End.
	 * @return array{count:int, paths:array<int, array{key:string, hits:int, ips:int}>}
	 */
	private static function not_found( $src, $from, $to ) {
		global $wpdb;
		$rows  = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT MAX(path) AS path, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips FROM %i WHERE src = %s AND status = 404 AND ts >= %d AND ts <= %d GROUP BY path_hash ORDER BY n DESC LIMIT 5000', PNCP_Traffic::table( 'raw' ), $src, $from, $to ) );
		$count = 0;
		$paths = array();
		foreach ( $rows as $r ) {
			if ( self::is_noise( (string) $r['path'] ) ) {
				continue;
			}
			$count  += (int) $r['n'];
			$paths[] = array(
				'key'  => (string) $r['path'],
				'hits' => (int) $r['n'],
				'ips'  => (int) $r['ips'],
			);
		}
		return array(
			'count' => $count,
			'paths' => $paths,
		);
	}

	/**
	 * The usual hourly number of 404 answers on real pages before a moment (raw rows in the raw window, the daily
	 * path keys before it).
	 *
	 * @param string $src   Source.
	 * @param int    $end   End of the range.
	 * @param int    $days  Days.
	 * @param int    $first The source's first data in the range (baseline()), 0 = none.
	 * @return float
	 */
	private static function baseline_404( $src, $end, $days, $first ) {
		global $wpdb;
		if ( $first <= 0 ) {
			return 0.0;
		}
		$start = $end - $days * DAY_IN_SECONDS;
		$floor = PNCP_Traffic::raw_floor();
		$count = 0;
		$a     = max( $start, $floor );
		if ( $a < $end ) {
			$rows = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT MAX(path) AS path, COUNT(*) AS n FROM %i WHERE src = %s AND status = 404 AND ts >= %d AND ts < %d GROUP BY path_hash ORDER BY n DESC LIMIT 5000', PNCP_Traffic::table( 'raw' ), $src, $a, $end ) );
			foreach ( $rows as $r ) {
				$count += self::is_noise( (string) $r['path'] ) ? 0 : (int) $r['n'];
			}
		}
		$from = $start;
		if ( $start < $floor ) {
			// Whole days only: the first day that starts inside the range.
			$day  = PNCP_Traffic::day_start( $start );
			$day  = $day < $start ? PNCP_Traffic::add_days( $day ) : $day;
			$from = min( $day, $floor );
			$rows = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT label, s404 FROM %i WHERE src = %s AND dim = %s AND day >= %d AND day < %d AND s404 > 0 AND k <> %s ORDER BY s404 DESC LIMIT 20000', PNCP_Traffic::table( 'day' ), $src, 'path', $day, $floor, PNCP_Traffic::OTHER ) );
			foreach ( $rows as $r ) {
				$count += self::is_noise( (string) $r['label'] ) ? 0 : (int) $r['s404'];
			}
		}
		$hours = max( 1.0, ( $end - max( $from, $first ) ) / HOUR_IN_SECONDS );
		return $count / $hours;
	}

	/**
	 * The busiest paths with a status in a range.
	 *
	 * @param string $src  Source.
	 * @param int    $from Start.
	 * @param int    $to   End.
	 * @param int    $low  Lowest status.
	 * @param int    $high Highest status.
	 * @return array<int, array{key:string, hits:int, ips:int}>
	 */
	private static function top_paths( $src, $from, $to, $low, $high ) {
		global $wpdb;
		$rows = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT MAX(path) AS path, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips FROM %i WHERE src = %s AND status >= %d AND status <= %d AND ts >= %d AND ts <= %d GROUP BY path_hash ORDER BY n DESC LIMIT 5', PNCP_Traffic::table( 'raw' ), $src, $low, $high, $from, $to ) );
		$out  = array();
		foreach ( $rows as $r ) {
			$out[] = array(
				'key'  => (string) $r['path'],
				'hits' => (int) $r['n'],
				'ips'  => (int) $r['ips'],
			);
		}
		return $out;
	}

	/**
	 * User-Agents of the last hour that send a lot, are neither a browser nor a verified search engine, and were
	 * not seen in the days before (raw rows of every source in the raw window, the daily User-Agent keys before).
	 *
	 * @param string                   $src   Source.
	 * @param int                      $from  Start of the hour.
	 * @param int                      $to    End.
	 * @param int                      $total Requests of the hour.
	 * @param array<string, float|int> $t     Thresholds.
	 * @return array<int, array<string, mixed>>
	 */
	private static function new_agents( $src, $from, $to, $total, $t ) {
		global $wpdb;
		$need = (int) ceil( min( (float) $t['ua_hits'], max( (float) $t['ua_min'], $t['ua_share'] * $total ) ) );
		$need = max( 1, $need );
		$rows = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT ua_hash, MAX(ua) AS ua, fam, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips, MIN(ts) AS f FROM %i WHERE src = %s AND ts >= %d AND ts <= %d GROUP BY ua_hash, fam HAVING COUNT(*) >= %d ORDER BY n DESC LIMIT 20', PNCP_Traffic::table( 'raw' ), $src, $from, $to, $need ) );
		$end  = $to - (int) $t['new_hours'] * HOUR_IN_SECONDS;
		$end  = min( $end, $from );
		$beg  = $end - (int) $t['days'] * DAY_IN_SECONDS;
		$out  = array();
		foreach ( $rows as $r ) {
			if ( in_array( (string) $r['fam'], array( 'browser', 'verified_bot' ), true ) ) {
				continue;
			}
			if ( self::agent_seen( (string) $r['ua_hash'], $beg, $end ) ) {
				continue;
			}
			$ips   = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT ip, COUNT(*) AS n FROM %i WHERE src = %s AND ua_hash = %s AND ts >= %d AND ts <= %d GROUP BY ip ORDER BY n DESC LIMIT 5', PNCP_Traffic::table( 'raw' ), $src, (string) $r['ua_hash'], $from, $to ) );
			$names = PNCP_Traffic_Ua::labels();
			$out[] = array(
				'key'     => (string) $r['ua'],
				'family'  => (string) $r['fam'],
				'label'   => isset( $names[ (string) $r['fam'] ] ) ? $names[ (string) $r['fam'] ] : (string) $r['fam'],
				'hits'    => (int) $r['n'],
				'ips'     => (int) $r['ips'],
				'percent' => $total > 0 ? 100 * (int) $r['n'] / $total : 0,
				'top_ips' => array_map(
					static function ( $row ) {
						return array(
							'ip'   => (string) $row['ip'],
							'hits' => (int) $row['n'],
						);
					},
					$ips
				),
			);
		}
		return $out;
	}

	/**
	 * Was a User-Agent seen between two moments (any source)?
	 *
	 * @param string $hash ua_hash.
	 * @param int    $from Start.
	 * @param int    $to   End (excluded).
	 * @return bool
	 */
	private static function agent_seen( $hash, $from, $to ) {
		global $wpdb;
		if ( $to <= $from ) {
			return false;
		}
		$floor = PNCP_Traffic::raw_floor();
		if ( max( $from, $floor ) < $to ) {
			$r = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT 1 AS x FROM %i WHERE ua_hash = %s AND ts >= %d AND ts < %d LIMIT 1', PNCP_Traffic::table( 'raw' ), $hash, max( $from, $floor ), $to ) );
			if ( $r ) {
				return true;
			}
		}
		if ( $from < $floor ) {
			$keys = array();
			foreach ( PNCP_Traffic_Ua::FAMILIES as $fam ) {
				$keys[] = PNCP_Traffic::hash( $hash . '|' . $fam );
			}
			$in = implode( ', ', array_fill( 0, count( $keys ), '%s' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Placeholders only.
			$r = PNCP_Traffic::rows( $wpdb->prepare( "SELECT 1 AS x FROM %i WHERE dim = %s AND k IN ({$in}) AND day >= %d AND day < %d LIMIT 1", array_merge( array( PNCP_Traffic::table( 'day' ), 'ua' ), $keys, array( PNCP_Traffic::day_start( $from ), min( $floor, $to ) ) ) ) );
			if ( $r ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The newest request stored of a source (raw rows; the hourly totals when the raw rows are gone).
	 *
	 * @param string $src Source.
	 * @return int Unix time, 0 = none.
	 */
	public static function last_row( $src ) {
		global $wpdb;
		$r = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT MAX(ts) AS t FROM %i WHERE src = %s', PNCP_Traffic::table( 'raw' ), $src ) );
		$t = isset( $r[0]['t'] ) ? (int) $r[0]['t'] : 0;
		if ( $t > 0 ) {
			return $t;
		}
		$r = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT MAX(hour_ts) AS t FROM %i WHERE src = %s', PNCP_Traffic::table( 'hour' ), $src ) );
		return isset( $r[0]['t'] ) && (int) $r[0]['t'] > 0 ? (int) $r[0]['t'] + HOUR_IN_SECONDS - 1 : 0;
	}

	/**
	 * Is a source collecting (set up), whatever it brings?
	 *
	 * @param string $src Source.
	 * @return bool
	 */
	public static function source_on( $src ) {
		$s = PNCP_Traffic::settings();
		if ( 'bunny' === $src ) {
			return PNCP_Traffic::bunny_on();
		}
		if ( 'server' === $src ) {
			return '' !== $s['log_path'];
		}
		return $s['wp'];
	}

	/**
	 * The sources that are set up, brought data before and usually bring at least stopped_min_hourly requests an
	 * hour, but brought nothing for stopped_hours hours. A stop already reported is not reported again.
	 *
	 * @param int                      $now   Unix time.
	 * @param array<string, float|int> $t     Thresholds.
	 * @param array<string, mixed>     $state state().
	 * @return array<string, array{last:int, usual:float, error:string}>
	 */
	private static function stopped_sources( $now, $t, $state ) {
		global $wpdb;
		$out    = array();
		$status = null;
		foreach ( PNCP_Traffic::SOURCES as $src ) {
			if ( ! self::source_on( $src ) ) {
				continue;
			}
			$last = self::last_row( $src );
			if ( $last <= 0 || $last >= $now - (int) $t['stopped_hours'] * HOUR_IN_SECONDS ) {
				continue;
			}
			if ( isset( $state['stopped'][ $src ] ) && (int) $state['stopped'][ $src ] >= $last ) {
				continue; // Reported already.
			}
			// How much it usually brought: the days before its last request.
			$r     = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT SUM(hits) AS n, MIN(hour_ts) AS f FROM %i WHERE src = %s AND hour_ts >= %d AND hour_ts <= %d', PNCP_Traffic::table( 'hour' ), $src, $last - (int) $t['days'] * DAY_IN_SECONDS, $last ) );
			$hits  = isset( $r[0]['n'] ) ? (int) $r[0]['n'] : 0;
			$first = isset( $r[0]['f'] ) ? (int) $r[0]['f'] : 0;
			if ( $hits <= 0 ) {
				// Not counted yet (the rollup is hourly): the raw rows.
				$r     = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT COUNT(*) AS n, MIN(ts) AS f FROM %i WHERE src = %s AND ts >= %d AND ts <= %d', PNCP_Traffic::table( 'raw' ), $src, $last - (int) $t['days'] * DAY_IN_SECONDS, $last ) );
				$hits  = isset( $r[0]['n'] ) ? (int) $r[0]['n'] : 0;
				$first = isset( $r[0]['f'] ) ? (int) $r[0]['f'] : 0;
			}
			$hours = $first > 0 ? max( 1.0, ( $last - $first ) / HOUR_IN_SECONDS ) : 1.0;
			$usual = $hits / $hours;
			if ( $usual < (float) $t['stopped_min_hourly'] ) {
				continue;
			}
			if ( null === $status ) {
				$status = PNCP_Traffic::sources_status();
			}
			$out[ $src ] = array(
				'last'  => $last,
				'usual' => $usual,
				'error' => isset( $status[ $src ]['error'] ) ? (string) $status[ $src ]['error'] : '',
			);
		}
		return $out;
	}

	/* ---------- The emails ---------- */

	/**
	 * The names of the sources.
	 *
	 * @return array<string, string>
	 */
	public static function source_names() {
		return array(
			'bunny'  => __( 'Bunny CDN logs', 'scrapelock' ),
			'server' => __( 'Web server access log', 'scrapelock' ),
			'wp'     => __( 'WordPress', 'scrapelock' ),
		);
	}

	/**
	 * A source's error code in words.
	 *
	 * @param string $src  bunny | server | wp.
	 * @param string $code Code (PNCP_Traffic::sources_status()).
	 * @param string $message The API's message (bunny api_error).
	 * @return string
	 */
	public static function error_text( $src, $code, $message = '' ) {
		$code = (string) $code;
		if ( '' === $code ) {
			return '';
		}
		if ( 'bunny' === $src ) {
			$texts = array(
				'not_connected' => __( 'The site is not connected to a Bunny CDN pull zone.', 'scrapelock' ),
				'import_off'    => __( '“Import attacks from Bunny CDN\'s logs” is off (or protection is off), so the CDN logs are not read.', 'scrapelock' ),
				'logging_off'   => __( 'Logging is off at the Bunny pull zone: there are no logs to read.', 'scrapelock' ),
				/* translators: %s: error message of the Bunny API */
				'api_error'     => sprintf( __( 'The last import of Bunny CDN\'s logs failed: %s', 'scrapelock' ), '' !== $message ? $message : '-' ),
			);
			return isset( $texts[ $code ] ) ? $texts[ $code ] : $code;
		}
		if ( 'server' === $src ) {
			return PNCP_Traffic_Log::refusal_text( $code );
		}
		return $code;
	}

	/**
	 * A count, as the emails show it.
	 *
	 * @param int|float $n Number.
	 * @param int       $decimals Decimals.
	 * @return string
	 */
	private static function num( $n, $decimals = 0 ) {
		return number_format_i18n( $n, $decimals );
	}

	/**
	 * A time, as the emails show it.
	 *
	 * @param int $ts Unix time.
	 * @return string
	 */
	private static function time_text( $ts ) {
		return (string) wp_date( (string) get_option( 'date_format' ) . ' ' . (string) get_option( 'time_format' ), (int) $ts );
	}

	/**
	 * The subject and the plain-text body of one alert.
	 *
	 * @param string               $type  Kind.
	 * @param array<string, mixed> $alert Figures (evaluate()).
	 * @return array{subject:string, body:string}
	 */
	public static function email( $type, $alert ) {
		$type  = (string) $type;
		$site  = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$names = self::source_names();
		$l     = array();
		$url   = '';
		if ( '5xx' === $type || '404' === $type ) {
			$is5     = '5xx' === $type;
			$subject = $is5
				/* translators: 1: site name, 2: number of server errors */
				? sprintf( __( '[%1$s] ScrapeLock: %2$s server errors (5xx) in the last hour', 'scrapelock' ), $site, self::num( $alert['count'] ) )
				/* translators: 1: site name, 2: number of pages not found */
				: sprintf( __( '[%1$s] ScrapeLock: %2$s pages not found (404) in the last hour', 'scrapelock' ), $site, self::num( $alert['count'] ) );
			$l[]     = sprintf(
				$is5
					/* translators: 1: number of server errors, 2: percent, 3: number of requests, 4: start time, 5: end time */
					? __( 'The site answered %1$s requests with a server error (5xx), %2$s%% of all %3$s requests, between %4$s and %5$s.', 'scrapelock' )
					/* translators: 1: number of 404 answers, 2: percent, 3: number of requests, 4: start time, 5: end time */
					: __( 'The site answered %1$s requests for pages with “not found” (404), %2$s%% of all %3$s requests, between %4$s and %5$s. Probes of scanners and files such as /llms.txt are not counted.', 'scrapelock' ),
				self::num( $alert['count'] ),
				self::num( $alert['percent'], 1 ),
				self::num( $alert['total'] ),
				self::time_text( $alert['from'] ),
				self::time_text( $alert['to'] )
			);
			$l[] = $alert['hours'] > 0
				/* translators: 1: usual number per hour, 2: days */
				? sprintf( __( 'Usually: %1$s per hour (average of the previous %2$s days).', 'scrapelock' ), self::num( $alert['usual'], 1 ), self::num( min( (int) self::thresholds()['days'], (int) ceil( $alert['hours'] / 24 ) ) ) )
				: __( 'There is no earlier data to compare with yet.', 'scrapelock' );
			/* translators: %s: name of the source */
			$l[] = sprintf( __( 'Source: %s.', 'scrapelock' ), isset( $names[ $alert['src'] ] ) ? $names[ $alert['src'] ] : $alert['src'] );
			if ( $alert['top'] ) {
				$l[] = '';
				$l[] = $is5 ? __( 'Addresses with the most server errors:', 'scrapelock' ) : __( 'Addresses not found most often:', 'scrapelock' );
				foreach ( array_slice( $alert['top'], 0, 5 ) as $row ) {
					/* translators: 1: path, 2: number of requests, 3: number of IP addresses */
					$l[] = '- ' . sprintf( __( '%1$s: %2$s (%3$s IPs)', 'scrapelock' ), PNCP_Log::display_path( $row['key'] ), self::num( $row['hits'] ), self::num( $row['ips'] ) );
				}
			}
			$l[] = '';
			$l[] = $is5 ? __( 'A plugin or theme update, the database or the server\'s PHP workers are the usual causes. The server\'s error log says more.', 'scrapelock' ) : __( 'A deleted or moved page that is still linked (from the site itself, a sitemap or another site) is the usual cause: redirect it, or fix the link.', 'scrapelock' );
			$url = self::tab_url(
				array(
					'view'    => 'problems',
					'problem' => $is5 ? '5xx' : '404',
					'from'    => $alert['from'],
					'to'      => $alert['to'],
					'status'  => $is5 ? '5xx' : '404',
					'src'     => $alert['src'],
				)
			);
		} elseif ( 'ua' === $type ) {
			$first   = $alert['top'][0];
			$subject = sprintf(
				/* translators: 1: site name, 2: number of requests, 3: kind of User-Agent */
				__( '[%1$s] ScrapeLock: a new User-Agent sent %2$s requests in the last hour (%3$s)', 'scrapelock' ),
				$site,
				self::num( $first['hits'] ),
				$first['label']
			);
			$l[] = sprintf(
				/* translators: 1: number of requests, 2: start time, 3: end time, 4: days */
				__( 'Between %2$s and %3$s the site received %1$s requests in all. These User-Agents sent many of them and were not seen in the %4$s days before:', 'scrapelock' ),
				self::num( $alert['total'] ),
				self::time_text( $alert['from'] ),
				self::time_text( $alert['to'] ),
				self::num( (int) self::thresholds()['days'] )
			);
			foreach ( array_slice( $alert['top'], 0, 5 ) as $row ) {
				$l[] = '';
				$l[] = '- ' . ( '' !== $row['key'] ? $row['key'] : __( '(no User-Agent)', 'scrapelock' ) );
				/* translators: 1: kind of User-Agent, 2: number of requests, 3: percent of all requests, 4: number of IP addresses */
				$l[] = '  ' . sprintf( __( '%1$s: %2$s requests (%3$s%%) from %4$s IPs', 'scrapelock' ), $row['label'], self::num( $row['hits'] ), self::num( $row['percent'], 1 ), self::num( $row['ips'] ) );
				if ( $row['top_ips'] ) {
					$ips = array();
					foreach ( array_slice( $row['top_ips'], 0, 5 ) as $ip ) {
						$ips[] = $ip['ip'] . ' (' . self::num( $ip['hits'] ) . ')';
					}
					/* translators: %s: list of IP addresses with their requests */
					$l[] = '  ' . sprintf( __( 'Most from: %s', 'scrapelock' ), implode( ', ', $ips ) );
				}
			}
			$l[] = '';
			$l[] = __( 'A new crawler, an uptime or SEO service someone set up, or a scraper. If it is not welcome, add it to the bot list (Bots and limits tab).', 'scrapelock' );
			$url = self::tab_url(
				array(
					'view' => 'raw',
					'from' => $alert['from'],
					'to'   => $alert['to'],
					'ua'   => $first['key'],
					'src'  => $alert['src'],
				)
			);
		} else {
			$subject = sprintf(
				/* translators: %s: site name */
				__( '[%s] ScrapeLock: a traffic source stopped delivering data', 'scrapelock' ),
				$site
			);
			foreach ( $alert['sources'] as $src => $row ) {
				$l[] = sprintf(
					/* translators: 1: name of the source, 2: date and time, 3: usual requests per hour */
					__( '%1$s: no requests since %2$s, while it usually brings %3$s requests an hour.', 'scrapelock' ),
					isset( $names[ $src ] ) ? $names[ $src ] : $src,
					self::time_text( $row['last'] ),
					self::num( $row['usual'], 1 )
				);
				$why = self::error_text( $src, $row['error'] );
				if ( '' !== $why ) {
					/* translators: %s: why the source does not deliver */
					$l[] = '  ' . sprintf( __( 'Last error: %s', 'scrapelock' ), $why );
				}
			}
			$l[] = '';
			$l[] = __( 'The Traffic tab shows each source and its last error. Until it works again, the figures miss these requests.', 'scrapelock' );
			$url = self::tab_url(
				array(
					'view' => 'sources',
					'from' => $alert['from'],
					'to'   => $alert['to'],
				)
			);
		}
		$l[] = '';
		$l[] = __( 'Open the Traffic tab:', 'scrapelock' );
		$l[] = $url;
		$l[] = '';
		$l[] = __( 'You get this email because “Email me about unusual traffic” is on in ScrapeLock (Traffic tab). At most one email of each kind is sent every 6 hours.', 'scrapelock' );
		return array(
			'subject' => $subject,
			'body'    => implode( "\n", $l ),
		);
	}

	/**
	 * Sends one alert.
	 *
	 * @param string               $type  Kind.
	 * @param array<string, mixed> $alert Figures.
	 * @return bool
	 */
	private static function send( $type, $alert ) {
		$to = self::recipients();
		if ( ! $to ) {
			return false;
		}
		$mail = self::email( $type, $alert );
		return (bool) wp_mail( $to, $mail['subject'], $mail['body'] );
	}

	/* ---------- Weekly report, dashboard ---------- */

	/**
	 * The "Traffic" part of the weekly attack report email (PNCP_Attack_Report::email()): requests, the share
	 * of 4xx and 5xx answers, the three addresses with the most errors and the three busiest User-Agents that are
	 * not browsers. Empty while collection is off.
	 *
	 * @param int $days Days.
	 * @return string[] Lines.
	 */
	public static function report_lines( $days = 7 ) {
		if ( ! PNCP_Traffic::enabled() || ! PNCP_Traffic::ready() ) {
			return array();
		}
		$days = max( 1, (int) $days );
		$f    = array(
			'from' => time() - $days * DAY_IN_SECONDS,
			'to'   => time(),
		);
		$o    = PNCP_Traffic::overview( $f );
		$num  = static function ( $n, $d = 0 ) {
			return number_format_i18n( $n, $d );
		};
		$pct  = static function ( $n ) use ( $o, $num ) {
			return $num( $o['total'] > 0 ? 100 * $n / $o['total'] : 0, 1 );
		};
		$l    = array( '', __( 'Traffic:', 'scrapelock' ) );
		/* translators: 1: requests, 2: IP addresses, 3: percent 4xx, 4: percent 5xx */
		$l[] = sprintf( __( 'Requests: %1$s from %2$s IPs; not found and other 4xx answers: %3$s%%, server errors (5xx): %4$s%%.', 'scrapelock' ), $num( $o['total'] ), $num( $o['ips'] ), $pct( $o['s4xx'] ), $pct( $o['s5xx'] ) );
		$problems = array();
		foreach ( array( '5xx', '404' ) as $type ) {
			$res = PNCP_Traffic::problems( $type, $f, 20 );
			foreach ( $res['rows'] as $row ) {
				if ( '404' === $type && self::is_noise( (string) $row['path'] ) ) {
					continue;
				}
				$key = (string) $row['path'];
				if ( ! isset( $problems[ $key ] ) ) {
					$problems[ $key ] = array(
						'hits'     => 0,
						'statuses' => array(),
					);
				}
				$problems[ $key ]['hits'] += (int) $row['hits'];
				foreach ( (array) $row['statuses'] as $code => $n ) {
					$problems[ $key ]['statuses'][ (string) $code ] = (int) $n;
				}
			}
		}
		uasort(
			$problems,
			static function ( $a, $b ) {
				return $b['hits'] <=> $a['hits'];
			}
		);
		if ( $problems ) {
			$l[] = __( 'Addresses with the most errors:', 'scrapelock' );
			foreach ( array_slice( $problems, 0, 3, true ) as $path => $row ) {
				$l[] = sprintf( '- %1$s: %2$s (%3$s)', PNCP_Log::display_path( (string) $path ), $num( $row['hits'] ), implode( ', ', array_keys( $row['statuses'] ) ) );
			}
		}
		$uas   = PNCP_Traffic::top( 'ua', $f, 50 );
		$names = PNCP_Traffic_Ua::labels();
		$shown = 0;
		foreach ( $uas['rows'] as $row ) {
			$fam = isset( $row['family'] ) ? (string) $row['family'] : '';
			if ( 'browser' === $fam || PNCP_Traffic::OTHER === (string) $row['key'] ) {
				continue;
			}
			if ( 0 === $shown ) {
				$l[] = __( 'Busiest User-Agents that are not browsers:', 'scrapelock' );
			}
			$l[] = sprintf( '- %1$s (%2$s): %3$s', '' !== (string) $row['key'] ? (string) $row['key'] : __( '(no User-Agent)', 'scrapelock' ), isset( $names[ $fam ] ) ? $names[ $fam ] : $fam, $num( $row['hits'] ) );
			if ( ++$shown >= 3 ) {
				break;
			}
		}
		$l[] = self::tab_url(
			array(
				'view' => 'overview',
				'from' => $f['from'],
				'to'   => $f['to'],
			)
		);
		return $l;
	}

	/**
	 * The dashboard widget's Traffic line (7 days; one query result, kept 10 minutes). Nothing while collection
	 * is off.
	 */
	public static function widget_line() {
		if ( ! PNCP_Traffic::enabled() || ! PNCP_Traffic::ready() ) {
			return;
		}
		$o = PNCP_Log::cache_get( self::WIDGET_CACHE );
		if ( ! is_array( $o ) || ! isset( $o['total'] ) ) {
			$o = PNCP_Traffic::overview(
				array(
					'from' => time() - 7 * DAY_IN_SECONDS,
					'to'   => time(),
				)
			);
			$o = array_intersect_key( $o, array_flip( array( 'total', 's4xx', 's5xx' ) ) );
			PNCP_Log::cache_set( self::WIDGET_CACHE, $o, 10 * MINUTE_IN_SECONDS );
		}
		$total = (int) $o['total'];
		$pct   = static function ( $n ) use ( $total ) {
			return number_format_i18n( $total > 0 ? 100 * (int) $n / $total : 0, 1 );
		};
		printf(
			'<p class="pncp-ar__widget-traffic">%1$s <a href="%2$s">%3$s</a></p>',
			esc_html(
				sprintf(
					/* translators: 1: requests, 2: percent 4xx, 3: percent 5xx */
					__( 'Traffic, 7 days: %1$s requests, %2$s%% 4xx, %3$s%% 5xx.', 'scrapelock' ),
					number_format_i18n( $total ),
					$pct( $o['s4xx'] ),
					$pct( $o['s5xx'] )
				)
			),
			esc_url( self::tab_url() ),
			esc_html__( 'Traffic tab', 'scrapelock' )
		);
	}

	/* ---------- Site Health ---------- */

	/**
	 * Adds the Site Health test while collection is on (filter site_status_tests, PNCP_Health::tests()).
	 *
	 * @param array<string, mixed> $tests Tests.
	 * @return array<string, mixed>
	 */
	public static function health_tests( $tests ) {
		if ( PNCP_Traffic::enabled() ) {
			$tests['direct']['scrapelock_traffic'] = array(
				'label' => __( 'ScrapeLock traffic statistics', 'scrapelock' ),
				'test'  => array( __CLASS__, 'health_test' ),
			);
		}
		return $tests;
	}

	/**
	 * Raw rows stored, and the cap on them.
	 *
	 * @return array{rows:int, cap:int}
	 */
	public static function raw_size() {
		global $wpdb;
		$r = PNCP_Traffic::ready() ? PNCP_Traffic::rows( $wpdb->prepare( 'SELECT COUNT(*) AS n FROM %i', PNCP_Traffic::table( 'raw' ) ) ) : array();
		/** This filter is documented in includes/class-pncp-traffic.php */
		$cap = (int) apply_filters( 'pncp_traffic_max_raw_rows', PNCP_Traffic::MAX_RAW_ROWS );
		return array(
			'rows' => isset( $r[0]['n'] ) ? (int) $r[0]['n'] : 0,
			'cap'  => $cap,
		);
	}

	/**
	 * The Site Health test "ScrapeLock traffic statistics": good when the source in use delivered data in the
	 * last 3 hours; recommended when a source that is set up reports an error, when no source is set up, when the
	 * source in use brought nothing for 3 hours, when the daily figures are behind, or when the raw rows are near
	 * their cap.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_test() {
		$status = PNCP_Traffic::sources_status();
		$names  = self::source_names();
		$src    = (string) $status['auto'];
		$issues = array();
		$any    = false;
		foreach ( PNCP_Traffic::SOURCES as $one ) {
			if ( ! self::source_on( $one ) ) {
				continue;
			}
			$any  = true;
			$code = (string) $status[ $one ]['error'];
			if ( '' !== $code && ! in_array( $code, array( 'not_connected', 'import_off', 'not_set' ), true ) ) {
				$issues[] = ( isset( $names[ $one ] ) ? $names[ $one ] : $one ) . ': ' . self::error_text( $one, $code, isset( $status[ $one ]['error_message'] ) ? (string) $status[ $one ]['error_message'] : '' );
			}
		}
		if ( ! $any ) {
			$issues[] = __( 'No source is set up: connect Bunny CDN and import its logs, enter the web server\'s access log, or let WordPress record the pages it serves.', 'scrapelock' );
		}
		$last = (int) $status[ $src ]['last_ingest'];
		if ( $any && $last < time() - self::STOPPED_HOURS * HOUR_IN_SECONDS ) {
			$issues[] = $last > 0
				/* translators: 1: name of the source, 2: date and time */
				? sprintf( __( '%1$s, the source in use, brought no request since %2$s.', 'scrapelock' ), isset( $names[ $src ] ) ? $names[ $src ] : $src, self::time_text( $last ) )
				/* translators: %s: name of the source */
				: sprintf( __( '%s, the source in use, has not brought any request yet.', 'scrapelock' ), isset( $names[ $src ] ) ? $names[ $src ] : $src );
		}
		$roll = $status['rollup'];
		if ( (int) $roll['pending'] > 0 || ( $last > 0 && (int) $roll['rolled_at'] < time() - 3 * HOUR_IN_SECONDS ) ) {
			$issues[] = (int) $roll['pending'] > 0
				/* translators: %s: number of days */
				? sprintf( _n( 'The daily figures are behind: %s day is waiting to be counted. WordPress\'s scheduled events (WP-Cron) may not run often enough.', 'The daily figures are behind: %s days are waiting to be counted. WordPress\'s scheduled events (WP-Cron) may not run often enough.', (int) $roll['pending'], 'scrapelock' ), number_format_i18n( (int) $roll['pending'] ) )
				: __( 'The daily figures were not counted in the last 3 hours: WordPress\'s scheduled events (WP-Cron) may not run.', 'scrapelock' );
		}
		$size = self::raw_size();
		if ( $size['cap'] > 0 && $size['rows'] >= 0.9 * $size['cap'] ) {
			$issues[] = sprintf(
				/* translators: 1: rows stored, 2: most rows kept */
				__( 'The record of single requests holds %1$s rows of at most %2$s: the oldest are deleted early. Keep each request for fewer days.', 'scrapelock' ),
				number_format_i18n( $size['rows'] ),
				number_format_i18n( $size['cap'] )
			);
		}
		$link = '<p><a href="' . esc_url( self::tab_url( array( 'view' => 'sources' ) ) ) . '">' . esc_html__( 'Open the Traffic tab', 'scrapelock' ) . '</a></p>';
		if ( ! $issues ) {
			return array(
				'label'       => __( 'ScrapeLock traffic statistics are up to date', 'scrapelock' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'scrapelock' ),
					'color' => 'blue',
				),
				/* translators: 1: name of the source, 2: date and time */
				'description' => '<p>' . esc_html( sprintf( __( '%1$s delivered requests in the last 3 hours (the newest at %2$s).', 'scrapelock' ), isset( $names[ $src ] ) ? $names[ $src ] : $src, self::time_text( $last ) ) ) . '</p>',
				'actions'     => $link,
				'test'        => 'scrapelock_traffic',
			);
		}
		$items = '';
		foreach ( $issues as $issue ) {
			$items .= '<li>' . esc_html( $issue ) . '</li>';
		}
		return array(
			'label'       => __( 'ScrapeLock traffic statistics need attention', 'scrapelock' ),
			'status'      => 'recommended',
			'badge'       => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'orange',
			),
			'description' => '<p>' . esc_html__( 'Traffic is collected, but the figures may be incomplete:', 'scrapelock' ) . '</p><ul>' . $items . '</ul>',
			'actions'     => $link,
			'test'        => 'scrapelock_traffic',
		);
	}

	/**
	 * The lines of the Site Health info section (PNCP_Health::info()): on or off with the source in use, and while
	 * on the raw rows and the first and last day of the daily figures.
	 *
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function info_fields() {
		global $wpdb;
		$no = __( 'No', 'scrapelock' );
		if ( ! PNCP_Traffic::enabled() ) {
			return array( 'traffic' => array( __( 'Traffic statistics', 'scrapelock' ), $no ) );
		}
		$names = self::source_names();
		$src   = PNCP_Traffic::best_source();
		$out   = array(
			/* translators: %s: name of the source in use */
			'traffic' => array( __( 'Traffic statistics', 'scrapelock' ), sprintf( __( 'Yes, from: %s', 'scrapelock' ), isset( $names[ $src ] ) ? $names[ $src ] : $src ) ),
		);
		if ( PNCP_Traffic::ready() ) {
			$size  = self::raw_size();
			$r     = PNCP_Traffic::rows( $wpdb->prepare( 'SELECT MIN(hour_ts) AS a, MAX(hour_ts) AS b FROM %i', PNCP_Traffic::table( 'hour' ) ) );
			$first = isset( $r[0]['a'] ) ? (int) $r[0]['a'] : 0;
			$lastd = isset( $r[0]['b'] ) ? (int) $r[0]['b'] : 0;
			$out['traffic_data'] = array(
				__( 'Traffic data', 'scrapelock' ),
				sprintf(
					/* translators: 1: rows, 2: first day, 3: last day */
					__( '%1$s requests stored; daily figures from %2$s to %3$s', 'scrapelock' ),
					number_format_i18n( $size['rows'] ),
					$first ? wp_date( 'Y-m-d', $first ) : '-',
					$lastd ? wp_date( 'Y-m-d', $lastd ) : '-'
				),
			);
		}
		return $out;
	}

	/* ---------- Uninstall ---------- */

	/**
	 * Deletes the option and the cached widget line.
	 */
	public static function uninstall() {
		delete_option( self::OPTION );
		PNCP_Log::cache_delete( self::WIDGET_CACHE );
	}
}
