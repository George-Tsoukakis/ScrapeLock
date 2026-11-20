<?php
/**
 * 3.12: reading the Traffic data (PNCP_Traffic): totals and a time series, the top keys of a dimension, the
 * problems (not found, server errors, redirects, uncached pages, large and slow responses), one User-Agent, path
 * or IP in detail, the raw requests and a CSV export. Read only, for wp-admin and WP-CLI (nothing of it is shown
 * publicly and there is no REST route).
 *
 * Every method takes the same filters (see filters()). A range that starts inside the raw window
 * (PNCP_Traffic::raw_floor()) is answered from the raw rows: exact, with every filter. A longer range is answered
 * from the aggregates (whole days, at most an hour behind), which hold one dimension at a time: a filter the
 * aggregates cannot answer (two dimensions at once, a search, the cache status…) is applied to the raw window
 * only, and the result says so ("clipped" true, "from" moved to the start of the raw window). Every result carries
 * src_used, from, to, basis (raw | agg) and clipped. Unique IPs are exact on raw rows; over the aggregates they
 * are added up per day ("ips_approx" true).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Traffic queries.
 */
final class PNCP_Traffic_Query {

	/**
	 * Most rows one page may ask for.
	 */
	const MAX_LIMIT = 500;

	/**
	 * Default most rows of a CSV export (filter `pncp_traffic_csv_max_rows`).
	 */
	const CSV_MAX = 100000;

	/**
	 * Seconds a result is cached (it is also counted again as soon as a row is added).
	 */
	const CACHE_TTL = 60;

	/**
	 * Most keys (groups) one raw top() / problems() query reads: up to this many the number of keys is exact
	 * (total_rows), beyond it unknown (-1, has_more says whether there is a next page). Saves a second pass over
	 * the rows only to count them.
	 */
	const GROUPS = 1000;

	/**
	 * Most raw rows a detail (one User-Agent, path or IP) reads in one pass for its breakdowns: of a busier key
	 * the newest ones (the result is "clipped" to the first of them).
	 */
	const DETAIL_SCAN = 200000;

	/**
	 * Raw rows per batch of that pass.
	 */
	const SCAN_BATCH = 10000;

	/**
	 * The dimensions top() takes.
	 */
	const TOP = array( 'ua', 'ua_family', 'path', 'referer', 'ip', 'country', 'status' );

	/**
	 * The problems problems() takes.
	 */
	const PROBLEMS = array( '404', '5xx', '3xx', 'uncached', 'large', 'slow' );

	/**
	 * The filters, checked: from, to (Unix time; default the last 24 hours, never before the aggregates' first
	 * day), src (auto | bunny | server | wp; auto = PNCP_Traffic::best_source()), status (a code such as 404, or
	 * "4xx"), ua (exact), ua_family (PNCP_Traffic_Ua::FAMILIES), path (exact, without the query), path_like
	 * (part of the path), ip (exact; masked like the stored ones with "traffic_ip_mode" masked), country (two
	 * letters), cache (HIT | MISS), search (part of the path or of the User-Agent). Anything else is ignored.
	 *
	 * @param mixed $filters Filters.
	 * @return array{from:int, to:int, src:string, status:array{0:int, 1:int}|null, ua:string, ua_family:string, path:string, path_like:string, ip:string, country:string, cache:string, search:string}
	 */
	public static function filters( $filters ) {
		$f    = is_array( $filters ) ? $filters : array();
		$get  = static function ( $key ) use ( $f ) {
			return isset( $f[ $key ] ) && is_scalar( $f[ $key ] ) ? trim( (string) $f[ $key ] ) : '';
		};
		$now  = time();
		$to   = is_numeric( $get( 'to' ) ) ? (int) $get( 'to' ) : $now;
		$to   = min( $to, $now + HOUR_IN_SECONDS );
		$from = is_numeric( $get( 'from' ) ) ? (int) $get( 'from' ) : $to - DAY_IN_SECONDS;
		$from = max( $from, PNCP_Traffic::agg_floor() );
		$from = min( $from, $to );
		$src  = $get( 'src' );
		$src  = in_array( $src, PNCP_Traffic::SOURCES, true ) ? $src : PNCP_Traffic::best_source();

		$status = null;
		$raw    = strtolower( $get( 'status' ) );
		if ( isset( $f['status'] ) && is_array( $f['status'] ) && 2 === count( $f['status'] ) ) {
			$status = array( (int) reset( $f['status'] ), (int) end( $f['status'] ) ); // Already checked (filters() output).
		} elseif ( preg_match( '/^([1-5])xx$/', $raw, $m ) ) {
			$status = array( (int) $m[1] * 100, (int) $m[1] * 100 + 99 );
		} elseif ( preg_match( '/^[1-9]\d\d$/', $raw ) ) {
			$status = array( (int) $raw, (int) $raw );
		}
		$path = $get( 'path' );
		if ( '' !== $path ) {
			$path = explode( '?', $path, 2 )[0];
			$path = PNCP_Traffic::text( '/' === $path[0] ? $path : '/' . $path, 512 );
		}
		$ip = PNCP_Ip::normalize( $get( 'ip' ) );
		if ( '' !== $ip && 'masked' === PNCP_Traffic::settings()['ip_mode'] ) {
			$ip = PNCP_Traffic::mask_ip( $ip );
		}
		$family  = $get( 'ua_family' );
		$country = strtoupper( $get( 'country' ) );
		$cache   = strtoupper( $get( 'cache' ) );
		return array(
			'from'      => $from,
			'to'        => $to,
			'src'       => $src,
			'status'    => $status,
			'ua'        => PNCP_Traffic::text( $get( 'ua' ), 255 ),
			'ua_family' => in_array( $family, PNCP_Traffic_Ua::FAMILIES, true ) ? $family : '',
			'path'      => $path,
			'path_like' => PNCP_Traffic::text( $get( 'path_like' ), 200 ),
			'ip'        => $ip,
			'country'   => preg_match( '/^[A-Z]{2}$/', $country ) ? $country : '',
			'cache'     => in_array( $cache, array( 'HIT', 'MISS' ), true ) ? $cache : '',
			'search'    => PNCP_Traffic::text( $get( 'search' ), 200 ),
		);
	}

	/**
	 * The dimension filters that are set.
	 *
	 * @param array<string, mixed> $f Filters (filters()).
	 * @return string[]
	 */
	private static function set_filters( $f ) {
		$out = array();
		foreach ( array( 'status', 'ua', 'ua_family', 'path', 'path_like', 'ip', 'country', 'cache', 'search' ) as $key ) {
			if ( null !== $f[ $key ] && '' !== $f[ $key ] ) {
				$out[] = $key;
			}
		}
		return $out;
	}

	/**
	 * Does the range start inside the raw window?
	 *
	 * @param array<string, mixed> $f Filters.
	 * @return bool
	 */
	private static function in_raw( $f ) {
		return (int) $f['from'] >= PNCP_Traffic::raw_floor();
	}

	/**
	 * The filters moved to the raw window (for what the aggregates cannot answer), and whether they were moved.
	 *
	 * @param array<string, mixed> $f Filters.
	 * @return array{0:array<string, mixed>, 1:bool}
	 */
	private static function clip( $f ) {
		$floor = PNCP_Traffic::raw_floor();
		if ( (int) $f['from'] >= $floor ) {
			return array( $f, false );
		}
		$f['from'] = min( $floor, (int) $f['to'] );
		return array( $f, true );
	}

	/**
	 * What every result carries.
	 *
	 * @param array<string, mixed> $f       Filters used.
	 * @param string               $basis   raw | agg.
	 * @param bool                 $clipped The range was moved to the raw window.
	 * @return array{src_used:string, from:int, to:int, basis:string, clipped:bool, ips_approx:bool}
	 */
	private static function meta( $f, $basis, $clipped ) {
		return array(
			'src_used'   => (string) $f['src'],
			'from'       => (int) $f['from'],
			'to'         => (int) $f['to'],
			'basis'      => $basis,
			'clipped'    => $clipped,
			'ips_approx' => 'agg' === $basis,
		);
	}

	/**
	 * The WHERE of a raw query: SQL with placeholders and its values.
	 *
	 * @param array<string, mixed> $f Filters.
	 * @return array{0:string, 1:array<int, mixed>}
	 */
	private static function raw_where( $f ) {
		global $wpdb;
		$w    = array( 'src = %s', 'ts >= %d', 'ts <= %d' );
		$args = array( (string) $f['src'], (int) $f['from'], (int) $f['to'] );
		if ( null !== $f['status'] ) {
			$w[]    = 'status >= %d AND status <= %d';
			$args[] = (int) $f['status'][0];
			$args[] = (int) $f['status'][1];
		}
		// The User-Agent and the path by their hashes only (64 bits), which the covering index holds: the
		// queries then read the index, not the rows.
		if ( '' !== $f['ua'] ) {
			$w[]    = 'ua_hash = %s';
			$args[] = PNCP_Traffic::hash( $f['ua'] );
		}
		if ( '' !== $f['ua_family'] ) {
			$w[]    = 'fam = %s';
			$args[] = $f['ua_family'];
		}
		if ( '' !== $f['path'] ) {
			$w[]    = 'path_hash = %s';
			$args[] = PNCP_Traffic::hash( $f['path'] );
		}
		if ( '' !== $f['path_like'] ) {
			$w[]    = 'path LIKE %s';
			$args[] = '%' . $wpdb->esc_like( $f['path_like'] ) . '%';
		}
		if ( '' !== $f['ip'] ) {
			$w[]    = 'ip = %s';
			$args[] = $f['ip'];
		}
		if ( '' !== $f['country'] ) {
			$w[]    = 'country = %s';
			$args[] = $f['country'];
		}
		if ( '' !== $f['cache'] ) {
			$w[] = 'HIT' === $f['cache'] ? 'hit = 1' : 'hit = 0';
		}
		if ( '' !== $f['search'] ) {
			$w[]    = '(path LIKE %s OR ua LIKE %s)';
			$like   = '%' . $wpdb->esc_like( $f['search'] ) . '%';
			$args[] = $like;
			$args[] = $like;
		}
		return array( implode( ' AND ', $w ), $args );
	}

	/**
	 * Runs a query built from SQL with placeholders (the first one %i for the table).
	 *
	 * @param string            $sql  SQL.
	 * @param array<int, mixed> $args Values.
	 * @return array<int, array<string, mixed>>
	 */
	private static function q( $sql, $args ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Built from fixed SQL with placeholders only; the values are prepared here.
		return PNCP_Traffic::rows( $wpdb->prepare( $sql, $args ) );
	}

	/**
	 * Prepares SQL built from fixed parts with placeholders only.
	 *
	 * @param string            $sql  SQL.
	 * @param array<int, mixed> $args Values.
	 * @return string
	 */
	private static function sql( $sql, $args ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Built from fixed SQL with placeholders only; the values are prepared here.
		return (string) $wpdb->prepare( $sql, $args );
	}

	/**
	 * A result, cached for CACHE_TTL seconds and counted again as soon as a row is added or the aggregates change.
	 *
	 * @param string   $name    Name and arguments.
	 * @param callable $compute Computes it.
	 * @return array<string, mixed>
	 */
	private static function cached( $name, $compute ) {
		global $wpdb;
		static $memo = array();
		if ( ! PNCP_Traffic::ready() ) {
			return $compute();
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, primary key.
		$max   = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MAX(id) FROM %i', PNCP_Traffic::table( 'raw' ) ) );
		$state = PNCP_Traffic::state();
		$key   = 'pncp_tr_q_' . md5( $name . '|' . $max . '|' . (int) $state['rolled_at'] . '|' . (int) get_option( PNCP_Traffic::GEN_OPTION, 0 ) . '|' . PNCP_Traffic::raw_floor() );
		if ( isset( $memo[ $key ] ) ) {
			return $memo[ $key ];
		}
		$cli   = defined( 'WP_CLI' ) && WP_CLI;
		$value = $cli ? false : PNCP_Log::cache_get( $key );
		if ( ! is_array( $value ) ) {
			$value = $compute();
			if ( ! $cli ) {
				PNCP_Log::cache_set( $key, $value, self::CACHE_TTL );
			}
		}
		if ( count( $memo ) > 50 ) {
			$memo = array();
		}
		$memo[ $key ] = $value;
		return $value;
	}

	/**
	 * Hourly buckets for ranges up to 3 days, daily ones beyond.
	 *
	 * @param array<string, mixed> $f Filters.
	 * @return string hour | day.
	 */
	private static function step( $f ) {
		return (int) $f['to'] - (int) $f['from'] <= 3 * DAY_IN_SECONDS ? 'hour' : 'day';
	}

	/**
	 * Empty buckets from the start of the range to its end.
	 *
	 * @param int    $from Start.
	 * @param int    $to   End.
	 * @param string $step hour | day.
	 * @return array<int, array{t:int, hits:int, s4xx:int, s5xx:int}> start => bucket.
	 */
	private static function buckets( $from, $to, $step ) {
		$out = array();
		$day = PNCP_Traffic::day_start( $from );
		if ( 'hour' === $step ) {
			$t = $day + (int) floor( ( $from - $day ) / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS;
			for ( $i = 0; $t <= $to && $i < 2000; $i++, $t += HOUR_IN_SECONDS ) {
				$out[ $t ] = array(
					't'    => $t,
					'hits' => 0,
					's4xx' => 0,
					's5xx' => 0,
				);
			}
			return $out;
		}
		for ( $i = 0; $day <= $to && $i < 400; $i++ ) {
			$out[ $day ] = array(
				't'    => $day,
				'hits' => 0,
				's4xx' => 0,
				's5xx' => 0,
			);
			$day         = PNCP_Traffic::add_days( $day );
		}
		return $out;
	}

	/**
	 * Adds hourly counts to the buckets.
	 *
	 * @param array<int, array<string, int>>   $buckets Buckets (changed in place).
	 * @param array<int, array<string, mixed>> $rows    Rows with h (hour start), hits, s4xx, s5xx.
	 * @param string                           $step    hour | day.
	 */
	private static function fill( &$buckets, $rows, $step ) {
		$days = array_keys( $buckets );
		foreach ( $rows as $r ) {
			$t = (int) $r['h'];
			if ( 'day' === $step ) {
				$t = PNCP_Traffic::day_start( $t );
			}
			if ( ! isset( $buckets[ $t ] ) ) {
				// An hour of a time zone with a half-hour offset, or before the first bucket: the nearest earlier one.
				$found = null;
				foreach ( $days as $start ) {
					if ( $start <= $t ) {
						$found = $start;
					}
				}
				if ( null === $found ) {
					continue;
				}
				$t = $found;
			}
			$buckets[ $t ]['hits'] += (int) $r['hits'];
			$buckets[ $t ]['s4xx'] += (int) $r['s4xx'];
			$buckets[ $t ]['s5xx'] += (int) $r['s5xx'];
		}
	}

	/* ---------- Overview ---------- */

	/**
	 * Totals and a time series.
	 *
	 * @param array<string, mixed> $filters Filters (see filters()).
	 * @return array{total:int, ips:int, bytes:int, s2xx:int, s3xx:int, s4xx:int, s5xx:int, cache_hits:int, cache_misses:int, series:array<int, array{t:int, hits:int, s4xx:int, s5xx:int}>, step:string, src_used:string, from:int, to:int, basis:string, clipped:bool, ips_approx:bool}
	 *         series: one bucket per hour for ranges up to 3 days, per day beyond (t = the bucket's start, Unix time;
	 *         days start at midnight in the site's time zone).
	 */
	public static function overview( $filters = array() ) {
		$f = self::filters( $filters );
		return self::cached(
			'overview|' . wp_json_encode( $f ),
			static function () use ( $f ) {
				return self::compute_overview( $f );
			}
		);
	}

	/**
	 * See overview().
	 *
	 * @param array<string, mixed> $f Filters.
	 * @return array<string, mixed>
	 */
	private static function compute_overview( $f ) {
		$set  = self::set_filters( $f );
		$keys = array( 'total', 'ips', 'bytes', 's2xx', 's3xx', 's4xx', 's5xx', 'cache_hits', 'cache_misses' );
		$out  = array_fill_keys( $keys, 0 );
		if ( self::in_raw( $f ) || ! PNCP_Traffic::ready() ) {
			return array_merge( $out, self::raw_overview( $f ), self::meta( $f, 'raw', false ) );
		}
		$dim = self::agg_dimension( $set );
		if ( null === $dim ) {
			list( $f, $clipped ) = self::clip( $f );
			return array_merge( $out, self::raw_overview( $f ), self::meta( $f, 'raw', $clipped ) );
		}
		return array_merge( $out, self::agg_overview( $f, $dim ), self::meta( $f, 'agg', false ) );
	}

	/**
	 * Which one dimension of the aggregates answers these filters ('' = the hourly totals), or null when none can.
	 *
	 * @param string[] $set The filters that are set.
	 * @return string|null
	 */
	private static function agg_dimension( $set ) {
		if ( ! $set ) {
			return '';
		}
		if ( count( $set ) > 1 ) {
			return null;
		}
		$map = array(
			'ua'        => 'ua',
			'ua_family' => 'ua_family',
			'path'      => 'path',
			'path_like' => 'path',
			'ip'        => 'ip',
			'country'   => 'country',
			'status'    => 'status',
		);
		return isset( $map[ $set[0] ] ) ? $map[ $set[0] ] : null;
	}

	/**
	 * The overview from the raw rows.
	 *
	 * @param array<string, mixed> $f Filters.
	 * @return array<string, mixed>
	 */
	private static function raw_overview( $f ) {
		list( $where, $args ) = self::raw_where( $f );
		$table                = PNCP_Traffic::table( 'raw' );
		$rows                 = self::q( 'SELECT COUNT(*) AS total, COUNT(DISTINCT ip) AS ips, SUM(bytes) AS bytes, ' . PNCP_Traffic::status_sums() . ', SUM(CASE WHEN hit = 1 THEN 1 ELSE 0 END) AS cache_hits, SUM(CASE WHEN hit = 0 THEN 1 ELSE 0 END) AS cache_misses FROM %i WHERE ' . $where, array_merge( array( $table ), $args ) );
		$r                    = isset( $rows[0] ) ? $rows[0] : array();
		$step                 = self::step( $f );
		$anchor               = PNCP_Traffic::day_start( (int) $f['from'] );
		$hours                = self::q( 'SELECT ts - ((ts - %d) %% 3600) AS h, COUNT(*) AS hits, SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) AS s4xx, SUM(CASE WHEN status >= 500 AND status < 600 THEN 1 ELSE 0 END) AS s5xx FROM %i WHERE ' . $where . ' GROUP BY h ORDER BY h', array_merge( array( $anchor, $table ), $args ) );
		$buckets              = self::buckets( (int) $f['from'], (int) $f['to'], $step );
		self::fill( $buckets, $hours, $step );
		$out = array( 'series' => array_values( $buckets ) );
		foreach ( array( 'total', 'ips', 'bytes', 's2xx', 's3xx', 's4xx', 's5xx', 'cache_hits', 'cache_misses' ) as $key ) {
			$out[ $key ] = isset( $r[ $key ] ) ? (int) $r[ $key ] : 0;
		}
		$out['step'] = $step;
		return $out;
	}

	/**
	 * The overview from the aggregates: the hourly totals, or the day rows of one dimension's key.
	 *
	 * @param array<string, mixed> $f   Filters.
	 * @param string               $dim Dimension ('' = hourly totals).
	 * @return array<string, mixed>
	 */
	private static function agg_overview( $f, $dim ) {
		$from_day = PNCP_Traffic::day_start( (int) $f['from'] );
		$to_day   = PNCP_Traffic::day_start( (int) $f['to'] );
		$step     = self::step( $f );
		$out      = array();
		if ( '' === $dim ) {
			$rows    = self::q( 'SELECT hour_ts AS h, hits, s2xx, s3xx, s4xx, s5xx, bytes, chits, misses FROM %i WHERE src = %s AND hour_ts >= %d AND hour_ts <= %d ORDER BY hour_ts', array( PNCP_Traffic::table( 'hour' ), $f['src'], $from_day, (int) $f['to'] ) );
			$buckets = self::buckets( $from_day, (int) $f['to'], $step );
			self::fill( $buckets, $rows, $step );
			$sum = array_fill_keys( array( 'hits', 's2xx', 's3xx', 's4xx', 's5xx', 'bytes', 'chits', 'misses' ), 0 );
			foreach ( $rows as $r ) {
				foreach ( $sum as $key => $n ) {
					$sum[ $key ] = $n + (int) $r[ $key ];
				}
			}
			$ips = self::q( 'SELECT COUNT(DISTINCT k) AS n FROM %i WHERE src = %s AND dim = %s AND day >= %d AND day <= %d AND k <> %s', array( PNCP_Traffic::table( 'day' ), $f['src'], 'ip', $from_day, $to_day, PNCP_Traffic::OTHER ) );
			$out = array(
				'total'        => $sum['hits'],
				'ips'          => isset( $ips[0]['n'] ) ? (int) $ips[0]['n'] : 0,
				'bytes'        => $sum['bytes'],
				's2xx'         => $sum['s2xx'],
				's3xx'         => $sum['s3xx'],
				's4xx'         => $sum['s4xx'],
				's5xx'         => $sum['s5xx'],
				'cache_hits'   => $sum['chits'],
				'cache_misses' => $sum['misses'],
				'series'       => array_values( $buckets ),
				'step'         => $step,
			);
			return $out;
		}
		list( $cond, $args ) = self::agg_key_condition( $f, $dim );
		$rows                = self::q( 'SELECT day AS h, SUM(hits) AS hits, SUM(s2xx) AS s2xx, SUM(s3xx) AS s3xx, SUM(s4xx) AS s4xx, SUM(s5xx) AS s5xx, SUM(bytes) AS bytes, SUM(chits) AS chits, SUM(misses) AS misses, SUM(ips) AS ips FROM %i WHERE src = %s AND dim = %s AND day >= %d AND day <= %d AND ' . $cond . ' GROUP BY day ORDER BY day', array_merge( array( PNCP_Traffic::table( 'day' ), $f['src'], $dim, $from_day, $to_day ), $args ) );
		$buckets             = self::buckets( $from_day, (int) $f['to'], 'day' );
		self::fill( $buckets, $rows, 'day' );
		$sum = array_fill_keys( array( 'hits', 's2xx', 's3xx', 's4xx', 's5xx', 'bytes', 'chits', 'misses', 'ips' ), 0 );
		foreach ( $rows as $r ) {
			foreach ( $sum as $key => $n ) {
				$sum[ $key ] = $n + (int) $r[ $key ];
			}
		}
		return array(
			'total'        => $sum['hits'],
			'ips'          => 'ip' === $dim ? min( 1, $sum['hits'] ) : $sum['ips'],
			'bytes'        => $sum['bytes'],
			's2xx'         => $sum['s2xx'],
			's3xx'         => $sum['s3xx'],
			's4xx'         => $sum['s4xx'],
			's5xx'         => $sum['s5xx'],
			'cache_hits'   => $sum['chits'],
			'cache_misses' => $sum['misses'],
			'series'       => array_values( $buckets ),
			'step'         => 'day',
		);
	}

	/**
	 * The condition on the day table for the one dimension filter that is set.
	 *
	 * @param array<string, mixed> $f   Filters.
	 * @param string               $dim Dimension.
	 * @return array{0:string, 1:array<int, mixed>}
	 */
	private static function agg_key_condition( $f, $dim ) {
		global $wpdb;
		switch ( $dim ) {
			case 'ua':
				return array( 'label = %s', array( $f['ua'] ) );
			case 'ua_family':
				return array( 'label = %s', array( $f['ua_family'] ) );
			case 'path':
				if ( '' !== $f['path'] ) {
					return array( 'k = %s', array( PNCP_Traffic::hash( $f['path'] ) ) );
				}
				return array( 'label LIKE %s', array( '%' . $wpdb->esc_like( $f['path_like'] ) . '%' ) );
			case 'ip':
				return array( 'label = %s', array( $f['ip'] ) );
			case 'country':
				return array( 'label = %s', array( $f['country'] ) );
			case 'status':
				return array( 'label >= %s AND label <= %s AND k <> %s', array( (string) $f['status'][0], (string) $f['status'][1], PNCP_Traffic::OTHER ) );
		}
		return array( '1 = 0', array() );
	}

	/* ---------- Top ---------- */

	/**
	 * The keys of a dimension with the most requests (or bytes, IPs, errors…).
	 *
	 * @param string               $dimension ua | ua_family | path | referer | ip | country | status.
	 * @param array<string, mixed> $filters   Filters (see filters()).
	 * @param int                  $limit     Rows, 1 to 500.
	 * @param int                  $offset    Rows to skip.
	 * @param string               $order     hits | ips | bytes | s4xx | s5xx | misses | last | first.
	 * @return array{rows:array<int, array<string, mixed>>, total_rows:int, has_more:bool, dimension:string, order:string, src_used:string, from:int, to:int, basis:string, clipped:bool, ips_approx:bool}
	 *         rows: key (the User-Agent, path, referrer ('' = none), IP, country, status code or family), hits, ips,
	 *         bytes, s4xx, s5xx, misses, first, last (Unix time); for ua also family and name, for ua_family name
	 *         (the family's label). total_rows: how many keys there are in all (for paging), -1 when there are
	 *         more than GROUPS over the raw rows (has_more then says whether a next page exists). A status class
	 *         filter (2xx, 3xx, 4xx, 404, 5xx) over a range longer than the raw window is answered from the daily
	 *         figures: hits exact, ips (ips_approx), bytes and misses in proportion, first / last of the key.
	 */
	public static function top( $dimension, $filters = array(), $limit = 50, $offset = 0, $order = 'hits' ) {
		$dimension = in_array( (string) $dimension, self::TOP, true ) ? (string) $dimension : 'path';
		$order     = in_array( (string) $order, array( 'hits', 'ips', 'bytes', 's4xx', 's5xx', 'misses', 'last', 'first' ), true ) ? (string) $order : 'hits';
		$limit     = max( 1, min( self::MAX_LIMIT, (int) $limit ) );
		$offset    = max( 0, (int) $offset );
		$f         = self::filters( $filters );
		return self::cached(
			'top|' . $dimension . '|' . $order . '|' . $limit . '|' . $offset . '|' . wp_json_encode( $f ),
			static function () use ( $dimension, $f, $limit, $offset, $order ) {
				return self::compute_top( $dimension, $f, $limit, $offset, $order );
			}
		);
	}

	/**
	 * See top().
	 *
	 * @param string               $dim    Dimension.
	 * @param array<string, mixed> $f      Filters.
	 * @param int                  $limit  Rows.
	 * @param int                  $offset Offset.
	 * @param string               $order  Order.
	 * @return array<string, mixed>
	 */
	private static function compute_top( $dim, $f, $limit, $offset, $order ) {
		$base = array(
			'dimension' => $dim,
			'order'     => $order,
		);
		if ( self::in_raw( $f ) || ! PNCP_Traffic::ready() ) {
			return array_merge( self::raw_top( $dim, $f, $limit, $offset, $order ), $base, self::meta( $f, 'raw', false ) );
		}
		$cond = self::agg_top_condition( $dim, $f );
		if ( null === $cond ) {
			// A status class (2xx, 3xx, 4xx, 404, 5xx) is counted per key in the daily figures too.
			$column = 'status' !== $dim ? self::status_column( $f ) : '';
			$cond   = '' !== $column ? self::agg_top_condition( $dim, array_merge( $f, array( 'status' => null ) ) ) : null;
			if ( null !== $cond ) {
				return array_merge( self::agg_top_status( $dim, $f, $limit, $offset, $order, $cond, $column ), $base, self::meta( $f, 'agg', false ) );
			}
			list( $f, $clipped ) = self::clip( $f );
			return array_merge( self::raw_top( $dim, $f, $limit, $offset, $order ), $base, self::meta( $f, 'raw', $clipped ) );
		}
		return array_merge( self::agg_top( $dim, $f, $limit, $offset, $order, $cond ), $base, self::meta( $f, 'agg', false ) );
	}

	/**
	 * The column of the daily figures that counts the requests of the status filter (s2xx, s3xx, s4xx, s404,
	 * s5xx), or '' when the filter is another one (a single code other than 404) or not set.
	 *
	 * @param array<string, mixed> $f Filters.
	 * @return string
	 */
	private static function status_column( $f ) {
		if ( null === $f['status'] ) {
			return '';
		}
		$map = array(
			'200-299' => 's2xx',
			'300-399' => 's3xx',
			'400-499' => 's4xx',
			'404-404' => 's404',
			'500-599' => 's5xx',
		);
		$key = (int) $f['status'][0] . '-' . (int) $f['status'][1];
		return isset( $map[ $key ] ) ? $map[ $key ] : '';
	}

	/**
	 * The SQL ORDER BY of an order.
	 *
	 * @param string $order Order.
	 * @return string
	 */
	private static function order_sql( $order ) {
		$map = array(
			'hits'   => 'hits DESC',
			'ips'    => 'ips DESC, hits DESC',
			'bytes'  => 'bytes DESC',
			's4xx'   => 's4xx DESC, hits DESC',
			's5xx'   => 's5xx DESC, hits DESC',
			'misses' => 'misses DESC, hits DESC',
			'last'   => 'last DESC',
			'first'  => 'first ASC',
		);
		return isset( $map[ $order ] ) ? $map[ $order ] : 'hits DESC';
	}

	/**
	 * One row of top(), from a query row.
	 *
	 * @param string               $dim Dimension.
	 * @param array<string, mixed> $r   Row with key, hits, ips…, fam.
	 * @return array<string, mixed>
	 */
	private static function top_row( $dim, $r ) {
		$row = array(
			'key'    => 'ip' === $dim ? PNCP_Traffic::shown_ip( (string) $r['label_key'] ) : (string) $r['label_key'],
			'hits'   => (int) $r['hits'],
			'ips'    => (int) $r['ips'],
			'bytes'  => (int) $r['bytes'],
			's4xx'   => (int) $r['s4xx'],
			's5xx'   => (int) $r['s5xx'],
			'misses' => (int) $r['misses'],
			'first'  => (int) $r['first'],
			'last'   => (int) $r['last'],
		);
		if ( 'ua' === $dim ) {
			$class         = PNCP_Traffic_Ua::classify( $row['key'] );
			$row['family'] = (string) $r['fam'];
			$row['name']   = $class['name'];
		} elseif ( 'ua_family' === $dim ) {
			$labels      = PNCP_Traffic_Ua::labels();
			$row['name'] = isset( $labels[ $row['key'] ] ) ? $labels[ $row['key'] ] : $row['key'];
		}
		return $row;
	}

	/**
	 * top() from the raw rows.
	 *
	 * @param string               $dim    Dimension.
	 * @param array<string, mixed> $f      Filters.
	 * @param int                  $limit  Rows.
	 * @param int                  $offset Offset.
	 * @param string               $order  Order.
	 * @return array{rows:array<int, array<string, mixed>>, total_rows:int}
	 */
	private static function raw_top( $dim, $f, $limit, $offset, $order ) {
		list( $where, $args ) = self::raw_where( $f );
		$col                  = PNCP_Traffic::dimension_column( $dim );
		$group                = 'ua' === $dim ? $col . ', fam' : $col;
		$table                = PNCP_Traffic::table( 'raw' );
		// One pass, from the covering index: the long texts (User-Agent, path) are read afterwards, for the keys
		// shown only. Up to GROUPS keys are read at once, which also counts them; beyond that the count is unknown.
		$window = $offset + $limit + 1 <= self::GROUPS;
		$rows   = self::q(
			'SELECT ' . $col . ' AS g, MAX(fam) AS fam, COUNT(*) AS hits, COUNT(DISTINCT ip) AS ips, SUM(bytes) AS bytes, SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) AS s4xx, SUM(CASE WHEN status >= 500 AND status < 600 THEN 1 ELSE 0 END) AS s5xx, SUM(CASE WHEN hit = 0 THEN 1 ELSE 0 END) AS misses, MIN(ts) AS first, MAX(ts) AS last FROM %i WHERE ' . $where . ' GROUP BY ' . $group . ' ORDER BY ' . self::order_sql( $order ) . ', g LIMIT %d OFFSET %d',
			array_merge( array( $table ), $args, $window ? array( self::GROUPS, 0 ) : array( $limit + 1, $offset ) )
		);
		$count  = count( $rows );
		if ( $window ) {
			$total = $count < self::GROUPS ? $count : -1;
			$rows  = array_slice( $rows, $offset, $limit + 1 );
		} else {
			$total = $count <= $limit ? $offset + $count : -1;
		}
		$more   = count( $rows ) > $limit;
		$rows   = array_slice( $rows, 0, $limit );
		$labels = PNCP_Traffic::labels( $dim, array_column( $rows, 'g' ) );
		$out    = array();
		foreach ( $rows as $r ) {
			$r['label_key'] = isset( $labels[ (string) $r['g'] ] ) ? $labels[ (string) $r['g'] ] : (string) $r['g'];
			$out[]          = self::top_row( $dim, $r );
		}
		return array(
			'rows'       => $out,
			'total_rows' => $total,
			'has_more'   => $more,
		);
	}

	/**
	 * The condition on the day table that answers top() with these filters, or null when it cannot (a filter on
	 * another dimension).
	 *
	 * @param string               $dim Dimension.
	 * @param array<string, mixed> $f   Filters.
	 * @return array{0:string, 1:array<int, mixed>}|null
	 */
	private static function agg_top_condition( $dim, $f ) {
		global $wpdb;
		$w    = array();
		$args = array();
		foreach ( self::set_filters( $f ) as $key ) {
			if ( 'ua_family' === $key && in_array( $dim, array( 'ua', 'ua_family' ), true ) ) {
				$w[]    = 'ua' === $dim ? 'fam = %s' : 'label = %s';
				$args[] = $f['ua_family'];
			} elseif ( 'ua' === $key && 'ua' === $dim ) {
				$w[]    = 'label = %s';
				$args[] = $f['ua'];
			} elseif ( 'path' === $key && 'path' === $dim ) {
				$w[]    = 'k = %s';
				$args[] = PNCP_Traffic::hash( $f['path'] );
			} elseif ( ( 'path_like' === $key && 'path' === $dim ) || ( 'search' === $key && in_array( $dim, array( 'ua', 'path', 'referer' ), true ) ) ) {
				$w[]    = 'label LIKE %s';
				$args[] = '%' . $wpdb->esc_like( $f[ $key ] ) . '%';
			} elseif ( 'ip' === $key && 'ip' === $dim ) {
				$w[]    = 'label = %s';
				$args[] = $f['ip'];
			} elseif ( 'country' === $key && 'country' === $dim ) {
				$w[]    = 'label = %s';
				$args[] = $f['country'];
			} elseif ( 'status' === $key && 'status' === $dim ) {
				$w[]    = 'label >= %s AND label <= %s';
				$args[] = (string) $f['status'][0];
				$args[] = (string) $f['status'][1];
			} else {
				return null;
			}
		}
		$w[]    = 'k <> %s';
		$args[] = PNCP_Traffic::OTHER;
		return array( implode( ' AND ', $w ), $args );
	}

	/**
	 * top() from the aggregates.
	 *
	 * @param string                                $dim    Dimension.
	 * @param array<string, mixed>                  $f      Filters.
	 * @param int                                   $limit  Rows.
	 * @param int                                   $offset Offset.
	 * @param string                                $order  Order.
	 * @param array{0:string, 1:array<int, mixed>} $cond   Condition (agg_top_condition()).
	 * @return array{rows:array<int, array<string, mixed>>, total_rows:int}
	 */
	private static function agg_top( $dim, $f, $limit, $offset, $order, $cond ) {
		$table = PNCP_Traffic::table( 'day' );
		$base  = array( $table, $f['src'], $dim, PNCP_Traffic::day_start( (int) $f['from'] ), PNCP_Traffic::day_start( (int) $f['to'] ) );
		$rows  = self::q(
			'SELECT MAX(label) AS label_key, MAX(fam) AS fam, SUM(hits) AS hits, SUM(ips) AS ips, SUM(bytes) AS bytes, SUM(s4xx) AS s4xx, SUM(s5xx) AS s5xx, SUM(misses) AS misses, MIN(first_ts) AS first, MAX(last_ts) AS last FROM %i WHERE src = %s AND dim = %s AND day >= %d AND day <= %d AND ' . $cond[0] . ' GROUP BY k ORDER BY ' . self::order_sql( $order ) . ' LIMIT %d OFFSET %d',
			array_merge( $base, $cond[1], array( $limit, $offset ) )
		);
		$count = self::q( 'SELECT COUNT(DISTINCT k) AS n FROM %i WHERE src = %s AND dim = %s AND day >= %d AND day <= %d AND ' . $cond[0], array_merge( $base, $cond[1] ) );
		$out   = array();
		foreach ( $rows as $r ) {
			$out[] = self::top_row( $dim, $r );
		}
		$total = isset( $count[0]['n'] ) ? (int) $count[0]['n'] : count( $out );
		return array(
			'rows'       => $out,
			'total_rows' => $total,
			'has_more'   => $offset + count( $out ) < $total,
		);
	}

	/**
	 * top() with a status class over the daily figures: the requests of that class per key (exact); its IPs at
	 * most the key's IPs of the day (ips_approx), its bytes and cache misses the key's in proportion, first and
	 * last the key's.
	 *
	 * @param string                                $dim    Dimension.
	 * @param array<string, mixed>                  $f      Filters.
	 * @param int                                   $limit  Rows.
	 * @param int                                   $offset Offset.
	 * @param string                                $order  Order.
	 * @param array{0:string, 1:array<int, mixed>} $cond   Condition of the other filters (agg_top_condition()).
	 * @param string                                $column s2xx | s3xx | s4xx | s404 | s5xx.
	 * @return array{rows:array<int, array<string, mixed>>, total_rows:int, has_more:bool}
	 */
	private static function agg_top_status( $dim, $f, $limit, $offset, $order, $cond, $column ) {
		$table = PNCP_Traffic::table( 'day' );
		$base  = array( $table, $f['src'], $dim, PNCP_Traffic::day_start( (int) $f['from'] ), PNCP_Traffic::day_start( (int) $f['to'] ) );
		$where = 'src = %s AND dim = %s AND day >= %d AND day <= %d AND ' . $cond[0] . ' AND ' . $column . ' > 0';
		$s4xx  = in_array( $column, array( 's4xx', 's404' ), true ) ? 'SUM(' . $column . ')' : '0';
		$s5xx  = 's5xx' === $column ? 'SUM(' . $column . ')' : '0';
		$rows  = self::q(
			'SELECT MAX(label) AS label_key, MAX(fam) AS fam, SUM(' . $column . ') AS hits, SUM(ips) AS ips, SUM(bytes * ' . $column . ' / hits) AS bytes, ' . $s4xx . ' AS s4xx, ' . $s5xx . ' AS s5xx, SUM(misses * ' . $column . ' / hits) AS misses, MIN(first_ts) AS first, MAX(last_ts) AS last FROM %i WHERE ' . $where . ' GROUP BY k ORDER BY ' . self::order_sql( $order ) . ' LIMIT %d OFFSET %d',
			array_merge( $base, $cond[1], array( $limit, $offset ) )
		);
		$count = self::q( 'SELECT COUNT(DISTINCT k) AS n FROM %i WHERE ' . $where, array_merge( $base, $cond[1] ) );
		$out   = array();
		foreach ( $rows as $r ) {
			$r['ips']    = min( (int) $r['ips'], (int) $r['hits'] );
			$r['bytes']  = (int) round( (float) $r['bytes'] );
			$r['misses'] = (int) round( (float) $r['misses'] );
			$out[]       = self::top_row( $dim, $r );
		}
		$total = isset( $count[0]['n'] ) ? (int) $count[0]['n'] : count( $out );
		return array(
			'rows'       => $out,
			'total_rows' => $total,
			'has_more'   => $offset + count( $out ) < $total,
		);
	}

	/* ---------- Problems ---------- */

	/**
	 * The paths with problems.
	 *
	 * - 404: "not found"; 5xx: server errors; 3xx: redirects (not 304, which is a cache revalidation).
	 * - uncached: pages (not static files, feeds or the REST API) served without the CDN cache (MISS and the
	 *   like), most first; only where the cache status is known (Bunny).
	 * - large: most bytes in all; slow: slowest on average (only where the time is logged: the server log with
	 *   $request_time, and the WordPress source).
	 *
	 * @param string               $type    404 | 5xx | 3xx | uncached | large | slow.
	 * @param array<string, mixed> $filters Filters (see filters()).
	 * @param int                  $limit   Rows, 1 to 500.
	 * @param int                  $offset  Rows to skip.
	 * @return array{rows:array<int, array<string, mixed>>, total_rows:int, has_more:bool, type:string, available:bool, src_used:string, from:int, to:int, basis:string, clipped:bool, ips_approx:bool}
	 *         rows: path, hits, ips, last, statuses (code => hits; over the aggregates for uncached / large / slow:
	 *         "2xx" … "5xx" => hits), top_referers (up to 5: referer, hits, internal = from this site), sample_ua,
	 *         bytes, avg_bytes, misses, miss_rate (0–1), avg_rt_ms (null when unknown). available: false when the
	 *         source has no data for this type (no cache status, no response times).
	 */
	public static function problems( $type, $filters = array(), $limit = 50, $offset = 0 ) {
		$type   = in_array( (string) $type, self::PROBLEMS, true ) ? (string) $type : '404';
		$limit  = max( 1, min( self::MAX_LIMIT, (int) $limit ) );
		$offset = max( 0, (int) $offset );
		$f      = self::filters( $filters );
		return self::cached(
			'problems|' . $type . '|' . $limit . '|' . $offset . '|' . wp_json_encode( $f ),
			static function () use ( $type, $f, $limit, $offset ) {
				return self::compute_problems( $type, $f, $limit, $offset );
			}
		);
	}

	/**
	 * See problems().
	 *
	 * @param string               $type   Type.
	 * @param array<string, mixed> $f      Filters.
	 * @param int                  $limit  Rows.
	 * @param int                  $offset Offset.
	 * @return array<string, mixed>
	 */
	private static function compute_problems( $type, $f, $limit, $offset ) {
		$base = array( 'type' => $type );
		// A status filter that holds every status of the type (404 with "4xx", 5xx with "5xx") changes nothing; one
		// that holds none of them leaves nothing.
		$range = array(
			'404' => array( 404, 404 ),
			'5xx' => array( 500, 599 ),
			'3xx' => array( 300, 399 ),
		);
		if ( null !== $f['status'] && isset( $range[ $type ] ) ) {
			list( $low, $high ) = $range[ $type ];
			if ( (int) $f['status'][0] <= $low && (int) $f['status'][1] >= $high ) {
				$f['status'] = null;
			} elseif ( (int) $f['status'][1] < $low || (int) $f['status'][0] > $high ) {
				return array_merge(
					array(
						'rows'       => array(),
						'total_rows' => 0,
						'has_more'   => false,
						'available'  => true,
					),
					$base,
					self::meta( $f, self::in_raw( $f ) ? 'raw' : 'agg', false )
				);
			}
		}
		$set = self::set_filters( $f );
		if ( self::in_raw( $f ) || ! PNCP_Traffic::ready() ) {
			return array_merge( self::raw_problems( $type, $f, $limit, $offset ), $base, self::meta( $f, 'raw', false ) );
		}
		if ( array() !== array_diff( $set, array( 'path_like' ) ) ) {
			list( $f, $clipped ) = self::clip( $f );
			return array_merge( self::raw_problems( $type, $f, $limit, $offset ), $base, self::meta( $f, 'raw', $clipped ) );
		}
		return array_merge( self::agg_problems( $type, $f, $limit, $offset ), $base, self::meta( $f, 'agg', false ) );
	}

	/**
	 * The raw condition of a problem type.
	 *
	 * @param string $type Type.
	 * @return string
	 */
	private static function problem_condition( $type ) {
		$map = array(
			'404'      => 'status = 404',
			'5xx'      => 'status >= 500 AND status < 600',
			'3xx'      => 'status >= 300 AND status < 400 AND status <> 304',
			'uncached' => "hit = 0 AND ptype = 'p'",
			'large'    => 'bytes > 0',
			'slow'     => 'rt_ms IS NOT NULL',
		);
		return isset( $map[ $type ] ) ? $map[ $type ] : $map['404'];
	}

	/**
	 * Is a referrer this site?
	 *
	 * @param string $referer Referrer.
	 * @return bool
	 */
	public static function internal( $referer ) {
		static $own = null;
		if ( null === $own ) {
			$own = strtolower( (string) preg_replace( '/^www\./i', '', (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) ) );
		}
		$host = strtolower( (string) preg_replace( '/^www\./i', '', (string) wp_parse_url( (string) $referer, PHP_URL_HOST ) ) );
		return '' !== $host && $host === $own;
	}

	/**
	 * A problems row with every field.
	 *
	 * @param array<string, mixed> $r Query row: path, hits, ips, last, bytes, misses, rt_sum, rt_n, sample_ua.
	 * @return array<string, mixed>
	 */
	private static function problem_row( $r ) {
		$hits = (int) $r['hits'];
		$rt_n = (int) $r['rt_n'];
		return array(
			'path'         => (string) $r['path'],
			'hits'         => $hits,
			'ips'          => (int) $r['ips'],
			'last'         => (int) $r['last'],
			'statuses'     => array(),
			'top_referers' => array(),
			'sample_ua'    => isset( $r['sample_ua'] ) ? (string) $r['sample_ua'] : '',
			'bytes'        => (int) $r['bytes'],
			'avg_bytes'    => $hits > 0 ? (int) round( (int) $r['bytes'] / $hits ) : 0,
			'misses'       => (int) $r['misses'],
			'miss_rate'    => $hits > 0 ? round( (int) $r['misses'] / $hits, 3 ) : 0.0,
			'avg_rt_ms'    => $rt_n > 0 ? (int) round( (int) $r['rt_sum'] / $rt_n ) : null,
		);
	}

	/**
	 * Adds the referrers of each path, top 5 (rows of path key, referer, hits).
	 *
	 * @param array<string, array<string, mixed>> $out  Rows by path key (changed in place).
	 * @param array<int, array<string, mixed>>    $refs Referrer rows (k, referer, hits), most first.
	 */
	private static function add_referers( &$out, $refs ) {
		foreach ( $refs as $r ) {
			$k = (string) $r['k'];
			if ( ! isset( $out[ $k ] ) || count( $out[ $k ]['top_referers'] ) >= 5 ) {
				continue;
			}
			$out[ $k ]['top_referers'][] = array(
				'referer'  => (string) $r['referer'],
				'hits'     => (int) $r['hits'],
				'internal' => self::internal( (string) $r['referer'] ),
			);
		}
	}

	/**
	 * problems() from the raw rows.
	 *
	 * @param string               $type   Type.
	 * @param array<string, mixed> $f      Filters.
	 * @param int                  $limit  Rows.
	 * @param int                  $offset Offset.
	 * @return array{rows:array<int, array<string, mixed>>, total_rows:int, available:bool}
	 */
	private static function raw_problems( $type, $f, $limit, $offset ) {
		global $wpdb;
		list( $where, $args ) = self::raw_where( $f );
		$table                = PNCP_Traffic::table( 'raw' );
		$cond                 = self::problem_condition( $type );
		$order                = array(
			'uncached' => 'misses DESC, hits DESC',
			'large'    => 'bytes DESC',
			'slow'     => 'SUM(rt_ms) / COUNT(rt_ms) DESC',
		);
		// One pass over the covering index (see raw_top()); the path and a User-Agent of each row shown come after.
		$window = $offset + $limit + 1 <= self::GROUPS;
		$rows   = self::q(
			'SELECT path_hash AS k, COUNT(*) AS hits, COUNT(DISTINCT ip) AS ips, MAX(ts) AS last, SUM(bytes) AS bytes, SUM(CASE WHEN hit = 0 THEN 1 ELSE 0 END) AS misses, SUM(rt_ms) AS rt_sum, COUNT(rt_ms) AS rt_n FROM %i WHERE ' . $where . ' AND ' . $cond . ' GROUP BY path_hash ORDER BY ' . ( isset( $order[ $type ] ) ? $order[ $type ] : 'hits DESC' ) . ', k LIMIT %d OFFSET %d',
			array_merge( array( $table ), $args, $window ? array( self::GROUPS, 0 ) : array( $limit + 1, $offset ) )
		);
		$count  = count( $rows );
		if ( $window ) {
			$total = $count < self::GROUPS ? $count : -1;
			$rows  = array_slice( $rows, $offset, $limit + 1 );
		} else {
			$total = $count <= $limit ? $offset + $count : -1;
		}
		$more  = count( $rows ) > $limit;
		$rows  = array_slice( $rows, 0, $limit );
		$paths = PNCP_Traffic::labels( 'path', array_column( $rows, 'k' ) );
		$out   = array();
		foreach ( $rows as $r ) {
			$k              = (string) $r['k'];
			$r['path']      = isset( $paths[ $k ] ) ? $paths[ $k ] : '';
			$r['sample_ua'] = (string) $wpdb->get_var( self::sql( 'SELECT ua FROM %i WHERE path_hash = %s AND ' . $where . ' AND ' . $cond . ' ORDER BY ts DESC LIMIT 1', array_merge( array( $table, $k ), $args ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- Prepared in sql().
			$out[ $k ]      = self::problem_row( $r );
		}
		if ( $out ) {
			$keys = array_keys( $out );
			$in   = implode( ', ', array_fill( 0, count( $keys ), '%s' ) );
			// The statuses: of the problem itself for 404 / 5xx / 3xx, of every request of the path otherwise.
			$scond = in_array( $type, array( '404', '5xx', '3xx' ), true ) ? ' AND ' . $cond : '';
			foreach ( self::q( 'SELECT path_hash AS k, status, COUNT(*) AS hits FROM %i WHERE ' . $where . $scond . ' AND path_hash IN (' . $in . ') GROUP BY path_hash, status ORDER BY hits DESC', array_merge( array( $table ), $args, $keys ) ) as $r ) {
				$out[ (string) $r['k'] ]['statuses'][ (string) (int) $r['status'] ] = (int) $r['hits'];
			}
			if ( 'uncached' === $type ) {
				// The share of misses among all requests of the page.
				foreach ( self::q( 'SELECT path_hash AS k, COUNT(*) AS hits FROM %i WHERE ' . $where . ' AND path_hash IN (' . $in . ') GROUP BY path_hash', array_merge( array( $table ), $args, $keys ) ) as $r ) {
					$k                      = (string) $r['k'];
					$out[ $k ]['hits']      = (int) $r['hits'];
					$out[ $k ]['miss_rate'] = (int) $r['hits'] > 0 ? round( $out[ $k ]['misses'] / (int) $r['hits'], 3 ) : 0.0;
				}
			}
			self::add_referers( $out, self::q( 'SELECT path_hash AS k, referer, COUNT(*) AS hits FROM %i WHERE ' . $where . ' AND ' . $cond . ' AND path_hash IN (' . $in . ') GROUP BY path_hash, referer ORDER BY hits DESC', array_merge( array( $table ), $args, $keys ) ) );
		}
		$available = true;
		if ( in_array( $type, array( 'uncached', 'slow' ), true ) && ! $out ) {
			$probe     = self::q( 'SELECT 1 AS one FROM %i WHERE ' . $where . ' AND ' . ( 'slow' === $type ? 'rt_ms IS NOT NULL' : 'hit < 2' ) . ' LIMIT 1', array_merge( array( $table ), $args ) );
			$available = (bool) $probe;
		}
		return array(
			'rows'       => array_values( $out ),
			'total_rows' => $total,
			'has_more'   => $more,
			'available'  => $available,
		);
	}

	/**
	 * problems() from the aggregates: the problems table for 404 / 5xx / 3xx, the path rows for the rest.
	 *
	 * @param string               $type   Type.
	 * @param array<string, mixed> $f      Filters.
	 * @param int                  $limit  Rows.
	 * @param int                  $offset Offset.
	 * @return array{rows:array<int, array<string, mixed>>, total_rows:int, available:bool}
	 */
	private static function agg_problems( $type, $f, $limit, $offset ) {
		global $wpdb;
		$from = PNCP_Traffic::day_start( (int) $f['from'] );
		$to   = PNCP_Traffic::day_start( (int) $f['to'] );
		$like = '' !== $f['path_like'] ? '%' . $wpdb->esc_like( $f['path_like'] ) . '%' : '%';
		$out  = array();
		if ( in_array( $type, array( '404', '5xx', '3xx' ), true ) ) {
			$conds = array(
				'404' => 'status = 404',
				'5xx' => 'status >= 500 AND status < 600',
				'3xx' => 'status >= 300 AND status < 400 AND status <> 304',
			);
			$table = PNCP_Traffic::table( 'err' );
			$where = 'src = %s AND day >= %d AND day <= %d AND path LIKE %s AND ' . $conds[ $type ];
			$args  = array( $table, $f['src'], $from, $to, $like );
			$rows  = self::q( 'SELECT k, MAX(path) AS path, SUM(hits) AS hits, SUM(ips) AS ips, MAX(last_ts) AS last, 0 AS bytes, 0 AS misses, 0 AS rt_sum, 0 AS rt_n, MAX(ua) AS sample_ua FROM %i WHERE ' . $where . ' GROUP BY k ORDER BY hits DESC LIMIT %d OFFSET %d', array_merge( $args, array( $limit, $offset ) ) );
			$count = self::q( 'SELECT COUNT(DISTINCT k) AS n FROM %i WHERE ' . $where, $args );
			foreach ( $rows as $r ) {
				$out[ (string) $r['k'] ] = self::problem_row( $r );
			}
			if ( $out ) {
				$keys = array_keys( $out );
				$in   = implode( ', ', array_fill( 0, count( $keys ), '%s' ) );
				foreach ( self::q( 'SELECT k, status, SUM(hits) AS hits FROM %i WHERE ' . $where . ' AND k IN (' . $in . ') GROUP BY k, status ORDER BY hits DESC', array_merge( $args, $keys ) ) as $r ) {
					$out[ (string) $r['k'] ]['statuses'][ (string) (int) $r['status'] ] = (int) $r['hits'];
				}
				self::add_referers( $out, self::q( 'SELECT k, MAX(referer) AS referer, SUM(hits) AS hits FROM %i WHERE ' . $where . ' AND k IN (' . $in . ') GROUP BY k, rk ORDER BY hits DESC', array_merge( $args, $keys ) ) );
			}
			$total = isset( $count[0]['n'] ) ? (int) $count[0]['n'] : count( $out );
			return array(
				'rows'       => array_values( $out ),
				'total_rows' => $total,
				'has_more'   => $offset + count( $out ) < $total,
				'available'  => true,
			);
		}
		$conds = array(
			'uncached' => array( "ptype = 'p' AND misses > 0", 'SUM(misses) DESC, SUM(hits) DESC' ),
			'large'    => array( 'bytes > 0', 'SUM(bytes) DESC' ),
			'slow'     => array( 'rt_n > 0', 'SUM(rt_sum) / SUM(rt_n) DESC' ),
		);
		$table = PNCP_Traffic::table( 'day' );
		$where = 'src = %s AND dim = %s AND day >= %d AND day <= %d AND k <> %s AND label LIKE %s AND ' . $conds[ $type ][0];
		$args  = array( $table, $f['src'], 'path', $from, $to, PNCP_Traffic::OTHER, $like );
		$rows  = self::q( 'SELECT k, MAX(label) AS path, SUM(hits) AS hits, SUM(ips) AS ips, MAX(last_ts) AS last, SUM(bytes) AS bytes, SUM(misses) AS misses, SUM(rt_sum) AS rt_sum, SUM(rt_n) AS rt_n, SUM(s2xx) AS s2xx, SUM(s3xx) AS s3xx, SUM(s4xx) AS s4xx, SUM(s5xx) AS s5xx FROM %i WHERE ' . $where . ' GROUP BY k ORDER BY ' . $conds[ $type ][1] . ' LIMIT %d OFFSET %d', array_merge( $args, array( $limit, $offset ) ) );
		$count = self::q( 'SELECT COUNT(DISTINCT k) AS n FROM %i WHERE ' . $where, $args );
		foreach ( $rows as $r ) {
			$row             = self::problem_row( $r );
			$row['statuses'] = array_filter(
				array(
					'2xx' => (int) $r['s2xx'],
					'3xx' => (int) $r['s3xx'],
					'4xx' => (int) $r['s4xx'],
					'5xx' => (int) $r['s5xx'],
				)
			);
			$out[]           = $row;
		}
		$total = isset( $count[0]['n'] ) ? (int) $count[0]['n'] : count( $out );
		return array(
			'rows'       => $out,
			'total_rows' => $total,
			'has_more'   => $offset + count( $out ) < $total,
			'available'  => (bool) $out || 'large' === $type,
		);
	}

	/* ---------- Detail ---------- */

	/**
	 * One User-Agent, path or IP: its totals and series (as overview()), and its top paths, User-Agents, statuses,
	 * countries, referrers and IPs (10 each, as top(); the breakdowns of a long range come from the raw window,
	 * see "clipped" in each).
	 *
	 * @param string               $kind    ua | path | ip.
	 * @param string               $key     The User-Agent, path or IP.
	 * @param array<string, mixed> $filters Filters (see filters()); the key replaces the filter of its kind.
	 * @return array{kind:string, key:string, summary:array<string, mixed>, paths?:array<string, mixed>, uas?:array<string, mixed>, statuses:array<string, mixed>, countries:array<string, mixed>, referers:array<string, mixed>, ips?:array<string, mixed>, family?:string, name?:string, src_used:string, from:int, to:int, basis:string, clipped:bool, ips_approx:bool}
	 */
	public static function detail( $kind, $key, $filters = array() ) {
		$kind             = in_array( (string) $kind, array( 'ua', 'path', 'ip' ), true ) ? (string) $kind : 'path';
		$filters          = is_array( $filters ) ? $filters : array();
		$filters[ $kind ] = (string) $key;
		$f                = self::filters( $filters );
		$summary          = self::overview( $f );
		$out              = array(
			'kind'    => $kind,
			'key'     => (string) $f[ $kind ],
			'summary' => $summary,
		);
		$parts            = array(
			'paths'     => 'path',
			'uas'       => 'ua',
			'statuses'  => 'status',
			'countries' => 'country',
			'referers'  => 'referer',
			'ips'       => 'ip',
		);
		$dims             = array_values( array_diff( $parts, array( $kind ) ) );
		if ( 'ua' === $kind ) {
			$dims[] = 'ua_family';
		}
		$scan = self::detail_scan( $dims, $f );
		foreach ( $parts as $name => $dim ) {
			if ( $dim === $kind ) {
				continue;
			}
			$out[ $name ] = isset( $scan[ $dim ] ) ? $scan[ $dim ] : self::top( $dim, $f, 10 );
		}
		if ( 'ua' === $kind ) {
			$c             = PNCP_Traffic_Ua::classify( $out['key'] );
			$out['family'] = $c['family'];
			$out['name']   = $c['name'];
			$families      = isset( $scan['ua_family'] ) ? $scan['ua_family'] : self::top( 'ua_family', $f, 10 );
			if ( ! empty( $families['rows'][0]['key'] ) ) {
				$out['family'] = (string) $families['rows'][0]['key']; // As stored: verified or fake by the IPs seen.
			}
		}
		return array_merge( $out, array_intersect_key( $summary, array_flip( array( 'src_used', 'from', 'to', 'basis', 'clipped', 'ips_approx' ) ) ) );
	}

	/**
	 * Would top() answer a dimension with these filters from the raw rows?
	 *
	 * @param string               $dim Dimension.
	 * @param array<string, mixed> $f   Filters.
	 * @return bool
	 */
	private static function answers_raw( $dim, $f ) {
		if ( self::in_raw( $f ) || ! PNCP_Traffic::ready() ) {
			return true;
		}
		if ( null !== self::agg_top_condition( $dim, $f ) ) {
			return false;
		}
		$column = 'status' !== $dim ? self::status_column( $f ) : '';
		return '' === $column || null === self::agg_top_condition( $dim, array_merge( $f, array( 'status' => null ) ) );
	}

	/**
	 * The breakdowns of a detail (the 10 busiest keys of each dimension, as top() orders them) that come from the
	 * raw rows, from one pass over the rows of that User-Agent, path or IP instead of one query per dimension (at
	 * most DETAIL_SCAN of them, the newest); the dimensions the daily figures answer are left to top().
	 *
	 * @param string[]             $dims Dimensions.
	 * @param array<string, mixed> $f    Filters (filters(), with the key's filter).
	 * @return array<string, array<string, mixed>> dimension => top() result.
	 */
	private static function detail_scan( $dims, $f ) {
		$dims = array_values(
			array_filter(
				$dims,
				static function ( $dim ) use ( $f ) {
					return self::answers_raw( $dim, $f );
				}
			)
		);
		if ( ! $dims || ! PNCP_Traffic::ready() ) {
			return array();
		}
		/**
		 * Filters the most raw rows the breakdowns of a User-Agent, path or IP detail read (the newest ones).
		 *
		 * @since 3.12.0
		 * @param int $rows Rows (default 200,000).
		 */
		$max = max( 1, (int) apply_filters( 'pncp_traffic_detail_rows', self::DETAIL_SCAN ) );
		return self::cached(
			'detail_scan|' . implode( ',', $dims ) . '|' . $max . '|' . wp_json_encode( $f ),
			static function () use ( $dims, $f, $max ) {
				return self::compute_detail_scan( $dims, $f, $max );
			}
		);
	}

	/**
	 * See detail_scan().
	 *
	 * @param string[]             $dims Dimensions.
	 * @param array<string, mixed> $f    Filters.
	 * @param int                  $max  Most rows.
	 * @return array<string, array<string, mixed>>
	 */
	private static function compute_detail_scan( $dims, $f, $max ) {
		list( $f, $clipped )  = self::in_raw( $f ) ? array( $f, false ) : self::clip( $f );
		list( $where, $args ) = self::raw_where( $f );
		$table                = PNCP_Traffic::table( 'raw' );
		$n                    = self::q( 'SELECT COUNT(*) AS n FROM %i WHERE ' . $where, array_merge( array( $table ), $args ) );
		if ( isset( $n[0]['n'] ) && (int) $n[0]['n'] > $max ) {
			// A very busy key: its newest requests ("clipped", from the first of them).
			$edge = self::q( 'SELECT ts FROM %i WHERE ' . $where . ' ORDER BY ts DESC LIMIT 1 OFFSET %d', array_merge( array( $table ), $args, array( $max - 1 ) ) );
			if ( isset( $edge[0]['ts'] ) ) {
				$f['from']            = max( (int) $f['from'], (int) $edge[0]['ts'] );
				$clipped              = true;
				list( $where, $args ) = self::raw_where( $f );
			}
		}
		$groups = array_fill_keys( $dims, array() );
		// In batches, by time (the key's own index orders them): memory holds the groups and one batch only.
		$last_ts = -1;
		$last_id = 0;
		while ( true ) {
			$batch = self::q( 'SELECT id, ts, ip, country, status, path_hash, ua_hash, fam, referer, bytes, hit FROM %i WHERE ' . $where . ' AND (ts > %d OR (ts = %d AND id > %d)) ORDER BY ts, id LIMIT %d', array_merge( array( $table ), $args, array( $last_ts, $last_ts, $last_id, self::SCAN_BATCH ) ) );
			if ( ! $batch ) {
				break;
			}
			self::scan_rows( $groups, $dims, $batch );
			$end     = end( $batch );
			$last_ts = (int) $end['ts'];
			$last_id = (int) $end['id'];
			if ( count( $batch ) < self::SCAN_BATCH ) {
				break;
			}
		}
		$out = array();
		foreach ( $dims as $dim ) {
			$list = array_values( $groups[ $dim ] );
			usort(
				$list,
				static function ( $a, $b ) use ( $dim ) {
					if ( $a['hits'] !== $b['hits'] ) {
						return $b['hits'] - $a['hits'];
					}
					return 'status' === $dim ? (int) $a['g'] - (int) $b['g'] : strcmp( $a['g'], $b['g'] );
				}
			);
			$top    = array_slice( $list, 0, 10 );
			$labels = PNCP_Traffic::labels( $dim, array_column( $top, 'g' ) );
			$rows   = array();
			foreach ( $top as $r ) {
				$r['ips']       = count( $r['ips'] );
				$r['label_key'] = isset( $labels[ $r['g'] ] ) ? $labels[ $r['g'] ] : $r['g'];
				$rows[]         = self::top_row( $dim, $r );
			}
			$out[ $dim ] = array_merge(
				array(
					'rows'       => $rows,
					'total_rows' => count( $list ),
					'has_more'   => count( $list ) > 10,
					'dimension'  => $dim,
					'order'      => 'hits',
				),
				self::meta( $f, 'raw', $clipped )
			);
		}
		return $out;
	}

	/**
	 * Adds raw rows to the groups of each dimension (compute_detail_scan()).
	 *
	 * @param array<string, array<string, array<string, mixed>>> $groups Groups (changed in place).
	 * @param string[]                                            $dims   Dimensions.
	 * @param array<int, array<string, mixed>>                    $rows   Raw rows.
	 */
	private static function scan_rows( &$groups, $dims, $rows ) {
		$cols = array(
			'ua'        => 'ua_hash',
			'ua_family' => 'fam',
			'path'      => 'path_hash',
			'referer'   => 'referer',
			'ip'        => 'ip',
			'country'   => 'country',
			'status'    => 'status',
		);
		foreach ( $rows as $r ) {
			$status = (int) $r['status'];
			foreach ( $dims as $dim ) {
				$g = (string) $r[ $cols[ $dim ] ];
				$k = 'ua' === $dim ? $g . '|' . $r['fam'] : $g;
				if ( ! isset( $groups[ $dim ][ $k ] ) ) {
					$groups[ $dim ][ $k ] = array(
						'g'      => $g,
						'fam'    => (string) $r['fam'],
						'hits'   => 0,
						'ips'    => array(),
						'bytes'  => 0,
						's4xx'   => 0,
						's5xx'   => 0,
						'misses' => 0,
						'first'  => PHP_INT_MAX,
						'last'   => 0,
					);
				}
				$x                             = &$groups[ $dim ][ $k ];
				$x['hits']                    += 1;
				$x['ips'][ (string) $r['ip'] ] = true;
				$x['bytes']                   += (int) $r['bytes'];
				$x['s4xx']                    += $status >= 400 && $status < 500 ? 1 : 0;
				$x['s5xx']                    += $status >= 500 && $status < 600 ? 1 : 0;
				$x['misses']                  += 0 === (int) $r['hit'] ? 1 : 0;
				$x['first']                    = min( $x['first'], (int) $r['ts'] );
				$x['last']                     = max( $x['last'], (int) $r['ts'] );
				$x['fam']                      = strcmp( (string) $r['fam'], $x['fam'] ) > 0 ? (string) $r['fam'] : $x['fam'];
				unset( $x );
			}
		}
	}

	/* ---------- Raw rows ---------- */

	/**
	 * The requests themselves, newest first (raw window only: "from" is moved to its start when earlier).
	 *
	 * @param array<string, mixed> $filters Filters (see filters()).
	 * @param int                  $limit   Rows, 1 to 500.
	 * @param int                  $offset  Rows to skip.
	 * @return array{rows:array<int, array{id:int, ts:int, src:string, ip:string, country:string, method:string, status:int, path:string, query:string, referer:string, ua:string, family:string, bytes:int, cache:string, edge:string, rt_ms:int|null}>, has_more:bool, src_used:string, from:int, to:int, basis:string, clipped:bool, ips_approx:bool}
	 */
	public static function raw( $filters = array(), $limit = 100, $offset = 0 ) {
		$limit               = max( 1, min( self::MAX_LIMIT, (int) $limit ) );
		$offset              = max( 0, (int) $offset );
		list( $f, $clipped ) = self::clip( self::filters( $filters ) );
		$out                 = array();
		$more                = false;
		if ( PNCP_Traffic::ready() ) {
			list( $where, $args ) = self::raw_where( $f );
			$rows                 = self::q( 'SELECT id, ts, src, ip, country, method, status, path, query, referer, ua, fam, bytes, cache, edge, rt_ms FROM %i WHERE ' . $where . ' ORDER BY ts DESC, id DESC LIMIT %d OFFSET %d', array_merge( array( PNCP_Traffic::table( 'raw' ) ), $args, array( $limit + 1, $offset ) ) );
			$more                 = count( $rows ) > $limit;
			foreach ( array_slice( $rows, 0, $limit ) as $r ) {
				$out[] = self::raw_row( $r );
			}
		}
		return array_merge(
			array(
				'rows'     => $out,
				'has_more' => $more,
			),
			self::meta( $f, 'raw', $clipped )
		);
	}

	/**
	 * A raw row with its types.
	 *
	 * @param array<string, mixed> $r Query row.
	 * @return array{id:int, ts:int, src:string, ip:string, country:string, method:string, status:int, path:string, query:string, referer:string, ua:string, family:string, bytes:int, cache:string, edge:string, rt_ms:int|null}
	 */
	private static function raw_row( $r ) {
		return array(
			'id'      => (int) $r['id'],
			'ts'      => (int) $r['ts'],
			'src'     => (string) $r['src'],
			'ip'      => PNCP_Traffic::shown_ip( (string) $r['ip'] ),
			'country' => (string) $r['country'],
			'method'  => (string) $r['method'],
			'status'  => (int) $r['status'],
			'path'    => (string) $r['path'],
			'query'   => (string) $r['query'],
			'referer' => (string) $r['referer'],
			'ua'      => (string) $r['ua'],
			'family'  => (string) $r['fam'],
			'bytes'   => (int) $r['bytes'],
			'cache'   => (string) $r['cache'],
			'edge'    => (string) $r['edge'],
			'rt_ms'   => null === $r['rt_ms'] ? null : (int) $r['rt_ms'],
		);
	}

	/* ---------- CSV ---------- */

	/**
	 * A CSV cell that a spreadsheet will not run as a formula (a leading = + - @, tab or carriage return gets a ').
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	public static function csv_cell( $value ) {
		$value = (string) $value;
		return '' !== $value && false !== strpos( "=+-@\t\r", $value[0] ) ? "'" . $value : $value;
	}

	/**
	 * Streams the raw rows (raw window, newest first) as CSV, in batches, at most CSV_MAX rows (filter
	 * `pncp_traffic_csv_max_rows`). Sends no headers: the caller does.
	 *
	 * @param array<string, mixed> $filters Filters (see filters()).
	 * @param resource             $handle  Stream to write to.
	 * @return int Rows written.
	 */
	public static function export_csv( $filters, $handle ) {
		if ( ! is_resource( $handle ) ) {
			return 0;
		}
		list( $f ) = self::clip( self::filters( $filters ) );
		/**
		 * Filters the most rows of a Traffic CSV export.
		 *
		 * @since 3.12.0
		 * @param int $rows Rows (default 100,000).
		 */
		$max   = max( 1, (int) apply_filters( 'pncp_traffic_csv_max_rows', self::CSV_MAX ) );
		$tz    = wp_timezone();
		$count = 0;
		fputcsv( $handle, array( 'time', 'source', 'ip', 'country', 'method', 'status', 'path', 'query', 'referer', 'user_agent', 'family', 'bytes', 'cache', 'edge', 'response_ms' ), ',', '"', '\\' );
		if ( ! PNCP_Traffic::ready() ) {
			return 0;
		}
		list( $where, $args ) = self::raw_where( $f );
		$last_ts              = PHP_INT_MAX;
		$last_id              = PHP_INT_MAX;
		while ( $count < $max ) {
			$batch = min( 1000, $max - $count );
			$rows  = self::q( 'SELECT id, ts, src, ip, country, method, status, path, query, referer, ua, fam, bytes, cache, edge, rt_ms FROM %i WHERE ' . $where . ' AND (ts < %d OR (ts = %d AND id < %d)) ORDER BY ts DESC, id DESC LIMIT %d', array_merge( array( PNCP_Traffic::table( 'raw' ) ), $args, array( min( $last_ts, 4294967295 ), min( $last_ts, 4294967295 ), min( $last_id, PHP_INT_MAX ), $batch ) ) );
			if ( ! $rows ) {
				break;
			}
			foreach ( $rows as $r ) {
				$r    = self::raw_row( $r );
				$time = new DateTime( '@' . $r['ts'] );
				$time->setTimezone( $tz );
				fputcsv(
					$handle,
					array_map(
						array( __CLASS__, 'csv_cell' ),
						array( $time->format( 'Y-m-d H:i:s' ), $r['src'], $r['ip'], $r['country'], $r['method'], $r['status'], $r['path'], $r['query'], $r['referer'], $r['ua'], $r['family'], $r['bytes'], $r['cache'], $r['edge'], null === $r['rt_ms'] ? '' : $r['rt_ms'] )
					),
					',',
					'"',
					'\\'
				);
				++$count;
				$last_ts = $r['ts'];
				$last_id = $r['id'];
			}
			if ( count( $rows ) < $batch ) {
				break;
			}
		}
		return $count;
	}
}
