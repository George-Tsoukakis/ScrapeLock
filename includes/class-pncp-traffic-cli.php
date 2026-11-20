<?php
/**
 * 3.12: WP-CLI "wp scrapelock traffic <subcommand>" (PNCP_Cli::traffic()): the sources, the figures, the raw
 * requests, a CSV export, delete everything, run the scheduled job now, test an access log path.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Traffic on the command line.
 */
final class PNCP_Traffic_Cli {

	/**
	 * The subcommands.
	 */
	const SUBCOMMANDS = array( 'status', 'overview', 'top', 'problems', 'raw', 'export', 'purge', 'run', 'test-path' );

	/**
	 * Runs a subcommand.
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cli( $args, $assoc_args ) {
		$sub = isset( $args[0] ) ? (string) $args[0] : 'status';
		$arg = isset( $args[1] ) ? (string) $args[1] : '';
		if ( ! in_array( $sub, self::SUBCOMMANDS, true ) ) {
			/* translators: %s: list of subcommands */
			WP_CLI::error( sprintf( __( 'Unknown subcommand. Use: %s.', 'scrapelock' ), implode( ', ', self::SUBCOMMANDS ) ) );
		}
		if ( 'test-path' === $sub ) {
			self::test_path( $arg, $assoc_args );
			return;
		}
		if ( 'status' === $sub ) {
			self::status( $assoc_args );
			return;
		}
		if ( ! PNCP_Traffic::enabled() && in_array( $sub, array( 'run' ), true ) ) {
			WP_CLI::warning( __( 'Traffic collection is off: the run only deletes what is left.', 'scrapelock' ) );
		}
		switch ( $sub ) {
			case 'overview':
				self::overview( $assoc_args );
				return;
			case 'top':
				self::top( $arg, $assoc_args );
				return;
			case 'problems':
				self::problems( $arg, $assoc_args );
				return;
			case 'raw':
				self::raw( $assoc_args );
				return;
			case 'export':
				self::export( $arg, $assoc_args );
				return;
			case 'purge':
				self::purge( $assoc_args );
				return;
			default:
				self::run();
		}
	}

	/**
	 * --format, checked: table, json, csv or yaml.
	 *
	 * @param array<string, string> $assoc_args Options.
	 * @return string
	 */
	private static function format( $assoc_args ) {
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$ok     = array( 'table', 'json', 'csv', 'yaml' );
		if ( ! in_array( $format, $ok, true ) ) {
			/* translators: %s: list of formats */
			WP_CLI::error( sprintf( __( 'Unknown --format. Use: %s.', 'scrapelock' ), implode( ', ', $ok ) ) );
		}
		return $format;
	}

	/**
	 * A time option: "24h", "7d", "30m" (that long ago), a date "2026-11-01" (its start in the site's time zone,
	 * or with $end its end), "2026-11-01 13:00", a Unix time, or "now".
	 *
	 * @param string $value Option.
	 * @param bool   $end   The end of a date.
	 * @return int|null Unix time, null = not understood.
	 */
	public static function parse_time( $value, $end = false ) {
		$value = strtolower( trim( (string) $value ) );
		if ( '' === $value ) {
			return null;
		}
		if ( 'now' === $value ) {
			return time();
		}
		if ( preg_match( '/^(\d+)\s*([mhdw])$/', $value, $m ) ) {
			$unit = array(
				'm' => MINUTE_IN_SECONDS,
				'h' => HOUR_IN_SECONDS,
				'd' => DAY_IN_SECONDS,
				'w' => WEEK_IN_SECONDS,
			);
			return time() - (int) $m[1] * $unit[ $m[2] ];
		}
		if ( preg_match( '/^\d{9,11}$/', $value ) ) {
			return (int) $value;
		}
		if ( preg_match( '/^\d{4}-\d{2}-\d{2}$/', $value ) ) {
			try {
				$d = new DateTimeImmutable( $value . ' 00:00:00', wp_timezone() );
			} catch ( Exception $e ) {
				return null;
			}
			$start = $d->getTimestamp();
			return $end ? PNCP_Traffic::add_days( $start ) - 1 : $start;
		}
		if ( preg_match( '/^\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}(?::\d{2})?$/', $value ) ) {
			try {
				return ( new DateTimeImmutable( str_replace( 't', ' ', $value ), wp_timezone() ) )->getTimestamp();
			} catch ( Exception $e ) {
				return null;
			}
		}
		return null;
	}

	/**
	 * The query filters from the options --from, --to, --src, --status, --ua, --family, --page (one path; --path is
	 * WP-CLI's own option), --path-like,
	 * --ip, --country, --cache, --search.
	 *
	 * @param array<string, string> $assoc_args Options.
	 * @return array<string, mixed>
	 */
	public static function filters( $assoc_args ) {
		$f = array();
		foreach ( array( 'from', 'to' ) as $key ) {
			if ( isset( $assoc_args[ $key ] ) ) {
				$t = self::parse_time( (string) $assoc_args[ $key ], 'to' === $key );
				if ( null === $t ) {
					/* translators: 1: option name, 2: value */
					WP_CLI::error( sprintf( __( '--%1$s: "%2$s" is not understood. Use e.g. 24h, 7d, 2026-11-01 or a Unix time.', 'scrapelock' ), $key, (string) $assoc_args[ $key ] ) );
				}
				$f[ $key ] = $t;
			}
		}
		if ( isset( $assoc_args['src'] ) && 'auto' !== $assoc_args['src'] ) {
			if ( ! in_array( (string) $assoc_args['src'], PNCP_Traffic::SOURCES, true ) ) {
				WP_CLI::error( __( '--src: use auto, bunny, server or wp.', 'scrapelock' ) );
			}
			$f['src'] = (string) $assoc_args['src'];
		}
		$map = array(
			'status'    => 'status',
			'ua'        => 'ua',
			'family'    => 'ua_family',
			'page'      => 'path', // --path is WP-CLI's own option (the WordPress folder).
			'path-like' => 'path_like',
			'ip'        => 'ip',
			'country'   => 'country',
			'cache'     => 'cache',
			'search'    => 'search',
		);
		foreach ( $map as $option => $key ) {
			if ( isset( $assoc_args[ $option ] ) && '' !== (string) $assoc_args[ $option ] ) {
				$f[ $key ] = (string) $assoc_args[ $option ];
			}
		}
		if ( isset( $f['status'] ) && ! preg_match( '/^(?:[1-5]xx|[1-9]\d\d)$/i', $f['status'] ) ) {
			WP_CLI::error( __( '--status: use a code such as 404, or 4xx / 5xx.', 'scrapelock' ) );
		}
		return $f;
	}

	/**
	 * --limit (1–500).
	 *
	 * @param array<string, string> $assoc_args Options.
	 * @param int                   $default    Default.
	 * @return int
	 */
	private static function limit( $assoc_args, $default ) {
		return isset( $assoc_args['limit'] ) ? max( 1, min( PNCP_Traffic_Query::MAX_LIMIT, (int) $assoc_args['limit'] ) ) : $default;
	}

	/**
	 * A time as a local date and time ('' for none).
	 *
	 * @param int $ts Unix time.
	 * @return string
	 */
	private static function when( $ts ) {
		return (int) $ts > 0 ? (string) wp_date( 'Y-m-d H:i:s', (int) $ts ) : '';
	}

	/**
	 * Prints what the result covers (table format only, to STDERR so piped output stays clean).
	 *
	 * @param array<string, mixed> $res    Result.
	 * @param string               $format Format.
	 */
	private static function meta_line( $res, $format ) {
		if ( 'table' !== $format ) {
			return;
		}
		$text = sprintf(
			/* translators: 1: source, 2: start, 3: end, 4: raw or agg */
			__( 'Source %1$s, %2$s to %3$s (%4$s).', 'scrapelock' ),
			(string) $res['src_used'],
			self::when( (int) $res['from'] ),
			self::when( (int) $res['to'] ),
			'raw' === $res['basis'] ? __( 'single requests', 'scrapelock' ) : __( 'daily figures', 'scrapelock' )
		);
		if ( ! empty( $res['clipped'] ) ) {
			$text .= ' ' . __( 'These filters can only be answered for the days whose single requests are still kept: the range was shortened.', 'scrapelock' );
		}
		WP_CLI::log( $text );
	}

	/**
	 * Status: the sources.
	 *
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function status( $assoc_args ) {
		$format = self::format( $assoc_args );
		$st     = PNCP_Traffic::sources_status();
		$items  = array();
		foreach ( PNCP_Traffic::SOURCES as $src ) {
			$row     = $st[ $src ];
			$code    = (string) $row['error'];
			$items[] = array(
				'source'      => $src,
				'on'          => ! empty( $row['on'] ) ? 'yes' : 'no',
				'auto'        => $st['auto'] === $src ? 'yes' : 'no',
				'last_ingest' => self::when( (int) $row['last_ingest'] ),
				'last_run'    => self::when( (int) $row['last_run'] ),
				'lines_today' => (int) $row['lines_today'],
				'error'       => $code,
				'message'     => PNCP_Traffic_Alerts::error_text( $src, $code, isset( $row['error_message'] ) ? (string) $row['error_message'] : '' ),
			);
		}
		WP_CLI\Utils\format_items( $format, $items, array( 'source', 'on', 'auto', 'last_ingest', 'last_run', 'lines_today', 'error', 'message' ) );
		if ( 'table' === $format ) {
			WP_CLI::log( $st['enabled'] ? __( 'Traffic collection: on.', 'scrapelock' ) : __( 'Traffic collection: off.', 'scrapelock' ) );
			/* translators: 1: date and time, 2: number of days */
			WP_CLI::log( sprintf( __( 'Daily figures counted: %1$s; days waiting: %2$d.', 'scrapelock' ), '' !== self::when( (int) $st['rollup']['rolled_at'] ) ? self::when( (int) $st['rollup']['rolled_at'] ) : '-', (int) $st['rollup']['pending'] ) );
		}
	}

	/**
	 * Overview: the totals (or with --series the time series).
	 *
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function overview( $assoc_args ) {
		$format = self::format( $assoc_args );
		$res    = PNCP_Traffic::overview( self::filters( $assoc_args ) );
		if ( ! empty( $assoc_args['series'] ) ) {
			$items = array();
			foreach ( $res['series'] as $b ) {
				$items[] = array(
					'time' => self::when( (int) $b['t'] ),
					'hits' => (int) $b['hits'],
					's4xx' => (int) $b['s4xx'],
					's5xx' => (int) $b['s5xx'],
				);
			}
			WP_CLI\Utils\format_items( $format, $items, array( 'time', 'hits', 's4xx', 's5xx' ) );
			self::meta_line( $res, $format );
			return;
		}
		$items = array();
		foreach ( array( 'total', 'ips', 'bytes', 's2xx', 's3xx', 's4xx', 's5xx', 'cache_hits', 'cache_misses' ) as $key ) {
			$items[] = array(
				'metric' => $key,
				'value'  => (int) $res[ $key ],
			);
		}
		foreach ( array( 'src_used', 'basis' ) as $key ) {
			$items[] = array(
				'metric' => $key,
				'value'  => (string) $res[ $key ],
			);
		}
		$items[] = array(
			'metric' => 'from',
			'value'  => self::when( (int) $res['from'] ),
		);
		$items[] = array(
			'metric' => 'to',
			'value'  => self::when( (int) $res['to'] ),
		);
		WP_CLI\Utils\format_items( $format, $items, array( 'metric', 'value' ) );
	}

	/**
	 * Top keys of a dimension.
	 *
	 * @param string                $dim        Dimension.
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function top( $dim, $assoc_args ) {
		if ( ! in_array( $dim, PNCP_Traffic_Query::TOP, true ) ) {
			/* translators: %s: list of dimensions */
			WP_CLI::error( sprintf( __( 'Give a dimension: %s.', 'scrapelock' ), implode( ', ', PNCP_Traffic_Query::TOP ) ) );
		}
		$format = self::format( $assoc_args );
		$order  = isset( $assoc_args['order'] ) ? (string) $assoc_args['order'] : 'hits';
		$res    = PNCP_Traffic::top( $dim, self::filters( $assoc_args ), self::limit( $assoc_args, 20 ), isset( $assoc_args['offset'] ) ? max( 0, (int) $assoc_args['offset'] ) : 0, $order );
		$items  = array();
		foreach ( $res['rows'] as $r ) {
			$items[] = array(
				'key'    => (string) $r['key'],
				'hits'   => (int) $r['hits'],
				'ips'    => (int) $r['ips'],
				'bytes'  => (int) $r['bytes'],
				's4xx'   => (int) $r['s4xx'],
				's5xx'   => (int) $r['s5xx'],
				'misses' => (int) $r['misses'],
				'family' => isset( $r['family'] ) ? (string) $r['family'] : '',
				'name'   => isset( $r['name'] ) ? (string) $r['name'] : '',
				'last'   => self::when( (int) $r['last'] ),
			);
		}
		$fields = array( 'key', 'hits', 'ips', 'bytes', 's4xx', 's5xx', 'misses', 'last' );
		if ( in_array( $dim, array( 'ua', 'ua_family' ), true ) ) {
			array_splice( $fields, 1, 0, 'ua' === $dim ? array( 'family', 'name' ) : array( 'name' ) );
		}
		WP_CLI\Utils\format_items( $format, $items, $fields );
		self::meta_line( $res, $format );
	}

	/**
	 * Problems of one kind.
	 *
	 * @param string                $type       Kind.
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function problems( $type, $assoc_args ) {
		if ( ! in_array( $type, PNCP_Traffic_Query::PROBLEMS, true ) ) {
			/* translators: %s: list of kinds */
			WP_CLI::error( sprintf( __( 'Give a kind: %s.', 'scrapelock' ), implode( ', ', PNCP_Traffic_Query::PROBLEMS ) ) );
		}
		$format = self::format( $assoc_args );
		$res    = PNCP_Traffic::problems( $type, self::filters( $assoc_args ), self::limit( $assoc_args, 20 ), isset( $assoc_args['offset'] ) ? max( 0, (int) $assoc_args['offset'] ) : 0 );
		if ( empty( $res['available'] ) ) {
			WP_CLI::warning( __( 'This source does not record what this kind needs (cache status or response time).', 'scrapelock' ) );
		}
		$items = array();
		foreach ( $res['rows'] as $r ) {
			$codes = array();
			foreach ( (array) $r['statuses'] as $code => $n ) {
				$codes[] = $code . ':' . (int) $n;
			}
			$ref     = isset( $r['top_referers'][0]['referer'] ) ? (string) $r['top_referers'][0]['referer'] : '';
			$items[] = array(
				'path'        => (string) $r['path'],
				'hits'        => (int) $r['hits'],
				'ips'         => (int) $r['ips'],
				'statuses'    => implode( ', ', $codes ),
				'top_referer' => $ref,
				'avg_bytes'   => isset( $r['avg_bytes'] ) ? (int) $r['avg_bytes'] : 0,
				'avg_rt_ms'   => isset( $r['avg_rt_ms'] ) ? (int) $r['avg_rt_ms'] : '',
				'last'        => self::when( (int) $r['last'] ),
			);
		}
		WP_CLI\Utils\format_items( $format, $items, array( 'path', 'hits', 'ips', 'statuses', 'top_referer', 'avg_bytes', 'avg_rt_ms', 'last' ) );
		self::meta_line( $res, $format );
	}

	/**
	 * The raw requests, newest first.
	 *
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function raw( $assoc_args ) {
		$format = self::format( $assoc_args );
		$res    = PNCP_Traffic::raw( self::filters( $assoc_args ), self::limit( $assoc_args, 50 ), isset( $assoc_args['offset'] ) ? max( 0, (int) $assoc_args['offset'] ) : 0 );
		$items  = array();
		foreach ( $res['rows'] as $r ) {
			$items[] = array(
				'time'    => self::when( (int) $r['ts'] ),
				'src'     => (string) $r['src'],
				'ip'      => (string) $r['ip'],
				'country' => (string) $r['country'],
				'method'  => (string) $r['method'],
				'status'  => (int) $r['status'],
				'path'    => (string) $r['path'],
				'query'   => (string) $r['query'],
				'referer' => (string) $r['referer'],
				'ua'      => (string) $r['ua'],
				'family'  => (string) $r['family'],
				'bytes'   => (int) $r['bytes'],
				'cache'   => (string) $r['cache'],
				'rt_ms'   => null === $r['rt_ms'] ? '' : (int) $r['rt_ms'],
			);
		}
		WP_CLI\Utils\format_items( $format, $items, array( 'time', 'src', 'ip', 'country', 'method', 'status', 'path', 'query', 'referer', 'ua', 'family', 'bytes', 'cache', 'rt_ms' ) );
		self::meta_line( $res, $format );
		if ( 'table' === $format && ! empty( $res['has_more'] ) ) {
			WP_CLI::log( __( 'More rows: use --offset or --limit.', 'scrapelock' ) );
		}
	}

	/**
	 * The raw requests as a CSV file. An existing file is replaced only with --force.
	 *
	 * @param string                $file       File.
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function export( $file, $assoc_args ) {
		if ( '' === $file ) {
			WP_CLI::error( __( 'Give the CSV file to write, e.g. wp scrapelock traffic export traffic.csv', 'scrapelock' ) );
		}
		$filters = self::filters( $assoc_args );
		if ( '-' === $file ) {
			$handle = fopen( 'php://output', 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streams to STDOUT.
			$count  = is_resource( $handle ) ? PNCP_Traffic::export_csv( $filters, $handle ) : 0;
			if ( is_resource( $handle ) ) {
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Stream.
			}
			unset( $count );
			return;
		}
		if ( file_exists( $file ) && empty( $assoc_args['force'] ) ) {
			/* translators: %s: file name */
			WP_CLI::error( sprintf( __( '%s exists already. Add --force to replace it.', 'scrapelock' ), $file ) );
		}
		$handle = @fopen( $file, 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.PHP.NoSilencedErrors.Discouraged -- A file the operator named; the error is reported below.
		if ( ! is_resource( $handle ) ) {
			WP_CLI::error( __( 'The file could not be written.', 'scrapelock' ) );
		}
		$count = PNCP_Traffic::export_csv( $filters, $handle );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Our file.
		/* translators: 1: number of rows, 2: file name */
		WP_CLI::success( sprintf( _n( '%1$d request written to %2$s.', '%1$d requests written to %2$s.', $count, 'scrapelock' ), $count, $file ) );
	}

	/**
	 * Deletes everything collected (needs --yes).
	 *
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function purge( $assoc_args ) {
		if ( empty( $assoc_args['yes'] ) ) {
			WP_CLI::error( __( 'This deletes every request and figure collected. Add --yes to do it.', 'scrapelock' ) );
		}
		PNCP_Traffic::purge_all();
		WP_CLI::success( __( 'Every request and figure collected was deleted. Collection goes on.', 'scrapelock' ) );
	}

	/**
	 * Runs the scheduled job now (the server log, the daily figures, the cleanup, the alerts).
	 */
	private static function run() {
		PNCP_Log::cache_delete( 'pncp_traffic_lock' );
		PNCP_Traffic::run();
		$st = PNCP_Traffic::sources_status();
		/* translators: 1: date and time, 2: number of days */
		WP_CLI::log( sprintf( __( 'Daily figures counted: %1$s; days waiting: %2$d.', 'scrapelock' ), '' !== self::when( (int) $st['rollup']['rolled_at'] ) ? self::when( (int) $st['rollup']['rolled_at'] ) : '-', (int) $st['rollup']['pending'] ) );
		$sent = PNCP_Traffic_Alerts::last_sent();
		if ( $sent ) {
			/* translators: %s: kinds of alert */
			WP_CLI::log( sprintf( __( 'Alerts sent: %s.', 'scrapelock' ), implode( ', ', array_keys( $sent ) ) ) );
		}
		WP_CLI::success( __( 'The traffic job ran.', 'scrapelock' ) );
	}

	/**
	 * Tests an access log path, as "Test this path" does.
	 *
	 * @param string                $path       Path.
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function test_path( $path, $assoc_args ) {
		$format = self::format( $assoc_args );
		if ( '' === $path ) {
			$path = PNCP_Traffic::settings()['log_path'];
		}
		$res   = PNCP_Traffic::test_log_path( $path );
		$items = array(
			array(
				'check' => 'code',
				'value' => (string) $res['code'],
			),
			array(
				'check' => 'message',
				'value' => PNCP_Traffic_Log::refusal_text( (string) $res['code'] ),
			),
			array(
				'check' => 'lines',
				'value' => (int) $res['lines'],
			),
			array(
				'check' => 'parsed',
				'value' => (int) $res['parsed'],
			),
			array(
				'check' => 'sample',
				'value' => null === $res['sample'] ? '' : (string) wp_json_encode( $res['sample'] ),
			),
		);
		WP_CLI\Utils\format_items( $format, $items, array( 'check', 'value' ) );
		if ( 'ok' !== $res['code'] ) {
			WP_CLI::halt( 1 );
		}
	}
}
