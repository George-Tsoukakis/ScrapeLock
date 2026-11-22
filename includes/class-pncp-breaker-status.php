<?php
/**
 * 3.12.9: what the circuit breaker (PNCP_Breaker) shows in WordPress: the Site Health test, the notice on the
 * ScrapeLock page and the Dashboard, the line in Site Health's info (and `wp scrapelock status`), "Resume
 * counting", `wp scrapelock breaker`, and the hourly tidy-up.
 *
 * With APCu as the store, WP-CLI does not see PHP-FPM's APCu: WordPress's admin pages and scheduled events copy
 * the state to a small file (snapshot) that WP-CLI reads, and a reset from WP-CLI is left there as a request that
 * the next admin page or scheduled event carries out. Never in a visitor's request.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The circuit breaker in wp-admin, Site Health and WP-CLI.
 */
final class PNCP_Breaker_Status {

	/**
	 * The admin-post action of "Resume counting".
	 */
	const RESET = 'pncp_breaker_reset';

	/**
	 * Registers the hooks (admin, scheduled events, WP-CLI).
	 */
	public static function init() {
		add_action( PNCP_Log::CRON, array( __CLASS__, 'hourly' ), 7 );
		if ( is_admin() ) {
			add_action( 'admin_init', array( __CLASS__, 'sync' ) );
			add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
			add_action( 'admin_post_' . self::RESET, array( __CLASS__, 'handle_reset' ) );
		}
	}

	/**
	 * Hourly: the tidy-up and the copy for WP-CLI.
	 */
	public static function hourly() {
		self::sync();
		PNCP_Breaker::tidy();
	}

	/**
	 * The name of a feature, for people.
	 *
	 * @param string $name Feature.
	 * @return string
	 */
	public static function label( $name ) {
		$labels = array(
			'precheck_files' => __( 'Pre-cache check counters (files)', 'scrapelock' ),
			'precheck_apcu'  => __( 'Pre-cache check counters (APCu)', 'scrapelock' ),
			'precheck_redis' => __( 'Pre-cache check counters (Redis)', 'scrapelock' ),
			'dns'            => __( 'DNS verification of search engines', 'scrapelock' ),
			'surge'          => __( 'Site-wide page count', 'scrapelock' ),
		);
		return isset( $labels[ $name ] ) ? $labels[ $name ] : $name;
	}

	/**
	 * What to do about a feature that tripped.
	 *
	 * @param string $name Feature.
	 * @return string
	 */
	public static function advice( $name ) {
		if ( 'dns' === $name || 0 === strpos( $name, 'dns_' ) ) {
			return __( 'The server\'s DNS resolver answers slowly: check /etc/resolv.conf or use a local caching resolver.', 'scrapelock' );
		}
		if ( '_redis' === substr( $name, -6 ) ) {
			return __( 'Redis answers slowly: check its latency (redis-cli --latency), its memory and that the server is not swapping.', 'scrapelock' );
		}
		if ( '_files' === substr( $name, -6 ) ) {
			return __( 'The disk stalls: install APCu (or use Redis) so counters stay in memory, check iowait and swap (sar, iostat), and raise pm.max_children if PHP workers run out.', 'scrapelock' );
		}
		return __( 'The server stalls: check the disk\'s iowait and swap (sar, iostat), the database load, and raise pm.max_children if PHP workers run out.', 'scrapelock' );
	}

	/**
	 * The report (PNCP_Breaker::report()), or WP-CLI's copy of PHP-FPM's when the state is in APCu.
	 *
	 * @return array{rows: array<string, array<string, mixed>>, kind: string, as_of: int}
	 */
	public static function report() {
		$snap = self::snapshot_for_cli();
		if ( null !== $snap ) {
			return array(
				'rows'  => $snap['rows'],
				'kind'  => 'apcu',
				'as_of' => (int) $snap['at'],
			);
		}
		return array(
			'rows'  => PNCP_Breaker::report( 24 ),
			'kind'  => PNCP_Breaker::kind(),
			'as_of' => 0,
		);
	}

	/**
	 * WP-CLI only, with APCu as PHP-FPM's store: the last copy, or null.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function snapshot_for_cli() {
		if ( ! ( defined( 'WP_CLI' ) && WP_CLI ) || 'apcu' === PNCP_Breaker::kind() || '' === PNCP_Breaker::dir() ) {
			return null;
		}
		$snap = json_decode( (string) @file_get_contents( PNCP_Breaker::dir() . '/breaker/_snapshot.json' ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- A local file that may be missing.
		// Written at least hourly (scheduled events) while PHP-FPM keeps the state in APCu: an older copy is stale.
		if ( ! is_array( $snap ) || ! isset( $snap['kind'], $snap['at'], $snap['rows'] ) || 'apcu' !== $snap['kind'] || ! is_array( $snap['rows'] ) || (int) $snap['at'] < time() - 2 * HOUR_IN_SECONDS ) {
			return null;
		}
		return $snap;
	}

	/**
	 * Admin pages and scheduled events, with APCu as the store: carries out a reset asked by WP-CLI and copies
	 * the state for WP-CLI. Nothing with any other store.
	 */
	public static function sync() {
		if ( '' === PNCP_Breaker::dir() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$folder = PNCP_Breaker::dir() . '/breaker';
		if ( 'apcu' !== PNCP_Breaker::kind() ) {
			// No longer APCu (Redis now, or APCu removed): WP-CLI reads the store itself.
			foreach ( array( '_snapshot.json', '_reset.json' ) as $name ) {
				if ( is_file( $folder . '/' . $name ) ) {
					wp_delete_file( $folder . '/' . $name );
				}
			}
			return;
		}
		$ask    = $folder . '/_reset.json';
		if ( is_file( $ask ) ) {
			$want = json_decode( (string) @file_get_contents( $ask ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- A local file.
			wp_delete_file( $ask );
			PNCP_Breaker::reset( is_array( $want ) && isset( $want['name'] ) ? (string) $want['name'] : '', ! empty( $want['history'] ) );
		}
		$rows = PNCP_Breaker::report( 24 );
		if ( ! $rows && ! is_file( $folder . '/_snapshot.json' ) ) {
			return;
		}
		self::write(
			$folder,
			'_snapshot.json',
			array(
				'kind' => 'apcu',
				'at'   => time(),
				'rows' => $rows,
			)
		);
	}

	/**
	 * Writes a small JSON file atomically (temporary file, then rename).
	 *
	 * @param string               $folder Folder.
	 * @param string               $name   File name.
	 * @param array<string, mixed> $value  Value.
	 */
	private static function write( $folder, $name, $value ) {
		// 3.12.10: written by WP-CLI as root too (_reset.json): the folder and the file then go to the owner of the
		// WordPress folder and a replaced file keeps its owner and mode (PNCP_File_Owner), for PHP-FPM to read them.
		if ( ! is_dir( $folder ) && ! ( PNCP_File_Owner::is_root() ? PNCP_File_Owner::mkdir( $folder, 0755 ) : wp_mkdir_p( $folder ) ) ) {
			return;
		}
		PNCP_File_Owner::put( $folder . '/' . $name, (string) wp_json_encode( $value ), 0644 );
	}

	/**
	 * Ends the suspensions (all or one); from WP-CLI with APCu, asks PHP-FPM to do it (sync()).
	 *
	 * @param string $name    Feature ('' = all).
	 * @param bool   $history Also clear the history.
	 * @return int|null How many were suspended (null: asked, done by the next admin page or scheduled event).
	 */
	public static function reset( $name = '', $history = false ) {
		if ( null !== self::snapshot_for_cli() ) {
			self::write(
				PNCP_Breaker::dir() . '/breaker',
				'_reset.json',
				array(
					'name'    => $name,
					'history' => $history,
				)
			);
			return null;
		}
		return PNCP_Breaker::reset( $name, $history );
	}

	/**
	 * The time of day of a trip.
	 *
	 * @param int $time Time.
	 * @return string
	 */
	private static function when( $time ) {
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $time );
	}

	/**
	 * One feature in words: what, when, how long it took, until when, how often.
	 *
	 * @param string               $name Feature.
	 * @param array<string, mixed> $row  Its row of the report.
	 * @return string
	 */
	public static function describe( $name, $row ) {
		$text = sprintf(
			/* translators: 1: feature, 2: date and time, 3: milliseconds, 4: the threshold in milliseconds */
			__( '%1$s: one operation took %3$s ms at %2$s (limit %4$s ms).', 'scrapelock' ),
			self::label( $name ),
			self::when( (int) $row['at'] ),
			number_format_i18n( (float) $row['ms'], floor( (float) $row['ms'] ) === (float) $row['ms'] ? 0 : 1 ),
			number_format_i18n( isset( $row['limit'] ) ? (float) $row['limit'] : PNCP_Breaker::threshold( $name ) )
		);
		$text .= ' ' . ( ! empty( $row['open'] )
			/* translators: %s: date and time */
			? sprintf( __( 'Suspended until %s: requests pass without it.', 'scrapelock' ), self::when( (int) $row['until'] ) )
			: __( 'Working again.', 'scrapelock' ) );
		$text .= ' ' . sprintf(
			/* translators: %d: number of times */
			_n( 'Tripped %d time in the last 24 hours.', 'Tripped %d times in the last 24 hours.', (int) $row['count'], 'scrapelock' ),
			(int) $row['count']
		);
		return $text;
	}

	/**
	 * The details as HTML (a list with the advice per feature).
	 *
	 * @param array<string, array<string, mixed>> $rows Report.
	 * @return string
	 */
	private static function details_html( $rows ) {
		$html = '<ul>';
		foreach ( $rows as $name => $row ) {
			$html .= '<li>' . esc_html( self::describe( $name, $row ) ) . ' <em>' . esc_html( self::advice( $name ) ) . '</em></li>';
		}
		return $html . '</ul>';
	}

	/**
	 * Is any feature suspended now?
	 *
	 * @param array<string, array<string, mixed>> $rows Report.
	 * @return bool
	 */
	private static function any_open( $rows ) {
		foreach ( $rows as $row ) {
			if ( ! empty( $row['open'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The "Resume counting" form.
	 *
	 * @return string
	 */
	private static function reset_form() {
		return '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">'
			. '<input type="hidden" name="action" value="' . esc_attr( self::RESET ) . '">'
			. wp_nonce_field( self::RESET, '_wpnonce', true, false )
			. '<button type="submit" class="button button-secondary">' . esc_html__( 'Resume counting now', 'scrapelock' ) . '</button></form>';
	}

	/**
	 * Site Health: good while nothing tripped in the last 24 hours; critical while a feature is suspended;
	 * recommended when one tripped and works again.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_test() {
		$rows   = self::report()['rows'];
		$result = array(
			'label'       => __( 'ScrapeLock counting and storage are fast', 'scrapelock' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Performance', 'scrapelock' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html(
				sprintf(
					/* translators: %s: milliseconds */
					__( 'No counting or storage operation took longer than %s ms in the last 24 hours.', 'scrapelock' ),
					number_format_i18n( PNCP_Breaker::threshold( 'precheck' ) )
				)
			) . '</p>',
			'actions'     => '',
			'test'        => 'scrapelock_breaker',
		);
		if ( ! $rows ) {
			return $result;
		}
		$open                          = self::any_open( $rows );
		$result['status']              = $open ? 'critical' : 'recommended';
		$result['badge']['color']      = $open ? 'red' : 'orange';
		$result['label']               = $open ? __( 'ScrapeLock suspended slow counting', 'scrapelock' ) : __( 'ScrapeLock counting was slow in the last 24 hours', 'scrapelock' );
		$result['description']         = '<p>' . esc_html(
			$open
				? __( 'An operation was too slow, so it is suspended for a while: requests pass without it, bans still apply.', 'scrapelock' )
				: __( 'An operation was too slow and was suspended for a while; it works again.', 'scrapelock' )
		) . '</p>' . self::details_html( $rows );
		$result['actions']             = $open && current_user_can( 'manage_options' ) ? '<p>' . self::reset_form() . '</p>' : '';
		return $result;
	}

	/**
	 * The notice on the ScrapeLock page and the Dashboard while a feature is suspended: one line, the details
	 * under "More".
	 */
	public static function notice() {
		if ( ! current_user_can( 'manage_options' ) || ! PNCP_Status::notice_screen() ) {
			return;
		}
		$rows = PNCP_Breaker::report( 24 );
		if ( ! self::any_open( $rows ) ) {
			return;
		}
		echo '<div class="notice notice-warning pncp-breaker"><p><strong>ScrapeLock:</strong> '
			. esc_html__( 'slow storage, so counting is suspended for a while. Visitors pass; bans still apply.', 'scrapelock' )
			. '</p><details class="pncp-more"><summary>' . esc_html__( 'More', 'scrapelock' ) . '</summary><div class="pncp-more__body">'
			. self::details_html( $rows ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in details_html().
			. '</div></details><p>'
			. self::reset_form() // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in reset_form().
			. '</p></div>';
	}

	/**
	 * "Resume counting now" (admin-post, nonce, manage_options).
	 */
	public static function handle_reset() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::RESET );
		PNCP_Breaker::reset();
		$back = wp_get_referer();
		wp_safe_redirect( $back ? $back : admin_url( 'site-health.php' ) );
		exit;
	}

	/**
	 * Which backend ScrapeLock's counters use: the one the pre-cache check recorded in the last day
	 * (PNCP_Breaker::record_backend()), else inferred: phpredis with the WP_REDIS_* constants of a Redis object
	 * cache, APCu when enabled in this PHP (never seen from WP-CLI), else files.
	 *
	 * @return array{kind: string, inferred: bool, cli: bool}
	 */
	public static function counters() {
		$cli  = defined( 'WP_CLI' ) && WP_CLI;
		$seen = PNCP_Breaker::recorded_backend();
		if ( $seen && (int) $seen['at'] > time() - DAY_IN_SECONDS && in_array( $seen['kind'], array( 'redis', 'apcu', 'files' ), true ) ) {
			return array(
				'kind'     => (string) $seen['kind'],
				'inferred' => false,
				'cli'      => $cli,
			);
		}
		$kind = 'files';
		if ( class_exists( 'Redis', false ) && ( defined( 'WP_REDIS_HOST' ) || defined( 'WP_REDIS_PATH' ) || defined( 'WP_REDIS_SCHEME' ) || defined( 'WP_REDIS_VERSION' ) ) ) {
			$kind = 'redis';
		} elseif ( function_exists( 'apcu_enabled' ) && apcu_enabled() && apply_filters( 'pncp_precheck_apcu', true ) && in_array( PHP_SAPI, (array) apply_filters( 'pncp_precheck_apcu_sapis', array( 'fpm-fcgi', 'apache2handler' ) ), true ) ) {
			// As PNCP_Precheck_Runtime::apcu_usable(): only where APCu is shared by every PHP process.
			$kind = 'apcu';
		}
		return array(
			'kind'     => $kind,
			'inferred' => true,
			'cli'      => $cli,
		);
	}

	/**
	 * The counters' backend in words.
	 *
	 * @param array{kind: string, inferred: bool, cli: bool} $counters counters().
	 * @return string
	 */
	public static function counters_text( $counters ) {
		$names = array(
			'redis' => 'Redis',
			'apcu'  => 'APCu',
			'files' => __( 'files', 'scrapelock' ),
		);
		$text = isset( $names[ $counters['kind'] ] ) ? $names[ $counters['kind'] ] : $counters['kind'];
		if ( $counters['inferred'] ) {
			$text .= ' ' . __( '(inferred)', 'scrapelock' );
		}
		if ( $counters['cli'] && 'files' === $counters['kind'] && $counters['inferred'] ) {
			$text .= ' — ' . __( 'WP-CLI cannot see PHP-FPM\'s APCu: Site Health shows what the site uses.', 'scrapelock' );
		}
		return $text;
	}

	/**
	 * Site Health "ScrapeLock counters": good with Redis or APCu, recommended with files; plus the breaker's line.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_counters() {
		$counters = self::counters();
		$memory   = 'files' !== $counters['kind'];
		$details  = '<p>' . esc_html(
			sprintf(
				/* translators: 1: Redis, APCu or files, 2: the circuit breaker's state */
				__( 'Counters: %1$s. Circuit breaker: %2$s.', 'scrapelock' ),
				self::counters_text( $counters ),
				self::info()
			)
		) . '</p>';
		return array(
			'label'       => $memory
				/* translators: %s: Redis or APCu */
				? sprintf( __( 'ScrapeLock counts in memory (%s)', 'scrapelock' ), 'redis' === $counters['kind'] ? 'Redis' : 'APCu' )
				: __( 'ScrapeLock counts in files on the disk', 'scrapelock' ),
			'status'      => $memory ? 'good' : 'recommended',
			'badge'       => array(
				'label' => __( 'Performance', 'scrapelock' ),
				'color' => $memory ? 'blue' : 'orange',
			),
			'description' => '<p>' . esc_html(
				$memory
					? __( 'Visitors\' requests are counted without touching the disk.', 'scrapelock' )
					: __( 'Install APCu or a Redis object cache so ScrapeLock never touches the disk in visitors\' requests.', 'scrapelock' )
			) . '</p>' . $details,
			'actions'     => '',
			'test'        => 'scrapelock_counters',
		);
	}

	/**
	 * The line of Site Health's info and `wp scrapelock status`.
	 *
	 * @return string
	 */
	public static function info() {
		$rows = self::report()['rows'];
		if ( ! $rows ) {
			return __( 'Nothing tripped in the last 24 hours', 'scrapelock' );
		}
		$parts = array();
		foreach ( $rows as $name => $row ) {
			$parts[] = ! empty( $row['open'] )
				/* translators: 1: feature, 2: time */
				? sprintf( __( '%1$s suspended until %2$s', 'scrapelock' ), $name, wp_date( 'H:i', (int) $row['until'] ) )
				/* translators: 1: feature, 2: number of times */
				: sprintf( __( '%1$s tripped %2$d× in 24 h', 'scrapelock' ), $name, (int) $row['count'] );
		}
		return implode( '; ', $parts );
	}

	/**
	 * `wp scrapelock breaker [status|reset] [<feature>] [--history] [--format=…]`.
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cli( $args, $assoc_args ) {
		$action = isset( $args[0] ) ? (string) $args[0] : 'status';
		$name   = isset( $args[1] ) ? (string) $args[1] : '';
		if ( '' !== $name && ! PNCP_Breaker::valid( $name ) ) {
			WP_CLI::error( __( 'Unknown feature name.', 'scrapelock' ) );
		}
		if ( 'reset' === $action ) {
			$count = self::reset( $name, ! empty( $assoc_args['history'] ) );
			if ( null === $count ) {
				WP_CLI::success( __( 'Asked: the next admin page or scheduled event resumes counting (the state is in PHP-FPM\'s APCu).', 'scrapelock' ) );
				return;
			}
			/* translators: %d: number of features */
			WP_CLI::success( sprintf( _n( 'Counting resumed (%d feature was suspended).', 'Counting resumed (%d features were suspended).', $count, 'scrapelock' ), $count ) );
			return;
		}
		if ( 'status' !== $action ) {
			WP_CLI::error( __( 'Use "status" or "reset".', 'scrapelock' ) );
		}
		$report = self::report();
		$items  = array();
		foreach ( $report['rows'] as $key => $row ) {
			if ( '' !== $name && $key !== $name ) {
				continue;
			}
			$items[] = array(
				'feature' => $key,
				'state'   => ! empty( $row['open'] ) ? 'open' : 'closed',
				'until'   => ! empty( $row['open'] ) ? wp_date( 'Y-m-d H:i:s', (int) $row['until'] ) : '-',
				'tripped' => wp_date( 'Y-m-d H:i:s', (int) $row['at'] ),
				'ms'      => (string) $row['ms'],
				'limit'   => (string) ( isset( $row['limit'] ) ? $row['limit'] : PNCP_Breaker::threshold( $key ) ),
				'trips24' => (string) $row['count'],
				'what'    => (string) $row['what'],
				'advice'  => self::advice( $key ),
			);
		}
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( ! $items && 'table' === $format ) {
			/* translators: %s: store (redis, apcu, files) */
			WP_CLI::line( sprintf( __( 'Nothing tripped in the last 24 hours (store: %s).', 'scrapelock' ), $report['kind'] ) );
			return;
		}
		if ( $report['as_of'] && 'table' === $format ) {
			/* translators: %s: date and time */
			WP_CLI::line( sprintf( __( 'PHP-FPM\'s state (APCu) as of %s.', 'scrapelock' ), wp_date( 'Y-m-d H:i:s', $report['as_of'] ) ) );
		}
		WP_CLI\Utils\format_items( $format, $items, array( 'feature', 'state', 'until', 'tripped', 'ms', 'limit', 'trips24', 'what', 'advice' ) );
	}
}
