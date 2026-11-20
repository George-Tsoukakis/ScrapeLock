<?php
/**
 * 3.8: the full attack report ("Attacks" tab). Where bots and attackers hit the site, how many try wp-admin and
 * the sign-in, from which addresses (with country and reputation), with which User-Agents, what the Bunny CDN edge
 * saw, and for each attacked address the point that locks it ("Lock this", PNCP_Hardening). Also: a CSV export,
 * "Block IP" buttons, a weekly email summary (WP-Cron, off by default) and a widget on the WordPress dashboard.
 *
 * It only reads: the figures come from PNCP_Attacks (component 1) and, for the User-Agents, from the Log. Nothing
 * here runs on a visitor's request: the hooks are admin pages, admin-post actions, the dashboard and one weekly
 * cron event. Every figure is cached for a minute (PNCP_Log::cache_*), keyed to the record's generation, so a
 * cleared record is counted again at once.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Attack report.
 */
final class PNCP_Attack_Report {

	/**
	 * Weekly cron event of the email summary.
	 */
	const CRON = 'pncp_attack_report_weekly';

	/**
	 * Option (not autoloaded): when the last weekly email was sent (Unix time).
	 */
	const LAST_OPTION = 'pncp_attack_report_last';

	/**
	 * Per-user transient prefix of the notice shown once after an action of this tab.
	 */
	const NOTICE = 'pncp_ar_msg_';

	/**
	 * Seconds the figures are cached.
	 */
	const CACHE_TTL = 60;

	/**
	 * Minutes of the "Block 24 h" button.
	 */
	const BAN_MINUTES = 1440;

	/**
	 * The categories of the "wp-admin and sign-in" section.
	 */
	const LOGIN_CATEGORIES = array( 'login_fail', 'login_probe', 'admin_probe', 'xmlrpc' );

	/**
	 * Registers the hooks. None of them runs on a visitor's page view.
	 */
	public static function init() {
		add_action( 'admin_post_pncp_attack_export', array( __CLASS__, 'handle_export' ) );
		add_action( 'admin_post_pncp_attack_block', array( __CLASS__, 'handle_block' ) );
		add_action( 'admin_post_pncp_attack_report_send', array( __CLASS__, 'handle_send' ) );
		add_action( self::CRON, array( __CLASS__, 'send_weekly' ) );
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'register_widget' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		if ( defined( 'PNCP_OPTION' ) ) {
			add_action( 'update_option_' . PNCP_OPTION, array( __CLASS__, 'sync_schedule' ), 20, 0 );
			add_action( 'add_option_' . PNCP_OPTION, array( __CLASS__, 'sync_schedule' ), 20, 0 );
		}
		add_action( 'admin_init', array( __CLASS__, 'sync_schedule' ), 20, 0 );
	}

	/* ---------- Settings ---------- */

	/**
	 * Is the weekly email on? ("report_weekly", default off.)
	 *
	 * @param array<string, mixed>|null $s Settings.
	 * @return bool
	 */
	public static function weekly_on( $s = null ) {
		$s = null === $s ? PNCP_Options::get() : $s;
		return ! empty( $s['report_weekly'] );
	}

	/**
	 * Who gets the weekly email: the site's administration email (filter `pncp_attack_report_recipients`).
	 *
	 * @return string[]
	 */
	public static function recipients() {
		$to = (array) apply_filters( 'pncp_attack_report_recipients', array( (string) get_option( 'admin_email' ) ) );
		return array_values( array_filter( array_map( 'sanitize_email', array_map( 'strval', $to ) ), 'is_email' ) );
	}

	/**
	 * Schedules or removes the weekly event so it matches the setting (after a settings save, and on admin pages:
	 * reading the cron array costs no query, it is autoloaded).
	 */
	public static function sync_schedule() {
		if ( function_exists( 'wp_installing' ) && wp_installing() ) {
			return;
		}
		$next = wp_next_scheduled( self::CRON );
		if ( self::weekly_on( PNCP_Options::stored() ) ) {
			if ( ! $next ) {
				wp_schedule_event( self::first_run(), 'weekly', self::CRON );
			}
		} elseif ( $next ) {
			wp_clear_scheduled_hook( self::CRON );
		}
	}

	/**
	 * The next Monday, 07:40 in the site's time zone (outside the busy top of the hour).
	 *
	 * @return int Unix time.
	 */
	public static function first_run() {
		try {
			$date = new DateTimeImmutable( 'now', wp_timezone() );
			$next = $date->modify( 'monday this week' )->setTime( 7, 40 );
			if ( $next->getTimestamp() <= time() + MINUTE_IN_SECONDS ) {
				$next = $next->modify( '+1 week' );
			}
			return $next->getTimestamp();
		} catch ( Exception $e ) {
			return time() + HOUR_IN_SECONDS;
		}
	}

	/**
	 * Removes the cron event (deactivation and uninstall).
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON );
	}

	/**
	 * Uninstall: the event and the option.
	 */
	public static function uninstall() {
		self::deactivate();
		delete_option( self::LAST_OPTION );
	}

	/* ---------- Figures ---------- */

	/**
	 * Is the attack record there to read (component 1 loaded and its table created)?
	 *
	 * @return bool
	 */
	public static function available() {
		return class_exists( 'PNCP_Attacks' ) && PNCP_Attacks::ready();
	}

	/**
	 * The periods offered (days => label), without those longer than the record keeps.
	 *
	 * @return array<int, string>
	 */
	public static function periods() {
		$all  = array(
			1  => __( '24 hours', 'scrapelock' ),
			7  => __( '7 days', 'scrapelock' ),
			30 => __( '30 days', 'scrapelock' ),
			90 => __( '90 days', 'scrapelock' ),
		);
		$keep = class_exists( 'PNCP_Attacks' ) ? PNCP_Attacks::retention() : 90;
		$out  = array();
		foreach ( $all as $days => $label ) {
			if ( $days <= $keep || 1 === $days ) {
				$out[ $days ] = $label;
			}
		}
		return $out;
	}

	/**
	 * The period and kind of attack chosen on the tab (GET, read only).
	 *
	 * @return array{0:int, 1:string}
	 */
	public static function filters() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only view filters.
		$days     = isset( $_GET['pncp_ar_days'] ) ? absint( $_GET['pncp_ar_days'] ) : 7;
		$category = isset( $_GET['pncp_ar_cat'] ) ? sanitize_key( wp_unslash( $_GET['pncp_ar_cat'] ) ) : '';
		// phpcs:enable
		$periods = self::periods();
		if ( ! isset( $periods[ $days ] ) ) {
			$days = isset( $periods[7] ) ? 7 : 1;
		}
		if ( ! class_exists( 'PNCP_Attacks' ) || ! isset( PNCP_Attacks::categories()[ $category ] ) ) {
			$category = '';
		}
		return array( $days, $category );
	}

	/**
	 * The first hour of the last N days (as PNCP_Attacks counts them).
	 *
	 * @param int $days Days.
	 * @return int
	 */
	private static function since( $days ) {
		return (int) ( floor( ( time() - max( 1, (int) $days ) * DAY_IN_SECONDS ) / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
	}

	/**
	 * A figure cached for CACHE_TTL seconds, keyed to the record's generation (WP-CLI counts afresh).
	 *
	 * @param string   $name    Name and arguments.
	 * @param callable $compute Computes it.
	 * @return mixed
	 */
	private static function cached( $name, $compute ) {
		static $memo = array();
		$gen         = class_exists( 'PNCP_Attacks' ) ? (int) get_option( PNCP_Attacks::GEN_OPTION, 0 ) : 0;
		$key         = 'pncp_ar_q_' . md5( $name . '|' . $gen );
		if ( array_key_exists( $key, $memo ) ) {
			return $memo[ $key ];
		}
		$cli   = defined( 'WP_CLI' ) && WP_CLI;
		$value = $cli ? false : PNCP_Log::cache_get( $key );
		if ( ! is_array( $value ) || ! array_key_exists( 'v', $value ) ) {
			$value = array( 'v' => $compute() );
			if ( ! $cli ) {
				PNCP_Log::cache_set( $key, $value, self::CACHE_TTL );
			}
		}
		$memo[ $key ] = $value['v'];
		return $value['v'];
	}

	/**
	 * Runs a prepared read query with errors suppressed (a missing table is "nothing").
	 *
	 * @param string $sql Prepared SQL.
	 * @return array<int, array<string, string>>
	 */
	private static function rows( $sql ) {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- Plugin table; $sql is prepared by the caller.
		$rows = (array) $wpdb->get_results( $sql, ARRAY_A );
		$wpdb->suppress_errors( $suppress );
		return $rows;
	}

	/**
	 * The totals of the period, with the share refused and the sign-in figures.
	 *
	 * @param int $days Days.
	 * @return array{total:int, blocked:int, unique_ips:int, pct_blocked:float, login_total:int, login_failed:int, login_ips:int, admin:int, xmlrpc:int, by_category:array<string,int>}
	 */
	public static function kpis( $days ) {
		$sum  = self::available() ? PNCP_Attacks::summary( $days ) : array(
			'total'       => 0,
			'blocked'     => 0,
			'unique_ips'  => 0,
			'by_category' => array(),
		);
		$cats = (array) $sum['by_category'];
		$get  = static function ( $key ) use ( $cats ) {
			return isset( $cats[ $key ] ) ? (int) $cats[ $key ] : 0;
		};
		$who  = self::login_ips( $days );
		return array(
			'total'        => (int) $sum['total'],
			'blocked'      => (int) $sum['blocked'],
			'unique_ips'   => (int) $sum['unique_ips'],
			'pct_blocked'  => $sum['total'] > 0 ? round( 100 * $sum['blocked'] / $sum['total'], 1 ) : 0.0,
			'login_total'  => $get( 'login_fail' ) + $get( 'login_probe' ) + $get( 'admin_probe' ) + $get( 'xmlrpc' ),
			'login_failed' => $get( 'login_fail' ),
			'login_ips'    => $who,
			'admin'        => $get( 'admin_probe' ),
			'xmlrpc'       => $get( 'xmlrpc' ),
			'by_category'  => array_map( 'intval', $cats ),
		);
	}

	/**
	 * Per kind of attack: events, refused, addresses.
	 *
	 * @param int $days Days.
	 * @return array<string, array{hits:int, blocked:int, ips:int}>
	 */
	public static function category_stats( $days ) {
		if ( ! self::available() ) {
			return array();
		}
		$days  = max( 1, (int) $days );
		$value = self::cached(
			'cats|' . $days,
			static function () use ( $days ) {
				global $wpdb;
				$out = array();
				foreach ( self::rows( $wpdb->prepare( "SELECT category, SUM(hits) AS hits, SUM(blocked) AS blocked, COUNT(DISTINCT NULLIF(ip, '')) AS ips FROM %i WHERE hour_ts >= %d GROUP BY category HAVING hits > 0 ORDER BY hits DESC", PNCP_Attacks::table(), self::since( $days ) ) ) as $row ) {
					$out[ (string) $row['category'] ] = array(
						'hits'    => (int) $row['hits'],
						'blocked' => (int) $row['blocked'],
						'ips'     => (int) $row['ips'],
					);
				}
				return $out;
			}
		);
		return is_array( $value ) ? $value : array();
	}

	/**
	 * Different addresses that tried wp-admin, the sign-in or XML-RPC.
	 *
	 * @param int $days Days.
	 * @return int
	 */
	public static function login_ips( $days ) {
		if ( ! self::available() ) {
			return 0;
		}
		$days = max( 1, (int) $days );
		return (int) self::cached(
			'loginips|' . $days,
			static function () use ( $days ) {
				global $wpdb;
				$rows = self::rows( $wpdb->prepare( "SELECT COUNT(DISTINCT NULLIF(ip, '')) AS n FROM %i WHERE category IN ('login_fail', 'login_probe', 'admin_probe', 'xmlrpc') AND hour_ts >= %d AND hits > 0", PNCP_Attacks::table(), self::since( $days ) ) );
				return $rows ? (int) $rows[0]['n'] : 0;
			}
		);
	}

	/**
	 * The addresses that tried wp-admin, the sign-in or XML-RPC most, with what they did.
	 *
	 * @param int $days  Days.
	 * @param int $limit Rows.
	 * @return array<int, array{ip:string, hits:int, failed:int, probes:int, admin:int, xmlrpc:int, last:int}>
	 */
	public static function login_top_ips( $days, $limit = 15 ) {
		if ( ! self::available() ) {
			return array();
		}
		$days  = max( 1, (int) $days );
		$limit = max( 1, min( 200, (int) $limit ) );
		$value = self::cached(
			'loginip|' . $days . '|' . $limit,
			static function () use ( $days, $limit ) {
				global $wpdb;
				$out = array();
				$sql = $wpdb->prepare(
					"SELECT ip, SUM(hits) AS hits,
						SUM(CASE WHEN category = 'login_fail' THEN hits ELSE 0 END) AS failed,
						SUM(CASE WHEN category = 'login_probe' THEN hits ELSE 0 END) AS probes,
						SUM(CASE WHEN category = 'admin_probe' THEN hits ELSE 0 END) AS admin,
						SUM(CASE WHEN category = 'xmlrpc' THEN hits ELSE 0 END) AS xmlrpc,
						MAX(last_ts) AS last
					FROM %i WHERE category IN ('login_fail', 'login_probe', 'admin_probe', 'xmlrpc') AND hour_ts >= %d AND ip <> ''
					GROUP BY ip HAVING hits > 0 ORDER BY hits DESC LIMIT %d",
					PNCP_Attacks::table(),
					self::since( $days ),
					$limit
				);
				foreach ( self::rows( $sql ) as $row ) {
					$out[] = array(
						'ip'     => (string) $row['ip'],
						'hits'   => (int) $row['hits'],
						'failed' => (int) $row['failed'],
						'probes' => (int) $row['probes'],
						'admin'  => (int) $row['admin'],
						'xmlrpc' => (int) $row['xmlrpc'],
						'last'   => (int) $row['last'],
					);
				}
				return $out;
			}
		);
		return is_array( $value ) ? $value : array();
	}

	/**
	 * The User-Agents of the requests ScrapeLock refused in the period (from the Log, which keeps them; the attack
	 * record does not). The Log may keep fewer days than the period.
	 *
	 * @param int $days  Days.
	 * @param int $limit Rows.
	 * @return array<int, array{ua:string, hits:int, ips:int}>
	 */
	public static function top_user_agents( $days, $limit = 15 ) {
		if ( ! PNCP_Log::ready() ) {
			return array();
		}
		$days  = max( 1, (int) $days );
		$limit = max( 1, min( 200, (int) $limit ) );
		$value = self::cached(
			'uas|' . $days . '|' . $limit,
			static function () use ( $days, $limit ) {
				global $wpdb;
				$out = array();
				$sql = $wpdb->prepare( "SELECT ua, SUM(hits) AS hits, COUNT(DISTINCT ip) AS ips FROM %i WHERE created >= %s AND ua <> '' GROUP BY ua ORDER BY hits DESC LIMIT %d", PNCP_Log::table(), gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS ), $limit );
				foreach ( self::rows( $sql ) as $row ) {
					$out[] = array(
						'ua'   => (string) $row['ua'],
						'hits' => (int) $row['hits'],
						'ips'  => (int) $row['ips'],
					);
				}
				return $out;
			}
		);
		return is_array( $value ) ? $value : array();
	}

	/**
	 * Events per hour of the day (0-23, site time zone) over the period: when the bots come.
	 *
	 * @param int $days Days.
	 * @return array<string, int> "00:00" => hits.
	 */
	public static function hour_of_day( $days ) {
		$out = array();
		for ( $h = 0; $h < 24; $h++ ) {
			$out[ sprintf( '%02d:00', $h ) ] = 0;
		}
		if ( ! self::available() ) {
			return $out;
		}
		foreach ( PNCP_Attacks::per_hour( max( 1, (int) $days ) * 24 ) as $label => $hits ) {
			$key = substr( (string) $label, 11, 5 );
			if ( isset( $out[ $key ] ) ) {
				$out[ $key ] += (int) $hits;
			}
		}
		return $out;
	}

	/**
	 * The country of an address (ISO code or ''). The local country database when it is there; otherwise the
	 * CDN's country header, but only for the address of this request (it describes the visitor, not other IPs).
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function country( $ip ) {
		static $memo = array();
		$ip          = (string) $ip;
		if ( '' === $ip || ! class_exists( 'PNCP_Geo' ) ) {
			return '';
		}
		if ( isset( $memo[ $ip ] ) ) {
			return $memo[ $ip ];
		}
		$code = '';
		if ( PNCP_Geo::has_files() && PNCP_Geo::status()['updated'] ) {
			$code = PNCP_Geo::lookup( $ip );
			$code = (string) apply_filters( 'pncp_visitor_country', $code, $ip );
		} elseif ( PNCP_Ip::client_ip() === $ip ) {
			$code = PNCP_Geo::country( $ip );
		} else {
			$code = (string) apply_filters( 'pncp_visitor_country', '', $ip );
		}
		$memo[ $ip ] = preg_match( '/^[A-Z]{2}$/', $code ) ? $code : '';
		return $memo[ $ip ];
	}

	/**
	 * The reputation of an address, when the reputation is in use.
	 *
	 * @param string $ip IP.
	 * @return array{score:int, level:string}|null
	 */
	public static function reputation( $ip ) {
		if ( ! class_exists( 'PNCP_Reputation' ) || ! PNCP_Reputation::active() ) {
			return null;
		}
		$rep = PNCP_Reputation::describe( (string) $ip );
		return array(
			'score' => (int) $rep['score'],
			'level' => (string) $rep['level'],
		);
	}

	/**
	 * The hardening point that locks an attacked address, if one does and it is still open.
	 *
	 * @param string $path Path.
	 * @return array{id:string, label:string}|null
	 */
	public static function lock_point( $path ) {
		if ( '' === (string) $path || ! class_exists( 'PNCP_Hardening' ) ) {
			return null;
		}
		$rec = PNCP_Hardening::recommend_for_path( (string) $path );
		return is_array( $rec ) && ! empty( $rec['id'] ) ? $rec : null;
	}

	/**
	 * Whether an IP may be blocked from this report, and why not ('' = it may).
	 *
	 * @param string $ip IP.
	 * @return string '' | invalid | local | own | allowed | official | exempt
	 */
	public static function block_refusal( $ip ) {
		$why = PNCP_Options::ban_refusal( (string) $ip );
		if ( '' !== $why ) {
			return $why;
		}
		if ( PNCP_Ip::is_cdn_edge( PNCP_Ip::normalize( (string) $ip ) ) ) {
			return 'official';
		}
		return '';
	}

	/* ---------- Admin actions ---------- */

	/**
	 * Capability and nonce check.
	 *
	 * @param string $nonce Nonce action.
	 */
	private static function verify( $nonce ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce );
	}

	/**
	 * The Attacks tab, with the period kept.
	 *
	 * @param int    $days   Days (0 = default).
	 * @param string $anchor Fragment, without "#".
	 * @return string
	 */
	public static function tab_url( $days = 0, $anchor = '' ) {
		$args = array( 'tab' => 'attacks' );
		if ( $days > 0 ) {
			$args['pncp_ar_days'] = (int) $days;
		}
		$url = class_exists( 'PNCP_Status' ) ? PNCP_Status::settings_url( $args ) : add_query_arg( $args, admin_url( 'options-general.php?page=scrapelock' ) );
		return $url . ( '' !== $anchor ? '#' . $anchor : '' );
	}

	/**
	 * Back to the page the form came from (the Attacks tab), with a notice shown once.
	 *
	 * @param string $type    success | error | warning.
	 * @param string $text    Notice.
	 * @param string $anchor  Fragment.
	 */
	private static function done( $type, $text, $anchor = '' ) {
		set_transient(
			self::NOTICE . get_current_user_id(),
			array( $type, $text ),
			MINUTE_IN_SECONDS
		);
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked in verify() by the caller.
		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 0;
		$back = wp_get_referer();
		if ( ! $back ) {
			$back = self::tab_url( $days );
		}
		$back = remove_query_arg( array( 'pncp_message' ), $back );
		$back = (string) preg_replace( '/#.*$/', '', $back );
		wp_safe_redirect( $back . ( '' !== $anchor ? '#' . $anchor : '' ) );
		exit;
	}

	/**
	 * Action pncp_attack_export (admin-post.php): the CSV. kind=report: the report as shown (key figures, kinds of
	 * attack, addresses attacked, IPs with country, usernames tried, User-Agents, CDN edge); kind=rows: every row of
	 * the record of the period (PNCP_Attacks::export_csv()).
	 */
	public static function handle_export() {
		self::verify( 'pncp_attack_export' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked in verify().
		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 7;
		$kind = isset( $_POST['kind'] ) ? sanitize_key( wp_unslash( $_POST['kind'] ) ) : 'report';
		// phpcs:enable
		$days = max( 1, min( 90, $days ) );
		if ( 'rows' === $kind && class_exists( 'PNCP_Attacks' ) ) {
			PNCP_Attacks::export_csv( $days );
			exit;
		}
		self::export_report_csv( $days );
		exit;
	}

	/**
	 * A CSV cell a spreadsheet will not run as a formula.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	public static function csv_cell( $value ) {
		$value = (string) $value;
		return '' !== $value && false !== strpos( "=+-@\t\r", $value[0] ) ? "'" . $value : $value;
	}

	/**
	 * Streams the report of the last N days as CSV: one line per item, the section in the first column.
	 *
	 * @param int $days Days.
	 */
	public static function export_report_csv( $days ) {
		$days = max( 1, (int) $days );
		if ( ! headers_sent() ) {
			nocache_headers();
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="scrapelock-attack-report-' . gmdate( 'Y-m-d' ) . '-' . $days . 'd.csv"' );
			header( 'X-Content-Type-Options: nosniff' );
		}
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming to the response.
		if ( ! $out ) {
			return;
		}
		foreach ( self::report_lines( $days ) as $line ) {
			fputcsv( $out, array_map( array( __CLASS__, 'csv_cell' ), $line ), ',', '"', '\\' );
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming to the response.
	}

	/**
	 * The lines of the report CSV (header first).
	 *
	 * @param int $days Days.
	 * @return array<int, array<int, string|int|float>>
	 */
	public static function report_lines( $days ) {
		$labels = class_exists( 'PNCP_Attacks' ) ? PNCP_Attacks::categories() : array();
		$k      = self::kpis( $days );
		$lines  = array( array( 'section', 'item', 'category', 'hits', 'ips', 'refused', 'country', 'note' ) );
		$kpi    = array(
			'attacks'             => $k['total'],
			'refused'             => $k['blocked'],
			'refused_percent'     => $k['pct_blocked'],
			'unique_ips'          => $k['unique_ips'],
			'wp_admin_and_login'  => $k['login_total'],
			'failed_sign_ins'     => $k['login_failed'],
			'wp_admin_logged_out' => $k['admin'],
			'xmlrpc_calls'        => $k['xmlrpc'],
			'login_ips'           => $k['login_ips'],
		);
		foreach ( $kpi as $name => $value ) {
			$lines[] = array( 'kpi', $name, '', $value, '', '', '', 'last ' . $days . ' days' );
		}
		foreach ( self::category_stats( $days ) as $cat => $row ) {
			$lines[] = array( 'category', isset( $labels[ $cat ] ) ? $labels[ $cat ] : $cat, $cat, $row['hits'], $row['ips'], $row['blocked'], '', '' );
		}
		if ( self::available() ) {
			foreach ( PNCP_Attacks::top_paths( $days, 100 ) as $row ) {
				$rec     = self::lock_point( $row['path'] );
				$lines[] = array( 'path', '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : '(many)', $row['category'], $row['hits'], $row['ips'], $row['blocked'], '', $rec ? 'lock: ' . $rec['label'] : '' );
			}
			foreach ( PNCP_Attacks::top_ips( $days, 100 ) as $row ) {
				$lines[] = array( 'ip', $row['ip'], $row['categories'], $row['hits'], '', '', self::country( $row['ip'] ), 'last ' . wp_date( 'Y-m-d H:i', $row['last'] ) );
			}
			foreach ( PNCP_Attacks::top_details( $days, 'login_fail', 50 ) as $row ) {
				$lines[] = array( 'username', $row['detail'], 'login_fail', $row['hits'], $row['ips'], '', '', username_exists( $row['detail'] ) ? 'exists on this site' : '' );
			}
			foreach ( PNCP_Attacks::top_paths( $days, 50, 'edge' ) as $row ) {
				$lines[] = array( 'edge', '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : '(many)', 'edge', $row['hits'], $row['ips'], $row['blocked'], '', '' );
			}
		}
		foreach ( self::top_user_agents( $days, 50 ) as $row ) {
			$lines[] = array( 'user_agent', $row['ua'], '', $row['hits'], $row['ips'], $row['hits'], '', 'refused (Log)' );
		}
		return $lines;
	}

	/**
	 * Action pncp_attack_block (admin-post.php): op=ban (blocks the IP for 24 hours) or op=permanent (adds it to
	 * "Always-blocked IPs"). Never the server, a private address, the administrator's own address, an
	 * always-allowed IP, a search engine, an AI search service or a CDN edge (PNCP_Options::ban_refusal()). The
	 * permanent block is a settings change, so it is refused while the site is locked (Lockdown).
	 */
	public static function handle_block() {
		self::verify( 'pncp_attack_block' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked in verify().
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$ip = isset( $_POST['ip'] ) ? PNCP_Ip::normalize( sanitize_text_field( wp_unslash( $_POST['ip'] ) ) ) : '';
		// phpcs:enable
		$why = self::block_refusal( $ip );
		if ( '' !== $why ) {
			self::done( 'error', self::refusal_text( $why ), 'pncp-ar-ips' );
		}
		$monitor = PNCP_Options::monitoring() ? ' ' . __( 'Monitor only is on: requests from it are logged as “Would block” and still let through.', 'scrapelock' ) : '';
		if ( 'permanent' === $op ) {
			if ( class_exists( 'PNCP_Lockdown' ) && PNCP_Lockdown::is_locked() ) {
				self::done( 'error', __( 'The site is locked with Lockdown: unlock it to change “Always-blocked IPs”.', 'scrapelock' ), 'pncp-ar-ips' );
			}
			$result = PNCP_Options::block_ip_permanently( $ip );
			$texts  = array(
				/* translators: %s: IP address */
				'added'   => array( 'success', __( '%s was added to “Always-blocked IPs”.', 'scrapelock' ) ),
				/* translators: %s: IP address */
				'exists'  => array( 'warning', __( '%s is already in “Always-blocked IPs”.', 'scrapelock' ) ),
				/* translators: %s: IP address */
				'full'    => array( 'error', __( '“Always-blocked IPs” is full (200 lines): %s was not added. Remove old lines on the Bots and limits tab, or use a range.', 'scrapelock' ) ),
				/* translators: %s: IP address */
				'refused' => array( 'error', __( '%s cannot be blocked.', 'scrapelock' ) ),
			);
			$text = isset( $texts[ $result ] ) ? $texts[ $result ] : $texts['refused'];
			self::done( $text[0], sprintf( $text[1], $ip ) . ( 'added' === $result ? $monitor : '' ), 'pncp-ar-ips' );
		}
		if ( 'ban' === $op ) {
			PNCP_Log::ban( $ip, self::BAN_MINUTES, 'manual' );
			if ( PNCP_Log::is_banned( $ip ) ) {
				/* translators: %s: IP address */
				self::done( 'success', sprintf( __( '%s is blocked for 24 hours.', 'scrapelock' ), $ip ) . $monitor, 'pncp-ar-ips' );
			}
			/* translators: %s: IP address */
			self::done( 'error', sprintf( __( '%s could not be blocked (the block table may be missing, or the address is shared by many visitors).', 'scrapelock' ), $ip ), 'pncp-ar-ips' );
		}
		self::done( 'error', __( 'Unknown action.', 'scrapelock' ) );
	}

	/**
	 * Why an address cannot be blocked, for people.
	 *
	 * @param string $why Code of block_refusal().
	 * @return string
	 */
	public static function refusal_text( $why ) {
		$texts = array(
			'invalid'  => __( 'That is not a valid IP address.', 'scrapelock' ),
			'local'    => __( 'A private or local address (this server, your network) is never blocked.', 'scrapelock' ),
			'own'      => __( 'That is your own address: blocking it would lock you out.', 'scrapelock' ),
			'allowed'  => __( 'The address is in “Always-allowed IPs”. Remove it there first.', 'scrapelock' ),
			'official' => __( 'The address belongs to a search engine, an AI search service or a CDN: blocking it would stop their crawlers or every visitor behind the CDN.', 'scrapelock' ),
		);
		return isset( $texts[ $why ] ) ? $texts[ $why ] : __( 'This address cannot be blocked.', 'scrapelock' );
	}

	/**
	 * Action pncp_attack_report_send (admin-post.php): sends the weekly email now, to the usual recipients.
	 */
	public static function handle_send() {
		self::verify( 'pncp_attack_report_send' );
		$to = self::recipients();
		if ( ! $to ) {
			self::done( 'error', __( 'No valid recipient: set the Administration Email Address under Settings → General.', 'scrapelock' ), 'pncp-ar-email' );
		}
		$sent = self::send( 7 );
		self::done(
			$sent ? 'success' : 'error',
			$sent
				/* translators: %s: email addresses */
				? sprintf( __( 'The report was sent to %s.', 'scrapelock' ), implode( ', ', $to ) )
				: __( 'The email could not be sent. Check that this site can send email (an SMTP plugin helps).', 'scrapelock' ),
			'pncp-ar-email'
		);
	}

	/* ---------- Weekly email ---------- */

	/**
	 * The cron event: sends the weekly summary when the setting is on (once per 6 days at most, so a doubled
	 * event or a restored backup does not send it twice).
	 */
	public static function send_weekly() {
		if ( ! self::weekly_on() ) {
			wp_clear_scheduled_hook( self::CRON );
			return;
		}
		$last = (int) get_option( self::LAST_OPTION, 0 );
		if ( $last > time() - 6 * DAY_IN_SECONDS ) {
			return;
		}
		if ( self::send( 7 ) ) {
			update_option( self::LAST_OPTION, time(), false );
		}
	}

	/**
	 * Sends the summary of the last N days.
	 *
	 * @param int $days Days.
	 * @return bool
	 */
	public static function send( $days = 7 ) {
		$to = self::recipients();
		if ( ! $to ) {
			return false;
		}
		$mail = self::email( $days );
		return (bool) wp_mail( $to, $mail['subject'], $mail['body'] );
	}

	/**
	 * The plain-text summary: totals, wp-admin and sign-in, the kinds of attack, the addresses attacked most with
	 * the point that locks each, the IPs, the usernames tried, the CDN edge, and a link to the report.
	 *
	 * @param int $days Days.
	 * @return array{subject:string, body:string}
	 */
	public static function email( $days = 7 ) {
		$days    = max( 1, (int) $days );
		$k       = self::kpis( $days );
		$labels  = class_exists( 'PNCP_Attacks' ) ? PNCP_Attacks::categories() : array();
		$site    = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$num     = static function ( $n ) {
			return number_format_i18n( (int) $n );
		};
		$subject = sprintf(
			/* translators: 1: site name, 2: number of attacks, 3: number of failed sign-ins */
			__( '[%1$s] Weekly attack report: %2$s attacks, %3$s failed sign-ins', 'scrapelock' ),
			$site,
			$num( $k['total'] ),
			$num( $k['login_failed'] )
		);
		$l   = array();
		$l[] = sprintf(
			/* translators: 1: site address, 2: first day, 3: last day */
			__( 'ScrapeLock attack report for %1$s, %2$s to %3$s.', 'scrapelock' ),
			home_url( '/' ),
			wp_date( get_option( 'date_format' ), time() - $days * DAY_IN_SECONDS ),
			wp_date( get_option( 'date_format' ) )
		);
		$l[] = '';
		if ( ! self::available() ) {
			$l[] = __( 'The attack record is not available (it is off, or its table does not exist yet).', 'scrapelock' );
		}
		/* translators: 1: attacks, 2: refused, 3: percent refused, 4: addresses */
		$l[] = sprintf( __( 'Attacks: %1$s, refused: %2$s (%3$s%%), from %4$s addresses.', 'scrapelock' ), $num( $k['total'] ), $num( $k['blocked'] ), number_format_i18n( $k['pct_blocked'], 1 ), $num( $k['unique_ips'] ) );
		/* translators: 1: total, 2: failed sign-ins, 3: wp-admin requests, 4: XML-RPC calls, 5: addresses */
		$l[] = sprintf( __( 'wp-admin and sign-in: %1$s attempts (%2$s failed sign-ins, %3$s wp-admin requests while logged out, %4$s XML-RPC calls) from %5$s addresses.', 'scrapelock' ), $num( $k['login_total'] ), $num( $k['login_failed'] ), $num( $k['admin'] ), $num( $k['xmlrpc'] ), $num( $k['login_ips'] ) );
		if ( PNCP_Options::monitoring() ) {
			$l[] = __( 'Monitor only is on: nothing is refused, “refused” counts what would be.', 'scrapelock' );
		}
		$stats = self::category_stats( $days );
		if ( $stats ) {
			$l[] = '';
			$l[] = __( 'Kinds of attack:', 'scrapelock' );
			foreach ( $stats as $cat => $row ) {
				$l[] = sprintf( '- %1$s: %2$s (%3$s IPs)', isset( $labels[ $cat ] ) ? $labels[ $cat ] : $cat, $num( $row['hits'] ), $num( $row['ips'] ) );
			}
		}
		if ( self::available() ) {
			$paths = PNCP_Attacks::top_paths( $days, 10 );
			if ( $paths ) {
				$l[] = '';
				$l[] = __( 'Addresses attacked most:', 'scrapelock' );
				foreach ( $paths as $row ) {
					$rec  = self::lock_point( $row['path'] );
					$line = sprintf( '- %1$s: %2$s (%3$s)', '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : __( '(many addresses)', 'scrapelock' ), $num( $row['hits'] ), isset( $labels[ $row['category'] ] ) ? $labels[ $row['category'] ] : $row['category'] );
					if ( $rec ) {
						/* translators: %s: name of the hardening point */
						$line .= ' ' . sprintf( __( '[can be locked: %s]', 'scrapelock' ), $rec['label'] );
					}
					$l[] = $line;
				}
			}
			$ips = PNCP_Attacks::top_ips( $days, 5 );
			if ( $ips ) {
				$l[] = '';
				$l[] = __( 'IPs that attacked most:', 'scrapelock' );
				foreach ( $ips as $row ) {
					$country = self::country( $row['ip'] );
					$l[]     = sprintf( '- %1$s%2$s: %3$s', $row['ip'], '' !== $country ? ' (' . $country . ')' : '', $num( $row['hits'] ) );
				}
			}
			$users = PNCP_Attacks::top_details( $days, 'login_fail', 5 );
			if ( $users ) {
				$l[] = '';
				$l[] = __( 'Usernames tried:', 'scrapelock' );
				foreach ( $users as $row ) {
					$l[] = sprintf( '- %1$s: %2$s%3$s', $row['detail'], $num( $row['hits'] ), username_exists( $row['detail'] ) ? ' ' . __( '(a real account on this site: give it a strong password and two-factor sign-in)', 'scrapelock' ) : '' );
				}
			}
			$edge = isset( $stats['edge'] ) ? $stats['edge']['hits'] : 0;
			if ( $edge ) {
				$l[] = '';
				/* translators: %s: number */
				$l[] = sprintf( __( 'Seen at the Bunny CDN edge: %s attacks.', 'scrapelock' ), $num( $edge ) );
			}
		}
		// 3.12: a short Traffic part, only while Traffic collects (nothing changes otherwise).
		if ( class_exists( 'PNCP_Traffic_Alerts' ) ) {
			$l = array_merge( $l, PNCP_Traffic_Alerts::report_lines( $days ) );
		}
		$l[] = '';
		$l[] = __( 'Full report, with “Lock this” and “Block IP” buttons:', 'scrapelock' );
		$l[] = self::tab_url( $days );
		$l[] = '';
		$l[] = __( 'You get this email because “Weekly attack report by email” is on in ScrapeLock (Log tab). Turn it off there.', 'scrapelock' );
		return array(
			'subject' => $subject,
			'body'    => implode( "\n", $l ),
		);
	}

	/* ---------- Assets, dashboard ---------- */

	/**
	 * The stylesheet and script, on the Attacks tab and on the dashboard (widget).
	 *
	 * @param string $hook Page hook.
	 */
	public static function assets( $hook ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects the assets.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		$ver = defined( 'PNCP_VERSION' ) ? PNCP_VERSION : '3.8.0';
		$url = defined( 'PNCP_URL' ) ? PNCP_URL : plugin_dir_url( __DIR__ . '/../scrapelock.php' );
		if ( 'index.php' === $hook ) {
			if ( current_user_can( 'manage_options' ) ) {
				wp_enqueue_style( 'pncp-attack-report', $url . 'assets/css/attack-report.css', array(), $ver );
			}
			return;
		}
		$ours = (bool) apply_filters( 'pncp_attack_report_screen', 'settings_page_scrapelock' === $hook && 'attacks' === $tab, $hook );
		if ( ! $ours ) {
			return;
		}
		self::enqueue();
	}

	/**
	 * Enqueues the stylesheet and the script (also for a page that prints render_tab() itself).
	 */
	public static function enqueue() {
		$ver = defined( 'PNCP_VERSION' ) ? PNCP_VERSION : '3.8.0';
		$url = defined( 'PNCP_URL' ) ? PNCP_URL : plugin_dir_url( __DIR__ . '/../scrapelock.php' );
		wp_enqueue_style( 'pncp-attack-report', $url . 'assets/css/attack-report.css', array(), $ver );
		wp_enqueue_script( 'pncp-attack-report', $url . 'assets/js/attack-report.js', array(), $ver, true );
		wp_localize_script(
			'pncp-attack-report',
			'pncpAttackReport',
			array(
				'i18n' => array(
					/* translators: 1: rows shown, 2: rows in total */
					'shown'   => __( '%1$s of %2$s rows', 'scrapelock' ),
					/* translators: %s: IP address */
					'confirm' => __( 'Add %s to “Always-blocked IPs”? Every request from it will be refused until you remove it.', 'scrapelock' ),
				),
			)
		);
	}

	/**
	 * Adds the dashboard widget, for administrators.
	 */
	public static function register_widget() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_add_dashboard_widget( 'pncp_attack_report', __( 'ScrapeLock: attacks in the last 7 days', 'scrapelock' ), array( __CLASS__, 'dashboard_widget' ) );
	}

	/**
	 * The dashboard widget: the key figures of 7 days, a small chart per day and the three addresses attacked most.
	 */
	public static function dashboard_widget() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$k = self::kpis( 7 );
		echo '<div class="pncp-ar pncp-ar--widget">';
		if ( ! self::available() ) {
			echo '<p>' . esc_html__( 'The attack record is not available yet: it starts with the next admin page.', 'scrapelock' ) . '</p>';
		}
		echo '<ul class="pncp-ar__kpis pncp-ar__kpis--small">';
		self::kpi_tile( $k['total'], __( 'attacks', 'scrapelock' ) );
		self::kpi_tile( $k['login_total'], __( 'wp-admin and sign-in attempts', 'scrapelock' ) );
		self::kpi_tile( $k['login_failed'], __( 'failed sign-ins', 'scrapelock' ) );
		self::kpi_tile( $k['unique_ips'], __( 'addresses', 'scrapelock' ) );
		echo '</ul>';
		if ( self::available() && $k['total'] > 0 ) {
			self::chart( 'pncp-ar-widget-chart', __( 'Attacks per day, last 7 days', 'scrapelock' ), PNCP_Attacks::per_day( 7 ), 'day', true );
			$paths = PNCP_Attacks::top_paths( 7, 3 );
			if ( $paths ) {
				echo '<p class="pncp-ar__widget-title"><strong>' . esc_html__( 'Attacked most', 'scrapelock' ) . '</strong></p><ul class="pncp-ar__widget-list">';
				foreach ( $paths as $row ) {
					printf(
						'<li><code>%1$s</code> <span>%2$s</span></li>',
						esc_html( '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : __( '(many addresses)', 'scrapelock' ) ),
						esc_html( number_format_i18n( $row['hits'] ) )
					);
				}
				echo '</ul>';
			}
		}
		// 3.12: one line of Traffic figures, only while Traffic collects (one cached query).
		if ( class_exists( 'PNCP_Traffic_Alerts' ) ) {
			PNCP_Traffic_Alerts::widget_line();
		}
		printf( '<p><a class="button button-small" href="%1$s">%2$s</a></p>', esc_url( self::tab_url( 7 ) ), esc_html__( 'Full attack report', 'scrapelock' ) );
		echo '</div>';
	}

	/* ---------- Rendering ---------- */

	/**
	 * The content of the "Attacks" tab: every card, in order.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	public static function render_tab( $s ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		list( $days, $category ) = self::filters();
		echo '<div class="pncp-ar" id="pncp-ar">';
		self::render_notices();
		self::render_overview_card( $days, $s );
		self::render_timeline_card( $days );
		self::render_categories_card( $days, $category );
		self::render_paths_card( $days, $category );
		self::render_login_card( $days );
		self::render_ips_card( $days, $category );
		self::render_user_agents_card( $days );
		self::render_edge_card( $days );
		self::render_tools_card( $days, $s );
		echo '</div>';
	}

	/**
	 * The notice of the last action (this tab's, or a "Lock this" of the hardening), shown once.
	 */
	public static function render_notices() {
		$uid = get_current_user_id();
		foreach ( array( self::NOTICE . $uid, 'pncp_harden_msg_' . $uid ) as $name ) {
			$notice = get_transient( $name );
			if ( ! is_array( $notice ) || count( $notice ) < 2 ) {
				continue;
			}
			delete_transient( $name );
			$type = in_array( $notice[0], array( 'success', 'error', 'warning', 'info' ), true ) ? $notice[0] : 'info';
			printf(
				'<div class="notice notice-%1$s inline pncp-ar__notice" role="%3$s"><p>%2$s</p></div>',
				esc_attr( $type ),
				esc_html( (string) $notice[1] ),
				'error' === $type ? 'alert' : 'status'
			);
		}
	}

	/**
	 * One key-figure tile.
	 *
	 * @param int|float $value Number.
	 * @param string    $label Label.
	 * @param string    $tone  '' | bad | good.
	 * @param string    $hint  Smaller text under the label.
	 * @param bool      $pct   Show as percent.
	 */
	private static function kpi_tile( $value, $label, $tone = '', $hint = '', $pct = false ) {
		printf(
			'<li class="pncp-ar__kpi%1$s"><span class="pncp-ar__kpi-value">%2$s</span> <span class="pncp-ar__kpi-label">%3$s</span>%4$s</li>',
			'' !== $tone ? ' pncp-ar__kpi--' . esc_attr( $tone ) : '',
			esc_html( $pct ? number_format_i18n( (float) $value, 1 ) . '%' : number_format_i18n( (int) $value ) ),
			esc_html( $label ),
			'' !== $hint ? ' <span class="pncp-ar__kpi-hint">' . esc_html( $hint ) . '</span>' : ''
		);
	}

	/**
	 * The URL of this tab with other filters.
	 *
	 * @param array<string, int|string> $args Query arguments ('' removes one).
	 * @param string                    $anchor Fragment.
	 * @return string
	 */
	private static function filter_url( $args, $anchor = '' ) {
		$url = remove_query_arg( array( 'pncp_message', '_wpnonce' ) );
		foreach ( $args as $key => $value ) {
			$url = '' === $value ? remove_query_arg( $key, $url ) : add_query_arg( $key, $value, $url );
		}
		return $url . ( '' !== $anchor ? '#' . $anchor : '' );
	}

	/**
	 * Card: title, period, key figures.
	 *
	 * @param int                  $days Days.
	 * @param array<string, mixed> $s    Settings.
	 */
	public static function render_overview_card( $days, $s ) {
		$k = self::kpis( $days );
		?>
		<section class="pncp-card pncp-card--wide pncp-ar__overview" aria-labelledby="pncp-ar-title">
			<h2 id="pncp-ar-title"><?php esc_html_e( 'Attack report', 'scrapelock' ); ?>
				<?php if ( PNCP_Options::monitoring( $s ) ) : ?>
					<span class="pncp-badge pncp-badge--monitor"><?php esc_html_e( 'Monitor only', 'scrapelock' ); ?></span>
				<?php endif; ?>
			</h2>
			<?php echo PNCP_Admin_Fields::para( __( 'Where bots hit this site. “Lock this” closes a point, “Block” stops an IP.', 'scrapelock' ), __( 'Where bots and attackers hit this site, how many try wp-admin and the sign-in, and from where. Recorded on this server, also when nothing was refused. Use “Lock this” next to an address to close that point, and “Block” next to an IP.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php self::render_availability(); ?>
			<nav class="pncp-ar__periods" aria-label="<?php esc_attr_e( 'Period', 'scrapelock' ); ?>">
				<?php foreach ( self::periods() as $value => $label ) : ?>
					<?php if ( $value === $days ) : ?>
						<span class="pncp-ar__period is-current" aria-current="true"><?php echo esc_html( $label ); ?></span>
					<?php else : ?>
						<a class="pncp-ar__period" href="<?php echo esc_url( self::filter_url( array( 'pncp_ar_days' => $value ) ) ); ?>"><?php echo esc_html( $label ); ?></a>
					<?php endif; ?>
				<?php endforeach; ?>
			</nav>
			<ul class="pncp-ar__kpis">
				<?php
				self::kpi_tile( $k['total'], __( 'attacks', 'scrapelock' ), $k['total'] ? 'bad' : '' );
				self::kpi_tile(
					$k['login_total'],
					__( 'wp-admin and sign-in attempts', 'scrapelock' ),
					'',
					/* translators: %s: number of addresses */
					sprintf( _n( 'from %s address', 'from %s addresses', $k['login_ips'], 'scrapelock' ), number_format_i18n( $k['login_ips'] ) )
				);
				self::kpi_tile( $k['login_failed'], __( 'failed sign-ins', 'scrapelock' ), $k['login_failed'] >= 50 ? 'bad' : '' );
				self::kpi_tile( $k['unique_ips'], __( 'different IPs', 'scrapelock' ) );
				self::kpi_tile(
					$k['pct_blocked'],
					PNCP_Options::monitoring( $s ) ? __( 'would be refused', 'scrapelock' ) : __( 'refused', 'scrapelock' ),
					'good',
					/* translators: %s: number of requests */
					sprintf( __( '%s requests', 'scrapelock' ), number_format_i18n( $k['blocked'] ) ),
					true
				);
				?>
			</ul>
		</section>
		<?php
	}

	/**
	 * Why the report may be empty.
	 */
	private static function render_availability() {
		if ( ! class_exists( 'PNCP_Attacks' ) ) {
			echo '<p class="pncp-ar__warn">' . esc_html__( 'The attack record is missing from this installation.', 'scrapelock' ) . '</p>';
			return;
		}
		if ( ! PNCP_Attacks::ready() ) {
			echo '<p class="pncp-ar__warn">' . esc_html__( 'The table of the attack record does not exist yet. It is created on the next admin page, if the database user may create tables.', 'scrapelock' ) . '</p>';
		}
		if ( ! PNCP_Attacks::enabled() ) {
			echo '<p class="pncp-ar__warn">' . esc_html__( 'Not recording: “Record where bots and attackers hit the site” (Log tab) is off, or the protection is disabled. The figures below are from before.', 'scrapelock' ) . '</p>';
		}
	}

	/**
	 * Card: the timeline per day, per hour and by hour of the day (one shown at a time with the script; all three
	 * one after the other without it).
	 *
	 * @param int $days Days.
	 */
	public static function render_timeline_card( $days ) {
		$hours = min( $days, 7 ) * 24;
		?>
		<section class="pncp-card pncp-card--wide pncp-ar__timeline" aria-labelledby="pncp-ar-timeline">
			<h2 id="pncp-ar-timeline"><?php esc_html_e( 'When they attack', 'scrapelock' ); ?></h2>
			<?php if ( ! self::available() ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<div class="pncp-ar__views" data-pncp-ar-views>
					<div class="pncp-ar__switch" role="group" aria-label="<?php esc_attr_e( 'Chart', 'scrapelock' ); ?>" hidden>
						<?php if ( $days > 1 ) : ?>
							<button type="button" class="button button-small" data-view="pncp-ar-chart-day"><?php esc_html_e( 'Per day', 'scrapelock' ); ?></button>
						<?php endif; ?>
						<button type="button" class="button button-small" data-view="pncp-ar-chart-hour"><?php esc_html_e( 'Per hour', 'scrapelock' ); ?></button>
						<button type="button" class="button button-small" data-view="pncp-ar-chart-hod"><?php esc_html_e( 'Hour of the day', 'scrapelock' ); ?></button>
					</div>
					<?php
					if ( $days > 1 ) {
						self::chart(
							'pncp-ar-chart-day',
							sprintf(
								/* translators: %s: number of days */
								__( 'Attacks per day, last %s days', 'scrapelock' ),
								number_format_i18n( $days )
							),
							PNCP_Attacks::per_day( $days ),
							'day'
						);
					}
					self::chart(
						'pncp-ar-chart-hour',
						sprintf(
							/* translators: %s: number of hours */
							__( 'Attacks per hour, last %s hours', 'scrapelock' ),
							number_format_i18n( $hours )
						),
						PNCP_Attacks::per_hour( $hours ),
						'hour'
					);
					self::chart(
						'pncp-ar-chart-hod',
						sprintf(
							/* translators: %s: number of days */
							_n( 'Attacks by hour of the day (site time), last %s day', 'Attacks by hour of the day (site time), last %s days', $days, 'scrapelock' ),
							number_format_i18n( $days )
						),
						self::hour_of_day( $days ),
						'hod'
					);
					?>
				</div>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * A bar chart: inline SVG for the bars and gridlines (stretched to the width), HTML for the labels (so the text
	 * stays sharp and readable on a phone), a title per bar, and the numbers as a table for screen readers.
	 *
	 * @param string             $id     Element id.
	 * @param string             $title  Title (also the accessible name).
	 * @param array<string, int> $series Label => value.
	 * @param string             $kind   day | hour | hod.
	 * @param bool               $small  Small (widget): no table, no axis.
	 */
	public static function chart( $id, $title, $series, $kind = 'day', $small = false ) {
		$series = array_map( 'intval', (array) $series );
		$n      = max( 1, count( $series ) );
		$max    = $series ? max( $series ) : 0;
		$sum    = array_sum( $series );
		$top    = self::nice_max( $max );
		$w      = 1000;
		$h      = 200;
		$gap    = $n > 60 ? 0.15 : 0.25;
		$bw     = $w / $n;
		$labels = array_keys( $series );
		$fmt    = static function ( $label ) use ( $kind ) {
			$label = (string) $label;
			if ( 'day' === $kind ) {
				$time = strtotime( $label . ' 12:00:00' );
				return $time ? wp_date( 'j M', $time, new DateTimeZone( 'UTC' ) ) : $label;
			}
			if ( 'hour' === $kind ) {
				$time = strtotime( substr( $label, 0, 10 ) . ' 12:00:00' );
				return ( $time ? wp_date( 'j M', $time, new DateTimeZone( 'UTC' ) ) . ' ' : '' ) . substr( $label, 11, 5 );
			}
			return $label;
		};
		$desc   = sprintf(
			/* translators: 1: number of attacks, 2: highest value of one bar, 3: label of that bar */
			__( '%1$s attacks in total; the most, %2$s, at %3$s.', 'scrapelock' ),
			number_format_i18n( $sum ),
			number_format_i18n( $max ),
			$max > 0 ? $fmt( (string) array_search( $max, $series, true ) ) : '–'
		);
		?>
		<figure class="pncp-ar__chart<?php echo $small ? ' pncp-ar__chart--small' : ''; ?>" id="<?php echo esc_attr( $id ); ?>" data-pncp-ar-view>
			<figcaption class="pncp-ar__chart-title"><?php echo esc_html( $title ); ?> <span class="pncp-ar__chart-desc"><?php echo esc_html( $desc ); ?></span></figcaption>
			<?php if ( ! $sum && ! $small ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<div class="pncp-ar__plot">
					<?php if ( ! $small ) : ?>
						<div class="pncp-ar__yaxis" aria-hidden="true">
							<span><?php echo esc_html( number_format_i18n( $top ) ); ?></span>
							<span><?php echo esc_html( number_format_i18n( $top / 2 ) ); ?></span>
							<span>0</span>
						</div>
					<?php endif; ?>
					<div class="pncp-ar__canvas">
						<svg viewBox="0 0 <?php echo (int) $w; ?> <?php echo (int) $h; ?>" preserveAspectRatio="none" role="img" aria-label="<?php echo esc_attr( $title . '. ' . $desc ); ?>" focusable="false">
							<line class="pncp-ar__grid" x1="0" y1="0.5" x2="<?php echo (int) $w; ?>" y2="0.5" vector-effect="non-scaling-stroke"></line>
							<line class="pncp-ar__grid" x1="0" y1="<?php echo (int) ( $h / 2 ); ?>" x2="<?php echo (int) $w; ?>" y2="<?php echo (int) ( $h / 2 ); ?>" vector-effect="non-scaling-stroke"></line>
							<line class="pncp-ar__axis" x1="0" y1="<?php echo (int) $h - 0.5; ?>" x2="<?php echo (int) $w; ?>" y2="<?php echo (int) $h - 0.5; ?>" vector-effect="non-scaling-stroke"></line>
							<?php
							$i = 0;
							foreach ( $series as $label => $value ) {
								$bh = $value > 0 ? max( 2, round( $h * $value / $top, 2 ) ) : 0;
								if ( $bh > 0 ) {
									printf(
										'<rect class="pncp-ar__bar%6$s" x="%1$s" y="%2$s" width="%3$s" height="%4$s"><title>%5$s</title></rect>',
										esc_attr( (string) round( $i * $bw + $bw * $gap / 2, 2 ) ),
										esc_attr( (string) round( $h - $bh, 2 ) ),
										esc_attr( (string) max( 0.5, round( $bw * ( 1 - $gap ), 2 ) ) ),
										esc_attr( (string) $bh ),
										esc_html( $fmt( $label ) . ': ' . number_format_i18n( $value ) ),
										$value === $max ? ' is-max' : ''
									);
								}
								++$i;
							}
							?>
						</svg>
						<div class="pncp-ar__xaxis" aria-hidden="true">
							<span><?php echo esc_html( $fmt( (string) reset( $labels ) ) ); ?></span>
							<?php if ( $n > 2 ) : ?>
								<span><?php echo esc_html( $fmt( (string) $labels[ (int) floor( $n / 2 ) ] ) ); ?></span>
							<?php endif; ?>
							<span><?php echo esc_html( $fmt( (string) end( $labels ) ) ); ?></span>
						</div>
					</div>
				</div>
				<?php if ( ! $small ) : ?>
					<details class="pncp-ar__data">
						<summary><?php esc_html_e( 'Show the numbers', 'scrapelock' ); ?></summary>
						<div class="pncp-table-wrap"><table class="widefat striped">
							<thead><tr><th scope="col"><?php echo esc_html( 'hod' === $kind ? __( 'Hour', 'scrapelock' ) : ( 'hour' === $kind ? __( 'Hour', 'scrapelock' ) : __( 'Day', 'scrapelock' ) ) ); ?></th><th scope="col" class="num"><?php esc_html_e( 'Attacks', 'scrapelock' ); ?></th></tr></thead>
							<tbody>
							<?php foreach ( $series as $label => $value ) : ?>
								<?php
								if ( 'hour' === $kind && ! $value ) {
									continue; // Up to 168 rows: only the hours with something.
								}
								?>
								<tr><td><?php echo esc_html( $fmt( $label ) ); ?></td><td class="num"><?php echo esc_html( number_format_i18n( $value ) ); ?></td></tr>
							<?php endforeach; ?>
							</tbody>
						</table></div>
					</details>
				<?php endif; ?>
			<?php endif; ?>
		</figure>
		<?php
	}

	/**
	 * A round top for the axis (1, 2, 2.5 or 5 times a power of ten), at least 4.
	 *
	 * @param int $max Highest value.
	 * @return int
	 */
	public static function nice_max( $max ) {
		$max = max( 4, (int) $max );
		if ( $max < 10 ) {
			return $max + $max % 2; // Even, so the middle line is a whole number.
		}
		$pow = (int) pow( 10, (int) floor( log10( $max ) ) );
		foreach ( array( 1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10 ) as $step ) {
			$top = (int) ceil( $step * $pow );
			if ( $top >= $max && 0 === $top % 2 ) {
				return $top;
			}
		}
		return 10 * $pow;
	}

	/**
	 * Card: the kinds of attack, with a bar, the share refused and what to do.
	 *
	 * @param int    $days     Days.
	 * @param string $category Category shown below ('' = all).
	 */
	public static function render_categories_card( $days, $category ) {
		$stats  = self::category_stats( $days );
		$labels = class_exists( 'PNCP_Attacks' ) ? PNCP_Attacks::categories() : array();
		$advice = class_exists( 'PNCP_Attacks' ) ? PNCP_Attacks::advice() : array();
		$total  = 0;
		foreach ( $stats as $row ) {
			$total += $row['hits'];
		}
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-ar-cats" aria-labelledby="pncp-ar-cats-title">
			<h2 id="pncp-ar-cats-title"><?php esc_html_e( 'Kinds of attack', 'scrapelock' ); ?></h2>
			<?php if ( ! $stats ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<p class="description"><?php esc_html_e( 'Choose a kind to see only its addresses and IPs below.', 'scrapelock' ); ?>
					<?php if ( '' !== $category ) : ?>
						<a href="<?php echo esc_url( self::filter_url( array( 'pncp_ar_cat' => '' ), 'pncp-ar-cats' ) ); ?>"><?php esc_html_e( 'Show all kinds', 'scrapelock' ); ?></a>
					<?php endif; ?>
				</p>
				<div class="pncp-table-wrap"><table class="widefat striped pncp-ar__cats">
					<thead><tr>
						<th scope="col"><?php esc_html_e( 'Kind of attack', 'scrapelock' ); ?></th>
						<th scope="col" class="pncp-ar__col-bar"><span class="screen-reader-text"><?php esc_html_e( 'Share', 'scrapelock' ); ?></span></th>
						<th scope="col" class="num"><?php esc_html_e( 'Attacks', 'scrapelock' ); ?></th>
						<th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th>
						<th scope="col" class="num"><?php esc_html_e( 'Refused', 'scrapelock' ); ?></th>
						<th scope="col" class="pncp-ar__advice"><?php esc_html_e( 'What it means, how to close it', 'scrapelock' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $stats as $key => $row ) : ?>
						<?php $share = 100 * $row['hits'] / max( 1, $total ); ?>
						<tr<?php echo $key === $category ? ' class="is-selected"' : ''; ?>>
							<td><a href="<?php echo esc_url( self::filter_url( array( 'pncp_ar_cat' => $key ), 'pncp-ar-paths' ) ); ?>"<?php echo $key === $category ? ' aria-current="true"' : ''; ?>><?php echo esc_html( isset( $labels[ $key ] ) ? $labels[ $key ] : $key ); ?></a>
								<span class="pncp-ar__advice-inline"><?php echo esc_html( isset( $advice[ $key ] ) ? $advice[ $key ] : '' ); ?></span></td>
							<td class="pncp-ar__col-bar"><span class="pncp-ar__meter" aria-hidden="true"><span style="width:<?php echo esc_attr( (string) max( 1, round( $share, 1 ) ) ); ?>%"></span></span><span class="pncp-ar__share"><?php echo esc_html( number_format_i18n( $share, 1 ) . '%' ); ?></span></td>
							<td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td>
							<td class="num"><?php echo esc_html( number_format_i18n( $row['ips'] ) ); ?></td>
							<td class="num"><?php echo esc_html( number_format_i18n( 100 * $row['blocked'] / max( 1, $row['hits'] ), 0 ) . '%' ); ?></td>
							<td class="pncp-ar__advice"><?php echo esc_html( isset( $advice[ $key ] ) ? $advice[ $key ] : '' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table></div>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * The "Lock this" button of a path, or what covers it.
	 *
	 * @param string $path Path.
	 */
	private static function lock_cell( $path ) {
		$rec = self::lock_point( $path );
		if ( ! $rec ) {
			printf( '<span class="pncp-ar__muted" title="%1$s">–</span>', esc_attr__( 'No point covers this address, or it is already locked.', 'scrapelock' ) );
			return;
		}
		ob_start();
		PNCP_Hardening::render_lock_button( $rec['id'] );
		$button = (string) ob_get_clean();
		if ( '' !== trim( $button ) ) {
			echo $button; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by PNCP_Hardening::render_lock_button().
			printf( '<span class="pncp-ar__lock-label">%s</span>', esc_html( $rec['label'] ) );
			return;
		}
		printf(
			'<a href="%1$s">%2$s</a>',
			esc_url( ( class_exists( 'PNCP_Status' ) ? PNCP_Status::settings_url( array( 'tab' => 'hardening' ) ) : admin_url() ) . '#pncp-hardening' ),
			/* translators: %s: name of the hardening point */
			esc_html( sprintf( __( 'Covered by: %s', 'scrapelock' ), $rec['label'] ) )
		);
	}

	/**
	 * Card: the addresses attacked most, each with "Lock this".
	 *
	 * @param int    $days     Days.
	 * @param string $category Category ('' = all).
	 */
	public static function render_paths_card( $days, $category ) {
		$rows   = self::available() ? PNCP_Attacks::top_paths( $days, 30, $category ) : array();
		$labels = class_exists( 'PNCP_Attacks' ) ? PNCP_Attacks::categories() : array();
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-ar-paths" aria-labelledby="pncp-ar-paths-title">
			<h2 id="pncp-ar-paths-title"><?php esc_html_e( 'Where they hit: addresses attacked most', 'scrapelock' ); ?>
				<?php if ( '' !== $category && isset( $labels[ $category ] ) ) : ?>
					<span class="pncp-badge"><?php echo esc_html( $labels[ $category ] ); ?></span>
				<?php endif; ?>
			</h2>
			<?php if ( ! $rows ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<?php self::table_filter( 'pncp-ar-paths-table', __( 'Filter addresses', 'scrapelock' ) ); ?>
				<div class="pncp-table-wrap"><table class="widefat striped pncp-ar__paths" id="pncp-ar-paths-table">
					<thead><tr>
						<th scope="col"><?php esc_html_e( 'Address', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Kind of attack', 'scrapelock' ); ?></th>
						<th scope="col" class="num"><?php esc_html_e( 'Attacks', 'scrapelock' ); ?></th>
						<th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th>
						<th scope="col" class="num"><?php esc_html_e( 'Refused', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Close this point', 'scrapelock' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $rows as $row ) : ?>
						<tr>
							<td class="pncp-ar__path"><code><?php echo esc_html( '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : __( '(many addresses)', 'scrapelock' ) ); ?></code></td>
							<td><?php echo esc_html( isset( $labels[ $row['category'] ] ) ? $labels[ $row['category'] ] : $row['category'] ); ?></td>
							<td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td>
							<td class="num"><?php echo esc_html( number_format_i18n( $row['ips'] ) ); ?></td>
							<td class="num"><?php echo esc_html( number_format_i18n( $row['blocked'] ) ); ?></td>
							<td class="pncp-ar__lock"><?php self::lock_cell( $row['path'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table></div>
				<p class="description">
					<?php
					if ( class_exists( 'PNCP_Hardening' ) ) {
						esc_html_e( '“Lock this” closes the point on the Vulnerable points tab, after asking.', 'scrapelock' );
					} else {
						esc_html_e( 'The Vulnerable points are not available in this installation, so there is no “Lock this”.', 'scrapelock' );
					}
					?>
				</p>
				<?php
				if ( class_exists( 'PNCP_Hardening' ) ) {
					echo PNCP_Admin_Fields::more( __( '“Lock this” closes the point on the Vulnerable points tab (what may stop working is asked first). A dash: no point covers that address, or it is already locked.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
				}
				?>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * A text box that filters a table (shown by the script).
	 *
	 * @param string $table Table id.
	 * @param string $label Label.
	 */
	private static function table_filter( $table, $label ) {
		printf(
			'<p class="pncp-ar__filter" hidden><label><span class="screen-reader-text">%1$s</span><input type="search" class="regular-text" placeholder="%1$s" data-pncp-ar-filter="%2$s"></label> <span class="pncp-ar__count" aria-live="polite"></span></p>',
			esc_attr( $label ),
			esc_attr( $table )
		);
	}

	/**
	 * The "Block 24 h" and "Always block" buttons of an IP, or why it cannot be blocked / that it is.
	 *
	 * @param string $ip   IP.
	 * @param int    $days Period, to come back to.
	 */
	private static function block_buttons( $ip, $days ) {
		if ( PNCP_Options::is_blocked_permanently( $ip ) ) {
			echo '<span class="pncp-badge pncp-badge--bad">' . esc_html__( 'Always blocked', 'scrapelock' ) . '</span>';
			return;
		}
		$why = self::block_refusal( $ip );
		if ( '' !== $why ) {
			$short = array(
				'own'      => __( 'Your address', 'scrapelock' ),
				'local'    => __( 'Local address', 'scrapelock' ),
				'allowed'  => __( 'Always allowed', 'scrapelock' ),
				'official' => __( 'Search engine or CDN', 'scrapelock' ),
			);
			printf( '<span class="pncp-badge" title="%2$s">%1$s</span>', esc_html( isset( $short[ $why ] ) ? $short[ $why ] : __( 'Cannot be blocked', 'scrapelock' ) ), esc_attr( self::refusal_text( $why ) ) );
			return;
		}
		$banned = PNCP_Log::is_banned( $ip );
		$locked = class_exists( 'PNCP_Lockdown' ) && PNCP_Lockdown::is_locked();
		echo '<span class="pncp-ar__actions">';
		if ( $banned ) {
			echo '<span class="pncp-badge pncp-badge--bad">' . esc_html__( 'Blocked now', 'scrapelock' ) . '</span>';
		} else {
			self::block_form( $ip, 'ban', __( 'Block 24 h', 'scrapelock' ), $days );
		}
		if ( ! $locked ) {
			self::block_form( $ip, 'permanent', __( 'Always block', 'scrapelock' ), $days );
		}
		echo '</span>';
	}

	/**
	 * One block form.
	 *
	 * @param string $ip    IP.
	 * @param string $op    ban | permanent.
	 * @param string $label Button text.
	 * @param int    $days  Period.
	 */
	private static function block_form( $ip, $op, $label, $days ) {
		printf( '<form method="post" action="%s" class="pncp-ar__form">', esc_url( admin_url( 'admin-post.php' ) ) );
		echo '<input type="hidden" name="action" value="pncp_attack_block">';
		echo '<input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
		echo '<input type="hidden" name="ip" value="' . esc_attr( $ip ) . '">';
		echo '<input type="hidden" name="days" value="' . esc_attr( (string) $days ) . '">';
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( 'pncp_attack_block', '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
		printf(
			'<button type="submit" class="button button-small"%3$s>%1$s<span class="screen-reader-text"> %2$s</span></button></form>',
			esc_html( $label ),
			esc_html( $ip ),
			'permanent' === $op ? ' data-pncp-ar-confirm="' . esc_attr( $ip ) . '"' : ''
		);
	}

	/**
	 * Card: wp-admin and the sign-in: the attempts, the usernames tried, the addresses, with "Block".
	 *
	 * @param int $days Days.
	 */
	public static function render_login_card( $days ) {
		$k     = self::kpis( $days );
		$cats  = $k['by_category'];
		$users = self::available() ? PNCP_Attacks::top_details( $days, 'login_fail', 15 ) : array();
		$ips   = self::login_top_ips( $days, 15 );
		$admin = self::available() ? PNCP_Attacks::top_paths( $days, 8, 'admin_probe' ) : array();
		$xml   = self::available() ? PNCP_Attacks::top_details( $days, 'xmlrpc', 8 ) : array();
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-ar-login" aria-labelledby="pncp-ar-login-title">
			<h2 id="pncp-ar-login-title"><?php esc_html_e( 'wp-admin and sign-in', 'scrapelock' ); ?></h2>
			<ul class="pncp-ar__kpis pncp-ar__kpis--small">
				<?php
				self::kpi_tile( isset( $cats['login_probe'] ) ? $cats['login_probe'] : 0, __( 'wp-login.php without signing in', 'scrapelock' ) );
				self::kpi_tile( $k['login_failed'], __( 'failed sign-ins', 'scrapelock' ), $k['login_failed'] >= 50 ? 'bad' : '' );
				self::kpi_tile( $k['admin'], __( 'wp-admin while logged out', 'scrapelock' ) );
				self::kpi_tile( $k['xmlrpc'], __( 'XML-RPC calls', 'scrapelock' ) );
				self::kpi_tile( $k['login_ips'], __( 'different IPs', 'scrapelock' ) );
				?>
			</ul>
			<?php if ( ! $k['login_total'] ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nobody tried wp-admin, the sign-in or XML-RPC in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<div class="pncp-ar__cols">
					<div>
						<h3><?php esc_html_e( 'Usernames tried', 'scrapelock' ); ?></h3>
						<?php if ( ! $users ) : ?>
							<p class="pncp-ar__muted"><?php esc_html_e( 'No failed sign-in.', 'scrapelock' ); ?></p>
						<?php else : ?>
							<div class="pncp-table-wrap"><table class="widefat striped">
								<thead><tr><th scope="col"><?php esc_html_e( 'Username', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'Tries', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th></tr></thead>
								<tbody>
								<?php foreach ( $users as $row ) : ?>
									<tr>
										<td><code><?php echo esc_html( $row['detail'] ); ?></code>
											<?php if ( username_exists( $row['detail'] ) || ( is_email( $row['detail'] ) && email_exists( $row['detail'] ) ) ) : ?>
												<span class="pncp-badge pncp-badge--bad" title="<?php esc_attr_e( 'This account exists: give it a long, unique password and two-factor sign-in.', 'scrapelock' ); ?>"><?php esc_html_e( 'Real account', 'scrapelock' ); ?></span>
											<?php endif; ?>
										</td>
										<td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td>
										<td class="num"><?php echo esc_html( number_format_i18n( $row['ips'] ) ); ?></td>
									</tr>
								<?php endforeach; ?>
								</tbody>
							</table></div>
						<?php endif; ?>
					</div>
					<div>
						<h3><?php esc_html_e( 'wp-admin addresses asked for', 'scrapelock' ); ?></h3>
						<?php if ( ! $admin ) : ?>
							<p class="pncp-ar__muted"><?php esc_html_e( 'None.', 'scrapelock' ); ?></p>
						<?php else : ?>
							<div class="pncp-table-wrap"><table class="widefat striped">
								<thead><tr><th scope="col"><?php esc_html_e( 'Address', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'Attacks', 'scrapelock' ); ?></th><th scope="col"><?php esc_html_e( 'Close', 'scrapelock' ); ?></th></tr></thead>
								<tbody>
								<?php foreach ( $admin as $row ) : ?>
									<tr><td class="pncp-ar__path"><code><?php echo esc_html( '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : __( '(many addresses)', 'scrapelock' ) ); ?></code></td><td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td><td class="pncp-ar__lock"><?php self::lock_cell( $row['path'] ); ?></td></tr>
								<?php endforeach; ?>
								</tbody>
							</table></div>
						<?php endif; ?>
						<?php if ( $xml ) : ?>
							<h3><?php esc_html_e( 'XML-RPC methods called', 'scrapelock' ); ?></h3>
							<div class="pncp-table-wrap"><table class="widefat striped">
								<thead><tr><th scope="col"><?php esc_html_e( 'Method', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'Calls', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th></tr></thead>
								<tbody>
								<?php foreach ( $xml as $row ) : ?>
									<tr><td><code><?php echo esc_html( $row['detail'] ); ?></code></td><td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td><td class="num"><?php echo esc_html( number_format_i18n( $row['ips'] ) ); ?></td></tr>
								<?php endforeach; ?>
								</tbody>
							</table></div>
						<?php endif; ?>
					</div>
				</div>
				<?php if ( $ips ) : ?>
					<h3><?php esc_html_e( 'Addresses that tried wp-admin and the sign-in most', 'scrapelock' ); ?></h3>
					<div class="pncp-table-wrap"><table class="widefat striped pncp-ar__ips">
						<thead><tr>
							<th scope="col"><?php esc_html_e( 'IP', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Country', 'scrapelock' ); ?></th>
							<th scope="col" class="num"><?php esc_html_e( 'Failed sign-ins', 'scrapelock' ); ?></th>
							<th scope="col" class="num"><?php esc_html_e( 'wp-login.php', 'scrapelock' ); ?></th>
							<th scope="col" class="num"><?php esc_html_e( 'wp-admin', 'scrapelock' ); ?></th>
							<th scope="col" class="num"><?php esc_html_e( 'XML-RPC', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Last seen', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Block', 'scrapelock' ); ?></th>
						</tr></thead>
						<tbody>
						<?php foreach ( $ips as $row ) : ?>
							<tr>
								<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
								<td><?php self::country_cell( $row['ip'] ); ?></td>
								<td class="num"><?php echo esc_html( number_format_i18n( $row['failed'] ) ); ?></td>
								<td class="num"><?php echo esc_html( number_format_i18n( $row['probes'] ) ); ?></td>
								<td class="num"><?php echo esc_html( number_format_i18n( $row['admin'] ) ); ?></td>
								<td class="num"><?php echo esc_html( number_format_i18n( $row['xmlrpc'] ) ); ?></td>
								<td class="pncp-ar__nowrap"><?php echo esc_html( self::ago( $row['last'] ) ); ?></td>
								<td><?php self::block_buttons( $row['ip'], $days ); ?></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table></div>
				<?php endif; ?>
				<?php echo PNCP_Admin_Fields::para( __( 'A real account tried here needs a long password and two-factor sign-in.', 'scrapelock' ), __( 'A real account among the usernames tried is a target: give it a long, unique password and two-factor sign-in, and turn on “Hide usernames from visitors”. If only a few people sign in, lock wp-login.php and XML-RPC on the Vulnerable points tab.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * "5 minutes ago" for the last hour, otherwise the date and time.
	 *
	 * @param int $time Unix time.
	 * @return string
	 */
	private static function ago( $time ) {
		$time = (int) $time;
		if ( $time <= 0 ) {
			return '–';
		}
		if ( time() - $time < DAY_IN_SECONDS ) {
			/* translators: %s: time span, e.g. "5 mins" */
			return sprintf( __( '%s ago', 'scrapelock' ), human_time_diff( $time ) );
		}
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $time );
	}

	/**
	 * The country cell.
	 *
	 * @param string $ip IP.
	 */
	private static function country_cell( $ip ) {
		$code = self::country( $ip );
		if ( '' === $code ) {
			echo '<span class="pncp-ar__muted" title="' . esc_attr__( 'Unknown: turn on the country database (Bots and limits tab) to see the country of every IP.', 'scrapelock' ) . '">–</span>';
			return;
		}
		echo '<abbr class="pncp-ar__country" title="' . esc_attr( $code ) . '">' . esc_html( $code ) . '</abbr>';
	}

	/**
	 * Card: the IPs that attacked most, with country, reputation, what they tried and "Block".
	 *
	 * @param int    $days     Days.
	 * @param string $category Category ('' = all).
	 */
	public static function render_ips_card( $days, $category ) {
		$rows   = self::available() ? PNCP_Attacks::top_ips( $days, 25, $category ) : array();
		$labels = class_exists( 'PNCP_Attacks' ) ? PNCP_Attacks::categories() : array();
		$rep_on = class_exists( 'PNCP_Reputation' ) && PNCP_Reputation::active();
		$levels = array(
			'good'    => __( 'Good', 'scrapelock' ),
			'neutral' => __( 'Neutral', 'scrapelock' ),
			'bad'     => __( 'Bad', 'scrapelock' ),
		);
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-ar-ips" aria-labelledby="pncp-ar-ips-title">
			<h2 id="pncp-ar-ips-title"><?php esc_html_e( 'IPs that attacked most', 'scrapelock' ); ?>
				<?php if ( '' !== $category && isset( $labels[ $category ] ) ) : ?>
					<span class="pncp-badge"><?php echo esc_html( $labels[ $category ] ); ?></span>
				<?php endif; ?>
			</h2>
			<?php if ( ! $rows ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<?php self::table_filter( 'pncp-ar-ips-table', __( 'Filter IPs', 'scrapelock' ) ); ?>
				<div class="pncp-table-wrap"><table class="widefat striped pncp-ar__ips" id="pncp-ar-ips-table">
					<thead><tr>
						<th scope="col"><?php esc_html_e( 'IP', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Country', 'scrapelock' ); ?></th>
						<?php if ( $rep_on ) : ?>
							<th scope="col"><?php esc_html_e( 'Reputation', 'scrapelock' ); ?></th>
						<?php endif; ?>
						<th scope="col" class="num"><?php esc_html_e( 'Attacks', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'What it tried', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last seen', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Block', 'scrapelock' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $rows as $row ) : ?>
						<?php
						$kinds = array();
						foreach ( array_filter( explode( ',', $row['categories'] ) ) as $key ) {
							$kinds[] = isset( $labels[ $key ] ) ? $labels[ $key ] : $key;
						}
						$rep = $rep_on ? self::reputation( $row['ip'] ) : null;
						?>
						<tr>
							<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
							<td><?php self::country_cell( $row['ip'] ); ?></td>
							<?php if ( $rep_on ) : ?>
								<td>
									<?php if ( $rep ) : ?>
										<span class="pncp-ar__rep pncp-ar__rep--<?php echo esc_attr( $rep['level'] ); ?>"><?php echo esc_html( ( isset( $levels[ $rep['level'] ] ) ? $levels[ $rep['level'] ] : $rep['level'] ) . ' (' . number_format_i18n( $rep['score'] ) . ')' ); ?></span>
									<?php endif; ?>
								</td>
							<?php endif; ?>
							<td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td>
							<td class="pncp-ar__kinds"><?php echo esc_html( implode( ', ', $kinds ) ); ?></td>
							<td class="pncp-ar__nowrap"><?php echo esc_html( self::ago( $row['last'] ) ); ?></td>
							<td><?php self::block_buttons( $row['ip'], $days ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table></div>
				<p class="description">
					<?php esc_html_e( '“Block 24 h” blocks the IP for a day; “Always block” blocks it permanently.', 'scrapelock' ); ?>
					<?php if ( PNCP_Options::monitoring() ) : ?>
						<strong><?php esc_html_e( 'Monitor only is on: a blocked IP is logged as “Would block” and still let through.', 'scrapelock' ); ?></strong>
					<?php endif; ?>
				</p>
				<?php echo PNCP_Admin_Fields::more( __( '“Block 24 h” blocks the IP (IPv6: its /64) for a day; “Always block” adds it to “Always-blocked IPs” (Bots and limits tab). Home connections change hands: prefer “Always block” for data centers and addresses that keep coming back. Search engines, CDN edges, your own and always-allowed addresses cannot be blocked here.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Card: the User-Agents of the refused requests (from the Log).
	 *
	 * @param int $days Days.
	 */
	public static function render_user_agents_card( $days ) {
		$rows = self::top_user_agents( $days, 15 );
		$keep = (int) PNCP_Options::stored()['log_retention'];
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-ar-uas" aria-labelledby="pncp-ar-uas-title">
			<h2 id="pncp-ar-uas-title"><?php esc_html_e( 'User-Agents of the refused requests', 'scrapelock' ); ?></h2>
			<?php if ( ! $rows ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'No refused request in the Log for this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<div class="pncp-table-wrap"><table class="widefat striped">
					<thead><tr><th scope="col"><?php esc_html_e( 'User-Agent', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'Requests', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th></tr></thead>
					<tbody>
					<?php foreach ( $rows as $row ) : ?>
						<tr><td class="pncp-ar__ua"><code><?php echo esc_html( $row['ua'] ); ?></code></td><td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td><td class="num"><?php echo esc_html( number_format_i18n( $row['ips'] ) ); ?></td></tr>
					<?php endforeach; ?>
					</tbody>
				</table></div>
			<?php endif; ?>
			<p class="description">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: number of days */
						_n( 'From the Log, kept %s day. Block by User-Agent only as a bot-list line.', 'From the Log, kept %s days. Block by User-Agent only as a bot-list line.', max( 1, $keep ), 'scrapelock' ),
						number_format_i18n( max( 1, $keep ) )
					)
				);
				?>
			</p>
			<?php echo PNCP_Admin_Fields::more( __( 'The Log keeps the User-Agent of every refused request; the attack record does not keep User-Agents. A User-Agent is easy to fake: block by it only on the Bots and limits tab, as a bot-list line.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		</section>
		<?php
	}

	/**
	 * Card: what the Bunny CDN edge saw (category "edge", imported from Bunny's logs).
	 *
	 * @param int $days Days.
	 */
	public static function render_edge_card( $days ) {
		$stats   = self::category_stats( $days );
		$hits    = isset( $stats['edge'] ) ? $stats['edge'] : null;
		$paths   = $hits ? PNCP_Attacks::top_paths( $days, 10, 'edge' ) : array();
		$details = $hits ? PNCP_Attacks::top_details( $days, 'edge', 10 ) : array();
		$bunny   = class_exists( 'PNCP_Bunny' ) && PNCP_Bunny::edge_available();
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-ar-edge" aria-labelledby="pncp-ar-edge-title">
			<h2 id="pncp-ar-edge-title"><?php esc_html_e( 'Seen at the Bunny CDN edge', 'scrapelock' ); ?></h2>
			<?php if ( ! $hits ) : ?>
				<p class="pncp-empty">
					<?php
					if ( $bunny ) {
						esc_html_e( 'Nothing from the CDN in this period.', 'scrapelock' );
					} else {
						esc_html_e( 'Bunny CDN is not connected. With Bunny connected (Bots and limits tab, CDN), the attacks it sees in its logs are added here, also those that never reached this server.', 'scrapelock' );
					}
					?>
				</p>
			<?php else : ?>
				<ul class="pncp-ar__kpis pncp-ar__kpis--small">
					<?php
					self::kpi_tile( $hits['hits'], __( 'attacks at the edge', 'scrapelock' ) );
					self::kpi_tile( $hits['ips'], __( 'different IPs', 'scrapelock' ) );
					self::kpi_tile( $hits['blocked'], __( 'refused at the edge', 'scrapelock' ) );
					?>
				</ul>
				<div class="pncp-ar__cols">
					<div>
						<h3><?php esc_html_e( 'Addresses', 'scrapelock' ); ?></h3>
						<div class="pncp-table-wrap"><table class="widefat striped">
							<thead><tr><th scope="col"><?php esc_html_e( 'Address', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'Attacks', 'scrapelock' ); ?></th><th scope="col"><?php esc_html_e( 'Close', 'scrapelock' ); ?></th></tr></thead>
							<tbody>
							<?php foreach ( $paths as $row ) : ?>
								<tr><td class="pncp-ar__path"><code><?php echo esc_html( '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : __( '(many addresses)', 'scrapelock' ) ); ?></code></td><td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td><td class="pncp-ar__lock"><?php self::lock_cell( $row['path'] ); ?></td></tr>
							<?php endforeach; ?>
							</tbody>
						</table></div>
					</div>
					<?php if ( $details ) : ?>
						<div>
							<h3><?php esc_html_e( 'What the CDN saw', 'scrapelock' ); ?></h3>
							<div class="pncp-table-wrap"><table class="widefat striped">
								<thead><tr><th scope="col"><?php esc_html_e( 'Detail', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'Attacks', 'scrapelock' ); ?></th><th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th></tr></thead>
								<tbody>
								<?php foreach ( $details as $row ) : ?>
									<tr><td><code><?php echo esc_html( $row['detail'] ); ?></code></td><td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td><td class="num"><?php echo esc_html( number_format_i18n( $row['ips'] ) ); ?></td></tr>
								<?php endforeach; ?>
								</tbody>
							</table></div>
						</div>
					<?php endif; ?>
				</div>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Card: CSV export and the weekly email.
	 *
	 * @param int                  $days Days.
	 * @param array<string, mixed> $s    Settings.
	 */
	public static function render_tools_card( $days, $s ) {
		$on   = self::weekly_on( $s );
		$next = wp_next_scheduled( self::CRON );
		$last = (int) get_option( self::LAST_OPTION, 0 );
		$to   = self::recipients();
		?>
		<div class="pncp-ar__tools">
			<section class="pncp-card" id="pncp-ar-export" aria-labelledby="pncp-ar-export-title">
				<h2 id="pncp-ar-export-title"><?php esc_html_e( 'Export', 'scrapelock' ); ?></h2>
				<?php echo PNCP_Admin_Fields::para( __( 'The report of this period as CSV, or every row of the record.', 'scrapelock' ), __( 'The report of the period shown, as a spreadsheet (CSV): key figures, kinds of attack, addresses with the point that locks them, IPs with country, usernames tried, User-Agents and the CDN edge. Or every row of the record: one line per hour, kind, address and IP.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pncp-ar__form">
					<input type="hidden" name="action" value="pncp_attack_export">
					<input type="hidden" name="days" value="<?php echo esc_attr( (string) $days ); ?>">
					<input type="hidden" name="kind" value="report">
					<?php echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( 'pncp_attack_export', '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup. ?>
					<button type="submit" class="button button-primary" id="pncp-ar-export-report"><?php esc_html_e( 'Download the report (CSV)', 'scrapelock' ); ?></button>
				</form>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pncp-ar__form">
					<input type="hidden" name="action" value="pncp_attack_export">
					<input type="hidden" name="days" value="<?php echo esc_attr( (string) $days ); ?>">
					<input type="hidden" name="kind" value="rows">
					<?php echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( 'pncp_attack_export', '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup. ?>
					<button type="submit" class="button" id="pncp-ar-export-rows"><?php esc_html_e( 'Download every row (CSV)', 'scrapelock' ); ?></button>
				</form>
				<p class="description"><?php esc_html_e( 'The files contain IP addresses and the usernames tried (personal data): keep them safe.', 'scrapelock' ); ?></p>
			</section>
			<section class="pncp-card" id="pncp-ar-email" aria-labelledby="pncp-ar-email-title">
				<h2 id="pncp-ar-email-title"><?php esc_html_e( 'Weekly email', 'scrapelock' ); ?>
					<?php $pncp_badge = PNCP_Status_State::weekly_report( $s ); // 3.11: three states, with the reason. ?>
					<span class="pncp-badge<?php echo $on ? ' pncp-badge--monitor' : ''; ?>" data-pncp-state="<?php echo esc_attr( $pncp_badge['state'] ); ?>"><?php echo esc_html( PNCP_Status_State::text( $pncp_badge ) ); ?></span>
				</h2>
				<p class="description">
					<?php
					if ( $on ) {
						echo esc_html(
							sprintf(
								/* translators: 1: email addresses, 2: date and time */
								__( 'Every Monday a 7-day summary goes to %1$s. Next: %2$s.', 'scrapelock' ),
								$to ? implode( ', ', $to ) : '–',
								$next ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $next ) : '–'
							)
						);
					} else {
						esc_html_e( 'Off: turn on “Weekly attack report by email” on the Log tab.', 'scrapelock' );
					}
					if ( $last ) {
						echo ' ' . esc_html(
							sprintf(
								/* translators: %s: date and time */
								__( 'Last sent: %s.', 'scrapelock' ),
								wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last )
							)
						);
					}
					?>
				</p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pncp-ar__form">
					<input type="hidden" name="action" value="pncp_attack_report_send">
					<input type="hidden" name="days" value="<?php echo esc_attr( (string) $days ); ?>">
					<?php echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( 'pncp_attack_report_send', '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup. ?>
					<button type="submit" class="button" id="pncp-ar-send"><?php esc_html_e( 'Send the weekly report now', 'scrapelock' ); ?></button>
				</form>
				<p><a href="<?php echo esc_url( ( class_exists( 'PNCP_Status' ) ? PNCP_Status::settings_url( array( 'tab' => 'log' ) ) : admin_url() ) . '#pncp-sec-attack-report' ); ?>"><?php esc_html_e( 'Email setting (Log tab)', 'scrapelock' ); ?></a></p>
			</section>
		</div>
		<?php
	}

	/* ---------- WP-CLI ---------- */

	/**
	 * "wp scrapelock attack-report [--days=<n>] [--send] [--format=text|csv]": prints the summary (the weekly
	 * email's text), the report CSV, or sends the email.
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cli( $args, $assoc_args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed -- WP-CLI signature.
		$days   = max( 1, min( 90, isset( $assoc_args['days'] ) ? (int) $assoc_args['days'] : 7 ) );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'text';
		if ( isset( $assoc_args['send'] ) ) {
			if ( self::send( $days ) ) {
				/* translators: %s: email addresses */
				WP_CLI::success( sprintf( __( 'Sent to %s.', 'scrapelock' ), implode( ', ', self::recipients() ) ) );
				return;
			}
			WP_CLI::error( __( 'The email could not be sent.', 'scrapelock' ) );
		}
		if ( 'csv' === $format ) {
			self::export_report_csv( $days );
			return;
		}
		if ( 'text' !== $format ) {
			WP_CLI::error( __( 'Unknown --format. Use: text or csv.', 'scrapelock' ) );
		}
		$mail = self::email( $days );
		WP_CLI::log( $mail['subject'] );
		WP_CLI::log( '' );
		WP_CLI::log( $mail['body'] );
	}
}
