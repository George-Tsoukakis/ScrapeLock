<?php
/**
 * WP-CLI: wp scrapelock status | block | unblock | blocked | emergency | log. Lockdown cannot be unlocked
 * from here: it opens only with the authenticator app (or SCRAPELOCK_UNLOCK in wp-config.php).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Manages ScrapeLock from the command line.
 */
final class PNCP_Cli {

	/**
	 * Registers the command.
	 */
	public static function init() {
		WP_CLI::add_command( 'scrapelock', __CLASS__ );
	}

	/**
	 * Shows what is on and off (the same list as the ScrapeLock section in Site Health → Info).
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock status
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function status( $args, $assoc_args ) {
		$info  = PNCP_Health::info( array() );
		$items = array();
		foreach ( $info['scrapelock']['fields'] as $field ) {
			$items[] = array(
				'setting' => $field['label'],
				'value'   => $field['value'],
			);
		}
		$summary = PNCP_Log::summary( 24 );
		$items[] = array(
			'setting' => __( 'IPs blocked now', 'scrapelock' ),
			'value'   => (string) PNCP_Log::count_bans(),
		);
		$items[] = array(
			'setting' => __( 'Blocked requests, last 24 hours', 'scrapelock' ),
			'value'   => (string) $summary['total'],
		);
		WP_CLI\Utils\format_items( self::format( $assoc_args ), $items, array( 'setting', 'value' ) );
	}

	/**
	 * Blocks an IP temporarily (IPv6: its /64), like the automatic temporary block.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address.
	 *
	 * [--minutes=<minutes>]
	 * : How long, 1 to 43200 (30 days).
	 * ---
	 * default: 1440
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock block 203.0.113.5 --minutes=60
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function block( $args, $assoc_args ) {
		$ip      = trim( (string) $args[0] );
		$minutes = isset( $assoc_args['minutes'] ) ? (int) $assoc_args['minutes'] : 1440;
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( 'Not a valid IP address.' );
		}
		if ( $minutes < 1 || $minutes > 30 * DAY_IN_SECONDS / MINUTE_IN_SECONDS ) {
			WP_CLI::error( '--minutes must be between 1 and 43200.' );
		}
		if ( PNCP_Bots::is_official_crawler_ip( $ip ) ) {
			WP_CLI::error( 'This IP belongs to Google or Bing: it is never blocked.' );
		}
		PNCP_Log::ban( $ip, $minutes, 'manual' );
		PNCP_Log::reset_cache();
		if ( ! PNCP_Log::is_banned( $ip ) ) {
			WP_CLI::error( 'The block was not stored.' );
		}
		WP_CLI::success( sprintf( 'Blocked %s for %d minutes.', PNCP_Ip::limit_key( $ip ), $minutes ) );
	}

	/**
	 * Lifts a temporary block.
	 *
	 * ## OPTIONS
	 *
	 * [<ip>...]
	 * : IP addresses, or the IPv6 /64 networks as `wp scrapelock blocked` lists them.
	 *
	 * [--all]
	 * : Lift every temporary block.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock unblock 203.0.113.5
	 *     wp scrapelock unblock --all
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function unblock( $args, $assoc_args ) {
		if ( ! empty( $assoc_args['all'] ) ) {
			$count = PNCP_Log::count_bans();
			PNCP_Log::unban_all();
			WP_CLI::success( sprintf( 'Lifted %d blocks.', $count ) );
			return;
		}
		if ( ! $args ) {
			WP_CLI::error( 'Give an IP address, or --all.' );
		}
		foreach ( $args as $ip ) {
			$ip = trim( (string) $ip );
			if ( ! PNCP_Ip::valid_range( $ip ) ) {
				WP_CLI::warning( sprintf( 'Not a valid IP address: %s', $ip ) );
				continue;
			}
			PNCP_Log::unban( $ip );
			WP_CLI::success( sprintf( 'Unblocked %s.', $ip ) );
		}
	}

	/**
	 * Lists the IPs blocked now.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv, yaml or count.
	 * ---
	 * default: table
	 * ---
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function blocked( $args, $assoc_args ) {
		$items = array();
		foreach ( PNCP_Log::active_bans( 0 ) as $ip => $ban ) {
			$items[] = array(
				'ip'     => (string) $ip,
				'reason' => $ban['reason'],
				'since'  => wp_date( 'Y-m-d H:i', $ban['since'] ),
				'until'  => wp_date( 'Y-m-d H:i', $ban['until'] ),
			);
		}
		WP_CLI\Utils\format_items( self::format( $assoc_args, true ), $items, array( 'ip', 'reason', 'since', 'until' ) );
	}

	/**
	 * Starts, stops or shows Emergency Mode (stricter limits for a while).
	 *
	 * ## OPTIONS
	 *
	 * <state>
	 * : on, off or status.
	 * ---
	 * options:
	 *   - on
	 *   - off
	 *   - status
	 * ---
	 *
	 * [--hours=<hours>]
	 * : With "on": how long, 1 to 72.
	 * ---
	 * default: 24
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock emergency on --hours=6
	 *     wp scrapelock emergency off
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function emergency( $args, $assoc_args ) {
		$state = (string) $args[0];
		if ( 'on' === $state ) {
			$hours = isset( $assoc_args['hours'] ) ? (int) $assoc_args['hours'] : 24;
			if ( $hours < 1 || $hours > 72 ) {
				WP_CLI::error( '--hours must be between 1 and 72.' );
			}
			if ( ! PNCP_Status::is_enabled() ) {
				WP_CLI::warning( 'Protection is off: Emergency Mode does nothing until it is turned on.' );
			}
			PNCP_Options::set_emergency( $hours );
		} elseif ( 'off' === $state ) {
			PNCP_Options::set_emergency( 0 );
		} elseif ( 'status' !== $state ) {
			WP_CLI::error( 'Use on, off or status.' );
		}
		$until = PNCP_Options::emergency_until();
		WP_CLI::success( $until ? sprintf( 'Emergency Mode is on until %s.', wp_date( 'Y-m-d H:i', $until ) ) : 'Emergency Mode is off.' );
	}

	/**
	 * Shows the log: the latest blocked requests, or with --top the totals per reason, the top IPs and the
	 * paths blocked most often.
	 *
	 * ## OPTIONS
	 *
	 * [--top]
	 * : Totals instead of single requests.
	 *
	 * [--hours=<hours>]
	 * : With --top: the period, 1 to 720.
	 * ---
	 * default: 24
	 * ---
	 *
	 * [--limit=<limit>]
	 * : Rows, 1 to 1000.
	 * ---
	 * default: 20
	 * ---
	 *
	 * [--format=<format>]
	 * : table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock log --limit=50
	 *     wp scrapelock log --top --hours=168
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function log( $args, $assoc_args ) {
		$limit   = max( 1, min( 1000, isset( $assoc_args['limit'] ) ? (int) $assoc_args['limit'] : 20 ) );
		$format  = self::format( $assoc_args );
		$reasons = PNCP_Log::reasons();
		if ( empty( $assoc_args['top'] ) ) {
			$items = array();
			foreach ( PNCP_Log::recent( $limit ) as $row ) {
				$items[] = array(
					'time'   => (string) $row['created'],
					'ip'     => (string) $row['ip'],
					'reason' => (string) $row['reason'],
					'hits'   => (int) $row['hits'],
					'path'   => isset( $row['path'] ) ? (string) $row['path'] : '',
					'ua'     => isset( $row['ua'] ) ? (string) $row['ua'] : '',
				);
			}
			WP_CLI\Utils\format_items( $format, $items, array( 'time', 'ip', 'reason', 'hits', 'path', 'ua' ) );
			return;
		}
		$hours   = max( 1, min( 720, isset( $assoc_args['hours'] ) ? (int) $assoc_args['hours'] : 24 ) );
		$summary = PNCP_Log::summary( $hours );
		$items   = array();
		foreach ( $summary['reasons'] as $reason => $hits ) {
			$items[] = array(
				'group' => 'reason',
				'value' => isset( $reasons[ $reason ] ) ? $reasons[ $reason ] : $reason,
				'hits'  => $hits,
			);
		}
		foreach ( array_slice( $summary['ips'], 0, $limit, true ) as $ip => $hits ) {
			$items[] = array(
				'group' => 'ip',
				'value' => (string) $ip,
				'hits'  => $hits,
			);
		}
		foreach ( PNCP_Log::top_paths( $hours, $limit ) as $group => $paths ) {
			foreach ( $paths as $path ) {
				$items[] = array(
					'group' => 'path:' . $group,
					'value' => $path['path'],
					'hits'  => $path['hits'],
				);
			}
		}
		if ( 'table' === $format ) {
			WP_CLI::log( sprintf( '%1$d blocked requests in the last %2$d hours.', $summary['total'], $hours ) );
		}
		WP_CLI\Utils\format_items( $format, $items, array( 'group', 'value', 'hits' ) );
	}

	/**
	 * The --format value, limited to the formats every list here supports.
	 *
	 * @param array<string, string> $assoc_args Options.
	 * @param bool                  $count      Is "count" allowed?
	 * @return string
	 */
	private static function format( $assoc_args, $count = false ) {
		$format  = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$allowed = array( 'table', 'json', 'csv', 'yaml' );
		if ( $count ) {
			$allowed[] = 'count';
		}
		if ( ! in_array( $format, $allowed, true ) ) {
			WP_CLI::error( 'Unknown --format. Use: ' . implode( ', ', $allowed ) . '.' );
		}
		return $format;
	}
}
