<?php
/**
 * WP-CLI: wp scrapelock status | block | unblock | blocked | emergency | lockdown status | check | log | settings.
 * Lockdown cannot be unlocked from here: it opens only with the authenticator app (or SCRAPELOCK_UNLOCK in
 * wp-config.php).
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
			WP_CLI::error( __( 'Not a valid IP address.', 'scrapelock' ) );
		}
		if ( $minutes < 1 || $minutes > 30 * DAY_IN_SECONDS / MINUTE_IN_SECONDS ) {
			WP_CLI::error( __( '--minutes must be between 1 and 43200.', 'scrapelock' ) );
		}
		$why = PNCP_Options::ban_refusal( $ip );
		if ( '' !== $why ) {
			WP_CLI::error( PNCP_Options::ban_refusal_text( $why ) );
		}
		PNCP_Log::ban( $ip, $minutes, 'manual' );
		PNCP_Log::reset_cache();
		if ( ! PNCP_Log::is_banned( $ip ) ) {
			WP_CLI::error( __( 'The block was not stored.', 'scrapelock' ) );
		}
		/* translators: 1: IP address or IPv6 network, 2: number of minutes */
		WP_CLI::success( sprintf( _n( 'Blocked %1$s for %2$d minute.', 'Blocked %1$s for %2$d minutes.', $minutes, 'scrapelock' ), PNCP_Ip::limit_key( $ip ), $minutes ) );
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
			/* translators: %d: number of blocks */
			WP_CLI::success( sprintf( _n( 'Lifted %d block.', 'Lifted %d blocks.', $count, 'scrapelock' ), $count ) );
			return;
		}
		if ( ! $args ) {
			WP_CLI::error( __( 'Give an IP address, or --all.', 'scrapelock' ) );
		}
		foreach ( $args as $ip ) {
			$ip = trim( (string) $ip );
			if ( ! PNCP_Ip::valid_range( $ip ) ) {
				/* translators: %s: what was given as an IP address */
				WP_CLI::warning( sprintf( __( 'Not a valid IP address: %s', 'scrapelock' ), $ip ) );
				continue;
			}
			// 3.4: say so when the IP was not blocked (an IPv6 address is blocked under its /64).
			$key    = false === strpos( $ip, '/' ) ? PNCP_Ip::limit_key( $ip ) : $ip;
			$active = array_key_exists( $key, PNCP_Log::active_bans( 0 ) );
			PNCP_Log::unban( $ip );
			if ( ! $active ) {
				/* translators: %s: IP address */
				WP_CLI::warning( sprintf( __( '%s had no temporary block: nothing was lifted.', 'scrapelock' ), $ip ) );
				continue;
			}
			/* translators: %s: IP address */
			WP_CLI::success( sprintf( __( 'Unblocked %s.', 'scrapelock' ), $ip ) );
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
				WP_CLI::error( __( '--hours must be between 1 and 72.', 'scrapelock' ) );
			}
			if ( ! PNCP_Status::is_enabled() ) {
				WP_CLI::warning( __( 'Protection is off: Emergency Mode does nothing until it is turned on.', 'scrapelock' ) );
			}
			PNCP_Options::set_emergency( $hours );
		} elseif ( 'off' === $state ) {
			PNCP_Options::set_emergency( 0 );
		} elseif ( 'status' !== $state ) {
			WP_CLI::error( __( 'Use on, off or status.', 'scrapelock' ) );
		}
		$until = PNCP_Options::emergency_until();
		/* translators: %s: date and time */
		WP_CLI::success( $until ? sprintf( __( 'Emergency Mode is on until %s.', 'scrapelock' ), wp_date( 'Y-m-d H:i', $until ) ) : __( 'Emergency Mode is off.', 'scrapelock' ) );
	}

	/**
	 * Shows the state of Lockdown. Read only: Lockdown cannot be locked or unlocked from here (it opens only
	 * with the authenticator app, or SCRAPELOCK_UNLOCK in wp-config.php).
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : status (the only action).
	 * ---
	 * options:
	 *   - status
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
	 *     wp scrapelock lockdown status
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function lockdown( $args, $assoc_args ) {
		if ( 'status' !== (string) $args[0] ) {
			WP_CLI::error( __( 'Use: wp scrapelock lockdown status. Lockdown is locked and unlocked on the ScrapeLock page, with the authenticator app.', 'scrapelock' ) );
		}
		$format = self::format( $assoc_args );
		$yes    = __( 'Yes', 'scrapelock' );
		$no     = __( 'No', 'scrapelock' );
		$locked = PNCP_Lockdown::is_locked();
		$until  = PNCP_Lockdown::unlocked_until();
		if ( PNCP_Lockdown::server_unlocked() ) {
			$state = __( 'Off from the server (SCRAPELOCK_UNLOCK)', 'scrapelock' );
		} elseif ( ! PNCP_Lockdown::configured() ) {
			$state = __( 'Not set up', 'scrapelock' );
		} elseif ( $locked ) {
			$state = __( 'Locked', 'scrapelock' );
		} elseif ( $until ) {
			/* translators: %s: date and time */
			$state = sprintf( __( 'Unlocked until %s', 'scrapelock' ), wp_date( 'Y-m-d H:i', $until ) );
		} else {
			$state = __( 'Not locked', 'scrapelock' );
		}
		$tampered = PNCP_Lockdown::tampered();
		$report   = PNCP_Integrity::report();
		$baseline = PNCP_Integrity::baseline();
		$items    = array(
			array( __( 'Lockdown', 'scrapelock' ), $state ),
			array( __( 'Lock data in order', 'scrapelock' ), '' === $tampered ? $yes : __( 'No: changed outside WordPress (see Site Health)', 'scrapelock' ) ),
			array( __( 'Security keys in wp-config.php', 'scrapelock' ), PNCP_Seal::keys_in_config() ? $yes : $no ),
			array( __( 'Guard file', 'scrapelock' ), is_multisite() ? '-' : ( PNCP_Seal::guard_installed() ? $yes : $no ) ),
			array( __( 'Roles frozen while locked', 'scrapelock' ), implode( ', ', PNCP_Lockdown::frozen_roles() ) ),
			array( __( 'File integrity fingerprint', 'scrapelock' ), $baseline['time'] ? wp_date( 'Y-m-d H:i', (int) $baseline['time'] ) : '-' ),
			array( __( 'Last file check', 'scrapelock' ), $report['time'] ? wp_date( 'Y-m-d H:i', (int) $report['time'] ) : '-' ),
			array( __( 'Changed code files', 'scrapelock' ), (string) count( PNCP_Integrity::findings( $report ) ) ),
		);
		$rows     = array();
		foreach ( $items as $item ) {
			$rows[] = array(
				'setting' => $item[0],
				'value'   => $item[1],
			);
		}
		WP_CLI\Utils\format_items( $format, $rows, array( 'setting', 'value' ) );
	}

	/**
	 * Explains what ScrapeLock would answer to a request, without acting on it.
	 *
	 * Nothing is counted, logged or blocked. The settings in effect now are used (also Emergency Mode and
	 * "Monitor only"). Not simulated: the human-check cookie (a script never has it), "page not found" (404),
	 * private URL tokens, WooCommerce cart and checkout pages, and the early and pre-cache checks, which run
	 * before WordPress. Run it without --user: with --user, that account may be exempt.
	 *
	 * The address can also be given with WP-CLI's own --url (a full URL of this site), e.g. on multisite.
	 *
	 * ## OPTIONS
	 *
	 * --ip=<ip>
	 * : The visitor's IP address.
	 *
	 * [--ua=<user-agent>]
	 * : The User-Agent. Leave it out for a request without one.
	 *
	 * [--address=<url>]
	 * : The address on this site, e.g. /?s=shoes, /feed/, /wp-json/wp/v2/posts or a full URL. Default: WP-CLI's --url, or the home page.
	 *
	 * [--browser]
	 * : Also send the headers a real browser sends (Accept-Language, Sec-Fetch-Mode and, for Chrome and Edge, Sec-CH-UA).
	 *
	 * [--accept-language=<value>]
	 * : The Accept-Language header.
	 *
	 * [--referer=<url>]
	 * : The Referer header.
	 *
	 * [--format=<format>]
	 * : table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock check --ip=203.0.113.5 --ua="python-requests/2.31"
	 *     wp scrapelock check --ip=66.249.66.1 --ua="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	 *     wp scrapelock check --ip=198.51.100.7 --ua="Mozilla/5.0 (Windows NT 10.0) Firefox/128.0" --browser --address=/feed/
	 *     wp scrapelock check --ip=198.51.100.7 --ua="curl/8.5" --url=https://example.com/wp-json/wp/v2/posts
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function check( $args, $assoc_args ) {
		$format = self::format( $assoc_args );
		$ip     = isset( $assoc_args['ip'] ) ? trim( (string) $assoc_args['ip'] ) : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( __( 'Give a valid IP address with --ip.', 'scrapelock' ) );
		}
		$ua = isset( $assoc_args['ua'] ) && true !== $assoc_args['ua'] ? (string) $assoc_args['ua'] : '';
		// --url is a global WP-CLI option (it chooses the site, and WP-CLI keeps it): it is used when --address is not given.
		$url     = isset( $assoc_args['address'] ) && true !== $assoc_args['address'] ? (string) $assoc_args['address'] : (string) WP_CLI::get_config( 'url' );
		$headers = array();
		if ( ! empty( $assoc_args['browser'] ) ) {
			$headers['Accept-Language'] = 'en-US,en;q=0.9';
			$headers['Sec-Fetch-Mode']  = 'navigate';
			$headers['Sec-Fetch-Dest']  = 'document';
			if ( preg_match( '#\b(?:Chrome|Chromium)/(\d+)#', $ua, $m ) ) {
				$headers['Sec-CH-UA'] = '"Chromium";v="' . (int) $m[1] . '", "Not.A/Brand";v="99"';
			}
		}
		if ( isset( $assoc_args['accept-language'] ) && true !== $assoc_args['accept-language'] ) {
			$headers['Accept-Language'] = (string) $assoc_args['accept-language'];
		}
		if ( isset( $assoc_args['referer'] ) && true !== $assoc_args['referer'] ) {
			$headers['Referer'] = (string) $assoc_args['referer'];
		}
		$url = trim( $url );
		if ( '' !== $url && '/' === $url[0] ) {
			$url = home_url( $url );
		} elseif ( '' !== $url && false === strpos( $url, '://' ) ) {
			$url = 'http://' . $url; // WP-CLI accepts --url=example.com/path.
		}
		$result  = PNCP_Bots::explain( $ip, $ua, $url, $headers );
		$reasons = PNCP_Log::reasons();
		$kinds   = array(
			'page'    => __( 'Page', 'scrapelock' ),
			'search'  => __( 'Search', 'scrapelock' ),
			'rest'    => __( 'REST API', 'scrapelock' ),
			'graphql' => __( 'GraphQL', 'scrapelock' ),
			'sitemap' => __( 'Sitemap', 'scrapelock' ),
		);
		if ( $result['code'] ) {
			$label   = isset( $reasons[ $result['reason'] ] ) ? $reasons[ $result['reason'] ] : $result['reason'];
			$verdict = sprintf(
				/* translators: 1: HTTP status code (403 or 429), 2: reason */
				429 === $result['code'] ? __( 'Limited (%1$d): %2$s', 'scrapelock' ) : __( 'Blocked (%1$d): %2$s', 'scrapelock' ),
				$result['code'],
				$label
			);
		} else {
			$why     = self::pass_reasons();
			$verdict = sprintf(
				/* translators: %s: why the request passes */
				__( 'Allowed: %s', 'scrapelock' ),
				isset( $why[ $result['pass'] ] ) ? $why[ $result['pass'] ] : $result['pass']
			);
		}
		$items = array(
			array( __( 'IP', 'scrapelock' ), $ip ),
			array( __( 'User-Agent', 'scrapelock' ), '' === $ua ? '-' : $ua ),
			array( __( 'Address', 'scrapelock' ), '' === $url ? home_url( '/' ) : $url ),
			array( __( 'Checked as', 'scrapelock' ), $kinds[ $result['context'] ] . ( $result['feed'] ? ' (' . __( 'feed', 'scrapelock' ) . ')' : '' ) ),
			array( __( 'Verdict', 'scrapelock' ), $verdict ),
		);
		if ( $result['monitor'] ) {
			$items[] = array( __( 'Monitor only', 'scrapelock' ), __( 'On: this request would be let through and logged as “Would block”.', 'scrapelock' ) );
		}
		if ( PNCP_Options::emergency_until() ) {
			/* translators: %s: date and time */
			$items[] = array( __( 'Emergency Mode', 'scrapelock' ), sprintf( __( 'On until %s (its stricter settings were used).', 'scrapelock' ), wp_date( 'Y-m-d H:i', PNCP_Options::emergency_until() ) ) );
		}
		$s    = PNCP_Options::get();
		$path = PNCP_Private_Urls::relative_path( rawurldecode( (string) wp_parse_url( '' === $url ? home_url( '/' ) : $url, PHP_URL_PATH ) ) );
		$args = array();
		wp_parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $args );
		if ( ! empty( $s['enabled'] ) && '' !== trim( (string) $s['private_paths'] ) && '' !== PNCP_Private_Urls::matching_pattern( $path, PNCP_Options::parse_list( $s['private_paths'] ), $args ) ) {
			$items[] = array( __( 'Private URL', 'scrapelock' ), __( 'Yes: without a valid token or an allowed IP it gets a 403 before these checks.', 'scrapelock' ) );
		}
		$rows = array();
		foreach ( $items as $item ) {
			$rows[] = array(
				'check' => $item[0],
				'value' => $item[1],
			);
		}
		WP_CLI\Utils\format_items( $format, $rows, array( 'check', 'value' ) );
	}

	/**
	 * Why a request passes, as PNCP_Bots::explain() reports it.
	 *
	 * @return array<string, string>
	 */
	private static function pass_reasons() {
		return array(
			'off'           => __( 'protection is off', 'scrapelock' ),
			'cron'          => __( 'scheduled tasks (cron) are not checked', 'scrapelock' ),
			'exempt'        => __( 'the current user is exempt (WP-CLI --user)', 'scrapelock' ),
			'open_path'     => __( 'robots.txt, llms.txt and the TDM opt-out are never blocked', 'scrapelock' ),
			'private_url'   => __( 'a private URL with a valid token', 'scrapelock' ),
			'local'         => __( 'the server itself or a private network address', 'scrapelock' ),
			'allow_ip'      => __( 'in “Always allowed IPs”', 'scrapelock' ),
			'filter'        => __( 'let through by the pncp_skip_guard filter', 'scrapelock' ),
			'search_engine' => __( 'a verified search engine (never blocked or limited)', 'scrapelock' ),
			'ai_search'     => __( 'a verified AI search bot (never blocked or limited)', 'scrapelock' ),
			'prefetch'      => __( 'a prefetch within its own limit', 'scrapelock' ),
			'passed'        => __( 'it passes every check, and is within the limits this minute', 'scrapelock' ),
		);
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
					'path'   => isset( $row['path'] ) ? PNCP_Log::display_path( (string) $row['path'] ) : '',
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
					'value' => PNCP_Log::display_path( $path['path'] ),
					'hits'  => $path['hits'],
				);
			}
		}
		if ( 'table' === $format ) {
			/* translators: 1: number of requests, 2: number of hours */
			WP_CLI::log( sprintf( __( '%1$d blocked requests in the last %2$d hours.', 'scrapelock' ), $summary['total'], $hours ) );
		}
		WP_CLI\Utils\format_items( $format, $items, array( 'group', 'value', 'hits' ) );
	}

	/**
	 * Exports, imports, reads or changes the settings. Every change goes through the same checks as the
	 * settings form, and the settings as they were are kept first (the last 5 versions, also listed under
	 * "Export, import and undo" on the settings page), so "settings undo" can put them back.
	 *
	 * The export leaves out secrets: the CDN shared secret, the API token for blocking at the CDN and the
	 * private feed tokens (only their hashes are stored). "get" never shows the CDN shared secret either.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : export, import, get, set or undo.
	 * ---
	 * options:
	 *   - export
	 *   - import
	 *   - get
	 *   - set
	 *   - undo
	 * ---
	 *
	 * [<name>]
	 * : import: the JSON file. get: one setting (all of them without it). set: the setting.
	 *
	 * [<value>]
	 * : set: the new value. On/off settings take 1/0, on/off, yes/no or true/false. In lists, separate lines with "\n".
	 *
	 * [--file=<file>]
	 * : export: write to this file instead of the screen.
	 *
	 * [--dry-run]
	 * : import, set: only show what would change.
	 *
	 * [--yes]
	 * : import: do not ask for confirmation.
	 *
	 * [--format=<format>]
	 * : get: table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock settings export --file=scrapelock.json
	 *     wp scrapelock settings import scrapelock.json --dry-run
	 *     wp scrapelock settings get rate_limit
	 *     wp scrapelock settings set rate_limit 40
	 *     wp scrapelock settings set block_ips "203.0.113.0/24\n198.51.100.7"
	 *     wp scrapelock settings undo
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function settings( $args, $assoc_args ) {
		// The settings checks report through add_settings_error(), which lives in wp-admin.
		if ( ! function_exists( 'add_settings_error' ) ) {
			require_once ABSPATH . 'wp-admin/includes/template.php';
		}
		$action = (string) $args[0];
		$name   = isset( $args[1] ) ? (string) $args[1] : '';
		$dry    = ! empty( $assoc_args['dry-run'] );
		if ( in_array( $action, array( 'import', 'set', 'undo' ), true ) && ! $dry && PNCP_Lockdown::is_locked() ) {
			WP_CLI::error( __( 'The site is locked: the settings cannot be changed until it is unlocked (with the authenticator app).', 'scrapelock' ) );
		}
		switch ( $action ) {
			case 'export':
				$json = PNCP_Settings_Io::export_json();
				if ( empty( $assoc_args['file'] ) ) {
					WP_CLI::line( $json );
					return;
				}
				$file = (string) $assoc_args['file'];
				// A folder that does not exist or cannot be written to gets the error below only, not PHP's warning.
				$dir = dirname( $file );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- A file named by whoever runs the command.
				if ( ! is_dir( $dir ) || ! wp_is_writable( file_exists( $file ) ? $file : $dir ) || false === file_put_contents( $file, $json . "\n" ) ) {
					WP_CLI::error( __( 'The file could not be written.', 'scrapelock' ) );
				}
				/* translators: %s: file name */
				WP_CLI::success( sprintf( __( 'Settings exported to %s (without the CDN shared secret, the CDN API token and the private feed tokens).', 'scrapelock' ), $assoc_args['file'] ) );
				return;

			case 'import':
				if ( '' === $name || ! is_readable( $name ) ) {
					WP_CLI::error( __( 'Give the JSON file to import, e.g. wp scrapelock settings import scrapelock.json', 'scrapelock' ) );
				}
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A local file named by whoever runs the command.
				$parsed = PNCP_Settings_Io::parse( (string) file_get_contents( $name ) );
				if ( is_wp_error( $parsed ) ) {
					WP_CLI::error( $parsed->get_error_message() );
				}
				if ( $parsed['ignored'] ) {
					/* translators: %s: list of settings */
					WP_CLI::warning( sprintf( __( 'Left out (unknown, secret or belonging to the other site): %s', 'scrapelock' ), implode( ', ', $parsed['ignored'] ) ) );
				}
				self::apply( PNCP_Settings_Io::prepare( $parsed['settings'] ), 'cli:import', $dry, empty( $assoc_args['yes'] ) );
				return;

			case 'get':
				$stored = PNCP_Options::stored();
				$keys   = array_keys( PNCP_Options::defaults() );
				if ( '' !== $name ) {
					if ( ! in_array( $name, $keys, true ) ) {
						/* translators: %s: setting name */
						WP_CLI::error( sprintf( __( 'Unknown setting "%s".', 'scrapelock' ), $name ) );
					}
					$keys = array( $name );
				}
				$items = array();
				foreach ( $keys as $key ) {
					$items[] = array(
						'setting' => $key,
						// The CDN shared secret is never shown: only whether one is set.
						'value'   => in_array( $key, PNCP_Settings_Io::secret_keys(), true ) ? ( '' === (string) $stored[ $key ] ? '' : '(set)' ) : (string) $stored[ $key ],
					);
				}
				if ( '' !== $name && 'table' === self::format( $assoc_args ) ) {
					WP_CLI::line( $items[0]['value'] );
					return;
				}
				WP_CLI\Utils\format_items( self::format( $assoc_args ), $items, array( 'setting', 'value' ) );
				return;

			case 'set':
				if ( '' === $name || ! isset( $args[2] ) ) {
					WP_CLI::error( __( 'Use: wp scrapelock settings set <setting> <value>', 'scrapelock' ) );
				}
				$secret = in_array( $name, PNCP_Settings_Io::secret_keys(), true );
				if ( ! $secret && ! in_array( $name, PNCP_Settings_Io::public_keys(), true ) ) {
					/* translators: %s: setting name */
					WP_CLI::error( sprintf( __( 'Unknown setting "%s". See: wp scrapelock settings get', 'scrapelock' ), $name ) );
				}
				$value = (string) $args[2];
				if ( in_array( $name, PNCP_Options::bool_keys(), true ) ) {
					$bool = filter_var( $value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );
					if ( null === $bool ) {
						/* translators: %s: setting name */
						WP_CLI::error( sprintf( __( '"%s" is an on/off setting: use 1 or 0.', 'scrapelock' ), $name ) );
					}
					$value = $bool ? '1' : '0';
				} elseif ( isset( PNCP_Options::choices()[ $name ] ) && ! in_array( $value, PNCP_Options::choices()[ $name ], true ) ) {
					/* translators: %s: list of values */
					WP_CLI::error( sprintf( __( 'Use one of: %s', 'scrapelock' ), implode( ', ', PNCP_Options::choices()[ $name ] ) ) );
				} elseif ( isset( PNCP_Options::int_ranges()[ $name ] ) && ! preg_match( '/^-?\d+$/', $value ) ) {
					/* translators: %s: setting name */
					WP_CLI::error( sprintf( __( '"%s" takes a whole number.', 'scrapelock' ), $name ) );
				} else {
					$value = str_replace( '\n', "\n", $value ); // Lists: one value per line.
				}
				$prepared = PNCP_Settings_Io::prepare( array( $name => $value ) );
				$now      = (string) $prepared['settings'][ $name ];
				if ( ! $secret && $now !== $value ) {
					/* translators: %s: the value as it is stored */
					WP_CLI::warning( sprintf( __( 'Stored as "%s" (adjusted by the settings checks).', 'scrapelock' ), str_replace( "\n", '\n', $now ) ) );
				}
				if ( $secret && (string) PNCP_Options::stored()[ $name ] !== $now ) {
					// Secrets are never listed among the changes: listed here, hidden.
					$prepared['changes'][] = array(
						'key' => $name,
						'old' => '(hidden)',
						'new' => '(hidden)',
					);
				}
				self::apply( $prepared, 'cli:set', $dry, false );
				return;

			case 'undo':
				$list = PNCP_Settings_Io::backups();
				if ( ! $list ) {
					WP_CLI::error( __( 'There is no earlier version to restore.', 'scrapelock' ) );
				}
				$label  = PNCP_Settings_Io::reason_label( $list[0] );
				$result = PNCP_Settings_Io::restore( $list[0]['id'] );
				if ( is_wp_error( $result ) ) {
					WP_CLI::error( $result->get_error_message() );
				}
				/* translators: 1: date and time, 2: what was about to change then (e.g. "Before an import") */
				WP_CLI::success( sprintf( __( 'Restored the settings saved %1$s (%2$s). Run it again to undo this.', 'scrapelock' ), wp_date( 'Y-m-d H:i', (int) $list[0]['time'] ), $label ) );
				return;
		}
		WP_CLI::error( __( 'Use export, import, get, set or undo.', 'scrapelock' ) );
	}

	/**
	 * Shows what a prepared change does, asks (if needed) and saves it.
	 *
	 * @param array<string, mixed> $prepared Result of PNCP_Settings_Io::prepare().
	 * @param string               $reason   Why (for the saved version).
	 * @param bool                 $dry      Only show.
	 * @param bool                 $ask      Ask for confirmation.
	 */
	private static function apply( $prepared, $reason, $dry, $ask ) {
		foreach ( $prepared['messages'] as $message ) {
			WP_CLI::warning( wp_strip_all_tags( $message['message'] ) );
		}
		if ( ! $prepared['changes'] ) {
			WP_CLI::success( __( 'Nothing to change: the settings are already like that.', 'scrapelock' ) );
			return;
		}
		WP_CLI\Utils\format_items( 'table', $prepared['changes'], array( 'key', 'old', 'new' ) );
		if ( $dry ) {
			/* translators: %d: number of settings */
			WP_CLI::success( sprintf( _n( '%d setting would change (dry run, nothing saved).', '%d settings would change (dry run, nothing saved).', count( $prepared['changes'] ), 'scrapelock' ), count( $prepared['changes'] ) ) );
			return;
		}
		if ( $ask ) {
			/* translators: %d: number of settings */
			WP_CLI::confirm( sprintf( _n( 'Change this %d setting?', 'Change these %d settings?', count( $prepared['changes'] ), 'scrapelock' ), count( $prepared['changes'] ) ) );
		}
		$result = PNCP_Settings_Io::apply( $prepared, $reason );
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		/* translators: %d: number of settings */
		WP_CLI::success( sprintf( _n( '%d setting changed. The previous settings were kept: "wp scrapelock settings undo" puts them back.', '%d settings changed. The previous settings were kept: "wp scrapelock settings undo" puts them back.', count( $prepared['changes'] ), 'scrapelock' ), count( $prepared['changes'] ) ) );
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
			/* translators: %s: list of formats */
			WP_CLI::error( sprintf( __( 'Unknown --format. Use: %s.', 'scrapelock' ), implode( ', ', $allowed ) ) );
		}
		return $format;
	}
}
