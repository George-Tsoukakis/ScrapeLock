<?php
/**
 * WP-CLI: wp scrapelock status | block | unblock | blocked | emergency | lockdown status | check | log | settings |
 * reputation | crowdsec | ai-referrals (3.7) | attacks | attack-report | login | harden | bunny | stealth (3.8) |
 * wizard (3.11) | traffic (3.12) | rules, cdn (3.12.6).
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
	 * 3.12.2: makes a real request of the site to itself now (its home page, as "Check again" in Vulnerable points
	 * asks for it) and prints what came back: who answered, the signature's result on the receiving side and the
	 * layer that passed or refused it; straight to the server when the public address refuses it. Then the latest
	 * notes of the site's own requests (--log).
	 *
	 * ## OPTIONS
	 *
	 * [--log]
	 * : Also print the last notes of the site's own requests (both sides).
	 *
	 * [--format=<format>]
	 * : text or json.
	 * ---
	 * default: text
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock selfcheck
	 *     wp scrapelock selfcheck --log
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function selfcheck( $args, $assoc_args ) {
		unset( $args );
		$trace = PNCP_Self_Check::run();
		if ( isset( $assoc_args['format'] ) && 'json' === $assoc_args['format'] ) {
			WP_CLI::line( (string) wp_json_encode( isset( $assoc_args['log'] ) ? array_merge( $trace, array( 'log' => PNCP_Self_Check::entries() ) ) : $trace ) );
			return;
		}
		WP_CLI::line( PNCP_Self_Check::summary( $trace ) );
		foreach ( PNCP_Self_Check::lines( $trace ) as $line ) {
			WP_CLI::line( '  ' . $line );
		}
		if ( isset( $assoc_args['log'] ) ) {
			WP_CLI::line( '' );
			WP_CLI::line( 'Notes of the site\'s own requests (newest first):' );
			foreach ( PNCP_Self_Check::entries() as $entry ) {
				$when = gmdate( 'H:i:s', (int) $entry['time'] );
				WP_CLI::line( '  ' . $when . ' ' . ( 'out' === $entry['side'] ? PNCP_Self_Check::step_line( $entry ) : $entry['method'] . ' ' . $entry['path'] . ': ' . PNCP_Self_Check::entry_line( $entry ) ) );
			}
		}
		if ( empty( $trace['ok'] ) && empty( $trace['origin'] ) ) {
			WP_CLI::halt( 1 );
		}
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
		// 3.12.4: the server rules on this server (the server asked directly first; kept 5 minutes).
		$nginx   = PNCP_Rules::nginx_status();
		$items[] = array(
			'setting' => __( 'Nginx server rules', 'scrapelock' ),
			'value'   => PNCP_Rules_Status::nginx_text( $nginx )['line'],
		);
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
	 * 3.4.2: the lock line SCRAPELOCK_LOCKED in wp-config.php, for the status.
	 *
	 * @return string
	 */
	private static function config_text() {
		$texts = array(
			'none'    => __( 'No', 'scrapelock' ),
			'invalid' => __( 'Not valid for this site (not used)', 'scrapelock' ),
			'current' => __( 'Yes, for this lock', 'scrapelock' ),
			'old'     => __( 'From an earlier lock: replace it', 'scrapelock' ),
			'stale'   => __( 'The site is not locked: remove it', 'scrapelock' ),
		);
		return $texts[ PNCP_Seal::config_status() ];
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
			array( __( 'Lock line in wp-config.php', 'scrapelock' ), self::config_text() ),
			array( __( 'Roles frozen while locked', 'scrapelock' ), implode( ', ', PNCP_Lockdown::frozen_roles() ) ),
			array( __( 'Roles that keep their work while locked', 'scrapelock' ), implode( ', ', PNCP_Lockdown::limited_roles() ) ),
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
		} elseif ( '' !== $url && '?' === $url[0] ) {
			$url = home_url( '/' . $url ); // 3.4.3: --address=?s=shoes was checked as "http://?s=shoes", a page.
		} elseif ( '' !== $url && false === strpos( $url, '://' ) ) {
			$url = 'http://' . $url; // WP-CLI accepts --url=example.com/path.
		}
		$result  = PNCP_Bots::explain( $ip, $ua, $url, $headers );
		$kinds   = PNCP_Tester::kinds(); // 3.12.1: with "Media" for a static file.
		$kind    = ! empty( $result['media'] ) ? 'media' : $result['context'];
		if ( $result['code'] ) {
			$label   = PNCP_Log::reason_label( $result['reason'] );
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
				isset( $why[ $result['pass'] ] ) ? $why[ $result['pass'] ] : __( 'another rule lets it through', 'scrapelock' )
			);
		}
		$items = array(
			array( __( 'IP', 'scrapelock' ), $ip ),
			array( __( 'User-Agent', 'scrapelock' ), '' === $ua ? '-' : $ua ),
			array( __( 'Address', 'scrapelock' ), '' === $url ? home_url( '/' ) : $url ),
			array( __( 'Checked as', 'scrapelock' ), ( isset( $kinds[ $kind ] ) ? $kinds[ $kind ] : __( 'Page', 'scrapelock' ) ) . ( $result['feed'] ? ' (' . __( 'feed', 'scrapelock' ) . ')' : '' ) ),
			array( __( 'Verdict', 'scrapelock' ), $verdict ),
		);
		// 3.12.1: the per-minute counter that decides the request and its limit, as on the "Check a request" card.
		$counter = PNCP_Tester::counter( $result, $ip, PNCP_Options::get() );
		if ( $counter ) {
			$items[] = array( $counter['label'], $counter['text'] );
		}
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
			'media'         => __( 'image or file; counted in the media limit, not as a page', 'scrapelock' ), // 3.12.1: as on the card.
			'media_preview' => __( 'a link preview in the “Always allowed” list; its images and files are not counted', 'scrapelock' ), // 3.12.2: as on the card.
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
		if ( empty( $assoc_args['top'] ) ) {
			$items = array();
			foreach ( PNCP_Log::recent( $limit ) as $row ) {
				$items[] = array(
					'time'    => (string) $row['created'],
					'ip'      => (string) $row['ip'],
					// 3.12.1: the label in the table for people; the key in json, csv and yaml, for scripts.
					'reason'  => 'table' === $format ? PNCP_Log::reason_label( (string) $row['reason'] ) : (string) $row['reason'],
					'hits'    => (int) $row['hits'],
					'path'    => isset( $row['path'] ) ? PNCP_Log::display_path( (string) $row['path'] ) : '',
					'ua'      => isset( $row['ua'] ) ? (string) $row['ua'] : '',
					'account' => isset( $row['account'] ) ? (string) $row['account'] : '', // 3.12.1: per-account limits.
				);
			}
			WP_CLI\Utils\format_items( $format, $items, array( 'time', 'ip', 'reason', 'hits', 'path', 'ua', 'account' ) );
			return;
		}
		$hours   = max( 1, min( 720, isset( $assoc_args['hours'] ) ? (int) $assoc_args['hours'] : 24 ) );
		$summary = PNCP_Log::summary( $hours );
		$items   = array();
		foreach ( $summary['reasons'] as $reason => $hits ) {
			$items[] = array(
				'group' => 'reason',
				'value' => PNCP_Log::reason_label( $reason ),
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
		$before = get_option( PNCP_OPTION, array() );
		$result = PNCP_Settings_Io::apply( $prepared, $reason );
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		// 3.9.1: count what was really saved; a setting can be refused on saving (e.g. the allowed IPs of a
		// locked login page at Bunny), with a warning printed above.
		wp_cache_delete( PNCP_OPTION, 'options' );
		$after   = get_option( PNCP_OPTION, array() );
		$changed = 0;
		foreach ( $prepared['changes'] as $change ) {
			$key      = (string) $change['key'];
			$was      = is_array( $before ) && array_key_exists( $key, $before ) ? $before[ $key ] : null;
			$is       = is_array( $after ) && array_key_exists( $key, $after ) ? $after[ $key ] : null;
			$changed += ( $was !== $is ) ? 1 : 0;
		}
		if ( ! $changed ) {
			WP_CLI::warning( __( 'Nothing was changed.', 'scrapelock' ) );
			return;
		}
		/* translators: %d: number of settings */
		WP_CLI::success( sprintf( _n( '%d setting changed. The previous settings were kept: "wp scrapelock settings undo" puts them back.', '%d settings changed. The previous settings were kept: "wp scrapelock settings undo" puts them back.', $changed, 'scrapelock' ), $changed ) );
	}

	/**
	 * The --format value, limited to the formats every list here supports.
	 *
	 * @param array<string, string> $assoc_args Options.
	 * @param bool                  $count      Is "count" allowed?
	 * @return string
	 */
	/**
	 * 3.7: shows (or forgets) the reputation of an IP: its score and the events that make it.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address.
	 *
	 * [--reset]
	 * : Forget everything recorded about it.
	 *
	 * [--format=<format>]
	 * : table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock reputation 203.0.113.5
	 *     wp scrapelock reputation 203.0.113.5 --reset
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function reputation( $args, $assoc_args ) {
		$ip = PNCP_Ip::normalize( isset( $args[0] ) ? (string) $args[0] : '' );
		if ( '' === $ip ) {
			WP_CLI::error( __( 'Give a valid IP address.', 'scrapelock' ) );
		}
		if ( ! empty( $assoc_args['reset'] ) ) {
			PNCP_Reputation::forget( $ip );
			/* translators: %s: IP address */
			WP_CLI::success( sprintf( __( 'The reputation of %s was forgotten.', 'scrapelock' ), $ip ) );
			return;
		}
		$s = PNCP_Options::get();
		if ( ! PNCP_Reputation::active( $s ) ) {
			WP_CLI::warning( __( 'Nothing is recorded: the reputation and the limit for IPs that never opened a page are both off.', 'scrapelock' ) );
		}
		$rep     = PNCP_Reputation::describe( $ip );
		$labels  = PNCP_Reputation::event_labels();
		$weights = PNCP_Reputation::weights();
		$items   = array();
		foreach ( $rep['events'] as $event => $when ) {
			$recent  = time() - (int) $when <= (int) $weights[ $event ][0];
			$items[] = array(
				'event' => isset( $labels[ $event ] ) ? $labels[ $event ] : $event,
				'when'  => wp_date( 'Y-m-d H:i', (int) $when ),
				'value' => (string) ( $recent ? $weights[ $event ][1] : $weights[ $event ][2] ),
			);
		}
		$items[] = array(
			'event' => __( 'Score', 'scrapelock' ),
			'when'  => $rep['level'],
			'value' => (string) $rep['score'],
		);
		WP_CLI\Utils\format_items( self::format( $assoc_args ), $items, array( 'event', 'when', 'value' ) );
	}

	/**
	 * 3.7: the CrowdSec blocklist: its state, a sync now, or whether an IP is listed.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : status, sync or check.
	 * ---
	 * options:
	 *   - status
	 *   - sync
	 *   - check
	 * ---
	 *
	 * [<ip>]
	 * : With "check": the IP address.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock crowdsec status
	 *     wp scrapelock crowdsec sync
	 *     wp scrapelock crowdsec check 203.0.113.5
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function crowdsec( $args, $assoc_args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI signature.
		$action = isset( $args[0] ) ? (string) $args[0] : 'status';
		$s      = PNCP_Options::get();
		if ( ! PNCP_Crowdsec::enabled( $s ) ) {
			WP_CLI::error( __( 'The CrowdSec blocklist is off (Bots and limits → CrowdSec blocklist).', 'scrapelock' ) );
		}
		if ( 'sync' === $action ) {
			$result = PNCP_Crowdsec::sync( true );
			if ( is_wp_error( $result ) ) {
				WP_CLI::error( $result->get_error_message() );
			}
			$state = PNCP_Crowdsec::state();
			/* translators: 1: number of addresses, 2: number of ranges */
			WP_CLI::success( sprintf( __( 'Updated: %1$d addresses, %2$d ranges.', 'scrapelock' ), (int) $state['count'], (int) $state['ranges'] ) );
			return;
		}
		if ( 'check' === $action ) {
			$ip = PNCP_Ip::normalize( isset( $args[1] ) ? (string) $args[1] : '' );
			if ( '' === $ip ) {
				WP_CLI::error( __( 'Give a valid IP address.', 'scrapelock' ) );
			}
			/* translators: %s: IP address */
			WP_CLI::log( sprintf( PNCP_Crowdsec::listed( $ip ) ? __( '%s is in the blocklist.', 'scrapelock' ) : __( '%s is not in the blocklist.', 'scrapelock' ), $ip ) );
			return;
		}
		$state = PNCP_Crowdsec::state();
		$items = array(
			array(
				'setting' => __( 'Source', 'scrapelock' ),
				'value'   => 'lapi' === $s['crowdsec_mode'] ? 'LAPI ' . $s['crowdsec_url'] : $s['crowdsec_url'],
			),
			array(
				'setting' => __( 'What a listed IP gets', 'scrapelock' ),
				'value'   => 'block' === $s['crowdsec_action'] ? '403' : (int) $s['rate_limit_crowdsec'] . '/min',
			),
			array(
				'setting' => __( 'Addresses', 'scrapelock' ),
				'value'   => (string) (int) $state['count'],
			),
			array(
				'setting' => __( 'Ranges', 'scrapelock' ),
				'value'   => (string) (int) $state['ranges'],
			),
			array(
				'setting' => __( 'Updated', 'scrapelock' ),
				'value'   => $state['synced'] ? wp_date( 'Y-m-d H:i', (int) $state['synced'] ) : '-',
			),
			array(
				'setting' => __( 'Last error', 'scrapelock' ),
				'value'   => '' !== (string) $state['error'] ? wp_date( 'Y-m-d H:i', (int) $state['error_at'] ) . ' ' . $state['error'] : '-',
			),
		);
		WP_CLI\Utils\format_items( 'table', $items, array( 'setting', 'value' ) );
	}

	/**
	 * 3.8: where bots and attackers hit the site (the attack record).
	 *
	 * ## OPTIONS
	 *
	 * [--days=<days>]
	 * : Period in days, 1-90. Default 7.
	 *
	 * [--category=<key>]
	 * : login_fail, login_probe, admin_probe, xmlrpc, user_enum, scanner, plugin_probe, install, injection, bot_block or edge.
	 *
	 * [--top=<what>]
	 * : paths, ips, users (usernames tried) or details (of --category). Default: per category.
	 *
	 * [--format=<format>]
	 * : table, json, csv, yaml or count.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock attacks --days=30
	 *     wp scrapelock attacks --top=users
	 *     wp scrapelock attacks --top=paths --category=plugin_probe
	 *
	 * @subcommand attacks
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function attacks( $args, $assoc_args ) {
		PNCP_Attacks::cli( $args, $assoc_args );
	}

	/**
	 * 3.8: the attack report: the weekly email's text, the report as CSV, or send the email now.
	 *
	 * ## OPTIONS
	 *
	 * [--days=<days>]
	 * : Period, 1-90. Default 7.
	 *
	 * [--format=<format>]
	 * : text (default) or csv.
	 *
	 * [--send]
	 * : Send the email now to the administration email (filter pncp_attack_report_recipients).
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock attack-report
	 *     wp scrapelock attack-report --days=30 --format=csv > report.csv
	 *     wp scrapelock attack-report --send
	 *
	 * @subcommand attack-report
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function attack_report( $args, $assoc_args ) {
		PNCP_Attack_Report::cli( $args, $assoc_args );
	}

	/**
	 * 3.8: sign-in protection: status, unlock an IP or a username, or print the sign-in address.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : status, unlock or url.
	 * ---
	 * options:
	 *   - status
	 *   - unlock
	 *   - url
	 * ---
	 *
	 * [<what>]
	 * : For unlock: an IP (lifts its block) or a username (ends its pause).
	 *
	 * [--format=<format>]
	 * : For status: table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock login status
	 *     wp scrapelock login unlock 203.0.113.5
	 *     wp scrapelock login unlock admin
	 *     wp scrapelock login url
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function login( $args, $assoc_args ) {
		PNCP_Login::cli( $args, $assoc_args );
	}

	/**
	 * 3.8: vulnerable points: list, check, lock and open them, and the server rules.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : list (default), check, apply <id>, revert <id>, apply-low, rules, write-htaccess or remove-htaccess.
	 *
	 * [<id>]
	 * : The point (see "list"), for apply and revert.
	 *
	 * [--server=<server>]
	 * : For rules: apache or nginx.
	 *
	 * [--format=<format>]
	 * : For list: table, json or csv.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock harden list
	 *     wp scrapelock harden apply xmlrpc
	 *     wp scrapelock harden rules --server=nginx
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function harden( $args, $assoc_args ) {
		PNCP_Hardening::cli( $args, $assoc_args );
	}

	/**
	 * 3.8: Bunny CDN: logs and Edge Rules.
	 *
	 * ## OPTIONS
	 *
	 * [<subcommand>]
	 * : status, import, rules, presets, preview <preset|harden_point>, lock <preset>, unlock <preset|rule-id>, logging [--enable], parse <file>.
	 *
	 * [<arg>]
	 * : Preset (login, xmlrpc, probes, core_files), rule ID or log file.
	 *
	 * [--enable]
	 * : With "logging": turn logging on at the pull zone.
	 *
	 * [--format=<format>]
	 * : table, json, csv, yaml or count.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock bunny status
	 *     wp scrapelock bunny lock probes
	 *     wp scrapelock bunny unlock preset_login
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function bunny( $args, $assoc_args ) {
		PNCP_Bunny::cli( $args, $assoc_args );
	}

	/**
	 * 3.12.6: the server rules: print a part exactly as the Server rules tab shows it, check whether the installed
	 * ones are current, or install them into the files you name (test, reload, put back on failure).
	 *
	 * "install" writes <file>.new, shows a unified diff, keeps the current file as <file>.old, puts the new one in
	 * place, runs the test (nginx -t; for a .conf of Apache apachectl -t; for a .htaccess a request of the home
	 * page) and the reload (nginx -s reload, else systemctl reload nginx; apachectl -k graceful), then removes the
	 * .old files and prints the status. When the test or the reload fails, every file is put back from its .old and
	 * the command exits with an error and the test's output. Nothing is guessed: only the files named are written,
	 * Nginx files must end in .conf, Apache files be .htaccess or end in .conf, a symlink must point into its own
	 * folder. An unchanged file is skipped. Only from WP-CLI; never while the site is locked.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : status (default), show or install.
	 *
	 * [--part=<part>]
	 * : For show: nginx-http, nginx-server, stealth-nginx, stealth-apache or apache.
	 *
	 * [--nginx-http=<file>]
	 * : For install: the file of Nginx part 1 (inside http { }).
	 *
	 * [--nginx-server=<file>]
	 * : For install: the file of Nginx part 2 (inside the site's server { }).
	 *
	 * [--stealth=<file>]
	 * : For install: the file of the Stealth rules for Nginx (inside the site's server { }, after part 2).
	 *
	 * [--apache=<file>]
	 * : For install: the .htaccess (only ScrapeLock's block is replaced, or added above # BEGIN WordPress) or a .conf.
	 *
	 * [--stealth-apache=<file>]
	 * : For install: the .htaccess (or .conf) for the Stealth rules for Apache.
	 *
	 * [--dry-run]
	 * : For install: show the diff only; nothing is changed.
	 *
	 * [--test-cmd=<command>]
	 * : For install: the test command instead of the default (e.g. "/www/server/nginx/sbin/nginx -t").
	 *
	 * [--reload-cmd=<command>]
	 * : For install: the reload command instead of the default (e.g. "systemctl reload nginx").
	 *
	 * [--yes]
	 * : For install: do not ask for confirmation.
	 *
	 * [--server=<server>]
	 * : For status: nginx or apache (default: the server the rules were seen on).
	 *
	 * [--format=<format>]
	 * : For status: table (default), json, csv or yaml.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock rules show --part=nginx-http > /etc/nginx/conf.d/scrapelock.conf.new
	 *     wp scrapelock rules status
	 *     wp scrapelock rules status --format=json
	 *     wp scrapelock rules install --nginx-http=/etc/nginx/conf.d/scrapelock.conf --nginx-server=/etc/nginx/snippets/scrapelock-site.conf --dry-run
	 *     wp scrapelock rules install --nginx-http=/www/server/panel/vhost/nginx/0.scrapelock-example_com.conf --nginx-server=/www/server/panel/vhost/nginx/extension/example.com/scrapelock.conf --stealth=/www/server/panel/vhost/nginx/extension/example.com/z-scrapelock-stealth.conf --yes
	 *     wp scrapelock rules install --apache=/var/www/html/.htaccess
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function rules( $args, $assoc_args ) {
		PNCP_Cli_Server::rules( $args, $assoc_args );
	}

	/**
	 * 3.12.6: purges addresses of this site (or the whole cache) at the CDN, with the plugin's stored credentials:
	 * the Bunny CDN pull zone and / or the Cloudflare zone. Only addresses on this site's own hosts; the keys are
	 * never printed. Bunny's and Cloudflare's rate limits are respected as for the other calls.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : purge
	 * ---
	 * options:
	 *   - purge
	 * ---
	 *
	 * [<url>...]
	 * : Addresses of this site, or paths such as /builtwith.txt (on the home address).
	 *
	 * [--all]
	 * : Purge the whole cache instead.
	 *
	 * [--yes]
	 * : With --all: do not ask for confirmation.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock cdn purge https://example.com/builtwith.txt
	 *     wp scrapelock cdn purge /builtwith.txt /robots.txt
	 *     wp scrapelock cdn purge --all --yes
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function cdn( $args, $assoc_args ) {
		PNCP_Cli_Server::cdn( $args, $assoc_args );
	}

	/**
	 * 3.12: Traffic: the sources, the figures, the requests, a CSV export, delete, run the job, test a log path.
	 *
	 * ## OPTIONS
	 *
	 * [<subcommand>]
	 * : status (default), overview, top <dimension>, problems <type>, raw, export <file>, purge, run or test-path <path>.
	 *
	 * [<arg>]
	 * : For top: ua, ua_family, path, referer, ip, country or status. For problems: 404, 5xx, 3xx, uncached, large or slow. For export: the CSV file ("-" = standard output). For test-path: the access log.
	 *
	 * [--from=<when>]
	 * : Start: 24h, 7d, 30m (that long ago), 2026-11-01, "2026-11-01 13:00" or a Unix time. Default: 24 hours ago.
	 *
	 * [--to=<when>]
	 * : End, in the same forms (a date = its end). Default: now.
	 *
	 * [--src=<source>]
	 * : auto (default), bunny, server or wp.
	 *
	 * [--status=<status>]
	 * : A status code such as 404, or 4xx / 5xx.
	 *
	 * [--ua=<user-agent>]
	 * : One User-Agent, exactly.
	 *
	 * [--family=<family>]
	 * : browser, verified_bot, fake_bot, ai_bot, seo_bot, preview, service, script, empty or other.
	 *
	 * [--page=<path>]
	 * : One path, exactly, e.g. /shop/. (--path is WP-CLI's own option, which chooses the WordPress folder.)
	 *
	 * [--path-like=<text>]
	 * : Part of the path.
	 *
	 * [--ip=<ip>]
	 * : One IP.
	 *
	 * [--country=<cc>]
	 * : Two-letter country code.
	 *
	 * [--cache=<cache>]
	 * : HIT or MISS.
	 *
	 * [--search=<text>]
	 * : Part of the path or of the User-Agent.
	 *
	 * [--order=<order>]
	 * : For top: hits, ips, bytes, s4xx, s5xx, misses, last or first.
	 *
	 * [--limit=<rows>]
	 * : Rows, 1-500 (top and problems: 20, raw: 50).
	 *
	 * [--offset=<rows>]
	 * : Rows to skip.
	 *
	 * [--series]
	 * : For overview: the requests per hour (or per day) instead of the totals.
	 *
	 * [--force]
	 * : For export: replace an existing file.
	 *
	 * [--yes]
	 * : For purge: confirm.
	 *
	 * [--format=<format>]
	 * : table (default), json, csv or yaml.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock traffic status
	 *     wp scrapelock traffic overview --from=7d
	 *     wp scrapelock traffic top ua --from=24h --family=ai_bot
	 *     wp scrapelock traffic problems 404 --from=2026-11-01 --to=2026-11-07
	 *     wp scrapelock traffic raw --status=5xx --limit=20 --format=json
	 *     wp scrapelock traffic export traffic.csv --from=3d --force
	 *     wp scrapelock traffic purge --yes
	 *     wp scrapelock traffic test-path /var/log/nginx/access.log
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function traffic( $args, $assoc_args ) {
		PNCP_Traffic_Cli::cli( $args, $assoc_args );
	}

	/**
	 * 3.8: Stealth (do not show that the site runs on WordPress): status, on, off, test, scan, rules.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : status (default), on, off, test, scan or rules.
	 *
	 * [--base=<folder>]
	 * : For on: the folder of the new addresses (default assets).
	 *
	 * [--rest=<prefix>]
	 * : For on: the REST API prefix instead of wp-json ("" keeps wp-json).
	 *
	 * [--page=<url>]
	 * : For scan: the page of this site to scan (default: the home page). (--url is WP-CLI's own option, which
	 * chooses the site.)
	 *
	 * [--server=<server>]
	 * : For rules: apache or nginx (default: the server last seen in wp-admin).
	 *
	 * [--format=<format>]
	 * : For status and scan: table, json, csv or yaml.
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock stealth status
	 *     wp scrapelock stealth on --base=static --rest=api
	 *     wp scrapelock stealth rules --server=nginx
	 *     wp scrapelock stealth scan --page=https://example.com/blog/
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function stealth( $args, $assoc_args ) {
		$action = isset( $args[0] ) ? (string) $args[0] : 'status';
		$done   = static function ( $result, $text ) {
			if ( is_wp_error( $result ) ) {
				WP_CLI::error( $result->get_error_message() );
			}
			WP_CLI::success( $text );
		};
		switch ( $action ) {
			case 'status':
				$items = array();
				foreach ( PNCP_Stealth::cli_status() as $key => $value ) {
					$items[] = array(
						'setting' => $key,
						'value'   => $value,
					);
				}
				WP_CLI\Utils\format_items( self::format( $assoc_args ), $items, array( 'setting', 'value' ) );
				return;
			case 'on':
				$done( PNCP_Stealth::cli_enable( array_intersect_key( $assoc_args, array_flip( array( 'base', 'rest' ) ) ) ), __( 'Stealth is on: the new addresses were tested.', 'scrapelock' ) );
				return;
			case 'off':
				$done( PNCP_Stealth::cli_disable(), __( 'Stealth is off.', 'scrapelock' ) );
				return;
			case 'test':
				$done( PNCP_Stealth::cli_test(), __( 'The new addresses work.', 'scrapelock' ) );
				return;
			case 'scan':
				$rows = PNCP_Stealth::cli_scan( isset( $assoc_args['page'] ) ? esc_url_raw( (string) $assoc_args['page'] ) : '' );
				WP_CLI\Utils\format_items( self::format( $assoc_args ), $rows, array( 'sign', 'pages', 'hideable', 'found' ) );
				return;
			case 'rules':
				$server = isset( $assoc_args['server'] ) ? sanitize_key( (string) $assoc_args['server'] ) : PNCP_Stealth::server();
				WP_CLI::line( PNCP_Stealth::rules_text( $server ) );
				return;
		}
		WP_CLI::error( __( 'Unknown action. Use: status, on, off, test, scan or rules.', 'scrapelock' ) );
	}

	/**
	 * 3.7: visits from AI assistants (ChatGPT, Perplexity, Claude, Gemini…): per assistant, or the pages they
	 * sent readers to.
	 *
	 * ## OPTIONS
	 *
	 * [--days=<days>]
	 * : How many days back, 1 to 90.
	 * ---
	 * default: 30
	 * ---
	 *
	 * [--pages]
	 * : List the pages instead of the assistants.
	 *
	 * [--format=<format>]
	 * : table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock ai-referrals
	 *     wp scrapelock ai-referrals --pages --days=7
	 *
	 * @subcommand ai-referrals
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function ai_referrals( $args, $assoc_args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed -- WP-CLI signature.
		$days      = max( 1, min( PNCP_Ai_Referrals::KEEP_DAYS, isset( $assoc_args['days'] ) ? (int) $assoc_args['days'] : 30 ) );
		$platforms = PNCP_Ai_Referrals::platforms();
		$items     = array();
		if ( ! empty( $assoc_args['pages'] ) ) {
			foreach ( PNCP_Ai_Referrals::top_pages( $days, 50 ) as $row ) {
				$items[] = array(
					'page'   => PNCP_Log::display_path( $row['path'] ),
					'visits' => $row['visits'],
					'from'   => $row['platforms'],
				);
			}
			WP_CLI\Utils\format_items( self::format( $assoc_args ), $items, array( 'page', 'visits', 'from' ) );
			return;
		}
		foreach ( PNCP_Ai_Referrals::totals( $days ) as $key => $visits ) {
			$items[] = array(
				'assistant' => isset( $platforms[ $key ]['name'] ) ? $platforms[ $key ]['name'] : $key,
				'visits'    => $visits,
			);
		}
		WP_CLI\Utils\format_items( self::format( $assoc_args ), $items, array( 'assistant', 'visits' ) );
	}

	/**
	 * 3.11: "For my site": what the assistant found (plugins, CDN, server) and the settings it proposes, as on the
	 * first tab of the settings page. Nothing changes without --apply; the settings as they are now are saved
	 * first ("wp scrapelock settings undo" puts them back).
	 *
	 * ## OPTIONS
	 *
	 * [--apply]
	 * : Apply the proposals that block nothing more (the ones ticked by default on the settings page).
	 *
	 * [--all]
	 * : With --apply: also the proposals that block more (marked "more").
	 *
	 * [--only=<settings>]
	 * : With --apply: only these proposals, comma-separated setting names (e.g. trust_bunny,content_paths).
	 *
	 * [--yes]
	 * : Do not ask for confirmation.
	 *
	 * [--format=<format>]
	 * : table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp scrapelock wizard
	 *     wp scrapelock wizard --apply --yes
	 *     wp scrapelock wizard --apply --only=precheck
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public function wizard( $args, $assoc_args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed -- WP-CLI signature.
		$format    = self::format( $assoc_args );
		$env       = PNCP_Wizard::detect();
		$proposals = PNCP_Wizard::proposals( null, $env );
		$items     = array();
		foreach ( $proposals as $key => $row ) {
			$texts         = PNCP_Wizard::row_texts( $row ); // 3.12.1: a row may change two settings (ban_strikes, ban_minutes).
			$items[ $key ] = array(
				'setting'  => $key,
				'now'      => $texts[0],
				'proposed' => $texts[1],
				'risk'     => $row['risk'],
				'reason'   => $row['reason'],
			);
		}
		if ( empty( $assoc_args['apply'] ) ) {
			if ( 'table' === $format ) {
				$found = PNCP_Wizard::detected_names( $env );
				/* translators: %s: list of plugins and services */
				WP_CLI::line( sprintf( __( 'Found on this site: %s', 'scrapelock' ), $found ? implode( ', ', $found ) : '-' ) );
				if ( ! $items ) {
					WP_CLI::success( __( 'Nothing to change: the settings already suit what was found.', 'scrapelock' ) );
				} else {
					WP_CLI\Utils\format_items( 'table', array_values( $items ), array( 'setting', 'now', 'proposed', 'risk', 'reason' ) );
				}
				foreach ( PNCP_Wizard::notes( null, $env ) as $note ) {
					WP_CLI::line( '- ' . $note['for'] . ': ' . $note['text'] );
				}
				return;
			}
			WP_CLI\Utils\format_items( $format, array_values( $items ), array( 'setting', 'now', 'proposed', 'risk', 'reason' ) );
			return;
		}
		if ( PNCP_Lockdown::is_locked() ) {
			WP_CLI::error( __( 'The site is locked: the settings cannot be changed until it is unlocked (with the authenticator app).', 'scrapelock' ) );
		}
		$keys = array();
		if ( ! empty( $assoc_args['only'] ) ) {
			foreach ( array_filter( array_map( 'trim', explode( ',', (string) $assoc_args['only'] ) ) ) as $key ) {
				if ( ! isset( $proposals[ $key ] ) ) {
					/* translators: %s: setting name */
					WP_CLI::error( sprintf( __( '"%s" is not one of the proposals.', 'scrapelock' ), $key ) );
				}
				$keys[] = $key;
			}
		} else {
			foreach ( $proposals as $key => $row ) {
				if ( ! empty( $assoc_args['all'] ) || PNCP_Wizard::RISK_NONE === $row['risk'] ) {
					$keys[] = $key;
				}
			}
		}
		if ( ! $keys ) {
			WP_CLI::success( __( 'Nothing to change: the settings already suit what was found.', 'scrapelock' ) );
			return;
		}
		WP_CLI\Utils\format_items( 'table', array_values( array_intersect_key( $items, array_flip( $keys ) ) ), array( 'setting', 'now', 'proposed', 'risk', 'reason' ) );
		if ( empty( $assoc_args['yes'] ) ) {
			/* translators: %d: number of settings */
			WP_CLI::confirm( sprintf( _n( 'Change this %d setting?', 'Change these %d settings?', count( $keys ), 'scrapelock' ), count( $keys ) ) );
		}
		$result = PNCP_Wizard::apply( $keys, $env );
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		foreach ( $result['messages'] as $message ) {
			WP_CLI::warning( wp_strip_all_tags( $message['message'] ) );
		}
		if ( '' === $result['id'] ) {
			WP_CLI::warning( __( 'Nothing was changed.', 'scrapelock' ) );
			return;
		}
		/* translators: %d: number of settings */
		WP_CLI::success( sprintf( _n( '%d setting changed. The previous settings were kept: "wp scrapelock settings undo" puts them back.', '%d settings changed. The previous settings were kept: "wp scrapelock settings undo" puts them back.', count( $result['changes'] ), 'scrapelock' ), count( $result['changes'] ) ) );
	}

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
