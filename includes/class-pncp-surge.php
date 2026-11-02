<?php
/**
 * Automatic Emergency Mode: the per-IP limits cannot see a scraper that spreads its requests over hundreds of IPs
 * (each one stays under the limit). The whole site can: pages per minute jump far above what the site usually
 * gets. ScrapeLock learns the usual rate and starts Emergency Mode on its own when it is exceeded for a few
 * minutes in a row.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Site-wide pages per minute, the usual rate, and the automatic start of Emergency Mode.
 */
final class PNCP_Surge {

	const STATE      = 'pncp_surge';
	const LAST       = 'pncp_surge_last';
	const MAIL       = 'pncp_surge_mail';
	const ALERT      = 'pncp_surge_alert';
	const MAIL_ALERT = 'pncp_surge_mail_alert';

	/**
	 * How long an alert ("notify" mode) is shown in wp-admin, and how long after one no new alert is sent while
	 * the surge goes on (one email per hour at most, not one per minute).
	 */
	const ALERT_HOURS = 6;
	const ALERT_QUIET = HOUR_IN_SECONDS;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( self::MAIL, array( __CLASS__, 'mail' ), 10, 3 );
		add_action( self::MAIL_ALERT, array( __CLASS__, 'mail_alert' ), 10, 2 );
	}

	/**
	 * How many times the usual rate counts as an attack, and for how many minutes in a row.
	 */
	const FACTOR  = 5;
	const MINUTES = 3;

	/**
	 * Weight of each new minute in the usual rate (about a 2-hour memory), and how many minutes are needed
	 * before it is trusted: until then only the minimum applies.
	 */
	const ALPHA  = 0.005;
	const WARMUP = 60;

	/**
	 * Called by the normal check with this minute's count, for every page request that counts (not verified
	 * search engines, not exempt staff). The first request of a minute closes the previous one.
	 *
	 * @param int                  $count  Pages in this minute so far, this one included.
	 * @param int                  $minute This minute (Unix time / 60).
	 * @param int                  $prev   Pages in the previous minute.
	 * @param array<string, mixed> $s      Settings.
	 */
	public static function observe( $count, $minute, $prev, $s ) {
		if ( 1 !== (int) $count ) {
			return;
		}
		$state = self::state();
		if ( $state['minute'] >= $minute - 1 ) {
			return; // Already closed by another request.
		}
		$closed = self::close( $state, $minute - 1, (int) $prev, $s );
		self::save( $closed );
		if ( $closed['streak'] >= (int) apply_filters( 'pncp_auto_emergency_minutes', self::MINUTES ) && ! empty( $s['auto_emergency'] ) && ! PNCP_Options::emergency_until() ) {
			if ( isset( $s['auto_emergency_mode'] ) && 'start' === $s['auto_emergency_mode'] ) {
				self::trigger( (int) $prev, self::threshold( $closed, $s ) );
			} else {
				self::alert( (int) $prev, self::threshold( $closed, $s ) );
			}
		}
	}

	/**
	 * Closes a minute: the streak of minutes above the threshold and the usual rate. Minutes without any request
	 * in between count as quiet ones. While Emergency Mode is on, the usual rate does not learn from the attack.
	 *
	 * @param array{minute:int, avg:float, samples:int, streak:int} $state  State.
	 * @param int                                                    $minute The minute being closed.
	 * @param int                                                    $count  Its pages.
	 * @param array<string, mixed>                                   $s      Settings.
	 * @return array{minute:int, avg:float, samples:int, streak:int}
	 */
	public static function close( $state, $minute, $count, $s ) {
		$alpha = self::ALPHA;
		$gap   = $state['minute'] > 0 ? max( 0, $minute - $state['minute'] - 1 ) : 0;
		if ( $gap ) {
			$state['avg']     *= pow( 1 - $alpha, min( $gap, 100000 ) );
			$state['samples'] += min( $gap, 100000 );
			$state['streak']   = 0;
		}
		$over            = $count >= self::threshold( $state, $s );
		$state['streak'] = $over ? $state['streak'] + 1 : 0;
		if ( ! PNCP_Options::emergency_until() ) {
			// A slow climb cannot teach it that an attack is normal: one minute moves the average at most a little.
			$learn            = min( (float) $count, 2 * $state['avg'] + 10 );
			$state['avg']     = $state['samples'] ? ( 1 - $alpha ) * $state['avg'] + $alpha * $learn : (float) $count;
			$state['samples'] = $state['samples'] + 1;
		}
		$state['minute'] = $minute;
		return $state;
	}

	/**
	 * Pages per minute that count as an attack: five times the usual rate, never below the minimum setting. Before
	 * the usual rate is known (the first hour), the minimum alone.
	 *
	 * @param array{minute:int, avg:float, samples:int, streak:int} $state State.
	 * @param array<string, mixed>                                   $s     Settings.
	 * @return int
	 */
	public static function threshold( $state, $s ) {
		$min = max( 1, (int) $s['auto_emergency_min'] );
		if ( $state['samples'] < self::WARMUP ) {
			return $min;
		}
		return max( $min, (int) ceil( (float) apply_filters( 'pncp_auto_emergency_factor', self::FACTOR ) * $state['avg'] ) );
	}

	/**
	 * Starts Emergency Mode, remembers why and emails the administration address.
	 *
	 * @param int $count     Pages in the last minute.
	 * @param int $threshold The threshold it crossed.
	 */
	private static function trigger( $count, $threshold ) {
		$hours = max( 1, min( 72, (int) apply_filters( 'pncp_auto_emergency_hours', 1 ) ) );
		// This runs inside a visitor's request, at the peak of the traffic. The page cache is NOT emptied: that
		// would send every visitor to PHP and the database at once (a cache stampede) exactly when the site is
		// under the most load. Cached pages are cheap to serve; the stricter checks apply to every request
		// that reaches PHP, and the early / pre-cache checks to the rest.
		PNCP_Options::set_emergency( $hours, false );
		$last = get_option( self::LAST, array() );
		$last = is_array( $last ) ? $last : array();
		array_unshift(
			$last,
			array(
				'time'      => time(),
				'count'     => $count,
				'threshold' => $threshold,
				'hours'     => $hours,
			)
		);
		update_option( self::LAST, array_slice( $last, 0, 10 ), false );
		// The email is sent from a scheduled event, not by the visitor whose request crossed the threshold.
		wp_schedule_single_event( time(), self::MAIL, array( $count, $threshold, $hours ) );
		// Started right away, in its own background request (a loopback to wp-cron.php that this request does
		// not wait for), also on sites where DISABLE_WP_CRON turned off the automatic start.
		if ( function_exists( 'spawn_cron' ) ) {
			spawn_cron();
		}
	}

	/**
	 * "Notify" mode: Emergency Mode is NOT started. The surge is remembered for the notice in wp-admin (with a
	 * one-click "Start Emergency Mode" button) and the administration address gets an email, at most once an
	 * hour while it goes on. A rush of real visitors looks the same as an attack from here; a person decides.
	 *
	 * @param int $count     Pages in the last minute.
	 * @param int $threshold The threshold it crossed.
	 */
	private static function alert( $count, $threshold ) {
		// The time of the last alert, or of its dismissal (also by starting Emergency Mode), as stored: a surge
		// that goes on brings no new notice and email for an hour after either.
		$alert = get_option( self::ALERT, array() );
		$last  = is_array( $alert ) ? max( isset( $alert['time'] ) ? (int) $alert['time'] : 0, isset( $alert['dismissed'] ) ? (int) $alert['dismissed'] : 0 ) : 0;
		if ( $last > time() - self::ALERT_QUIET ) {
			return; // Already told: no email every minute while the surge goes on.
		}
		update_option(
			self::ALERT,
			array(
				'time'      => time(),
				'count'     => $count,
				'threshold' => $threshold,
			),
			false
		);
		// Sent from a scheduled event in a background request, not by the visitor whose request crossed it.
		wp_schedule_single_event( time(), self::MAIL_ALERT, array( $count, $threshold ) );
		if ( function_exists( 'spawn_cron' ) ) {
			spawn_cron();
		}
	}

	/**
	 * The surge alert still shown in wp-admin ("notify" mode), or null: none, older than ALERT_HOURS, or
	 * already answered (Emergency Mode started, or the notice dismissed).
	 *
	 * @return array{time:int, count:int, threshold:int}|null
	 */
	public static function alert_state() {
		$alert = get_option( self::ALERT, array() );
		if ( ! is_array( $alert ) || empty( $alert['time'] ) || ! empty( $alert['dismissed'] ) || (int) $alert['time'] < time() - self::ALERT_HOURS * HOUR_IN_SECONDS ) {
			return null;
		}
		return array(
			'time'      => (int) $alert['time'],
			'count'     => isset( $alert['count'] ) ? (int) $alert['count'] : 0,
			'threshold' => isset( $alert['threshold'] ) ? (int) $alert['threshold'] : 0,
		);
	}

	/**
	 * Forgets the alert (Emergency Mode was started, or the administrator dismissed the notice).
	 */
	public static function clear_alert() {
		// 3.4: kept with the time it was dismissed rather than deleted, so a quiet hour follows the dismissal
		// too (alert()). Before, dismissing the notice during a surge that went on brought it back, with a new
		// email, a minute later.
		$alert = get_option( self::ALERT, array() );
		if ( ! is_array( $alert ) || empty( $alert['time'] ) ) {
			delete_option( self::ALERT );
			return;
		}
		if ( empty( $alert['dismissed'] ) ) {
			$alert['dismissed'] = time();
			update_option( self::ALERT, $alert, false );
		}
	}

	/**
	 * Emails the administration address about a surge in "notify" mode (scheduled by alert()).
	 *
	 * @param int $count     Pages in the last minute.
	 * @param int $threshold The threshold it crossed.
	 */
	public static function mail_alert( $count, $threshold ) {
		$to = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
		if ( ! is_email( $to ) ) {
			return;
		}
		$body = sprintf(
			/* translators: 1: pages per minute, 2: threshold, 3: minutes in a row */
			__( 'The site received %1$d pages per minute, above the %2$d that count as an attack, for %3$d minutes in a row. This can be a scraping attack spread over many IP addresses, or many real visitors at once (a newsletter, a link on a popular site). ScrapeLock has NOT changed anything.', 'scrapelock' ),
			(int) $count,
			(int) $threshold,
			(int) apply_filters( 'pncp_auto_emergency_minutes', self::MINUTES )
		);
		$body .= "\n\n" . __( 'If it is an attack, open the ScrapeLock page and click “Start Emergency Mode”. It changes, until it ends:', 'scrapelock' );
		foreach ( PNCP_Options::emergency_changes( PNCP_Options::stored() ) as $line ) {
			$body .= "\n- " . $line;
		}
		$body .= "\n\n" . PNCP_Status::settings_url();
		wp_mail(
			$to,
			/* translators: %s: site name */
			sprintf( __( '[%s] ScrapeLock: unusual traffic, start Emergency Mode?', 'scrapelock' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			$body
		);
	}

	/**
	 * Emails the administration address that Emergency Mode started (scheduled by trigger()).
	 *
	 * @param int $count     Pages in the last minute.
	 * @param int $threshold The threshold it crossed.
	 * @param int $hours     Hours.
	 */
	public static function mail( $count, $threshold, $hours ) {
		$count     = (int) $count;
		$threshold = (int) $threshold;
		$hours     = (int) $hours;
		$to        = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
		if ( is_email( $to ) ) {
			wp_mail(
				$to,
				/* translators: %s: site name */
				sprintf( __( '[%s] ScrapeLock: Emergency Mode started automatically', 'scrapelock' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
				sprintf(
					/* translators: 1: pages per minute, 2: threshold, 3: minutes in a row, 4: number of hours */
					_n(
						'The site received %1$d pages per minute, above the %2$d that count as an attack, for %3$d minutes in a row. ScrapeLock started Emergency Mode for %4$d hour: stricter limits and checks for everyone except verified search engines and exempt staff. It ends by itself; you can end it sooner from the ScrapeLock page.',
						'The site received %1$d pages per minute, above the %2$d that count as an attack, for %3$d minutes in a row. ScrapeLock started Emergency Mode for %4$d hours: stricter limits and checks for everyone except verified search engines and exempt staff. It ends by itself; you can end it sooner from the ScrapeLock page.',
						$hours,
						'scrapelock'
					),
					$count,
					$threshold,
					(int) apply_filters( 'pncp_auto_emergency_minutes', self::MINUTES ),
					$hours
				) . "\n\n" . PNCP_Status::settings_url()
			);
		}
	}

	/**
	 * The stored state.
	 *
	 * @return array{minute:int, avg:float, samples:int, streak:int}
	 */
	public static function state() {
		$state = get_option( self::STATE, array() );
		$state = is_array( $state ) ? $state : array();
		return array(
			'minute'  => isset( $state['minute'] ) ? (int) $state['minute'] : 0,
			'avg'     => isset( $state['avg'] ) ? (float) $state['avg'] : 0.0,
			'samples' => isset( $state['samples'] ) ? (int) $state['samples'] : 0,
			'streak'  => isset( $state['streak'] ) ? (int) $state['streak'] : 0,
		);
	}

	/**
	 * Saves the state (autoloaded: it is read once a minute, by the first request of the minute).
	 *
	 * @param array{minute:int, avg:float, samples:int, streak:int} $state State.
	 */
	private static function save( $state ) {
		update_option( self::STATE, $state, true );
	}

	/**
	 * The last automatic starts, newest first.
	 *
	 * @return array<int, array{time:int, count:int, threshold:int, hours:int}>
	 */
	public static function last() {
		$last = get_option( self::LAST, array() );
		return is_array( $last ) ? $last : array();
	}
}
