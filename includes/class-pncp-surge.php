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

	const STATE = 'pncp_surge';
	const LAST  = 'pncp_surge_last';

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
			self::trigger( (int) $prev, self::threshold( $closed, $s ) );
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
		PNCP_Options::set_emergency( $hours );
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
		$to = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
		if ( is_email( $to ) ) {
			wp_mail(
				$to,
				'[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] ScrapeLock: ' . __( 'Emergency Mode started automatically', 'scrapelock' ),
				sprintf(
					/* translators: 1: pages per minute, 2: threshold, 3: minutes in a row, 4: hours */
					__( 'The site received %1$d pages per minute, above the %2$d that count as an attack, for %3$d minutes in a row. ScrapeLock started Emergency Mode for %4$d hour(s): stricter limits and checks for everyone except verified search engines and exempt staff. It ends by itself; you can end it sooner from the ScrapeLock page.', 'scrapelock' ),
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
