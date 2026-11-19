<?php
/**
 * 3.7: the reputation of each IP, built from what it did on this site and fading with time.
 *
 * Every IP (IPv6: its /64, like the limits) gets a small record: for each kind of event, when it last happened.
 * Good events raise the score (someone signed in from it, it passed the human check, it reads pages), bad ones
 * lower it (the bot trap, a scanner probe, a fake crawler, an attack in the User-Agent, limits exceeded, a
 * temporary block). Recent events weigh more than old ones, and after 7 days an event is forgotten.
 *
 * The score is used in two places, both optional:
 * - An IP with a good reputation (at least GOOD) is never blocked temporarily for exceeding a limit: it still
 *   gets the 429 answers, but no violation. Offices, schools and mobile networks share one address, and one
 *   member who scrolls fast should not lock everybody out. The trap, scanner probes and the bot list still
 *   block it as usual.
 * - An IP with a bad reputation (at most BAD) gets the stricter page limit "rate_limit_lowrep": an IP that was
 *   blocked comes back slower, for days, instead of starting again from zero when the block ends.
 *
 * The same records tell "rate_limit_apionly" whether an IP ever opened a page (PNCP_Reputation::seen_page()).
 *
 * Stored like the per-minute counters (PNCP_Log::cache_get(): object cache, APCu or the plugin's table), one
 * read per request and a write only when something new happened (a page view is noted at most every 30 minutes).
 * Two requests of the same IP at the same moment may each keep only their own event; that loses an event, never
 * invents one. No personal data beyond what the block log already keeps: the key is a hash of the IP.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * IP reputation.
 */
final class PNCP_Reputation {

	/**
	 * At or above this score: never blocked temporarily for a limit (filter `pncp_reputation_good`). Signed in
	 * (80) and passed the human check (60) is enough; a human check alone is not, since a headless browser can
	 * pass it too.
	 */
	const GOOD = 100;

	/**
	 * At or below this score: the stricter page limit (filter `pncp_reputation_bad`). One temporary block, or one
	 * request from the bot list or with an attack in its User-Agent, is enough.
	 */
	const BAD = -40;

	/**
	 * Events older than this are forgotten, and the record expires.
	 */
	const KEEP = WEEK_IN_SECONDS;

	/**
	 * Records read in this PHP request: IP key => record.
	 *
	 * @var array<string, array<string, int>>
	 */
	private static $memo = array();

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 10, 2 );
	}

	/**
	 * Is anything using the records? The reputation itself, or the limit for IPs that never opened a page.
	 *
	 * @param array<string, mixed>|null $s Settings.
	 * @return bool
	 */
	public static function active( $s = null ) {
		$s = null === $s ? PNCP_Options::get() : $s;
		return ! empty( $s['enabled'] ) && ( ! empty( $s['reputation'] ) || (int) $s['rate_limit_apionly'] > 0 );
	}

	/**
	 * The kinds of events and what they are worth: [ seconds, value while that recent, value after ].
	 * Filter `pncp_reputation_weights`.
	 *
	 * @return array<string, array{0:int, 1:int, 2:int}>
	 */
	public static function weights() {
		return (array) apply_filters(
			'pncp_reputation_weights',
			array(
				// Good.
				'login'  => array( DAY_IN_SECONDS, 80, 40 ),  // Someone signed in from this IP.
				'human'  => array( DAY_IN_SECONDS, 60, 30 ),  // Passed the human check.
				'page'   => array( HOUR_IN_SECONDS, 10, 5 ),  // Reads pages of the site (not only the API).
				// Bad.
				'trap'   => array( DAY_IN_SECONDS, -100, -60 ), // Opened the bot trap.
				'probe'  => array( DAY_IN_SECONDS, -80, -40 ),  // Asked for .env, .git or backups.
				'attack' => array( DAY_IN_SECONDS, -80, -40 ),  // An attack in the User-Agent, the site opened by IP.
				'fake'   => array( DAY_IN_SECONDS, -70, -40 ),  // A fake search engine or AI search bot.
				'ban'    => array( DAY_IN_SECONDS, -60, -30 ),  // Was blocked temporarily.
				'bot'    => array( DAY_IN_SECONDS, -40, -20 ),  // Bot list, no browser headers or headless.
				'limit'  => array( HOUR_IN_SECONDS, -20, -10 ), // Exceeded a limit.
				'r404'   => array( HOUR_IN_SECONDS, -15, -5 ),  // Exceeded the "page not found" limit.
			)
		);
	}

	/**
	 * The event a log reason stands for ('' = none).
	 *
	 * @param string $reason Key of PNCP_Log::reasons().
	 * @return string
	 */
	public static function event_of( $reason ) {
		$reason = (string) $reason;
		$map    = array(
			'trap'         => 'trap',
			'probe'        => 'probe',
			'bad_ua'       => 'attack',
			'host_ip'      => 'attack',
			'fake_crawler' => 'fake',
			'fake_ai_bot'  => 'fake',
			'bot_ua'       => 'bot',
			'empty_ua'     => 'bot',
			'no_browser'   => 'bot',
			'headless'     => 'bot',
			'fake_browser' => 'bot',
			'blocked_ref'  => 'bot',
			'rate_404'     => 'r404',
		);
		if ( isset( $map[ $reason ] ) ) {
			return $map[ $reason ];
		}
		// Every other limit, except the ones that do not say anything about this one IP: shared counters of a
		// network or an account, prefetches, and the reputation's own limit (it would feed itself).
		if ( 0 === strpos( $reason, 'rate_' ) && ! in_array( $reason, array( 'rate_page56', 'rate_account', 'rate_prefetch', 'rate_lowrep' ), true ) ) {
			return 'limit';
		}
		return '';
	}

	/**
	 * Notes an event of an IP.
	 *
	 * @param string $ip    IP.
	 * @param string $event Key of weights().
	 */
	public static function record( $ip, $event ) {
		if ( '' === (string) $ip || ! self::active() || PNCP_Bots::explaining() || ! PNCP_Ip::reliable() || PNCP_Ip::is_cdn_edge( (string) $ip ) ) {
			return;
		}
		$weights = self::weights();
		if ( ! isset( $weights[ $event ] ) ) {
			return;
		}
		$record = self::get( $ip );
		$now    = time();
		// A page view is noted at most every 30 minutes, any other event at most once a minute: the record is
		// written only when something changes that matters for the score.
		$every = 'page' === $event ? 30 * MINUTE_IN_SECONDS : MINUTE_IN_SECONDS;
		if ( isset( $record[ $event ] ) && $now - (int) $record[ $event ] < $every ) {
			return;
		}
		$record[ $event ] = $now;
		foreach ( $record as $key => $when ) {
			if ( ! isset( $weights[ $key ] ) || $now - (int) $when > self::KEEP ) {
				unset( $record[ $key ] );
			}
		}
		$key                = PNCP_Ip::limit_key( $ip );
		self::$memo[ $key ] = $record;
		PNCP_Log::cache_set( self::cache_key( $key ), $record, self::KEEP );
	}

	/**
	 * Notes the event of a refused request, by its log reason.
	 *
	 * @param string $ip     IP.
	 * @param string $reason Reason.
	 */
	public static function record_reason( $ip, $reason ) {
		$event = self::event_of( $reason );
		if ( '' !== $event ) {
			self::record( $ip, $event );
		}
	}

	/**
	 * A temporary block: the block itself, and the trap or the probe that caused it.
	 *
	 * @param string $ip     IP.
	 * @param string $reason Reason of the block.
	 */
	public static function on_ban( $ip, $reason ) {
		if ( in_array( $reason, array( 'trap', 'probe' ), true ) ) {
			self::record( $ip, $reason );
		}
		self::record( $ip, 'ban' );
	}

	/**
	 * Someone signed in: a person with an account is behind this IP.
	 *
	 * @param string       $login User name.
	 * @param WP_User|null $user  User.
	 */
	public static function on_login( $login, $user = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter -- Hook signature.
		self::record( PNCP_Ip::client_ip(), 'login' );
	}

	/**
	 * The record of an IP: event => when it last happened.
	 *
	 * @param string $ip IP.
	 * @return array<string, int>
	 */
	public static function get( $ip ) {
		$key = PNCP_Ip::limit_key( (string) $ip );
		if ( '' === $key ) {
			return array();
		}
		if ( ! isset( self::$memo[ $key ] ) ) {
			$stored             = PNCP_Log::cache_get( self::cache_key( $key ) );
			self::$memo[ $key ] = is_array( $stored ) ? array_map( 'intval', $stored ) : array();
		}
		return self::$memo[ $key ];
	}

	/**
	 * The score of an IP: the sum of its events, each worth its recent or its older value.
	 *
	 * @param string $ip IP.
	 * @return int
	 */
	public static function score( $ip ) {
		return self::score_of( self::get( $ip ) );
	}

	/**
	 * The score of a record.
	 *
	 * @param array<string, int> $record Record.
	 * @param int|null           $now    Time (null = now).
	 * @return int
	 */
	public static function score_of( $record, $now = null ) {
		$now     = null === $now ? time() : (int) $now;
		$weights = self::weights();
		$score   = 0;
		foreach ( (array) $record as $event => $when ) {
			if ( ! isset( $weights[ $event ] ) ) {
				continue;
			}
			$age = $now - (int) $when;
			if ( $age < 0 || $age > self::KEEP ) {
				continue;
			}
			$score += $age <= (int) $weights[ $event ][0] ? (int) $weights[ $event ][1] : (int) $weights[ $event ][2];
		}
		return $score;
	}

	/**
	 * Good enough to never get a temporary block for a limit?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function trusted( $ip ) {
		$s = PNCP_Options::get();
		return ! empty( $s['reputation'] ) && ! empty( $s['enabled'] ) && self::score( $ip ) >= (int) apply_filters( 'pncp_reputation_good', self::GOOD );
	}

	/**
	 * Bad enough for the stricter page limit?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function suspect( $ip ) {
		$s = PNCP_Options::get();
		return ! empty( $s['reputation'] ) && ! empty( $s['enabled'] ) && self::score( $ip ) <= (int) apply_filters( 'pncp_reputation_bad', self::BAD );
	}

	/**
	 * Did this IP open a page of the site (or pass the human check, or sign in) in the last 24 hours? For the
	 * limit on IPs that only read the API, the feeds and the sitemaps.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function seen_page( $ip ) {
		$record = self::get( $ip );
		$since  = time() - DAY_IN_SECONDS;
		foreach ( array( 'page', 'human', 'login' ) as $event ) {
			if ( isset( $record[ $event ] ) && (int) $record[ $event ] >= $since ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Forgets an IP's record (unblocking it by hand, "wp scrapelock reputation --reset").
	 *
	 * @param string $ip IP.
	 */
	public static function forget( $ip ) {
		$key = PNCP_Ip::limit_key( (string) $ip );
		unset( self::$memo[ $key ] );
		PNCP_Log::cache_delete( self::cache_key( $key ) );
	}

	/**
	 * A readable summary of an IP's reputation (CLI, "Check a request").
	 *
	 * @param string $ip IP.
	 * @return array{score:int, level:string, events:array<string, int>}
	 */
	public static function describe( $ip ) {
		$record = self::get( $ip );
		$score  = self::score_of( $record );
		$level  = 'neutral';
		if ( $score >= (int) apply_filters( 'pncp_reputation_good', self::GOOD ) ) {
			$level = 'good';
		} elseif ( $score <= (int) apply_filters( 'pncp_reputation_bad', self::BAD ) ) {
			$level = 'bad';
		}
		arsort( $record );
		return array(
			'score'  => $score,
			'level'  => $level,
			'events' => $record,
		);
	}

	/**
	 * Names of the events, for people.
	 *
	 * @return array<string, string>
	 */
	public static function event_labels() {
		return array(
			'login'  => __( 'Someone signed in', 'scrapelock' ),
			'human'  => __( 'Passed the human check', 'scrapelock' ),
			'page'   => __( 'Read pages', 'scrapelock' ),
			'trap'   => __( 'Opened the bot trap', 'scrapelock' ),
			'probe'  => __( 'Scanner probe', 'scrapelock' ),
			'attack' => __( 'Attack in the request', 'scrapelock' ),
			'fake'   => __( 'Fake search engine or AI bot', 'scrapelock' ),
			'ban'    => __( 'Blocked temporarily', 'scrapelock' ),
			'bot'    => __( 'Refused as a bot', 'scrapelock' ),
			'limit'  => __( 'Exceeded a limit', 'scrapelock' ),
			'r404'   => __( 'Too many “page not found”', 'scrapelock' ),
		);
	}

	/**
	 * Storage key of an IP key's record.
	 *
	 * @param string $key IP key (PNCP_Ip::limit_key()).
	 * @return string
	 */
	private static function cache_key( $key ) {
		return 'pncp_rep_' . md5( (string) $key );
	}
}
