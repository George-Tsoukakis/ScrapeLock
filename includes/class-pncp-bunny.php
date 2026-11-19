<?php
/**
 * Bunny CDN, deeper: every visitor passes through Bunny, also for pages Bunny serves from its cache, which never
 * reach WordPress. ScrapeLock reads the pull zone's logs to see the attacks WordPress cannot see, and locks
 * vulnerable addresses (wp-login.php, xmlrpc.php, .env and .git probes…) at the edge with one click, as Bunny
 * Edge Rules made with the site owner's own account.
 *
 * Bunny's APIs as ScrapeLock uses them (see the readme's External services):
 * - Pull zone:  GET  {api}/pullzone/{id}  (EnableLogging, LoggingIPAnonymizationEnabled, EdgeRules[]).
 *               POST {api}/pullzone/{id}  with {"EnableLogging": true} (only when the owner clicks the button).
 * - Edge rules: POST {api}/pullzone/{id}/edgerules/addOrUpdate, DELETE {api}/pullzone/{id}/edgerules/{guid}.
 * - Logs:       GET  {log}/{MM-dd-yy}/{id}.log?order=asc&start=N&end=M, one request per line, fields separated by
 *               "|": cache status|status|timestamp (ms)|bytes|pull zone|remote IP|referer|URL|edge location|
 *               User-Agent|request ID|country. The parser accepts missing fields at the end and extra "|" in the
 *               User-Agent.
 * {api} = https://api.bunny.net (filter `pncp_bunny_api_base`), {log} = https://logging.bunnycdn.com (filter
 * `pncp_bunny_log_base`). Header "AccessKey" with the account's API key.
 *
 * Nothing here runs while a visitor waits: the import and the rule updates run from cron (every 15 minutes) or
 * when an administrator clicks a button. A normal page view reads and writes nothing of this.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Reads attacks from Bunny CDN's logs and manages the Edge Rules ScrapeLock created.
 */
final class PNCP_Bunny {

	/**
	 * Own connection (pull zone and API key) when "Blocking at the CDN" is not set to Bunny CDN.
	 */
	const CONFIG = 'pncp_bunny_config';

	/**
	 * Import cursor, logging status, last run and the hourly counts of what was seen at the edge.
	 */
	const STATE = 'pncp_bunny_state';

	/**
	 * The Edge Rules ScrapeLock created: id => rule. Rules not in here are never touched.
	 */
	const RULES = 'pncp_bunny_rules';

	/**
	 * API calls of the last 5 minutes: [window start, calls].
	 */
	const CALLS = 'pncp_bunny_calls';

	const CRON     = 'pncp_bunny_run';
	const SCHEDULE = 'pncp_15min';
	const ACTION   = 'pncp_bunny';

	/**
	 * Log reason (PNCP_Log::reasons()) of a temporary block for too many requests seen at the edge.
	 */
	const REASON = 'edge_rate';

	/**
	 * Description prefix of every Edge Rule ScrapeLock creates.
	 */
	const PREFIX = 'ScrapeLock: ';

	/**
	 * API calls in 5 minutes at most.
	 */
	const CALL_BUDGET = 60;

	/**
	 * Seconds one API call may take; a log download may take longer.
	 */
	const CALL_TIMEOUT = 10;
	const LOG_TIMEOUT  = 20;

	/**
	 * Seconds a run may work.
	 */
	const BUDGET = 20;

	/**
	 * Bunny's enums as ScrapeLock uses them (filter `pncp_bunny_edge_rule` can change the whole rule).
	 */
	const ACTION_BLOCK   = 4; // ActionType BlockRequest.
	const TRIGGER_URL    = 0; // Trigger Type Url.
	const TRIGGER_IP     = 5; // Trigger Type RemoteIP.
	const MATCH_ANY      = 0;
	const MATCH_ALL      = 1;
	const MATCH_NONE     = 2;
	const MAX_PATTERNS   = 50;
	const MAX_ALLOW_IPS  = 40;
	const MAX_AGGREGATES = 3000;

	/**
	 * 3.9: the fewest log lines the check "full or anonymized IPs" decides on (fewer are added up over runs).
	 */
	const IP_SAMPLE_MIN = 20;

	/**
	 * 3.9: the share of lines with a hidden IP (IPv4 ending in .0, IPv6 with an empty second half, no IP)
	 * from which the logs count as anonymized. Real IPs end in .0 about once in 256.
	 */
	const IP_SAMPLE_SHARE = 0.9;

	/**
	 * 3.9: the hidden admin page "What would be blocked", shown before every lock at Bunny.
	 */
	const PREVIEW_PAGE = 'scrapelock-bunny-lock';

	/**
	 * 3.9: the most attacking IPs whose normal traffic the preview looks up.
	 */
	const PREVIEW_IPS = 200;

	/**
	 * 3.9: the most IPs whose normal page views from the logs are kept (only IPs that also attacked).
	 */
	const MAX_NORMAL = 3000;

	/**
	 * 3.9: the most IPs kept per lockable address and day from the logs (the requests are all counted).
	 */
	const POINT_IPS = 200;

	/**
	 * 3.9: days the requests for the lockable addresses are kept from the logs (the preview shows 7).
	 */
	const POINT_DAYS = 8;

	/**
	 * The credentials of this request (false = not read yet).
	 *
	 * @var array{zone:string, token:string, source:string}|null|false
	 */
	private static $creds = false;

	/**
	 * Whether this request removes everything (deactivation, uninstall): not held to the call budget.
	 *
	 * @var bool
	 */
	private static $removing_all = false;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'pncp_bunny_lock_preview', array( __CLASS__, 'lock_preview_checks' ), 10, 2 ); // 3.9.
		add_action( 'xmlrpc_call', array( __CLASS__, 'note_xmlrpc_call' ), 10, 1 ); // 3.9: real XML-RPC use, for the warning before a lock.
		add_action( 'pingback_post', array( __CLASS__, 'note_pingback' ) );
		add_filter( 'cron_schedules', array( __CLASS__, 'schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected -- 15 minutes, the import interval.
		add_action( self::CRON, array( __CLASS__, 'run' ) );
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		add_action( 'admin_menu', array( __CLASS__, 'preview_menu' ) ); // 3.9: "What would be blocked".
		add_action( 'admin_init', array( __CLASS__, 'maybe_schedule' ) );
		add_action( 'update_option_' . PNCP_OPTION, array( __CLASS__, 'settings_changed' ), 20, 2 );
		add_action( 'update_option_' . PNCP_Edge::CONFIG, array( __CLASS__, 'edge_config_changed' ), 10, 2 );
	}

	/**
	 * The 15-minute schedule.
	 *
	 * @param array<string, array<string, mixed>> $schedules Schedules.
	 * @return array<string, array<string, mixed>>
	 */
	public static function schedules( $schedules ) {
		if ( ! isset( $schedules[ self::SCHEDULE ] ) ) {
			$schedules[ self::SCHEDULE ] = array(
				'interval' => 15 * MINUTE_IN_SECONDS,
				'display'  => __( 'Every 15 minutes (ScrapeLock)', 'scrapelock' ),
			);
		}
		return $schedules;
	}

	/* ---------- Settings ---------- */

	/**
	 * The settings of this component, with their defaults when they are not registered (yet).
	 *
	 * @return array{import:bool, all_lines:bool, flood:int, strikes:bool, rate:int, allow:string[]}
	 */
	public static function settings() {
		$s     = PNCP_Options::get();
		$allow = isset( $s['bunny_login_allow'] ) ? $s['bunny_login_allow'] : '';
		$allow = is_array( $allow ) ? $allow : preg_split( '/[\s,]+/', (string) $allow, -1, PREG_SPLIT_NO_EMPTY );
		$ips   = array();
		foreach ( (array) $allow as $entry ) {
			$entry = trim( (string) $entry );
			if ( '' !== $entry && ( filter_var( $entry, FILTER_VALIDATE_IP ) || PNCP_Ip::valid_range( $entry ) ) ) {
				$ips[] = $entry;
			}
		}
		return array(
			'import'    => ! empty( $s['bunny_import'] ),
			'all_lines' => ! empty( $s['bunny_all_lines'] ),
			'flood'     => isset( $s['bunny_flood_4xx'] ) ? max( 0, min( 10000, (int) $s['bunny_flood_4xx'] ) ) : 30,
			'strikes'   => ! empty( $s['bunny_strikes'] ),
			'rate'      => isset( $s['bunny_rate'] ) ? max( 0, min( 10000, (int) $s['bunny_rate'] ) ) : 120,
			'allow'     => array_values( array_unique( $ips ) ),
		);
	}

	/**
	 * The pull zone and API key: those of "Blocking at the CDN" when it is set to Bunny CDN, otherwise the
	 * connection of this card (option pncp_bunny_config; the key can come from SCRAPELOCK_BUNNY_KEY in
	 * wp-config.php).
	 *
	 * @return array{zone:string, token:string, source:string}|null
	 */
	public static function credentials() {
		if ( false !== self::$creds ) {
			return self::$creds;
		}
		self::$creds = null;
		$edge        = PNCP_Edge::config();
		if ( 'bunny' === $edge['provider'] && '' !== $edge['zone'] && '' !== $edge['token'] ) {
			self::$creds = array(
				'zone'   => $edge['zone'],
				'token'  => $edge['token'],
				'source' => 'edge',
			);
			return self::$creds;
		}
		$own = self::own_config();
		if ( '' !== $own['zone'] && '' !== $own['token'] ) {
			self::$creds = array(
				'zone'   => $own['zone'],
				'token'  => $own['token'],
				'source' => 'own',
			);
		}
		return self::$creds;
	}

	/**
	 * Forgets the credentials read in this request (after a change, and for tests).
	 */
	public static function reset() {
		self::$creds = false;
	}

	/**
	 * The own connection of this card.
	 *
	 * @return array{zone:string, token:string}
	 */
	public static function own_config() {
		$c     = get_option( self::CONFIG, array() );
		$c     = is_array( $c ) ? $c : array();
		$token = self::key_from_config() ? (string) SCRAPELOCK_BUNNY_KEY : ( isset( $c['token'] ) ? (string) $c['token'] : '' );
		return array(
			'zone'  => PNCP_Edge::clean_zone( 'bunny', isset( $c['zone'] ) ? (string) $c['zone'] : '' ),
			'token' => PNCP_Edge::clean_token( $token ),
		);
	}

	/**
	 * Is the own API key set in wp-config.php (SCRAPELOCK_BUNNY_KEY)?
	 *
	 * @return bool
	 */
	public static function key_from_config() {
		return defined( 'SCRAPELOCK_BUNNY_KEY' ) && '' !== PNCP_Edge::clean_token( (string) SCRAPELOCK_BUNNY_KEY );
	}

	/**
	 * Can vulnerable points be locked at the Bunny CDN edge?
	 *
	 * @return bool
	 */
	public static function edge_available() {
		return null !== self::credentials();
	}

	/**
	 * Should Edge Rules block now? Not while protection is off or in Monitor only: the rules stay at Bunny,
	 * switched off, and are switched on again by the next run.
	 *
	 * @return bool
	 */
	public static function enforcing() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && ! PNCP_Options::monitoring( $s );
	}

	/* ---------- Scheduling ---------- */

	/**
	 * Is there work for cron: an import, or rules to keep in step?
	 *
	 * @return bool
	 */
	public static function wanted() {
		if ( null === self::credentials() ) {
			return false;
		}
		$s = PNCP_Options::get();
		return ( self::settings()['import'] && ! empty( $s['enabled'] ) ) || (bool) self::rules();
	}

	/**
	 * Schedules or clears the run (wp-admin and after a settings change; reads only the cron option, which
	 * WordPress has loaded anyway).
	 */
	public static function maybe_schedule() {
		$next = wp_next_scheduled( self::CRON );
		if ( self::wanted() ) {
			if ( ! $next ) {
				wp_schedule_event( time() + MINUTE_IN_SECONDS, self::SCHEDULE, self::CRON );
			}
		} elseif ( $next ) {
			wp_clear_scheduled_hook( self::CRON );
		}
	}

	/**
	 * The settings were saved: Monitor only or protection may have changed, so the rules follow soon.
	 *
	 * @param mixed $old   Previous value of the settings.
	 * @param mixed $value New value.
	 */
	public static function settings_changed( $old = array(), $value = array() ) {
		self::reset();
		if ( ! self::rules() ) {
			self::maybe_schedule();
			return;
		}
		$was = is_array( $old ) && isset( $old['login_slug'] ) ? (string) $old['login_slug'] : '';
		$now = is_array( $value ) && isset( $value['login_slug'] ) ? (string) $value['login_slug'] : '';
		if ( $was !== $now && self::preset_locked( 'login' ) ) {
			// The sign-in address changed while wp-login.php is locked at Bunny: the rule follows now, not at
			// the next run, so nobody is left without a way to sign in.
			self::login_changed();
		}
		wp_clear_scheduled_hook( self::CRON );
		wp_schedule_event( time() + 30, self::SCHEDULE, self::CRON );
	}

	/**
	 * "Blocking at the CDN" got another configuration. The Edge Rules made with the previous Bunny pull zone are
	 * removed with the previous key, unless this card still reaches that pull zone.
	 *
	 * @param mixed $old Previous value.
	 * @param mixed $value New value.
	 */
	public static function edge_config_changed( $old, $value ) {
		self::reset();
		$old = is_array( $old ) ? $old : array();
		$new = is_array( $value ) ? $value : array();
		if ( empty( $old['provider'] ) || 'bunny' !== $old['provider'] ) {
			self::maybe_schedule();
			return;
		}
		$old_zone = PNCP_Edge::clean_zone( 'bunny', isset( $old['zone'] ) ? (string) $old['zone'] : '' );
		$creds    = self::credentials();
		if ( '' === $old_zone || ( null !== $creds && $creds['zone'] === $old_zone ) ) {
			self::maybe_schedule();
			return;
		}
		$token = PNCP_Edge::token_from_config() ? (string) SCRAPELOCK_EDGE_TOKEN : ( isset( $old['token'] ) ? (string) $old['token'] : '' );
		if ( '' === $token && isset( $new['token'] ) && ( isset( $new['provider'] ) && 'bunny' === $new['provider'] ) ) {
			$token = (string) $new['token']; // Same account, another pull zone: the token was kept.
		}
		$c = array(
			'zone'   => $old_zone,
			'token'  => PNCP_Edge::clean_token( $token ),
			'source' => 'edge',
		);
		if ( '' !== $c['token'] ) {
			self::remove_rules_of( $c, 15 );
		}
		self::maybe_schedule();
	}

	/* ---------- API ---------- */

	/**
	 * The base address of an API, from its filter (an https or http address without a trailing slash).
	 *
	 * @param string $which api | log.
	 * @return string
	 */
	public static function base( $which ) {
		if ( 'log' === $which ) {
			/**
			 * Filters the address of Bunny's logging API (https://logging.bunnycdn.com).
			 *
			 * @param string $base Address.
			 */
			$base = (string) apply_filters( 'pncp_bunny_log_base', 'https://logging.bunnycdn.com' );
			$def  = 'https://logging.bunnycdn.com';
		} else {
			/**
			 * Filters the address of Bunny's API (https://api.bunny.net).
			 *
			 * @param string $base Address.
			 */
			$base = (string) apply_filters( 'pncp_bunny_api_base', PNCP_Edge::BUNNY_API );
			$def  = PNCP_Edge::BUNNY_API;
		}
		$base = untrailingslashit( trim( $base ) );
		return preg_match( '#^https?://[^\s/?\#]+(?:/[^\s?\#]*)?$#i', $base ) ? $base : $def;
	}

	/**
	 * One call to Bunny's API, with the account's API key.
	 *
	 * @param array{zone:string, token:string} $c       Credentials.
	 * @param string                           $method  Method.
	 * @param string                           $url     Address.
	 * @param array<string, mixed>|null        $body    JSON body.
	 * @param array<string, mixed>             $options timeout, bytes (limit_response_size), raw (no JSON).
	 * @return array{status:string, code:int, json:array<mixed>, body:string, message:string, truncated:bool}
	 */
	private static function call( $c, $method, $url, $body = null, $options = array() ) {
		$out    = array(
			'status'    => 'error',
			'code'      => 0,
			'json'      => array(),
			'body'      => '',
			'message'   => '',
			'truncated' => false,
		);
		$now    = time();
		$window = get_option( self::CALLS, array() );
		$window = is_array( $window ) && isset( $window[0], $window[1] ) && (int) $window[0] > $now - 5 * MINUTE_IN_SECONDS && (int) $window[0] <= $now ? array( (int) $window[0], (int) $window[1] ) : array( $now, 0 );
		// WP-CLI is someone at the server on purpose (e.g. removing a rule that locked them out): no budget.
		if ( ! self::$removing_all && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			/**
			 * Filters the most calls ScrapeLock makes to Bunny's APIs in 5 minutes (60 by default).
			 *
			 * @param int $budget Calls.
			 */
			$budget = max( 10, (int) apply_filters( 'pncp_bunny_call_budget', self::CALL_BUDGET ) );
			// An administrator's click may use twice as many: the automatic runs leave room for it.
			$budget = is_admin() && ! wp_doing_cron() ? 2 * $budget : $budget;
			if ( $window[1] >= $budget ) {
				$out['status']  = 'wait';
				$out['message'] = __( 'ScrapeLock made many calls to Bunny in the last 5 minutes; it will continue in a few minutes.', 'scrapelock' );
				return $out;
			}
			++$window[1];
			update_option( self::CALLS, $window, false );
		}
		$raw  = ! empty( $options['raw'] );
		$args = array(
			'method'      => $method,
			'timeout'     => isset( $options['timeout'] ) ? (int) $options['timeout'] : self::CALL_TIMEOUT,
			'redirection' => 0,
			'user-agent'  => 'ScrapeLock/' . ( defined( 'PNCP_VERSION' ) ? PNCP_VERSION : '' ),
			'headers'     => array(
				'AccessKey' => $c['token'],
				'Accept'    => $raw ? 'text/plain, */*' : 'application/json',
			),
		);
		if ( ! empty( $options['bytes'] ) ) {
			$args['limit_response_size'] = (int) $options['bytes'];
		}
		if ( null !== $body ) {
			$args['headers']['Content-Type'] = 'application/json';
			$args['body']                    = (string) wp_json_encode( $body );
		}
		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			/* translators: %s: error message */
			$out['message'] = sprintf( __( 'Bunny could not be reached: %s', 'scrapelock' ), self::redact( substr( sanitize_text_field( $response->get_error_message() ), 0, 200 ), $c['token'] ) );
			if ( 'http_request_not_executed' === $response->get_error_code() ) {
				$out['message'] .= ' ' . __( 'WordPress blocks requests to other sites on this server (WP_HTTP_BLOCK_EXTERNAL): add api.bunny.net and logging.bunnycdn.com to WP_ACCESSIBLE_HOSTS.', 'scrapelock' );
			}
			return $out;
		}
		$code             = (int) wp_remote_retrieve_response_code( $response );
		$text             = (string) wp_remote_retrieve_body( $response );
		$out['code']      = $code;
		$out['body']      = $raw ? $text : '';
		$out['truncated'] = ! empty( $options['bytes'] ) && strlen( $text ) >= (int) $options['bytes'];
		$json             = $raw ? null : json_decode( $text, true );
		$out['json']      = is_array( $json ) ? $json : array();
		if ( $code >= 200 && $code < 300 ) {
			$out['status'] = 'ok';
			return $out;
		}
		$detail = isset( $out['json']['Message'] ) && is_scalar( $out['json']['Message'] ) ? (string) $out['json']['Message'] : '';
		$detail = self::redact( substr( sanitize_text_field( $detail ), 0, 200 ), $c['token'] );
		if ( 401 === $code || 403 === $code ) {
			$out['status']  = 'denied';
			$out['message'] = __( 'Bunny refused the API key. Use the API key from Account settings → API in the bunny.net dashboard.', 'scrapelock' );
		} elseif ( 404 === $code ) {
			$out['status']  = 'missing';
			$out['message'] = __( 'Bunny does not know this address (pull zone, rule or log).', 'scrapelock' );
		} elseif ( 429 === $code ) {
			$out['status']  = 'wait';
			$out['message'] = __( 'Bunny asked to slow down; ScrapeLock will continue in a few minutes.', 'scrapelock' );
		} elseif ( $code >= 500 ) {
			/* translators: %d: HTTP status code */
			$out['message'] = sprintf( __( 'Bunny answered with an error (HTTP %d); ScrapeLock will try again later.', 'scrapelock' ), $code );
		} else {
			$out['status'] = 'refused';
			/* translators: %d: HTTP status code */
			$out['message'] = sprintf( __( 'Bunny did not accept the request (HTTP %d).', 'scrapelock' ), $code );
		}
		if ( '' !== $detail ) {
			$out['message'] .= ' (' . $detail . ')';
		}
		return $out;
	}

	/**
	 * Takes the API key out of a text.
	 *
	 * @param string $text  Text.
	 * @param string $token API key.
	 * @return string
	 */
	private static function redact( $text, $token ) {
		return strlen( (string) $token ) >= 8 ? str_replace( (string) $token, '[key]', (string) $text ) : (string) $text;
	}

	/**
	 * The pull zone, as Bunny returns it.
	 *
	 * @param array{zone:string, token:string} $c Credentials.
	 * @return array{status:string, code:int, json:array<mixed>, body:string, message:string, truncated:bool}
	 */
	private static function pull_zone( $c ) {
		return self::call( $c, 'GET', self::base( 'api' ) . '/pullzone/' . rawurlencode( $c['zone'] ) );
	}

	/* ---------- State ---------- */

	/**
	 * The state, with every field present.
	 *
	 * @return array<string, mixed>
	 */
	public static function state() {
		$s        = get_option( self::STATE, array() );
		$s        = is_array( $s ) ? $s : array();
		$defaults = array(
			'zone'       => '',
			'day'        => '',
			'offset'     => 0,
			'sig'        => '',
			'floor'      => 0,
			'last_run'   => 0,
			'last_ok'    => 0,
			'lines'      => 0,
			'found'      => 0,
			'error'      => '',
			'error_time' => 0,
			'logging'    => array(),
			'ips'        => array(),
			'normal'     => array(),
			'points'     => array(),
			'points_0'   => 0,
			'hours'      => array(),
			'struck'     => 0,
			'skipped'    => 0,
		);
		$s        = array_merge( $defaults, array_intersect_key( $s, $defaults ) );
		foreach ( array( 'logging', 'ips', 'normal', 'points', 'hours' ) as $key ) {
			$s[ $key ] = is_array( $s[ $key ] ) ? $s[ $key ] : array();
		}
		return $s;
	}

	/**
	 * Saves the state (not autoloaded: only cron and the settings page read it).
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function save_state( $state ) {
		if ( false === get_option( self::STATE, false ) ) {
			add_option( self::STATE, $state, '', false );
		} else {
			update_option( self::STATE, $state, false );
		}
	}

	/**
	 * The Edge Rules ScrapeLock created.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function rules() {
		$rules = get_option( self::RULES, array() );
		return is_array( $rules ) ? $rules : array();
	}

	/**
	 * Saves the rules ScrapeLock created.
	 *
	 * @param array<string, array<string, mixed>> $rules Rules.
	 */
	private static function save_rules( $rules ) {
		if ( ! $rules ) {
			delete_option( self::RULES );
			return;
		}
		if ( false === get_option( self::RULES, false ) ) {
			add_option( self::RULES, $rules, '', false );
		} else {
			update_option( self::RULES, $rules, false );
		}
	}

	/**
	 * The Edge Rules ScrapeLock manages, for the card, WP-CLI and other components.
	 *
	 * @return array<string, array{id:string, label:string, patterns:string[], allow:string[], guid:string, zone:string, enabled:bool, created:int, updated:int, missing:bool}>
	 */
	public static function list_ours() {
		$out = array();
		foreach ( self::rules() as $id => $rule ) {
			$out[ (string) $id ] = array(
				'id'       => (string) $id,
				'label'    => isset( $rule['label'] ) ? (string) preg_replace( '/^ScrapeLock\s*(?:hardening)?\s*:\s*/i', '', (string) $rule['label'] ) : (string) $id,
				'patterns' => isset( $rule['patterns'] ) ? array_map( 'strval', (array) $rule['patterns'] ) : array(),
				'allow'    => isset( $rule['allow'] ) ? array_map( 'strval', (array) $rule['allow'] ) : array(),
				'guid'     => isset( $rule['guid'] ) ? (string) $rule['guid'] : '',
				'zone'     => isset( $rule['zone'] ) ? (string) $rule['zone'] : '',
				'enabled'  => ! empty( $rule['enabled'] ),
				'created'  => isset( $rule['created'] ) ? (int) $rule['created'] : 0,
				'updated'  => isset( $rule['updated'] ) ? (int) $rule['updated'] : 0,
				'missing'  => ! empty( $rule['missing'] ),
			);
		}
		return $out;
	}

	/* ---------- Edge Rules ---------- */

	/**
	 * A rule ID as stored: lowercase letters, digits, "_" and "-", at most 40 characters.
	 *
	 * @param string $id ID.
	 * @return string
	 */
	private static function clean_id( $id ) {
		return substr( sanitize_key( (string) $id ), 0, 40 );
	}

	/**
	 * URL patterns as Bunny's "Request URL" trigger takes them (wildcards "*"): no spaces or control characters,
	 * at most 255 characters each, at most MAX_PATTERNS, and never a pattern that is only wildcards.
	 *
	 * @param string[] $patterns Patterns.
	 * @return string[]
	 */
	private static function clean_patterns( $patterns ) {
		$out = array();
		foreach ( (array) $patterns as $pattern ) {
			$pattern = trim( (string) $pattern );
			if ( '' === $pattern || strlen( $pattern ) > 255 || preg_match( '/[\s\x00-\x1F\x7F"<>]/', $pattern ) || '' === trim( $pattern, '*/' ) ) {
				continue;
			}
			$out[ $pattern ] = $pattern;
		}
		return array_slice( array_values( $out ), 0, self::MAX_PATTERNS );
	}

	/**
	 * The Description of a rule at Bunny: "ScrapeLock: <label> [<id>]", which also finds it again after it was
	 * created.
	 *
	 * @param string $id    ID.
	 * @param string $label Label.
	 * @return string
	 */
	private static function description( $id, $label ) {
		$label = trim( preg_replace( '/^ScrapeLock\s*(?:hardening)?\s*:\s*/i', '', sanitize_text_field( (string) $label ) ) );
		$label = function_exists( 'mb_substr' ) ? mb_substr( $label, 0, 120 ) : substr( $label, 0, 120 );
		return self::PREFIX . ( '' !== $label ? $label : $id ) . ' [' . $id . ']';
	}

	/**
	 * The JSON body of a rule for addOrUpdate.
	 *
	 * @param string               $id      ID.
	 * @param array<string, mixed> $rule    Rule (label, patterns, allow, except, guid).
	 * @param bool                 $enabled Whether it blocks.
	 * @return array<string, mixed>
	 */
	private static function body( $id, $rule, $enabled ) {
		$triggers = array(
			array(
				'Type'                => self::TRIGGER_URL,
				'PatternMatches'      => array_values( (array) $rule['patterns'] ),
				'PatternMatchingType' => self::MATCH_ANY,
				'Parameter1'          => '',
			),
		);
		if ( ! empty( $rule['allow'] ) ) {
			$triggers[] = array(
				'Type'                => self::TRIGGER_IP,
				'PatternMatches'      => array_values( (array) $rule['allow'] ),
				'PatternMatchingType' => self::MATCH_NONE,
				'Parameter1'          => '',
			);
		}
		if ( ! empty( $rule['except'] ) ) {
			$triggers[] = array(
				'Type'                => self::TRIGGER_URL,
				'PatternMatches'      => array_values( (array) $rule['except'] ),
				'PatternMatchingType' => self::MATCH_NONE,
				'Parameter1'          => '',
			);
		}
		$body = array(
			'ActionType'          => self::ACTION_BLOCK,
			'ActionParameter1'    => '',
			'ActionParameter2'    => '',
			'Triggers'            => $triggers,
			'TriggerMatchingType' => count( $triggers ) > 1 ? self::MATCH_ALL : self::MATCH_ANY,
			'Description'         => self::description( $id, (string) $rule['label'] ),
			'Enabled'             => (bool) $enabled,
		);
		if ( ! empty( $rule['guid'] ) ) {
			$body = array( 'Guid' => (string) $rule['guid'] ) + $body;
		}
		/**
		 * Filters an Edge Rule before ScrapeLock sends it to Bunny (addOrUpdate).
		 *
		 * @param array<string, mixed> $body The rule as JSON.
		 * @param string               $id   ScrapeLock's ID of the rule.
		 */
		return (array) apply_filters( 'pncp_bunny_edge_rule', $body, $id );
	}

	/**
	 * The Edge Rules of the pull zone: GUID => Description.
	 *
	 * @param array<mixed> $zone The pull zone as JSON.
	 * @return array<string, array{description:string, enabled:bool}>
	 */
	private static function zone_rules( $zone ) {
		$out = array();
		if ( isset( $zone['EdgeRules'] ) && is_array( $zone['EdgeRules'] ) ) {
			foreach ( $zone['EdgeRules'] as $rule ) {
				if ( is_array( $rule ) && isset( $rule['Guid'] ) && is_scalar( $rule['Guid'] ) ) {
					$out[ (string) $rule['Guid'] ] = array(
						'description' => isset( $rule['Description'] ) && is_scalar( $rule['Description'] ) ? (string) $rule['Description'] : '',
						'enabled'     => ! isset( $rule['Enabled'] ) || ! empty( $rule['Enabled'] ),
					);
				}
			}
		}
		return $out;
	}

	/**
	 * A GUID as Bunny writes it.
	 *
	 * @param string $guid GUID.
	 * @return string Empty when it is not one.
	 */
	private static function clean_guid( $guid ) {
		$guid = strtolower( trim( (string) $guid ) );
		return preg_match( '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $guid ) ? $guid : '';
	}

	/**
	 * Why a change cannot be made now ('' = it can).
	 *
	 * @return WP_Error|null
	 */
	private static function refusal() {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked with Lockdown: unlock it to change the rules at Bunny CDN.', 'scrapelock' ) );
		}
		if ( null === self::credentials() ) {
			return new WP_Error( 'pncp_no_bunny', __( 'Bunny CDN is not connected: set the pull zone and API key first.', 'scrapelock' ) );
		}
		return null;
	}

	/**
	 * Creates or updates an Edge Rule that blocks the requests whose URL matches one of the patterns. Only rules
	 * ScrapeLock created are ever updated. In Monitor only, or with protection off, the rule is made switched off
	 * and the next run switches it on once ScrapeLock blocks.
	 *
	 * @param string               $id           ScrapeLock's ID of the rule (e.g. harden_xmlrpc, preset_login).
	 * @param string[]             $url_patterns Bunny "Request URL" patterns, e.g. "*\/xmlrpc.php*".
	 * @param string               $label        What it blocks, for the Description at Bunny.
	 * @param array<string, mixed> $options      allow: IPs and ranges never blocked; except: URL patterns never blocked.
	 * @return true|WP_Error
	 */
	public static function edge_block( $id, $url_patterns, $label, $options = array() ) {
		$refused = self::refusal();
		if ( $refused ) {
			return $refused;
		}
		$id       = self::clean_id( $id );
		$patterns = self::clean_patterns( $url_patterns );
		if ( '' === $id || ! $patterns ) {
			return new WP_Error( 'pncp_bad_rule', __( 'This rule has no address to block.', 'scrapelock' ) );
		}
		$allow = array();
		foreach ( isset( $options['allow'] ) ? (array) $options['allow'] : array() as $ip ) {
			$ip = trim( (string) $ip );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) || PNCP_Ip::valid_range( $ip ) ) {
				$allow[ $ip ] = $ip;
			}
		}
		$rule = array(
			'label'    => sanitize_text_field( (string) $label ),
			'patterns' => $patterns,
			'allow'    => array_slice( array_values( $allow ), 0, self::MAX_ALLOW_IPS ),
			'except'   => self::clean_patterns( isset( $options['except'] ) ? (array) $options['except'] : array() ),
		);
		return self::send( $id, $rule, self::enforcing() );
	}

	/**
	 * Sends a rule to Bunny (update when ScrapeLock has its GUID for this pull zone, otherwise create) and keeps
	 * its GUID.
	 *
	 * @param string               $id      ID.
	 * @param array<string, mixed> $rule    label, patterns, allow, except.
	 * @param bool                 $enabled Whether it blocks.
	 * @return true|WP_Error
	 */
	private static function send( $id, $rule, $enabled ) {
		$c     = self::credentials();
		$rules = self::rules();
		$old   = isset( $rules[ $id ] ) ? $rules[ $id ] : null;
		$url   = self::base( 'api' ) . '/pullzone/' . rawurlencode( $c['zone'] ) . '/edgerules/addOrUpdate';
		if ( $old && ! empty( $old['guid'] ) && isset( $old['zone'] ) && $old['zone'] === $c['zone'] ) {
			$rule['guid'] = (string) $old['guid'];
			$res          = self::call( $c, 'POST', $url, self::body( $id, $rule, $enabled ) );
			if ( 'ok' === $res['status'] ) {
				return self::keep( $id, $rule, $enabled, $c['zone'], $old );
			}
			if ( 'missing' !== $res['status'] ) {
				return new WP_Error( 'pncp_bunny_' . $res['status'], $res['message'] );
			}
			unset( $rule['guid'] ); // Removed in the Bunny dashboard: made again.
		} elseif ( $old && ! empty( $old['guid'] ) ) {
			// Another pull zone now: the old rule is removed first (same account, same key).
			self::delete_rule( $c, $old );
		}
		$before = self::pull_zone( $c );
		if ( 'ok' !== $before['status'] ) {
			return new WP_Error( 'pncp_bunny_' . $before['status'], $before['message'] );
		}
		$known = self::zone_rules( $before['json'] );
		$res   = self::call( $c, 'POST', $url, self::body( $id, $rule, $enabled ) );
		if ( 'ok' !== $res['status'] ) {
			return new WP_Error( 'pncp_bunny_' . $res['status'], $res['message'] );
		}
		$guid = isset( $res['json']['Guid'] ) && is_scalar( $res['json']['Guid'] ) ? self::clean_guid( (string) $res['json']['Guid'] ) : '';
		if ( '' === $guid ) {
			// addOrUpdate answers without a body: the new rule is the one with this Description that was not there before.
			$after = self::pull_zone( $c );
			$want  = self::description( $id, (string) $rule['label'] );
			if ( 'ok' === $after['status'] ) {
				foreach ( self::zone_rules( $after['json'] ) as $g => $found ) {
					if ( ! isset( $known[ $g ] ) && $found['description'] === $want ) {
						$guid = self::clean_guid( $g );
						break;
					}
				}
			}
		}
		if ( '' === $guid ) {
			return new WP_Error( 'pncp_bunny_guid', __( 'Bunny accepted the rule, but ScrapeLock could not find it again to manage it. Check the Edge Rules of the pull zone in the bunny.net dashboard (its description starts with “ScrapeLock:”).', 'scrapelock' ) );
		}
		$rule['guid'] = $guid;
		return self::keep( $id, $rule, $enabled, $c['zone'], $old );
	}

	/**
	 * Notes a rule that Bunny confirmed.
	 *
	 * @param string                    $id      ID.
	 * @param array<string, mixed>      $rule    Rule with guid.
	 * @param bool                      $enabled Whether it blocks.
	 * @param string                    $zone    Pull zone.
	 * @param array<string, mixed>|null $old     Previous record.
	 * @return true
	 */
	private static function keep( $id, $rule, $enabled, $zone, $old ) {
		$rules        = self::rules();
		$rules[ $id ] = array(
			'guid'     => (string) $rule['guid'],
			'zone'     => (string) $zone,
			'label'    => (string) $rule['label'],
			'patterns' => array_values( (array) $rule['patterns'] ),
			'allow'    => isset( $rule['allow'] ) ? array_values( (array) $rule['allow'] ) : array(),
			'except'   => isset( $rule['except'] ) ? array_values( (array) $rule['except'] ) : array(),
			'enabled'  => (bool) $enabled,
			'created'  => $old && isset( $old['created'] ) ? (int) $old['created'] : time(),
			'updated'  => time(),
		);
		self::save_rules( $rules );
		self::maybe_schedule();
		return true;
	}

	/**
	 * Removes an Edge Rule ScrapeLock created.
	 *
	 * @param string $id ScrapeLock's ID of the rule.
	 * @return true|WP_Error
	 */
	public static function edge_unblock( $id ) {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked with Lockdown: unlock it to change the rules at Bunny CDN.', 'scrapelock' ) );
		}
		return self::remove( self::clean_id( $id ) );
	}

	/**
	 * Removes a rule (also while locked: deactivation, WP-CLI).
	 *
	 * @param string $id ID.
	 * @return true|WP_Error
	 */
	private static function remove( $id ) {
		$rules = self::rules();
		if ( ! isset( $rules[ $id ] ) ) {
			return true; // Not one of ScrapeLock's, or already gone.
		}
		$c = self::credentials();
		if ( null === $c ) {
			return new WP_Error( 'pncp_no_bunny', __( 'Bunny CDN is not connected: remove the rule in the bunny.net dashboard (Edge Rules, description “ScrapeLock: …”).', 'scrapelock' ) );
		}
		$done = self::delete_rule( $c, $rules[ $id ] );
		if ( is_wp_error( $done ) ) {
			return $done;
		}
		$rules = self::rules();
		unset( $rules[ $id ] );
		self::save_rules( $rules );
		self::maybe_schedule();
		return true;
	}

	/**
	 * DELETE of one rule at Bunny ("not found" counts as removed).
	 *
	 * @param array{zone:string, token:string} $c    Credentials (the key; the pull zone of the rule is used).
	 * @param array<string, mixed>             $rule Stored rule.
	 * @return true|WP_Error
	 */
	private static function delete_rule( $c, $rule ) {
		$guid = self::clean_guid( isset( $rule['guid'] ) ? (string) $rule['guid'] : '' );
		$zone = isset( $rule['zone'] ) && '' !== (string) $rule['zone'] ? (string) $rule['zone'] : $c['zone'];
		if ( '' === $guid ) {
			return true;
		}
		$res = self::call( $c, 'DELETE', self::base( 'api' ) . '/pullzone/' . rawurlencode( $zone ) . '/edgerules/' . rawurlencode( $guid ) );
		if ( 'ok' === $res['status'] || 'missing' === $res['status'] ) {
			return true;
		}
		return new WP_Error( 'pncp_bunny_' . $res['status'], $res['message'] );
	}

	/**
	 * Removes every rule ScrapeLock created at a pull zone (configuration changed).
	 *
	 * @param array{zone:string, token:string} $c       Credentials of that pull zone.
	 * @param int                              $seconds Time budget.
	 */
	private static function remove_rules_of( $c, $seconds ) {
		$end   = microtime( true ) + $seconds;
		$rules = self::rules();
		foreach ( $rules as $id => $rule ) {
			if ( microtime( true ) > $end ) {
				break;
			}
			if ( isset( $rule['zone'] ) && (string) $rule['zone'] === $c['zone'] && true === self::delete_rule( $c, $rule ) ) {
				unset( $rules[ $id ] );
			}
		}
		self::save_rules( $rules );
	}

	/**
	 * Removes every rule ScrapeLock created (deactivation, uninstall). Rules that are left (Bunny not reachable)
	 * carry "ScrapeLock:" in their description in the Bunny dashboard.
	 *
	 * @param int $seconds Time budget.
	 * @return int Rules left.
	 */
	public static function remove_all( $seconds = 15 ) {
		self::$removing_all = true;
		$c                  = self::credentials();
		$end                = microtime( true ) + max( 1, (int) $seconds );
		$rules              = self::rules();
		if ( null !== $c ) {
			foreach ( $rules as $id => $rule ) {
				if ( microtime( true ) > $end ) {
					break;
				}
				if ( true === self::delete_rule( $c, $rule ) ) {
					unset( $rules[ $id ] );
				}
			}
		}
		self::save_rules( $rules );
		self::$removing_all = false;
		return count( $rules );
	}

	/**
	 * Deactivation: removes the rules at Bunny and the scheduled run.
	 */
	public static function deactivate() {
		self::remove_all( 15 );
		wp_clear_scheduled_hook( self::CRON );
	}

	/**
	 * Uninstall: removes the rules at Bunny, the scheduled run and the options.
	 */
	public static function uninstall() {
		self::remove_all( 15 );
		wp_clear_scheduled_hook( self::CRON );
		foreach ( array( self::CONFIG, self::STATE, self::RULES, self::CALLS ) as $option ) {
			delete_option( $option );
		}
	}

	/**
	 * Keeps the rules in step: switched on while ScrapeLock blocks, off in Monitor only or with protection off,
	 * and the login rule's allowed IPs follow the administrators' IPs. Also notes rules removed in the Bunny
	 * dashboard.
	 *
	 * @param array<mixed>|null $zone  The pull zone as JSON (null = not read).
	 * @param float             $end   Deadline (microtime).
	 * @return int Rules sent again.
	 */
	public static function sync_rules( $zone = null, $end = 0.0 ) {
		$c = self::credentials();
		if ( null === $c || PNCP_Lockdown::is_locked() ) {
			return 0; // Changes wait until the site is unlocked.
		}
		$end   = $end > 0 ? $end : microtime( true ) + 10;
		$on    = self::enforcing();
		$rules = self::rules();
		$sent  = 0;
		$live  = is_array( $zone ) ? self::zone_rules( $zone ) : null;
		foreach ( $rules as $id => $rule ) {
			if ( microtime( true ) > $end || $sent >= 10 ) {
				break;
			}
			if ( null !== $live && isset( $rule['zone'] ) && $rule['zone'] === $c['zone'] && ! empty( $rule['guid'] ) && ! isset( $live[ (string) $rule['guid'] ] ) ) {
				// Removed in the Bunny dashboard: the owner decided, so ScrapeLock forgets it instead of making it again.
				unset( $rules[ $id ] );
				self::save_rules( $rules );
				continue;
			}
			$want    = $rule;
			$rule_on = $on;
			if ( 'preset_login' === $id ) {
				// The administrators' IPs follow. While the sign-in page is at wp-login.php again (the address
				// was opened again, cleared, or turned off with SCRAPELOCK_LOGIN_SLUG_OFF), the rule never blocks
				// everyone: without a known administrator IP it is switched off.
				$allow = self::login_rule_allow(); // 3.9: the explicit list, for a lock made since 3.9.
				if ( $allow ) {
					$want['allow'] = $allow;
				}
				if ( empty( $want['allow'] ) && ! self::custom_login_active() ) {
					$rule_on = false;
				}
			}
			$same_allow = ( isset( $rule['allow'] ) ? (array) $rule['allow'] : array() ) === ( isset( $want['allow'] ) ? (array) $want['allow'] : array() );
			// Only ScrapeLock's own record is compared: a rule switched off by hand in the Bunny dashboard stays off.
			if ( ( ! empty( $rule['enabled'] ) ) === $rule_on && $same_allow ) {
				continue;
			}
			++$sent;
			self::send( (string) $id, $want, $rule_on );
			$rules = self::rules();
		}
		return $sent;
	}

	/**
	 * The sign-in address changed (or was turned off in wp-config.php): the login rule at Bunny is sent again
	 * at once (allowed IPs, or switched off). Errors wait for the next run.
	 */
	public static function login_changed() {
		if ( null === self::credentials() || PNCP_Lockdown::is_locked() || ! self::preset_locked( 'login' ) ) {
			return;
		}
		PNCP_Options::flush();
		if ( class_exists( 'PNCP_Login' ) ) {
			PNCP_Login::flush();
		}
		self::sync_rules( null, microtime( true ) + 8 );
	}

	/* ---------- Presets ---------- */

	/**
	 * Is the login page moved to an address of the site's own (PNCP_Login)? Then wp-login.php can be blocked
	 * for everyone. Filter `pncp_bunny_custom_login`.
	 *
	 * @return bool
	 */
	public static function custom_login_active() {
		$on = false;
		if ( class_exists( 'PNCP_Login' ) ) {
			// PNCP_Login serves the sign-in form at its own address and rewrites every link and form to it, so
			// requests for wp-login.php itself then come from bots only.
			if ( method_exists( 'PNCP_Login', 'custom_login_active' ) ) {
				$on = (bool) PNCP_Login::custom_login_active();
			} elseif ( method_exists( 'PNCP_Login', 'slug' ) ) {
				$on = '' !== (string) PNCP_Login::slug();
			}
		}
		/**
		 * Filters whether the login page is moved away from wp-login.php (by PNCP_Login or another plugin that
		 * no longer uses wp-login.php in its addresses).
		 *
		 * @param bool $on Moved.
		 */
		return (bool) apply_filters( 'pncp_bunny_custom_login', $on );
	}

	/**
	 * The IPs that may still open wp-login.php when it is locked at Bunny: the administrators' IPs of the last
	 * 30 days, the IP of the administrator using this page, and "bunny_login_allow".
	 *
	 * @return string[]
	 */
	public static function login_allowlist() {
		$out = array();
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() && current_user_can( 'manage_options' ) && PNCP_Ip::reliable() ) {
			$ip = PNCP_Ip::client_ip();
			if ( '' !== $ip && ! PNCP_Ip::is_cdn_edge( $ip ) && ! PNCP_Ip::is_local( $ip ) ) {
				$out[ $ip ] = $ip;
			}
		}
		foreach ( array_keys( PNCP_Edge::staff() ) as $key ) {
			$key         = (string) $key;
			$out[ $key ] = $key;
		}
		foreach ( self::settings()['allow'] as $ip ) {
			$out[ $ip ] = $ip;
		}
		$out = array_values( $out );
		sort( $out );
		return array_slice( $out, 0, self::MAX_ALLOW_IPS );
	}

	/* ---------- 3.9: the login page lock follows an explicit list ---------- */

	/**
	 * 3.9: set (time) when wp-login.php was locked at Bunny with the explicit list only. A rule made before 3.9
	 * has no such mark and keeps following the administrators' IPs (login_allowlist()), so upgraded sites keep
	 * the behaviour they had.
	 */
	const LOGIN_STRICT = 'pncp_bunny_login_strict';

	/**
	 * The IPs and ranges listed under "Allowed IPs for the login page at Bunny" (bunny_login_allow), which the
	 * administrator confirmed. An entry may be a CIDR range, e.g. an IPv6 /64.
	 *
	 * @return string[]
	 */
	public static function login_allow_list() {
		return array_slice( self::settings()['allow'], 0, self::MAX_ALLOW_IPS );
	}

	/**
	 * The IPs the login rule at Bunny lets through: since 3.9 only the explicit list; a rule locked before 3.9
	 * keeps following the administrators' IPs too.
	 *
	 * Bunny's "Remote IP" trigger is sent the entries as written, CIDR included (an IPv6 /64 as
	 * 2001:db8:1:2::/64). That Bunny matches CIDR in this trigger is the assumption of 3.8 (see specs/5-bunny.md)
	 * and is not verified against the real API; filter `pncp_bunny_edge_rule` can rewrite the trigger.
	 *
	 * @return string[]
	 */
	public static function login_rule_allow() {
		return get_option( self::LOGIN_STRICT, false ) ? self::login_allow_list() : self::login_allowlist();
	}

	/**
	 * The public IP of the administrator using this page, when ScrapeLock can see it ('' otherwise).
	 *
	 * @return string
	 */
	public static function current_admin_ip() {
		if ( ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() || ! current_user_can( 'manage_options' ) || ! PNCP_Ip::reliable() ) {
			return '';
		}
		$ip = PNCP_Ip::client_ip();
		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) || PNCP_Ip::is_cdn_edge( $ip ) || PNCP_Ip::is_local( $ip ) ) {
			return '';
		}
		return $ip;
	}

	/**
	 * Why wp-login.php cannot be locked at Bunny now: the allowed list is empty, or it does not hold the IP of
	 * the administrator who locks (or that IP cannot be seen). Empty = it can. From WP-CLI (someone at the
	 * server, no IP) only the empty list counts.
	 *
	 * @return string[]
	 */
	public static function login_lock_blockers() {
		$out  = array();
		$list = self::login_allow_list();
		$cli  = defined( 'WP_CLI' ) && WP_CLI;
		$ip   = $cli ? '' : self::current_admin_ip();
		if ( ! $cli && '' === $ip ) {
			$out[] = __( 'ScrapeLock cannot see your real IP (it appears as the address of a proxy, of Bunny or of this server), so it cannot check that the lock leaves you a way in. Set “Real visitor IP” in Bots first, then lock again.', 'scrapelock' );
		}
		if ( ! $list ) {
			$out[] = __( 'The list “Allowed IPs for the login page at Bunny” is empty, so the lock would refuse everyone at wp-login.php, you included. Add your IP with “Add selected” under the suggestions in this card (or type it in Bots → Bunny CDN logs and save), then lock again.', 'scrapelock' );
		} elseif ( '' !== $ip && ! PNCP_Ip::in_any( $ip, $list ) ) {
			$out[] = sprintf(
				/* translators: 1: the administrator's IP, 2: the entry to add (the IP, or its IPv6 /64) */
				__( 'Your IP now (%1$s) is not in “Allowed IPs for the login page at Bunny”, so the lock would keep you out of wp-login.php. Add %2$s with “Add selected” under the suggestions in this card (or in Bots → Bunny CDN logs), then lock again.', 'scrapelock' ),
				$ip,
				PNCP_Ip::limit_key( $ip )
			);
		}
		return $out;
	}

	/**
	 * The IPs to suggest for the allowed list: the IP of the administrator using this page and those
	 * administrators used in wp-admin in the last 30 days (PNCP_Edge::staff()), when the list does not already
	 * cover them. IPv6 addresses are offered as their /64, since a connection's IPv6 address changes within it.
	 *
	 * @return array<string, array{last:int, current:bool}> Entry => last seen, is the IP now.
	 */
	public static function login_allow_suggestions() {
		$list = self::login_allow_list();
		$out  = array();
		$ip   = self::current_admin_ip();
		if ( '' !== $ip ) {
			$out[ PNCP_Ip::limit_key( $ip ) ] = array(
				'last'    => time(),
				'current' => true,
			);
		}
		foreach ( PNCP_Edge::staff() as $key => $time ) {
			$key = (string) $key;
			if ( ! isset( $out[ $key ] ) ) {
				$out[ $key ] = array(
					'last'    => (int) $time,
					'current' => false,
				);
			}
		}
		foreach ( array_keys( $out ) as $key ) {
			$base = explode( '/', (string) $key, 2 )[0];
			if ( ! PNCP_Ip::valid_range( (string) $key ) || PNCP_Ip::is_local( $base ) || PNCP_Ip::is_cdn_edge( $base ) || ( $list && PNCP_Ip::in_any( $base, $list ) ) ) {
				unset( $out[ $key ] );
			}
		}
		return $out;
	}

	/**
	 * Adds suggested entries to "Allowed IPs for the login page at Bunny". Only entries that are suggested
	 * now are taken: this is the confirmation of a suggestion, not a free form.
	 *
	 * @param string[] $picked Entries the administrator ticked.
	 * @return string[]|WP_Error The entries added.
	 */
	public static function add_login_allow( $picked ) {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked with Lockdown: unlock it to change the settings.', 'scrapelock' ) );
		}
		$offer = self::login_allow_suggestions();
		$add   = array();
		foreach ( (array) $picked as $entry ) {
			$entry = trim( (string) $entry );
			if ( isset( $offer[ $entry ] ) ) {
				$add[ $entry ] = $entry;
			}
		}
		if ( ! $add ) {
			return new WP_Error( 'pncp_none', __( 'Tick at least one of the suggested IPs, then click “Add selected”.', 'scrapelock' ) );
		}
		$stored = PNCP_Options::stored();
		$list   = PNCP_Options::parse_list( isset( $stored['bunny_login_allow'] ) ? (string) $stored['bunny_login_allow'] : '' );
		if ( count( $list ) + count( $add ) > self::MAX_ALLOW_IPS ) {
			/* translators: %d: most entries */
			return new WP_Error( 'pncp_full', sprintf( __( 'The list may hold at most %d IPs and ranges (what Bunny accepts in one rule): remove old ones in Bots → Bunny CDN logs first.', 'scrapelock' ), self::MAX_ALLOW_IPS ) );
		}
		$stored['bunny_login_allow'] = implode( "\n", array_values( array_unique( array_merge( $list, array_values( $add ) ) ) ) );
		// As PNCP_Options::block_ip_permanently(): a change of this list does not need the page cache purged.
		$purge = has_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache' );
		if ( false !== $purge ) {
			remove_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache', $purge );
		}
		update_option( PNCP_OPTION, $stored );
		if ( false !== $purge ) {
			add_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache', $purge );
		}
		PNCP_Options::flush();
		if ( self::preset_locked( 'login' ) ) {
			self::login_changed(); // A lock made with the list follows it now, not at the next run.
		}
		return array_values( $add );
	}

	/**
	 * Locks wp-login.php at Bunny with the explicit list, after the checks of login_lock_blockers().
	 *
	 * @param array<string, mixed> $preset  The login preset.
	 * @param array<string, mixed> $options Options for edge_block() (except).
	 * @return true|WP_Error
	 */
	private static function lock_login( $preset, $options ) {
		$blockers = self::login_lock_blockers();
		if ( $blockers ) {
			return new WP_Error( 'pncp_login_allow', implode( ' ', $blockers ) );
		}
		$options['allow'] = self::login_allow_list();
		$result           = self::edge_block( 'preset_login', $preset['patterns'], $preset['label'], $options );
		if ( true === $result ) {
			update_option( self::LOGIN_STRICT, time(), false );
		}
		return $result;
	}

	/**
	 * Filter `pncp_bunny_lock_preview` (the confirmation before a lock at Bunny): the reasons the login page
	 * cannot be locked go in as blockers, what locking XML-RPC stops as warnings.
	 *
	 * @param mixed  $preview The preview (warnings, blockers: lists of strings).
	 * @param string $preset  Preset.
	 * @return array<string, mixed>
	 */
	public static function lock_preview_checks( $preview, $preset = '' ) {
		$preview = is_array( $preview ) ? $preview : array();
		foreach ( array( 'warnings', 'blockers' ) as $key ) {
			$preview[ $key ] = isset( $preview[ $key ] ) && is_array( $preview[ $key ] ) ? $preview[ $key ] : array();
		}
		if ( 'login' === $preset ) {
			$preview['blockers'] = array_merge( $preview['blockers'], self::login_lock_blockers() );
		}
		if ( 'xmlrpc' === $preset && method_exists( __CLASS__, 'xmlrpc_lock_warnings' ) ) {
			$preview['warnings'] = array_merge( $preview['warnings'], self::xmlrpc_lock_warnings() );
		}
		return $preview;
	}

	/**
	 * The "Allowed IPs for the login page at Bunny" part of the card: the list, whether it covers the IP now,
	 * and the suggestions to confirm.
	 *
	 * @param bool $locked Site locked with Lockdown.
	 */
	private static function render_login_allow( $locked ) {
		$list   = self::login_allow_list();
		$ip     = self::current_admin_ip();
		$offer  = self::login_allow_suggestions();
		$is     = self::preset_locked( 'login' );
		$strict = (bool) get_option( self::LOGIN_STRICT, false );
		echo '<div class="pncp-bunny-login-allow" id="pncp-bunny-login-allow"><h4>' . esc_html__( 'Allowed IPs for the login page at Bunny', 'scrapelock' ) . '</h4>';
		if ( $list ) {
			/* translators: %s: list of IPs and ranges */
			echo '<p>' . esc_html( sprintf( __( 'A lock of wp-login.php lets only these IPs and ranges through: %s.', 'scrapelock' ), implode( ', ', $list ) ) ) . '</p>';
		} else {
			echo '<p class="pncp-edge-error">' . esc_html__( 'The list is empty: wp-login.php cannot be locked at Bunny until it holds at least your IP.', 'scrapelock' ) . '</p>';
		}
		if ( '' !== $ip ) {
			$covered = $list && PNCP_Ip::in_any( $ip, $list );
			echo '<p class="' . esc_attr( $covered ? '' : 'pncp-edge-error' ) . '">' . esc_html(
				$covered
					/* translators: %s: IP */
					? sprintf( __( 'Your IP now (%s) is in the list.', 'scrapelock' ), $ip )
					/* translators: %s: IP */
					: sprintf( __( 'Your IP now (%s) is not in the list.', 'scrapelock' ), $ip )
			) . ( $is && ! $covered && $strict ? ' ' . esc_html__( 'The lock at Bunny keeps you out of wp-login.php from here: add it below.', 'scrapelock' ) : '' ) . '</p>';
		}
		if ( $is && ! $strict ) {
			echo '<p class="description">' . esc_html__( 'This lock was made before ScrapeLock 3.9: it also lets in the IPs administrators used in the last 30 days, without asking. To use only this list, remove the lock and lock again.', 'scrapelock' ) . '</p>';
		}
		if ( $offer && ! $locked ) {
			printf( '<form method="post" action="%s" class="pncp-bunny-form pncp-bunny-allow-add">', esc_url( admin_url( 'admin-post.php' ) ) );
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '"><input type="hidden" name="op" value="login_allow_add">';
			echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( self::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
			echo '<fieldset><legend>' . esc_html__( 'Suggested: the IPs administrators used in wp-admin in the last 30 days. Tick the ones that are yours or your team\'s, then add them.', 'scrapelock' ) . '</legend>';
			foreach ( $offer as $entry => $info ) {
				$what = $info['current']
					? __( 'your IP now', 'scrapelock' )
					/* translators: %s: date and time */
					: sprintf( __( 'last seen in wp-admin %s', 'scrapelock' ), self::when( $info['last'] ) );
				printf(
					'<label style="display:block"><input type="checkbox" name="ips[]" value="%1$s"> <code>%2$s</code> <span class="description">(%3$s)</span></label>',
					esc_attr( $entry ),
					esc_html( $entry ),
					esc_html( $what )
				);
			}
			echo '</fieldset><p class="description">' . esc_html__( 'An IPv6 address is suggested as its /64 network: the address of an IPv6 connection changes within it.', 'scrapelock' ) . '</p>';
			echo '<p><button type="submit" class="button button-small">' . esc_html__( 'Add selected', 'scrapelock' ) . '</button></p></form>';
		}
		echo '<p class="description">' . esc_html__( 'Edit or remove entries in Bots → Bunny CDN logs → “Allowed IPs for the login page at Bunny” (one IP or range per line, an IPv6 /64 such as 2001:db8:1:2::/64 too).', 'scrapelock' ) . '</p></div>';
	}

	/* ---------- 3.9: what locking XML-RPC stops ---------- */

	/**
	 * 3.9: when XML-RPC was last used for real (not autoloaded): kind (auth = a call after a sign-in, pingback =
	 * a pingback accepted) => the hours with such a use in the last 30 days (Unix times, at most one an hour),
	 * and the name of the last signed-in method.
	 */
	const XMLRPC_USE = 'pncp_xmlrpc_use';

	/**
	 * Action `xmlrpc_call`: WordPress fires it in each method, after the sign-in for those that need one. Only
	 * calls with a signed-in user count as use.
	 *
	 * @param string $name Method, e.g. wp.getUsersBlogs.
	 */
	public static function note_xmlrpc_call( $name = '' ) {
		if ( function_exists( 'get_current_user_id' ) && get_current_user_id() > 0 ) {
			self::note_xmlrpc( 'auth', (string) $name );
		}
	}

	/**
	 * Action `pingback_post`: a pingback from another site was accepted.
	 */
	public static function note_pingback() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			self::note_xmlrpc( 'pingback', '' );
		}
	}

	/**
	 * Notes one use, at most one write an hour per kind.
	 *
	 * @param string $kind   auth | pingback.
	 * @param string $method Method name.
	 */
	private static function note_xmlrpc( $kind, $method ) {
		$use   = get_option( self::XMLRPC_USE, array() );
		$use   = is_array( $use ) ? $use : array();
		$times = isset( $use[ $kind ] ) && is_array( $use[ $kind ] ) ? array_map( 'intval', $use[ $kind ] ) : array();
		$now   = time();
		if ( $times && max( $times ) > $now - HOUR_IN_SECONDS ) {
			return;
		}
		$since = $now - 30 * DAY_IN_SECONDS;
		$keep  = array();
		foreach ( $times as $t ) {
			if ( $t > $since ) {
				$keep[] = $t;
			}
		}
		$keep[]       = $now;
		$use[ $kind ] = array_slice( $keep, -720 );
		if ( 'auth' === $kind ) {
			$use['method'] = substr( (string) preg_replace( '/[^A-Za-z0-9_.]/', '', $method ), 0, 60 );
		}
		if ( false === get_option( self::XMLRPC_USE, false ) ) {
			add_option( self::XMLRPC_USE, $use, '', false );
		} else {
			update_option( self::XMLRPC_USE, $use, false );
		}
	}

	/**
	 * The uses of the last 30 days of one kind.
	 *
	 * @param string $kind auth | pingback.
	 * @return array{hours:int, last:int, method:string}
	 */
	public static function xmlrpc_use( $kind ) {
		$use   = get_option( self::XMLRPC_USE, array() );
		$use   = is_array( $use ) ? $use : array();
		$since = time() - 30 * DAY_IN_SECONDS;
		$times = array();
		foreach ( isset( $use[ $kind ] ) && is_array( $use[ $kind ] ) ? $use[ $kind ] : array() as $t ) {
			if ( (int) $t > $since ) {
				$times[] = (int) $t;
			}
		}
		return array(
			'hours'  => count( $times ),
			'last'   => $times ? max( $times ) : 0,
			'method' => 'auth' === $kind && isset( $use['method'] ) ? (string) $use['method'] : '',
		);
	}

	/**
	 * Is Jetpack active on this site? Filter `pncp_jetpack_active`.
	 *
	 * @return bool
	 */
	public static function jetpack_active() {
		$on = defined( 'JETPACK__VERSION' ) || class_exists( 'Jetpack' );
		if ( ! $on ) {
			$on = in_array( 'jetpack/jetpack.php', (array) get_option( 'active_plugins', array() ), true );
			if ( ! $on && is_multisite() ) {
				$on = isset( ( (array) get_site_option( 'active_sitewide_plugins', array() ) )['jetpack/jetpack.php'] );
			}
		}
		/**
		 * Filters whether Jetpack counts as active (for the warning before XML-RPC is locked at the CDN).
		 *
		 * @param bool $on Active.
		 */
		return (bool) apply_filters( 'pncp_jetpack_active', $on );
	}

	/**
	 * How many users have at least one application password.
	 *
	 * @return int
	 */
	public static function app_password_users() {
		global $wpdb;
		$key    = class_exists( 'WP_Application_Passwords' ) && defined( 'WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS' ) ? WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS : '_application_passwords';
		$cached = wp_cache_get( 'app_password_users', 'scrapelock' );
		if ( false !== $cached ) {
			return (int) $cached;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- One count, cached for the request; no API counts users by meta value.
		$count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value NOT IN ( '', 'a:0:{}' )", $key ) );
		wp_cache_set( 'app_password_users', $count, 'scrapelock', MINUTE_IN_SECONDS );
		return $count;
	}

	/**
	 * What a lock of xmlrpc.php at the CDN would stop on this site: Jetpack active, application passwords,
	 * signed-in XML-RPC use or pingbacks in the last 30 days. Empty when nothing points to a real use.
	 *
	 * @return string[]
	 */
	public static function xmlrpc_lock_warnings() {
		$out = array();
		if ( self::jetpack_active() ) {
			$out[] = __( 'Jetpack is active: it talks to WordPress.com through xmlrpc.php, so its connection, Stats, Publicize, backups and the WordPress.com app stop working.', 'scrapelock' );
		}
		$apps = self::app_password_users();
		if ( $apps > 0 ) {
			$out[] = sprintf(
				/* translators: %s: number of users */
				_n( '%s user has application passwords: apps and publishing tools that sign in with them through XML-RPC (the WordPress mobile app, desktop editors, some automation services) stop working. Through the REST API they keep working.', '%s users have application passwords: apps and publishing tools that sign in with them through XML-RPC (the WordPress mobile app, desktop editors, some automation services) stop working. Through the REST API they keep working.', $apps, 'scrapelock' ),
				number_format_i18n( $apps )
			);
		}
		$auth = self::xmlrpc_use( 'auth' );
		if ( $auth['hours'] > 0 ) {
			$out[] = sprintf(
				/* translators: 1: date and time, 2: method name, 3: number of hours */
				_n( 'Someone signed in through xmlrpc.php successfully in the last 30 days (last %1$s, method %2$s; in %3$s hour): the mobile app or publishing tool they used stops working.', 'Someone signed in through xmlrpc.php successfully in the last 30 days (last %1$s, method %2$s; in %3$s different hours): the mobile app or publishing tool they used stops working.', $auth['hours'], 'scrapelock' ),
				self::when( $auth['last'] ),
				'' !== $auth['method'] ? $auth['method'] : '?',
				number_format_i18n( $auth['hours'] )
			);
		}
		$ping = self::xmlrpc_use( 'pingback' );
		if ( $ping['hours'] > 0 ) {
			$out[] = sprintf(
				/* translators: %s: date and time */
				__( 'Pingbacks from other sites were accepted in the last 30 days (last %s): no new pingbacks arrive once xmlrpc.php is locked.', 'scrapelock' ),
				self::when( $ping['last'] )
			);
		}
		if ( $out ) {
			$out[] = __( 'Locked at Bunny, xmlrpc.php is refused for everyone, Jetpack\'s servers included, before WordPress sees the request.', 'scrapelock' );
		}
		return $out;
	}

	/**
	 * The warnings about XML-RPC in the card, while it is not locked at Bunny.
	 */
	private static function render_xmlrpc_warnings() {
		if ( self::preset_locked( 'xmlrpc' ) ) {
			return;
		}
		$warn = self::xmlrpc_lock_warnings();
		if ( ! $warn ) {
			return;
		}
		echo '<div class="notice notice-warning inline pncp-bunny-xmlrpc-warn"><p><strong>' . esc_html__( 'Before you lock XML-RPC (xmlrpc.php) at Bunny, this will stop working:', 'scrapelock' ) . '</strong></p><ul>';
		foreach ( $warn as $line ) {
			echo '<li>' . esc_html( $line ) . '</li>';
		}
		echo '</ul></div>';
	}

	/**
	 * The presets of the "Lock at Bunny" buttons. A preset that is also a point of PNCP_Hardening is locked
	 * through it (same rule, same state on the hardening card).
	 *
	 * @return array<string, array{label:string, blocks:string, breaks:string, patterns:string[], except:string[], evidence:array<int, array{0:string, 1:string}>, harden:string}>
	 */
	public static function presets() {
		$core = (string) wp_parse_url( site_url( '/' ), PHP_URL_PATH );
		$core = '' !== $core ? trailingslashit( $core ) : '/';
		$out  = array(
			'login'      => array(
				'label'    => __( 'Login page (wp-login.php)', 'scrapelock' ),
				'blocks'   => self::custom_login_active()
					? __( 'Every request for wp-login.php: the login page has its own address, so only bots still ask for wp-login.php.', 'scrapelock' )
					: __( 'Every request for wp-login.php, except from the IPs and ranges listed under “Allowed IPs for the login page at Bunny”. The list must hold your IP now; the IPs administrators used in the last 30 days are suggested below, to add with one click.', 'scrapelock' ),
				'breaks'   => __( 'Anyone else who signs in at wp-login.php (authors, members, customers without a shop account page) is refused, and so are you from an IP that is not in the list: then remove the rule in the bunny.net dashboard (Edge Rules, “ScrapeLock: …”) or run wp scrapelock bunny unlock preset_login. Password-protected posts keep working. When the sign-in page goes back to wp-login.php (“Open again”, an empty sign-in address, or SCRAPELOCK_LOGIN_SLUG_OFF in wp-config.php), the rule keeps letting in the listed IPs.', 'scrapelock' ),
				'patterns' => array( '*' . $core . 'wp-login.php*' ),
				'except'   => array( '*action=postpass*' ),
				'evidence' => array( array( 'login_fail', '' ), array( 'login_probe', '' ), array( 'edge', $core . 'wp-login.php' ) ),
				'harden'   => '',
			),
			'xmlrpc'     => array(
				'label'    => __( 'XML-RPC (xmlrpc.php)', 'scrapelock' ),
				'blocks'   => __( 'Every request for xmlrpc.php, where bots try hundreds of passwords in one request.', 'scrapelock' ),
				'breaks'   => __( 'Jetpack, the WordPress mobile app and old publishing tools that use XML-RPC.', 'scrapelock' ),
				'patterns' => array( '*' . $core . 'xmlrpc.php*' ),
				'except'   => array(),
				'evidence' => array( array( 'xmlrpc', '' ), array( 'edge', $core . 'xmlrpc.php' ) ),
				'harden'   => 'xmlrpc',
			),
			'probes'     => array(
				'label'    => __( 'Secret files: .env, .git, backups, database dumps', 'scrapelock' ),
				'blocks'   => __( 'Requests for .env, .git, .svn, wp-config.php copies, .sql dumps, phpMyAdmin and the usual backup and web shell names. A real site never serves them.', 'scrapelock' ),
				'breaks'   => __( 'Nothing a visitor uses. /.well-known/ (certificates, app links) is not touched.', 'scrapelock' ),
				'patterns' => array(
					'*/.env*',
					'*/.git*',
					'*/.svn/*',
					'*/.hg/*',
					'*/.aws/*',
					'*/.ssh/*',
					'*/.DS_Store*',
					'*/.htpasswd*',
					'*/wp-config.php.*',
					'*/wp-config.php~*',
					'*/wp-config.bak*',
					'*/wp-config.old*',
					'*/wp-config.txt*',
					'*.sql',
					'*.sql.gz',
					'*/phpmyadmin*',
					'*/adminer.php*',
					'*/backup.zip*',
					'*/backup.tar.gz*',
					'*/debug.log*',
					'*/vendor/phpunit/*',
				),
				'except'   => array(),
				'evidence' => array( array( 'scanner', '' ), array( 'edge', '/.env' ), array( 'edge', '/.git' ), array( 'edge', '/wp-config' ), array( 'edge', '/phpmyadmin' ) ),
				'harden'   => '',
			),
			'core_files' => array(
				'label'    => __( 'WordPress\'s own files: readme.html, license.txt, install.php…', 'scrapelock' ),
				'blocks'   => __( 'readme.html, license.txt, wp-config-sample.php, wp-admin/install.php and setup-config.php, which scanners open to learn that the site runs WordPress, and which version.', 'scrapelock' ),
				'breaks'   => __( 'Nothing a visitor uses.', 'scrapelock' ),
				'patterns' => array(
					'*' . $core . 'readme.html*',
					'*' . $core . 'license.txt*',
					'*' . $core . 'wp-config-sample.php*',
					'*' . $core . 'wp-admin/install.php*',
					'*' . $core . 'wp-admin/setup-config.php*',
				),
				'except'   => array(),
				'evidence' => array( array( 'install', '' ), array( 'scanner', $core . 'readme.html' ) ),
				'harden'   => 'core_files',
			),
		);
		/**
		 * Filters the presets of the "Lock at Bunny" buttons.
		 *
		 * @param array<string, array<string, mixed>> $presets Presets.
		 */
		return (array) apply_filters( 'pncp_bunny_presets', $out );
	}

	/**
	 * Locks through PNCP_Hardening when it offers the point?
	 *
	 * @param array<string, mixed> $preset Preset.
	 * @return bool
	 */
	private static function via_hardening( $preset ) {
		if ( empty( $preset['harden'] ) || ! class_exists( 'PNCP_Hardening' ) || ! method_exists( 'PNCP_Hardening', 'edge' ) || ! method_exists( 'PNCP_Hardening', 'point' ) ) {
			return false;
		}
		$point = PNCP_Hardening::point( (string) $preset['harden'] );
		return is_array( $point ) && ! empty( $point['edge'] );
	}

	/**
	 * The rule ID of a preset.
	 *
	 * @param string $id Preset.
	 * @return string
	 */
	public static function preset_rule_id( $id ) {
		$presets = self::presets();
		if ( isset( $presets[ $id ] ) && self::via_hardening( $presets[ $id ] ) ) {
			return 'harden_' . $presets[ $id ]['harden'];
		}
		return 'preset_' . $id;
	}

	/**
	 * Is a preset locked at Bunny now (by this card or the hardening card)?
	 *
	 * @param string $id Preset.
	 * @return bool
	 */
	public static function preset_locked( $id ) {
		$rules = self::rules();
		return isset( $rules[ self::preset_rule_id( $id ) ] ) || isset( $rules[ 'preset_' . $id ] );
	}

	/**
	 * Locks a preset at Bunny.
	 *
	 * @param string $id Preset.
	 * @return true|WP_Error
	 */
	public static function lock_preset( $id ) {
		$presets = self::presets();
		if ( ! isset( $presets[ $id ] ) ) {
			return new WP_Error( 'pncp_unknown', __( 'Unknown preset.', 'scrapelock' ) );
		}
		$preset = $presets[ $id ];
		if ( self::via_hardening( $preset ) ) {
			return PNCP_Hardening::edge( (string) $preset['harden'], true );
		}
		$options = array( 'except' => $preset['except'] );
		if ( 'login' === $id ) {
			// 3.9: only the explicit, confirmed list, which must hold the IP of the administrator who locks. Also
			// while the sign-in page has its own address: the rule falls back to the list when the address goes
			// back to wp-login.php (sync_rules()).
			return self::lock_login( $preset, $options );
		}
		return self::edge_block( 'preset_' . $id, $preset['patterns'], $preset['label'], $options );
	}

	/**
	 * Removes a preset's rule.
	 *
	 * @param string $id Preset.
	 * @return true|WP_Error
	 */
	public static function unlock_preset( $id ) {
		$presets = self::presets();
		if ( isset( $presets[ $id ] ) && self::via_hardening( $presets[ $id ] ) && isset( self::rules()[ 'harden_' . $presets[ $id ]['harden'] ] ) ) {
			return PNCP_Hardening::edge( (string) $presets[ $id ]['harden'], false );
		}
		return self::edge_unblock( 'preset_' . $id );
	}

	/* ---------- Logging ---------- */

	/**
	 * How to turn logging on at Bunny.
	 *
	 * @return string
	 */
	public static function logging_how() {
		return __( 'In the bunny.net dashboard: CDN → your pull zone → Logging → turn on “Enable logging”, then save. Logs are kept by Bunny for 3 days; ScrapeLock reads them every 15 minutes. With “Log anonymization” on, Bunny hides the last part of each IP: ScrapeLock still sees where bots hit, but cannot block single addresses from the logs.', 'scrapelock' );
	}

	/**
	 * Is logging on at the pull zone? Asks Bunny (one call) and keeps the answer.
	 *
	 * @param array<mixed>|null $zone The pull zone as JSON, if already read.
	 * @return array{status:string, enabled:bool|null, anonymized:bool|null, message:string, how:string, time:int}
	 */
	public static function bunny_logging_check( $zone = null ) {
		$how = self::logging_how();
		$out = array(
			'status'     => 'unknown',
			'enabled'    => null,
			'anonymized' => null,
			'message'    => '',
			'how'        => $how,
			'time'       => time(),
		);
		$c   = self::credentials();
		if ( null === $c ) {
			$out['status']  = 'off';
			$out['message'] = __( 'Bunny CDN is not connected.', 'scrapelock' );
			return $out;
		}
		if ( null === $zone ) {
			$res = self::pull_zone( $c );
			if ( 'ok' !== $res['status'] ) {
				$out['status']  = 'error';
				$out['message'] = $res['message'];
				self::note_logging( $out );
				return $out;
			}
			$zone = $res['json'];
		}
		if ( array_key_exists( 'EnableLogging', $zone ) ) {
			$out['enabled'] = ! empty( $zone['EnableLogging'] );
		}
		if ( array_key_exists( 'LoggingIPAnonymizationEnabled', $zone ) ) {
			$out['anonymized'] = ! empty( $zone['LoggingIPAnonymizationEnabled'] );
		}
		if ( true === $out['enabled'] ) {
			$out['status']  = $out['anonymized'] ? 'anonymized' : 'on';
			$out['message'] = $out['anonymized']
				? __( 'Logging is on, with IP anonymization: ScrapeLock sees where bots hit, but not their full IPs, so it blocks no address because of the logs.', 'scrapelock' )
				: __( 'Logging is on at the pull zone.', 'scrapelock' );
		} elseif ( false === $out['enabled'] ) {
			$out['status']  = 'off';
			$out['message'] = __( 'Logging is off at the pull zone: Bunny keeps no logs to read.', 'scrapelock' );
		} else {
			$out['message'] = __( 'Bunny did not say whether logging is on.', 'scrapelock' );
		}
		self::note_logging( $out );
		return $out;
	}

	/**
	 * Keeps the logging status in the state.
	 *
	 * @param array<string, mixed> $status Status.
	 */
	private static function note_logging( $status ) {
		$state            = self::state();
		$state['logging'] = array_intersect_key( $status, array_flip( array( 'status', 'enabled', 'anonymized', 'message', 'time' ) ) );
		self::save_state( $state );
	}

	/**
	 * Turns logging on at the pull zone (an administrator clicked the button).
	 *
	 * @return true|WP_Error
	 */
	public static function enable_logging() {
		$refused = self::refusal();
		if ( $refused ) {
			return $refused;
		}
		$c   = self::credentials();
		$res = self::call( $c, 'POST', self::base( 'api' ) . '/pullzone/' . rawurlencode( $c['zone'] ), array( 'EnableLogging' => true ) );
		if ( 'ok' !== $res['status'] ) {
			return new WP_Error( 'pncp_bunny_' . $res['status'], $res['message'] );
		}
		$check = self::bunny_logging_check();
		if ( false === $check['enabled'] ) {
			return new WP_Error( 'pncp_bunny_logging', __( 'Bunny accepted the change, but logging is still off. Turn it on in the bunny.net dashboard.', 'scrapelock' ) );
		}
		return true;
	}

	/* ---------- Import ---------- */

	/**
	 * One run (cron, every 15 minutes; "Import now"): reads the pull zone (logging status, rules), keeps the rules
	 * in step and imports the new log lines.
	 *
	 * @return array{lines:int, found:int, error:string}
	 */
	public static function run() {
		$result = array(
			'lines' => 0,
			'found' => 0,
			'error' => '',
		);
		$c      = self::credentials();
		if ( null === $c ) {
			self::maybe_schedule();
			return $result;
		}
		if ( ! PNCP_Log::cache_add( 'pncp_bunny_lock', time(), 5 * MINUTE_IN_SECONDS ) ) {
			$result['error'] = __( 'Another import is running.', 'scrapelock' );
			return $result;
		}
		$end  = self::deadline();
		$zone = self::pull_zone( $c );
		if ( 'ok' === $zone['status'] ) {
			$logging = self::bunny_logging_check( $zone['json'] );
			self::sync_rules( $zone['json'], $end );
		} else {
			$logging = array( 'enabled' => null );
		}
		$s = PNCP_Options::get();
		if ( self::settings()['import'] && ! empty( $s['enabled'] ) && false !== $logging['enabled'] ) {
			$result = self::import( $c, $end );
		} elseif ( 'ok' !== $zone['status'] ) {
			$result['error'] = $zone['message'];
		}
		$state             = self::state();
		$state['last_run'] = time();
		if ( '' !== $result['error'] ) {
			$state['error']      = $result['error'];
			$state['error_time'] = time();
		} else {
			$state['error'] = '';
		}
		self::save_state( $state );
		PNCP_Log::cache_delete( 'pncp_bunny_lock' );
		self::maybe_schedule();
		return $result;
	}

	/**
	 * When a run stops starting new work: BUDGET seconds, less when PHP's time limit is closer.
	 *
	 * @return float
	 */
	private static function deadline() {
		$budget = self::BUDGET;
		$limit  = (int) ini_get( 'max_execution_time' );
		if ( $limit > 0 ) {
			$start  = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : microtime( true );
			$budget = min( $budget, max( 3, $limit - ( microtime( true ) - $start ) - 8 ) );
		}
		return microtime( true ) + $budget;
	}

	/**
	 * The day of a log file as Bunny names it (UTC): MM-dd-yy.
	 *
	 * @param int $time Unix time.
	 * @return string
	 */
	public static function log_day( $time ) {
		return gmdate( 'm-d-y', $time );
	}

	/**
	 * Imports the new lines of the pull zone's logs: from the cursor, yesterday's file until its end, then
	 * today's. At most a number of lines and bytes per run, within the time budget.
	 *
	 * @param array{zone:string, token:string} $c   Credentials.
	 * @param float                            $end Deadline.
	 * @return array{lines:int, found:int, error:string}
	 */
	public static function import( $c, $end ) {
		$result = array(
			'lines' => 0,
			'found' => 0,
			'error' => '',
		);
		$state  = self::state();
		$today  = self::log_day( time() );
		$yday   = self::log_day( time() - DAY_IN_SECONDS );
		if ( $state['zone'] !== $c['zone'] || ! in_array( $state['day'], array( $today, $yday ), true ) ) {
			// First run, another pull zone, or a cursor older than yesterday: start with today's file, from now on
			// (older lines are not imported, so turning the import on does not flood the record with old lines).
			$state['zone']   = $c['zone'];
			$state['day']    = $today;
			$state['offset'] = 0;
			$state['sig']    = '';
			$state['floor']  = ( time() - 15 * MINUTE_IN_SECONDS ) * 1000;
		}
		$floor = (int) $state['floor'];
		/**
		 * Filters the most log lines one request asks for (20,000 by default).
		 *
		 * @param int $lines Lines.
		 */
		$per = max( 100, (int) apply_filters( 'pncp_bunny_lines_per_request', 20000 ) );
		/**
		 * Filters the most bytes of one log download (8 MB by default).
		 *
		 * @param int $bytes Bytes.
		 */
		$bytes    = max( 65536, (int) apply_filters( 'pncp_bunny_log_bytes', 8 * MB_IN_BYTES ) );
		$analysis = self::new_analysis();
		$sample   = self::new_ip_sample();
		for ( $i = 0; $i < 4; $i++ ) {
			if ( microtime( true ) >= $end ) {
				break;
			}
			$day    = $state['day'];
			$offset = max( 0, (int) $state['offset'] );
			$url    = self::base( 'log' ) . '/' . rawurlencode( $day ) . '/' . rawurlencode( $c['zone'] ) . '.log';
			$url    = add_query_arg(
				array(
					'order' => 'asc',
					'start' => $offset,
					'end'   => $offset + $per,
				),
				$url
			);
			$res    = self::call(
				$c,
				'GET',
				$url,
				null,
				array(
					'raw'     => true,
					'timeout' => self::LOG_TIMEOUT,
					'bytes'   => $bytes,
				)
			);
			if ( 'missing' === $res['status'] ) {
				$res['status'] = 'ok'; // No log for this day (yet): nothing to read.
				$res['body']   = '';
			}
			if ( 'ok' !== $res['status'] ) {
				$result['error'] = $res['message'];
				break;
			}
			$lines = self::split_lines( $res['body'], $res['truncated'] );
			// Did Bunny ignore start/end? Then the answer begins with the first line of the day again.
			if ( $offset > 0 && $lines && '' !== $state['sig'] && self::signature( $lines[0] ) === $state['sig'] ) {
				$lines = array_slice( $lines, $offset );
			}
			if ( 0 === $offset && $lines ) {
				$state['sig'] = self::signature( $lines[0] );
			}
			$count = count( $lines );
			foreach ( $lines as $line ) {
				self::sample_ip( $sample, $line );
				$row = self::parse_line( $line );
				// Lines from before the import was turned on (or before another pull zone was set) are not imported.
				if ( $row && $row['ts'] >= $floor ) {
					self::count_points( $analysis, $row ); // 3.9: every request for a lockable address, for the preview.
					self::analyse( $analysis, $row );
					++$result['lines'];
				}
			}
			$state['offset'] = $offset + $count;
			if ( $count < $per && ! $res['truncated'] ) {
				if ( $day !== $today ) {
					$state['day']    = $today; // Yesterday is read to its end: on to today.
					$state['offset'] = 0;
					$state['sig']    = '';
					continue;
				}
				break; // Caught up.
			}
		}
		// 3.9: full or anonymized IPs, from every line read (also with no attack at all), before store() uses it.
		$state['ips']    = self::ip_verdict( $state['ips'], $sample );
		$result['found'] = self::store( $analysis, $state );
		$state['lines']  = $result['lines'];
		$state['found']  = $result['found'];
		if ( '' === $result['error'] ) {
			$state['last_ok'] = time();
		}
		$current = self::state();
		// Keep what the run noted meanwhile (logging status).
		$state['logging'] = $current['logging'];
		self::save_state( $state );
		return $result;
	}

	/**
	 * The complete lines of a download (the last one is dropped when the download was cut off).
	 *
	 * @param string $body      Body.
	 * @param bool   $truncated Cut off at the byte limit.
	 * @return string[]
	 */
	public static function split_lines( $body, $truncated = false ) {
		$body = str_replace( "\r", '', (string) $body );
		if ( '' === trim( $body ) ) {
			return array();
		}
		$lines = explode( "\n", $body );
		if ( $truncated && "\n" !== substr( $body, -1 ) ) {
			array_pop( $lines );
		}
		return array_values(
			array_filter(
				$lines,
				static function ( $line ) {
					return '' !== trim( $line );
				}
			)
		);
	}

	/**
	 * What identifies a line (its request ID, or the line itself).
	 *
	 * @param string $line Line.
	 * @return string
	 */
	private static function signature( $line ) {
		return md5( (string) $line );
	}

	/**
	 * One log line as fields. Tolerant: fields missing at the end are empty, and extra "|" are taken to belong
	 * to the User-Agent (the only free text after the URL). Lines with fewer than 8 fields, without a valid IP or
	 * without a URL are skipped.
	 *
	 * @param string $line Line.
	 * @return array{cache:string, status:int, ts:int, bytes:int, zone:string, ip:string, referer:string, url:string, path:string, query:string, edge:string, ua:string, id:string, country:string}|null
	 */
	public static function parse_line( $line ) {
		$f = explode( '|', trim( (string) $line ) );
		$n = count( $f );
		if ( $n < 8 ) {
			return null;
		}
		if ( $n > 12 ) {
			$ua = implode( '|', array_slice( $f, 9, $n - 11 ) );
			$f  = array_merge( array_slice( $f, 0, 9 ), array( $ua ), array_slice( $f, -2 ) );
		}
		$f  = array_pad( $f, 12, '' );
		$ip = PNCP_Ip::normalize( trim( $f[5] ) );
		if ( '' === $ip ) {
			return null;
		}
		$url = trim( $f[7] );
		if ( '' === $url ) {
			return null;
		}
		$parts = wp_parse_url( preg_match( '#^[a-z][a-z0-9+.\-]*://#i', $url ) ? $url : 'http://x' . ( '/' === $url[0] ? '' : '/' ) . $url );
		if ( ! is_array( $parts ) ) {
			return null;
		}
		$ts = trim( $f[2] );
		$ts = ctype_digit( $ts ) ? (int) $ts : 0;
		if ( $ts > 0 && $ts < 100000000000 ) {
			$ts *= 1000; // Seconds instead of milliseconds.
		}
		return array(
			'cache'   => strtoupper( trim( $f[0] ) ),
			'status'  => (int) trim( $f[1] ),
			'ts'      => $ts > 0 ? $ts : time() * 1000,
			'bytes'   => (int) trim( $f[3] ),
			'zone'    => trim( $f[4] ),
			'ip'      => $ip,
			'referer' => trim( $f[6] ),
			'url'     => $url,
			'path'    => isset( $parts['path'] ) && '' !== $parts['path'] ? (string) $parts['path'] : '/',
			'query'   => isset( $parts['query'] ) ? (string) $parts['query'] : '',
			'edge'    => trim( $f[8] ),
			'ua'      => trim( $f[9] ),
			'id'      => trim( $f[10] ),
			'country' => strtoupper( substr( trim( $f[11] ), 0, 2 ) ),
		);
	}

	/**
	 * What an attack-looking request is (the detail of its record), or '' for a normal one.
	 *
	 * @param array<string, mixed> $row    Parsed line.
	 * @param string[]             $agents Blocked User-Agents.
	 * @return string
	 */
	public static function classify( $row, $agents = array() ) {
		$path   = strtolower( rawurldecode( (string) $row['path'] ) );
		$query  = strtolower( rawurldecode( (string) $row['query'] ) );
		$status = (int) $row['status'];
		if ( preg_match( '#/xmlrpc\.php$#', $path ) ) {
			return 'xmlrpc.php';
		}
		if ( preg_match( '#/wp-login\.php$#', $path ) ) {
			return false !== strpos( $query, 'action=postpass' ) ? '' : 'wp-login.php';
		}
		if ( preg_match( '#/wp-admin/(?:install|setup-config|upgrade)\.php$#', $path ) ) {
			return 'installer';
		}
		if ( preg_match( '#/wp-admin(?:/|$)#', $path ) && ! preg_match( '#/wp-admin/(?:admin-ajax|admin-post)\.php$#', $path ) && $status >= 300 ) {
			// 302 to the login page (not signed in) or refused: a signed-in user gets 200, so that is skipped.
			return 'wp-admin';
		}
		if ( preg_match( '/(?:^|&)author=\d/', $query ) || ( false !== strpos( $path, '/wp-json/wp/v2/users' ) || false !== strpos( $path, '/' . rest_get_url_prefix() . '/wp/v2/users' ) ) || false !== strpos( $query, 'rest_route=/wp/v2/users' ) ) {
			return 'user enumeration';
		}
		// phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- File names, lowercased.
		if ( preg_match( '#/\.(?:env|git|svn|hg|aws|ssh|docker|htpasswd|ds_store)|/wp-config\.(?:php[~._\-].*|bak|old|orig|save|txt|swp)$|\.(?:sql|sql\.gz|sqlite|bak|swp)$|/(?:phpmyadmin|pma|myadmin|adminer)(?:/|\.php|$)|/(?:backup|backups|dump|database|db|site|www|wordpress)\.(?:zip|tar|tar\.gz|tgz|rar|7z|sql)$|/(?:shell|c99|r57|wso|alfa|webshell|cmd)\.php$|/vendor/phpunit/|/debug\.log$#', $path ) ) {
			return 'scanner';
		}
		if ( $status >= 400 && $status < 500 && preg_match( '#/wp-content/(?:plugins|themes)/([a-z0-9_.\-]+)#', $path, $m ) ) {
			return 'plugin probe';
		}
		if ( class_exists( 'PNCP_Attacks' ) && method_exists( 'PNCP_Attacks', 'injection_type' ) ) {
			$type = (string) PNCP_Attacks::injection_type( (string) $row['path'] . ( '' !== (string) $row['query'] ? '?' . $row['query'] : '' ) );
			if ( '' !== $type ) {
				return 'injection: ' . $type;
			}
		}
		if ( $agents && '' !== (string) $row['ua'] ) {
			$name = self::bad_bot( (string) $row['ua'], $agents );
			if ( '' !== $name ) {
				return 'bad bot: ' . $name;
			}
		}
		return '';
	}

	/**
	 * The name in the bot list a User-Agent matches ('' = none). Memoised per User-Agent.
	 *
	 * @param string   $ua     User-Agent.
	 * @param string[] $agents Blocked User-Agents.
	 * @return string
	 */
	private static function bad_bot( $ua, $agents ) {
		static $memo = array();
		if ( isset( $memo[ $ua ] ) ) {
			return $memo[ $ua ];
		}
		$name = '';
		if ( PNCP_Bots::ua_in_list( $ua, $agents ) ) {
			foreach ( $agents as $agent ) {
				if ( PNCP_Bots::ua_in_list( $ua, array( $agent ) ) ) {
					$name = ltrim( (string) $agent, '=' );
					break;
				}
			}
		}
		if ( count( $memo ) < 5000 ) {
			$memo[ $ua ] = $name;
		}
		return $name;
	}

	/**
	 * A request for a static file (image, style, script, font, media), which a page view makes dozens of.
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	private static function is_static( $path ) {
		return (bool) preg_match( '#\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav|m4a|pdf)$#i', (string) $path );
	}

	/**
	 * A new analysis (what one run collects before it is stored).
	 *
	 * @return array<string, mixed>
	 */
	private static function new_analysis() {
		$s = PNCP_Options::get();
		return array(
			's'       => $s,
			'cfg'     => self::settings(),
			'agents'  => isset( $s['bot_list'] ) ? PNCP_Options::blocked_agents( $s ) : array(),
			'staff'   => PNCP_Edge::staff(),
			'edge'    => PNCP_Edge::state()['rules'],
			'rules'   => self::active_patterns(),
			'agg'     => array(),
			'minutes' => array(),
			'errors'  => array(),
			'normal'  => array(),
			'points'  => array(),
			'any_rx'  => self::point_any_regex(),
			'hours'   => array(),
			'skip'    => array(),
			'skipped' => 0,
		);
	}

	/**
	 * The URL patterns of the rules that block now, as regular expressions with their labels.
	 *
	 * @return array<string, string> Regex => label.
	 */
	private static function active_patterns() {
		$out = array();
		foreach ( self::rules() as $rule ) {
			if ( empty( $rule['enabled'] ) ) {
				continue;
			}
			foreach ( (array) $rule['patterns'] as $pattern ) {
				$regex         = '#^' . str_replace( '\*', '.*', preg_quote( (string) $pattern, '#' ) ) . '$#i';
				$out[ $regex ] = (string) $rule['label'];
			}
		}
		return $out;
	}

	/**
	 * Is an IP one ScrapeLock never counts: the server, private networks, the administrators of the last
	 * 30 days, CDN edges, search engines' official addresses, always-allowed User-Agents from their IPs?
	 *
	 * @param array<string, mixed> $a   Analysis.
	 * @param array<string, mixed> $row Line.
	 * @return bool
	 */
	private static function spared( &$a, $row ) {
		$memo = $row['ip'] . "\0" . $row['ua'];
		if ( isset( $a['skip'][ $memo ] ) ) {
			return $a['skip'][ $memo ];
		}
		$ip    = (string) $row['ip'];
		$spare = PNCP_Ip::is_local( $ip ) || PNCP_Ip::is_private( $ip ) || isset( $a['staff'][ PNCP_Ip::limit_key( $ip ) ] ) || PNCP_Ip::is_cdn_edge( $ip ) || PNCP_Bots::is_official_crawler_ip( $ip ) || '' !== PNCP_Ip::official_owner( $ip )
			// While the Google / Bing lists are not downloaded: their core ranges (log lines have no DNS check).
			|| PNCP_Options::crawler_fallback_ip( $ip );
		if ( ! $spare && isset( $a['s']['allow_list'] ) ) {
			$spare = PNCP_Bots::allow_list_match( (string) $row['ua'], $ip, $a['s'] );
		}
		if ( ! $spare && in_array( $ip, $a['cfg']['allow'], true ) ) {
			$spare = true;
		}
		if ( count( $a['skip'] ) < 20000 ) {
			$a['skip'][ $memo ] = $spare;
		}
		return $spare;
	}

	/**
	 * Adds one line to the analysis.
	 *
	 * @param array<string, mixed> $a   Analysis.
	 * @param array<string, mixed> $row Parsed line.
	 */
	public static function analyse( &$a, $row ) {
		if ( self::spared( $a, $row ) ) {
			++$a['skipped'];
			return;
		}
		$ip     = (string) $row['ip'];
		$status = (int) $row['status'];
		$sec    = (int) floor( (int) $row['ts'] / 1000 );
		// Blocked at Bunny itself: by one of ScrapeLock's rules, or because the IP is in the pull zone's block list.
		$at_edge = '';
		if ( 403 === $status ) {
			foreach ( $a['rules'] as $regex => $label ) {
				if ( preg_match( $regex, (string) $row['url'] ) ) {
					$at_edge = $label;
					break;
				}
			}
			if ( '' === $at_edge && isset( $a['edge'][ $ip ] ) ) {
				$at_edge = __( 'blocked IP', 'scrapelock' );
			}
		}
		$served = '' !== $at_edge || 0 === strpos( (string) $row['cache'], 'HIT' );
		// Speed: requests for pages (not static files) per IP and minute, all lines (also those WordPress saw).
		if ( ! self::is_static( (string) $row['path'] ) && count( $a['minutes'] ) < 50000 ) {
			$mk                  = $ip . '|' . (int) floor( $sec / 60 );
			$a['minutes'][ $mk ] = isset( $a['minutes'][ $mk ] ) ? $a['minutes'][ $mk ] + 1 : 1;
		}
		if ( $status >= 400 && $status < 500 && count( $a['errors'] ) < 20000 ) {
			if ( ! isset( $a['errors'][ $ip ] ) ) {
				$a['errors'][ $ip ] = array(
					'n'     => 0,
					'paths' => array(),
				);
			}
			++$a['errors'][ $ip ]['n'];
			$p = (string) $row['path'];
			if ( count( $a['errors'][ $ip ]['paths'] ) < 50 || isset( $a['errors'][ $ip ]['paths'][ $p ] ) ) {
				$a['errors'][ $ip ]['paths'][ $p ] = isset( $a['errors'][ $ip ]['paths'][ $p ] ) ? $a['errors'][ $ip ]['paths'][ $p ] + 1 : 1;
			}
		}
		// 3.9: normal page views per IP (answered, not a static file, not attack-looking), for the lock preview.
		$detail = null;
		if ( $status >= 200 && $status < 400 && '' === $at_edge && ! self::is_static( (string) $row['path'] ) && ( isset( $a['normal'][ $ip ] ) || count( $a['normal'] ) < 20000 ) && ! self::is_point( $a, (string) $row['url'] ) ) {
			$detail = self::classify( $row, $a['agents'] );
			if ( '' === $detail ) {
				$a['normal'][ $ip ] = isset( $a['normal'][ $ip ] ) ? $a['normal'][ $ip ] + 1 : 1;
			}
		}
		// Requests that reached WordPress were already recorded there, unless "bunny_all_lines" asks for them too.
		if ( ! $served && ! $a['cfg']['all_lines'] ) {
			return;
		}
		$detail = null === $detail ? self::classify( $row, $a['agents'] ) : $detail;
		if ( '' === $detail && '' === $at_edge ) {
			return;
		}
		if ( '' === $detail ) {
			$detail = 'blocked at CDN';
		}
		$blocked = '' !== $at_edge || 403 === $status || 429 === $status;
		$path    = 0 === strpos( $detail, 'bad bot' ) ? '' : (string) $row['path'];
		self::count_up( $a, $path, $ip, $blocked, '' !== $at_edge ? $detail . ' (' . __( 'blocked at Bunny', 'scrapelock' ) . ')' : $detail, $sec );
	}

	/**
	 * Adds one event to the aggregates.
	 *
	 * @param array<string, mixed> $a       Analysis.
	 * @param string               $path    Path.
	 * @param string               $ip      IP.
	 * @param bool                 $blocked Refused.
	 * @param string               $detail  Detail.
	 * @param int                  $sec     Time of the request.
	 * @param int                  $hits    Count.
	 */
	private static function count_up( &$a, $path, $ip, $blocked, $detail, $sec, $hits = 1 ) {
		$key = md5( $path . '|' . $ip . '|' . $detail . '|' . ( $blocked ? 1 : 0 ) );
		if ( ! isset( $a['agg'][ $key ] ) ) {
			if ( count( $a['agg'] ) >= self::MAX_AGGREGATES ) {
				$ip  = ''; // Too many: kept without the address.
				$key = md5( $path . '||' . $detail . '|' . ( $blocked ? 1 : 0 ) );
			}
			if ( ! isset( $a['agg'][ $key ] ) ) {
				$a['agg'][ $key ] = array(
					'path'    => $path,
					'ip'      => $ip,
					'blocked' => $blocked,
					'detail'  => $detail,
					'hits'    => 0,
				);
			}
		}
		$a['agg'][ $key ]['hits'] += $hits;
		$hour                      = (int) ( floor( $sec / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
		if ( ! isset( $a['hours'][ $hour ] ) ) {
			$a['hours'][ $hour ] = array( 0, 0 );
		}
		$a['hours'][ $hour ][0] += $hits;
		$a['hours'][ $hour ][1] += $blocked ? $hits : 0;
	}

	/**
	 * Stores what a run found: the attack record (PNCP_Attacks, category "edge"), the hourly counts and,
	 * when turned on, violations for IPs that were too fast at the edge.
	 *
	 * @param array<string, mixed> $a     Analysis.
	 * @param array<string, mixed> $state State (counts are added).
	 * @return int Events found.
	 */
	public static function store( &$a, &$state ) {
		$cfg = $a['cfg'];
		// Floods of errors (404, 403…) per IP.
		if ( $cfg['flood'] > 0 ) {
			foreach ( $a['errors'] as $ip => $e ) {
				if ( $e['n'] >= $cfg['flood'] ) {
					arsort( $e['paths'] );
					self::count_up( $a, (string) key( $e['paths'] ), (string) $ip, false, '4xx flood', time(), 1 );
				}
			}
		}
		// Too fast at the edge: one violation per IP and minute over the limit, for the last hour only.
		$anonymized = self::logs_anonymized( $state );
		$struck     = 0;
		if ( $cfg['strikes'] && $cfg['rate'] > 0 && ! $anonymized ) {
			$since = (int) floor( ( time() - HOUR_IN_SECONDS ) / 60 );
			$fast  = array();
			foreach ( $a['minutes'] as $mk => $n ) {
				list( $ip, $minute ) = explode( '|', $mk );
				if ( $n > $cfg['rate'] && (int) $minute >= $since ) {
					$fast[ $ip ] = isset( $fast[ $ip ] ) ? $fast[ $ip ] + 1 : 1;
				}
			}
			foreach ( $fast as $ip => $minutes ) {
				self::count_up( $a, '', (string) $ip, false, 'too fast at the CDN', time(), 1 );
				for ( $i = 0; $i < $minutes && $i < 20; $i++ ) {
					++$struck;
					if ( PNCP_Log::strike( (string) $ip, self::REASON ) ) {
						break;
					}
				}
			}
		}
		$found = 0;
		$rec   = class_exists( 'PNCP_Attacks' ) && method_exists( 'PNCP_Attacks', 'record' );
		foreach ( $a['agg'] as $event ) {
			$found += (int) $event['hits'];
			if ( ! $rec ) {
				continue;
			}
			$hits = min( 100000, (int) $event['hits'] );
			if ( method_exists( 'PNCP_Attacks', 'record_hits' ) ) {
				PNCP_Attacks::record_hits( 'edge', (string) $event['path'], (string) $event['ip'], (bool) $event['blocked'], (string) $event['detail'], $hits );
				continue;
			}
			for ( $i = 0; $i < $hits; $i++ ) {
				PNCP_Attacks::record( 'edge', (string) $event['path'], (string) $event['ip'], (bool) $event['blocked'], (string) $event['detail'] );
			}
		}
		if ( $rec && method_exists( 'PNCP_Attacks', 'flush' ) ) {
			PNCP_Attacks::flush();
		}
		self::note_normal( $a, $state );
		$hours = isset( $state['hours'] ) && is_array( $state['hours'] ) ? $state['hours'] : array();
		foreach ( $a['hours'] as $hour => $n ) {
			$old            = isset( $hours[ $hour ] ) ? (array) $hours[ $hour ] : array( 0, 0 );
			$hours[ $hour ] = array( (int) $old[0] + $n[0], (int) ( isset( $old[1] ) ? $old[1] : 0 ) + $n[1] );
		}
		$keep = time() - 8 * DAY_IN_SECONDS;
		foreach ( array_keys( $hours ) as $hour ) {
			if ( (int) $hour < $keep ) {
				unset( $hours[ $hour ] );
			}
		}
		ksort( $hours );
		$state['hours']   = $hours;
		$state['struck']  = $struck;
		$state['skipped'] = (int) $a['skipped'];
		$a['agg']         = array();
		return $found;
	}

	/**
	 * The attacks seen at the edge in the last N hours.
	 *
	 * @param int $hours Hours.
	 * @return array{seen:int, blocked:int}
	 */
	public static function seen( $hours ) {
		$since = time() - (int) $hours * HOUR_IN_SECONDS;
		$out   = array(
			'seen'    => 0,
			'blocked' => 0,
		);
		foreach ( self::state()['hours'] as $hour => $n ) {
			if ( (int) $hour + HOUR_IN_SECONDS > $since ) {
				$out['seen']    += (int) $n[0];
				$out['blocked'] += isset( $n[1] ) ? (int) $n[1] : 0;
			}
		}
		return $out;
	}

	/* ---------- 3.9: full or anonymized IPs in the logs ---------- */

	/**
	 * An empty sample of the IPs of log lines.
	 *
	 * @return array<string, int>
	 */
	public static function new_ip_sample() {
		return array(
			'full'   => 0,
			'hidden' => 0,
			'v6'     => 0,
		);
	}

	/**
	 * What the IP field of a raw log line looks like: 'full', 'hidden' (anonymized: IPv4 ending in .0, IPv6
	 * whose last group is zero, which includes a zeroed second half, or cut off, a masked or missing address)
	 * or '' (not a log line). A real IPv6 address ends in :0 about once in 65536.
	 *
	 * Bunny's "Log anonymization" either replaces the last part of the address with zero ("one digit") or
	 * drops the address; both are seen here, also when parse_line() skips the line for want of an IP.
	 *
	 * @param string $line Raw line.
	 * @return string
	 */
	public static function ip_kind( $line ) {
		$f = explode( '|', trim( (string) $line ) );
		if ( count( $f ) < 8 ) {
			return '';
		}
		$ip = strtolower( trim( $f[5] ) );
		if ( '' === $ip || '-' === $ip || '0.0.0.0' === $ip || '::' === $ip ) {
			return 'hidden';
		}
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return '0' === substr( $ip, strrpos( $ip, '.' ) + 1 ) ? 'hidden' : 'full';
		}
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$bin = inet_pton( $ip );
			// 3.9: the last group zeroed ("one digit", as the last octet of IPv4) or the whole second half.
			return ( false !== $bin && "\0\0" === substr( $bin, -2 ) ) ? 'hidden_v6' : 'full_v6';
		}
		// Masked with x or a star, or cut off after a few groups of the address.
		if ( preg_match( '/^[0-9a-f:.]*[x*][0-9a-fx*:.]*$/', $ip ) || preg_match( '/^[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){1,6}:?$/', $ip ) || preg_match( '/^\d{1,3}(?:\.\d{1,3}){1,2}\.?$/', $ip ) ) {
			return 'hidden';
		}
		return '';
	}

	/**
	 * Adds one raw line to a sample.
	 *
	 * @param array<string, int> $sample Sample.
	 * @param string             $line   Raw line.
	 */
	public static function sample_ip( &$sample, $line ) {
		$kind = self::ip_kind( $line );
		if ( '' === $kind ) {
			return;
		}
		if ( '_v6' === substr( $kind, -3 ) ) {
			++$sample['v6'];
			$kind = substr( $kind, 0, -3 );
		}
		++$sample[ $kind ];
	}

	/**
	 * The new result of the check, from the last one and the lines of this run. Runs with few lines are added
	 * up until there are IP_SAMPLE_MIN of them, so a quiet site is checked too, and a few real addresses
	 * ending in .0 never make the logs look anonymized.
	 *
	 * @param array<string, mixed> $old    Last result (state "ips").
	 * @param array<string, int>   $sample Lines of this run.
	 * @return array{status:string, time:int, lines:int, hidden:int, v6:int, pending:array<string, int>, looked:int}
	 */
	public static function ip_verdict( $old, $sample ) {
		$old     = is_array( $old ) ? $old : array();
		$out     = array(
			'status'  => isset( $old['status'] ) && in_array( $old['status'], array( 'full', 'anonymized' ), true ) ? (string) $old['status'] : 'unknown',
			'time'    => isset( $old['time'] ) ? (int) $old['time'] : 0,
			'lines'   => isset( $old['lines'] ) ? (int) $old['lines'] : 0,
			'hidden'  => isset( $old['hidden'] ) ? (int) $old['hidden'] : 0,
			'v6'      => isset( $old['v6'] ) ? (int) $old['v6'] : 0,
			'pending' => self::new_ip_sample(),
			'looked'  => time(),
		);
		$pending = isset( $old['pending'] ) && is_array( $old['pending'] ) ? $old['pending'] : array();
		foreach ( $out['pending'] as $key => $n ) {
			$out['pending'][ $key ] = ( isset( $pending[ $key ] ) ? (int) $pending[ $key ] : 0 ) + ( isset( $sample[ $key ] ) ? (int) $sample[ $key ] : 0 );
		}
		$total = $out['pending']['full'] + $out['pending']['hidden'];
		/**
		 * Filters the fewest log lines the check "full or anonymized IPs" decides on (20 by default).
		 *
		 * @param int $lines Lines.
		 */
		$min = max( 1, (int) apply_filters( 'pncp_bunny_ip_sample_min', self::IP_SAMPLE_MIN ) );
		if ( $total >= $min ) {
			$out['status']  = $out['pending']['hidden'] >= self::IP_SAMPLE_SHARE * $total ? 'anonymized' : 'full';
			$out['time']    = time();
			$out['lines']   = $total;
			$out['hidden']  = $out['pending']['hidden'];
			$out['v6']      = $out['pending']['v6'];
			$out['pending'] = self::new_ip_sample();
		}
		return $out;
	}

	/**
	 * Are the IPs in the logs anonymized? The check of the lines when there is one, else what the pull zone says.
	 *
	 * @param array<string, mixed>|null $state State (null = read it).
	 * @return bool
	 */
	public static function logs_anonymized( $state = null ) {
		$state = null === $state ? self::state() : $state;
		$ips   = isset( $state['ips'] ) && is_array( $state['ips'] ) ? $state['ips'] : array();
		if ( isset( $ips['status'] ) && in_array( $ips['status'], array( 'full', 'anonymized' ), true ) ) {
			return 'anonymized' === $ips['status'];
		}
		return ! empty( $state['logging']['anonymized'] );
	}

	/**
	 * The result of the check in words, and whether it is a warning.
	 *
	 * @param array<string, mixed>|null $state State (null = read it).
	 * @return array{0:string, 1:bool}
	 */
	public static function ip_check_text( $state = null ) {
		$state = null === $state ? self::state() : $state;
		$ips   = is_array( $state['ips'] ) ? $state['ips'] : array();
		$st    = isset( $ips['status'] ) ? (string) $ips['status'] : 'unknown';
		if ( 'full' === $st ) {
			return array(
				/* translators: 1: date and time, 2: number of log lines */
				sprintf( __( 'The logs have full IPs (checked %1$s, on %2$s lines).', 'scrapelock' ), self::when( (int) $ips['time'] ), number_format_i18n( (int) $ips['lines'] ) ),
				false,
			);
		}
		if ( 'anonymized' === $st ) {
			return array(
				sprintf(
					/* translators: 1: lines with a hidden IP, 2: lines checked, 3: date and time */
					__( 'Log anonymization is on: ScrapeLock cannot block from the logs (%1$s of %2$s lines without a full IP, checked %3$s). The attacks are still counted, with the shortened addresses Bunny writes. To turn it off, in the bunny.net dashboard: CDN → your pull zone → Logging → turn off “Log anonymization”, then save.', 'scrapelock' ),
					number_format_i18n( (int) $ips['hidden'] ),
					number_format_i18n( (int) $ips['lines'] ),
					self::when( (int) $ips['time'] )
				),
				true,
			);
		}
		$seen = isset( $ips['pending'] ) && is_array( $ips['pending'] ) ? (int) array_sum( array_intersect_key( $ips['pending'], array_flip( array( 'full', 'hidden' ) ) ) ) : 0;
		if ( ! empty( $ips['looked'] ) ) {
			return array(
				/* translators: 1: lines read so far, 2: lines needed, 3: date and time */
				sprintf( __( 'Not yet known whether the logs have full IPs: %1$s of %2$s log lines needed so far (last look %3$s).', 'scrapelock' ), number_format_i18n( $seen ), number_format_i18n( self::IP_SAMPLE_MIN ), self::when( (int) $ips['looked'] ) ),
				false,
			);
		}
		return array( __( 'Not yet checked whether the logs have full IPs: every import checks it.', 'scrapelock' ), false );
	}

	/**
	 * The line of the check in the "Logs" list of the card.
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function render_ip_check( $state ) {
		$text = self::ip_check_text( $state );
		echo '<li class="pncp-bunny-ips' . ( $text[1] ? ' pncp-edge-error' : '' ) . '">' . ( $text[1] ? '<strong>' : '' ) . esc_html( $text[0] ) . ( $text[1] ? '</strong>' : '' ) . '</li>';
	}

	/* ---------- 3.9: "What would be blocked", before every lock at Bunny ---------- */

	/**
	 * Keeps the normal page views of the IPs that also attacked in this run (from the logs), for the preview.
	 * Only those IPs: the addresses of ordinary visitors are not stored.
	 *
	 * @param array<string, mixed> $a     Analysis.
	 * @param array<string, mixed> $state State.
	 */
	private static function note_normal( &$a, &$state ) {
		$normal = isset( $state['normal'] ) && is_array( $state['normal'] ) ? $state['normal'] : array();
		$now    = time();
		$ips    = array();
		foreach ( $a['agg'] as $event ) {
			$ips[] = (string) $event['ip'];
		}
		// 3.9: and the IPs that asked for an address that can be locked at Bunny (wp-login.php, xmlrpc.php…).
		foreach ( $a['points'] as $days ) {
			foreach ( $days as $c ) {
				$ips = array_merge( $ips, array_map( 'strval', array_keys( $c['ips'] ) ) );
			}
		}
		foreach ( array_unique( $ips ) as $ip ) {
			if ( '' === $ip || empty( $a['normal'][ $ip ] ) ) {
				continue;
			}
			$old                = isset( $normal[ $ip ] ) && is_array( $normal[ $ip ] ) ? $normal[ $ip ] : array( 0, 0 );
			$normal[ $ip ]      = array( (int) $old[0] + (int) $a['normal'][ $ip ], $now );
			$a['normal'][ $ip ] = 0; // Counted once, even when the IP has several events.
		}
		$keep = $now - 8 * DAY_IN_SECONDS;
		foreach ( $normal as $ip => $n ) {
			if ( ! is_array( $n ) || (int) $n[1] < $keep ) {
				unset( $normal[ $ip ] );
			}
		}
		if ( count( $normal ) > self::MAX_NORMAL ) {
			uasort(
				$normal,
				static function ( $x, $y ) {
					return (int) $y[1] - (int) $x[1];
				}
			);
			$normal = array_slice( $normal, 0, self::MAX_NORMAL, true );
		}
		$state['normal'] = $normal;
		self::note_points( $a, $state );
	}

	/**
	 * 3.9: the URL patterns of every address that can be locked at Bunny (the presets and the hardening points
	 * with a rule at the CDN), as Bunny matches them: on the whole URL, "*" for anything, case-insensitive.
	 *
	 * @return array<string, string> Pattern => regular expression.
	 */
	public static function point_patterns() {
		$patterns = array();
		foreach ( self::presets() as $preset ) {
			$patterns = array_merge( $patterns, array_map( 'strval', isset( $preset['patterns'] ) ? (array) $preset['patterns'] : array() ) );
		}
		if ( class_exists( 'PNCP_Hardening' ) && method_exists( 'PNCP_Hardening', 'points' ) ) {
			foreach ( PNCP_Hardening::points() as $point ) {
				$patterns = array_merge( $patterns, array_map( 'strval', isset( $point['edge'] ) ? (array) $point['edge'] : array() ) );
			}
		}
		$out = array();
		foreach ( array_unique( $patterns ) as $pattern ) {
			if ( '' !== trim( $pattern, '*' ) ) {
				$out[ $pattern ] = '#^' . str_replace( '\*', '.*', preg_quote( $pattern, '#' ) ) . '$#i';
			}
		}
		return $out;
	}

	/**
	 * One regular expression for all of point_patterns(), to skip most lines with one test ('' = none).
	 *
	 * @return string
	 */
	private static function point_any_regex() {
		$parts = array();
		foreach ( array_keys( self::point_patterns() ) as $pattern ) {
			$parts[] = str_replace( '\*', '.*', preg_quote( $pattern, '#' ) );
		}
		return $parts ? '#^(?:' . implode( '|', $parts ) . ')$#i' : '';
	}

	/**
	 * Does the URL of a log line ask for an address that can be locked at Bunny?
	 *
	 * @param array<string, mixed> $a   Analysis.
	 * @param string               $url URL of the line.
	 * @return bool
	 */
	private static function is_point( $a, $url ) {
		return ! empty( $a['any_rx'] ) && preg_match( $a['any_rx'], $url );
	}

	/**
	 * Counts a log line on every lockable address it asks for: all requests, attacks or not, per day (UTC), with
	 * the IPs (at most POINT_IPS per address and day; the requests of the others are counted all the same).
	 *
	 * @param array<string, mixed> $a   Analysis.
	 * @param array<string, mixed> $row Parsed line.
	 */
	private static function count_points( &$a, $row ) {
		$url = (string) $row['url'];
		if ( ! self::is_point( $a, $url ) ) {
			return;
		}
		if ( ! isset( $a['point_rx'] ) ) {
			$a['point_rx'] = self::point_patterns();
		}
		$ip  = (string) $row['ip'];
		$day = (int) floor( (int) $row['ts'] / 1000 / DAY_IN_SECONDS );
		foreach ( $a['point_rx'] as $pattern => $regex ) {
			if ( ! preg_match( $regex, $url ) ) {
				continue;
			}
			if ( ! isset( $a['points'][ $pattern ][ $day ] ) ) {
				$a['points'][ $pattern ][ $day ] = array(
					'n'      => 0,
					'ips'    => array(),
					'capped' => 0,
				);
			}
			$c = &$a['points'][ $pattern ][ $day ];
			++$c['n'];
			if ( isset( $c['ips'][ $ip ] ) ) {
				++$c['ips'][ $ip ];
			} elseif ( count( $c['ips'] ) < self::POINT_IPS ) {
				$c['ips'][ $ip ] = 1;
			} else {
				$c['capped'] = 1;
			}
			unset( $c );
		}
	}

	/**
	 * Adds the counts of a run to the state, and drops the days older than POINT_DAYS.
	 *
	 * @param array<string, mixed> $a     Analysis.
	 * @param array<string, mixed> $state State.
	 */
	private static function note_points( $a, &$state ) {
		$points = isset( $state['points'] ) && is_array( $state['points'] ) ? $state['points'] : array();
		foreach ( $a['points'] as $pattern => $days ) {
			foreach ( $days as $day => $c ) {
				$empty    = array(
					'n'      => 0,
					'ips'    => array(),
					'capped' => 0,
				);
				$old      = isset( $points[ $pattern ][ $day ] ) && is_array( $points[ $pattern ][ $day ] ) ? $points[ $pattern ][ $day ] : $empty;
				$old['n'] = (int) $old['n'] + (int) $c['n'];
				foreach ( $c['ips'] as $ip => $n ) {
					if ( isset( $old['ips'][ $ip ] ) ) {
						$old['ips'][ $ip ] = (int) $old['ips'][ $ip ] + (int) $n;
					} elseif ( count( $old['ips'] ) < self::POINT_IPS ) {
						$old['ips'][ $ip ] = (int) $n;
					} else {
						$old['capped'] = 1;
					}
				}
				$old['capped']              = ! empty( $old['capped'] ) || ! empty( $c['capped'] ) ? 1 : 0;
				$points[ $pattern ][ $day ] = $old;
			}
		}
		$keep = (int) floor( time() / DAY_IN_SECONDS ) - self::POINT_DAYS;
		foreach ( $points as $pattern => $days ) {
			foreach ( (array) $days as $day => $c ) {
				if ( (int) $day < $keep ) {
					unset( $points[ $pattern ][ $day ] );
				}
			}
			if ( empty( $points[ $pattern ] ) ) {
				unset( $points[ $pattern ] );
			}
		}
		if ( empty( $state['points_0'] ) ) {
			$state['points_0'] = time(); // Since when the logs are counted (3.9).
		}
		$state['points'] = $points;
	}

	/**
	 * The requests of the last N days (UTC days, today included) for the given patterns, from the logs: all of
	 * them, attacks or not.
	 *
	 * @param string[] $patterns Patterns.
	 * @param int      $days     Days.
	 * @return array{available:bool, since:int, requests:int, ips:int, capped:bool, anonymized:bool, top:array<string, int>, allowed:int}
	 */
	public static function preview_logs( $patterns, $days ) {
		$state = self::state();
		$out   = array(
			'available'  => self::settings()['import'] && ! empty( $state['last_ok'] ) && ! empty( $state['points_0'] ),
			'since'      => (int) $state['points_0'],
			'requests'   => 0,
			'ips'        => 0,
			'capped'     => false,
			'anonymized' => self::logs_anonymized( $state ),
			'top'        => array(),
			'allowed'    => 0, // Set by lock_preview(): IPs of these let through by the rule.
		);
		$from  = (int) floor( time() / DAY_IN_SECONDS ) - max( 1, (int) $days ) + 1;
		$ips   = array();
		foreach ( array_unique( array_map( 'strval', (array) $patterns ) ) as $pattern ) {
			if ( ! isset( $state['points'][ $pattern ] ) || ! is_array( $state['points'][ $pattern ] ) ) {
				continue;
			}
			foreach ( $state['points'][ $pattern ] as $day => $c ) {
				if ( (int) $day < $from || ! is_array( $c ) ) {
					continue;
				}
				$out['requests'] += (int) $c['n'];
				$out['capped']    = $out['capped'] || ! empty( $c['capped'] );
				foreach ( (array) $c['ips'] as $ip => $n ) {
					$ips[ (string) $ip ] = ( isset( $ips[ (string) $ip ] ) ? $ips[ (string) $ip ] : 0 ) + (int) $n;
				}
			}
		}
		arsort( $ips );
		$out['ips'] = count( $ips );
		$out['top'] = array_slice( $ips, 0, self::PREVIEW_IPS, true );
		return $out;
	}

	/**
	 * Registers the hidden page of the preview (not in the menu; opened from the "Lock at Bunny" buttons).
	 */
	public static function preview_menu() {
		$hook = add_submenu_page( '', __( 'Lock at Bunny CDN', 'scrapelock' ), '', 'manage_options', self::PREVIEW_PAGE, array( __CLASS__, 'render_preview_page' ) );
		if ( $hook ) {
			add_action(
				'load-' . $hook,
				static function () {
					global $title;
					$title = __( 'Lock at Bunny CDN', 'scrapelock' ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- A hidden page has no title of its own.
				}
			);
		}
	}

	/**
	 * The address of the preview of a lock.
	 *
	 * @param string $kind preset (Bunny card) | harden (hardening point).
	 * @param string $id   Preset or point.
	 * @param string $back Where Cancel and the result go ('' = the Bunny card).
	 * @return string
	 */
	public static function preview_url( $kind, $id, $back = '' ) {
		return add_query_arg(
			array(
				'page'     => self::PREVIEW_PAGE,
				'kind'     => 'harden' === $kind ? 'harden' : 'preset',
				'id'       => sanitize_key( (string) $id ),
				'back'     => rawurlencode( self::preview_back( (string) $back ) ),
				'_wpnonce' => wp_create_nonce( 'pncp_bunny_preview' ),
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * A safe return address in wp-admin, the Bunny card by default.
	 *
	 * @param string $back Address.
	 * @return string
	 */
	private static function preview_back( $back ) {
		$default = PNCP_Status::settings_url( array( 'tab' => 'bots' ) );
		$back    = '' !== $back ? wp_validate_redirect( $back, $default ) : $default;
		// Never back to the preview itself.
		return false !== strpos( $back, 'page=' . self::PREVIEW_PAGE ) ? $default : $back;
	}

	/**
	 * Sends the browser to the preview of a lock (a "Lock at Bunny" click without the confirmation).
	 *
	 * @param string $kind preset | harden.
	 * @param string $id   Preset or point.
	 */
	public static function to_preview( $kind, $id ) {
		$back = wp_get_referer();
		wp_safe_redirect( self::preview_url( $kind, $id, $back ? $back : '' ) );
		exit;
	}

	/**
	 * The nonce action of the confirmation of one lock.
	 *
	 * @param string $kind preset | harden.
	 * @param string $id   Preset or point.
	 * @return string
	 */
	private static function confirm_action( $kind, $id ) {
		return 'pncp_bunny_lock|' . $kind . '|' . $id;
	}

	/**
	 * Was this lock confirmed on its preview? The caller has checked the capability and its own nonce. Also
	 * refuses when the preview now has a blocker (it is built again: the data may have changed meanwhile).
	 *
	 * @param string $kind preset | harden.
	 * @param string $id   Preset or point.
	 * @return bool|WP_Error False: not confirmed (show the preview). WP_Error: refused.
	 */
	public static function lock_confirmed( $kind, $id ) {
		$kind = 'harden' === $kind ? 'harden' : 'preset';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- This is the nonce check.
		$nonce = isset( $_POST['pncp_confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['pncp_confirm'] ) ) : '';
		if ( '' === $nonce || ! wp_verify_nonce( $nonce, self::confirm_action( $kind, (string) $id ) ) ) {
			return false;
		}
		$preview = self::lock_preview( $kind, (string) $id );
		if ( is_wp_error( $preview ) ) {
			return $preview;
		}
		if ( $preview['blockers'] ) {
			return new WP_Error( 'pncp_bunny_blocked', implode( ' ', $preview['blockers'] ) );
		}
		return true;
	}

	/**
	 * What a lock at Bunny would block, and who hit it: the preview shown before every lock.
	 *
	 * Extension point, filter 'pncp_bunny_lock_preview' ( array $preview, string $preset ): other parts add to
	 * $preview['warnings'] (strings, shown above the Confirm button) and $preview['blockers'] (strings: any
	 * blocker disables Confirm, and lock_confirmed() refuses the lock while one remains). $preset is the key of
	 * presets() ('login', 'xmlrpc', 'probes', 'core_files'…), or 'harden_<point>' for a hardening point without
	 * a preset. The other keys of $preview are described below; they are for display only.
	 *
	 * @param string $kind preset (Bunny card) | harden (hardening point).
	 * @param string $id   Preset or point.
	 * @return array<string, mixed>|WP_Error {
	 *     @type string   $kind      preset | harden.
	 *     @type string   $id        Preset or point.
	 *     @type string   $preset    Preset key passed to the filter.
	 *     @type string   $label     Name of the point.
	 *     @type string   $blocks    What it blocks.
	 *     @type string   $breaks    What may stop working.
	 *     @type string[] $patterns  URL patterns Bunny refuses.
	 *     @type string[] $except    URL patterns let through.
	 *     @type string[] $allow     IPs let through.
	 *     @type bool     $locked    Already locked.
	 *     @type bool     $enforcing The rule blocks now (false: Monitor only or protection off).
	 *     @type array    $hits      See preview_hits().
	 *     @type array    $logs      See preview_logs().
	 *     @type array    $normal    See preview_normal().
	 *     @type string[] $warnings  Warnings.
	 *     @type string[] $blockers  Reasons the lock is refused.
	 * }
	 */
	public static function lock_preview( $kind, $id ) {
		$kind    = 'harden' === $kind ? 'harden' : 'preset';
		$id      = sanitize_key( (string) $id );
		$presets = self::presets();
		$preview = array(
			'kind'      => $kind,
			'id'        => $id,
			'preset'    => $id,
			'label'     => '',
			'blocks'    => '',
			'breaks'    => '',
			'patterns'  => array(),
			'except'    => array(),
			'allow'     => array(),
			'locked'    => false,
			'enforcing' => self::enforcing(),
			'hits'      => array(),
			'logs'      => array(),
			'normal'    => array(),
			'warnings'  => array(),
			'blockers'  => array(),
		);
		if ( 'preset' === $kind ) {
			if ( ! isset( $presets[ $id ] ) ) {
				return new WP_Error( 'pncp_unknown', __( 'Unknown preset.', 'scrapelock' ) );
			}
			$p                   = $presets[ $id ];
			$preview['label']    = (string) $p['label'];
			$preview['blocks']   = (string) $p['blocks'];
			$preview['breaks']   = (string) $p['breaks'];
			$preview['patterns'] = array_values( (array) $p['patterns'] );
			$preview['except']   = array_values( (array) $p['except'] );
			$preview['locked']   = self::preset_locked( $id );
			if ( self::via_hardening( $p ) ) {
				// Locked through the hardening point: the point's patterns are the ones sent.
				$point               = PNCP_Hardening::point( (string) $p['harden'] );
				$preview['patterns'] = array_values( (array) $point['edge'] );
				$preview['except']   = array();
			}
			if ( 'login' === $id ) {
				// A lock made from 3.9 sends only the confirmed list ("Allowed IPs for the login page at Bunny").
				$preview['allow'] = self::login_allow_list();
			}
		} else {
			$point = class_exists( 'PNCP_Hardening' ) && method_exists( 'PNCP_Hardening', 'point' ) ? PNCP_Hardening::point( $id ) : null;
			if ( ! is_array( $point ) || empty( $point['edge'] ) ) {
				return new WP_Error( 'pncp_unknown', __( 'This point cannot be locked at the CDN.', 'scrapelock' ) );
			}
			$preview['label']    = (string) $point['label'];
			$preview['patterns'] = array_values( (array) $point['edge'] );
			$preview['locked']   = isset( self::rules()[ 'harden_' . $id ] );
			$preview['preset']   = 'harden_' . $id;
			foreach ( $presets as $key => $p ) {
				if ( isset( $p['harden'] ) && $id === $p['harden'] ) {
					$preview['preset'] = (string) $key;
					$preview['blocks'] = (string) $p['blocks'];
					$preview['breaks'] = (string) $p['breaks'];
					break;
				}
			}
			if ( '' === $preview['blocks'] && isset( $point['blocks'] ) && is_string( $point['blocks'] ) ) {
				$preview['blocks'] = $point['blocks'];
			}
		}
		$preview['hits'] = self::preview_hits( $preview['patterns'], 7 );
		$preview['logs'] = self::preview_logs( $preview['patterns'], 7 ); // 3.9: every request in the logs, attacks or not.
		$ips             = $preview['hits']['top'];
		foreach ( $preview['logs']['top'] as $ip => $n ) {
			$ips[ $ip ] = max( isset( $ips[ $ip ] ) ? (int) $ips[ $ip ] : 0, (int) $n );
		}
		$preview['logs']['allowed'] = 0;
		foreach ( array_keys( $ips ) as $ip ) {
			if ( $preview['allow'] && PNCP_Ip::in_any( (string) $ip, (array) $preview['allow'] ) ) {
				$preview['logs']['allowed'] += isset( $preview['logs']['top'][ $ip ] ) ? 1 : 0;
				unset( $ips[ $ip ] ); // Let through by the rule (the allowed IPs of the login page): not refused.
			}
		}
		arsort( $ips );
		$preview['normal'] = self::preview_normal( array_slice( $ips, 0, self::PREVIEW_IPS, true ) );
		if ( $preview['locked'] ) {
			$preview['warnings'][] = __( 'This point is already locked at Bunny: Confirm sends the rule again.', 'scrapelock' );
		}
		if ( ! $preview['enforcing'] ) {
			$preview['warnings'][] = __( 'ScrapeLock does not block now (Monitor only or protection off): the rule is created switched off, and switched on when ScrapeLock blocks again.', 'scrapelock' );
		}
		if ( $preview['normal']['found'] > 0 ) {
			$preview['warnings'][] = sprintf(
				/* translators: %s: number of IPs */
				_n( '%s IP that hit these addresses also used the site normally: check the list above before you lock.', '%s IPs that hit these addresses also used the site normally: check the list above before you lock.', $preview['normal']['found'], 'scrapelock' ),
				number_format_i18n( $preview['normal']['found'] )
			);
		}
		/**
		 * Filters the preview of a lock at Bunny: add 'warnings' (shown) or 'blockers' (refuse the lock).
		 *
		 * @param array<string, mixed> $preview Preview, see PNCP_Bunny::lock_preview().
		 * @param string               $preset  Preset key, or 'harden_<point>'.
		 */
		$filtered = apply_filters( 'pncp_bunny_lock_preview', $preview, $preview['preset'] );
		if ( is_array( $filtered ) ) {
			foreach ( array( 'warnings', 'blockers' ) as $key ) {
				$preview[ $key ] = isset( $filtered[ $key ] ) ? array_values( array_filter( array_map( 'strval', (array) $filtered[ $key ] ), 'strlen' ) ) : $preview[ $key ];
			}
			$preview = array_merge( $filtered, array_intersect_key( $preview, array_flip( array( 'kind', 'id', 'preset', 'warnings', 'blockers' ) ) ) );
		}
		return $preview;
	}

	/**
	 * A URL pattern of a rule ("*" = anything) as a LIKE on the recorded path. The record keeps the path without
	 * the host and the query, which is what the patterns' "*" at both ends stand for.
	 *
	 * @param string $pattern Pattern.
	 * @return string
	 */
	private static function pattern_like( $pattern ) {
		global $wpdb;
		$pattern = (string) preg_replace( '#^\*?https?://[^/*]*#i', '*', (string) $pattern );
		return implode( '%', array_map( array( $wpdb, 'esc_like' ), explode( '*', $pattern ) ) );
	}

	/**
	 * The requests of the last N days on paths that match the patterns, from the attack record (every category,
	 * also "edge" from the imported Bunny logs).
	 *
	 * @param string[] $patterns Patterns.
	 * @param int      $days     Days.
	 * @return array{available:bool, requests:int, blocked:int, ips:int, no_ip:int, categories:array<string, int>, top:array<string, int>}
	 */
	public static function preview_hits( $patterns, $days ) {
		global $wpdb;
		$out   = array(
			'available'  => false,
			'requests'   => 0,
			'blocked'    => 0,
			'ips'        => 0,
			'no_ip'      => 0,
			'categories' => array(),
			'top'        => array(),
		);
		$likes = array();
		foreach ( array_slice( (array) $patterns, 0, self::MAX_PATTERNS ) as $pattern ) {
			$like = self::pattern_like( (string) $pattern );
			if ( '' !== trim( $like, '%' ) ) {
				$likes[] = $like;
			}
		}
		if ( ! $likes || ! class_exists( 'PNCP_Attacks' ) || ! method_exists( 'PNCP_Attacks', 'ready' ) || ! PNCP_Attacks::ready() ) {
			return $out;
		}
		$out['available'] = true;
		$since            = (int) ( floor( ( time() - (int) $days * DAY_IN_SECONDS ) / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
		$where            = '(' . implode( ' OR ', array_fill( 0, count( $likes ), 'path LIKE %s' ) ) . ')';
		$args             = array_merge( array( PNCP_Attacks::table(), $since ), $likes );
		// Rows with no request (hits = 0: e.g. a visit to wp-login.php that ended in a sign-in that worked) are left
		// out, as in the attack report.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- $where holds only "path LIKE %s" placeholders, filled by prepare(); an admin page, not cached.
		$total = $wpdb->get_row( $wpdb->prepare( "SELECT SUM(hits) AS hits, SUM(blocked) AS blocked, COUNT(DISTINCT NULLIF(ip, '')) AS ips, SUM(CASE WHEN ip = '' THEN hits ELSE 0 END) AS no_ip FROM %i WHERE hour_ts >= %d AND hits > 0 AND {$where}", $args ), ARRAY_A );
		$cats  = $wpdb->get_results( $wpdb->prepare( "SELECT category, SUM(hits) AS hits FROM %i WHERE hour_ts >= %d AND hits > 0 AND {$where} GROUP BY category ORDER BY hits DESC", $args ), ARRAY_A );
		$top   = $wpdb->get_results( $wpdb->prepare( "SELECT ip, SUM(hits) AS hits FROM %i WHERE hour_ts >= %d AND hits > 0 AND ip <> '' AND {$where} GROUP BY ip ORDER BY hits DESC LIMIT %d", array_merge( $args, array( self::PREVIEW_IPS ) ) ), ARRAY_A );
		// phpcs:enable
		if ( is_array( $total ) ) {
			$out['requests'] = (int) $total['hits'];
			$out['blocked']  = (int) $total['blocked'];
			$out['ips']      = (int) $total['ips'];
			$out['no_ip']    = (int) $total['no_ip'];
		}
		foreach ( (array) $cats as $row ) {
			$out['categories'][ (string) $row['category'] ] = (int) $row['hits'];
		}
		foreach ( (array) $top as $row ) {
			$out['top'][ (string) $row['ip'] ] = (int) $row['hits'];
		}
		return $out;
	}

	/**
	 * Which of the IPs also had normal traffic: an administrator's IP (30 days), a sign-in to any account from it
	 * (30 days), pages read, the human check passed or a sign-in in the reputation record (7 days), normal page
	 * views at Bunny in the imported logs (8 days). Says which sources are not available.
	 *
	 * @param array<string, int> $ips IP => requests on the patterns.
	 * @return array{checked:int, found:int, rows:array<int, array{ip:string, hits:int, why:string[]}>, sources:array<string, bool>}
	 */
	public static function preview_normal( $ips ) {
		global $wpdb;
		$state   = self::state();
		$rep     = class_exists( 'PNCP_Reputation' ) && PNCP_Reputation::active();
		$logs    = self::settings()['import'] && ! self::logs_anonymized( $state ) && ! empty( $state['last_ok'] );
		$out     = array(
			'checked' => 0,
			'found'   => 0,
			'rows'    => array(),
			'sources' => array(
				'admins'     => true,
				'logins'     => class_exists( 'PNCP_Login' ),
				'reputation' => $rep,
				'logs'       => $logs,
			),
		);
		$staff   = PNCP_Edge::staff();
		$known   = array();
		$since30 = time() - 30 * DAY_IN_SECONDS;
		if ( $out['sources']['logins'] && $ips ) {
			// The IPs users signed in from (PNCP_Login, as keyed hashes of the address): at most 500 accounts.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- An admin page, once.
			$metas = $wpdb->get_col( $wpdb->prepare( "SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s LIMIT 500", PNCP_Login::KNOWN_META ) );
			foreach ( (array) $metas as $meta ) {
				foreach ( (array) maybe_unserialize( $meta ) as $hash => $when ) {
					if ( (int) $when > $since30 ) {
						$known[ (string) $hash ] = true;
					}
				}
			}
		}
		$since7 = time() - 7 * DAY_IN_SECONDS;
		foreach ( $ips as $ip => $hits ) {
			$ip = (string) $ip;
			++$out['checked'];
			$why = array();
			$key = PNCP_Ip::limit_key( $ip );
			if ( isset( $staff[ $key ] ) ) {
				$why[] = __( 'an administrator used wp-admin from it (last 30 days)', 'scrapelock' );
			}
			if ( $known && isset( $known[ substr( hash_hmac( 'sha256', $key, wp_salt( 'auth' ) ), 0, 20 ) ] ) ) {
				$why[] = __( 'someone signed in to an account from it (last 30 days)', 'scrapelock' );
			}
			if ( $rep ) {
				$record = PNCP_Reputation::get( $ip );
				$labels = array(
					'login' => __( 'signed in', 'scrapelock' ),
					'human' => __( 'passed the human check', 'scrapelock' ),
					'page'  => __( 'opened pages', 'scrapelock' ),
				);
				foreach ( $labels as $event => $label ) {
					if ( isset( $record[ $event ] ) && (int) $record[ $event ] >= $since7 ) {
						/* translators: %s: what the IP did */
						$why[] = sprintf( __( '%s (reputation record, last 7 days)', 'scrapelock' ), $label );
					}
				}
			}
			if ( $logs && isset( $state['normal'][ $ip ] ) && is_array( $state['normal'][ $ip ] ) ) {
				/* translators: %s: number of pages */
				$why[] = sprintf( __( 'opened %s pages through Bunny (logs)', 'scrapelock' ), number_format_i18n( (int) $state['normal'][ $ip ][0] ) );
			}
			if ( $why ) {
				++$out['found'];
				$out['rows'][] = array(
					'ip'   => $ip,
					'hits' => (int) $hits,
					'why'  => $why,
				);
			}
		}
		return $out;
	}

	/**
	 * The page "Lock at Bunny CDN": what would be blocked, with Confirm and Cancel.
	 */
	public static function render_preview_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Checked just below.
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		$kind  = isset( $_GET['kind'] ) && 'harden' === $_GET['kind'] ? 'harden' : 'preset';
		$id    = isset( $_GET['id'] ) ? sanitize_key( wp_unslash( $_GET['id'] ) ) : '';
		$back  = self::preview_back( isset( $_GET['back'] ) ? esc_url_raw( wp_unslash( $_GET['back'] ) ) : '' );
		// phpcs:enable
		$card = 'preset' === $kind ? PNCP_Edge::reopen( $back, 'pncp-bunny' ) : $back . ( false === strpos( $back, '#' ) ? '#pncp-hardening' : '' ); // 3.9: the card, opened.
		echo '<div class="wrap pncp-bunny-preview">';
		if ( ! wp_verify_nonce( $nonce, 'pncp_bunny_preview' ) ) {
			echo '<h1>' . esc_html__( 'Lock at Bunny CDN', 'scrapelock' ) . '</h1><div class="notice notice-error"><p>' . esc_html__( 'The link has expired. Go back and click “Lock at Bunny” again.', 'scrapelock' ) . '</p></div>';
			echo '<p><a class="button" href="' . esc_url( $card ) . '">' . esc_html__( 'Back', 'scrapelock' ) . '</a></p></div>';
			return;
		}
		$preview = self::lock_preview( $kind, $id );
		if ( is_wp_error( $preview ) ) {
			echo '<h1>' . esc_html__( 'Lock at Bunny CDN', 'scrapelock' ) . '</h1><div class="notice notice-error"><p>' . esc_html( $preview->get_error_message() ) . '</p></div>';
			echo '<p><a class="button" href="' . esc_url( $card ) . '">' . esc_html__( 'Back', 'scrapelock' ) . '</a></p></div>';
			return;
		}
		if ( PNCP_Lockdown::is_locked() ) {
			$preview['blockers'][] = __( 'The site is locked with Lockdown: unlock it to change the rules at Bunny CDN.', 'scrapelock' );
		}
		if ( ! self::edge_available() ) {
			$preview['blockers'][] = __( 'Bunny CDN is not connected.', 'scrapelock' );
		}
		/* translators: %s: name of the point */
		echo '<h1>' . esc_html( sprintf( __( 'Lock at Bunny CDN: %s', 'scrapelock' ), $preview['label'] ) ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Nothing is sent to Bunny until you click “Confirm”.', 'scrapelock' ) . '</p>';
		self::render_preview_what( $preview );
		self::render_preview_hits( $preview );
		self::render_preview_normal( $preview );
		foreach ( $preview['warnings'] as $text ) {
			echo '<div class="notice notice-warning inline pncp-bunny-preview-warning"><p>' . esc_html( (string) $text ) . '</p></div>';
		}
		foreach ( $preview['blockers'] as $text ) {
			echo '<div class="notice notice-error inline pncp-bunny-preview-blocker"><p><strong>' . esc_html( (string) $text ) . '</strong></p></div>';
		}
		$harden = 'harden' === $kind;
		printf( '<form method="post" action="%s" class="pncp-bunny-confirm"><p>', esc_url( admin_url( 'admin-post.php' ) ) );
		echo '<input type="hidden" name="action" value="' . esc_attr( $harden ? PNCP_Hardening::ACTION : self::ACTION ) . '">';
		echo '<input type="hidden" name="op" value="' . esc_attr( $harden ? 'edge_on' : 'lock' ) . '">';
		echo '<input type="hidden" name="id" value="' . esc_attr( $id ) . '">';
		echo '<input type="hidden" name="pncp_confirm" value="' . esc_attr( wp_create_nonce( self::confirm_action( $kind, $id ) ) ) . '">';
		wp_nonce_field( $harden ? PNCP_Hardening::ACTION : self::ACTION, '_wpnonce', false );
		echo '<input type="hidden" name="_wp_http_referer" value="' . esc_attr( $back ) . '">';
		printf( '<button type="submit" class="button button-primary"%1$s>%2$s</button> ', $preview['blockers'] ? ' disabled' : '', esc_html__( 'Confirm: lock at Bunny', 'scrapelock' ) );
		echo '<a class="button" href="' . esc_url( $card ) . '">' . esc_html__( 'Cancel', 'scrapelock' ) . '</a>';
		echo '</p></form></div>';
	}

	/**
	 * Preview: the addresses that will be cut.
	 *
	 * @param array<string, mixed> $preview Preview.
	 */
	private static function render_preview_what( $preview ) {
		echo '<h2>' . esc_html__( 'Addresses Bunny will refuse (403)', 'scrapelock' ) . '</h2>';
		if ( '' !== (string) $preview['blocks'] ) {
			echo '<p>' . esc_html( (string) $preview['blocks'] ) . '</p>';
		}
		echo '<p class="pncp-bunny-preview-patterns">';
		foreach ( (array) $preview['patterns'] as $pattern ) {
			echo '<code>' . esc_html( (string) $pattern ) . '</code> ';
		}
		echo '</p>';
		if ( $preview['except'] ) {
			/* translators: %s: URL patterns */
			echo '<p>' . esc_html( sprintf( __( 'Except the addresses: %s', 'scrapelock' ), implode( ' ', (array) $preview['except'] ) ) ) . '</p>';
		}
		if ( $preview['allow'] ) {
			/* translators: %s: list of IPs */
			echo '<p>' . esc_html( sprintf( __( 'Except from these IPs: %s', 'scrapelock' ), implode( ', ', (array) $preview['allow'] ) ) ) . '</p>';
		}
		if ( '' !== (string) $preview['breaks'] ) {
			echo '<p><strong>' . esc_html__( 'What may stop working:', 'scrapelock' ) . '</strong> ' . esc_html( (string) $preview['breaks'] ) . '</p>';
		}
	}

	/**
	 * Preview: who hit these addresses in the last 7 days.
	 *
	 * @param array<string, mixed> $preview Preview.
	 */
	private static function render_preview_hits( $preview ) {
		$h = $preview['hits'];
		echo '<h2>' . esc_html__( 'Requests on these addresses, last 7 days', 'scrapelock' ) . '</h2>';
		self::render_preview_logs( $preview );
		if ( ! $h['available'] ) {
			echo '<p class="pncp-bunny-preview-hits">' . esc_html__( 'Not available: the attack record is off or not set up, so ScrapeLock cannot say who asked for these addresses.', 'scrapelock' ) . '</p>';
			return;
		}
		echo '<p class="pncp-bunny-preview-hits">' . esc_html(
			sprintf(
				/* translators: 1: requests, 2: IPs, 3: requests already refused */
				__( '%1$s requests from %2$s IPs (%3$s of them already refused).', 'scrapelock' ),
				number_format_i18n( (int) $h['requests'] ),
				number_format_i18n( (int) $h['ips'] ),
				number_format_i18n( (int) $h['blocked'] )
			)
		);
		if ( (int) $h['no_ip'] > 0 ) {
			/* translators: %s: requests */
			echo ' ' . esc_html( sprintf( __( '%s requests were recorded without their address.', 'scrapelock' ), number_format_i18n( (int) $h['no_ip'] ) ) );
		}
		echo '</p>';
		echo '<p class="description">' . esc_html__( 'From the attack record: what WordPress saw, and what Bunny served itself (imported from its logs, when the import is on). Normal visits are not recorded there.', 'scrapelock' ) . '</p>';
		if ( $h['categories'] ) {
			$labels = class_exists( 'PNCP_Attacks' ) ? PNCP_Attacks::categories() : array();
			echo '<table class="widefat striped" style="max-width:640px"><thead><tr><th scope="col">' . esc_html__( 'What', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Requests', 'scrapelock' ) . '</th></tr></thead><tbody>';
			foreach ( $h['categories'] as $cat => $n ) {
				echo '<tr><td>' . esc_html( isset( $labels[ $cat ] ) ? $labels[ $cat ] : (string) $cat ) . '</td><td>' . esc_html( number_format_i18n( (int) $n ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
	}

	/**
	 * Preview: every request on these addresses in the imported Bunny logs.
	 *
	 * @param array<string, mixed> $preview Preview.
	 */
	private static function render_preview_logs( $preview ) {
		$g = isset( $preview['logs'] ) && is_array( $preview['logs'] ) ? $preview['logs'] : array( 'available' => false );
		if ( empty( $g['available'] ) ) {
			echo '<p class="pncp-bunny-preview-logs">' . esc_html__( 'From the Bunny logs: not available (the import from Bunny\'s logs is off or has not run since ScrapeLock 3.9).', 'scrapelock' ) . '</p>';
			return;
		}
		$text = sprintf(
			/* translators: 1: requests, 2: IPs */
			__( 'From the Bunny logs: %1$s requests from %2$s IPs, attacks or not.', 'scrapelock' ),
			number_format_i18n( (int) $g['requests'] ),
			( $g['capped'] ? '≥ ' : '' ) . number_format_i18n( (int) $g['ips'] )
		);
		if ( (int) $g['since'] > time() - 7 * DAY_IN_SECONDS ) {
			/* translators: %s: date and time */
			$text .= ' ' . sprintf( __( 'Counted since %s, so less than 7 days.', 'scrapelock' ), self::when( (int) $g['since'] ) );
		}
		if ( ! empty( $g['allowed'] ) ) {
			/* translators: %s: number of IPs */
			$text .= ' ' . sprintf( _n( '%s of these IPs is in the allowed list and is let through.', '%s of these IPs are in the allowed list and are let through.', (int) $g['allowed'], 'scrapelock' ), number_format_i18n( (int) $g['allowed'] ) );
		}
		if ( ! empty( $g['anonymized'] ) ) {
			$text .= ' ' . __( 'Bunny anonymizes the IPs in the logs, so several visitors may share one shortened address.', 'scrapelock' );
		}
		echo '<p class="pncp-bunny-preview-logs"><strong>' . esc_html( $text ) . '</strong></p>';
	}

	/**
	 * Preview: which of those IPs also used the site normally.
	 *
	 * @param array<string, mixed> $preview Preview.
	 */
	private static function render_preview_normal( $preview ) {
		$n = $preview['normal'];
		echo '<h2>' . esc_html__( 'Normal traffic from the same IPs', 'scrapelock' ) . '</h2>';
		if ( ! $n['checked'] ) {
			echo '<p class="pncp-bunny-preview-normal">' . esc_html__( 'No IP to check: no recorded request on these addresses.', 'scrapelock' ) . '</p>';
		} elseif ( ! $n['found'] ) {
			/* translators: %s: number of IPs */
			echo '<p class="pncp-bunny-preview-normal">' . esc_html( sprintf( _n( 'The %s IP checked had no normal traffic in the data below.', 'None of the %s IPs checked had normal traffic in the data below.', $n['checked'], 'scrapelock' ), number_format_i18n( $n['checked'] ) ) ) . '</p>';
		} else {
			echo '<table class="widefat striped pncp-bunny-preview-normal" style="max-width:960px"><thead><tr><th scope="col">' . esc_html__( 'IP', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Requests on these addresses', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Also', 'scrapelock' ) . '</th></tr></thead><tbody>';
			foreach ( array_slice( $n['rows'], 0, 50 ) as $row ) {
				echo '<tr><td><code>' . esc_html( $row['ip'] ) . '</code></td><td>' . esc_html( number_format_i18n( (int) $row['hits'] ) ) . '</td><td>' . esc_html( implode( '; ', $row['why'] ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		$src   = $n['sources'];
		$lines = array(
			__( 'Administrators\' IPs of the last 30 days: checked.', 'scrapelock' ),
			$src['logins'] ? __( 'Sign-ins to accounts of the last 30 days: checked.', 'scrapelock' ) : __( 'Sign-ins to accounts: not available.', 'scrapelock' ),
			$src['reputation'] ? __( 'Reputation record (pages read, human check, sign-ins, last 7 days): checked.', 'scrapelock' ) : __( 'Reputation record (pages read, human check): not available, the IP reputation is off.', 'scrapelock' ),
			$src['logs'] ? __( 'Page views through Bunny in the imported logs: checked.', 'scrapelock' ) : __( 'Page views through Bunny in the logs: not available (the import is off, has not run yet, or the logs have anonymized IPs).', 'scrapelock' ),
		);
		echo '<ul class="pncp-bunny-preview-sources">';
		foreach ( $lines as $line ) {
			echo '<li>' . esc_html( $line ) . '</li>';
		}
		if ( $n['checked'] >= self::PREVIEW_IPS ) {
			/* translators: %s: number of IPs */
			echo '<li>' . esc_html( sprintf( __( 'Only the %s IPs with the most requests were checked.', 'scrapelock' ), number_format_i18n( self::PREVIEW_IPS ) ) ) . '</li>';
		}
		echo '</ul>';
	}

	/* ---------- Admin ---------- */

	/**
	 * The admin-post handler (action pncp_bunny). Fields: op (lock, unlock, unlock_rule, check, logging_on,
	 * import, save, forget), id.
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$id = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : '';
		if ( 'check' === $op ) {
			$check = self::bunny_logging_check();
			self::done( 'error' === $check['status'] ? new WP_Error( 'pncp_bunny', $check['message'] ) : $check['message'] );
		}
		if ( 'import' === $op ) {
			$r = self::run();
			if ( '' !== $r['error'] ) {
				self::done( new WP_Error( 'pncp_bunny', $r['error'] ) );
			}
			/* translators: 1: number of log lines, 2: number of attacks */
			self::done( sprintf( __( 'Imported %1$s log lines from Bunny; %2$s attack requests found.', 'scrapelock' ), number_format_i18n( $r['lines'] ), number_format_i18n( $r['found'] ) ) . ' ' . self::ip_check_text()[0] );
		}
		if ( PNCP_Lockdown::is_locked() ) {
			self::done( new WP_Error( 'pncp_locked', __( 'The site is locked with Lockdown: unlock it to change the rules at Bunny CDN.', 'scrapelock' ) ) );
		}
		$presets = self::presets();
		switch ( $op ) {
			case 'lock':
				// 3.9: only after "Confirm" on the preview ("What would be blocked").
				$confirmed = self::lock_confirmed( 'preset', $id );
				if ( false === $confirmed ) {
					self::to_preview( 'preset', $id );
				}
				if ( is_wp_error( $confirmed ) ) {
					self::done( $confirmed );
				}
				/* translators: %s: what is locked */
				self::done( self::lock_preset( $id ), sprintf( __( 'Locked at Bunny CDN: %s.', 'scrapelock' ), isset( $presets[ $id ] ) ? $presets[ $id ]['label'] : $id ) . ( self::enforcing() ? '' : ' ' . __( 'The rule is switched off until ScrapeLock blocks (Monitor only or protection off).', 'scrapelock' ) ) );
				break;
			case 'unlock':
				self::done( self::unlock_preset( $id ), __( 'The rule was removed at Bunny CDN.', 'scrapelock' ) );
				break;
			case 'unlock_rule':
				$rule = isset( $_POST['rule'] ) ? self::clean_id( sanitize_key( wp_unslash( $_POST['rule'] ) ) ) : '';
				if ( 0 === strpos( $rule, 'harden_' ) && class_exists( 'PNCP_Hardening' ) && method_exists( 'PNCP_Hardening', 'edge' ) ) {
					$hid = substr( $rule, 7 );
					self::done( PNCP_Hardening::edge( $hid, false ), __( 'The rule was removed at Bunny CDN.', 'scrapelock' ) );
				}
				self::done( self::edge_unblock( $rule ), __( 'The rule was removed at Bunny CDN.', 'scrapelock' ) );
				break;
			case 'login_allow_add':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked above with check_admin_referer().
				$picked = isset( $_POST['ips'] ) && is_array( $_POST['ips'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['ips'] ) ) : array();
				$added  = self::add_login_allow( $picked );
				/* translators: %s: list of IPs */
				self::done( is_wp_error( $added ) ? $added : sprintf( __( 'Added to “Allowed IPs for the login page at Bunny”: %s.', 'scrapelock' ), implode( ', ', $added ) ) );
				break;
			case 'logging_on':
				self::done( self::enable_logging(), __( 'Logging is on at the pull zone. The first lines can be read within 15 minutes.', 'scrapelock' ) );
				break;
			case 'save':
				// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked above with check_admin_referer().
				$zone = PNCP_Edge::clean_zone( 'bunny', isset( $_POST['zone'] ) ? sanitize_text_field( wp_unslash( $_POST['zone'] ) ) : '' );
				$raw  = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
				// phpcs:enable
				$old   = self::own_config();
				$token = self::key_from_config() ? $old['token'] : ( '' === trim( $raw ) ? $old['token'] : PNCP_Edge::clean_token( $raw ) );
				if ( '' === $zone || '' === $token ) {
					self::done( new WP_Error( 'pncp_bunny', '' === $zone ? __( 'The pull zone ID is a number: see the address of the pull zone\'s page in the bunny.net dashboard.', 'scrapelock' ) : __( 'The API key is not valid.', 'scrapelock' ) ) );
				}
				self::done( self::save_own( $zone, $token ), __( 'Connected to the Bunny pull zone.', 'scrapelock' ) );
				break;
			case 'forget':
				self::forget_own();
				self::done( __( 'The Bunny connection of this card was removed, with the rules ScrapeLock made with it.', 'scrapelock' ) );
				break;
		}
		self::done( new WP_Error( 'pncp_unknown', __( 'Unknown action.', 'scrapelock' ) ) );
	}

	/**
	 * Saves the own connection after a test call (the pull zone must answer).
	 *
	 * @param string $zone  Pull zone ID.
	 * @param string $token API key.
	 * @return true|WP_Error
	 */
	public static function save_own( $zone, $token ) {
		$test = self::pull_zone(
			array(
				'zone'  => $zone,
				'token' => $token,
			)
		);
		if ( 'ok' !== $test['status'] ) {
			return new WP_Error( 'pncp_bunny_' . $test['status'], $test['message'] );
		}
		$old = self::own_config();
		if ( '' !== $old['zone'] && $old['zone'] !== $zone && '' !== $old['token'] && 'own' === ( self::credentials() ? self::credentials()['source'] : '' ) ) {
			self::remove_rules_of(
				array(
					'zone'  => $old['zone'],
					'token' => $old['token'],
				),
				15
			);
		}
		$value = array(
			'zone'  => $zone,
			'token' => self::key_from_config() ? '' : $token,
		);
		if ( false === get_option( self::CONFIG, false ) ) {
			add_option( self::CONFIG, $value, '', false );
		} else {
			update_option( self::CONFIG, $value, false );
		}
		self::reset();
		self::maybe_schedule();
		return true;
	}

	/**
	 * Removes the own connection, and the rules made with it first.
	 */
	public static function forget_own() {
		$c = self::credentials();
		if ( null !== $c && 'own' === $c['source'] ) {
			self::remove_rules_of( $c, 15 );
		}
		delete_option( self::CONFIG );
		self::reset();
		self::maybe_schedule();
	}

	/**
	 * Back to the page the form came from, with the result shown once.
	 *
	 * @param true|string|WP_Error $result  Result, or the message.
	 * @param string               $message Message on success.
	 */
	private static function done( $result, $message = '' ) {
		if ( is_string( $result ) ) {
			$message = $result;
			$result  = true;
		}
		$notice = is_wp_error( $result ) ? array( 'error', $result->get_error_message() ) : array( 'success', $message );
		set_transient( 'pncp_bunny_msg_' . get_current_user_id(), $notice, MINUTE_IN_SECONDS );
		$back = wp_get_referer();
		if ( ! $back ) {
			$back = PNCP_Status::settings_url( array( 'tab' => 'bots' ) );
		}
		// 3.9: back to the card, with "Blocking at the CDN (advanced)" open.
		wp_safe_redirect( PNCP_Edge::reopen( remove_query_arg( array( 'pncp_message' ), $back ), 'pncp-bunny' ) );
		exit;
	}

	/**
	 * One admin-post button.
	 *
	 * @param string                $op      Operation.
	 * @param string                $label   Button text.
	 * @param array<string, string> $fields  More fields.
	 * @param string                $css     Button class.
	 * @param string                $confirm Confirmation text, '' = none.
	 */
	private static function button( $op, $label, $fields = array(), $css = 'button button-small', $confirm = '' ) {
		printf( '<form method="post" action="%s" class="pncp-bunny-form" style="display:inline-block;margin:0 4px 4px 0">', esc_url( admin_url( 'admin-post.php' ) ) );
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '">';
		echo '<input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
		foreach ( $fields as $name => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '">';
		}
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( self::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
		printf(
			'<button type="submit" class="%1$s"%3$s>%2$s</button></form>',
			esc_attr( $css ),
			esc_html( $label ),
			'' !== $confirm ? ' onclick="return window.confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ');"' : ''
		);
	}

	/**
	 * A date and time in the site's format.
	 *
	 * @param int $time Unix time.
	 * @return string
	 */
	private static function when( $time ) {
		return (string) wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $time );
	}

	/**
	 * The notice of the last action of this user, once.
	 */
	public static function render_notice() {
		$key    = 'pncp_bunny_msg_' . get_current_user_id();
		$notice = get_transient( $key );
		if ( ! is_array( $notice ) || 2 !== count( $notice ) ) {
			return;
		}
		delete_transient( $key );
		printf( '<div class="notice notice-%1$s inline"><p>%2$s</p></div>', 'error' === $notice[0] ? 'error' : 'success', esc_html( (string) $notice[1] ) );
	}

	/**
	 * The card "Bunny CDN: attacks and locks at the edge", for the "Blocking at the CDN" area.
	 */
	public static function render_card() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$c      = self::credentials();
		$state  = self::state();
		$cfg    = self::settings();
		$locked = PNCP_Lockdown::is_locked();
		?>
		<section class="pncp-card pncp-card--wide pncp-bunny" id="pncp-bunny" aria-labelledby="pncp-bunny-title">
			<h2 id="pncp-bunny-title"><?php esc_html_e( 'Bunny CDN: attacks and locks at the edge', 'scrapelock' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Every visitor passes through Bunny CDN, also for pages Bunny serves from its cache, which never reach WordPress. ScrapeLock reads the pull zone\'s logs every 15 minutes to see those attacks too, and can lock vulnerable addresses at Bunny with one click (Edge Rules in your own account, marked “ScrapeLock:”). Rules ScrapeLock did not make are never touched.', 'scrapelock' ); ?></p>
			<?php
			self::render_notice();
			if ( $locked ) {
				echo '<p class="description">' . esc_html__( 'The site is locked: the rules at Bunny cannot be changed until it is unlocked.', 'scrapelock' ) . '</p>';
			}
			self::render_connection( $c, $locked );
			if ( null === $c ) {
				echo '</section>';
				return;
			}
			self::render_status( $state, $cfg, $locked );
			self::render_seen();
			self::render_rules( $locked );
			self::render_presets( $locked );
			?>
		</section>
		<?php
	}

	/**
	 * The connection part of the card.
	 *
	 * @param array<string, string>|null $c      Credentials.
	 * @param bool                       $locked Site locked.
	 */
	private static function render_connection( $c, $locked ) {
		if ( null !== $c && 'edge' === $c['source'] ) {
			/* translators: %s: pull zone ID */
			echo '<p>' . esc_html( sprintf( __( 'Uses the Bunny connection of “Blocking at the CDN” (pull zone %s).', 'scrapelock' ), $c['zone'] ) ) . '</p>';
			return;
		}
		$own = self::own_config();
		echo '<p class="description">' . esc_html__( '“Blocking at the CDN” is not set to Bunny CDN. If this site is served by Bunny all the same, connect its pull zone here (only for the logs and the Edge Rules below; the bans then stay with the CDN chosen there).', 'scrapelock' ) . '</p>';
		if ( $locked ) {
			return;
		}
		printf( '<form method="post" action="%s" class="pncp-bunny-connect">', esc_url( admin_url( 'admin-post.php' ) ) );
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '"><input type="hidden" name="op" value="save">';
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( self::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="pncp-bunny-zone"><?php esc_html_e( 'Pull zone ID', 'scrapelock' ); ?></label></th>
				<td><input type="text" class="regular-text code" id="pncp-bunny-zone" name="zone" value="<?php echo esc_attr( $own['zone'] ); ?>" autocomplete="off" spellcheck="false" inputmode="numeric">
				<p class="description"><?php esc_html_e( 'The number in the address of the pull zone\'s page in the bunny.net dashboard.', 'scrapelock' ); ?></p></td>
			</tr>
			<tr>
				<th scope="row"><label for="pncp-bunny-token"><?php esc_html_e( 'API key', 'scrapelock' ); ?></label></th>
				<td>
					<?php if ( self::key_from_config() ) : ?>
						<p><?php esc_html_e( 'Set in wp-config.php (SCRAPELOCK_BUNNY_KEY).', 'scrapelock' ); ?></p>
					<?php else : ?>
						<input type="password" class="regular-text" id="pncp-bunny-token" name="token" value="" autocomplete="new-password" spellcheck="false" placeholder="<?php echo esc_attr( '' !== $own['token'] ? __( 'Saved. Leave empty to keep it.', 'scrapelock' ) : '' ); ?>">
					<?php endif; ?>
					<p class="description"><?php esc_html_e( 'Account settings → API in the bunny.net dashboard. It gives access to the whole account; it is stored in the database and never shown again. To keep it out of the database, add define( \'SCRAPELOCK_BUNNY_KEY\', \'…\' ); to wp-config.php instead.', 'scrapelock' ); ?></p>
				</td>
			</tr>
		</table>
		<p><button type="submit" class="button"><?php esc_html_e( 'Save and test', 'scrapelock' ); ?></button></p>
		</form>
		<?php
		if ( null !== $c ) {
			self::button( 'forget', __( 'Disconnect', 'scrapelock' ), array(), 'button button-small', __( 'Remove this connection and the rules ScrapeLock made at Bunny with it?', 'scrapelock' ) );
		}
	}

	/**
	 * Logging and import status.
	 *
	 * @param array<string, mixed> $state  State.
	 * @param array<string, mixed> $cfg    Settings.
	 * @param bool                 $locked Site locked.
	 */
	private static function render_status( $state, $cfg, $locked ) {
		$log    = $state['logging'];
		$status = isset( $log['status'] ) ? (string) $log['status'] : 'unknown';
		echo '<h3>' . esc_html__( 'Logs', 'scrapelock' ) . '</h3><ul class="pncp-list-status pncp-bunny-status">';
		if ( isset( $log['message'] ) && '' !== (string) $log['message'] ) {
			/* translators: 1: status, 2: date and time */
			echo '<li class="' . esc_attr( in_array( $status, array( 'off', 'error' ), true ) ? 'pncp-edge-error' : '' ) . '">' . esc_html( sprintf( __( '%1$s (checked %2$s)', 'scrapelock' ), (string) $log['message'], self::when( isset( $log['time'] ) ? (int) $log['time'] : 0 ) ) ) . '</li>';
		} else {
			echo '<li>' . esc_html__( 'Not checked yet whether logging is on at the pull zone.', 'scrapelock' ) . '</li>';
		}
		self::render_ip_check( $state );
		if ( in_array( $status, array( 'off', 'anonymized', 'unknown' ), true ) ) {
			echo '<li>' . esc_html( self::logging_how() ) . '</li>';
		}
		if ( ! $cfg['import'] ) {
			echo '<li>' . esc_html__( 'Importing the logs is off: turn on “Import attacks from Bunny CDN\'s logs” in the settings above.', 'scrapelock' ) . '</li>';
		} elseif ( $state['last_run'] ) {
			/* translators: 1: date and time, 2: lines, 3: attack requests */
			echo '<li>' . esc_html( sprintf( __( 'Last import: %1$s, %2$s lines read, %3$s attack requests found.', 'scrapelock' ), self::when( (int) $state['last_run'] ), number_format_i18n( (int) $state['lines'] ), number_format_i18n( (int) $state['found'] ) ) ) . '</li>';
			$next = wp_next_scheduled( self::CRON );
			if ( $next ) {
				/* translators: %s: date and time */
				echo '<li>' . esc_html( sprintf( __( 'Next import: %s', 'scrapelock' ), self::when( $next ) ) ) . '</li>';
			}
		} else {
			echo '<li>' . esc_html__( 'The first import starts within 15 minutes. It begins with the last 15 minutes of the log, not with older lines.', 'scrapelock' ) . '</li>';
		}
		if ( '' !== (string) $state['error'] ) {
			/* translators: 1: date and time, 2: error message */
			echo '<li class="pncp-edge-error"><strong>' . esc_html( sprintf( __( 'Last error (%1$s): %2$s', 'scrapelock' ), self::when( (int) $state['error_time'] ), (string) $state['error'] ) ) . '</strong></li>';
		}
		if ( $cfg['strikes'] ) {
			echo '<li>' . esc_html(
				self::logs_anonymized( $state )
					? __( 'IPs too fast at the CDN are not blocked: Bunny anonymizes the IPs in its logs.', 'scrapelock' )
					/* translators: %d: requests per minute */
					: sprintf( __( 'IPs that ask for more than %d pages per minute at the CDN get a violation toward a temporary block (not in Monitor only).', 'scrapelock' ), (int) $cfg['rate'] )
			) . '</li>';
		}
		echo '</ul><p>';
		self::button( 'check', __( 'Check logging at Bunny', 'scrapelock' ) );
		if ( 'off' === $status && ! $locked ) {
			self::button( 'logging_on', __( 'Turn on logging at Bunny', 'scrapelock' ), array(), 'button button-small button-primary', __( 'Turn on logging for this pull zone at Bunny? Bunny then keeps a log of every request (IP, address, User-Agent) for 3 days.', 'scrapelock' ) );
		}
		if ( $cfg['import'] ) {
			self::button( 'import', __( 'Import now', 'scrapelock' ) );
		}
		echo '</p>';
	}

	/**
	 * What was seen at the edge.
	 */
	private static function render_seen() {
		$day  = self::seen( 24 );
		$week = self::seen( 24 * 7 );
		echo '<h3>' . esc_html__( 'Attacks seen at the CDN', 'scrapelock' ) . '</h3>';
		echo '<p>' . esc_html(
			sprintf(
				/* translators: 1: requests in 24 hours, 2: blocked of them, 3: requests in 7 days, 4: blocked of them */
				__( 'Last 24 hours: %1$s attack requests (%2$s blocked). Last 7 days: %3$s (%4$s blocked).', 'scrapelock' ),
				number_format_i18n( $day['seen'] ),
				number_format_i18n( $day['blocked'] ),
				number_format_i18n( $week['seen'] ),
				number_format_i18n( $week['blocked'] )
			)
		) . '</p>';
		if ( ! class_exists( 'PNCP_Attacks' ) || ! method_exists( 'PNCP_Attacks', 'top_details' ) ) {
			return;
		}
		$rows = PNCP_Attacks::top_details( 7, 'edge', 10 );
		if ( ! $rows ) {
			return;
		}
		echo '<table class="widefat striped pncp-bunny-seen"><thead><tr><th scope="col">' . esc_html__( 'What (last 7 days)', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Requests', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'IPs', 'scrapelock' ) . '</th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr><td>' . esc_html( '' !== (string) $row['detail'] ? (string) $row['detail'] : __( '(many addresses)', 'scrapelock' ) ) . '</td><td>' . esc_html( number_format_i18n( (int) $row['hits'] ) ) . '</td><td>' . esc_html( number_format_i18n( (int) $row['ips'] ) ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * The rules ScrapeLock manages, with Remove buttons.
	 *
	 * @param bool $locked Site locked.
	 */
	private static function render_rules( $locked ) {
		$rules = self::list_ours();
		echo '<h3>' . esc_html__( 'Edge Rules ScrapeLock manages', 'scrapelock' ) . '</h3>';
		if ( ! $rules ) {
			echo '<p class="description">' . esc_html__( 'None yet.', 'scrapelock' ) . '</p>';
			return;
		}
		$on = self::enforcing();
		echo '<table class="widefat striped pncp-bunny-rules"><thead><tr><th scope="col">' . esc_html__( 'Rule', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Blocks', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'State', 'scrapelock' ) . '</th><th scope="col"><span class="screen-reader-text">' . esc_html__( 'Action', 'scrapelock' ) . '</span></th></tr></thead><tbody>';
		foreach ( $rules as $rule ) {
			$patterns = implode( ' ', array_slice( $rule['patterns'], 0, 6 ) ) . ( count( $rule['patterns'] ) > 6 ? ' …' : '' );
			echo '<tr><td>' . esc_html( $rule['label'] ) . '</td><td><code>' . esc_html( $patterns ) . '</code>';
			if ( $rule['allow'] ) {
				/* translators: %s: list of IPs */
				echo '<br><span class="description">' . esc_html( sprintf( __( 'Except from: %s', 'scrapelock' ), implode( ', ', array_slice( $rule['allow'], 0, 8 ) ) . ( count( $rule['allow'] ) > 8 ? ' …' : '' ) ) ) . '</span>';
			}
			echo '</td><td>';
			if ( $rule['enabled'] ) {
				esc_html_e( 'Blocking', 'scrapelock' );
			} else {
				echo esc_html( $on ? __( 'Switched off, switched on with the next run', 'scrapelock' ) : __( 'Switched off while ScrapeLock does not block (Monitor only or protection off)', 'scrapelock' ) );
			}
			/* translators: %s: date */
			echo '<br><span class="description">' . esc_html( sprintf( __( 'Since %s', 'scrapelock' ), self::when( $rule['created'] ) ) ) . '</span></td><td>';
			if ( ! $locked ) {
				/* translators: %s: rule */
				self::button( 'unlock_rule', __( 'Remove', 'scrapelock' ), array( 'rule' => $rule['id'] ), 'button button-small', sprintf( __( 'Remove the rule “%s” at Bunny CDN?', 'scrapelock' ), $rule['label'] ) );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * The "Lock at Bunny" presets, with the attacks seen on each point.
	 *
	 * @param bool $locked Site locked.
	 */
	private static function render_presets( $locked ) {
		echo '<h3>' . esc_html__( 'Lock at Bunny with one click', 'scrapelock' ) . '</h3>';
		echo '<table class="widefat striped pncp-bunny-presets"><thead><tr><th scope="col">' . esc_html__( 'Point', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'What it blocks, what may stop working', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Attacks, 7 days', 'scrapelock' ) . '</th><th scope="col"><span class="screen-reader-text">' . esc_html__( 'Action', 'scrapelock' ) . '</span></th></tr></thead><tbody>';
		foreach ( self::presets() as $id => $preset ) {
			$hits = 0;
			if ( class_exists( 'PNCP_Attacks' ) && method_exists( 'PNCP_Attacks', 'count' ) ) {
				foreach ( (array) $preset['evidence'] as $ev ) {
					$hits += (int) PNCP_Attacks::count( 7, (string) $ev[0], (string) $ev[1] );
				}
			}
			$is = self::preset_locked( (string) $id );
			echo '<tr><td><strong>' . esc_html( (string) $preset['label'] ) . '</strong></td><td>' . esc_html( (string) $preset['blocks'] ) . '<br><span class="description">' . esc_html( (string) $preset['breaks'] ) . '</span></td><td>' . esc_html( number_format_i18n( $hits ) ) . '</td><td>';
			if ( $is ) {
				echo '<span class="pncp-bunny-locked">' . esc_html__( 'Locked at Bunny', 'scrapelock' ) . '</span><br>';
				if ( ! $locked ) {
					self::button( 'unlock', __( 'Remove', 'scrapelock' ), array( 'id' => (string) $id ) );
				}
			} elseif ( ! $locked ) {
				// 3.9: opens the preview "What would be blocked"; the lock happens only after "Confirm" there.
				self::button( 'lock', __( 'Lock at Bunny…', 'scrapelock' ), array( 'id' => (string) $id ), $hits > 0 ? 'button button-small button-primary' : 'button button-small' );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
		self::render_login_allow( $locked ); // 3.9: the explicit list and its suggestions.
		self::render_xmlrpc_warnings(); // 3.9: what locking XML-RPC stops.
	}

	/* ---------- Site Health, privacy, WP-CLI ---------- */

	/**
	 * Site Health test: logging at Bunny and the last import.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_test() {
		$result = array(
			'label'       => __( 'ScrapeLock reads Bunny CDN\'s logs', 'scrapelock' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html__( 'Attacks on pages Bunny serves from its cache never reach WordPress; ScrapeLock sees them in the pull zone\'s logs.', 'scrapelock' ) . '</p>',
			'actions'     => '',
			'test'        => 'pncp_bunny',
		);
		$c      = self::credentials();
		$state  = self::state();
		$cfg    = self::settings();
		if ( null === $c || ! $cfg['import'] ) {
			$result['label'] = __( 'ScrapeLock does not read Bunny CDN\'s logs', 'scrapelock' );
			if ( null !== $c ) {
				$result['description'] = '<p>' . esc_html__( 'The site is connected to Bunny CDN, but importing its logs is off: attacks on cached pages stay unseen. Turn on “Import attacks from Bunny CDN\'s logs”.', 'scrapelock' ) . '</p>';
			}
			return $result;
		}
		$status = isset( $state['logging']['status'] ) ? (string) $state['logging']['status'] : '';
		if ( 'off' === $status ) {
			$result['status']      = 'recommended';
			$result['label']       = __( 'Logging is off at the Bunny pull zone', 'scrapelock' );
			$result['description'] = '<p>' . esc_html( self::logging_how() ) . '</p>';
		} elseif ( '' !== (string) $state['error'] && (int) $state['last_ok'] < time() - 2 * HOUR_IN_SECONDS ) {
			$result['status'] = 'recommended';
			$result['label']  = __( 'ScrapeLock could not read Bunny CDN\'s logs', 'scrapelock' );
			/* translators: %s: error */
			$result['description'] = '<p>' . esc_html( sprintf( __( 'The last import failed: %s', 'scrapelock' ), (string) $state['error'] ) ) . '</p>';
		}
		return $result;
	}

	/**
	 * The text for the privacy policy guide.
	 *
	 * @return string
	 */
	public static function privacy_policy() {
		return __( 'When “Import attacks from Bunny CDN\'s logs” is on, this site downloads the logs of its own Bunny CDN pull zone (logging.bunnycdn.com) every 15 minutes. They contain the IP address, the address asked for, the referrer, the browser identification (User-Agent) and the country of each request. Only requests that look like attacks are kept, with the IP address, for as long as the attack record is kept; the rest is discarded at once. When a vulnerable address is locked at Bunny CDN, the IP addresses administrators used in the last 30 days may be sent to the site owner\'s Bunny account, so that they are let through.', 'scrapelock' )
			// 3.9: kept for the preview "What would be blocked".
			. ' ' . __( 'For the IP addresses whose requests looked like attacks or asked for an address that can be locked at Bunny CDN (such as wp-login.php or xmlrpc.php), the number of those requests and of the normal pages they opened through Bunny is also kept, for 8 days, so that ScrapeLock can show what a lock would refuse and warn before it refuses a real visitor.', 'scrapelock' );
	}

	/**
	 * "wp scrapelock bunny <status|import|rules|presets|lock|unlock|logging|parse>".
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cli( $args, $assoc_args ) {
		$sub    = isset( $args[0] ) ? (string) $args[0] : 'status';
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( ! in_array( $format, array( 'table', 'json', 'csv', 'yaml', 'count' ), true ) ) {
			WP_CLI::error( __( 'Unknown --format. Use: table, json, csv, yaml or count.', 'scrapelock' ) );
		}
		if ( 'parse' !== $sub && null === self::credentials() ) {
			WP_CLI::error( __( 'Bunny CDN is not connected.', 'scrapelock' ) );
		}
		$fail = static function ( $result, $ok ) {
			if ( is_wp_error( $result ) ) {
				WP_CLI::error( $result->get_error_message() );
			}
			WP_CLI::success( $ok );
		};
		switch ( $sub ) {
			case 'status':
				$state = self::state();
				$c     = self::credentials();
				$day   = self::seen( 24 );
				$week  = self::seen( 168 );
				$items = array(
					array(
						'key'   => 'pull_zone',
						'value' => $c['zone'] . ' (' . $c['source'] . ')',
					),
					array(
						'key'   => 'import',
						'value' => self::settings()['import'] ? 'on' : 'off',
					),
					array(
						'key'   => 'logging',
						'value' => isset( $state['logging']['status'] ) ? (string) $state['logging']['status'] : 'unknown',
					),
					array(
						'key'   => 'log_ips',
						'value' => ( isset( $state['ips']['status'] ) ? (string) $state['ips']['status'] : 'unknown' ) . ( ! empty( $state['ips']['time'] ) ? ' (' . wp_date( 'Y-m-d H:i:s', (int) $state['ips']['time'] ) . ', ' . (int) $state['ips']['lines'] . ' lines)' : '' ),
					),
					array(
						'key'   => 'last_run',
						'value' => $state['last_run'] ? wp_date( 'Y-m-d H:i:s', (int) $state['last_run'] ) : '-',
					),
					array(
						'key'   => 'cursor',
						'value' => $state['day'] . ' +' . (int) $state['offset'],
					),
					array(
						'key'   => 'seen_24h',
						'value' => $day['seen'] . ' (' . $day['blocked'] . ' blocked)',
					),
					array(
						'key'   => 'seen_7d',
						'value' => $week['seen'] . ' (' . $week['blocked'] . ' blocked)',
					),
					array(
						'key'   => 'rules',
						'value' => (string) count( self::rules() ),
					),
					array(
						'key'   => 'error',
						'value' => (string) $state['error'],
					),
				);
				WP_CLI\Utils\format_items( $format, $items, array( 'key', 'value' ) );
				return;
			case 'import':
				$r = self::run();
				if ( '' !== $r['error'] ) {
					WP_CLI::error( $r['error'] );
				}
				/* translators: 1: lines, 2: attack requests */
				WP_CLI::success( sprintf( __( '%1$d lines read, %2$d attack requests found.', 'scrapelock' ), $r['lines'], $r['found'] ) );
				return;
			case 'rules':
				$items = array();
				foreach ( self::list_ours() as $rule ) {
					$items[] = array(
						'id'       => $rule['id'],
						'label'    => $rule['label'],
						'guid'     => $rule['guid'],
						'zone'     => $rule['zone'],
						'enabled'  => $rule['enabled'] ? 'yes' : 'no',
						'patterns' => implode( ' ', $rule['patterns'] ),
						'allow'    => implode( ' ', $rule['allow'] ),
					);
				}
				WP_CLI\Utils\format_items( $format, $items, array( 'id', 'label', 'guid', 'zone', 'enabled', 'patterns', 'allow' ) );
				return;
			case 'presets':
				$items = array();
				foreach ( self::presets() as $id => $preset ) {
					$items[] = array(
						'preset' => $id,
						'label'  => $preset['label'],
						'locked' => self::preset_locked( (string) $id ) ? 'yes' : 'no',
						'rule'   => self::preset_rule_id( (string) $id ),
					);
				}
				WP_CLI\Utils\format_items( $format, $items, array( 'preset', 'label', 'locked', 'rule' ) );
				return;
			case 'preview':
				// 3.9: "What would be blocked" for a preset, or a hardening point as harden_<point>, as JSON.
				$target  = isset( $args[1] ) ? sanitize_key( $args[1] ) : '';
				$harden  = 0 === strpos( $target, 'harden_' );
				$preview = self::lock_preview( $harden ? 'harden' : 'preset', $harden ? substr( $target, 7 ) : $target );
				if ( is_wp_error( $preview ) ) {
					WP_CLI::error( $preview->get_error_message() );
				}
				WP_CLI::log( (string) wp_json_encode( $preview, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
				return;
			case 'lock':
				$fail( self::lock_preset( isset( $args[1] ) ? sanitize_key( $args[1] ) : '' ), __( 'Locked at Bunny CDN.', 'scrapelock' ) );
				return;
			case 'unlock':
				$id = isset( $args[1] ) ? sanitize_key( $args[1] ) : '';
				if ( isset( self::presets()[ $id ] ) ) {
					$fail( self::unlock_preset( $id ), __( 'Removed at Bunny CDN.', 'scrapelock' ) );
					return;
				}
				// A rule ID; also while the site is locked, so a locked-out owner can open the login page again.
				$fail( self::remove( self::clean_id( $id ) ), __( 'Removed at Bunny CDN.', 'scrapelock' ) );
				return;
			case 'logging':
				if ( isset( $assoc_args['enable'] ) ) {
					$fail( self::enable_logging(), __( 'Logging is on at the pull zone.', 'scrapelock' ) );
					return;
				}
				$check = self::bunny_logging_check();
				WP_CLI::log( $check['message'] );
				if ( 'on' !== $check['status'] ) {
					WP_CLI::log( $check['how'] );
				}
				return;
			case 'parse':
				$file = isset( $args[1] ) ? (string) $args[1] : '';
				if ( '' === $file || ! is_readable( $file ) ) {
					WP_CLI::error( __( 'Give the path of a Bunny log file.', 'scrapelock' ) );
				}
				$a = self::new_analysis();
				// Every line counts here, also those WordPress saw.
				$a['cfg']['all_lines'] = true;
				$items                 = array();
				$handle                = fopen( $file, 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Reads a local file given on the command line.
				while ( false !== ( $line = fgets( $handle ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition -- Line by line.
					$row = self::parse_line( $line );
					if ( ! $row ) {
						continue;
					}
					$items[] = array(
						'ip'     => $row['ip'],
						'status' => $row['status'],
						'cache'  => $row['cache'],
						'path'   => $row['path'],
						'what'   => self::classify( $row, $a['agents'] ),
					);
				}
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See fopen().
				WP_CLI\Utils\format_items( $format, $items, array( 'ip', 'status', 'cache', 'path', 'what' ) );
				return;
		}
		WP_CLI::error( __( 'Use: status, import, rules, presets, lock <preset>, unlock <preset|rule>, logging [--enable] or parse <file>.', 'scrapelock' ) );
	}
}
