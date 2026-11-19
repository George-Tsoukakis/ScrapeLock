<?php
/**
 * 3.8: attack telemetry. Where bots and attackers hit the site, also when nothing was refused: failed sign-ins and
 * the usernames tried, visits to wp-login.php that do not end in a sign-in, logged-out requests for /wp-admin/,
 * XML-RPC calls (each call of a system.multicall counted), username enumeration, scanner probes, "page not found"
 * under /wp-content/plugins/ and /themes/, attack patterns in the address, and every request ScrapeLock refused.
 *
 * One row per hour, category, path, IP and detail, with a counter (an atomic INSERT … ON DUPLICATE KEY UPDATE), in
 * the table {prefix}pncp_attacks. Nothing is written for a normal page view: the request is only looked at, at the
 * end, with a few string checks, and a row is written only when it matched. At most a set number of new rows a
 * minute is written; past it the events are added up per category and path without the IP ("Many addresses"),
 * and during a flood beyond that they are not stored. Staff who are exempt, verified search engines and the
 * server itself are never recorded. Kept for 7, 30 or 90 days ("attack_retention").
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Attack telemetry.
 */
final class PNCP_Attacks {

	/**
	 * Option with the table's schema version (autoloaded: read when something is recorded).
	 */
	const DB_OPTION = 'pncp_attacks_db';

	/**
	 * Table schema version.
	 */
	const DB_VERSION = 1;

	/**
	 * Option bumped when the data is cleared, so the cached figures of the admin screen are counted again.
	 */
	const GEN_OPTION = 'pncp_attacks_gen';

	/**
	 * Seconds the figures of the admin screen are cached.
	 */
	const CACHE_TTL = 60;

	/**
	 * At most this many different rows from one web request (a multicall with hundreds of usernames is one row
	 * per username up to this many).
	 */
	const MAX_PER_REQUEST = 20;

	/**
	 * In WP-CLI and cron (imported CDN logs) the buffer is written every this many different rows.
	 */
	const MAX_BUFFER_BATCH = 500;

	/**
	 * New rows a minute before events are added up without the IP (filter `pncp_attack_rows_per_minute`).
	 */
	const ROWS_PER_MINUTE = 120;

	/**
	 * Writes (requests that store something) a minute before the events are not stored at all (filter
	 * `pncp_attack_writes_per_minute`, 0 = no cap).
	 */
	const WRITES_PER_MINUTE = 3000;

	/**
	 * Rows one DELETE of the cleanup removes.
	 */
	const DELETE_BATCH = 5000;

	/**
	 * Events of this request, key => entry, written at shutdown.
	 *
	 * @var array<string, array{category:string, path:string, ip:string, detail:string, hits:int, blocked:int, ctx:bool}>
	 */
	private static $buffer = array();

	/**
	 * The refusal of this request (PNCP_Log::add()), or null.
	 *
	 * @var array{reason:string, code:int, ip:string}|null
	 */
	private static $refused = null;

	/**
	 * The action of wp-login.php when it was loaded in this request (login_init), or null.
	 *
	 * @var string|null
	 */
	private static $login_action = null;

	/**
	 * A sign-in succeeded in this request.
	 *
	 * @var bool
	 */
	private static $login_ok = false;

	/**
	 * A sign-in failed in this request (wp_login_failed).
	 *
	 * @var bool
	 */
	private static $login_failed = false;

	/**
	 * A sign-in of this request was refused by ScrapeLock before the password counted.
	 *
	 * @var bool
	 */
	private static $login_refused = false;

	/**
	 * Whether the shutdown writer is attached.
	 *
	 * @var bool
	 */
	private static $hooked = false;

	/**
	 * Per-request memo of the checks on the visitor (exempt, local, verified crawler).
	 *
	 * @var bool|null
	 */
	private static $visitor_ok = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ), 10, 2 );
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 10, 0 );
		add_action( 'login_init', array( __CLASS__, 'on_login_page' ), 0 );
		add_action( 'init', array( __CLASS__, 'on_xmlrpc' ), 1 );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'on_rest' ), -10, 3 );
		add_action( 'admin_post_pncp_attacks_export', array( __CLASS__, 'handle_export' ) );
		add_action( 'admin_post_pncp_attacks_clear', array( __CLASS__, 'handle_clear' ) );
		self::hook();
	}

	/**
	 * Attaches the writer to shutdown, once. Every request is looked at there (string checks only).
	 */
	private static function hook() {
		if ( ! self::$hooked && function_exists( 'add_action' ) ) {
			self::$hooked = true;
			add_action( 'shutdown', array( __CLASS__, 'shutdown' ), 0 );
		}
	}

	/**
	 * Called by the early check (PNCP_Early) for wp-admin/install.php and upgrade.php, where the plugin itself
	 * does not load: the request is looked at and written at shutdown like any other.
	 */
	public static function watch_installer() {
		self::hook();
	}

	/* ---------- Table ---------- */

	/**
	 * The table.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'pncp_attacks';
	}

	/**
	 * Creates or updates the table (PNCP_Log::install() calls it). The row key is a hash of category, path, IP and
	 * detail, so the unique key stays short on every database.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
			hour_ts int(10) unsigned NOT NULL DEFAULT 0,
			k char(32) NOT NULL DEFAULT '',
			category varchar(20) NOT NULL DEFAULT '',
			path varchar(191) NOT NULL DEFAULT '',
			ip varchar(45) NOT NULL DEFAULT '',
			detail varchar(100) NOT NULL DEFAULT '',
			hits int(10) unsigned NOT NULL DEFAULT 0,
			blocked int(10) unsigned NOT NULL DEFAULT 0,
			last_ts int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (hour_ts,k),
			KEY category_hour (category,hour_ts),
			KEY ip_hour (ip,hour_ts)
			) {$charset};"
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema check on install.
		$found = (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
		if ( 0 === strcasecmp( $found, $table ) ) {
			update_option( self::DB_OPTION, self::DB_VERSION, true );
		}
	}

	/**
	 * Is the table there?
	 *
	 * @return bool
	 */
	public static function ready() {
		return (int) get_option( self::DB_OPTION, 0 ) >= self::DB_VERSION;
	}

	/* ---------- Settings ---------- */

	/**
	 * Is recording on? ("attack_record", default on, and the protection enabled.)
	 *
	 * @return bool
	 */
	public static function enabled() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && ( ! isset( $s['attack_record'] ) || ! empty( $s['attack_record'] ) );
	}

	/**
	 * Days the rows are kept ("attack_retention": 7, 30 or 90, default 30).
	 *
	 * @return int
	 */
	public static function retention() {
		$s    = PNCP_Options::get();
		$days = isset( $s['attack_retention'] ) ? (int) $s['attack_retention'] : 30;
		return in_array( $days, array( 7, 30, 90 ), true ) ? $days : 30;
	}

	/* ---------- Categories ---------- */

	/**
	 * The keys of categories(), without the labels (checked on every event, so no translation is looked up).
	 */
	const KEYS = array( 'login_fail', 'login_probe', 'admin_probe', 'xmlrpc', 'user_enum', 'scanner', 'plugin_probe', 'install', 'injection', 'bot_block', 'edge' );

	/**
	 * The categories with their labels.
	 *
	 * @return array<string, string>
	 */
	public static function categories() {
		return array(
			'login_fail'   => __( 'Failed sign-in', 'scrapelock' ),
			'login_probe'  => __( 'Sign-in page without signing in', 'scrapelock' ),
			'admin_probe'  => __( 'wp-admin while logged out', 'scrapelock' ),
			'xmlrpc'       => __( 'XML-RPC call', 'scrapelock' ),
			'user_enum'    => __( 'Username enumeration', 'scrapelock' ),
			'scanner'      => __( 'Scanner probe (.env, .git, backups…)', 'scrapelock' ),
			'plugin_probe' => __( 'Plugin or theme probe', 'scrapelock' ),
			'install'      => __( 'Installer or upgrade script', 'scrapelock' ),
			'injection'    => __( 'Attack pattern in the address (SQL, script, ../)', 'scrapelock' ),
			'bot_block'    => __( 'Refused by ScrapeLock', 'scrapelock' ),
			'edge'         => __( 'Attack seen at the CDN', 'scrapelock' ),
		);
	}

	/**
	 * What each category means and how to close that point, for the report.
	 *
	 * @return array<string, string>
	 */
	public static function advice() {
		return array(
			'login_fail'   => __( 'Someone tried a password and it was wrong. Many from few addresses is password guessing: use strong passwords and two-factor sign-in, and block the addresses below.', 'scrapelock' ),
			'login_probe'  => __( 'wp-login.php was opened or posted to without a sign-in that worked. Bots do this to find the sign-in form. Restrict wp-login.php at the server or the CDN if only a few people sign in.', 'scrapelock' ),
			'admin_probe'  => __( 'Requests for /wp-admin/ from someone not signed in. WordPress sends them to the sign-in page; many of them are scanners mapping the site.', 'scrapelock' ),
			'xmlrpc'       => __( 'Calls to xmlrpc.php. system.multicall tries hundreds of passwords in one request. If no app or Jetpack uses XML-RPC, block xmlrpc.php at the server or the CDN.', 'scrapelock' ),
			'user_enum'    => __( '?author=N or the REST users list: collecting usernames to guess their passwords. Turn on “Hide usernames from visitors”.', 'scrapelock' ),
			'scanner'      => __( 'Requests for files that should never be public (.env, .git, backups, database dumps, phpMyAdmin). Turn on “Ban scanners on their first probe”.', 'scrapelock' ),
			'plugin_probe' => __( '“Page not found” under /wp-content/plugins/ or /themes/: a scanner checking for plugins with known holes. Keep plugins up to date and delete the ones you do not use.', 'scrapelock' ),
			'install'      => __( 'Requests for install.php, setup-config.php or upgrade.php: looking for a site that is not set up yet, to take it over. WordPress runs these files before it loads plugins, so they are recorded only with “Early check” on (install.php and upgrade.php) or from the Bunny CDN logs; setup-config.php is seen only in the CDN or server logs. The “WordPress\'s own files” point on the Vulnerable points tab closes them.', 'scrapelock' ),
			'injection'    => __( 'SQL, script, file-path or code patterns in the address. Recorded only, not blocked: a firewall at the server or the CDN can refuse them.', 'scrapelock' ),
			'bot_block'    => __( 'Requests ScrapeLock refused (or, in Monitor only, would refuse). The detail is the reason, as in the Log.', 'scrapelock' ),
			'edge'         => __( 'Attacks seen in the CDN’s logs, before they reached this server.', 'scrapelock' ),
		);
	}

	/* ---------- Recording ---------- */

	/**
	 * Records one event. Cheap: it is added to this request's buffer, written once at shutdown.
	 *
	 * @param string $category Key of categories().
	 * @param string $path     Path asked for (as the log keeps it, percent-encoded or decoded).
	 * @param string $ip       IP.
	 * @param bool   $blocked  Whether it was refused.
	 * @param string $detail   Detail (the username tried, the XML-RPC method, the reason…).
	 */
	public static function record( $category, $path, $ip, $blocked = false, $detail = '' ) {
		self::add( (string) $category, (string) $path, (string) $ip, (bool) $blocked, (string) $detail, 1 );
	}

	/**
	 * Records the same event $hits times at once (an aggregated line of a CDN log import).
	 *
	 * @param string $category Key of categories().
	 * @param string $path     Path asked for.
	 * @param string $ip       IP.
	 * @param bool   $blocked  Whether they were refused.
	 * @param string $detail   Detail.
	 * @param int    $hits     How many times (1 to 100000).
	 */
	public static function record_hits( $category, $path, $ip, $blocked, $detail, $hits ) {
		self::add( (string) $category, (string) $path, (string) $ip, (bool) $blocked, (string) $detail, (int) $hits );
	}

	/**
	 * Adds to the buffer.
	 *
	 * @param string $category Category.
	 * @param string $path     Path.
	 * @param string $ip       IP.
	 * @param bool   $blocked  Refused.
	 * @param string $detail   Detail.
	 * @param int    $hits     Count.
	 */
	private static function add( $category, $path, $ip, $blocked, $detail, $hits ) {
		if ( ! in_array( $category, self::KEYS, true ) || ! self::enabled() ) {
			return;
		}
		$ip = PNCP_Ip::normalize( $ip );
		if ( '' === $ip || PNCP_Ip::is_local( $ip ) ) {
			return; // The server itself (cron, loopback requests, Site Health).
		}
		$path   = self::clean( self::path_for( $category, $path ), 191 );
		$detail = self::clean( $detail, 100 );
		$key    = md5( $category . '|' . $path . '|' . $ip . '|' . $detail );
		$hits   = max( 1, min( 100000, (int) $hits ) );
		if ( isset( self::$buffer[ $key ] ) ) {
			self::$buffer[ $key ]['hits']    += $hits;
			self::$buffer[ $key ]['blocked'] += $blocked ? $hits : 0;
			return;
		}
		$batch = self::in_web_request() ? self::MAX_PER_REQUEST : self::MAX_BUFFER_BATCH;
		if ( count( self::$buffer ) >= $batch ) {
			if ( self::in_web_request() ) {
				return; // Enough for one request.
			}
			self::flush();
		}
		self::$buffer[ $key ] = array(
			'category' => $category,
			'path'     => $path,
			'ip'       => $ip,
			'detail'   => $detail,
			'hits'     => $hits,
			'blocked'  => $blocked ? $hits : 0,
			// The checks on the visitor (exempt staff, verified crawler) apply when the event is this request's own.
			'ctx'      => self::in_web_request() && PNCP_Ip::client_ip() === $ip,
		);
		self::hook();
	}

	/**
	 * The path a category keeps: the sign-in page as /wp-login.php (also with extra path info after it), and for
	 * wp-admin only the files that exist (an attacker asking for /wp-admin/<random> makes one row, not one per
	 * request).
	 *
	 * @param string $category Category.
	 * @param string $path     Path asked for.
	 * @return string
	 */
	private static function path_for( $category, $path ) {
		$path = (string) $path;
		if ( 'login_probe' === $category && preg_match( '#^(.*?/wp-login\.php)#i', $path, $m ) ) {
			return $m[1];
		}
		if ( 'admin_probe' === $category ) {
			$decoded = strtolower( rawurldecode( $path ) );
			$at      = strpos( $decoded, '/wp-admin' );
			if ( false === $at ) {
				return $path;
			}
			$rel = ltrim( (string) substr( $decoded, $at + 9 ), '/' );
			if ( '' === $rel ) {
				return substr( $decoded, 0, $at ) . '/wp-admin/';
			}
			if ( preg_match( '#^[a-z0-9_-]+(?:/[a-z0-9_-]+)?\.php$#', $rel ) && defined( 'ABSPATH' ) && is_file( ABSPATH . 'wp-admin/' . $rel ) ) {
				return substr( $decoded, 0, $at ) . '/wp-admin/' . $rel;
			}
			return substr( $decoded, 0, $at ) . '/wp-admin/*';
		}
		return $path;
	}

	/**
	 * The path kept for a row once more than ROWS_PER_MINUTE new rows were written in the minute: a fixed bucket,
	 * so a flood of unique paths adds up in a few rows.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	private static function overflow_path( $path ) {
		$lower = strtolower( (string) $path );
		foreach ( array( 'wp-login.php', 'xmlrpc.php', 'wp-admin' ) as $part ) {
			if ( false !== strpos( $lower, $part ) ) {
				return 'wp-admin' === $part ? '/wp-admin/*' : '/' . $part;
			}
		}
		return '';
	}

	/**
	 * Printable text without tags or control characters, at most $max characters.
	 *
	 * @param string $text Text.
	 * @param int    $max  Length.
	 * @return string
	 */
	private static function clean( $text, $max ) {
		$text = wp_check_invalid_utf8( (string) $text, true );
		$text = trim( (string) preg_replace( '/[\x00-\x1F\x7F<>]/', '', $text ) );
		return function_exists( 'mb_substr' ) ? mb_substr( $text, 0, $max ) : substr( $text, 0, $max );
	}

	/**
	 * A web request (not cron, not WP-CLI)?
	 *
	 * @return bool
	 */
	private static function in_web_request() {
		return ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() );
	}

	/**
	 * Called from PNCP_Log::add() for every refusal (and, in Monitor only, every "would block", code 0): recorded at
	 * shutdown, in the category the request also matched, or as "Refused by ScrapeLock" with the reason.
	 *
	 * @param string $reason Reason (key of PNCP_Log::reasons()).
	 * @param int    $code   HTTP status (PNCP_Log::MONITOR_CODE = would block).
	 * @param string $ip     IP.
	 */
	public static function on_blocked( $reason, $code, $ip ) {
		if ( '' === (string) $ip ) {
			return;
		}
		// The first reason is the one that matters; "New temporary block" follows the reason that caused it.
		if ( null === self::$refused || ( 'ban' === self::$refused['reason'] && 'ban' !== $reason ) ) {
			self::$refused = array(
				'reason' => (string) $reason,
				'code'   => (int) $code,
				'ip'     => (string) $ip,
			);
		}
		self::hook();
	}

	/**
	 * A failed sign-in (wp_login_failed), with the username tried. A sign-in that ScrapeLock refused before the
	 * password counted (blocked IP, paused username) is not a wrong password: it is recorded at shutdown as a
	 * refused sign-in, without the username, so the owner's own refused sign-ins do not count against the account.
	 *
	 * @param string $username Username or email tried.
	 * @param mixed  $error    The WP_Error (WordPress 5.4+).
	 */
	public static function on_login_failed( $username, $error = null ) {
		if ( is_wp_error( $error ) && in_array( 'pncp_login_locked', $error->get_error_codes(), true ) ) {
			self::$login_refused = true;
			return;
		}
		self::$login_failed = true;
		self::record( 'login_fail', self::request_path(), PNCP_Ip::client_ip(), false, (string) $username );
	}

	/**
	 * A sign-in worked (wp_login).
	 */
	public static function on_login() {
		global $wpdb;
		self::$login_ok = true;
		if ( ! self::ready() ) {
			return;
		}
		// The visit to the sign-in form just before was a person, not a bot: taken back out of this hour's count.
		$ip       = PNCP_Ip::client_ip();
		$path     = self::clean( self::request_path(), 191 );
		$k        = md5( 'login_probe|' . $path . '|' . $ip . '|GET' );
		$hour     = (int) ( floor( time() / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, one row by its primary key, only on a sign-in.
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = hits - 1 WHERE hour_ts = %d AND k = %s AND hits > 0', self::table(), $hour, $k ) );
		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * The sign-in page (wp-login.php, or where a "hide login" plugin moved it) is loaded (login_init).
	 */
	public static function on_login_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read only, to name the action.
		self::$login_action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
	}

	/**
	 * XML-RPC: the method called, and for system.multicall each call inside it (one row, counted N times).
	 */
	public static function on_xmlrpc() {
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return;
		}
		// Read only: WordPress's xmlrpc.php fills this global from php://input.
		$raw_post = isset( $GLOBALS['HTTP_RAW_POST_DATA'] ) ? $GLOBALS['HTTP_RAW_POST_DATA'] : null;
		$body     = is_string( $raw_post ) ? $raw_post : '';
		$path     = self::request_path();
		$ip       = PNCP_Ip::client_ip();
		if ( '' === trim( $body ) ) {
			self::add( 'xmlrpc', $path, $ip, false, 'GET', 1 );
			return;
		}
		$head   = substr( $body, 0, 4096 );
		$method = preg_match( '#<methodName>\s*([A-Za-z0-9_.:-]{1,80})\s*</methodName>#i', $head, $m ) ? $m[1] : '?';
		if ( 'system.multicall' !== strtolower( $method ) ) {
			self::add( 'xmlrpc', $path, $ip, false, $method, 1 );
			return;
		}
		// Each struct of the call list has a member "methodName" with the method as its value.
		$calls = (int) preg_match_all( '#<name>\s*methodName\s*</name>\s*<value>\s*(?:<string>)?\s*([A-Za-z0-9_.:-]{1,80})#i', $body, $all );
		$inner = $calls ? array_count_values( $all[1] ) : array();
		arsort( $inner );
		$first = $inner ? (string) key( $inner ) : '';
		self::add( 'xmlrpc', $path, $ip, false, 'system.multicall' . ( '' !== $first ? ' (' . $first . ')' : '' ), max( 1, $calls ) );
	}

	/**
	 * REST: the users list (/wp/v2/users) asked for by someone not signed in. Nothing is changed.
	 *
	 * @param mixed           $result  Result.
	 * @param WP_REST_Server  $server  Server.
	 * @param WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function on_rest( $result, $server, $request ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundInExtendedClassBeforeLastUsed,Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed -- Filter signature.
		if ( $request instanceof WP_REST_Request && ! is_user_logged_in() && preg_match( '#^/wp/v2/users(?:/|$)#i', (string) $request->get_route() ) ) {
			self::record( 'user_enum', '/' . rest_get_url_prefix() . '/wp/v2/users', PNCP_Ip::client_ip(), false, substr( (string) $request->get_route(), 0, 100 ) );
		}
		return $result;
	}

	/**
	 * The path of this request, percent-encoded as the log keeps it, without the query string.
	 *
	 * @return string
	 */
	private static function request_path() {
		$path = (string) wp_parse_url( PNCP_Log::request_uri(), PHP_URL_PATH );
		return '' === $path ? '/' : $path;
	}

	/**
	 * At the end of every request: what it matched (string checks on its path and query), then the buffer is
	 * written. Nothing is read or written when nothing matched.
	 */
	public static function shutdown() {
		if ( self::in_web_request() ) {
			self::classify_request();
		}
		self::flush();
	}

	/**
	 * Adds the categories of this request to the buffer.
	 */
	private static function classify_request() {
		if ( ! function_exists( 'is_user_logged_in' ) || ! self::enabled() ) {
			// The early check refused it before WordPress loaded: only the refusal is known.
			if ( null !== self::$refused && self::enabled() ) {
				self::add( 'bot_block', self::request_path(), self::$refused['ip'], PNCP_Log::MONITOR_CODE !== self::$refused['code'], self::$refused['reason'], 1 );
			}
			return;
		}
		$ip = PNCP_Ip::client_ip();
		if ( '' === $ip ) {
			return;
		}
		$path    = self::request_path();
		$decoded = strtolower( self::decoded_path() );
		$status  = (int) http_response_code();
		// A "page not found" that WordPress answers with a redirect (the trailing slash) is still a 404.
		$missing = $status >= 400 || ( function_exists( 'is_404' ) && did_action( 'wp' ) && is_404() );
		$logged  = is_user_logged_in();
		$found   = array();

		// Sign-in page without a sign-in that worked (a failed one is already "Failed sign-in").
		$method   = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		$at_login = null !== self::$login_action || 'wp-login.php' === basename( $decoded );
		if ( $at_login && 'POST' === $method && ! self::$login_ok && ! self::$login_failed && ! $logged
			&& ( self::$login_refused || ( null !== self::$refused && self::$refused['ip'] === $ip ) )
			&& in_array( (string) self::$login_action, array( '', 'login' ), true ) ) {
			// A password sent while the IP is blocked or the username paused: a sign-in attempt that was refused.
			$why     = null !== self::$refused ? self::$refused['reason'] : 'login_user';
			$found[] = array( 'login_fail', '(refused: ' . $why . ')' );
		} elseif ( null !== self::$login_action && ! self::$login_ok && ! self::$login_failed && ! $logged
			&& ! in_array( self::$login_action, array( 'postpass', 'logout', 'confirmaction', 'confirm_admin_email', 'checkemail', 'entered_recovery_mode' ), true ) ) {
			$found[] = array( 'login_probe', $method . ( 'login' !== self::$login_action ? ' ' . self::$login_action : '' ) );
		}

		$file = basename( $decoded );
		if ( ! $logged && preg_match( '#/wp-admin/(?:install|setup-config|upgrade)\.php$|/wp-admin/maint/repair\.php$#', $decoded ) ) {
			$found[] = array( 'install', '' );
		} elseif ( ! $logged && preg_match( '#/wp-admin(?:/|$)#', $decoded ) && ! in_array( $file, array( 'admin-ajax.php', 'admin-post.php' ), true ) ) {
			$found[] = array( 'admin_probe', '' );
		} elseif ( $missing && preg_match( '#/wp-content/(plugins|themes)/([^/]+)#', $decoded, $m ) ) {
			$found[] = array( 'plugin_probe', substr( $m[1], 0, -1 ) . ': ' . $m[2] );
		} elseif ( $missing && self::is_scanner_path( $decoded, $status ) ) {
			$found[] = array( 'scanner', '' );
		}

		// ?author=N: the usual way to collect the usernames (as PNCP_Bots::is_author_scan(), also when not blocked).
		if ( ! $logged && ! is_admin() ) {
			// phpcs:disable WordPress.Security.NonceVerification -- Read-only check of a public parameter.
			$author = isset( $_POST['author'] ) ? sanitize_text_field( wp_unslash( $_POST['author'] ) ) : ( isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : '' );
			// phpcs:enable
			if ( '' !== $author && preg_match( '/\d/', $author ) ) {
				$found[] = array( 'user_enum', 'author=' . substr( $author, 0, 20 ) );
			}
		}

		$injection = self::injection_type();
		if ( '' !== $injection ) {
			$found[] = array( 'injection', $injection );
		}

		$refused = null !== self::$refused && self::$refused['ip'] === $ip ? self::$refused : null;
		if ( ! $found && ! self::$buffer && null === $refused ) {
			return; // A normal request: nothing to record.
		}
		// Refused: logged as a refusal, or answered 403 / 429 (the probe guard refuses without logging when it does not ban).
		$blocked = ( null !== $refused && PNCP_Log::MONITOR_CODE !== $refused['code'] ) || in_array( $status, array( 403, 429 ), true );
		if ( null !== $refused && ! $found && ! self::own_events( $ip ) ) {
			$found[] = array( 'bot_block', $refused['reason'] );
		}
		foreach ( $found as $event ) {
			$detail = '' === $event[1] && null !== $refused ? $refused['reason'] : $event[1];
			self::add( $event[0], $path, $ip, $blocked, $detail, 1 );
		}
		if ( $blocked ) {
			// Events recorded earlier in the request (a failed sign-in, an XML-RPC call) were refused too.
			foreach ( self::$buffer as $key => $entry ) {
				if ( $entry['ip'] === $ip && $entry['blocked'] < $entry['hits'] ) {
					self::$buffer[ $key ]['blocked'] = $entry['hits'];
				}
			}
		}
	}

	/**
	 * Does the buffer hold events of this IP?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private static function own_events( $ip ) {
		foreach ( self::$buffer as $entry ) {
			if ( $entry['ip'] === $ip ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The request path, decoded once, without control characters.
	 *
	 * @return string
	 */
	private static function decoded_path() {
		if ( class_exists( 'PNCP_Bots' ) ) {
			return PNCP_Bots::request_path();
		}
		return (string) preg_replace( '/[\x00-\x1F\x7F]/', '', rawurldecode( self::request_path() ) );
	}

	/**
	 * A refused or missing file that only scanners ask for: the probe list of "Ban scanners on their first probe",
	 * or, for a "page not found", any path that looks for files or admin areas (PNCP_Log::is_probe_path()).
	 *
	 * @param string $decoded Decoded path, lower case.
	 * @param int    $status  HTTP status.
	 * @return bool
	 */
	private static function is_scanner_path( $decoded, $status ) {
		if ( class_exists( 'PNCP_Probe' ) && PNCP_Probe::matches( PNCP_Probe::request_path() ) ) {
			return true;
		}
		return ( 404 === $status || ( function_exists( 'is_404' ) && did_action( 'wp' ) && is_404() ) ) && PNCP_Log::is_probe_path( $decoded );
	}

	/**
	 * Attack patterns in the query string and the path (detection only): 'sqli', 'xss', 'traversal', 'rce' or ''.
	 * Decoded twice (double encoding). Plain words such as "select" or "union" in a search do not match: only the
	 * shapes of an attack do.
	 *
	 * @param string|null $uri Request URI (null = this request).
	 * @return string
	 */
	public static function injection_type( $uri = null ) {
		$uri = null === $uri ? PNCP_Log::request_uri() : (string) $uri;
		if ( '' === $uri || ( false === strpos( $uri, '?' ) && false === strpos( $uri, '%' ) && false === strpos( $uri, '..' ) ) ) {
			return '';
		}
		$text   = strtolower( rawurldecode( rawurldecode( str_replace( '+', ' ', substr( $uri, 0, 4096 ) ) ) ) );
		$text   = (string) preg_replace( '#/\*.*?\*/#s', ' ', $text ); // SQL comments used as spaces: UNION/**/SELECT.
		$checks = array(
			'traversal' => '#(?:\.\./|\.\.\\\\){2,}|/etc/(?:passwd|shadow|hosts)|(?:^|[=/])(?:c:|%systemroot%)\\\\windows|\x00|wp-config\.php(?:\?|$|&|\#)#',
			'rce'       => '#\$\{jndi:|\$\{\s*(?:env|sys|lower|upper):|(?:php|data|expect|zip|phar|glob)://|(?:^|[;&|`])\s*(?:cat|wget|curl|bash|sh|nc|python|perl)\s+[-/]|\b(?:base64_decode|eval|assert|system|passthru|shell_exec)\s*\(#',
			'sqli'      => '#\bunion\b(?:\s+all)?\s+select\b|\bselect\b.{1,200}\bfrom\b.{1,80}\b(?:information_schema|mysql\.user|wp_users)\b|\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b|[\'"]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d|\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|\#)|\b(?:extractvalue|updatexml)\s*\(|\bconcat\s*\(\s*0x[0-9a-f]+#',
			'xss'       => '#<\s*(?:script|iframe|svg|img|body|object|embed)\b|javascript\s*:|\bon(?:error|load|mouseover|focus|toggle)\s*=|document\.cookie|\balert\s*\(#',
		);
		foreach ( $checks as $type => $regex ) {
			if ( preg_match( $regex, $text ) ) {
				return $type;
			}
		}
		return '';
	}

	/**
	 * Is the visitor of this request one that is never recorded: exempt staff, the server itself, a verified search
	 * engine or AI search bot?
	 *
	 * @return bool
	 */
	private static function visitor_skipped() {
		if ( null !== self::$visitor_ok ) {
			return ! self::$visitor_ok;
		}
		$skip = false;
		if ( function_exists( 'is_user_logged_in' ) && class_exists( 'PNCP_Lockdown' ) && PNCP_Options::user_is_exempt( PNCP_Options::get() ) ) {
			$skip = true;
		} elseif ( PNCP_Ip::is_local_request() ) {
			$skip = true;
		} elseif ( class_exists( 'PNCP_Bots' ) ) {
			$ip     = PNCP_Ip::client_ip();
			$ua     = PNCP_Bots::user_agent();
			$family = PNCP_Bots::claimed_crawler( $ua );
			if ( '' !== $family && ! PNCP_Ip::is_cdn_edge( $ip ) && PNCP_Bots::is_verified_crawler( $family, $ip ) ) {
				$skip = true;
			} elseif ( 'verified' === PNCP_Bots::ai_verdict( $ua, $ip, PNCP_Options::get() ) ) {
				$skip = true;
			}
		}
		self::$visitor_ok = ! $skip;
		return $skip;
	}

	/**
	 * Writes the buffer: one atomic INSERT … ON DUPLICATE KEY UPDATE per row of the hour. Past ROWS_PER_MINUTE new
	 * rows in the minute, the rows lose their IP and detail, and the path becomes a fixed bucket (overflow_path());
	 * past WRITES_PER_MINUTE writes in the minute, nothing is stored.
	 */
	public static function flush() {
		global $wpdb;
		if ( ! self::$buffer ) {
			return;
		}
		$entries      = self::$buffer;
		self::$buffer = array();
		if ( ! self::ready() || ! PNCP_Log::ready() ) {
			return;
		}
		foreach ( $entries as $key => $entry ) {
			if ( $entry['ctx'] && self::visitor_skipped() ) {
				unset( $entries[ $key ] );
			}
		}
		if ( ! $entries ) {
			return;
		}
		$minute = (int) floor( time() / MINUTE_IN_SECONDS );
		$cap    = (int) apply_filters( 'pncp_attack_writes_per_minute', self::WRITES_PER_MINUTE );
		if ( $cap > 0 && PNCP_Log::cache_incr( 'pncp_at_w_' . $minute, 2 * MINUTE_IN_SECONDS ) > $cap ) {
			return; // A flood: the log, the bans and the limits still deal with it.
		}
		$overflow = (int) PNCP_Log::cache_get( 'pncp_at_n_' . $minute ) >= max( 10, (int) apply_filters( 'pncp_attack_rows_per_minute', self::ROWS_PER_MINUTE ) );
		$hour     = (int) ( floor( time() / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
		$now      = time();
		$suppress = $wpdb->suppress_errors( true );
		foreach ( $entries as $entry ) {
			if ( $overflow ) {
				$entry['ip']     = '';
				$entry['detail'] = '';
				$entry['path']   = self::overflow_path( $entry['path'] );
			}
			$k = md5( $entry['category'] . '|' . $entry['path'] . '|' . $entry['ip'] . '|' . $entry['detail'] );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, one atomic counter per row of the hour.
			$done = $wpdb->query(
				$wpdb->prepare(
					'INSERT INTO %i (hour_ts, k, category, path, ip, detail, hits, blocked, last_ts) VALUES (%d, %s, %s, %s, %s, %s, %d, %d, %d) ON DUPLICATE KEY UPDATE hits = hits + %d, blocked = blocked + %d, last_ts = %d',
					self::table(),
					$hour,
					$k,
					$entry['category'],
					$entry['path'],
					$entry['ip'],
					$entry['detail'],
					$entry['hits'],
					$entry['blocked'],
					$now,
					$entry['hits'],
					$entry['blocked'],
					$now
				)
			);
			if ( 1 === $done ) {
				PNCP_Log::cache_incr( 'pncp_at_n_' . $minute, 2 * MINUTE_IN_SECONDS ); // A new row.
			}
		}
		$wpdb->suppress_errors( $suppress );
	}

	/* ---------- Reading ---------- */

	/**
	 * The first hour of the last N days.
	 *
	 * @param int $days Days.
	 * @return int Unix time.
	 */
	private static function since( $days ) {
		return (int) ( floor( ( time() - max( 1, (int) $days ) * DAY_IN_SECONDS ) / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
	}

	/**
	 * A figure, cached for CACHE_TTL seconds (admin screens; the table is not read on normal requests).
	 *
	 * @param string   $name    Name and arguments.
	 * @param callable $compute Computes it.
	 * @return mixed
	 */
	private static function cached( $name, $compute ) {
		static $memo = array();
		$key         = 'pncp_at_q_' . md5( $name . '|' . (int) get_option( self::GEN_OPTION, 0 ) );
		if ( isset( $memo[ $key ] ) ) {
			return $memo[ $key ];
		}
		$cli   = defined( 'WP_CLI' ) && WP_CLI; // WP-CLI always counts afresh.
		$value = $cli ? false : PNCP_Log::cache_get( $key );
		if ( ! is_array( $value ) || ! array_key_exists( 'v', $value ) ) {
			$value = array( 'v' => self::ready() ? $compute() : null );
			if ( ! $cli ) {
				PNCP_Log::cache_set( $key, $value, self::CACHE_TTL );
			}
		}
		$memo[ $key ] = $value['v'];
		return $value['v'];
	}

	/**
	 * Runs a read query with errors suppressed (a missing table is "nothing").
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
	 * The totals of the last N days.
	 *
	 * @param int $days Days.
	 * @return array{total:int, blocked:int, unique_ips:int, by_category:array<string,int>, login:array{attempts:int, failed:int, ips:int}}
	 */
	public static function summary( $days ) {
		$days  = max( 1, (int) $days );
		$value = self::cached(
			'summary|' . $days,
			static function () use ( $days ) {
				global $wpdb;
				$since = self::since( $days );
				$out   = array(
					'total'       => 0,
					'blocked'     => 0,
					'unique_ips'  => 0,
					'by_category' => array(),
					'login'       => array(
						'attempts' => 0,
						'failed'   => 0,
						'ips'      => 0,
					),
				);
				foreach ( self::rows( $wpdb->prepare( 'SELECT category, SUM(hits) AS hits, SUM(blocked) AS blocked FROM %i WHERE hour_ts >= %d GROUP BY category HAVING hits > 0 ORDER BY hits DESC', self::table(), $since ) ) as $row ) {
					$out['by_category'][ (string) $row['category'] ] = (int) $row['hits'];
					$out['total']                                   += (int) $row['hits'];
					$out['blocked']                                 += (int) $row['blocked'];
				}
				$ips               = self::rows( $wpdb->prepare( "SELECT COUNT(DISTINCT ip) AS n FROM %i WHERE hour_ts >= %d AND ip <> '' AND hits > 0", self::table(), $since ) );
				$out['unique_ips'] = $ips ? (int) $ips[0]['n'] : 0;
				$login             = self::rows( $wpdb->prepare( "SELECT COUNT(DISTINCT NULLIF(ip, '')) AS n FROM %i WHERE category IN ('login_fail', 'login_probe') AND hour_ts >= %d AND hits > 0", self::table(), $since ) );
				$failed            = isset( $out['by_category']['login_fail'] ) ? $out['by_category']['login_fail'] : 0;
				$out['login']      = array(
					'attempts' => $failed + ( isset( $out['by_category']['login_probe'] ) ? $out['by_category']['login_probe'] : 0 ),
					'failed'   => $failed,
					'ips'      => $login ? (int) $login[0]['n'] : 0,
				);
				return $out;
			}
		);
		return is_array( $value ) ? $value : array(
			'total'       => 0,
			'blocked'     => 0,
			'unique_ips'  => 0,
			'by_category' => array(),
			'login'       => array(
				'attempts' => 0,
				'failed'   => 0,
				'ips'      => 0,
			),
		);
	}

	/**
	 * The paths hit most in the last N days.
	 *
	 * @param int    $days     Days.
	 * @param int    $limit    Rows.
	 * @param string $category Only this category ('' = all).
	 * @return array<int, array{path:string, category:string, hits:int, ips:int, blocked:int}>
	 */
	public static function top_paths( $days, $limit = 20, $category = '' ) {
		$days     = max( 1, (int) $days );
		$limit    = max( 1, min( 1000, (int) $limit ) );
		$category = (string) $category;
		$value    = self::cached(
			'paths|' . $days . '|' . $limit . '|' . $category,
			static function () use ( $days, $limit, $category ) {
				global $wpdb;
				$sql = '' === $category
					? $wpdb->prepare( "SELECT path, category, SUM(hits) AS hits, COUNT(DISTINCT NULLIF(ip, '')) AS ips, SUM(blocked) AS blocked FROM %i WHERE hour_ts >= %d GROUP BY path, category HAVING hits > 0 ORDER BY hits DESC LIMIT %d", self::table(), self::since( $days ), $limit )
					: $wpdb->prepare( "SELECT path, category, SUM(hits) AS hits, COUNT(DISTINCT NULLIF(ip, '')) AS ips, SUM(blocked) AS blocked FROM %i WHERE category = %s AND hour_ts >= %d GROUP BY path, category HAVING hits > 0 ORDER BY hits DESC LIMIT %d", self::table(), $category, self::since( $days ), $limit );
				$out = array();
				foreach ( self::rows( $sql ) as $row ) {
					$out[] = array(
						'path'     => (string) $row['path'],
						'category' => (string) $row['category'],
						'hits'     => (int) $row['hits'],
						'ips'      => (int) $row['ips'],
						'blocked'  => (int) $row['blocked'],
					);
				}
				return $out;
			}
		);
		return is_array( $value ) ? $value : array();
	}

	/**
	 * The addresses with the most events in the last N days (rows added up without an IP are left out).
	 *
	 * @param int    $days     Days.
	 * @param int    $limit    Rows.
	 * @param string $category Only this category ('' = all).
	 * @return array<int, array{ip:string, hits:int, categories:string, last:int}>
	 */
	public static function top_ips( $days, $limit = 20, $category = '' ) {
		$days     = max( 1, (int) $days );
		$limit    = max( 1, min( 1000, (int) $limit ) );
		$category = (string) $category;
		$value    = self::cached(
			'ips|' . $days . '|' . $limit . '|' . $category,
			static function () use ( $days, $limit, $category ) {
				global $wpdb;
				$sql = '' === $category
					? $wpdb->prepare( "SELECT ip, SUM(hits) AS hits, GROUP_CONCAT(DISTINCT category ORDER BY category) AS categories, MAX(last_ts) AS last FROM %i WHERE hour_ts >= %d AND ip <> '' GROUP BY ip HAVING hits > 0 ORDER BY hits DESC LIMIT %d", self::table(), self::since( $days ), $limit )
					: $wpdb->prepare( "SELECT ip, SUM(hits) AS hits, GROUP_CONCAT(DISTINCT category ORDER BY category) AS categories, MAX(last_ts) AS last FROM %i WHERE category = %s AND hour_ts >= %d AND ip <> '' GROUP BY ip HAVING hits > 0 ORDER BY hits DESC LIMIT %d", self::table(), $category, self::since( $days ), $limit );
				$out = array();
				foreach ( self::rows( $sql ) as $row ) {
					$out[] = array(
						'ip'         => (string) $row['ip'],
						'hits'       => (int) $row['hits'],
						'categories' => (string) $row['categories'],
						'last'       => (int) $row['last'],
					);
				}
				return $out;
			}
		);
		return is_array( $value ) ? $value : array();
	}

	/**
	 * The most frequent details of a category (the usernames tried, the XML-RPC methods, the plugins probed…).
	 *
	 * @param int    $days     Days.
	 * @param string $category Category.
	 * @param int    $limit    Rows.
	 * @return array<int, array{detail:string, hits:int, ips:int}>
	 */
	public static function top_details( $days, $category, $limit = 20 ) {
		$days     = max( 1, (int) $days );
		$limit    = max( 1, min( 1000, (int) $limit ) );
		$category = (string) $category;
		$value    = self::cached(
			'details|' . $days . '|' . $limit . '|' . $category,
			static function () use ( $days, $limit, $category ) {
				global $wpdb;
				$out = array();
				foreach ( self::rows( $wpdb->prepare( "SELECT detail, SUM(hits) AS hits, COUNT(DISTINCT NULLIF(ip, '')) AS ips FROM %i WHERE category = %s AND hour_ts >= %d AND detail <> '' GROUP BY detail HAVING hits > 0 ORDER BY hits DESC LIMIT %d", self::table(), $category, self::since( $days ), $limit ) ) as $row ) {
					$out[] = array(
						'detail' => (string) $row['detail'],
						'hits'   => (int) $row['hits'],
						'ips'    => (int) $row['ips'],
					);
				}
				return $out;
			}
		);
		return is_array( $value ) ? $value : array();
	}

	/**
	 * Events per hour of the period, by the hour they started (Unix time => hits).
	 *
	 * @param int    $since    Unix time.
	 * @param string $category Category ('' = all).
	 * @return array<int, int>
	 */
	private static function hourly( $since, $category ) {
		$value = self::cached(
			'hourly|' . $since . '|' . $category,
			static function () use ( $since, $category ) {
				global $wpdb;
				$sql = '' === $category
					? $wpdb->prepare( 'SELECT hour_ts, SUM(hits) AS hits FROM %i WHERE hour_ts >= %d GROUP BY hour_ts', self::table(), $since )
					: $wpdb->prepare( 'SELECT hour_ts, SUM(hits) AS hits FROM %i WHERE category = %s AND hour_ts >= %d GROUP BY hour_ts', self::table(), $category, $since );
				$out = array();
				foreach ( self::rows( $sql ) as $row ) {
					$out[ (int) $row['hour_ts'] ] = (int) $row['hits'];
				}
				return $out;
			}
		);
		return is_array( $value ) ? $value : array();
	}

	/**
	 * Events per day of the last N days, in the site's time zone (every day present, 0 where none).
	 *
	 * @param int    $days     Days.
	 * @param string $category Category ('' = all).
	 * @return array<string, int> Y-m-d => hits.
	 */
	public static function per_day( $days, $category = '' ) {
		$days = max( 1, min( 366, (int) $days ) );
		$out  = array();
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$out[ wp_date( 'Y-m-d', time() - $i * DAY_IN_SECONDS ) ] = 0;
		}
		$first = (string) key( $out );
		foreach ( self::hourly( self::since( $days + 1 ), (string) $category ) as $hour => $hits ) {
			$day = wp_date( 'Y-m-d', $hour );
			if ( $day >= $first && isset( $out[ $day ] ) ) {
				$out[ $day ] += $hits;
			}
		}
		return $out;
	}

	/**
	 * Events per hour of the last N hours, in the site's time zone (every hour present).
	 *
	 * @param int $hours Hours.
	 * @return array<string, int> 'Y-m-d H:00' => hits.
	 */
	public static function per_hour( $hours = 48 ) {
		$hours = max( 1, min( 24 * 90, (int) $hours ) );
		$now   = (int) ( floor( time() / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
		$data  = self::hourly( $now - ( $hours - 1 ) * HOUR_IN_SECONDS, '' );
		$out   = array();
		for ( $i = $hours - 1; $i >= 0; $i-- ) {
			$hour                                  = $now - $i * HOUR_IN_SECONDS;
			$out[ wp_date( 'Y-m-d H:00', $hour ) ] = isset( $data[ $hour ] ) ? $data[ $hour ] : 0;
		}
		return $out;
	}

	/**
	 * Events of a category in the last N days, optionally only on paths that start with a prefix (the evidence
	 * "N attempts on this point").
	 *
	 * @param int    $days        Days.
	 * @param string $category    Category ('' = all).
	 * @param string $path_prefix Path prefix ('' = any), e.g. /xmlrpc.php or /wp-content/plugins/.
	 * @return int
	 */
	public static function count( $days, $category, $path_prefix = '' ) {
		$days        = max( 1, (int) $days );
		$category    = (string) $category;
		$path_prefix = (string) $path_prefix;
		$value       = self::cached(
			'count|' . $days . '|' . $category . '|' . $path_prefix,
			static function () use ( $days, $category, $path_prefix ) {
				global $wpdb;
				$like = '' !== $path_prefix ? $wpdb->esc_like( $path_prefix ) . '%' : '';
				// An empty category or prefix is folded to TRUE by the database before the index is chosen.
				$rows = self::rows( $wpdb->prepare( "SELECT SUM(hits) AS n FROM %i WHERE hour_ts >= %d AND ( %s = '' OR category = %s ) AND ( %s = '' OR path LIKE %s )", self::table(), self::since( $days ), $category, $category, $like, $like ) );
				return $rows ? (int) $rows[0]['n'] : 0;
			}
		);
		return (int) $value;
	}

	/* ---------- Cleanup ---------- */

	/**
	 * Deletes rows older than the retention (hourly, from PNCP_Log::cleanup()), in batches.
	 *
	 * @param int $seconds Time budget.
	 */
	public static function cleanup( $seconds = 10 ) {
		global $wpdb;
		if ( ! self::ready() ) {
			return;
		}
		$before   = self::since( self::retention() );
		$budget   = microtime( true ) + max( 1, (int) $seconds );
		$suppress = $wpdb->suppress_errors( true );
		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, batched delete on the primary key.
			$deleted = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE hour_ts < %d LIMIT %d', self::table(), $before, self::DELETE_BATCH ) );
			if ( false === $deleted ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table; a database without DELETE … LIMIT.
				$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE hour_ts < %d', self::table(), $before ) );
				break;
			}
		} while ( self::DELETE_BATCH === (int) $deleted && microtime( true ) < $budget );
		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * Deletes everything ("Delete the attack record").
	 */
	public static function clear() {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'TRUNCATE TABLE %i', self::table() ) );
		$wpdb->suppress_errors( $suppress );
		update_option( self::GEN_OPTION, (int) get_option( self::GEN_OPTION, 0 ) + 1, false );
	}

	/**
	 * Drops the table and the options (uninstall).
	 */
	public static function uninstall() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall.
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', self::table() ) );
		delete_option( self::DB_OPTION );
		delete_option( self::GEN_OPTION );
	}

	/* ---------- Export ---------- */

	/**
	 * A CSV cell that a spreadsheet will not run as a formula.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	private static function csv_cell( $value ) {
		$value = (string) $value;
		return '' !== $value && false !== strpos( "=+-@\t\r", $value[0] ) ? "'" . $value : $value;
	}

	/**
	 * Streams the rows of the last N days as CSV (one line per hour, category, path, IP and detail), in batches.
	 * Sends the headers when they can still be sent.
	 *
	 * @param int $days Days.
	 */
	public static function export_csv( $days ) {
		global $wpdb;
		$days = max( 1, (int) $days );
		if ( ! headers_sent() ) {
			nocache_headers();
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="scrapelock-attacks-' . gmdate( 'Y-m-d' ) . '.csv"' );
			header( 'X-Content-Type-Options: nosniff' );
		}
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming to the response.
		if ( ! $out ) {
			return;
		}
		$labels = self::categories();
		fputcsv( $out, array( 'hour', 'category', 'category_label', 'path', 'ip', 'detail', 'hits', 'blocked', 'last_seen' ), ',', '"', '\\' );
		if ( self::ready() ) {
			$since = self::since( $days );
			$hour  = $since - 1;
			$k     = '';
			do {
				$rows = self::rows( $wpdb->prepare( 'SELECT hour_ts, k, category, path, ip, detail, hits, blocked, last_ts FROM %i WHERE hour_ts >= %d AND ( hour_ts > %d OR ( hour_ts = %d AND k > %s ) ) ORDER BY hour_ts, k LIMIT 2000', self::table(), $since, $hour, $hour, $k ) );
				foreach ( $rows as $row ) {
					fputcsv(
						$out,
						array(
							wp_date( 'Y-m-d H:00', (int) $row['hour_ts'] ),
							$row['category'],
							isset( $labels[ $row['category'] ] ) ? $labels[ $row['category'] ] : $row['category'],
							self::csv_cell( PNCP_Log::display_path( $row['path'] ) ),
							'' !== $row['ip'] ? $row['ip'] : 'many',
							self::csv_cell( $row['detail'] ),
							(int) $row['hits'],
							(int) $row['blocked'],
							wp_date( 'Y-m-d H:i:s', (int) $row['last_ts'] ),
						),
						',',
						'"',
						'\\'
					);
					$hour = (int) $row['hour_ts'];
					$k    = (string) $row['k'];
				}
				$more = 2000 === count( $rows );
			} while ( $more );
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming to the response.
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
	 * The admin page to go back to: the "Attacks" tab of the settings page.
	 *
	 * @param string $message Notice code.
	 * @return string
	 */
	private static function back_url( $message ) {
		$args = array( 'tab' => 'attacks' );
		if ( '' !== $message ) {
			$args['pncp_message'] = $message;
		}
		return class_exists( 'PNCP_Status' ) ? PNCP_Status::settings_url( $args ) : add_query_arg( $args, admin_url( 'options-general.php?page=scrapelock' ) );
	}

	/**
	 * Action pncp_attacks_export (admin-post.php): downloads the CSV.
	 */
	public static function handle_export() {
		self::verify( 'pncp_attacks_export' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked in verify().
		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : self::retention();
		self::export_csv( max( 1, min( 90, $days ) ) );
		exit;
	}

	/**
	 * Action pncp_attacks_clear (admin-post.php): deletes the record. Not while the site is locked (Lockdown): the
	 * record is evidence, and a stolen administrator account must not be able to wipe it.
	 */
	public static function handle_clear() {
		self::verify( 'pncp_attacks_clear' );
		if ( class_exists( 'PNCP_Lockdown' ) && PNCP_Lockdown::is_locked() ) {
			wp_safe_redirect( self::back_url( 'attacks_locked' ) );
			exit;
		}
		self::clear();
		wp_safe_redirect( self::back_url( 'attacks_cleared' ) );
		exit;
	}

	/**
	 * The notices of the actions above (the integrator adds them to PNCP_Admin's notices).
	 *
	 * @return array<string, array{0:string, 1:string}> Code => [ type, text ].
	 */
	public static function notices() {
		return array(
			'attacks_cleared' => array( 'success', __( 'The attack record was deleted.', 'scrapelock' ) ),
			'attacks_locked'  => array( 'error', __( 'The site is locked: the attack record cannot be deleted until you unlock it.', 'scrapelock' ) ),
		);
	}

	/* ---------- Admin screen ---------- */

	/**
	 * The period and category chosen on the report (GET, read only).
	 *
	 * @return array{0:int, 1:string}
	 */
	private static function filters() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only view filters.
		$days     = isset( $_GET['pncp_at_days'] ) ? absint( $_GET['pncp_at_days'] ) : 7;
		$category = isset( $_GET['pncp_at_cat'] ) ? sanitize_key( wp_unslash( $_GET['pncp_at_cat'] ) ) : '';
		// phpcs:enable
		$days = in_array( $days, array( 1, 7, 30, 90 ), true ) ? $days : 7;
		if ( ! isset( self::categories()[ $category ] ) ) {
			$category = '';
		}
		return array( min( $days, max( 1, self::retention() ) ), $category );
	}

	/**
	 * The full report: every card below, in order. The integrator calls it on the "Attacks" tab.
	 */
	public static function render_report() {
		list( $days, $category ) = self::filters();
		self::render_summary_card( $days, $category );
		self::render_where_card( $days );
		self::render_paths_card( $days, $category );
		self::render_ips_card( $days, $category );
		self::render_details_card( $days );
		self::render_tools_card( $days );
	}

	/**
	 * A number with its label.
	 *
	 * @param int    $value Number.
	 * @param string $label Label.
	 */
	private static function stat( $value, $label ) {
		printf(
			'<div class="pncp-attacks__stat"><strong>%1$s</strong> <span>%2$s</span></div>',
			esc_html( number_format_i18n( (int) $value ) ),
			esc_html( $label )
		);
	}

	/**
	 * Card: totals, the period and category filters, and the chart.
	 *
	 * @param int    $days     Days.
	 * @param string $category Category ('' = all).
	 */
	public static function render_summary_card( $days = 7, $category = '' ) {
		$sum    = self::summary( $days );
		$labels = self::categories();
		$cats   = $sum['by_category'];
		?>
		<section class="pncp-card pncp-card--wide pncp-attacks" aria-labelledby="pncp-attacks-title">
			<h2 id="pncp-attacks-title">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: number of days */
						_n( 'Attacks on this site (last %s day)', 'Attacks on this site (last %s days)', $days, 'scrapelock' ),
						number_format_i18n( $days )
					)
				);
				?>
			</h2>
			<?php if ( ! self::enabled() ) : ?>
				<p class="description"><?php esc_html_e( 'Not recording: “Record where bots and attackers hit the site” is off, or the protection is disabled.', 'scrapelock' ); ?></p>
			<?php endif; ?>
			<?php if ( ! self::ready() ) : ?>
				<p class="description"><?php esc_html_e( 'The table of the attack record does not exist yet. It is created on the next admin page, if the database user may create tables.', 'scrapelock' ); ?></p>
			<?php endif; ?>
			<?php self::render_filters( $days, $category ); ?>
			<div class="pncp-attacks__stats" style="display:flex;flex-wrap:wrap;gap:8px 24px;margin:12px 0;">
				<?php
				self::stat( $sum['total'], __( 'events', 'scrapelock' ) );
				self::stat( $sum['blocked'], __( 'refused', 'scrapelock' ) );
				self::stat( $sum['unique_ips'], __( 'addresses', 'scrapelock' ) );
				self::stat( $sum['login']['failed'], __( 'failed sign-ins', 'scrapelock' ) );
				self::stat( $sum['login']['attempts'], __( 'visits to the sign-in without signing in', 'scrapelock' ) );
				self::stat( isset( $cats['admin_probe'] ) ? $cats['admin_probe'] : 0, __( 'wp-admin requests while logged out', 'scrapelock' ) );
				self::stat( isset( $cats['xmlrpc'] ) ? $cats['xmlrpc'] : 0, __( 'XML-RPC calls', 'scrapelock' ) );
				?>
			</div>
			<?php
			if ( '' !== $category ) {
				echo '<h3>' . esc_html( $labels[ $category ] ) . '</h3>';
			}
			self::render_chart( 1 === $days ? self::per_hour( 24 ) : self::per_day( $days, $category ), 1 === $days );
			?>
			<p class="description"><?php esc_html_e( 'Recorded on this server, also when nothing was refused: one row per hour, kind of attack, address and IP, with a count. Exempt staff, verified search engines and the server itself are not recorded. A normal page view writes nothing.', 'scrapelock' ); ?></p>
		</section>
		<?php
	}

	/**
	 * The period links and the category menu (a GET form that keeps the page's other parameters).
	 *
	 * @param int    $days     Days.
	 * @param string $category Category.
	 */
	private static function render_filters( $days, $category ) {
		$periods = array(
			1  => __( '24 hours', 'scrapelock' ),
			7  => __( '7 days', 'scrapelock' ),
			30 => __( '30 days', 'scrapelock' ),
			90 => __( '90 days', 'scrapelock' ),
		);
		echo '<p class="pncp-attacks__periods">';
		foreach ( $periods as $value => $label ) {
			if ( $value > self::retention() ) {
				continue;
			}
			$url = add_query_arg( 'pncp_at_days', $value, remove_query_arg( array( 'pncp_message', '_wpnonce' ) ) );
			if ( $value === $days ) {
				printf( '<strong aria-current="true">%s</strong> ', esc_html( $label ) );
			} else {
				printf( '<a href="%1$s">%2$s</a> ', esc_url( $url ), esc_html( $label ) );
			}
		}
		echo '</p>';
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only: the page's own GET parameters.
		$keep = array();
		foreach ( array( 'page', 'tab' ) as $param ) {
			if ( isset( $_GET[ $param ] ) ) {
				$keep[ $param ] = sanitize_key( wp_unslash( $_GET[ $param ] ) );
			}
		}
		// phpcs:enable
		?>
		<form method="get" action="" class="pncp-attacks__filter">
			<?php foreach ( $keep as $name => $value ) : ?>
				<input type="hidden" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>">
			<?php endforeach; ?>
			<input type="hidden" name="pncp_at_days" value="<?php echo esc_attr( (string) $days ); ?>">
			<label for="pncp-at-cat"><?php esc_html_e( 'Kind of attack', 'scrapelock' ); ?></label>
			<select id="pncp-at-cat" name="pncp_at_cat">
				<option value=""><?php esc_html_e( 'All', 'scrapelock' ); ?></option>
				<?php foreach ( self::categories() as $key => $label ) : ?>
					<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $category, $key ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
			<?php submit_button( __( 'Show', 'scrapelock' ), 'secondary', '', false ); ?>
		</form>
		<?php
	}

	/**
	 * A bar chart as inline SVG, with a title per bar for screen readers and tooltips.
	 *
	 * @param array<string, int> $series Label => value.
	 * @param bool               $hourly Labels are hours.
	 */
	public static function render_chart( $series, $hourly = false ) {
		$max = $series ? max( 1, max( $series ) ) : 1;
		$n   = max( 1, count( $series ) );
		$w   = 720;
		$h   = 140;
		$bw  = $w / $n;
		$sum = array_sum( $series );
		if ( ! $sum ) {
			echo '<p class="pncp-empty">' . esc_html__( 'Nothing recorded in this period.', 'scrapelock' ) . '</p>';
			return;
		}
		printf(
			'<svg class="pncp-attacks__chart" viewBox="0 0 %1$d %2$d" width="100%%" height="%2$d" preserveAspectRatio="none" role="img" aria-label="%3$s" style="max-width:100%%;color:#d63638;background:rgba(0,0,0,.03)">',
			(int) $w,
			(int) ( $h + 16 ),
			esc_attr(
				sprintf(
					/* translators: 1: number of events, 2: highest value of one bar */
					__( '%1$s events, at most %2$s in one bar', 'scrapelock' ),
					number_format_i18n( $sum ),
					number_format_i18n( $max )
				)
			)
		);
		$i = 0;
		foreach ( $series as $label => $value ) {
			$bh = $value > 0 ? max( 1, round( $h * $value / $max, 1 ) ) : 0;
			printf(
				'<rect x="%1$s" y="%2$s" width="%3$s" height="%4$s" fill="currentColor"><title>%5$s</title></rect>',
				esc_attr( (string) round( $i * $bw + 1, 1 ) ),
				esc_attr( (string) ( $h - $bh ) ),
				esc_attr( (string) max( 1, round( $bw - 2, 1 ) ) ),
				esc_attr( (string) $bh ),
				esc_html( $label . ': ' . number_format_i18n( $value ) )
			);
			++$i;
		}
		$keys  = array_keys( $series );
		$first = (string) reset( $keys );
		$last  = (string) end( $keys );
		printf(
			'<text x="2" y="%1$d" font-size="11" fill="#646970">%2$s</text><text x="%3$d" y="%1$d" font-size="11" fill="#646970" text-anchor="end">%4$s</text><text x="%3$d" y="11" font-size="11" fill="#646970" text-anchor="end">%5$s</text>',
			(int) ( $h + 13 ),
			esc_html( $hourly ? substr( $first, 11 ) : $first ),
			(int) ( $w - 2 ),
			esc_html( $hourly ? substr( $last, 11 ) : $last ),
			esc_html( number_format_i18n( $max ) )
		);
		echo '</svg>';
	}

	/**
	 * Card: where they hit, per kind of attack, with what it means and how to close it.
	 *
	 * @param int $days Days.
	 */
	public static function render_where_card( $days = 7 ) {
		$sum    = self::summary( $days );
		$labels = self::categories();
		$advice = self::advice();
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-attacks-where">
			<h2 id="pncp-attacks-where"><?php esc_html_e( 'Where they hit, and how to close it', 'scrapelock' ); ?></h2>
			<?php if ( ! $sum['by_category'] ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
					<th scope="col"><?php esc_html_e( 'Kind of attack', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'Events', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'Share', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'What it means', 'scrapelock' ); ?></th>
				</tr></thead><tbody>
				<?php foreach ( $sum['by_category'] as $key => $hits ) : ?>
					<tr>
						<td><a href="<?php echo esc_url( add_query_arg( 'pncp_at_cat', $key, remove_query_arg( 'pncp_message' ) ) ); ?>"><?php echo esc_html( isset( $labels[ $key ] ) ? $labels[ $key ] : $key ); ?></a></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $hits ) ); ?></td>
						<td class="num"><?php echo esc_html( number_format_i18n( 100 * $hits / max( 1, $sum['total'] ), 1 ) . '%' ); ?></td>
						<td><?php echo esc_html( isset( $advice[ $key ] ) ? $advice[ $key ] : '' ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody></table></div>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Card: the paths hit most.
	 *
	 * @param int    $days     Days.
	 * @param string $category Category ('' = all).
	 */
	public static function render_paths_card( $days = 7, $category = '' ) {
		$rows   = self::top_paths( $days, 25, $category );
		$labels = self::categories();
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-attacks-paths">
			<h2 id="pncp-attacks-paths"><?php esc_html_e( 'Addresses attacked most', 'scrapelock' ); ?></h2>
			<?php if ( ! $rows ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
					<th scope="col"><?php esc_html_e( 'Address', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Kind of attack', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'Events', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'Refused', 'scrapelock' ); ?></th>
				</tr></thead><tbody>
				<?php foreach ( $rows as $row ) : ?>
					<tr>
						<td><code><?php echo esc_html( '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : __( '(many addresses)', 'scrapelock' ) ); ?></code></td>
						<td><?php echo esc_html( isset( $labels[ $row['category'] ] ) ? $labels[ $row['category'] ] : $row['category'] ); ?></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $row['ips'] ) ); ?></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $row['blocked'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody></table></div>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Card: the addresses with the most events, each with "Always block" (the Log's own action).
	 *
	 * @param int    $days     Days.
	 * @param string $category Category ('' = all).
	 */
	public static function render_ips_card( $days = 7, $category = '' ) {
		$rows   = self::top_ips( $days, 25, $category );
		$labels = self::categories();
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-attacks-ips">
			<h2 id="pncp-attacks-ips"><?php esc_html_e( 'Addresses that attacked most', 'scrapelock' ); ?></h2>
			<?php if ( ! $rows ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php else : ?>
				<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
					<th scope="col"><?php esc_html_e( 'IP', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'Events', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'What it tried', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Last seen', 'scrapelock' ); ?></th>
					<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'scrapelock' ); ?></span></th>
				</tr></thead><tbody>
				<?php foreach ( $rows as $row ) : ?>
					<?php
					$kinds = array();
					foreach ( array_filter( explode( ',', $row['categories'] ) ) as $key ) {
						$kinds[] = isset( $labels[ $key ] ) ? $labels[ $key ] : $key;
					}
					?>
					<tr>
						<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td>
						<td><?php echo esc_html( implode( ', ', $kinds ) ); ?></td>
						<td><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $row['last'] ) ); ?></td>
						<td>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
								<input type="hidden" name="action" value="pncp_log">
								<input type="hidden" name="op" value="block_permanent">
								<input type="hidden" name="ip" value="<?php echo esc_attr( $row['ip'] ); ?>">
								<?php wp_nonce_field( 'pncp_log', '_wpnonce', true ); ?>
								<button type="submit" class="button button-small">
									<?php esc_html_e( 'Always block', 'scrapelock' ); ?><span class="screen-reader-text"> <?php echo esc_html( $row['ip'] ); ?></span>
								</button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody></table></div>
				<p class="description"><?php esc_html_e( '“Always block” adds the address to “Always-blocked IPs”. Addresses of home connections change hands: prefer it for data centers and for addresses that keep coming back.', 'scrapelock' ); ?></p>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Card: the usernames tried, the XML-RPC methods, the plugins and themes probed, the attack patterns.
	 *
	 * @param int $days Days.
	 */
	public static function render_details_card( $days = 7 ) {
		$lists    = array(
			'login_fail'   => array( __( 'Usernames tried', 'scrapelock' ), __( 'Username', 'scrapelock' ) ),
			'xmlrpc'       => array( __( 'XML-RPC methods called', 'scrapelock' ), __( 'Method', 'scrapelock' ) ),
			'plugin_probe' => array( __( 'Plugins and themes looked for', 'scrapelock' ), __( 'Plugin or theme', 'scrapelock' ) ),
			'injection'    => array( __( 'Attack patterns', 'scrapelock' ), __( 'Pattern', 'scrapelock' ) ),
			'bot_block'    => array( __( 'Why ScrapeLock refused', 'scrapelock' ), __( 'Reason', 'scrapelock' ) ),
		);
		$patterns = array(
			'sqli'      => __( 'SQL injection', 'scrapelock' ),
			'xss'       => __( 'Script injection (XSS)', 'scrapelock' ),
			'traversal' => __( 'File path traversal (../, /etc/passwd)', 'scrapelock' ),
			'rce'       => __( 'Code or command injection', 'scrapelock' ),
		);
		$reasons  = PNCP_Log::reasons();
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-attacks-details">
			<h2 id="pncp-attacks-details"><?php esc_html_e( 'What they tried', 'scrapelock' ); ?></h2>
			<?php
			$any = false;
			foreach ( $lists as $category => $titles ) :
				$rows = self::top_details( $days, $category, 15 );
				if ( ! $rows ) {
					continue;
				}
				$any = true;
				?>
				<h3><?php echo esc_html( $titles[0] ); ?></h3>
				<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
					<th scope="col"><?php echo esc_html( $titles[1] ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'Events', 'scrapelock' ); ?></th>
					<th scope="col" class="num"><?php esc_html_e( 'IPs', 'scrapelock' ); ?></th>
				</tr></thead><tbody>
				<?php foreach ( $rows as $row ) : ?>
					<?php
					$label = $row['detail'];
					if ( 'injection' === $category && isset( $patterns[ $label ] ) ) {
						$label = $patterns[ $label ];
					} elseif ( 'bot_block' === $category && isset( $reasons[ $label ] ) ) {
						$label = $reasons[ $label ];
					}
					?>
					<tr>
						<td><code><?php echo esc_html( $label ); ?></code></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $row['ips'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody></table></div>
			<?php endforeach; ?>
			<?php if ( ! $any ) : ?>
				<p class="pncp-empty"><?php esc_html_e( 'Nothing recorded in this period.', 'scrapelock' ); ?></p>
			<?php endif; ?>
			<?php if ( self::top_details( $days, 'login_fail', 1 ) ) : ?>
				<p class="description"><?php esc_html_e( 'A real username in this list is a target: give that account a long, unique password and two-factor sign-in.', 'scrapelock' ); ?></p>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Card: CSV export and deleting the record.
	 *
	 * @param int $days Days.
	 */
	public static function render_tools_card( $days = 7 ) {
		$locked = class_exists( 'PNCP_Lockdown' ) && PNCP_Lockdown::is_locked();
		?>
		<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-attacks-tools">
			<h2 id="pncp-attacks-tools"><?php esc_html_e( 'Export or delete the attack record', 'scrapelock' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:12px;">
				<input type="hidden" name="action" value="pncp_attacks_export">
				<input type="hidden" name="days" value="<?php echo esc_attr( (string) $days ); ?>">
				<?php wp_nonce_field( 'pncp_attacks_export', '_wpnonce', true ); ?>
				<?php submit_button( __( 'Download as CSV', 'scrapelock' ), 'secondary', 'submit', false, array( 'id' => 'pncp-attacks-export' ) ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;">
				<input type="hidden" name="action" value="pncp_attacks_clear">
				<?php wp_nonce_field( 'pncp_attacks_clear', '_wpnonce', true ); ?>
				<?php
				$attrs = array( 'id' => 'pncp-attacks-clear' );
				if ( $locked ) {
					$attrs['disabled'] = 'disabled';
				}
				submit_button( __( 'Delete the attack record', 'scrapelock' ), 'delete', 'submit', false, $attrs );
				?>
			</form>
			<p class="description">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: number of days */
						_n( 'The CSV has the period shown above, one line per hour, kind of attack, address and IP. The record keeps IP addresses and the usernames tried, and is deleted automatically after %s day.', 'The CSV has the period shown above, one line per hour, kind of attack, address and IP. The record keeps IP addresses and the usernames tried, and is deleted automatically after %s days.', self::retention(), 'scrapelock' ),
						number_format_i18n( self::retention() )
					)
				);
				?>
				<?php if ( $locked ) : ?>
					<?php esc_html_e( 'While the site is locked it cannot be deleted.', 'scrapelock' ); ?>
				<?php endif; ?>
			</p>
		</section>
		<?php
	}

	/**
	 * A small card for the Dashboard tab: the last 24 hours.
	 */
	public static function render_dashboard_card() {
		$sum  = self::summary( 1 );
		$cats = $sum['by_category'];
		?>
		<section class="pncp-card" aria-labelledby="pncp-attacks-24h">
			<h2 id="pncp-attacks-24h"><?php esc_html_e( 'Attacks in the last 24 hours', 'scrapelock' ); ?></h2>
			<ul>
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'Failed sign-ins: %s', 'scrapelock' ), number_format_i18n( $sum['login']['failed'] ) ) ); ?></li>
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'wp-admin requests while logged out: %s', 'scrapelock' ), number_format_i18n( isset( $cats['admin_probe'] ) ? $cats['admin_probe'] : 0 ) ) ); ?></li>
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'XML-RPC calls: %s', 'scrapelock' ), number_format_i18n( isset( $cats['xmlrpc'] ) ? $cats['xmlrpc'] : 0 ) ) ); ?></li>
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'Scanner and plugin probes: %s', 'scrapelock' ), number_format_i18n( ( isset( $cats['scanner'] ) ? $cats['scanner'] : 0 ) + ( isset( $cats['plugin_probe'] ) ? $cats['plugin_probe'] : 0 ) ) ) ); ?></li>
				<li><?php echo esc_html( sprintf( /* translators: %s: number */ __( 'Different addresses: %s', 'scrapelock' ), number_format_i18n( $sum['unique_ips'] ) ) ); ?></li>
			</ul>
			<p><a href="<?php echo esc_url( self::back_url( '' ) ); ?>"><?php esc_html_e( 'Full report', 'scrapelock' ); ?></a></p>
		</section>
		<?php
	}

	/* ---------- Site Health ---------- */

	/**
	 * Site Health test: password guessing in the last 24 hours.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_test() {
		$result = array(
			'label'       => __( 'No password guessing in the last 24 hours', 'scrapelock' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html__( 'ScrapeLock records failed sign-ins and XML-RPC calls. Fewer than 50 failed sign-ins in a day is normal background noise.', 'scrapelock' ) . '</p>',
			'actions'     => '',
			'test'        => 'pncp_attacks',
		);
		if ( ! self::enabled() || ! self::ready() ) {
			$result['label']       = __( 'ScrapeLock does not record attacks', 'scrapelock' );
			$result['description'] = '<p>' . esc_html__( 'Without the attack record you cannot see where bots try to sign in or what they look for. Turn on “Record where bots and attackers hit the site”.', 'scrapelock' ) . '</p>';
			return $result;
		}
		$sum    = self::summary( 1 );
		$failed = $sum['login']['failed'];
		$multi  = self::count( 1, 'xmlrpc' );
		if ( $failed > 0 || $multi > 0 ) {
			$result['label'] = sprintf(
				/* translators: 1: number of failed sign-ins, 2: number of XML-RPC calls */
				__( 'Failed sign-ins in the last 24 hours: %1$s, XML-RPC calls: %2$s (normal background noise)', 'scrapelock' ),
				number_format_i18n( $failed ),
				number_format_i18n( $multi )
			);
			$result['actions'] = '<p><a href="' . esc_url( self::back_url( '' ) ) . '">' . esc_html__( 'See the attack report', 'scrapelock' ) . '</a></p>';
		}
		if ( $failed >= 50 || $multi >= 200 ) {
			$result['status']      = 'recommended';
			$result['label']       = __( 'Bots are guessing passwords on this site', 'scrapelock' );
			$result['description'] = '<p>' . esc_html(
				sprintf(
					/* translators: 1: number of failed sign-ins, 2: number of addresses, 3: number of XML-RPC calls */
					__( 'In the last 24 hours: %1$s failed sign-ins from %2$s addresses, and %3$s XML-RPC calls. Use strong passwords and two-factor sign-in, hide usernames from visitors, and block xmlrpc.php if nothing uses it.', 'scrapelock' ),
					number_format_i18n( $failed ),
					number_format_i18n( $sum['login']['ips'] ),
					number_format_i18n( $multi )
				)
			) . '</p>';
			$result['actions'] = '<p><a href="' . esc_url( self::back_url( '' ) ) . '">' . esc_html__( 'See the attack report', 'scrapelock' ) . '</a></p>';
		}
		return $result;
	}

	/* ---------- WP-CLI ---------- */

	/**
	 * The rows of "wp scrapelock attacks".
	 *
	 * @param int    $days     Days.
	 * @param string $category Category ('' = all).
	 * @param string $top      categories | paths | ips | users | details.
	 * @return array{0:array<int, array<string, mixed>>, 1:string[]} Items and fields.
	 */
	public static function cli_rows( $days, $category = '', $top = 'categories' ) {
		$labels = self::categories();
		$items  = array();
		switch ( $top ) {
			case 'paths':
				foreach ( self::top_paths( $days, 50, $category ) as $row ) {
					$items[] = array(
						'path'     => '' !== $row['path'] ? PNCP_Log::display_path( $row['path'] ) : '(many)',
						'category' => $row['category'],
						'hits'     => $row['hits'],
						'ips'      => $row['ips'],
						'blocked'  => $row['blocked'],
					);
				}
				return array( $items, array( 'path', 'category', 'hits', 'ips', 'blocked' ) );
			case 'ips':
				foreach ( self::top_ips( $days, 50, $category ) as $row ) {
					$items[] = array(
						'ip'         => $row['ip'],
						'hits'       => $row['hits'],
						'categories' => $row['categories'],
						'last'       => wp_date( 'Y-m-d H:i:s', $row['last'] ),
					);
				}
				return array( $items, array( 'ip', 'hits', 'categories', 'last' ) );
			case 'users':
			case 'details':
				$cat = 'users' === $top ? 'login_fail' : ( '' !== $category ? $category : 'login_fail' );
				foreach ( self::top_details( $days, $cat, 50 ) as $row ) {
					$items[] = array(
						'detail' => $row['detail'],
						'hits'   => $row['hits'],
						'ips'    => $row['ips'],
					);
				}
				return array( $items, array( 'detail', 'hits', 'ips' ) );
		}
		$sum = self::summary( $days );
		foreach ( $sum['by_category'] as $key => $hits ) {
			if ( '' !== $category && $key !== $category ) {
				continue;
			}
			$items[] = array(
				'category' => $key,
				'label'    => isset( $labels[ $key ] ) ? $labels[ $key ] : $key,
				'hits'     => $hits,
			);
		}
		return array( $items, array( 'category', 'label', 'hits' ) );
	}

	/**
	 * "wp scrapelock attacks [--days=<n>] [--category=<key>] [--top=paths|ips|users|details] [--format=<f>]".
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cli( $args, $assoc_args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed -- WP-CLI signature.
		$days     = max( 1, min( 90, isset( $assoc_args['days'] ) ? (int) $assoc_args['days'] : 7 ) );
		$category = isset( $assoc_args['category'] ) ? sanitize_key( $assoc_args['category'] ) : '';
		$top      = isset( $assoc_args['top'] ) ? sanitize_key( $assoc_args['top'] ) : 'categories';
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( '' !== $category && ! isset( self::categories()[ $category ] ) ) {
			/* translators: %s: list of categories */
			WP_CLI::error( sprintf( __( 'Unknown --category. Use: %s.', 'scrapelock' ), implode( ', ', array_keys( self::categories() ) ) ) );
		}
		if ( ! in_array( $top, array( 'categories', 'paths', 'ips', 'users', 'details' ), true ) ) {
			WP_CLI::error( __( 'Unknown --top. Use: paths, ips, users or details.', 'scrapelock' ) );
		}
		if ( ! in_array( $format, array( 'table', 'json', 'csv', 'yaml', 'count' ), true ) ) {
			WP_CLI::error( __( 'Unknown --format. Use: table, json, csv, yaml or count.', 'scrapelock' ) );
		}
		if ( 'categories' === $top && 'table' === $format ) {
			$sum = self::summary( $days );
			WP_CLI::log(
				sprintf(
					/* translators: 1: days, 2: events, 3: refused, 4: addresses, 5: failed sign-ins */
					__( 'Last %1$d days: %2$d events, %3$d refused, %4$d addresses, %5$d failed sign-ins.', 'scrapelock' ),
					$days,
					$sum['total'],
					$sum['blocked'],
					$sum['unique_ips'],
					$sum['login']['failed']
				)
			);
		}
		list( $items, $fields ) = self::cli_rows( $days, $category, $top );
		WP_CLI\Utils\format_items( $format, $items, $fields );
	}
}
