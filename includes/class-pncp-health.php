<?php
/**
 * ScrapeLock on Tools → Site Health: tests for the settings that silently stop working (the real visitor IP
 * behind a CDN, the early check, the pre-cache check, the official IP lists, Lockdown), for the states that
 * should not last (Emergency Mode, Monitor only), and a section in the Info tab.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Site Health tests and debug information.
 */
final class PNCP_Health {

	/**
	 * 3.5: admin-post action (and nonce action) of "Check again now".
	 */
	const RECHECK = 'pncp_health_recheck';

	/**
	 * 3.5: transient with the last robots.txt check (codes, flags and agent names only, never the body).
	 */
	const ROBOTS_CACHE = 'pncp_health_robots';

	/**
	 * 3.5: transient with the last private folders check (folder ids only, never a folder name).
	 */
	const FOLDERS_CACHE = 'pncp_health_folders';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'site_status_tests', array( __CLASS__, 'tests' ) );
		add_filter( 'debug_information', array( __CLASS__, 'info' ) );
		if ( is_admin() ) {
			// 3.5: the two tests that request the site itself run after the page has loaded (Site Health's async tests).
			add_action( 'wp_ajax_health-check-scrapelock-robots', array( __CLASS__, 'ajax_robots' ) );
			add_action( 'wp_ajax_health-check-scrapelock-folders', array( __CLASS__, 'ajax_folders' ) );
			add_action( 'admin_post_' . self::RECHECK, array( __CLASS__, 'handle_recheck' ) );
		}
	}

	/**
	 * The tests, all direct (they only read settings, files and the current request). 3.5: plus two async ones
	 * that ask the site itself for robots.txt and for test files in the private folders (cached for a day).
	 *
	 * @param array<string, mixed> $tests Tests.
	 * @return array<string, mixed>
	 */
	public static function tests( $tests ) {
		$names = array(
			'protection' => __( 'ScrapeLock protection', 'scrapelock' ),
			'emergency'  => __( 'ScrapeLock Emergency Mode', 'scrapelock' ),
			'monitor'    => __( 'ScrapeLock Monitor only', 'scrapelock' ),
			'ip_lists'   => __( 'ScrapeLock official IP lists', 'scrapelock' ),
			'real_ip'    => __( 'ScrapeLock real visitor IP', 'scrapelock' ),
			'origin'     => __( 'ScrapeLock only through the CDN', 'scrapelock' ),
			'early'      => __( 'ScrapeLock early check', 'scrapelock' ),
			'precheck'   => __( 'ScrapeLock pre-cache check', 'scrapelock' ),
			'lockdown'   => __( 'ScrapeLock Lockdown', 'scrapelock' ),
			'integrity'  => __( 'ScrapeLock file integrity', 'scrapelock' ),
		);
		foreach ( $names as $key => $label ) {
			$tests['direct'][ 'scrapelock_' . $key ] = array(
				'label' => $label,
				'test'  => array( __CLASS__, 'test_' . $key ),
			);
		}
		// 3.5: two more direct tests, and two async ones that request the site itself (robots.txt, private folders).
		// The async keys have exactly one underscore: Site Health's script replaces only the first one when it
		// builds the AJAX action (health-check-scrapelock-robots). No REST route: a new namespace would show in
		// /wp-json/ and the tests would depend on the REST API being reachable.
		$tests['direct']['scrapelock_open_content'] = array(
			'label' => __( 'ScrapeLock content in other channels', 'scrapelock' ),
			'test'  => array( __CLASS__, 'test_open_content' ),
		);
		$tests['direct']['scrapelock_conflicts']    = array(
			'label' => __( 'ScrapeLock and plugins that do the same job', 'scrapelock' ),
			'test'  => array( __CLASS__, 'test_conflicts' ),
		);
		$tests['async']['scrapelock_robots']        = array(
			'label'             => __( 'ScrapeLock lines in robots.txt', 'scrapelock' ),
			'test'              => 'scrapelock_robots',
			'has_rest'          => false,
			'async_direct_test' => array( __CLASS__, 'test_robots' ),
		);
		$tests['async']['scrapelock_folders']       = array(
			'label'             => __( 'ScrapeLock private folders', 'scrapelock' ),
			'test'              => 'scrapelock_folders',
			'has_rest'          => false,
			'async_direct_test' => array( __CLASS__, 'test_folders' ),
		);
		return $tests;
	}

	/**
	 * One result in the form Site Health expects.
	 *
	 * @param string $key         Test key.
	 * @param string $status      good | recommended | critical.
	 * @param string $label       Title.
	 * @param string $description Explanation (plain text).
	 * @param string $tab         Settings tab for the link ('' = none).
	 * @param string $anchor      Section of the tab for the link, e.g. "pncp-sec-lists" ('' = the top).
	 * @param string $extra       More actions, already escaped HTML (e.g. a "Stop Emergency Mode" link).
	 * @param string $details     3.5: more description, already escaped HTML (lists, lines to copy), after the text.
	 * @return array<string, mixed>
	 */
	private static function result( $key, $status, $label, $description, $tab = '', $anchor = '', $extra = '', $details = '' ) {
		$link = '';
		if ( '' !== $tab ) {
			$url  = PNCP_Status::settings_url( array( 'tab' => $tab ) ) . ( '' !== $anchor ? '#' . $anchor : '' );
			$link = '<p><a href="' . esc_url( $url ) . '">' . esc_html__( 'Open the ScrapeLock settings', 'scrapelock' ) . '</a></p>';
		}
		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'critical' === $status ? 'red' : ( 'recommended' === $status ? 'orange' : 'blue' ),
			),
			'description' => '<p>' . esc_html( $description ) . '</p>' . $details,
			'actions'     => $extra . $link,
			'test'        => 'scrapelock_' . $key,
		);
	}

	/**
	 * Is protection on?
	 *
	 * @return array<string, mixed>
	 */
	public static function test_protection() {
		if ( PNCP_Status::is_enabled() ) {
			return self::result( 'protection', 'good', __( 'ScrapeLock protection is on', 'scrapelock' ), __( 'Content, feeds and the REST API are protected and bots are checked.', 'scrapelock' ) );
		}
		return self::result( 'protection', 'recommended', __( 'ScrapeLock protection is off', 'scrapelock' ), __( 'The plugin is active but protects nothing: content can be copied and bots are not checked.', 'scrapelock' ), 'general' );
	}

	/**
	 * Emergency Mode is meant for the hours of an attack, not for good: it shows excerpts instead of full text
	 * in lists, limits data centers harder and turns on the browser checks, which real visitors and services
	 * notice. Recommended while it runs; critical when it was started for more than a day (it can run up to 72
	 * hours), so a forgotten start is noticed.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_emergency() {
		$until = PNCP_Options::emergency_until();
		if ( ! $until ) {
			return self::result( 'emergency', 'good', __( 'ScrapeLock Emergency Mode is off', 'scrapelock' ), __( 'The normal settings apply. Emergency Mode is started by hand (or by the automatic Emergency Mode, if you let it) during a scraping attack, and ends by itself.', 'scrapelock' ) );
		}
		$left = $until - time();
		$stop = '<p><a class="button" href="' . esc_url( PNCP_Status::emergency_stop_url() ) . '">' . esc_html__( 'Stop Emergency Mode now', 'scrapelock' ) . '</a></p>';
		return self::result(
			'emergency',
			$left > DAY_IN_SECONDS ? 'critical' : 'recommended',
			/* translators: %s: time left, e.g. "3 hours" */
			sprintf( __( 'ScrapeLock Emergency Mode is on for another %s', 'scrapelock' ), human_time_diff( time(), $until ) ),
			sprintf(
				/* translators: %s: date and time */
				__( 'Until %s, stricter limits and checks apply to everyone except verified search engines and exempt staff, and lists of articles may show excerpts instead of the full text. Real visitors and some services (feeds, apps, monitoring from data centers) can notice it. Stop it as soon as the attack is over.', 'scrapelock' ),
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $until )
			),
			'general',
			'',
			$stop
		);
	}

	/**
	 * "Monitor only": every check runs, but nothing is blocked. Fine for the first days, not for good.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_monitor() {
		$s = PNCP_Options::stored();
		if ( empty( $s['enabled'] ) || ! PNCP_Options::monitoring( $s ) ) {
			return self::result( 'monitor', 'good', __( 'ScrapeLock blocks what its settings say', 'scrapelock' ), __( '“Monitor only” is off: requests that the settings refuse are blocked.', 'scrapelock' ) );
		}
		$description = __( 'Every check runs, but a request the settings would refuse is let through and only logged as “Would block”. Scrapers are not stopped. Check the “Would block” entries in the Log, add the services you rely on to “Always allowed”, then turn “Monitor only” off.', 'scrapelock' );
		if ( ! empty( $s['monitor_until'] ) ) {
			$description .= ' ' . sprintf(
				/* translators: %s: date and time */
				__( 'This is the first week of a new install: ScrapeLock starts blocking on its own on %s.', 'scrapelock' ),
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $s['monitor_until'] )
			);
		}
		$log = '<p><a href="' . esc_url( PNCP_Status::log_url( 'monitor' ) ) . '">' . esc_html__( 'See what would have been blocked', 'scrapelock' ) . '</a></p>';
		return self::result( 'monitor', 'recommended', __( 'ScrapeLock is in “Monitor only” mode: nothing is blocked', 'scrapelock' ), $description, 'bots', 'pncp-sec-monitor', $log );
	}

	/**
	 * The official lists of Google, Bing and Cloudflare are downloaded once a day. Missing, or not refreshed
	 * for more than 3 days (the daily task stopped, or the server cannot reach them), real crawlers are
	 * verified with slower DNS lookups only and the Cloudflare addresses come from the list built into the
	 * plugin, which ages with it. Only the lists the current settings use are checked.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_ip_lists() {
		$names   = array(
			'google'     => 'Google',
			'bing'       => 'Bing',
			'cloudflare' => 'Cloudflare',
		);
		$updated = PNCP_Ip::lists_updated();
		$needed  = PNCP_Ip::needed_lists();
		$missing = array();
		$stale   = array();
		foreach ( $names as $key => $label ) {
			if ( ! in_array( $key, $needed, true ) ) {
				continue;
			}
			if ( empty( $updated[ $key ] ) ) {
				$missing[] = $label;
			} elseif ( $updated[ $key ] < time() - 3 * DAY_IN_SECONDS ) {
				$stale[] = $label;
			}
		}
		if ( ! $missing && ! $stale ) {
			return self::result( 'ip_lists', 'good', __( 'The official IP lists are up to date', 'scrapelock' ), __( 'The lists of Google, Bing and (when used) Cloudflare are refreshed every day.', 'scrapelock' ) );
		}
		$parts = array();
		if ( $missing ) {
			/* translators: %s: list names, e.g. "Google, Bing" */
			$parts[] = sprintf( __( 'Never downloaded: %s.', 'scrapelock' ), implode( ', ', $missing ) );
		}
		if ( $stale ) {
			/* translators: %s: list names, e.g. "Google, Bing" */
			$parts[] = sprintf( __( 'Not refreshed for more than 3 days: %s.', 'scrapelock' ), implode( ', ', $stale ) );
		}
		$parts[] = __( 'Until they are, real search engines are verified with slower DNS lookups only, and the Cloudflare addresses come from the list built into the plugin. The lists are refreshed once a day through WordPress\'s scheduled tasks (cron): check that cron runs and that the server can reach the Google, Bing and Cloudflare websites, or use “Refresh lists now”.', 'scrapelock' );
		return self::result( 'ip_lists', 'recommended', __( 'ScrapeLock official IP lists are missing or out of date', 'scrapelock' ), implode( ' ', $parts ), 'bots', 'pncp-sec-lists' );
	}

	/**
	 * Behind a CDN, does every visitor appear with the CDN's address?
	 *
	 * @return array<string, mixed>
	 */
	public static function test_real_ip() {
		$cdn = PNCP_Status::is_enabled() ? PNCP_Ip::cdn_hides_visitors() : '';
		if ( 'cloudflare' === $cdn ) {
			return self::result( 'real_ip', 'critical', __( 'All visitors appear with a Cloudflare address', 'scrapelock' ), __( 'The site is behind Cloudflare, but ScrapeLock sees Cloudflare\'s address instead of the visitor\'s. Limits and blocks then hit Cloudflare itself, i.e. many visitors at once. Use CF-Connecting-IP (one click on the Bots tab).', 'scrapelock' ), 'bots' );
		}
		if ( 'bunny' === $cdn ) {
			return self::result( 'real_ip', 'critical', __( 'All visitors appear with a Bunny CDN address', 'scrapelock' ), __( 'The site is behind Bunny CDN, but ScrapeLock sees Bunny\'s address instead of the visitor\'s. Limits and blocks then hit Bunny itself, i.e. many visitors at once. Use X-Real-IP from Bunny (one click on the Bots tab).', 'scrapelock' ), 'bots' );
		}
		$s    = PNCP_Options::stored();
		$wide = array();
		foreach ( PNCP_Options::parse_list( $s['trusted_proxies'] ) as $range ) {
			if ( PNCP_Options::range_too_wide( $range ) ) {
				$wide[] = $range;
			}
		}
		$open = array();
		foreach ( array( 'allow_ips', 'private_ips' ) as $key ) {
			foreach ( PNCP_Options::parse_list( isset( $s[ $key ] ) ? $s[ $key ] : '' ) as $range ) {
				if ( PNCP_Options::range_too_wide( PNCP_Options::unmap_range( $range ) ) ) {
					$open[] = $range;
				}
			}
		}
		if ( $open && ! $wide ) {
			// 3.4: saved by an earlier version (the form, import and WP-CLI now refuse them).
			/* translators: %s: the IP ranges */
			return self::result( 'real_ip', 'recommended', __( 'ScrapeLock allowed or private IPs include ranges that are too wide', 'scrapelock' ), sprintf( __( 'These ranges in "Always allowed IPs" or the private URL IPs cover a large part of the internet: %s. Every visitor in them skips the protection. Remove them and list only your own addresses.', 'scrapelock' ), implode( ', ', $open ) ), 'bots' );
		}
		if ( $wide ) {
			// 3.4: saved by an earlier version. They are ignored now, but the setting should be corrected.
			/* translators: %s: the IP ranges */
			return self::result( 'real_ip', 'recommended', __( 'ScrapeLock trusted proxies include ranges that are too wide', 'scrapelock' ), sprintf( __( 'These trusted proxy ranges cover a large part of the internet: %s. With them any visitor could choose its own IP with a header, so ScrapeLock ignores them. Remove them and list only the addresses of your own proxy or load balancer.', 'scrapelock' ), implode( ', ', $wide ) ), 'bots' );
		}
		return self::result( 'real_ip', 'good', __( 'ScrapeLock sees the real visitor IP', 'scrapelock' ), __( 'No CDN was found hiding the visitors\' addresses on this request.', 'scrapelock' ) );
	}

	/**
	 * "Only through the CDN" on, but every request comes from a local reverse proxy that is not trusted, so they
	 * all pass as the server's own requests and the setting does nothing.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_origin() {
		if ( ! PNCP_Status::is_enabled() || ! PNCP_Origin::active() ) {
			return self::result( 'origin', 'good', __( 'ScrapeLock “Only through the CDN” is not in use', 'scrapelock' ), __( 'Requests that go around the CDN are not refused. Turn it on (Bots tab) once the CDN sends the shared secret.', 'scrapelock' ) );
		}
		if ( PNCP_Origin::proxy_problem() ) {
			return self::result( 'origin', 'critical', __( '“Only through the CDN” does not protect this site yet', 'scrapelock' ), PNCP_Origin::proxy_message(), 'bots' );
		}
		return self::result( 'origin', 'good', __( 'ScrapeLock refuses requests that go around the CDN', 'scrapelock' ), __( 'Requests without the CDN shared secret get a 403.', 'scrapelock' ) );
	}

	/**
	 * Early check on, but the mu-plugin is missing.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_early() {
		$s = PNCP_Options::stored();
		if ( empty( $s['enabled'] ) || empty( $s['early_mode'] ) ) {
			return self::result( 'early', 'good', __( 'The ScrapeLock early check is off', 'scrapelock' ), __( 'Bots are checked when the plugin loads, as usual.', 'scrapelock' ) );
		}
		if ( PNCP_Early::installed() ) {
			return self::result( 'early', 'good', __( 'The ScrapeLock early check is running', 'scrapelock' ), __( 'Its file in wp-content/mu-plugins is in place: bots are stopped before other plugins load.', 'scrapelock' ) );
		}
		return self::result( 'early', 'recommended', __( 'The ScrapeLock early check is on but not running', 'scrapelock' ), __( 'Its file in wp-content/mu-plugins is missing or out of date (the server does not allow direct file writes). Bots are still checked, only later. Save the settings again, or turn the setting off.', 'scrapelock' ), 'bots' );
	}

	/**
	 * Pre-cache check on, but not loaded from wp-config.php.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_precheck() {
		$s = PNCP_Options::stored();
		if ( empty( $s['enabled'] ) || empty( $s['precheck'] ) ) {
			// 3.4.3: a page cache plugin that serves stored pages from advanced-cache.php (WP Super Cache, W3 Total
			// Cache, Cache Enabler, WP Rocket...) answers before ScrapeLock's normal and early checks: without the
			// pre-cache check, bots, limits and bans do not apply to those pages.
			if ( ! empty( $s['enabled'] ) && defined( 'WP_CACHE' ) && WP_CACHE && file_exists( WP_CONTENT_DIR . '/advanced-cache.php' ) && ! is_multisite() ) {
				return self::result( 'precheck', 'recommended', __( 'A page cache answers before ScrapeLock', 'scrapelock' ), __( 'A page cache plugin serves stored pages before WordPress loads, so the bot list, the page limits and the blocks do not apply to them. Turn on the pre-cache check in the Bots tab.', 'scrapelock' ), 'bots' );
			}
			return self::result( 'precheck', 'good', __( 'The ScrapeLock pre-cache check is off', 'scrapelock' ), __( 'Pages served from the page cache are not checked first; the normal check works as usual.', 'scrapelock' ) );
		}
		if ( PNCP_Precheck::active() ) {
			return self::result( 'precheck', 'good', __( 'The ScrapeLock pre-cache check is running', 'scrapelock' ), __( 'wp-config.php loads the check before the page cache.', 'scrapelock' ) );
		}
		return self::result( 'precheck', 'recommended', __( 'The ScrapeLock pre-cache check is on but not running', 'scrapelock' ), __( 'wp-config.php does not load it (it could not be changed, or the folder uploads/scrapelock could not be created). The normal check works as before; the Bots tab shows the lines to add by hand.', 'scrapelock' ), 'bots' );
	}

	/**
	 * Lockdown: off from the server, or updates waiting while locked.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_lockdown() {
		if ( PNCP_Lockdown::server_unlocked() ) {
			return self::result( 'lockdown', 'critical', __( 'ScrapeLock Lockdown is off from the server', 'scrapelock' ), __( 'SCRAPELOCK_UNLOCK is set in wp-config.php, so the lock is not applied. Connect the authenticator app again, then remove that line.', 'scrapelock' ), 'lockdown' );
		}
		if ( '' !== PNCP_Lockdown::tampered() ) {
			return self::result( 'lockdown', 'critical', __( 'ScrapeLock Lockdown data was changed outside WordPress', 'scrapelock' ), __( 'The lock state in the database no longer matches its signature or the guard file. If you did not change the keys in wp-config.php, someone changed the database directly; while the guard file says the site is locked, it stays locked. Check the site with a security scanner and change the database password.', 'scrapelock' ), 'lockdown' );
		}
		if ( PNCP_Lockdown::configured() && ! PNCP_Seal::keys_in_config() ) {
			return self::result( 'lockdown', 'recommended', __( 'ScrapeLock Lockdown: the security keys are not in wp-config.php', 'scrapelock' ), __( 'AUTH_KEY and AUTH_SALT are not defined in wp-config.php, so WordPress keeps them in the database. Lockdown encrypts and signs its data with them: someone who can change the database could then also read them. Add the keys to wp-config.php (from https://api.wordpress.org/secret-key/1.1/salt/) and connect the authenticator app again.', 'scrapelock' ), 'lockdown' );
		}
		if ( ( PNCP_Lockdown::is_locked() || PNCP_Lockdown::unlocked_until() ) && PNCP_Seal::needs_config() && '' === PNCP_Seal::beacon_writable_dir() ) {
			// 3.4.2: no folder can be written: the lock line in wp-config.php is the only copy outside the database.
			if ( 'current' === PNCP_Seal::config_status() ) {
				return self::result( 'lockdown', 'recommended', __( 'ScrapeLock Lockdown is kept by the line in wp-config.php', 'scrapelock' ), __( 'WordPress cannot write to wp-content/mu-plugins or any other folder of wp-content, so the lock is kept outside the database by the line SCRAPELOCK_LOCKED in wp-config.php: if the Lockdown data in the database is deleted or changed, the site stays locked. Someone who can change the database directly could still deactivate ScrapeLock itself, and the active plugins and the theme are not kept from the start of every request. Let the web server write to wp-content/mu-plugins, then lock the site again.', 'scrapelock' ), 'lockdown' );
			}
			return self::result( 'lockdown', 'critical', __( 'ScrapeLock Lockdown is not protected yet', 'scrapelock' ), __( 'The site is locked, but WordPress cannot write to any folder of wp-content, and the lock line SCRAPELOCK_LOCKED for this lock is not in wp-config.php (it is missing, from an earlier lock, or not valid for this site): everything about the lock is in the database only, and someone who can change the database directly could delete it so that the site looks as if it had never been locked. Add the line shown on the Lockdown page to wp-config.php.', 'scrapelock' ), 'lockdown' );
		}
		if ( ! PNCP_Lockdown::is_locked() && ! PNCP_Lockdown::unlocked_until() && ! PNCP_Lockdown::server_unlocked() && 'stale' === PNCP_Seal::config_status() ) {
			return self::result( 'lockdown', 'recommended', __( 'ScrapeLock Lockdown: remove the lock line from wp-config.php', 'scrapelock' ), __( 'The site is unlocked, but wp-config.php still has the line SCRAPELOCK_LOCKED of the lock that has ended. Remove it: while it is there, if the Lockdown data is deleted from the database, the site locks again.', 'scrapelock' ), 'lockdown' );
		}
		if ( PNCP_Lockdown::is_locked() && ! PNCP_Seal::guard_installed() ) {
			if ( '' !== PNCP_Seal::beacon_path() ) {
				/* translators: %s: folder of the lock file */
				$text = sprintf( __( 'The file wp-content/mu-plugins/scrapelock-lockdown-guard.php could not be written, so the lock is kept by a signed lock file in %s. If the Lockdown data in the database is deleted or changed the site stays locked, but someone who can change the database directly could still deactivate ScrapeLock itself, and the active plugins and the theme are not kept from the start of every request. Let the web server write to wp-content/mu-plugins, then lock the site again.', 'scrapelock' ), PNCP_Seal::short_path( dirname( PNCP_Seal::beacon_path() ) ) );
			} elseif ( '' !== PNCP_Seal::beacon_writable_dir() ) {
				// 3.4.1: a folder can be written now (for example a site locked without the guard by 3.4.0): the lock
				// file is written by the hourly check, or when the site is locked again.
				/* translators: %s: folder of the lock file */
				$text = sprintf( __( 'The file wp-content/mu-plugins/scrapelock-lockdown-guard.php could not be written, and the signed lock file is not written yet, although %s can be written: for now everything about the lock is in the database only. ScrapeLock writes the lock file in its hourly check; to write it now, unlock and lock the site again.', 'scrapelock' ), PNCP_Seal::short_path( PNCP_Seal::beacon_writable_dir() ) );
			} else {
				$text = __( 'The file wp-content/mu-plugins/scrapelock-lockdown-guard.php could not be written, and no other folder of wp-content either: everything about the lock is in the database only. Someone who can change the database directly could delete it and open the lock without it being noticed. Let the web server write to wp-content/mu-plugins, then lock the site again.', 'scrapelock' );
			}
			return self::result( 'lockdown', 'recommended', __( 'ScrapeLock Lockdown works without its guard file', 'scrapelock' ), $text, 'lockdown' );
		}
		if ( ! PNCP_Lockdown::configured() ) {
			return self::result( 'lockdown', 'good', __( 'ScrapeLock Lockdown is not set up', 'scrapelock' ), __( 'Lockdown is optional: it freezes changes to plugins, themes, users and settings until it is unlocked with an authenticator app.', 'scrapelock' ) );
		}
		if ( ! PNCP_Lockdown::is_locked() ) {
			return self::result( 'lockdown', 'good', __( 'ScrapeLock Lockdown is unlocked', 'scrapelock' ), __( 'Changes to the site are allowed. Lock it again when you are done.', 'scrapelock' ) );
		}
		$waiting = self::updates_waiting();
		if ( $waiting > 0 ) {
			return self::result(
				'lockdown',
				'recommended',
				/* translators: %d: number of updates. */
				sprintf( _n( 'The site is locked: %d update is waiting', 'The site is locked: %d updates are waiting', $waiting, 'scrapelock' ), $waiting ),
				__( 'While locked, updates are not installed, not even automatically (so WordPress also reports background updates as off). Unlock with the authenticator app, update, then lock again.', 'scrapelock' ),
				'lockdown'
			);
		}
		return self::result( 'lockdown', 'good', __( 'The site is locked by ScrapeLock Lockdown', 'scrapelock' ), __( 'Plugins, themes, users and settings cannot be changed until it is unlocked with the authenticator app. Automatic updates wait too (so WordPress reports background updates as off).', 'scrapelock' ) );
	}

	/**
	 * File integrity: code files added or changed while locked, or different from WordPress.org.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_integrity() {
		$report = PNCP_Integrity::report();
		// 3.4.3: read once: each read unpacks the whole fingerprint (tens of thousands of files on a large site).
		$base   = PNCP_Integrity::baseline();
		$locked = PNCP_Lockdown::is_locked();
		if ( ! empty( $report['tampered'] ) || ( $locked && $base['tampered'] ) ) {
			return self::result( 'integrity', 'critical', __( 'The ScrapeLock file fingerprint was changed outside WordPress', 'scrapelock' ), __( 'The fingerprint of the code files was changed or removed in the database while the site was locked, so new or changed files might have been hidden. Check the files with a security scanner; a new fingerprint is taken the next time you lock the site.', 'scrapelock' ), 'lockdown' );
		}
		// The hourly check runs on WordPress's cron: if it stopped (DISABLE_WP_CRON without a real cron job, or
		// the event was removed), a quiet report must not look like a clean site.
		if ( $locked && $base['time'] && (int) $report['time'] < time() - 3 * HOUR_IN_SECONDS ) {
			return self::result( 'integrity', 'recommended', __( 'The ScrapeLock file check has not run for more than 3 hours', 'scrapelock' ), __( 'The file check runs every hour through WordPress\'s scheduled tasks (cron). If DISABLE_WP_CRON is set in wp-config.php, add a real cron job that calls wp-cron.php, or run "wp cron event run --due-now" regularly.', 'scrapelock' ), 'lockdown' );
		}
		$found = PNCP_Integrity::findings( $report );
		if ( $found ) {
			return self::result(
				'integrity',
				'critical',
				/* translators: %d: number of files. */
				sprintf( _n( 'ScrapeLock found %d changed code file', 'ScrapeLock found %d changed code files', count( $found ), 'scrapelock' ), count( $found ) ),
				__( 'Code files were added or changed while the site was locked, or differ from the official copies on WordPress.org. Nobody can install or update anything while the site is locked, so a file you do not recognise is often a backdoor uploaded through a vulnerable plugin. The list is on the Lockdown tab.', 'scrapelock' ),
				'lockdown'
			);
		}
		if ( ! $base['time'] ) {
			return self::result( 'integrity', 'good', __( 'ScrapeLock file integrity is not active', 'scrapelock' ), __( 'The fingerprint of the code files is taken when the site is locked with Lockdown, and checked every hour while it stays locked.', 'scrapelock' ) );
		}
		return self::result( 'integrity', 'good', __( 'No changed code files', 'scrapelock' ), __( 'No code file was added or changed since the site was locked, and WordPress and its plugins from WordPress.org match their official copies.', 'scrapelock' ) );
	}

	/**
	 * 3.5: Site Health's script runs the robots.txt test through admin-ajax (async test without a REST route).
	 */
	public static function ajax_robots() {
		check_ajax_referer( 'health-check-site-status' );
		if ( ! current_user_can( 'view_site_health_checks' ) ) {
			wp_send_json_error( null, 403 );
		}
		wp_send_json_success( self::test_robots() );
	}

	/**
	 * 3.5: Site Health's script runs the private folders test through admin-ajax.
	 */
	public static function ajax_folders() {
		check_ajax_referer( 'health-check-site-status' );
		if ( ! current_user_can( 'view_site_health_checks' ) ) {
			wp_send_json_error( null, 403 );
		}
		wp_send_json_success( self::test_folders() );
	}

	/**
	 * 3.5: "Check again now": forgets the last robots.txt and folders checks, so Site Health asks the site again
	 * (after a CDN purge, a server change or new rules).
	 */
	public static function handle_recheck() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::RECHECK );
		delete_transient( self::ROBOTS_CACHE );
		delete_transient( self::FOLDERS_CACHE );
		wp_safe_redirect( admin_url( 'site-health.php' ) );
		exit;
	}

	/**
	 * 3.5: the "Check again now" link, for administrators only.
	 *
	 * @return string Escaped HTML ('' for other users).
	 */
	private static function recheck_link() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return '';
		}
		return '<p><a href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=' . self::RECHECK ), self::RECHECK ) ) . '">' . esc_html__( 'Check again now', 'scrapelock' ) . '</a></p>';
	}

	/**
	 * 3.5: lines to copy, in a read-only box (a textarea copies cleanly and needs no CSS).
	 *
	 * @param string $text The lines.
	 * @return string Escaped HTML.
	 */
	private static function copy_block( $text ) {
		$text = rtrim( (string) $text ) . "\n";
		$rows = min( 16, substr_count( $text, "\n" ) + 1 );
		return '<p><textarea class="large-text code" rows="' . (int) $rows . '" readonly onfocus="this.select()">' . esc_textarea( $text ) . '</textarea></p>';
	}

	/**
	 * 3.5: an escaped list.
	 *
	 * @param string[] $items Items (plain text).
	 * @return string Escaped HTML.
	 */
	private static function html_list( $items ) {
		$out = '<ul>';
		foreach ( $items as $item ) {
			$out .= '<li>' . esc_html( $item ) . '</li>';
		}
		return $out . '</ul>';
	}

	/**
	 * 3.5: scheme, host and port of an address (a default port counts as 0, so that http and https on the same
	 * host compare equal: the usual redirect to https stays on the site).
	 *
	 * @param string $url Address.
	 * @return array{host: string, port: int}|null Null for anything but http(s) with a host.
	 */
	private static function url_origin( $url ) {
		$p = wp_parse_url( (string) $url );
		if ( ! is_array( $p ) || empty( $p['host'] ) || empty( $p['scheme'] ) ) {
			return null;
		}
		$scheme = strtolower( $p['scheme'] );
		if ( 'http' !== $scheme && 'https' !== $scheme ) {
			return null;
		}
		$port = isset( $p['port'] ) ? (int) $p['port'] : 0;
		if ( ( 'http' === $scheme && 80 === $port ) || ( 'https' === $scheme && 443 === $port ) ) {
			$port = 0;
		}
		return array(
			'host' => strtolower( $p['host'] ),
			'port' => $port,
		);
	}

	/**
	 * 3.5: is the address on the site itself (same host and port as home_url())? Nothing else is ever requested.
	 *
	 * @param string $url Address.
	 * @return bool
	 */
	private static function on_site( $url ) {
		$a = self::url_origin( $url );
		$b = self::url_origin( home_url( '/' ) );
		return null !== $a && null !== $b && $a === $b;
	}

	/**
	 * 3.5: GET an address of the site itself, like PNCP_Rules::nginx_status(): short timeout, small answer, no
	 * cookies. A redirect is followed by hand, once, and only on the same host.
	 *
	 * @param string $url   Address on the site.
	 * @param int    $limit Most bytes read.
	 * @return array{outcome: string, code: int, body: string, type: string, reason: string} outcome: ok (HTTP 200
	 *         and not a web page), not_served (404 / 410, or a web page), error (anything else). reason: a code
	 *         for reason_text(): redirect, http:<code>, or msg:<transport error>.
	 */
	private static function fetch( $url, $limit ) {
		$out  = array(
			'outcome' => 'error',
			'code'    => 0,
			'body'    => '',
			'type'    => '',
			'reason'  => 'redirect',
		);
		$hops = 0;
		while ( true ) {
			if ( ! self::on_site( $url ) ) {
				return $out; // 3.5: never another address (reason "redirect": it can only come from a Location).
			}
			$response = wp_remote_get(
				$url,
				array(
					'timeout'             => 5,
					'redirection'         => 0, // 3.5: a redirect is followed by hand, once, and only on the same host.
					'sslverify'           => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter for requests to the site itself.
					'limit_response_size' => (int) $limit,
				)
			);
			if ( is_wp_error( $response ) ) {
				$out['reason'] = 'msg:' . $response->get_error_message();
				return $out;
			}
			$code        = (int) wp_remote_retrieve_response_code( $response );
			$out['code'] = $code;
			if ( in_array( $code, array( 301, 302, 303, 307, 308 ), true ) ) {
				$location = wp_remote_retrieve_header( $response, 'location' );
				$location = is_array( $location ) ? (string) reset( $location ) : (string) $location;
				if ( $hops++ >= 1 || '' === $location ) {
					$out['reason'] = 'redirect';
					return $out;
				}
				$url = WP_Http::make_absolute_url( $location, $url );
				continue;
			}
			$type        = wp_remote_retrieve_header( $response, 'content-type' );
			$out['type'] = strtolower( is_array( $type ) ? (string) reset( $type ) : (string) $type );
			$out['body'] = (string) wp_remote_retrieve_body( $response );
			if ( 200 === $code ) {
				$html           = false !== strpos( $out['type'], 'text/html' ) || 0 === strpos( ltrim( $out['body'] ), '<' );
				$out['outcome'] = $html ? 'not_served' : 'ok';
				$out['reason']  = '';
			} elseif ( 404 === $code || 410 === $code ) {
				$out['outcome'] = 'not_served';
				$out['reason']  = '';
			} else {
				$out['reason'] = 'http:' . $code;
			}
			return $out;
		}
	}

	/**
	 * 3.5: why a request failed, in words (the cache keeps only the code, so a language switch still works).
	 *
	 * @param string $reason Code from fetch() or the folders test.
	 * @return string
	 */
	private static function reason_text( $reason ) {
		$reason = (string) $reason;
		if ( 0 === strpos( $reason, 'http:' ) ) {
			/* translators: %d: HTTP status code, e.g. 403 */
			return sprintf( __( 'HTTP %d', 'scrapelock' ), (int) substr( $reason, 5 ) );
		}
		if ( 0 === strpos( $reason, 'msg:' ) ) {
			return substr( $reason, 4 );
		}
		if ( 'uploads' === $reason ) {
			return __( 'the uploads folder is not available', 'scrapelock' );
		}
		if ( 'nowrite' === $reason ) {
			return __( 'the uploads folder cannot be written', 'scrapelock' );
		}
		if ( 'nofolder' === $reason ) {
			return __( 'no test file could be written in the folders', 'scrapelock' );
		}
		if ( 'nofetch' === $reason ) {
			return __( 'the test files written in the folders could not be fetched', 'scrapelock' );
		}
		if ( 'elsewhere' === $reason ) {
			return __( 'the uploads folder is served from another address', 'scrapelock' );
		}
		return __( 'it redirects to another address', 'scrapelock' );
	}

	/**
	 * 3.5: does the robots.txt crawlers get have ScrapeLock's lines? A robots.txt file in the site's root folder
	 * replaces the one WordPress makes (and with it everything ScrapeLock adds); a CDN, the host or another plugin
	 * can do the same. The site asks itself for /robots.txt once a day (or on "Check again now"), and never
	 * writes the file.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_robots() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) ) {
			return self::robots_off();
		}
		if ( ! get_option( 'blog_public' ) ) {
			return self::result( 'robots', 'good', __( 'robots.txt asks every bot to stay away', 'scrapelock' ), __( '“Discourage search engines from indexing this site” is on (Settings → Reading), so WordPress asks every bot to stay away and ScrapeLock adds nothing to robots.txt.', 'scrapelock' ) );
		}
		// 3.5: only ScrapeLock's own lines (the method, not the filter: other plugins' lines are not ours to check).
		$block = PNCP_Bots::robots_txt( '', true );
		if ( '' === trim( $block ) ) {
			return self::robots_off();
		}
		$home = wp_parse_url( home_url( '/' ) );
		if ( ! is_array( $home ) || empty( $home['host'] ) ) {
			return self::robots_off();
		}
		// Crawlers read robots.txt only at the root of the host, also when WordPress is in a folder.
		$origin     = ( isset( $home['scheme'] ) ? strtolower( $home['scheme'] ) : 'http' ) . '://' . $home['host'] . ( isset( $home['port'] ) ? ':' . (int) $home['port'] : '' );
		$robots_url = $origin . '/robots.txt';
		$in_folder  = '' !== trim( (string) ( isset( $home['path'] ) ? $home['path'] : '' ), '/' );
		if ( is_multisite() && ! is_subdomain_install() && ! is_main_site() ) {
			return self::result( 'robots', 'good', __( 'robots.txt belongs to the main site of the network', 'scrapelock' ), __( 'In a network with sites in folders, crawlers read only the robots.txt of the main site, so the AI crawler lines come from the main site\'s ScrapeLock settings. The bot trap of this site is not listed there; polite crawlers are kept away from it by its nofollow link only.', 'scrapelock' ) );
		}

		// Files in the root folder (only when WordPress is at the root: otherwise the root folder is unknown).
		$robots_file = '';
		$llms_file   = '';
		if ( ! $in_folder ) {
			foreach ( self::root_dirs() as $dir ) {
				if ( '' === $robots_file && is_file( $dir . 'robots.txt' ) ) {
					$robots_file = $dir . 'robots.txt';
				}
				foreach ( array( 'llms.txt', 'llms-full.txt' ) as $name ) {
					if ( '' === $llms_file && is_file( $dir . $name ) ) {
						$llms_file = $dir . $name;
					}
				}
			}
		}

		$key  = md5( (string) wp_json_encode( array( PNCP_VERSION, $robots_url, $block, '' !== $robots_file ? @filemtime( $robots_file ) . '-' . @filesize( $robots_file ) : '', '' !== $llms_file ? '1' : '0' ) ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A file removed in between only changes the key.
		$got  = get_transient( self::ROBOTS_CACHE );
		$data = is_array( $got ) && isset( $got['key'], $got['data'] ) && $key === $got['key'] && is_array( $got['data'] ) ? $got['data'] : null;
		if ( null === $data ) {
			$data = self::robots_probe( $s, $block, $robots_url, $origin . '/llms.txt', $robots_file, $in_folder );
			set_transient(
				self::ROBOTS_CACHE,
				array(
					'key'  => $key,
					'data' => $data,
				),
				// 3.5: a check that could not fetch robots.txt is kept an hour, not a day.
				in_array( isset( $data['source'] ) ? $data['source'] : 'unknown', array( 'http', 'file', 'none' ), true ) ? DAY_IN_SECONDS : HOUR_IN_SECONDS
			);
		}
		// 3.5: like the served llms.txt (robots_probe()), the file matters only while AI crawlers are asked to stay
		// away. Worked out on every run, so a cached check follows the settings.
		$data['llms_file'] = '' !== $llms_file && ! empty( $s['robots_ai_block'] ) && empty( $s['allow_ai_search'] );
		return self::robots_result( $data, $block, $robots_url );
	}

	/**
	 * 3.5: the robots.txt WordPress would send (do_robots() without its header and action): the core rules and
	 * everything the robots_txt filter adds (the sitemap, SEO plugins, ScrapeLock's lines).
	 *
	 * @return string
	 */
	private static function wordpress_robots_txt() {
		$public = (string) get_option( 'blog_public' );
		$output = "User-agent: *\n";
		if ( '0' === $public ) {
			$output .= "Disallow: /\n";
		} else {
			$path    = (string) wp_parse_url( site_url(), PHP_URL_PATH );
			$output .= "Disallow: $path/wp-admin/\n";
			$output .= "Allow: $path/wp-admin/admin-ajax.php\n";
		}
		/** This filter is documented in wp-includes/functions.php */
		return (string) apply_filters( 'robots_txt', $output, $public ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.
	}

	/**
	 * 3.5: the robots.txt result when ScrapeLock adds nothing.
	 *
	 * @return array<string, mixed>
	 */
	private static function robots_off() {
		return self::result( 'robots', 'good', __( 'ScrapeLock adds nothing to robots.txt', 'scrapelock' ), __( 'Protection is off, or the bot trap, the AI crawler lines, the web archive lines and Content Signals are all off, so there is nothing to check.', 'scrapelock' ) );
	}

	/**
	 * 3.5: the folders a robots.txt file can be in: WordPress's home path, and ABSPATH only when the site address
	 * and the WordPress address share their path (with WordPress in its own folder, a file in that folder is never
	 * served at /robots.txt). Never DOCUMENT_ROOT, which may be outside open_basedir and is empty in cron.
	 *
	 * @return string[] Folders with a trailing slash.
	 */
	private static function root_dirs() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$home = untrailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) );
		$site = untrailingslashit( (string) wp_parse_url( site_url( '/' ), PHP_URL_PATH ) );
		$dirs = array();
		foreach ( strtolower( $home ) === strtolower( $site ) ? array( get_home_path(), ABSPATH ) : array( get_home_path() ) as $dir ) {
			if ( '' !== (string) $dir && '/' !== (string) $dir ) {
				$dirs[] = trailingslashit( wp_normalize_path( (string) $dir ) );
			}
		}
		return array_values( array_unique( $dirs ) );
	}

	/**
	 * 3.5: asks the site for robots.txt (and llms.txt) and compares it with ScrapeLock's lines.
	 *
	 * @param array<string, mixed> $s           Effective settings.
	 * @param string               $block       ScrapeLock's lines.
	 * @param string               $robots_url  /robots.txt at the root of the host.
	 * @param string               $llms_url    /llms.txt at the root of the host.
	 * @param string               $robots_file robots.txt file in the root folder ('' = none).
	 * @param bool                 $in_folder   WordPress is in a folder.
	 * @return array<string, mixed> Codes, flags and agent names only (it is cached).
	 */
	private static function robots_probe( $s, $block, $robots_url, $llms_url, $robots_file, $in_folder ) {
		$data     = array(
			'source'      => 'unknown',
			'code'        => 0,
			'reason'      => '',
			'physical'    => '' !== $robots_file,
			'in_folder'   => (bool) $in_folder,
			'missing'     => array(),
			'llms_file'   => false,
			'llms_served' => false,
		);
		$response = self::fetch( $robots_url, 524288 );
		$served   = null;
		if ( 'ok' === $response['outcome'] ) {
			$data['source'] = 'http';
			$served         = $response['body'];
		} elseif ( 'not_served' === $response['outcome'] ) {
			$data['source'] = 'none';
			$data['code']   = $response['code'];
		} else {
			$data['reason'] = $response['reason'];
			$data['code']   = $response['code'];
			if ( '' !== $robots_file && is_readable( $robots_file ) ) {
				$text = file_get_contents( $robots_file, false, null, 0, 524288 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A local file, read only.
				if ( false !== $text ) {
					$data['source'] = 'file';
					$served         = $text;
				}
			}
		}
		if ( null !== $served ) {
			$data['missing'] = self::robots_missing( $served, $block );
		}
		// The llms.txt note matters only while AI crawlers are asked to stay away, and only if the server answered.
		if ( ! empty( $s['robots_ai_block'] ) && empty( $s['allow_ai_search'] ) && in_array( $response['outcome'], array( 'ok', 'not_served' ), true ) ) {
			$llms                = self::fetch( $llms_url, 4096 );
			$data['llms_served'] = 'ok' === $llms['outcome'];
		}
		return $data;
	}

	/**
	 * 3.5: reads a robots.txt the way Google does: comments dropped, blank lines do not end a group, a run of
	 * User-agent lines starts a group, Allow / Disallow lines belong to it. Content-Signal lines are collected
	 * from anywhere in the file; other fields are ignored.
	 *
	 * @param string $text robots.txt.
	 * @return array{groups: array<int, array{agents: string[], rules: array<int, array{0: string, 1: string}>}>, signals: string[]}
	 */
	private static function robots_groups( $text ) {
		$text    = (string) $text;
		$text    = 0 === strpos( $text, "\xEF\xBB\xBF" ) ? substr( $text, 3 ) : $text;
		$groups  = array();
		$signals = array();
		$agents  = false; // The last field read was a User-agent line.
		foreach ( (array) preg_split( '/\r\n|\r|\n/', $text ) as $line ) {
			$hash = strpos( (string) $line, '#' );
			$line = trim( false === $hash ? (string) $line : substr( (string) $line, 0, $hash ) );
			if ( '' === $line || false === strpos( $line, ':' ) ) {
				continue;
			}
			list( $field, $value ) = explode( ':', $line, 2 );
			$field                 = strtolower( trim( $field ) );
			$value                 = trim( $value );
			if ( 'user-agent' === $field ) {
				if ( ! $agents || ! $groups ) {
					$groups[] = array(
						'agents' => array(),
						'rules'  => array(),
					);
				}
				$groups[ count( $groups ) - 1 ]['agents'][] = strtolower( $value );
				$agents                                     = true;
			} elseif ( 'allow' === $field || 'disallow' === $field ) {
				if ( $groups ) {
					$groups[ count( $groups ) - 1 ]['rules'][] = array( $field, $value );
				}
				$agents = false;
			} elseif ( 'content-signal' === $field ) {
				$signals[] = strtolower( (string) preg_replace( '/\s+/', '', $value ) );
				$agents    = false;
			}
		}
		return array(
			'groups'  => $groups,
			'signals' => $signals,
		);
	}

	/**
	 * 3.5: the rules that apply to a crawler: those of every group that names it, or else those of every "*" group.
	 *
	 * @param array<string, mixed> $parsed From robots_groups().
	 * @param string               $agent  Crawler name ("*" for every crawler).
	 * @return array<int, array{0: string, 1: string}>
	 */
	private static function robots_rules_for( $parsed, $agent ) {
		$agent = strtolower( (string) $agent );
		$own   = array();
		$star  = array();
		foreach ( $parsed['groups'] as $group ) {
			if ( in_array( $agent, $group['agents'], true ) ) {
				$own = array_merge( $own, $group['rules'] );
			}
			if ( in_array( '*', $group['agents'], true ) ) {
				$star = array_merge( $star, $group['rules'] );
			}
		}
		foreach ( $parsed['groups'] as $group ) {
			if ( in_array( $agent, $group['agents'], true ) ) {
				return $own; // A group that names the crawler wins over "*", even with no Disallow line.
			}
		}
		return $star;
	}

	/**
	 * 3.5: does a plain Disallow line cover the path? Lines with wildcards are ignored (never counted as present).
	 *
	 * @param array<int, array{0: string, 1: string}> $rules Rules.
	 * @param string                                  $path  Path.
	 * @return bool
	 */
	private static function robots_blocks( $rules, $path ) {
		foreach ( $rules as $rule ) {
			if ( 'disallow' === $rule[0] && '' !== $rule[1] && false === strpbrk( $rule[1], '*$' ) && 0 === strpos( (string) $path, $rule[1] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.5: what of ScrapeLock's lines the served robots.txt lacks. No settings are read: the bot trap path, the
	 * crawlers and the Content-Signal value all come from the expected lines.
	 *
	 * @param string $served The robots.txt crawlers get.
	 * @param string $block  ScrapeLock's lines (PNCP_Bots::robots_txt( '', true )).
	 * @return array{trap: bool, ai: string[], ai_total: int, archives: string[], archives_total: int, signal: string, signal_count: int}
	 *         trap: the bot trap line is missing; signal: ok (present or not expected), missing or differs.
	 */
	private static function robots_missing( $served, $block ) {
		$have     = self::robots_groups( $served );
		$want     = self::robots_groups( $block );
		$archives = array_map( 'strtolower', PNCP_Bots::archive_agents() );
		$out      = array(
			'trap'           => false,
			'ai'             => array(),
			'ai_total'       => 0,
			'archives'       => array(),
			'archives_total' => 0,
			'signal'         => 'ok',
			'signal_count'   => count( $have['signals'] ),
		);
		$star     = self::robots_rules_for( $have, '*' );
		foreach ( $want['groups'] as $group ) {
			if ( in_array( '*', $group['agents'], true ) ) {
				foreach ( $group['rules'] as $rule ) {
					if ( 'disallow' === $rule[0] && '' !== $rule[1] && ! self::robots_blocks( $star, $rule[1] ) ) {
						$out['trap'] = true;
					}
				}
			}
		}
		// Original spelling of the crawler names, for display.
		foreach ( (array) preg_split( '/\r\n|\r|\n/', (string) $block ) as $line ) {
			if ( ! preg_match( '/^\s*user-agent\s*:\s*([^#\s][^#]*?)\s*(?:#.*)?$/i', $line, $m ) || '*' === $m[1] ) {
				continue;
			}
			$name = $m[1];
			$kind = in_array( strtolower( $name ), $archives, true ) ? 'archives' : 'ai';
			++$out[ $kind . '_total' ];
			if ( ! self::robots_blocks( self::robots_rules_for( $have, $name ), '/' ) ) {
				$out[ $kind ][] = $name;
			}
		}
		if ( $want['signals'] ) {
			if ( in_array( $want['signals'][0], $have['signals'], true ) ) {
				$out['signal'] = 'ok';
			} else {
				$out['signal'] = $have['signals'] ? 'differs' : 'missing';
			}
		}
		return $out;
	}

	/**
	 * 3.5: the robots.txt result from the (cached) check.
	 *
	 * @param array<string, mixed> $data       From robots_probe().
	 * @param string               $block      ScrapeLock's lines.
	 * @param string               $robots_url /robots.txt at the root of the host.
	 * @return array<string, mixed>
	 */
	private static function robots_result( $data, $block, $robots_url ) {
		$recheck = self::recheck_link();
		$lines   = self::copy_block( $block );
		$llms    = '';
		if ( ! empty( $data['llms_file'] ) || ! empty( $data['llms_served'] ) ) {
			$llms = ' ' . __( 'Your site also serves llms.txt, a list of your content written for AI tools, while ScrapeLock asks AI crawlers to stay away. ScrapeLock leaves llms.txt open to every bot and does not change it. If you do not want to offer your content to AI tools, remove it (the option of the plugin that makes it, or the file in the site\'s root folder).', 'scrapelock' );
			if ( ! empty( $data['llms_file'] ) ) {
				$llms .= ' ' . __( 'It is a file in the site\'s root folder, so it replaces any llms.txt a plugin makes.', 'scrapelock' );
			}
		}
		$source = isset( $data['source'] ) ? (string) $data['source'] : 'unknown';

		if ( 'none' === $source ) {
			if ( 200 === (int) $data['code'] ) {
				/* translators: %s: address of robots.txt */
				$text = sprintf( __( '%s returns a web page instead of a text file, so crawlers find no rules at all.', 'scrapelock' ), $robots_url );
			} else {
				/* translators: 1: address of robots.txt, 2: HTTP status code */
				$text = sprintf( __( '%1$s answers with HTTP %2$d, so crawlers find no rules at all: the bot trap, AI crawler and Content-Signal lines that ScrapeLock adds are not sent.', 'scrapelock' ), $robots_url, (int) $data['code'] );
			}
			if ( '' === (string) get_option( 'permalink_structure' ) ) {
				$text .= ' ' . __( 'With plain permalinks (Settings → Permalinks) WordPress cannot answer /robots.txt itself: choose another permalink structure, or create the file with the lines below.', 'scrapelock' );
				// 3.5: the whole robots.txt WordPress would send (its own rules, the sitemap, other plugins' lines and
				// ScrapeLock's), not only ScrapeLock's lines.
				$details = '<p>' . esc_html__( 'The robots.txt WordPress would send, ScrapeLock\'s lines included:', 'scrapelock' ) . '</p>' . self::copy_block( self::wordpress_robots_txt() );
			} else {
				if ( 200 !== (int) $data['code'] ) {
					// 3.5: usually a server rule, not a missing file: a file would hide the robots.txt WordPress makes.
					$text .= ' ' . __( 'On Nginx, a “location = /robots.txt” block without “try_files $uri /index.php?$args;” answers itself instead of passing the request to WordPress: add that line to it, or remove the block. Do not create a robots.txt file: it would replace the one WordPress makes, with its sitemap lines.', 'scrapelock' );
				}
				$details = '<p>' . esc_html__( 'The lines ScrapeLock adds:', 'scrapelock' ) . '</p>' . $lines;
			}
			return self::result( 'robots', 'recommended', __( 'No robots.txt is served', 'scrapelock' ), $text . $llms, 'bots', 'pncp-sec-ai', $recheck, $details );
		}

		if ( 'http' !== $source && 'file' !== $source ) {
			$reason = self::reason_text( isset( $data['reason'] ) ? $data['reason'] : '' );
			if ( ! empty( $data['in_folder'] ) ) {
				/* translators: 1: address of robots.txt, 2: why it could not be fetched */
				$text = sprintf( __( 'WordPress is in a folder, and crawlers read only %1$s, which WordPress does not make. ScrapeLock could not fetch it from the server (%2$s): check that it has the lines below.', 'scrapelock' ), $robots_url, $reason );
				return self::result( 'robots', 'recommended', __( 'ScrapeLock could not check robots.txt', 'scrapelock' ), $text, '', '', $recheck, $lines );
			}
			/* translators: 1: address of robots.txt, 2: why it could not be fetched */
			$text = sprintf( __( 'There is no robots.txt file in the site\'s root folder, so the web server should send the one WordPress makes, with ScrapeLock\'s lines. ScrapeLock could not fetch %1$s from the server to confirm it (%2$s). Open it in a browser to see what crawlers get.', 'scrapelock' ), $robots_url, $reason );
			// 3.5: a failed loopback is "could not check", as in the folder case above: a CDN or server rule that
			// replaces robots.txt would otherwise pass unnoticed.
			return self::result( 'robots', 'recommended', __( 'ScrapeLock could not check robots.txt', 'scrapelock' ), $text, '', '', $recheck, $lines );
		}

		$missing = isset( $data['missing'] ) && is_array( $data['missing'] ) ? $data['missing'] : array();
		$missing = array_merge(
			array(
				'trap'           => false,
				'ai'             => array(),
				'ai_total'       => 0,
				'archives'       => array(),
				'archives_total' => 0,
				'signal'         => 'ok',
				'signal_count'   => 0,
			),
			$missing
		);
		$checked = '';
		if ( 'file' === $source ) {
			/* translators: %s: why the address could not be fetched */
			$checked = ' ' . sprintf( __( '(Checked in the file itself: the address could not be fetched from the server: %s.)', 'scrapelock' ), self::reason_text( isset( $data['reason'] ) ? $data['reason'] : '' ) );
		}
		$items = array();
		if ( $missing['trap'] ) {
			$items[] = __( 'The Disallow line for the bot trap. Polite crawlers that are not verified search engines (SEO tools, smaller search engines) may follow its hidden link and be blocked.', 'scrapelock' );
		}
		if ( $missing['ai'] ) {
			/* translators: 1: number of AI crawlers missing, 2: number of AI crawlers ScrapeLock lists, 3: up to three crawler names */
			$items[] = sprintf( __( '%1$d of %2$d AI crawlers, e.g. %3$s.', 'scrapelock' ), count( $missing['ai'] ), (int) $missing['ai_total'], implode( ', ', array_slice( $missing['ai'], 0, 3 ) ) );
		}
		if ( $missing['archives'] ) {
			/* translators: 1: number of web archives missing, 2: number of web archives ScrapeLock lists, 3: up to three crawler names */
			$items[] = sprintf( __( '%1$d of %2$d web archives, e.g. %3$s.', 'scrapelock' ), count( $missing['archives'] ), (int) $missing['archives_total'], implode( ', ', array_slice( $missing['archives'], 0, 3 ) ) );
		}
		if ( 'missing' === $missing['signal'] ) {
			$items[] = __( 'The Content-Signal line.', 'scrapelock' );
		} elseif ( 'differs' === $missing['signal'] ) {
			$items[] = __( 'The Content-Signal line has other values than your settings.', 'scrapelock' );
		}

		if ( ! $items ) {
			/* translators: %s: address of robots.txt */
			$text = sprintf( __( '%s has every line that the current ScrapeLock settings add (bot trap, AI crawlers, web archives, Content Signals, as they are turned on).', 'scrapelock' ), $robots_url );
			if ( ! empty( $data['physical'] ) ) {
				$text .= ' ' . __( 'It is a file in the site\'s root folder, which WordPress and ScrapeLock cannot change: when an update of ScrapeLock adds AI crawlers, this test lists the lines to add.', 'scrapelock' );
			}
			$text .= $checked;
			if ( (int) $missing['signal_count'] > 1 ) {
				$text .= ' ' . __( 'It has more than one Content-Signal line (a CDN may add its own); the companies that read them may take either.', 'scrapelock' );
			}
			return self::result( 'robots', 'good', __( 'Crawlers get ScrapeLock\'s lines in robots.txt', 'scrapelock' ), $text . $llms, '', '', $recheck );
		}

		if ( ! empty( $data['in_folder'] ) ) {
			/* translators: %s: address of robots.txt */
			$text = sprintf( __( 'WordPress is in a folder, and crawlers read only %s, which WordPress does not make. ScrapeLock\'s lines must be added to that file.', 'scrapelock' ), $robots_url );
		} elseif ( ! empty( $data['physical'] ) ) {
			$text = __( 'There is a file robots.txt in the site\'s root folder. The web server sends that file instead of the robots.txt that WordPress makes, so the lines ScrapeLock adds do not reach crawlers.', 'scrapelock' );
		} else {
			/* translators: %s: address of robots.txt */
			$text = sprintf( __( '%s does not have every line that ScrapeLock adds. Another plugin, the theme, the host or the CDN may replace it.', 'scrapelock' ), $robots_url );
		}
		$text .= ' ' . __( 'ScrapeLock still blocks AI crawlers and checks bots on the server: robots.txt is only the polite request, but without it polite crawlers cannot know what to avoid.', 'scrapelock' ) . $checked;
		if ( ! empty( $data['in_folder'] ) || ! empty( $data['physical'] ) ) {
			$howto = __( 'Add these lines to the robots.txt file. If it already has a “User-agent: *” group, put the lines that follow “User-agent: *” below into that group. ScrapeLock never writes this file.', 'scrapelock' );
		} else {
			// 3.5: no file to edit: creating one would hide the robots.txt WordPress makes, with its sitemap lines.
			$howto = __( 'Purge the page cache and the CDN cache, then check again. If the lines are still missing, find the plugin or the host setting that replaces robots.txt (SEO plugins often have a robots.txt editor) and add these lines there. Do not create a robots.txt file: it would replace the one WordPress makes, with its sitemap lines.', 'scrapelock' );
		}
		$details = '<p>' . esc_html__( 'Missing:', 'scrapelock' ) . '</p>' . self::html_list( $items )
			. '<p>' . esc_html( $howto ) . '</p>'
			. $lines;
		return self::result( 'robots', 'recommended', __( 'robots.txt does not have ScrapeLock\'s lines', 'scrapelock' ), $text . $llms, 'bots', 'pncp-sec-ai', $recheck, $details );
	}

	/**
	 * 3.5: ScrapeLock's private folders in uploads (clean originals of watermarked images, the pre-cache check's
	 * data, the country database) each have an .htaccess file that refuses every request, which Nginx, IIS and
	 * some Apache setups ignore. A throwaway text file is written in each folder and fetched from its web address;
	 * it is removed in the same run. Once a day, or on "Check again now".
	 *
	 * @return array<string, mixed>
	 */
	public static function test_folders() {
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) || empty( $uploads['baseurl'] ) ) {
			return self::folders_unknown( 'uploads' );
		}
		$folders = self::folders( (string) $uploads['basedir'] );
		if ( ! $folders ) {
			return self::result( 'folders', 'good', __( 'ScrapeLock has no private folders yet', 'scrapelock' ), __( 'The clean originals of watermarked images, the pre-cache check\'s data and the country database are kept in folders of uploads that are created when those features are first used.', 'scrapelock' ) );
		}
		$baseurl = (string) $uploads['baseurl'];
		if ( ! self::on_site( $baseurl ) ) {
			return self::folders_unknown( 'elsewhere' ); // 3.5: offloaded uploads or a CDN host: never requested.
		}
		// The key is a hash: the transient never holds a folder name.
		$key  = md5( (string) wp_json_encode( array( PNCP_VERSION, $baseurl, array_keys( $folders ), array_values( $folders ) ) ) );
		$got  = get_transient( self::FOLDERS_CACHE );
		$data = is_array( $got ) && isset( $got['key'], $got['data'] ) && $key === $got['key'] && is_array( $got['data'] ) ? $got['data'] : null;
		if ( null === $data ) {
			$data = self::folders_probe( $folders, (string) $uploads['basedir'], $baseurl );
			set_transient(
				self::FOLDERS_CACHE,
				array(
					'key'  => $key,
					'data' => $data,
				),
				// 3.5: a check that could not fetch the control file is kept an hour, not a day.
				'ok' === $data['control'] ? DAY_IN_SECONDS : HOUR_IN_SECONDS
			);
		}
		if ( 'ok' !== $data['control'] ) {
			return self::folders_unknown( $data['reason'] );
		}
		$names   = array(
			'originals' => __( 'the folder with the clean originals of watermarked images', 'scrapelock' ),
			'precheck'  => __( 'the pre-cache check\'s data folder (counters, bans and visitor IP addresses)', 'scrapelock' ),
			'geo'       => __( 'the country database folder', 'scrapelock' ),
		);
		$pick    = static function ( $ids ) use ( $names ) {
			$out = array();
			foreach ( (array) $ids as $id ) {
				if ( isset( $names[ $id ] ) ) {
					$out[] = $names[ $id ];
				}
			}
			return $out;
		};
		$recheck = self::recheck_link();
		$open    = array_values( array_intersect( array_keys( $names ), (array) $data['open'] ) );
		if ( ! $open ) {
			$closed = $pick( $data['closed'] );
			$failed = $pick( $data['failed'] );
			if ( ! $closed ) {
				// 3.5: a test file that was written but could not be fetched is not a folder that cannot be written.
				return self::folders_unknown( ! empty( $data['nofetch'] ) ? 'nofetch' : 'nofolder' );
			}
			/* translators: %s: list of folders, e.g. "the country database folder" */
			$text = sprintf( __( 'A test file was written in each folder and fetched from its web address; the server refused it: %s.', 'scrapelock' ), implode( ', ', $closed ) );
			if ( $failed ) {
				/* translators: %s: list of folders */
				$text .= ' ' . sprintf( __( 'Could not be tested: %s.', 'scrapelock' ), implode( ', ', $failed ) );
			}
			return self::result( 'folders', 'good', __( 'ScrapeLock\'s private folders cannot be read from the web', 'scrapelock' ), $text, '', '', $recheck );
		}

		$items = array();
		$why   = array(
			'originals' => __( 'The folder with the clean originals of watermarked images: the images can be downloaded without the watermark. Its random name is the only protection.', 'scrapelock' ),
			'precheck'  => __( 'The pre-cache check\'s data folder: it holds visitor IP addresses (personal data). Its random name is the only protection.', 'scrapelock' ),
			'geo'       => __( 'The country database folder: the database files can be downloaded by anyone (public data, but the downloads cost bandwidth).', 'scrapelock' ),
		);
		foreach ( $open as $id ) {
			$items[] = $why[ $id ];
		}
		if ( ! empty( $data['listing'] ) ) {
			$items[] = __( 'The uploads folder lists its content to visitors, so the random folder names are visible. Turn off directory listings (Nginx: autoindex off; Apache: Options -Indexes).', 'scrapelock' );
		}
		$details = self::html_list( $items ) . self::folders_fix( $open, $baseurl );
		$status  = ! empty( $data['listing'] ) ? 'critical' : 'recommended';
		return self::result( 'folders', $status, __( 'ScrapeLock\'s private folders can be read from the web', 'scrapelock' ), __( 'A test file in these folders could be downloaded from its web address, so anyone who finds the address can read the files.', 'scrapelock' ), 'rules', '', $recheck, $details );
	}

	/**
	 * 3.5: how to refuse the open folders on this web server. Never the random folder names: only the fixed ones.
	 *
	 * @param string[] $open    Open folder ids.
	 * @param string   $baseurl Uploads address.
	 * @return string Escaped HTML.
	 */
	private static function folders_fix( $open, $baseurl ) {
		global $is_nginx, $is_apache;
		if ( ! empty( $is_nginx ) ) {
			$path  = untrailingslashit( (string) wp_parse_url( $baseurl, PHP_URL_PATH ) );
			$rules = array();
			if ( in_array( 'precheck', $open, true ) ) {
				$rules[] = 'location ^~ ' . $path . '/' . PNCP_Precheck::DIR . '/ { deny all; return 404; }';
			}
			if ( in_array( 'geo', $open, true ) ) {
				$rules[] = 'location ^~ ' . $path . '/' . PNCP_Geo::DIR . '/ { deny all; return 404; }';
			}
			$out = '';
			if ( $rules ) {
				$out .= '<p>' . esc_html__( 'Nginx ignores the .htaccess files ScrapeLock puts in these folders. Add these lines to the server { } block of the site, above the other location blocks, then reload Nginx:', 'scrapelock' ) . '</p>' . self::copy_block( implode( "\n", $rules ) );
			} else {
				$out .= '<p>' . esc_html__( 'Nginx ignores the .htaccess files ScrapeLock puts in these folders.', 'scrapelock' ) . '</p>';
			}
			if ( in_array( 'originals', $open, true ) ) {
				$out .= '<p>' . esc_html__( 'For the clean originals, add the line from the “Server rules” tab (it holds the folder\'s random name, so it is not shown here).', 'scrapelock' ) . '</p>';
			}
			return $out;
		}
		if ( ! empty( $is_apache ) ) {
			return '<p>' . esc_html__( 'Each folder has an .htaccess file that refuses every request, but the server ignores it. Let .htaccess files work in the uploads folder (AllowOverride All, or at least AuthConfig and Limit), or add the rules of the “Server rules” tab.', 'scrapelock' ) . '</p>';
		}
		return '<p>' . esc_html__( 'Refuse every request to these folders in the web server\'s configuration (ScrapeLock\'s .htaccess files work only on Apache and LiteSpeed).', 'scrapelock' ) . '</p>';
	}

	/**
	 * 3.5: the folders result when nothing could be fetched. Never "protected": on Apache and LiteSpeed the
	 * .htaccess files normally apply (good), elsewhere it is unknown (recommended).
	 *
	 * @param string $reason Reason code (see reason_text()).
	 * @return array<string, mixed>
	 */
	private static function folders_unknown( $reason ) {
		global $is_apache;
		/* translators: %s: why the test file could not be fetched */
		$text = sprintf( __( 'ScrapeLock could not fetch a test file from the uploads folder of this server (%s), so it cannot tell whether its private folders are refused.', 'scrapelock' ), self::reason_text( $reason ) );
		if ( ! empty( $is_apache ) ) {
			$text .= ' ' . __( 'On Apache and LiteSpeed the .htaccess file in each folder refuses every request, unless the server ignores .htaccess files.', 'scrapelock' );
		}
		return self::result( 'folders', ! empty( $is_apache ) ? 'good' : 'recommended', __( 'ScrapeLock could not test its private folders', 'scrapelock' ), $text, '', '', self::recheck_link() );
	}

	/**
	 * 3.5: ScrapeLock's private folders that exist, inside uploads. Never creates a folder or its option
	 * (PNCP_Watermark::backup_dir() and PNCP_Precheck::dir() would, for a missing name or key).
	 *
	 * @param string $basedir Uploads folder.
	 * @return array<string, string> id => real path without a trailing slash (originals, precheck, geo).
	 */
	private static function folders( $basedir ) {
		$base = realpath( $basedir );
		if ( false === $base ) {
			return array();
		}
		$base = trailingslashit( wp_normalize_path( $base ) );
		$list = array();
		$name = (string) get_option( 'pncp_backup_dir', '' );
		if ( preg_match( '/^pncp-originals-[a-z0-9]{12}$/', $name ) ) {
			$list['originals'] = trailingslashit( $basedir ) . $name;
		}
		if ( ! is_multisite() && preg_match( '/^[a-z0-9]{20}$/', (string) get_option( PNCP_Precheck::KEY, '' ) ) ) {
			$list['precheck'] = PNCP_Precheck::dir();
		}
		$list['geo'] = PNCP_Geo::dir();
		$out         = array();
		foreach ( $list as $id => $path ) {
			if ( '' === (string) $path || ! is_dir( $path ) ) {
				continue;
			}
			$real = realpath( $path );
			if ( false === $real ) {
				continue;
			}
			$real = untrailingslashit( wp_normalize_path( $real ) );
			if ( strlen( $real ) + 1 > strlen( $base ) && 0 === strpos( $real . '/', $base ) ) {
				$out[ $id ] = $real;
			}
		}
		return $out;
	}

	/**
	 * 3.5: writes a throwaway text file in a folder (random name and content).
	 *
	 * @param string $dir Folder (real path).
	 * @return array{0: string, 1: string}|null File name and content, or null if it could not be written.
	 */
	private static function probe_write( $dir ) {
		if ( ! is_dir( $dir ) || ! wp_is_writable( $dir ) ) {
			return null;
		}
		$name  = 'pncp-probe-' . strtolower( wp_generate_password( 20, false, false ) ) . '.txt';
		$token = wp_generate_password( 32, false, false );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- A 32-byte throwaway file, removed in the same run.
		if ( false === file_put_contents( $dir . '/' . $name, $token, LOCK_EX ) ) {
			return null;
		}
		return array( $name, $token );
	}

	/**
	 * 3.5: removes probe files a crashed run left behind (older than an hour, so a run in progress is not hit).
	 *
	 * @param string $dir Folder.
	 */
	private static function probe_cleanup( $dir ) {
		foreach ( (array) glob( $dir . '/pncp-probe-*.txt' ) as $file ) {
			if ( is_string( $file ) && is_file( $file ) && (int) filemtime( $file ) < time() - HOUR_IN_SECONDS ) {
				wp_delete_file( $file );
			}
		}
	}

	/**
	 * 3.5: the folders check itself: a control file in the uploads root (public anyway) must be readable first,
	 * or nothing can be told; then one file in each folder. At most 5 requests, every file removed.
	 *
	 * @param array<string, string> $folders From folders().
	 * @param string                $basedir Uploads folder.
	 * @param string                $baseurl Uploads address.
	 * @return array<string, mixed> Folder ids only (it is cached).
	 */
	private static function folders_probe( $folders, $basedir, $baseurl ) {
		$data = array(
			'control' => 'error',
			'reason'  => 'uploads',
			'open'    => array(),
			'closed'  => array(),
			'failed'  => array(),
			'listing' => false,
		);
		$base = realpath( $basedir );
		if ( false === $base ) {
			return $data;
		}
		$base = untrailingslashit( wp_normalize_path( $base ) );
		$url  = untrailingslashit( $baseurl );
		self::probe_cleanup( $base );
		foreach ( $folders as $dir ) {
			self::probe_cleanup( $dir );
		}

		$control = self::probe_write( $base );
		if ( null === $control ) {
			$data['reason'] = 'nowrite';
			return $data;
		}
		$response = self::fetch( $url . '/' . $control[0], 1024 );
		wp_delete_file( $base . '/' . $control[0] );
		if ( 200 !== $response['code'] || trim( $response['body'] ) !== $control[1] ) {
			// A loopback that cannot read even a public file proves nothing about the private ones.
			$data['reason'] = 0 === $response['code'] || 'redirect' === $response['reason'] ? $response['reason'] : 'http:' . $response['code'];
			return $data;
		}
		$data['control'] = 'ok';
		$data['reason']  = '';

		foreach ( $folders as $id => $dir ) {
			$probe = self::probe_write( $dir );
			if ( null === $probe ) {
				$data['failed'][] = $id;
				continue;
			}
			$response = self::fetch( $url . '/' . substr( $dir, strlen( $base ) + 1 ) . '/' . $probe[0], 1024 );
			wp_delete_file( $dir . '/' . $probe[0] ); // Removed whatever the answer was.
			if ( 200 === $response['code'] && trim( $response['body'] ) === $probe[1] ) {
				$data['open'][] = $id;
			} elseif ( 0 === $response['code'] ) {
				$data['failed'][] = $id; // A transport error (its message may hold the address: never printed).
				$data['nofetch']  = true; // 3.5: see test_folders().
			} else {
				$data['closed'][] = $id;
			}
		}

		if ( array_intersect( array( 'originals', 'precheck' ), $data['open'] ) ) {
			$response        = self::fetch( $url . '/', 262144 );
			$data['listing'] = 200 === $response['code'] && (bool) preg_match( '/pncp-originals-[a-z0-9]{12}|precheck-[a-z0-9]{20}/', $response['body'] );
		}
		return $data;
	}

	/**
	 * 3.5: are the pages' copy protection settings on?
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return bool
	 */
	private static function copy_protection_on( $s ) {
		foreach ( array( 'block_selection', 'block_context_menu', 'block_shortcuts', 'block_image_drag', 'block_text_drag' ) as $key ) {
			if ( ! empty( $s[ $key ] ) ) {
				return true;
			}
		}
		return isset( $s['copy_mode'] ) && 'block' === $s['copy_mode'];
	}

	/**
	 * 3.5: copy protection or the watermark on the pages, while the same text is open in the REST API, full-text
	 * feeds or WPGraphQL. Stored settings: Emergency Mode closes these channels only for a while.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_open_content() {
		$s    = PNCP_Options::stored();
		$copy = ! empty( $s['enabled'] ) && self::copy_protection_on( $s );
		$mark = ! empty( $s['enabled'] ) && ! empty( $s['watermark_enabled'] );
		if ( ! $copy && ! $mark ) {
			return self::result( 'open_content', 'good', __( 'ScrapeLock copy protection and watermark are off', 'scrapelock' ), __( 'Nothing to compare: when they are on, this test checks that the REST API, the feeds and WPGraphQL do not give the same content away.', 'scrapelock' ) );
		}
		// 3.5: the watermark protects images, and the REST API, the feeds and WPGraphQL give the same watermarked
		// image addresses: only the text channels count, and only while copy protection is on.
		if ( ! $copy ) {
			return self::result( 'open_content', 'good', __( 'Watermarked images stay watermarked in every channel', 'scrapelock' ), __( 'The REST API, the feeds and WPGraphQL give the same watermarked image addresses as the pages, so they do not get around the watermark.', 'scrapelock' ) );
		}
		$open = array();
		if ( empty( $s['rest_hide_content'] ) ) {
			$open[] = __( 'The REST API gives the full text of posts, pages and products to anyone (for example /wp-json/wp/v2/posts).', 'scrapelock' );
		}
		if ( isset( $s['feed_mode'] ) && 'full' === $s['feed_mode'] ) {
			$open[] = __( 'The RSS / Atom feeds carry the full text of every new post.', 'scrapelock' );
		}
		if ( PNCP_Graphql::active() && empty( $s['graphql_hide_content'] ) ) {
			$open[] = __( 'WPGraphQL gives the full text to anyone.', 'scrapelock' );
		}
		if ( ! $open ) {
			return self::result( 'open_content', 'good', __( 'Your content is not open in other channels', 'scrapelock' ), __( 'Copy protection is on, and the REST API, the feeds and WPGraphQL do not give the full text to visitors.', 'scrapelock' ) );
		}
		$text  = __( 'Copy protection is on for the pages, but scrapers rarely copy from pages when the same text is available elsewhere.', 'scrapelock' );
		$text .= ' ' . __( 'Turn these off in the “Feeds and API” tab, unless an app, a headless front end or a feed service needs them.', 'scrapelock' );
		return self::result( 'open_content', 'recommended', __( 'Your content can still be taken through other channels', 'scrapelock' ), $text, 'content', '', '', self::html_list( $open ) );
	}

	/**
	 * 3.5: other active plugins that do one of ScrapeLock's jobs (only while ScrapeLock's own feature for that job
	 * is on). Security / firewall plugins and page caches are never listed: they work alongside ScrapeLock.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_conflicts() {
		$s        = PNCP_Options::stored();
		$defaults = array(
			'wp-content-copy-protector'                       => 'copy',
			'secure-copy-content-protection'                  => 'copy',
			'wp-copyprotect'                                  => 'copy',
			'no-right-click-images-plugin'                    => 'copy',
			'kripanov-anticopia'                              => 'copy',
			'init-content-protector'                          => 'copy',
			'whoknew-shield'                                  => 'copy',
			'robart-image-guard'                              => 'copy',
			'selective-image-guard'                           => 'copy',
			'image-watermark'                                 => 'watermark',
			'easy-watermark'                                  => 'watermark',
			'better-robots-txt'                               => 'bots',
			'bot-lockout'                                     => 'bots',
			'blackhole-bad-bots'                              => 'bots',
			'dark-visitors'                                   => 'bots',
			'block-ai-crawlers'                               => 'bots',
			'content-heal-ai-crawler-protection-honeypot-shield' => 'bots',
		);
		/**
		 * 3.5: plugins that do the same job as ScrapeLock, reported on Site Health while ScrapeLock's own feature
		 * for that job is on.
		 *
		 * @param array<string, string> $plugins Plugin folder (or single-file name without .php) => copy, watermark
		 *                                       or bots. Other types are ignored.
		 */
		$list = apply_filters( 'pncp_conflicting_plugins', $defaults );
		$map  = array();
		foreach ( is_array( $list ) ? $list : array() as $slug => $type ) {
			if ( is_string( $slug ) && '' !== $slug && in_array( $type, array( 'copy', 'watermark', 'bots' ), true ) ) {
				$map[ strtolower( $slug ) ] = $type;
			}
		}
		$on = array(
			'copy'      => ! empty( $s['enabled'] ) && self::copy_protection_on( $s ),
			// 3.5: the watermark does nothing while the protection is off (PNCP_Watermark), like the copy check.
			'watermark' => ! empty( $s['enabled'] ) && ! empty( $s['watermark_enabled'] ),
			'bots'      => ! empty( $s['enabled'] ) && ( ! empty( $s['block_bots'] ) || ! empty( $s['robots_ai_block'] ) || ! empty( $s['trap_enabled'] ) ),
		);

		$files = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$files = array_merge( $files, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		$self  = strtolower( dirname( plugin_basename( PNCP_FILE ) ) );
		$found = array();
		foreach ( array_unique( array_filter( $files, 'is_string' ) ) as $file ) {
			$dir  = dirname( $file );
			$slug = strtolower( '.' === $dir ? preg_replace( '/\.php$/i', '', basename( $file ) ) : $dir );
			if ( $slug === $self || ! isset( $map[ $slug ] ) || ! $on[ $map[ $slug ] ] ) {
				continue;
			}
			$name = $slug;
			if ( is_file( WP_PLUGIN_DIR . '/' . $file ) ) {
				if ( ! function_exists( 'get_plugin_data' ) ) {
					require_once ABSPATH . 'wp-admin/includes/plugin.php';
				}
				$header = get_plugin_data( WP_PLUGIN_DIR . '/' . $file, false, false );
				$name   = ! empty( $header['Name'] ) ? (string) $header['Name'] : $slug;
			}
			$found[] = array( $map[ $slug ], $name );
		}
		if ( ! $found ) {
			return self::result( 'conflicts', 'good', __( 'No other plugin does ScrapeLock\'s job', 'scrapelock' ), __( 'No other copy-protection, watermark or bot-blocking plugin is active. Security and firewall plugins are not counted: they work alongside ScrapeLock.', 'scrapelock' ) );
		}
		$items = array();
		$types = array();
		foreach ( $found as $item ) {
			$types[] = $item[0];
			if ( 'copy' === $item[0] ) {
				/* translators: %s: plugin name */
				$items[] = sprintf( __( '%s: two copy-protection scripts on the same page can cancel each other\'s exceptions (staff, accessibility tools, the source added to copied text) and do the work twice. ScrapeLock\'s copy settings are on the “On the page” tab.', 'scrapelock' ), $item[1] );
			} elseif ( 'watermark' === $item[0] ) {
				/* translators: %s: plugin name */
				$items[] = sprintf( __( '%s: two watermark plugins can stamp an image twice, and restoring the originals with one can undo the other. ScrapeLock\'s watermark is on the Images tab.', 'scrapelock' ), $item[1] );
			} else {
				/* translators: %s: plugin name */
				$items[] = sprintf( __( '%s: two plugins that block bots or AI crawlers can disagree (one allows AI search, the other refuses it), and both change robots.txt.', 'scrapelock' ), $item[1] );
			}
		}
		$tabs = array(
			'copy'      => 'general',
			'watermark' => 'images',
			'bots'      => 'bots',
		);
		$tab  = in_array( 'copy', $types, true ) ? 'general' : $tabs[ $types[0] ];
		return self::result( 'conflicts', 'recommended', __( 'Other plugins do the same job as ScrapeLock', 'scrapelock' ), __( 'Two plugins doing the same job on the same request make problems hard to explain. Keep one of them for each job.', 'scrapelock' ), $tab, '', '', self::html_list( $items ) );
	}

	/**
	 * Updates WordPress already knows about (core, plugins, themes, translations not counted).
	 *
	 * @return int
	 */
	private static function updates_waiting() {
		$count = 0;
		foreach ( array( 'update_plugins', 'update_themes' ) as $name ) {
			$data = get_site_transient( $name );
			if ( is_object( $data ) && ! empty( $data->response ) && is_array( $data->response ) ) {
				$count += count( $data->response );
			}
		}
		$core = get_site_transient( 'update_core' );
		if ( is_object( $core ) && ! empty( $core->updates ) && is_array( $core->updates ) ) {
			foreach ( $core->updates as $update ) {
				if ( is_object( $update ) && isset( $update->response ) && 'upgrade' === $update->response ) {
					++$count;
					break;
				}
			}
		}
		return $count;
	}

	/**
	 * The ScrapeLock section on the Info tab (and in the copied report). No secrets: no keys, tokens or
	 * IP lists, only what is on and off.
	 *
	 * @param array<string, mixed> $info Sections.
	 * @return array<string, mixed>
	 */
	public static function info( $info ) {
		$s    = PNCP_Options::stored();
		$yes  = __( 'Yes', 'scrapelock' );
		$no   = __( 'No', 'scrapelock' );
		$flag = static function ( $key ) use ( $s, $yes, $no ) {
			return ! empty( $s[ $key ] ) ? $yes : $no;
		};
		// A limit per minute as it is stored, or "off" for 0.
		$per_min = static function ( $key ) use ( $s ) {
			/* translators: %d: requests per minute */
			return (int) $s[ $key ] > 0 ? sprintf( __( '%d/min', 'scrapelock' ), (int) $s[ $key ] ) : __( 'Off', 'scrapelock' );
		};
		$until   = PNCP_Options::emergency_until();
		$fp_time = PNCP_Integrity::baseline()['time']; // 3.4.3: read once (see test_integrity()).
		$lists   = array();
		foreach ( PNCP_Ip::lists_updated() as $name => $time ) {
			$lists[] = $name . ': ' . ( $time ? wp_date( 'Y-m-d H:i', $time ) : '-' );
		}
		if ( PNCP_Lockdown::server_unlocked() ) {
			$lock = __( 'Off from the server (SCRAPELOCK_UNLOCK)', 'scrapelock' );
		} elseif ( ! PNCP_Lockdown::configured() ) {
			$lock = __( 'Not set up', 'scrapelock' );
		} elseif ( PNCP_Lockdown::is_locked() ) {
			$lock = __( 'Locked', 'scrapelock' );
		} elseif ( PNCP_Lockdown::unlocked_until() ) {
			/* translators: %s: date and time. */
			$lock = sprintf( __( 'Unlocked until %s', 'scrapelock' ), wp_date( 'Y-m-d H:i', PNCP_Lockdown::unlocked_until() ) );
		} else {
			$lock = __( 'Not locked', 'scrapelock' );
		}
		$edge = __( 'Off', 'scrapelock' );
		if ( PNCP_Edge::usable() ) {
			$state = PNCP_Edge::state();
			/* translators: 1: CDN name, 2: number of addresses */
			$edge = sprintf( __( '%1$s, %2$d addresses blocked', 'scrapelock' ), PNCP_Edge::providers()[ PNCP_Edge::config()['provider'] ], PNCP_Edge::count() );
			if ( '' !== $state['error'] ) {
				/* translators: %s: error message */
				$edge .= '; ' . sprintf( __( 'last error: %s', 'scrapelock' ), $state['error'] );
			}
		}
		$fields = array(
			'version'        => array( __( 'Version', 'scrapelock' ), PNCP_VERSION ),
			'enabled'        => array( __( 'Protection', 'scrapelock' ), $flag( 'enabled' ) ),
			/* translators: %s: date and time. */
			'emergency'      => array( __( 'Emergency Mode', 'scrapelock' ), $until ? sprintf( __( 'On until %s', 'scrapelock' ), wp_date( 'Y-m-d H:i', $until ) ) : $no ),
			'monitor'        => array( __( 'Monitor only (nothing blocked)', 'scrapelock' ), PNCP_Options::monitoring( $s ) ? ( ! empty( $s['monitor_until'] ) ? sprintf( /* translators: %s: date and time. */ __( 'On until %s', 'scrapelock' ), wp_date( 'Y-m-d H:i', (int) $s['monitor_until'] ) ) : $yes ) : $no ),
			'block_bots'     => array( __( 'Block the bot list', 'scrapelock' ), $flag( 'block_bots' ) ),
			'browsers_only'  => array( __( 'Browsers only', 'scrapelock' ), $flag( 'require_browser_headers' ) ),
			'human_check'    => array( __( 'Human check', 'scrapelock' ), empty( $s['human_check'] ) ? $no : $per_min( 'rate_limit_unverified' ) ),
			'rate_limits'    => array( __( 'Limits per minute (pages, search, REST, 404, sitemaps)', 'scrapelock' ), implode( ', ', array_map( $per_min, array( 'rate_limit', 'rate_limit_search', 'rate_limit_rest', 'rate_limit_404', 'rate_limit_sitemap' ) ) ) ),
			'datacenter'     => array( __( 'Limit for data centers', 'scrapelock' ), $per_min( 'rate_limit_datacenter' ) ),
			'cart_limits'    => array( __( 'WooCommerce limits per minute (cart / checkout, coupons)', 'scrapelock' ), $per_min( 'rate_limit_cart' ) . ', ' . $per_min( 'rate_limit_coupon' ) ),
			'countries'      => array( __( 'Blocked countries', 'scrapelock' ), '' !== trim( (string) $s['countries_block'] ) ? implode( ', ', PNCP_Options::parse_countries( (string) $s['countries_block'] ) ) : '-' ),
			'countries_lim'  => array( __( 'Countries with a stricter limit', 'scrapelock' ), '' !== trim( (string) $s['countries_strict'] ) ? implode( ', ', PNCP_Options::parse_countries( (string) $s['countries_strict'] ) ) . ' (' . $per_min( 'rate_limit_country' ) . ')' : '-' ),
			'exempt_cap'     => array( __( 'Who is exempt', 'scrapelock' ), (string) $s['exempt_cap'] ),
			'feed_mode'      => array( __( 'Feeds', 'scrapelock' ), (string) $s['feed_mode'] ),
			'rest_content'   => array( __( 'Content hidden in the REST API', 'scrapelock' ), $flag( 'rest_hide_content' ) ),
			'ip_header'      => array( __( 'Real visitor IP', 'scrapelock' ), (string) $s['ip_header'] ),
			'ip_lists'       => array( __( 'Official IP lists updated', 'scrapelock' ), $lists ? implode( ', ', $lists ) : '-' ),
			'early'          => array( __( 'Early check', 'scrapelock' ), empty( $s['early_mode'] ) ? $no : ( PNCP_Early::installed() ? __( 'Running', 'scrapelock' ) : __( 'On, not running', 'scrapelock' ) ) ),
			'precheck'       => array( __( 'Pre-cache check', 'scrapelock' ), empty( $s['precheck'] ) ? $no : ( PNCP_Precheck::active() ? __( 'Running', 'scrapelock' ) : __( 'On, not running', 'scrapelock' ) ) ),
			'user_enum'      => array( __( 'Hide usernames', 'scrapelock' ), $flag( 'block_user_enum' ) ),
			'pingback'       => array( __( 'Pingbacks off', 'scrapelock' ), $flag( 'disable_pingback' ) ),
			'rest_map'       => array( __( 'REST map hidden from visitors', 'scrapelock' ), $flag( 'hide_rest_discovery' ) ),
			'versions'       => array( __( 'Versions hidden', 'scrapelock' ), $flag( 'hide_versions' ) ),
			'list_excerpts'  => array( __( 'Excerpts in lists of articles', 'scrapelock' ), $flag( 'list_excerpts' ) ),
			'ipv6_wide'      => array( __( 'IPv6 /56 limit', 'scrapelock' ), $flag( 'ipv6_wide' ) ),
			'archives'       => array( __( 'Web archives blocked', 'scrapelock' ), $flag( 'block_archivers' ) ),
			'upload_php'     => array( __( 'No PHP in the uploads folder', 'scrapelock' ), $flag( 'block_upload_php' ) ),
			'auto_emergency' => array( __( 'Automatic Emergency Mode', 'scrapelock' ), empty( $s['auto_emergency'] ) ? $no : ( 'start' === $s['auto_emergency_mode'] ? __( 'Starts on its own', 'scrapelock' ) : __( 'Alerts only', 'scrapelock' ) ) ),
			'edge'           => array( __( 'Blocking at the CDN', 'scrapelock' ), $edge ),
			'cdn_only'       => array( __( 'Only through the CDN', 'scrapelock' ), PNCP_Origin::active( $s ) ? $yes : $no ),
			'integrity'      => array( __( 'File integrity fingerprint', 'scrapelock' ), $fp_time ? wp_date( 'Y-m-d H:i', $fp_time ) : '-' ),
			'lockdown'       => array( __( 'Lockdown', 'scrapelock' ), $lock ),
			'lockdown_roles' => array( __( 'Roles frozen while locked', 'scrapelock' ), implode( ', ', PNCP_Lockdown::frozen_roles() ) ),
			'lockdown_work'  => array( __( 'Roles that keep their work while locked', 'scrapelock' ), implode( ', ', PNCP_Lockdown::limited_roles() ) ),
		);
		if ( ! class_exists( 'WooCommerce' ) ) {
			unset( $fields['cart_limits'] );
		}
		$section = array(
			'label'  => 'ScrapeLock',
			'fields' => array(),
		);
		foreach ( $fields as $key => $field ) {
			$section['fields'][ $key ] = array(
				'label' => $field[0],
				'value' => $field[1],
			);
		}
		$info['scrapelock'] = $section;
		return $info;
	}
}
