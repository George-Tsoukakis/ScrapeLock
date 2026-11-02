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
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'site_status_tests', array( __CLASS__, 'tests' ) );
		add_filter( 'debug_information', array( __CLASS__, 'info' ) );
	}

	/**
	 * The tests, all direct (they only read settings, files and the current request).
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
	 * @return array<string, mixed>
	 */
	private static function result( $key, $status, $label, $description, $tab = '', $anchor = '', $extra = '' ) {
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
			'description' => '<p>' . esc_html( $description ) . '</p>',
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
		$parts[] = __( 'Until they are, real search engines are verified with slower DNS lookups only, and the Cloudflare addresses come from the list built into the plugin. The lists are refreshed once a day through WordPress\'s scheduled tasks (cron): check that cron runs and that the server can reach google.com, bing.com and cloudflare.com, or use “Refresh lists now”.', 'scrapelock' );
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
		if ( PNCP_Lockdown::is_locked() && ! PNCP_Seal::guard_installed() ) {
			return self::result( 'lockdown', 'recommended', __( 'ScrapeLock Lockdown works without its guard file', 'scrapelock' ), __( 'The file wp-content/mu-plugins/scrapelock-lockdown-guard.php could not be written. The lock works, but someone who can change the database directly could open it. Let the web server write to wp-content/mu-plugins, then lock the site again.', 'scrapelock' ), 'lockdown' );
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
		if ( ! empty( $report['tampered'] ) || ( PNCP_Lockdown::is_locked() && PNCP_Integrity::baseline()['tampered'] ) ) {
			return self::result( 'integrity', 'critical', __( 'The ScrapeLock file fingerprint was changed outside WordPress', 'scrapelock' ), __( 'The fingerprint of the code files was changed or removed in the database while the site was locked, so new or changed files might have been hidden. Check the files with a security scanner; a new fingerprint is taken the next time you lock the site.', 'scrapelock' ), 'lockdown' );
		}
		// The hourly check runs on WordPress's cron: if it stopped (DISABLE_WP_CRON without a real cron job, or
		// the event was removed), a quiet report must not look like a clean site.
		if ( PNCP_Lockdown::is_locked() && PNCP_Integrity::baseline()['time'] && (int) $report['time'] < time() - 3 * HOUR_IN_SECONDS ) {
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
		if ( ! PNCP_Integrity::baseline()['time'] ) {
			return self::result( 'integrity', 'good', __( 'ScrapeLock file integrity is not active', 'scrapelock' ), __( 'The fingerprint of the code files is taken when the site is locked with Lockdown, and checked every hour while it stays locked.', 'scrapelock' ) );
		}
		return self::result( 'integrity', 'good', __( 'No changed code files', 'scrapelock' ), __( 'No code file was added or changed since the site was locked, and WordPress and its plugins from WordPress.org match their official copies.', 'scrapelock' ) );
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
			'integrity'      => array( __( 'File integrity fingerprint', 'scrapelock' ), PNCP_Integrity::baseline()['time'] ? wp_date( 'Y-m-d H:i', PNCP_Integrity::baseline()['time'] ) : '-' ),
			'lockdown'       => array( __( 'Lockdown', 'scrapelock' ), $lock ),
			'lockdown_roles' => array( __( 'Roles frozen while locked', 'scrapelock' ), implode( ', ', PNCP_Lockdown::frozen_roles() ) ),
		);
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
