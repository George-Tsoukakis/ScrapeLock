<?php
/**
 * Service bots of active plugins: a plugin that is active on the site has servers (or a preload of its own)
 * that fetch the site's pages, and those requests are not browsers. With "Browsers only", the bot list or the
 * headless check they got a 403, e.g. WP Rocket's "WP-Rocket-SaaS" (Remove Unused CSS, critical CSS) while WP
 * Rocket itself was active on the same site. 3.10: while the plugin is active, its bot is allowed like an
 * entry of "Always allowed User-Agents" (it passes the bot list, "Browsers only" and the headless check), and
 * the administrator can stop allowing each one. Nothing is ever blocked here: this only lets requests through.
 *
 * What the allowance does NOT do (a User-Agent is easy to spoof): it never exempts from the page limits, the
 * bot trap, the probe ban, the malicious User-Agent check, fake crawler checks or blocked IPs and countries.
 * Only an entry verified by IP (an official address list in the registry, or a request from the site's own
 * server address for the bots a plugin sends from the site itself) is also exempt from the data center and
 * country limits, exactly like a pinned "UA@CIDR" entry of the always-allowed list.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Registry of plugins => their service bots, the per-bot switch and the Bots tab panel and notice.
 */
final class PNCP_Plugin_Bots {

	/**
	 * Stored state: array{ off: string[] } (the ids the administrator stopped allowing). A separate option, not
	 * a setting of pncp_settings: no settings form posts it, so saving a tab never changes it. No option = every
	 * known bot of an active plugin allowed (existing sites get the allowance on upgrade without a migration).
	 */
	const OPTION = 'pncp_plugin_bots';

	/**
	 * The admin-post action of the "Allow" / "Stop allowing" buttons.
	 */
	const ACTION = 'pncp_plugin_bot';

	/**
	 * Log reasons that the allowance prevents (counted for the notice and the panel). Not limits, not attacks.
	 */
	const REASONS = array( 'bot_ua', 'no_browser', 'headless', 'fake_browser' );

	/**
	 * Registry memo for this request.
	 *
	 * @var array<string, array<string, mixed>>|null
	 */
	private static $registry = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		add_action( 'admin_notices', array( __CLASS__, 'render_result_notice' ) );
	}

	/**
	 * The known plugins and their bots. Only bots whose User-Agent is documented by the plugin's maker or seen in
	 * real logs; image optimizers (ShortPixel, Imagify, Smush) are not here because they fetch image files, which
	 * the web server serves without WordPress (ScrapeLock never sees them). OneSignal is not here either: its
	 * service worker file is fetched by the visitors' own browsers, not by a OneSignal bot.
	 *
	 * Each entry: name (the plugin's name, not translated), plugins (basenames; any one active is enough), agents
	 * (User-Agent parts, case-insensitive, like the always-allowed list), ips (optional: an official address list;
	 * when set, the bot is allowed ONLY from these addresses), site (optional: User-Agent parts the plugin sends
	 * from the site's own server, verified by the server's address), source (where the User-Agent is documented).
	 *
	 * Filter `pncp_plugin_bots` adds, changes or removes entries (keys are ids: lowercase letters, digits, "-").
	 *
	 * @return array<string, array{name:string, plugins:string[], agents:string[], ips:string[], site:string[], source:string}>
	 */
	public static function registry() {
		if ( null !== self::$registry ) {
			return self::$registry;
		}
		$known = array(
			// WP Rocket: "WP-Rocket-SaaS" is the User-Agent of its SaaS (Remove Unused CSS, critical CSS / LCP
			// optimization), from WP Rocket's servers; seen in real logs (pharmacyneeds.gr, ~480 requests in 7 days).
			// "WP Rocket/Preload" (also "WP Rocket/Homepage_Preload_After_Purge_Cache" and the like) is the
			// cache preload, which WP Rocket sends from the site itself (includes/.../Preload in WP Rocket's code).
			'wp-rocket' => array(
				'name'    => 'WP Rocket',
				'plugins' => array( 'wp-rocket/wp-rocket.php' ),
				'agents'  => array( 'WP-Rocket-SaaS', 'WP Rocket/' ),
				'ips'     => array(),
				'site'    => array( 'WP Rocket/' ),
				'source'  => 'https://docs.wp-rocket.me/',
			),
			// Jetpack: "Jetpack by WordPress.com" (WordPress.com's servers: sync, Protect, Backup) and "jetmon"
			// (the Jetpack uptime monitor, "jetmon/1.0 (Jetpack Site Uptime Monitor by WordPress.com)").
			'jetpack'   => array(
				'name'    => 'Jetpack',
				'plugins' => array( 'jetpack/jetpack.php' ),
				'agents'  => array( 'Jetpack by WordPress.com', 'jetmon/' ),
				'ips'     => array(),
				'site'    => array(),
				'source'  => 'https://jetpack.com/support/monitor/',
			),
		);
		/**
		 * The service bots of plugins.
		 *
		 * @param array<string, array<string, mixed>> $known id => entry (see PNCP_Plugin_Bots::registry()).
		 */
		$raw = apply_filters( 'pncp_plugin_bots', $known );
		$out = array();
		foreach ( is_array( $raw ) ? $raw : array() as $id => $entry ) {
			$id = is_string( $id ) ? sanitize_key( $id ) : '';
			if ( '' === $id || ! is_array( $entry ) ) {
				continue;
			}
			$clean = array(
				'name'    => isset( $entry['name'] ) ? sanitize_text_field( (string) $entry['name'] ) : $id,
				'plugins' => array(),
				'agents'  => array(),
				'ips'     => array(),
				'site'    => array(),
				'source'  => isset( $entry['source'] ) ? esc_url_raw( (string) $entry['source'] ) : '',
			);
			foreach ( isset( $entry['plugins'] ) ? (array) $entry['plugins'] : array() as $plugin ) {
				$plugin = trim( (string) $plugin );
				if ( '' !== $plugin && false !== strpos( $plugin, '/' ) && false === strpos( $plugin, '..' ) ) {
					$clean['plugins'][] = $plugin;
				}
			}
			// The same rule as the "Always allow this User-Agent" button: no part that would also match browsers.
			foreach ( array( 'agents', 'site' ) as $key ) {
				foreach ( isset( $entry[ $key ] ) ? (array) $entry[ $key ] : array() as $agent ) {
					$agent = trim( (string) $agent );
					if ( '' === PNCP_Options::allow_token_refusal( $agent ) ) {
						$clean[ $key ][] = $agent;
					}
				}
			}
			foreach ( isset( $entry['ips'] ) ? (array) $entry['ips'] : array() as $range ) {
				if ( PNCP_Ip::valid_range( (string) $range ) && ! PNCP_Options::range_too_wide( (string) $range ) ) {
					$clean['ips'][] = trim( (string) $range );
				}
			}
			if ( $clean['plugins'] && $clean['agents'] ) {
				$out[ $id ] = $clean;
			}
		}
		self::$registry = $out;
		return $out;
	}

	/**
	 * Forgets the registry of this request (tests, and after the filter changed).
	 */
	public static function reset() {
		self::$registry = null;
	}

	/**
	 * Is one of these plugins active (on this site, or network-wide on a multisite)?
	 *
	 * @param string[] $plugins Plugin basenames.
	 * @return bool
	 */
	public static function plugin_active( $plugins ) {
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		return (bool) array_intersect( (array) $plugins, $active );
	}

	/**
	 * The ids the administrator stopped allowing.
	 *
	 * @return string[]
	 */
	public static function switched_off() {
		$state = get_option( self::OPTION, array() );
		$off   = is_array( $state ) && isset( $state['off'] ) ? (array) $state['off'] : array();
		return array_values( array_filter( array_map( 'sanitize_key', $off ) ) );
	}

	/**
	 * Is this bot allowed now: its plugin active and the administrator did not stop allowing it?
	 *
	 * @param string $id Id from registry().
	 * @return bool
	 */
	public static function allowed( $id ) {
		$registry = self::registry();
		return isset( $registry[ $id ] ) && self::plugin_active( $registry[ $id ]['plugins'] ) && ! in_array( $id, self::switched_off(), true );
	}

	/**
	 * The allowed plugin bot this request comes from, if any. The User-Agent is compared first (a few substring
	 * checks), so an ordinary request costs nothing more.
	 *
	 * @param string $ua User-Agent.
	 * @param string $ip IP.
	 * @return array{id:string, verified:bool}|null verified = matched by an address (official list or the site's own server).
	 */
	public static function match( $ua, $ip ) {
		$ua = (string) $ua;
		if ( '' === trim( $ua ) ) {
			return null;
		}
		foreach ( self::registry() as $id => $entry ) {
			if ( ! PNCP_Bots::ua_in_list( $ua, $entry['agents'] ) || ! self::allowed( $id ) ) {
				continue;
			}
			$reliable = PNCP_Ip::reliable();
			if ( $entry['ips'] ) {
				// An official address list: from those addresses only, like a pinned "UA@CIDR" entry.
				if ( $reliable && PNCP_Ip::in_any( $ip, $entry['ips'] ) ) {
					return array(
						'id'       => $id,
						'verified' => true,
					);
				}
				continue;
			}
			// A bot the plugin sends from the site itself (e.g. WP Rocket's preload through the CDN): verified when
			// the address is the server's own.
			$site = $entry['site'] && $reliable && PNCP_Bots::ua_in_list( $ua, $entry['site'] ) && PNCP_Ip::is_local( $ip );
			return array(
				'id'       => $id,
				'verified' => $site,
			);
		}
		return null;
	}

	/**
	 * Requests of a bot refused in the last days for a reason that the allowance prevents (self::REASONS).
	 *
	 * @param string $id   Id from registry().
	 * @param int    $days Days back.
	 * @return int
	 */
	public static function refused( $id, $days = 7 ) {
		global $wpdb;
		$registry = self::registry();
		if ( ! isset( $registry[ $id ] ) || ! PNCP_Log::ready() ) {
			return 0;
		}
		$like = array();
		$args = array( PNCP_Log::table(), gmdate( 'Y-m-d H:i:s', time() - (int) $days * DAY_IN_SECONDS ) );
		foreach ( $registry[ $id ]['agents'] as $agent ) {
			$like[] = 'ua LIKE %s';
			$args[] = '%' . $wpdb->esc_like( $agent ) . '%';
		}
		$args    = array_merge( $args, self::REASONS );
		$reasons = implode( ', ', array_fill( 0, count( self::REASONS ), '%s' ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Admin screen; the interpolated parts hold only placeholders, one per value.
		$n = $wpdb->get_var( $wpdb->prepare( 'SELECT SUM(hits) FROM %i WHERE created >= %s AND (' . implode( ' OR ', $like ) . ") AND reason IN ($reasons)", $args ) );
		return (int) $n;
	}

	/**
	 * The known bots whose plugin is active: id => entry + allowed + refused (last 7 days).
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function active() {
		$out = array();
		$off = self::switched_off();
		foreach ( self::registry() as $id => $entry ) {
			if ( self::plugin_active( $entry['plugins'] ) ) {
				$out[ $id ] = $entry + array(
					'allowed' => ! in_array( $id, $off, true ),
					'refused' => self::refused( $id ),
				);
			}
		}
		return $out;
	}

	/**
	 * Allows a bot again, or stops allowing it.
	 *
	 * @param string $id    Id from registry().
	 * @param bool   $allow True = allow (remove from the switched-off list).
	 * @return bool False for an unknown id.
	 */
	public static function set_allowed( $id, $allow ) {
		if ( ! isset( self::registry()[ $id ] ) ) {
			return false;
		}
		$off = array_diff( self::switched_off(), array( $id ) );
		if ( ! $allow ) {
			$off[] = $id;
		}
		update_option( self::OPTION, array( 'off' => array_values( array_unique( $off ) ) ), true );
		return true;
	}

	/* ---------- Admin ---------- */

	/**
	 * The buttons: "Allow" / "Stop allowing" (nonce, manage_options, not while the site is locked).
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked just above.
		$allow = isset( $_POST['allow'] ) ? sanitize_key( wp_unslash( $_POST['allow'] ) ) : '';
		$stop  = isset( $_POST['stop'] ) ? sanitize_key( wp_unslash( $_POST['stop'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		$id      = '' !== $allow ? $allow : $stop;
		$message = 'plugin_bot_error';
		if ( ! PNCP_Lockdown::is_locked() && '' !== $id && self::set_allowed( $id, '' !== $allow ) ) {
			$message = '' !== $allow ? 'plugin_bot_allowed' : 'plugin_bot_stopped';
		}
		wp_safe_redirect(
			PNCP_Status::settings_url(
				array(
					'tab'          => 'bots',
					'pncp_message' => $message,
					'pncp_bot'     => $id,
				)
			) . '#pncp-sec-allowed'
		);
		exit;
	}

	/**
	 * The notice after a button (the settings page's own notices do not know these codes).
	 */
	public static function render_result_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Only displays a notice.
		$message = isset( $_GET['pncp_message'] ) ? sanitize_key( wp_unslash( $_GET['pncp_message'] ) ) : '';
		$id      = isset( $_GET['pncp_bot'] ) ? sanitize_key( wp_unslash( $_GET['pncp_bot'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		if ( ! $screen || 'settings_page_' . PNCP_Status::SETTINGS_PAGE !== $screen->id || 0 !== strpos( $message, 'plugin_bot_' ) ) {
			return;
		}
		$registry = self::registry();
		$name     = isset( $registry[ $id ] ) ? $registry[ $id ]['name'] : '';
		if ( 'plugin_bot_allowed' === $message && '' !== $name ) {
			/* translators: %s: plugin name, e.g. WP Rocket */
			$text = sprintf( __( 'The service bot of %s is allowed again while the plugin is active. The page limits still apply to it.', 'scrapelock' ), $name );
			$type = 'success';
		} elseif ( 'plugin_bot_stopped' === $message && '' !== $name ) {
			/* translators: %s: plugin name, e.g. WP Rocket */
			$text = sprintf( __( 'The service bot of %s is no longer allowed: it is checked like any other visitor.', 'scrapelock' ), $name );
			$type = 'success';
		} else {
			$text = __( 'Nothing changed: the bot is unknown, or the site is locked.', 'scrapelock' );
			$type = 'error';
		}
		printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $type ), esc_html( $text ) );
	}

	/**
	 * The form the buttons submit (they sit inside the Bots tab's settings form, so they point to this one with
	 * the "form" attribute), and the warning about a known bot that is not allowed and was refused lately.
	 * Called at the top of the Bots tab, before its settings form opens.
	 */
	public static function render_notice_and_form() {
		printf( '<form id="pncp-plugin-bots-form" method="post" action="%s">', esc_url( admin_url( 'admin-post.php' ) ) );
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( self::ACTION ) );
		wp_nonce_field( self::ACTION );
		echo '</form>';
		foreach ( self::active() as $id => $bot ) {
			if ( $bot['allowed'] || $bot['refused'] < 1 ) {
				continue;
			}
			echo '<div class="notice notice-warning inline pncp-plugin-bot-notice"><p>';
			echo esc_html(
				sprintf(
					/* translators: 1: number of requests, 2: plugin name, 3: User-Agent parts */
					_n( 'ScrapeLock refused %1$s request of %2$s\'s service bot (%3$s) in the last 7 days, while %2$s is active on this site. You stopped allowing it; the plugin may not work fully without it.', 'ScrapeLock refused %1$s requests of %2$s\'s service bot (%3$s) in the last 7 days, while %2$s is active on this site. You stopped allowing it; the plugin may not work fully without it.', $bot['refused'], 'scrapelock' ),
					number_format_i18n( $bot['refused'] ),
					$bot['name'],
					implode( ', ', $bot['agents'] )
				)
			);
			echo '</p><p>';
			self::button( 'allow', $id, __( 'Allow', 'scrapelock' ), 'button button-primary' );
			echo '</p></div>';
		}
	}

	/**
	 * The list under "Always allowed": each known bot of an active plugin, whether it is allowed, and a switch.
	 */
	public static function render_panel() {
		$bots = self::active();
		echo '<div class="pncp-plugin-bots"><p><strong>' . esc_html__( 'Service bots of your active plugins', 'scrapelock' ) . '</strong></p>';
		if ( ! $bots ) {
			$names = wp_list_pluck( self::registry(), 'name' );
			printf(
				'<p class="description">%s</p></div>',
				esc_html(
					sprintf(
						/* translators: %s: list of plugin names */
						__( 'None of the plugins whose service bots ScrapeLock knows (%s) is active here. When one is, its bot is allowed while the plugin stays active.', 'scrapelock' ),
						implode( ', ', $names )
					)
				)
			);
			return;
		}
		echo '<ul>';
		foreach ( $bots as $id => $bot ) {
			echo '<li class="pncp-plugin-bot" data-bot="' . esc_attr( $id ) . '"><code>' . esc_html( implode( ', ', $bot['agents'] ) ) . '</code> ';
			if ( $bot['allowed'] ) {
				/* translators: %s: plugin name, e.g. WP Rocket */
				echo '<span class="pncp-plugin-bot-on">' . esc_html( sprintf( __( 'Allowed because %s is active.', 'scrapelock' ), $bot['name'] ) ) . '</span> ';
				self::button( 'stop', $id, __( 'Stop allowing', 'scrapelock' ), 'button button-small' );
			} else {
				/* translators: %s: plugin name, e.g. WP Rocket */
				echo '<span class="pncp-plugin-bot-off">' . esc_html( sprintf( __( 'Not allowed: you stopped allowing it, although %s is active.', 'scrapelock' ), $bot['name'] ) ) . '</span> ';
				self::button( 'allow', $id, __( 'Allow', 'scrapelock' ), 'button button-small' );
			}
			if ( $bot['refused'] > 0 ) {
				echo ' <span class="description">' . esc_html(
					sprintf(
						/* translators: %s: number of requests */
						_n( '%s request refused in the last 7 days.', '%s requests refused in the last 7 days.', $bot['refused'], 'scrapelock' ),
						number_format_i18n( $bot['refused'] )
					)
				) . '</span>';
			}
			echo '</li>';
		}
		echo '</ul><p class="description">' . esc_html__( 'Allowed like the User-Agents above: they pass the bot list, “Browsers only” and the headless check. The page limits, the bot trap and the attack checks still apply, because a User-Agent is easy to spoof. The buttons save at once.', 'scrapelock' ) . '</p></div>';
	}

	/**
	 * A button of the form of render_notice_and_form().
	 *
	 * @param string $op    allow | stop.
	 * @param string $id    Bot id.
	 * @param string $label Label.
	 * @param string $class CSS classes.
	 */
	private static function button( $op, $id, $label, $class ) {
		printf(
			'<button type="submit" form="pncp-plugin-bots-form" name="%1$s" value="%2$s" class="%3$s">%4$s</button>',
			esc_attr( $op ),
			esc_attr( $id ),
			esc_attr( $class ),
			esc_html( $label )
		);
	}
}
