<?php
/**
 * Status indicator: Dashboard widget (with a 24-hour summary) and a button in the admin bar.
 * One-click enable, disable only after confirmation, Emergency Mode.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Protection status, toggle and Emergency Mode.
 */
final class PNCP_Status {

	const ACTION    = 'pncp_toggle';
	const EMERGENCY = 'pncp_emergency';
	const MONITOR   = 'pncp_monitor';
	const DISMISS   = 'pncp_surge_dismiss';

	// Same as PNCP_Admin::PAGE; the admin class is not loaded on the public site, where the bar is shown.
	const SETTINGS_PAGE = 'scrapelock';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'add_widget' ) );
		add_action( 'admin_bar_menu', array( __CLASS__, 'admin_bar' ), 90 );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'admin_bar_css' ) );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'admin_bar_css' ) );
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle_toggle' ) );
		add_action( 'admin_post_' . self::EMERGENCY, array( __CLASS__, 'handle_emergency' ) );
		add_action( 'admin_post_' . self::MONITOR, array( __CLASS__, 'handle_monitor' ) );
		add_action( 'admin_post_' . self::DISMISS, array( __CLASS__, 'handle_dismiss' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_filter( 'removable_query_args', array( __CLASS__, 'removable_args' ) );
	}

	/**
	 * WordPress removes our query args from the address bar after the notice.
	 *
	 * @param string[] $args Query args.
	 * @return string[]
	 */
	public static function removable_args( $args ) {
		$args[] = 'pncp_toggled';
		$args[] = 'pncp_emergency';
		$args[] = 'pncp_confirm';
		$args[] = 'pncp_enforced';
		return $args;
	}

	/**
	 * Is protection enabled?
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return ! empty( PNCP_Options::stored()['enabled'] );
	}

	/**
	 * The settings page.
	 *
	 * @param array<string, string> $args Query args.
	 * @return string
	 */
	public static function settings_url( $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::SETTINGS_PAGE ), $args ), admin_url( 'options-general.php' ) );
	}

	/**
	 * Enable URL (with nonce) that returns to the current page.
	 *
	 * @return string
	 */
	private static function enable_url() {
		$back = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : admin_url();
		return wp_nonce_url(
			add_query_arg(
				array(
					'action'   => self::ACTION,
					'state'    => 'on',
					'redirect' => rawurlencode( $back ),
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION
		);
	}

	/**
	 * Disabling always goes to a confirmation page (one click in the bar is not enough).
	 *
	 * @return string
	 */
	public static function disable_url() {
		return self::settings_url( array( 'pncp_confirm' => 'disable' ) );
	}

	/**
	 * Ends Emergency Mode (with nonce).
	 *
	 * @return string
	 */
	public static function emergency_stop_url() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => self::EMERGENCY,
					'hours'  => 0,
				),
				admin_url( 'admin-post.php' )
			),
			self::EMERGENCY
		);
	}

	/**
	 * Starts Emergency Mode with one click (with nonce), from the surge alert of the automatic Emergency Mode.
	 *
	 * @param int $hours Duration in hours (one of the choices of handle_emergency()).
	 * @return string
	 */
	public static function emergency_start_url( $hours = 1 ) {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => self::EMERGENCY,
					'hours'  => (int) $hours,
				),
				admin_url( 'admin-post.php' )
			),
			self::EMERGENCY
		);
	}

	/**
	 * Dismisses the surge alert (with nonce).
	 *
	 * @return string
	 */
	public static function surge_dismiss_url() {
		return wp_nonce_url( add_query_arg( 'action', self::DISMISS, admin_url( 'admin-post.php' ) ), self::DISMISS );
	}

	/**
	 * Enable (GET with nonce) or disable (POST only, from the confirmation form). Administrators only.
	 */
	public static function handle_toggle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified above.
		$state  = isset( $_REQUEST['state'] ) ? sanitize_key( wp_unslash( $_REQUEST['state'] ) ) : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'off' === $state && 'POST' !== $method ) {
			wp_safe_redirect( self::disable_url() );
			exit;
		}
		if ( ! in_array( $state, array( 'on', 'off' ), true ) ) {
			wp_die( esc_html__( 'Invalid request.', 'scrapelock' ), '', array( 'response' => 400 ) );
		}

		$settings            = PNCP_Options::stored();
		$settings['enabled'] = 'on' === $state ? 1 : 0;
		update_option( PNCP_OPTION, $settings ); // Also flushes the cache (update_option_pncp_settings).
		PNCP_Options::flush();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified above. Not sanitize_text_field (it strips the %XX of Greek URLs).
		$redirect = isset( $_REQUEST['redirect'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect'] ) ) : '';
		$redirect = wp_validate_redirect( $redirect, admin_url() );
		if ( '' === $redirect || false !== strpos( $redirect, 'pncp_confirm=' ) ) {
			$redirect = self::settings_url();
		}
		// The notice is shown only in wp-admin, so we add the query arg only there.
		if ( false !== strpos( $redirect, '/wp-admin/' ) ) {
			$redirect = add_query_arg( 'pncp_toggled', $settings['enabled'] ? 'on' : 'off', $redirect );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Starts (POST, with a duration) or ends (GET/POST with nonce) Emergency Mode.
	 */
	public static function handle_emergency() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::EMERGENCY );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified above.
		$hours = isset( $_REQUEST['hours'] ) ? absint( $_REQUEST['hours'] ) : 0;
		if ( ! in_array( $hours, array( 0, 1, 6, 24, 72 ), true ) ) {
			$hours = 24;
		}
		PNCP_Options::set_emergency( $hours ); // Also answers the surge alert, if there is one.
		wp_safe_redirect( self::settings_url( array( 'pncp_emergency' => $hours ? 'on' : 'off' ) ) );
		exit;
	}

	/**
	 * Dismisses the surge alert of the automatic Emergency Mode (nonce, administrators only).
	 */
	public static function handle_dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::DISMISS );
		PNCP_Surge::clear_alert();
		$redirect = wp_validate_redirect( wp_get_referer(), self::settings_url() );
		wp_safe_redirect( $redirect ? $redirect : self::settings_url() );
		exit;
	}

	/**
	 * The surge alert of the automatic Emergency Mode in "notify" mode: what happened, and one click to start
	 * Emergency Mode for an hour, or to dismiss it. Only while Emergency Mode is off and protection is on.
	 */
	private static function surge_notice() {
		$alert = PNCP_Surge::alert_state();
		if ( ! $alert || PNCP_Options::emergency_until() || ! self::is_enabled() || ! self::notice_screen() ) {
			return;
		}
		printf(
			'<div class="notice notice-warning pncp-surge-notice"><p><strong>%1$s</strong> %2$s</p><p><a class="button button-primary" href="%3$s">%4$s</a> <a class="button" href="%5$s">%6$s</a> <a href="%7$s">%8$s</a></p></div>',
			esc_html__( 'Unusual traffic.', 'scrapelock' ),
			esc_html(
				sprintf(
					/* translators: 1: time, 2: pages per minute, 3: threshold */
					__( 'At %1$s the site received %2$d pages per minute, above the %3$d that count as an attack. It can be a scraping attack spread over many IPs, or many real visitors at once. Nothing has been changed.', 'scrapelock' ),
					wp_date( get_option( 'time_format' ), $alert['time'] ),
					$alert['count'],
					$alert['threshold']
				)
			),
			esc_url( self::emergency_start_url( 1 ) ),
			esc_html__( 'Start Emergency Mode (1 hour)', 'scrapelock' ),
			esc_url( self::surge_dismiss_url() ),
			esc_html__( 'Dismiss', 'scrapelock' ),
			esc_url( self::settings_url() . '#pncp-emergency-title' ),
			esc_html__( 'What Emergency Mode changes', 'scrapelock' )
		);
	}

	/**
	 * "Enforce now": ends "Monitor only" (POST with nonce), so the checks start blocking. Administrators only.
	 */
	public static function handle_monitor() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::MONITOR );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'POST' !== $method ) {
			wp_die( esc_html__( 'Invalid request.', 'scrapelock' ), '', array( 'response' => 400 ) );
		}
		$settings                  = PNCP_Options::stored();
		$settings['monitor_mode']  = 0;
		$settings['monitor_until'] = 0;
		update_option( PNCP_OPTION, $settings ); // Also rewrites the early and pre-cache checks (update_option_pncp_settings).
		PNCP_Options::flush();
		// Started by hand: no "blocking has started" notice later on.
		update_option( PNCP_Options::MONITOR_ENDED_OPTION, 'shown', false );
		wp_safe_redirect( self::settings_url( array( 'pncp_enforced' => PNCP_Options::monitoring( PNCP_Options::stored() ) ? 'failed' : 'on' ) ) );
		exit;
	}

	/**
	 * The Log tab, showing all events, the real blocks or the "would block" entries of "Monitor only".
	 *
	 * @param string $view all | blocked | monitor.
	 * @return string
	 */
	public static function log_url( $view ) {
		return self::settings_url(
			array(
				'tab'      => 'log',
				'log_view' => $view,
			)
		);
	}

	/**
	 * The "Enforce now" button (a small form with nonce).
	 */
	public static function enforce_form() {
		printf( '<form method="post" action="%s" class="pncp-inline-form">', esc_url( admin_url( 'admin-post.php' ) ) );
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( self::MONITOR ) );
		wp_nonce_field( self::MONITOR );
		printf( '<button type="submit" class="button button-primary">%s</button>', esc_html__( 'Enforce now', 'scrapelock' ) );
		echo '</form>';
	}

	/**
	 * While "Monitor only" is on: what would have been blocked so far, by reason, with a link to those entries
	 * in the Log tab and the "Enforce now" button. Once, after the first-week monitoring ended: blocking started.
	 */
	private static function monitor_notice() {
		$s = PNCP_Options::stored();
		if ( 'pending' === get_option( PNCP_Options::MONITOR_ENDED_OPTION ) ) {
			// Told once: marked as shown as soon as it is printed.
			update_option( PNCP_Options::MONITOR_ENDED_OPTION, 'shown', false );
			printf(
				'<div class="notice notice-info is-dismissible"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
				esc_html__( 'ScrapeLock now blocks.', 'scrapelock' ),
				esc_html(
					sprintf(
						/* translators: %d: number of days */
						__( 'The first %d days in “Monitor only” have ended: requests the settings refuse now get a 403 or 429. You can go back to “Monitor only” in “Bots and limits”.', 'scrapelock' ),
						PNCP_Options::MONITOR_DAYS
					)
				),
				esc_url( self::settings_url( array( 'tab' => 'log' ) ) ),
				esc_html__( 'See the log', 'scrapelock' )
			);
		}
		if ( empty( $s['enabled'] ) || ! PNCP_Options::monitoring( $s ) || ! self::notice_screen() ) {
			return;
		}
		// The first-week monitoring: since it started; turned on by hand: the last 7 days (the longest the log keeps by default).
		$hours   = ! empty( $s['monitor_until'] ) ? max( 1, (int) ceil( ( time() - ( (int) $s['monitor_until'] - PNCP_Options::MONITOR_DAYS * DAY_IN_SECONDS ) ) / HOUR_IN_SECONDS ) ) : 7 * 24;
		$summary = PNCP_Log::summary( $hours, 'monitor' );
		$labels  = PNCP_Log::reasons();
		echo '<div class="notice notice-warning pncp-monitor-notice"><p><strong>' . esc_html__( 'ScrapeLock is in “Monitor only”: nothing is blocked.', 'scrapelock' ) . '</strong> ';
		if ( ! empty( $s['monitor_until'] ) ) {
			echo esc_html(
				sprintf(
					/* translators: %s: date and time */
					__( 'It starts blocking on its own on %s.', 'scrapelock' ),
					wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $s['monitor_until'] )
				)
			) . ' ';
		}
		echo esc_html(
			sprintf(
				/* translators: %s: number of requests */
				_n( 'So far %s request would have been blocked.', 'So far %s requests would have been blocked.', (int) $summary['total'], 'scrapelock' ),
				number_format_i18n( $summary['total'] )
			)
		);
		echo '</p>';
		if ( $summary['reasons'] ) {
			echo '<ul class="ul-disc">';
			foreach ( array_slice( $summary['reasons'], 0, 8, true ) as $reason => $n ) {
				printf( '<li>%1$s: %2$s</li>', esc_html( isset( $labels[ $reason ] ) ? $labels[ $reason ] : $reason ), esc_html( number_format_i18n( $n ) ) );
			}
			echo '</ul>';
		}
		echo '<p>';
		printf(
			'<a href="%1$s">%2$s</a>',
			esc_url( self::log_url( 'monitor' ) ),
			esc_html__( 'See what would be blocked in the log', 'scrapelock' )
		);
		echo '</p>';
		self::enforce_form();
		echo '</div>';
	}

	/**
	 * Lasting notices (Emergency Mode, insecure proxy setting) appear only on the Dashboard and on the
	 * ScrapeLock settings page, not on every admin screen.
	 *
	 * @return bool
	 */
	public static function notice_screen() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		return $screen && in_array( $screen->id, array( 'dashboard', 'settings_page_' . PNCP_Admin::PAGE ), true );
	}

	/**
	 * Notices after actions, and a warning while Emergency Mode is running.
	 */
	public static function notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Only displays a notice.
		if ( isset( $_GET['pncp_toggled'] ) ) {
			$on = 'on' === sanitize_key( wp_unslash( $_GET['pncp_toggled'] ) );
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
				$on ? 'success' : 'warning',
				esc_html( $on ? __( 'ScrapeLock enabled.', 'scrapelock' ) : __( 'ScrapeLock disabled. The site is not protected.', 'scrapelock' ) )
			);
		}
		if ( isset( $_GET['pncp_emergency'] ) ) {
			$on = 'on' === sanitize_key( wp_unslash( $_GET['pncp_emergency'] ) );
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
				$on ? 'warning' : 'success',
				esc_html( $on ? __( 'Emergency Mode started.', 'scrapelock' ) : __( 'Emergency Mode stopped. Your normal settings apply again.', 'scrapelock' ) )
			);
		}
		if ( isset( $_GET['pncp_enforced'] ) ) {
			$on = 'on' === sanitize_key( wp_unslash( $_GET['pncp_enforced'] ) );
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
				$on ? 'success' : 'error',
				esc_html( $on ? __( '“Monitor only” is off: ScrapeLock now blocks.', 'scrapelock' ) : __( '“Monitor only” could not be turned off (the settings cannot change while the site is locked).', 'scrapelock' ) )
			);
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		self::monitor_notice();
		self::surge_notice();
		$until = PNCP_Options::emergency_until();
		if ( $until && self::is_enabled() && self::notice_screen() ) {
			printf(
				'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
				esc_html__( 'Emergency Mode is on.', 'scrapelock' ),
				esc_html(
					sprintf(
						/* translators: %s: date and time */
						__( 'Stricter limits apply until %s.', 'scrapelock' ),
						wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $until )
					)
				),
				esc_url( self::emergency_stop_url() ),
				esc_html__( 'End now', 'scrapelock' )
			);
		}
	}

	/**
	 * Dashboard widget.
	 */
	public static function add_widget() {
		if ( current_user_can( 'manage_options' ) ) {
			wp_add_dashboard_widget( 'pncp_status', __( 'ScrapeLock', 'scrapelock' ), array( __CLASS__, 'render_widget' ) );
		}
	}

	/**
	 * The active protection layers, for the widget.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array<string, bool>
	 */
	private static function layers( $s ) {
		return array(
			__( 'Copy / right click on the page', 'scrapelock' ) => ! empty( $s['block_selection'] ) || ! empty( $s['block_context_menu'] ) || 'block' === $s['copy_mode'],
			__( 'REST API / GraphQL without content', 'scrapelock' ) => ! empty( $s['rest_hide_content'] ),
			__( 'RSS excerpt only or disabled', 'scrapelock' ) => 'full' !== $s['feed_mode'],
			__( 'Blocking scrapers / AI bots', 'scrapelock' ) => ! empty( $s['block_bots'] ),
			__( 'Fake Googlebot / Bingbot', 'scrapelock' ) => ! empty( $s['block_fake_crawlers'] ),
			__( 'Bot trap', 'scrapelock' )                 => ! empty( $s['trap_enabled'] ),
			__( 'Pages per minute per IP', 'scrapelock' )  => (int) $s['rate_limit'] > 0,
			__( 'Protected feeds', 'scrapelock' )          => '' !== trim( (string) $s['private_paths'] ),
			__( 'No framing by other sites', 'scrapelock' ) => ! empty( $s['block_framing'] ),
			__( 'AI opt-out declaration (TDM)', 'scrapelock' ) => ! empty( $s['tdm_reservation'] ),
			__( 'Image watermark', 'scrapelock' )          => ! empty( $s['watermark_enabled'] ),
		);
	}

	/**
	 * Widget content.
	 */
	public static function render_widget() {
		$s       = PNCP_Options::get();
		$on      = ! empty( $s['enabled'] );
		$until   = PNCP_Options::emergency_until();
		$monitor = $on && PNCP_Options::monitoring( $s );
		// One SUM, kept for 5 minutes: the widget shows only the total (not the grouped summary).
		$total   = PNCP_Log::total( 24, $monitor ? 'monitor' : 'blocked' );
		?>
		<div class="pncp-widget">
			<p class="pncp-state <?php echo $on ? ( $until || $monitor ? 'is-emergency' : 'is-on' ) : 'is-off'; ?>">
				<span class="dashicons <?php echo $on ? 'dashicons-shield-alt' : 'dashicons-warning'; ?>" aria-hidden="true"></span>
				<strong>
				<?php
				if ( ! $on ) {
					esc_html_e( 'Protection is disabled', 'scrapelock' );
				} elseif ( $monitor ) {
					esc_html_e( 'Monitor only: nothing is blocked', 'scrapelock' );
				} elseif ( $until ) {
					esc_html_e( 'Emergency Mode is active', 'scrapelock' );
				} else {
					esc_html_e( 'The site is protected', 'scrapelock' );
				}
				?>
				</strong>
			</p>
			<?php if ( $on ) : ?>
				<p class="pncp-summary">
					<?php
					if ( $monitor ) {
						echo esc_html(
							sprintf(
								/* translators: %s: requests */
								__( 'Last 24 hours: %s requests would have been blocked', 'scrapelock' ),
								number_format_i18n( $total )
							)
						);
					} else {
						echo esc_html(
							sprintf(
								/* translators: 1: requests, 2: active bans */
								__( 'Last 24 hours: %1$s blocked requests · %2$s IPs blocked now', 'scrapelock' ),
								number_format_i18n( $total ),
								number_format_i18n( PNCP_Log::count_bans() )
							)
						);
					}
					?>
				</p>
				<ul class="pncp-layers">
					<?php foreach ( self::layers( $s ) as $label => $active ) : ?>
						<li>
							<span class="dashicons <?php echo $active ? 'dashicons-yes' : 'dashicons-minus'; ?>" aria-hidden="true"></span>
							<?php echo esc_html( $label ); ?>
							<span class="screen-reader-text"><?php echo esc_html( $active ? __( '(on)', 'scrapelock' ) : __( '(off)', 'scrapelock' ) ); ?></span>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
			<p class="pncp-actions">
				<?php if ( $on ) : ?>
					<a class="button" href="<?php echo esc_url( self::disable_url() ); ?>"><?php esc_html_e( 'Disable…', 'scrapelock' ); ?></a>
				<?php else : ?>
					<a class="button button-primary" href="<?php echo esc_url( self::enable_url() ); ?>"><?php esc_html_e( 'Enable', 'scrapelock' ); ?></a>
				<?php endif; ?>
				<a href="<?php echo esc_url( self::settings_url() ); ?>"><?php esc_html_e( 'Settings', 'scrapelock' ); ?></a>
				<a href="<?php echo esc_url( self::settings_url( array( 'tab' => 'log' ) ) ); ?>"><?php esc_html_e( 'Log', 'scrapelock' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Button in the admin bar (top bar), in both admin and the front end.
	 *
	 * @param WP_Admin_Bar $bar The admin bar.
	 */
	public static function admin_bar( $bar ) {
		// Administrators keep the button while the site is locked: it leads to the Lockdown tab.
		if ( ! PNCP_Lockdown::can( 'manage_options' ) ) {
			return;
		}
		$on        = self::is_enabled();
		$emergency = $on && PNCP_Options::emergency_until();
		$locked    = PNCP_Lockdown::is_locked();
		$monitor   = $on && PNCP_Options::monitoring();
		if ( $monitor ) {
			$label = __( 'Protection: MONITOR ONLY', 'scrapelock' );
		} elseif ( $emergency ) {
			$label = __( 'Protection: EMERGENCY', 'scrapelock' );
		} else {
			$label = $on ? __( 'Protection: ON', 'scrapelock' ) : __( 'Protection: OFF', 'scrapelock' );
		}
		if ( $locked ) {
			$label .= ' · ' . __( 'Locked', 'scrapelock' );
		}

		$bar->add_node(
			array(
				'id'    => 'pncp-status',
				'title' => '<span class="ab-icon dashicons ' . ( $on ? 'dashicons-shield-alt' : 'dashicons-warning' ) . '" aria-hidden="true"></span><span class="ab-label">' . esc_html( $label ) . '</span>',
				'href'  => $locked ? PNCP_Lockdown::page_url() : self::settings_url(),
				'meta'  => array(
					'class' => $monitor || $emergency ? 'pncp-emergency' : ( $on ? 'pncp-on' : 'pncp-off' ),
					'title' => $monitor ? __( 'Monitor only: nothing is blocked', 'scrapelock' ) : ( $on ? __( 'The site is protected', 'scrapelock' ) : __( 'Protection is disabled', 'scrapelock' ) ),
				),
			)
		);
		$lockdown = array(
			'parent' => 'pncp-status',
			'id'     => 'pncp-lockdown',
			'title'  => '<span class="ab-icon dashicons dashicons-' . ( $locked ? 'lock' : 'unlock' ) . '" aria-hidden="true"></span>' . esc_html__( 'Lockdown', 'scrapelock' ),
			'href'   => PNCP_Lockdown::page_url(),
		);
		if ( $locked ) {
			// Nothing else can be changed while locked.
			$bar->add_node( $lockdown );
			return;
		}
		$bar->add_node(
			array(
				'parent' => 'pncp-status',
				'id'     => 'pncp-toggle',
				'title'  => esc_html( $on ? __( 'Disable…', 'scrapelock' ) : __( 'Enable', 'scrapelock' ) ),
				'href'   => $on ? self::disable_url() : self::enable_url(),
			)
		);
		if ( $emergency ) {
			$bar->add_node(
				array(
					'parent' => 'pncp-status',
					'id'     => 'pncp-emergency-stop',
					'title'  => esc_html__( 'End Emergency Mode', 'scrapelock' ),
					'href'   => self::emergency_stop_url(),
				)
			);
		}
		$bar->add_node(
			array(
				'parent' => 'pncp-status',
				'id'     => 'pncp-settings',
				'title'  => esc_html__( 'Settings', 'scrapelock' ),
				'href'   => self::settings_url(),
			)
		);
		$bar->add_node( $lockdown );
	}

	/**
	 * Colors for the button and the widget (green = ON, red = OFF, orange = Emergency).
	 */
	public static function admin_bar_css() {
		if ( ! is_admin_bar_showing() || ! PNCP_Lockdown::can( 'manage_options' ) ) {
			return;
		}
		$css = '#wpadminbar #wp-admin-bar-pncp-status .ab-icon:before{top:2px}'
			// The lock in the drop-down sits on the text line, centred with "Lockdown".
			. '#wpadminbar #wp-admin-bar-pncp-lockdown>.ab-item{display:flex;align-items:center;gap:6px}'
			. '#wpadminbar #wp-admin-bar-pncp-status #wp-admin-bar-pncp-lockdown .ab-icon{float:none;display:block;width:16px;height:16px;margin:0!important;padding:0!important}'
			. '#wpadminbar #wp-admin-bar-pncp-lockdown .ab-icon:before{display:block;top:0;padding:0;font-size:16px;line-height:16px;width:16px;height:16px}'
			. '#wpadminbar #wp-admin-bar-pncp-status.pncp-on>.ab-item .ab-icon:before{color:#46b450}'
			. '#wpadminbar #wp-admin-bar-pncp-status.pncp-off>.ab-item{background:#b32d2e;color:#fff}'
			. '#wpadminbar #wp-admin-bar-pncp-status.pncp-emergency>.ab-item{background:#9a4a00;color:#fff}'
			. '#wpadminbar #wp-admin-bar-pncp-status.pncp-off>.ab-item .ab-icon:before,#wpadminbar #wp-admin-bar-pncp-status.pncp-emergency>.ab-item .ab-icon:before{color:#fff}'
			. '.pncp-widget .pncp-state{display:flex;align-items:center;gap:6px;margin:0 0 10px;padding:10px 12px;border-radius:4px;font-size:14px}'
			. '.pncp-widget .pncp-state.is-on{background:#edfaef;color:#1e4620}'
			. '.pncp-widget .pncp-state.is-off{background:#fcf0f1;color:#8a2424}'
			. '.pncp-widget .pncp-state.is-emergency{background:#fcf3e6;color:#6b3500}'
			. '.pncp-widget .pncp-summary{margin:0 0 8px;color:#3c434a}'
			. '.pncp-widget .pncp-layers{margin:0 0 12px}'
			. '.pncp-widget .pncp-layers li{display:flex;align-items:center;gap:4px;margin:2px 0}'
			. '.pncp-widget .pncp-layers .dashicons-yes{color:#1a7f37}'
			. '.pncp-widget .pncp-layers .dashicons-minus{color:#8c8f94}'
			. '.pncp-widget .pncp-actions{display:flex;align-items:center;gap:12px;margin:0;flex-wrap:wrap}'
			. '@media screen and (max-width:782px){#wpadminbar #wp-toolbar>ul>li#wp-admin-bar-pncp-status{display:block}'
			. '#wpadminbar #wp-admin-bar-pncp-status>.ab-item{width:52px;text-align:center;padding:0}'
			. '#wpadminbar #wp-admin-bar-pncp-status .ab-icon{margin:0;padding:0}'
			. '#wpadminbar #wp-admin-bar-pncp-status .ab-icon:before{font-size:32px;line-height:46px;top:0}'
			. '#wpadminbar #wp-admin-bar-pncp-status .ab-label{display:none}}';
		wp_add_inline_style( 'admin-bar', $css );
	}
}
