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
		PNCP_Options::set_emergency( $hours );
		wp_safe_redirect( self::settings_url( array( 'pncp_emergency' => $hours ? 'on' : 'off' ) ) );
		exit;
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
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
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
		$summary = PNCP_Log::summary( 24 );
		?>
		<div class="pncp-widget">
			<p class="pncp-state <?php echo $on ? ( $until ? 'is-emergency' : 'is-on' ) : 'is-off'; ?>">
				<span class="dashicons <?php echo $on ? 'dashicons-shield-alt' : 'dashicons-warning'; ?>" aria-hidden="true"></span>
				<strong>
				<?php
				if ( ! $on ) {
					esc_html_e( 'Protection is disabled', 'scrapelock' );
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
					echo esc_html(
						sprintf(
							/* translators: 1: requests, 2: active bans */
							__( 'Last 24 hours: %1$s blocked requests · %2$s IPs blocked now', 'scrapelock' ),
							number_format_i18n( $summary['total'] ),
							number_format_i18n( PNCP_Log::count_bans() )
						)
					);
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
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$on        = self::is_enabled();
		$emergency = $on && PNCP_Options::emergency_until();
		if ( $emergency ) {
			$label = __( 'Protection: EMERGENCY', 'scrapelock' );
		} else {
			$label = $on ? __( 'Protection: ON', 'scrapelock' ) : __( 'Protection: OFF', 'scrapelock' );
		}

		$bar->add_node(
			array(
				'id'    => 'pncp-status',
				'title' => '<span class="ab-icon dashicons ' . ( $on ? 'dashicons-shield-alt' : 'dashicons-warning' ) . '" aria-hidden="true"></span><span class="ab-label">' . esc_html( $label ) . '</span>',
				'href'  => self::settings_url(),
				'meta'  => array(
					'class' => $emergency ? 'pncp-emergency' : ( $on ? 'pncp-on' : 'pncp-off' ),
					'title' => $on ? __( 'The site is protected', 'scrapelock' ) : __( 'Protection is disabled', 'scrapelock' ),
				),
			)
		);
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
	}

	/**
	 * Colors for the button and the widget (green = ON, red = OFF, orange = Emergency).
	 */
	public static function admin_bar_css() {
		if ( ! is_admin_bar_showing() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$css = '#wpadminbar #wp-admin-bar-pncp-status .ab-icon:before{top:2px}'
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
