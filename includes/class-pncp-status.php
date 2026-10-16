<?php
/**
 * Ένδειξη κατάστασης: widget στον Πίνακα ελέγχου (με σύνοψη 24ώρου) και κουμπί στη γραμμή διαχείρισης.
 * Ενεργοποίηση με ένα κλικ, απενεργοποίηση μόνο μετά από επιβεβαίωση, Emergency Mode.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Κατάσταση προστασίας, διακόπτης και Emergency Mode.
 */
final class PNCP_Status {

	const ACTION    = 'pncp_toggle';
	const EMERGENCY = 'pncp_emergency';

	// Ίδιο με το PNCP_Admin::PAGE· η κλάση του admin δεν φορτώνεται στο δημόσιο site, όπου φαίνεται η μπάρα.
	const SETTINGS_PAGE = 'content-protect';

	/**
	 * Δένει τα hooks.
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
	 * Το WordPress σβήνει τις παραμέτρους μας από τη γραμμή διευθύνσεων μετά το μήνυμα.
	 *
	 * @param string[] $args Παράμετροι.
	 * @return string[]
	 */
	public static function removable_args( $args ) {
		$args[] = 'pncp_toggled';
		$args[] = 'pncp_emergency';
		$args[] = 'pncp_confirm';
		return $args;
	}

	/**
	 * Είναι ενεργή η προστασία;
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return ! empty( PNCP_Options::stored()['enabled'] );
	}

	/**
	 * Η σελίδα ρυθμίσεων.
	 *
	 * @param array<string, string> $args Παράμετροι.
	 * @return string
	 */
	public static function settings_url( $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::SETTINGS_PAGE ), $args ), admin_url( 'options-general.php' ) );
	}

	/**
	 * URL ενεργοποίησης (με nonce), που επιστρέφει στην τρέχουσα σελίδα.
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
	 * Η απενεργοποίηση πηγαίνει πάντα σε σελίδα επιβεβαίωσης (δεν αρκεί ένα κλικ στη μπάρα).
	 *
	 * @return string
	 */
	public static function disable_url() {
		return self::settings_url( array( 'pncp_confirm' => 'disable' ) );
	}

	/**
	 * Τερματισμός του Emergency Mode (με nonce).
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
	 * Ενεργοποίηση (GET με nonce) ή απενεργοποίηση (μόνο POST, από τη φόρμα επιβεβαίωσης). Μόνο διαχειριστές.
	 */
	public static function handle_toggle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Δεν έχετε δικαίωμα να αλλάξετε αυτή τη ρύθμιση.', 'content-protect' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Ελέγχθηκε παραπάνω.
		$state  = isset( $_REQUEST['state'] ) ? sanitize_key( wp_unslash( $_REQUEST['state'] ) ) : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'off' === $state && 'POST' !== $method ) {
			wp_safe_redirect( self::disable_url() );
			exit;
		}
		if ( ! in_array( $state, array( 'on', 'off' ), true ) ) {
			wp_die( esc_html__( 'Άκυρο αίτημα.', 'content-protect' ), '', array( 'response' => 400 ) );
		}

		$settings            = PNCP_Options::stored();
		$settings['enabled'] = 'on' === $state ? 1 : 0;
		update_option( PNCP_OPTION, $settings ); // Αδειάζει και την cache (update_option_pncp_settings).
		PNCP_Options::flush();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Ελέγχθηκε παραπάνω. Όχι sanitize_text_field (σβήνει τα %XX των ελληνικών URLs).
		$redirect = isset( $_REQUEST['redirect'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect'] ) ) : '';
		$redirect = wp_validate_redirect( $redirect, admin_url() );
		if ( '' === $redirect || false !== strpos( $redirect, 'pncp_confirm=' ) ) {
			$redirect = self::settings_url();
		}
		// Το μήνυμα φαίνεται μόνο στο wp-admin, οπότε μόνο εκεί προσθέτουμε την παράμετρο.
		if ( false !== strpos( $redirect, '/wp-admin/' ) ) {
			$redirect = add_query_arg( 'pncp_toggled', $settings['enabled'] ? 'on' : 'off', $redirect );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Έναρξη (POST, με διάρκεια) ή τέλος (GET/POST με nonce) του Emergency Mode.
	 */
	public static function handle_emergency() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Δεν έχετε δικαίωμα να αλλάξετε αυτή τη ρύθμιση.', 'content-protect' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::EMERGENCY );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Ελέγχθηκε παραπάνω.
		$hours = isset( $_REQUEST['hours'] ) ? absint( $_REQUEST['hours'] ) : 0;
		if ( ! in_array( $hours, array( 0, 1, 6, 24, 72 ), true ) ) {
			$hours = 24;
		}
		PNCP_Options::set_emergency( $hours );
		wp_safe_redirect( self::settings_url( array( 'pncp_emergency' => $hours ? 'on' : 'off' ) ) );
		exit;
	}

	/**
	 * Μηνύματα μετά τις ενέργειες και προειδοποίηση όσο τρέχει το Emergency Mode.
	 */
	public static function notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Μόνο εμφάνιση μηνύματος.
		if ( isset( $_GET['pncp_toggled'] ) ) {
			$on = 'on' === sanitize_key( wp_unslash( $_GET['pncp_toggled'] ) );
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
				$on ? 'success' : 'warning',
				esc_html( $on ? __( 'Η προστασία περιεχομένου ενεργοποιήθηκε.', 'content-protect' ) : __( 'Η προστασία περιεχομένου απενεργοποιήθηκε. Το site δεν προστατεύεται.', 'content-protect' ) )
			);
		}
		if ( isset( $_GET['pncp_emergency'] ) ) {
			$on = 'on' === sanitize_key( wp_unslash( $_GET['pncp_emergency'] ) );
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
				$on ? 'warning' : 'success',
				esc_html( $on ? __( 'Το Emergency Mode ξεκίνησε.', 'content-protect' ) : __( 'Το Emergency Mode σταμάτησε. Ισχύουν ξανά οι κανονικές ρυθμίσεις.', 'content-protect' ) )
			);
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		$until = PNCP_Options::emergency_until();
		if ( $until && self::is_enabled() ) {
			printf(
				'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
				esc_html__( 'Emergency Mode σε λειτουργία.', 'content-protect' ),
				esc_html(
					sprintf(
						/* translators: %s: ημερομηνία και ώρα */
						__( 'Ισχύουν αυστηρότερα όρια μέχρι %s.', 'content-protect' ),
						wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $until )
					)
				),
				esc_url( self::emergency_stop_url() ),
				esc_html__( 'Τέλος τώρα', 'content-protect' )
			);
		}
	}

	/**
	 * Widget στον Πίνακα ελέγχου.
	 */
	public static function add_widget() {
		if ( current_user_can( 'manage_options' ) ) {
			wp_add_dashboard_widget( 'pncp_status', __( 'Προστασία περιεχομένου', 'content-protect' ), array( __CLASS__, 'render_widget' ) );
		}
	}

	/**
	 * Τα ενεργά επίπεδα προστασίας, για το widget.
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 * @return array<string, bool>
	 */
	private static function layers( $s ) {
		return array(
			__( 'Αντιγραφή / δεξί κλικ στη σελίδα', 'content-protect' ) => ! empty( $s['block_selection'] ) || ! empty( $s['block_context_menu'] ) || 'block' === $s['copy_mode'],
			__( 'REST API / GraphQL χωρίς κείμενο', 'content-protect' ) => ! empty( $s['rest_hide_content'] ),
			__( 'RSS μόνο περίληψη ή κλειστό', 'content-protect' ) => 'full' !== $s['feed_mode'],
			__( 'Μπλοκάρισμα scrapers / AI bots', 'content-protect' ) => ! empty( $s['block_bots'] ),
			__( 'Ψεύτικα Googlebot / Bingbot', 'content-protect' ) => ! empty( $s['block_fake_crawlers'] ),
			__( 'Παγίδα για bots', 'content-protect' )     => ! empty( $s['trap_enabled'] ),
			__( 'Όριο σελίδων ανά IP', 'content-protect' ) => (int) $s['rate_limit'] > 0,
			__( 'Προστατευμένα feeds', 'content-protect' ) => '' !== trim( (string) $s['private_paths'] ),
			__( 'Όχι μέσα σε iframe ξένου site', 'content-protect' ) => ! empty( $s['block_framing'] ),
			__( 'Δήλωση εξαίρεσης από AI (TDM)', 'content-protect' ) => ! empty( $s['tdm_reservation'] ),
			__( 'Υδατογράφημα εικόνων', 'content-protect' ) => ! empty( $s['watermark_enabled'] ),
		);
	}

	/**
	 * Περιεχόμενο του widget.
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
					esc_html_e( 'Η προστασία είναι απενεργοποιημένη', 'content-protect' );
				} elseif ( $until ) {
					esc_html_e( 'Emergency Mode σε λειτουργία', 'content-protect' );
				} else {
					esc_html_e( 'Το site προστατεύεται', 'content-protect' );
				}
				?>
				</strong>
			</p>
			<?php if ( $on ) : ?>
				<p class="pncp-summary">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: αιτήματα, 2: ενεργοί αποκλεισμοί */
							__( 'Τελευταίες 24 ώρες: %1$s μπλοκαρισμένα αιτήματα · %2$s αποκλεισμένες IP τώρα', 'content-protect' ),
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
							<span class="screen-reader-text"><?php echo esc_html( $active ? __( '(ενεργό)', 'content-protect' ) : __( '(ανενεργό)', 'content-protect' ) ); ?></span>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
			<p class="pncp-actions">
				<?php if ( $on ) : ?>
					<a class="button" href="<?php echo esc_url( self::disable_url() ); ?>"><?php esc_html_e( 'Απενεργοποίηση…', 'content-protect' ); ?></a>
				<?php else : ?>
					<a class="button button-primary" href="<?php echo esc_url( self::enable_url() ); ?>"><?php esc_html_e( 'Ενεργοποίηση', 'content-protect' ); ?></a>
				<?php endif; ?>
				<a href="<?php echo esc_url( self::settings_url() ); ?>"><?php esc_html_e( 'Ρυθμίσεις', 'content-protect' ); ?></a>
				<a href="<?php echo esc_url( self::settings_url( array( 'tab' => 'log' ) ) ); ?>"><?php esc_html_e( 'Αρχείο', 'content-protect' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Κουμπί στη γραμμή διαχείρισης (πάνω μπάρα), σε admin και site.
	 *
	 * @param WP_Admin_Bar $bar Η μπάρα.
	 */
	public static function admin_bar( $bar ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$on        = self::is_enabled();
		$emergency = $on && PNCP_Options::emergency_until();
		if ( $emergency ) {
			$label = __( 'Προστασία: EMERGENCY', 'content-protect' );
		} else {
			$label = $on ? __( 'Προστασία: ON', 'content-protect' ) : __( 'Προστασία: OFF', 'content-protect' );
		}

		$bar->add_node(
			array(
				'id'    => 'pncp-status',
				'title' => '<span class="ab-icon dashicons ' . ( $on ? 'dashicons-shield-alt' : 'dashicons-warning' ) . '" aria-hidden="true"></span><span class="ab-label">' . esc_html( $label ) . '</span>',
				'href'  => self::settings_url(),
				'meta'  => array(
					'class' => $emergency ? 'pncp-emergency' : ( $on ? 'pncp-on' : 'pncp-off' ),
					'title' => $on ? __( 'Το site προστατεύεται', 'content-protect' ) : __( 'Η προστασία είναι απενεργοποιημένη', 'content-protect' ),
				),
			)
		);
		$bar->add_node(
			array(
				'parent' => 'pncp-status',
				'id'     => 'pncp-toggle',
				'title'  => esc_html( $on ? __( 'Απενεργοποίηση…', 'content-protect' ) : __( 'Ενεργοποίηση', 'content-protect' ) ),
				'href'   => $on ? self::disable_url() : self::enable_url(),
			)
		);
		if ( $emergency ) {
			$bar->add_node(
				array(
					'parent' => 'pncp-status',
					'id'     => 'pncp-emergency-stop',
					'title'  => esc_html__( 'Τέλος Emergency Mode', 'content-protect' ),
					'href'   => self::emergency_stop_url(),
				)
			);
		}
		$bar->add_node(
			array(
				'parent' => 'pncp-status',
				'id'     => 'pncp-settings',
				'title'  => esc_html__( 'Ρυθμίσεις', 'content-protect' ),
				'href'   => self::settings_url(),
			)
		);
	}

	/**
	 * Χρώματα για το κουμπί και το widget (πράσινο = ON, κόκκινο = OFF, πορτοκαλί = Emergency).
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
