<?php
/**
 * Ένδειξη κατάστασης: widget στον Πίνακα ελέγχου και κουμπί στη γραμμή διαχείρισης,
 * με ενεργοποίηση/απενεργοποίηση με ένα κλικ.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Κατάσταση προστασίας και γρήγορος διακόπτης.
 */
final class PNCP_Status {

	const ACTION = 'pncp_toggle';

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
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_filter( 'removable_query_args', array( __CLASS__, 'removable_args' ) );
	}

	/**
	 * Το WordPress σβήνει το pncp_toggled από τη γραμμή διευθύνσεων μετά το μήνυμα.
	 *
	 * @param string[] $args Παράμετροι.
	 * @return string[]
	 */
	public static function removable_args( $args ) {
		$args[] = 'pncp_toggled';
		return $args;
	}

	/**
	 * onclick με επιβεβαίωση, μόνο για την απενεργοποίηση.
	 *
	 * @param bool $on Αν η προστασία είναι τώρα ενεργή.
	 * @return string
	 */
	private static function confirm_attr( $on ) {
		if ( ! $on ) {
			return '';
		}
		return ' onclick="return confirm(\'' . esc_js( __( 'Να απενεργοποιηθεί η προστασία σε όλο το site;', 'content-protect' ) ) . '\');"';
	}

	/**
	 * Είναι ενεργή η προστασία;
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return ! empty( PNCP_Options::get()['enabled'] );
	}

	/**
	 * URL του διακόπτη (με nonce), που επιστρέφει στην τρέχουσα σελίδα.
	 *
	 * @return string
	 */
	private static function toggle_url() {
		$back = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : admin_url();
		return wp_nonce_url(
			add_query_arg(
				array(
					'action'   => self::ACTION,
					'redirect' => rawurlencode( $back ),
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION
		);
	}

	/**
	 * Ενεργοποίηση/απενεργοποίηση. Μόνο διαχειριστές, με nonce.
	 */
	public static function handle_toggle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Δεν έχετε δικαίωμα να αλλάξετε αυτή τη ρύθμιση.', 'content-protect' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		$settings            = PNCP_Options::get();
		$settings['enabled'] = empty( $settings['enabled'] ) ? 1 : 0;
		update_option( PNCP_OPTION, $settings ); // Αδειάζει και την cache (update_option_pncp_settings).

		// Το PHP έχει ήδη αποκωδικοποιήσει το $_GET μία φορά· όχι sanitize_text_field (σβήνει τα %XX των ελληνικών URLs).
		$redirect = isset( $_GET['redirect'] ) ? esc_url_raw( wp_unslash( $_GET['redirect'] ) ) : '';
		$redirect = wp_validate_redirect( $redirect, admin_url() );
		// Το μήνυμα φαίνεται μόνο στο wp-admin, οπότε μόνο εκεί προσθέτουμε την παράμετρο.
		if ( false !== strpos( $redirect, '/wp-admin/' ) ) {
			$redirect = add_query_arg( 'pncp_toggled', $settings['enabled'] ? 'on' : 'off', $redirect );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Μήνυμα μετά τον διακόπτη.
	 */
	public static function notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Μόνο εμφάνιση μηνύματος.
		if ( ! isset( $_GET['pncp_toggled'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$on = 'on' === sanitize_key( wp_unslash( $_GET['pncp_toggled'] ) );
		printf(
			'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
			$on ? 'success' : 'warning',
			esc_html( $on ? __( 'Η προστασία περιεχομένου ενεργοποιήθηκε.', 'content-protect' ) : __( 'Η προστασία περιεχομένου απενεργοποιήθηκε. Το site δεν προστατεύεται.', 'content-protect' ) )
		);
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
			__( 'REST API χωρίς κείμενο', 'content-protect' )           => ! empty( $s['rest_hide_content'] ),
			__( 'RSS μόνο περίληψη ή κλειστό', 'content-protect' )      => 'full' !== $s['feed_mode'],
			__( 'Μπλοκάρισμα scrapers / AI bots', 'content-protect' )   => ! empty( $s['block_bots'] ),
			__( 'Όριο σελίδων ανά IP', 'content-protect' )             => (int) $s['rate_limit'] > 0,
			__( 'Ιδιωτικά URLs (XML feeds)', 'content-protect' )      => '' !== trim( (string) $s['private_paths'] ),
			__( 'Υδατογράφημα νέων εικόνων', 'content-protect' )       => ! empty( $s['watermark_enabled'] ),
		);
	}

	/**
	 * Περιεχόμενο του widget.
	 */
	public static function render_widget() {
		$s  = PNCP_Options::get();
		$on = ! empty( $s['enabled'] );
		?>
		<div class="pncp-widget">
			<p class="pncp-state <?php echo $on ? 'is-on' : 'is-off'; ?>">
				<span class="dashicons <?php echo $on ? 'dashicons-shield-alt' : 'dashicons-warning'; ?>" aria-hidden="true"></span>
				<strong><?php echo esc_html( $on ? __( 'Το site προστατεύεται', 'content-protect' ) : __( 'Η προστασία είναι απενεργοποιημένη', 'content-protect' ) ); ?></strong>
			</p>
			<?php if ( $on ) : ?>
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
				<a class="button <?php echo $on ? '' : 'button-primary'; ?>" href="<?php echo esc_url( self::toggle_url() ); ?>"<?php echo self::confirm_attr( $on ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped με esc_js. ?>>
					<?php echo esc_html( $on ? __( 'Απενεργοποίηση', 'content-protect' ) : __( 'Ενεργοποίηση', 'content-protect' ) ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'options-general.php?page=' . self::SETTINGS_PAGE ) ); ?>"><?php esc_html_e( 'Ρυθμίσεις', 'content-protect' ); ?></a>
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
		$on = self::is_enabled();

		$bar->add_node(
			array(
				'id'    => 'pncp-status',
				'title' => '<span class="ab-icon dashicons ' . ( $on ? 'dashicons-shield-alt' : 'dashicons-warning' ) . '" aria-hidden="true"></span><span class="ab-label">' . esc_html( $on ? __( 'Προστασία: ON', 'content-protect' ) : __( 'Προστασία: OFF', 'content-protect' ) ) . '</span>',
				'href'  => admin_url( 'options-general.php?page=' . self::SETTINGS_PAGE ),
				'meta'  => array(
					'class' => $on ? 'pncp-on' : 'pncp-off',
					'title' => $on ? __( 'Το site προστατεύεται', 'content-protect' ) : __( 'Η προστασία είναι απενεργοποιημένη', 'content-protect' ),
				),
			)
		);
		$bar->add_node(
			array(
				'parent' => 'pncp-status',
				'id'     => 'pncp-toggle',
				'title'  => esc_html( $on ? __( 'Απενεργοποίηση', 'content-protect' ) : __( 'Ενεργοποίηση', 'content-protect' ) ),
				'href'   => self::toggle_url(),
				'meta'   => $on ? array( 'onclick' => 'return confirm(\'' . esc_js( __( 'Να απενεργοποιηθεί η προστασία σε όλο το site;', 'content-protect' ) ) . '\');' ) : array(),
			)
		);
		$bar->add_node(
			array(
				'parent' => 'pncp-status',
				'id'     => 'pncp-settings',
				'title'  => esc_html__( 'Ρυθμίσεις', 'content-protect' ),
				'href'   => admin_url( 'options-general.php?page=' . self::SETTINGS_PAGE ),
			)
		);
	}

	/**
	 * Χρώματα για το κουμπί και το widget (πράσινο = ON, πορτοκαλί = OFF).
	 */
	public static function admin_bar_css() {
		if ( ! is_admin_bar_showing() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$css = '#wpadminbar #wp-admin-bar-pncp-status .ab-icon:before{top:2px}'
			. '#wpadminbar #wp-admin-bar-pncp-status.pncp-on>.ab-item .ab-icon:before{color:#46b450}'
			. '#wpadminbar #wp-admin-bar-pncp-status.pncp-off>.ab-item{background:#b32d2e;color:#fff}'
			. '#wpadminbar #wp-admin-bar-pncp-status.pncp-off>.ab-item .ab-icon:before{color:#fff}'
			. '.pncp-widget .pncp-state{display:flex;align-items:center;gap:6px;margin:0 0 10px;padding:10px 12px;border-radius:4px;font-size:14px}'
			. '.pncp-widget .pncp-state.is-on{background:#edfaef;color:#1e4620}'
			. '.pncp-widget .pncp-state.is-off{background:#fcf0f1;color:#8a2424}'
			. '.pncp-widget .pncp-layers{margin:0 0 12px}'
			. '.pncp-widget .pncp-layers li{display:flex;align-items:center;gap:4px;margin:2px 0}'
			. '.pncp-widget .pncp-layers .dashicons-yes{color:#1a7f37}'
			. '.pncp-widget .pncp-layers .dashicons-minus{color:#8c8f94}'
			. '.pncp-widget .pncp-actions{display:flex;align-items:center;gap:12px;margin:0}'
			. '@media screen and (max-width:782px){#wpadminbar #wp-toolbar>ul>li#wp-admin-bar-pncp-status{display:block}'
			. '#wpadminbar #wp-admin-bar-pncp-status>.ab-item{width:52px;text-align:center;padding:0}'
			. '#wpadminbar #wp-admin-bar-pncp-status .ab-icon{margin:0;padding:0}'
			. '#wpadminbar #wp-admin-bar-pncp-status .ab-icon:before{font-size:32px;line-height:46px;top:0}'
			. '#wpadminbar #wp-admin-bar-pncp-status .ab-label{display:none}}';
		wp_add_inline_style( 'admin-bar', $css );
	}
}
