<?php
/**
 * Σελίδα ρυθμίσεων στο wp-admin (Ρυθμίσεις → Προστασία περιεχομένου), με καρτέλες.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Admin UI. Οι ρυθμίσεις περνούν από το Settings API (nonce και capability τα ελέγχει το options.php).
 * Οι ενέργειες (προφίλ, token, αποκλεισμοί, εργαλείο εικόνων) περνούν από admin-post / AJAX με nonce.
 */
final class PNCP_Admin {

	const PAGE  = 'content-protect';
	const GROUP = 'pncp_settings_group';

	/**
	 * Δένει τα hooks.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( PNCP_FILE ), array( __CLASS__, 'action_links' ) );
		add_action( 'admin_post_pncp_profile', array( __CLASS__, 'handle_profile' ) );
		add_action( 'admin_post_pncp_token', array( __CLASS__, 'handle_token' ) );
		add_action( 'admin_post_pncp_log', array( __CLASS__, 'handle_log' ) );
		add_action( 'wp_ajax_pncp_wm_batch', array( __CLASS__, 'ajax_wm_batch' ) );
		add_action( 'admin_notices', array( __CLASS__, 'upgrade_notices' ) );
	}

	/**
	 * Εγγραφή στο μενού Ρυθμίσεις.
	 */
	public static function menu() {
		add_options_page(
			__( 'Προστασία περιεχομένου', 'content-protect' ),
			__( 'Προστασία περιεχομένου', 'content-protect' ),
			'manage_options',
			self::PAGE,
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * Εγγραφή του option στο Settings API.
	 */
	public static function register() {
		register_setting(
			self::GROUP,
			PNCP_OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'PNCP_Options', 'sanitize' ),
				'default'           => PNCP_Options::defaults(),
				'show_in_rest'      => false,
			)
		);
	}

	/**
	 * CSS και JS μόνο στη σελίδα του plugin.
	 *
	 * @param string $hook Σελίδα.
	 */
	public static function assets( $hook ) {
		if ( 'settings_page_' . self::PAGE !== $hook ) {
			return;
		}
		wp_enqueue_style( 'pncp-admin', PNCP_URL . 'assets/css/admin.css', array(), PNCP_VERSION );
		wp_enqueue_script( 'pncp-admin', PNCP_URL . 'assets/js/admin.js', array(), PNCP_VERSION, true );
		wp_localize_script(
			'pncp-admin',
			'pncpAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'pncp_wm_batch' ),
				'i18n'    => array(
					'confirmApply'  => __( 'Θα ξαναφτιαχτούν όλες οι εικόνες της βιβλιοθήκης με υδατογράφημα. Έχετε backup του φακέλου uploads; Συνέχεια;', 'content-protect' ),
					'confirmRemove' => __( 'Θα αφαιρεθεί το υδατογράφημα από όλες τις εικόνες. Συνέχεια;', 'content-protect' ),
					/* translators: 1: εικόνες που έγιναν, 2: σύνολο */
					'progress'      => __( 'Επεξεργάστηκαν %1$s από %2$s εικόνες…', 'content-protect' ),
					/* translators: 1: σύνολο εικόνων, 2: σφάλματα */
					'done'          => __( 'Ολοκληρώθηκε: %1$s εικόνες. Σφάλματα: %2$s.', 'content-protect' ),
					'error'         => __( 'Διακοπή λόγω σφάλματος. Πατήστε ξανά το κουμπί για να συνεχίσει από εκεί που σταμάτησε.', 'content-protect' ),
					'copied'        => __( 'Αντιγράφηκε', 'content-protect' ),
				),
			)
		);
	}

	/**
	 * Σύνδεσμος «Ρυθμίσεις» στη λίστα πρόσθετων.
	 *
	 * @param string[] $links Σύνδεσμοι.
	 * @return string[]
	 */
	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( PNCP_Status::settings_url() ) . '">' . esc_html__( 'Ρυθμίσεις', 'content-protect' ) . '</a>' );
		return $links;
	}

	/**
	 * Οι καρτέλες.
	 *
	 * @return array<string, string>
	 */
	private static function tabs() {
		return array(
			'general' => __( 'Στη σελίδα', 'content-protect' ),
			'bots'    => __( 'Bots και όρια', 'content-protect' ),
			'content' => __( 'Feeds και API', 'content-protect' ),
			'images'  => __( 'Εικόνες', 'content-protect' ),
			'rules'   => __( 'Κανόνες server', 'content-protect' ),
			'log'     => __( 'Αρχείο', 'content-protect' ),
		);
	}

	/**
	 * Η τρέχουσα καρτέλα.
	 *
	 * @return string
	 */
	private static function current_tab() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Μόνο επιλογή καρτέλας.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'general';
		return array_key_exists( $tab, self::tabs() ) ? $tab : 'general';
	}

	/* ---------- Πεδία ---------- */

	/**
	 * Checkbox γραμμή.
	 *
	 * @param array<string, mixed> $s     Ρυθμίσεις.
	 * @param string               $key   Κλειδί.
	 * @param string               $label Κείμενο.
	 * @param string               $help  Βοήθεια (προαιρετικό).
	 */
	private static function checkbox( $s, $key, $label, $help = '' ) {
		$id = 'pncp-' . $key;
		printf(
			'<label for="%1$s"><input type="checkbox" id="%1$s" name="%2$s[%3$s]" value="1"%4$s%5$s> %6$s</label>',
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			checked( ! empty( $s[ $key ] ), true, false ),
			$help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : '',
			esc_html( $label )
		);
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
		}
		echo '<br>';
	}

	/**
	 * Radio ομάδα.
	 *
	 * @param array<string, mixed>  $s       Ρυθμίσεις.
	 * @param string                $key     Κλειδί.
	 * @param string                $legend  Τίτλος.
	 * @param array<string, string> $options τιμή => κείμενο.
	 */
	private static function radios( $s, $key, $legend, $options ) {
		echo '<fieldset><legend class="screen-reader-text">' . esc_html( $legend ) . '</legend>';
		foreach ( $options as $value => $label ) {
			$id = 'pncp-' . $key . '-' . $value;
			printf(
				'<label for="%1$s"><input type="radio" id="%1$s" name="%2$s[%3$s]" value="%4$s"%5$s> %6$s</label><br>',
				esc_attr( $id ),
				esc_attr( PNCP_OPTION ),
				esc_attr( $key ),
				esc_attr( $value ),
				checked( (string) $s[ $key ], (string) $value, false ),
				esc_html( $label )
			);
		}
		echo '</fieldset>';
	}

	/**
	 * Select.
	 *
	 * @param array<string, mixed>  $s       Ρυθμίσεις.
	 * @param string                $key     Κλειδί.
	 * @param array<string, string> $options τιμή => κείμενο.
	 * @param string                $help    Βοήθεια.
	 */
	private static function select( $s, $key, $options, $help = '' ) {
		$id = 'pncp-' . $key;
		printf( '<select id="%1$s" name="%2$s[%3$s]"%4$s>', esc_attr( $id ), esc_attr( PNCP_OPTION ), esc_attr( $key ), $help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : '' );
		foreach ( $options as $value => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( (string) $s[ $key ], (string) $value, false ), esc_html( $label ) );
		}
		echo '</select>';
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
		}
	}

	/**
	 * Πεδίο αριθμού με ετικέτα και βοήθεια.
	 *
	 * @param array<string, mixed> $s     Ρυθμίσεις.
	 * @param string               $key   Κλειδί.
	 * @param string               $label Κείμενο.
	 * @param string               $help  Βοήθεια.
	 */
	private static function number( $s, $key, $label, $help = '' ) {
		$range = PNCP_Options::int_ranges()[ $key ];
		$id    = 'pncp-' . $key;
		printf(
			'<p><label for="%1$s">%2$s</label> <input type="number" class="small-text" id="%1$s" name="%3$s[%4$s]" value="%5$d" min="%6$d"%7$s%8$s></p>',
			esc_attr( $id ),
			esc_html( $label ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			(int) $s[ $key ],
			(int) $range[0],
			PHP_INT_MAX === $range[1] ? '' : ' max="' . (int) $range[1] . '"',
			$help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : ''
		);
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
		}
	}

	/**
	 * Textarea με ετικέτα.
	 *
	 * @param array<string, mixed> $s     Ρυθμίσεις.
	 * @param string               $key   Κλειδί.
	 * @param string               $label Ετικέτα.
	 * @param string               $help  Βοήθεια.
	 * @param int                  $rows  Γραμμές.
	 */
	private static function textarea( $s, $key, $label, $help = '', $rows = 4 ) {
		$id = 'pncp-' . $key;
		printf( '<p><label for="%s">%s</label></p>', esc_attr( $id ), esc_html( $label ) );
		printf(
			'<textarea class="large-text code" rows="%1$d" id="%2$s" name="%3$s[%4$s]"%5$s>%6$s</textarea>',
			(int) $rows,
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			$help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : '',
			esc_textarea( (string) $s[ $key ] )
		);
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
		}
	}

	/**
	 * Αρχή φόρμας ρυθμίσεων μιας καρτέλας.
	 *
	 * @param string $section Καρτέλα.
	 */
	private static function form_open( $section ) {
		echo '<form method="post" action="options.php">';
		settings_fields( self::GROUP );
		printf( '<input type="hidden" name="%s[_sections][]" value="%s">', esc_attr( PNCP_OPTION ), esc_attr( $section ) );
		echo '<table class="form-table" role="presentation">';
	}

	/**
	 * Τέλος φόρμας ρυθμίσεων.
	 */
	private static function form_close() {
		echo '</table>';
		submit_button( __( 'Αποθήκευση αλλαγών', 'content-protect' ) );
		echo '</form>';
	}

	/**
	 * Φόρμα admin-post με nonce (για ενέργειες).
	 *
	 * @param string $action  Action.
	 * @param string $nonce   Nonce action.
	 * @param string $classes Κλάσεις.
	 */
	private static function action_form_open( $action, $nonce, $classes = '' ) {
		printf( '<form method="post" action="%s" class="%s">', esc_url( admin_url( 'admin-post.php' ) ), esc_attr( $classes ) );
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( $action ) );
		wp_nonce_field( $nonce );
	}

	/* ---------- Σελίδα ---------- */

	/**
	 * Η σελίδα ρυθμίσεων.
	 */
	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$tab = self::current_tab();
		?>
		<div class="wrap pncp-admin">
			<h1><?php esc_html_e( 'Προστασία περιεχομένου', 'content-protect' ); ?></h1>
			<?php
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Μόνο εμφάνιση της επιβεβαίωσης.
			if ( isset( $_GET['pncp_confirm'] ) && PNCP_Status::is_enabled() ) {
				self::render_disable_confirm();
			}
			?>
			<nav class="nav-tab-wrapper" aria-label="<?php esc_attr_e( 'Ενότητες ρυθμίσεων', 'content-protect' ); ?>">
				<?php foreach ( self::tabs() as $key => $label ) : ?>
					<a href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => $key ) ) ); ?>" class="nav-tab<?php echo $tab === $key ? ' nav-tab-active' : ''; ?>"<?php echo $tab === $key ? ' aria-current="page"' : ''; ?>><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</nav>
			<?php
			$method = 'tab_' . $tab;
			self::$method( PNCP_Options::stored() );
			?>
		</div>
		<?php
	}

	/**
	 * Επιβεβαίωση απενεργοποίησης (από τη μπάρα ή το widget).
	 */
	private static function render_disable_confirm() {
		?>
		<div class="notice notice-warning pncp-confirm">
			<p><strong><?php esc_html_e( 'Να απενεργοποιηθεί η προστασία σε όλο το site;', 'content-protect' ); ?></strong></p>
			<p><?php esc_html_e( 'Μέχρι να την ενεργοποιήσετε ξανά, bots και επισκέπτες θα μπορούν να αντιγράφουν ελεύθερα κείμενα, εικόνες και feeds.', 'content-protect' ); ?></p>
			<?php self::action_form_open( PNCP_Status::ACTION, PNCP_Status::ACTION ); ?>
				<input type="hidden" name="state" value="off">
				<p>
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Ναι, απενεργοποίηση', 'content-protect' ); ?></button>
					<a class="button" href="<?php echo esc_url( PNCP_Status::settings_url() ); ?>"><?php esc_html_e( 'Ακύρωση', 'content-protect' ); ?></a>
				</p>
			</form>
		</div>
		<?php
	}

	/**
	 * Καρτέλα «Στη σελίδα»: κατάσταση, προφίλ, Emergency Mode και τι μπλοκάρεται στον browser.
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function tab_general( $s ) {
		self::render_profiles( $s );
		self::form_open( 'general' );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Κατάσταση', 'content-protect' ); ?></th>
			<td><?php self::checkbox( $s, 'enabled', __( 'Η προστασία είναι ενεργή', 'content-protect' ) ); ?></td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Πού εφαρμόζεται', 'content-protect' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'scope_posts', __( 'Άρθρα', 'content-protect' ) );
				self::checkbox( $s, 'scope_pages', __( 'Σελίδες', 'content-protect' ) );
				self::checkbox( $s, 'scope_home', __( 'Αρχική, κατηγορίες, αναζήτηση και αρχεία', 'content-protect' ) );
				self::checkbox( $s, 'scope_products', __( 'Προϊόντα WooCommerce', 'content-protect' ) );
				self::checkbox( $s, 'skip_woo_pages', __( 'Να μην εφαρμόζεται σε καλάθι, ταμείο και «Ο λογαριασμός μου»', 'content-protect' ), __( 'Συνιστάται: οι πελάτες πρέπει να μπορούν να αντιγράφουν αριθμό παραγγελίας και κωδικούς κουπονιών.', 'content-protect' ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="pncp-excluded_ids"><?php esc_html_e( 'Εξαιρέσεις', 'content-protect' ); ?></label></th>
			<td>
				<input type="text" class="regular-text" id="pncp-excluded_ids" name="<?php echo esc_attr( PNCP_OPTION ); ?>[excluded_ids]" value="<?php echo esc_attr( $s['excluded_ids'] ); ?>" aria-describedby="pncp-excluded_ids-help" inputmode="numeric">
				<p class="description" id="pncp-excluded_ids-help"><?php esc_html_e( 'IDs σελίδων ή άρθρων χωρισμένα με κόμμα, π.χ. 12, 45. Για ένα μόνο κομμάτι κειμένου (τηλέφωνο, email, κωδικό), βάλτε του την CSS κλάση pncp-allow.', 'content-protect' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Τι μπλοκάρεται', 'content-protect' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'block_selection', __( 'Επιλογή κειμένου με το ποντίκι ή το δάχτυλο', 'content-protect' ) );
				self::checkbox( $s, 'block_context_menu', __( 'Δεξί κλικ', 'content-protect' ) );
				self::checkbox( $s, 'block_shortcuts', __( 'Συντομεύσεις Ctrl/Cmd + A, C, X, S, U', 'content-protect' ), __( 'Η πλοήγηση με πληκτρολόγιο (Tab, βελάκια, Enter) δεν επηρεάζεται ποτέ.', 'content-protect' ) );
				self::checkbox( $s, 'block_devtools', __( 'Συντομεύσεις εργαλείων προγραμματιστή (F12, Ctrl+Shift+I/J/C/K, Cmd+Opt+I/J/C/U)', 'content-protect' ), __( 'Κοσμητικό: κόβει μόνο τις συντομεύσεις. Δεν ανιχνεύει τα DevTools και δεν «σπάει» τη σελίδα.', 'content-protect' ) );
				self::checkbox( $s, 'block_image_drag', __( 'Σύρσιμο εικόνων και «Αποθήκευση εικόνας» με παρατεταμένο πάτημα στο κινητό', 'content-protect' ) );
				self::checkbox( $s, 'block_text_drag', __( 'Σύρσιμο επιλεγμένου κειμένου σε άλλο παράθυρο', 'content-protect' ) );
				self::checkbox( $s, 'blur_on_capture', __( 'Θόλωμα της σελίδας όταν πατηθεί Print Screen ή συντόμευση στιγμιότυπου οθόνης', 'content-protect' ), __( 'Προαιρετικό. Πιάνει μόνο τις συντομεύσεις που βλέπει ο browser (Print Screen, Win+Shift+S, Cmd+Shift+3/4/5). Δεν σταματά εργαλεία εκτός browser ή φωτογραφία με κινητό.', 'content-protect' ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Όταν κάποιος αντιγράφει', 'content-protect' ); ?></th>
			<td>
				<?php
				self::radios(
					$s,
					'copy_mode',
					__( 'Όταν κάποιος αντιγράφει', 'content-protect' ),
					array(
						'block'       => __( 'Να μπλοκάρεται η αντιγραφή', 'content-protect' ),
						'attribution' => __( 'Να επιτρέπεται, με την πηγή και τον σύνδεσμο προσαρτημένα στο τέλος', 'content-protect' ),
						'allow'       => __( 'Να επιτρέπεται κανονικά', 'content-protect' ),
					)
				);
				self::number( $s, 'attribution_min_chars', __( 'Η πηγή προσαρτάται από τόσους χαρακτήρες και πάνω:', 'content-protect' ), __( 'Μικρότερα αποσπάσματα (π.χ. μια λέξη ή ένα τηλέφωνο) αντιγράφονται χωρίς πηγή. 0 = πάντα.', 'content-protect' ) );
				?>
				<p class="description"><?php esc_html_e( 'Η επιλογή με την πηγή έχει νόημα όταν η επιλογή κειμένου είναι ανοιχτή.', 'content-protect' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Εκτύπωση', 'content-protect' ); ?></th>
			<td>
				<?php
				self::radios(
					$s,
					'print_mode',
					__( 'Εκτύπωση', 'content-protect' ),
					array(
						'source' => __( 'Επιτρέπεται, με τον σύνδεσμο της σελίδας στο κάτω μέρος (συνιστάται)', 'content-protect' ),
						'allow'  => __( 'Επιτρέπεται κανονικά', 'content-protect' ),
						'block'  => __( 'Δεν επιτρέπεται', 'content-protect' ),
					)
				);
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="pncp-exempt_cap"><?php esc_html_e( 'Ποιοι εξαιρούνται', 'content-protect' ); ?></label></th>
			<td>
				<?php
				self::select(
					$s,
					'exempt_cap',
					array(
						'edit_posts'        => __( 'Συνδεδεμένοι συντάκτες και διαχειριστές', 'content-protect' ),
						'edit_others_posts' => __( 'Συνδεδεμένοι αρχισυντάκτες και διαχειριστές', 'content-protect' ),
						'manage_options'    => __( 'Μόνο οι διαχειριστές', 'content-protect' ),
						'none'              => __( 'Κανείς (για δοκιμή της προστασίας)', 'content-protect' ),
					),
					__( 'Ισχύει για την προστασία στη σελίδα και για τους ελέγχους στον server (bots, όρια, αποκλεισμοί). Πελάτες με λογαριασμό δεν εξαιρούνται.', 'content-protect' )
				);
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Μήνυμα στον επισκέπτη', 'content-protect' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'show_message', __( 'Να εμφανίζεται μήνυμα όταν μπλοκάρεται κάτι', 'content-protect' ) ); ?>
				<label for="pncp-message" class="screen-reader-text"><?php esc_html_e( 'Κείμενο μηνύματος', 'content-protect' ); ?></label>
				<input type="text" class="large-text" id="pncp-message" name="<?php echo esc_attr( PNCP_OPTION ); ?>[message]" value="<?php echo esc_attr( $s['message'] ); ?>" maxlength="200">
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Iframe και AI', 'content-protect' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'block_framing', __( 'Οι σελίδες δεν ανοίγουν μέσα σε iframe άλλου site', 'content-protect' ), __( 'Headers X-Frame-Options και CSP frame-ancestors. Τα embeds του WordPress (oEmbed) συνεχίζουν να λειτουργούν.', 'content-protect' ) );
				self::checkbox( $s, 'tdm_reservation', __( 'Δήλωση εξαίρεσης από εκπαίδευση AI και εξόρυξη κειμένου (TDM)', 'content-protect' ), __( 'Header και meta tdm-reservation, /.well-known/tdmrep.json και noai/noimageai. Νομική βάση: Οδηγία (ΕΕ) 2019/790, άρθρο 4 παρ. 3 (ν. 4996/2022): η επιφύλαξη δικαιωμάτων σε μηχαναγνώσιμη μορφή.', 'content-protect' ) );
				?>
				<p><label for="pncp-tdm_policy_url"><?php esc_html_e( 'Σελίδα με τους όρους αδειοδότησης (προαιρετικό):', 'content-protect' ); ?></label>
				<input type="url" class="regular-text code" id="pncp-tdm_policy_url" name="<?php echo esc_attr( PNCP_OPTION ); ?>[tdm_policy_url]" value="<?php echo esc_attr( $s['tdm_policy_url'] ); ?>" placeholder="https://"></p>
			</td>
		</tr>
		<?php
		self::form_close();
	}

	/**
	 * Προφίλ και Emergency Mode.
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function render_profiles( $s ) {
		$current  = PNCP_Options::current_profile( $s );
		$profiles = array(
			'balanced' => array( __( 'Ισορροπημένο', 'content-protect' ), __( 'Αντιγραφή με πηγή, όριο 60 σελίδες/λεπτό, αποκλεισμός μετά από 3 παραβάσεις. Για τα περισσότερα sites.', 'content-protect' ) ),
			'strict'   => array( __( 'Αυστηρό', 'content-protect' ), __( 'Χωρίς επιλογή και αντιγραφή κειμένου, όριο 40 σελίδες/λεπτό, αποκλεισμός 3 ωρών μετά από 2 παραβάσεις.', 'content-protect' ) ),
			'maximum'  => array( __( 'Μέγιστο', 'content-protect' ), __( 'Και χωρίς εκτύπωση και RSS, μόνο browsers, θόλωμα σε screenshot, όριο 30/λεπτό, αποκλεισμός 12 ωρών μετά από 2 παραβάσεις. Μπορεί να ενοχλήσει κάποιους επισκέπτες.', 'content-protect' ) ),
		);
		$until    = PNCP_Options::emergency_until();
		?>
		<div class="pncp-cards">
			<section class="pncp-card" aria-labelledby="pncp-profiles-title">
				<h2 id="pncp-profiles-title"><?php esc_html_e( 'Έτοιμα προφίλ', 'content-protect' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Ένα κλικ αλλάζει τις ρυθμίσεις προστασίας και ορίων. Λίστες, feeds, IP και υδατογράφημα δεν αλλάζουν. Μετά μπορείτε να προσαρμόσετε ό,τι θέλετε.', 'content-protect' ); ?></p>
				<p><?php esc_html_e( 'Τώρα:', 'content-protect' ); ?> <strong><?php echo esc_html( '' === $current ? __( 'Προσαρμοσμένο', 'content-protect' ) : $profiles[ $current ][0] ); ?></strong></p>
				<?php self::action_form_open( 'pncp_profile', 'pncp_profile', 'pncp-profile-form' ); ?>
					<?php foreach ( $profiles as $key => $profile ) : ?>
						<div class="pncp-profile<?php echo $current === $key ? ' is-current' : ''; ?>">
							<button type="submit" name="profile" value="<?php echo esc_attr( $key ); ?>" class="button<?php echo 'balanced' === $key ? ' button-primary' : ''; ?>" aria-describedby="pncp-profile-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $profile[0] ); ?></button>
							<p class="description" id="pncp-profile-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $profile[1] ); ?></p>
						</div>
					<?php endforeach; ?>
				</form>
			</section>
			<section class="pncp-card pncp-card--emergency" aria-labelledby="pncp-emergency-title">
				<h2 id="pncp-emergency-title"><?php esc_html_e( 'Emergency Mode', 'content-protect' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Για επίθεση scraping σε εξέλιξη: μόνο browsers, όριο 20 σελίδες/λεπτό, αποκλεισμός 6 ωρών μετά από 2 παραβάσεις, REST/GraphQL χωρίς κείμενο. Οι ρυθμίσεις σας δεν αλλάζουν: στη λήξη ισχύουν ξανά όπως ήταν.', 'content-protect' ); ?></p>
				<?php if ( $until ) : ?>
					<p class="pncp-emergency-on">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: ημερομηνία και ώρα */
								__( 'Σε λειτουργία μέχρι %s.', 'content-protect' ),
								wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $until )
							)
						);
						?>
					</p>
					<p><a class="button" href="<?php echo esc_url( PNCP_Status::emergency_stop_url() ); ?>"><?php esc_html_e( 'Τέλος τώρα', 'content-protect' ); ?></a></p>
				<?php else : ?>
					<?php self::action_form_open( PNCP_Status::EMERGENCY, PNCP_Status::EMERGENCY ); ?>
						<p>
							<label for="pncp-emergency-hours"><?php esc_html_e( 'Διάρκεια:', 'content-protect' ); ?></label>
							<select id="pncp-emergency-hours" name="hours">
								<option value="1"><?php esc_html_e( '1 ώρα', 'content-protect' ); ?></option>
								<option value="6"><?php esc_html_e( '6 ώρες', 'content-protect' ); ?></option>
								<option value="24" selected><?php esc_html_e( '24 ώρες', 'content-protect' ); ?></option>
								<option value="72"><?php esc_html_e( '3 ημέρες', 'content-protect' ); ?></option>
							</select>
							<button type="submit" class="button pncp-button-danger"><?php esc_html_e( 'Έναρξη Emergency Mode', 'content-protect' ); ?></button>
						</p>
					</form>
				<?php endif; ?>
			</section>
		</div>
		<?php
	}

	/**
	 * Καρτέλα «Bots και όρια».
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function tab_bots( $s ) {
		self::form_open( 'bots' );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Scrapers και AI bots', 'content-protect' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'block_bots', __( 'Μπλοκάρισμα (403) των User-Agents της λίστας', 'content-protect' ) );
				self::checkbox( $s, 'block_empty_ua', __( 'Μπλοκάρισμα αιτημάτων χωρίς User-Agent', 'content-protect' ) );
				self::checkbox( $s, 'block_fake_crawlers', __( 'Μπλοκάρισμα ψεύτικων Googlebot, Bingbot, Applebot και Yandex', 'content-protect' ), __( 'Η IP ελέγχεται με τις επίσημες λίστες της Google και της Bing και με reverse DNS. Οι πραγματικές μηχανές αναζήτησης περνούν πάντα, χωρίς όριο.', 'content-protect' ) );
				self::checkbox( $s, 'require_browser_headers', __( 'Μόνο browsers: 403 σε σελίδες χωρίς Accept-Language ή χωρίς «Mozilla/» στο User-Agent', 'content-protect' ), __( 'Κόβει τα περισσότερα scripts. Τα previews συνδέσμων (Facebook, Viber, WhatsApp κ.ά.) της λίστας «Πάντα επιτρεπτά» περνούν.', 'content-protect' ) );
				self::checkbox( $s, 'trap_enabled', __( 'Παγίδα για bots', 'content-protect' ), __( 'Αόρατος σύνδεσμος σε κάθε σελίδα, απαγορευμένος στο robots.txt. Όποιος τον ανοίγει αποκλείεται προσωρινά, ακόμη κι αν παριστάνει browser. Οι επισκέπτες δεν τον βλέπουν και ένα ξένο site δεν μπορεί να τους παγιδεύσει.', 'content-protect' ) );
				self::textarea( $s, 'bot_list', __( 'Λίστα User-Agents που μπλοκάρονται (ένα ανά γραμμή, ταιριάζει οπουδήποτε στο User-Agent, χωρίς διάκριση πεζών/κεφαλαίων):', 'content-protect' ), __( 'Περιέχει δύο κατηγορίες AI: crawlers εκπαίδευσης (GPTBot, ClaudeBot, CCBot, Google-Extended κ.ά.) και AI αναζήτηση / βοηθούς (OAI-SearchBot, ChatGPT-User, Claude-SearchBot, PerplexityBot κ.ά.). Τη δεύτερη μπορείτε να την επιτρέψετε με την επιλογή από κάτω.', 'content-protect' ), 10 );
				self::checkbox( $s, 'allow_ai_search', __( 'Επιτρέπονται οι AI μηχανές αναζήτησης και βοηθοί (όχι οι crawlers εκπαίδευσης)', 'content-protect' ), sprintf( /* translators: %s: λίστα User-Agents */ __( 'Για να εμφανίζεται το site στις απαντήσεις AI αναζήτησης με σύνδεσμο, χωρίς να δίνεται για εκπαίδευση μοντέλων. Επιτρέπονται: %s. Βγαίνουν και από το Disallow του robots.txt και από τους κανόνες server. Το όριο σελίδων ισχύει κανονικά, γιατί το User-Agent πλαστογραφείται.', 'content-protect' ), implode( ', ', PNCP_Options::ai_search_agents() ) ) );
				self::textarea( $s, 'allow_list', __( 'Πάντα επιτρεπτά User-Agents (previews συνδέσμων, πλατφόρμες τιμών, monitoring):', 'content-protect' ), __( 'Υπερισχύουν της λίστας bots και του «Μόνο browsers». Το όριο σελίδων ισχύει και για αυτούς, γιατί το User-Agent πλαστογραφείται εύκολα.', 'content-protect' ), 5 );
				self::textarea( $s, 'allow_ips', __( 'Πάντα επιτρεπτές IP / CIDR (γραφείο, ERP, monitoring), μία ανά γραμμή:', 'content-protect' ), __( 'Δεν ελέγχονται, δεν μετρούν στα όρια και δεν αποκλείονται ποτέ.', 'content-protect' ), 3 );
				self::checkbox( $s, 'robots_ai_block', __( 'Δήλωση των AI crawlers στο robots.txt (Disallow)', 'content-protect' ), __( 'Ισχύει για το εικονικό robots.txt του WordPress. Αν υπάρχει φυσικό αρχείο robots.txt, αυτό έχει προτεραιότητα.', 'content-protect' ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Όρια ανά IP', 'content-protect' ); ?></th>
			<td>
				<?php
				self::number( $s, 'rate_limit', __( 'Σελίδες ανά λεπτό (0 = ανενεργό):', 'content-protect' ), __( 'Τιμή εκκίνησης: 60. Πάνω από το όριο απαντά 429. Προσοχή σε δίκτυα με κοινή IP (εταιρείες, κινητή τηλεφωνία) και σε CDN: ορίστε πρώτα σωστά την «Πραγματική IP επισκέπτη».', 'content-protect' ) );
				self::number( $s, 'rate_limit_search', __( 'Αναζητήσεις (?s=) ανά λεπτό (0 = ανενεργό):', 'content-protect' ), __( 'Η αναζήτηση είναι βαριά για τον server και αγαπημένη των scrapers. Τιμή εκκίνησης: 20.', 'content-protect' ) );
				self::number( $s, 'rate_limit_rest', __( 'Αιτήματα REST API (/wp-json/) και GraphQL ανά λεπτό (0 = ανενεργό):', 'content-protect' ), __( 'Μόνο αιτήματα ανάγνωσης από επισκέπτες. Καλάθι, ταμείο και φόρμες (POST) δεν μετράνε. Τιμή εκκίνησης: 60.', 'content-protect' ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Προσωρινός αποκλεισμός', 'content-protect' ); ?></th>
			<td>
				<?php
				self::number( $s, 'ban_strikes', __( 'Αποκλεισμός μετά από τόσες παραβάσεις μέσα σε 10 λεπτά (0 = ποτέ):', 'content-protect' ), __( 'Παράβαση: κάθε λεπτό που η IP ξεπέρασε ένα όριο, και κάθε ψεύτικο Googlebot. Η παγίδα αποκλείει αμέσως.', 'content-protect' ) );
				self::number( $s, 'ban_minutes', __( 'Διάρκεια αποκλεισμού (λεπτά):', 'content-protect' ) );
				?>
				<p><label for="pncp-log_retention"><?php esc_html_e( 'Διατήρηση αρχείου αποκλεισμών:', 'content-protect' ); ?></label>
				<?php
				self::select(
					$s,
					'log_retention',
					array(
						'1'  => __( '1 ημέρα', 'content-protect' ),
						'7'  => __( '7 ημέρες', 'content-protect' ),
						'30' => __( '30 ημέρες', 'content-protect' ),
					),
					__( 'Το αρχείο κρατά IP και User-Agent, δηλαδή προσωπικά δεδομένα (GDPR). Σβήνεται αυτόματα.', 'content-protect' )
				);
				?>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="pncp-ip_header"><?php esc_html_e( 'Πραγματική IP επισκέπτη', 'content-protect' ); ?></label></th>
			<td>
				<?php
				self::select(
					$s,
					'ip_header',
					array(
						'remote_addr'      => __( 'REMOTE_ADDR (χωρίς CDN/proxy)', 'content-protect' ),
						'cf_connecting_ip' => 'CF-Connecting-IP (Cloudflare)',
						'x_forwarded_for'  => 'X-Forwarded-For',
						'x_real_ip'        => 'X-Real-IP',
						'true_client_ip'   => 'True-Client-IP',
					),
					__( 'Πίσω από CDN ή reverse proxy όλοι οι επισκέπτες φαίνονται με την IP του CDN. Επιλέξτε το header με την πραγματική IP.', 'content-protect' )
				);
				?>
				<p><strong><?php esc_html_e( 'Trusted Proxy:', 'content-protect' ); ?></strong> <?php esc_html_e( 'το header διαβάζεται μόνο όταν το αίτημα έρχεται από proxy που εμπιστεύεστε. Αλλιώς ο καθένας θα μπορούσε να γράψει όποια IP θέλει και να παρακάμψει όρια και αποκλεισμούς. CF-Connecting-IP: μόνο από το Cloudflare. X-Real-IP / X-Forwarded-For: και από τον ίδιο τον server ή ιδιωτικό δίκτυο (Nginx μπροστά από τον Apache). True-Client-IP: μόνο από τους proxies της λίστας.', 'content-protect' ); ?></p>
				<?php
				self::checkbox( $s, 'trust_cloudflare', __( 'Αξιόπιστες οι διευθύνσεις του Cloudflare', 'content-protect' ), __( 'Η επίσημη λίστα του Cloudflare ανανεώνεται κάθε μέρα.', 'content-protect' ) );
				if ( ! empty( $s['trust_any_proxy'] ) ) {
					echo '<div class="pncp-inline-warning">';
					self::checkbox( $s, 'trust_any_proxy', __( 'Εμπιστοσύνη σε κάθε αίτημα (συμπεριφορά της 1.4, μη ασφαλής)', 'content-protect' ), __( 'Ενεργή γιατί έτσι δούλευε η έκδοση 1.4. Συμπληρώστε τους proxies σας παρακάτω και ξετσεκάρετέ την. Αφού κλείσει, δεν ξανανοίγει.', 'content-protect' ) );
					echo '</div>';
				}
				self::textarea( $s, 'trusted_proxies', __( 'Άλλοι αξιόπιστοι proxies / load balancers (IP ή CIDR, μία ανά γραμμή):', 'content-protect' ), '', 3 );
				?>
				<p class="description">
					<?php
					esc_html_e( 'Τι βλέπει ο server σε αυτό το αίτημα:', 'content-protect' );
					echo '<br><code>REMOTE_ADDR = ' . esc_html( PNCP_Ip::remote_addr() ) . '</code>';
					foreach ( PNCP_Ip::ip_headers() as $key ) {
						if ( ! empty( $_SERVER[ $key ] ) ) {
							echo '<br><code>' . esc_html( $key . ' = ' . sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) ) . '</code>';
						}
					}
					echo '<br>' . esc_html__( 'Αξιόπιστος proxy:', 'content-protect' ) . ' <code>' . esc_html( PNCP_Ip::is_trusted_proxy( PNCP_Ip::remote_addr(), $s, (string) $s['ip_header'] ) ? __( 'ναι', 'content-protect' ) : __( 'όχι', 'content-protect' ) ) . '</code>';
					echo '<br>' . esc_html__( 'IP που χρησιμοποιεί τώρα το plugin:', 'content-protect' ) . ' <code>' . esc_html( PNCP_Ip::client_ip() ) . '</code>';
					?>
				</p>
			</td>
		</tr>
		<?php
		self::form_close();
		self::render_ip_lists();
	}

	/**
	 * Κατάσταση των επίσημων λιστών IP.
	 */
	private static function render_ip_lists() {
		$updated = PNCP_Ip::lists_updated();
		$names   = array(
			'google'     => 'Google',
			'bing'       => 'Bing',
			'cloudflare' => 'Cloudflare',
		);
		?>
		<h2><?php esc_html_e( 'Επίσημες λίστες IP', 'content-protect' ); ?></h2>
		<ul class="pncp-list-status">
			<?php foreach ( $names as $key => $label ) : ?>
				<li>
					<strong><?php echo esc_html( $label ); ?>:</strong>
					<?php
					if ( empty( $updated[ $key ] ) ) {
						echo esc_html( 'cloudflare' === $key ? __( 'ενσωματωμένη λίστα (δεν έχει κατέβει ακόμη)', 'content-protect' ) : __( 'δεν έχει κατέβει ακόμη, χρησιμοποιείται μόνο DNS', 'content-protect' ) );
					} else {
						echo esc_html(
							sprintf(
								/* translators: 1: πλήθος διευθύνσεων, 2: ημερομηνία */
								__( '%1$s διευθύνσεις, ενημέρωση %2$s', 'content-protect' ),
								number_format_i18n( count( PNCP_Ip::list_of( $key ) ) ),
								wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $updated[ $key ] )
							)
						);
					}
					?>
				</li>
			<?php endforeach; ?>
		</ul>
		<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
			<input type="hidden" name="op" value="refresh_lists">
			<?php submit_button( __( 'Ανανέωση τώρα', 'content-protect' ), 'secondary', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Καρτέλα «Feeds και API».
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function tab_content( $s ) {
		self::render_tokens( $s );
		self::form_open( 'content' );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Προστατευμένα feeds', 'content-protect' ); ?></th>
			<td>
				<?php
				self::textarea( $s, 'private_paths', __( 'Διαδρομές που δεν είναι δημόσιες (μία ανά γραμμή, το * σημαίνει «οτιδήποτε»), π.χ. /skroutz.xml, /feeds/*.xml:', 'content-protect' ) );
				self::textarea( $s, 'private_ips', __( 'Ή επιτρεπόμενες IP / CIDR της υπηρεσίας (μία ανά γραμμή):', 'content-protect' ), __( 'Χωρίς σωστό token ή επιτρεπόμενη IP απαντά 403. Ισχύει για feeds που φτιάχνει η PHP. Για στατικά αρχεία .xml δείτε την καρτέλα «Κανόνες server».', 'content-protect' ), 3 );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'REST API', 'content-protect' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'rest_hide_content', __( 'Κρύψιμο του κειμένου (content, excerpt) των άρθρων, σελίδων και προϊόντων από επισκέπτες', 'content-protect' ), __( 'Το REST μένει ανοιχτό για φόρμες, oEmbed, SEO plugins και δικά σας endpoints. Όσοι μπορούν να γράψουν άρθρα βλέπουν κανονικά το κείμενο. Εξαιρέσεις από κώδικα: φίλτρο pncp_rest_hide_content.', 'content-protect' ) ); ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'GraphQL', 'content-protect' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'graphql_hide_content', __( 'Κρύψιμο του κειμένου στο WPGraphQL (content, excerpt, περιγραφές προϊόντων)', 'content-protect' ) );
				echo '<p class="description">' . esc_html( PNCP_Graphql::active() ? __( 'Το WPGraphQL είναι ενεργό: ισχύουν και ο έλεγχος bots, οι αποκλεισμοί και το όριο REST / GraphQL.', 'content-protect' ) : __( 'Το WPGraphQL δεν είναι εγκατεστημένο· η ρύθμιση θα ισχύσει αν το εγκαταστήσετε.', 'content-protect' ) ) . '</p>';
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'RSS / Atom feeds', 'content-protect' ); ?></th>
			<td>
				<?php
				self::radios(
					$s,
					'feed_mode',
					__( 'RSS / Atom feeds', 'content-protect' ),
					array(
						'excerpt'  => __( 'Μόνο σύντομη περίληψη με σύνδεσμο προς το άρθρο (συνιστάται)', 'content-protect' ),
						'full'     => __( 'Πλήρες κείμενο', 'content-protect' ),
						'disabled' => __( 'Απενεργοποιημένα', 'content-protect' ),
					)
				);
				?>
			</td>
		</tr>
		<?php
		self::form_close();
	}

	/**
	 * Token, URLs ανά υπηρεσία και στατιστικά των feeds.
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function render_tokens( $s ) {
		$data  = PNCP_Private_Urls::token_data();
		$key   = 'pncp_new_token_' . get_current_user_id();
		$fresh = (string) get_transient( $key );
		if ( '' !== $fresh ) {
			delete_transient( $key ); // Φαίνεται μία μόνο φορά.
		}
		$paths = PNCP_Options::parse_list( $s['private_paths'] );
		$stats = PNCP_Private_Urls::stats();
		?>
		<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-token-title">
			<h2 id="pncp-token-title"><?php esc_html_e( 'Token πρόσβασης', 'content-protect' ); ?></h2>
			<?php if ( '' !== $fresh ) : ?>
				<div class="notice notice-success inline pncp-fresh-token">
					<p><strong><?php esc_html_e( 'Νέο token. Αντιγράψτε το τώρα: δεν θα ξαναεμφανιστεί.', 'content-protect' ); ?></strong></p>
					<p><code id="pncp-token-value" class="pncp-token"><?php echo esc_html( $fresh ); ?></code> <button type="button" class="button pncp-copy" data-target="pncp-token-value"><?php esc_html_e( 'Αντιγραφή', 'content-protect' ); ?></button></p>
					<p><?php esc_html_e( 'Header για ERP / API:', 'content-protect' ); ?> <code>X-Content-Protect-Token: <?php echo esc_html( $fresh ); ?></code> <?php esc_html_e( 'ή', 'content-protect' ); ?> <code>Authorization: Bearer <?php echo esc_html( $fresh ); ?></code></p>
					<?php if ( $paths ) : ?>
						<p><?php esc_html_e( 'URL για Skroutz, BestPrice, Google Merchant (δέχονται μόνο URL):', 'content-protect' ); ?></p>
						<ul>
							<?php foreach ( $paths as $i => $pattern ) : ?>
								<li><code id="pncp-url-<?php echo (int) $i; ?>"><?php echo esc_html( PNCP_Private_Urls::example_url( $pattern, $fresh ) ); ?></code> <button type="button" class="button button-small pncp-copy" data-target="pncp-url-<?php echo (int) $i; ?>"><?php esc_html_e( 'Αντιγραφή', 'content-protect' ); ?></button></li>
							<?php endforeach; ?>
						</ul>
					<?php endif; ?>
				</div>
			<?php endif; ?>
			<p>
				<?php
				if ( '' === $data['hash'] ) {
					esc_html_e( 'Δεν υπάρχει token. Δημιουργήστε ένα για να δώσετε πρόσβαση στις υπηρεσίες.', 'content-protect' );
				} else {
					echo esc_html(
						sprintf(
							/* translators: 1: τελευταίοι 4 χαρακτήρες, 2: ημερομηνία */
							__( 'Ενεργό token που τελειώνει σε …%1$s, από %2$s. Αποθηκεύεται μόνο το hash του, οπότε δεν μπορεί να εμφανιστεί ξανά.', 'content-protect' ),
							$data['hint'],
							$data['created'] ? wp_date( get_option( 'date_format' ), $data['created'] ) : '—'
						)
					);
				}
				?>
			</p>
			<?php if ( '' !== $data['prev_hash'] && $data['prev_until'] > time() ) : ?>
				<p class="pncp-inline-warning">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: τελευταίοι 4 χαρακτήρες, 2: ημερομηνία */
							__( 'Το προηγούμενο token (…%1$s) ισχύει ακόμη μέχρι %2$s, ώστε να προλάβετε να αλλάξετε το URL στις υπηρεσίες.', 'content-protect' ),
							$data['prev_hint'],
							wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $data['prev_until'] )
						)
					);
					?>
				</p>
				<?php self::action_form_open( 'pncp_token', 'pncp_token' ); ?>
					<input type="hidden" name="op" value="revoke_prev">
					<?php submit_button( __( 'Ακύρωση του προηγούμενου τώρα', 'content-protect' ), 'secondary', 'submit', false ); ?>
				</form>
			<?php endif; ?>
			<?php self::action_form_open( 'pncp_token', 'pncp_token', 'pncp-token-form' ); ?>
				<input type="hidden" name="op" value="rotate">
				<p>
					<?php if ( '' !== $data['hash'] ) : ?>
						<label for="pncp-grace"><?php esc_html_e( 'Το τρέχον token να ισχύει ακόμη:', 'content-protect' ); ?></label>
						<select id="pncp-grace" name="grace">
							<option value="0"><?php esc_html_e( 'Καθόλου (ακύρωση αμέσως)', 'content-protect' ); ?></option>
							<option value="1"><?php esc_html_e( '1 ημέρα', 'content-protect' ); ?></option>
							<option value="7" selected><?php esc_html_e( '7 ημέρες', 'content-protect' ); ?></option>
							<option value="30"><?php esc_html_e( '30 ημέρες', 'content-protect' ); ?></option>
						</select>
					<?php endif; ?>
					<button type="submit" class="button button-primary"><?php echo esc_html( '' === $data['hash'] ? __( 'Δημιουργία token', 'content-protect' ) : __( 'Νέο token (εναλλαγή)', 'content-protect' ) ); ?></button>
				</p>
			</form>
			<p class="description"><?php esc_html_e( 'Header για ERP και δικά σας integrations (δεν φαίνεται σε logs και ιστορικό). Token στο URL για Skroutz, BestPrice και Google Merchant, που δέχονται μόνο URL.', 'content-protect' ); ?></p>

			<?php if ( $paths ) : ?>
				<h3><?php esc_html_e( 'Πρόσβαση ανά feed', 'content-protect' ); ?></h3>
				<table class="widefat striped pncp-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Διαδρομή', 'content-protect' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Επιτυχίες', 'content-protect' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Τελευταία πρόσβαση', 'content-protect' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Με', 'content-protect' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Αρνήσεις', 'content-protect' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php
						$via_labels = array(
							'header' => __( 'header', 'content-protect' ),
							'url'    => __( 'token στο URL', 'content-protect' ),
							'ip'     => __( 'επιτρεπόμενη IP', 'content-protect' ),
							'admin'  => __( 'διαχειριστής', 'content-protect' ),
						);
						foreach ( $paths as $pattern ) :
							$row = isset( $stats[ strtolower( $pattern ) ] ) ? $stats[ strtolower( $pattern ) ] : array();
							?>
							<tr>
								<td><code><?php echo esc_html( $pattern ); ?></code></td>
								<td><?php echo esc_html( number_format_i18n( isset( $row['ok'] ) ? (int) $row['ok'] : 0 ) ); ?></td>
								<td><?php echo esc_html( ! empty( $row['last_ok'] ) ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $row['last_ok'] ) . ' · ' . $row['last_ip'] : __( 'Ποτέ', 'content-protect' ) ); ?></td>
								<td><?php echo esc_html( ! empty( $row['last_via'] ) && isset( $via_labels[ $row['last_via'] ] ) ? $via_labels[ $row['last_via'] ] : '—' ); ?></td>
								<td><?php echo esc_html( number_format_i18n( isset( $row['denied'] ) ? (int) $row['denied'] : 0 ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Καρτέλα «Εικόνες».
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function tab_images( $s ) {
		self::form_open( 'images' );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Υδατογράφημα', 'content-protect' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'watermark_enabled', __( 'Υδατογράφημα στις νέες εικόνες', 'content-protect' ), __( 'Μπαίνει στα μεγέθη που φτιάχνει το WordPress (thumbnails, medium, large). Για εικόνες που υπάρχουν ήδη, χρησιμοποιήστε το εργαλείο πιο κάτω. Το εικονίδιο site, το λογότυπο και το ίδιο το υδατογράφημα δεν το παίρνουν ποτέ.', 'content-protect' ) );
				if ( ! PNCP_Watermark::available() ) {
					echo '<p class="pncp-inline-warning"><strong>' . esc_html__( 'Η βιβλιοθήκη GD της PHP δεν είναι διαθέσιμη στον server, οπότε το υδατογράφημα δεν θα εφαρμοστεί.', 'content-protect' ) . '</strong></p>';
				}
				self::checkbox( $s, 'watermark_full', __( 'Υδατογράφημα και στην εικόνα πλήρους μεγέθους', 'content-protect' ), __( 'Χωρίς αυτό, η πλήρης εικόνα μένει καθαρή και κατεβαίνει από τη διεύθυνσή της. Το καθαρό πρωτότυπο φυλάγεται σε κρυφό φάκελο, ώστε να γίνεται πάντα επαναφορά.', 'content-protect' ) );
				self::checkbox( $s, 'watermark_products', __( 'Υδατογράφημα και στις εικόνες προϊόντων WooCommerce', 'content-protect' ) );
				?>
				<p class="pncp-inline-warning" id="pncp-products-warning"><?php esc_html_e( 'Δεν συνιστάται: Google Merchant Center, Skroutz και BestPrice απορρίπτουν εικόνες προϊόντων με υδατογράφημα, και τα feeds δείχνουν συνήθως την εικόνα πλήρους μεγέθους. Για τα προϊόντα, η προστασία από hotlink (καρτέλα «Κανόνες server») είναι καλύτερη επιλογή. Αν μια εικόνα με υδατογράφημα γίνει αργότερα εικόνα προϊόντος, λογότυπο ή εικονίδιο, το υδατογράφημα αφαιρείται αυτόματα.', 'content-protect' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Εμφάνιση', 'content-protect' ); ?></th>
			<td>
				<?php
				self::number( $s, 'watermark_image_id', __( 'ID εικόνας PNG από τη Βιβλιοθήκη πολυμέσων (0 = το domain του site ως κείμενο):', 'content-protect' ), __( 'Συνιστάται PNG με διάφανο φόντο (π.χ. το λογότυπο). Το ID φαίνεται στη διεύθυνση όταν ανοίγετε την εικόνα στη Βιβλιοθήκη.', 'content-protect' ) );
				?>
				<p><label for="pncp-watermark_position"><?php esc_html_e( 'Θέση:', 'content-protect' ); ?></label>
				<?php
				self::select(
					$s,
					'watermark_position',
					array(
						'br'     => __( 'Κάτω δεξιά', 'content-protect' ),
						'bl'     => __( 'Κάτω αριστερά', 'content-protect' ),
						'tr'     => __( 'Πάνω δεξιά', 'content-protect' ),
						'tl'     => __( 'Πάνω αριστερά', 'content-protect' ),
						'center' => __( 'Στο κέντρο', 'content-protect' ),
						'tiled'  => __( 'Επανάληψη σε όλη την εικόνα, διαγώνια (δύσκολα αφαιρείται)', 'content-protect' ),
					)
				);
				?>
				</p>
				<?php
				self::number( $s, 'watermark_size', __( 'Μέγεθος (% του πλάτους της εικόνας):', 'content-protect' ), __( 'Στη διαγώνια επανάληψη, το μέγεθος κάθε επανάληψης.', 'content-protect' ) );
				self::number( $s, 'watermark_opacity', __( 'Αδιαφάνεια (%):', 'content-protect' ) );
				self::number( $s, 'watermark_min_width', __( 'Μόνο σε μεγέθη με πλάτος από (px):', 'content-protect' ), __( 'Τα μικρά thumbnails μένουν καθαρά.', 'content-protect' ) );
				?>
			</td>
		</tr>
		<?php
		self::form_close();
		self::render_watermark_tool( $s );
	}

	/**
	 * Εργαλείο εφαρμογής / αφαίρεσης σε εικόνες που υπάρχουν ήδη.
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function render_watermark_tool( $s ) {
		$total = self::image_count();
		?>
		<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-tool-title">
			<h2 id="pncp-tool-title"><?php esc_html_e( 'Εικόνες που υπάρχουν ήδη', 'content-protect' ); ?></h2>
			<p><?php echo esc_html( sprintf( /* translators: %s: πλήθος */ __( 'Εικόνες JPEG / PNG / WebP στη βιβλιοθήκη: %s.', 'content-protect' ), number_format_i18n( $total ) ) ); ?></p>
			<p class="description"><?php esc_html_e( 'Κάθε εικόνα ξαναφτιάχνεται από το καθαρό πρωτότυπο, οπότε δεν μπαίνει ποτέ διπλό υδατογράφημα, ούτε σε εικόνες που πήραν υδατογράφημα από την έκδοση 1.x. Αν η σελίδα κλείσει στη μέση, πατήστε ξανά: συνεχίζει από εκεί που σταμάτησε. Κρατήστε backup του φακέλου uploads πριν ξεκινήσετε.', 'content-protect' ); ?></p>
			<?php if ( empty( $s['watermark_enabled'] ) ) : ?>
				<p class="pncp-inline-warning"><?php esc_html_e( 'Το υδατογράφημα είναι ανενεργό: η «Εφαρμογή» θα αφήσει τις εικόνες καθαρές. Ενεργοποιήστε το και αποθηκεύστε πρώτα.', 'content-protect' ); ?></p>
			<?php endif; ?>
			<p class="pncp-tool-buttons">
				<button type="button" class="button button-primary pncp-wm-run" data-mode="apply" data-total="<?php echo (int) $total; ?>"<?php disabled( ! PNCP_Watermark::available() ); ?>><?php esc_html_e( 'Εφαρμογή υδατογραφήματος', 'content-protect' ); ?></button>
				<button type="button" class="button pncp-wm-run" data-mode="remove" data-total="<?php echo (int) $total; ?>"><?php esc_html_e( 'Αφαίρεση υδατογραφήματος', 'content-protect' ); ?></button>
			</p>
			<div class="pncp-progress" hidden>
				<progress max="100" value="0" aria-labelledby="pncp-progress-text"></progress>
				<p id="pncp-progress-text" role="status" aria-live="polite"></p>
			</div>
		</section>
		<?php
	}

	/**
	 * Πόσες εικόνες έχει η βιβλιοθήκη.
	 *
	 * @return int
	 */
	private static function image_count() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Οθόνη διαχείρισης.
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_mime_type IN ('image/jpeg','image/png','image/webp')" );
	}

	/**
	 * AJAX: μια παρτίδα εικόνων. Ο δείκτης (cursor) είναι το τελευταίο ID που ολοκληρώθηκε.
	 */
	public static function ajax_wm_batch() {
		check_ajax_referer( 'pncp_wm_batch', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Δεν έχετε δικαίωμα.', 'content-protect' ) ), 403 );
		}
		$mode   = isset( $_POST['mode'] ) && 'remove' === $_POST['mode'] ? 'remove' : 'apply';
		$cursor = isset( $_POST['cursor'] ) ? absint( $_POST['cursor'] ) : 0;
		$other  = 'apply' === $mode ? 'remove' : 'apply';
		if ( 0 === $cursor ) {
			// Νέα εκτέλεση: αν η ίδια ενέργεια είχε διακοπεί, συνεχίζει από εκεί που σταμάτησε. Η άλλη
			// ενέργεια ξεχνά τη θέση της (μετά από «Αφαίρεση» η «Εφαρμογή» ξεκινά από την αρχή).
			$cursor = (int) get_option( 'pncp_wm_cursor_' . $mode, 0 );
			delete_option( 'pncp_wm_cursor_' . $other );
		}

		global $wpdb;
		$batch = (int) apply_filters( 'pncp_watermark_batch_size', 3 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Παρτίδα του εργαλείου.
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_mime_type IN ('image/jpeg','image/png','image/webp') AND ID > %d ORDER BY ID ASC LIMIT %d", $cursor, max( 1, $batch ) ) );

		$errors = 0;
		foreach ( $ids as $id ) {
			if ( 'error' === PNCP_Watermark::rebuild( (int) $id, 'apply' === $mode ) ) {
				++$errors;
			}
			$cursor = (int) $id;
			update_option( 'pncp_wm_cursor_' . $mode, $cursor, false );
		}
		$done = count( $ids ) < max( 1, $batch );
		if ( $done ) {
			delete_option( 'pncp_wm_cursor_' . $mode );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πρόοδος του εργαλείου.
		$position = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_mime_type IN ('image/jpeg','image/png','image/webp') AND ID <= %d", $cursor ) );
		wp_send_json_success(
			array(
				'cursor'   => $cursor,
				'position' => $position,
				'errors'   => $errors,
				'done'     => $done,
			)
		);
	}

	/**
	 * Καρτέλα «Κανόνες server».
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function tab_rules( $s ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Ίδια υπογραφή με τις άλλες καρτέλες.
		?>
		<p><?php esc_html_e( 'Το plugin ελέγχει μόνο αιτήματα που φτάνουν στην PHP. Σελίδες από page cache, εικόνες και στατικά αρχεία τα σερβίρει απευθείας ο server ή το CDN. Οι παρακάτω κανόνες είναι φτιαγμένοι για το δικό σας site, με τις τρέχουσες ρυθμίσεις. Δοκιμάστε τους πρώτα σε staging.', 'content-protect' ); ?></p>
		<p class="description"><?php esc_html_e( 'Το plugin δεν κρατά API token του Cloudflare στη βάση: εσείς περνάτε τους κανόνες, εκεί που έχετε ήδη πρόσβαση.', 'content-protect' ); ?></p>

		<h2><?php esc_html_e( 'Cloudflare', 'content-protect' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Security → WAF → Custom rules → Create rule → Edit expression. Επικολλήστε την έκφραση και επιλέξτε την ενέργεια που αναφέρεται.', 'content-protect' ); ?></p>
		<?php foreach ( PNCP_Rules::cloudflare() as $key => $rule ) : ?>
			<h3><?php echo esc_html( $rule['title'] ); ?> <span class="pncp-badge"><?php echo esc_html( $rule['action'] ); ?></span></h3>
			<?php self::code_block( 'pncp-cf-' . $key, $rule['expression'], 3 ); ?>
		<?php endforeach; ?>

		<h2><?php esc_html_e( 'Nginx', 'content-protect' ); ?></h2>
		<p class="description"><?php esc_html_e( '1) Μέσα στο http { }, π.χ. στο αρχείο /etc/nginx/conf.d/content-protect.conf:', 'content-protect' ); ?></p>
		<?php self::code_block( 'pncp-nginx-http', PNCP_Rules::nginx_http(), 8 ); ?>
		<p class="description"><?php esc_html_e( '2) Μέσα στο server { } του site, πριν από τα υπόλοιπα location. Μετά: nginx -t και reload.', 'content-protect' ); ?></p>
		<?php self::code_block( 'pncp-nginx-server', PNCP_Rules::nginx_server(), 18 ); ?>

		<h2><?php esc_html_e( 'Apache (.htaccess, πάνω από το # BEGIN WordPress)', 'content-protect' ); ?></h2>
		<?php self::code_block( 'pncp-apache', PNCP_Rules::apache(), 14 ); ?>
		<?php
	}

	/**
	 * Πεδίο κώδικα μόνο για ανάγνωση με κουμπί αντιγραφής.
	 *
	 * @param string $id   ID.
	 * @param string $code Κώδικας.
	 * @param int    $rows Γραμμές.
	 */
	private static function code_block( $id, $code, $rows ) {
		printf(
			'<div class="pncp-code"><textarea id="%1$s" class="large-text code" rows="%2$d" readonly aria-label="%3$s">%4$s</textarea><p><button type="button" class="button pncp-copy" data-target="%1$s">%5$s</button></p></div>',
			esc_attr( $id ),
			(int) $rows,
			esc_attr__( 'Κανόνες για αντιγραφή', 'content-protect' ),
			esc_textarea( $code ),
			esc_html__( 'Αντιγραφή', 'content-protect' )
		);
	}

	/**
	 * Καρτέλα «Αρχείο»: σύνοψη 24ώρου, ενεργοί αποκλεισμοί, τελευταία συμβάντα.
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 */
	private static function tab_log( $s ) {
		$summary = PNCP_Log::summary( 24 );
		$reasons = PNCP_Log::reasons();
		$bans    = PNCP_Log::active_bans();
		$format  = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		?>
		<h2><?php esc_html_e( 'Τελευταίες 24 ώρες', 'content-protect' ); ?></h2>
		<p class="pncp-big-number"><?php echo esc_html( sprintf( /* translators: %s: πλήθος */ __( '%s μπλοκαρισμένα αιτήματα', 'content-protect' ), number_format_i18n( $summary['total'] ) ) ); ?></p>
		<div class="pncp-cards">
			<section class="pncp-card">
				<h3><?php esc_html_e( 'Ανά λόγο', 'content-protect' ); ?></h3>
				<?php self::count_list( $summary['reasons'], $reasons ); ?>
			</section>
			<section class="pncp-card">
				<h3><?php esc_html_e( 'Κορυφαίες IP', 'content-protect' ); ?></h3>
				<?php self::count_list( $summary['ips'] ); ?>
			</section>
			<section class="pncp-card">
				<h3><?php esc_html_e( 'Κορυφαία User-Agents', 'content-protect' ); ?></h3>
				<?php self::count_list( $summary['uas'] ); ?>
			</section>
		</div>

		<h2><?php esc_html_e( 'Αποκλεισμένες IP τώρα', 'content-protect' ); ?></h2>
		<?php if ( ! $bans ) : ?>
			<p><?php esc_html_e( 'Καμία.', 'content-protect' ); ?></p>
		<?php else : ?>
			<table class="widefat striped pncp-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'IP', 'content-protect' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Αιτία', 'content-protect' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Λήγει', 'content-protect' ); ?></th>
						<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Ενέργεια', 'content-protect' ); ?></span></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( array_slice( $bans, 0, 200, true ) as $ip => $ban ) : ?>
						<tr>
							<td><code><?php echo esc_html( $ip ); ?></code></td>
							<td><?php echo esc_html( isset( $reasons[ $ban['reason'] ] ) ? $reasons[ $ban['reason'] ] : $ban['reason'] ); ?></td>
							<td><?php echo esc_html( wp_date( $format, (int) $ban['until'] ) ); ?></td>
							<td>
								<?php self::action_form_open( 'pncp_log', 'pncp_log', 'pncp-inline-form' ); ?>
									<input type="hidden" name="op" value="unban">
									<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>">
									<button type="submit" class="button button-small"><?php esc_html_e( 'Άρση', 'content-protect' ); ?></button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
				<input type="hidden" name="op" value="unban_all">
				<?php submit_button( __( 'Άρση όλων', 'content-protect' ), 'secondary', 'submit', true ); ?>
			</form>
		<?php endif; ?>

		<h2><?php esc_html_e( 'Τελευταία συμβάντα', 'content-protect' ); ?></h2>
		<?php $rows = PNCP_Log::recent( 100 ); ?>
		<?php if ( ! $rows ) : ?>
			<p><?php esc_html_e( 'Δεν υπάρχουν συμβάντα.', 'content-protect' ); ?></p>
		<?php else : ?>
			<table class="widefat striped pncp-table pncp-log-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Ώρα', 'content-protect' ); ?></th>
						<th scope="col"><?php esc_html_e( 'IP', 'content-protect' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Λόγος', 'content-protect' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Αιτήματα', 'content-protect' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Διαδρομή', 'content-protect' ); ?></th>
						<th scope="col"><?php esc_html_e( 'User-Agent', 'content-protect' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $rows as $row ) : ?>
						<tr>
							<td><?php echo esc_html( wp_date( $format, (int) strtotime( $row['created'] . ' UTC' ) ) ); ?></td>
							<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
							<td><?php echo esc_html( ( isset( $reasons[ $row['reason'] ] ) ? $reasons[ $row['reason'] ] : $row['reason'] ) . ' (' . $row['code'] . ')' ); ?></td>
							<td><?php echo esc_html( number_format_i18n( (int) $row['hits'] ) ); ?></td>
							<td><code><?php echo esc_html( $row['path'] ); ?></code></td>
							<td class="pncp-ua"><?php echo esc_html( $row['ua'] ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<p class="description">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: ημέρες */
					__( 'Το αρχείο σβήνεται αυτόματα μετά από %s ημέρες (ρύθμιση στην καρτέλα «Bots και όρια»).', 'content-protect' ),
					$s['log_retention']
				)
			);
			?>
		</p>
		<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
			<input type="hidden" name="op" value="clear_log">
			<?php submit_button( __( 'Διαγραφή αρχείου', 'content-protect' ), 'delete', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Λίστα «τιμή — πλήθος».
	 *
	 * @param array<string, int>    $counts Πλήθη.
	 * @param array<string, string> $labels Ετικέτες (προαιρετικά).
	 */
	private static function count_list( $counts, $labels = array() ) {
		if ( ! $counts ) {
			echo '<p>' . esc_html__( 'Τίποτα.', 'content-protect' ) . '</p>';
			return;
		}
		echo '<ol class="pncp-count-list">';
		foreach ( $counts as $key => $count ) {
			printf( '<li><span>%s</span> <strong>%s</strong></li>', esc_html( isset( $labels[ $key ] ) ? $labels[ $key ] : (string) $key ), esc_html( number_format_i18n( $count ) ) );
		}
		echo '</ol>';
	}

	/* ---------- Ενέργειες ---------- */

	/**
	 * Έλεγχος δικαιώματος και nonce για τις ενέργειες.
	 *
	 * @param string $nonce Nonce action.
	 */
	private static function verify( $nonce ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Δεν έχετε δικαίωμα να αλλάξετε αυτή τη ρύθμιση.', 'content-protect' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce );
	}

	/**
	 * Επιστροφή σε καρτέλα με μήνυμα.
	 *
	 * @param string $tab     Καρτέλα.
	 * @param string $message Κωδικός μηνύματος.
	 */
	private static function back( $tab, $message ) {
		wp_safe_redirect(
			PNCP_Status::settings_url(
				array(
					'tab'          => $tab,
					'pncp_message' => $message,
				)
			)
		);
		exit;
	}

	/**
	 * Εφαρμογή προφίλ.
	 */
	public static function handle_profile() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Το nonce ελέγχεται στο verify().
		self::verify( 'pncp_profile' );
		$profile  = isset( $_POST['profile'] ) ? sanitize_key( wp_unslash( $_POST['profile'] ) ) : '';
		$profiles = PNCP_Options::profiles();
		if ( ! isset( $profiles[ $profile ] ) ) {
			self::back( 'general', 'error' );
		}
		update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $profiles[ $profile ] ) );
		PNCP_Options::flush();
		self::back( 'general', 'profile' );
		// phpcs:enable
	}

	/**
	 * Token: νέο / εναλλαγή / ακύρωση του προηγούμενου.
	 */
	public static function handle_token() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Το nonce ελέγχεται στο verify().
		self::verify( 'pncp_token' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( 'rotate' === $op ) {
			$grace = isset( $_POST['grace'] ) ? absint( $_POST['grace'] ) : 0;
			$grace = in_array( $grace, array( 0, 1, 7, 30 ), true ) ? $grace : 7;
			$token = PNCP_Private_Urls::rotate( $grace );
			// Μία εμφάνιση, μόνο σε αυτόν τον χρήστη, για λίγα λεπτά.
			set_transient( 'pncp_new_token_' . get_current_user_id(), $token, 10 * MINUTE_IN_SECONDS );
			self::back( 'content', 'token' );
		}
		if ( 'revoke_prev' === $op ) {
			PNCP_Private_Urls::revoke_previous();
			self::back( 'content', 'revoked' );
		}
		self::back( 'content', 'error' );
		// phpcs:enable
	}

	/**
	 * Αρχείο και αποκλεισμοί.
	 */
	public static function handle_log() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Το nonce ελέγχεται στο verify().
		self::verify( 'pncp_log' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		switch ( $op ) {
			case 'unban':
				$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					PNCP_Log::unban( $ip );
				}
				self::back( 'log', 'unbanned' );
				break;
			case 'unban_all':
				PNCP_Log::unban_all();
				self::back( 'log', 'unbanned' );
				break;
			case 'clear_log':
				PNCP_Log::clear();
				self::back( 'log', 'cleared' );
				break;
			case 'refresh_lists':
				$result = PNCP_Ip::refresh_lists();
				self::back( 'bots', in_array( 0, $result, true ) ? 'lists_partial' : 'lists' );
				break;
		}
		self::back( 'general', 'error' );
		// phpcs:enable
	}

	/**
	 * Μηνύματα μετά τις ενέργειες, και ειδοποιήσεις της αναβάθμισης από την 1.4.
	 */
	public static function upgrade_notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$ours   = $screen && 'settings_page_' . self::PAGE === $screen->id;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Μόνο εμφάνιση μηνύματος.
		$message = $ours && isset( $_GET['pncp_message'] ) ? sanitize_key( wp_unslash( $_GET['pncp_message'] ) ) : '';
		$texts   = array(
			'profile'       => array( 'success', __( 'Το προφίλ εφαρμόστηκε.', 'content-protect' ) ),
			'token'         => array( 'success', __( 'Δημιουργήθηκε νέο token.', 'content-protect' ) ),
			'revoked'       => array( 'success', __( 'Το προηγούμενο token ακυρώθηκε.', 'content-protect' ) ),
			'unbanned'      => array( 'success', __( 'Ο αποκλεισμός άρθηκε.', 'content-protect' ) ),
			'cleared'       => array( 'success', __( 'Το αρχείο διαγράφηκε.', 'content-protect' ) ),
			'lists'         => array( 'success', __( 'Οι λίστες IP ανανεώθηκαν.', 'content-protect' ) ),
			'lists_partial' => array( 'warning', __( 'Κάποιες λίστες IP δεν κατέβηκαν· κρατήθηκε η προηγούμενη εκδοχή τους. Θα ξαναδοκιμάσει αύριο.', 'content-protect' ) ),
			'error'         => array( 'error', __( 'Η ενέργεια δεν ολοκληρώθηκε.', 'content-protect' ) ),
		);
		if ( isset( $texts[ $message ] ) ) {
			printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $texts[ $message ][0] ), esc_html( $texts[ $message ][1] ) );
		}

		// Το token της 1.x ισχύει ακόμη, αλλά υπάρχει μόνο ως hash: δεν μπορεί να εμφανιστεί.
		if ( $ours && get_option( 'pncp_legacy_token_migrated' ) ) {
			delete_option( 'pncp_legacy_token_migrated' );
			printf(
				'<div class="notice notice-info"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
				esc_html__( 'Από την 2.1 το token των feeds αποθηκεύεται μόνο ως hash. Το παλιό token εξακολουθεί να ισχύει, αλλά δεν μπορεί πλέον να εμφανιστεί. Αν δεν το έχετε αποθηκευμένο, δημιουργήστε νέο token.', 'content-protect' ),
				esc_url( PNCP_Status::settings_url( array( 'tab' => 'feeds' ) ) ),
				esc_html__( 'Feeds και token', 'content-protect' )
			);
		}
		if ( ! empty( PNCP_Options::stored()['trust_any_proxy'] ) ) {
			printf(
				'<div class="notice notice-warning"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
				esc_html__( 'Προστασία περιεχομένου: η πραγματική IP διαβάζεται από header χωρίς έλεγχο του proxy (όπως στην 1.4). Αυτό επιτρέπει πλαστογράφηση της IP.', 'content-protect' ),
				esc_url( PNCP_Status::settings_url( array( 'tab' => 'bots' ) ) ),
				esc_html__( 'Ρύθμιση Trusted Proxy', 'content-protect' )
			);
		}
	}
}
