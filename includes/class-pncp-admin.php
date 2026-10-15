<?php
/**
 * Σελίδα ρυθμίσεων στο wp-admin (Ρυθμίσεις → Προστασία περιεχομένου).
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Admin UI, με το Settings API (nonce και capability τα ελέγχει το options.php).
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
		add_filter( 'plugin_action_links_' . plugin_basename( PNCP_FILE ), array( __CLASS__, 'action_links' ) );
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
	 * Σύνδεσμος «Ρυθμίσεις» στη λίστα πρόσθετων.
	 *
	 * @param string[] $links Σύνδεσμοι.
	 * @return string[]
	 */
	public static function action_links( $links ) {
		$url = admin_url( 'options-general.php?page=' . self::PAGE );
		array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Ρυθμίσεις', 'content-protect' ) . '</a>' );
		return $links;
	}

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
				checked( $s[ $key ], $value, false ),
				esc_html( $label )
			);
		}
		echo '</fieldset>';
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
	 * Η σελίδα ρυθμίσεων.
	 */
	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s = PNCP_Options::get();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Προστασία περιεχομένου', 'content-protect' ); ?></h1>
			<p><?php esc_html_e( 'Δυσκολεύει την αντιγραφή κειμένων και εικόνων από τους επισκέπτες. Οι συνδεδεμένοι συντάκτες, οι φόρμες, το καλάθι και το ταμείο δεν επηρεάζονται. Οι μηχανές αναζήτησης βλέπουν τη σελίδα κανονικά.', 'content-protect' ); ?></p>

			<form method="post" action="options.php">
				<?php settings_fields( self::GROUP ); ?>
				<table class="form-table" role="presentation">
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
							self::checkbox( $s, 'block_image_drag', __( 'Σύρσιμο εικόνων', 'content-protect' ) );
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
							?>
							<?php self::number( $s, 'attribution_min_chars', __( 'Η πηγή προσαρτάται από τόσους χαρακτήρες και πάνω:', 'content-protect' ), __( 'Μικρότερα αποσπάσματα (π.χ. μια λέξη ή ένα τηλέφωνο) αντιγράφονται χωρίς πηγή. 0 = πάντα.', 'content-protect' ) ); ?>
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
							<select id="pncp-exempt_cap" name="<?php echo esc_attr( PNCP_OPTION ); ?>[exempt_cap]">
								<?php
								$caps = array(
									'edit_posts'        => __( 'Συνδεδεμένοι συντάκτες και διαχειριστές', 'content-protect' ),
									'edit_others_posts' => __( 'Συνδεδεμένοι αρχισυντάκτες και διαχειριστές', 'content-protect' ),
									'manage_options'    => __( 'Μόνο οι διαχειριστές', 'content-protect' ),
									'none'              => __( 'Κανείς (για δοκιμή της προστασίας)', 'content-protect' ),
								);
								foreach ( $caps as $value => $label ) {
									printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( $s['exempt_cap'], $value, false ), esc_html( $label ) );
								}
								?>
							</select>
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
						<th scope="row"><?php esc_html_e( 'REST API', 'content-protect' ); ?></th>
						<td>
							<?php self::checkbox( $s, 'rest_hide_content', __( 'Κρύψιμο του κειμένου (content, excerpt) των άρθρων, σελίδων και προϊόντων από επισκέπτες', 'content-protect' ), __( 'Το REST μένει ανοιχτό για φόρμες, oEmbed, SEO plugins και δικά σας endpoints. Όσοι μπορούν να γράψουν άρθρα βλέπουν κανονικά το κείμενο. Εξαιρέσεις από κώδικα: φίλτρο pncp_rest_hide_content.', 'content-protect' ) ); ?>
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
					<tr>
						<th scope="row"><?php esc_html_e( 'Scrapers και AI bots', 'content-protect' ); ?></th>
						<td>
							<?php
							self::checkbox( $s, 'block_bots', __( 'Μπλοκάρισμα (403) των User-Agents της λίστας', 'content-protect' ) );
							self::checkbox( $s, 'block_empty_ua', __( 'Μπλοκάρισμα αιτημάτων χωρίς User-Agent', 'content-protect' ) );
							?>
							<p><label for="pncp-bot_list"><?php esc_html_e( 'Λίστα User-Agents (ένα ανά γραμμή, ταιριάζει οπουδήποτε στο User-Agent, χωρίς διάκριση πεζών/κεφαλαίων):', 'content-protect' ); ?></label></p>
							<textarea class="large-text code" rows="8" id="pncp-bot_list" name="<?php echo esc_attr( PNCP_OPTION ); ?>[bot_list]" aria-describedby="pncp-bot_list-help"><?php echo esc_textarea( $s['bot_list'] ); ?></textarea>
							<p class="description" id="pncp-bot_list-help"><?php esc_html_e( 'Επαληθευμένα Googlebot, Bingbot, Applebot και Yandex (με reverse DNS) δεν μπλοκάρονται ποτέ, ό,τι κι αν γράφει η λίστα. Το ίδιο ισχύει για συνδεδεμένους χρήστες και για αιτήματα από τον ίδιο τον server.', 'content-protect' ); ?></p>
							<?php self::checkbox( $s, 'robots_ai_block', __( 'Δήλωση των AI crawlers στο robots.txt (Disallow)', 'content-protect' ), __( 'Ισχύει για το εικονικό robots.txt του WordPress. Αν υπάρχει φυσικό αρχείο robots.txt, αυτό έχει προτεραιότητα.', 'content-protect' ) ); ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Όριο σελίδων ανά IP', 'content-protect' ); ?></th>
						<td>
							<?php self::number( $s, 'rate_limit', __( 'Σελίδες ανά λεπτό ανά IP για επισκέπτες (0 = ανενεργό):', 'content-protect' ), __( 'Πάνω από το όριο απαντά 429. Προσοχή σε δίκτυα με κοινή IP (εταιρείες, κινητή τηλεφωνία) και σε CDN: ορίστε πρώτα σωστά την «Πραγματική IP επισκέπτη». Τιμή εκκίνησης: 60. Σελίδες που σερβίρονται από page cache του server δεν μετράνε. Δείτε το README για αντίστοιχο κανόνα Nginx.', 'content-protect' ) ); ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="pncp-ip_header"><?php esc_html_e( 'Πραγματική IP επισκέπτη', 'content-protect' ); ?></label></th>
						<td>
							<select id="pncp-ip_header" name="<?php echo esc_attr( PNCP_OPTION ); ?>[ip_header]" aria-describedby="pncp-ip_header-help">
								<?php
								$headers = array(
									'remote_addr'      => __( 'REMOTE_ADDR (χωρίς CDN/proxy)', 'content-protect' ),
									'x_forwarded_for'  => 'X-Forwarded-For',
									'x_real_ip'        => 'X-Real-IP',
									'cf_connecting_ip' => 'CF-Connecting-IP (Cloudflare)',
									'true_client_ip'   => 'True-Client-IP',
								);
								foreach ( $headers as $value => $label ) {
									printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( $s['ip_header'], $value, false ), esc_html( $label ) );
								}
								?>
							</select>
							<p class="description" id="pncp-ip_header-help"><?php esc_html_e( 'Πίσω από CDN ή reverse proxy όλοι οι επισκέπτες φαίνονται με την IP του CDN. Τότε το όριο σελίδων και η επαλήθευση μηχανών αναζήτησης δεν δουλεύουν σωστά. Επιλέξτε το header που περιέχει την πραγματική IP, μόνο αν ο server δέχεται αιτήματα αποκλειστικά από το CDN (αλλιώς το header πλαστογραφείται). Καλύτερη λύση: real_ip στον Nginx.', 'content-protect' ); ?></p>
							<p class="description">
								<?php
								esc_html_e( 'Τι βλέπει ο server σε αυτό το αίτημα:', 'content-protect' );
								echo '<br><code>REMOTE_ADDR = ' . esc_html( isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '—' ) . '</code>';
								foreach ( PNCP_Bots::ip_headers() as $key ) {
									if ( ! empty( $_SERVER[ $key ] ) ) {
										echo '<br><code>' . esc_html( $key . ' = ' . sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) ) . '</code>';
									}
								}
								echo '<br>' . esc_html__( 'IP που χρησιμοποιεί τώρα το plugin:', 'content-protect' ) . ' <code>' . esc_html( PNCP_Bots::client_ip() ) . '</code>';
								?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Ιδιωτικά URLs (XML feeds)', 'content-protect' ); ?></th>
						<td>
							<p><label for="pncp-private_paths"><?php esc_html_e( 'Διαδρομές που δεν είναι δημόσιες (μία ανά γραμμή, το * σημαίνει «οτιδήποτε»), π.χ. /skroutz.xml, /feeds/*.xml:', 'content-protect' ); ?></label></p>
							<textarea class="large-text code" rows="4" id="pncp-private_paths" name="<?php echo esc_attr( PNCP_OPTION ); ?>[private_paths]"><?php echo esc_textarea( $s['private_paths'] ); ?></textarea>
							<p><label for="pncp-private_token"><?php esc_html_e( 'Μυστικό token (τουλάχιστον 16 γράμματα/αριθμοί· κενό = νέο τυχαίο):', 'content-protect' ); ?></label>
							<input type="text" class="regular-text code" id="pncp-private_token" name="<?php echo esc_attr( PNCP_OPTION ); ?>[private_token]" value="<?php echo esc_attr( $s['private_token'] ); ?>" autocomplete="off"></p>
							<?php
							$first = PNCP_Options::parse_list( $s['private_paths'] );
							if ( $first && '' !== $s['private_token'] ) {
								echo '<p class="description">' . esc_html__( 'Δώστε στην υπηρεσία το URL με το token, π.χ.:', 'content-protect' ) . '<br><code>' . esc_html( PNCP_Private_Urls::example_url( $first[0], $s['private_token'] ) ) . '</code></p>';
							}
							?>
							<p><label for="pncp-private_ips"><?php esc_html_e( 'Ή επιτρεπόμενες IP / CIDR της υπηρεσίας (μία ανά γραμμή):', 'content-protect' ); ?></label></p>
							<textarea class="large-text code" rows="3" id="pncp-private_ips" name="<?php echo esc_attr( PNCP_OPTION ); ?>[private_ips]" aria-describedby="pncp-private_ips-help"><?php echo esc_textarea( $s['private_ips'] ); ?></textarea>
							<p class="description" id="pncp-private_ips-help"><?php esc_html_e( 'Χωρίς σωστό token ή επιτρεπόμενη IP απαντά 403. Ισχύει για feeds που φτιάχνει η PHP. Στατικά αρχεία .xml (π.χ. μέσα στο uploads) τα σερβίρει απευθείας ο web server: για αυτά δείτε τον κανόνα Nginx στο README.', 'content-protect' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Υδατογράφημα εικόνων', 'content-protect' ); ?></th>
						<td>
							<?php
							self::checkbox( $s, 'watermark_enabled', __( 'Υδατογράφημα στα νέα uploads', 'content-protect' ), __( 'Μπαίνει στα μεγέθη που φτιάχνει το WordPress (thumbnails, medium, large). Το πρωτότυπο αρχείο δεν αλλάζει. Δεν επηρεάζει εικόνες που ανέβηκαν πριν.', 'content-protect' ) );
							if ( ! PNCP_Watermark::available() ) {
								echo '<p class="description"><strong>' . esc_html__( 'Η βιβλιοθήκη GD της PHP δεν είναι διαθέσιμη στον server, οπότε το υδατογράφημα δεν θα εφαρμοστεί.', 'content-protect' ) . '</strong></p>';
							}
							self::number( $s, 'watermark_image_id', __( 'ID εικόνας PNG από τη Βιβλιοθήκη πολυμέσων (0 = το domain του site ως κείμενο):', 'content-protect' ), __( 'Συνιστάται PNG με διάφανο φόντο (π.χ. το λογότυπο). Το ID φαίνεται στη διεύθυνση όταν ανοίγετε την εικόνα στη Βιβλιοθήκη.', 'content-protect' ) );
							self::number( $s, 'watermark_opacity', __( 'Αδιαφάνεια (%):', 'content-protect' ) );
							self::number( $s, 'watermark_min_width', __( 'Μόνο σε μεγέθη με πλάτος από (px):', 'content-protect' ), __( 'Τα μικρά thumbnails μένουν καθαρά.', 'content-protect' ) );
							?>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Αποθήκευση αλλαγών', 'content-protect' ) ); ?>
			</form>
		</div>
		<?php
	}
}
