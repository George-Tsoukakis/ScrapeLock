<?php
/**
 * Ρυθμίσεις: προεπιλογές, ανάγνωση και καθάρισμα εισόδου.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Κεντρικό σημείο για το option `pncp_settings`.
 */
final class PNCP_Options {

	/**
	 * Επιτρεπτές τιμές για τα πεδία επιλογής.
	 *
	 * @return array<string, string[]>
	 */
	public static function choices() {
		return array(
			'copy_mode'  => array( 'block', 'attribution', 'allow' ),
			'print_mode' => array( 'allow', 'source', 'block' ),
			'exempt_cap' => array( 'manage_options', 'edit_others_posts', 'edit_posts', 'none' ),
			'feed_mode'  => array( 'full', 'excerpt', 'disabled' ),
			'ip_header'  => array( 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip', 'true_client_ip' ),
		);
	}

	/**
	 * Τα boolean πεδία.
	 *
	 * @return string[]
	 */
	public static function bool_keys() {
		return array(
			'enabled',
			'scope_posts',
			'scope_pages',
			'scope_home',
			'scope_products',
			'block_selection',
			'block_context_menu',
			'block_shortcuts',
			'block_devtools',
			'block_image_drag',
			'show_message',
			'skip_woo_pages',
			'rest_hide_content',
			'block_bots',
			'block_empty_ua',
			'robots_ai_block',
			'watermark_enabled',
		);
	}

	/**
	 * Ακέραια πεδία: κλειδί => [ελάχιστο, μέγιστο].
	 *
	 * @return array<string, int[]>
	 */
	public static function int_ranges() {
		return array(
			'attribution_min_chars' => array( 0, 10000 ),
			'rate_limit'            => array( 0, 10000 ),
			'watermark_image_id'    => array( 0, PHP_INT_MAX ),
			'watermark_opacity'     => array( 10, 100 ),
			'watermark_min_width'   => array( 0, 5000 ),
		);
	}

	/**
	 * Η προεπιλεγμένη λίστα με User-Agents που μπλοκάρονται (ένα ανά γραμμή, χωρίς διάκριση πεζών/κεφαλαίων).
	 * Δεν περιέχει ποτέ μηχανές αναζήτησης.
	 *
	 * @return string
	 */
	public static function default_bot_list() {
		return implode(
			"\n",
			array(
				'GPTBot',
				'ChatGPT-User',
				'CCBot',
				'ClaudeBot',
				'Claude-Web',
				'anthropic-ai',
				'PerplexityBot',
				'Bytespider',
				'meta-externalagent',
				'Diffbot',
				'ImagesiftBot',
				'Scrapy',
				'HTTrack',
				'curl/',
				'Wget/',
				'python-requests',
				'python-urllib',
				'aiohttp',
				'Go-http-client',
			)
		);
	}

	/**
	 * Προεπιλογές.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults() {
		return array(
			'enabled'               => 1,
			'scope_posts'           => 1,
			'scope_pages'           => 1,
			'scope_home'            => 1,
			'scope_products'        => 1,
			'block_selection'       => 1,
			'block_context_menu'    => 1,
			'block_shortcuts'       => 1,
			'block_devtools'        => 1,
			'block_image_drag'      => 1,
			'show_message'          => 1,
			'skip_woo_pages'        => 1,
			'copy_mode'             => 'attribution',
			'attribution_min_chars' => 200,
			'print_mode'            => 'source',
			'exempt_cap'            => 'edit_posts',
			'excluded_ids'          => '',
			'message'               => __( 'Το περιεχόμενο αυτής της σελίδας προστατεύεται.', 'content-protect' ),
			'rest_hide_content'     => 1,
			'feed_mode'             => 'excerpt',
			'block_bots'            => 1,
			'block_empty_ua'        => 1,
			'bot_list'              => self::default_bot_list(),
			'robots_ai_block'       => 1,
			'rate_limit'            => 0,
			'watermark_enabled'     => 0,
			'watermark_image_id'    => 0,
			'watermark_opacity'     => 50,
			'watermark_min_width'   => 300,
			'ip_header'             => 'remote_addr',
			'private_paths'         => '',
			'private_token'         => '',
			'private_ips'           => '',
		);
	}

	/**
	 * Οι αποθηκευμένες ρυθμίσεις, συμπληρωμένες με προεπιλογές.
	 *
	 * @return array<string, mixed>
	 */
	public static function get() {
		$stored = get_option( PNCP_OPTION, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::defaults(), $stored );
	}

	/**
	 * Καθαρίζει ό,τι έρχεται από τη φόρμα. Κρατά μόνο γνωστά κλειδιά.
	 *
	 * @param mixed $input Τιμές της φόρμας.
	 * @return array<string, mixed>
	 */
	public static function sanitize( $input ) {
		$input    = is_array( $input ) ? $input : array();
		$defaults = self::defaults();
		$clean    = array();

		foreach ( self::bool_keys() as $key ) {
			$clean[ $key ] = empty( $input[ $key ] ) ? 0 : 1;
		}

		foreach ( self::choices() as $key => $allowed ) {
			$value         = isset( $input[ $key ] ) ? sanitize_key( $input[ $key ] ) : '';
			$clean[ $key ] = in_array( $value, $allowed, true ) ? $value : $defaults[ $key ];
		}

		foreach ( self::int_ranges() as $key => $range ) {
			$value         = isset( $input[ $key ] ) && '' !== $input[ $key ] ? (int) $input[ $key ] : $defaults[ $key ];
			$clean[ $key ] = max( $range[0], min( $range[1], $value ) );
		}

		$ids = isset( $input['excluded_ids'] ) ? (string) $input['excluded_ids'] : '';
		$ids = array_filter( array_map( 'absint', preg_split( '/[\s,]+/', $ids ) ) );
		$clean['excluded_ids'] = implode( ', ', array_unique( $ids ) );

		$message          = isset( $input['message'] ) ? sanitize_text_field( $input['message'] ) : '';
		$clean['message'] = '' === $message ? $defaults['message'] : mb_substr( $message, 0, 200 );

		$clean['bot_list'] = implode( "\n", self::parse_list( isset( $input['bot_list'] ) ? (string) $input['bot_list'] : '' ) );

		$clean['private_paths'] = implode( "\n", self::parse_list( isset( $input['private_paths'] ) ? (string) $input['private_paths'] : '' ) );

		$ips = array();
		foreach ( self::parse_list( isset( $input['private_ips'] ) ? (string) $input['private_ips'] : '' ) as $range ) {
			$parts = explode( '/', $range, 2 );
			if ( ! filter_var( $parts[0], FILTER_VALIDATE_IP ) ) {
				continue;
			}
			$max = filter_var( $parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 128 : 32;
			if ( isset( $parts[1] ) && ( ! ctype_digit( $parts[1] ) || (int) $parts[1] > $max ) ) {
				continue;
			}
			$ips[] = $range;
		}
		$clean['private_ips'] = implode( "\n", $ips );

		// Token: μόνο γράμματα/αριθμοί. Αν είναι κενό, φτιάχνεται τυχαίο 32 χαρακτήρων.
		// Αν το πεδίο λείπει (αποθήκευση από κώδικα), κρατάμε το υπάρχον token, ώστε να μη σπάσουν τα URLs.
		$current = self::get()['private_token'];
		$token   = isset( $input['private_token'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', (string) $input['private_token'] ) : (string) $current;
		$clean['private_token'] = strlen( $token ) >= 16 ? substr( $token, 0, 64 ) : wp_generate_password( 32, false, false );

		return $clean;
	}

	/**
	 * Λίστα γραμμών: χωρίς κενά, διπλότυπα και χαρακτήρες ελέγχου, έως 200 γραμμές των 100 χαρακτήρων.
	 *
	 * @param string $raw Κείμενο με μία τιμή ανά γραμμή.
	 * @return string[]
	 */
	public static function parse_list( $raw ) {
		$lines = preg_split( '/\r\n|\r|\n/', $raw );
		$out   = array();
		foreach ( $lines as $line ) {
			$line = trim( sanitize_text_field( $line ) );
			if ( '' !== $line ) {
				$out[ strtolower( $line ) ] = mb_substr( $line, 0, 100 );
			}
		}
		return array_slice( array_values( $out ), 0, 200 );
	}

	/**
	 * Τα IDs που εξαιρούνται, ως ακέραιοι.
	 *
	 * @param array<string, mixed> $settings Ρυθμίσεις.
	 * @return int[]
	 */
	public static function excluded_ids( $settings ) {
		return array_filter( array_map( 'absint', explode( ',', (string) $settings['excluded_ids'] ) ) );
	}

	/**
	 * Εξαιρείται ο τρέχων χρήστης από την προστασία;
	 *
	 * @param array<string, mixed> $settings Ρυθμίσεις.
	 * @return bool
	 */
	public static function user_is_exempt( $settings ) {
		return 'none' !== $settings['exempt_cap'] && is_user_logged_in() && current_user_can( $settings['exempt_cap'] );
	}
}
