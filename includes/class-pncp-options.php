<?php
/**
 * Ρυθμίσεις: προεπιλογές, ανάγνωση, καθάρισμα εισόδου, προφίλ και Emergency Mode.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Κεντρικό σημείο για το option `pncp_settings`.
 *
 * - stored():    ό,τι έχει αποθηκευτεί, συμπληρωμένο με προεπιλογές (για τη σελίδα ρυθμίσεων).
 * - get():       οι ρυθμίσεις που ισχύουν τώρα: stored() + αυστηρότερες τιμές όσο τρέχει το Emergency Mode.
 */
final class PNCP_Options {

	/**
	 * Option με τη λήξη του Emergency Mode (timestamp, 0 = ανενεργό).
	 */
	const EMERGENCY_OPTION = 'pncp_emergency_until';

	/**
	 * Cache του get() για το τρέχον αίτημα.
	 *
	 * @var array<string, mixed>|null
	 */
	private static $cache = null;

	/**
	 * Επιτρεπτές τιμές για τα πεδία επιλογής.
	 *
	 * @return array<string, string[]>
	 */
	public static function choices() {
		return array(
			'copy_mode'          => array( 'block', 'attribution', 'allow' ),
			'print_mode'         => array( 'allow', 'source', 'block' ),
			'exempt_cap'         => array( 'manage_options', 'edit_others_posts', 'edit_posts', 'none' ),
			'feed_mode'          => array( 'full', 'excerpt', 'disabled' ),
			'ip_header'          => array( 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip', 'true_client_ip' ),
			'watermark_position' => array( 'br', 'bl', 'tr', 'tl', 'center', 'tiled' ),
			'log_retention'      => array( '1', '7', '30' ),
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
			'block_text_drag',
			'blur_on_capture',
			'show_message',
			'skip_woo_pages',
			'rest_hide_content',
			'graphql_hide_content',
			'block_bots',
			'block_empty_ua',
			'block_fake_crawlers',
			'require_browser_headers',
			'trap_enabled',
			'robots_ai_block',
			'allow_ai_search',
			'block_framing',
			'tdm_reservation',
			'trust_cloudflare',
			'trust_any_proxy',
			'watermark_enabled',
			'watermark_full',
			'watermark_products',
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
			'rate_limit_search'     => array( 0, 10000 ),
			'rate_limit_rest'       => array( 0, 10000 ),
			'ban_strikes'           => array( 0, 20 ),
			'ban_minutes'           => array( 1, 10080 ),
			'watermark_image_id'    => array( 0, PHP_INT_MAX ),
			'watermark_opacity'     => array( 10, 100 ),
			'watermark_size'        => array( 5, 60 ),
			'watermark_min_width'   => array( 0, 5000 ),
		);
	}

	/**
	 * Πεδία-λίστες (μία τιμή ανά γραμμή).
	 *
	 * @return string[]
	 */
	public static function list_keys() {
		return array( 'bot_list', 'allow_list', 'private_paths' );
	}

	/**
	 * Πεδία με IP / CIDR (μία ανά γραμμή).
	 *
	 * @return string[]
	 */
	public static function ip_list_keys() {
		return array( 'private_ips', 'allow_ips', 'trusted_proxies' );
	}

	/**
	 * Σε ποια καρτέλα της σελίδας ρυθμίσεων ανήκει κάθε πεδίο. Κάθε καρτέλα αποθηκεύει μόνο τα δικά της
	 * πεδία· τα υπόλοιπα κρατούν την τιμή τους.
	 *
	 * @return array<string, string[]>
	 */
	public static function sections() {
		return array(
			'general' => array( 'enabled', 'scope_posts', 'scope_pages', 'scope_home', 'scope_products', 'skip_woo_pages', 'excluded_ids', 'block_selection', 'block_context_menu', 'block_shortcuts', 'block_devtools', 'block_image_drag', 'block_text_drag', 'blur_on_capture', 'copy_mode', 'attribution_min_chars', 'print_mode', 'exempt_cap', 'show_message', 'message', 'block_framing', 'tdm_reservation', 'tdm_policy_url' ),
			'bots'    => array( 'block_bots', 'block_empty_ua', 'block_fake_crawlers', 'require_browser_headers', 'trap_enabled', 'bot_list', 'allow_list', 'allow_ips', 'allow_ai_search', 'robots_ai_block', 'rate_limit', 'rate_limit_search', 'rate_limit_rest', 'ban_strikes', 'ban_minutes', 'log_retention', 'ip_header', 'trust_cloudflare', 'trust_any_proxy', 'trusted_proxies' ),
			'content' => array( 'rest_hide_content', 'graphql_hide_content', 'feed_mode', 'private_paths', 'private_ips' ),
			'images'  => array( 'watermark_enabled', 'watermark_full', 'watermark_products', 'watermark_image_id', 'watermark_opacity', 'watermark_size', 'watermark_position', 'watermark_min_width' ),
		);
	}

	/**
	 * Η λίστα της 1.4 (για να ξέρει η αναβάθμιση αν ο χρήστης την είχε αλλάξει).
	 *
	 * @return string[]
	 */
	public static function legacy_bot_list() {
		return array( 'GPTBot', 'ChatGPT-User', 'CCBot', 'ClaudeBot', 'Claude-Web', 'anthropic-ai', 'PerplexityBot', 'Bytespider', 'meta-externalagent', 'Diffbot', 'ImagesiftBot', 'Scrapy', 'HTTrack', 'curl/', 'Wget/', 'python-requests', 'python-urllib', 'aiohttp', 'Go-http-client' );
	}

	/**
	 * Οι User-Agents που μπλοκάρονται από προεπιλογή (υποσυμβολοσειρά, χωρίς διάκριση πεζών/κεφαλαίων).
	 * Δεν περιέχει ποτέ μηχανές αναζήτησης, previews κοινωνικών δικτύων ή πλατφόρμες σύγκρισης τιμών.
	 *
	 * @return string[]
	 */
	public static function default_bot_entries() {
		return array_merge(
			self::legacy_bot_list(),
			array(
				// AI crawlers και agents.
				'OAI-SearchBot',
				'Claude-User',
				'Claude-SearchBot',
				'Perplexity-User',
				'Google-CloudVertexBot',
				'Applebot-Extended',
				'meta-externalfetcher',
				'FacebookBot',
				'Amazonbot',
				'cohere-ai',
				'cohere-training-data-crawler',
				'AI2Bot',
				'Ai2Bot-Dolma',
				'YouBot',
				'DuckAssistBot',
				'MistralAI-User',
				'PanguBot',
				'Timpibot',
				'omgili',
				'Webzio-Extended',
				'Kangaroo Bot',
				'Sidetrade indexer bot',
				'VelenPublicWebCrawler',
				'ICC-Crawler',
				'img2dataset',
				'Brightbot',
				'TikTokSpider',
				'iaskspider',
				'QualifiedBot',
				// Εργαλεία scraping και headless browsers.
				'HeadlessChrome',
				'PhantomJS',
				'Puppeteer',
				'Playwright',
				'Selenium',
				'Firecrawl',
				'Apify',
				'crawl4ai',
				'ScrapingBee',
				'Zyte',
				'node-fetch',
				'axios/',
				'okhttp',
				'libwww-perl',
				'Java/',
				'httpx',
				'colly',
				'Nutch',
			)
		);
	}

	/**
	 * AI μηχανές αναζήτησης και βοηθοί: φέρνουν το site στις απαντήσεις (με σύνδεσμο) ή ανοίγουν μια σελίδα
	 * επειδή τη ζήτησε ένας χρήστης. Δεν είναι οι crawlers εκπαίδευσης (GPTBot, ClaudeBot, CCBot,
	 * Google-Extended, Applebot-Extended κ.ά.), που μένουν μπλοκαρισμένοι.
	 *
	 * @return string[]
	 */
	public static function ai_search_agents() {
		return (array) apply_filters(
			'pncp_ai_search_agents',
			array( 'OAI-SearchBot', 'ChatGPT-User', 'Claude-SearchBot', 'Claude-User', 'PerplexityBot', 'Perplexity-User', 'DuckAssistBot', 'MistralAI-User' )
		);
	}

	/**
	 * Οι AI μηχανές αναζήτησης που επιτρέπονται με τις τρέχουσες ρυθμίσεις (κενό αν η επιλογή είναι ανενεργή).
	 *
	 * @return string[]
	 */
	public static function allowed_ai_search() {
		return empty( self::get()['allow_ai_search'] ) ? array() : self::ai_search_agents();
	}

	/**
	 * Η προεπιλεγμένη λίστα ως κείμενο.
	 *
	 * @return string
	 */
	public static function default_bot_list() {
		return implode( "\n", self::default_bot_entries() );
	}

	/**
	 * User-Agents που περνούν πάντα τον έλεγχο λίστας και «headers browser» (previews συνδέσμων, πλατφόρμες
	 * τιμών, monitoring). Το User-Agent πλαστογραφείται, οπότε το όριο σελίδων ισχύει κανονικά και για αυτούς.
	 *
	 * @return string
	 */
	public static function default_allow_list() {
		return implode(
			"\n",
			array( 'facebookexternalhit', 'Facebot', 'Twitterbot', 'LinkedInBot', 'WhatsApp', 'TelegramBot', 'Slackbot', 'Discordbot', 'Pinterest', 'Viber', 'SkypeUriPreview', 'Skroutz', 'BestPrice', 'UptimeRobot', 'Pingdom', 'Jetpack' )
		);
	}

	/**
	 * Προεπιλογές.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults() {
		return array(
			'enabled'                 => 1,
			'scope_posts'             => 1,
			'scope_pages'             => 1,
			'scope_home'              => 1,
			'scope_products'          => 1,
			'block_selection'         => 1,
			'block_context_menu'      => 1,
			'block_shortcuts'         => 1,
			'block_devtools'          => 1,
			'block_image_drag'        => 1,
			'block_text_drag'         => 1,
			'blur_on_capture'         => 0,
			'show_message'            => 1,
			'skip_woo_pages'          => 1,
			'copy_mode'               => 'attribution',
			'attribution_min_chars'   => 200,
			'print_mode'              => 'source',
			'exempt_cap'              => 'edit_posts',
			'excluded_ids'            => '',
			// Πριν από το after_setup_theme (π.χ. στον έλεγχο των feeds) οι μεταφράσεις δεν φορτώνονται ακόμη.
			'message'                 => did_action( 'after_setup_theme' ) ? __( 'Το περιεχόμενο αυτής της σελίδας προστατεύεται.', 'content-protect' ) : 'Το περιεχόμενο αυτής της σελίδας προστατεύεται.',
			'rest_hide_content'       => 1,
			'graphql_hide_content'    => 1,
			'feed_mode'               => 'excerpt',
			'block_bots'              => 1,
			'block_empty_ua'          => 1,
			'block_fake_crawlers'     => 1,
			'require_browser_headers' => 0,
			'trap_enabled'            => 1,
			'bot_list'                => self::default_bot_list(),
			'allow_list'              => self::default_allow_list(),
			'allow_ips'               => '',
			'robots_ai_block'         => 1,
			'allow_ai_search'         => 0,
			'block_framing'           => 1,
			'tdm_reservation'         => 1,
			'tdm_policy_url'          => '',
			'rate_limit'              => 0,
			'rate_limit_search'       => 0,
			'rate_limit_rest'         => 0,
			'ban_strikes'             => 3,
			'ban_minutes'             => 60,
			'log_retention'           => '7',
			'ip_header'               => 'remote_addr',
			'trust_cloudflare'        => 1,
			'trust_any_proxy'         => 0,
			'trusted_proxies'         => '',
			'private_paths'           => '',
			'private_ips'             => '',
			'watermark_enabled'       => 0,
			'watermark_full'          => 0,
			'watermark_products'      => 0,
			'watermark_image_id'      => 0,
			'watermark_opacity'       => 50,
			'watermark_size'          => 25,
			'watermark_position'      => 'br',
			'watermark_min_width'     => 300,
		);
	}

	/**
	 * Τα έτοιμα προφίλ: τιμές που γράφονται στις ρυθμίσεις όταν πατηθεί το κουμπί.
	 * Δεν αγγίζουν πεδία, λίστες, feeds, υδατογράφημα και IP.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function profiles() {
		$base = array(
			'block_bots'          => 1,
			'block_empty_ua'      => 1,
			'block_fake_crawlers' => 1,
			'trap_enabled'        => 1,
			'robots_ai_block'     => 1,
			'block_framing'       => 1,
			'tdm_reservation'     => 1,
			'rest_hide_content'   => 1,
			'block_context_menu'  => 1,
			'block_image_drag'    => 1,
			'block_text_drag'     => 1,
			'block_shortcuts'     => 1,
			'block_devtools'      => 1,
		);
		return array(
			'balanced' => array_merge(
				$base,
				array(
					'block_selection'         => 0,
					'copy_mode'               => 'attribution',
					'print_mode'              => 'source',
					'feed_mode'               => 'excerpt',
					'require_browser_headers' => 0,
					'blur_on_capture'         => 0,
					'rate_limit'              => 60,
					'rate_limit_search'       => 20,
					'rate_limit_rest'         => 60,
					'ban_strikes'             => 3,
					'ban_minutes'             => 60,
				)
			),
			'strict'   => array_merge(
				$base,
				array(
					'block_selection'         => 1,
					'copy_mode'               => 'block',
					'print_mode'              => 'source',
					'feed_mode'               => 'excerpt',
					'require_browser_headers' => 0,
					'blur_on_capture'         => 0,
					'rate_limit'              => 40,
					'rate_limit_search'       => 10,
					'rate_limit_rest'         => 30,
					'ban_strikes'             => 2,
					'ban_minutes'             => 180,
				)
			),
			'maximum'  => array_merge(
				$base,
				array(
					'block_selection'         => 1,
					'copy_mode'               => 'block',
					'print_mode'              => 'block',
					'feed_mode'               => 'disabled',
					'require_browser_headers' => 1,
					'blur_on_capture'         => 1,
					'rate_limit'              => 30,
					'rate_limit_search'       => 6,
					'rate_limit_rest'         => 20,
					'ban_strikes'             => 2,
					'ban_minutes'             => 720,
				)
			),
		);
	}

	/**
	 * Ποιο προφίλ ταιριάζει ακριβώς με τις ρυθμίσεις (ή '' για «Προσαρμοσμένο»).
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 * @return string
	 */
	public static function current_profile( $s ) {
		foreach ( self::profiles() as $name => $values ) {
			$match = true;
			foreach ( $values as $key => $value ) {
				if ( (string) $s[ $key ] !== (string) $value ) {
					$match = false;
					break;
				}
			}
			if ( $match ) {
				return $name;
			}
		}
		return '';
	}

	/**
	 * Οι αυστηρότερες τιμές του Emergency Mode. Τα όρια παίρνουν το μικρότερο από τα δύο.
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 * @return array<string, mixed>
	 */
	public static function emergency_overlay( $s ) {
		$min = static function ( $current, $cap ) {
			$current = (int) $current;
			return $current > 0 ? min( $current, $cap ) : $cap;
		};
		return array(
			'block_bots'              => 1,
			'block_empty_ua'          => 1,
			'block_fake_crawlers'     => 1,
			'require_browser_headers' => 1,
			'trap_enabled'            => 1,
			'rest_hide_content'       => 1,
			'graphql_hide_content'    => 1,
			'block_framing'           => 1,
			'feed_mode'               => 'full' === $s['feed_mode'] ? 'excerpt' : $s['feed_mode'],
			'rate_limit'              => $min( $s['rate_limit'], 20 ),
			'rate_limit_search'       => $min( $s['rate_limit_search'], 5 ),
			'rate_limit_rest'         => $min( $s['rate_limit_rest'], 10 ),
			'ban_strikes'             => 2,
			'ban_minutes'             => max( (int) $s['ban_minutes'], 360 ),
		);
	}

	/**
	 * Πότε λήγει το Emergency Mode (0 = ανενεργό).
	 *
	 * @return int
	 */
	public static function emergency_until() {
		$until = (int) get_option( self::EMERGENCY_OPTION, 0 );
		return $until > time() ? $until : 0;
	}

	/**
	 * Ξεκινά ή σταματά το Emergency Mode.
	 *
	 * @param int $hours Διάρκεια σε ώρες (0 = τέλος).
	 */
	public static function set_emergency( $hours ) {
		$hours = max( 0, min( 72, (int) $hours ) );
		update_option( self::EMERGENCY_OPTION, $hours ? time() + $hours * HOUR_IN_SECONDS : 0, true );
		self::flush();
		pncp_purge_page_cache();
	}

	/**
	 * Οι αποθηκευμένες ρυθμίσεις, συμπληρωμένες με προεπιλογές.
	 *
	 * @return array<string, mixed>
	 */
	public static function stored() {
		$stored = get_option( PNCP_OPTION, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::defaults(), $stored );
	}

	/**
	 * Οι ρυθμίσεις που ισχύουν τώρα (με το Emergency Mode, αν τρέχει).
	 *
	 * @return array<string, mixed>
	 */
	public static function get() {
		if ( null === self::$cache ) {
			$s = self::stored();
			if ( ! empty( $s['enabled'] ) && self::emergency_until() ) {
				$s = array_merge( $s, self::emergency_overlay( $s ) );
			}
			self::$cache = $s;
		}
		return self::$cache;
	}

	/**
	 * Ξεχνά την cache του αιτήματος (μετά από αλλαγή ρυθμίσεων).
	 */
	public static function flush() {
		self::$cache = null;
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
			$value         = isset( $input[ $key ] ) ? sanitize_key( (string) $input[ $key ] ) : '';
			$clean[ $key ] = in_array( $value, $allowed, true ) ? $value : $defaults[ $key ];
		}

		foreach ( self::int_ranges() as $key => $range ) {
			$value         = isset( $input[ $key ] ) && '' !== $input[ $key ] ? (int) $input[ $key ] : $defaults[ $key ];
			$clean[ $key ] = max( $range[0], min( $range[1], $value ) );
		}

		$ids                   = isset( $input['excluded_ids'] ) ? (string) $input['excluded_ids'] : '';
		$ids                   = array_filter( array_map( 'absint', preg_split( '/[\s,]+/', $ids ) ) );
		$clean['excluded_ids'] = implode( ', ', array_unique( $ids ) );

		$message          = isset( $input['message'] ) ? sanitize_text_field( (string) $input['message'] ) : '';
		$clean['message'] = '' === $message ? $defaults['message'] : mb_substr( $message, 0, 200 );

		foreach ( self::list_keys() as $key ) {
			$clean[ $key ] = implode( "\n", self::parse_list( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' ) );
		}

		foreach ( self::ip_list_keys() as $key ) {
			$clean[ $key ] = implode( "\n", self::parse_ip_list( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' ) );
		}

		$policy                  = isset( $input['tdm_policy_url'] ) ? esc_url_raw( trim( (string) $input['tdm_policy_url'] ), array( 'https', 'http' ) ) : '';
		$clean['tdm_policy_url'] = (string) $policy;

		$stored = self::stored();

		// Η επιλογή «εμπιστοσύνη σε κάθε proxy» μένει μόνο για όσους την είχαν ήδη (αναβάθμιση από 1.4).
		// Από τη φόρμα μπορεί μόνο να κλείσει, όχι να ανοίξει (η αναβάθμιση την ανοίγει από κώδικα).
		if ( isset( $input['_sections'] ) && empty( $stored['trust_any_proxy'] ) ) {
			$clean['trust_any_proxy'] = 0;
		}

		// Φόρμα μιας καρτέλας: αλλάζουν μόνο τα πεδία της· τα υπόλοιπα κρατούν την αποθηκευμένη τιμή.
		if ( isset( $input['_sections'] ) ) {
			$keep = array();
			foreach ( self::sections() as $section => $keys ) {
				if ( ! in_array( $section, (array) $input['_sections'], true ) ) {
					$keep = array_merge( $keep, $keys );
				}
			}
			foreach ( $keep as $key ) {
				$clean[ $key ] = $stored[ $key ];
			}
		}

		self::flush();
		return $clean;
	}

	/**
	 * Λίστα γραμμών: χωρίς κενά, διπλότυπα και χαρακτήρες ελέγχου, έως 200 γραμμές των 100 χαρακτήρων.
	 *
	 * @param string $raw Κείμενο με μία τιμή ανά γραμμή.
	 * @return string[]
	 */
	public static function parse_list( $raw ) {
		$lines = preg_split( '/\r\n|\r|\n/', (string) $raw );
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
	 * Λίστα IP / CIDR: κρατά μόνο έγκυρες τιμές.
	 *
	 * @param string $raw Κείμενο με μία τιμή ανά γραμμή.
	 * @return string[]
	 */
	public static function parse_ip_list( $raw ) {
		$out = array();
		foreach ( self::parse_list( $raw ) as $range ) {
			if ( PNCP_Ip::valid_range( $range ) ) {
				$out[] = $range;
			}
		}
		return $out;
	}

	/**
	 * Τα IDs που εξαιρούνται, ως ακέραιοι.
	 *
	 * @param array<string, mixed> $settings Ρυθμίσεις.
	 * @return int[]
	 */
	public static function excluded_ids( $settings ) {
		return array_values( array_filter( array_map( 'absint', explode( ',', (string) $settings['excluded_ids'] ) ) ) );
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
