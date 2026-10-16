<?php
/**
 * Προστασία στον server: scrapers και AI bots, ψεύτικες μηχανές αναζήτησης, όρια ανά endpoint,
 * προσωρινός αποκλεισμός IP, παγίδα για bots και robots.txt.
 *
 * Ισχύει μόνο για αιτήματα που φτάνουν στην PHP. Σελίδες που σερβίρονται από page cache
 * (Nginx FastCGI, WP Rocket κ.λπ.) δεν περνούν από εδώ: δείτε τους κανόνες server στις ρυθμίσεις.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Bots, όρια και αποκλεισμοί.
 */
final class PNCP_Bots {

	/**
	 * Μηχανές αναζήτησης που επαληθεύονται: μοτίβα User-Agent, domains reverse DNS και επίσημη λίστα IP.
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private static $crawlers = array(
		'google' => array(
			'ua'   => array( 'googlebot', 'google-inspectiontool', 'storebot-google', 'adsbot-google', 'mediapartners-google', 'googleother', 'feedfetcher-google', 'google-read-aloud', 'apis-google', 'google-site-verification', 'google-safety' ),
			'dns'  => array( '.googlebot.com', '.google.com' ),
			'list' => 'google',
		),
		'bing'   => array(
			'ua'   => array( 'bingbot', 'adidxbot', 'bingpreview', 'msnbot' ),
			'dns'  => array( '.search.msn.com' ),
			'list' => 'bing',
		),
		'apple'  => array(
			'ua'   => array( 'applebot' ),
			'dns'  => array( '.applebot.apple.com' ),
			'list' => '',
		),
		'yandex' => array(
			'ua'   => array( 'yandexbot', 'yandeximages', 'yandexmobilebot', 'yandexmetrika' ),
			'dns'  => array( '.yandex.ru', '.yandex.net', '.yandex.com' ),
			'list' => '',
		),
	);

	/**
	 * Δένει τα hooks.
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'trap_guard' ), 0 );
		add_action( 'template_redirect', array( __CLASS__, 'page_guard' ), 0 );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'rest_guard' ), 0, 3 );
		add_action( 'wp_footer', array( __CLASS__, 'trap_link' ), 99 );
		add_filter( 'wp_speculation_rules_href_exclude_paths', array( __CLASS__, 'speculation_exclude' ) );
		add_filter( 'robots_txt', array( __CLASS__, 'robots_txt' ), 99, 2 );
		// Οι μπλοκαρισμένοι User-Agents δεν παίρνουν σελίδες από την cache του WP Rocket, ώστε να φτάσουν εδώ.
		add_filter( 'rocket_cache_reject_ua', array( __CLASS__, 'rocket_reject_ua' ) );
	}

	/**
	 * Η IP του επισκέπτη (για συμβατότητα με κώδικα που καλούσε την 1.4).
	 *
	 * @return string
	 */
	public static function client_ip() {
		return PNCP_Ip::client_ip();
	}

	/**
	 * Το User-Agent του αιτήματος.
	 *
	 * @return string
	 */
	public static function user_agent() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
	}

	/**
	 * Προβολές σελίδων και αναζήτηση.
	 */
	public static function page_guard() {
		if ( is_robots() || is_favicon() ) {
			return;
		}
		$verdict = self::check( is_search() ? 'search' : 'page' );
		if ( $verdict ) {
			self::die_html( $verdict['code'] );
		}
	}

	/**
	 * REST API (/wp-json/): μόνο για αιτήματα ανάγνωσης από επισκέπτες.
	 *
	 * @param mixed           $result  Αποτέλεσμα (null = συνέχεια).
	 * @param WP_REST_Server  $server  Server.
	 * @param WP_REST_Request $request Αίτημα.
	 * @return mixed
	 */
	public static function rest_guard( $result, $server, $request ) {
		if ( null !== $result || ! $request instanceof WP_REST_Request ) {
			return $result;
		}
		// Μόνο ανάγνωση: καλάθι, ταμείο, φόρμες και webhooks πληρωμών (POST) δεν ελέγχονται.
		if ( ! in_array( strtoupper( (string) $request->get_method() ), array( 'GET', 'HEAD' ), true ) ) {
			return $result;
		}
		// Το Store API του WooCommerce (καλάθι, mini-cart) καλείται από κάθε σελίδα: δεν μετρά στο όριο.
		$count   = 0 !== strpos( (string) $request->get_route(), '/wc/store' );
		$verdict = self::check( 'rest', $count );
		if ( ! $verdict ) {
			return $result;
		}
		// Το 403 / 429 δεν πρέπει να μπει σε cache του REST (π.χ. LiteSpeed Cache).
		self::no_cache();
		do_action( 'litespeed_control_set_nocache', 'content-protect' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Hook του LiteSpeed Cache.
		if ( 429 === $verdict['code'] ) {
			$server->send_header( 'Retry-After', '60' );
		}
		return new WP_Error(
			429 === $verdict['code'] ? 'pncp_rate_limited' : 'pncp_forbidden',
			429 === $verdict['code'] ? __( 'Πάρα πολλά αιτήματα. Δοκιμάστε ξανά σε ένα λεπτό.', 'content-protect' ) : __( 'Η πρόσβαση δεν επιτρέπεται.', 'content-protect' ),
			array( 'status' => $verdict['code'] )
		);
	}

	/**
	 * Ο κεντρικός έλεγχος.
	 *
	 * Bots, ψεύτικες μηχανές αναζήτησης και αποκλεισμοί ισχύουν για κάθε μέθοδο (μια σελίδα δίνεται και με
	 * POST). Τα όρια μετρούν μόνο προβολές (GET/HEAD, όχι prefetch), ώστε φόρμες και ταμείο να μη μετράνε.
	 *
	 * @param string $context page | search | rest | graphql.
	 * @param bool   $count   Να μετρήσει στο όριο.
	 * @return array{code:int, reason:string}|null Null αν το αίτημα περνά.
	 */
	public static function check( $context, $count = true ) {
		$s = PNCP_Options::get();
		// Όχι εξαίρεση για wp_doing_ajax(): το WooCommerce δηλώνει DOING_AJAX στα wc-ajax, οπότε κάθε bot θα
		// περνούσε (επιβεβαιωμένο με πραγματικό WooCommerce). Το admin-ajax.php δεν φτάνει έτσι κι αλλιώς εδώ.
		if ( empty( $s['enabled'] ) || wp_doing_cron() ) {
			return null;
		}
		// Εξαιρούνται μόνο οι ρόλοι της ρύθμισης «Ποιοι εξαιρούνται», όχι κάθε συνδεδεμένος χρήστης: ένας
		// λογαριασμός πελάτη στο WooCommerce φτιάχνεται από τον καθένα. Στο REST / GraphQL εξαιρούνται και όσοι
		// γράφουν περιεχόμενο, γιατί ο block editor κάνει δεκάδες αιτήματα το λεπτό.
		if ( PNCP_Options::user_is_exempt( $s ) || ( in_array( $context, array( 'rest', 'graphql' ), true ) && current_user_can( 'edit_posts' ) ) ) {
			return null;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'graphql' !== $context && ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) || self::is_prefetch() ) ) {
			$count = false;
		}
		// AJAX του WooCommerce (καλάθι, ταμείο): δεν μετρά στο όριο σελίδων, αλλά bots, ψεύτικοι crawlers και
		// αποκλεισμοί ελέγχονται κανονικά. Μόνο για ενέργειες που έχει δηλώσει το WooCommerce (ή επέκτασή του).
		if ( self::is_wc_ajax() || ( 'page' === $context && self::is_shop_transaction_page() ) ) {
			$count = false;
		}
		// Ιδιωτικό URL (XML feed) με σωστό token: η υπηρεσία μπορεί να έχει οποιοδήποτε User-Agent.
		if ( PNCP_Private_Urls::granted() ) {
			return null;
		}

		$ua = self::user_agent();
		$ip = PNCP_Ip::client_ip();

		if ( '' === $ip || PNCP_Ip::is_local( $ip ) ) {
			return null;
		}
		// Πάντα επιτρεπτές IP: μόνο αν η IP δεν μπορεί να πλαστογραφηθεί (όχι «εμπιστοσύνη σε κάθε proxy»).
		if ( PNCP_Ip::reliable() && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['allow_ips'] ) ) ) {
			return null;
		}

		/**
		 * Φίλτρο για να αφήσετε ένα αίτημα να περάσει όλους τους ελέγχους.
		 *
		 * @param bool   $skip    Αν θα παραλειφθεί ο έλεγχος.
		 * @param string $context page | search | rest | graphql.
		 * @param string $ip      IP.
		 */
		if ( apply_filters( 'pncp_skip_guard', false, $context, $ip ) ) {
			return null;
		}

		// Πρώτα η επαλήθευση: μια πραγματική μηχανή αναζήτησης περνά ακόμη κι αν κάποιος κατάφερε να
		// αποκλειστεί η IP της.
		$family = self::claimed_crawler( $ua );
		if ( '' !== $family && self::is_verified_crawler( $family, $ip ) ) {
			return null; // Επαληθευμένες μηχανές αναζήτησης: ποτέ μπλοκάρισμα, ποτέ όριο.
		}

		if ( PNCP_Log::is_banned( $ip ) ) {
			return self::verdict( 403, 'banned', $ip );
		}

		if ( '' !== $family && ! empty( $s['block_fake_crawlers'] ) ) {
			PNCP_Log::strike( $ip, 'fake_crawler' );
			return self::verdict( 403, 'fake_crawler', $ip );
		}

		$allowed_ua = '' !== $ua && self::ua_in_list( $ua, array_merge( PNCP_Options::parse_list( $s['allow_list'] ), PNCP_Options::allowed_ai_search() ) );

		if ( ! empty( $s['block_bots'] ) && ! $allowed_ua ) {
			if ( '' === trim( $ua ) && ! empty( $s['block_empty_ua'] ) ) {
				return self::verdict( 403, 'empty_ua', $ip );
			}
			if ( '' !== $ua && self::ua_in_list( $ua, PNCP_Options::parse_list( $s['bot_list'] ) ) ) {
				return self::verdict( 403, 'bot_ua', $ip );
			}
		}

		// Κάθε browser στέλνει Accept-Language και «Mozilla/» στο User-Agent· τα περισσότερα scripts όχι.
		// Όχι στα wc-ajax: κάποιες πύλες πληρωμών / επεκτάσεις τα καλούν από server, χωρίς Accept-Language.
		if ( ! empty( $s['require_browser_headers'] ) && ! $allowed_ua && in_array( $context, array( 'page', 'search' ), true ) && ! self::is_wc_ajax() && ! self::looks_like_browser( $ua ) ) {
			return self::verdict( 403, 'no_browser', $ip );
		}

		$limits = array(
			'page'    => array( 'rate_limit', 'rate_page' ),
			'search'  => array( 'rate_limit_search', 'rate_search' ),
			'rest'    => array( 'rate_limit_rest', 'rate_rest' ),
			'graphql' => array( 'rate_limit_rest', 'rate_rest' ),
		);
		if ( $count && isset( $limits[ $context ] ) ) {
			$limit = (int) $s[ $limits[ $context ][0] ];
			if ( $limit > 0 ) {
				$count = self::hit( $ip, $limits[ $context ][1] );
				if ( $count > $limit ) {
					// Μία «παράβαση» ανά λεπτό που ξεπεράστηκε το όριο, όχι μία ανά αίτημα.
					if ( $count === $limit + 1 ) {
						PNCP_Log::strike( $ip, $limits[ $context ][1] );
					}
					return self::verdict( 429, $limits[ $context ][1], $ip );
				}
			}
		}

		return null;
	}

	/**
	 * Καταγράφει και επιστρέφει την απόφαση.
	 *
	 * @param int    $code   HTTP κωδικός.
	 * @param string $reason Λόγος.
	 * @param string $ip     IP.
	 * @return array{code:int, reason:string}
	 */
	private static function verdict( $code, $reason, $ip ) {
		PNCP_Log::add( $reason, $code, $ip );
		return array(
			'code'   => $code,
			'reason' => $reason,
		);
	}

	/**
	 * Είναι πραγματικό αίτημα wc-ajax; Το WooCommerce πρέπει να είναι ενεργό και η ενέργεια δηλωμένη
	 * (`wc_ajax_{ενέργεια}`), αλλιώς ένα σκέτο ?wc-ajax=x στο URL θα αρκούσε.
	 *
	 * @return bool
	 */
	public static function is_wc_ajax() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Μόνο το όνομα της ενέργειας.
		$action = isset( $_GET['wc-ajax'] ) ? sanitize_key( wp_unslash( $_GET['wc-ajax'] ) ) : '';
		return '' !== $action && class_exists( 'WooCommerce' ) && has_action( 'wc_ajax_' . $action );
	}

	/**
	 * Σελίδα συναλλαγής του WooCommerce (καλάθι, ταμείο, «Ευχαριστούμε», «Ο λογαριασμός μου»). Δεν μετρά
	 * στο όριο σελίδων: ένας πελάτης που αγοράζει ανοίγει 4–5 τέτοιες σελίδες μέσα σε ένα λεπτό.
	 * Bots και αποκλεισμοί ελέγχονται κανονικά.
	 *
	 * @return bool
	 */
	public static function is_shop_transaction_page() {
		if ( ! function_exists( 'is_cart' ) || ! did_action( 'wp' ) ) {
			return false;
		}
		// Όχι σκέτο is_wc_endpoint_url(): είναι true για κάθε URL με ?orders=1 κ.λπ., άρα θα έκλεινε το όριο παντού.
		// Η σελίδα «Ευχαριστούμε» και οι σελίδες λογαριασμού καλύπτονται από τα is_checkout() / is_account_page().
		return is_cart() || is_checkout() || is_account_page();
	}

	/**
	 * Prefetch / prerender (browser, επέκταση ή speculative loading): δεν είναι προβολή.
	 *
	 * @return bool
	 */
	public static function is_prefetch() {
		foreach ( array( 'HTTP_SEC_PURPOSE', 'HTTP_PURPOSE', 'HTTP_X_MOZ', 'HTTP_X_PURPOSE' ) as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) && false !== stripos( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ), 'prefetch' ) ) {
				return true;
			}
		}
		return ! empty( $_SERVER['HTTP_SEC_PURPOSE'] ) && false !== stripos( sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_PURPOSE'] ) ), 'prerender' );
	}

	/**
	 * Μοιάζει με browser;
	 *
	 * @param string $ua User-Agent.
	 * @return bool
	 */
	private static function looks_like_browser( $ua ) {
		$lang = isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ) : '';
		return '' !== trim( $lang ) && 0 === strpos( $ua, 'Mozilla/' );
	}

	/**
	 * Ταιριάζει το User-Agent με κάποιο στοιχείο της λίστας; (υποσυμβολοσειρά, χωρίς διάκριση πεζών/κεφαλαίων)
	 *
	 * @param string   $ua   User-Agent.
	 * @param string[] $needles Λίστα.
	 * @return bool
	 */
	public static function ua_in_list( $ua, $needles ) {
		foreach ( $needles as $needle ) {
			if ( '' !== $needle && false !== stripos( $ua, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Ποια μηχανή αναζήτησης δηλώνει το User-Agent ('' = καμία).
	 *
	 * @param string $ua User-Agent.
	 * @return string
	 */
	public static function claimed_crawler( $ua ) {
		foreach ( self::$crawlers as $family => $def ) {
			if ( self::ua_in_list( $ua, $def['ua'] ) ) {
				return $family;
			}
		}
		return '';
	}

	/**
	 * Είναι πραγματική μηχανή αναζήτησης; Πρώτα η επίσημη λίστα IP (Google, Bing), μετά reverse DNS
	 * και forward DNS που πρέπει να επιστρέφει την ίδια IP. Θετικό αποτέλεσμα 24 ώρες, αρνητικό 1 ώρα.
	 *
	 * @param string $family google | bing | apple | yandex.
	 * @param string $ip     IP.
	 * @return bool
	 */
	public static function is_verified_crawler( $family, $ip ) {
		if ( ! isset( self::$crawlers[ $family ] ) || '' === $ip ) {
			return false;
		}
		$def = self::$crawlers[ $family ];
		if ( '' !== $def['list'] && PNCP_Ip::in_any( $ip, PNCP_Ip::list_of( $def['list'] ) ) ) {
			return true;
		}

		$key    = 'pncp_se_' . md5( $family . '|' . $ip );
		$cached = PNCP_Log::cache_get( $key );
		if ( false !== $cached ) {
			return 'yes' === $cached;
		}

		// Το DNS μπλοκάρει τον PHP worker: έως 20 έλεγχοι το λεπτό σε όλο το site. Πάνω από αυτό, μη
		// επαληθευμένο (Google και Bing επαληθεύονται ήδη από τις λίστες IP, χωρίς DNS).
		$budget = 'pncp_dns_' . (int) floor( time() / MINUTE_IN_SECONDS );
		$used   = (int) PNCP_Log::cache_get( $budget );
		if ( $used >= (int) apply_filters( 'pncp_dns_lookups_per_minute', 20 ) ) {
			return false;
		}
		PNCP_Log::cache_set( $budget, $used + 1, 2 * MINUTE_IN_SECONDS );

		$verified = false;
		$host     = (string) apply_filters( 'pncp_reverse_dns', null, $ip );
		if ( '' === $host ) {
			$host = (string) gethostbyaddr( $ip );
		}
		if ( $host && $host !== $ip ) {
			$host_lc = strtolower( rtrim( $host, '.' ) );
			foreach ( $def['dns'] as $domain ) {
				if ( substr( $host_lc, -strlen( $domain ) ) === $domain ) {
					$verified = in_array( $ip, self::forward_ips( $host_lc ), true );
					break;
				}
			}
		}

		PNCP_Log::cache_set( $key, $verified ? 'yes' : 'no', $verified ? DAY_IN_SECONDS : HOUR_IN_SECONDS );
		return $verified;
	}

	/**
	 * Ανήκει η IP στις επίσημες λίστες της Google ή της Bing; (τέτοιες IP δεν αποκλείονται ποτέ)
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_official_crawler_ip( $ip ) {
		return PNCP_Ip::in_any( $ip, PNCP_Ip::list_of( 'google' ) ) || PNCP_Ip::in_any( $ip, PNCP_Ip::list_of( 'bing' ) );
	}

	/**
	 * Οι IPv4/IPv6 ενός hostname.
	 *
	 * @param string $host Hostname.
	 * @return string[]
	 */
	private static function forward_ips( $host ) {
		$pre = apply_filters( 'pncp_forward_dns', null, $host );
		if ( is_array( $pre ) ) {
			return $pre;
		}
		$ips     = array();
		$records = @dns_get_record( $host, DNS_A | DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Αποτυχία DNS = μη επαληθευμένο.
		if ( is_array( $records ) ) {
			foreach ( $records as $record ) {
				if ( ! empty( $record['ip'] ) ) {
					$ips[] = $record['ip'];
				}
				if ( ! empty( $record['ipv6'] ) ) {
					$ips[] = inet_ntop( inet_pton( $record['ipv6'] ) );
				}
			}
		}
		return $ips;
	}

	/**
	 * Μετράει τα αιτήματα της IP στο τρέχον λεπτό, ανά είδος. Object cache αν υπάρχει, αλλιώς transient.
	 *
	 * @param string $ip     IP.
	 * @param string $bucket Είδος (rate_page, rate_search, rate_rest).
	 * @return int
	 */
	private static function hit( $ip, $bucket ) {
		$key = 'pncp_rl_' . md5( $bucket . '|' . $ip ) . '_' . (int) floor( time() / MINUTE_IN_SECONDS );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_add( $key, 0, 'pncp', 2 * MINUTE_IN_SECONDS );
			return (int) wp_cache_incr( $key, 1, 'pncp' );
		}
		$count = self::db_incr( $key, 2 * MINUTE_IN_SECONDS );
		if ( null !== $count ) {
			return $count;
		}
		// Βάση χωρίς ON DUPLICATE KEY (π.χ. SQLite): απλό transient, όχι ατομικό.
		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, 2 * MINUTE_IN_SECONDS );
		return $count;
	}

	/**
	 * Ατομικός μετρητής στη βάση, για sites χωρίς object cache. Με ταυτόχρονα αιτήματα, το «διάβασε +1
	 * γράψε» των transients χάνει μετρήσεις (επιβεβαιωμένο: όριο 50, πέρναγαν έως 65). Εδώ η αύξηση
	 * γίνεται μέσα στη MySQL και η νέα τιμή διαβάζεται με LAST_INSERT_ID() της ίδιας σύνδεσης.
	 * Γράφεται ως κανονικό transient (με timeout), οπότε το καθαρίζει το WordPress όπως όλα τα transients.
	 *
	 * @param string $key Κλειδί transient.
	 * @param int    $ttl Δευτερόλεπτα.
	 * @return int|null Null αν η βάση δεν το υποστηρίζει.
	 */
	private static function db_incr( $key, $ttl ) {
		global $wpdb;
		if ( ! ( $wpdb instanceof wpdb ) || ! ( $wpdb->dbh instanceof mysqli ) ) {
			return null;
		}
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Ατομικός μετρητής: δεν γίνεται με το options API.
		$rows = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, '1', 'off')
				ON DUPLICATE KEY UPDATE option_value = LAST_INSERT_ID(option_value + 1)",
				'_transient_' . $key
			)
		);
		if ( false === $rows ) {
			$wpdb->suppress_errors( $suppress );
			return null;
		}
		$insert_id = (int) $wpdb->insert_id; // mysqli_insert_id() της ίδιας σύνδεσης (εγγραφής): = option_value + 1.
		if ( 1 === (int) $rows ) {
			// Νέα εγγραφή: η λήξη, για τον καθαρισμό των transients.
			$wpdb->query(
				$wpdb->prepare(
					"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'off')",
					'_transient_timeout_' . $key,
					(string) ( time() + (int) $ttl )
				)
			);
			$count = 1;
		} else {
			// Όχι ξεχωριστό SELECT LAST_INSERT_ID(): με HyperDB / read-write split θα πήγαινε σε replica.
			$count = $insert_id;
			if ( $count < 2 ) {
				$wpdb->suppress_errors( $suppress );
				return null; // Απρόσμενο: πίσω στο transient.
			}
		}
		// phpcs:enable
		$wpdb->suppress_errors( $suppress );
		return $count;
	}

	/**
	 * Η απάντηση δεν μπαίνει σε καμία cache: headers για browsers / CDN, DONOTCACHEPAGE για τα plugins
	 * cache της PHP (WP Super Cache, W3TC, WP Rocket κ.ά.) και X-LiteSpeed-Cache-Control για τον LiteSpeed.
	 * Αλλιώς ένα 403 για bot θα σερβιριζόταν μετά σε επισκέπτες, ή ένα feed με token σε όλους.
	 */
	public static function no_cache() {
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Σταθερά των plugins cache.
		}
		if ( ! headers_sent() ) {
			nocache_headers();
			header( 'X-LiteSpeed-Cache-Control: no-cache' );
		}
	}

	/**
	 * Τερματίζει το αίτημα με 403 ή 429, χωρίς να μπει στην cache.
	 *
	 * @param int $code HTTP κωδικός.
	 */
	public static function die_html( $code ) {
		self::no_cache();
		if ( 429 === $code ) {
			header( 'Retry-After: 60' );
			$message = __( 'Πάρα πολλά αιτήματα. Δοκιμάστε ξανά σε ένα λεπτό.', 'content-protect' );
		} else {
			$message = __( 'Η πρόσβαση δεν επιτρέπεται.', 'content-protect' );
		}
		wp_die( esc_html( $message ), esc_html( (string) $code ), array( 'response' => (int) $code ) );
	}

	/* ---------- Παγίδα για bots ---------- */

	/**
	 * Η διαδρομή της παγίδας: σταθερή για το site, διαφορετική σε κάθε site.
	 *
	 * @return string π.χ. /cp-a1b2c3d4e5/
	 */
	public static function trap_path() {
		return '/cp-' . substr( hash_hmac( 'sha256', 'pncp-trap', wp_salt( 'nonce' ) ), 0, 10 ) . '/';
	}

	/**
	 * Αόρατος σύνδεσμος στο τέλος κάθε σελίδας: οι άνθρωποι δεν τον βλέπουν, οι screen readers
	 * τον αγνοούν (aria-hidden, tabindex=-1), οι μηχανές αναζήτησης τον αγνοούν (robots.txt, nofollow).
	 */
	public static function trap_link() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['trap_enabled'] ) || PNCP_Options::user_is_exempt( $s ) ) {
			return;
		}
		printf(
			'<a href="%s" rel="nofollow noindex" tabindex="-1" aria-hidden="true" class="pncp-hp" style="position:absolute!important;left:-10000px!important;top:auto!important;width:1px!important;height:1px!important;overflow:hidden!important">%s</a>',
			esc_url( home_url( self::trap_path() ) ),
			esc_html__( 'Αρχείο', 'content-protect' )
		);
	}

	/**
	 * Το speculative loading του WordPress δεν προφορτώνει ποτέ την παγίδα.
	 *
	 * @param string[] $paths Διαδρομές.
	 * @return string[]
	 */
	public static function speculation_exclude( $paths ) {
		$paths   = (array) $paths;
		$paths[] = self::trap_path() . '*';
		return $paths;
	}

	/**
	 * Όποιος ανοίγει την παγίδα αποκλείεται.
	 *
	 * Ένα ξένο site δεν μπορεί να κάνει τους επισκέπτες σας να αποκλειστούν (π.χ. με <img src="…παγίδα">):
	 * οι browsers στέλνουν Sec-Fetch-Site/Sec-Fetch-Dest, και αποκλεισμός γίνεται μόνο για πλοήγηση
	 * από το ίδιο το site ή για αίτημα χωρίς αυτά τα headers (bots). Το prefetch δεν μετράει.
	 */
	public static function trap_guard() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['trap_enabled'] ) ) {
			return;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = PNCP_Private_Urls::relative_path( rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) ) );
		if ( 0 !== stripos( trailingslashit( $path ), self::trap_path() ) ) {
			return;
		}

		self::no_cache();
		header( 'X-Robots-Tag: noindex, nofollow' );

		$ip = PNCP_Ip::client_ip();
		if ( self::trap_should_ban( $ip ) ) {
			PNCP_Log::add( 'trap', 403, $ip );
			// «Αποκλεισμός μετά από 0 παραβάσεις» = ποτέ αποκλεισμός: μόνο καταγραφή.
			if ( (int) $s['ban_strikes'] > 0 ) {
				PNCP_Log::ban( $ip, (int) $s['ban_minutes'], 'trap' );
			}
		}

		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo 'Forbidden';
		exit;
	}

	/**
	 * Μηχανές αναζήτησης χωρίς επαλήθευση (δεν δημοσιεύουν λίστες IP / DNS που ελέγχουμε). Αν δεν είδαν
	 * το Disallow (π.χ. φυσικό robots.txt ή παλιό αντίγραφο), δεν αποκλείονται από την παγίδα.
	 *
	 * @return string[]
	 */
	public static function trap_exempt_agents() {
		return (array) apply_filters( 'pncp_trap_exempt_agents', array( 'DuckDuckBot', 'Baiduspider', 'SeznamBot', 'PetalBot', 'Sogou', 'Yeti', 'Qwantbot', 'MojeekBot', 'Ecosia' ) );
	}

	/**
	 * Πρέπει να αποκλειστεί η IP που άνοιξε την παγίδα;
	 *
	 * Ποτέ: συνδεδεμένοι χρήστες, ο server, πάντα επιτρεπτές IP, IP της Google / Bing, μηχανές αναζήτησης,
	 * IP που ίσως είναι πλαστογραφημένη (εμπιστοσύνη σε κάθε proxy), prefetch, αιτήματα από ξένο site ή
	 * που δεν είναι πλοήγηση, και κλικ ανθρώπου (Sec-Fetch-User, π.χ. σύνδεσμος σε σχόλιο).
	 * Browser χωρίς Sec-Fetch (παλιό Safari / Firefox): αποκλεισμός μόνο στη δεύτερη φορά μέσα σε 10 λεπτά.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private static function trap_should_ban( $ip ) {
		$s = PNCP_Options::get();
		if ( '' === $ip || PNCP_Options::user_is_exempt( $s ) || PNCP_Ip::is_local( $ip ) || ! PNCP_Ip::reliable() || self::is_official_crawler_ip( $ip ) ) {
			return false;
		}
		if ( PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['allow_ips'] ) ) ) {
			return false;
		}
		$ua     = self::user_agent();
		$family = self::claimed_crawler( $ua );
		if ( ( '' !== $family && self::is_verified_crawler( $family, $ip ) ) || self::ua_in_list( $ua, self::trap_exempt_agents() ) ) {
			return false;
		}
		if ( self::is_prefetch() ) {
			return false;
		}
		$header = static function ( $name ) {
			return isset( $_SERVER[ $name ] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER[ $name ] ) ) ) : '';
		};
		$site   = $header( 'HTTP_SEC_FETCH_SITE' );
		$dest   = $header( 'HTTP_SEC_FETCH_DEST' );
		if ( '' !== $site && ! in_array( $site, array( 'same-origin', 'none' ), true ) ) {
			return false; // Από ξένο site (cross-site / same-site): όχι αποκλεισμός.
		}
		if ( '' !== $dest && 'document' !== $dest ) {
			return false; // Εικόνα, iframe, script κ.λπ.: όχι πλοήγηση.
		}
		if ( '?1' === $header( 'HTTP_SEC_FETCH_USER' ) ) {
			return false; // Κλικ ανθρώπου σε σύνδεσμο (π.χ. κάποιος έβαλε τη διεύθυνση σε σχόλιο).
		}
		if ( '' === $site && 0 === strpos( $ua, 'Mozilla/' ) ) {
			// Browser χωρίς Sec-Fetch: ίσως παλιός browser που φόρτωσε <img> ξένου site. Δεύτερη φορά = bot.
			$key  = 'pncp_tr_' . md5( $ip );
			$seen = (int) PNCP_Log::cache_get( $key );
			PNCP_Log::cache_set( $key, $seen + 1, 10 * MINUTE_IN_SECONDS );
			return $seen >= 1;
		}
		return true;
	}

	/* ---------- robots.txt και WP Rocket ---------- */

	/**
	 * Τα AI crawlers που δηλώνονται στο robots.txt.
	 *
	 * @return string[]
	 */
	public static function robots_agents() {
		return (array) apply_filters(
			'pncp_robots_ai_agents',
			array( 'GPTBot', 'ChatGPT-User', 'OAI-SearchBot', 'CCBot', 'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'anthropic-ai', 'PerplexityBot', 'Perplexity-User', 'Bytespider', 'Google-Extended', 'Google-CloudVertexBot', 'Applebot-Extended', 'meta-externalagent', 'meta-externalfetcher', 'FacebookBot', 'Amazonbot', 'Diffbot', 'cohere-ai', 'cohere-training-data-crawler', 'AI2Bot', 'Ai2Bot-Dolma', 'YouBot', 'DuckAssistBot', 'MistralAI-User', 'PanguBot', 'Timpibot', 'omgili', 'Webzio-Extended', 'ImagesiftBot', 'img2dataset', 'TikTokSpider' )
		);
	}

	/**
	 * Disallow για AI crawlers και για την παγίδα στο εικονικό robots.txt. Δεν αγγίζει μηχανές αναζήτησης.
	 *
	 * @param string $output    Το robots.txt.
	 * @param bool   $is_public Αν το site επιτρέπει ευρετηρίαση.
	 * @return string
	 */
	public static function robots_txt( $output, $is_public ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || ! $is_public ) {
			return $output;
		}

		$block = '';
		if ( ! empty( $s['trap_enabled'] ) ) {
			$block .= "\n# Content Protect\nUser-agent: *\nDisallow: " . wp_parse_url( home_url( self::trap_path() ), PHP_URL_PATH ) . "\n";
		}
		if ( ! empty( $s['robots_ai_block'] ) ) {
			$block .= "\n# Content Protect: AI crawlers\n";
			$search = array_map( 'strtolower', PNCP_Options::allowed_ai_search() );
			foreach ( self::robots_agents() as $agent ) {
				if ( in_array( strtolower( $agent ), $search, true ) ) {
					continue; // AI αναζήτηση επιτρεπτή: δεν δηλώνεται Disallow.
				}
				$block .= 'User-agent: ' . $agent . "\n";
			}
			$block .= "Disallow: /\n";
		}
		return '' === $block ? $output : rtrim( $output ) . "\n" . $block;
	}

	/**
	 * Λέει στο WP Rocket να μη σερβίρει cache στους μπλοκαρισμένους User-Agents.
	 *
	 * @param string[] $uas User-Agents.
	 * @return string[]
	 */
	public static function rocket_reject_ua( $uas ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['block_bots'] ) ) {
			return $uas;
		}
		$uas    = (array) $uas;
		$search = array_map( 'strtolower', PNCP_Options::allowed_ai_search() );
		foreach ( PNCP_Options::parse_list( $s['bot_list'] ) as $needle ) {
			if ( in_array( strtolower( $needle ), $search, true ) ) {
				continue;
			}
			$uas[] = preg_quote( $needle, '#' );
		}
		return $uas;
	}
}
