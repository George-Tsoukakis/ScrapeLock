<?php
/**
 * Προστασία στον server: μπλοκάρισμα scraper/AI User-Agents, όριο σελίδων ανά IP, robots.txt.
 *
 * Ισχύει μόνο για αιτήματα που φτάνουν στην PHP. Σελίδες που σερβίρονται από page cache
 * (Nginx FastCGI, WP Rocket κ.λπ.) δεν περνούν από εδώ. Δείτε το README για κανόνες Nginx.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Bots και όριο αιτημάτων.
 */
final class PNCP_Bots {

	/**
	 * Μηχανές αναζήτησης που επαληθεύονται με reverse DNS: μοτίβο User-Agent => επιτρεπτά domains.
	 *
	 * @var array<string, string[]>
	 */
	private static $search_engines = array(
		'googlebot'             => array( '.googlebot.com', '.google.com' ),
		'google-inspectiontool' => array( '.googlebot.com', '.google.com' ),
		'bingbot'              => array( '.search.msn.com' ),
		'adidxbot'             => array( '.search.msn.com' ),
		'applebot'             => array( '.applebot.apple.com' ),
		'yandex'               => array( '.yandex.ru', '.yandex.net', '.yandex.com' ),
	);

	/**
	 * Δένει τα hooks.
	 */
	public static function init() {
		add_action( 'template_redirect', array( __CLASS__, 'guard' ), 0 );
		add_filter( 'robots_txt', array( __CLASS__, 'robots_txt' ), 99, 2 );
		// Οι μπλοκαρισμένοι User-Agents δεν παίρνουν σελίδες από την cache του WP Rocket, ώστε να φτάσουν εδώ.
		add_filter( 'rocket_cache_reject_ua', array( __CLASS__, 'rocket_reject_ua' ) );
	}

	/**
	 * Τα headers που μπορεί να φέρουν την πραγματική IP πίσω από CDN/proxy: ρύθμιση => κλειδί $_SERVER.
	 *
	 * @return array<string, string>
	 */
	public static function ip_headers() {
		return array(
			'x_forwarded_for'  => 'HTTP_X_FORWARDED_FOR',
			'x_real_ip'        => 'HTTP_X_REAL_IP',
			'cf_connecting_ip' => 'HTTP_CF_CONNECTING_IP',
			'true_client_ip'   => 'HTTP_TRUE_CLIENT_IP',
		);
	}

	/**
	 * Η IP του επισκέπτη. Από προεπιλογή το REMOTE_ADDR. Πίσω από CDN/proxy, επιλέξτε στις ρυθμίσεις
	 * το header με την πραγματική IP. Τα headers πλαστογραφούνται εύκολα, οπότε αυτό είναι ασφαλές μόνο
	 * όταν ο server δέχεται αιτήματα αποκλειστικά από το CDN. Φίλτρο: `pncp_client_ip`.
	 *
	 * @return string
	 */
	public static function client_ip() {
		$ip      = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$setting = PNCP_Options::get()['ip_header'];
		$headers = self::ip_headers();
		if ( isset( $headers[ $setting ] ) && ! empty( $_SERVER[ $headers[ $setting ] ] ) ) {
			// X-Forwarded-For: ο επισκέπτης μπορεί να γράψει ό,τι θέλει στην αρχή. Το CDN προσθέτει την
			// πραγματική IP στο τέλος, οπότε κρατάμε την τελευταία τιμή (για ένα CDN μπροστά από τον server).
			$list = array_map( 'trim', explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $headers[ $setting ] ] ) ) ) );
			$last = (string) end( $list );
			if ( filter_var( $last, FILTER_VALIDATE_IP ) ) {
				$ip = $last;
			}
		}
		$ip = (string) apply_filters( 'pncp_client_ip', $ip );
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	/**
	 * Το User-Agent του αιτήματος.
	 *
	 * @return string
	 */
	private static function user_agent() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
	}

	/**
	 * Τρέχει πριν φορτώσει το template: 403 για μπλοκαρισμένα bots, 429 πάνω από το όριο.
	 */
	public static function guard() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || is_user_logged_in() || is_robots() || is_favicon() || wp_doing_ajax() ) {
			return;
		}
		// Μόνο προβολές σελίδων: όχι φόρμες (POST) και όχι AJAX του WooCommerce (wc-ajax), π.χ. καλάθι και ταμείο.
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Μόνο έλεγχος ύπαρξης.
		if ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) || isset( $_GET['wc-ajax'] ) ) {
			return;
		}

		$ua = self::user_agent();
		$ip = self::client_ip();

		// Αιτήματα από τον ίδιο τον server (cache preload, cron, loopback) δεν μπλοκάρονται.
		if ( self::is_local( $ip ) ) {
			return;
		}

		// Επαληθευμένες μηχανές αναζήτησης δεν μπλοκάρονται ποτέ και δεν μετράνε στο όριο.
		if ( self::is_verified_search_engine( $ua, $ip ) ) {
			return;
		}

		if ( ! empty( $s['block_bots'] ) ) {
			if ( '' === trim( $ua ) && ! empty( $s['block_empty_ua'] ) ) {
				self::deny( 403 );
			}
			if ( '' !== $ua && self::ua_in_list( $ua, PNCP_Options::parse_list( $s['bot_list'] ) ) ) {
				self::deny( 403 );
			}
		}

		$limit = (int) $s['rate_limit'];
		if ( $limit > 0 && '' !== $ip && self::over_limit( $ip, $limit ) ) {
			self::deny( 429 );
		}
	}

	/**
	 * Είναι η IP του ίδιου του server;
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private static function is_local( $ip ) {
		if ( in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			return true;
		}
		$server = isset( $_SERVER['SERVER_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : '';
		return '' !== $ip && $ip === $server;
	}

	/**
	 * Ταιριάζει το User-Agent με κάποιο στοιχείο της λίστας; (υποσυμβολοσειρά, χωρίς διάκριση πεζών/κεφαλαίων)
	 *
	 * @param string   $ua   User-Agent.
	 * @param string[] $list Λίστα.
	 * @return bool
	 */
	public static function ua_in_list( $ua, $list ) {
		foreach ( $list as $needle ) {
			if ( '' !== $needle && false !== stripos( $ua, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Είναι πραγματική μηχανή αναζήτησης; Έλεγχος reverse DNS και μετά forward DNS ότι επιστρέφει την ίδια IP.
	 * Το αποτέλεσμα κρατιέται 24 ώρες ανά IP, ώστε το DNS να γίνεται σπάνια.
	 *
	 * @param string $ua User-Agent.
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_verified_search_engine( $ua, $ip ) {
		$domains = array();
		foreach ( self::$search_engines as $pattern => $allowed ) {
			if ( false !== stripos( $ua, $pattern ) ) {
				$domains = $allowed;
				break;
			}
		}
		if ( ! $domains || '' === $ip ) {
			return false;
		}

		$key    = 'pncp_se_' . md5( $ip );
		$cached = wp_using_ext_object_cache() ? wp_cache_get( $key, 'pncp' ) : get_transient( $key );
		if ( false !== $cached ) {
			return 'yes' === $cached;
		}

		$verified = false;
		$host     = gethostbyaddr( $ip );
		if ( $host && $host !== $ip ) {
			$host_lc = strtolower( rtrim( $host, '.' ) );
			foreach ( $domains as $domain ) {
				if ( substr( $host_lc, -strlen( $domain ) ) === $domain ) {
					$verified = in_array( $ip, self::forward_ips( $host_lc ), true );
					break;
				}
			}
		}

		// Θετικό αποτέλεσμα 24 ώρες, αρνητικό 1 ώρα.
		$ttl = $verified ? DAY_IN_SECONDS : HOUR_IN_SECONDS;
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $verified ? 'yes' : 'no', 'pncp', $ttl );
		} else {
			set_transient( $key, $verified ? 'yes' : 'no', $ttl );
		}
		return $verified;
	}

	/**
	 * Οι IPv4/IPv6 ενός hostname.
	 *
	 * @param string $host Hostname.
	 * @return string[]
	 */
	private static function forward_ips( $host ) {
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
	 * Μετράει τις σελίδες της IP στο τρέχον λεπτό. Χρησιμοποιεί το object cache αν υπάρχει, αλλιώς transient.
	 *
	 * @param string $ip    IP.
	 * @param int    $limit Όριο σελίδων ανά λεπτό.
	 * @return bool
	 */
	private static function over_limit( $ip, $limit ) {
		$bucket = (int) floor( time() / MINUTE_IN_SECONDS );
		$key    = 'pncp_rl_' . md5( $ip ) . '_' . $bucket;

		if ( wp_using_ext_object_cache() ) {
			wp_cache_add( $key, 0, 'pncp', 2 * MINUTE_IN_SECONDS );
			$count = (int) wp_cache_incr( $key, 1, 'pncp' );
		} else {
			$count = (int) get_transient( $key ) + 1;
			set_transient( $key, $count, 2 * MINUTE_IN_SECONDS );
		}

		return $count > $limit;
	}

	/**
	 * Τερματίζει το αίτημα με 403 ή 429, χωρίς να μπει στην cache.
	 *
	 * @param int $code HTTP κωδικός.
	 */
	private static function deny( $code ) {
		nocache_headers();
		if ( 429 === $code ) {
			header( 'Retry-After: 60' );
			$message = __( 'Πάρα πολλά αιτήματα. Δοκιμάστε ξανά σε ένα λεπτό.', 'content-protect' );
		} else {
			$message = __( 'Η πρόσβαση δεν επιτρέπεται.', 'content-protect' );
		}
		wp_die( esc_html( $message ), esc_html( (string) $code ), array( 'response' => $code ) );
	}

	/**
	 * Τα AI crawlers που δηλώνονται στο robots.txt.
	 *
	 * @return string[]
	 */
	public static function robots_agents() {
		return (array) apply_filters(
			'pncp_robots_ai_agents',
			array( 'GPTBot', 'ChatGPT-User', 'CCBot', 'ClaudeBot', 'anthropic-ai', 'PerplexityBot', 'Bytespider', 'Google-Extended', 'Applebot-Extended', 'meta-externalagent', 'Diffbot' )
		);
	}

	/**
	 * Προσθέτει Disallow για AI crawlers στο εικονικό robots.txt. Δεν αγγίζει μηχανές αναζήτησης.
	 *
	 * @param string $output Το robots.txt.
	 * @param bool   $public Αν το site επιτρέπει ευρετηρίαση.
	 * @return string
	 */
	public static function robots_txt( $output, $public ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['robots_ai_block'] ) || ! $public ) {
			return $output;
		}

		$block = "\n# Content Protect: AI crawlers\n";
		foreach ( self::robots_agents() as $agent ) {
			$block .= 'User-agent: ' . $agent . "\nDisallow: /\n\n";
		}
		return rtrim( $output ) . "\n" . $block;
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
		foreach ( PNCP_Options::parse_list( $s['bot_list'] ) as $needle ) {
			$uas[] = preg_quote( rtrim( $needle, '/' ), '#' );
		}
		return $uas;
	}
}
