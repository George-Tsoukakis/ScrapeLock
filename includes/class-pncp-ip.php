<?php
/**
 * Διευθύνσεις IP: πραγματική IP επισκέπτη πίσω από CDN/proxy (Trusted Proxy), CIDR και οι επίσημες
 * λίστες IP του Cloudflare, της Google και της Bing (ανανέωση κάθε μέρα με WP-Cron).
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Βοηθητικά για IP.
 */
final class PNCP_Ip {

	/**
	 * Option με τις λίστες που κατεβαίνουν (όχι autoload).
	 */
	const LISTS_OPTION = 'pncp_ip_lists';

	/**
	 * Cron hook της ανανέωσης.
	 */
	const CRON = 'pncp_refresh_ip_lists';

	/**
	 * Cache της IP για το αίτημα.
	 *
	 * @var string|null
	 */
	private static $client_ip = null;

	/**
	 * Αν η IP του αιτήματος δεν μπορεί να πλαστογραφηθεί.
	 *
	 * @var bool
	 */
	private static $reliable = true;

	/**
	 * Cache των λιστών για το αίτημα.
	 *
	 * @var array<string, string[]>
	 */
	private static $lists = array();

	/**
	 * Δένει τα hooks.
	 */
	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'refresh_lists' ) );
	}

	/**
	 * Οι πηγές των λιστών: όνομα => URLs.
	 *
	 * @return array<string, string[]>
	 */
	public static function sources() {
		return array(
			'cloudflare' => array( 'https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6' ),
			'google'     => array(
				'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
				'https://developers.google.com/static/search/apis/ipranges/special-crawlers.json',
				'https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json',
			),
			'bing'       => array( 'https://www.bing.com/toolbox/bingbot.json' ),
		);
	}

	/**
	 * Οι διευθύνσεις του Cloudflare (https://www.cloudflare.com/ips/), για την περίπτωση που η λήψη αποτύχει.
	 *
	 * @return string[]
	 */
	public static function cloudflare_fallback() {
		return array(
			'173.245.48.0/20',
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'141.101.64.0/18',
			'108.162.192.0/18',
			'190.93.240.0/20',
			'188.114.96.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			'162.158.0.0/15',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'172.64.0.0/13',
			'131.0.72.0/22',
			'2400:cb00::/32',
			'2606:4700::/32',
			'2803:f800::/32',
			'2405:b500::/32',
			'2405:8100::/32',
			'2a06:98c0::/29',
			'2c0f:f248::/32',
		);
	}

	/**
	 * Μια λίστα CIDR. Για το Cloudflare, αν δεν έχει κατέβει, η ενσωματωμένη.
	 *
	 * @param string $name cloudflare | google | bing.
	 * @return string[]
	 */
	public static function list_of( $name ) {
		if ( ! isset( self::$lists[ $name ] ) ) {
			// Ένα option ανά λίστα: η μικρή λίστα του Cloudflare είναι autoload (χρειάζεται σε κάθε αίτημα πίσω
			// από Cloudflare), οι μεγάλες της Google / Bing διαβάζονται μόνο όταν κάποιος δηλώνει crawler.
			$list                 = get_option( self::LISTS_OPTION . '_' . $name, array() );
			self::$lists[ $name ] = is_array( $list ) ? $list : array();
		}
		$list = self::$lists[ $name ];
		if ( ! $list && 'cloudflare' === $name ) {
			$list = self::cloudflare_fallback();
		}
		return $list;
	}

	/**
	 * Αποθηκεύει μια λίστα (και σε tests).
	 *
	 * @param string   $name   Όνομα.
	 * @param string[] $ranges CIDR.
	 */
	public static function store_list( $name, $ranges ) {
		update_option( self::LISTS_OPTION . '_' . $name, array_values( $ranges ), 'cloudflare' === $name );
		$updated          = get_option( self::LISTS_OPTION . '_updated', array() );
		$updated          = is_array( $updated ) ? $updated : array();
		$updated[ $name ] = time();
		update_option( self::LISTS_OPTION . '_updated', $updated, false );
		unset( self::$lists[ $name ] );
	}

	/**
	 * Πότε ανανεώθηκαν οι λίστες: όνομα => timestamp.
	 *
	 * @return array<string, int>
	 */
	public static function lists_updated() {
		$updated = get_option( self::LISTS_OPTION . '_updated', array() );
		return is_array( $updated ) ? array_map( 'intval', $updated ) : array();
	}

	/**
	 * Κατεβάζει τις λίστες. Αν μια πηγή αποτύχει, κρατά την προηγούμενη τιμή της.
	 *
	 * @return array<string, int> Πλήθος διευθύνσεων ανά λίστα (0 = απέτυχε).
	 */
	public static function refresh_lists() {
		$result = array();

		foreach ( self::sources() as $name => $urls ) {
			$ranges = array();
			$ok     = true;
			foreach ( $urls as $url ) {
				$response = wp_remote_get(
					$url,
					array(
						'timeout'     => 10,
						'redirection' => 2,
						'user-agent'  => 'Content-Protect/' . PNCP_VERSION . '; ' . home_url( '/' ),
					)
				);
				if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
					$ok = false;
					break;
				}
				$found = self::parse_ranges( (string) wp_remote_retrieve_body( $response ) );
				if ( ! $found ) {
					$ok = false;
					break;
				}
				$ranges = array_merge( $ranges, $found );
			}
			if ( $ok ) {
				$ranges = array_values( array_unique( $ranges ) );
				self::store_list( $name, $ranges );
				$result[ $name ] = count( $ranges );
			} else {
				$result[ $name ] = 0;
			}
		}
		return $result;
	}

	/**
	 * Βρίσκει CIDR σε JSON της Google/Bing ({"prefixes":[{"ipv4Prefix":…}]}) ή σε απλό κείμενο (Cloudflare).
	 *
	 * @param string $body Περιεχόμενο.
	 * @return string[]
	 */
	public static function parse_ranges( $body ) {
		$out  = array();
		$json = json_decode( $body, true );
		if ( is_array( $json ) && isset( $json['prefixes'] ) && is_array( $json['prefixes'] ) ) {
			foreach ( $json['prefixes'] as $prefix ) {
				foreach ( array( 'ipv4Prefix', 'ipv6Prefix' ) as $key ) {
					if ( isset( $prefix[ $key ] ) && self::valid_range( (string) $prefix[ $key ] ) ) {
						$out[] = (string) $prefix[ $key ];
					}
				}
			}
			return $out;
		}
		foreach ( preg_split( '/\s+/', trim( $body ) ) as $line ) {
			if ( self::valid_range( $line ) ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	/**
	 * Τα headers που μπορεί να φέρουν την πραγματική IP: ρύθμιση => κλειδί $_SERVER.
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
	 * Το REMOTE_ADDR.
	 *
	 * @return string
	 */
	public static function remote_addr() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	/**
	 * Είναι το REMOTE_ADDR ένας proxy που εμπιστευόμαστε για αυτό το header;
	 *
	 * - CF-Connecting-IP: μόνο το Cloudflare (το γράφει πάντα το ίδιο) και οι «Αξιόπιστοι proxies».
	 * - True-Client-IP: μόνο οι «Αξιόπιστοι proxies» (το Cloudflare το περνά όπως το έστειλε ο επισκέπτης).
	 * - X-Real-IP: ο ίδιος ο server / ιδιωτικό δίκτυο (Nginx μπροστά) και οι «Αξιόπιστοι proxies».
	 * - X-Forwarded-For: όλα τα παραπάνω· η αλυσίδα διαβάζεται από το τέλος.
	 *
	 * @param string               $ip      IP.
	 * @param array<string, mixed> $s       Ρυθμίσεις.
	 * @param string               $setting Header (ip_header).
	 * @return bool
	 */
	public static function is_trusted_proxy( $ip, $s, $setting = 'x_forwarded_for' ) {
		if ( '' === $ip ) {
			return false;
		}
		if ( self::in_any( $ip, PNCP_Options::parse_list( $s['trusted_proxies'] ) ) ) {
			return true;
		}
		$cloudflare = ! empty( $s['trust_cloudflare'] ) && self::in_any( $ip, self::list_of( 'cloudflare' ) );
		switch ( $setting ) {
			case 'cf_connecting_ip':
				return $cloudflare;
			case 'true_client_ip':
				return false;
			case 'x_real_ip':
				return self::is_private( $ip );
			default:
				return $cloudflare || self::is_private( $ip );
		}
	}

	/**
	 * Η IP του επισκέπτη.
	 *
	 * Από προεπιλογή το REMOTE_ADDR. Αν έχει επιλεγεί header (π.χ. CF-Connecting-IP), διαβάζεται ΜΟΝΟ όταν
	 * το αίτημα έρχεται από αξιόπιστο proxy, αλλιώς ο καθένας θα έγραφε ό,τι IP ήθελε. Στο X-Forwarded-For
	 * η αλυσίδα διαβάζεται από το τέλος και παραλείπονται οι αξιόπιστοι proxies. Φίλτρο: `pncp_client_ip`.
	 *
	 * Με την «εμπιστοσύνη σε κάθε proxy» (συμπεριφορά της 1.4) η IP χρησιμοποιείται για όρια, αλλά θεωρείται
	 * αναξιόπιστη: δεν ανοίγει επιτρεπόμενες IP και feeds και δεν οδηγεί σε αποκλεισμό από την παγίδα.
	 *
	 * @return string
	 */
	public static function client_ip() {
		if ( null !== self::$client_ip ) {
			return self::$client_ip;
		}
		$s              = PNCP_Options::get();
		$remote         = self::remote_addr();
		$ip             = $remote;
		$headers        = self::ip_headers();
		$setting        = (string) $s['ip_header'];
		self::$reliable = true;

		if ( isset( $headers[ $setting ] ) && ! empty( $_SERVER[ $headers[ $setting ] ] ) ) {
			$legacy  = ! empty( $s['trust_any_proxy'] ) && ! self::is_trusted_proxy( $remote, $s, $setting );
			$trusted = $legacy || self::is_trusted_proxy( $remote, $s, $setting );
			if ( $trusted ) {
				$chain = array_map( 'trim', explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $headers[ $setting ] ] ) ) ) );
				// Από το τέλος: η τελευταία τιμή είναι αυτή που έγραψε ο δικός μας proxy.
				for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
					$candidate = $chain[ $i ];
					if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
						break;
					}
					$ip = $candidate;
					if ( $legacy || 'x_forwarded_for' !== $setting || ! self::is_trusted_proxy( $candidate, $s, $setting ) ) {
						break;
					}
				}
				if ( $legacy && $ip !== $remote ) {
					self::$reliable = false;
				}
			}
		}

		$ip              = (string) apply_filters( 'pncp_client_ip', $ip );
		self::$client_ip = filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
		return self::$client_ip;
	}

	/**
	 * Μπορεί να πλαστογραφηθεί η IP του αιτήματος; (false μόνο με την «εμπιστοσύνη σε κάθε proxy»)
	 *
	 * @return bool
	 */
	public static function reliable() {
		self::client_ip();
		return self::$reliable;
	}

	/**
	 * Ξεχνά την IP του αιτήματος (για tests και μετά από αλλαγή ρυθμίσεων).
	 */
	public static function reset() {
		self::$client_ip = null;
		self::$reliable  = true;
		self::$lists     = array();
	}

	/**
	 * Ιδιωτική, loopback ή reserved IP;
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_private( $ip ) {
		return (bool) filter_var( $ip, FILTER_VALIDATE_IP ) && ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Είναι η IP του ίδιου του server (cron, cache preload, loopback);
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_local( $ip ) {
		if ( in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			return true;
		}
		$server = isset( $_SERVER['SERVER_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : '';
		return '' !== $ip && $ip === $server;
	}

	/**
	 * Έγκυρη IP ή CIDR;
	 *
	 * @param string $range Τιμή.
	 * @return bool
	 */
	public static function valid_range( $range ) {
		$parts = explode( '/', trim( (string) $range ), 2 );
		if ( ! filter_var( $parts[0], FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( ! isset( $parts[1] ) ) {
			return true;
		}
		$max = filter_var( $parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 128 : 32;
		return ctype_digit( $parts[1] ) && (int) $parts[1] <= $max;
	}

	/**
	 * Ανήκει η IP σε κάποια από τις διευθύνσεις/CIDR;
	 *
	 * @param string   $ip     IP.
	 * @param string[] $ranges Λίστα.
	 * @return bool
	 */
	public static function in_any( $ip, $ranges ) {
		foreach ( $ranges as $range ) {
			if ( self::in_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Ανήκει η IP σε μια IP ή CIDR (IPv4/IPv6);
	 *
	 * @param string $ip    IP.
	 * @param string $range IP ή CIDR, π.χ. 203.0.113.0/24.
	 * @return bool
	 */
	public static function in_range( $ip, $range ) {
		$parts  = explode( '/', trim( (string) $range ), 2 );
		$subnet = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Λάθος τιμή = false.
		$addr   = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $subnet || false === $addr || strlen( $subnet ) !== strlen( $addr ) ) {
			return false;
		}
		$max = strlen( $addr ) * 8;
		if ( isset( $parts[1] ) ) {
			if ( ! ctype_digit( $parts[1] ) || (int) $parts[1] > $max ) {
				return false; // Λάθος CIDR: ποτέ «όλες οι IP».
			}
			$bits = (int) $parts[1];
		} else {
			$bits = $max;
		}
		$bytes = intdiv( $bits, 8 );
		if ( substr( $addr, 0, $bytes ) !== substr( $subnet, 0, $bytes ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = 0xFF << ( 8 - $rest ) & 0xFF;
		return ( ord( $addr[ $bytes ] ) & $mask ) === ( ord( $subnet[ $bytes ] ) & $mask );
	}
}
