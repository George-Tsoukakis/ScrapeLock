<?php
/**
 * IP addresses: real visitor IP behind a CDN/proxy (Trusted Proxy), CIDR and the official
 * IP lists of Cloudflare, Google and Bing (refreshed daily via WP-Cron).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * IP helpers.
 */
final class PNCP_Ip {

	/**
	 * Option holding the downloaded lists (not autoloaded).
	 */
	const LISTS_OPTION = 'pncp_ip_lists';

	/**
	 * Cron hook for the refresh.
	 */
	const CRON = 'pncp_refresh_ip_lists';

	/**
	 * Per-request cache of the IP.
	 *
	 * @var string|null
	 */
	private static $client_ip = null;

	/**
	 * Whether the request IP cannot be spoofed.
	 *
	 * @var bool
	 */
	private static $reliable = true;

	/**
	 * Per-request cache of the lists.
	 *
	 * @var array<string, string[]>
	 */
	private static $lists = array();

	/**
	 * Attaches the hooks.
	 */
	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'refresh_lists' ) );
	}

	/**
	 * The list sources: name => URLs.
	 *
	 * @return array<string, string[]>
	 */
	public static function sources() {
		return array(
			'cloudflare' => array( 'https://api.cloudflare.com/client/v4/ips' ),
			'google'     => array(
				'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
				'https://developers.google.com/static/search/apis/ipranges/special-crawlers.json',
				'https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json',
			),
			'bing'       => array( 'https://www.bing.com/toolbox/bingbot.json' ),
		);
	}

	/**
	 * Cloudflare's addresses (https://www.cloudflare.com/ips/), in case the download fails.
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
	 * A CIDR list. For Cloudflare, the built-in one if it has not been downloaded.
	 *
	 * @param string $name cloudflare | google | bing.
	 * @return string[]
	 */
	public static function list_of( $name ) {
		if ( ! isset( self::$lists[ $name ] ) ) {
			// One option per list: Cloudflare's small list is autoloaded (needed on every request behind
			// Cloudflare); the large Google / Bing lists are read only when someone claims to be a crawler.
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
	 * Stores a list (also in tests).
	 *
	 * @param string   $name   Name.
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
	 * When the lists were refreshed: name => timestamp.
	 *
	 * @return array<string, int>
	 */
	public static function lists_updated() {
		$updated = get_option( self::LISTS_OPTION . '_updated', array() );
		return is_array( $updated ) ? array_map( 'intval', $updated ) : array();
	}

	/**
	 * The lists the current settings use. Only these are downloaded: the Google and Bing lists while
	 * protection is on, the Cloudflare list only when a Cloudflare proxy is trusted for the real IP.
	 *
	 * @return string[]
	 */
	public static function needed_lists() {
		$s      = PNCP_Options::get();
		$needed = array();
		if ( ! empty( $s['enabled'] ) ) {
			$needed[] = 'google';
			$needed[] = 'bing';
		}
		if ( ! empty( $s['trust_cloudflare'] ) && in_array( $s['ip_header'], array( 'cf_connecting_ip', 'x_forwarded_for' ), true ) ) {
			$needed[] = 'cloudflare';
		}
		return $needed;
	}

	/**
	 * Downloads the lists. If a source fails, its previous value is kept.
	 *
	 * @return array<string, int> Number of addresses per list (0 = failed).
	 */
	public static function refresh_lists() {
		$result = array();
		$needed = self::needed_lists();

		foreach ( self::sources() as $name => $urls ) {
			if ( ! in_array( $name, $needed, true ) ) {
				continue;
			}
			$ranges = array();
			$ok     = true;
			foreach ( $urls as $url ) {
				$response = wp_remote_get(
					$url,
					array(
						'timeout'     => 10,
						'redirection' => 2,
						'user-agent'  => 'ScrapeLock/' . PNCP_VERSION,
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
	 * Finds CIDRs in Google/Bing JSON ({"prefixes":[{"ipv4Prefix":…}]}) or in plain text (Cloudflare).
	 *
	 * @param string $body Content.
	 * @return string[]
	 */
	public static function parse_ranges( $body ) {
		$out  = array();
		$json = json_decode( $body, true );
		if ( is_array( $json ) && isset( $json['result'] ) && is_array( $json['result'] ) ) {
			foreach ( array( 'ipv4_cidrs', 'ipv6_cidrs' ) as $key ) {
				if ( isset( $json['result'][ $key ] ) && is_array( $json['result'][ $key ] ) ) {
					foreach ( $json['result'][ $key ] as $range ) {
						if ( self::valid_range( (string) $range ) ) {
							$out[] = (string) $range;
						}
					}
				}
			}
			return $out;
		}
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
	 * The headers that may carry the real IP: setting => $_SERVER key.
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
	 * The REMOTE_ADDR.
	 *
	 * @return string
	 */
	public static function remote_addr() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	/**
	 * Does REMOTE_ADDR belong to Cloudflare? Then, without the right "Real visitor IP" setting, every
	 * visitor would appear with a Cloudflare address.
	 *
	 * @return bool
	 */
	public static function remote_is_cloudflare() {
		$remote = self::remote_addr();
		return '' !== $remote && self::in_any( $remote, self::list_of( 'cloudflare' ) );
	}

	/**
	 * Is the site behind Cloudflare? The request carries CF-Connecting-IP and comes from Cloudflare, or
	 * REMOTE_ADDR was already replaced with the visitor's IP (as the Cloudflare plugin does).
	 *
	 * @return bool
	 */
	public static function behind_cloudflare() {
		$header = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '';
		if ( '' === $header || ! filter_var( $header, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		return self::remote_is_cloudflare() || self::remote_addr() === $header;
	}

	/**
	 * Is the Cloudflare plugin active?
	 *
	 * @return bool
	 */
	public static function cloudflare_plugin_active() {
		return defined( 'CLOUDFLARE_PLUGIN_DIR' ) || class_exists( '\\Cloudflare\\APO\\WordPress\\Hooks', false );
	}

	/**
	 * Is REMOTE_ADDR a proxy we trust for this header?
	 *
	 * - CF-Connecting-IP: only Cloudflare (it always sets it itself) and the "Trusted proxies".
	 * - True-Client-IP: only the "Trusted proxies" (Cloudflare passes it on as the visitor sent it).
	 * - X-Real-IP: the server itself / private network (Nginx in front) and the "Trusted proxies".
	 * - X-Forwarded-For: all of the above; the chain is read from the end.
	 *
	 * @param string               $ip      IP.
	 * @param array<string, mixed> $s       Settings.
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
	 * The visitor's IP.
	 *
	 * REMOTE_ADDR by default. If a header is selected (e.g. CF-Connecting-IP), it is read ONLY when
	 * the request comes from a trusted proxy, otherwise anyone could write any IP they wanted. In X-Forwarded-For
	 * the chain is read from the end and trusted proxies are skipped. Filter: `pncp_client_ip`.
	 *
	 * With "trust every proxy" (1.4 behaviour) the IP is used for limits, but is considered
	 * untrusted: it does not unlock allowed IPs and feeds, and does not lead to a ban from the trap.
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
				// From the end: the last value is the one written by our own proxy.
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
	 * Can the request IP be spoofed? (false only with "trust every proxy")
	 *
	 * @return bool
	 */
	public static function reliable() {
		self::client_ip();
		return self::$reliable;
	}

	/**
	 * Forgets the request IP (for tests and after a settings change).
	 */
	public static function reset() {
		self::$client_ip = null;
		self::$reliable  = true;
		self::$lists     = array();
	}

	/**
	 * The key under which an IP is counted for limits and violations.
	 *
	 * IPv4: the address itself. IPv6: its network (/64 by default), because a single
	 * connection usually gets a whole /64 and could change address on every request.
	 * An IPv4-mapped IPv6 address (::ffff:203.0.113.5) counts as the IPv4 address.
	 * Filter `pncp_ipv6_prefix` (48–128, 128 = per address).
	 *
	 * @param string $ip IP.
	 * @return string e.g. 203.0.113.5 or 2001:db8:1:2::/64
	 */
	public static function limit_key( $ip ) {
		$bin = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $bin || 16 !== strlen( $bin ) ) {
			return (string) $ip;
		}
		if ( 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			return (string) inet_ntop( substr( $bin, 12 ) );
		}
		$prefix = max( 48, min( 128, (int) apply_filters( 'pncp_ipv6_prefix', 64 ) ) );
		if ( 128 === $prefix ) {
			return (string) inet_ntop( $bin );
		}
		$bytes = intdiv( $prefix, 8 );
		$net   = substr( $bin, 0, $bytes );
		if ( $prefix % 8 ) {
			$net .= chr( ord( $bin[ $bytes ] ) & ( 0xFF << ( 8 - $prefix % 8 ) & 0xFF ) );
		}
		return inet_ntop( str_pad( $net, 16, "\0" ) ) . '/' . $prefix;
	}

	/**
	 * Private, loopback or reserved IP?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_private( $ip ) {
		return (bool) filter_var( $ip, FILTER_VALIDATE_IP ) && ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Is it the server's own IP (cron, cache preload, loopback)?
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
	 * Valid IP or CIDR?
	 *
	 * @param string $range Value.
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
	 * Does the IP belong to any of the addresses/CIDRs?
	 *
	 * @param string   $ip     IP.
	 * @param string[] $ranges List.
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
	 * Does the IP belong to an IP or CIDR (IPv4/IPv6)?
	 *
	 * @param string $ip    IP.
	 * @param string $range IP or CIDR, e.g. 203.0.113.0/24.
	 * @return bool
	 */
	public static function in_range( $ip, $range ) {
		$parts  = explode( '/', trim( (string) $range ), 2 );
		$subnet = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		$addr   = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $subnet || false === $addr || strlen( $subnet ) !== strlen( $addr ) ) {
			return false;
		}
		$max = strlen( $addr ) * 8;
		if ( isset( $parts[1] ) ) {
			if ( ! ctype_digit( $parts[1] ) || (int) $parts[1] > $max ) {
				return false; // Invalid CIDR: never "all IPs".
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
