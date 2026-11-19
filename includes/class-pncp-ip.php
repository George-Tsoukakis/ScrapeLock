<?php
/**
 * IP addresses: real visitor IP behind a CDN/proxy (Trusted Proxy), CIDR and the official
 * IP lists of Cloudflare, Bunny CDN, Google and Bing (refreshed daily via WP-Cron).
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
	 * 3.6.1: autoloaded option with the fingerprint (list_sum()) of the Bunny list when all its addresses are
	 * spelled as normalize() spells them ('' = they are not).
	 */
	const BUNNY_SUM = 'pncp_ip_lists_bunny_sum';

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
	 * 3.6: the addresses the request passed through on its way here (REMOTE_ADDR and the proxies after the
	 * visitor in the real-IP header). See is_local_request().
	 *
	 * @var string[]
	 */
	private static $hops = array();

	/**
	 * 3.6: a CDN edge trusted for the "Real visitor IP" header connected, but the header was missing or not
	 * an IP, so the edge's own address stands in. See is_cdn_edge().
	 *
	 * @var bool
	 */
	private static $no_visitor_ip = false;

	/**
	 * Per-request cache of the lists.
	 *
	 * @var array<string, string[]>
	 */
	private static $lists = array();

	/**
	 * The Bunny list as a lookup table (address => true) plus its CIDRs, built once per request.
	 *
	 * @var array{0:array<string, bool>, 1:string[]}|null
	 */
	private static $bunny = null;

	/**
	 * 3.4.3: official_owner() per IP for this request, forgotten with the lists (it was a static variable that
	 * kept the answer of a list that store_list() had just replaced).
	 *
	 * @var array<string, string>
	 */
	private static $owners = array();

	/**
	 * Attaches the hooks.
	 */
	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'refresh_lists' ), 10, 0 );
		add_action( 'admin_init', array( __CLASS__, 'fetch_missing' ) ); // Also right after a settings change.
		add_action( 'update_option_' . PNCP_OPTION, array( __CLASS__, 'forget_missing_try' ) );
	}

	/**
	 * A settings change can need a new list: it is asked for at once, not after the hourly pause.
	 */
	public static function forget_missing_try() {
		delete_transient( 'pncp_lists_missing_try' );
	}

	/**
	 * The list sources: name => URLs.
	 *
	 * @return array<string, string[]>
	 */
	public static function sources() {
		return array(
			'cloudflare'      => array( 'https://api.cloudflare.com/client/v4/ips' ),
			// Bunny CDN edge servers (since 2.6): one address per server, IPv4 and IPv6.
			'bunny'           => array(
				'https://bunnycdn.com/api/system/edgeserverlist',
				'https://bunnycdn.com/api/system/edgeserverlist/IPv6',
			),
			'google'          => array(
				'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
				'https://developers.google.com/static/search/apis/ipranges/special-crawlers.json',
				'https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json',
			),
			'bing'            => array( 'https://www.bing.com/toolbox/bingbot.json' ),
			// 3.10: Applebot and DuckDuckBot publish their addresses too. Applebot is also verified by reverse DNS
			// (*.applebot.apple.com); DuckDuckBot has no reverse DNS of its own, so its list is the only proof.
			'apple'           => array( 'https://search.developer.apple.com/applebot.json' ),
			'duckduckgo'      => array( 'https://duckduckgo.com/duckduckbot.json' ),
			// AI search bots and assistants (since 2.5), one list per User-Agent.
			'openai_search'   => array( 'https://openai.com/searchbot.json' ),
			'openai_user'     => array( 'https://openai.com/chatgpt-user.json' ),
			'perplexity_bot'  => array( 'https://www.perplexity.com/perplexitybot.json' ),
			'perplexity_user' => array( 'https://www.perplexity.com/perplexity-user.json' ),
			// Anthropic (Claude-SearchBot, Claude-User), since 2.6.2.
			'anthropic'       => array( 'https://claude.com/crawling/bots.json' ),
			// Data centers that publish their addresses (since 3.0), for the stricter page limit. AWS: only the
			// servers (EC2), not CloudFront or the other services. Azure publishes its list at an address that
			// changes every week, so it is not included.
			'dc_aws'          => array( 'https://ip-ranges.amazonaws.com/ip-ranges.json' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- A list of IP ranges downloaded as data, not an asset loaded by the site.
			'dc_gcp'          => array( 'https://www.gstatic.com/ipranges/cloud.json' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- A list of IP ranges downloaded as data, not an asset loaded by the site.
			'dc_oracle'       => array( 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json' ),
			'dc_digitalocean' => array( 'https://digitalocean.com/geo/google.csv' ),
			'dc_linode'       => array( 'https://geoip.linode.com/' ),
		);
	}

	/**
	 * The data center lists and their names.
	 *
	 * @return array<string, string>
	 */
	public static function datacenters() {
		return array(
			'dc_aws'          => 'AWS',
			'dc_gcp'          => 'Google Cloud',
			'dc_oracle'       => 'Oracle Cloud',
			'dc_digitalocean' => 'DigitalOcean',
			'dc_linode'       => 'Akamai / Linode',
		);
	}

	/**
	 * Which data center the IP belongs to ('' = none known). Thousands of ranges cannot be checked one by one on
	 * every page, so they are kept in small groups by their first byte (IPv4) or first two bytes (IPv6): one
	 * small option is read per request, and only its ranges are compared.
	 *
	 * @param string $ip IP.
	 * @return string The provider's name, or ''.
	 */
	public static function datacenter( $ip ) {
		$bin = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $bin ) {
			return '';
		}
		if ( 16 === strlen( $bin ) && 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$bin = substr( $bin, 12 ); // IPv4-mapped IPv6.
		}
		$hex  = bin2hex( $bin );
		$name = self::dc_group_name( $bin );
		// The list of groups is small and autoloaded: an address whose group does not exist costs no query.
		$known = get_option( 'pncp_dc_groups', array() );
		if ( ! is_array( $known ) ) {
			return '';
		}
		if ( isset( $known[0] ) ) {
			// As stored before 3.6.1: only the names of the groups (until the lists are next refreshed).
			if ( ! in_array( $name, $known, true ) ) {
				return '';
			}
		} elseif ( ! isset( $known[ $name ] ) || ! self::dc_byte_listed( (string) $known[ $name ], ord( $bin[ strlen( $bin ) > 4 ? 2 : 1 ] ) ) ) {
			// 3.6.1: the group also says which values of the next byte its ranges cover. Most visitors' addresses
			// are in no range of their group: the group (an option of its own, often thousands of ranges) is
			// then not read at all, where it was one query and a large unserialize() on every page.
			return '';
		}
		// 3.4.3: the stamp of the last rebuild is part of the APCu key. The lists are often refreshed from WP-CLI
		// (cron run by "wp cron event run"), which cannot clear the web server's APCu: the old ranges stayed in
		// use for up to an hour. Autoloaded, like the list of groups.
		$apcu  = PNCP_Log::apcu_key( $name . '_' . (string) get_option( 'pncp_dc_stamp', '' ) );
		$group = PNCP_Log::apcu_ok() ? apcu_fetch( $apcu ) : false;
		if ( ! is_array( $group ) ) {
			$group = get_option( $name, array() );
			// 3.5: not while a request is only explained ("Check a request" writes no cache entry).
			if ( PNCP_Log::apcu_ok() && is_array( $group ) && ! ( class_exists( 'PNCP_Bots', false ) && PNCP_Bots::explaining() ) ) {
				apcu_store( $apcu, $group, HOUR_IN_SECONDS );
			}
		}
		foreach ( is_array( $group ) ? $group : array() as $row ) {
			if ( strcmp( $hex, $row[0] ) >= 0 && strcmp( $hex, $row[1] ) <= 0 ) {
				$names = self::datacenters();
				return isset( $names[ $row[2] ] ) ? $names[ $row[2] ] : (string) $row[2];
			}
		}
		return '';
	}

	/**
	 * The option that holds the group of an address.
	 *
	 * @param string $bin Packed address (4 or 16 bytes).
	 * @return string
	 */
	private static function dc_group_name( $bin ) {
		return 4 === strlen( $bin ) ? 'pncp_dc_4_' . ord( $bin[0] ) : 'pncp_dc_6_' . bin2hex( substr( $bin, 0, 2 ) );
	}

	/**
	 * 3.6.1: is a value of the byte after the group's own byte(s) covered by a range of the group? The group's
	 * map is 256 bits as 64 hex digits, most significant bit first.
	 *
	 * @param string $map  Map (64 hex digits).
	 * @param int    $byte The byte's value (0–255).
	 * @return bool
	 */
	private static function dc_byte_listed( $map, $byte ) {
		if ( 64 !== strlen( $map ) || ! ctype_xdigit( $map ) ) {
			return true; // Not a map (changed elsewhere): the group decides.
		}
		return 0 !== ( hexdec( $map[ $byte >> 2 ] ) & ( 8 >> ( $byte & 3 ) ) );
	}

	/**
	 * Rebuilds the groups from the downloaded data center lists: each range as its first and last address (hex,
	 * so they compare as text), in the group of its first byte(s). Lists are at least /8 (IPv4) and /16 (IPv6)
	 * (sane_ranges()), so a range never spans two groups.
	 */
	public static function build_datacenter_index() {
		$groups = array();
		$maps   = array();
		foreach ( array_keys( self::datacenters() ) as $name ) {
			// 3.4.3: sane_ranges() again, for a list written to the database some other way: a range wider than
			// a group would only be put in the group of its first address.
			foreach ( self::sane_ranges( self::list_of( $name ) ) as $range ) {
				$parts = explode( '/', (string) $range, 2 );
				$start = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Validated when stored.
				if ( false === $start ) {
					continue;
				}
				$bits = isset( $parts[1] ) ? (int) $parts[1] : strlen( $start ) * 8;
				// 3.4.3: an IPv4-mapped range (::ffff:54.0.0.0/104) in the IPv4 group, where datacenter() looks for
				// its addresses (sane_ranges() keeps it at least /104).
				if ( 16 === strlen( $start ) && 0 === strpos( $start, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
					$start = substr( $start, 12 );
					$bits  = max( 0, $bits - 96 );
				}
				$end  = $start;
				for ( $i = 0, $len = strlen( $start ); $i < $len; $i++ ) {
					$keep        = max( 0, min( 8, $bits - $i * 8 ) );
					$mask        = ( 0xFF << ( 8 - $keep ) ) & 0xFF;
					$start[ $i ] = chr( ord( $start[ $i ] ) & $mask );
					$end[ $i ]   = chr( ord( $start[ $i ] ) | ( ~$mask & 0xFF ) );
				}
				$group              = self::dc_group_name( $start );
				$groups[ $group ][] = array( bin2hex( $start ), bin2hex( $end ), $name );
				// 3.6.1: the values of the next byte the range covers (all of them in between its first and last).
				$at = 4 === strlen( $start ) ? 1 : 2;
				if ( ! isset( $maps[ $group ] ) ) {
					$maps[ $group ] = array_fill( 0, 256, false );
				}
				for ( $b = ord( $start[ $at ] ), $last = ord( $end[ $at ] ); $b <= $last; $b++ ) {
					$maps[ $group ][ $b ] = true;
				}
			}
		}
		$old = get_option( 'pncp_dc_groups', array() );
		$old = is_array( $old ) ? ( isset( $old[0] ) ? $old : array_keys( $old ) ) : array();
		foreach ( array_diff( $old, array_keys( $groups ) ) as $gone ) {
			delete_option( $gone );
		}
		foreach ( $groups as $option => $rows ) {
			update_option( $option, $rows, false );
		}
		update_option( 'pncp_dc_stamp', (string) microtime( true ), true );
		// Autoloaded (a short list of names, 3.6.1: each with the map of dc_byte_listed()): read on every page
		// without a query of its own.
		$index = array();
		foreach ( $maps as $group => $bits ) {
			$hex = '';
			for ( $i = 0; $i < 256; $i += 4 ) {
				$hex .= dechex( ( $bits[ $i ] ? 8 : 0 ) | ( $bits[ $i + 1 ] ? 4 : 0 ) | ( $bits[ $i + 2 ] ? 2 : 0 ) | ( $bits[ $i + 3 ] ? 1 : 0 ) );
			}
			$index[ $group ] = $hex;
		}
		update_option( 'pncp_dc_groups', $index, true );
		if ( function_exists( 'wp_set_option_autoload' ) ) {
			wp_set_option_autoload( 'pncp_dc_groups', true ); // Stored as not autoloaded before 3.3.2.
		}
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
			// One option per list: the CDN lists are autoloaded (needed on every request behind the CDN); the
			// large Google / Bing lists are read only when someone claims to be a crawler.
			$list = get_option( self::LISTS_OPTION . '_' . $name, array() );
			// 3.4.3: only text entries. A list damaged in the database (an entry that is a list itself) made
			// is_bunny() fail with a fatal error on every request.
			self::$lists[ $name ] = is_array( $list ) ? array_values( array_filter( $list, 'is_string' ) ) : array();
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
		$ranges = array_values( self::sane_ranges( $ranges ) );
		update_option( self::LISTS_OPTION . '_' . $name, $ranges, in_array( $name, array( 'cloudflare', 'bunny' ), true ) );
		if ( 'bunny' === $name ) {
			// 3.6.1: the fingerprint of the list when every address in it is spelled as normalize() spells it,
			// so is_bunny() can use the list as it is ('' = not so: is_bunny() builds its table as before).
			$canonical = true;
			foreach ( $ranges as $range ) {
				if ( false === strpos( $range, '/' ) && self::normalize( $range ) !== $range ) {
					$canonical = false;
					break;
				}
			}
			update_option( self::BUNNY_SUM, $canonical && $ranges ? self::list_sum( $ranges ) : '', true );
		}
		$updated          = get_option( self::LISTS_OPTION . '_updated', array() );
		$updated          = is_array( $updated ) ? $updated : array();
		$updated[ $name ] = time();
		update_option( self::LISTS_OPTION . '_updated', $updated, false );
		unset( self::$lists[ $name ] );
		self::$bunny  = null;
		self::$owners = array();
		if ( isset( self::datacenters()[ $name ] ) ) {
			self::build_datacenter_index();
		}
	}

	/**
	 * 3.6.1: a fingerprint of a list (its length and a CRC of its entries), to tell that it is the list a note
	 * was made about.
	 *
	 * @param string[] $list List.
	 * @return string
	 */
	private static function list_sum( $list ) {
		return count( $list ) . ':' . sprintf( '%u', crc32( implode( "\n", $list ) ) );
	}

	/**
	 * Drops absurdly broad or malformed entries from a downloaded list, so a bad or hostile source cannot
	 * ship "0.0.0.0/0" (which would make every IP an official crawler, a trusted proxy, or a blocked one).
	 * A single address keeps its full /32 or /128. Rejected: non-ranges, prefixes shorter than /8 (IPv4) or
	 * /16 (IPv6), and the all-zero network.
	 *
	 * @param string[] $ranges IPs and CIDRs.
	 * @return string[]
	 */
	public static function sane_ranges( $ranges ) {
		$out = array();
		foreach ( (array) $ranges as $range ) {
			$range = trim( (string) $range );
			if ( '' === $range || ! self::valid_range( $range ) ) {
				continue;
			}
			$parts = explode( '/', $range, 2 );
			// The same limits as for the "Trusted proxies", including an IPv4-mapped range (::ffff:0.0.0.0/96
			// is every IPv4 address, as in_range() compares it).
			if ( PNCP_Options::range_too_wide( $range ) ) {
				continue; // Far too broad for an edge/crawler list.
			}
			$packed = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Validated above.
			if ( false !== $packed && 16 === strlen( $packed ) && 0 === strpos( $packed, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
				$packed = substr( $packed, 12 ); // IPv4-mapped: its IPv4 part.
			}
			if ( false !== $packed && str_repeat( "\0", strlen( $packed ) ) === $packed ) {
				continue; // 0.0.0.0 / :: base: reject.
			}
			$out[] = $range;
		}
		return $out;
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
	 * protection is on, the Cloudflare / Bunny list only when that CDN is trusted for the real IP (Bunny also
	 * for its country header), and the AI search lists only when AI search is allowed and "Verify AI search
	 * bots" is on.
	 *
	 * @return string[]
	 */
	public static function needed_lists() {
		$s      = PNCP_Options::get();
		$needed = array();
		if ( ! empty( $s['enabled'] ) ) {
			$needed[] = 'google';
			$needed[] = 'bing';
			$needed[] = 'apple';
			$needed[] = 'duckduckgo';
		}
		if ( ! empty( $s['trust_cloudflare'] ) && in_array( $s['ip_header'], array( 'cf_connecting_ip', 'x_forwarded_for' ), true ) ) {
			$needed[] = 'cloudflare';
		}
		if ( ! empty( $s['trust_bunny'] ) && ( in_array( $s['ip_header'], array( 'x_real_ip', 'x_forwarded_for' ), true ) || ( ! empty( $s['enabled'] ) && ( '' !== $s['countries_block'] || '' !== $s['countries_strict'] ) ) ) ) {
			$needed[] = 'bunny';
		}
		if ( ! empty( $s['enabled'] ) && ! empty( $s['allow_ai_search'] ) && ! empty( $s['verify_ai_bots'] ) ) {
			$needed = array_merge( $needed, array_values( PNCP_Bots::ai_bot_lists() ) );
		}
		if ( ! empty( $s['enabled'] ) && (int) $s['rate_limit_datacenter'] > 0 ) {
			$needed = array_merge( $needed, array_keys( self::datacenters() ) );
		}
		return $needed;
	}

	/**
	 * Whose official address is this: a search engine, an AI search service or a CDN in front of the site?
	 * Blocking one of these would stop that company's search bots, or every visitor behind the CDN.
	 *
	 * @param string $ip IP.
	 * @return string The owner, e.g. Anthropic; '' when it is in none of the lists.
	 */
	public static function official_owner( $ip ) {
		$ip = (string) $ip;
		if ( isset( self::$owners[ $ip ] ) ) {
			return self::$owners[ $ip ];
		}
		$owners = array(
			'google'          => 'Google',
			'bing'            => 'Bing',
			'apple'           => 'Apple',
			'duckduckgo'      => 'DuckDuckGo',
			'openai_search'   => 'OpenAI',
			'openai_user'     => 'OpenAI',
			'perplexity_bot'  => 'Perplexity',
			'perplexity_user' => 'Perplexity',
			'anthropic'       => 'Anthropic',
			'cloudflare'      => 'Cloudflare',
		);
		$owner  = '';
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			foreach ( $owners as $list => $name ) {
				if ( self::in_any( $ip, self::list_of( $list ) ) ) {
					$owner = $name;
					break;
				}
			}
			if ( '' === $owner && self::is_bunny( $ip ) ) {
				$owner = 'Bunny CDN';
			}
		}
		self::$owners[ $ip ] = $owner;
		return $owner;
	}

	/**
	 * The lists the current settings use but that were never downloaded (e.g. a list new in an update, or one
	 * a setting has just turned on).
	 *
	 * @return string[]
	 */
	public static function missing_lists() {
		return array_values( array_diff( array_unique( self::needed_lists() ), array_keys( self::lists_updated() ) ) );
	}

	/**
	 * Downloads the missing lists right away (in the background, on the next request) instead of waiting for
	 * the daily refresh. At most once an hour, so a source that is down is not asked on every request.
	 */
	public static function fetch_missing() {
		if ( ! self::missing_lists() || get_transient( 'pncp_lists_missing_try' ) ) {
			return;
		}
		set_transient( 'pncp_lists_missing_try', 1, HOUR_IN_SECONDS );
		if ( ! wp_next_scheduled( self::CRON, array( 'missing' ) ) ) {
			wp_schedule_single_event( time(), self::CRON, array( 'missing' ) );
		}
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
						// Bunny answers in XML unless JSON is asked for; the others always send JSON.
						'headers'     => array( 'Accept' => 'application/json' ),
					)
				);
				if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
					$ok = false;
					break;
				}
				// Only what would be stored counts: a source that sends nothing usable keeps the previous list.
				$found = self::sane_ranges( self::parse_ranges( (string) wp_remote_retrieve_body( $response ) ) );
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
		PNCP_Precheck::refresh(); // The pre-cache check keeps its own copy of the lists.
		return $result;
	}

	/**
	 * Finds CIDRs in Google/Bing JSON ({"prefixes":[{"ipv4Prefix":…}]}), Cloudflare JSON, a JSON array of
	 * addresses (Bunny), XML (<string>address</string>) or plain text.
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
		// AWS (ip-ranges.json): only the servers (EC2), not CloudFront and the other services.
		// 3.10: only when the entries name their service, as AWS's do: a list of {"ip_prefix": …} without one
		// (another publisher using the same key) is read by the generic branch below instead of coming out empty.
		if ( is_array( $json ) && isset( $json['prefixes'][0]['ip_prefix'], $json['prefixes'][0]['service'] ) ) {
			$keys = array(
				'prefixes'      => 'ip_prefix',
				'ipv6_prefixes' => 'ipv6_prefix',
			);
			foreach ( $keys as $list => $key ) {
				foreach ( isset( $json[ $list ] ) && is_array( $json[ $list ] ) ? $json[ $list ] : array() as $prefix ) {
					if ( isset( $prefix['service'], $prefix[ $key ] ) && 'EC2' === $prefix['service'] && self::valid_range( (string) $prefix[ $key ] ) ) {
						$out[] = (string) $prefix[ $key ];
					}
				}
			}
			return $out;
		}
		// Oracle Cloud (public_ip_ranges.json): regions → cidrs.
		if ( is_array( $json ) && isset( $json['regions'] ) && is_array( $json['regions'] ) ) {
			foreach ( $json['regions'] as $region ) {
				foreach ( isset( $region['cidrs'] ) && is_array( $region['cidrs'] ) ? $region['cidrs'] : array() as $cidr ) {
					if ( isset( $cidr['cidr'] ) && self::valid_range( (string) $cidr['cidr'] ) ) {
						$out[] = (string) $cidr['cidr'];
					}
				}
			}
			return $out;
		}
		if ( is_array( $json ) && isset( $json['prefixes'] ) && is_array( $json['prefixes'] ) ) {
			foreach ( $json['prefixes'] as $prefix ) {
				foreach ( array( 'ipv4Prefix', 'ipv6Prefix' ) as $key ) {
					if ( isset( $prefix[ $key ] ) && is_scalar( $prefix[ $key ] ) && self::valid_range( (string) $prefix[ $key ] ) ) {
						$out[] = (string) $prefix[ $key ];
					}
				}
			}
			if ( $out ) {
				return $out;
			}
		}
		if ( is_array( $json ) && array_values( $json ) === $json ) {
			foreach ( $json as $range ) {
				if ( is_string( $range ) && self::valid_range( $range ) ) {
					$out[] = $range;
				}
			}
			if ( $out ) {
				return $out;
			}
		}
		// 3.10: any other JSON (the AI services' lists: "prefixes" as plain strings, "ip_ranges", "ipv4" / "ipv6",
		// {"cidr": …}, …): every text value that is an address or a CIDR, at any depth.
		if ( is_array( $json ) ) {
			return self::json_ranges( $json );
		}
		// Plain text, one per line, the values of an XML list, or a geofeed CSV (DigitalOcean, Linode: the range
		// is the first field; comment lines start with #).
		$body = (string) preg_replace( '/^#.*$/m', '', $body );
		foreach ( preg_split( '/[\s<>,]+/', trim( $body ) ) as $line ) {
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
		static $memo = array( null, '' ); // 3.6.1: REMOTE_ADDR as given and its normalized form (asked many times per request).
		$raw = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Only the memo key; sanitized below.
		if ( is_string( $raw ) && $raw === $memo[0] ) {
			return $memo[1];
		}
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$ip = self::normalize( $ip );
		if ( is_string( $raw ) ) {
			$memo = array( $raw, $ip );
		}
		return $ip;
	}

	/**
	 * One spelling per address, so that it matches the lists and the DNS answers: without a port or brackets
	 * ("1.2.3.4:5678", "[2001:db8::1]:443", as some proxies send), IPv6 in its short lowercase form, and an
	 * IPv4-mapped IPv6 address (::ffff:203.0.113.5, from dual-stack sockets) as the IPv4 address.
	 *
	 * @param string $ip IP as received.
	 * @return string The IP, or '' if it is not one.
	 */
	public static function normalize( $ip ) {
		$ip = trim( (string) $ip );
		if ( '' === $ip ) {
			return '';
		}
		if ( '[' === $ip[0] ) {
			$end = strpos( $ip, ']' );
			$ip  = false === $end ? '' : substr( $ip, 1, $end - 1 );
		} elseif ( 1 === substr_count( $ip, ':' ) ) {
			$ip = substr( $ip, 0, (int) strpos( $ip, ':' ) ); // IPv4 with a port.
		}
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $bin ) {
			return '';
		}
		if ( 16 === strlen( $bin ) && 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$bin = substr( $bin, 12 );
		}
		return (string) inet_ntop( $bin );
	}

	/**
	 * Is the address an edge server of a CDN in front of the site (Cloudflare, Bunny)? Many visitors share
	 * one: it is never counted, limited or banned as if it were a single visitor.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_cdn( $ip ) {
		$ip = (string) $ip;
		return '' !== $ip && ( self::in_any( $ip, self::list_of( 'cloudflare' ) ) || self::is_bunny( $ip ) );
	}

	/**
	 * Is the address the CDN edge that connected to the server, still standing in for the visitor (the real
	 * visitor IP could not be read)? Only then is it shared by many visitors. A CDN address that came from the
	 * real-IP header is a client of its own (e.g. a Cloudflare Worker, which a scraper can rent) and is limited
	 * like any other.
	 *
	 * 3.4: with a CDN shared secret set, only a request that carries it comes through this site's own CDN. A
	 * request from a CDN address without it was sent through someone else's account at the same CDN (their own
	 * zone, or a Worker), which anyone can set up: it stands in for nobody here, and is limited, blocked and
	 * banned like any other address.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_cdn_edge( $ip ) {
		$ip = (string) $ip;
		if ( '' === $ip || self::remote_addr() !== $ip ) {
			return false;
		}
		// 3.6: not when the edge was trusted for the real-IP header but sent none (or not an IP): this site's own
		// CDN always writes it, so such a request came through someone else's zone at the same CDN.
		self::client_ip();
		if ( self::$no_visitor_ip && $ip === self::$client_ip ) {
			return false;
		}
		return self::is_cdn( $ip ) && self::cdn_secret_ok( PNCP_Options::get() );
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
	 * Does an address belong to a Bunny CDN edge server? The list has one address per server (about a
	 * thousand), so it is looked up in a table instead of being compared one by one.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_bunny( $ip ) {
		if ( '' === $ip ) {
			return false;
		}
		if ( null === self::$bunny ) {
			$list = self::list_of( 'bunny' );
			$sum  = $list ? get_option( self::BUNNY_SUM, false ) : '';
			if ( is_string( $sum ) && '' !== $sum && self::list_sum( $list ) === $sum ) {
				// 3.6.1: every address in the list is already written as normalize() writes it (checked when the
				// list was stored, see BUNNY_SUM): the list itself is the lookup table. Building it took ~0.35 ms
				// on every request (an inet_pton() and inet_ntop() per address).
				self::$bunny = array( array_flip( $list ), array_values( preg_grep( '#/#', $list ) ) );
			} else {
				$exact     = array();
				$cidrs     = array();
				$mapped    = str_repeat( "\0", 10 ) . "\xff\xff";
				$canonical = true;
				foreach ( $list as $range ) {
					if ( false === strpos( $range, '/' ) ) {
						// 3.4.3: in the spelling of normalize(), as the visitor IP is: an IPv4-mapped entry matches its
						// IPv4 visitor, and an entry that is not an address is skipped instead of warning.
						$bin = @inet_pton( $range ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
						if ( false === $bin ) {
							$canonical = false;
							continue;
						}
						if ( 16 === strlen( $bin ) && 0 === strpos( $bin, $mapped ) ) {
							$bin = substr( $bin, 12 );
						}
						$key           = (string) inet_ntop( $bin );
						$exact[ $key ] = true;
						$canonical     = $canonical && $key === $range;
					} else {
						$cidrs[] = $range;
					}
				}
				self::$bunny = array( $exact, $cidrs );
				// A list stored before 3.6.1: its fingerprint is noted once (a later request takes the quick way).
				if ( $list && false === $sum && ! ( class_exists( 'PNCP_Bots', false ) && PNCP_Bots::explaining() ) ) {
					add_option( self::BUNNY_SUM, $canonical ? self::list_sum( $list ) : '', '', true );
				}
			}
		}
		$key = self::normalize( (string) $ip );
		if ( '' !== $key && isset( self::$bunny[0][ $key ] ) ) {
			return true;
		}
		return self::in_any( $ip, self::$bunny[1] );
	}

	/**
	 * Does REMOTE_ADDR belong to Bunny CDN (from the downloaded list)?
	 *
	 * @return bool
	 */
	public static function remote_is_bunny() {
		return self::is_bunny( self::remote_addr() );
	}

	/**
	 * Is the request coming through Bunny CDN? Bunny adds CDN-ServerId and "Via: BunnyCDN" to the
	 * requests it sends to the site. Only for notices on the settings page: anyone can send these headers.
	 *
	 * @return bool
	 */
	public static function behind_bunny() {
		$via = isset( $_SERVER['HTTP_VIA'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_VIA'] ) ) : '';
		return ! empty( $_SERVER['HTTP_CDN_SERVERID'] ) || false !== stripos( $via, 'BunnyCDN' );
	}

	/**
	 * Is the site behind a CDN while every visitor appears with the CDN's address (the "Real visitor IP"
	 * setting does not match)? Then limits and blocks hit the CDN itself. Judged from the current request.
	 *
	 * @return string 'cloudflare', 'bunny' or ''.
	 */
	public static function cdn_hides_visitors() {
		$ip = self::client_ip();
		if ( self::remote_is_cloudflare() && '' !== $ip && self::in_any( $ip, self::list_of( 'cloudflare' ) ) ) {
			return 'cloudflare';
		}
		if ( ! self::behind_bunny() ) {
			return '';
		}
		$real = isset( $_SERVER['HTTP_X_REAL_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) : '';
		if ( '' === $real || self::remote_addr() === $real || ! filter_var( $real, FILTER_VALIDATE_IP ) || $ip === $real ) {
			return '';
		}
		return 'bunny';
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
	 * - X-Real-IP: Bunny CDN, the server itself / private network (Nginx in front) and the "Trusted proxies".
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
		if ( self::in_any( $ip, self::trusted_ranges( $s ) ) ) {
			return true;
		}
		// A multi-tenant CDN (Bunny, Cloudflare) trusts its own edge IPs, but an attacker can point their own
		// pull zone at this origin and set the real-IP header to anything. When a CDN secret is configured,
		// the CDN edge is trusted only if the request carries it (the admin sets the CDN to inject the header).
		$secret_ok  = self::cdn_secret_ok( $s );
		$cloudflare = ! empty( $s['trust_cloudflare'] ) && $secret_ok && self::in_any( $ip, self::list_of( 'cloudflare' ) );
		$bunny      = ! empty( $s['trust_bunny'] ) && $secret_ok && self::is_bunny( $ip );
		switch ( $setting ) {
			case 'cf_connecting_ip':
				return $cloudflare;
			case 'true_client_ip':
				return false;
			case 'x_real_ip':
				return self::is_private( $ip ) || $bunny;
			default:
				return $cloudflare || self::is_private( $ip ) || $bunny;
		}
	}

	/**
	 * The "Trusted proxies" that count. 3.4: a range wider than /8 (IPv4) or /16 (IPv6) is ignored (and no longer
	 * saved): with it, any visitor could choose its own IP with a header.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string[]
	 */
	public static function trusted_ranges( $s ) {
		static $memo = array( null, array() ); // 3.6.1: read several times per request (client_ip()).
		$raw = isset( $s['trusted_proxies'] ) ? $s['trusted_proxies'] : '';
		if ( is_string( $raw ) && $raw === $memo[0] ) {
			return $memo[1];
		}
		$out = array();
		foreach ( PNCP_Options::parse_list( $raw ) as $range ) {
			if ( ! PNCP_Options::range_too_wide( $range ) ) {
				$out[] = $range;
			}
		}
		if ( is_string( $raw ) ) {
			$memo = array( $raw, $out );
		}
		return $out;
	}

	/**
	 * Is the CDN shared secret satisfied? True when none is configured (behaviour unchanged), or when the
	 * request carries the matching X-ScrapeLock-CDN header. Explicit "Trusted proxies" and private proxies
	 * are never gated by this; only the CDN edge lists are.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return bool
	 */
	public static function cdn_secret_ok( $s ) {
		$secret = isset( $s['cdn_secret'] ) ? trim( (string) $s['cdn_secret'] ) : '';
		if ( '' === $secret ) {
			return true;
		}
		$sent = isset( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] ) ) ) : '';
		return '' !== $sent && hash_equals( $secret, $sent );
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
		$setting             = (string) $s['ip_header'];
		self::$reliable      = true;
		self::$hops          = array( $remote );
		self::$no_visitor_ip = false;

		if ( isset( $headers[ $setting ] ) && ! empty( $_SERVER[ $headers[ $setting ] ] ) ) {
			$legacy  = ! empty( $s['trust_any_proxy'] ) && ! self::is_trusted_proxy( $remote, $s, $setting );
			$trusted = $legacy || self::is_trusted_proxy( $remote, $s, $setting );
			if ( $trusted ) {
				$chain = array_map( 'trim', explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $headers[ $setting ] ] ) ) ) );
				// 3.6.1: a Cloudflare edge on the way (REMOTE_ADDR, or a hop that a proxy of this server wrote into
				// X-Forwarded-For). Everything to its left in X-Forwarded-For came from whoever sent the request to
				// Cloudflare: a Cloudflare Worker (which anyone can rent, and whose subrequests leave from Cloudflare's
				// own addresses) can write any address there. The walk stops at the edge, and the visitor is the
				// CF-Connecting-IP that Cloudflare writes itself (see cloudflare_hop()).
				$cf_hop = ! $legacy && 'x_forwarded_for' === $setting && self::cloudflare_hop( $remote );
				$i      = count( $chain ) - 1;
				// From the end: the last value is the one written by our own proxy.
				for ( ; ! $cf_hop && $i >= 0; $i-- ) {
					$candidate = self::normalize( $chain[ $i ] );
					if ( '' === $candidate ) {
						break;
					}
					$ip = $candidate;
					if ( $legacy || 'x_forwarded_for' !== $setting || ! self::is_trusted_proxy( $candidate, $s, $setting ) ) {
						break;
					}
					if ( self::cloudflare_hop( $candidate ) ) {
						$cf_hop = true; // $i is moved left past the edge by the loop: the edge is a hop, not the visitor.
					}
				}
				if ( $cf_hop ) {
					$ip = self::cloudflare_visitor( $chain, $i, $ip, $s );
				}
				if ( $legacy && $ip !== $remote ) {
					self::$reliable = false;
				}
				// 3.6: the proxies after the visitor in the chain, as far as they were read.
				$links = count( $chain );
				for ( $h = max( 0, $i + 1 ); $h < $links; $h++ ) {
					$hop = self::normalize( $chain[ $h ] );
					if ( '' !== $hop ) {
						self::$hops[] = $hop;
					}
				}
				// 3.6: the header of a trusted CDN edge held no IP. The edge's address is not shared by real
				// visitors then (this site's own CDN always writes it), so it is limited like any other client.
				if ( ! $legacy && $ip === $remote && self::is_cdn( $remote ) ) {
					self::$no_visitor_ip = true;
				}
				// 3.4.3: a Bunny CDN edge without the CDN secret. Anyone can point a pull zone of their own at this
				// site and make it send any visitor IP: the IP still counts for the limits, but it does not unlock
				// the always-allowed IPs or the private URL IPs, and does not get anyone banned by the trap or
				// blocked at the CDN. Explicit "Trusted proxies" and the server's own network are not affected.
				// Every hop between the visitor and this server is looked at, so it also holds behind a local proxy
				// (Nginx or Varnish in front of PHP: REMOTE_ADDR is 127.0.0.1, the Bunny edge a hop further).
				if ( ! $legacy && $ip !== $remote && '' === trim( (string) ( isset( $s['cdn_secret'] ) ? $s['cdn_secret'] : '' ) ) ) {
					foreach ( self::$hops as $hop ) {
						if ( $hop !== $ip && ! self::in_any( $hop, self::trusted_ranges( $s ) ) && ! self::is_private( $hop ) && self::is_bunny( $hop ) ) {
							self::$reliable = false;
							break;
						}
					}
				}
			}
		} elseif ( isset( $headers[ $setting ] ) && self::is_cdn( $remote ) && self::is_trusted_proxy( $remote, $s, $setting ) ) {
			// 3.6: a trusted CDN edge sent no "Real visitor IP" header at all (see above).
			self::$no_visitor_ip = true;
		} elseif ( 'remote_addr' === $setting && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::is_trusted_proxy( $remote, $s, 'cf_connecting_ip' ) ) {
			// "Real visitor IP" left at the default but the request comes from a Cloudflare edge (checked against
			// Cloudflare's list, and the CDN secret if one is set): Cloudflare always writes CF-Connecting-IP
			// itself, so it is the visitor. Otherwise every visitor would share the edge's address and its limits.
			$candidate = self::normalize( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) );
			if ( '' !== $candidate ) {
				$ip = $candidate;
			}
		}

		$ip              = self::normalize( (string) apply_filters( 'pncp_client_ip', $ip ) );
		self::$client_ip = $ip;
		return self::$client_ip;
	}

	/**
	 * 3.6.1: is the address a Cloudflare edge (from Cloudflare's published list, not a private address)?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private static function cloudflare_hop( $ip ) {
		return '' !== $ip && ! self::is_private( $ip ) && self::in_any( $ip, self::list_of( 'cloudflare' ) );
	}

	/**
	 * 3.6.1: the visitor behind a Cloudflare edge found in X-Forwarded-For (or as REMOTE_ADDR). Cloudflare writes
	 * CF-Connecting-IP itself and a Worker cannot set it, while everything left of the edge in X-Forwarded-For
	 * came from the client: so CF-Connecting-IP is the visitor. On a normal Cloudflare site Cloudflare also
	 * appended that same address to X-Forwarded-For, and the two agree. When they do not (or CF-Connecting-IP is
	 * missing) and the request does not carry the CDN shared secret, someone wrote X-Forwarded-For through
	 * Cloudflare (a Worker, their own zone): the IP is then unreliable, as for a Bunny edge without the secret
	 * (counted for the limits, but it unlocks no allowed or private IPs, earns no violation and bans nobody).
	 *
	 * @param string[]             $chain    The X-Forwarded-For entries.
	 * @param int                  $left     Index of the entry left of the Cloudflare edge (-1 = none).
	 * @param string               $fallback The IP found so far.
	 * @param array<string, mixed> $s        Settings.
	 * @return string
	 */
	private static function cloudflare_visitor( $chain, $left, $fallback, $s ) {
		$xff = $left >= 0 && isset( $chain[ $left ] ) ? self::normalize( $chain[ $left ] ) : '';
		$cf  = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? self::normalize( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) ) : '';
		$own = '' !== trim( (string) ( isset( $s['cdn_secret'] ) ? $s['cdn_secret'] : '' ) ) && self::cdn_secret_ok( $s );
		if ( ! $own && ( '' === $cf || $xff !== $cf ) ) {
			self::$reliable = false;
		}
		if ( '' !== $cf ) {
			return $cf;
		}
		return '' !== $xff ? $xff : $fallback;
	}

	/**
	 * 3.6.1: the client address a forwarding header names, when it is not the server itself: the last address of
	 * X-Forwarded-For (the one the nearest proxy wrote), X-Real-IP, CF-Connecting-IP or the last "for=" of
	 * Forwarded. Only used to tell whether a proxy passes on visitors; never trusted as the visitor's IP.
	 * (Moved here from PNCP_Origin, so that the early check, which loads no PNCP_Origin, can use it.)
	 *
	 * @return string The address, or '' when no header names an outside address.
	 */
	public static function forwarded_client() {
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP' ) as $header ) {
			if ( empty( $_SERVER[ $header ] ) ) {
				continue;
			}
			$value = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
			if ( 'HTTP_FORWARDED' === $header ) {
				$value = preg_match_all( '/for\s*=\s*"?([^";,\s]+)/i', $value, $found ) ? (string) end( $found[1] ) : '';
			} else {
				$parts = explode( ',', $value );
				$value = (string) end( $parts );
			}
			$ip = self::normalize( $value );
			if ( '' !== $ip && ! self::is_local( $ip ) ) {
				return $ip;
			}
		}
		return '';
	}

	/**
	 * 3.6.1: does this request come from a reverse proxy that "Real visitor IP" does not trust? REMOTE_ADDR is
	 * the server itself or a private address (a local Nginx / Varnish, a container network, a load balancer), a
	 * forwarding header names an outside client, and the visitor IP is still REMOTE_ADDR. Then every visitor
	 * shares that one address: nothing may be decided per IP (a ban on it would block the whole site), and the
	 * administrator is told to set "Real visitor IP" (PNCP_Origin::notice(), Site Health).
	 *
	 * @return bool
	 */
	public static function untrusted_proxy_peer() {
		$remote = self::remote_addr();
		if ( '' === $remote || ! ( self::is_local( $remote ) || self::is_private( $remote ) ) ) {
			return false;
		}
		return self::client_ip() === $remote && '' !== self::forwarded_client();
	}

	/**
	 * Can the request IP be trusted? False when it may be spoofed: "trust every proxy", a Bunny edge without the
	 * CDN shared secret, or (3.6.1) X-Forwarded-For through Cloudflare that does not match CF-Connecting-IP.
	 * An unreliable IP is still counted for the limits, but unlocks nothing and earns no violation or ban.
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
		self::$client_ip     = null;
		self::$reliable      = true;
		self::$hops          = array();
		self::$no_visitor_ip = false;
		self::$lists         = array();
		self::$bunny         = null;
		self::$owners        = array();
	}

	/**
	 * 3.6: is this request from the server itself (cron, cache preload, loopback)? The visitor IP must be the
	 * loopback or the server's own address AND it must not have come from far away: the IP is reliable and
	 * every address on its way (REMOTE_ADDR and each proxy read in the header) is on the server or its private
	 * network. Being equal to REMOTE_ADDR is not enough: behind Nginx on 127.0.0.1, X-Forwarded-For can end
	 * in 127.0.0.1 after passing through a CDN edge.
	 * Before, a loopback address in the real-IP header was enough, and anyone who could make a trusted CDN edge
	 * send one (a Bunny pull zone of their own, without the CDN secret) skipped every check.
	 *
	 * @return bool
	 */
	public static function is_local_request() {
		$ip = self::client_ip();
		if ( '' === $ip || ! self::is_local( $ip ) ) {
			return false;
		}
		if ( ! self::$reliable ) {
			return false;
		}
		foreach ( self::$hops as $hop ) {
			if ( ! self::is_local( $hop ) && ! self::is_private( $hop ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The key under which an IP is counted for limits and violations.
	 *
	 * IPv4: the address itself. IPv6: its network (/64 by default), because a single
	 * connection usually gets a whole /64 and could change address on every request.
	 * An IPv4-mapped IPv6 address (::ffff:203.0.113.5) counts as the IPv4 address.
	 * Filter `pncp_ipv6_prefix` (48–128, 128 = per address).
	 *
	 * @param string   $ip     IP.
	 * @param int|null $prefix IPv6 network size (null = the filter, /64 by default).
	 * @return string e.g. 203.0.113.5 or 2001:db8:1:2::/64
	 */
	public static function limit_key( $ip, $prefix = null ) {
		$bin = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $bin || 16 !== strlen( $bin ) ) {
			return (string) $ip;
		}
		if ( 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			return (string) inet_ntop( substr( $bin, 12 ) );
		}
		$prefix = max( 48, min( 128, null === $prefix ? (int) apply_filters( 'pncp_ipv6_prefix', 64 ) : (int) $prefix ) );
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
	 * 3.6.1: the network an address belongs to, for the per-network share of new counters
	 * (PNCP_Bots::db_incr_capped()): IPv4 /24, IPv6 /48 (IPv4-mapped as IPv4).
	 *
	 * @param string $ip IP.
	 * @return string e.g. 203.0.113.0/24 or 2001:db8:1::/48; '' when it is not an IP.
	 */
	public static function network_key( $ip ) {
		$bin = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $bin ) {
			return '';
		}
		if ( 16 === strlen( $bin ) && 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$bin = substr( $bin, 12 );
		}
		if ( 4 === strlen( $bin ) ) {
			return inet_ntop( substr( $bin, 0, 3 ) . "\0" ) . '/24';
		}
		return inet_ntop( substr( $bin, 0, 6 ) . str_repeat( "\0", 10 ) ) . '/48';
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
	 * 3.10: every text value of a decoded JSON document that is an address or a CIDR, at any depth (at most 8
	 * levels and 100000 values, so a hostile source cannot make a refresh run forever).
	 *
	 * @param array<mixed> $json  Decoded JSON.
	 * @param int          $depth Current depth.
	 * @return string[]
	 */
	public static function json_ranges( $json, $depth = 0 ) {
		$out = array();
		if ( $depth > 8 ) {
			return $out;
		}
		foreach ( $json as $value ) {
			if ( count( $out ) >= 100000 ) {
				break;
			}
			if ( is_array( $value ) ) {
				$out = array_merge( $out, self::json_ranges( $value, $depth + 1 ) );
			} elseif ( is_string( $value ) && self::valid_range( trim( $value ) ) ) {
				$out[] = trim( $value );
			}
		}
		return $out;
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
		// Same answers as in_range() for each range, but the address is read once and each range only once per
		// request (compiled_range()): the official lists are compared on every request, several times.
		$addr = @inet_pton( (string) $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $addr ) {
			return false;
		}
		$len   = strlen( $addr );
		$addr4 = null; // The IPv4 address an IPv4-mapped IPv6 address carries.
		if ( 16 === $len && 0 === strpos( $addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff" ) ) {
			$addr4 = substr( $addr, 12 );
		} elseif ( 4 === $len ) {
			$addr4 = $addr;
		}
		foreach ( $ranges as $range ) {
			$range = (string) $range;
			$c     = isset( self::$compiled[ $range ] ) ? self::$compiled[ $range ] : self::compiled_range( $range );
			if ( 4 === $c[0] ) {
				// An IPv4 range: an IPv4 address, or the IPv4 address an IPv4-mapped IPv6 address carries.
				if ( null !== $c[1] && null !== $addr4 && ( $addr4 & $c[2] ) === $c[1] ) {
					return true;
				}
			} elseif ( 16 === $c[0] ) {
				if ( 16 === $len ) {
					if ( null !== $c[1] && ( $addr & $c[2] ) === $c[1] ) {
						return true;
					}
				} elseif ( null !== $c[3] && ( $addr & $c[4] ) === $c[3] ) {
					return true; // An IPv4-mapped range (::ffff:198.51.100.0/120) for an IPv4 address.
				}
			}
		}
		return false;
	}

	/**
	 * Ranges already read in this request: range as written => compiled_range().
	 *
	 * @var array<string, array{0:int, 1:string|null, 2:string, 3:string|null, 4:string}>
	 */
	private static $compiled = array();

	/**
	 * A range read once for in_any(), with exactly the rules of in_range(): the length of its address (0 = not
	 * an address: never matches), its network and mask for an address of the same kind (null = invalid prefix:
	 * never matches), and for an IPv4-mapped range (::ffff:a.b.c.d with no prefix or /96–/128) the IPv4 network
	 * and mask it stands for (null = none).
	 *
	 * @param string $range IP or CIDR as written.
	 * @return array{0:int, 1:string|null, 2:string, 3:string|null, 4:string}
	 */
	private static function compiled_range( $range ) {
		if ( count( self::$compiled ) >= 50000 ) {
			self::$compiled = array(); // A long-running process (WP-CLI) does not keep growing.
		}
		$parts  = explode( '/', trim( $range ), 2 );
		$subnet = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		$out    = array( 0, null, '', null, '' );
		if ( false !== $subnet ) {
			$len    = strlen( $subnet );
			$out[0] = $len;
			$bits   = $len * 8;
			$valid  = true;
			if ( isset( $parts[1] ) ) {
				$valid = ctype_digit( $parts[1] ) && (int) $parts[1] <= $bits;
				$bits  = (int) $parts[1];
			}
			if ( $valid ) {
				$out[2] = self::mask( $bits, $len );
				$out[1] = $subnet & $out[2];
			}
			if ( 16 === $len && 0 === strpos( $subnet, "\0\0\0\0\0\0\0\0\0\0\xff\xff" ) && ( ! isset( $parts[1] ) || ( ctype_digit( $parts[1] ) && (int) $parts[1] >= 96 && (int) $parts[1] <= 128 ) ) ) {
				$out[4] = self::mask( isset( $parts[1] ) ? (int) $parts[1] - 96 : 32, 4 );
				$out[3] = substr( $subnet, 12 ) & $out[4];
			}
		}
		self::$compiled[ $range ] = $out;
		return $out;
	}

	/**
	 * A network mask of $bits ones, $len bytes long.
	 *
	 * @param int $bits Prefix length (0 to $len * 8).
	 * @param int $len  4 or 16.
	 * @return string
	 */
	private static function mask( $bits, $len ) {
		$full = intdiv( $bits, 8 );
		$mask = str_repeat( "\xff", $full );
		if ( $bits % 8 ) {
			$mask .= chr( 0xFF << ( 8 - $bits % 8 ) & 0xFF );
		}
		return str_pad( $mask, $len, "\0" );
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
		// An IPv4-mapped IPv6 address is compared as the IPv4 address it carries.
		$mapped = str_repeat( "\0", 10 ) . "\xff\xff";
		if ( false !== $addr && 16 === strlen( $addr ) && false !== $subnet && 4 === strlen( $subnet ) && 0 === strpos( $addr, $mapped ) ) {
			$addr = substr( $addr, 12 );
		}
		// 3.4: and so is a range written in that form (::ffff:198.51.100.7, ::ffff:198.51.100.0/120, saved before
		// such lines were saved as IPv4), for an IPv4 visitor.
		if ( false !== $addr && 4 === strlen( $addr ) && false !== $subnet && 16 === strlen( $subnet ) && 0 === strpos( $subnet, $mapped ) && ( ! isset( $parts[1] ) || ( ctype_digit( $parts[1] ) && (int) $parts[1] >= 96 && (int) $parts[1] <= 128 ) ) ) {
			$subnet = substr( $subnet, 12 );
			if ( isset( $parts[1] ) ) {
				$parts[1] = (string) ( (int) $parts[1] - 96 );
			}
		}
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
