<?php
/**
 * Country of a visitor: Cloudflare's CF-IPCountry header, Bunny CDN's CDN-RequestCountryCode header, or the
 * free DB-IP Lite database.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Country lookup for the "blocked countries" and "stricter limit" lists.
 *
 * Behind Cloudflare the CF-IPCountry header is used, only when the request really comes from a Cloudflare
 * address; behind Bunny CDN its CDN-RequestCountryCode header, only from a Bunny edge server ("Trust Bunny CDN
 * addresses" on). Otherwise, with "Download the country database" on, the DB-IP Lite country file (CC BY 4.0) is
 * downloaded once a month and turned into two small sorted binary files in uploads/scrapelock-geo/:
 * IPv4 records of 10 bytes (start, end, country) and IPv6 records of 18 bytes (the first 64 bits of start and
 * end, country). A lookup is a binary search of about 20 reads. No database, no tables, no data sent anywhere.
 * Without a country, nothing happens.
 */
final class PNCP_Geo {

	const OPTION = 'pncp_geo';
	const DIR    = 'scrapelock-geo';

	/**
	 * Countries already looked up in this request.
	 *
	 * @var array<string, string>
	 */
	private static $cache = array();

	/**
	 * Registers the hooks: the daily list refresh also refreshes the database when it is a month old.
	 */
	public static function init() {
		add_action( PNCP_Ip::CRON, array( __CLASS__, 'maybe_refresh' ), 20 );
	}

	/**
	 * Is the database used by the current settings?
	 *
	 * @return bool
	 */
	public static function needed() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && ! empty( $s['geo_db'] );
	}

	/**
	 * Folder of the files.
	 *
	 * @return string
	 */
	public static function dir() {
		$upload = wp_upload_dir( null, false );
		return trailingslashit( $upload['basedir'] ) . self::DIR;
	}

	/**
	 * Download URL of DB-IP Lite for a month (Y-m).
	 *
	 * @param string $month Month.
	 * @return string
	 */
	public static function source_url( $month ) {
		return (string) apply_filters( 'pncp_geo_source_url', 'https://download.db-ip.com/free/dbip-country-lite-' . $month . '.csv.gz', $month );
	}

	/**
	 * State: updated (timestamp), month, v4 / v6 (number of ranges).
	 *
	 * @return array{updated:int, month:string, v4:int, v6:int}
	 */
	public static function status() {
		$data = get_option( self::OPTION, array() );
		$data = is_array( $data ) ? $data : array();
		return array(
			'updated' => isset( $data['updated'] ) ? (int) $data['updated'] : 0,
			'month'   => isset( $data['month'] ) ? (string) $data['month'] : '',
			'v4'      => isset( $data['v4'] ) ? (int) $data['v4'] : 0,
			'v6'      => isset( $data['v6'] ) ? (int) $data['v6'] : 0,
		);
	}

	/**
	 * The visitor's country (ISO code), or '' if unknown.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function country( $ip ) {
		if ( '' === $ip ) {
			return '';
		}
		if ( isset( self::$cache[ $ip ] ) ) {
			return self::$cache[ $ip ];
		}
		$country = self::from_cloudflare();
		if ( '' === $country ) {
			$country = self::from_bunny();
		}
		if ( '' === $country && self::status()['updated'] ) {
			$country = self::lookup( $ip );
		}
		$country            = (string) apply_filters( 'pncp_visitor_country', $country, $ip );
		self::$cache[ $ip ] = preg_match( '/^[A-Z]{2}$/', $country ) ? $country : '';
		return self::$cache[ $ip ];
	}

	/**
	 * Forgets the request cache (for tests).
	 */
	public static function reset() {
		self::$cache = array();
	}

	/**
	 * CF-IPCountry, only if the request comes from a Cloudflare address (otherwise anyone could write it).
	 *
	 * @return string
	 */
	private static function from_cloudflare() {
		if ( empty( $_SERVER['HTTP_CF_IPCOUNTRY'] ) || ! PNCP_Ip::remote_is_cloudflare() ) {
			return '';
		}
		$code = strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) );
		// XX = unknown, T1 = Tor.
		return preg_match( '/^[A-Z]{2}$/', $code ) && 'XX' !== $code && 'T1' !== $code ? $code : '';
	}

	/**
	 * CDN-RequestCountryCode, only if the request comes from a Bunny edge server and Bunny is trusted.
	 *
	 * @return string
	 */
	private static function from_bunny() {
		$s = PNCP_Options::get();
		if ( empty( $_SERVER['HTTP_CDN_REQUESTCOUNTRYCODE'] ) || empty( $s['trust_bunny'] ) || ! PNCP_Ip::remote_is_bunny() ) {
			return '';
		}
		$code = strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CDN_REQUESTCOUNTRYCODE'] ) ) );
		return preg_match( '/^[A-Z]{2}$/', $code ) && 'XX' !== $code ? $code : '';
	}

	/**
	 * Binary search in the files.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function lookup( $ip ) {
		$packed = inet_pton( $ip );
		if ( false === $packed ) {
			return '';
		}
		// An IPv4-mapped IPv6 address (::ffff:1.2.3.4) is the IPv4 address.
		if ( 16 === strlen( $packed ) && 0 === strpos( $packed, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$packed = substr( $packed, 12 );
		}
		if ( 4 === strlen( $packed ) ) {
			return self::search( self::dir() . '/v4.bin', 4, $packed );
		}
		return self::search( self::dir() . '/v6.bin', 8, substr( $packed, 0, 8 ) );
	}

	/**
	 * Binary search in records of ( 2 × $width + 2 ) bytes: start, end, country.
	 *
	 * @param string $file  File.
	 * @param int    $width Bytes of an address.
	 * @param string $key   The address (big-endian bytes).
	 * @return string
	 */
	private static function search( $file, $width, $key ) {
		if ( ! is_readable( $file ) ) {
			return '';
		}
		$size  = 2 * $width + 2;
		$total = (int) floor( (int) filesize( $file ) / $size );
		if ( $total < 1 ) {
			return '';
		}
		try {
			$handle = new SplFileObject( $file, 'rb' );
		} catch ( Exception $e ) {
			return '';
		}
		$low  = 0;
		$high = $total - 1;
		while ( $low <= $high ) {
			$mid = (int) ( ( $low + $high ) / 2 );
			$handle->fseek( $mid * $size );
			$record = (string) $handle->fread( $size );
			if ( strlen( $record ) !== $size ) {
				return '';
			}
			if ( strcmp( $key, substr( $record, 0, $width ) ) < 0 ) {
				$high = $mid - 1;
			} elseif ( strcmp( $key, substr( $record, $width, $width ) ) > 0 ) {
				$low = $mid + 1;
			} else {
				return substr( $record, 2 * $width, 2 );
			}
		}
		return '';
	}

	/**
	 * Daily: refreshes the database if it is used and is missing or older than 28 days.
	 */
	public static function maybe_refresh() {
		if ( self::needed() && self::status()['updated'] < time() - 28 * DAY_IN_SECONDS ) {
			self::refresh();
		}
	}

	/**
	 * Downloads this month's file (or last month's, early in the month) and replaces the database.
	 * On any failure the previous database stays.
	 *
	 * @return bool
	 */
	public static function refresh() {
		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		foreach ( array( gmdate( 'Y-m' ), gmdate( 'Y-m', strtotime( 'first day of last month' ) ) ) as $month ) {
			$file = download_url( self::source_url( $month ), 300 );
			if ( is_wp_error( $file ) ) {
				continue;
			}
			$ok = self::import( $file, $month );
			wp_delete_file( $file );
			if ( $ok ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Reads a DB-IP CSV (gzip or plain: "start,end,country" per line) and writes the binary files.
	 *
	 * @param string $path  File.
	 * @param string $month Month of the data.
	 * @return bool
	 */
	public static function import( $path, $month ) {
		$handle = gzopen( $path, 'rb' ); // Reads plain files too.
		if ( ! $handle ) {
			return false;
		}
		$v4    = '';
		$v6    = '';
		$last4 = null;
		$last6 = null;
		while ( ! gzeof( $handle ) ) {
			$line = gzgets( $handle, 512 );
			if ( false === $line ) {
				break;
			}
			$row = str_getcsv( trim( $line ), ',', '"', '\\' );
			if ( count( $row ) < 3 || ! preg_match( '/^[A-Z]{2}$/', strtoupper( $row[2] ) ) ) {
				continue;
			}
			$start = inet_pton( trim( $row[0] ) );
			$end   = inet_pton( trim( $row[1] ) );
			if ( false === $start || false === $end || strlen( $start ) !== strlen( $end ) ) {
				continue;
			}
			$code = strtoupper( $row[2] );
			if ( 4 === strlen( $start ) ) {
				self::append( $v4, $last4, $start, $end, $code );
			} else {
				// Only the first 64 bits: a country is never smaller than a /64.
				self::append( $v6, $last6, substr( $start, 0, 8 ), substr( $end, 0, 8 ), $code );
			}
		}
		gzclose( $handle );
		self::flush( $v4, $last4 );
		self::flush( $v6, $last6 );

		$count4 = (int) ( strlen( $v4 ) / 10 );
		$count6 = (int) ( strlen( $v6 ) / 18 );
		// A real file has hundreds of thousands of ranges: a broken download must not replace the database.
		if ( $count4 < (int) apply_filters( 'pncp_geo_min_ranges', 10000 ) ) {
			return false;
		}
		if ( ! self::write( 'v4.bin', $v4 ) || ! self::write( 'v6.bin', $v6 ) ) {
			return false;
		}
		update_option(
			self::OPTION,
			array(
				'updated' => time(),
				'month'   => $month,
				'v4'      => $count4,
				'v6'      => $count6,
			),
			false
		);
		self::reset();
		return true;
	}

	/**
	 * Adds a range, merging it with the previous one when it continues it with the same country.
	 * Overlaps (from cutting IPv6 to /64) keep the first range.
	 *
	 * @param string                           $out   Records written so far.
	 * @param array{0:string,1:string,2:string}|null $last  The range being built.
	 * @param string                           $start Start.
	 * @param string                           $end   End.
	 * @param string                           $code  Country.
	 */
	private static function append( &$out, &$last, $start, $end, $code ) {
		if ( null !== $last ) {
			if ( strcmp( $start, $last[1] ) <= 0 ) {
				if ( strcmp( $end, $last[1] ) <= 0 ) {
					return; // Fully inside the previous range.
				}
				$start = self::increment( $last[1] );
			}
			if ( $code === $last[2] && self::increment( $last[1] ) === $start ) {
				$last[1] = $end;
				return;
			}
			$out .= $last[0] . $last[1] . $last[2];
		}
		$last = array( $start, $end, $code );
	}

	/**
	 * Writes the last range.
	 *
	 * @param string                                 $out  Records.
	 * @param array{0:string,1:string,2:string}|null $last Range.
	 */
	private static function flush( &$out, $last ) {
		if ( null !== $last ) {
			$out .= $last[0] . $last[1] . $last[2];
		}
	}

	/**
	 * The next address (big-endian bytes + 1).
	 *
	 * @param string $bytes Address.
	 * @return string
	 */
	private static function increment( $bytes ) {
		for ( $i = strlen( $bytes ) - 1; $i >= 0; $i-- ) {
			$byte = ord( $bytes[ $i ] );
			if ( $byte < 255 ) {
				$bytes[ $i ] = chr( $byte + 1 );
				return $bytes;
			}
			$bytes[ $i ] = "\0";
		}
		return $bytes;
	}

	/**
	 * Writes a file in the folder, with direct file access only.
	 *
	 * @param string $name     File name.
	 * @param string $contents Contents.
	 * @return bool
	 */
	private static function write( $name, $contents ) {
		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$dir = self::dir();
		if ( ! wp_mkdir_p( $dir ) || 'direct' !== get_filesystem_method( array(), $dir ) || ! WP_Filesystem() ) {
			return false;
		}
		global $wp_filesystem;
		if ( ! $wp_filesystem->exists( $dir . '/index.html' ) ) {
			$wp_filesystem->put_contents( $dir . '/index.html', '', FS_CHMOD_FILE );
			$wp_filesystem->put_contents( $dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n", FS_CHMOD_FILE );
		}
		return (bool) $wp_filesystem->put_contents( $dir . '/' . $name, $contents, FS_CHMOD_FILE );
	}

	/**
	 * Removes the files and the folder (uninstall).
	 */
	public static function remove_files() {
		foreach ( array( 'v4.bin', 'v6.bin', 'index.html', 'index.php', '.htaccess' ) as $name ) {
			$file = self::dir() . '/' . $name;
			if ( file_exists( $file ) ) {
				wp_delete_file( $file );
			}
		}
	}
}
