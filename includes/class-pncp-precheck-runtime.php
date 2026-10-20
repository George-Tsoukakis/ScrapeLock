<?php
/**
 * Pre-cache check: runs from wp-config.php, before WordPress and before the page cache (WP Rocket,
 * WP Super Cache, …) can serve a stored page. Without WordPress: no database, no hooks, no translations.
 *
 * It only does what can be decided cheaply: always-blocked IPs, active bans and the page limit per IP.
 * Everything else (bots, verification of search engines, countries, the trap, logged-in users) stays with
 * the normal check, which runs for every request that is not served from the cache. Counters live in APCu
 * when available, otherwise in small files in the plugin's data folder. When in doubt, the request passes:
 * any error here must never take the site down.
 *
 * The configuration is written by PNCP_Precheck (includes/class-pncp-precheck.php) into the generated
 * run.php, which calls PNCP_Precheck_Runtime::run().
 *
 * @package ScrapeLock
 */

// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors.Discouraged -- Runs before WordPress: its functions do not exist yet; every value is validated below.

/**
 * The check that runs before the page cache.
 */
final class PNCP_Precheck_Runtime {

	/**
	 * Runs the check. Ends the request with 403 / 429 when it must be refused, otherwise returns.
	 *
	 * @param array<string, mixed> $c Configuration (see PNCP_Precheck::config()).
	 */
	public static function run( $c ) {
		try {
			$verdict = self::verdict( $c, time() );
		} catch ( Throwable $e ) {
			return;
		}
		if ( null === $verdict ) {
			return;
		}
		list( $code, $reason, $ip ) = $verdict;
		self::event( $c, $code, $reason, $ip );
		if ( ! headers_sent() ) {
			http_response_code( $code );
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'X-Robots-Tag: noindex' );
			if ( 429 === $code ) {
				header( 'Retry-After: 60' );
			}
		}
		if ( 'HEAD' !== self::method() ) {
			echo 429 === $code ? 'Too many requests.' : 'Access denied.';
		}
		exit;
	}

	/**
	 * The decision: null (passes) or [code, reason, IP].
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 * @return array{0:int, 1:string, 2:string}|null
	 */
	public static function verdict( $c, $now ) {
		if ( 'cli' === PHP_SAPI || ! self::counts( $c ) ) {
			return null;
		}
		$ip = self::client_ip( $c, $reliable );
		if ( '' === $ip || self::is_local( $ip ) ) {
			return null;
		}
		if ( $reliable && self::in_any( $ip, $c['allow'] ) ) {
			return null;
		}
		// A CDN address means "Real visitor IP" is not set: then one decision would hit many visitors at once.
		if ( self::in_any( $ip, $c['cdn'] ) ) {
			return null;
		}
		if ( self::in_any( $ip, $c['block'] ) ) {
			return array( 403, 'blocked_ip', $ip );
		}

		// Search engines: Google and Bing are verified with their official lists. The others (Applebot,
		// YandexBot) are verified with DNS by the normal check, so they are left to it.
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( (string) $_SERVER['HTTP_USER_AGENT'] ) : '';
		foreach ( $c['crawlers'] as $crawler ) {
			if ( self::ua_in( $ua, $crawler['ua'] ) ) {
				if ( null === $crawler['ips'] || self::in_any( $ip, $crawler['ips'] ) ) {
					return null;
				}
				break; // Claims to be Google / Bing from another address: counted like everyone else.
			}
		}

		$dir = (string) $c['dir'];
		if ( self::banned( $dir, $ip, $now ) ) {
			return array( 403, 'banned', $ip );
		}
		$limit = (int) $c['limit'];
		if ( $limit < 1 ) {
			return null;
		}
		$key   = self::limit_key( $ip, (int) $c['v6_prefix'] );
		$count = self::hit( $c, $key, $now );
		if ( $count <= $limit ) {
			return null;
		}
		// One "violation" per minute over the limit, as in the normal check; enough of them = a ban.
		if ( $count === $limit + 1 && self::strike( $c, $key, $now ) ) {
			self::ban( $dir, $ip, $now + max( 1, (int) $c['ban_minutes'] ) * 60 );
			self::event( $c, 403, 'ban', $ip );
		}
		return array( 429, 'rate_page', $ip );
	}

	/**
	 * The request method.
	 *
	 * @return string
	 */
	public static function method() {
		return isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) $_SERVER['REQUEST_METHOD'] ) : 'GET';
	}

	/**
	 * Is this a page request the check is for? Not: forms (anything but GET / HEAD), prefetch, logged-in
	 * users, wp-admin, login, cron, REST, XML-RPC, AJAX and the trap; those go to the normal check anyway.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function counts( $c ) {
		if ( ! in_array( self::method(), array( 'GET', 'HEAD' ), true ) ) {
			return false;
		}
		foreach ( array( 'HTTP_SEC_PURPOSE', 'HTTP_PURPOSE', 'HTTP_X_MOZ', 'HTTP_X_PURPOSE' ) as $header ) {
			if ( isset( $_SERVER[ $header ] ) && false !== stripos( (string) $_SERVER[ $header ], 'prefetch' ) ) {
				return false;
			}
		}
		// Page caches never serve these cookies a stored page: the normal check sees them.
		foreach ( array_keys( $_COOKIE ) as $name ) {
			if ( 0 === strpos( (string) $name, 'wordpress_logged_in_' ) ) {
				return false;
			}
		}
		$uri   = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$query = (string) parse_url( $uri, PHP_URL_QUERY );
		if ( '' !== $query && preg_match( '/(?:^|&)(?:rest_route|wc-ajax|doing_wp_cron)=/i', $query ) ) {
			return false;
		}
		$path = '/' . ltrim( rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ), '/' );
		$home = (string) $c['home'];
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		// robots.txt and llms.txt: every bot must be able to read them.
		if ( preg_match( '#^/(?:robots|llms|llms-full)\.txt$#i', $path ) ) {
			return false;
		}
		return ! preg_match( '#^/(?:index\.php/)?(?:wp-admin|wp-login\.php|wp-cron\.php|xmlrpc\.php|wp-json|wp-signup\.php|wp-activate\.php|wp-trackback\.php|wp-comments-post\.php|cp-[0-9a-f]{10})(?:/|$)#i', $path );
	}

	/**
	 * The visitor's IP, as PNCP_Ip::client_ip() finds it: the selected header only from a trusted proxy.
	 *
	 * @param array<string, mixed> $c        Configuration.
	 * @param bool                 $reliable Set to false when the IP may be spoofed ("trust every proxy").
	 * @return string
	 */
	public static function client_ip( $c, &$reliable ) {
		$reliable = true;
		$remote   = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
		$remote   = filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '';
		$ip       = $remote;
		$header   = (string) $c['header'];
		if ( '' !== $header && ! empty( $_SERVER[ $header ] ) ) {
			$trusted = self::trusted( $remote, $c );
			$legacy  = ! empty( $c['trust_any'] ) && ! $trusted;
			if ( $trusted || $legacy ) {
				$chain = array_map( 'trim', explode( ',', (string) $_SERVER[ $header ] ) );
				for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
					if ( ! filter_var( $chain[ $i ], FILTER_VALIDATE_IP ) ) {
						break;
					}
					$ip = $chain[ $i ];
					if ( $legacy || 'HTTP_X_FORWARDED_FOR' !== $header || ! self::trusted( $ip, $c ) ) {
						break;
					}
				}
				if ( $legacy && $ip !== $remote ) {
					$reliable = false;
				}
			}
		}
		return $ip;
	}

	/**
	 * Is the address a proxy trusted for the selected header?
	 *
	 * @param string               $ip IP.
	 * @param array<string, mixed> $c  Configuration.
	 * @return bool
	 */
	public static function trusted( $ip, $c ) {
		if ( '' === $ip ) {
			return false;
		}
		if ( ! empty( $c['private'] ) && filter_var( $ip, FILTER_VALIDATE_IP ) && ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return true;
		}
		return self::in_any( $ip, $c['proxies'] );
	}

	/**
	 * The server itself (cron, cache preload, loopback)?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_local( $ip ) {
		return in_array( $ip, array( '127.0.0.1', '::1' ), true ) || ( isset( $_SERVER['SERVER_ADDR'] ) && (string) $_SERVER['SERVER_ADDR'] === $ip );
	}

	/**
	 * Does the IP belong to a set? A set is [ exact addresses (address => true), CIDRs ].
	 *
	 * @param string                                  $ip  IP.
	 * @param array{0:array<string, bool>, 1:string[]} $set Set.
	 * @return bool
	 */
	public static function in_any( $ip, $set ) {
		$packed = @inet_pton( $ip );
		if ( false === $packed ) {
			return false;
		}
		if ( isset( $set[0][ (string) inet_ntop( $packed ) ] ) ) {
			return true;
		}
		foreach ( $set[1] as $range ) {
			list( $subnet, $bits ) = explode( '/', $range, 2 );
			$net                   = @inet_pton( $subnet );
			if ( false === $net || strlen( $net ) !== strlen( $packed ) ) {
				continue;
			}
			$bits  = (int) $bits;
			$bytes = intdiv( $bits, 8 );
			if ( substr( $packed, 0, $bytes ) !== substr( $net, 0, $bytes ) ) {
				continue;
			}
			$rest = $bits % 8;
			if ( 0 === $rest ) {
				return true;
			}
			$mask = 0xFF << ( 8 - $rest ) & 0xFF;
			if ( ( ord( $packed[ $bytes ] ) & $mask ) === ( ord( $net[ $bytes ] ) & $mask ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Does the (lowercase) User-Agent contain one of the (lowercase) needles?
	 *
	 * @param string   $ua      User-Agent.
	 * @param string[] $needles Needles.
	 * @return bool
	 */
	public static function ua_in( $ua, $needles ) {
		foreach ( $needles as $needle ) {
			if ( false !== strpos( $ua, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The key an IP is counted under, as PNCP_Ip::limit_key(): IPv6 per network (/64 by default).
	 *
	 * @param string $ip     IP.
	 * @param int    $prefix IPv6 prefix.
	 * @return string
	 */
	public static function limit_key( $ip, $prefix ) {
		$bin = @inet_pton( $ip );
		if ( false === $bin || 16 !== strlen( $bin ) ) {
			return $ip;
		}
		if ( 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			return (string) inet_ntop( substr( $bin, 12 ) );
		}
		$prefix = max( 48, min( 128, $prefix ) );
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
	 * Counts a page for the key in the current minute and returns the count.
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param string               $key Key.
	 * @param int                  $now Time.
	 * @return int
	 */
	public static function hit( $c, $key, $now ) {
		$minute = (int) floor( $now / 60 );
		if ( ! empty( $c['apcu'] ) && function_exists( 'apcu_enabled' ) && apcu_enabled() ) {
			$name = 'pncp_pc_' . md5( $c['dir'] . '|' . $key . '|' . $minute );
			apcu_add( $name, 0, 120 );
			$count = apcu_inc( $name );
			if ( false !== $count ) {
				return (int) $count;
			}
		}
		$dir = $c['dir'] . '/hits/' . $minute;
		if ( ! is_dir( $dir ) && @mkdir( $dir, 0755, true ) ) {
			self::cleanup( $c['dir'] . '/hits', $minute );
		}
		return self::increment( $dir . '/' . md5( $key ) );
	}

	/**
	 * Adds 1 to a counter file, under a lock.
	 *
	 * @param string $file File.
	 * @return int The new value (0 if the file cannot be written: the request then passes).
	 */
	public static function increment( $file ) {
		$handle = @fopen( $file, 'c+' );
		if ( ! $handle ) {
			return 0;
		}
		$count = 0;
		if ( flock( $handle, LOCK_EX ) ) {
			$count = (int) stream_get_contents( $handle ) + 1;
			ftruncate( $handle, 0 );
			rewind( $handle );
			fwrite( $handle, (string) $count );
			fflush( $handle );
			flock( $handle, LOCK_UN );
		}
		fclose( $handle );
		return $count;
	}

	/**
	 * Removes the counters of past minutes (once a minute, by the first request of the new minute).
	 *
	 * @param string $base   The hits folder.
	 * @param int    $minute Current minute.
	 */
	public static function cleanup( $base, $minute ) {
		foreach ( (array) @scandir( $base ) as $name ) {
			if ( ctype_digit( (string) $name ) && (int) $name < $minute - 1 ) {
				foreach ( (array) @scandir( $base . '/' . $name ) as $file ) {
					if ( '.' !== $file && '..' !== $file ) {
						@unlink( $base . '/' . $name . '/' . $file );
					}
				}
				@rmdir( $base . '/' . $name );
			}
		}
	}

	/**
	 * Records a violation; true when they reach the configured number within 10 minutes.
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param string               $key Key.
	 * @param int                  $now Time.
	 * @return bool
	 */
	public static function strike( $c, $key, $now ) {
		$needed = (int) $c['ban_strikes'];
		if ( $needed < 1 ) {
			return false;
		}
		$dir = $c['dir'] . '/strikes';
		if ( ! is_dir( $dir ) ) {
			@mkdir( $dir, 0755, true );
		}
		$file   = $dir . '/' . md5( $key );
		$handle = @fopen( $file, 'c+' );
		if ( ! $handle ) {
			return false;
		}
		$banned = false;
		if ( flock( $handle, LOCK_EX ) ) {
			$parts = explode( '|', (string) stream_get_contents( $handle ) );
			$first = isset( $parts[1] ) ? (int) $parts[0] : 0;
			$count = isset( $parts[1] ) ? (int) $parts[1] : 0;
			if ( $now - $first > 600 ) {
				$first = $now;
				$count = 0;
			}
			++$count;
			$banned = $count >= $needed;
			ftruncate( $handle, 0 );
			rewind( $handle );
			fwrite( $handle, $banned ? '' : $first . '|' . $count );
			flock( $handle, LOCK_UN );
		}
		fclose( $handle );
		return $banned;
	}

	/**
	 * Is the IP banned? (A file per IP with the expiry; written here and by the normal check.)
	 *
	 * @param string $dir Data folder.
	 * @param string $ip  IP.
	 * @param int    $now Time.
	 * @return bool
	 */
	public static function banned( $dir, $ip, $now ) {
		$file = $dir . '/bans/' . md5( $ip );
		if ( ! is_file( $file ) ) {
			return false;
		}
		return (int) @file_get_contents( $file ) > $now;
	}

	/**
	 * Bans an IP until a time.
	 *
	 * @param string $dir   Data folder.
	 * @param string $ip    IP.
	 * @param int    $until Expiry.
	 */
	public static function ban( $dir, $ip, $until ) {
		if ( ! is_dir( $dir . '/bans' ) ) {
			@mkdir( $dir . '/bans', 0755, true );
		}
		@file_put_contents( $dir . '/bans/' . md5( $ip ), (string) $until, LOCK_EX );
	}

	/**
	 * Appends an event for the plugin's log (imported into the database by WordPress later). The file starts
	 * with "<?php exit;" so that it shows nothing if someone opens it from the web. Capped at 2 MB.
	 *
	 * @param array<string, mixed> $c      Configuration.
	 * @param int                  $code   HTTP status code.
	 * @param string               $reason Reason.
	 * @param string               $ip     IP.
	 */
	public static function event( $c, $code, $reason, $ip ) {
		$file = $c['dir'] . '/events.php';
		if ( is_file( $file ) && filesize( $file ) > 2 * 1024 * 1024 ) {
			return;
		}
		$clean = static function ( $value, $max ) {
			return substr( (string) preg_replace( '/[\x00-\x1F\x7F]+/', ' ', (string) $value ), 0, $max );
		};
		$uri   = isset( $_SERVER['REQUEST_URI'] ) ? (string) parse_url( (string) $_SERVER['REQUEST_URI'], PHP_URL_PATH ) : '';
		$ua    = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		$line  = implode( "\t", array( time(), (int) $code, $clean( $reason, 20 ), $clean( $ip, 45 ), $clean( $uri, 255 ), $clean( $ua, 255 ) ) ) . "\n";
		if ( ! is_file( $file ) ) {
			$line = "<?php exit; ?>\n" . $line;
		}
		@file_put_contents( $file, $line, FILE_APPEND | LOCK_EX );
	}
}
