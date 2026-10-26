<?php
/**
 * Pre-cache check: runs from wp-config.php, before WordPress and before the page cache (WP Rocket,
 * WP Super Cache, …) can serve a stored page. Without WordPress: no database, no hooks, no translations.
 *
 * It only does what can be decided cheaply: always-blocked IPs, active bans and the page limit per IP.
 * Everything else (bots, verification of search engines, countries, the trap, logged-in users) stays with
 * the normal check, which runs for every request that is not served from the cache. Counters live in APCu
 * when available, otherwise in small files in the plugin's data folder (uploads/scrapelock/precheck-RANDOM).
 * When in doubt, the request passes: any error here must never take the site down.
 *
 * The line in wp-config.php includes this file and calls PNCP_Precheck_Runtime::boot() with the data folder;
 * the configuration is read from config.json there, written by PNCP_Precheck (includes/class-pncp-precheck.php).
 * This file only defines the class: opened directly, it does nothing.
 *
 * @package ScrapeLock
 */

// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors.Discouraged -- Runs before WordPress: its functions do not exist yet; every value is validated below.

/**
 * The check that runs before the page cache.
 */
final class PNCP_Precheck_Runtime {

	/**
	 * Called by the line in wp-config.php: reads the configuration from the data folder and runs the check.
	 *
	 * @param string $dir The data folder.
	 */
	public static function boot( $dir ) {
		try {
			$c = self::load( (string) $dir );
		} catch ( Throwable $e ) {
			return;
		}
		if ( null !== $c ) {
			self::run( $c );
		}
	}

	/**
	 * The configuration in config.json, or null. With APCu it is decoded once per change of the file.
	 *
	 * @param string $dir The data folder.
	 * @return array<string, mixed>|null
	 */
	public static function load( $dir ) {
		if ( '' === $dir ) {
			return null;
		}
		$file = $dir . '/config.json';
		$stat = @stat( $file );
		if ( false === $stat ) {
			return null;
		}
		$apcu    = function_exists( 'apcu_enabled' ) && apcu_enabled();
		$name    = 'pncp_pc_cfg_' . md5( $file );
		$version = $stat['mtime'] . '|' . $stat['size'] . '|' . $stat['ino'];
		if ( $apcu ) {
			$cached = apcu_fetch( $name );
			if ( is_array( $cached ) && isset( $cached[0], $cached[1] ) && $version === $cached[0] ) {
				return $cached[1];
			}
		}
		$c = json_decode( (string) @file_get_contents( $file ), true );
		if ( ! is_array( $c ) || ! isset( $c['format'] ) || 2 !== $c['format'] ) {
			return null;
		}
		$c['dir'] = $dir;
		if ( $apcu && ! empty( $c['apcu'] ) ) {
			apcu_store( $name, array( $version, $c ), 3600 );
		}
		return $c;
	}

	/**
	 * Runs the check. Ends the request with 403 / 429 when it must be refused, otherwise returns.
	 *
	 * @param array<string, mixed> $c Configuration (see PNCP_Precheck::config()).
	 */
	public static function run( $c ) {
		// A run.php written before 3.3.1 passes its own configuration: it does nothing until wp-admin
		// replaces its line in wp-config.php.
		if ( ! is_array( $c ) || ! isset( $c['format'] ) || 2 !== $c['format'] ) {
			return;
		}
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
		if ( 'cli' === PHP_SAPI || ! self::applies( $c ) ) {
			return null;
		}
		$direct = self::not_via_cdn( $c );
		if ( '' !== $direct ) {
			return array( 403, 'not_via_cdn', $direct );
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

		$dir    = (string) $c['dir'];
		$bankey = self::limit_key( $ip, (int) $c['v6_prefix'] ); // IPv6: the /64, so a ban is not dodged by rotating addresses.
		if ( self::banned( $dir, $bankey, $now ) ) {
			return array( 403, 'banned', $ip );
		}
		// Up to here (always-blocked IPs and temporary bans) every request is checked, even a POST: otherwise
		// a cached page could be served to an IP that is already blocked or banned. The rate limit below
		// counts the GET / HEAD views; the normal check counts the rest.
		if ( ! self::countable() ) {
			return null;
		}
		$limit = (int) $c['limit'];
		if ( $limit < 1 ) {
			return null;
		}
		// Prefetch: its own limit, three times the page limit, never a violation (as in the normal check).
		if ( self::is_prefetch() ) {
			return self::hit( $c, $bankey . '|prefetch', $now ) > 3 * $limit ? array( 429, 'rate_prefetch', $ip ) : null;
		}
		// IPv6: also the /56, at four times the limit, without a violation (as in the normal check).
		if ( ! empty( $c['v6_wide'] ) && false !== strpos( $ip, ':' ) && (int) $c['v6_prefix'] > 56 ) {
			$wide = self::limit_key( $ip, 56 );
			if ( false !== strpos( $wide, '/56' ) && self::hit( $c, $wide . '|56', $now ) > 4 * $limit ) {
				return array( 429, 'rate_page56', $ip );
			}
		}
		$count = self::hit( $c, $bankey, $now );
		if ( $count <= $limit ) {
			return null;
		}
		// One "violation" per minute over the limit, as in the normal check; enough of them = a ban.
		if ( $count === $limit + 1 && self::strike( $c, $bankey, $now ) ) {
			self::ban( $dir, $bankey, $now + max( 1, (int) $c['ban_minutes'] ) * 60 );
			self::event( $c, 403, 'ban', $ip ); // The event keeps the exact IP for the log.
		}
		return array( 429, 'rate_page', $ip );
	}

	/**
	 * "Only through the CDN": a page request without the CDN's secret went straight to the server.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return string The address it came from, or '' when it may pass.
	 */
	public static function not_via_cdn( $c ) {
		if ( empty( $c['cdn_only'] ) || self::cdn_trust_ok( $c ) ) {
			return '';
		}
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
		return filter_var( $remote, FILTER_VALIDATE_IP ) && ! self::is_local( $remote ) ? $remote : '';
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
	 * Is this a page request the check is for? Not: forms (anything but GET / HEAD, counted by the normal
	 * check), logged-in users, wp-admin, login, cron, REST, XML-RPC, AJAX and the trap; those go to the normal check anyway.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function applies( $c ) {
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
		// robots.txt, llms.txt and the TDM opt-out: every bot must be able to read them.
		if ( preg_match( '#^/(?:robots|llms|llms-full)\.txt$#i', $path ) || 0 === strcasecmp( $path, '/.well-known/tdmrep.json' ) ) {
			return false;
		}
		return ! preg_match( '#^/(?:index\.php/)?(?:wp-admin|wp-login\.php|wp-cron\.php|xmlrpc\.php|wp-json|wp-signup\.php|wp-activate\.php|wp-trackback\.php|wp-comments-post\.php|cp-[0-9a-f]{10})(?:/|$)#i', $path );
	}

	/**
	 * Does this request count toward the page limit here? Every GET/HEAD view; a prefetch toward its own,
	 * larger limit (verdict()). The prefetch headers (Sec-Fetch-Dest, Sec-Purpose) can be sent by any script,
	 * so not counting them let a single IP scrape cached pages without limit (2.8.2 and earlier). A form
	 * (POST etc.) is never served from the cache: the normal check counts it. The always-blocked list and the temporary bans in verdict() run
	 * regardless of this.
	 *
	 * @return bool
	 */
	public static function countable() {
		return in_array( self::method(), array( 'GET', 'HEAD' ), true );
	}

	/**
	 * Prefetch / prerender, as PNCP_Bots::is_prefetch() sees it.
	 *
	 * @return bool
	 */
	public static function is_prefetch() {
		if ( empty( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ) {
			return false;
		}
		foreach ( array( 'HTTP_SEC_PURPOSE', 'HTTP_PURPOSE', 'HTTP_X_MOZ', 'HTTP_X_PURPOSE' ) as $header ) {
			if ( isset( $_SERVER[ $header ] ) && ( false !== stripos( (string) $_SERVER[ $header ], 'prefetch' ) || ( 'HTTP_SEC_PURPOSE' === $header && false !== stripos( (string) $_SERVER[ $header ], 'prerender' ) ) ) ) {
				return true;
			}
		}
		return false;
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
		// With a CDN secret set but not present on the request, only the explicit "Trusted proxies" are
		// trusted, not the CDN edge lists (so a spoofed CDN edge IP cannot set the real-IP header).
		$set = self::cdn_trust_ok( $c ) ? $c['proxies'] : ( isset( $c['proxies_base'] ) ? $c['proxies_base'] : $c['proxies'] );
		return self::in_any( $ip, $set );
	}

	/**
	 * Is the CDN shared secret satisfied for this request? (true when none is configured).
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function cdn_trust_ok( $c ) {
		$hash = isset( $c['cdn_secret_hash'] ) ? (string) $c['cdn_secret_hash'] : '';
		if ( '' === $hash ) {
			return true;
		}
		$sent = isset( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] ) ? trim( (string) $_SERVER['HTTP_X_SCRAPELOCK_CDN'] ) : '';
		return '' !== $sent && hash_equals( $hash, hash( 'sha256', $sent ) );
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
	 * Appends an event for the plugin's log (imported into the database by WordPress later): one line of
	 * tab-separated text in events.log. Capped at 2 MB.
	 *
	 * @param array<string, mixed> $c      Configuration.
	 * @param int                  $code   HTTP status code.
	 * @param string               $reason Reason.
	 * @param string               $ip     IP.
	 */
	public static function event( $c, $code, $reason, $ip ) {
		$file = $c['dir'] . '/events.log';
		if ( is_file( $file ) && filesize( $file ) > 2 * 1024 * 1024 ) {
			return;
		}
		$clean = static function ( $value, $max ) {
			return substr( (string) preg_replace( '/[\x00-\x1F\x7F<>]+/', ' ', (string) $value ), 0, $max );
		};
		$uri   = isset( $_SERVER['REQUEST_URI'] ) ? (string) parse_url( (string) $_SERVER['REQUEST_URI'], PHP_URL_PATH ) : '';
		$ua    = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		$line  = implode( "\t", array( time(), (int) $code, $clean( $reason, 20 ), $clean( $ip, 45 ), $clean( $uri, 255 ), $clean( $ua, 255 ) ) ) . "\n";
		@file_put_contents( $file, $line, FILE_APPEND | LOCK_EX );
	}
}
