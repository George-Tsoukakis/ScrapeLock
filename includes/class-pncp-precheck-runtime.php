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
	 * 3.5: seconds after a first probe in which another probe of the same IP key is part of the same first
	 * burst (probe_seen()); PNCP_Bots::FIRST_BAN_BURST is the same for WordPress.
	 */
	const BURST = 10;

	/**
	 * Whether this request was logged here as "would block" ("Monitor only"): WordPress's own log then does
	 * not log it a second time (PNCP_Log::add()).
	 *
	 * @var bool
	 */
	public static $monitored = false;

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
		if ( ! is_array( $c ) || ! isset( $c['format'] ) || ! in_array( $c['format'], array( 2, 3 ), true ) ) {
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
		if ( ! is_array( $c ) || ! isset( $c['format'] ) || ! in_array( $c['format'], array( 2, 3 ), true ) ) {
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
		// "Monitor only": the verdict is logged as "would block" (code 0) and the request goes on, to the page
		// cache or WordPress.
		if ( self::monitoring( $c, time() ) ) {
			self::event( $c, 0, $reason, $ip );
			self::$monitored = true;
			return;
		}
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
		if ( self::emergency( $c, $now ) ) {
			// 3.4: Emergency Mode's stricter page limit and bans (never looser than the stored ones).
			// 3.4.3: the stricter of the two also here, as in PNCP_Options::emergency_overlay(), so a configuration
			// written before 3.4.3 (always 2 violations) does not loosen a stored 1 or 0 (0 = never ban stays 0).
			// The ban duration is the file's: the overlay has always taken the longer one.
			$e     = (array) $c['emergency'];
			$limit = (int) $c['limit'];
			if ( isset( $e['limit'] ) && (int) $e['limit'] > 0 ) {
				$c['limit'] = $limit > 0 ? min( $limit, (int) $e['limit'] ) : (int) $e['limit'];
			}
			$strikes = (int) $c['ban_strikes'];
			if ( isset( $e['ban_strikes'] ) && $strikes > 0 ) {
				$c['ban_strikes'] = (int) $e['ban_strikes'] > 0 ? min( $strikes, (int) $e['ban_strikes'] ) : $strikes;
			}
			$c['ban_minutes'] = isset( $e['ban_minutes'] ) ? (int) $e['ban_minutes'] : (int) $c['ban_minutes'];
			// 3.4.3: the /56 limit and the human check's stricter limit, which Emergency Mode turns on.
			if ( ! empty( $e['v6_wide'] ) ) {
				$c['v6_wide'] = true;
			}
			if ( ! empty( $e['human'] ) && isset( $c['human'] ) && is_array( $c['human'] ) ) {
				$own                 = (int) $c['human']['limit'];
				$c['human']['limit'] = $own > 0 ? min( $own, (int) $e['human'] ) : (int) $e['human'];
			}
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
		// 3.4: not without the CDN shared secret, when one is set: such a request came through someone else's
		// account at the CDN, and is limited like any other address.
		// 3.4.1: only the edge that connected (REMOTE_ADDR). A Cloudflare address from the real-IP header is a client of
		// its own (a Cloudflare Worker, which a scraper can rent), as in PNCP_Ip::is_cdn_edge().
		if ( self::is_cdn( $ip, $c ) && self::cdn_trust_ok( $c ) && self::normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '' ) === $ip ) {
			return null;
		}
		if ( self::in_any( $ip, $c['block'] ) ) {
			return array( 403, 'blocked_ip', $ip );
		}

		// Search engines: Google and Bing are verified with their official lists. The others (Applebot,
		// YandexBot) are verified with DNS by the normal check, so they are left to it.
		// A crawler that cannot be verified here (no list) still gets the ban check below: otherwise a banned
		// scraper only had to put "Applebot" in its User-Agent to read every cached page. 3.4.3: it gets a larger
		// limit of its own (below) instead of none.
		$ua         = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( (string) $_SERVER['HTTP_USER_AGENT'] ) : '';
		$unverified = false;
		foreach ( $c['crawlers'] as $i => $crawler ) {
			if ( self::ua_in( $ua, $crawler['ua'] ) ) {
				$ips = true === $crawler['ips'] ? self::crawler_set( $c, $i ) : $crawler['ips'];
				if ( null === $ips ) {
					$unverified = true;
				} elseif ( self::in_any( $ip, $ips ) ) {
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
		// 3.4.3: the bot list (and an empty User-Agent), as the normal check, unless "always allowed".
		$allowed = self::ua_allowed( $c, $ua, $ip, $reliable );
		if ( ! $allowed ) {
			if ( '' === trim( $ua ) && ! empty( $c['empty_ua'] ) ) {
				return array( 403, 'empty_ua', $ip );
			}
			if ( '' !== $ua && ! empty( $c['bots'] ) && self::ua_listed( $ua, (array) $c['bots'] ) ) {
				return array( 403, 'bot_ua', $ip );
			}
		}
		// 3.5: a scanner probe (.env, .git, wp-config.php backups, dumps, backup archives at the top of the site):
		// the configured paths can never be a WordPress page, so no 404 is needed to know. Only when the file does
		// not exist, and never for what the normal check exempts and this one cannot verify (a login cookie, a
		// crawler without a list, an allowed User-Agent, an IP that may be forged): those are left to WordPress.
		if ( isset( $c['probe'] ) && is_array( $c['probe'] ) && self::probe( $c, $ua, $ip, $bankey, $reliable, $allowed, $unverified ) ) {
			if ( ! self::monitoring( $c, $now ) && (int) $c['ban_strikes'] > 0 ) {
				$full    = self::probe_seen( $dir, $bankey, $now );
				$minutes = max( 1, (int) $c['ban_minutes'] );
				$first   = isset( $c['probe']['first'] ) ? (int) $c['probe']['first'] : 10;
				self::ban( $dir, $bankey, $now + ( $full || $first <= 0 ? $minutes : min( $first, $minutes ) ) * 60 );
				if ( $full ) {
					self::event( $c, 403, 'ban', $ip ); // The full ban, as for the page limit; the first one is the 'probe' event.
				}
			}
			return array( 403, 'probe', $ip );
		}
		// Up to here (always-blocked IPs and temporary bans) every request is checked, even a POST: otherwise
		// a cached page could be served to an IP that is already blocked or banned. The rate limit below
		// counts the GET / HEAD views; the normal check counts the rest.
		if ( ! self::countable() || self::shop_page( $c ) ) {
			return null;
		}
		$limit = (int) $c['limit'];
		if ( $limit < 1 ) {
			return null;
		}
		// 3.4.3: a crawler that cannot be verified here (Applebot, YandexBot: DNS, which the normal check does)
		// was not counted at all, so "Applebot" in the User-Agent read every cached page without limit. It now has
		// four times the page limit, never a violation: far above what the real crawler asks of one site.
		if ( $unverified ) {
			return self::hit( $c, $bankey . '|crawler', $now ) > 4 * $limit ? array( 429, 'rate_page', $ip ) : null;
		}
		// 3.4.3: a login cookie skipped this whole check before. Its name is public (a hash of the site address),
		// and a page cache that serves stored pages to logged-in users (WP Super Cache "cache for known users")
		// then served them without any limit. The check cannot verify the cookie, so it gets the blocks above
		// and four times the page limit, never a violation; staff get their own rules from the normal check.
		if ( self::login_cookie() ) {
			return self::hit( $c, $bankey . '|login', $now ) > 4 * $limit ? array( 429, 'rate_page', $ip ) : null;
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
		// 3.4.3: the human check's stricter limit for visitors without its cookie, as in the normal check.
		$human = isset( $c['human'] ) && is_array( $c['human'] ) ? (int) $c['human']['limit'] : 0;
		if ( $human > 0 && ! $allowed && ! self::human_ok( $c, $ip, $bankey ) ) {
			$unv = self::hit( $c, $bankey . '|unverified', $now );
			if ( $unv > $human ) {
				if ( $unv === $human + 1 && ! self::monitoring( $c, $now ) && self::strike( $c, $bankey, $now ) ) {
					self::ban( $dir, $bankey, $now + max( 1, (int) $c['ban_minutes'] ) * 60 );
					self::event( $c, 403, 'ban', $ip );
				}
				return array( 429, 'rate_unverified', $ip );
			}
		}
		$count = self::hit( $c, $bankey, $now );
		if ( $count <= $limit ) {
			return null;
		}
		// One "violation" per minute over the limit, as in the normal check; enough of them = a ban. Not in
		// "Monitor only", which never bans.
		if ( $count === $limit + 1 && ! self::monitoring( $c, $now ) && self::strike( $c, $bankey, $now ) ) {
			self::ban( $dir, $bankey, $now + max( 1, (int) $c['ban_minutes'] ) * 60 );
			self::event( $c, 403, 'ban', $ip ); // The event keeps the exact IP for the log.
		}
		return array( 429, 'rate_page', $ip );
	}

	/**
	 * 3.5: is this request a scanner probe to refuse and ban here ("Ban scanners on their first probe")? Only the
	 * paths of the configuration (PNCP_Probe::RUNTIME_KEYS, never a WordPress page), only for a file that does
	 * not exist, and only when the exemptions of the normal check (PNCP_Bots::should_ban_on_sight()) can be
	 * decided here; anything in doubt goes on to WordPress, which decides with the full check.
	 *
	 * @param array<string, mixed> $c          Configuration.
	 * @param string               $ua         User-Agent (lowercase).
	 * @param string               $ip         IP.
	 * @param string               $bankey     The IP's key (IPv6: the /64).
	 * @param bool                 $reliable   Whether the IP can be trusted.
	 * @param bool                 $allowed    Whether the User-Agent is always allowed.
	 * @param bool                 $unverified Whether it claims to be a crawler this check cannot verify.
	 * @return bool
	 */
	public static function probe( $c, $ua, $ip, $bankey, $reliable, $allowed, $unverified ) {
		if ( ! $reliable || $allowed || $unverified || '' === $bankey || self::login_cookie() || self::is_prefetch() ) {
			return false;
		}
		$re = isset( $c['probe']['re'] ) ? (string) $c['probe']['re'] : '';
		if ( '' === $re ) {
			return false;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$full = '/' . ltrim( rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ), '/' );
		if ( false !== strpos( $full, "\0" ) || preg_match( '#(?:^|[/\\\\])\.\.(?:[/\\\\]|$)#', $full ) ) {
			return false; // Never a file look-up outside the site: WordPress decides.
		}
		$full = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $full );
		$path = $full;
		$home = (string) $c['home'];
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		$path = (string) preg_replace( '#^/index\.php(?=/)#i', '', $path );
		if ( 1 !== @preg_match( '#' . $re . '#i', $path ) ) {
			return false;
		}
		// Sec-Fetch, as the normal check: another site's <img>, a sub-resource or a human click never bans.
		$site = isset( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ? strtolower( trim( (string) $_SERVER['HTTP_SEC_FETCH_SITE'] ) ) : '';
		$dest = isset( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ? strtolower( trim( (string) $_SERVER['HTTP_SEC_FETCH_DEST'] ) ) : '';
		$user = isset( $_SERVER['HTTP_SEC_FETCH_USER'] ) ? trim( (string) $_SERVER['HTTP_SEC_FETCH_USER'] ) : '';
		if ( ( '' !== $site && ! in_array( $site, array( 'same-origin', 'none' ), true ) ) || ( '' !== $dest && 'document' !== $dest ) || '?1' === $user ) {
			return false;
		}
		if ( '' === $site && 0 === strpos( $ua, 'mozilla/' ) ) {
			return false; // A browser without Sec-Fetch: the normal check counts its probes (3rd within 10 minutes).
		}
		if ( isset( $c['probe']['skip_ua'] ) && '' !== $ua && self::ua_in( $ua, array_filter( array_map( 'strval', (array) $c['probe']['skip_ua'] ) ) ) ) {
			return false; // Search engines without verification (pncp_trap_exempt_agents).
		}
		foreach ( (array) $c['crawlers'] as $i => $crawler ) {
			if ( is_array( $crawler ) && isset( $crawler['ips'] ) && true === $crawler['ips'] ) {
				$set = self::crawler_set( $c, $i );
				if ( is_array( $set ) && isset( $set[1] ) && self::in_any( $ip, $set ) ) {
					return false; // An official crawler address (Google, Bing), whatever its User-Agent.
				}
			}
		}
		// Only a file that does not exist; without any place to look, WordPress decides.
		$candidates = array();
		$root       = isset( $_SERVER['DOCUMENT_ROOT'] ) ? (string) $_SERVER['DOCUMENT_ROOT'] : '';
		if ( '' !== $root ) {
			$candidates[] = rtrim( $root, '/\\' ) . $full;
		}
		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
		if ( '' !== $script && 'index.php' === basename( $script ) ) {
			$candidates[] = dirname( $script ) . $path;
		}
		if ( ! $candidates ) {
			return false;
		}
		foreach ( $candidates as $file ) {
			if ( @file_exists( $file ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 3.5: the 24-hour memory of the probe ban: true when this IP key already probed within 24 hours (then the
	 * full ban); otherwise the time of this probe is written and false is returned (the short first ban). Any
	 * failure is false, never an error.
	 *
	 * @param string $dir Data folder.
	 * @param string $key The IP's key (IPv6: the /64).
	 * @param int    $now Time.
	 * @return bool
	 */
	public static function probe_seen( $dir, $key, $now ) {
		$folder = $dir . '/probes';
		if ( ! is_dir( $folder ) ) {
			@mkdir( $folder, 0755, true );
		}
		$file = $folder . '/' . md5( $key );
		$time = is_file( $file ) ? (int) @file_get_contents( $file ) : 0;
		if ( $time > $now - 86400 ) {
			// 3.5: a probe within BURST seconds of the first one is part of the same first burst (parallel requests
			// that passed the ban check before the first ban was stored): the short ban too.
			return $time <= $now - self::BURST;
		}
		@file_put_contents( $file, (string) (int) $now, LOCK_EX );
		return false;
	}

	/**
	 * Is "Monitor only" in effect (as PNCP_Options::monitoring())? The first-week monitoring of a new install
	 * ends at its time here too, even before WordPress rewrites the configuration.
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 * @return bool
	 */
	public static function monitoring( $c, $now ) {
		if ( self::emergency( $c, $now ) ) {
			return false; // 3.4: Emergency Mode really blocks, also while "Monitor only" is on (as in WordPress).
		}
		return ! empty( $c['monitor'] ) && ( empty( $c['monitor_until'] ) || $now < (int) $c['monitor_until'] );
	}

	/**
	 * Is Emergency Mode on (3.4: its end time is in the configuration)?
	 *
	 * @param array<string, mixed> $c   Configuration.
	 * @param int                  $now Time.
	 * @return bool
	 */
	public static function emergency( $c, $now ) {
		return ! empty( $c['emergency_until'] ) && $now < (int) $c['emergency_until'] && isset( $c['emergency'] ) && is_array( $c['emergency'] );
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
		$remote = self::normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '' );
		if ( '' === $remote ) {
			return '';
		}
		if ( ! self::is_local( $remote ) ) {
			return $remote;
		}
		// The server itself only when no proxy passed the request on: behind a local reverse proxy (Nginx in
		// front of Apache, Varnish) every request comes from 127.0.0.1, also the ones that went around the CDN.
		// Those are judged by the visitor's address, as PNCP_Origin::exempt() does.
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP' ) as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = self::client_ip( $c, $reliable );
				return '' !== $ip && ! self::is_local( $ip ) ? $ip : '';
			}
		}
		return '';
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
		$uri   = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$query = (string) parse_url( $uri, PHP_URL_QUERY );
		// Not doing_wp_cron: the cron loopback goes to wp-cron.php (excluded below), and on any other path it is a
		// page like the others (ALTERNATE_WP_CRON's redirect), counted by the normal check too. Left out, any
		// ?doing_wp_cron=1 added to a page skipped the bans and the page limit here.
		if ( '' !== $query && preg_match( '/(?:^|&)(?:rest_route|wc-ajax)=/i', $query ) ) {
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
	 * 3.4.1: a WooCommerce cart, checkout or My account page (or an endpoint below it, such as the order received
	 * page or My account > Orders)? These never count toward the page limit, as in the normal check: a shopper
	 * reloads them many times. The paths and page IDs come from the configuration (PNCP_Precheck::config()).
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @return bool
	 */
	public static function shop_page( $c ) {
		if ( empty( $c['shop'] ) || ! is_array( $c['shop'] ) ) {
			return false;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$ids  = isset( $c['shop']['ids'] ) ? array_map( 'intval', (array) $c['shop']['ids'] ) : array();
		$args = array();
		parse_str( (string) parse_url( $uri, PHP_URL_QUERY ), $args );
		if ( isset( $args['page_id'] ) && is_scalar( $args['page_id'] ) && in_array( (int) $args['page_id'], $ids, true ) ) {
			return true;
		}
		$path = '/' . ltrim( rawurldecode( (string) parse_url( $uri, PHP_URL_PATH ) ), '/' );
		$home = (string) $c['home'];
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		$path = strtolower( (string) preg_replace( '#^/index\.php(?=/)#i', '', $path ) );
		foreach ( isset( $c['shop']['paths'] ) ? (array) $c['shop']['paths'] : array() as $shop ) {
			$shop = (string) $shop;
			if ( '' !== $shop && '/' !== $shop && ( rtrim( $path, '/' ) === $shop || 0 === strpos( $path, $shop . '/' ) ) ) {
				return true;
			}
		}
		return false;
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
		$remote   = self::normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '' );
		$ip       = $remote;
		$header   = (string) $c['header'];
		if ( '' !== $header && ! empty( $_SERVER[ $header ] ) ) {
			$trusted = self::trusted( $remote, $c );
			$legacy  = ! empty( $c['trust_any'] ) && ! $trusted;
			if ( $trusted || $legacy ) {
				$chain = array_map( 'trim', explode( ',', (string) $_SERVER[ $header ] ) );
				$hops  = array( $remote ); // 3.4.3: the trusted proxies the address passed through.
				for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
					$candidate = self::normalize_ip( $chain[ $i ] );
					if ( '' === $candidate ) {
						break;
					}
					$ip = $candidate;
					if ( $legacy || 'HTTP_X_FORWARDED_FOR' !== $header || ! self::trusted( $ip, $c ) ) {
						break;
					}
					$hops[] = $ip;
				}
				if ( $legacy && $ip !== $remote ) {
					$reliable = false;
				}
				// 3.4.3: a Bunny CDN edge without the CDN secret, as in PNCP_Ip::client_ip(): counted, but not trusted
				// for the always-allowed IPs. Also behind a local proxy (Nginx in front of PHP: REMOTE_ADDR is
				// 127.0.0.1 and the Bunny edge is a hop further in X-Forwarded-For), so every hop is looked at.
				if ( ! $legacy && $ip !== $remote && 3 === $c['format'] && empty( $c['cdn_secret_hash'] ) && ! empty( $c['proxies_cdn']['bunny'] ) ) {
					foreach ( $hops as $hop ) {
						if ( $hop !== $ip && self::in_any( $hop, $c['cdn_bunny'] ) && ! self::in_any( $hop, $c['proxies'] )
							&& ! ( ! empty( $c['private'] ) && ! filter_var( $hop, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) ) {
							$reliable = false;
						}
					}
				}
			}
		} elseif ( '' === $header && ! empty( $c['cf_auto'] ) && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::cf_edge( $remote, $c ) ) {
			// 3.4.1: "Real visitor IP" left at the default, but the request comes from a Cloudflare edge: Cloudflare
			// always writes CF-Connecting-IP itself, so it is the visitor (as in PNCP_Ip::client_ip()). Otherwise
			// every visitor, banned or not, would pass here as the shared edge address.
			$candidate = self::normalize_ip( (string) $_SERVER['HTTP_CF_CONNECTING_IP'] );
			if ( '' !== $candidate ) {
				$ip = $candidate;
			}
		}
		return $ip;
	}

	/**
	 * May this address set CF-Connecting-IP (PNCP_Ip::is_trusted_proxy() for that header)? An explicit trusted proxy,
	 * or a Cloudflare edge when the CDN secret, if one is set, is on the request.
	 *
	 * @param string               $ip IP.
	 * @param array<string, mixed> $c  Configuration.
	 * @return bool
	 */
	public static function cf_edge( $ip, $c ) {
		if ( '' === $ip || 3 !== $c['format'] ) {
			return false;
		}
		return self::in_any( $ip, $c['proxies'] ) || ( self::cdn_trust_ok( $c ) && self::in_any( $ip, $c['cdn_cf'] ) );
	}

	/**
	 * The same spelling as PNCP_Ip::normalize() (no port or brackets, short IPv6, IPv4-mapped as IPv4), without
	 * WordPress, which is not loaded yet here.
	 *
	 * @param string $ip IP as received.
	 * @return string The IP, or ''.
	 */
	public static function normalize_ip( $ip ) {
		$ip = trim( (string) $ip );
		if ( '' === $ip ) {
			return '';
		}
		if ( '[' === $ip[0] ) {
			$end = strpos( $ip, ']' );
			$ip  = false === $end ? '' : substr( $ip, 1, $end - 1 );
		} elseif ( 1 === substr_count( $ip, ':' ) ) {
			$ip = substr( $ip, 0, (int) strpos( $ip, ':' ) );
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
		if ( 3 === $c['format'] ) {
			if ( self::in_any( $ip, $c['proxies'] ) ) {
				return true;
			}
			if ( ! self::cdn_trust_ok( $c ) ) {
				return false;
			}
			return ( ! empty( $c['proxies_cdn']['cf'] ) && self::in_any( $ip, $c['cdn_cf'] ) ) || ( ! empty( $c['proxies_cdn']['bunny'] ) && self::in_any( $ip, $c['cdn_bunny'] ) );
		}
		$set = self::cdn_trust_ok( $c ) ? $c['proxies'] : ( isset( $c['proxies_base'] ) ? $c['proxies_base'] : $c['proxies'] );
		return self::in_any( $ip, $set );
	}

	/**
	 * Is the address a CDN edge (Cloudflare, Bunny)?
	 *
	 * @param string               $ip IP.
	 * @param array<string, mixed> $c  Configuration.
	 * @return bool
	 */
	public static function is_cdn( $ip, $c ) {
		if ( 3 === $c['format'] ) {
			return self::in_any( $ip, $c['cdn_cf'] ) || self::in_any( $ip, $c['cdn_bunny'] );
		}
		return self::in_any( $ip, $c['cdn'] );
	}

	/**
	 * The official list of a crawler family, from crawlers.json: read only when a request claims to be a
	 * crawler (most requests do not), once per request.
	 *
	 * @param array<string, mixed> $c Configuration.
	 * @param int                  $i The family's position.
	 * @return array{0:array<string, bool>, 1:string[]}|null Null = no list: the normal check decides.
	 */
	public static function crawler_set( $c, $i ) {
		static $sets = null;
		if ( null === $sets ) {
			$sets = json_decode( (string) @file_get_contents( $c['dir'] . '/crawlers.json' ), true );
			$sets = is_array( $sets ) ? $sets : array();
		}
		return isset( $sets[ $i ] ) && is_array( $sets[ $i ] ) ? $sets[ $i ] : null;
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
	 * 3.4.3: does the request carry a WordPress login cookie (any; the check cannot verify it)?
	 *
	 * @return bool
	 */
	public static function login_cookie() {
		foreach ( array_keys( $_COOKIE ) as $name ) {
			if ( 0 === strpos( (string) $name, 'wordpress_logged_in_' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.4.3: is the (lowercase) User-Agent in the list? "=name" = the whole User-Agent, as
	 * PNCP_Bots::ua_in_list().
	 *
	 * @param string   $ua      User-Agent (lowercase).
	 * @param string[] $needles Lowercase needles.
	 * @return bool
	 */
	public static function ua_listed( $ua, $needles ) {
		foreach ( $needles as $needle ) {
			$needle = (string) $needle;
			if ( '' === $needle || '=' === $needle ) {
				continue;
			}
			if ( '=' === $needle[0] ? trim( $ua ) === substr( $needle, 1 ) : false !== strpos( $ua, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.4.3: does the User-Agent match an "always allowed" entry (one pinned to IPs only from them, and only
	 * when the IP is reliable), as PNCP_Bots::allow_list_match()?
	 *
	 * @param array<string, mixed> $c        Configuration.
	 * @param string               $ua       User-Agent (lowercase).
	 * @param string               $ip       IP.
	 * @param bool                 $reliable Whether the IP can be trusted.
	 * @return bool
	 */
	public static function ua_allowed( $c, $ua, $ip, $reliable ) {
		if ( '' === $ua || empty( $c['allow_ua'] ) || ! is_array( $c['allow_ua'] ) ) {
			return false;
		}
		foreach ( $c['allow_ua'] as $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry[0] ) || '' === (string) $entry[0] || false === strpos( $ua, (string) $entry[0] ) ) {
				continue;
			}
			if ( ! isset( $entry[1] ) || null === $entry[1] || ( $reliable && is_array( $entry[1] ) && self::in_any( $ip, $entry[1] ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.4.3: does the visitor have a valid human check cookie for cached pages (PNCP_Human::pc_value())?
	 *
	 * @param array<string, mixed> $c      Configuration.
	 * @param string               $ip     IP.
	 * @param string               $bankey The IP's key (IPv6: the /64).
	 * @return bool
	 */
	public static function human_ok( $c, $ip, $bankey ) {
		$name = isset( $c['human']['cookie'] ) ? (string) $c['human']['cookie'] : '';
		$key  = isset( $c['human']['key'] ) ? (string) $c['human']['key'] : '';
		if ( '' === $name || strlen( $key ) < 32 || empty( $_COOKIE[ $name ] ) || ! is_string( $_COOKIE[ $name ] ) ) {
			return false;
		}
		$parts = explode( '.', (string) $_COOKIE[ $name ] );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) || (int) $parts[0] < time() ) {
			return false;
		}
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		return hash_equals( hash_hmac( 'sha256', $parts[0] . '|' . $bankey . '|' . md5( $ua ), $key ), $parts[1] );
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
	 * @param int    $max    Most files removed in this call (0 = no limit).
	 */
	public static function cleanup( $base, $minute, $max = 300 ) {
		// At most $max files per call inside a visitor's request: after an attack spread over thousands of IPs,
		// the old minutes hold thousands of files, and one visitor must not wait for all of them. What is left
		// is removed by the next minutes' first requests and by the hourly cleanup (PNCP_Precheck::cleanup_hits).
		$left = (int) $max > 0 ? (int) $max : PHP_INT_MAX;
		foreach ( (array) @scandir( $base ) as $name ) {
			if ( ctype_digit( (string) $name ) && (int) $name < $minute - 1 ) {
				foreach ( (array) @scandir( $base . '/' . $name ) as $file ) {
					if ( '.' !== $file && '..' !== $file ) {
						if ( $left-- <= 0 ) {
							return;
						}
						@unlink( $base . '/' . $name . '/' . $file );
					}
				}
				@rmdir( $base . '/' . $name );
			}
		}
		// 3.4.3: the hourly cleanup (no limit) also removes the strikes older than their 10-minute window and the
		// expired bans. Nothing else did: one file of each stayed behind for every IP that ever hit the limit.
		if ( (int) $max <= 0 ) {
			$now  = (int) $minute * 60;
			$data = dirname( $base );
			foreach ( (array) @scandir( $data . '/strikes' ) as $file ) {
				$path = $data . '/strikes/' . $file;
				if ( '.' !== $file && '..' !== $file && is_file( $path ) && (int) @filemtime( $path ) < $now - 600 ) {
					@unlink( $path );
				}
			}
			// 3.5: the probe ban's 24-hour memory.
			foreach ( (array) @scandir( $data . '/probes' ) as $file ) {
				$path = $data . '/probes/' . $file;
				if ( '.' !== $file && '..' !== $file && is_file( $path ) && (int) @filemtime( $path ) < $now - 86400 ) {
					@unlink( $path );
				}
			}
			foreach ( (array) @scandir( $data . '/bans' ) as $file ) {
				$path = $data . '/bans/' . $file;
				// Not one written in the last minute: a new ban may have just replaced an expired one.
				if ( '.' !== $file && '..' !== $file && is_file( $path ) && (int) @filemtime( $path ) < $now - 60 && (int) @file_get_contents( $path ) <= $now ) {
					@unlink( $path );
				}
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
		// Silenced: WordPress may move the file away for its import (PNCP_Precheck) between the two calls.
		if ( is_file( $file ) && @filesize( $file ) > 2 * 1024 * 1024 ) {
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
