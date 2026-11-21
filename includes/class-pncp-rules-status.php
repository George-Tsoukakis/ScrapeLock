<?php
/**
 * 3.12.4: are the server rules installed on THIS server? (The "Status" of the Server rules tab.)
 *
 * Up to 3.12.3 the site asked its check address (PNCP_Rules::nginx_check_path()) through its public address.
 * Behind a CDN that is the CDN, not the server: Bunny CDN without "Forward Host Header" sends the origin's name
 * as Host and another server { } (the panel's default site) answers 404; a CDN that keeps a 404 in its cache (or
 * ignores the query string) answers the old 404 after the rules are installed; an edge rule refuses the request.
 * Every one of these read "Not installed", although the rules were in the site's server { }.
 *
 * - The server is asked directly first (PNCP_Self_Check::origin_candidates() / origin_request(): the site's host
 *   and port pinned to 127.0.0.1, SERVER_ADDR or SCRAPELOCK_SERVER_IPS, the Host header and the TLS name
 *   unchanged, signed, the self-check User-Agent), then the public address. Which way answered is kept.
 * - Without a fingerprint at the check address, the fingerprint header of the site's own pages
 *   (PNCP_Rules::HASH_HEADER, 3.12.3) counts, as for every self-check (PNCP_Rules_State), so the tab and the
 *   "out of date" notice say the same.
 * - Any other answer is named (kind): WordPress answered (part 2 not active in this server { }), Nginx answered
 *   itself (another location took the address: part 2 missing or nested), only the CDN answered (the server could
 *   not be asked), the CDN's cache answered, something else. text() says it in one line, and what to do.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The installed server rules, as the server itself reports them.
 */
final class PNCP_Rules_Status {

	/**
	 * Transient of the Nginx check (kept 5 minutes): array{want:string, v:int, body:string, error:string,
	 * via:string, ip:string, kind:string, code:int}. "want" and "body" are read by PNCP_Rules_State too.
	 */
	const NGINX = 'pncp_nginx_status';

	/**
	 * Transient of the Apache check (kept 5 minutes), the same shape.
	 */
	const APACHE = 'pncp_apache_status';

	/**
	 * The shape of the kept answers (3.12.3 kept want, body and error only: asked again).
	 */
	const VERSION = 2;

	/**
	 * Seconds one direct request to the server may take (a firewall that drops packets to an address of the
	 * server must not hold the Server rules tab for long).
	 */
	const ORIGIN_TIMEOUT = 3;

	/**
	 * Seconds of the request through the public address.
	 */
	const PUBLIC_TIMEOUT = 5;

	/**
	 * Whether the Nginx rules are installed and match the current settings.
	 *
	 * @param bool $fresh Ask again now (else the answer of the last 5 minutes, unless the rules changed since).
	 * @return array{state:string, parts:string[], error:string, via:string, ip:string, kind:string, code:int}
	 *         state: current, stale, missing or error; parts: the out-of-date parts (http, server); via: origin
	 *         (the server directly), public (the public address) or ''; kind: see answer_kind() and probe_nginx().
	 */
	public static function nginx( $fresh = false ) {
		$want = PNCP_Rules::nginx_fingerprint();
		$got  = $fresh ? false : self::kept( self::NGINX, $want );
		if ( ! is_array( $got ) ) {
			$got = array(
				'want' => $want,
				'v'    => self::VERSION,
			) + self::probe_nginx( $want );
			set_transient( self::NGINX, $got, 5 * MINUTE_IN_SECONDS );
		}
		return self::nginx_of( $got, $want );
	}

	/**
	 * The Nginx status of the last 5 minutes, without asking (Site Health, the self-check's lines); null when none
	 * is kept for the current rules.
	 *
	 * @return array{state:string, parts:string[], error:string, via:string, ip:string, kind:string, code:int}|null
	 */
	public static function nginx_kept() {
		$want = PNCP_Rules::nginx_fingerprint();
		$got  = self::kept( self::NGINX, $want );
		return is_array( $got ) ? self::nginx_of( $got, $want ) : null;
	}

	/**
	 * A kept answer for these rules, or false.
	 *
	 * @param string $key  Transient.
	 * @param string $want The current fingerprint.
	 * @return array<string, mixed>|false
	 */
	private static function kept( $key, $want ) {
		$got = get_transient( $key );
		if ( ! is_array( $got ) || ( $got['want'] ?? '' ) !== $want || self::VERSION !== (int) ( $got['v'] ?? 0 ) ) {
			return false;
		}
		return $got;
	}

	/**
	 * The status from a kept answer.
	 *
	 * @param array<string, mixed> $got  The kept answer.
	 * @param string               $want The current fingerprints ("<http> <server>").
	 * @return array{state:string, parts:string[], error:string, via:string, ip:string, kind:string, code:int}
	 */
	public static function nginx_of( $got, $want ) {
		$out  = self::base( $got );
		$body = trim( (string) ( $got['body'] ?? '' ) );
		if ( preg_match( '/^([0-9a-f]+) ([0-9a-f]+)$/', $body, $m ) ) {
			$wants = explode( ' ', $want . ' ' );
			if ( $m[1] !== $wants[0] ) {
				$out['parts'][] = 'http';
			}
			if ( $m[2] !== $wants[1] ) {
				$out['parts'][] = 'server';
			}
			$out['state'] = $out['parts'] ? 'stale' : 'current';
		} elseif ( 'error' === $out['kind'] ) {
			$out['state'] = 'error';
		}
		return $out;
	}

	/**
	 * The fields every status has.
	 *
	 * @param array<string, mixed> $got The kept answer.
	 * @return array{state:string, parts:string[], error:string, via:string, ip:string, kind:string, code:int}
	 */
	private static function base( $got ) {
		return array(
			'state' => 'missing',
			'parts' => array(),
			'error' => (string) ( $got['error'] ?? '' ),
			'via'   => (string) ( $got['via'] ?? '' ),
			'ip'    => (string) ( $got['ip'] ?? '' ),
			'kind'  => (string) ( $got['kind'] ?? '' ),
			'code'  => (int) ( $got['code'] ?? 0 ),
		);
	}

	/**
	 * The arguments of the status requests.
	 *
	 * @param int $timeout Seconds.
	 * @return array<string, mixed>
	 */
	private static function args( $timeout ) {
		return array(
			'timeout'             => $timeout,
			'redirection'         => 0,
			'sslverify'           => (bool) apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter for requests to the site itself.
			'user-agent'          => PNCP_Self_Check::user_agent(),
			'limit_response_size' => 65536,
		);
	}

	/**
	 * Asks the check address of the Nginx rules: the server directly first, then the public address; without a
	 * fingerprint there, the header of the site's pages; else what answered.
	 *
	 * @param string $want The current fingerprints.
	 * @return array{body:string, error:string, via:string, ip:string, kind:string, code:int}
	 */
	private static function probe_nginx( $want ) {
		$url   = add_query_arg( 't', time(), home_url( PNCP_Rules::nginx_check_path() ) ); // Past any cache.
		$first = self::probe_nginx_at( $url, $want );
		$https = isset( $first['https'] ) ? (string) $first['https'] : '';
		// An http:// site address that the server sends to https:// (aaPanel's "Force HTTPS": a 301 before any
		// location): the check address there, once.
		if ( '' !== $https ) {
			$second = self::probe_nginx_at( $first['https'], $want );
			unset( $second['https'] );
			return $second;
		}
		unset( $first['https'] );
		return $first;
	}

	/**
	 * The https:// address of the same check address that a redirect of an http:// one names ('' for any other
	 * answer or address).
	 *
	 * @param string                        $url      The address asked.
	 * @param array<string, mixed>|WP_Error $response The answer.
	 * @return string
	 */
	public static function https_redirect( $url, $response ) {
		if ( is_wp_error( $response ) || 'http' !== wp_parse_url( $url, PHP_URL_SCHEME ) ) {
			return '';
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$to   = wp_remote_retrieve_header( $response, 'location' );
		$to   = is_string( $to ) ? $to : '';
		if ( ! in_array( $code, array( 301, 302, 307, 308 ), true ) || 'https' !== wp_parse_url( $to, PHP_URL_SCHEME ) ) {
			return '';
		}
		$same = strtolower( (string) wp_parse_url( $to, PHP_URL_HOST ) ) === strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) )
			&& (string) wp_parse_url( $to, PHP_URL_PATH ) === PNCP_Rules::nginx_check_path();
		$port = (int) wp_parse_url( $to, PHP_URL_PORT );
		return $same ? add_query_arg( 't', time(), 'https://' . wp_parse_url( $to, PHP_URL_HOST ) . ( $port ? ':' . $port : '' ) . PNCP_Rules::nginx_check_path() ) : '';
	}

	/**
	 * probe_nginx() at one address.
	 *
	 * @param string $url  The check address.
	 * @param string $want The current fingerprints.
	 * @return array{body:string, error:string, via:string, ip:string, kind:string, code:int, https?:string}
	 */
	private static function probe_nginx_at( $url, $want ) {
		$origin    = null;
		$origin_ip = '';
		foreach ( PNCP_Self_Check::origin_candidates() as $ip ) {
			$response = PNCP_Self_Check::origin_request( $url, self::args( self::ORIGIN_TIMEOUT ), $ip );
			if ( null === $response ) {
				break; // Not possible here (no cURL, an address that is not the site's).
			}
			if ( ! is_wp_error( $response ) ) {
				$origin    = $response;
				$origin_ip = $ip;
				break;
			}
		}
		$https = null === $origin ? '' : self::https_redirect( $url, $origin );
		if ( '' !== $https ) {
			return array( 'https' => $https ) + self::found( '', 'origin', $origin_ip, $origin, 'redirect' );
		}
		$origin_fp = null === $origin ? '' : self::fingerprint_of( $origin );
		if ( '' !== $origin_fp && $origin_fp === $want ) {
			return self::found( $origin_fp, 'origin', $origin_ip, $origin, 'fingerprint' );
		}
		$args                = self::args( self::PUBLIC_TIMEOUT );
		$args['pncp_public'] = true; // Never routed to the server by PNCP_Self_Check::route_request(): the public way.
		$public              = wp_remote_get( $url, $args );
		$https               = self::https_redirect( $url, $public );
		if ( '' !== $https && null === $origin ) {
			return array( 'https' => $https ) + self::found( '', 'public', '', $public, 'redirect' );
		}
		$public_fp           = is_wp_error( $public ) ? '' : self::fingerprint_of( $public );
		// The server's answer counts first; the public one when the server gave none (or, at 127.0.0.1, the
		// answer of another server { } that listens there, while the site's own one answers the public way).
		if ( '' !== $public_fp && ( '' === $origin_fp || $public_fp === $want ) ) {
			return self::found( $public_fp, 'public', '', $public, 'fingerprint' );
		}
		if ( '' !== $origin_fp ) {
			return self::found( $origin_fp, 'origin', $origin_ip, $origin, 'fingerprint' );
		}
		// No fingerprint at the check address: the header of the site's own pages (3.12.3), as a self-check sees it.
		$kind   = self::nginx_kind( $origin, $public );
		$header = self::header_probe();
		if ( 'nginx' === PNCP_Rules_State::format_of( $header['value'] ) ) {
			// header_wp: the rules are active, but the check address reached WordPress (a rewrite at server level
			// before the location = of part 2 of before 3.12.4).
			return self::found( $header['value'], $header['via'], $header['ip'], null, 'wp' === $kind['kind'] ? 'header_wp' : 'header' );
		}
		$code = 0;
		if ( 'origin' === $kind['via'] && null !== $origin ) {
			$code = (int) wp_remote_retrieve_response_code( $origin );
		} elseif ( 'public' === $kind['via'] && ! is_wp_error( $public ) ) {
			$code = (int) wp_remote_retrieve_response_code( $public );
		}
		return array(
			'body'  => '',
			'error' => is_wp_error( $public ) && 'error' === $kind['kind'] ? $public->get_error_message() : '',
			'via'   => $kind['via'],
			'ip'    => 'origin' === $kind['via'] ? $origin_ip : '',
			'kind'  => $kind['kind'],
			'code'  => $code,
		);
	}

	/**
	 * A found fingerprint, as kept.
	 *
	 * @param string                    $value    Fingerprint.
	 * @param string                    $via      origin or public.
	 * @param string                    $ip       The server address (origin).
	 * @param array<string, mixed>|null $response The answer (null: from a header).
	 * @param string                    $kind     fingerprint or header.
	 * @return array{body:string, error:string, via:string, ip:string, kind:string, code:int}
	 */
	private static function found( $value, $via, $ip, $response, $kind ) {
		return array(
			'body'  => $value,
			'error' => '',
			'via'   => $via,
			'ip'    => 'origin' === $via ? $ip : '',
			'kind'  => $kind,
			'code'  => null === $response ? 200 : (int) wp_remote_retrieve_response_code( $response ),
		);
	}

	/**
	 * The fingerprints in an answer of the check address ("<http> <server>"), '' when it is not that.
	 *
	 * @param array<string, mixed> $response The answer.
	 * @return string
	 */
	public static function fingerprint_of( $response ) {
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return '';
		}
		$body = trim( (string) wp_remote_retrieve_body( $response ) );
		return 'nginx' === PNCP_Rules_State::format_of( $body ) ? $body : '';
	}

	/**
	 * What answered the check address instead of the rules.
	 *
	 * - The server answered directly: its answer says it (wp, nginx or other); a CDN plays no part in it.
	 * - Only the public address answered: cached (the CDN's cache answered), cdn (through a CDN, the server could
	 *   not be asked: another site behind the CDN's Host header, an edge rule), else wp, nginx or other.
	 * - Nothing answered: error.
	 *
	 * @param array<string, mixed>|null     $origin The server's answer (null = none).
	 * @param array<string, mixed>|WP_Error $public The public answer.
	 * @return array{kind:string, via:string}
	 */
	public static function nginx_kind( $origin, $public ) {
		if ( null !== $origin ) {
			return array(
				'kind' => self::answer_kind( $origin ),
				'via'  => 'origin',
			);
		}
		if ( is_wp_error( $public ) ) {
			return array(
				'kind' => 'error',
				'via'  => '',
			);
		}
		$headers = PNCP_Self_Check::headers_of( $public );
		if ( self::is_cached( $headers ) ) {
			$kind = 'cached';
		} elseif ( self::via_cdn( $headers ) ) {
			$kind = 'cdn';
		} else {
			$kind = self::answer_kind( $public );
		}
		return array(
			'kind' => $kind,
			'via'  => 'public',
		);
	}

	/**
	 * Who answered: wp (WordPress: ScrapeLock's marker, WordPress's headers or its 404 page), nginx (Nginx itself:
	 * its own error page, or Server: nginx without anything of WordPress), other.
	 *
	 * @param array<string, mixed> $response The answer.
	 * @return string
	 */
	public static function answer_kind( $response ) {
		$headers = PNCP_Self_Check::headers_of( $response );
		$body    = substr( (string) wp_remote_retrieve_body( $response ), 0, 65536 );
		$link    = isset( $headers['link'] ) ? $headers['link'] : '';
		if ( isset( $headers['x-scrapelock'] ) || isset( $headers['x-pingback'] ) || false !== strpos( $link, 'api.w.org' )
			|| preg_match( '#/wp-(?:content|includes)/|<body[^>]+class="[^"]*\berror404\b#i', $body ) ) {
			return 'wp';
		}
		$server = isset( $headers['server'] ) ? strtolower( $headers['server'] ) : '';
		if ( preg_match( '#<center>\s*(?:nginx|openresty|tengine)#i', $body ) || preg_match( '/^(?:nginx|openresty|tengine)/', $server ) ) {
			return 'nginx';
		}
		return 'other';
	}

	/**
	 * Did a CDN's (or a proxy's) cache answer?
	 *
	 * @param array<string, string> $headers Lowercase headers.
	 * @return bool
	 */
	public static function is_cached( $headers ) {
		foreach ( array( 'cdn-cache', 'cf-cache-status', 'x-cache', 'x-proxy-cache', 'x-cache-status', 'x-litespeed-cache' ) as $name ) {
			if ( isset( $headers[ $name ] ) && preg_match( '/\bhit\b/i', $headers[ $name ] ) ) {
				return true;
			}
		}
		return isset( $headers['age'] ) && (int) $headers['age'] > 0;
	}

	/**
	 * Did the answer come through a CDN?
	 *
	 * @param array<string, string> $headers Lowercase headers.
	 * @return bool
	 */
	public static function via_cdn( $headers ) {
		$server = isset( $headers['server'] ) ? strtolower( $headers['server'] ) : '';
		return isset( $headers['cdn-requestid'] ) || isset( $headers['cdn-pullzone'] ) || isset( $headers['cf-ray'] ) || isset( $headers['x-amz-cf-id'] )
			|| isset( $headers['x-served-by'] ) || 0 === strpos( $server, 'bunnycdn' ) || 0 === strpos( $server, 'cloudflare' );
	}

	/**
	 * The fingerprint header (PNCP_Rules::HASH_HEADER) of the site's home page: the server directly first, then the
	 * public address, only from an answer this WordPress gave to that very request (not a cached copy). Every
	 * answer is also noted by PNCP_Rules_State (PNCP_Self_Check::request()).
	 *
	 * @return array{value:string, via:string, ip:string, reached:bool} reached: this WordPress answered.
	 */
	public static function header_probe() {
		$url  = home_url( '/' );
		$args = self::args( self::ORIGIN_TIMEOUT );
		$out  = array(
			'value'   => '',
			'via'     => '',
			'ip'      => '',
			'reached' => false,
		);
		foreach ( array( 'origin', 'public' ) as $mode ) {
			if ( 'public' === $mode ) {
				$args['timeout'] = self::PUBLIC_TIMEOUT;
			}
			$result = PNCP_Self_Check::request( $url, $args, $mode );
			$last   = $result['steps'] ? end( $result['steps'] ) : null;
			if ( ! is_array( $last ) || ! PNCP_Self_Check::is_own_answer( $result['response'], (string) $last['id'] ) ) {
				continue;
			}
			$headers = PNCP_Self_Check::headers_of( $result['response'] );
			$name    = strtolower( PNCP_Rules::HASH_HEADER );
			return array(
				'value'   => isset( $headers[ $name ] ) ? trim( $headers[ $name ] ) : '',
				'via'     => (string) $last['via'],
				'ip'      => (string) $last['ip'],
				'reached' => true,
			);
		}
		return $out;
	}

	/**
	 * Is the site on aaPanel (its sites live in /www/wwwroot/)? Only the path: aaPanel's open_basedir would refuse
	 * a look at /www/server.
	 *
	 * @return bool
	 */
	public static function is_aapanel() {
		/**
		 * 3.12.4: is the site on aaPanel (the Server rules status then names aaPanel's places)?
		 *
		 * @param bool $aapanel ABSPATH is under /www/wwwroot/.
		 */
		return (bool) apply_filters( 'pncp_is_aapanel', 0 === strpos( wp_normalize_path( ABSPATH ), '/www/wwwroot/' ) );
	}

	/**
	 * The Nginx status for people: one line, what to do (details) and the notice class.
	 *
	 * @param array{state:string, parts:string[], error:string, via:string, ip:string, kind:string, code:int} $status What nginx() returned.
	 * @return array{line:string, more:string, class:string}
	 */
	public static function nginx_text( $status ) {
		$names = array(
			'http'   => __( '1) http { }', 'scrapelock' ),
			'server' => __( '2) server { }', 'scrapelock' ),
		);
		$top   = __( 'Put part 2 at the top level of the site\'s server { } (not inside another location such as location / { }, and not in http { }), then run nginx -t and reload Nginx.', 'scrapelock' );
		if ( self::is_aapanel() ) {
			$top .= ' ' . __( 'aaPanel: Website → the site → Config, right below #SSL-END, then Save.', 'scrapelock' );
		}
		$ips  = __( 'To let the check ask the server directly, add the server\'s address to SCRAPELOCK_SERVER_IPS in wp-config.php.', 'scrapelock' );
		$line = '';
		$more = '';
		$cls  = 'notice-info';
		switch ( 'current' === $status['state'] || 'stale' === $status['state'] || 'error' === $status['state'] ? $status['state'] : $status['kind'] ) {
			case 'current':
				$cls  = 'notice-success';
				$line = __( 'Installed and up to date with the current settings.', 'scrapelock' );
				break;
			case 'stale':
				$cls  = 'notice-warning';
				$line = sprintf(
					/* translators: %s: the parts, e.g. "1) http { }, 2) server { }" */
					__( 'Installed, but out of date: the settings have changed since. Copy again: %s. Then nginx -t and reload.', 'scrapelock' ),
					implode( ', ', array_intersect_key( $names, array_flip( $status['parts'] ) ) )
				);
				break;
			case 'error':
				/* translators: %s: error message */
				$line = sprintf( __( 'Could not check: the site could not reach itself (%s).', 'scrapelock' ), $status['error'] );
				$more = $ips;
				break;
			case 'wp':
				$cls  = 'notice-warning';
				$line = __( 'Not active: the check address reached WordPress, so part 2 is not in this site\'s server { }.', 'scrapelock' );
				$more = __( 'If part 2 is there, a WordPress rewrite at server level (if (!-e $request_filename) { rewrite … }, common on aaPanel, BT Panel and CloudPanel) runs first: copy part 2 again (since 3.12.4 it answers above that rewrite) and keep it above the rewrite include.', 'scrapelock' ) . ' ' . $top;
				break;
			case 'nginx':
				$cls  = 'notice-warning';
				/* translators: %d: HTTP status, e.g. 404 */
				$line = sprintf( __( 'Not active: Nginx answered the check address itself (HTTP %d), so another location took it.', 'scrapelock' ), $status['code'] );
				$more = __( 'Part 2 is missing from this site\'s server { }, or sits inside another location { }: then a regex location (on aaPanel location ~ \.well-known) answers instead.', 'scrapelock' ) . ' ' . $top;
				break;
			case 'cdn':
				$cls  = 'notice-warning';
				$line = __( 'Not seen: the server could not be asked directly, and through the CDN the check address did not answer with the rules.', 'scrapelock' );
				$more = __( 'Through the CDN another site may answer: in Bunny CDN turn on Forward Host Header (Pull zone → General → Origin).', 'scrapelock' ) . ' ' . $ips;
				break;
			case 'cached':
				$cls  = 'notice-warning';
				$line = __( 'Not seen: the CDN answered the check address from its cache. Purge it there, then Check again.', 'scrapelock' );
				$more = __( 'Purge /.well-known/scrapelock-nginx (or the whole cache) in the CDN, and do not let it cache 404 answers or ignore the query string.', 'scrapelock' ) . ' ' . $ips;
				break;
			case 'other':
				/* translators: %d: HTTP status, e.g. 403 */
				$line = sprintf( __( 'Not seen: the check address answered HTTP %d, not the rules\' fingerprint.', 'scrapelock' ), $status['code'] );
				$more = __( 'Something else answered (another web server, a firewall or a proxy). Check that Nginx serves the site and that part 2 is at the top level of its server { }.', 'scrapelock' );
				break;
			default:
				$line = __( 'Not installed on this site\'s Nginx (or the site is not served by Nginx).', 'scrapelock' );
		}
		if ( in_array( $status['state'], array( 'current', 'stale' ), true ) ) {
			$more = self::via_text( $status );
		}
		return array(
			'line'  => $line,
			'more'  => $more,
			'class' => $cls,
		);
	}

	/**
	 * Which way the rules answered, for people.
	 *
	 * @param array{via:string, ip:string, kind:string} $status Status.
	 * @return string
	 */
	public static function via_text( $status ) {
		if ( 'header_wp' === $status['kind'] ) {
			return __( 'Seen in the X-ScrapeLock-Rules header of the site\'s own pages; the check address itself reached WordPress, because a WordPress rewrite at server level runs first. Copy part 2 again: since 3.12.4 it answers the check address above that rewrite.', 'scrapelock' );
		}
		if ( 'header' === $status['kind'] ) {
			return __( 'Seen in the X-ScrapeLock-Rules header of the site\'s own pages.', 'scrapelock' );
		}
		if ( 'origin' === $status['via'] ) {
			/* translators: %s: the server address, e.g. 127.0.0.1 */
			return sprintf( __( 'Checked on the server directly (%s).', 'scrapelock' ), $status['ip'] );
		}
		return 'public' === $status['via'] ? __( 'Checked through the public address.', 'scrapelock' ) : '';
	}

	/**
	 * Should the Nginx status be told outside the Server rules tab (Site Health, the self-check)? Only on a site
	 * that uses the rules (a fingerprint was seen) and only when the check names what is wrong.
	 *
	 * @param array{state:string, kind:string}|null $status What nginx_kept() returned.
	 * @return bool
	 */
	public static function worth_telling( $status ) {
		return is_array( $status ) && 'missing' === $status['state'] && in_array( $status['kind'], array( 'wp', 'nginx', 'cdn', 'cached', 'other' ), true ) && PNCP_Rules_State::in_use();
	}

	/**
	 * The Apache status for people.
	 *
	 * @param array{state:string, kind:string, via:string, ip:string} $status What apache() returned.
	 * @return array{line:string, more:string, class:string}
	 */
	public static function apache_text( $status ) {
		if ( 'current' === $status['state'] ) {
			return array(
				'line'  => __( 'Installed and up to date with the current settings.', 'scrapelock' ),
				'more'  => self::via_text( $status ),
				'class' => 'notice-success',
			);
		}
		if ( 'stale' === $status['state'] ) {
			return array(
				'line'  => __( 'Installed, but out of date: the settings have changed since. Copy the rules again into the .htaccess.', 'scrapelock' ),
				'more'  => self::via_text( $status ),
				'class' => 'notice-warning',
			);
		}
		if ( 'error' === $status['state'] ) {
			return array(
				'line'  => __( 'Could not check: WordPress did not answer the site\'s own request.', 'scrapelock' ),
				'more'  => __( 'To let the check ask the server directly, add the server\'s address to SCRAPELOCK_SERVER_IPS in wp-config.php.', 'scrapelock' ),
				'class' => 'notice-info',
			);
		}
		return array(
			'line'  => __( 'Not installed in this site\'s .htaccess (or mod_headers is off).', 'scrapelock' ),
			'more'  => __( 'The rules send their fingerprint in a header (mod_headers) to the site\'s own requests; the site asks the server directly first. Put them above # BEGIN WordPress.', 'scrapelock' ),
			'class' => 'notice-info',
		);
	}

	/**
	 * Whether the Apache rules are installed and match the current settings: their header (mod_headers), in the
	 * answer of this WordPress to its own request, the server directly first. Apache has no check address: the
	 * header is set on every answer, whatever the order of the RewriteRules, so the .htaccess is never read.
	 *
	 * @param bool $fresh Ask again now.
	 * @return array{state:string, parts:string[], error:string, via:string, ip:string, kind:string, code:int}
	 */
	public static function apache( $fresh = false ) {
		$want = PNCP_Rules::apache_fingerprint();
		$got  = $fresh ? false : self::kept( self::APACHE, $want );
		if ( ! is_array( $got ) ) {
			$probe = self::header_probe();
			$got   = array(
				'want'  => $want,
				'v'     => self::VERSION,
				'body'  => 'apache' === PNCP_Rules_State::format_of( $probe['value'] ) ? $probe['value'] : '',
				'error' => '',
				'via'   => $probe['via'],
				'ip'    => $probe['ip'],
				'kind'  => $probe['reached'] ? ( '' === $probe['value'] ? 'no_header' : 'header' ) : 'error',
				'code'  => 0,
			);
			set_transient( self::APACHE, $got, 5 * MINUTE_IN_SECONDS );
		}
		$out  = self::base( $got );
		$body = trim( (string) ( $got['body'] ?? '' ) );
		if ( '' !== $body ) {
			$out['state'] = $body === $want ? 'current' : 'stale';
		} elseif ( 'error' === $out['kind'] ) {
			$out['state'] = 'error';
		}
		return $out;
	}
}
