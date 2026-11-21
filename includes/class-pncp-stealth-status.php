<?php
/**
 * 3.12.6: are the Stealth server rules installed on THIS server, and are they the current ones?
 *
 * The Stealth rules (PNCP_Stealth::rules_text()) carry a fingerprint of their own, like the main rules since 3.12.3:
 *
 * - Nginx: a check address (/.well-known/scrapelock-stealth) answered with the fingerprint by a server-level
 *   `if ($uri = …) { return 200 "<fingerprint>\n"; }` (a panel's WordPress rewrite at server level, e.g. aaPanel's
 *   `if (!-e $request_filename) { rewrite … }`, runs before any location) and by a `location =` as a fallback.
 * - Apache: a header (X-ScrapeLock-Stealth, mod_headers) in the answers to the site's own signed requests.
 * - The fingerprint covers every rule line but the ones that carry it, and no comment: a new plugin version with
 *   the same rules is not "out of date".
 *
 * The status (installed and up to date, out of date, installed without a fingerprint, not found) asks the server
 * directly first, then the public address (PNCP_Self_Check's origin helpers, as PNCP_Rules_Status does), and is
 * kept 5 minutes. When the folder of the new addresses or the folders of the map change (a new plugin or theme),
 * an admin notice asks to copy the Stealth rules again (dismissible per change), and Site Health says it.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The installed Stealth server rules against the current ones.
 */
final class PNCP_Stealth_Status {

	/**
	 * The check address of the Nginx rules (under the home path).
	 */
	const CHECK = '/.well-known/scrapelock-stealth';

	/**
	 * The fingerprint header of the Apache rules.
	 */
	const HEADER = 'X-ScrapeLock-Stealth';

	/**
	 * Transient of the last check (5 minutes): array{want:string, format:string, v:int, body:string, error:string,
	 * via:string, ip:string, kind:string, code:int}.
	 */
	const STATUS = 'pncp_stealth_rules_status';

	/**
	 * Option (not autoloaded): what was last seen on the server. array{installed:string, time:int, base:string,
	 * folders:string, dismissed:string}; base and folders are those of the rules when the installed ones were the
	 * current ones.
	 */
	const SEEN = 'pncp_stealth_rules_seen';

	/**
	 * Admin-post action (and nonce action) of "Dismiss".
	 */
	const DISMISS = 'pncp_stealth_rules_dismiss';

	/**
	 * The shape of the kept answers.
	 */
	const VERSION = 1;

	/**
	 * Seconds of one direct request to the server, and of the request through the public address.
	 */
	const ORIGIN_TIMEOUT = 3;
	const PUBLIC_TIMEOUT = 5;

	/**
	 * The current fingerprints of this request (rules_text() builds the address map).
	 *
	 * @var array<string, string>
	 */
	private static $current = array();

	/**
	 * Registers the hooks (wp-admin).
	 */
	public static function init() {
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_action( 'admin_post_' . self::DISMISS, array( __CLASS__, 'handle_dismiss' ) );
	}

	/* ---------- The fingerprint in the rules ---------- */

	/**
	 * The check address of the Nginx rules (with the home path of a site in a sub-folder).
	 *
	 * @return string
	 */
	public static function check_path() {
		return (string) wp_parse_url( home_url( self::CHECK ), PHP_URL_PATH );
	}

	/**
	 * The fingerprint of rule lines: every line that is not empty or a comment.
	 *
	 * @param string[] $lines Lines.
	 * @return string 12 hex digits.
	 */
	public static function hash( $lines ) {
		$rules = array();
		foreach ( $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' !== $line && 0 !== strpos( $line, '#' ) ) {
				$rules[] = $line;
			}
		}
		return substr( md5( implode( "\n", $rules ) ), 0, 12 );
	}

	/**
	 * The rule lines with the lines that carry their fingerprint: for Nginx at the top (server level, above a
	 * panel's WordPress rewrite) and a `location =` fallback; for Apache a header after the rewrites.
	 *
	 * @param string   $server apache | nginx.
	 * @param string[] $lines  The rules (PNCP_Stealth::rule_lines()).
	 * @return string[]
	 */
	public static function with_fingerprint( $server, $lines ) {
		$fp = self::hash( $lines );
		if ( 'apache' === $server ) {
			$lines[] = '# The fingerprint of these rules, sent only to ScrapeLock\'s own requests: the plugin sees which Stealth rules are installed.';
			$lines[] = '<IfModule mod_headers.c>';
			$lines[] = 'Header always set ' . self::HEADER . ' "' . $fp . '" "expr=-n %{HTTP:X-ScrapeLock-Sig}"';
			$lines[] = '</IfModule>';
			return $lines;
		}
		$path = self::check_path();
		$head = array(
			'# Lets ScrapeLock check that these Stealth rules are installed and current (tab "Server rules"). Server level and',
			'# ABOVE a WordPress rewrite at server level (if (!-e $request_filename) { rewrite ... }, aaPanel): it runs first.',
			'if ($uri = ' . $path . ') { return 200 "' . $fp . '\\n"; }',
			'location = ' . $path . ' {',
			'    default_type text/plain;',
			'    add_header Cache-Control "no-store" always;',
			'    return 200 "' . $fp . '\\n";',
			'}',
		);
		$first = array_slice( $lines, 0, 1 );
		$rest  = array_slice( $lines, 1 );
		if ( ! isset( $first[0] ) || 0 !== strpos( ltrim( (string) $first[0] ), '#' ) ) {
			return array_merge( $head, $lines );
		}
		return array_merge( $first, $head, $rest );
	}

	/**
	 * The fingerprint of the Stealth rules the current settings give.
	 *
	 * @param string $format nginx | apache.
	 * @return string
	 */
	public static function current( $format = 'nginx' ) {
		$format = 'apache' === $format ? 'apache' : 'nginx';
		if ( ! isset( self::$current[ $format ] ) ) {
			self::$current[ $format ] = self::fingerprint_in( PNCP_Stealth::rules_text( $format ), $format );
		}
		return self::$current[ $format ];
	}

	/**
	 * Forgets the fingerprints of this request (after a change of the settings or of the folders).
	 */
	public static function reset() {
		self::$current = array();
	}

	/**
	 * The fingerprint written in a text of the rules ('' when none).
	 *
	 * @param string $text   Rules.
	 * @param string $format nginx | apache.
	 * @return string
	 */
	public static function fingerprint_in( $text, $format ) {
		$regex = 'apache' === $format ? '/' . self::HEADER . ' "([0-9a-f]{12})"/' : '/return 200 "([0-9a-f]{12})\\\\n";/';
		return preg_match( $regex, (string) $text, $m ) ? $m[1] : '';
	}

	/* ---------- What the server says ---------- */

	/**
	 * Which rules this site uses: apache (Apache, LiteSpeed) or nginx (Nginx and any other server).
	 *
	 * @return string
	 */
	public static function format() {
		return 'apache' === PNCP_Stealth::server() ? 'apache' : 'nginx';
	}

	/**
	 * Whether the Stealth rules are installed and current.
	 *
	 * @param bool $fresh Ask again now (else the answer of the last 5 minutes, unless the rules changed since).
	 * @return array{state:string, format:string, installed:string, want:string, error:string, via:string, ip:string, kind:string, code:int}
	 *         state: current, stale, unmarked (Stealth works, the rules have no fingerprint: from before 3.12.6),
	 *         missing or error.
	 */
	public static function status( $fresh = false ) {
		$format = self::format();
		$want   = self::current( $format );
		$got    = $fresh ? false : self::kept( $format, $want );
		if ( ! is_array( $got ) ) {
			$got = array(
				'want'   => $want,
				'format' => $format,
				'v'      => self::VERSION,
			) + ( 'apache' === $format ? self::probe_header() : self::probe_nginx() );
			set_transient( self::STATUS, $got, 5 * MINUTE_IN_SECONDS );
		}
		$status = self::status_of( $got, $want );
		if ( '' !== $status['installed'] ) {
			self::remember( $status['installed'], $want );
		}
		return $status;
	}

	/**
	 * The status of the last 5 minutes without asking (null when none is kept for the current rules).
	 *
	 * @return array{state:string, format:string, installed:string, want:string, error:string, via:string, ip:string, kind:string, code:int}|null
	 */
	public static function kept_status() {
		$format = self::format();
		$want   = self::current( $format );
		$got    = self::kept( $format, $want );
		return is_array( $got ) ? self::status_of( $got, $want ) : null;
	}

	/**
	 * A kept answer for these rules, or false.
	 *
	 * @param string $format nginx | apache.
	 * @param string $want   The current fingerprint.
	 * @return array<string, mixed>|false
	 */
	private static function kept( $format, $want ) {
		$got = get_transient( self::STATUS );
		if ( ! is_array( $got ) || ( $got['want'] ?? '' ) !== $want || ( $got['format'] ?? '' ) !== $format || self::VERSION !== (int) ( $got['v'] ?? 0 ) ) {
			return false;
		}
		return $got;
	}

	/**
	 * The status from a kept answer.
	 *
	 * @param array<string, mixed> $got  The kept answer.
	 * @param string               $want The current fingerprint.
	 * @return array{state:string, format:string, installed:string, want:string, error:string, via:string, ip:string, kind:string, code:int}
	 */
	public static function status_of( $got, $want ) {
		$body = trim( (string) ( $got['body'] ?? '' ) );
		$body = preg_match( '/^[0-9a-f]{12}$/', $body ) ? $body : '';
		$kind = (string) ( $got['kind'] ?? '' );
		if ( '' !== $body ) {
			$state = $body === $want ? 'current' : 'stale';
		} elseif ( 'error' === $kind ) {
			$state = 'error';
		} elseif ( PNCP_Stealth::active() ) {
			$state = 'unmarked';
		} else {
			$state = 'missing';
		}
		return array(
			'state'     => $state,
			'format'    => 'apache' === ( $got['format'] ?? '' ) ? 'apache' : 'nginx',
			'installed' => $body,
			'want'      => $want,
			'error'     => (string) ( $got['error'] ?? '' ),
			'via'       => (string) ( $got['via'] ?? '' ),
			'ip'        => (string) ( $got['ip'] ?? '' ),
			'kind'      => $kind,
			'code'      => (int) ( $got['code'] ?? 0 ),
		);
	}

	/**
	 * The arguments of the requests.
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
	 * The fingerprint in an answer of the check address ('' when it is not one).
	 *
	 * @param array<string, mixed>|WP_Error|null $response The answer.
	 * @return string
	 */
	public static function body_fingerprint( $response ) {
		if ( null === $response || is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return '';
		}
		$body = trim( (string) wp_remote_retrieve_body( $response ) );
		return preg_match( '/^[0-9a-f]{12}$/', $body ) ? $body : '';
	}

	/**
	 * The https:// address of the check address that a redirect of the http:// one names ('' otherwise).
	 *
	 * @param string                             $url      The address asked.
	 * @param array<string, mixed>|WP_Error|null $response The answer.
	 * @return string
	 */
	private static function https_of( $url, $response ) {
		if ( null === $response || is_wp_error( $response ) || 'http' !== wp_parse_url( $url, PHP_URL_SCHEME ) ) {
			return '';
		}
		$to = wp_remote_retrieve_header( $response, 'location' );
		$to = is_string( $to ) ? $to : '';
		if ( ! in_array( (int) wp_remote_retrieve_response_code( $response ), array( 301, 302, 307, 308 ), true ) || 'https' !== wp_parse_url( $to, PHP_URL_SCHEME )
			|| strtolower( (string) wp_parse_url( $to, PHP_URL_HOST ) ) !== strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) )
			|| (string) wp_parse_url( $to, PHP_URL_PATH ) !== self::check_path() ) {
			return '';
		}
		$port = (int) wp_parse_url( $to, PHP_URL_PORT );
		return add_query_arg( 't', time(), 'https://' . wp_parse_url( $to, PHP_URL_HOST ) . ( $port ? ':' . $port : '' ) . self::check_path() );
	}

	/**
	 * Asks the check address: the server directly first, then the public address (one https:// redirect followed).
	 *
	 * @param string $url The address ('' = the check address of the site).
	 * @param int    $hop Redirects followed.
	 * @return array{body:string, error:string, via:string, ip:string, kind:string, code:int}
	 */
	private static function probe_nginx( $url = '', $hop = 0 ) {
		$url    = '' === $url ? add_query_arg( 't', time(), home_url( self::CHECK ) ) : $url;
		$origin = null;
		$ip_ok  = '';
		foreach ( PNCP_Self_Check::origin_candidates() as $ip ) {
			$response = PNCP_Self_Check::origin_request( $url, self::args( self::ORIGIN_TIMEOUT ), $ip );
			if ( null === $response ) {
				break; // Not possible here.
			}
			if ( ! is_wp_error( $response ) ) {
				$origin = $response;
				$ip_ok  = $ip;
				break;
			}
		}
		$https = self::https_of( $url, $origin );
		if ( '' !== $https && $hop < 1 ) {
			return self::probe_nginx( $https, $hop + 1 );
		}
		$fp = self::body_fingerprint( $origin );
		if ( '' !== $fp ) {
			return self::found( $fp, 'origin', $ip_ok, $origin );
		}
		$args                = self::args( self::PUBLIC_TIMEOUT );
		$args['pncp_public'] = true; // The public way, never routed to the server.
		$public              = wp_remote_get( $url, $args );
		$https               = self::https_of( $url, $public );
		if ( '' !== $https && $hop < 1 && null === $origin ) {
			return self::probe_nginx( $https, $hop + 1 );
		}
		$fp = self::body_fingerprint( $public );
		if ( '' !== $fp ) {
			return self::found( $fp, 'public', '', $public );
		}
		$kind = PNCP_Rules_Status::nginx_kind( $origin, $public );
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
			'ip'    => 'origin' === $kind['via'] ? $ip_ok : '',
			'kind'  => $kind['kind'],
			'code'  => $code,
		);
	}

	/**
	 * Apache: the header of the site's home page, in an answer this WordPress gave to that very request (the
	 * server directly first).
	 *
	 * @return array{body:string, error:string, via:string, ip:string, kind:string, code:int}
	 */
	private static function probe_header() {
		$args = self::args( self::ORIGIN_TIMEOUT );
		foreach ( array( 'origin', 'public' ) as $mode ) {
			if ( 'public' === $mode ) {
				$args['timeout'] = self::PUBLIC_TIMEOUT;
			}
			$result = PNCP_Self_Check::request( home_url( '/' ), $args, $mode );
			$last   = $result['steps'] ? end( $result['steps'] ) : null;
			if ( ! is_array( $last ) || ! PNCP_Self_Check::is_own_answer( $result['response'], (string) $last['id'] ) ) {
				continue;
			}
			$headers = PNCP_Self_Check::headers_of( $result['response'] );
			$value   = isset( $headers[ strtolower( self::HEADER ) ] ) ? trim( $headers[ strtolower( self::HEADER ) ] ) : '';
			return array(
				'body'  => preg_match( '/^[0-9a-f]{12}$/', $value ) ? $value : '',
				'error' => '',
				'via'   => (string) $last['via'],
				'ip'    => 'origin' === (string) $last['via'] ? (string) $last['ip'] : '',
				'kind'  => '' === $value ? 'no_header' : 'header',
				'code'  => (int) wp_remote_retrieve_response_code( $result['response'] ),
			);
		}
		return array(
			'body'  => '',
			'error' => '',
			'via'   => '',
			'ip'    => '',
			'kind'  => 'error',
			'code'  => 0,
		);
	}

	/**
	 * A found fingerprint, as kept.
	 *
	 * @param string               $value    Fingerprint.
	 * @param string               $via      origin or public.
	 * @param string               $ip       The server address (origin).
	 * @param array<string, mixed> $response The answer.
	 * @return array{body:string, error:string, via:string, ip:string, kind:string, code:int}
	 */
	private static function found( $value, $via, $ip, $response ) {
		return array(
			'body'  => $value,
			'error' => '',
			'via'   => $via,
			'ip'    => 'origin' === $via ? $ip : '',
			'kind'  => 'fingerprint',
			'code'  => (int) wp_remote_retrieve_response_code( $response ),
		);
	}

	/* ---------- "Copy the Stealth rules again" ---------- */

	/**
	 * What was seen on the server, cleaned.
	 *
	 * @return array{installed:string, time:int, base:string, folders:string, dismissed:string}
	 */
	public static function seen() {
		$raw = get_option( self::SEEN, array() );
		$raw = is_array( $raw ) ? $raw : array();
		return array(
			'installed' => isset( $raw['installed'] ) && preg_match( '/^[0-9a-f]{12}$/', (string) $raw['installed'] ) ? (string) $raw['installed'] : '',
			'time'      => isset( $raw['time'] ) ? (int) $raw['time'] : 0,
			'base'      => isset( $raw['base'] ) ? sanitize_key( (string) $raw['base'] ) : '',
			'folders'   => isset( $raw['folders'] ) ? (string) preg_replace( '/[^0-9a-f]/', '', (string) $raw['folders'] ) : '',
			'dismissed' => isset( $raw['dismissed'] ) ? (string) preg_replace( '/[^0-9a-z|]/', '', (string) $raw['dismissed'] ) : '',
		);
	}

	/**
	 * The folders of the address map now (a signature of their real addresses and the words).
	 *
	 * @return string
	 */
	public static function folders() {
		$config = PNCP_Stealth::build();
		$paths  = wp_list_pluck( $config['map'], 'path' );
		sort( $paths );
		$words = array_values( $config['words'] );
		sort( $words );
		return substr( md5( (string) wp_json_encode( array( $paths, $words ) ) ), 0, 12 );
	}

	/**
	 * Notes the fingerprint the server reported (written only when something changed).
	 *
	 * @param string $installed The installed fingerprint.
	 * @param string $want      The current one.
	 */
	public static function remember( $installed, $want ) {
		$seen = self::seen();
		$new  = $seen;
		if ( $installed !== $seen['installed'] ) {
			$new['installed'] = $installed;
			$new['time']      = time();
		}
		if ( $installed === $want ) {
			$new['base']    = (string) PNCP_Stealth::settings()['stealth_base'];
			$new['folders'] = self::folders();
			// 3.12.8: the server has the rules of a map the pages do not use yet (copied or installed without
			// "Test again"): it is tested and put into use shortly (PNCP_Stealth::refresh()).
			$state = PNCP_Stealth::state();
			if ( '' !== (string) $state['pending'] && 'failed' !== (string) $state['pending'] ) {
				PNCP_Stealth::schedule_refresh();
			}
		}
		if ( $new !== $seen ) {
			if ( false === get_option( self::SEEN, false ) ) {
				add_option( self::SEEN, $new, '', false );
			} else {
				update_option( self::SEEN, $new, false );
			}
		}
	}

	/**
	 * Why the Stealth rules on the server must be copied again ('' = they need not): base (the folder of the
	 * new addresses changed), folders (a plugin or theme folder appeared or went), changed (anything else).
	 * Only while Stealth is turned on, and not where ScrapeLock writes the rules into .htaccess itself.
	 *
	 * @return string
	 */
	public static function needs_copy() {
		$s = PNCP_Stealth::settings();
		if ( empty( $s['stealth_enabled'] ) || empty( $s['enabled'] ) ) {
			return '';
		}
		$state  = PNCP_Stealth::state();
		$format = self::format();
		if ( 'apache' === $format && ! empty( $state['htaccess'] ) ) {
			return '';
		}
		$seen = self::seen();
		$base = (string) $s['stealth_base'];
		if ( '' !== $seen['installed'] ) {
			$want = self::current( $format );
			if ( $want === $seen['installed'] ) {
				return '';
			}
			if ( '' !== $seen['base'] && $seen['base'] !== $base ) {
				return 'base';
			}
			$now = self::folders();
			return '' !== $seen['folders'] && $now !== $seen['folders'] ? 'folders' : 'changed';
		}
		// Rules without a fingerprint (from before 3.12.6): what Stealth itself noticed.
		if ( '' !== (string) $state['base'] && (string) $state['base'] !== $base ) {
			return 'base';
		}
		return ! empty( $state['active'] ) && '' !== (string) $state['pending'] && 'failed' !== (string) $state['pending'] ? 'folders' : '';
	}

	/**
	 * 3.12.8: what the administrator has to do next about the Stealth rules, for WP-CLI ('' = nothing): the
	 * notice's text with the commands, or, while the new map waits for its rules, how to put it into use.
	 *
	 * @return string
	 */
	public static function cli_next() {
		$reason = self::needs_copy();
		if ( '' !== $reason ) {
			return self::message( $reason ) . ' ' . ( 'apache' === self::format()
				? __( 'With WP-CLI: wp scrapelock rules install --stealth-apache=<file>, then wp scrapelock stealth test.', 'scrapelock' )
				: __( 'With WP-CLI: wp scrapelock rules install --stealth=<file>, then wp scrapelock stealth test.', 'scrapelock' ) );
		}
		$state = PNCP_Stealth::state();
		if ( empty( $state['active'] ) || '' === (string) $state['pending'] || 'failed' === (string) $state['pending'] ) {
			return '';
		}
		$kept = self::kept_status();
		return null !== $kept && 'current' === $kept['state']
			? __( 'The server has the Stealth rules of a new address map: ScrapeLock tests it and puts it into use within a minute (or now: wp scrapelock stealth test).', 'scrapelock' )
			: __( 'A new address map waits for its Stealth rules: copy the Stealth rules again (wp scrapelock rules install), then run wp scrapelock stealth test.', 'scrapelock' );
	}

	/**
	 * The text of the notice.
	 *
	 * @param string $reason What needs_copy() returned.
	 * @return string
	 */
	public static function message( $reason ) {
		$then = 'apache' === self::format()
			? __( 'Put them into the .htaccess file, above # BEGIN WordPress, then press "Test again" in Stealth.', 'scrapelock' )
			: __( 'Put them into the server configuration, run nginx -t, reload Nginx, then press "Test again" in Stealth.', 'scrapelock' );
		switch ( $reason ) {
			case 'base':
				$why = __( 'The folder of the Stealth addresses changed: copy the Stealth rules again (Server rules → Stealth).', 'scrapelock' );
				break;
			case 'folders':
				$why = __( 'A plugin or theme folder changed: copy the Stealth rules again (Server rules → Stealth). Until then its files are served through the general wp-content address.', 'scrapelock' );
				break;
			default:
				$why = __( 'The Stealth rules on the server are out of date: copy the Stealth rules again (Server rules → Stealth).', 'scrapelock' );
		}
		return $why . ' ' . $then;
	}

	/**
	 * The admin notice: administrators, ScrapeLock's pages and the dashboard, until dismissed for this change.
	 */
	public static function notice() {
		if ( ! current_user_can( 'manage_options' ) || ! PNCP_Status::notice_screen() ) {
			return;
		}
		$reason = self::needs_copy();
		if ( '' === $reason || self::pair( $reason ) === self::seen()['dismissed'] ) {
			return;
		}
		$url = PNCP_Status::settings_url( array( 'tab' => 'rules' ) ) . '#pncp-rules-stealth';
		echo '<div class="notice notice-warning pncp-stealth-rules-stale"><p><strong>ScrapeLock:</strong> ' . esc_html( self::message( $reason ) ) . '</p><p>';
		printf( '<a class="button button-secondary" href="%s">%s</a> ', esc_url( $url ), esc_html__( 'Open the Stealth rules', 'scrapelock' ) );
		printf( '<form method="post" action="%s" style="display:inline">', esc_url( admin_url( 'admin-post.php' ) ) );
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( self::DISMISS ) );
		wp_nonce_field( self::DISMISS );
		echo '<button type="submit" class="button-link">' . esc_html__( 'Dismiss', 'scrapelock' ) . '</button></form></p></div>';
	}

	/**
	 * What a dismissal is for: the reason and the fingerprints.
	 *
	 * @param string $reason What needs_copy() returned.
	 * @return string
	 */
	private static function pair( $reason ) {
		return $reason . '|' . self::seen()['installed'] . '|' . self::current( self::format() );
	}

	/**
	 * "Dismiss" (admin-post, nonce, manage_options): until the rules change again.
	 */
	public static function handle_dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::DISMISS );
		$reason = self::needs_copy();
		if ( '' !== $reason ) {
			$seen              = self::seen();
			$seen['dismissed'] = self::pair( $reason );
			update_option( self::SEEN, $seen, false );
		}
		$back = wp_get_referer();
		wp_safe_redirect( $back ? $back : admin_url() );
		exit;
	}

	/* ---------- For people ---------- */

	/**
	 * The status in one line, what to do, and the notice class.
	 *
	 * @param array{state:string, format:string, installed:string, want:string, error:string, via:string, ip:string, kind:string, code:int} $status What status() returned.
	 * @return array{line:string, more:string, class:string}
	 */
	public static function text( $status ) {
		$apache = 'apache' === $status['format'];
		$place  = $apache
			? __( 'Put the Apache rules into the .htaccess file, above # BEGIN WordPress (ScrapeLock writes them there itself when it may).', 'scrapelock' )
			: __( 'Put the Nginx rules at the top level of the site\'s server { }, above the WordPress rewrite, then nginx -t and reload.', 'scrapelock' );
		if ( ! $apache && PNCP_Rules_Status::is_aapanel() ) {
			$place .= ' ' . self::aapanel_text();
		}
		$cls  = 'notice-info';
		$more = '';
		switch ( $status['state'] ) {
			case 'current':
				$cls  = 'notice-success';
				$line = __( 'Installed and up to date.', 'scrapelock' );
				$more = PNCP_Rules_Status::via_text( $status );
				break;
			case 'stale':
				$cls  = 'notice-warning';
				$line = __( 'Installed, but out of date: the folder of the addresses or the folders of the plugins and themes changed. Copy the Stealth rules again.', 'scrapelock' );
				$more = $place;
				break;
			case 'unmarked':
				$line = __( 'Installed and working, but without a fingerprint (rules from before 3.12.6): copy them again to let ScrapeLock see whether they are up to date.', 'scrapelock' );
				$more = $place;
				break;
			case 'error':
				/* translators: %s: error message */
				$line = sprintf( __( 'Could not check: the site could not reach itself (%s).', 'scrapelock' ), $status['error'] );
				$more = __( 'To let the check ask the server directly, add the server\'s address to SCRAPELOCK_SERVER_IPS in wp-config.php.', 'scrapelock' );
				break;
			default:
				$cls  = PNCP_Stealth::active() || ! empty( PNCP_Stealth::settings()['stealth_enabled'] ) ? 'notice-warning' : 'notice-info';
				$line = __( 'Not found on this server.', 'scrapelock' );
				if ( 'wp' === $status['kind'] && ! $apache ) {
					$more = __( 'The check address reached WordPress: the Stealth rules are not in this site\'s server { }, or they are below a WordPress rewrite at server level, which runs first.', 'scrapelock' ) . ' ' . $place;
				} elseif ( 'cached' === $status['kind'] ) {
					$more = __( 'The CDN answered the check address from its cache: purge it there, then check again.', 'scrapelock' );
				} elseif ( 'cdn' === $status['kind'] ) {
					$more = __( 'The server could not be asked directly, and through the CDN the check address did not answer with the rules. To let the check ask the server directly, add the server\'s address to SCRAPELOCK_SERVER_IPS in wp-config.php.', 'scrapelock' );
				} else {
					$more = $place;
				}
		}
		return array(
			'line'  => $line,
			'more'  => $more,
			'class' => $cls,
		);
	}

	/**
	 * Where the Stealth rules go on aaPanel.
	 *
	 * @return string
	 */
	public static function aapanel_text() {
		return __( 'aaPanel: a file of its own in /www/server/panel/vhost/nginx/extension/<site>/, after scrapelock.conf (the files there are read in alphabetical order), e.g. z-scrapelock-stealth.conf. That folder is included at the top of the site\'s server { }, before the rewrite include, so the Stealth rules run before the WordPress rewrite.', 'scrapelock' );
	}

	/**
	 * The Stealth card of the Server rules tab: the status, where the rules go, the rules.
	 */
	public static function render_rules_card() {
		$s = PNCP_Stealth::settings();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only asks the site again; changes nothing.
		$fresh = isset( $_GET['pncp_stealth_check'] );
		$on    = ! empty( $s['stealth_enabled'] );
		?>
		<section class="pncp-card pncp-card--wide pncp-rules-card" id="pncp-rules-stealth" aria-labelledby="pncp-rules-stealth-title">
		<h2 id="pncp-rules-stealth-title"><?php esc_html_e( 'Stealth', 'scrapelock' ); ?></h2>
		<?php if ( $on || '' !== self::seen()['installed'] ) : ?>
			<?php
			$text  = self::text( self::status( $fresh ) );
			$again = PNCP_Status::settings_url(
				array(
					'tab'                => 'rules',
					'pncp_stealth_check' => 1,
				)
			) . '#pncp-rules-stealth';
			?>
			<div class="notice <?php echo esc_attr( $text['class'] ); ?> inline" id="pncp-stealth-rules-status"><p><strong><?php esc_html_e( 'Status:', 'scrapelock' ); ?></strong> <?php echo esc_html( $text['line'] ); ?>
				<a href="<?php echo esc_url( $again ); ?>"><?php esc_html_e( 'Check again', 'scrapelock' ); ?></a></p>
				<?php echo PNCP_Admin_Fields::more( $text['more'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?></div>
		<?php else : ?>
			<p class="description"><?php esc_html_e( 'Stealth is off (Vulnerable points → Stealth): these rules are needed only when it is on.', 'scrapelock' ); ?></p>
		<?php endif; ?>
		<?php echo PNCP_Admin_Fields::para( __( 'They serve Stealth\'s neutral addresses. Copy them again after a base folder change or a new plugin or theme.', 'scrapelock' ), __( 'They map the neutral addresses back to the real files by pattern, so files that a plugin writes later (e.g. the minified files of WP Rocket after its cache is cleared) are served too. They carry a fingerprint, so this status says whether the rules on the server are the current ones. With an optimization plugin (WP Rocket, Autoptimize, LiteSpeed Cache, W3 Total Cache) they also turn the inner wp-content and wp-includes of its files\' addresses back.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<div class="pncp-rules-steps">
		<div class="pncp-rules-step">
		<h3><?php esc_html_e( 'Nginx', 'scrapelock' ); ?></h3>
		<ul class="ul-disc description">
			<li><?php esc_html_e( 'At the top level of the site\'s server { } (not inside a location), after part 2 of the ScrapeLock rules and above the WordPress rewrite: a WordPress rewrite at server level (aaPanel, BT Panel, CloudPanel) runs before any location.', 'scrapelock' ); ?></li>
			<li><?php echo esc_html( self::aapanel_text() ); ?></li>
			<li><?php esc_html_e( 'Then run nginx -t, reload Nginx only if it says “test is successful”, and press “Test again” in Stealth.', 'scrapelock' ); ?></li>
		</ul>
		<?php self::code_block( 'pncp-stealth-nginx', PNCP_Stealth::rules_text( 'nginx' ), 10 ); ?>
		</div>
		<div class="pncp-rules-step">
		<h3><?php esc_html_e( 'Apache (.htaccess, above # BEGIN WordPress)', 'scrapelock' ); ?></h3>
		<p class="description"><?php esc_html_e( 'ScrapeLock writes them into .htaccess itself when it may; otherwise copy them there.', 'scrapelock' ); ?></p>
		<?php self::code_block( 'pncp-stealth-apache', PNCP_Stealth::rules_text( 'apache' ), 10 ); ?>
		</div>
		</div>
		</section>
		<?php
	}

	/**
	 * Read-only code field with a copy button (the markup of the Server rules tab).
	 *
	 * @param string $id   ID.
	 * @param string $code Code.
	 * @param int    $rows Rows.
	 */
	private static function code_block( $id, $code, $rows ) {
		printf(
			'<div class="pncp-code"><textarea id="%1$s" class="large-text code" rows="%2$d" readonly aria-label="%3$s">%4$s</textarea><p><button type="button" class="button pncp-copy" data-target="%1$s">%5$s</button></p></div>',
			esc_attr( $id ),
			(int) $rows,
			esc_attr__( 'Rules to copy', 'scrapelock' ),
			esc_textarea( $code ),
			esc_html__( 'Copy', 'scrapelock' )
		);
	}

	/**
	 * The status line of the Stealth card (Vulnerable points): the last check, without asking.
	 */
	public static function render_card_line() {
		$status = self::kept_status();
		$reason = self::needs_copy();
		$url    = PNCP_Status::settings_url( array( 'tab' => 'rules' ) ) . '#pncp-rules-stealth';
		if ( '' !== $reason ) {
			$line = self::message( $reason );
			$cls  = 'notice-warning';
		} elseif ( null !== $status ) {
			$text = self::text( $status );
			$line = $text['line'];
			$cls  = $text['class'];
		} else {
			return;
		}
		printf( '<div class="notice %1$s inline" id="pncp-stealth-card-rules"><p><strong>%2$s</strong> %3$s <a href="%4$s">%5$s</a></p></div>', esc_attr( $cls ), esc_html__( 'Server rules:', 'scrapelock' ), esc_html( $line ), esc_url( $url ), esc_html__( 'Open the Stealth rules', 'scrapelock' ) );
	}

	/**
	 * Site Health: adds the state of the Stealth rules to Stealth's result.
	 *
	 * @param array<string, mixed> $result PNCP_Stealth::health_result().
	 * @return array<string, mixed>
	 */
	public static function health( $result ) {
		$s = PNCP_Stealth::settings();
		if ( empty( $s['stealth_enabled'] ) ) {
			return $result;
		}
		$status = self::status();
		$reason = self::needs_copy();
		$link   = current_user_can( 'manage_options' ) ? '<p><a class="button" href="' . esc_url( PNCP_Status::settings_url( array( 'tab' => 'rules' ) ) . '#pncp-rules-stealth' ) . '">' . esc_html__( 'Open the Stealth rules', 'scrapelock' ) . '</a></p>' : '';
		if ( '' !== $reason || 'stale' === $status['state'] ) {
			$result['status']               = 'recommended';
			$result['label']                = __( 'The ScrapeLock Stealth server rules are out of date', 'scrapelock' );
			$result['description']          = '<p>' . esc_html( self::message( '' !== $reason ? $reason : 'changed' ) ) . '</p>';
			$result['actions']              = $link . ( isset( $result['actions'] ) ? (string) $result['actions'] : '' );
			$result['badge']['color']       = 'orange';
			return $result;
		}
		$text                   = self::text( $status );
		$result['description'] .= '<p>' . esc_html__( 'Stealth server rules:', 'scrapelock' ) . ' ' . esc_html( $text['line'] ) . '</p>';
		if ( 'missing' === $status['state'] && 'good' === $result['status'] ) {
			$result['status'] = 'recommended';
			$result['label']  = __( 'The ScrapeLock Stealth server rules were not found on this server', 'scrapelock' );
		}
		return $result;
	}
}
