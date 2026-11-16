<?php
/**
 * 3.5: "Check a request": the side-effect-free simulator (PNCP_Bots::explain(), until now only "wp scrapelock
 * check") from the Log tab, with presets, the reason and why, and curl lines for a real test.
 *
 * Nothing is counted, logged, banned or cached by a check: explain() only reads the counters, the bans and the
 * geo data, and the check runs as a logged-out visitor without the human-check cookie. The card itself is drawn
 * by PNCP_Tester_View (loaded only on the Log tab); this class holds the endpoint and the texts.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The "Check a request" endpoint (admin-ajax), its texts and the admin-bar link.
 */
final class PNCP_Tester {

	/**
	 * AJAX action and nonce action.
	 */
	const ACTION = 'pncp_check_request';

	/**
	 * TEST-NET-3 (RFC 5737): never a real visitor.
	 */
	const SAMPLE_IP = '203.0.113.10';

	/**
	 * The longest User-Agent a check accepts (bytes).
	 */
	const MAX_UA = 512;

	/**
	 * The longest address or Referer a check accepts (bytes).
	 */
	const MAX_URL = 2048;

	/**
	 * Registers the hooks: the AJAX action (logged-in users only), the admin-bar link and the assets.
	 */
	public static function init() {
		// No wp_ajax_nopriv_: a logged-out visitor gets admin-ajax's own "0".
		add_action( 'wp_ajax_' . self::ACTION, array( __CLASS__, 'ajax' ) );
		// After PNCP_Status::admin_bar() (90), which adds the "Protection: …" menu these nodes go into.
		add_action( 'admin_bar_menu', array( __CLASS__, 'admin_bar' ), 91 );
		// After PNCP_Admin::assets() (10), which registers pncp-admin.
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
	}

	/**
	 * The AJAX action: POST only, nonce, manage_options (strict: refused while the site is locked), then run().
	 */
	public static function ajax() {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		if ( 'POST' !== $method ) {
			self::send_error( 'method', __( 'The check must be sent with POST.', 'scrapelock' ), '', 405 );
		}
		if ( false === check_ajax_referer( self::ACTION, 'nonce', false ) ) {
			self::send_error( 'nonce', __( 'This page has expired. Reload it and try again.', 'scrapelock' ), '', 403 );
		}
		// Strict current_user_can(), not PNCP_Lockdown::can(): a check is an admin tool, and the Log tab is not
		// reachable while the site is locked.
		if ( ! current_user_can( 'manage_options' ) || PNCP_Lockdown::is_locked() ) {
			self::send_error( 'forbidden', __( 'You are not allowed to do this.', 'scrapelock' ), '', 403 );
		}
		$input = array();
		foreach ( array( 'mode', 'ip', 'ua', 'address', 'browser', 'referer' ) as $key ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce checked above; run() strips control characters, checks lengths and validates each field.
			$input[ $key ] = isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? (string) wp_unslash( $_POST[ $key ] ) : '';
		}
		$data = self::run( $input );
		if ( is_wp_error( $data ) ) {
			$extra = $data->get_error_data();
			self::send_error(
				(string) $data->get_error_code(),
				$data->get_error_message(),
				is_array( $extra ) && isset( $extra['field'] ) ? (string) $extra['field'] : '',
				is_array( $extra ) && isset( $extra['status'] ) ? (int) $extra['status'] : 400
			);
		}
		wp_send_json_success( $data );
	}

	/**
	 * Sends an error answer of the endpoint (section 4.4 of the spec) and stops.
	 *
	 * @param string $code    Error code (method, nonce, forbidden, ip, ua, address, referer).
	 * @param string $message Plain text for the admin.
	 * @param string $field   The form field at fault ('' = none).
	 * @param int    $status  HTTP status.
	 */
	private static function send_error( $code, $message, $field, $status ) {
		wp_send_json_error(
			array(
				'code'    => $code,
				'message' => $message,
				'field'   => $field,
			),
			$status
		);
	}

	/**
	 * Runs one check. The capability is not checked here (ajax() does it), so "wp eval" tests can call it.
	 *
	 * @param array<string, mixed> $input mode, ip, ua, address, browser, referer (already unslashed).
	 * @return array<string, mixed>|WP_Error The answer of section 4.3, or the field at fault (status 400).
	 */
	public static function run( array $input ) {
		$s       = PNCP_Options::get();
		$mode    = isset( $input['mode'] ) && 'self' === $input['mode'] ? 'self' : 'custom';
		$ip      = isset( $input['ip'] ) && is_scalar( $input['ip'] ) ? trim( (string) $input['ip'] ) : '';
		$ua      = self::clean( isset( $input['ua'] ) ? $input['ua'] : '' );
		$address = self::clean( isset( $input['address'] ) ? $input['address'] : '' );
		$referer = self::clean( isset( $input['referer'] ) ? $input['referer'] : '' );
		$browser = ! empty( $input['browser'] ) && '0' !== $input['browser'];

		// The address first: it is used in both modes.
		$url = self::address_url( $address );
		if ( '' === $url ) {
			return self::field_error( 'address', __( 'Enter an address on this site, e.g. /shop/ or /?s=shoes.', 'scrapelock' ) );
		}

		$notes = array();
		if ( 'self' === $mode ) {
			// The admin's own request: their IP as ScrapeLock sees it, their User-Agent and some of their headers.
			$ip      = PNCP_Ip::client_ip();
			$ua      = self::server_value( 'HTTP_USER_AGENT', self::MAX_UA );
			$headers = array();
			$lang    = self::server_value( 'HTTP_ACCEPT_LANGUAGE', self::MAX_URL );
			$ch_ua   = self::server_value( 'HTTP_SEC_CH_UA', self::MAX_URL );
			if ( '' !== $lang ) {
				$headers['Accept-Language'] = $lang;
			}
			if ( '' !== $ch_ua ) {
				$headers['Sec-CH-UA'] = $ch_ua;
			}
			// The browser sends "cors" for this fetch; a page visit is what is checked.
			if ( '' !== self::server_value( 'HTTP_SEC_FETCH_MODE', 64 ) ) {
				$headers['Sec-Fetch-Mode'] = 'navigate';
				$headers['Sec-Fetch-Dest'] = 'document';
			}
			$notes[] = __( 'Your own request: your IP and the headers your browser sent with this check, as if you were logged out.', 'scrapelock' );
		} else {
			if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return self::field_error( 'ip', __( 'Enter a valid IP address (IPv4 or IPv6).', 'scrapelock' ) );
			}
			if ( strlen( $ua ) > self::MAX_UA ) {
				return self::field_error( 'ua', __( 'The User-Agent is too long (512 characters at most).', 'scrapelock' ) );
			}
			if ( strlen( $referer ) > self::MAX_URL ) {
				return self::field_error( 'referer', __( 'The Referer is too long.', 'scrapelock' ) );
			}
			$headers = $browser ? self::browser_headers( $ua ) : array();
			if ( '' !== $referer ) {
				$headers['Referer'] = $referer;
			}
		}

		$result = self::explain_as_visitor( $ip, $ua, $url, $headers );

		$reasons = PNCP_Log::reasons();
		$passes  = self::pass_reasons();
		$code    = (int) $result['code'];
		$reason  = $code ? (string) $result['reason'] : '';
		$pass    = $code ? '' : (string) $result['pass'];
		$r_label = '' === $reason ? '' : ( isset( $reasons[ $reason ] ) ? $reasons[ $reason ] : $reason );
		$p_label = '' === $pass ? '' : ( isset( $passes[ $pass ] ) ? $passes[ $pass ] : $pass );

		if ( $code ) {
			$verdict  = ! empty( $result['monitor'] ) ? 'monitor' : ( 429 === $code ? 'limited' : 'blocked' );
			$badge    = 'monitor' === $verdict ? __( 'Would block', 'scrapelock' ) : ( 429 === $code ? __( 'Limited', 'scrapelock' ) : __( 'Blocked', 'scrapelock' ) );
			$headline = sprintf(
				/* translators: 1: HTTP status code (403 or 429), 2: reason */
				429 === $code ? __( 'Limited (%1$d): %2$s', 'scrapelock' ) : __( 'Blocked (%1$d): %2$s', 'scrapelock' ),
				$code,
				$r_label
			);
		} else {
			$verdict = 'allowed';
			$badge   = __( 'Allowed', 'scrapelock' );
			/* translators: %s: why the request passes */
			$headline = sprintf( __( 'Allowed: %s', 'scrapelock' ), $p_label );
		}

		$kinds = array(
			'page'    => __( 'Page', 'scrapelock' ),
			'search'  => __( 'Search', 'scrapelock' ),
			'rest'    => __( 'REST API', 'scrapelock' ),
			'graphql' => __( 'GraphQL', 'scrapelock' ),
			'sitemap' => __( 'Sitemap', 'scrapelock' ),
		);
		$context = (string) $result['context'];
		$why     = self::why( $result, $ua, $s );
		$notes   = array_merge( $notes, self::notes( $result, $ip, $ua, $url, $s ) );

		return array(
			'verdict'          => $verdict,
			'code'             => $code,
			'status'           => in_array( $verdict, array( 'blocked', 'limited' ), true ) ? $code : 200,
			'badge'            => $badge,
			'headline'         => $headline,
			'reason'           => $reason,
			'reason_label'     => $r_label,
			'pass'             => $pass,
			'pass_label'       => $p_label,
			'why'              => $why['why'],
			'link'             => $why['link'],
			'notes'            => array_values( $notes ),
			'checked_as'       => $context,
			'checked_as_label' => ( isset( $kinds[ $context ] ) ? $kinds[ $context ] : $context ) . ( ! empty( $result['feed'] ) ? ' (' . __( 'feed', 'scrapelock' ) . ')' : '' ),
			'feed'             => ! empty( $result['feed'] ),
			'monitor'          => ! empty( $result['monitor'] ),
			'inconclusive'     => ! empty( $result['inconclusive'] ),
			'request'          => array(
				'mode'    => $mode,
				'ip'      => $ip,
				'ua'      => $ua,
				'address' => $url,
				// An empty set must encode as {}, not [].
				'headers' => (object) $headers,
			),
		);
	}

	/**
	 * PNCP_Bots::explain() as a logged-out visitor without the human-check cookie: check() exempts staff, so
	 * without this every check from wp-admin would answer "exempt", and the admin's own human-check cookie must
	 * not count (explain() documents it as absent). The user and the cookies are always put back.
	 *
	 * @param string                $ip      IP.
	 * @param string                $ua      User-Agent.
	 * @param string                $url     Absolute address on this site.
	 * @param array<string, string> $headers Request headers.
	 * @return array<string, mixed> What explain() returns.
	 */
	private static function explain_as_visitor( $ip, $ua, $url, $headers ) {
		$user    = get_current_user_id();
		$cookies = array();
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- Only kept and put back exactly as they were.
		foreach ( array( PNCP_Human::COOKIE, PNCP_Human::PC_COOKIE ) as $name ) {
			if ( array_key_exists( $name, $_COOKIE ) ) {
				$cookies[ $name ] = $_COOKIE[ $name ];
				unset( $_COOKIE[ $name ] );
			}
		}
		// phpcs:enable
		wp_set_current_user( 0 );
		try {
			$result = PNCP_Bots::explain( $ip, $ua, $url, $headers );
		} finally {
			foreach ( $cookies as $name => $value ) {
				$_COOKIE[ $name ] = $value; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Put back as it was.
			}
			wp_set_current_user( $user );
		}
		return $result;
	}

	/**
	 * A field error for run().
	 *
	 * @param string $field   Field (ip, ua, address, referer); also the error code.
	 * @param string $message Plain text.
	 * @return WP_Error
	 */
	private static function field_error( $field, $message ) {
		return new WP_Error(
			$field,
			$message,
			array(
				'status' => 400,
				'field'  => $field,
			)
		);
	}

	/**
	 * A typed value without control characters, trimmed.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	private static function clean( $value ) {
		if ( ! is_scalar( $value ) ) {
			return '';
		}
		return trim( (string) preg_replace( '/[\x00-\x1F\x7F]/', '', (string) $value ) );
	}

	/**
	 * A header of the current request, unslashed, without control characters, cut to a length.
	 *
	 * @param string $key $_SERVER key.
	 * @param int    $max Bytes at most.
	 * @return string
	 */
	private static function server_value( $key, $max ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Control characters are removed; the value is only simulated and returned as JSON text.
		$value = isset( $_SERVER[ $key ] ) && is_string( $_SERVER[ $key ] ) ? self::clean( wp_unslash( $_SERVER[ $key ] ) ) : '';
		if ( strlen( $value ) > $max ) {
			$value = wp_check_invalid_utf8( substr( $value, 0, $max ), true );
		}
		return $value;
	}

	/**
	 * The typed address as an absolute URL of this site, as "wp scrapelock check" builds it.
	 *
	 * @param string $address '' (home page), /path?query, ?query, or http(s)://this-host/…
	 * @return string '' when it is not an address of this site.
	 */
	private static function address_url( $address ) {
		if ( strlen( $address ) > self::MAX_URL ) {
			return '';
		}
		if ( '' === $address ) {
			return home_url( '/' );
		}
		if ( '/' === $address[0] ) {
			return home_url( $address );
		}
		if ( '?' === $address[0] ) {
			return home_url( '/' . $address );
		}
		if ( ! preg_match( '#^https?://#i', $address ) ) {
			return '';
		}
		$host = wp_parse_url( $address, PHP_URL_HOST );
		$home = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( ! is_string( $host ) || ! is_string( $home ) || '' === $host || 0 !== strcasecmp( $host, $home ) ) {
			return '';
		}
		return $address;
	}

	/**
	 * The presets of the card, in their order. The User-Agents go into curl lines, so they never contain
	 * a double quote, $, `, \ or %.
	 *
	 * @return array<string, array{label:string, mode:string, ua:string, browser:bool}>
	 */
	public static function presets() {
		$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
		return array(
			'gptbot'          => array(
				'label'   => __( 'GPTBot (AI crawler)', 'scrapelock' ),
				'mode'    => 'custom',
				'ua'      => 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot',
				'browser' => false,
			),
			'fake_googlebot'  => array(
				'label'   => __( 'Fake Googlebot', 'scrapelock' ),
				'mode'    => 'custom',
				'ua'      => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
				'browser' => false,
			),
			'curl'            => array(
				'label'   => __( 'curl', 'scrapelock' ),
				'mode'    => 'custom',
				'ua'      => 'curl/8.5.0',
				'browser' => false,
			),
			'python_requests' => array(
				'label'   => __( 'python-requests', 'scrapelock' ),
				'mode'    => 'custom',
				'ua'      => 'python-requests/2.32.3',
				'browser' => false,
			),
			'bare_browser'    => array(
				'label'   => __( 'Browser without browser headers', 'scrapelock' ),
				'mode'    => 'custom',
				'ua'      => $chrome,
				'browser' => false,
			),
			'real_browser'    => array(
				'label'   => __( 'Real browser (Chrome)', 'scrapelock' ),
				'mode'    => 'custom',
				'ua'      => $chrome,
				'browser' => true,
			),
			'self'            => array(
				'label'   => __( 'Your own request', 'scrapelock' ),
				'mode'    => 'self',
				'ua'      => '',
				'browser' => false,
			),
		);
	}

	/**
	 * Why a request passes, as PNCP_Bots::explain() reports it (own copy: the CLI's one names WP-CLI --user).
	 *
	 * @return array<string, string>
	 */
	public static function pass_reasons() {
		return array(
			'off'           => __( 'protection is off', 'scrapelock' ),
			'cron'          => __( 'scheduled tasks (cron) are not checked', 'scrapelock' ),
			'exempt'        => __( 'the current user is exempt', 'scrapelock' ),
			'open_path'     => __( 'robots.txt, llms.txt and the TDM opt-out are never blocked', 'scrapelock' ),
			'private_url'   => __( 'a private URL with a valid token', 'scrapelock' ),
			'local'         => __( 'the server itself or a private network address', 'scrapelock' ),
			'allow_ip'      => __( 'in “Always allowed IPs”', 'scrapelock' ),
			'filter'        => __( 'let through by the pncp_skip_guard filter', 'scrapelock' ),
			'search_engine' => __( 'a verified search engine (never blocked or limited)', 'scrapelock' ),
			'ai_search'     => __( 'a verified AI search bot (never blocked or limited)', 'scrapelock' ),
			'prefetch'      => __( 'a prefetch within its own limit', 'scrapelock' ),
			'passed'        => __( 'it passes every check, and is within the limits this minute', 'scrapelock' ),
		);
	}

	/**
	 * What the check does not simulate, for the card.
	 *
	 * @return string[]
	 */
	public static function not_covered() {
		$list = array(
			__( 'The “page not found” (404) limit: the check does not know whether the address exists.', 'scrapelock' ),
			__( 'WooCommerce cart and checkout: their own limits, and the cart and checkout pages, which never count toward the page limit.', 'scrapelock' ),
			__( 'The early check and the pre-cache check: they run before WordPress, with fewer checks. A page cache or CDN may also answer before ScrapeLock sees the request.', 'scrapelock' ),
			__( 'The human-check cookie: the simulated visitor never has it, as for a script.', 'scrapelock' ),
			__( 'Private URLs (feeds with a token): the token is not checked.', 'scrapelock' ),
			__( 'The bot trap, the server rules (Nginx, Apache) and blocking at the CDN.', 'scrapelock' ),
		);
		// Only once the scanner ban (3.5) is in this build: it acts on "page not found" answers.
		if ( array_key_exists( 'probe_ban', PNCP_Options::defaults() ) ) {
			$list[] = __( 'Banning scanners on their first probe request: it acts on “page not found” answers.', 'scrapelock' );
		}
		return $list;
	}

	/**
	 * Copy-ready curl lines for a real test from another computer, built from this site's public addresses
	 * only: never a token, a secret, a nonce or a cookie.
	 *
	 * @return string Lines ending with "\n".
	 */
	public static function curl_lines() {
		$s       = PNCP_Options::get();
		$presets = self::presets();
		$home    = self::shell_url( home_url( '/' ) );
		$rest    = self::shell_url( rest_url( 'wp/v2/posts' ) );
		$cmd     = 'curl -s -o /dev/null -w "%%{http_code}\n" -A "%s" "%s"';
		$lines   = array();
		if ( '' !== $home ) {
			$lines[] = '# ' . __( 'An AI training crawler (GPTBot)', 'scrapelock' );
			$lines[] = sprintf( $cmd, $presets['gptbot']['ua'], $home );
			$lines[] = '# ' . __( 'A fake Googlebot (not from Google\'s addresses)', 'scrapelock' );
			$lines[] = sprintf( $cmd, $presets['fake_googlebot']['ua'], $home );
			$lines[] = '# ' . __( 'A script (python-requests)', 'scrapelock' );
			$lines[] = sprintf( $cmd, $presets['python_requests']['ua'], $home );
			$lines[] = '# ' . __( 'A script that copies a browser\'s User-Agent but sends no browser headers', 'scrapelock' );
			$lines[] = sprintf( $cmd, $presets['bare_browser']['ua'], $home );
		}
		if ( '' !== $rest ) {
			$lines[] = '# ' . __( 'The REST API, as a script', 'scrapelock' );
			$lines[] = sprintf( $cmd, $presets['python_requests']['ua'], $rest );
		}
		if ( '' !== $home && (int) $s['rate_limit'] > 0 ) {
			$n       = (int) $s['rate_limit'] + 2;
			$lines[] = '# ' . sprintf(
				/* translators: %d: number of requests */
				__( 'The page limit (%d pages in a row): the last ones should get 429. This one counts: the computer you run it from is limited for the rest of the minute, and running it again can block it temporarily (unblock it under “IPs blocked now”).', 'scrapelock' ),
				$n
			);
			$lines[] = sprintf(
				'for i in $(seq 1 %1$d); do curl -s -o /dev/null -w "%%{http_code} " -A "%2$s" -H "Accept-Language: en" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Dest: document" "%3$s"; done; echo',
				$n,
				$presets['real_browser']['ua'],
				$home
			);
		}
		return implode( "\n", $lines ) . ( $lines ? "\n" : '' );
	}

	/**
	 * A URL that is safe inside double quotes in a shell, or '' to skip its line.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	private static function shell_url( $url ) {
		$url = esc_url_raw( $url );
		// esc_url_raw() never leaves a double quote; $, ` and \ would still be read by the shell.
		return '' === $url || preg_match( '/["$`\\\\]/', $url ) ? '' : $url;
	}

	/**
	 * The line under the card title: whether the current user is exempt as staff.
	 *
	 * @return string
	 */
	public static function exempt_line() {
		if ( PNCP_Options::user_is_exempt( PNCP_Options::get() ) ) {
			return __( 'You are exempt as staff: ScrapeLock never blocks you while you are logged in. Test in a private window, or check a request here.', 'scrapelock' );
		}
		return __( '“Who is excluded” is set to Nobody: the checks apply to you too, even while logged in.', 'scrapelock' );
	}

	/**
	 * The data of the card's script (window.pncpTester).
	 *
	 * @return array<string, mixed>
	 */
	public static function js_data() {
		return array(
			'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
			'action'   => self::ACTION,
			'nonce'    => wp_create_nonce( self::ACTION ),
			'sampleIp' => self::SAMPLE_IP,
			'presets'  => self::presets(),
			'i18n'     => array(
				'checking'    => __( 'Checking…', 'scrapelock' ),
				'checkingDns' => __( 'Checking… A search engine is verified with a DNS lookup, which can take a few seconds.', 'scrapelock' ),
				'failed'      => __( 'The check could not run. Reload the page and try again.', 'scrapelock' ),
				'none'        => __( 'none', 'scrapelock' ),
				'checkedAs'   => __( 'Checked as', 'scrapelock' ),
				'ip'          => __( 'IP', 'scrapelock' ),
				'ua'          => __( 'User-Agent', 'scrapelock' ),
				'address'     => __( 'Address', 'scrapelock' ),
				'headers'     => __( 'Headers', 'scrapelock' ),
				'selfIp'      => __( 'your IP', 'scrapelock' ),
				'selfNote'    => __( 'Your own request: your IP and the headers your browser sent with this check.', 'scrapelock' ),
			),
		);
	}

	/**
	 * The card's CSS and JS: only on the Log tab, for administrators, while the site is not locked.
	 *
	 * @param string $hook Page hook.
	 */
	public static function assets( $hook ) {
		if ( ! class_exists( 'PNCP_Admin' ) || 'settings_page_' . PNCP_Admin::PAGE !== $hook ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only chooses which tab's assets load.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		if ( 'log' !== $tab || PNCP_Lockdown::is_locked() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_enqueue_style( 'pncp-tester', PNCP_URL . 'assets/css/tester.css', array( 'pncp-admin' ), PNCP_VERSION );
		wp_enqueue_script( 'pncp-tester', PNCP_URL . 'assets/js/tester.js', array( 'pncp-admin' ), PNCP_VERSION, true );
		wp_localize_script( 'pncp-tester', 'pncpTester', self::js_data() );
	}

	/**
	 * Two nodes in the "Protection: …" admin-bar menu: "Check a request", and the staff-exemption note.
	 *
	 * @param WP_Admin_Bar $bar The admin bar.
	 */
	public static function admin_bar( $bar ) {
		if ( ! PNCP_Lockdown::can( 'manage_options' ) || PNCP_Lockdown::is_locked() || ! is_object( $bar ) || ! $bar->get_node( 'pncp-status' ) ) {
			return;
		}
		$bar->add_node(
			array(
				'parent' => 'pncp-status',
				'id'     => 'pncp-tester-link',
				'title'  => esc_html__( 'Check a request', 'scrapelock' ),
				'href'   => PNCP_Status::settings_url( array( 'tab' => 'log' ) ) . '#pncp-tester',
			)
		);
		if ( PNCP_Options::user_is_exempt( PNCP_Options::get() ) ) {
			$bar->add_node(
				array(
					'parent' => 'pncp-status',
					'id'     => 'pncp-exempt-note',
					'title'  => esc_html__( 'You are exempt as staff: test in a private window', 'scrapelock' ),
					'href'   => false,
				)
			);
		}
	}

	/**
	 * Why the request gets this answer, and the setting that decides it.
	 *
	 * @param array<string, mixed> $result What explain() returns.
	 * @param string               $ua     User-Agent.
	 * @param array<string, mixed> $s      Settings.
	 * @return array{why:string, link:array{url:string, label:string}|null}
	 */
	private static function why( array $result, $ua, array $s ) {
		$bots      = array( 'bots', 'bots', __( 'Bots', 'scrapelock' ) );
		$allowed   = array( 'bots', 'allowed', __( 'Always allowed', 'scrapelock' ) );
		$blocked   = array( 'bots', 'blocked', __( 'Always blocked', 'scrapelock' ) );
		$ai        = array( 'bots', 'ai', __( 'AI', 'scrapelock' ) );
		$countries = array( 'bots', 'countries', __( 'Countries', 'scrapelock' ) );
		$limits    = array( 'bots', 'limits', __( 'Limits', 'scrapelock' ) );
		$human     = array( 'bots', 'human', __( 'Human check', 'scrapelock' ) );
		$why       = '';
		$link      = null;

		if ( ! empty( $result['code'] ) ) {
			$reason  = (string) $result['reason'];
			$reasons = PNCP_Log::reasons();
			$label   = isset( $reasons[ $reason ] ) ? $reasons[ $reason ] : $reason;
			switch ( $reason ) {
				case 'bot_ua':
					$why  = __( 'Its User-Agent matches an entry of the blocked bots (your bot list, the AI crawlers built into ScrapeLock, or the generic HTTP libraries when that option is on). To let a service you rely on through, add it to “Always allowed”.', 'scrapelock' );
					$link = $allowed;
					break;
				case 'empty_ua':
					$why  = __( 'The request sends no User-Agent, and requests without one are blocked.', 'scrapelock' );
					$link = $bots;
					break;
				case 'fake_crawler':
					$why  = __( 'It says it is a search engine, but its IP is not on that search engine\'s official list and its DNS name does not belong to it.', 'scrapelock' );
					$link = $bots;
					break;
				case 'fake_ai_bot':
					$why  = __( 'It says it is an AI search bot that you allow, but its IP is not on that bot\'s official IP list.', 'scrapelock' );
					$link = $ai;
					break;
				case 'no_browser':
					$why  = __( '“Browsers only” is on: a page needs an Accept-Language header and a User-Agent that starts with “Mozilla/”. Scripts usually send neither.', 'scrapelock' );
					$link = $bots;
					break;
				case 'headless':
					$why  = __( 'The browser says it is headless (HeadlessChrome in its Sec-CH-UA header).', 'scrapelock' );
					$link = $bots;
					break;
				case 'fake_browser':
					$why  = __( 'Over HTTPS the User-Agent claims Chrome, Edge or Firefox, but the request lacks the Sec-Fetch-Mode and Sec-CH-UA headers those browsers always send.', 'scrapelock' );
					$link = $bots;
					break;
				case 'blocked_ip':
					$why  = __( 'The IP is in “Always blocked” IPs.', 'scrapelock' );
					$link = $blocked;
					break;
				case 'blocked_ref':
					$why  = __( 'The Referer is in the always-blocked referrers.', 'scrapelock' );
					$link = $blocked;
					break;
				case 'banned':
					$why = __( 'This IP is blocked temporarily right now. You can unblock it under “IPs blocked now” on this tab.', 'scrapelock' );
					break;
				case 'country':
					$why  = __( 'The IP\'s country is in “Blocked countries”.', 'scrapelock' );
					$link = $countries;
					break;
				case 'rate_unverified':
					$why  = __( 'This IP is over the stricter page limit for visitors without the human check this minute (a script never has it).', 'scrapelock' );
					$link = $human;
					break;
				case 'rate_country':
					$why  = __( 'This IP is over the page limit for the stricter countries this minute.', 'scrapelock' );
					$link = $countries;
					break;
				default:
					if ( 0 === strpos( $reason, 'rate_' ) ) {
						$why = sprintf(
							/* translators: %s: name of the limit, e.g. "Pages per minute" */
							__( 'This IP is over the “%s” limit this minute: the counters of this minute were read and this check added this request (a large REST list counts as more than one), but nothing was counted.', 'scrapelock' ),
							$label
						);
						$link = $limits;
					} else {
						$why = $label;
					}
			}
		} else {
			$pass   = (string) $result['pass'];
			$passes = self::pass_reasons();
			switch ( $pass ) {
				case 'off':
					$why  = __( 'Protection is off: nothing is checked.', 'scrapelock' );
					$link = array(
						'url'   => esc_url_raw( PNCP_Status::settings_url( array( 'tab' => 'general' ) ) ),
						'label' => __( 'On the page', 'scrapelock' ), // 3.5: the tab's name (PNCP_Admin::tabs()).
					);
					break;
				case 'exempt':
					$why = __( 'Should not happen here (the check runs as a logged-out visitor); kept for completeness.', 'scrapelock' );
					break;
				case 'open_path':
					$why = __( 'A blocked bot must still be able to read the rules it is asked to follow.', 'scrapelock' );
					break;
				case 'local':
					$why = __( 'This address is the server itself, which is never blocked. Try another IP.', 'scrapelock' );
					break;
				case 'allow_ip':
					$why  = __( 'The IP is in “Always allowed IPs”: no check applies to it.', 'scrapelock' );
					$link = $allowed;
					break;
				case 'filter':
					$why = __( 'Code on this site (a theme or plugin using the pncp_skip_guard filter) lets this request through.', 'scrapelock' );
					break;
				case 'search_engine':
					$why = __( 'Its IP is on the search engine\'s official list, or its DNS name belongs to the search engine.', 'scrapelock' );
					break;
				case 'ai_search':
					$why  = __( 'You allow this AI search bot and its IP is on its official list.', 'scrapelock' );
					$link = $ai;
					break;
				case 'prefetch':
					$why  = __( 'Prefetches have their own limit, three times the page limit.', 'scrapelock' );
					$link = $limits;
					break;
				case 'passed':
					$why = __( 'It passes every check that is on, and this IP is within the limits this minute.', 'scrapelock' );
					break;
				default:
					// cron, private_url and anything newer: the label says it all.
					$why = isset( $passes[ $pass ] ) ? $passes[ $pass ] : $pass;
			}
		}

		if ( is_array( $link ) && isset( $link[0] ) ) {
			$link = array(
				'url'   => esc_url_raw( PNCP_Status::settings_url( array( 'tab' => $link[0] ) ) . '#pncp-sec-' . $link[1] ),
				'label' => $link[2],
			);
		}
		return array(
			'why'  => $why,
			'link' => $link,
		);
	}

	/**
	 * The extra notes under the answer, in the order of the spec (2.4).
	 *
	 * @param array<string, mixed> $result What explain() returns.
	 * @param string               $ip     IP.
	 * @param string               $ua     User-Agent.
	 * @param string               $url    Absolute address.
	 * @param array<string, mixed> $s      Settings.
	 * @return string[]
	 */
	private static function notes( array $result, $ip, $ua, $url, array $s ) {
		$notes  = array();
		$passed = empty( $result['code'] ) && 'passed' === $result['pass'];
		if ( ! empty( $result['monitor'] ) ) {
			$notes[] = __( 'Monitor only is on: this request would be let through and logged as “Would block”.', 'scrapelock' );
		}
		if ( $passed && ! empty( $result['inconclusive'] ) ) {
			$notes[] = __( 'It says it is a search engine, but its IP could not be verified now (DNS did not answer, or too many lookups this minute). It is not blocked as a fake; the normal limits apply.', 'scrapelock' );
		}
		if ( $passed && empty( $s['block_http_libs'] ) && PNCP_Bots::ua_in_list( $ua, PNCP_Options::http_library_agents() ) ) {
			$notes[] = __( 'Generic HTTP libraries such as curl and python-requests are not blocked: “Also block generic HTTP libraries” is off. Apps, headless front ends and sync tools use them.', 'scrapelock' );
		}
		if ( $passed && in_array( $result['context'], array( 'page', 'search' ), true ) && empty( $s['require_browser_headers'] ) && 0 !== strpos( $ua, 'Mozilla/' ) ) {
			$notes[] = __( '“Browsers only” is off, so a script that is not on the bot list gets pages within the limits.', 'scrapelock' );
		}
		if ( PNCP_Ip::is_cdn_edge( $ip ) ) {
			$notes[] = __( 'This address is a CDN edge shared by many visitors: per-IP checks (lists, temporary blocks, limits) are skipped for it.', 'scrapelock' );
		}
		$until = PNCP_Options::emergency_until();
		if ( $until ) {
			/* translators: %s: date and time */
			$notes[] = sprintf( __( 'Emergency Mode is on until %s: its stricter settings were used.', 'scrapelock' ), wp_date( 'Y-m-d H:i', $until ) );
		}
		// The same test as "wp scrapelock check".
		$path = PNCP_Private_Urls::relative_path( rawurldecode( (string) wp_parse_url( $url, PHP_URL_PATH ) ) );
		$args = array();
		wp_parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $args );
		if ( ! empty( $s['enabled'] ) && '' !== trim( (string) $s['private_paths'] ) && '' !== PNCP_Private_Urls::matching_pattern( $path, PNCP_Options::parse_list( $s['private_paths'] ), $args ) ) {
			$notes[] = __( 'This address is a private URL: without a valid token or an allowed IP it gets a 403 before these checks.', 'scrapelock' );
		}
		return $notes;
	}

	/**
	 * The headers a real browser sends, as "wp scrapelock check --browser" adds them.
	 *
	 * @param string $ua User-Agent.
	 * @return array<string, string>
	 */
	private static function browser_headers( $ua ) {
		$headers = array(
			'Accept-Language' => 'en-US,en;q=0.9',
			'Sec-Fetch-Mode'  => 'navigate',
			'Sec-Fetch-Dest'  => 'document',
		);
		if ( preg_match( '#\b(?:Chrome|Chromium)/(\d+)#', $ua, $m ) ) {
			$headers['Sec-CH-UA'] = '"Chromium";v="' . (int) $m[1] . '", "Not.A/Brand";v="99"';
		}
		return $headers;
	}
}
