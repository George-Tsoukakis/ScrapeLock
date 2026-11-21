<?php
/**
 * 3.12.3: are the server rules on the server the current ones?
 *
 * The generated Nginx and Apache rules carry their fingerprint in a response header (PNCP_Rules::HASH_HEADER),
 * sent only to the site's own signed requests. Every self-check (Vulnerable points, Site Health, "Run a real
 * self-check now", wp scrapelock selfcheck) reads it from an answer this WordPress gave to that very request
 * (observe()) and compares it with the fingerprint of the rules the current settings give. Nginx rules of before
 * 3.12.3 have no header: their check address (PNCP_Rules::nginx_status()) answers instead.
 *
 * - The result is kept in a small option (STATE): the installed fingerprint, the current one, when it was seen.
 * - A site that never had rules installed (no fingerprint was ever seen) is never told anything.
 * - A settings change that changes the rules marks them out of date at once (settings_changed()).
 * - 3.12.6: "installed" is what the server last reported, and stays so: a settings save only recomputes "current",
 *   and one answer without the header (a location with add_header lines of its own, the moment of a reload, a
 *   cached copy) says nothing about the server. "Not found" is told only when two fresh checks of the server, a few
 *   seconds apart, found no rules (checked(); the second one runs from the admin page, recheck()). When only one
 *   part of the Nginx rules differs, the message names it.
 * - Out of date: an admin notice (manage_options, ScrapeLock's pages and the dashboard, dismissible per
 *   fingerprint) and a Site Health "recommended" result, both with "See what changed": a line diff of the rules
 *   as they were when copied (the Server rules tab keeps the text of the last few, remember_texts()) and now.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The installed server rules against the current ones.
 */
final class PNCP_Rules_State {

	/**
	 * Option (not autoloaded): array{installed:string, format:string, current:string, time:int, seen:int,
	 * dismissed:string, miss:int, gone:int}. 3.12.6: miss = when a fresh check first found no rules since they
	 * were last seen, gone = when a second one confirmed it.
	 */
	const STATE = 'pncp_rules_state';

	/**
	 * Option (not autoloaded): the text of the rules as the Server rules tab showed them, "<format>:<fingerprint>"
	 * => array{text:string, time:int}, the newest KEEP.
	 */
	const TEXTS = 'pncp_rules_texts';

	/**
	 * Texts kept.
	 */
	const KEEP = 4;

	/**
	 * Admin-post action (and nonce action) of "Dismiss".
	 */
	const DISMISS = 'pncp_rules_dismiss';

	/**
	 * Nonce action (and query argument) of "See what changed".
	 */
	const DIFF = 'pncp_rules_diff';

	/**
	 * 3.12.6: admin-ajax action (and nonce action) of the second check, a few seconds after a first one found no
	 * rules.
	 */
	const RECHECK = 'pncp_rules_recheck';

	/**
	 * 3.12.6: seconds between the two fresh checks before "not found" is told.
	 */
	const RECHECK_GAP = 3;

	/**
	 * 3.12.6: a first failed check older than this is forgotten (the next failed one is a first one again).
	 */
	const MISS_WINDOW = 600;

	/**
	 * What this request already wrote (observe() is called for each answer of a run).
	 *
	 * @var string
	 */
	private static $noted = '';

	/**
	 * Registers the hooks (wp-admin).
	 */
	public static function init() {
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_action( 'admin_post_' . self::DISMISS, array( __CLASS__, 'handle_dismiss' ) );
		add_action( 'wp_ajax_' . self::RECHECK, array( __CLASS__, 'ajax_recheck' ) );
		add_action( 'admin_footer', array( __CLASS__, 'recheck_script' ) );
	}

	/**
	 * The stored state, cleaned.
	 *
	 * @return array{installed:string, format:string, current:string, time:int, seen:int, dismissed:string, miss:int, gone:int}
	 */
	public static function state() {
		$raw = get_option( self::STATE, array() );
		$raw = is_array( $raw ) ? $raw : array();
		$out = array(
			'installed' => '',
			'format'    => '',
			'current'   => '',
			'time'      => 0,
			'seen'      => 0,
			'dismissed' => '',
			'miss'      => 0,
			'gone'      => 0,
		);
		foreach ( array( 'installed', 'current', 'dismissed' ) as $key ) {
			$out[ $key ] = isset( $raw[ $key ] ) && is_string( $raw[ $key ] ) ? (string) preg_replace( '/[^0-9a-f |]/', '', $raw[ $key ] ) : '';
		}
		$out['format'] = isset( $raw['format'] ) && in_array( $raw['format'], array( 'nginx', 'apache' ), true ) ? $raw['format'] : '';
		$out['time']   = isset( $raw['time'] ) ? (int) $raw['time'] : 0;
		$out['seen']   = isset( $raw['seen'] ) ? (int) $raw['seen'] : 0;
		$out['miss']   = isset( $raw['miss'] ) ? (int) $raw['miss'] : 0;
		$out['gone']   = isset( $raw['gone'] ) ? (int) $raw['gone'] : 0;
		return $out;
	}

	/**
	 * Stores the state.
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function save( $state ) {
		if ( false === get_option( self::STATE, false ) ) {
			add_option( self::STATE, $state, '', false );
		} else {
			update_option( self::STATE, $state, false );
		}
	}

	/**
	 * The format of a fingerprint the server reported: "<http> <server>" (Nginx) or one (Apache), '' when it is
	 * neither.
	 *
	 * @param string $value Header value.
	 * @return string
	 */
	public static function format_of( $value ) {
		$value = trim( (string) $value );
		if ( preg_match( '/^[0-9a-f]{12} [0-9a-f]{12}$/', $value ) ) {
			return 'nginx';
		}
		return preg_match( '/^[0-9a-f]{12}$/', $value ) ? 'apache' : '';
	}

	/**
	 * The fingerprint of the rules the current settings give, in a format.
	 *
	 * @param string $format nginx or apache.
	 * @return string
	 */
	public static function current( $format ) {
		return 'apache' === $format ? PNCP_Rules::apache_fingerprint() : PNCP_Rules::nginx_fingerprint();
	}

	/**
	 * An answer to one of the site's own requests (PNCP_Self_Check::request()): its HASH_HEADER, when this WordPress
	 * answered that very request (so it reached the server, not a CDN's cached copy).
	 *
	 * @param array<string, mixed>|WP_Error $response The answer.
	 * @param string                        $id       PNCP_Self_Check::request_id() of the request's signature.
	 */
	public static function observe( $response, $id ) {
		if ( is_wp_error( $response ) || ! PNCP_Self_Check::is_own_answer( $response, (string) $id ) ) {
			return;
		}
		$headers = PNCP_Self_Check::headers_of( $response );
		$value   = isset( $headers[ strtolower( PNCP_Rules::HASH_HEADER ) ] ) ? trim( $headers[ strtolower( PNCP_Rules::HASH_HEADER ) ] ) : '';
		self::record( $value );
	}

	/**
	 * Notes what the server reported ('' = no header). Without the header, the last answer of the check address of
	 * the Nginx rules (rules of before 3.12.3, or a location whose own add_header lines hide the header) counts
	 * instead: as PNCP_Rules::nginx_status() keeps it, never a request of its own here (run() asks it first).
	 *
	 * @param string $value The header's value ('' = none).
	 */
	public static function record( $value ) {
		$value  = trim( (string) $value );
		$format = self::format_of( $value );
		if ( '' === $format ) {
			// 3.12.6: an answer without the header leaves "installed" as last seen (see the class comment).
			$value = '';
			$got   = get_transient( 'pncp_nginx_status' );
			$body  = self::nginx_body();
			// Only an answer kept for the current rules (nginx_status() asks again when they change).
			if ( is_array( $got ) && ( $got['want'] ?? '' ) === PNCP_Rules::nginx_fingerprint() && 'nginx' === self::format_of( $body ) ) {
				$value  = $body;
				$format = 'nginx';
			}
		}
		$state = self::state();
		if ( '' === $format ) {
			$format = '' !== $state['format'] ? $state['format'] : self::guess_format();
		}
		$current = self::current( $format );
		$key     = $value . '|' . $current;
		if ( $key === self::$noted ) {
			return; // Already written in this run.
		}
		self::$noted      = $key;
		$state['format']  = $format;
		$state['current'] = $current;
		$state['time']    = time();
		if ( '' !== $value ) {
			$state['installed'] = $value;
			$state['seen']      = time();
			$state['miss']      = 0;
			$state['gone']      = 0;
		}
		self::save( $state );
	}

	/**
	 * 3.12.6: the result of a fresh check of the server itself (PNCP_Rules_Status::nginx() / apache() asked it
	 * now). A fingerprint is noted as installed. No fingerprint, from an answer that shows the server itself
	 * answered without the rules ($definitive), counts as one failed check: the first is only remembered (the
	 * admin page asks again a few seconds later, recheck()); a second one at least RECHECK_GAP seconds later
	 * confirms that the rules are gone. An answer that could not reach the server changes nothing.
	 *
	 * @param string   $format     nginx or apache.
	 * @param string   $value      The fingerprint found ('' = none).
	 * @param bool     $definitive The server answered, without the rules.
	 * @param int|null $now        The time (tests).
	 */
	public static function checked( $format, $value, $definitive, $now = null ) {
		$value = trim( (string) $value );
		if ( '' !== self::format_of( $value ) ) {
			self::$noted = '';
			self::record( $value );
			return;
		}
		$state = self::state();
		if ( ! $definitive || ! $state['seen'] || ( '' !== $state['format'] && $format !== $state['format'] ) ) {
			return; // Nothing new, or a site that never had rules (never told anything).
		}
		$now = null === $now ? time() : (int) $now;
		if ( $state['gone'] ) {
			return;
		}
		if ( ! $state['miss'] || $state['miss'] < $now - self::MISS_WINDOW || $state['miss'] > $now ) {
			$state['miss'] = $now;
		} elseif ( $now - $state['miss'] >= self::RECHECK_GAP ) {
			$state['gone'] = $now;
		} else {
			return; // Too soon: the same moment (a reload) says nothing more.
		}
		$state['current'] = self::current( '' !== $state['format'] ? $state['format'] : $format );
		$state['time']    = $now;
		self::save( $state );
	}

	/**
	 * 3.12.6: is a second check due (a first one found no rules, not confirmed yet)?
	 *
	 * @param int|null $now The time (tests).
	 * @return bool
	 */
	public static function recheck_due( $now = null ) {
		$state = self::state();
		$now   = null === $now ? time() : (int) $now;
		return $state['seen'] > 0 && ! $state['gone'] && $state['miss'] > 0 && $state['miss'] >= $now - self::MISS_WINDOW;
	}

	/**
	 * 3.12.6: the second check (admin-ajax, nonce, manage_options): the server is asked again now, and the
	 * notice's HTML (empty when the rules are not out of date) goes back.
	 */
	public static function ajax_recheck() {
		if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( self::RECHECK, '_wpnonce', false ) ) {
			wp_send_json_error( array(), 403 );
		}
		self::recheck();
		ob_start();
		self::notice_html();
		wp_send_json_success(
			array(
				'stale'  => self::is_stale(),
				'notice' => (string) ob_get_clean(),
			)
		);
	}

	/**
	 * 3.12.6: asks the server again now (the second of the two checks), in the format the rules were seen in.
	 */
	public static function recheck() {
		if ( 'apache' === self::state()['format'] ) {
			PNCP_Rules_Status::apache( true );
		} else {
			PNCP_Rules_Status::nginx( true );
		}
	}

	/**
	 * 3.12.6: on ScrapeLock's pages and the dashboard, while a second check is due: asks for it a few seconds
	 * after the page loaded (not in the request that saved the settings), and shows the notice it returns.
	 */
	public static function recheck_script() {
		if ( ! current_user_can( 'manage_options' ) || ! PNCP_Status::notice_screen() || ! self::recheck_due() ) {
			return;
		}
		$config = array(
			'url'   => admin_url( 'admin-ajax.php' ),
			'nonce' => wp_create_nonce( self::RECHECK ),
			'delay' => 4000,
		);
		$js     = '(function(c){setTimeout(function(){var f=new FormData();f.append("action",' . wp_json_encode( self::RECHECK ) . ');f.append("_wpnonce",c.nonce);'
			. 'fetch(c.url,{method:"POST",credentials:"same-origin",body:f}).then(function(r){return r.json();}).then(function(r){'
			. 'if(!r||!r.success||!r.data.notice||document.querySelector(".pncp-rules-stale")){return;}'
			. 'var w=document.querySelector("#wpbody-content .wrap")||document.getElementById("wpbody-content");if(!w){return;}'
			. 'var d=document.createElement("div");d.innerHTML=r.data.notice;var h=w.querySelector("h1,h2");'
			. 'while(d.firstChild){if(h&&h.parentNode===w){w.insertBefore(d.firstChild,h.nextSibling);}else{w.insertBefore(d.firstChild,w.firstChild);}}'
			. '}).catch(function(){});},c.delay);})(' . wp_json_encode( $config ) . ');';
		wp_print_inline_script_tag( $js, array( 'id' => 'pncp-rules-recheck' ) );
	}

	/**
	 * The check address of the Nginx rules answered (the Server rules tab): what it reported is noted like a header.
	 */
	public static function from_status() {
		$body = self::nginx_body();
		if ( 'nginx' === self::format_of( $body ) ) {
			self::record( $body );
		}
	}

	/**
	 * The last answer of the Nginx rules' check address ('' = none).
	 *
	 * @return string
	 */
	private static function nginx_body() {
		$got = get_transient( 'pncp_nginx_status' );
		return is_array( $got ) && isset( $got['body'] ) ? trim( (string) $got['body'] ) : '';
	}

	/**
	 * The web server, when no fingerprint said it: Nginx unless the server software says Apache or LiteSpeed.
	 *
	 * @return string
	 */
	private static function guess_format() {
		$soft = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		return ( false !== strpos( $soft, 'apache' ) || false !== strpos( $soft, 'litespeed' ) ) ? 'apache' : 'nginx';
	}

	/**
	 * After the settings were saved (update_option_pncp_settings): when the site uses server rules, the current
	 * fingerprint is compared at once, so the notice shows right after saving a setting that changes them.
	 */
	public static function settings_changed() {
		$state = self::state();
		if ( ! $state['seen'] || '' === $state['format'] ) {
			return; // No rules were ever seen on this site: nothing to compare.
		}
		PNCP_Options::flush();
		$current = self::current( $state['format'] );
		if ( $current !== $state['current'] ) {
			$state['current'] = $current;
			self::save( $state );
		}
	}

	/**
	 * Does the site use server rules: was a fingerprint ever seen?
	 *
	 * @return bool
	 */
	public static function in_use() {
		return self::state()['seen'] > 0;
	}

	/**
	 * Are the installed rules out of date (or gone) while the site uses them?
	 *
	 * @return bool
	 */
	public static function is_stale() {
		$state = self::state();
		return $state['seen'] > 0 && '' !== $state['current'] && ( $state['gone'] > 0 || $state['installed'] !== $state['current'] );
	}

	/**
	 * 3.12.6: the parts of the Nginx rules that differ between the installed and the current ones (http, server);
	 * empty for Apache, for rules that are gone, or when both are the same.
	 *
	 * @param array<string, mixed>|null $state State (null = stored).
	 * @return string[]
	 */
	public static function stale_parts( $state = null ) {
		$state = null === $state ? self::state() : $state;
		if ( $state['gone'] || 'nginx' !== self::format_of( (string) $state['installed'] ) || 'nginx' !== self::format_of( (string) $state['current'] ) ) {
			return array();
		}
		$installed = explode( ' ', (string) $state['installed'] );
		$current   = explode( ' ', (string) $state['current'] );
		$parts     = array();
		if ( $installed[0] !== $current[0] ) {
			$parts[] = 'http';
		}
		if ( $installed[1] !== $current[1] ) {
			$parts[] = 'server';
		}
		return $parts;
	}

	/**
	 * The fingerprint for people ('' = none seen).
	 *
	 * @param string $value Fingerprint.
	 * @return string
	 */
	private static function shown( $value ) {
		return '' === $value ? __( 'not found', 'scrapelock' ) : $value;
	}

	/**
	 * The out-of-date message: "The server rules are out of date (installed: X, current: Y). Copy them again from
	 * Server rules."
	 *
	 * @return string
	 */
	public static function message() {
		$state = self::state();
		$parts = self::stale_parts( $state );
		if ( array( 'http' ) === $parts ) {
			return sprintf(
				/* translators: 1: fingerprint of the installed rules, 2: fingerprint of the current ones */
				__( 'The server rules are installed, but part 1 (http { }) is out of date (installed: %1$s, current: %2$s). Copy part 1 again from Server rules.', 'scrapelock' ),
				$state['installed'],
				$state['current']
			);
		}
		if ( array( 'server' ) === $parts ) {
			return sprintf(
				/* translators: 1: fingerprint of the installed rules, 2: fingerprint of the current ones */
				__( 'The server rules are installed, but part 2 (server { }) is out of date (installed: %1$s, current: %2$s). Copy part 2 again from Server rules.', 'scrapelock' ),
				$state['installed'],
				$state['current']
			);
		}
		return sprintf(
			/* translators: 1: fingerprint of the installed rules, 2: fingerprint of the current ones */
			__( 'The server rules are out of date (installed: %1$s, current: %2$s). Copy them again from Server rules.', 'scrapelock' ),
			self::shown( $state['gone'] ? '' : $state['installed'] ),
			$state['current']
		);
	}

	/**
	 * The address of "See what changed" (nonce).
	 *
	 * @return string
	 */
	public static function diff_url() {
		return wp_nonce_url(
			PNCP_Status::settings_url(
				array(
					'tab'      => 'rules',
					self::DIFF => 1,
				)
			),
			self::DIFF
		) . '#pncp-rules-diff';
	}

	/**
	 * Keeps the text of the rules the Server rules tab shows now (the administrator copies them from there), under
	 * their fingerprint, so a later diff has the text of the installed ones.
	 */
	public static function remember_texts() {
		$texts = get_option( self::TEXTS, array() );
		$texts = is_array( $texts ) ? $texts : array();
		$new   = array(
			'nginx:' . PNCP_Rules::nginx_fingerprint() => PNCP_Rules::nginx(),
			'apache:' . PNCP_Rules::apache_fingerprint() => PNCP_Rules::apache(),
		);
		$changed = false;
		foreach ( $new as $key => $text ) {
			if ( ! isset( $texts[ $key ] ) || ! is_array( $texts[ $key ] ) || ( $texts[ $key ]['text'] ?? '' ) !== $text || (int) ( $texts[ $key ]['time'] ?? 0 ) < time() - DAY_IN_SECONDS ) {
				unset( $texts[ $key ] );
				$texts[ $key ] = array(
					'text' => $text,
					'time' => time(),
				);
				$changed       = true;
			}
		}
		if ( ! $changed ) {
			return;
		}
		uasort(
			$texts,
			static function ( $a, $b ) {
				return (int) ( is_array( $b ) ? ( $b['time'] ?? 0 ) : 0 ) - (int) ( is_array( $a ) ? ( $a['time'] ?? 0 ) : 0 );
			}
		);
		// The newest KEEP of each format.
		$count = array();
		foreach ( array_keys( $texts ) as $key ) {
			$format           = (string) strtok( (string) $key, ':' );
			$count[ $format ] = isset( $count[ $format ] ) ? $count[ $format ] + 1 : 1;
			if ( $count[ $format ] > self::KEEP ) {
				unset( $texts[ $key ] );
			}
		}
		if ( false === get_option( self::TEXTS, false ) ) {
			add_option( self::TEXTS, $texts, '', false );
		} else {
			update_option( self::TEXTS, $texts, false );
		}
	}

	/**
	 * The text of the rules with this fingerprint, as the Server rules tab showed them ('' = unknown).
	 *
	 * @param string $format      nginx or apache.
	 * @param string $fingerprint Fingerprint.
	 * @return string
	 */
	public static function text_of( $format, $fingerprint ) {
		$texts = get_option( self::TEXTS, array() );
		$key   = $format . ':' . $fingerprint;
		return is_array( $texts ) && isset( $texts[ $key ]['text'] ) && '' !== $fingerprint ? (string) $texts[ $key ]['text'] : '';
	}

	/**
	 * "See what changed": the installed rules against the current ones, as a line diff. Only for administrators
	 * with a valid nonce; '' otherwise.
	 *
	 * @return string Escaped HTML.
	 */
	public static function render_diff() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified right below.
		if ( ! isset( $_GET[ self::DIFF ] ) || ! current_user_can( 'manage_options' ) ) {
			return '';
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, self::DIFF ) ) {
			return '<div class="notice notice-error inline" id="pncp-rules-diff"><p>' . esc_html__( 'This page has expired. Reload it and try again.', 'scrapelock' ) . '</p></div>';
		}
		$state   = self::state();
		$format  = '' !== $state['format'] ? $state['format'] : 'nginx';
		$current = 'apache' === $format ? PNCP_Rules::apache() : PNCP_Rules::nginx();
		$old     = self::text_of( $format, $state['installed'] );
		$out     = '<section class="pncp-card pncp-card--wide" id="pncp-rules-diff"><h2>' . esc_html__( 'What changed in the server rules', 'scrapelock' ) . '</h2>';
		$out    .= '<p>' . esc_html( self::is_stale() ? self::message() : __( 'The installed server rules are the current ones.', 'scrapelock' ) ) . '</p>';
		if ( '' === $old ) {
			$out .= '<p>' . esc_html__( 'The text of the installed rules is not known (they were copied before 3.12.3, or from somewhere else). These are the current rules:', 'scrapelock' ) . '</p>';
			$out .= '<textarea class="large-text code" rows="16" readonly>' . esc_textarea( $current ) . '</textarea>';
		} else {
			$diff = wp_text_diff(
				$old,
				$current,
				array(
					'title_left'  => __( 'Installed', 'scrapelock' ),
					'title_right' => __( 'Current', 'scrapelock' ),
				)
			);
			$out .= '' === $diff ? '<p>' . esc_html__( 'No difference in the text.', 'scrapelock' ) . '</p>' : wp_kses_post( $diff );
		}
		return $out . '</section>';
	}

	/**
	 * The admin notice while the rules are out of date: administrators only, on ScrapeLock's pages and the
	 * dashboard, until dismissed for these fingerprints.
	 */
	public static function notice() {
		if ( ! PNCP_Status::notice_screen() ) {
			return;
		}
		self::notice_html();
	}

	/**
	 * The notice itself, on any screen (3.12.6: also the answer of the second check).
	 */
	private static function notice_html() {
		if ( ! current_user_can( 'manage_options' ) || ! self::is_stale() ) {
			return;
		}
		$state = self::state();
		if ( self::pair( $state ) === $state['dismissed'] ) {
			return;
		}
		echo '<div class="notice notice-warning pncp-rules-stale"><p><strong>ScrapeLock:</strong> ' . esc_html( self::message() ) . '</p><p>';
		printf( '<a class="button button-secondary" href="%s">%s</a> ', esc_url( self::diff_url() ), esc_html__( 'See what changed', 'scrapelock' ) );
		printf( '<form method="post" action="%s" style="display:inline">', esc_url( admin_url( 'admin-post.php' ) ) );
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( self::DISMISS ) );
		wp_nonce_field( self::DISMISS );
		echo '<button type="submit" class="button-link">' . esc_html__( 'Dismiss', 'scrapelock' ) . '</button></form></p></div>';
	}

	/**
	 * The fingerprints a dismissal is for.
	 *
	 * @param array<string, mixed> $state State.
	 * @return string
	 */
	private static function pair( $state ) {
		return (string) $state['installed'] . '|' . (string) $state['current'] . ( empty( $state['gone'] ) ? '' : '|gone' );
	}

	/**
	 * "Dismiss" (admin-post, nonce, manage_options): until the fingerprints change.
	 */
	public static function handle_dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::DISMISS );
		$state              = self::state();
		$state['dismissed'] = self::pair( $state );
		self::save( $state );
		$back = wp_get_referer();
		wp_safe_redirect( $back ? $back : admin_url() );
		exit;
	}

	/**
	 * Site Health: "recommended" while the installed rules are out of date.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_test() {
		$base = array(
			'badge' => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'blue',
			),
			'test'  => 'scrapelock_server_rules',
		);
		// 3.12.4: the rules were in use and the check address now names what is wrong (the answer of the last
		// 5 minutes; Site Health asks nothing more).
		$nginx = PNCP_Rules_Status::nginx_kept();
		if ( ! self::is_stale() && null !== $nginx && PNCP_Rules_Status::worth_telling( $nginx ) ) {
			$text                   = PNCP_Rules_Status::nginx_text( $nginx );
			$again                  = PNCP_Status::settings_url(
				array(
					'tab'              => 'rules',
					'pncp_nginx_check' => 1,
				)
			);
			$base['badge']['color'] = 'orange';
			return $base + array(
				'label'       => __( 'The ScrapeLock Nginx rules were not seen on this server', 'scrapelock' ),
				'status'      => 'recommended',
				'description' => '<p>' . esc_html( $text['line'] ) . '</p>' . ( '' !== $text['more'] ? '<p>' . esc_html( $text['more'] ) . '</p>' : '' ),
				'actions'     => current_user_can( 'manage_options' ) ? '<p><a class="button" href="' . esc_url( $again ) . '">' . esc_html__( 'Check again', 'scrapelock' ) . '</a></p>' : '',
			);
		}
		if ( ! self::is_stale() ) {
			return $base + array(
				'label'       => self::in_use() ? __( 'The ScrapeLock server rules are up to date', 'scrapelock' ) : __( 'No ScrapeLock server rules were seen on this server', 'scrapelock' ),
				'status'      => 'good',
				'description' => '<p>' . esc_html( self::in_use() ? __( 'The rules on the web server match the current settings.', 'scrapelock' ) : __( 'The server rules are optional: the plugin protects the pages without them.', 'scrapelock' ) ) . '</p>',
				'actions'     => '',
			);
		}
		$base['badge']['color'] = 'orange';
		return $base + array(
			'label'       => __( 'The ScrapeLock server rules are out of date', 'scrapelock' ),
			'status'      => 'recommended',
			'description' => '<p>' . esc_html( self::message() ) . '</p>' . ( null !== $nginx && PNCP_Rules_Status::worth_telling( $nginx ) ? '<p>' . esc_html( PNCP_Rules_Status::nginx_text( $nginx )['line'] ) . '</p>' : '' ),
			'actions'     => current_user_can( 'manage_options' ) ? '<p><a class="button" href="' . esc_url( self::diff_url() ) . '">' . esc_html__( 'See what changed', 'scrapelock' ) . '</a></p>' : '',
		);
	}

	/**
	 * Forgets everything (uninstall).
	 */
	public static function forget() {
		delete_option( self::STATE );
		delete_option( self::TEXTS );
	}
}
