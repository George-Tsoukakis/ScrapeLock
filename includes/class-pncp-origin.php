<?php
/**
 * "Only through the CDN": the server answers only requests that passed through the site's CDN. The CDN adds
 * the shared secret ("CDN shared secret") to every request as the header X-ScrapeLock-CDN; a request without
 * it went straight to the server's own address, around the CDN and everything the CDN blocks, and gets a 403.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Refuses requests that did not come through the CDN.
 */
final class PNCP_Origin {

	/**
	 * Autoloaded option: when a request last reached the server from a local proxy that is not trusted (time).
	 */
	const PROXY_OPTION = 'pncp_origin_proxy';

	/**
	 * Headers a reverse proxy adds with the address of the client it is passing on.
	 */
	const FORWARD_HEADERS = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP' );

	/**
	 * Registers the check: as early as a plugin can, before the theme, the other plugins' init and the REST API.
	 */
	public static function init() {
		add_action( 'plugins_loaded', array( __CLASS__, 'guard' ), 0 );
		add_action( 'admin_init', array( __CLASS__, 'sync_precheck' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		// After a settings change the warning is judged again from the next request through the proxy.
		add_action( 'update_option_' . PNCP_OPTION, array( __CLASS__, 'forget_proxy' ) );
	}

	/**
	 * The pre-cache check runs from the top of wp-config.php, before SCRAPELOCK_CDN_ONLY is defined further
	 * down, so it follows its own copy of the setting. When wp-config.php turns the setting off, that copy is
	 * rewritten on the next wp-admin page (wp-admin itself is never refused by the pre-cache check).
	 */
	public static function sync_precheck() {
		if ( defined( 'SCRAPELOCK_CDN_ONLY' ) && ! SCRAPELOCK_CDN_ONLY && ! empty( PNCP_Options::stored()['cdn_only'] ) ) {
			PNCP_Precheck::refresh();
		}
	}

	/**
	 * Is the setting in effect? Never without a secret, and never when wp-config.php turns it off
	 * (define( 'SCRAPELOCK_CDN_ONLY', false ); the way back in if the CDN stops sending the header).
	 *
	 * @param array<string, mixed>|null $s Settings (null = stored).
	 * @return bool
	 */
	public static function active( $s = null ) {
		$s = null === $s ? PNCP_Options::stored() : $s;
		if ( defined( 'SCRAPELOCK_CDN_ONLY' ) && ! SCRAPELOCK_CDN_ONLY ) {
			return false;
		}
		return ! empty( $s['enabled'] ) && ! empty( $s['cdn_only'] ) && '' !== trim( (string) $s['cdn_secret'] );
	}

	/**
	 * Did this request bring the secret?
	 *
	 * @param string $secret The secret.
	 * @return bool
	 */
	public static function has_secret( $secret ) {
		$secret = trim( (string) $secret );
		$sent   = isset( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SCRAPELOCK_CDN'] ) ) ) : '';
		return '' !== $secret && '' !== $sent && hash_equals( $secret, $sent );
	}

	/**
	 * Did a proxy pass this request on? Any of X-Forwarded-For, Forwarded, X-Real-IP or CF-Connecting-IP.
	 *
	 * @return bool
	 */
	public static function forwarded() {
		foreach ( self::FORWARD_HEADERS as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The client address a forwarding header names, when it is not the server itself: the last address of
	 * X-Forwarded-For (the one the nearest proxy wrote), X-Real-IP, CF-Connecting-IP or the last "for=" of
	 * Forwarded. Only used to tell whether a local proxy passes on visitors; never trusted as the visitor's IP.
	 *
	 * @return string The address, or '' when no header names an outside address.
	 */
	public static function forwarded_client() {
		foreach ( self::FORWARD_HEADERS as $header ) {
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
			$ip = PNCP_Ip::normalize( $value );
			if ( '' !== $ip && ! PNCP_Ip::is_local( $ip ) ) {
				return $ip;
			}
		}
		return '';
	}

	/**
	 * Is the request exempt? WP-CLI, WordPress's cron and the server itself (cache preload, loopback).
	 *
	 * "The server itself" means REMOTE_ADDR is the loopback or the server's own address AND no proxy passed the
	 * request on. Behind a local reverse proxy (Nginx in front of Apache, Varnish, Plesk) every request comes
	 * from 127.0.0.1, including the ones that went around the CDN: those carry a forwarding header, so they are
	 * judged by the visitor's address as "Real visitor IP" finds it (the header only from a trusted proxy). When
	 * the proxy is not trusted, that is still the loopback and the request passes as before; notice() and Site
	 * Health then say that the setting does nothing on this server.
	 *
	 * @return bool
	 */
	public static function exempt() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return true;
		}
		if ( ! PNCP_Ip::is_local( PNCP_Ip::remote_addr() ) ) {
			return false;
		}
		if ( ! self::forwarded() ) {
			return true;
		}
		return PNCP_Ip::is_local( PNCP_Ip::client_ip() );
	}

	/**
	 * Does this request come through a local proxy that "Real visitor IP" does not trust? REMOTE_ADDR is the
	 * server itself, a forwarding header names an outside client, but the visitor's IP is still the loopback.
	 *
	 * @return bool
	 */
	public static function untrusted_local_proxy() {
		$remote = PNCP_Ip::remote_addr();
		return PNCP_Ip::is_local( $remote ) && '' !== self::forwarded_client() && PNCP_Ip::client_ip() === $remote;
	}

	/**
	 * Remembers (at most once a day) that requests come through a local proxy that is not trusted, so the
	 * warning is shown even when the admin opens wp-admin another way; forgets it once the proxy is trusted.
	 */
	private static function note_proxy() {
		if ( ! PNCP_Ip::is_local( PNCP_Ip::remote_addr() ) || ! self::forwarded() ) {
			return;
		}
		$seen = self::seen();
		if ( self::untrusted_local_proxy() ) {
			if ( $seen < time() - DAY_IN_SECONDS ) {
				update_option( self::PROXY_OPTION, time(), true ); // Autoloaded: read without a query on the next requests.
			}
		} elseif ( $seen && '' !== self::forwarded_client() ) {
			delete_option( self::PROXY_OPTION );
		}
	}

	/**
	 * When an untrusted local proxy was last seen (0 = not seen). Read from the autoloaded options only, so a
	 * site where the option does not exist pays no extra query on every request.
	 *
	 * @return int
	 */
	private static function seen() {
		$all = wp_load_alloptions();
		return isset( $all[ self::PROXY_OPTION ] ) ? (int) $all[ self::PROXY_OPTION ] : 0;
	}

	/**
	 * Forgets the remembered proxy (after the settings are saved).
	 */
	public static function forget_proxy() {
		if ( self::seen() ) {
			delete_option( self::PROXY_OPTION );
		}
	}

	/**
	 * Does "Only through the CDN" do nothing because of a local proxy that is not trusted? Judged from this
	 * request, or from one in the last 7 days.
	 *
	 * @return bool
	 */
	public static function proxy_problem() {
		if ( ! self::active() ) {
			return false;
		}
		return self::untrusted_local_proxy() || self::seen() > time() - 7 * DAY_IN_SECONDS;
	}

	/**
	 * The explanation of the problem, for the admin notice and Site Health.
	 *
	 * @return string
	 */
	public static function proxy_message() {
		return __( 'Requests reach WordPress from a reverse proxy on this server (REMOTE_ADDR is 127.0.0.1 or the server\'s own address, with a forwarding header such as X-Forwarded-For), but that proxy is not trusted. ScrapeLock cannot tell them from the server\'s own requests, so “Only through the CDN” lets them all through, also the ones that went around the CDN. On the Bots tab, set “Real visitor IP” to the header the proxy sets (usually X-Forwarded-For or X-Real-IP); a proxy on the server itself is trusted for it.', 'scrapelock' );
	}

	/**
	 * Warning on the dashboard and the settings page while "Only through the CDN" does nothing because of an
	 * untrusted local proxy.
	 */
	public static function notice() {
		if ( ! current_user_can( 'manage_options' ) || ! PNCP_Status::notice_screen() || ! self::proxy_problem() ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
			esc_html__( '“Only through the CDN” does not protect this site yet.', 'scrapelock' ),
			esc_html( self::proxy_message() ),
			esc_url( PNCP_Status::settings_url( array( 'tab' => 'bots' ) ) . '#pncp-sec-ip' ),
			esc_html__( 'Open the setting', 'scrapelock' )
		);
	}

	/**
	 * Ends the request with 403 when it did not come through the CDN.
	 */
	public static function guard() {
		$s = PNCP_Options::stored();
		if ( ! self::active( $s ) ) {
			return;
		}
		self::note_proxy();
		if ( self::exempt() || self::has_secret( (string) $s['cdn_secret'] ) ) {
			return;
		}
		// "Monitor only": logged as "would block", and the request goes on.
		if ( PNCP_Options::monitoring() ) {
			PNCP_Log::add( 'not_via_cdn', PNCP_Log::MONITOR_CODE, PNCP_Ip::remote_addr() );
			return;
		}
		PNCP_Log::add( 'not_via_cdn', 403, PNCP_Ip::remote_addr() );
		if ( ! headers_sent() ) {
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'X-Robots-Tag: noindex' );
		}
		// No translation: this runs before the translations are loaded.
		echo 'Access denied.';
		exit;
	}
}
