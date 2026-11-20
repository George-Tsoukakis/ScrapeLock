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
	 * 3.6.1: autoloaded option: when a request last came from a proxy that "Real visitor IP" does not trust (on
	 * the server or a private network, PNCP_Ip::untrusted_proxy_peer()), whether or not "Only through the CDN" is
	 * on (time).
	 */
	const PEER_OPTION = 'pncp_proxy_peer';

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
		// 3.6.1: whenever protection is on; at the end of the request, so the visitor IP was found with every
		// plugin's filters (cheap: returns at once unless REMOTE_ADDR is local or private).
		add_action( 'shutdown', array( __CLASS__, 'note_peer' ) );
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
		return PNCP_Ip::forwarded_client(); // 3.6.1: moved to PNCP_Ip (the early check uses it too).
	}

	/**
	 * Is the request exempt? WP-CLI, WordPress's cron and the server itself (cache preload, loopback, 3.12.1: a
	 * request the site signed, PNCP_Server_Ips::sig_ok()).
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
		// 3.12.1: the site's own request (signed, or from one of the server's addresses, PNCP_Server_Ips): its checks
		// (Vulnerable points, Site Health) reach the server around the CDN when the site's name resolves to it.
		if ( PNCP_Server_Ips::is_request() ) {
			return true;
		}
		if ( ! PNCP_Ip::is_local( PNCP_Ip::remote_addr() ) ) {
			return false;
		}
		if ( ! self::forwarded() ) {
			return true;
		}
		return PNCP_Ip::is_local_request();
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
	 * 3.6.1: remembers (at most once a day) that requests come from a proxy on the server or a private network
	 * that "Real visitor IP" does not trust, whenever protection is on (not only with "Only through the CDN"):
	 * behind a local proxy every visitor then passes as the server itself, and behind a private one they all
	 * share one address. Forgets it once the proxy is trusted.
	 */
	public static function note_peer() {
		$remote = PNCP_Ip::remote_addr();
		if ( '' === $remote || ! ( PNCP_Ip::is_local( $remote ) || PNCP_Ip::is_private( $remote ) ) || ! self::forwarded() ) {
			return;
		}
		$s = PNCP_Options::stored();
		if ( empty( $s['enabled'] ) ) {
			return;
		}
		$all  = wp_load_alloptions();
		$seen = isset( $all[ self::PEER_OPTION ] ) ? (int) $all[ self::PEER_OPTION ] : 0;
		if ( PNCP_Ip::untrusted_proxy_peer() ) {
			if ( $seen < time() - DAY_IN_SECONDS ) {
				update_option( self::PEER_OPTION, time(), true );
			}
		} elseif ( $seen && '' !== PNCP_Ip::forwarded_client() ) {
			delete_option( self::PEER_OPTION );
		}
	}

	/**
	 * 3.6.1: is "Real visitor IP" wrong for the proxy in front of this site? Judged from this request, or from
	 * one in the last 7 days (note_peer()).
	 *
	 * @return bool
	 */
	public static function peer_problem() {
		if ( ! PNCP_Status::is_enabled() ) {
			return false;
		}
		$all = wp_load_alloptions();
		return PNCP_Ip::untrusted_proxy_peer() || ( isset( $all[ self::PEER_OPTION ] ) && (int) $all[ self::PEER_OPTION ] > time() - 7 * DAY_IN_SECONDS );
	}

	/**
	 * 3.6.1: the explanation of peer_problem(), for the admin notice and Site Health.
	 *
	 * @return string
	 */
	public static function peer_message() {
		return __( 'Requests reach WordPress from a reverse proxy or load balancer on this server or a private network (REMOTE_ADDR is 127.0.0.1, the server\'s own address or a private address such as 10.x or 172.16-31.x, with a forwarding header such as X-Forwarded-For), but “Real visitor IP” does not read the visitor\'s address from it. Every visitor then has the proxy\'s address: on 127.0.0.1 they all pass as the server itself and are not checked, and on a private address nothing is limited or banned per IP (a ban would block the whole site). On the Bots tab, set “Real visitor IP” to the header the proxy sets (usually X-Forwarded-For or X-Real-IP); a proxy on the server or a private network is trusted for it.', 'scrapelock' );
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
		$all = wp_load_alloptions();
		if ( isset( $all[ self::PEER_OPTION ] ) ) {
			delete_option( self::PEER_OPTION ); // 3.6.1.
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
		if ( ! current_user_can( 'manage_options' ) || ! PNCP_Status::notice_screen() ) {
			return;
		}
		if ( ! self::proxy_problem() ) {
			if ( self::peer_problem() ) {
				// 3.6.1: the same problem without "Only through the CDN".
				printf(
					'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
					esc_html__( 'ScrapeLock cannot see your visitors\' addresses.', 'scrapelock' ),
					esc_html( self::peer_message() ),
					esc_url( PNCP_Status::settings_url( array( 'tab' => 'bots' ) ) . '#pncp-sec-ip' ),
					esc_html__( 'Open the setting', 'scrapelock' )
				);
			}
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
		// 3.4.3: logged with the address the request was judged by: behind a local proxy that is the visitor's,
		// not 127.0.0.1 (as the pre-cache check logs it).
		$from = PNCP_Ip::is_local( PNCP_Ip::remote_addr() ) ? PNCP_Ip::client_ip() : PNCP_Ip::remote_addr();
		// "Monitor only": logged as "would block", and the request goes on.
		if ( PNCP_Options::monitoring() ) {
			PNCP_Log::add( 'not_via_cdn', PNCP_Log::MONITOR_CODE, $from );
			return;
		}
		PNCP_Self_Check::set_layer( 'origin' );
		PNCP_Log::add( 'not_via_cdn', 403, $from );
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
