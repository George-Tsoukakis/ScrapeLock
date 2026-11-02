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
	 * Registers the check: as early as a plugin can, before the theme, the other plugins' init and the REST API.
	 */
	public static function init() {
		add_action( 'plugins_loaded', array( __CLASS__, 'guard' ), 0 );
		add_action( 'admin_init', array( __CLASS__, 'sync_precheck' ) );
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
	 * Is the request exempt? The server itself (cron, cache preload, loopback), WP-CLI and WordPress's cron.
	 *
	 * @return bool
	 */
	public static function exempt() {
		return ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || PNCP_Ip::is_local( PNCP_Ip::remote_addr() );
	}

	/**
	 * Ends the request with 403 when it did not come through the CDN.
	 */
	public static function guard() {
		$s = PNCP_Options::stored();
		if ( ! self::active( $s ) || self::exempt() || self::has_secret( (string) $s['cdn_secret'] ) ) {
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
