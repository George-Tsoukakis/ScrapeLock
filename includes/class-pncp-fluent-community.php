<?php
/**
 * 3.11: FluentCommunity (plugin fluent-community/fluent-community.php). While it is active:
 *
 * - Its portal (default /hub/, or the slug set in FluentCommunity) counts as one of the "Content addresses" of the
 *   Log tab, merged at runtime: the stored setting is never changed, and the field says the portal was added
 *   because FluentCommunity is active.
 * - Its own REST reads (GET /wp-json/fluent-community/…) by signed-in members do not count toward the per-IP
 *   "REST API requests per minute": the portal is a single-page app that loads every screen through them, so an
 *   active member reached the limit while reading (live logs: 429 on /wp-json/fluent-community/v2/feeds).
 *   3.12.1: they are not exempt either: they count per account (the user ID, whatever the address), up to
 *   PNCP_Bots::MEMBER_REST_FACTOR (4) times the REST limit in the same one-minute window, and toward the
 *   per-account page limit ("Pages per minute per signed-in account"), MEMBER_REST_FACTOR reads as one page (a
 *   portal screen is several reads). Over it, that account alone gets a 429
 *   and the log row keeps its username (reason rate_member); other members on the same address are not
 *   affected, and no violation is counted toward a ban of the IP. Only with a valid session: a REST request is
 *   signed in only with the X-WP-Nonce of the member's own session (WordPress drops the cookie session without
 *   it), so a guest or a script with a copied cookie counts toward the normal per-IP REST limit. Every other
 *   check (always-blocked IPs, bans, bots) still applies to them.
 * - The early check and the pre-cache check run before WordPress knows who is signed in: neither counts any
 *   REST request (the pre-cache check leaves /wp-json/ and ?rest_route= alone, the early check every request
 *   with a sign-in cookie and every limit), so these reads are counted only here, once WordPress has checked
 *   the session.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * FluentCommunity integration.
 */
final class PNCP_Fluent_Community {

	const BASENAME = 'fluent-community/fluent-community.php';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'pncp_content_paths', array( __CLASS__, 'content_paths' ) );
	}

	/**
	 * Is FluentCommunity active? By its constant or class (loaded), or by the list of active plugins (before it
	 * has loaded, e.g. in the early check).
	 *
	 * @return bool
	 */
	public static function active() {
		$active = defined( 'FLUENT_COMMUNITY_PLUGIN_VERSION' ) || class_exists( 'FluentCommunity\App\App', false ) || class_exists( 'FluentCommunity\App\Services\Helper', false );
		if ( ! $active ) {
			$active = PNCP_Plugin_Bots::plugin_active( array( self::BASENAME ) ); // This site's or network-wide.
		}
		/**
		 * Filter: whether FluentCommunity counts as active for ScrapeLock.
		 *
		 * @since 3.11.0
		 * @param bool $active Active.
		 */
		return (bool) apply_filters( 'pncp_fluent_community_active', $active );
	}

	/**
	 * The portal's path prefix, e.g. /hub. FluentCommunity's own setting (its constant, or its Helper class once
	 * loaded), otherwise /hub.
	 *
	 * @return string
	 */
	public static function portal_path() {
		$slug = '';
		if ( defined( 'FLUENT_COMMUNITY_PORTAL_SLUG' ) ) {
			$slug = (string) constant( 'FLUENT_COMMUNITY_PORTAL_SLUG' );
		} elseif ( is_callable( array( 'FluentCommunity\App\Services\Helper', 'getPortalSlug' ) ) ) {
			try {
				$slug = (string) call_user_func( array( 'FluentCommunity\App\Services\Helper', 'getPortalSlug' ) );
			} catch ( Throwable $e ) {
				$slug = '';
			}
		}
		/**
		 * Filter: the slug of the FluentCommunity portal ('' = "hub").
		 *
		 * @since 3.11.0
		 * @param string $slug Slug.
		 */
		$slug = trim( (string) apply_filters( 'pncp_fluent_community_slug', $slug ), " \t\n\r\0\x0B/" );
		$slug = '' !== $slug ? implode( '/', array_map( 'sanitize_title', explode( '/', $slug ) ) ) : 'hub';
		return '/' . trim( $slug, '/' );
	}

	/**
	 * The content addresses this integration adds now: the portal, while FluentCommunity is active.
	 *
	 * @return string[]
	 */
	public static function added_paths() {
		return self::active() ? array( self::portal_path() ) : array();
	}

	/**
	 * Adds the portal to the "Content addresses" (filter pncp_content_paths), unless it is there already.
	 *
	 * @param string[] $paths Paths.
	 * @return string[]
	 */
	public static function content_paths( $paths ) {
		$paths = (array) $paths;
		foreach ( self::added_paths() as $path ) {
			$covered = false;
			foreach ( $paths as $known ) {
				if ( 0 === stripos( trailingslashit( $path ), trailingslashit( (string) $known ) ) ) {
					$covered = true;
					break;
				}
			}
			if ( ! $covered ) {
				$paths[] = $path;
			}
		}
		return $paths;
	}

	/**
	 * 3.12.1: is this REST read a member's portal read, counted per account instead of per IP
	 * (PNCP_Bots::check(), rate_member)? A GET or HEAD of FluentCommunity's own namespace by a signed-in user,
	 * while FluentCommunity is active.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool
	 */
	public static function member_rest( $request ) {
		if ( ! $request instanceof WP_REST_Request || ! in_array( strtoupper( (string) $request->get_method() ), array( 'GET', 'HEAD' ), true ) ) {
			return false;
		}
		if ( ! preg_match( '#^/fluent-community(?:/|$)#i', (string) $request->get_route() ) ) {
			return false;
		}
		return is_user_logged_in() && self::active();
	}

	/**
	 * The 3.11 name of member_rest(): such a read stays out of the per-IP REST limit (since 3.12.1 it counts per
	 * account).
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool
	 */
	public static function uncounted_rest( $request ) {
		return self::member_rest( $request );
	}

	/**
	 * 3.12.1: the note under "REST API requests per minute" on the Bots tab while FluentCommunity is active, in two
	 * parts (PNCP_Admin_Fields::help()).
	 *
	 * @return array{0: string, 1: string} Two '' while FluentCommunity is not active.
	 */
	public static function rest_note_help() {
		if ( ! self::active() ) {
			return array( '', '' );
		}
		return array(
			__( 'FluentCommunity: members\' portal reads count per account, at 4× this limit.', 'scrapelock' ),
			__( 'Signed-in members\' reads of /wp-json/fluent-community/ count per account, not per IP address, up to four times this limit per minute, and toward “Pages per minute per signed-in account”, four reads as one page. Over it, only that account gets “Too many requests” and the log shows its username. Guests count toward this limit as usual.', 'scrapelock' ),
		);
	}

	/**
	 * The note under "Content addresses" on the Log tab, in two parts: one short line, and the rest (shown under
	 * "More", PNCP_Admin_Fields::help()).
	 *
	 * @return array{0: string, 1: string} Two '' while FluentCommunity is not active.
	 */
	public static function note_help() {
		$paths = self::added_paths();
		if ( ! $paths ) {
			return array( '', '' );
		}
		return array(
			sprintf(
				/* translators: %s: a path prefix, e.g. /hub/ */
				__( 'Also counted: %s, because FluentCommunity is active.', 'scrapelock' ),
				implode( ', ', array_map( 'trailingslashit', $paths ) )
			),
			__( 'Your list above is not changed. Its REST reads by signed-in members count per account, at four times the REST API limit.', 'scrapelock' ),
		);
	}

	/**
	 * The same note as one text (the "For my site" advice).
	 *
	 * @return string '' while FluentCommunity is not active.
	 */
	public static function note() {
		return trim( implode( ' ', self::note_help() ) );
	}
}
