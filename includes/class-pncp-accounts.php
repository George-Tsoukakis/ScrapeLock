<?php
/**
 * 3.6: one account used from several addresses at once (a shared subscription, a password that leaked, or a
 * script spread over many servers with one member's login). The administrator is emailed and, optionally, the
 * account is signed out everywhere else. The per-account page limit is in PNCP_Bots::check() (rate_account).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Shared accounts.
 */
final class PNCP_Accounts {

	/**
	 * Seconds within which the addresses of an account count as "at once".
	 */
	const WINDOW = 600;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'template_redirect', array( __CLASS__, 'observe' ), 3 );
	}

	/**
	 * Is this user watched? Signed in, not exempt from the protection, and not staff (Lockdown's list).
	 *
	 * @param int                  $user_id User.
	 * @param array<string, mixed> $s       Settings.
	 * @return bool
	 */
	public static function watched( $user_id, $s ) {
		return $user_id > 0 && ! PNCP_Options::user_is_exempt( $s ) && ! PNCP_Lockdown::is_staff( $user_id ) && ! user_can( $user_id, 'edit_posts' );
	}

	/**
	 * Notes the address of a signed-in account on a page of the site and acts when the account has been seen from
	 * "Addresses at once" (shared_ips) different addresses within WINDOW seconds. One cache write per account and
	 * address a minute at most (IPv6 counts per /64, as the limits do).
	 *
	 * @return array{0:int, 1:bool}|null [addresses seen, whether this request found a shared account], or null when nothing was watched.
	 */
	public static function observe() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['shared_alert'] ) || is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return null;
		}
		$user_id = get_current_user_id();
		if ( ! self::watched( $user_id, $s ) ) {
			return null;
		}
		$ip = PNCP_Ip::client_ip();
		if ( '' === $ip || PNCP_Ip::is_local_request() ) {
			return null;
		}
		$key  = PNCP_Ip::limit_key( $ip );
		$now  = time();
		$name = 'pncp_acct_' . $user_id;
		$seen = PNCP_Log::cache_get( $name );
		$seen = is_array( $seen ) ? $seen : array();
		foreach ( $seen as $address => $time ) {
			if ( (int) $time < $now - self::WINDOW ) {
				unset( $seen[ $address ] );
			}
		}
		if ( isset( $seen[ $key ] ) && (int) $seen[ $key ] > $now - MINUTE_IN_SECONDS ) {
			return array( count( $seen ), false ); // Seen this minute already: nothing to write.
		}
		$seen[ $key ] = $now;
		arsort( $seen );
		$seen = array_slice( $seen, 0, 50, true );
		PNCP_Log::cache_set( $name, $seen, self::WINDOW );
		if ( count( $seen ) < max( 2, (int) $s['shared_ips'] ) ) {
			return array( count( $seen ), false );
		}
		self::found( $user_id, $seen, $key, $s );
		return array( count( $seen ), true );
	}

	/**
	 * An account seen from several addresses at once: signs it out everywhere else (with the option on), emails
	 * the administration address (once a day per account) and fires `pncp_shared_account`.
	 *
	 * @param int                  $user_id User.
	 * @param array<string, int>   $seen    Address => last seen.
	 * @param string               $current The address of this request.
	 * @param array<string, mixed> $s       Settings.
	 */
	private static function found( $user_id, $seen, $current, $s ) {
		$signed_out = false;
		if ( ! empty( $s['shared_logout'] ) && class_exists( 'WP_Session_Tokens' ) ) {
			$token = wp_get_session_token();
			if ( '' !== $token ) {
				WP_Session_Tokens::get_instance( $user_id )->destroy_others( $token );
				$signed_out = true;
				// Counted again from this address.
				PNCP_Log::cache_set( 'pncp_acct_' . $user_id, array( $current => time() ), self::WINDOW );
			}
		}
		/**
		 * Fires when one account was used from several addresses at once.
		 *
		 * @param int      $user_id    User.
		 * @param string[] $addresses  The addresses (IPv6: their /64), newest first.
		 * @param bool     $signed_out Whether its other sessions were signed out.
		 */
		do_action( 'pncp_shared_account', $user_id, array_keys( $seen ), $signed_out );
		if ( ! PNCP_Log::cache_add( 'pncp_acct_alert_' . $user_id, 1, DAY_IN_SECONDS ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		$to   = get_option( 'admin_email' );
		if ( ! $user || ! is_email( $to ) ) {
			return;
		}
		$lines = array();
		foreach ( $seen as $address => $time ) {
			$lines[] = '- ' . $address . ' (' . wp_date( 'Y-m-d H:i', (int) $time ) . ')';
		}
		$body = sprintf(
			/* translators: 1: user name, 2: number of addresses, 3: minutes */
			__( 'The account “%1$s” was used from %2$d different addresses within %3$d minutes. It may be shared, or its password may have leaked.', 'scrapelock' ),
			$user->user_login,
			count( $seen ),
			(int) ( self::WINDOW / MINUTE_IN_SECONDS )
		) . "\n\n" . implode( "\n", $lines ) . "\n\n"
			. ( $signed_out ? __( 'Its other sessions were signed out; the newest address stays signed in.', 'scrapelock' ) : __( 'Nothing was changed. To sign such accounts out everywhere else on their own, turn on “Then sign the account out everywhere else” (On the page → Members and readers).', 'scrapelock' ) )
			. "\n\n" . admin_url( 'user-edit.php?user_id=' . (int) $user_id ) . "\n\n"
			. __( 'You get this email at most once a day per account.', 'scrapelock' );
		wp_mail( $to, '[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] ScrapeLock: ' . __( 'One account used from several addresses', 'scrapelock' ), $body );
	}
}
