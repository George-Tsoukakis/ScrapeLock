<?php
/**
 * 3.11: the state of each protection layer as the status badges show it, in three states: "On" (in effect
 * now), "Set but not active" with the reason (the setting is on, but something keeps it from working: protection
 * is off, the CDN secret is missing, the loader is not in wp-config.php…) and "Off" (the setting is off).
 *
 * Before 3.11 a badge was on or off only, so a setting that was on but not in effect read as "Off" (e.g.
 * "Pre-cache check: Off" with the setting on, "Only through the CDN: off" with the setting on and no secret).
 * Every reason here comes from the runtime state the checks themselves use (PNCP_Precheck::active(),
 * PNCP_Early::installed(), PNCP_Origin::active()…), so a badge never says "On" for a check that does not run.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * State of the protection layers.
 */
final class PNCP_Status_State {

	const ON  = 'on';
	const SET = 'set';
	const OFF = 'off';

	/**
	 * One state.
	 *
	 * @param string $state  on | set | off.
	 * @param string $reason Why a setting that is on is not in effect ('' for on and off).
	 * @return array{state:string, reason:string}
	 */
	private static function state( $state, $reason = '' ) {
		return array(
			'state'  => $state,
			'reason' => self::SET === $state ? (string) $reason : '',
		);
	}

	/**
	 * "Protection is off": the reason shared by every layer while the main switch is off.
	 *
	 * @return string
	 */
	public static function protection_off_reason() {
		return __( 'protection is off', 'scrapelock' );
	}

	/**
	 * A plain setting: on, set but not active while protection is off, or off.
	 *
	 * @param array<string, mixed> $s  Settings.
	 * @param bool                 $on Whether the setting is on.
	 * @return array{state:string, reason:string}
	 */
	public static function setting( $s, $on ) {
		if ( ! $on ) {
			return self::state( self::OFF );
		}
		if ( empty( $s['enabled'] ) ) {
			return self::state( self::SET, self::protection_off_reason() );
		}
		return self::state( self::ON );
	}

	/**
	 * The main switch.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array{state:string, reason:string}
	 */
	public static function protection( $s ) {
		return self::state( empty( $s['enabled'] ) ? self::OFF : self::ON );
	}

	/**
	 * The early check (the mu-plugin).
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array{state:string, reason:string}
	 */
	public static function early( $s ) {
		if ( empty( $s['early_mode'] ) ) {
			return self::state( self::OFF );
		}
		if ( empty( $s['enabled'] ) ) {
			return self::state( self::SET, self::protection_off_reason() );
		}
		if ( ! PNCP_Early::installed() ) {
			return self::state( self::SET, __( 'its file in wp-content/mu-plugins could not be written', 'scrapelock' ) );
		}
		return self::state( self::ON );
	}

	/**
	 * The pre-cache check (the line in wp-config.php and its configuration file).
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array{state:string, reason:string}
	 */
	public static function precheck( $s ) {
		if ( empty( $s['precheck'] ) ) {
			return self::state( self::OFF );
		}
		if ( is_multisite() ) {
			return self::state( self::SET, __( 'not available on multisite (wp-config.php is shared by every site)', 'scrapelock' ) );
		}
		if ( empty( $s['enabled'] ) ) {
			return self::state( self::SET, self::protection_off_reason() );
		}
		if ( PNCP_Precheck::active() ) {
			return self::state( self::ON );
		}
		$status = (string) get_option( PNCP_Precheck::STATUS, '' );
		if ( 'no_files' === $status ) {
			return self::state( self::SET, __( 'the folder uploads/scrapelock could not be created', 'scrapelock' ) );
		}
		if ( ! PNCP_Precheck::in_config() ) {
			if ( 'deferred' === $status ) {
				return self::state( self::SET, __( 'the loader is added to wp-config.php on the next wp-admin page', 'scrapelock' ) );
			}
			return self::state( self::SET, __( 'the loader is not in wp-config.php', 'scrapelock' ) );
		}
		return self::state( self::SET, __( 'its configuration file is out of date (it is written again on the next wp-admin page)', 'scrapelock' ) );
	}

	/**
	 * "Only through the CDN".
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array{state:string, reason:string}
	 */
	public static function cdn_only( $s ) {
		if ( empty( $s['cdn_only'] ) ) {
			return self::state( self::OFF );
		}
		if ( empty( $s['enabled'] ) ) {
			return self::state( self::SET, self::protection_off_reason() );
		}
		if ( defined( 'SCRAPELOCK_CDN_ONLY' ) && ! SCRAPELOCK_CDN_ONLY ) {
			return self::state( self::SET, __( 'turned off in wp-config.php (SCRAPELOCK_CDN_ONLY)', 'scrapelock' ) );
		}
		if ( '' === trim( (string) $s['cdn_secret'] ) ) {
			return self::state( self::SET, __( 'the CDN secret is missing', 'scrapelock' ) );
		}
		if ( PNCP_Origin::proxy_problem() ) {
			return self::state( self::SET, __( 'a reverse proxy on this server is not trusted, so every request looks like the server\'s own', 'scrapelock' ) );
		}
		return self::state( self::ON );
	}

	/**
	 * "AI bots verified": the AI search bots are allowed and checked against their official address lists.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array{state:string, reason:string}
	 */
	public static function ai_verified( $s ) {
		if ( empty( $s['verify_ai_bots'] ) ) {
			return self::state( self::OFF );
		}
		if ( empty( $s['allow_ai_search'] ) ) {
			return self::state( self::SET, __( 'AI search engines are not allowed, so there is nothing to verify', 'scrapelock' ) );
		}
		return self::setting( $s, true );
	}

	/**
	 * The country lists: they need the country of the visitor (Cloudflare, Bunny CDN or the country database).
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array{state:string, reason:string}
	 */
	public static function countries( $s ) {
		if ( '' === trim( (string) $s['countries_block'] ) && '' === trim( (string) $s['countries_strict'] ) ) {
			return self::state( self::OFF );
		}
		if ( empty( $s['enabled'] ) ) {
			return self::state( self::SET, self::protection_off_reason() );
		}
		$status = PNCP_Geo::status();
		if ( empty( $status['updated'] ) && ! PNCP_Ip::behind_cloudflare() && ! PNCP_Ip::behind_bunny() ) {
			return self::state( self::SET, empty( $s['geo_db'] ) ? __( 'the country database is off and no CDN sends the country', 'scrapelock' ) : __( 'the country database is not downloaded yet', 'scrapelock' ) );
		}
		return self::state( self::ON );
	}

	/**
	 * Stealth (its own card on the Rules tab).
	 *
	 * @param array<string, mixed> $s Settings (PNCP_Stealth::settings()).
	 * @return array{state:string, reason:string}
	 */
	public static function stealth( $s ) {
		if ( PNCP_Stealth::active() ) {
			return self::state( self::ON );
		}
		if ( empty( $s['stealth_enabled'] ) ) {
			return self::state( self::OFF );
		}
		if ( empty( $s['enabled'] ) ) {
			return self::state( self::SET, self::protection_off_reason() );
		}
		if ( is_multisite() ) {
			return self::state( self::SET, __( 'not available on multisite', 'scrapelock' ) );
		}
		if ( defined( 'SCRAPELOCK_STEALTH_OFF' ) && SCRAPELOCK_STEALTH_OFF ) {
			return self::state( self::SET, __( 'turned off in wp-config.php (SCRAPELOCK_STEALTH_OFF)', 'scrapelock' ) );
		}
		$error = (string) ( isset( PNCP_Stealth::state()['error'] ) ? PNCP_Stealth::state()['error'] : '' );
		return self::state( self::SET, '' !== $error ? $error : __( 'its test has not passed yet', 'scrapelock' ) );
	}

	/**
	 * The weekly attack report by email.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array{state:string, reason:string}
	 */
	public static function weekly_report( $s ) {
		if ( ! PNCP_Attack_Report::weekly_on( $s ) ) {
			return self::state( self::OFF );
		}
		if ( ! PNCP_Attack_Report::recipients() ) {
			return self::state( self::SET, __( 'the site has no valid administration email address', 'scrapelock' ) );
		}
		if ( ! wp_next_scheduled( PNCP_Attack_Report::CRON ) ) {
			return self::state( self::SET, __( 'it is not scheduled yet', 'scrapelock' ) );
		}
		return self::state( self::ON );
	}

	/**
	 * The badge text: "On", "Set but not active: <reason>" or "Off".
	 *
	 * @param array{state:string, reason:string} $state State.
	 * @return string
	 */
	public static function text( $state ) {
		if ( self::ON === $state['state'] ) {
			return __( 'On', 'scrapelock' );
		}
		if ( self::SET === $state['state'] ) {
			/* translators: %s: why the setting is not in effect, e.g. "the CDN secret is missing" */
			return sprintf( __( 'Set but not active: %s', 'scrapelock' ), $state['reason'] );
		}
		return __( 'Off', 'scrapelock' );
	}

	/**
	 * The same in lower case, for a line of text ("Early check: on · Pre-cache check: set but not active: …").
	 *
	 * @param array{state:string, reason:string} $state State.
	 * @return string
	 */
	public static function inline_text( $state ) {
		if ( self::ON === $state['state'] ) {
			return __( 'on', 'scrapelock' );
		}
		if ( self::SET === $state['state'] ) {
			/* translators: %s: why the setting is not in effect, e.g. "the CDN secret is missing" */
			return sprintf( __( 'set but not active: %s', 'scrapelock' ), $state['reason'] );
		}
		return __( 'off', 'scrapelock' );
	}
}
