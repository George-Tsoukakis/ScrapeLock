<?php
/**
 * ScrapeLock on Tools → Site Health: tests for the settings that silently stop working (the real visitor IP
 * behind a CDN, the early check, the pre-cache check, Lockdown) and a section in the Info tab.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Site Health tests and debug information.
 */
final class PNCP_Health {

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'site_status_tests', array( __CLASS__, 'tests' ) );
		add_filter( 'debug_information', array( __CLASS__, 'info' ) );
	}

	/**
	 * The tests, all direct (they only read settings, files and the current request).
	 *
	 * @param array<string, mixed> $tests Tests.
	 * @return array<string, mixed>
	 */
	public static function tests( $tests ) {
		$names = array(
			'protection' => __( 'ScrapeLock protection', 'scrapelock' ),
			'real_ip'    => __( 'ScrapeLock real visitor IP', 'scrapelock' ),
			'early'      => __( 'ScrapeLock early check', 'scrapelock' ),
			'precheck'   => __( 'ScrapeLock pre-cache check', 'scrapelock' ),
			'lockdown'   => __( 'ScrapeLock Lockdown', 'scrapelock' ),
			'integrity'  => __( 'ScrapeLock file integrity', 'scrapelock' ),
		);
		foreach ( $names as $key => $label ) {
			$tests['direct'][ 'scrapelock_' . $key ] = array(
				'label' => $label,
				'test'  => array( __CLASS__, 'test_' . $key ),
			);
		}
		return $tests;
	}

	/**
	 * One result in the form Site Health expects.
	 *
	 * @param string $key         Test key.
	 * @param string $status      good | recommended | critical.
	 * @param string $label       Title.
	 * @param string $description Explanation (plain text).
	 * @param string $tab         Settings tab for the link ('' = none).
	 * @return array<string, mixed>
	 */
	private static function result( $key, $status, $label, $description, $tab = '' ) {
		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'critical' === $status ? 'red' : ( 'recommended' === $status ? 'orange' : 'blue' ),
			),
			'description' => '<p>' . esc_html( $description ) . '</p>',
			'actions'     => '' === $tab ? '' : '<p><a href="' . esc_url( PNCP_Status::settings_url( array( 'tab' => $tab ) ) ) . '">' . esc_html__( 'Open the ScrapeLock settings', 'scrapelock' ) . '</a></p>',
			'test'        => 'scrapelock_' . $key,
		);
	}

	/**
	 * Is protection on?
	 *
	 * @return array<string, mixed>
	 */
	public static function test_protection() {
		if ( PNCP_Status::is_enabled() ) {
			return self::result( 'protection', 'good', __( 'ScrapeLock protection is on', 'scrapelock' ), __( 'Content, feeds and the REST API are protected and bots are checked.', 'scrapelock' ) );
		}
		return self::result( 'protection', 'recommended', __( 'ScrapeLock protection is off', 'scrapelock' ), __( 'The plugin is active but protects nothing: content can be copied and bots are not checked.', 'scrapelock' ), 'general' );
	}

	/**
	 * Behind a CDN, does every visitor appear with the CDN's address?
	 *
	 * @return array<string, mixed>
	 */
	public static function test_real_ip() {
		$cdn = PNCP_Status::is_enabled() ? PNCP_Ip::cdn_hides_visitors() : '';
		if ( 'cloudflare' === $cdn ) {
			return self::result( 'real_ip', 'critical', __( 'All visitors appear with a Cloudflare address', 'scrapelock' ), __( 'The site is behind Cloudflare, but ScrapeLock sees Cloudflare\'s address instead of the visitor\'s. Limits and blocks then hit Cloudflare itself, i.e. many visitors at once. Use CF-Connecting-IP (one click on the Bots tab).', 'scrapelock' ), 'bots' );
		}
		if ( 'bunny' === $cdn ) {
			return self::result( 'real_ip', 'critical', __( 'All visitors appear with a Bunny CDN address', 'scrapelock' ), __( 'The site is behind Bunny CDN, but ScrapeLock sees Bunny\'s address instead of the visitor\'s. Limits and blocks then hit Bunny itself, i.e. many visitors at once. Use X-Real-IP from Bunny (one click on the Bots tab).', 'scrapelock' ), 'bots' );
		}
		return self::result( 'real_ip', 'good', __( 'ScrapeLock sees the real visitor IP', 'scrapelock' ), __( 'No CDN was found hiding the visitors\' addresses on this request.', 'scrapelock' ) );
	}

	/**
	 * Early check on, but the mu-plugin is missing.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_early() {
		$s = PNCP_Options::stored();
		if ( empty( $s['enabled'] ) || empty( $s['early_mode'] ) ) {
			return self::result( 'early', 'good', __( 'The ScrapeLock early check is off', 'scrapelock' ), __( 'Bots are checked when the plugin loads, as usual.', 'scrapelock' ) );
		}
		if ( PNCP_Early::installed() ) {
			return self::result( 'early', 'good', __( 'The ScrapeLock early check is running', 'scrapelock' ), __( 'Its file in wp-content/mu-plugins is in place: bots are stopped before other plugins load.', 'scrapelock' ) );
		}
		return self::result( 'early', 'recommended', __( 'The ScrapeLock early check is on but not running', 'scrapelock' ), __( 'Its file in wp-content/mu-plugins is missing or out of date (the server does not allow direct file writes). Bots are still checked, only later. Save the settings again, or turn the setting off.', 'scrapelock' ), 'bots' );
	}

	/**
	 * Pre-cache check on, but not loaded from wp-config.php.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_precheck() {
		$s = PNCP_Options::stored();
		if ( empty( $s['enabled'] ) || empty( $s['precheck'] ) ) {
			return self::result( 'precheck', 'good', __( 'The ScrapeLock pre-cache check is off', 'scrapelock' ), __( 'Pages served from the page cache are not checked first; the normal check works as usual.', 'scrapelock' ) );
		}
		if ( PNCP_Precheck::active() ) {
			return self::result( 'precheck', 'good', __( 'The ScrapeLock pre-cache check is running', 'scrapelock' ), __( 'wp-config.php loads the check before the page cache.', 'scrapelock' ) );
		}
		return self::result( 'precheck', 'recommended', __( 'The ScrapeLock pre-cache check is on but not running', 'scrapelock' ), __( 'wp-config.php does not load it (it could not be changed, or the folder wp-content/scrapelock-precheck could not be created). The normal check works as before; the Bots tab shows the lines to add by hand.', 'scrapelock' ), 'bots' );
	}

	/**
	 * Lockdown: off from the server, or updates waiting while locked.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_lockdown() {
		if ( PNCP_Lockdown::server_unlocked() ) {
			return self::result( 'lockdown', 'critical', __( 'ScrapeLock Lockdown is off from the server', 'scrapelock' ), __( 'SCRAPELOCK_UNLOCK is set in wp-config.php, so the lock is not applied. Connect the authenticator app again, then remove that line.', 'scrapelock' ), 'lockdown' );
		}
		if ( ! PNCP_Lockdown::configured() ) {
			return self::result( 'lockdown', 'good', __( 'ScrapeLock Lockdown is not set up', 'scrapelock' ), __( 'Lockdown is optional: it freezes changes to plugins, themes, users and settings until it is unlocked with an authenticator app.', 'scrapelock' ) );
		}
		if ( ! PNCP_Lockdown::is_locked() ) {
			return self::result( 'lockdown', 'good', __( 'ScrapeLock Lockdown is unlocked', 'scrapelock' ), __( 'Changes to the site are allowed. Lock it again when you are done.', 'scrapelock' ) );
		}
		$waiting = self::updates_waiting();
		if ( $waiting > 0 ) {
			return self::result(
				'lockdown',
				'recommended',
				/* translators: %d: number of updates. */
				sprintf( _n( 'The site is locked: %d update is waiting', 'The site is locked: %d updates are waiting', $waiting, 'scrapelock' ), $waiting ),
				__( 'While locked, updates are not installed, not even automatically (so WordPress also reports background updates as off). Unlock with the authenticator app, update, then lock again.', 'scrapelock' ),
				'lockdown'
			);
		}
		return self::result( 'lockdown', 'good', __( 'The site is locked by ScrapeLock Lockdown', 'scrapelock' ), __( 'Plugins, themes, users and settings cannot be changed until it is unlocked with the authenticator app. Automatic updates wait too (so WordPress reports background updates as off).', 'scrapelock' ) );
	}

	/**
	 * File integrity: code files added or changed while locked, or different from WordPress.org.
	 *
	 * @return array<string, mixed>
	 */
	public static function test_integrity() {
		$found = PNCP_Integrity::findings( PNCP_Integrity::report() );
		if ( $found ) {
			return self::result(
				'integrity',
				'critical',
				/* translators: %d: number of files. */
				sprintf( _n( 'ScrapeLock found %d changed code file', 'ScrapeLock found %d changed code files', count( $found ), 'scrapelock' ), count( $found ) ),
				__( 'Code files were added or changed while the site was locked, or differ from the official copies on WordPress.org. Nobody can install or update anything while the site is locked, so a file you do not recognise is often a backdoor uploaded through a vulnerable plugin. The list is on the Lockdown tab.', 'scrapelock' ),
				'lockdown'
			);
		}
		if ( ! PNCP_Integrity::baseline()['time'] ) {
			return self::result( 'integrity', 'good', __( 'ScrapeLock file integrity is not active', 'scrapelock' ), __( 'The fingerprint of the code files is taken when the site is locked with Lockdown, and checked every hour while it stays locked.', 'scrapelock' ) );
		}
		return self::result( 'integrity', 'good', __( 'No changed code files', 'scrapelock' ), __( 'No code file was added or changed since the site was locked, and WordPress and its plugins from WordPress.org match their official copies.', 'scrapelock' ) );
	}

	/**
	 * Updates WordPress already knows about (core, plugins, themes, translations not counted).
	 *
	 * @return int
	 */
	private static function updates_waiting() {
		$count = 0;
		foreach ( array( 'update_plugins', 'update_themes' ) as $name ) {
			$data = get_site_transient( $name );
			if ( is_object( $data ) && ! empty( $data->response ) && is_array( $data->response ) ) {
				$count += count( $data->response );
			}
		}
		$core = get_site_transient( 'update_core' );
		if ( is_object( $core ) && ! empty( $core->updates ) && is_array( $core->updates ) ) {
			foreach ( $core->updates as $update ) {
				if ( is_object( $update ) && isset( $update->response ) && 'upgrade' === $update->response ) {
					++$count;
					break;
				}
			}
		}
		return $count;
	}

	/**
	 * The ScrapeLock section on the Info tab (and in the copied report). No secrets: no keys, tokens or
	 * IP lists, only what is on and off.
	 *
	 * @param array<string, mixed> $info Sections.
	 * @return array<string, mixed>
	 */
	public static function info( $info ) {
		$s     = PNCP_Options::stored();
		$yes   = __( 'Yes', 'scrapelock' );
		$no    = __( 'No', 'scrapelock' );
		$flag  = static function ( $key ) use ( $s, $yes, $no ) {
			return ! empty( $s[ $key ] ) ? $yes : $no;
		};
		$until = PNCP_Options::emergency_until();
		$lists = array();
		foreach ( PNCP_Ip::lists_updated() as $name => $time ) {
			$lists[] = $name . ': ' . ( $time ? wp_date( 'Y-m-d H:i', $time ) : '-' );
		}
		if ( PNCP_Lockdown::server_unlocked() ) {
			$lock = __( 'Off from the server (SCRAPELOCK_UNLOCK)', 'scrapelock' );
		} elseif ( ! PNCP_Lockdown::configured() ) {
			$lock = __( 'Not set up', 'scrapelock' );
		} elseif ( PNCP_Lockdown::is_locked() ) {
			$lock = __( 'Locked', 'scrapelock' );
		} elseif ( PNCP_Lockdown::unlocked_until() ) {
			/* translators: %s: date and time. */
			$lock = sprintf( __( 'Unlocked until %s', 'scrapelock' ), wp_date( 'Y-m-d H:i', PNCP_Lockdown::unlocked_until() ) );
		} else {
			$lock = __( 'Not locked', 'scrapelock' );
		}
		$fields = array(
			'version'        => array( __( 'Version', 'scrapelock' ), PNCP_VERSION ),
			'enabled'        => array( __( 'Protection', 'scrapelock' ), $flag( 'enabled' ) ),
			/* translators: %s: date and time. */
			'emergency'      => array( __( 'Emergency Mode', 'scrapelock' ), $until ? sprintf( __( 'On until %s', 'scrapelock' ), wp_date( 'Y-m-d H:i', $until ) ) : $no ),
			'ip_header'      => array( __( 'Real visitor IP', 'scrapelock' ), (string) $s['ip_header'] ),
			'ip_lists'       => array( __( 'Official IP lists updated', 'scrapelock' ), $lists ? implode( ', ', $lists ) : '-' ),
			'early'          => array( __( 'Early check', 'scrapelock' ), empty( $s['early_mode'] ) ? $no : ( PNCP_Early::installed() ? __( 'Running', 'scrapelock' ) : __( 'On, not running', 'scrapelock' ) ) ),
			'precheck'       => array( __( 'Pre-cache check', 'scrapelock' ), empty( $s['precheck'] ) ? $no : ( PNCP_Precheck::active() ? __( 'Running', 'scrapelock' ) : __( 'On, not running', 'scrapelock' ) ) ),
			'user_enum'      => array( __( 'Hide usernames', 'scrapelock' ), $flag( 'block_user_enum' ) ),
			'pingback'       => array( __( 'Pingbacks off', 'scrapelock' ), $flag( 'disable_pingback' ) ),
			'rest_map'       => array( __( 'REST map hidden from visitors', 'scrapelock' ), $flag( 'hide_rest_discovery' ) ),
			'versions'       => array( __( 'Versions hidden', 'scrapelock' ), $flag( 'hide_versions' ) ),
			'list_excerpts'  => array( __( 'Excerpts in lists of articles', 'scrapelock' ), $flag( 'list_excerpts' ) ),
			'ipv6_wide'      => array( __( 'IPv6 /56 limit', 'scrapelock' ), $flag( 'ipv6_wide' ) ),
			'archives'       => array( __( 'Web archives blocked', 'scrapelock' ), $flag( 'block_archivers' ) ),
			'upload_php'     => array( __( 'No PHP in the uploads folder', 'scrapelock' ), $flag( 'block_upload_php' ) ),
			'integrity'      => array( __( 'File integrity fingerprint', 'scrapelock' ), PNCP_Integrity::baseline()['time'] ? wp_date( 'Y-m-d H:i', PNCP_Integrity::baseline()['time'] ) : '-' ),
			'lockdown'       => array( __( 'Lockdown', 'scrapelock' ), $lock ),
			'lockdown_roles' => array( __( 'Roles frozen while locked', 'scrapelock' ), implode( ', ', PNCP_Lockdown::frozen_roles() ) ),
		);
		$section = array(
			'label'  => 'ScrapeLock',
			'fields' => array(),
		);
		foreach ( $fields as $key => $field ) {
			$section['fields'][ $key ] = array(
				'label' => $field[0],
				'value' => $field[1],
			);
		}
		$info['scrapelock'] = $section;
		return $info;
	}
}
