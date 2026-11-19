<?php
/**
 * 3.10: the tab named in the address of the settings page (?tab=…): other names people use for a tab (from
 * older versions, the documentation or a support answer, e.g. "vulnerable" or "server") open that tab, and a
 * name that is no tab at all opens the first tab with a notice, instead of silently showing it.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Tab names and their aliases.
 */
final class PNCP_Admin_Tabs {

	/**
	 * Other names of the tabs: alias => tab key (see PNCP_Admin::tabs()). Keys are as sanitize_key() gives them.
	 *
	 * @return array<string, string>
	 */
	public static function aliases() {
		$aliases = array(
			// "Vulnerable points".
			'vulnerable'        => 'hardening',
			'vulnerable-points' => 'hardening',
			'vulnerable_points' => 'hardening',
			'vulnerabilities'   => 'hardening',
			'harden'            => 'hardening',
			'security'          => 'hardening',
			// "Server rules".
			'server'            => 'rules',
			'server-rules'      => 'rules',
			'server_rules'      => 'rules',
			'rule'              => 'rules',
			'nginx'             => 'rules',
			'apache'            => 'rules',
			'htaccess'          => 'rules',
			// "Attacks".
			'attack'            => 'attacks',
			'attack-report'     => 'attacks',
			'attack_report'     => 'attacks',
			'report'            => 'attacks',
			// "Log".
			'logs'              => 'log',
			// "Bots and limits".
			'bot'               => 'bots',
			'limits'            => 'bots',
			'bots-and-limits'   => 'bots',
			'edge'              => 'bots',
			'cdn'               => 'bots',
			'bunny'             => 'bots',
			// "Feeds and API".
			'feeds'             => 'content',
			'feed'              => 'content',
			'api'               => 'content',
			'rest'              => 'content',
			// "Images".
			'image'             => 'images',
			'watermark'         => 'images',
			// "On the page".
			'page'              => 'general',
			'on-the-page'       => 'general',
			'protection'        => 'general',
			// "Lockdown".
			'lock'              => 'lockdown',
		);
		/**
		 * Filters the other names of the settings tabs (alias => tab key).
		 *
		 * @param array<string, string> $aliases Aliases.
		 */
		return (array) apply_filters( 'pncp_admin_tab_aliases', $aliases );
	}

	/**
	 * The tab to show for a requested name.
	 *
	 * @param string                $requested Requested name (as in ?tab=, unsanitized is fine).
	 * @param array<string, string> $tabs      Tab key => label; the first one is the default.
	 * @return array{tab: string, unknown: string} The tab, and the requested name when it is no tab nor alias.
	 */
	public static function resolve( $requested, $tabs ) {
		$keys    = array_keys( $tabs );
		$first   = $keys ? (string) $keys[0] : 'general';
		$name    = sanitize_key( (string) $requested );
		$aliases = self::aliases();
		if ( '' === $name ) {
			return array(
				'tab'     => $first,
				'unknown' => '',
			);
		}
		if ( isset( $tabs[ $name ] ) ) {
			return array(
				'tab'     => $name,
				'unknown' => '',
			);
		}
		if ( isset( $aliases[ $name ] ) && isset( $tabs[ $aliases[ $name ] ] ) ) {
			return array(
				'tab'     => (string) $aliases[ $name ],
				'unknown' => '',
			);
		}
		return array(
			'tab'     => $first,
			'unknown' => $name,
		);
	}

	/**
	 * The tab requested by this page load (?tab=).
	 *
	 * @param array<string, string> $tabs Tab key => label.
	 * @return array{tab: string, unknown: string}
	 */
	public static function current( $tabs ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects a tab.
		$requested = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		return self::resolve( $requested, $tabs );
	}

	/**
	 * The notice for an unknown tab in the address: "Unknown tab “x”: showing On the page".
	 *
	 * @param array<string, string> $tabs Tab key => label.
	 */
	public static function render_notice( $tabs ) {
		$current = self::current( $tabs );
		if ( '' === $current['unknown'] || ! isset( $tabs[ $current['tab'] ] ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning pncp-unknown-tab"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: 1: the tab name from the address, 2: name of the tab shown instead */
					__( 'Unknown tab “%1$s”: showing %2$s', 'scrapelock' ),
					$current['unknown'],
					$tabs[ $current['tab'] ]
				)
			)
		);
	}
}
