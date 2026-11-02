<?php
/**
 * Plugin uninstall: removes settings, the log table, cron events and transient data.
 *
 * Does NOT delete the folder with the clean image originals (uploads/pncp-originals-…), nor its index
 * (the _pncp_wm meta of each image and pncp_backup_dir): if some images are watermarked at full size, those
 * are their only clean copies, and a reinstall can restore them with "Remove watermark".
 *
 * @package ScrapeLock
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

require_once __DIR__ . '/includes/class-pncp-paths.php';

/**
 * Cleans up a single site.
 */
function pncp_uninstall_site() {
	global $wpdb;

	// Blocks still waiting to be removed at the CDN (deactivation stops after 20 seconds, or on a rate limit):
	// one more try now, before their list is deleted with the settings. Otherwise they would stay at the CDN
	// for good, as permanent blocks. Rules that are still left carry the note "ScrapeLock" in the CDN dashboard.
	$pncp_retire = get_option( 'pncp_edge_retire', array() );
	$pncp_config = get_option( 'pncp_edge', array() );
	if ( ( is_array( $pncp_retire ) && $pncp_retire ) || ( is_array( $pncp_config ) && ! empty( $pncp_config['provider'] ) ) ) {
		try {
			defined( 'PNCP_OPTION' ) || define( 'PNCP_OPTION', 'pncp_settings' );
			foreach ( array( 'time', 'options', 'ip', 'log', 'edge' ) as $pncp_class ) {
				require_once __DIR__ . '/includes/class-pncp-' . $pncp_class . '.php';
			}
			PNCP_Edge::remove_all( 20 );
		} catch ( Throwable $pncp_error ) {
			unset( $pncp_error ); // Uninstall goes on: the leftover rules can be removed in the CDN dashboard.
		}
	}
	unset( $pncp_retire, $pncp_config );

	foreach ( array( 'pncp_settings', 'pncp_version', 'pncp_db_version', 'pncp_emergency_until', 'pncp_ip_lists', 'pncp_ip_lists_cloudflare', 'pncp_ip_lists_bunny', 'pncp_ip_lists_google', 'pncp_ip_lists_bing', 'pncp_ip_lists_openai_search', 'pncp_ip_lists_openai_user', 'pncp_ip_lists_perplexity_bot', 'pncp_ip_lists_perplexity_user', 'pncp_ip_lists_anthropic', 'pncp_ip_lists_updated', 'pncp_bans', 'pncp_feed_token', 'pncp_feed_stats', 'pncp_legacy_token_notice', 'pncp_legacy_token_migrated', 'pncp_wm_cursor_apply', 'pncp_wm_cursor_remove', 'pncp_upgrade_lock', 'pncp_geo', 'pncp_origin_proxy', 'pncp_precheck_status', 'pncp_precheck_key', 'pncp_log_uas', 'pncp_lockdown', 'pncp_lockdown_log', 'pncp_integrity', 'pncp_integrity_report', 'pncp_integrity_alerted', 'pncp_surge', 'pncp_surge_last', 'pncp_surge_alert', 'pncp_edge', 'pncp_edge_state', 'pncp_edge_retire', 'pncp_edge_staff', 'pncp_edge_lock', 'pncp_edge_dirty', 'pncp_edge_not_before', 'pncp_edge_calls', 'pncp_lockdown_snap', 'pncp_lockdown_digests', 'pncp_lockdown_window', 'pncp_lockdown_mutex', 'pncp_lockdown_mutex_pri', 'pncp_lockdown_fails', 'pncp_lockdown_dblock', 'pncp_integrity_stat', 'pncp_integrity_scan', 'pncp_upgrade_files', 'pncp_log_cleaned', 'pncp_bans_until', 'pncp_monitor_ended', 'pncp_settings_backups' ) as $pncp_option ) {
		delete_option( $pncp_option );
	}
	// Every event of each hook, whatever its arguments (wp_clear_scheduled_hook() only removes the ones without).
	foreach ( array( 'pncp_refresh_ip_lists', 'pncp_log_cleanup', 'pncp_log_cleanup_more', 'pncp_wm_unmark', 'pncp_edge_sync', 'pncp_integrity_official', 'pncp_integrity_resume', 'pncp_surge_mail', 'pncp_surge_mail_alert', 'pncp_background_purge', 'pncp_upgrade_files' ) as $pncp_hook ) {
		wp_unschedule_hook( $pncp_hook );
	}
	// The Lockdown guard (must-use plugin), only if it is ours.
	$pncp_guard = PNCP_Paths::mu_plugins() . '/scrapelock-lockdown-guard.php';
	if ( is_readable( $pncp_guard ) && false !== strpos( (string) file_get_contents( $pncp_guard, false, null, 0, 200 ), 'Plugin Name: ScrapeLock Lockdown guard' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		wp_delete_file( $pncp_guard );
	}
	// 3.4: the copy of the wrong-code counters next to the guard (3.4.1: in its own folder; 3.4.0: a .json file).
	$pncp_fails_dir = PNCP_Paths::mu_plugins() . '/scrapelock-lockdown-data';
	foreach ( array( PNCP_Paths::mu_plugins() . '/scrapelock-lockdown-fails.json', $pncp_fails_dir . '/fails.php', $pncp_fails_dir . '/index.php' ) as $pncp_fails_file ) {
		if ( file_exists( $pncp_fails_file ) ) {
			wp_delete_file( $pncp_fails_file );
		}
	}
	if ( is_dir( $pncp_fails_dir ) ) {
		@rmdir( $pncp_fails_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Only succeeds when empty.
	}
	unset( $pncp_fails_dir, $pncp_fails_file );
	// 3.4.1: the signed lock file written when the guard could not be (wp-content/uploads/scrapelock-lockdown or
	// wp-content/scrapelock-lockdown), only ScrapeLock's files, and the folder when it is empty then.
	foreach ( array( WP_CONTENT_DIR . '/uploads/scrapelock-lockdown', WP_CONTENT_DIR . '/scrapelock-lockdown' ) as $pncp_dir ) {
		if ( ! is_dir( $pncp_dir ) ) {
			continue;
		}
		foreach ( array_merge( (array) glob( $pncp_dir . '/lock-*.php' ), (array) glob( $pncp_dir . '/.lock-*.tmp' ) ) as $pncp_file ) {
			if ( is_string( $pncp_file ) && ( '.tmp' === substr( $pncp_file, -4 ) || 0 === strpos( (string) file_get_contents( $pncp_file, false, null, 0, 64 ), "<?php exit; ?>\n{\"beacon\":" ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
				wp_delete_file( $pncp_file );
			}
		}
		// The copy of the wrong-code counters next to the lock file.
		foreach ( (array) glob( $pncp_dir . '/fails-*.php' ) as $pncp_file ) {
			if ( is_string( $pncp_file ) && 0 === strpos( (string) file_get_contents( $pncp_file, false, null, 0, 64 ), "<?php exit; ?>\n{\"rows\":" ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
				wp_delete_file( $pncp_file );
			}
		}
		foreach ( array(
			'index.php' => "<?php\n// Silence is golden.\n",
			'.htaccess' => "# ScrapeLock Lockdown\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n",
		) as $pncp_name => $pncp_content ) {
			if ( is_file( $pncp_dir . '/' . $pncp_name ) && file_get_contents( $pncp_dir . '/' . $pncp_name ) === $pncp_content ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
				wp_delete_file( $pncp_dir . '/' . $pncp_name );
			}
		}
		@rmdir( $pncp_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Only succeeds when empty.
	}
	unset( $pncp_dir, $pncp_file, $pncp_name, $pncp_content );
	// The lock file of the code checks (in the must-use plugins folder, or in wp-content).
	foreach ( array( PNCP_Paths::mu_plugins(), PNCP_Paths::content() ) as $pncp_dir ) {
		if ( file_exists( $pncp_dir . '/scrapelock-lockdown.lock' ) ) {
			wp_delete_file( $pncp_dir . '/scrapelock-lockdown.lock' );
		}
	}

	// The per-attachment "already watermarked" record (_pncp_wm) and pncp_backup_dir are kept on purpose: they
	// are the index of the clean image originals, which are intentionally not deleted (see the file header).
	// Without them a later reinstall could no longer tell which backup belongs to which file.

	// The country database folder (this site's uploads; on multisite each site has its own). Its files first,
	// then the now-empty folder.
	$pncp_geo = trailingslashit( wp_upload_dir( null, false )['basedir'] ) . 'scrapelock-geo';
	foreach ( array( 'v4.bin', 'v6.bin', 'index.html', 'index.php', '.htaccess' ) as $pncp_geo_file ) {
		if ( file_exists( $pncp_geo . '/' . $pncp_geo_file ) ) {
			wp_delete_file( $pncp_geo . '/' . $pncp_geo_file );
		}
	}
	if ( is_dir( $pncp_geo ) ) {
		@rmdir( $pncp_geo ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Only succeeds when empty; harmless otherwise.
	}
	unset( $pncp_geo, $pncp_geo_file );

	// "No PHP in the uploads folder": ScrapeLock's block in the .htaccess of the uploads folder (other content stays).
	$pncp_htaccess = trailingslashit( wp_upload_dir( null, false )['basedir'] ) . '.htaccess';
	if ( file_exists( $pncp_htaccess ) ) {
		require_once __DIR__ . '/includes/class-pncp-rules.php';
		PNCP_Rules::remove_marker_block( $pncp_htaccess ); // The whole block, markers included.
	}
	unset( $pncp_htaccess );

	// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Runs once, on uninstall.
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'pncp_log' ) );
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'pncp_bans' ) );
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_pncp_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_pncp_' ) . '%',
			$wpdb->esc_like( '_site_transient_pncp_' ) . '%',
			$wpdb->esc_like( '_site_transient_timeout_pncp_' ) . '%',
			$wpdb->esc_like( 'pncp_dc_' ) . '%',
			$wpdb->esc_like( 'pncp_ip_lists_dc_' ) . '%'
		)
	);
	// phpcs:enable
}

// The pre-cache check (normally already removed on deactivation): its line in wp-config.php and its files.
if ( ! is_multisite() ) {
	require_once __DIR__ . '/includes/class-pncp-precheck.php';
	PNCP_Precheck::remove( false );
}

// The early check (mu-plugin, shared by all sites of a network): removed only if ScrapeLock wrote it.
$pncp_early = PNCP_Paths::mu_plugins() . '/scrapelock-early.php';
if ( is_readable( $pncp_early ) && false !== strpos( (string) file_get_contents( $pncp_early, false, null, 0, 200 ), 'Plugin Name: ScrapeLock early check' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	wp_delete_file( $pncp_early );
}
unset( $pncp_early );

if ( is_multisite() ) {
	foreach ( get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	) as $pncp_site_id ) {
		switch_to_blog( $pncp_site_id );
		pncp_uninstall_site();
		restore_current_blog();
	}
} else {
	pncp_uninstall_site();
}

// Lockdown: on multisite its state is network-wide (site options); the pending app secret is user meta.
delete_site_option( 'pncp_lockdown' );
delete_site_option( 'pncp_lockdown_log' );
delete_site_option( 'pncp_lockdown_mutex' );
delete_site_option( 'pncp_lockdown_mutex_pri' );
delete_site_option( 'pncp_lockdown_fails' );
delete_site_option( 'pncp_lockdown_dblock' );
delete_site_option( 'pncp_integrity' );
delete_site_option( 'pncp_integrity_report' );
delete_site_option( 'pncp_integrity_scan' );
delete_metadata( 'user', 0, 'pncp_lockdown_pending', '', true );
delete_site_option( 'pncp_lockdown_digests' );
// 3.4, multisite: the snapshot of the whole network, its fingerprints and the changes noted while unlocked for a while.
delete_site_option( 'pncp_lockdown_net_snap' );
delete_site_option( 'pncp_lockdown_net_digests' );
delete_site_option( 'pncp_lockdown_net_window' );

// Network transients (Lockdown wrong-code counters, recovery codes shown once, cached checksums): on multisite
// they live in the network's own table, which the per-site cleanup above does not reach.
if ( is_multisite() ) {
	global $wpdb; // uninstall.php is included from inside a function: the global must be named.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Runs once, on uninstall.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
			$wpdb->esc_like( '_site_transient_pncp_' ) . '%',
			$wpdb->esc_like( '_site_transient_timeout_pncp_' ) . '%'
		)
	);
}
