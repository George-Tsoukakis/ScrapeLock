<?php
/**
 * Plugin uninstall: removes settings, the log table, cron events and transient data.
 *
 * Does NOT delete the folder with the clean image originals (uploads/pncp-originals-…): if some
 * images are watermarked at full size, those are their only clean copies.
 *
 * @package ScrapeLock
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Cleans up a single site.
 */
function pncp_uninstall_site() {
	global $wpdb;

	foreach ( array( 'pncp_settings', 'pncp_version', 'pncp_db_version', 'pncp_emergency_until', 'pncp_ip_lists', 'pncp_ip_lists_cloudflare', 'pncp_ip_lists_bunny', 'pncp_ip_lists_google', 'pncp_ip_lists_bing', 'pncp_ip_lists_openai_search', 'pncp_ip_lists_openai_user', 'pncp_ip_lists_perplexity_bot', 'pncp_ip_lists_perplexity_user', 'pncp_ip_lists_anthropic', 'pncp_ip_lists_updated', 'pncp_bans', 'pncp_feed_token', 'pncp_feed_stats', 'pncp_legacy_token_notice', 'pncp_legacy_token_migrated', 'pncp_wm_cursor_apply', 'pncp_wm_cursor_remove', 'pncp_upgrade_lock', 'pncp_geo', 'pncp_precheck_status', 'pncp_log_uas' ) as $pncp_option ) {
		delete_option( $pncp_option );
	}
	wp_clear_scheduled_hook( 'pncp_refresh_ip_lists' );
	wp_clear_scheduled_hook( 'pncp_log_cleanup' );
	wp_clear_scheduled_hook( 'pncp_wm_unmark' );

	// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Runs once, on uninstall.
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'pncp_log' ) );
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'pncp_bans' ) );
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_pncp_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_pncp_' ) . '%'
		)
	);
	// phpcs:enable
}

// The country database (uploads/scrapelock-geo, shared by the sites of a network).
$pncp_geo = trailingslashit( wp_upload_dir( null, false )['basedir'] ) . 'scrapelock-geo';
foreach ( array( 'v4.bin', 'v6.bin', 'index.php', '.htaccess' ) as $pncp_file ) {
	if ( file_exists( $pncp_geo . '/' . $pncp_file ) ) {
		wp_delete_file( $pncp_geo . '/' . $pncp_file );
	}
}
unset( $pncp_geo, $pncp_file );

// The pre-cache check (normally already removed on deactivation): its line in wp-config.php and its files.
if ( ! is_multisite() ) {
	require_once __DIR__ . '/includes/class-pncp-precheck.php';
	PNCP_Precheck::remove( false );
}

// The early check (mu-plugin, shared by all sites of a network): removed only if ScrapeLock wrote it.
$pncp_early = trailingslashit( WPMU_PLUGIN_DIR ) . 'scrapelock-early.php';
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
