<?php
/**
 * Διαγραφή plugin: σβήνει ρυθμίσεις, πίνακα αρχείου, cron και προσωρινά δεδομένα.
 *
 * ΔΕΝ σβήνει τον φάκελο με τα καθαρά πρωτότυπα των εικόνων (uploads/pncp-originals-…): αν κάποιες
 * εικόνες έχουν υδατογράφημα στο πλήρες μέγεθος, εκεί είναι τα μόνα καθαρά αντίγραφά τους.
 *
 * @package Content_Protect
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Καθαρίζει ένα site.
 */
function pncp_uninstall_site() {
	global $wpdb;

	foreach ( array( 'pncp_settings', 'pncp_version', 'pncp_db_version', 'pncp_emergency_until', 'pncp_ip_lists', 'pncp_ip_lists_cloudflare', 'pncp_ip_lists_google', 'pncp_ip_lists_bing', 'pncp_ip_lists_updated', 'pncp_bans', 'pncp_feed_token', 'pncp_feed_stats', 'pncp_legacy_token_notice', 'pncp_legacy_token_migrated', 'pncp_wm_cursor_apply', 'pncp_wm_cursor_remove', 'pncp_upgrade_lock' ) as $pncp_option ) {
		delete_option( $pncp_option );
	}
	wp_clear_scheduled_hook( 'pncp_refresh_ip_lists' );
	wp_clear_scheduled_hook( 'pncp_log_cleanup' );
	wp_clear_scheduled_hook( 'pncp_wm_unmark' );

	// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Μία φορά, στη διαγραφή.
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
