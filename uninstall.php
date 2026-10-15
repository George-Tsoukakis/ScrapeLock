<?php
/**
 * Διαγραφή plugin: σβήνει τις ρυθμίσεις του και τα προσωρινά δεδομένα (όριο αιτημάτων, επαλήθευση bots).
 *
 * @package Content_Protect
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Καθαρίζει ένα site.
 */
function pncp_uninstall_site() {
	global $wpdb;

	delete_option( 'pncp_settings' );
	delete_option( 'pncp_version' );

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Μία φορά, στη διαγραφή.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_pncp_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_pncp_' ) . '%'
		)
	);
}

if ( is_multisite() ) {
	foreach ( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) as $pncp_site_id ) {
		switch_to_blog( $pncp_site_id );
		pncp_uninstall_site();
		restore_current_blog();
	}
} else {
	pncp_uninstall_site();
}
