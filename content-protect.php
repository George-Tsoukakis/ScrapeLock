<?php
/**
 * Plugin Name:       Content Protect
 * Description:       Προστασία περιεχομένου: αποτρέπει την αντιγραφή κειμένου και εικόνων, κλείνει το κείμενο στο REST API και στο RSS, μπλοκάρει scrapers και AI bots και βάζει προαιρετικά υδατογράφημα. Δεν επηρεάζει φόρμες, καλάθι, ταμείο και μηχανές αναζήτησης.
 * Version:           1.3.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            The-Greek
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       content-protect
 * Domain Path:       /languages
 */

defined( 'ABSPATH' ) || exit;

// Αν φορτώθηκε ήδη άλλο αντίγραφο (π.χ. η παλιά έκδοση σε άλλο φάκελο), δεν ξαναφορτώνουμε.
if ( defined( 'PNCP_VERSION' ) ) {
	return;
}

define( 'PNCP_VERSION', '1.3.0' );
define( 'PNCP_FILE', __FILE__ );
define( 'PNCP_DIR', plugin_dir_path( __FILE__ ) );
define( 'PNCP_URL', plugin_dir_url( __FILE__ ) );
define( 'PNCP_OPTION', 'pncp_settings' );

require_once PNCP_DIR . 'includes/class-pncp-options.php';
require_once PNCP_DIR . 'includes/class-pncp-frontend.php';
require_once PNCP_DIR . 'includes/class-pncp-rest.php';
require_once PNCP_DIR . 'includes/class-pncp-feed.php';
require_once PNCP_DIR . 'includes/class-pncp-bots.php';
require_once PNCP_DIR . 'includes/class-pncp-watermark.php';
require_once PNCP_DIR . 'includes/class-pncp-private-urls.php';

if ( is_admin() ) {
	require_once PNCP_DIR . 'includes/class-pncp-admin.php';
	PNCP_Admin::init();
}

PNCP_Frontend::init();
PNCP_Rest::init();
PNCP_Feed::init();
PNCP_Bots::init();
PNCP_Watermark::init();
PNCP_Private_Urls::init();

/**
 * Φορτώνει τις μεταφράσεις.
 */
function pncp_load_textdomain() {
	load_plugin_textdomain( 'content-protect', false, dirname( plugin_basename( PNCP_FILE ) ) . '/languages' );
}
add_action( 'init', 'pncp_load_textdomain' );

/**
 * Στην ενεργοποίηση γράφει τις προεπιλογές, χωρίς να πειράζει υπάρχουσες ρυθμίσεις.
 */
function pncp_activate() {
	if ( false === get_option( PNCP_OPTION ) ) {
		add_option( PNCP_OPTION, PNCP_Options::defaults() );
	}
	pncp_purge_page_cache();
}
register_activation_hook( PNCP_FILE, 'pncp_activate' );
register_deactivation_hook( PNCP_FILE, 'pncp_deactivate' );

/**
 * Στην απενεργοποίηση αφαιρεί τη λίστα bots από το WP Rocket και αδειάζει την cache.
 */
function pncp_deactivate() {
	remove_filter( 'rocket_cache_reject_ua', array( 'PNCP_Bots', 'rocket_reject_ua' ) );
	pncp_purge_page_cache();
}

/**
 * Αδειάζει την cache σελίδων, ώστε οι επισκέπτες να δουν αμέσως τις νέες ρυθμίσεις.
 * Καλύπτει WP Rocket και Nginx Helper (FastCGI cache), αν υπάρχουν.
 */
function pncp_purge_page_cache() {
	// Το WP Rocket ξαναγράφει το config του, ώστε να ισχύσει η λίστα bots (rocket_cache_reject_ua).
	if ( function_exists( 'rocket_generate_config_file' ) ) {
		rocket_generate_config_file();
	}
	if ( function_exists( 'flush_rocket_htaccess' ) ) {
		flush_rocket_htaccess();
	}
	if ( function_exists( 'rocket_clean_domain' ) ) {
		rocket_clean_domain();
	}
	do_action( 'rt_nginx_helper_purge_all' );
}
add_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache' );

/**
 * Μετά από ενημέρωση του plugin (νέο zip) δεν τρέχει το activation hook,
 * οπότε η cache αδειάζει μία φορά όταν αλλάξει η έκδοση.
 */
function pncp_maybe_purge_after_update() {
	if ( get_option( 'pncp_version' ) === PNCP_VERSION ) {
		return;
	}
	update_option( 'pncp_version', PNCP_VERSION, false );
	pncp_purge_page_cache();
}
add_action( 'admin_init', 'pncp_maybe_purge_after_update' );

/**
 * Το WP Rocket (Delay JS) δεν πρέπει να καθυστερεί την προστασία μέχρι την πρώτη
 * κίνηση του επισκέπτη, αλλιώς το πρώτο δεξί κλικ περνάει.
 *
 * @param string[] $exclusions Μοτίβα που εξαιρούνται.
 * @return string[]
 */
function pncp_rocket_delay_exclusions( $exclusions ) {
	$exclusions   = (array) $exclusions;
	$exclusions[] = 'content-protect/assets/js/protect.js';
	$exclusions[] = 'pncpConfig';
	return $exclusions;
}
add_filter( 'rocket_delay_js_exclusions', 'pncp_rocket_delay_exclusions' );
