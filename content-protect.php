<?php
/**
 * Plugin Name:       Content Protect
 * Description:       Προστασία περιεχομένου: δυσκολεύει την αντιγραφή κειμένου και εικόνων, κλείνει το κείμενο στο REST API, στο GraphQL και στο RSS, μπλοκάρει scrapers, AI bots και ψεύτικα Googlebot, αποκλείει προσωρινά IP που επιμένουν, προστατεύει τα XML feeds με token και βάζει προαιρετικά υδατογράφημα. Δεν επηρεάζει φόρμες, καλάθι, ταμείο και μηχανές αναζήτησης.
 * Version:           2.2.1
 * Requires at least: 6.2
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

define( 'PNCP_VERSION', '2.2.1' );
define( 'PNCP_FILE', __FILE__ );
define( 'PNCP_DIR', plugin_dir_path( __FILE__ ) );
define( 'PNCP_URL', plugin_dir_url( __FILE__ ) );
define( 'PNCP_OPTION', 'pncp_settings' );

require_once PNCP_DIR . 'includes/class-pncp-options.php';
require_once PNCP_DIR . 'includes/class-pncp-ip.php';
require_once PNCP_DIR . 'includes/class-pncp-log.php';
require_once PNCP_DIR . 'includes/class-pncp-frontend.php';
require_once PNCP_DIR . 'includes/class-pncp-rest.php';
require_once PNCP_DIR . 'includes/class-pncp-graphql.php';
require_once PNCP_DIR . 'includes/class-pncp-feed.php';
require_once PNCP_DIR . 'includes/class-pncp-bots.php';
require_once PNCP_DIR . 'includes/class-pncp-watermark.php';
require_once PNCP_DIR . 'includes/class-pncp-private-urls.php';
require_once PNCP_DIR . 'includes/class-pncp-rules.php';
require_once PNCP_DIR . 'includes/class-pncp-status.php';

if ( is_admin() ) {
	require_once PNCP_DIR . 'includes/class-pncp-admin.php';
	PNCP_Admin::init();
}

PNCP_Ip::init();
PNCP_Log::init();
PNCP_Frontend::init();
PNCP_Rest::init();
PNCP_Graphql::init();
PNCP_Feed::init();
PNCP_Bots::init();
PNCP_Watermark::init();
PNCP_Private_Urls::init();
PNCP_Status::init();

/**
 * Φορτώνει τις μεταφράσεις.
 */
function pncp_load_textdomain() {
	load_plugin_textdomain( 'content-protect', false, dirname( plugin_basename( PNCP_FILE ) ) . '/languages' );
}
add_action( 'init', 'pncp_load_textdomain' );

/**
 * Ενεργοποίηση: προεπιλογές (χωρίς να πειράζει υπάρχουσες ρυθμίσεις), πίνακας αρχείου, cron.
 *
 * @param bool $network_wide Ενεργοποίηση σε όλο το δίκτυο (multisite).
 */
function pncp_activate( $network_wide = false ) {
	if ( is_multisite() && $network_wide ) {
		foreach ( get_sites(
			array(
				'fields' => 'ids',
				'number' => 0,
			)
		) as $pncp_site_id ) {
			switch_to_blog( $pncp_site_id );
			pncp_upgrade();
			restore_current_blog();
		}
		return;
	}
	pncp_upgrade();
}
register_activation_hook( PNCP_FILE, 'pncp_activate' );
register_deactivation_hook( PNCP_FILE, 'pncp_deactivate' );

/**
 * Απενεργοποίηση: σταματούν τα cron, φεύγει η λίστα bots από το WP Rocket και αδειάζει η cache.
 * Ρυθμίσεις, αρχείο και καθαρά πρωτότυπα μένουν (σβήνονται μόνο στη Διαγραφή του plugin).
 */
function pncp_deactivate() {
	wp_clear_scheduled_hook( PNCP_Ip::CRON );
	wp_clear_scheduled_hook( PNCP_Log::CRON );
	remove_filter( 'rocket_cache_reject_ua', array( 'PNCP_Bots', 'rocket_reject_ua' ) );
	pncp_purge_page_cache();
}

/**
 * Εγκατάσταση και αναβάθμιση. Τρέχει στην ενεργοποίηση και μία φορά μετά από κάθε νέο zip
 * (το activation hook δεν τρέχει όταν αντικαθίσταται το plugin).
 */
function pncp_upgrade() {
	$from   = (string) get_option( 'pncp_version', '' );
	$stored = get_option( PNCP_OPTION );

	if ( ! is_array( $stored ) ) {
		add_option( PNCP_OPTION, PNCP_Options::defaults() );
	} elseif ( '' === $from || version_compare( $from, '2.0.0', '<' ) ) {
		update_option( PNCP_OPTION, pncp_migrate_from_1x( $stored ), true );
	}

	// Έως την 2.2.0 το token της 1.x κρατιόταν σε καθαρή μορφή μέχρι να το δει ο διαχειριστής: σβήνεται.
	if ( false !== get_option( 'pncp_legacy_token_notice', false ) ) {
		delete_option( 'pncp_legacy_token_notice' );
		update_option( 'pncp_legacy_token_migrated', 1, false );
	}

	PNCP_Log::install();
	// Autoload: διαβάζεται σε κάθε αίτημα, χωρίς ξεχωριστό ερώτημα.
	add_option( PNCP_Options::EMERGENCY_OPTION, 0, '', true );
	if ( ! wp_next_scheduled( PNCP_Ip::CRON ) ) {
		wp_schedule_event( time() + 60, 'daily', PNCP_Ip::CRON );
	}
	// Κάθε ώρα (από την 2.2): σβήνει αρχείο, αποκλεισμούς και μετρητές που έληξαν.
	$event = function_exists( 'wp_get_scheduled_event' ) ? wp_get_scheduled_event( PNCP_Log::CRON ) : false;
	if ( $event && 'hourly' !== $event->schedule ) {
		wp_clear_scheduled_hook( PNCP_Log::CRON );
	}
	if ( ! wp_next_scheduled( PNCP_Log::CRON ) ) {
		wp_schedule_event( time() + 5 * MINUTE_IN_SECONDS, 'hourly', PNCP_Log::CRON );
	}
	update_option( 'pncp_version', PNCP_VERSION, false );
	PNCP_Options::flush();
	// Τα plugins cache (π.χ. LiteSpeed) δηλώνουν τα hooks τους αργότερα: καθάρισμα στο init.
	if ( did_action( 'init' ) ) {
		pncp_purge_page_cache();
	} else {
		add_action( 'init', 'pncp_purge_page_cache', 99 );
	}
}

/**
 * Ρυθμίσεις της 1.x προς 2.x.
 *
 * - Τα νέα πεδία παίρνουν την προεπιλογή τους (οι νέες προστασίες ενεργοποιούνται).
 * - Η λίστα bots: αν ήταν η προεπιλεγμένη της 1.4, γίνεται η νέα· αν την είχατε αλλάξει, κρατά τις
 *   αλλαγές σας και προστίθενται μόνο τα νέα bots.
 * - Το token των feeds αποθηκευόταν σε καθαρή μορφή: γίνεται hash και συνεχίζει να ισχύει, αλλά δεν
 *   αποθηκεύεται ούτε εμφανίζεται ξανά. Ο διαχειριστής ενημερώνεται να φτιάξει νέο αν δεν το έχει κρατήσει.
 * - Header πραγματικής IP χωρίς Cloudflare: κρατά τη συμπεριφορά της 1.4 (εμπιστοσύνη σε κάθε proxy)
 *   μέχρι να οριστούν οι proxies, ώστε να μη σπάσει το όριο σελίδων. Με προειδοποίηση.
 *
 * @param array<string, mixed> $old Ρυθμίσεις της 1.x.
 * @return array<string, mixed>
 */
function pncp_migrate_from_1x( $old ) {
	$new = array_merge( PNCP_Options::defaults(), $old );

	$list   = isset( $old['bot_list'] ) ? PNCP_Options::parse_list( (string) $old['bot_list'] ) : array();
	$legacy = array_map( 'strtolower', PNCP_Options::legacy_bot_list() );
	$lower  = array_map( 'strtolower', $list );
	sort( $legacy );
	sort( $lower );
	if ( isset( $old['bot_list'] ) && ! $list ) {
		$new['bot_list'] = ''; // Την είχατε αδειάσει σκόπιμα: μένει άδεια.
	} elseif ( ! $list || $lower === $legacy ) {
		$new['bot_list'] = PNCP_Options::default_bot_list();
	} else {
		foreach ( PNCP_Options::default_bot_entries() as $entry ) {
			if ( ! in_array( strtolower( $entry ), array_map( 'strtolower', $list ), true ) && ! in_array( strtolower( $entry ), $legacy, true ) ) {
				$list[] = $entry;
			}
		}
		$new['bot_list'] = implode( "\n", array_slice( $list, 0, 200 ) );
	}

	if ( ! empty( $old['private_token'] ) ) {
		PNCP_Private_Urls::import_plain( (string) $old['private_token'] );
		// Μόνο σημαία, ποτέ το ίδιο το token: δεν μένει αντίγραφο σε καθαρή μορφή ούτε προσωρινά.
		if ( '' !== trim( (string) ( isset( $old['private_paths'] ) ? $old['private_paths'] : '' ) ) ) {
			update_option( 'pncp_legacy_token_migrated', 1, false );
		}
	}
	unset( $new['private_token'] );

	$header = isset( $old['ip_header'] ) ? (string) $old['ip_header'] : 'remote_addr';
	if ( ! in_array( $header, array( 'remote_addr', 'cf_connecting_ip' ), true ) ) {
		$new['trust_any_proxy'] = 1;
	}

	return $new;
}

/**
 * Μετά από ενημέρωση του plugin (νέο zip ή αυτόματη ενημέρωση) τρέχει η αναβάθμιση μία φορά, στο πρώτο
 * αίτημα, πριν από κάθε έλεγχο: όχι στην πρώτη επίσκεψη διαχειριστή, γιατί μέχρι τότε θα ίσχυαν μισές ρυθμίσεις.
 */
function pncp_maybe_upgrade() {
	if ( get_option( 'pncp_version' ) === PNCP_VERSION ) {
		return;
	}
	// Ένα αίτημα κάνει την αναβάθμιση· τα ταυτόχρονα δεν την ξανατρέχουν (κλείδωμα 60 δευτ., add_option είναι ατομικό).
	$lock = (int) get_option( 'pncp_upgrade_lock', 0 );
	if ( $lock > time() - MINUTE_IN_SECONDS ) {
		return;
	}
	if ( $lock ) {
		delete_option( 'pncp_upgrade_lock' );
	}
	if ( ! add_option( 'pncp_upgrade_lock', time(), '', false ) ) {
		return;
	}
	pncp_upgrade();
	delete_option( 'pncp_upgrade_lock' );
}
add_action( 'plugins_loaded', 'pncp_maybe_upgrade', -100 );

/**
 * Αδειάζει την cache σελίδων, ώστε οι επισκέπτες να δουν αμέσως τις νέες ρυθμίσεις.
 * Καλύπτει WP Rocket, WP Super Cache, W3 Total Cache, LiteSpeed Cache, WP Fastest Cache, SiteGround Optimizer
 * και Nginx Helper (FastCGI cache), όσα υπάρχουν.
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
	// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Hooks άλλων plugins.
	do_action( 'rt_nginx_helper_purge_all' ); // Nginx Helper (FastCGI cache).
	do_action( 'litespeed_purge_all' ); // LiteSpeed Cache.
	// phpcs:enable
	if ( function_exists( 'wp_cache_clear_cache' ) ) {
		wp_cache_clear_cache( is_multisite() ? get_current_blog_id() : 0 ); // WP Super Cache (σε multisite μόνο αυτό το site).
	}
	if ( function_exists( 'w3tc_flush_all' ) ) {
		w3tc_flush_all(); // W3 Total Cache.
	}
	if ( function_exists( 'wpfc_clear_all_cache' ) ) {
		wpfc_clear_all_cache( true ); // WP Fastest Cache.
	}
	if ( function_exists( 'sg_cachepress_purge_cache' ) ) {
		sg_cachepress_purge_cache(); // SiteGround Optimizer.
	}
}
add_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache' );

/**
 * Μετά από αλλαγή ρυθμίσεων ξεχνιούνται οι cache του αιτήματος.
 */
function pncp_settings_changed() {
	PNCP_Options::flush();
	PNCP_Ip::reset();
	PNCP_Watermark::reset();
	// Νέες ρυθμίσεις υδατογραφήματος: το εργαλείο εικόνων ξεκινά από την αρχή.
	delete_option( 'pncp_wm_cursor_apply' );
	delete_option( 'pncp_wm_cursor_remove' );
}
add_action( 'update_option_' . PNCP_OPTION, 'pncp_settings_changed', 0 );
// Οι ρυθμίσεις διαβάζονται πρώτη φορά πριν φορτωθούν οι μεταφράσεις: ξαναδιαβάζονται μετά.
add_action( 'after_setup_theme', array( 'PNCP_Options', 'flush' ), 0 );

/**
 * Το WP Rocket (Delay JS / Defer JS) δεν πρέπει να καθυστερεί την προστασία μέχρι την πρώτη
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
add_filter( 'rocket_exclude_defer_js', 'pncp_rocket_delay_exclusions' );
add_filter( 'rocket_exclude_js', 'pncp_rocket_delay_exclusions' );
