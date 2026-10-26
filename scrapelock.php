<?php
/**
 * Plugin Name:       ScrapeLock – Content & AI Bot Protection
 * Description:       Protects your content: makes copying text and images harder, hides the text in the REST API, GraphQL and RSS, blocks scrapers, AI bots and fake Googlebots, temporarily blocks persistent IPs, protects XML feeds with a token and adds an optional watermark. Lockdown freezes every change to the site until it is unlocked with an authenticator app. Forms, cart, checkout and search engines are not affected.
 * Version:           3.3.1
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            CodeBunny
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       scrapelock
 * Domain Path:       /languages
 */

defined( 'ABSPATH' ) || exit;

// If another copy is already loaded (e.g. the old version in another folder), do not load again.
if ( defined( 'PNCP_VERSION' ) ) {
	return;
}

define( 'PNCP_VERSION', '3.3.1' );
define( 'PNCP_FILE', __FILE__ );
define( 'PNCP_DIR', plugin_dir_path( __FILE__ ) );
define( 'PNCP_URL', plugin_dir_url( __FILE__ ) );
defined( 'PNCP_OPTION' ) || define( 'PNCP_OPTION', 'pncp_settings' ); // Also defined by the early check (mu-plugin).

require_once PNCP_DIR . 'includes/class-pncp-options.php';
require_once PNCP_DIR . 'includes/class-pncp-ip.php';
require_once PNCP_DIR . 'includes/class-pncp-log.php';
require_once PNCP_DIR . 'includes/class-pncp-frontend.php';
require_once PNCP_DIR . 'includes/class-pncp-rest.php';
require_once PNCP_DIR . 'includes/class-pncp-graphql.php';
require_once PNCP_DIR . 'includes/class-pncp-feed.php';
require_once PNCP_DIR . 'includes/class-pncp-bots.php';
require_once PNCP_DIR . 'includes/class-pncp-surge.php';
require_once PNCP_DIR . 'includes/class-pncp-edge.php';
require_once PNCP_DIR . 'includes/class-pncp-origin.php';
require_once PNCP_DIR . 'includes/class-pncp-watermark.php';
require_once PNCP_DIR . 'includes/class-pncp-private-urls.php';
require_once PNCP_DIR . 'includes/class-pncp-rules.php';
require_once PNCP_DIR . 'includes/class-pncp-status.php';
require_once PNCP_DIR . 'includes/class-pncp-early.php';
require_once PNCP_DIR . 'includes/class-pncp-human.php';
require_once PNCP_DIR . 'includes/class-pncp-geo.php';
require_once PNCP_DIR . 'includes/class-pncp-precheck.php';
require_once PNCP_DIR . 'includes/class-pncp-totp.php';
require_once PNCP_DIR . 'includes/class-pncp-lockdown.php';
require_once PNCP_DIR . 'includes/class-pncp-seal.php';
require_once PNCP_DIR . 'includes/class-pncp-integrity.php';
require_once PNCP_DIR . 'includes/class-pncp-surface.php';
require_once PNCP_DIR . 'includes/class-pncp-health.php';
require_once PNCP_DIR . 'includes/class-pncp-abilities.php';

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
PNCP_Edge::init();
PNCP_Origin::init();
PNCP_Watermark::init();
PNCP_Private_Urls::init();
PNCP_Status::init();
PNCP_Human::init();
PNCP_Geo::init();
PNCP_Precheck::init();
PNCP_Lockdown::init();
PNCP_Seal::init();
PNCP_Integrity::init();
PNCP_Surface::init();
PNCP_Health::init();
PNCP_Abilities::init();

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once PNCP_DIR . 'includes/class-pncp-cli.php';
	PNCP_Cli::init();
}

/**
 * Activation: defaults (without touching existing settings), log table, cron.
 *
 * @param bool $network_wide Activation across the whole network (multisite).
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
 * Deactivation: cron jobs stop, the bot list is removed from WP Rocket and the cache is cleared.
 * Settings, log and clean originals remain (they are removed only when the plugin is deleted).
 */
function pncp_deactivate() {
	wp_clear_scheduled_hook( PNCP_Ip::CRON );
	wp_clear_scheduled_hook( PNCP_Log::CRON );
	// The blocks ScrapeLock made at the CDN go away with it (the bans themselves end with the plugin).
	PNCP_Edge::remove_all();
	// The Lockdown guard keeps ScrapeLock active while locked: it goes when the plugin is deactivated.
	PNCP_Seal::remove_guard();
	remove_filter( 'rocket_cache_reject_ua', array( 'PNCP_Bots', 'rocket_reject_ua' ) );
	// The early check goes away with the plugin. On multisite the file is shared: it stays, and does nothing
	// on sites where ScrapeLock is not active.
	if ( ! is_multisite() ) {
		PNCP_Early::remove();
	}
	// The pre-cache check: its line in wp-config.php and its files go away with the plugin.
	PNCP_Precheck::remove();
	PNCP_Rules::sync_uploads_htaccess( false );
	pncp_purge_page_cache();
}

/**
 * Installation and upgrade. Runs on activation and once after every new zip
 * (the activation hook does not run when the plugin is replaced).
 */
function pncp_upgrade() {
	$from   = (string) get_option( 'pncp_version', '' );
	$stored = get_option( PNCP_OPTION );

	if ( ! is_array( $stored ) ) {
		add_option( PNCP_OPTION, PNCP_Options::defaults() );
	} elseif ( '' === $from || version_compare( $from, '2.0.0', '<' ) ) {
		update_option( PNCP_OPTION, pncp_migrate_from_1x( $stored ), true );
	} else {
		// 2.4 and later: the new protections stay off on existing sites (the defaults are for new installs).
		$added = array();
		if ( version_compare( $from, '2.4.0', '<' ) ) {
			$added += PNCP_Options::new_in_240();
		}
		if ( version_compare( $from, '2.5.0', '<' ) ) {
			$added += PNCP_Options::new_in_250();
		}
		if ( version_compare( $from, '2.6.0', '<' ) ) {
			$added += PNCP_Options::new_in_260();
		}
		if ( version_compare( $from, '2.9.0', '<' ) ) {
			$added += PNCP_Options::new_in_290();
		}
		if ( version_compare( $from, '3.0.0', '<' ) ) {
			$added += PNCP_Options::new_in_300();
		}
		$added = array_diff_key( $added, $stored );
		// 2.8.3: the HTTP libraries that passed the bot list are added to it. Your own entries stay; a list
		// emptied on purpose stays empty.
		if ( version_compare( $from, '2.8.3', '<' ) && isset( $stored['bot_list'] ) ) {
			$list = PNCP_Options::parse_list( (string) $stored['bot_list'] );
			if ( $list ) {
				$lower = array_map( 'strtolower', $list );
				foreach ( PNCP_Options::new_bots_in_283() as $entry ) {
					if ( ! in_array( strtolower( $entry ), $lower, true ) ) {
						$list[] = $entry;
					}
				}
				$added['bot_list'] = implode( "\n", array_slice( $list, 0, 200 ) );
			}
		}
		if ( $added ) {
			update_option( PNCP_OPTION, array_merge( $stored, $added ), true );
		}
	}

	// Up to 2.2.0 the 1.x token was kept in plain form until the admin saw it: it is deleted.
	if ( false !== get_option( 'pncp_legacy_token_notice', false ) ) {
		delete_option( 'pncp_legacy_token_notice' );
		update_option( 'pncp_legacy_token_migrated', 1, false );
	}

	PNCP_Log::install();
	// Autoload: read on every request, without a separate query.
	add_option( PNCP_Options::EMERGENCY_OPTION, 0, '', true );
	if ( ! wp_next_scheduled( PNCP_Ip::CRON ) ) {
		wp_schedule_event( time() + 60, 'daily', PNCP_Ip::CRON );
	}
	// Hourly (since 2.2): deletes expired log entries, blocks and counters.
	$event = function_exists( 'wp_get_scheduled_event' ) ? wp_get_scheduled_event( PNCP_Log::CRON ) : false;
	if ( $event && 'hourly' !== $event->schedule ) {
		wp_clear_scheduled_hook( PNCP_Log::CRON );
	}
	if ( ! wp_next_scheduled( PNCP_Log::CRON ) ) {
		wp_schedule_event( time() + 5 * MINUTE_IN_SECONDS, 'hourly', PNCP_Log::CRON );
	}
	// 3.3: Lockdown data stored before signatures existed is signed now (while pncp_version still says older).
	if ( '' !== $from && version_compare( $from, '3.3.0', '<' ) ) {
		PNCP_Lockdown::upgrade_seal();
	}
	update_option( 'pncp_version', PNCP_VERSION, true ); // Autoloaded: read on every request by pncp_maybe_upgrade().
	PNCP_Options::flush();
	// The early check (mu-plugin): written again if the plugin folder changed, removed if it is off.
	PNCP_Early::sync();
	// The pre-cache check: the loader is written again (new version, new plugin folder) or removed.
	PNCP_Precheck::sync();
	PNCP_Rules::sync_uploads_htaccess();
	// A list that is new in this version (e.g. Anthropic in 2.6.2) is downloaded now, not with the daily refresh.
	PNCP_Ip::forget_missing_try();
	PNCP_Ip::fetch_missing();
	// Cache plugins (e.g. LiteSpeed, WP Rocket) finish loading later: before init the purge waits for init.
	pncp_purge_page_cache();
}

/**
 * Settings from 1.x to 2.x.
 *
 * - New fields get their defaults (the new protections are enabled).
 * - The bot list: if it was the 1.4 default, it becomes the new one; if you had changed it, your
 *   changes are kept and only the new bots are added.
 * - The feeds token was stored in plain form: it is hashed and stays valid, but it is not
 *   stored or shown again. The admin is told to create a new one if they have not kept it.
 * - Real-IP header without Cloudflare: keeps the 1.4 behaviour (trust every proxy)
 *   until the proxies are set, so the page limit does not break. With a warning.
 *
 * @param array<string, mixed> $old Settings of 1.x.
 * @return array<string, mixed>
 */
function pncp_migrate_from_1x( $old ) {
	// The 2.4, 2.5, 2.6, 2.9 and 3.0 additions stay off, as on every existing site.
	$new = array_merge( PNCP_Options::defaults(), PNCP_Options::new_in_240(), PNCP_Options::new_in_250(), PNCP_Options::new_in_260(), PNCP_Options::new_in_290(), PNCP_Options::new_in_300(), $old );

	$list   = isset( $old['bot_list'] ) ? PNCP_Options::parse_list( (string) $old['bot_list'] ) : array();
	$legacy = array_map( 'strtolower', PNCP_Options::legacy_bot_list() );
	$lower  = array_map( 'strtolower', $list );
	sort( $legacy );
	sort( $lower );
	if ( isset( $old['bot_list'] ) && ! $list ) {
		$new['bot_list'] = ''; // You had emptied it on purpose: it stays empty.
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
		// Only a flag, never the token itself: no plain copy is kept, not even temporarily.
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
 * After a plugin update (new zip or auto-update) the upgrade runs once, on the first
 * request, before any check: not on the first admin visit, because until then half the settings would apply.
 */
function pncp_maybe_upgrade() {
	if ( get_option( 'pncp_version' ) === PNCP_VERSION ) {
		return;
	}
	// One request runs the upgrade; concurrent ones do not rerun it (60 s lock, add_option is atomic).
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
 * Clears the page cache so visitors see the new settings immediately.
 * Covers WP Rocket, WP Super Cache, W3 Total Cache, LiteSpeed Cache, WP Fastest Cache, SiteGround Optimizer,
 * Nginx Helper (FastCGI cache) and the Cloudflare plugin, whichever are present.
 */
function pncp_purge_page_cache() {
	// Before init (the upgrade runs on plugins_loaded) the cache plugins have not finished loading: WP Rocket
	// crashed when asked to rebuild its config that early. The purge then runs once, on init.
	if ( ! did_action( 'init' ) ) {
		if ( ! has_action( 'init', 'pncp_purge_page_cache' ) ) {
			add_action( 'init', 'pncp_purge_page_cache', 99 );
		}
		return;
	}
	// WP Rocket rewrites its config so the bot list takes effect (rocket_cache_reject_ua).
	if ( function_exists( 'rocket_generate_config_file' ) ) {
		rocket_generate_config_file();
	}
	if ( function_exists( 'flush_rocket_htaccess' ) ) {
		flush_rocket_htaccess();
	}
	if ( function_exists( 'rocket_clean_domain' ) ) {
		rocket_clean_domain();
	}
	// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Hooks of other plugins.
	do_action( 'rt_nginx_helper_purge_all' ); // Nginx Helper (FastCGI cache).
	do_action( 'litespeed_purge_all' ); // LiteSpeed Cache.
	// phpcs:enable
	if ( function_exists( 'wp_cache_clear_cache' ) ) {
		wp_cache_clear_cache( is_multisite() ? get_current_blog_id() : 0 ); // WP Super Cache (on multisite, only this site).
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
	// Cloudflare plugin: purges the edge cache when its APO or HTML caching is on (otherwise it does nothing).
	if ( isset( $GLOBALS['cloudflareHooks'] ) && is_object( $GLOBALS['cloudflareHooks'] ) && method_exists( $GLOBALS['cloudflareHooks'], 'purgeCacheEverything' ) ) {
		try {
			$GLOBALS['cloudflareHooks']->purgeCacheEverything();
		} catch ( Throwable $e ) {
			unset( $e ); // A Cloudflare API error must not break saving the settings.
		}
	}
}
add_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache' );

/**
 * After a settings change the per-request caches are forgotten.
 */
function pncp_settings_changed() {
	PNCP_Options::flush();
	PNCP_Ip::reset();
	PNCP_Watermark::reset();
	// New watermark settings: the image tool starts over.
	delete_option( 'pncp_wm_cursor_apply' );
	delete_option( 'pncp_wm_cursor_remove' );
}
add_action( 'update_option_' . PNCP_OPTION, 'pncp_settings_changed', 0 );
add_action( 'update_option_' . PNCP_OPTION, array( 'PNCP_Early', 'sync' ) );
add_action( 'update_option_' . PNCP_OPTION, array( 'PNCP_Precheck', 'sync' ) );
add_action( 'update_option_' . PNCP_OPTION, array( 'PNCP_Rules', 'settings_saved' ) );
// Settings are first read before the translations load: they are read again afterwards.
add_action( 'after_setup_theme', array( 'PNCP_Options', 'flush' ), 0 );

/**
 * WP Rocket (Delay JS / Defer JS) must not delay the protection until the visitor's first
 * interaction, otherwise the first right-click gets through.
 *
 * @param string[] $exclusions Patterns to exclude.
 * @return string[]
 */
function pncp_rocket_delay_exclusions( $exclusions ) {
	$exclusions   = (array) $exclusions;
	$exclusions[] = dirname( plugin_basename( PNCP_FILE ) ) . '/assets/js/protect.js';
	$exclusions[] = 'pncpConfig';
	return $exclusions;
}
add_filter( 'rocket_delay_js_exclusions', 'pncp_rocket_delay_exclusions' );
add_filter( 'rocket_exclude_defer_js', 'pncp_rocket_delay_exclusions' );
add_filter( 'rocket_exclude_js', 'pncp_rocket_delay_exclusions' );
