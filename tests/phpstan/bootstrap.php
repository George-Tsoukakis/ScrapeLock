<?php
/**
 * PHPStan only (never loaded by WordPress): the constants WordPress defines at run time (wp-settings.php,
 * default-constants.php) that the WordPress stubs do not declare, the plugin's own constants from
 * scrapelock.php whose value comes from a WordPress function, and the optional SCRAPELOCK_* constants a site
 * may set in wp-config.php (always read behind defined()). Their values here mean nothing: phpstan.neon.dist
 * lists them as dynamic constants.
 *
 * @package ScrapeLock
 */

foreach ( array(
	'WPINC'                 => 'wp-includes',
	'COOKIEPATH'            => '/',
	'COOKIEHASH'            => '',
	'WPMU_PLUGIN_URL'       => '',
	'PNCP_URL'              => '',
	'SCRAPELOCK_BUNNY_KEY'  => '',
	'SCRAPELOCK_EDGE_TOKEN' => '',
) as $pncp_name => $pncp_value ) {
	if ( ! defined( $pncp_name ) ) {
		define( $pncp_name, $pncp_value );
	}
}
