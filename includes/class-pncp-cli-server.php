<?php
/**
 * 3.12.6: WP-CLI for the server: "wp scrapelock cdn purge" (PNCP_Cli::cdn()).
 *
 * Only from WP-CLI. The stored credentials (Bunny API key, Cloudflare token) are used, never printed.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Server and CDN commands.
 */
final class PNCP_Cli_Server {

	/**
	 * Stops unless this runs in WP-CLI (never in a web request).
	 */
	private static function cli_only() {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI || 'cli' !== PHP_SAPI ) {
			wp_die( esc_html__( 'Only from WP-CLI.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
	}

	/* ---------- wp scrapelock cdn ---------- */

	/**
	 * Wp scrapelock cdn purge <url>... | --all [--yes].
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cdn( $args, $assoc_args ) {
		self::cli_only();
		$action = isset( $args[0] ) ? (string) $args[0] : '';
		if ( 'purge' !== $action ) {
			WP_CLI::error( __( 'Unknown action. Use: purge.', 'scrapelock' ) );
		}
		$urls = array_slice( $args, 1 );
		$all  = ! empty( $assoc_args['all'] );
		if ( $all && $urls ) {
			WP_CLI::error( __( 'Give addresses or --all, not both.', 'scrapelock' ) );
		}
		if ( ! $all && ! $urls ) {
			WP_CLI::error( __( 'Give the addresses to purge, or --all.', 'scrapelock' ) );
		}
		if ( null === PNCP_Bunny::credentials() && ! PNCP_Edge::cloudflare_connected() ) {
			WP_CLI::error( __( 'No CDN connection is set (Bunny CDN or Cloudflare under "Blocking at the CDN", or the Bunny card).', 'scrapelock' ) );
		}
		if ( $all && empty( $assoc_args['yes'] ) ) {
			WP_CLI::confirm( __( 'Purge the whole CDN cache of this site?', 'scrapelock' ) );
		}
		$result = PNCP_Edge::cdn_purge( $urls, $all );
		if ( $result['refused'] ) {
			/* translators: %s: addresses */
			WP_CLI::error( sprintf( __( 'Not an address of this site (nothing was purged): %s', 'scrapelock' ), implode( ', ', $result['refused'] ) ) );
		}
		$failed = 0;
		foreach ( $result['rows'] as $provider => $row ) {
			if ( 'ok' === $row['status'] ) {
				if ( $all ) {
					/* translators: %s: CDN name */
					WP_CLI::success( sprintf( __( '%s: the whole cache was purged.', 'scrapelock' ), $provider ) );
				} else {
					/* translators: 1: CDN name, 2: number of addresses */
					WP_CLI::success( sprintf( _n( '%1$s: %2$d address purged.', '%1$s: %2$d addresses purged.', $row['done'], 'scrapelock' ), $provider, $row['done'] ) );
				}
				continue;
			}
			++$failed;
			/* translators: 1: CDN name, 2: number of addresses purged before the error, 3: error message */
			WP_CLI::warning( sprintf( __( '%1$s: not purged (%2$d done before the error): %3$s', 'scrapelock' ), $provider, $row['done'], $row['message'] ) );
		}
		if ( $failed ) {
			WP_CLI::halt( 1 );
		}
	}
}
