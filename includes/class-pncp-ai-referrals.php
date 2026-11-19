<?php
/**
 * 3.7: visitors that come from AI assistants. When ChatGPT, Perplexity, Claude, Gemini, Copilot and the like cite
 * a page, people click through; this counts those visits per day, platform and page, on this server. It shows
 * whether allowing the AI search bots ("Allow AI search engines and assistants") brings readers, and which pages
 * the assistants recommend.
 *
 * What is counted: a page view by a visitor (not staff, not a refused request) whose Referer is an AI assistant,
 * or whose address carries utm_source=<assistant> (ChatGPT adds utm_source=chatgpt.com to its links). Nothing
 * about the visitor is stored: no IP, no User-Agent, no cookie; one row per day, platform and page, with a count.
 * Pages served by a page cache without reaching WordPress are not counted. Kept for 90 days.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * AI referrals.
 */
final class PNCP_Ai_Referrals {

	/**
	 * Days the counts are kept.
	 */
	const KEEP_DAYS = 90;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		// After page_guard (priority 0) has let the request through, and before the theme prints anything.
		add_action( 'template_redirect', array( __CLASS__, 'count' ), 5 );
	}

	/**
	 * The table.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'pncp_airef';
	}

	/**
	 * Creates the table (PNCP_Log::install() calls it).
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
			day date NOT NULL,
			platform varchar(20) NOT NULL DEFAULT '',
			path varchar(191) NOT NULL DEFAULT '',
			hits int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (day,platform,path),
			KEY platform (platform)
			) {$charset};"
		);
	}

	/**
	 * The assistants: key => [ name, referrer hosts (a host matches itself and its subdomains), utm_source values ].
	 * Filter `pncp_ai_referrers`.
	 *
	 * @return array<string, array{name:string, hosts:string[], utm:string[]}>
	 */
	public static function platforms() {
		return (array) apply_filters(
			'pncp_ai_referrers',
			array(
				'chatgpt'    => array(
					'name'  => 'ChatGPT',
					'hosts' => array( 'chatgpt.com', 'chat.openai.com', 'openai.com' ),
					'utm'   => array( 'chatgpt.com', 'chatgpt', 'openai' ),
				),
				'perplexity' => array(
					'name'  => 'Perplexity',
					'hosts' => array( 'perplexity.ai', 'perplexity.com' ),
					'utm'   => array( 'perplexity', 'perplexity.ai' ),
				),
				'claude'     => array(
					'name'  => 'Claude',
					'hosts' => array( 'claude.ai', 'claude.com' ),
					'utm'   => array( 'claude.ai', 'claude' ),
				),
				'gemini'     => array(
					'name'  => 'Gemini',
					'hosts' => array( 'gemini.google.com', 'bard.google.com', 'notebooklm.google.com' ),
					'utm'   => array( 'gemini', 'bard' ),
				),
				'copilot'    => array(
					'name'  => 'Microsoft Copilot',
					'hosts' => array( 'copilot.microsoft.com', 'copilot.cloud.microsoft' ),
					'utm'   => array( 'copilot', 'copilot.com' ),
				),
				'deepseek'   => array(
					'name'  => 'DeepSeek',
					'hosts' => array( 'chat.deepseek.com', 'deepseek.com' ),
					'utm'   => array( 'deepseek' ),
				),
				'grok'       => array(
					'name'  => 'Grok',
					'hosts' => array( 'grok.com', 'x.ai' ),
					'utm'   => array( 'grok', 'grok.com' ),
				),
				'mistral'    => array(
					'name'  => 'Mistral Le Chat',
					'hosts' => array( 'chat.mistral.ai' ),
					'utm'   => array( 'mistral', 'chat.mistral.ai' ),
				),
				'meta'       => array(
					'name'  => 'Meta AI',
					'hosts' => array( 'meta.ai' ),
					'utm'   => array( 'meta.ai' ),
				),
				'you'        => array(
					'name'  => 'You.com',
					'hosts' => array( 'you.com' ),
					'utm'   => array( 'you.com' ),
				),
				'phind'      => array(
					'name'  => 'Phind',
					'hosts' => array( 'phind.com' ),
					'utm'   => array( 'phind' ),
				),
				'kagi'       => array(
					'name'  => 'Kagi Assistant',
					'hosts' => array( 'kagi.com' ),
					'utm'   => array(),
				),
			)
		);
	}

	/**
	 * Which assistant a Referer and a utm_source point to ('' = none).
	 *
	 * @param string $referer Referer.
	 * @param string $utm     utm_source.
	 * @return string Key of platforms().
	 */
	public static function platform_of( $referer, $utm = '' ) {
		$host = strtolower( (string) wp_parse_url( (string) $referer, PHP_URL_HOST ) );
		$utm  = strtolower( trim( (string) $utm ) );
		foreach ( self::platforms() as $key => $platform ) {
			if ( '' !== $host ) {
				foreach ( (array) $platform['hosts'] as $candidate ) {
					$candidate = strtolower( (string) $candidate );
					if ( $host === $candidate || substr( $host, -strlen( '.' . $candidate ) ) === '.' . $candidate ) {
						return (string) $key;
					}
				}
			}
			if ( '' !== $utm && in_array( $utm, array_map( 'strtolower', (array) $platform['utm'] ), true ) ) {
				return (string) $key;
			}
		}
		return '';
	}

	/**
	 * Counts this page view if it comes from an assistant.
	 */
	public static function count() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['ai_referrals'] ) || is_admin() || wp_doing_ajax() || is_feed() || is_robots() || is_404() || is_preview() || PNCP_Bots::is_prefetch() ) {
			return;
		}
		if ( PNCP_Options::user_is_exempt( $s ) ) {
			return; // Staff checking a link from ChatGPT are not readers.
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'GET' !== $method ) {
			return;
		}
		$referer = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
		$utm     = isset( $_GET['utm_source'] ) ? sanitize_text_field( wp_unslash( $_GET['utm_source'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read only, for counting.
		if ( '' === $referer && '' === $utm ) {
			return;
		}
		$platform = self::platform_of( $referer, $utm );
		if ( '' === $platform ) {
			return;
		}
		self::add( $platform, self::page_path() );
	}

	/**
	 * The page, without the query string (utm_ and other tracking parameters would make one page many), relative
	 * to the site, percent-encoded as the log keeps it.
	 *
	 * @return string
	 */
	private static function page_path() {
		// A post, page or product: its permalink, so the same article is one row whatever address led to it (and
		// with plain permalinks, "/?p=123", the query is what tells articles apart).
		if ( is_singular() ) {
			$link = get_permalink( get_queried_object_id() );
			if ( is_string( $link ) && '' !== $link ) {
				$path  = (string) wp_parse_url( $link, PHP_URL_PATH );
				$query = (string) wp_parse_url( $link, PHP_URL_QUERY );
				$base  = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
				if ( '' !== $base && '/' !== $base && 0 === strpos( $path, rtrim( $base, '/' ) ) ) {
					$path = substr( $path, strlen( rtrim( $base, '/' ) ) );
				}
				$path = ( '' === $path ? '/' : $path ) . ( '' !== $query ? '?' . $query : '' );
				return substr( $path, 0, 191 ); // Percent-encoded, like the log; shown with PNCP_Log::display_path().
			}
		}
		$uri  = PNCP_Log::request_uri();
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$base = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		if ( '' !== $base && '/' !== $base && 0 === strpos( $path, rtrim( $base, '/' ) ) ) {
			$path = substr( $path, strlen( rtrim( $base, '/' ) ) );
		}
		$path = '' === $path ? '/' : $path;
		return substr( $path, 0, 191 );
	}

	/**
	 * Adds one visit, atomically.
	 *
	 * @param string $platform Platform key.
	 * @param string $path     Page.
	 */
	public static function add( $platform, $path ) {
		global $wpdb;
		if ( ! PNCP_Log::ready() ) {
			return;
		}
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, one atomic counter.
		$wpdb->query( $wpdb->prepare( 'INSERT INTO %i (day, platform, path, hits) VALUES (%s, %s, %s, 1) ON DUPLICATE KEY UPDATE hits = hits + 1', self::table(), wp_date( 'Y-m-d' ), substr( (string) $platform, 0, 20 ), (string) $path ) );
		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * Visits per platform in the last N days, most first.
	 *
	 * @param int $days Days.
	 * @return array<string, int> Platform key => visits.
	 */
	public static function totals( $days = 30 ) {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, small aggregate.
		$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT platform, SUM(hits) AS visits FROM %i WHERE day >= %s GROUP BY platform ORDER BY visits DESC', self::table(), self::since( $days ) ), ARRAY_A );
		$wpdb->suppress_errors( $suppress );
		$out = array();
		foreach ( $rows as $row ) {
			$out[ (string) $row['platform'] ] = (int) $row['visits'];
		}
		return $out;
	}

	/**
	 * The pages most visited from assistants in the last N days.
	 *
	 * @param int $days  Days.
	 * @param int $limit Rows.
	 * @return array<int, array{path:string, visits:int, platforms:string}>
	 */
	public static function top_pages( $days = 30, $limit = 10 ) {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, small aggregate.
		$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT path, SUM(hits) AS visits, GROUP_CONCAT(DISTINCT platform ORDER BY platform) AS platforms FROM %i WHERE day >= %s GROUP BY path ORDER BY visits DESC LIMIT %d', self::table(), self::since( $days ), max( 1, (int) $limit ) ), ARRAY_A );
		$wpdb->suppress_errors( $suppress );
		$out = array();
		foreach ( $rows as $row ) {
			$out[] = array(
				'path'      => (string) $row['path'],
				'visits'    => (int) $row['visits'],
				'platforms' => (string) $row['platforms'],
			);
		}
		return $out;
	}

	/**
	 * Visits per day in the last N days (every day present, 0 where none).
	 *
	 * @param int $days Days.
	 * @return array<string, int> Y-m-d => visits.
	 */
	public static function per_day( $days = 30 ) {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table, small aggregate.
		$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT day, SUM(hits) AS visits FROM %i WHERE day >= %s GROUP BY day', self::table(), self::since( $days ) ), ARRAY_A );
		$wpdb->suppress_errors( $suppress );
		$out   = array();
		$today = (int) strtotime( wp_date( 'Y-m-d' ) . ' 00:00:00 UTC' );
		for ( $i = max( 1, (int) $days ) - 1; $i >= 0; $i-- ) {
			$out[ gmdate( 'Y-m-d', $today - $i * DAY_IN_SECONDS ) ] = 0;
		}
		foreach ( $rows as $row ) {
			if ( isset( $out[ (string) $row['day'] ] ) ) {
				$out[ (string) $row['day'] ] = (int) $row['visits'];
			}
		}
		return $out;
	}

	/**
	 * The first day of the last N days, in the site's time zone.
	 *
	 * @param int $days Days.
	 * @return string Y-m-d.
	 */
	private static function since( $days ) {
		return wp_date( 'Y-m-d', time() - ( max( 1, (int) $days ) - 1 ) * DAY_IN_SECONDS );
	}

	/**
	 * Deletes counts older than KEEP_DAYS (hourly, with the log cleanup).
	 */
	public static function cleanup() {
		global $wpdb;
		if ( ! PNCP_Log::ready() ) {
			return;
		}
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE day < %s', self::table(), self::since( self::KEEP_DAYS ) ) );
		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * Deletes every count ("Clear" on the Log tab).
	 */
	public static function clear() {
		global $wpdb;
		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::table() ) );
		$wpdb->suppress_errors( $suppress );
	}
}
