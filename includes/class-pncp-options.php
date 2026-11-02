<?php
/**
 * Settings: defaults, reading, input sanitizing, profiles and Emergency Mode.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Central point for the `pncp_settings` option.
 *
 * - stored():    whatever is stored, filled in with defaults (for the settings page).
 * - get():       the settings in effect now: stored() + stricter values while Emergency Mode runs.
 */
final class PNCP_Options {

	/**
	 * Option holding the Emergency Mode expiry (timestamp, 0 = inactive).
	 */
	const EMERGENCY_OPTION = 'pncp_emergency_until';

	/**
	 * How many days a new install starts in "Monitor only" before it starts blocking on its own.
	 */
	const MONITOR_DAYS = 7;

	/**
	 * Option that remembers the end of the first-week monitoring: "pending" until the administrator has been
	 * told that blocking started, then "shown", so they are told once.
	 */
	const MONITOR_ENDED_OPTION = 'pncp_monitor_ended';

	/**
	 * Cache of get() for the current request.
	 *
	 * @var array<string, mixed>|null
	 */
	private static $cache = null;

	/**
	 * Allowed values for the choice fields.
	 *
	 * @return array<string, string[]>
	 */
	public static function choices() {
		return array(
			'copy_mode'           => array( 'block', 'attribution', 'allow' ),
			'print_mode'          => array( 'allow', 'source', 'block' ),
			'exempt_cap'          => array( 'manage_options', 'edit_others_posts', 'edit_posts', 'none' ),
			'feed_mode'           => array( 'full', 'excerpt', 'disabled' ),
			'ip_header'           => array( 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip', 'true_client_ip' ),
			'watermark_position'  => array( 'br', 'bl', 'tr', 'tl', 'center', 'tiled' ),
			'log_retention'       => array( '1', '7', '30' ),
			// What the automatic Emergency Mode does when the site is hit far harder than usual: tell the
			// administrator (email + notice with a "Start Emergency Mode" button), or start it on its own.
			'auto_emergency_mode' => array( 'notify', 'start' ),
		);
	}

	/**
	 * The boolean fields.
	 *
	 * @return string[]
	 */
	public static function bool_keys() {
		return array(
			'enabled',
			'scope_posts',
			'scope_pages',
			'scope_home',
			'scope_products',
			'block_selection',
			'block_context_menu',
			'block_shortcuts',
			'block_devtools',
			'block_image_drag',
			'block_text_drag',
			'blur_on_capture',
			'show_message',
			'skip_woo_pages',
			'rest_hide_content',
			'graphql_hide_content',
			'block_bots',
			'block_empty_ua',
			'block_fake_crawlers',
			'require_browser_headers',
			'trap_enabled',
			'robots_ai_block',
			'allow_ai_search',
			'block_framing',
			'tdm_reservation',
			'trust_cloudflare',
			'trust_any_proxy',
			'watermark_enabled',
			'watermark_full',
			'watermark_products',
			'block_user_enum',
			'early_mode',
			'feed_source_link',
			'content_signal',
			'verify_ai_bots',
			'block_headless',
			'human_check',
			'geo_db',
			'trust_bunny',
			'precheck',
			'disable_pingback',
			'hide_rest_discovery',
			'hide_versions',
			'list_excerpts',
			'ipv6_wide',
			'block_archivers',
			'block_upload_php',
			'auto_emergency',
			'cdn_only',
			'block_http_libs',
			'monitor_mode',
		);
	}

	/**
	 * Integer fields: key => [minimum, maximum].
	 *
	 * @return array<string, int[]>
	 */
	public static function int_ranges() {
		return array(
			'attribution_min_chars' => array( 0, 10000 ),
			'rate_limit'            => array( 0, 10000 ),
			'rate_limit_search'     => array( 0, 10000 ),
			'rate_limit_rest'       => array( 0, 10000 ),
			'rate_limit_404'        => array( 0, 10000 ),
			'rate_limit_unverified' => array( 0, 10000 ),
			'rate_limit_sitemap'    => array( 0, 10000 ),
			'rate_limit_country'    => array( 0, 10000 ),
			'auto_emergency_min'    => array( 10, 1000000 ),
			'rate_limit_datacenter' => array( 0, 10000 ),
			'ban_strikes'           => array( 0, 20 ),
			'ban_minutes'           => array( 1, 10080 ),
			'watermark_image_id'    => array( 0, PHP_INT_MAX ),
			'watermark_opacity'     => array( 10, 100 ),
			'watermark_size'        => array( 5, 60 ),
			'watermark_min_width'   => array( 0, 5000 ),
		);
	}

	/**
	 * List fields (one value per line).
	 *
	 * @return string[]
	 */
	public static function list_keys() {
		return array( 'bot_list', 'allow_list', 'private_paths', 'block_referrers', 'content_paths' );
	}

	/**
	 * IP / CIDR fields (one per line).
	 *
	 * @return string[]
	 */
	public static function ip_list_keys() {
		return array( 'private_ips', 'allow_ips', 'trusted_proxies', 'block_ips' );
	}

	/**
	 * Which settings page tab each field belongs to. Each tab saves only its own
	 * fields; the rest keep their value.
	 *
	 * @return array<string, string[]>
	 */
	public static function sections() {
		return array(
			'general' => array( 'enabled', 'scope_posts', 'scope_pages', 'scope_home', 'scope_products', 'skip_woo_pages', 'excluded_ids', 'block_selection', 'block_context_menu', 'block_shortcuts', 'block_devtools', 'block_image_drag', 'block_text_drag', 'blur_on_capture', 'copy_mode', 'attribution_min_chars', 'print_mode', 'exempt_cap', 'show_message', 'message', 'block_framing', 'tdm_reservation', 'tdm_policy_url' ),
			'bots'    => array( 'monitor_mode', 'block_bots', 'block_empty_ua', 'block_fake_crawlers', 'require_browser_headers', 'block_headless', 'trap_enabled', 'block_http_libs', 'block_archivers', 'ipv6_wide', 'bot_list', 'allow_list', 'allow_ips', 'allow_ai_search', 'verify_ai_bots', 'robots_ai_block', 'content_signal', 'block_ips', 'block_referrers', 'block_user_enum', 'rate_limit', 'rate_limit_search', 'rate_limit_rest', 'rate_limit_404', 'rate_limit_sitemap', 'human_check', 'rate_limit_unverified', 'geo_db', 'countries_block', 'countries_strict', 'rate_limit_country', 'rate_limit_datacenter', 'ban_strikes', 'ban_minutes', 'auto_emergency', 'auto_emergency_mode', 'auto_emergency_min', 'early_mode', 'precheck', 'ip_header', 'trust_cloudflare', 'trust_bunny', 'trust_any_proxy', 'trusted_proxies', 'cdn_secret', 'cdn_only' ),
			'content' => array( 'rest_hide_content', 'hide_rest_discovery', 'graphql_hide_content', 'feed_mode', 'feed_source_link', 'list_excerpts', 'private_paths', 'private_ips', 'disable_pingback', 'hide_versions', 'block_upload_php' ),
			'images'  => array( 'watermark_enabled', 'watermark_full', 'watermark_products', 'watermark_image_id', 'watermark_opacity', 'watermark_size', 'watermark_position', 'watermark_min_width' ),
			// Log tab: how long the log is kept, and the addresses that count as "Pages" in it (until 3.3 on the
			// Bots and limits tab, same keys).
			'log'     => array( 'log_retention', 'content_paths' ),
		);
	}

	/**
	 * The 1.4 list (so the upgrade knows whether the user had changed it).
	 *
	 * @return string[]
	 */
	public static function legacy_bot_list() {
		return array( 'GPTBot', 'ChatGPT-User', 'CCBot', 'ClaudeBot', 'Claude-Web', 'anthropic-ai', 'PerplexityBot', 'Bytespider', 'meta-externalagent', 'Diffbot', 'ImagesiftBot', 'Scrapy', 'HTTrack', 'curl/', 'Wget/', 'python-requests', 'python-urllib', 'aiohttp', 'Go-http-client' );
	}

	/**
	 * The User-Agents blocked by default (substring, case-insensitive): AI crawlers and named scraping tools.
	 * Never contains search engines, social network previews or price comparison platforms.
	 *
	 * Since 3.4 it no longer contains the generic HTTP libraries (curl, okhttp, Dart, python-requests etc.):
	 * WooCommerce mobile apps, headless front ends, ERP price sync and uptime monitors use the same ones, so
	 * blocking them by default broke real sites. They are blocked only with "Also block generic HTTP libraries"
	 * (block_http_libs, see http_library_agents()). Existing sites keep the list they have.
	 *
	 * @return string[]
	 */
	public static function default_bot_entries() {
		$libraries = array_map( 'strtolower', self::http_library_agents() );
		$entries   = array();
		foreach ( self::legacy_bot_list() as $entry ) {
			if ( ! in_array( strtolower( $entry ), $libraries, true ) ) {
				$entries[] = $entry;
			}
		}
		return array_merge(
			$entries,
			array(
				// AI crawlers and agents.
				'OAI-SearchBot',
				'Claude-User',
				'Claude-SearchBot',
				'Perplexity-User',
				'Google-CloudVertexBot',
				'Applebot-Extended',
				'meta-externalfetcher',
				'FacebookBot',
				'Amazonbot',
				'cohere-ai',
				'cohere-training-data-crawler',
				'AI2Bot',
				'Ai2Bot-Dolma',
				'YouBot',
				'DuckAssistBot',
				'MistralAI-User',
				'PanguBot',
				'Timpibot',
				'omgili',
				'Webzio-Extended',
				'Kangaroo Bot',
				'Sidetrade indexer bot',
				'VelenPublicWebCrawler',
				'ICC-Crawler',
				'img2dataset',
				'Brightbot',
				'TikTokSpider',
				'iaskspider',
				'QualifiedBot',
				// Scraping tools and headless browsers: made for copying sites, not for talking to an API.
				'HeadlessChrome',
				'PhantomJS',
				'Puppeteer',
				'Playwright',
				'Selenium',
				'Firecrawl',
				'Apify',
				'crawl4ai',
				'ScrapingBee',
				'Zyte',
				'colly',
				'Nutch',
				'Mechanize',
			)
		);
	}

	/**
	 * Generic HTTP libraries: the User-Agent each one sends when the program does not set its own. Scrapers use
	 * them, but so do mobile apps (Flutter "Dart/", Android "okhttp"), headless front ends (node-fetch, axios,
	 * undici), ERP and price sync (Java, Guzzle, python-requests) and monitors (curl). Blocked on top of the bot
	 * list only with "Also block generic HTTP libraries (strict)". Until 3.3 they were part of the default list,
	 * so lists saved before 3.4 usually contain them already.
	 *
	 * @return string[]
	 */
	public static function http_library_agents() {
		return (array) apply_filters(
			'pncp_http_library_agents',
			array( 'curl/', 'Wget/', 'python-requests', 'python-urllib', 'aiohttp', 'httpx', 'Go-http-client', 'node-fetch', 'axios/', '=node', 'undici', 'okhttp', 'Dart/', 'Java/', 'Java-http-client', 'Apache-HttpClient', 'GuzzleHttp', 'libwww-perl', 'HTTP-Tiny', '=Ruby', 'Faraday v', 'Bun/', 'Deno/', 'PowerShell/' )
		);
	}

	/**
	 * The generic HTTP libraries that a stored bot list contains (lists saved before 3.4 usually do): they are
	 * blocked even with "Also block generic HTTP libraries" off, so the Bots tab names them.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string[]
	 */
	public static function http_libraries_in_list( $s ) {
		$list = array_map( 'strtolower', self::parse_list( isset( $s['bot_list'] ) ? (string) $s['bot_list'] : '' ) );
		$out  = array();
		foreach ( self::http_library_agents() as $agent ) {
			if ( in_array( strtolower( (string) $agent ), $list, true ) ) {
				$out[] = (string) $agent;
			}
		}
		return $out;
	}

	/**
	 * AI search engines and assistants: they bring the site into answers (with a link) or open a page
	 * because a user asked for it. They are not the training crawlers (GPTBot, ClaudeBot, CCBot,
	 * Google-Extended, Applebot-Extended etc.), which stay blocked.
	 *
	 * @return string[]
	 */
	public static function ai_search_agents() {
		return (array) apply_filters(
			'pncp_ai_search_agents',
			array( 'OAI-SearchBot', 'ChatGPT-User', 'Claude-SearchBot', 'Claude-User', 'PerplexityBot', 'Perplexity-User', 'DuckAssistBot', 'MistralAI-User' )
		);
	}

	/**
	 * The AI search engines allowed with the current settings (empty if the option is off).
	 *
	 * @return string[]
	 */
	public static function allowed_ai_search() {
		return empty( self::get()['allow_ai_search'] ) ? array() : self::ai_search_agents();
	}

	/**
	 * An "always allowed" entry: the User-Agent part and the IPs it is accepted from.
	 * "Skroutz" = from any IP; "Skroutz@203.0.113.0/24, 198.51.100.7" = only from these addresses.
	 * Invalid IPs are ignored; an entry with "@" but no valid IP is never accepted.
	 *
	 * @param string $entry Entry of the list.
	 * @return array{ua:string, ips:string[], pinned:bool}
	 */
	public static function split_allow_entry( $entry ) {
		$parts = explode( '@', (string) $entry, 2 );
		$ips   = array();
		if ( isset( $parts[1] ) ) {
			foreach ( preg_split( '/[\s,]+/', $parts[1] ) as $range ) {
				if ( PNCP_Ip::valid_range( $range ) ) {
					$ips[] = $range;
				}
			}
		}
		return array(
			'ua'     => trim( $parts[0] ),
			'ips'    => $ips,
			'pinned' => isset( $parts[1] ),
		);
	}

	/**
	 * The default list as text.
	 *
	 * @return string
	 */
	public static function default_bot_list() {
		return implode( "\n", self::default_bot_entries() );
	}

	/**
	 * The User-Agents blocked when "Block bots" is on: the editable bot list, the AI crawlers built into the
	 * plugin (PNCP_Bots::known_ai_agents()), with "Block web archives" the archive crawlers and, with "Also block
	 * generic HTTP libraries", the libraries of http_library_agents(); no duplicates.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string[]
	 */
	public static function blocked_agents( $s ) {
		$out = array();
		foreach ( array_merge( self::parse_list( $s['bot_list'] ), PNCP_Bots::known_ai_agents(), empty( $s['block_archivers'] ) ? array() : PNCP_Bots::archive_agents(), empty( $s['block_http_libs'] ) ? array() : self::http_library_agents() ) as $agent ) {
			$agent = trim( (string) $agent );
			if ( '' !== $agent && '=' !== $agent ) {
				$out[ strtolower( $agent ) ] = $agent;
			}
		}
		return array_values( $out );
	}

	/**
	 * HTTP libraries added to the bot list in 2.8.3: the User-Agent each one sends by default (measured, not
	 * guessed). "=" = the whole User-Agent, for names too short to match safely anywhere in it. Sites older than
	 * 2.8.3 get them on upgrade (pncp_upgrade()), as they did then. Since 3.4 all but Mechanize are in
	 * http_library_agents() instead of the default list.
	 *
	 * @return string[]
	 */
	public static function new_bots_in_283() {
		return array( '=node', 'undici', '=Ruby', 'Java-http-client', 'Apache-HttpClient', 'GuzzleHttp', 'Bun/', 'Deno/', 'Dart/', 'HTTP-Tiny', 'PowerShell/', 'Faraday v', 'Mechanize' );
	}

	/**
	 * User-Agents that always pass the list check and the "browser headers" check (link previews, price
	 * platforms, monitoring). The User-Agent can be spoofed, so the page limit still applies to them as usual.
	 * An entry can be tied to IPs with "@": "Skroutz@203.0.113.0/24, 198.51.100.7" (see split_allow_entry()).
	 *
	 * @return string
	 */
	public static function default_allow_list() {
		return implode(
			"\n",
			array(
				'facebookexternalhit',
				'Facebot',
				'Twitterbot',
				'LinkedInBot',
				'WhatsApp',
				'TelegramBot',
				'Slackbot',
				'Discordbot',
				'Pinterest',
				'Viber',
				'SkypeUriPreview',
				'Skroutz',
				'BestPrice',
				// Uptime monitors and site managers (since 3.4, new installs only).
				'UptimeRobot',
				'Pingdom',
				'Jetpack',
				'StatusCake',
				'Site24x7',
				'Better Uptime',
				'BetterStack',
				'HetrixTools',
				'ManageWP',
				'MainWP',
				'WPUmbrella',
				'WP Umbrella',
				'Freshping',
				'Uptime-Kuma',
			)
		);
	}

	/**
	 * Defaults.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults() {
		return array(
			'enabled'                 => 1,
			'scope_posts'             => 1,
			'scope_pages'             => 1,
			'scope_home'              => 1,
			'scope_products'          => 1,
			// Since 3.4 off on new installs, as in the recommended Balanced preset: blocking selection also stops
			// select-to-speak, screen readers' "read selection", translation tools and copying with the source.
			// Existing sites keep their stored value (see new_in_340()).
			'block_selection'         => 0,
			'block_context_menu'      => 1,
			'block_shortcuts'         => 1,
			'block_devtools'          => 0, // Since 2.3: cosmetic, it stops no bot; on in the Strict / Maximum presets.
			'block_image_drag'        => 1,
			'block_text_drag'         => 1,
			'blur_on_capture'         => 0,
			'show_message'            => 1,
			'skip_woo_pages'          => 1,
			'copy_mode'               => 'attribution',
			'attribution_min_chars'   => 200,
			'print_mode'              => 'source',
			'exempt_cap'              => 'edit_posts',
			'excluded_ids'            => '',
			// Before after_setup_theme (e.g. in the feeds check) the translations are not loaded yet.
			// Empty = the default message, translated when it is shown (in the site's language, also after the
			// language changes). Stored translated before 3.3.2, in whatever language was active at install.
			'message'                 => '',
			'rest_hide_content'       => 1,
			'graphql_hide_content'    => 1,
			'feed_mode'               => 'excerpt',
			'block_bots'              => 1,
			'block_empty_ua'          => 1,
			'block_fake_crawlers'     => 1,
			'require_browser_headers' => 0,
			'trap_enabled'            => 1,
			'bot_list'                => self::default_bot_list(),
			// Since 3.4. Off on new and existing sites: apps, headless front ends and sync tools use these libraries.
			'block_http_libs'         => 0,
			'allow_list'              => self::default_allow_list(),
			'allow_ips'               => '',
			'robots_ai_block'         => 1,
			'allow_ai_search'         => 0,
			'block_framing'           => 1,
			'tdm_reservation'         => 1,
			'tdm_policy_url'          => '',
			// Since 2.3 new installs start with the Balanced limits; existing sites keep their stored values.
			'rate_limit'              => 60,
			'rate_limit_search'       => 20,
			'rate_limit_rest'         => 60,
			'ban_strikes'             => 3,
			'ban_minutes'             => 60,
			'log_retention'           => '7',
			'content_paths'           => '',
			'ip_header'               => 'remote_addr',
			'trust_cloudflare'        => 1,
			'trust_any_proxy'         => 0,
			'trusted_proxies'         => '',
			'cdn_secret'              => '',
			'private_paths'           => '',
			'private_ips'             => '',
			'watermark_enabled'       => 0,
			'watermark_full'          => 0,
			'watermark_products'      => 0,
			'watermark_image_id'      => 0,
			'watermark_opacity'       => 50,
			'watermark_size'          => 25,
			'watermark_position'      => 'br',
			'watermark_min_width'     => 300,
			// Since 2.4. New installs get them on; existing sites get the values of new_in_240() on upgrade.
			'rate_limit_404'          => 30,
			'block_user_enum'         => 1,
			'block_ips'               => '',
			'block_referrers'         => '',
			'early_mode'              => 0,
			'feed_source_link'        => 1,
			'content_signal'          => 1,
			// Since 2.5. Existing sites get the values of new_in_250() on upgrade.
			'verify_ai_bots'          => 1,
			'block_headless'          => 0,
			// Since 2.6. Existing sites get the values of new_in_260() on upgrade.
			'human_check'             => 0,
			'rate_limit_unverified'   => 20,
			'rate_limit_sitemap'      => 5,
			'geo_db'                  => 0,
			'countries_block'         => '',
			'countries_strict'        => '',
			'rate_limit_country'      => 10,
			'trust_bunny'             => 1,
			'precheck'                => 0,
			// Since 2.8. Off on new and existing sites: they change what other services may rely on.
			'disable_pingback'        => 0,
			'hide_rest_discovery'     => 0,
			// Since 2.9. Existing sites get the values of new_in_290() on upgrade (off).
			'hide_versions'           => 1,
			// Off on new sites too: excerpts change how the site looks; the /56 count could reach visitors of a
			// mobile network that gives neighbouring phones addresses of the same /56. Both on in Emergency Mode.
			'list_excerpts'           => 0,
			'ipv6_wide'               => 0,
			'block_archivers'         => 0,
			// Since 3.0. Existing sites get the value of new_in_300() on upgrade (off).
			'block_upload_php'        => 1,
			// Starts Emergency Mode on its own during an attack (PNCP_Surge). Existing sites: off.
			'auto_emergency'          => 1,
			'auto_emergency_min'      => 300,
			// Since 3.4. A sudden rush of real visitors (a newsletter, a link on a big site) looks the same as an
			// attack, and Emergency Mode changes many settings at once (browsers only, which also refuses feed
			// readers, excerpts in lists, stricter limits): new installs only tell the administrator, who starts it
			// with one click. Existing sites that had the automatic start on keep "start" (see new_in_340()).
			'auto_emergency_mode'     => 'notify',
			// Pages per minute from data center addresses (0 = off). Existing sites: off.
			'rate_limit_datacenter'   => 15,
			// Since 3.2. Off everywhere: it needs a rule at the CDN first.
			'cdn_only'                => 0,
			// Since 3.4. "Monitor only": log what would be blocked, block nothing. Off here (existing sites and
			// "reset" keep blocking); a new install turns it on for its first week, see new_install().
			'monitor_mode'            => 0,
			// When the first-week monitoring ends (timestamp, 0 = no end: switched on by hand). Not a form field.
			'monitor_until'           => 0,
		);
	}

	/**
	 * What a brand-new install gets on top of the defaults: "Monitor only" for its first week, so the owner
	 * sees in the log what would be blocked (staff are exempt and never notice a block themselves) before
	 * anything is. Afterwards it starts blocking on its own (end_monitor_trial()). Existing sites never get this.
	 *
	 * @return array<string, int>
	 */
	public static function new_install() {
		return array(
			'monitor_mode'  => 1,
			'monitor_until' => time() + self::MONITOR_DAYS * DAY_IN_SECONDS,
		);
	}

	/**
	 * Is "Monitor only" in effect: every check logs what it would block and lets the request through?
	 * The first-week monitoring ends at its time even before the hourly task has turned the setting off
	 * (or when it cannot, e.g. while the site is locked).
	 *
	 * @param array<string, mixed>|null $s Settings (null = the settings in effect now).
	 * @return bool
	 */
	public static function monitoring( $s = null ) {
		$s = null === $s ? self::get() : $s;
		return ! empty( $s['monitor_mode'] ) && ( empty( $s['monitor_until'] ) || time() < (int) $s['monitor_until'] );
	}

	/**
	 * Ends the first-week monitoring once its time has come: the setting is turned off (blocking starts) and
	 * the administrator is told once, with a notice in wp-admin and an email. Runs hourly and in wp-admin.
	 */
	public static function end_monitor_trial() {
		$s = self::stored();
		if ( empty( $s['monitor_mode'] ) || empty( $s['monitor_until'] ) || time() < (int) $s['monitor_until'] ) {
			return;
		}
		$since              = (int) $s['monitor_until'] - self::MONITOR_DAYS * DAY_IN_SECONDS;
		$s['monitor_mode']  = 0;
		$s['monitor_until'] = 0;
		update_option( PNCP_OPTION, $s ); // Refused while the site is locked: monitoring() has already ended anyway.
		self::flush();
		// add_option() does nothing when the option exists: told once, even if the update above is retried.
		if ( add_option( self::MONITOR_ENDED_OPTION, 'pending', '', false ) ) {
			self::mail_monitor_ended( $since );
		}
	}

	/**
	 * The email sent when the first-week monitoring ends.
	 *
	 * @param int $since When the monitoring started.
	 */
	private static function mail_monitor_ended( $since ) {
		$counts = PNCP_Log::summary( max( 1, (int) ceil( ( time() - $since ) / HOUR_IN_SECONDS ) ), 'monitor' );
		$labels = PNCP_Log::reasons();
		$lines  = array();
		foreach ( array_slice( $counts['reasons'], 0, 10, true ) as $reason => $n ) {
			$lines[] = '- ' . ( isset( $labels[ $reason ] ) ? $labels[ $reason ] : $reason ) . ': ' . number_format_i18n( $n );
		}
		$body = sprintf(
			/* translators: 1: site name, 2: number of days, 3: number of requests */
			__( 'ScrapeLock on %1$s now blocks bots and scrapers: the first %2$d days in “Monitor only” have ended. In that time %3$s requests would have been blocked.', 'scrapelock' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			self::MONITOR_DAYS,
			number_format_i18n( $counts['total'] )
		);
		if ( $lines ) {
			$body .= "\n\n" . implode( "\n", $lines );
		}
		$body .= "\n\n" . __( 'To see what is blocked, or to go back to “Monitor only”, open the ScrapeLock settings:', 'scrapelock' ) . "\n" . admin_url( 'options-general.php?page=scrapelock&tab=log' );
		/* translators: %s: site name */
		wp_mail( get_option( 'admin_email' ), sprintf( __( '[%s] ScrapeLock now blocks bots', 'scrapelock' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ), $body );
	}

	/**
	 * The settings added (or with a new default) in 3.4, with the values existing sites get on upgrade. The
	 * automatic Emergency Mode keeps doing what it did: a site that had it on keeps starting it on its own
	 * ("start"); a site that had it off gets "notify", the safer choice, should it ever turn it on. Text selection
	 * stays blocked, as it was by default before 3.4.
	 *
	 * @param array<string, mixed> $stored Stored settings.
	 * @return array<string, string>
	 */
	public static function new_in_340( $stored ) {
		return array(
			'auto_emergency_mode' => ! empty( $stored['auto_emergency'] ) ? 'start' : 'notify',
			// The default before 3.4. Every site stores it, so this only matters for settings that lack it.
			'block_selection'     => 1,
		);
	}

	/**
	 * The settings added in 3.0, with the values existing sites get on upgrade: off.
	 *
	 * @return array<string, int>
	 */
	public static function new_in_300() {
		return array(
			'block_upload_php'      => 0,
			'auto_emergency'        => 0,
			'rate_limit_datacenter' => 0,
		);
	}

	/**
	 * The settings added in 2.9, with the values existing sites get on upgrade: everything off.
	 *
	 * @return array<string, int>
	 */
	public static function new_in_290() {
		return array(
			'hide_versions'   => 0,
			'list_excerpts'   => 0,
			'ipv6_wide'       => 0,
			'block_archivers' => 0,
		);
	}

	/**
	 * The settings added in 2.6, with the values existing sites get on upgrade: everything off.
	 *
	 * @return array<string, int|string>
	 */
	public static function new_in_260() {
		return array(
			'human_check'           => 0,
			'rate_limit_unverified' => 20,
			'rate_limit_sitemap'    => 0,
			'geo_db'                => 0,
			'countries_block'       => '',
			'countries_strict'      => '',
			'rate_limit_country'    => 10,
			'trust_bunny'           => 0,
			'precheck'              => 0,
		);
	}

	/**
	 * Why an IP must not be blocked by hand ('' = it may be). The same rules for the Log tab, WP-CLI and the
	 * Abilities API (AI agents): never the server itself, a private address, the IP of whoever asks, an
	 * always-allowed IP, or an official address of a search engine, an AI search service or a CDN edge (that
	 * would block every visitor behind it).
	 *
	 * @param string $ip IP.
	 * @return string invalid | local | own | allowed | official, or ''.
	 */
	public static function ban_refusal( $ip ) {
		$ip = PNCP_Ip::normalize( (string) $ip );
		if ( '' === $ip ) {
			return 'invalid';
		}
		if ( PNCP_Ip::is_local( $ip ) || PNCP_Ip::is_private( $ip ) ) {
			return 'local';
		}
		if ( PNCP_Ip::client_ip() === $ip ) {
			return 'own';
		}
		if ( PNCP_Ip::in_any( $ip, self::parse_list( self::stored()['allow_ips'] ) ) ) {
			return 'allowed';
		}
		if ( PNCP_Bots::is_official_crawler_ip( $ip ) || '' !== PNCP_Ip::official_owner( $ip ) || self::crawler_fallback_ip( $ip ) ) {
			return 'official';
		}
		return '';
	}

	/**
	 * 3.4: is the IP in the main, long-standing ranges of Googlebot or Bingbot, while the official list of that
	 * crawler is not downloaded yet (a new install without internet access, or a failed download)? Only for
	 * refusing a manual block and for blocking at the CDN (3.4.1): the full lists decide everything else once
	 * they are there.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function crawler_fallback_ip( $ip ) {
		$fallback = array(
			'google' => array( '66.249.64.0/19', '2001:4860:4801::/48' ),
			'bing'   => array( '157.55.39.0/24', '207.46.13.0/24', '40.77.167.0/24' ),
		);
		foreach ( $fallback as $name => $ranges ) {
			if ( ! PNCP_Ip::list_of( $name ) && PNCP_Ip::in_any( $ip, $ranges ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A sentence for ban_refusal()'s answer.
	 *
	 * @param string $why Answer of ban_refusal().
	 * @return string
	 */
	public static function ban_refusal_text( $why ) {
		$texts = array(
			'invalid'  => __( 'Not a valid IP address.', 'scrapelock' ),
			'local'    => __( 'This is the server itself or a private address: it is never blocked.', 'scrapelock' ),
			'own'      => __( 'This is your own IP address: it is not blocked, so you do not lock yourself out.', 'scrapelock' ),
			'allowed'  => __( 'This IP is in "Always allowed IPs".', 'scrapelock' ),
			'official' => __( 'This IP belongs to a search engine, an AI search service or a CDN in front of the site (blocking it would block every visitor behind it): it is never blocked.', 'scrapelock' ),
		);
		return isset( $texts[ $why ] ) ? $texts[ $why ] : '';
	}

	/**
	 * Adds an IP to "Always blocked IPs" (button "Block permanently" in the Log tab). Never the server itself,
	 * the administrator's own IP, an always-allowed IP or a Google / Bing address. Saving this list does not
	 * empty the page cache (only the IP list changes).
	 *
	 * @param string $ip IP.
	 * @return string added | exists | full | refused
	 */
	public static function block_ip_permanently( $ip ) {
		$ip = trim( (string) $ip );
		if ( '' !== self::ban_refusal( $ip ) ) {
			return 'refused';
		}
		$stored = self::stored();
		$list   = self::parse_list( $stored['block_ips'] );
		if ( in_array( $ip, $list, true ) ) {
			return 'exists';
		}
		if ( count( $list ) >= 200 ) {
			return 'full'; // The list keeps at most 200 lines (parse_list).
		}
		$list[]              = $ip;
		$stored['block_ips'] = implode( "\n", $list );
		$purge               = has_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache' );
		if ( false !== $purge ) {
			remove_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache', $purge );
		}
		update_option( PNCP_OPTION, $stored );
		if ( false !== $purge ) {
			add_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache', $purge );
		}
		self::flush();
		return 'added';
	}

	/**
	 * Is the IP in "Always blocked IPs"?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_blocked_permanently( $ip ) {
		return PNCP_Ip::in_any( (string) $ip, self::parse_list( self::stored()['block_ips'] ) );
	}

	/**
	 * The part of a blocked User-Agent that the "Always allow this User-Agent" button suggests: the bot-list
	 * entry it matched ("Dart/", "okhttp", "GPTBot"), so exactly what blocked it passes. An entry that must be
	 * the whole User-Agent ("=node") suggests the whole User-Agent, because the allow list matches anywhere.
	 *
	 * @param string               $ua User-Agent.
	 * @param array<string, mixed> $s  Settings.
	 * @return string
	 */
	public static function allow_token_for( $ua, $s ) {
		$ua = trim( (string) $ua );
		foreach ( self::blocked_agents( $s ) as $needle ) {
			if ( PNCP_Bots::ua_in_list( $ua, array( $needle ) ) ) {
				return '=' === $needle[0] ? mb_substr( $ua, 0, 100 ) : $needle;
			}
		}
		return mb_substr( $ua, 0, 100 );
	}

	/**
	 * Why a User-Agent part must not be added to "Always allowed User-Agents" ('' = it may be). Refused: empty,
	 * fewer than three letters or digits, "@" (IP pinning is set in the Bots tab, where the IPs can be checked),
	 * and anything so generic that it would also match an ordinary browser or every bot ("Mozilla", "Chrome",
	 * "compatible", "bot"): the allow list overrides the bot list and "Browsers only", so such an entry would
	 * switch them off for everyone.
	 *
	 * @param string $token User-Agent part.
	 * @return string empty | generic, or ''.
	 */
	public static function allow_token_refusal( $token ) {
		$token = trim( (string) $token );
		if ( '' === $token || preg_match_all( '/[A-Za-z0-9]/', $token ) < 3 || false !== strpos( $token, '@' ) ) {
			return 'empty';
		}
		$samples = array(
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
			'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
			'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
			'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
			'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
			'Mozilla/5.0 (compatible; ExampleBot/1.0; +https://www.example.com/bot.html)',
		);
		foreach ( $samples as $sample ) {
			if ( false !== stripos( $sample, $token ) ) {
				return 'generic';
			}
		}
		$generic = array( 'bot', 'bots', 'crawl', 'crawler', 'spider', 'http', 'https', 'client', 'agent', 'user-agent', 'browser', 'mobile', 'compatible', 'www', 'com' );
		return in_array( strtolower( rtrim( $token, '/' ) ), $generic, true ) ? 'generic' : '';
	}

	/**
	 * Adds a User-Agent part to "Always allowed User-Agents" (button "Always allow this User-Agent" in the Log
	 * tab). Like block_ip_permanently(), saving it does not empty the page cache: only the list changes.
	 *
	 * @param string $token User-Agent part, e.g. "Dart/" or "okhttp".
	 * @return string added | exists | full | refused
	 */
	public static function allow_user_agent( $token ) {
		$token = mb_substr( trim( sanitize_text_field( (string) $token ) ), 0, 100 );
		if ( '' !== self::allow_token_refusal( $token ) ) {
			return 'refused';
		}
		$stored = self::stored();
		$list   = self::parse_list( $stored['allow_list'] );
		if ( in_array( strtolower( $token ), array_map( 'strtolower', $list ), true ) ) {
			return 'exists';
		}
		if ( count( $list ) >= 200 ) {
			return 'full'; // The list keeps at most 200 lines (parse_list).
		}
		$list[]               = $token;
		$stored['allow_list'] = implode( "\n", $list );
		$purge                = has_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache' );
		if ( false !== $purge ) {
			remove_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache', $purge );
		}
		update_option( PNCP_OPTION, $stored );
		if ( false !== $purge ) {
			add_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache', $purge );
		}
		self::flush();
		return 'added';
	}

	/**
	 * Country codes (ISO 3166-1 alpha-2) from free text: "cn, RU ru\nkp" -> "CN\nRU\nKP".
	 *
	 * @param string $raw Text.
	 * @return string[]
	 */
	public static function parse_countries( $raw ) {
		$out = array();
		foreach ( preg_split( '/[\s,;]+/', strtoupper( (string) $raw ) ) as $code ) {
			if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
				$out[ $code ] = $code;
			}
		}
		return array_slice( array_values( $out ), 0, 250 );
	}

	/**
	 * The settings added in 2.5, with the values existing sites get on upgrade: off.
	 *
	 * @return array<string, int>
	 */
	public static function new_in_250() {
		return array(
			'verify_ai_bots' => 0,
			'block_headless' => 0,
		);
	}

	/**
	 * The settings added in 2.4, with the values existing sites get on upgrade: everything off,
	 * so that nothing changes on a site until its administrator turns it on.
	 *
	 * @return array<string, int|string>
	 */
	public static function new_in_240() {
		return array(
			'rate_limit_404'   => 0,
			'block_user_enum'  => 0,
			'block_ips'        => '',
			'block_referrers'  => '',
			'early_mode'       => 0,
			'feed_source_link' => 0,
			'content_signal'   => 0,
		);
	}

	/**
	 * The preset profiles: values written to the settings when the button is pressed.
	 * They do not touch fields, lists, feeds, watermark and IPs.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function profiles() {
		$base = array(
			'block_bots'          => 1,
			'block_empty_ua'      => 1,
			'block_fake_crawlers' => 1,
			'trap_enabled'        => 1,
			'robots_ai_block'     => 1,
			'block_framing'       => 1,
			'tdm_reservation'     => 1,
			'rest_hide_content'   => 1,
			'block_context_menu'  => 1,
			'block_image_drag'    => 1,
			'block_text_drag'     => 1,
			'block_shortcuts'     => 1,
		);
		return array(
			'balanced' => array_merge(
				$base,
				array(
					'block_selection'         => 0,
					'copy_mode'               => 'attribution',
					'print_mode'              => 'source',
					'feed_mode'               => 'excerpt',
					'require_browser_headers' => 0,
					'blur_on_capture'         => 0,
					'rate_limit'              => 60,
					'rate_limit_search'       => 20,
					'rate_limit_rest'         => 60,
					'ban_strikes'             => 3,
					'ban_minutes'             => 60,
				)
			),
			'strict'   => array_merge(
				$base,
				array(
					'block_selection'         => 1,
					'copy_mode'               => 'block',
					'print_mode'              => 'source',
					'feed_mode'               => 'excerpt',
					'require_browser_headers' => 0,
					'blur_on_capture'         => 0,
					'block_devtools'          => 1,
					'rate_limit'              => 40,
					'rate_limit_search'       => 10,
					'rate_limit_rest'         => 30,
					'ban_strikes'             => 2,
					'ban_minutes'             => 180,
				)
			),
			'maximum'  => array_merge(
				$base,
				array(
					'block_selection'         => 1,
					'copy_mode'               => 'block',
					'print_mode'              => 'block',
					'feed_mode'               => 'disabled',
					'require_browser_headers' => 1,
					'blur_on_capture'         => 1,
					'block_devtools'          => 1,
					'rate_limit'              => 30,
					'rate_limit_search'       => 6,
					'rate_limit_rest'         => 20,
					'ban_strikes'             => 2,
					'ban_minutes'             => 720,
				)
			),
		);
	}

	/**
	 * Which profile exactly matches the settings (or '' for "Custom").
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	public static function current_profile( $s ) {
		foreach ( self::profiles() as $name => $values ) {
			$match = true;
			foreach ( $values as $key => $value ) {
				if ( (string) $s[ $key ] !== (string) $value ) {
					$match = false;
					break;
				}
			}
			if ( $match ) {
				return $name;
			}
		}
		return '';
	}

	/**
	 * The stricter Emergency Mode values. Limits take the smaller of the two.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array<string, mixed>
	 */
	public static function emergency_overlay( $s ) {
		$min = static function ( $current, $cap ) {
			$current = (int) $current;
			return $current > 0 ? min( $current, $cap ) : $cap;
		};
		return array(
			// 3.4: Emergency Mode is started to stop an attack (by the administrator, or on its own when set to),
			// so it blocks also while "Monitor only" is on, for example in the first week of a new install.
			// Before, it only logged what it would block then. "Monitor only" is back when it ends.
			'monitor_mode'            => 0,
			'block_bots'              => 1,
			'block_empty_ua'          => 1,
			'block_fake_crawlers'     => 1,
			'require_browser_headers' => 1,
			'block_headless'          => 1,
			'trap_enabled'            => 1,
			'rest_hide_content'       => 1,
			'graphql_hide_content'    => 1,
			'block_framing'           => 1,
			'feed_mode'               => 'full' === $s['feed_mode'] ? 'excerpt' : $s['feed_mode'],
			'rate_limit'              => $min( $s['rate_limit'], 20 ),
			'rate_limit_search'       => $min( $s['rate_limit_search'], 5 ),
			'rate_limit_rest'         => $min( $s['rate_limit_rest'], 10 ),
			'rate_limit_404'          => $min( $s['rate_limit_404'], 10 ),
			'rate_limit_sitemap'      => $min( $s['rate_limit_sitemap'], 5 ),
			'human_check'             => 1,
			'rate_limit_unverified'   => $min( $s['rate_limit_unverified'], 10 ),
			'block_user_enum'         => 1,
			'ban_strikes'             => 2,
			'ban_minutes'             => max( (int) $s['ban_minutes'], 360 ),
			'list_excerpts'           => 1,
			'ipv6_wide'               => 1,
			'rate_limit_datacenter'   => $min( $s['rate_limit_datacenter'], 5 ),
		);
	}

	/**
	 * What Emergency Mode changes on this site, in words: one line per setting of emergency_overlay() whose value
	 * differs from the current one. Built from the overlay itself, so the description on the settings page is
	 * always the list of what really changes (a setting the overlay gets later without a label here is still
	 * listed, by its name).
	 *
	 * @param array<string, mixed> $s Stored settings.
	 * @return string[]
	 */
	public static function emergency_changes( $s ) {
		$s     = array_merge( self::defaults(), (array) $s );
		$lines = array();
		foreach ( self::emergency_overlay( $s ) as $key => $value ) {
			if ( isset( $s[ $key ] ) && (string) $s[ $key ] === (string) $value ) {
				continue; // Already like this in your settings: nothing changes.
			}
			if ( 'monitor_mode' === $key && ! self::monitoring( $s ) ) {
				continue; // "Monitor only" is on in the settings but has already ended (the first week is over).
			}
			$lines[] = self::emergency_label( $key, $value );
		}
		return $lines;
	}

	/**
	 * One setting of Emergency Mode, in words, with the value it gets.
	 *
	 * @param string $key   Setting.
	 * @param mixed  $value Value in Emergency Mode.
	 * @return string
	 */
	public static function emergency_label( $key, $value ) {
		$n = (int) $value;
		switch ( $key ) {
			case 'monitor_mode':
				return __( '“Monitor only” is paused: everything below really blocks', 'scrapelock' );
			case 'block_bots':
				return __( 'The bot list blocks AI crawlers and scrapers', 'scrapelock' );
			case 'block_empty_ua':
				return __( 'Requests without a User-Agent are blocked', 'scrapelock' );
			case 'block_fake_crawlers':
				return __( 'Fake search engines are blocked', 'scrapelock' );
			case 'require_browser_headers':
				return __( 'Browsers only: pages are refused to clients that do not send browser headers (feeds stay open to feed readers and podcast apps)', 'scrapelock' );
			case 'block_headless':
				return __( 'Headless and fake browsers are blocked (not on feeds)', 'scrapelock' );
			case 'trap_enabled':
				return __( 'The bot trap is on', 'scrapelock' );
			case 'rest_hide_content':
				return __( 'The REST API does not show the text of posts', 'scrapelock' );
			case 'graphql_hide_content':
				return __( 'GraphQL does not show the text of posts', 'scrapelock' );
			case 'block_framing':
				return __( 'Other sites cannot show your pages in a frame', 'scrapelock' );
			case 'feed_mode':
				return 'disabled' === $value ? __( 'RSS / Atom feeds are disabled', 'scrapelock' ) : __( 'RSS / Atom feeds show a short excerpt only', 'scrapelock' );
			case 'rate_limit':
				/* translators: %d: number of pages */
				return sprintf( _n( 'At most %d page per minute per IP', 'At most %d pages per minute per IP', $n, 'scrapelock' ), $n );
			case 'rate_limit_search':
				/* translators: %d: number of searches */
				return sprintf( _n( 'At most %d search per minute per IP', 'At most %d searches per minute per IP', $n, 'scrapelock' ), $n );
			case 'rate_limit_rest':
				/* translators: %d: number of requests */
				return sprintf( _n( 'At most %d REST API / GraphQL request per minute per IP', 'At most %d REST API / GraphQL requests per minute per IP', $n, 'scrapelock' ), $n );
			case 'rate_limit_404':
				/* translators: %d: number of pages */
				return sprintf( _n( 'At most %d “page not found” per minute per IP', 'At most %d “page not found” per minute per IP', $n, 'scrapelock' ), $n );
			case 'rate_limit_sitemap':
				/* translators: %d: number of requests */
				return sprintf( _n( 'At most %d sitemap request per minute per IP', 'At most %d sitemap requests per minute per IP', $n, 'scrapelock' ), $n );
			case 'human_check':
				return __( 'The human check is on', 'scrapelock' );
			case 'rate_limit_unverified':
				/* translators: %d: number of pages */
				return sprintf( _n( 'Visitors who have not passed the human check: at most %d page per minute', 'Visitors who have not passed the human check: at most %d pages per minute', $n, 'scrapelock' ), $n );
			case 'block_user_enum':
				return __( 'Lists of user names (author scans) are blocked', 'scrapelock' );
			case 'ban_strikes':
				/* translators: %d: number of violations */
				return sprintf( _n( 'An IP is blocked temporarily after %d violation', 'An IP is blocked temporarily after %d violations', $n, 'scrapelock' ), $n );
			case 'ban_minutes':
				return 0 === $n % 60
					/* translators: %d: number of hours */
					? sprintf( _n( 'A temporary block lasts %d hour', 'A temporary block lasts %d hours', (int) ( $n / 60 ), 'scrapelock' ), (int) ( $n / 60 ) )
					/* translators: %d: number of minutes */
					: sprintf( _n( 'A temporary block lasts %d minute', 'A temporary block lasts %d minutes', $n, 'scrapelock' ), $n );
			case 'list_excerpts':
				return __( 'Lists of articles (home page, categories, archives, search) show an excerpt and a link instead of the full text', 'scrapelock' );
			case 'ipv6_wide':
				return __( 'IPv6: the whole /56 network is limited too', 'scrapelock' );
			case 'rate_limit_datacenter':
				/* translators: %d: number of pages */
				return sprintf( _n( 'At most %d page per minute from data centers (also services in “Always allowed” that are not pinned to their IPs)', 'At most %d pages per minute from data centers (also services in “Always allowed” that are not pinned to their IPs)', $n, 'scrapelock' ), $n );
		}
		return $key . ': ' . (string) $value;
	}

	/**
	 * The settings that change what a logged-out visitor gets for an address that a page cache or a CDN may keep
	 * a copy of: the HTML of pages and feeds, their headers, robots.txt, and the cache plugins' own rules (WP
	 * Rocket's list of User-Agents that never get cached pages). Only a change to one of these empties the page
	 * cache (pncp_settings_purge()); every other setting is read by PHP on each request, or written to its own
	 * file (early check, pre-cache check, uploads rule), so a cached page is still right after it changes.
	 *
	 * Not here on purpose: log retention, limits, countries, IP lists, proxies, CDN secret, "Monitor only", the
	 * automatic Emergency Mode (checked in PHP, before or without the cache); who is exempt (staff are logged in
	 * and never get cached pages); the watermark look (it changes image files, not the HTML, and the files are
	 * redone later by the image tool).
	 *
	 * @return string[]
	 */
	public static function cache_keys() {
		return array(
			// Whether and where the protection script and its settings are printed into the page.
			'enabled',
			'scope_posts',
			'scope_pages',
			'scope_home',
			'scope_products',
			'skip_woo_pages',
			'excluded_ids',
			'block_selection',
			'block_context_menu',
			'block_shortcuts',
			'block_devtools',
			'block_image_drag',
			'block_text_drag',
			'blur_on_capture',
			'copy_mode',
			'attribution_min_chars',
			'print_mode',
			'show_message',
			'message',
			'human_check',
			'trap_enabled',
			// Headers and tags in the page head.
			'block_framing',
			'tdm_reservation',
			'tdm_policy_url',
			'hide_versions',
			'hide_rest_discovery',
			'disable_pingback',
			// What pages, lists and feeds contain.
			'list_excerpts',
			'feed_mode',
			'feed_source_link',
			'watermark_full',
			'rest_hide_content',
			'graphql_hide_content',
			'block_user_enum',
			'private_paths',
			'private_ips',
			// robots.txt (a CDN keeps .txt files) and the User-Agents WP Rocket must never serve from its cache.
			'robots_ai_block',
			'content_signal',
			'allow_ai_search',
			'block_bots',
			'block_empty_ua',
			'bot_list',
			'block_http_libs',
			'block_archivers',
			'precheck',
		);
	}

	/**
	 * Which of cache_keys() differ between two sets of settings.
	 *
	 * @param array<string, mixed> $old Settings before.
	 * @param array<string, mixed> $new Settings after.
	 * @return string[]
	 */
	public static function cache_keys_changed( $old, $new ) {
		$defaults = self::defaults();
		$old      = array_merge( $defaults, is_array( $old ) ? $old : array() );
		$new      = array_merge( $defaults, is_array( $new ) ? $new : array() );
		$changed  = array();
		foreach ( self::cache_keys() as $key ) {
			if ( (string) $old[ $key ] !== (string) $new[ $key ] ) {
				$changed[] = $key;
			}
		}
		return $changed;
	}

	/**
	 * When Emergency Mode expires (0 = inactive).
	 *
	 * @return int
	 */
	public static function emergency_until() {
		$until = (int) get_option( self::EMERGENCY_OPTION, 0 );
		return $until > time() ? $until : 0;
	}

	/**
	 * Starts or stops Emergency Mode.
	 *
	 * The page cache is never emptied here. Emergency Mode is started at the peak of an attack: emptying the
	 * whole cache (and Cloudflare's, "purge everything") would send every visitor to PHP and the database at
	 * once, and make the administrator's click wait for the cache plugins and the Cloudflare API. Most of what
	 * it changes (limits, bot checks, temporary blocks) is checked in PHP on every request, so cached pages are
	 * still right. Only when it changes something a cached page contains (cache_keys(): e.g. excerpts in the
	 * lists, the frame header, the feeds) is the cache emptied, once, in a background request (a loopback to
	 * wp-cron.php that nobody waits for). The automatic start passes false and empties nothing: see PNCP_Surge.
	 *
	 * @param int  $hours Duration in hours (0 = stop).
	 * @param bool $purge Whether the page cache may be emptied in the background when cached pages change.
	 */
	public static function set_emergency( $hours, $purge = true ) {
		$hours  = max( 0, min( 72, (int) $hours ) );
		$before = self::get();
		update_option( self::EMERGENCY_OPTION, $hours ? time() + $hours * HOUR_IN_SECONDS : 0, true );
		self::flush();
		// 3.4: the pre-cache check applies Emergency Mode too (its end time and limits are in its configuration).
		PNCP_Precheck::refresh();
		if ( $purge && self::cache_keys_changed( $before, self::get() ) ) {
			pncp_schedule_purge();
		}
		// Started or stopped (from the ScrapeLock page, WP-CLI or the Abilities API): the alert of the automatic
		// Emergency Mode, if one is shown, has been answered.
		PNCP_Surge::clear_alert();
	}

	/**
	 * The message shown to visitors: the administrator's own, or the default in the site's language.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	public static function message( $s ) {
		$own = isset( $s['message'] ) ? trim( (string) $s['message'] ) : '';
		return '' !== $own ? $own : __( 'The content of this page is protected.', 'scrapelock' );
	}

	/**
	 * The default message as it may be stored by earlier versions: in English, and translated.
	 *
	 * @return string[]
	 */
	public static function default_messages() {
		return array_unique( array( 'The content of this page is protected.', __( 'The content of this page is protected.', 'scrapelock' ) ) );
	}

	/**
	 * The stored settings, filled in with defaults.
	 *
	 * @return array<string, mixed>
	 */
	public static function stored() {
		$stored = get_option( PNCP_OPTION, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		// Settings stored before 3.4 that the upgrade could not add to: on a site locked with Lockdown the
		// settings keep their value (pncp_upgrade() is refused like any other change). They get the values an
		// upgrade gives existing sites, not the new-install defaults, so an automatic Emergency Mode that started
		// on its own keeps doing so.
		if ( $stored && ! isset( $stored['auto_emergency_mode'] ) ) {
			$stored += self::new_in_340( $stored );
		}
		$defaults = self::defaults();
		foreach ( $defaults as $key => $default ) {
			// 3.4: a setting that should be a single value but is stored as a list or nothing (changed in the
			// database, or damaged) gets its default, instead of warnings on every page that shows it.
			if ( array_key_exists( $key, $stored ) && is_scalar( $default ) && ! is_scalar( $stored[ $key ] ) ) {
				$stored[ $key ] = $default;
			}
		}
		return array_merge( $defaults, $stored );
	}

	/**
	 * The settings in effect now (with Emergency Mode, if running).
	 *
	 * @return array<string, mixed>
	 */
	public static function get() {
		if ( null === self::$cache ) {
			$s = self::stored();
			if ( ! empty( $s['enabled'] ) && self::emergency_until() ) {
				$s = array_merge( $s, self::emergency_overlay( $s ) );
			}
			self::$cache = $s;
		}
		return self::$cache;
	}

	/**
	 * Forgets the request cache (after a settings change).
	 */
	public static function flush() {
		self::$cache = null;
	}

	/**
	 * Sanitizes whatever comes from the form. Keeps only known keys.
	 *
	 * @param mixed $input Form values.
	 * @return array<string, mixed>
	 */
	public static function sanitize( $input ) {
		$input    = is_array( $input ) ? $input : array();
		$defaults = self::defaults();
		$clean    = array();

		foreach ( self::bool_keys() as $key ) {
			$clean[ $key ] = empty( $input[ $key ] ) ? 0 : 1;
		}

		foreach ( self::choices() as $key => $allowed ) {
			$value         = isset( $input[ $key ] ) ? sanitize_key( (string) $input[ $key ] ) : '';
			$clean[ $key ] = in_array( $value, $allowed, true ) ? $value : $defaults[ $key ];
		}

		foreach ( self::int_ranges() as $key => $range ) {
			$value         = isset( $input[ $key ] ) && '' !== $input[ $key ] ? (int) $input[ $key ] : $defaults[ $key ];
			$clean[ $key ] = max( $range[0], min( $range[1], $value ) );
		}

		$ids                   = isset( $input['excluded_ids'] ) ? (string) $input['excluded_ids'] : '';
		$ids                   = array_filter( array_map( 'absint', preg_split( '/[\s,]+/', $ids ) ) );
		$clean['excluded_ids'] = implode( ', ', array_unique( $ids ) );

		$message          = isset( $input['message'] ) ? sanitize_text_field( (string) $input['message'] ) : '';
		// The default text, unchanged, is stored as "default" (empty), so it keeps following the site's language.
		$clean['message'] = '' === $message || in_array( $message, self::default_messages(), true ) ? '' : mb_substr( $message, 0, 200 );

		foreach ( self::list_keys() as $key ) {
			$clean[ $key ] = implode( "\n", self::parse_list( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' ) );
		}
		// Private URLs: a line that would match the homepage or every page ("/", "*") would answer 403 to every
		// visitor. Such lines are not saved, and the administrator is told which.
		$private = array();
		$refused = array();
		foreach ( self::parse_list( $clean['private_paths'] ) as $pattern ) {
			if ( null === PNCP_Private_Urls::parse_pattern( $pattern ) ) {
				$refused[] = $pattern;
			} else {
				$private[] = $pattern;
			}
		}
		$clean['private_paths'] = implode( "\n", $private );
		if ( $refused && function_exists( 'add_settings_error' ) ) {
			/* translators: %s: the refused lines */
			add_settings_error( PNCP_OPTION, 'pncp_private_paths', sprintf( __( 'These private URLs were not saved, because they would block the homepage or every page for all visitors: %s. Use the path of the feed (e.g. /skroutz.xml) or its query (e.g. /?feed=skroutz).', 'scrapelock' ), implode( ', ', $refused ) ) );
		}

		foreach ( self::ip_list_keys() as $key ) {
			$clean[ $key ] = implode( "\n", self::parse_ip_list( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' ) );
		}

		foreach ( array( 'countries_block', 'countries_strict' ) as $key ) {
			$clean[ $key ] = implode( "\n", self::parse_countries( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' ) );
		}
		self::guard_block_lists( $clean, $input );

		$policy                  = isset( $input['tdm_policy_url'] ) ? esc_url_raw( trim( (string) $input['tdm_policy_url'] ), array( 'https', 'http' ) ) : '';
		$clean['tdm_policy_url'] = (string) $policy;

		// A shared secret for the CDN (header value): only safe characters, kept short.
		$secret = isset( $input['cdn_secret'] ) ? (string) preg_replace( '/[^A-Za-z0-9._\-]/', '', (string) $input['cdn_secret'] ) : '';
		$stored = self::stored();
		// The form never shows the saved secret: an empty field keeps it, the "remove" box clears it.
		if ( '' === $secret && empty( $input['cdn_secret_clear'] ) ) {
			$secret = (string) $stored['cdn_secret'];
		}
		$clean['cdn_secret'] = substr( $secret, 0, 100 );

		// "Only through the CDN" is turned on (or its secret changed) only from a request that brought the secret:
		// that proves the CDN sends it. Otherwise the next request, and the administrator, would get a 403.
		$was = ! empty( $stored['cdn_only'] ) ? (string) $stored['cdn_secret'] : '';
		if ( ! empty( $clean['cdn_only'] ) && ( '' === $clean['cdn_secret'] || ( $was !== $clean['cdn_secret'] && ! empty( $input['_sections'] ) && ! PNCP_Origin::has_secret( $clean['cdn_secret'] ) ) ) ) {
			$clean['cdn_only'] = 0;
			if ( function_exists( 'add_settings_error' ) ) {
				add_settings_error( PNCP_OPTION, 'pncp_cdn_only', '' === $clean['cdn_secret'] ? __( '“Only through the CDN” was not turned on: set a CDN shared secret first.', 'scrapelock' ) : __( '“Only through the CDN” was not turned on: this request did not bring the secret in the X-ScrapeLock-CDN header, so the CDN does not send it yet (or you opened the site around the CDN). Add the header at the CDN, reload this page and try again.', 'scrapelock' ) );
			}
		}

		// The "trust every proxy" option remains only for those who already had it (upgrade from 1.4).
		// The form can only turn it off, not on (the upgrade turns it on in code).
		if ( isset( $input['_sections'] ) && empty( $stored['trust_any_proxy'] ) ) {
			$clean['trust_any_proxy'] = 0;
		}

		// Single-tab form: only its fields change; the rest keep their stored value.
		if ( isset( $input['_sections'] ) ) {
			$keep = array();
			foreach ( self::sections() as $section => $keys ) {
				if ( ! in_array( $section, (array) $input['_sections'], true ) ) {
					$keep = array_merge( $keep, $keys );
				}
			}
			foreach ( $keep as $key ) {
				$clean[ $key ] = $stored[ $key ];
			}
		}

		// The end of the first-week monitoring is not a form field. It is kept while "Monitor only" stays on;
		// turned off, it goes; turned on by hand, the mode has no end (it blocks again only when you say so).
		// A programmatic save (a new install, the hourly end) brings its own value.
		if ( empty( $clean['monitor_mode'] ) ) {
			$clean['monitor_until'] = 0;
		} elseif ( isset( $input['monitor_until'] ) && ! isset( $input['_sections'] ) ) {
			$clean['monitor_until'] = absint( $input['monitor_until'] );
		} else {
			$clean['monitor_until'] = ! empty( $stored['monitor_mode'] ) ? absint( $stored['monitor_until'] ) : 0;
		}

		self::flush();
		return $clean;
	}

	/**
	 * Guards against blocking everyone by mistake, like the private URLs guard above. "Always blocked IPs" do not
	 * keep a range wider than /8 (IPv4, 16 million addresses) or /16 (IPv6): 0.0.0.0/0 or ::/0 would refuse every
	 * visitor, and ranges that wide always hold real visitors and search engines. The administrator is told which
	 * lines were not saved. A range that holds the IP of whoever is saving, or a blocked country that is the shop's
	 * own country (WooCommerce) or the one this request comes from, is saved (it can be intended, e.g. while
	 * testing through a VPN), but with a warning.
	 *
	 * Only what the form (or an import) brings is checked: a tab that does not save these fields keeps them as
	 * they are.
	 *
	 * @param array<string, mixed> $clean Sanitized values (changed in place).
	 * @param array<string, mixed> $input Form values.
	 */
	private static function guard_block_lists( &$clean, $input ) {
		$notify = function_exists( 'add_settings_error' );
		// 3.4: the same limit for the lists that let addresses through. A trusted proxy range this wide lets any
		// visitor choose its own IP with a header (even 127.0.0.1, the server itself), like "trust any proxy";
		// an allowed range this wide lets a large part of the internet past the protection.
		$texts = array(
			/* translators: %s: the refused lines */
			'trusted_proxies' => __( 'These trusted proxy ranges were not saved, because they are too wide (wider than /8 for IPv4 or /16 for IPv6): any visitor could then choose its own IP with a header and never be limited or blocked: %s. List only the addresses of your own proxy or load balancer.', 'scrapelock' ),
			/* translators: %s: the refused lines */
			'allow_ips'       => __( 'These always-allowed IP ranges were not saved, because they are too wide (wider than /8 for IPv4 or /16 for IPv6) and would let a large part of the internet past the protection: %s.', 'scrapelock' ),
			/* translators: %s: the refused lines */
			'private_ips'     => __( 'These IP ranges for the private URLs were not saved, because they are too wide (wider than /8 for IPv4 or /16 for IPv6) and would open the private URLs to a large part of the internet: %s.', 'scrapelock' ),
		);
		foreach ( $texts as $key => $text ) {
			if ( ! self::saved_here( $key, $input ) ) {
				continue; // Not on the tab being saved: kept as it is.
			}
			$keep_list = array();
			$wide_list = array();
			foreach ( self::parse_list( isset( $clean[ $key ] ) ? $clean[ $key ] : '' ) as $range ) {
				if ( self::range_too_wide( $range ) ) {
					$wide_list[] = $range;
				} else {
					$keep_list[] = $range;
				}
			}
			$clean[ $key ] = implode( "\n", $keep_list );
			if ( $wide_list && $notify ) {
				add_settings_error( PNCP_OPTION, 'pncp_' . $key . '_wide', sprintf( $text, implode( ', ', $wide_list ) ) );
			}
		}

		if ( isset( $input['_sections'] ) && ! in_array( 'bots', (array) $input['_sections'], true ) ) {
			return;
		}
		$kept = array();
		$wide = array();
		foreach ( self::parse_list( $clean['block_ips'] ) as $range ) {
			if ( self::range_too_wide( $range ) ) {
				$wide[] = $range;
			} else {
				$kept[] = $range;
			}
		}
		$clean['block_ips'] = implode( "\n", $kept );
		if ( $wide && $notify ) {
			add_settings_error(
				PNCP_OPTION,
				'pncp_block_ips_wide',
				/* translators: %s: the refused lines */
				sprintf( __( 'These always-blocked IP ranges were not saved, because they are too wide (wider than /8 for IPv4 or /16 for IPv6) and would block a large part of the internet or every visitor: %s. Block single addresses or narrower ranges, e.g. 203.0.113.0/24.', 'scrapelock' ), implode( ', ', $wide ) )
			);
		}
		$ip = PNCP_Ip::client_ip();
		if ( '' !== $ip && $notify ) {
			$own = array();
			foreach ( $kept as $range ) {
				if ( PNCP_Ip::in_range( $ip, $range ) ) {
					$own[] = $range;
				}
			}
			if ( $own ) {
				add_settings_error(
					PNCP_OPTION,
					'pncp_block_ips_own',
					/* translators: 1: the IP of the administrator, 2: the ranges */
					sprintf( __( 'Warning: your own IP (%1$s) is in these always-blocked IPs: %2$s. They were saved, but you can lock yourself out of this site (the early check and the pre-cache check refuse them before anyone is logged in), together with everyone on your network. If this is not intended, remove them, or add your IP to “Always allowed IPs”.', 'scrapelock' ), $ip, implode( ', ', $own ) ),
					'warning'
				);
			}
		}

		$blocked = self::parse_list( $clean['countries_block'] );
		if ( ! $blocked || ! $notify ) {
			return;
		}
		$shop = self::shop_country();
		if ( '' !== $shop && in_array( $shop, $blocked, true ) ) {
			add_settings_error(
				PNCP_OPTION,
				'pncp_countries_shop',
				/* translators: %s: country code */
				sprintf( __( 'Warning: the blocked countries include %s, the country of your shop (WooCommerce → Settings → Store address). It was saved, but customers from your own country will be refused.', 'scrapelock' ), $shop ),
				'warning'
			);
		}
		$here = '' !== $ip ? PNCP_Geo::country( $ip ) : '';
		if ( '' !== $here && $here !== $shop && in_array( $here, $blocked, true ) ) {
			add_settings_error(
				PNCP_OPTION,
				'pncp_countries_here',
				/* translators: %s: country code */
				sprintf( __( 'Warning: the blocked countries include %s, the country you are visiting from now. It was saved, but you will be refused once you log out, and so will visitors from there.', 'scrapelock' ), $here ),
				'warning'
			);
		}
	}

	/**
	 * Does this save bring the field (the form of its tab, an import or WP-CLI, which save every field)?
	 *
	 * @param string               $key   Field.
	 * @param array<string, mixed> $input Form values.
	 * @return bool
	 */
	private static function saved_here( $key, $input ) {
		if ( ! isset( $input['_sections'] ) ) {
			return true;
		}
		foreach ( self::sections() as $section => $fields ) {
			if ( in_array( $key, $fields, true ) && in_array( $section, (array) $input['_sections'], true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Is an IP range wider than /8 (IPv4) or /16 (IPv6)?
	 *
	 * @param string $range IP or CIDR.
	 * @return bool
	 */
	public static function range_too_wide( $range ) {
		$parts = explode( '/', trim( (string) $range ), 2 );
		if ( ! isset( $parts[1] ) || ! ctype_digit( $parts[1] ) ) {
			return false; // A single address.
		}
		$prefix = (int) $parts[1];
		if ( ! filter_var( $parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $prefix < 8;
		}
		// 3.4: IPv6 written for IPv4 addresses (::ffff:0.0.0.0/96 is "every IPv4 address"): the IPv4 limit counts
		// for the part after the first 96 bits, and a wider IPv6 range that holds all of them is too wide too.
		$bin    = inet_pton( $parts[0] );
		$mapped = str_repeat( "\0", 10 ) . "\xff\xff";
		if ( false !== $bin && 16 === strlen( $bin ) && self::same_bits( $bin, $mapped, min( $prefix, 96 ) ) ) {
			return $prefix < 96 + 8;
		}
		return $prefix < 16;
	}

	/**
	 * Do two binary strings start with the same bits?
	 *
	 * @param string $a    Binary string.
	 * @param string $b    Binary string.
	 * @param int    $bits How many bits.
	 * @return bool
	 */
	private static function same_bits( $a, $b, $bits ) {
		$bytes = intdiv( $bits, 8 );
		if ( substr( $a, 0, $bytes ) !== substr( $b, 0, $bytes ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = ( 0xff << ( 8 - $rest ) ) & 0xff;
		return ( ord( $a[ $bytes ] ) & $mask ) === ( ord( $b[ $bytes ] ) & $mask );
	}

	/**
	 * The country of the WooCommerce store address (ISO code), or '' without WooCommerce.
	 *
	 * @return string
	 */
	public static function shop_country() {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return '';
		}
		// "GR:I" (country:state) or "GR".
		$country = strtoupper( strtok( (string) get_option( 'woocommerce_default_country', '' ), ':' ) );
		return preg_match( '/^[A-Z]{2}$/', $country ) ? $country : '';
	}

	/**
	 * Line list: no blanks, duplicates or control characters, up to 200 lines of 100 characters.
	 *
	 * @param string $raw Text with one value per line.
	 * @return string[]
	 */
	public static function parse_list( $raw ) {
		if ( ! is_scalar( $raw ) ) {
			return array(); // Not text (a damaged setting): no lines.
		}
		$lines = preg_split( '/\r\n|\r|\n/', (string) $raw );
		$out   = array();
		foreach ( $lines as $line ) {
			$line = trim( sanitize_text_field( $line ) );
			if ( '' !== $line ) {
				$out[ strtolower( $line ) ] = mb_substr( $line, 0, 100 );
			}
		}
		return array_slice( array_values( $out ), 0, 200 );
	}

	/**
	 * IP / CIDR list: keeps only valid values.
	 *
	 * @param string $raw Text with one value per line.
	 * @return string[]
	 */
	public static function parse_ip_list( $raw ) {
		$out = array();
		foreach ( self::parse_list( $raw ) as $range ) {
			if ( PNCP_Ip::valid_range( $range ) ) {
				$out[] = self::unmap_range( $range );
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * 3.4: an IPv4 address (or range) written in its IPv6 form (::ffff:198.51.100.7, ::ffff:198.51.100.0/120) is
	 * saved as IPv4 (198.51.100.7, 198.51.100.0/24): visitors are compared by their IPv4 address, so the IPv6
	 * form never matched anyone. A wider IPv6 range is kept as written.
	 *
	 * @param string $range IP or CIDR.
	 * @return string
	 */
	public static function unmap_range( $range ) {
		$parts = explode( '/', (string) $range, 2 );
		if ( false === strpos( $parts[0], ':' ) || ! filter_var( $parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $range;
		}
		$bin = inet_pton( $parts[0] );
		if ( false === $bin || 16 !== strlen( $bin ) || str_repeat( "\0", 10 ) . "\xff\xff" !== substr( $bin, 0, 12 ) ) {
			return $range;
		}
		$v4 = (string) inet_ntop( substr( $bin, 12 ) );
		if ( ! isset( $parts[1] ) ) {
			return $v4;
		}
		$prefix = (int) $parts[1];
		return $prefix >= 96 ? $v4 . '/' . ( $prefix - 96 ) : $range;
	}

	/**
	 * The excluded IDs, as integers.
	 *
	 * @param array<string, mixed> $settings Settings.
	 * @return int[]
	 */
	public static function excluded_ids( $settings ) {
		return array_values( array_filter( array_map( 'absint', explode( ',', (string) $settings['excluded_ids'] ) ) ) );
	}

	/**
	 * Is the current user excluded from protection?
	 *
	 * @param array<string, mixed> $settings Settings.
	 * @return bool
	 */
	public static function user_is_exempt( $settings ) {
		return 'none' !== $settings['exempt_cap'] && is_user_logged_in() && PNCP_Lockdown::can( $settings['exempt_cap'] );
	}
}
