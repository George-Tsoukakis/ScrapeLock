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
			'copy_mode'          => array( 'block', 'attribution', 'allow' ),
			'print_mode'         => array( 'allow', 'source', 'block' ),
			'exempt_cap'         => array( 'manage_options', 'edit_others_posts', 'edit_posts', 'none' ),
			'feed_mode'          => array( 'full', 'excerpt', 'disabled' ),
			'ip_header'          => array( 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip', 'true_client_ip' ),
			'watermark_position' => array( 'br', 'bl', 'tr', 'tl', 'center', 'tiled' ),
			'log_retention'      => array( '1', '7', '30' ),
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
			'bots'    => array( 'block_bots', 'block_empty_ua', 'block_fake_crawlers', 'require_browser_headers', 'block_headless', 'trap_enabled', 'block_archivers', 'ipv6_wide', 'bot_list', 'allow_list', 'allow_ips', 'allow_ai_search', 'verify_ai_bots', 'robots_ai_block', 'content_signal', 'block_ips', 'block_referrers', 'block_user_enum', 'rate_limit', 'rate_limit_search', 'rate_limit_rest', 'rate_limit_404', 'rate_limit_sitemap', 'human_check', 'rate_limit_unverified', 'geo_db', 'countries_block', 'countries_strict', 'rate_limit_country', 'ban_strikes', 'ban_minutes', 'auto_emergency', 'auto_emergency_min', 'early_mode', 'precheck', 'log_retention', 'content_paths', 'ip_header', 'trust_cloudflare', 'trust_bunny', 'trust_any_proxy', 'trusted_proxies', 'cdn_secret' ),
			'content' => array( 'rest_hide_content', 'hide_rest_discovery', 'graphql_hide_content', 'feed_mode', 'feed_source_link', 'list_excerpts', 'private_paths', 'private_ips', 'disable_pingback', 'hide_versions', 'block_upload_php' ),
			'images'  => array( 'watermark_enabled', 'watermark_full', 'watermark_products', 'watermark_image_id', 'watermark_opacity', 'watermark_size', 'watermark_position', 'watermark_min_width' ),
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
	 * The User-Agents blocked by default (substring, case-insensitive).
	 * Never contains search engines, social network previews or price comparison platforms.
	 *
	 * @return string[]
	 */
	public static function default_bot_entries() {
		return array_merge(
			self::legacy_bot_list(),
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
				// Scraping tools and headless browsers.
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
				'node-fetch',
				'axios/',
				'okhttp',
				'libwww-perl',
				'Java/',
				'httpx',
				'colly',
				'Nutch',
			),
			self::new_bots_in_283()
		);
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
	 * plugin (PNCP_Bots::known_ai_agents()) and, with "Block web archives", the archive crawlers; no duplicates.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string[]
	 */
	public static function blocked_agents( $s ) {
		$out = array();
		foreach ( array_merge( self::parse_list( $s['bot_list'] ), PNCP_Bots::known_ai_agents(), empty( $s['block_archivers'] ) ? array() : PNCP_Bots::archive_agents() ) as $agent ) {
			$agent = trim( (string) $agent );
			if ( '' !== $agent && '=' !== $agent ) {
				$out[ strtolower( $agent ) ] = $agent;
			}
		}
		return array_values( $out );
	}

	/**
	 * HTTP libraries added to the bot list in 2.8.3: the User-Agent each one sends by default (measured, not
	 * guessed). "=" = the whole User-Agent, for names too short to match safely anywhere in it. Existing sites
	 * get them on upgrade (pncp_upgrade()).
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
			array( 'facebookexternalhit', 'Facebot', 'Twitterbot', 'LinkedInBot', 'WhatsApp', 'TelegramBot', 'Slackbot', 'Discordbot', 'Pinterest', 'Viber', 'SkypeUriPreview', 'Skroutz', 'BestPrice', 'UptimeRobot', 'Pingdom', 'Jetpack' )
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
			'block_selection'         => 1,
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
			'message'                 => did_action( 'after_setup_theme' ) ? __( 'The content of this page is protected.', 'scrapelock' ) : 'The content of this page is protected.',
			'rest_hide_content'       => 1,
			'graphql_hide_content'    => 1,
			'feed_mode'               => 'excerpt',
			'block_bots'              => 1,
			'block_empty_ua'          => 1,
			'block_fake_crawlers'     => 1,
			'require_browser_headers' => 0,
			'trap_enabled'            => 1,
			'bot_list'                => self::default_bot_list(),
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
		);
	}

	/**
	 * The settings added in 3.0, with the values existing sites get on upgrade: off.
	 *
	 * @return array<string, int>
	 */
	public static function new_in_300() {
		return array(
			'block_upload_php' => 0,
			'auto_emergency'   => 0,
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
	 * Adds an IP to "Always blocked IPs" (button "Block permanently" in the Log tab). Never the server itself,
	 * the administrator's own IP, an always-allowed IP or a Google / Bing address. Saving this list does not
	 * empty the page cache (only the IP list changes).
	 *
	 * @param string $ip IP.
	 * @return string added | exists | full | refused
	 */
	public static function block_ip_permanently( $ip ) {
		$ip = trim( (string) $ip );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || PNCP_Ip::is_local( $ip ) || PNCP_Ip::is_private( $ip ) || PNCP_Ip::client_ip() === $ip || PNCP_Bots::is_official_crawler_ip( $ip ) || '' !== PNCP_Ip::official_owner( $ip ) || PNCP_Ip::in_any( $ip, self::parse_list( self::stored()['allow_ips'] ) ) ) {
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
		);
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
	 * @param int $hours Duration in hours (0 = stop).
	 */
	public static function set_emergency( $hours ) {
		$hours = max( 0, min( 72, (int) $hours ) );
		update_option( self::EMERGENCY_OPTION, $hours ? time() + $hours * HOUR_IN_SECONDS : 0, true );
		self::flush();
		pncp_purge_page_cache();
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
		return array_merge( self::defaults(), $stored );
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
		$clean['message'] = '' === $message ? $defaults['message'] : mb_substr( $message, 0, 200 );

		foreach ( self::list_keys() as $key ) {
			$clean[ $key ] = implode( "\n", self::parse_list( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' ) );
		}

		foreach ( self::ip_list_keys() as $key ) {
			$clean[ $key ] = implode( "\n", self::parse_ip_list( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' ) );
		}

		foreach ( array( 'countries_block', 'countries_strict' ) as $key ) {
			$clean[ $key ] = implode( "\n", self::parse_countries( isset( $input[ $key ] ) ? (string) $input[ $key ] : '' ) );
		}

		$policy                  = isset( $input['tdm_policy_url'] ) ? esc_url_raw( trim( (string) $input['tdm_policy_url'] ), array( 'https', 'http' ) ) : '';
		$clean['tdm_policy_url'] = (string) $policy;

		// A shared secret for the CDN (header value): only safe characters, kept short.
		$secret               = isset( $input['cdn_secret'] ) ? (string) preg_replace( '/[^A-Za-z0-9._\-]/', '', (string) $input['cdn_secret'] ) : '';
		$clean['cdn_secret']  = substr( $secret, 0, 100 );

		$stored = self::stored();

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

		self::flush();
		return $clean;
	}

	/**
	 * Line list: no blanks, duplicates or control characters, up to 200 lines of 100 characters.
	 *
	 * @param string $raw Text with one value per line.
	 * @return string[]
	 */
	public static function parse_list( $raw ) {
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
				$out[] = $range;
			}
		}
		return $out;
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
