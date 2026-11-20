<?php
/**
 * 3.11: the names of the settings in words, for every place that lists settings rather than showing their
 * fields: the tables of "Reset this tab" and "Import settings", the Emergency Mode box and the like. The texts
 * are the labels of the fields themselves, so they are already translated wherever the fields are.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Setting labels.
 */
final class PNCP_Setting_Labels {

	/**
	 * Labels of this request.
	 *
	 * @var array<string, string>|null
	 */
	private static $labels = null;

	/**
	 * Every setting with the label of its field.
	 *
	 * @return array<string, string>
	 */
	public static function all() {
		if ( null !== self::$labels ) {
			return self::$labels;
		}
		$labels = array(
			'ai_referrals'            => __( 'Count visitors who come from AI assistants (ChatGPT, Perplexity, Claude, Gemini, Copilot…)', 'scrapelock' ),
			'allow_ai_search'         => __( 'Allow AI search engines and assistants (not training crawlers)', 'scrapelock' ),
			'allow_ips'               => __( 'Always allowed IPs / CIDR (office, ERP, monitoring), one per line:', 'scrapelock' ),
			'allow_list'              => __( 'Always allowed User-Agents (link previews, price comparison platforms, monitoring):', 'scrapelock' ),
			'attack_record'           => __( 'Record where bots and attackers hit the site', 'scrapelock' ),
			'attack_retention'        => __( 'Keep the attack record for', 'scrapelock' ),
			'attribution_min_chars'   => __( 'Append the source from this many characters and up:', 'scrapelock' ),
			'auto_emergency'          => __( 'Watch for attacks spread over many IPs (automatic Emergency Mode)', 'scrapelock' ),
			'auto_emergency_min'      => __( 'Minimum pages per minute for the automatic start:', 'scrapelock' ),
			'auto_emergency_mode'     => __( 'When it happens:', 'scrapelock' ),
			'ban_minutes'             => __( 'Block duration (minutes):', 'scrapelock' ),
			'ban_strikes'             => __( 'Block after this many violations within 10 minutes (0 = never):', 'scrapelock' ),
			'block_archivers'         => __( 'Block web archives (Wayback Machine)', 'scrapelock' ),
			'block_bots'              => __( 'Block (403) the User-Agents in the list', 'scrapelock' ),
			'block_context_menu'      => __( 'Right click', 'scrapelock' ),
			'block_devtools'          => __( 'Developer tools shortcuts (F12, Ctrl+Shift+I/J/C/K, Cmd+Opt+I/J/C/U)', 'scrapelock' ),
			'block_empty_ua'          => __( 'Block requests without a User-Agent', 'scrapelock' ),
			'block_fake_crawlers'     => __( 'Block fake Googlebot, Bingbot, Applebot and Yandex', 'scrapelock' ),
			'block_framing'           => __( 'Pages do not open inside another site\'s iframe', 'scrapelock' ),
			'block_headless'          => __( 'Block headless and fake browsers', 'scrapelock' ),
			'block_http_libs'         => __( 'Also block generic HTTP libraries (strict)', 'scrapelock' ),
			'block_image_drag'        => __( 'Dragging images and “Save image” with a long press on mobile', 'scrapelock' ),
			'block_ip_host'           => __( 'Refuse requests that open the site by its IP address instead of its name', 'scrapelock' ),
			'block_ips'               => __( 'IPs / CIDR that are always blocked (403), one per line:', 'scrapelock' ),
			'block_referrers'         => __( 'Referrer domains that are always blocked (403), one per line, e.g. copy-site.example:', 'scrapelock' ),
			'block_selection'         => __( 'Text selection with the mouse or finger', 'scrapelock' ),
			'block_seo_crawlers'      => __( 'Block SEO and marketing data crawlers (Ahrefs, Semrush, Majestic…)', 'scrapelock' ),
			'block_shortcuts'         => __( 'Shortcuts Ctrl/Cmd + A, C, X, S, U', 'scrapelock' ),
			'block_text_drag'         => __( 'Dragging selected text to another window', 'scrapelock' ),
			'block_upload_php'        => __( 'No PHP in the uploads folder', 'scrapelock' ),
			'block_user_enum'         => __( 'Hide usernames from visitors', 'scrapelock' ),
			'blur_on_capture'         => __( 'Blur the page when Print Screen or a screenshot shortcut is pressed', 'scrapelock' ),
			'bot_list'                => __( 'User-Agents to block (one per line, matches anywhere in the User-Agent, case-insensitive):', 'scrapelock' ),
			'bunny_all_lines'         => __( 'Also record requests that reached WordPress', 'scrapelock' ),
			'bunny_flood_4xx'         => __( 'Errors per IP that count as a flood (0 = off):', 'scrapelock' ),
			'bunny_import'            => __( 'Import attacks from Bunny CDN\'s logs', 'scrapelock' ),
			'bunny_login_allow'       => __( 'Allowed IPs for the login page at Bunny, one per line:', 'scrapelock' ),
			'bunny_rate'              => __( 'Pages per minute and IP at the CDN (0 = off):', 'scrapelock' ),
			'bunny_strikes'           => __( 'Count IPs that are too fast at the CDN toward a temporary block', 'scrapelock' ),
			'cdn_only'                => __( 'Only through the CDN: refuse (403) requests that do not bring the secret', 'scrapelock' ),
			'cdn_secret'              => __( 'CDN shared secret (optional):', 'scrapelock' ),
			'content_paths'           => __( 'Content addresses: path prefixes of pages that other plugins show, one per line, e.g. /hub/space/', 'scrapelock' ),
			'content_signal'          => __( 'Content Signals in robots.txt: search yes, AI training no', 'scrapelock' ),
			'copy_mode'               => __( 'When someone copies', 'scrapelock' ),
			'countries_block'         => __( 'Blocked countries (403), two-letter codes separated by commas, e.g. CN, RU:', 'scrapelock' ),
			'countries_strict'        => __( 'Countries with a stricter page limit, e.g. those your customers do not come from:', 'scrapelock' ),
			'crowdsec_action'         => __( 'What a listed IP gets:', 'scrapelock' ),
			'crowdsec_key'            => __( 'Bouncer key (LAPI), or user:password for a list (optional for a public list):', 'scrapelock' ),
			'crowdsec_mode'           => __( 'Use the CrowdSec blocklist:', 'scrapelock' ),
			'crowdsec_url'            => __( 'Address of the CrowdSec agent (LAPI) or of the list:', 'scrapelock' ),
			'disable_pingback'        => __( 'Turn off pingbacks', 'scrapelock' ),
			'early_mode'              => __( 'Early check: block known bots before the theme and the other plugins load', 'scrapelock' ),
			'edge_send_blocks'        => __( 'Send temporary blocks to the CDN', 'scrapelock' ),
			'enabled'                 => __( 'Protection is active', 'scrapelock' ),
			'excluded_ids'            => __( 'Exceptions', 'scrapelock' ),
			'exempt_cap'              => __( 'Who is excluded', 'scrapelock' ),
			'feed_mode'               => __( 'RSS / Atom feeds', 'scrapelock' ),
			'feed_source_link'        => __( 'Full text: add “The post … first appeared on …” at the end', 'scrapelock' ),
			'geo_db'                  => __( 'Download the free country database (DB-IP Lite, once a month)', 'scrapelock' ),
			'graphql_hide_content'    => __( 'Hide the text in WPGraphQL (content, excerpt, product descriptions)', 'scrapelock' ),
			'hide_fingerprint'        => __( 'Hide that the site runs on WordPress, as far as possible', 'scrapelock' ),
			'hide_rest_discovery'     => __( 'Hide the REST API map from visitors', 'scrapelock' ),
			'hide_versions'           => __( 'Hide the versions of WordPress, PHP and the plugins', 'scrapelock' ),
			'human_check'             => __( 'Stricter page limit for visitors who have not shown they are people', 'scrapelock' ),
			'ip_header'               => __( 'Real visitor IP', 'scrapelock' ),
			'ipv6_wide'               => __( 'IPv6: also limit the whole /56 network (four times the page limit)', 'scrapelock' ),
			'list_excerpts'           => __( 'Lists of articles: an excerpt and a link instead of the full text', 'scrapelock' ),
			'log_retention'           => __( 'Keep the block log for', 'scrapelock' ),
			'login_ban_minutes'       => __( 'Block the IP for (minutes):', 'scrapelock' ),
			'login_generic_errors'    => __( 'One error message for a wrong username, email or password', 'scrapelock' ),
			'login_limit'             => __( 'Limit failed sign-ins', 'scrapelock' ),
			'login_max'               => __( 'Failed sign-ins per IP before it is blocked:', 'scrapelock' ),
			'login_slug'              => __( 'Sign-in address', 'scrapelock' ),
			'login_user_email'        => __( 'Email the account a link to sign in during a pause', 'scrapelock' ),
			'login_user_max'          => __( 'Failed sign-ins per username before it is paused (0 = off):', 'scrapelock' ),
			'login_user_minutes'      => __( 'Pause the username for (minutes):', 'scrapelock' ),
			'login_window'            => __( '…within this many minutes:', 'scrapelock' ),
			'message'                 => __( 'Message to the visitor', 'scrapelock' ),
			'monitor_mode'            => __( 'Monitor only (log what would be blocked, block nothing)', 'scrapelock' ),
			'precheck'                => __( 'Pre-cache check: apply the page limit and blocks also to pages served from the page cache', 'scrapelock' ),
			'print_mode'              => __( 'Printing', 'scrapelock' ),
			'private_ips'             => __( 'Or allowed IPs / CIDR of the service (one per line):', 'scrapelock' ),
			'private_paths'           => __( 'Paths that are not public (one per line, * means “anything”), e.g. /skroutz.xml, /feeds/*.xml, or a feed served with a query, e.g. /?feed=skroutz:', 'scrapelock' ),
			'probe_ban'               => __( 'Ban scanners on their first probe', 'scrapelock' ),
			'rate_limit'              => __( 'Pages per minute (0 = off):', 'scrapelock' ),
			'rate_limit_404'          => __( '“Page not found” (404) per minute (0 = off):', 'scrapelock' ),
			'rate_limit_account'      => __( 'Pages per minute per signed-in account (0 = off):', 'scrapelock' ),
			'rate_limit_apionly'      => __( 'REST API, GraphQL, feeds and sitemaps per minute for IPs that never opened a page (0 = off):', 'scrapelock' ),
			'rate_limit_cart'         => __( 'WooCommerce cart and checkout actions per minute (0 = off):', 'scrapelock' ),
			'rate_limit_country'      => __( 'Pages per minute for these countries (0 = off):', 'scrapelock' ),
			'rate_limit_coupon'       => __( 'WooCommerce coupon attempts per minute (0 = off):', 'scrapelock' ),
			'rate_limit_crowdsec'     => __( 'Pages per minute for listed IPs (0 = off):', 'scrapelock' ),
			'rate_limit_datacenter'   => __( 'Pages per minute from data centers (0 = off):', 'scrapelock' ),
			'rate_limit_lowrep'       => __( 'Pages per minute for IPs with a bad reputation (0 = off):', 'scrapelock' ),
			'rate_limit_rest'         => __( 'REST API (/wp-json/) and GraphQL requests per minute (0 = off):', 'scrapelock' ),
			'rate_limit_search'       => __( 'Searches (?s=) per minute (0 = off):', 'scrapelock' ),
			'rate_limit_sitemap'      => __( 'Sitemaps per minute (0 = off):', 'scrapelock' ),
			'rate_limit_unverified'   => __( 'Pages per minute without the cookie (0 = off):', 'scrapelock' ),
			'report_weekly'           => __( 'Weekly attack report by email', 'scrapelock' ),
			'reputation'              => __( 'Remember how each IP behaves (reputation)', 'scrapelock' ),
			'require_browser_headers' => __( 'Browsers only: 403 for pages without Accept-Language or without “Mozilla/” in the User-Agent', 'scrapelock' ),
			'rest_hide_content'       => __( 'Hide the text (content, excerpt) of posts, pages and products from visitors', 'scrapelock' ),
			'robots_ai_block'         => __( 'Declare AI crawlers in robots.txt (Disallow)', 'scrapelock' ),
			'scope_home'              => __( 'Home, categories, search and archives', 'scrapelock' ),
			'scope_pages'             => __( 'Pages', 'scrapelock' ),
			'scope_posts'             => __( 'Posts', 'scrapelock' ),
			'scope_products'          => __( 'WooCommerce products', 'scrapelock' ),
			'shared_alert'            => __( 'Email me when one account is used from several addresses at once', 'scrapelock' ),
			'shared_ips'              => __( 'Addresses at once:', 'scrapelock' ),
			'shared_logout'           => __( 'Then sign the account out everywhere else', 'scrapelock' ),
			'show_message'            => __( 'Show a message when something is blocked', 'scrapelock' ),
			'skip_woo_pages'          => __( 'Do not apply on cart, checkout and “My account”', 'scrapelock' ),
			'stealth_base'            => __( 'Folder of the new addresses:', 'scrapelock' ),
			'stealth_block_files'     => __( 'Refuse readme.html and other files only WordPress has', 'scrapelock' ),
			'stealth_enabled'         => __( 'Turn on Stealth (tested first)', 'scrapelock' ),
			'stealth_endpoints'       => __( 'Neutral addresses for forms and Ajax', 'scrapelock' ),
			'stealth_rest_prefix'     => __( 'REST API prefix instead of wp-json (empty = keep wp-json):', 'scrapelock' ),
			'stealth_sitemap'         => __( 'Sitemap at /sitemap.xml instead of /wp-sitemap.xml', 'scrapelock' ),
			'syslog_bans'             => __( 'Write each temporary block to the system log, for fail2ban', 'scrapelock' ),
			'tdm_policy_url'          => __( 'Page with the licensing terms (optional):', 'scrapelock' ),
			'tdm_reservation'         => __( 'Opt-out declaration from AI training and text and data mining (TDM)', 'scrapelock' ),
			'text_trace'              => __( 'Hide an invisible trace of the account in the text', 'scrapelock' ),
			'trap_enabled'            => __( 'Bot trap', 'scrapelock' ),
			'trust_any_proxy'         => __( 'Trust every request (1.4 behaviour, insecure)', 'scrapelock' ),
			'trust_bunny'             => __( 'Trust Bunny CDN addresses', 'scrapelock' ),
			'trust_cloudflare'        => __( 'Trust Cloudflare addresses', 'scrapelock' ),
			'trusted_proxies'         => __( 'Other trusted proxies / load balancers (IP or CIDR, one per line):', 'scrapelock' ),
			'user_mark'               => __( 'Show who is reading over protected pages', 'scrapelock' ),
			'user_mark_guests'        => __( 'Also for visitors who are not signed in (their IP address and the time)', 'scrapelock' ),
			'user_mark_opacity'       => __( 'How visible (percent):', 'scrapelock' ),
			'verify_ai_bots'          => __( 'Verify AI search bots with their official IP lists (OpenAI, Perplexity, Anthropic)', 'scrapelock' ),
			'watermark_enabled'       => __( 'Watermark new images', 'scrapelock' ),
			'watermark_full'          => __( 'Watermark the full-size image too', 'scrapelock' ),
			'watermark_image_id'      => __( 'PNG image ID from the Media Library (0 = the site\'s domain as text):', 'scrapelock' ),
			'watermark_min_width'     => __( 'Only on sizes with width from (px):', 'scrapelock' ),
			'watermark_opacity'       => __( 'Opacity (%):', 'scrapelock' ),
			'watermark_position'      => __( 'Position:', 'scrapelock' ),
			'watermark_products'      => __( 'Watermark WooCommerce product images too', 'scrapelock' ),
			'watermark_size'          => __( 'Size (% of the image width):', 'scrapelock' ),
		);
		/**
		 * Filter: the names of the settings in words (key => label).
		 *
		 * @since 3.11.0
		 * @param array<string, string> $labels Labels.
		 */
		self::$labels = (array) apply_filters( 'pncp_setting_labels', $labels );
		return self::$labels;
	}

	/**
	 * The name of one setting in words, without the colon its field label may end with. A setting without a label
	 * (a key added by another plugin through the settings filter) gets its key in words, never the bare key.
	 *
	 * @param string $key Setting.
	 * @return string
	 */
	public static function label( $key ) {
		$all = self::all();
		if ( isset( $all[ $key ] ) && '' !== trim( (string) $all[ $key ] ) ) {
			return rtrim( trim( (string) $all[ $key ] ), ': ' );
		}
		return ucfirst( str_replace( '_', ' ', (string) $key ) );
	}

	/**
	 * A stored value in words: "On" / "Off" for the switches, the value itself for everything else.
	 *
	 * @param string $key   Setting.
	 * @param string $value Value (as text).
	 * @return string
	 */
	public static function value( $key, $value ) {
		if ( in_array( $key, PNCP_Options::bool_keys(), true ) && in_array( (string) $value, array( '0', '1', '' ), true ) ) {
			return '1' === (string) $value ? __( 'On', 'scrapelock' ) : __( 'Off', 'scrapelock' );
		}
		return (string) $value;
	}
}
