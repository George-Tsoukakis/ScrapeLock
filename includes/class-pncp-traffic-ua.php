<?php
/**
 * 3.12: what a User-Agent is, for the Traffic screens: a browser, a search engine (verified by its official address
 * list, or fake), an AI bot, an SEO tool, a link preview, a service, a script (an HTTP library), empty, or other,
 * with a short product name. Built on the plugin's own lists (crawler families, AI lists, link previews, SEO
 * crawlers, HTTP libraries, the service bots of plugins, the bot list and the always-allowed list). No DNS: only
 * list membership. Deterministic, and cached per request.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * User-Agent classification.
 */
final class PNCP_Traffic_Ua {

	/**
	 * The families, in the order the screens list them.
	 */
	const FAMILIES = array( 'browser', 'verified_bot', 'fake_bot', 'ai_bot', 'seo_bot', 'preview', 'service', 'script', 'empty', 'other' );

	/**
	 * Most entries in each per-request cache.
	 */
	const MEMO = 20000;

	/**
	 * User-Agent => [family, name, list to verify against ('' = none), verify kind].
	 *
	 * @var array<string, array{0:string, 1:string, 2:string, 3:string}>
	 */
	private static $memo = array();

	/**
	 * list|ip => on the list.
	 *
	 * @var array<string, bool>
	 */
	private static $ip_memo = array();

	/**
	 * The needles of this request (built once).
	 *
	 * @var array<string, array<int|string, string>>|null
	 */
	private static $lists = null;

	/**
	 * Forgets the caches (tests, after a settings change).
	 */
	public static function reset() {
		self::$memo    = array();
		self::$ip_memo = array();
		self::$lists   = null;
	}

	/**
	 * Labels of the families, translated.
	 *
	 * @return array<string, string>
	 */
	public static function labels() {
		return array(
			'browser'      => __( 'Browsers', 'scrapelock' ),
			'verified_bot' => __( 'Search engines (verified)', 'scrapelock' ),
			'fake_bot'     => __( 'Fake search engines and AI bots', 'scrapelock' ),
			'ai_bot'       => __( 'AI bots', 'scrapelock' ),
			'seo_bot'      => __( 'SEO tools', 'scrapelock' ),
			'preview'      => __( 'Link previews', 'scrapelock' ),
			'service'      => __( 'Services and monitors', 'scrapelock' ),
			'script'       => __( 'Scripts and HTTP libraries', 'scrapelock' ),
			'empty'        => __( 'No User-Agent', 'scrapelock' ),
			'other'        => __( 'Other', 'scrapelock' ),
		);
	}

	/**
	 * What a User-Agent is.
	 *
	 * - empty: no User-Agent (or "-").
	 * - service: a plugin's service bot (PNCP_Plugin_Bots), WordPress itself, uptime monitors, OneSignal, and the
	 *   entries of the always-allowed list that are not in another family.
	 * - verified_bot / fake_bot: a search engine (PNCP_Bots::crawler_families(), DuckDuckBot, Google's other
	 *   fetchers) from an address on its official list, or not. Without a list (YandexBot), with a list that is
	 *   not downloaded or stale, without an IP, or with anonymized logs: verified_bot (it cannot be told fake).
	 *   An AI search bot with an official list (PNCP_Bots::ai_bot_lists()) off its list is fake_bot too.
	 * - ai_bot, seo_bot, preview, script: the plugin's lists of AI crawlers, SEO crawlers, link previews, HTTP
	 *   libraries, headless browsers and site rippers.
	 * - browser: Mozilla/5.0 with a browser engine and no bot words.
	 * - other: everything else (also the bot list's own entries, and search engines that cannot be verified).
	 *
	 * @param string $ua        User-Agent.
	 * @param string $ip        IP ('' = by the User-Agent alone).
	 * @param bool   $no_verify The IP cannot verify anything (anonymized logs).
	 * @return array{family:string, name:string}
	 */
	public static function classify( $ua, $ip = '', $no_verify = false ) {
		$ua = trim( (string) $ua );
		if ( isset( self::$memo[ $ua ] ) ) {
			$base = self::$memo[ $ua ];
		} else {
			$base = self::by_agent( $ua );
			if ( count( self::$memo ) >= self::MEMO ) {
				self::$memo = array();
			}
			self::$memo[ $ua ] = $base;
		}
		list( $family, $name, $list, $kind ) = $base;
		if ( '' !== $list && '' !== (string) $ip && ! $no_verify ) {
			$on = self::on_list( $list, (string) $ip );
			if ( null !== $on && ! $on ) {
				// Off its official list: a fake search engine or AI bot; Google's other fetchers are just "other".
				$family = 'fetcher' === $kind ? 'other' : 'fake_bot';
			}
		}
		return array(
			'family' => $family,
			'name'   => $name,
		);
	}

	/**
	 * Is the address on an official list? null when it cannot be told (no list, or a stale one).
	 *
	 * @param string $list List name (PNCP_Ip::sources()).
	 * @param string $ip   IP.
	 * @return bool|null
	 */
	private static function on_list( $list, $ip ) {
		$key = $list . '|' . $ip;
		if ( array_key_exists( $key, self::$ip_memo ) ) {
			return self::$ip_memo[ $key ];
		}
		$extra  = PNCP_Ip::extra_ranges( $list );
		$ranges = PNCP_Ip::list_of( $list );
		if ( $extra && PNCP_Ip::in_any( $ip, $extra ) ) {
			$on = true;
		} elseif ( ! $ranges || PNCP_Ip::list_stale( $list ) ) {
			$on = null;
		} else {
			$on = PNCP_Ip::in_any( $ip, $ranges );
		}
		if ( count( self::$ip_memo ) >= self::MEMO ) {
			self::$ip_memo = array();
		}
		self::$ip_memo[ $key ] = $on;
		return $on;
	}

	/**
	 * The lists (needles), built once per request.
	 *
	 * @return array<string, array<int|string, string>>
	 */
	private static function lists() {
		if ( null !== self::$lists ) {
			return self::$lists;
		}
		$s       = PNCP_Options::get();
		$service = array( 'WordPress/', 'OneSignal', 'UptimeRobot', 'Pingdom', 'StatusCake', 'Site24x7', 'Better Uptime', 'BetterStack', 'Uptime-Kuma', 'UptimeKuma', 'Freshping', 'HetrixTools', 'jetmon/', 'ManageWP', 'WP Umbrella', 'MainWP', 'InfiniteWP', 'Monit/', 'Zabbix', 'Nagios', 'check_http', 'Datadog', 'NewRelicPinger', 'Cron-job.org', 'cron-job.org', 'Uptime.com', 'Updown.io', 'updown.io', 'Checkly', 'GoogleStackdriverMonitoring', 'Amazon-Route53-Health-Check', 'ELB-HealthChecker', 'kube-probe', 'AuthenticationServices', 'Let\'s Encrypt', 'letsencrypt' );
		$ai      = array_merge(
			array( 'GPTBot', 'ChatGPT-User', 'ChatGPT-Agent', 'OAI-SearchBot', 'CCBot', 'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'Claude-Web', 'anthropic-ai', 'PerplexityBot', 'Perplexity-User', 'Bytespider', 'Google-CloudVertexBot', 'Google-Extended', 'Applebot-Extended', 'meta-externalagent', 'meta-externalfetcher', 'meta-webindexer', 'FacebookBot', 'Amazonbot', 'Diffbot', 'cohere-ai', 'cohere-training-data-crawler', 'AI2Bot', 'Ai2Bot-Dolma', 'YouBot', 'DuckAssistBot', 'MistralAI-User', 'PanguBot', 'Timpibot', 'omgili', 'Webzio-Extended', 'ImagesiftBot', 'img2dataset', 'TikTokSpider' ),
			PNCP_Bots::known_ai_agents(),
			PNCP_Options::ai_search_agents()
		);
		$preview = array_merge( PNCP_Bots::link_preview_agents(), array( 'Pinterestbot', 'Pinterest/', 'redditbot', 'Embedly', 'Iframely', 'SkypeUriPreview', 'Snapchat', 'Mastodon/', 'Bluesky', 'Cardyb', 'vkShare', 'Google-PageRenderer', 'MicrosoftPreview' ) );
		$script  = array_merge( PNCP_Options::http_library_agents(), array( 'Scrapy', 'HeadlessChrome', 'PhantomJS', 'Puppeteer', 'Playwright', 'Selenium', 'python-httpx', 'Python/', 'PycURL', 'WinHttp', 'Mechanize', 'HTTPie', 'lwp-trivial', 'libcurl', 'Wget', 'colly', 'Nutch', 'scrapy-', 'Go http package', 'fasthttp', 'reqwest', 'RestSharp', 'Postman', 'insomnia', 'Jakarta Commons', 'masscan', 'zgrab', 'Nuclei', 'sqlmap', 'Nikto', 'WPScan', 'nmap', 'Nmap' ), PNCP_Bots::ripper_agents() );
		// Search engines that publish no list ScrapeLock can check: named, never "verified".
		$search  = array( 'PetalBot', 'Baiduspider', 'SeznamBot', 'Sogou', 'Qwantbot', 'Qwantify', 'Yeti/', 'coccocbot', 'MojeekBot', 'Exabot', 'NaverBot', 'Daum', 'YisouSpider', '360Spider', 'ia_archiver', 'archive.org_bot', 'heritrix', 'Neevabot', 'BraveBot', 'Kagibot', 'Marginalia' );
		$allow   = array();
		foreach ( PNCP_Options::parse_list( isset( $s['allow_list'] ) ? (string) $s['allow_list'] : '' ) as $entry ) {
			$split = PNCP_Options::split_allow_entry( $entry );
			if ( '' !== $split['ua'] ) {
				$allow[] = $split['ua'];
			}
		}
		$plugin = array();
		$names  = array();
		foreach ( PNCP_Plugin_Bots::registry() as $entry ) {
			foreach ( array_merge( $entry['agents'], $entry['site'] ) as $agent ) {
				$plugin[]                     = $agent;
				$names[ strtolower( $agent ) ] = $entry['name'];
			}
		}
		self::$lists = array(
			'service' => $service,
			'ai'      => array_values( array_unique( array_filter( array_map( 'strval', $ai ) ) ) ),
			'preview' => $preview,
			'seo'     => PNCP_Bots::seo_agents(),
			'script'  => array_values( array_filter( array_map( 'strval', $script ) ) ),
			'search'  => $search,
			'allow'   => $allow,
			'plugin'  => $plugin,
			'names'   => $names,
			'bots'    => PNCP_Options::parse_list( isset( $s['bot_list'] ) ? (string) $s['bot_list'] : '' ),
		);
		return self::$lists;
	}

	/**
	 * The classification by the User-Agent alone: [family, name, list to verify the IP against, kind].
	 *
	 * @param string $ua User-Agent.
	 * @return array{0:string, 1:string, 2:string, 3:string}
	 */
	private static function by_agent( $ua ) {
		if ( '' === $ua || '-' === $ua ) {
			return array( 'empty', '', '', '' );
		}
		$l = self::lists();
		// A plugin's service bot (WP Rocket, Jetpack…), by the plugin's name.
		$hit = self::first( $ua, $l['plugin'] );
		if ( '' !== $hit ) {
			$name = isset( $l['names'][ strtolower( $hit ) ] ) ? $l['names'][ strtolower( $hit ) ] : self::token( $ua, $hit );
			return array( 'service', (string) $name, '', '' );
		}
		// Search engines: their official address list decides (no DNS here).
		$family = PNCP_Bots::claimed_crawler( $ua );
		if ( '' !== $family ) {
			$families = PNCP_Bots::crawler_families();
			$needle   = self::first( $ua, $families[ $family ]['ua'] );
			$list     = (string) $families[ $family ]['list'];
			if ( '' === $list && 'apple' === $family ) {
				$list = 'apple';
			}
			return array( 'verified_bot', self::token( $ua, $needle ), $list, 'crawler' );
		}
		foreach ( PNCP_Bots::listed_fetchers() as $list => $needles ) {
			$needle = self::first( $ua, (array) $needles );
			if ( '' !== $needle ) {
				return array( 'duckduckgo' === $list ? 'verified_bot' : 'service', self::token( $ua, $needle ), (string) $list, 'duckduckgo' === $list ? 'crawler' : 'fetcher' );
			}
		}
		// AI bots; the AI search bots with an official list are checked against it.
		$needle = self::first( $ua, $l['ai'] );
		if ( '' !== $needle ) {
			return array( 'ai_bot', self::token( $ua, $needle ), PNCP_Bots::claimed_ai_list( $ua ), 'ai' );
		}
		$needle = self::first( $ua, $l['preview'] );
		if ( '' !== $needle ) {
			return array( 'preview', self::token( $ua, $needle ), '', '' );
		}
		$needle = self::first( $ua, $l['seo'] );
		if ( '' !== $needle ) {
			return array( 'seo_bot', self::token( $ua, $needle ), '', '' );
		}
		$needle = self::first( $ua, $l['service'] );
		if ( '' !== $needle ) {
			return array( 'service', self::token( $ua, $needle ), '', '' );
		}
		$needle = self::first( $ua, $l['script'] );
		if ( '' !== $needle ) {
			return array( 'script', self::token( $ua, $needle ), '', '' );
		}
		$needle = self::first( $ua, $l['search'] );
		if ( '' !== $needle ) {
			return array( 'other', self::token( $ua, $needle ), '', '' );
		}
		$needle = self::first( $ua, $l['allow'] );
		if ( '' !== $needle ) {
			return array( 'service', self::token( $ua, $needle ), '', '' );
		}
		$needle = self::first( $ua, $l['bots'] );
		if ( '' !== $needle ) {
			return array( 'other', self::token( $ua, $needle ), '', '' );
		}
		$browser = self::browser( $ua );
		if ( '' !== $browser ) {
			return array( 'browser', $browser, '', '' );
		}
		if ( preg_match( '#([A-Za-z0-9][A-Za-z0-9._\-]*(?:bot|crawler|spider|crawl|fetcher|scanner|monitor|checker|agent)[A-Za-z0-9._\-]*)#i', $ua, $m ) ) {
			return array( 'other', substr( $m[1], 0, 40 ), '', '' );
		}
		return array( 'other', self::token( $ua, '' ), '', '' );
	}

	/**
	 * The needle of a list found first in the User-Agent (PNCP_Bots::ua_in_list() rules: case-insensitive, "="
	 * for the whole User-Agent), or ''.
	 *
	 * @param string            $ua      User-Agent.
	 * @param array<int, mixed> $needles Needles.
	 * @return string
	 */
	private static function first( $ua, $needles ) {
		$lower = strtolower( $ua );
		$found = '';
		$at    = PHP_INT_MAX;
		foreach ( $needles as $needle ) {
			$needle = (string) $needle;
			if ( '' === $needle || '=' === $needle ) {
				continue;
			}
			if ( '=' === $needle[0] ) {
				if ( 0 === strcasecmp( $ua, substr( $needle, 1 ) ) ) {
					return $needle;
				}
				continue;
			}
			$pos = strpos( $lower, strtolower( $needle ) );
			// The name that comes first in the User-Agent ("TelegramBot (like TwitterBot)" is TelegramBot).
			if ( false !== $pos && $pos < $at ) {
				$found = $needle;
				$at    = $pos;
			}
		}
		return $found;
	}

	/**
	 * The product name around a needle, as the User-Agent writes it ("Googlebot-Image", "python-requests"); the
	 * first product token when there is no needle.
	 *
	 * @param string $ua     User-Agent.
	 * @param string $needle Needle ('' = the first token).
	 * @return string
	 */
	private static function token( $ua, $needle ) {
		$needle = ltrim( (string) $needle, '=' );
		if ( '' === $needle ) {
			$ua = (string) preg_replace( '#^Mozilla/[\d.]+\s*(?:\([^)]*\)\s*)?#', '', $ua );
			return preg_match( '#^[\s"\']*([A-Za-z0-9][A-Za-z0-9._\-]*)#', $ua, $m ) ? substr( $m[1], 0, 40 ) : '';
		}
		$pos = stripos( $ua, $needle );
		if ( false === $pos ) {
			return substr( rtrim( $needle, '/' ), 0, 40 );
		}
		if ( false !== strpos( $needle, ' ' ) ) {
			return substr( substr( $ua, $pos, strlen( $needle ) ), 0, 40 );
		}
		$rest = substr( $ua, $pos );
		return preg_match( '#^([A-Za-z0-9][A-Za-z0-9._\-]*)#', $rest, $m ) ? substr( rtrim( $m[1], '.-_' ), 0, 40 ) : substr( rtrim( $needle, '/' ), 0, 40 );
	}

	/**
	 * The browser a User-Agent names, or '' when it does not look like one.
	 *
	 * @param string $ua User-Agent.
	 * @return string
	 */
	private static function browser( $ua ) {
		if ( 0 !== strpos( $ua, 'Mozilla/5.0' ) && 0 !== strpos( $ua, 'Mozilla/4.0 (compatible; MSIE' ) && 0 !== strpos( $ua, 'Opera/' ) ) {
			return '';
		}
		if ( preg_match( '#bot\b|crawl|spider|slurp|fetch|preview|scan|monitor|https?://|@|\bheadless#i', $ua ) ) {
			return '';
		}
		if ( ! preg_match( '#(?:AppleWebKit|Gecko/|Trident/|MSIE |Presto/|Mobile)#', $ua ) ) {
			return '';
		}
		$names = array(
			'#\bEdg(?:e|A|iOS)?/#'                => 'Edge',
			'#\b(?:OPR|OPT|Opera)[/ ]#'           => 'Opera',
			'#\bSamsungBrowser/#'                 => 'Samsung Internet',
			'#\bYaBrowser/#'                      => 'Yandex Browser',
			'#\bFBA[NV]/|\bFB_IAB/#'              => 'Facebook app',
			'#\bInstagram\b#'                     => 'Instagram app',
			'#\bVivaldi/#'                        => 'Vivaldi',
			'#\bBrave\b#'                         => 'Brave',
			'#\bDuckDuckGo/#'                     => 'DuckDuckGo browser',
			'#\b(?:Firefox|FxiOS)/#'              => 'Firefox',
			'#\bCriOS/#'                          => 'Chrome',
			'#; wv\)#'                            => 'Android WebView',
			'#\bChrom(?:e|ium)/#'                 => 'Chrome',
			'#\bVersion/[\d.]+.*\bSafari/#'       => 'Safari',
			'#\b(?:iPhone|iPad).*AppleWebKit/#'   => 'Safari',
			'#\bTrident/|\bMSIE #'                => 'Internet Explorer',
		);
		foreach ( $names as $pattern => $name ) {
			if ( preg_match( $pattern, $ua ) ) {
				return $name;
			}
		}
		return 'Browser';
	}
}
