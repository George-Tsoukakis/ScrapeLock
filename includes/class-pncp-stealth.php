<?php
/**
 * 3.8: Stealth, "Do not show that the site runs on WordPress". Tools that tell what a site is built with
 * (BuiltWith, Wappalyzer, WhatCMS) and vulnerability scanners read the addresses of the theme, plugin and core
 * files (/wp-content/, /wp-includes/), the REST API address (/wp-json/), the sitemap (/wp-sitemap.xml), the
 * markup only WordPress prints and a few files only WordPress has (readme.html, license.txt). With Stealth on,
 * visitors get neutral addresses instead (/assets/…), served by rules of the web server, and that markup goes.
 *
 * Opt-in and off by default. It never changes anything stored (posts keep their real image addresses): only what
 * is sent to visitors who are not signed in is rewritten, so turning it off puts everything back at once. Before
 * it turns on, the site asks itself for a few files through the new addresses and compares them byte for byte
 * with the real files: if one does not come back, nothing changes, so the site never loses its styles and scripts.
 * A check twice a day turns it off again on its own if the rules stop working (e.g. after moving host).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Neutral asset addresses, REST prefix and sitemap address, removal of WordPress-only markup, server rules with a
 * self-test, and a scan for what still shows that the site runs on WordPress.
 */
final class PNCP_Stealth {

	/**
	 * Option with the state that was tested: the address map, the rules, the result of the self-test.
	 */
	const OPTION = 'pncp_stealth';

	/**
	 * Transient with the result of the last scan (only codes, signature ids and short snippets of public pages).
	 */
	const SCAN = 'pncp_stealth_scan';

	/**
	 * Marker of the block in the site's .htaccess.
	 */
	const MARKER = 'ScrapeLock Stealth';

	/**
	 * Twice-daily check of the rules (turns Stealth off on its own when they stop working).
	 */
	const CRON = 'pncp_stealth_check';

	/**
	 * Single event after a plugin, theme or WordPress update: the address map follows the change.
	 */
	const REFRESH = 'pncp_stealth_refresh';

	/**
	 * Single event after ScrapeLock is activated again: Stealth is tested and turned on if it was on.
	 */
	const RESTART = 'pncp_stealth_restart';

	/**
	 * Admin-post / nonce actions.
	 */
	const ACTION_SAVE = 'pncp_stealth_save';
	const ACTION_TEST = 'pncp_stealth_test';
	const ACTION_OFF  = 'pncp_stealth_off';
	const ACTION_SCAN = 'pncp_stealth_scan';

	/**
	 * Ajax / admin-post action the self-test calls through the new addresses.
	 */
	const PING = 'pncp_stealth_ping';

	/**
	 * 3.8: admin-post.php action of the password form of protected posts while Stealth is on (instead of
	 * wp-login.php?action=postpass, which names WordPress and the sign-in page).
	 */
	const POSTPASS = 'pncp_postpass';

	/**
	 * The REST answer of this request was cleaned already (rest_post_dispatch also runs for embedded requests).
	 *
	 * @var bool
	 */
	private static $rest_cleaned = false;

	/**
	 * File types served through the new addresses. PHP is never among them: a PHP file keeps its real address.
	 */
	const STATIC_EXT = 'css|js|mjs|map|json|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|m4v|webm|ogg|ogv|mp3|m4a|wav|pdf|vtt';

	/**
	 * Words that give WordPress, WooCommerce and the plugins away even in a file name (Wappalyzer reads
	 * "woocommerce" and "wp-embed.min.js" anywhere in a script address). In the new addresses they are replaced
	 * with a short code that the server rules turn back into the word. The slugs of the active plugins and themes
	 * are added to these.
	 *
	 * @var string[]
	 */
	private static $fixed_words = array( 'woocommerce', 'wordpress', 'wp-embed', 'wp-emoji', 'gutenberg' );

	/**
	 * Set while ScrapeLock is being deactivated or Stealth is being turned off in this request.
	 *
	 * @var bool
	 */
	private static $off = false;

	/**
	 * Set while save() writes the settings itself (the update_option hook then does nothing).
	 *
	 * @var bool
	 */
	private static $saving = false;

	/**
	 * The rewriting regex and its replacements for this request.
	 *
	 * @var array{0:string, 1:array<string, array<string, string>>}|null
	 */
	private static $compiled = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'update_option_' . PNCP_OPTION, array( __CLASS__, 'settings_changed' ), 20, 2 );
		add_action( self::CRON, array( __CLASS__, 'check' ) );
		add_action( self::REFRESH, array( __CLASS__, 'refresh' ) );
		add_action( self::RESTART, array( __CLASS__, 'restart' ) );
		add_action( 'wp_ajax_nopriv_' . self::PING, array( __CLASS__, 'ping' ) );
		add_action( 'wp_ajax_' . self::PING, array( __CLASS__, 'ping' ) );
		add_action( 'admin_post_nopriv_' . self::PING, array( __CLASS__, 'ping' ) );
		add_action( 'admin_post_' . self::PING, array( __CLASS__, 'ping' ) );
		// Always registered: a password form printed while Stealth was on still works after it is turned off.
		add_action( 'admin_post_nopriv_' . self::POSTPASS, array( __CLASS__, 'postpass' ) );
		add_action( 'admin_post_' . self::POSTPASS, array( __CLASS__, 'postpass' ) );
		foreach ( array( 'activated_plugin', 'deactivated_plugin', 'switch_theme', 'upgrader_process_complete' ) as $hook ) {
			add_action( $hook, array( __CLASS__, 'schedule_refresh' ) );
		}
		if ( is_admin() ) {
			add_action( 'admin_post_' . self::ACTION_SAVE, array( __CLASS__, 'handle_save' ) );
			add_action( 'admin_post_' . self::ACTION_TEST, array( __CLASS__, 'handle_test' ) );
			add_action( 'admin_post_' . self::ACTION_OFF, array( __CLASS__, 'handle_off' ) );
			add_action( 'admin_post_' . self::ACTION_SCAN, array( __CLASS__, 'handle_scan' ) );
			add_action( 'wp_ajax_health-check-scrapelock-stealth', array( __CLASS__, 'ajax_health' ) );
			PNCP_Stealth_Status::init(); // 3.12.6: "copy the Stealth rules again".
		}
		add_filter( 'site_status_tests', array( __CLASS__, 'health_tests' ) );
		add_action( 'init', array( __CLASS__, 'ensure_cron' ), 30 );
		add_action( 'admin_init', array( __CLASS__, 'remember_server' ) );
		add_action( 'init', array( __CLASS__, 'heal_rules' ), 9999 );

		if ( ! self::active() ) {
			return;
		}
		if ( '' !== self::live_rest_prefix() ) {
			add_filter( 'rest_url_prefix', array( __CLASS__, 'rest_url_prefix' ), 99 );
			add_action( 'init', array( __CLASS__, 'old_rest_rules' ), 20 );
		}
		if ( self::live_sitemap() ) {
			add_action( 'init', array( __CLASS__, 'sitemap_rules' ), 20 );
			add_filter( 'home_url', array( __CLASS__, 'sitemap_url' ), 99, 2 );
			add_filter( 'wp_sitemaps_stylesheet_content', array( __CLASS__, 'sitemap_stylesheet' ), 99 );
			add_filter( 'wp_sitemaps_stylesheet_index_content', array( __CLASS__, 'sitemap_stylesheet' ), 99 );
		}
		add_action( 'parse_request', array( __CLASS__, 'old_addresses' ), 1 );
		add_action( 'init', array( __CLASS__, 'blocked_scripts' ), 1 );
		add_action( 'template_redirect', array( __CLASS__, 'start_buffer' ), -9999 );
		// 3.12.6: the final HTML of the optimization plugins, before they store it in their cache (WP Rocket's own
		// buffer is inside this one, but another order or plugin must not bring their addresses back).
		// 3.12.7: WP Rocket writes its page cache in the buffer advanced-cache.php starts before the plugins, from
		// the output of this buffer and of its optimization buffer (template_redirect 2, rocket_buffer); its last
		// stage that adds addresses runs at 110000. Not on rocket_css_url / rocket_js_url: its later stages (delay
		// JS exclusions, background CSS) need the real address of the minified file.
		foreach ( array( 'rocket_buffer', 'autoptimize_html_after_minify', 'litespeed_buffer_after', 'w3tc_process_content' ) as $hook ) {
			add_filter( $hook, array( __CLASS__, 'optimized_html' ), PHP_INT_MAX );
		}
		add_filter( 'rest_pre_echo_response', array( __CLASS__, 'rest_response' ), 99, 3 );
		add_filter( 'robots_txt', array( __CLASS__, 'robots_txt' ), 9999 );
		add_filter( 'body_class', array( __CLASS__, 'body_class' ), 99 );
		add_filter( 'wp_resource_hints', array( __CLASS__, 'resource_hints' ), 99, 2 );
		add_filter( 'emoji_svg_url', array( __CLASS__, 'emoji_svg_url' ), 99 );
		add_filter( 'the_password_form', array( __CLASS__, 'password_form' ), 99 );
		add_action( 'rest_api_init', array( __CLASS__, 'rest_headers' ), 99 );
		add_filter( 'load_script_translations', array( __CLASS__, 'script_translations' ), 99 );
	}

	/* ---------- Settings and state ---------- */

	/**
	 * Defaults of the settings of this class (keys of PNCP_Options).
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults() {
		return array(
			'stealth_enabled'     => 0,
			'stealth_base'        => 'assets',
			'stealth_rest_prefix' => '',
			'stealth_sitemap'     => 1,
			'stealth_block_files' => 1,
			'stealth_endpoints'   => 1,
		);
	}

	/**
	 * The settings in effect, with the defaults of this class where a key is missing.
	 *
	 * @return array<string, mixed>
	 */
	public static function settings() {
		$s = PNCP_Options::get();
		foreach ( self::defaults() as $key => $default ) {
			if ( ! isset( $s[ $key ] ) ) {
				$s[ $key ] = $default;
			}
		}
		return $s;
	}

	/**
	 * Sanitizes the base folder of the new addresses: 2 to 30 lower-case letters, digits, "-" and "_", not one
	 * WordPress uses. '' when unusable.
	 *
	 * @param string      $raw    Text.
	 * @param string|null $reason Why it was refused.
	 * @return string
	 */
	public static function sanitize_base( $raw, &$reason = null ) {
		$base = strtolower( trim( (string) $raw, " \t\n\r\0\x0B/" ) );
		if ( (string) preg_replace( '/[^a-z0-9_-]/', '', $base ) !== $base || strlen( $base ) < 2 || strlen( $base ) > 30 ) {
			$reason = __( 'Use 2 to 30 lower-case letters, digits, "-" or "_", e.g. assets or static.', 'scrapelock' );
			return '';
		}
		if ( self::reserved( $base ) ) {
			$reason = __( 'This address is already used by WordPress or gives it away.', 'scrapelock' );
			return '';
		}
		return $base;
	}

	/**
	 * Sanitizes the REST API prefix ('' = keep wp-json).
	 *
	 * @param string      $raw    Text.
	 * @param string|null $reason Why it was refused.
	 * @return string
	 */
	public static function sanitize_rest_prefix( $raw, &$reason = null ) {
		$prefix = strtolower( trim( (string) $raw, " \t\n\r\0\x0B/" ) );
		if ( '' === $prefix || 'wp-json' === $prefix ) {
			return '';
		}
		if ( (string) preg_replace( '/[^a-z0-9_-]/', '', $prefix ) !== $prefix || strlen( $prefix ) < 2 || strlen( $prefix ) > 30 ) {
			$reason = __( 'Use 2 to 30 lower-case letters, digits, "-" or "_", e.g. api.', 'scrapelock' );
			return '';
		}
		if ( self::reserved( $prefix ) ) {
			$reason = __( 'This address is already used by WordPress or gives it away.', 'scrapelock' );
			return '';
		}
		return $prefix;
	}

	/**
	 * Is the address one WordPress uses, one of a page or post, or one that gives WordPress away?
	 *
	 * @param string $slug Clean slug.
	 * @return bool
	 */
	private static function reserved( $slug ) {
		if ( 0 === strpos( $slug, 'wp' ) || false !== strpos( $slug, 'WordPress' ) ) {
			return true;
		}
		$taken = array( 'admin', 'login', 'dashboard', 'feed', 'comments', 'search', 'page', 'author', 'embed', 'trackback', 'sitemap', 'robots', 'index', 'xmlrpc', 'category', 'tag', 'type', 'attachment', 'favicon', 'well-known' );
		if ( in_array( $slug, $taken, true ) ) {
			return true;
		}
		if ( function_exists( 'get_page_by_path' ) && get_page_by_path( $slug ) ) {
			return true;
		}
		if ( class_exists( 'PNCP_Login' ) && PNCP_Login::slug() === $slug ) {
			return true;
		}
		return false;
	}

	/**
	 * The tested state.
	 *
	 * @return array<string, mixed>
	 */
	public static function state() {
		$state = get_option( self::OPTION, array() );
		$state = is_array( $state ) ? $state : array();
		return array_merge(
			array(
				'active'   => 0,
				'sig'      => '',
				'base'     => '',
				'map'      => array(),
				'words'    => array(),
				'ends'     => array(),
				'server'   => '',
				'tested'   => 0,
				'error'    => '',
				'fails'    => 0,
				'htaccess' => 0,
				'pending'  => '',
				'auto_off' => 0,
				'rest'     => '',
				'sitemap'  => 0,
				'files'    => 0,
				'seen'     => '',
			),
			$state
		);
	}

	/**
	 * Saves the state (autoloaded: it is read on every page view, without a query).
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function save_state( $state ) {
		update_option( self::OPTION, $state, true );
		self::$compiled = null;
		PNCP_Stealth_Status::reset();
	}

	/**
	 * Is Stealth on and its rules tested? Recovery: define( 'SCRAPELOCK_STEALTH_OFF', true ); in wp-config.php.
	 *
	 * @return bool
	 */
	public static function active() {
		if ( self::$off || ( defined( 'SCRAPELOCK_STEALTH_OFF' ) && SCRAPELOCK_STEALTH_OFF ) || is_multisite() ) {
			return false;
		}
		$s = self::settings();
		if ( empty( $s['enabled'] ) || empty( $s['stealth_enabled'] ) ) {
			return false;
		}
		$state = self::state();
		return ! empty( $state['active'] ) && (string) $state['base'] === (string) $s['stealth_base'] && ! empty( $state['map'] );
	}

	/**
	 * The REST prefix in effect ('' = wp-json).
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	private static function rest_prefix( $s ) {
		// 3.8 (integration): only the form is checked here, as it runs on every request (old_addresses(), init).
		// The stored value went through sanitize_rest_prefix() when it was saved; its page lookup is a query.
		$prefix = strtolower( trim( (string) $s['stealth_rest_prefix'], " \t\n\r\0\x0B/" ) );
		if ( '' === $prefix || 'wp-json' === $prefix || (string) preg_replace( '/[^a-z0-9_-]/', '', $prefix ) !== $prefix || strlen( $prefix ) < 2 || strlen( $prefix ) > 30 ) {
			return '';
		}
		return $prefix;
	}

	/**
	 * The REST prefix in effect now: the tested one, while the setting still asks for it ('' = wp-json).
	 *
	 * @return string
	 */
	private static function live_rest_prefix() {
		$tested = (string) self::state()['rest'];
		return '' !== $tested && self::rest_prefix( self::settings() ) === $tested ? $tested : '';
	}

	/**
	 * Is the sitemap at /sitemap.xml now (tested, still asked for, pretty permalinks)?
	 *
	 * @return bool
	 */
	private static function live_sitemap() {
		return ! empty( self::state()['sitemap'] ) && ! empty( self::settings()['stealth_sitemap'] ) && '' !== (string) get_option( 'permalink_structure' );
	}

	/**
	 * Does the sitemap get the address /sitemap.xml? Only with WordPress's own sitemaps and pretty permalinks,
	 * and not when a file sitemap.xml exists.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return bool
	 */
	private static function sitemap_on( $s ) {
		if ( empty( $s['stealth_sitemap'] ) || '' === (string) get_option( 'permalink_structure' ) ) {
			return false;
		}
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		return ! file_exists( trailingslashit( get_home_path() ) . 'sitemap.xml' );
	}

	/* ---------- The address map ---------- */

	/**
	 * The folders that get a neutral address: the active themes and plugins, the must-use plugins, the uploads,
	 * wp-includes and (for anything else in it, e.g. a plugin activated since) wp-content. Only folders served from
	 * this site's own host.
	 *
	 * @return array{map: array<string, array<string, string>>, words: array<string, string>, ends: array<string, string>}
	 */
	public static function build() {
		$dirs  = array();
		$slugs = array();
		$add   = function ( $kind, $url, $dir, $slug = '' ) use ( &$dirs, &$slugs ) {
			$path = self::same_host_path( $url );
			if ( '' === $path || ! is_dir( $dir ) || ! self::rule_safe_path( $path ) ) {
				return;
			}
			$dirs[ $kind . '|' . $path ] = array(
				'kind' => $kind,
				'path' => $path,
				'dir'  => wp_normalize_path( untrailingslashit( $dir ) ),
			);
			if ( '' !== $slug && strlen( $slug ) >= 4 && preg_match( '/^[a-z0-9_-]+$/', $slug ) ) {
				$slugs[] = $slug;
			}
		};

		$add( 'includes', includes_url(), ABSPATH . WPINC );
		$add( 'content', content_url(), WP_CONTENT_DIR );
		$uploads = wp_upload_dir( null, false );
		if ( empty( $uploads['error'] ) ) {
			$add( 'uploads', $uploads['baseurl'], $uploads['basedir'] );
		}
		// The folders of all plugins and themes: a plugin or theme added later is served through these (its folder
		// name shows until the map is brought up to date).
		$add( 'plugins', plugins_url(), WP_PLUGIN_DIR );
		$add( 'themes', get_theme_root_uri(), get_theme_root() );
		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			$add( 'mu', WPMU_PLUGIN_URL, WPMU_PLUGIN_DIR );
		}
		foreach ( array_unique( array( get_stylesheet(), get_template() ) ) as $theme ) {
			$t = wp_get_theme( $theme );
			if ( $t->exists() ) {
				$add( 'theme', $t->get_stylesheet_directory_uri(), $t->get_stylesheet_directory(), $theme );
			}
		}
		foreach ( (array) get_option( 'active_plugins', array() ) as $file ) {
			$folder = dirname( (string) $file );
			if ( '.' === $folder || '' === $folder ) {
				continue;
			}
			$add( 'plugin', plugins_url( $folder ), WP_PLUGIN_DIR . '/' . $folder, strtolower( $folder ) );
		}

		$map  = array();
		$used = array();
		foreach ( $dirs as $key => $entry ) {
			$n = 0;
			do {
				$alias = substr( wp_hash( 'pncp-stealth|' . $key . '|' . $n ), 0, 6 );
				++$n;
			} while ( isset( $used[ $alias ] ) || ctype_digit( $alias ) );
			$used[ $alias ] = true;
			$map[ $alias ]  = $entry;
		}
		// Longest real address first: a plugin before wp-content.
		uasort(
			$map,
			function ( $a, $b ) {
				return strlen( $b['path'] ) - strlen( $a['path'] );
			}
		);

		$words = array();
		foreach ( array_unique( array_merge( self::$fixed_words, $slugs, self::cache_words() ) ) as $word ) {
			$words[ 'q' . substr( wp_hash( 'pncp-stealth-word|' . $word ), 0, 6 ) ] = $word;
		}

		$ends = array();
		foreach ( array(
			'ajax'    => admin_url( 'admin-ajax.php' ),
			'post'    => admin_url( 'admin-post.php' ),
			'comment' => site_url( 'wp-comments-post.php' ),
		) as $name => $url ) {
			$path = self::same_host_path( $url );
			if ( '' !== $path ) {
				$ends[ $name ] = $path;
			}
		}

		return array(
			'map'   => $map,
			'words' => $words,
			'ends'  => $ends,
		);
	}

	/**
	 * 3.12.8: can a folder's path be written as the target of a rule? A space (a plugin uploaded as "my plugin (2)"),
	 * a quote, ";", "{", "$" or "%" would break the Nginx rules (nginx -t fails) or the .htaccess (every page answers
	 * 500 until the self-test puts it back). Such a folder gets no address of its own: its files are served through
	 * the address of the folder above it (plugins, themes, wp-content).
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	private static function rule_safe_path( $path ) {
		return (bool) preg_match( '#^[A-Za-z0-9._~@+/-]+$#', (string) $path );
	}

	/**
	 * 3.12.6: the optimization plugins whose files carry a second WordPress address inside their own address. WP
	 * Rocket's minified copies keep the path of the original file (wp-content/cache/min/1/wp-content/themes/…,
	 * cache/busting/1/wp-includes/…, cache/background-css/1/<host>/wp-content/…); Autoptimize (cache/autoptimize/),
	 * LiteSpeed Cache (litespeed/css|js/) and W3 Total Cache (cache/minify/) write files with neutral names in
	 * wp-content, which the general wp-content address already serves. Active plugin, its constant, or (WP Rocket)
	 * its cache folders. Filter `pncp_stealth_optimizers`.
	 *
	 * @return string[] wp-rocket, autoptimize, litespeed, w3tc.
	 */
	public static function optimizers() {
		$active = (array) get_option( 'active_plugins', array() );
		$known  = array(
			'wp-rocket'   => array( 'wp-rocket/wp-rocket.php', 'WP_ROCKET_VERSION' ),
			'autoptimize' => array( 'autoptimize/autoptimize.php', 'AUTOPTIMIZE_PLUGIN_VERSION' ),
			'litespeed'   => array( 'litespeed-cache/litespeed-cache.php', 'LSCWP_V' ),
			'w3tc'        => array( 'w3-total-cache/w3-total-cache.php', 'W3TC_VERSION' ),
		);
		$out    = array();
		foreach ( $known as $name => $how ) {
			if ( in_array( $how[0], $active, true ) || defined( $how[1] ) ) {
				$out[] = $name;
			}
		}
		if ( ! in_array( 'wp-rocket', $out, true ) ) {
			foreach ( array( 'min', 'busting', 'background-css' ) as $folder ) {
				if ( is_dir( WP_CONTENT_DIR . '/cache/' . $folder ) ) {
					$out[] = 'wp-rocket';
					break;
				}
			}
		}
		/**
		 * 3.12.6: the optimization plugins Stealth adapts its addresses to.
		 *
		 * @param string[] $out wp-rocket, autoptimize, litespeed, w3tc.
		 */
		return array_values( array_unique( array_map( 'strval', (array) apply_filters( 'pncp_stealth_optimizers', $out ) ) ) );
	}

	/**
	 * 3.12.6: the words of the inner addresses of the optimization plugins' files: the last folder of the content
	 * and core addresses (wp-content, wp-includes) and LiteSpeed Cache's folder. Like the other words they get a
	 * code in the new addresses that the server rules turn back, so every file such a plugin writes later is
	 * served by the same few rules (no list of files). Nothing without an optimization plugin: the rules of other
	 * sites stay as they were.
	 *
	 * @return string[]
	 */
	public static function cache_words() {
		$optimizers = self::optimizers();
		if ( ! $optimizers ) {
			return array();
		}
		$words = array();
		foreach ( array( content_url(), includes_url() ) as $url ) {
			$last = basename( (string) self::same_host_path( $url ) );
			if ( false !== strpos( $last, 'wp-' ) ) {
				$words[] = $last;
			}
		}
		$words[] = 'wp-content'; // An optimization plugin's copy of a file of a site that moved its content folder.
		$words[] = 'wp-includes';
		if ( in_array( 'litespeed', $optimizers, true ) ) {
			$words[] = 'litespeed';
		}
		return array_values(
			array_unique(
				array_filter(
					$words,
					function ( $w ) {
						return (bool) preg_match( '/^[a-z0-9_.-]{4,}$/i', $w );
					}
				)
			)
		);
	}

	/**
	 * The path of an address on this site's host ('' for another host), without the trailing slash.
	 *
	 * @param string $url Address.
	 * @return string
	 */
	private static function same_host_path( $url ) {
		$host = strtolower( (string) wp_parse_url( (string) $url, PHP_URL_HOST ) );
		if ( '' === $host || ! in_array( $host, self::hosts(), true ) ) {
			return '';
		}
		$path = (string) wp_parse_url( (string) $url, PHP_URL_PATH );
		return '/' . trim( $path, '/' );
	}

	/**
	 * The host names of this site (home and WordPress address), with the port when there is one.
	 *
	 * @param bool $port With the port.
	 * @return string[]
	 */
	private static function hosts( $port = false ) {
		$out = array();
		foreach ( array( home_url(), site_url() ) as $url ) {
			$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
			if ( '' === $host ) {
				continue;
			}
			$p     = wp_parse_url( $url, PHP_URL_PORT );
			$out[] = $port && $p ? $host . ':' . $p : $host;
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * The path of the home page, with slashes on both ends ("/" or "/blog/").
	 *
	 * @return string
	 */
	private static function home_path() {
		$path = trim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );
		return '' === $path ? '/' : '/' . $path . '/';
	}

	/**
	 * A signature of a configuration: what the self-test proved.
	 *
	 * @param string               $base   Base folder.
	 * @param array<string, mixed> $config build() result.
	 * @return string
	 */
	private static function signature( $base, $config ) {
		return md5( (string) wp_json_encode( array( $base, $config['map'], $config['words'], $config['ends'] ) ) );
	}

	/* ---------- Server rules ---------- */

	/**
	 * Which web server: apache (also LiteSpeed, reads .htaccess), nginx, or other.
	 *
	 * @return string
	 */
	public static function server() {
		global $is_apache, $is_nginx;
		$server = ! empty( $is_apache ) ? 'apache' : ( ! empty( $is_nginx ) ? 'nginx' : 'other' );
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			// No web server in WP-CLI (and cron may run from the command line): the one last seen in wp-admin.
			$seen   = (string) self::state()['seen'];
			$server = '' !== $seen ? $seen : $server;
		}
		/**
		 * Filters the detected web server (apache, nginx or other).
		 *
		 * @param string $server Server.
		 */
		return (string) apply_filters( 'pncp_stealth_server', $server );
	}

	/**
	 * Remembers the web server seen in wp-admin, for WP-CLI and cron (written only when it changes).
	 */
	public static function remember_server() {
		if ( wp_doing_ajax() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$server = self::server();
		$state  = self::state();
		if ( $state['seen'] !== $server ) {
			$state['seen'] = $server;
			self::save_state( $state );
		}
	}

	/**
	 * The pattern of the old WordPress files blocked for visitors, relative to the home folder.
	 *
	 * @return string[]
	 */
	private static function blocked_files() {
		$site = self::same_host_path( site_url( '/' ) );
		$home = rtrim( self::home_path(), '/' );
		$rel  = ltrim( 0 === strpos( $site, $home ) ? substr( $site, strlen( $home ) ) : $site, '/' );
		$rel  = '' === $rel ? '' : trailingslashit( $rel );
		$out  = array();
		foreach ( array( 'readme.html', 'license.txt', 'wp-config-sample.php', 'wp-links-opml.php', 'wp-trackback.php' ) as $file ) {
			$out[] = $rel . $file;
		}
		return $out;
	}

	/**
	 * Should the server refuse readme.html and the like? Not in Monitor only (nothing is refused then).
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return bool
	 */
	private static function blocks_files( $s ) {
		return ! empty( $s['stealth_block_files'] ) && ! PNCP_Options::monitoring();
	}

	/**
	 * The lines of the rules, for Apache (in .htaccess, relative to the home folder) or Nginx (in server { }).
	 *
	 * @param string               $server apache | nginx.
	 * @param string               $base   Base folder.
	 * @param array<string, mixed> $config build() result.
	 * @return string[]
	 */
	public static function rule_lines( $server, $base, $config ) {
		$s     = self::settings();
		$ext   = self::STATIC_EXT;
		$home  = self::home_path();
		$lines = array();
		$q     = preg_quote( $base, '#' );
		if ( 'apache' === $server ) {
			$lines[] = '<IfModule mod_rewrite.c>';
			$lines[] = 'RewriteEngine On';
			$lines[] = 'RewriteBase ' . $home;
			foreach ( $config['words'] as $token => $word ) {
				// Twice: a word can be in the address two times (folder and file name).
				$lines[] = 'RewriteRule ^(' . $q . '/[0-9a-f]{6}/.*?)' . $token . '(.*)$ $1' . $word . '$2 [DPI]';
				$lines[] = 'RewriteRule ^(' . $q . '/[0-9a-f]{6}/.*?)' . $token . '(.*)$ $1' . $word . '$2 [DPI]';
			}
			foreach ( $config['map'] as $alias => $entry ) {
				$lines[] = 'RewriteRule ^' . $q . '/' . $alias . '/(.+\.(?:' . $ext . '))$ ' . $entry['path'] . '/$1 [L,NC]';
			}
			$lines = array_merge( $lines, self::sibling_lines( 'apache', $q, $config ) );
			if ( ! empty( $s['stealth_endpoints'] ) ) {
				foreach ( $config['ends'] as $name => $path ) {
					$lines[] = 'RewriteRule ^' . $q . '/' . $name . '$ ' . $path . ' [L,QSA]';
				}
			}
			if ( self::blocks_files( $s ) ) {
				$files   = array_map(
					function ( $f ) {
						return preg_quote( $f, '#' );
					},
					self::blocked_files()
				);
				$lines[] = 'RewriteRule ^(?:' . implode( '|', $files ) . ')$ - [R=404,L,NC]';
			}
			$lines[] = '</IfModule>';
			return PNCP_Stealth_Status::with_fingerprint( 'apache', $lines ); // 3.12.6: the installed rules can be checked.
		}
		$lines[] = '# Inside the site\'s server { }, above the location blocks. Then nginx -t and reload.';
		$prefix  = $home . $base;
		foreach ( $config['words'] as $token => $word ) {
			$lines[] = 'rewrite "^(' . $prefix . '/[0-9a-f]{6}/.*?)' . $token . '(.*)$" $1' . $word . '$2;';
			$lines[] = 'rewrite "^(' . $prefix . '/[0-9a-f]{6}/.*?)' . $token . '(.*)$" $1' . $word . '$2;';
		}
		foreach ( $config['map'] as $alias => $entry ) {
			$lines[] = 'rewrite "(?i)^' . $prefix . '/' . $alias . '/(.+\.(?:' . $ext . '))$" ' . $entry['path'] . '/$1 last;';
		}
		$lines = array_merge( $lines, self::sibling_lines( 'nginx', $prefix, $config ) );
		if ( ! empty( $s['stealth_endpoints'] ) ) {
			foreach ( $config['ends'] as $name => $path ) {
				$lines[] = 'rewrite "^' . $prefix . '/' . $name . '$" ' . $path . ' last;';
			}
		}
		if ( self::blocks_files( $s ) ) {
			$lines[] = 'location ~* "^' . $home . '(?:' . implode( '|', array_map( 'preg_quote', self::blocked_files() ) ) . ')$" { return 404; }';
		}
		return PNCP_Stealth_Status::with_fingerprint( 'nginx', $lines ); // 3.12.6: the installed rules can be checked.
	}

	/**
	 * 3.12.8: a stylesheet or script served at /<base>/<alias>/… that reaches a sibling folder with "../" (a child
	 * theme's @import url("../parent/style.css"), a plugin's url(../../other-plugin/img.png)) makes the browser ask
	 * for /<base>/<sibling>/…, one level above the aliases. One rule per parent folder of the map (themes, plugins,
	 * wp-content) serves those siblings from their real folder; only the folders of the map, static types only.
	 *
	 * @param string               $server apache | nginx.
	 * @param string               $prefix The start of the patterns (Apache: the base, quoted; Nginx: home path + base).
	 * @param array<string, mixed> $config build() result.
	 * @return string[]
	 */
	private static function sibling_lines( $server, $prefix, $config ) {
		$groups = array();
		$used   = array();
		foreach ( (array) $config['map'] as $entry ) {
			if ( in_array( (string) $entry['kind'], array( 'content', 'includes' ), true ) ) {
				continue;
			}
			$name   = basename( (string) $entry['path'] );
			$parent = dirname( (string) $entry['path'] );
			if ( isset( $used[ $name ] ) || preg_match( '/^[0-9a-f]{6}$/', $name ) || isset( $config['ends'][ $name ] ) || ! preg_match( '/^[A-Za-z0-9._-]+$/', $name ) || '/' === $parent ) {
				continue;
			}
			$used[ $name ]         = true;
			$groups[ $parent ][] = preg_quote( $name, '#' );
		}
		$lines = array();
		foreach ( $groups as $parent => $names ) {
			if ( count( $names ) < 2 ) {
				continue; // A folder's only sibling of the map is itself.
			}
			$pattern = '/(' . implode( '|', $names ) . ')/(.+\.(?:' . self::STATIC_EXT . '))$';
			$lines[] = 'apache' === $server
				? 'RewriteRule ^' . $prefix . $pattern . ' ' . $parent . '/$1/$2 [L,NC]'
				: 'rewrite "(?i)^' . $prefix . $pattern . '" ' . $parent . '/$1/$2 last;';
		}
		return $lines;
	}

	/**
	 * The rules for copying by hand, with the markers.
	 *
	 * @param string $server apache | nginx.
	 * @return string
	 */
	public static function rules_text( $server ) {
		$s      = self::settings();
		$base   = self::sanitize_base( (string) $s['stealth_base'] );
		$base   = '' === $base ? 'assets' : $base;
		$config = self::build();
		$lines  = self::rule_lines( 'apache' === $server ? 'apache' : 'nginx', $base, $config );
		return '# BEGIN ' . self::MARKER . "\n" . implode( "\n", $lines ) . "\n# END " . self::MARKER . "\n";
	}

	/**
	 * The site's .htaccess (in the folder of the home page).
	 *
	 * @return string
	 */
	private static function htaccess_file() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		return trailingslashit( get_home_path() ) . '.htaccess';
	}

	/**
	 * Can the rules be written into .htaccess?
	 *
	 * @return bool
	 */
	public static function htaccess_writable() {
		$file = self::htaccess_file();
		return 'apache' === self::server() && ( file_exists( $file ) ? wp_is_writable( $file ) : wp_is_writable( dirname( $file ) ) );
	}

	/**
	 * A text without the Stealth block (and the blank line written after it).
	 *
	 * @param string $text File contents.
	 * @return string
	 */
	private static function without_block( $text ) {
		$marker = preg_quote( self::MARKER, '/' );
		return (string) preg_replace( '/^# BEGIN ' . $marker . '\R.*?^# END ' . $marker . '(?:\R\R?|\z)/ms', '', (string) $text, 1 );
	}

	/**
	 * Writes the block into .htaccess above "# BEGIN WordPress" (or at the top): the place is prepared with empty
	 * markers, then insert_with_markers() fills it.
	 *
	 * @param string[] $lines Rules.
	 * @return bool
	 */
	private static function write_htaccess( $lines ) {
		$file = self::htaccess_file();
		if ( ! self::htaccess_writable() ) {
			return false;
		}
		$text = file_exists( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( false === strpos( $text, '# BEGIN ' . self::MARKER ) ) {
			$empty = '# BEGIN ' . self::MARKER . "\n# END " . self::MARKER . "\n\n";
			$pos   = strpos( $text, '# BEGIN WordPress' );
			$text  = false === $pos ? $empty . $text : substr( $text, 0, $pos ) . $empty . substr( $text, $pos );
			if ( false === file_put_contents( $file, $text, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- The site's own .htaccess; only the empty markers are added here.
				return false;
			}
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$ok = insert_with_markers( $file, self::MARKER, $lines );
		clearstatcache();
		return (bool) $ok;
	}

	/**
	 * Removes the block from .htaccess; the rest of the file stays byte for byte as it was.
	 *
	 * @return bool
	 */
	public static function remove_htaccess() {
		$file = self::htaccess_file();
		if ( ! is_readable( $file ) ) {
			return true;
		}
		$text = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( false === strpos( $text, '# BEGIN ' . self::MARKER ) ) {
			return true;
		}
		if ( ! wp_is_writable( $file ) ) {
			return false;
		}
		$ok = false !== file_put_contents( $file, self::without_block( $text ), LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- The site's own file, only our block goes.
		clearstatcache();
		return $ok;
	}

	/**
	 * The current .htaccess, to put it back after a failed test (null = it did not exist).
	 *
	 * @return string|null
	 */
	private static function htaccess_backup() {
		$file = self::htaccess_file();
		return file_exists( $file ) ? (string) file_get_contents( $file ) : null; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Puts .htaccess back.
	 *
	 * @param string|null $before Contents (null = delete).
	 */
	private static function htaccess_restore( $before ) {
		$file = self::htaccess_file();
		if ( null === $before ) {
			wp_delete_file( $file );
		} else {
			file_put_contents( $file, $before, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Puts back the site's own file.
		}
		clearstatcache();
	}

	/* ---------- Turning on and off ---------- */

	/**
	 * Why a change is refused now (null = allowed).
	 *
	 * @return WP_Error|null
	 */
	private static function refusal() {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked with Lockdown: unlock it to change Stealth.', 'scrapelock' ) );
		}
		if ( is_multisite() ) {
			return new WP_Error( 'pncp_multisite', __( 'Stealth is not available on multisite networks.', 'scrapelock' ) );
		}
		return null;
	}

	/**
	 * Tests the rules and turns Stealth on (writes .htaccess on Apache first; on Nginx and other servers the
	 * rules must already be in the server configuration). Nothing changes when a test fails.
	 *
	 * @param bool $check Refuse while locked.
	 * @return true|WP_Error
	 */
	public static function activate( $check = true ) {
		if ( $check ) {
			$refused = self::refusal();
			if ( $refused ) {
				return $refused;
			}
		}
		$s    = self::settings();
		$base = self::sanitize_base( (string) $s['stealth_base'] );
		if ( '' === $base ) {
			return new WP_Error( 'pncp_stealth_base', __( 'The base folder of the new addresses is not usable.', 'scrapelock' ) );
		}
		$config = self::build();
		$server = self::server();
		$state  = self::state();
		$wrote  = false;
		$before = null;
		if ( 'apache' === $server && self::htaccess_writable() ) {
			$before = self::htaccess_backup();
			$wrote  = self::write_htaccess( self::rule_lines( 'apache', $base, $config ) );
		}
		$result = self::self_test( $base, $config );
		if ( is_wp_error( $result ) ) {
			if ( $wrote ) {
				self::htaccess_restore( $before );
			}
			$was_active        = ! empty( $state['active'] );
			$state['active']   = 0;
			$state['error']    = $result->get_error_message();
			$state['tested']   = time();
			$state['server']   = $server;
			$state['htaccess'] = (int) ( false !== strpos( (string) self::htaccess_backup(), '# BEGIN ' . self::MARKER ) );
			if ( $state['htaccess'] ) {
				$state['htaccess'] = self::remove_htaccess() ? 0 : 1; // The old block was put back: it goes too, Stealth is off.
			}
			self::save_state( $state );
			if ( $was_active ) {
				self::reset_rewrite_rules();
			}
			return $result;
		}
		$was                = ! empty( $state['active'] ) ? (string) $state['sig'] . '|' . (string) $state['rest'] . '|' . (int) $state['sitemap'] : '';
		$state['active']    = 1;
		$state['sig']       = self::signature( $base, $config );
		$state['base']      = $base;
		$state['map']       = $config['map'];
		$state['words']     = $config['words'];
		$state['ends']      = ! empty( $s['stealth_endpoints'] ) ? $config['ends'] : array();
		$state['server']    = $server;
		$state['tested']    = time();
		$state['error']     = '';
		$state['fails']     = 0;
		$state['htaccess']  = $wrote ? 1 : 0;
		$state['pending']   = '';
		$state['auto_off']  = 0;
		$state['rest']      = self::rest_prefix( $s );
		$state['sitemap']   = self::sitemap_on( $s ) ? 1 : 0;
		$state['files']     = self::blocks_files( $s ) ? 1 : 0;
		$state['activated'] = isset( $state['activated'] ) && $was ? $state['activated'] : time();
		self::save_state( $state );
		if ( $was !== $state['sig'] . '|' . $state['rest'] . '|' . $state['sitemap'] ) {
			self::reset_rewrite_rules();
			self::purge_page_cache();
		}
		self::note( 'stealth_on' );
		return true;
	}

	/**
	 * Turns the rewriting off and removes the rules from .htaccess (the setting is left as it is).
	 *
	 * @param string $why Why ('' = asked; 'auto' = the check found the rules no longer work).
	 * @return true|WP_Error
	 */
	public static function deactivate( $why = '' ) {
		$state             = self::state();
		$was               = ! empty( $state['active'] );
		self::$off         = true;
		$removed           = self::remove_htaccess();
		$state['active']   = 0;
		$state['htaccess'] = $removed ? 0 : (int) $state['htaccess'];
		$state['auto_off'] = 'auto' === $why ? time() : 0;
		if ( 'auto' === $why ) {
			$state['error'] = __( 'The new addresses stopped working, so Stealth turned itself off. Check the server rules and test again.', 'scrapelock' );
		}
		self::save_state( $state );
		if ( $was ) {
			self::reset_rewrite_rules();
			self::purge_page_cache();
		}
		self::note( 'auto' === $why ? 'stealth_auto_off' : 'stealth_off' );
		return $removed ? true : new WP_Error( 'pncp_not_writable', __( 'The .htaccess file cannot be written: remove the ScrapeLock Stealth block yourself.', 'scrapelock' ) );
	}

	/**
	 * The rewrite rules are built again on the next request, with the REST and sitemap addresses in effect then
	 * (here the hooks of this request still have the old ones). One write, once.
	 */
	private static function reset_rewrite_rules() {
		delete_option( 'rewrite_rules' );
	}

	/**
	 * 3.12.6: the addresses of the pages changed (Stealth on, off, another map): the page cache plugins' stored
	 * pages (WP Rocket, LiteSpeed Cache, W3 Total Cache and the others pncp_purge_page_cache() knows) are emptied,
	 * so no stored page keeps addresses the server rules no longer serve. A CDN's cache is not: purge it there.
	 */
	private static function purge_page_cache() {
		if ( function_exists( 'pncp_purge_page_cache' ) ) {
			pncp_purge_page_cache();
		}
	}

	/**
	 * The stored rewrite rules must have the REST and sitemap addresses in effect now. They do not when Stealth
	 * was turned off without a new request in between (SCRAPELOCK_STEALTH_OFF, the protection switched off, the
	 * self-check): the rules are then built again in this request, before WordPress reads them. One array lookup
	 * per request, a write only when they do not match.
	 */
	public static function heal_rules() {
		// Only a site where Stealth once moved the REST API or the sitemap can have rules with other addresses.
		// A site whose rules lack the REST key for another reason (a plugin that removes the REST API) is left
		// alone, or every page view would build the rules again.
		$state = self::state();
		if ( ( '' === (string) $state['rest'] && empty( $state['sitemap'] ) ) || '' === (string) get_option( 'permalink_structure' ) ) {
			return;
		}
		$rules = get_option( 'rewrite_rules' );
		if ( ! is_array( $rules ) || ! $rules ) {
			return;
		}
		$ok = isset( $rules[ '^' . rest_get_url_prefix() . '/?$' ] );
		if ( $ok && self::active() && self::live_sitemap() ) {
			$ok = isset( $rules['^sitemap-([a-z]+?)-(\d+?)\.xml$'] );
		}
		// At most once an hour: if the rebuilt rules still do not match, something else shapes them.
		if ( ! $ok && PNCP_Log::cache_add( 'pncp_stealth_heal', time(), HOUR_IN_SECONDS ) ) {
			self::reset_rewrite_rules();
		}
	}

	/**
	 * For the activation of ScrapeLock: if Stealth was on, it is tested and turned on again a little later (the
	 * self-test needs ScrapeLock active, which it is only once the activation has finished).
	 */
	public static function plugin_activated() {
		$s = self::settings();
		if ( ! empty( $s['enabled'] ) && ! empty( $s['stealth_enabled'] ) && ! is_multisite() && ! wp_next_scheduled( self::RESTART ) ) {
			wp_schedule_single_event( time() + 30, self::RESTART );
		}
	}

	/**
	 * The event of plugin_activated().
	 */
	public static function restart() {
		$s = self::settings();
		if ( ! empty( $s['enabled'] ) && ! empty( $s['stealth_enabled'] ) && ! self::active() ) {
			self::activate( false );
		}
	}

	/**
	 * For the deactivation of ScrapeLock: the rules go, the addresses are WordPress's own again, the events stop.
	 */
	public static function plugin_deactivated() {
		self::$off = true;
		self::remove_htaccess();
		$state = self::state();
		if ( ! empty( $state['active'] ) ) {
			$state['active'] = 0;
			update_option( self::OPTION, $state, true );
			self::reset_rewrite_rules();
		}
		wp_clear_scheduled_hook( self::CRON );
		wp_clear_scheduled_hook( self::REFRESH );
		wp_clear_scheduled_hook( self::RESTART );
	}

	/**
	 * For uninstall: everything this class stored.
	 */
	public static function uninstall() {
		self::$off = true;
		self::remove_htaccess();
		delete_option( self::OPTION );
		delete_transient( self::SCAN );
		delete_option( 'rewrite_rules' );
		wp_clear_scheduled_hook( self::CRON );
		wp_clear_scheduled_hook( self::REFRESH );
		wp_clear_scheduled_hook( self::RESTART );
	}

	/**
	 * The settings were saved (settings form, import, WP-CLI): Stealth follows the switch and the base folder.
	 *
	 * @param mixed $old   Old value.
	 * @param mixed $value New value.
	 */
	public static function settings_changed( $old, $value ) {
		$new = $value;
		if ( self::$saving || ! is_array( $new ) ) {
			return;
		}
		$old  = is_array( $old ) ? $old : array();
		$keys = array_keys( self::defaults() );
		$diff = false;
		foreach ( $keys as $key ) {
			if ( ( isset( $old[ $key ] ) ? (string) $old[ $key ] : '' ) !== ( isset( $new[ $key ] ) ? (string) $new[ $key ] : '' ) ) {
				$diff = true;
			}
		}
		$was_on = ! empty( $old['enabled'] ) && ! empty( $old['stealth_enabled'] );
		$is_on  = ! empty( $new['enabled'] ) && ! empty( $new['stealth_enabled'] );
		if ( ! $diff && $was_on === $is_on && ( ! isset( $old['monitor_mode'] ) || ( isset( $new['monitor_mode'] ) && (string) $old['monitor_mode'] === (string) $new['monitor_mode'] ) ) ) {
			return;
		}
		PNCP_Options::flush();
		if ( $is_on ) {
			self::activate( false ); // The save itself was allowed; a failed test leaves Stealth off.
		} elseif ( $was_on || ! empty( self::state()['active'] ) ) {
			self::deactivate();
		}
	}

	/**
	 * Saves settings of this class through the same sanitizing as the settings form, then tests and turns on or off.
	 *
	 * @param array<string, mixed> $changes Key => value.
	 * @return true|WP_Error
	 */
	public static function save( $changes ) {
		$refused = self::refusal();
		if ( $refused ) {
			return $refused;
		}
		$stored = PNCP_Options::stored();
		foreach ( (array) $changes as $key => $value ) {
			if ( array_key_exists( $key, self::defaults() ) ) {
				$stored[ $key ] = $value;
			}
		}
		if ( ! has_filter( 'sanitize_option_' . PNCP_OPTION ) ) {
			$stored = PNCP_Options::sanitize( $stored );
		}
		self::$saving = true;
		update_option( PNCP_OPTION, $stored );
		self::$saving = false;
		PNCP_Options::flush();
		$s = self::settings();
		foreach ( (array) $changes as $key => $value ) {
			if ( array_key_exists( $key, self::defaults() ) && (string) $s[ $key ] !== (string) $value ) {
				return new WP_Error( 'pncp_setting', __( 'The setting could not be changed.', 'scrapelock' ) );
			}
		}
		if ( ! empty( $s['stealth_enabled'] ) ) {
			if ( empty( $s['enabled'] ) ) {
				return new WP_Error( 'pncp_disabled', __( 'Saved, but the ScrapeLock protection is off: Stealth starts when it is turned on.', 'scrapelock' ) );
			}
			return self::activate();
		}
		return self::deactivate();
	}

	/* ---------- Self-test ---------- */

	/**
	 * Asks the site for files through the new addresses and compares them with the real files, byte for byte;
	 * the ajax, admin-post and comment addresses must answer like the real ones, and a PHP file must not run
	 * through the new addresses. Filter pncp_stealth_self_test decides instead (bool or WP_Error).
	 *
	 * @param string               $base   Base folder.
	 * @param array<string, mixed> $config build() result.
	 * @param int                  $max    Most folders to test (0 = all).
	 * @return true|WP_Error
	 */
	public static function self_test( $base, $config, $max = 0 ) {
		/**
		 * Filters the self-test of the new addresses. Return true or a WP_Error to decide yourself.
		 *
		 * @param true|WP_Error|null $pre    Null = make the test.
		 * @param string             $base   Base folder.
		 * @param array              $config Address map.
		 */
		$pre = apply_filters( 'pncp_stealth_self_test', null, $base, $config );
		if ( true === $pre || is_wp_error( $pre ) ) {
			return $pre;
		}
		$s     = self::settings();
		$tests = array();
		$temp  = '';
		foreach ( $config['map'] as $alias => $entry ) {
			$file = 'uploads' === $entry['kind'] ? '' : self::sample_file( $entry['dir'] );
			if ( 'uploads' === $entry['kind'] ) {
				// A file of our own with a word in its name: tests the uploads address and the word codes at once.
				// 3.12.6: with the inner words of the optimization plugins too (wp-content, wp-includes).
				$inner = array_intersect( self::cache_words(), array_values( (array) $config['words'] ) );
				$name  = 'pncp-wordpress-' . ( $inner ? implode( '-', $inner ) . '-' : '' ) . 'check-' . wp_generate_password( 8, false ) . '.css';
				$body = '/* ' . wp_generate_password( 32, false ) . ' */';
				if ( wp_is_writable( $entry['dir'] ) && false !== file_put_contents( $entry['dir'] . '/' . $name, $body ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- A temporary test file, deleted below.
					$temp = $entry['dir'] . '/' . $name;
					$file = $temp;
				} else {
					$file = self::sample_file( $entry['dir'] );
				}
			}
			if ( '' === $file ) {
				continue;
			}
			$tests[ $alias ] = $file;
		}
		if ( $max > 0 ) {
			$tests = array_slice( $tests, 0, $max, true );
		}
		$error = null;
		foreach ( $tests as $alias => $file ) {
			$rest = ltrim( substr( wp_normalize_path( $file ), strlen( $config['map'][ $alias ]['dir'] ) ), '/' );
			$url  = self::alias_url( $base, $alias, self::encode_words( $rest, $config['words'] ) );
			$r    = self::fetch( $url );
			if ( is_wp_error( $r ) ) {
				$error = new WP_Error( 'pncp_stealth_test', sprintf( /* translators: 1: address, 2: error */ __( 'The site could not ask itself for %1$s (%2$s). If the site needs a password (staging) or blocks requests from itself, Stealth cannot be tested.', 'scrapelock' ), $url, $r->get_error_message() ) );
				break;
			}
			$real = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file, compared with the answer.
			if ( 200 !== $r['code'] || md5( $r['body'] ) !== md5( $real ) ) {
				/* translators: 1: address, 2: HTTP status code */
				$error = new WP_Error( 'pncp_stealth_test', sprintf( __( '%1$s did not return the real file (HTTP %2$d). The server rules are missing or not read: add them to the server configuration (Nginx) or check that .htaccess may use mod_rewrite (Apache), then test again.', 'scrapelock' ), $url, (int) $r['code'] ) );
				break;
			}
		}
		if ( '' !== $temp ) {
			wp_delete_file( $temp );
		}
		if ( $error ) {
			return $error;
		}
		if ( ! $tests ) {
			return new WP_Error( 'pncp_stealth_test', __( 'No file was found to test the new addresses with.', 'scrapelock' ) );
		}
		// A PHP file must never run through the new addresses.
		$includes = array_search( 'includes', wp_list_pluck( $config['map'], 'kind' ), true );
		if ( false !== $includes ) {
			$r = self::fetch( self::alias_url( $base, (string) $includes, 'version.php' ) );
			if ( ! is_wp_error( $r ) && 200 === $r['code'] && '' === trim( $r['body'] ) ) {
				return new WP_Error( 'pncp_stealth_php', __( 'The server runs PHP files through the new addresses. Use the rules exactly as given (they only serve styles, scripts, images, fonts and media), then test again.', 'scrapelock' ) );
			}
		}
		if ( ! empty( $s['stealth_endpoints'] ) ) {
			$expect = self::ping_answer();
			foreach ( array( 'ajax', 'post' ) as $name ) {
				if ( empty( $config['ends'][ $name ] ) ) {
					continue;
				}
				$url = home_url( '/' . $base . '/' . $name ) . '?action=' . self::PING;
				$r   = self::fetch( $url );
				if ( is_wp_error( $r ) || false === strpos( $r['body'], $expect ) ) {
					/* translators: %s: address */
					return new WP_Error( 'pncp_stealth_end', sprintf( __( '%s does not reach WordPress. Add the server rules for it, or turn off "Neutral addresses for forms and Ajax", then test again.', 'scrapelock' ), $url ) );
				}
			}
			if ( ! empty( $config['ends']['comment'] ) ) {
				$real  = self::fetch( site_url( 'wp-comments-post.php' ) );
				$alias = self::fetch( home_url( '/' . $base . '/comment' ) );
				if ( is_wp_error( $real ) || is_wp_error( $alias ) || $real['code'] !== $alias['code'] ) {
					/* translators: %s: address */
					return new WP_Error( 'pncp_stealth_end', sprintf( __( '%s does not reach WordPress. Add the server rules for it, or turn off "Neutral addresses for forms and Ajax", then test again.', 'scrapelock' ), home_url( '/' . $base . '/comment' ) ) );
				}
			}
		}
		return true;
	}

	/**
	 * What the self-test's ajax and admin-post call answers.
	 *
	 * @return string
	 */
	private static function ping_answer() {
		return 'pncp-stealth-' . substr( wp_hash( 'pncp-stealth-ping' ), 0, 12 );
	}

	/**
	 * Answers the self-test's call (nothing secret: a fixed text of this site).
	 */
	public static function ping() {
		nocache_headers();
		echo esc_html( self::ping_answer() );
		exit;
	}

	/**
	 * A small static file in a folder to test with (styles and scripts first, then images), or ''.
	 *
	 * @param string $dir Folder.
	 * @return string
	 */
	private static function sample_file( $dir ) {
		foreach ( array( 'style.css', 'css/dashicons.min.css', 'js/jquery/jquery.min.js' ) as $known ) {
			if ( is_file( $dir . '/' . $known ) ) {
				return $dir . '/' . $known;
			}
		}
		$best  = '';
		$size  = PHP_INT_MAX;
		$count = 0;
		try {
			$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST );
			$it->setMaxDepth( 4 );
			foreach ( $it as $f ) {
				if ( ++$count > 3000 ) {
					break;
				}
				if ( ! $f->isFile() || ! preg_match( '/\.(?:css|js|png|svg|gif|jpe?g|webp|woff2?)$/i', $f->getFilename() ) ) {
					continue;
				}
				if ( $f->getSize() > 0 && $f->getSize() < $size ) {
					$best = wp_normalize_path( $f->getPathname() );
					$size = $f->getSize();
					if ( preg_match( '/\.(?:css|js)$/i', $best ) && $size < 50000 ) {
						break;
					}
				}
			}
		} catch ( Exception $e ) {
			return '';
		}
		return $best;
	}

	/**
	 * The new address of a file.
	 *
	 * @param string $base  Base folder.
	 * @param string $alias Alias.
	 * @param string $rest  Path in the folder.
	 * @return string
	 */
	private static function alias_url( $base, $alias, $rest ) {
		return home_url( '/' . $base . '/' . $alias . '/' . ltrim( $rest, '/' ) );
	}

	/**
	 * GET without cookies and without following redirects; the site asks itself. 3.12.2: straight to the server
	 * when ScrapeLock's checks for bots or a firewall refuse the site's own request on the public way
	 * (PNCP_Self_Check::request()).
	 *
	 * @param string $url Address.
	 * @return array{code:int, body:string, headers:array<string, string|string[]>}|WP_Error
	 */
	private static function fetch( $url ) {
		$r = PNCP_Self_Check::request(
			add_query_arg( 'pncp_st', wp_generate_password( 6, false ), $url ),
			array(
				'method'      => 'GET',
				'timeout'     => 8,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter for requests to the site itself.
				'user-agent'  => PNCP_Self_Check::user_agent(), // 3.12.3: the one User-Agent of every self-check.
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			),
			'self'
		)['response'];
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		$headers = wp_remote_retrieve_headers( $r );
		return array(
			'code'    => (int) wp_remote_retrieve_response_code( $r ),
			'body'    => (string) wp_remote_retrieve_body( $r ),
			'headers' => is_object( $headers ) && method_exists( $headers, 'getAll' ) ? $headers->getAll() : (array) $headers,
		);
	}

	/* ---------- Checks over time ---------- */

	/**
	 * Schedules the twice-daily check while Stealth is on (and removes it when off).
	 */
	public static function ensure_cron() {
		$on = ! empty( self::settings()['stealth_enabled'] );
		$at = wp_next_scheduled( self::CRON );
		if ( $on && ! $at ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'twicedaily', self::CRON );
		} elseif ( ! $on && $at ) {
			wp_clear_scheduled_hook( self::CRON );
		}
	}

	/**
	 * A plugin, theme or WordPress changed: the map follows shortly (in the background, after the change).
	 */
	public static function schedule_refresh() {
		if ( self::active() && ! wp_next_scheduled( self::REFRESH ) ) {
			wp_schedule_single_event( time() + 30, self::REFRESH );
		}
	}

	/**
	 * The twice-daily check: are the new addresses still served? Two failed checks in a row (the second a few
	 * minutes after the first) turn Stealth off on its own and email the administrator. Also brings the rules up
	 * to date (a new plugin, Monitor only ended).
	 */
	public static function check() {
		if ( ! self::active() ) {
			return;
		}
		$state  = self::state();
		$config = array(
			'map'   => $state['map'],
			'words' => $state['words'],
			'ends'  => $state['ends'],
		);
		$result = self::self_test( (string) $state['base'], $config, 3 );
		if ( is_wp_error( $result ) ) {
			$state['fails'] = (int) $state['fails'] + 1;
			$state['error'] = $result->get_error_message();
			self::save_state( $state );
			if ( $state['fails'] >= 2 ) {
				self::deactivate( 'auto' );
				self::mail_auto_off( $result->get_error_message() );
			} else {
				wp_schedule_single_event( time() + 5 * MINUTE_IN_SECONDS, self::CRON ); // Once more, a few minutes later.
			}
			return;
		}
		if ( $state['fails'] ) {
			$state['fails'] = 0;
			$state['error'] = '';
			self::save_state( $state );
		}
		self::refresh();
	}

	/**
	 * Brings the map and the rules up to date after a change (plugins, theme, Monitor only). On Apache the new
	 * rules are written and tested, and put back when the test fails; on other servers the new rules wait for
	 * the administrator (the old ones keep working: a new plugin's files are served through the wp-content address).
	 *
	 * 3.12.8: on those servers the new map is tested here too, and used as soon as the server serves it. Before,
	 * only "Test again" put it into use: rules copied by hand or with `wp scrapelock rules install` were reported
	 * "installed and up to date" (their fingerprint is of build()), while the pages kept being rewritten with the
	 * words of the stored map (rewrite() reads state['words']). After 3.12.6 that map lacked the inner words of
	 * WP Rocket's files, so /assets/<alias>/cache/min/1/wp-content/… kept its inner wp-content on every fresh page.
	 * Taking the new map up empties the page caches (WP Rocket, the Nginx fastcgi cache…, pncp_purge_page_cache()).
	 */
	public static function refresh() {
		if ( ! self::active() || PNCP_Lockdown::is_locked() ) {
			return;
		}
		$s      = self::settings();
		$state  = self::state();
		$base   = (string) $state['base'];
		$config = self::build();
		$sig    = self::signature( $base, $config );
		$files  = self::blocks_files( $s ) ? 1 : 0;
		if ( $sig === $state['sig'] && (int) ( isset( $state['files'] ) ? $state['files'] : 0 ) === $files ) {
			return;
		}
		if ( 'apache' === $state['server'] && ! empty( $state['htaccess'] ) ) {
			$before = self::htaccess_backup();
			if ( self::write_htaccess( self::rule_lines( 'apache', $base, $config ) ) && true === self::self_test( $base, $config ) ) {
				$state['sig']     = $sig;
				$state['map']     = $config['map'];
				$state['words']   = $config['words'];
				$state['ends']    = ! empty( $s['stealth_endpoints'] ) ? $config['ends'] : array();
				$state['files']   = $files;
				$state['pending'] = '';
				$state['tested']  = time();
			} else {
				self::htaccess_restore( $before );
				$state['pending'] = 'failed';
			}
		} elseif ( self::sanitize_base( (string) $s['stealth_base'] ) === $base && 'current' === PNCP_Stealth_Status::status( true )['state'] && true === self::self_test( $base, $config ) ) {
			// The server already has the rules of the new map: the check address answers their fingerprint (that of
			// build()) and the self-test passes (its file carries the inner words). A new base folder still needs
			// "Test again" (the old addresses would stop working).
			$state['sig']     = $sig;
			$state['map']     = $config['map'];
			$state['words']   = $config['words'];
			$state['ends']    = ! empty( $s['stealth_endpoints'] ) ? $config['ends'] : array();
			$state['files']   = $files;
			$state['pending'] = '';
			$state['tested']  = time();
		} else {
			$state['pending'] = $sig;
		}
		self::save_state( $state );
		if ( $sig === $state['sig'] ) {
			self::purge_page_cache(); // 3.12.6: the new map is in use.
		}
	}

	/**
	 * Emails the administrator that Stealth turned itself off.
	 *
	 * @param string $why Error.
	 */
	private static function mail_auto_off( $why ) {
		$subject = sprintf( /* translators: %s: site name */ __( '[%s] ScrapeLock Stealth turned itself off', 'scrapelock' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
		$body    = __( 'The neutral addresses of the theme, plugin and core files (Stealth) stopped working twice in a row, so ScrapeLock turned Stealth off and the site uses its real addresses again. Nothing else changed.', 'scrapelock' ) . "\n\n" . $why . "\n\n" . PNCP_Status::settings_url( array( 'tab' => self::tab() ) );
		wp_mail( get_option( 'admin_email' ), $subject, $body );
	}

	/**
	 * Adds a line to ScrapeLock's own notes, when the log has a place for it.
	 *
	 * @param string $what Code.
	 */
	private static function note( $what ) {
		/**
		 * Fires when Stealth is turned on or off.
		 *
		 * @param string $what stealth_on | stealth_off | stealth_auto_off.
		 */
		do_action( 'pncp_stealth_changed', $what );
	}

	/* ---------- REST prefix, sitemap, old addresses ---------- */

	/**
	 * The REST API under its new prefix.
	 *
	 * @param string $prefix Prefix.
	 * @return string
	 */
	public static function rest_url_prefix( $prefix ) {
		$new = self::live_rest_prefix();
		return '' === $new ? $prefix : $new;
	}

	/**
	 * /wp-json/ keeps working for requests that sign in (cookies, application passwords, WooCommerce keys, Jetpack):
	 * apps and integrations that call it keep working. For everyone else it is "page not found" (old_addresses()).
	 */
	public static function old_rest_rules() {
		add_rewrite_rule( '^wp-json/?$', 'index.php?rest_route=/', 'top' );
		add_rewrite_rule( '^wp-json/(.*)?', 'index.php?rest_route=/$matches[1]', 'top' );
	}

	/**
	 * /sitemap.xml and its sub-sitemaps instead of /wp-sitemap*.xml.
	 */
	public static function sitemap_rules() {
		add_rewrite_rule( '^sitemap\.xml$', 'index.php?sitemap=index', 'top' );
		add_rewrite_rule( '^sitemap\.xsl$', 'index.php?sitemap-stylesheet=sitemap', 'top' );
		add_rewrite_rule( '^sitemap-index\.xsl$', 'index.php?sitemap-stylesheet=index', 'top' );
		add_rewrite_rule( '^sitemap-([a-z]+?)-([a-z\d_-]+?)-(\d+?)\.xml$', 'index.php?sitemap=$matches[1]&sitemap-subtype=$matches[2]&paged=$matches[3]', 'top' );
		add_rewrite_rule( '^sitemap-([a-z]+?)-(\d+?)\.xml$', 'index.php?sitemap=$matches[1]&paged=$matches[2]', 'top' );
	}

	/**
	 * The addresses WordPress builds for its sitemaps (robots.txt, the index, the stylesheets).
	 *
	 * @param string $url  Address.
	 * @param string $path Path asked for.
	 * @return string
	 */
	public static function sitemap_url( $url, $path = '' ) {
		if ( is_string( $path ) && 0 === strpos( $path, '/wp-sitemap' ) && preg_match( '#^/wp-sitemap((?:-[a-z0-9_-]+)?\.(?:xml|xsl))$#', $path, $m ) ) {
			return substr( $url, 0, -strlen( $path ) ) . '/sitemap' . $m[1];
		}
		return $url;
	}

	/**
	 * The sitemap's stylesheet says "generated by WordPress": that sentence goes.
	 *
	 * @param string $xsl Stylesheet.
	 * @return string
	 */
	public static function sitemap_stylesheet( $xsl ) {
		$sentence = esc_xml( __( 'This XML Sitemap is generated by WordPress to make your content more visible for search engines.' ) ); // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- WordPress's own sentence, as it is in the stylesheet.
		$xsl      = str_replace( array( $sentence, 'This XML Sitemap is generated by WordPress to make your content more visible for search engines.' ), '', (string) $xsl );
		$out      = preg_replace( '~/\*(?:(?!\*/).)*?WordPress(?:(?!\*/).)*?\*/~is', '', $xsl ); // Comments with links to WordPress's bug tracker.
		return is_string( $out ) ? $out : $xsl;
	}

	/**
	 * Old addresses that only WordPress has: /wp-json/ and ?rest_route= for requests that do not sign in, and /wp-sitemap*.xml
	 * (verified search engines get a redirect to the new sitemap, everyone else "page not found"). In Monitor
	 * only they keep working.
	 *
	 * @param WP $wp Request.
	 */
	public static function old_addresses( $wp ) {
		if ( PNCP_Options::monitoring() || ! $wp instanceof WP ) {
			return;
		}
		$path = self::request_path();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only the presence of the key.
		$route = isset( $_GET['rest_route'] ) && '' !== (string) get_option( 'permalink_structure' );
		if ( '' !== self::live_rest_prefix() && ( preg_match( '#^wp-json(?:/|$)#', $path ) || $route ) && ! self::signs_in() ) {
			// /wp-json/ and ?rest_route= (WordPress's address of the REST API without pretty permalinks): only the
			// new prefix answers visitors who do not sign in.
			self::not_found( $wp );
			return;
		}
		if ( self::live_sitemap() && preg_match( '#^wp-sitemap(?:-[a-z0-9_-]+)?\.(?:xml|xsl)$#', $path ) ) {
			if ( self::verified_crawler() ) {
				wp_safe_redirect( home_url( '/' . substr( $path, 3 ) ), 301 );
				exit;
			}
			self::not_found( $wp );
		}
	}

	/**
	 * The path of this request after the home folder, without the leading slash.
	 *
	 * @return string
	 */
	private static function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared.
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$home = self::home_path();
		return 0 === strpos( $path, $home ) ? (string) substr( $path, strlen( $home ) ) : ltrim( $path, '/' );
	}

	/**
	 * Does the request sign in (cookie, application password, WooCommerce API key, Jetpack signature)?
	 *
	 * @return bool
	 */
	private static function signs_in() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Only checks whether the keys are present.
		$yes = is_user_logged_in() || ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) || ! empty( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) || ! empty( $_SERVER['PHP_AUTH_USER'] )
			|| isset( $_GET['consumer_key'] ) || isset( $_GET['oauth_consumer_key'] ) || ( isset( $_GET['signature'], $_GET['token'] ) );
		// phpcs:enable
		/**
		 * Filters whether a request may still use the old /wp-json/ address.
		 *
		 * @param bool $yes Allowed.
		 */
		return (bool) apply_filters( 'pncp_stealth_old_rest_allowed', $yes );
	}

	/**
	 * Is the visitor a verified search engine (Googlebot, Bingbot… checked by ScrapeLock)?
	 *
	 * @return bool
	 */
	private static function verified_crawler() {
		if ( ! class_exists( 'PNCP_Bots' ) || ! method_exists( 'PNCP_Bots', 'claimed_crawler' ) ) {
			return false;
		}
		$family = PNCP_Bots::claimed_crawler( PNCP_Bots::user_agent() );
		return '' !== $family && PNCP_Bots::is_verified_crawler( $family, PNCP_Bots::client_ip() );
	}

	/**
	 * Makes the request a normal "page not found" of the theme.
	 *
	 * @param WP $wp Request.
	 */
	private static function not_found( $wp ) {
		$wp->query_vars = array( 'error' => '404' );
		remove_action( 'parse_request', 'rest_api_loaded' );
	}

	/**
	 * The files wp-links-opml.php and wp-trackback.php answer "page not found" (only WordPress has them). Not in Monitor only.
	 */
	public static function blocked_scripts() {
		$s = self::settings();
		if ( empty( $s['stealth_block_files'] ) || PNCP_Options::monitoring() || is_user_logged_in() ) {
			return;
		}
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared.
		if ( in_array( $script, array( 'wp-links-opml.php', 'wp-trackback.php' ), true ) ) {
			status_header( 404 );
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
			echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
			exit;
		}
	}

	/* ---------- What visitors get ---------- */

	/**
	 * Should what this request sends be rewritten? Only for visitors who are not signed in, never in wp-admin,
	 * Ajax, cron, XML-RPC, the Customizer, previews, feeds and sitemaps.
	 *
	 * @return bool
	 */
	private static function rewrites_request() {
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return false;
		}
		if ( is_user_logged_in() || is_customize_preview() || is_preview() || is_feed() || is_robots() || get_query_var( 'sitemap' ) || get_query_var( 'sitemap-stylesheet' ) ) {
			return false;
		}
		/**
		 * Filters whether this page is rewritten by Stealth.
		 *
		 * @param bool $yes Rewritten.
		 */
		return (bool) apply_filters( 'pncp_stealth_rewrite', true );
	}

	/**
	 * Starts the output buffer of the page.
	 */
	public static function start_buffer() {
		$rewrites = self::rewrites_request();
		if ( $rewrites ) {
			ob_start( array( __CLASS__, 'end_buffer' ) );
		}
		if ( self::debugging() ) {
			PNCP_Stealth_Debug::start( $rewrites );
		}
	}

	/**
	 * 3.12.8: is the debug log asked for (PNCP_Stealth_Debug: the constant or the filter)? Its class is only
	 * loaded then.
	 *
	 * @return bool
	 */
	private static function debugging() {
		return defined( 'SCRAPELOCK_STEALTH_DEBUG' ) || has_filter( 'pncp_stealth_debug' );
	}

	/**
	 * The page, rewritten: HTML, CSS, JavaScript and JSON only (the type it is sent with).
	 *
	 * @param string $html  Output.
	 * @param int    $phase Buffer phase.
	 * @return string
	 */
	public static function end_buffer( $html, $phase = 0 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- ob_start() callback signature.
		if ( ! is_string( $html ) || '' === $html ) {
			return $html;
		}
		$type = 'text/html';
		foreach ( headers_list() as $header ) {
			if ( 0 === stripos( $header, 'content-type:' ) ) {
				$type = strtolower( trim( substr( $header, 13 ) ) );
			}
		}
		if ( preg_match( '#^text/html#', $type ) ) {
			// The last pass before the page cache stores the page (see PNCP_Stealth_Debug): rewrite() also gives
			// the codes to new addresses an earlier pass left with a word in them.
			$out = self::clean_html( self::rewrite( $html ) );
			if ( self::debugging() ) {
				PNCP_Stealth_Debug::stage( 'buffer', 'template_redirect:-9999', $html, $out );
			}
			return $out;
		}
		if ( preg_match( '#^(?:text/css|(?:text|application)/(?:x-)?javascript|application/(?:[a-z.+-]+\+)?json)#', $type ) ) {
			return self::rewrite( $html );
		}
		return $html;
	}

	/**
	 * 3.12.6: the HTML an optimization plugin gives its filter last (WP Rocket's rocket_buffer, Autoptimize,
	 * LiteSpeed Cache, W3 Total Cache), rewritten like the page: their minified and combined files, preload links
	 * and lazy-load attributes get the new addresses before the page is stored in their cache.
	 *
	 * @param mixed $html Page.
	 * @return mixed
	 */
	public static function optimized_html( $html ) {
		if ( ! is_string( $html ) || '' === $html || ! self::active() || ! self::rewrites_request() ) {
			return $html;
		}
		$out = self::rewrite( $html );
		if ( self::debugging() ) {
			PNCP_Stealth_Debug::stage( current_filter(), 'PHP_INT_MAX', $html, $out );
		}
		return $out;
	}

	/**
	 * REST answers for visitors who are not signed in: the addresses inside them.
	 *
	 * @param mixed           $result  Data.
	 * @param WP_REST_Server  $server  Server.
	 * @param WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function rest_response( $result, $server = null, $request = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Filter signature.
		if ( is_user_logged_in() ) {
			return $result;
		}
		return self::rewrite_deep( $result );
	}

	/**
	 * Rewrites every text in a value.
	 *
	 * @param mixed $value Value.
	 * @param int   $depth Depth.
	 * @return mixed
	 */
	private static function rewrite_deep( $value, $depth = 0 ) {
		if ( is_string( $value ) ) {
			return false !== strpos( $value, '/' ) ? self::rewrite( $value ) : $value;
		}
		if ( $depth > 30 ) {
			return $value;
		}
		if ( is_array( $value ) ) {
			foreach ( $value as $k => $v ) {
				$value[ $k ] = self::rewrite_deep( $v, $depth + 1 );
			}
		} elseif ( $value instanceof stdClass ) {
			foreach ( get_object_vars( $value ) as $k => $v ) {
				$value->$k = self::rewrite_deep( $v, $depth + 1 );
			}
		}
		return $value;
	}

	/**
	 * The regex that finds the real addresses (absolute, protocol-relative and root-relative, plain or with the
	 * escaped slashes of JSON), and what each one becomes.
	 *
	 * @return array{0:string, 1:array<string, array<string, string>>}
	 */
	private static function compiled() {
		if ( null !== self::$compiled ) {
			return self::$compiled;
		}
		$state = self::state();
		$hosts = array_map(
			function ( $h ) {
				return preg_quote( $h, '~' );
			},
			self::hosts( true )
		);
		$sep   = '\\\\?/';
		$alts  = array();
		$repl  = array();
		$items = array();
		foreach ( (array) $state['map'] as $alias => $entry ) {
			$items[ 'd' . $alias ] = array(
				'path'  => (string) $entry['path'],
				'kind'  => 'dir',
				'alias' => (string) $alias,
			);
		}
		foreach ( (array) $state['ends'] as $name => $path ) {
			$items[ 'e' . $name ] = array(
				'path'  => (string) $path,
				'kind'  => 'end',
				'alias' => (string) $name,
			);
		}
		uasort(
			$items,
			function ( $a, $b ) {
				return strlen( $b['path'] ) - strlen( $a['path'] );
			}
		);
		foreach ( $items as $key => $item ) {
			$segments = array_filter( explode( '/', $item['path'] ), 'strlen' );
			if ( ! $segments ) {
				continue;
			}
			$path = '';
			foreach ( $segments as $segment ) {
				$path .= $sep . preg_quote( $segment, '~' );
			}
			// 3.12.8: also after a quote escaped in an attribute (style="background:url(&quot;/wp-content/…&quot;)").
			$alts[]       = '(?:(?:https?:)?' . $sep . $sep . '(?:' . implode( '|', $hosts ) . ')|(?<=[\s"\'(=,]|&quot;|&#039;|&#39;|&#34;|&apos;))' . $path . '(*MARK:' . $key . ')';
			$repl[ $key ] = $item;
		}
		if ( ! $alts ) {
			self::$compiled = array( '', array() );
			return self::$compiled;
		}
		$regex          = '~(?:' . implode( '|', $alts ) . ')(?=\\\\?/|["\'\s)<>,?#&]|$)((?:\\\\?/(?:[^\s"\'<>(),\\\\?#&]|\\\\/)*)?)((?:[?#](?:[^\s"\'<>(),\\\\]|\\\\/)*)?)~';
		self::$compiled = array( $regex, $repl );
		return self::$compiled;
	}

	/**
	 * Rewrites the real addresses in a text to the new ones.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	public static function rewrite( $text ) {
		if ( ! is_string( $text ) || ( false === strpos( $text, '/wp-' ) && false === strpos( $text, '\\/wp-' ) && false === strpos( $text, 'wp-comments-post' ) && ! self::custom_paths() ) ) {
			return $text;
		}
		list( $regex, $repl ) = self::compiled();
		if ( '' === $regex ) {
			return $text;
		}
		$state = self::state();
		$base  = (string) $state['base'];
		$words = (array) $state['words'];
		$home  = self::home_path();
		$out   = preg_replace_callback(
			$regex,
			function ( $m ) use ( $repl, $base, $words, $home ) {
				if ( empty( $m['MARK'] ) || ! isset( $repl[ $m['MARK'] ] ) ) {
					return $m[0];
				}
				$item  = $repl[ $m['MARK'] ];
				$rest  = (string) $m[1];
				$query = (string) $m[2];
				$whole = (string) $m[0];
				$head  = substr( $whole, 0, strlen( $whole ) - strlen( $rest ) - strlen( $query ) );
				$esc   = false !== strpos( $head, '\\/' );
				$plain = str_replace( '\\/', '/', $rest );
				if ( 'end' === $item['kind'] ) {
					if ( '' !== $plain ) {
						return $whole; // admin-ajax.php/something: not ours.
					}
					$new = $home . $base . '/' . $item['alias'];
				} else {
					if ( preg_match( '/\.php$/i', $plain ) ) {
						return $whole; // PHP keeps its real address.
					}
					if ( ! self::served_type( $plain ) ) {
						return $whole; // 3.12.8: a file the rules do not serve (.zip, .docx…) keeps its real address.
					}
					$new = $home . $base . '/' . $item['alias'] . self::encode_words( $plain, $words );
				}
				$origin = '';
				if ( preg_match( '~^((?:https?:)?\\\\?/\\\\?/[^/\\\\]+)~', $head, $o ) ) {
					$origin = $o[1];
				}
				if ( $esc ) {
					$new = str_replace( '/', '\\/', $new );
				}
				return $origin . $new . $query;
			},
			$text
		);
		$out = is_string( $out ) ? $out : $text;
		return '' !== $base && false !== strpos( $out, $base ) ? self::code_new_addresses( $out, $state, $home ) : $out;
	}

	/**
	 * 3.12.8: the new addresses already in a text (made by an earlier pass, or kept by a plugin from one) get the
	 * codes of the words they still carry: /assets/<alias>/cache/min/1/wp-content/… becomes …/1/<code>/…, as the
	 * first pass would have made it. The rest of the address only; the codes in it are left as they are, so a
	 * second run changes nothing. The server rules turn every code back wherever it is in the address (at most
	 * twice per word, as here).
	 *
	 * @param string               $text  Text.
	 * @param array<string, mixed> $state State.
	 * @param string               $home  Home path.
	 * @return string
	 */
	private static function code_new_addresses( $text, $state, $home ) {
		$words = (array) $state['words'];
		$map   = (array) $state['map'];
		if ( ! $words || ! $map ) {
			return $text;
		}
		$sep  = '\\\\?/';
		$path = '';
		foreach ( array_filter( explode( '/', $home . (string) $state['base'] ), 'strlen' ) as $segment ) {
			$path .= $sep . preg_quote( $segment, '~' );
		}
		$hosts = array_map(
			function ( $h ) {
				return preg_quote( $h, '~' );
			},
			self::hosts( true )
		);
		$regex = '~(?:(?:https?:)?' . $sep . $sep . '(?:' . implode( '|', $hosts ) . ')|(?<=[\s"\'(=,]))' . $path . $sep . '([0-9a-f]{6})((?:' . $sep . '(?:[^\s"\'<>(),\\\\?#&]|\\\\/)*)?)~';
		$out   = preg_replace_callback(
			$regex,
			function ( $m ) use ( $words, $map ) {
				if ( ! isset( $map[ $m[1] ] ) || '' === $m[2] ) {
					return $m[0];
				}
				$plain = str_replace( '\\/', '/', $m[2] );
				$new   = self::encode_left( $plain, $words );
				if ( $new === $plain || preg_match( '/\.php$/i', $plain ) ) {
					return $m[0];
				}
				if ( false !== strpos( $m[2], '\\/' ) ) {
					$new = str_replace( '/', '\\/', $new );
				}
				return substr( $m[0], 0, strlen( $m[0] ) - strlen( $m[2] ) ) . $new;
			},
			$text
		);
		return is_string( $out ) ? $out : $text;
	}

	/**
	 * 3.12.8: encode_words() for a path that may already hold codes: only the text between the codes changes, and
	 * a word only while the path then holds it at most twice (coded or not), as the server rules turn it back.
	 *
	 * @param string                $path  Path.
	 * @param array<string, string> $words Code => word.
	 * @return string
	 */
	private static function encode_left( $path, $words ) {
		$parts = preg_split( '~(' . implode( '|', array_map( 'preg_quote', array_keys( $words ) ) ) . ')~', $path, -1, PREG_SPLIT_DELIM_CAPTURE );
		if ( ! is_array( $parts ) ) {
			return $path;
		}
		$codes = array();
		$plain = '';
		foreach ( $parts as $i => $part ) {
			if ( 1 === $i % 2 ) {
				$codes[] = $part;
			} else {
				$plain .= $part . '/';
			}
		}
		$counts = array_count_values( $codes );
		$map    = array();
		foreach ( $words as $token => $word ) {
			$n = substr_count( $plain, $word );
			if ( $n > 0 && $n + ( isset( $counts[ $token ] ) ? $counts[ $token ] : 0 ) <= 2 ) {
				$map[ $word ] = $token;
			}
		}
		if ( ! $map ) {
			return $path;
		}
		foreach ( $parts as $i => $part ) {
			if ( 0 === $i % 2 ) {
				$parts[ $i ] = strtr( $part, $map );
			}
		}
		return implode( '', $parts );
	}

	/**
	 * 3.12.8: is the file of a path one of the types the rules serve (STATIC_EXT)? A path without a file type in
	 * its last part is a folder a script adds file names to (true). An upload linked from a post (.zip, .docx,
	 * .epub, .csv…) would answer 404 at a neutral address: it keeps its real one.
	 *
	 * @param string $path Path after the folder of the map.
	 * @return bool
	 */
	private static function served_type( $path ) {
		if ( ! preg_match( '~/[^/]*\.([a-z][a-z0-9]*)$~i', $path, $m ) ) {
			return true;
		}
		return (bool) preg_match( '~^(?:' . self::STATIC_EXT . ')$~i', $m[1] );
	}

	/**
	 * Does a folder of the map live somewhere else than /wp-…/ (a custom uploads or content folder)?
	 *
	 * @return bool
	 */
	private static function custom_paths() {
		static $custom = null;
		if ( null === $custom ) {
			$custom = false;
			foreach ( (array) self::state()['map'] as $entry ) {
				if ( false === strpos( (string) $entry['path'], '/wp-' ) ) {
					$custom = true;
				}
			}
		}
		return $custom;
	}

	/**
	 * Replaces the words that give the site away in a path with their codes (at most twice each, as the rules do).
	 *
	 * @param string                $path  Path.
	 * @param array<string, string> $words Code => word.
	 * @return string
	 */
	private static function encode_words( $path, $words ) {
		$map = array();
		foreach ( $words as $token => $word ) {
			$n = substr_count( $path, $word );
			if ( $n > 0 && $n <= 2 ) {
				$map[ $word ] = $token;
			}
		}
		return $map ? strtr( $path, $map ) : $path;
	}

	/**
	 * The password form of protected posts posts to admin-post.php (which visitors see at the Stealth folder)
	 * instead of wp-login.php?action=postpass. Only for pages Stealth rewrites.
	 *
	 * @param string $output Form.
	 * @return string
	 */
	public static function password_form( $output ) {
		if ( ! is_string( $output ) || false === stripos( $output, 'action=postpass' ) || ! self::rewrites_request() ) {
			return $output;
		}
		$out = preg_replace(
			'~(<form\b[^>]*\baction=)(["\'])[^"\']*wp-login\.php\?action=postpass[^"\']*\2([^>]*>)~i',
			'$1$2' . esc_url( admin_url( 'admin-post.php' ) ) . '$2$3<input type="hidden" name="action" value="' . self::POSTPASS . '" />',
			$output,
			1
		);
		return is_string( $out ) ? $out : $output;
	}

	/**
	 * The password form of protected posts, sent to admin-post.php: what wp-login.php?action=postpass does (the
	 * cookie with the hashed password, then back to the post).
	 */
	public static function postpass() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- As WordPress's own postpass: the form has no nonce (cached pages), and it only sets the visitor's own cookie.
		$redirect_to = isset( $_POST['redirect_to'] ) && is_string( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : (string) wp_get_referer();
		if ( ! isset( $_POST['post_password'] ) || ! is_string( $_POST['post_password'] ) ) {
			wp_safe_redirect( '' !== $redirect_to ? $redirect_to : home_url( '/' ) );
			exit;
		}
		require_once ABSPATH . WPINC . '/class-phpass.php';
		$hasher = new PasswordHash( 8, true );
		/** This filter is documented in wp-login.php */
		$expire = apply_filters( 'post_password_expires', time() + 10 * DAY_IN_SECONDS ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter.
		$secure = '' !== $redirect_to && 'https' === wp_parse_url( $redirect_to, PHP_URL_SCHEME );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- A password, hashed as it is typed.
		setcookie( 'wp-postpass_' . COOKIEHASH, $hasher->HashPassword( wp_unslash( $_POST['post_password'] ) ), $expire, COOKIEPATH, COOKIE_DOMAIN, $secure );
		// phpcs:enable
		wp_safe_redirect( '' !== $redirect_to ? $redirect_to : home_url( '/' ) );
		exit;
	}

	/**
	 * REST answers to visitors who do not sign in: without the "Link: rel=https://api.w.org/" header and the
	 * X-WP-… names in the CORS headers, which tell scanners the site runs WordPress (rest_api_init).
	 */
	public static function rest_headers() {
		if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST || self::signs_in() ) {
			return;
		}
		add_filter( 'rest_exposed_cors_headers', array( __CLASS__, 'without_wp_headers' ), 99 );
		add_filter( 'rest_allowed_cors_headers', array( __CLASS__, 'without_wp_headers' ), 99 );
		add_filter( 'rest_post_dispatch', array( __CLASS__, 'rest_no_link' ), 99 );
	}

	/**
	 * A CORS header list without the X-WP-… names.
	 *
	 * @param mixed $headers Header names.
	 * @return string[]
	 */
	public static function without_wp_headers( $headers ) {
		return array_values(
			array_filter(
				array_map( 'strval', (array) $headers ),
				function ( $h ) {
					return 0 !== stripos( $h, 'x-wp-' );
				}
			)
		);
	}

	/**
	 * Removes the Link header the REST server sent before the answer (rel=https://api.w.org/). The answer's own
	 * headers (pagination links) are sent after this.
	 *
	 * @param mixed $response Response.
	 * @return mixed
	 */
	public static function rest_no_link( $response ) {
		if ( ! self::$rest_cleaned && ! headers_sent() ) {
			self::$rest_cleaned = true;
			header_remove( 'Link' );
		}
		return $response;
	}

	/**
	 * Markup only WordPress prints: generator tags, links to the REST API, RSD, oEmbed, pingback and the shortlink
	 * (also when a theme or plugin prints them itself), the emoji script, the "wp-" ids of styles and scripts, and
	 * HTML comments that name WordPress, WooCommerce or an SEO or cache plugin.
	 *
	 * @param string $html Page.
	 * @return string
	 */
	public static function clean_html( $html ) {
		$out  = preg_replace(
			array(
				'~<meta\s[^>]*name=["\']generator["\'][^>]*>\s*~i',
				'~<link\s[^>]*rel=["\'](?:https://api\.w\.org/|EditURI|wlwmanifest|pingback|shortlink)["\'][^>]*>\s*~i',
				'~<link\s[^>]*type=["\'](?:application/json\+oembed|text/xml\+oembed)["\'][^>]*>\s*~i',
				'~<link\s[^>]*href=["\'](?:https?:)?//s\.w\.org/?["\'][^>]*>\s*~i',
				'~<script\b[^>]*>(?:(?!</script>).)*?_wpemojiSettings(?:(?!</script>).)*</script>\s*~is',
				'~<script\b[^>]*\bid=["\']wp-emoji-settings["\'][^>]*>.*?</script>\s*~is',
				'~<script\b[^>]*>(?:(?!</script>).)*?wp-emoji-settings(?:(?!</script>).)*</script>\s*~is',
				'~<style\b[^>]*\bid=["\']wp-emoji-styles-inline-css["\'][^>]*>.*?</style>\s*~is',
			),
			'',
			$html
		);
		$html = is_string( $out ) ? $out : $html;
		// Ids of enqueued styles and scripts ("wp-block-library-css", "woocommerce-general-css"): a short code
		// of the handle instead. The data of script modules keeps its id (the scripts read it).
		$out  = preg_replace_callback(
			'~(<(?:link|style|script)\b[^>]*?\sid=)(["\'])([^"\']+?)(-css|-inline-css|-js|-js-extra|-js-before|-js-after|-js-translations|-js-modulepreload|-js-module)\2~i',
			function ( $m ) {
				if ( 0 === strpos( $m[3], 'wp-script-module-data-' ) ) {
					return $m[0];
				}
				return $m[1] . $m[2] . 's' . substr( md5( $m[3] ), 0, 8 ) . $m[4] . $m[2];
			},
			$html
		);
		$html = is_string( $out ) ? $out : $html;
		$out  = preg_replace( '~(<style\b[^>]*\sid=["\'])wp-custom-css(["\'])~i', '$1custom-css$2', $html );
		$html = is_string( $out ) ? $out : $html;
		$out  = preg_replace( '~(<script\b[^>]*\sid=["\'])wp-importmap(["\'])~i', '$1importmap$2', $html );
		$html = is_string( $out ) ? $out : $html;
		// The "sourceURL" notes WordPress adds to inline styles and scripts name their handles.
		$out  = preg_replace( '~[ \t]*(?:/\*#\s*sourceURL=[^*]*\*/|//#\s*sourceURL=[^\r\n<]*)~', '', $html );
		$html = is_string( $out ) ? $out : $html;
		// Speculative loading: the rules exclude /wp-admin/* and /wp-*.php; those lines go.
		$out  = preg_replace_callback( '~(<script\b[^>]*type=["\']speculationrules["\'][^>]*>)(.*?)(</script>)~is', array( __CLASS__, 'clean_speculation' ), $html );
		$html = is_string( $out ) ? $out : $html;
		// HTML comments that name WordPress, WooCommerce or an SEO or cache plugin (not conditional comments).
		$out = preg_replace_callback(
			'~<!--(.*?)-->[ \t]*\R?~s',
			function ( $m ) {
				if ( preg_match( '~^\s*\[if|^\s*<!\[endif~i', $m[1] ) ) {
					return $m[0];
				}
				return preg_match( '~WordPress|woocommerce|wp[:_-]|yoast|rank math|all in one seo|seopress|elementor|jetpack|w3 total cache|super cache|wp rocket|litespeed|autoptimize|powered by~i', $m[1] ) ? '' : $m[0];
			},
			$html
		);
		return self::without_footprints( is_string( $out ) ? $out : $html );
	}

	/**
	 * 3.12.7: the footer comments of performance and cache plugins, by their exact words, that reach this buffer
	 * (those a plugin adds in its own outer buffer, when it stores the page, do not: WP Rocket's and Redis Object
	 * Cache's are switched off where they are made, see PNCP_Surface). HTML comments only, never conditional ones.
	 *
	 * @param string $html Page.
	 * @return string
	 */
	public static function without_footprints( $html ) {
		$signs = '~^\s*(?:'
			. 'This website is like a Rocket, isn\'t it\?|(?:Cached|Optimized) for great performance(?: - Debug: cached@\d+)?\s*$' // WP Rocket.
			. '|Performance optimized by (?:Redis Object Cache|W3 Total Cache)\b'
			. '|Dynamic page generated in [\d.]+ seconds\.|Cached page generated by WP-Super-Cache\b|super cache\s*$|Compression = gzip\s*$'
			. '|Page (?:optimized|generated|cached|supported) by LiteSpeed Cache\b'
			. '|Autoptimize found a problem with the HTML\b'
			. '|WP Fastest Cache file was created in\b|Hummingbird cache file was created in\b'
			. '|(?:Optimized|Cached) (?:with|by) (?:the )?(?:SiteGround (?:Speed )?Optimizer|SG Optimizer)\b'
			. ')|wprediscache\.com~i';
		$out   = preg_replace_callback(
			'~\R?<!--(.*?)-->[ \t]*~s',
			function ( $m ) use ( $signs ) {
				if ( preg_match( '~^\s*\[if|<!\[endif\]\s*$~i', $m[1] ) ) {
					return $m[0];
				}
				return preg_match( $signs, $m[1] ) ? '' : $m[0];
			},
			$html
		);
		return is_string( $out ) ? $out : $html;
	}

	/**
	 * 3.12.7: the JSON of script translations (wp_set_script_translations()) without what names files and tools:
	 * "comment":{"reference":"wp-includes/js/dist/…"} or a plugin's path, and "generator" (GlotPress, WP-CLI).
	 * wp.i18n reads only "locale_data"; the text domain and locale stay (the scripts look their texts up by them).
	 *
	 * @param mixed $json JSON of the translations, or false.
	 * @return mixed
	 */
	public static function script_translations( $json ) {
		if ( ! is_string( $json ) || ( false === strpos( $json, '"comment"' ) && false === strpos( $json, '"generator"' ) ) || ! self::rewrites_request() ) {
			return $json;
		}
		$data = json_decode( $json );
		if ( ! $data instanceof stdClass || ! isset( $data->locale_data ) ) {
			return $json;
		}
		unset( $data->comment, $data->generator );
		// Default flags, as the files are written: "/" stays escaped, so no "</script>" can end the inline script.
		$out = wp_json_encode( $data );
		return is_string( $out ) ? $out : $json;
	}

	/**
	 * Speculation rules without the entries that name /wp-… addresses.
	 *
	 * @param string[] $m Match: opening tag, JSON, closing tag.
	 * @return string
	 */
	public static function clean_speculation( $m ) {
		$data = json_decode( $m[2], true );
		if ( ! is_array( $data ) ) {
			return $m[0];
		}
		$walk = function ( $value ) use ( &$walk ) {
			if ( ! is_array( $value ) ) {
				return $value;
			}
			$list = array_keys( $value ) === range( 0, count( $value ) - 1 );
			foreach ( $value as $k => $v ) {
				if ( is_string( $v ) && preg_match( '~/wp-~', $v ) ) {
					unset( $value[ $k ] );
					continue;
				}
				$value[ $k ] = $walk( $v );
			}
			return $list ? array_values( $value ) : $value;
		};
		return $m[1] . wp_json_encode( $walk( $data ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . $m[3];
	}

	/**
	 * The robots.txt without lines for /wp-admin/ (the sign-in pages answer "page not found" to visitors anyway).
	 *
	 * @param string $output robots.txt.
	 * @return string
	 */
	public static function robots_txt( $output ) {
		$admin = preg_quote( (string) self::same_host_path( admin_url() ), '#' );
		$out   = preg_replace( '#^(?:Disallow|Allow):\s*' . $admin . '/(?:admin-ajax\.php)?\s*\R?#mi', '', (string) $output );
		return is_string( $out ) ? $out : $output;
	}

	/**
	 * Body classes that name the theme folder ("wp-theme-…", "wp-child-theme-…") go for visitors.
	 *
	 * @param string[] $classes Classes.
	 * @return string[]
	 */
	public static function body_class( $classes ) {
		if ( is_user_logged_in() ) {
			return $classes;
		}
		return array_values(
			array_filter(
				(array) $classes,
				function ( $c ) {
					return ! preg_match( '/^wp-(?:child-)?theme-/', (string) $c );
				}
			)
		);
	}

	/**
	 * No dns-prefetch to s.w.org (WordPress's emoji server).
	 *
	 * @param array<int, mixed> $urls Hints.
	 * @param string            $type Relation.
	 * @return array<int, mixed>
	 */
	public static function resource_hints( $urls, $type ) {
		if ( 'dns-prefetch' !== $type || is_user_logged_in() ) {
			return $urls;
		}
		return array_values(
			array_filter(
				(array) $urls,
				function ( $u ) {
					$href = is_array( $u ) ? ( isset( $u['href'] ) ? (string) $u['href'] : '' ) : (string) $u;
					return false === strpos( $href, 's.w.org' );
				}
			)
		);
	}

	/**
	 * Emoji images are not loaded from s.w.org for visitors (browsers show emoji by themselves).
	 *
	 * @param string $url Address.
	 * @return string|false
	 */
	public static function emoji_svg_url( $url ) {
		return is_admin() || is_user_logged_in() ? $url : false;
	}

	/* ---------- Scan ---------- */

	/**
	 * The signatures the scan looks for, in the style of the open Wappalyzer fingerprints for WordPress,
	 * WooCommerce and the block editor, plus what scanners check. hide = Stealth can remove it.
	 *
	 * @return array<string, array{label:string, in:string, re:string, hide:bool, fix:string}>
	 */
	public static function signatures() {
		$stealth = __( 'Turn Stealth on (or test it again).', 'scrapelock' );
		$theme   = __( 'Printed by the theme or a plugin as it is: it cannot be renamed without breaking it.', 'scrapelock' );
		return array(
			'wp_paths'      => array(
				'label' => __( 'Addresses with /wp-content/ or /wp-includes/', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~\\\\?/wp-(?:content|includes)\\\\?/~',
				'hide'  => true,
				'fix'   => __( 'Stealth rewrites them. One that remains is on another host (a CDN or an image of another site) or is built by a script.', 'scrapelock' ),
			),
			'generator'     => array(
				'label' => __( 'A "generator" meta tag', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~<meta[^>]+name=["\']generator["\'][^>]*>~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'api_w_org'     => array(
				'label' => __( 'A link to the REST API (api.w.org)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~api\.w\.org~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'emoji'         => array(
				'label' => __( 'The WordPress emoji script (s.w.org, _wpemojiSettings)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~_wpemojiSettings|wp-emoji|s\.w\.org~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'wp_json'       => array(
				'label' => __( 'The REST API address /wp-json/', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~\\\\?/wp-json\\\\?/|rest_route=~i',
				'hide'  => true,
				'fix'   => __( 'Give the REST API another prefix below.', 'scrapelock' ),
			),
			'xmlrpc'        => array(
				'label' => __( 'A link to xmlrpc.php', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~xmlrpc\.php~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'wp_login'      => array(
				'label' => __( 'A link to wp-login.php', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~wp-login\.php~i',
				'hide'  => true,
				'fix'   => __( 'Move the sign-in address (Sign-in protection): its links then use the new address.', 'scrapelock' ),
			),
			'wp_admin'      => array(
				'label' => __( 'An address in /wp-admin/ (e.g. admin-ajax.php)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~\\\\?/wp-admin\\\\?/~i',
				'hide'  => true,
				'fix'   => __( 'Turn on "Neutral addresses for forms and Ajax". One that remains is written by a plugin into a script.', 'scrapelock' ),
			),
			'comments_post' => array(
				'label' => __( 'The comment form posts to wp-comments-post.php', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~wp-comments-post\.php~i',
				'hide'  => true,
				'fix'   => __( 'Turn on "Neutral addresses for forms and Ajax".', 'scrapelock' ),
			),
			'handle_ids'    => array(
				'label' => __( '"wp-" ids of styles and scripts (e.g. wp-block-library-css)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~\sid=["\']wp-[a-z0-9-]+-(?:css|js)["\']~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'wp_comments'   => array(
				'label' => __( 'HTML comments that name WordPress or a plugin', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~<!--[^>]{0,200}(?:wordpress|woocommerce|wp:|yoast|rank math)~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'theme_class'   => array(
				'label' => __( 'The theme folder in the body classes (wp-theme-…)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~class=["\'][^"\']*\bwp-(?:child-)?theme-~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'wp_embed'      => array(
				'label' => __( 'The embed script wp-embed.min.js', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~wp-embed(?:\.min)?\.js~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'sitemap_link'  => array(
				'label' => __( 'The sitemap address wp-sitemap.xml', 'scrapelock' ),
				'in'    => 'any',
				're'    => '~wp-sitemap~i',
				'hide'  => true,
				'fix'   => __( 'Turn on "Sitemap at /sitemap.xml".', 'scrapelock' ),
			),
			'woo_src'       => array(
				'label' => __( '"woocommerce" in the address of a script or style', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~(?:src|href)=["\'][^"\']*woocommerce[^"\']*\.(?:js|css)~i',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'block_classes' => array(
				'label' => __( 'Block class names (wp-block-…, wp-element-…)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~class=["\'][^"\']*\bwp-(?:block|element|site-blocks)~i',
				'hide'  => false,
				'fix'   => __( 'The styles of the blocks depend on these names, so they stay. Wappalyzer reports them as "WordPress Block Editor"; a classic theme without blocks has fewer.', 'scrapelock' ),
			),
			'interactivity' => array(
				'label' => __( 'Interactive blocks (data-wp-… attributes, @wordpress/ modules)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~data-wp-(?:interactive|context|bind|on)|@wordpress/~i',
				'hide'  => false,
				'fix'   => __( 'The scripts of the navigation, search and image blocks read them, so they stay.', 'scrapelock' ),
			),
			'wp_js'         => array(
				'label' => __( 'WordPress scripts by name (wp.i18n, wpApiSettings…)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~\bwp\.(?:i18n|ajax|apiFetch|receiveEmbedMessage|hooks)\b|wpApiSettings|wp_username~',
				'hide'  => false,
				'fix'   => $theme,
			),
			'woo_markup'    => array(
				'label' => __( 'WooCommerce class names and scripts (woocommerce, wc_add_to_cart_params)', 'scrapelock' ),
				'in'    => 'html',
				're'    => '~class=["\'][^"\']*\bwoocommerce\b|wc_add_to_cart_params|woocommerce_params|wc_cart_fragments_params~i',
				'hide'  => false,
				'fix'   => __( 'The shop\'s styles and scripts depend on them, so they stay.', 'scrapelock' ),
			),
			'h_pingback'    => array(
				'label' => __( 'The X-Pingback header', 'scrapelock' ),
				'in'    => 'headers',
				're'    => '~^x-pingback:~mi',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'h_link'        => array(
				'label' => __( 'Link headers to the REST API or the shortlink', 'scrapelock' ),
				'in'    => 'headers',
				're'    => '~^link:.*(?:api\.w\.org|rel=shortlink|wp-json)~mi',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'h_redirect'    => array(
				'label' => __( 'The header X-Redirect-By: WordPress', 'scrapelock' ),
				'in'    => 'headers',
				're'    => '~^x-redirect-by:\s*wordpress~mi',
				'hide'  => true,
				'fix'   => $stealth,
			),
			'h_powered'     => array(
				'label' => __( 'The PHP version in X-Powered-By', 'scrapelock' ),
				'in'    => 'headers',
				're'    => '~^x-powered-by:\s*php~mi',
				'hide'  => true,
				'fix'   => __( 'Stealth hides the versions; if it remains, set expose_php = Off in php.ini.', 'scrapelock' ),
			),
			'h_wp_header'   => array(
				'label' => __( 'Headers that start with X-WP-', 'scrapelock' ),
				'in'    => 'headers',
				're'    => '~^x-wp-~mi',
				'hide'  => false,
				'fix'   => __( 'Sent only by REST API answers, which work as before.', 'scrapelock' ),
			),
			'cookies'       => array(
				'label' => __( 'WordPress or WooCommerce cookies for visitors', 'scrapelock' ),
				'in'    => 'headers',
				're'    => '~^set-cookie:\s*(?:wordpress_|wp-settings|wp_woocommerce_session|woocommerce_)~mi',
				'hide'  => false,
				'fix'   => __( 'Set by WordPress or WooCommerce for signing in and for the cart; their names cannot change.', 'scrapelock' ),
			),
			'robots_admin'  => array(
				'label' => __( 'robots.txt names /wp-admin/', 'scrapelock' ),
				'in'    => 'robots',
				're'    => '~^(?:Dis)?allow:\s*\S*/wp-admin/~mi',
				'hide'  => true,
				'fix'   => $stealth,
			),
		);
	}

	/**
	 * The pages and files the scan asks for, each with what it checks.
	 *
	 * @param string $url Home page.
	 * @return array<int|string, array{url:string, kind:string}> Keys are names; "404" becomes an integer key.
	 */
	private static function scan_targets( $url ) {
		$home  = trailingslashit( $url );
		$pages = array(
			'home'   => array(
				'url'  => $home,
				'kind' => 'page',
			),
			'robots' => array(
				'url'  => $home . 'robots.txt',
				'kind' => 'robots',
			),
			'404'    => array(
				'url'  => $home . 'pncp-' . strtolower( wp_generate_password( 10, false ) ) . '/',
				'kind' => 'page',
			),
		);
		$posts = get_posts(
			array(
				'numberposts'      => 1,
				'post_status'      => 'publish',
				'post_type'        => 'post',
				'has_password'     => false,
				'suppress_filters' => true,
			)
		);
		if ( $posts ) {
			$pages['post'] = array(
				'url'  => (string) get_permalink( $posts[0] ),
				'kind' => 'page',
			);
		}
		if ( function_exists( 'wc_get_page_id' ) && wc_get_page_id( 'shop' ) > 0 ) {
			$pages['shop'] = array(
				'url'  => (string) get_permalink( wc_get_page_id( 'shop' ) ),
				'kind' => 'page',
			);
		}
		foreach ( array( 'readme.html', 'license.txt', 'wp-login.php', 'wp-admin/', 'wp-json/', 'wp-sitemap.xml', 'xmlrpc.php', 'wp-links-opml.php' ) as $file ) {
			$pages[ $file ] = array(
				'url'  => $home . $file,
				'kind' => 'file',
			);
		}
		return $pages;
	}

	/**
	 * Asks the site's public pages (home, a post, a 404, robots.txt) and the files only WordPress has for what still
	 * shows that the site runs on WordPress, as a visitor who is not signed in. The result is kept for a day.
	 *
	 * @param string $url Home page ('' = this site's).
	 * @return array{time:int, active:bool, pages:array<string, int>, found:array<int, array<string, mixed>>}
	 */
	public static function scan( $url = '' ) {
		$url   = '' === $url ? home_url( '/' ) : esc_url_raw( $url );
		$sigs  = self::signatures();
		$found = array();
		$pages = array();
		foreach ( self::scan_targets( $url ) as $id => $target ) {
			$r = self::fetch( $target['url'] );
			if ( is_wp_error( $r ) ) {
				$pages[ $id ] = 0;
				continue;
			}
			$pages[ $id ] = $r['code'];
			$headers      = '';
			foreach ( $r['headers'] as $name => $values ) {
				foreach ( (array) $values as $value ) {
					$headers .= strtolower( (string) $name ) . ': ' . $value . "\n";
				}
			}
			if ( 'file' === $target['kind'] ) {
				$leak = self::file_leak( $id, $r );
				if ( $leak ) {
					$found[] = array_merge( $leak, array( 'page' => $id ) );
				}
				foreach ( array( 'h_redirect', 'h_powered' ) as $sig ) {
					if ( preg_match( $sigs[ $sig ]['re'], $headers, $m ) ) {
						$found[] = self::finding( $sig, $id, $m[0] );
					}
				}
				continue;
			}
			foreach ( $sigs as $sig => $def ) {
				if ( 'headers' === $def['in'] ) {
					$subject = $headers;
				} elseif ( 'robots' === $def['in'] ) {
					$subject = 'robots' === $target['kind'] ? $r['body'] : '';
				} elseif ( 'html' === $def['in'] ) {
					$subject = 'page' === $target['kind'] ? $r['body'] : '';
				} else {
					$subject = $r['body'];
				}
				if ( '' !== $subject && preg_match( $def['re'], $subject, $m ) ) {
					$found[] = self::finding( $sig, $id, $m[0] );
				}
			}
		}
		// One line per signature, with the pages it was found on.
		$merged = array();
		foreach ( $found as $f ) {
			if ( isset( $merged[ $f['id'] ] ) ) {
				$merged[ $f['id'] ]['pages'][] = $f['page'];
				continue;
			}
			$f['pages']         = array( $f['page'] );
			$merged[ $f['id'] ] = $f;
		}
		foreach ( $merged as $k => $f ) {
			unset( $merged[ $k ]['page'] );
			$merged[ $k ]['pages'] = array_values( array_unique( $f['pages'] ) );
		}
		usort(
			$merged,
			function ( $a, $b ) {
				return (int) $b['hide'] - (int) $a['hide'];
			}
		);
		$result = array(
			'time'   => time(),
			'active' => self::active(),
			'pages'  => $pages,
			'found'  => $merged,
		);
		if ( home_url( '/' ) === $url ) {
			set_transient( self::SCAN, $result, DAY_IN_SECONDS );
		}
		return $result;
	}

	/**
	 * One finding.
	 *
	 * @param string $sig      Signature id.
	 * @param string $page     Page id.
	 * @param string $evidence What matched.
	 * @return array<string, mixed>
	 */
	private static function finding( $sig, $page, $evidence ) {
		$def = self::signatures()[ $sig ];
		return array(
			'id'       => $sig,
			'label'    => $def['label'],
			'page'     => $page,
			'evidence' => wp_strip_all_tags( strlen( trim( (string) $evidence ) ) > 60 ? '…' . substr( trim( (string) $evidence ), -60 ) : trim( (string) $evidence ) ),
			'hide'     => $def['hide'],
			'fix'      => $def['fix'],
		);
	}

	/**
	 * Does a file only WordPress has answer?
	 *
	 * @param string                                                     $id File.
	 * @param array{code:int, body:string, headers:array<string, mixed>} $r  Answer.
	 * @return array<string, mixed>|null
	 */
	private static function file_leak( $id, $r ) {
		$code = (int) $r['code'];
		$body = (string) $r['body'];
		$loc  = isset( $r['headers']['location'] ) ? implode( ' ', (array) $r['headers']['location'] ) : '';
		$fix  = __( 'Turn on "Refuse readme.html and other files only WordPress has" (and Stealth).', 'scrapelock' );
		$hit  = null;
		switch ( $id ) {
			case 'readme.html':
			case 'license.txt':
				$hit = 200 === $code && false !== stripos( $body, 'WordPress' ) ? array( __( 'readme.html or license.txt of WordPress can be read', 'scrapelock' ), true, $fix ) : null;
				break;
			case 'wp-links-opml.php':
				$hit = 200 === $code ? array( __( 'wp-links-opml.php answers', 'scrapelock' ), true, $fix ) : null;
				break;
			case 'wp-login.php':
				$hit = 200 === $code ? array( __( 'The sign-in page wp-login.php answers', 'scrapelock' ), true, __( 'Move the sign-in address (Sign-in protection).', 'scrapelock' ) ) : null;
				break;
			case 'wp-admin/':
				$hit = ( $code >= 300 && $code < 400 && false !== strpos( $loc, 'wp-login.php' ) ) || 200 === $code ? array( __( '/wp-admin/ sends visitors to the WordPress sign-in page', 'scrapelock' ), true, __( 'Move the sign-in address (Sign-in protection): /wp-admin/ then answers "page not found" to visitors.', 'scrapelock' ) ) : null;
				break;
			case 'wp-json/':
				$hit = 200 === $code && false !== strpos( $body, '"namespaces"' ) ? array( __( '/wp-json/ answers with the REST API', 'scrapelock' ), true, __( 'Give the REST API another prefix below.', 'scrapelock' ) ) : null;
				break;
			case 'wp-sitemap.xml':
				$hit = 200 === $code || ( $code >= 300 && $code < 400 && false !== strpos( $loc, 'wp-sitemap' ) ) ? array( __( '/wp-sitemap.xml answers', 'scrapelock' ), true, __( 'Turn on "Sitemap at /sitemap.xml".', 'scrapelock' ) ) : null;
				break;
			case 'xmlrpc.php':
				$hit = false !== stripos( $body, 'XML-RPC server accepts POST requests only' ) ? array( __( 'xmlrpc.php answers with WordPress\'s own text', 'scrapelock' ), false, __( 'Block XML-RPC in Vulnerable points, unless an app or Jetpack needs it.', 'scrapelock' ) ) : null;
				break;
		}
		if ( ! $hit ) {
			return null;
		}
		return array(
			'id'       => 'file_' . sanitize_key( $id ),
			'label'    => $hit[0],
			'evidence' => 'HTTP ' . $code,
			'hide'     => $hit[1],
			'fix'      => $hit[2],
		);
	}

	/* ---------- Admin ---------- */

	/**
	 * The settings tab the card is on.
	 *
	 * @return string
	 */
	public static function tab() {
		/**
		 * Filters the settings tab of the Stealth card.
		 *
		 * @param string $tab Tab.
		 */
		return (string) apply_filters( 'pncp_stealth_tab', 'hardening' );
	}

	/**
	 * Where the admin actions return to.
	 *
	 * @param string $message Notice code.
	 */
	private static function back( $message ) {
		$url = wp_get_referer();
		$url = $url ? remove_query_arg( array( 'pncp_stealth_msg' ), $url ) : PNCP_Status::settings_url( array( 'tab' => self::tab() ) );
		wp_safe_redirect( add_query_arg( 'pncp_stealth_msg', $message, $url ) . '#pncp-stealth' );
		exit;
	}

	/**
	 * Keeps the text of an error for the next page view of this user.
	 *
	 * @param true|WP_Error $result Result.
	 * @return string Notice code.
	 */
	private static function remember( $result ) {
		if ( is_wp_error( $result ) ) {
			set_transient( 'pncp_stealth_err_' . get_current_user_id(), $result->get_error_message(), 10 * MINUTE_IN_SECONDS );
			return 'error';
		}
		return 'ok';
	}

	/**
	 * Checks the nonce and the capability of an admin action.
	 *
	 * @param string $action Nonce action.
	 */
	private static function verify( $action ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	/**
	 * "Save and test" of the card.
	 */
	public static function handle_save() {
		self::verify( self::ACTION_SAVE );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked in verify().
		$base   = isset( $_POST['stealth_base'] ) ? sanitize_text_field( wp_unslash( $_POST['stealth_base'] ) ) : '';
		$prefix = isset( $_POST['stealth_rest_prefix'] ) ? sanitize_text_field( wp_unslash( $_POST['stealth_rest_prefix'] ) ) : '';
		$reason = '';
		$clean  = self::sanitize_base( $base, $reason );
		if ( '' === $clean ) {
			self::back( self::remember( new WP_Error( 'pncp_stealth_base', $reason ) ) );
		}
		$reason = '';
		$rest   = self::sanitize_rest_prefix( $prefix, $reason );
		if ( '' !== $reason ) {
			self::back( self::remember( new WP_Error( 'pncp_stealth_rest', $reason ) ) );
		}
		$changes = array(
			'stealth_enabled'     => empty( $_POST['stealth_enabled'] ) ? 0 : 1,
			'stealth_base'        => $clean,
			'stealth_rest_prefix' => $rest,
			'stealth_sitemap'     => empty( $_POST['stealth_sitemap'] ) ? 0 : 1,
			'stealth_block_files' => empty( $_POST['stealth_block_files'] ) ? 0 : 1,
			'stealth_endpoints'   => empty( $_POST['stealth_endpoints'] ) ? 0 : 1,
		);
		// phpcs:enable
		self::back( self::remember( self::save( $changes ) ) );
	}

	/**
	 * "Test again".
	 */
	public static function handle_test() {
		self::verify( self::ACTION_TEST );
		self::back( self::remember( self::activate() ) );
	}

	/**
	 * "Turn off".
	 */
	public static function handle_off() {
		self::verify( self::ACTION_OFF );
		self::back( self::remember( self::save( array( 'stealth_enabled' => 0 ) ) ) );
	}

	/**
	 * "Scan now".
	 */
	public static function handle_scan() {
		self::verify( self::ACTION_SCAN );
		self::scan();
		self::back( 'scanned' );
	}

	/**
	 * A form button for an admin action.
	 *
	 * @param string $action Action.
	 * @param string $label  Label.
	 * @param string $css    Button class.
	 */
	private static function button( $action, $label, $css = 'button' ) {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pncp-inline-form" style="display:inline-block;margin:0 6px 6px 0">
			<input type="hidden" name="action" value="<?php echo esc_attr( $action ); ?>">
			<?php wp_nonce_field( $action ); ?>
			<button type="submit" class="<?php echo esc_attr( $css ); ?>"><?php echo esc_html( $label ); ?></button>
		</form>
		<?php
	}

	/**
	 * The card: switch and options, the state of the self-test, the rules, and "What still shows this is WordPress".
	 */
	public static function render_card() {
		$s      = self::settings();
		$state  = self::state();
		$active = self::active();
		$server = self::server();
		$locked = PNCP_Lockdown::is_locked();
		$scan   = get_transient( self::SCAN );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects a notice.
		$msg = isset( $_GET['pncp_stealth_msg'] ) ? sanitize_key( wp_unslash( $_GET['pncp_stealth_msg'] ) ) : '';
		$err = '';
		if ( 'error' === $msg ) {
			$err = (string) get_transient( 'pncp_stealth_err_' . get_current_user_id() );
			delete_transient( 'pncp_stealth_err_' . get_current_user_id() );
		}
		$login = class_exists( 'PNCP_Login' ) ? PNCP_Login::slug() : '';
		?>
		<section class="pncp-card pncp-card--wide pncp-stealth" id="pncp-stealth" aria-labelledby="pncp-stealth-title">
			<h2 id="pncp-stealth-title"><?php esc_html_e( 'Stealth: do not show that the site runs on WordPress', 'scrapelock' ); ?>
				<?php $pncp_badge = PNCP_Status_State::stealth( $s ); // 3.11: three states, with the reason. ?>
				<?php if ( $active ) : ?>
					<span class="pncp-badge" data-pncp-state="on"><?php esc_html_e( 'On', 'scrapelock' ); ?></span>
				<?php elseif ( PNCP_Status_State::SET === $pncp_badge['state'] ) : ?>
					<span class="pncp-badge pncp-badge--bad" data-pncp-state="set"><?php echo esc_html( PNCP_Status_State::text( $pncp_badge ) ); ?></span>
				<?php else : ?>
					<span class="pncp-badge" data-pncp-state="off"><?php esc_html_e( 'Off', 'scrapelock' ); ?></span>
				<?php endif; ?>
			</h2>
			<?php echo PNCP_Admin_Fields::para( __( 'Visitors get neutral addresses instead of /wp-content/ and other WordPress traces.', 'scrapelock' ), __( 'Tools like BuiltWith and Wappalyzer, and the scanners that look for known holes, first find out what a site is built with: from the addresses of the theme and plugin files (/wp-content/, /wp-includes/), the REST API (/wp-json/), the sitemap (/wp-sitemap.xml), markup only WordPress prints and files only WordPress has. With Stealth, visitors get neutral addresses instead (for example /assets/3fa9c1/style.css), served by rules of your web server. Nothing stored changes: turning it off puts everything back at once.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php echo PNCP_Admin_Fields::para( __( 'Tested before it turns on and twice a day. Clear the caches after switching.', 'scrapelock' ), __( 'Before it turns on, the site asks itself for files through the new addresses and compares them byte for byte with the real ones; if one does not come back, nothing changes, so the site never loses its styles or scripts. A check twice a day turns it off again on its own (and emails you) if the rules stop working. Signed-in users see the real addresses: check the result in a private window. Clear the page cache (and the CDN cache) after turning it on or off.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php echo PNCP_Admin_Fields::para( __( 'Nginx fastcgi cache: emptied too when SCRAPELOCK_FASTCGI_CACHE_PATH or Nginx Helper names its folder.', 'scrapelock' ), __( 'When Stealth is turned on or off, or its addresses change, ScrapeLock deletes this site\'s pages from the Nginx fastcgi cache if it knows the folder: the constant SCRAPELOCK_FASTCGI_CACHE_PATH in wp-config.php, else the folder of Nginx Helper. On the server, "wp scrapelock cache status" finds the folder in the Nginx configuration and prints the line to add; "wp scrapelock cache purge --all" empties it. Only cache files of this site\'s addresses are deleted.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>

			<?php if ( 'ok' === $msg ) : ?>
				<div class="notice notice-success inline"><p><?php echo esc_html( $active ? __( 'Tested and on.', 'scrapelock' ) : __( 'Saved. Stealth is off.', 'scrapelock' ) ); ?></p></div>
			<?php elseif ( 'error' === $msg && '' !== $err ) : ?>
				<div class="notice notice-error inline"><p><?php echo esc_html( $err ); ?></p></div>
			<?php elseif ( 'scanned' === $msg ) : ?>
				<div class="notice notice-success inline"><p><?php esc_html_e( 'Scan done.', 'scrapelock' ); ?></p></div>
			<?php endif; ?>
			<?php if ( ! $active && ! empty( $s['stealth_enabled'] ) && '' !== (string) $state['error'] && 'error' !== $msg ) : ?>
				<div class="notice notice-warning inline"><p><strong><?php esc_html_e( 'Stealth is turned on but not working:', 'scrapelock' ); ?></strong> <?php echo esc_html( (string) $state['error'] ); ?></p></div>
			<?php endif; ?>
			<?php if ( $active && $state['pending'] && 'apache' !== $state['server'] ) : ?>
				<div class="notice notice-info inline"><p><?php esc_html_e( 'A plugin or theme changed: copy the new server rules below and press "Test again". Until then its files are served through the general wp-content address, which works but shows the plugin\'s folder name.', 'scrapelock' ); ?></p></div>
			<?php else : ?>
				<?php PNCP_Stealth_Status::render_card_line(); // 3.12.6: the Stealth rules on the server. ?>
			<?php endif; ?>
			<?php if ( $locked ) : ?>
				<p><strong><?php esc_html_e( 'The site is locked with Lockdown: unlock it to change Stealth.', 'scrapelock' ); ?></strong></p>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_SAVE ); ?>">
				<?php wp_nonce_field( self::ACTION_SAVE ); ?>
				<p><label><input type="checkbox" name="stealth_enabled" value="1" <?php checked( ! empty( $s['stealth_enabled'] ) ); ?> <?php disabled( $locked ); ?>> <strong><?php esc_html_e( 'Turn on Stealth (tested first)', 'scrapelock' ); ?></strong></label></p>
				<p>
					<label for="pncp-stealth-base"><?php esc_html_e( 'Folder of the new addresses:', 'scrapelock' ); ?></label>
					<code><?php echo esc_html( self::home_path() ); ?></code><input type="text" id="pncp-stealth-base" name="stealth_base" class="regular-text" style="width:12em" value="<?php echo esc_attr( (string) $s['stealth_base'] ); ?>" <?php disabled( $locked ); ?>><code>/…</code>
					<br><span class="description"><?php esc_html_e( 'Any neutral word, e.g. assets or static.', 'scrapelock' ); ?></span>
				</p>
				<?php echo PNCP_Admin_Fields::more( __( 'The real addresses keep working too (scanners that guess them still find the files; nothing on your pages points to them any more).', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
				<p>
					<label for="pncp-stealth-rest"><?php esc_html_e( 'REST API prefix instead of wp-json (empty = keep wp-json):', 'scrapelock' ); ?></label>
					<input type="text" id="pncp-stealth-rest" name="stealth_rest_prefix" class="regular-text" style="width:12em" value="<?php echo esc_attr( (string) $s['stealth_rest_prefix'] ); ?>" placeholder="api" <?php disabled( $locked ); ?>>
					<br><span class="description"><?php esc_html_e( 'Signed-in API clients keep /wp-json/; others get “page not found”.', 'scrapelock' ); ?></span>
				</p>
				<?php echo PNCP_Admin_Fields::more( __( 'The block editor and everything on the site use the new prefix by themselves. /wp-json/ keeps working for requests that sign in (application passwords, WooCommerce API keys, Jetpack); for anyone else it answers "page not found". Leave it empty if an app or service calls /wp-json/ without signing in.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
				<p><label><input type="checkbox" name="stealth_sitemap" value="1" <?php checked( ! empty( $s['stealth_sitemap'] ) ); ?> <?php disabled( $locked ); ?>> <?php esc_html_e( 'Sitemap at /sitemap.xml instead of /wp-sitemap.xml', 'scrapelock' ); ?></label>
					<br><span class="description"><?php esc_html_e( 'robots.txt points to it. Resubmit /sitemap.xml in Search Console.', 'scrapelock' ); ?></span></p>
				<?php echo PNCP_Admin_Fields::more( __( 'robots.txt points to the new address. Verified search engines that ask for the old one are redirected; others get "page not found". Only WordPress\'s own sitemaps (not those of an SEO plugin), with pretty permalinks. If you submitted the old address in Google Search Console, submit /sitemap.xml.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
				<p><label><input type="checkbox" name="stealth_endpoints" value="1" <?php checked( ! empty( $s['stealth_endpoints'] ) ); ?> <?php disabled( $locked ); ?>> <?php esc_html_e( 'Neutral addresses for forms and Ajax', 'scrapelock' ); ?></label>
					<br><span class="description"><?php esc_html_e( 'admin-ajax.php, admin-post.php and wp-comments-post.php get neutral addresses.', 'scrapelock' ); ?></span></p>
				<?php echo PNCP_Admin_Fields::more( __( 'admin-ajax.php, admin-post.php and wp-comments-post.php get addresses in the same folder (…/ajax, …/post, …/comment) in the pages visitors get. The real files keep working.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
				<p><label><input type="checkbox" name="stealth_block_files" value="1" <?php checked( ! empty( $s['stealth_block_files'] ) ); ?> <?php disabled( $locked ); ?>> <?php esc_html_e( 'Refuse readme.html and other files only WordPress has', 'scrapelock' ); ?></label>
					<br><span class="description"><?php esc_html_e( 'readme.html, license.txt and similar answer “page not found”; trackbacks stop.', 'scrapelock' ); ?></span></p>
				<?php echo PNCP_Admin_Fields::more( __( 'readme.html, license.txt, wp-config-sample.php, wp-links-opml.php and wp-trackback.php answer "page not found" (trackbacks stop; they are nearly all spam). Not while Monitor only is on.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
				<p class="description">
					<?php if ( '' === $login ) : ?>
						<?php esc_html_e( 'wp-login.php still shows WordPress: move the sign-in address on the Bots and limits tab.', 'scrapelock' ); ?>
					<?php else : ?>
						<?php /* translators: %s: sign-in address */ ?>
						<?php echo esc_html( sprintf( __( 'The sign-in page is at %s; wp-login.php and /wp-admin/ answer "page not found".', 'scrapelock' ), home_url( '/' . $login . '/' ) ) ); ?>
					<?php endif; ?>
				</p>
				<?php if ( ! $locked ) : ?>
					<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Save and test', 'scrapelock' ); ?></button></p>
				<?php endif; ?>
			</form>
			<?php if ( ! $locked && ! empty( $s['stealth_enabled'] ) ) : ?>
				<p>
					<?php self::button( self::ACTION_TEST, __( 'Test again', 'scrapelock' ) ); ?>
					<?php self::button( self::ACTION_OFF, __( 'Turn off', 'scrapelock' ) ); ?>
				</p>
			<?php endif; ?>
			<?php if ( $state['tested'] ) : ?>
				<?php /* translators: 1: date and time, 2: web server */ ?>
				<p class="description"><?php echo esc_html( sprintf( __( 'Last tested: %1$s (%2$s).', 'scrapelock' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $state['tested'] ), (string) $state['server'] ) ); ?></p>
			<?php endif; ?>

			<details <?php echo 'apache' !== $server && ! $active ? 'open' : ''; ?>>
				<summary><?php echo esc_html( 'apache' === $server ? __( 'Server rules (written into .htaccess for you)', 'scrapelock' ) : __( 'Server rules (add them, then press Save and test)', 'scrapelock' ) ); ?></summary>
				<?php if ( 'apache' !== $server ) : ?>
					<?php echo PNCP_Admin_Fields::para( __( 'Nginx: in the server { } block above the locations, then nginx -t and reload.', 'scrapelock' ), __( 'Nginx: inside the site\'s server { } block, above the location blocks; then nginx -t and reload. Other servers (IIS, Caddy): the same rewrites in their own syntax. After adding or removing a plugin, copy them again.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
					<?php echo PNCP_Admin_Fields::para( __( 'aaPanel: a file of its own in extension/<site>/, after scrapelock.conf, e.g. z-scrapelock-stealth.conf.', 'scrapelock' ), PNCP_Stealth_Status::aapanel_text() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
					<p><a href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => 'rules' ) ) . '#pncp-rules-stealth' ); ?>"><?php esc_html_e( 'Status of the Stealth rules', 'scrapelock' ); ?></a></p>
				<?php elseif ( ! self::htaccess_writable() ) : ?>
					<p class="description"><?php esc_html_e( 'The .htaccess file cannot be written: copy the Apache rules into it yourself, above # BEGIN WordPress.', 'scrapelock' ); ?></p>
				<?php endif; ?>
				<h3><?php esc_html_e( 'Nginx', 'scrapelock' ); ?></h3>
				<textarea class="large-text code" rows="8" readonly><?php echo esc_textarea( self::rules_text( 'nginx' ) ); ?></textarea>
				<h3><?php esc_html_e( 'Apache (.htaccess, above # BEGIN WordPress)', 'scrapelock' ); ?></h3>
				<textarea class="large-text code" rows="8" readonly><?php echo esc_textarea( self::rules_text( 'apache' ) ); ?></textarea>
				<?php echo PNCP_Admin_Fields::para( __( 'Styles lost after a server change? Define SCRAPELOCK_STEALTH_OFF as true in wp-config.php.', 'scrapelock' ), __( 'If the site ever loses its styles after a server change, add define( \'SCRAPELOCK_STEALTH_OFF\', true ); to wp-config.php: the real addresses are used again at once.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			</details>

			<h3><?php esc_html_e( 'What still shows this is WordPress', 'scrapelock' ); ?></h3>
			<?php echo PNCP_Admin_Fields::para( __( 'Looks for WordPress traces in pages and files, as a signed-out visitor.', 'scrapelock' ), __( 'The scan asks the home page, a post, a "page not found" page, robots.txt and the files only WordPress has, as a visitor who is not signed in, and looks for the signs that BuiltWith, Wappalyzer and the scanners use.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php self::button( self::ACTION_SCAN, __( 'Scan now', 'scrapelock' ) ); ?>
			<?php if ( is_array( $scan ) && isset( $scan['found'] ) ) : ?>
				<?php /* translators: %s: date and time */ ?>
				<p class="description"><?php echo esc_html( sprintf( __( 'Scanned: %s.', 'scrapelock' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $scan['time'] ) ) ); ?></p>
				<?php if ( ! $scan['found'] ) : ?>
					<p><strong><?php esc_html_e( 'Nothing found.', 'scrapelock' ); ?></strong></p>
				<?php else : ?>
					<div class="pncp-table-wrap">
					<table class="widefat striped">
						<thead><tr><th><?php esc_html_e( 'Sign', 'scrapelock' ); ?></th><th><?php esc_html_e( 'Where', 'scrapelock' ); ?></th><th><?php esc_html_e( 'Found', 'scrapelock' ); ?></th><th><?php esc_html_e( 'What to do', 'scrapelock' ); ?></th></tr></thead>
						<tbody>
						<?php foreach ( $scan['found'] as $f ) : ?>
							<tr>
								<td>
									<?php echo esc_html( (string) $f['label'] ); ?>
									<?php if ( empty( $f['hide'] ) ) : ?>
										<span class="pncp-badge"><?php esc_html_e( 'cannot be hidden', 'scrapelock' ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php echo esc_html( implode( ', ', (array) $f['pages'] ) ); ?></td>
								<td><code><?php echo esc_html( (string) $f['evidence'] ); ?></code></td>
								<td><?php echo esc_html( (string) $f['fix'] ); ?></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
					</div>
				<?php endif; ?>
			<?php endif; ?>
			<details>
				<summary><?php esc_html_e( 'What can never be hidden', 'scrapelock' ); ?></summary>
				<ul class="ul-disc">
					<li><?php esc_html_e( 'Signed-in users get WordPress\'s cookies (wordpress_logged_in_…) and the real addresses; shoppers get WooCommerce\'s cart cookies.', 'scrapelock' ); ?></li>
					<li><?php esc_html_e( 'Class names the styles depend on: the blocks (wp-block-…), WooCommerce (woocommerce, product, cart) and those of the theme and the page builders, and the data-wp-… attributes and @wordpress/ modules of interactive blocks.', 'scrapelock' ); ?></li>
					<li><?php esc_html_e( 'Markup and script names a plugin prints itself (e.g. wc_add_to_cart_params), and addresses a script builds while the page runs.', 'scrapelock' ); ?></li>
					<li><?php esc_html_e( 'What optimization plugins print for their own scripts: WP Rocket\'s data-rocket-… attributes, rocket-lazyload and rocketlazyloadscript (its lazy loading and delayed scripts need them), and the addresses inside the CSS and JavaScript files they minify or combine (a file is sent as it is stored). The addresses of those files themselves are neutral (WP Rocket, Autoptimize, LiteSpeed Cache, W3 Total Cache).', 'scrapelock' ); ?></li>
					<li><?php esc_html_e( 'The real addresses of files still answer (/wp-content/…, /wp-includes/…, xmlrpc.php): the administration, feeds and emails need them, so a scanner that guesses them still finds WordPress. To refuse them, lock “XML-RPC” on the Vulnerable points tab, and block /wp-includes/ and /wp-content/ requests without a same-site Referer at your CDN or server if you need to (test it first: some feed readers and email clients load images that way). With a REST prefix of your own, /wp-json/ and ?rest_route= answer only requests that sign in.', 'scrapelock' ); ?></li>
					<li><?php esc_html_e( 'Comments a page-cache plugin adds when it stores the page (W3 Total Cache, WP Super Cache, LiteSpeed Cache, WP Fastest Cache, Hummingbird): turn them off in that plugin. Those of WP Rocket and Redis Object Cache are turned off, and the file paths in the translations of scripts removed; their text domain stays.', 'scrapelock' ); ?></li>
					<li><?php esc_html_e( 'Your hosting, DNS and IP addresses, and the TLS certificate. WHOIS shows who registered the domain, not what the site is built with: hide those details with the privacy option of your domain registrar.', 'scrapelock' ); ?></li>
				</ul>
			</details>
		</section>
		<?php
	}

	/* ---------- Site Health and WP-CLI ---------- */

	/**
	 * Adds the async Site Health test while Stealth is turned on.
	 *
	 * @param array<string, mixed> $tests Tests.
	 * @return array<string, mixed>
	 */
	public static function health_tests( $tests ) {
		if ( ! empty( self::settings()['stealth_enabled'] ) ) {
			$tests['async']['scrapelock_stealth'] = array(
				'label'    => __( 'ScrapeLock Stealth', 'scrapelock' ),
				'test'     => 'scrapelock-stealth',
				'has_rest' => false,
			);
		}
		return $tests;
	}

	/**
	 * The Site Health result.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_result() {
		$link   = sprintf( '<p><a href="%s">%s</a></p>', esc_url( PNCP_Status::settings_url( array( 'tab' => self::tab() ) ) . '#pncp-stealth' ), esc_html__( 'Open Stealth', 'scrapelock' ) );
		$result = array(
			'label'       => __( 'WordPress is hidden from tools that tell what a site is built with', 'scrapelock' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html__( 'Visitors get neutral addresses for the theme, plugin and core files, and markup only WordPress prints is removed.', 'scrapelock' ) . '</p>',
			'actions'     => $link,
			'test'        => 'scrapelock_stealth',
		);
		if ( ! self::active() ) {
			$state                 = self::state();
			$result['status']      = 'recommended';
			$result['label']       = __( 'ScrapeLock Stealth is turned on but not working', 'scrapelock' );
			$result['description'] = '<p>' . esc_html( '' !== (string) $state['error'] ? (string) $state['error'] : __( 'The new addresses have not been tested yet.', 'scrapelock' ) ) . '</p>';
			return PNCP_Stealth_Status::health( $result );
		}
		$scan = get_transient( self::SCAN );
		if ( ! is_array( $scan ) || empty( $scan['active'] ) ) {
			$scan = self::scan();
		}
		$left = array_filter(
			(array) $scan['found'],
			function ( $f ) {
				return ! empty( $f['hide'] );
			}
		);
		if ( $left ) {
			$result['status']      = 'recommended';
			$result['label']       = __( 'Some pages still show that the site runs on WordPress', 'scrapelock' );
			$items                 = array_map(
				function ( $f ) {
					return '<li>' . esc_html( $f['label'] . ': ' . $f['fix'] ) . '</li>';
				},
				$left
			);
			$result['description'] = '<ul>' . implode( '', $items ) . '</ul>';
		}
		return PNCP_Stealth_Status::health( $result ); // 3.12.6: the Stealth rules on the server.
	}

	/**
	 * Site Health's async call.
	 */
	public static function ajax_health() {
		check_ajax_referer( 'health-check-site-status' );
		if ( ! current_user_can( 'view_site_health_checks' ) ) {
			wp_send_json_error();
		}
		wp_send_json_success( self::health_result() );
	}

	/**
	 * For `wp scrapelock stealth status`.
	 *
	 * @return array<string, string>
	 */
	public static function cli_status() {
		$s     = self::settings();
		$state = self::state();
		return array(
			'setting'  => ! empty( $s['stealth_enabled'] ) ? 'on' : 'off',
			'active'   => self::active() ? 'yes' : 'no',
			'base'     => self::home_path() . (string) $s['stealth_base'] . '/',
			'rest'     => '' === self::rest_prefix( $s ) ? 'wp-json' : self::rest_prefix( $s ),
			'sitemap'  => self::active() && self::live_sitemap() ? 'sitemap.xml' : 'wp-sitemap.xml',
			'server'   => self::server(),
			'htaccess' => ! empty( $state['htaccess'] ) ? 'written' : 'no',
			'tested'   => $state['tested'] ? gmdate( 'Y-m-d H:i:s', (int) $state['tested'] ) . ' UTC' : '-',
			'folders'  => (string) count( (array) $state['map'] ),
			'rules'    => null !== PNCP_Stealth_Status::kept_status() ? PNCP_Stealth_Status::kept_status()['state'] : '-', // 3.12.6.
			'error'    => (string) $state['error'],
		);
	}

	/**
	 * For `wp scrapelock stealth on [--base=<folder>] [--rest=<prefix>]`.
	 *
	 * @param array<string, string> $args Options.
	 * @return true|WP_Error
	 */
	public static function cli_enable( $args = array() ) {
		$changes = array( 'stealth_enabled' => 1 );
		if ( isset( $args['base'] ) ) {
			$reason = '';
			$base   = self::sanitize_base( $args['base'], $reason );
			if ( '' === $base ) {
				return new WP_Error( 'pncp_stealth_base', $reason );
			}
			$changes['stealth_base'] = $base;
		}
		if ( isset( $args['rest'] ) ) {
			$reason = '';
			$rest   = self::sanitize_rest_prefix( $args['rest'], $reason );
			if ( '' !== $reason ) {
				return new WP_Error( 'pncp_stealth_rest', $reason );
			}
			$changes['stealth_rest_prefix'] = $rest;
		}
		return self::save( $changes );
	}

	/**
	 * For `wp scrapelock stealth off`.
	 *
	 * @return true|WP_Error
	 */
	public static function cli_disable() {
		return self::save( array( 'stealth_enabled' => 0 ) );
	}

	/**
	 * For `wp scrapelock stealth test`.
	 *
	 * @return true|WP_Error
	 */
	public static function cli_test() {
		return self::activate();
	}

	/**
	 * For `wp scrapelock stealth scan [--url=<home>]`: rows of what was found.
	 *
	 * @param string $url Home page.
	 * @return array<int, array<string, string>>
	 */
	public static function cli_scan( $url = '' ) {
		$scan = self::scan( $url );
		$rows = array();
		foreach ( $scan['found'] as $f ) {
			$rows[] = array(
				'sign'     => (string) $f['label'],
				'pages'    => implode( ',', (array) $f['pages'] ),
				'hideable' => $f['hide'] ? 'yes' : 'no',
				'found'    => (string) $f['evidence'],
			);
		}
		return $rows;
	}
}
