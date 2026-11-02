<?php
/**
 * Generator of web server and Cloudflare rules, tailored to this specific site.
 *
 * The plugin protects only what reaches PHP. Pages from page cache, static files (images, .xml)
 * and the folder with the clean originals need rules on the server or the CDN. The plugin keeps no Cloudflare
 * API token: it outputs the rules and you apply them yourself.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Nginx, Apache and Cloudflare rules.
 */
final class PNCP_Rules {

	/**
	 * Platforms that load images from your site (hotlinking allowed).
	 *
	 * @return string[]
	 */
	public static function hotlink_allowed() {
		return (array) apply_filters(
			'pncp_hotlink_allowed',
			array( 'google.', 'googleusercontent.', 'bing.com', 'skroutz.gr', 'bestprice.gr', 'facebook.com', 'instagram.com', 'pinterest.' )
		);
	}

	/**
	 * The site domain.
	 *
	 * @return string
	 */
	private static function host() {
		return (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * The path of a URL of this site, without a trailing slash (e.g. /wp-content for content_url()).
	 *
	 * @param string $url URL.
	 * @return string
	 */
	private static function url_path( $url ) {
		return untrailingslashit( (string) wp_parse_url( $url, PHP_URL_PATH ) );
	}

	/**
	 * The uploads path within the site (e.g. /wp-content/uploads).
	 *
	 * @return string
	 */
	private static function uploads_path() {
		$path = (string) wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH );
		return untrailingslashit( $path );
	}

	/**
	 * The User-Agents of the bot list, with the AI crawlers built into the plugin (Nginx and Apache: one regex,
	 * no length limit). Cloudflare gets only the editable list: its own "AI Crawler" category rule covers the rest.
	 *
	 * @param bool $builtin Whether to add the built-in AI crawlers.
	 * @return string[]
	 */
	private static function bots( $builtin = true ) {
		$s = PNCP_Options::get();
		return $builtin ? PNCP_Options::blocked_agents( $s ) : PNCP_Options::parse_list( $s['bot_list'] );
	}

	/**
	 * Files that give the version of WordPress or of a plugin / theme away ("Hide versions"): readme.html and
	 * license.txt in the WordPress folder, and readme / changelog files of plugins and themes. Static files:
	 * WordPress never sees the request, so only the server can refuse them.
	 *
	 * @return string[] Regexes of the request path (with the leading slash).
	 */
	private static function version_regexes() {
		$core    = untrailingslashit( (string) wp_parse_url( site_url( '/' ), PHP_URL_PATH ) );
		$content = untrailingslashit( (string) wp_parse_url( content_url(), PHP_URL_PATH ) );
		return array(
			'^' . preg_quote( $core, '#' ) . '/(?:readme\.html|license\.txt)$',
			'^' . preg_quote( $content, '#' ) . '/(?:plugins|themes|mu-plugins)/.*/(?:readme|changelog|changes|history|upgrade)(?:\.(?:txt|md|html?))?$',
		);
	}

	/**
	 * PHP in the uploads folder: files people and plugins upload must never run. A backdoor uploaded through a
	 * vulnerable plugin usually lands there.
	 *
	 * @return string Regex of the request path (with the leading slash).
	 */
	private static function upload_php_regex() {
		return '^' . preg_quote( self::uploads_path(), '#' ) . '/.*\.(?:php[0-9]?|phtml|phar)$';
	}

	/**
	 * Apache reads an .htaccess inside the uploads folder by itself: ScrapeLock writes its block there ("No PHP
	 * in the uploads folder"), between its own markers, so whatever other plugins wrote there stays. Nginx
	 * ignores the file: it needs the rule of the "Server rules" tab.
	 *
	 * @param bool|null $on Whether the block should be there (null = the setting).
	 */
	public static function sync_uploads_htaccess( $on = null ) {
		$on   = null === $on ? ! empty( PNCP_Options::get()['enabled'] ) && ! empty( PNCP_Options::get()['block_upload_php'] ) : (bool) $on;
		$dir  = wp_get_upload_dir()['basedir'];
		$file = trailingslashit( $dir ) . '.htaccess';
		if ( ! is_dir( $dir ) || ( ! $on && ! file_exists( $file ) ) ) {
			return;
		}
		if ( ! $on ) {
			// Off: only a file that has our block is touched, and the block goes completely, markers included
			// (insert_with_markers() with no lines would leave an empty block with its comments in someone
			// else's file).
			self::remove_marker_block( $file );
			return;
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$lines = array(
			'# No PHP in the uploads folder: a file uploaded here never runs as code.',
			'<FilesMatch "\.(?i:php[0-9]?|phtml|phar)$">',
			'	<IfModule mod_authz_core.c>',
			'		Require all denied',
			'	</IfModule>',
			'	<IfModule !mod_authz_core.c>',
			'		Order allow,deny',
			'		Deny from all',
			'	</IfModule>',
			'</FilesMatch>',
		);
		insert_with_markers( $file, 'ScrapeLock', $lines );
	}

	/**
	 * Removes the "# BEGIN ScrapeLock … # END ScrapeLock" block from a file, if it has one. The rest of the file
	 * stays as it is; a file that held nothing else is left empty, not deleted (the server may expect it).
	 *
	 * @param string $file File.
	 */
	public static function remove_marker_block( $file ) {
		if ( ! is_readable( $file ) || ! wp_is_writable( $file ) ) {
			return;
		}
		$text = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( false === strpos( $text, '# BEGIN ScrapeLock' ) ) {
			return;
		}
		// insert_with_markers() joins the lines before the block, the block and the lines after it with line
		// breaks, so it adds one line break before "# BEGIN ScrapeLock" (a blank line when the file ended with
		// one). That line break goes with the block, so the file is byte for byte what it was before the block
		// was added, and turning the setting on and off again does not leave one more blank line each time.
		// A block at the very start of the file has no line break before it: the one after it goes instead.
		$clean = (string) preg_replace(
			array(
				'/\R^# BEGIN ScrapeLock\R.*?^# END ScrapeLock(?=\R|\z)/ms',
				'/\A# BEGIN ScrapeLock\R.*?^# END ScrapeLock(?:\R|\z)/ms',
			),
			'',
			$text
		);
		if ( $clean !== $text ) {
			file_put_contents( $file, $clean, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Same file, same owner.
		}
	}

	/**
	 * After the settings are saved (hook update_option_pncp_settings, whose arguments are not used).
	 */
	public static function settings_saved() {
		self::sync_uploads_htaccess();
	}

	/**
	 * The always-allowed User-Agents.
	 *
	 * @return string[]
	 */
	private static function allowed() {
		$out = array();
		foreach ( PNCP_Options::parse_list( PNCP_Options::get()['allow_list'] ) as $entry ) {
			$entry = PNCP_Options::split_allow_entry( $entry );
			// Entries tied to IPs are checked by WordPress: server rules cannot combine User-Agent and IP here.
			if ( ! $entry['pinned'] && '' !== $entry['ua'] ) {
				$out[] = $entry['ua'];
			}
		}
		return array_merge( $out, PNCP_Options::allowed_ai_search() );
	}

	/**
	 * The private paths as regex (for Nginx / Apache).
	 *
	 * @return string[]
	 */
	private static function private_regexes() {
		$out = array();
		foreach ( PNCP_Options::parse_list( PNCP_Options::get()['private_paths'] ) as $pattern ) {
			// Patterns with a query, or too broad to be safe, are left to PHP (a server rule cannot check them).
			$parsed = PNCP_Private_Urls::parse_pattern( $pattern );
			if ( null === $parsed || $parsed['query'] ) {
				continue;
			}
			$full  = (string) wp_parse_url( home_url( $parsed['path'] ), PHP_URL_PATH );
			$out[] = '^' . str_replace( '\*', '.*', preg_quote( $full, '#' ) ) . '$';
		}
		return $out;
	}

	/**
	 * Regex for Nginx/Apache from a word list.
	 *
	 * @param string[] $words Words.
	 * @return string
	 */
	private static function alternation( $words ) {
		$quoted = array();
		foreach ( $words as $word ) {
			$exact    = '=' === substr( $word, 0, 1 ); // "=node": the whole User-Agent.
			$quoted[] = ( $exact ? '^' : '' ) . str_replace( array( ' ', '"' ), array( '\\s', '' ), preg_quote( $exact ? substr( $word, 1 ) : $word, '#' ) ) . ( $exact ? '$' : '' );
		}
		return '(' . implode( '|', $quoted ) . ')';
	}

	/**
	 * The site's own suffix for the Nginx names (variables, limit zone): several WordPress sites can share one
	 * Nginx, and the same name defined twice in http { } stops nginx -t.
	 *
	 * @return string E.g. example_com.
	 */
	public static function nginx_id() {
		$site = (string) preg_replace( '#^[a-z]+://#i', '', untrailingslashit( home_url() ) );
		$id   = trim( strtolower( (string) preg_replace( '/[^A-Za-z0-9]+/', '_', $site ) ), '_' );
		if ( '' === $id || strlen( $id ) > 40 ) {
			$id = substr( $id, 0, 33 ) . '_' . substr( md5( $site ), 0, 6 );
		}
		return $id;
	}

	/**
	 * Nginx name with the site's suffix (without the $).
	 *
	 * @param string $name Name, e.g. block.
	 * @return string E.g. pncp_block_example_com.
	 */
	private static function nv( $name ) {
		return 'pncp_' . $name . '_' . self::nginx_id();
	}

	/**
	 * Fingerprint of the rules: the lines without the comments, so a new plugin version with the same rules is
	 * not reported as out of date.
	 *
	 * @param string[] $lines Lines.
	 * @return string
	 */
	private static function nginx_hash( $lines ) {
		$rules = array();
		foreach ( $lines as $line ) {
			if ( '' !== trim( $line ) && 0 !== strpos( ltrim( $line ), '#' ) ) {
				$rules[] = trim( $line );
			}
		}
		return substr( md5( implode( "\n", $rules ) ), 0, 12 );
	}

	/**
	 * The address at which the installed rules answer with their fingerprints.
	 *
	 * @return string E.g. /.well-known/scrapelock-nginx.
	 */
	public static function nginx_check_path() {
		return (string) wp_parse_url( home_url( '/.well-known/scrapelock-nginx' ), PHP_URL_PATH );
	}

	/**
	 * Whether the Nginx rules are installed and match the current settings. The site asks itself; the answer is
	 * kept for 5 minutes and is asked again as soon as the settings change the rules.
	 *
	 * @param bool $fresh Ask again now.
	 * @return array{state: string, parts: string[], error: string} state: current, stale, missing or error; parts:
	 *                                                               the out-of-date parts (http, server).
	 */
	public static function nginx_status( $fresh = false ) {
		preg_match( '/default "([0-9a-f]+)"/', self::nginx_http(), $http );
		preg_match( '/ ([0-9a-f]+)\\\\n";/', self::nginx_server(), $server );
		$want = ( $http[1] ?? '' ) . ' ' . ( $server[1] ?? '' );
		$key  = 'pncp_nginx_status';
		$got  = $fresh ? false : get_transient( $key );
		if ( ! is_array( $got ) || ( $got['want'] ?? '' ) !== $want ) {
			$response = wp_remote_get(
				add_query_arg( 't', time(), home_url( '/.well-known/scrapelock-nginx' ) ), // Past any CDN cache.
				array(
					'timeout'     => 5,
					'redirection' => 0,
					'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter for requests to the site itself.
				)
			);
			$got      = array(
				'want'  => $want,
				'body'  => is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ? '' : trim( (string) wp_remote_retrieve_body( $response ) ),
				'error' => is_wp_error( $response ) ? $response->get_error_message() : '',
			);
			set_transient( $key, $got, 5 * MINUTE_IN_SECONDS );
		}
		$out = array(
			'state' => 'missing',
			'parts' => array(),
			'error' => $got['error'],
		);
		if ( '' !== $got['error'] ) {
			$out['state'] = 'error';
		} elseif ( preg_match( '/^([0-9a-f]+) ([0-9a-f]+)$/', $got['body'], $m ) ) {
			list( $want_http, $want_server ) = explode( ' ', $want );
			if ( $m[1] !== $want_http ) {
				$out['parts'][] = 'http';
			}
			if ( $m[2] !== $want_server ) {
				$out['parts'][] = 'server';
			}
			$out['state'] = $out['parts'] ? 'stale' : 'current';
		}
		return $out;
	}

	/**
	 * Nginx rules: both parts together (for copying into a notes file).
	 *
	 * @return string
	 */
	public static function nginx() {
		return '# ScrapeLock ' . PNCP_VERSION . ' — ' . self::host() . "\n# 1) In http { } (e.g. /etc/nginx/conf.d/scrapelock.conf):\n"
			. self::nginx_http() . "\n# 2) In the server { } of " . self::host() . ":\n" . self::nginx_server();
	}

	/**
	 * Nginx, part 1: inside http { } (map for the bots, limit zone).
	 *
	 * @return string
	 */
	public static function nginx_http() {
		$s     = PNCP_Options::get();
		$lines = array();
		if ( $s['block_bots'] && self::bots() ) {
			$lines[] = 'map $http_user_agent $' . self::nv( 'bad_bot' ) . ' {';
			$lines[] = '    default 0;';
			if ( self::allowed() ) {
				$lines[] = '    "~*' . self::alternation( self::allowed() ) . '" 0;'; // First: it matches first.
			}
			$lines[] = '    "~*' . self::alternation( self::bots() ) . '" 1;';
			if ( $s['block_empty_ua'] ) {
				$lines[] = '    "" 1;';
			}
			$lines[] = '}';
		}
		if ( ( $s['block_bots'] && self::bots() ) || $s['block_headless'] ) {
			// robots.txt and llms.txt stay open for every bot: it must be able to read the rules it is asked to follow.
			$lines[] = 'map $uri $' . self::nv( 'open_path' ) . ' {';
			$lines[] = '    default 0;';
			$lines[] = '    "~*^/(robots|llms|llms-full)\.txt$" 1;';
			$lines[] = '    "~*^/\.well-known/tdmrep\.json$" 1;';
			$lines[] = '    ' . self::nginx_check_path() . ' 1;';
			$lines[] = '}';
		}
		if ( $s['block_headless'] ) {
			// Chrome / Edge / Opera 90+ always send Sec-Fetch-Mode and Sec-CH-UA over HTTPS, Firefox 90+ Sec-Fetch-Mode:
			// a "browser" without them is a script. Android in-app browsers (; wv) and the always-allowed User-Agents pass.
			$lines[] = 'map "$https|$http_sec_fetch_mode|$http_sec_ch_ua|$http_user_agent" $' . self::nv( 'fake_browser' ) . ' {';
			$lines[] = '    default 0;';
			$lines[] = '    "~*^[^|]*\\|[^|]*\\|[^|]*HeadlessChrome" 1;';
			$lines[] = '    "~; wv\\)" 0;';
			// Search engines and other bots also write "Chrome/" in their User-Agent and send no browser headers: they
			// are not fake browsers (WordPress verifies them by IP / DNS). Bot User-Agents name themselves or a URL.
			$lines[] = '    "~*^[^|]*\\|[^|]*\\|[^|]*\\|.*' . self::alternation( self::not_fake_browsers() ) . '" 0;';
			$lines[] = '    "~^on\\|\\|\\|.*\\b(Chrome|Chromium)/(9[0-9]|[1-9][0-9]{2})\\." 1;';
			$lines[] = '    "~^on\\|\\|[^|]*\\|.*\\bFirefox/(9[0-9]|[1-9][0-9]{2})\\." 1;';
			$lines[] = '}';
		}
		if ( self::private_regexes() ) {
			// Token for the static feeds: in the URL (cp_token) or in the header. Put your own in place of YOUR_TOKEN.
			$lines[] = 'map "$arg_cp_token:$http_x_scrapelock_token" $' . self::nv( 'token_ok' ) . ' {';
			$lines[] = '    default 0;';
			$lines[] = '    "~^YOUR_TOKEN:" 1;';
			$lines[] = '    "~:YOUR_TOKEN$" 1;';
			$lines[] = '}';
		}
		$checks = self::nginx_block_vars();
		if ( $checks ) {
			// One variable for the server { } part: blocked when a check says so, except on the open paths.
			$lines[] = 'map "' . implode( '', $checks ) . ':$' . self::nv( 'open_path' ) . '" $' . self::nv( 'block' ) . ' {';
			$lines[] = '    default 0;';
			$lines[] = '    "~^[01]*1[01]*:0$" 1;';
			$lines[] = '}';
		}
		$rate    = (int) $s['rate_limit'] > 0 ? (int) $s['rate_limit'] : 60;
		$lines[] = 'limit_req_zone $binary_remote_addr zone=' . self::nv( 'pages' ) . ':10m rate=' . $rate . 'r/m;';
		// Lets the plugin see that this part is installed and matches the current settings.
		$lines[] = 'map $host $' . self::nv( 'rules' ) . ' { default "' . self::nginx_hash( $lines ) . '"; }';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * The Nginx variables (maps in part 1) that block a request: bot list and / or fake browsers.
	 *
	 * @return string[]
	 */
	private static function nginx_block_vars() {
		$s    = PNCP_Options::get();
		$vars = array();
		if ( $s['block_bots'] && self::bots() ) {
			$vars[] = '$' . self::nv( 'bad_bot' );
		}
		if ( $s['block_headless'] ) {
			$vars[] = '$' . self::nv( 'fake_browser' );
		}
		return $vars;
	}

	/**
	 * Nginx, part 2: inside the site's server { }.
	 *
	 * @return string
	 */
	public static function nginx_server() {
		$s       = PNCP_Options::get();
		$host    = self::host();
		$uploads = self::uploads_path();
		$backup  = (string) get_option( 'pncp_backup_dir' );
		$lines   = array();
		if ( self::nginx_block_vars() ) {
			$lines[] = '# Blocks bots' . ( $s['block_headless'] ? ' and fake browsers' : '' ) . ' BEFORE the page cache (FastCGI cache, WP Rocket, WP Super Cache), also';
			$lines[] = '# for files that never reach WordPress (e.g. scanners asking for .php files). robots.txt / llms.txt stay open.';
			$lines[] = 'if ($' . self::nv( 'block' ) . ') { return 403; }';
			$lines[] = '';
		}
		$lines[] = '# Page limit per IP (also for cached pages): put this line ONLY in the location that serves pages';
		$lines[] = '# (PHP / page cache), NOT where CSS, JS, images and fonts are served: one page loads dozens of them.';
		$lines[] = '# Behind Cloudflare: set real_ip_header CF-Connecting-IP first (see the plugin FAQ).';
		$lines[] = '# Behind Bunny CDN: real_ip_header X-Real-IP, with set_real_ip_from for each Bunny edge server.';
		$lines[] = '#   limit_req zone=' . self::nv( 'pages' ) . ' burst=20 nodelay;';
		$lines[] = 'limit_req_status 429;';
		$lines[] = '';
		if ( '' !== $backup ) {
			$lines[] = '# Clean originals of watermarked images: never public.';
			$lines[] = 'location ^~ ' . $uploads . '/' . $backup . '/ { deny all; return 404; }';
			$lines[] = '';
		}
		if ( $s['hide_versions'] ) {
			$lines[] = '# Hide versions: readme / changelog files that give the version of WordPress, plugins and themes away (404).';
			foreach ( self::version_regexes() as $regex ) {
				$lines[] = 'location ~* ' . $regex . ' { return 404; }';
			}
			$lines[] = '';
		}
		if ( $s['block_upload_php'] ) {
			$lines[] = '# No PHP in the uploads folder. Put it ABOVE the location that passes .php files to PHP: Nginx uses the';
			$lines[] = '# first regex location that matches.';
			$lines[] = 'location ~* ' . self::upload_php_regex() . ' { deny all; }';
			$lines[] = '';
		}
		$lines[] = '# Hotlink: images load only from your site and from search engines / price comparison platforms.';
		$lines[] = '# (If a location for images already exists, e.g. for expires, put the two lines inside it.)';
		$lines[] = 'location ~* ^' . preg_quote( $uploads, '#' ) . '/.*\.(jpe?g|png|webp|gif|avif)$ {';
		// The domain as regex: as a plain name it would clash with server_names ("conflicting parameter" in nginx -t).
		$allowed = array();
		foreach ( self::hotlink_allowed() as $domain ) {
			$allowed[] = '~^' . self::referer_host_regex( $domain );
		}
		$lines[] = '    valid_referers none blocked server_names ~^([^/]*\\.)?' . self::nginx_referer( $host ) . '(:|/|$) ' . implode( ' ', $allowed ) . ';';
		$lines[] = '    if ($invalid_referer) { return 403; }';
		$lines[] = '}';
		$regexes = self::private_regexes();
		if ( $regexes ) {
			$lines[] = '';
			$lines[] = '# Feeds: static files only with the token (map $' . self::nv( 'token_ok' ) . ' in http { }). Feeds generated by PHP';
			$lines[] = '# go to WordPress, which checks the token, Bearer, allowed IPs and administrator.';
			$lines[] = '# (Only return inside the ifs: otherwise the Nginx "if is evil" problem would lose try_files.)';
			foreach ( $regexes as $regex ) {
				$lines[] = 'location ~* ' . $regex . ' {';
				$lines[] = '    error_page 418 = @pncp_static_feed;';
				$lines[] = '    if (-f $request_filename) { return 418; }';
				$lines[] = '    try_files $uri /index.php?$args;';
				$lines[] = '}';
			}
			$lines[] = 'location @pncp_static_feed {';
			$lines[] = '    if ($' . self::nv( 'token_ok' ) . ' = 0) { return 403; }';
			$lines[] = '    add_header Cache-Control "private, no-store" always;';
			$lines[] = '    add_header Referrer-Policy "no-referrer" always;';
			$lines[] = '    try_files $uri =404;';
			$lines[] = '}';
		}
		$lines[] = '';
		$lines[] = '# Lets ScrapeLock check that both parts are installed and match the current settings (tab "Server rules").';
		$lines[] = 'location = ' . self::nginx_check_path() . ' {';
		$lines[] = '    default_type text/plain;';
		$lines[] = '    add_header Cache-Control "no-store" always;';
		$lines[] = '    return 200 "$' . self::nv( 'rules' ) . ' ' . self::nginx_hash( $lines ) . '\\n";';
		$lines[] = '}';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Referer regex for Nginx.
	 *
	 * @param string $domain Domain.
	 * @return string
	 */
	public static function nginx_referer( $domain ) {
		return str_replace( '.', '\.', rtrim( $domain, '.' ) );
	}

	/**
	 * A referer regex anchored to the host: the domain itself or a subdomain of it, never the domain merely
	 * appearing somewhere in the address (https://leech.example/?google.com). "google." means any ending
	 * (google.com, google.gr).
	 *
	 * @param string $domain Domain from hotlink_allowed().
	 * @return string Regex for the host part, without the scheme.
	 */
	public static function referer_host_regex( $domain ) {
		$domain = (string) $domain;
		$body   = self::nginx_referer( $domain );
		// "google." = Google's own country domains (google.com, google.gr, google.co.uk, google.com.cy), not
		// google.example.com, which anyone can create under their own domain.
		$any    = '.' === substr( $domain, -1 ) ? '\.[a-z]{2,3}(\.[a-z]{2})?' : '';
		return '([^/]*\.)?' . $body . $any . '(:|/|$)';
	}

	/**
	 * Apache rules (.htaccess, above the WordPress rules).
	 *
	 * @return string
	 */
	public static function apache() {
		$s       = PNCP_Options::get();
		$host    = self::host();
		$uploads = ltrim( self::uploads_path(), '/' );
		$backup  = (string) get_option( 'pncp_backup_dir' );
		$lines   = array();

		$lines[] = '# BEGIN ScrapeLock ' . PNCP_VERSION;
		$lines[] = '<IfModule mod_rewrite.c>';
		$lines[] = 'RewriteEngine On';
		$open    = 'RewriteCond %{REQUEST_URI} !^/(?:(robots|llms|llms-full)\.txt|\.well-known/tdmrep\.json)$ [NC]';
		if ( $s['block_bots'] && self::bots() ) {
			$lines[] = '# Bots in the list: 403 before the page cache. robots.txt / llms.txt stay open for every bot.';
			$lines[] = $open;
			if ( self::allowed() ) {
				$lines[] = 'RewriteCond %{HTTP_USER_AGENT} !' . self::alternation( self::allowed() ) . ' [NC]';
			}
			$lines[] = 'RewriteCond %{HTTP_USER_AGENT} ' . self::alternation( self::bots() ) . ' [NC]';
			$lines[] = 'RewriteRule .* - [F,L]';
			if ( $s['block_empty_ua'] ) {
				$lines[] = $open;
				$lines[] = 'RewriteCond %{HTTP_USER_AGENT} ^-?$';
				$lines[] = 'RewriteRule .* - [F,L]';
			}
		}
		if ( $s['block_headless'] ) {
			$lines[] = '# Fake browsers: Chrome / Edge 90+ without Sec-Fetch-Mode and Sec-CH-UA, Firefox 90+ without Sec-Fetch-Mode (HTTPS only).';
			$lines[] = '# Search engines and other bots that write "Chrome/" in their User-Agent are not affected.';
			foreach ( array( 'chrome', 'firefox' ) as $browser ) {
				$lines[] = $open;
				$lines[] = 'RewriteCond %{HTTPS} =on';
				$lines[] = 'RewriteCond %{HTTP:Sec-Fetch-Mode} ^$';
				if ( 'chrome' === $browser ) {
					$lines[] = 'RewriteCond %{HTTP:Sec-CH-UA} ^$';
					$lines[] = 'RewriteCond %{HTTP_USER_AGENT} \b(Chrome|Chromium)/(9[0-9]|[1-9][0-9]{2})\.';
				} else {
					$lines[] = 'RewriteCond %{HTTP_USER_AGENT} \bFirefox/(9[0-9]|[1-9][0-9]{2})\.';
				}
				$lines[] = 'RewriteCond %{HTTP_USER_AGENT} !(;\swv\)|' . substr( self::alternation( self::not_fake_browsers() ), 1 ) . ' [NC]';
				$lines[] = 'RewriteRule .* - [F,L]';
			}
		}
		if ( '' !== $backup ) {
			$lines[] = '# Clean originals: never public (there is also an .htaccess inside the folder).';
			$lines[] = 'RewriteRule ^' . preg_quote( $uploads . '/' . $backup, '#' ) . '/ - [F,L]';
		}
		if ( $s['hide_versions'] ) {
			$lines[] = '# Hide versions: readme / changelog files that give the version of WordPress, plugins and themes away (404).';
			foreach ( self::version_regexes() as $regex ) {
				$lines[] = 'RewriteRule ' . str_replace( '^/', '^', $regex ) . ' - [R=404,NC,L]';
			}
		}
		if ( $s['block_upload_php'] ) {
			$lines[] = '# No PHP in the uploads folder (ScrapeLock also writes this into the .htaccess of the uploads folder).';
			$lines[] = 'RewriteRule ' . str_replace( '^/', '^', self::upload_php_regex() ) . ' - [F,NC,L]';
		}
		$lines[] = '# Image hotlinking.';
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^$';
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://([^/]+\.)?' . preg_quote( $host, '#' ) . '(:[0-9]+)?(/|$) [NC]';
		foreach ( self::hotlink_allowed() as $domain ) {
			$lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://' . self::referer_host_regex( $domain ) . ' [NC]';
		}
		$lines[] = 'RewriteRule ^' . preg_quote( $uploads, '#' ) . '/.*\.(jpe?g|png|webp|gif|avif)$ - [F,NC,L]';
		foreach ( self::private_regexes() as $regex ) {
			$lines[] = '# Feed that is a static file: only with the token (put yours in place of YOUR_TOKEN).';
			$lines[] = '# PHP feeds are checked by WordPress (token, Bearer, allowed IPs, administrator).';
			$lines[] = 'RewriteCond %{REQUEST_FILENAME} -f';
			$lines[] = 'RewriteCond %{QUERY_STRING} !(^|&)cp_token=YOUR_TOKEN(&|$)';
			$lines[] = 'RewriteCond %{HTTP:X-ScrapeLock-Token} !^YOUR_TOKEN$';
			$lines[] = 'RewriteRule ' . str_replace( '^/', '^', $regex ) . ' - [F,L]';
		}
		$lines[] = '# Authorization: Bearer reaches PHP with PHP-FPM / CGI too.';
		$lines[] = 'RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]';
		$lines[] = '</IfModule>';
		$lines[] = '# END ScrapeLock';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * User-Agents that write "Chrome/" or "Firefox/" without being browsers: search engines and other bots, and the
	 * always-allowed ones. The fake-browser server rules never block them (WordPress verifies them by IP / DNS).
	 *
	 * @return string[]
	 */
	private static function not_fake_browsers() {
		$out = array( 'bot', 'crawl', 'spider', 'slurp', 'fetch', 'preview', 'compatible;', 'http://', 'https://', 'lighthouse', 'pagespeed' );
		foreach ( PNCP_Bots::crawler_families() as $def ) {
			$out = array_merge( $out, $def['ua'] );
		}
		return array_values( array_unique( array_merge( $out, self::allowed() ) ) );
	}

	/**
	 * Exclusion of the always-allowed User-Agents in the Cloudflare expression.
	 *
	 * @return string
	 */
	private static function cf_allowed() {
		$parts = self::cf_allowed_parts();
		return $parts ? ' and not (' . implode( ' or ', $parts ) . ')' : '';
	}

	/**
	 * The always-allowed User-Agents as Cloudflare conditions.
	 *
	 * @return string[]
	 */
	private static function cf_allowed_parts() {
		$parts = array();
		foreach ( self::allowed() as $ua ) {
			$ua = strtolower( trim( (string) $ua ) );
			if ( '' !== $ua ) {
				$parts[] = 'lower(http.user_agent) contains ' . self::cf_string( $ua );
			}
		}
		return array_values( array_unique( $parts ) );
	}

	/**
	 * 3.4.1: a quoted string for a Cloudflare expression. Cloudflare only knows the escapes \\" and \\\\, so a
	 * backslash or a quote typed in a list no longer makes the expression invalid.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	private static function cf_string( $value ) {
		return '"' . str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), (string) $value ) . '"';
	}

	/**
	 * 3.4.1: conditions joined with " or " into as few expressions as possible, each at most $max characters
	 * with its head and tail. A condition that does not fit even alone is left out (never an expression over the
	 * limit, which Cloudflare refuses).
	 *
	 * @param string[] $parts Conditions.
	 * @param string   $head  Text before them.
	 * @param string   $tail  Text after them.
	 * @param int      $max   Most characters.
	 * @return string[] The expressions.
	 */
	private static function cf_chunks( $parts, $head, $tail, $max = 4090 ) {
		$chunks = array();
		$chunk  = array();
		foreach ( $parts as $part ) {
			if ( strlen( $head . $part . $tail ) > $max ) {
				continue;
			}
			if ( $chunk && strlen( $head . implode( ' or ', array_merge( $chunk, array( $part ) ) ) . $tail ) > $max ) {
				$chunks[] = $head . implode( ' or ', $chunk ) . $tail;
				$chunk    = array();
			}
			$chunk[] = $part;
		}
		if ( $chunk ) {
			$chunks[] = $head . implode( ' or ', $chunk ) . $tail;
		}
		return $chunks;
	}

	/**
	 * Expressions for Cloudflare (Security → WAF → Custom rules / Rate limiting rules).
	 *
	 * @return array<string, array{title:string, action:string, expression:string}>
	 */
	public static function cloudflare() {
		$s       = PNCP_Options::get();
		$host    = self::host();
		$uploads = self::uploads_path();
		// First rule: robots.txt and llms.txt skip the others, so every bot can read them. A separate rule keeps
		// the long bot expression under Cloudflare's 4096-character limit.
		$qhost = self::cf_string( $host );
		$rules = array(
			'open' => array(
				'title'      => __( 'First: robots.txt and llms.txt open for every bot (put this rule at the top)', 'scrapelock' ),
				'action'     => __( 'Skip · all remaining custom rules', 'scrapelock' ),
				'expression' => '(http.host eq ' . $qhost . ') and http.request.uri.path in {"/robots.txt" "/llms.txt" "/llms-full.txt" "/.well-known/tdmrep.json"}',
			),
		);

		$bots = self::bots( false );
		if ( $s['block_bots'] && $bots ) {
			// The allowed AI search bots are left out of the list instead of being excluded again after it: shorter.
			$search = array_map( 'strtolower', PNCP_Options::allowed_ai_search() );
			$parts  = array();
			foreach ( $bots as $bot ) {
				$bot = strtolower( trim( (string) $bot ) );
				if ( '=' === substr( $bot, 0, 1 ) ) {
					$parts[] = 'lower(http.user_agent) eq ' . self::cf_string( substr( $bot, 1 ) ); // "=node": the whole User-Agent.
				} elseif ( '' !== $bot && ! in_array( $bot, $search, true ) ) {
					$parts[] = 'lower(http.user_agent) contains ' . self::cf_string( $bot );
				}
			}
			if ( $s['block_empty_ua'] ) {
				$parts[] = 'http.user_agent eq ""';
			}
			// Cloudflare accepts expressions up to 4096 characters: a long list becomes two or more rules. 3.4.1: a
			// long list of always-allowed User-Agents (repeated in every part) becomes a Skip rule of its own instead,
			// placed before the bot rules.
			$head  = '(http.host eq ' . $qhost . ') and not cf.client.bot and (';
			$tail  = ')' . self::cf_allowed();
			$allow = self::cf_allowed_parts();
			if ( strlen( $tail ) > 1000 ) {
				$tail = ')';
				foreach ( self::cf_chunks( $allow, '(http.host eq ' . $qhost . ') and (', ')' ) as $i => $expression ) {
					$rules[ 0 === $i ? 'allowed' : 'allowed_' . ( $i + 1 ) ] = array(
						'title'      => __( 'Always-allowed User-Agents (the list is too long to repeat in every bot rule: keep this rule and the bot rules last, in this order)', 'scrapelock' ),
						'action'     => __( 'Skip · all remaining custom rules', 'scrapelock' ),
						'expression' => $expression,
					);
				}
			}
			$chunks = self::cf_chunks( $parts, $head, $tail );
			foreach ( $chunks as $i => $expression ) {
				$rules[ 0 === $i ? 'bots' : 'bots_' . ( $i + 1 ) ] = array(
					'title'      => 0 === $i ? __( 'Scrapers and AI bots', 'scrapelock' ) : sprintf(
						/* translators: %d: part number */
						__( 'Scrapers and AI bots (part %d: the list is longer than one Cloudflare rule)', 'scrapelock' ),
						$i + 1
					),
					'action'     => 'Block',
					'expression' => $expression,
				);
			}
		}

		$rules['fake'] = array(
			'title'      => __( 'Fake Googlebot / Bingbot (not a verified Cloudflare bot)', 'scrapelock' ),
			'action'     => 'Block',
			'expression' => '(http.host eq ' . $qhost . ') and not cf.client.bot and (lower(http.user_agent) contains "googlebot" or lower(http.user_agent) contains "bingbot" or lower(http.user_agent) contains "applebot")',
		);

		// starts_with() on the whole address (available on every Cloudflare plan, unlike regex): the allowed site
		// must be the referer's host, not text anywhere in it (https://leech.example/?google.com passed with
		// "contains"). A full domain ends with "/", so bing.com.leech.example does not match either.
		$referers = array( 'http.referer eq ""' );
		$bare  = preg_replace( '/^www\./i', '', $host );
		$hosts = array_unique( array( $host, $bare, 'www.' . $bare ) );
		foreach ( array( 'https://', 'http://' ) as $scheme ) {
			foreach ( $hosts as $own ) {
				$referers[] = 'starts_with(http.referer, ' . self::cf_string( $scheme . $own . '/' ) . ')';
				$referers[] = 'starts_with(http.referer, ' . self::cf_string( $scheme . $own . ':' ) . ')';
			}
		}
		$own  = $referers;
		$head = '(http.host eq ' . $qhost . ') and starts_with(http.request.uri.path, ' . self::cf_string( $uploads . '/' ) . ') and http.request.uri.path.extension in {"jpg" "jpeg" "png" "webp" "gif" "avif"} and not (';
		// Cloudflare refuses an expression over 4096 characters: with a long list of allowed sites (filter
		// pncp_hotlink_allowed) fewer subdomains are listed, and with a very long one only the site itself.
		foreach ( array( array( '', 'www.', 'm.', 'l.', 'lm.', 'images.' ), array( '', 'www.' ), array( '' ), array() ) as $subs ) {
			$referers = $own;
			foreach ( $subs ? self::hotlink_allowed() : array() as $domain ) {
				// A domain is letters, digits, dots and hyphens: anything else (a quote, a backslash) is dropped.
				$domain = strtolower( (string) preg_replace( '/[^a-z0-9.\-]/i', '', (string) $domain ) );
				if ( '' === trim( $domain, '.' ) ) {
					continue;
				}
				$end = '.' === substr( $domain, -1 ) ? '' : '/';
				foreach ( $subs as $sub ) {
					$referers[] = 'starts_with(http.referer, ' . self::cf_string( 'https://' . $sub . $domain . $end ) . ')';
				}
			}
			if ( strlen( $head . implode( ' or ', $referers ) . ')' ) <= 4090 ) {
				break;
			}
		}
		$rules['hotlink'] = array(
			'title'      => __( 'Image hotlinking', 'scrapelock' ),
			'action'     => 'Block',
			'expression' => $head . implode( ' or ', $referers ) . ')',
		);

		$backup = (string) get_option( 'pncp_backup_dir' );
		if ( '' !== $backup ) {
			$rules['originals'] = array(
				'title'      => __( 'Clean originals folder', 'scrapelock' ),
				'action'     => 'Block',
				'expression' => '(http.host eq ' . $qhost . ') and starts_with(http.request.uri.path, ' . self::cf_string( $uploads . '/' . $backup . '/' ) . ')',
			);
		}

		$rate = (int) $s['rate_limit'] > 0 ? (int) $s['rate_limit'] : 60;
		// Pages only: not files (CSS, JS, images, fonts), not wp-admin / wp-includes / wp-content and not the
		// Store API. 3.4.1: one rule per plan, because Cloudflare allows fewer fields in rate limiting rules on the
		// smaller plans (Free: the path and verified bots; Pro and Business: also the host and the query; the
		// cookie, which keeps logged-in users out, only on Enterprise).
		$paths = 'not cf.client.bot and http.request.uri.path.extension in {"" "php" "html" "xml"} and not starts_with(http.request.uri.path, ' . self::cf_string( self::url_path( admin_url() ) ) . ') and not starts_with(http.request.uri.path, ' . self::cf_string( self::url_path( includes_url() ) . '/' ) . ') and not starts_with(http.request.uri.path, ' . self::cf_string( self::url_path( content_url() ) . '/' ) . ') and not starts_with(http.request.uri.path, "/wp-json/wc/store")';
		$rules['rate'] = array(
			'title'      => sprintf(
				/* translators: %d: pages per minute */
				__( 'Rate limiting, Free plan: %d requests per minute per IP (Rate limiting rules, characteristic: IP)', 'scrapelock' ),
				$rate
			),
			'action'     => __( 'Block · period 10 seconds, with the limit divided by 6 (the only period on the Free plan)', 'scrapelock' ),
			'expression' => $paths,
		);
		$rules['rate_pro'] = array(
			'title'      => sprintf(
				/* translators: %d: pages per minute */
				__( 'Rate limiting, Pro and Business plans: %d requests per minute per IP (use this one instead of the Free plan rule)', 'scrapelock' ),
				$rate
			),
			'action'     => __( 'Block · period 1 minute', 'scrapelock' ),
			'expression' => '(http.host eq ' . $qhost . ') and ' . $paths . ' and not http.request.uri.query contains "wc-ajax="',
		);
		$rules['rate_enterprise'] = array(
			'title'      => sprintf(
				/* translators: %d: pages per minute */
				__( 'Rate limiting, Enterprise plan: %d requests per minute per IP, logged-in users not counted (use this one instead of the others)', 'scrapelock' ),
				$rate
			),
			'action'     => __( 'Block · period 1 minute', 'scrapelock' ),
			'expression' => '(http.host eq ' . $qhost . ') and ' . $paths . ' and not http.request.uri.query contains "wc-ajax=" and not http.cookie contains "wordpress_logged_in_"',
		);
		// With "Allow AI search engines and assistants" only the training crawlers: the AI search bots are allowed here too.
		$categories  = empty( $s['allow_ai_search'] ) ? '"AI Crawler" "AI Assistant" "AI Search"' : '"AI Crawler"';
		$rules['ai'] = array(
			'title'      => empty( $s['allow_ai_search'] ) ? __( 'AI crawlers, assistants and AI search declared by Cloudflare', 'scrapelock' ) : __( 'AI training crawlers declared by Cloudflare (category “AI Crawler”; AI search and assistants are allowed)', 'scrapelock' ),
			'action'     => 'Block',
			'expression' => '(http.host eq ' . $qhost . ') and cf.verified_bot_category in {' . $categories . '}',
		);
		if ( isset( $rules['allowed'] ) ) {
			// The Skip rule skips every custom rule after it: it and the bot rules go last, so the always-allowed
			// User-Agents skip only the bot rules. The rate limiting rules are in a phase of their own.
			$last = array();
			foreach ( array_keys( $rules ) as $key ) {
				if ( 0 === strpos( $key, 'allowed' ) || 0 === strpos( $key, 'bots' ) ) {
					$last[ $key ] = $rules[ $key ];
					unset( $rules[ $key ] );
				}
			}
			$rules = array_merge( $rules, $last );
		}
		return $rules;
	}
}
