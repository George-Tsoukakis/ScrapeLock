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
	 * The uploads path within the site (e.g. /wp-content/uploads).
	 *
	 * @return string
	 */
	private static function uploads_path() {
		$path = (string) wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH );
		return '' === $path ? '/wp-content/uploads' : untrailingslashit( $path );
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
			$path = (string) wp_parse_url( $pattern, PHP_URL_PATH );
			if ( '' === $path ) {
				continue;
			}
			$full  = (string) wp_parse_url( home_url( PNCP_Private_Urls::relative_path( $path ) ), PHP_URL_PATH );
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
		$lines[] = '# Hotlink: images load only from your site and from search engines / price comparison platforms.';
		$lines[] = '# (If a location for images already exists, e.g. for expires, put the two lines inside it.)';
		$lines[] = 'location ~* ^' . preg_quote( $uploads, '#' ) . '/.*\.(jpe?g|png|webp|gif|avif)$ {';
		// The domain as regex: as a plain name it would clash with server_names ("conflicting parameter" in nginx -t).
		$lines[] = '    valid_referers none blocked server_names ~^([^/]*\\.)?' . self::nginx_referer( $host ) . '(:|/|$) ~' . implode( ' ~', array_map( array( __CLASS__, 'nginx_referer' ), self::hotlink_allowed() ) ) . ';';
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
		$lines[] = '# Image hotlinking.';
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^$';
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://([^/]+\.)?' . preg_quote( $host, '#' ) . '/ [NC]';
		foreach ( self::hotlink_allowed() as $domain ) {
			$lines[] = 'RewriteCond %{HTTP_REFERER} !' . preg_quote( $domain, '#' ) . ' [NC]';
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
		$parts = array();
		foreach ( self::allowed() as $ua ) {
			$parts[] = 'lower(http.user_agent) contains "' . strtolower( str_replace( '"', '', $ua ) ) . '"';
		}
		return $parts ? ' and not (' . implode( ' or ', $parts ) . ')' : '';
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
		$rules = array(
			'open' => array(
				'title'      => __( 'First: robots.txt and llms.txt open for every bot (put this rule at the top)', 'scrapelock' ),
				'action'     => __( 'Skip · all remaining custom rules', 'scrapelock' ),
				'expression' => '(http.host eq "' . $host . '") and http.request.uri.path in {"/robots.txt" "/llms.txt" "/llms-full.txt" "/.well-known/tdmrep.json"}',
			),
		);

		$bots = self::bots( false );
		if ( $s['block_bots'] && $bots ) {
			// The allowed AI search bots are left out of the list instead of being excluded again after it: shorter.
			$search = array_map( 'strtolower', PNCP_Options::allowed_ai_search() );
			$parts  = array();
			foreach ( $bots as $bot ) {
				$bot = strtolower( str_replace( '"', '', $bot ) );
				if ( '=' === substr( $bot, 0, 1 ) ) {
					$parts[] = 'lower(http.user_agent) eq "' . substr( $bot, 1 ) . '"'; // "=node": the whole User-Agent.
				} elseif ( ! in_array( $bot, $search, true ) ) {
					$parts[] = 'lower(http.user_agent) contains "' . $bot . '"';
				}
			}
			if ( $s['block_empty_ua'] ) {
				$parts[] = 'http.user_agent eq ""';
			}
			// Cloudflare accepts expressions up to 4096 characters: a long list becomes two or more rules.
			$head   = '(http.host eq "' . $host . '") and not cf.client.bot and (';
			$tail   = ')' . self::cf_allowed();
			$chunks = array( array() );
			foreach ( $parts as $part ) {
				$current = end( $chunks );
				if ( $current && strlen( $head . implode( ' or ', array_merge( $current, array( $part ) ) ) . $tail ) > 4090 ) {
					$chunks[] = array();
				}
				$chunks[ count( $chunks ) - 1 ][] = $part;
			}
			foreach ( $chunks as $i => $chunk ) {
				$rules[ 0 === $i ? 'bots' : 'bots_' . ( $i + 1 ) ] = array(
					'title'      => 0 === $i ? __( 'Scrapers and AI bots', 'scrapelock' ) : sprintf(
						/* translators: %d: part number */
						__( 'Scrapers and AI bots (part %d: the list is longer than one Cloudflare rule)', 'scrapelock' ),
						$i + 1
					),
					'action'     => 'Block',
					'expression' => $head . implode( ' or ', $chunk ) . $tail,
				);
			}
		}

		$rules['fake'] = array(
			'title'      => __( 'Fake Googlebot / Bingbot (not a verified Cloudflare bot)', 'scrapelock' ),
			'action'     => 'Block',
			'expression' => '(http.host eq "' . $host . '") and not cf.client.bot and (lower(http.user_agent) contains "googlebot" or lower(http.user_agent) contains "bingbot" or lower(http.user_agent) contains "applebot")',
		);

		$referers = array( 'http.referer eq ""', 'http.referer contains "' . $host . '"' );
		foreach ( self::hotlink_allowed() as $domain ) {
			$referers[] = 'http.referer contains "' . $domain . '"';
		}
		$rules['hotlink'] = array(
			'title'      => __( 'Image hotlinking', 'scrapelock' ),
			'action'     => 'Block',
			'expression' => '(http.host eq "' . $host . '") and starts_with(http.request.uri.path, "' . $uploads . '/") and http.request.uri.path.extension in {"jpg" "jpeg" "png" "webp" "gif" "avif"} and not (' . implode( ' or ', $referers ) . ')',
		);

		$backup = (string) get_option( 'pncp_backup_dir' );
		if ( '' !== $backup ) {
			$rules['originals'] = array(
				'title'      => __( 'Clean originals folder', 'scrapelock' ),
				'action'     => 'Block',
				'expression' => '(http.host eq "' . $host . '") and starts_with(http.request.uri.path, "' . $uploads . '/' . $backup . '/")',
			);
		}

		$rate          = (int) $s['rate_limit'] > 0 ? (int) $s['rate_limit'] : 60;
		$rules['rate'] = array(
			'title'      => sprintf(
				/* translators: %d: pages per minute */
				__( 'Rate limiting: %d requests per minute per IP (Rate limiting rules, characteristic: IP)', 'scrapelock' ),
				$rate
			),
			'action'     => __( 'Block · period 1 minute (on the free plan: 10 sec, with limit / 6)', 'scrapelock' ),
			// Pages only: not files (CSS, JS, images, fonts), not wp-admin / wp-includes / wp-content,
			// not cart AJAX (wc-ajax, Store API) and not logged-in users.
			'expression' => '(http.host eq "' . $host . '") and not cf.client.bot and http.request.uri.path.extension in {"" "php" "html" "xml"} and not starts_with(http.request.uri.path, "/wp-admin") and not starts_with(http.request.uri.path, "/wp-includes/") and not starts_with(http.request.uri.path, "/wp-content/") and not starts_with(http.request.uri.path, "/wp-json/wc/store") and not http.request.uri.query contains "wc-ajax=" and not http.cookie contains "wordpress_logged_in_"',
		);
		// With "Allow AI search engines and assistants" only the training crawlers: the AI search bots are allowed here too.
		$categories  = empty( $s['allow_ai_search'] ) ? '"AI Crawler" "AI Assistant" "AI Search"' : '"AI Crawler"';
		$rules['ai'] = array(
			'title'      => empty( $s['allow_ai_search'] ) ? __( 'AI crawlers, assistants and AI search declared by Cloudflare', 'scrapelock' ) : __( 'AI training crawlers declared by Cloudflare (category “AI Crawler”; AI search and assistants are allowed)', 'scrapelock' ),
			'action'     => 'Block',
			'expression' => '(http.host eq "' . $host . '") and cf.verified_bot_category in {' . $categories . '}',
		);
		return $rules;
	}
}
