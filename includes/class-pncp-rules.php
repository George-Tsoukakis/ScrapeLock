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
	 * 3.12.3: the request headers in which a proxy passes on the address of the client it forwards. A loopback or
	 * private address of the server counts as the server itself only when the request carries none of them.
	 */
	const FORWARD_HEADERS = array( 'X-Forwarded-For', 'X-Real-IP', 'Forwarded', 'CF-Connecting-IP' );

	/**
	 * 3.12.3: the response header with the fingerprint of the installed rules (only for the site's own signed
	 * requests, which carry X-ScrapeLock-Sig).
	 */
	const HASH_HEADER = 'X-ScrapeLock-Rules';

	/**
	 * 3.12.3: where the fingerprint goes in the lines, before it is known.
	 */
	const HASH_SLOT = '{{pncp-hash}}';

	/**
	 * 3.12.3: the key of the Nginx map $pncp_block_<site> ("<the block checks>:<open path>:<self><forwarded>") that
	 * blocks: a check says so, the path is not open, and the request is not the server's own ("0x" = not one of its
	 * addresses; "21" = a loopback or private one that a proxy passed on). evaluate() matches the same key.
	 */
	const BLOCK_REGEX = '^[01]*1[01]*:0:(0[01]|21)$';

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
	 * 3.4.3: a location argument for Nginx. A private path with a space ("/price list.xml"), or WordPress in a
	 * folder with one, broke nginx -t ("invalid number of arguments in location"): such an argument is quoted.
	 *
	 * @param string $arg Path or regex.
	 * @return string
	 */
	private static function nginx_arg( $arg ) {
		if ( ! preg_match( '/[\s;"\'{}]/', $arg ) ) {
			return $arg; // As before: rules already installed stay "current".
		}
		// Nginx reads \\ as \ and \" as ", and keeps any other backslash: every backslash is doubled.
		return '"' . str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $arg ) . '"';
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
	 * 3.4.3: alternation() for a quoted Nginx string. Nginx reads \\ in a string as one backslash, so a backslash
	 * typed in a list (preg_quote() makes it \\) reached the regex alone and escaped the next character: the
	 * entry stopped matching, and one at the end of a word could break the regex. Lists without a backslash give
	 * the same lines (and fingerprints) as before.
	 *
	 * @param string[] $words Words.
	 * @return string
	 */
	private static function nginx_alternation( $words ) {
		return str_replace( '\\\\', '\\\\\\\\', self::alternation( $words ) );
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
	 * 3.12.3: the server's own addresses for the server rules, validated: 127.0.0.1, ::1, SERVER_ADDR, the outbound
	 * addresses the site's signed requests to itself were seen leaving from (detected and learned, PNCP_Server_Ips)
	 * and SCRAPELOCK_SERVER_IPS, plus the filter pncp_server_ips. Not the addresses the site's name resolves to:
	 * behind a CDN that ScrapeLock does not know, those are the CDN's, which stands in for every visitor. Never a CDN
	 * edge, never anything but an IPv4 / IPv6 address or CIDR, never a range wider than /8 (IPv6 /16), and a private
	 * range no wider than /24 (IPv6 /64). "local" (loopback and private) count only when no proxy passed the request
	 * on.
	 *
	 * @return array{public: string[], local: string[]}
	 */
	public static function self_addresses() {
		$out    = array(
			'public' => array(),
			'local'  => array( '127.0.0.1', '::1' ),
		);
		$ips    = array( '127.0.0.1', '::1' );
		$server = isset( $_SERVER['SERVER_ADDR'] ) ? PNCP_Ip::normalize( sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) ) : '';
		if ( '' !== $server ) {
			$ips[] = $server;
		}
		$ips = array_merge( $ips, PNCP_Server_Ips::outbound_ips(), array_keys( PNCP_Server_Ips::stored()['learned'] ), PNCP_Server_Ips::const_ips() );
		/** This filter is documented in includes/class-pncp-server-ips.php */
		$ips = apply_filters( 'pncp_server_ips', $ips );
		foreach ( is_array( $ips ) ? $ips : array() as $range ) {
			if ( ! is_string( $range ) ) {
				continue;
			}
			$entry = self::self_entry( (string) $range );
			if ( null !== $entry && ! in_array( $entry[0], $out[ $entry[1] ], true ) ) {
				$out[ $entry[1] ][] = $entry[0];
			}
		}
		return $out;
	}

	/**
	 * 3.12.3: one address or CIDR for the server rules, in canonical form (a CIDR by its network address), with
	 * its kind; null when it must not be written into a web server's configuration.
	 *
	 * @param string $range Address or CIDR.
	 * @return array{0: string, 1: string}|null The address and "public" or "local".
	 */
	public static function self_entry( $range ) {
		$range = trim( (string) $range );
		// Only the characters of an address: whatever else reached the list never reaches a configuration file.
		if ( ! preg_match( '#^[0-9A-Fa-f:.]{2,45}(?:/[0-9]{1,3})?$#', $range ) || ! PNCP_Ip::valid_range( $range ) ) {
			return null;
		}
		$range = PNCP_Options::unmap_range( $range );
		$parts = explode( '/', $range, 2 );
		$bin   = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid value = false.
		if ( false === $bin ) {
			return null;
		}
		$bits   = 8 * strlen( $bin );
		$prefix = isset( $parts[1] ) ? (int) $parts[1] : $bits;
		if ( $prefix > $bits || PNCP_Options::range_too_wide( $range ) ) {
			return null;
		}
		// The network address: the host bits of a CIDR are cleared (Nginx warns about them otherwise).
		$net = '';
		$size = strlen( $bin );
		for ( $i = 0; $i < $size; $i++ ) {
			$keep = max( 0, min( 8, $prefix - 8 * $i ) );
			$net .= chr( ord( $bin[ $i ] ) & ( 0xff << ( 8 - $keep ) ) & 0xff );
		}
		$addr = (string) inet_ntop( $net );
		if ( '0.0.0.0' === $addr || '::' === $addr ) {
			return null; // The unspecified address: every address, or none.
		}
		$local = in_array( $addr, array( '127.0.0.1', '::1' ), true ) || 0 === strpos( $addr, '127.' ) || PNCP_Ip::is_private( $addr );
		if ( $local && $prefix < ( 32 === $bits ? 24 : 64 ) ) {
			return null; // A private range wider than one network of the server.
		}
		if ( ! $local && PNCP_Ip::is_cdn( $addr ) ) {
			return null; // A CDN edge stands in for every visitor behind it.
		}
		return array( $prefix < $bits ? $addr . '/' . $prefix : $addr, $local ? 'local' : 'public' );
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
	 * Whether the Nginx rules are installed and match the current settings. 3.12.4: the server is asked directly
	 * first, then the public address (PNCP_Rules_Status::nginx()). The answer is kept for 5 minutes and is asked
	 * again as soon as the settings change the rules.
	 *
	 * @param bool $fresh Ask again now.
	 * @return array{state:string, parts:string[], error:string, via:string, ip:string, kind:string, code:int}
	 *         state: current, stale, missing or error; parts: the out-of-date parts (http, server); via and kind:
	 *         see PNCP_Rules_Status::nginx().
	 */
	public static function nginx_status( $fresh = false ) {
		return PNCP_Rules_Status::nginx( $fresh );
	}

	/**
	 * 3.12.3: the fingerprints of the current Nginx rules as the installed ones report them ("<http> <server>", the
	 * answer of nginx_check_path() and the header HASH_HEADER).
	 *
	 * @return string
	 */
	public static function nginx_fingerprint() {
		preg_match( '/\$' . preg_quote( self::nv( 'rules' ), '/' ) . ' \{ default "([0-9a-f]+)"; \}/', self::nginx_http(), $http );
		preg_match( '/ ([0-9a-f]+)\\\\n";/', self::nginx_server(), $server );
		return ( $http[1] ?? '' ) . ' ' . ( $server[1] ?? '' );
	}

	/**
	 * 3.12.3: the fingerprint of the current Apache rules (the value of their header HASH_HEADER).
	 *
	 * @return string
	 */
	public static function apache_fingerprint() {
		return preg_match( '/^Header always set ' . self::HASH_HEADER . ' "([0-9a-f]+)"/m', self::apache(), $m ) ? $m[1] : '';
	}

	/**
	 * 3.12.3: how Nginx reads a quoted (or bare) argument of its configuration: \" \' and \\ lose the backslash,
	 * \t \r \n become the characters, any other backslash stays (ngx_conf_read_token()).
	 *
	 * @param string $token The argument as written.
	 * @return string
	 */
	public static function nginx_unquote( $token ) {
		$token = (string) $token;
		if ( strlen( $token ) >= 2 && ( '"' === $token[0] || "'" === $token[0] ) && substr( $token, -1 ) === $token[0] ) {
			$token = substr( $token, 1, -1 );
		}
		return (string) preg_replace_callback(
			'/\\\\(["\'\\\\trn])/',
			static function ( $m ) {
				$map = array(
					't' => "\t",
					'r' => "\r",
					'n' => "\n",
				);
				return isset( $map[ $m[1] ] ) ? $map[ $m[1] ] : $m[1];
			},
			$token
		);
	}

	/**
	 * 3.12.3: the value of one of nginx_maps() for a request, as Nginx finds it: an exact string first, then the
	 * regular expressions in their order (~* without regard to case), else the default 0.
	 *
	 * @param array{key:string, fields:string[], entries:array<int, array{0:string, 1:string}>} $map    The map.
	 * @param array<string, string>                                                          $fields The request's fields.
	 * @return array{value:string, entry:int} The value and the entry that matched (-1 = the default).
	 */
	public static function nginx_map_value( $map, $fields ) {
		$parts = array();
		foreach ( $map['fields'] as $field ) {
			$parts[] = isset( $fields[ $field ] ) ? (string) $fields[ $field ] : '';
		}
		$key = implode( '|', $parts );
		foreach ( $map['entries'] as $i => $entry ) {
			$pattern = self::nginx_unquote( $entry[0] );
			if ( '~' !== substr( $pattern, 0, 1 ) && $pattern === $key ) {
				return array(
					'value' => (string) $entry[1],
					'entry' => (int) $i,
				);
			}
		}
		foreach ( $map['entries'] as $i => $entry ) {
			$pattern = self::nginx_unquote( $entry[0] );
			if ( '~' !== substr( $pattern, 0, 1 ) ) {
				continue;
			}
			$ci    = '~*' === substr( $pattern, 0, 2 );
			$regex = substr( $pattern, $ci ? 2 : 1 );
			if ( self::pcre_match( $regex, $key, $ci ) ) {
				return array(
					'value' => (string) $entry[1],
					'entry' => (int) $i,
				);
			}
		}
		return array(
			'value' => '0',
			'entry' => -1,
		);
	}

	/**
	 * A regular expression of the server rules (PCRE, as Nginx and Apache read it) against a text.
	 *
	 * @param string $regex The expression, without delimiters.
	 * @param string $text  Text.
	 * @param bool   $ci    Without regard to case.
	 * @return bool
	 */
	private static function pcre_match( $regex, $text, $ci ) {
		// A delimiter that no expression of the rules holds (preg_quote() escapes only "#").
		$ok = @preg_match( "\x01" . $regex . "\x01" . ( $ci ? 'i' : '' ), (string) $text ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- An invalid expression is no match (Nginx would refuse it at nginx -t).
		return 1 === $ok;
	}

	/**
	 * 3.12.3: is an address one of the server's own for the server rules (self_addresses())? A loopback or private
	 * one only when no proxy passed the request on (none of FORWARD_HEADERS).
	 *
	 * @param string                $ip      Address the web server sees ('' = unknown: not the server).
	 * @param array<string, string> $headers Lowercase request headers.
	 * @return string "1" (public address), "2" (loopback / private) or "0", as the Nginx geo.
	 */
	public static function self_value( $ip, $headers ) {
		$ip = PNCP_Ip::normalize( (string) $ip );
		if ( '' === $ip ) {
			return '0';
		}
		$self = self::self_addresses();
		if ( PNCP_Ip::in_any( $ip, $self['public'] ) ) {
			return '1';
		}
		return PNCP_Ip::in_any( $ip, $self['local'] ) ? '2' : '0';
	}

	/**
	 * 3.12.3: what ScrapeLock's own generated server rules (the current settings) do with a request, before PHP:
	 * the rule that refuses it, or null when they let it through to the site. The same maps and the same block
	 * expression as the Nginx rules (nginx_maps(), BLOCK_REGEX), then the locations of part 2 in Nginx's order (the
	 * folders that are never public, then the first regular expression that matches). The Apache rules check the
	 * same.
	 *
	 * @param array<string, mixed> $request ua, headers (name => value), https (bool), method, path, remote (the
	 *                                      address the web server sees; '' = unknown, not the server).
	 * @return array{rule:string, code:int}|null
	 */
	public static function evaluate( $request ) {
		$headers = array();
		foreach ( isset( $request['headers'] ) && is_array( $request['headers'] ) ? $request['headers'] : array() as $name => $value ) {
			$headers[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', array_map( 'strval', $value ) ) : (string) $value;
		}
		$ua   = isset( $request['ua'] ) ? (string) $request['ua'] : ( isset( $headers['user-agent'] ) ? $headers['user-agent'] : '' );
		$path = isset( $request['path'] ) && '' !== (string) $request['path'] ? (string) $request['path'] : '/';
		$path = (string) rawurldecode( (string) wp_parse_url( $path, PHP_URL_PATH ) ); // Nginx's $uri: decoded, no query.
		$path = '' === $path ? '/' : $path;
		// 3.12.4: part 2 answers its check address at server level, before every other line.
		if ( self::nginx_check_path() === $path ) {
			return null;
		}
		$fields = array(
			'ua'             => $ua,
			'uri'            => $path,
			'https'          => ! empty( $request['https'] ) ? 'on' : '',
			'sec_fetch_mode' => isset( $headers['sec-fetch-mode'] ) ? $headers['sec-fetch-mode'] : '',
			'sec_ch_ua'      => isset( $headers['sec-ch-ua'] ) ? $headers['sec-ch-ua'] : '',
		);
		$values = array();
		$which  = array();
		foreach ( self::nginx_maps() as $name => $map ) {
			$got             = self::nginx_map_value( $map, $fields );
			$values[ $name ] = $got['value'];
			$which[ $name ]  = $got['entry'];
		}
		$forward = '';
		foreach ( self::FORWARD_HEADERS as $header ) {
			$forward .= isset( $headers[ strtolower( $header ) ] ) ? $headers[ strtolower( $header ) ] : '';
		}
		$self   = self::self_value( isset( $request['remote'] ) ? (string) $request['remote'] : '', $headers );
		$checks = '';
		$names  = array();
		foreach ( self::nginx_block_vars() as $var ) {
			$name    = substr( $var, strlen( '$pncp_' ), - ( strlen( self::nginx_id() ) + 1 ) );
			$checks .= isset( $values[ $name ] ) ? $values[ $name ] : '0';
			$names[] = $name;
		}
		$open = isset( $values['open_path'] ) ? $values['open_path'] : '0';
		if ( $names && self::pcre_match( self::BLOCK_REGEX, $checks . ':' . $open . ':' . $self . ( '' === $forward ? '0' : '1' ), false ) ) {
			foreach ( $names as $name ) {
				if ( '1' === $values[ $name ] ) {
					$maps = self::nginx_maps();
					$rule = $name;
					// The empty User-Agent has an entry of its own in the bot map.
					if ( 'bad_bot' === $name && '""' === $maps['bad_bot']['entries'][ $which['bad_bot'] ][0] ) {
						$rule = 'empty_ua';
					}
					return array(
						'rule' => $rule,
						'code' => 403,
					);
				}
			}
		}
		// Part 2: the folders that are never public (location ^~, before any regular expression).
		foreach ( self::private_prefixes() as $prefix ) {
			if ( 0 === strpos( $path, $prefix ) ) {
				return array(
					'rule' => 'private_folder',
					'code' => 404,
				);
			}
		}
		// Then the first regular expression location that matches, in the order of part 2.
		foreach ( self::regex_locations() as $location ) {
			if ( ! self::pcre_match( $location['regex'], $path, true ) ) {
				continue;
			}
			if ( 'hotlink' === $location['rule'] ) {
				$referer = isset( $headers['referer'] ) ? $headers['referer'] : '';
				if ( '' === $referer || self::referer_allowed( $referer ) ) {
					return null;
				}
			}
			return '' === $location['rule'] ? null : array(
				'rule' => $location['rule'],
				'code' => (int) $location['code'],
			);
		}
		return null;
	}

	/**
	 * 3.12.3: the folders that part 2 of the Nginx rules never serves (location ^~ … { deny all; return 404; }).
	 *
	 * @return string[] Path prefixes, with the trailing slash.
	 */
	private static function private_prefixes() {
		$uploads = self::uploads_path();
		$out     = array();
		$backup  = (string) get_option( 'pncp_backup_dir' );
		if ( '' !== $backup ) {
			$out[] = $uploads . '/' . $backup . '/';
		}
		if ( '' !== (string) get_option( PNCP_Precheck::KEY, '' ) ) {
			$out[] = $uploads . '/' . PNCP_Precheck::DIR . '/';
		}
		if ( is_dir( PNCP_Geo::dir() ) ) {
			$out[] = $uploads . '/' . PNCP_Geo::DIR . '/';
		}
		return $out;
	}

	/**
	 * 3.12.3: the regular expression locations of part 2, in their order: the rule each one is ('' = the request goes
	 * on to WordPress, which decides) and the status of its refusal.
	 *
	 * @return array<int, array{regex:string, rule:string, code:int}>
	 */
	private static function regex_locations() {
		$s   = PNCP_Options::get();
		$out = array();
		if ( $s['hide_versions'] || ! empty( $s['hide_fingerprint'] ) ) {
			foreach ( self::version_regexes() as $regex ) {
				$out[] = array(
					'regex' => $regex,
					'rule'  => 'version_file',
					'code'  => 404,
				);
			}
		}
		foreach ( array( self::probe_regex(), self::probe_regex( 'server_missing' ) ) as $regex ) {
			if ( '' !== $regex ) {
				$out[] = array(
					'regex' => $regex,
					'rule'  => '',
					'code'  => 0,
				);
			}
		}
		if ( $s['block_upload_php'] ) {
			$out[] = array(
				'regex' => self::upload_php_regex(),
				'rule'  => 'upload_php',
				'code'  => 403,
			);
		}
		$out[] = array(
			'regex' => self::hotlink_regex(),
			'rule'  => 'hotlink',
			'code'  => 403,
		);
		return $out;
	}

	/**
	 * The path of the images of the hotlink rule.
	 *
	 * @return string
	 */
	private static function hotlink_regex() {
		return '^' . preg_quote( self::uploads_path(), '#' ) . '/.*\.(jpe?g|png|webp|gif|avif)$';
	}

	/**
	 * 3.12.3: is a Referer one the hotlink rule accepts (the site itself, or one of hotlink_allowed())?
	 *
	 * @param string $referer Referer.
	 * @return bool
	 */
	private static function referer_allowed( $referer ) {
		$rest = (string) preg_replace( '#^https?://#i', '', (string) $referer, 1, $count );
		if ( 0 === $count ) {
			return true; // "blocked": a Referer without a scheme (a proxy or firewall removed it).
		}
		if ( self::pcre_match( '^([^/]*\.)?' . self::nginx_referer( self::host() ) . '(:|/|$)', $rest, true ) ) {
			return true;
		}
		foreach ( self::hotlink_allowed() as $domain ) {
			if ( self::pcre_match( '^' . self::referer_host_regex( $domain ), $rest, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.12.3: a rule of evaluate(), for people.
	 *
	 * @param string $rule Rule.
	 * @return string
	 */
	public static function rule_label( $rule ) {
		$labels = array(
			'fake_browser'   => __( 'fake browser', 'scrapelock' ),
			'bad_bot'        => __( 'bot list', 'scrapelock' ),
			'empty_ua'       => __( 'empty User-Agent', 'scrapelock' ),
			'private_folder' => __( 'folder that is never public', 'scrapelock' ),
			'version_file'   => __( 'hide versions', 'scrapelock' ),
			'upload_php'     => __( 'no PHP in the uploads folder', 'scrapelock' ),
			'hotlink'        => __( 'image hotlinking', 'scrapelock' ),
		);
		return isset( $labels[ $rule ] ) ? $labels[ $rule ] : (string) $rule;
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
	 * 3.12.3: the maps come from nginx_maps(), which evaluate() reads too, and the server's own addresses
	 * (self_geo()) are exempt from every block and from the page limit.
	 *
	 * @return string
	 */
	public static function nginx_http() {
		$s        = PNCP_Options::get();
		$lines    = array();
		$volatile = array(); // Lines left out of the fingerprint: the server's addresses (not settings).
		$maps     = self::nginx_maps();
		foreach ( $maps as $name => $map ) {
			$lines[] = 'map ' . $map['key'] . ' $' . self::nv( $name ) . ' {';
			$lines[] = '    default 0;';
			foreach ( $map['entries'] as $entry ) {
				$lines[] = '    ' . $entry[0] . ' ' . $entry[1] . ';';
			}
			$lines[] = '}';
		}
		// 3.12.3: the server's own addresses (PNCP_Server_Ips): its requests to itself (the self-checks, cron, cache
		// preloads) are never blocked by these rules. 1 = a public address of the server; 2 = a loopback or private
		// one, which counts only when no proxy passed the request on (a proxy on the same machine, e.g. a tunnel,
		// would otherwise make every visitor "the server").
		$self    = self::self_addresses();
		$lines[] = '# The server\'s own addresses: never blocked or limited by these rules (1 = public; 2 = loopback / private,';
		$lines[] = '# only when no proxy passed the request on). Behind a CDN, Nginx needs real_ip for the public one.';
		$lines[] = 'geo $' . self::nv( 'self' ) . ' {';
		$lines[] = '    default 0;';
		$values  = array(
			'local'  => '2',
			'public' => '1',
		);
		foreach ( $values as $kind => $value ) {
			foreach ( $self[ $kind ] as $range ) {
				$volatile[ count( $lines ) ] = true;
				$lines[]                     = '    ' . $range . ' ' . $value . ';';
			}
		}
		$lines[] = '}';
		$lines[] = 'map "' . self::nginx_forward_key() . '" $' . self::nv( 'fwd' ) . ' { default 1; "" 0; }';
		$checks  = self::nginx_block_vars();
		if ( $checks ) {
			// One variable for the server { } part: blocked when a check says so, except on the open paths and for
			// the server itself (3.12.3: "0x" = not the server, "21" = a local address passed on by a proxy).
			$lines[] = 'map "' . implode( '', $checks ) . ':$' . self::nv( 'open_path' ) . ':$' . self::nv( 'self' ) . '$' . self::nv( 'fwd' ) . '" $' . self::nv( 'block' ) . ' {';
			$lines[] = '    default 0;';
			$lines[] = '    "~' . self::BLOCK_REGEX . '" 1;';
			$lines[] = '}';
		}
		$rate = (int) $s['rate_limit'] > 0 ? (int) $s['rate_limit'] : 60;
		$key  = '$binary_remote_addr';
		// 3.4.3: the "Always allowed IPs" are not limited by Nginx either (an empty key is not counted). The
		// Google and Bing lists change every day, so they are not written here: the comment in part 2 says so.
		$exempt = array();
		foreach ( PNCP_Options::parse_list( $s['allow_ips'] ) as $range ) {
			$range = trim( (string) $range );
			if ( PNCP_Ip::valid_range( $range ) ) {
				$exempt[] = PNCP_Options::unmap_range( $range );
			}
		}
		if ( $exempt ) {
			$lines[] = 'geo $' . self::nv( 'limit_exempt' ) . ' {';
			$lines[] = '    default 0;';
			foreach ( array_unique( $exempt ) as $range ) {
				$lines[] = '    ' . $range . ' 1;';
			}
			$lines[] = '}';
			// 3.12.3: the server itself is not counted either. Only where the zone already had this key: Nginx refuses
			// to reload (the test passes, the reload fails) when the key of an existing zone changes, so a zone keyed
			// by $binary_remote_addr keeps it.
			$lines[] = 'map "$' . self::nv( 'limit_exempt' ) . '$' . self::nv( 'self' ) . '$' . self::nv( 'fwd' ) . '" $' . self::nv( 'limit_key' ) . ' { default $binary_remote_addr; "~^1" ""; "~^.(1.|20)$" ""; }';
			$key     = '$' . self::nv( 'limit_key' );
		}
		$lines[] = 'limit_req_zone ' . $key . ' zone=' . self::nv( 'pages' ) . ':10m rate=' . $rate . 'r/m;';
		// Lets the plugin see that this part is installed and matches the current settings.
		$lines[] = 'map $host $' . self::nv( 'rules' ) . ' { default "' . self::nginx_hash( array_diff_key( $lines, $volatile ) ) . '"; }';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * 3.12.3: the request headers a proxy adds with the address it passes on, as one Nginx string (empty when the
	 * request came straight from the machine that sent it).
	 *
	 * @return string
	 */
	private static function nginx_forward_key() {
		$out = '';
		foreach ( self::FORWARD_HEADERS as $header ) {
			$out .= '$http_' . str_replace( '-', '_', strtolower( $header ) );
		}
		return $out;
	}

	/**
	 * 3.12.3: the maps of part 1 that decide on a request, in order: name (without the site suffix) => the Nginx
	 * key, the request fields it is made of (joined by "|") and the entries (pattern as written in the
	 * configuration, value). nginx_http() writes them; evaluate() reads them with Nginx's own rules, so the
	 * plugin's view of the rules cannot drift from what Nginx does.
	 *
	 * @return array<string, array{key:string, fields:string[], entries:array<int, array{0:string, 1:string}>}>
	 */
	public static function nginx_maps() {
		$s    = PNCP_Options::get();
		$maps = array();
		if ( $s['block_bots'] && self::bots() ) {
			$entries = array();
			if ( self::allowed() ) {
				$entries[] = array( '"~*' . self::nginx_alternation( self::allowed() ) . '"', '0' ); // First: it matches first.
			}
			$entries[] = array( '"~*' . self::nginx_alternation( self::bots() ) . '"', '1' );
			if ( $s['block_empty_ua'] ) {
				$entries[] = array( '""', '1' );
			}
			$maps['bad_bot'] = array(
				'key'     => '$http_user_agent',
				'fields'  => array( 'ua' ),
				'entries' => $entries,
			);
		}
		if ( ( $s['block_bots'] && self::bots() ) || $s['block_headless'] ) {
			// robots.txt and llms.txt stay open for every bot: it must be able to read the rules it is asked to follow.
			$maps['open_path'] = array(
				'key'     => '$uri',
				'fields'  => array( 'uri' ),
				'entries' => array(
					array( '"~*^/(robots|llms|llms-full)\.txt$"', '1' ),
					array( '"~*^/\.well-known/tdmrep\.json$"', '1' ),
					array( self::nginx_check_path(), '1' ),
				),
			);
		}
		if ( $s['block_headless'] ) {
			// Chrome / Edge / Opera 90+ always send Sec-Fetch-Mode and Sec-CH-UA over HTTPS, Firefox 90+ Sec-Fetch-Mode:
			// a "browser" without them is a script. Android in-app browsers (; wv) and the always-allowed User-Agents pass.
			// Search engines and other bots also write "Chrome/" in their User-Agent and send no browser headers: they
			// are not fake browsers (WordPress verifies them by IP / DNS). Bot User-Agents name themselves or a URL.
			$maps['fake_browser'] = array(
				'key'     => '"$https|$http_sec_fetch_mode|$http_sec_ch_ua|$http_user_agent"',
				'fields'  => array( 'https', 'sec_fetch_mode', 'sec_ch_ua', 'ua' ),
				'entries' => array(
					array( '"~*^[^|]*\\|[^|]*\\|[^|]*HeadlessChrome"', '1' ),
					array( '"~; wv\\)"', '0' ),
					array( '"~*^[^|]*\\|[^|]*\\|[^|]*\\|.*' . self::nginx_alternation( self::not_fake_browsers() ) . '"', '0' ),
					array( '"~^on\\|\\|\\|.*\\b(Chrome|Chromium)/(9[0-9]|[1-9][0-9]{2})\\."', '1' ),
					array( '"~^on\\|\\|[^|]*\\|.*\\bFirefox/(9[0-9]|[1-9][0-9]{2})\\."', '1' ),
				),
			);
		}
		if ( self::private_regexes() ) {
			// Token for the static feeds: in the URL (cp_token) or in the header. Put your own in place of YOUR_TOKEN.
			$maps['token_ok'] = array(
				'key'     => '"$arg_cp_token:$http_x_scrapelock_token"',
				'fields'  => array(),
				'entries' => array(
					array( '"~^YOUR_TOKEN:"', '1' ),
					array( '"~:YOUR_TOKEN$"', '1' ),
				),
			);
		}
		return $maps;
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
		// 3.12.3: the fingerprint of the installed rules, only in the answers to the site's own signed requests (the
		// header X-ScrapeLock-Sig; Nginx cannot verify it, but the fingerprint says nothing about the site), so every
		// self-check sees whether the rules on the server are the current ones. An empty value sends no header.
		$lines[] = '# The fingerprint of these rules, sent only to ScrapeLock\'s own requests (X-ScrapeLock-Sig): the plugin sees';
		$lines[] = '# which rules are installed. Nginx uses add_header lines of one level only: a location with add_header';
		$lines[] = '# lines of its own needs this add_header line too, and add_header lines that nginx.conf has only in';
		$lines[] = '# http { } must be repeated in this server { } (a server { } with its own add_header ignores them).';
		$lines[] = 'set $' . self::nv( 'rules_hdr' ) . ' "";';
		$lines[] = 'if ($http_x_scrapelock_sig) { set $' . self::nv( 'rules_hdr' ) . ' "$' . self::nv( 'rules' ) . ' ' . self::HASH_SLOT . '"; }';
		$lines[] = 'add_header ' . self::HASH_HEADER . ' $' . self::nv( 'rules_hdr' ) . ' always;';
		$lines[] = '';
		// 3.12.4: the check address answered at server level too. Panels (aaPanel, BT Panel, CloudPanel) often put the
		// WordPress rewrite at server level (if (!-e $request_filename) { rewrite ... /index.php last; }): it runs
		// before any location is chosen, and the location = below never sees the request. These lines come first.
		$lines[] = '# The check address, answered here too: a WordPress rewrite at server level (if (!-e $request_filename)';
		$lines[] = '# { rewrite ... }, common on aaPanel, BT Panel and CloudPanel) runs before any location. Keep these lines ABOVE it.';
		$lines[] = 'if ($uri = ' . self::nginx_arg( self::nginx_check_path() ) . ') { return 200 "$' . self::nv( 'rules' ) . ' ' . self::HASH_SLOT . '\\n"; }';
		$lines[] = '';
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
		$lines[] = '# Search engines are limited like everyone here (Nginx cannot verify them): on a large site, leave the line';
		$lines[] = '# out, or add the Google / Bing ranges to "Always allowed IPs". The always allowed IPs are not limited.';
		$lines[] = '#   limit_req zone=' . self::nv( 'pages' ) . ' burst=20 nodelay;';
		$lines[] = 'limit_req_status 429;';
		$lines[] = '';
		if ( '' !== $backup ) {
			$lines[] = '# Clean originals of watermarked images: never public.';
			$lines[] = 'location ^~ ' . self::nginx_arg( $uploads . '/' . $backup . '/' ) . ' { deny all; return 404; }';
			$lines[] = '';
		}
		// 3.5: the pre-cache check's data (counters, bans, visitor IPs) and the country database: Nginx ignores the
		// .htaccess files in them. Fixed names only, as Site Health prints them (PNCP_Health::folders_fix()), and
		// only for a folder that exists, so the rules of a site that never used them stay as they were.
		$data = array();
		if ( '' !== (string) get_option( PNCP_Precheck::KEY, '' ) ) {
			$data[] = 'location ^~ ' . self::nginx_arg( $uploads . '/' . PNCP_Precheck::DIR . '/' ) . ' { deny all; return 404; }';
		}
		if ( is_dir( PNCP_Geo::dir() ) ) {
			$data[] = 'location ^~ ' . self::nginx_arg( $uploads . '/' . PNCP_Geo::DIR . '/' ) . ' { deny all; return 404; }';
		}
		if ( $data ) {
			$lines[] = '# ScrapeLock\'s data folders (pre-cache check, country database): never public.';
			$lines   = array_merge( $lines, $data );
			$lines[] = '';
		}
		if ( $s['hide_versions'] || ! empty( $s['hide_fingerprint'] ) ) {
			$lines[] = '# Hide versions: readme / changelog files that give the version of WordPress, plugins and themes away (404).';
			foreach ( self::version_regexes() as $regex ) {
				$lines[] = 'location ~* ' . self::nginx_arg( $regex ) . ' { return 404; }';
			}
			$lines[] = '';
		}
		// 3.5: "Ban scanners on their first probe": the probe paths go to WordPress, which bans (only when on).
		$probe   = self::probe_regex();
		$missing = self::probe_regex( 'server_missing' );
		if ( '' !== $probe ) {
			$lines[] = '# Scanner probes (.env, .git, wp-config.php backups, SSH keys): sent to WordPress, which bans the IP';
			$lines[] = '# ("Ban scanners on their first probe"). These files are never served, even if they exist. Put it ABOVE any';
			$lines[] = '# location that denies hidden files (location ~ /\\.): Nginx uses the first regex location that matches.';
			$lines[] = 'location ~* ' . self::nginx_arg( $probe ) . ' { rewrite ^ ' . self::url_path( home_url() ) . '/index.php last; }';
			$lines[] = '';
		}
		// 3.5: dumps and archives at the top of the site only when no such file exists (a real download is served).
		if ( '' !== $missing ) {
			$lines[] = '# Scanner probes for database dumps and backup archives: sent to WordPress only when the file does not exist.';
			$lines[] = 'location ~* ' . self::nginx_arg( $missing ) . ' { try_files $uri ' . self::url_path( home_url() ) . '/index.php?$args; }';
			$lines[] = '';
		}
		if ( $s['block_upload_php'] ) {
			$lines[] = '# No PHP in the uploads folder. Put it ABOVE the location that passes .php files to PHP: Nginx uses the';
			$lines[] = '# first regex location that matches.';
			$lines[] = 'location ~* ' . self::nginx_arg( self::upload_php_regex() ) . ' { deny all; }';
			$lines[] = '';
		}
		$lines[] = '# Hotlink: images load only from your site and from search engines / price comparison platforms.';
		$lines[] = '# (If a location for images already exists, e.g. for expires, put the two lines inside it.)';
		$lines[] = 'location ~* ' . self::nginx_arg( self::hotlink_regex() ) . ' {';
		// The domain as regex: as a plain name it would clash with server_names ("conflicting parameter" in nginx -t).
		// Quoted: "google." becomes [a-z]{2,3}, and an unquoted { starts a block for Nginx (nginx -t fails).
		$allowed = array();
		foreach ( self::hotlink_allowed() as $domain ) {
			$allowed[] = '"~^' . self::referer_host_regex( $domain ) . '"';
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
				$lines[] = 'location ~* ' . self::nginx_arg( $regex ) . ' {';
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
		$lines[] = '    return 200 "$' . self::nv( 'rules' ) . ' ' . self::HASH_SLOT . '\\n";';
		$lines[] = '}';
		// The fingerprint of this part: every line but the two that carry it.
		$hashed = array();
		foreach ( $lines as $line ) {
			if ( false === strpos( $line, self::HASH_SLOT ) ) {
				$hashed[] = $line;
			}
		}
		return str_replace( self::HASH_SLOT, self::nginx_hash( $hashed ), implode( "\n", $lines ) ) . "\n";
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
	 * 3.4.3: a regex of the request path (with the leading slash) for a RewriteRule in the .htaccess of the
	 * WordPress rules. Apache matches a RewriteRule there against the path without the folder of that .htaccess,
	 * which is the site's home folder: with WordPress in a subfolder (/blog) the rules kept "^blog/..." and never
	 * matched. At the root of the domain the result is the same as before.
	 *
	 * @param string $regex Regex starting with ^/.
	 * @return string
	 */
	private static function apache_regex( $regex ) {
		$head = '^' . preg_quote( self::url_path( home_url() ) . '/', '#' );
		return 0 === strpos( $regex, $head ) ? '^' . substr( $regex, strlen( $head ) ) : str_replace( '^/', '^', $regex );
	}

	/**
	 * 3.5: the scanner probe paths for the server rules (PNCP_Probe::SERVER_KEYS), as a regex of the full request
	 * path, or '' when "Ban scanners on their first probe" is off.
	 *
	 * @param string $where 'server' (always sent to WordPress) or 'server_missing' (only when no such file exists).
	 * @return string
	 */
	private static function probe_regex( $where = 'server' ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['probe_ban'] ) ) {
			return '';
		}
		$body = PNCP_Probe::body( $where );
		return '' === $body ? '' : '^' . preg_quote( self::url_path( home_url() ) . '/', '#' ) . $body . '$';
	}

	/**
	 * Apache rules (.htaccess, above the WordPress rules).
	 *
	 * @return string
	 */
	public static function apache() {
		$s       = PNCP_Options::get();
		$host    = self::host();
		$uploads = self::uploads_path();
		$backup  = (string) get_option( 'pncp_backup_dir' );
		$lines   = array();

		$volatile = array(); // Lines left out of the fingerprint: the server's addresses (not settings).

		$lines[] = '# BEGIN ScrapeLock ' . PNCP_VERSION;
		$lines[] = '<IfModule mod_rewrite.c>';
		$lines[] = 'RewriteEngine On';
		$open    = 'RewriteCond %{REQUEST_URI} !^/(?:(robots|llms|llms-full)\.txt|\.well-known/tdmrep\.json)$ [NC]';
		// 3.12.3: the server's own addresses are never blocked by the rules below (its self-checks, cron, cache
		// preloads). A loopback or private address only when no proxy passed the request on: the address and the
		// forwarding headers together are then just the address.
		$self    = self::self_addresses();
		$single  = array(
			'public' => array(),
			'local'  => array(),
		);
		$cidrs   = array();
		foreach ( $self as $kind => $ranges ) {
			foreach ( $ranges as $range ) {
				if ( false === strpos( $range, '/' ) ) {
					$single[ $kind ][] = str_replace( '.', '\\.', $range ); // Only digits, hex, dots and colons (self_entry()).
				} else {
					$cidrs[] = array( $range, $kind );
				}
			}
		}
		$forward = '';
		foreach ( self::FORWARD_HEADERS as $header ) {
			$forward .= '%{HTTP:' . $header . '}';
		}
		$lines[] = '# The server\'s own addresses: never blocked by the rules below (loopback / private ones only when no proxy';
		$lines[] = '# passed the request on). Behind a CDN, Apache needs mod_remoteip for the public ones.';
		if ( $single['public'] ) {
			$volatile[ count( $lines ) ] = true;
			$lines[]                     = 'RewriteCond %{REMOTE_ADDR} ^(?:' . implode( '|', $single['public'] ) . ')$ [OR]';
		}
		$volatile[ count( $lines ) ] = true;
		$lines[]                     = 'RewriteCond %{REMOTE_ADDR}' . $forward . ' ^(?:' . implode( '|', $single['local'] ) . ')$';
		$lines[]                     = 'RewriteRule .* - [E=PNCP_SELF:1]';
		if ( $cidrs ) {
			// Ranges need Apache 2.4's expressions, which LiteSpeed does not read: there only single addresses count.
			$lines[] = '<IfModule !LiteSpeed>';
			foreach ( $cidrs as $i => $cidr ) {
				$volatile[ count( $lines ) ] = true;
				$lines[]                     = 'RewriteCond expr "-R \'' . $cidr[0] . '\'' . ( 'local' === $cidr[1] ? ' && -z \'' . $forward . '\'' : '' ) . '"' . ( $i < count( $cidrs ) - 1 ? ' [OR]' : '' );
			}
			$lines[] = 'RewriteRule .* - [E=PNCP_SELF:1]';
			$lines[] = '</IfModule>';
		}
		$not_self = 'RewriteCond %{ENV:PNCP_SELF} !^1$';
		if ( $s['block_bots'] && self::bots() ) {
			$lines[] = '# Bots in the list: 403 before the page cache. robots.txt / llms.txt stay open for every bot.';
			$lines[] = $not_self;
			$lines[] = $open;
			if ( self::allowed() ) {
				$lines[] = 'RewriteCond %{HTTP_USER_AGENT} !' . self::alternation( self::allowed() ) . ' [NC]';
			}
			$lines[] = 'RewriteCond %{HTTP_USER_AGENT} ' . self::alternation( self::bots() ) . ' [NC]';
			$lines[] = 'RewriteRule .* - [F,L]';
			if ( $s['block_empty_ua'] ) {
				$lines[] = $not_self;
				$lines[] = $open;
				$lines[] = 'RewriteCond %{HTTP_USER_AGENT} ^-?$';
				$lines[] = 'RewriteRule .* - [F,L]';
			}
		}
		if ( $s['block_headless'] ) {
			$lines[] = '# Fake browsers: Chrome / Edge 90+ without Sec-Fetch-Mode and Sec-CH-UA, Firefox 90+ without Sec-Fetch-Mode (HTTPS only).';
			$lines[] = '# Search engines and other bots that write "Chrome/" in their User-Agent are not affected.';
			foreach ( array( 'chrome', 'firefox' ) as $browser ) {
				$lines[] = $not_self;
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
			$lines[] = 'RewriteRule ' . self::apache_regex( '^' . preg_quote( $uploads . '/' . $backup, '#' ) . '/' ) . ' - [F,L]';
		}
		if ( $s['hide_versions'] || ! empty( $s['hide_fingerprint'] ) ) {
			$lines[] = '# Hide versions: readme / changelog files that give the version of WordPress, plugins and themes away (404).';
			foreach ( self::version_regexes() as $regex ) {
				$lines[] = 'RewriteRule ' . self::apache_regex( $regex ) . ' - [R=404,NC,L]';
			}
		}
		// 3.5: "Ban scanners on their first probe" (only when on).
		$probe   = self::probe_regex();
		$missing = self::probe_regex( 'server_missing' );
		if ( '' !== $probe ) {
			$lines[] = '# Scanner probes (.env, .git, wp-config.php backups, SSH keys): sent to WordPress, which bans the IP.';
			$lines[] = 'RewriteRule ' . self::apache_regex( $probe ) . ' ' . self::url_path( home_url() ) . '/index.php [NC,L]';
		}
		// 3.5: dumps and archives at the top of the site only when no such file exists (a real download is served).
		if ( '' !== $missing ) {
			$lines[] = '# Scanner probes for database dumps and backup archives: sent to WordPress only when the file does not exist.';
			$lines[] = 'RewriteCond %{REQUEST_FILENAME} !-f';
			$lines[] = 'RewriteRule ' . self::apache_regex( $missing ) . ' ' . self::url_path( home_url() ) . '/index.php [NC,L]';
		}
		if ( $s['block_upload_php'] ) {
			$lines[] = '# No PHP in the uploads folder (ScrapeLock also writes this into the .htaccess of the uploads folder).';
			$lines[] = 'RewriteRule ' . self::apache_regex( self::upload_php_regex() ) . ' - [F,NC,L]';
		}
		$lines[] = '# Image hotlinking.';
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^$';
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://([^/]+\.)?' . preg_quote( $host, '#' ) . '(:[0-9]+)?(/|$) [NC]';
		foreach ( self::hotlink_allowed() as $domain ) {
			$lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://' . self::referer_host_regex( $domain ) . ' [NC]';
		}
		$lines[] = 'RewriteRule ' . self::apache_regex( self::hotlink_regex() ) . ' - [F,NC,L]';
		foreach ( self::private_regexes() as $regex ) {
			$lines[] = '# Feed that is a static file: only with the token (put yours in place of YOUR_TOKEN).';
			$lines[] = '# PHP feeds are checked by WordPress (token, Bearer, allowed IPs, administrator).';
			$lines[] = 'RewriteCond %{REQUEST_FILENAME} -f';
			$lines[] = 'RewriteCond %{QUERY_STRING} !(^|&)cp_token=YOUR_TOKEN(&|$)';
			$lines[] = 'RewriteCond %{HTTP:X-ScrapeLock-Token} !^YOUR_TOKEN$';
			$lines[] = 'RewriteRule ' . self::apache_regex( $regex ) . ' - [F,L]';
		}
		$lines[] = '# Authorization: Bearer reaches PHP with PHP-FPM / CGI too.';
		$lines[] = 'RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]';
		$lines[] = '</IfModule>';
		// 3.12.3: the fingerprint of these rules, only in the answers to the site's own signed requests (mod_headers).
		$hashed  = array_diff_key( $lines, $volatile );
		$lines[] = '# The fingerprint of these rules, sent only to ScrapeLock\'s own requests: the plugin sees which rules are installed.';
		$lines[] = '<IfModule mod_headers.c>';
		$lines[] = 'Header always set ' . self::HASH_HEADER . ' "' . self::nginx_hash( $hashed ) . '" "expr=-n %{HTTP:X-ScrapeLock-Sig}"';
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
