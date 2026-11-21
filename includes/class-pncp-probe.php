<?php
/**
 * 3.5: the scanner probe list ("Ban scanners on their first probe"): paths only attack scanners ask for, as
 * anchored regexes for WordPress, the pre-cache check and the server rules. The ban itself is in
 * PNCP_Bots::probe_guard() and PNCP_Precheck_Runtime::verdict().
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * 3.5: the probe paths. Every entry is a PCRE body matched as #^/(?:BODY)$#i against the request path relative
 * to the site's home path, decoded once (like WordPress). No init(): nothing runs on a normal request.
 */
final class PNCP_Probe {

	/**
	 * 3.5: the entries the pre-cache check runtime mirrors: a match can never be a WordPress page (a dot segment,
	 * or an extension WordPress never gives a page), because the runtime runs before WordPress and cannot know
	 * whether the answer would be a 404.
	 */
	const RUNTIME_KEYS = array( 'env', 'vcs', 'wp_config_backup', 'sql_dump', 'backup_archive' );

	/**
	 * 3.5: the entries the Nginx / Apache rules send to WordPress. Never phpMyAdmin, Adminer or PHP in uploads:
	 * a real one of the host must keep working, and the regex location must not override the PHP location.
	 */
	const SERVER_KEYS = array( 'env', 'vcs', 'wp_config_backup', 'sql_dump', 'backup_archive', 'ssh_key' );

	/**
	 * 3.5: the server-rule entries sent to WordPress only when no such file exists: a real download of the same
	 * name (the site's own name.zip, wordpress.zip, sample.sql) keeps being served. The other SERVER_KEYS (.env,
	 * .git, wp-config.php copies, SSH keys) are never served, even when they exist.
	 */
	const SERVER_IF_MISSING_KEYS = array( 'sql_dump', 'backup_archive' );

	/**
	 * 3.5: the list of this request, memoized per home URL (built only when needed).
	 *
	 * @var array<string, array<string, string>>
	 */
	private static $paths = array();

	/**
	 * 3.11: listed_body() of this request, memoized per home URL (as $paths).
	 *
	 * @var array<string, string>
	 */
	private static $listed = array();

	/**
	 * 3.5: the probe list, key => body, after the filter pncp_probe_trap_paths and validate().
	 *
	 * @return array<string, string>
	 */
	public static function paths() {
		$home = (string) home_url( '/' );
		if ( isset( self::$paths[ $home ] ) ) {
			return self::$paths[ $home ];
		}
		$hosts   = self::hosts();
		$uploads = self::uploads();
		$paths   = array(
			// Laravel / Node / Docker secrets (/.env, /.env.local, /api/.env). A dot segment is never a permalink.
			'env'              => '(?:.*/)?\.env(?:\.[a-z0-9_-]+)*',
			// Version-control folders: source code and credentials.
			'vcs'              => '(?:.*/)?\.(?:git|svn|hg|bzr)(?:/.*)?',
			// Editor and hand-made copies of wp-config.php (served as text, with the database password). A suffix
			// is required: wp-config.php itself and wp-config-sample.php never match.
			'wp_config_backup' => '(?:.*/)?\.?wp-config(?:\.php)?(?:\.(?:bak|backup|old|orig|original|save|saved|swp|swo|txt|tmp|dist|[0-9])|~|[_-](?:bak|backup|old))',
			// Database dumps at the top of the site only.
			'sql_dump'         => '[^/]+\.sql(?:\.(?:gz|zip|bz2|xz|tgz|tar|7z))?',
			// Whole-site archives at the top of the site, a fixed set of names (and the site's own host name).
			'backup_archive'   => '(?:(?:backup|backups|bak|db|database|dump)(?:[._-][a-z0-9._-]*)?|site|website|www|wordpress|wp|public_html|htdocs|html|web' . ( '' !== $hosts ? '|' . $hosts : '' ) . ')\.(?:zip|tar|tar\.gz|tgz|gz|rar|7z|bz2)',
			// Private SSH keys. Not in the runtime: /id_rsa could in theory be a post slug.
			'ssh_key'          => '(?:.*/)?(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|\.ssh(?:/.*)?)',
			// phpMyAdmin at the top or one level down. WordPress only: acted on only when the answer is a 404.
			// 3.5: only the scanner forms (phpmyadmin, phpmyadmin2, phpMyAdmin-5.2.1-all-languages), never a slug
			// such as phpmyadmin-tutorial, and never under the tag, category, author, feed or page bases.
			'phpmyadmin'       => '(?:(?!(?:' . self::archive_bases() . ')/)[^/]+/)?phpmyadmin(?:[0-9._]*|-[0-9][a-z0-9._-]*)(?:/.*)?',
			// Adminer. WordPress only: a real one is executed by the server and never a WordPress 404.
			'adminer'          => '(?:.*/)?adminer[a-z0-9._-]*\.php',
		);
		// 3.11: the probes of other software (Spring Boot, Docker, Railway, Symfony, payment and cloud credentials,
		// a wp-config.php typo-squat), from listed_paths() and the filter pncp_probe_paths. WordPress only.
		$listed = self::listed_body();
		if ( '' !== $listed ) {
			$paths['service_files'] = $listed;
		}
		if ( '' !== $uploads ) {
			// A PHP file in the uploads folder (web-shell scanners). WordPress only: "No PHP in the uploads folder"
			// is the server's part.
			$paths['upload_php'] = $uploads . '/.*\.(?:php[0-9]?|phtml|phar)';
		}
		/**
		 * 3.5: the scanner probe list of "Ban scanners on their first probe", key => PCRE body. Each body is
		 * matched as #^/(?:BODY)$#i against the request path relative to the home path (decoded); write "any
		 * depth" as (?:.*\/)? and escape #. Added keys are checked by WordPress only; only the keys of
		 * PNCP_Probe::RUNTIME_KEYS / SERVER_KEYS are mirrored to the pre-cache check and the server rules (after
		 * the next settings save). Invalid or too broad entries are dropped.
		 *
		 * @param array<string, string> $paths Key => body.
		 */
		$filtered = apply_filters( 'pncp_probe_trap_paths', $paths );
		$valid    = array();
		foreach ( is_array( $filtered ) ? $filtered : array() as $key => $body ) {
			if ( self::validate( $body ) ) {
				$valid[ (string) $key ] = (string) $body;
			}
		}
		self::$paths[ $home ] = $valid;
		return $valid;
	}

	/**
	 * 3.11: the probe paths of other software that only scanners ask for on a WordPress site, as plain paths
	 * relative to the home path: "*" is any part of one path segment, and a final "/*" is the folder and anything
	 * under it. Seen on real sites, cut only by the rate limits before: Spring Boot's /actuator/*, /admin/auth.json,
	 * Docker and Railway files, Symfony's parameters.yml, payment gateway and cloud credentials, /secrets, a
	 * Git folder copied under another name, and /wp-conflg.php (a typo-squat of wp-config.php). The same safety as
	 * the other entries (probe_guard()): only when WordPress answers 404 and no such file exists, never for
	 * staff, verified search engines, always-allowed IPs and User-Agents or a human click, and never for a
	 * site-metadata file (PNCP_Paths::is_site_metadata()).
	 *
	 * @return string[]
	 */
	public static function listed_paths() {
		$paths = array(
			'/actuator',
			'/actuator/*',
			'/admin/auth.json',
			'/Dockerfile',
			'/docker-compose.yml',
			'/docker-compose.yaml',
			'/railway.toml',
			'/railway.json',
			'/payment_gateways/*.yaml',
			'/payment_gateways/*.yml',
			'/payment_gateways/*.json',
			'/config/parameters.yml',
			'/config/parameters.yaml',
			'/app/config/parameters.yml',
			'/credentials',
			'/credentials.yml',
			'/credentials.yaml',
			'/credentials.json',
			'/secrets',
			'/secrets/*',
			'/secrets.yml',
			'/secrets.yaml',
			'/secrets.json',
			'/.aws/*',
			'/.vscode/sftp.json',
			'/*.git/config',
			'/wp-conflg.php',
		);
		/**
		 * 3.11: the plain probe paths of "Ban scanners on their first probe" (relative to the home path, "*" = any
		 * part of one segment, a final "/*" = the folder and anything under it). Checked by WordPress only, with
		 * the same safety as the built-in list (404 only, never a real file, staff, verified bots or a site file).
		 * For full regular expressions use pncp_probe_trap_paths.
		 *
		 * @param string[] $paths Paths, e.g. /actuator/*.
		 */
		$filtered = apply_filters( 'pncp_probe_paths', $paths );
		$out      = array();
		foreach ( is_array( $filtered ) ? $filtered : array() as $path ) {
			$path = '/' . ltrim( trim( (string) $path ), '/' );
			if ( '/' !== $path && strlen( $path ) <= 200 && false === strpos( $path, "\0" ) ) {
				$out[ strtolower( $path ) ] = $path;
			}
		}
		return array_values( $out );
	}

	/**
	 * 3.11: listed_paths() as one PCRE body (each path checked alone first, so a too broad one, e.g. "/*", is
	 * dropped instead of the whole entry).
	 *
	 * @return string '(?:p1|p2|...)', or ''.
	 */
	private static function listed_body() {
		$home = (string) home_url( '/' );
		if ( isset( self::$listed[ $home ] ) ) {
			return self::$listed[ $home ];
		}
		$bodies = array();
		foreach ( self::listed_paths() as $path ) {
			$body = self::glob_body( $path );
			if ( '' !== $body && self::validate( $body ) ) {
				$bodies[] = $body;
			}
		}
		self::$listed[ $home ] = $bodies ? '(?:' . implode( '|', $bodies ) . ')' : '';
		return self::$listed[ $home ];
	}

	/**
	 * 3.11: a plain path of listed_paths() as a body of the list (without the leading slash).
	 *
	 * @param string $path Path, e.g. /payment_gateways/*.yaml.
	 * @return string
	 */
	private static function glob_body( $path ) {
		$path = ltrim( (string) $path, '/' );
		$tail = '';
		if ( '/*' === substr( $path, -2 ) ) {
			$path = substr( $path, 0, -2 );
			$tail = '(?:/.*)?';
		}
		if ( '' === $path ) {
			return '';
		}
		return str_replace( '\\*', '[^/]*', preg_quote( $path, '#' ) ) . $tail;
	}

	/**
	 * 3.11: whether a path (relative to home, decoded) is one of listed_paths() (for the Log and the attack record,
	 * PNCP_Log::is_probe_path()). Never a site-metadata file.
	 *
	 * @param string $path Path, e.g. /actuator/env.
	 * @return bool
	 */
	public static function matches_listed( $path ) {
		if ( PNCP_Paths::is_site_metadata( (string) $path ) ) {
			return false;
		}
		$body = self::listed_body();
		return '' !== $body && 1 === preg_match( '#^/' . $body . '$#i', '/' . ltrim( (string) $path, '/' ) );
	}

	/**
	 * 3.5: the bodies of a set joined into one group.
	 *
	 * @param string $where 'wp' (every entry), 'runtime' (RUNTIME_KEYS), 'server' (SERVER_KEYS without
	 *                      SERVER_IF_MISSING_KEYS) or 'server_missing' (3.5: SERVER_IF_MISSING_KEYS).
	 * @return string '(?:b1|b2|...)', or '' when there is none.
	 */
	public static function body( $where = 'wp' ) {
		$bodies = array();
		foreach ( self::paths() as $key => $body ) {
			if ( 'runtime' === $where && ! in_array( $key, self::RUNTIME_KEYS, true ) ) {
				continue;
			}
			if ( 'server' === $where || 'server_missing' === $where ) {
				// A line break would end the rule; Apache reads whitespace as the end of the argument.
				if ( ! in_array( $key, self::SERVER_KEYS, true ) || preg_match( '/\s/', $body ) ) {
					continue;
				}
				// 3.5: each entry in one of the two server rules.
				if ( in_array( $key, self::SERVER_IF_MISSING_KEYS, true ) !== ( 'server_missing' === $where ) ) {
					continue;
				}
			}
			$bodies[] = $body;
		}
		return $bodies ? '(?:' . implode( '|', $bodies ) . ')' : '';
	}

	/**
	 * 3.5: whether a path (relative to home, decoded) is on the probe list.
	 *
	 * @param string $path Path, e.g. /.env.
	 * @return bool
	 */
	public static function matches( $path ) {
		// 3.10: a site-metadata file (/llms.txt, /.well-known/*, icons, service workers…) is never a probe, also
		// when an entry added with pncp_probe_trap_paths would match it.
		if ( PNCP_Paths::is_site_metadata( (string) $path ) ) {
			return false;
		}
		$body = self::body( 'wp' );
		return '' !== $body && 1 === preg_match( '#^/' . $body . '$#i', '/' . ltrim( (string) $path, '/' ) );
	}

	/**
	 * 3.5: the path of this request as the list is matched: decoded once (PNCP_Bots::request_path()), relative to
	 * the home path, and a leading /index.php/ (PATH_INFO permalinks) reduced to /.
	 *
	 * @return string
	 */
	public static function request_path() {
		$path = PNCP_Private_Urls::relative_path( PNCP_Bots::request_path() );
		return (string) preg_replace( '#^/index\.php(?=/)#i', '', $path );
	}

	/**
	 * 3.5: whether the file (or folder) asked for exists, so a probe for a real file is never banned. A path with
	 * a ".." segment or a NUL byte is never looked up (false: such a request matched the strict list).
	 *
	 * @param string $path Path relative to home, decoded (request_path()).
	 * @return bool
	 */
	public static function file_exists( $path ) {
		$path = '/' . ltrim( (string) $path, '/' );
		$full = '/' . ltrim( PNCP_Bots::request_path(), '/' );
		foreach ( array( $path, $full ) as $check ) {
			if ( false !== strpos( $check, "\0" ) || preg_match( '#(?:^|[/\\\\])\.\.(?:[/\\\\]|$)#', $check ) ) {
				return false;
			}
		}
		$candidates = array();
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- Server paths, only used for file_exists().
		$root = isset( $_SERVER['DOCUMENT_ROOT'] ) ? (string) wp_unslash( $_SERVER['DOCUMENT_ROOT'] ) : '';
		if ( '' !== $root ) {
			$candidates[] = rtrim( $root, '/\\' ) . $full;
		}
		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? (string) wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) : '';
		// phpcs:enable
		if ( '' !== $script && 'index.php' === basename( $script ) ) {
			$candidates[] = dirname( $script ) . $path;
		}
		$candidates[] = untrailingslashit( ABSPATH ) . $path;
		$candidates   = array_unique( $candidates );
		// 3.12.9: in a visitor's request with a persistent object cache or APCu the answer is kept there for an
		// hour: a scanner asking for the same addresses again and again does not make the request ask the disk.
		$key = 'pncp_pf_' . md5( implode( "\n", $candidates ) );
		if ( PNCP_Defer::active() ) {
			$kept = PNCP_Defer::get( $key );
			if ( false !== $kept ) {
				return 1 === (int) $kept;
			}
		}
		$found = false;
		foreach ( $candidates as $file ) {
			if ( @file_exists( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir may refuse the look-up: then "does not exist".
				$found = true;
				break;
			}
		}
		if ( PNCP_Defer::active() ) {
			PNCP_Defer::set( $key, $found ? 1 : 0, HOUR_IN_SECONDS );
		}
		return $found;
	}

	/**
	 * 3.5: an entry is kept only if it compiles (also alone, so it cannot close the group it is put in), is not
	 * too long, and matches none of the addresses every site has (an entry such as ".*" would ban everyone).
	 *
	 * @param mixed $body PCRE body.
	 * @return bool
	 */
	private static function validate( $body ) {
		if ( ! is_string( $body ) || '' === $body || strlen( $body ) > 2000 || false !== strpos( $body, "\0" ) ) {
			return false;
		}
		// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged -- A broken filter must not print warnings on a visitor's page.
		if ( false === @preg_match( '#' . $body . '#i', '' ) || false === @preg_match( '#^/(?:' . $body . ')$#i', '' ) ) {
			return false;
		}
		$samples = array( '/', '/index.php', '/wp-login.php', '/wp-admin/', '/wp-admin/admin-ajax.php', '/wp-cron.php', '/xmlrpc.php', '/wp-config.php', '/wp-json/', '/robots.txt', '/llms.txt', '/favicon.ico', '/sitemap.xml', '/wp-sitemap.xml', '/feed/', '/.well-known/acme-challenge/x', '/.well-known/security.txt', '/.well-known/tdmrep.json', '/wp-content/themes/x/style.css', '/wp-content/uploads/2024/01/a.jpg', PNCP_Bots::trap_path() );
		foreach ( $samples as $sample ) {
			if ( 0 !== @preg_match( '#^/(?:' . $body . ')$#i', $sample ) ) {
				return false;
			}
		}
		// phpcs:enable
		return true;
	}

	/**
	 * 3.5: the site's own host names for the backup archive entry (example.com.zip): the host of home_url(), the
	 * host without "www." and its first label (when not an IP and at least 3 characters), regex-quoted.
	 *
	 * @return string Alternatives joined with |, or ''.
	 */
	private static function hosts() {
		$host = strtolower( trim( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ), '[]' ) );
		if ( '' === $host ) {
			return '';
		}
		$names = array( $host );
		if ( false === filter_var( $host, FILTER_VALIDATE_IP ) ) {
			$bare    = 0 === strpos( $host, 'www.' ) ? substr( $host, 4 ) : $host;
			$names[] = $bare;
			$label   = (string) strtok( $bare, '.' );
			if ( strlen( $label ) >= 3 ) {
				$names[] = $label;
			}
		}
		$quoted = array();
		foreach ( array_unique( array_filter( $names ) ) as $name ) {
			$quoted[] = preg_quote( $name, '#' );
		}
		return implode( '|', $quoted );
	}

	/**
	 * 3.5: the first path segments of WordPress's archives (tag and category bases, author, feed, page, search,
	 * comments), regex-quoted and joined with |, for the phpMyAdmin entry.
	 *
	 * @return string
	 */
	private static function archive_bases() {
		$bases = array( 'tag', 'category', 'author', 'feed', 'page', 'search', 'comments' );
		foreach ( array( 'tag_base', 'category_base' ) as $option ) {
			$base = trim( (string) get_option( $option ), '/' );
			if ( '' !== $base ) {
				$bases[] = (string) strtok( $base, '/' );
			}
		}
		$quoted = array();
		foreach ( array_unique( array_map( 'strtolower', $bases ) ) as $base ) {
			$quoted[] = preg_quote( $base, '#' );
		}
		return implode( '|', $quoted );
	}

	/**
	 * 3.5: the uploads folder relative to home, regex-quoted, without the leading slash (wp\-content/uploads),
	 * or '' when the uploads are on another host (offloaded media) or at the home path itself.
	 *
	 * @return string
	 */
	private static function uploads() {
		$base = (string) wp_get_upload_dir()['baseurl'];
		$host = strtolower( (string) wp_parse_url( $base, PHP_URL_HOST ) );
		$home = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
		if ( '' === $base || $host !== $home ) {
			return '';
		}
		$path = trim( PNCP_Private_Urls::relative_path( (string) wp_parse_url( $base, PHP_URL_PATH ) ), '/' );
		return '' === $path ? '' : preg_quote( $path, '#' );
	}
}
