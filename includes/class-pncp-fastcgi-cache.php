<?php
/**
 * 3.12.7: the Nginx fastcgi cache of this site, emptied where ScrapeLock empties the page caches.
 *
 * Nginx keeps each cached answer as a file under the folder of fastcgi_cache_path, named after the MD5 of its
 * cache key, starting with a binary header and then the line "\nKEY: <cache key>\n". Deleting the file is how a
 * cached page is purged (Nginx then fetches the page again; Nginx Helper's "Delete local server cache files" does
 * the same). Nginx Helper's own purge (rt_nginx_helper_purge_all) works only when its purge is on and its method
 * and folder match the server's, which is often not the case (a control panel's own fastcgi_cache_path).
 *
 * Where the folder comes from, in this order (the first that names a folder wins; nothing is guessed):
 *   1. the constant SCRAPELOCK_FASTCGI_CACHE_PATH (wp-config.php);
 *   2. Nginx Helper: its constant RT_WP_NGINX_HELPER_CACHE_PATH, or its default folder when its purge method is
 *      "Delete local server cache files" (unlink_files) and that folder exists;
 *   3. WP-CLI only (PNCP_Cli_Server): the Nginx configuration (nginx -T, or the files given), its
 *      fastcgi_cache_path of the zone that this site's server { } block names with fastcgi_cache.
 * A web request uses 1 and 2 only.
 *
 * What is deleted: only regular files inside that folder (symbolic links are never followed or deleted, at most
 * three levels of subfolders as Nginx's levels= allows), whose name is an MD5 (32 hex digits), whose first bytes
 * are Nginx's cache file header with a KEY line whose MD5 is the file's name (or, for a Vary variant, is in the
 * header), and whose key names one of this site's hosts at its start (and, for addresses, the address's path).
 * A folder that is "/", a system folder or holds WordPress itself is refused. The work per run is capped.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The Nginx fastcgi cache.
 */
final class PNCP_Fastcgi_Cache {

	/** Nginx Helper's folder when RT_WP_NGINX_HELPER_CACHE_PATH is not set (its own default). */
	const HELPER_DEFAULT = '/var/run/nginx-cache';

	/** Nginx Helper's settings. */
	const HELPER_OPTION = 'rt_wp_nginx_helper_options';

	/** The last purge of a web request or WP-CLI (counts only; not autoloaded). */
	const LAST = 'pncp_fastcgi_last';

	/** Bytes read from a file to find its KEY line (a longer key is read up to KEY_BYTES). */
	const HEAD_BYTES = 1024;

	/** The most bytes read for a long key. */
	const KEY_BYTES = 8192;

	/** Subfolder levels (Nginx's levels= has at most three). */
	const MAX_DEPTH = 3;

	/** Request methods that a cache key may start with (before or after the scheme). */
	const METHODS = 'GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS';

	/**
	 * Folders that are never a cache folder (also every folder that holds WordPress, see safe_root()).
	 *
	 * @var string[]
	 */
	private static $system = array( '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib32', '/lib64', '/media', '/mnt', '/opt', '/proc', '/root', '/run', '/sbin', '/srv', '/sys', '/tmp', '/usr', '/var', '/www', '/var/run', '/var/cache', '/var/lib', '/var/log', '/var/tmp', '/var/www', '/usr/local', '/usr/share', '/usr/lib', '/etc/nginx', '/www/server', '/www/wwwroot', '/www/wwwlogs', '/www/server/nginx' );

	/* ---------- Where the cache is ---------- */

	/**
	 * The folders known without reading the Nginx configuration: the constant, else Nginx Helper's.
	 *
	 * @return array<int, array{path:string, source:string}>
	 */
	public static function known_dirs() {
		if ( defined( 'SCRAPELOCK_FASTCGI_CACHE_PATH' ) && is_string( SCRAPELOCK_FASTCGI_CACHE_PATH ) && '' !== trim( SCRAPELOCK_FASTCGI_CACHE_PATH ) ) {
			$out = array();
			// Several folders (several zones) separated by commas.
			foreach ( explode( ',', SCRAPELOCK_FASTCGI_CACHE_PATH ) as $path ) {
				if ( '' !== trim( $path ) ) {
					$out[] = array(
						'path'   => trim( $path ),
						'source' => 'SCRAPELOCK_FASTCGI_CACHE_PATH',
					);
				}
			}
			return $out;
		}
		$helper = self::helper_dir();
		return '' === $helper ? array() : array(
			array(
				'path'   => $helper,
				'source' => 'Nginx Helper',
			),
		);
	}

	/**
	 * Nginx Helper's cache folder: its constant RT_WP_NGINX_HELPER_CACHE_PATH, or its default folder when its
	 * settings purge by deleting the files (purge_method "unlink_files") and the folder exists. '' otherwise.
	 *
	 * @return string
	 */
	public static function helper_dir() {
		if ( defined( 'RT_WP_NGINX_HELPER_CACHE_PATH' ) && is_string( RT_WP_NGINX_HELPER_CACHE_PATH ) && '' !== trim( RT_WP_NGINX_HELPER_CACHE_PATH ) ) {
			return trim( RT_WP_NGINX_HELPER_CACHE_PATH );
		}
		$opt = get_site_option( self::HELPER_OPTION );
		if ( ! is_array( $opt ) ) {
			$opt = get_option( self::HELPER_OPTION );
		}
		if ( is_array( $opt ) && isset( $opt['purge_method'] ) && 'unlink_files' === $opt['purge_method']
			&& ( ! isset( $opt['cache_method'] ) || 'enable_fastcgi' === $opt['cache_method'] ) && is_dir( self::HELPER_DEFAULT ) ) {
			return self::HELPER_DEFAULT;
		}
		return '';
	}

	/**
	 * A folder that may be scanned: its real path, or a WP_Error that says why not ("/", a system folder, a
	 * folder that holds WordPress, a relative path, one that does not exist or cannot be read).
	 *
	 * @param string $dir Folder.
	 * @return string|WP_Error
	 */
	public static function safe_root( $dir ) {
		$dir = trim( (string) $dir );
		if ( '' === $dir || '/' !== $dir[0] || false !== strpos( $dir, "\0" ) || preg_match( '#(^|/)\.\.?(/|$)#', $dir ) ) {
			/* translators: %s: folder */
			return new WP_Error( 'pncp_cache_path', sprintf( __( 'Not an absolute folder path: %s', 'scrapelock' ), $dir ) );
		}
		$real = realpath( $dir );
		if ( false === $real || ! is_dir( $real ) ) {
			/* translators: %s: folder */
			return new WP_Error( 'pncp_cache_missing', sprintf( __( 'The cache folder does not exist or cannot be read: %s', 'scrapelock' ), $dir ) );
		}
		$real = rtrim( $real, '/' );
		$wp   = array();
		foreach ( array( ABSPATH, WP_CONTENT_DIR ) as $path ) {
			$r = realpath( $path );
			if ( false !== $r ) {
				$wp[] = rtrim( $r, '/' );
			}
		}
		$holds_wp = false;
		foreach ( $wp as $path ) {
			if ( $path === $real || 0 === strpos( $path . '/', $real . '/' ) ) {
				$holds_wp = true;
			}
		}
		// "/", a folder right under it, a system folder, a home folder, or one that holds WordPress.
		if ( '' === $real || 1 >= substr_count( $real, '/' ) || in_array( $real, self::$system, true ) || '/home' === dirname( $real ) || $holds_wp ) {
			/* translators: %s: folder */
			return new WP_Error( 'pncp_cache_refused', sprintf( __( 'Refused: %s is a system folder or holds the site, not a cache folder.', 'scrapelock' ), '' === $real ? '/' : $real ) );
		}
		if ( ! is_readable( $real ) ) {
			/* translators: %s: folder */
			return new WP_Error( 'pncp_cache_missing', sprintf( __( 'The cache folder does not exist or cannot be read: %s', 'scrapelock' ), $dir ) );
		}
		return $real;
	}

	/* ---------- Cache files ---------- */

	/**
	 * The cache key of an Nginx cache file, or null when it is not one: the name is an MD5, the file starts with
	 * Nginx's header (a small version number in its first bytes) followed by "\nKEY: …\n", and the MD5 of the key
	 * is the file's name (or is in the header: the variant of a Vary answer).
	 *
	 * @param string $file Path of a regular file.
	 * @return string|null
	 */
	public static function read_key( $file ) {
		$name = basename( $file );
		if ( ! preg_match( '/^[0-9a-f]{32}$/', $name ) ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Reads the first bytes of a cache file only.
		$fh = @fopen( $file, 'rb' );
		if ( false === $fh ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- As above.
		$head = (string) fread( $fh, self::HEAD_BYTES );
		$pos  = strpos( $head, "\nKEY: " );
		if ( false !== $pos && false === strpos( $head, "\n", $pos + 6 ) && strlen( $head ) === self::HEAD_BYTES ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- A long key: a little more of the same file.
			$head .= (string) fread( $fh, self::KEY_BYTES - self::HEAD_BYTES );
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- As above.
		return self::key_of( $head, $name );
	}

	/**
	 * The key in the first bytes of a cache file named $name (see read_key()), or null.
	 *
	 * @param string $head The first bytes.
	 * @param string $name The file name (an MD5).
	 * @return string|null
	 */
	public static function key_of( $head, $name ) {
		// The header: the cache version (5 since Nginx 1.9; 3 and 4 before) as a little- or big-endian integer.
		if ( strlen( $head ) < 16 ) {
			return null;
		}
		$le = ord( $head[0] ) > 0 && ord( $head[0] ) < 64 && "\0\0\0" === substr( $head, 1, 3 );
		$be = "\0\0\0" === substr( $head, 0, 3 ) && ord( $head[3] ) > 0 && ord( $head[3] ) < 64;
		if ( ! $le && ! $be ) {
			return null;
		}
		$pos = strpos( $head, "\nKEY: " );
		if ( false === $pos || $pos < 16 ) {
			return null;
		}
		$end = strpos( $head, "\n", $pos + 6 );
		if ( false === $end ) {
			return null;
		}
		$key = substr( $head, $pos + 6, $end - $pos - 6 );
		if ( '' === $key || preg_match( '/[\x00-\x1f\x7f]/', $key ) ) {
			return null;
		}
		if ( md5( $key ) !== $name && false === strpos( substr( $head, 0, $pos ), md5( $key, true ) ) ) {
			return null;
		}
		return $key;
	}

	/**
	 * Where a cache key names a host at its start: [host, the rest after the host and an optional port], or null.
	 * The start may hold only the scheme (http, https, with ://) and the request method, in either order, and
	 * separators; so "httpsGETexample.com/a", "https://example.com/a", "GET|https|example.com|/a" match
	 * example.com, while "httpsGETnotexample.com/a" and "…other.com/?u=example.com" do not.
	 *
	 * @param string   $key   Cache key.
	 * @param string[] $hosts Hosts (lowercase).
	 * @return array{0:string, 1:string}|null
	 */
	public static function key_host( $key, $hosts ) {
		$key = (string) $key;
		$sep = '[\s|:\/,;_]*';
		$m   = '(?:' . self::METHODS . ')';
		// At most the scheme and the method (either order) before the host: "httpsGEThttpexample.com" is not
		// example.com's. The host is matched without case ($http_host keeps the visitor's), the rest as written.
		$lead = '^' . $sep . '(?:https?' . $sep . '(?:' . $m . $sep . ')?|' . $m . $sep . '(?:https?' . $sep . ')?)?';
		foreach ( $hosts as $host ) {
			$host = strtolower( (string) $host );
			if ( '' !== $host && preg_match( '#' . $lead . '(?i:' . preg_quote( $host, '#' ) . ')(?::\d+)?(?=$|[^A-Za-z0-9.\-])#', $key, $hit ) ) {
				// A separator after the host ("GET|https|example.com|/a"): the address starts after it.
				return array( $host, (string) preg_replace( '/^[\s|;,]+/', '', (string) substr( $key, strlen( $hit[0] ) ) ) );
			}
		}
		return null;
	}

	/**
	 * Does a cache key belong to this site (one of its hosts, under its home path), or, with $targets, to one
	 * of those addresses (host and path; the query string too when the address has one)?
	 *
	 * @param string                                       $key     Cache key.
	 * @param string[]                                     $hosts   This site's hosts.
	 * @param string                                       $base    The home path ("/" or "/sub/").
	 * @param array<int, array{host:string, uri:string}>|null $targets Addresses, or null for the whole site.
	 * @return bool
	 */
	public static function key_matches( $key, $hosts, $base, $targets = null ) {
		$hit = self::key_host( $key, $hosts );
		if ( null === $hit ) {
			return false;
		}
		list( $host, $rest ) = $hit;
		if ( null === $targets ) {
			return '/' === $base || '' === $base || 0 === strpos( $rest, $base ) || rtrim( $base, '/' ) === $rest || 0 === strpos( $rest, rtrim( $base, '/' ) . '?' );
		}
		foreach ( $targets as $t ) {
			if ( $t['host'] !== $host ) {
				continue;
			}
			$uri = $t['uri'];
			if ( $rest === $uri ) {
				return true;
			}
			// After the address: a query string (when the address has none), or what the key adds after it
			// ("$request_uri$cookie_…" with a separator).
			$next = substr( $rest, strlen( $uri ), 1 );
			if ( 0 === strpos( $rest, $uri ) && ( ( '?' === $next && false === strpos( $uri, '?' ) ) || in_array( $next, array( ' ', '|', "\t", ';' ), true ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Addresses as [host, uri] for key_matches(); null for one that is not this site's.
	 *
	 * @param string[] $urls Full addresses of this site (PNCP_Edge::own_url()).
	 * @return array<int, array{host:string, uri:string}>
	 */
	public static function targets( $urls ) {
		$out = array();
		foreach ( $urls as $url ) {
			$p = wp_parse_url( (string) $url );
			if ( ! is_array( $p ) || empty( $p['host'] ) ) {
				continue;
			}
			$out[] = array(
				'host' => strtolower( $p['host'] ),
				'uri'  => ( isset( $p['path'] ) && '' !== $p['path'] ? $p['path'] : '/' ) . ( isset( $p['query'] ) ? '?' . $p['query'] : '' ),
			);
		}
		return $out;
	}

	/**
	 * This site's home path ("/" or "/sub/"): on a multisite in folders, only the pages of this site.
	 *
	 * @return string
	 */
	public static function base_path() {
		$path = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		return '' === $path ? '/' : trailingslashit( $path );
	}

	/* ---------- Purge ---------- */

	/**
	 * Deletes this site's cache files (or those of the addresses) in the folders.
	 *
	 * @param array<int, array{path:string, source:string}> $dirs Folders.
	 * @param string[]|null                                 $urls Full addresses of this site, or null for all.
	 * @param array{dry?:bool, limit?:int, seconds?:float, hosts?:string[]} $opts dry: count only; limit: files
	 *        looked at per folder; seconds: time per run; hosts: this site's hosts (default PNCP_Edge::site_hosts()).
	 * @return array<int, array{path:string, source:string, error:string, files:int, matched:int, removed:int, failed:int, other:int, links:int, capped:bool}>
	 */
	public static function purge( $dirs, $urls = null, $opts = array() ) {
		$cli     = defined( 'WP_CLI' ) && WP_CLI;
		$limit   = isset( $opts['limit'] ) ? (int) $opts['limit'] : (int) apply_filters( 'pncp_fastcgi_purge_limit', $cli ? 500000 : 20000 );
		$seconds = isset( $opts['seconds'] ) ? (float) $opts['seconds'] : ( $cli ? 600.0 : 5.0 );
		$hosts   = isset( $opts['hosts'] ) ? array_map( 'strtolower', $opts['hosts'] ) : PNCP_Edge::site_hosts();
		$targets = null === $urls ? null : self::targets( $urls );
		$base    = self::base_path();
		$stop    = microtime( true ) + max( 0.1, $seconds );
		$out     = array();
		$seen    = array();
		foreach ( $dirs as $dir ) {
			$row  = array(
				'path'    => (string) $dir['path'],
				'source'  => (string) $dir['source'],
				'error'   => '',
				'files'   => 0,
				'matched' => 0,
				'removed' => 0,
				'failed'  => 0,
				'other'   => 0,
				'links'   => 0,
				'capped'  => false,
			);
			$root = self::safe_root( $dir['path'] );
			if ( is_wp_error( $root ) ) {
				$row['error'] = $root->get_error_message();
				$out[]        = $row;
				continue;
			}
			if ( isset( $seen[ $root ] ) ) {
				continue; // The same folder named twice (two zones, one folder).
			}
			$seen[ $root ] = true;
			$row['path']   = $root;
			$ctx           = array(
				'hosts'   => $hosts,
				'base'    => $base,
				'targets' => $targets,
				'dry'     => ! empty( $opts['dry'] ),
				'limit'   => max( 1, $limit ),
				'stop'    => $stop,
			);
			self::walk( $root, 0, $ctx, $row );
			$out[] = $row;
		}
		return $out;
	}

	/**
	 * One folder of the cache (recursive, at most MAX_DEPTH levels below the root, never through a link).
	 *
	 * @param string                                                                                                 $dir   Folder.
	 * @param int                                                                                                    $depth Level below the root.
	 * @param array{hosts:string[], base:string, targets:array<int, array{host:string, uri:string}>|null, dry:bool, limit:int, stop:float} $ctx What to delete.
	 * @param array<string, mixed>                                                                                   $row   Counts (by reference).
	 */
	private static function walk( $dir, $depth, $ctx, &$row ) {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A folder that cannot be read is skipped.
		$dh = @opendir( $dir );
		if ( false === $dh ) {
			return;
		}
		// phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition -- The readdir() loop.
		while ( false !== ( $entry = readdir( $dh ) ) ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			if ( $row['capped'] ) {
				break;
			}
			$path = $dir . '/' . $entry;
			if ( is_link( $path ) ) {
				++$row['links'];
				continue;
			}
			if ( is_dir( $path ) ) {
				if ( $depth < self::MAX_DEPTH ) {
					self::walk( $path, $depth + 1, $ctx, $row );
				}
				continue;
			}
			if ( ! is_file( $path ) ) {
				continue;
			}
			if ( $row['files'] >= $ctx['limit'] || microtime( true ) > $ctx['stop'] ) {
				$row['capped'] = true;
				break;
			}
			++$row['files'];
			$key = self::read_key( $path );
			if ( null === $key || ! self::key_matches( $key, $ctx['hosts'], $ctx['base'], $ctx['targets'] ) ) {
				++$row['other'];
				continue;
			}
			++$row['matched'];
			if ( $ctx['dry'] ) {
				continue;
			}
			wp_delete_file( $path );
			clearstatcache( true, $path );
			if ( file_exists( $path ) || is_link( $path ) ) {
				++$row['failed'];
			} else {
				++$row['removed'];
			}
		}
		closedir( $dh );
	}

	/**
	 * The purge of pncp_purge_page_cache() (settings saved, Stealth on, off or another map, an upgrade): the
	 * folders known without the Nginx configuration (known_dirs()), the whole site. Nothing without one.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function purge_known() {
		$dirs = self::known_dirs();
		if ( ! $dirs ) {
			return array();
		}
		$rows = self::purge( $dirs );
		self::remember( $rows, 'auto' );
		return $rows;
	}

	/**
	 * Keeps the counts of the last purge (for wp scrapelock cache status).
	 *
	 * @param array<int, array<string, mixed>> $rows Result of purge().
	 * @param string                           $how  auto or cli.
	 */
	public static function remember( $rows, $how ) {
		update_option(
			self::LAST,
			array(
				'time' => time(),
				'how'  => $how,
				'rows' => $rows,
			),
			false
		);
	}

	/* ---------- The Nginx configuration (WP-CLI) ---------- */

	/**
	 * The files of an "nginx -T" output: path => text, in order (the first is the main configuration). Text
	 * without the "# configuration file …:" lines is one file named "".
	 *
	 * @param string $dump Output of nginx -T.
	 * @return array<string, string>
	 */
	public static function dump_files( $dump ) {
		$parts = preg_split( '/^# configuration file (.+?):\r?$/m', (string) $dump, -1, PREG_SPLIT_DELIM_CAPTURE );
		if ( ! is_array( $parts ) || count( $parts ) < 3 ) {
			return array( '' => (string) $dump );
		}
		$files = array();
		$n     = count( $parts );
		for ( $i = 1; $i + 1 < $n; $i += 2 ) {
			$files[ trim( $parts[ $i ] ) ] = $parts[ $i + 1 ];
		}
		return $files;
	}

	/**
	 * The tokens of Nginx configuration text: [text, is "{", "}" or ";"]. Comments are dropped, quotes removed.
	 *
	 * @param string $text Configuration.
	 * @return array<int, array{0:string, 1:bool}>
	 */
	public static function tokens( $text ) {
		$out = array();
		$len = strlen( $text );
		$i   = 0;
		while ( $i < $len ) {
			$c = $text[ $i ];
			if ( ctype_space( $c ) ) {
				++$i;
			} elseif ( '#' === $c ) {
				$nl = strpos( $text, "\n", $i );
				$i  = false === $nl ? $len : $nl + 1;
			} elseif ( ';' === $c || '{' === $c || '}' === $c ) {
				$out[] = array( $c, true );
				++$i;
			} elseif ( '"' === $c || "'" === $c ) {
				$buf = '';
				$j   = $i + 1;
				while ( $j < $len && $text[ $j ] !== $c ) {
					if ( '\\' === $text[ $j ] && $j + 1 < $len ) {
						$buf .= $text[ $j + 1 ];
						$j   += 2;
						continue;
					}
					$buf .= $text[ $j ];
					++$j;
				}
				$out[] = array( $buf, false );
				$i     = $j + 1;
			} else {
				$j = $i;
				while ( $j < $len && ! ctype_space( $text[ $j ] ) && false === strpos( ';{}', $text[ $j ] ) ) {
					++$j;
				}
				$out[] = array( substr( $text, $i, $j - $i ), false );
				$i     = $j;
			}
		}
		return $out;
	}

	/**
	 * The directives of the configuration as a tree, the include directives replaced by the files they name.
	 *
	 * @param string                                $main   Main file (a key of $files).
	 * @param array<string, string>|callable        $files  path => text, or a function( pattern ) giving that.
	 * @param string                                $prefix Folder for relative includes.
	 * @return array<int, array{name:string, args:string[], block:array<int, mixed>|null}>
	 */
	public static function tree( $main, $files, $prefix ) {
		$budget = 200; // Files included at most (a loop of includes ends here).
		return self::tree_of( self::text_of( $main, $files ), $files, $prefix, $budget, 0 );
	}

	/**
	 * Text of one file.
	 *
	 * @param string                         $path  Path.
	 * @param array<string, string>|callable $files Files.
	 * @return string
	 */
	private static function text_of( $path, $files ) {
		if ( is_callable( $files ) ) {
			$got = call_user_func( $files, $path );
			return is_array( $got ) && $got ? (string) reset( $got ) : '';
		}
		return isset( $files[ $path ] ) ? $files[ $path ] : '';
	}

	/**
	 * Tree of one text.
	 *
	 * @param string                         $text   Text.
	 * @param array<string, string>|callable $files  Files.
	 * @param string                         $prefix Folder for relative includes.
	 * @param int                            $budget Files still allowed (by reference).
	 * @param int                            $depth  Include depth.
	 * @return array<int, array{name:string, args:string[], block:array<int, mixed>|null}>
	 */
	private static function tree_of( $text, $files, $prefix, &$budget, $depth ) {
		$tokens = self::tokens( $text );
		$pos    = 0;
		return self::block( $tokens, $pos, $files, $prefix, $budget, $depth );
	}

	/**
	 * Directives until the end of a block.
	 *
	 * @param array<int, array{0:string, 1:bool}> $tokens Tokens.
	 * @param int                                 $pos    Position (by reference).
	 * @param array<string, string>|callable      $files  Files.
	 * @param string                              $prefix Folder for relative includes.
	 * @param int                                 $budget Files still allowed (by reference).
	 * @param int                                 $depth  Include depth.
	 * @return array<int, array{name:string, args:string[], block:array<int, mixed>|null}>
	 */
	private static function block( $tokens, &$pos, $files, $prefix, &$budget, $depth ) {
		$out  = array();
		$word = array();
		$n    = count( $tokens );
		while ( $pos < $n ) {
			list( $tok, $special ) = $tokens[ $pos ];
			++$pos;
			if ( ! $special ) {
				$word[] = $tok;
				continue;
			}
			if ( '}' === $tok ) {
				break;
			}
			$name = $word ? strtolower( (string) array_shift( $word ) ) : '';
			if ( '{' === $tok ) {
				$out[] = array(
					'name'  => $name,
					'args'  => $word,
					'block' => self::block( $tokens, $pos, $files, $prefix, $budget, $depth ),
				);
			} elseif ( 'include' === $name && isset( $word[0] ) && $depth < 10 ) {
				foreach ( self::included( $word[0], $files, $prefix ) as $text ) {
					if ( --$budget < 0 ) {
						break;
					}
					foreach ( self::tree_of( $text, $files, $prefix, $budget, $depth + 1 ) as $d ) {
						$out[] = $d;
					}
				}
			} elseif ( '' !== $name ) {
				$out[] = array(
					'name'  => $name,
					'args'  => $word,
					'block' => null,
				);
			}
			$word = array();
		}
		return $out;
	}

	/**
	 * The texts an include pattern names (a relative one is in $prefix, as Nginx resolves it).
	 *
	 * @param string                         $pattern Pattern.
	 * @param array<string, string>|callable $files   Files.
	 * @param string                         $prefix  Folder for relative includes.
	 * @return string[]
	 */
	private static function included( $pattern, $files, $prefix ) {
		if ( '' !== $prefix && '/' !== $pattern[0] ) {
			$pattern = rtrim( $prefix, '/' ) . '/' . $pattern;
		}
		if ( is_callable( $files ) ) {
			$got = call_user_func( $files, $pattern );
			return is_array( $got ) ? array_values( array_map( 'strval', $got ) ) : array();
		}
		$out = array();
		foreach ( $files as $path => $text ) {
			if ( '' !== $path && fnmatch( $pattern, $path, FNM_PATHNAME ) ) {
				$out[] = $text;
			}
		}
		return $out;
	}

	/**
	 * The fastcgi caches of this site in the configuration: each zone that a server { } block of one of its
	 * hosts names with fastcgi_cache (in the block, one of its locations, or inherited from http { }), with
	 * the folder of its fastcgi_cache_path and the cache key in effect there. Notes say what could not be used.
	 *
	 * @param array<int, array{name:string, args:string[], block:array<int, mixed>|null}> $tree  tree().
	 * @param string[]                                                                     $hosts This site's hosts.
	 * @return array{caches:array<int, array{zone:string, path:string, key:string}>, notes:string[], servers:int}
	 */
	public static function find_caches( $tree, $hosts ) {
		$paths = array();
		$http  = array(
			'cache' => array(),
			'key'   => '',
		);
		$servers = array();
		self::scan( $tree, $paths, $servers, $http, 0 );
		$out   = array(
			'caches'  => array(),
			'notes'   => array(),
			'servers' => 0,
		);
		$hosts = array_map( 'strtolower', $hosts );
		foreach ( $servers as $server ) {
			if ( ! self::server_matches( $server['names'], $hosts ) ) {
				continue;
			}
			++$out['servers'];
			$zones = $server['cache'] ? $server['cache'] : $http['cache'];
			$key   = '' !== $server['key'] ? $server['key'] : $http['key'];
			foreach ( $zones as $zone ) {
				if ( 'off' === $zone ) {
					continue;
				}
				if ( false !== strpos( $zone, '$' ) ) {
					/* translators: %s: Nginx variable */
					$out['notes'][] = sprintf( __( 'The cache zone is a variable (%s): name the folder with SCRAPELOCK_FASTCGI_CACHE_PATH.', 'scrapelock' ), $zone );
					continue;
				}
				if ( ! isset( $paths[ $zone ] ) ) {
					/* translators: %s: cache zone */
					$out['notes'][] = sprintf( __( 'No fastcgi_cache_path defines the zone %s.', 'scrapelock' ), $zone );
					continue;
				}
				$row = array(
					'zone' => $zone,
					'path' => $paths[ $zone ],
					'key'  => $key,
				);
				if ( ! in_array( $row, $out['caches'], true ) ) {
					$out['caches'][] = $row;
				}
			}
		}
		return $out;
	}

	/**
	 * Collects fastcgi_cache_path zones, server blocks and the http { } cache settings.
	 *
	 * @param array<int, array{name:string, args:string[], block:array<int, mixed>|null}> $nodes   Directives.
	 * @param array<string, string>                                                        $paths   zone => folder.
	 * @param array<int, array{names:string[], cache:string[], key:string}>               $servers Servers.
	 * @param array{cache:string[], key:string}                                            $http    http-level.
	 * @param int                                                                          $level   0 = main, 1 = http.
	 */
	private static function scan( $nodes, &$paths, &$servers, &$http, $level ) {
		foreach ( $nodes as $d ) {
			if ( 'fastcgi_cache_path' === $d['name'] && isset( $d['args'][0] ) ) {
				foreach ( array_slice( $d['args'], 1 ) as $arg ) {
					if ( preg_match( '/^keys_zone=([^:]+)/', $arg, $m ) ) {
						$paths[ $m[1] ] = $d['args'][0];
					}
				}
			} elseif ( 'server' === $d['name'] && is_array( $d['block'] ) ) {
				$s = array(
					'names' => array(),
					'cache' => array(),
					'key'   => '',
				);
				self::server_scan( $d['block'], $s, $paths );
				$servers[] = $s;
			} elseif ( 'http' === $d['name'] && is_array( $d['block'] ) ) {
				self::scan( $d['block'], $paths, $servers, $http, 1 );
			} elseif ( $level <= 1 && 'fastcgi_cache' === $d['name'] && isset( $d['args'][0] ) ) {
				$http['cache'][] = $d['args'][0];
			} elseif ( $level <= 1 && 'fastcgi_cache_key' === $d['name'] && isset( $d['args'][0] ) && '' === $http['key'] ) {
				$http['key'] = implode( ' ', $d['args'] );
			}
		}
	}

	/**
	 * Inside a server { } block (and its locations).
	 *
	 * @param array<int, array{name:string, args:string[], block:array<int, mixed>|null}> $nodes Directives.
	 * @param array{names:string[], cache:string[], key:string}                            $s     The server.
	 * @param array<string, string>                                                        $paths zone => folder.
	 */
	private static function server_scan( $nodes, &$s, &$paths ) {
		foreach ( $nodes as $d ) {
			if ( 'server_name' === $d['name'] ) {
				foreach ( $d['args'] as $name ) {
					$s['names'][] = strtolower( $name );
				}
			} elseif ( 'fastcgi_cache' === $d['name'] && isset( $d['args'][0] ) ) {
				if ( ! in_array( $d['args'][0], $s['cache'], true ) ) {
					$s['cache'][] = $d['args'][0];
				}
			} elseif ( 'fastcgi_cache_key' === $d['name'] && isset( $d['args'][0] ) && '' === $s['key'] ) {
				$s['key'] = implode( ' ', $d['args'] );
			} elseif ( 'fastcgi_cache_path' === $d['name'] && isset( $d['args'][0] ) ) {
				foreach ( array_slice( $d['args'], 1 ) as $arg ) {
					if ( preg_match( '/^keys_zone=([^:]+)/', $arg, $m ) ) {
						$paths[ $m[1] ] = $d['args'][0];
					}
				}
			} elseif ( is_array( $d['block'] ) ) {
				self::server_scan( $d['block'], $s, $paths );
			}
		}
	}

	/**
	 * Does a server_name list name one of the hosts (exact, "*.example.com", ".example.com", "example.*")?
	 * Regular expressions (~…) are not evaluated.
	 *
	 * @param string[] $names server_name values.
	 * @param string[] $hosts Hosts.
	 * @return bool
	 */
	public static function server_matches( $names, $hosts ) {
		foreach ( $names as $name ) {
			foreach ( $hosts as $host ) {
				if ( $name === $host
					|| ( 0 === strpos( $name, '*.' ) && substr( $host, -strlen( $name ) + 1 ) === substr( $name, 1 ) )
					|| ( 0 === strpos( $name, '.' ) && ( substr( $name, 1 ) === $host || substr( $host, -strlen( $name ) ) === $name ) )
					|| ( '.*' === substr( $name, -2 ) && 0 === strpos( $host, substr( $name, 0, -1 ) ) ) ) {
					return true;
				}
			}
		}
		return false;
	}
}
