<?php
/**
 * 3.12.8: Stealth's debug log (opt-in) and `wp scrapelock stealth check`.
 *
 * The log is off unless wp-config.php has define( 'SCRAPELOCK_STEALTH_DEBUG', true ); (24 hours) or a number of
 * hours (1 to 72), or the filter pncp_stealth_debug returns one of those. It ends by itself when that time has
 * passed since its first line, even if the line stays in wp-config.php (delete the file or run
 * `wp scrapelock stealth debug --clear` for a new period). One line per stage of a page: the hook and its
 * priority, whether the page held WP Rocket's minified addresses (/cache/min/) and inner wp-content /
 * wp-includes, before and after, and the codes of those words. Never an IP, a User-Agent, a cookie or a query
 * string; the page's path only. At most 256 KB, in uploads/scrapelock/ under a name that cannot be guessed.
 *
 * Which stage is last: Stealth's own buffer (template_redirect -9999) is started before WP Rocket's optimization
 * buffer (template_redirect 2), so it gets WP Rocket's finished page (after every rocket_buffer filter) and is
 * the outermost buffer a plugin can start. Only WP Rocket's page cache buffer is outside it (advanced-cache.php,
 * before the plugins load): it stores exactly what Stealth's buffer returns. A buffer started later (for
 * example at template_redirect PHP_INT_MAX) would be inside WP Rocket's and run before rocket_buffer.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Stealth debug log and page check.
 */
class PNCP_Stealth_Debug {

	const MAX_BYTES = 262144;

	/**
	 * When this log period started (null = not read yet in this request).
	 *
	 * @var int|null
	 */
	private static $started = null;

	/**
	 * How many hours the log is on (0 = off): the constant SCRAPELOCK_STEALTH_DEBUG, or the filter.
	 *
	 * @return int
	 */
	public static function hours() {
		$value = defined( 'SCRAPELOCK_STEALTH_DEBUG' ) ? constant( 'SCRAPELOCK_STEALTH_DEBUG' ) : false;
		/**
		 * 3.12.8: turns Stealth's debug log on: true (24 hours) or a number of hours (1 to 72).
		 *
		 * @param bool|int $value Off by default.
		 */
		$value = apply_filters( 'pncp_stealth_debug', $value );
		if ( true === $value ) {
			return 24;
		}
		if ( is_numeric( $value ) && (float) $value > 0 ) {
			return (int) min( 72, max( 1, ceil( (float) $value ) ) );
		}
		return 0;
	}

	/**
	 * Is the log on now (turned on, and its period not over)?
	 *
	 * @return bool
	 */
	public static function on() {
		$hours = self::hours();
		if ( $hours <= 0 ) {
			return false;
		}
		$start = self::started();
		return 0 === $start || time() < $start + $hours * HOUR_IN_SECONDS;
	}

	/**
	 * The log file ('' when the uploads folder is not usable).
	 *
	 * @return string
	 */
	public static function file() {
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}
		return untrailingslashit( $uploads['basedir'] ) . '/scrapelock/stealth-debug-' . substr( wp_hash( 'pncp-stealth-debug' ), 0, 12 ) . '.log';
	}

	/**
	 * When the log period started (its first line), 0 when there is no log.
	 *
	 * @return int
	 */
	private static function started() {
		if ( null === self::$started ) {
			self::$started = 0;
			$file          = self::file();
			if ( '' !== $file && is_readable( $file ) ) {
				$head = (string) file_get_contents( $file, false, null, 0, 200 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
				if ( preg_match( '/started (\d{9,11})/', $head, $m ) ) {
					self::$started = (int) $m[1];
				}
			}
		}
		return self::$started;
	}

	/**
	 * Adds a line (the first one says when the period started).
	 *
	 * @param string $line Line.
	 */
	private static function write( $line ) {
		$file = self::file();
		if ( '' === $file || ! wp_mkdir_p( dirname( $file ) ) ) {
			return;
		}
		if ( ! is_file( dirname( $file ) . '/index.html' ) ) {
			file_put_contents( dirname( $file ) . '/index.html', '' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- An empty index, no listing of the folder.
		}
		clearstatcache( true, $file );
		$size = is_file( $file ) ? (int) filesize( $file ) : 0;
		if ( 0 === $size ) {
			self::$started = time();
			$line          = '# ScrapeLock Stealth debug log, started ' . self::$started . ' (' . gmdate( 'Y-m-d H:i:s', self::$started ) . ' UTC), for ' . self::hours() . " hours. No visitor data.\n" . $line;
		} elseif ( $size + strlen( $line ) > self::MAX_BYTES ) {
			return;
		}
		file_put_contents( $file, $line, FILE_APPEND | LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- The debug log the administrator turned on.
	}

	/**
	 * The path of this page (no query string, no visitor data).
	 *
	 * @return string
	 */
	private static function page() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Reduced to its path just below.
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		return substr( (string) preg_replace( '~[^A-Za-z0-9/_.%-]~', '', $path ), 0, 100 );
	}

	/**
	 * The codes of the inner words (wp-content, wp-includes, …) in the stored map: code => word.
	 *
	 * @return array<string, string>
	 */
	private static function inner_codes() {
		return array_intersect( (array) PNCP_Stealth::state()['words'], PNCP_Stealth::cache_words() );
	}

	/**
	 * What a page holds: its size, WP Rocket's minified addresses, inner wp-content / wp-includes in them, all
	 * wp-content / wp-includes, and the codes of the inner words.
	 *
	 * @param string $html Page.
	 * @return array{bytes:int, cache_min:int, inner:int, wp_content:int, wp_includes:int, codes:int}
	 */
	public static function counts( $html ) {
		$html  = str_replace( '\\/', '/', (string) $html );
		$codes = 0;
		foreach ( array_keys( self::inner_codes() ) as $code ) {
			$codes += substr_count( $html, (string) $code );
		}
		return array(
			'bytes'       => strlen( $html ),
			'cache_min'   => substr_count( $html, '/cache/min/' ),
			'inner'       => (int) preg_match_all( '~/cache/(?:min|busting|background-css)/\d+/(?:[^/\s"\'<>]+/)?wp-(?:content|includes)/~', $html ),
			'wp_content'  => substr_count( $html, 'wp-content' ),
			'wp_includes' => substr_count( $html, 'wp-includes' ),
			'codes'       => $codes,
		);
	}

	/**
	 * Logs a stage: before and after.
	 *
	 * @param string      $stage    Hook or buffer.
	 * @param string      $priority Its priority.
	 * @param string      $before   Page before.
	 * @param string|null $after    Page after (null = the stage only looks).
	 */
	public static function stage( $stage, $priority, $before, $after = null ) {
		if ( ! self::on() || ! is_string( $before ) ) {
			return;
		}
		$b    = self::counts( $before );
		$a    = is_string( $after ) ? self::counts( $after ) : $b;
		$line = gmdate( 'Y-m-d\TH:i:s\Z' ) . ' stage=' . sanitize_key( $stage ) . ' prio=' . $priority . ' page=' . self::page() . ' bytes=' . $b['bytes'];
		foreach ( array( 'cache_min', 'inner', 'wp_content', 'wp_includes', 'codes' ) as $key ) {
			$line .= ' ' . $key . '=' . $b[ $key ] . ( is_string( $after ) ? '>' . $a[ $key ] : '' );
		}
		self::write( $line . "\n" );
	}

	/**
	 * The start of a page (Stealth's buffer): whether it is rewritten, and what the stored map holds. Adds the
	 * first look at the optimization plugins' HTML (before their own filters).
	 *
	 * @param bool $rewrites Stealth's buffer started.
	 */
	public static function start( $rewrites ) {
		if ( ! self::on() ) {
			return;
		}
		$state  = PNCP_Stealth::state();
		$inner  = self::inner_codes();
		$wanted = array_diff( PNCP_Stealth::cache_words(), $inner );
		self::write(
			gmdate( 'Y-m-d\TH:i:s\Z' ) . ' stage=start prio=template_redirect:-9999 page=' . self::page()
			. ' rewrites=' . ( $rewrites ? 'yes' : 'no' ) . ' active=' . ( PNCP_Stealth::active() ? 'yes' : 'no' )
			. ' optimizers=' . self::csv( PNCP_Stealth::optimizers() ) . ' inner_words=' . self::csv( $inner )
			. ' missing_words=' . self::csv( $wanted ) . ' pending=' . ( '' !== (string) $state['pending'] ? 'yes' : 'no' ) . "\n"
		);
		if ( $rewrites ) {
			foreach ( array( 'rocket_buffer', 'autoptimize_html_after_minify', 'litespeed_buffer_after', 'w3tc_process_content' ) as $hook ) {
				add_filter( $hook, array( __CLASS__, 'first_look' ), PHP_INT_MIN );
			}
		}
	}

	/**
	 * A list for a log line ('-' when empty).
	 *
	 * @param string[] $items Items.
	 * @return string
	 */
	private static function csv( $items ) {
		return $items ? implode( ',', array_map( 'sanitize_key', $items ) ) : '-';
	}

	/**
	 * The optimization plugin's HTML before its own filters (only looks).
	 *
	 * @param mixed $html Page.
	 * @return mixed
	 */
	public static function first_look( $html ) {
		if ( is_string( $html ) ) {
			self::stage( current_filter(), 'PHP_INT_MIN', $html );
		}
		return $html;
	}

	/**
	 * The last lines of the log.
	 *
	 * @param int $n Lines.
	 * @return string[]
	 */
	public static function tail( $n = 50 ) {
		$file = self::file();
		if ( '' === $file || ! is_readable( $file ) ) {
			return array();
		}
		$lines = preg_split( '/\R/', trim( (string) file_get_contents( $file ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return array_slice( is_array( $lines ) ? $lines : array(), -max( 1, (int) $n ) );
	}

	/**
	 * Deletes the log (the next one starts a new period).
	 *
	 * @return bool
	 */
	public static function clear() {
		$file          = self::file();
		self::$started = null;
		if ( '' !== $file && is_file( $file ) ) {
			wp_delete_file( $file );
		}
		return '' === $file || ! is_file( $file );
	}

	/**
	 * An address cut to 160 characters.
	 *
	 * @param string $text Address.
	 * @return string
	 */
	public static function short( $text ) {
		return substr( (string) $text, 0, 160 );
	}

	/**
	 * For `wp scrapelock stealth check [<url>]`: a page of this site as a visitor gets it (not signed in, through
	 * the caches), and what it holds.
	 *
	 * @param string $url Page (default: the home page). Only this site's hosts.
	 * @return array<string, string>|WP_Error
	 */
	public static function check( $url = '' ) {
		$url  = '' === $url ? home_url( '/' ) : $url;
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		$own  = array();
		foreach ( array( home_url(), site_url() ) as $u ) {
			$own[] = strtolower( (string) wp_parse_url( $u, PHP_URL_HOST ) );
		}
		if ( '' === $host || ! in_array( $host, $own, true ) || ! preg_match( '#^https?://#i', $url ) ) {
			return new WP_Error( 'pncp_stealth_check', __( 'Give a page of this site (its own host).', 'scrapelock' ) );
		}
		$r = PNCP_Self_Check::request(
			$url,
			array(
				'method'      => 'GET',
				'timeout'     => 20,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter for requests to the site itself.
				'headers'     => array( 'Accept' => 'text/html' ),
			),
			'page'
		)['response'];
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		$body  = (string) wp_remote_retrieve_body( $r );
		$c     = self::counts( $body );
		$cache = array();
		foreach ( array( 'x-pn-fastcgi-cache', 'x-fastcgi-cache', 'x-cache', 'x-nginx-cache', 'cdn-cache', 'cf-cache-status', 'x-rocket-nginx-serving-static' ) as $name ) {
			$value = (string) wp_remote_retrieve_header( $r, $name );
			if ( '' !== $value ) {
				$cache[] = $name . ': ' . $value;
			}
		}
		$rules   = PNCP_Stealth::active() ? PNCP_Stealth_Status::status( true )['state'] : '-';
		$next    = PNCP_Stealth_Status::cli_next();
		$state   = PNCP_Stealth::state();
		$codes   = array();
		$plain   = str_replace( '\\/', '/', $body );
		$inner   = self::inner_codes();
		$missing = array_diff( array_values( PNCP_Stealth::build()['words'] ), array_values( (array) $state['words'] ) );
		foreach ( $inner as $code => $word ) {
			$codes[] = $word . '=' . substr_count( $plain, (string) $code );
		}
		preg_match_all( '~[^\s"\'<>()]*wp-(?:content|includes)[^\s"\'<>()]*~', $plain, $m );
		$leaks = array_slice( array_unique( $m[0] ), 0, 5 );
		$base  = (string) $state['base'];
		return array(
			'url'            => $url,
			'code'           => (string) wp_remote_retrieve_response_code( $r ),
			'cache'          => $cache ? implode( ', ', $cache ) : '-',
			'stealth'        => PNCP_Stealth::active() ? 'on' : 'off',
			'bytes'          => (string) $c['bytes'],
			'wp-content'     => (string) $c['wp_content'],
			'wp-includes'    => (string) $c['wp_includes'],
			'cache/min'      => (string) $c['cache_min'],
			'inner'          => (string) $c['inner'],
			'new addresses'  => '' !== $base ? (string) preg_match_all( '~/' . preg_quote( $base, '~' ) . '/[0-9a-f]{6}/~', $plain ) : '0',
			'codes'          => $codes ? implode( ', ', $codes ) : '-',
			'words not used' => $missing ? implode( ', ', $missing ) . ' (' . ( 'current' === $rules ? __( 'run wp scrapelock stealth test', 'scrapelock' ) : __( 'copy the Stealth rules again, then run wp scrapelock stealth test', 'scrapelock' ) ) . ')' : '-',
			'examples'       => $leaks ? implode( ' ', array_map( array( __CLASS__, 'short' ), $leaks ) ) : '-',
			'rules'          => $rules,
			'next'           => '' !== $next ? $next : '-',
			'verdict'        => 0 === $c['wp_content'] + $c['wp_includes'] ? 'clean' : 'leaks',
			'debug log'      => self::on() ? self::file() : 'off',
		);
	}
}
