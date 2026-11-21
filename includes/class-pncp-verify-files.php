<?php
/**
 * 3.12.6: "Verification files": a small file that a service asks for to verify that the site is yours
 * (/builtwith.txt, /google<hex>.html, /BingSiteAuth.xml, /yandex_<hex>.html, /.well-known/<name>), served for a
 * few hours to every bot, also to one the bot list blocks, then gone.
 *
 * - The path is one name at the root of the site, or under /.well-known/; text only (txt, html, htm, xml, json,
 *   or no extension under /.well-known/), never a PHP-like name, never wp-*, never a file the plugin serves itself.
 *   The content is text, at most MAX_BYTES.
 * - Served by WordPress as the plugin loads (maybe_serve()), before every check of the plugin, with the type of its
 *   extension and no caching. Optionally also written to the site's root folder (only with the explicit choice):
 *   never over an existing file, and only the plugin's own file (same content) is removed.
 * - Open for every bot: the plugin's checks (PNCP_Bots::open_paths(), so the early check too), the pre-cache check
 *   (its configuration's "open"), and the server rules: the Nginx map $pncp_open_path and the Apache conditions.
 *   Those lines are left out of the rules' fingerprint (like the server's own addresses): a file that is there for
 *   a day must not make the rules "out of date" twice (when it is added and when it goes). Nginx and Apache read
 *   them only when the rules are copied again (wp scrapelock rules install); the tool says so.
 * - The address is purged at the CDN when the file is added and when it goes (PNCP_Edge::cdn_purge()).
 * - It goes by itself after its hours (1 to MAX_HOURS, 24 by default): a single cron event, the hourly one, and
 *   never served after that time in any case.
 * - Added and removed in the Server rules tab (admin-post, nonce, manage_options, never while locked) and with
 *   wp scrapelock verify-file add | list | remove.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Temporary verification files.
 */
final class PNCP_Verify_Files {

	/**
	 * Option (autoloaded, only while there are files): path => array{until:int, disk:int}.
	 */
	const INDEX = 'pncp_verify_files';

	/**
	 * Option (not autoloaded): path => array{content:string, created:int, sha1:string} (sha1: of the file written
	 * to the root folder, '' when none).
	 */
	const DATA = 'pncp_verify_files_data';

	/**
	 * Cron hook of the end of a file.
	 */
	const CRON = 'pncp_verify_files_expire';

	/**
	 * Admin-post action (and nonce action prefix).
	 */
	const ACTION = 'pncp_verify_file';

	/**
	 * The largest content.
	 */
	const MAX_BYTES = 65536;

	/**
	 * The most hours a file stays.
	 */
	const MAX_HOURS = 168;

	/**
	 * The most files at once.
	 */
	const MAX_FILES = 10;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'sweep' ) );
		add_action( PNCP_Log::CRON, array( __CLASS__, 'sweep' ), 30 );
		if ( is_admin() ) {
			add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		}
	}

	/* ---------- The files ---------- */

	/**
	 * The files that are open now: path => until. Read on every request (an autoloaded option that only exists
	 * while there are files).
	 *
	 * @param int|null $now The time (tests).
	 * @return array<string, int>
	 */
	public static function paths( $now = null ) {
		$index = get_option( self::INDEX, array() );
		if ( ! is_array( $index ) || ! $index ) {
			return array();
		}
		$now = null === $now ? time() : (int) $now;
		$out = array();
		foreach ( $index as $path => $row ) {
			$until = is_array( $row ) && isset( $row['until'] ) ? (int) $row['until'] : 0;
			if ( $until > $now && is_string( $path ) && '' !== $path ) {
				$out[ $path ] = $until;
			}
		}
		return $out;
	}

	/**
	 * Every file, with its content: path => array{until, disk, content, created, sha1}.
	 *
	 * @return array<string, array{until:int, disk:int, content:string, created:int, sha1:string}>
	 */
	public static function all() {
		$index = get_option( self::INDEX, array() );
		$data  = get_option( self::DATA, array() );
		$index = is_array( $index ) ? $index : array();
		$data  = is_array( $data ) ? $data : array();
		$out   = array();
		foreach ( $index as $path => $row ) {
			$d            = isset( $data[ $path ] ) && is_array( $data[ $path ] ) ? $data[ $path ] : array();
			$out[ $path ] = array(
				'until'   => (int) ( $row['until'] ?? 0 ),
				'disk'    => (int) ( $row['disk'] ?? 0 ),
				'content' => (string) ( $d['content'] ?? '' ),
				'created' => (int) ( $d['created'] ?? 0 ),
				'sha1'    => (string) ( $d['sha1'] ?? '' ),
			);
		}
		return $out;
	}

	/**
	 * Stores the files (the index goes when empty, so a site without files reads nothing more).
	 *
	 * @param array<string, array{until:int, disk:int, content:string, created:int, sha1:string}> $files Files.
	 */
	private static function store( $files ) {
		if ( ! $files ) {
			delete_option( self::INDEX );
			delete_option( self::DATA );
			return;
		}
		$index = array();
		$data  = array();
		foreach ( $files as $path => $f ) {
			$index[ $path ] = array(
				'until' => (int) $f['until'],
				'disk'  => (int) $f['disk'],
			);
			$data[ $path ]  = array(
				'content' => (string) $f['content'],
				'created' => (int) $f['created'],
				'sha1'    => (string) $f['sha1'],
			);
		}
		update_option( self::DATA, $data, false );
		update_option( self::INDEX, $index, true );
	}

	/**
	 * Checks a path: "/name.ext" at the root or "/.well-known/name"; the clean path or an error.
	 *
	 * @param string $path Path.
	 * @return string|WP_Error
	 */
	public static function check_path( $path ) {
		$path = trim( (string) $path );
		if ( '' !== $path && '/' !== $path[0] ) {
			$path = '/' . $path;
		}
		$bad = static function ( $text ) {
			return new WP_Error( 'pncp_verify_path', $text );
		};
		if ( ! preg_match( '#^/(\.well-known/)?([A-Za-z0-9][A-Za-z0-9._-]{0,99})$#', $path, $m ) || false !== strpos( $path, '..' ) ) {
			return $bad( __( 'Give one file name at the root of the site (e.g. /builtwith.txt, /google1234abcd.html, /BingSiteAuth.xml) or under /.well-known/ (e.g. /.well-known/example.txt): letters, digits, ".", "-" and "_" only, no folders, no "..".', 'scrapelock' ) );
		}
		$well = '' !== $m[1];
		$name = strtolower( $m[2] );
		$ext  = false === strpos( $name, '.' ) ? '' : substr( $name, strrpos( $name, '.' ) + 1 );
		if ( preg_match( '/\.(?:php[0-9]*|phtml|phar|pht|phps|inc|cgi|fcgi|pl|py|rb|sh|asp|aspx|jsp|exe|dll|so|htaccess|htpasswd|ini|env|config|cfg|conf|log|sql|bak|zip|gz)(?:\.|$)/', $name ) || 0 === strpos( $name, '.' ) ) {
			return $bad( __( 'Not a file name that can be opened: no PHP-like, script, configuration or archive files.', 'scrapelock' ) );
		}
		if ( ! in_array( $ext, array( 'txt', 'html', 'htm', 'xml', 'json' ), true ) && ! ( $well && '' === $ext ) ) {
			return $bad( __( 'Only text files: .txt, .html, .htm, .xml or .json (under /.well-known/ also a name without an extension).', 'scrapelock' ) );
		}
		if ( preg_match( '/^(?:wp-|xmlrpc|index\.|uploads|robots\.txt$|llms(?:-full)?\.txt$|sitemap|wp_sitemap|tdmrep\.json$|scrapelock)/', $name ) ) {
			return $bad( __( 'This name belongs to WordPress or to ScrapeLock itself: choose the name the service asks for.', 'scrapelock' ) );
		}
		return $path;
	}

	/**
	 * Checks the content: text, at most MAX_BYTES.
	 *
	 * @param string $content Content.
	 * @return string|WP_Error
	 */
	public static function check_content( $content ) {
		$content = (string) $content;
		if ( '' === trim( $content ) ) {
			return new WP_Error( 'pncp_verify_content', __( 'Give the content the service asks for.', 'scrapelock' ) );
		}
		if ( strlen( $content ) > self::MAX_BYTES ) {
			/* translators: %d: kilobytes */
			return new WP_Error( 'pncp_verify_content', sprintf( __( 'The content is too long: at most %d KB.', 'scrapelock' ), (int) ( self::MAX_BYTES / 1024 ) ) );
		}
		if ( wp_check_invalid_utf8( $content ) !== $content || preg_match( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $content ) || false !== stripos( $content, '<?php' ) ) {
			return new WP_Error( 'pncp_verify_content', __( 'Only text (UTF-8, no control characters, no PHP).', 'scrapelock' ) );
		}
		return $content;
	}

	/**
	 * The Content-Type of a path.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function type_of( $path ) {
		$ext   = strtolower( (string) pathinfo( (string) $path, PATHINFO_EXTENSION ) );
		$types = array(
			'txt'  => 'text/plain',
			'html' => 'text/html',
			'htm'  => 'text/html',
			'xml'  => 'application/xml',
			'json' => 'application/json',
		);
		return ( isset( $types[ $ext ] ) ? $types[ $ext ] : 'text/plain' ) . '; charset=utf-8';
	}

	/**
	 * The address of a path on this site.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function url_of( $path ) {
		$home = wp_parse_url( home_url( '/' ) );
		$home = is_array( $home ) ? $home : array();
		return ( $home['scheme'] ?? 'https' ) . '://' . ( $home['host'] ?? '' ) . ( isset( $home['port'] ) ? ':' . $home['port'] : '' ) . $path;
	}

	/**
	 * Adds (or replaces) a file.
	 *
	 * @param string   $path    Path.
	 * @param string   $content Content.
	 * @param int      $hours   Hours, 1 to MAX_HOURS.
	 * @param bool     $disk    Also write it to the site's root folder.
	 * @param int|null $now     The time (tests).
	 * @return array{path:string, url:string, until:int, disk:string, purge:array<string, array{status:string, done:int, message:string}>}|WP_Error
	 *         disk: '' (not asked), written, exists (a file is there: not replaced), notwritable.
	 */
	public static function add( $path, $content, $hours = 24, $disk = false, $now = null ) {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked: nothing can be changed until it is unlocked (with the authenticator app).', 'scrapelock' ) );
		}
		$path = self::check_path( $path );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		$content = self::check_content( $content );
		if ( is_wp_error( $content ) ) {
			return $content;
		}
		$hours = (int) $hours;
		if ( $hours < 1 || $hours > self::MAX_HOURS ) {
			/* translators: %d: most hours */
			return new WP_Error( 'pncp_verify_hours', sprintf( __( 'Hours: 1 to %d.', 'scrapelock' ), self::MAX_HOURS ) );
		}
		$files = self::all();
		if ( isset( $files[ $path ] ) ) {
			self::remove( $path, false ); // Replaced: its own file on disk goes first.
			$files = self::all();
		}
		if ( count( $files ) >= self::MAX_FILES ) {
			/* translators: %d: number of files */
			return new WP_Error( 'pncp_verify_many', sprintf( __( 'At most %d verification files at once: remove one first.', 'scrapelock' ), self::MAX_FILES ) );
		}
		$now      = null === $now ? time() : (int) $now;
		$until    = $now + $hours * HOUR_IN_SECONDS;
		$written  = $disk ? self::write_disk( $path, $content ) : '';
		$sha1     = 'written' === $written ? sha1( $content ) : '';
		$files[ $path ] = array(
			'until'   => $until,
			'disk'    => 'written' === $written ? 1 : 0,
			'content' => $content,
			'created' => $now,
			'sha1'    => $sha1,
		);
		self::store( $files );
		wp_schedule_single_event( $until + 5, self::CRON );
		self::changed();
		return array(
			'path'  => $path,
			'url'   => self::url_of( $path ),
			'until' => $until,
			'disk'  => $written,
			'purge' => self::purge( $path ),
		);
	}

	/**
	 * Removes a file: its own file on disk, the open path, and the address at the CDN.
	 *
	 * @param string $path  Path.
	 * @param bool   $purge Purge at the CDN (not when it is replaced right away).
	 * @return array{removed:bool, disk:string, purge:array<string, array{status:string, done:int, message:string}>}
	 *         disk: removed, kept (changed by someone: not ours any more), '' (none written).
	 */
	public static function remove( $path, $purge = true ) {
		$files = self::all();
		$out   = array(
			'removed' => false,
			'disk'    => '',
			'purge'   => array(),
		);
		if ( ! isset( $files[ $path ] ) ) {
			return $out;
		}
		if ( $files[ $path ]['disk'] ) {
			$out['disk'] = self::remove_disk( $path, $files[ $path ]['sha1'] ) ? 'removed' : 'kept';
		}
		unset( $files[ $path ] );
		self::store( $files );
		self::changed();
		$out['removed'] = true;
		if ( $purge ) {
			$out['purge'] = self::purge( $path );
		}
		return $out;
	}

	/**
	 * Removes the files whose time is over (cron), and purges them at the CDN.
	 *
	 * @param int|null $now The time (tests).
	 * @return string[] The paths removed.
	 */
	public static function sweep( $now = null ) {
		$now  = null === $now ? time() : (int) $now;
		$gone = array();
		foreach ( self::all() as $path => $f ) {
			if ( $f['until'] <= $now ) {
				self::remove( $path );
				$gone[] = $path;
			}
		}
		if ( ! self::all() ) {
			wp_unschedule_hook( self::CRON );
		}
		return $gone;
	}

	/**
	 * Removes every file (uninstall).
	 */
	public static function remove_all() {
		foreach ( array_keys( self::all() ) as $path ) {
			self::remove( $path, false );
		}
		delete_option( self::INDEX );
		delete_option( self::DATA );
		wp_unschedule_hook( self::CRON );
	}

	/**
	 * The open paths changed: the pre-cache check's configuration is written again.
	 */
	private static function changed() {
		if ( class_exists( 'PNCP_Precheck' ) ) {
			PNCP_Precheck::refresh();
		}
	}

	/**
	 * Purges the file's address at the CDN, when the plugin has credentials for one.
	 *
	 * @param string $path Path.
	 * @return array<string, array{status:string, done:int, message:string}>
	 */
	private static function purge( $path ) {
		if ( null === PNCP_Bunny::credentials() && ! PNCP_Edge::cloudflare_connected() ) {
			return array();
		}
		return PNCP_Edge::cdn_purge( array( self::url_of( $path ) ) )['rows'];
	}

	/* ---------- The file in the root folder (only when asked) ---------- */

	/**
	 * The file in the site's root folder.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	private static function disk_path( $path ) {
		return untrailingslashit( PNCP_Site_Files::root_dir() ) . $path;
	}

	/**
	 * Writes the file to the root folder: never over a file that is there; /.well-known/ only where that folder
	 * exists. Not on a site of a network other than the main one (the root folder is shared).
	 *
	 * @param string $path    Path.
	 * @param string $content Content.
	 * @return string written, exists or notwritable.
	 */
	private static function write_disk( $path, $content ) {
		if ( is_multisite() && ! is_main_site() ) {
			return 'notwritable';
		}
		$file = self::disk_path( $path );
		$dir  = dirname( $file );
		if ( file_exists( $file ) || is_link( $file ) ) {
			return 'exists';
		}
		$fs = self::filesystem( $dir );
		if ( ! $fs || ! is_dir( $dir ) ) {
			return 'notwritable';
		}
		return $fs->put_contents( $file, $content, FS_CHMOD_FILE ) ? 'written' : 'notwritable';
	}

	/**
	 * Removes the file from the root folder, only if it is still the one written (same content).
	 *
	 * @param string $path Path.
	 * @param string $sha1 The content written.
	 * @return bool
	 */
	private static function remove_disk( $path, $sha1 ) {
		$file = self::disk_path( $path );
		if ( ! is_file( $file ) || is_link( $file ) || '' === $sha1 || ! hash_equals( $sha1, (string) sha1_file( $file ) ) ) {
			return false;
		}
		$fs = self::filesystem( dirname( $file ) );
		return $fs && $fs->delete( $file );
	}

	/**
	 * WP_Filesystem with direct access to a folder, or null.
	 *
	 * @param string $dir Folder.
	 * @return WP_Filesystem_Base|null
	 */
	private static function filesystem( $dir ) {
		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( ! wp_is_writable( $dir ) || 'direct' !== get_filesystem_method( array(), $dir ) || ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof WP_Filesystem_Base ? $wp_filesystem : null;
	}

	/* ---------- Serving ---------- */

	/**
	 * The path of this request, as the browser sent it (from the root of the host).
	 *
	 * @return string
	 */
	private static function request_path() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared with the stored paths.
		return rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
	}

	/**
	 * Is this request for an open verification file (GET or HEAD)? Its path, or ''.
	 *
	 * @return string
	 */
	public static function requested() {
		$paths = self::paths();
		if ( ! $paths ) {
			return '';
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		$path   = self::request_path();
		return in_array( $method, array( 'GET', 'HEAD' ), true ) && isset( $paths[ $path ] ) ? $path : '';
	}

	/**
	 * Serves the file as the plugin loads, before any check of the plugin: 200, the type of its extension, no
	 * caching (it goes in a few hours), never sniffed, never run (a sandbox for HTML).
	 */
	public static function maybe_serve() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || is_admin() ) {
			return;
		}
		$path = self::requested();
		if ( '' === $path ) {
			return;
		}
		$data = get_option( self::DATA, array() );
		if ( ! is_array( $data ) || ! isset( $data[ $path ]['content'] ) ) {
			return;
		}
		$content = (string) $data[ $path ]['content'];
		status_header( 200 );
		header( 'Content-Type: ' . self::type_of( $path ) );
		header( 'Content-Length: ' . strlen( $content ) );
		header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		header( 'CDN-Cache-Control: no-store' );
		header( 'Pragma: no-cache' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Robots-Tag: noindex' );
		header( "Content-Security-Policy: sandbox; default-src 'none'" );
		if ( 'HEAD' !== strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) ) ) ) {
			echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- The file's own text, served as a file (type, nosniff, sandbox).
		}
		exit;
	}

	/* ---------- The Server rules tab ---------- */

	/**
	 * Add / Remove (admin-post, nonce, manage_options, never while locked).
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked right below, with the operation in the nonce action.
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		check_admin_referer( self::ACTION . '_' . $op );
		if ( PNCP_Lockdown::is_locked() ) {
			wp_die( esc_html__( 'The site is locked: nothing can be changed until it is unlocked (with the authenticator app).', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		$lines = array();
		if ( 'add' === $op ) {
			$path    = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
			$content = isset( $_POST['content'] ) ? (string) wp_unslash( $_POST['content'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Checked by check_content(): text only, served as a file.
			$hours   = isset( $_POST['hours'] ) ? absint( $_POST['hours'] ) : 24;
			$disk    = ! empty( $_POST['disk'] );
			$type    = self::type_of( $path );
			if ( ( 0 === strpos( $type, 'text/html' ) || 0 === strpos( $type, 'application/xml' ) ) && ! current_user_can( 'unfiltered_html' ) && false !== strpos( $content, '<' ) ) {
				$result = new WP_Error( 'pncp_verify_content', __( 'An HTML or XML file with markup needs the unfiltered_html capability.', 'scrapelock' ) );
			} else {
				$result = self::add( $path, $content, $hours, $disk );
			}
			$lines = is_wp_error( $result ) ? array( array( 'error', $result->get_error_message() ) ) : self::result_lines( $result );
		} elseif ( 'remove' === $op ) {
			$path   = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
			$result = self::remove( $path );
			/* translators: %s: path */
			$lines = $result['removed'] ? array_merge( array( array( 'success', sprintf( __( '%s was removed.', 'scrapelock' ), $path ) ) ), self::purge_lines( $result['purge'] ) ) : array( array( 'error', __( 'There is no such verification file.', 'scrapelock' ) ) );
			if ( 'kept' === $result['disk'] ) {
				$lines[] = array( 'warning', __( 'The file in the root folder was changed since ScrapeLock wrote it, so it was left there.', 'scrapelock' ) );
			}
		} else {
			wp_die( esc_html__( 'Unknown action.', 'scrapelock' ), '', array( 'response' => 400 ) );
		}
		// phpcs:enable
		set_transient( 'pncp_verify_msg_' . get_current_user_id(), $lines, 5 * MINUTE_IN_SECONDS );
		wp_safe_redirect( PNCP_Status::settings_url( array( 'tab' => 'rules' ) ) . '#pncp-verify-files' );
		exit;
	}

	/**
	 * What an add did, for people: [class, text] lines.
	 *
	 * @param array{path:string, url:string, until:int, disk:string, purge:array<string, array{status:string, done:int, message:string}>} $result What add() returned.
	 * @return array<int, array{0:string, 1:string}>
	 */
	public static function result_lines( $result ) {
		$lines = array(
			array(
				'success',
				/* translators: 1: address, 2: date and time */
				sprintf( __( '%1$s is served to every bot until %2$s, then removed.', 'scrapelock' ), $result['url'], wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $result['until'] ) ),
			),
		);
		$disk  = array(
			'written'     => array( 'success', __( 'It was also written to the site\'s root folder (removed with it).', 'scrapelock' ) ),
			'exists'      => array( 'warning', __( 'A file with this name is already in the root folder: it was not replaced, and the server serves that one.', 'scrapelock' ) ),
			'notwritable' => array( 'warning', __( 'It could not be written to the root folder: WordPress serves it.', 'scrapelock' ) ),
		);
		if ( isset( $disk[ $result['disk'] ] ) ) {
			$lines[] = $disk[ $result['disk'] ];
		}
		$lines = array_merge( $lines, self::purge_lines( $result['purge'] ) );
		$lines[] = array( 'info', self::rules_hint() );
		return $lines;
	}

	/**
	 * What the CDN said, for people.
	 *
	 * @param array<string, array{status:string, done:int, message:string}> $rows PNCP_Edge::cdn_purge() rows.
	 * @return array<int, array{0:string, 1:string}>
	 */
	public static function purge_lines( $rows ) {
		$lines = array();
		foreach ( $rows as $provider => $row ) {
			$lines[] = 'ok' === $row['status']
				/* translators: %s: CDN name */
				? array( 'success', sprintf( __( '%s: the address was purged.', 'scrapelock' ), $provider ) )
				/* translators: 1: CDN name, 2: error */
				: array( 'warning', sprintf( __( '%1$s: the address was not purged: %2$s', 'scrapelock' ), $provider, $row['message'] ) );
		}
		return $lines;
	}

	/**
	 * The server rules and the file: they let it through only once copied again.
	 *
	 * @return string
	 */
	public static function rules_hint() {
		return __( 'The plugin and the pre-cache check let every bot read it now. Server rules that block bots (Nginx part 1, Apache) let it through only once they are copied again (wp scrapelock rules install, or Server rules); their fingerprint does not change for a verification file, so no "out of date" notice says it.', 'scrapelock' );
	}

	/**
	 * The card in the Server rules tab.
	 */
	public static function render_card() {
		$locked = PNCP_Lockdown::is_locked();
		$msgs   = get_transient( 'pncp_verify_msg_' . get_current_user_id() );
		if ( is_array( $msgs ) ) {
			delete_transient( 'pncp_verify_msg_' . get_current_user_id() );
		}
		echo '<section class="pncp-card pncp-card--wide pncp-rules-card" id="pncp-verify-files" aria-labelledby="pncp-verify-files-h"><h2 id="pncp-verify-files-h">' . esc_html__( 'Verification files', 'scrapelock' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'A file a service asks for to verify that the site is yours (e.g. /builtwith.txt, /google…html, /BingSiteAuth.xml, /.well-known/…): served to every bot, also to one the bot list blocks, for a few hours, then removed.', 'scrapelock' ) . '</p>';
		foreach ( is_array( $msgs ) ? $msgs : array() as $msg ) {
			if ( is_array( $msg ) && isset( $msg[0], $msg[1] ) ) {
				echo '<div class="notice notice-' . esc_attr( (string) $msg[0] ) . ' inline"><p>' . esc_html( (string) $msg[1] ) . '</p></div>';
			}
		}
		$files = self::all();
		if ( $files ) {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Address', 'scrapelock' ) . '</th><th>' . esc_html__( 'Until', 'scrapelock' ) . '</th><th>' . esc_html__( 'Root folder', 'scrapelock' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $files as $path => $f ) {
				echo '<tr><td><a href="' . esc_url( self::url_of( $path ) ) . '" target="_blank" rel="noopener"><code>' . esc_html( $path ) . '</code></a></td><td>' . esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $f['until'] ) ) . '</td><td>' . esc_html( $f['disk'] ? __( 'written', 'scrapelock' ) : '-' ) . '</td><td>';
				if ( ! $locked ) {
					echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '"><input type="hidden" name="op" value="remove"><input type="hidden" name="path" value="' . esc_attr( $path ) . '">';
					wp_nonce_field( self::ACTION . '_remove' );
					echo '<button type="submit" class="button button-small">' . esc_html__( 'Remove', 'scrapelock' ) . '</button></form>';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		if ( $locked ) {
			echo '<p class="pncp-inline-warning">' . esc_html__( 'The site is locked: verification files cannot be added or removed.', 'scrapelock' ) . '</p></section>';
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="pncp-verify-form"><input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '"><input type="hidden" name="op" value="add">';
		wp_nonce_field( self::ACTION . '_add' );
		echo '<p><label for="pncp-verify-path">' . esc_html__( 'Address', 'scrapelock' ) . '</label><br><input type="text" class="regular-text code" id="pncp-verify-path" name="path" placeholder="/builtwith.txt" required maxlength="120"></p>';
		/* translators: %d: kilobytes */
		echo '<p><label for="pncp-verify-content">' . esc_html( sprintf( __( 'Content (text, at most %d KB)', 'scrapelock' ), (int) ( self::MAX_BYTES / 1024 ) ) ) . '</label><br><textarea class="large-text code" rows="4" id="pncp-verify-content" name="content" required maxlength="' . esc_attr( (string) self::MAX_BYTES ) . '"></textarea></p>';
		/* translators: %d: most hours */
		echo '<p><label for="pncp-verify-hours">' . esc_html( sprintf( __( 'Remove after (hours, 1 to %d)', 'scrapelock' ), self::MAX_HOURS ) ) . '</label><br><input type="number" class="small-text" id="pncp-verify-hours" name="hours" value="24" min="1" max="' . esc_attr( (string) self::MAX_HOURS ) . '"></p>';
		echo '<p><label><input type="checkbox" name="disk" value="1"> ' . esc_html__( 'Also write the file to the site\'s root folder (never over an existing file; removed with it). Only needed when the server answers that address itself, without WordPress.', 'scrapelock' ) . '</label></p>';
		echo '<p class="description">' . esc_html( self::rules_hint() ) . '</p>';
		echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Add the file', 'scrapelock' ) . '</button></p></form></section>';
	}
}
