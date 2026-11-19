<?php
/**
 * 3.10.1: small files that services and devices ask for at the root of the site, and that a site often lacks:
 * apple-touch-icon.png (iPhones and iPads, Apple's link previews) and OneSignalSDKWorker.js (the service worker of
 * OneSignal's push notifications, asked for again at the root by browsers that subscribed when it was there).
 * Site Health tells which ones answer "not found" and offers to create them, one click each; nothing is written
 * without that click. A file is never overwritten, and only files ScrapeLock created (same content) are removed.
 *
 * Plus a Site Health test for Wordfence behind a CDN: does it read the visitor's address, or the CDN's?
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Root site files and the Wordfence address check.
 */
final class PNCP_Site_Files {

	/**
	 * Admin-post action (and nonce action prefix) of "Create" and "Remove".
	 */
	const ACTION = 'pncp_site_files';

	/**
	 * Option: the files ScrapeLock created, name => sha1 of the content written.
	 */
	const RECORD = 'pncp_site_files';

	/**
	 * Transient with the last check (file ids and outcomes only).
	 */
	const CACHE = 'pncp_health_site_files';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		if ( ! is_admin() && ! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
			return;
		}
		add_filter( 'site_status_tests', array( __CLASS__, 'tests' ) );
		add_action( 'wp_ajax_health-check-scrapelock-sitefiles', array( __CLASS__, 'ajax_test' ) );
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
	}

	/**
	 * The files ScrapeLock can create: id => file names at the root of the site.
	 *
	 * @return array<string, string[]>
	 */
	public static function files() {
		return array(
			'icon'      => array( 'apple-touch-icon.png', 'apple-touch-icon-precomposed.png' ),
			'onesignal' => array( 'OneSignalSDKWorker.js' ),
		);
	}

	/**
	 * Does this site need the file at all? The icon: always (it is made from the Site Icon). OneSignal's worker:
	 * only while the OneSignal plugin is active.
	 *
	 * @param string $id File id.
	 * @return bool
	 */
	public static function wanted( $id ) {
		if ( 'onesignal' === $id ) {
			return self::onesignal_active();
		}
		return 'icon' === $id;
	}

	/**
	 * Is OneSignal's WordPress plugin active (any folder name it was installed under)?
	 *
	 * @return bool
	 */
	public static function onesignal_active() {
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		foreach ( $active as $plugin ) {
			if ( 0 === strpos( (string) $plugin, 'onesignal-free-web-push-notifications/' ) ) {
				return true;
			}
		}
		return (bool) apply_filters( 'pncp_onesignal_active', false );
	}

	/**
	 * The content of OneSignalSDKWorker.js: the one line OneSignal documents for its v16 SDK.
	 *
	 * @return string
	 */
	public static function onesignal_worker() {
		$url = (string) apply_filters( 'pncp_onesignal_worker_sdk', 'https://cdn.onesignal.com/sdks/web/v16/OneSignalSDK.sw.js' );
		return 'importScripts(' . wp_json_encode( esc_url_raw( $url ), JSON_UNESCAPED_SLASHES ) . ");\n";
	}

	/**
	 * The folder of the site's root (where home_url( '/' ) points), with a trailing slash.
	 *
	 * @return string
	 */
	public static function root_dir() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		return (string) apply_filters( 'pncp_site_files_root', trailingslashit( get_home_path() ) );
	}

	/**
	 * Was this file created by ScrapeLock, and is it still as written?
	 *
	 * @param string $name File name.
	 * @return bool
	 */
	public static function ours( $name ) {
		$record = get_option( self::RECORD, array() );
		$path   = self::root_dir() . $name;
		return is_array( $record ) && isset( $record[ $name ] ) && is_file( $path ) && hash_equals( (string) $record[ $name ], (string) sha1_file( $path ) );
	}

	/**
	 * The Site Health tests.
	 *
	 * @param array<string, mixed> $tests Tests.
	 * @return array<string, mixed>
	 */
	public static function tests( $tests ) {
		// One underscore in the key: Site Health builds the AJAX action from it (health-check-scrapelock-sitefiles).
		$tests['async']['scrapelock_sitefiles'] = array(
			'label'             => __( 'ScrapeLock site files', 'scrapelock' ),
			'test'              => 'scrapelock_sitefiles',
			'has_rest'          => false,
			'async_direct_test' => array( __CLASS__, 'test' ),
		);
		if ( self::wordfence_active() ) {
			$tests['direct']['scrapelock_wordfence'] = array(
				'label' => __( 'Wordfence and the visitor address', 'scrapelock' ),
				'test'  => array( __CLASS__, 'test_wordfence' ),
			);
		}
		return $tests;
	}

	/**
	 * Site Health's script runs the site files test through admin-ajax.
	 */
	public static function ajax_test() {
		check_ajax_referer( 'health-check-site-status' );
		if ( ! current_user_can( 'view_site_health_checks' ) ) {
			wp_send_json_error( null, 403 );
		}
		wp_send_json_success( self::test() );
	}

	/**
	 * Asks the site for each file it needs (cached for a day; an hour when something failed).
	 *
	 * @return array<string, string> id => ok | missing | error.
	 */
	public static function probe() {
		$ids = array();
		foreach ( array_keys( self::files() ) as $id ) {
			if ( self::wanted( $id ) && ( 'icon' !== $id || has_site_icon() ) ) {
				$ids[] = $id;
			}
		}
		$key = md5( (string) wp_json_encode( array( PNCP_VERSION, home_url( '/' ), $ids ) ) );
		$got = get_transient( self::CACHE );
		if ( is_array( $got ) && isset( $got['key'], $got['data'] ) && $key === $got['key'] && is_array( $got['data'] ) ) {
			return $got['data'];
		}
		$data = array();
		foreach ( $ids as $id ) {
			$names       = self::files()[ $id ];
			$data[ $id ] = self::fetch( home_url( '/' . $names[0] ), 'icon' === $id ? 'image/' : 'javascript' );
		}
		set_transient(
			self::CACHE,
			array(
				'key'  => $key,
				'data' => $data,
			),
			in_array( 'error', $data, true ) ? HOUR_IN_SECONDS : DAY_IN_SECONDS
		);
		return $data;
	}

	/**
	 * GET a file of the site: ok (HTTP 200 of the expected type), missing (404 / 410, or a web page in its place),
	 * error (anything else). Redirects are followed by WordPress (at most 2).
	 *
	 * @param string $url  Address.
	 * @param string $type Part of the expected Content-Type.
	 * @return string
	 */
	private static function fetch( $url, $type ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'             => 5,
				'redirection'         => 2,
				'sslverify'           => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter for requests to the site itself.
				'limit_response_size' => 65536,
			)
		);
		if ( is_wp_error( $response ) ) {
			return 'error';
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 404 === $code || 410 === $code ) {
			return 'missing';
		}
		if ( 200 !== $code ) {
			return 'error';
		}
		$got = strtolower( (string) wp_remote_retrieve_header( $response, 'content-type' ) );
		if ( false !== strpos( $got, 'text/html' ) ) {
			return 'missing'; // A "not found" page answered with 200 (some themes and caches).
		}
		return ( '' === $got || false !== strpos( $got, $type ) || false !== strpos( $got, 'octet-stream' ) ) ? 'ok' : 'missing';
	}

	/**
	 * The site files test.
	 *
	 * @return array<string, mixed>
	 */
	public static function test() {
		$data   = self::probe();
		$admin  = current_user_can( 'manage_options' );
		$items  = array();
		$good   = array();
		$status = 'good';

		if ( ! has_site_icon() ) {
			$status  = 'recommended';
			$items[] = '<li>' . esc_html__( 'The site has no Site Icon, so iPhones, iPads and Apple\'s link previews find no apple-touch-icon and get "not found". Choose one in Appearance → Customize → Site Identity → Site Icon (at least 512 × 512 pixels); ScrapeLock can then also create apple-touch-icon.png from it.', 'scrapelock' )
				. ' <a href="' . esc_url( admin_url( 'customize.php?autofocus[section]=title_tagline' ) ) . '">' . esc_html__( 'Choose a Site Icon', 'scrapelock' ) . '</a></li>';
		}
		$labels = array(
			'icon'      => __( 'apple-touch-icon.png (iPhones, iPads and Apple\'s link previews), made from the Site Icon', 'scrapelock' ),
			'onesignal' => __( 'OneSignalSDKWorker.js (OneSignal push notifications: browsers that subscribed when the file was at the root ask for it there)', 'scrapelock' ),
		);
		foreach ( $data as $id => $outcome ) {
			if ( ! isset( $labels[ $id ] ) ) {
				continue;
			}
			$names = self::files()[ $id ];
			if ( 'ok' === $outcome ) {
				$good[] = $names[0];
				continue;
			}
			$status = 'recommended';
			$exists = is_file( self::root_dir() . $names[0] );
			if ( 'error' === $outcome ) {
				// The site could not ask itself (loopback refused by the host, a timeout). Still useful: is the
				// file in the site's folder at all?
				/* translators: %s: file description */
				$line = esc_html( sprintf( __( 'Could not be checked over the web: %s.', 'scrapelock' ), $labels[ $id ] ) );
				if ( ! $exists ) {
					$line .= ' ' . esc_html__( 'The file is not in the folder of the site.', 'scrapelock' );
					if ( $admin ) {
						$line .= ' ' . self::button( 'create', $id, __( 'Create it', 'scrapelock' ) );
					}
				}
				$items[] = '<li>' . $line . '</li>';
				continue;
			}
			if ( $exists ) {
				/* translators: %s: file name */
				$items[] = '<li>' . esc_html( sprintf( __( '%s is on the server but the site answers "not found". If the site is behind a CDN (Bunny, Cloudflare), purge this address in the CDN, then check again.', 'scrapelock' ), $names[0] ) ) . '</li>';
				continue;
			}
			/* translators: %s: file description */
			$line = esc_html( sprintf( __( 'Not found: %s.', 'scrapelock' ), $labels[ $id ] ) );
			if ( $admin ) {
				$line .= ' ' . self::button( 'create', $id, __( 'Create it', 'scrapelock' ) );
			}
			$items[] = '<li>' . $line . '</li>';
		}

		$recheck = $admin ? '<p><a href="' . esc_url( self::action_url( 'recheck', '' ) ) . '">' . esc_html__( 'Check again now', 'scrapelock' ) . '</a></p>' : '';
		$remove  = '';
		if ( $admin ) {
			foreach ( self::files() as $id => $names ) {
				if ( self::ours( $names[0] ) ) {
					/* translators: %s: file name */
					$remove .= '<p>' . self::button( 'remove', $id, sprintf( __( 'Remove %s (created by ScrapeLock)', 'scrapelock' ), $names[0] ) ) . '</p>';
				}
			}
		}
		if ( 'good' === $status ) {
			$text = $good
				/* translators: %s: list of file names */
				? sprintf( __( 'These files answer normally: %s.', 'scrapelock' ), implode( ', ', $good ) )
				: __( 'No file is missing that this site needs.', 'scrapelock' );
			return self::result( 'sitefiles', 'good', __( 'Files that devices and services ask for are there', 'scrapelock' ), $text, $recheck . $remove );
		}
		$details = '<ul>' . implode( '', $items ) . '</ul>'
			. '<p>' . esc_html__( 'A missing file is not a security problem; ScrapeLock does not block these requests or count them as attacks. Creating a file writes it in the folder of the site and never replaces a file that is already there.', 'scrapelock' ) . '</p>';
		return self::result( 'sitefiles', 'recommended', __( 'Files that devices and services ask for are missing', 'scrapelock' ), __( 'The site answers "not found" for files that phones, browsers or an active plugin ask for at its root.', 'scrapelock' ), $recheck . $remove, $details );
	}

	/**
	 * A small form button for admin-post (POST, with a nonce).
	 *
	 * @param string $op    create | remove.
	 * @param string $id    File id.
	 * @param string $label Button text.
	 * @return string Escaped HTML.
	 */
	private static function button( $op, $id, $label ) {
		return '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">'
			. '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '">'
			. '<input type="hidden" name="op" value="' . esc_attr( $op ) . '">'
			. '<input type="hidden" name="file" value="' . esc_attr( $id ) . '">'
			. wp_nonce_field( self::ACTION . '_' . $op . '_' . $id, '_wpnonce', true, false )
			. '<button type="submit" class="button button-secondary">' . esc_html( $label ) . '</button></form>';
	}

	/**
	 * A nonce-protected link (for "Check again now").
	 *
	 * @param string $op Operation.
	 * @param string $id File id.
	 * @return string
	 */
	private static function action_url( $op, $id ) {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => self::ACTION,
					'op'     => $op,
					'file'   => $id,
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION . '_' . $op . '_' . $id
		);
	}

	/**
	 * Create, Remove and Check again now.
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Checked right below, with the operation and file in the nonce action.
		$op = isset( $_REQUEST['op'] ) ? sanitize_key( wp_unslash( $_REQUEST['op'] ) ) : '';
		$id = isset( $_REQUEST['file'] ) ? sanitize_key( wp_unslash( $_REQUEST['file'] ) ) : '';
		// phpcs:enable
		check_admin_referer( self::ACTION . '_' . $op . '_' . $id );
		$done = 'recheck';
		if ( 'create' === $op ) {
			$done = self::create( $id );
		} elseif ( 'remove' === $op ) {
			$done = self::remove( $id );
		} elseif ( 'recheck' !== $op ) {
			wp_die( esc_html__( 'Unknown action.', 'scrapelock' ), '', array( 'response' => 400 ) );
		}
		delete_transient( self::CACHE );
		wp_safe_redirect( add_query_arg( 'pncp_site_files', rawurlencode( $done ), admin_url( 'site-health.php' ) ) );
		exit;
	}

	/**
	 * Writes the file(s) of one id at the root of the site. Never over a file that is there.
	 *
	 * @param string $id File id.
	 * @return string Result code for notice().
	 */
	public static function create( $id ) {
		$files = self::files();
		if ( ! isset( $files[ $id ] ) || ! self::wanted( $id ) ) {
			return 'unknown';
		}
		$dir = self::root_dir();
		if ( 'icon' === $id ) {
			$content = self::icon_png();
			if ( '' === $content ) {
				return 'noicon';
			}
		} else {
			$content = self::onesignal_worker();
		}
		$fs = self::filesystem( $dir );
		if ( ! $fs ) {
			return 'notwritable';
		}
		$record  = get_option( self::RECORD, array() );
		$record  = is_array( $record ) ? $record : array();
		$written = 0;
		foreach ( $files[ $id ] as $name ) {
			$path = $dir . $name;
			if ( $fs->exists( $path ) ) {
				continue; // Never replaced: it may be the site's own file.
			}
			if ( ! $fs->put_contents( $path, $content, FS_CHMOD_FILE ) ) {
				return $written ? 'partial' : 'notwritable';
			}
			$record[ $name ] = sha1( $content );
			++$written;
		}
		update_option( self::RECORD, $record, false );
		return $written ? 'created' : 'exists';
	}

	/**
	 * Removes the file(s) of one id, only those ScrapeLock created and nobody changed.
	 *
	 * @param string $id File id.
	 * @return string Result code for notice().
	 */
	public static function remove( $id ) {
		$files = self::files();
		if ( ! isset( $files[ $id ] ) ) {
			return 'unknown';
		}
		$dir    = self::root_dir();
		$fs     = self::filesystem( $dir );
		$record = get_option( self::RECORD, array() );
		$record = is_array( $record ) ? $record : array();
		$gone   = 0;
		foreach ( $files[ $id ] as $name ) {
			if ( $fs && self::ours( $name ) && $fs->delete( $dir . $name ) ) {
				++$gone;
			}
			if ( ! is_file( $dir . $name ) ) {
				unset( $record[ $name ] );
			}
		}
		update_option( self::RECORD, $record, false );
		return $gone ? 'removed' : 'notours';
	}

	/**
	 * Removes every file ScrapeLock created (uninstall).
	 */
	public static function remove_all() {
		foreach ( array_keys( self::files() ) as $id ) {
			self::remove( $id );
		}
		delete_option( self::RECORD );
		delete_transient( self::CACHE );
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

	/**
	 * The Site Icon as a 180 × 180 PNG (Apple's size), or ''.
	 *
	 * @return string
	 */
	public static function icon_png() {
		$attachment = (int) get_option( 'site_icon' );
		$file       = $attachment ? get_attached_file( $attachment ) : '';
		if ( ! $file || ! is_file( $file ) ) {
			return '';
		}
		$editor = wp_get_image_editor( $file );
		if ( is_wp_error( $editor ) || ! $editor->supports_mime_type( 'image/png' ) ) {
			return '';
		}
		$editor->resize( 180, 180, true );
		$tmp = wp_tempnam( 'pncp-icon.png' );
		$out = $editor->save( $tmp, 'image/png' );
		$png = '';
		if ( ! is_wp_error( $out ) && ! empty( $out['path'] ) && is_file( $out['path'] ) ) {
			$png = (string) file_get_contents( $out['path'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A local temporary file.
			wp_delete_file( $out['path'] );
		}
		if ( is_file( $tmp ) ) {
			wp_delete_file( $tmp );
		}
		return 0 === strpos( $png, "\x89PNG" ) ? $png : '';
	}

	/**
	 * The notice after Create / Remove, on Site Health.
	 */
	public static function notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only: which message to show.
		$code = isset( $_GET['pncp_site_files'] ) ? sanitize_key( wp_unslash( $_GET['pncp_site_files'] ) ) : '';
		if ( '' === $code || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$messages = array(
			'created'     => array( 'success', __( 'The file was created at the root of the site. If the site is behind a CDN, purge its address there; Site Health checks it again below.', 'scrapelock' ) ),
			'removed'     => array( 'success', __( 'The file created by ScrapeLock was removed.', 'scrapelock' ) ),
			'recheck'     => array( 'info', __( 'The site files are checked again below.', 'scrapelock' ) ),
			'exists'      => array( 'warning', __( 'A file with that name is already there, so nothing was written.', 'scrapelock' ) ),
			'partial'     => array( 'warning', __( 'Only some of the files could be written. Check the permissions of the site\'s folder.', 'scrapelock' ) ),
			'notwritable' => array( 'error', __( 'The folder of the site cannot be written to by WordPress. Upload the file yourself with FTP or your host\'s file manager.', 'scrapelock' ) ),
			'noicon'      => array( 'error', __( 'The Site Icon could not be turned into a PNG image. Choose a Site Icon (PNG or JPEG, at least 512 × 512 pixels) and try again.', 'scrapelock' ) ),
			'notours'     => array( 'warning', __( 'Nothing was removed: ScrapeLock removes only files it created and that nobody changed since.', 'scrapelock' ) ),
			'unknown'     => array( 'error', __( 'Unknown file.', 'scrapelock' ) ),
		);
		if ( ! isset( $messages[ $code ] ) ) {
			return;
		}
		echo '<div class="notice notice-' . esc_attr( $messages[ $code ][0] ) . ' is-dismissible"><p>' . esc_html( $messages[ $code ][1] ) . '</p></div>';
	}

	/**
	 * Is Wordfence active (its IP function is there)?
	 *
	 * @return bool
	 */
	public static function wordfence_active() {
		return class_exists( 'wfUtils' ) && is_callable( array( 'wfUtils', 'getIP' ) );
	}

	/**
	 * The address Wordfence reads for this request ('' when unknown).
	 *
	 * @return string
	 */
	public static function wordfence_ip() {
		$ip = self::wordfence_active() ? call_user_func( array( 'wfUtils', 'getIP' ) ) : '';
		return (string) apply_filters( 'pncp_wordfence_ip', is_string( $ip ) ? PNCP_Ip::normalize( $ip ) : '' );
	}

	/**
	 * Wordfence's "How does Wordfence get IPs" setting ('' = its automatic choice).
	 *
	 * @return string
	 */
	public static function wordfence_setting() {
		$how = class_exists( 'wfConfig' ) && is_callable( array( 'wfConfig', 'get' ) ) ? call_user_func( array( 'wfConfig', 'get' ), 'howGetIPs', '' ) : '';
		return (string) apply_filters( 'pncp_wordfence_how', is_string( $how ) ? $how : '' );
	}

	/**
	 * Wordfence behind a CDN: does it read the visitor's address (as ScrapeLock does) or the CDN's? Checked on
	 * this very request (the administrator's own visit to Site Health).
	 *
	 * @return array<string, mixed>
	 */
	public static function test_wordfence() {
		$remote  = PNCP_Ip::remote_addr();
		$visitor = PNCP_Ip::client_ip();
		$wf      = self::wordfence_ip();
		$how     = self::wordfence_setting();
		$via_cdn = '' !== $remote && $remote !== $visitor && PNCP_Ip::is_cdn( $remote );
		$fix     = '<p>' . esc_html__( 'In Wordfence → All Options → General Wordfence Options → "How does Wordfence get IPs", choose "Use the X-Forwarded-For HTTP header", and put the CDN\'s addresses in "Trusted Proxies", so that nobody who reaches the server directly can write a false address in that header. Then compare "Detected IP" on that page with your own address.', 'scrapelock' ) . '</p>';
		$ranges  = PNCP_Ip::list_of( 'bunny' );
		if ( $ranges && PNCP_Ip::is_bunny( $remote ) ) {
			$fix .= '<p>' . esc_html__( 'Bunny CDN\'s addresses, as ScrapeLock downloaded them (for "Trusted Proxies"):', 'scrapelock' ) . '</p>'
				. '<p><textarea class="large-text code" rows="6" readonly onfocus="this.select()">' . esc_textarea( implode( "\n", $ranges ) . "\n" ) . '</textarea></p>';
		}
		if ( $via_cdn && '' !== $wf ) {
			if ( $wf === $visitor ) {
				/* translators: %s: IP address */
				return self::result( 'wordfence', 'good', __( 'Wordfence reads the visitor\'s address behind the CDN', 'scrapelock' ), sprintf( __( 'For your visit to this page, Wordfence and ScrapeLock both read %s.', 'scrapelock' ), $visitor ) );
			}
			$status = ( $wf === $remote || PNCP_Ip::is_cdn( $wf ) ) ? 'critical' : 'recommended';
			/* translators: 1: address Wordfence reads, 2: visitor's address */
			$text = sprintf( __( 'For your visit to this page, Wordfence read %1$s, but your address is %2$s.', 'scrapelock' ), $wf, $visitor );
			if ( 'critical' === $status ) {
				$text .= ' ' . __( 'That is a server of the CDN: Wordfence would block or rate-limit the CDN, and with it every visitor, instead of the attacker, and its logs show the CDN instead of the visitors.', 'scrapelock' );
			}
			return self::result( 'wordfence', $status, __( 'Wordfence does not read the visitor\'s address behind the CDN', 'scrapelock' ), $text, '', $fix );
		}
		if ( 'REMOTE_ADDR' === $how && ( PNCP_Ip::behind_bunny() || PNCP_Ip::behind_cloudflare() || PNCP_Ip::is_cdn( $remote ) ) ) {
			return self::result( 'wordfence', 'recommended', __( 'Wordfence may read the CDN\'s address instead of the visitor\'s', 'scrapelock' ), __( 'Wordfence is set to use the address of the connection (REMOTE_ADDR), and the site is behind a CDN: that address is a server of the CDN.', 'scrapelock' ), '', $fix );
		}
		return self::result( 'wordfence', 'good', __( 'Wordfence and ScrapeLock read the same address', 'scrapelock' ), __( 'This visit did not come through a CDN, or Wordfence read the same address as ScrapeLock. Open this page through the site\'s public address to check the CDN.', 'scrapelock' ) );
	}

	/**
	 * One result in the form Site Health expects.
	 *
	 * @param string $key         Test key (after "scrapelock_").
	 * @param string $status      good | recommended | critical.
	 * @param string $label       Title.
	 * @param string $description Plain text.
	 * @param string $actions     Escaped HTML.
	 * @param string $details     Escaped HTML after the text.
	 * @return array<string, mixed>
	 */
	private static function result( $key, $status, $label, $description, $actions = '', $details = '' ) {
		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => 'wordfence' === $key ? __( 'Security', 'scrapelock' ) : __( 'Performance', 'scrapelock' ),
				'color' => 'critical' === $status ? 'red' : ( 'recommended' === $status ? 'orange' : 'blue' ),
			),
			'description' => '<p>' . esc_html( $description ) . '</p>' . $details,
			'actions'     => $actions,
			'test'        => 'scrapelock_' . $key,
		);
	}
}
