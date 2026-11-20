<?php
/**
 * One-click hardening of the points bots attack most: XML-RPC, wp-admin, the login, WordPress's own files,
 * the file editor, application passwords, usernames, the REST map, PHP where it never needs to run, directory
 * listing, pingbacks and a few security headers.
 *
 * Each point says what it protects, what it may break, whether it is on now (checked on the site itself, not only
 * read from the settings), how many attacks hit it (PNCP_Attacks, when present), and where it is enforced:
 * by WordPress, by the web server (.htaccess / Nginx rules) or at the Bunny CDN edge.
 *
 * Points that are already ScrapeLock settings (Hide usernames, Hide the REST map, No PHP in uploads, No
 * pingbacks, No framing) are changed through the settings themselves, never duplicated.
 *
 * Normal page views cost nothing: the option is autoloaded, and the hooks of a point are added only when it is on.
 * Nothing is written to the database unless a request is refused.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The "Vulnerable points" catalog, its enforcement, the server rules and the admin card.
 */
final class PNCP_Hardening {

	/**
	 * Option with the points applied here (autoloaded: read on every request without a query).
	 * array{ points: array<string,int>, edge: array<string,int>, xmlrpc_jetpack: int, htaccess: int }
	 */
	const OPTION = 'pncp_hardening';

	/**
	 * Option with the last applies and reverts (not autoloaded).
	 */
	const HISTORY = 'pncp_hardening_history';

	/**
	 * Transient with the result of the live checks.
	 */
	const LIVE = 'pncp_harden_live';

	/**
	 * Marker of ScrapeLock's hardening block in the site's .htaccess.
	 */
	const MARKER = 'ScrapeLock Hardening';

	/**
	 * Nonce action and admin-post action.
	 */
	const ACTION = 'pncp_harden';

	/**
	 * How many history entries are kept.
	 */
	const HISTORY_MAX = 50;

	/**
	 * The points of this request (built once).
	 *
	 * @var array<string, array<string, mixed>>|null
	 */
	private static $points = null;

	/**
	 * The option of this request.
	 *
	 * @var array<string, mixed>|null
	 */
	private static $state = null;

	/**
	 * Registers the hooks. Only the hooks of the points that are on are added.
	 */
	public static function init() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		// While the site is locked with Lockdown, the applied points keep their value too.
		add_filter( 'pncp_lockdown_protected_options', array( __CLASS__, 'protected_options' ) );

		$on = self::state()['points'];
		if ( ! $on ) {
			return;
		}
		if ( isset( $on['xmlrpc'] ) ) {
			// After PNCP_Attacks::on_xmlrpc() (init, 1) has counted the call, before any XML-RPC method runs.
			add_action( 'init', array( __CLASS__, 'xmlrpc_gate' ), 2 );
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'xmlrpc_methods' ), 99 );
			add_filter( 'wp_headers', array( __CLASS__, 'no_pingback_header' ), 99 );
			add_action( 'init', array( __CLASS__, 'no_rsd_link' ), 20 );
		}
		if ( isset( $on['hide_admin'] ) ) {
			add_action( 'init', array( __CLASS__, 'admin_gate' ), 1 );
			add_action( 'template_redirect', array( __CLASS__, 'no_admin_shortcuts' ), 0 );
		}
		if ( isset( $on['file_editor'] ) ) {
			add_filter( 'map_meta_cap', array( __CLASS__, 'no_file_editor' ), 99, 2 );
		}
		if ( isset( $on['app_passwords'] ) ) {
			add_filter( 'wp_is_application_passwords_available_for_user', array( __CLASS__, 'app_passwords_for' ), 99, 2 );
		}
		if ( isset( $on['author_archives'] ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'author_gate' ), 0 );
			add_filter( 'author_link', array( __CLASS__, 'author_link' ), 99 );
		}
		if ( isset( $on['headers'] ) ) {
			add_action( 'send_headers', array( __CLASS__, 'security_headers' ) );
			add_action( 'login_init', array( __CLASS__, 'security_headers' ) );
			add_action( 'admin_init', array( __CLASS__, 'security_headers' ) );
		}
	}

	/* ---------- State ---------- */

	/**
	 * The option, filled in.
	 *
	 * @param bool $fresh Read it again.
	 * @return array{points: array<string,int>, edge: array<string,int>, xmlrpc_jetpack: int, htaccess: int}
	 */
	public static function state( $fresh = false ) {
		if ( null === self::$state || $fresh ) {
			$raw         = get_option( self::OPTION, array() );
			$raw         = is_array( $raw ) ? $raw : array();
			self::$state = array(
				'points'         => isset( $raw['points'] ) && is_array( $raw['points'] ) ? array_map( 'intval', $raw['points'] ) : array(),
				'edge'           => isset( $raw['edge'] ) && is_array( $raw['edge'] ) ? array_map( 'intval', $raw['edge'] ) : array(),
				'xmlrpc_jetpack' => ! empty( $raw['xmlrpc_jetpack'] ) ? 1 : 0,
				'htaccess'       => isset( $raw['htaccess'] ) ? (int) $raw['htaccess'] : 0,
			);
		}
		return self::$state;
	}

	/**
	 * Saves the option (autoloaded) and forgets the live checks.
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function save_state( $state ) {
		self::$state = null;
		update_option( self::OPTION, $state, true );
		self::$state = null;
		delete_transient( self::LIVE );
	}

	/**
	 * Adds the option to those Lockdown keeps while the site is locked.
	 *
	 * @param mixed $names Option names.
	 * @return string[]
	 */
	public static function protected_options( $names ) {
		$names   = is_array( $names ) ? $names : array();
		$names[] = self::OPTION;
		return $names;
	}

	/**
	 * Is the point on in ScrapeLock (applied here, or its setting on)? Says nothing about the server.
	 *
	 * @param string $id Point.
	 * @return bool
	 */
	public static function is_applied( $id ) {
		$point = self::point( $id );
		if ( ! $point ) {
			return false;
		}
		if ( '' !== $point['setting'] ) {
			$s = PNCP_Options::stored();
			return ! empty( $s[ $point['setting'] ] );
		}
		if ( 'login' === $id ) {
			return 'on' === self::login_status();
		}
		return isset( self::state()['points'][ $id ] );
	}

	/**
	 * Is the protection on (the main switch), so the points that refuse requests work?
	 *
	 * @return bool
	 */
	private static function enabled() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] );
	}

	/* ---------- Catalog ---------- */

	/**
	 * The path of the WordPress folder within the site's address, with a trailing slash ("/" or "/wp/").
	 *
	 * @return string
	 */
	private static function core_path() {
		return trailingslashit( (string) wp_parse_url( site_url( '/' ), PHP_URL_PATH ) );
	}

	/**
	 * The path of wp-content within the site's address, without a trailing slash ("/wp-content").
	 *
	 * @return string
	 */
	private static function content_path() {
		return untrailingslashit( (string) wp_parse_url( content_url(), PHP_URL_PATH ) );
	}

	/**
	 * The path of the uploads folder within the site's address, without a trailing slash.
	 *
	 * @return string
	 */
	private static function uploads_path() {
		return untrailingslashit( (string) wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH ) );
	}

	/**
	 * The catalog of points, without their status.
	 *
	 * Keys of each point: id, label, protects, risk (low|medium|high), breaks (what may stop working), where
	 * (keys of where_labels()), setting (the ScrapeLock setting it maps to, or ''), server (whether it needs server
	 * rules), evidence (list of [attack category, path prefix]), edge (Bunny CDN URL patterns, empty = not offered).
	 *
	 * @return array<string, array<string, mixed>>
	 */
	/**
	 * 3.11: the one-line versions of "protects" and "breaks" of each point, shown in the table; the full texts
	 * of points() are folded under "More". A point missing here shows its full texts as before.
	 *
	 * @return array<string, array{0: string, 1: string}> Point id => [ protects, breaks ].
	 */
	public static function short_texts() {
		return array(
			'xmlrpc'          => array( __( 'Refuses xmlrpc.php, used for mass password guessing and pingback attacks.', 'scrapelock' ), __( 'Jetpack (unless allowed), the mobile app and old publishing tools stop working.', 'scrapelock' ) ),
			'hide_admin'      => array( __( 'Signed-out visitors get “page not found” at /wp-admin/.', 'scrapelock' ), __( 'wp-admin links show “page not found” until you sign in.', 'scrapelock' ) ),
			'login'           => array( __( 'Limits failed logins and moves the login page to your own address.', 'scrapelock' ), __( 'Write down the new login address; the old one stops working.', 'scrapelock' ) ),
			'core_files'      => array( __( 'readme.html, license.txt, install.php and similar answer “page not found”.', 'scrapelock' ), __( 'Nothing for visitors. On Nginx, run “wp core update-db” after updates.', 'scrapelock' ) ),
			'file_editor'     => array( __( 'Turns off the theme and plugin code editors in wp-admin.', 'scrapelock' ), __( 'Edit files over SFTP or with your host\'s file manager instead.', 'scrapelock' ) ),
			'app_passwords'   => array( __( 'Only administrators can create and use application passwords.', 'scrapelock' ), __( 'Apps that sign in with a non-administrator application password stop working.', 'scrapelock' ) ),
			'user_enum'       => array( __( 'Hides usernames from ?author=N and /wp-json/wp/v2/users.', 'scrapelock' ), __( 'Nothing for visitors; the users sitemap is removed.', 'scrapelock' ) ),
			'author_archives' => array( __( 'Author pages answer “page not found” for visitors.', 'scrapelock' ), __( 'Author pages leave search results; multi-author sites should leave it off.', 'scrapelock' ) ),
			'rest_map'        => array( __( 'Visitors get an empty /wp-json/ route list; every route still works.', 'scrapelock' ), __( 'Rare: an outside tool that discovers the API while signed out.', 'scrapelock' ) ),
			'upload_php'      => array( __( 'No PHP file in the uploads folder ever runs.', 'scrapelock' ), __( 'Only a plugin that runs its own PHP from uploads (very rare).', 'scrapelock' ) ),
			'includes_php'    => array( __( 'The server refuses PHP files in wp-includes opened directly.', 'scrapelock' ), __( 'Nothing on a normal site; ms-files.php stays open on multisite.', 'scrapelock' ) ),
			'content_php'     => array( __( 'The server refuses PHP files under wp-content opened by address.', 'scrapelock' ), __( 'Plugins with their own PHP address break: test payments and forms after.', 'scrapelock' ) ),
			'dir_listing'     => array( __( 'Folders without an index file answer 403 instead of a file list.', 'scrapelock' ), __( 'Nothing for visitors; the self-test reverts it if the host refuses.', 'scrapelock' ) ),
			'pingback'        => array( __( 'Closes pingback.ping, used for DDoS and for probing pages.', 'scrapelock' ), __( 'You no longer receive pingbacks; trackbacks and comments still work.', 'scrapelock' ) ),
			'headers'         => array( __( 'Adds nosniff, a strict Referrer-Policy and a Permissions-Policy header.', 'scrapelock' ), __( 'Pages that use the camera, microphone or location stop asking for them.', 'scrapelock' ) ),
			'framing'         => array( __( 'Other sites cannot show your pages inside their iframe.', 'scrapelock' ), __( 'Only if you frame your own pages on another site of yours.', 'scrapelock' ) ),
		);
	}

	public static function points() {
		if ( null !== self::$points ) {
			return self::$points;
		}
		$core    = self::core_path();
		$content = self::content_path();
		$uploads = self::uploads_path();
		$points  = array(
			'xmlrpc'          => array(
				'label'    => __( 'XML-RPC (xmlrpc.php)', 'scrapelock' ),
				'protects' => __( 'Refuses every request to xmlrpc.php. Bots use it to try hundreds of passwords in one request (system.multicall) and to make the site attack others with pingbacks.', 'scrapelock' ),
				'risk'     => 'medium',
				'breaks'   => __( 'Jetpack, the WordPress mobile app and old publishing tools (Windows Live Writer, some IFTTT recipes) use XML-RPC. With “Allow Jetpack” on, Jetpack\'s own servers still get through, without pingbacks.', 'scrapelock' ),
				'where'    => array( 'wordpress', 'server', 'edge' ),
				'setting'  => '',
				'server'   => false,
				'evidence' => array( array( 'xmlrpc', '' ) ),
				'edge'     => array( '*' . $core . 'xmlrpc.php*' ),
			),
			'hide_admin'      => array(
				'label'    => __( 'wp-admin for visitors', 'scrapelock' ),
				'protects' => __( 'Visitors who are not signed in get “page not found” for /wp-admin/ instead of a redirect to the login page, so bots do not learn that the site runs WordPress or where to log in. admin-ajax.php and admin-post.php keep working.', 'scrapelock' ),
				'risk'     => 'medium',
				'breaks'   => __( 'A link to a wp-admin page (in an email or a bookmark) opens “page not found” until you sign in: open the login page first. /admin, /dashboard and /login no longer lead to the login page.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => '',
				'server'   => false,
				'evidence' => array( array( 'admin_probe', '' ) ),
				'edge'     => array(),
			),
			'login'           => array(
				'label'    => __( 'Login page (wp-login.php)', 'scrapelock' ),
				'protects' => __( 'Limits failed logins per IP and moves the login page to an address of your own, so password-guessing bots find nothing at wp-login.php.', 'scrapelock' ),
				'risk'     => 'medium',
				'breaks'   => __( 'Write down the new login address: the old one answers “page not found”. Plugins that link to wp-login.php are sent to the new address. “Open again” moves the login page back to wp-login.php and keeps the limit of failed logins on (turn it off on the Bots tab).', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => '',
				'server'   => false,
				'evidence' => array( array( 'login_fail', '' ), array( 'login_probe', '' ) ),
				'edge'     => array(),
			),
			'core_files'      => array(
				'label'    => __( 'WordPress\'s own files: readme.html, license.txt, install.php…', 'scrapelock' ),
				'protects' => __( 'readme.html, license.txt, wp-config-sample.php, wp-admin/install.php and setup-config.php answer “page not found”, and wp-admin/upgrade.php does too for visitors who are not signed in. Scanners open them to see that the site runs WordPress, which version, and whether it can still be installed again.', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'Nothing a visitor uses. The “Update database” screen after a WordPress update still works for signed-in administrators (Apache); on Nginx run “wp core update-db” instead.', 'scrapelock' ),
				'where'    => array( 'server', 'edge' ),
				'setting'  => '',
				'server'   => true,
				'evidence' => array(
					array( 'install', '' ),
					array( 'scanner', $core . 'readme.html' ),
					array( 'scanner', $core . 'license.txt' ),
					array( 'scanner', $core . 'wp-config-sample.php' ),
				),
				'edge'     => array(
					'*' . $core . 'readme.html*',
					'*' . $core . 'license.txt*',
					'*' . $core . 'wp-config-sample.php*',
					'*' . $core . 'wp-admin/install.php*',
					'*' . $core . 'wp-admin/setup-config.php*',
				),
			),
			'file_editor'     => array(
				'label'    => __( 'Theme and plugin file editor', 'scrapelock' ),
				'protects' => __( 'Nobody can edit theme or plugin code from wp-admin (Appearance → Theme File Editor, Plugins → Plugin File Editor). Someone who steals an administrator password usually puts a backdoor in there first.', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'The two editor screens disappear. Edit files over SFTP or with your host\'s file manager instead.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => '',
				'server'   => false,
				'evidence' => array(
					array( 'admin_probe', $core . 'wp-admin/theme-editor.php' ),
					array( 'admin_probe', $core . 'wp-admin/plugin-editor.php' ),
				),
				'edge'     => array(),
			),
			'app_passwords'   => array(
				'label'    => __( 'Application passwords for non-administrators', 'scrapelock' ),
				'protects' => __( 'Only administrators can create and use application passwords (REST API and XML-RPC logins without the normal login page). A stolen editor or customer account cannot be turned into a permanent API key.', 'scrapelock' ),
				'risk'     => 'medium',
				'breaks'   => __( 'An app or service that signs in with the application password of an editor, author or shop manager (a mobile app, Zapier, a publishing tool) stops working. Administrators are not affected.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => '',
				'server'   => false,
				'evidence' => array(),
				'edge'     => array(),
			),
			'user_enum'       => array(
				'label'    => __( 'Usernames: ?author=N and REST /wp/v2/users', 'scrapelock' ),
				'protects' => __( 'Bots collect the usernames of the site with ?author=1, 2, 3… and /wp-json/wp/v2/users, then try passwords for them. Visitors get “page not found” and an empty list (the setting “Hide usernames from visitors”).', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'Nothing for visitors; signed-in users see everything as before. The users sitemap is removed.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => 'block_user_enum',
				'server'   => false,
				'evidence' => array( array( 'user_enum', '' ) ),
				'edge'     => array(),
			),
			'author_archives' => array(
				'label'    => __( 'Author archives (/author/name/)', 'scrapelock' ),
				'protects' => __( 'The author pages show each username in their address. For visitors they answer “page not found”, and links to them point to the home page.', 'scrapelock' ),
				'risk'     => 'medium',
				'breaks'   => __( 'Author pages leave search results, and a theme that shows “More posts by this author” links to the home page. Sites with several authors who have their own pages should leave this off.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => '',
				'server'   => false,
				'evidence' => array( array( 'user_enum', self::home_path() . 'author/' ), array( 'bot_block', self::home_path() . 'author/' ), array( 'scanner', self::home_path() . 'author/' ) ),
				'edge'     => array(),
			),
			'rest_map'        => array(
				'label'    => __( 'REST API map (/wp-json/)', 'scrapelock' ),
				'protects' => __( '/wp-json/ lists every route of every plugin: a map of what to attack. Visitors get an empty list and no links to it; each route still works (the setting “Hide the REST API map”).', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'Rare: an outside tool that discovers the API from /wp-json/ while not signed in. The block editor and signed-in users are not affected.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => 'hide_rest_discovery',
				'server'   => false,
				'evidence' => array( array( 'scanner', self::home_path() . 'wp-json' ) ),
				'edge'     => array(),
			),
			'upload_php'      => array(
				'label'    => __( 'PHP in the uploads folder', 'scrapelock' ),
				'protects' => __( 'A backdoor uploaded through a vulnerable plugin usually lands in the uploads folder. No PHP file there ever runs (the setting “No PHP in the uploads folder”; on Apache ScrapeLock writes it into the uploads folder\'s .htaccess, on Nginx it needs the rule below).', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'Only a plugin that runs its own PHP from the uploads folder (very rare).', 'scrapelock' ),
				'where'    => array( 'wordpress', 'server', 'edge' ),
				'setting'  => 'block_upload_php',
				'server'   => false,
				'evidence' => array( array( 'scanner', $uploads . '/' ), array( 'injection', $uploads . '/' ) ),
				'edge'     => array( '*' . $uploads . '/*.php*', '*' . $uploads . '/*.phtml*', '*' . $uploads . '/*.phar*' ),
			),
			'includes_php'    => array(
				'label'    => __( 'PHP files in wp-includes, opened directly', 'scrapelock' ),
				'protects' => __( 'The PHP files in wp-includes are never meant to be opened in a browser; scanners open them to find errors that show the server\'s folders, or old bugs. The server refuses them (the classic editor\'s wp-tinymce.php stays open).', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'Nothing in a normal site. On a multisite network that still serves files through ms-files.php, that file stays open.', 'scrapelock' ),
				'where'    => array( 'server' ),
				'setting'  => '',
				'server'   => true,
				'evidence' => array( array( 'scanner', $core . 'wp-includes/' ), array( 'injection', $core . 'wp-includes/' ) ),
				'edge'     => array(),
			),
			'content_php'     => array(
				'label'    => __( 'PHP files in wp-content, opened directly', 'scrapelock' ),
				'protects' => __( 'Scanners call the PHP files of plugins and themes directly, looking for the ones with known holes (file uploaders, old image scripts). The server refuses every PHP file under wp-content that is opened by its address.', 'scrapelock' ),
				'risk'     => 'high',
				'breaks'   => __( 'Plugins and themes that have their own PHP address (some captchas, image resizers, download counters, payment callbacks of older gateways) stop working. Test the site, the shop\'s payment and the forms right after, or add the files to the filter pncp_harden_php_allow.', 'scrapelock' ),
				'where'    => array( 'server' ),
				'setting'  => '',
				'server'   => true,
				'evidence' => array( array( 'plugin_probe', '' ), array( 'scanner', $content . '/' ) ),
				'edge'     => array(),
			),
			'dir_listing'     => array(
				'label'    => __( 'Directory listing', 'scrapelock' ),
				'protects' => __( 'A folder without an index file (wp-includes, uploads, a plugin\'s folder) can show the list of its files. The server answers 403 instead, so nobody browses the files of the site.', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'Nothing a visitor uses. Some hosts do not allow “Options” in .htaccess; the self-test then puts the file back on its own.', 'scrapelock' ),
				'where'    => array( 'server' ),
				'setting'  => '',
				'server'   => true,
				'evidence' => array(),
				'edge'     => array(),
			),
			'pingback'        => array(
				'label'    => __( 'XML-RPC pingbacks', 'scrapelock' ),
				'protects' => __( 'pingback.ping stays open even when XML-RPC is “off”, and is used to make the site send requests to other sites (DDoS) or to check that a page exists (the setting “Turn off XML-RPC pingbacks”). Other XML-RPC methods keep working.', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'Other blogs can no longer tell you they linked to you with a pingback. Trackbacks and comments are not affected.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => 'disable_pingback',
				'server'   => false,
				'evidence' => array( array( 'xmlrpc', '' ) ),
				'edge'     => array(),
			),
			'headers'         => array(
				'label'    => __( 'Security headers', 'scrapelock' ),
				'protects' => __( 'X-Content-Type-Options: nosniff (an uploaded file is never run as a script), Referrer-Policy: strict-origin-when-cross-origin (other sites do not see your full addresses and their query strings) and Permissions-Policy (no camera, microphone or location for scripts on your pages).', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'A page that uses the visitor\'s camera, microphone or location (a store finder with “Use my location”, a video chat) stops asking for it. Leave it off then, or change the header with the filter pncp_harden_headers.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => '',
				'server'   => false,
				'evidence' => array(),
				'edge'     => array(),
			),
			'framing'         => array(
				'label'    => __( 'Framing by other sites (X-Frame-Options)', 'scrapelock' ),
				'protects' => __( 'Other sites cannot show your pages inside their own iframe (click-jacking, copied pages under another address). The setting “Pages do not open inside another site\'s iframe”.', 'scrapelock' ),
				'risk'     => 'low',
				'breaks'   => __( 'Only if you show your own pages inside another site of yours. WordPress embeds (oEmbed) keep working.', 'scrapelock' ),
				'where'    => array( 'wordpress' ),
				'setting'  => 'block_framing',
				'server'   => false,
				'evidence' => array(),
				'edge'     => array(),
			),
		);
		foreach ( $points as $id => $point ) {
			$points[ $id ]['id'] = $id;
		}
		self::$points = $points;
		return $points;
	}

	/**
	 * One point, or null.
	 *
	 * @param string $id Point.
	 * @return array<string, mixed>|null
	 */
	public static function point( $id ) {
		$points = self::points();
		return isset( $points[ $id ] ) ? $points[ $id ] : null;
	}

	/**
	 * The path of the home page within the site's address, with a trailing slash.
	 *
	 * @return string
	 */
	private static function home_path() {
		return trailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) );
	}

	/**
	 * Labels of the risk levels.
	 *
	 * @return array<string, string>
	 */
	public static function risk_labels() {
		return array(
			'low'    => __( 'Low', 'scrapelock' ),
			'medium' => __( 'Medium', 'scrapelock' ),
			'high'   => __( 'High', 'scrapelock' ),
		);
	}

	/**
	 * Labels of the places a point is enforced.
	 *
	 * @return array<string, string>
	 */
	public static function where_labels() {
		return array(
			'wordpress' => __( 'WordPress', 'scrapelock' ),
			'server'    => __( 'Server rules', 'scrapelock' ),
			'edge'      => __( 'Bunny edge', 'scrapelock' ),
		);
	}

	/**
	 * Labels of the states.
	 *
	 * @return array<string, string>
	 */
	public static function state_labels() {
		return array(
			'on'      => __( 'Locked', 'scrapelock' ),
			'partial' => __( 'Partly', 'scrapelock' ),
			'off'     => __( 'Open', 'scrapelock' ),
			'na'      => __( 'Not available', 'scrapelock' ),
		);
	}

	/* ---------- Evidence ---------- */

	/**
	 * Attacks seen on a point in the last days (0 without the attack report).
	 *
	 * @param string $id   Point.
	 * @param int    $days Days.
	 * @return int
	 */
	public static function evidence( $id, $days ) {
		$point = self::point( $id );
		if ( ! $point || ! $point['evidence'] || ! class_exists( 'PNCP_Attacks' ) || ! method_exists( 'PNCP_Attacks', 'count' ) ) {
			return 0;
		}
		$total = 0;
		foreach ( $point['evidence'] as $pair ) {
			$total += (int) PNCP_Attacks::count( (int) $days, (string) $pair[0], (string) $pair[1] );
		}
		return $total;
	}

	/**
	 * Which point would lock a path seen in the attack report ("Lock this" buttons). Null when no point covers it,
	 * or the point that does is already locked.
	 *
	 * @param string $path Request path (a query string is allowed, e.g. "/?author=1").
	 * @return array{id:string, label:string}|null
	 */
	public static function recommend_for_path( $path ) {
		$path  = strtolower( rawurldecode( (string) $path ) );
		$query = (string) wp_parse_url( $path, PHP_URL_QUERY );
		$path  = (string) wp_parse_url( $path, PHP_URL_PATH );
		$core  = preg_quote( self::core_path(), '#' );
		$cont  = preg_quote( self::content_path(), '#' );
		$up    = preg_quote( self::uploads_path(), '#' );
		$rules = array(
			'#' . $core . 'xmlrpc\.php$#'                  => 'xmlrpc',
			'#' . $core . '(?:readme\.html|license\.txt|wp-config-sample\.php)$#' => 'core_files',
			'#' . $core . 'wp-admin/(?:install|upgrade|setup-config)\.php$#' => 'core_files',
			'#' . $core . 'wp-admin/(?:theme|plugin)-editor\.php$#' => 'file_editor',
			'#' . $core . 'wp-admin/authorize-application\.php$#' => 'app_passwords',
			'#' . $core . 'wp-admin(?:/|$)#'               => 'hide_admin',
			'#' . $core . 'wp-login\.php$#'                => 'login',
			'#/wp-json/wp/v2/users#'                       => 'user_enum',
			'#/author/[^/]+#'                              => 'author_archives',
			'#/wp-json/?$#'                                => 'rest_map',
			'#^' . $up . '/.*\.(?:php[0-9]?|phtml|phar)$#' => 'upload_php',
			'#' . $core . 'wp-includes/.+\.php$#'          => 'includes_php',
			'#^' . $cont . '/.+\.php$#'                    => 'content_php',
			'#(?:' . $core . 'wp-includes|^' . $cont . ')(?:/[^.?]*)?/$#' => 'dir_listing',
		);
		$id    = '';
		if ( preg_match( '/(?:^|&)author=\d/', $query ) || 0 === strpos( $query, 'rest_route=/wp/v2/users' ) ) {
			$id = 'user_enum';
		} else {
			foreach ( $rules as $regex => $point ) {
				if ( preg_match( $regex, $path ) ) {
					$id = $point;
					break;
				}
			}
		}
		if ( '' === $id || ( 'login' === $id && ! self::login_available() ) ) {
			return null;
		}
		if ( 'on' === self::status( $id )['state'] ) {
			return null;
		}
		$point = self::point( $id );
		return array(
			'id'    => $id,
			'label' => (string) $point['label'],
		);
	}

	/* ---------- Status ---------- */

	/**
	 * The status of a point: what ScrapeLock has on, combined with the last live check of the site.
	 *
	 * @param string $id   Point.
	 * @param bool   $live Use the live checks (from the cache; they are made when missing).
	 * @return array{state:string, note:string}
	 */
	public static function status( $id, $live = true ) {
		$point = self::point( $id );
		if ( ! $point ) {
			return array(
				'state' => 'na',
				'note'  => '',
			);
		}
		if ( 'login' === $id ) {
			return self::login_row_status();
		}
		$applied  = self::is_applied( $id );
		$edge     = isset( self::state()['edge'][ $id ] );
		$checks   = $live ? self::live() : array();
		$check    = isset( $checks[ $id ] ) ? $checks[ $id ] : null;
		$state    = $applied ? 'on' : 'off';
		$note     = '';
		$blocking = in_array( $id, array( 'xmlrpc', 'hide_admin', 'user_enum', 'author_archives', 'rest_map', 'upload_php' ), true );

		if ( 'file_editor' === $id && defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return array(
				'state' => 'on',
				'note'  => __( 'Already off in wp-config.php (DISALLOW_FILE_EDIT).', 'scrapelock' ),
			);
		}
		if ( $applied && ! $point['server'] && ! self::enabled() ) {
			return array(
				'state' => 'partial',
				'note'  => __( 'On, but ScrapeLock\'s protection is turned off, so it does nothing now.', 'scrapelock' ),
			);
		}
		if ( $applied && $blocking && PNCP_Options::monitoring() ) {
			return array(
				'state' => 'partial',
				'note'  => __( '“Monitor only” is on: such requests are logged as “Would block” and let through.', 'scrapelock' ),
			);
		}
		if ( $point['server'] ) {
			// Only the server can enforce it: the live check decides.
			if ( null !== $check && 'unknown' !== $check['state'] ) {
				$state = $check['state'];
				$note  = $check['note'];
				if ( $applied && 'on' !== $state ) {
					$state = 'partial';
					$note  = trim( $note . ' ' . __( 'Turned on here, but the server does not refuse it yet: add the server rules below.', 'scrapelock' ) );
				} elseif ( ! $applied && 'on' === $state ) {
					$note = trim( $note . ' ' . __( 'Already refused by your server or CDN.', 'scrapelock' ) );
				}
			} else {
				$state = $applied ? 'partial' : 'off';
				$note  = $applied ? __( 'Turned on here; whether the server enforces it could not be checked.', 'scrapelock' ) : '';
			}
		} elseif ( null !== $check && 'unknown' !== $check['state'] ) {
			if ( $applied && 'on' !== $check['state'] ) {
				$state = 'partial';
				$note  = $check['note'];
			} elseif ( ! $applied && 'on' === $check['state'] ) {
				$state = 'on';
				if ( 'hide_admin' === $id && class_exists( 'PNCP_Login' ) && PNCP_Login::hides_login() ) {
					$note = __( 'Done by the moved sign-in address (Login point).', 'scrapelock' );
				} else {
					$note = trim( $check['note'] . ' ' . __( 'Already done by your server, your CDN or another plugin.', 'scrapelock' ) );
				}
			} elseif ( '' !== $check['note'] ) {
				$note = $check['note'];
			}
		} elseif ( null !== $check && in_array( $id, array( 'headers', 'framing' ), true ) && '' !== $check['note'] ) {
			// 3.10: "could not be checked" and where it looked, instead of nothing.
			$note = $check['note'];
		}
		if ( 'xmlrpc' === $id && $applied && self::state()['xmlrpc_jetpack'] && 'on' === $state ) {
			$note = trim( $note . ' ' . __( 'Jetpack\'s servers are still let through, without pingbacks.', 'scrapelock' ) );
		}
		if ( $edge ) {
			$note = trim( $note . ' ' . __( 'Also locked at the Bunny CDN edge.', 'scrapelock' ) );
			if ( 'off' === $state ) {
				$state = 'partial';
			}
		}
		return array(
			'state' => $state,
			'note'  => $note,
		);
	}

	/**
	 * The catalog with status and evidence, for the card, WP-CLI and the Abilities API.
	 *
	 * @param bool $live Use the live checks.
	 * @return array<int, array<string, mixed>>
	 */
	public static function rows( $live = true ) {
		$rows = array();
		foreach ( self::points() as $id => $point ) {
			$status = self::status( $id, $live );
			$rows[] = array_merge(
				$point,
				array(
					'state'   => $status['state'],
					'note'    => $status['note'],
					'applied' => self::is_applied( $id ),
					'edge_on' => isset( self::state()['edge'][ $id ] ),
					'hits7'   => self::evidence( $id, 7 ),
					'hits30'  => self::evidence( $id, 30 ),
				)
			);
		}
		return $rows;
	}

	/* ---------- Login (component PNCP_Login) ---------- */

	/**
	 * Does the login protection (PNCP_Login) offer the hardening calls?
	 *
	 * @return bool
	 */
	private static function login_available() {
		return class_exists( 'PNCP_Login' ) && method_exists( 'PNCP_Login', 'hardening_status' ) && method_exists( 'PNCP_Login', 'hardening_apply' ) && method_exists( 'PNCP_Login', 'hardening_revert' );
	}

	/**
	 * The state of the login protection: on | partial | off | na.
	 *
	 * @return string
	 */
	private static function login_status() {
		if ( ! self::login_available() ) {
			return 'na';
		}
		$state = (string) PNCP_Login::hardening_status();
		return in_array( $state, array( 'on', 'partial', 'off' ), true ) ? $state : 'off';
	}

	/**
	 * The status row of the login point.
	 *
	 * @return array{state:string, note:string}
	 */
	private static function login_row_status() {
		$state = self::login_status();
		if ( 'na' === $state ) {
			return array(
				'state' => 'na',
				'note'  => __( 'Comes with ScrapeLock\'s login protection, which this version does not have yet.', 'scrapelock' ),
			);
		}
		$note = '';
		if ( 'partial' === $state ) {
			$note = __( 'Only part of it is on (the limit of failed logins or the login address).', 'scrapelock' );
		}
		if ( 'off' !== $state && ! self::enabled() ) {
			$state = 'partial';
			$note  = __( 'On, but ScrapeLock\'s protection is turned off, so it does nothing now.', 'scrapelock' );
		}
		return array(
			'state' => $state,
			'note'  => $note,
		);
	}

	/* ---------- Apply / revert ---------- */

	/**
	 * Why a change may not be made now, or null.
	 *
	 * @return WP_Error|null
	 */
	private static function refusal() {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked with Lockdown: unlock it to change the hardening.', 'scrapelock' ) );
		}
		return null;
	}

	/**
	 * Locks a point.
	 *
	 * @param string $id Point.
	 * @return true|WP_Error
	 */
	public static function apply( $id ) {
		return self::change( (string) $id, true );
	}

	/**
	 * Opens a point again.
	 *
	 * @param string $id Point.
	 * @return true|WP_Error
	 */
	public static function revert( $id ) {
		return self::change( (string) $id, false );
	}

	/**
	 * Applies or reverts a point and logs it.
	 *
	 * @param string $id Point.
	 * @param bool   $on Apply (true) or revert.
	 * @return true|WP_Error
	 */
	private static function change( $id, $on ) {
		$point = self::point( $id );
		if ( ! $point ) {
			return new WP_Error( 'pncp_unknown', __( 'Unknown point.', 'scrapelock' ) );
		}
		$refused = self::refusal();
		if ( $refused ) {
			return $refused;
		}
		if ( 'login' === $id ) {
			if ( ! self::login_available() ) {
				return new WP_Error( 'pncp_na', __( 'The login protection is not available in this version.', 'scrapelock' ) );
			}
			$result = $on ? PNCP_Login::hardening_apply() : PNCP_Login::hardening_revert();
			$result = is_wp_error( $result ) ? $result : true;
		} elseif ( '' !== $point['setting'] ) {
			$result = self::set_setting( $point['setting'], $on ? 1 : 0 );
		} else {
			$state = self::state( true );
			$was   = $state;
			if ( $on ) {
				$state['points'][ $id ] = time();
			} else {
				unset( $state['points'][ $id ] );
			}
			self::save_state( $state );
			$result = true;
			// Rules already written into .htaccess follow the change (with the self-test and rollback). When the
			// file was put back, the point goes back too, so what is shown is what the server does.
			if ( ( $point['server'] || 'xmlrpc' === $id ) && self::htaccess_has_block() ) {
				$written = self::write_htaccess();
				if ( is_wp_error( $written ) ) {
					$result = $written;
					self::save_state( $was );
				}
			}
		}
		delete_transient( self::LIVE );
		self::note( $on ? 'apply' : 'revert', $id, is_wp_error( $result ) ? $result->get_error_message() : '' );
		return $result;
	}

	/**
	 * Changes one ScrapeLock setting through its normal sanitize path.
	 *
	 * @param string $key   Setting.
	 * @param int    $value Value.
	 * @return true|WP_Error
	 */
	private static function set_setting( $key, $value ) {
		$stored = PNCP_Options::stored();
		if ( ! array_key_exists( $key, $stored ) ) {
			return new WP_Error( 'pncp_setting', __( 'This setting does not exist in this version.', 'scrapelock' ) );
		}
		$stored[ $key ] = $value;
		// In wp-admin the option is registered with PNCP_Options::sanitize() as its sanitize callback; elsewhere
		// (WP-CLI, the Abilities API) it is sanitized here, so the value goes through the same checks either way.
		if ( ! has_filter( 'sanitize_option_' . PNCP_OPTION ) ) {
			$stored = PNCP_Options::sanitize( $stored );
		}
		update_option( PNCP_OPTION, $stored );
		PNCP_Options::flush();
		if ( (int) ! empty( PNCP_Options::stored()[ $key ] ) !== (int) $value ) {
			return new WP_Error( 'pncp_setting', __( 'The setting could not be changed.', 'scrapelock' ) );
		}
		return true;
	}

	/**
	 * Locks every low-risk point that is not locked yet.
	 *
	 * @return array<string, true|WP_Error> Point => result.
	 */
	public static function apply_low_risk() {
		$refused = self::refusal();
		if ( $refused ) {
			return array( '' => $refused );
		}
		$out = array();
		foreach ( self::points() as $id => $point ) {
			if ( 'low' !== $point['risk'] || self::is_applied( $id ) || 'on' === self::status( $id, false )['state'] ) {
				continue;
			}
			$out[ $id ] = self::apply( $id );
		}
		return $out;
	}

	/**
	 * Lets Jetpack's servers through while XML-RPC is locked (without pingbacks), or not.
	 *
	 * @param bool $allow Allow.
	 * @return true|WP_Error
	 */
	public static function set_jetpack( $allow ) {
		$refused = self::refusal();
		if ( $refused ) {
			return $refused;
		}
		$state                   = self::state( true );
		$state['xmlrpc_jetpack'] = $allow ? 1 : 0;
		self::save_state( $state );
		if ( self::htaccess_has_block() ) {
			$written = self::write_htaccess(); // The server rule for xmlrpc.php is left out with Jetpack allowed.
			if ( is_wp_error( $written ) ) {
				return $written;
			}
		}
		self::note( $allow ? 'jetpack_on' : 'jetpack_off', 'xmlrpc' );
		return true;
	}

	/**
	 * Adds an entry to the history.
	 *
	 * @param string $action What was done.
	 * @param string $id     Point ('' = none).
	 * @param string $error  Error message ('' = it worked).
	 */
	private static function note( $action, $id, $error = '' ) {
		$history = get_option( self::HISTORY, array() );
		$history = is_array( $history ) ? $history : array();
		$user    = wp_get_current_user();
		array_unshift(
			$history,
			array(
				'time'   => time(),
				'action' => (string) $action,
				'id'     => (string) $id,
				'user'   => $user && $user->exists() ? (string) $user->user_login : ( defined( 'WP_CLI' ) && WP_CLI ? 'WP-CLI' : '' ),
				'error'  => (string) $error,
			)
		);
		update_option( self::HISTORY, array_slice( $history, 0, self::HISTORY_MAX ), false );
	}

	/**
	 * The history, newest first.
	 *
	 * @param int $limit How many.
	 * @return array<int, array{time:int, action:string, id:string, user:string, error:string}>
	 */
	public static function history( $limit = 10 ) {
		$history = get_option( self::HISTORY, array() );
		return array_slice( is_array( $history ) ? $history : array(), 0, max( 1, (int) $limit ) );
	}

	/* ---------- Enforcement (WordPress) ---------- */

	/**
	 * Is the request one that a refusing point must leave alone: a verified search engine?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private static function spared( $ip ) {
		return '' !== $ip && class_exists( 'PNCP_Bots' ) && PNCP_Bots::is_official_crawler_ip( $ip );
	}

	/**
	 * Refuses a request (or, in "Monitor only", logs that it would have and lets it through).
	 *
	 * @param string $reason Log reason.
	 * @param int    $code   Status code.
	 * @return bool Whether the request is refused (the caller ends it).
	 */
	private static function refuse( $reason, $code ) {
		$ip = PNCP_Ip::client_ip();
		// The server itself (the live checks of this card, Site Health) gets the real answer, unlogged and never
		// counted toward a ban.
		$local = '' === $ip || PNCP_Ip::is_local( $ip );
		if ( PNCP_Options::monitoring() ) {
			if ( ! $local ) {
				PNCP_Log::add( $reason, PNCP_Log::MONITOR_CODE, $ip );
			}
			return false;
		}
		if ( ! $local ) {
			PNCP_Log::add( $reason, $code, $ip );
			// Only XML-RPC counts toward a temporary block: people do not use it by hand, while a signed-out
			// editor may open an old wp-admin bookmark a few times.
			if ( 'harden_xmlrpc' === $reason ) {
				PNCP_Log::strike( $ip, $reason );
			}
		}
		return true;
	}

	/**
	 * Jetpack's own servers (documented by Jetpack; filter pncp_harden_jetpack_ips).
	 *
	 * @return string[]
	 */
	public static function jetpack_ranges() {
		$ranges = array( '122.248.245.244/32', '54.217.201.243/32', '54.232.116.4/32', '192.0.80.0/20', '192.0.96.0/20', '192.0.112.0/20', '195.234.108.0/22' );
		/**
		 * Filters the addresses let through to XML-RPC when "Allow Jetpack" is on.
		 *
		 * @param string[] $ranges IPs and CIDR ranges.
		 */
		return array_values( array_filter( array_map( 'strval', (array) apply_filters( 'pncp_harden_jetpack_ips', $ranges ) ) ) );
	}

	/**
	 * Is the request from Jetpack's servers, while they are allowed?
	 *
	 * @return bool
	 */
	private static function jetpack_request() {
		return self::state()['xmlrpc_jetpack'] && PNCP_Ip::in_any( PNCP_Ip::client_ip(), self::jetpack_ranges() );
	}

	/**
	 * XML-RPC: every request is refused with 403 (Jetpack's servers pass when allowed).
	 */
	public static function xmlrpc_gate() {
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST || ! self::enabled() ) {
			return;
		}
		$ip = PNCP_Ip::client_ip();
		if ( self::jetpack_request() || self::spared( $ip ) ) {
			return;
		}
		if ( ! self::refuse( 'harden_xmlrpc', 403 ) ) {
			return;
		}
		self::plain_response( 403 );
	}

	/**
	 * Without XML-RPC methods (and, for Jetpack, without pingbacks), whatever gets past the gate.
	 *
	 * @param array<string, mixed> $methods Methods.
	 * @return array<string, mixed>
	 */
	public static function xmlrpc_methods( $methods ) {
		if ( ! self::enabled() || ! is_array( $methods ) ) {
			return $methods;
		}
		if ( self::jetpack_request() ) {
			unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
			return $methods;
		}
		return PNCP_Options::monitoring() ? $methods : array();
	}

	/**
	 * No X-Pingback header pointing to xmlrpc.php.
	 *
	 * @param array<string, string> $headers Headers.
	 * @return array<string, string>
	 */
	public static function no_pingback_header( $headers ) {
		if ( is_array( $headers ) && self::enabled() ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/**
	 * No RSD link (it points to xmlrpc.php) in the page head.
	 */
	public static function no_rsd_link() {
		if ( self::enabled() ) {
			remove_action( 'wp_head', 'rsd_link' );
		}
	}

	/**
	 * Hides wp-admin from visitors who are not signed in: "page not found" instead of the redirect to the login page.
	 */
	public static function admin_gate() {
		global $pagenow;
		if ( ! is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || is_user_logged_in() || ! self::enabled() ) {
			return;
		}
		$open = (array) apply_filters( 'pncp_harden_admin_open', array( 'admin-ajax.php', 'admin-post.php', 'load-styles.php', 'load-scripts.php' ) );
		if ( in_array( (string) $pagenow, $open, true ) ) {
			return;
		}
		if ( self::spared( PNCP_Ip::client_ip() ) || ! self::refuse( 'harden_admin', 404 ) ) {
			return;
		}
		self::plain_response( 404 );
	}

	/**
	 * /admin, /dashboard and /login lead to the login page for visitors: not while wp-admin is hidden.
	 */
	public static function no_admin_shortcuts() {
		if ( ! is_user_logged_in() && self::enabled() && ! PNCP_Options::monitoring() ) {
			remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
		}
	}

	/**
	 * Ends the request with a bare status page that does not say which software runs the site.
	 *
	 * @param int $code 403 or 404.
	 */
	private static function plain_response( $code ) {
		$title = 404 === $code ? 'Not Found' : 'Forbidden';
		$text  = 404 === $code ? 'The requested URL was not found on this server.' : 'You don\'t have permission to access this resource.';
		if ( ! headers_sent() ) {
			status_header( $code );
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
			header_remove( 'X-Pingback' );
			header_remove( 'X-Powered-By' );
		}
		echo '<!DOCTYPE html><html><head><title>' . esc_html( $code . ' ' . $title ) . '</title></head><body><h1>' . esc_html( $title ) . '</h1><p>' . esc_html( $text ) . '</p></body></html>';
		exit;
	}

	/**
	 * The theme and plugin file editors are gone for everyone.
	 *
	 * @param string[] $caps Primitive capabilities.
	 * @param string   $cap  Meta capability.
	 * @return string[]
	 */
	public static function no_file_editor( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_themes', 'edit_plugins', 'edit_files' ), true ) && self::enabled() ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	/**
	 * Application passwords only for administrators.
	 *
	 * @param bool    $available Available.
	 * @param WP_User $user      User.
	 * @return bool
	 */
	public static function app_passwords_for( $available, $user ) {
		if ( ! $available || ! self::enabled() || ! $user instanceof WP_User ) {
			return $available;
		}
		return user_can( $user, 'manage_options' ) || ( is_multisite() && is_super_admin( $user->ID ) );
	}

	/**
	 * Author archives answer "page not found" to visitors who are not signed in. The same answer for everyone,
	 * search engines included: a page that is gone, not a block (anything else would show crawlers a page visitors
	 * cannot open).
	 */
	public static function author_gate() {
		global $wp_query;
		if ( ! is_author() || is_user_logged_in() || ! self::enabled() ) {
			return;
		}
		if ( ! self::refuse( 'harden_author', 404 ) ) {
			return;
		}
		remove_action( 'template_redirect', 'redirect_canonical' );
		if ( $wp_query instanceof WP_Query ) {
			$wp_query->set_404();
		}
		status_header( 404 );
		nocache_headers();
	}

	/**
	 * Links to author archives point to the home page for visitors.
	 *
	 * @param string $link Link.
	 * @return string
	 */
	public static function author_link( $link ) {
		if ( is_admin() || is_user_logged_in() || ! self::enabled() || PNCP_Options::monitoring() ) {
			return $link;
		}
		return home_url( '/' );
	}

	/**
	 * The security headers this point sends (filter pncp_harden_headers).
	 *
	 * @return array<string, string>
	 */
	public static function header_values() {
		$headers = array(
			'X-Content-Type-Options' => 'nosniff',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			'Permissions-Policy'     => 'camera=(), microphone=(), geolocation=(), browsing-topics=()',
		);
		/**
		 * Filters the security headers of the "Security headers" point. An empty value leaves that header out.
		 *
		 * @param array<string, string> $headers Header => value.
		 */
		$headers = apply_filters( 'pncp_harden_headers', $headers );
		return array_filter( array_map( 'strval', is_array( $headers ) ? $headers : array() ), 'strlen' );
	}

	/**
	 * Sends the security headers, unless the server or another plugin already set them.
	 */
	public static function security_headers() {
		if ( headers_sent() || ! self::enabled() ) {
			return;
		}
		$sent = array();
		foreach ( headers_list() as $line ) {
			$sent[ strtolower( trim( strtok( $line, ':' ) ) ) ] = true;
		}
		foreach ( self::header_values() as $name => $value ) {
			if ( ! isset( $sent[ strtolower( $name ) ] ) && preg_match( '/^[A-Za-z0-9-]+$/', $name ) ) {
				header( $name . ': ' . str_replace( array( "\r", "\n" ), '', $value ) );
			}
		}
	}

	/* ---------- Live checks ---------- */

	/**
	 * Asks the site itself whether each point is really locked: the results of the last check (6 hours), or a new
	 * check when there is none. Only wp-admin, WP-CLI and Site Health call it.
	 *
	 * @param bool $fresh Check again now.
	 * @return array<string, array{state:string, note:string}>
	 */
	public static function live( $fresh = false ) {
		if ( ! $fresh ) {
			$cached = get_transient( self::LIVE );
			if ( is_array( $cached ) ) {
				return $cached;
			}
			if ( ! is_admin() && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
				return array(); // Never on a visitor's request.
			}
		}
		$out = self::run_live_checks();
		set_transient( self::LIVE, $out, 6 * HOUR_IN_SECONDS );
		return $out;
	}

	/**
	 * One request to this site, as a visitor who is not signed in.
	 *
	 * @param string $url    Address.
	 * @param string $method GET, HEAD or POST.
	 * @param string $body   POST body.
	 * @return array{code:int, body:string, headers:array<string,string>, location:string}|WP_Error
	 */
	private static function fetch( $url, $method = 'GET', $body = '' ) {
		$args = array(
			'method'              => $method,
			'timeout'             => 4,
			'redirection'         => 0,
			'sslverify'           => (bool) apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter.
			'limit_response_size' => 65536,
			'user-agent'          => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 ScrapeLock-Selftest',
			'headers'             => array(
				'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
				'Accept-Language' => 'en-US,en;q=0.9',
				'Cache-Control'   => 'no-cache',
			),
		);
		if ( 'POST' === $method ) {
			$args['body']                    = $body;
			$args['headers']['Content-Type'] = 'text/xml';
		}
		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$headers = array();
		$raw     = wp_remote_retrieve_headers( $response );
		$raw     = is_object( $raw ) && method_exists( $raw, 'getAll' ) ? $raw->getAll() : (array) $raw;
		foreach ( $raw as $name => $value ) {
			$headers[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
		}
		return array(
			'code'     => (int) wp_remote_retrieve_response_code( $response ),
			'body'     => (string) wp_remote_retrieve_body( $response ),
			'headers'  => $headers,
			'location' => isset( $headers['location'] ) ? $headers['location'] : '',
		);
	}

	/**
	 * 3.10: the home page as a visitor gets it: GET (not HEAD), following up to five redirects (http to https,
	 * www, trailing slash) to the final answer, instead of reading the headers of the first redirect.
	 *
	 * @return array{response:array<string, mixed>|WP_Error, url:string, chain:array<int, array{url:string, code:int}>}
	 */
	private static function fetch_public_home() {
		$url   = home_url( '/' );
		$chain = array();
		for ( $hop = 0; $hop <= 5; $hop++ ) {
			$r = self::fetch( $url );
			if ( is_wp_error( $r ) ) {
				break;
			}
			$chain[] = array(
				'url'  => $url,
				'code' => (int) $r['code'],
			);
			if ( ! in_array( (int) $r['code'], array( 301, 302, 303, 307, 308 ), true ) || '' === trim( $r['location'] ) ) {
				break;
			}
			$next = WP_Http::make_absolute_url( trim( $r['location'] ), $url );
			if ( ! preg_match( '#^https?://#i', $next ) ) {
				$r = new WP_Error( 'pncp_redirect', __( 'the home page redirects to an address that is not a web address', 'scrapelock' ) );
				break;
			}
			$url = $next;
			if ( 5 === $hop ) {
				$r = new WP_Error( 'pncp_redirects', __( 'too many redirects', 'scrapelock' ) );
			}
		}
		return array(
			'response' => $r,
			'url'      => $url,
			'chain'    => $chain,
		);
	}

	/**
	 * 3.10: the CDN that answered, from its response headers ('' when none is seen).
	 *
	 * @param array<string, string> $headers Lowercase response headers.
	 * @return string
	 */
	private static function cdn_in_answer( $headers ) {
		$server = isset( $headers['server'] ) ? strtolower( $headers['server'] ) : '';
		if ( false !== strpos( $server, 'bunnycdn' ) || isset( $headers['cdn-pullzone'] ) || isset( $headers['cdn-requestid'] ) || isset( $headers['cdn-uid'] ) ) {
			return 'Bunny CDN';
		}
		if ( isset( $headers['cf-ray'] ) || false !== strpos( $server, 'cloudflare' ) ) {
			return 'Cloudflare';
		}
		return '';
	}

	/**
	 * 3.10: the CDN this site is set up with in ScrapeLock ("Blocking at the CDN" or the Bunny card), or ''.
	 *
	 * @return string
	 */
	private static function cdn_configured() {
		if ( ! class_exists( 'PNCP_Edge' ) ) {
			return '';
		}
		if ( PNCP_Edge::bunny_in_use() ) {
			return 'Bunny CDN';
		}
		return 'cloudflare' === PNCP_Edge::config()['provider'] ? 'Cloudflare' : '';
	}

	/**
	 * 3.10: the "Security headers" and "Framing" checks, on the final answer of fetch_public_home(). Says which
	 * address and status it read, and "could not be checked" (never "missing") when it cannot see the answer that
	 * visitors get: an error, a final answer that is not a page, or a CDN set up here that the answer did not pass.
	 *
	 * @param array<string, mixed> $public Result of fetch_public_home().
	 * @return array{headers:array{state:string, note:string}, framing:array{state:string, note:string}}
	 */
	private static function check_home_headers( $public ) {
		$home  = $public['response'];
		$chain = (array) $public['chain'];
		$steps = array();
		foreach ( $chain as $step ) {
			$steps[] = $step['url'] . ' (HTTP ' . (int) $step['code'] . ')';
		}
		/* translators: %s: addresses with their HTTP status, joined by arrows */
		$where   = $steps ? sprintf( __( 'Checked: %s.', 'scrapelock' ), implode( ' → ', $steps ) ) : '';
		$unknown = static function ( $why ) use ( $where ) {
			$r = array(
				'state' => 'unknown',
				'note'  => trim( $why . ' ' . $where ),
			);
			return array(
				'headers' => $r,
				'framing' => $r,
			);
		};
		if ( is_wp_error( $home ) ) {
			/* translators: %s: error message */
			return $unknown( sprintf( __( 'Could not be checked: the site could not read its public home page (%s).', 'scrapelock' ), $home->get_error_message() ) );
		}
		$code = (int) $home['code'];
		if ( $code < 200 || $code > 299 ) {
			/* translators: %d: HTTP status code */
			return $unknown( sprintf( __( 'Could not be checked: the home page answered HTTP %d to the site itself, not the page visitors get.', 'scrapelock' ), $code ) );
		}
		$headers = (array) $home['headers'];
		$has     = static function ( $name ) use ( $headers ) {
			$name = strtolower( $name );
			return isset( $headers[ $name ] ) && '' !== trim( (string) $headers[ $name ] );
		};
		$missing = array();
		$want    = self::header_values();
		foreach ( array_keys( $want ) as $name ) {
			if ( ! $has( $name ) ) {
				$missing[] = $name;
			}
		}
		$frame    = $has( 'x-frame-options' ) || ( $has( 'content-security-policy' ) && false !== stripos( $headers['content-security-policy'], 'frame-ancestors' ) );
		$seen     = self::cdn_in_answer( $headers );
		$expected = self::cdn_configured();
		if ( '' !== $seen ) {
			/* translators: %s: CDN name */
			$where = trim( $where . ' ' . sprintf( __( 'The answer came through %s: these are the headers visitors get.', 'scrapelock' ), $seen ) );
		}
		// The site reached its own server directly (hosts file, internal DNS), not the CDN in front of it: what the
		// CDN adds cannot be seen, so a header that is not there is not "missing".
		$blind = '' === $seen && '' !== $expected;
		/* translators: 1: CDN name, 2: header names */
		$blind_note = __( 'Could not be checked: the answer came straight from your server, not through %1$s, so headers that %1$s adds cannot be seen from here. Not in this answer: %2$s.', 'scrapelock' );
		if ( ! $missing ) {
			$headers_out = array(
				'state' => 'on',
				'note'  => $where,
			);
		} elseif ( $blind ) {
			$headers_out = array(
				'state' => 'unknown',
				'note'  => trim( sprintf( $blind_note, $expected, implode( ', ', $missing ) ) . ' ' . $where ),
			);
		} else {
			$headers_out = array(
				'state' => count( $missing ) < count( $want ) ? 'partial' : 'off',
				/* translators: %s: header names */
				'note'  => trim( sprintf( __( 'Missing on the home page: %s.', 'scrapelock' ), implode( ', ', $missing ) ) . ' ' . $where ),
			);
		}
		if ( ! $frame && $blind ) {
			$framing_out = array(
				'state' => 'unknown',
				'note'  => trim( sprintf( $blind_note, $expected, 'X-Frame-Options' ) . ' ' . $where ),
			);
		} else {
			$framing_out = array(
				'state' => $frame ? 'on' : 'off',
				'note'  => '',
			);
		}
		return array(
			'headers' => $headers_out,
			'framing' => $framing_out,
		);
	}

	/**
	 * Is an answer a refusal (403, 404, 405, 410 or 444)?
	 *
	 * @param array<string, mixed> $r Answer of fetch().
	 * @return bool
	 */
	private static function refused( $r ) {
		return in_array( (int) $r['code'], array( 401, 403, 404, 405, 410, 444 ), true );
	}

	/**
	 * Makes the live checks.
	 *
	 * @return array<string, array{state:string, note:string}>
	 */
	private static function run_live_checks() {
		$out     = array();
		$unknown = static function ( $why ) {
			return array(
				'state' => 'unknown',
				'note'  => $why,
			);
		};
		$public  = self::fetch_public_home();
		$home    = $public['response'];
		if ( is_wp_error( $home ) && ! $public['chain'] ) {
			/* translators: %s: error message */
			$why = sprintf( __( 'Could not check: the site could not reach itself (%s).', 'scrapelock' ), $home->get_error_message() );
			foreach ( array_keys( self::points() ) as $id ) {
				$out[ $id ] = $unknown( $why );
			}
			return $out;
		}

		// Security headers and framing: the headers of the public home page (3.10: after its redirects, GET).
		$heads          = self::check_home_headers( $public );
		$out['headers'] = $heads['headers'];
		$out['framing'] = $heads['framing'];
		$core            = self::core_path();
		$site            = untrailingslashit( site_url() );
		$out['xmlrpc']   = self::check_xmlrpc( $site . '/xmlrpc.php' );
		$out['pingback'] = self::check_pingback( $site . '/xmlrpc.php' );

		// wp-admin: a redirect to the login page means it is open.
		$admin             = self::fetch( $site . '/wp-admin/' );
		$out['hide_admin'] = is_wp_error( $admin ) ? $unknown( $admin->get_error_message() ) : array(
			'state' => self::refused( $admin ) ? 'on' : 'off',
			'note'  => '',
		);

		// WordPress's own files: each one.
		$open  = array();
		$files = array( 'readme.html', 'license.txt', 'wp-config-sample.php', 'wp-admin/install.php', 'wp-admin/setup-config.php', 'wp-admin/upgrade.php' );
		foreach ( $files as $file ) {
			$r = self::fetch( $site . '/' . $file, 'GET' );
			if ( ! is_wp_error( $r ) && ! self::refused( $r ) ) {
				$open[] = $file;
			}
		}
		$out['core_files'] = array(
			'state' => ! $open ? 'on' : ( count( $open ) < count( $files ) ? 'partial' : 'off' ),
			/* translators: %s: file names */
			'note'  => $open ? sprintf( __( 'Still open: %s.', 'scrapelock' ), implode( ', ', $open ) ) : '',
		);

		// PHP in wp-includes and wp-content: two harmless files (they print nothing).
		$r                   = self::fetch( $site . '/wp-includes/version.php' );
		$out['includes_php'] = is_wp_error( $r ) ? $unknown( $r->get_error_message() ) : array(
			'state' => self::refused( $r ) ? 'on' : 'off',
			'note'  => '',
		);
		$r                   = self::fetch( content_url( '/index.php' ) );
		$out['content_php']  = is_wp_error( $r ) ? $unknown( $r->get_error_message() ) : array(
			'state' => self::refused( $r ) ? 'on' : 'off',
			'note'  => '',
		);

		// Directory listing: wp-includes has no index file.
		$r                  = self::fetch( $site . '/wp-includes/' );
		$out['dir_listing'] = is_wp_error( $r ) ? $unknown( $r->get_error_message() ) : array(
			'state' => ( 200 === $r['code'] && preg_match( '/<title>\s*Index of|Directory listing for/i', $r['body'] ) ) ? 'off' : 'on',
			'note'  => '',
		);

		// Usernames: ?author=1 and the REST list.
		$r     = self::fetch( home_url( '/?author=1' ) );
		$users = self::fetch( rest_url( 'wp/v2/users' ) );
		if ( is_wp_error( $r ) || is_wp_error( $users ) ) {
			$out['user_enum'] = $unknown( '' );
		} else {
			$author_open = in_array( $r['code'], array( 301, 302, 307, 308 ), true ) && false !== strpos( $r['location'], 'author' );
			$list        = json_decode( $users['body'], true );
			$list_open   = 200 === $users['code'] && is_array( $list ) && ! empty( $list[0]['slug'] );
			$found       = array();
			if ( $author_open ) {
				$found[] = '?author=1';
			}
			if ( $list_open ) {
				$found[] = '/wp-json/wp/v2/users';
			}
			$out['user_enum'] = array(
				'state' => ! $found ? 'on' : ( count( $found ) < 2 ? 'partial' : 'off' ),
				/* translators: %s: addresses */
				'note'  => $found ? sprintf( __( 'Still shows usernames: %s.', 'scrapelock' ), implode( ', ', $found ) ) : '',
			);
		}

		// The REST map.
		$r               = self::fetch( rest_url() );
		$map             = is_wp_error( $r ) ? null : json_decode( $r['body'], true );
		$out['rest_map'] = is_wp_error( $r ) ? $unknown( $r->get_error_message() ) : array(
			'state' => ( is_array( $map ) && ! empty( $map['routes'] ) ) || preg_match( '/"namespaces"\s*:\s*\[\s*"/', $r['body'] ) ? 'off' : 'on',
			'note'  => '',
		);

		$out['upload_php'] = self::check_upload_php();
		return $out;
	}

	/**
	 * XML-RPC: does system.listMethods answer?
	 *
	 * @param string $url xmlrpc.php.
	 * @return array{state:string, note:string}
	 */
	private static function check_xmlrpc( $url ) {
		$r = self::fetch( $url, 'POST', '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' );
		if ( is_wp_error( $r ) ) {
			return array(
				'state' => 'unknown',
				'note'  => $r->get_error_message(),
			);
		}
		$open = 200 === $r['code'] && false !== strpos( $r['body'], '<methodResponse' ) && false !== strpos( $r['body'], 'system.' );
		return array(
			'state' => $open ? 'off' : 'on',
			'note'  => '',
		);
	}

	/**
	 * Pingbacks: is pingback.ping among the methods (or XML-RPC refused altogether)?
	 *
	 * @param string $url xmlrpc.php.
	 * @return array{state:string, note:string}
	 */
	private static function check_pingback( $url ) {
		$r = self::fetch( $url, 'POST', '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' );
		if ( is_wp_error( $r ) ) {
			return array(
				'state' => 'unknown',
				'note'  => $r->get_error_message(),
			);
		}
		return array(
			'state' => false !== strpos( $r['body'], 'pingback.ping' ) ? 'off' : 'on',
			'note'  => '',
		);
	}

	/**
	 * PHP in uploads: a test file is put there for a moment and opened. Only when the folder is writable; the file
	 * prints a fixed word and is deleted at once.
	 *
	 * @return array{state:string, note:string}
	 */
	private static function check_upload_php() {
		$dir = wp_get_upload_dir();
		if ( ! empty( $dir['error'] ) || ! wp_is_writable( $dir['basedir'] ) ) {
			return array(
				'state' => 'unknown',
				'note'  => __( 'Could not check: the uploads folder is not writable.', 'scrapelock' ),
			);
		}
		$name = 'pncp-selftest-' . wp_generate_password( 12, false ) . '.php';
		$file = trailingslashit( $dir['basedir'] ) . $name;
		// The file only prints a fixed word: nothing it receives is used.
		if ( false === file_put_contents( $file, "<?php echo 'pncp' . '-ran';\n" ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- A test file, deleted right after.
			return array(
				'state' => 'unknown',
				'note'  => '',
			);
		}
		$r = self::fetch( trailingslashit( $dir['baseurl'] ) . $name );
		wp_delete_file( $file );
		if ( is_wp_error( $r ) ) {
			return array(
				'state' => 'unknown',
				'note'  => $r->get_error_message(),
			);
		}
		$ran = false !== strpos( $r['body'], 'pncp-ran' );
		return array(
			'state' => $ran ? 'off' : 'on',
			'note'  => $ran ? __( 'A PHP file in uploads still runs: on Nginx, add the rule from the “Server rules” tab.', 'scrapelock' ) : '',
		);
	}

	/* ---------- Server rules ---------- */

	/**
	 * The server points that are applied, and XML-RPC when its server rule applies (not with Jetpack allowed).
	 *
	 * @return string[]
	 */
	private static function server_points() {
		$on  = self::state()['points'];
		$ids = array();
		foreach ( array( 'xmlrpc', 'core_files', 'includes_php', 'content_php', 'dir_listing' ) as $id ) {
			if ( isset( $on[ $id ] ) && ( 'xmlrpc' !== $id || ! self::state()['xmlrpc_jetpack'] ) ) {
				$ids[] = $id;
			}
		}
		return $ids;
	}

	/**
	 * PHP files under wp-content that stay open with "PHP files in wp-content" (paths relative to wp-content).
	 *
	 * @return string[]
	 */
	private static function php_allow() {
		/**
		 * Filters the PHP files under wp-content that stay open when "PHP files in wp-content, opened directly"
		 * is locked, as paths relative to wp-content (e.g. "plugins/my-plugin/callback.php").
		 *
		 * @param string[] $files Paths.
		 */
		$files = (array) apply_filters( 'pncp_harden_php_allow', array() );
		$out   = array();
		foreach ( $files as $file ) {
			$file = ltrim( str_replace( '\\', '/', (string) $file ), '/' );
			if ( '' !== $file && preg_match( '#^[A-Za-z0-9._/-]+\.php$#', $file ) && false === strpos( $file, '..' ) ) {
				$out[] = $file;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * A path relative to the folder of the site's .htaccess (where the home page is), for RewriteRule.
	 *
	 * @param string $path Path within the site's address.
	 * @return string
	 */
	private static function rel( $path ) {
		$home = self::home_path();
		$path = (string) $path;
		return 0 === strpos( $path, $home ) ? substr( $path, strlen( $home ) ) : ltrim( $path, '/' );
	}

	/**
	 * Apache rules for the applied server points (without the markers), or '' when there are none.
	 *
	 * @param string[]|null $ids Points (null = the applied ones).
	 * @return string
	 */
	public static function apache_rules( $ids = null ) {
		$ids     = null === $ids ? self::server_points() : $ids;
		$core    = preg_quote( self::rel( self::core_path() ), '#' );
		$content = preg_quote( self::rel( self::content_path() . '/' ), '#' );
		$lines   = array();
		if ( in_array( 'dir_listing', $ids, true ) ) {
			$lines[] = '# No directory listing.';
			$lines[] = 'Options -Indexes';
		}
		$rewrite = array();
		if ( in_array( 'xmlrpc', $ids, true ) ) {
			$rewrite[] = '# XML-RPC: refused before PHP.';
			$rewrite[] = 'RewriteRule ^' . $core . 'xmlrpc\.php$ - [F,NC,L]';
		}
		if ( in_array( 'core_files', $ids, true ) ) {
			$rewrite[] = '# WordPress\'s own files: page not found. upgrade.php stays open for signed-in users (database updates).';
			$rewrite[] = 'RewriteRule ^' . $core . '(?:readme\.html|license\.txt|wp-config-sample\.php|wp-admin/install\.php|wp-admin/setup-config\.php)$ - [R=404,NC,L]';
			$rewrite[] = 'RewriteCond %{HTTP_COOKIE} !wordpress_logged_in_';
			$rewrite[] = 'RewriteRule ^' . $core . 'wp-admin/upgrade\.php$ - [R=404,NC,L]';
		}
		if ( in_array( 'includes_php', $ids, true ) ) {
			$rewrite[] = '# PHP files in wp-includes are never opened directly (the classic editor\'s wp-tinymce.php and ms-files.php stay open).';
			$rewrite[] = 'RewriteRule ^' . $core . 'wp-includes/(?!js/tinymce/wp-tinymce\.php$|ms-files\.php$).+\.php$ - [F,NC,L]';
		}
		if ( in_array( 'content_php', $ids, true ) ) {
			$rewrite[] = '# PHP files in wp-content are never opened directly.';
			foreach ( self::php_allow() as $file ) {
				$rewrite[] = 'RewriteCond %{REQUEST_URI} !' . preg_quote( '/' . $file, '#' ) . '$';
			}
			$rewrite[] = 'RewriteRule ^' . $content . '.+\.(?:php[0-9]?|phtml|phar)$ - [F,NC,L]';
		}
		if ( $rewrite ) {
			$lines[] = '<IfModule mod_rewrite.c>';
			$lines[] = 'RewriteEngine On';
			$lines   = array_merge( $lines, $rewrite );
			$lines[] = '</IfModule>';
		}
		return $lines ? implode( "\n", $lines ) . "\n" : '';
	}

	/**
	 * Nginx rules for the applied server points (inside the site's server { }, before the location for PHP).
	 *
	 * @param string[]|null $ids Points (null = the applied ones).
	 * @return string
	 */
	public static function nginx_rules( $ids = null ) {
		$ids     = null === $ids ? self::server_points() : $ids;
		$core    = self::core_path();
		$content = self::content_path() . '/';
		$quote   = static function ( $path ) {
			return preg_quote( $path, '#' );
		};
		$lines   = array();
		if ( in_array( 'dir_listing', $ids, true ) ) {
			$lines[] = '# No directory listing.';
			$lines[] = 'autoindex off;';
		}
		if ( in_array( 'xmlrpc', $ids, true ) ) {
			$lines[] = '# XML-RPC: refused before PHP.';
			$lines[] = 'location = ' . $core . 'xmlrpc.php { return 403; }';
		}
		if ( in_array( 'core_files', $ids, true ) ) {
			$lines[] = '# WordPress\'s own files: page not found. (After a WordPress update that needs it, run “wp core update-db”.)';
			$lines[] = 'location ~* ^' . $quote( $core ) . '(?:readme\.html|license\.txt|wp-config-sample\.php|wp-admin/(?:install|setup-config|upgrade)\.php)$ { return 404; }';
		}
		if ( in_array( 'includes_php', $ids, true ) ) {
			$lines[] = '# PHP files in wp-includes are never opened directly (wp-tinymce.php and ms-files.php stay open).';
			$lines[] = 'location ~* ^' . $quote( $core ) . 'wp-includes/(?!js/tinymce/wp-tinymce\.php$|ms-files\.php$).+\.php$ { return 403; }';
		}
		if ( in_array( 'content_php', $ids, true ) ) {
			$allow   = self::php_allow();
			$lines[] = '# PHP files in wp-content are never opened directly.';
			$except  = $allow ? '(?!' . implode( '$|', array_map( $quote, $allow ) ) . '$)' : '';
			$lines[] = 'location ~* ^' . $quote( $content ) . $except . '.+\.(?:php[0-9]?|phtml|phar)$ { return 403; }';
		}
		if ( ! $lines ) {
			return '';
		}
		array_unshift( $lines, '# BEGIN ' . self::MARKER, '# Inside the site\'s server { }, before the location ~ \.php$ block. Then nginx -t and reload.' );
		$lines[] = '# END ' . self::MARKER;
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Is the site served by Apache (or LiteSpeed), where .htaccess is read? Filter pncp_harden_is_apache.
	 *
	 * @return bool
	 */
	public static function is_apache() {
		global $is_apache;
		return (bool) apply_filters( 'pncp_harden_is_apache', ! empty( $is_apache ) );
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
	 * Does the site's .htaccess hold ScrapeLock's hardening block?
	 *
	 * @return bool
	 */
	public static function htaccess_has_block() {
		$file = self::htaccess_file();
		if ( ! is_readable( $file ) ) {
			return false;
		}
		return false !== strpos( (string) file_get_contents( $file ), '# BEGIN ' . self::MARKER ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Can ScrapeLock write the site's .htaccess?
	 *
	 * @return bool
	 */
	public static function htaccess_writable() {
		$file = self::htaccess_file();
		return self::is_apache() && ( file_exists( $file ) ? wp_is_writable( $file ) : wp_is_writable( dirname( $file ) ) );
	}

	/**
	 * A text without ScrapeLock's hardening block.
	 *
	 * @param string $text File contents.
	 * @return string
	 */
	private static function without_block( $text ) {
		$marker = preg_quote( self::MARKER, '/' );
		// write_htaccess() puts a blank line between the block and what follows, or before it at the end of the file:
		// it goes with the block, so the file is byte for byte what it was before.
		return (string) preg_replace(
			array(
				'/\A# BEGIN ' . $marker . '\R.*?^# END ' . $marker . '(?:\R\R?|\z)/ms',
				'/\R?\R^# BEGIN ' . $marker . '\R.*?^# END ' . $marker . '(?:\R|\z)/ms',
			),
			'',
			$text,
			1
		);
	}

	/**
	 * The self-test: does the home page answer 200, and does a static file of WordPress?
	 *
	 * @return bool
	 */
	private static function site_answers() {
		/**
		 * Filters the self-test of the .htaccess change. Return a bool to decide yourself.
		 *
		 * @param bool|null $answer Null = make the test.
		 */
		$pre = apply_filters( 'pncp_harden_self_test', null );
		if ( is_bool( $pre ) ) {
			return $pre;
		}
		foreach ( array( home_url( '/' ), includes_url( 'css/dashicons.min.css' ) ) as $url ) {
			$r = self::fetch( $url, 'GET' );
			if ( is_wp_error( $r ) || 200 !== $r['code'] ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Writes the rules of the applied server points into the site's .htaccess, between ScrapeLock's markers and above
	 * the WordPress block. The site is asked before and after; if it no longer answers 200, the file is put back.
	 * Without server points the block is removed.
	 *
	 * @return true|WP_Error
	 */
	public static function write_htaccess() {
		$refused = self::refusal();
		if ( $refused ) {
			return $refused;
		}
		if ( ! self::is_apache() ) {
			return new WP_Error( 'pncp_not_apache', __( 'This site is not served by Apache: copy the Nginx rules into the server configuration instead.', 'scrapelock' ) );
		}
		if ( ! self::htaccess_writable() ) {
			return new WP_Error( 'pncp_not_writable', __( 'The .htaccess file cannot be written: copy the rules into it yourself, above # BEGIN WordPress.', 'scrapelock' ) );
		}
		$rules = self::apache_rules();
		if ( '' === $rules ) {
			return self::remove_htaccess();
		}
		if ( ! self::site_answers() ) {
			return new WP_Error( 'pncp_selftest_before', __( 'The site does not answer 200 to itself, so the change could not be tested: nothing was written. Copy the rules by hand and check the site right after.', 'scrapelock' ) );
		}
		$file    = self::htaccess_file();
		$existed = file_exists( $file );
		$before  = $existed ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$rest    = self::without_block( $before );
		$block   = '# BEGIN ' . self::MARKER . "\n" . $rules . '# END ' . self::MARKER . "\n";
		$pos     = strpos( $rest, '# BEGIN WordPress' );
		$after   = false === $pos ? rtrim( $rest ) . ( '' === trim( $rest ) ? '' : "\n\n" ) . $block : substr( $rest, 0, $pos ) . $block . "\n" . substr( $rest, $pos );
		if ( false === file_put_contents( $file, $after, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- The site's own .htaccess, put back below if the site breaks.
			return new WP_Error( 'pncp_not_writable', __( 'The .htaccess file could not be written.', 'scrapelock' ) );
		}
		clearstatcache();
		if ( ! self::site_answers() ) {
			self::restore_htaccess( $file, $existed, $before );
			self::note( 'htaccess_rollback', '' );
			return new WP_Error( 'pncp_rolled_back', __( 'After the change the site stopped answering 200, so .htaccess was put back as it was. Your host may not allow some of these rules (for example “Options”): copy the ones you need by hand, one at a time.', 'scrapelock' ) );
		}
		$state             = self::state( true );
		$state['htaccess'] = time();
		self::save_state( $state );
		self::note( 'htaccess_write', '' );
		return true;
	}

	/**
	 * Puts the .htaccess back as it was.
	 *
	 * @param string $file    File.
	 * @param bool   $existed Whether it existed.
	 * @param string $before  Its contents.
	 */
	private static function restore_htaccess( $file, $existed, $before ) {
		if ( $existed ) {
			file_put_contents( $file, $before, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Puts back the site's own file.
		} else {
			wp_delete_file( $file );
		}
		clearstatcache();
	}

	/**
	 * Removes ScrapeLock's hardening block from the site's .htaccess (the rest stays as it is).
	 *
	 * @param bool $check Refuse while locked (false on deactivation and uninstall).
	 * @return true|WP_Error
	 */
	public static function remove_htaccess( $check = true ) {
		if ( $check ) {
			$refused = self::refusal();
			if ( $refused ) {
				return $refused;
			}
		}
		$file = self::htaccess_file();
		if ( self::htaccess_has_block() ) {
			if ( ! wp_is_writable( $file ) ) {
				return new WP_Error( 'pncp_not_writable', __( 'The .htaccess file cannot be written: remove the ScrapeLock Hardening block yourself.', 'scrapelock' ) );
			}
			$text = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			file_put_contents( $file, self::without_block( $text ), LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- The site's own file, only our block goes.
			clearstatcache();
		}
		$state             = self::state( true );
		$state['htaccess'] = 0;
		self::save_state( $state );
		if ( $check ) {
			self::note( 'htaccess_remove', '' );
		}
		return true;
	}

	/* ---------- Bunny CDN edge ---------- */

	/**
	 * Can points be locked at the Bunny CDN edge?
	 *
	 * @return bool
	 */
	public static function edge_available() {
		return class_exists( 'PNCP_Bunny' ) && method_exists( 'PNCP_Bunny', 'edge_available' ) && PNCP_Bunny::edge_available();
	}

	/**
	 * Locks a point at the Bunny CDN edge, or unlocks it.
	 *
	 * @param string $id Point.
	 * @param bool   $on Lock.
	 * @return true|WP_Error
	 */
	public static function edge( $id, $on ) {
		$point = self::point( (string) $id );
		if ( ! $point || ! $point['edge'] ) {
			return new WP_Error( 'pncp_unknown', __( 'This point cannot be locked at the CDN.', 'scrapelock' ) );
		}
		$refused = self::refusal();
		if ( $refused ) {
			return $refused;
		}
		if ( ! self::edge_available() ) {
			return new WP_Error( 'pncp_no_edge', __( 'Bunny CDN is not connected.', 'scrapelock' ) );
		}
		if ( $on && 'xmlrpc' === $id && self::state()['xmlrpc_jetpack'] ) {
			return new WP_Error( 'pncp_jetpack', __( 'Jetpack is allowed through XML-RPC: a block at the CDN would refuse it too. Turn “Allow Jetpack” off first.', 'scrapelock' ) );
		}
		/* translators: %s: name of the point */
		$label  = sprintf( __( 'ScrapeLock hardening: %s', 'scrapelock' ), $point['label'] );
		$result = $on ? PNCP_Bunny::edge_block( 'harden_' . $id, $point['edge'], $label ) : PNCP_Bunny::edge_unblock( 'harden_' . $id );
		if ( true === $result ) {
			$state = self::state( true );
			if ( $on ) {
				$state['edge'][ $id ] = time();
			} else {
				unset( $state['edge'][ $id ] );
			}
			self::save_state( $state );
		}
		$result = is_wp_error( $result ) ? $result : ( true === $result ? true : new WP_Error( 'pncp_edge', __( 'Bunny CDN did not confirm the change.', 'scrapelock' ) ) );
		self::note( $on ? 'edge_on' : 'edge_off', $id, is_wp_error( $result ) ? $result->get_error_message() : '' );
		return $result;
	}

	/* ---------- Admin ---------- */

	/**
	 * The admin-post handler (action pncp_harden). Fields: op (apply, revert, apply_low, edge_on, edge_off,
	 * htaccess_write, htaccess_remove, jetpack_on, jetpack_off, recheck), id.
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$id = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : '';
		if ( 'recheck' === $op ) {
			self::live( true );
			self::done( __( 'Checked again.', 'scrapelock' ) );
		}
		if ( PNCP_Lockdown::is_locked() ) {
			self::done( new WP_Error( 'pncp_locked', __( 'The site is locked with Lockdown: unlock it to change the hardening.', 'scrapelock' ) ) );
		}
		$point = self::point( $id );
		$name  = $point ? $point['label'] : '';
		switch ( $op ) {
			case 'apply':
				/* translators: %s: name of the point */
				self::done( self::apply( $id ), sprintf( __( 'Locked: %s.', 'scrapelock' ), $name ) );
				break;
			case 'revert':
				/* translators: %s: name of the point */
				self::done( self::revert( $id ), sprintf( __( 'Opened again: %s.', 'scrapelock' ), $name ) );
				break;
			case 'apply_low':
				$results = self::apply_low_risk();
				$failed  = array_filter( $results, 'is_wp_error' );
				if ( $failed ) {
					self::done( reset( $failed ) );
				}
				self::done(
					$results
						/* translators: %d: number of points */
						? sprintf( _n( '%d low-risk point locked.', '%d low-risk points locked.', count( $results ), 'scrapelock' ), count( $results ) )
						: __( 'Every low-risk point was already locked.', 'scrapelock' )
				);
				break;
			case 'edge_on':
			case 'edge_off':
				if ( 'edge_on' === $op && class_exists( 'PNCP_Bunny' ) && method_exists( 'PNCP_Bunny', 'lock_confirmed' ) ) {
					// 3.9: only after "Confirm" on the preview of PNCP_Bunny ("What would be blocked").
					$confirmed = PNCP_Bunny::lock_confirmed( 'harden', $id );
					if ( false === $confirmed ) {
						PNCP_Bunny::to_preview( 'harden', $id );
					}
					if ( is_wp_error( $confirmed ) ) {
						self::done( $confirmed );
					}
				}
				self::done( self::edge( $id, 'edge_on' === $op ), 'edge_on' === $op ? __( 'Locked at the Bunny CDN edge.', 'scrapelock' ) : __( 'Removed from the Bunny CDN edge.', 'scrapelock' ) );
				break;
			case 'htaccess_write':
				self::done( self::write_htaccess(), __( 'The rules were written into .htaccess and the site still answers.', 'scrapelock' ) );
				break;
			case 'htaccess_remove':
				self::done( self::remove_htaccess(), __( 'The rules were removed from .htaccess.', 'scrapelock' ) );
				break;
			case 'jetpack_on':
			case 'jetpack_off':
				self::done( self::set_jetpack( 'jetpack_on' === $op ), 'jetpack_on' === $op ? __( 'Jetpack\'s servers may use XML-RPC (without pingbacks).', 'scrapelock' ) : __( 'XML-RPC is refused to Jetpack too.', 'scrapelock' ) );
				break;
		}
		self::done( new WP_Error( 'pncp_unknown', __( 'Unknown action.', 'scrapelock' ) ) );
	}

	/**
	 * Back to the page the form came from, with the result shown once.
	 *
	 * @param true|string|WP_Error $result  Result, or the message when there is no result to check.
	 * @param string               $message Message on success.
	 */
	private static function done( $result, $message = '' ) {
		if ( is_string( $result ) ) {
			$message = $result;
			$result  = true;
		}
		$notice = is_wp_error( $result ) ? array( 'error', $result->get_error_message() ) : array( 'success', $message );
		set_transient( 'pncp_harden_msg_' . get_current_user_id(), $notice, MINUTE_IN_SECONDS );
		$back = wp_get_referer();
		if ( ! $back ) {
			$back = PNCP_Status::settings_url( array( 'tab' => 'hardening' ) );
		}
		wp_safe_redirect( remove_query_arg( array( 'pncp_message', 'pncp_harden' ), $back ) . '#pncp-hardening' );
		exit;
	}

	/**
	 * One admin-post button.
	 *
	 * @param string $op      Operation.
	 * @param string $id      Point.
	 * @param string $label   Button text.
	 * @param string $css     Button class.
	 * @param string $confirm Text of a confirmation, '' = none.
	 */
	private static function button( $op, $id, $label, $css = 'button button-small', $confirm = '' ) {
		printf( '<form method="post" action="%s" class="pncp-harden-form">', esc_url( admin_url( 'admin-post.php' ) ) );
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '">';
		echo '<input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
		echo '<input type="hidden" name="id" value="' . esc_attr( $id ) . '">';
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( self::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
		printf(
			'<button type="submit" class="%1$s"%3$s>%2$s</button></form>',
			esc_attr( $css ),
			esc_html( $label ),
			'' !== $confirm ? ' onclick="return window.confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ');"' : ''
		);
	}

	/**
	 * The "Lock this" button of a point, for the attack report. Prints nothing when the point is locked, cannot be
	 * applied here, or the site is locked with Lockdown.
	 *
	 * @param string $id    Point (from recommend_for_path()).
	 * @param string $label Button text ('' = "Lock this").
	 */
	public static function render_lock_button( $id, $label = '' ) {
		$point = self::point( (string) $id );
		if ( ! $point || PNCP_Lockdown::is_locked() || ! current_user_can( 'manage_options' ) || self::is_applied( $id ) || ( 'login' === $id && ! self::login_available() ) ) {
			return;
		}
		$confirm = 'low' === $point['risk'] ? '' : sprintf(
			/* translators: 1: name of the point, 2: what may break */
			__( 'Lock “%1$s”? What may stop working: %2$s', 'scrapelock' ),
			$point['label'],
			$point['breaks']
		);
		self::button( 'apply', $id, '' !== $label ? $label : __( 'Lock this', 'scrapelock' ), 'button button-small', $confirm );
	}

	/**
	 * The badge of a state.
	 *
	 * @param string $state State.
	 * @return string HTML.
	 */
	private static function state_badge( $state ) {
		$labels = self::state_labels();
		$label  = isset( $labels[ $state ] ) ? $labels[ $state ] : __( 'Unknown', 'scrapelock' );
		return '<span class="pncp-badge pncp-harden-state pncp-harden-state--' . esc_attr( $state ) . '">' . esc_html( $label ) . '</span>';
	}

	/**
	 * The "Vulnerable points" card.
	 */
	public static function render_card() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$locked = PNCP_Lockdown::is_locked();
		$rows   = self::rows();
		$risks  = self::risk_labels();
		$wheres = self::where_labels();
		$edge   = self::edge_available();
		$notice = get_transient( 'pncp_harden_msg_' . get_current_user_id() );
		if ( is_array( $notice ) ) {
			delete_transient( 'pncp_harden_msg_' . get_current_user_id() );
		}
		$have_attacks = class_exists( 'PNCP_Attacks' );
		?>
		<style>
			.pncp-harden-form{display:inline-block;margin:0 4px 4px 0}
			.pncp-harden-state--on{background:#d1f0d8;color:#0a5b1f}
			.pncp-harden-state--partial{background:#fcf0c8;color:#6b4e00}
			.pncp-harden-state--off{background:#fbdcdc;color:#8a1f11}
			.pncp-harden-state--na{background:#eee;color:#555}
			.pncp-harden-risk--high{color:#8a1f11;font-weight:600}
			.pncp-harden-risk--medium{color:#6b4e00;font-weight:600}
			.pncp-harden-rec{margin:6px 0 0;padding:4px 8px;border-left:3px solid #d63638;background:#fcf0f1}
			.pncp-harden-table td{vertical-align:top}
			.pncp-harden-table .num{text-align:right;white-space:nowrap}
		</style>
		<section class="pncp-card pncp-card--wide" id="pncp-hardening" aria-labelledby="pncp-hardening-title">
		<h2 id="pncp-hardening-title"><?php esc_html_e( 'Vulnerable points', 'scrapelock' ); ?></h2>
		<?php echo PNCP_Admin_Fields::para( __( 'Where bots attack WordPress sites, checked here as a visitor. Lock or reopen with one click.', 'scrapelock' ), __( 'The places bots attack on every WordPress site, whether each one is locked on this site (checked by asking the site itself, as a visitor), how many attacks reached it, and what locking it may break. Lock a point with one click and open it again the same way.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<?php if ( is_array( $notice ) && 2 === count( $notice ) ) : ?>
			<div class="notice notice-<?php echo 'error' === $notice[0] ? 'error' : 'success'; ?> inline"><p><?php echo esc_html( (string) $notice[1] ); ?></p></div>
		<?php endif; ?>
		<?php if ( $locked ) : ?>
			<div class="notice notice-warning inline"><p><?php esc_html_e( 'The site is locked: unlock it on the Lockdown tab to change these points.', 'scrapelock' ); ?></p></div>
		<?php endif; ?>
		<?php if ( PNCP_Options::monitoring() ) : ?>
			<p class="pncp-inline-warning"><?php esc_html_e( '“Monitor only” is on: points that refuse requests only log them as “Would block” for now.', 'scrapelock' ); ?></p>
		<?php endif; ?>
		<?php if ( ! $have_attacks ) : ?>
			<p class="description"><?php esc_html_e( 'The attack counts appear once the attack report is available.', 'scrapelock' ); ?></p>
		<?php endif; ?>
		<?php if ( ! $locked ) : ?>
			<p>
			<?php self::button( 'apply_low', '', __( 'Lock all low-risk points', 'scrapelock' ), 'button button-primary' ); ?>
			<?php self::button( 'recheck', '', __( 'Check again', 'scrapelock' ), 'button' ); ?>
			</p>
		<?php endif; ?>
		<div class="pncp-table-wrap"><table class="widefat striped pncp-harden-table">
		<thead><tr>
			<th scope="col"><?php esc_html_e( 'Point', 'scrapelock' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Status', 'scrapelock' ); ?></th>
			<th scope="col" class="num"><?php esc_html_e( 'Attacks 7 days', 'scrapelock' ); ?></th>
			<th scope="col" class="num"><?php esc_html_e( '30 days', 'scrapelock' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Risk of locking it', 'scrapelock' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Action', 'scrapelock' ); ?></th>
		</tr></thead>
		<tbody>
		<?php foreach ( $rows as $row ) : ?>
			<?php
			$where = array();
			foreach ( $row['where'] as $w ) {
				$where[] = isset( $wheres[ $w ] ) ? $wheres[ $w ] : $w;
			}
			?>
			<tr id="pncp-harden-<?php echo esc_attr( $row['id'] ); ?>">
			<td>
				<strong><?php echo esc_html( $row['label'] ); ?></strong>
				<?php echo self::folded_text( $row, 0, 'protects' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
				<p class="description pncp-muted">
				<?php
				/* translators: %s: places, e.g. "WordPress, Server rules" */
				echo esc_html( sprintf( __( 'Enforced by: %s', 'scrapelock' ), implode( ', ', $where ) ) );
				?>
				</p>
				<?php if ( $row['hits30'] > 0 && 'on' !== $row['state'] && 'na' !== $row['state'] ) : ?>
					<p class="pncp-harden-rec">
					<?php
					/* translators: %s: number of attacks */
					echo esc_html( sprintf( _n( '%s attack reached this point in the last 30 days: lock it.', '%s attacks reached this point in the last 30 days: lock it.', $row['hits30'], 'scrapelock' ), number_format_i18n( $row['hits30'] ) ) );
					?>
					</p>
				<?php endif; ?>
			</td>
			<td>
				<?php echo self::state_badge( $row['state'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in state_badge(). ?>
				<?php if ( '' !== $row['note'] ) : ?>
					<p class="description"><?php echo esc_html( $row['note'] ); ?></p>
				<?php endif; ?>
			</td>
			<td class="num"><?php echo $have_attacks && $row['evidence'] ? esc_html( number_format_i18n( $row['hits7'] ) ) : '–'; ?></td>
			<td class="num"><?php echo $have_attacks && $row['evidence'] ? esc_html( number_format_i18n( $row['hits30'] ) ) : '–'; ?></td>
			<td>
				<span class="pncp-harden-risk--<?php echo esc_attr( $row['risk'] ); ?>"><?php echo esc_html( $risks[ $row['risk'] ] ); ?></span>
				<?php echo self::folded_text( $row, 1, 'breaks' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			</td>
			<td>
				<?php
				if ( ! $locked ) {
					self::render_actions( $row, $edge );
				}
				?>
			</td>
			</tr>
		<?php endforeach; ?>
		</tbody></table></div>
		<?php self::render_server_rules( $locked ); ?>
		<?php self::render_history(); ?>
		</section>
		<?php
	}

	/**
	 * The buttons of one row.
	 *
	 * @param array<string, mixed> $row  Row of rows().
	 * @param bool                 $edge Whether Bunny CDN is connected.
	 */
	private static function render_actions( $row, $edge ) {
		$id = $row['id'];
		if ( 'login' === $id && ! self::login_available() ) {
			echo '<span class="pncp-muted">–</span>';
			return;
		}
		if ( 'file_editor' === $id && defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT && ! $row['applied'] ) {
			echo '<span class="pncp-muted">' . esc_html__( 'Set in wp-config.php', 'scrapelock' ) . '</span>';
			return;
		}
		if ( $row['applied'] ) {
			self::button( 'revert', $id, __( 'Open again', 'scrapelock' ), 'button button-small' );
		} else {
			self::render_lock_button( $id, __( 'Lock', 'scrapelock' ) );
		}
		if ( 'xmlrpc' === $id ) {
			$jetpack = self::state()['xmlrpc_jetpack'];
			self::button( $jetpack ? 'jetpack_off' : 'jetpack_on', $id, $jetpack ? __( 'Refuse Jetpack too', 'scrapelock' ) : __( 'Allow Jetpack', 'scrapelock' ), 'button button-small button-link' );
		}
		if ( $edge && $row['edge'] ) {
			if ( $row['edge_on'] ) {
				self::button( 'edge_off', $id, __( 'Unlock at Bunny CDN', 'scrapelock' ), 'button button-small' );
			} elseif ( 'xmlrpc' !== $id || ! self::state()['xmlrpc_jetpack'] ) {
				// 3.9: opens "What would be blocked" (PNCP_Bunny::lock_preview()), which also lists what stops working.
				self::button( 'edge_on', $id, __( 'Lock at Bunny CDN…', 'scrapelock' ) );
			}
		}
	}

	/**
	 * 3.11: a "protects" or "breaks" text of a point in the table: the short line, the full text under "More".
	 *
	 * @param array<string, mixed> $row  Row of the table (has "id" and the full texts).
	 * @param int                  $part 0 for "protects", 1 for "breaks" (index in short_texts()).
	 * @param string               $key  "protects" or "breaks".
	 * @return string HTML.
	 */
	private static function folded_text( $row, $part, $key ) {
		$short = self::short_texts();
		$full  = isset( $row[ $key ] ) ? (string) $row[ $key ] : '';
		if ( ! isset( $short[ $row['id'] ][ $part ] ) ) {
			return '<p class="description">' . esc_html( $full ) . '</p>';
		}
		return PNCP_Admin_Fields::description( '', PNCP_Admin_Fields::help( $short[ $row['id'] ][ $part ], $full ) );
	}

	/**
	 * Server rules of the applied server points: write into .htaccess (Apache) or copy (Apache, Nginx).
	 *
	 * @param bool $locked Whether the site is locked.
	 */
	private static function render_server_rules( $locked ) {
		$apache = self::apache_rules();
		$nginx  = self::nginx_rules();
		?>
		<h3><?php esc_html_e( 'Server rules for these points', 'scrapelock' ); ?></h3>
		<?php if ( '' === $apache ) : ?>
			<?php echo PNCP_Admin_Fields::para( __( 'No point that needs the web server is locked here yet.', 'scrapelock' ), __( 'No point that needs the web server is locked here yet (WordPress\'s own files, PHP in wp-includes or wp-content, directory listing, XML-RPC before PHP).', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php if ( ! $locked && self::htaccess_has_block() ) : ?>
				<p><?php self::button( 'htaccess_remove', '', __( 'Remove the rules from .htaccess', 'scrapelock' ), 'button' ); ?></p>
			<?php endif; ?>
			<?php
			return;
		endif;
		?>
		<?php echo PNCP_Admin_Fields::para( __( 'Enforced by the web server, so static files are covered too.', 'scrapelock' ), __( 'These points are enforced by the web server, before WordPress, so they also cover static files. ScrapeLock can write them into the site\'s .htaccess on Apache: it asks the site before and after, and puts the file back on its own if the site stops answering.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<?php if ( self::is_apache() ) : ?>
			<?php if ( self::htaccess_has_block() ) : ?>
				<div class="notice notice-success inline"><p><?php esc_html_e( 'Written into .htaccess (block “ScrapeLock Hardening”). It follows your changes here on its own.', 'scrapelock' ); ?></p></div>
			<?php endif; ?>
			<?php if ( ! $locked ) : ?>
				<p>
				<?php
				if ( self::htaccess_writable() ) {
					self::button( 'htaccess_write', '', self::htaccess_has_block() ? __( 'Write into .htaccess again', 'scrapelock' ) : __( 'Write into .htaccess (with self-test)', 'scrapelock' ), 'button button-primary' );
				} else {
					echo '<span class="pncp-inline-warning">' . esc_html__( 'The .htaccess file cannot be written by WordPress: copy the rules into it yourself, above # BEGIN WordPress.', 'scrapelock' ) . '</span> ';
				}
				if ( self::htaccess_has_block() ) {
					self::button( 'htaccess_remove', '', __( 'Remove from .htaccess', 'scrapelock' ), 'button' );
				}
				?>
				</p>
			<?php endif; ?>
		<?php endif; ?>
		<h4><?php esc_html_e( 'Apache (.htaccess, above # BEGIN WordPress)', 'scrapelock' ); ?></h4>
		<?php self::code_block( 'pncp-harden-apache', '# BEGIN ' . self::MARKER . "\n" . $apache . '# END ' . self::MARKER . "\n", 8 ); ?>
		<h4><?php esc_html_e( 'Nginx (inside the site\'s server { })', 'scrapelock' ); ?></h4>
		<?php self::code_block( 'pncp-harden-nginx', $nginx, 8 ); ?>
		<?php
	}

	/**
	 * Read-only code field with a copy button (the same markup as the "Server rules" tab).
	 *
	 * @param string $id   ID.
	 * @param string $code Code.
	 * @param int    $rows Rows.
	 */
	private static function code_block( $id, $code, $rows ) {
		printf(
			'<div class="pncp-code"><textarea id="%1$s" class="large-text code" rows="%2$d" readonly aria-label="%3$s">%4$s</textarea><p><button type="button" class="button pncp-copy" data-target="%1$s">%5$s</button></p></div>',
			esc_attr( $id ),
			(int) $rows,
			esc_attr__( 'Rules to copy', 'scrapelock' ),
			esc_textarea( $code ),
			esc_html__( 'Copy', 'scrapelock' )
		);
	}

	/**
	 * Labels of the history actions.
	 *
	 * @return array<string, string>
	 */
	private static function action_labels() {
		return array(
			'apply'             => __( 'Locked', 'scrapelock' ),
			'revert'            => __( 'Opened again', 'scrapelock' ),
			'edge_on'           => __( 'Locked at Bunny CDN', 'scrapelock' ),
			'edge_off'          => __( 'Unlocked at Bunny CDN', 'scrapelock' ),
			'jetpack_on'        => __( 'Jetpack allowed', 'scrapelock' ),
			'jetpack_off'       => __( 'Jetpack refused', 'scrapelock' ),
			'htaccess_write'    => __( 'Rules written into .htaccess', 'scrapelock' ),
			'htaccess_remove'   => __( 'Rules removed from .htaccess', 'scrapelock' ),
			'htaccess_rollback' => __( '.htaccess put back after a failed self-test', 'scrapelock' ),
		);
	}

	/**
	 * The last changes.
	 */
	private static function render_history() {
		$history = self::history( 10 );
		if ( ! $history ) {
			return;
		}
		$labels = self::action_labels();
		?>
		<h3><?php esc_html_e( 'Last changes', 'scrapelock' ); ?></h3>
		<div class="pncp-table-wrap"><table class="widefat striped">
		<thead><tr>
			<th scope="col"><?php esc_html_e( 'When', 'scrapelock' ); ?></th>
			<th scope="col"><?php esc_html_e( 'What', 'scrapelock' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Who', 'scrapelock' ); ?></th>
		</tr></thead><tbody>
		<?php foreach ( $history as $entry ) : ?>
			<?php
			$point = '' !== $entry['id'] ? self::point( $entry['id'] ) : null;
			$what  = isset( $labels[ $entry['action'] ] ) ? $labels[ $entry['action'] ] : $entry['action'];
			if ( $point ) {
				$what .= ': ' . $point['label'];
			}
			if ( '' !== $entry['error'] ) {
				/* translators: %s: error message */
				$what .= ' — ' . sprintf( __( 'failed: %s', 'scrapelock' ), $entry['error'] );
			}
			?>
			<tr>
				<td><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $entry['time'] ) ); ?></td>
				<td><?php echo esc_html( $what ); ?></td>
				<td><?php echo esc_html( $entry['user'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody></table></div>
		<?php
	}

	/* ---------- Site Health ---------- */

	/**
	 * Site Health test: attacked points that are still open.
	 *
	 * @return array<string, mixed>
	 */
	public static function health_test() {
		$open = array();
		foreach ( self::rows() as $row ) {
			if ( $row['hits30'] > 0 && in_array( $row['state'], array( 'off', 'partial' ), true ) ) {
				$open[] = $row;
			}
		}
		$result = array(
			'label'       => __( 'The points bots attack on this site are locked', 'scrapelock' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'scrapelock' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html__( 'ScrapeLock found no attacked point that is still open.', 'scrapelock' ) . '</p>',
			'actions'     => '',
			'test'        => 'scrapelock_hardening',
		);
		if ( ! $open ) {
			return $result;
		}
		$items = '';
		foreach ( $open as $row ) {
			/* translators: 1: name of the point, 2: number of attacks */
			$items .= '<li>' . esc_html( sprintf( __( '%1$s: %2$s attacks in 30 days', 'scrapelock' ), $row['label'], number_format_i18n( $row['hits30'] ) ) ) . '</li>';
		}
		$result['status']      = 'recommended';
		$result['label']       = __( 'Bots attack points of this site that are still open', 'scrapelock' );
		$result['description'] = '<p>' . esc_html__( 'These points were attacked in the last 30 days and are not locked:', 'scrapelock' ) . '</p><ul>' . $items . '</ul>';
		$result['actions']     = '<p><a href="' . esc_url( PNCP_Status::settings_url( array( 'tab' => 'hardening' ) ) . '#pncp-hardening' ) . '">' . esc_html__( 'Lock them in ScrapeLock', 'scrapelock' ) . '</a></p>';
		return $result;
	}

	/* ---------- WP-CLI ---------- */

	/**
	 * Runs `wp scrapelock harden <list|apply|revert|apply-low|rules|write-htaccess|remove-htaccess|check> [<id>] [--server=apache|nginx] [--format=table]`.
	 *
	 * @param string[]              $args       Positional arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cli( $args, $assoc_args ) {
		if ( ! class_exists( 'WP_CLI' ) ) {
			return;
		}
		$sub = isset( $args[0] ) ? (string) $args[0] : 'list';
		$id  = isset( $args[1] ) ? sanitize_key( (string) $args[1] ) : '';
		$out = static function ( $result, $ok ) {
			if ( is_wp_error( $result ) ) {
				WP_CLI::error( $result->get_error_message() );
			}
			WP_CLI::success( $ok );
		};
		switch ( $sub ) {
			case 'check':
				self::live( true );
				// Falls through to the list.
			case 'list':
				$items = array();
				foreach ( self::rows() as $row ) {
					$items[] = array(
						'id'      => $row['id'],
						'status'  => $row['state'],
						'risk'    => $row['risk'],
						'7d'      => $row['hits7'],
						'30d'     => $row['hits30'],
						'where'   => implode( ',', $row['where'] ),
						'note'    => $row['note'],
						'applied' => $row['applied'] ? 'yes' : 'no',
					);
				}
				WP_CLI\Utils\format_items( isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table', $items, array( 'id', 'status', 'applied', 'risk', '7d', '30d', 'where', 'note' ) );
				break;
			case 'apply':
			case 'revert':
				if ( ! self::point( $id ) ) {
					WP_CLI::error( 'Unknown point. See: wp scrapelock harden list' );
				}
				$out( 'apply' === $sub ? self::apply( $id ) : self::revert( $id ), ( 'apply' === $sub ? 'Locked: ' : 'Opened again: ' ) . $id );
				break;
			case 'apply-low':
				$results = self::apply_low_risk();
				foreach ( $results as $point => $result ) {
					if ( is_wp_error( $result ) ) {
						WP_CLI::warning( ( '' !== $point ? $point . ': ' : '' ) . $result->get_error_message() );
					} else {
						WP_CLI::log( 'Locked: ' . $point );
					}
				}
				WP_CLI::success( count( array_filter( $results, 'is_bool' ) ) . ' point(s) locked.' );
				break;
			case 'rules':
				$server = isset( $assoc_args['server'] ) ? (string) $assoc_args['server'] : 'apache';
				WP_CLI::line( 'nginx' === $server ? self::nginx_rules() : self::apache_rules() );
				break;
			case 'write-htaccess':
				$out( self::write_htaccess(), 'Written into .htaccess; the site still answers 200.' );
				break;
			case 'remove-htaccess':
				$out( self::remove_htaccess(), 'Removed from .htaccess.' );
				break;
			default:
				WP_CLI::error( 'Unknown subcommand. Use: list, check, apply <id>, revert <id>, apply-low, rules [--server=nginx], write-htaccess, remove-htaccess.' );
		}
	}

	/* ---------- Lifecycle ---------- */

	/**
	 * Deactivation: the .htaccess block goes (the rest of the file stays). Points stay stored.
	 */
	public static function deactivate() {
		if ( PNCP_Lockdown::is_locked() ) {
			return;
		}
		self::remove_htaccess( false );
		delete_transient( self::LIVE );
	}

	/**
	 * Uninstall: the .htaccess block and the options go.
	 */
	public static function uninstall() {
		self::remove_htaccess( false );
		delete_option( self::OPTION );
		delete_option( self::HISTORY );
		delete_transient( self::LIVE );
	}
}
