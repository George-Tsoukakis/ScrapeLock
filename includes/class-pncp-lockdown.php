<?php
/**
 * Lockdown: freezes every change made from wp-admin, the REST API or XML-RPC (plugins, themes, updates,
 * the file editor, users and roles, settings, content) until an administrator unlocks it with a code
 * from an authenticator app. Visitors and customers are not affected: they browse, order, register as
 * customers and comment as usual.
 *
 * Lost phone: one-time recovery codes, or, as a last resort, define( 'SCRAPELOCK_UNLOCK', true ); in
 * wp-config.php (whoever can edit that file controls the site anyway).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The lock, its enforcement and its page in wp-admin.
 */
final class PNCP_Lockdown {

	const OPTION        = 'pncp_lockdown';
	const LOG_OPTION    = 'pncp_lockdown_log';
	const PENDING_META  = 'pncp_lockdown_pending';
	const ACTION        = 'pncp_lockdown';
	const MAX_FAILS     = 5;  // Per user, in 15 minutes.
	const MAX_FAILS_ALL = 20; // All users together, in an hour.
	const CODES         = 10;
	const MUTEX         = 'pncp_lockdown_mutex';

	/**
	 * Inside can(): the lock does not take capabilities away.
	 *
	 * @var int
	 */
	private static $bypass = 0;

	/**
	 * The lock writing its own state: the protected options may change.
	 *
	 * @var bool
	 */
	private static $writing = false;

	/**
	 * The state, read once per request.
	 *
	 * @var array<string, mixed>|null
	 */
	private static $state = null;

	/**
	 * Staff or not, per user.
	 *
	 * @var array<int, bool>
	 */
	private static $staff = array();

	/**
	 * The wp_die() handler that was in place before ours.
	 *
	 * @var callable|null
	 */
	private static $die_handler = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'map_meta_cap', array( __CLASS__, 'map_meta_cap' ), 9999, 3 );
		add_filter( 'file_mod_allowed', array( __CLASS__, 'file_mod_allowed' ) );
		add_filter( 'automatic_updater_disabled', array( __CLASS__, 'updater_disabled' ) );
		foreach ( self::protected_options() as $option ) {
			add_filter( 'pre_update_option_' . $option, array( __CLASS__, 'keep_option' ), 9999, 3 );
		}
		foreach ( array( 'active_sitewide_plugins', 'admin_email', self::OPTION ) as $option ) {
			add_filter( 'pre_update_site_option_' . $option, array( __CLASS__, 'keep_option' ), 9999, 3 );
		}
		add_filter( 'update_user_metadata', array( __CLASS__, 'keep_roles' ), 9999, 4 );
		add_filter( 'add_user_metadata', array( __CLASS__, 'keep_roles' ), 9999, 4 );
		add_filter( 'wp_pre_insert_user_data', array( __CLASS__, 'keep_login' ), 9999, 3 );
		// The change was refused (keep_login): no "your email / password was changed" message either.
		add_filter( 'send_email_change_email', array( __CLASS__, 'change_email' ), 9999, 2 );
		add_filter( 'send_password_change_email', array( __CLASS__, 'change_email' ), 9999, 2 );
		add_filter( 'allow_password_reset', array( __CLASS__, 'allow_password_reset' ), 9999, 2 );
		add_filter( 'wp_is_application_passwords_available_for_user', array( __CLASS__, 'app_passwords' ), 9999, 2 );
		add_action( 'woocommerce_save_account_details_errors', array( __CLASS__, 'woocommerce_account_errors' ), 10, 2 );
		// WooCommerce sends users who cannot edit posts away from wp-admin and hides their admin bar: staff
		// would then not even reach the unlock page.
		add_filter( 'woocommerce_prevent_admin_access', array( __CLASS__, 'woocommerce_admin_access' ) );
		add_filter( 'woocommerce_disable_admin_bar', array( __CLASS__, 'woocommerce_admin_access' ) );
		if ( is_admin() ) {
			add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
			add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
			add_action( 'network_admin_notices', array( __CLASS__, 'notices' ) );
			add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
			add_filter( 'wp_die_handler', array( __CLASS__, 'die_handler' ), PHP_INT_MAX );
		}
	}

	/* ---------- State ---------- */

	/**
	 * The stored state.
	 *
	 * @return array{secret:string, locked:bool, until:int, last_step:int, codes:string[], since:int}
	 */
	public static function state() {
		if ( null === self::$state ) {
			$stored      = get_site_option( self::OPTION, array() );
			self::$state = array_merge(
				array(
					'secret'    => '',
					'locked'    => false,
					'until'     => 0,
					'last_step' => 0,
					'codes'     => array(),
					'since'     => 0,
					'ack'       => false,
					'roles'     => null,
					'quarantine' => false,
				),
				is_array( $stored ) ? $stored : array()
			);
		}
		return self::$state;
	}

	/**
	 * Saves the state.
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function save( $state ) {
		self::$writing = true;
		update_site_option( self::OPTION, $state );
		self::$writing = false;
		self::$state   = $state;
	}

	/**
	 * Is the authenticator app connected?
	 *
	 * @return bool
	 */
	public static function configured() {
		return '' !== self::state()['secret'];
	}

	/**
	 * Unlocked from the server (wp-config.php) for a lost phone.
	 *
	 * @return bool
	 */
	public static function server_unlocked() {
		return defined( 'SCRAPELOCK_UNLOCK' ) && true === SCRAPELOCK_UNLOCK;
	}

	/**
	 * Is the site locked right now?
	 *
	 * @return bool
	 */
	public static function is_locked() {
		if ( self::server_unlocked() ) {
			return false;
		}
		$s = self::state();
		return ! empty( $s['locked'] ) && time() >= (int) $s['until'];
	}

	/**
	 * Locked, but opened for a while: until when (0 = not).
	 *
	 * @return int
	 */
	public static function unlocked_until() {
		$s = self::state();
		return ! empty( $s['locked'] ) && (int) $s['until'] > time() ? (int) $s['until'] : 0;
	}

	/* ---------- Who ---------- */

	/**
	 * Capabilities that let a role take over the site (plugins, themes, files, users, settings). A role
	 * with any of them is always frozen while locked; it cannot be unticked.
	 *
	 * @return string[]
	 */
	public static function control_caps() {
		return array( 'manage_options', 'activate_plugins', 'install_plugins', 'update_plugins', 'delete_plugins', 'edit_plugins', 'install_themes', 'update_themes', 'delete_themes', 'switch_themes', 'edit_themes', 'edit_theme_options', 'update_core', 'edit_files', 'create_users', 'edit_users', 'promote_users', 'delete_users', 'remove_users', 'unfiltered_upload', 'manage_network', 'manage_network_options', 'manage_network_plugins' );
	}

	/**
	 * Capabilities of editorial and shop staff: a role with any of them is frozen by default (it can be
	 * unticked on the Lockdown tab).
	 *
	 * @return string[]
	 */
	private static function staff_caps() {
		return array( 'unfiltered_html', 'list_users', 'import', 'export', 'manage_categories', 'moderate_comments', 'edit_others_posts', 'edit_others_pages', 'edit_pages', 'publish_pages', 'manage_woocommerce', 'edit_shop_orders', 'edit_others_shop_orders', 'edit_others_products', 'view_woocommerce_reports' );
	}

	/**
	 * The capabilities a role grants.
	 *
	 * @param string $role Role.
	 * @return string[]
	 */
	private static function role_caps( $role ) {
		$object = wp_roles()->get_role( (string) $role );
		return $object ? array_keys( array_filter( $object->capabilities ) ) : array();
	}

	/**
	 * Is this role always frozen (it can take over the site)?
	 *
	 * @param string $role Role.
	 * @return bool
	 */
	public static function role_always( $role ) {
		return array() !== array_intersect( self::role_caps( $role ), self::control_caps() );
	}

	/**
	 * Is this role frozen when nothing was chosen? Roles that can take over the site, editorial and shop
	 * staff, and WordPress' own content roles. Subscribers, customers and member roles of other plugins
	 * (e.g. accounts that post listings or community posts) are not, even with extra capabilities.
	 *
	 * @param string $role Role.
	 * @return bool
	 */
	private static function role_default( $role ) {
		return self::role_always( $role ) || in_array( $role, array( 'administrator', 'editor', 'author', 'contributor', 'shop_manager' ), true ) || array() !== array_intersect( self::role_caps( $role ), self::staff_caps() );
	}

	/**
	 * The roles frozen while locked: the ones chosen on the Lockdown tab (or the defaults), plus every role
	 * that can take over the site.
	 *
	 * @return string[]
	 */
	public static function frozen_roles() {
		$chosen = self::state()['roles'];
		$roles  = array();
		foreach ( array_keys( wp_roles()->get_names() ) as $role ) {
			if ( self::role_always( $role ) || ( is_array( $chosen ) ? in_array( $role, $chosen, true ) : self::role_default( $role ) ) ) {
				$roles[] = $role;
			}
		}
		return $roles;
	}

	/**
	 * Do these stored capabilities ({prefix}capabilities) make a user staff? A frozen role, or a single
	 * capability given to the user that belongs to staff.
	 *
	 * @param mixed $caps {prefix}capabilities value.
	 * @return bool
	 */
	private static function grants_staff( $caps ) {
		if ( ! is_array( $caps ) ) {
			return false;
		}
		$frozen = self::frozen_roles();
		$roles  = wp_roles();
		foreach ( $caps as $name => $grant ) {
			$name = (string) $name;
			if ( ! $grant ) {
				continue;
			}
			if ( $roles->is_role( $name ) ? in_array( $name, $frozen, true ) : in_array( $name, array_merge( self::control_caps(), self::staff_caps() ), true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Staff: users with a frozen role (see frozen_roles()) or a staff capability of their own. Everyone
	 * else (customers, subscribers, members) is not touched by the lock. Uses the roles as stored, not the
	 * capabilities the lock takes away.
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	public static function is_staff( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id < 1 ) {
			return false;
		}
		if ( ! isset( self::$staff[ $user_id ] ) ) {
			self::$staff[ $user_id ] = ( is_multisite() && is_super_admin( $user_id ) ) || self::grants_staff( self::user_caps( $user_id ) );
		}
		return self::$staff[ $user_id ];
	}

	/**
	 * An administrator who can lock and unlock.
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	public static function is_owner( $user_id ) {
		$user = get_userdata( (int) $user_id );
		if ( ! $user ) {
			return false;
		}
		return is_multisite() ? is_super_admin( $user->ID ) : ! empty( $user->allcaps['manage_options'] );
	}

	/**
	 * current_user_can() as if the site were not locked. For what ScrapeLock shows to staff (exemptions,
	 * full text in the API): reading, not changing.
	 *
	 * @param string $cap  Capability.
	 * @param mixed  ...$args Object ID etc.
	 * @return bool
	 */
	public static function can( $cap, ...$args ) {
		++self::$bypass;
		try {
			return current_user_can( $cap, ...$args );
		} finally {
			--self::$bypass;
		}
	}

	/**
	 * The stored capabilities of a user ({prefix}capabilities: roles and single capabilities).
	 *
	 * @param int $user_id User.
	 * @return array<string, bool>
	 */
	private static function user_caps( $user_id ) {
		global $wpdb;
		$caps = get_user_meta( $user_id, $wpdb->get_blog_prefix() . 'capabilities', true );
		return is_array( $caps ) ? $caps : array();
	}

	/**
	 * The capabilities beyond reading that a set of roles / capabilities grants, sorted.
	 *
	 * @param mixed $caps {prefix}capabilities value.
	 * @return string[]
	 */
	private static function privileged( $caps ) {
		$out = array();
		if ( ! is_array( $caps ) ) {
			return $out;
		}
		$roles = wp_roles();
		foreach ( $caps as $name => $grant ) {
			if ( ! $grant ) {
				continue;
			}
			$role = $roles->get_role( (string) $name );
			$list = $role ? array_keys( array_filter( $role->capabilities ) ) : array( (string) $name );
			foreach ( $list as $cap ) {
				if ( ! in_array( $cap, array( 'read', 'exist' ), true ) && 0 !== strpos( $cap, 'level_' ) ) {
					$out[ $cap ] = true;
				}
			}
		}
		$out = array_keys( $out );
		sort( $out );
		return $out;
	}

	/* ---------- Enforcement ---------- */

	/**
	 * While locked, staff keep only "read": wp-admin opens, nothing can be changed.
	 *
	 * @param string[] $caps    Primitive capabilities required.
	 * @param string   $cap     Capability checked.
	 * @param int      $user_id User.
	 * @return string[]
	 */
	public static function map_meta_cap( $caps, $cap, $user_id ) {
		if ( self::$bypass || ! $user_id || in_array( $cap, array( 'read', 'exist', 'level_0' ), true ) || ! self::is_locked() || ! self::is_staff( $user_id ) ) {
			return $caps;
		}
		return array( 'do_not_allow' );
	}

	/**
	 * No installs, updates, deletions or file editing (plugins, themes, core, translations).
	 *
	 * @param bool $allowed Allowed.
	 * @return bool
	 */
	public static function file_mod_allowed( $allowed ) {
		return self::is_locked() ? false : $allowed;
	}

	/**
	 * No automatic updates.
	 *
	 * @param bool $disabled Disabled.
	 * @return bool
	 */
	public static function updater_disabled( $disabled ) {
		return self::is_locked() ? true : $disabled;
	}

	/**
	 * The options that keep their value while locked, whatever code tries to change them.
	 *
	 * @return string[]
	 */
	private static function protected_options() {
		global $wpdb;
		return array( 'active_plugins', 'template', 'stylesheet', 'siteurl', 'home', 'admin_email', 'new_admin_email', 'users_can_register', 'default_role', $wpdb->get_blog_prefix() . 'user_roles', PNCP_OPTION, self::OPTION );
	}

	/**
	 * Keeps a protected option unchanged while locked.
	 *
	 * @param mixed  $value     New value.
	 * @param mixed  $old_value Old value.
	 * @param string $option    Option.
	 * @return mixed
	 */
	public static function keep_option( $value, $old_value, $option ) {
		if ( self::$writing || ! self::is_locked() || $value === $old_value ) {
			return $value;
		}
		self::refused( 'option:' . $option );
		return $old_value;
	}

	/**
	 * No new staff and no role changes for staff while locked (every role change ends up in
	 * {prefix}capabilities). Customers and members registering or changing between roles that are not
	 * frozen are not affected.
	 *
	 * @param null|bool $check    Short-circuit.
	 * @param int       $user_id  User.
	 * @param string    $meta_key Key.
	 * @param mixed     $value    New value.
	 * @return null|bool
	 */
	public static function keep_roles( $check, $user_id, $meta_key, $value ) {
		global $wpdb;
		if ( null !== $check || self::$writing || ! is_string( $meta_key ) || 'capabilities' !== substr( $meta_key, -12 ) || 0 !== strpos( $meta_key, $wpdb->base_prefix ) || ! self::is_locked() ) {
			return $check;
		}
		$old = get_user_meta( $user_id, $meta_key, true );
		$new = maybe_unserialize( $value );
		if ( ( ! self::grants_staff( $old ) && ! self::grants_staff( $new ) ) || self::privileged( $new ) === self::privileged( $old ) ) {
			return $check;
		}
		self::refused( 'role:' . (int) $user_id );
		return false;
	}

	/**
	 * Staff email and password stay as they are, whatever path tries to change them.
	 *
	 * @param array<string, mixed> $data   Data for the users table.
	 * @param bool                 $update Update of an existing user.
	 * @param int|null             $user_id User.
	 * @return array<string, mixed>
	 */
	public static function keep_login( $data, $update, $user_id ) {
		if ( ! $update || ! $user_id || self::$writing || ! self::is_locked() || ! self::is_staff( (int) $user_id ) ) {
			return $data;
		}
		$old = get_userdata( (int) $user_id );
		if ( $old && ( $data['user_email'] !== $old->user_email || $data['user_pass'] !== $old->user_pass ) ) {
			$data['user_email'] = $old->user_email;
			$data['user_pass']  = $old->user_pass;
			self::refused( 'login:' . (int) $user_id );
		}
		return $data;
	}

	/**
	 * No "changed" email for a staff change that keep_login() refused.
	 *
	 * @param bool                 $send Send.
	 * @param array<string, mixed> $user The user before the change.
	 * @return bool
	 */
	public static function change_email( $send, $user ) {
		return isset( $user['ID'] ) && ! self::$writing && self::is_locked() && self::is_staff( (int) $user['ID'] ) ? false : $send;
	}

	/**
	 * No "lost password" resets for staff while locked.
	 *
	 * @param bool $allow   Allowed.
	 * @param int  $user_id User.
	 * @return bool
	 */
	public static function allow_password_reset( $allow, $user_id ) {
		return self::is_locked() && self::is_staff( (int) $user_id ) ? false : $allow;
	}

	/**
	 * No new application passwords (a back door) for staff while locked.
	 *
	 * @param bool    $available Available.
	 * @param WP_User $user      User.
	 * @return bool
	 */
	public static function app_passwords( $available, $user ) {
		return $user instanceof WP_User && self::is_locked() && self::is_staff( $user->ID ) ? false : $available;
	}

	/**
	 * WooCommerce "Account details": staff cannot change their email or password there while locked.
	 *
	 * @param WP_Error $errors Errors.
	 * @param object   $user   User being saved.
	 */
	public static function woocommerce_account_errors( $errors, $user ) {
		if ( $errors instanceof WP_Error && isset( $user->ID ) && self::is_locked() && self::is_staff( (int) $user->ID ) ) {
			$errors->add( 'pncp_locked', __( 'This site is locked: account details of staff cannot be changed until an administrator unlocks it.', 'scrapelock' ) );
		}
	}

	/**
	 * WooCommerce: staff keep wp-admin and the admin bar while locked.
	 *
	 * @param bool $prevent Prevent / disable.
	 * @return bool
	 */
	public static function woocommerce_admin_access( $prevent ) {
		return $prevent && self::is_locked() && self::is_staff( get_current_user_id() ) ? false : $prevent;
	}

	/**
	 * Logs a refused change (once per request and kind).
	 *
	 * @param string $what What.
	 */
	private static function refused( $what ) {
		static $seen = array();
		if ( isset( $seen[ $what ] ) ) {
			return;
		}
		$seen[ $what ] = true;
		self::event( 'refused', $what );
	}

	/* ---------- Codes ---------- */

	/**
	 * Encrypts the secret with a key from wp-config.php (AUTH_KEY / AUTH_SALT), so a copy of the database
	 * alone does not give the codes.
	 *
	 * @param string $plain Secret.
	 * @return string
	 */
	private static function seal( $plain ) {
		if ( ! function_exists( 'sodium_crypto_secretbox' ) ) {
			return 'p:' . $plain;
		}
		$nonce = random_bytes( 24 );
		return 'v1:' . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, self::key() ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary to text.
	}

	/**
	 * Decrypts the secret ('' if it cannot: e.g. the keys in wp-config.php were changed).
	 *
	 * @param string $sealed Sealed secret.
	 * @return string
	 */
	private static function unseal( $sealed ) {
		$sealed = (string) $sealed;
		if ( 0 === strpos( $sealed, 'p:' ) ) {
			return substr( $sealed, 2 );
		}
		if ( 0 !== strpos( $sealed, 'v1:' ) || ! function_exists( 'sodium_crypto_secretbox_open' ) ) {
			return '';
		}
		$raw = base64_decode( substr( $sealed, 3 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Text to binary.
		if ( false === $raw || strlen( $raw ) < 25 ) {
			return '';
		}
		try {
			$plain = sodium_crypto_secretbox_open( substr( $raw, 24 ), substr( $raw, 0, 24 ), self::key() );
		} catch ( Exception $e ) {
			return '';
		}
		return false === $plain ? '' : $plain;
	}

	/**
	 * The encryption key.
	 *
	 * @return string 32 bytes.
	 */
	private static function key() {
		return hash( 'sha256', wp_salt( 'auth' ) . '|pncp_lockdown', true );
	}

	/**
	 * New recovery codes: shown once, stored hashed.
	 *
	 * @return string[]
	 */
	private static function new_codes() {
		$alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
		$codes    = array();
		for ( $i = 0; $i < self::CODES; $i++ ) {
			$code = '';
			for ( $j = 0; $j < 8; $j++ ) {
				$code .= $alphabet[ random_int( 0, strlen( $alphabet ) - 1 ) ];
			}
			$codes[] = substr( $code, 0, 4 ) . '-' . substr( $code, 4 );
		}
		return $codes;
	}

	/**
	 * A recovery code, hashed (bcrypt: independent of the keys in wp-config.php).
	 *
	 * @param string $code Code.
	 * @return string
	 */
	public static function hash_code( $code ) {
		return password_hash( $code, PASSWORD_DEFAULT );
	}

	/**
	 * Too many wrong codes lately?
	 *
	 * @return bool
	 */
	private static function too_many_fails() {
		return (int) get_site_transient( 'pncp_ld_fail_' . get_current_user_id() ) >= self::MAX_FAILS || (int) get_site_transient( 'pncp_ld_fail_all' ) >= self::MAX_FAILS_ALL;
	}

	/**
	 * Counts a wrong code.
	 */
	private static function failed() {
		$key  = 'pncp_ld_fail_' . get_current_user_id();
		$mine = (int) get_site_transient( $key ) + 1;
		set_site_transient( $key, $mine, 15 * MINUTE_IN_SECONDS );
		set_site_transient( 'pncp_ld_fail_all', (int) get_site_transient( 'pncp_ld_fail_all' ) + 1, HOUR_IN_SECONDS );
		self::event( 'failed' );
		if ( self::MAX_FAILS === $mine ) {
			self::mail( __( 'Too many wrong lockdown codes', 'scrapelock' ), __( 'Someone typed several wrong authenticator codes on the Lockdown page. Further attempts from that account are blocked for 15 minutes. If it was not you, change that account\'s password.', 'scrapelock' ) );
		}
	}

	/**
	 * Checks a code from the app or, if allowed, a recovery code (used up).
	 *
	 * @param string $code           Code typed.
	 * @param bool   $allow_recovery Recovery codes accepted.
	 * @return string 'app', 'recovery' or '' (wrong).
	 */
	private static function check_code( $code, $allow_recovery ) {
		// One check at a time, on the state as it is in the database now: two requests with the same code at
		// the same moment cannot both pass (the second sees the step or the recovery code already used).
		if ( ! self::lock() ) {
			return 'busy';
		}
		try {
			self::reload();
			return self::check_code_locked( $code, $allow_recovery );
		} finally {
			self::release();
		}
	}

	/**
	 * check_code(), inside the lock.
	 *
	 * @param string $code           Code typed.
	 * @param bool   $allow_recovery Recovery codes accepted.
	 * @return string 'app', 'recovery' or '' (wrong).
	 */
	private static function check_code_locked( $code, $allow_recovery ) {
		$state  = self::state();
		$secret = self::unseal( $state['secret'] );
		$step   = '' !== $secret ? PNCP_Totp::verify( $secret, $code, (int) $state['last_step'] ) : false;
		if ( false !== $step ) {
			$state['last_step'] = $step;
			self::save( $state );
			return 'app';
		}
		$typed = strtolower( preg_replace( '/[^a-z0-9]/i', '', (string) $code ) );
		if ( $allow_recovery && 8 === strlen( $typed ) ) {
			$typed = substr( $typed, 0, 4 ) . '-' . substr( $typed, 4 );
			foreach ( $state['codes'] as $i => $hash ) {
				if ( password_verify( $typed, $hash ) ) {
					unset( $state['codes'][ $i ] );
					$state['codes'] = array_values( $state['codes'] );
					self::save( $state );
					self::event( 'recovery_used' );
					self::mail( __( 'A lockdown recovery code was used', 'scrapelock' ), __( 'A recovery code was used on the Lockdown page. If it was not you, change the administrators\' passwords and create new recovery codes.', 'scrapelock' ) );
					return 'recovery';
				}
			}
		}
		return '';
	}

	/**
	 * Sets the row that holds the lock (the same place as the state: wp_options, or wp_sitemeta on
	 * multisite) to a value, optionally only while its current value is below a time: one atomic UPDATE.
	 *
	 * @param string   $value      New value.
	 * @param int|null $older_than Only if the current value is below this (null: always).
	 * @return int Rows changed.
	 */
	private static function mutex_set( $value, $older_than = null ) {
		global $wpdb;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- An atomic compare-and-set on our own row; no cache to update.
		if ( is_multisite() ) {
			$rows = null === $older_than
				? $wpdb->query( $wpdb->prepare( 'UPDATE %i SET meta_value = %s WHERE meta_key = %s AND site_id = %d', $wpdb->sitemeta, $value, self::MUTEX, get_current_network_id() ) )
				: $wpdb->query( $wpdb->prepare( 'UPDATE %i SET meta_value = %s WHERE meta_key = %s AND site_id = %d AND meta_value + 0 < %d', $wpdb->sitemeta, $value, self::MUTEX, get_current_network_id(), $older_than ) );
		} else {
			$rows = null === $older_than
				? $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s', $wpdb->options, $value, self::MUTEX ) )
				: $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value + 0 < %d', $wpdb->options, $value, self::MUTEX, $older_than ) );
		}
		// phpcs:enable
		return (int) $rows;
	}

	/**
	 * Takes the lock: an atomic UPDATE that only one request can win, valid for 10 seconds at most (so a
	 * request that dies never leaves it held). Waits up to 3 seconds for it.
	 *
	 * @return bool
	 */
	private static function lock() {
		if ( false === get_site_option( self::MUTEX, false ) ) {
			add_site_option( self::MUTEX, '0' );
		}
		for ( $i = 0; $i < 30; $i++ ) {
			$now = time();
			if ( 1 === self::mutex_set( (string) ( $now + 10 ), $now ) ) {
				return true;
			}
			usleep( 100000 );
		}
		return false;
	}

	/**
	 * Releases the lock.
	 */
	private static function release() {
		self::mutex_set( '0' );
	}

	/**
	 * Forgets the state read earlier in this request, so the next read comes from the database (or from a
	 * persistent object cache, which the request that changed it has already updated).
	 */
	private static function reload() {
		if ( is_multisite() ) {
			wp_cache_delete( get_current_network_id() . ':' . self::OPTION, 'site-options' );
		} else {
			wp_cache_delete( self::OPTION, 'options' );
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( 'notoptions', 'options' );
		}
		self::$state = null;
	}

	/* ---------- Log and email ---------- */

	/**
	 * Adds an event to the lockdown log (the last 30).
	 *
	 * @param string $event  Event.
	 * @param string $detail Detail.
	 */
	private static function event( $event, $detail = '' ) {
		$user = wp_get_current_user();
		$log  = get_site_option( self::LOG_OPTION, array() );
		$log  = is_array( $log ) ? $log : array();
		array_unshift(
			$log,
			array(
				'time'   => time(),
				'event'  => $event,
				'detail' => $detail,
				'user'   => $user->exists() ? $user->user_login : '',
				'ip'     => PNCP_Ip::client_ip(),
			)
		);
		update_site_option( self::LOG_OPTION, array_slice( $log, 0, 30 ) );
	}

	/**
	 * Adds an event of another part of ScrapeLock (file integrity) to the lockdown log.
	 *
	 * @param string $event  Event.
	 * @param string $detail Detail.
	 */
	public static function record( $event, $detail = '' ) {
		self::event( $event, $detail );
	}

	/**
	 * Is "Quarantine" on (file integrity)?
	 *
	 * @return bool
	 */
	public static function quarantine_on() {
		return ! empty( self::state()['quarantine'] );
	}

	/**
	 * Deactivates plugins whose files changed while the site was locked ("Quarantine"). The list of active
	 * plugins is otherwise frozen while locked; deactivating only takes something away, and ScrapeLock itself
	 * is never in the list.
	 *
	 * @param string[] $files Plugin files (folder/file.php).
	 */
	public static function deactivate_for_quarantine( $files ) {
		$own   = plugin_basename( PNCP_FILE );
		$files = array_values( array_diff( array_map( 'strval', (array) $files ), array( $own ) ) );
		if ( ! $files ) {
			return;
		}
		if ( ! function_exists( 'deactivate_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		self::$writing = true;
		deactivate_plugins( $files, true );
		self::$writing = false;
	}

	/**
	 * Emails the site's administration address.
	 *
	 * @param string $subject Subject.
	 * @param string $message Message.
	 */
	private static function mail( $subject, $message ) {
		$user = wp_get_current_user();
		$to   = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
		if ( ! is_email( $to ) ) {
			return;
		}
		$body = $message . "\n\n"
			/* translators: %s: user name */
			. sprintf( __( 'User: %s', 'scrapelock' ), $user->exists() ? $user->user_login : '-' ) . "\n"
			/* translators: %s: IP address */
			. sprintf( __( 'IP: %s', 'scrapelock' ), PNCP_Ip::client_ip() ) . "\n"
			. self::page_url() . "\n";
		wp_mail( $to, '[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] ScrapeLock: ' . $subject, $body );
	}

	/* ---------- wp-admin ---------- */

	/**
	 * The Lockdown tab of the ScrapeLock page (reachable for administrators also while locked).
	 *
	 * @param array<string, string> $args Query arguments.
	 * @return string
	 */
	public static function page_url( $args = array() ) {
		return PNCP_Status::settings_url( array_merge( array( 'tab' => 'lockdown' ), $args ) );
	}

	/**
	 * Is this the Lockdown tab? (While locked, the ScrapeLock page shows only that tab.)
	 *
	 * @return bool
	 */
	public static function on_tab() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects a tab.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		return $screen && 'settings_page_' . PNCP_Admin::PAGE === $screen->id && ( 'lockdown' === $tab || self::is_locked() );
	}

	/**
	 * QR code and code field scripts on the Lockdown tab.
	 *
	 * @param string $hook Page hook.
	 */
	public static function assets( $hook ) {
		if ( 'settings_page_' . PNCP_Admin::PAGE !== $hook || ! self::on_tab() ) {
			return;
		}
		wp_enqueue_script( 'pncp-qrcode', PNCP_URL . 'assets/js/vendor/qrcode.js', array(), '1.4.4', true );
		wp_enqueue_script( 'pncp-lockdown', PNCP_URL . 'assets/js/lockdown.js', array( 'pncp-qrcode' ), PNCP_VERSION, true );
	}

	/**
	 * Notices: to staff while locked, to administrators while unlocked for a while or unlocked from the server.
	 */
	public static function notices() {
		if ( self::on_tab() ) {
			return;
		}
		$user  = get_current_user_id();
		$owner = self::is_owner( $user );
		if ( self::server_unlocked() && $owner ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'ScrapeLock Lockdown is off from the server: SCRAPELOCK_UNLOCK is set in wp-config.php. Remove that line as soon as you can.', 'scrapelock' ) . '</p></div>';
			return;
		}
		if ( self::is_locked() && self::is_staff( $user ) ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'This site is locked.', 'scrapelock' ) . '</strong> ' . esc_html__( 'Changes from wp-admin are disabled until an administrator unlocks the site with the authenticator app.', 'scrapelock' );
			if ( $owner ) {
				echo ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Unlock', 'scrapelock' ) . '</a>';
			}
			echo '</p></div>';
			return;
		}
		$until = self::unlocked_until();
		if ( $until && $owner ) {
			/* translators: %s: time */
			echo '<div class="notice notice-info"><p>' . esc_html( sprintf( __( 'The site is unlocked until %s, then it locks again by itself.', 'scrapelock' ), wp_date( (string) get_option( 'time_format' ), $until ) ) ) . ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Lock now', 'scrapelock' ) . '</a></p></div>';
		}
	}

	/**
	 * While locked, "Sorry, you are not allowed to…" in wp-admin says why: the site is locked. Only the HTML
	 * handler: AJAX, JSON and XML-RPC answers stay as they are.
	 *
	 * @param callable $handler The wp_die() handler.
	 * @return callable
	 */
	public static function die_handler( $handler ) {
		self::$die_handler = $handler;
		return array( __CLASS__, 'die_locked' );
	}

	/**
	 * Shows a "the site is locked" page instead of WordPress' bare "Sorry, you are not allowed to…": what is
	 * going on, and for administrators the Unlock button (other staff see that the site is locked, not where
	 * it is unlocked). WordPress' own message stays under "Technical detail". Then hands over to the previous
	 * handler, which prints the page.
	 *
	 * @param string|WP_Error      $message Message.
	 * @param string|int           $title   Title.
	 * @param array<string, mixed> $args    Arguments.
	 */
	public static function die_locked( $message, $title = '', $args = array() ) {
		$user = get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification -- Only skips the page for the lock's own pages.
		$own = self::on_tab() || ( isset( $_REQUEST['action'] ) && self::ACTION === $_REQUEST['action'] );
		if ( $user && ! $own && self::is_locked() && self::is_staff( $user ) ) {
			$detail  = is_wp_error( $message ) ? $message->get_error_message() : (string) $message;
			$message = self::locked_page( self::is_owner( $user ), $detail );
			$title   = __( 'The site is locked', 'scrapelock' );
			if ( is_array( $args ) && empty( $args['response'] ) ) {
				$args['response'] = 403;
			}
		}
		$handler = is_callable( self::$die_handler ) ? self::$die_handler : '_default_wp_die_handler';
		call_user_func( $handler, $message, $title, $args );
	}

	/**
	 * The "site is locked" page (inside WordPress' error page).
	 *
	 * @param bool   $owner  Administrator: show the Unlock button.
	 * @param string $detail WordPress' message (already HTML from core).
	 * @return string HTML.
	 */
	private static function locked_page( $owner, $detail ) {
		$lock  = '<svg viewBox="0 0 24 24" width="40" height="40" aria-hidden="true" focusable="false"><path fill="currentColor" d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5zm-3 5a3 3 0 1 1 6 0v3H9V7zm3 7a1.5 1.5 0 0 1 .75 2.8V18a.75.75 0 0 1-1.5 0v-1.2A1.5 1.5 0 0 1 12 14z"/></svg>';
		$style = '<style>'
			. '.pncp-locked{text-align:center;padding:8px 0 4px}'
			. '.pncp-locked-icon{display:inline-flex;align-items:center;justify-content:center;width:72px;height:72px;border-radius:50%;background:#fcf0e3;color:#b26200;margin-bottom:4px}'
			. '#error-page .pncp-locked h1{border:0;margin:12px 0 0;padding:0;font-size:22px;line-height:1.3;color:#1d2327}'
			. '#error-page .pncp-locked p{margin:12px auto;max-width:520px;font-size:14px;line-height:1.6;color:#3c434a}'
			. '#error-page .pncp-locked .pncp-locked-actions{margin-top:24px}'
			. '.pncp-locked-btn{display:inline-block;background:#2271b1;color:#fff!important;border-radius:4px;padding:10px 22px;font-size:14px;font-weight:600;text-decoration:none;margin:0 6px 8px}'
			. '.pncp-locked-btn:hover,.pncp-locked-btn:focus{background:#135e96}'
			. '.pncp-locked-link{display:inline-block;margin:0 6px 8px;padding:10px 4px;font-size:14px;color:#2271b1}'
			. '.pncp-locked details{margin:20px auto 0;max-width:520px;text-align:left;font-size:12px;color:#646970}'
			. '.pncp-locked summary{cursor:pointer}'
			. '#error-page .pncp-locked details p{font-size:12px;margin:8px 0 0;color:#646970}'
			. '</style>';
		$html  = $style . '<div class="pncp-locked">'
			. '<div class="pncp-locked-icon">' . $lock . '</div>'
			. '<h1>' . esc_html__( 'The site is locked', 'scrapelock' ) . '</h1>'
			. '<p>' . esc_html__( 'ScrapeLock Lockdown is on, so nothing can be changed right now: plugins, themes, users, settings and content are frozen. This keeps the site safe even if someone has stolen a password.', 'scrapelock' ) . '</p>'
			. '<p>' . ( $owner
				? esc_html__( 'To make this change, unlock the site with the code from your authenticator app, then lock it again when you are done.', 'scrapelock' )
				: esc_html__( 'To make this change, ask an administrator to unlock the site.', 'scrapelock' ) ) . '</p>'
			. '<p class="pncp-locked-actions">'
			. ( $owner ? '<a class="pncp-locked-btn" href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Unlock the site', 'scrapelock' ) . '</a>' : '' )
			. '<a class="pncp-locked-link" href="' . esc_url( admin_url() ) . '">' . esc_html__( 'Back to the Dashboard', 'scrapelock' ) . '</a>'
			. '</p>';
		if ( '' !== trim( wp_strip_all_tags( $detail ) ) ) {
			$html .= '<details><summary>' . esc_html__( 'Technical detail', 'scrapelock' ) . '</summary><p>' . wp_kses_post( $detail ) . '</p></details>';
		}
		return $html . '</div>';
	}

	/**
	 * Updates waiting (they cannot be installed while locked).
	 *
	 * @return int
	 */
	private static function pending_updates() {
		$count = 0;
		foreach ( array( 'update_plugins', 'update_themes' ) as $key ) {
			$data   = get_site_transient( $key );
			$count += is_object( $data ) && ! empty( $data->response ) ? count( (array) $data->response ) : 0;
		}
		$core = get_site_transient( 'update_core' );
		if ( is_object( $core ) && ! empty( $core->updates ) ) {
			foreach ( $core->updates as $update ) {
				if ( isset( $update->response ) && 'upgrade' === $update->response ) {
					++$count;
					break;
				}
			}
		}
		return $count;
	}

	/**
	 * A form to admin-post with nonce and operation.
	 *
	 * @param string $op Operation.
	 */
	private static function form_open( $op ) {
		printf( '<form method="post" action="%s" class="pncp-ld-form">', esc_url( admin_url( 'admin-post.php' ) ) );
		printf( '<input type="hidden" name="action" value="%s"><input type="hidden" name="op" value="%s">', esc_attr( self::ACTION ), esc_attr( $op ) );
		wp_nonce_field( self::ACTION );
	}

	/**
	 * The code field.
	 *
	 * @param bool $recovery Recovery codes accepted.
	 */
	private static function code_field( $recovery = false ) {
		printf(
			'<p><label for="pncp-ld-code-%1$s">%2$s</label><br><input type="text" id="pncp-ld-code-%1$s" name="code" class="regular-text pncp-ld-code" autocomplete="one-time-code" inputmode="%3$s" required></p>',
			esc_attr( wp_unique_id() ),
			$recovery ? esc_html__( 'Code from the authenticator app (or a recovery code)', 'scrapelock' ) : esc_html__( 'Code from the authenticator app', 'scrapelock' ),
			$recovery ? 'text' : 'numeric'
		);
	}

	/**
	 * The Lockdown tab.
	 */
	public static function render_tab() {
		if ( ! self::is_owner( get_current_user_id() ) ) {
			wp_die( esc_html__( 'Only administrators can lock and unlock the site.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		$state   = self::state();
		$pending = (string) get_user_meta( get_current_user_id(), self::PENDING_META, true );
		$fmt     = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		?>
		<div class="pncp-ld">
			<p class="pncp-ld-intro"><?php esc_html_e( 'While the site is locked, nobody can change it from wp-admin, the REST API or XML-RPC, not even an administrator or someone who stole a password: no plugins, themes or updates, no file editing, no new users or role changes, no settings, no content changes. Visitors and customers are not affected. Locking and unlocking need a code from your authenticator app.', 'scrapelock' ); ?></p>
			<?php
			self::render_message();
			if ( self::server_unlocked() ) {
				echo '<div class="notice notice-error inline"><p><strong>' . esc_html__( 'Unlocked from the server.', 'scrapelock' ) . '</strong> ' . esc_html__( 'SCRAPELOCK_UNLOCK is set in wp-config.php, so the lock is not applied. You can remove the authenticator below and connect a new one; then remove that line from wp-config.php.', 'scrapelock' ) . '</p></div>';
			}
			if ( $state['secret'] && '' === self::unseal( $state['secret'] ) ) {
				echo '<div class="notice notice-error inline"><p>' . esc_html__( 'The app secret cannot be read: the security keys in wp-config.php have changed. Unlock with a recovery code, or from the server, then connect the app again.', 'scrapelock' ) . '</p></div>';
			}
			$codes = get_site_transient( 'pncp_ld_codes_' . get_current_user_id() );
			if ( is_array( $codes ) ) {
				delete_site_transient( 'pncp_ld_codes_' . get_current_user_id() );
				self::render_codes( $codes );
			}
			if ( ! self::is_locked() ) {
				self::render_warning();
			}
			if ( ! self::configured() && '' !== $pending ) {
				self::render_pending( self::unseal( $pending ) );
			} elseif ( ! self::configured() ) {
				self::render_setup();
			} else {
				self::render_status( $state, $fmt );
				PNCP_Integrity::render( $fmt );
				if ( ! self::is_locked() ) {
					self::render_quarantine( $state );
				}
			}
			self::render_report();
			self::render_log( $fmt );
			?>
		</div>
		<?php
	}

	/**
	 * The result of the last action.
	 */
	private static function render_message() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects a message.
		$code     = isset( $_GET['pncp_ld'] ) ? sanitize_key( wp_unslash( $_GET['pncp_ld'] ) ) : '';
		$messages = array(
			'connected' => array( 'success', __( 'The authenticator app is connected. You can lock the site now.', 'scrapelock' ) ),
			'locked'    => array( 'success', __( 'The site is locked.', 'scrapelock' ) ),
			'unlocked'  => array( 'success', __( 'The site is unlocked.', 'scrapelock' ) ),
			'codes'     => array( 'success', __( 'New recovery codes created. The old ones no longer work.', 'scrapelock' ) ),
			'removed'   => array( 'success', __( 'The authenticator app was removed and the lock is off.', 'scrapelock' ) ),
			'cancelled' => array( 'info', __( 'Setup cancelled.', 'scrapelock' ) ),
			'wrong'     => array( 'error', __( 'Wrong or expired code. Wait for a new code in the app and try again.', 'scrapelock' ) ),
			'wait'      => array( 'error', __( 'Too many wrong codes. Try again in 15 minutes.', 'scrapelock' ) ),
			'error'     => array( 'error', __( 'That action is not possible right now.', 'scrapelock' ) ),
			'roles'     => array( 'success', __( 'The frozen roles were saved.', 'scrapelock' ) ),
			'integrity' => array( 'success', __( 'The file integrity check is done.', 'scrapelock' ) ),
			'quarantine' => array( 'success', __( 'The quarantine setting was saved.', 'scrapelock' ) ),
			'ack'       => array( 'error', __( 'Tick the box to confirm that you have saved your recovery codes and understand how to unlock the site.', 'scrapelock' ) ),
		);
		if ( isset( $messages[ $code ] ) ) {
			printf( '<div class="notice notice-%s inline"><p>%s</p></div>', esc_attr( $messages[ $code ][0] ), esc_html( $messages[ $code ][1] ) );
		}
	}

	/**
	 * Before locking: there is a single way to unlock.
	 */
	private static function render_warning() {
		?>
		<div class="pncp-ld-box pncp-ld-warning" role="note">
			<h2><span class="dashicons dashicons-warning" aria-hidden="true"></span> <?php esc_html_e( 'Important: there is only one way to unlock', 'scrapelock' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'Only the 6-digit code from the authenticator app on your phone unlocks the site. There is no reset by email or SMS, no "forgot code" link, and no other administrator, your hosting company or ScrapeLock support can unlock it from WordPress.', 'scrapelock' ); ?></li>
				<li><?php esc_html_e( 'Backup: the 10 recovery codes shown once when you connect the app. Print them and keep them away from the phone; each one unlocks the site once.', 'scrapelock' ); ?></li>
				<li><?php esc_html_e( 'Lost both the phone and the recovery codes? Only someone with access to the server files (FTP or your hosting panel) can unlock the site, by adding a line to wp-config.php.', 'scrapelock' ); ?></li>
				<li><?php esc_html_e( 'While locked, password resets for staff are frozen too: if you forget your WordPress password, the same line in wp-config.php is the way back.', 'scrapelock' ); ?></li>
			</ul>
		</div>
		<?php
	}

	/**
	 * The full report: what the lock freezes, what keeps working, and who it applies to on this site.
	 */
	private static function render_report() {
		$counts       = count_users();
		$frozen_roles = self::frozen_roles();
		$staff        = array();
		$open_roles   = array();
		$names        = wp_roles()->get_names();
		foreach ( $counts['avail_roles'] as $role => $count ) {
			if ( ! $count || 'none' === $role ) {
				continue;
			}
			$label = sprintf( '%s: %d', isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : $role, $count );
			if ( in_array( $role, $frozen_roles, true ) ) {
				$staff[] = $label;
			} else {
				$open_roles[] = $label;
			}
		}
		$theme   = wp_get_theme();
		$plugins = count( (array) get_option( 'active_plugins', array() ) ) + count( (array) get_site_option( 'active_sitewide_plugins', array() ) );
		$frozen  = array(
			__( 'Plugins', 'scrapelock' )          => array(
				__( 'Installing, uploading a zip, updating, deleting, activating and deactivating plugins, including ScrapeLock itself.', 'scrapelock' ),
				__( 'Automatic plugin updates.', 'scrapelock' ),
			),
			__( 'Themes', 'scrapelock' )           => array(
				__( 'Installing, updating, deleting and switching themes; automatic theme updates.', 'scrapelock' ),
				__( 'The Customizer, the Site Editor, menus and widgets.', 'scrapelock' ),
			),
			__( 'WordPress', 'scrapelock' )        => array(
				__( 'WordPress core updates, automatic updates and translation updates.', 'scrapelock' ),
				__( 'The plugin and theme file editor: no file can be changed through WordPress.', 'scrapelock' ),
			),
			__( 'Users', 'scrapelock' )            => array(
				__( 'Creating, deleting and editing users; changing roles; creating administrators, also by code.', 'scrapelock' ),
				__( 'Staff email and password changes, "lost password" resets for staff, and new application passwords for staff. Existing application passwords of staff stop working.', 'scrapelock' ),
			),
			__( 'Settings', 'scrapelock' )         => array(
				__( 'Every settings page (General, Reading, Permalinks, WooCommerce, other plugins) and the ScrapeLock settings.', 'scrapelock' ),
				__( 'Also by code: active plugins, theme, site address, admin email, registration, default role, role definitions, ScrapeLock settings and the lock itself.', 'scrapelock' ),
			),
			__( 'Content', 'scrapelock' )          => array(
				__( 'Creating, editing and deleting posts, pages, products, coupons, categories and media; comment moderation.', 'scrapelock' ),
				__( 'Orders in wp-admin: staff cannot process them while locked.', 'scrapelock' ),
			),
			__( 'Where it applies', 'scrapelock' ) => array(
				__( 'wp-admin, admin-ajax, the REST API (also WooCommerce REST API keys of staff, e.g. an ERP that writes stock), XML-RPC, application passwords, and the code of other plugins for the protected items above.', 'scrapelock' ),
			),
		);
		$open    = array(
			__( 'Visitors browse the site; search engines and the bots you allow are not affected.', 'scrapelock' ),
			__( 'Customers order and pay, register, log in, edit their own account and reset their own password.', 'scrapelock' ),
			__( 'Comments from visitors, payment webhooks, cron jobs and the scheduled tasks of plugins.', 'scrapelock' ),
			__( 'Logging in (also for staff, who then only see the dashboard); the ScrapeLock bot protection and firewalls such as Wordfence.', 'scrapelock' ),
			__( 'Read-only XML feeds with a ScrapeLock token.', 'scrapelock' ),
		);
		?>
		<div class="pncp-ld-box pncp-ld-report">
			<h2><?php esc_html_e( 'What exactly is locked', 'scrapelock' ); ?></h2>
			<table class="widefat striped pncp-ld-report-table">
				<tbody>
					<?php foreach ( $frozen as $area => $items ) : ?>
						<tr>
							<th scope="row"><?php echo esc_html( $area ); ?></th>
							<td><ul>
								<?php foreach ( $items as $item ) : ?>
									<li><span class="dashicons dashicons-lock" aria-hidden="true"></span> <?php echo esc_html( $item ); ?></li>
								<?php endforeach; ?>
							</ul></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<h3><?php esc_html_e( 'What keeps working', 'scrapelock' ); ?></h3>
			<ul class="pncp-ld-open">
				<?php foreach ( $open as $item ) : ?>
					<li><span class="dashicons dashicons-yes" aria-hidden="true"></span> <?php echo esc_html( $item ); ?></li>
				<?php endforeach; ?>
			</ul>
			<h3><?php esc_html_e( 'On this site', 'scrapelock' ); ?></h3>
			<ul class="pncp-ld-site">
				<?php /* translators: %s: roles and number of users, e.g. "Administrator: 2, Editor: 1" */ ?>
				<li><?php echo esc_html( sprintf( __( 'Staff accounts that keep only "read" while locked: %s.', 'scrapelock' ), $staff ? implode( ', ', $staff ) : __( 'none', 'scrapelock' ) ) ); ?></li>
				<?php /* translators: %s: roles and number of users, e.g. "Subscriber: 120, Customer: 3000" */ ?>
				<li><?php echo esc_html( sprintf( __( 'Accounts that keep working as usual while locked: %s.', 'scrapelock' ), $open_roles ? implode( ', ', $open_roles ) : __( 'none', 'scrapelock' ) ) ); ?></li>
				<?php /* translators: 1: number of plugins, 2: theme name */ ?>
				<li><?php echo esc_html( sprintf( _n( '%1$d active plugin and the theme "%2$s" stay exactly as they are.', '%1$d active plugins and the theme "%2$s" stay exactly as they are.', $plugins, 'scrapelock' ), $plugins, $theme->get( 'Name' ) ) ); ?></li>
				<li><?php esc_html_e( 'Not covered: whoever can change the files or the database on the server (FTP, hosting panel, WP-CLI) controls the site with or without the lock.', 'scrapelock' ); ?></li>
			</ul>
		</div>
		<?php
	}

	/**
	 * Step 1: start connecting the app.
	 */
	private static function render_setup() {
		?>
		<div class="pncp-ld-box">
			<h2><?php esc_html_e( 'Connect an authenticator app', 'scrapelock' ); ?></h2>
			<p><?php esc_html_e( 'Install an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, Authy, 1Password or similar). Then click the button: a QR code appears for the app to scan.', 'scrapelock' ); ?></p>
			<?php
			self::form_open( 'setup' );
			submit_button( __( 'Connect the app', 'scrapelock' ), 'primary', 'submit', false );
			echo '</form>';
			?>
		</div>
		<?php
	}

	/**
	 * Step 2: scan the QR code and confirm with a code.
	 *
	 * @param string $secret Pending secret.
	 */
	private static function render_pending( $secret ) {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		?>
		<div class="pncp-ld-box">
			<h2><?php esc_html_e( 'Scan the QR code', 'scrapelock' ); ?></h2>
			<p><?php esc_html_e( 'In the app, add an account and scan this code. The QR code is created in your browser: the secret is not sent anywhere.', 'scrapelock' ); ?></p>
			<div class="pncp-ld-qr" data-pncp-qr="<?php echo esc_attr( PNCP_Totp::uri( $secret, $host, 'ScrapeLock' ) ); ?>"></div>
			<p><?php esc_html_e( 'Cannot scan? Type this key in the app instead:', 'scrapelock' ); ?><br><code class="pncp-ld-secret"><?php echo esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ); ?></code></p>
			<?php
			self::form_open( 'confirm' );
			self::code_field();
			submit_button( __( 'Confirm', 'scrapelock' ), 'primary', 'submit', false );
			echo '</form>';
			self::form_open( 'cancel' );
			submit_button( __( 'Cancel', 'scrapelock' ), 'link', 'submit', false );
			echo '</form>';
			?>
		</div>
		<?php
	}

	/**
	 * Recovery codes, once.
	 *
	 * @param string[] $codes Codes.
	 */
	private static function render_codes( $codes ) {
		?>
		<div class="pncp-ld-box pncp-ld-codes">
			<h2><?php esc_html_e( 'Your recovery codes', 'scrapelock' ); ?></h2>
			<p><strong><?php esc_html_e( 'Print them or keep them somewhere safe, away from your phone. They are shown only now.', 'scrapelock' ); ?></strong> <?php esc_html_e( 'If you lose your phone, each code unlocks the site once.', 'scrapelock' ); ?></p>
			<ul class="pncp-ld-code-list">
				<?php foreach ( $codes as $code ) : ?>
					<li><code><?php echo esc_html( $code ); ?></code></li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php
	}

	/**
	 * Locked / unlocked, and the actions.
	 *
	 * @param array<string, mixed> $state State.
	 * @param string               $fmt   Date format.
	 */
	private static function render_status( $state, $fmt ) {
		$locked  = self::is_locked();
		$until   = self::unlocked_until();
		$updates = self::pending_updates();
		?>
		<div class="pncp-ld-box pncp-ld-status <?php echo $locked ? 'is-locked' : 'is-open'; ?>">
			<h2>
				<span class="dashicons dashicons-<?php echo $locked ? 'lock' : 'unlock'; ?>" aria-hidden="true"></span>
				<?php
				if ( $locked ) {
					esc_html_e( 'The site is locked', 'scrapelock' );
				} elseif ( $until ) {
					/* translators: %s: time */
					echo esc_html( sprintf( __( 'Unlocked until %s', 'scrapelock' ), wp_date( (string) get_option( 'time_format' ), $until ) ) );
				} else {
					esc_html_e( 'The site is not locked', 'scrapelock' );
				}
				?>
			</h2>
			<?php if ( $locked && $state['since'] ) : ?>
				<?php /* translators: %s: date and time */ ?>
				<p><?php echo esc_html( sprintf( __( 'Locked since %s.', 'scrapelock' ), wp_date( $fmt, (int) $state['since'] ) ) ); ?></p>
			<?php endif; ?>
			<?php if ( $updates ) : ?>
				<?php /* translators: %d: number of updates */ ?>
				<p class="pncp-ld-updates"><?php echo esc_html( sprintf( _n( '%d update is waiting. Unlock for a while to install it, then lock again.', '%d updates are waiting. Unlock for a while to install them, then lock again.', $updates, 'scrapelock' ), $updates ) ); ?></p>
			<?php endif; ?>
			<?php
			if ( $locked ) {
				self::form_open( 'unlock' );
				self::code_field( true );
				echo '<p><label for="pncp-ld-minutes">' . esc_html__( 'Unlock for', 'scrapelock' ) . '</label><br><select id="pncp-ld-minutes" name="minutes">';
				foreach ( array(
					15  => __( '15 minutes', 'scrapelock' ),
					30  => __( '30 minutes', 'scrapelock' ),
					60  => __( '1 hour', 'scrapelock' ),
					120 => __( '2 hours', 'scrapelock' ),
					0   => __( 'Until I lock it again', 'scrapelock' ),
				) as $minutes => $label ) {
					printf( '<option value="%d"%s>%s</option>', (int) $minutes, selected( 30, $minutes, false ), esc_html( $label ) );
				}
				echo '</select></p>';
				submit_button( __( 'Unlock', 'scrapelock' ), 'primary', 'submit', false );
				echo '</form>';
			} elseif ( $until ) {
				self::form_open( 'relock' );
				submit_button( __( 'Lock again now', 'scrapelock' ), 'primary', 'submit', false );
				echo '</form>';
			} elseif ( ! self::server_unlocked() ) {
				self::form_open( 'lock' );
				self::code_field();
				if ( empty( $state['ack'] ) ) {
					echo '<p><label><input type="checkbox" name="ack" value="1" required> ' . esc_html__( 'I have printed or saved my recovery codes, and I understand that only the app, a recovery code or access to the server files can unlock the site.', 'scrapelock' ) . '</label></p>';
				}
				submit_button( __( 'Lock the site', 'scrapelock' ), 'primary', 'submit', false );
				echo '</form>';
			}
			?>
		</div>
		<?php if ( ! $locked ) : ?>
			<?php self::render_roles(); ?>
			<div class="pncp-ld-box">
				<h2><?php esc_html_e( 'Recovery codes and app', 'scrapelock' ); ?></h2>
				<?php /* translators: %d: number of codes */ ?>
				<p><?php echo esc_html( sprintf( _n( '%d recovery code left.', '%d recovery codes left.', count( $state['codes'] ), 'scrapelock' ), count( $state['codes'] ) ) ); ?></p>
				<?php
				self::form_open( 'codes' );
				self::code_field();
				submit_button( __( 'Create new recovery codes', 'scrapelock' ), 'secondary', 'submit', false );
				echo '</form>';
				if ( ! $until ) {
					echo '<hr>';
					self::form_open( 'remove' );
					if ( ! self::server_unlocked() ) {
						self::code_field();
					}
					submit_button( __( 'Remove the authenticator app', 'scrapelock' ), 'delete', 'submit', false );
					echo '</form>';
				}
				?>
			</div>
		<?php endif; ?>
		<?php if ( $locked ) : ?>
		<div class="pncp-ld-box">
			<h2><?php esc_html_e( 'Lost your phone?', 'scrapelock' ); ?></h2>
			<p><?php esc_html_e( 'Type one of your recovery codes in the unlock field instead of an app code. No codes left? Add this line to wp-config.php (FTP or your hosting panel), then remove the app here and connect a new one:', 'scrapelock' ); ?></p>
			<p><code>define( 'SCRAPELOCK_UNLOCK', true );</code></p>
		</div>
		<?php endif; ?>
		<?php
	}

	/**
	 * Which roles are frozen while locked: every role with its number of users, ticked if frozen. Roles that
	 * can take over the site are always ticked.
	 */
	private static function render_roles() {
		$counts = count_users();
		$frozen = self::frozen_roles();
		?>
		<div class="pncp-ld-box pncp-ld-roles">
			<h2><?php esc_html_e( 'Who is frozen while locked', 'scrapelock' ); ?></h2>
			<p><?php esc_html_e( 'Ticked roles keep only "read" while the site is locked. Untick the roles of your members or customers if they create content on the site themselves (listings, community posts): they then keep working as usual, including their own email and password. Roles that can change plugins, themes, users or settings are always frozen.', 'scrapelock' ); ?></p>
			<?php self::form_open( 'roles' ); ?>
			<input type="hidden" name="roles[]" value="">
			<ul class="pncp-ld-role-list">
				<?php foreach ( wp_roles()->get_names() as $role => $name ) : ?>
					<?php
					$always = self::role_always( $role );
					$count  = isset( $counts['avail_roles'][ $role ] ) ? (int) $counts['avail_roles'][ $role ] : 0;
					?>
					<li>
						<label>
							<input type="checkbox" name="roles[]" value="<?php echo esc_attr( $role ); ?>"<?php checked( in_array( $role, $frozen, true ) ); ?><?php disabled( $always ); ?>>
							<?php
							/* translators: 1: role name, 2: number of users */
							echo esc_html( sprintf( _n( '%1$s (%2$d user)', '%1$s (%2$d users)', $count, 'scrapelock' ), translate_user_role( $name ), $count ) );
							if ( $always ) {
								echo ' <span class="description">' . esc_html__( 'always frozen', 'scrapelock' ) . '</span>';
							}
							?>
						</label>
					</li>
				<?php endforeach; ?>
			</ul>
			<?php
			self::code_field();
			submit_button( __( 'Save frozen roles', 'scrapelock' ), 'secondary', 'submit', false );
			echo '</form>';
			?>
		</div>
		<?php
	}

	/**
	 * "Quarantine" for the file integrity check: saved with the app code, only while not locked (like the roles).
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function render_quarantine( $state ) {
		?>
		<div class="pncp-ld-box pncp-ld-quarantine">
			<h2><?php esc_html_e( 'Quarantine', 'scrapelock' ); ?></h2>
			<?php self::form_open( 'quarantine' ); ?>
			<p><label><input type="checkbox" name="quarantine" value="1"<?php checked( ! empty( $state['quarantine'] ) ); ?>> <?php esc_html_e( 'When files change while the site is locked: deactivate the plugin they belong to, and rename new PHP files in the uploads folder so they no longer run', 'scrapelock' ); ?></label></p>
			<p class="description"><?php esc_html_e( 'Nothing is deleted. A deactivated plugin may be one your site needs (for example the shop or the forms), so it stays off until you check it, unlock and activate it again. ScrapeLock itself is never deactivated. Off by default: you are emailed either way.', 'scrapelock' ); ?></p>
			<?php
			self::code_field();
			submit_button( __( 'Save quarantine', 'scrapelock' ), 'secondary', 'submit', false );
			echo '</form>';
			?>
		</div>
		<?php
	}

	/**
	 * The lockdown log.
	 *
	 * @param string $fmt Date format.
	 */
	private static function render_log( $fmt ) {
		$log = get_site_option( self::LOG_OPTION, array() );
		if ( ! is_array( $log ) || ! $log ) {
			return;
		}
		$labels = array(
			'connected'     => __( 'App connected', 'scrapelock' ),
			'locked'        => __( 'Locked', 'scrapelock' ),
			'unlocked'      => __( 'Unlocked', 'scrapelock' ),
			'relocked'      => __( 'Locked again', 'scrapelock' ),
			'failed'        => __( 'Wrong code', 'scrapelock' ),
			'recovery_used' => __( 'Recovery code used', 'scrapelock' ),
			'codes'         => __( 'New recovery codes', 'scrapelock' ),
			'removed'       => __( 'App removed', 'scrapelock' ),
			'refused'       => __( 'Change refused', 'scrapelock' ),
			'roles'         => __( 'Frozen roles changed', 'scrapelock' ),
			'integrity'     => __( 'Changed files found', 'scrapelock' ),
			'quarantine'    => __( 'Quarantine', 'scrapelock' ),
			'quarantine_setting' => __( 'Quarantine setting', 'scrapelock' ),
		);
		?>
		<h2><?php esc_html_e( 'Recent lockdown events', 'scrapelock' ); ?></h2>
		<table class="widefat striped pncp-ld-log">
			<thead><tr><th><?php esc_html_e( 'When', 'scrapelock' ); ?></th><th><?php esc_html_e( 'Event', 'scrapelock' ); ?></th><th><?php esc_html_e( 'User', 'scrapelock' ); ?></th><th><?php esc_html_e( 'IP', 'scrapelock' ); ?></th></tr></thead>
			<tbody>
				<?php foreach ( $log as $row ) : ?>
					<tr>
						<td><?php echo esc_html( wp_date( $fmt, (int) $row['time'] ) ); ?></td>
						<td><?php echo esc_html( ( isset( $labels[ $row['event'] ] ) ? $labels[ $row['event'] ] : $row['event'] ) . ( '' !== $row['detail'] ? ' (' . $row['detail'] . ')' : '' ) ); ?></td>
						<td><?php echo esc_html( $row['user'] ); ?></td>
						<td><?php echo esc_html( $row['ip'] ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/* ---------- Actions ---------- */

	/**
	 * Back to the page with a message.
	 *
	 * @param string $message Message code.
	 */
	private static function back( $message ) {
		wp_safe_redirect( self::page_url( array( 'pncp_ld' => $message ) ) );
		exit;
	}

	/**
	 * Locks, unlocks, connects and removes the app.
	 */
	public static function handle() {
		$user = get_current_user_id();
		if ( ! self::is_owner( $user ) ) {
			wp_die( esc_html__( 'Only administrators can lock and unlock the site.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked above.
		$op   = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$mins = isset( $_POST['minutes'] ) ? absint( $_POST['minutes'] ) : 30;
		$ack  = ! empty( $_POST['ack'] );
		$pick = isset( $_POST['roles'] ) && is_array( $_POST['roles'] ) ? array_filter( array_map( 'sanitize_key', wp_unslash( $_POST['roles'] ) ) ) : array();
		// phpcs:enable
		$state = self::state();

		if ( 'relock' === $op ) {
			// Locking again needs no code: it only makes the site safer.
			if ( ! self::unlocked_until() ) {
				self::back( 'error' );
			}
			$state['until'] = 0;
			self::save( $state );
			self::event( 'relocked' );
			PNCP_Integrity::snapshot(); // Updates may have run while it was open: a new fingerprint.
			self::back( 'locked' );
		}
		if ( 'cancel' === $op ) {
			delete_user_meta( $user, self::PENDING_META );
			self::back( 'cancelled' );
		}
		if ( 'setup' === $op ) {
			if ( self::configured() ) {
				self::back( 'error' );
			}
			update_user_meta( $user, self::PENDING_META, self::seal( PNCP_Totp::new_secret() ) );
			self::back( 'setup' );
		}
		if ( 'remove' === $op && self::server_unlocked() ) {
			self::remove_app( $state );
		}
		if ( ! in_array( $op, array( 'confirm', 'lock', 'unlock', 'codes', 'remove', 'roles', 'quarantine' ), true ) ) {
			self::back( 'error' );
		}
		if ( self::too_many_fails() ) {
			self::back( 'wait' );
		}

		if ( 'confirm' === $op ) {
			$secret = self::unseal( (string) get_user_meta( $user, self::PENDING_META, true ) );
			$step   = '' !== $secret && ! self::configured() ? PNCP_Totp::verify( $secret, $code ) : false;
			if ( false === $step ) {
				self::failed();
				self::back( 'wrong' );
			}
			$codes = self::new_codes();
			self::save(
				array_merge(
					$state,
					array(
						'secret'    => self::seal( $secret ),
						'locked'    => false,
						'until'     => 0,
						'last_step' => $step,
						'codes'     => array_map( array( __CLASS__, 'hash_code' ), $codes ),
					)
				)
			);
			delete_user_meta( $user, self::PENDING_META );
			set_site_transient( 'pncp_ld_codes_' . $user, $codes, 2 * MINUTE_IN_SECONDS );
			self::event( 'connected' );
			self::back( 'connected' );
		}

		$locked = self::is_locked();
		// The first lock: only after confirming the recovery codes are saved (checked before the code is used).
		if ( 'lock' === $op && empty( $state['ack'] ) && ! $ack ) {
			self::back( 'ack' );
		}
		if ( ! self::configured() || ( 'lock' === $op && ( $locked || self::unlocked_until() ) ) || ( 'unlock' === $op && ! $locked ) || ( in_array( $op, array( 'codes', 'remove', 'roles', 'quarantine' ), true ) && $locked ) || ( 'remove' === $op && self::unlocked_until() ) ) {
			self::back( 'error' );
		}
		$how = self::check_code( $code, 'unlock' === $op );
		if ( 'busy' === $how ) {
			self::back( 'error' );
		}
		if ( '' === $how ) {
			self::failed();
			self::back( 'wrong' );
		}
		$state = self::state();

		if ( 'lock' === $op ) {
			$state['locked'] = true;
			$state['until']  = 0;
			$state['since']  = time();
			$state['ack']    = true;
			self::save( $state );
			self::event( 'locked' );
			PNCP_Integrity::snapshot();
			self::back( 'locked' );
		}
		if ( 'unlock' === $op ) {
			$mins = in_array( $mins, array( 0, 15, 30, 60, 120 ), true ) ? $mins : 30;
			if ( 0 === $mins ) {
				$state['locked'] = false;
				$state['until']  = 0;
			} else {
				$state['until'] = time() + $mins * MINUTE_IN_SECONDS;
			}
			self::save( $state );
			PNCP_Integrity::mark_stale(); // Updates are allowed now: the next check takes a new fingerprint.
			/* translators: %d: minutes */
			self::event( 'unlocked', $mins ? sprintf( __( '%d min', 'scrapelock' ), $mins ) : __( 'until locked again', 'scrapelock' ) );
			self::mail( __( 'The site was unlocked', 'scrapelock' ), __( 'The site was unlocked on the Lockdown page. If it was not you, lock it again and change the administrators\' passwords.', 'scrapelock' ) );
			self::back( 'unlocked' );
		}
		if ( 'roles' === $op ) {
			// Only existing roles; the roles that can take over the site are added in frozen_roles() anyway.
			$state['roles'] = array_values( array_intersect( array_keys( wp_roles()->get_names() ), $pick ) );
			self::save( $state );
			self::$staff = array();
			self::event( 'roles', implode( ', ', self::frozen_roles() ) );
			self::back( 'roles' );
		}
		if ( 'quarantine' === $op ) {
			$state['quarantine'] = ! empty( $_POST['quarantine'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked at the top of handle().
			self::save( $state );
			self::event( 'quarantine_setting', $state['quarantine'] ? __( 'on', 'scrapelock' ) : __( 'off', 'scrapelock' ) );
			self::back( 'quarantine' );
		}
		if ( 'codes' === $op ) {
			$codes          = self::new_codes();
			$state['codes'] = array_map( array( __CLASS__, 'hash_code' ), $codes );
			self::save( $state );
			set_site_transient( 'pncp_ld_codes_' . $user, $codes, 2 * MINUTE_IN_SECONDS );
			self::event( 'codes' );
			self::back( 'codes' );
		}
		self::remove_app( $state );
	}

	/**
	 * Removes the app and turns the lock off.
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function remove_app( $state ) {
		$state['secret']    = '';
		$state['locked']    = false;
		$state['until']     = 0;
		$state['last_step'] = 0;
		$state['codes']     = array();
		$state['ack']       = false;
		self::save( $state );
		self::event( 'removed' );
		self::mail( __( 'The authenticator app was removed', 'scrapelock' ), __( 'The authenticator app was removed from the Lockdown page and the lock is off. If it was not you, change the administrators\' passwords.', 'scrapelock' ) );
		self::back( 'removed' );
	}
}
