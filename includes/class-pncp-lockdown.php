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
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'map_meta_cap', array( __CLASS__, 'map_meta_cap' ), 9999, 3 );
		add_filter( 'file_mod_allowed', array( __CLASS__, 'file_mod_allowed' ) );
		add_filter( 'automatic_updater_disabled', array( __CLASS__, 'updater_disabled' ) );
		foreach ( self::protected_options() as $option ) {
			add_filter( 'pre_update_option_' . $option, array( __CLASS__, 'keep_option' ), 9999, 3 );
		}
		foreach ( array( 'active_sitewide_plugins', 'auto_update_plugins', 'auto_update_themes', 'admin_email', self::OPTION ) as $option ) {
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
	 * Staff: any user with a capability beyond reading (authors, editors, shop managers, administrators).
	 * Customers and subscribers are not staff: the lock does not touch them. Uses the roles as stored,
	 * not the capabilities the lock takes away.
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
			self::$staff[ $user_id ] = ( is_multisite() && is_super_admin( $user_id ) ) || array() !== self::privileged( self::user_caps( $user_id ) );
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
		return array( 'active_plugins', 'template', 'stylesheet', 'siteurl', 'home', 'admin_email', 'new_admin_email', 'users_can_register', 'default_role', 'auto_update_plugins', 'auto_update_themes', $wpdb->get_blog_prefix() . 'user_roles', PNCP_OPTION, self::OPTION );
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
	 * {prefix}capabilities). Customers registering or changing role between customer roles are not affected.
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
		if ( self::privileged( maybe_unserialize( $value ) ) === self::privileged( $old ) ) {
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
	 * The table, key column, value column and extra condition of the row that holds the lock (the same place
	 * as the state: wp_options, or wp_sitemeta on multisite).
	 *
	 * @return string[]
	 */
	private static function mutex_row() {
		global $wpdb;
		if ( is_multisite() ) {
			return array( $wpdb->sitemeta, 'meta_key', 'meta_value', $wpdb->prepare( ' AND site_id = %d', get_current_network_id() ) );
		}
		return array( $wpdb->options, 'option_name', 'option_value', '' );
	}

	/**
	 * Takes the lock: an atomic UPDATE that only one request can win, valid for 10 seconds at most (so a
	 * request that dies never leaves it held). Waits up to 3 seconds for it.
	 *
	 * @return bool
	 */
	private static function lock() {
		global $wpdb;
		if ( false === get_site_option( self::MUTEX, false ) ) {
			add_site_option( self::MUTEX, '0' );
		}
		list( $table, $key, $value, $where ) = self::mutex_row();
		for ( $i = 0; $i < 30; $i++ ) {
			$now = time();
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- An atomic compare-and-set; $where is prepared above.
			if ( 1 === (int) $wpdb->query( $wpdb->prepare( 'UPDATE %i SET %i = %s WHERE %i = %s AND %i + 0 < %d', $table, $value, (string) ( $now + 10 ), $key, self::MUTEX, $value, $now ) . $where ) ) {
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
		global $wpdb;
		list( $table, $key, $value, $where ) = self::mutex_row();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- $where is prepared in mutex_row().
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET %i = %s WHERE %i = %s', $table, $value, '0', $key, self::MUTEX ) . $where );
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
		$counts = count_users();
		$staff  = array();
		$others = 0;
		$names  = wp_roles()->get_names();
		foreach ( $counts['avail_roles'] as $role => $count ) {
			if ( ! $count || 'none' === $role ) {
				continue;
			}
			if ( array() !== self::privileged( array( $role => true ) ) ) {
				$staff[] = sprintf( '%s: %d', isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : $role, $count );
			} else {
				$others += $count;
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
				__( 'Also by code: active plugins, theme, site address, admin email, registration, default role, role definitions, automatic update lists, ScrapeLock settings and the lock itself.', 'scrapelock' ),
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
				<?php /* translators: %d: number of users */ ?>
				<li><?php echo esc_html( sprintf( _n( '%d customer or subscriber account is not affected.', '%d customer and subscriber accounts are not affected.', $others, 'scrapelock' ), $others ) ); ?></li>
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
		if ( ! in_array( $op, array( 'confirm', 'lock', 'unlock', 'codes', 'remove' ), true ) ) {
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
		if ( ! self::configured() || ( 'lock' === $op && ( $locked || self::unlocked_until() ) ) || ( 'unlock' === $op && ! $locked ) || ( in_array( $op, array( 'codes', 'remove' ), true ) && $locked ) || ( 'remove' === $op && self::unlocked_until() ) ) {
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
			/* translators: %d: minutes */
			self::event( 'unlocked', $mins ? sprintf( __( '%d min', 'scrapelock' ), $mins ) : __( 'until locked again', 'scrapelock' ) );
			self::mail( __( 'The site was unlocked', 'scrapelock' ), __( 'The site was unlocked on the Lockdown page. If it was not you, lock it again and change the administrators\' passwords.', 'scrapelock' ) );
			self::back( 'unlocked' );
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
