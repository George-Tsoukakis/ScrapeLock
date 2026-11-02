<?php
/**
 * Lockdown: freezes every change made from wp-admin, the REST API or XML-RPC (plugins, themes, updates,
 * the file editor, users and roles, settings, content) until an administrator unlocks it with a code
 * from an authenticator app. Visitors and customers are not affected: they browse, order, register as
 * customers and comment as usual. Shop managers (and roles not ticked on the Lockdown tab) keep their shop and
 * content work, without the capabilities that can take over the site (PNCP_Lockdown::limited_caps()).
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
	const MAX_FAILS     = 5;  // Per account from one IP, in 15 minutes (then refused for 15 min, 1 h, 6 h).
	const MAX_FAILS_ACCOUNT = 20; // Per account from all IPs, in an hour (app codes only).
	const MAX_FAILS_ALL = 20; // Per IP (IPv6: per /64), in an hour.
	const MAX_FAILS_SITE = 100; // All accounts and IPs together, in an hour: a ceiling for guessing from many places.
	const CODES         = 10;
	const MUTEX         = 'pncp_lockdown_mutex';
	const FAILS_OPTION  = 'pncp_lockdown_fails'; // The wrong-code counters (see fail_buckets()).
	const MUTEX_TTL     = 5; // 3.4: seconds the code-check lock is held at most (was 10; a check takes far less).
	const DB_FOREIGN    = 'pncp_lockdown_dblock'; // 3.4.2: the connection last found holding the database lock for itself.
	const MUTEX_PRI     = 'pncp_lockdown_mutex_pri'; // 3.4.2: set while a correct code waits for the code-check lock.
	const PRI_TTL       = 9; // 3.4.2: seconds a correct code waits for the code-check lock at most (see fallback_lock()).

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
	 * What the seal found when the state was read: '' (in order), 'replay' (the guard file says locked but the
	 * database does not: the site stays locked), 'forged' (there is no guard to compare with, but the state is
	 * missing, does not match its signature or is older than the lock, while the signed snapshot of that lock is
	 * still there: the site stays locked too) or 'keys' (the signature does not match and nothing signed shows a
	 * lock: changed in the database, or the keys in wp-config.php were changed).
	 *
	 * @var string
	 */
	private static $tamper = '';

	/**
	 * Does the stored state carry a valid signature (or come from before 3.3)?
	 *
	 * @var bool
	 */
	private static $sig_ok = true;

	/**
	 * 3.4: is the stored state, though genuinely signed, older than the one the guard names (a copy put back
	 * from a backup)? Its app secret and recovery codes may be old ones, so they are not used.
	 *
	 * @var bool
	 */
	private static $older = false;

	/**
	 * 3.4.1: the generation of a guard file or lock file found on this request that is older than the unlock
	 * for good the stored state signs (put back from a backup taken while locked): it no longer counts, and it
	 * is removed once the state is read (0: none was found).
	 *
	 * @var int
	 */
	private static $stale = 0;

	/**
	 * 3.4.2: the stored state is a genuinely signed one of the current lock that is newer than the guard file
	 * or lock file of this server (another web server with its own wp-content saved it: an unlock for a while,
	 * or a lock again). The files of this server are brought up to date once the state is read.
	 *
	 * @var bool
	 */
	private static $follow = false;

	/**
	 * 3.4.2: the stored state is a genuinely signed, newer unlock for a while made on another web server, while
	 * the guard file or lock file of this server says locked. This server stays locked (see seal_check()).
	 *
	 * @var bool
	 */
	private static $elsewhere = false;

	/**
	 * Staff or not, per user.
	 *
	 * @var array<int, bool>
	 */
	private static $staff = array();

	/**
	 * The capabilities refused to working roles while locked (limited_caps()), per request.
	 *
	 * @var string[]|null
	 */
	private static $limited_caps = null;

	/**
	 * Was $limited_caps built after plugins_loaded (every filter in place)?
	 *
	 * @var bool
	 */
	private static $limited_final = false;

	/**
	 * The wp_die() handler that was in place before ours.
	 *
	 * @var callable|null
	 */
	private static $die_handler = null;

	/**
	 * Was this request signed in with an application password?
	 *
	 * @var bool
	 */
	private static $app_password = false;

	/**
	 * 3.4: while unlocked for a while, per user on this request: did the stored capabilities let the account
	 * administer the site before the change being written (note_role())?
	 *
	 * @var array<int, bool>
	 */
	private static $caps_before = array();

	/**
	 * Per user: is this request signed in with the session that unlocked for a while?
	 *
	 * @var array<int, bool>
	 */
	private static $session_ok = array();

	/**
	 * The value this request wrote to the code-check lock (see lock()), so that release() only frees its own.
	 *
	 * @var string
	 */
	private static $mutex = '';

	/**
	 * The value this request wrote to the priority row (see fallback_lock()), so that release() only frees its own.
	 *
	 * @var string
	 */
	private static $pri = '';

	/**
	 * When this request first saw each value of the row (see mutex_take()), by value.
	 *
	 * @var array<string, float>
	 */
	private static $seen_at = array();

	/**
	 * The open lock file this request holds an exclusive lock on while it holds the code-check lock (see
	 * local_lock()), or null.
	 *
	 * @var resource|null
	 */
	private static $local = null;

	/**
	 * The name of the lock file this request holds (see local_lock()): written in the values it puts in the
	 * code-check lock. '' when it holds none.
	 *
	 * @var string
	 */
	private static $local_id = '';

	/**
	 * The name of the database lock (GET_LOCK) this request holds as the code-check lock, '' when it holds none
	 * (see db_lock()).
	 *
	 * @var string
	 */
	private static $db_held = '';

	/**
	 * Can the database lock be used on this request? Null until first tried; false after it failed once (the
	 * file lock and the row are used from then on, see lock()).
	 *
	 * @var bool|null
	 */
	private static $db_usable = null;

	/**
	 * Is the stored state being read and checked right now (state())?
	 *
	 * @var bool
	 */
	private static $reading = false;

	/**
	 * Alerts found while the state was being read: sent once it is read (see state()).
	 *
	 * @var array<int, array{0: string, 1: string}>
	 */
	private static $queued = array();

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'map_meta_cap', array( __CLASS__, 'map_meta_cap' ), 9999, 4 );
		add_filter( 'file_mod_allowed', array( __CLASS__, 'file_mod_allowed' ) );
		add_filter( 'automatic_updater_disabled', array( __CLASS__, 'updater_disabled' ) );
		foreach ( self::protected_options() as $option ) {
			add_filter( 'pre_update_option_' . $option, array( __CLASS__, 'keep_option' ), 9999, 3 );
		}
		// Multisite: the network options too (3.4: also the super admins and who may register).
		foreach ( array( 'active_sitewide_plugins', 'admin_email', 'site_admins', 'registration', self::OPTION ) as $option ) {
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
		add_action( 'application_password_did_authenticate', array( __CLASS__, 'note_app_password' ) );
		add_action( 'wp_authenticate_application_password_errors', array( __CLASS__, 'app_password_errors' ), 10, 3 );
		add_action( 'woocommerce_save_account_details_errors', array( __CLASS__, 'woocommerce_account_errors' ), 10, 2 );
		// WooCommerce sends users who cannot edit posts away from wp-admin and hides their admin bar: staff
		// would then not even reach the unlock page.
		add_filter( 'woocommerce_prevent_admin_access', array( __CLASS__, 'woocommerce_admin_access' ) );
		add_filter( 'woocommerce_disable_admin_bar', array( __CLASS__, 'woocommerce_admin_access' ) );
		// 3.4: unlocked for a while, the owner's changes through WordPress are noted, and kept when the site locks
		// again by itself: on the first request after the end (before the seal compares the options), or in the
		// hourly check, whichever comes first.
		add_action( 'updated_option', array( __CLASS__, 'note_option' ), 10, 3 );
		add_action( 'added_option', array( __CLASS__, 'note_added_option' ), 10, 2 );
		add_action( 'deleted_option', array( __CLASS__, 'note_deleted_option' ) );
		// Multisite: the network options changed by the owner during an unlock for a while.
		add_action( 'update_site_option', array( __CLASS__, 'note_site_option' ), 10, 3 );
		add_action( 'add_site_option', array( __CLASS__, 'note_added_site_option' ), 10, 2 );
		add_action( 'delete_site_option', array( __CLASS__, 'note_deleted_site_option' ) );
		// Multisite: who is staff depends on the site (its roles), so it is looked up again on another site.
		add_action( 'switch_blog', array( __CLASS__, 'forget_staff' ) );
		add_filter( 'update_user_metadata', array( __CLASS__, 'note_caps_before' ), PHP_INT_MAX, 3 );
		add_filter( 'add_user_metadata', array( __CLASS__, 'note_caps_before' ), PHP_INT_MAX, 3 );
		add_action( 'updated_user_meta', array( __CLASS__, 'note_role' ), 10, 4 );
		add_action( 'added_user_meta', array( __CLASS__, 'note_role' ), 10, 4 );
		add_action( 'plugins_loaded', array( __CLASS__, 'expire_window' ), 0 );
		add_action( PNCP_Log::CRON, array( __CLASS__, 'expire_window' ), 5 );
		add_action( PNCP_Log::CRON, array( __CLASS__, 'maintain_files' ), 6 );
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
			self::$reading = true;
			try {
				$stored = self::check_seal();
			} finally {
				self::$reading = false;
			}
			unset( $stored['sig'] );
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
					// 3.3: who unlocked for a while (only that account gets its rights back), and the time of the
					// file fingerprint (a deleted or older fingerprint is noticed).
					'unlocked_by' => 0,
					'fp'          => 0,
					// 3.4: the version that signed the state. Signed with it, so unsigned data is never taken for
					// data from before 3.3 once a version with signatures has written it (PNCP_Seal::legacy()).
					'sealed'      => '',
					// 3.4: the (keyed) fingerprint of the browser session that unlocked for a while. Only requests
					// signed in with that session get the rights back; another session of the same account, an
					// application password, XML-RPC or a WooCommerce API key stay as when locked.
					'unlock_session' => '',
					// 3.4: the generation of the state (one more on every save, also noted in the guard file), and
					// the generation of the snapshot of the protected options that belongs to it. A signed copy
					// put back from an older backup has a lower generation than the guard and is not accepted.
					'gen'            => 0,
					'snap'           => 0,
					// 3.4, multisite: the lock has a snapshot of the whole network (PNCP_Seal::network_mode()).
					'net'            => 0,
					// 3.4: the lock time of the snapshot the state names (a snapshot that is missing a moment after the
					// lock was deleted, not still being taken), and the site's administration address in it: alerts
					// go there while locked, not to an address someone changed in the database.
					'snapped'        => 0,
					'mail'           => '',
					// 3.4.1: the generation of the unlock for good that removed the guard file or the lock file. A
					// file of the lock from before it (lower generation), put back from a backup, no longer counts.
					'freed'          => 0,
					// 3.4.2: the generation of the state saved when the site was locked, and the address alerts go to
					// signed then: the lock line for wp-config.php names them (PNCP_Seal::CONFIG).
					'lgen'           => 0,
					'lmail'          => '',
				),
				$stored
			);
		}
		if ( self::$follow && ! self::$reading ) {
			self::$follow = false;
			self::follow_files();
		}
		if ( self::$stale && ! self::$reading ) {
			$stale       = self::$stale;
			self::$stale = 0;
			$removed     = PNCP_Seal::remove_stale( $stale, (int) self::$state['freed'] );
			if ( $removed ) {
				self::event( 'stale_file', implode( ', ', array_map( array( 'PNCP_Seal', 'short_path' ), $removed ) ) );
			}
		}
		// Alerts found while reading the state are sent now: where they go depends on the state.
		$alerts       = self::$queued;
		self::$queued = array();
		foreach ( $alerts as $alert ) {
			self::tamper_alert( $alert[0], $alert[1] );
		}
		return self::$state;
	}

	/**
	 * Reads the stored state and checks it against its signature and against the guard file (PNCP_Seal).
	 *
	 * The guard and the state are written a moment apart. A request that sees one of them already changed and
	 * the other not yet looks again before it raises the alarm: the guard file once more, and the state once
	 * more after a short wait when it is exactly one generation behind the guard.
	 *
	 * @return array<string, mixed> Stored state, with its signature.
	 */
	private static function check_seal() {
		$stored = self::stored();
		self::seal_check( $stored );
		// 3.4.2: also when the state is a newer unlock for a while than the guard read at the start of this request:
		// another request on this server may have just written both (see seal_check(), $elsewhere).
		if ( ( 'replay' === self::$tamper || self::$elsewhere ) && PNCP_Seal::refresh_beacon() ) {
			self::seal_check( $stored );
		}
		$beacon = PNCP_Seal::beacon();
		if ( 'replay' === self::$tamper && $beacon && isset( $beacon['gen'], $stored['gen'] ) && (int) $stored['gen'] === $beacon['gen'] - 1 ) {
			usleep( 250000 );
			self::forget_cached();
			$stored = self::stored();
			self::seal_check( $stored );
		}
		if ( '' !== self::$tamper ) {
			$floor = $beacon && isset( $beacon['gen'] ) ? (int) $beacon['gen'] : 0;
			$floor = max( $floor, self::config_floor() );
			$older = 'replay' === self::$tamper && self::$sig_ok && ! empty( $stored['locked'] ) && $floor > 0 && ( isset( $stored['gen'] ) ? (int) $stored['gen'] : 0 ) < $floor;
			self::tamper_alert( $older ? 'replay' : 'state', $older ? 'state' : self::$tamper );
		}
		return $stored;
	}

	/**
	 * The state as stored (with its signature).
	 *
	 * @return array<string, mixed>
	 */
	private static function stored() {
		$stored = get_site_option( self::OPTION, array() );
		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * Compares the stored state with its signature and the guard: sets $sig_ok and $tamper.
	 *
	 * @param array<string, mixed> $stored Stored state, with its signature.
	 */
	private static function seal_check( $stored ) {
		$sig = isset( $stored['sig'] ) ? $stored['sig'] : null;
		unset( $stored['sig'] );
		$empty        = ! $stored;
		self::$sig_ok = $empty || ( null === $sig ? PNCP_Seal::legacy() : PNCP_Seal::valid( $stored, $sig ) );
		self::$tamper = '';
		self::$older  = false;
		self::$stale     = 0;
		self::$follow    = false;
		self::$elsewhere = false;
		$beacon          = PNCP_Seal::beacon();
		// 3.4.2: the lock line in wp-config.php (PNCP_Seal::CONFIG): the generation of the lock it names. A state
		// older than that was put back from a copy taken before the lock (or is a copy of an earlier lock).
		$floor = self::config_floor();
		$gen   = isset( $stored['gen'] ) ? (int) $stored['gen'] : 0;
		if ( $beacon && $beacon['locked'] && self::$sig_ok && ! $empty && empty( $stored['locked'] ) && isset( $beacon['gen'], $stored['freed'] ) && (int) $beacon['gen'] < (int) $stored['freed'] && $gen >= $floor ) {
			// 3.4.1: the guard file or the lock file is older than the unlock for good the signed state names (the
			// unlock removed it; it was put back, for example with a backup of wp-content/uploads or mu-plugins
			// taken while the site was locked). Only an unlock with the app (or a recovery code) signs that, so
			// the database alone cannot make a file of the current lock look old. It no longer counts.
			self::$stale = (int) $beacon['gen'];
			return;
		}
		if ( $beacon && $beacon['locked'] ) {
			// The guard (a file) says the site is locked: a database that says otherwise was changed behind
			// WordPress's back, or put back from an older copy. The site stays locked. 3.4: a signed state from
			// an older copy also says "locked", but its generation is lower than the one in the guard (a newer
			// one is fine: the state is saved a moment before the guard, and only ever goes up).
			//
			// 3.4.2: a signed state of a higher generation than the guard, unlocked for a while (a later "until"),
			// is accepted too. On one web server it cannot exist: an unlock writes the guard first, and every
			// earlier state has a lower generation. It is what several web servers that share the database but
			// each have their own wp-content see when the owner unlocked on another one; this server's files then
			// follow it (follow_files()). The database alone cannot make one: only the keys sign it.
			//
			// But such a state cannot tell whether it is still the latest: a copy of an unlock for a while, put
			// back in the database after the owner locked again on the other server, looks just the same to a
			// server that missed that lock. So an unlock for a while made elsewhere is only followed while this
			// server is itself unlocked for a while (its guard says so: then the copy opens nothing that is not
			// already open). A server whose guard says locked stays locked, without an alarm (the state is
			// genuine); the owner unlocks it on its own Lockdown page. A newer lock (or an ended unlock) is always
			// followed: it only locks.
			self::$older = ( isset( $beacon['gen'] ) && $gen < $beacon['gen'] ) || $gen < $floor;
			$newer       = self::$sig_ok && ! empty( $stored['locked'] ) && isset( $beacon['gen'] ) && $gen > $beacon['gen'] && $gen >= $floor;
			if ( ! self::$sig_ok || empty( $stored['locked'] ) || ( ! $newer && ( isset( $stored['until'] ) ? (int) $stored['until'] : 0 ) > $beacon['until'] ) || ( isset( $beacon['gen'] ) && $gen < $beacon['gen'] ) || $gen < $floor ) {
				self::$tamper = 'replay';
			} elseif ( $newer && ( isset( $stored['until'] ) ? (int) $stored['until'] : 0 ) > time() && (int) $beacon['until'] <= time() ) {
				self::$elsewhere = true;
			} elseif ( $newer ) {
				self::$follow = true;
			}
		} elseif ( $floor > 0 && ( $empty || ! self::$sig_ok || $gen < $floor ) ) {
			// 3.4.2: no file of the lock says "locked", but the lock line in wp-config.php does, and the state is
			// missing, does not match its signature or is older than the lock the line names: deleted, changed or
			// put back from an older copy in the database. The site stays locked, as with the guard file. A genuine
			// state of this lock or a later one (an unlock for a while, or for good) is followed as usual: only an
			// unlock with the app or a recovery code signs one, and the database alone cannot.
			self::$older  = self::$sig_ok && ! $empty && $gen < $floor;
			self::$tamper = 'replay';
		} elseif ( ! self::$sig_ok ) {
			// No guard to compare with (it could not be written, or the site was locked without it). A state that
			// does not match its signature while the signed snapshot of a lock is there was changed in the
			// database (for example "locked" set to false): the site stays locked. Without anything signed, the
			// keys in wp-config.php may simply have been changed.
			self::$tamper = PNCP_Seal::lock_evidence( true ) ? 'forged' : 'keys';
		} elseif ( $empty || empty( $stored['locked'] ) ) {
			$since = $empty ? null : ( isset( $stored['since'] ) ? (int) $stored['since'] : 0 );
			$snap  = $empty ? null : ( isset( $stored['snap'] ) ? (int) $stored['snap'] : null );
			// The state was deleted, or put back from a copy older than the lock, while the signed fingerprints of
			// the lock are still there (only the autoloaded ones are read here: no extra query on every request).
			// 3.4: the signed snapshot of the lock is read too. Without a guard file that says "locked" (it could
			// not be written, or the owner locked without it on purpose) the fingerprints can be deleted along
			// with the state, and the snapshot is what is left. It costs one small query (none with a persistent
			// object cache); the snapshot itself is only there while the site is locked (a full unlock deletes
			// it), so an unlocked site never loads it.
			if ( PNCP_Seal::lock_evidence( false, $since, $snap ) || PNCP_Seal::snapshot_evidence( $since, $snap ) ) {
				self::$tamper = 'forged';
			}
		}
	}

	/**
	 * 3.4.2: brings this server's guard file (or lock file) up to the stored state, which is newer and signed
	 * (see seal_check()): another web server saved it. Looked at again first: a request on this server may have
	 * written them a moment ago.
	 */
	private static function follow_files() {
		PNCP_Seal::refresh_beacon();
		$beacon = PNCP_Seal::beacon();
		$state  = self::$state;
		if ( ! $beacon || empty( $state['locked'] ) || ! isset( $beacon['gen'] ) || (int) $state['gen'] <= (int) $beacon['gen'] ) {
			return;
		}
		PNCP_Seal::write_lock_files( true, (int) $state['until'], (int) $state['gen'], (int) $state['snap'] );
	}

	/**
	 * What the seal found: '' (in order), 'replay' or 'keys' (see $tamper).
	 *
	 * @return string
	 */
	public static function tampered() {
		self::state();
		return self::$tamper;
	}

	/**
	 * 3.4.2: the generation of the lock that the lock line in wp-config.php names (0: no valid line, or it is
	 * not followed on this request).
	 *
	 * @return int
	 */
	private static function config_floor() {
		$config = PNCP_Seal::config_lock();
		return null === $config ? 0 : (int) $config['gen'];
	}

	/**
	 * Saves the state.
	 *
	 * @param array<string, mixed> $state State.
	 * @param bool                 $free  3.4.1: an unlock for good. A guard file or lock file that still says
	 *                                    "locked" is removed too, also when the stored state does not say so.
	 * @return bool False when the guard file could not be changed (the state was not changed either).
	 */
	private static function save( $state, $free = false ) {
		unset( $state['sig'] );
		$prev = null === self::$state ? self::state() : self::$state;
		// 3.4: the stored state is forged, or an older copy, while the guard says locked: saving it would sign
		// its app secret and recovery codes (perhaps old ones) as current. Only a save that removes the app
		// (with SCRAPELOCK_UNLOCK) goes through; anything else waits until the owner has dealt with it.
		if ( in_array( self::$tamper, array( 'replay', 'forged' ), true ) && ( ! self::$sig_ok || self::$older ) && ! empty( $state['secret'] ) ) {
			return false;
		}
		$locked = ! empty( $state['locked'] );
		$until  = $locked ? (int) $state['until'] : 0;
		$was    = ! empty( $prev['locked'] );
		// 3.4: every save gets the next generation, and while locked (or when unlocking) the guard is written
		// again with it, so no copy of the state saved before this one is accepted any more.
		$state['gen']  = self::next_generation( $state );
		$state['snap'] = isset( $state['snap'] ) ? (int) $state['snap'] : 0;
		if ( $locked && ! $was ) {
			// 3.4.2: a new lock. The lock line for wp-config.php names its generation and the address alerts go to.
			$state['lgen']  = $state['gen'];
			$state['lmail'] = PNCP_Seal::lock_mail();
		}
		// 3.4.1: on an unlock for good, also a file that says "locked" while the stored state does not (a file put
		// back from a backup, or a lock whose state could not be saved) is removed.
		$beacon = $free && ! $locked ? PNCP_Seal::beacon() : null;
		$file   = $beacon && $beacon['locked'];
		$guard  = $was || $locked || $file;
		// Less locked (unlocked, or open for longer): the guard first, so it never says "locked" while the
		// database says otherwise. If the guard cannot be changed, the state is not either. 3.4.1: the same for
		// the lock file written instead of the guard when the guard cannot be written (PNCP_Seal::write_beacon()).
		$less = ( ! $locked && ( $was || $file ) ) || ( $locked && $until > (int) $prev['until'] );
		if ( $guard && $less && ! PNCP_Seal::write_lock_files( $locked, $until, $state['gen'], $state['snap'] ) && ( PNCP_Seal::guard_installed() || '' !== PNCP_Seal::beacon_path() ) ) {
			return false;
		}
		// 3.4.1: unlocked for good, and no file says "locked" any more: a file of this lock or an earlier one
		// (a lower generation) that is put back later no longer counts (see seal_check()).
		if ( ! $locked && ( $was || $file ) && $guard && $less ) {
			$state['freed'] = $state['gen'];
		}
		$state['sealed'] = PNCP_VERSION;
		$stored          = $state;
		$stored['sig']   = PNCP_Seal::sign( $state );
		self::$writing   = true;
		$saved           = update_site_option( self::OPTION, $stored );
		self::$writing   = false;
		if ( ! $saved && $guard && $less && ( $was || $file ) ) {
			// The database refused the write after the guard was changed: the guard goes back to the state that
			// is still stored, or every request would see the stored state as an older copy.
			PNCP_Seal::write_lock_files( true, (int) $prev['until'], (int) $prev['gen'], (int) $prev['snap'] );
			return false;
		}
		self::$state      = $state;
		self::$session_ok = array();
		self::$tamper     = '';
		self::$sig_ok     = true;
		self::$older      = false;
		// More locked, or as locked as before: the database first, then the guard.
		if ( $guard && ! $less ) {
			PNCP_Seal::write_lock_files( $locked, $until, $state['gen'], $state['snap'] );
		}
		return true;
	}

	/**
	 * The next generation: higher than the one of the state (as stored or about to be saved) and the one in the
	 * guard file, so it only ever goes up, also after a state that was put back from an older copy.
	 *
	 * @param array<string, mixed>|null $state The state about to be saved (null: the one stored now).
	 * @return int
	 */
	public static function next_generation( $state = null ) {
		$gen = (int) self::state()['gen'];
		if ( is_array( $state ) && isset( $state['gen'] ) ) {
			$gen = max( $gen, (int) $state['gen'] );
		}
		$beacon = PNCP_Seal::beacon();
		if ( $beacon && isset( $beacon['gen'] ) ) {
			$gen = max( $gen, (int) $beacon['gen'] );
		}
		// 3.4.2: and the lock line in wp-config.php: a state saved after it (also after the Lockdown data was
		// deleted) is newer than the lock it names.
		return max( $gen, PNCP_Seal::config_gen() ) + 1;
	}

	/**
	 * Notes the generation of a new snapshot of the protected options in the (signed) state, and so in the
	 * guard: older snapshots and fingerprints are no longer accepted (PNCP_Seal::snapshot()).
	 *
	 * @param int  $gen Generation of the snapshot.
	 * @param bool $net Multisite: a new snapshot of the whole network (the lock has one from now on).
	 */
	public static function note_snapshot( $gen, $net = false ) {
		$state            = self::state();
		$state['snap']    = (int) $gen;
		$state['snapped'] = (int) $state['since'];
		$mail             = PNCP_Seal::alert_address();
		if ( '' !== $mail ) {
			$state['mail'] = $mail;
		}
		if ( $net ) {
			$state['net'] = 1;
		}
		self::save( $state );
	}

	/**
	 * The upgrade to 3.4: a genuine state signed by 3.3 gets a generation (and the guard with it), and the
	 * genuine snapshot of the current lock too. Only data that matches its signature and the guard is saved
	 * again, and only once (it then has a generation); a forged or older state is left as it is (the site stays
	 * locked and the owner is alerted, check_seal()).
	 */
	public static function upgrade_generation() {
		if ( false === get_site_option( self::OPTION, false ) ) {
			return;
		}
		self::reload();
		$state = self::state();
		if ( '' !== self::$tamper || ! self::$sig_ok || (int) $state['gen'] > 0 ) {
			return;
		}
		self::save( $state );
		if ( ! empty( $state['locked'] ) ) {
			PNCP_Seal::upgrade_snapshot();
		}
	}

	/**
	 * The upgrade to 3.3: signs the state and the fingerprint stored before signatures existed, writes the
	 * guard and takes the snapshot of the protected options if the site is locked.
	 *
	 * Only for data that really is from before 3.3 (PNCP_Seal::legacy()): nothing signed yet, no guard, no
	 * snapshot. Someone who can write to the database could otherwise change the protected options, add an
	 * administrator and set the stored version back to "3.2.0": the upgrade would then sign their values and
	 * accept their administrator. Data that already carries signatures is never signed again; the protected
	 * options are put back from the snapshot as usual (PNCP_Seal::verify_options()).
	 *
	 * @param string $from The version the upgrade comes from.
	 */
	public static function upgrade_seal( $from = '' ) {
		if ( false === get_site_option( self::OPTION, false ) ) {
			return;
		}
		if ( ! PNCP_Seal::legacy() ) {
			// The stored version says "before 3.3" but a newer version already signed the data (or the guard is
			// there): the version was set back in the database. Nothing is signed again; the owner is told.
			if ( '' !== $from && version_compare( $from, '3.3.0', '<' ) && ( PNCP_Seal::guard_installed() || '' !== PNCP_Seal::beacon_path() || PNCP_Seal::sealed_before() ) ) {
				self::tamper_alert( 'version', $from );
			}
			return;
		}
		self::reload();
		$state = self::state();
		if ( '' !== self::$tamper ) {
			// The guard says locked and the database does not, or the data does not match its signature: signing
			// it now would make a forged state (e.g. "unlocked") look genuine and remove the guard. Left as it is;
			// the site stays locked and the owner is alerted (check_seal()).
			return;
		}
		$state['fp'] = PNCP_Integrity::resign();
		self::save( $state );
		if ( ! empty( $state['locked'] ) ) {
			PNCP_Seal::take_site_snapshot(); // There is none yet (legacy() checked it): the values as the lock left them.
		}
		self::event( 'sealed' );
	}

	/**
	 * Notes the time of a new file fingerprint in the (signed) state.
	 *
	 * @param int $time Time of the fingerprint.
	 */
	public static function note_fingerprint( $time ) {
		$state       = self::state();
		$state['fp'] = (int) $time;
		self::save( $state );
	}

	/**
	 * Writes a protected option while locked (the seal putting back a value changed behind WordPress's back).
	 *
	 * @param string $option Option.
	 * @param mixed  $value  Value from the snapshot (false = the option did not exist).
	 */
	public static function write_protected( $option, $value ) {
		self::$writing = true;
		// 3.4.1: WordPress would email the address being replaced (the one planted in the database) that the
		// administration address "was changed", naming the genuine one. Not for a value put back.
		$notify = 'admin_email' === $option && false !== has_action( 'update_option_admin_email', 'wp_site_admin_email_change_notification' );
		if ( $notify ) {
			remove_action( 'update_option_admin_email', 'wp_site_admin_email_change_notification', 10 );
		}
		// Without the values the guard keeps on this request: update_option() compares with the stored value.
		try {
			PNCP_Seal::unguarded(
				static function () use ( $option, $value ) {
					if ( false === $value ) {
						delete_option( $option );
					} else {
						update_option( $option, $value );
					}
				}
			);
		} finally {
			if ( $notify ) {
				add_action( 'update_option_admin_email', 'wp_site_admin_email_change_notification', 10, 3 );
			}
			self::$writing = false;
		}
	}

	/**
	 * Multisite: writes a network option while locked (the seal putting back a value changed behind WordPress's
	 * back).
	 *
	 * @param string $option Network option.
	 * @param mixed  $value  Value from the snapshot of the network (false = the option did not exist).
	 */
	public static function write_protected_site( $option, $value ) {
		self::$writing = true;
		$notify = 'admin_email' === $option && false !== has_action( 'update_site_option_admin_email', 'wp_network_admin_email_change_notification' );
		if ( $notify ) {
			remove_action( 'update_site_option_admin_email', 'wp_network_admin_email_change_notification', 10 );
		}
		try {
			PNCP_Seal::unguarded(
				static function () use ( $option, $value ) {
					if ( false === $value ) {
						delete_site_option( $option );
					} else {
						update_site_option( $option, $value );
					}
				}
			);
		} finally {
			if ( $notify ) {
				add_action( 'update_site_option_admin_email', 'wp_network_admin_email_change_notification', 10, 4 );
			}
			self::$writing = false;
		}
	}

	/**
	 * The options the seal saves when the site is locked and puts back if they change behind WordPress's back:
	 * the protected options (per site), without the lock's own state, which is signed.
	 *
	 * @return string[]
	 */
	public static function sealed_options() {
		return array_values( array_diff( self::protected_options(), array( self::OPTION ) ) );
	}

	/**
	 * Something was changed behind WordPress's back: logged, and emailed at most once an hour per kind.
	 *
	 * @param string $kind   state | snapshot | snapshot_copy | replay | options | admin | apps | fingerprint | version |
	 *                       login | fails.
	 * @param string $detail Detail.
	 */
	public static function tamper_alert( $kind, $detail = '' ) {
		if ( ! did_action( 'init' ) ) {
			// Too early for translations (the seal runs before init): reported on init.
			add_action(
				'init',
				static function () use ( $kind, $detail ) {
					self::tamper_alert( $kind, $detail );
				}
			);
			return;
		}
		if ( self::$reading ) {
			self::$queued[] = array( (string) $kind, (string) $detail );
			return;
		}
		$key = 'pncp_ld_tamper_' . sanitize_key( $kind );
		if ( self::alerted( $key ) ) {
			return;
		}
		// 3.4: signed, with the time it ends, so a value planted in the database cannot switch the alerts off.
		$until = time() + HOUR_IN_SECONDS;
		set_site_transient( $key, $until . ':' . PNCP_Seal::sign( array( 'alerted', $key, $until ) ), HOUR_IN_SECONDS );
		self::event( 'tampered', $kind . ( '' !== $detail ? ': ' . $detail : '' ) );
		$texts = array(
			'state'         => __( 'The Lockdown data in the database no longer matches its signature, the guard file or the lock line in wp-config.php. The site stays locked. If you did not change the keys in wp-config.php, someone changed the database directly: check the site with a security scanner and change the database password.', 'scrapelock' ),
			'snapshot'      => __( 'The saved copy of the protected settings no longer matches its signature, so changed settings cannot be put back. If you did not change the keys in wp-config.php, someone changed the database directly.', 'scrapelock' ),
			'snapshot_copy' => __( 'The saved copy of the protected settings was deleted or changed in the database while the site was locked. It was put back from the guard file, and changed settings are put back from it. Someone changed the database directly: check the site with a security scanner and change the database password.', 'scrapelock' ),
			'login'         => __( 'The password of an administrator account was changed directly in the database while the site was locked. The account cannot sign in with it while the site stays locked; unlock with SCRAPELOCK_UNLOCK in wp-config.php or a recovery code from a session that is still signed in, then set a new password. Account:', 'scrapelock' ),
			'fails'         => __( 'The counters of wrong Lockdown codes were deleted or set back in the database while the site was locked. The copy next to the guard file or the lock file still counts. Someone changed the database directly: check the site with a security scanner and change the database password.', 'scrapelock' ),
			'options'       => __( 'Protected settings were changed directly in the database while the site was locked, and have been put back:', 'scrapelock' ),
			'admin'         => __( 'Accounts were given administrator rights behind WordPress\'s back after the site was locked. They cannot sign in while it stays locked; check and remove them before you unlock:', 'scrapelock' ),
			'fingerprint'   => __( 'The fingerprint of the code files was changed or removed in the database while the site was locked, so new or changed files might have been hidden. Check the files with a security scanner; a new fingerprint is taken the next time you lock the site.', 'scrapelock' ),
			'apps'          => __( 'Application passwords were added to staff accounts behind WordPress\'s back while the site was locked. They were refused and removed; check these accounts and change their passwords:', 'scrapelock' ),
			'replay'        => __( 'An older copy of the Lockdown data (for example from a database backup) was put back in the database while the site was locked. It was not accepted: the site stays locked, and the active plugins and the theme stay as they were when it was locked. If you did not restore a backup yourself, someone changed the database directly: check the site with a security scanner and change the database password. Found:', 'scrapelock' ),
			'version'       => __( 'The ScrapeLock version stored in the database was set back to an older one, while the Lockdown data had already been signed by a newer version. Nothing was signed again and changed protected settings are put back. If you did not install an older ScrapeLock yourself, someone changed the database directly: check the site with a security scanner and change the database password. Version found:', 'scrapelock' ),
		);
		$text = isset( $texts[ $kind ] ) ? $texts[ $kind ] : $texts['state'];
		self::mail( __( 'Lockdown data was changed outside WordPress', 'scrapelock' ), $text . ( '' !== $detail ? ' ' . $detail : '' ) );
	}

	/**
	 * Was this alert emailed less than an hour ago? Only a value ScrapeLock signed counts, and never for longer
	 * than an hour from now, whatever the stored value or its expiry time says.
	 *
	 * @param string $key Name of the transient.
	 * @return bool
	 */
	private static function alerted( $key ) {
		$parts = explode( ':', (string) get_site_transient( $key ), 2 );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) ) {
			return false;
		}
		$until = (int) $parts[0];
		return $until > time() && $until <= time() + HOUR_IN_SECONDS && PNCP_Seal::valid( array( 'alerted', $key, $until ), $parts[1] );
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
		if ( 'replay' === self::$tamper || 'forged' === self::$tamper || self::$elsewhere ) {
			return true; // The guard file, or the signed snapshot of the lock, says locked: the database cannot open it.
		}
		return ! empty( $s['locked'] ) && time() >= (int) $s['until'];
	}

	/**
	 * Locked, but opened for a while: until when (0 = not).
	 *
	 * @return int
	 */
	public static function unlocked_until() {
		$s = self::state();
		if ( 'replay' === self::$tamper || 'forged' === self::$tamper || self::$elsewhere ) {
			return 0;
		}
		return ! empty( $s['locked'] ) && (int) $s['until'] > time() ? (int) $s['until'] : 0;
	}

	/* ---------- Unlocked for a while: locking again by itself ---------- */

	/**
	 * Has an unlock for a while ended, without the snapshot of the protected options taken again since? Its end
	 * time stays in the state until expire_window() has run. Never while the state cannot be trusted.
	 *
	 * @return bool
	 */
	public static function reseal_pending() {
		if ( self::server_unlocked() || '' !== self::tampered() ) {
			return false;
		}
		$s = self::state();
		return ! empty( $s['locked'] ) && (int) $s['until'] > 0 && time() >= (int) $s['until'];
	}

	/**
	 * Is this request the administrator who unlocked for a while, in the browser session that unlocked, while it
	 * is still open? Only their changes are noted (and kept afterwards); not other requests, other sessions,
	 * application passwords, WP-CLI or scheduled events, nor ScrapeLock putting a value back.
	 *
	 * @return bool
	 */
	public static function window_session() {
		if ( self::$writing || ! did_action( 'plugins_loaded' ) ) {
			return false;
		}
		$by = (int) self::state()['unlocked_by'];
		return $by > 0 && self::unlocked_until() && get_current_user_id() === $by && self::unlocking_session( $by );
	}

	/**
	 * A protected option to note (see window_session())?
	 *
	 * @param string $option Option.
	 * @return bool
	 */
	private static function noted( $option ) {
		return in_array( (string) $option, self::sealed_options(), true ) && self::window_session();
	}

	/**
	 * A protected option was changed through WordPress (updated_option).
	 *
	 * @param string $option Option.
	 * @param mixed  $old    Old value.
	 * @param mixed  $value  New value.
	 */
	public static function note_option( $option, $old, $value ) {
		if ( self::noted( $option ) ) {
			PNCP_Seal::window_note( (string) $option, $old, $value );
		}
	}

	/**
	 * A protected option was added through WordPress (added_option).
	 *
	 * @param string $option Option.
	 * @param mixed  $value  Value.
	 */
	public static function note_added_option( $option, $value ) {
		if ( self::noted( $option ) ) {
			PNCP_Seal::window_note( (string) $option, false, $value );
		}
	}

	/**
	 * A protected option was deleted through WordPress (deleted_option).
	 *
	 * @param string $option Option.
	 */
	public static function note_deleted_option( $option ) {
		if ( self::noted( $option ) ) {
			PNCP_Seal::window_note( (string) $option, null, false );
		}
	}

	/**
	 * Multisite: a network option was changed through WordPress (update_site_option).
	 *
	 * @param string $option Option.
	 * @param mixed  $value  New value.
	 * @param mixed  $old    Old value.
	 */
	public static function note_site_option( $option, $value, $old ) {
		if ( self::noted_site( $option ) ) {
			PNCP_Seal::window_note_network( (string) $option, $old, $value );
		}
	}

	/**
	 * Multisite: a network option was added through WordPress (add_site_option).
	 *
	 * @param string $option Option.
	 * @param mixed  $value  Value.
	 */
	public static function note_added_site_option( $option, $value ) {
		if ( self::noted_site( $option ) ) {
			PNCP_Seal::window_note_network( (string) $option, false, $value );
		}
	}

	/**
	 * Multisite: a network option was deleted through WordPress (delete_site_option).
	 *
	 * @param string $option Option.
	 */
	public static function note_deleted_site_option( $option ) {
		if ( self::noted_site( $option ) ) {
			PNCP_Seal::window_note_network( (string) $option, null, false );
		}
	}

	/**
	 * A network option to note (see window_session())?
	 *
	 * @param string $option Option.
	 * @return bool
	 */
	private static function noted_site( $option ) {
		return is_multisite() && in_array( (string) $option, PNCP_Seal::NETWORK_OPTIONS, true ) && self::window_session();
	}

	/**
	 * Forgets who is staff (switch_blog: on multisite it depends on the site).
	 */
	public static function forget_staff() {
		self::$staff = array();
	}

	/**
	 * Can this user administer the current site, by the roles and capabilities stored for it? (Multisite: used
	 * for each site a user belongs to, see PNCP_Seal::authenticate().)
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	public static function can_administer( $user_id ) {
		return self::grants_control( self::user_caps( (int) $user_id ) );
	}

	/**
	 * Is it the key of the roles of a user on this site ({prefix}capabilities)?
	 *
	 * @param mixed $meta_key Meta key.
	 * @return bool
	 */
	private static function caps_key( $meta_key ) {
		global $wpdb;
		return is_string( $meta_key ) && $wpdb->get_blog_prefix() . 'capabilities' === $meta_key;
	}

	/**
	 * Can these stored capabilities administer the site?
	 *
	 * @param mixed $caps {prefix}capabilities value.
	 * @return bool
	 */
	private static function grants_control( $caps ) {
		return array() !== array_intersect( self::privileged( $caps ), self::control_caps() );
	}

	/**
	 * Before a role change is written: notes whether the account could administer the site until now (as
	 * stored). A filter that changes nothing.
	 *
	 * @param null|bool $check    Short-circuit.
	 * @param int       $user_id  User.
	 * @param string    $meta_key Key.
	 * @return null|bool
	 */
	public static function note_caps_before( $check, $user_id, $meta_key ) {
		if ( null === $check && self::caps_key( $meta_key ) && self::window_session() ) {
			self::$caps_before[ (int) $user_id ] = self::grants_control( get_user_meta( (int) $user_id, $meta_key, true ) );
		}
		return $check;
	}

	/**
	 * After a role change through WordPress by the owner during an unlock for a while: notes the account. It
	 * counts as an administrator the owner added only if it could not administer the site before this change
	 * (an account given the rights in the database, which the owner then only edited, is not taken over).
	 *
	 * @param int    $meta_id  Meta ID.
	 * @param int    $user_id  User.
	 * @param string $meta_key Key.
	 * @param mixed  $value    New value.
	 */
	public static function note_role( $meta_id, $user_id, $meta_key, $value ) {
		if ( ! self::caps_key( $meta_key ) || ! self::window_session() ) {
			return;
		}
		$user_id = (int) $user_id;
		$before  = ! empty( self::$caps_before[ $user_id ] );
		unset( self::$caps_before[ $user_id ], self::$staff[ $user_id ] );
		$value = maybe_unserialize( $value );
		$kind  = self::grants_control( $value ) ? ( $before ? -1 : 2 ) : ( self::grants_staff( $value ) ? 1 : 0 );
		if ( -1 !== $kind ) {
			PNCP_Seal::window_note_user( $user_id, $kind );
		}
	}

	/**
	 * The first request after an unlock for a while has ended (or the hourly check): the site is locked again,
	 * and the signed snapshot is taken again with the changes the owner made through WordPress meanwhile
	 * (PNCP_Seal::accept_window()), so they are not put back and reported as changed outside WordPress, and the
	 * administrators they added can sign in.
	 *
	 * One request at a time: the same lock as the code checks, taken without waiting (a request that does not
	 * get it compares with the snapshot as it will be, PNCP_Seal::current_snapshot()). The state is read again
	 * once the lock is held, so the snapshot is taken once.
	 */
	public static function expire_window() {
		if ( ! self::reseal_pending() || ! self::try_lock() ) {
			return;
		}
		try {
			self::reload();
			if ( ! self::reseal_pending() ) {
				return; // Another request did it a moment ago.
			}
			$noted = PNCP_Seal::window_summary();
			$gen   = PNCP_Seal::accept_window();
			$state = self::state();
			if ( $gen > 0 ) {
				$state['snap'] = $gen;
			}
			$state['until']          = 0;
			$state['unlocked_by']    = 0;
			$state['unlock_session'] = '';
			self::save( $state );
			PNCP_Seal::forget_window();
			$detail = implode( ', ', $noted['options'] ) . ( $noted['admins'] ? ( $noted['options'] ? ', ' : '' ) . 'admins: ' . $noted['admins'] : '' );
			// Logged on init: the current user is only looked up from then on.
			if ( did_action( 'init' ) ) {
				self::event( 'relocked_auto', $detail );
			} else {
				add_action(
					'init',
					static function () use ( $detail ) {
						self::event( 'relocked_auto', $detail );
					}
				);
			}
		} finally {
			self::release();
		}
	}

	/* ---------- Who ---------- */

	/**
	 * Capabilities that let an account administer the site (plugins, themes, files, users, settings, the
	 * Customizer). The accounts with any of them are the "administrators" of the lock's snapshot.
	 *
	 * @return string[]
	 */
	public static function control_caps() {
		return array( 'manage_options', 'activate_plugins', 'install_plugins', 'update_plugins', 'delete_plugins', 'edit_plugins', 'install_themes', 'update_themes', 'delete_themes', 'switch_themes', 'edit_themes', 'edit_theme_options', 'update_core', 'edit_files', 'create_users', 'edit_users', 'promote_users', 'delete_users', 'remove_users', 'unfiltered_upload', 'manage_network', 'manage_network_options', 'manage_network_plugins' );
	}

	/**
	 * Capabilities of an administrator: a role with any of them is always frozen while locked (it keeps only
	 * "read"); it cannot be unticked. The others of control_caps() (edit_theme_options, which WooCommerce
	 * gives to shop managers) do not freeze the whole role: they are refused like every capability of
	 * limited_caps().
	 *
	 * @return string[]
	 */
	private static function owner_caps() {
		return array_values( array_diff( self::control_caps(), array( 'edit_theme_options' ) ) );
	}

	/**
	 * The capabilities refused while locked to the roles that keep their work (shop managers, and every role
	 * that is not ticked on the Lockdown tab): everything that can change code, the look of the whole site,
	 * other users, settings or where payments go, or carry the site's data away. Content, products, orders,
	 * coupons, reports, media and comments are not in it. Filter: pncp_lockdown_limited_caps (only adds:
	 * control_caps() cannot be taken out).
	 *
	 * @return string[]
	 */
	public static function limited_caps() {
		if ( null === self::$limited_caps || ! self::$limited_final ) {
			$caps = array_merge(
				self::control_caps(),
				array(
					// Code and the look of the whole site: Customizer, Site Editor, menus, widgets, theme option
					// pages (some themes take scripts there), custom CSS, unfiltered HTML (scripts in content).
					'customize',
					'edit_css',
					'unfiltered_html',
					// WordPress itself and translations.
					'install_languages',
					'update_languages',
					'update_php',
					'update_https',
					'resume_plugins',
					'resume_themes',
					// Users and data of the whole site.
					'add_users',
					'import',
					'export',
					'manage_privacy_options',
					'export_others_personal_data',
					'erase_others_personal_data',
					// Multisite.
					'manage_sites',
					'create_sites',
					'delete_sites',
					'delete_site',
					'manage_network_users',
					'manage_network_themes',
					'upgrade_network',
					'setup_network',
					// WooCommerce settings: payment methods (where the money goes), shipping, taxes, emails,
					// the store's own API keys and webhooks, extensions.
					'manage_woocommerce',
				)
			);
			/**
			 * Filters the capabilities refused while the site is locked to roles that keep their work (shop
			 * managers and roles that are not ticked on the Lockdown tab). Capabilities can only be added.
			 *
			 * @param string[] $caps Capabilities.
			 */
			$more               = apply_filters( 'pncp_lockdown_limited_caps', $caps );
			self::$limited_caps = array_values( array_unique( array_merge( $caps, array_map( 'strval', is_array( $more ) ? $more : array() ) ) ) );
			// Kept for the request once every plugin has added its filters.
			self::$limited_final = (bool) did_action( 'plugins_loaded' );
		}
		return self::$limited_caps;
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
	 * Is this role always frozen (an administrator: it can take over the site)?
	 *
	 * @param string $role Role.
	 * @return bool
	 */
	public static function role_always( $role ) {
		return array() !== array_intersect( self::role_caps( $role ), self::owner_caps() );
	}

	/**
	 * Does this role have capabilities that are refused while locked (limited_caps())? Such a role, when it is
	 * not frozen, keeps its work while locked without them (shop managers by default).
	 *
	 * @param string $role Role.
	 * @return bool
	 */
	public static function role_limited( $role ) {
		return array() !== array_intersect( self::role_caps( $role ), self::limited_caps() );
	}

	/**
	 * A WooCommerce shop role (shop manager, or a role of another plugin with the same rights)?
	 *
	 * @param string $role Role.
	 * @return bool
	 */
	private static function shop_role( $role ) {
		return array() !== array_intersect( self::role_caps( $role ), array( 'manage_woocommerce', 'edit_shop_orders', 'edit_others_shop_orders' ) );
	}

	/**
	 * Is this role frozen when nothing was chosen? Roles that can take over the site, editorial staff, and
	 * WordPress' own content roles. Shop roles are not: shop managers keep orders, products, coupons, reports
	 * and content while locked, without the capabilities of limited_caps(). Subscribers, customers and member
	 * roles of other plugins (e.g. accounts that post listings or community posts) are not frozen either.
	 *
	 * @param string $role Role.
	 * @return bool
	 */
	private static function role_default( $role ) {
		if ( self::role_always( $role ) || in_array( $role, array( 'administrator', 'editor', 'author', 'contributor' ), true ) ) {
			return true;
		}
		return ! self::shop_role( $role ) && array() !== array_intersect( self::role_caps( $role ), self::staff_caps() );
	}

	/**
	 * The roles frozen while locked (only "read"): the ones chosen on the Lockdown tab (or the defaults), plus
	 * every role that can take over the site.
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
	 * The roles that keep their work while locked, without the capabilities of limited_caps(): the roles that
	 * are not frozen but have any of them (shop managers by default).
	 *
	 * @return string[]
	 */
	public static function limited_roles() {
		$frozen = self::frozen_roles();
		$roles  = array();
		foreach ( array_keys( wp_roles()->get_names() ) as $role ) {
			if ( ! in_array( $role, $frozen, true ) && self::role_limited( $role ) ) {
				$roles[] = $role;
			}
		}
		return $roles;
	}

	/**
	 * What these stored capabilities ({prefix}capabilities) make a user while locked: 2 = frozen (a frozen
	 * role, or a single capability of staff given to the user), 1 = keeps its work without the capabilities
	 * of limited_caps() (a role of limited_roles()), 0 = not touched.
	 *
	 * @param mixed $caps {prefix}capabilities value.
	 * @return int
	 */
	private static function grants_level( $caps ) {
		if ( ! is_array( $caps ) ) {
			return 0;
		}
		$frozen = self::frozen_roles();
		$roles  = wp_roles();
		$level  = 0;
		foreach ( $caps as $name => $grant ) {
			$name = (string) $name;
			if ( ! $grant ) {
				continue;
			}
			if ( $roles->is_role( $name ) ) {
				if ( in_array( $name, $frozen, true ) ) {
					return 2;
				}
				if ( self::role_limited( $name ) ) {
					$level = 1;
				}
			} elseif ( in_array( $name, array_merge( self::control_caps(), self::staff_caps() ), true ) ) {
				return 2;
			}
		}
		return $level;
	}

	/**
	 * Do these stored capabilities ({prefix}capabilities) make a user staff (frozen, or keeping its work
	 * without the capabilities of limited_caps())?
	 *
	 * @param mixed $caps {prefix}capabilities value.
	 * @return bool
	 */
	private static function grants_staff( $caps ) {
		return self::grants_level( $caps ) > 0;
	}

	/**
	 * What a user is while locked: 2 = frozen, 1 = keeps its work without the capabilities of limited_caps(),
	 * 0 = not touched (see grants_level()). Network admins are frozen.
	 *
	 * @param int $user_id User.
	 * @return int
	 */
	public static function staff_level( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id < 1 ) {
			return 0;
		}
		if ( ! isset( self::$staff[ $user_id ] ) ) {
			self::$staff[ $user_id ] = ( is_multisite() && is_super_admin( $user_id ) ) ? 2 : self::grants_level( self::user_caps( $user_id ) );
		}
		return self::$staff[ $user_id ];
	}

	/**
	 * Staff: users with a frozen role (see frozen_roles()), a role that keeps its work while locked (see
	 * limited_roles()) or a staff capability of their own. Their email, password and application passwords
	 * stay as they are while locked. Everyone else (customers, subscribers, members) is not touched by the
	 * lock. Uses the roles as stored, not the capabilities the lock takes away.
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	public static function is_staff( $user_id ) {
		return self::staff_level( $user_id ) > 0;
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
	 * While locked, frozen staff keep only "read": wp-admin opens, nothing can be changed. Roles that keep
	 * their work (shop managers by default) lose only the capabilities of limited_caps().
	 *
	 * @param string[] $caps    Primitive capabilities required.
	 * @param string   $cap     Capability checked.
	 * @param int      $user_id User.
	 * @param mixed[]  $args    Object ID etc.
	 * @return string[]
	 */
	public static function map_meta_cap( $caps, $cap, $user_id, $args = array() ) {
		if ( self::$bypass || ! $user_id || in_array( $cap, array( 'read', 'exist', 'level_0' ), true ) ) {
			return $caps;
		}
		// Unlocked for a while: only for the administrator who unlocked, and only in the browser session they
		// unlocked with. Other staff, another session of the same account (a stolen cookie), an application
		// password, XML-RPC and WooCommerce API keys stay as when locked: someone who can write to the database
		// could have planted a password or key for that account in advance.
		$by     = (int) self::state()['unlocked_by'];
		$frozen = self::is_locked() || ( $by > 0 && self::unlocked_until() && ( (int) $user_id !== $by || ! self::unlocking_session( (int) $user_id ) ) );
		$level  = $frozen ? self::staff_level( $user_id ) : 0;
		if ( $level < 1 ) {
			return $caps;
		}
		if ( $level > 1 || self::limited_refuses( (array) $caps, (string) $cap, (int) $user_id, (array) $args ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	/**
	 * Is this capability refused to a role that keeps its work while locked? Any capability of limited_caps(),
	 * asked for directly or needed for it. Editing another user is allowed only for users the lock does not
	 * touch (customers, subscribers), as WooCommerce lets shop managers do; never for staff or administrators.
	 *
	 * @param string[] $caps    Primitive capabilities required.
	 * @param string   $cap     Capability checked.
	 * @param int      $user_id User.
	 * @param mixed[]  $args    Object ID etc.
	 * @return bool
	 */
	private static function limited_refuses( $caps, $cap, $user_id, $args ) {
		$check = array_merge( array( $cap ), array_map( 'strval', $caps ) );
		// 3.4.2: also current_user_can( 'edit_users', $id ) with a user id, as the WooCommerce REST API asks it
		// (wc/v3/customers): the same edit of one customer as user-edit.php and wp/v2/users.
		if ( in_array( $cap, array( 'edit_user', 'edit_users' ), true ) && isset( $args[0] ) && is_numeric( $args[0] ) && (int) $args[0] > 0 && (int) $args[0] !== $user_id && ! self::is_staff( (int) $args[0] ) ) {
			$check = array_diff( $check, array( 'edit_users' ) );
		}
		return array() !== array_intersect( $check, self::limited_caps() );
	}

	/**
	 * The fingerprint of a session token as kept in the lock state. Keyed with the keys in wp-config.php, so it
	 * is not the value WordPress stores the session under (session_tokens) and cannot be made from the database.
	 *
	 * @param string $token Session token.
	 * @return string
	 */
	private static function session_hash( $token ) {
		return hash_hmac( 'sha256', (string) $token, PNCP_Seal::key_material() . '|pncp_unlock_session' );
	}

	/**
	 * Is this request signed in, with a valid login cookie, in the session that unlocked the site for a while?
	 * Not for application passwords, XML-RPC or anything else that does not carry that cookie (WooCommerce API
	 * keys, WP-CLI, scheduled events).
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	private static function unlocking_session( $user_id ) {
		if ( isset( self::$session_ok[ $user_id ] ) ) {
			return self::$session_ok[ $user_id ];
		}
		// False while checking: code hooked to the cookie check could ask for capabilities again.
		self::$session_ok[ $user_id ] = false;
		$hash = (string) self::state()['unlock_session'];
		if ( '' === $hash || self::$app_password || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || get_current_user_id() !== $user_id ) {
			return false;
		}
		$cookie = wp_parse_auth_cookie( '', 'logged_in' );
		if ( empty( $cookie['token'] ) || ! hash_equals( $hash, self::session_hash( $cookie['token'] ) ) ) {
			return false;
		}
		// The cookie must be genuine and its session still open (signed out = no rights).
		self::$session_ok[ $user_id ] = (int) wp_validate_auth_cookie( '', 'logged_in' ) === $user_id;
		return self::$session_ok[ $user_id ];
	}

	/**
	 * Notes that this request signed in with an application password.
	 */
	public static function note_app_password() {
		self::$app_password = true;
		self::$session_ok   = array();
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
		// 3.3: also the uploads folder and its address (a folder where PHP runs) and whether search engines
		// may index the site.
		return array( 'active_plugins', 'template', 'stylesheet', 'siteurl', 'home', 'admin_email', 'new_admin_email', 'users_can_register', 'default_role', $wpdb->get_blog_prefix() . 'user_roles', 'upload_path', 'upload_url_path', 'blog_public', PNCP_OPTION, PNCP_Edge::CONFIG, self::OPTION );
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
	 * No application passwords (a back door) for staff while locked, and while unlocked for a while: they can
	 * neither be used nor created until the site is unlocked "until I lock it again".
	 *
	 * @param bool    $available Available.
	 * @param WP_User $user      User.
	 * @return bool
	 */
	public static function app_passwords( $available, $user ) {
		return $user instanceof WP_User && ( self::is_locked() || self::unlocked_until() ) && self::is_staff( $user->ID ) ? false : $available;
	}

	/**
	 * While there is a snapshot of a lock: a staff application password that was not there when the site was
	 * locked is refused (it can only have been added in the database), also with SCRAPELOCK_UNLOCK.
	 *
	 * @param WP_Error             $error Errors so far.
	 * @param WP_User              $user  User.
	 * @param array<string, mixed> $item  The application password.
	 */
	public static function app_password_errors( $error, $user, $item ) {
		if ( ! $error instanceof WP_Error || ! $user instanceof WP_User || ! isset( $item['uuid'] ) || ! PNCP_Seal::app_password_new( $user->ID, (string) $item['uuid'] ) ) {
			return;
		}
		self::tamper_alert( 'apps', $user->user_login );
		$error->add( 'pncp_locked', __( 'This application password was added while the site was locked and cannot be used.', 'scrapelock' ) );
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
		// The same refusal is logged at most once every 10 minutes: code that retries on every page (a cache
		// plugin rewriting its settings, for example) would otherwise write to the database on every request.
		$key = 'pncp_ld_ref_' . md5( $what );
		if ( get_site_transient( $key ) ) {
			return;
		}
		set_site_transient( $key, 1, 10 * MINUTE_IN_SECONDS );
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
		return hash( 'sha256', PNCP_Seal::key_material() . '|pncp_lockdown', true );
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
	 * How long codes are refused after too many wrong ones: the first time, the second time, and from the third
	 * time on. The count of lockouts is forgotten a day after the last one ended.
	 *
	 * @return int[] Seconds.
	 */
	private static function lockout_steps() {
		return array( 15 * MINUTE_IN_SECONDS, HOUR_IN_SECONDS, 6 * HOUR_IN_SECONDS );
	}

	/**
	 * The wrong-code counters this request is counted in: their limit, how long they count, whether reaching the
	 * limit locks out (for longer each time) and whether the limit also holds back recovery codes.
	 *
	 * Per account from this IP: not per account alone, so that someone using a stolen session of the owner's own
	 * account somewhere else cannot use up the owner's tries. Per account from all IPs: a higher limit, so that a
	 * stolen session cannot guess from many IPs. Per IP (IPv6: per /64): all accounts together. And a ceiling for
	 * the whole site: guessing from many accounts and IPs at once stops. Recovery codes (long and random, so they
	 * cannot be guessed) are only held back by the per-IP limit: whatever happens on other IPs or other sessions
	 * of the same account, the owner can still unlock with one.
	 *
	 * @return array<string, array{limit: int, window: int, lockout: bool, recovery: bool}>
	 */
	private static function fail_buckets() {
		$user = get_current_user_id();
		// 3.4: a keyed hash of the IP (the counters are also copied to a file next to the guard, see fails_save()).
		$ip = substr( PNCP_Seal::sign( array( 'fails_ip', PNCP_Ip::limit_key( PNCP_Ip::client_ip() ) ) ), 0, 32 );
		return array(
			'u:' . $user . ':' . $ip => array(
				'limit'    => self::MAX_FAILS,
				'window'   => 15 * MINUTE_IN_SECONDS,
				'lockout'  => true,
				'recovery' => false,
			),
			'a:' . $user             => array(
				'limit'    => self::MAX_FAILS_ACCOUNT,
				'window'   => HOUR_IN_SECONDS,
				'lockout'  => true,
				'recovery' => false,
			),
			'i:' . $ip               => array(
				'limit'    => self::MAX_FAILS_ALL,
				'window'   => HOUR_IN_SECONDS,
				'lockout'  => true,
				'recovery' => true,
			),
			'site'                   => array(
				'limit'    => self::MAX_FAILS_SITE,
				'window'   => HOUR_IN_SECONDS,
				'lockout'  => false,
				'recovery' => false,
			),
		);
	}

	/**
	 * One counter: wrong codes since the start of its window, locked out until, lockouts so far, last change.
	 *
	 * @param array<string, mixed> $fails All counters.
	 * @param string               $key   Counter.
	 * @return array{n: int, start: int, until: int, level: int, last: int}
	 */
	private static function fail_row( $fails, $key ) {
		$row = isset( $fails[ $key ] ) && is_array( $fails[ $key ] ) ? $fails[ $key ] : array();
		$out = array();
		foreach ( array( 'n', 'start', 'until', 'level', 'last' ) as $field ) {
			$out[ $field ] = isset( $row[ $field ] ) ? max( 0, (int) $row[ $field ] ) : 0;
		}
		// 3.4: values this code never writes are ignored, so a counter changed in the database (or a copy of
		// one from much earlier) cannot refuse codes for longer than a real lockout: a window that starts in the
		// future, a lockout that ends more than the longest lockout from now.
		$now   = time();
		$steps = self::lockout_steps();
		if ( $out['start'] > $now + 60 ) {
			$out['n']     = 0;
			$out['start'] = 0;
		}
		if ( $out['until'] > $now + max( $steps ) + 60 ) {
			$out['until'] = 0;
		}
		return $out;
	}

	/**
	 * The wrong-code counters as they are in the database now (called inside the lock, so never an older copy
	 * from earlier in the request or from the cache).
	 *
	 * @return array<string, mixed>
	 */
	private static function fails_load() {
		self::reload();
		return self::fails_read();
	}

	/**
	 * The wrong-code counters as stored, if they match their signature. 3.4: they are signed, so counters
	 * written in the database (for example a lockout of the owner's IP that would last for years) count as
	 * none; counters stored by an earlier version start over once.
	 *
	 * @return array<string, mixed>
	 */
	private static function fails_read() {
		$db   = self::fails_db();
		$file = self::fails_file_read();
		// 3.4: while the guard is in place, the counters are also kept in a file next to it, and every save counts
		// one up in both (3.4.1: with the lock file instead of the guard, the weaker lock, next to the lock file).
		// Counters deleted in the database, or set back to an older copy, would otherwise start again from
		// nothing: a file further on than the database counts instead, and the owner is alerted.
		if ( $file['seq'] > $db['seq'] ) {
			self::tamper_alert( 'fails' );
			return $file['rows'];
		}
		return $db['rows'];
	}

	/**
	 * The counters in the database, if they match their signature: rows and the number of their save (0 for
	 * counters saved before the copy in the file).
	 *
	 * @return array{rows: array<string, mixed>, seq: int}
	 */
	private static function fails_db() {
		$stored = get_site_option( self::FAILS_OPTION, array() );
		$none   = array(
			'rows' => array(),
			'seq'  => 0,
		);
		if ( ! is_array( $stored ) || ! isset( $stored['rows'], $stored['sig'] ) || ! is_array( $stored['rows'] ) ) {
			return $none;
		}
		$seq    = isset( $stored['seq'] ) ? (int) $stored['seq'] : 0;
		$signed = isset( $stored['seq'] ) ? array(
			'fails' => $stored['rows'],
			'seq'   => $seq,
		) : array( 'fails' => $stored['rows'] );
		if ( ! PNCP_Seal::valid( $signed, $stored['sig'] ) ) {
			return $none;
		}
		return array(
			'rows' => $stored['rows'],
			'seq'  => $seq,
		);
	}

	/**
	 * The first line of the file with the copy of the wrong-code counters: PHP that stops at once, so a web
	 * request to the file shows nothing (a .json file is shown as it is by the web server).
	 */
	const FAILS_HEAD = "<?php exit; ?>\n";

	/**
	 * The index.php of the folder of that file: no folder listing on servers that would show one.
	 */
	const FAILS_INDEX = "<?php\n// Silence is golden.\n";

	/**
	 * The folder of the copy of the wrong-code counters: a sub-folder of the must-use plugins folder, whose
	 * files WordPress never loads (it only loads the PHP files directly in that folder).
	 *
	 * @return string
	 */
	public static function fails_dir() {
		return PNCP_Paths::mu_plugins() . '/scrapelock-lockdown-data';
	}

	/**
	 * The file with the copy of the wrong-code counters (next to the guard, see fails_read()). 3.4.1: a PHP file
	 * that starts with FAILS_HEAD, then the JSON, so the web server never shows its content.
	 *
	 * @return string
	 */
	public static function fails_file() {
		return self::fails_dir() . '/fails.php';
	}

	/**
	 * Where 3.4.0 kept that copy (a .json file the web server shows to anyone). Read once more and deleted
	 * (fails_file_read()).
	 *
	 * @return string
	 */
	public static function fails_file_legacy() {
		return PNCP_Paths::mu_plugins() . '/scrapelock-lockdown-fails.json';
	}

	/**
	 * Is this a file of the counters' folder exactly as ScrapeLock writes it, which cannot run any code? Its
	 * index.php, or the counters file: FAILS_HEAD and then text without "<" (the JSON is written with "<" and
	 * ">" escaped), so nothing after the first line can open PHP again. The file integrity check does not note
	 * them (they change on every wrong code); a file there with anything else in it is checked like any other.
	 *
	 * @param string $path File.
	 * @return bool
	 */
	public static function fails_inert( $path ) {
		$path = wp_normalize_path( (string) $path );
		if ( wp_normalize_path( dirname( $path ) ) !== wp_normalize_path( self::fails_dir() ) || ! is_readable( $path ) ) {
			return false;
		}
		$name = basename( $path );
		if ( 'index.php' !== $name && 'fails.php' !== $name ) {
			return false;
		}
		clearstatcache( true, $path );
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable = checked.
		if ( false === $size || $size > 2097152 ) {
			return false; // Far more than 1000 counters: not what ScrapeLock writes.
		}
		$data = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file; unreadable = checked.
		if ( ! is_string( $data ) ) {
			return false;
		}
		if ( 'index.php' === $name ) {
			return self::FAILS_INDEX === $data;
		}
		return 0 === strpos( $data, self::FAILS_HEAD ) && false === strpos( substr( $data, strlen( self::FAILS_HEAD ) ), '<' );
	}

	/**
	 * The signed counters in a file's content (otherwise none): rows and the number of their save.
	 *
	 * @param string|false $text The JSON.
	 * @return array{rows: array<string, mixed>, seq: int, raw: array<string, mixed>|null}
	 */
	private static function fails_parse( $text ) {
		$none = array(
			'rows' => array(),
			'seq'  => 0,
			'raw'  => null,
		);
		$data = is_string( $text ) ? json_decode( $text, true ) : null;
		if ( ! is_array( $data ) || ! isset( $data['rows'], $data['seq'], $data['sig'] ) || ! is_array( $data['rows'] ) || ! is_string( $data['sig'] ) ) {
			return $none;
		}
		$signed = array(
			'fails_file' => $data['rows'],
			'seq'        => (int) $data['seq'],
		);
		if ( ! PNCP_Seal::valid( $signed, $data['sig'] ) ) {
			return $none;
		}
		return array(
			'rows' => $data['rows'],
			'seq'  => (int) $data['seq'],
			'raw'  => array(
				'rows' => $data['rows'],
				'seq'  => (int) $data['seq'],
				'sig'  => $data['sig'],
			),
		);
	}

	/**
	 * The counters in the file, if it matches its signature (otherwise none): rows and the number of their save.
	 * 3.4.1: a .json file left by 3.4.0 still counts (so the upgrade does not set the counters back): it is moved
	 * into the new file, then deleted. Also the copy next to the lock file (the weaker lock), whichever of them
	 * is furthest on.
	 *
	 * @return array{rows: array<string, mixed>, seq: int}
	 */
	private static function fails_file_read() {
		$file = array(
			'rows' => array(),
			'seq'  => 0,
			'raw'  => null,
		);
		foreach ( array_merge( array( self::fails_file() ), PNCP_Seal::beacon_fails_paths() ) as $path ) {
			if ( ! is_readable( $path ) ) {
				continue;
			}
			clearstatcache( true, $path );
			$text = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			if ( 0 === strpos( $text, self::FAILS_HEAD ) ) {
				$one = self::fails_parse( substr( $text, strlen( self::FAILS_HEAD ) ) );
				if ( $one['seq'] > $file['seq'] ) {
					$file = $one;
				}
			}
		}
		$legacy = self::fails_file_legacy();
		if ( file_exists( $legacy ) ) {
			$old = self::fails_parse( is_readable( $legacy ) ? file_get_contents( $legacy ) : false ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			$to  = self::fails_target();
			if ( $old['seq'] > $file['seq'] && '' !== $to ) {
				// Moved only when written (otherwise it stays, and still counts, until it can be).
				$moved = self::fails_file_put( $old['raw'], $to );
				$file  = $old;
			} else {
				// Not further on than the new file (or not genuine): nothing in it counts. Without a guard or a lock
				// file there is nothing to keep it next to (it went with the guard in 3.4.0).
				$moved = true;
			}
			if ( $moved ) {
				wp_delete_file( $legacy );
			}
		}
		return array(
			'rows' => $file['rows'],
			'seq'  => $file['seq'],
		);
	}

	/**
	 * 3.4.1: moves the counters of a .json file left by 3.4.0 (shown by the web server to anyone) into the new
	 * file and deletes it, on the upgrade and in the hourly check, so it does not wait until a code is checked.
	 */
	public static function fails_migrate() {
		if ( file_exists( self::fails_file_legacy() ) ) {
			self::fails_file_read();
		}
	}

	/**
	 * 3.4.1: the files of the lock outside the database, on the upgrade and in the hourly check: a .json file of
	 * counters left by 3.4.0 is moved (see fails_migrate()), and a site locked without the guard file and
	 * without any signed copy outside the database (locked by 3.4.0 without the guard, or while no folder could
	 * be written) gets its signed lock file as soon as a folder can be written. Until then, deleting the Lockdown
	 * data in the database would open the lock without it being noticed.
	 */
	public static function maintain_files() {
		self::fails_migrate();
		if ( self::server_unlocked() || '' !== self::tampered() ) {
			return;
		}
		$state = self::state();
		if ( empty( $state['locked'] ) || PNCP_Seal::guard_installed() || '' !== PNCP_Seal::beacon_path() ) {
			return;
		}
		if ( ! PNCP_Seal::can_write_guard() && '' === PNCP_Seal::beacon_writable_dir() ) {
			return;
		}
		// With the generations of the state stored now: an unlock that runs meanwhile removes the files first and
		// signs a higher generation, so a file written here a moment later no longer counts (seal_check()).
		if ( PNCP_Seal::write_lock_files( true, (int) $state['until'], (int) $state['gen'], (int) $state['snap'] ) ) {
			$path = PNCP_Seal::guard_installed() ? PNCP_Seal::path() : PNCP_Seal::beacon_path();
			self::event( 'lock_file', PNCP_Seal::short_path( $path ) );
		}
	}

	/**
	 * 3.4.1: the file the copy of the counters is written to: next to the guard while it is there, otherwise
	 * next to the lock file ('' when there is neither).
	 *
	 * @return string
	 */
	private static function fails_target() {
		if ( PNCP_Seal::guard_installed() ) {
			return self::fails_file();
		}
		return PNCP_Seal::beacon_fails_path();
	}

	/**
	 * Writes the counters file (and its folder with an index.php), unless the file already holds a later save.
	 * The file is locked while it is read and written, so an older copy never overwrites a newer one.
	 *
	 * @param array<string, mixed> $stored Rows, seq and signature.
	 * @param string               $path   3.4.1: the file (see fails_target()). The folder of the lock file is
	 *                                     never created here: it is there with the lock file.
	 * @return bool Whether the file holds this save (or a later one) now.
	 */
	private static function fails_file_put( $stored, $path ) {
		$dir = dirname( $path );
		// phpcs:disable WordPress.WP.AlternativeFunctions -- Small data files of the guard; flock() needs a handle from fopen().
		if ( self::fails_file() === $path ) {
			if ( ! is_dir( $dir ) ) {
				if ( ! wp_is_writable( dirname( $dir ) ) || ! wp_mkdir_p( $dir ) ) {
					return false;
				}
			}
			if ( ! file_exists( $dir . '/index.php' ) ) {
				@file_put_contents( $dir . '/index.php', self::FAILS_INDEX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Only keeps folder listings away.
			}
		} elseif ( ! is_dir( $dir ) ) {
			return false;
		}
		$json = wp_json_encode( $stored, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT );
		if ( ! is_string( $json ) ) {
			return false;
		}
		$handle = @fopen( $path, 'c+' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Not writable: no copy.
		if ( false === $handle ) {
			return false;
		}
		$ok = false;
		if ( flock( $handle, LOCK_EX ) ) {
			$text = (string) stream_get_contents( $handle, -1, 0 );
			$now  = 0 === strpos( $text, self::FAILS_HEAD ) ? self::fails_parse( substr( $text, strlen( self::FAILS_HEAD ) ) ) : array( 'seq' => 0 );
			if ( $now['seq'] >= (int) $stored['seq'] ) {
				$ok = true;
			} elseif ( ftruncate( $handle, 0 ) && rewind( $handle ) ) {
				$ok = false !== fwrite( $handle, self::FAILS_HEAD . $json );
				fflush( $handle );
			}
			flock( $handle, LOCK_UN );
		}
		fclose( $handle );
		// phpcs:enable WordPress.WP.AlternativeFunctions
		return $ok;
	}

	/**
	 * Removes the counters file, its folder and a .json file left by 3.4.0 (with the guard, on deactivation and
	 * on uninstall). 3.4.1: and the copy next to the lock file.
	 */
	public static function fails_remove() {
		$dir = self::fails_dir();
		foreach ( array_merge( array( self::fails_file_legacy(), $dir . '/fails.php', $dir . '/index.php' ), PNCP_Seal::beacon_fails_paths() ) as $file ) {
			if ( file_exists( $file ) ) {
				wp_delete_file( $file );
			}
		}
		if ( is_dir( $dir ) ) {
			@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Only succeeds when empty (nothing of someone else is removed).
		}
	}

	/**
	 * Saves the wrong-code counters. A counter is kept while it counts, while its lockout lasts and for a day
	 * after it (so that the next lockout is longer); at most 1000 of them, so that wrong codes from very many IPs
	 * cannot make the option grow without end. The ones with a lockout that still lasts are kept first.
	 *
	 * @param array<string, mixed> $fails All counters.
	 */
	private static function fails_save( $fails ) {
		$now  = time();
		$keep = array();
		foreach ( $fails as $key => $row ) {
			$row = self::fail_row( $fails, $key );
			if ( $row['start'] + HOUR_IN_SECONDS >= $now || $row['until'] + DAY_IN_SECONDS >= $now ) {
				$keep[ $key ] = $row;
			}
		}
		if ( count( $keep ) > 1000 ) {
			uasort(
				$keep,
				static function ( $a, $b ) use ( $now ) {
					$locked = (int) ( $b['until'] > $now ) - (int) ( $a['until'] > $now );
					return $locked ? $locked : $b['last'] - $a['last'];
				}
			);
			$keep = array_slice( $keep, 0, 1000, true );
		}
		// 3.4: one more than the last save in the database and in the file (see fails_read()).
		$seq    = max( self::fails_db()['seq'], self::fails_file_read()['seq'] ) + 1;
		$stored = array(
			'rows' => $keep,
			'seq'  => $seq,
			// Named, so it cannot pass for other signed data.
			'sig'  => PNCP_Seal::sign(
				array(
					'fails' => $keep,
					'seq'   => $seq,
				)
			),
		);
		if ( is_multisite() ) {
			update_site_option( self::FAILS_OPTION, $stored );
		} else {
			update_option( self::FAILS_OPTION, $stored, false ); // Not autoloaded: only read on the Lockdown page.
		}
		// 3.4: the copy in the file next to the guard (after the database: a file newer than the database means
		// the database was changed). Only while the guard is there; the file goes with it. 3.4.1: without the
		// guard, next to the lock file (the weaker lock), and it goes with that.
		$to = self::fails_target();
		if ( '' !== $to ) {
			self::fails_file_put(
				array(
					'rows' => $keep,
					'seq'  => $seq,
					'sig'  => PNCP_Seal::sign(
						array(
							'fails_file' => $keep,
							'seq'        => $seq,
						)
					),
				),
				$to
			);
		}
	}

	/**
	 * Until when codes typed on this request are refused (0: they are not).
	 *
	 * @param array<string, mixed> $fails    All counters.
	 * @param bool                 $recovery The code has the shape of a recovery code.
	 * @return int
	 */
	private static function blocked_until( $fails, $recovery ) {
		$now   = time();
		$until = 0;
		foreach ( self::fail_buckets() as $key => $bucket ) {
			if ( $recovery && ! $bucket['recovery'] ) {
				continue;
			}
			$row = self::fail_row( $fails, $key );
			if ( $bucket['lockout'] && $row['until'] > $now ) {
				$until = max( $until, $row['until'] );
			} elseif ( ! $bucket['lockout'] && $row['n'] >= $bucket['limit'] && $row['start'] + $bucket['window'] > $now ) {
				$until = max( $until, $row['start'] + $bucket['window'] );
			}
		}
		return $until;
	}

	/**
	 * Counts a wrong code in every counter of this request (a wrong recovery code only in the per-IP one: it is
	 * only held back there). A counter that reaches its limit locks out: 15 minutes the first time, then 1 hour,
	 * then 6 hours.
	 *
	 * @param array<string, mixed> $fails    All counters (changed).
	 * @param bool                 $recovery The code has the shape of a recovery code.
	 * @return array<int, array{0: string, 1: int}> The lockouts this wrong code started: kind and seconds.
	 */
	private static function count_fail( &$fails, $recovery ) {
		$now   = time();
		$steps = self::lockout_steps();
		$out   = array();
		foreach ( self::fail_buckets() as $key => $bucket ) {
			if ( $recovery && ! $bucket['recovery'] ) {
				continue;
			}
			$row = self::fail_row( $fails, $key );
			if ( $row['start'] + $bucket['window'] <= $now ) {
				$row['n']     = 0;
				$row['start'] = $now;
			}
			if ( $row['level'] && $row['until'] + DAY_IN_SECONDS < $now ) {
				$row['level'] = 0; // A day without a lockout: the next one is the shortest again.
			}
			++$row['n'];
			$row['last'] = $now;
			if ( $bucket['lockout'] && $row['n'] >= $bucket['limit'] ) {
				$length       = $steps[ min( $row['level'], count( $steps ) - 1 ) ];
				$row['until'] = $now + $length;
				$row['n']     = 0;
				$row['start'] = $now;
				++$row['level'];
				$out[] = array( substr( $key, 0, 1 ), $length );
			} elseif ( ! $bucket['lockout'] && $row['n'] === $bucket['limit'] ) {
				$out[] = array( 's', $row['start'] + $bucket['window'] - $now );
			}
			$fails[ $key ] = $row;
		}
		return $out;
	}

	/**
	 * Logs a lockout and emails the site's administration address about it.
	 *
	 * @param string $kind   'u' (this account from this IP), 'a' (this account), 'i' (this IP) or 's' (the site).
	 * @param int    $length Seconds.
	 */
	private static function lockout_notice( $kind, $length ) {
		$time = human_time_diff( 0, max( 60, $length ) );
		switch ( $kind ) {
			case 'u':
				/* translators: %s: length of time, e.g. "15 mins" */
				$message = sprintf( __( 'Someone typed several wrong authenticator codes on the Lockdown page. Further codes from that account and IP are refused for %s. If it was not you, change that account\'s password and sign out its other sessions on the Lockdown page.', 'scrapelock' ), $time );
				$detail  = __( 'account and IP', 'scrapelock' );
				break;
			case 'a':
				/* translators: %s: length of time, e.g. "1 hour" */
				$message = sprintf( __( 'Many wrong authenticator codes were typed on the Lockdown page with the same account. Further app codes from that account are refused for %s; recovery codes still work. If it was not you, change that account\'s password and sign out its other sessions on the Lockdown page.', 'scrapelock' ), $time );
				$detail  = __( 'account', 'scrapelock' );
				break;
			case 'i':
				/* translators: %s: length of time, e.g. "1 hour" */
				$message = sprintf( __( 'Many wrong codes on the Lockdown page came from the same IP. Further codes from that IP are refused for %s.', 'scrapelock' ), $time );
				$detail  = __( 'IP', 'scrapelock' );
				break;
			default:
				/* translators: %s: length of time, e.g. "1 hour" */
				$message = sprintf( __( 'Many wrong codes were typed on the Lockdown page, from several accounts or IPs. App codes are refused on the whole site for up to %s; recovery codes still work. Check who has administrator access to the site.', 'scrapelock' ), $time );
				$detail  = __( 'whole site', 'scrapelock' );
		}
		self::event( 'lockout', $detail . ', ' . $time );
		self::mail( __( 'Too many wrong lockdown codes', 'scrapelock' ), $message );
	}

	/**
	 * Checks a code in one critical section: under the lock, on what is in the database now, the counters are
	 * checked, the code is checked and a wrong code is counted. Parallel requests wait for each other, so they
	 * cannot all pass the counter check before any of them is counted, and the same code cannot be used twice.
	 *
	 * @param callable $check    Checks the code, inside the lock: returns '' if it is wrong.
	 * @param bool     $recovery The code has the shape of a recovery code (only the per-IP limit holds it back).
	 * @param bool     $correct  3.4.2: the code was found correct before the lock (it is checked again inside it):
	 *                           it goes before requests with codes that are not (see fallback_lock()).
	 * @return string What $check returned, '' (wrong), 'wait' (too many wrong codes) or 'busy' (no lock).
	 */
	private static function attempt( $check, $recovery, $correct = false ) {
		if ( ! self::lock( $correct ) ) {
			return 'busy';
		}
		$lockouts = array();
		try {
			$fails = self::fails_load();
			if ( self::blocked_until( $fails, $recovery ) ) {
				$result = 'wait';
			} else {
				$result = (string) call_user_func( $check );
				if ( '' === $result ) {
					$lockouts = self::count_fail( $fails, $recovery );
					self::fails_save( $fails );
				}
			}
		} finally {
			self::release();
		}
		if ( '' === $result ) {
			self::event( 'failed' );
		}
		foreach ( $lockouts as $lockout ) {
			self::lockout_notice( $lockout[0], $lockout[1] );
		}
		return $result;
	}

	/**
	 * Until when app codes (and recovery codes) typed now from this account and IP would be refused, for the
	 * message on the page (read without the lock: only shown).
	 *
	 * @return int[] Array of two: app codes, recovery codes (0: not refused).
	 */
	private static function wait_until() {
		$fails = self::fails_read();
		return array( self::blocked_until( $fails, false ), self::blocked_until( $fails, true ) );
	}

	/**
	 * Signs out every other session of the current account (needs a correct code, also while locked: someone
	 * with a stolen session must not stay signed in). The session of this request stays.
	 *
	 * @return bool
	 */
	private static function sign_out_others() {
		$token = wp_get_session_token();
		if ( '' === $token ) {
			return false;
		}
		WP_Session_Tokens::get_instance( get_current_user_id() )->destroy_others( $token );
		self::event( 'sessions' );
		return true;
	}

	/**
	 * Checks a code from the app or, if allowed, a recovery code (used up). Only inside attempt(), so on the
	 * state as it is in the database now: two requests with the same code at the same moment cannot both pass
	 * (the second sees the step or the recovery code already used). A code with the shape of a recovery code is
	 * never checked as an app code (app codes have 6 digits), so it cannot be used to guess app codes past the
	 * limits that hold back app codes.
	 *
	 * @param string      $code           Code typed.
	 * @param bool        $allow_recovery Recovery codes accepted.
	 * @param string|null $found          The stored hash the code matched, found before the lock was taken
	 *                                    (recovery_match(): '' when none), or null to compare here.
	 * @return string 'app', 'recovery' or '' (wrong).
	 */
	private static function check_code_locked( $code, $allow_recovery, $found = null ) {
		$state  = self::state();
		$secret = self::unseal( $state['secret'] );
		$step   = '' !== $secret ? PNCP_Totp::verify( $secret, $code, (int) $state['last_step'] ) : false;
		if ( false !== $step ) {
			$state['last_step'] = $step;
			self::save( $state );
			return 'app';
		}
		$typed = strtolower( preg_replace( '/[^a-z0-9]/i', '', (string) $code ) );
		if ( $allow_recovery && 8 === strlen( $typed ) && '' !== $found ) {
			$typed = substr( $typed, 0, 4 ) . '-' . substr( $typed, 4 );
			foreach ( $state['codes'] as $i => $hash ) {
				// The hash found before the lock must still be there (not used up meanwhile by another request).
				if ( null !== $found ? hash_equals( (string) $hash, $found ) : password_verify( $typed, $hash ) ) {
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
	 * 3.4.2: is this the current code of the app, as the state reads now (before the lock; check_code_locked()
	 * checks it again inside it)? Only to let it go first (see fallback_lock()).
	 *
	 * @param string $code Code typed.
	 * @return bool
	 */
	private static function app_code_ok( $code ) {
		$state  = self::state();
		$secret = self::unseal( $state['secret'] );
		return '' !== $secret && false !== PNCP_Totp::verify( $secret, $code, (int) $state['last_step'] );
	}

	/**
	 * Which stored recovery code hash a typed code matches, compared outside the lock (see handle()): the state
	 * as read on this request. check_code_locked() then only checks that the hash is still unused.
	 *
	 * @param string $code Code typed.
	 * @return string The matching hash, or '' when none matches.
	 */
	private static function recovery_match( $code ) {
		$typed = strtolower( preg_replace( '/[^a-z0-9]/i', '', (string) $code ) );
		if ( 8 !== strlen( $typed ) ) {
			return '';
		}
		$typed = substr( $typed, 0, 4 ) . '-' . substr( $typed, 4 );
		foreach ( (array) self::state()['codes'] as $hash ) {
			if ( is_string( $hash ) && password_verify( $typed, $hash ) ) {
				return $hash;
			}
		}
		return '';
	}

	/**
	 * The value of the row that holds the lock, read from the database itself (never from a cache): the same
	 * place as the state, wp_options, or wp_sitemeta on multisite.
	 *
	 * @param string $row The row: MUTEX, or MUTEX_PRI (3.4.2).
	 * @return string|null Null when the row is missing.
	 */
	private static function mutex_read( $row = self::MUTEX ) {
		global $wpdb;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Compare-and-set on our own row needs the value as it is now.
		$value = is_multisite()
			? $wpdb->get_var( $wpdb->prepare( 'SELECT meta_value FROM %i WHERE meta_id = %d', $wpdb->sitemeta, self::mutex_meta_id( $row ) ) )
			: $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s LIMIT 1', $wpdb->options, $row ) );
		// phpcs:enable
		return null === $value ? null : (string) $value;
	}

	/**
	 * Multisite: the one row of wp_sitemeta that holds the lock, the oldest if two requests (or someone with
	 * database access) added more than one. wp_sitemeta has no unique key, and an UPDATE on the meta_key alone
	 * would change every copy, so no request could ever take the lock again.
	 *
	 * @param string $row The row: MUTEX or MUTEX_PRI.
	 * @return int 0 when there is none.
	 */
	private static function mutex_meta_id( $row = self::MUTEX ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Our own row, read from the database itself.
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MIN(meta_id) FROM %i WHERE meta_key = %s AND site_id = %d', $wpdb->sitemeta, $row, get_current_network_id() ) );
	}

	/**
	 * Changes the row that holds the lock from one value to another: one atomic UPDATE, which only one of
	 * several requests that read the same value can win.
	 *
	 * @param string $old   The value read before.
	 * @param string $value New value.
	 * @param string $row   The row: MUTEX or MUTEX_PRI.
	 * @return int Rows changed.
	 */
	private static function mutex_swap( $old, $value, $row = self::MUTEX ) {
		global $wpdb;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- An atomic compare-and-set on our own row; no cache to update.
		$rows = is_multisite()
			? $wpdb->query( $wpdb->prepare( 'UPDATE %i SET meta_value = %s WHERE meta_id = %d AND meta_value = %s', $wpdb->sitemeta, $value, self::mutex_meta_id( $row ), $old ) )
			: $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value = %s', $wpdb->options, $value, $row, $old ) );
		// phpcs:enable
		return (int) $rows;
	}

	/**
	 * A new value for the row that holds the lock: until when it is held, a random token and a signature.
	 * The token ends with the name of the lock file this request holds (see local_lock()), if any.
	 *
	 * @param int $until Until when.
	 * @return string
	 */
	private static function mutex_value( $until ) {
		$token = wp_generate_password( 16, false ) . ( '' !== self::$local_id ? '-' . self::$local_id : '' );
		return (int) $until . ':' . $token . ':' . PNCP_Seal::sign( array( 'mutex', (int) $until, $token ) );
	}

	/**
	 * Is the lock held by a request right now? Only a value written by ScrapeLock counts (3.4: it is signed):
	 * one written in the database to keep every code check "busy" is free, whatever time it names, and so is
	 * one that ends more than 6 seconds from now (3.4: a lock is only ever taken for 5 seconds; a code check
	 * takes a fraction of a second).
	 *
	 * A value that names the lock file this request holds now is free too. Every request that writes such
	 * a value holds that file's lock until it has freed the row again, and only one request can hold it: so the
	 * request that wrote the value is done (or ended), and the value is left over, or was copied and written
	 * back in the database to keep the owner's codes "busy".
	 *
	 * 3.4.2: with $since, a value taken at least two seconds before $since is free too: a code check holds the
	 * lock for a fraction of a second, so such a value is left over or written back (see fallback_lock()).
	 *
	 * @param string|null $value Value of the row.
	 * @param int         $now   Time.
	 * @param int         $since When this request started to wait for the row (0: no such limit).
	 * @return bool
	 */
	private static function mutex_held( $value, $now, $since = 0 ) {
		$parts = explode( ':', (string) $value, 3 );
		if ( 3 !== count( $parts ) || ! ctype_digit( $parts[0] ) ) {
			return false;
		}
		if ( '' !== self::$local_id && null !== self::$local && substr( $parts[1], -17 ) === '-' . self::$local_id ) {
			return false;
		}
		$until = (int) $parts[0];
		if ( $since > 0 && $until - self::MUTEX_TTL <= $since - 2 ) {
			return false;
		}
		return $until > $now && $until <= $now + self::MUTEX_TTL + 1 && PNCP_Seal::valid( array( 'mutex', $until, $parts[1] ), $parts[2] );
	}

	/**
	 * Takes the lock if it is free when looked at: read the row, and swap it for a new value only if it is
	 * still the value that was read.
	 *
	 * 3.4: a value this request already saw in the row, then saw replaced by another one, and now sees again was
	 * written back (every lock gets a new random value, so a request that really holds the lock never writes an
	 * earlier one): it counts as free.
	 *
	 * @param string[] $seen  The values this request saw in the row so far, in order (changed).
	 * @param int      $since See mutex_held().
	 * @return bool
	 */
	private static function mutex_take( &$seen = array(), $since = 0 ) {
		$now     = time();
		$current = self::mutex_read();
		if ( null === $current ) {
			self::mutex_create();
			$current = self::mutex_read();
		}
		$replayed = null !== $current && '0' !== $current && in_array( $current, array_slice( $seen, 0, -1 ), true );
		// 3.4.2: with $since, a value this request has seen in the row for a second and a half or more is free too:
		// no code check holds the lock that long, so it is left over or written back after it was freed.
		if ( $since > 0 && null !== $current && '0' !== $current ) {
			if ( ! isset( self::$seen_at[ $current ] ) ) {
				self::$seen_at[ $current ] = microtime( true );
			}
			$replayed = $replayed || microtime( true ) - self::$seen_at[ $current ] >= 1.5;
		}
		if ( null !== $current && end( $seen ) !== $current ) {
			$seen[] = $current;
		}
		if ( null === $current || ( ! $replayed && self::mutex_held( $current, $now, $since ) ) ) {
			return false;
		}
		$value = self::mutex_value( $now + self::MUTEX_TTL );
		if ( 1 !== self::mutex_swap( $current, $value ) ) {
			return false;
		}
		self::$mutex = $value;
		return true;
	}

	/**
	 * Creates the row that holds the lock, free, if it is not there yet. Never over another request's value:
	 * add_option() writes with "ON DUPLICATE KEY UPDATE", so two requests that both found no row would both set
	 * it to free, and both take the lock (3.4: the first wrong codes on a site could be checked twice at once).
	 *
	 * @param string $row The row: MUTEX or MUTEX_PRI.
	 */
	private static function mutex_create( $row = self::MUTEX ) {
		global $wpdb;
		if ( is_multisite() ) {
			add_site_option( $row, '0' ); // wp_sitemeta has no unique key: a plain insert after a check.
			return;
		}
		$quiet = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Our own row; a duplicate is refused by the unique key, as wanted.
		$wpdb->query( $wpdb->prepare( 'INSERT INTO %i (option_name, option_value, autoload) VALUES (%s, %s, %s)', $wpdb->options, $row, '0', 'no' ) );
		$wpdb->suppress_errors( $quiet );
	}

	/**
	 * Takes the lock. Waits up to 5 seconds for it: parallel requests wait in turn.
	 *
	 * 3.4.2: on MySQL and MariaDB, a named lock of the database server (GET_LOCK(), see db_lock()). Every web
	 * server that uses the database waits on the same lock, writing rows of a table cannot fake or keep it, and
	 * the database server frees it at once when the request (its connection) ends or dies.
	 *
	 * Otherwise (the SQLite drop-in, a database drop-in with several connections, GET_LOCK() failed, or its lock
	 * is held from outside): the file lock and the row, see fallback_lock().
	 *
	 * 3.4.2: while requests may use that fallback (a connection was found holding the database lock for itself in
	 * the last day, see fallback_possible()), a request that holds the database lock also takes the row, so the
	 * two ways exclude each other: one that started on the fallback just before the database lock was freed
	 * cannot check a code at the same time.
	 *
	 * @param bool $correct The code was found correct before the lock (see attempt()).
	 * @return bool
	 */
	private static function lock( $correct = false ) {
		$db = self::db_lock_checked( 5 );
		if ( false === $db ) {
			return false;
		}
		if ( null === $db ) {
			return self::fallback_lock( $correct );
		}
		if ( ! self::fallback_possible() ) {
			return true;
		}
		// Only requests that started on the fallback before this one got the database lock can hold the row now
		// (later ones wait for the database lock), and none of those takes long: see mutex_held() for $since.
		$since = time();
		$end   = microtime( true ) + 5;
		$seen  = array();
		while ( true ) {
			if ( self::mutex_take( $seen, $since ) ) {
				return true;
			}
			if ( microtime( true ) + 0.1 > $end ) {
				self::db_unlock();
				return false;
			}
			usleep( 100000 );
		}
	}

	/**
	 * The lock without the database lock: first the lock of a file on this server (local_lock()), then the row in
	 * the database, an atomic compare-and-set that only one request can win, valid for MUTEX_TTL seconds at most
	 * (so a request that dies never leaves it held). Requests on this server wait for each other on the file,
	 * which the database cannot change: a value copied from the row while held and written back after it was
	 * freed no longer keeps the owner's correct code "busy". The row still makes requests on other servers (with
	 * another lock file) wait.
	 *
	 * 3.4.2: the row alone is no fair queue across servers: requests that keep sending wrong codes to one server
	 * (each one a fresh value in the row), and those values written back by someone with database access right
	 * after they were freed, could keep a correct code on another server waiting until it answered "busy", again
	 * and again. So a code that was found correct before the lock (a recovery code that matches an unused one, or
	 * the app's current code) goes first: it marks the priority row (signed, for PRI_TTL seconds at most), which
	 * every other request waits for before it takes the file or the row, and it treats a value of the row taken
	 * two seconds or more before it started to wait as free (no code check takes that long). It gets the lock
	 * within about two seconds. A copy of the priority row written back only holds back requests whose code is
	 * not correct, and only until it ends.
	 *
	 * @param bool $correct The code was found correct before the lock.
	 * @return bool
	 */
	private static function fallback_lock( $correct ) {
		$since = 0;
		$end   = microtime( true ) + 5;
		if ( $correct ) {
			$since = self::pri_set();
			$end   = microtime( true ) + self::PRI_TTL - 1;
		}
		$seen = array();
		$file = false;
		while ( true ) {
			if ( ! $correct && self::pri_held() ) {
				if ( $file ) {
					self::local_unlock();
					$file = false;
				}
			} else {
				if ( ! $file ) {
					$file = self::local_lock( min( $end, microtime( true ) + 0.1 ) );
				}
				if ( $file && self::mutex_take( $seen, $since ) ) {
					return true;
				}
			}
			if ( microtime( true ) + 0.1 > $end ) {
				self::local_unlock();
				self::pri_release();
				return false;
			}
			usleep( 100000 );
		}
	}

	/**
	 * Marks the priority row (see fallback_lock()) for PRI_TTL seconds: written over whatever it holds (several
	 * correct codes may wait at once; they then take the row in turn).
	 *
	 * @return int The time it was marked.
	 */
	private static function pri_set() {
		global $wpdb;
		$now = time();
		if ( null === self::mutex_read( self::MUTEX_PRI ) ) {
			self::mutex_create( self::MUTEX_PRI );
		}
		$until = $now + self::PRI_TTL;
		$token = wp_generate_password( 16, false );
		$value = $until . ':' . $token . ':' . PNCP_Seal::sign( array( 'mutex-pri', $until, $token ) );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Our own row, written in the database itself; no cache to update.
		$rows = is_multisite()
			? $wpdb->query( $wpdb->prepare( 'UPDATE %i SET meta_value = %s WHERE meta_id = %d', $wpdb->sitemeta, $value, self::mutex_meta_id( self::MUTEX_PRI ) ) )
			: $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s', $wpdb->options, $value, self::MUTEX_PRI ) );
		// phpcs:enable
		self::$pri = $rows ? $value : '';
		return $now;
	}

	/**
	 * Is the priority row marked by a request with a correct code (signed, not ended)?
	 *
	 * @return bool
	 */
	private static function pri_held() {
		$parts = explode( ':', (string) self::mutex_read( self::MUTEX_PRI ), 3 );
		if ( 3 !== count( $parts ) || ! ctype_digit( $parts[0] ) ) {
			return false;
		}
		$now   = time();
		$until = (int) $parts[0];
		return $until > $now && $until <= $now + self::PRI_TTL + 1 && PNCP_Seal::valid( array( 'mutex-pri', $until, $parts[1] ), $parts[2] );
	}

	/**
	 * Frees the priority row, if it still holds the value this request wrote.
	 */
	private static function pri_release() {
		if ( '' !== self::$pri ) {
			self::mutex_swap( self::$pri, '0', self::MUTEX_PRI );
			self::$pri = '';
		}
	}

	/**
	 * Takes the lock if it is free right now, without waiting (expire_window(), on an ordinary request).
	 *
	 * @return bool
	 */
	private static function try_lock() {
		$db = self::db_lock_checked( 0 );
		if ( false === $db ) {
			return false;
		}
		if ( true === $db ) {
			$seen = array();
			if ( ! self::fallback_possible() || self::mutex_take( $seen, time() ) ) {
				return true;
			}
			self::db_unlock();
			return false;
		}
		if ( self::pri_held() || ! self::local_lock( 0 ) ) {
			return false;
		}
		if ( self::mutex_take() ) {
			return true;
		}
		self::local_unlock();
		return false;
	}

	/**
	 * Releases the lock. The database lock is only ever freed by the connection that holds it. Otherwise only
	 * if the row is still the value this request wrote (after more than MUTEX_TTL seconds another request may
	 * hold it now): the row first, then the file. The priority row last (3.4.2).
	 */
	private static function release() {
		if ( '' !== self::$mutex ) {
			self::mutex_swap( self::$mutex, '0' );
			self::$mutex = '';
		}
		self::db_unlock();
		self::local_unlock();
		self::pri_release();
	}

	/**
	 * Can the code-check lock be a named lock of the database server here?
	 *
	 * Only with the mysqli connection of WordPress's own database class (or a subclass that keeps its one
	 * connection, such as the one of a query logger): a drop-in that spreads queries over several database
	 * servers (HyperDB, LudicrousDB) could send the SELECT to a replica, where the lock would not be shared;
	 * the SQLite drop-in has no such locks. Those use the file lock and the row, as before.
	 *
	 * @return bool
	 */
	public static function db_lock_usable() {
		global $wpdb;
		if ( null === self::$db_usable ) {
			$usable = $wpdb instanceof wpdb && ! property_exists( $wpdb, 'dbhs' ) && $wpdb->dbh instanceof mysqli;
			/**
			 * Filters whether the code-check lock of Lockdown is a named lock of the database server (GET_LOCK()).
			 *
			 * @param bool $usable True on WordPress's own MySQL / MariaDB connection.
			 */
			self::$db_usable = (bool) apply_filters( 'pncp_lockdown_db_lock', $usable );
		}
		return self::$db_usable;
	}

	/**
	 * The name of the database lock: the same on every web server of this site (made from the keys in
	 * wp-config.php, the database name, the table prefix and the site, or the network on multisite, whose
	 * Lockdown state is shared by all its sites), different for other sites on the same database server
	 * (names are global there), and not guessable without the keys. 48 characters (at most 64 are allowed).
	 * The name is not a secret, though: anyone who can list the database's connections (the database user of
	 * WordPress itself can, for its own connections) sees it in the query text while a code is checked. That is
	 * why a lock held for longer than any code check takes is not obeyed (see db_lock_checked()).
	 *
	 * @return string
	 */
	public static function db_lock_name() {
		global $wpdb;
		$scope = is_multisite() ? 'network:' . get_current_network_id() : 'site:' . get_current_blog_id();
		return 'pncp_ld_' . substr( hash( 'sha256', PNCP_Seal::sign( array( 'db-lock', (string) $wpdb->dbname, (string) $wpdb->base_prefix, $scope ) ) ), 0, 40 );
	}

	/**
	 * Takes the database lock, and finds out when it is kept by a connection that is not a code check.
	 *
	 * 3.4.2: a code check holds the lock for a fraction of a second. Someone with the database password could
	 * read the lock's name from the list of running queries and hold it from their own connection for as long
	 * as they like, so that every code (app and recovery) answered "busy". So: when the lock is taken, its
	 * holder is looked up (IS_USED_LOCK()). If that connection has been idle or in one query for longer than a
	 * code check can last, or is the one found doing so before, or it still holds the lock after a full wait,
	 * the lock is "foreign": this request uses the file lock and the row instead (as on SQLite), the event is
	 * logged and the administrator is emailed (once an hour at most), and the owner's code is checked.
	 *
	 * @param int $wait Seconds to wait for a lock held by a code check (0: do not wait).
	 * @return bool|null True: held. False: held by another code check right now (only with $wait 0). Null: use
	 *                   the file lock and the row.
	 */
	private static function db_lock_checked( $wait ) {
		$got = self::db_lock( 0 );
		if ( false !== $got ) {
			return $got;
		}
		$holder = self::db_lock_holder();
		if ( ! self::db_lock_foreign( $holder ) ) {
			if ( $wait <= 0 ) {
				return false;
			}
			$got = self::db_lock( $wait );
			if ( false !== $got ) {
				return $got;
			}
			// Held all this time: no code check takes that long.
			$holder = self::db_lock_holder();
		}
		self::db_lock_report( $holder );
		return null;
	}

	/**
	 * The id of the database connection that holds the database lock now (0: none, or not known).
	 *
	 * @return int
	 */
	private static function db_lock_holder() {
		global $wpdb;
		$quiet = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- A lock of the database server, not data: nothing to cache.
		$id = $wpdb->get_var( $wpdb->prepare( 'SELECT IS_USED_LOCK(%s)', self::db_lock_name() ) );
		$wpdb->suppress_errors( $quiet );
		return max( 0, (int) $id );
	}

	/**
	 * Does connection $id hold the database lock for itself (not for a code check)? Yes when it is the one
	 * found doing so before (in the last day; connection ids are not reused while the database server runs),
	 * or when the list of connections shows it idle or in the same query for longer than MUTEX_TTL. The list
	 * only shows the connections of the same database user without the PROCESS privilege: otherwise only a
	 * full wait tells (db_lock_checked()).
	 *
	 * @param int $id Connection id.
	 * @return bool
	 */
	private static function db_lock_foreign( $id ) {
		global $wpdb;
		if ( $id <= 0 ) {
			return false;
		}
		$known = self::db_foreign_known();
		if ( $known && $known['id'] === $id && $known['time'] > time() - DAY_IN_SECONDS ) {
			return true;
		}
		$quiet = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- The database server's list of connections: nothing to cache.
		$time = $wpdb->get_var( $wpdb->prepare( 'SELECT TIME FROM information_schema.PROCESSLIST WHERE ID = %d', $id ) );
		$wpdb->suppress_errors( $quiet );
		return null !== $time && (int) $time > self::MUTEX_TTL;
	}

	/**
	 * Notes that connection $id holds the database lock for itself: in the lockdown log (once per connection)
	 * and by email to the administrator (at most once an hour).
	 *
	 * @param int $id Connection id (0: not known).
	 */
	private static function db_lock_report( $id ) {
		$known = self::db_foreign_known();
		$now   = time();
		if ( $known && $known['id'] === $id && $id > 0 ) {
			self::db_foreign_save( $id, $now, $known['mailed'] );
			return;
		}
		$mailed = $known ? min( $known['mailed'], $now ) : 0;
		$detail = $id > 0
			/* translators: %d: id of a database connection */
			? sprintf( __( 'database connection %d', 'scrapelock' ), $id )
			: __( 'unknown database connection', 'scrapelock' );
		self::db_foreign_save( $id, $now, $mailed > $now - HOUR_IN_SECONDS ? $mailed : $now );
		self::event( 'db_lock', $detail );
		if ( $mailed <= $now - HOUR_IN_SECONDS ) {
			self::mail(
				__( 'The lock for Lockdown codes was held from outside', 'scrapelock' ),
				/* translators: %s: e.g. "database connection 42" */
				sprintf( __( 'A connection to the database (%s) held the lock that Lockdown uses while it checks a code, for longer than any code check takes. Codes are now checked with ScrapeLock\'s own lock instead, so they still work. Only someone with the database password can do this: change that password (and the keys in wp-config.php), and check who has access to the database.', 'scrapelock' ), $detail )
			);
		}
	}

	/**
	 * The connection last found holding the database lock for itself (db_lock_report()), only as ScrapeLock
	 * wrote it. 3.4.2: signed, so a value written in the database cannot make a code check that really holds
	 * the lock look "foreign" (other requests would then check codes at the same time, past the limits for
	 * wrong codes), nor set back when the administrator was last emailed.
	 *
	 * @return array{id:int, time:int, mailed:int}|array{} Empty when there is none (or it is not signed).
	 */
	private static function db_foreign_known() {
		$known = get_site_option( self::DB_FOREIGN, array() );
		if ( ! is_array( $known ) || ! isset( $known['id'], $known['time'], $known['mailed'], $known['sig'] ) ) {
			return array();
		}
		$data = array(
			'id'     => (int) $known['id'],
			'time'   => (int) $known['time'],
			'mailed' => (int) $known['mailed'],
		);
		return PNCP_Seal::valid( array( 'db-foreign', $data['id'], $data['time'], $data['mailed'] ), $known['sig'] ) ? $data : array();
	}

	/**
	 * Saves the connection found holding the database lock for itself, signed (see db_foreign_known()).
	 *
	 * @param int $id     Connection id (0: not known).
	 * @param int $time   When it was found.
	 * @param int $mailed When the administrator was last emailed about it.
	 */
	private static function db_foreign_save( $id, $time, $mailed ) {
		update_site_option(
			self::DB_FOREIGN,
			array(
				'id'     => (int) $id,
				'time'   => (int) $time,
				'mailed' => (int) $mailed,
				'sig'    => PNCP_Seal::sign( array( 'db-foreign', (int) $id, (int) $time, (int) $mailed ) ),
			)
		);
	}

	/**
	 * May some requests use the fallback lock now while others hold the database lock (fallback_lock())? Only
	 * after a connection was found holding the database lock for itself, in the last day.
	 *
	 * @return bool
	 */
	private static function fallback_possible() {
		$known = self::db_foreign_known();
		return $known && $known['time'] > time() - DAY_IN_SECONDS;
	}

	/**
	 * Takes the database lock, waiting up to $wait seconds (GET_LOCK(): the database server lets the waiting
	 * requests in one after another).
	 *
	 * Someone who can open their own connection to the database (or run queries that last) could hold it
	 * once they know its name, as they could lock the tables themselves: that is not something a plugin can
	 * prevent. A stolen admin session with ordinary database writes cannot.
	 *
	 * @param int $wait Seconds (0: do not wait).
	 * @return bool|null True: held. False: held by another request all that time. Null: the database lock
	 *                   cannot be used (then the file lock and the row are, for the rest of this request).
	 */
	private static function db_lock( $wait ) {
		global $wpdb;
		self::db_unlock();
		if ( ! self::db_lock_usable() ) {
			return null;
		}
		$name  = self::db_lock_name();
		$quiet = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- A lock of the database server, not data: nothing to cache.
		$got = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $name, (int) $wait ) );
		$wpdb->suppress_errors( $quiet );
		if ( '1' === (string) $got ) {
			self::$db_held = $name;
			static $hooked = false;
			if ( ! $hooked ) {
				// After a fatal error the connection may live on (a persistent connection): free the lock then too.
				register_shutdown_function( array( __CLASS__, 'db_unlock' ) );
				$hooked = true;
			}
			return true;
		}
		if ( '0' === (string) $got ) {
			return false;
		}
		self::$db_usable = false; // NULL or an error: GET_LOCK() is not available on this server.
		return null;
	}

	/**
	 * Frees the database lock, if this request holds it (also called at shutdown).
	 */
	public static function db_unlock() {
		global $wpdb;
		if ( '' === self::$db_held ) {
			return;
		}
		$name          = self::$db_held;
		self::$db_held = '';
		if ( ! $wpdb instanceof wpdb ) {
			return;
		}
		$quiet = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- A lock of the database server, not data: nothing to cache.
		$wpdb->query( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $name ) );
		$wpdb->suppress_errors( $quiet );
	}

	/**
	 * The lock file on this server: next to the guard in the must-use plugins folder, or in wp-content when that
	 * folder cannot be written. It only holds a random name (nothing secret).
	 *
	 * @return string
	 */
	public static function local_lock_file() {
		$dir = PNCP_Paths::mu_plugins();
		if ( ! is_dir( $dir ) || ! wp_is_writable( $dir ) ) {
			$dir = PNCP_Paths::content();
		}
		return $dir . '/scrapelock-lockdown.lock';
	}

	/**
	 * Takes the exclusive lock of the lock file, waiting until $end (polling every 10 ms). Only
	 * the requests on this server (that share this file) wait for each other here; the database row then
	 * covers the others (lock()). When the file cannot be opened, there is no file lock and only the row counts,
	 * as before.
	 *
	 * The file's name, written in the row's value, comes from a random name kept in the file, the name of this
	 * server and the file's inode, so a copy of the file on another server does not have the same name.
	 *
	 * @param float $end Until when to wait (0: do not wait).
	 * @return bool False when the file is locked by another request until then.
	 */
	private static function local_lock( $end ) {
		self::local_unlock();
		$path = self::local_lock_file();
		// phpcs:disable WordPress.WP.AlternativeFunctions -- A lock file: flock() needs a handle from fopen().
		$handle = @fopen( $path, 'c+' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Not writable: try read only, then no file lock.
		if ( false === $handle ) {
			$handle = @fopen( $path, 'r' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Missing and not creatable: no file lock.
		}
		if ( false === $handle ) {
			return true;
		}
		while ( ! flock( $handle, LOCK_EX | LOCK_NB ) ) {
			if ( microtime( true ) + 0.01 > $end ) {
				fclose( $handle );
				return false;
			}
			usleep( 10000 );
		}
		$name = trim( (string) stream_get_contents( $handle, 64, 0 ) );
		if ( ! preg_match( '/^[A-Za-z0-9]{32}$/', $name ) ) {
			$name = wp_generate_password( 32, false );
			if ( ! ftruncate( $handle, 0 ) || false === fwrite( $handle, $name ) ) {
				$name = '';
			}
			fflush( $handle );
		}
		// phpcs:enable
		$stat = fstat( $handle );
		if ( '' === $name || ! is_array( $stat ) ) {
			flock( $handle, LOCK_UN );
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- The lock file.
			return true;
		}
		self::$local    = $handle;
		self::$local_id = substr( hash( 'sha256', $name . '|' . php_uname( 'n' ) . '|' . $stat['dev'] . '|' . $stat['ino'] ), 0, 16 );
		return true;
	}

	/**
	 * Releases the lock of the lock file, if this request holds it.
	 */
	private static function local_unlock() {
		if ( null !== self::$local ) {
			flock( self::$local, LOCK_UN );
			fclose( self::$local ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- The lock file.
		}
		self::$local    = null;
		self::$local_id = '';
	}

	/**
	 * Forgets the state read earlier in this request, so the next read comes from the database (or from a
	 * persistent object cache, which the request that changed it has already updated).
	 */
	private static function reload() {
		self::forget_cached();
		self::$state      = null;
		self::$session_ok = array();
	}

	/**
	 * Forgets the cached copy of the stored state (and the counters next to it) on this request.
	 */
	private static function forget_cached() {
		if ( is_multisite() ) {
			wp_cache_delete( get_current_network_id() . ':' . self::OPTION, 'site-options' );
			wp_cache_delete( get_current_network_id() . ':' . self::FAILS_OPTION, 'site-options' );
			wp_cache_delete( get_current_network_id() . ':notoptions', 'site-options' );
		} else {
			wp_cache_delete( self::OPTION, 'options' );
			wp_cache_delete( self::FAILS_OPTION, 'options' );
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( 'notoptions', 'options' );
		}
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
		// The stored list (not the one the guard keeps on this request: the same list, with ScrapeLock added).
		PNCP_Seal::unguarded(
			static function () use ( $files ) {
				deactivate_plugins( $files, true );
			}
		);
		self::$writing = false;
		// The new list of active plugins is the one to keep. Only that value in the snapshot: the other protected
		// options and the administrators stay as they were signed when the site was locked.
		PNCP_Seal::update_snapshot( 'active_plugins' );
		// Multisite: a plugin active on the whole network is deactivated there; that list is kept too.
		PNCP_Seal::update_network_value( 'active_sitewide_plugins' );
	}

	/**
	 * Emails the site's administration address.
	 *
	 * @param string $subject Subject.
	 * @param string $message Message.
	 */
	private static function mail( $subject, $message ) {
		$user = wp_get_current_user();
		$to   = self::alert_to();
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

	/**
	 * Where alerts go. 3.4: while the site is locked (or the lock data was changed), the administration address
	 * as it was signed when the site was locked: from the snapshot (or its copy in the guard file), or else from
	 * the signed state. Someone who changed the address in the database does not get the alert about it.
	 *
	 * @return string
	 */
	private static function alert_to() {
		$live = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
		if ( ! self::is_locked() && '' === self::tampered() ) {
			return (string) $live;
		}
		$to = PNCP_Seal::alert_address();
		if ( '' === $to && self::$sig_ok && is_email( self::state()['mail'] ) ) {
			$to = (string) self::state()['mail'];
		}
		return '' !== $to ? $to : (string) $live;
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
		wp_localize_script( 'pncp-lockdown', 'pncpLockdown', array( 'working' => __( 'Please wait…', 'scrapelock' ) ) );
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
		if ( $owner && ( self::is_locked() || self::unlocked_until() ) && '' === self::tampered() && PNCP_Seal::needs_config() && 'current' !== PNCP_Seal::config_status() ) {
			// 3.4.2: nothing outside the database keeps the lock yet.
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'The ScrapeLock lock is not protected yet.', 'scrapelock' ) . '</strong> ' . esc_html__( 'Add the lock line shown on the Lockdown page to wp-config.php.', 'scrapelock' ) . ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Lockdown', 'scrapelock' ) . '</a></p></div>';
		} elseif ( $owner && ! self::is_locked() && ! self::unlocked_until() && 'stale' === PNCP_Seal::config_status() ) {
			echo '<div class="notice notice-warning"><p>' . esc_html( self::config_remove_text() ) . '</p></div>';
		}
		if ( self::is_locked() && self::is_staff( $user ) ) {
			$text = 1 === self::staff_level( $user ) ? __( 'You can keep working on orders, products, coupons, reports and content. Plugins, themes, menus and widgets, users, settings, import and export stay frozen until an administrator unlocks the site with the authenticator app.', 'scrapelock' ) : __( 'Changes from wp-admin are disabled until an administrator unlocks the site with the authenticator app.', 'scrapelock' );
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'This site is locked.', 'scrapelock' ) . '</strong> ' . esc_html( $text );
			if ( $owner ) {
				echo ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Unlock', 'scrapelock' ) . '</a>';
			}
			echo '</p></div>';
			return;
		}
		$until = self::unlocked_until();
		if ( $until && $owner ) {
			/* translators: %s: time */
			echo '<div class="notice notice-info"><p>' . esc_html( sprintf( __( 'The site is unlocked until %s, then it locks again by itself.', 'scrapelock' ), wp_date( (string) get_option( 'time_format' ), $until ) ) ) . ' ';
			if ( (int) self::state()['unlocked_by'] === $user ) {
				echo esc_html( self::window_text() ) . ' ';
			}
			echo '<a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Lock now', 'scrapelock' ) . '</a></p></div>';
		}
	}

	/**
	 * While unlocked for a while: what is kept when the site locks again by itself, and what was noted so far.
	 *
	 * @return string
	 */
	private static function window_text() {
		$text  = __( 'What you change through WordPress in this browser session is kept when it locks again: plugins you activate or deactivate, the theme, the site address, the administration email, roles, administrators you add and ScrapeLock settings. Changes made any other way (directly in the database, from another session or with WP-CLI) are put back.', 'scrapelock' );
		$noted = PNCP_Seal::window_summary();
		if ( $noted['options'] || $noted['admins'] ) {
			$parts = $noted['options'];
			if ( $noted['admins'] ) {
				/* translators: %d: number of accounts */
				$parts[] = sprintf( _n( '%d new administrator', '%d new administrators', $noted['admins'], 'scrapelock' ), $noted['admins'] );
			}
			/* translators: %s: list of settings */
			$text .= ' ' . sprintf( __( 'Kept so far: %s.', 'scrapelock' ), implode( ', ', $parts ) );
		} else {
			$text .= ' ' . __( 'Nothing changed so far.', 'scrapelock' );
		}
		return $text;
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
		// WordPress' error page prints no enqueued styles: the registered stylesheet is printed with the page.
		wp_register_style( 'pncp-locked', PNCP_URL . 'assets/css/locked.css', array(), PNCP_VERSION );
		ob_start();
		wp_print_styles( 'pncp-locked' );
		$style = (string) ob_get_clean();
		$html  = $style . '<div class="pncp-locked">'
			. '<div class="pncp-locked-icon">' . $lock . '</div>'
			. '<h1>' . esc_html__( 'The site is locked', 'scrapelock' ) . '</h1>'
			. '<p>' . ( 1 === self::staff_level( get_current_user_id() )
				? esc_html__( 'ScrapeLock Lockdown is on: you can keep working on orders, products, coupons, reports and content, but plugins, themes, menus and widgets, users, settings, import and export are frozen. This keeps the site safe even if someone has stolen a password.', 'scrapelock' )
				: esc_html__( 'ScrapeLock Lockdown is on, so nothing can be changed right now: plugins, themes, users, settings and content are frozen. This keeps the site safe even if someone has stolen a password.', 'scrapelock' ) ) . '</p>'
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
			self::render_config();
			if ( ! self::is_locked() ) {
				self::render_warning();
			}
			if ( is_multisite() ) {
				self::render_multisite();
			}
			if ( ! self::configured() && self::is_locked() ) {
				// The state was deleted in the database while the site is locked (check_seal()): no new app here.
				echo '<div class="notice notice-error inline"><p>' . esc_html__( 'The Lockdown data in the database was changed outside WordPress, so its code cannot be trusted and the site stays locked. To unlock, add define( \'SCRAPELOCK_UNLOCK\', true ); to wp-config.php, remove the app on this page, set it up again and lock. Then remove the line.', 'scrapelock' ) . '</p></div>';
			} elseif ( ! self::configured() && '' !== $pending ) {
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
			'wait'      => array( 'error', self::wait_message() ),
			'busy'      => array( 'error', __( 'Another code was being checked at the same moment. Try again. If this keeps coming back, something is holding the lock for code checks (see the events below); to get in anyway, add define( \'SCRAPELOCK_UNLOCK\', true ); to wp-config.php.', 'scrapelock' ) ),
			'sessions'  => array( 'success', __( 'All other sessions of your account were signed out. You are still signed in here.', 'scrapelock' ) ),
			'unlocked_out' => array( 'success', __( 'The site is unlocked, and all other sessions of your account were signed out.', 'scrapelock' ) ),
			'error'     => array( 'error', __( 'That action is not possible right now.', 'scrapelock' ) ),
			'roles'     => array( 'success', __( 'The frozen roles were saved.', 'scrapelock' ) ),
			'integrity' => array( 'success', __( 'The file integrity check is done.', 'scrapelock' ) ),
			'quarantine' => array( 'success', __( 'The quarantine setting was saved.', 'scrapelock' ) ),
			'ack'       => array( 'error', __( 'Tick the box to confirm that you have saved your recovery codes and understand how to unlock the site.', 'scrapelock' ) ),
			'tampered'  => array( 'error', __( 'The Lockdown data in the database was changed outside WordPress, so its code cannot be trusted and the site stays locked. To unlock, add define( \'SCRAPELOCK_UNLOCK\', true ); to wp-config.php, remove the app on this page, set it up again and lock. Then remove the line.', 'scrapelock' ) ),
			'noguard'   => array( 'error', __( 'The site was not locked: the guard file wp-content/mu-plugins/scrapelock-lockdown-guard.php could not be written, because WordPress cannot write files to that folder directly. Without it, someone who can change the database directly (for example through a vulnerable plugin) could unlock the site. Let the web server write to wp-content/mu-plugins (create the folder if it is missing), then lock again. Or tick "Lock without the guard file (weaker)".', 'scrapelock' ) ),
			'guard'     => array( 'error', __( 'The site was not unlocked: the guard file wp-content/mu-plugins/scrapelock-lockdown-guard.php could not be changed. Check that the web server may write to that folder, or unlock from the server with SCRAPELOCK_UNLOCK.', 'scrapelock' ) ),
		);
		if ( isset( $messages[ $code ] ) ) {
			printf( '<div class="notice notice-%s inline"><p>%s</p></div>', esc_attr( $messages[ $code ][0] ), esc_html( $messages[ $code ][1] ) );
		}
		$key     = 'pncp_ld_unknown_' . get_current_user_id();
		$unknown = in_array( $code, array( 'unlocked', 'unlocked_out' ), true ) ? get_site_transient( $key ) : false;
		if ( is_array( $unknown ) && $unknown ) {
			delete_site_transient( $key );
			printf( '<div class="notice notice-warning inline"><p>%s</p></div>', esc_html( self::unknown_text( array_map( 'strval', $unknown ) ) ) );
		}
	}

	/**
	 * The warning about accounts that got administrator rights behind WordPress's back while the site was
	 * locked, after a full unlock.
	 *
	 * @param string[] $unknown The accounts.
	 * @return string
	 */
	private static function unknown_text( $unknown ) {
		/* translators: %s: list of accounts, e.g. "bob (#5), eve (#7)" */
		return sprintf( __( 'Check these accounts: they got administrator rights directly in the database while the site was locked, and can sign in and administer the site now that it is unlocked. Remove their rights or delete them if you did not give them: %s', 'scrapelock' ), implode( ', ', $unknown ) );
	}

	/**
	 * After too many wrong codes: until when codes are refused, and whether a recovery code still works.
	 *
	 * @return string
	 */
	private static function wait_message() {
		list( $app, $recovery ) = self::wait_until();
		$fmt = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		if ( $recovery ) {
			/* translators: %s: date and time */
			return sprintf( __( 'Too many wrong codes from this IP. Try again after %s.', 'scrapelock' ), wp_date( $fmt, $recovery ) );
		}
		if ( $app ) {
			/* translators: %s: date and time */
			return sprintf( __( 'Too many wrong codes. App codes are refused until %s. You can still unlock with a recovery code.', 'scrapelock' ), wp_date( $fmt, $app ) );
		}
		return __( 'Too many wrong codes. Try again later.', 'scrapelock' );
	}

	/**
	 * 3.4.2: what to tell the owner about the lock line once the lock is over.
	 *
	 * @return string
	 */
	private static function config_remove_text() {
		return __( 'wp-config.php still has the lock line define( \'SCRAPELOCK_LOCKED\', ... ); of a lock that has ended. Remove that line now: while it is there, if the Lockdown data is deleted from the database, the site locks again, and only SCRAPELOCK_UNLOCK or removing the line opens it.', 'scrapelock' );
	}

	/**
	 * 3.4.2: the lock line for wp-config.php on the Lockdown tab: to add (or replace) while the site is locked,
	 * to remove once it is unlocked for good (see PNCP_Seal::CONFIG).
	 */
	private static function render_config() {
		$status = PNCP_Seal::config_status();
		if ( ! self::is_locked() && ! self::unlocked_until() ) {
			if ( ! self::server_unlocked() && 'stale' === $status ) {
				echo '<div class="notice notice-warning inline"><p>' . esc_html( self::config_remove_text() ) . '</p></div>';
			}
			return;
		}
		if ( '' !== self::tampered() ) {
			return; // The messages about the changed data say what to do.
		}
		$need = PNCP_Seal::needs_config();
		if ( 'current' === $status ) {
			$text = __( 'wp-config.php has the lock line of this lock: if the Lockdown data in the database is deleted, changed or put back from an older copy, the site stays locked.', 'scrapelock' );
			if ( $need ) {
				$text .= ' ' . __( 'It is the only copy of the lock outside the database: keep it until you unlock "until I lock it again", then remove it. An unlock for a while does not need any change to it.', 'scrapelock' );
			}
			echo '<div class="notice notice-success inline"><p>' . esc_html( $text ) . '</p></div>';
			return;
		}
		$line = PNCP_Seal::current_config_line();
		if ( '' === $line ) {
			return;
		}
		$notes = array();
		if ( 'old' === $status ) {
			$notes[] = __( 'The SCRAPELOCK_LOCKED line in wp-config.php is from an earlier lock: replace it with this one.', 'scrapelock' );
		} elseif ( 'invalid' === $status ) {
			$notes[] = __( 'The SCRAPELOCK_LOCKED line in wp-config.php does not belong to this site (the line of another site, changed by hand, or the keys in wp-config.php were changed since), so it is not used: replace it with this one.', 'scrapelock' );
		}
		if ( $need ) {
			echo '<div class="pncp-ld-box pncp-ld-warning" role="alert"><h2><span class="dashicons dashicons-warning" aria-hidden="true"></span> ' . esc_html__( 'The lock is not protected yet: add this line to wp-config.php', 'scrapelock' ) . '</h2>';
			echo '<p>' . esc_html__( 'WordPress cannot write to any folder of wp-content on this server, so neither the guard file nor the lock file could be written: for now everything about the lock is in the database only, and someone who can change the database directly could delete it so that the site looks as if it had never been locked. Add this line to wp-config.php by hand (FTP or your hosting panel), above the line "That\'s all, stop editing!". It is signed with this site\'s keys and only says that this site is locked: while it is there, the site stays locked whatever the database says, until you unlock it with the app.', 'scrapelock' ) . '</p>';
		} else {
			echo '<details class="pncp-ld-box"><summary>' . esc_html__( 'Optional: a second copy of the lock in wp-config.php', 'scrapelock' ) . '</summary>';
			echo '<p>' . esc_html__( 'The guard file or the lock file already keeps the lock outside the database. For one more copy that the web server cannot change, add this line to wp-config.php: if someone deletes those files and the Lockdown data in the database, the site still stays locked.', 'scrapelock' ) . '</p>';
		}
		foreach ( $notes as $note ) {
			echo '<p><strong>' . esc_html( $note ) . '</strong></p>';
		}
		echo '<textarea id="pncp-ld-config-line" class="large-text code" rows="2" readonly aria-label="' . esc_attr__( 'Line for wp-config.php', 'scrapelock' ) . '">' . esc_textarea( $line ) . '</textarea>';
		echo '<p><button type="button" class="button pncp-copy" data-target="pncp-ld-config-line">' . esc_html__( 'Copy', 'scrapelock' ) . '</button></p>';
		echo '<p class="description">' . esc_html__( 'An unlock for a while needs no change to the line. When you unlock "until I lock it again", remove it; the next lock gets a new one. Lost the phone and the recovery codes? SCRAPELOCK_UNLOCK still works as described below.', 'scrapelock' );
		if ( is_multisite() ) {
			echo ' ' . esc_html__( 'Multisite: one line for the whole network, as the lock covers every site.', 'scrapelock' );
		}
		echo '</p>';
		echo $need ? '</div>' : '</details>';
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
				<?php if ( ! defined( 'SCRAPELOCK_KEY' ) && ! self::configured() ) : ?>
					<li><?php esc_html_e( 'The app is tied to the security keys in wp-config.php (AUTH_KEY, AUTH_SALT). Some security plugins and hosting companies change them automatically, for example after a scan: the app codes then stop working and only a recovery code or the wp-config.php line unlocks the site. To avoid this, add a key of ScrapeLock\'s own to wp-config.php BEFORE you connect the app:', 'scrapelock' ); ?> <code>define( 'SCRAPELOCK_KEY', '<?php echo esc_html( wp_generate_password( 48, false ) ); ?>' );</code></li>
				<?php elseif ( ! defined( 'SCRAPELOCK_KEY' ) ) : ?>
					<li><?php esc_html_e( 'The app is tied to the security keys in wp-config.php (AUTH_KEY, AUTH_SALT), which some security plugins and hosting companies change automatically. To tie it to a key of ScrapeLock\'s own instead: first remove the app below, then add SCRAPELOCK_KEY to wp-config.php, then connect the app again. Adding the key while the app is connected makes its codes stop working.', 'scrapelock' ); ?></li>
				<?php endif; ?>
			</ul>
		</div>
		<?php
	}

	/**
	 * Multisite: what the lock covers on a network, and its limits.
	 */
	private static function render_multisite() {
		$limits = PNCP_Seal::network_limits();
		?>
		<div class="pncp-ld-box" role="note">
			<h2><?php esc_html_e( 'Multisite network', 'scrapelock' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'The lock covers the whole network: locking or unlocking here does it for every site.', 'scrapelock' ); ?></li>
				<li>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: number of sites */
						__( 'When you lock, ScrapeLock saves a signed copy of the plugins active on the whole network, the super admins, the network admin email and the registration setting, and of the protected settings and administrators of every site where ScrapeLock is active (up to %d sites). Each site checks its own copy and puts back what was changed directly in the database. An account made a super admin or a site administrator behind WordPress\'s back cannot sign in.', 'scrapelock' ),
						$limits['sites']
					)
				);
				?>
				</li>
				<li>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: number of sites */
						__( 'The guard file keeps the plugins active on the whole network (with ScrapeLock) and, for the first %d sites, their active plugins and theme as they were when you locked, from the start of every request.', 'scrapelock' ),
						$limits['guard']
					)
				);
				?>
				</li>
				<li>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: number of sites */
						__( 'Limits: sites added after you locked are not covered until you unlock and lock again. On a network with more than %d sites, the full copy of the settings of the other sites is saved on their first visit after you locked, from the values that still match the fingerprints taken when you locked: a setting changed directly in the database before that visit is reported, but apart from the active plugins and the theme it cannot be put back.', 'scrapelock' ),
						$limits['now']
					)
				);
				?>
				</li>
			</ul>
			<?php
			$coverage = PNCP_Seal::network_coverage();
			if ( self::is_locked() && ! PNCP_Seal::network_mode() ) {
				echo '<p class="pncp-inline-warning">' . esc_html__( 'This network was locked with an earlier version of ScrapeLock: only the site where it was locked has a saved copy of its settings, and the super admins and the network plugins are not checked. Unlock and lock again to protect every site.', 'scrapelock' ) . '</p>';
			} elseif ( null !== $coverage && self::is_locked() ) {
				/* translators: 1: number of sites, 2: number of sites */
				echo '<p>' . esc_html( sprintf( __( 'Sites covered by this lock: %1$d of %2$d (sites where ScrapeLock is not active are not counted as covered).', 'scrapelock' ), $coverage['covered'], $coverage['total'] ) ) . '</p>';
			}
			?>
		</div>
		<?php
	}

	/**
	 * The full report: what the lock freezes, what keeps working, and who it applies to on this site.
	 */
	private static function render_report() {
		$counts       = self::user_counts();
		$frozen_roles = self::frozen_roles();
		$work_roles   = self::limited_roles();
		$staff        = array();
		$working      = array();
		$open_roles   = array();
		$names        = wp_roles()->get_names();
		foreach ( $counts['avail_roles'] as $role => $count ) {
			if ( ! $count || 'none' === $role ) {
				continue;
			}
			$label = sprintf( '%s: %d', isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : $role, $count );
			if ( in_array( $role, $frozen_roles, true ) ) {
				$staff[] = $label;
			} elseif ( in_array( $role, $work_roles, true ) ) {
				$working[] = $label;
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
				__( 'The Customizer, the Site Editor, menus, widgets and the option pages of themes, for every role.', 'scrapelock' ),
			),
			__( 'WordPress', 'scrapelock' )        => array(
				__( 'WordPress core updates, automatic updates and translation updates.', 'scrapelock' ),
				__( 'The plugin and theme file editor: no file can be changed through WordPress.', 'scrapelock' ),
			),
			__( 'Users', 'scrapelock' )            => array(
				__( 'Creating and deleting users; changing roles; creating administrators, also by code. Shop managers can still edit the details of customers (not of staff), as WooCommerce allows.', 'scrapelock' ),
				__( 'Staff email and password changes (also of shop managers), "lost password" resets for staff, and new application passwords for staff. Existing application passwords of staff stop working.', 'scrapelock' ),
			),
			__( 'Settings', 'scrapelock' )         => array(
				__( 'Every settings page (General, Reading, Permalinks, WooCommerce with its payment methods, other plugins) and the ScrapeLock settings; import and export.', 'scrapelock' ),
				__( 'Also by code: active plugins, theme, site address, admin email, registration, default role, role definitions, ScrapeLock settings and the lock itself.', 'scrapelock' ),
			),
			__( 'Content', 'scrapelock' )          => array(
				__( 'For frozen roles: creating, editing and deleting posts, pages, products, coupons, categories and media; comment moderation; processing orders in wp-admin.', 'scrapelock' ),
				__( 'For every staff role: HTML that can carry scripts.', 'scrapelock' ),
			),
			__( 'Where it applies', 'scrapelock' ) => array(
				__( 'wp-admin, admin-ajax, the REST API (also WooCommerce REST API keys of staff, e.g. an ERP that writes stock), XML-RPC, application passwords, and the code of other plugins for the protected items above.', 'scrapelock' ),
			),
		);
		$open    = array(
			__( 'Visitors browse the site; search engines and the bots you allow are not affected.', 'scrapelock' ),
			__( 'Customers order and pay, register, log in, edit their own account and reset their own password.', 'scrapelock' ),
			__( 'Comments from visitors, payment webhooks, cron jobs and the scheduled tasks of plugins.', 'scrapelock' ),
			__( 'Logging in (also for staff: frozen roles then only see the dashboard); the ScrapeLock bot protection and firewalls such as Wordfence.', 'scrapelock' ),
			__( 'Shop managers (unless their role is ticked below): orders and refunds, products and stock, coupons, reports and analytics, customers, posts, pages, media and comments.', 'scrapelock' ),
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
				<?php /* translators: %s: roles and number of users, e.g. "Shop manager: 2" */ ?>
				<li><?php echo esc_html( sprintf( __( 'Staff accounts that keep their shop and content work while locked, without plugins, themes, menus and widgets, users, settings, import and export: %s.', 'scrapelock' ), $working ? implode( ', ', $working ) : __( 'none', 'scrapelock' ) ) ); ?></li>
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
	 * Users per role, counted once per page (count_users() is a heavy query on a shop with many customers) and
	 * kept for 10 minutes.
	 *
	 * @return array{total_users:int, avail_roles:array<string, int>}
	 */
	private static function user_counts() {
		static $counts = null;
		if ( null === $counts ) {
			$key    = 'pncp_ld_user_counts_' . get_current_blog_id();
			$counts = get_transient( $key );
			if ( ! is_array( $counts ) || ! isset( $counts['avail_roles'] ) ) {
				$counts = count_users();
				set_transient( $key, $counts, 10 * MINUTE_IN_SECONDS );
			}
		}
		return $counts;
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
					if ( '' === self::tampered() && PNCP_Seal::needs_config() && 'current' !== PNCP_Seal::config_status() ) {
						echo '<br><small>' . esc_html__( 'Not protected yet: add the lock line shown above to wp-config.php.', 'scrapelock' ) . '</small>';
					}
				} elseif ( $until ) {
					/* translators: %s: time */
					echo esc_html( sprintf( __( 'Unlocked until %s', 'scrapelock' ), wp_date( (string) get_option( 'time_format' ), $until ) ) );
					$by = get_userdata( (int) $state['unlocked_by'] );
					if ( $by ) {
						/* translators: %s: user name */
						echo '<br><small>' . esc_html( sprintf( __( 'Only for %s; the other staff stay as when locked.', 'scrapelock' ), $by->display_name ) ) . '</small>';
						echo '<br><small>' . esc_html__( 'Only in the browser session that unlocked: other sessions of this account, application passwords, XML-RPC and API keys stay as when locked until you unlock "until I lock it again". If you sign out, lock again and unlock.', 'scrapelock' ) . '</small>';
						if ( get_current_user_id() === (int) $state['unlocked_by'] ) {
							echo '<br><small>' . esc_html( self::window_text() ) . '</small>';
						}
					}
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
				echo '<p><label><input type="checkbox" name="others" value="1"> ' . esc_html__( 'Also sign out all other sessions of this account', 'scrapelock' ) . '</label></p>';
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
				if ( ! PNCP_Seal::can_write_guard() ) {
					$beacon = PNCP_Seal::beacon_writable_dir();
					echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'WordPress cannot write the guard file to wp-content/mu-plugins on this server. The guard keeps a signed copy of the lock outside the database, keeps the active plugins and the theme as they were from the start of every request and keeps ScrapeLock active. Let the web server write to that folder (create it if it is missing), then reload this page.', 'scrapelock' ) . '</p><p>';
					if ( '' !== $beacon ) {
						/* translators: %s: folder */
						echo esc_html( sprintf( __( 'With the weaker lock, ScrapeLock writes a signed lock file to %s instead: if someone deletes or changes the Lockdown data in the database, the site stays locked, protected settings are put back and the alert goes to the address signed when you locked. It does not keep the active plugins and the theme from the start of every request, and someone who can change the database directly could still deactivate ScrapeLock itself.', 'scrapelock' ), PNCP_Seal::short_path( $beacon ) ) );
					} else {
						echo esc_html__( 'No other folder of wp-content can be written either. With the weaker lock, this page then shows a line to add to wp-config.php by hand, define( \'SCRAPELOCK_LOCKED\', \'...\' ); (signed with this site\'s keys): with it, if someone deletes or changes the Lockdown data in the database, the site stays locked, protected settings are put back while their saved copy is there and the alert goes to the address signed when you locked. Until the line is there, everything about the lock is kept in the database only: someone who can change the database directly can delete all of it, and the site then looks as if it had never been locked. This cannot be noticed or reported.', 'scrapelock' );
					}
					echo '</p></div>';
					echo '<p><label><input type="checkbox" name="weak" value="1"> ' . esc_html__( 'Lock without the guard file (weaker)', 'scrapelock' ) . '</label></p>';
				}
				submit_button( __( 'Lock the site', 'scrapelock' ), 'primary', 'submit', false );
				echo '</form>';
			}
			?>
		</div>
		<?php self::render_sessions(); ?>
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
	 * Signing out the other sessions of this account, with a code: also while locked, so that someone who stole a
	 * session of the owner's account (and keeps typing wrong codes with it) can be thrown out.
	 */
	private static function render_sessions() {
		$sessions = count( WP_Session_Tokens::get_instance( get_current_user_id() )->get_all() );
		?>
		<div class="pncp-ld-box pncp-ld-sessions">
			<h2><?php esc_html_e( 'Other sessions of your account', 'scrapelock' ); ?></h2>
			<?php /* translators: %d: number of sessions */ ?>
			<p><?php echo esc_html( sprintf( _n( 'Your account is signed in %d time, counting this one.', 'Your account is signed in %d times, counting this one.', $sessions, 'scrapelock' ), $sessions ) ); ?> <?php esc_html_e( 'If someone else may be using your account (a stolen password or session), sign out everywhere else. This works while the site is locked too; you stay signed in here.', 'scrapelock' ); ?></p>
			<?php
			self::form_open( 'sessions' );
			self::code_field( true );
			submit_button( __( 'Sign out all other sessions of this account', 'scrapelock' ), 'secondary', 'submit', false );
			echo '</form>';
			?>
		</div>
		<?php
	}

	/**
	 * Which roles are frozen while locked: every role with its number of users, ticked if frozen. Roles that
	 * can take over the site are always ticked.
	 */
	private static function render_roles() {
		$counts = self::user_counts();
		$frozen = self::frozen_roles();
		?>
		<div class="pncp-ld-box pncp-ld-roles">
			<h2><?php esc_html_e( 'Who is frozen while locked', 'scrapelock' ); ?></h2>
			<p><?php esc_html_e( 'What a locked site still allows each role:', 'scrapelock' ); ?></p>
			<ul class="pncp-ld-role-help">
				<li><strong><?php esc_html_e( 'Administrators', 'scrapelock' ); ?></strong> <?php esc_html_e( '(and every role that can change plugins, themes, users or settings): always frozen. They keep only "read", and the owner unlocks the site here with the authenticator app.', 'scrapelock' ); ?></li>
				<li><strong><?php esc_html_e( 'Ticked roles', 'scrapelock' ); ?></strong> <?php esc_html_e( 'keep only "read": they can log in and look, but not change anything. They cannot change their own email or password, and their application passwords cannot be used or added.', 'scrapelock' ); ?></li>
				<li><strong><?php esc_html_e( 'Unticked staff roles', 'scrapelock' ); ?></strong> <?php esc_html_e( '(shop managers by default) keep their work: orders and refunds, products and stock, coupons, reports and analytics, customers, posts, pages, media and comments. Frozen for them: plugins, themes, the Customizer, menus and widgets, creating or promoting users and editing staff accounts, WordPress and WooCommerce settings (payment methods too), import and export, and HTML that can carry scripts. They cannot change their own email or password, and their application passwords cannot be used or added.', 'scrapelock' ); ?></li>
				<li><strong><?php esc_html_e( 'Other unticked roles', 'scrapelock' ); ?></strong> <?php esc_html_e( '(customers, subscribers, members who post listings or community posts) keep working as usual, including their own email and password.', 'scrapelock' ); ?></li>
			</ul>
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
							} elseif ( self::role_limited( $role ) ) {
								echo ' <span class="description">' . esc_html__( 'unticked: keeps its work, without the rights frozen for staff', 'scrapelock' ) . '</span>';
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
			'relocked_auto' => __( 'Locked again by itself; your changes were kept', 'scrapelock' ),
			'failed'        => __( 'Wrong code', 'scrapelock' ),
			'recovery_used' => __( 'Recovery code used', 'scrapelock' ),
			'codes'         => __( 'New recovery codes', 'scrapelock' ),
			'removed'       => __( 'App removed', 'scrapelock' ),
			'refused'       => __( 'Change refused', 'scrapelock' ),
			'roles'         => __( 'Frozen roles changed', 'scrapelock' ),
			'integrity'     => __( 'Changed files found', 'scrapelock' ),
			'quarantine'    => __( 'Quarantine', 'scrapelock' ),
			'quarantine_setting' => __( 'Quarantine setting', 'scrapelock' ),
			'tampered'      => __( 'Changed outside WordPress', 'scrapelock' ),
			'sealed'        => __( 'Lockdown data signed', 'scrapelock' ),
			'lockout'       => __( 'Codes refused after too many wrong ones', 'scrapelock' ),
			'sessions'      => __( 'Other sessions signed out', 'scrapelock' ),
			'stale_file'    => __( 'Old lock file from before the last unlock removed', 'scrapelock' ),
			'lock_file'     => __( 'Signed copy of the lock written outside the database', 'scrapelock' ),
			'db_lock'       => __( 'Code-check lock held from outside; ScrapeLock\'s own lock used', 'scrapelock' ),
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
	 * The message for a code that did not pass attempt().
	 *
	 * @param string $how What attempt() returned.
	 * @return string Message code.
	 */
	private static function code_message( $how ) {
		if ( 'wait' === $how ) {
			return 'wait';
		}
		return 'busy' === $how ? 'busy' : 'wrong';
	}

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
		$mins = in_array( $mins, array( 0, 15, 30, 60, 120 ), true ) ? $mins : 30;
		$ack  = ! empty( $_POST['ack'] );
		$weak = ! empty( $_POST['weak'] );
		$out  = ! empty( $_POST['others'] );
		$pick = isset( $_POST['roles'] ) && is_array( $_POST['roles'] ) ? array_filter( array_map( 'sanitize_key', wp_unslash( $_POST['roles'] ) ) ) : array();
		// phpcs:enable
		$state = self::state();

		if ( 'relock' === $op ) {
			// Locking again needs no code: it only makes the site safer. 3.4.2: also from a web server that stays
			// locked while the site was unlocked for a while on another one (seal_check(), $elsewhere).
			if ( ! self::unlocked_until() && ! self::$elsewhere ) {
				self::back( 'error' );
			}
			$state['until']          = 0;
			$state['unlocked_by']    = 0;
			$state['unlock_session'] = '';
			self::save( $state );
			self::event( 'relocked' );
			PNCP_Integrity::snapshot(); // Updates may have run while it was open: a new fingerprint.
			// Staff could not add application passwords while it was open either: new ones on the accounts the
			// last snapshot knew were added in the database. Removed before the new snapshot would accept them.
			PNCP_Seal::check_apps_all( true );
			PNCP_Seal::take_snapshot();
			PNCP_Seal::forget_window(); // Locked by hand: the snapshot is taken as the site is now.
			self::back( 'locked' );
		}
		if ( 'cancel' === $op ) {
			delete_user_meta( $user, self::PENDING_META );
			self::back( 'cancelled' );
		}
		// While locked, no app can be connected: with the state deleted in the database the site stays locked
		// (check_seal()), and a new app would otherwise unlock it. The way out is SCRAPELOCK_UNLOCK.
		if ( in_array( $op, array( 'setup', 'confirm' ), true ) && self::is_locked() ) {
			delete_user_meta( $user, self::PENDING_META );
			self::back( '' !== self::tampered() ? 'tampered' : 'error' );
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
		// The state in the database no longer matches its signature while the guard says locked: its secret
		// and codes cannot be trusted. The way out is the one for a lost phone (SCRAPELOCK_UNLOCK).
		// Not with SCRAPELOCK_UNLOCK: whoever can edit wp-config.php sets the app up again that way.
		// 3.4: the same for a genuinely signed state that is older than the guard (put back from a backup): its
		// secret and recovery codes may be old ones.
		if ( ! self::server_unlocked() && in_array( self::tampered(), array( 'replay', 'forged' ), true ) && ( ! self::$sig_ok || self::$older || ! self::configured() ) ) {
			self::back( 'tampered' );
		}
		if ( ! in_array( $op, array( 'confirm', 'lock', 'unlock', 'sessions', 'codes', 'remove', 'roles', 'quarantine' ), true ) ) {
			self::back( 'error' );
		}
		// A recovery code (8 characters; app codes have 6 digits) is accepted to unlock and to sign out the other
		// sessions. It is only held back by the per-IP limit (see fail_buckets()), so the owner can always unlock
		// with one, even while a stolen session of the same account keeps typing wrong codes elsewhere.
		$recovery = in_array( $op, array( 'unlock', 'sessions' ), true );
		$shape    = $recovery && 8 === strlen( (string) preg_replace( '/[^a-z0-9]/i', '', $code ) );

		if ( 'confirm' === $op ) {
			$secret = '';
			$step   = false;
			$how    = self::attempt(
				static function () use ( $user, $code, &$secret, &$step ) {
					$secret = self::unseal( (string) get_user_meta( $user, self::PENDING_META, true ) );
					$step   = '' !== $secret && ! self::configured() ? PNCP_Totp::verify( $secret, $code ) : false;
					return false === $step ? '' : 'app';
				},
				false
			);
			if ( 'app' !== $how ) {
				self::back( self::code_message( $how ) );
			}
			if ( in_array( self::tampered(), array( 'replay', 'forged' ), true ) ) {
				// Only with SCRAPELOCK_UNLOCK (checked above): the guard file or the lock file still says "locked"
				// while the state was deleted or changed. A new app starts unlocked, so they go first; otherwise the
				// new app could not be saved (save() keeps an untrusted state from being signed).
				PNCP_Seal::write_guard( false, 0 );
				PNCP_Seal::config_off(); // 3.4.2: the lock line cannot be removed from here: not followed on this request.
				PNCP_Seal::forget_snapshots();
				PNCP_Integrity::forget();
				self::reload();
			}
			$state = self::state();
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
						'fp'        => 0,
						'net'       => 0,
					)
				)
			);
			delete_user_meta( $user, self::PENDING_META );
			// A new app starts unlocked (it cannot be connected while the site is locked): a guard file or a
			// snapshot left from an earlier lock (for example after the state was deleted and the site was opened
			// with SCRAPELOCK_UNLOCK) would otherwise keep it locked.
			PNCP_Seal::write_guard( false, 0 );
			PNCP_Seal::forget_snapshots();
			PNCP_Seal::forget_window();
			PNCP_Integrity::forget();
			set_site_transient( 'pncp_ld_codes_' . $user, $codes, 2 * MINUTE_IN_SECONDS );
			self::event( 'connected' );
			self::back( 'connected' );
		}

		$locked = self::is_locked();
		// The first lock: only after confirming the recovery codes are saved (checked before the code is used).
		if ( 'lock' === $op && empty( $state['ack'] ) && ! $ack ) {
			self::back( 'ack' );
		}
		// Without the guard file, someone who can change the database directly could open the lock (delete its
		// state): locking needs the guard, unless the owner chose the weaker lock on purpose. Checked before the
		// code is used, so the owner can fix the folder and try again with the same code.
		if ( 'lock' === $op && ! $weak && ! PNCP_Seal::can_write_guard() ) {
			self::back( 'noguard' );
		}
		// Signing out the other sessions needs no unlock: it works locked or not, as it only takes access away.
		// A timed unlock belongs to this browser session: without one (no login cookie), nobody would get the rights.
		if ( 'unlock' === $op && 0 !== $mins && '' === wp_get_session_token() ) {
			self::back( 'error' );
		}
		if ( ! self::configured() || ( 'lock' === $op && ( $locked || self::unlocked_until() ) ) || ( 'unlock' === $op && ! $locked ) || ( in_array( $op, array( 'codes', 'remove', 'roles', 'quarantine' ), true ) && $locked ) || ( 'remove' === $op && self::unlocked_until() ) || ( ( 'sessions' === $op || $out ) && '' === wp_get_session_token() ) ) {
			self::back( 'error' );
		}
		// 3.4: a code with the shape of a recovery code is compared with the (slow, bcrypt) hashes before the lock
		// is taken; inside it only the hash it matched is looked up. Otherwise every such attempt would hold the
		// lock for about half a second, and sessions typing wrong ones from many IPs could keep the owner's
		// correct recovery code waiting ("busy"). A request whose IP is already refused does not get that far.
		$match = null;
		if ( $shape ) {
			$wait = self::wait_until();
			if ( $wait[1] ) {
				self::back( self::code_message( 'wait' ) );
			}
			$match = self::recovery_match( $code );
		}
		$how = self::attempt(
			static function () use ( $code, $recovery, $match ) {
				return self::check_code_locked( $code, $recovery, $match );
			},
			$shape,
			( null !== $match && '' !== $match ) || self::app_code_ok( $code )
		);
		if ( ! in_array( $how, array( 'app', 'recovery' ), true ) ) {
			self::back( self::code_message( $how ) );
		}
		$state = self::state();

		if ( 'sessions' === $op ) {
			self::sign_out_others();
			self::back( 'sessions' );
		}

		if ( 'lock' === $op ) {
			// The guard first: if it cannot be written after all, the site is not locked (unless the owner chose
			// the weaker lock). If the state cannot be saved after it, the guard keeps the site locked.
			if ( ! PNCP_Seal::write_guard( true, 0 ) ) {
				if ( ! $weak ) {
					self::back( 'noguard' );
				}
				// 3.4.1: the weaker lock: the signed lock file outside the database instead, where PHP can write it.
				PNCP_Seal::write_beacon( true, 0 );
			}
			$state['locked']      = true;
			$state['until']       = 0;
			$state['since']       = time();
			$state['ack']         = true;
			$state['unlocked_by'] = 0;
			$state['unlock_session'] = '';
			self::save( $state );
			if ( PNCP_Seal::guard_installed() ) {
				$how = '';
			} elseif ( '' !== PNCP_Seal::beacon_path() ) {
				/* translators: %s: folder of the lock file */
				$how = sprintf( __( 'without the guard file, with the signed lock file in %s', 'scrapelock' ), PNCP_Seal::short_path( dirname( PNCP_Seal::beacon_path() ) ) );
			} else {
				$how = __( 'without the guard file, without any signed copy outside the database until the lock line SCRAPELOCK_LOCKED is added to wp-config.php', 'scrapelock' );
			}
			self::event( 'locked', $how );
			// The snapshot of the protected options first: the file fingerprint starts a background request
			// (the official checksums), which must find the snapshot of this lock already there.
			PNCP_Seal::take_snapshot();
			PNCP_Seal::forget_window();
			PNCP_Integrity::snapshot();
			self::back( 'locked' );
		}
		if ( 'unlock' === $op ) {
			if ( 0 === $mins ) {
				$state['locked']         = false;
				$state['until']          = 0;
				$state['unlocked_by']    = 0;
				$state['unlock_session'] = '';
				$state['net']            = 0;
			} else {
				$state['until']       = time() + $mins * MINUTE_IN_SECONDS;
				$state['unlocked_by'] = $user; // Only this administrator gets the rights back meanwhile,
				// and only in this browser session (see unlocking_session()).
				$state['unlock_session'] = self::session_hash( wp_get_session_token() );
			}
			// A new unlock starts with nothing noted (a record of an earlier unlock no longer matches anyway).
			PNCP_Seal::forget_window();
			if ( ! self::save( $state, 0 === $mins ) ) {
				self::back( 'guard' );
			}
			$unknown = array();
			if ( 0 === $mins ) {
				// 3.4: accounts that got administrator rights behind WordPress's back while the site was locked could
				// not sign in until now; from now on they can. Named on the page and in the email, so the owner can
				// check them (the snapshot that knows who they are is deleted next).
				$unknown = PNCP_Seal::check_admins( false );
				if ( $unknown ) {
					set_site_transient( 'pncp_ld_unknown_' . $user, $unknown, 10 * MINUTE_IN_SECONDS );
					self::event( 'tampered', 'admin (unlocked): ' . implode( ', ', $unknown ) );
				}
				// Application passwords work again from now on: the ones added in the database while the site was
				// locked are removed first, while the snapshot to compare with is still there.
				PNCP_Seal::check_apps_all();
				PNCP_Seal::forget_snapshots();
			}
			PNCP_Integrity::mark_stale(); // Updates are allowed now: the next check takes a new fingerprint.
			if ( 0 === $mins && PNCP_Integrity::fingerprint_while_locked() ) {
				PNCP_Integrity::forget(); // It could not be marked (changed in the database): it would still say "locked".
			}
			/* translators: %d: minutes */
			self::event( 'unlocked', $mins ? sprintf( __( '%d min', 'scrapelock' ), $mins ) : __( 'until locked again', 'scrapelock' ) );
			$line = 0 === $mins && null !== PNCP_Seal::config_lock() ? "\n\n" . self::config_remove_text() : '';
			self::mail( __( 'The site was unlocked', 'scrapelock' ), __( 'The site was unlocked on the Lockdown page. If it was not you, lock it again and change the administrators\' passwords.', 'scrapelock' ) . ( $unknown ? "\n\n" . self::unknown_text( $unknown ) : '' ) . $line );
			self::back( $out && self::sign_out_others() ? 'unlocked_out' : 'unlocked' );
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
		$state['unlocked_by'] = 0;
		$state['unlock_session'] = '';
		$state['fp']        = 0;
		$state['net']       = 0;
		if ( ! self::save( $state ) ) {
			self::back( 'guard' );
		}
		// The lock is off: also when the stored state had been deleted (so save() saw nothing locked), the guard
		// file or the lock file must not keep saying "locked" (with SCRAPELOCK_UNLOCK, after such an attack).
		if ( ! PNCP_Seal::write_guard( false, 0 ) ) {
			self::back( 'guard' );
		}
		PNCP_Seal::check_apps_all(); // As for a full unlock (also with SCRAPELOCK_UNLOCK).
		PNCP_Seal::forget_window();
		PNCP_Seal::forget_snapshots();
		PNCP_Integrity::forget();
		self::event( 'removed' );
		self::mail( __( 'The authenticator app was removed', 'scrapelock' ), __( 'The authenticator app was removed from the Lockdown page and the lock is off. If it was not you, change the administrators\' passwords.', 'scrapelock' ) );
		self::back( 'removed' );
	}
}
