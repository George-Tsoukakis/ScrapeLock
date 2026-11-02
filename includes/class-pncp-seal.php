<?php
/**
 * Lockdown seal: keeps the lock honest against someone who can write to the database directly (for example
 * through SQL injection in another plugin) but not to the files.
 *
 * - The lock state and the file fingerprint are signed (HMAC) with a key derived from the keys in
 *   wp-config.php, which are not in the database. A changed or forged value no longer matches its signature.
 * - A small must-use plugin (the "guard") holds a signed copy of "locked / until when" and of the generation
 *   of the lock state (a number that goes up with every save). It is a file, so deleting the state in the
 *   database, or putting back an older copy of it from a backup, cannot unlock the site or bring back an old
 *   app secret or old recovery codes. While locked the guard also keeps the list of active plugins and the
 *   theme as they were when the site was locked, before any other plugin loads, and keeps ScrapeLock loaded.
 * - When the site is locked, the protected options are saved (signed) and put back if they change behind
 *   WordPress's back, and the accounts that could administer the site are noted: another account that gains
 *   such rights while locked cannot sign in.
 * - 3.4, multisite: the lock covers the whole network. The network options (network plugins, super admins) are
 *   saved in a signed snapshot of the network, which also notes the fingerprints and administrators of every
 *   site; each site checks its own snapshot against it, and the guard keeps the plugins and themes per site.
 *
 * Someone who can change the files themselves (or wp-config.php) can still do anything; that is what the file
 * integrity check, "No PHP in uploads" and the server's own security are for.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Signatures, the guard file, the snapshot of protected options and of the administrators.
 */
final class PNCP_Seal {

	/**
	 * Snapshot of the protected options and the administrators, taken when the site is locked (per site).
	 */
	const SNAP = 'pncp_lockdown_snap';

	/**
	 * The fingerprints of the same options, signed and autoloaded: what every request compares, without reading
	 * the (larger, not autoloaded) snapshot itself unless something changed.
	 */
	const DIGESTS = 'pncp_lockdown_digests';

	/**
	 * Seconds after the lock during which a missing snapshot of that lock is not an alarm yet: the lock is saved
	 * a moment before its snapshot is taken (snapshot_pending()).
	 */
	const SNAPSHOT_GRACE = 60;

	/**
	 * 3.4: what the administrator who unlocked for a while changed through WordPress meanwhile (signed, per site,
	 * not autoloaded): kept when the site locks again by itself (accept_window()).
	 */
	const WINDOW = 'pncp_lockdown_window';

	/**
	 * The guard (must-use plugin).
	 */
	const FILE   = 'scrapelock-lockdown-guard.php';
	const MARKER = 'ScrapeLock Lockdown guard';

	/**
	 * The options the guard keeps as they were when the site was locked, from the very start of every request:
	 * other plugins are loaded from the list of active plugins, so putting it back later (verify_options(), on
	 * plugins_loaded) would be too late for a plugin added to it in the database.
	 */
	const GUARDED = array( 'active_plugins', 'template', 'stylesheet' );

	/**
	 * 3.4: the constant the guard file defines with a signed copy of the whole snapshot (single site). Someone
	 * who can only change the database can delete or change the snapshot there, but not this copy: the changed
	 * settings are still put back from it, and the snapshot in the database is put back too.
	 */
	const COPY = 'PNCP_LOCKDOWN_SNAP_COPY';

	/**
	 * 3.4, multisite: the snapshot of the whole network, taken when the network is locked (a network option,
	 * signed, not read on every request): the network options below, the super admins, the application
	 * passwords, and for every site where ScrapeLock is active the fingerprints of its protected options, its
	 * administrators and the generation of its own snapshot. Each site keeps its own snapshot as well (SNAP and
	 * DIGESTS above, per site), and checks it against this one.
	 */
	const NET_SNAP = 'pncp_lockdown_net_snap';

	/**
	 * 3.4, multisite: the fingerprints of the network options and the generation of every site's snapshot,
	 * signed: what every request on every site compares (small, without the values themselves).
	 */
	const NET_DIGESTS = 'pncp_lockdown_net_digests';

	/**
	 * 3.4, multisite: what the administrator who unlocked for a while changed in the network options meanwhile
	 * (signed). The changes on each site are noted in that site's own WINDOW.
	 */
	const NET_WINDOW = 'pncp_lockdown_net_window';

	/**
	 * 3.4, multisite: the network options kept while locked and put back if they change behind WordPress's
	 * back: the plugins active on the whole network, the super admins, the network admin email and who may
	 * register accounts and sites.
	 */
	const NETWORK_OPTIONS = array( 'active_sitewide_plugins', 'site_admins', 'admin_email', 'registration' );

	/**
	 * The signed fingerprints of the network (NET_DIGESTS) as read on this request: null = not read yet, false =
	 * missing or not matching their signature.
	 *
	 * @var array<string, mixed>|false|null
	 */
	private static $net_digests = null;

	/**
	 * The guard's record as written on this request (the constant from the guard file is from the start of
	 * the request).
	 *
	 * @var array{locked:bool, until:int, gen?:int, snap?:int}|null
	 */
	private static $current = null;

	/**
	 * 3.4: the signed copy of the snapshot that the guard holds on this request (null: as the guard file defined
	 * it at the start of the request; false: none). Changed when the guard is written again on this request.
	 *
	 * @var array<string, mixed>|false|null
	 */
	private static $copy = null;

	/**
	 * 3.4: did snapshot() on this request return the copy from the guard file, because the snapshot in the
	 * database is missing, changed or older?
	 *
	 * @var bool
	 */
	private static $from_copy = false;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		// Early: right after the plugins have loaded, before themes, REST and the admin.
		add_action( 'plugins_loaded', array( __CLASS__, 'verify_options' ), 1 );
		add_filter( 'authenticate', array( __CLASS__, 'authenticate' ), 100 );
		// 3.4: a password WordPress itself changes is noted in the snapshot (see password_changed()).
		add_action( 'wp_set_password', array( __CLASS__, 'on_set_password' ), 10, 3 );
		add_action( 'profile_update', array( __CLASS__, 'on_profile_update' ), 10, 2 );
	}

	/**
	 * WordPress set a new password (wp_set_password()), for example when it stores the hash again in a newer
	 * format as the owner signs in.
	 *
	 * @param string       $password Password (not used).
	 * @param int          $user_id  User.
	 * @param WP_User|null $old      The user before the change.
	 */
	public static function on_set_password( $password, $user_id, $old = null ) {
		if ( $old instanceof WP_User ) {
			self::password_changed( (int) $user_id, (string) $old->user_pass );
		}
	}

	/**
	 * WordPress updated an account (wp_update_user()), perhaps its password.
	 *
	 * @param int          $user_id User.
	 * @param WP_User|null $old     The user before the change.
	 */
	public static function on_profile_update( $user_id, $old = null ) {
		if ( $old instanceof WP_User ) {
			self::password_changed( (int) $user_id, (string) $old->user_pass );
		}
	}

	/* ---------- Signatures ---------- */

	/**
	 * The signing key: from the keys in wp-config.php (AUTH_KEY / AUTH_SALT), never stored.
	 *
	 * @return string
	 */
	private static function key() {
		return hash( 'sha256', self::key_material() . '|pncp_lockdown_sig', true );
	}

	/**
	 * What the keys of Lockdown are made from: SCRAPELOCK_KEY when wp-config.php defines it, otherwise the
	 * WordPress keys (AUTH_KEY / AUTH_SALT). Security plugins and hosts sometimes change the WordPress keys
	 * on their own; a key of ScrapeLock's own is not touched by that.
	 *
	 * @return string
	 */
	public static function key_material() {
		if ( defined( 'SCRAPELOCK_KEY' ) && is_string( SCRAPELOCK_KEY ) && strlen( SCRAPELOCK_KEY ) >= 32 ) {
			return 'scrapelock|' . SCRAPELOCK_KEY;
		}
		return wp_salt( 'auth' );
	}

	/**
	 * The same data always gives the same text (keys sorted at every level).
	 *
	 * @param mixed $data Data.
	 * @return mixed
	 */
	private static function canonical( $data ) {
		if ( ! is_array( $data ) ) {
			return $data;
		}
		ksort( $data );
		foreach ( $data as $key => $value ) {
			$data[ $key ] = self::canonical( $value );
		}
		return $data;
	}

	/**
	 * The signature of some data.
	 *
	 * @param mixed $data Data.
	 * @return string
	 */
	public static function sign( $data ) {
		return hash_hmac( 'sha256', (string) wp_json_encode( self::canonical( $data ) ), self::key() );
	}

	/**
	 * Does the signature match the data?
	 *
	 * @param mixed $data Data.
	 * @param mixed $sig  Signature.
	 * @return bool
	 */
	public static function valid( $data, $sig ) {
		return is_string( $sig ) && 64 === strlen( $sig ) && hash_equals( self::sign( $data ), $sig );
	}

	/**
	 * Data stored before 3.3, which had no signatures yet: accepted until the upgrade signs it.
	 *
	 * The version stored in the database is not enough on its own: someone who can write to the database could
	 * set it back to "3.2.0" and then strip the signatures, or make the upgrade sign their own values. So the
	 * data counts as "from before 3.3" only when nothing that 3.3 and later write is there: no guard file, no
	 * signature and no "sealed" marker in the lock state, no snapshot of the protected options, no signed
	 * fingerprint of the files.
	 *
	 * @return bool
	 */
	public static function legacy() {
		// The guard file only exists since 3.3: with it in place, unsigned data is never accepted, whatever the
		// version stored in the database says.
		if ( self::guard_installed() ) {
			return false;
		}
		$from = (string) get_option( 'pncp_version', '' );
		if ( '' === $from || version_compare( $from, '3.3.0', '>=' ) ) {
			return false;
		}
		return ! self::sealed_before();
	}

	/**
	 * Has a version with signatures (3.3 or later) already written Lockdown data on this site? Only looks at
	 * whether the data is there, not at the signatures: anything a newer version wrote means that unsigned data
	 * next to it was not written by an older version.
	 *
	 * @return bool
	 */
	public static function sealed_before() {
		$state = get_site_option( PNCP_Lockdown::OPTION, array() );
		if ( is_array( $state ) && ( isset( $state['sig'] ) || ! empty( $state['sealed'] ) ) ) {
			return true;
		}
		if ( false !== get_option( self::DIGESTS, false ) || false !== get_option( self::SNAP, false ) ) {
			return true;
		}
		if ( is_multisite() && ( false !== get_site_option( self::NET_DIGESTS, false ) || false !== get_site_option( self::NET_SNAP, false ) ) ) {
			return true;
		}
		return PNCP_Integrity::fingerprint_signed();
	}

	/**
	 * Is there signed data that only exists while the site is locked? Used when the lock state is missing, does
	 * not match its signature, or says "not locked": if the snapshot of the protected options (or a current
	 * fingerprint of the files) is there and genuine, the site was locked and the state was deleted, forged or
	 * put back from an older copy behind WordPress's back.
	 *
	 * @param bool     $full  Also read the snapshot and the fingerprint (not autoloaded: only when something is
	 *                        already wrong). Otherwise only the autoloaded fingerprints of the options, which cost
	 *                        no query.
	 * @param int|null $since The lock time ("since") of a state that is genuine but says "not locked": only
	 *                        fingerprints noted for another lock count then. Null: any genuine fingerprints count.
	 * @param int|null $snap  The generation of the snapshot that state names (3.4): only fingerprints of a
	 *                        newer snapshot count then. Null or 0: a state from before 3.4 (the lock time counts).
	 * @return bool
	 */
	public static function lock_evidence( $full, $since = null, $snap = null ) {
		$record = self::digests_record( ! $full );
		if ( null !== $record ) {
			if ( null === $since ) {
				return true;
			}
			if ( $snap && isset( $record['gen'] ) ) {
				// Fingerprints newer than the snapshot the state knows: they were stored after that state was saved,
				// so the state was put back from an older copy. Older ones (an old copy put back) are no evidence.
				if ( (int) $record['gen'] > (int) $snap ) {
					return true;
				}
			} elseif ( isset( $record['since'] ) && (int) $record['since'] !== (int) $since ) {
				// A genuine unlock keeps the lock time in the state, and the fingerprints of that lock are deleted
				// right after it: the same lock time is the normal case (or the moment in between), never an alarm.
				return true;
			}
		}
		if ( ! $full ) {
			return false;
		}
		if ( is_multisite() && ( null !== self::net_record( self::NET_DIGESTS ) || null !== self::net_record( self::NET_SNAP ) ) ) {
			return true; // The signed snapshot of a network lock.
		}
		return null !== self::snapshot_record() || PNCP_Integrity::fingerprint_while_locked();
	}

	/**
	 * Has the owner just locked the site, and is the snapshot of this lock not stored yet? The lock is saved a
	 * moment before its snapshot is taken (in the same request): a request in between, such as the background
	 * request the lock starts for the official checksums, finds no snapshot of this lock. That is no alarm for
	 * SNAPSHOT_GRACE seconds after the (signed) lock time, as long as no snapshot of this lock is there yet.
	 *
	 * @param array<string, mixed>|null $record The signed snapshot record that is there now, if any.
	 * @return bool
	 */
	private static function snapshot_pending( $record ) {
		if ( '' !== PNCP_Lockdown::tampered() ) {
			return false;
		}
		$state = PNCP_Lockdown::state();
		$since = (int) $state['since'];
		if ( $since <= 0 || $since > time() + 5 || $since < time() - self::SNAPSHOT_GRACE ) {
			return false;
		}
		// 3.4: the snapshot of this lock was stored already, so a missing one was deleted: the state notes the
		// lock time of the snapshot it names, and the fingerprints of this lock are stored right after it.
		$digests = self::digests_record();
		if ( ( isset( $state['snapped'] ) && (int) $state['snapped'] === $since ) || ( null !== $digests && isset( $digests['since'] ) && (int) $digests['since'] === $since ) ) {
			return false;
		}
		return null === $record || ! isset( $record['since'] ) || (int) $record['since'] !== $since;
	}

	/**
	 * Is the signed snapshot of a lock still there while the state says the site is not locked (or is gone)?
	 * The same rules as for the fingerprints in lock_evidence(): a snapshot newer than the one the state
	 * knows, or one of another lock, shows that the state was put back from an older copy (or changed); the
	 * snapshot of the lock the state itself ended is the moment between a genuine unlock and the deletion of
	 * its snapshot, never an alarm. Used on sites without the guard file (PNCP_Lockdown::seal_check()).
	 *
	 * @param int|null $since The lock time in the state (null: there is no state).
	 * @param int|null $snap  The generation of the snapshot the state knows.
	 * @return bool
	 */
	public static function snapshot_evidence( $since = null, $snap = null ) {
		$record = self::snapshot_record();
		if ( null === $record ) {
			return false;
		}
		if ( null === $since ) {
			return true;
		}
		if ( $snap && isset( $record['gen'] ) ) {
			return (int) $record['gen'] > (int) $snap;
		}
		return isset( $record['since'] ) && (int) $record['since'] !== (int) $since;
	}

	/**
	 * Are the keys the signatures rely on in wp-config.php? Otherwise WordPress keeps them in the database,
	 * where someone who can change the database can also read them.
	 *
	 * @return bool
	 */
	public static function keys_in_config() {
		foreach ( array( 'AUTH_KEY', 'AUTH_SALT' ) as $name ) {
			if ( ! defined( $name ) || '' === (string) constant( $name ) || 'put your unique phrase here' === constant( $name ) ) {
				return false;
			}
		}
		return true;
	}

	/* ---------- The guard (must-use plugin) ---------- */

	/**
	 * Path of the guard.
	 *
	 * @return string
	 */
	public static function path() {
		return PNCP_Paths::mu_plugins() . '/' . self::FILE;
	}

	/**
	 * The guard's signed record, as the guard file defined it on this request: [locked, until, gen, snap], or
	 * null when there is no guard (or it does not match the keys in wp-config.php). A guard written before 3.4
	 * has no generations ("gen" and "snap" are missing then).
	 *
	 * @return array{locked:bool, until:int, gen?:int, snap?:int}|null
	 */
	public static function beacon() {
		if ( null !== self::$current ) {
			return self::$current['locked'] ? self::$current : null;
		}
		if ( ! defined( 'PNCP_LOCKDOWN_BEACON' ) ) {
			return null;
		}
		$data = json_decode( (string) PNCP_LOCKDOWN_BEACON, true );
		if ( ! is_array( $data ) || ! isset( $data['locked'], $data['until'], $data['sig'] ) ) {
			return null;
		}
		$record = self::record( $data['locked'], $data['until'], isset( $data['gen'] ) ? $data['gen'] : null, isset( $data['snap'] ) ? $data['snap'] : null );
		return self::valid( $record, $data['sig'] ) ? $record : null;
	}

	/**
	 * Reads the guard file again, when the record defined at the start of this request no longer matches the
	 * database: another request may have written the guard and the state in between (they are written a moment
	 * apart). Only a record that matches its signature counts; a guard that is gone now counts as "not locked",
	 * since only ScrapeLock removes it.
	 *
	 * @return bool Whether the guard changed since the start of the request.
	 */
	public static function refresh_beacon() {
		if ( null !== self::$current || ! defined( 'PNCP_LOCKDOWN_BEACON' ) ) {
			return false; // Written on this request (so it is current), or there was no guard at the start.
		}
		clearstatcache( true, self::path() );
		if ( ! self::ours( self::path() ) ) {
			self::$current = self::record( false, 0 );
			return true;
		}
		$code = (string) file_get_contents( self::path() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( ! preg_match( "/define\\( 'PNCP_LOCKDOWN_BEACON', '((?:[^'\\\\]|\\\\.)*)' \\);/", $code, $match ) ) {
			return false;
		}
		$json = strtr(
			$match[1],
			array(
				'\\\\' => '\\',
				"\\'"  => "'",
			)
		); // How var_export() wrote the text.
		if ( (string) PNCP_LOCKDOWN_BEACON === $json ) {
			return false;
		}
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || ! isset( $data['locked'], $data['until'], $data['sig'] ) ) {
			return false;
		}
		$record = self::record( $data['locked'], $data['until'], isset( $data['gen'] ) ? $data['gen'] : null, isset( $data['snap'] ) ? $data['snap'] : null );
		if ( ! self::valid( $record, $data['sig'] ) ) {
			return false;
		}
		self::$current = $record;
		return true;
	}

	/**
	 * The record the guard signs.
	 *
	 * 3.4: also the generation of the lock state ("gen", one more on every save) and the generation of the
	 * snapshot of the protected options ("snap"). A signed state, snapshot or set of fingerprints from an older
	 * copy of the database has a lower generation than the guard, so it is no longer accepted.
	 *
	 * @param bool     $locked Locked.
	 * @param int      $until  Unlocked for a while until (0 = not).
	 * @param int|null $gen    Generation of the state (null: a guard from before 3.4).
	 * @param int|null $snap   Generation of the snapshot (null: a guard from before 3.4).
	 * @return array{locked:bool, until:int, gen?:int, snap?:int}
	 */
	private static function record( $locked, $until, $gen = null, $snap = null ) {
		$record = array(
			'locked' => (bool) $locked,
			'until'  => (int) $until,
		);
		if ( null !== $gen ) {
			$record['gen']  = (int) $gen;
			$record['snap'] = (int) $snap;
		}
		return $record;
	}

	/**
	 * The guard's code: the signed record and, while locked, the active plugins and the theme kept as they were
	 * when the site was locked (from the signed snapshot), with ScrapeLock always in the list of active plugins.
	 *
	 * The guard is a must-use plugin: it runs before WordPress reads the list of active plugins, so a plugin
	 * added to that list in the database is never loaded, not even once. The values are written into the file
	 * itself, so the guard needs neither the database nor the keys (which WordPress has not loaded yet at that
	 * point) to trust them. Without a genuine snapshot only ScrapeLock is kept in the list, as before. On
	 * multisite the guard file is shared by all sites: it holds the values per site, see network_guard_code().
	 * Nothing is enforced while unlocked for a while, or with SCRAPELOCK_UNLOCK in wp-config.php, or when
	 * ScrapeLock's own files are gone.
	 *
	 * @param bool     $locked Locked.
	 * @param int      $until  Unlocked for a while until (0 = not).
	 * @param int|null $gen    Generation of the state (null: the one stored now).
	 * @param int|null $snap   Generation of the snapshot (null: the one stored now).
	 * @return string
	 */
	public static function code( $locked, $until, $gen = null, $snap = null ) {
		if ( null === $gen || null === $snap ) {
			$state = PNCP_Lockdown::state();
			$gen   = null === $gen ? (int) $state['gen'] : $gen;
			$snap  = null === $snap ? (int) $state['snap'] : $snap;
		}
		$record = self::record( $locked, $until, $gen, $snap );
		$json   = (string) wp_json_encode( array_merge( $record, array( 'sig' => self::sign( $record ) ) ) );
		$base   = plugin_basename( PNCP_FILE );
		$values = $locked ? self::guarded_values( (int) $snap ) : array();
		$copy   = $locked && ! is_multisite() ? self::snapshot_source( (int) $snap ) : null;
		$export = array( __CLASS__, 'php_value' );
		$code   = "<?php\n"
			. "/**\n"
			. ' * Plugin Name: ' . self::MARKER . "\n"
			. " * Description: Created by ScrapeLock while the site is locked with Lockdown. It keeps a signed copy of the lock outside the database, keeps the active plugins and the theme as they were when the site was locked and keeps ScrapeLock active. It is removed when the lock is turned off or ScrapeLock is deactivated.\n"
			. " *\n"
			. " * @package ScrapeLock\n"
			. " */\n\n"
			. "defined( 'ABSPATH' ) || exit;\n\n"
			. "defined( 'PNCP_LOCKDOWN_BEACON' ) || define( 'PNCP_LOCKDOWN_BEACON', " . $export( $json ) . " );\n";
		if ( ! $locked ) {
			return $code;
		}
		if ( is_multisite() ) {
			return $code . self::network_guard_code( $until, $base, (int) $snap );
		}
		if ( null !== $copy ) {
			// 3.4: the whole signed snapshot (see COPY), serialized so that its values keep their exact types (the
			// fingerprints compare serialized values), and encoded so that it is one plain line of text.
			$code .= "defined( '" . self::COPY . "' ) || define( '" . self::COPY . "', " . $export( base64_encode( serialize( $copy ) ) ) . " );\n"; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize, WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Our own signed data, read back with allowed_classes off.
		}
		return $code
			. 'if ( time() >= ' . (int) $until . " && ! ( defined( 'SCRAPELOCK_UNLOCK' ) && true === SCRAPELOCK_UNLOCK ) && ! is_multisite() && is_readable( " . $export( PNCP_FILE ) . " ) ) {\n"
			. "\t// The values as they were when the site was locked. ScrapeLock reads the stored values (to put them back)\n"
			. "\t// with 'pass' set, and changes 'values' when it writes the guard again on the same request.\n"
			. "\t\$GLOBALS['pncp_lockdown_guard'] = array(\n"
			. "\t\t'own'    => " . $export( $base ) . ",\n"
			. "\t\t'values' => " . $export( $values ) . ",\n"
			. "\t\t'pass'   => false,\n"
			. "\t);\n"
			. "\t( static function () {\n"
			. "\t\t\$filter = static function ( \$value, \$option ) {\n"
			. "\t\t\t\$guard = isset( \$GLOBALS['pncp_lockdown_guard'] ) && is_array( \$GLOBALS['pncp_lockdown_guard'] ) ? \$GLOBALS['pncp_lockdown_guard'] : array();\n"
			. "\t\t\tif ( ! empty( \$guard['pass'] ) || ! isset( \$guard['own'] ) ) {\n"
			. "\t\t\t\treturn \$value;\n"
			. "\t\t\t}\n"
			. "\t\t\tif ( isset( \$guard['values'] ) && is_array( \$guard['values'] ) && array_key_exists( \$option, \$guard['values'] ) ) {\n"
			. "\t\t\t\t\$value = \$guard['values'][ \$option ];\n"
			. "\t\t\t}\n"
			. "\t\t\tif ( 'active_plugins' === \$option ) {\n"
			. "\t\t\t\t\$value = is_array( \$value ) ? array_values( \$value ) : array();\n"
			. "\t\t\t\tif ( ! in_array( \$guard['own'], \$value, true ) ) {\n"
			. "\t\t\t\t\t\$value[] = \$guard['own'];\n"
			. "\t\t\t\t}\n"
			. "\t\t\t}\n"
			. "\t\t\treturn \$value;\n"
			. "\t\t};\n"
			. "\t\tforeach ( " . $export( self::GUARDED ) . " as \$option ) {\n"
			. "\t\t\tadd_filter( 'option_' . \$option, \$filter, 1, 2 );\n"
			. "\t\t\tadd_filter( 'default_option_' . \$option, \$filter, 1, 2 );\n"
			. "\t\t}\n"
			. "\t} )();\n"
			. "}\n";
	}

	/**
	 * The guard's code on multisite, where one guard file serves every site of the network: the plugins active
	 * on the whole network as they were when the network was locked (with ScrapeLock kept among them if it was
	 * active for the whole network), and the active plugins and the theme of each site, by site ID, for the
	 * sites the snapshot of the network lists them for (see guard_payload()). A site that is not listed (added
	 * after the lock, or beyond the number of sites the guard holds) keeps its stored values.
	 *
	 * @param int    $until Unlocked for a while until (0 = not).
	 * @param string $base  ScrapeLock's plugin file (folder/file.php).
	 * @param int    $snap  The generation of the snapshot the state names.
	 * @return string
	 */
	private static function network_guard_code( $until, $base, $snap ) {
		$payload = self::guard_payload( $snap );
		$export  = array( __CLASS__, 'php_value' );
		return 'if ( time() >= ' . (int) $until . " && ! ( defined( 'SCRAPELOCK_UNLOCK' ) && true === SCRAPELOCK_UNLOCK ) && is_readable( " . $export( PNCP_FILE ) . " ) ) {\n"
			. "\t// Multisite: the values as they were when the network was locked, per site ID ('sites') and for the whole\n"
			. "\t// network ('network'). ScrapeLock reads the stored values (to put them back) with 'pass' set.\n"
			. "\t\$GLOBALS['pncp_lockdown_guard'] = array(\n"
			. "\t\t'own'         => " . $export( $base ) . ",\n"
			. "\t\t'values'      => array(),\n"
			. "\t\t'sites'       => " . $export( $payload['sites'] ) . ",\n"
			. "\t\t'network'     => " . $export( $payload['network'] ) . ",\n"
			. "\t\t'network_own' => " . $export( $payload['network_own'] ) . ",\n"
			. "\t\t'pass'        => false,\n"
			. "\t);\n"
			. "\t( static function () {\n"
			. "\t\t\$read   = static function () {\n"
			. "\t\t\treturn isset( \$GLOBALS['pncp_lockdown_guard'] ) && is_array( \$GLOBALS['pncp_lockdown_guard'] ) ? \$GLOBALS['pncp_lockdown_guard'] : array();\n"
			. "\t\t};\n"
			. "\t\t\$filter = static function ( \$value, \$option ) use ( \$read ) {\n"
			. "\t\t\t\$guard = \$read();\n"
			. "\t\t\t\$id    = get_current_blog_id();\n"
			. "\t\t\tif ( empty( \$guard['pass'] ) && isset( \$guard['sites'][ \$id ] ) && is_array( \$guard['sites'][ \$id ] ) && array_key_exists( \$option, \$guard['sites'][ \$id ] ) ) {\n"
			. "\t\t\t\t\$value = \$guard['sites'][ \$id ][ \$option ];\n"
			. "\t\t\t}\n"
			. "\t\t\treturn \$value;\n"
			. "\t\t};\n"
			. "\t\t\$network = static function ( \$value, \$option ) use ( \$read ) {\n"
			. "\t\t\t\$guard = \$read();\n"
			. "\t\t\tif ( ! empty( \$guard['pass'] ) || ! isset( \$guard['own'] ) ) {\n"
			. "\t\t\t\treturn \$value;\n"
			. "\t\t\t}\n"
			. "\t\t\tif ( isset( \$guard['network'] ) && is_array( \$guard['network'] ) && array_key_exists( \$option, \$guard['network'] ) ) {\n"
			. "\t\t\t\t\$value = \$guard['network'][ \$option ];\n"
			. "\t\t\t}\n"
			. "\t\t\tif ( ! empty( \$guard['network_own'] ) ) {\n"
			. "\t\t\t\t\$value = is_array( \$value ) ? \$value : array();\n"
			. "\t\t\t\tif ( ! isset( \$value[ \$guard['own'] ] ) ) {\n"
			. "\t\t\t\t\t\$value[ \$guard['own'] ] = 1;\n"
			. "\t\t\t\t}\n"
			. "\t\t\t}\n"
			. "\t\t\treturn \$value;\n"
			. "\t\t};\n"
			. "\t\tforeach ( " . $export( self::GUARDED ) . " as \$option ) {\n"
			. "\t\t\tadd_filter( 'option_' . \$option, \$filter, 1, 2 );\n"
			. "\t\t\tadd_filter( 'default_option_' . \$option, \$filter, 1, 2 );\n"
			. "\t\t}\n"
			. "\t\tadd_filter( 'site_option_active_sitewide_plugins', \$network, 1, 2 );\n"
			. "\t\tadd_filter( 'default_site_option_active_sitewide_plugins', \$network, 1, 2 );\n"
			. "\t} )();\n"
			. "}\n";
	}

	/**
	 * What the guard keeps on multisite (see network_guard_code()), from the genuine snapshot of the network for
	 * this lock: 'network' (the plugins active on the whole network), 'sites' (site ID => active plugins and
	 * theme) and 'network_own' (keep ScrapeLock active on the whole network). Without a genuine snapshot of the
	 * network (missing, changed, from an older lock, or a network locked before 3.4) only ScrapeLock is kept, in
	 * the plugins of the whole network if it is active there now.
	 *
	 * @param int $snap The generation of the snapshot the state names.
	 * @return array{network:array<string, mixed>, sites:array<int, array<string, mixed>>, network_own:bool}
	 */
	private static function guard_payload( $snap ) {
		$out = array(
			'network'     => array(),
			'sites'       => array(),
			'network_own' => false,
		);
		$own = plugin_basename( PNCP_FILE );
		$net = self::net_record( self::NET_SNAP );
		if ( null !== $net && self::generation_ok( $net, $snap ) && isset( $net['values'], $net['sites'] ) && is_array( $net['values'] ) && is_array( $net['sites'] ) ) {
			$plugins = isset( $net['values']['active_sitewide_plugins'] ) ? $net['values']['active_sitewide_plugins'] : false;
			if ( is_array( $plugins ) ) {
				$list = array();
				foreach ( $plugins as $file => $time ) {
					if ( is_string( $file ) && '' !== $file ) {
						$list[ $file ] = (int) $time;
					}
				}
				ksort( $list );
				$out['network']['active_sitewide_plugins'] = $list;
				$out['network_own']                        = isset( $list[ $own ] );
			}
			foreach ( $net['sites'] as $id => $entry ) {
				if ( is_array( $entry ) && isset( $entry['guard'] ) && is_array( $entry['guard'] ) && $entry['guard'] ) {
					$out['sites'][ (int) $id ] = $entry['guard'];
				}
			}
			ksort( $out['sites'] );
			return $out;
		}
		$stored             = self::stored_site_option( 'active_sitewide_plugins' );
		$out['network_own'] = is_array( $stored ) && isset( $stored[ $own ] );
		return $out;
	}

	/**
	 * The values of the guarded options (active plugins, theme) that the guard keeps for one site, from the
	 * values read for a snapshot: lists of plugin files, and non-empty names of themes.
	 *
	 * @param array<string, mixed> $values Option => value.
	 * @return array<string, mixed>
	 */
	private static function guard_subset( $values ) {
		$out = array();
		foreach ( self::GUARDED as $option ) {
			if ( ! array_key_exists( $option, $values ) ) {
				continue;
			}
			$value = $values[ $option ];
			if ( 'active_plugins' === $option && is_array( $value ) ) {
				$out[ $option ] = array_values( array_filter( array_map( 'strval', $value ), 'strlen' ) );
			} elseif ( 'active_plugins' !== $option && is_string( $value ) && '' !== $value ) {
				$out[ $option ] = $value;
			}
		}
		return $out;
	}

	/**
	 * A value as PHP code, on one line: text, numbers, true/false and lists of them.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	public static function php_value( $value ) {
		if ( ! is_array( $value ) ) {
			return var_export( is_scalar( $value ) ? $value : null, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes a value as PHP code (quotes escaped).
		}
		if ( ! $value ) {
			return 'array()';
		}
		$list  = array_keys( $value ) === range( 0, count( $value ) - 1 );
		$items = array();
		foreach ( $value as $key => $item ) {
			$items[] = ( $list ? '' : self::php_value( $key ) . ' => ' ) . self::php_value( $item );
		}
		return 'array( ' . implode( ', ', $items ) . ' )';
	}

	/**
	 * The values the guard keeps (active plugins, theme), from the genuine snapshot of this lock. Empty without
	 * one (missing, changed, or from an older lock), and on multisite, where the guard file is shared by every
	 * site of the network and keeps the values per site instead (guard_payload()).
	 *
	 * @param int $snap The generation of the snapshot the state names.
	 * @return array<string, mixed>
	 */
	private static function guarded_values( $snap ) {
		if ( is_multisite() ) {
			return array();
		}
		$record = self::snapshot_source( $snap );
		return null === $record ? array() : self::guard_subset( $record['values'] );
	}

	/**
	 * Single site: the signed snapshot of this lock (with its signature) that the guard file keeps a copy of:
	 * the one in the database, or else the copy the guard holds now (the one in the database was deleted,
	 * changed or set back to an older one). Null without either for this generation.
	 *
	 * @param int $snap The generation of the snapshot the state names.
	 * @return array<string, mixed>|null
	 */
	private static function snapshot_source( $snap ) {
		$record = self::snapshot_record();
		if ( null !== $record && self::generation_ok( $record, $snap ) ) {
			$record['sig'] = self::sign( $record );
			return $record;
		}
		$copy = self::guard_copy();
		if ( null !== $copy && self::generation_ok( $copy, $snap ) ) {
			$copy['sig'] = self::sign( $copy );
			return $copy;
		}
		return null;
	}

	/**
	 * The signed copy of the snapshot the guard file holds (see COPY), without its signature, if it matches it.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function guard_copy() {
		if ( null === self::$copy ) {
			self::$copy = false;
			if ( defined( self::COPY ) ) {
				$raw        = base64_decode( (string) constant( self::COPY ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- See code().
				$data       = is_string( $raw ) ? @unserialize( $raw, array( 'allowed_classes' => false ) ) : false; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize, WordPress.PHP.NoSilencedErrors.Discouraged -- Our own signed data, no objects.
				self::$copy = is_array( $data ) ? $data : false;
			}
		}
		$copy = self::$copy;
		if ( ! is_array( $copy ) || ! isset( $copy['sig'], $copy['values'], $copy['admins'], $copy['time'] ) || ! is_array( $copy['values'] ) || ! is_array( $copy['admins'] ) ) {
			return null;
		}
		$sig = $copy['sig'];
		unset( $copy['sig'] );
		return self::valid( $copy, $sig ) ? $copy : null;
	}

	/**
	 * Reads an option as it is stored, without the values the guard keeps on this request (the seal compares
	 * the stored value with the snapshot and puts it back).
	 *
	 * @param string $option Option.
	 * @return mixed
	 */
	public static function stored_option( $option ) {
		return self::unguarded(
			static function () use ( $option ) {
				return get_option( $option );
			}
		);
	}

	/**
	 * Reads a network option (multisite) as it is stored, without the values the guard keeps on this request.
	 *
	 * @param string $option Option.
	 * @return mixed
	 */
	public static function stored_site_option( $option ) {
		return self::unguarded(
			static function () use ( $option ) {
				return get_site_option( $option );
			}
		);
	}

	/**
	 * Runs something with the guard's values switched off for this request (reading or writing the stored
	 * value: update_option() would otherwise see the guard's value and think nothing changed).
	 *
	 * @param callable $callback What to run.
	 * @return mixed What it returns.
	 */
	public static function unguarded( $callback ) {
		if ( ! isset( $GLOBALS['pncp_lockdown_guard'] ) || ! is_array( $GLOBALS['pncp_lockdown_guard'] ) ) {
			return $callback();
		}
		$before = ! empty( $GLOBALS['pncp_lockdown_guard']['pass'] );
		// Put back afterwards, also when the callback throws.
		$GLOBALS['pncp_lockdown_guard']['pass'] = true;
		try {
			return $callback();
		} finally {
			$GLOBALS['pncp_lockdown_guard']['pass'] = $before;
		}
	}

	/**
	 * Writes the guard for this state (removes it when not locked). Only with direct file access; without it
	 * the lock works as before, without the copy outside the database.
	 *
	 * @param bool     $locked Locked.
	 * @param int      $until  Until.
	 * @param int|null $gen    Generation of the state (null: the one stored now).
	 * @param int|null $snap   Generation of the snapshot (null: the one stored now).
	 * @return bool Whether the guard is now as it should be.
	 */
	public static function write_guard( $locked, $until, $gen = null, $snap = null ) {
		if ( ! $locked ) {
			self::remove_guard();
			$ok = ! file_exists( self::path() );
			if ( $ok ) {
				self::$copy    = false;
				self::$current = array(
					'locked' => false,
					'until'  => 0,
				);
				self::guard_now( false, 0 );
			}
			return $ok;
		}
		if ( null === $gen || null === $snap ) {
			$state = PNCP_Lockdown::state();
			$gen   = null === $gen ? (int) $state['gen'] : $gen;
			$snap  = null === $snap ? (int) $state['snap'] : $snap;
		}
		$path   = self::path();
		$code   = self::code( $locked, $until, $gen, $snap );
		$record = self::record( true, $until, $gen, $snap );
		if ( is_readable( $path ) && (string) file_get_contents( $path ) === $code ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			self::$current = $record;
			self::guard_now( time() >= (int) $until, (int) $snap );
			return true;
		}
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return false;
		}
		$dir = PNCP_Paths::mu_plugins();
		if ( ! $filesystem->is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		if ( $filesystem->exists( $path ) && ! self::ours( $path ) ) {
			return false; // Someone else's file with the same name: never overwritten.
		}
		$copy = $locked && ! is_multisite() ? self::snapshot_source( (int) $snap ) : null;
		$ok   = $filesystem->put_contents( $path, $code, FS_CHMOD_FILE );
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $path, true );
		}
		if ( $ok ) {
			self::$copy    = null === $copy ? false : $copy;
			self::$current = $record;
			self::guard_now( time() >= (int) $until, (int) $snap );
		}
		return (bool) $ok;
	}

	/**
	 * The guard file was written again on this request: the values it keeps change now too, not only from the
	 * next request on (for example after unlocking, or after the quarantine deactivated a plugin).
	 *
	 * @param bool $active Whether the guard keeps values now (locked, not unlocked for a while).
	 * @param int  $snap   The generation of the snapshot the state names.
	 */
	private static function guard_now( $active, $snap ) {
		if ( ! isset( $GLOBALS['pncp_lockdown_guard'] ) || ! is_array( $GLOBALS['pncp_lockdown_guard'] ) ) {
			return;
		}
		if ( ! is_multisite() ) {
			$GLOBALS['pncp_lockdown_guard']['values'] = $active ? self::guarded_values( (int) $snap ) : array();
			return;
		}
		$payload = $active ? self::guard_payload( (int) $snap ) : array(
			'network'     => array(),
			'sites'       => array(),
			'network_own' => false,
		);
		foreach ( $payload as $key => $value ) {
			$GLOBALS['pncp_lockdown_guard'][ $key ] = $value;
		}
	}

	/**
	 * Removes the guard, only if it is ours.
	 */
	public static function remove_guard() {
		$fails = PNCP_Lockdown::fails_file();
		if ( file_exists( $fails ) ) {
			wp_delete_file( $fails ); // The copy of the wrong-code counters goes with the guard.
		}
		$path = self::path();
		if ( file_exists( $path ) && self::ours( $path ) ) {
			wp_delete_file( $path );
			if ( function_exists( 'opcache_invalidate' ) ) {
				opcache_invalidate( $path, true );
			}
		}
	}

	/**
	 * Is the guard exactly the file ScrapeLock writes for the lock as it is stored now (nothing changed or added
	 * by hand)? Used by the file integrity check, as the guard is written again on every change of the lock.
	 *
	 * @return bool
	 */
	public static function guard_genuine() {
		$path = self::path();
		if ( ! self::ours( $path ) || '' !== PNCP_Lockdown::tampered() ) {
			return false;
		}
		$state  = PNCP_Lockdown::state();
		$locked = ! empty( $state['locked'] );
		if ( ! $locked ) {
			return false;
		}
		return (string) file_get_contents( $path ) === self::code( true, (int) $state['until'], (int) $state['gen'], (int) $state['snap'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Is the guard in place?
	 *
	 * @return bool
	 */
	public static function guard_installed() {
		return self::ours( self::path() );
	}

	/**
	 * Can the guard be written on this site (direct file access to wp-content/mu-plugins, and no file of
	 * someone else under its name)? Checked before locking: without the guard, someone who can change the
	 * database directly could open the lock.
	 *
	 * @return bool
	 */
	public static function can_write_guard() {
		$path = self::path();
		if ( self::ours( $path ) && wp_is_writable( $path ) ) {
			return true;
		}
		if ( file_exists( $path ) && ! self::ours( $path ) ) {
			return false;
		}
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return false;
		}
		$dir = PNCP_Paths::mu_plugins();
		return $filesystem->is_dir( $dir ) ? $filesystem->is_writable( $dir ) : $filesystem->is_writable( dirname( $dir ) );
	}

	/**
	 * Was the file written by ScrapeLock?
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	private static function ours( $path ) {
		if ( ! is_readable( $path ) ) {
			return false;
		}
		$head = (string) file_get_contents( $path, false, null, 0, 200 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return false !== strpos( $head, 'Plugin Name: ' . self::MARKER );
	}

	/**
	 * WP_Filesystem with direct access, or null (never asks for FTP details).
	 *
	 * @return WP_Filesystem_Base|null
	 */
	private static function filesystem() {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		// The check writes a test file in the folder it is given: for a mu-plugins folder that does not exist yet
		// (most sites) it would always fail and the file would never be written. Then wp-content is asked.
		$mu      = PNCP_Paths::mu_plugins();
		$context = is_dir( $mu ) ? $mu : dirname( $mu );
		if ( 'direct' !== get_filesystem_method( array(), $context ) || ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof WP_Filesystem_Base ? $wp_filesystem : null;
	}

	/* ---------- Protected options and administrators ---------- */

	/**
	 * The accounts that could administer the site (any capability that can take it over).
	 *
	 * @return int[]
	 */
	public static function admin_ids() {
		// The upgrade runs on plugins_loaded, before WordPress sets up the roles: get_users() needs them.
		wp_roles();
		$ids = get_users(
			array(
				'capability__in' => PNCP_Lockdown::control_caps(),
				'fields'         => 'ID',
				'number'         => 500,
			)
		);
		$ids = array_map( 'intval', (array) $ids );
		sort( $ids );
		return $ids;
	}

	/**
	 * Fingerprint of an option's value.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	private static function digest( $value ) {
		return md5( maybe_serialize( $value ) );
	}

	/**
	 * The fingerprints of some values.
	 *
	 * @param array<string, mixed> $values Option => value.
	 * @return array<string, string>
	 */
	private static function digests_of( $values ) {
		$digests = array();
		foreach ( $values as $option => $value ) {
			$digests[ (string) $option ] = self::digest( $value );
		}
		return $digests;
	}

	/**
	 * Takes the snapshot when the site is locked (and again when the site is locked again after a temporary
	 * unlock). Signed. Only ever called right after the owner locked the site with the app code: the values and
	 * the administrators as they are now become the ones that count, so it never runs on its own (an upgrade, a
	 * scheduled event), where it would make values changed behind WordPress's back look genuine.
	 */
	public static function take_snapshot() {
		if ( is_multisite() ) {
			self::take_network_snapshot();
			return;
		}
		self::take_site_snapshot();
	}

	/**
	 * Takes the snapshot of this site only (see take_snapshot()). On multisite only for a lock taken before 3.3
	 * (the upgrade to 3.3): a lock taken since then takes the snapshot of the whole network.
	 */
	public static function take_site_snapshot() {
		$admins = self::admin_ids();
		self::store_snapshot( self::site_values(), $admins, null, self::staff_apps(), true, is_multisite() ? null : self::passwords_of( $admins ) );
	}

	/**
	 * 3.4, single site: keyed fingerprints of the stored password hashes of some accounts (user => fingerprint).
	 * A password hash needs no secret, so someone who can change the database could set one for an
	 * administrator and sign in with it; while locked, an account whose hash no longer matches the snapshot
	 * cannot sign in (authenticate()).
	 *
	 * @param int[] $ids Users.
	 * @return array<int, string>
	 */
	private static function passwords_of( $ids ) {
		global $wpdb;
		$ids = array_values( array_filter( array_map( 'intval', $ids ) ) );
		$out = array();
		if ( ! $ids ) {
			return $out;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- One query for all of them, as stored now; the placeholders are built from the count.
		$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT ID, user_pass FROM %i WHERE ID IN (' . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ')', $wpdb->users, ...$ids ) );
		foreach ( $rows as $row ) {
			if ( '' !== (string) $row->user_pass ) {
				$out[ (int) $row->ID ] = self::pass_print( (string) $row->user_pass );
			}
		}
		ksort( $out );
		return $out;
	}

	/**
	 * The password hash of an account as it is in the database now (never a cached copy).
	 *
	 * @param int $id User.
	 * @return string
	 */
	private static function stored_pass( $id ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Compared with the snapshot: the value as stored now, not a cached one.
		return (string) $wpdb->get_var( $wpdb->prepare( 'SELECT user_pass FROM %i WHERE ID = %d', $wpdb->users, (int) $id ) );
	}

	/**
	 * The keyed fingerprint of a password hash (never the hash itself in the snapshot).
	 *
	 * @param string $hash Password hash.
	 * @return string
	 */
	private static function pass_print( $hash ) {
		return substr( hash_hmac( 'sha256', 'pass|' . $hash, self::key() ), 0, 32 );
	}

	/**
	 * 3.4, single site: WordPress itself changed the password of an account the snapshot has a fingerprint for
	 * (during an unlock for a while, or when it stores the hash again in a newer format as the owner signs in).
	 * The snapshot gets the new fingerprint, but only if the hash before the change was the one in the snapshot:
	 * a hash written in the database first is never taken over this way.
	 *
	 * @param int    $user_id  User.
	 * @param string $old_hash The hash before the change.
	 */
	public static function password_changed( $user_id, $old_hash ) {
		if ( is_multisite() ) {
			return;
		}
		$snap = self::snapshot();
		$id   = (int) $user_id;
		if ( null === $snap || ! isset( $snap['pass'] ) || ! is_array( $snap['pass'] ) || ! isset( $snap['pass'][ $id ] ) ) {
			return;
		}
		$now = self::stored_pass( $id );
		if ( '' === $now || ! hash_equals( (string) $snap['pass'][ $id ], self::pass_print( (string) $old_hash ) ) || hash_equals( (string) $snap['pass'][ $id ], self::pass_print( $now ) ) ) {
			return;
		}
		$snap['pass'][ $id ] = self::pass_print( $now );
		self::store_snapshot( $snap['values'], $snap['admins'], isset( $snap['since'] ) ? (int) $snap['since'] : null, isset( $snap['apps'] ) ? $snap['apps'] : null, true, $snap['pass'] );
	}

	/**
	 * Does the stored password hash of an account still match the snapshot? True when the snapshot has no
	 * fingerprint for it (an account added later, or a snapshot from before this check).
	 *
	 * @param array<string, mixed> $snap Snapshot.
	 * @param int                  $id   User.
	 * @return bool
	 */
	private static function password_ok( $snap, $id ) {
		if ( ! isset( $snap['pass'] ) || ! is_array( $snap['pass'] ) || ! isset( $snap['pass'][ $id ] ) ) {
			return true;
		}
		return hash_equals( (string) $snap['pass'][ $id ], self::pass_print( self::stored_pass( $id ) ) );
	}

	/**
	 * The protected options of the current site, as stored.
	 *
	 * @return array<string, mixed>
	 */
	private static function site_values() {
		$values = array();
		foreach ( PNCP_Lockdown::sealed_options() as $option ) {
			$values[ $option ] = self::stored_option( $option );
		}
		return $values;
	}

	/**
	 * The application passwords of the staff accounts (see PNCP_Lockdown::is_staff()): user => UUIDs, sorted.
	 * Every staff account is listed, also without application passwords, so a password added later to any of
	 * them is noticed.
	 *
	 * @return array<int, string[]>
	 */
	public static function staff_apps() {
		$apps = array();
		foreach ( self::staff_ids() as $id ) {
			$apps[ $id ] = self::user_apps( $id );
		}
		return $apps;
	}

	/**
	 * The UUIDs of a user's application passwords, sorted.
	 *
	 * @param int $id User.
	 * @return string[]
	 */
	private static function user_apps( $id ) {
		$uuids = array();
		foreach ( WP_Application_Passwords::get_user_application_passwords( (int) $id ) as $item ) {
			if ( isset( $item['uuid'] ) ) {
				$uuids[] = (string) $item['uuid'];
			}
		}
		sort( $uuids );
		return $uuids;
	}

	/**
	 * The staff accounts of the current site (frozen roles), and everyone with application passwords who is
	 * staff here, sorted.
	 *
	 * @return int[]
	 */
	private static function staff_ids() {
		wp_roles();
		$ids    = array();
		$frozen = PNCP_Lockdown::frozen_roles();
		if ( $frozen ) {
			$ids = get_users(
				array(
					'role__in' => $frozen,
					'fields'   => 'ID',
					'number'   => 2000,
				)
			);
		}
		// Also everyone who has application passwords: staff through a capability of their own, network admins.
		$with = get_users(
			array(
				'blog_id'      => 0,
				'meta_key'     => WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Only on lock and in the hourly check.
				'meta_compare' => 'EXISTS',
				'fields'       => 'ID',
				'number'       => 2000,
			)
		);
		$out  = array();
		foreach ( array_unique( array_map( 'intval', array_merge( (array) $ids, (array) $with ) ) ) as $id ) {
			if ( PNCP_Lockdown::is_staff( $id ) ) {
				$out[] = $id;
			}
		}
		sort( $out );
		return $out;
	}

	/**
	 * Was this application password of a staff account added after the site was locked? Staff cannot add one
	 * while locked (or unlocked for a while), so it was added in the database. False without a snapshot that
	 * lists the application passwords (not locked, or a snapshot from before 3.4).
	 *
	 * @param int    $user_id User.
	 * @param string $uuid    The application password.
	 * @return bool
	 */
	public static function app_password_new( $user_id, $uuid ) {
		$snap = self::current_snapshot();
		if ( null === $snap || ! isset( $snap['apps'] ) || ! is_array( $snap['apps'] ) || ! PNCP_Lockdown::is_staff( (int) $user_id ) ) {
			return false;
		}
		$known = isset( $snap['apps'][ (int) $user_id ] ) ? (array) $snap['apps'][ (int) $user_id ] : array();
		return ! in_array( (string) $uuid, $known, true );
	}

	/**
	 * Removes the application passwords that were added to staff accounts after the snapshot was taken, and
	 * reports them. Run hourly while locked, and before the snapshot is replaced or removed (locked again after
	 * a while, unlocked for good, app removed), because from then on they would count as genuine.
	 *
	 * @param bool $known_only Only the accounts the snapshot lists: after a temporary unlock, an account may have
	 *                         become staff in the meantime (with application passwords made before).
	 * @param bool $alert      Report them (false: the caller reports, see check_apps_all()).
	 * @return string[] The accounts concerned.
	 */
	public static function check_apps( $known_only = false, $alert = true ) {
		$snap = self::current_snapshot();
		if ( null === $snap || ! isset( $snap['apps'] ) || ! is_array( $snap['apps'] ) ) {
			return array();
		}
		$found = array();
		foreach ( self::staff_apps() as $id => $uuids ) {
			if ( $known_only && ! isset( $snap['apps'][ $id ] ) ) {
				continue;
			}
			$known = isset( $snap['apps'][ $id ] ) ? (array) $snap['apps'][ $id ] : array();
			$new   = array_diff( $uuids, $known );
			if ( ! $new ) {
				continue;
			}
			foreach ( $new as $uuid ) {
				WP_Application_Passwords::delete_application_password( $id, $uuid );
			}
			$user    = get_userdata( $id );
			$found[] = ( $user ? $user->user_login . ' (#' . $id . ')' : '#' . $id ) . ': ' . count( $new );
		}
		if ( $found && $alert ) {
			PNCP_Lockdown::tamper_alert( 'apps', implode( ', ', array_slice( $found, 0, 10 ) ) );
		}
		return $found;
	}

	/**
	 * Updates one value in the snapshot (and its fingerprint), keeping everything else as it was signed: for a
	 * change ScrapeLock itself makes while locked (the quarantine deactivating a plugin). Nothing is signed when
	 * there is no genuine snapshot to update.
	 *
	 * @param string $option Option.
	 * @return bool Whether the snapshot was updated.
	 */
	public static function update_snapshot( $option ) {
		if ( is_multisite() && self::network_mode() ) {
			self::ensure_site_snapshot();
		}
		$snap = self::snapshot();
		if ( null === $snap || ! array_key_exists( (string) $option, $snap['values'] ) ) {
			return false;
		}
		$snap['values'][ (string) $option ] = self::stored_option( (string) $option );
		self::store_snapshot( $snap['values'], $snap['admins'], isset( $snap['since'] ) ? (int) $snap['since'] : null, isset( $snap['apps'] ) ? $snap['apps'] : null, true, isset( $snap['pass'] ) ? $snap['pass'] : null );
		return true;
	}

	/**
	 * Signs and stores the snapshot and the fingerprints of its values.
	 *
	 * @param array<string, mixed>      $values Option => value.
	 * @param int[]                     $admins The accounts that could administer the site.
	 * @param int|null                  $since  The lock time it belongs to (null: the lock time in the state now).
	 * @param array<int, string[]>|null $apps   The application passwords of the staff accounts (null: not kept,
	 *                                          a snapshot from before 3.4).
	 * @param bool                      $note   Note its generation in the state now (false: the caller saves the
	 *                                          state itself, in the same write as its other changes).
	 * @param array<int, string>|null   $pass   Single site, 3.4: the fingerprints of the password hashes of the
	 *                                          administrators (null: not kept).
	 * @return int The generation of the snapshot.
	 */
	private static function store_snapshot( $values, $admins, $since = null, $apps = null, $note = true, $pass = null ) {
		$since = null === $since ? (int) PNCP_Lockdown::state()['since'] : (int) $since;
		// 3.4: a generation higher than any before it. The state (and the guard) note it, so a snapshot or set of
		// fingerprints put back from an older copy of the database is no longer accepted.
		$gen = PNCP_Lockdown::next_generation();
		self::write_site_snapshot( $values, $admins, $since, $gen, $apps, false, $pass );
		if ( is_multisite() && self::network_mode() ) {
			// Multisite: the snapshot of the network names the generation of each site's snapshot. Only this site's
			// entry changes; the other sites keep theirs (and their own, older generation).
			$net = self::net_snapshot();
			if ( null !== $net ) {
				$id                  = get_current_blog_id();
				$old                 = isset( $net['sites'][ $id ] ) && is_array( $net['sites'][ $id ] ) ? $net['sites'][ $id ] : array();
				$net['sites'][ $id ] = self::site_entry( $values, $admins, $gen, true, isset( $old['guard'] ) );
				$net['gen']          = $gen;
				self::store_network( $net );
			}
		}
		// Snapshot first, then the state and the guard: a request in between sees a snapshot newer than the one
		// the state names, which is accepted (only older ones are not).
		if ( $note ) {
			PNCP_Lockdown::note_snapshot( $gen );
		}
		return $gen;
	}

	/**
	 * Signs and stores the snapshot of the current site and the fingerprints of its values, with a generation
	 * given by the caller.
	 *
	 * @param array<string, mixed>      $values Option => value.
	 * @param int[]                     $admins The accounts that could administer the site.
	 * @param int                       $since  The lock time it belongs to.
	 * @param int                       $gen    The generation.
	 * @param array<int, string[]>|null $apps   The application passwords of the staff accounts (null: not kept).
	 * @param bool                      $lazy   Multisite: only the fingerprints (marked "lazy"); the snapshot itself
	 *                                          is taken on the first request to the site (ensure_site_snapshot()).
	 * @param array<int, string>|null   $pass   The fingerprints of the administrators' password hashes (null: not
	 *                                          kept).
	 */
	private static function write_site_snapshot( $values, $admins, $since, $gen, $apps = null, $lazy = false, $pass = null ) {
		if ( $lazy ) {
			self::save_digests( $values, $since, $gen, true );
			return;
		}
		$snap = array(
			'time'   => time(),
			'values' => $values,
			'admins' => array_values( array_map( 'intval', $admins ) ),
			// 3.4: the lock it belongs to. A lock state put back from before this lock no longer matches it.
			'since'  => $since,
			'gen'    => $gen,
		);
		if ( is_array( $apps ) ) {
			// 3.4: the application passwords of the staff accounts (check_apps()).
			$snap['apps'] = $apps;
		}
		if ( is_array( $pass ) ) {
			// 3.4: the administrators' password hashes, as keyed fingerprints (see passwords_of()).
			$snap['pass'] = $pass;
		}
		$snap['sig'] = self::sign( $snap );
		update_option( self::SNAP, $snap, false );
		wp_cache_delete( self::SNAP, 'options' );
		self::save_digests( $values, $since, $gen );
	}

	/**
	 * The upgrade to 3.4: gives the genuine snapshot of the current lock a generation (the same values,
	 * administrators and application passwords as signed when the site was locked, never the options as they
	 * are now). Nothing happens without a genuine snapshot.
	 */
	public static function upgrade_snapshot() {
		$snap = self::snapshot();
		if ( null === $snap || isset( $snap['gen'] ) ) {
			return;
		}
		self::store_snapshot( $snap['values'], $snap['admins'], isset( $snap['since'] ) ? (int) $snap['since'] : null, isset( $snap['apps'] ) ? $snap['apps'] : null, true, isset( $snap['pass'] ) ? $snap['pass'] : null );
	}

	/**
	 * Stores the signed fingerprints of the protected options (autoloaded).
	 *
	 * @param array<string, mixed> $values Option => value.
	 * @param int                  $since  The lock time they belong to.
	 * @param int                  $gen    The generation of the snapshot they belong to (0: a snapshot from
	 *                                     before 3.4).
	 * @param bool                 $lazy   Multisite: the snapshot itself is not taken yet (see
	 *                                     write_site_snapshot()).
	 */
	private static function save_digests( $values, $since, $gen = 0, $lazy = false ) {
		$record = array(
			'digests' => self::digests_of( $values ),
			'since'   => (int) $since,
		);
		if ( $gen ) {
			$record['gen'] = (int) $gen;
		}
		if ( $lazy ) {
			$record['lazy'] = true;
		}
		$record['sig'] = self::sign( $record );
		update_option( self::DIGESTS, $record, true );
	}

	/**
	 * The signed fingerprints of the current snapshot, or null (missing, not matching their signature, or from
	 * an older snapshot than the one the state and the guard name).
	 *
	 * @return array<string, string>|null
	 */
	private static function digests() {
		$record = self::digests_record();
		$want   = self::wanted_site_snap();
		if ( -1 === $want ) {
			return null;
		}
		if ( null !== $record && ! self::generation_ok( $record, $want ) ) {
			// The fingerprints are autoloaded: read at the start of this request, perhaps a moment before another
			// request stored newer ones with a new snapshot (for example when an unlock for a while has just
			// ended), while the state was read later. Read once more from the database before calling it old.
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( self::DIGESTS, 'options' );
			$record = self::digests_record();
		}
		return null !== $record && self::generation_ok( $record, $want ) ? $record['digests'] : null;
	}

	/**
	 * The generation of the snapshot that counts now: the one the guard names (a file, so it cannot be set back
	 * in the database), or the one the genuine state names. 0: no generations yet (data from before 3.4).
	 *
	 * @return int
	 */
	public static function wanted_snap() {
		$want   = '' === PNCP_Lockdown::tampered() ? (int) PNCP_Lockdown::state()['snap'] : 0;
		$beacon = self::beacon();
		if ( $beacon && isset( $beacon['snap'] ) ) {
			$want = max( $want, (int) $beacon['snap'] );
		}
		return $want;
	}

	/**
	 * The generation of this site's snapshot that counts now. On a single site the one of the lock
	 * (wanted_snap()). On a multisite network locked with 3.4 or later the one the signed snapshot of the network
	 * names for this site: each site's snapshot changes on its own (the quarantine, an unlock for a while), so
	 * the generation of the lock is often newer than a site's own. -1: the network's snapshot does not list this
	 * site (added after the lock, or ScrapeLock was not active on it): there is nothing to compare with.
	 * 0 when the network's fingerprints cannot be read (missing or changed, reported by verify_network()): any
	 * genuine snapshot of this lock is accepted then.
	 *
	 * @return int
	 */
	private static function wanted_site_snap() {
		if ( ! is_multisite() || ! self::network_mode() ) {
			return self::wanted_snap();
		}
		$net = self::net_digests();
		if ( null === $net ) {
			return 0;
		}
		$id = get_current_blog_id();
		return isset( $net['sites'][ $id ] ) ? max( 1, (int) $net['sites'][ $id ] ) : -1;
	}

	/**
	 * Is a signed snapshot (or set of fingerprints) the current one? It must be at least as new as the generation
	 * that counts now: an older one was put back from a copy of the database. A newer one is fine (the snapshot
	 * is stored a moment before the state notes it).
	 *
	 * @param array<string, mixed> $record Snapshot or fingerprints (signature already checked).
	 * @param int                  $want   The generation that counts now (0: none, everything from before 3.4).
	 * @return bool
	 */
	private static function generation_ok( $record, $want ) {
		if ( (int) $want <= 0 ) {
			return true;
		}
		return isset( $record['gen'] ) && (int) $record['gen'] >= (int) $want;
	}

	/**
	 * The record of the signed fingerprints (without its signature), or null.
	 *
	 * @param bool $loaded_only Only if WordPress already loaded it with the autoloaded options: a site that never
	 *                          locked costs no extra query on every request.
	 * @return array{digests:array<string, string>, since?:int, gen?:int}|null
	 */
	private static function digests_record( $loaded_only = false ) {
		if ( $loaded_only ) {
			$all = wp_load_alloptions();
			if ( ! isset( $all[ self::DIGESTS ] ) ) {
				return null;
			}
		}
		$record = get_option( self::DIGESTS );
		if ( ! is_array( $record ) || ! isset( $record['digests'], $record['sig'] ) || ! is_array( $record['digests'] ) ) {
			return null;
		}
		$sig = $record['sig'];
		unset( $record['sig'] );
		return self::valid( $record, $sig ) ? $record : null;
	}

	/**
	 * The snapshot of the current lock, if its signature matches and it is not older than the generation that
	 * counts now: [time, values, admins], or null.
	 *
	 * @return array{time:int, values:array<string, mixed>, admins:int[]}|null
	 */
	public static function snapshot() {
		self::$from_copy = false;
		$snap            = self::snapshot_record();
		if ( null === $snap && ( is_multisite() || null === self::guard_copy() ) ) {
			return null;
		}
		$want = self::wanted_site_snap();
		if ( -1 === $want ) {
			return null;
		}
		if ( ! is_multisite() && ( null === $snap || ! self::generation_ok( $snap, $want ) ) ) {
			// 3.4: the snapshot in the database is missing, changed or older than this lock: the signed copy in the
			// guard file counts instead (verify_options() puts it back in the database).
			$copy = self::guard_copy();
			if ( null !== $copy && self::generation_ok( $copy, $want ) ) {
				self::$from_copy = true;
				return $copy;
			}
		}
		if ( null === $snap ) {
			return null;
		}
		if ( is_multisite() && self::network_mode() && ( ! isset( $snap['since'] ) || self::lock_since() !== (int) $snap['since'] ) ) {
			return null; // From another lock (each site's snapshot is checked against the lock of the network).
		}
		return self::generation_ok( $snap, $want ) ? $snap : null;
	}

	/**
	 * The snapshot if its signature matches, whatever its generation (also an older one put back from a copy of
	 * the database): only as evidence that the site was locked, and to tell an older copy from a changed one.
	 *
	 * @return array{time:int, values:array<string, mixed>, admins:int[]}|null
	 */
	private static function snapshot_record() {
		$snap = get_option( self::SNAP );
		if ( ! is_array( $snap ) || ! isset( $snap['sig'], $snap['values'], $snap['admins'], $snap['time'] ) ) {
			return null;
		}
		$sig = $snap['sig'];
		unset( $snap['sig'] );
		return self::valid( $snap, $sig ) && is_array( $snap['values'] ) && is_array( $snap['admins'] ) ? $snap : null;
	}

	/* ---------- Multisite: the snapshot of the whole network ---------- */

	/**
	 * Was this network locked with a snapshot of the whole network (3.4 or later)? The (signed) state says so;
	 * genuine fingerprints of the network count too, so a state that cannot be trusted does not switch it off. A
	 * network locked with an earlier version has a snapshot of one site only (the one where it was locked).
	 *
	 * @return bool
	 */
	public static function network_mode() {
		if ( ! is_multisite() ) {
			return false;
		}
		return ! empty( PNCP_Lockdown::state()['net'] ) || null !== self::net_record( self::NET_DIGESTS );
	}

	/**
	 * A signed network record (NET_SNAP or NET_DIGESTS) without its signature, whatever its generation, or null
	 * (missing, or not matching its signature). The fingerprints are read once per request.
	 *
	 * @param string $name NET_SNAP or NET_DIGESTS.
	 * @return array<string, mixed>|null
	 */
	private static function net_record( $name ) {
		if ( self::NET_DIGESTS === $name && null !== self::$net_digests ) {
			return false === self::$net_digests ? null : self::$net_digests;
		}
		$stored = get_site_option( $name );
		$record = null;
		if ( is_array( $stored ) && isset( $stored['sig'], $stored['sites'], $stored['since'], $stored['gen'] ) && is_array( $stored['sites'] ) ) {
			$sig = $stored['sig'];
			unset( $stored['sig'] );
			$keys = self::NET_SNAP === $name ? array( 'values', 'super', 'apps' ) : array( 'digests' );
			$ok   = self::valid( $stored, $sig );
			foreach ( $keys as $key ) {
				$ok = $ok && isset( $stored[ $key ] ) && is_array( $stored[ $key ] );
			}
			$record = $ok ? $stored : null;
		}
		if ( self::NET_DIGESTS === $name ) {
			self::$net_digests = null === $record ? false : $record;
		}
		return $record;
	}

	/**
	 * Forgets the network's fingerprints read on this request (the next read comes from the database).
	 */
	private static function forget_net_cache() {
		self::$net_digests = null;
		wp_cache_delete( get_current_network_id() . ':' . self::NET_DIGESTS, 'site-options' );
		wp_cache_delete( get_current_network_id() . ':' . self::NET_SNAP, 'site-options' );
		wp_cache_delete( get_current_network_id() . ':notoptions', 'site-options' );
	}

	/**
	 * The signed fingerprints of the network for the current lock, or null (missing, changed, or older than the
	 * generation that counts now). Like the fingerprints of a site, read once more from the database before an
	 * older one is called old: another request may have stored newer ones a moment ago.
	 *
	 * @return array{digests:array<string, string>, sites:array<int, int>, since:int, gen:int}|null
	 */
	private static function net_digests() {
		static $reread = false;

		$record = self::net_record( self::NET_DIGESTS );
		$want   = self::wanted_snap();
		if ( ( null === $record || ! self::generation_ok( $record, $want ) ) && ! $reread ) {
			$reread = true;
			self::forget_net_cache();
			$record = self::net_record( self::NET_DIGESTS );
		}
		return null !== $record && self::generation_ok( $record, $want ) ? $record : null;
	}

	/**
	 * The snapshot of the network for the current lock, if its signature matches and it is not older than the
	 * generation that counts now, or null.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function net_snapshot() {
		$net = self::net_record( self::NET_SNAP );
		return null !== $net && self::generation_ok( $net, self::wanted_snap() ) ? $net : null;
	}

	/**
	 * The lock time the snapshots belong to: from the network's signed fingerprints when they can be read (the
	 * state itself may have been changed), otherwise from the state.
	 *
	 * @return int
	 */
	private static function lock_since() {
		$net = is_multisite() ? self::net_digests() : null;
		return null !== $net ? (int) $net['since'] : (int) PNCP_Lockdown::state()['since'];
	}

	/**
	 * Signs and stores the snapshot of the network and its fingerprints (the generation of every site's
	 * snapshot with them).
	 *
	 * @param array<string, mixed> $net The snapshot of the network.
	 */
	private static function store_network( $net ) {
		unset( $net['sig'] );
		ksort( $net['sites'] );
		$stored        = $net;
		$stored['sig'] = self::sign( $net );
		update_site_option( self::NET_SNAP, $stored );
		$sites = array();
		foreach ( $net['sites'] as $id => $entry ) {
			$sites[ (int) $id ] = (int) $entry['gen'];
		}
		$digests        = array(
			'digests' => self::digests_of( $net['values'] ),
			'sites'   => $sites,
			'since'   => (int) $net['since'],
			'gen'     => (int) $net['gen'],
		);
		$digests['sig'] = self::sign( $digests );
		update_site_option( self::NET_DIGESTS, $digests );
		self::forget_net_cache();
	}

	/**
	 * What the snapshot of the network keeps of one site: the generation of its own snapshot, the fingerprints
	 * of its protected options, its administrators, whether its snapshot was taken at once ("taken"; otherwise
	 * on its first request) and, for the first sites, the active plugins and the theme the guard keeps.
	 *
	 * @param array<string, mixed> $values Option => value.
	 * @param int[]                $admins The accounts that could administer the site.
	 * @param int                  $gen    The generation of its snapshot.
	 * @param bool                 $taken  The snapshot itself was stored.
	 * @param bool                 $guard  Also the values the guard keeps.
	 * @return array<string, mixed>
	 */
	private static function site_entry( $values, $admins, $gen, $taken, $guard ) {
		$admins = array_values( array_unique( array_map( 'intval', $admins ) ) );
		sort( $admins );
		$entry = array(
			'gen'     => (int) $gen,
			'digests' => self::digests_of( $values ),
			'admins'  => $admins,
			'taken'   => (bool) $taken,
		);
		if ( $guard ) {
			$entry['guard'] = self::guard_subset( $values );
		}
		return $entry;
	}

	/**
	 * Multisite: how many sites the lock of a network covers ('sites', filter pncp_lockdown_network_sites,
	 * 1000), how many of them get their full snapshot at once when the network is locked ('now', filter
	 * pncp_lockdown_network_snapshots, 50; the others on their first request), and for how many the guard keeps
	 * the active plugins and the theme ('guard', filter pncp_lockdown_guard_sites, 100: the guard file is read on
	 * every request).
	 *
	 * @return array{sites:int, now:int, guard:int}
	 */
	public static function network_limits() {
		return array(
			'sites' => max( 1, (int) apply_filters( 'pncp_lockdown_network_sites', 1000 ) ),
			'now'   => max( 1, (int) apply_filters( 'pncp_lockdown_network_snapshots', 50 ) ),
			'guard' => max( 0, (int) apply_filters( 'pncp_lockdown_guard_sites', 100 ) ),
		);
	}

	/**
	 * Multisite: how many sites the snapshot of the network covers, and how many sites the network had when it
	 * was locked (for the Lockdown tab). Null without a genuine snapshot of the network.
	 *
	 * @return array{covered:int, total:int}|null
	 */
	public static function network_coverage() {
		$net = is_multisite() ? self::net_snapshot() : null;
		if ( null === $net ) {
			return null;
		}
		return array(
			'covered' => count( $net['sites'] ),
			'total'   => isset( $net['total'] ) ? (int) $net['total'] : count( $net['sites'] ),
		);
	}

	/**
	 * The sites the lock of a network covers: up to 1000 (filter pncp_lockdown_network_sites), the current site
	 * first.
	 *
	 * @return int[]
	 */
	public static function network_site_ids() {
		$limit   = self::network_limits()['sites'];
		$ids     = array_map(
			'intval',
			(array) get_sites(
				array(
					'fields'                 => 'ids',
					'number'                 => $limit,
					'network_id'             => get_current_network_id(),
					'orderby'                => 'id',
					'order'                  => 'ASC',
					'update_site_meta_cache' => false,
				)
			)
		);
		$current = get_current_blog_id();
		$ids     = array_values( array_diff( $ids, array( $current ) ) );
		array_unshift( $ids, $current );
		return array_slice( $ids, 0, max( $limit, 1 ) );
	}

	/**
	 * The IDs of the super admins (from a list of logins, or the ones WordPress knows now).
	 *
	 * @param mixed $logins Logins (null: get_super_admins()).
	 * @return int[]
	 */
	private static function super_ids( $logins = null ) {
		$ids = array();
		foreach ( (array) ( null === $logins ? get_super_admins() : $logins ) as $login ) {
			$user = is_string( $login ) ? get_user_by( 'login', $login ) : false;
			if ( $user ) {
				$ids[] = (int) $user->ID;
			}
		}
		$ids = array_values( array_unique( $ids ) );
		sort( $ids );
		return $ids;
	}

	/**
	 * Everyone with application passwords on the network: user => UUIDs (for the snapshot of a site taken on
	 * its first request after the lock).
	 *
	 * @return array<int, string[]>
	 */
	private static function network_apps() {
		$with = get_users(
			array(
				'blog_id'      => 0,
				'meta_key'     => WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Only when the network is locked.
				'meta_compare' => 'EXISTS',
				'fields'       => 'ID',
				'number'       => 2000,
			)
		);
		$apps = array();
		foreach ( array_map( 'intval', (array) $with ) as $id ) {
			$apps[ $id ] = self::user_apps( $id );
		}
		ksort( $apps );
		return $apps;
	}

	/**
	 * Multisite: takes the snapshot of the whole network when it is locked (only ever right after the owner
	 * locked it with the app code, like take_snapshot()).
	 *
	 * The network options, the super admins and the application passwords go in the snapshot of the network.
	 * Every site where ScrapeLock is active (up to network_site_ids()) gets the signed fingerprints of its
	 * protected options and its administrators, noted in the snapshot of the network too. The first 50 sites
	 * (filter pncp_lockdown_network_snapshots) get their full snapshot at once; the others on their first request
	 * (ensure_site_snapshot()), from the values that still match the fingerprints taken now, so a large network
	 * does not wait for every copy. The guard keeps the active plugins and the theme of the first 100 sites
	 * (filter pncp_lockdown_guard_sites).
	 */
	private static function take_network_snapshot() {
		$since  = (int) PNCP_Lockdown::state()['since'];
		$gen    = PNCP_Lockdown::next_generation();
		$own    = plugin_basename( PNCP_FILE );
		$values = array();
		foreach ( self::NETWORK_OPTIONS as $option ) {
			$values[ $option ] = self::stored_site_option( $option );
		}
		$network_active = is_array( $values['active_sitewide_plugins'] ) && isset( $values['active_sitewide_plugins'][ $own ] );
		$limits         = self::network_limits();
		$now            = $limits['now'];
		$guard          = $limits['guard'];
		$sites          = array();
		$taken          = 0;
		foreach ( self::network_site_ids() as $id ) {
			switch_to_blog( $id );
			try {
				$site = self::site_values();
				if ( ! $network_active && ! ( is_array( $site['active_plugins'] ) && in_array( $own, $site['active_plugins'], true ) ) ) {
					// ScrapeLock does not run on this site, so nothing there would check a snapshot. One left from an
					// earlier lock goes.
					delete_option( self::SNAP );
					delete_option( self::DIGESTS );
					continue;
				}
				$admins = self::admin_ids();
				$eager  = $taken < $now;
				if ( $eager ) {
					self::write_site_snapshot( $site, $admins, $since, $gen, self::staff_apps() );
					++$taken;
				} else {
					delete_option( self::SNAP ); // One left from an earlier lock.
					self::write_site_snapshot( $site, $admins, $since, $gen, null, true );
				}
				$sites[ $id ] = self::site_entry( $site, $admins, $gen, $eager, count( $sites ) < $guard );
			} finally {
				restore_current_blog();
			}
		}
		self::store_network(
			array(
				'time'   => time(),
				'since'  => $since,
				'gen'    => $gen,
				'values' => $values,
				'super'  => self::super_ids(),
				'apps'   => self::network_apps(),
				'sites'  => $sites,
				'total'  => (int) get_sites(
					array(
						'count'      => true,
						'network_id' => get_current_network_id(),
					)
				),
			)
		);
		PNCP_Lockdown::note_snapshot( $gen, true );
	}

	/**
	 * Multisite: a site whose snapshot was not taken at once (or whose snapshot is missing, changed or older than
	 * the snapshot of the network names) gets it now, from the values that still match the fingerprints the
	 * snapshot of the network took when the network was locked. Those are exactly the values of the lock, so
	 * nothing changed behind WordPress's back is ever taken as genuine. A value that no longer matches cannot be
	 * known any more: the active plugins and the theme come from the snapshot of the network when it holds them
	 * (and are put back), anything else is reported.
	 */
	private static function ensure_site_snapshot() {
		if ( null !== self::snapshot() ) {
			return;
		}
		$net = self::net_snapshot();
		$id  = get_current_blog_id();
		if ( null === $net || ! isset( $net['sites'][ $id ] ) || ! is_array( $net['sites'][ $id ] ) ) {
			return;
		}
		$entry  = $net['sites'][ $id ];
		$old    = self::snapshot_record();
		$stored = false !== get_option( self::SNAP, false );
		$values = array();
		$lost   = array();
		foreach ( isset( $entry['digests'] ) ? (array) $entry['digests'] : array() as $option => $digest ) {
			$option = (string) $option;
			$now    = self::stored_option( $option );
			if ( self::digest( $now ) === $digest ) {
				$values[ $option ] = $now;
			} elseif ( isset( $entry['guard'] ) && is_array( $entry['guard'] ) && array_key_exists( $option, $entry['guard'] ) ) {
				$values[ $option ] = $entry['guard'][ $option ]; // As the guard keeps it; put back by restore().
			} else {
				$lost[] = $option;
			}
		}
		$apps = array();
		foreach ( self::staff_ids() as $user ) {
			$apps[ $user ] = isset( $net['apps'][ $user ] ) ? array_values( array_map( 'strval', (array) $net['apps'][ $user ] ) ) : array();
		}
		self::write_site_snapshot( $values, isset( $entry['admins'] ) ? (array) $entry['admins'] : array(), (int) $net['since'], (int) $entry['gen'], $apps );
		// A snapshot taken at once that is gone, changed, or older than the one the network names was changed in
		// the database. A snapshot of an earlier lock, left on a site whose snapshot is taken now, was not.
		$tampered = ! empty( $entry['taken'] ) || ( $stored && ( null === $old || ( isset( $old['since'] ) && (int) $old['since'] === (int) $net['since'] ) ) );
		if ( $tampered || $lost ) {
			$detail = self::site_label( $id ) . ( $lost ? ': ' . implode( ', ', $lost ) : '' );
			PNCP_Lockdown::tamper_alert( null !== $old && ! $lost ? 'replay' : 'snapshot', $detail );
		}
	}

	/**
	 * Multisite: puts back the network options that changed behind WordPress's back, compared with the signed
	 * snapshot of the network (the fingerprints first, on every request). Returns the network's fingerprints
	 * for the per-site checks, or null when they cannot be read (reported).
	 *
	 * @return array{digests:array<string, string>, sites:array<int, int>, since:int, gen:int}|null
	 */
	private static function verify_network() {
		$record  = self::net_digests();
		$pending = PNCP_Lockdown::reseal_pending();
		if ( null !== $record && ! $pending ) {
			$same = true;
			foreach ( $record['digests'] as $option => $digest ) {
				if ( self::digest( self::stored_site_option( (string) $option ) ) !== $digest ) {
					$same = false;
					break;
				}
			}
			if ( $same ) {
				return $record;
			}
		}
		$net = self::current_network_snapshot();
		if ( null === $net ) {
			if ( self::snapshot_pending( self::net_record( self::NET_SNAP ) ) ) {
				return $record; // Just locked: the snapshot of the network is being taken (see snapshot_pending()).
			}
			PNCP_Lockdown::tamper_alert( null !== self::net_record( self::NET_SNAP ) ? 'replay' : 'snapshot', 'network' );
			return $record;
		}
		$restored = array();
		foreach ( $net['values'] as $option => $value ) {
			if ( self::digest( self::stored_site_option( (string) $option ) ) !== self::digest( $value ) ) {
				PNCP_Lockdown::write_protected_site( (string) $option, $value );
				$restored[] = (string) $option;
			}
		}
		if ( $restored ) {
			PNCP_Lockdown::tamper_alert( 'options', 'network: ' . implode( ', ', $restored ) );
		}
		if ( null === $record ) {
			if ( null !== self::net_record( self::NET_DIGESTS ) ) {
				PNCP_Lockdown::tamper_alert( 'replay', 'network' );
			}
			// The fingerprints again, from the signed snapshot of the network (never from the values as they are).
			$genuine = self::net_snapshot();
			if ( null !== $genuine ) {
				self::store_network( $genuine );
			}
			$record = self::net_digests();
		}
		return $record;
	}

	/**
	 * Multisite: the snapshot of the network that counts now: with the changes the owner made to the network
	 * options during an unlock for a while that has just ended (see current_snapshot()).
	 *
	 * @return array<string, mixed>|null
	 */
	public static function current_network_snapshot() {
		$net = self::net_snapshot();
		if ( null === $net || ! PNCP_Lockdown::reseal_pending() ) {
			return $net;
		}
		$record = self::window_record( false, true );
		if ( null === $record ) {
			return $net;
		}
		foreach ( $record['values'] as $option => $value ) {
			if ( array_key_exists( (string) $option, $net['values'] ) ) {
				$net['values'][ (string) $option ] = $value;
			}
		}
		if ( array_key_exists( 'site_admins', $record['values'] ) ) {
			// The super admins the owner added (or removed) meanwhile, by their login, as WordPress keeps them.
			$net['super'] = self::super_ids( (array) $net['values']['site_admins'] );
		}
		return $net;
	}

	/**
	 * Multisite: one network option changed by ScrapeLock itself while locked (the quarantine deactivating a
	 * plugin active on the whole network): only that value changes in the snapshot of the network.
	 *
	 * @param string $option Network option.
	 * @return bool Whether the snapshot of the network was updated.
	 */
	public static function update_network_value( $option ) {
		if ( ! is_multisite() || ! self::network_mode() ) {
			return false;
		}
		$net = self::net_snapshot();
		if ( null === $net || ! array_key_exists( (string) $option, $net['values'] ) ) {
			return false;
		}
		$gen                               = PNCP_Lockdown::next_generation();
		$net['values'][ (string) $option ] = self::stored_site_option( (string) $option );
		$net['gen']                        = $gen;
		self::store_network( $net );
		PNCP_Lockdown::note_snapshot( $gen );
		return true;
	}

	/**
	 * 3.4: the administration address as signed when the site (or the network) was locked: from the snapshot,
	 * or from its copy in the guard file. Empty without a genuine one. Alerts go there while locked
	 * (PNCP_Lockdown::alert_to()), so someone who changed the address in the database does not get them.
	 *
	 * @return string
	 */
	public static function alert_address() {
		if ( is_multisite() && self::network_mode() ) {
			$net  = self::net_snapshot();
			$mail = null !== $net && isset( $net['values']['admin_email'] ) ? $net['values']['admin_email'] : '';
		} else {
			$snap = self::snapshot();
			$mail = null !== $snap && isset( $snap['values']['admin_email'] ) ? $snap['values']['admin_email'] : '';
		}
		return is_string( $mail ) && is_email( $mail ) ? $mail : '';
	}

	/**
	 * Deletes the snapshots when the lock ends for good (unlocked "until I lock it again", the app removed, or a
	 * new app connected): of this site, and on multisite of every site and of the network.
	 */
	public static function forget_snapshots() {
		delete_option( self::SNAP );
		delete_option( self::DIGESTS );
		if ( ! is_multisite() ) {
			return;
		}
		foreach ( self::network_site_ids() as $id ) {
			if ( get_current_blog_id() !== $id ) {
				delete_blog_option( $id, self::SNAP );
				delete_blog_option( $id, self::DIGESTS );
			}
		}
		delete_site_option( self::NET_SNAP );
		delete_site_option( self::NET_DIGESTS );
		self::forget_net_cache();
	}

	/**
	 * Runs check_apps() on every site the lock of the network covers (multisite), or on this site.
	 *
	 * @param bool $known_only See check_apps().
	 * @return string[] The accounts concerned.
	 */
	public static function check_apps_all( $known_only = false ) {
		if ( ! is_multisite() || ! self::network_mode() ) {
			return self::check_apps( $known_only );
		}
		$net   = self::net_snapshot();
		$ids   = null !== $net ? array_map( 'intval', array_keys( $net['sites'] ) ) : array( get_current_blog_id() );
		$found = array();
		foreach ( $ids as $id ) {
			switch_to_blog( $id );
			try {
				foreach ( self::check_apps( $known_only, false ) as $line ) {
					$found[] = self::site_label( $id ) . ' ' . $line;
				}
			} finally {
				restore_current_blog();
			}
		}
		if ( $found ) {
			PNCP_Lockdown::tamper_alert( 'apps', implode( ', ', array_slice( $found, 0, 10 ) ) );
		}
		return $found;
	}

	/**
	 * A site, for an alert and the lockdown log. Like the names of the options in the same messages, it is not
	 * translated: some of them are written before WordPress loads translations (the seal runs on
	 * plugins_loaded).
	 *
	 * @param int $id Site ID.
	 * @return string
	 */
	private static function site_label( $id ) {
		return 'site ' . (int) $id;
	}

	/**
	 * A user's login and ID, for an alert.
	 *
	 * @param int $id User.
	 * @return string
	 */
	private static function user_label( $id ) {
		$user = get_userdata( (int) $id );
		return $user ? $user->user_login . ' (#' . (int) $id . ')' : '#' . (int) $id;
	}

	/* ---------- Unlocked for a while: what is kept when it locks again by itself ---------- */

	/**
	 * Notes a change of a protected option made through WordPress while the site is unlocked for a while, by the
	 * administrator who unlocked, in the browser session that unlocked (PNCP_Lockdown::window_session()). Only
	 * the change itself is noted, against the signed snapshot: what this write added, changed or removed
	 * compared with the value it replaced. A value changed directly in the database (now or before) that a
	 * WordPress screen then saves again unchanged is not part of the change, so it is still put back.
	 *
	 * @param string $option Option.
	 * @param mixed  $before The value it replaced (null: not known, e.g. the option was deleted).
	 * @param mixed  $after  The new value (false: deleted).
	 */
	public static function window_note( $option, $before, $after ) {
		if ( is_multisite() && self::network_mode() ) {
			self::ensure_site_snapshot(); // A site whose snapshot is taken on its first request.
		}
		$snap = self::snapshot();
		if ( null === $snap || ! array_key_exists( (string) $option, $snap['values'] ) ) {
			return;
		}
		$record = self::window_record( true );
		if ( null === $record ) {
			return;
		}
		$option = (string) $option;
		$base   = array_key_exists( $option, $record['values'] ) ? $record['values'][ $option ] : $snap['values'][ $option ];

		$record['values'][ $option ] = self::merge_change( $base, $before, $after );
		self::save_window( $record );
	}

	/**
	 * Multisite: the same for a network option (see window_note()), against the snapshot of the network.
	 *
	 * @param string $option Network option.
	 * @param mixed  $before The value it replaced (null: not known).
	 * @param mixed  $after  The new value (false: deleted).
	 */
	public static function window_note_network( $option, $before, $after ) {
		$net = is_multisite() ? self::net_snapshot() : null;
		if ( null === $net || ! array_key_exists( (string) $option, $net['values'] ) ) {
			return;
		}
		$record = self::window_record( true, true );
		if ( null === $record ) {
			return;
		}
		$option = (string) $option;
		$base   = array_key_exists( $option, $record['values'] ) ? $record['values'][ $option ] : $net['values'][ $option ];

		$record['values'][ $option ] = self::merge_change( $base, $before, $after );
		self::save_window( $record, true );
	}

	/**
	 * Notes that the administrator who unlocked changed the role of an account meanwhile: 2 = it can administer
	 * the site now (and could not before this change), 1 = staff, 0 = neither. Only an account noted with 2 is
	 * added to the administrators of the snapshot when the site locks again by itself.
	 *
	 * @param int $user_id User.
	 * @param int $kind    2, 1 or 0.
	 */
	public static function window_note_user( $user_id, $kind ) {
		if ( null === self::snapshot() ) {
			return;
		}
		$record = self::window_record( true );
		if ( null === $record ) {
			return;
		}
		$record['users'][ (int) $user_id ] = (int) $kind;
		self::save_window( $record );
	}

	/**
	 * Applies one change (from $old to $new) to a value of the snapshot. Lists (such as the active plugins) are
	 * treated as sets: what the change added is added, what it removed is removed. Lists of settings (keys and
	 * values) are compared key by key, at every level: only the keys the change touched take the new value.
	 * Anything else (text, numbers, a value of another kind) takes the new value.
	 *
	 * @param mixed $base   The value of the snapshot (or as already changed during this unlock).
	 * @param mixed $before The value before the change.
	 * @param mixed $after  The value after it.
	 * @return mixed
	 */
	private static function merge_change( $base, $before, $after ) {
		if ( $before === $after ) {
			return $base;
		}
		if ( ! is_array( $base ) || ! is_array( $before ) || ! is_array( $after ) ) {
			return $after;
		}
		if ( self::is_list( $before ) && self::is_list( $after ) && self::is_list( $base ) && self::scalars( $before ) && self::scalars( $after ) && self::scalars( $base ) ) {
			$added   = array_diff( $after, $before );
			$removed = array_diff( $before, $after );
			$out     = array_values( array_diff( $base, $removed ) );
			foreach ( $added as $item ) {
				if ( ! in_array( $item, $out, true ) ) {
					$out[] = $item;
				}
			}
			$sorted = $after;
			sort( $sorted );
			if ( $sorted === $after ) {
				sort( $out ); // WordPress keeps the active plugins sorted.
			}
			return $out;
		}
		$out = $base;
		foreach ( array_keys( $before + $after ) as $key ) {
			if ( ! array_key_exists( $key, $after ) ) {
				unset( $out[ $key ] );
			} elseif ( ! array_key_exists( $key, $before ) || ! array_key_exists( $key, $base ) ) {
				if ( ! array_key_exists( $key, $before ) || $before[ $key ] !== $after[ $key ] ) {
					$out[ $key ] = $after[ $key ];
				}
			} elseif ( $before[ $key ] !== $after[ $key ] ) {
				$out[ $key ] = self::merge_change( $base[ $key ], $before[ $key ], $after[ $key ] );
			}
		}
		return $out;
	}

	/**
	 * Is it a plain list (keys 0, 1, 2…)? The empty array counts as one.
	 *
	 * @param array<mixed> $value Value.
	 * @return bool
	 */
	private static function is_list( $value ) {
		$i = 0;
		foreach ( array_keys( $value ) as $key ) {
			if ( $key !== $i++ ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Does the list hold only text and numbers?
	 *
	 * @param array<mixed> $value Value.
	 * @return bool
	 */
	private static function scalars( $value ) {
		foreach ( $value as $item ) {
			if ( ! is_scalar( $item ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The signed record of the changes made during the current unlock, or null: missing, not matching its
	 * signature, or from another unlock (each one has its own lock time, end time and snapshot). With $fresh, an
	 * empty record for the current unlock instead of null (null only when the site is not unlocked for a while
	 * now, or the state cannot be trusted).
	 *
	 * @param bool $fresh   An empty record when there is none for this unlock.
	 * @param bool $network Multisite: the record of the network options (NET_WINDOW) instead of this site's.
	 * @return array{since:int, until:int, snap:int, values:array<string, mixed>, users:array<int, int>}|null
	 */
	private static function window_record( $fresh = false, $network = false ) {
		if ( '' !== PNCP_Lockdown::tampered() ) {
			return null;
		}
		$state = PNCP_Lockdown::state();
		if ( empty( $state['locked'] ) || (int) $state['until'] <= 0 ) {
			return null;
		}
		$id = array(
			'since' => (int) $state['since'],
			'until' => (int) $state['until'],
			'snap'  => (int) $state['snap'],
		);
		// Read from the database, not from this request's cache: another request of the same session may have
		// noted a change a moment ago.
		if ( $network ) {
			wp_cache_delete( get_current_network_id() . ':' . self::NET_WINDOW, 'site-options' );
			$stored = get_site_option( self::NET_WINDOW );
		} else {
			wp_cache_delete( self::WINDOW, 'options' );
			$stored = get_option( self::WINDOW );
		}
		if ( is_array( $stored ) && isset( $stored['sig'], $stored['values'], $stored['users'] ) && is_array( $stored['values'] ) && is_array( $stored['users'] ) ) {
			$sig = $stored['sig'];
			unset( $stored['sig'] );
			if ( self::valid( $stored, $sig ) && isset( $stored['since'], $stored['until'], $stored['snap'] ) && (int) $stored['since'] === $id['since'] && (int) $stored['until'] === $id['until'] && (int) $stored['snap'] === $id['snap'] ) {
				return $stored;
			}
		}
		return $fresh ? $id + array(
			'values' => array(),
			'users'  => array(),
		) : null;
	}

	/**
	 * Signs and stores the record of the changes made during the current unlock (not autoloaded).
	 *
	 * @param array<string, mixed> $record  Record.
	 * @param bool                 $network Multisite: the record of the network options.
	 */
	private static function save_window( $record, $network = false ) {
		unset( $record['sig'] );
		$record['sig'] = self::sign( $record );
		if ( $network ) {
			update_site_option( self::NET_WINDOW, $record );
		} elseif ( false === get_option( self::WINDOW, false ) ) {
			add_option( self::WINDOW, $record, '', false );
		} else {
			update_option( self::WINDOW, $record, false );
		}
	}

	/**
	 * Forgets the changes noted during an unlock (locked again, unlocked for good, a new unlock, the app removed).
	 */
	public static function forget_window() {
		delete_option( self::WINDOW );
		if ( ! is_multisite() ) {
			return;
		}
		// Multisite: the changes were noted on each site where they were made, and for the network.
		delete_site_option( self::NET_WINDOW );
		foreach ( self::network_site_ids() as $id ) {
			if ( get_current_blog_id() !== $id ) {
				delete_blog_option( $id, self::WINDOW );
			}
		}
	}

	/**
	 * The names of the protected options changed during the current unlock, and the number of accounts that were
	 * made administrators (for the notice while it is open).
	 *
	 * @return array{options:string[], admins:int}
	 */
	public static function window_summary() {
		$record  = self::window_record();
		$network = is_multisite() ? self::window_record( false, true ) : null;
		$options = null !== $record ? array_keys( $record['values'] ) : array();
		if ( null !== $network ) {
			// Multisite: the network options too (only this site's own options are listed).
			$options = array_merge( $options, array_keys( $network['values'] ) );
		}
		$admins = 0;
		foreach ( null !== $record ? $record['users'] : array() as $kind ) {
			$admins += 2 === (int) $kind ? 1 : 0;
		}
		return array(
			'options' => array_values( array_unique( $options ) ),
			'admins'  => $admins,
		);
	}

	/**
	 * The snapshot that counts now. Normally the signed snapshot of the lock. When an unlock for a while has
	 * just ended and the snapshot was not taken again yet (PNCP_Lockdown::reseal_pending()), the signed
	 * snapshot with the changes noted during the unlock applied: the same values accept_window() will sign, so
	 * a request in between neither puts back the owner's changes nor accepts anything else.
	 *
	 * @return array{time:int, values:array<string, mixed>, admins:int[]}|null
	 */
	public static function current_snapshot() {
		$snap = self::snapshot();
		if ( null === $snap || ! PNCP_Lockdown::reseal_pending() ) {
			return $snap;
		}
		$record = self::window_record();
		if ( null === $record ) {
			return $snap;
		}
		foreach ( $record['values'] as $option => $value ) {
			if ( array_key_exists( (string) $option, $snap['values'] ) ) {
				$snap['values'][ (string) $option ] = $value;
			}
		}
		$users = array();
		foreach ( $record['users'] as $id => $kind ) {
			if ( (int) $kind > 0 ) {
				$users[ (int) $id ] = (int) $kind;
			}
		}
		if ( $users ) {
			// Only accounts the owner made administrators that still are: never an account that was given the
			// rights in the database (also not one the owner only edited, see PNCP_Lockdown::note_role()).
			$added = array();
			foreach ( $users as $id => $kind ) {
				if ( 2 === $kind ) {
					$added[] = $id;
				}
			}
			$admins         = array_intersect( $added, self::admin_ids() );
			$snap['admins'] = array_values( array_unique( array_map( 'intval', array_merge( $snap['admins'], $admins ) ) ) );
			sort( $snap['admins'] );
			if ( isset( $snap['apps'] ) && is_array( $snap['apps'] ) ) {
				// Accounts that became staff during the unlock keep the application passwords they had (staff cannot
				// add any while unlocked for a while), instead of the hourly check removing them as planted.
				foreach ( array_keys( $users ) as $id ) {
					if ( ! isset( $snap['apps'][ $id ] ) && PNCP_Lockdown::is_staff( $id ) ) {
						$uuids = array();
						foreach ( WP_Application_Passwords::get_user_application_passwords( $id ) as $item ) {
							if ( isset( $item['uuid'] ) ) {
								$uuids[] = (string) $item['uuid'];
							}
						}
						sort( $uuids );
						$snap['apps'][ $id ] = $uuids;
					}
				}
				ksort( $snap['apps'] );
			}
		}
		return $snap;
	}

	/**
	 * An unlock for a while has ended: signs the snapshot again with the changes the owner made through
	 * WordPress during it (current_snapshot()), and the administrators they added. Values changed any other way
	 * (directly in the database, during the unlock or at any other time) are not taken over: they are put back
	 * from it as usual (verify_options()). Run by PNCP_Lockdown::expire_window(), one request at a time.
	 *
	 * The caller notes the generation in the state (with the end of the unlock, in one write: a request in
	 * between then sees the state at most one generation behind the guard, which it waits for).
	 *
	 * @return int The generation of the new snapshot (0: none was signed, there is no genuine snapshot).
	 */
	public static function accept_window() {
		if ( is_multisite() && self::network_mode() ) {
			return self::accept_network_window();
		}
		$snap = self::current_snapshot();
		if ( null === $snap ) {
			return 0;
		}
		return self::store_snapshot( $snap['values'], $snap['admins'], isset( $snap['since'] ) ? (int) $snap['since'] : null, isset( $snap['apps'] ) ? $snap['apps'] : null, false, isset( $snap['pass'] ) ? $snap['pass'] : null );
	}

	/**
	 * Multisite: accept_window() for the whole network. Every site where the owner changed something during the
	 * unlock gets its snapshot again with those changes (the other sites keep theirs), and the snapshot of the
	 * network gets the changes to the network options, with one new generation for all of them.
	 *
	 * @return int The generation of the new snapshot of the network (0: there is no genuine one).
	 */
	private static function accept_network_window() {
		$net = self::current_network_snapshot();
		if ( null === $net ) {
			return 0;
		}
		$gen = PNCP_Lockdown::next_generation();
		foreach ( array_map( 'intval', array_keys( $net['sites'] ) ) as $id ) {
			switch_to_blog( $id );
			try {
				if ( null === self::window_record() ) {
					continue; // Nothing changed on this site.
				}
				$snap = self::current_snapshot();
				if ( null === $snap ) {
					continue;
				}
				self::write_site_snapshot( $snap['values'], $snap['admins'], (int) $net['since'], $gen, isset( $snap['apps'] ) ? $snap['apps'] : null );
				$net['sites'][ $id ] = self::site_entry( $snap['values'], $snap['admins'], $gen, true, isset( $net['sites'][ $id ]['guard'] ) );
			} finally {
				restore_current_blog();
			}
		}
		$net['gen']  = $gen;
		$net['time'] = time();
		self::store_network( $net );
		return $gen;
	}

	/**
	 * While locked: puts back any protected option that changed behind WordPress's back (WordPress itself
	 * cannot change them while locked), and reports it.
	 */
	public static function verify_options() {
		if ( is_multisite() && ( PNCP_Lockdown::is_locked() || PNCP_Lockdown::unlocked_until() ) && self::network_mode() && ! self::verify_site_of_network() ) {
			return;
		}
		if ( ! PNCP_Lockdown::is_locked() ) {
			return;
		}
		if ( PNCP_Lockdown::reseal_pending() ) {
			// 3.4: an unlock for a while has just ended and the snapshot could not be taken again yet (another
			// request is doing it): compared with the snapshot as it will be, the owner's changes included.
			$snap = self::current_snapshot();
			if ( null !== $snap ) {
				self::restore( $snap );
				return;
			}
		}
		// The quick way, on every request: the autoloaded fingerprints against the options (also autoloaded).
		// The snapshot itself is read only when something differs, or when there are no fingerprints yet.
		// The fingerprints cover the same options as the snapshot they were made with (an option added to the
		// protected list by a later version is in neither until the next lock), so they are enough on their own.
		$digests = self::digests();
		if ( null !== $digests ) {
			$same = true;
			foreach ( $digests as $option => $digest ) {
				if ( self::digest( self::stored_option( (string) $option ) ) !== $digest ) {
					$same = false;
					break;
				}
			}
			if ( $same ) {
				return;
			}
		}
		$snap = self::snapshot();
		if ( null === $snap && is_multisite() && self::network_mode() ) {
			// Multisite: taken again from the values that still match the snapshot of the network (and reported).
			self::ensure_site_snapshot();
			$snap = self::snapshot();
		}
		if ( null === $snap ) {
			$record = self::snapshot_record();
			if ( self::snapshot_pending( $record ) ) {
				// 3.4: the owner has just locked the site and the request that locks it is still taking the
				// snapshot (a visitor, or the background request it started, came in between): not an alarm.
				return;
			}
			if ( null !== $record ) {
				// Genuine, but from an older lock or before a later change: put back from a copy of the database.
				// Nothing can be put back from it; the guard still keeps the plugins and the theme.
				PNCP_Lockdown::tamper_alert( 'replay', 'snapshot' );
			} elseif ( false !== get_option( self::SNAP, false ) || ( ! is_multisite() && ! self::legacy() ) ) {
				// Multisite, a network locked before 3.4: only the site where it was locked has a snapshot. The other
				// sites have none, which is not an alarm (the Lockdown tab says to lock again).
				PNCP_Lockdown::tamper_alert( 'snapshot' );
			}
			return;
		}
		if ( self::$from_copy ) {
			// 3.4: the snapshot in the database was deleted, changed or set back to an older one: put back from the
			// copy in the guard file (signed, so nothing is signed again), then the settings from it as usual.
			self::$from_copy = false;
			$copy            = $snap;
			$copy['sig']     = self::sign( $snap );
			update_option( self::SNAP, $copy, false );
			wp_cache_delete( self::SNAP, 'options' );
			PNCP_Lockdown::tamper_alert( 'snapshot_copy' );
		}
		self::restore( $snap );
		if ( null === $digests ) {
			$old = self::digests_record();
			if ( null !== $old && isset( $snap['gen'] ) ) {
				// Genuine fingerprints of an older snapshot: put back from a copy of the database.
				PNCP_Lockdown::tamper_alert( 'replay', 'digests' );
			}
			// A snapshot from before 3.3.2, or fingerprints from an older snapshot: the fingerprints of this one
			// (from the signed snapshot, never from the options as they are now).
			self::save_digests( $snap['values'], isset( $snap['since'] ) ? (int) $snap['since'] : (int) PNCP_Lockdown::state()['since'], isset( $snap['gen'] ) ? (int) $snap['gen'] : 0 );
		}
	}

	/**
	 * Multisite, a network locked with 3.4 or later, while locked or unlocked for a while: checks the network
	 * options (while locked), and makes sure this site has its own snapshot (taken on its first request when it
	 * was not taken at once).
	 *
	 * @return bool Whether this site's own snapshot is to be checked next (false: the lock does not cover it).
	 */
	private static function verify_site_of_network() {
		$net = PNCP_Lockdown::is_locked() ? self::verify_network() : self::net_digests();
		if ( null === $net ) {
			return true; // Reported: each site still checks its own snapshot.
		}
		if ( ! isset( $net['sites'][ get_current_blog_id() ] ) ) {
			return false; // Added after the lock, or ScrapeLock was not active here: nothing to compare with.
		}
		$record = self::digests_record( true );
		if ( null === $record || ! empty( $record['lazy'] ) ) {
			self::ensure_site_snapshot();
		}
		return true;
	}

	/**
	 * Puts back the protected options that differ from a snapshot, and reports them.
	 *
	 * @param array{values:array<string, mixed>} $snap Snapshot.
	 */
	private static function restore( $snap ) {
		$restored = array();
		foreach ( $snap['values'] as $option => $value ) {
			if ( self::digest( self::stored_option( (string) $option ) ) !== self::digest( $value ) ) {
				PNCP_Lockdown::write_protected( (string) $option, $value );
				$restored[] = (string) $option;
			}
		}
		if ( $restored ) {
			$where = is_multisite() ? self::site_label( get_current_blog_id() ) . ': ' : '';
			PNCP_Lockdown::tamper_alert( 'options', $where . implode( ', ', $restored ) );
		}
	}

	/**
	 * The hourly check while locked: accounts that can administer the site now but could not when it was
	 * locked (rights given behind WordPress's back) are reported.
	 *
	 * @param bool $report Report them (false: only list them, for the warning when the owner unlocks).
	 * @return string[] The accounts found (at most 10).
	 */
	public static function check_admins( $report = true ) {
		if ( is_multisite() ) {
			return self::check_network_admins( $report );
		}
		$snap = self::current_snapshot();
		if ( null === $snap ) {
			return array();
		}
		$new = array_diff( self::admin_ids(), $snap['admins'] );
		if ( ! $new ) {
			return array();
		}
		$logins = array();
		foreach ( array_slice( $new, 0, 10 ) as $id ) {
			$user     = get_userdata( (int) $id );
			$logins[] = $user ? $user->user_login . ' (#' . (int) $id . ')' : '#' . (int) $id;
		}
		if ( $report ) {
			PNCP_Lockdown::tamper_alert( 'admin', implode( ', ', $logins ) );
		}
		return $logins;
	}

	/**
	 * Multisite: check_admins() for the network. Super admins who were not super admins when the network was
	 * locked, and on each site accounts that can administer it but could not then, are reported. On the main
	 * site every site the lock covers is checked, on the others only the site itself. Nothing for a network
	 * locked before 3.4 (it has no snapshot of the network).
	 *
	 * @param bool $report See check_admins().
	 * @return string[]
	 */
	private static function check_network_admins( $report = true ) {
		if ( ! self::network_mode() ) {
			return array();
		}
		$net = self::current_network_snapshot();
		if ( null === $net ) {
			return array();
		}
		$found = array();
		foreach ( array_diff( self::super_ids(), array_map( 'intval', (array) $net['super'] ) ) as $id ) {
			$found[] = 'super admin ' . self::user_label( $id );
		}
		$ids = is_main_site() ? array_map( 'intval', array_keys( $net['sites'] ) ) : array( get_current_blog_id() );
		foreach ( $ids as $id ) {
			if ( ! isset( $net['sites'][ $id ] ) ) {
				continue;
			}
			switch_to_blog( $id );
			try {
				$known = self::site_admins_known( $net['sites'][ $id ] );
				foreach ( array_diff( self::admin_ids(), $known ) as $user ) {
					$found[] = self::site_label( $id ) . ' ' . self::user_label( $user );
				}
			} finally {
				restore_current_blog();
			}
		}
		$found = array_slice( $found, 0, 10 );
		if ( $found && $report ) {
			PNCP_Lockdown::tamper_alert( 'admin', implode( ', ', $found ) );
		}
		return $found;
	}

	/**
	 * Multisite, in the site being checked: the accounts that could administer it when the network was locked
	 * (from its own snapshot, which also has the ones the owner added during an unlock for a while that has just
	 * ended, or else from the snapshot of the network).
	 *
	 * @param array<string, mixed> $entry The site's entry in the snapshot of the network.
	 * @return int[]
	 */
	private static function site_admins_known( $entry ) {
		$snap = self::current_snapshot();
		return array_map( 'intval', null !== $snap ? $snap['admins'] : ( isset( $entry['admins'] ) ? (array) $entry['admins'] : array() ) );
	}

	/**
	 * Multisite: authenticate() for the network. A user is refused when they are a super admin but were not when
	 * the network was locked, or when they can administer a site the lock covers but could not then (their
	 * rights were given behind WordPress's back). Every site the user belongs to is looked at, not only the one
	 * they sign in on: the login cookie works for the whole network.
	 *
	 * @param WP_User $user User.
	 * @return WP_User|WP_Error
	 */
	private static function authenticate_network( $user ) {
		if ( ! self::network_mode() ) {
			return $user; // A network locked before 3.4 (see the notice on the Lockdown tab).
		}
		$net = self::current_network_snapshot();
		if ( null === $net ) {
			return $user; // Reported by verify_network().
		}
		$id    = (int) $user->ID;
		$where = '';
		if ( is_super_admin( $id ) && ! in_array( $id, array_map( 'intval', (array) $net['super'] ), true ) ) {
			$where = 'network';
		}
		foreach ( '' === $where ? array_map( 'intval', array_keys( get_blogs_of_user( $id, true ) ) ) : array() as $blog ) {
			if ( ! isset( $net['sites'][ $blog ] ) ) {
				continue;
			}
			switch_to_blog( $blog );
			try {
				if ( ! in_array( $id, self::site_admins_known( $net['sites'][ $blog ] ), true ) && PNCP_Lockdown::can_administer( $id ) ) {
					$where = self::site_label( $blog );
				}
			} finally {
				restore_current_blog();
			}
			if ( '' !== $where ) {
				break;
			}
		}
		if ( '' === $where ) {
			return $user;
		}
		PNCP_Lockdown::tamper_alert( 'admin', $user->user_login . ' (' . $where . ')' );
		return new WP_Error( 'pncp_locked', __( 'This account cannot sign in while the site is locked: it was given administrator rights after the site was locked.', 'scrapelock' ) );
	}

	/**
	 * While locked: an account that can administer the site but did not when the site was locked cannot
	 * sign in (its rights were given behind WordPress's back: WordPress itself refuses that while locked).
	 *
	 * @param WP_User|WP_Error|null $user User so far.
	 * @return WP_User|WP_Error|null
	 */
	public static function authenticate( $user ) {
		if ( ! $user instanceof WP_User || ! PNCP_Lockdown::is_locked() ) {
			return $user;
		}
		if ( is_multisite() ) {
			return self::authenticate_network( $user );
		}
		if ( ! array_intersect( PNCP_Lockdown::control_caps(), array_keys( array_filter( (array) $user->allcaps ) ) ) ) {
			return $user;
		}
		$snap = self::current_snapshot();
		if ( null !== $snap && in_array( (int) $user->ID, $snap['admins'], true ) && ! self::password_ok( $snap, (int) $user->ID ) ) {
			// 3.4: the password hash was written in the database (WordPress itself refuses to change it while
			// locked, and a change through WordPress during an unlock is noted in the snapshot).
			PNCP_Lockdown::tamper_alert( 'login', $user->user_login );
			return new WP_Error( 'pncp_locked', __( 'This account cannot sign in while the site is locked: its password was changed after the site was locked.', 'scrapelock' ) );
		}
		if ( null === $snap || in_array( (int) $user->ID, $snap['admins'], true ) ) {
			return $user; // Without a valid snapshot there is nothing to compare with (reported by verify_options()).
		}
		PNCP_Lockdown::tamper_alert( 'admin', $user->user_login );
		return new WP_Error( 'pncp_locked', __( 'This account cannot sign in while the site is locked: it was given administrator rights after the site was locked.', 'scrapelock' ) );
	}
}
