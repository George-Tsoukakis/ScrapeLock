<?php
/**
 * Lockdown seal: keeps the lock honest against someone who can write to the database directly (for example
 * through SQL injection in another plugin) but not to the files.
 *
 * - The lock state and the file fingerprint are signed (HMAC) with a key derived from the keys in
 *   wp-config.php, which are not in the database. A changed or forged value no longer matches its signature.
 * - A small must-use plugin (the "guard") holds a signed copy of "locked / until when". It is a file, so
 *   deleting or replacing the state in the database cannot unlock the site, and the guard keeps ScrapeLock
 *   loaded if its line is removed from the list of active plugins.
 * - When the site is locked, the protected options are saved (signed) and put back if they change behind
 *   WordPress's back, and the accounts that could administer the site are noted: another account that gains
 *   such rights while locked cannot sign in.
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
	 * The guard (must-use plugin).
	 */
	const FILE   = 'scrapelock-lockdown-guard.php';
	const MARKER = 'ScrapeLock Lockdown guard';

	/**
	 * The guard's record as written on this request (the constant from the guard file is from the start of
	 * the request).
	 *
	 * @var array{locked:bool, until:int}|null
	 */
	private static $current = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		// Early: right after the plugins have loaded, before themes, REST and the admin.
		add_action( 'plugins_loaded', array( __CLASS__, 'verify_options' ), 1 );
		add_filter( 'authenticate', array( __CLASS__, 'authenticate' ), 100 );
	}

	/* ---------- Signatures ---------- */

	/**
	 * The signing key: from the keys in wp-config.php (AUTH_KEY / AUTH_SALT), never stored.
	 *
	 * @return string
	 */
	private static function key() {
		return hash( 'sha256', wp_salt( 'auth' ) . '|pncp_lockdown_sig', true );
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
	 * @return bool
	 */
	public static function legacy() {
		$from = (string) get_option( 'pncp_version', '' );
		return '' !== $from && version_compare( $from, '3.3.0', '<' );
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
		return trailingslashit( WPMU_PLUGIN_DIR ) . self::FILE;
	}

	/**
	 * The guard's signed record, as the guard file defined it on this request: [locked, until], or null when
	 * there is no guard (or it does not match the keys in wp-config.php).
	 *
	 * @return array{locked:bool, until:int}|null
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
		$record = array(
			'locked' => (bool) $data['locked'],
			'until'  => (int) $data['until'],
		);
		return self::valid( $record, $data['sig'] ) ? $record : null;
	}

	/**
	 * The guard's code: the signed record, and, while locked, ScrapeLock kept in the list of active plugins.
	 *
	 * @param bool $locked Locked.
	 * @param int  $until  Unlocked for a while until (0 = not).
	 * @return string
	 */
	public static function code( $locked, $until ) {
		$record = array(
			'locked' => (bool) $locked,
			'until'  => (int) $until,
		);
		$json   = (string) wp_json_encode( array_merge( $record, array( 'sig' => self::sign( $record ) ) ) );
		$base   = plugin_basename( PNCP_FILE );
		return "<?php\n"
			. "/**\n"
			. ' * Plugin Name: ' . self::MARKER . "\n"
			. " * Description: Created by ScrapeLock while the site is locked with Lockdown. It keeps a signed copy of the lock outside the database and keeps ScrapeLock active. It is removed when the lock is turned off or ScrapeLock is deactivated.\n"
			. " *\n"
			. " * @package ScrapeLock\n"
			. " */\n\n"
			. "defined( 'ABSPATH' ) || exit;\n\n"
			. "defined( 'PNCP_LOCKDOWN_BEACON' ) || define( 'PNCP_LOCKDOWN_BEACON', " . var_export( $json, true ) . " );\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the record as PHP code.
			. ( $locked ? 'if ( time() >= ' . (int) $until . " && ! ( defined( 'SCRAPELOCK_UNLOCK' ) && true === SCRAPELOCK_UNLOCK ) && ! is_multisite() && is_readable( " . var_export( PNCP_FILE, true ) . " ) ) {\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the path as PHP code.
				. "\tadd_filter(\n"
				. "\t\t'option_active_plugins',\n"
				. "\t\tstatic function ( \$plugins ) {\n"
				. "\t\t\t\$plugins = is_array( \$plugins ) ? \$plugins : array();\n"
				. "\t\t\tif ( ! in_array( " . var_export( $base, true ) . ", \$plugins, true ) ) {\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the basename as PHP code.
				. "\t\t\t\t\$plugins[] = " . var_export( $base, true ) . ";\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes the basename as PHP code.
				. "\t\t\t}\n"
				. "\t\t\treturn \$plugins;\n"
				. "\t\t},\n"
				. "\t\t1\n"
				. "\t);\n"
				. "}\n" : '' );
	}

	/**
	 * Writes the guard for this state (removes it when not locked). Only with direct file access; without it
	 * the lock works as before, without the copy outside the database.
	 *
	 * @param bool $locked Locked.
	 * @param int  $until  Until.
	 * @return bool Whether the guard is now as it should be.
	 */
	public static function write_guard( $locked, $until ) {
		if ( ! $locked ) {
			self::remove_guard();
			$ok = ! file_exists( self::path() );
			if ( $ok ) {
				self::$current = array(
					'locked' => false,
					'until'  => 0,
				);
			}
			return $ok;
		}
		$path   = self::path();
		$code   = self::code( $locked, $until );
		$record = array(
			'locked' => true,
			'until'  => (int) $until,
		);
		if ( is_readable( $path ) && (string) file_get_contents( $path ) === $code ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			self::$current = $record;
			return true;
		}
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return false;
		}
		$dir = trailingslashit( WPMU_PLUGIN_DIR );
		if ( ! $filesystem->is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		if ( $filesystem->exists( $path ) && ! self::ours( $path ) ) {
			return false; // Someone else's file with the same name: never overwritten.
		}
		$ok = $filesystem->put_contents( $path, $code, FS_CHMOD_FILE );
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $path, true );
		}
		if ( $ok ) {
			self::$current = $record;
		}
		return (bool) $ok;
	}

	/**
	 * Removes the guard, only if it is ours.
	 */
	public static function remove_guard() {
		$path = self::path();
		if ( file_exists( $path ) && self::ours( $path ) ) {
			wp_delete_file( $path );
			if ( function_exists( 'opcache_invalidate' ) ) {
				opcache_invalidate( $path, true );
			}
		}
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
		if ( 'direct' !== get_filesystem_method( array(), WPMU_PLUGIN_DIR ) || ! WP_Filesystem() ) {
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
	 * Takes the snapshot when the site is locked (and after a change ScrapeLock itself makes while locked,
	 * e.g. the quarantine). Signed.
	 */
	public static function take_snapshot() {
		$values = array();
		foreach ( PNCP_Lockdown::sealed_options() as $option ) {
			$values[ $option ] = get_option( $option );
		}
		$snap        = array(
			'time'   => time(),
			'values' => $values,
			'admins' => self::admin_ids(),
		);
		$snap['sig'] = self::sign( $snap );
		update_option( self::SNAP, $snap, false );
		wp_cache_delete( self::SNAP, 'options' );
	}

	/**
	 * The snapshot, if its signature matches: [time, values, admins], or null.
	 *
	 * @return array{time:int, values:array<string, mixed>, admins:int[]}|null
	 */
	public static function snapshot() {
		$snap = get_option( self::SNAP );
		if ( ! is_array( $snap ) || ! isset( $snap['sig'], $snap['values'], $snap['admins'], $snap['time'] ) ) {
			return null;
		}
		$sig = $snap['sig'];
		unset( $snap['sig'] );
		return self::valid( $snap, $sig ) && is_array( $snap['values'] ) && is_array( $snap['admins'] ) ? $snap : null;
	}

	/**
	 * While locked: puts back any protected option that changed behind WordPress's back (WordPress itself
	 * cannot change them while locked), and reports it.
	 */
	public static function verify_options() {
		if ( ! PNCP_Lockdown::is_locked() ) {
			return;
		}
		$snap = self::snapshot();
		if ( null === $snap ) {
			if ( false !== get_option( self::SNAP, false ) || ! self::legacy() ) {
				PNCP_Lockdown::tamper_alert( 'snapshot' );
			}
			return;
		}
		$restored = array();
		foreach ( $snap['values'] as $option => $value ) {
			if ( self::digest( get_option( (string) $option ) ) !== self::digest( $value ) ) {
				PNCP_Lockdown::write_protected( (string) $option, $value );
				$restored[] = (string) $option;
			}
		}
		if ( $restored ) {
			PNCP_Lockdown::tamper_alert( 'options', implode( ', ', $restored ) );
		}
	}

	/**
	 * The hourly check while locked: accounts that can administer the site now but could not when it was
	 * locked (rights given behind WordPress's back) are reported.
	 */
	public static function check_admins() {
		$snap = self::snapshot();
		if ( null === $snap || is_multisite() ) {
			return;
		}
		$new = array_diff( self::admin_ids(), $snap['admins'] );
		if ( ! $new ) {
			return;
		}
		$logins = array();
		foreach ( array_slice( $new, 0, 10 ) as $id ) {
			$user     = get_userdata( (int) $id );
			$logins[] = $user ? $user->user_login . ' (#' . (int) $id . ')' : '#' . (int) $id;
		}
		PNCP_Lockdown::tamper_alert( 'admin', implode( ', ', $logins ) );
	}

	/**
	 * While locked: an account that can administer the site but did not when the site was locked cannot
	 * sign in (its rights were given behind WordPress's back: WordPress itself refuses that while locked).
	 *
	 * @param WP_User|WP_Error|null $user User so far.
	 * @return WP_User|WP_Error|null
	 */
	public static function authenticate( $user ) {
		if ( ! $user instanceof WP_User || is_multisite() || ! PNCP_Lockdown::is_locked() ) {
			return $user;
		}
		if ( ! array_intersect( PNCP_Lockdown::control_caps(), array_keys( array_filter( (array) $user->allcaps ) ) ) ) {
			return $user;
		}
		$snap = self::snapshot();
		if ( null === $snap || in_array( (int) $user->ID, $snap['admins'], true ) ) {
			return $user; // Without a valid snapshot there is nothing to compare with (reported by verify_options()).
		}
		PNCP_Lockdown::tamper_alert( 'admin', $user->user_login );
		return new WP_Error( 'pncp_locked', __( 'This account cannot sign in while the site is locked: it was given administrator rights after the site was locked.', 'scrapelock' ) );
	}
}
