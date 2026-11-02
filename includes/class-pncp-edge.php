<?php
/**
 * Blocking at the CDN: the IPs ScrapeLock bans are also blocked by Cloudflare or Bunny CDN, with the site
 * owner's own account. A scraper that keeps going is then stopped at the edge, before its requests reach the
 * server (no PHP, no database). Each block is removed when the ban ends.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Keeps the CDN's block list in step with the active bans: adds the new ones, removes the ones that ended.
 * Runs from cron, never while a visitor waits.
 */
final class PNCP_Edge {

	/**
	 * Provider, zone and token (protected while the site is locked).
	 */
	const CONFIG = 'pncp_edge';

	/**
	 * What is blocked at the CDN now, the last run and the last error.
	 */
	const STATE = 'pncp_edge_state';

	/**
	 * Blocks of a previous configuration (another zone or provider, or turned off) still to be removed.
	 */
	const RETIRE = 'pncp_edge_retire';

	/**
	 * Recent IPs of administrators: never blocked at the CDN, where a block also covers wp-admin.
	 */
	const STAFF = 'pncp_edge_staff';

	const CRON = 'pncp_edge_sync';

	/**
	 * The lock of a run: a row in wp_options that holds the time it ends. Taken with one atomic UPDATE, so two
	 * runs can never both hold it (a transient can be read as free by two requests at once).
	 */
	const LOCK = 'pncp_edge_lock';

	/**
	 * Changes since the last run (bans added or lifted, settings saved): a value that changes every time.
	 * A run that sees it change while it works schedules another run, so no change is lost.
	 */
	const DIRTY = 'pncp_edge_dirty';

	/**
	 * API calls per run, so a run stays short and well inside the providers' rate limits.
	 */
	const BATCH = 25;

	/**
	 * Seconds a run may start new API calls. With the 10-second timeout of one call, a run ends within about
	 * 30 seconds; the lock lasts much longer than that (LOCK_TTL), so it never expires during a run.
	 */
	const BUDGET = 20;

	/**
	 * Seconds the lock is held at most, if a run dies without releasing it.
	 */
	const LOCK_TTL = 300;

	/**
	 * Removals the CDN refuses (other than "not found") are tried this many times before they are given up
	 * and listed on the settings page, to be removed by hand.
	 */
	const TRIES = 3;

	/**
	 * The lock value of this request while it holds the lock.
	 *
	 * @var string
	 */
	private static $lock = '';

	const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';
	const BUNNY_API      = 'https://api.bunny.net';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'sync' ) );
		add_action( 'pncp_bans_changed', array( __CLASS__, 'soon' ) );
		// Protection turned off or on, or the real-IP setting changed: the blocks follow.
		add_action( 'update_option_' . PNCP_OPTION, array( __CLASS__, 'soon' ) );
		add_action( 'admin_init', array( __CLASS__, 'remember_staff' ) );
		// Administrators who stopped opening wp-admin: their IPs go after 30 days all the same.
		add_action( PNCP_Log::CRON, array( __CLASS__, 'prune_staff' ) );
	}

	/* ---------- Configuration ---------- */

	/**
	 * The supported CDNs.
	 *
	 * @return array<string, string>
	 */
	public static function providers() {
		return array(
			'cloudflare' => 'Cloudflare',
			'bunny'      => 'Bunny CDN',
		);
	}

	/**
	 * The stored configuration. The token can also come from wp-config.php (SCRAPELOCK_EDGE_TOKEN), which
	 * keeps it out of the database.
	 *
	 * @return array{provider:string, zone:string, token:string}
	 */
	public static function config() {
		$c     = get_option( self::CONFIG, array() );
		$c     = is_array( $c ) ? $c : array();
		$token = self::token_from_config() ? (string) SCRAPELOCK_EDGE_TOKEN : ( isset( $c['token'] ) ? (string) $c['token'] : '' );
		return array(
			'provider' => isset( $c['provider'] ) && isset( self::providers()[ $c['provider'] ] ) ? (string) $c['provider'] : '',
			'zone'     => isset( $c['zone'] ) ? (string) $c['zone'] : '',
			'token'    => self::clean_token( $token ),
		);
	}

	/**
	 * Is the token set in wp-config.php?
	 *
	 * @return bool
	 */
	public static function token_from_config() {
		return defined( 'SCRAPELOCK_EDGE_TOKEN' ) && '' !== self::clean_token( (string) SCRAPELOCK_EDGE_TOKEN );
	}

	/**
	 * A zone ID as each provider writes it: Cloudflare 32 hexadecimal characters, Bunny a number.
	 *
	 * @param string $provider Provider.
	 * @param string $zone     Zone ID.
	 * @return string Empty if not valid.
	 */
	public static function clean_zone( $provider, $zone ) {
		$zone = strtolower( trim( (string) $zone ) );
		if ( 'cloudflare' === $provider ) {
			return preg_match( '/^[0-9a-f]{32}$/', $zone ) ? $zone : '';
		}
		if ( 'bunny' === $provider ) {
			return preg_match( '/^[0-9]{1,12}$/', $zone ) ? $zone : '';
		}
		return '';
	}

	/**
	 * A token or API key: letters, digits, "-" and "_" only.
	 *
	 * @param string $token Token.
	 * @return string
	 */
	public static function clean_token( $token ) {
		$token = trim( (string) $token );
		return preg_match( '/^[A-Za-z0-9_\-]{16,200}$/', $token ) ? $token : '';
	}

	/**
	 * Is everything filled in to talk to the CDN?
	 *
	 * @param array{provider:string, zone:string, token:string}|null $c Configuration (null = stored).
	 * @return bool
	 */
	public static function usable( $c = null ) {
		$c = null === $c ? self::config() : $c;
		return '' !== $c['provider'] && '' !== $c['zone'] && '' !== $c['token'];
	}

	/**
	 * Should the bans be blocked at the CDN now? Not while protection is off, and not while the real visitor
	 * IP is read from a header without checking the proxy: anyone could then put any address in that header,
	 * get it banned and so blocked at the CDN for everyone.
	 *
	 * @return bool
	 */
	public static function active() {
		$s = PNCP_Options::stored();
		return self::usable() && ! empty( $s['enabled'] ) && empty( $s['trust_any_proxy'] );
	}

	/**
	 * Saves a new configuration. The blocks made with the previous one (another zone or CDN, or turned off)
	 * are removed in the background, with the previous credentials.
	 *
	 * @param array{provider:string, zone:string, token:string} $config New configuration (token already resolved).
	 */
	public static function save_config( $config ) {
		$old = self::config();
		// A new token for the same zone manages the same blocks; another zone or CDN, or off, does not.
		if ( $old['provider'] !== $config['provider'] || $old['zone'] !== $config['zone'] ) {
			self::retire( $old );
		}
		$stored = array(
			'provider' => $config['provider'],
			'zone'     => $config['zone'],
			'token'    => self::token_from_config() ? '' : $config['token'],
		);
		if ( false === get_option( self::CONFIG, false ) ) {
			add_option( self::CONFIG, $stored, '', false );
		} else {
			update_option( self::CONFIG, $stored, false );
		}
		self::soon();
	}

	/**
	 * Moves the blocks made with a configuration to the removal queue, with what is needed to remove them, and
	 * empties the state. A token kept in wp-config.php is never copied into the database: the queue only notes
	 * that it comes from there, and it is read from wp-config.php again when the blocks are removed.
	 *
	 * @param array{provider:string, zone:string, token:string} $c Configuration the blocks were made with.
	 */
	private static function retire( $c ) {
		$state = self::state( true );
		$items = array();
		foreach ( $state['rules'] as $key => $rule ) {
			if ( ! empty( $rule['own'] ) ) {
				$items[ $key ] = $rule;
			}
		}
		if ( $items && self::usable( $c ) ) {
			self::queue_add( $c, $items );
		}
		$state['rules'] = array();
		$state['error'] = '';
		// No configuration owns the state now: a run still busy with the old one hands what it does next to the
		// removal queue (see commit_rule()).
		$state['owner'] = '';
		self::save_state( $state );
	}

	/**
	 * Adds blocks to the removal queue, as one entry with the credentials to remove them.
	 *
	 * @param array{provider:string, zone:string, token:string} $c     Configuration the blocks were made with.
	 * @param array<string, array<string, mixed>>               $items Ban key => block.
	 */
	private static function queue_add( $c, $items ) {
		$entry = array(
			'id'       => self::new_id(),
			'provider' => $c['provider'],
			'zone'     => $c['zone'],
			'items'    => $items,
		);
		if ( self::is_config_token( $c['token'] ) ) {
			$entry['token_source'] = 'config'; // Read from wp-config.php when needed, never stored.
		} else {
			$entry['token'] = $c['token'];
		}
		$queue   = self::retire_queue( true );
		$queue[] = $entry;
		self::save_queue( $queue );
	}

	/**
	 * Is this the token set in wp-config.php?
	 *
	 * @param string $token Token.
	 * @return bool
	 */
	private static function is_config_token( $token ) {
		return self::token_from_config() && '' !== (string) $token && hash_equals( self::clean_token( (string) SCRAPELOCK_EDGE_TOKEN ), (string) $token );
	}

	/**
	 * A short random ID for a queue entry, so a run can update its own entry while other requests add theirs.
	 *
	 * @return string
	 */
	private static function new_id() {
		return strtolower( wp_generate_password( 12, false, false ) );
	}

	/**
	 * Blocks still to be removed from previous configurations.
	 *
	 * @param bool $fresh Read from the database, not from what this request read before.
	 * @return array<int, array<string, mixed>>
	 */
	private static function retire_queue( $fresh = false ) {
		$queue = $fresh ? self::fresh_option( self::RETIRE ) : get_option( self::RETIRE, array() );
		return is_array( $queue ) ? array_values( $queue ) : array();
	}

	/**
	 * Saves the removal queue, or deletes it when it is empty.
	 *
	 * @param array<int, array<string, mixed>> $queue Queue.
	 */
	private static function save_queue( $queue ) {
		$queue = array_values( $queue );
		if ( ! $queue ) {
			delete_option( self::RETIRE );
		} elseif ( false === get_option( self::RETIRE, false ) ) {
			add_option( self::RETIRE, $queue, '', false );
		} else {
			update_option( self::RETIRE, $queue, false );
		}
	}

	/**
	 * The credentials of a queue entry. A token that comes from wp-config.php is read from there now.
	 *
	 * @param array<string, mixed> $entry Queue entry.
	 * @return array{provider:string, zone:string, token:string}
	 */
	private static function entry_config( $entry ) {
		if ( isset( $entry['token_source'] ) && 'config' === $entry['token_source'] ) {
			$token = self::token_from_config() ? self::clean_token( (string) SCRAPELOCK_EDGE_TOKEN ) : '';
		} else {
			$token = isset( $entry['token'] ) ? self::clean_token( (string) $entry['token'] ) : '';
		}
		return array(
			'provider' => isset( $entry['provider'] ) && isset( self::providers()[ $entry['provider'] ] ) ? (string) $entry['provider'] : '',
			'zone'     => isset( $entry['zone'] ) ? (string) $entry['zone'] : '',
			'token'    => $token,
		);
	}

	/**
	 * Up to 3.3.2 the removal queue held a copy of the token, even when it was set in wp-config.php. Such copies
	 * are removed: the entry now notes that the token comes from wp-config.php. Entries also get an ID. Runs on
	 * upgrade and before every run, and changes nothing once done.
	 */
	public static function migrate_queue() {
		$queue   = self::retire_queue( true );
		$changed = false;
		foreach ( $queue as $i => $entry ) {
			if ( ! is_array( $entry ) ) {
				unset( $queue[ $i ] );
				$changed = true;
				continue;
			}
			if ( empty( $entry['id'] ) ) {
				$queue[ $i ]['id'] = self::new_id();
				$changed           = true;
			}
			if ( isset( $entry['token'] ) && self::is_config_token( (string) $entry['token'] ) ) {
				unset( $queue[ $i ]['token'] );
				$queue[ $i ]['token_source'] = 'config';
				$changed                     = true;
			}
		}
		if ( $changed ) {
			self::save_queue( $queue );
		}
	}

	/**
	 * Updates one block in one queue entry, on a fresh copy of the queue, so entries that other requests added
	 * in the meantime are kept. An entry with nothing left is removed.
	 *
	 * @param string                    $entry_id Entry ID.
	 * @param string                    $key      Ban key.
	 * @param array<string, mixed>|null $item     The block, or null when it is gone.
	 */
	private static function commit_queue_item( $entry_id, $key, $item ) {
		$queue = self::retire_queue( true );
		foreach ( $queue as $i => $entry ) {
			if ( ! isset( $entry['id'] ) || $entry_id !== $entry['id'] ) {
				continue;
			}
			$items = isset( $entry['items'] ) && is_array( $entry['items'] ) ? $entry['items'] : array();
			if ( null === $item ) {
				unset( $items[ $key ] );
			} else {
				$items[ $key ] = $item;
			}
			if ( $items ) {
				$queue[ $i ]['items'] = $items;
			} else {
				unset( $queue[ $i ] );
			}
			self::save_queue( $queue );
			return;
		}
	}

	/**
	 * Removes a whole queue entry (its credentials no longer work).
	 *
	 * @param string $entry_id Entry ID.
	 */
	private static function drop_queue_entry( $entry_id ) {
		$queue = self::retire_queue( true );
		foreach ( $queue as $i => $entry ) {
			if ( isset( $entry['id'] ) && $entry_id === $entry['id'] ) {
				unset( $queue[ $i ] );
			}
		}
		self::save_queue( $queue );
	}

	/**
	 * Reads an option from the database, not from what this request read before: another request (the
	 * settings page, a ban) may have changed it since. With a persistent object cache the request that changed
	 * it has already updated the cache.
	 *
	 * @param string $name Option name.
	 * @return mixed
	 */
	private static function fresh_option( $name ) {
		wp_cache_delete( $name, 'options' );
		$notoptions = wp_cache_get( 'notoptions', 'options' );
		if ( is_array( $notoptions ) && isset( $notoptions[ $name ] ) ) {
			unset( $notoptions[ $name ] );
			wp_cache_set( 'notoptions', $notoptions, 'options' );
		}
		$alloptions = wp_cache_get( 'alloptions', 'options' );
		if ( is_array( $alloptions ) && isset( $alloptions[ $name ] ) ) {
			wp_cache_delete( 'alloptions', 'options' ); // Stored as autoloaded by an old version.
		}
		return get_option( $name, array() );
	}

	/* ---------- State ---------- */

	/**
	 * What is blocked at the CDN: ban key => [id (Cloudflare rule), until, own (made by ScrapeLock), pending
	 * (the time an add was sent whose answer was not saved yet), fails (removals refused so far)]. Also the
	 * configuration the blocks belong to (owner), the last run, the last error and the blocks that could not be
	 * removed (dropped).
	 *
	 * @param bool $fresh Read from the database, not from what this request read before.
	 * @return array{rules:array<string, array<string, mixed>>, time:int, error:string, error_time:int, owner:string|null, dropped:array<int, array<string, mixed>>}
	 */
	public static function state( $fresh = false ) {
		$state = $fresh ? self::fresh_option( self::STATE ) : get_option( self::STATE, array() );
		$state = is_array( $state ) ? $state : array();
		return array(
			'rules'      => isset( $state['rules'] ) && is_array( $state['rules'] ) ? $state['rules'] : array(),
			'time'       => isset( $state['time'] ) ? (int) $state['time'] : 0,
			'error'      => isset( $state['error'] ) ? (string) $state['error'] : '',
			'error_time' => isset( $state['error_time'] ) ? (int) $state['error_time'] : 0,
			// Null: saved by a version before 3.4, which did not record it.
			'owner'      => isset( $state['owner'] ) ? (string) $state['owner'] : null,
			'dropped'    => isset( $state['dropped'] ) && is_array( $state['dropped'] ) ? array_values( $state['dropped'] ) : array(),
		);
	}

	/**
	 * Saves the state (not autoloaded: only cron and the settings page read it).
	 *
	 * @param array<string, mixed> $state State.
	 */
	private static function save_state( $state ) {
		if ( false === get_option( self::STATE, false ) ) {
			add_option( self::STATE, $state, '', false );
		} else {
			update_option( self::STATE, $state, false );
		}
	}

	/**
	 * Which configuration blocks belong to: provider and zone.
	 *
	 * @param array{provider:string, zone:string, token:string} $c Configuration.
	 * @return string
	 */
	private static function fingerprint( $c ) {
		return $c['provider'] . ':' . $c['zone'];
	}

	/**
	 * Saves one block right after the API call that made, changed or removed it (on a fresh copy of the state),
	 * so a run that stops halfway (time limit, fatal error) never forgets a block it made. If the configuration
	 * changed while the run was busy, the block belongs to the old one: a block ScrapeLock made goes to the
	 * removal queue instead.
	 *
	 * @param array{provider:string, zone:string, token:string} $c    Configuration of the run.
	 * @param string                                            $key  Ban key.
	 * @param array<string, mixed>|null                         $rule The block, or null when it is gone.
	 */
	private static function commit_rule( $c, $key, $rule ) {
		$state = self::state( true );
		if ( self::fingerprint( $c ) !== $state['owner'] ) {
			if ( is_array( $rule ) && ! empty( $rule['own'] ) && self::usable( $c ) ) {
				self::queue_add( $c, array( $key => $rule ) );
			}
			return;
		}
		if ( null === $rule ) {
			unset( $state['rules'][ $key ] );
		} else {
			$state['rules'][ $key ] = $rule;
		}
		self::save_state( $state );
	}

	/**
	 * Notes a block that could not be removed by ScrapeLock, so the site owner can remove it by hand (the
	 * newest 20).
	 *
	 * @param string $provider Provider.
	 * @param string $key      Ban key.
	 * @param string $message  What the CDN answered.
	 */
	private static function record_dropped( $provider, $key, $message ) {
		$state = self::state( true );
		array_unshift(
			$state['dropped'],
			array(
				'key'      => $key,
				'provider' => $provider,
				'time'     => time(),
				'message'  => $message,
			)
		);
		$state['dropped'] = array_slice( $state['dropped'], 0, 20 );
		self::save_state( $state );
	}

	/**
	 * How many addresses ScrapeLock has blocked at the CDN now.
	 *
	 * @return int
	 */
	public static function count() {
		return count(
			array_filter(
				self::state()['rules'],
				static function ( $rule ) {
					return ! empty( $rule['own'] ) && empty( $rule['pending'] );
				}
			)
		);
	}

	/**
	 * At most this many addresses are blocked at the CDN (the newest bans). Filter `pncp_edge_max` (1–5000).
	 *
	 * @return int
	 */
	public static function max() {
		return max( 1, min( 5000, (int) apply_filters( 'pncp_edge_max', 500 ) ) );
	}

	/* ---------- Administrators ---------- */

	/**
	 * Remembers the IP of administrators who open wp-admin (30 days, the last 20). A block at the CDN also
	 * covers wp-admin and the login page, which a ban by ScrapeLock itself does not: an administrator must
	 * never lock themselves out that way. An IP address is personal data: every write keeps only the last
	 * 30 days, and prune_staff() removes older entries also when nobody opens wp-admin.
	 */
	public static function remember_staff() {
		if ( ! current_user_can( 'manage_options' ) || wp_doing_ajax() ) {
			return;
		}
		$ip = PNCP_Ip::client_ip();
		if ( '' === $ip || ! PNCP_Ip::reliable() ) {
			return;
		}
		$key   = PNCP_Ip::limit_key( $ip );
		$staff = self::staff();
		if ( isset( $staff[ $key ] ) && $staff[ $key ] > time() - 12 * HOUR_IN_SECONDS ) {
			self::prune_staff(); // Seen recently: no new entry, but entries older than 30 days still go.
			return;
		}
		$staff[ $key ] = time();
		arsort( $staff );
		self::save_staff( array_slice( $staff, 0, 20, true ) );
	}

	/**
	 * Removes the administrators' IPs not seen for 30 days from the database (only when there are any: no
	 * write otherwise).
	 */
	public static function prune_staff() {
		$stored = get_option( self::STAFF, array() );
		if ( ! is_array( $stored ) || ! $stored ) {
			return;
		}
		$fresh = self::staff();
		if ( count( $fresh ) !== count( $stored ) ) {
			self::save_staff( $fresh );
		}
	}

	/**
	 * Stores the administrators' IPs (not autoloaded: read only in wp-admin and when blocking at the CDN).
	 *
	 * @param array<string, int> $staff Ban key => last seen, only the last 30 days.
	 */
	private static function save_staff( $staff ) {
		if ( false === get_option( self::STAFF, false ) ) {
			add_option( self::STAFF, $staff, '', false );
		} else {
			update_option( self::STAFF, $staff, false );
		}
	}

	/**
	 * The administrators' IPs of the last 30 days: ban key => last seen.
	 *
	 * @return array<string, int>
	 */
	public static function staff() {
		$staff = get_option( self::STAFF, array() );
		$staff = is_array( $staff ) ? $staff : array();
		$since = time() - 30 * DAY_IN_SECONDS;
		$out   = array();
		foreach ( $staff as $key => $time ) {
			if ( (int) $time > $since ) {
				$out[ (string) $key ] = (int) $time;
			}
		}
		return $out;
	}

	/* ---------- Running ---------- */

	/**
	 * A ban was added or lifted: run in the background as soon as possible (with the next request to the
	 * site, by WordPress's cron), not while the visitor waits. The change is also noted, so a run that is busy
	 * right now runs again when it ends.
	 */
	public static function soon() {
		if ( ! self::usable() && ! self::retire_queue() ) {
			return;
		}
		update_option( self::DIRTY, uniqid( '', true ), false );
		$next = wp_next_scheduled( self::CRON );
		if ( $next && $next <= time() + 30 ) {
			return;
		}
		if ( $next ) {
			wp_unschedule_event( $next, self::CRON );
		}
		wp_schedule_single_event( time(), self::CRON );
	}

	/**
	 * After activation (or an upgrade): blocks left in the removal queue by a deactivation that ran out of
	 * time are removed now, and the CDN is brought in step with the bans again.
	 */
	public static function resume() {
		self::migrate_queue();
		// A token saved in the settings before the same one was put in wp-config.php: the copy in the database
		// is no longer used, so it is removed.
		$stored = get_option( self::CONFIG, array() );
		if ( is_array( $stored ) && isset( $stored['token'] ) && '' !== $stored['token'] && self::is_config_token( self::clean_token( (string) $stored['token'] ) ) ) {
			$stored['token'] = '';
			update_option( self::CONFIG, $stored, false );
		}
		self::soon();
	}

	/**
	 * Takes the lock: one atomic UPDATE that only one request can win, and only once the lock is free or has
	 * expired (a run that died).
	 *
	 * @return bool
	 */
	private static function lock() {
		global $wpdb;
		if ( false === self::fresh_option_raw( self::LOCK ) ) {
			add_option( self::LOCK, '0', '', false );
		}
		$now   = time();
		$value = (string) ( $now + self::LOCK_TTL );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- An atomic compare-and-set on our own row; no cache to update.
		$rows = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value + 0 < %d', $wpdb->options, $value, self::LOCK, $now ) );
		wp_cache_delete( self::LOCK, 'options' );
		if ( 1 !== (int) $rows ) {
			return false;
		}
		self::$lock = $value;
		return true;
	}

	/**
	 * Releases the lock, if this request still holds it.
	 */
	private static function unlock() {
		global $wpdb;
		if ( '' === self::$lock ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Releases our own lock only.
		$wpdb->query( $wpdb->prepare( "UPDATE %i SET option_value = '0' WHERE option_name = %s AND option_value = %s", $wpdb->options, self::LOCK, self::$lock ) );
		wp_cache_delete( self::LOCK, 'options' );
		self::$lock = '';
	}

	/**
	 * An option as it is in the database now, false if missing.
	 *
	 * @param string $name Option name.
	 * @return mixed
	 */
	private static function fresh_option_raw( $name ) {
		self::fresh_option( $name );
		return get_option( $name, false );
	}

	/**
	 * More time for this request where the host allows it: a run makes up to BATCH calls of up to 10 seconds,
	 * and WordPress's cron sets no time limit of its own.
	 */
	private static function raise_time_limit() {
		if ( function_exists( 'set_time_limit' ) && false === strpos( (string) ini_get( 'disable_functions' ), 'set_time_limit' ) ) {
			@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Not allowed on every host.
		}
	}

	/**
	 * Schedules the next run at this time, unless one is already due earlier (a ban that came in during this
	 * run, for example). With $force, earlier runs are moved to this time (the CDN asked to slow down).
	 *
	 * @param int  $time  Time; 0 for none.
	 * @param bool $force Move earlier runs too.
	 */
	private static function schedule( $time, $force = false ) {
		if ( ! $time ) {
			return;
		}
		$next = wp_next_scheduled( self::CRON );
		if ( $next && $next <= $time && ! $force ) {
			return;
		}
		if ( $next ) {
			wp_clear_scheduled_hook( self::CRON );
		}
		wp_schedule_single_event( $time, self::CRON );
	}

	/**
	 * The addresses that should be blocked at the CDN: the newest active bans, without the administrators'
	 * IPs and without addresses of search engines, AI search services or the CDNs themselves. Bunny CDN blocks
	 * single addresses only, so a banned IPv6 network (/64) is left to ScrapeLock there.
	 *
	 * @param string $provider Provider.
	 * @return array<string, array{until:int, reason:string}>
	 */
	public static function wanted( $provider ) {
		// "Monitor only" blocks nothing, also at the CDN: the blocks made there are removed, and come back
		// with the next run after blocking starts (every settings change schedules one).
		if ( ! self::active() || PNCP_Options::monitoring() ) {
			return array();
		}
		$staff = self::staff();
		$max   = self::max();
		$out   = array();
		// A few more than the maximum, so the addresses left out below do not take room from the others.
		foreach ( PNCP_Log::active_bans( 2 * $max + 50 ) as $key => $ban ) {
			if ( count( $out ) >= $max ) {
				break;
			}
			$key  = (string) $key;
			$base = false === strpos( $key, '/' ) ? $key : strstr( $key, '/', true );
			if ( isset( $staff[ $key ] ) || ! filter_var( $base, FILTER_VALIDATE_IP ) || PNCP_Ip::is_local( $base ) || PNCP_Ip::is_private( $base ) || '' !== PNCP_Ip::official_owner( $base ) ) {
				continue;
			}
			if ( 'bunny' === $provider && $base !== $key ) {
				continue;
			}
			$out[ $key ] = array(
				'until'  => (int) $ban['until'],
				'reason' => (string) $ban['reason'],
			);
		}
		return $out;
	}

	/**
	 * One run: removes the blocks of previous configurations, then adds the new bans and removes the ended
	 * ones, at most BATCH API calls and BUDGET seconds. Each block is saved right after its API call. Schedules
	 * the next run: soon if work is left or something changed during the run, otherwise when the next block
	 * ends.
	 */
	public static function sync() {
		if ( ! self::lock() ) {
			// Another run is busy: try again in a minute (it may end before the change that queued this run).
			self::schedule( time() + MINUTE_IN_SECONDS );
			return;
		}
		$next = 0;
		$wait = 0;
		try {
			self::raise_time_limit();
			$dirty = self::fresh_option_raw( self::DIRTY );
			self::migrate_queue();
			$deadline = time() + self::BUDGET;
			$calls    = 0;
			$left     = self::run_retire( $calls, $wait, $deadline );
			$c        = self::config();
			$error    = null;
			if ( self::usable( $c ) && ! $wait ) {
				$result = self::run_config( $c, $calls, $deadline );
				$left   = $left || $result['left'];
				$wait   = $result['wait'];
				$error  = $result['error'];
			}
			$state         = self::state( true );
			$state['time'] = time();
			if ( null !== $error ) {
				if ( '' !== $error ) {
					$state['error']      = $error;
					$state['error_time'] = time();
				} else {
					$state['error'] = '';
				}
			}
			self::save_state( $state );

			if ( $wait ) {
				$next = time() + $wait;
			} elseif ( $left ) {
				$next = time() + MINUTE_IN_SECONDS;
			} else {
				foreach ( $state['rules'] as $rule ) {
					if ( ! empty( $rule['own'] ) ) {
						$end  = (int) $rule['until'] + 5;
						$next = $next ? min( $next, $end ) : $end;
					}
				}
				$next = $next ? max( $next, time() + MINUTE_IN_SECONDS ) : 0;
			}
			// A ban or a setting changed while this run was busy: what it changed may not be done yet.
			if ( self::fresh_option_raw( self::DIRTY ) !== $dirty ) {
				$next = $wait ? min( $next, time() + MINUTE_IN_SECONDS ) : time();
				$wait = 0;
			}
		} finally {
			self::unlock();
		}
		self::schedule( $next, (bool) $wait );
	}

	/**
	 * Removes the blocks of previous configurations.
	 *
	 * @param int $calls    API calls made so far in this run (updated).
	 * @param int $wait     Seconds to wait before the next run, if the CDN asked to slow down (updated).
	 * @param int $deadline No new API call after this time.
	 * @return bool Whether some are left.
	 */
	private static function run_retire( &$calls, &$wait, $deadline ) {
		$queue = self::retire_queue( true );
		if ( ! $queue ) {
			return false;
		}
		foreach ( $queue as $entry ) {
			$id    = isset( $entry['id'] ) ? (string) $entry['id'] : '';
			$c     = self::entry_config( $entry );
			$items = isset( $entry['items'] ) && is_array( $entry['items'] ) ? $entry['items'] : array();
			if ( '' === $id ) {
				continue; // Not migrated yet (migrate_queue() gives every entry an ID).
			}
			if ( ! self::usable( $c ) ) {
				// The token was in wp-config.php and is not there any more: these blocks cannot be removed from
				// here. They are listed on the settings page, to be removed by hand.
				foreach ( $items as $key => $rule ) {
					self::record_dropped( $c['provider'], (string) $key, __( 'The API token is no longer set in wp-config.php.', 'scrapelock' ) );
				}
				self::drop_queue_entry( $id );
				continue;
			}
			foreach ( $items as $key => $rule ) {
				$key = (string) $key;
				if ( $calls >= self::BATCH || time() >= $deadline ) {
					break 2;
				}
				$rule = is_array( $rule ) ? $rule : array();
				$res  = self::remove( $c, $key, $rule, $calls );
				if ( 'ok' === $res['status'] ) {
					self::commit_queue_item( $id, $key, null );
				} elseif ( 'wait' === $res['status'] ) {
					$wait = 5 * MINUTE_IN_SECONDS;
					break 2;
				} elseif ( 'denied' === $res['status'] ) {
					// The old credentials no longer work: nothing more can be done with them.
					foreach ( $items as $gone => $unused ) {
						self::record_dropped( $c['provider'], (string) $gone, $res['message'] );
					}
					self::drop_queue_entry( $id );
					break;
				} elseif ( 'refused' === $res['status'] ) {
					// This one block only: tried again a few times, then given up (and listed), so it never holds
					// up the rest of the queue for good.
					$rule['fails'] = isset( $rule['fails'] ) ? (int) $rule['fails'] + 1 : 1;
					if ( $rule['fails'] >= self::TRIES ) {
						self::commit_queue_item( $id, $key, null );
						self::record_dropped( $c['provider'], $key, $res['message'] );
					} else {
						self::commit_queue_item( $id, $key, $rule );
					}
				} else {
					break 2; // Network or server error: next run.
				}
			}
		}
		return (bool) self::retire_queue( true );
	}

	/**
	 * Brings the CDN in step with the active bans, for the current configuration.
	 *
	 * @param array{provider:string, zone:string, token:string} $c        Configuration.
	 * @param int                                               $calls    API calls made so far (updated).
	 * @param int                                               $deadline No new API call after this time.
	 * @return array{left:bool, wait:int, error:string}
	 */
	private static function run_config( $c, &$calls, $deadline ) {
		$fp    = self::fingerprint( $c );
		$state = self::state( true );
		if ( $fp !== $state['owner'] ) {
			// Empty (after a change of configuration, whose blocks went to the removal queue) or saved by an older
			// version: the blocks in the state belong to this configuration from now on.
			$state['owner'] = $fp;
		}
		$wanted = self::wanted( $c['provider'] );
		$todo   = array();
		foreach ( $state['rules'] as $key => $rule ) {
			if ( ! isset( $wanted[ $key ] ) ) {
				$todo[] = array( 'remove', (string) $key );
			}
		}
		foreach ( $wanted as $key => $ban ) {
			if ( isset( $state['rules'][ $key ] ) ) {
				$state['rules'][ $key ]['until'] = $ban['until']; // A renewed ban.
				if ( ! empty( $state['rules'][ $key ]['pending'] ) ) {
					$todo[] = array( 'add', (string) $key ); // An add whose answer was never saved: checked first.
				}
			} else {
				$todo[] = array( 'add', (string) $key );
			}
		}
		self::save_state( $state );
		if ( ! $todo ) {
			return array(
				'left'  => false,
				'wait'  => 0,
				'error' => '',
			);
		}
		$rules    = $state['rules'];
		$error    = '';
		$wait     = 0;
		$done     = 0;
		$existing = null;
		foreach ( $todo as $job ) {
			if ( $calls >= self::BATCH || time() >= $deadline ) {
				break;
			}
			list( $op, $key ) = $job;
			$res              = null;
			if ( 'remove' === $op ) {
				$rule = $rules[ $key ];
				if ( empty( $rule['own'] ) ) {
					self::commit_rule( $c, $key, null ); // Blocked by the site owner before ScrapeLock: left as it is.
					++$done;
					continue;
				}
				$res = self::remove( $c, $key, $rule, $calls );
				if ( 'ok' === $res['status'] ) {
					self::commit_rule( $c, $key, null );
					++$done;
					continue;
				}
				if ( 'refused' === $res['status'] ) {
					// The CDN does not accept removing this one: tried again a few times (a passing problem), then
					// given up and listed on the settings page, to be removed by hand.
					$rule['fails'] = isset( $rule['fails'] ) ? (int) $rule['fails'] + 1 : 1;
					if ( $rule['fails'] >= self::TRIES ) {
						self::commit_rule( $c, $key, null );
						self::record_dropped( $c['provider'], $key, $res['message'] );
					} else {
						self::commit_rule( $c, $key, $rule );
					}
					$error = $res['message'];
					++$done; // This one address only; the others go on.
					continue;
				}
			} else {
				$ban     = $wanted[ $key ];
				$pending = isset( $rules[ $key ] ) && ! empty( $rules[ $key ]['pending'] );
				if ( 'bunny' === $c['provider'] && null === $existing ) {
					// The addresses already in the pull zone's list: those were put there by the site owner,
					// so ScrapeLock does not add them again and never removes them.
					++$calls;
					$list = self::bunny_blocked( $c );
					if ( ! is_array( $list['list'] ) ) {
						$error = $list['message'];
						$wait  = 'denied' === $list['status'] ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS;
						break;
					}
					$existing = $list['list'];
				}
				if ( is_array( $existing ) && in_array( $key, $existing, true ) ) {
					// Already listed. If ScrapeLock had sent this add (pending), the address was not in the list
					// before, so the block is ScrapeLock's: it is removed when the ban ends.
					self::commit_rule(
						$c,
						$key,
						array(
							'id'    => '',
							'until' => $ban['until'],
							'own'   => $pending,
						)
					);
					++$done;
					continue;
				}
				if ( 'cloudflare' === $c['provider'] && $pending ) {
					// The answer to an earlier add was lost: the rule may exist at Cloudflare already.
					$found = self::cloudflare_find( $c, $key, $calls );
					if ( 'ok' !== $found['status'] ) {
						$res = $found; // Handled below as an error of this call.
					} elseif ( '' !== $found['id'] ) {
						self::commit_rule(
							$c,
							$key,
							array(
								'id'    => $found['id'],
								'until' => $ban['until'],
								'own'   => $found['ours'],
							)
						);
						++$done;
						continue;
					}
				}
				if ( null === $res ) {
					// Saved before the call: if the answer never arrives (time limit, timeout), the next run
					// looks for the block instead of thinking it is someone else's.
					self::commit_rule(
						$c,
						$key,
						array(
							'id'      => '',
							'until'   => $ban['until'],
							'own'     => true,
							'pending' => time(),
						)
					);
					++$calls;
					$res = self::add( $c, $key, $ban );
					if ( 'exists' === $res['status'] && 'cloudflare' === $c['provider'] ) {
						// A rule for this address exists. One with the note "ScrapeLock" was made by ScrapeLock (a
						// run whose answer was lost): it is adopted. Any other is the site owner's: never removed.
						$found = self::cloudflare_find( $c, $key, $calls );
						if ( 'ok' === $found['status'] && '' !== $found['id'] ) {
							$res['id'] = $found['id'];
							if ( $found['ours'] ) {
								$res['status'] = 'ok';
							}
						} elseif ( 'ok' !== $found['status'] ) {
							$res = $found; // Still pending: the next run looks again.
						}
					}
					if ( in_array( $res['status'], array( 'ok', 'exists', 'refused' ), true ) ) {
						// Not ours ("exists": the site owner's own rule; "refused": the CDN does not accept this one
						// address) are kept as such, so they are not tried again and never removed.
						self::commit_rule(
							$c,
							$key,
							array(
								'id'    => $res['id'],
								'until' => $ban['until'],
								'own'   => 'ok' === $res['status'],
							)
						);
					}
				}
				if ( 'ok' === $res['status'] || 'exists' === $res['status'] ) {
					++$done;
					continue;
				}
				if ( 'refused' === $res['status'] ) {
					$error = $res['message'];
					++$done; // This one address only; the others go on.
					continue;
				}
			}
			// Wrong token or zone: no point retrying every few minutes. Rate limit, network or server error:
			// a few minutes. A pending add stays pending: the next run checks whether it arrived.
			$error = $res['message'];
			$wait  = 'denied' === $res['status'] ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS;
			break;
		}
		return array(
			'left'  => $done < count( $todo ),
			'wait'  => $wait,
			'error' => $error,
		);
	}

	/**
	 * Deactivation: removes the blocks ScrapeLock made (current and previous configurations), for at most
	 * the given number of seconds. Blocks that are left stay in the removal queue: they are removed when the
	 * plugin is activated again, or on uninstall. Cloudflare rules carry the note "ScrapeLock" and can also be
	 * removed from the Cloudflare dashboard.
	 *
	 * @param int $seconds Time limit.
	 */
	public static function remove_all( $seconds = 20 ) {
		self::retire( self::config() );
		self::migrate_queue();
		$deadline = time() + max( 1, (int) $seconds );
		// A run that is busy right now removes the same blocks; a block removed twice is "not found" the second
		// time, which counts as done. So this goes on even without the lock.
		$locked = self::lock();
		try {
			while ( self::retire_queue( true ) && time() < $deadline ) {
				$calls = 0;
				$wait  = 0;
				self::run_retire( $calls, $wait, $deadline );
				if ( $wait || $calls < self::BATCH ) {
					break; // Finished, or stopped by an error: no point hammering the CDN.
				}
			}
		} finally {
			if ( $locked ) {
				self::unlock();
			}
		}
		// No run after deactivation (the plugin's code does not run then); the queue stays for resume().
		wp_clear_scheduled_hook( self::CRON );
	}

	/* ---------- The CDN APIs ---------- */

	/**
	 * Blocks one address (IPv4, IPv6, or an IPv6 /64 on Cloudflare).
	 *
	 * @param array{provider:string, zone:string, token:string} $c   Configuration.
	 * @param string                                            $key Ban key.
	 * @param array{until:int, reason:string}                   $ban The ban.
	 * @return array{status:string, id:string, message:string} status: ok | exists | refused | denied | wait | error.
	 */
	private static function add( $c, $key, $ban ) {
		if ( 'cloudflare' === $c['provider'] ) {
			$target = false !== strpos( $key, '/' ) ? 'ip_range' : ( false !== strpos( $key, ':' ) ? 'ip6' : 'ip' );
			$res    = self::request(
				$c,
				'POST',
				self::CLOUDFLARE_API . '/zones/' . rawurlencode( $c['zone'] ) . '/firewall/access_rules/rules',
				array(
					'mode'          => 'block',
					'configuration' => array(
						'target' => $target,
						'value'  => $key,
					),
					'notes'         => 'ScrapeLock: ' . $ban['reason'] . ', until ' . gmdate( 'Y-m-d H:i', $ban['until'] ) . ' UTC',
				)
			);
			if ( 'ok' === $res['status'] ) {
				$id = isset( $res['json']['result']['id'] ) ? (string) $res['json']['result']['id'] : '';
				return array(
					'status'  => '' !== $id ? 'ok' : 'error',
					'id'      => $id,
					'message' => '' !== $id ? '' : __( 'The CDN did not return the new block.', 'scrapelock' ),
				);
			}
			// The address already has a rule (made by the site owner): it is left alone.
			if ( 'refused' === $res['status'] && preg_match( '/duplicate|already exist/i', $res['message'] ) ) {
				$res['status'] = 'exists';
			}
			return array(
				'status'  => $res['status'],
				'id'      => '',
				'message' => $res['message'],
			);
		}
		$res = self::request( $c, 'POST', self::BUNNY_API . '/pullzone/' . rawurlencode( $c['zone'] ) . '/addBlockedIp', array( 'BlockedIp' => $key ) );
		return array(
			'status'  => $res['status'],
			'id'      => '',
			'message' => $res['message'],
		);
	}

	/**
	 * Removes one block that ScrapeLock made. A Cloudflare block whose rule ID is not known (an add whose answer
	 * was lost) is looked up first, and removed only if its note says ScrapeLock made it.
	 *
	 * @param array{provider:string, zone:string, token:string} $c     Configuration.
	 * @param string                                            $key   Ban key.
	 * @param array<string, mixed>                              $rule  The block.
	 * @param int                                               $calls API calls made so far (updated).
	 * @return array{status:string, message:string}
	 */
	private static function remove( $c, $key, $rule, &$calls ) {
		if ( 'cloudflare' === $c['provider'] ) {
			$id = isset( $rule['id'] ) ? (string) $rule['id'] : '';
			if ( '' === $id ) {
				$found = self::cloudflare_find( $c, $key, $calls );
				if ( 'ok' !== $found['status'] ) {
					return array(
						'status'  => $found['status'],
						'message' => $found['message'],
					);
				}
				$id = $found['ours'] ? $found['id'] : '';
			}
			if ( ! preg_match( '/^[A-Za-z0-9]{1,64}$/', $id ) ) {
				return array(
					'status'  => 'ok', // Nothing of ScrapeLock's at the CDN for this address.
					'message' => '',
				);
			}
			++$calls;
			$res = self::request( $c, 'DELETE', self::CLOUDFLARE_API . '/zones/' . rawurlencode( $c['zone'] ) . '/firewall/access_rules/rules/' . $id );
		} else {
			++$calls;
			$res = self::request( $c, 'POST', self::BUNNY_API . '/pullzone/' . rawurlencode( $c['zone'] ) . '/removeBlockedIp', array( 'BlockedIp' => $key ) );
		}
		// Already gone (removed by hand at the CDN): done.
		if ( 'refused' === $res['status'] && 404 === $res['code'] ) {
			$res['status'] = 'ok';
		}
		return array(
			'status'  => $res['status'],
			'message' => $res['message'],
		);
	}

	/**
	 * Looks up the Cloudflare rule for exactly this address (one API call): its ID, and whether ScrapeLock
	 * made it (every rule ScrapeLock makes has a note that starts with "ScrapeLock").
	 *
	 * @param array{provider:string, zone:string, token:string} $c     Configuration.
	 * @param string                                            $key   Ban key (IP or IPv6 /64).
	 * @param int                                               $calls API calls made so far (updated).
	 * @return array{status:string, id:string, ours:bool, message:string} id is empty when there is no rule.
	 */
	private static function cloudflare_find( $c, $key, &$calls ) {
		++$calls;
		$res = self::request( $c, 'GET', self::CLOUDFLARE_API . '/zones/' . rawurlencode( $c['zone'] ) . '/firewall/access_rules/rules?' . http_build_query( array( 'configuration.value' => $key ) ) );
		$out = array(
			'status'  => $res['status'],
			'id'      => '',
			'ours'    => false,
			'message' => $res['message'],
		);
		if ( 'ok' !== $res['status'] ) {
			return $out;
		}
		foreach ( isset( $res['json']['result'] ) && is_array( $res['json']['result'] ) ? $res['json']['result'] : array() as $rule ) {
			if ( ! is_array( $rule ) || ! isset( $rule['configuration']['value'], $rule['id'] ) || $key !== (string) $rule['configuration']['value'] ) {
				continue;
			}
			$id   = (string) $rule['id'];
			$ours = isset( $rule['notes'] ) && 0 === strpos( (string) $rule['notes'], 'ScrapeLock' ) && ( ! isset( $rule['mode'] ) || 'block' === $rule['mode'] );
			if ( '' === $out['id'] || $ours ) {
				$out['id']   = $id;
				$out['ours'] = $ours;
			}
			if ( $ours ) {
				break;
			}
		}
		return $out;
	}

	/**
	 * The addresses in the Bunny pull zone's block list.
	 *
	 * @param array{provider:string, zone:string, token:string} $c Configuration.
	 * @return array{status:string, list:string[]|null, message:string}
	 */
	private static function bunny_blocked( $c ) {
		$res  = self::request( $c, 'GET', self::BUNNY_API . '/pullzone/' . rawurlencode( $c['zone'] ) );
		$list = null;
		if ( 'ok' === $res['status'] ) {
			$list = array();
			if ( isset( $res['json']['BlockedIps'] ) && is_array( $res['json']['BlockedIps'] ) ) {
				foreach ( $res['json']['BlockedIps'] as $ip ) {
					$list[] = (string) $ip;
				}
			}
		}
		return array(
			'status'  => $res['status'],
			'list'    => $list,
			'message' => $res['message'],
		);
	}

	/**
	 * Checks the configuration with one read-only request: the token, its permissions and the zone.
	 *
	 * @param array{provider:string, zone:string, token:string} $c Configuration.
	 * @return string Empty if it works, otherwise what went wrong.
	 */
	public static function test( $c ) {
		if ( ! self::usable( $c ) ) {
			return __( 'Fill in the zone ID and the token.', 'scrapelock' );
		}
		if ( 'cloudflare' === $c['provider'] ) {
			$res = self::request( $c, 'GET', self::CLOUDFLARE_API . '/zones/' . rawurlencode( $c['zone'] ) . '/firewall/access_rules/rules?per_page=5' );
		} else {
			$res = self::request( $c, 'GET', self::BUNNY_API . '/pullzone/' . rawurlencode( $c['zone'] ) );
		}
		return 'ok' === $res['status'] ? '' : $res['message'];
	}

	/**
	 * Tests the whole path with an address that belongs to nobody (203.0.113.0/24, reserved for
	 * documentation): blocks it at the CDN, checks that the CDN lists it, removes it and checks that it is
	 * gone. No setting changes and no visitor is affected.
	 *
	 * @param array{provider:string, zone:string, token:string} $c Configuration.
	 * @return array{ok:bool, message:string}
	 */
	public static function test_block( $c ) {
		$fail = static function ( $step, $message ) {
			return array(
				'ok'      => false,
				/* translators: 1: the step that failed, 2: what the CDN answered */
				'message' => sprintf( __( '%1$s failed: %2$s', 'scrapelock' ), $step, $message ),
			);
		};
		if ( ! self::usable( $c ) ) {
			return $fail( __( 'Connection', 'scrapelock' ), __( 'Fill in the zone ID and the token.', 'scrapelock' ) );
		}
		$ip  = '203.0.113.' . wp_rand( 200, 254 );
		$ban = array(
			'until'  => time() + MINUTE_IN_SECONDS,
			'reason' => 'test',
		);
		$before = self::listed( $c, $ip );
		if ( is_string( $before ) ) {
			return $fail( __( 'Connection', 'scrapelock' ), $before );
		}
		if ( true === $before ) {
			return $fail( __( 'Connection', 'scrapelock' ), __( 'The test address is already blocked at the CDN; try again.', 'scrapelock' ) );
		}
		$add = self::add( $c, $ip, $ban );
		if ( 'ok' !== $add['status'] ) {
			return $fail( __( 'Adding the test block', 'scrapelock' ), $add['message'] );
		}
		$rule   = array(
			'id'  => $add['id'],
			'own' => true,
		);
		$listed = self::listed( $c, $ip );
		$calls  = 0;
		$remove = self::remove( $c, $ip, $rule, $calls );
		if ( true !== $listed ) {
			return $fail( __( 'Finding the test block at the CDN', 'scrapelock' ), is_string( $listed ) ? $listed : __( 'The CDN accepted the block but does not list it.', 'scrapelock' ) );
		}
		if ( 'ok' !== $remove['status'] ) {
			/* translators: %s: test IP address */
			return $fail( __( 'Removing the test block', 'scrapelock' ), $remove['message'] . ' ' . sprintf( __( 'Remove %s by hand at the CDN.', 'scrapelock' ), $ip ) );
		}
		$gone = self::listed( $c, $ip );
		if ( false !== $gone ) {
			/* translators: %s: test IP address */
			return $fail( __( 'Removing the test block', 'scrapelock' ), ( is_string( $gone ) ? $gone : __( 'The CDN still lists it.', 'scrapelock' ) ) . ' ' . sprintf( __( 'Remove %s by hand at the CDN.', 'scrapelock' ), $ip ) );
		}
		return array(
			'ok'      => true,
			/* translators: 1: test IP address, 2: CDN name */
			'message' => sprintf( __( 'The test address %1$s was blocked at %2$s, found there and removed again. Blocking at the CDN works.', 'scrapelock' ), $ip, self::providers()[ $c['provider'] ] ),
		);
	}

	/**
	 * Does the CDN list a block for this exact address?
	 *
	 * @param array{provider:string, zone:string, token:string} $c  Configuration.
	 * @param string                                            $ip IP.
	 * @return bool|string True / false, or what went wrong.
	 */
	private static function listed( $c, $ip ) {
		if ( 'bunny' === $c['provider'] ) {
			$res = self::bunny_blocked( $c );
			return is_array( $res['list'] ) ? in_array( $ip, $res['list'], true ) : $res['message'];
		}
		$calls = 0;
		$found = self::cloudflare_find( $c, $ip, $calls );
		return 'ok' === $found['status'] ? '' !== $found['id'] : $found['message'];
	}

	/**
	 * One request to the CDN's API, with the site owner's token.
	 *
	 * @param array{provider:string, zone:string, token:string} $c      Configuration.
	 * @param string                                            $method Method.
	 * @param string                                            $url    URL.
	 * @param array<string, mixed>|null                         $body   JSON body.
	 * @return array{status:string, code:int, json:array<string, mixed>, message:string}
	 */
	private static function request( $c, $method, $url, $body = null ) {
		$headers = array(
			'Accept'       => 'application/json',
			'Content-Type' => 'application/json',
		);
		if ( 'cloudflare' === $c['provider'] ) {
			$headers['Authorization'] = 'Bearer ' . $c['token'];
		} else {
			$headers['AccessKey'] = $c['token'];
		}
		$args = array(
			'method'      => $method,
			'timeout'     => 10,
			'redirection' => 0,
			'user-agent'  => 'ScrapeLock/' . PNCP_VERSION,
			'headers'     => $headers,
		);
		if ( null !== $body ) {
			$args['body'] = (string) wp_json_encode( $body );
		}
		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			return array(
				'status'  => 'error',
				'code'    => 0,
				'json'    => array(),
				/* translators: %s: error message */
				'message' => sprintf( __( 'The CDN could not be reached: %s', 'scrapelock' ), $response->get_error_message() ),
			);
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$json = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		$json = is_array( $json ) ? $json : array();
		if ( $code >= 200 && $code < 300 && ( 'cloudflare' !== $c['provider'] || ! empty( $json['success'] ) ) ) {
			return array(
				'status'  => 'ok',
				'code'    => $code,
				'json'    => $json,
				'message' => '',
			);
		}
		$detail = '';
		if ( isset( $json['errors'][0]['message'] ) ) {
			$detail = (string) $json['errors'][0]['message']; // Cloudflare.
		} elseif ( isset( $json['Message'] ) ) {
			$detail = (string) $json['Message']; // Bunny.
		}
		$detail = substr( sanitize_text_field( $detail ), 0, 200 );
		if ( 401 === $code || 403 === $code ) {
			$status  = 'denied';
			$message = __( 'The CDN refused the token: check that it is correct, that it belongs to this zone and that it has the permission described under “API token”.', 'scrapelock' );
		} elseif ( 429 === $code ) {
			$status  = 'wait';
			$message = __( 'The CDN asked to slow down; it will continue in a few minutes.', 'scrapelock' );
		} elseif ( $code >= 500 || 0 === $code ) {
			$status = 'error';
			/* translators: %d: HTTP status code */
			$message = sprintf( __( 'The CDN answered with an error (HTTP %d); it will try again in a few minutes.', 'scrapelock' ), $code );
		} else {
			$status = 'refused';
			/* translators: %d: HTTP status code */
			$message = sprintf( __( 'The CDN did not accept the request (HTTP %d).', 'scrapelock' ), $code );
			if ( 404 === $code ) {
				$message = __( 'The CDN does not know this zone ID.', 'scrapelock' );
			}
		}
		return array(
			'status'  => $status,
			'code'    => $code,
			'json'    => $json,
			'message' => '' !== $detail ? $message . ' (' . $detail . ')' : $message,
		);
	}
}
