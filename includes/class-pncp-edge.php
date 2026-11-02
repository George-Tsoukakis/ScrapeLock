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
	const LOCK = 'pncp_edge_lock';

	/**
	 * API calls per run, so a run stays short and well inside the providers' rate limits.
	 */
	const BATCH = 25;

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
	 * Moves the blocks made with a configuration to the removal queue, with the credentials needed to remove
	 * them, and empties the state.
	 *
	 * @param array{provider:string, zone:string, token:string} $c Configuration the blocks were made with.
	 */
	private static function retire( $c ) {
		$state = self::state();
		$items = array();
		foreach ( $state['rules'] as $key => $rule ) {
			if ( ! empty( $rule['own'] ) ) {
				$items[ $key ] = $rule;
			}
		}
		if ( $items && self::usable( $c ) ) {
			$queue   = self::retire_queue();
			$queue[] = array(
				'provider' => $c['provider'],
				'zone'     => $c['zone'],
				'token'    => $c['token'],
				'items'    => $items,
			);
			update_option( self::RETIRE, $queue, false );
		}
		$state['rules'] = array();
		$state['error'] = '';
		self::save_state( $state );
	}

	/**
	 * Blocks still to be removed from previous configurations.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function retire_queue() {
		$queue = get_option( self::RETIRE, array() );
		return is_array( $queue ) ? array_values( $queue ) : array();
	}

	/* ---------- State ---------- */

	/**
	 * What is blocked at the CDN: ban key => [id (Cloudflare rule), until, own (made by ScrapeLock)].
	 *
	 * @return array{rules:array<string, array<string, mixed>>, time:int, error:string, error_time:int}
	 */
	public static function state() {
		$state = get_option( self::STATE, array() );
		$state = is_array( $state ) ? $state : array();
		return array(
			'rules'      => isset( $state['rules'] ) && is_array( $state['rules'] ) ? $state['rules'] : array(),
			'time'       => isset( $state['time'] ) ? (int) $state['time'] : 0,
			'error'      => isset( $state['error'] ) ? (string) $state['error'] : '',
			'error_time' => isset( $state['error_time'] ) ? (int) $state['error_time'] : 0,
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
	 * How many addresses ScrapeLock has blocked at the CDN now.
	 *
	 * @return int
	 */
	public static function count() {
		return count(
			array_filter(
				self::state()['rules'],
				static function ( $rule ) {
					return ! empty( $rule['own'] );
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
	 * never lock themselves out that way.
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
			return; // Seen recently: no write on every admin page.
		}
		$staff[ $key ] = time();
		arsort( $staff );
		$staff = array_slice( $staff, 0, 20, true );
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
	 * site, by WordPress's cron), not while the visitor waits.
	 */
	public static function soon() {
		if ( ! self::usable() && ! self::retire_queue() ) {
			return;
		}
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
	 * The addresses that should be blocked at the CDN: the newest active bans, without the administrators'
	 * IPs and without addresses of search engines, AI search services or the CDNs themselves. Bunny CDN blocks
	 * single addresses only, so a banned IPv6 network (/64) is left to ScrapeLock there.
	 *
	 * @param string $provider Provider.
	 * @return array<string, array{until:int, reason:string}>
	 */
	public static function wanted( $provider ) {
		if ( ! self::active() ) {
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
	 * ones, at most BATCH API calls. Schedules the next run: soon if work is left, otherwise when the next
	 * block ends.
	 */
	public static function sync() {
		if ( get_transient( self::LOCK ) ) {
			return; // Another run is busy.
		}
		set_transient( self::LOCK, 1, 2 * MINUTE_IN_SECONDS );
		$calls = 0;
		$wait  = 0;
		$left  = self::run_retire( $calls, $wait );
		$state = self::state();
		$c     = self::config();
		if ( self::usable( $c ) && ! $wait ) {
			$result = self::run_config( $c, $state, $calls );
			$left   = $left || $result['left'];
			$wait   = $result['wait'];
		}
		$state['time'] = time();
		self::save_state( $state );
		delete_transient( self::LOCK );

		wp_clear_scheduled_hook( self::CRON );
		$next = 0;
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
		if ( $next ) {
			wp_schedule_single_event( $next, self::CRON );
		}
	}

	/**
	 * Removes the blocks of previous configurations.
	 *
	 * @param int $calls API calls made so far in this run (updated).
	 * @param int $wait  Seconds to wait before the next run, if the CDN asked to slow down (updated).
	 * @return bool Whether some are left.
	 */
	private static function run_retire( &$calls, &$wait ) {
		$queue = self::retire_queue();
		if ( ! $queue ) {
			return false;
		}
		foreach ( $queue as $i => $entry ) {
			$c     = array(
				'provider' => isset( $entry['provider'] ) ? (string) $entry['provider'] : '',
				'zone'     => isset( $entry['zone'] ) ? (string) $entry['zone'] : '',
				'token'    => isset( $entry['token'] ) ? (string) $entry['token'] : '',
			);
			$items = isset( $entry['items'] ) && is_array( $entry['items'] ) ? $entry['items'] : array();
			foreach ( $items as $key => $rule ) {
				if ( $calls >= self::BATCH ) {
					break 2;
				}
				++$calls;
				$res = self::remove( $c, (string) $key, $rule );
				if ( 'ok' === $res['status'] ) {
					unset( $items[ $key ] );
				} elseif ( 'wait' === $res['status'] ) {
					$wait = 5 * MINUTE_IN_SECONDS;
					break 2;
				} elseif ( 'denied' === $res['status'] ) {
					$items = array(); // The old credentials no longer work: nothing more can be done with them.
					break;
				} else {
					break 2; // Network or server error: next run.
				}
			}
			if ( $items ) {
				$queue[ $i ]['items'] = $items;
			} else {
				unset( $queue[ $i ] );
			}
		}
		$queue = array_values( $queue );
		if ( $queue ) {
			update_option( self::RETIRE, $queue, false );
		} else {
			delete_option( self::RETIRE );
		}
		return (bool) $queue;
	}

	/**
	 * Brings the CDN in step with the active bans, for the current configuration.
	 *
	 * @param array{provider:string, zone:string, token:string} $c     Configuration.
	 * @param array<string, mixed>                              $state State (updated).
	 * @param int                                               $calls API calls made so far (updated).
	 * @return array{left:bool, wait:int}
	 */
	private static function run_config( $c, &$state, &$calls ) {
		$wanted = self::wanted( $c['provider'] );
		$rules  = $state['rules'];
		$todo   = array();
		foreach ( $rules as $key => $rule ) {
			if ( ! isset( $wanted[ $key ] ) ) {
				$todo[] = array( 'remove', (string) $key );
			}
		}
		$existing = null;
		foreach ( $wanted as $key => $ban ) {
			if ( isset( $rules[ $key ] ) ) {
				$rules[ $key ]['until'] = $ban['until']; // A renewed ban.
			} else {
				$todo[] = array( 'add', (string) $key );
			}
		}
		$state['rules'] = $rules;
		if ( ! $todo ) {
			$state['error'] = '';
			return array(
				'left' => false,
				'wait' => 0,
			);
		}
		$error = '';
		$wait  = 0;
		$done  = 0;
		foreach ( $todo as $job ) {
			if ( $calls >= self::BATCH ) {
				break;
			}
			list( $op, $key ) = $job;
			if ( 'remove' === $op ) {
				$rule = $state['rules'][ $key ];
				if ( empty( $rule['own'] ) ) {
					unset( $state['rules'][ $key ] ); // Blocked by the site owner before ScrapeLock: left as it is.
					++$done;
					continue;
				}
				++$calls;
				$res = self::remove( $c, $key, $rule );
				if ( 'ok' === $res['status'] || 'refused' === $res['status'] ) {
					// Removed, or the CDN does not accept removing it (then it cannot be done from here).
					unset( $state['rules'][ $key ] );
				}
			} else {
				if ( 'bunny' === $c['provider'] && null === $existing ) {
					// The addresses already in the pull zone's list: those were put there by the site owner,
					// so ScrapeLock does not add them again and never removes them.
					++$calls;
					$existing = self::bunny_blocked( $c );
					if ( ! is_array( $existing['list'] ) ) {
						$res      = $existing;
						$existing = array();
						$error    = $res['message'];
						$wait     = 'wait' === $res['status'] ? 5 * MINUTE_IN_SECONDS : 0;
						break;
					}
					$existing = $existing['list'];
				}
				if ( is_array( $existing ) && in_array( $key, $existing, true ) ) {
					$state['rules'][ $key ] = array(
						'id'    => '',
						'until' => $wanted[ $key ]['until'],
						'own'   => false,
					);
					++$done;
					continue;
				}
				++$calls;
				$res = self::add( $c, $key, $wanted[ $key ] );
				if ( in_array( $res['status'], array( 'ok', 'exists', 'refused' ), true ) ) {
					// Not ours ("exists": the site owner's own rule; "refused": the CDN does not accept this one
					// address) are kept as such, so they are not tried again and never removed.
					$state['rules'][ $key ] = array(
						'id'    => $res['id'],
						'until' => $wanted[ $key ]['until'],
						'own'   => 'ok' === $res['status'],
					);
				}
			}
			if ( 'ok' === $res['status'] || 'exists' === $res['status'] ) {
				++$done;
				continue;
			}
			$error = $res['message'];
			if ( 'refused' === $res['status'] ) {
				++$done; // This one address only; the others go on.
				continue;
			}
			// Wrong token or zone: no point retrying every few minutes. Rate limit, network or server error:
			// a few minutes.
			$wait = 'denied' === $res['status'] ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS;
			break;
		}
		if ( '' !== $error ) {
			$state['error']      = $error;
			$state['error_time'] = time();
		} else {
			$state['error'] = '';
		}
		return array(
			'left' => $done < count( $todo ),
			'wait' => $wait,
		);
	}

	/**
	 * Deactivation: removes the blocks ScrapeLock made (current and previous configurations), for at most
	 * the given number of seconds. Cloudflare rules that are left carry the note "ScrapeLock" and can be
	 * removed from the Cloudflare dashboard.
	 *
	 * @param int $seconds Time limit.
	 */
	public static function remove_all( $seconds = 20 ) {
		self::retire( self::config() );
		$until = time() + max( 1, (int) $seconds );
		while ( self::retire_queue() && time() < $until ) {
			$calls = 0;
			$wait  = 0;
			self::run_retire( $calls, $wait );
			if ( $wait || $calls < self::BATCH ) {
				break; // Finished, or stopped by an error: no point hammering the CDN.
			}
		}
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
	 * Removes one block that ScrapeLock made.
	 *
	 * @param array{provider:string, zone:string, token:string} $c    Configuration.
	 * @param string                                            $key  Ban key.
	 * @param array<string, mixed>                              $rule The block.
	 * @return array{status:string, message:string}
	 */
	private static function remove( $c, $key, $rule ) {
		if ( 'cloudflare' === $c['provider'] ) {
			$id = isset( $rule['id'] ) ? (string) $rule['id'] : '';
			if ( ! preg_match( '/^[A-Za-z0-9]{1,64}$/', $id ) ) {
				return array(
					'status'  => 'ok',
					'message' => '',
				);
			}
			$res = self::request( $c, 'DELETE', self::CLOUDFLARE_API . '/zones/' . rawurlencode( $c['zone'] ) . '/firewall/access_rules/rules/' . $id );
		} else {
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
		$remove = self::remove( $c, $ip, $rule );
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
		$res = self::request( $c, 'GET', self::CLOUDFLARE_API . '/zones/' . rawurlencode( $c['zone'] ) . '/firewall/access_rules/rules?' . http_build_query( array( 'configuration.value' => $ip ) ) );
		if ( 'ok' !== $res['status'] ) {
			return $res['message'];
		}
		foreach ( isset( $res['json']['result'] ) && is_array( $res['json']['result'] ) ? $res['json']['result'] : array() as $rule ) {
			if ( isset( $rule['configuration']['value'] ) && $ip === $rule['configuration']['value'] ) {
				return true;
			}
		}
		return false;
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
