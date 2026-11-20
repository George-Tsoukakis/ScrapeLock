<?php
/**
 * 3.12: the actions of the Traffic tab (PNCP_Admin_Traffic): "Start collecting", "Test this path", "Delete
 * collected traffic", "Block this User-Agent", "Always allow" and the CSV export. Each is an admin-post action with
 * a nonce and manage_options; the ones that change something are refused while the site is locked (Lockdown), and
 * Block / Allow save the settings as an earlier version (PNCP_Settings_Io::backup()) before they write one line.
 *
 * Block adds an exact entry ("=<the whole User-Agent>") to the bot list when the User-Agent fits in one entry (100
 * characters) as it is, else the product name it carries ("python-requests/"), and only one that does not match an
 * ordinary browser. Allow adds the whole User-Agent (as "Allow this service" does in the Log). Nothing is blocked or
 * allowed without the confirmation step, which shows the exact line first.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Traffic tab actions.
 */
final class PNCP_Traffic_Actions {

	/**
	 * The admin-post action (and nonce) of the changes.
	 */
	const ACTION = 'pncp_traffic';

	/**
	 * The admin-post action (and nonce) of the CSV export.
	 */
	const CSV = 'pncp_traffic_csv';

	/**
	 * Transient (per user) with the result of "Test this path".
	 */
	const TEST = 'pncp_tr_test_';

	/**
	 * Reasons of the saved versions.
	 */
	const REASON_BLOCK = 'traffic_block';
	const REASON_ALLOW = 'traffic_allow';
	const REASON_START = 'traffic_start';

	/**
	 * Most lines of the bot list and the allow list (PNCP_Options::parse_list()).
	 */
	const MAX_LINES = 200;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		add_action( 'admin_post_' . self::CSV, array( __CLASS__, 'handle_csv' ) );
	}

	/* ---------- Checks ---------- */

	/**
	 * Capability and nonce.
	 *
	 * @param string $nonce Nonce action.
	 */
	private static function verify( $nonce ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce );
	}

	/**
	 * Back to the Traffic tab.
	 *
	 * @param array<string, string> $args Query arguments (tr_view, tr_msg…).
	 */
	private static function back( $args ) {
		wp_safe_redirect( PNCP_Admin_Traffic::url_for( $args ) );
		exit;
	}

	/**
	 * The User-Agent of this request (the administrator's browser).
	 *
	 * @return string
	 */
	public static function own_ua() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? PNCP_Traffic::text( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 255 ) : '';
	}

	/**
	 * Is the User-Agent the administrator's own (or would the pattern also match it)?
	 *
	 * @param string $ua      User-Agent.
	 * @param string $pattern Bot list entry ('' = only compare the User-Agent).
	 * @return bool
	 */
	private static function is_own( $ua, $pattern = '' ) {
		$own = self::own_ua();
		if ( '' === $own ) {
			return false;
		}
		if ( 0 === strcasecmp( trim( $own ), trim( (string) $ua ) ) ) {
			return true;
		}
		return '' !== $pattern && PNCP_Bots::ua_in_list( $own, array( $pattern ) );
	}

	/**
	 * The line as the list keeps it (sanitize_text_field(), 100 characters): '' when it would change.
	 *
	 * @param string $line Line.
	 * @return string
	 */
	private static function kept( $line ) {
		$parsed = PNCP_Options::parse_list( $line );
		return 1 === count( $parsed ) && $parsed[0] === $line ? $line : '';
	}

	/**
	 * The product names of a User-Agent ("GPTBot", "python-requests"), without the browser words.
	 *
	 * @param string $ua User-Agent.
	 * @return string[]
	 */
	private static function product_tokens( $ua ) {
		$stop = array( 'mozilla', 'applewebkit', 'chrome', 'chromium', 'safari', 'gecko', 'firefox', 'version', 'mobile', 'edg', 'edge', 'opr', 'opera', 'khtml', 'trident', 'msie', 'crios', 'fxios', 'samsungbrowser', 'yabrowser', 'ucbrowser', 'windows', 'android', 'linux', 'cpu', 'os', 'iphone', 'ipad', 'mac', 'intel', 'x11', 'win64', 'wow64', 'x64', 'ubuntu', 'headlesschrome' );
		$out  = array();
		if ( preg_match_all( '#(?<![A-Za-z0-9._-])([A-Za-z][A-Za-z0-9._-]{2,40})/\d#', (string) $ua, $m ) ) {
			foreach ( $m[1] as $name ) {
				if ( ! in_array( strtolower( $name ), $stop, true ) ) {
					$out[] = $name;
				}
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * The bot list entry "Block this User-Agent" adds: the exact User-Agent ("=…") when the list can keep it as it
	 * is, else the first product name in it ("Name/") that matches no ordinary browser. '' when there is none.
	 *
	 * @param string $ua User-Agent.
	 * @return string
	 */
	public static function block_pattern( $ua ) {
		$ua = trim( (string) $ua );
		if ( '' === $ua ) {
			return '';
		}
		$exact = self::kept( '=' . $ua );
		if ( '' !== $exact && PNCP_Bots::ua_in_list( $ua, array( $exact ) ) ) {
			return $exact;
		}
		foreach ( self::product_tokens( $ua ) as $name ) {
			$token = self::kept( $name . '/' );
			if ( '' !== $token && '' === PNCP_Options::allow_token_refusal( $token ) && PNCP_Bots::ua_in_list( $ua, array( $token ) ) ) {
				return $token;
			}
		}
		return '';
	}

	/**
	 * The allow list entry "Always allow" adds: the whole User-Agent (as the list keeps it), so only this client
	 * passes. '' when the list would change it so that it no longer matches.
	 *
	 * @param string $ua User-Agent.
	 * @return string
	 */
	public static function allow_pattern( $ua ) {
		$ua      = trim( (string) $ua );
		$pattern = PNCP_Bot_Match::service_pattern( $ua );
		$pattern = '' === $pattern ? '' : self::kept( $pattern );
		return '' !== $pattern && false !== stripos( $ua, $pattern ) ? $pattern : '';
	}

	/**
	 * Is a line in a list already (case does not matter, as in the lists)?
	 *
	 * @param string $line Line.
	 * @param string $list The setting's text.
	 * @return bool
	 */
	private static function listed( $line, $list ) {
		return in_array( strtolower( $line ), array_map( 'strtolower', PNCP_Options::parse_list( $list ) ), true );
	}

	/**
	 * What "Block this User-Agent" would do.
	 *
	 * refusal: locked | empty | own | none (no safe entry) | exists (the bot list blocks it already) | allowed (an
	 * always-allowed entry lets it in, which wins over the bot list) | full, or ''. extra: the second confirmation
	 * is needed: crawler (a search engine) | browser (an ordinary browser), or ''. service: the plugin service bot
	 * it is (stays allowed while that plugin is active), or ''.
	 *
	 * @param string $ua User-Agent.
	 * @return array{pattern:string, refusal:string, extra:string, service:string, matched:string}
	 */
	public static function block_check( $ua ) {
		$ua      = trim( (string) $ua );
		$s       = PNCP_Options::get();
		$stored  = PNCP_Options::stored();
		$pattern = self::block_pattern( $ua );
		$entry   = '' === $ua ? null : PNCP_Bot_Match::entry( $ua, $s );
		$class   = PNCP_Traffic_Ua::classify( $ua );
		$bot     = PNCP_Plugin_Bots::match( $ua, '' );
		$out     = array(
			'pattern' => $pattern,
			'refusal' => '',
			'extra'   => '',
			'service' => null !== $bot && isset( PNCP_Plugin_Bots::registry()[ $bot['id'] ] ) ? (string) PNCP_Plugin_Bots::registry()[ $bot['id'] ]['name'] : '',
			'matched' => null !== $entry ? (string) $entry['token'] : '',
		);
		if ( '' !== PNCP_Bots::claimed_crawler( $ua ) || 'verified_bot' === $class['family'] ) {
			$out['extra'] = 'crawler';
		} elseif ( 'browser' === $class['family'] ) {
			$out['extra'] = 'browser';
		}
		if ( PNCP_Lockdown::is_locked() ) {
			$out['refusal'] = 'locked';
		} elseif ( '' === $ua ) {
			$out['refusal'] = 'empty';
		} elseif ( self::is_own( $ua, $pattern ) ) {
			$out['refusal'] = 'own';
		} elseif ( null !== $entry ) {
			$out['refusal'] = 'exists';
		} elseif ( '' === $pattern ) {
			$out['refusal'] = 'none';
		} elseif ( PNCP_Bots::allow_list_match( $ua, '', array( 'allow_list' => (string) $stored['allow_list'] ) ) ) {
			$out['refusal'] = 'allowed';
		} elseif ( count( PNCP_Options::parse_list( (string) $stored['bot_list'] ) ) >= self::MAX_LINES ) {
			$out['refusal'] = 'full';
		}
		return $out;
	}

	/**
	 * What "Always allow" would do.
	 *
	 * refusal: locked | empty | crawler (search engines are let in from their own addresses; an entry would let
	 * the fakes in too) | browser (browsers are not blocked by the bot list) | generic | exists | full | none, or ''.
	 *
	 * @param string $ua User-Agent.
	 * @return array{pattern:string, refusal:string, blocked:string}
	 */
	public static function allow_check( $ua ) {
		$ua      = trim( (string) $ua );
		$stored  = PNCP_Options::stored();
		$pattern = self::allow_pattern( $ua );
		$class   = PNCP_Traffic_Ua::classify( $ua );
		$entry   = '' === $ua ? null : PNCP_Bot_Match::entry( $ua, PNCP_Options::get() );
		$out     = array(
			'pattern' => $pattern,
			'refusal' => '',
			'blocked' => null !== $entry ? (string) $entry['token'] : '',
		);
		if ( PNCP_Lockdown::is_locked() ) {
			$out['refusal'] = 'locked';
		} elseif ( '' === $ua ) {
			$out['refusal'] = 'empty';
		} elseif ( '' !== PNCP_Bots::claimed_crawler( $ua ) || in_array( $class['family'], array( 'verified_bot', 'fake_bot' ), true ) ) {
			$out['refusal'] = 'crawler';
		} elseif ( 'browser' === $class['family'] ) {
			$out['refusal'] = 'browser';
		} elseif ( '' === $pattern ) {
			$out['refusal'] = 'none';
		} elseif ( '' !== PNCP_Options::allow_token_refusal( $pattern ) ) {
			$out['refusal'] = 'generic';
		} elseif ( self::listed( $pattern, (string) $stored['allow_list'] ) || PNCP_Bots::allow_list_match( $ua, '', array( 'allow_list' => (string) $stored['allow_list'] ) ) ) {
			$out['refusal'] = 'exists';
		} elseif ( count( PNCP_Options::parse_list( (string) $stored['allow_list'] ) ) >= self::MAX_LINES ) {
			$out['refusal'] = 'full';
		}
		return $out;
	}

	/**
	 * Stores the settings with one more line in a list, without emptying the page cache (only a list changes, as
	 * for "Block permanently" in the Log).
	 *
	 * @param string $key  bot_list | allow_list.
	 * @param string $line Line.
	 * @return bool Whether exactly one line was added.
	 */
	private static function add_line( $key, $line ) {
		$stored = PNCP_Options::stored();
		$before = PNCP_Options::parse_list( (string) $stored[ $key ] );
		$list   = $before;
		$list[] = $line;

		$stored[ $key ] = implode( "\n", $list );
		$purge          = has_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache' );
		if ( false !== $purge ) {
			remove_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache', $purge );
		}
		update_option( PNCP_OPTION, $stored );
		if ( false !== $purge ) {
			add_action( 'update_option_' . PNCP_OPTION, 'pncp_purge_page_cache', $purge );
		}
		PNCP_Options::flush();
		$after = PNCP_Options::parse_list( (string) PNCP_Options::stored()[ $key ] );
		return count( $after ) === count( $before ) + 1 && self::listed( $line, implode( "\n", $after ) );
	}

	/**
	 * Adds the block entry of a User-Agent to the bot list, after the checks and an earlier version.
	 *
	 * @param string $ua       User-Agent.
	 * @param string $expected The entry the confirmation showed (refused when it differs now).
	 * @param bool   $extra    The second confirmation (search engine, browser) was given.
	 * @return array{0:string, 1:string} Result (added | changed | extra | the refusals of block_check() | error) and the saved version's ID.
	 */
	public static function block( $ua, $expected, $extra ) {
		$check = self::block_check( $ua );
		if ( '' !== $check['refusal'] ) {
			return array( $check['refusal'], '' );
		}
		if ( ! hash_equals( $check['pattern'], (string) $expected ) ) {
			return array( 'changed', '' );
		}
		if ( '' !== $check['extra'] && ! $extra ) {
			return array( 'extra', '' );
		}
		$undo = PNCP_Settings_Io::backup( self::REASON_BLOCK );
		return array( self::add_line( 'bot_list', $check['pattern'] ) ? 'added' : 'error', $undo );
	}

	/**
	 * Adds the allow entry of a User-Agent to "Always allowed User-Agents", after the checks and an earlier version.
	 *
	 * @param string $ua       User-Agent.
	 * @param string $expected The entry the confirmation showed.
	 * @return array{0:string, 1:string} Result and the saved version's ID.
	 */
	public static function allow( $ua, $expected ) {
		$check = self::allow_check( $ua );
		if ( '' !== $check['refusal'] ) {
			return array( $check['refusal'], '' );
		}
		if ( ! hash_equals( $check['pattern'], (string) $expected ) ) {
			return array( 'changed', '' );
		}
		$undo = PNCP_Settings_Io::backup( self::REASON_ALLOW );
		return array( self::add_line( 'allow_list', $check['pattern'] ) ? 'added' : 'error', $undo );
	}

	/* ---------- Sources ---------- */

	/**
	 * Access log paths that are often used (checked by "Start collecting" when no source is set).
	 *
	 * @return string[]
	 */
	public static function log_candidates() {
		$host = sanitize_file_name( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$list = array(
			'/var/log/nginx/access.log',
			'/var/log/nginx/' . $host . '.access.log',
			'/var/log/nginx/' . $host . '-access.log',
			'/var/log/apache2/access.log',
			'/var/log/apache2/' . $host . '-access.log',
			'/var/log/httpd/access_log',
			'/var/log/httpd/access.log',
		);
		/**
		 * Filters the access log paths "Start collecting" tries when no source is set.
		 *
		 * @since 3.12.0
		 * @param string[] $list Absolute paths.
		 */
		return array_values( array_filter( array_map( 'strval', (array) apply_filters( 'pncp_traffic_log_candidates', $list ) ) ) );
	}

	/**
	 * The source "Start collecting" recommends and the settings it changes for it: the Bunny CDN logs when they are
	 * imported (they also hold the pages served from the CDN's cache), else the access log set or found, else
	 * WordPress itself.
	 *
	 * @return array{source:string, changes:array<string, mixed>, path:string}
	 */
	public static function recommended() {
		$t = PNCP_Traffic::settings();
		if ( PNCP_Traffic::bunny_on() ) {
			return array(
				'source'  => 'bunny',
				'changes' => array(),
				'path'    => '',
			);
		}
		if ( '' !== $t['log_path'] ) {
			return array(
				'source'  => 'server',
				'changes' => array(),
				'path'    => $t['log_path'],
			);
		}
		foreach ( PNCP_Traffic_Log::user_may_read() ? self::log_candidates() : array() as $path ) {
			$test = PNCP_Traffic::test_log_path( $path );
			if ( 'ok' === $test['code'] ) {
				return array(
					'source'  => 'server',
					'changes' => array( 'traffic_log_path' => $path ),
					'path'    => $path,
				);
			}
		}
		return array(
			'source'  => 'wp',
			'changes' => $t['wp'] ? array() : array( 'traffic_wp' => 1 ),
			'path'    => '',
		);
	}

	/* ---------- Handlers ---------- */

	/**
	 * The changes: start, purge, test_path, block, allow.
	 */
	public static function handle() {
		self::verify( self::ACTION );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked in verify().
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( 'test_path' === $op ) {
			if ( ! PNCP_Traffic_Log::user_may_read() ) {
				self::back(
					array(
						'tr_view' => 'settings',
						'tr_msg'  => 'network_only',
					)
				);
			}
			$path = isset( $_POST['path'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['path'] ) ) ) : '';
			$path = substr( $path, 0, 500 );
			set_transient( self::TEST . get_current_user_id(), array( $path, PNCP_Traffic::test_log_path( $path ) ), 5 * MINUTE_IN_SECONDS );
			self::back(
				array(
					'tr_view' => 'settings',
					'tr_msg'  => 'tested',
				)
			);
		}
		if ( PNCP_Lockdown::is_locked() ) {
			self::back( array( 'tr_msg' => 'locked' ) );
		}
		switch ( $op ) {
			case 'start':
				$rec     = self::recommended();
				$changes = array_merge( $rec['changes'], array( 'traffic' => 1 ) );
				// 3.12.1: the IP addresses choice of the start screen (Masked chosen in advance); none sent = as stored.
				$mode = isset( $_POST['ip_mode'] ) ? sanitize_key( wp_unslash( $_POST['ip_mode'] ) ) : '';
				if ( in_array( $mode, array( 'masked', 'full' ), true ) ) {
					$changes['traffic_ip_mode'] = $mode;
				}
				PNCP_Settings_Io::backup( self::REASON_START );
				update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
				PNCP_Options::flush();
				PNCP_Traffic::maybe_schedule();
				self::back( array( 'tr_msg' => 'started' ) );
				break;
			case 'purge':
				if ( empty( $_POST['confirm'] ) ) {
					self::back(
						array(
							'tr_view' => 'settings',
							'tr_msg'  => 'purge_unconfirmed',
						)
					);
				}
				PNCP_Traffic::purge_all();
				self::back(
					array(
						'tr_view' => 'settings',
						'tr_msg'  => 'purged',
					)
				);
				break;
			case 'block':
			case 'allow':
				$ua       = isset( $_POST['ua'] ) && is_string( $_POST['ua'] ) ? PNCP_Traffic::text( wp_unslash( $_POST['ua'] ), 255 ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Control characters removed by text(); only compared and turned into a list line that the list sanitizes, never printed unescaped.
				$expected = isset( $_POST['pattern'] ) && is_string( $_POST['pattern'] ) ? wp_unslash( $_POST['pattern'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared with hash_equals() to the entry worked out again here.
				if ( empty( $_POST['confirm'] ) ) {
					$result = array( 'unconfirmed', '' );
				} elseif ( 'block' === $op ) {
					$result = self::block( trim( $ua ), $expected, ! empty( $_POST['confirm_extra'] ) );
				} else {
					$result = self::allow( trim( $ua ), $expected );
				}
				$args = array(
					'tr_view' => 'ua',
					'tr_key'  => trim( $ua ),
					'tr_msg'  => $op . '_' . $result[0],
				);
				if ( '' !== $result[1] ) {
					$args['pncp_undo'] = $result[1];
				}
				self::back( $args );
				break;
		}
		self::back( array( 'tr_msg' => 'error' ) );
		// phpcs:enable
	}

	/**
	 * "Export CSV": the raw requests with the filters of the screen, as a download.
	 */
	public static function handle_csv() {
		self::verify( self::CSV );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked in verify(); every value is checked in state().
		$state   = PNCP_Admin_Traffic::state( wp_unslash( $_POST ) );
		$filters = PNCP_Admin_Traffic::filters( $state );
		$host    = sanitize_file_name( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$handle  = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- A download streamed to the browser.
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="scrapelock-traffic-' . $host . '-' . wp_date( 'Y-m-d' ) . '.csv"' );
		header( 'X-Content-Type-Options: nosniff' );
		if ( false !== $handle ) {
			PNCP_Traffic::export_csv( $filters, $handle );
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
		}
		exit;
	}

	/* ---------- Notices ---------- */

	/**
	 * The notice of a result code (tr_msg): type and one sentence.
	 *
	 * @param string $code Code.
	 * @return array{0:string, 1:string}|null
	 */
	public static function notice( $code ) {
		$texts = array(
			'started'           => array( 'success', __( 'Collecting traffic: the first figures appear within 15 minutes, so come back to this tab soon.', 'scrapelock' ) ),
			'purged'            => array( 'success', __( 'The collected traffic was deleted; collection goes on if it is on.', 'scrapelock' ) ),
			'purge_unconfirmed' => array( 'error', __( 'Nothing was deleted: tick the confirmation box, then press the button again.', 'scrapelock' ) ),
			'tested'            => array( 'info', '' ),
			'locked'            => array( 'error', __( 'Nothing changed: the site is locked, so unlock it on the Lockdown tab first.', 'scrapelock' ) ),
			'network_only'      => array( 'error', __( 'Nothing was read: on a network only a network administrator may read the server\'s access log.', 'scrapelock' ) ),
			'error'             => array( 'error', __( 'The action was not completed: reload the page and try again.', 'scrapelock' ) ),
			'block_added'       => array( 'success', __( 'The User-Agent was added to the bot list; remove it under “Bots and limits” → “Bot list” or use Undo.', 'scrapelock' ) ),
			'allow_added'       => array( 'success', __( 'The User-Agent was added to “Always allowed User-Agents”; remove it under “Bots and limits” or use Undo.', 'scrapelock' ) ),
			'block_exists'      => array( 'info', __( 'Nothing changed: the bot list already blocks this User-Agent.', 'scrapelock' ) ),
			'allow_exists'      => array( 'info', __( 'Nothing changed: this User-Agent is already always allowed.', 'scrapelock' ) ),
			'block_unconfirmed' => array( 'error', __( 'Nothing changed: tick “Yes, add this line”, then press the button again.', 'scrapelock' ) ),
			'allow_unconfirmed' => array( 'error', __( 'Nothing changed: tick “Yes, add this line”, then press the button again.', 'scrapelock' ) ),
			'block_extra'       => array( 'error', __( 'Nothing changed: tick the second box to confirm you mean this User-Agent, then try again.', 'scrapelock' ) ),
			'block_changed'     => array( 'error', __( 'Nothing changed: the line to add is different now, so check it again below.', 'scrapelock' ) ),
			'allow_changed'     => array( 'error', __( 'Nothing changed: the line to add is different now, so check it again below.', 'scrapelock' ) ),
			'block_full'        => array( 'error', __( 'Nothing changed: the bot list has 200 lines, so remove some under “Bots and limits” first.', 'scrapelock' ) ),
			'allow_full'        => array( 'error', __( 'Nothing changed: the always-allowed User-Agents have 200 lines, so remove some first.', 'scrapelock' ) ),
			'block_own'         => array( 'error', __( 'Nothing changed: this would block your own browser, so it is never added.', 'scrapelock' ) ),
			'block_allowed'     => array( 'error', __( 'Nothing changed: an always-allowed entry lets it in, so remove that entry first.', 'scrapelock' ) ),
			'block_none'        => array( 'error', __( 'Nothing changed: no safe line was found, so add a part of it under “Bots and limits” → “Bot list”.', 'scrapelock' ) ),
			'block_empty'       => array( 'error', __( 'Nothing changed: use “Block requests without a User-Agent” under “Bots and limits” instead.', 'scrapelock' ) ),
			'allow_empty'       => array( 'error', __( 'Nothing changed: a request without a User-Agent cannot be allowed by name.', 'scrapelock' ) ),
			'allow_crawler'     => array( 'error', __( 'Nothing changed: search engines are let in from their own addresses, so no entry is needed.', 'scrapelock' ) ),
			'allow_browser'     => array( 'error', __( 'Nothing changed: browsers are not blocked by the bot list, so no entry is needed.', 'scrapelock' ) ),
			'allow_generic'     => array( 'error', __( 'Nothing changed: this would also match ordinary browsers, so add a narrower part by hand.', 'scrapelock' ) ),
			'allow_none'        => array( 'error', __( 'Nothing changed: no safe line was found, so add a part of it under “Bots and limits” → “Always allowed”.', 'scrapelock' ) ),
			'block_locked'      => array( 'error', __( 'Nothing changed: the site is locked, so unlock it on the Lockdown tab first.', 'scrapelock' ) ),
			'allow_locked'      => array( 'error', __( 'Nothing changed: the site is locked, so unlock it on the Lockdown tab first.', 'scrapelock' ) ),
			'block_error'       => array( 'error', __( 'The line could not be saved: reload the page and try again.', 'scrapelock' ) ),
			'allow_error'       => array( 'error', __( 'The line could not be saved: reload the page and try again.', 'scrapelock' ) ),
		);
		return isset( $texts[ $code ] ) ? $texts[ $code ] : null;
	}
}
