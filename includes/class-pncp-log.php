<?php
/**
 * Αρχείο αποκλεισμών (πίνακας {prefix}pncp_log) και προσωρινοί αποκλεισμοί IP.
 *
 * Το αρχείο κρατά IP και User-Agent, δηλαδή προσωπικά δεδομένα: σβήνεται αυτόματα μετά από 1, 7 ή 30 ημέρες.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Καταγραφή και αποκλεισμοί.
 */
final class PNCP_Log {

	/**
	 * Έκδοση του σχήματος του πίνακα.
	 */
	const DB_VERSION = '2';

	/**
	 * Option όπου κρατούσε τους αποκλεισμούς η 2.1 (μεταφέρονται στον πίνακα στην αναβάθμιση).
	 */
	const BANS_OPTION = 'pncp_bans';

	/**
	 * Πόσοι αποκλεισμοί εμφανίζονται στη σελίδα ρυθμίσεων (ο πίνακας κρατά όλους).
	 */
	const MAX_BANS = 500;

	/**
	 * Cache του is_banned για το αίτημα.
	 *
	 * @var array<string, bool>
	 */
	private static $banned = array();

	/**
	 * Cron hook του καθαρισμού.
	 */
	const CRON = 'pncp_log_cleanup';

	/**
	 * Δένει τα hooks.
	 */
	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'cleanup' ) );
		add_action( 'admin_init', array( __CLASS__, 'privacy_policy' ) );
	}

	/**
	 * Το όνομα του πίνακα.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'pncp_log';
	}

	/**
	 * Ο πίνακας των αποκλεισμών. Μία γραμμή ανά IP, με ατομικό INSERT … ON DUPLICATE KEY UPDATE: η 2.1
	 * τους κρατούσε σε ένα option που ξαναγραφόταν ολόκληρο, και με 1500 ταυτόχρονους αποκλεισμούς
	 * κρατιόνταν μόνο ~150 (επιβεβαιωμένο σε δοκιμή φόρτου).
	 *
	 * @return string
	 */
	public static function bans_table() {
		global $wpdb;
		return $wpdb->prefix . 'pncp_bans';
	}

	/**
	 * Δημιουργεί ή ενημερώνει τον πίνακα.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created datetime NOT NULL,
			ip varchar(45) NOT NULL DEFAULT '',
			reason varchar(20) NOT NULL DEFAULT '',
			code smallint(5) unsigned NOT NULL DEFAULT 0,
			hits int(10) unsigned NOT NULL DEFAULT 1,
			path varchar(255) NOT NULL DEFAULT '',
			ua varchar(255) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY created (created),
			KEY ip (ip)
			) {$charset};"
		);
		$bans = self::bans_table();
		dbDelta(
			"CREATE TABLE {$bans} (
			ip varchar(45) NOT NULL,
			until_ts int(10) unsigned NOT NULL DEFAULT 0,
			since_ts int(10) unsigned NOT NULL DEFAULT 0,
			reason varchar(20) NOT NULL DEFAULT '',
			PRIMARY KEY  (ip),
			KEY until_ts (until_ts)
			) {$charset};"
		);
		// Μόνο αν οι πίνακες φτιάχτηκαν πραγματικά (π.χ. ο χρήστης της βάσης μπορεί να μην έχει CREATE).
		foreach ( array( $table, $bans ) as $name ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Έλεγχος σχήματος στην εγκατάσταση.
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $name ) ) ) !== $name ) {
				return;
			}
		}
		update_option( 'pncp_db_version', self::DB_VERSION, false );

		// Αποκλεισμοί της 2.1 (option) → πίνακας.
		$old = get_option( self::BANS_OPTION );
		if ( is_array( $old ) ) {
			foreach ( $old as $ip => $ban ) {
				if ( is_array( $ban ) && isset( $ban['until'] ) && (int) $ban['until'] > time() && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					self::store_ban( (string) $ip, (int) $ban['until'], isset( $ban['reason'] ) ? (string) $ban['reason'] : 'ban', isset( $ban['since'] ) ? (int) $ban['since'] : time() );
				}
			}
		}
		delete_option( self::BANS_OPTION );
	}

	/**
	 * Οι λόγοι αποκλεισμού με την περιγραφή τους.
	 *
	 * @return array<string, string>
	 */
	public static function reasons() {
		return array(
			'bot_ua'       => __( 'User-Agent στη λίστα bots', 'content-protect' ),
			'empty_ua'     => __( 'Χωρίς User-Agent', 'content-protect' ),
			'fake_crawler' => __( 'Ψεύτικη μηχανή αναζήτησης', 'content-protect' ),
			'no_browser'   => __( 'Χωρίς headers browser', 'content-protect' ),
			'rate_page'    => __( 'Όριο σελίδων', 'content-protect' ),
			'rate_search'  => __( 'Όριο αναζητήσεων', 'content-protect' ),
			'rate_rest'    => __( 'Όριο REST / GraphQL', 'content-protect' ),
			'trap'         => __( 'Παγίδα για bots', 'content-protect' ),
			'ban'          => __( 'Νέος προσωρινός αποκλεισμός', 'content-protect' ),
			'banned'       => __( 'Αίτημα από αποκλεισμένη IP', 'content-protect' ),
			'feed_denied'  => __( 'Ιδιωτικό URL χωρίς token', 'content-protect' ),
		);
	}

	/**
	 * Γράφει ένα συμβάν. Ίδια IP και λόγος μέσα στο ίδιο λεπτό γίνονται μία γραμμή με μετρητή,
	 * ώστε ένα bot που επιμένει να μη γεμίζει τη βάση.
	 *
	 * @param string $reason Λόγος (κλειδί του reasons()).
	 * @param int    $code   HTTP κωδικός.
	 * @param string $ip     IP.
	 */
	public static function add( $reason, $code, $ip ) {
		global $wpdb;
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return;
		}

		$key = 'pncp_lg_' . md5( $ip . '|' . $reason . '|' . (int) floor( time() / MINUTE_IN_SECONDS ) );
		$id  = (int) self::cache_get( $key );
		if ( $id > 0 ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Μετρητής, χωρίς cache.
			$wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = hits + 1 WHERE id = %d', self::table(), $id ) );
			return;
		}

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$ua   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin.
		$wpdb->insert(
			self::table(),
			array(
				'created' => gmdate( 'Y-m-d H:i:s' ),
				'ip'      => substr( $ip, 0, 45 ),
				'reason'  => substr( $reason, 0, 20 ),
				'code'    => (int) $code,
				'hits'    => 1,
				'path'    => mb_substr( $path, 0, 255 ),
				'ua'      => mb_substr( $ua, 0, 255 ),
			),
			array( '%s', '%s', '%s', '%d', '%d', '%s', '%s' )
		);
		if ( $wpdb->insert_id ) {
			self::cache_set( $key, (int) $wpdb->insert_id, 2 * MINUTE_IN_SECONDS );
		}
	}

	/**
	 * Σβήνει ό,τι είναι παλαιότερο από τη διατήρηση και τους αποκλεισμούς που έληξαν.
	 */
	public static function cleanup() {
		global $wpdb;
		$days   = max( 1, (int) PNCP_Options::stored()['log_retention'] );
		$before = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		if ( get_option( 'pncp_db_version' ) === self::DB_VERSION ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created < %s', self::table(), $before ) );
		}
		if ( get_option( 'pncp_db_version' ) === self::DB_VERSION ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE until_ts < %d', self::bans_table(), time() ) );
		}
		self::purge_expired_transients();
	}

	/**
	 * Σβήνει τα transients του plugin που έληξαν (μετρητές ορίων ανά IP και λεπτό, παραβάσεις). Το WordPress
	 * τα σβήνει μία φορά τη μέρα· σε επίθεση από χιλιάδες IP μαζεύονται χιλιάδες γραμμές, οπότε εδώ κάθε ώρα.
	 */
	public static function purge_expired_transients() {
		global $wpdb;
		if ( wp_using_ext_object_cache() ) {
			return;
		}
		$suppress = $wpdb->suppress_errors( true ); // Σύνταξη MySQL· σε άλλη βάση απλώς δεν γίνεται (το κάνει το WordPress μία φορά τη μέρα).
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Μαζικός καθαρισμός, όπως το delete_expired_transients() του WordPress.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE a, b FROM {$wpdb->options} a, {$wpdb->options} b
				WHERE a.option_name LIKE %s
				AND a.option_name NOT LIKE %s
				AND b.option_name = CONCAT( '_transient_timeout_', SUBSTRING( a.option_name, 12 ) )
				AND b.option_value < %d",
				$wpdb->esc_like( '_transient_pncp_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_' ) . '%',
				time()
			)
		);
		// phpcs:enable
		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * Σβήνει όλο το αρχείο.
	 */
	public static function clear() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::table() ) );
	}

	/**
	 * Οι τελευταίες εγγραφές.
	 *
	 * @param int $limit Πλήθος.
	 * @return array<int, array<string, mixed>>
	 */
	public static function recent( $limit = 100 ) {
		global $wpdb;
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return array();
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Οθόνη διαχείρισης.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY id DESC LIMIT %d', self::table(), max( 1, (int) $limit ) ), ARRAY_A );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Σύνοψη ενός διαστήματος: σύνολα ανά λόγο, κορυφαίες IP και User-Agents.
	 *
	 * @param int $hours Ώρες πίσω.
	 * @return array<string, mixed>
	 */
	public static function summary( $hours = 24 ) {
		global $wpdb;
		$empty = array(
			'total'   => 0,
			'reasons' => array(),
			'ips'     => array(),
			'uas'     => array(),
		);
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return $empty;
		}
		$since = gmdate( 'Y-m-d H:i:s', time() - (int) $hours * HOUR_IN_SECONDS );
		$table = self::table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Οθόνη διαχείρισης / widget.
		$reasons = $wpdb->get_results( $wpdb->prepare( 'SELECT reason, SUM(hits) AS n FROM %i WHERE created >= %s GROUP BY reason ORDER BY n DESC', $table, $since ), ARRAY_A );
		$ips     = $wpdb->get_results( $wpdb->prepare( 'SELECT ip, SUM(hits) AS n FROM %i WHERE created >= %s GROUP BY ip ORDER BY n DESC LIMIT 10', $table, $since ), ARRAY_A );
		$uas     = $wpdb->get_results( $wpdb->prepare( "SELECT ua, SUM(hits) AS n FROM %i WHERE created >= %s AND ua <> '' GROUP BY ua ORDER BY n DESC LIMIT 10", $table, $since ), ARRAY_A );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		$out = $empty;
		foreach ( (array) $reasons as $row ) {
			$out['reasons'][ $row['reason'] ] = (int) $row['n'];
			$out['total']                    += (int) $row['n'];
		}
		foreach ( (array) $ips as $row ) {
			$out['ips'][ $row['ip'] ] = (int) $row['n'];
		}
		foreach ( (array) $uas as $row ) {
			$out['uas'][ $row['ua'] ] = (int) $row['n'];
		}
		return $out;
	}

	/* ---------- Αποκλεισμοί ---------- */

	/**
	 * Είναι αποκλεισμένη η IP; Ένα ερώτημα στο PRIMARY KEY (ή στο object cache, αν υπάρχει).
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_banned( $ip ) {
		global $wpdb;
		if ( '' === $ip || get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return false;
		}
		if ( isset( self::$banned[ $ip ] ) ) {
			return self::$banned[ $ip ];
		}
		$key = 'pncp_ban_' . md5( $ip );
		if ( wp_using_ext_object_cache() ) {
			$until = wp_cache_get( $key, 'pncp' );
			if ( false !== $until ) {
				self::$banned[ $ip ] = (int) $until > time();
				return self::$banned[ $ip ];
			}
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin· η cache είναι παραπάνω.
		$until = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT until_ts FROM %i WHERE ip = %s', self::bans_table(), $ip ) );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $until, 'pncp', $until > time() ? $until - time() : 5 * MINUTE_IN_SECONDS );
		}
		self::$banned[ $ip ] = $until > time();
		return self::$banned[ $ip ];
	}

	/**
	 * Ξεχνά την cache αποκλεισμών του αιτήματος (σε μακρόβιες διεργασίες, π.χ. WP-CLI και tests).
	 */
	public static function reset_cache() {
		self::$banned = array();
	}

	/**
	 * Αποκλείει την IP για κάποια λεπτά.
	 *
	 * @param string $ip      IP.
	 * @param int    $minutes Λεπτά.
	 * @param string $reason  Αιτία (κλειδί του reasons()).
	 */
	public static function ban( $ip, $minutes, $reason ) {
		// Ποτέ οι IP της Google / Bing, όποιος κι αν προσπάθησε να τις «παγιδεύσει».
		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) || PNCP_Bots::is_official_crawler_ip( $ip ) ) {
			return;
		}
		$until = time() + max( 1, (int) $minutes ) * MINUTE_IN_SECONDS;
		self::store_ban( $ip, $until, $reason, time() );
		self::add( 'ban', 403, $ip );
	}

	/**
	 * Γράφει (ή ανανεώνει) έναν αποκλεισμό, ατομικά.
	 *
	 * @param string $ip     IP.
	 * @param int    $until  Λήξη.
	 * @param string $reason Αιτία.
	 * @param int    $since  Από πότε.
	 */
	private static function store_ban( $ip, $until, $reason, $since ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Ατομική εγγραφή στον πίνακα του plugin.
		$ok = $wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (ip, until_ts, since_ts, reason) VALUES (%s, %d, %d, %s) ON DUPLICATE KEY UPDATE since_ts = IF(until_ts <= UNIX_TIMESTAMP(), VALUES(since_ts), since_ts), until_ts = GREATEST(until_ts, VALUES(until_ts)), reason = VALUES(reason)',
				self::bans_table(),
				$ip,
				$until,
				$since,
				substr( (string) $reason, 0, 20 )
			)
		);
		if ( false === $ok ) {
			// Βάση χωρίς ON DUPLICATE KEY / GREATEST (π.χ. SQLite): REPLACE.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin.
			$wpdb->replace(
				self::bans_table(),
				array(
					'ip'       => $ip,
					'until_ts' => $until,
					'since_ts' => $since,
					'reason'   => substr( (string) $reason, 0, 20 ),
				),
				array( '%s', '%d', '%d', '%s' )
			);
		}
		self::$banned[ $ip ] = true;
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( 'pncp_ban_' . md5( $ip ), $until, 'pncp', max( 1, $until - time() ) );
		}
	}

	/**
	 * Άρση αποκλεισμού μιας IP.
	 *
	 * @param string $ip IP.
	 */
	public static function unban( $ip ) {
		global $wpdb;
		self::cache_delete( 'pncp_st_' . md5( $ip ) );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_delete( 'pncp_ban_' . md5( $ip ), 'pncp' );
		}
		unset( self::$banned[ $ip ] );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin.
		$wpdb->delete( self::bans_table(), array( 'ip' => $ip ), array( '%s' ) );
	}

	/**
	 * Άρση όλων των αποκλεισμών.
	 */
	public static function unban_all() {
		global $wpdb;
		foreach ( array_keys( self::active_bans( 0 ) ) as $ip ) {
			self::cache_delete( 'pncp_st_' . md5( (string) $ip ) );
			if ( wp_using_ext_object_cache() ) {
				wp_cache_delete( 'pncp_ban_' . md5( (string) $ip ), 'pncp' );
			}
		}
		self::$banned = array();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', self::bans_table() ) );
	}

	/**
	 * Οι ενεργοί αποκλεισμοί, οι πιο πρόσφατοι πρώτοι.
	 *
	 * @param int $limit Μέγιστο πλήθος (0 = όλοι).
	 * @return array<string, array<string, mixed>>
	 */
	public static function active_bans( $limit = self::MAX_BANS ) {
		global $wpdb;
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return array();
		}
		$sql = $wpdb->prepare( 'SELECT ip, until_ts, since_ts, reason FROM %i WHERE until_ts > %d ORDER BY since_ts DESC', self::bans_table(), time() );
		if ( (int) $limit > 0 ) {
			$sql .= $wpdb->prepare( ' LIMIT %d', (int) $limit );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- Πίνακας του plugin· prepared παραπάνω.
		$rows = (array) $wpdb->get_results( $sql, ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ (string) $row['ip'] ] = array(
				'until'  => (int) $row['until_ts'],
				'since'  => (int) $row['since_ts'],
				'reason' => (string) $row['reason'],
			);
		}
		return $out;
	}

	/**
	 * Πόσοι αποκλεισμοί ισχύουν τώρα.
	 *
	 * @return int
	 */
	public static function count_bans() {
		global $wpdb;
		if ( get_option( 'pncp_db_version' ) !== self::DB_VERSION ) {
			return 0;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Πίνακας του plugin.
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE until_ts > %d', self::bans_table(), time() ) );
	}

	/**
	 * Καταγράφει μια «παράβαση». Όταν φτάσουν το όριο μέσα σε 10 λεπτά, η IP αποκλείεται.
	 *
	 * @param string $ip     IP.
	 * @param string $reason Αιτία.
	 * @return bool Αν η IP μόλις αποκλείστηκε.
	 */
	public static function strike( $ip, $reason ) {
		$s       = PNCP_Options::get();
		$strikes = (int) $s['ban_strikes'];
		if ( $strikes < 1 || '' === $ip ) {
			return false;
		}
		$key   = 'pncp_st_' . md5( $ip );
		$count = (int) self::cache_get( $key ) + 1;
		self::cache_set( $key, $count, 10 * MINUTE_IN_SECONDS );
		if ( $count >= $strikes ) {
			self::cache_delete( $key );
			self::ban( $ip, (int) $s['ban_minutes'], $reason );
			return true;
		}
		return false;
	}

	/* ---------- Cache: object cache αν υπάρχει, αλλιώς transients ---------- */

	/**
	 * Ανάγνωση.
	 *
	 * @param string $key Κλειδί.
	 * @return mixed
	 */
	public static function cache_get( $key ) {
		return wp_using_ext_object_cache() ? wp_cache_get( $key, 'pncp' ) : get_transient( $key );
	}

	/**
	 * Εγγραφή.
	 *
	 * @param string $key   Κλειδί.
	 * @param mixed  $value Τιμή.
	 * @param int    $ttl   Δευτερόλεπτα.
	 */
	public static function cache_set( $key, $value, $ttl ) {
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $value, 'pncp', max( 1, (int) $ttl ) );
		} else {
			set_transient( $key, $value, max( 1, (int) $ttl ) );
		}
	}

	/**
	 * Διαγραφή.
	 *
	 * @param string $key Κλειδί.
	 */
	public static function cache_delete( $key ) {
		if ( wp_using_ext_object_cache() ) {
			wp_cache_delete( $key, 'pncp' );
		} else {
			delete_transient( $key );
		}
	}

	/**
	 * Πρόταση κειμένου για την Πολιτική απορρήτου.
	 */
	public static function privacy_policy() {
		if ( ! is_admin() || ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		wp_add_privacy_policy_content(
			__( 'Προστασία περιεχομένου', 'content-protect' ),
			'<p>' . esc_html__( 'Για την προστασία του περιεχομένου από αυτοματοποιημένη αντιγραφή, όταν ένα αίτημα μπλοκάρεται καταγράφουμε τη διεύθυνση IP, το User-Agent του browser, τη σελίδα και την ώρα. Τα στοιχεία αυτά διαγράφονται αυτόματα μετά από λίγες ημέρες και δεν χρησιμοποιούνται για άλλο σκοπό.', 'content-protect' ) . '</p>'
		);
	}
}
