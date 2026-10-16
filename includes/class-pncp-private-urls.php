<?php
/**
 * Προστατευμένα feeds: XML προϊόντων (Skroutz, BestPrice, Google Merchant κ.λπ.) και ό,τι άλλο δίνει όλο
 * το κείμενο σε ένα αρχείο. Πρόσβαση μόνο με μυστικό token ή από επιτρεπόμενες IP.
 *
 * Το token γίνεται δεκτό:
 * - στο header X-Content-Protect-Token ή Authorization: Bearer … (για ERP και δικά σας integrations)·
 * - στο URL, ?cp_token=… (για Skroutz, BestPrice, Google Merchant, που δέχονται μόνο URL).
 *
 * Στη βάση αποθηκεύεται μόνο το SHA-256 του token. Το token φαίνεται μία φορά, όταν δημιουργείται.
 * Με την εναλλαγή, το παλιό token ισχύει για λίγες ημέρες ακόμη (περίοδος χάριτος).
 *
 * Ισχύει για URLs που σερβίρει η PHP. Στατικά αρχεία (π.χ. .xml μέσα στο uploads) τα σερβίρει
 * απευθείας ο web server· για αυτά δείτε τους κανόνες server.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Έλεγχος πρόσβασης σε URLs της λίστας.
 */
final class PNCP_Private_Urls {

	const QUERY_ARG = 'cp_token';

	/**
	 * Option με τα hashes των tokens (όχι autoload).
	 */
	const TOKEN_OPTION = 'pncp_feed_token';

	/**
	 * Option με τα στατιστικά ανά μοτίβο (όχι autoload).
	 */
	const STATS_OPTION = 'pncp_feed_stats';

	/**
	 * Αν το τρέχον αίτημα πέρασε τον έλεγχο (για να μην το μπλοκάρει μετά ο έλεγχος bots).
	 *
	 * @var bool
	 */
	private static $granted = false;

	/**
	 * Δένει τα hooks. Τρέχει νωρίς, πριν τα plugins των feeds βγάλουν το XML.
	 */
	public static function init() {
		add_action( 'plugins_loaded', array( __CLASS__, 'guard' ), 0 );
	}

	/**
	 * Πέρασε το τρέχον αίτημα τον έλεγχο ιδιωτικού URL;
	 *
	 * @return bool
	 */
	public static function granted() {
		return self::$granted;
	}

	/**
	 * Μπλοκάρει (403) όταν το URL είναι στη λίστα και δεν υπάρχει σωστό token ή επιτρεπόμενη IP.
	 */
	public static function guard() {
		self::$granted = false;
		$s             = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || '' === trim( (string) $s['private_paths'] ) ) {
			return;
		}

		$path    = self::request_path();
		$pattern = '' === $path ? '' : self::matching_pattern( $path, PNCP_Options::parse_list( $s['private_paths'] ) );
		if ( '' === $pattern ) {
			return;
		}

		// Ούτε η επιτυχής απάντηση μπαίνει σε κοινή cache: πολλά CDN αγνοούν το query string,
		// οπότε το feed με το token θα σερβιριζόταν μετά και χωρίς token.
		PNCP_Bots::no_cache();
		header( 'Cache-Control: private, no-store, max-age=0' );
		header( 'X-Robots-Tag: noindex, nofollow' );
		// Το token μπορεί να είναι στο URL: δεν διαρρέει μέσω Referer σε άλλα sites.
		header( 'Referrer-Policy: no-referrer' );
		header( 'X-Content-Type-Options: nosniff' );

		$via = self::access_via( $s );
		self::record( $pattern, $via );
		if ( '' !== $via ) {
			self::$granted = true;
			return;
		}

		PNCP_Log::add( 'feed_denied', 403, PNCP_Ip::client_ip() );
		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		// Χωρίς μετάφραση: τρέχει πριν φορτωθούν οι μεταφράσεις (init).
		echo 'Forbidden';
		exit;
	}

	/**
	 * Πώς επιτρέπεται η πρόσβαση: 'header', 'url', 'ip', 'admin' ή '' (δεν επιτρέπεται).
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 * @return string
	 */
	public static function access_via( $s ) {
		$header = self::header_token();
		if ( '' !== $header && self::token_valid( $header ) ) {
			return 'header';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Token πρόσβασης, όχι φόρμα.
		$query = isset( $_GET[ self::QUERY_ARG ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::QUERY_ARG ] ) ) : '';
		if ( '' !== $query && self::token_valid( $query ) ) {
			return 'url';
		}

		$ip = PNCP_Ip::client_ip();
		if ( '' !== $ip && PNCP_Ip::reliable() && PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( $s['private_ips'] ) ) ) {
			return 'ip';
		}

		return current_user_can( 'manage_options' ) ? 'admin' : '';
	}

	/**
	 * Το token από X-Content-Protect-Token ή Authorization: Bearer.
	 * Ο Apache με PHP-FPM/CGI κρύβει το Authorization: δείτε τον κανόνα στο README.
	 *
	 * @return string
	 */
	private static function header_token() {
		foreach ( array( 'HTTP_X_CONTENT_PROTECT_TOKEN' ) as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				return trim( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) );
			}
		}
		foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$value = trim( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) );
				if ( 0 === stripos( $value, 'Bearer ' ) ) {
					return trim( substr( $value, 7 ) );
				}
			}
		}
		return '';
	}

	/* ---------- Tokens ---------- */

	/**
	 * Τα αποθηκευμένα στοιχεία του token.
	 *
	 * @return array{hash:string, hint:string, created:int, prev_hash:string, prev_hint:string, prev_until:int}
	 */
	public static function token_data() {
		$data = get_option( self::TOKEN_OPTION, array() );
		$data = is_array( $data ) ? $data : array();
		return array(
			'hash'       => isset( $data['hash'] ) ? (string) $data['hash'] : '',
			'hint'       => isset( $data['hint'] ) ? (string) $data['hint'] : '',
			'created'    => isset( $data['created'] ) ? (int) $data['created'] : 0,
			'prev_hash'  => isset( $data['prev_hash'] ) ? (string) $data['prev_hash'] : '',
			'prev_hint'  => isset( $data['prev_hint'] ) ? (string) $data['prev_hint'] : '',
			'prev_until' => isset( $data['prev_until'] ) ? (int) $data['prev_until'] : 0,
		);
	}

	/**
	 * Hash ενός token.
	 *
	 * @param string $token Token.
	 * @return string
	 */
	public static function hash( $token ) {
		return hash( 'sha256', (string) $token );
	}

	/**
	 * Ισχύει το token; (το τρέχον, ή το προηγούμενο μέσα στην περίοδο χάριτος)
	 *
	 * @param string $token Token.
	 * @return bool
	 */
	public static function token_valid( $token ) {
		$token = (string) $token;
		if ( strlen( $token ) < 16 ) {
			return false;
		}
		$data = self::token_data();
		$hash = self::hash( $token );
		if ( '' !== $data['hash'] && hash_equals( $data['hash'], $hash ) ) {
			return true;
		}
		return '' !== $data['prev_hash'] && $data['prev_until'] > time() && hash_equals( $data['prev_hash'], $hash );
	}

	/**
	 * Νέο token. Το προηγούμενο ισχύει ακόμη για $grace_days ημέρες (0 = ακυρώνεται αμέσως).
	 *
	 * @param int $grace_days Ημέρες χάριτος.
	 * @return string Το νέο token (δεν αποθηκεύεται πουθενά σε καθαρή μορφή).
	 */
	public static function rotate( $grace_days ) {
		$old        = self::token_data();
		$token      = wp_generate_password( 40, false, false );
		$data       = array(
			'hash'       => self::hash( $token ),
			'hint'       => substr( $token, -4 ),
			'created'    => time(),
			'prev_hash'  => '',
			'prev_hint'  => '',
			'prev_until' => 0,
		);
		$grace_days = max( 0, min( 90, (int) $grace_days ) );
		if ( '' !== $old['hash'] && $grace_days > 0 ) {
			$data['prev_hash']  = $old['hash'];
			$data['prev_hint']  = $old['hint'];
			$data['prev_until'] = time() + $grace_days * DAY_IN_SECONDS;
		}
		update_option( self::TOKEN_OPTION, $data, false );
		return $token;
	}

	/**
	 * Αποθηκεύει ένα υπάρχον token (μετάβαση από την 1.4, όπου το token ήταν σε καθαρή μορφή).
	 *
	 * @param string $token Token.
	 */
	public static function import_plain( $token ) {
		$token = (string) $token;
		if ( strlen( $token ) < 16 ) {
			return;
		}
		update_option(
			self::TOKEN_OPTION,
			array(
				'hash'       => self::hash( $token ),
				'hint'       => substr( $token, -4 ),
				'created'    => time(),
				'prev_hash'  => '',
				'prev_hint'  => '',
				'prev_until' => 0,
			),
			false
		);
	}

	/**
	 * Ακυρώνει αμέσως το προηγούμενο token.
	 */
	public static function revoke_previous() {
		$data               = self::token_data();
		$data['prev_hash']  = '';
		$data['prev_hint']  = '';
		$data['prev_until'] = 0;
		update_option( self::TOKEN_OPTION, $data, false );
	}

	/* ---------- Στατιστικά ---------- */

	/**
	 * Καταγράφει την πρόσβαση στο μοτίβο: μετρητές, τελευταία επιτυχής πρόσβαση και τρόπος.
	 *
	 * @param string $pattern Μοτίβο της λίστας.
	 * @param string $via     Τρόπος πρόσβασης ('' = άρνηση).
	 */
	private static function record( $pattern, $via ) {
		$stats = self::stats();
		$key   = strtolower( $pattern );
		$row   = isset( $stats[ $key ] ) ? $stats[ $key ] : array(
			'ok'        => 0,
			'denied'    => 0,
			'last_ok'   => 0,
			'last_via'  => '',
			'last_ip'   => '',
			'last_deny' => 0,
		);
		if ( '' === $via ) {
			// Οι αρνήσεις τις προκαλεί ο καθένας: εγγραφή στη βάση το πολύ μία φορά το λεπτό ανά διαδρομή.
			$throttle = 'pncp_fd_' . md5( $key );
			if ( PNCP_Log::cache_get( $throttle ) ) {
				return;
			}
			PNCP_Log::cache_set( $throttle, 1, MINUTE_IN_SECONDS );
			++$row['denied'];
			$row['last_deny'] = time();
		} else {
			++$row['ok'];
			$row['last_ok']  = time();
			$row['last_via'] = $via;
			$row['last_ip']  = PNCP_Ip::client_ip();
		}
		$stats[ $key ] = $row;
		update_option( self::STATS_OPTION, array_slice( $stats, 0, 200, true ), false );
	}

	/**
	 * Τα στατιστικά: μοτίβο (πεζά) => στοιχεία.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function stats() {
		$stats = get_option( self::STATS_OPTION, array() );
		return is_array( $stats ) ? $stats : array();
	}

	/* ---------- Διαδρομές ---------- */

	/**
	 * Η διαδρομή του αιτήματος, σχετική με τη ρίζα του site (π.χ. /skroutz.xml).
	 *
	 * @return string
	 */
	private static function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Μόνο σύγκριση με μοτίβα.
		$path = self::relative_path( rawurldecode( (string) wp_parse_url( (string) $uri, PHP_URL_PATH ) ) );
		// Το WordPress δέχεται και τη μορφή /index.php/διαδρομή.
		if ( 0 === stripos( $path, '/index.php/' ) ) {
			$path = substr( $path, strlen( '/index.php' ) );
		}
		return $path;
	}

	/**
	 * Αφαιρεί τον υποφάκελο της εγκατάστασης (π.χ. /blog) από μια διαδρομή.
	 *
	 * @param string $path Διαδρομή.
	 * @return string
	 */
	public static function relative_path( $path ) {
		$path = '/' . ltrim( (string) $path, '/' );
		$home = rtrim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		return $path;
	}

	/**
	 * Το πρώτο μοτίβο που ταιριάζει με τη διαδρομή ('' = κανένα). Το * σημαίνει «οτιδήποτε».
	 *
	 * @param string   $path     Διαδρομή.
	 * @param string[] $patterns Μοτίβα (διαδρομές ή πλήρη URLs).
	 * @return string
	 */
	public static function matching_pattern( $path, $patterns ) {
		foreach ( $patterns as $pattern ) {
			$p = (string) wp_parse_url( $pattern, PHP_URL_PATH );
			if ( '' === $p ) {
				continue;
			}
			$p = self::relative_path( $p );
			// Με ή χωρίς / στο τέλος (το WordPress δέχεται και τα δύο για τις περισσότερες διαδρομές).
			$regex = '#^' . str_replace( '\*', '.*', preg_quote( untrailingslashit( $p ), '#' ) ) . '/?$#i';
			if ( preg_match( $regex, $path ) ) {
				return $pattern;
			}
		}
		return '';
	}

	/**
	 * Ταιριάζει η διαδρομή με κάποιο μοτίβο;
	 *
	 * @param string   $path     Διαδρομή.
	 * @param string[] $patterns Μοτίβα.
	 * @return bool
	 */
	public static function path_matches( $path, $patterns ) {
		return '' !== self::matching_pattern( $path, $patterns );
	}

	/**
	 * Ανήκει η IP σε μια IP ή CIDR; (για συμβατότητα με την 1.4)
	 *
	 * @param string $ip    IP.
	 * @param string $range IP ή CIDR.
	 * @return bool
	 */
	public static function ip_in_range( $ip, $range ) {
		return PNCP_Ip::in_range( $ip, $range );
	}

	/**
	 * Το URL ενός μοτίβου με το token, για τη σελίδα ρυθμίσεων.
	 *
	 * @param string $pattern Μοτίβο.
	 * @param string $token   Token.
	 * @return string
	 */
	public static function example_url( $pattern, $token ) {
		$path = self::relative_path( (string) wp_parse_url( $pattern, PHP_URL_PATH ) );
		if ( false !== strpos( $path, '*' ) ) {
			$path = '/feed.xml'; // Μοτίβο με *: δείχνουμε ένα γενικό παράδειγμα.
		}
		return add_query_arg( self::QUERY_ARG, rawurlencode( $token ), home_url( $path ) );
	}
}
