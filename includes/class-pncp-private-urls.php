<?php
/**
 * Ιδιωτικά URLs: XML feeds προϊόντων (Skroutz, BestPrice, Google Merchant κ.λπ.) και ό,τι άλλο
 * δίνει όλο το κείμενο σε ένα αρχείο. Πρόσβαση μόνο με μυστικό token ή από επιτρεπόμενες IP.
 *
 * Ισχύει για URLs που σερβίρει η PHP. Στατικά αρχεία (π.χ. .xml μέσα στο uploads) τα σερβίρει
 * απευθείας ο web server· για αυτά δείτε τον κανόνα Nginx στο README.
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
	 * Δένει τα hooks. Τρέχει νωρίς, πριν τα plugins των feeds βγάλουν το XML.
	 */
	public static function init() {
		add_action( 'plugins_loaded', array( __CLASS__, 'guard' ), 0 );
	}

	/**
	 * Μπλοκάρει (403) όταν το URL είναι στη λίστα και δεν υπάρχει σωστό token ή επιτρεπόμενη IP.
	 */
	public static function guard() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || '' === trim( (string) $s['private_paths'] ) ) {
			return;
		}

		$path = self::request_path();
		if ( '' === $path || ! self::path_matches( $path, PNCP_Options::parse_list( $s['private_paths'] ) ) ) {
			return;
		}

		// Ούτε η επιτυχής απάντηση μπαίνει σε κοινή cache: πολλά CDN αγνοούν το query string,
		// οπότε το feed με το token θα σερβιριζόταν μετά και χωρίς token.
		nocache_headers();
		header( 'Cache-Control: private, no-store, max-age=0' );

		if ( self::is_allowed( $s ) ) {
			return;
		}

		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		// Χωρίς μετάφραση: τρέχει πριν φορτωθούν οι μεταφράσεις (init).
		echo 'Forbidden';
		exit;
	}

	/**
	 * Σωστό token, επιτρεπόμενη IP ή διαχειριστής;
	 *
	 * @param array<string, mixed> $s Ρυθμίσεις.
	 * @return bool
	 */
	private static function is_allowed( $s ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Token πρόσβασης, όχι φόρμα.
		$token = isset( $_GET[ self::QUERY_ARG ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::QUERY_ARG ] ) ) : '';
		if ( '' !== $token && '' !== (string) $s['private_token'] && hash_equals( (string) $s['private_token'], $token ) ) {
			return true;
		}

		$ip = PNCP_Bots::client_ip();
		if ( '' !== $ip ) {
			foreach ( PNCP_Options::parse_list( $s['private_ips'] ) as $range ) {
				if ( self::ip_in_range( $ip, $range ) ) {
					return true;
				}
			}
		}

		return current_user_can( 'manage_options' );
	}

	/**
	 * Η διαδρομή του αιτήματος, σχετική με τη ρίζα του site (π.χ. /skroutz.xml).
	 *
	 * @return string
	 */
	private static function request_path() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Μόνο σύγκριση με μοτίβα.
		$path = self::relative_path( rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) ) );
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
	private static function relative_path( $path ) {
		$path = '/' . ltrim( $path, '/' );
		$home = rtrim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
		if ( '' !== $home && ( 0 === strcasecmp( $path, $home ) || 0 === stripos( $path, $home . '/' ) ) ) {
			$path = '/' . ltrim( substr( $path, strlen( $home ) ), '/' );
		}
		return $path;
	}

	/**
	 * Ταιριάζει η διαδρομή με κάποιο μοτίβο; Το * σημαίνει «οτιδήποτε». Χωρίς διάκριση πεζών/κεφαλαίων.
	 *
	 * @param string   $path     Διαδρομή.
	 * @param string[] $patterns Μοτίβα (διαδρομές ή πλήρη URLs).
	 * @return bool
	 */
	public static function path_matches( $path, $patterns ) {
		foreach ( $patterns as $pattern ) {
			$p = (string) wp_parse_url( $pattern, PHP_URL_PATH );
			if ( '' === $p ) {
				continue;
			}
			$p     = self::relative_path( $p );
			$regex = '#^' . str_replace( '\*', '.*', preg_quote( $p, '#' ) ) . '$#i';
			if ( preg_match( $regex, $path ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Ανήκει η IP σε μια IP ή CIDR (IPv4/IPv6);
	 *
	 * @param string $ip    IP.
	 * @param string $range IP ή CIDR, π.χ. 203.0.113.0/24.
	 * @return bool
	 */
	public static function ip_in_range( $ip, $range ) {
		$parts  = explode( '/', trim( $range ), 2 );
		$subnet = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$addr   = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $subnet || false === $addr || strlen( $subnet ) !== strlen( $addr ) ) {
			return false;
		}
		$max  = strlen( $addr ) * 8;
		if ( isset( $parts[1] ) ) {
			if ( ! ctype_digit( $parts[1] ) || (int) $parts[1] > $max ) {
				return false; // Λάθος CIDR: ποτέ «όλες οι IP».
			}
			$bits = (int) $parts[1];
		} else {
			$bits = $max;
		}
		$bytes = intdiv( $bits, 8 );
		if ( substr( $addr, 0, $bytes ) !== substr( $subnet, 0, $bytes ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = 0xFF << ( 8 - $rest ) & 0xFF;
		return ( ord( $addr[ $bytes ] ) & $mask ) === ( ord( $subnet[ $bytes ] ) & $mask );
	}

	/**
	 * Παράδειγμα URL με το token, για τη σελίδα ρυθμίσεων.
	 *
	 * @param string $path  Διαδρομή.
	 * @param string $token Token.
	 * @return string
	 */
	public static function example_url( $path, $token ) {
		$path = self::relative_path( (string) wp_parse_url( $path, PHP_URL_PATH ) );
		if ( false !== strpos( $path, '*' ) ) {
			$path = '/feed.xml'; // Μοτίβο με *: δείχνουμε ένα γενικό παράδειγμα.
		}
		return add_query_arg( self::QUERY_ARG, rawurlencode( $token ), home_url( $path ) );
	}
}
