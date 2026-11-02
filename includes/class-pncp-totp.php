<?php
/**
 * Time-based one-time passwords (RFC 6238, as used by Google Authenticator, Microsoft Authenticator,
 * Authy and the like): SHA-1, 6 digits, 30-second steps.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * TOTP codes and the Base32 secret that authenticator apps read from the QR code.
 */
final class PNCP_Totp {

	const DIGITS = 6;
	const PERIOD = 30;

	/**
	 * A new random secret, Base32 (160 bits, as RFC 4226 recommends).
	 *
	 * @return string
	 */
	public static function new_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * The current time step.
	 *
	 * @param int|null $time Unix time (default: now).
	 * @return int
	 */
	public static function step( $time = null ) {
		return (int) floor( ( null === $time ? time() : (int) $time ) / self::PERIOD );
	}

	/**
	 * The code for a time step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Time step.
	 * @return string Six digits, with leading zeros.
	 */
	public static function code( $secret, $step ) {
		$key = self::base32_decode( $secret );
		if ( '' === $key ) {
			return '';
		}
		// 8-byte big-endian counter. Two 32-bit halves, so it also works on 32-bit PHP.
		$hash   = hash_hmac( 'sha1', pack( 'N2', ( $step >> 32 ) & 0xFFFFFFFF, $step & 0xFFFFFFFF ), $key, true );
		$offset = ord( $hash[19] ) & 0x0F;
		$value  = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) | ( ord( $hash[ $offset + 1 ] ) << 16 ) | ( ord( $hash[ $offset + 2 ] ) << 8 ) | ord( $hash[ $offset + 3 ] );
		return str_pad( (string) ( $value % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Checks a code against the current step and one step either side (phone clocks drift a little).
	 *
	 * @param string   $secret    Base32 secret.
	 * @param string   $code      The code typed (spaces are ignored).
	 * @param int      $last_step The last step already used: it and older ones are refused (no replay).
	 * @param int|null $time      Unix time (default: now).
	 * @return int|false The matching step, or false.
	 */
	public static function verify( $secret, $code, $last_step = 0, $time = null ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		if ( ! preg_match( '/^\d{' . self::DIGITS . '}$/', $code ) ) {
			return false;
		}
		$now = self::step( $time );
		foreach ( array( $now, $now - 1, $now + 1 ) as $step ) {
			if ( $step > $last_step && hash_equals( self::code( $secret, $step ), $code ) ) {
				return $step;
			}
		}
		return false;
	}

	/**
	 * The otpauth:// address the QR code carries.
	 *
	 * @param string $secret  Base32 secret.
	 * @param string $account Account label (e.g. the site's host).
	 * @param string $issuer  Issuer shown in the app.
	 * @return string
	 */
	public static function uri( $secret, $account, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer ) . ':' . rawurlencode( $account )
			. '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer )
			. '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
	}

	/**
	 * Base32 (RFC 4648), without padding.
	 *
	 * @param string $bytes Binary.
	 * @return string
	 */
	public static function base32_encode( $bytes ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits     = '';
		foreach ( str_split( $bytes ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= $alphabet[ bindec( str_pad( $chunk, 5, '0' ) ) ];
		}
		return $out;
	}

	/**
	 * Base32 to binary. Case, spaces and padding are ignored; '' if invalid.
	 *
	 * @param string $text Base32.
	 * @return string
	 */
	public static function base32_decode( $text ) {
		$text = strtoupper( preg_replace( '/[\s=]+/', '', (string) $text ) );
		if ( '' === $text || ! preg_match( '/^[A-Z2-7]+$/', $text ) ) {
			return '';
		}
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits     = '';
		foreach ( str_split( $text ) as $char ) {
			$bits .= str_pad( decbin( strpos( $alphabet, $char ) ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}
}
