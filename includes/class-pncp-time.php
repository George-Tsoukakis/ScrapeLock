<?php
/**
 * How long the current PHP request may still work. ScrapeLock never raises PHP's time limit: long jobs (the file
 * integrity pass, the official checksums, the CDN sync) do what fits in the time left and continue in the next
 * scheduled run.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Time left in this request.
 */
final class PNCP_Time {

	/**
	 * Seconds kept free at the end of the request for what comes after the job (saving, the response).
	 */
	const RESERVE = 5;

	/**
	 * The fallback start of the request, when the server does not give REQUEST_TIME_FLOAT.
	 *
	 * @var float|null
	 */
	private static $start = null;

	/**
	 * How many seconds a job may still take in this request: at most $want, less when PHP's max_execution_time
	 * would end the request earlier (minus RESERVE). Without a time limit (WP-CLI, a real cron job with
	 * max_execution_time = 0), $want.
	 *
	 * The time used is counted from the start of the request as wall-clock time. PHP counts its limit in CPU time
	 * on Linux, which is never more than that, so the answer errs on the safe side.
	 *
	 * @param float $want Seconds the job would like.
	 * @return float Seconds, 0 or more.
	 */
	public static function left( $want ) {
		$limit = (int) ini_get( 'max_execution_time' );
		if ( $limit <= 0 ) {
			return max( 0.0, (float) $want );
		}
		$used = max( 0.0, microtime( true ) - self::start() );
		return max( 0.0, min( (float) $want, $limit - $used - self::RESERVE ) );
	}

	/**
	 * The time by which a job of at most $want seconds must stop, as a microtime( true ) value.
	 *
	 * @param float $want Seconds the job would like.
	 * @return float
	 */
	public static function deadline( $want ) {
		return microtime( true ) + self::left( $want );
	}

	/**
	 * When this request started.
	 *
	 * @return float
	 */
	private static function start() {
		if ( isset( $_SERVER['REQUEST_TIME_FLOAT'] ) && is_numeric( $_SERVER['REQUEST_TIME_FLOAT'] ) ) {
			return (float) $_SERVER['REQUEST_TIME_FLOAT'];
		}
		if ( null === self::$start ) {
			self::$start = microtime( true );
		}
		return self::$start;
	}
}
