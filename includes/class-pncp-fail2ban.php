<?php
/**
 * 3.7: one line in the system log (syslog, facility AUTH) for every temporary block, so fail2ban (or any tool that
 * reads the system log) can block the same IP in the server's firewall. A blocked scraper then no longer reaches
 * PHP at all: not even the 403 costs anything. For servers where you can install fail2ban (a VPS or a dedicated
 * server); on shared hosting the line goes to a log nobody reads, so the option is off by default.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The syslog line and the fail2ban filter and jail to go with it.
 */
final class PNCP_Fail2ban {

	/**
	 * The program name in the syslog line ("scrapelock[PID]: …"), which the fail2ban filter looks for.
	 */
	const IDENT = 'scrapelock';

	/**
	 * Writes the line for a new temporary block, when "Write blocks to the system log" is on.
	 *
	 * @param string $ip      The IP that was blocked (the exact one, also for an IPv6 /64 block).
	 * @param int    $minutes For how long.
	 * @param string $reason  Reason (key of PNCP_Log::reasons()).
	 */
	public static function log_ban( $ip, $minutes, $reason ) {
		$s = PNCP_Options::get();
		if ( empty( $s['syslog_bans'] ) || ! self::available() ) {
			return;
		}
		$ip = PNCP_Ip::normalize( (string) $ip );
		if ( '' === $ip ) {
			return;
		}
		$line = self::line( $ip, (int) $minutes, (string) $reason );
		// phpcs:disable WordPress.PHP.DevelopmentFunctions -- The system log is the purpose of this option.
		if ( @openlog( self::IDENT, LOG_PID | LOG_NDELAY, self::facility() ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Disabled on some hosts.
			@syslog( LOG_WARNING, $line ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			@closelog(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		// phpcs:enable
	}

	/**
	 * The text of the line. Only the IP, numbers, the reason key and the host name: nothing a visitor chose, so
	 * nothing can forge a second line or another IP for fail2ban.
	 *
	 * @param string $ip      IP.
	 * @param int    $minutes Minutes.
	 * @param string $reason  Reason.
	 * @return string
	 */
	public static function line( $ip, $minutes, $reason ) {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		return sprintf(
			'ban %s for %d minutes reason=%s site=%s',
			$ip,
			max( 1, (int) $minutes ),
			preg_replace( '/[^a-z0-9_]/', '', strtolower( $reason ) ),
			preg_replace( '/[^a-z0-9.\-]/', '', strtolower( $host ) )
		);
	}

	/**
	 * Can PHP write to the system log here? (Some hosts disable openlog() / syslog().)
	 *
	 * @return bool
	 */
	public static function available() {
		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );
		return function_exists( 'openlog' ) && function_exists( 'syslog' ) && ! in_array( 'syslog', $disabled, true ) && ! in_array( 'openlog', $disabled, true );
	}

	/**
	 * The syslog facility: AUTH, where fail2ban usually looks (/var/log/auth.log on Debian and Ubuntu,
	 * /var/log/secure on Red Hat). Filter `pncp_syslog_facility` (e.g. LOG_LOCAL0 for a log of its own).
	 *
	 * @return int
	 */
	public static function facility() {
		return (int) apply_filters( 'pncp_syslog_facility', LOG_AUTH );
	}

	/**
	 * The fail2ban filter: /etc/fail2ban/filter.d/scrapelock.conf.
	 *
	 * @return string
	 */
	public static function filter_conf() {
		return '# /etc/fail2ban/filter.d/scrapelock.conf (ScrapeLock ' . PNCP_VERSION . ")\n"
			. "[Definition]\n"
			. 'failregex = ^.*' . self::IDENT . "\\[\\d+\\]: ban <HOST> for \\d+ minutes\\b\n"
			. "ignoreregex =\n";
	}

	/**
	 * The fail2ban jail: /etc/fail2ban/jail.d/scrapelock.local. One line is enough (maxretry = 1): ScrapeLock has
	 * already counted the violations. The firewall block lasts as long as ScrapeLock's own.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	public static function jail_conf( $s ) {
		$minutes = max( 1, (int) $s['ban_minutes'] );
		return '# /etc/fail2ban/jail.d/scrapelock.local (ScrapeLock ' . PNCP_VERSION . ")\n"
			. "[scrapelock]\n"
			. "enabled  = true\n"
			. "filter   = scrapelock\n"
			. "# Debian / Ubuntu: /var/log/auth.log. Red Hat, AlmaLinux, Rocky: /var/log/secure. With systemd only: backend = systemd.\n"
			. "logpath  = /var/log/auth.log\n"
			. "maxretry = 1\n"
			. "findtime = 60\n"
			. 'bantime  = ' . ( $minutes * 60 ) . "\n"
			. "# Your own addresses (office, monitoring) are never blocked here:\n"
			. "ignoreip = 127.0.0.1/8 ::1\n"
			. "port     = http,https\n";
	}
}
