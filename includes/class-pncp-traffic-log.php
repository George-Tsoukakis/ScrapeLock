<?php
/**
 * 3.12: the web server's access log as a Traffic source ("traffic_log_path"). Nginx and Apache "combined" lines,
 * with an optional virtual host in front ("example.com:443 1.2.3.4 - - […]", Apache's vhost_combined) and the
 * usual Nginx additions at the end (the request time, the upstream time, "rt=0.123", the X-Forwarded-For header).
 *
 * Read in the scheduled run only, incrementally: a cursor (device, inode, byte offset and the first line's
 * signature) continues where the last run stopped, a rotated file is finished from "<path>.1" (or "<path>.1.gz"
 * with zlib) before the new file is read from its start, and each run stops at a time, byte and line budget.
 * The path must be absolute, without "..", stream wrappers or a hidden file name, named like an access log, and
 * allowed by open_basedir (also where a symlink points to).
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The server access log source.
 */
final class PNCP_Traffic_Log {

	/**
	 * Default most bytes one run reads (filter `pncp_traffic_log_bytes`).
	 */
	const MAX_BYTES = 33554432;

	/**
	 * Default most lines one run reads (filter `pncp_traffic_log_lines`).
	 */
	const MAX_LINES = 100000;

	/**
	 * Bytes read from the end of the file on the first run (older lines are not imported).
	 */
	const FIRST_BYTES = 4194304;

	/**
	 * Longest line read (longer ones are skipped).
	 */
	const MAX_LINE = 16384;

	/**
	 * Is the path one this source may read? Only the form of the path and open_basedir are checked (nothing is
	 * opened).
	 *
	 * @param string $path Path.
	 * @return string '' when it may, else not_set | not_absolute | not_allowed | not_access_log.
	 */
	public static function path_refusal( $path ) {
		$path = (string) $path;
		if ( '' === trim( $path ) ) {
			return 'not_set';
		}
		if ( false !== strpos( $path, "\0" ) || false !== strpos( $path, '://' ) || preg_match( '#^[a-z][a-z0-9+.\-]+:#i', $path ) ) {
			return 'not_allowed'; // A stream wrapper (php://, phar://, compress.zlib:, glob:…).
		}
		$windows = (bool) preg_match( '#^[A-Za-z]:[\\\\/]#', $path );
		if ( '/' !== $path[0] && ! $windows ) {
			return 'not_absolute';
		}
		if ( preg_match( '#(?:^|[\\\\/])\.\.(?:[\\\\/]|$)#', $path ) ) {
			return 'not_allowed';
		}
		if ( ! self::name_ok( $path ) ) {
			return 'not_access_log';
		}
		if ( ! self::basedir_ok( $path ) ) {
			return 'not_allowed';
		}
		// A symlink (or a link in a parent folder) must not lead outside open_basedir either.
		$real = @realpath( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A missing file is no error here.
		if ( is_string( $real ) && ( ! self::basedir_ok( $real ) || ! self::name_ok( $real ) ) ) {
			return 'not_allowed';
		}
		if ( false === $real && ! @file_exists( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir warnings.
			// Missing, or a link that leads where open_basedir does not let PHP look (PHP resolves links for its
			// checks, so the link itself cannot be seen): the folder's listing tells them apart.
			$entries = @scandir( dirname( $path ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- See above.
			if ( is_array( $entries ) && in_array( basename( $path ), $entries, true ) ) {
				return 'not_allowed';
			}
		}
		return '';
	}

	/**
	 * May the current user set or test the access log path? On a network only a network administrator: the log is
	 * the whole server's, with the visitors of every site. Requests without a signed-in user (cron, WP-CLI) may.
	 *
	 * @return bool
	 */
	public static function user_may_read() {
		return ! is_multisite() || ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() || current_user_can( 'manage_network_options' );
	}

	/**
	 * A code of path_refusal() / test_path() in words.
	 *
	 * @param string $code Code.
	 * @return string
	 */
	public static function refusal_text( $code ) {
		$texts = array(
			'not_set'        => __( 'No access log path is set.', 'scrapelock' ),
			'not_absolute'   => __( 'Enter the full path of the file, starting with /.', 'scrapelock' ),
			'not_allowed'    => __( 'This path cannot be used: no "..", no stream wrappers such as php://, and it must be inside the folders PHP may open (open_basedir).', 'scrapelock' ),
			'unreadable'     => __( 'PHP cannot read this file (it does not exist, or its permissions do not allow the web server user to read it).', 'scrapelock' ),
			'not_access_log' => __( 'This does not look like an access log: the name must end in .log or contain "access", and its lines must be in the Nginx / Apache "combined" format.', 'scrapelock' ),
			'read_error'     => __( 'The access log could not be read.', 'scrapelock' ),
			'ok'             => __( 'The access log can be read.', 'scrapelock' ),
		);
		return isset( $texts[ $code ] ) ? $texts[ $code ] : (string) $code;
	}

	/**
	 * Is the file name that of an access log? "*.log" (also rotated: access.log.1, access.log-20261120), or a name
	 * with "access" in it that is not a script, a configuration or a hidden file (.htaccess).
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	private static function name_ok( $path ) {
		$name = (string) preg_replace( '#^.*[\\\\/]#', '', (string) $path );
		if ( '' === $name || '.' === $name[0] || ! preg_match( '#^[A-Za-z0-9._\-]+$#', $name ) ) {
			return false;
		}
		if ( preg_match( '#\.log(?:[.\-_]\d+)?$#i', $name ) ) {
			return true;
		}
		return false !== stripos( $name, 'access' ) && ! preg_match( '#\.(?:php\d?|phtml|phar|inc|sql|json|ini|conf|cnf|env|sh|py|pl|cgi|js|html?|xml|ya?ml|key|pem|crt|bak|zip|gz)$#i', $name );
	}

	/**
	 * Is the path inside open_basedir (when it is set)?
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	public static function basedir_ok( $path ) {
		$base = (string) ini_get( 'open_basedir' );
		if ( '' === trim( $base ) ) {
			return true;
		}
		/**
		 * Filters the open_basedir folders the server log must be in (tests).
		 *
		 * @since 3.12.0
		 * @param string[] $dirs Folders.
		 */
		$dirs = (array) apply_filters( 'pncp_traffic_open_basedir', explode( PATH_SEPARATOR, $base ) );
		$path = str_replace( '\\', '/', (string) $path );
		foreach ( $dirs as $dir ) {
			$dir = rtrim( str_replace( '\\', '/', trim( (string) $dir ) ), '/' );
			if ( '' === $dir || '.' === $dir ) {
				continue;
			}
			if ( $path === $dir || 0 === strpos( $path, $dir . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * "Test this path": may it be read, can it be read, and do its last lines read as an access log?
	 *
	 * @param string $path Path.
	 * @return array{code:string, lines:int, parsed:int, sample:array<string, mixed>|null} code: not_set |
	 *         not_absolute | not_allowed | unreadable | not_access_log | ok; lines: lines looked at (the last 64 KB);
	 *         parsed: how many of them read as access log lines; sample: the last one, parsed.
	 */
	public static function test_path( $path ) {
		$out  = array(
			'code'   => '',
			'lines'  => 0,
			'parsed' => 0,
			'sample' => null,
		);
		$path = trim( (string) $path );
		$why  = self::path_refusal( $path );
		if ( '' !== $why ) {
			$out['code'] = $why;
			return $out;
		}
		if ( ! @is_file( $path ) || ! @is_readable( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir warnings.
			$out['code'] = 'unreadable';
			return $out;
		}
		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A vanished file reads as 0.
		$fh   = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- A local log file, read only.
		if ( ! $fh ) {
			$out['code'] = 'unreadable';
			return $out;
		}
		$from = max( 0, $size - 65536 );
		fseek( $fh, $from );
		$data = (string) fread( $fh, 65536 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- See above.
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
		$lines = explode( "\n", str_replace( "\r", '', $data ) );
		if ( $from > 0 ) {
			array_shift( $lines ); // Cut in the middle.
		}
		$s = PNCP_Options::get();
		foreach ( $lines as $line ) {
			if ( '' === trim( $line ) ) {
				continue;
			}
			++$out['lines'];
			$row = self::parse_line( $line, $s );
			if ( $row ) {
				++$out['parsed'];
				$out['sample'] = $row;
			}
		}
		$out['code'] = $out['lines'] > 0 && 0 === $out['parsed'] ? 'not_access_log' : 'ok';
		return $out;
	}

	/**
	 * One access log line as a request (see PNCP_Traffic::ingest()), or null when it is not one.
	 *
	 * The client IP: the line's address, unless it is a trusted proxy or a CDN edge (PNCP_Ip::is_cdn() with
	 * "Trust Cloudflare / Bunny addresses", the trusted proxies, the server's own network) and the line ends with
	 * an X-Forwarded-For value: then the last address in it that is not such a proxy.
	 *
	 * @param string                    $line Line.
	 * @param array<string, mixed>|null $s    Settings (null = the settings in effect).
	 * @return array<string, mixed>|null
	 */
	public static function parse_line( $line, $s = null ) {
		$line = rtrim( (string) $line, "\r\n" );
		if ( '' === $line || strlen( $line ) > self::MAX_LINE ) {
			return null;
		}
		$q   = '"((?:[^"\\\\]|\\\\.)*)"';
		$rx  = '#^(?:(\S+)\s+)?(\[?[0-9A-Fa-f:.]+\]?)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+' . $q . '\s+(\d{3})\s+(\d+|-)(?:\s+' . $q . '\s+' . $q . ')?(.*)$#';
		if ( ! preg_match( $rx, $line, $m ) ) {
			return null;
		}
		$peer = PNCP_Ip::normalize( $m[2] );
		if ( '' === $peer ) {
			return null;
		}
		$time = DateTime::createFromFormat( 'd/M/Y:H:i:s O', $m[3] );
		if ( ! $time ) {
			return null;
		}
		$request = stripcslashes( $m[4] );
		$method  = '';
		$target  = '';
		if ( preg_match( '#^([A-Z]{3,10})\s+(\S+)(?:\s+HTTP/[\d.]+)?$#', $request, $r ) ) {
			$method = $r[1];
			$target = $r[2];
		}
		if ( '' === $target || ( '/' !== $target[0] && ! preg_match( '#^https?://#i', $target ) && '*' !== $target ) ) {
			$target = '/'; // A malformed request ("-", binary garbage from a scanner): counted on "/".
		}
		$rest = (string) $m[9]; // Unmatched optional groups are '' (the last group always matches).
		$s    = null === $s ? PNCP_Options::get() : $s;
		return array(
			'ts'      => $time->getTimestamp(),
			'ip'      => self::client( $peer, self::forwarded( $rest ), $s ),
			'method'  => $method,
			'status'  => (int) $m[5],
			'url'     => $target,
			'bytes'   => '-' === $m[6] ? 0 : (int) $m[6],
			'referer' => stripcslashes( (string) $m[7] ),
			'ua'      => stripcslashes( (string) $m[8] ),
			'rt_ms'   => self::request_time( $rest ),
			'edge'    => PNCP_Ip::is_cdn( $peer ) ? 'cdn' : '',
		);
	}

	/**
	 * The X-Forwarded-For value at the end of a line (the last quoted value that is a list of addresses), or ''.
	 *
	 * @param string $rest What follows the User-Agent.
	 * @return string
	 */
	private static function forwarded( $rest ) {
		if ( ! preg_match_all( '#"([^"]*)"#', (string) $rest, $all ) ) {
			return '';
		}
		foreach ( array_reverse( $all[1] ) as $value ) {
			$value = trim( (string) $value );
			if ( '' === $value || '-' === $value || ! preg_match( '#^[0-9A-Fa-f:.\[\]]+(?:\s*,\s*[0-9A-Fa-f:.\[\]]+)*$#', $value ) ) {
				continue;
			}
			// Every entry must be an address ("0.000" or "1.200", an upstream time, is not).
			$ok = true;
			foreach ( explode( ',', $value ) as $part ) {
				$ok = $ok && '' !== PNCP_Ip::normalize( $part );
			}
			if ( $ok ) {
				return $value;
			}
		}
		return '';
	}

	/**
	 * The request time in milliseconds from the end of a line ("rt=0.123", "request_time=0.123", or the first bare
	 * number with a decimal point, as Nginx writes $request_time), or null.
	 *
	 * @param string $rest What follows the User-Agent.
	 * @return int|null
	 */
	private static function request_time( $rest ) {
		$rest = (string) $rest;
		if ( preg_match( '#\b(?:rt|request_time)=\"?(\d+(?:\.\d+)?)#', $rest, $m ) ) {
			return (int) round( (float) $m[1] * 1000 );
		}
		$bare = trim( (string) preg_replace( '#"[^"]*"#', ' ', $rest ) );
		if ( '' !== $bare && preg_match( '#^(\d+\.\d+)\b#', $bare, $m ) ) {
			return (int) round( (float) $m[1] * 1000 );
		}
		return null;
	}

	/**
	 * Is an address a proxy whose X-Forwarded-For can be believed: a trusted proxy, the server or its private
	 * network, or an edge of a trusted CDN (Cloudflare / Bunny with their "Trust" switch on)?
	 *
	 * @param string               $ip IP.
	 * @param array<string, mixed> $s  Settings.
	 * @return bool
	 */
	private static function trusted_peer( $ip, $s ) {
		if ( '' === $ip ) {
			return false;
		}
		if ( PNCP_Ip::in_any( $ip, PNCP_Ip::trusted_ranges( $s ) ) || PNCP_Ip::is_private( $ip ) || PNCP_Ip::is_local( $ip ) ) {
			return true;
		}
		if ( ! PNCP_Ip::is_cdn( $ip ) ) {
			return false;
		}
		$bunny = PNCP_Ip::is_bunny( $ip );
		return $bunny ? ! empty( $s['trust_bunny'] ) : ! empty( $s['trust_cloudflare'] );
	}

	/**
	 * The client of a log line: the peer, or, behind a trusted proxy or CDN edge, the last untrusted address of
	 * X-Forwarded-For.
	 *
	 * @param string               $peer The line's address.
	 * @param string               $xff  X-Forwarded-For ('' = none).
	 * @param array<string, mixed> $s    Settings.
	 * @return string
	 */
	private static function client( $peer, $xff, $s ) {
		if ( '' === $xff || ! self::trusted_peer( $peer, $s ) ) {
			return $peer;
		}
		$chain = array_reverse( array_map( 'trim', explode( ',', $xff ) ) );
		$ip    = $peer;
		foreach ( $chain as $hop ) {
			$hop = PNCP_Ip::normalize( $hop );
			if ( '' === $hop ) {
				break;
			}
			$ip = $hop;
			if ( ! self::trusted_peer( $hop, $s ) ) {
				break;
			}
		}
		return $ip;
	}

	/* ---------- Reading ---------- */

	/**
	 * The identity of an open file: device, inode and size.
	 *
	 * @param string $path Path.
	 * @return array{dev:int, ino:int, size:int}|null
	 */
	private static function stat( $path ) {
		clearstatcache( true, $path );
		$st = @stat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A missing file is no error here.
		if ( ! is_array( $st ) ) {
			return null;
		}
		return array(
			'dev'  => (int) $st['dev'],
			'ino'  => (int) $st['ino'],
			'size' => (int) $st['size'],
		);
	}

	/**
	 * The signature of a file: the hash of its first line (up to 256 bytes), or '' when it is empty.
	 *
	 * @param string $path Path (or a compress.zlib:// path for a .gz).
	 * @param bool   $gz   A gzip file.
	 * @return string
	 */
	private static function signature( $path, $gz = false ) {
		$fh = $gz ? @gzopen( $path, 'rb' ) : @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- A local log file, read only.
		if ( ! $fh ) {
			return '';
		}
		$line = $gz ? gzgets( $fh, 257 ) : fgets( $fh, 257 );
		if ( $gz ) {
			gzclose( $fh );
		} else {
			fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
		}
		return is_string( $line ) && '' !== $line ? md5( $line ) : '';
	}

	/**
	 * Reads what is new in the log, within the budget. Runs from PNCP_Traffic::run(); the cursor and the result
	 * are kept in PNCP_Traffic::STATE ("server").
	 *
	 * @param float $deadline microtime( true ) to stop at.
	 * @return array{lines:int, stored:int, error:string} error: a code of test_path(), or read_error.
	 */
	public static function run( $deadline ) {
		$path   = PNCP_Traffic::settings()['log_path'];
		$state  = PNCP_Traffic::state();
		$cursor = $state['server'];
		$result = array(
			'lines'  => 0,
			'stored' => 0,
			'error'  => '',
		);
		$why    = self::path_refusal( $path );
		$st     = '' === $why ? self::stat( $path ) : null;
		if ( '' === $why && ( null === $st || ! @is_readable( $path ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir warnings.
			$why = 'unreadable';
		}
		if ( '' !== $why ) {
			$result['error']    = $why;
			$cursor['error']    = $why;
			$cursor['last_run'] = time();
			$state['server']    = $cursor;
			PNCP_Traffic::save_state( $state );
			return $result;
		}
		/**
		 * Filters the most bytes one run reads from the server log.
		 *
		 * @since 3.12.0
		 * @param int $bytes Bytes (default 32 MB).
		 */
		$budget = array(
			'bytes'    => max( 65536, (int) apply_filters( 'pncp_traffic_log_bytes', self::MAX_BYTES ) ),
			/**
			 * Filters the most lines one run reads from the server log.
			 *
			 * @since 3.12.0
			 * @param int $lines Lines (default 100,000).
			 */
			'lines'    => max( 100, (int) apply_filters( 'pncp_traffic_log_lines', self::MAX_LINES ) ),
			'deadline' => (float) $deadline,
		);
		$sig    = self::signature( $path );
		$same   = isset( $cursor['path'], $cursor['dev'], $cursor['ino'], $cursor['offset'], $cursor['sig'] ) && $cursor['path'] === $path
			&& (int) $cursor['dev'] === $st['dev'] && (int) $cursor['ino'] === $st['ino'] && (int) $cursor['offset'] <= $st['size']
			&& ( '' === (string) $cursor['sig'] || (string) $cursor['sig'] === $sig );
		$s      = PNCP_Options::get();
		if ( ! $same && isset( $cursor['path'], $cursor['offset'] ) && $cursor['path'] === $path ) {
			// Rotated (replaced, or emptied in place): the rest of the old file is in <path>.1 (or .1.gz).
			$old = self::rotated( $path, $cursor );
			if ( null !== $old ) {
				$read              = self::read( $old['path'], $old['gz'], (int) $cursor['offset'], $budget, $s );
				$result['lines']  += $read['lines'];
				$result['stored'] += $read['stored'];
			}
			$offset = 0;
		} elseif ( $same ) {
			$offset = (int) $cursor['offset'];
		} else {
			// First run (or another file): only the end of the file, older lines are not imported.
			$offset = max( 0, $st['size'] - self::FIRST_BYTES );
		}
		$read = self::read( $path, false, $offset, $budget, $s );
		if ( null === $read['offset'] ) {
			$result['error'] = 'read_error';
		}
		$result['lines']  += $read['lines'];
		$result['stored'] += $read['stored'];
		$cursor = array(
			'path'     => $path,
			'dev'      => $st['dev'],
			'ino'      => $st['ino'],
			'offset'   => null === $read['offset'] ? $offset : $read['offset'],
			'sig'      => $sig,
			'last_run' => time(),
			'last_ok'  => '' === $result['error'] ? time() : ( isset( $cursor['last_ok'] ) ? (int) $cursor['last_ok'] : 0 ),
			'error'    => $result['error'],
			'lines'    => $result['lines'],
		);
		PNCP_Traffic::flush();
		$state           = PNCP_Traffic::state();
		$state['server'] = $cursor;
		PNCP_Traffic::save_state( $state );
		return $result;
	}

	/**
	 * Where the rest of a rotated log is: "<path>.1" when it is the file the cursor was in (same inode, or the same
	 * first line), else "<path>.1.gz" with the same first line (zlib), else null.
	 *
	 * @param string               $path   Path.
	 * @param array<string, mixed> $cursor The cursor of the last run.
	 * @return array{path:string, gz:bool}|null
	 */
	private static function rotated( $path, $cursor ) {
		$one = $path . '.1';
		$st  = self::stat( $one );
		if ( null !== $st && @is_readable( $one ) && '' === self::path_refusal( $one ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir warnings.
			$inode = isset( $cursor['dev'], $cursor['ino'] ) && (int) $cursor['dev'] === $st['dev'] && (int) $cursor['ino'] === $st['ino'];
			if ( $inode || ( ! empty( $cursor['sig'] ) && self::signature( $one ) === (string) $cursor['sig'] ) ) {
				return array(
					'path' => $one,
					'gz'   => false,
				);
			}
		}
		$gz = $one . '.gz';
		if ( function_exists( 'gzopen' ) && ! empty( $cursor['sig'] ) && @is_readable( $gz ) && self::basedir_ok( $gz ) && self::signature( $gz, true ) === (string) $cursor['sig'] ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir warnings.
			return array(
				'path' => $gz,
				'gz'   => true,
			);
		}
		return null;
	}

	/**
	 * Reads complete lines from an offset, within the budget (shared by the calls of one run), and stores them.
	 *
	 * @param string                                     $path   Path.
	 * @param bool                                       $gz     A gzip file.
	 * @param int                                        $offset Byte offset (of the uncompressed data).
	 * @param array{bytes:int, lines:int, deadline:float} $budget Budget, used up in place.
	 * @param array<string, mixed>                       $s      Settings.
	 * @return array{offset:int|null, lines:int, stored:int} offset: where the next run starts (null = not opened).
	 */
	private static function read( $path, $gz, $offset, &$budget, $s ) {
		$out = array(
			'offset' => null,
			'lines'  => 0,
			'stored' => 0,
		);
		$fh  = $gz ? @gzopen( $path, 'rb' ) : @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- A local log file, read only.
		if ( ! $fh ) {
			return $out;
		}
		$seek = $gz ? gzseek( $fh, $offset ) : fseek( $fh, $offset );
		if ( 0 !== $seek ) {
			$gz ? gzclose( $fh ) : fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
			return $out;
		}
		$pos = $offset;
		if ( $offset > 0 && ! $gz ) {
			// Not at the start of a line (the first run starts near the end): skip to the next one.
			fseek( $fh, $offset - 1 );
			$prev = fread( $fh, 1 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- See above.
			if ( "\n" !== $prev ) {
				$skip = fgets( $fh );
				$pos += is_string( $skip ) ? strlen( $skip ) : 0;
				if ( is_string( $skip ) && "\n" !== substr( $skip, -1 ) ) {
					fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
					$out['offset'] = $offset; // No complete line yet.
					return $out;
				}
			}
		}
		while ( $budget['bytes'] > 0 && $budget['lines'] > 0 && microtime( true ) < $budget['deadline'] ) {
			$line = $gz ? gzgets( $fh, self::MAX_LINE + 2 ) : fgets( $fh, self::MAX_LINE + 2 );
			if ( ! is_string( $line ) || '' === $line ) {
				break;
			}
			if ( "\n" !== substr( $line, -1 ) ) {
				if ( strlen( $line ) <= self::MAX_LINE ) {
					break; // The line is still being written: the next run reads it.
				}
				// Far too long: skipped to its end.
				$length = strlen( $line );
				do {
					$more    = $gz ? gzgets( $fh, self::MAX_LINE + 2 ) : fgets( $fh, self::MAX_LINE + 2 );
					$length += is_string( $more ) ? strlen( $more ) : 0;
				} while ( is_string( $more ) && "\n" !== substr( $more, -1 ) && $length < 64 * self::MAX_LINE );
				$pos += $length;
				continue;
			}
			$pos               += strlen( $line );
			$budget['bytes']   -= strlen( $line );
			$budget['lines']   -= 1;
			$out['lines']      += 1;
			$row                = self::parse_line( $line, $s );
			if ( $row && PNCP_Traffic::ingest( $row, 'server' ) ) {
				++$out['stored'];
			}
		}
		$gz ? gzclose( $fh ) : fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
		$out['offset'] = $pos;
		return $out;
	}
}
