<?php
/**
 * 3.12.6: WP-CLI for the server: "wp scrapelock rules show | status | install" (PNCP_Cli::rules()) and
 * "wp scrapelock cdn purge" (PNCP_Cli::cdn()) and "wp scrapelock verify-file add | list | remove"
 * (PNCP_Cli::verify_file()).
 *
 * Only from WP-CLI (cli_only()). The stored credentials (Bunny API key, Cloudflare token) are used, never printed.
 * "rules install" writes only the files named on the command line: <file>.new, a diff, <file>.old while the new
 * one is tested, the test command (nginx -t), the reload, and every file back from its .old when the test or the
 * reload fails. This is the only class that runs commands of the system.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Server and CDN commands.
 */
final class PNCP_Cli_Server {

	/**
	 * Stops unless this runs in WP-CLI (never in a web request).
	 */
	private static function cli_only() {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI || 'cli' !== PHP_SAPI ) {
			wp_die( esc_html__( 'Only from WP-CLI.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * The parts "rules show" prints: name => [server, what].
	 *
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function parts() {
		return array(
			'nginx-http'     => array( 'nginx', __( 'Nginx part 1, inside http { }', 'scrapelock' ) ),
			'nginx-server'   => array( 'nginx', __( 'Nginx part 2, inside the site\'s server { }', 'scrapelock' ) ),
			'stealth-nginx'  => array( 'nginx', __( 'Stealth rules for Nginx, inside the site\'s server { }', 'scrapelock' ) ),
			'stealth-apache' => array( 'apache', __( 'Stealth rules for Apache (.htaccess)', 'scrapelock' ) ),
			'apache'         => array( 'apache', __( 'Apache rules (.htaccess, above # BEGIN WordPress)', 'scrapelock' ) ),
		);
	}

	/**
	 * The text of a part, exactly as the Server rules tab (and the Stealth card) shows it.
	 *
	 * @param string $part A key of parts().
	 * @return string
	 */
	public static function part_text( $part ) {
		switch ( $part ) {
			case 'nginx-http':
				return PNCP_Rules::nginx_http();
			case 'nginx-server':
				return PNCP_Rules::nginx_server();
			case 'stealth-nginx':
				return PNCP_Stealth::rules_text( 'nginx' );
			case 'stealth-apache':
				return PNCP_Stealth::rules_text( 'apache' );
			case 'apache':
				return PNCP_Rules::apache();
		}
		return '';
	}

	/**
	 * Wp scrapelock rules show | status | install.
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function rules( $args, $assoc_args ) {
		self::cli_only();
		$action = isset( $args[0] ) ? (string) $args[0] : 'status';
		if ( 'show' === $action ) {
			$part = isset( $assoc_args['part'] ) ? (string) $assoc_args['part'] : '';
			if ( ! isset( self::parts()[ $part ] ) ) {
				/* translators: %s: list of parts */
				WP_CLI::error( sprintf( __( 'Give --part: %s.', 'scrapelock' ), implode( ', ', array_keys( self::parts() ) ) ) );
			}
			// As the Server rules tab: the text shown is kept under its fingerprint (for "See what changed" later).
			PNCP_Rules_State::remember_texts();
			echo self::part_text( $part ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Plain text for a configuration file, printed exactly.
			return;
		}
		if ( 'status' === $action ) {
			self::print_status( self::status( isset( $assoc_args['server'] ) ? (string) $assoc_args['server'] : '' ), self::format( $assoc_args ) );
			return;
		}
		if ( 'install' === $action ) {
			self::install( $assoc_args );
			return;
		}
		WP_CLI::error( __( 'Unknown action. Use: show, status or install.', 'scrapelock' ) );
	}

	/**
	 * The output format: table (default), json, csv or yaml.
	 *
	 * @param array<string, string> $assoc_args Options.
	 * @return string
	 */
	private static function format( $assoc_args ) {
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( ! in_array( $format, array( 'table', 'json', 'csv', 'yaml' ), true ) ) {
			WP_CLI::error( __( 'Unknown --format. Use: table, json, csv, yaml.', 'scrapelock' ) );
		}
		return $format;
	}

	/* ---------- rules status ---------- */

	/**
	 * The server whose rules are checked: the one asked for, else the one the rules were seen in, else the one
	 * last seen in wp-admin; Nginx when nothing says it.
	 *
	 * @param string $server nginx, apache or ''.
	 * @return string
	 */
	private static function server( $server ) {
		if ( in_array( $server, array( 'nginx', 'apache' ), true ) ) {
			return $server;
		}
		if ( '' !== $server ) {
			WP_CLI::error( __( 'Unknown --server. Use: nginx or apache.', 'scrapelock' ) );
		}
		$seen = PNCP_Rules_State::state()['format'];
		if ( '' !== $seen ) {
			return $seen;
		}
		return 'apache' === PNCP_Stealth::server() ? 'apache' : 'nginx';
	}

	/**
	 * A fresh check of the installed rules: the server asked now; when it answered without them, asked again 4 s
	 * later (a reload in between), as the admin page does before it says "not found".
	 *
	 * @param string $server nginx, apache or '' (see server()).
	 * @return array<string, string>
	 */
	public static function status( $server = '' ) {
		$server = self::server( $server );
		$check  = static function () use ( $server ) {
			return 'apache' === $server ? PNCP_Rules_Status::apache( true ) : PNCP_Rules_Status::nginx( true );
		};
		$st     = $check();
		if ( 'missing' === $st['state'] && in_array( $st['kind'], array( 'wp', 'nginx', 'no_header' ), true ) ) {
			sleep( PNCP_Rules_State::RECHECK_GAP + 1 );
			$st = $check();
		}
		$names  = array(
			'current' => 'current',
			'stale'   => 'out_of_date',
			'missing' => 'not_found',
			'error'   => 'error',
		);
		$state  = PNCP_Rules_State::state();
		$via    = $st['via'];
		if ( 'origin' === $via && '' !== $st['ip'] ) {
			$via .= ' ' . $st['ip'];
		}
		if ( in_array( $st['kind'], array( 'header', 'header_wp' ), true ) ) {
			$via = 'header' . ( '' !== $via ? ' (' . $via . ')' : '' );
		}
		$text = 'apache' === $server ? PNCP_Rules_Status::apache_text( $st ) : PNCP_Rules_Status::nginx_text( $st );
		$out  = array(
			'server'    => $server,
			'state'     => isset( $names[ $st['state'] ] ) ? $names[ $st['state'] ] : $st['state'],
			'parts'     => implode( ',', $st['parts'] ),
			'via'       => $via,
			'installed' => $state['installed'],
			'seen'      => $state['seen'] ? gmdate( 'Y-m-d H:i:s', $state['seen'] ) . ' UTC' : '',
			'current'   => PNCP_Rules_State::current( $server ),
			'message'   => trim( $text['line'] . ' ' . $text['more'] ),
		);
		// 3.12.6: the Stealth rules' own status, where that class exists (PNCP_Stealth_Status).
		$stealth_status = array( 'PNCP_Stealth_Status', 'status' );
		if ( class_exists( $stealth_status[0] ) && is_callable( $stealth_status ) && ! empty( PNCP_Stealth::settings()['stealth_enabled'] ) ) {
			$stealth = (array) call_user_func( $stealth_status, true );
			foreach ( array( 'state', 'installed', 'want' ) as $key ) {
				if ( isset( $stealth[ $key ] ) && is_scalar( $stealth[ $key ] ) ) {
					$out[ 'stealth_' . ( 'want' === $key ? 'current' : $key ) ] = (string) $stealth[ $key ];
				}
			}
		}
		/**
		 * 3.12.6: the fields of "wp scrapelock rules status" (and of the status "rules install" prints at its end).
		 *
		 * @param array<string, string> $out    Field => value.
		 * @param string                $server nginx or apache.
		 */
		$out = (array) apply_filters( 'pncp_cli_rules_status', $out, $server );
		return array_map( 'strval', $out );
	}

	/**
	 * Prints a status: one JSON object, or field / value rows.
	 *
	 * @param array<string, string> $status What status() returned.
	 * @param string                $format table, json, csv or yaml.
	 */
	private static function print_status( $status, $format ) {
		if ( 'json' === $format ) {
			WP_CLI::line( (string) wp_json_encode( $status, JSON_UNESCAPED_SLASHES ) );
			return;
		}
		$rows = array();
		foreach ( $status as $field => $value ) {
			$rows[] = array(
				'field' => $field,
				'value' => $value,
			);
		}
		WP_CLI\Utils\format_items( $format, $rows, array( 'field', 'value' ) );
	}

	/* ---------- rules install ---------- */

	/**
	 * The options of "rules install": option => [part, server].
	 *
	 * @return array<string, array{0:string, 1:string}>
	 */
	private static function install_options() {
		return array(
			'nginx-http'     => array( 'nginx-http', 'nginx' ),
			'nginx-server'   => array( 'nginx-server', 'nginx' ),
			'stealth'        => array( 'stealth-nginx', 'nginx' ),
			'apache'         => array( 'apache', 'apache' ),
			'stealth-apache' => array( 'stealth-apache', 'apache' ),
		);
	}

	/**
	 * Checks a file named on the command line: an absolute path in a folder that exists; Nginx files end in .conf,
	 * Apache files are .htaccess or end in .conf; a symlink only to a file in the same folder; no leftover .old.
	 *
	 * @param string $path   Path.
	 * @param string $server nginx or apache.
	 * @return string|WP_Error The real file to write (a symlink's target, else the path).
	 */
	public static function check_path( $path, $server ) {
		$path = (string) $path;
		$name = basename( $path );
		if ( '' === $path || '/' !== $path[0] || false !== strpos( $path, "\0" ) || preg_match( '#(?:^|/)\.\.?(?:/|$)#', $path ) ) {
			/* translators: %s: path */
			return new WP_Error( 'pncp_path', sprintf( __( 'Give an absolute path without "..": %s', 'scrapelock' ), $path ) );
		}
		if ( 'nginx' === $server ? ! preg_match( '/^[^\/]+\.conf$/', $name ) : ( '.htaccess' !== $name && ! preg_match( '/^[^\/]+\.conf$/', $name ) ) ) {
			return new WP_Error(
				'pncp_path',
				'nginx' === $server
					/* translators: %s: path */
					? sprintf( __( 'Nginx rules go only into a file ending in .conf: %s', 'scrapelock' ), $path )
					/* translators: %s: path */
					: sprintf( __( 'Apache rules go only into a .htaccess file or a file ending in .conf: %s', 'scrapelock' ), $path )
			);
		}
		$dir = realpath( dirname( $path ) );
		if ( false === $dir || ! is_dir( $dir ) ) {
			/* translators: %s: folder */
			return new WP_Error( 'pncp_path', sprintf( __( 'The folder does not exist: %s', 'scrapelock' ), dirname( $path ) ) );
		}
		$real = $dir . '/' . $name;
		if ( is_link( $path ) ) {
			$target = realpath( $path );
			if ( false === $target || dirname( $target ) !== $dir || ! is_file( $target ) ) {
				/* translators: %s: path */
				return new WP_Error( 'pncp_path', sprintf( __( 'A symlink that points outside its folder (or to nothing) is never written through: %s', 'scrapelock' ), $path ) );
			}
			$real = $target;
		} elseif ( file_exists( $path ) && ! is_file( $path ) ) {
			/* translators: %s: path */
			return new WP_Error( 'pncp_path', sprintf( __( 'Not a file: %s', 'scrapelock' ), $path ) );
		}
		foreach ( array( '.new', '.old' ) as $ext ) {
			if ( is_link( $real . $ext ) || ( '.old' === $ext && file_exists( $real . $ext ) ) || ( file_exists( $real . $ext ) && ! is_file( $real . $ext ) ) ) {
				/* translators: %s: path */
				return new WP_Error( 'pncp_path', sprintf( __( 'Remove %s first (left from an earlier run?).', 'scrapelock' ), $real . $ext ) );
			}
		}
		return $real;
	}

	/**
	 * The placeholder of the static feeds' token in the rules, the token of the installed file (so the token the
	 * owner put there stays), or ''.
	 *
	 * @param string $old The installed file.
	 * @return string
	 */
	public static function installed_token( $old ) {
		foreach ( array( '/"~\^([A-Za-z0-9_\-]{8,200}):" 1;/', '/cp_token=([A-Za-z0-9_\-]{8,200})\(&\|\$\)/' ) as $regex ) {
			if ( preg_match( $regex, (string) $old, $m ) && 'YOUR_TOKEN' !== $m[1] ) {
				return $m[1];
			}
		}
		return '';
	}

	/**
	 * The file as it will be: an Nginx file or an Apache .conf is the part itself; a .htaccess keeps everything
	 * but the part's block (# BEGIN ScrapeLock … # END ScrapeLock), which is replaced, or added above
	 * # BEGIN WordPress (or at the top).
	 *
	 * @param string $part The part (parts()).
	 * @param string $text The part's text.
	 * @param string $old  The file now ('' = none).
	 * @param bool   $htaccess The file is a .htaccess.
	 * @return string
	 */
	public static function file_text( $part, $text, $old, $htaccess ) {
		if ( ! $htaccess ) {
			return $text;
		}
		$begin = 'stealth-apache' === $part ? '# BEGIN ScrapeLock Stealth' : '# BEGIN ScrapeLock';
		$end   = 'stealth-apache' === $part ? '# END ScrapeLock Stealth' : '# END ScrapeLock';
		// The main block's BEGIN carries the version; the Stealth block's never matches it (no digit after it).
		$regex = '/^' . preg_quote( $begin, '/' ) . ( 'stealth-apache' === $part ? '' : '(?: [0-9][^\n]*)?' ) . '\R.*?^' . preg_quote( $end, '/' ) . '[ \t]*(?:\R|\z)/ms';
		if ( preg_match( $regex, $old ) ) {
			return (string) preg_replace_callback(
				$regex,
				static function () use ( $text ) {
					return $text;
				},
				$old,
				1
			);
		}
		$pos = strpos( $old, '# BEGIN WordPress' );
		return false === $pos ? $text . ( '' !== $old ? "\n" . $old : '' ) : substr( $old, 0, $pos ) . $text . "\n" . substr( $old, $pos );
	}

	/**
	 * A unified diff (3 lines of context) of two texts, '' when they are the same.
	 *
	 * @param string $old   Old text.
	 * @param string $new   New text.
	 * @param string $label The file's name.
	 * @return string
	 */
	public static function unified_diff( $old, $new, $label ) {
		if ( $old === $new ) {
			return '';
		}
		if ( ! class_exists( 'Text_Diff', false ) ) {
			require_once ABSPATH . WPINC . '/wp-diff.php';
		}
		$a    = '' === $old ? array() : explode( "\n", rtrim( $old, "\n" ) );
		$b    = '' === $new ? array() : explode( "\n", rtrim( $new, "\n" ) );
		$diff = new Text_Diff( 'native', array( $a, $b ) );
		$flat = array(); // [type, line, old line no, new line no].
		$x    = 1;
		$y    = 1;
		foreach ( $diff->getDiff() as $op ) {
			// An addition has no orig, a deletion no final (false, not an empty array).
			$orig  = is_array( $op->orig ) ? $op->orig : array();
			$final = is_array( $op->final ) ? $op->final : array();
			if ( $op instanceof Text_Diff_Op_copy ) {
				foreach ( $orig as $line ) {
					$flat[] = array( ' ', $line, $x++, $y++ );
				}
				continue;
			}
			foreach ( $orig as $line ) {
				$flat[] = array( '-', $line, $x++, $y );
			}
			foreach ( $final as $line ) {
				$flat[] = array( '+', $line, $x, $y++ );
			}
		}
		$out  = '--- ' . $label . "\n+++ " . $label . ".new\n";
		$n    = count( $flat );
		$i    = 0;
		$ctx  = 3;
		while ( $i < $n ) {
			if ( ' ' === $flat[ $i ][0] ) {
				++$i;
				continue;
			}
			$start = max( 0, $i - $ctx );
			$end   = $i;
			$last  = $i;
			for ( $j = $i; $j < $n; $j++ ) {
				if ( ' ' !== $flat[ $j ][0] ) {
					$last = $j;
				} elseif ( $j - $last > 2 * $ctx ) {
					break;
				}
			}
			$end   = min( $n - 1, $last + $ctx );
			$lines = '';
			$xl    = 0;
			$yl    = 0;
			for ( $k = $start; $k <= $end; $k++ ) {
				$lines .= $flat[ $k ][0] . $flat[ $k ][1] . "\n";
				$xl    += '+' === $flat[ $k ][0] ? 0 : 1;
				$yl    += '-' === $flat[ $k ][0] ? 0 : 1;
			}
			$xs   = $xl ? $flat[ $start ][2] : $flat[ $start ][2] - 1;
			$ys   = $yl ? $flat[ $start ][3] : $flat[ $start ][3] - 1;
			$out .= '@@ -' . $xs . ( 1 === $xl ? '' : ',' . $xl ) . ' +' . $ys . ( 1 === $yl ? '' : ',' . $yl ) . " @@\n" . $lines;
			$i    = $end + 1;
		}
		return $out;
	}

	/**
	 * The program on PATH (then the usual places), or ''.
	 *
	 * @param string[] $names  Program names.
	 * @param string[] $places Other full paths to try.
	 * @return string
	 */
	public static function find_program( $names, $places = array() ) {
		foreach ( $names as $name ) {
			foreach ( explode( PATH_SEPARATOR, (string) getenv( 'PATH' ) ) as $dir ) {
				if ( '' !== $dir && is_file( $dir . '/' . $name ) && is_executable( $dir . '/' . $name ) ) {
					return $dir . '/' . $name;
				}
			}
		}
		foreach ( $places as $place ) {
			if ( is_file( $place ) && is_executable( $place ) ) {
				return $place;
			}
		}
		return '';
	}

	/**
	 * Runs a command of the system (through the shell, as typed by the person at the server, or built here with
	 * escapeshellarg()): its exit code and its output (stdout and stderr together).
	 *
	 * @param string $command The command.
	 * @return array{0:int, 1:string}
	 */
	private static function run( $command ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open -- WP-CLI only (cli_only()): the test and reload commands of the web server, which is what "rules install" is for.
		$proc = proc_open(
			$command . ' 2>&1',
			array(
				0 => array( 'file', '/dev/null', 'r' ),
				1 => array( 'pipe', 'w' ),
			),
			$pipes
		);
		if ( ! is_resource( $proc ) ) {
			return array( 127, __( 'The command could not be started.', 'scrapelock' ) );
		}
		$output = (string) stream_get_contents( $pipes[1] );
		fclose( $pipes[1] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- The pipe of proc_open().
		return array( (int) proc_close( $proc ), trim( $output ) );
	}

	/**
	 * The default test and reload commands of a server ('' = none: a .htaccess is read on every request).
	 *
	 * @param string $server   nginx or apache.
	 * @param bool   $htaccess Only .htaccess files.
	 * @return array{test:string, reload:string, alt:string}
	 */
	private static function commands( $server, $htaccess ) {
		if ( 'nginx' === $server ) {
			$bin = self::find_program( array( 'nginx' ), array( '/usr/sbin/nginx', '/usr/local/sbin/nginx', '/www/server/nginx/sbin/nginx' ) );
			$sys = self::find_program( array( 'systemctl' ) );
			return array(
				'test'   => '' !== $bin ? escapeshellarg( $bin ) . ' -t' : '',
				'reload' => '' !== $bin ? escapeshellarg( $bin ) . ' -s reload' : '',
				'alt'    => '' !== $sys ? escapeshellarg( $sys ) . ' reload nginx' : '',
			);
		}
		if ( $htaccess ) {
			return array(
				'test'   => '',
				'reload' => '',
				'alt'    => '',
			);
		}
		$bin = self::find_program( array( 'apachectl', 'apache2ctl' ), array( '/usr/sbin/apachectl', '/usr/sbin/apache2ctl' ) );
		return array(
			'test'   => '' !== $bin ? escapeshellarg( $bin ) . ' -t' : '',
			'reload' => '' !== $bin ? escapeshellarg( $bin ) . ' -k graceful' : '',
			'alt'    => '',
		);
	}

	/**
	 * The site's home page answers (not 5xx) after a .htaccess change, which Apache reads on the next request.
	 *
	 * @return array{0:int, 1:string}
	 */
	private static function http_test() {
		$r = wp_remote_get(
			add_query_arg( 'pncp_rules', time(), home_url( '/' ) ),
			array(
				'timeout'     => 10,
				'redirection' => 0,
				'sslverify'   => false,
				'user-agent'  => PNCP_Self_Check::user_agent(),
			)
		);
		$code = is_wp_error( $r ) ? 0 : (int) wp_remote_retrieve_response_code( $r );
		/* translators: %s: HTTP status or error */
		return array( $code >= 500 || 0 === $code ? 1 : 0, sprintf( __( 'The home page answered: %s', 'scrapelock' ), is_wp_error( $r ) ? $r->get_error_message() : 'HTTP ' . $code ) );
	}

	/**
	 * Puts back every file swapped so far (from its .old; a file that was new is removed).
	 *
	 * @param array<int, array<string, mixed>> $done The files swapped.
	 * @return string[] Files that could not be put back.
	 */
	private static function restore( $done ) {
		$bad = array();
		foreach ( array_reverse( $done ) as $f ) {
			$real = (string) $f['real'];
			// phpcs:disable WordPress.WP.AlternativeFunctions.rename_rename, WordPress.WP.AlternativeFunctions.unlink_unlink -- WP-CLI only: the web server's own files, named on the command line.
			$ok = $f['existed'] ? @rename( $real . '.old', $real ) : ( ! file_exists( $real ) || @unlink( $real ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Reported below.
			// phpcs:enable
			if ( ! $ok ) {
				$bad[] = $real;
			}
		}
		return $bad;
	}

	/**
	 * Wp scrapelock rules install.
	 *
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function install( $assoc_args ) {
		if ( PNCP_Lockdown::is_locked() ) {
			WP_CLI::error( __( 'The site is locked: nothing is installed until it is unlocked (with the authenticator app).', 'scrapelock' ) );
		}
		$dry   = ! empty( $assoc_args['dry-run'] );
		$files = array(); // Real path => file.
		foreach ( self::install_options() as $option => $def ) {
			if ( ! isset( $assoc_args[ $option ] ) ) {
				continue;
			}
			list( $part, $server ) = $def;
			$real                  = self::check_path( (string) $assoc_args[ $option ], $server );
			if ( is_wp_error( $real ) ) {
				WP_CLI::error( $real->get_error_message() );
			}
			$htaccess = '.htaccess' === basename( (string) $real );
			if ( isset( $files[ $real ] ) && ( ! $htaccess || $files[ $real ]['server'] !== $server ) ) {
				/* translators: %s: path */
				WP_CLI::error( sprintf( __( 'Two parts cannot go into the same file: %s', 'scrapelock' ), $real ) );
			}
			if ( ! isset( $files[ $real ] ) ) {
				$files[ $real ] = array(
					'real'     => $real,
					'path'     => (string) $assoc_args[ $option ],
					'server'   => $server,
					'htaccess' => $htaccess,
					'parts'    => array(),
				);
			}
			$files[ $real ]['parts'][] = $part;
		}
		if ( ! $files ) {
			WP_CLI::error( __( 'Name the files: --nginx-http=<file> --nginx-server=<file> [--stealth=<file>], or --apache=<file> [--stealth-apache=<file>]. Nothing is guessed.', 'scrapelock' ) );
		}
		PNCP_Rules_State::remember_texts(); // As the Server rules tab: the text installed is kept for "See what changed".
		$changed = array();
		foreach ( $files as $real => $f ) {
			$old   = is_file( $real ) ? (string) file_get_contents( $real ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A local file named on the command line.
			$token = self::installed_token( $old );
			$new   = $old;
			foreach ( $f['parts'] as $part ) {
				$text = self::part_text( $part );
				if ( false !== strpos( $text, 'YOUR_TOKEN' ) ) {
					if ( '' === $token ) {
						/* translators: %s: path */
						WP_CLI::error( sprintf( __( 'The rules for the static private feeds need your token in place of YOUR_TOKEN, and %s has none to keep: install them by hand once (Server rules), then this command keeps that token.', 'scrapelock' ), $f['path'] ) );
					}
					$text = str_replace( 'YOUR_TOKEN', $token, $text );
				}
				$new = $f['htaccess'] || 1 < count( $f['parts'] ) ? self::file_text( $part, $text, $new, $f['htaccess'] ) : $text;
			}
			if ( $new === $old ) {
				/* translators: %s: path */
				WP_CLI::log( sprintf( __( 'Unchanged, skipped: %s', 'scrapelock' ), $f['path'] ) );
				continue;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- WP-CLI only: the web server's file named on the command line, written next to it first.
			if ( false === @file_put_contents( $real . '.new', $new, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Reported right here.
				foreach ( $changed as $c ) {
					wp_delete_file( $c['real'] . '.new' );
				}
				/* translators: %s: path */
				WP_CLI::error( sprintf( __( 'Could not write %s.', 'scrapelock' ), $real . '.new' ) );
			}
			if ( is_file( $real ) ) {
				@chmod( $real . '.new', fileperms( $real ) & 0777 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- The permissions of the file it replaces.
			}
			$diff = self::unified_diff( $old, $new, $f['path'] );
			WP_CLI::log( '' !== $token ? str_replace( $token, '[token]', $diff ) : $diff );
			$f['existed'] = is_file( $real );
			$changed[]    = $f;
		}
		if ( ! $changed ) {
			WP_CLI::success( __( 'The installed files are already the current rules: nothing to do.', 'scrapelock' ) );
			self::print_status( self::status( (string) reset( $files )['server'] ), 'table' );
			return;
		}
		if ( $dry ) {
			foreach ( $changed as $f ) {
				wp_delete_file( $f['real'] . '.new' );
			}
			WP_CLI::success( __( 'Dry run: nothing was changed.', 'scrapelock' ) );
			return;
		}
		if ( empty( $assoc_args['yes'] ) ) {
			/* translators: %d: number of files */
			WP_CLI::confirm( sprintf( _n( 'Install this %d file, test the configuration and reload?', 'Install these %d files, test the configuration and reload?', count( $changed ), 'scrapelock' ), count( $changed ) ) );
		}
		// The swap: each file to .old (kept until the test passed), the .new one in its place.
		$done = array();
		foreach ( $changed as $f ) {
			$real = $f['real'];
			// phpcs:disable WordPress.WP.AlternativeFunctions.rename_rename -- WP-CLI only: the web server's files named on the command line.
			$ok = ( ! $f['existed'] || @rename( $real, $real . '.old' ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Reported below.
			if ( $ok && ! @rename( $real . '.new', $real ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Reported below.
				if ( $f['existed'] ) {
					@rename( $real . '.old', $real ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Best effort, reported below.
				}
				$ok = false;
			}
			// phpcs:enable
			if ( ! $ok ) {
				$bad = self::restore( $done );
				foreach ( $changed as $c ) {
					wp_delete_file( $c['real'] . '.new' );
				}
				/* translators: 1: path, 2: files that could not be put back */
				WP_CLI::error( sprintf( __( 'Could not put %1$s in place; the files were put back.%2$s', 'scrapelock' ), $real, $bad ? ' ' . implode( ', ', $bad ) : '' ) );
			}
			$done[] = $f;
		}
		// Test, then reload, per server; any failure puts every file back.
		$servers = array();
		foreach ( $changed as $f ) {
			$servers[ $f['server'] ] = isset( $servers[ $f['server'] ] ) ? $servers[ $f['server'] ] && $f['htaccess'] : $f['htaccess'];
		}
		$fail = static function ( $what, $output ) use ( $done ) {
			$bad = self::restore( $done );
			if ( '' !== $output ) {
				WP_CLI::log( $output );
			}
			if ( $bad ) {
				/* translators: 1: what failed, 2: files */
				WP_CLI::error( sprintf( __( '%1$s failed, and these files could not be put back from their .old copy: %2$s', 'scrapelock' ), $what, implode( ', ', $bad ) ) );
			}
			/* translators: %s: what failed */
			WP_CLI::error( sprintf( __( '%s failed: every file was put back as it was.', 'scrapelock' ), $what ) );
		};
		$reloads = array();
		foreach ( $servers as $server => $htaccess ) {
			$cmds = self::commands( $server, $htaccess );
			$test = isset( $assoc_args['test-cmd'] ) ? (string) $assoc_args['test-cmd'] : $cmds['test'];
			if ( '' === $test && 'nginx' === $server ) {
				$fail( __( 'The test', 'scrapelock' ), __( 'nginx was not found on PATH: give --test-cmd and --reload-cmd.', 'scrapelock' ) );
			}
			list( $rc, $output ) = '' === $test ? self::http_test() : self::run( $test );
			if ( 0 !== $rc ) {
				/* translators: %s: command */
				$fail( sprintf( __( 'The test (%s)', 'scrapelock' ), '' === $test ? 'HTTP' : $test ), $output );
			}
			/* translators: %s: command */
			WP_CLI::log( sprintf( __( 'Test passed: %s', 'scrapelock' ), '' === $test ? 'HTTP' : $test ) );
			$reloads[ $server ] = $cmds;
		}
		foreach ( $reloads as $server => $cmds ) {
			$reload = isset( $assoc_args['reload-cmd'] ) ? (string) $assoc_args['reload-cmd'] : $cmds['reload'];
			if ( '' === $reload ) {
				continue; // A .htaccess: read on every request.
			}
			list( $rc, $output ) = self::run( $reload );
			if ( 0 !== $rc && ! isset( $assoc_args['reload-cmd'] ) && '' !== $cmds['alt'] ) {
				list( $rc, $output ) = self::run( $cmds['alt'] );
				$reload              = $cmds['alt'];
			}
			if ( 0 !== $rc ) {
				/* translators: %s: command */
				$fail( sprintf( __( 'The reload (%s)', 'scrapelock' ), $reload ), $output );
			}
			/* translators: %s: command */
			WP_CLI::log( sprintf( __( 'Reloaded: %s', 'scrapelock' ), $reload ) );
		}
		foreach ( $done as $f ) {
			if ( $f['existed'] ) {
				wp_delete_file( $f['real'] . '.old' );
			}
		}
		/* translators: %d: number of files */
		WP_CLI::success( sprintf( _n( '%d file installed.', '%d files installed.', count( $done ), 'scrapelock' ), count( $done ) ) );
		sleep( 1 ); // The workers of the reloaded server.
		self::print_status( self::status( (string) array_key_first( $servers ) ), 'table' );
	}

	/* ---------- wp scrapelock verify-file ---------- */

	/**
	 * Wp scrapelock verify-file add <path> --content=<text>|--from=<file> [--hours=24] [--write] | list | remove <path>.
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function verify_file( $args, $assoc_args ) {
		self::cli_only();
		$action = isset( $args[0] ) ? (string) $args[0] : 'list';
		$path   = isset( $args[1] ) ? (string) $args[1] : '';
		if ( 'list' === $action ) {
			$rows = array();
			foreach ( PNCP_Verify_Files::all() as $p => $f ) {
				$rows[] = array(
					'path'  => $p,
					'url'   => PNCP_Verify_Files::url_of( $p ),
					'until' => gmdate( 'Y-m-d H:i:s', $f['until'] ) . ' UTC',
					'bytes' => strlen( $f['content'] ),
					'disk'  => $f['disk'] ? 'yes' : 'no',
				);
			}
			WP_CLI\Utils\format_items( self::format( $assoc_args ), $rows, array( 'path', 'url', 'until', 'bytes', 'disk' ) );
			return;
		}
		if ( 'add' === $action ) {
			if ( isset( $assoc_args['content'] ) === isset( $assoc_args['from'] ) ) {
				WP_CLI::error( __( 'Give the content with --content=<text> or --from=<file> (one of the two).', 'scrapelock' ) );
			}
			$content = isset( $assoc_args['content'] ) ? (string) $assoc_args['content'] : '';
			if ( isset( $assoc_args['from'] ) ) {
				$from = (string) $assoc_args['from'];
				if ( ! is_file( $from ) || ! is_readable( $from ) || filesize( $from ) > PNCP_Verify_Files::MAX_BYTES ) {
					/* translators: 1: file, 2: kilobytes */
					WP_CLI::error( sprintf( __( 'Cannot read %1$s (a readable file of at most %2$d KB).', 'scrapelock' ), $from, (int) ( PNCP_Verify_Files::MAX_BYTES / 1024 ) ) );
				}
				$content = (string) file_get_contents( $from ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A local file named on the command line.
			}
			$result = PNCP_Verify_Files::add( $path, $content, isset( $assoc_args['hours'] ) ? (int) $assoc_args['hours'] : 24, ! empty( $assoc_args['write'] ) );
			if ( is_wp_error( $result ) ) {
				WP_CLI::error( $result->get_error_message() );
			}
			self::print_lines( PNCP_Verify_Files::result_lines( $result ) );
			return;
		}
		if ( 'remove' === $action ) {
			if ( PNCP_Lockdown::is_locked() ) {
				WP_CLI::error( __( 'The site is locked: nothing can be changed until it is unlocked (with the authenticator app).', 'scrapelock' ) );
			}
			$result = PNCP_Verify_Files::remove( '' !== $path && '/' !== $path[0] ? '/' . $path : $path );
			if ( ! $result['removed'] ) {
				WP_CLI::error( __( 'There is no such verification file.', 'scrapelock' ) );
			}
			if ( 'kept' === $result['disk'] ) {
				WP_CLI::warning( __( 'The file in the root folder was changed since ScrapeLock wrote it, so it was left there.', 'scrapelock' ) );
			}
			self::print_lines( PNCP_Verify_Files::purge_lines( $result['purge'] ) );
			/* translators: %s: path */
			WP_CLI::success( sprintf( __( '%s was removed.', 'scrapelock' ), $path ) );
			return;
		}
		WP_CLI::error( __( 'Unknown action. Use: add, list or remove.', 'scrapelock' ) );
	}

	/**
	 * Prints [class, text] lines: success, warning, or a plain line.
	 *
	 * @param array<int, array{0:string, 1:string}> $lines Lines.
	 */
	private static function print_lines( $lines ) {
		foreach ( $lines as $line ) {
			if ( 'success' === $line[0] ) {
				WP_CLI::success( $line[1] );
			} elseif ( 'warning' === $line[0] || 'error' === $line[0] ) {
				WP_CLI::warning( $line[1] );
			} else {
				WP_CLI::log( $line[1] );
			}
		}
	}

	/* ---------- wp scrapelock cdn ---------- */

	/**
	 * Wp scrapelock cdn purge <url>... | --all [--yes].
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cdn( $args, $assoc_args ) {
		self::cli_only();
		$action = isset( $args[0] ) ? (string) $args[0] : '';
		if ( 'purge' !== $action ) {
			WP_CLI::error( __( 'Unknown action. Use: purge.', 'scrapelock' ) );
		}
		$urls = array_slice( $args, 1 );
		$all  = ! empty( $assoc_args['all'] );
		if ( $all && $urls ) {
			WP_CLI::error( __( 'Give addresses or --all, not both.', 'scrapelock' ) );
		}
		if ( ! $all && ! $urls ) {
			WP_CLI::error( __( 'Give the addresses to purge, or --all.', 'scrapelock' ) );
		}
		if ( null === PNCP_Bunny::credentials() && ! PNCP_Edge::cloudflare_connected() ) {
			WP_CLI::error( __( 'No CDN connection is set (Bunny CDN or Cloudflare under "Blocking at the CDN", or the Bunny card).', 'scrapelock' ) );
		}
		if ( $all && empty( $assoc_args['yes'] ) ) {
			WP_CLI::confirm( __( 'Purge the whole CDN cache of this site?', 'scrapelock' ) );
		}
		$result = PNCP_Edge::cdn_purge( $urls, $all );
		if ( $result['refused'] ) {
			/* translators: %s: addresses */
			WP_CLI::error( sprintf( __( 'Not an address of this site (nothing was purged): %s', 'scrapelock' ), implode( ', ', $result['refused'] ) ) );
		}
		$failed = 0;
		foreach ( $result['rows'] as $provider => $row ) {
			if ( 'ok' === $row['status'] ) {
				if ( $all ) {
					/* translators: %s: CDN name */
					WP_CLI::success( sprintf( __( '%s: the whole cache was purged.', 'scrapelock' ), $provider ) );
				} else {
					/* translators: 1: CDN name, 2: number of addresses */
					WP_CLI::success( sprintf( _n( '%1$s: %2$d address purged.', '%1$s: %2$d addresses purged.', $row['done'], 'scrapelock' ), $provider, $row['done'] ) );
				}
				continue;
			}
			++$failed;
			/* translators: 1: CDN name, 2: number of addresses purged before the error, 3: error message */
			WP_CLI::warning( sprintf( __( '%1$s: not purged (%2$d done before the error): %3$s', 'scrapelock' ), $provider, $row['done'], $row['message'] ) );
		}
		if ( $failed ) {
			WP_CLI::halt( 1 );
		}
	}
}
