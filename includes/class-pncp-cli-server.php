<?php
/**
 * 3.12.6: WP-CLI for the server: "wp scrapelock rules show | status | install" (PNCP_Cli::rules()) and
 * "wp scrapelock cdn purge" (PNCP_Cli::cdn()) and "wp scrapelock verify-file add | list | remove"
 * (PNCP_Cli::verify_file()); 3.12.7: "wp scrapelock cache status | purge" (PNCP_Cli::cache(), the Nginx fastcgi
 * cache, PNCP_Fastcgi_Cache), which runs "nginx -T" (the program's full path, escapeshellarg()) to read the
 * configuration.
 *
 * Only from WP-CLI (cli_only()). The stored credentials (Bunny API key, Cloudflare token) are used, never printed.
 * "rules install" writes only the files named on the command line: <file>.new, a diff, <file>.old while the new
 * one is tested, the test command (nginx -t), the reload, and every file back from its .old when the test or the
 * reload fails. This is the only class that runs commands of the system: the defaults are built here from the
 * program's full path with escapeshellarg(); the only command text from outside are --test-cmd and --reload-cmd,
 * which the person at the server types and which run through the shell as given. Nothing of a request, a setting
 * or a stored option ever becomes part of a command.
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
		// 3.12.6: the Stealth rules' own status (PNCP_Stealth_Status, a fresh check), while Stealth is turned on:
		// state (current, stale, unmarked, missing, error), the installed and the current fingerprint.
		if ( ! empty( PNCP_Stealth::settings()['stealth_enabled'] ) ) {
			$stealth                  = PNCP_Stealth_Status::status( true );
			$out['stealth_state']     = $stealth['state'];
			$out['stealth_installed'] = $stealth['installed'];
			$out['stealth_current']   = $stealth['want'];
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
	 * 3.12.8: the test and reload commands "rules install" runs for a server: --test-cmd and --reload-cmd as given,
	 * else the defaults (commands()); the reload falls back to the alternative (systemctl reload nginx) when the
	 * server's own program was not found. A configuration that is read only at a reload (Nginx, an Apache .conf)
	 * needs both: "missing" names the one that is not there (the install then stops and puts every file back). A
	 * .htaccess alone needs neither: the home page is asked instead, and Apache reads it on every request.
	 *
	 * @param string                                        $server     nginx or apache.
	 * @param bool                                          $htaccess   Only .htaccess files.
	 * @param array<string, string>                         $assoc_args Options.
	 * @param array{test:string, reload:string, alt:string} $cmds       commands().
	 * @return array{test:string, reload:string, alt:string, missing:string, message:string}
	 */
	public static function install_commands( $server, $htaccess, $assoc_args, $cmds ) {
		$given  = isset( $assoc_args['reload-cmd'] );
		$test   = isset( $assoc_args['test-cmd'] ) ? (string) $assoc_args['test-cmd'] : (string) $cmds['test'];
		$reload = $given ? (string) $assoc_args['reload-cmd'] : (string) $cmds['reload'];
		$alt    = $given ? '' : (string) $cmds['alt'];
		if ( '' === $reload && '' !== $alt ) {
			$reload = $alt;
			$alt    = '';
		}
		$out = array(
			'test'    => $test,
			'reload'  => $reload,
			'alt'     => $alt,
			'missing' => '',
			'message' => '',
		);
		if ( $htaccess ) {
			return $out;
		}
		if ( '' === $test ) {
			$out['missing'] = 'test';
			$out['message'] = 'nginx' === $server
				? __( 'nginx was not found on PATH: give --test-cmd and --reload-cmd.', 'scrapelock' )
				: __( 'apachectl was not found on PATH: give --test-cmd and --reload-cmd.', 'scrapelock' );
		} elseif ( '' === $reload ) {
			$out['missing'] = 'reload';
			/* translators: %s: nginx or apache */
			$out['message'] = sprintf( __( 'No command to reload %s was found: give --reload-cmd.', 'scrapelock' ), $server );
		}
		return $out;
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
			// owner: the .old file is the original itself (renamed, same inode), so it comes back with its owner and mode.
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
			// 3.12.10: the .new file gets the owner, group and exact mode of the file it replaces before the swap
			// (WP-CLI often runs as root; a root-owned .htaccess could no longer be read or written by the web
			// server). A new .htaccess is 0644 and, as root, belongs to the owner of the WordPress folder, as
			// WordPress's own .htaccess does. A new .conf stays root's (the server reads it as root; handing it to
			// the web server's user would let that user change the server's configuration). A chown that fails
			// (not root) changes nothing.
			$meta = PNCP_File_Owner::capture( $real );
			if ( null !== $meta ) {
				PNCP_File_Owner::restore( $real . '.new', $meta );
			} elseif ( $f['htaccess'] ) {
				@chmod( $real . '.new', 0644 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- A new .htaccess, readable by the web server.
				PNCP_File_Owner::restore( $real . '.new', null );
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
			// 3.12.8: a configuration read only at a reload needs a test and a reload command (install_commands()).
			$plan = self::install_commands( $server, $htaccess, $assoc_args, self::commands( $server, $htaccess ) );
			if ( '' !== $plan['missing'] ) {
				$fail( 'test' === $plan['missing'] ? __( 'The test', 'scrapelock' ) : __( 'The reload', 'scrapelock' ), $plan['message'] );
			}
			$test                = $plan['test'];
			list( $rc, $output ) = '' === $test ? self::http_test() : self::run( $test );
			if ( 0 !== $rc ) {
				/* translators: %s: command */
				$fail( sprintf( __( 'The test (%s)', 'scrapelock' ), '' === $test ? 'HTTP' : $test ), $output );
			}
			/* translators: %s: command */
			WP_CLI::log( sprintf( __( 'Test passed: %s', 'scrapelock' ), '' === $test ? 'HTTP' : $test ) );
			$reloads[ $server ] = $plan;
		}
		foreach ( $reloads as $server => $cmds ) {
			$reload = $cmds['reload'];
			if ( '' === $reload ) {
				continue; // A .htaccess: read on every request.
			}
			list( $rc, $output ) = self::run( $reload );
			if ( 0 !== $rc && '' !== $cmds['alt'] ) {
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
		// 3.12.7: the server's fastcgi cache first (by default with --all), so the CDN fetches fresh pages.
		$server = isset( $assoc_args['server-cache'] ) ? (bool) $assoc_args['server-cache'] : $all;
		$cdn    = null !== PNCP_Bunny::credentials() || PNCP_Edge::cloudflare_connected();
		// 3.12.8: before both, the page caches of the WordPress cache plugins (WP Rocket and the others).
		$plugin = self::plugin_cache_wanted( $assoc_args, $all );
		if ( ! $cdn && ! $server && ! $plugin ) { // Nothing to empty: as in 3.12.6.
			WP_CLI::error( __( 'No CDN connection is set (Bunny CDN or Cloudflare under "Blocking at the CDN", or the Bunny card).', 'scrapelock' ) );
		}
		$good = self::own_urls( $urls );
		if ( $all && empty( $assoc_args['yes'] ) ) {
			self::plugin_cache_announce( (array) $plugin );
			WP_CLI::confirm( $server ? __( 'Purge the whole CDN cache of this site, and its pages in the server\'s fastcgi cache?', 'scrapelock' ) : __( 'Purge the whole CDN cache of this site?', 'scrapelock' ) );
		}
		$failed = 0;
		if ( null !== $plugin ) {
			self::plugin_cache_purge( $all ? null : $good, ! empty( $assoc_args['minify'] ) );
		}
		if ( $server && ! self::server_cache_purge( $all ? null : $good, $assoc_args, false ) ) {
			++$failed;
		}
		if ( ! $cdn ) {
			WP_CLI::warning( __( 'No CDN connection is set (Bunny CDN or Cloudflare under "Blocking at the CDN", or the Bunny card).', 'scrapelock' ) );
			WP_CLI::halt( $failed ? 1 : 0 );
		}
		$result = PNCP_Edge::cdn_purge( $good, $all );
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

	/**
	 * 3.12.8: whether "cdn purge" empties the cache plugins' page caches: on unless --no-plugin-cache.
	 * --minify needs --all (the CDN would keep the old minified files that other pages still link).
	 *
	 * @param array<string, string> $assoc_args Options.
	 * @param bool                  $all        --all.
	 * @return string[]|null Names of the active cache plugins; null with --no-plugin-cache.
	 */
	private static function plugin_cache_wanted( $assoc_args, $all ) {
		if ( ! empty( $assoc_args['minify'] ) && ! $all ) {
			WP_CLI::error( __( '--minify needs --all: the CDN would keep the old minified files.', 'scrapelock' ) );
		}
		if ( isset( $assoc_args['plugin-cache'] ) && ! $assoc_args['plugin-cache'] ) {
			if ( ! empty( $assoc_args['minify'] ) ) {
				WP_CLI::error( __( '--minify empties the cache plugins\' files: not with --no-plugin-cache.', 'scrapelock' ) );
			}
			return null;
		}
		return array_keys( array_filter( pncp_cache_plugins() ) );
	}

	/**
	 * Before the confirmation of --all: the cache plugins whose page caches are emptied first.
	 *
	 * @param string[] $names Active cache plugins.
	 */
	private static function plugin_cache_announce( $names ) {
		if ( $names ) {
			/* translators: %s: names of cache plugins */
			WP_CLI::log( sprintf( __( 'First the page caches of: %s.', 'scrapelock' ), implode( ', ', $names ) ) );
		}
	}

	/**
	 * Empties the cache plugins' page caches (pncp_purge_plugin_caches()) and prints one line for each.
	 *
	 * @param string[]|null $urls   Full addresses of this site, or null for every page.
	 * @param bool          $minify Also the minified CSS / JS files (--minify).
	 */
	private static function plugin_cache_purge( $urls, $minify ) {
		foreach ( pncp_purge_plugin_caches( $urls, $minify ) as $row ) {
			$page = 'page' === $row['kind'];
			if ( 'cleaned' === $row['status'] ) {
				/* translators: %s: name of a cache plugin */
				$text = sprintf( $page ? __( '%s page cache: cleaned', 'scrapelock' ) : __( '%s: cleaned', 'scrapelock' ), $row['name'] );
			} elseif ( 'skipped' === $row['status'] ) {
				/* translators: %s: name of a cache plugin */
				$text = sprintf( __( '%s page cache: not cleaned (it cannot empty single addresses; use --all)', 'scrapelock' ), $row['name'] );
			} elseif ( 'kept' === $row['status'] ) {
				/* translators: %s: name of a cache plugin */
				$text = sprintf( __( '%s: kept (--minify empties them)', 'scrapelock' ), $row['name'] );
			} else {
				/* translators: %s: name of a cache plugin */
				$text = sprintf( $page ? __( '%s page cache: not active', 'scrapelock' ) : __( '%s: not active', 'scrapelock' ), $row['name'] );
			}
			WP_CLI::log( $text );
		}
	}

	/**
	 * The full addresses of this site for the arguments; stops (nothing purged) when one is not this site's.
	 *
	 * @param string[] $urls Addresses or paths.
	 * @return string[]
	 */
	private static function own_urls( $urls ) {
		$good    = array();
		$refused = array();
		foreach ( $urls as $url ) {
			$own = PNCP_Edge::own_url( (string) $url );
			if ( '' === $own ) {
				$refused[] = (string) $url;
			} else {
				$good[] = $own;
			}
		}
		if ( $refused ) {
			/* translators: %s: addresses */
			WP_CLI::error( sprintf( __( 'Not an address of this site (nothing was purged): %s', 'scrapelock' ), implode( ', ', $refused ) ) );
		}
		return $good;
	}

	/* ---------- wp scrapelock cache (3.12.7) ---------- */

	/**
	 * Wp scrapelock cache status | purge <url>... | --all [--yes] [--dry-run] [--cache-dir=<dir>] [--nginx-conf=<file>].
	 *
	 * @param string[]              $args       Arguments.
	 * @param array<string, string> $assoc_args Options.
	 */
	public static function cache( $args, $assoc_args ) {
		self::cli_only();
		$action = isset( $args[0] ) ? (string) $args[0] : 'status';
		if ( 'status' === $action ) {
			self::cache_status( $assoc_args );
			return;
		}
		if ( 'purge' !== $action ) {
			WP_CLI::error( __( 'Unknown action. Use: status or purge.', 'scrapelock' ) );
		}
		$urls = array_slice( $args, 1 );
		$all  = ! empty( $assoc_args['all'] );
		if ( $all && $urls ) {
			WP_CLI::error( __( 'Give addresses or --all, not both.', 'scrapelock' ) );
		}
		if ( ! $all && ! $urls ) {
			WP_CLI::error( __( 'Give the addresses to purge, or --all.', 'scrapelock' ) );
		}
		$good = self::own_urls( $urls );
		$dry  = ! empty( $assoc_args['dry-run'] );
		if ( $all && ! $dry && empty( $assoc_args['yes'] ) ) {
			WP_CLI::confirm( __( 'Delete every page of this site from the server\'s fastcgi cache?', 'scrapelock' ) );
		}
		if ( ! self::server_cache_purge( $all ? null : $good, $assoc_args, $dry ) ) {
			WP_CLI::halt( 1 );
		}
	}

	/**
	 * Where the fastcgi cache is: --cache-dir, else SCRAPELOCK_FASTCGI_CACHE_PATH / Nginx Helper, else the Nginx
	 * configuration (--nginx-conf=<file>, else nginx -T).
	 *
	 * @param array<string, string> $assoc_args Options.
	 * @param bool                  $known      3.12.8: false = not the constant / Nginx Helper (to compare them).
	 * @return array{dirs:array<int, array{path:string, source:string}>, notes:string[], keys:array<string, string>}
	 */
	public static function cache_dirs( $assoc_args, $known = true ) {
		$out = array(
			'dirs'  => array(),
			'notes' => array(),
			'keys'  => array(),
		);
		if ( isset( $assoc_args['cache-dir'] ) && '' !== trim( (string) $assoc_args['cache-dir'] ) ) {
			foreach ( explode( ',', (string) $assoc_args['cache-dir'] ) as $path ) {
				if ( '' !== trim( $path ) ) {
					$out['dirs'][] = array(
						'path'   => trim( $path ),
						'source' => '--cache-dir',
					);
				}
			}
			return $out;
		}
		$out['dirs'] = $known ? PNCP_Fastcgi_Cache::known_dirs() : array();
		if ( $out['dirs'] ) {
			return $out;
		}
		if ( isset( $assoc_args['nginx-conf'] ) && '' !== trim( (string) $assoc_args['nginx-conf'] ) ) {
			$main   = trim( (string) $assoc_args['nginx-conf'] );
			$source = $main;
			if ( '/' !== $main[0] || ! is_file( $main ) || ! is_readable( $main ) ) {
				/* translators: %s: file */
				WP_CLI::error( sprintf( __( 'Cannot read the Nginx configuration file %s.', 'scrapelock' ), $main ) );
			}
			$tree = PNCP_Fastcgi_Cache::tree( $main, array( __CLASS__, 'conf_files' ), dirname( $main ) );
		} else {
			$bin = self::find_program( array( 'nginx' ), array( '/usr/sbin/nginx', '/usr/local/sbin/nginx', '/www/server/nginx/sbin/nginx' ) );
			if ( '' === $bin ) {
				$out['notes'][] = __( 'nginx was not found on PATH: give --nginx-conf=<file> or --cache-dir=<dir>, or set SCRAPELOCK_FASTCGI_CACHE_PATH.', 'scrapelock' );
				return $out;
			}
			$source        = 'nginx -T';
			list( , $dump ) = self::run( escapeshellarg( $bin ) . ' -T' );
			$files         = PNCP_Fastcgi_Cache::dump_files( $dump );
			if ( 1 === count( $files ) && isset( $files[''] ) ) {
				/* translators: %s: output of nginx -T */
				$out['notes'][] = sprintf( __( 'nginx -T printed no configuration (run WP-CLI as root?): %s', 'scrapelock' ), substr( trim( $dump ), 0, 300 ) );
				return $out;
			}
			$main = (string) key( $files );
			$tree = PNCP_Fastcgi_Cache::tree( $main, $files, dirname( $main ) );
		}
		$found        = PNCP_Fastcgi_Cache::find_caches( $tree, PNCP_Edge::site_hosts() );
		$out['notes'] = $found['notes'];
		if ( ! $found['servers'] ) {
			/* translators: %s: host names */
			$out['notes'][] = sprintf( __( 'No server { } block with server_name %s in the Nginx configuration.', 'scrapelock' ), implode( ' / ', PNCP_Edge::site_hosts() ) );
		} elseif ( ! $found['caches'] ) {
			$out['notes'][] = __( 'This site\'s server { } block uses no fastcgi_cache.', 'scrapelock' );
		}
		foreach ( $found['caches'] as $c ) {
			$out['dirs'][]             = array(
				'path'   => $c['path'],
				/* translators: 1: where it was read, 2: cache zone */
				'source' => sprintf( __( '%1$s, zone %2$s', 'scrapelock' ), $source, $c['zone'] ),
			);
			$out['keys'][ $c['path'] ] = $c['key'];
		}
		return $out;
	}

	/**
	 * The configuration files an include pattern names (for --nginx-conf): path => text, readable regular
	 * files of at most 1 MB, 100 at most.
	 *
	 * @param string $pattern Path or glob pattern.
	 * @return array<string, string>
	 */
	public static function conf_files( $pattern ) {
		$out   = array();
		$paths = glob( $pattern );
		foreach ( is_array( $paths ) ? array_slice( $paths, 0, 100 ) : array() as $path ) {
			if ( is_file( $path ) && is_readable( $path ) && filesize( $path ) <= MB_IN_BYTES ) {
				$out[ $path ] = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A local configuration file named by the person at the server.
			}
		}
		return $out;
	}

	/**
	 * Wp scrapelock cache status: where the cache is, how it was found, and this site's files in it.
	 *
	 * @param array<string, string> $assoc_args Options.
	 */
	private static function cache_status( $assoc_args ) {
		$found = self::cache_dirs( $assoc_args );
		foreach ( $found['notes'] as $note ) {
			WP_CLI::log( $note );
		}
		if ( ! $found['dirs'] ) {
			WP_CLI::log( __( 'No fastcgi cache folder is known for this site.', 'scrapelock' ) );
			return;
		}
		$rows = PNCP_Fastcgi_Cache::purge( $found['dirs'], null, array( 'dry' => true ) );
		$good = array(); // 3.12.8: the folders the purge accepts, for the constant.
		foreach ( $rows as $row ) {
			if ( '' === $row['error'] ) {
				$good[] = array(
					'path'   => $row['path'],
					'source' => $row['source'],
				);
			}
		}
		foreach ( $rows as $row ) {
			/* translators: 1: folder, 2: how it was found */
			WP_CLI::log( sprintf( __( 'Folder: %1$s (from %2$s)', 'scrapelock' ), $row['path'], $row['source'] ) );
			if ( isset( $found['keys'][ $row['path'] ] ) && '' !== $found['keys'][ $row['path'] ] ) {
				/* translators: %s: fastcgi_cache_key */
				WP_CLI::log( sprintf( __( 'Cache key: %s', 'scrapelock' ), $found['keys'][ $row['path'] ] ) );
			}
			if ( '' !== $row['error'] ) {
				WP_CLI::warning( $row['error'] );
				continue;
			}
			/* translators: 1: files of this site, 2: files looked at */
			WP_CLI::log( sprintf( __( 'This site\'s cached pages: %1$d (of %2$d files).', 'scrapelock' ), $row['matched'], $row['files'] ) );
			WP_CLI::log( wp_is_writable( $row['path'] ) ? __( 'Writable by this user: yes.', 'scrapelock' ) : __( 'Writable by this user: no (run WP-CLI as root or as the web server\'s user).', 'scrapelock' ) );
		}
		if ( $good ) {
			self::constant_state( $good, $assoc_args );
		} elseif ( ! empty( $assoc_args['save-constant'] ) ) {
			WP_CLI::error( __( 'Not saved: no folder the purge accepts.', 'scrapelock' ) );
		}
		$last = get_option( PNCP_Fastcgi_Cache::LAST );
		if ( is_array( $last ) && isset( $last['time'], $last['rows'] ) && is_array( $last['rows'] ) ) {
			$removed = 0;
			$failed  = 0;
			foreach ( $last['rows'] as $r ) {
				$removed += is_array( $r ) && isset( $r['removed'] ) ? (int) $r['removed'] : 0;
				$failed  += is_array( $r ) && isset( $r['failed'] ) ? (int) $r['failed'] : 0;
			}
			/* translators: 1: date and time, 2: number of files, 3: number of files */
			WP_CLI::log( sprintf( __( 'Last purge: %1$s, %2$d files removed, %3$d could not be deleted.', 'scrapelock' ), wp_date( 'Y-m-d H:i', (int) $last['time'] ), $removed, $failed ) );
		}
	}

	/**
	 * When the folder was found in the Nginx configuration: how to let the automatic purges use it too.
	 *
	 * @param array<int, array{path:string, source:string}> $dirs Folders.
	 */
	private static function constant_hint( $dirs ) {
		if ( ! $dirs || PNCP_Fastcgi_Cache::known_dirs() ) {
			return;
		}
		/* translators: %s: command */
		WP_CLI::log( sprintf( __( 'So that ScrapeLock\'s automatic purges (settings, Stealth) empty it too: %s', 'scrapelock' ), self::constant_command( $dirs ) ) );
	}

	/**
	 * 3.12.8: the anchor of "wp config set": the line every wp-config.php has. WP-CLI's default anchor, the
	 * comment "That's all, stop editing!", is missing in some wp-config.php files, and then the command fails.
	 */
	const CONFIG_ANCHOR = "require_once ABSPATH . 'wp-settings.php';";

	/**
	 * 3.12.8: the ready-made "wp config set" command for SCRAPELOCK_FASTCGI_CACHE_PATH (the folders quoted for the
	 * shell; the anchor and placement put the line before wp-settings.php is loaded).
	 *
	 * @param array<int, array{path:string, source:string}> $dirs Folders.
	 * @return string
	 */
	public static function constant_command( $dirs ) {
		return 'wp config set SCRAPELOCK_FASTCGI_CACHE_PATH ' . escapeshellarg( self::constant_value( $dirs ) ) . ' --type=constant --anchor="' . self::CONFIG_ANCHOR . '" --placement=before';
	}

	/**
	 * The value of SCRAPELOCK_FASTCGI_CACHE_PATH for these folders (comma separated).
	 *
	 * @param array<int, array{path:string, source:string}> $dirs Folders.
	 * @return string
	 */
	private static function constant_value( $dirs ) {
		return implode( ',', array_values( array_unique( wp_list_pluck( $dirs, 'path' ) ) ) );
	}

	/**
	 * 3.12.8: whether SCRAPELOCK_FASTCGI_CACHE_PATH names the same folders as $found (order, a trailing slash
	 * and links aside).
	 *
	 * @param string                                        $value Value of the constant.
	 * @param array<int, array{path:string, source:string}> $found Folders found.
	 * @return bool
	 */
	public static function constant_matches( $value, $found ) {
		$norm = static function ( $paths ) {
			$out = array();
			foreach ( $paths as $path ) {
				$path = trim( (string) $path );
				if ( '' === $path ) {
					continue;
				}
				$real  = realpath( $path );
				$out[] = untrailingslashit( false !== $real ? $real : $path );
			}
			$out = array_values( array_unique( $out ) );
			sort( $out );
			return $out;
		};
		$a = $norm( explode( ',', $value ) );
		return array() !== $a && $norm( wp_list_pluck( $found, 'path' ) ) === $a;
	}

	/**
	 * 3.12.8, cache status: whether SCRAPELOCK_FASTCGI_CACHE_PATH is defined and names the folder found, and the
	 * ready-made "wp config set" line when it should be added or changed; --save-constant writes it.
	 *
	 * @param array<int, array{path:string, source:string}> $dirs       Folders cache_dirs() returned.
	 * @param array<string, string>                         $assoc_args Options.
	 */
	private static function constant_state( $dirs, $assoc_args ) {
		$defined = defined( 'SCRAPELOCK_FASTCGI_CACHE_PATH' ) && is_string( SCRAPELOCK_FASTCGI_CACHE_PATH ) && '' !== trim( SCRAPELOCK_FASTCGI_CACHE_PATH );
		$found   = $dirs;
		if ( $defined ) {
			// The folders came from the constant: read the Nginx configuration (or --cache-dir) to compare.
			$found = self::cache_dirs( $assoc_args, false )['dirs'];
			if ( ! $found ) {
				/* translators: %s: value of the constant */
				WP_CLI::log( sprintf( __( 'SCRAPELOCK_FASTCGI_CACHE_PATH is defined (%s); the Nginx configuration gave no folder to compare it with.', 'scrapelock' ), SCRAPELOCK_FASTCGI_CACHE_PATH ) );
				if ( ! empty( $assoc_args['save-constant'] ) ) {
					WP_CLI::log( __( 'Nothing to save.', 'scrapelock' ) );
				}
				return;
			}
			if ( self::constant_matches( SCRAPELOCK_FASTCGI_CACHE_PATH, $found ) ) {
				WP_CLI::log( __( 'SCRAPELOCK_FASTCGI_CACHE_PATH is defined and matches the folder found.', 'scrapelock' ) );
				if ( ! empty( $assoc_args['save-constant'] ) ) {
					WP_CLI::log( __( 'Nothing to save.', 'scrapelock' ) );
				}
				return;
			}
			/* translators: 1: value of the constant, 2: folders */
			WP_CLI::warning( sprintf( __( 'SCRAPELOCK_FASTCGI_CACHE_PATH is defined (%1$s) but the folder found is %2$s. To change it:', 'scrapelock' ), SCRAPELOCK_FASTCGI_CACHE_PATH, self::constant_value( $found ) ) );
		} elseif ( $dirs && 'Nginx Helper' === $dirs[0]['source'] ) {
			WP_CLI::log( __( 'SCRAPELOCK_FASTCGI_CACHE_PATH is not defined; Nginx Helper\'s folder is used. To name it anyway:', 'scrapelock' ) );
		} else {
			WP_CLI::log( __( 'SCRAPELOCK_FASTCGI_CACHE_PATH is not defined. So that ScrapeLock\'s automatic purges (settings, Stealth) empty this folder too, add it:', 'scrapelock' ) );
		}
		WP_CLI::log( '  ' . self::constant_command( $found ) );
		WP_CLI::log( __( '(The anchor: WP-CLI\'s default anchor "/* That\'s all, stop editing! */" is missing in some wp-config.php files.)', 'scrapelock' ) );
		if ( ! empty( $assoc_args['save-constant'] ) ) {
			self::save_constant( $found, $defined, $assoc_args );
		} elseif ( ! $defined && 'Nginx Helper' !== $found[0]['source'] ) {
			WP_CLI::log( __( 'Or run "wp scrapelock cache status --save-constant" to add it (checked on a copy of wp-config.php first).', 'scrapelock' ) );
		}
	}

	/**
	 * 3.12.8: cache status --save-constant: adds SCRAPELOCK_FASTCGI_CACHE_PATH to wp-config.php with WP-CLI's own
	 * "config set" (its config transformer), before the line that loads wp-settings.php. Only when the constant is
	 * not defined yet, the folders were found here (Nginx configuration or --cache-dir) and the purge accepts each,
	 * and wp-config.php is writable. First on a copy of wp-config.php: the copy must still parse and hold the line
	 * before wp-settings.php; then the file itself, checked the same way, and put back as it was if it is not.
	 *
	 * @param array<int, array{path:string, source:string}> $dirs       Folders found.
	 * @param bool                                          $defined    The constant is already defined.
	 * @param array<string, string>                         $assoc_args Options (--yes).
	 */
	private static function save_constant( $dirs, $defined, $assoc_args ) {
		if ( $defined ) {
			WP_CLI::error( __( 'Not saved: SCRAPELOCK_FASTCGI_CACHE_PATH is already defined. Change it with the command above, or by hand.', 'scrapelock' ) );
		}
		if ( 'Nginx Helper' === $dirs[0]['source'] ) {
			WP_CLI::error( __( 'Not saved: Nginx Helper\'s folder is already used by the automatic purges.', 'scrapelock' ) );
		}
		foreach ( PNCP_Fastcgi_Cache::purge( $dirs, null, array( 'dry' => true ) ) as $row ) {
			if ( '' !== $row['error'] ) {
				/* translators: %s: why the folder is refused */
				WP_CLI::error( sprintf( __( 'Not saved: %s', 'scrapelock' ), $row['error'] ) );
			}
		}
		$file = (string) \WP_CLI\Utils\locate_wp_config();
		if ( '' === $file || ! is_file( $file ) ) {
			WP_CLI::error( __( 'Not saved: wp-config.php was not found.', 'scrapelock' ) );
		}
		if ( ! wp_is_writable( $file ) || is_link( $file ) ) {
			/* translators: %s: file */
			WP_CLI::error( sprintf( __( 'Not saved: %s is not writable by this user (or is a link). Run the command above as its owner.', 'scrapelock' ), $file ) );
		}
		$value  = self::constant_value( $dirs );
		$before = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- wp-config.php, a local file.
		if ( false === strpos( $before, self::CONFIG_ANCHOR ) ) {
			/* translators: %s: line of wp-config.php */
			WP_CLI::error( sprintf( __( 'Not saved: wp-config.php has no line %s. Add the constant by hand, before wp-settings.php is loaded.', 'scrapelock' ), self::CONFIG_ANCHOR ) );
		}
		// The dry run: the same command on a copy.
		if ( ! function_exists( 'wp_tempnam' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$copy = wp_tempnam( 'pncp-wp-config' );
		file_put_contents( $copy, $before ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- A temporary copy.
		$res   = self::config_set( $value, $copy );
		$error = 0 === $res['code'] ? self::config_check( (string) file_get_contents( $copy ), $value ) : trim( $res['stderr'] . ' ' . $res['stdout'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- The temporary copy.
		wp_delete_file( $copy );
		if ( '' !== $error ) {
			/* translators: %s: error */
			WP_CLI::error( sprintf( __( 'Not saved: the trial on a copy of wp-config.php failed: %s', 'scrapelock' ), $error ) );
		}
		/* translators: 1: file, 2: value */
		WP_CLI::log( sprintf( __( 'Trial on a copy of %1$s: passed. It adds SCRAPELOCK_FASTCGI_CACHE_PATH = %2$s.', 'scrapelock' ), $file, $value ) );
		if ( empty( $assoc_args['yes'] ) ) {
			WP_CLI::confirm( __( 'Add it to wp-config.php now?', 'scrapelock' ) );
		}
		// 3.12.10: WP-CLI's config transformer writes the file in place today, but whatever it does (a later version
		// may write a new file), wp-config.php keeps its owner, group and exact mode (run as root, a root:root 0640
		// wp-config.php takes the site down for PHP-FPM).
		$meta = PNCP_File_Owner::capture( $file );
		$res  = self::config_set( $value, $file );
		PNCP_File_Owner::restore( $file, $meta );
		clearstatcache( true, $file );
		$error = 0 === $res['code'] ? self::config_check( (string) file_get_contents( $file ), $value ) : trim( $res['stderr'] . ' ' . $res['stdout'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- wp-config.php, a local file.
		if ( '' !== $error ) {
			file_put_contents( $file, $before ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- wp-config.php put back as it was.
			PNCP_File_Owner::restore( $file, $meta );
			/* translators: %s: error */
			WP_CLI::error( sprintf( __( 'Not saved (wp-config.php put back as it was): %s', 'scrapelock' ), $error ) );
		}
		WP_CLI::success( __( 'SCRAPELOCK_FASTCGI_CACHE_PATH added to wp-config.php: the automatic purges (settings, Stealth) empty this folder too.', 'scrapelock' ) );
	}

	/**
	 * Runs WP-CLI's "config set" for SCRAPELOCK_FASTCGI_CACHE_PATH on a file, in another process.
	 *
	 * @param string $value Value.
	 * @param string $file  wp-config.php or its copy.
	 * @return array{code:int, stdout:string, stderr:string}
	 */
	private static function config_set( $value, $file ) {
		$res = WP_CLI::runcommand(
			'config set SCRAPELOCK_FASTCGI_CACHE_PATH ' . escapeshellarg( $value ) . ' --type=constant --anchor=' . escapeshellarg( self::CONFIG_ANCHOR ) . ' --placement=before --config-file=' . escapeshellarg( $file ),
			array(
				'return'     => 'all',
				'exit_error' => false,
				'launch'     => true,
			)
		);
		return array(
			'code'   => is_object( $res ) && isset( $res->return_code ) ? (int) $res->return_code : 1,
			'stdout' => is_object( $res ) && isset( $res->stdout ) ? (string) $res->stdout : '',
			'stderr' => is_object( $res ) && isset( $res->stderr ) ? (string) $res->stderr : '',
		);
	}

	/**
	 * 3.12.8: checks a wp-config.php text after "config set": it parses as PHP, defines SCRAPELOCK_FASTCGI_CACHE_PATH
	 * once with this value, before the line that loads wp-settings.php. '' when good, else why not.
	 *
	 * @param string $text  Contents of the file.
	 * @param string $value Value of the constant.
	 * @return string
	 */
	public static function config_check( $text, $value ) {
		try {
			if ( ! token_get_all( $text, TOKEN_PARSE ) ) {
				return __( 'the file is empty.', 'scrapelock' );
			}
		} catch ( \ParseError $e ) {
			/* translators: %s: PHP parse error */
			return sprintf( __( 'the file no longer parses as PHP (%s).', 'scrapelock' ), $e->getMessage() );
		}
		$define = "define( 'SCRAPELOCK_FASTCGI_CACHE_PATH', " . var_export( $value, true ) . ' );'; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- The PHP literal WP-CLI writes.
		$at     = strpos( $text, $define );
		$load   = strpos( $text, self::CONFIG_ANCHOR );
		if ( false === $at || 1 !== substr_count( $text, "'SCRAPELOCK_FASTCGI_CACHE_PATH'" ) ) {
			return __( 'the line of the constant is not in the file once.', 'scrapelock' );
		}
		if ( false === $load || $at > $load ) {
			return __( 'the constant is not before the line that loads wp-settings.php.', 'scrapelock' );
		}
		return '';
	}

	/**
	 * Purges this site's pages (or the addresses) in the fastcgi cache and prints the counts.
	 *
	 * @param string[]|null         $urls       Full addresses of this site, or null for every page.
	 * @param array<string, string> $assoc_args Options (--cache-dir, --nginx-conf).
	 * @param bool                  $dry        Count only.
	 * @return bool False when files could not be deleted or a folder was refused.
	 */
	public static function server_cache_purge( $urls, $assoc_args, $dry ) {
		$found = self::cache_dirs( $assoc_args );
		foreach ( $found['notes'] as $note ) {
			WP_CLI::log( $note );
		}
		if ( ! $found['dirs'] ) {
			WP_CLI::log( __( 'Server cache: no fastcgi cache folder is known for this site (nothing purged there).', 'scrapelock' ) );
			return true;
		}
		$rows = PNCP_Fastcgi_Cache::purge( $found['dirs'], $urls, array( 'dry' => $dry ) );
		$ok   = true;
		foreach ( $rows as $row ) {
			if ( '' !== $row['error'] ) {
				/* translators: %s: error */
				WP_CLI::warning( sprintf( __( 'Server cache: %s', 'scrapelock' ), $row['error'] ) );
				$ok = false;
				continue;
			}
			if ( $dry ) {
				/* translators: 1: folder, 2: number of files, 3: files of other sites or other pages */
				WP_CLI::log( sprintf( __( 'Server cache (%1$s): %2$d files would be removed, %3$d other files kept.', 'scrapelock' ), $row['path'], $row['matched'], $row['other'] ) );
			} else {
				/* translators: 1: folder, 2: number of files, 3: files of other sites or other pages */
				WP_CLI::success( sprintf( __( 'Server cache (%1$s): %2$d files removed, %3$d other files kept.', 'scrapelock' ), $row['path'], $row['removed'], $row['other'] ) );
			}
			if ( $row['failed'] ) {
				$ok = false;
				/* translators: %d: number of files */
				WP_CLI::warning( sprintf( __( 'Server cache: %d files could not be deleted (no permission): run WP-CLI as root or as the web server\'s user.', 'scrapelock' ), $row['failed'] ) );
			}
			if ( $row['links'] ) {
				/* translators: %d: number of links */
				WP_CLI::log( sprintf( __( 'Server cache: %d symbolic links skipped (never followed).', 'scrapelock' ), $row['links'] ) );
			}
			if ( $row['capped'] ) {
				$ok = false;
				/* translators: %d: number of files */
				WP_CLI::warning( sprintf( __( 'Server cache: stopped after %d files: run it again.', 'scrapelock' ), $row['files'] ) );
			}
		}
		if ( ! $dry ) {
			PNCP_Fastcgi_Cache::remember( $rows, 'cli' );
			self::constant_hint( $found['dirs'] );
		}
		return $ok;
	}
}
