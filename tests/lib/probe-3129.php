<?php
/**
 * Tests only (t_3129_requests.php copies it into mu-plugins and removes it at the end): for a request with the
 * header X-PNCP-Probe, every database query and every file access made from ScrapeLock's own code (the plugin
 * folder, or a query anywhere below a call from it) is noted, and written at the very end of the request to
 * wp-content/pncp-probe/<id>.json. PHP files the plugin includes are not counted (opcache serves them).
 *
 * @package ScrapeLock
 */

// phpcs:disable -- Test fixture, not shipped code.

if ( empty( $_SERVER['HTTP_X_PNCP_PROBE'] ) || ! preg_match( '/^[a-z0-9_-]{1,40}$/', (string) $_SERVER['HTTP_X_PNCP_PROBE'] ) ) {
	return;
}

final class PNCP_Probe_3129 {
	public static $root = '';
	public static $db   = array();
	public static $io   = array();
	public static $t0   = 0.0;
	public static $busy = false;

	public static function ours( $file ) {
		static $plugin = null;
		if ( null === $plugin && defined( 'PNCP_DIR' ) ) {
			$plugin = rtrim( (string) PNCP_DIR, '/' ) . '/'; // The path PHP loaded the plugin from (no stale realpath cache).
			self::$root = $plugin;
		}
		return '' !== self::$root && is_string( $file ) && 0 === strpos( $file, self::$root ) && 0 !== strpos( $file, self::$root . 'tests/' );
	}

	/** The first frame of plugin code anywhere in the stack (for queries), or ''. */
	public static function from_plugin() {
		foreach ( debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS ) as $f ) {
			if ( isset( $f['file'] ) && self::ours( $f['file'] ) ) {
				return substr( $f['file'], strlen( self::$root ) ) . ':' . $f['line'];
			}
		}
		return '';
	}

	/** The code that called the file function, if it is the plugin's (for file access), or ''. */
	public static function direct_caller() {
		$trace = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS );
		foreach ( $trace as $f ) {
			if ( isset( $f['class'] ) && __CLASS__ === $f['class'] || isset( $f['class'] ) && 'PNCP_Probe_3129_File' === $f['class'] ) {
				continue;
			}
			if ( isset( $f['file'] ) ) {
				if ( isset( $f['function'] ) && in_array( $f['function'], array( 'require', 'require_once', 'include', 'include_once' ), true ) ) {
					return ''; // Loading the plugin's code (opcache), not its own file access.
				}
				return self::ours( $f['file'] ) ? substr( $f['file'], strlen( self::$root ) ) . ':' . $f['line'] : '';
			}
		}
		return '';
	}

	public static function note_io( $op, $path ) {
		if ( self::$busy ) {
			return;
		}
		if ( 'stat' === $op && preg_match( '#/includes/class-pncp-[a-z0-9-]+\.php$#', (string) $path ) ) {
			return; // The class autoloader finding the plugin's code (opcache_is_script_cached() with opcache).
		}
		$who = self::direct_caller();
		if ( '' !== $who ) {
			self::$io[] = $who . ' ' . $op . ' ' . basename( (string) $path );
		}
	}
}

final class PNCP_Probe_3129_File {
	public $context;
	private $h;
	private $d;

	private static function real( callable $fn ) {
		stream_wrapper_restore( 'file' );
		try {
			return $fn();
		} finally {
			stream_wrapper_unregister( 'file' );
			stream_wrapper_register( 'file', __CLASS__ );
		}
	}
	public function stream_open( $path, $mode, $options, &$opened ) {
		if ( ! ( $options & 0x80 ) ) { // Not STREAM_OPEN_FOR_INCLUDE.
			PNCP_Probe_3129::note_io( 'open(' . $mode . ')', $path );
		}
		$ctx     = $this->context;
		$this->h = self::real(
			static function () use ( $path, $mode, $options, $ctx ) {
				$use = (bool) ( $options & STREAM_USE_PATH );
				return $ctx ? @fopen( $path, $mode, $use, $ctx ) : @fopen( $path, $mode, $use );
			}
		);
		if ( $this->h && ( $options & STREAM_USE_PATH ) ) {
			$opened = $path;
		}
		return (bool) $this->h;
	}
	public function stream_read( $n ) { return fread( $this->h, $n ); }
	public function stream_write( $d ) { return fwrite( $this->h, $d ); }
	public function stream_eof() { return feof( $this->h ); }
	public function stream_tell() { return ftell( $this->h ); }
	public function stream_seek( $o, $w = SEEK_SET ) { return 0 === fseek( $this->h, $o, $w ); }
	public function stream_flush() { return fflush( $this->h ); }
	public function stream_close() { if ( $this->h ) { fclose( $this->h ); } }
	public function stream_stat() { return fstat( $this->h ); }
	public function stream_lock( $op ) { PNCP_Probe_3129::note_io( 'flock', '' ); return flock( $this->h, $op ); }
	public function stream_truncate( $n ) { return ftruncate( $this->h, $n ); }
	public function stream_set_option( $o, $a1, $a2 ) { return false; }
	public function stream_metadata( $path, $option, $value ) {
		PNCP_Probe_3129::note_io( 'meta', $path );
		return self::real(
			static function () use ( $path, $option, $value ) {
				switch ( $option ) {
					case STREAM_META_TOUCH:
						return @touch( $path, isset( $value[0] ) ? $value[0] : time(), isset( $value[1] ) ? $value[1] : time() );
					case STREAM_META_ACCESS:
						return @chmod( $path, $value );
					case STREAM_META_OWNER:
					case STREAM_META_OWNER_NAME:
						return @chown( $path, $value );
					case STREAM_META_GROUP:
					case STREAM_META_GROUP_NAME:
						return @chgrp( $path, $value );
				}
				return false;
			}
		);
	}
	public function url_stat( $path, $flags ) {
		PNCP_Probe_3129::note_io( 'stat', $path );
		return self::real(
			static function () use ( $path, $flags ) {
				if ( $flags & STREAM_URL_STAT_LINK ) {
					return @lstat( $path );
				}
				return ( $flags & STREAM_URL_STAT_QUIET ) ? ( file_exists( $path ) ? @stat( $path ) : false ) : @stat( $path );
			}
		);
	}
	public function unlink( $path ) { PNCP_Probe_3129::note_io( 'unlink', $path ); return self::real( static function () use ( $path ) { return @unlink( $path ); } ); }
	public function rename( $a, $b ) { PNCP_Probe_3129::note_io( 'rename', $a ); return self::real( static function () use ( $a, $b ) { return @rename( $a, $b ); } ); }
	public function mkdir( $p, $m, $o ) { PNCP_Probe_3129::note_io( 'mkdir', $p ); return self::real( static function () use ( $p, $m, $o ) { return @mkdir( $p, $m, (bool) ( $o & STREAM_MKDIR_RECURSIVE ) ); } ); }
	public function rmdir( $p, $o ) { PNCP_Probe_3129::note_io( 'rmdir', $p ); return self::real( static function () use ( $p ) { return @rmdir( $p ); } ); }
	public function dir_opendir( $p, $o ) { PNCP_Probe_3129::note_io( 'opendir', $p ); $this->d = self::real( static function () use ( $p ) { return @opendir( $p ); } ); return (bool) $this->d; }
	public function dir_readdir() { return readdir( $this->d ); }
	public function dir_rewinddir() { rewinddir( $this->d ); return true; }
	public function dir_closedir() { closedir( $this->d ); return true; }
}

PNCP_Probe_3129::$t0   = microtime( true );
$pncp_probe_root       = realpath( WP_CONTENT_DIR . '/plugins/scrapelock' );
PNCP_Probe_3129::$root = $pncp_probe_root ? $pncp_probe_root . '/' : '';
stream_wrapper_unregister( 'file' );
stream_wrapper_register( 'file', 'PNCP_Probe_3129_File' );

add_filter(
	'query',
	static function ( $q ) {
		$who = PNCP_Probe_3129::from_plugin();
		if ( '' !== $who ) {
			PNCP_Probe_3129::$db[] = $who . ' ' . substr( preg_replace( '/\s+/', ' ', (string) $q ), 0, 160 );
		}
		return $q;
	},
	-PHP_INT_MAX
);

// Written last (after every shutdown callback, the plugin's included).
add_action(
	'shutdown',
	static function () {
		register_shutdown_function(
			static function () {
				PNCP_Probe_3129::$busy = true;
				stream_wrapper_restore( 'file' );
				$dir = WP_CONTENT_DIR . '/pncp-probe';
				if ( ! is_dir( $dir ) ) {
					@mkdir( $dir, 0700 );
				}
				file_put_contents(
					$dir . '/' . $_SERVER['HTTP_X_PNCP_PROBE'] . '.json',
					json_encode(
						array(
							'db'     => PNCP_Probe_3129::$db,
							'io'     => PNCP_Probe_3129::$io,
							'ms'     => round( ( microtime( true ) - PNCP_Probe_3129::$t0 ) * 1000, 2 ),
							'status' => http_response_code(),
							'ext'    => wp_using_ext_object_cache(),
							'total'  => isset( $GLOBALS['wpdb'] ) ? (int) $GLOBALS['wpdb']->num_queries : 0,
						)
					)
				);
			}
		);
	},
	PHP_INT_MAX
);
