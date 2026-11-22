<?php
/**
 * Tests only (t_3129_strace.php puts a wp-content/object-cache.php that defines WP_REDIS_SCHEME / WP_REDIS_PATH and
 * includes this file, and removes it at the end): a small persistent object cache on Redis (phpredis), behaving
 * like Redis Object Cache: integers stored raw (so INCRBY is atomic), everything else serialized, per-site key
 * prefix (WP_CACHE_KEY_SALT), and redis_instance() for the connection.
 *
 * @package ScrapeLock
 */

// phpcs:disable -- Test fixture, not shipped code.

class PNCP_Test_Redis_Cache {
	public $r;
	public $local = array();
	public $np = array();
	public $global = array();
	public $prefix;
	public $blog = 1;
	public function __construct() {
		$this->prefix = defined( 'WP_CACHE_KEY_SALT' ) ? WP_CACHE_KEY_SALT : 'wp:';
		$this->r      = new Redis();
		$this->r->connect( WP_REDIS_PATH, 0, 1.0 );
		if ( defined( 'WP_REDIS_PASSWORD' ) ) {
			$this->r->auth( WP_REDIS_PASSWORD );
		}
	}
	public function redis_instance() {
		return $this->r;
	}
	private function k( $key, $group ) {
		$group = '' === $group ? 'default' : $group;
		return $this->prefix . ( isset( $this->global[ $group ] ) ? '' : $this->blog . ':' ) . $group . ':' . $key;
	}
	private function np( $group ) {
		return isset( $this->np[ '' === $group ? 'default' : $group ] );
	}
	private function enc( $v ) {
		return is_int( $v ) ? $v : serialize( $v );
	}
	private function dec( $v ) {
		if ( is_string( $v ) && preg_match( '/^-?\d+$/', $v ) ) {
			return (int) $v;
		}
		return unserialize( $v );
	}
	public function get( $key, $group = 'default', $force = false, &$found = null ) {
		$k = $this->k( $key, $group );
		if ( ! $force && array_key_exists( $k, $this->local ) ) {
			$found = true;
			return is_object( $this->local[ $k ] ) ? clone $this->local[ $k ] : $this->local[ $k ];
		}
		if ( $this->np( $group ) ) {
			$found = false;
			return false;
		}
		$v = $this->r->get( $k );
		if ( false === $v ) {
			$found = false;
			return false;
		}
		$found = true;
		$v     = $this->dec( $v );
		$this->local[ $k ] = $v;
		return is_object( $v ) ? clone $v : $v;
	}
	public function set( $key, $data, $group = 'default', $expire = 0 ) {
		$k = $this->k( $key, $group );
		$this->local[ $k ] = is_object( $data ) ? clone $data : $data;
		if ( ! $this->np( $group ) ) {
			$expire > 0 ? $this->r->setex( $k, (int) $expire, $this->enc( $data ) ) : $this->r->set( $k, $this->enc( $data ) );
		}
		return true;
	}
	public function add( $key, $data, $group = 'default', $expire = 0 ) {
		$k = $this->k( $key, $group );
		if ( $this->np( $group ) ) {
			if ( array_key_exists( $k, $this->local ) ) {
				return false;
			}
			$this->local[ $k ] = $data;
			return true;
		}
		$opts = array( 'nx' );
		if ( $expire > 0 ) {
			$opts['ex'] = (int) $expire;
		}
		$ok = $this->r->set( $k, $this->enc( $data ), $opts );
		if ( $ok ) {
			$this->local[ $k ] = $data;
		}
		return (bool) $ok;
	}
	public function replace( $key, $data, $group = 'default', $expire = 0 ) {
		$k = $this->k( $key, $group );
		if ( $this->np( $group ) ) {
			if ( ! array_key_exists( $k, $this->local ) ) {
				return false;
			}
			$this->local[ $k ] = $data;
			return true;
		}
		$opts = array( 'xx' );
		if ( $expire > 0 ) {
			$opts['ex'] = (int) $expire;
		}
		$ok = $this->r->set( $k, $this->enc( $data ), $opts );
		if ( $ok ) {
			$this->local[ $k ] = $data;
		}
		return (bool) $ok;
	}
	public function delete( $key, $group = 'default' ) {
		$k = $this->k( $key, $group );
		unset( $this->local[ $k ] );
		return $this->np( $group ) ? true : (bool) $this->r->del( $k );
	}
	public function incr( $key, $n = 1, $group = 'default' ) {
		$k = $this->k( $key, $group );
		if ( $this->np( $group ) ) {
			if ( ! array_key_exists( $k, $this->local ) ) {
				return false;
			}
			$this->local[ $k ] = max( 0, (int) $this->local[ $k ] + (int) $n );
			return $this->local[ $k ];
		}
		if ( ! $this->r->exists( $k ) ) {
			return false;
		}
		$v = (int) $this->r->incrBy( $k, (int) $n );
		if ( $v < 0 ) {
			$this->r->set( $k, 0, array( 'keepttl' ) );
			$v = 0;
		}
		$this->local[ $k ] = $v;
		return $v;
	}
	public function flush() {
		$this->local = array();
		$it = null;
		while ( $keys = $this->r->scan( $it, $this->prefix . '*', 1000 ) ) {
			$this->r->del( $keys );
		}
		return true;
	}
	public function flush_runtime() {
		$this->local = array();
		return true;
	}
	public function add_non_persistent_groups( $g ) {
		foreach ( (array) $g as $x ) {
			$this->np[ $x ] = true;
		}
	}
	public function add_global_groups( $g ) {
		foreach ( (array) $g as $x ) {
			$this->global[ $x ] = true;
		}
	}
	public function switch_to_blog( $id ) {
		$this->blog = (int) $id;
	}
}
function wp_cache_init() { $GLOBALS['wp_object_cache'] = new PNCP_Test_Redis_Cache(); }
function wp_cache_add( $k, $d, $g = '', $e = 0 ) { return $GLOBALS['wp_object_cache']->add( $k, $d, $g, $e ); }
function wp_cache_add_multiple( array $d, $g = '', $e = 0 ) { $o = array(); foreach ( $d as $k => $v ) { $o[ $k ] = wp_cache_add( $k, $v, $g, $e ); } return $o; }
function wp_cache_set( $k, $d, $g = '', $e = 0 ) { return $GLOBALS['wp_object_cache']->set( $k, $d, $g, $e ); }
function wp_cache_set_multiple( array $d, $g = '', $e = 0 ) { $o = array(); foreach ( $d as $k => $v ) { $o[ $k ] = wp_cache_set( $k, $v, $g, $e ); } return $o; }
function wp_cache_replace( $k, $d, $g = '', $e = 0 ) { return $GLOBALS['wp_object_cache']->replace( $k, $d, $g, $e ); }
function wp_cache_get( $k, $g = '', $force = false, &$found = null ) { return $GLOBALS['wp_object_cache']->get( $k, $g, $force, $found ); }
function wp_cache_get_multiple( $keys, $g = '', $force = false ) { $o = array(); foreach ( $keys as $k ) { $o[ $k ] = wp_cache_get( $k, $g, $force ); } return $o; }
function wp_cache_delete( $k, $g = '' ) { return $GLOBALS['wp_object_cache']->delete( $k, $g ); }
function wp_cache_delete_multiple( array $keys, $g = '' ) { $o = array(); foreach ( $keys as $k ) { $o[ $k ] = wp_cache_delete( $k, $g ); } return $o; }
function wp_cache_incr( $k, $n = 1, $g = '' ) { return $GLOBALS['wp_object_cache']->incr( $k, $n, $g ); }
function wp_cache_decr( $k, $n = 1, $g = '' ) { return $GLOBALS['wp_object_cache']->incr( $k, -$n, $g ); }
function wp_cache_flush() { return $GLOBALS['wp_object_cache']->flush(); }
function wp_cache_flush_runtime() { return $GLOBALS['wp_object_cache']->flush_runtime(); }
function wp_cache_flush_group( $g ) { return false; }
function wp_cache_supports( $f ) { return in_array( $f, array( 'add_multiple', 'set_multiple', 'get_multiple', 'delete_multiple', 'flush_runtime' ), true ); }
function wp_cache_close() { return true; }
function wp_cache_add_global_groups( $g ) { $GLOBALS['wp_object_cache']->add_global_groups( $g ); }
function wp_cache_add_non_persistent_groups( $g ) { $GLOBALS['wp_object_cache']->add_non_persistent_groups( $g ); }
function wp_cache_switch_to_blog( $id ) { $GLOBALS['wp_object_cache']->switch_to_blog( $id ); }
function wp_cache_reset() {}
