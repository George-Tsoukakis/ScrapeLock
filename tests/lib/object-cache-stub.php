<?php
/**
 * Tests only: a small persistent object cache (one file per key) for sites without Redis. t_3129_requests.php
 * copies it to wp-content/object-cache.php when REDIS_DROPIN is not given, and removes it at the end. It stands in
 * for Redis: values outlive the request, add() and incr() are atomic (one lock), non-persistent groups stay in
 * memory. Its own file access is not ScrapeLock's (the test's probe counts only calls made from the plugin's code).
 *
 * @package ScrapeLock
 */

// phpcs:disable -- Test fixture, not shipped code.

class PNCP_Test_Stub_Cache {
	public $dir;
	public $local  = array();
	public $np     = array();
	public $global = array();
	public $blog   = 1;

	public function __construct() {
		$this->dir = WP_CONTENT_DIR . '/pncp-test-cache';
		if ( ! is_dir( $this->dir ) ) {
			@mkdir( $this->dir, 0700, true );
		}
	}
	private function id( $key, $group ) {
		$group = '' === (string) $group ? 'default' : (string) $group;
		$blog  = isset( $this->global[ $group ] ) ? 0 : $this->blog;
		return $blog . ':' . $group . ':' . $key;
	}
	private function path( $id ) {
		return $this->dir . '/' . md5( $id );
	}
	private function persistent( $group ) {
		return ! isset( $this->np[ '' === (string) $group ? 'default' : (string) $group ] );
	}
	private function lock() {
		$h = fopen( $this->dir . '/.lock', 'c' );
		flock( $h, LOCK_EX );
		return $h;
	}
	private function unlock( $h ) {
		flock( $h, LOCK_UN );
		fclose( $h );
	}
	private function load( $id, &$found ) {
		$raw = @file_get_contents( $this->path( $id ) );
		if ( false === $raw ) {
			$found = false;
			return false;
		}
		$row = unserialize( $raw );
		if ( ! is_array( $row ) || ( $row[0] > 0 && $row[0] < time() ) ) {
			$found = false;
			return false;
		}
		$found = true;
		return $row[1];
	}
	private function store( $id, $data, $expire ) {
		$tmp = $this->path( $id ) . '.' . getmypid() . mt_rand();
		file_put_contents( $tmp, serialize( array( $expire > 0 ? time() + (int) $expire : 0, $data ) ) );
		rename( $tmp, $this->path( $id ) );
	}
	public function get( $key, $group = 'default', $force = false, &$found = null ) {
		$id = $this->id( $key, $group );
		if ( ! $force && array_key_exists( $id, $this->local ) ) {
			$found = true;
			return is_object( $this->local[ $id ] ) ? clone $this->local[ $id ] : $this->local[ $id ];
		}
		if ( ! $this->persistent( $group ) ) {
			$found = false;
			return false;
		}
		$v = $this->load( $id, $found );
		if ( $found ) {
			$this->local[ $id ] = $v;
		}
		return $v;
	}
	public function set( $key, $data, $group = 'default', $expire = 0 ) {
		$id                 = $this->id( $key, $group );
		$this->local[ $id ] = is_object( $data ) ? clone $data : $data;
		if ( $this->persistent( $group ) ) {
			$this->store( $id, $data, (int) $expire );
		}
		return true;
	}
	public function add( $key, $data, $group = 'default', $expire = 0 ) {
		$id = $this->id( $key, $group );
		if ( ! $this->persistent( $group ) ) {
			if ( array_key_exists( $id, $this->local ) ) {
				return false;
			}
			$this->local[ $id ] = $data;
			return true;
		}
		$h = $this->lock();
		$f = null;
		$this->load( $id, $f );
		if ( ! $f ) {
			$this->store( $id, $data, (int) $expire );
			$this->local[ $id ] = $data;
		}
		$this->unlock( $h );
		return ! $f;
	}
	public function replace( $key, $data, $group = 'default', $expire = 0 ) {
		$f = null;
		$this->get( $key, $group, true, $f );
		return $f ? $this->set( $key, $data, $group, $expire ) : false;
	}
	public function delete( $key, $group = 'default' ) {
		$id = $this->id( $key, $group );
		unset( $this->local[ $id ] );
		if ( $this->persistent( $group ) ) {
			@unlink( $this->path( $id ) );
		}
		return true;
	}
	public function incr( $key, $n = 1, $group = 'default' ) {
		$id = $this->id( $key, $group );
		if ( ! $this->persistent( $group ) ) {
			if ( ! isset( $this->local[ $id ] ) ) {
				return false;
			}
			$this->local[ $id ] = max( 0, (int) $this->local[ $id ] + (int) $n );
			return $this->local[ $id ];
		}
		$h   = $this->lock();
		$f   = null;
		$v   = $this->load( $id, $f );
		$raw = $f ? @unserialize( (string) @file_get_contents( $this->path( $id ) ) ) : null;
		if ( $f ) {
			$v   = max( 0, (int) $v + (int) $n );
			$exp = is_array( $raw ) && $raw[0] > 0 ? $raw[0] - time() : 0;
			$this->store( $id, $v, max( 0, $exp ) );
			$this->local[ $id ] = $v;
		}
		$this->unlock( $h );
		return $f ? $v : false;
	}
	public function flush() {
		$this->local = array();
		foreach ( (array) glob( $this->dir . '/*' ) as $file ) {
			@unlink( $file );
		}
		return true;
	}
}

function wp_cache_init() {
	$GLOBALS['wp_object_cache'] = new PNCP_Test_Stub_Cache();
}
function wp_cache_get( $key, $group = '', $force = false, &$found = null ) {
	return $GLOBALS['wp_object_cache']->get( $key, $group, $force, $found );
}
function wp_cache_get_multiple( $keys, $group = '', $force = false ) {
	$out = array();
	foreach ( $keys as $k ) {
		$out[ $k ] = wp_cache_get( $k, $group, $force );
	}
	return $out;
}
function wp_cache_set( $key, $data, $group = '', $expire = 0 ) {
	return $GLOBALS['wp_object_cache']->set( $key, $data, $group, $expire );
}
function wp_cache_set_multiple( array $data, $group = '', $expire = 0 ) {
	$out = array();
	foreach ( $data as $k => $v ) {
		$out[ $k ] = wp_cache_set( $k, $v, $group, $expire );
	}
	return $out;
}
function wp_cache_add( $key, $data, $group = '', $expire = 0 ) {
	return $GLOBALS['wp_object_cache']->add( $key, $data, $group, $expire );
}
function wp_cache_add_multiple( array $data, $group = '', $expire = 0 ) {
	$out = array();
	foreach ( $data as $k => $v ) {
		$out[ $k ] = wp_cache_add( $k, $v, $group, $expire );
	}
	return $out;
}
function wp_cache_replace( $key, $data, $group = '', $expire = 0 ) {
	return $GLOBALS['wp_object_cache']->replace( $key, $data, $group, $expire );
}
function wp_cache_delete( $key, $group = '' ) {
	return $GLOBALS['wp_object_cache']->delete( $key, $group );
}
function wp_cache_delete_multiple( array $keys, $group = '' ) {
	$out = array();
	foreach ( $keys as $k ) {
		$out[ $k ] = wp_cache_delete( $k, $group );
	}
	return $out;
}
function wp_cache_incr( $key, $offset = 1, $group = '' ) {
	return $GLOBALS['wp_object_cache']->incr( $key, $offset, $group );
}
function wp_cache_decr( $key, $offset = 1, $group = '' ) {
	return $GLOBALS['wp_object_cache']->incr( $key, -$offset, $group );
}
function wp_cache_flush() {
	return $GLOBALS['wp_object_cache']->flush();
}
function wp_cache_flush_runtime() {
	$GLOBALS['wp_object_cache']->local = array();
	return true;
}
function wp_cache_flush_group( $group ) {
	return false;
}
function wp_cache_supports( $feature ) {
	return in_array( $feature, array( 'add_multiple', 'set_multiple', 'get_multiple', 'delete_multiple', 'flush_runtime' ), true );
}
function wp_cache_close() {
	return true;
}
function wp_cache_add_global_groups( $groups ) {
	foreach ( (array) $groups as $g ) {
		$GLOBALS['wp_object_cache']->global[ $g ] = true;
	}
}
function wp_cache_add_non_persistent_groups( $groups ) {
	foreach ( (array) $groups as $g ) {
		$GLOBALS['wp_object_cache']->np[ $g ] = true;
	}
}
function wp_cache_switch_to_blog( $blog_id ) {
	$GLOBALS['wp_object_cache']->blog = (int) $blog_id;
}
function wp_cache_reset() {
	$GLOBALS['wp_object_cache']->local = array();
}
