<?php
/**
 * 3.13.0: keeps the owner, group and permissions of the files the plugin writes.
 *
 * A file written into a temporary file and renamed over the original belongs to the user who wrote it, with
 * that user's umask. When WP-CLI runs as root (--allow-root), a rewritten wp-config.php became root:root 0640
 * and PHP-FPM (www-data) could no longer read it: "Failed opening required wp-config.php", the site down.
 *
 * Use:
 *   $meta = PNCP_File_Owner::capture( $path );   // before the write (null when the file does not exist yet)
 *   ... write a temp file, rename() it over $path ...
 *   PNCP_File_Owner::restore( $path, $meta );     // after the rename
 *
 * restore() puts back the original mode (always) and the original owner and group (only possible as root).
 * For a new file or folder (no $meta), when running as root, it is given to the owner and group of the
 * WordPress folder (ABSPATH), so the web server's user can read and later rewrite it; the mode is left as is.
 *
 * It uses no WordPress function, so it can be called from any point of the plugin. The pre-cache check
 * (class-pncp-precheck-runtime.php) loads no other file of the plugin and has its own copy of this logic.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Owner, group and permissions of the files the plugin writes.
 */
final class PNCP_File_Owner {

	/**
	 * Whether this process runs as root.
	 *
	 * @return bool
	 */
	public static function is_root() {
		return function_exists( 'posix_geteuid' ) && 0 === posix_geteuid();
	}

	/**
	 * The owner, group and permission bits of an existing file or folder.
	 *
	 * @param string $path File or folder.
	 * @return array{uid:int,gid:int,mode:int}|null Null when it does not exist or cannot be read.
	 */
	public static function capture( $path ) {
		clearstatcache( true, $path );
		$stat = @stat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a missing file is an answer.
		if ( false === $stat ) {
			return null;
		}
		return array(
			'uid'  => (int) $stat['uid'],
			'gid'  => (int) $stat['gid'],
			'mode' => (int) $stat['mode'] & 07777,
		);
	}

	/**
	 * The owner and group a new file should get when root writes it: those of the WordPress folder.
	 *
	 * @return array{uid:int,gid:int}|null Null when not root or the folder cannot be read.
	 */
	public static function base() {
		if ( ! self::is_root() || ! defined( 'ABSPATH' ) ) {
			return null;
		}
		$meta = self::capture( rtrim( (string) ABSPATH, '/' ) );
		if ( null === $meta || 0 === $meta['uid'] ) {
			return null; // A WordPress folder owned by root: nothing to hand the file to.
		}
		return array(
			'uid' => $meta['uid'],
			'gid' => $meta['gid'],
		);
	}

	/**
	 * Puts back what capture() recorded, after a file was written or renamed over. Without $meta (a new file
	 * or folder), when root, hands it to the owner of the WordPress folder. Never fails loudly.
	 *
	 * @param string                                  $path File or folder that was written.
	 * @param array{uid:int,gid:int,mode:int}|null    $meta What capture() returned before the write.
	 * @return bool Whether the file now has the wanted owner and mode (true when there was nothing to do).
	 */
	public static function restore( $path, $meta = null ) {
		clearstatcache( true, $path );
		if ( ! file_exists( $path ) ) {
			return false;
		}
		$ok = true;
		if ( is_array( $meta ) ) {
			if ( ( (int) @fileperms( $path ) & 07777 ) !== $meta['mode'] ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$ok = @chmod( $path, $meta['mode'] ) && $ok; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod
			}
			$owner = array(
				'uid' => $meta['uid'],
				'gid' => $meta['gid'],
			);
		} else {
			$owner = self::base();
		}
		if ( null !== $owner && self::is_root() ) {
			if ( (int) @fileowner( $path ) !== $owner['uid'] ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$ok = @chown( $path, $owner['uid'] ) && $ok; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chown
			}
			if ( (int) @filegroup( $path ) !== $owner['gid'] ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$ok = @chgrp( $path, $owner['gid'] ) && $ok; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chgrp
			}
		}
		clearstatcache( true, $path );
		return $ok;
	}

	/**
	 * Writes a file whole (temp file in the same folder, then rename) and keeps its owner, group and mode.
	 * A new file gets $mode when given, and as root the owner of the WordPress folder.
	 *
	 * @param string   $path     File.
	 * @param string   $contents Contents.
	 * @param int|null $mode     Mode for a new file (an existing file keeps its own).
	 * @return bool
	 */
	public static function put( $path, $contents, $mode = null ) {
		$meta = self::capture( $path );
		$tmp  = dirname( $path ) . '/.' . basename( $path ) . '.' . substr( md5( uniqid( (string) mt_rand(), true ) ), 0, 10 ) . '.tmp'; // phpcs:ignore WordPress.WP.AlternativeRand.rand_mt_rand
		if ( strlen( $contents ) !== @file_put_contents( $tmp, $contents ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink
			return false;
		}
		// The temp file gets the final owner and mode before the rename, so no reader ever sees it wrong.
		if ( null === $meta && null !== $mode ) {
			@chmod( $tmp, $mode ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod
		}
		self::restore( $tmp, $meta );
		if ( ! @rename( $tmp, $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink
			return false;
		}
		return true;
	}

	/**
	 * Creates a folder (and its parents) and, as root, hands each new folder to the WordPress folder's owner.
	 *
	 * @param string $dir  Folder.
	 * @param int    $mode Mode.
	 * @return bool Whether the folder exists.
	 */
	public static function mkdir( $dir, $mode = 0755 ) {
		$dir = rtrim( $dir, '/' );
		if ( is_dir( $dir ) ) {
			return true;
		}
		$parent = dirname( $dir );
		if ( $parent !== $dir && ! is_dir( $parent ) && ! self::mkdir( $parent, $mode ) ) {
			return false;
		}
		if ( ! @mkdir( $dir, $mode ) && ! is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
			return false;
		}
		self::restore( $dir, null );
		return true;
	}
}
