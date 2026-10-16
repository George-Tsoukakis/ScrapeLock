<?php
/**
 * Image watermarking.
 *
 * - Applied to the sizes WordPress generates (thumbnail, medium, large…) and, optionally, to the
 *   full-size image. Before that, the clean full-size file is saved in a hidden folder, so it can
 *   always be restored.
 * - Never a double watermark: each image records (meta `_pncp_wm`) which files are already watermarked. When
 *   sizes are regenerated, they are always generated from a clean source.
 * - Excluded: the watermark itself, the site icon, the logo, the WooCommerce placeholder image
 *   and (by default) product images, which Google Merchant, Skroutz etc. reject.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * GD watermark: a PNG image from the media library or, if none is set, the site's domain.
 */
final class PNCP_Watermark {

	/**
	 * Meta holding the image state: ['full' => [relative path => md5 of the watermarked file], 'sizes' => [file => 1|0]].
	 */
	const META = '_pncp_wm';

	/**
	 * Cron hook that removes the watermark from one image (e.g. when it becomes a logo or a product image).
	 */
	const CRON_UNMARK = 'pncp_wm_unmark';

	/**
	 * Supported image types.
	 *
	 * @var string[]
	 */
	private static $mimes = array( 'image/jpeg', 'image/png', 'image/webp' );

	/**
	 * How many sizes failed to regenerate during the last run.
	 *
	 * @var int
	 */
	private static $errors = 0;

	/**
	 * Per-request watermark cache.
	 *
	 * @var resource|\GdImage|false|null
	 */
	private static $mark = null;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'wp_generate_attachment_metadata', array( __CLASS__, 'on_generate' ), 20, 3 );
		add_action( 'delete_attachment', array( __CLASS__, 'on_delete' ) );
		add_action( self::CRON_UNMARK, array( __CLASS__, 'unmark' ) );
		add_action( 'added_post_meta', array( __CLASS__, 'on_post_meta' ), 10, 4 );
		add_action( 'updated_post_meta', array( __CLASS__, 'on_post_meta' ), 10, 4 );
		add_action( 'updated_option', array( __CLASS__, 'on_option' ), 10, 3 );
		add_action( 'added_option', array( __CLASS__, 'on_added_option' ), 10, 2 );
		add_filter( 'load_image_to_edit_path', array( __CLASS__, 'edit_from_clean' ), 10, 2 );
	}

	/**
	 * Is the GD library available?
	 *
	 * @return bool
	 */
	public static function available() {
		return function_exists( 'imagecreatetruecolor' ) && function_exists( 'imagecopyresampled' ) && function_exists( 'imagerotate' );
	}

	/* ---------- Which images ---------- */

	/**
	 * Site images that never get a watermark: icon, logos, placeholder, watermark.
	 *
	 * @return int[]
	 */
	public static function protected_ids() {
		$ids = array(
			(int) PNCP_Options::stored()['watermark_image_id'],
			(int) get_option( 'site_icon' ),
			(int) get_option( 'site_logo' ),
			(int) get_theme_mod( 'custom_logo' ),
			(int) get_option( 'woocommerce_placeholder_image' ),
		);
		return array_values( array_filter( $ids ) );
	}

	/**
	 * Is this a WooCommerce product image? (attached to a product, featured image or gallery image)
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return bool
	 */
	public static function is_product_image( $attachment_id ) {
		global $wpdb;
		$attachment_id = (int) $attachment_id;
		$parent        = (int) wp_get_post_parent_id( $attachment_id );
		if ( $parent && in_array( get_post_type( $parent ), array( 'product', 'product_variation' ), true ) ) {
			return true;
		}
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- One query per image, only while it is being processed.
		$thumb = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT pm.post_id FROM {$wpdb->postmeta} pm INNER JOIN {$wpdb->posts} p ON p.ID = pm.post_id
				WHERE pm.meta_key = '_thumbnail_id' AND pm.meta_value = %s AND p.post_type IN ('product','product_variation') LIMIT 1",
				(string) $attachment_id
			)
		);
		if ( $thumb ) {
			return true;
		}
		$galleries = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT meta_value FROM {$wpdb->postmeta} WHERE meta_key = '_product_image_gallery' AND meta_value LIKE %s",
				'%' . $wpdb->esc_like( (string) $attachment_id ) . '%'
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery
		foreach ( (array) $galleries as $gallery ) {
			if ( in_array( $attachment_id, array_map( 'intval', explode( ',', (string) $gallery ) ), true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Does this image get a watermark with the current settings?
	 *
	 * @param int                  $attachment_id Attachment ID.
	 * @param array<string, mixed> $s             Settings.
	 * @return bool
	 */
	public static function eligible( $attachment_id, $s ) {
		$attachment_id = (int) $attachment_id;
		if ( empty( $s['enabled'] ) || empty( $s['watermark_enabled'] ) || ! self::available() ) {
			return false;
		}
		if ( ! in_array( get_post_mime_type( $attachment_id ), self::$mimes, true ) ) {
			return false;
		}
		if ( in_array( $attachment_id, self::protected_ids(), true ) ) {
			return false;
		}
		$context = (string) get_post_meta( $attachment_id, '_wp_attachment_context', true );
		if ( in_array( $context, array( 'site-icon', 'custom-logo', 'site-logo' ), true ) ) {
			return false;
		}
		if ( empty( $s['watermark_products'] ) && self::is_product_image( $attachment_id ) ) {
			return false;
		}

		/**
		 * Filter to exclude images.
		 *
		 * @param bool $apply         Whether to apply the watermark.
		 * @param int  $attachment_id Attachment ID.
		 */
		return (bool) apply_filters( 'pncp_watermark_attachment', true, $attachment_id );
	}

	/* ---------- New uploads and size regeneration ---------- */

	/**
	 * Runs every time WordPress generates sizes (new upload, «Regenerate Thumbnails», missing sizes).
	 *
	 * @param array<string, mixed> $metadata      The metadata.
	 * @param int                  $attachment_id Attachment ID.
	 * @param string               $context       create | update.
	 * @return array<string, mixed>
	 */
	public static function on_generate( $metadata, $attachment_id, $context = 'create' ) {
		if ( ! is_array( $metadata ) || empty( $metadata['file'] ) ) {
			return $metadata;
		}
		$s     = PNCP_Options::get();
		$state = self::state( $attachment_id );

		// If the full size is watermarked, the sizes just generated come from it:
		// restore the clean image and regenerate sizes from a clean source, otherwise they would get a double watermark.
		$regen = false;
		if ( $state['full'] ) {
			self::restore_full( $attachment_id, $state );
			$state['full'] = array();
			$regen         = true;
		}
		if ( 'create' === $context ) {
			$state['sizes'] = array();
		}

		$apply = self::eligible( $attachment_id, $s );
		if ( ! $apply && ! $regen ) {
			self::save_state( $attachment_id, $state );
			return $metadata;
		}

		$metadata = self::process_sizes( $attachment_id, $metadata, $state, $s, $apply, $regen );
		if ( $apply && ! empty( $s['watermark_full'] ) ) {
			self::mark_full( $attachment_id, $state, $s );
		} elseif ( ! $apply ) {
			self::drop_backups( $attachment_id );
		}
		self::save_state( $attachment_id, $state );
		return $metadata;
	}

	/**
	 * Rebuilds an image from a clean source, with or without a watermark (bulk apply tool).
	 * Safe to run again as many times as needed: it always starts from the clean original. This way
	 * it also removes the 1.x watermarks, which left no marker.
	 *
	 * @param int  $attachment_id Attachment ID.
	 * @param bool $apply         true = watermarked (if allowed), false = clean.
	 * @return string done | skipped | error
	 */
	public static function rebuild( $attachment_id, $apply ) {
		$attachment_id = (int) $attachment_id;
		if ( ! in_array( get_post_mime_type( $attachment_id ), self::$mimes, true ) ) {
			return 'skipped';
		}
		$metadata = wp_get_attachment_metadata( $attachment_id );
		if ( ! is_array( $metadata ) || empty( $metadata['file'] ) ) {
			return 'skipped';
		}
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'image' );
		}

		$s     = PNCP_Options::get();
		$state = self::state( $attachment_id );
		self::restore_full( $attachment_id, $state );
		$state = array(
			'full'  => array(),
			'sizes' => array(),
		);

		$apply        = $apply && self::eligible( $attachment_id, $s );
		self::$errors = 0;
		$metadata     = self::process_sizes( $attachment_id, $metadata, $state, $s, $apply, true );
		if ( $apply && ! empty( $s['watermark_full'] ) ) {
			self::mark_full( $attachment_id, $state, $s );
		}
		if ( ! $apply ) {
			self::drop_backups( $attachment_id );
		}
		self::save_state( $attachment_id, $state );
		wp_update_attachment_metadata( $attachment_id, $metadata );
		return self::$errors ? 'error' : 'done';
	}

	/**
	 * Removes the watermark from one image (cron, when the image becomes a logo / product image).
	 *
	 * @param int $attachment_id Attachment ID.
	 */
	public static function unmark( $attachment_id ) {
		$state = self::state( $attachment_id );
		if ( $state['full'] || in_array( 1, $state['sizes'], true ) ) {
			self::rebuild( $attachment_id, false );
		}
	}

	/**
	 * Sizes: (optionally) regenerate from a clean source, then watermark those that are not watermarked yet.
	 *
	 * @param int                  $attachment_id ID.
	 * @param array<string, mixed> $metadata      Metadata.
	 * @param array<string, mixed> $state         State (modified).
	 * @param array<string, mixed> $s             Settings.
	 * @param bool                 $apply         Whether to apply the watermark.
	 * @param bool                 $regen         Regenerate from a clean source the ones not yet recorded.
	 * @return array<string, mixed> Metadata (with updated filesize).
	 */
	private static function process_sizes( $attachment_id, $metadata, &$state, $s, $apply, $regen ) {
		if ( empty( $metadata['sizes'] ) || ! is_array( $metadata['sizes'] ) ) {
			return $metadata;
		}
		$dir = trailingslashit( dirname( (string) get_attached_file( $attachment_id, true ) ) );
		// The full-size files have already been restored (restore_full), so they are clean.
		$source = $regen ? self::clean_source( $attachment_id ) : '';
		$crops  = wp_get_registered_image_subsizes();

		foreach ( $metadata['sizes'] as $name => $size ) {
			if ( empty( $size['file'] ) ) {
				continue;
			}
			$file = wp_basename( $size['file'] );
			// Two sizes with the same dimensions share one file: process it once.
			if ( array_key_exists( $file, $state['sizes'] ) ) {
				continue;
			}
			$path = $dir . $file;
			$mime = isset( $size['mime-type'] ) ? (string) $size['mime-type'] : (string) wp_check_filetype( $file )['type'];

			if ( $regen ) {
				$crop = isset( $crops[ $name ]['crop'] ) ? $crops[ $name ]['crop'] : true;
				if ( '' === $source || ! self::resize_from( $source, $path, (int) $size['width'], (int) $size['height'], $crop, $mime ) ) {
					// Not regenerated from a clean source: it may already be watermarked, so we do not add a second one.
					++self::$errors;
					continue;
				}
			}

			$marked = false;
			if ( $apply && (int) $size['width'] >= (int) $s['watermark_min_width'] ) {
				$marked = self::apply_to_file( $path, $mime, $s );
			}
			$state['sizes'][ $file ] = $marked ? 1 : 0;

			if ( is_file( $path ) ) {
				clearstatcache( true, $path );
				$metadata['sizes'][ $name ]['filesize'] = (int) filesize( $path );
			}
		}
		return $metadata;
	}

	/**
	 * Watermark the full size (and the original upload, if WordPress downscaled it to «-scaled»).
	 * The clean file is saved before every change.
	 *
	 * @param int                  $attachment_id ID.
	 * @param array<string, mixed> $state         State (modified).
	 * @param array<string, mixed> $s             Settings.
	 */
	private static function mark_full( $attachment_id, &$state, $s ) {
		$mime = (string) get_post_mime_type( $attachment_id );
		foreach ( self::full_files( $attachment_id ) as $path ) {
			$rel = self::relative( $path );
			if ( isset( $state['full'][ $rel ] ) || ! self::ensure_backup( $path ) ) {
				continue;
			}
			$type = wp_check_filetype( $path )['type'];
			if ( self::apply_to_file( $path, $type ? $type : $mime, $s ) ) {
				clearstatcache( true, $path );
				// Hash of the file we wrote: if it changes (e.g. image replacement), the backup is no longer valid.
				$state['full'][ $rel ] = (string) md5_file( $path );
			}
		}
	}

	/**
	 * The full-size files: the attached file (e.g. -scaled) and the original upload.
	 *
	 * @param int $attachment_id ID.
	 * @return string[]
	 */
	private static function full_files( $attachment_id ) {
		$files    = array();
		$attached = (string) get_attached_file( $attachment_id, true );
		if ( '' !== $attached && is_file( $attached ) ) {
			$files[] = $attached;
		}
		$original = function_exists( 'wp_get_original_image_path' ) ? (string) wp_get_original_image_path( $attachment_id, true ) : '';
		if ( '' !== $original && $original !== $attached && is_file( $original ) ) {
			$files[] = $original;
		}
		return $files;
	}

	/**
	 * Restores the clean full-size files from the backup.
	 *
	 * Only when the file on disk is still the one we wrote (same hash). If it changed (e.g.
	 * «Enable Media Replace» uploaded a new image under the same name), the file on disk is the new clean
	 * original and the old backup is deleted. Backups without a record (orphans) are deleted too.
	 *
	 * @param int                  $attachment_id ID.
	 * @param array<string, mixed> $state         State.
	 */
	private static function restore_full( $attachment_id, $state ) {
		$paths    = array();
		$original = function_exists( 'wp_get_original_image_path' ) ? (string) wp_get_original_image_path( $attachment_id, true ) : '';
		$attached = (string) get_attached_file( $attachment_id, true );
		// Original upload first: WordPress regenerates the «-scaled» from it.
		foreach ( array( $original, $attached ) as $path ) {
			if ( '' !== $path ) {
				$paths[ self::relative( $path ) ] = $path;
			}
		}
		foreach ( array_keys( (array) $state['full'] ) as $rel ) {
			$paths[ (string) $rel ] = self::absolute( (string) $rel );
		}
		$derived_ok = false; // The original upload is still ours: the -scaled was simply regenerated from it.
		$orig_rel   = '' !== $original && $original !== $attached ? self::relative( $original ) : '';
		foreach ( $paths as $rel => $path ) {
			$backup = self::backup_path( $path );
			if ( '' === $backup || ! is_file( $backup ) ) {
				continue;
			}
			$hash = isset( $state['full'][ $rel ] ) ? (string) $state['full'][ $rel ] : '';
			$ours = '' !== $hash && is_file( $path ) && md5_file( $path ) === $hash;
			if ( $rel === $orig_rel ) {
				$derived_ok = $ours;
			} elseif ( '' !== $hash && $derived_ok && is_file( $path ) ) {
				$ours = true;
			}
			if ( ! is_file( $path ) ) {
				// The file is missing (e.g. offload plugin): the backup is never deleted in this case.
				if ( '' !== $hash ) {
					copy( $backup, $path );
				}
			} elseif ( $ours ) {
				copy( $backup, $path );
			} else {
				wp_delete_file( $backup ); // A new file replaced the old one: the backup is no longer valid.
			}
		}
	}

	/**
	 * The source for new sizes: the original upload or the full size. Always called after restore_full,
	 * so the files on disk are clean.
	 *
	 * @param int $attachment_id ID.
	 * @return string
	 */
	private static function clean_source( $attachment_id ) {
		$original = function_exists( 'wp_get_original_image_path' ) ? (string) wp_get_original_image_path( $attachment_id, true ) : '';
		$attached = (string) get_attached_file( $attachment_id, true );
		foreach ( array( $original, $attached ) as $path ) {
			if ( '' !== $path && is_file( $path ) ) {
				return $path;
			}
		}
		return '';
	}

	/**
	 * The WordPress image editor (crop, rotate) starts from the clean backup,
	 * so the new image does not carry the watermark.
	 *
	 * @param string $path          File to edit.
	 * @param int    $attachment_id ID.
	 * @return string
	 */
	public static function edit_from_clean( $path, $attachment_id ) {
		$state = self::state( $attachment_id );
		$rel   = self::relative( (string) $path );
		if ( '' === $rel || empty( $state['full'][ $rel ] ) || ! is_file( (string) $path ) || md5_file( (string) $path ) !== $state['full'][ $rel ] ) {
			return $path;
		}
		$backup = self::backup_path( (string) $path );
		return '' !== $backup && is_file( $backup ) ? $backup : $path;
	}

	/**
	 * Generates a size from the source, under the same file name WordPress already uses.
	 *
	 * @param string     $source Source.
	 * @param string     $target Target file.
	 * @param int        $width  Width.
	 * @param int        $height Height.
	 * @param bool|array $crop   Crop.
	 * @param string     $mime   Target file type.
	 * @return bool
	 */
	private static function resize_from( $source, $target, $width, $height, $crop, $mime ) {
		$editor = wp_get_image_editor( $source );
		if ( is_wp_error( $editor ) ) {
			return false;
		}
		if ( method_exists( $editor, 'maybe_exif_rotate' ) ) {
			$editor->maybe_exif_rotate();
		}
		$current = $editor->get_size();
		// Same dimensions as the source: WordPress does not resize, it is saved as is.
		if ( (int) $current['width'] !== $width || (int) $current['height'] !== $height ) {
			$resized = $editor->resize( $width, $height, $crop );
			if ( is_wp_error( $resized ) ) {
				return false;
			}
		}
		$saved = $editor->save( $target, $mime ? $mime : null );
		if ( is_wp_error( $saved ) || empty( $saved['path'] ) ) {
			return false;
		}
		// If a format filter (image_editor_output_format) changed the extension, the file keeps the name WordPress knows.
		if ( $saved['path'] !== $target && is_file( $saved['path'] ) ) {
			copy( $saved['path'], $target );
			wp_delete_file( $saved['path'] );
		}
		return true;
	}

	/* ---------- Backups of the clean files ---------- */

	/**
	 * The hidden backup folder, inside uploads, with a random name (not guessable).
	 * Contains .htaccess (Apache) and index.php; for Nginx see the server rules.
	 *
	 * @return string Path with a trailing / ('' if it could not be created).
	 */
	public static function backup_dir() {
		$uploads = wp_get_upload_dir();
		if ( ! empty( $uploads['error'] ) ) {
			return '';
		}
		$name = (string) get_option( 'pncp_backup_dir' );
		if ( ! preg_match( '/^pncp-originals-[a-z0-9]{12}$/', $name ) ) {
			$name = 'pncp-originals-' . strtolower( wp_generate_password( 12, false, false ) );
			update_option( 'pncp_backup_dir', $name, false );
		}
		$dir = trailingslashit( $uploads['basedir'] ) . $name . '/';
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}
		if ( ! is_file( $dir . '.htaccess' ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Small configuration file.
			file_put_contents( $dir . '.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			file_put_contents( $dir . 'index.php', "<?php\n// Silence is golden.\n" );
		}
		return $dir;
	}

	/**
	 * The path relative to uploads.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private static function relative( $path ) {
		$base = trailingslashit( wp_get_upload_dir()['basedir'] );
		return 0 === strpos( $path, $base ) ? substr( $path, strlen( $base ) ) : '';
	}

	/**
	 * Absolute path from a path relative to uploads.
	 *
	 * @param string $rel Relative path.
	 * @return string
	 */
	private static function absolute( $rel ) {
		return trailingslashit( wp_get_upload_dir()['basedir'] ) . ltrim( $rel, '/' );
	}

	/**
	 * Where the clean backup of a file is stored.
	 *
	 * @param string $path File inside uploads.
	 * @return string
	 */
	public static function backup_path( $path ) {
		$rel = self::relative( (string) $path );
		if ( '' === $rel || false !== strpos( $rel, '..' ) ) {
			return '';
		}
		$dir = self::backup_dir();
		return '' === $dir ? '' : $dir . $rel;
	}

	/**
	 * Saves the clean file. Called after restore_full, so the file on disk is clean
	 * and the backup is always refreshed from it.
	 *
	 * @param string $path File.
	 * @return bool
	 */
	private static function ensure_backup( $path ) {
		$backup = self::backup_path( $path );
		if ( '' === $backup || ! wp_mkdir_p( dirname( $backup ) ) ) {
			return false;
		}
		return copy( $path, $backup );
	}

	/**
	 * Deletes the backups of an image.
	 *
	 * @param int $attachment_id ID.
	 */
	private static function drop_backups( $attachment_id ) {
		$paths = self::full_files( $attachment_id );
		foreach ( array_keys( self::state( $attachment_id )['full'] ) as $rel ) {
			$paths[] = self::absolute( (string) $rel );
		}
		foreach ( array_unique( $paths ) as $path ) {
			$backup = self::backup_path( $path );
			if ( '' !== $backup && is_file( $backup ) ) {
				wp_delete_file( $backup );
			}
		}
	}

	/**
	 * Image deletion: the backups are removed too.
	 *
	 * @param int $attachment_id ID.
	 */
	public static function on_delete( $attachment_id ) {
		if ( get_post_meta( $attachment_id, self::META, true ) ) {
			self::drop_backups( (int) $attachment_id );
		}
	}

	/* ---------- State ---------- */

	/**
	 * The state of an image.
	 *
	 * @param int $attachment_id ID.
	 * @return array{full: array<string, string>, sizes: array<string, int>}
	 */
	public static function state( $attachment_id ) {
		$state = get_post_meta( (int) $attachment_id, self::META, true );
		$state = is_array( $state ) ? $state : array();
		return array(
			'full'  => isset( $state['full'] ) && is_array( $state['full'] ) ? array_map( 'strval', $state['full'] ) : array(),
			'sizes' => isset( $state['sizes'] ) && is_array( $state['sizes'] ) ? array_map( 'intval', $state['sizes'] ) : array(),
		);
	}

	/**
	 * Saves the state (deletes the meta if the image is completely clean).
	 *
	 * @param int                  $attachment_id ID.
	 * @param array<string, mixed> $state         State.
	 */
	private static function save_state( $attachment_id, $state ) {
		if ( ! $state['full'] && ! in_array( 1, $state['sizes'], true ) ) {
			delete_post_meta( (int) $attachment_id, self::META );
			return;
		}
		update_post_meta( (int) $attachment_id, self::META, $state );
	}

	/* ---------- Automatic removal on logos and product images ---------- */

	/**
	 * When an image becomes a product image, it loses the watermark (unless allowed on products).
	 *
	 * @param int    $meta_id    ID meta.
	 * @param int    $object_id  Post ID.
	 * @param string $meta_key   Key.
	 * @param mixed  $meta_value Value.
	 */
	public static function on_post_meta( $meta_id, $object_id, $meta_key, $meta_value ) {
		if ( ! in_array( $meta_key, array( '_thumbnail_id', '_product_image_gallery' ), true ) ) {
			return;
		}
		if ( ! empty( PNCP_Options::get()['watermark_products'] ) || ! in_array( get_post_type( $object_id ), array( 'product', 'product_variation' ), true ) ) {
			return;
		}
		self::schedule_unmark( array_map( 'intval', explode( ',', (string) $meta_value ) ) );
	}

	/**
	 * When an image becomes the site icon / logo / placeholder, it loses the watermark.
	 *
	 * @param string $option Option.
	 * @param mixed  $old    Old value.
	 * @param mixed  $value  New value.
	 */
	public static function on_option( $option, $old, $value ) {
		if ( in_array( $option, array( 'site_icon', 'site_logo', 'woocommerce_placeholder_image' ), true ) ) {
			self::schedule_unmark( array( (int) $value ) );
		} elseif ( PNCP_OPTION === $option && is_array( $value ) && ! empty( $value['watermark_image_id'] ) ) {
			// The image set as the watermark must not itself be watermarked.
			self::schedule_unmark( array( (int) $value['watermark_image_id'] ) );
		} elseif ( 0 === strpos( $option, 'theme_mods_' ) && is_array( $value ) && ! empty( $value['custom_logo'] ) ) {
			self::schedule_unmark( array( (int) $value['custom_logo'] ) );
		}
	}

	/**
	 * The same for options being created now.
	 *
	 * @param string $option Option.
	 * @param mixed  $value  Value.
	 */
	public static function on_added_option( $option, $value ) {
		self::on_option( $option, null, $value );
	}

	/**
	 * Schedules removal for the images that are watermarked.
	 *
	 * @param int[] $ids IDs.
	 */
	private static function schedule_unmark( $ids ) {
		foreach ( array_unique( array_filter( $ids ) ) as $id ) {
			if ( get_post_meta( $id, self::META, true ) && ! wp_next_scheduled( self::CRON_UNMARK, array( $id ) ) ) {
				wp_schedule_single_event( time() + 10, self::CRON_UNMARK, array( $id ) );
			}
		}
	}

	/* ---------- Drawing ---------- */

	/**
	 * Watermark a single file.
	 *
	 * @param string               $path Path.
	 * @param string               $mime Type.
	 * @param array<string, mixed> $s    Settings.
	 * @return bool
	 */
	public static function apply_to_file( $path, $mime, $s ) {
		if ( ! self::available() || ! is_file( $path ) || ! wp_is_writable( $path ) ) {
			return false;
		}
		$image = self::load( $path, $mime );
		if ( ! $image ) {
			return false;
		}
		$mark = self::mark( (int) $s['watermark_image_id'] );
		if ( ! $mark ) {
			return false;
		}

		$width  = imagesx( $image );
		$height = imagesy( $image );
		$mark_w = imagesx( $mark );
		$mark_h = imagesy( $mark );
		$target = max( 1, (int) round( $width * max( 5, min( 60, (int) $s['watermark_size'] ) ) / 100 ) );
		$scale  = min( 1, $target / $mark_w );
		$dst_w  = max( 1, (int) round( $mark_w * $scale ) );
		$dst_h  = max( 1, (int) round( $mark_h * $scale ) );

		$layer = self::transparent( $dst_w, $dst_h );
		imagecopyresampled( $layer, $mark, 0, 0, 0, 0, $dst_w, $dst_h, $mark_w, $mark_h );
		self::fade( $layer, (int) $s['watermark_opacity'] );
		imagealphablending( $image, true );

		$position = (string) $s['watermark_position'];
		if ( 'tiled' === $position ) {
			self::tile( $image, $layer );
		} else {
			$margin = (int) round( min( $width, $height ) * 0.02 );
			switch ( $position ) {
				case 'tl':
					$x = $margin;
					$y = $margin;
					break;
				case 'tr':
					$x = $width - $dst_w - $margin;
					$y = $margin;
					break;
				case 'bl':
					$x = $margin;
					$y = $height - $dst_h - $margin;
					break;
				case 'center':
					$x = (int) round( ( $width - $dst_w ) / 2 );
					$y = (int) round( ( $height - $dst_h ) / 2 );
					break;
				default:
					$x = $width - $dst_w - $margin;
					$y = $height - $dst_h - $margin;
			}
			imagecopy( $image, $layer, $x, $y, 0, 0, $dst_w, $dst_h );
		}

		return self::save( $image, $path, $mime );
	}

	/**
	 * Repeated watermark in a diagonal pattern across the whole image.
	 *
	 * @param resource|\GdImage $image Image.
	 * @param resource|\GdImage $layer Watermark (already with transparency).
	 */
	private static function tile( $image, $layer ) {
		$rotated = imagerotate( $layer, 30, imagecolorallocatealpha( $layer, 0, 0, 0, 127 ) );
		if ( ! $rotated ) {
			return;
		}
		imagesavealpha( $rotated, true );
		$w      = imagesx( $image );
		$h      = imagesy( $image );
		$tile_w = imagesx( $rotated );
		$tile_h = imagesy( $rotated );
		$step_x = max( 1, (int) round( $tile_w * 1.6 ) );
		$step_y = max( 1, (int) round( $tile_h * 1.4 ) );
		$row    = 0;
		for ( $y = -$tile_h / 2; $y < $h; $y += $step_y ) {
			$offset = ( $row % 2 ) ? (int) round( $step_x / 2 ) : 0;
			for ( $x = -$tile_w / 2 + $offset; $x < $w; $x += $step_x ) {
				imagecopy( $image, $rotated, (int) $x, (int) $y, 0, 0, $tile_w, $tile_h );
			}
			++$row;
		}
	}

	/**
	 * New transparent image.
	 *
	 * @param int $w Width.
	 * @param int $h Height.
	 * @return resource|\GdImage
	 */
	private static function transparent( $w, $h ) {
		$img = imagecreatetruecolor( $w, $h );
		imagealphablending( $img, false );
		imagesavealpha( $img, true );
		imagefill( $img, 0, 0, imagecolorallocatealpha( $img, 0, 0, 0, 127 ) );
		return $img;
	}

	/**
	 * Opens a JPEG, PNG or WebP image.
	 *
	 * @param string $path Path.
	 * @param string $mime Type.
	 * @return resource|\GdImage|false
	 */
	private static function load( $path, $mime ) {
		switch ( $mime ) {
			case 'image/jpeg':
				return function_exists( 'imagecreatefromjpeg' ) ? @imagecreatefromjpeg( $path ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			case 'image/png':
				$img = function_exists( 'imagecreatefrompng' ) ? @imagecreatefrompng( $path ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( $img ) {
					// Palette PNG: convert to truecolor, otherwise the transparent watermark breaks.
					if ( ! imageistruecolor( $img ) ) {
						imagepalettetotruecolor( $img );
					}
					imagesavealpha( $img, true );
				}
				return $img;
			case 'image/webp':
				$img = function_exists( 'imagecreatefromwebp' ) ? @imagecreatefromwebp( $path ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( $img ) {
					imagesavealpha( $img, true );
				}
				return $img;
		}
		return false;
	}

	/**
	 * Saves in the same format.
	 *
	 * @param resource|\GdImage $image Image.
	 * @param string            $path  Path.
	 * @param string            $mime  Type.
	 * @return bool
	 */
	private static function save( $image, $path, $mime ) {
		switch ( $mime ) {
			case 'image/jpeg':
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core filter.
				return imagejpeg( $image, $path, (int) apply_filters( 'jpeg_quality', 82, 'pncp_watermark' ) );
			case 'image/png':
				return imagepng( $image, $path, 6 );
			case 'image/webp':
				return function_exists( 'imagewebp' ) && imagewebp( $image, $path, 82 );
		}
		return false;
	}

	/**
	 * The watermark image: the library PNG or the site's domain as text.
	 *
	 * @param int $image_id PNG image ID (0 = text).
	 * @return resource|\GdImage|false
	 */
	private static function mark( $image_id ) {
		if ( null !== self::$mark ) {
			return self::$mark;
		}
		self::$mark = false;
		if ( $image_id > 0 ) {
			$file = (string) get_attached_file( $image_id );
			// If the image was ever watermarked, its clean backup is used.
			$backup = '' === $file ? '' : self::backup_path( $file );
			if ( '' !== $backup && is_file( $backup ) ) {
				$file = $backup;
			}
			if ( $file && is_file( $file ) && 'image/png' === get_post_mime_type( $image_id ) ) {
				$png = @imagecreatefrompng( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( $png ) {
					if ( ! imageistruecolor( $png ) ) {
						imagepalettetotruecolor( $png );
					}
					imagesavealpha( $png, true );
					self::$mark = $png;
					return self::$mark;
				}
			}
		}
		self::$mark = self::text_mark( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		return self::$mark;
	}

	/**
	 * Forgets the per-request watermark (after a settings change or in tests).
	 */
	public static function reset() {
		self::$mark = null;
	}

	/**
	 * White text with a shadow. GD's built-in font has Latin characters only,
	 * which is why the domain is used. For a logo or Greek text, set a PNG image.
	 *
	 * @param string $text Text.
	 * @return resource|\GdImage|false
	 */
	private static function text_mark( $text ) {
		$text = preg_replace( '/[^\x20-\x7E]/', '', $text );
		if ( '' === $text ) {
			return false;
		}
		$font  = 5;
		$w     = imagefontwidth( $font ) * strlen( $text ) + 2;
		$h     = imagefontheight( $font ) + 2;
		$small = self::transparent( $w, $h );
		imagestring( $small, $font, 1, 1, $text, imagecolorallocatealpha( $small, 0, 0, 0, 40 ) );
		imagestring( $small, $font, 0, 0, $text, imagecolorallocatealpha( $small, 255, 255, 255, 0 ) );

		// Scale up x4, so that scaling does not blur too much.
		$big = self::transparent( $w * 4, $h * 4 );
		imagecopyresized( $big, $small, 0, 0, 0, 0, $w * 4, $h * 4, $w, $h );
		return $big;
	}

	/**
	 * Reduces each pixel's opacity to the configured percentage.
	 *
	 * @param resource|\GdImage $layer   Layer.
	 * @param int               $opacity 10–100.
	 */
	private static function fade( $layer, $opacity ) {
		if ( $opacity >= 100 ) {
			return;
		}
		$factor = $opacity / 100;
		$w      = imagesx( $layer );
		$h      = imagesy( $layer );
		for ( $x = 0; $x < $w; $x++ ) {
			for ( $y = 0; $y < $h; $y++ ) {
				$rgba  = imagecolorat( $layer, $x, $y );
				$alpha = ( $rgba >> 24 ) & 0x7F;
				if ( 127 === $alpha ) {
					continue;
				}
				$new = (int) round( 127 - ( 127 - $alpha ) * $factor );
				imagesetpixel( $layer, $x, $y, imagecolorallocatealpha( $layer, ( $rgba >> 16 ) & 0xFF, ( $rgba >> 8 ) & 0xFF, $rgba & 0xFF, $new ) );
			}
		}
	}
}
