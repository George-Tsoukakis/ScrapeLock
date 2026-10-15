<?php
/**
 * Υδατογράφημα στα μεγέθη εικόνων που φτιάχνει το WordPress για νέα uploads.
 *
 * Το πρωτότυπο αρχείο (και το "-scaled" του WordPress) δεν αγγίζεται ποτέ. Αν απενεργοποιήσετε
 * τη λειτουργία και ξαναφτιάξετε τα thumbnails, οι εικόνες βγαίνουν καθαρές.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Υδατογράφημα με GD: εικόνα PNG από τη βιβλιοθήκη πολυμέσων ή, αν δεν οριστεί, το domain του site.
 */
final class PNCP_Watermark {

	/**
	 * Δένει τα hooks.
	 */
	public static function init() {
		add_filter( 'wp_generate_attachment_metadata', array( __CLASS__, 'apply_to_sizes' ), 20, 2 );
	}

	/**
	 * Είναι διαθέσιμη η βιβλιοθήκη GD;
	 *
	 * @return bool
	 */
	public static function available() {
		return function_exists( 'imagecreatetruecolor' ) && function_exists( 'imagecopyresampled' );
	}

	/**
	 * Βάζει υδατογράφημα σε κάθε μέγεθος της νέας εικόνας.
	 *
	 * @param array<string, mixed> $metadata      Τα metadata του συνημμένου.
	 * @param int                  $attachment_id ID συνημμένου.
	 * @return array<string, mixed>
	 */
	public static function apply_to_sizes( $metadata, $attachment_id ) {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || empty( $s['watermark_enabled'] ) || ! self::available() ) {
			return $metadata;
		}
		if ( empty( $metadata['sizes'] ) || ! is_array( $metadata['sizes'] ) ) {
			return $metadata;
		}
		if ( (int) $attachment_id === (int) $s['watermark_image_id'] ) {
			return $metadata; // Το ίδιο το υδατογράφημα.
		}

		/**
		 * Φίλτρο για να εξαιρέσετε εικόνες (π.χ. λογότυπα).
		 *
		 * @param bool $apply         Αν θα μπει υδατογράφημα.
		 * @param int  $attachment_id ID συνημμένου.
		 */
		if ( ! apply_filters( 'pncp_watermark_attachment', true, $attachment_id ) ) {
			return $metadata;
		}

		$dir  = trailingslashit( dirname( (string) get_attached_file( $attachment_id ) ) );
		$done = array();
		foreach ( $metadata['sizes'] as $size ) {
			// Δύο μεγέθη με τις ίδιες διαστάσεις μοιράζονται ένα αρχείο: υδατογράφημα μόνο μία φορά.
			if ( empty( $size['file'] ) || isset( $done[ $size['file'] ] ) || (int) $size['width'] < (int) $s['watermark_min_width'] ) {
				continue;
			}
			$done[ $size['file'] ] = true;
			$mime = isset( $size['mime-type'] ) ? $size['mime-type'] : '';
			self::apply_to_file( $dir . wp_basename( $size['file'] ), $mime, $s );
		}

		return $metadata;
	}

	/**
	 * Υδατογράφημα σε ένα αρχείο.
	 *
	 * @param string               $path Διαδρομή.
	 * @param string               $mime Τύπος.
	 * @param array<string, mixed> $s    Ρυθμίσεις.
	 * @return bool
	 */
	public static function apply_to_file( $path, $mime, $s ) {
		if ( ! is_file( $path ) || ! is_writable( $path ) ) {
			return false;
		}

		$image = self::load( $path, $mime );
		if ( ! $image ) {
			return false;
		}

		$width  = imagesx( $image );
		$height = imagesy( $image );
		$mark   = self::mark( (int) $s['watermark_image_id'] );
		if ( ! $mark ) {
			return false;
		}

		// Το υδατογράφημα πιάνει έως το 25% του πλάτους, κάτω δεξιά, με περιθώριο 2%.
		$mark_w = imagesx( $mark );
		$mark_h = imagesy( $mark );
		$target = max( 1, (int) round( $width * 0.25 ) );
		$scale  = min( 1, $target / $mark_w );
		$dst_w  = max( 1, (int) round( $mark_w * $scale ) );
		$dst_h  = max( 1, (int) round( $mark_h * $scale ) );
		$margin = (int) round( min( $width, $height ) * 0.02 );

		$layer = imagecreatetruecolor( $dst_w, $dst_h );
		imagealphablending( $layer, false );
		imagesavealpha( $layer, true );
		imagefill( $layer, 0, 0, imagecolorallocatealpha( $layer, 0, 0, 0, 127 ) );
		imagecopyresampled( $layer, $mark, 0, 0, 0, 0, $dst_w, $dst_h, $mark_w, $mark_h );
		self::fade( $layer, (int) $s['watermark_opacity'] );

		imagealphablending( $image, true );
		imagecopy( $image, $layer, $width - $dst_w - $margin, $height - $dst_h - $margin, 0, 0, $dst_w, $dst_h );

		return self::save( $image, $path, $mime );
	}

	/**
	 * Ανοίγει εικόνα JPEG, PNG ή WebP.
	 *
	 * @param string $path Διαδρομή.
	 * @param string $mime Τύπος.
	 * @return resource|\GdImage|false
	 */
	private static function load( $path, $mime ) {
		switch ( $mime ) {
			case 'image/jpeg':
				return function_exists( 'imagecreatefromjpeg' ) ? @imagecreatefromjpeg( $path ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			case 'image/png':
				$img = function_exists( 'imagecreatefrompng' ) ? @imagecreatefrompng( $path ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( $img ) {
					// PNG με παλέτα: σε truecolor, αλλιώς το διάφανο υδατογράφημα χαλάει.
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
	 * Αποθηκεύει στην ίδια μορφή.
	 *
	 * @param resource|\GdImage $image Εικόνα.
	 * @param string            $path  Διαδρομή.
	 * @param string            $mime  Τύπος.
	 * @return bool
	 */
	private static function save( $image, $path, $mime ) {
		switch ( $mime ) {
			case 'image/jpeg':
				return imagejpeg( $image, $path, (int) apply_filters( 'jpeg_quality', 82, 'pncp_watermark' ) );
			case 'image/png':
				return imagepng( $image, $path, 6 );
			case 'image/webp':
				return function_exists( 'imagewebp' ) && imagewebp( $image, $path, 82 );
		}
		return false;
	}

	/**
	 * Η εικόνα του υδατογραφήματος: το PNG της βιβλιοθήκης ή το domain του site ως κείμενο.
	 *
	 * @param int $image_id ID εικόνας PNG (0 = κείμενο).
	 * @return resource|\GdImage|false
	 */
	private static function mark( $image_id ) {
		if ( $image_id > 0 ) {
			$file = get_attached_file( $image_id );
			if ( $file && is_file( $file ) && 'image/png' === get_post_mime_type( $image_id ) ) {
				$png = @imagecreatefrompng( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( $png ) {
					imagesavealpha( $png, true );
					return $png;
				}
			}
		}
		return self::text_mark( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	}

	/**
	 * Κείμενο λευκό με σκιά. Η ενσωματωμένη γραμματοσειρά της GD έχει μόνο λατινικούς χαρακτήρες,
	 * γι' αυτό χρησιμοποιείται το domain. Για λογότυπο ή ελληνικά, ορίστε εικόνα PNG.
	 *
	 * @param string $text Κείμενο.
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
		$small = imagecreatetruecolor( $w, $h );
		imagealphablending( $small, false );
		imagesavealpha( $small, true );
		imagefill( $small, 0, 0, imagecolorallocatealpha( $small, 0, 0, 0, 127 ) );
		imagestring( $small, $font, 1, 1, $text, imagecolorallocatealpha( $small, 0, 0, 0, 40 ) );
		imagestring( $small, $font, 0, 0, $text, imagecolorallocatealpha( $small, 255, 255, 255, 0 ) );

		// Μεγέθυνση x4, ώστε η κλιμάκωση στο 25% της εικόνας να μη θολώνει πολύ.
		$big = imagecreatetruecolor( $w * 4, $h * 4 );
		imagealphablending( $big, false );
		imagesavealpha( $big, true );
		imagefill( $big, 0, 0, imagecolorallocatealpha( $big, 0, 0, 0, 127 ) );
		imagecopyresized( $big, $small, 0, 0, 0, 0, $w * 4, $h * 4, $w, $h );

		return $big;
	}

	/**
	 * Μειώνει τη διαφάνεια κάθε pixel στο ποσοστό που ορίστηκε.
	 *
	 * @param resource|\GdImage $layer   Επίπεδο.
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
