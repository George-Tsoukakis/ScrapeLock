<?php
/**
 * ScrapeLock — υδατογράφημα σε πραγματικό WordPress (χρειάζεται GD).
 *
 *   WP_DIR=/path/to/wordpress php t_watermark.php
 *
 * Οι εικόνες είναι PNG: η κωδικοποίηση PNG είναι ντετερμινιστική, οπότε «ίδιο md5» σημαίνει «ίδια εικόνα»
 * και μπορούμε να αποδείξουμε ότι δεν μπαίνει ποτέ διπλό υδατογράφημα.
 */

$wp_dir = getenv( 'WP_DIR' );
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/image.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
require_once ABSPATH . 'wp-admin/includes/media.php';

if ( ! extension_loaded( 'gd' ) ) {
	echo "SKIP χωρίς GD\n";
	exit( 0 );
}
// Ίδιος editor για όλα τα resize (το Imagick, αν υπάρχει, δίνει άλλα bytes).
add_filter(
	'wp_image_editors',
	static function () {
		return array( 'WP_Image_Editor_GD' );
	}
);

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Watermark::reset();
}

/** PNG με διαβάθμιση (για να φαίνεται κάθε αλλαγή στα pixels). */
function make_png( $w, $h, $seed ) {
	$img = imagecreatetruecolor( $w, $h );
	for ( $y = 0; $y < $h; $y += 4 ) {
		$c = imagecolorallocate( $img, ( $y * 3 + $seed ) % 256, ( $y + $seed * 7 ) % 256, ( ( 200 - $y + $seed ) % 256 + 256 ) % 256 );
		imagefilledrectangle( $img, 0, $y, $w - 1, $y + 3, $c );
	}
	$file = get_temp_dir() . 'pncp-test-' . $seed . '-' . wp_generate_password( 6, false ) . '.png';
	imagepng( $img, $file );
	return $file;
}

function upload( $file, $parent = 0 ) {
	$tmp = get_temp_dir() . 'up-' . basename( $file );
	copy( $file, $tmp );
	$id = media_handle_sideload(
		array(
			'name'     => basename( $file ),
			'tmp_name' => $tmp,
		),
		$parent
	);
	return is_wp_error( $id ) ? 0 : (int) $id;
}

function size_path( $id, $size = 'medium' ) {
	$meta = wp_get_attachment_metadata( $id );
	return trailingslashit( dirname( get_attached_file( $id ) ) ) . $meta['sizes'][ $size ]['file'];
}

function regenerate( $id ) {
	// Όπως το «Regenerate Thumbnails» / wp media regenerate: από το αρχικό αρχείο.
	$meta = wp_generate_attachment_metadata( $id, wp_get_original_image_path( $id ) );
	wp_update_attachment_metadata( $id, $meta );
}

settings(
	array(
		'enabled'             => 1,
		'watermark_enabled'   => 0,
		'watermark_full'      => 0,
		'watermark_products'  => 0,
		'watermark_image_id'  => 0,
		'watermark_position'  => 'br',
		'watermark_size'      => 25,
		'watermark_opacity'   => 60,
		'watermark_min_width' => 200,
	)
);

/* ---------- Αναφορά: η ίδια εικόνα χωρίς υδατογράφημα ---------- */
$src   = make_png( 1200, 800, 11 );
$clean = upload( $src );
t( 'upload χωρίς υδατογράφημα', $clean > 0 );
$c_medium = md5_file( size_path( $clean ) );
$c_full   = md5_file( get_attached_file( $clean ) );
t( 'χωρίς υδατογράφημα: κανένα meta', '' === get_post_meta( $clean, PNCP_Watermark::META, true ) );

/* ---------- Νέο upload με υδατογράφημα ---------- */
settings( array( 'watermark_enabled' => 1 ) );
$a  = upload( $src );
$m1 = md5_file( size_path( $a ) );
t( 'νέο upload: το medium έχει υδατογράφημα', $m1 !== $c_medium );
t( 'νέο upload: το πλήρες μέγεθος μένει καθαρό (watermark_full = 0)', md5_file( get_attached_file( $a ) ) === $c_full );
t( 'νέο upload: thumbnail 150px (κάτω από το ελάχιστο πλάτος) καθαρό', 0 === PNCP_Watermark::state( $a )['sizes'][ wp_basename( size_path( $a, 'thumbnail' ) ) ] );

regenerate( $a );
t( 'Regenerate Thumbnails: όχι διπλό υδατογράφημα', md5_file( size_path( $a ) ) === $m1 );
wp_update_image_subsizes( $a );
t( 'wp_update_image_subsizes (context update): όχι διπλό', md5_file( size_path( $a ) ) === $m1 );
PNCP_Watermark::on_generate( wp_get_attachment_metadata( $a ), $a, 'update' );
t( 'ξανά το φίλτρο σε context update: όχι διπλό', md5_file( size_path( $a ) ) === $m1 );

/* ---------- Πλήρες μέγεθος ---------- */
settings( array( 'watermark_full' => 1 ) );
PNCP_Watermark::rebuild( $a, true );
$f1 = md5_file( get_attached_file( $a ) );
t( 'rebuild με watermark_full: το πλήρες μέγεθος έχει υδατογράφημα', $f1 !== $c_full );
t( 'rebuild: το medium ίδιο με πριν (όχι διπλό)', md5_file( size_path( $a ) ) === $m1 );
$backup = PNCP_Watermark::backup_path( get_attached_file( $a ) );
t( 'το καθαρό πρωτότυπο φυλάχτηκε', is_file( $backup ) && md5_file( $backup ) === $c_full );
t( 'ο φάκελος αντιγράφων έχει .htaccess και index.html (κανένα αρχείο PHP στο uploads)', is_file( dirname( $backup, 3 ) . '/.htaccess' ) && is_file( dirname( $backup, 3 ) . '/index.html' ), dirname( $backup, 3 ) );
t( 'το όνομα του φακέλου δεν μαντεύεται', (bool) preg_match( '/pncp-originals-[a-z0-9]{12}/', $backup ) );
PNCP_Watermark::rebuild( $a, true );
t( 'rebuild δεύτερη φορά (διακοπή και ξανά): όχι διπλό', md5_file( get_attached_file( $a ) ) === $f1 && md5_file( size_path( $a ) ) === $m1 );
regenerate( $a );
t( 'Regenerate Thumbnails από πλήρες με υδατογράφημα: πλήρες όχι διπλό', md5_file( get_attached_file( $a ) ) === $f1 );
t( 'Regenerate Thumbnails από πλήρες με υδατογράφημα: medium όχι διπλό', md5_file( size_path( $a ) ) === $m1 );

/* ---------- Αντικατάσταση εικόνας στο ίδιο όνομα (π.χ. Enable Media Replace) ---------- */
$keep_full = get_attached_file( $a );
$newsrc    = make_png( 1200, 800, 77 );
settings( array( 'watermark_full' => 0, 'watermark_enabled' => 0 ) );
$n_ref     = upload( $newsrc );
$n_full    = md5_file( get_attached_file( $n_ref ) );
$n_medium  = md5_file( size_path( $n_ref ) );
settings( array( 'watermark_full' => 1, 'watermark_enabled' => 1 ) );
copy( $newsrc, $keep_full ); // νέα εικόνα πάνω από το πλήρες μέγεθος με υδατογράφημα
regenerate( $a );
t( 'αντικατάσταση εικόνας: δεν επανέρχεται η παλιά εικόνα από το αντίγραφο', md5_file( get_attached_file( $a ) ) !== $f1 && md5_file( get_attached_file( $a ) ) !== $c_full && md5_file( get_attached_file( $a ) ) !== $n_full );
t( 'αντικατάσταση εικόνας: το αντίγραφο είναι πλέον η νέα καθαρή εικόνα', md5_file( PNCP_Watermark::backup_path( get_attached_file( $a ) ) ) === $n_full );
PNCP_Watermark::rebuild( $a, false );
t( 'αντικατάσταση εικόνας: η αφαίρεση δίνει τη νέα εικόνα καθαρή', md5_file( get_attached_file( $a ) ) === $n_full && md5_file( size_path( $a ) ) === $n_medium );
copy( $src, $keep_full ); // πίσω στην αρχική εικόνα για τα επόμενα
PNCP_Watermark::rebuild( $a, true );

/* ---------- Αποτυχία resize: όχι υδατογράφημα πάνω σε υδατογράφημα ---------- */
$medium_before = md5_file( size_path( $a ) );
$no_editor     = static function () {
	return array(); // Κανένας image editor (π.χ. λείπει μνήμη / μορφή που δεν διαβάζεται).
};
add_filter( 'wp_image_editors', $no_editor, 99 );
$res = PNCP_Watermark::rebuild( $a, true );
remove_filter( 'wp_image_editors', $no_editor, 99 );
t( 'αποτυχία resize: το εργαλείο αναφέρει σφάλμα', 'error' === $res, (string) $res );
t( 'αποτυχία resize: το medium δεν πήρε δεύτερο υδατογράφημα', md5_file( size_path( $a ) ) === $medium_before );
$backup_a = PNCP_Watermark::backup_path( get_attached_file( $a ) );
$hidden   = get_attached_file( $a ) . '.hidden';
rename( get_attached_file( $a ), $hidden );
PNCP_Watermark::rebuild( $a, true );
t( 'λείπει το πλήρες αρχείο (offload): το καθαρό αντίγραφο δεν χάνεται', is_file( $backup_a ) && md5_file( $backup_a ) === $c_full );
unlink( $hidden );
PNCP_Watermark::rebuild( $a, true );

/* ---------- Αφαίρεση ---------- */
PNCP_Watermark::rebuild( $a, false );
t( 'αφαίρεση: πλήρες ξανά καθαρό', md5_file( get_attached_file( $a ) ) === $c_full );
t( 'αφαίρεση: medium ξανά καθαρό', md5_file( size_path( $a ) ) === $c_medium );
t( 'αφαίρεση: χωρίς meta και χωρίς αντίγραφο', '' === get_post_meta( $a, PNCP_Watermark::META, true ) && ! is_file( $backup ) );

/* ---------- Εικόνα με υδατογράφημα από την 1.4 (χωρίς σημάδι) ---------- */
settings( array( 'watermark_full' => 0 ) );
PNCP_Watermark::apply_to_file( size_path( $a ), 'image/png', PNCP_Options::get() ); // όπως θα την άφηνε η 1.4
t( 'προσομοίωση 1.4: medium με υδατογράφημα, χωρίς meta', md5_file( size_path( $a ) ) === $m1 && '' === get_post_meta( $a, PNCP_Watermark::META, true ) );
PNCP_Watermark::rebuild( $a, true );
t( 'εργαλείο «Εφαρμογή» σε εικόνα της 1.4: ένα υδατογράφημα, όχι δύο', md5_file( size_path( $a ) ) === $m1 );

/* ---------- Εξαιρέσεις: λογότυπο, εικονίδιο, προϊόντα ---------- */
settings( array( 'watermark_full' => 1 ) );
PNCP_Watermark::rebuild( $a, true );
update_option( 'site_icon', $a );
$next = wp_next_scheduled( PNCP_Watermark::CRON_UNMARK, array( $a ) );
t( 'εικόνα που γίνεται εικονίδιο site: προγραμματίζεται αφαίρεση', (bool) $next );
PNCP_Watermark::unmark( $a );
wp_clear_scheduled_hook( PNCP_Watermark::CRON_UNMARK, array( $a ) );
t( 'εικονίδιο site: καθαρό πλήρες και medium', md5_file( get_attached_file( $a ) ) === $c_full && md5_file( size_path( $a ) ) === $c_medium );
PNCP_Watermark::rebuild( $a, true );
t( 'εικονίδιο site: το εργαλείο δεν του ξαναβάζει υδατογράφημα', md5_file( size_path( $a ) ) === $c_medium );
delete_option( 'site_icon' );

set_theme_mod( 'custom_logo', 0 );
$logo = upload( $src );
set_theme_mod( 'custom_logo', $logo );
t( 'λογότυπο θέματος: προγραμματίζεται αφαίρεση', (bool) wp_next_scheduled( PNCP_Watermark::CRON_UNMARK, array( $logo ) ) );
PNCP_Watermark::unmark( $logo );
wp_clear_scheduled_hook( PNCP_Watermark::CRON_UNMARK, array( $logo ) );
t( 'λογότυπο θέματος: καθαρό', md5_file( size_path( $logo ) ) === $c_medium );
remove_theme_mod( 'custom_logo' );

$product = wp_insert_post( array( 'post_type' => 'product', 'post_status' => 'publish', 'post_title' => 'Προϊόν' ) );
$p_img   = upload( $src, $product );
t( 'εικόνα που ανεβαίνει σε προϊόν: χωρίς υδατογράφημα', md5_file( size_path( $p_img ) ) === $c_medium && md5_file( get_attached_file( $p_img ) ) === $c_full );
$b = upload( $src );
t( 'εικόνα βιβλιοθήκης: με υδατογράφημα', md5_file( size_path( $b ) ) === $m1 );
update_post_meta( $product, '_product_image_gallery', $p_img . ',' . $b );
t( 'μπαίνει σε γκαλερί προϊόντος: προγραμματίζεται αφαίρεση', (bool) wp_next_scheduled( PNCP_Watermark::CRON_UNMARK, array( $b ) ) );
PNCP_Watermark::unmark( $b );
wp_clear_scheduled_hook( PNCP_Watermark::CRON_UNMARK, array( $b ) );
t( 'γκαλερί προϊόντος: καθαρή', md5_file( size_path( $b ) ) === $c_medium && md5_file( get_attached_file( $b ) ) === $c_full );
settings( array( 'watermark_products' => 1 ) );
PNCP_Watermark::rebuild( $b, true );
t( 'με «και στα προϊόντα»: παίρνει υδατογράφημα', md5_file( size_path( $b ) ) === $m1 );
settings( array( 'watermark_products' => 0 ) );

$logo_png = make_png( 400, 120, 99 );
settings( array( 'watermark_enabled' => 0 ) );
$mark_ref = upload( $logo_png );
$mark_md  = md5_file( size_path( $mark_ref ) );
settings( array( 'watermark_enabled' => 1 ) );
$mark_id = upload( $logo_png );
t( 'λογότυπο PNG που ανέβηκε με ενεργό υδατογράφημα: το πήρε', md5_file( size_path( $mark_id ) ) !== $mark_md );
settings( array( 'watermark_image_id' => $mark_id ) );
t( 'ορίζεται ως υδατογράφημα: προγραμματίζεται αφαίρεση', (bool) wp_next_scheduled( PNCP_Watermark::CRON_UNMARK, array( $mark_id ) ) );
PNCP_Watermark::unmark( $mark_id );
wp_clear_scheduled_hook( PNCP_Watermark::CRON_UNMARK, array( $mark_id ) );
t( 'η εικόνα του υδατογραφήματος έμεινε καθαρή', md5_file( size_path( $mark_id ) ) === $mark_md );
PNCP_Watermark::rebuild( $mark_id, true );
t( 'το εργαλείο δεν βάζει υδατογράφημα στην εικόνα του υδατογραφήματος', md5_file( size_path( $mark_id ) ) === $mark_md );
$c = upload( $src );
t( 'υδατογράφημα από PNG της βιβλιοθήκης', md5_file( size_path( $c ) ) !== $c_medium && md5_file( size_path( $c ) ) !== $m1 );
settings( array( 'watermark_image_id' => 0 ) );

/* ---------- Μεγάλη εικόνα (-scaled) ---------- */
$big     = make_png( 3000, 1600, 23 );
settings( array( 'watermark_enabled' => 0, 'watermark_full' => 0 ) );
$big_ref = upload( $big );
$ref_s   = md5_file( get_attached_file( $big_ref ) );
$ref_o   = md5_file( wp_get_original_image_path( $big_ref ) );
$ref_m   = md5_file( size_path( $big_ref, 'large' ) );
settings( array( 'watermark_enabled' => 1, 'watermark_full' => 1 ) );
$g = upload( $big );
t( 'μεγάλη εικόνα: το WordPress έφτιαξε -scaled', false !== strpos( get_attached_file( $g ), '-scaled' ) );
$g_s = md5_file( get_attached_file( $g ) );
$g_o = md5_file( wp_get_original_image_path( $g ) );
$g_m = md5_file( size_path( $g, 'large' ) );
t( 'μεγάλη εικόνα: υδατογράφημα και στο -scaled και στο αρχικό upload', $g_s !== $ref_s && $g_o !== $ref_o );
regenerate( $g );
t( 'μεγάλη εικόνα, Regenerate: όχι διπλό (scaled, αρχικό, large)', md5_file( get_attached_file( $g ) ) === $g_s && md5_file( wp_get_original_image_path( $g ) ) === $g_o && md5_file( size_path( $g, 'large' ) ) === $g_m );
PNCP_Watermark::rebuild( $g, false );
t( 'μεγάλη εικόνα, αφαίρεση: όλα καθαρά', md5_file( get_attached_file( $g ) ) === $ref_s && md5_file( wp_get_original_image_path( $g ) ) === $ref_o && md5_file( size_path( $g, 'large' ) ) === $ref_m );

/* ---------- Διαγραφή ---------- */
PNCP_Watermark::rebuild( $g, true );
$g_backup = PNCP_Watermark::backup_path( get_attached_file( $g ) );
t( 'πριν τη διαγραφή υπάρχει αντίγραφο', is_file( $g_backup ) );
wp_delete_attachment( $g, true );
t( 'διαγραφή εικόνας: φεύγει και το αντίγραφο', ! is_file( $g_backup ) );

/* ---------- Θέσεις και tiled (δείγματα για οπτικό έλεγχο) ---------- */
$out = getenv( 'PNCP_SAMPLES' );
foreach ( array( 'br', 'center', 'tiled' ) as $pos ) {
	settings( array( 'watermark_position' => $pos, 'watermark_size' => 'tiled' === $pos ? 18 : 25, 'watermark_opacity' => 45 ) );
	$file = make_png( 900, 600, 42 );
	$ok   = PNCP_Watermark::apply_to_file( $file, 'image/png', PNCP_Options::get() );
	t( "θέση $pos", $ok && md5_file( $file ) !== md5_file( make_png( 900, 600, 42 ) ) );
	if ( $out ) {
		copy( $file, rtrim( $out, '/' ) . "/sample-$pos.png" );
	}
}
foreach ( array( 'image/jpeg' => 'imagejpeg', 'image/webp' => 'imagewebp' ) as $mime => $fn ) {
	$img  = imagecreatetruecolor( 800, 500 );
	$file = get_temp_dir() . 'pncp-' . md5( $mime ) . ( 'image/jpeg' === $mime ? '.jpg' : '.webp' );
	$fn( $img, $file );
	$before = md5_file( $file );
	t( "υδατογράφημα σε $mime", PNCP_Watermark::apply_to_file( $file, $mime, PNCP_Options::get() ) && md5_file( $file ) !== $before );
}

settings( array( 'watermark_enabled' => 0, 'watermark_full' => 0, 'watermark_position' => 'br', 'watermark_size' => 25 ) );
echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
