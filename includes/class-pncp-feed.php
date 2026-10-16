<?php
/**
 * RSS/Atom: πλήρες κείμενο, μόνο περίληψη με σύνδεσμο, ή καθόλου feeds.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Ελέγχει τι δίνουν τα feeds.
 */
final class PNCP_Feed {

	/**
	 * Δένει τα hooks ανάλογα με τη ρύθμιση.
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'setup' ) );
	}

	/**
	 * Η ρύθμιση διαβάζεται στο init, ώστε να έχουν φορτωθεί οι μεταφράσεις.
	 */
	public static function setup() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) || 'full' === $s['feed_mode'] ) {
			return;
		}

		if ( 'disabled' === $s['feed_mode'] ) {
			foreach ( array( 'do_feed', 'do_feed_rdf', 'do_feed_rss', 'do_feed_rss2', 'do_feed_atom', 'do_feed_rss2_comments', 'do_feed_atom_comments' ) as $hook ) {
				add_action( $hook, array( __CLASS__, 'disabled' ), 1 );
			}
			remove_action( 'wp_head', 'feed_links', 2 );
			remove_action( 'wp_head', 'feed_links_extra', 3 );
			return;
		}

		// excerpt: το WordPress τότε δεν βγάζει καθόλου το content:encoded.
		// Όχι στο wp-admin, ώστε να μην αποθηκευτεί κατά λάθος στις Ρυθμίσεις → Ανάγνωση.
		if ( is_admin() ) {
			return;
		}
		add_filter( 'pre_option_rss_use_excerpt', array( __CLASS__, 'force_excerpt' ) );
		add_filter( 'the_excerpt_rss', array( __CLASS__, 'append_link' ), 99 );
		add_filter( 'the_content_feed', array( __CLASS__, 'content_to_excerpt' ), 99 );
	}

	/**
	 * Πάντα περίληψη στα feeds.
	 *
	 * @return string
	 */
	public static function force_excerpt() {
		return '1';
	}

	/**
	 * Για feeds που δείχνουν περιεχόμενο παρ' όλα αυτά (π.χ. Atom), δίνουμε μόνο την περίληψη.
	 *
	 * @return string
	 */
	public static function content_to_excerpt() {
		return wpautop( esc_html( self::excerpt_text() ) . ' ' . self::link_html() );
	}

	/**
	 * Προσθέτει «Διαβάστε το πλήρες άρθρο στο …» στο τέλος της περίληψης.
	 *
	 * @param string $excerpt Η περίληψη.
	 * @return string
	 */
	public static function append_link( $excerpt ) {
		$text = sprintf(
			/* translators: 1: όνομα site, 2: σύνδεσμος του άρθρου */
			__( 'Διαβάστε το πλήρες άρθρο στο %1$s: %2$s', 'content-protect' ),
			wp_strip_all_tags( get_bloginfo( 'name' ) ),
			get_permalink()
		);
		return trim( $excerpt ) . ' ' . $text;
	}

	/**
	 * Η περίληψη του τρέχοντος άρθρου ως απλό κείμενο.
	 *
	 * @return string
	 */
	private static function excerpt_text() {
		$post = get_post();
		if ( ! $post ) {
			return '';
		}
		if ( has_excerpt( $post ) ) {
			return wp_strip_all_tags( $post->post_excerpt );
		}
		return wp_trim_words( wp_strip_all_tags( strip_shortcodes( $post->post_content ) ), 55 );
	}

	/**
	 * Σύνδεσμος προς το άρθρο.
	 *
	 * @return string
	 */
	private static function link_html() {
		return sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url( get_permalink() ),
			esc_html(
				sprintf(
					/* translators: %s: όνομα site */
					__( 'Διαβάστε το πλήρες άρθρο στο %s', 'content-protect' ),
					wp_strip_all_tags( get_bloginfo( 'name' ) )
				)
			)
		);
	}

	/**
	 * Απάντηση όταν τα feeds είναι κλειστά.
	 */
	public static function disabled() {
		wp_die(
			esc_html__( 'Τα feeds αυτού του site είναι απενεργοποιημένα.', 'content-protect' ),
			esc_html__( 'Μη διαθέσιμο', 'content-protect' ),
			array( 'response' => 410 )
		);
	}
}
