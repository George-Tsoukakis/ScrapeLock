<?php
/**
 * RSS/Atom: full text, excerpt only with a link, or no feeds at all.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Controls what the feeds provide.
 */
final class PNCP_Feed {

	/**
	 * Attaches the hooks according to the setting.
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'setup' ) );
	}

	/**
	 * The setting is read on init, so that translations have been loaded.
	 */
	public static function setup() {
		$s = PNCP_Options::get();
		if ( empty( $s['enabled'] ) ) {
			return;
		}
		if ( 'full' === $s['feed_mode'] ) {
			// Full text: a source line at the end, so that a site that republishes the feed links back to the original.
			if ( ! empty( $s['feed_source_link'] ) && ! is_admin() ) {
				add_filter( 'the_content_feed', array( __CLASS__, 'append_source' ), 99 );
			}
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

		// excerpt: WordPress then does not output content:encoded at all.
		// Not in wp-admin, so that it is not saved by mistake in Settings → Reading.
		if ( is_admin() ) {
			return;
		}
		add_filter( 'pre_option_rss_use_excerpt', array( __CLASS__, 'force_excerpt' ) );
		add_filter( 'the_excerpt_rss', array( __CLASS__, 'append_link' ), 99 );
		add_filter( 'the_content_feed', array( __CLASS__, 'content_to_excerpt' ), 99 );
	}

	/**
	 * Always an excerpt in feeds.
	 *
	 * @return string
	 */
	public static function force_excerpt() {
		return '1';
	}

	/**
	 * For feeds that show content anyway (e.g. Atom), we provide only the excerpt.
	 *
	 * @return string
	 */
	public static function content_to_excerpt() {
		return wpautop( esc_html( self::excerpt_text() ) . ' ' . self::link_html() );
	}

	/**
	 * Appends "Read the full article at …" to the end of the excerpt.
	 *
	 * @param string $excerpt The excerpt.
	 * @return string
	 */
	public static function append_link( $excerpt ) {
		$text = sprintf(
			/* translators: 1: site name, 2: article link */
			__( 'Read the full article at %1$s: %2$s', 'scrapelock' ),
			wp_strip_all_tags( get_bloginfo( 'name' ) ),
			get_permalink()
		);
		return trim( $excerpt ) . ' ' . $text;
	}

	/**
	 * "The post … first appeared on …" at the end of the full text in feeds.
	 *
	 * @param string $content The content.
	 * @return string
	 */
	public static function append_source( $content ) {
		if ( ! get_post() ) {
			return $content;
		}
		$plain = static function ( $text ) {
			return esc_html( wp_strip_all_tags( html_entity_decode( (string) $text, ENT_QUOTES, 'UTF-8' ) ) );
		};
		$line  = sprintf(
			/* translators: 1: article link, 2: site link */
			__( 'The post %1$s first appeared on %2$s.', 'scrapelock' ),
			sprintf( '<a href="%1$s">%2$s</a>', esc_url( get_permalink() ), $plain( get_the_title() ) ),
			sprintf( '<a href="%1$s">%2$s</a>', esc_url( home_url( '/' ) ), $plain( get_bloginfo( 'name' ) ) )
		);
		return $content . "\n<p>" . $line . '</p>';
	}

	/**
	 * The current article's excerpt as plain text.
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
	 * Link to the article.
	 *
	 * @return string
	 */
	private static function link_html() {
		return sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url( get_permalink() ),
			esc_html(
				sprintf(
					/* translators: %s: site name */
					__( 'Read the full article at %s', 'scrapelock' ),
					wp_strip_all_tags( get_bloginfo( 'name' ) )
				)
			)
		);
	}

	/**
	 * Response when feeds are closed.
	 */
	public static function disabled() {
		wp_die(
			esc_html__( 'The feeds of this site are disabled.', 'scrapelock' ),
			esc_html__( 'Unavailable', 'scrapelock' ),
			array( 'response' => 410 )
		);
	}
}
