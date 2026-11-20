<?php
/**
 * 3.11: the parts of the Bots and limits tab as an accordion. Each part (Monitor only, Scrapers and bots, AI,
 * Always allowed…) is a <details> with the part's old id (pncp-sec-<id>), so quick links, the status bar and
 * the open parts kept across a Save (PNCP_Admin_Sections) find it as before. Only Bots, Limits and Sign-in are
 * open on a plain visit; after a Save the parts that were open are open again.
 *
 * Display only: the fields stay in the same settings form with the same names, so saving works as before.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Accordion of the settings parts.
 */
final class PNCP_Admin_Accordion {

	/**
	 * Whether the parts printed now are accordion parts.
	 *
	 * @var bool
	 */
	private static $active = false;

	/**
	 * Starts printing parts as accordion parts.
	 */
	public static function start() {
		self::$active = true;
	}

	/**
	 * Stops: the parts printed after this are rows of a settings table again.
	 */
	public static function stop() {
		self::$active = false;
	}

	/**
	 * Whether the accordion is on.
	 *
	 * @return bool
	 */
	public static function active() {
		return self::$active;
	}

	/**
	 * The parts open on a plain visit (part ids without "pncp-sec-").
	 *
	 * @return string[]
	 */
	public static function default_open() {
		/**
		 * Filters the parts of the Bots and limits tab that are open on a plain visit.
		 *
		 * @param string[] $ids Part ids (as in pncp-sec-<id>).
		 */
		return array_map( 'strval', (array) apply_filters( 'pncp_admin_open_sections', array( 'bots', 'limits', 'login' ) ) );
	}

	/**
	 * Whether a part is printed open: back from a Save, the parts that were open; else the default ones.
	 *
	 * @param string $id Part id (without "pncp-sec-").
	 * @return bool
	 */
	public static function is_open( $id ) {
		$requested = PNCP_Admin_Sections::requested_keys();
		if ( $requested ) {
			return in_array( 'pncp-sec-' . $id, $requested, true );
		}
		return in_array( (string) $id, self::default_open(), true );
	}

	/**
	 * Opens a part: its <details> with the title as summary, and a settings table with one card.
	 *
	 * @param string $id    Part id (the element id is pncp-sec-<id>).
	 * @param string $title Title.
	 */
	public static function part_open( $id, $title ) {
		printf(
			'<details class="pncp-advanced pncp-acc" id="pncp-sec-%1$s"%2$s><summary><h3 class="pncp-advanced__title">%3$s</h3></summary><table class="form-table" role="presentation"><tr class="pncp-acc__card"><td>',
			esc_attr( $id ),
			self::is_open( $id ) ? ' open' : '',
			esc_html( $title )
		);
	}

	/**
	 * Closes a part.
	 */
	public static function part_close() {
		echo '</td></tr></table></details>';
	}
}
