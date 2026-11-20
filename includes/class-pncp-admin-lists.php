<?php
/**
 * 3.11: long lists on the settings page (the bot list, the allow lists, the IP lists) show as "85 entries", the
 * first few entries and an "Edit" button that shows the textarea. The textarea is always in the page with its
 * full value and its usual name, so saving works exactly as before; without JavaScript it is simply shown.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Folded list editors.
 */
final class PNCP_Admin_Lists {

	/**
	 * A list with at least this many entries starts folded (lists folded in earlier versions always do).
	 */
	const COLLAPSE_FROM = 6;

	/**
	 * Entries shown in the preview.
	 */
	const PREVIEW = 4;

	/**
	 * The settings shown with the list editor: the one-per-line lists and the IP lists.
	 *
	 * @return string[]
	 */
	public static function keys() {
		$keys = array_merge( PNCP_Options::list_keys(), PNCP_Options::ip_list_keys() );
		/**
		 * Filters the settings (one entry per line) shown as a folded list with an "Edit" button.
		 *
		 * @param string[] $keys Setting keys.
		 */
		return array_values( array_map( 'strval', (array) apply_filters( 'pncp_admin_list_keys', $keys ) ) );
	}

	/**
	 * Whether a list is shown folded.
	 *
	 * @param string $key   Setting key.
	 * @param int    $count Number of entries.
	 * @param bool   $fold  Whether the list was folded in earlier versions (bot list, allow list).
	 * @return bool
	 */
	public static function folds( $key, $count, $fold = false ) {
		return in_array( (string) $key, self::keys(), true ) && ( $fold || (int) $count >= self::COLLAPSE_FROM );
	}

	/**
	 * Element id of a list editor.
	 *
	 * @param string $key Setting key.
	 * @return string
	 */
	public static function id( $key ) {
		return 'pncp-' . $key . '-list';
	}

	/**
	 * The first few entries, each shortened, and how many more there are.
	 *
	 * @param string[] $entries Entries.
	 * @return string Plain text.
	 */
	public static function preview( $entries ) {
		$entries = array_values( (array) $entries );
		if ( ! $entries ) {
			return __( 'Empty', 'scrapelock' );
		}
		$shown = array();
		foreach ( array_slice( $entries, 0, self::PREVIEW ) as $entry ) {
			$entry   = (string) $entry;
			$shown[] = function_exists( 'mb_strimwidth' ) ? mb_strimwidth( $entry, 0, 40, '…', 'UTF-8' ) : ( strlen( $entry ) > 40 ? substr( $entry, 0, 39 ) . '…' : $entry );
		}
		$text = implode( ', ', $shown );
		$more = count( $entries ) - count( $shown );
		if ( $more > 0 ) {
			$text .= ' ' . sprintf(
				/* translators: %s: number of further entries */
				_n( 'and %s more', 'and %s more', $more, 'scrapelock' ),
				number_format_i18n( $more )
			);
		}
		return $text;
	}

	/**
	 * Opens a list editor: the bar (label, number of entries, Edit) and the preview, then the part with the
	 * textarea (closed by close()).
	 *
	 * @param string $key     Setting key.
	 * @param string $label   Label of the list.
	 * @param string $value   The list (one entry per line).
	 * @param string $risk    Escaped HTML of the risk tag ('' for none).
	 */
	public static function open( $key, $label, $value, $risk = '' ) {
		$entries = PNCP_Options::parse_list( (string) $value );
		$count   = count( $entries );
		$id      = self::id( $key );
		$open    = PNCP_Admin_Sections::requested( $id ); // Back from a Save with the editor open.
		printf(
			'<div class="pncp-list%1$s" id="%2$s" data-pncp-list="1"><div class="pncp-list__bar"><span class="pncp-list__label">%3$s</span> <span class="pncp-badge">%4$s</span>%5$s <button type="button" class="button button-small pncp-list__edit" aria-expanded="%6$s" aria-controls="%2$s-editor" data-label-edit="%7$s" data-label-done="%8$s">%9$s</button></div><p class="pncp-list__preview description">%10$s</p><div class="pncp-list__editor" id="%2$s-editor">',
			$open ? ' is-open' : '',
			esc_attr( $id ),
			esc_html( $label ),
			esc_html( sprintf( /* translators: %s: number of entries */ _n( '%s entry', '%s entries', $count, 'scrapelock' ), number_format_i18n( $count ) ) ),
			'' !== $risk ? ' ' . $risk : '', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by the caller.
			$open ? 'true' : 'false',
			esc_attr__( 'Edit', 'scrapelock' ),
			esc_attr__( 'Done', 'scrapelock' ),
			esc_html( $open ? __( 'Done', 'scrapelock' ) : __( 'Edit', 'scrapelock' ) ),
			esc_html( self::preview( $entries ) )
		);
	}

	/**
	 * Closes a list editor.
	 */
	public static function close() {
		echo '</div></div>';
	}
}
