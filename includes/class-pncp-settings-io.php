<?php
/**
 * Settings: undo (the last versions before a preset, an import or a reset), export and import as JSON,
 * and "reset a tab to its defaults". Used by the settings page and WP-CLI.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Keeps the previous settings before every change made in one click, and moves settings between sites.
 *
 * Every change goes through PNCP_Options::sanitize(), as if it came from the settings form (all tabs at once):
 * the same checks apply (private URLs, too wide IP ranges, "Only through the CDN", "trust every proxy").
 */
final class PNCP_Settings_Io {

	/**
	 * Option with the saved versions (not autoloaded: read only on the settings page and by WP-CLI).
	 */
	const BACKUPS = 'pncp_settings_backups';

	/**
	 * How many versions are kept.
	 */
	const KEEP = 5;

	/**
	 * Largest import file, in bytes. A full export is around 20 KB.
	 */
	const MAX_FILE = 262144;

	/**
	 * Format of the export file.
	 */
	const FORMAT = 1;

	/**
	 * Settings that are never exported, shown or imported: secrets. The API token for blocking at the CDN and
	 * the private feed tokens (stored only as hashes) are kept in their own options and are not part of the
	 * settings at all, so they are never exported either.
	 *
	 * @return string[]
	 */
	public static function secret_keys() {
		return array( 'cdn_secret' );
	}

	/**
	 * Settings that belong to this site's state, not to its configuration: not exported or imported.
	 *
	 * @return string[]
	 */
	public static function internal_keys() {
		return array( 'monitor_until' );
	}

	/**
	 * The settings an import or "settings set" may change.
	 *
	 * @return string[]
	 */
	public static function public_keys() {
		return array_values( array_diff( array_keys( PNCP_Options::defaults() ), self::secret_keys(), self::internal_keys() ) );
	}

	/* ---------- Saved versions (undo) ---------- */

	/**
	 * Saves the current settings as a version that can be restored. The oldest goes beyond KEEP versions.
	 *
	 * @param string $reason What is about to change: profile:<name>, import, reset:<tab>, restore, cli:set, cli:import.
	 * @return string The version's ID.
	 */
	public static function backup( $reason ) {
		$current = get_option( PNCP_OPTION, array() );
		$list    = self::backups();
		$id      = strtolower( wp_generate_password( 12, false ) );
		array_unshift(
			$list,
			array(
				'id'       => $id,
				'time'     => time(),
				'user'     => get_current_user_id(),
				'reason'   => sanitize_text_field( (string) $reason ),
				'settings' => is_array( $current ) ? $current : array(),
			)
		);
		$list = array_slice( $list, 0, self::KEEP );
		// Not autoloaded: five copies of the settings are not needed on every request.
		if ( false === get_option( self::BACKUPS, false ) ) {
			add_option( self::BACKUPS, $list, '', false );
		} else {
			update_option( self::BACKUPS, $list, false );
		}
		return $id;
	}

	/**
	 * The saved versions, newest first.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function backups() {
		$list = get_option( self::BACKUPS, array() );
		$out  = array();
		foreach ( is_array( $list ) ? $list : array() as $item ) {
			if ( is_array( $item ) && isset( $item['id'], $item['time'], $item['settings'] ) && is_array( $item['settings'] ) ) {
				$out[] = $item;
			}
		}
		return $out;
	}

	/**
	 * One saved version.
	 *
	 * @param string $id ID.
	 * @return array<string, mixed>|null
	 */
	public static function find( $id ) {
		foreach ( self::backups() as $item ) {
			if ( '' !== (string) $id && hash_equals( (string) $item['id'], (string) $id ) ) {
				return $item;
			}
		}
		return null;
	}

	/**
	 * Puts a saved version back. The settings as they are now are saved first, so the restore can be undone too.
	 *
	 * @param string $id ID.
	 * @return string|WP_Error The ID of the version saved before the restore.
	 */
	public static function restore( $id ) {
		$item = self::find( $id );
		if ( ! $item ) {
			return new WP_Error( 'pncp_no_backup', __( 'This saved version no longer exists (only the last 5 are kept).', 'scrapelock' ) );
		}
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked: the settings cannot be changed until it is unlocked.', 'scrapelock' ) );
		}
		$before = self::backup( 'restore' );
		update_option( PNCP_OPTION, self::restored( PNCP_Options::stored(), $item['settings'] ) );
		PNCP_Options::flush();
		return $before;
	}

	/**
	 * The settings a restore saves: the saved version on top of the current settings, except what belongs to
	 * the site as it is now (3.4), as on import and reset.
	 *
	 * - The CDN shared secret stays the current one: the CDN keeps sending it. An older one put back, with
	 *   "Only through the CDN" on, would refuse every visitor that comes through the CDN.
	 * - The end of the first-week "Monitor only" stays the current one, and so does "Monitor only" itself when
	 *   the saved version only had it on because it was saved during that first week: undoing a preset does
	 *   not bring the trial back after "Enforce now". "Monitor only" the administrator turned on by hand (no
	 *   end date) is restored like any other setting, without an end date.
	 *
	 * @param array<string, mixed> $current The settings now.
	 * @param array<string, mixed> $saved   The saved version.
	 * @return array<string, mixed>
	 */
	public static function restored( $current, $saved ) {
		$values = array_merge( $current, $saved );
		foreach ( array_merge( self::secret_keys(), self::internal_keys() ) as $key ) {
			if ( array_key_exists( $key, $current ) ) {
				$values[ $key ] = $current[ $key ];
			} else {
				unset( $values[ $key ] );
			}
		}
		if ( ! empty( $saved['monitor_mode'] ) && ! empty( $saved['monitor_until'] ) ) {
			$values['monitor_mode'] = ! empty( $current['monitor_mode'] ) ? 1 : 0; // The trial: as it is now.
		} elseif ( ! empty( $saved['monitor_mode'] ) ) {
			$values['monitor_until'] = 0; // Turned on by hand: no end date.
		}
		if ( empty( $values['monitor_mode'] ) ) {
			$values['monitor_until'] = 0;
		}
		return $values;
	}

	/**
	 * A short description of a saved version, e.g. "Before the Maximum preset".
	 *
	 * @param array<string, mixed> $item Saved version.
	 * @return string
	 */
	public static function reason_label( $item ) {
		$parts = explode( ':', (string) $item['reason'], 2 );
		$what  = isset( $parts[1] ) ? $parts[1] : '';
		switch ( $parts[0] ) {
			case 'profile':
				$names = array(
					'balanced' => __( 'Balanced', 'scrapelock' ),
					'strict'   => __( 'Strict', 'scrapelock' ),
					'maximum'  => __( 'Maximum', 'scrapelock' ),
				);
				/* translators: %s: preset name */
				return sprintf( __( 'Before the %s preset', 'scrapelock' ), isset( $names[ $what ] ) ? $names[ $what ] : $what );
			case 'import':
				return __( 'Before an import', 'scrapelock' );
			case 'reset':
				$tabs = self::tab_names();
				/* translators: %s: tab name */
				return sprintf( __( 'Before resetting the “%s” tab', 'scrapelock' ), isset( $tabs[ $what ] ) ? $tabs[ $what ] : $what );
			case 'restore':
				return __( 'Before restoring an earlier version', 'scrapelock' );
			case 'cli':
				/* translators: %s: WP-CLI command */
				return sprintf( __( 'Before “wp scrapelock settings %s”', 'scrapelock' ), $what );
		}
		return (string) $item['reason'];
	}

	/**
	 * The names of the tabs that hold settings (as on the settings page).
	 *
	 * @return array<string, string>
	 */
	public static function tab_names() {
		return array(
			'general' => __( 'On the page', 'scrapelock' ),
			'bots'    => __( 'Bots and limits', 'scrapelock' ),
			'content' => __( 'Feeds and API', 'scrapelock' ),
			'images'  => __( 'Images', 'scrapelock' ),
			'log'     => __( 'Log', 'scrapelock' ),
		);
	}

	/* ---------- Export / import ---------- */

	/**
	 * What the export file holds: every setting except secrets and this site's state.
	 *
	 * @return array<string, mixed>
	 */
	public static function export() {
		$stored   = PNCP_Options::stored();
		$settings = array();
		foreach ( self::public_keys() as $key ) {
			$settings[ $key ] = $stored[ $key ];
		}
		return array(
			'plugin'   => 'scrapelock',
			'format'   => self::FORMAT,
			'version'  => PNCP_VERSION,
			'exported' => gmdate( 'c' ),
			'site'     => home_url( '/' ),
			// Told in the file too, so whoever imports it knows what to set again by hand.
			'excluded' => array( 'cdn_secret', 'edge_api_token', 'private_feed_tokens' ),
			'settings' => $settings,
		);
	}

	/**
	 * The export as JSON text.
	 *
	 * @return string
	 */
	public static function export_json() {
		return (string) wp_json_encode( self::export(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}

	/**
	 * Reads an export file. Takes the whole file ({"plugin": "scrapelock", "settings": {...}}) or only the
	 * settings object. Unknown keys, secrets and this site's state are left out (and named).
	 *
	 * @param string $json File contents.
	 * @return array{settings: array<string, mixed>, ignored: string[]}|WP_Error
	 */
	public static function parse( $json ) {
		$json = (string) $json;
		if ( strlen( $json ) > self::MAX_FILE ) {
			return new WP_Error( 'pncp_import_size', __( 'The file is too large to be a ScrapeLock export.', 'scrapelock' ) );
		}
		$data = json_decode( preg_replace( '/^\xEF\xBB\xBF/', '', $json ), true );
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'pncp_import_json', __( 'The file is not valid JSON.', 'scrapelock' ) );
		}
		if ( isset( $data['settings'] ) ) {
			if ( isset( $data['plugin'] ) && 'scrapelock' !== $data['plugin'] ) {
				return new WP_Error( 'pncp_import_plugin', __( 'The file is not a ScrapeLock export.', 'scrapelock' ) );
			}
			$data = $data['settings'];
		}
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'pncp_import_json', __( 'The file holds no settings.', 'scrapelock' ) );
		}
		$known    = self::public_keys();
		$settings = array();
		$ignored  = array();
		foreach ( $data as $key => $value ) {
			$key = (string) $key;
			if ( ! in_array( $key, $known, true ) || ! is_scalar( $value ) ) {
				$ignored[] = sanitize_key( $key );
				continue;
			}
			$settings[ $key ] = $value;
		}
		if ( ! $settings ) {
			return new WP_Error( 'pncp_import_empty', __( 'The file holds no ScrapeLock settings.', 'scrapelock' ) );
		}
		return array(
			'settings' => $settings,
			'ignored'  => array_values( array_filter( $ignored ) ),
		);
	}

	/**
	 * What the settings would become with these values: they go through PNCP_Options::sanitize() like a save
	 * of every tab, on top of the current settings (keys that are not given keep their value; the CDN secret
	 * is kept). Nothing is saved here.
	 *
	 * @param array<string, mixed> $values Values to change.
	 * @return array{settings: array<string, mixed>, changes: array<int, array<string, string>>, messages: array<int, array<string, string>>}
	 */
	public static function prepare( $values ) {
		global $wp_settings_errors;
		$stored = PNCP_Options::stored();
		$input  = array_merge( $stored, array_intersect_key( (array) $values, array_flip( self::public_keys() ) ) );
		// Empty = keep the stored secret, as in the form. The end of the first-week monitoring stays this site's.
		foreach ( array_merge( self::secret_keys(), self::internal_keys() ) as $key ) {
			unset( $input[ $key ] );
		}
		if ( isset( $values['cdn_secret'] ) ) {
			$input['cdn_secret'] = (string) $values['cdn_secret']; // Only from WP-CLI "settings set".
			if ( '' === $input['cdn_secret'] ) {
				$input['cdn_secret_clear'] = 1;
			}
		}
		// As if every tab were saved at once: the form's checks apply.
		$input['_sections'] = array_keys( PNCP_Options::sections() );

		$saved              = $wp_settings_errors;
		$wp_settings_errors = array(); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Collects only the messages of this check, restored below.
		$new                = PNCP_Options::sanitize( $input );
		$messages           = array();
		foreach ( (array) $wp_settings_errors as $error ) {
			if ( isset( $error['setting'], $error['message'] ) && PNCP_OPTION === $error['setting'] ) {
				$messages[] = array(
					'type'    => isset( $error['type'] ) && 'warning' === $error['type'] ? 'warning' : 'error',
					'message' => (string) $error['message'],
				);
			}
		}
		$wp_settings_errors = $saved; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Restored.

		return array(
			'settings' => $new,
			'changes'  => self::diff( $stored, $new ),
			'messages' => $messages,
		);
	}

	/**
	 * Saves prepared settings, after saving the current ones as a version that can be restored.
	 *
	 * @param array<string, mixed> $prepared Result of prepare().
	 * @param string               $reason   Why (see backup()).
	 * @return string|WP_Error The ID of the saved version, '' when nothing changes.
	 */
	public static function apply( $prepared, $reason ) {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked: the settings cannot be changed until it is unlocked.', 'scrapelock' ) );
		}
		if ( empty( $prepared['changes'] ) ) {
			return '';
		}
		$id = self::backup( $reason );
		update_option( PNCP_OPTION, $prepared['settings'] );
		PNCP_Options::flush();
		return $id;
	}

	/**
	 * The default values of one tab's settings (for "Reset this tab to defaults"). The CDN shared secret is
	 * kept: it is not shown anywhere, and the CDN keeps sending it.
	 *
	 * @param string $section Tab (general, bots, content, images, log).
	 * @return array<string, mixed>
	 */
	public static function section_defaults( $section ) {
		$sections = PNCP_Options::sections();
		if ( ! isset( $sections[ $section ] ) ) {
			return array();
		}
		$defaults = PNCP_Options::defaults();
		$values   = array();
		foreach ( $sections[ $section ] as $key ) {
			if ( isset( $defaults[ $key ] ) && in_array( $key, self::public_keys(), true ) ) {
				$values[ $key ] = $defaults[ $key ];
			}
		}
		return $values;
	}

	/**
	 * The settings that differ, with both values as short text. Secrets and this site's state are not listed.
	 *
	 * @param array<string, mixed> $old Settings before.
	 * @param array<string, mixed> $new Settings after.
	 * @return array<int, array<string, string>> key, old, new.
	 */
	public static function diff( $old, $new ) {
		$out = array();
		foreach ( self::public_keys() as $key ) {
			$a = isset( $old[ $key ] ) ? (string) $old[ $key ] : '';
			$b = isset( $new[ $key ] ) ? (string) $new[ $key ] : '';
			if ( $a !== $b ) {
				$out[] = array(
					'key' => $key,
					'old' => self::short( $a ),
					'new' => self::short( $b ),
				);
			}
		}
		return $out;
	}

	/**
	 * A value in one short line: lists separated by commas, cut after 120 characters.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	private static function short( $value ) {
		$value = implode( ', ', array_filter( array_map( 'trim', preg_split( '/\r\n|\r|\n/', $value ) ), 'strlen' ) );
		return mb_strlen( $value ) > 120 ? mb_substr( $value, 0, 117 ) . '…' : $value;
	}
}
