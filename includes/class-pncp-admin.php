<?php
/**
 * Settings page in wp-admin (Settings → ScrapeLock), with tabs.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/class-pncp-admin-fields.php';

/**
 * Admin UI. Settings go through the Settings API (options.php checks nonce and capability).
 * Actions (profiles, token, bans, image tool) go through admin-post / AJAX with a nonce.
 */
final class PNCP_Admin {

	const PAGE  = 'scrapelock';
	const GROUP = 'pncp_settings_group';

	/**
	 * The tab whose settings form is open (for the "Reset this tab to defaults" link under it).
	 *
	 * @var string
	 */
	private static $form_section = '';

	/**
	 * 3.4.3: the action of the admin-post form opened last, so every action form gets its own button id
	 * (submit_button() prints id="submit" on all of them).
	 *
	 * @var string
	 */
	private static $action_form = '';

	/**
	 * 3.4.3: submit button ids used so far, per action.
	 *
	 * @var int[]
	 */
	private static $submit_ids = array();

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( PNCP_FILE ), array( __CLASS__, 'action_links' ) );
		add_action( 'admin_post_pncp_profile', array( __CLASS__, 'handle_profile' ) );
		add_action( 'admin_post_pncp_settings', array( __CLASS__, 'handle_settings' ) );
		add_action( 'admin_post_pncp_token', array( __CLASS__, 'handle_token' ) );
		add_action( 'admin_post_pncp_log', array( __CLASS__, 'handle_log' ) );
		add_action( 'admin_post_pncp_cf_ip', array( __CLASS__, 'handle_cf_ip' ) );
		add_action( 'admin_post_pncp_bunny_ip', array( __CLASS__, 'handle_bunny_ip' ) );
		add_action( 'admin_post_pncp_edge', array( __CLASS__, 'handle_edge' ) );
		add_action( 'wp_ajax_pncp_wm_batch', array( __CLASS__, 'ajax_wm_batch' ) );
		add_action( 'admin_notices', array( __CLASS__, 'upgrade_notices' ) );
		PNCP_Admin_Sections::init(); // 3.10: folded parts stay open after a Save.
		PNCP_Wizard::init(); // 3.11: "For my site" (admin-post pncp_wizard).
		PNCP_Admin_Traffic::init(); // 3.12: the Traffic tab and its actions.
	}

	/**
	 * Adds the entry to the Settings menu.
	 */
	public static function menu() {
		add_options_page(
			__( 'ScrapeLock', 'scrapelock' ),
			__( 'ScrapeLock', 'scrapelock' ),
			// Administrators keep only "read" while the site is locked: they still reach the Lockdown tab.
			PNCP_Lockdown::is_owner( get_current_user_id() ) ? 'read' : 'manage_options',
			self::PAGE,
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * Registers the option with the Settings API.
	 */
	public static function register() {
		register_setting(
			self::GROUP,
			PNCP_OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'PNCP_Options', 'sanitize' ),
				'default'           => PNCP_Options::defaults(),
				'show_in_rest'      => false,
			)
		);
	}

	/**
	 * CSS and JS only on the plugin page.
	 *
	 * @param string $hook Page hook.
	 */
	public static function assets( $hook ) {
		if ( 'settings_page_' . self::PAGE !== $hook ) {
			return;
		}
		// A body class of our own, so the page-wide layout rules (full width, background) stay on this page only.
		add_filter(
			'admin_body_class',
			static function ( $classes ) {
				return $classes . ' pncp-admin-page';
			}
		);
		wp_enqueue_style( 'pncp-admin', PNCP_URL . 'assets/css/admin.css', array(), PNCP_VERSION );
		wp_enqueue_script( 'pncp-admin', PNCP_URL . 'assets/js/admin.js', array(), PNCP_VERSION, true );
		wp_localize_script(
			'pncp-admin',
			'pncpAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'pncp_wm_batch' ),
				'i18n'    => array(
					'confirmApply'  => __( 'All images in the library will be regenerated with a watermark. Do you have a backup of the uploads folder? Continue?', 'scrapelock' ),
					'confirmRemove' => __( 'The watermark will be removed from all images. Continue?', 'scrapelock' ),
					/* translators: 1: images done, 2: total */
					'progress'      => __( 'Processed %1$s of %2$s images…', 'scrapelock' ),
					/* translators: 1: total images, 2: errors */
					'done'          => __( 'Done: %1$s images. Errors: %2$s.', 'scrapelock' ),
					'error'         => __( 'Stopped because of an error. Click the button again to resume where it stopped.', 'scrapelock' ),
					'copied'        => __( 'Copied', 'scrapelock' ),
				),
			)
		);
	}

	/**
	 * "Settings" link in the plugins list.
	 *
	 * @param string[] $links Links.
	 * @return string[]
	 */
	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( PNCP_Status::settings_url() ) . '">' . esc_html__( 'Settings', 'scrapelock' ) . '</a>' );
		return $links;
	}

	/**
	 * The tabs.
	 *
	 * @return array<string, string>
	 */
	private static function tabs() {
		return array(
			'general'   => __( 'On the page', 'scrapelock' ),
			'bots'      => __( 'Bots and limits', 'scrapelock' ),
			'content'   => __( 'Feeds and API', 'scrapelock' ),
			'images'    => __( 'Images', 'scrapelock' ),
			'rules'     => __( 'Server rules', 'scrapelock' ),
			'log'       => __( 'Log', 'scrapelock' ),
			// 3.8: where bots hit the site, and the points to lock.
			'attacks'   => __( 'Attacks', 'scrapelock' ),
			// 3.12: every request the site answered (PNCP_Admin_Traffic).
			'traffic'   => __( 'Traffic', 'scrapelock' ),
			'hardening' => __( 'Vulnerable points', 'scrapelock' ),
			'lockdown'  => __( 'Lockdown', 'scrapelock' ),
		);
	}

	/**
	 * The current tab.
	 *
	 * @return string
	 */
	private static function current_tab() {
		if ( PNCP_Lockdown::is_locked() ) {
			return 'lockdown'; // Nothing else can be changed while locked.
		}
		// 3.10: aliases (e.g. "vulnerable", "server") and a notice for an unknown tab: PNCP_Admin_Tabs.
		return PNCP_Admin_Tabs::current( self::tabs() )['tab'];
	}

	/* ---------- Fields ---------- */

	/**
	 * Checkbox row.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param string               $key   Key.
	 * @param string               $label Label text.
	 * @param string|array<int, string> $help Help text (optional): a string, or PNCP_Admin_Fields::help( short, more ).
	 */
	private static function checkbox( $s, $key, $label, $help = '' ) {
		$id = 'pncp-' . $key;
		echo '<div class="pncp-field pncp-field--toggle">';
		// 3.5: the requirement (dimmed, never disabled), the risk tag and the default are added around the field.
		printf(
			'<label for="%1$s"><input type="checkbox" class="pncp-toggle" id="%1$s" name="%2$s[%3$s]" value="1"%4$s%5$s%6$s> <span class="pncp-field__label">%7$s</span></label>',
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			checked( ! empty( $s[ $key ] ), true, false ),
			PNCP_Admin_Fields::describedby_attr( $key, (bool) $help ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in describedby_attr().
			PNCP_Admin_Fields::requires_attr( $key, $s ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_attr().
			esc_html( $label )
		);
		echo PNCP_Admin_Fields::risk_tag( $key ) . PNCP_Admin_Fields::default_note( $key, $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
		if ( $help ) {
			echo PNCP_Admin_Fields::description( $id . '-help', $help ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in description().
		}
		echo PNCP_Admin_Fields::requires_note( $key, $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_note().
		echo '</div>';
	}

	/**
	 * Radio group.
	 *
	 * @param array<string, mixed>  $s       Settings.
	 * @param string                $key     Key.
	 * @param string                $legend  Legend.
	 * @param array<string, string> $options value => label.
	 */
	private static function radios( $s, $key, $legend, $options ) {
		// 3.5: the fieldset carries the requirement (none of the radio groups has one today).
		echo '<fieldset' . PNCP_Admin_Fields::requires_attr( $key, $s ) . '><legend class="screen-reader-text">' . esc_html( $legend ) . '</legend>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_attr().
		foreach ( $options as $value => $label ) {
			$id    = 'pncp-' . $key . '-' . $value;
			$risky = PNCP_Admin_Fields::is_risky_choice( $key, (string) $value );
			// 3.5: the default choice gets a "Default" badge, a choice that can affect visitors or SEO the risk tag.
			printf(
				'<label for="%1$s"><input type="radio" id="%1$s" name="%2$s[%3$s]" value="%4$s"%5$s%6$s> %7$s%8$s%9$s</label><br>',
				esc_attr( $id ),
				esc_attr( PNCP_OPTION ),
				esc_attr( $key ),
				esc_attr( $value ),
				checked( (string) $s[ $key ], (string) $value, false ),
				$risky ? ' aria-describedby="' . esc_attr( PNCP_Admin_Fields::risk_id( $key, (string) $value ) ) . '"' : '',
				esc_html( $label ),
				PNCP_Admin_Fields::is_default( $key, (string) $value ) ? ' <span class="pncp-tag pncp-tag--default">' . esc_html__( 'Default', 'scrapelock' ) . '</span>' : '',
				$risky ? ' ' . PNCP_Admin_Fields::risk_tag( $key, (string) $value ) : '' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in risk_tag().
			);
		}
		echo '</fieldset>';
		echo PNCP_Admin_Fields::requires_note( $key, $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_note().
	}

	/**
	 * Select.
	 *
	 * @param array<string, mixed>      $s       Settings.
	 * @param string                    $key     Key.
	 * @param array<int|string, string> $options value => label.
	 * @param string|array<int, string> $help    Help text: a string, or PNCP_Admin_Fields::help( short, more ).
	 */
	private static function select( $s, $key, $options, $help = '' ) {
		$id = 'pncp-' . $key;
		printf(
			'<select id="%1$s" name="%2$s[%3$s]"%4$s%5$s>',
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			PNCP_Admin_Fields::describedby_attr( $key, (bool) $help ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in describedby_attr().
			PNCP_Admin_Fields::requires_attr( $key, $s ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_attr().
		);
		foreach ( $options as $value => $label ) {
			// 3.5: options hold no markup, so the default and the risky choices are marked in the text.
			if ( PNCP_Admin_Fields::is_default( $key, (string) $value ) ) {
				/* translators: %s: label of the default choice of a drop-down */
				$label = sprintf( __( '%s (default)', 'scrapelock' ), $label );
			}
			if ( PNCP_Admin_Fields::is_risky_choice( $key, (string) $value ) ) {
				/* translators: %s: label of a choice of a drop-down */
				$label = sprintf( __( '%s (may affect visitors/SEO)', 'scrapelock' ), $label );
			}
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( (string) $s[ $key ], (string) $value, false ), esc_html( $label ) );
		}
		echo '</select>';
		if ( $help ) {
			echo PNCP_Admin_Fields::description( $id . '-help', $help ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in description().
		}
		echo PNCP_Admin_Fields::requires_note( $key, $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_note().
	}

	/**
	 * Number field with label and help text.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param string               $key   Key.
	 * @param string               $label Label text.
	 * @param string|array<int, string> $help Help text: a string, or PNCP_Admin_Fields::help( short, more ).
	 */
	private static function number( $s, $key, $label, $help = '' ) {
		$range = PNCP_Options::int_ranges()[ $key ];
		$id    = 'pncp-' . $key;
		echo '<div class="pncp-field pncp-field--number">';
		// 3.5: the requirement, the risk tag and the default are added around the field.
		printf(
			'<p><label for="%1$s">%2$s</label> <input type="number" class="small-text" id="%1$s" name="%3$s[%4$s]" value="%5$d" min="%6$d"%7$s%8$s%9$s>%10$s</p>',
			esc_attr( $id ),
			esc_html( $label ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			(int) $s[ $key ],
			(int) $range[0],
			PHP_INT_MAX === $range[1] ? '' : ' max="' . (int) $range[1] . '"',
			PNCP_Admin_Fields::describedby_attr( $key, (bool) $help ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in describedby_attr().
			PNCP_Admin_Fields::requires_attr( $key, $s ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_attr().
			PNCP_Admin_Fields::risk_tag( $key ) . PNCP_Admin_Fields::default_note( $key, $s ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
		);
		if ( $help ) {
			echo PNCP_Admin_Fields::description( $id . '-help', $help ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in description().
		}
		echo PNCP_Admin_Fields::requires_note( $key, $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_note().
		echo '</div>';
	}

	/**
	 * Textarea with label.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param string               $key   Key.
	 * @param string               $label Label.
	 * @param string|array<int, string> $help Help text: a string, or PNCP_Admin_Fields::help( short, more ).
	 * @param int                  $rows  Rows.
	 * @param bool                 $fold  Long list: shown folded, with the number of entries.
	 */
	/**
	 * A single-line password field (for a secret). The value is not shown as plain text.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param string               $key   Option key.
	 * @param string               $label Label.
	 * @param string|array<int, string> $help Help text: a string, or PNCP_Admin_Fields::help( short, more ).
	 */
	private static function password( $s, $key, $label, $help = '' ) {
		$id = 'pncp-' . $key;
		echo '<div class="pncp-field">';
		printf( '<p><label for="%s">%s</label></p>', esc_attr( $id ), esc_html( $label ) );
		// The saved secret is never printed into the page (page source, browser password managers): the field
		// stays empty, an empty field keeps it, and a box clears it.
		$saved = '' !== (string) ( isset( $s[ $key ] ) ? $s[ $key ] : '' );
		printf(
			'<input type="password" class="regular-text" id="%1$s" name="%2$s[%3$s]" value="" placeholder="%4$s" autocomplete="off" spellcheck="false"%5$s>',
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			esc_attr( $saved ? __( 'Saved. Leave empty to keep it.', 'scrapelock' ) : '' ),
			$help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : ''
		);
		if ( $saved ) {
			printf(
				'<p><label><input type="checkbox" name="%1$s[%2$s_clear]" value="1"> %3$s</label></p>',
				esc_attr( PNCP_OPTION ),
				esc_attr( $key ),
				esc_html__( 'Remove the saved secret', 'scrapelock' )
			);
		}
		if ( $help ) {
			echo PNCP_Admin_Fields::description( $id . '-help', $help ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in description().
		}
		echo '</div>';
	}

	private static function textarea( $s, $key, $label, $help = '', $rows = 4, $fold = false ) {
		$id = 'pncp-' . $key;
		echo '<div class="pncp-field pncp-field--text">';
		// 3.11: a long list shows "N entries", a preview and an "Edit" button (PNCP_Admin_Lists) instead of a fold.
		$list = PNCP_Admin_Lists::folds( $key, count( PNCP_Options::parse_list( (string) $s[ $key ] ) ), $fold );
		if ( $list ) {
			$fold = false;
			PNCP_Admin_Lists::open( $key, $label, (string) $s[ $key ], isset( PNCP_Admin_Fields::risky()[ $key ] ) ? '<span class="pncp-tag pncp-tag--risk">' . esc_html__( 'May affect visitors/SEO', 'scrapelock' ) . '</span>' : '' );
		}
		if ( $fold ) {
			$count = count( PNCP_Options::parse_list( (string) $s[ $key ] ) );
			// 3.5: a folded list shows its risk tag on the summary too (without the id, which the tag below has).
			$risk = isset( PNCP_Admin_Fields::risky()[ $key ] ) ? ' ' . PNCP_Admin_Fields::risk_icon() : '';
			printf(
				'<details class="pncp-fold"><summary>%s <span class="pncp-badge">%s</span>%s</summary>',
				esc_html( $label ),
				esc_html( sprintf( /* translators: %s: number of entries */ _n( '%s entry', '%s entries', $count, 'scrapelock' ), number_format_i18n( $count ) ) ),
				$risk // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in risk_icon().
			);
		}
		printf( '<p><label for="%s"%s>%s</label></p>', esc_attr( $id ), $fold || $list ? ' class="screen-reader-text"' : '', esc_html( $label ) );
		echo PNCP_Admin_Fields::risk_tag( $key ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in risk_tag().
		printf(
			'<textarea class="large-text code" rows="%1$d" id="%2$s" name="%3$s[%4$s]"%5$s%6$s>%7$s</textarea>',
			(int) $rows,
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			PNCP_Admin_Fields::describedby_attr( $key, (bool) $help ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in describedby_attr().
			PNCP_Admin_Fields::requires_attr( $key, $s ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_attr().
			esc_textarea( (string) $s[ $key ] )
		);
		if ( $help ) {
			echo PNCP_Admin_Fields::description( $id . '-help', $help ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in description().
		}
		echo PNCP_Admin_Fields::requires_note( $key, $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_note().
		if ( $list ) {
			PNCP_Admin_Lists::close();
		}
		echo $fold ? '</details></div>' : '</div>';
	}

	/**
	 * Opens a settings card (a row of the form table).
	 *
	 * @param string $id    Section id (for the quick links).
	 * @param string $title Title.
	 */
	private static function row_open( $id, $title ) {
		if ( PNCP_Admin_Accordion::active() ) {
			PNCP_Admin_Accordion::part_open( $id, $title ); // 3.11: a folded part of the accordion.
			return;
		}
		printf( '<tr id="pncp-sec-%s"><th scope="row">%s</th><td>', esc_attr( $id ), esc_html( $title ) );
	}

	/**
	 * Closes a settings card.
	 */
	private static function row_close() {
		if ( PNCP_Admin_Accordion::active() ) {
			PNCP_Admin_Accordion::part_close();
			return;
		}
		echo '</td></tr>';
	}

	/**
	 * A heading between two parts of one settings form (e.g. "Bots" and "Limits" on the Bots and limits tab).
	 * Closes the settings table of the part before and opens the table of the next part: the fields stay in
	 * the same form.
	 *
	 * @param string $id    Part id (the heading's anchor is pncp-group-<id>).
	 * @param string $title Heading.
	 * @param string $intro One sentence about what the part holds.
	 */
	private static function group_heading( $id, $title, $intro ) {
		$accordion = PNCP_Admin_Accordion::active(); // 3.11: the parts are <details> of their own, no table between them.
		echo $accordion ? '' : '</table>';
		printf( '<h2 class="pncp-group-title" id="pncp-group-%s">%s</h2>', esc_attr( $id ), esc_html( $title ) );
		printf( '<p class="description pncp-group-intro">%s</p>', esc_html( $intro ) );
		echo $accordion ? '' : '<table class="form-table" role="presentation">';
	}

	/**
	 * Whether the folded "Network and CDN" part of the Bots and limits tab opens on its own: something in it
	 * needs a look (an insecure 1.4 setting, a CDN that hides every visitor, an early or pre-cache check that
	 * is on but not running), or the administrator just used one of its one-click fixes.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return bool
	 */
	private static function network_needs_attention( $s ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only decides whether a part is shown open.
		$message = isset( $_GET['pncp_message'] ) ? sanitize_key( wp_unslash( $_GET['pncp_message'] ) ) : '';
		return ! empty( $s['trust_any_proxy'] )
			|| in_array( $message, array( 'cf_ip', 'bunny_ip', 'bunny_ip_failed' ), true )
			|| '' !== PNCP_Ip::cdn_hides_visitors()
			|| ( ! empty( $s['early_mode'] ) && ! PNCP_Early::installed() )
			// 3.11: every setting of this part that the status badges show as "set but not active" (PNCP_Status_State),
			// "Only through the CDN" without its secret included; not while protection itself is off.
			|| ( ! empty( $s['enabled'] ) && ! is_multisite() && PNCP_Status_State::SET === PNCP_Status_State::precheck( $s )['state'] )
			|| ( ! empty( $s['enabled'] ) && PNCP_Status_State::SET === PNCP_Status_State::cdn_only( $s )['state'] );
	}

	/**
	 * One line with the state of the "Network and CDN" part, shown next to its heading while it is folded.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	private static function network_summary( $s ) {
		// 3.11: three states (PNCP_Status_State): "set but not active: <reason>" instead of "off" for a setting that is
		// on but not in effect (before: "Pre-cache check: off" with the setting on, "Only through the CDN: off" without
		// the secret), and "on" only when it runs (the early check is on only with its file in place).
		return sprintf(
			/* translators: 1: name of an HTTP header (e.g. REMOTE_ADDR), 2: "on", "off" or "set but not active: <reason>" (early check), 3: the same for the pre-cache check, 4: the same for "only through the CDN" */
			__( 'Real visitor IP: %1$s · Early check: %2$s · Pre-cache check: %3$s · Only through the CDN: %4$s', 'scrapelock' ),
			PNCP_Setting_Labels::header_name( (string) $s['ip_header'] ),
			PNCP_Status_State::inline_text( PNCP_Status_State::early( $s ) ),
			PNCP_Status_State::inline_text( PNCP_Status_State::precheck( $s ) ),
			PNCP_Status_State::inline_text( PNCP_Status_State::cdn_only( $s ) )
		);
	}

	/**
	 * Quick links to the sections of a long tab.
	 *
	 * @param array<string, string> $sections id => label.
	 */
	private static function section_nav( $sections ) {
		echo '<nav class="pncp-section-nav" aria-label="' . esc_attr__( 'Sections of this tab', 'scrapelock' ) . '"><ul>';
		foreach ( $sections as $id => $label ) {
			printf( '<li><a href="#pncp-sec-%s">%s</a></li>', esc_attr( $id ), esc_html( $label ) );
		}
		echo '</ul></nav>';
	}

	/**
	 * Status of the protection at the top of every tab.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_status_bar( $s ) {
		$emergency = PNCP_Options::emergency_until();
		$items     = self::status_items( $s );
		echo '<ul class="pncp-status-bar" aria-label="' . esc_attr__( 'Protection status', 'scrapelock' ) . '">';
		if ( ! empty( $s['enabled'] ) && PNCP_Options::monitoring( $s ) ) {
			printf(
				'<li class="pncp-pill pncp-pill--alert pncp-pill--monitor"><a href="%1$s">%2$s</a></li>',
				esc_url( PNCP_Status::settings_url( array( 'tab' => 'bots' ) ) . '#pncp-sec-monitor' ),
				esc_html( self::monitor_label( $s ) )
			);
		}
		if ( $emergency ) {
			echo '<li class="pncp-pill pncp-pill--alert">' . esc_html__( 'Emergency Mode', 'scrapelock' ) . '</li>';
		}
		foreach ( $items as $item ) {
			if ( $item[0] ) {
				printf(
					'<li class="pncp-pill pncp-pill--on" data-pncp-state="on"><span class="screen-reader-text">%1$s </span>%2$s</li>',
					esc_html__( 'On:', 'scrapelock' ),
					esc_html( $item[1] )
				);
				continue;
			}
			// 3.11: on in the settings, not in effect: the reason is on the pill, which links to the setting.
			if ( PNCP_Status_State::SET === $item[3]['state'] ) {
				printf(
					'<li class="pncp-pill pncp-pill--set" data-pncp-state="set"><a href="%1$s">%2$s: <span class="pncp-pill__reason">%3$s</span></a></li>',
					esc_url( PNCP_Status::settings_url( array( 'tab' => $item[2][0] ) ) . '#' . $item[2][1] ),
					esc_html( $item[1] ),
					esc_html( PNCP_Status_State::text( $item[3] ) )
				);
				continue;
			}
			printf(
				'<li class="pncp-pill pncp-pill--off" data-pncp-state="off"><a href="%1$s"><span class="screen-reader-text">%2$s </span>%3$s</a></li>',
				esc_url( PNCP_Status::settings_url( array( 'tab' => $item[2][0] ) ) . '#' . $item[2][1] ),
				esc_html__( 'Off:', 'scrapelock' ),
				esc_html( $item[1] )
			);
		}
		echo '</ul>';
	}

	/**
	 * The protection layers shown in the status bar: on or off, label, and where the setting is.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return array<int, array{0: bool, 1: string, 2: string[], 3: array{state:string, reason:string}}>
	 */
	private static function status_items( $s ) {
		// 3.5: the third element is where the setting is (tab and anchor): an "Off" pill links to it.
		// 3.11: the fourth is the state in three (PNCP_Status_State): on, set but not active (with the reason), off.
		// The first stays "in effect now", for the count of layers on.
		$items = array(
			array( PNCP_Status_State::protection( $s ), __( 'Protection', 'scrapelock' ), array( 'general', 'pncp-enabled' ) ),
			array( PNCP_Status_State::early( $s ), __( 'Early check', 'scrapelock' ), array( 'bots', 'pncp-sec-early' ) ),
			// The row, not the checkbox: the checkbox is not there on multisite.
			array( PNCP_Status_State::precheck( $s ), __( 'Pre-cache check', 'scrapelock' ), array( 'bots', 'pncp-sec-early' ) ),
			array( PNCP_Status_State::setting( $s, ! empty( $s['human_check'] ) ), __( 'Human check', 'scrapelock' ), array( 'bots', 'pncp-sec-human' ) ),
			array( PNCP_Status_State::ai_verified( $s ), __( 'AI bots verified', 'scrapelock' ), array( 'bots', 'pncp-sec-ai' ) ),
			array( PNCP_Status_State::setting( $s, ! empty( $s['block_headless'] ) ), __( 'Headless browsers', 'scrapelock' ), array( 'bots', 'pncp-block_headless' ) ),
			array( PNCP_Status_State::countries( $s ), __( 'Countries', 'scrapelock' ), array( 'bots', 'pncp-sec-countries' ) ),
		);
		// 3.11: "Only through the CDN" once it is set (a pill while it is off would only add noise for most sites).
		if ( ! empty( $s['cdn_only'] ) ) {
			$items[] = array( PNCP_Status_State::cdn_only( $s ), __( 'Only through the CDN', 'scrapelock' ), array( 'bots', 'pncp-sec-ip' ) ); // Its row in "Network and CDN".
		}
		foreach ( $items as $i => $item ) {
			$items[ $i ] = array( PNCP_Status_State::ON === $item[0]['state'], $item[1], $item[2], $item[0] );
		}
		return $items;
	}

	/**
	 * "Monitor only: nothing is blocked", with the day blocking starts on its own during the first-week monitoring.
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	public static function monitor_label( $s ) {
		if ( ! empty( $s['monitor_until'] ) ) {
			return sprintf(
				/* translators: %s: date */
				__( 'Monitor only: nothing is blocked until %s', 'scrapelock' ),
				wp_date( get_option( 'date_format' ), (int) $s['monitor_until'] )
			);
		}
		return __( 'Monitor only: nothing is blocked', 'scrapelock' );
	}

	/**
	 * Country of this request and state of the database (inside the "Countries" card).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_geo_status( $s ) {
		$status  = PNCP_Geo::status();
		$country = PNCP_Geo::country( PNCP_Ip::client_ip() );
		echo '<p class="description pncp-geo-status">';
		echo esc_html__( 'Country of this request:', 'scrapelock' ) . ' <code>' . esc_html( '' !== $country ? $country : '—' ) . '</code><br>';
		if ( $status['updated'] ) {
			echo esc_html(
				sprintf(
					/* translators: 1: number of IPv4 ranges, 2: number of IPv6 ranges, 3: month of the data, 4: date */
					__( 'Country database: %1$s IPv4 and %2$s IPv6 ranges, data of %3$s, downloaded %4$s.', 'scrapelock' ),
					number_format_i18n( $status['v4'] ),
					number_format_i18n( $status['v6'] ),
					$status['month'],
					wp_date( get_option( 'date_format' ), $status['updated'] )
				)
			);
		} elseif ( ! empty( $s['geo_db'] ) ) {
			esc_html_e( 'Country database: not downloaded yet. Use “Download now” at the bottom of this tab.', 'scrapelock' );
		} else {
			esc_html_e( 'Country database: off. Without it, Cloudflare or Bunny, the country lists do nothing.', 'scrapelock' );
		}
		echo '</p><p class="description pncp-geo-credit">';
		printf(
			/* translators: %s: link to DB-IP */
			esc_html__( 'IP geolocation by %s (CC BY 4.0).', 'scrapelock' ),
			'<a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a>'
		);
		echo '</p>';
	}

	/**
	 * Opens a tab's settings form.
	 *
	 * @param string $section Tab.
	 */
	private static function form_open( $section ) {
		self::$form_section = $section;
		// 3.5: data-pncp-watch: the script shows "Unsaved changes" and warns before leaving with changes.
		echo '<form method="post" action="options.php" class="pncp-settings-form" data-pncp-watch="1">';
		settings_fields( self::GROUP );
		printf( '<input type="hidden" name="%s[_sections][]" value="%s">', esc_attr( PNCP_OPTION ), esc_attr( $section ) );
		echo PNCP_Admin_Accordion::active() ? '' : '<table class="form-table" role="presentation">';
	}

	/**
	 * Closes the settings form.
	 *
	 * @param bool $table Whether a settings table is still open (false when the form ends with a folded part).
	 */
	private static function form_close( $table = true ) {
		if ( $table ) {
			echo '</table>';
		}
		// 3.5: "Unsaved changes" next to the button, shown by the script while the form differs from the page load.
		echo '<p class="submit">';
		submit_button( __( 'Save changes', 'scrapelock' ), 'primary', 'submit', false );
		echo ' <span class="pncp-unsaved" role="status" hidden>' . esc_html__( 'Unsaved changes', 'scrapelock' ) . '</span></p>';
		if ( isset( PNCP_Settings_Io::tab_names()[ self::$form_section ] ) ) {
			// A link, not a button: it opens a confirmation that lists what would change (render_reset_confirm()).
			printf(
				'<p class="pncp-reset-tab"><a href="%1$s">%2$s</a></p>',
				esc_url(
					PNCP_Status::settings_url(
						array(
							'tab'        => self::$form_section,
							'pncp_reset' => self::$form_section,
						)
					)
				),
				esc_html__( 'Reset this tab to defaults…', 'scrapelock' )
			);
		}
		echo '</form>';
	}

	/**
	 * admin-post form with nonce (for actions).
	 *
	 * @param string $action  Action.
	 * @param string $nonce   Nonce action.
	 * @param string $classes CSS classes.
	 */
	private static function action_form_open( $action, $nonce, $classes = '' ) {
		printf( '<form method="post" action="%s" class="%s">', esc_url( admin_url( 'admin-post.php' ) ), esc_attr( $classes ) );
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( $action ) );
		self::$action_form = $action;
		self::nonce_field( $nonce );
	}

	/**
	 * 3.4.3: wp_nonce_field() without its id="_wpnonce", which repeated on every action form of a page. The
	 * field name and the referer field stay the same, so the handlers check the nonce as before.
	 *
	 * @param string $nonce Nonce action.
	 */
	private static function nonce_field( $nonce ) {
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( $nonce, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
	}

	/**
	 * 3.4.3: a unique id for the submit button of the action form opened last: pncp-submit-<action>, then
	 * pncp-submit-<action>-2 and so on. The button keeps the name "submit".
	 *
	 * @return array Attributes for submit_button().
	 */
	private static function submit_attrs() {
		$key = '' !== self::$action_form ? self::$action_form : 'form';
		$n   = isset( self::$submit_ids[ $key ] ) ? self::$submit_ids[ $key ] + 1 : 1;

		self::$submit_ids[ $key ] = $n;
		return array( 'id' => 'pncp-submit-' . str_replace( '_', '-', $key ) . ( $n > 1 ? '-' . $n : '' ) );
	}

	/* ---------- Page ---------- */

	/**
	 * The settings page.
	 */
	public static function render() {
		if ( ! PNCP_Lockdown::can( 'manage_options' ) ) {
			return;
		}
		$tab    = self::current_tab();
		$locked = PNCP_Lockdown::is_locked();
		$stored = PNCP_Options::stored();
		// Icons of the tabs (decorative: the label stays the accessible name).
		$icons = array(
			'general'   => 'visibility',
			'bots'      => 'shield',
			'content'   => 'rss',
			'images'    => 'format-image',
			'rules'     => 'editor-code',
			'log'       => 'chart-bar',
			'attacks'   => 'warning',
			'traffic'   => 'chart-line',
			'hardening' => 'shield-alt',
			'lockdown'  => $locked ? 'lock' : 'unlock',
		);
		?>
		<div class="wrap pncp-admin pncp-admin--<?php echo esc_attr( $tab ); ?><?php echo $locked ? ' is-site-locked' : ''; ?>">
			<?php self::render_header( $stored, $locked ); ?>
			<hr class="wp-header-end">
			<?php
			if ( ! $locked ) {
				PNCP_Admin_Tabs::render_notice( self::tabs() ); // 3.10: unknown ?tab= in the address.
			}
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays the confirmation.
			if ( isset( $_GET['pncp_confirm'] ) && PNCP_Status::is_enabled() && ! $locked ) {
				self::render_disable_confirm();
			}
			if ( ! $locked ) {
				self::render_kpis( $stored );
				self::render_status_bar( $stored );
			}
			?>
			<?php self::render_tab_nav( $tab, $locked, $icons ); // 3.11: the tabs in four groups. ?>
			<div class="pncp-panel">
			<?php
			if ( 'lockdown' === $tab ) {
				PNCP_Lockdown::render_tab();
			} else {
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays the confirmation.
				if ( isset( $_GET['pncp_reset'] ) && sanitize_key( wp_unslash( $_GET['pncp_reset'] ) ) === $tab ) {
					self::render_reset_confirm( $tab );
				}
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays the confirmation.
				if ( 'general' === $tab && isset( $_GET['pncp_import'] ) ) {
					self::render_import_confirm();
				}
				$method = 'tab_' . $tab;
				self::$method( $stored );
			}
			?>
			</div>
		</div>
		<?php
	}

	/**
	 * 3.11: the tab bar in two levels: the groups (Content, Bots & limits, Security, Records), each with its
	 * tabs. Every tab keeps its address (?tab=…) and its markup (nav-tab, nav-tab-active, aria-current).
	 *
	 * @param string                $tab    Current tab.
	 * @param bool                  $locked Whether the site is locked (only Lockdown can be opened).
	 * @param array<string, string> $icons  Tab key => dashicon name.
	 */
	private static function render_tab_nav( $tab, $locked, $icons ) {
		echo '<nav class="nav-tab-wrapper pncp-tabs pncp-tabs--grouped" aria-label="' . esc_attr__( 'Settings sections', 'scrapelock' ) . '">';
		foreach ( PNCP_Admin_Tabs::grouped( self::tabs() ) as $group => $data ) {
			$current = isset( $data['tabs'][ $tab ] );
			printf(
				'<div class="pncp-tab-group pncp-tab-group--%1$s%2$s" role="group" aria-labelledby="pncp-tab-group-%1$s"><span class="pncp-tab-group__title" id="pncp-tab-group-%1$s">%3$s</span><span class="pncp-tab-group__tabs">',
				esc_attr( $group ),
				$current ? ' is-current' : '',
				esc_html( $data['label'] )
			);
			foreach ( $data['tabs'] as $key => $label ) {
				$icon = '<span class="dashicons dashicons-' . esc_attr( isset( $icons[ $key ] ) ? $icons[ $key ] : 'admin-generic' ) . '" aria-hidden="true"></span> ';
				if ( $locked && 'lockdown' !== $key ) {
					printf(
						'<span class="nav-tab pncp-tab-locked" title="%1$s">%2$s%3$s</span>',
						esc_attr__( 'Locked: unlock the site to change the settings', 'scrapelock' ),
						$icon, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
						esc_html( $label )
					);
					continue;
				}
				printf(
					'<a href="%1$s" class="nav-tab%2$s%3$s"%4$s>%5$s%6$s</a>',
					esc_url( PNCP_Status::settings_url( array( 'tab' => $key ) ) ),
					$tab === $key ? ' nav-tab-active' : '',
					'lockdown' === $key ? ' pncp-tab-lockdown' : '',
					$tab === $key ? ' aria-current="page"' : '',
					$icon, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
					esc_html( $label )
				);
			}
			echo '</span></div>';
		}
		echo '</nav>';
	}

	/**
	 * Page header: product name and version, the state of the protection in one word, and the main actions.
	 *
	 * @param array<string, mixed> $s      Settings.
	 * @param bool                 $locked Whether the site is locked.
	 */
	private static function render_header( $s, $locked ) {
		if ( $locked ) {
			$state = array( 'locked', 'lock', __( 'Site locked', 'scrapelock' ) );
		} elseif ( empty( $s['enabled'] ) ) {
			$state = array( 'off', 'warning', __( 'Protection off', 'scrapelock' ) );
		} elseif ( PNCP_Options::emergency_until() ) {
			$state = array( 'emergency', 'warning', __( 'Emergency Mode', 'scrapelock' ) );
		} elseif ( PNCP_Options::monitoring( $s ) ) {
			$state = array( 'monitor', 'visibility', __( 'Monitor only', 'scrapelock' ) );
		} else {
			$state = array( 'on', 'yes-alt', __( 'Protected', 'scrapelock' ) );
		}
		?>
		<header class="pncp-header">
			<div class="pncp-header__brand">
				<span class="pncp-logo" aria-hidden="true">
					<svg viewBox="0 0 24 24" width="28" height="28" focusable="false"><path fill="currentColor" d="M12 1.5 3.5 4.8v6.1c0 5.3 3.6 10.2 8.5 11.6 4.9-1.4 8.5-6.3 8.5-11.6V4.8L12 1.5Zm0 5.2a3 3 0 0 1 3 3V11h.6c.5 0 .9.4.9.9v4.2c0 .5-.4.9-.9.9H8.4a.9.9 0 0 1-.9-.9v-4.2c0-.5.4-.9.9-.9H9V9.7a3 3 0 0 1 3-3Zm0 1.6c-.8 0-1.4.6-1.4 1.4V11h2.8V9.7c0-.8-.6-1.4-1.4-1.4Z"/></svg>
				</span>
				<div class="pncp-header__text">
					<h1 class="pncp-title"><?php esc_html_e( 'ScrapeLock', 'scrapelock' ); ?> <span class="pncp-version"><?php echo esc_html( PNCP_VERSION ); ?></span></h1>
					<p class="pncp-header__tagline"><?php esc_html_e( 'Content, scraping and site protection', 'scrapelock' ); ?></p>
				</div>
			</div>
			<p class="pncp-header__state">
				<span class="pncp-state-badge pncp-state-badge--<?php echo esc_attr( $state[0] ); ?>">
					<span class="dashicons dashicons-<?php echo esc_attr( $state[1] ); ?>" aria-hidden="true"></span>
					<span class="screen-reader-text"><?php esc_html_e( 'Status:', 'scrapelock' ); ?> </span><?php echo esc_html( $state[2] ); ?>
				</span>
			</p>
			<div class="pncp-header__actions">
				<?php if ( $locked ) : ?>
					<a class="button button-primary" href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => 'lockdown' ) ) ); ?>"><?php esc_html_e( 'Lockdown', 'scrapelock' ); ?></a>
				<?php elseif ( empty( $s['enabled'] ) ) : ?>
					<?php self::action_form_open( PNCP_Status::ACTION, PNCP_Status::ACTION, 'pncp-inline-form' ); ?>
						<input type="hidden" name="state" value="on">
						<button type="submit" class="button button-primary"><?php esc_html_e( 'Enable protection', 'scrapelock' ); ?></button>
					</form>
				<?php else : ?>
					<a class="button" href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => 'log' ) ) . '#pncp-tester' ); ?>"><?php esc_html_e( 'Check a request', 'scrapelock' ); ?></a>
					<a class="button button-primary" href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => 'log' ) ) ); ?>"><?php esc_html_e( 'View log', 'scrapelock' ); ?></a>
					<a class="pncp-header__off" href="<?php echo esc_url( PNCP_Status::disable_url() ); ?>"><?php esc_html_e( 'Disable…', 'scrapelock' ); ?></a>
				<?php endif; ?>
			</div>
		</header>
		<?php
	}

	/**
	 * Four figures under the header: blocked requests in the last 24 hours, IPs blocked now, protection layers
	 * on and the preset. The 24-hour figure is the cached summary of the Log tab (counted at most every 5 minutes).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_kpis( $s ) {
		$monitor = ! empty( $s['enabled'] ) && PNCP_Options::monitoring( $s );
		$summary = PNCP_Log::summary_cached( 24, $monitor ? 'monitor' : 'blocked' );
		$total   = isset( $summary['value']['total'] ) ? (int) $summary['value']['total'] : 0;
		$items   = self::status_items( $s );
		$on      = count( array_filter( array_column( $items, 0 ) ) );
		$profile = PNCP_Options::current_profile( $s );
		$names   = array(
			'balanced' => __( 'Balanced', 'scrapelock' ),
			'strict'   => __( 'Strict', 'scrapelock' ),
			'maximum'  => __( 'Maximum', 'scrapelock' ),
		);
		$kpis    = array(
			array(
				$monitor ? __( 'Would block, 24 h', 'scrapelock' ) : __( 'Blocked, 24 h', 'scrapelock' ),
				number_format_i18n( $total ),
				PNCP_Status::log_url( $monitor ? 'monitor' : 'blocked' ),
				$monitor ? 'warn' : 'accent',
			),
			array( __( 'IPs blocked now', 'scrapelock' ), number_format_i18n( PNCP_Log::count_bans() ), PNCP_Status::settings_url( array( 'tab' => 'log' ) ) . '#pncp-sec-bans', 'neutral' ),
			array(
				__( 'Protection layers on', 'scrapelock' ),
				/* translators: 1: layers on, 2: all layers */
				sprintf( __( '%1$s of %2$s', 'scrapelock' ), number_format_i18n( $on ), number_format_i18n( count( $items ) ) ),
				'',
				count( $items ) === $on ? 'good' : 'neutral',
			),
			array( __( 'Preset', 'scrapelock' ), isset( $names[ $profile ] ) ? $names[ $profile ] : __( 'Custom', 'scrapelock' ), PNCP_Status::settings_url() . '#pncp-profiles-title', 'neutral' ),
		);
		echo '<ul class="pncp-kpis" aria-label="' . esc_attr__( 'Overview', 'scrapelock' ) . '">';
		foreach ( $kpis as $kpi ) {
			$value = '<span class="pncp-kpi__value">' . esc_html( $kpi[1] ) . '</span>';
			printf(
				'<li class="pncp-kpi pncp-kpi--%1$s"><span class="pncp-kpi__label">%2$s</span>%3$s</li>',
				esc_attr( $kpi[3] ),
				esc_html( $kpi[0] ),
				'' !== $kpi[2] ? '<a class="pncp-kpi__link" href="' . esc_url( $kpi[2] ) . '">' . $value . '</a>' : $value // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
			);
		}
		echo '</ul>';
	}

	/**
	 * Disable confirmation (from the admin bar or the widget).
	 */
	private static function render_disable_confirm() {
		?>
		<div class="notice notice-warning pncp-confirm">
			<p><strong><?php esc_html_e( 'Disable protection on the whole site?', 'scrapelock' ); ?></strong></p>
			<p><?php esc_html_e( 'Until you enable it again, bots and visitors will be able to copy texts, images and feeds freely.', 'scrapelock' ); ?></p>
			<?php self::action_form_open( PNCP_Status::ACTION, PNCP_Status::ACTION ); ?>
				<input type="hidden" name="state" value="off">
				<p>
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Yes, disable', 'scrapelock' ); ?></button>
					<a class="button" href="<?php echo esc_url( PNCP_Status::settings_url() ); ?>"><?php esc_html_e( 'Cancel', 'scrapelock' ); ?></a>
				</p>
			</form>
		</div>
		<?php
	}

	/**
	 * "On the page" tab: status, profiles, Emergency Mode and what is blocked in the browser.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_general( $s ) {
		PNCP_Wizard::render_panel(); // 3.11: "For my site".
		self::render_profiles( $s );
		self::form_open( 'general' );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Status', 'scrapelock' ); ?></th>
			<td><?php self::checkbox( $s, 'enabled', __( 'Protection is active', 'scrapelock' ) ); ?></td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Where it applies', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'scope_posts', __( 'Posts', 'scrapelock' ) );
				self::checkbox( $s, 'scope_pages', __( 'Pages', 'scrapelock' ) );
				self::checkbox( $s, 'scope_home', __( 'Home, categories, search and archives', 'scrapelock' ) );
				self::checkbox( $s, 'scope_products', __( 'WooCommerce products', 'scrapelock' ) );
				self::checkbox( $s, 'skip_woo_pages', __( 'Do not apply on cart, checkout and “My account”', 'scrapelock' ), __( 'Recommended: customers must be able to copy order numbers and coupon codes.', 'scrapelock' ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="pncp-excluded_ids"><?php esc_html_e( 'Exceptions', 'scrapelock' ); ?></label></th>
			<td>
				<input type="text" class="regular-text" id="pncp-excluded_ids" name="<?php echo esc_attr( PNCP_OPTION ); ?>[excluded_ids]" value="<?php echo esc_attr( $s['excluded_ids'] ); ?>" aria-describedby="pncp-excluded_ids-help" inputmode="numeric">
				<?php echo PNCP_Admin_Fields::description( 'pncp-excluded_ids-help', PNCP_Admin_Fields::help( __( 'Comma-separated page or post IDs, e.g. 12, 45.', 'scrapelock' ), __( 'For a single piece of text (phone, email, code), give it the CSS class pncp-allow.', 'scrapelock' ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'What is blocked', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'block_selection', __( 'Text selection with the mouse or finger', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Not recommended: it breaks read-aloud, translation and copying with the source.', 'scrapelock' ), __( 'It also stops visitors who select text to have it read aloud (select-to-speak, screen readers), translated or looked up, and copying with the source below cannot work. Off in the Balanced preset.', 'scrapelock' ) ) );
				self::checkbox( $s, 'block_context_menu', __( 'Right click', 'scrapelock' ) );
				self::checkbox( $s, 'block_shortcuts', __( 'Shortcuts Ctrl/Cmd + A, C, X, S, U', 'scrapelock' ), __( 'Keyboard navigation (Tab, arrows, Enter) is never affected.', 'scrapelock' ) );
				self::checkbox( $s, 'block_devtools', __( 'Developer tools shortcuts (F12, Ctrl+Shift+I/J/C/K, Cmd+Opt+I/J/C/U)', 'scrapelock' ), __( 'Cosmetic: blocks only the shortcuts; DevTools is not detected or broken.', 'scrapelock' ) );
				self::checkbox( $s, 'block_image_drag', __( 'Dragging images and “Save image” with a long press on mobile', 'scrapelock' ) );
				self::checkbox( $s, 'block_text_drag', __( 'Dragging selected text to another window', 'scrapelock' ) );
				self::checkbox( $s, 'blur_on_capture', __( 'Blur the page when Print Screen or a screenshot shortcut is pressed', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Catches only the shortcuts the browser sees.', 'scrapelock' ), __( 'Print Screen, Win+Shift+S and Cmd+Shift+3/4/5. It does not stop tools outside the browser or a photo taken with a phone.', 'scrapelock' ) ) );
				?>
			</td>
		</tr>
		<tr id="pncp-readers">
			<th scope="row"><?php esc_html_e( 'Members and readers', 'scrapelock' ); ?></th>
			<td>
				<?php echo PNCP_Admin_Fields::para( __( 'Screenshots cannot be stopped; these options trace copies back to an account.', 'scrapelock' ), __( 'No web page can stop a screenshot, a screen recording or a photo of the screen. These options make copies traceable instead, and stop accounts that are shared or used to copy everything. Staff who are exempt (“Who is excluded”) never see or trigger them.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
				<?php
				self::checkbox( $s, 'user_mark', __( 'Show who is reading over protected pages', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'A faint user name and time over the page, visible on every screenshot.', 'scrapelock' ), __( 'A faint line repeated over the page with the account\'s user name and the date and time, so every screenshot, recording or photo shows whose account it came from. It never gets in the way of clicks, taps or selecting text, and appears again if it is removed.', 'scrapelock' ) ) );
				self::checkbox( $s, 'user_mark_guests', __( 'Also for visitors who are not signed in (their IP address and the time)', 'scrapelock' ), __( 'Loaded by the page, so caching still works; search engines do not see it.', 'scrapelock' ) );
				self::number( $s, 'user_mark_opacity', __( 'How visible (percent):', 'scrapelock' ), __( '10 is faint but readable on a screenshot.', 'scrapelock' ) );
				self::checkbox( $s, 'text_trace', __( 'Hide an invisible trace of the account in the text', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Invisible characters per account; Log → “Find whose copy this is” reads them.', 'scrapelock' ), __( 'For signed-in accounts: invisible characters, different for each account, are placed in the text of protected pages. When the text turns up somewhere else, paste it under Log → “Find whose copy this is” to see the account and when. Visitors who are not signed in get the text without a trace.', 'scrapelock' ) ) );
				self::number( $s, 'rate_limit_account', __( 'Pages per minute per signed-in account (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Counts one account across all its IP addresses. For example 30.', 'scrapelock' ), __( 'The other limits count per IP address; a member could run a script from many addresses with one account.', 'scrapelock' ) ) );
				self::checkbox( $s, 'shared_alert', __( 'Email me when one account is used from several addresses at once', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Counted over 10 minutes; at most one alert per account a day.', 'scrapelock' ), __( 'Mobile phones change address often, so there is one alert at most per account a day.', 'scrapelock' ) ) );
				self::number( $s, 'shared_ips', __( 'Addresses at once:', 'scrapelock' ) );
				self::checkbox( $s, 'shared_logout', __( 'Then sign the account out everywhere else', 'scrapelock' ), __( 'The newest session stays; the others must sign in again. Never for staff.', 'scrapelock' ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'When someone copies', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::radios(
					$s,
					'copy_mode',
					__( 'When someone copies', 'scrapelock' ),
					array(
						'block'       => __( 'Block copying', 'scrapelock' ),
						'attribution' => __( 'Allow, with the source and link appended at the end', 'scrapelock' ),
						'allow'       => __( 'Allow normally', 'scrapelock' ),
					)
				);
				self::number( $s, 'attribution_min_chars', __( 'Append the source from this many characters and up:', 'scrapelock' ), __( 'Shorter copies, like a phone number, go without the source. 0 = always.', 'scrapelock' ) );
				?>
				<p class="description"><?php esc_html_e( 'The source option makes sense when text selection is allowed.', 'scrapelock' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Printing', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::radios(
					$s,
					'print_mode',
					__( 'Printing', 'scrapelock' ),
					array(
						'source' => __( 'Allowed, with the page link at the bottom (recommended)', 'scrapelock' ),
						'allow'  => __( 'Allowed normally', 'scrapelock' ),
						'block'  => __( 'Not allowed', 'scrapelock' ),
					)
				);
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="pncp-exempt_cap"><?php esc_html_e( 'Who is excluded', 'scrapelock' ); ?></label></th>
			<td>
				<?php
				self::select(
					$s,
					'exempt_cap',
					array(
						'edit_posts'        => __( 'Logged-in contributors, authors, editors, shop managers and administrators (anyone who can write posts)', 'scrapelock' ),
						'edit_others_posts' => __( 'Logged-in editors and administrators', 'scrapelock' ),
						'manage_options'    => __( 'Administrators only', 'scrapelock' ),
						'none'              => __( 'Nobody (for testing the protection)', 'scrapelock' ),
					),
					PNCP_Admin_Fields::help( __( 'Covers on-page protection and server checks. Customers are not excluded.', 'scrapelock' ), __( 'The server checks are the bot checks, the limits and the blocks. Customers with an account get the protection like any visitor.', 'scrapelock' ) )
				);
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Message to the visitor', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'show_message', __( 'Show a message when something is blocked', 'scrapelock' ) ); ?>
				<?php // 3.5: a wrapper of its own, so dimming the text does not dim the checkbox above. ?>
				<div class="pncp-field">
				<label for="pncp-message" class="screen-reader-text"><?php esc_html_e( 'Message text', 'scrapelock' ); ?></label>
				<input type="text" class="large-text" id="pncp-message" name="<?php echo esc_attr( PNCP_OPTION ); ?>[message]" value="<?php echo esc_attr( $s['message'] ); ?>" placeholder="<?php echo esc_attr( PNCP_Options::message( array() ) ); ?>" maxlength="200" aria-describedby="pncp-message-help pncp-message-requires"<?php echo PNCP_Admin_Fields::requires_attr( 'message', $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_attr(). ?>>
				<p class="description" id="pncp-message-help"><?php esc_html_e( 'Leave empty for the default message in the site language.', 'scrapelock' ); ?></p>
				<?php echo PNCP_Admin_Fields::requires_note( 'message', $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_note(). ?>
				</div>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Iframe and AI', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'block_framing', __( 'Pages do not open inside another site\'s iframe', 'scrapelock' ), __( 'X-Frame-Options and CSP frame-ancestors headers. WordPress embeds (oEmbed) keep working.', 'scrapelock' ) );
				self::checkbox( $s, 'tdm_reservation', __( 'Opt-out declaration from AI training and text and data mining (TDM)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Sends the tdm-reservation header and meta, tdmrep.json and noai/noimageai.', 'scrapelock' ), __( 'The file is /.well-known/tdmrep.json. Legal basis: Directive (EU) 2019/790, Article 4(3): reservation of rights in a machine-readable format.', 'scrapelock' ) ) );
				?>
				<p><label for="pncp-tdm_policy_url"><?php esc_html_e( 'Page with the licensing terms (optional):', 'scrapelock' ); ?></label>
				<input type="url" class="regular-text code" id="pncp-tdm_policy_url" name="<?php echo esc_attr( PNCP_OPTION ); ?>[tdm_policy_url]" value="<?php echo esc_attr( $s['tdm_policy_url'] ); ?>" placeholder="https://" aria-describedby="pncp-tdm_policy_url-requires"<?php echo PNCP_Admin_Fields::requires_attr( 'tdm_policy_url', $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_attr(). ?>></p>
				<?php echo PNCP_Admin_Fields::requires_note( 'tdm_policy_url', $s ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in requires_note(). ?>
			</td>
		</tr>
		<?php
		self::form_close();
		self::render_settings_io();
	}

	/**
	 * Export, import and the saved versions (undo).
	 */
	private static function render_settings_io() {
		$backups = PNCP_Settings_Io::backups();
		?>
		<section class="pncp-card pncp-settings-io" aria-labelledby="pncp-settings-io-title">
			<h2 id="pncp-settings-io-title"><?php esc_html_e( 'Export, import and undo', 'scrapelock' ); ?></h2>
			<?php echo PNCP_Admin_Fields::para( __( 'All tabs as one JSON file, for a backup or another site. Secrets are left out.', 'scrapelock' ), __( 'The file leaves out secrets: the CDN shared secret, the API token for blocking at the CDN and the private feed tokens (of which only a hash is stored). Set those again on the other site.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php self::action_form_open( 'pncp_settings', 'pncp_settings', 'pncp-inline-form' ); ?>
				<input type="hidden" name="op" value="export">
				<p><button type="submit" class="button"><?php esc_html_e( 'Export settings', 'scrapelock' ); ?></button></p>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
				<input type="hidden" name="action" value="pncp_settings">
				<input type="hidden" name="op" value="import_preview">
				<?php self::nonce_field( 'pncp_settings' ); ?>
				<p>
					<label for="pncp-import-file"><?php esc_html_e( 'Import settings from a file:', 'scrapelock' ); ?></label>
					<input type="file" id="pncp-import-file" name="pncp_import_file" accept=".json,application/json" required aria-describedby="pncp-import-help">
					<button type="submit" class="button"><?php esc_html_e( 'Check the file', 'scrapelock' ); ?></button>
				</p>
				<p class="description" id="pncp-import-help"><?php esc_html_e( 'Nothing changes until you have seen the changes and confirmed.', 'scrapelock' ); ?></p>
			</form>
			<h3><?php esc_html_e( 'Earlier versions', 'scrapelock' ); ?></h3>
			<?php if ( ! $backups ) : ?>
				<p class="description"><?php esc_html_e( 'None yet. Presets, imports and resets keep the previous settings here (last 5).', 'scrapelock' ); ?></p>
			<?php else : ?>
				<ul class="pncp-backups">
					<?php foreach ( $backups as $item ) : ?>
						<li>
							<?php
							$user = get_userdata( (int) $item['user'] );
							echo esc_html(
								sprintf(
									/* translators: 1: date and time, 2: what changed, 3: user name */
									__( '%1$s: %2$s (%3$s)', 'scrapelock' ),
									wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $item['time'] ),
									PNCP_Settings_Io::reason_label( $item ),
									$user ? $user->display_name : __( 'WP-CLI or automatic', 'scrapelock' )
								)
							);
							self::action_form_open( 'pncp_settings', 'pncp_settings', 'pncp-inline-form' );
							?>
								<input type="hidden" name="op" value="restore">
								<input type="hidden" name="id" value="<?php echo esc_attr( $item['id'] ); ?>">
								<button type="submit" class="button button-small"><?php esc_html_e( 'Restore', 'scrapelock' ); ?></button>
							</form>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * The settings that would change, as a table.
	 *
	 * @param array<int, array<string, string>> $changes key, old, new.
	 * @param string                            $label   Header of the new values.
	 */
	private static function render_changes( $changes, $label ) {
		?>
		<div class="pncp-table-wrap">
		<table class="widefat striped pncp-changes">
			<thead><tr><th scope="col"><?php esc_html_e( 'Setting', 'scrapelock' ); ?></th><th scope="col"><?php esc_html_e( 'Now', 'scrapelock' ); ?></th><th scope="col"><?php echo esc_html( $label ); ?></th></tr></thead>
			<tbody>
				<?php foreach ( $changes as $change ) : ?>
					<tr>
						<?php // 3.11: the setting in words, and On / Off for a switch (the key stays in the title, for support). ?>
						<td title="<?php echo esc_attr( $change['key'] ); ?>"><?php echo esc_html( PNCP_Setting_Labels::label( $change['key'] ) ); ?></td>
						<td><?php echo '' === $change['old'] ? '<em>' . esc_html__( '(empty)', 'scrapelock' ) . '</em>' : esc_html( PNCP_Setting_Labels::value( $change['key'], $change['old'] ) ); ?></td>
						<td><?php echo '' === $change['new'] ? '<em>' . esc_html__( '(empty)', 'scrapelock' ) . '</em>' : esc_html( PNCP_Setting_Labels::value( $change['key'], $change['new'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		</div>
		<?php
	}

	/**
	 * The warnings and refusals of PNCP_Options::sanitize() for a prepared change.
	 *
	 * @param array<int, array<string, string>> $messages type, message.
	 */
	private static function render_messages( $messages ) {
		foreach ( $messages as $message ) {
			printf( '<div class="notice notice-%1$s inline"><p>%2$s</p></div>', esc_attr( $message['type'] ), esc_html( $message['message'] ) );
		}
	}

	/**
	 * Confirmation of an import: what the file would change.
	 */
	private static function render_import_confirm() {
		$data = get_transient( 'pncp_import_' . get_current_user_id() );
		if ( ! is_array( $data ) || empty( $data['settings'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'The checked file is no longer available (it is kept for 15 minutes). Choose it again.', 'scrapelock' ) . '</p></div>';
			return;
		}
		$prepared = PNCP_Settings_Io::prepare( $data['settings'] );
		?>
		<div class="notice notice-warning pncp-confirm pncp-import-confirm">
			<p><strong><?php esc_html_e( 'Import these settings?', 'scrapelock' ); ?></strong>
			<?php
			if ( ! empty( $data['name'] ) ) {
				echo ' ' . esc_html( (string) $data['name'] );
			}
			?>
			</p>
			<?php
			self::render_messages( $prepared['messages'] );
			if ( ! empty( $data['ignored'] ) ) {
				/* translators: %s: setting names */
				echo '<p>' . esc_html( sprintf( __( 'Left out (unknown, secret or belonging to the other site): %s', 'scrapelock' ), implode( ', ', $data['ignored'] ) ) ) . '</p>';
			}
			if ( $prepared['changes'] ) {
				/* translators: %d: number of settings */
				echo '<p>' . esc_html( sprintf( _n( '%d setting would change. The current settings are kept as an earlier version, so you can undo the import.', '%d settings would change. The current settings are kept as an earlier version, so you can undo the import.', count( $prepared['changes'] ), 'scrapelock' ), count( $prepared['changes'] ) ) ) . '</p>';
				self::render_changes( $prepared['changes'], __( 'After the import', 'scrapelock' ) );
			} else {
				echo '<p>' . esc_html__( 'The file holds the same settings as this site: nothing would change.', 'scrapelock' ) . '</p>';
			}
			self::action_form_open( 'pncp_settings', 'pncp_settings' );
			?>
				<p>
					<?php if ( $prepared['changes'] ) : ?>
						<button type="submit" name="op" value="import_apply" class="button button-primary"><?php esc_html_e( 'Yes, import', 'scrapelock' ); ?></button>
					<?php endif; ?>
					<button type="submit" name="op" value="import_cancel" class="button"><?php esc_html_e( 'Cancel', 'scrapelock' ); ?></button>
				</p>
			</form>
		</div>
		<?php
	}

	/**
	 * Confirmation of "Reset this tab to defaults": what would change.
	 *
	 * @param string $tab Tab.
	 */
	private static function render_reset_confirm( $tab ) {
		$names = PNCP_Settings_Io::tab_names();
		if ( ! isset( $names[ $tab ] ) ) {
			return;
		}
		$prepared = PNCP_Settings_Io::prepare( PNCP_Settings_Io::section_defaults( $tab ) );
		?>
		<div class="notice notice-warning pncp-confirm pncp-reset-confirm">
			<p><strong>
			<?php
			/* translators: %s: tab name */
			echo esc_html( sprintf( __( 'Reset the “%s” tab to its defaults?', 'scrapelock' ), $names[ $tab ] ) );
			?>
			</strong></p>
			<?php if ( $prepared['changes'] ) : ?>
				<p><?php esc_html_e( 'Only the settings of this tab change. The current settings are kept as an earlier version, so you can undo the reset.', 'scrapelock' ); ?><?php echo 'bots' === $tab ? ' ' . esc_html__( 'The CDN shared secret is kept.', 'scrapelock' ) : ''; ?></p>
				<?php self::render_messages( $prepared['messages'] ); ?>
				<?php self::render_changes( $prepared['changes'], __( 'Default', 'scrapelock' ) ); ?>
				<?php self::action_form_open( 'pncp_settings', 'pncp_settings' ); ?>
					<input type="hidden" name="op" value="reset">
					<input type="hidden" name="section" value="<?php echo esc_attr( $tab ); ?>">
					<p>
						<button type="submit" class="button button-primary"><?php esc_html_e( 'Yes, reset', 'scrapelock' ); ?></button>
						<a class="button" href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => $tab ) ) ); ?>"><?php esc_html_e( 'Cancel', 'scrapelock' ); ?></a>
					</p>
				</form>
			<?php else : ?>
				<p><?php esc_html_e( 'This tab already has its default settings: nothing would change.', 'scrapelock' ); ?></p>
				<p><a class="button" href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => $tab ) ) ); ?>"><?php esc_html_e( 'Back', 'scrapelock' ); ?></a></p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Profiles and Emergency Mode.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_profiles( $s ) {
		$current  = PNCP_Options::current_profile( $s );
		$profiles = array(
			'balanced' => array( __( 'Balanced', 'scrapelock' ), __( 'Copy with source, limit 60 pages/minute, block after 3 violations. For most sites.', 'scrapelock' ) ),
			'strict'   => array( __( 'Strict', 'scrapelock' ), __( 'No text selection or copying, limit 40 pages/minute, 3-hour block after 2 violations.', 'scrapelock' ) ),
			'maximum'  => array( __( 'Maximum', 'scrapelock' ), __( 'Adds no printing, no RSS, browsers only, screenshot blur; 30/minute, 12-hour blocks.', 'scrapelock' ) ),
		);
		$until    = PNCP_Options::emergency_until();
		?>
		<div class="pncp-cards">
			<section class="pncp-card" aria-labelledby="pncp-profiles-title">
				<h2 id="pncp-profiles-title"><?php esc_html_e( 'Presets', 'scrapelock' ); ?></h2>
				<p class="description"><?php esc_html_e( 'One click sets protection and limits; lists, feeds, IPs and watermark stay.', 'scrapelock' ); ?></p>
				<p><?php esc_html_e( 'Current:', 'scrapelock' ); ?> <strong><?php echo esc_html( '' === $current ? __( 'Custom', 'scrapelock' ) : $profiles[ $current ][0] ); ?></strong></p>
				<?php self::action_form_open( 'pncp_profile', 'pncp_profile', 'pncp-profile-form' ); ?>
					<?php foreach ( $profiles as $key => $profile ) : ?>
						<div class="pncp-profile<?php echo $current === $key ? ' is-current' : ''; ?>">
							<button type="submit" name="profile" value="<?php echo esc_attr( $key ); ?>" class="button<?php echo 'balanced' === $key ? ' button-primary' : ''; ?>" aria-describedby="pncp-profile-<?php echo esc_attr( $key ); ?>"<?php self::profile_confirm( $s, $key ); ?>><?php echo esc_html( $profile[0] ); ?></button>
							<p class="description" id="pncp-profile-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $profile[1] ); ?><?php echo 'maximum' === $key ? ' ' . PNCP_Admin_Fields::risk_icon() : ''; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?></p>
						</div>
					<?php endforeach; ?>
				</form>
			</section>
			<section class="pncp-card pncp-card--emergency" aria-labelledby="pncp-emergency-title">
				<h2 id="pncp-emergency-title"><?php esc_html_e( 'Emergency Mode', 'scrapelock' ); ?></h2>
				<p class="description"><?php esc_html_e( 'For an attack in progress. Your own settings apply again when it ends.', 'scrapelock' ); ?></p>
				<?php
				// Made from the overlay itself (PNCP_Options::emergency_overlay()), so it lists exactly what changes.
				$changes = PNCP_Options::emergency_changes( PNCP_Options::stored() );
				if ( $changes ) {
					echo '<p class="description">' . esc_html__( 'While it is on, compared with your settings:', 'scrapelock' ) . '</p><ul class="pncp-emergency-changes">';
					foreach ( $changes as $change ) {
						echo '<li>' . esc_html( $change ) . '</li>';
					}
					echo '</ul>';
				} else {
					echo '<p class="description">' . esc_html__( 'Your settings are already at least as strict as Emergency Mode: it would change nothing.', 'scrapelock' ) . '</p>';
				}
				?>
				<?php if ( $until ) : ?>
					<p class="pncp-emergency-on">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: date and time */
								__( 'Active until %s.', 'scrapelock' ),
								wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $until )
							)
						);
						?>
					</p>
					<p><a class="button" href="<?php echo esc_url( PNCP_Status::emergency_stop_url() ); ?>"><?php esc_html_e( 'End now', 'scrapelock' ); ?></a></p>
					<?php
					$auto = PNCP_Surge::last();
					if ( $auto && (int) $auto[0]['time'] + (int) $auto[0]['hours'] * HOUR_IN_SECONDS >= $until - 60 ) {
						/* translators: 1: pages per minute, 2: threshold */
						echo '<p class="description">' . esc_html( sprintf( __( 'Started automatically: %1$d pages per minute, above %2$d.', 'scrapelock' ), (int) $auto[0]['count'], (int) $auto[0]['threshold'] ) ) . '</p>';
					}
					?>
				<?php else : ?>
					<?php
					$state = PNCP_Surge::state();
					if ( ! empty( $s['auto_emergency'] ) && 'start' === $s['auto_emergency_mode'] ) {
						echo '<p class="description">' . esc_html(
							$state['samples'] >= PNCP_Surge::WARMUP
								/* translators: 1: usual pages per minute, 2: threshold */
								? sprintf( __( 'Automatic start: on. Usually %1$s pages per minute; it starts above %2$d.', 'scrapelock' ), number_format_i18n( $state['avg'], 1 ), PNCP_Surge::threshold( $state, $s ) )
								/* translators: %d: threshold */
								: sprintf( __( 'Automatic start: on, still learning; meanwhile it starts above %d pages per minute.', 'scrapelock' ), PNCP_Surge::threshold( $state, $s ) )
						) . '</p>';
					} elseif ( ! empty( $s['auto_emergency'] ) ) {
						echo '<p class="description">' . esc_html(
							$state['samples'] >= PNCP_Surge::WARMUP
								/* translators: 1: usual pages per minute, 2: threshold */
								? sprintf( __( 'Attack alert: on. Usually %1$s pages per minute; alert above %2$d.', 'scrapelock' ), number_format_i18n( $state['avg'], 1 ), PNCP_Surge::threshold( $state, $s ) )
								/* translators: %d: threshold */
								: sprintf( __( 'Attack alert: on, still learning; meanwhile the alert is above %d pages per minute.', 'scrapelock' ), PNCP_Surge::threshold( $state, $s ) )
						) . '</p>';
						echo PNCP_Admin_Fields::more( __( 'An alert is an email and a notice here with a button to start Emergency Mode.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
					}
					?>
					<?php self::action_form_open( PNCP_Status::EMERGENCY, PNCP_Status::EMERGENCY ); ?>
						<p>
							<label for="pncp-emergency-hours"><?php esc_html_e( 'Duration:', 'scrapelock' ); ?></label>
							<select id="pncp-emergency-hours" name="hours">
								<option value="1"><?php esc_html_e( '1 hour', 'scrapelock' ); ?></option>
								<option value="6"><?php esc_html_e( '6 hours', 'scrapelock' ); ?></option>
								<option value="24" selected><?php esc_html_e( '24 hours', 'scrapelock' ); ?></option>
								<option value="72"><?php esc_html_e( '3 days', 'scrapelock' ); ?></option>
							</select>
							<button type="submit" class="button pncp-button-danger"><?php esc_html_e( 'Start Emergency Mode', 'scrapelock' ); ?></button>
						</p>
					</form>
				<?php endif; ?>
			</section>
		</div>
		<?php
	}

	/**
	 * A confirm() question on a preset button when the preset turns off RSS feeds or printing that are on now
	 * (assets/js/admin.js asks it before the form is sent).
	 *
	 * @param array<string, mixed> $s   Settings.
	 * @param string               $key Preset.
	 */
	private static function profile_confirm( $s, $key ) {
		$values = PNCP_Options::profiles()[ $key ];
		$feeds  = isset( $values['feed_mode'] ) && 'disabled' === $values['feed_mode'] && 'disabled' !== $s['feed_mode'];
		$print  = isset( $values['print_mode'] ) && 'block' === $values['print_mode'] && 'block' !== $s['print_mode'];
		if ( $feeds && $print ) {
			$text = __( 'This preset turns off the RSS feeds and printing. Feed readers, podcast apps, newsletter tools and services that read your feed stop getting it, and visitors cannot print pages. The current settings are kept, so you can undo it. Continue?', 'scrapelock' );
		} elseif ( $feeds ) {
			$text = __( 'This preset turns off the RSS feeds. Feed readers, podcast apps, newsletter tools and services that read your feed stop getting it. The current settings are kept, so you can undo it. Continue?', 'scrapelock' );
		} elseif ( $print ) {
			$text = __( 'This preset turns off printing: visitors cannot print pages. The current settings are kept, so you can undo it. Continue?', 'scrapelock' );
		} else {
			return;
		}
		printf( ' data-pncp-confirm="%s"', esc_attr( $text ) );
	}

	/**
	 * "Bots and limits" tab.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_bots( $s ) {
		self::render_cloudflare_hint( $s );
		PNCP_Plugin_Bots::render_notice_and_form(); // 3.10: before the settings form (the buttons have a form of their own).
		PNCP_Ai_Search_List::render_notice( $s ); // 3.11: allowed AI search bots still in the bot list.
		self::section_nav(
			array(
				'monitor'    => __( 'Monitor only', 'scrapelock' ),
				'bots'       => __( 'Bots', 'scrapelock' ),
				'ai'         => __( 'AI', 'scrapelock' ),
				'allowed'    => __( 'Always allowed', 'scrapelock' ),
				'blocked'    => __( 'Always blocked', 'scrapelock' ),
				'login'      => __( 'Sign-in', 'scrapelock' ),
				'limits'     => __( 'Limits', 'scrapelock' ),
				'human'      => __( 'Human check', 'scrapelock' ),
				'reputation' => __( 'Reputation', 'scrapelock' ),
				'countries'  => __( 'Countries', 'scrapelock' ),
				'crowdsec'   => __( 'CrowdSec', 'scrapelock' ),
				'ban'        => __( 'Temporary block', 'scrapelock' ),
				'network'    => __( 'Network and CDN', 'scrapelock' ),
				'edge'       => __( 'Blocking at the CDN', 'scrapelock' ),
				'lists'      => __( 'IP lists', 'scrapelock' ),
			)
		);
		// One form in three parts: Bots, Limits, and "Network and CDN" (folded: most sites never change it).
		// The parts are only headings between tables; every field still belongs to the same form and the same
		// "bots" section of the settings, so saving keeps working exactly as before.
		// 3.11: every part is a folded <details> (PNCP_Admin_Accordion); only Bots, Limits and Sign-in are open.
		PNCP_Admin_Accordion::start();
		self::form_open( 'bots' );
		?>
		<?php self::row_open( 'monitor', __( 'Monitor only', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'monitor_mode', __( 'Monitor only (log what would be blocked, block nothing)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Runs every check but only logs “Would block”; nothing is refused.', 'scrapelock' ), __( 'Every check below still runs, but a request it would refuse is let through and written to the log as “Would block”. No IP is blocked temporarily and nothing is blocked at the CDN. Use it to see what the settings would do before they do it: you and your staff are exempt, so you would never notice a block yourselves. Private URLs (feeds with a token) and Lockdown are not affected: they keep protecting.', 'scrapelock' ) ) );
				if ( ! empty( $s['monitor_mode'] ) && ! empty( $s['monitor_until'] ) && PNCP_Options::monitoring( $s ) ) {
					printf(
						'<p class="description pncp-monitor-until">%s</p>',
						esc_html(
							sprintf(
								/* translators: %s: date and time */
								__( 'New install: blocking starts on its own on %s. Untick the box to start now.', 'scrapelock' ),
								wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $s['monitor_until'] )
							)
						)
					);
					echo PNCP_Admin_Fields::more( __( 'You can also use “Enforce now”. Turned on by hand, “Monitor only” has no end.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
				}
				?>
		<?php self::row_close(); ?>
		<?php self::group_heading( 'bots', __( 'Bots', 'scrapelock' ), __( 'Who may read the site: bot list, AI crawlers, allowed and blocked lists.', 'scrapelock' ) ); ?>
		<?php self::row_open( 'bots', __( 'Scrapers and bots', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'block_bots', __( 'Block (403) the User-Agents in the list', 'scrapelock' ) );
				self::checkbox( $s, 'block_empty_ua', __( 'Block requests without a User-Agent', 'scrapelock' ) );
				self::checkbox( $s, 'block_fake_crawlers', __( 'Block fake Googlebot, Bingbot, Applebot and Yandex', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Checks the IP against the official lists and with reverse DNS.', 'scrapelock' ), __( 'The IP is checked against the official Google and Bing lists and with reverse DNS. Real search engines always pass, without limits.', 'scrapelock' ) ) );
				self::checkbox( $s, 'require_browser_headers', __( 'Browsers only: 403 for pages without Accept-Language or without “Mozilla/” in the User-Agent', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Stops most scripts; link previews in “Always allowed” still pass.', 'scrapelock' ), __( 'Stops most scripts. Link previews (Facebook, Viber, WhatsApp etc.) in the “Always allowed” list pass.', 'scrapelock' ) ) );
				self::checkbox( $s, 'block_headless', __( 'Block headless and fake browsers', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Catches HeadlessChrome and, on HTTPS, Chrome look-alikes without Sec-Fetch headers.', 'scrapelock' ), __( 'Blocks Chrome running without a window when it says so in its headers (“HeadlessChrome”), and, on HTTPS, scripts that copy the User-Agent of Chrome, Edge or Firefox without the Sec-Fetch headers every modern browser sends. It catches common tools and cheap scrapers, not every automated browser: one that is carefully disguised (e.g. Puppeteer with “stealth”, or Selenium with a visible Chrome) sends the same headers as a person. The page limits, the human check and the bot trap still apply to those. In-app browsers (Android WebView) are not checked.', 'scrapelock' ) ) );
				self::checkbox( $s, 'trap_enabled', __( 'Bot trap', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'A hidden link, disallowed in robots.txt; whoever opens it is blocked.', 'scrapelock' ), __( 'Invisible link on every page, disallowed in robots.txt. Whoever opens it is blocked temporarily, even if it pretends to be a browser. Visitors do not see it, and another site cannot trap them.', 'scrapelock' ) ) );
				// 3.5: opt-in ban of vulnerability scanners on their first probe (PNCP_Bots::probe_guard()).
				self::checkbox( $s, 'probe_ban', __( 'Ban scanners on their first probe', 'scrapelock' ), PNCP_Admin_Fields::help( __( '10-minute block on the first request for .env, .git, dumps and similar.', 'scrapelock' ), __( 'Blocks an IP for 10 minutes the first time it asks for a file that only attack scanners look for and that does not exist on this site: .env, .git, backup copies of wp-config.php, database dumps and backup archives at the top of the site, SSH keys, phpMyAdmin, Adminer, PHP files in the uploads folder, and what scanners look for in other software (Spring Boot /actuator, Dockerfile and docker-compose files, credentials and secrets files, .aws, .vscode/sftp.json). A second probe within 24 hours gets the full temporary block. phpMyAdmin, Adminer and PHP files in uploads are caught only when the web server passes those requests to WordPress: Nginx usually answers a missing .php file itself, and “No PHP in uploads” refuses them first. Staff, verified search engines, the always-allowed IPs and User-Agents, and people who click a link or type the address in a browser are never blocked. On Nginx, add the updated rules from the “Server rules” tab so that requests for hidden files (.env, .git) reach WordPress.', 'scrapelock' ) ) );
				self::textarea( $s, 'bot_list', __( 'User-Agents to block (one per line, matches anywhere in the User-Agent, case-insensitive):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Includes AI training crawlers and AI search bots; search can be allowed below.', 'scrapelock' ), __( 'It contains two AI categories: training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended etc.) and AI search / assistants (OAI-SearchBot, ChatGPT-User, Claude-SearchBot, PerplexityBot etc.). You can allow the second one in the next section.', 'scrapelock' ) . ' ' . sprintf( /* translators: %s: number of AI crawlers */ __( 'In addition, %s more AI crawlers and agents (DeepSeek, Grok, Qwen, Mistral, NotebookLM and others) are blocked by name: that list is built into ScrapeLock and updated with each version, so it is not shown here. A line that starts with “=” must be the whole User-Agent, e.g. “=node”.', 'scrapelock' ), number_format_i18n( count( PNCP_Bots::known_ai_agents() ) ) ) ), 10, true );
				self::checkbox( $s, 'block_http_libs', __( 'Also block generic HTTP libraries (strict)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Blocks curl, python-requests and similar, which apps and monitors also use.', 'scrapelock' ), __( 'Blocks the User-Agent that programming libraries send by default: curl, Wget, python-requests, Go, Java, okhttp, Dart, node-fetch, axios, Guzzle and others. Many cheap scrapers use them, but so do WooCommerce mobile apps (Flutter, Android), headless front ends, ERP and price sync, and uptime monitors. Turn it on only if nothing like that reads your site, or add those services to “Always allowed” first.', 'scrapelock' ) ) );
				$libraries = PNCP_Options::http_libraries_in_list( $s );
				if ( $libraries && empty( $s['block_http_libs'] ) ) {
					printf(
						'<p class="description pncp-http-libs-note">%s</p>',
						esc_html(
							sprintf(
								/* translators: %s: list of User-Agents, e.g. "curl/, okhttp, Dart/" */
								__( 'Your bot list still blocks these HTTP libraries, even with this off: %s.', 'scrapelock' ),
								implode( ', ', $libraries )
							)
						)
					);
					echo PNCP_Admin_Fields::more( __( 'Lists saved before ScrapeLock 3.4 had them by default. If a mobile app, a headless front end or a sync service gets a 403, remove those lines from the list, or allow the service in “Always allowed”.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
				}
				// 3.7.
				self::checkbox( $s, 'block_seo_crawlers', __( 'Block SEO and marketing data crawlers (Ahrefs, Semrush, Majestic…)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Backlink and competitor-research crawlers. Leave off if you use one.', 'scrapelock' ), sprintf( /* translators: %s: list of User-Agents */ __( 'They are not search engines: backlink indexes and competitor research tools crawl hard and sell what they collect, to your competitors too. Blocked and asked in robots.txt: %s. Leave it off if you use one of these tools for your own site, or add its audit bot to “Always allowed”.', 'scrapelock' ), implode( ', ', PNCP_Bots::seo_agents() ) ) ) );
				self::checkbox( $s, 'block_ip_host', __( 'Refuse requests that open the site by its IP address instead of its name', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Scanners sweep IP ranges; people and search engines use the domain name.', 'scrapelock' ), __( 'Scanners that sweep whole address ranges ask for http://203.0.113.5/ instead of your domain; people and search engines follow links, which carry the name. Requests for a private address (a load balancer\'s health check, a reverse proxy) and a site that is set up with its IP as its address are never refused. Always on in Emergency Mode.', 'scrapelock' ) ) );
				printf(
					'<p class="description">%s</p>',
					esc_html(
						sprintf(
							/* translators: %s: number of programs */
							__( 'With the bot list on, %s site rippers and attack User-Agents are blocked too.', 'scrapelock' ),
							number_format_i18n( count( PNCP_Bots::ripper_agents() ) )
						)
					)
				);
				echo PNCP_Admin_Fields::more( __( 'Rippers and address harvesters such as HTTrack, WebCopier, Teleport Pro, Offline Explorer, SiteSucker and Octoparse, and any User-Agent that carries an attack instead of a name (HTML tags, Shellshock, Log4Shell, SQL injection): no browser or crawler sends one.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'ai', __( 'AI search and training', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'allow_ai_search', __( 'Allow AI search engines and assistants (not training crawlers)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Appear in AI search answers with a link, without feeding model training.', 'scrapelock' ), sprintf( /* translators: %s: list of User-Agents */ __( 'So the site appears in AI search answers with a link, without being given for model training. Allowed: %s. They are also removed from the robots.txt Disallow and from the server rules. The page limit still applies, because the User-Agent can be spoofed. While this is off, ScrapeLock blocks them, also when they are not in the bot list.', 'scrapelock' ), implode( ', ', PNCP_Options::ai_search_agents() ) ) ) );
				self::checkbox( $s, 'verify_ai_bots', __( 'Verify AI search bots with their official IP lists (OpenAI, Perplexity, Anthropic)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Real OpenAI, Perplexity and Anthropic search bots pass; impostors get a 403.', 'scrapelock' ), __( 'With AI search allowed: the real OAI-SearchBot, ChatGPT-User, PerplexityBot, Perplexity-User, Claude-SearchBot and Claude-User are never limited or blocked, and requests that only use their name get a 403 (“Fake AI search bot”). The lists are downloaded once a day; until then nothing changes.', 'scrapelock' ) ) );
				self::checkbox( $s, 'robots_ai_block', __( 'Declare AI crawlers in robots.txt (Disallow)', 'scrapelock' ), __( 'Only the virtual robots.txt; a physical robots.txt file takes precedence.', 'scrapelock' ) );
				self::checkbox( $s, 'block_archivers', __( 'Block web archives (Wayback Machine)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Blocks the Internet Archive crawlers; pages already archived stay there.', 'scrapelock' ), __( 'The Internet Archive keeps a public copy of every page it visits, and that copy can be scraped without ever reaching your site. This blocks its crawlers (ia_archiver, archive.org_bot, heritrix) and asks them in robots.txt. Copies already in the archive stay there. Leave it off if you want your site to be archived.', 'scrapelock' ) ) );
				self::checkbox( $s, 'content_signal', __( 'Content Signals in robots.txt: search yes, AI training no', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Says search=yes, ai-train=no: a statement of terms, not a block.', 'scrapelock' ), __( 'A line that says what the content may be used for (contentsignals.org): search=yes, ai-train=no, and ai-input according to “Allow AI search engines”. It does not block anything; it is a statement of your terms that well-behaved companies read.', 'scrapelock' ) ) );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'allowed', __( 'Always allowed', 'scrapelock' ) ); ?>
				<?php
				self::textarea( $s, 'allow_list', __( 'Always allowed User-Agents (link previews, price comparison platforms, monitoring):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Overrides the bot list and “Browsers only”; the page limit still applies.', 'scrapelock' ), __( 'They override the bot list and “Browsers only”. The page limit applies to them too, because the User-Agent is easy to spoof. To accept an entry only from specific IPs, add @ and the addresses, e.g. Skroutz@203.0.113.0/24.', 'scrapelock' ) ), 5, true );
				self::textarea( $s, 'allow_ips', __( 'Always allowed IPs / CIDR (office, ERP, monitoring), one per line:', 'scrapelock' ), __( 'Never checked, never limited, never blocked.', 'scrapelock' ), 3 );
				PNCP_Plugin_Bots::render_panel(); // 3.10.
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'blocked', __( 'Always blocked', 'scrapelock' ) ); ?>
				<?php
				self::textarea( $s, 'block_ips', __( 'IPs / CIDR that are always blocked (403), one per line:', 'scrapelock' ), __( 'For example a scraper\'s server from the log; “Always allowed IPs” win.', 'scrapelock' ), 3 );
				self::textarea( $s, 'block_referrers', __( 'Referrer domains that are always blocked (403), one per line, e.g. copy-site.example:', 'scrapelock' ), __( 'Requests from links or embeds on these sites, subdomains included.', 'scrapelock' ), 3 );
				self::checkbox( $s, 'block_user_enum', __( 'Hide usernames from visitors', 'scrapelock' ), PNCP_Admin_Fields::help( __( '?author=N, the REST API and the users sitemap stop showing usernames.', 'scrapelock' ), __( '?author=1, 2, 3… returns “page not found” instead of the redirect to /author/username/, the REST API does not list users, the users sitemap is removed and oEmbed shows the site instead of the author. Logged-in users see everything as before. Author archives with a link stay.', 'scrapelock' ) ) );
				?>
		<?php self::row_close(); ?>
		<?php self::render_login_settings( $s ); ?>
		<?php self::group_heading( 'limits', __( 'Limits', 'scrapelock' ), __( 'Pages per minute, stricter limits for some visitors, and temporary blocks.', 'scrapelock' ) ); ?>
		<?php self::row_open( 'limits', __( 'Limits per IP', 'scrapelock' ) ); ?>
				<?php
				self::number( $s, 'rate_limit', __( 'Pages per minute (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( '429 above it. Behind a CDN, set “Real visitor IP” first.', 'scrapelock' ), __( 'Above the limit it returns 429. Be careful with networks that share an IP (companies, mobile carriers) and with CDNs: set the “Real visitor IP” correctly first.', 'scrapelock' ) ) );
				self::number( $s, 'rate_limit_search', __( 'Searches (?s=) per minute (0 = off):', 'scrapelock' ), __( 'Search is heavy for the server and a favourite of scrapers.', 'scrapelock' ) );
				self::number( $s, 'rate_limit_rest', __( 'REST API (/wp-json/) and GraphQL requests per minute (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Visitor read requests only; long per_page lists count as 2 or 3.', 'scrapelock' ), __( 'Only read requests from visitors. Cart, checkout and forms (POST) do not count. A list of more than 20 items (per_page) counts as 2 requests, more than 50 as 3.', 'scrapelock' ) ) );
				// 3.12.1: FluentCommunity's members count per account (PNCP_Fluent_Community::rest_note_help()).
				$pncp_fc_rest = PNCP_Fluent_Community::rest_note_help();
				if ( '' !== $pncp_fc_rest[0] ) {
					echo PNCP_Admin_Fields::para( $pncp_fc_rest[0], $pncp_fc_rest[1], 'pncp-fluent-rest-note' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
				}
				self::number( $s, 'rate_limit_404', __( '“Page not found” (404) per minute (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Catches address guessing; missing images, CSS and scripts do not count.', 'scrapelock' ), __( 'Scrapers guess addresses (?p=1, 2, 3…, old product URLs) to find content. Missing images, CSS, scripts and the favicon do not count.', 'scrapelock' ) ) );
				self::number( $s, 'rate_limit_sitemap', __( 'Sitemaps per minute (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Scrapers read sitemaps first; verified search engines are never limited.', 'scrapelock' ), __( 'Scrapers read the sitemap first to find every page. Covers the sitemaps of WordPress, Rank Math, Yoast and similar plugins. Google, Bing and the other verified search engines are never limited.', 'scrapelock' ) ) );
				// 3.7.
				self::number( $s, 'rate_limit_apionly', __( 'REST API, GraphQL, feeds and sitemaps per minute for IPs that never opened a page (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'For IPs that read only the API, feeds or sitemaps, never pages.', 'scrapelock' ), __( 'Many scrapers skip the HTML and read only the API, the feeds or the sitemaps. A visitor opens a page first; such a scraper never does. An IP that has not opened a page of the site in the last 24 hours (nor passed the human check, nor signed in) gets this limit on those addresses, on top of the others. Feed readers and apps that read the API from their own servers count here too: add them to “Always allowed”. A headless front end that reads the REST API from its server needs its IP in “Always allowed IPs”. With a page cache plugin, cached pages do not reach WordPress and so are not seen: turn on the pre-cache check or the human check, or keep this limit at 20 or more. Suggested value: 10.', 'scrapelock' ) ) );
				self::checkbox( $s, 'ipv6_wide', __( 'IPv6: also limit the whole /56 network (four times the page limit)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Also counts the whole /56, up to four times the page limit.', 'scrapelock' ), __( 'Pages are counted per /64, because one connection usually gets a whole /64. A server or a home connection often has a /56 or more, so a scraper can take a new /64 for every request. This also counts the /56 the /64 belongs to, up to four times the page limit (429 above it, without a block). Some mobile networks give neighbouring phones addresses of the same /56: on a site with many visitors from them, keep it off. Always on in Emergency Mode.', 'scrapelock' ) ) );
				self::number( $s, 'rate_limit_datacenter', __( 'Pages per minute from data centers (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Cloud servers (AWS, Google Cloud…) get this instead; 5 in Emergency Mode.', 'scrapelock' ), __( 'People rarely browse from a server; scrapers very often run on one. Visitors from the published addresses of AWS, Google Cloud, Oracle Cloud, DigitalOcean and Akamai / Linode get this stricter limit instead of the normal one. The lists are downloaded from the providers once a day. Some VPNs use these providers, so their users get this limit too: it is meant for reading, not for blocking. The always-allowed User-Agents (monitoring, price platforms) and verified search engines are not affected. 5 in Emergency Mode.', 'scrapelock' ) ) );
				if ( class_exists( 'WooCommerce' ) ) {
					self::number( $s, 'rate_limit_cart', __( 'WooCommerce cart and checkout actions per minute (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Cart, coupon and order actions; shoppers need a few, bots hundreds.', 'scrapelock' ), __( 'Adding, changing and removing cart items, coupons and placing the order, through the Store API (block cart and checkout), wc-ajax and the classic forms. A shopper needs a handful per minute; bots that fill carts, test stolen cards or spam orders need hundreds. Above the limit: 429, with a JSON error for the Store API and wc-ajax. Exempt staff and users who can edit posts or manage the shop are never limited. 30 in Emergency Mode.', 'scrapelock' ) ) );
					self::number( $s, 'rate_limit_coupon', __( 'WooCommerce coupon attempts per minute (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Every code tried counts, valid or not; 5 in Emergency Mode.', 'scrapelock' ), __( 'Each coupon code tried counts, valid or not, so guessing codes is slowed to this many per minute per IP. 5 in Emergency Mode.', 'scrapelock' ) ) );
				} else {
					// Not shown without WooCommerce, but kept: saving this tab must not reset them.
					foreach ( array( 'rate_limit_cart', 'rate_limit_coupon' ) as $pncp_key ) {
						printf( '<input type="hidden" name="%s[%s]" value="%d">', esc_attr( PNCP_OPTION ), esc_attr( $pncp_key ), (int) $s[ $pncp_key ] );
					}
				}
				self::checkbox( $s, 'auto_emergency', __( 'Watch for attacks spread over many IPs (automatic Emergency Mode)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Reacts when traffic is five times the usual for 3 minutes.', 'scrapelock' ), __( 'The limits per IP cannot see a scraper that spreads its requests over hundreds of IPs. The whole site can: ScrapeLock learns how many pages per minute your site usually serves, and when that is exceeded five times over for 3 minutes in a row (and never below the minimum below), it does what you choose here. Verified search engines and exempt staff are not counted. Pages served from a page cache without reaching WordPress are not counted either.', 'scrapelock' ) ) );
				echo '<div class="pncp-field"><label for="pncp-auto_emergency_mode">' . esc_html__( 'When it happens:', 'scrapelock' ) . '</label> ';
				self::select(
					$s,
					'auto_emergency_mode',
					array(
						'notify' => __( 'Email me and show a notice with a “Start Emergency Mode” button', 'scrapelock' ), // 3.5: "(default)" is added.
						'start'  => __( 'Start Emergency Mode for 1 hour on its own, and email me', 'scrapelock' ),
					),
					PNCP_Admin_Fields::help( __( 'A rush of real visitors looks the same as an attack.', 'scrapelock' ), __( 'A rush of real visitors (a newsletter, a link on a popular site) looks the same as an attack. Emergency Mode changes many settings at once, listed in its box on the first tab, e.g. excerpts instead of full text in lists and stricter limits for data centers, where some services in “Always allowed” run. Feeds stay open to feed readers and podcast apps.', 'scrapelock' ) )
				);
				echo '</div>';
				self::number( $s, 'auto_emergency_min', __( 'Minimum pages per minute for the automatic start:', 'scrapelock' ), __( 'Below this the site never counts as under attack.', 'scrapelock' ) );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'human', __( 'Human check', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'human_check', __( 'Stricter page limit for visitors who have not shown they are people', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'An invisible check on the first scroll or tap; no captcha.', 'scrapelock' ), __( 'A small script waits for the visitor\'s first real interaction (scroll, tap, key or mouse movement), solves a light challenge in the background and receives a cookie for 7 days. Nobody sees a captcha or a window. Visitors without the cookie (scripts, and people with JavaScript turned off) get the limit below instead of the normal page limit. Search engines and verified AI search bots are not affected. With a page cache plugin, turn on the pre-cache check so that cached pages get this limit too. A determined scraper can repeat the steps, but each of its IPs has to do the work.', 'scrapelock' ) ) );
				self::number( $s, 'rate_limit_unverified', __( 'Pages per minute without the cookie (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'People get the cookie with their first scroll or tap.', 'scrapelock' ), __( 'A person reads far fewer pages per minute, and gets the cookie with the first scroll or tap.', 'scrapelock' ) ) );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'reputation', __( 'Reputation', 'scrapelock' ) ); ?>
				<?php
				// 3.7: PNCP_Reputation.
				self::checkbox( $s, 'reputation', __( 'Remember how each IP behaves (reputation)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Scores each IP over 7 days: good ones are spared, bad ones limited.', 'scrapelock' ), __( 'Each IP gets a score from what it did here in the last 7 days, recent events counting more: someone signed in from it, it passed the human check, it reads pages (good); the bot trap, a scanner probe, a fake search engine, an attack in the request, limits exceeded, a temporary block (bad). An IP with a good score (someone signed in and passed the human check) is never blocked temporarily for exceeding a limit: it still gets “too many requests”, but an office, a school or a mobile network behind one address is not locked out because of one fast reader. An IP with a bad score gets the stricter limit below for days, instead of starting from zero when its block ends. Stored like the per-minute counters; no data leaves the server.', 'scrapelock' ) ) );
				self::number( $s, 'rate_limit_lowrep', __( 'Pages per minute for IPs with a bad reputation (0 = off):', 'scrapelock' ), '' );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'countries', __( 'Countries', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'geo_db', __( 'Download the free country database (DB-IP Lite, once a month)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Not needed behind Cloudflare or Bunny CDN. About 5 MB, monthly.', 'scrapelock' ), __( 'Needed when the site is not behind Cloudflare or Bunny CDN. About 5 MB to download, stored as two small files in uploads/scrapelock-geo. Behind Cloudflare the country that Cloudflare sends is used, behind Bunny the one Bunny sends (when it reaches the site directly from Bunny), and the database is not needed.', 'scrapelock' ) ) );
				self::textarea( $s, 'countries_block', __( 'Blocked countries (403), two-letter codes separated by commas, e.g. CN, RU:', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Search engines and “Always allowed” are never blocked by country.', 'scrapelock' ), __( 'Search engines, verified AI search bots and the “Always allowed” list are never blocked by country. People who travel or use a VPN appear with the country of their connection.', 'scrapelock' ) ), 2 );
				self::textarea( $s, 'countries_strict', __( 'Countries with a stricter page limit, e.g. those your customers do not come from:', 'scrapelock' ), '', 2 );
				self::number( $s, 'rate_limit_country', __( 'Pages per minute for these countries (0 = off):', 'scrapelock' ), '' );
				self::render_geo_status( $s );
				?>
		<?php self::row_close(); ?>
		<?php ob_start(); // 3.11: printed under "Advanced", after the temporary block. ?>
		<?php self::row_open( 'crowdsec', __( 'CrowdSec blocklist', 'scrapelock' ) ); ?>
				<?php
				// 3.7: PNCP_Crowdsec.
				echo '<div class="pncp-field"><label for="pncp-crowdsec_mode">' . esc_html__( 'Use the CrowdSec blocklist:', 'scrapelock' ) . '</label> ';
				self::select(
					$s,
					'crowdsec_mode',
					array(
						'off'  => __( 'Off', 'scrapelock' ),
						'lapi' => __( 'From my CrowdSec agent (LAPI, bouncer key)', 'scrapelock' ),
						'list' => __( 'From a blocklist address (plain text, one IP or CIDR per line)', 'scrapelock' ),
					),
					PNCP_Admin_Fields::help( __( 'IPs that attack other sites, from your CrowdSec agent or a list.', 'scrapelock' ), __( 'CrowdSec is a free, open source security engine whose users share the IPs that attack them. Its community blocklist holds scanners, brute-forcers and scrapers seen on many sites, residential proxies among them, which the limits of a single site cannot recognise in time. With your own CrowdSec agent (on a VPS: install CrowdSec, then run “cscli bouncers add scrapelock” for the key), ScrapeLock asks it every 15 minutes for what changed. Without one, use the address of a CrowdSec Console blocklist integration (key: user:password) or of another plain-text list; it is downloaded once an hour. Private addresses, ranges wider than /16 (IPv6 /32), this server, CDN edges and official search engine addresses are never taken from a list.', 'scrapelock' ) )
				);
				echo '</div>';
				printf(
					'<div class="pncp-field"><p><label for="pncp-crowdsec_url">%1$s</label><br><input type="url" class="regular-text code" id="pncp-crowdsec_url" name="%2$s[crowdsec_url]" value="%3$s" placeholder="http://127.0.0.1:8080" spellcheck="false"></p></div>',
					esc_html__( 'Address of the CrowdSec agent (LAPI) or of the list:', 'scrapelock' ),
					esc_attr( PNCP_OPTION ),
					esc_attr( (string) $s['crowdsec_url'] )
				);
				self::password( $s, 'crowdsec_key', __( 'Bouncer key (LAPI), or user:password for a list (optional for a public list):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Never shown or exported. Or define SCRAPELOCK_CROWDSEC_KEY in wp-config.php.', 'scrapelock' ), __( 'Kept in the database and never shown or exported. To keep it out of the database, define SCRAPELOCK_CROWDSEC_KEY in wp-config.php instead.', 'scrapelock' ) ) );
				echo '<div class="pncp-field"><label for="pncp-crowdsec_action">' . esc_html__( 'What a listed IP gets:', 'scrapelock' ) . '</label> ';
				self::select(
					$s,
					'crowdsec_action',
					array(
						'limit' => __( 'The stricter page limit below', 'scrapelock' ),
						'block' => __( 'A 403 on every request', 'scrapelock' ),
					),
					PNCP_Admin_Fields::help( __( 'Addresses change hands, so the stricter limit is safer than a 403.', 'scrapelock' ), __( 'Addresses change hands (mobile networks, home connections that get a new address every day, VPNs), so a list is never certain. The stricter limit lets a real visitor read on slowly; the 403 refuses outright. A listed IP earns no violation either way.', 'scrapelock' ) )
				);
				echo '</div>';
				self::number( $s, 'rate_limit_crowdsec', __( 'Pages per minute for listed IPs (0 = off):', 'scrapelock' ), '' );
				?>
		<?php self::row_close(); ?>
		<?php $crowdsec = (string) ob_get_clean(); ?>
		<?php self::row_open( 'ban', __( 'Temporary block', 'scrapelock' ) ); ?>
				<?php
				self::number( $s, 'ban_strikes', __( 'Block after this many violations within 10 minutes (0 = never):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'A violation is a minute over a limit, or a fake Googlebot.', 'scrapelock' ), __( 'Violation: every minute in which the IP exceeded a limit, and every fake Googlebot. The trap blocks immediately: for 10 minutes the first time, for the full time if the same IP falls into it again within 24 hours.', 'scrapelock' ) ) );
				self::number( $s, 'ban_minutes', __( 'Block duration (minutes):', 'scrapelock' ) );
				// 3.7: PNCP_Fail2ban.
				self::checkbox( $s, 'syslog_bans', __( 'Write each temporary block to the system log, for fail2ban', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Lets fail2ban block the IP in the firewall. Leave off on shared hosting.', 'scrapelock' ), __( 'On a VPS or a dedicated server, fail2ban can read these lines and block the IP in the server\'s firewall for the same time, so a blocked scraper no longer reaches PHP at all. The filter and the jail to copy are on the “Server rules” tab. On shared hosting leave it off: nobody reads that log.', 'scrapelock' ) ) );
				if ( ! empty( $s['syslog_bans'] ) && ! PNCP_Fail2ban::available() ) {
					echo '<p class="description pncp-inline-warning">' . esc_html__( 'PHP cannot write to the system log here: enable openlog() and syslog() in php.ini.', 'scrapelock' ) . '</p>';
				}
				?>
				<p class="description"><?php esc_html_e( 'How long the log is kept is set on the Log tab.', 'scrapelock' ); ?></p>
		<?php self::row_close(); ?>
		<?php
		self::group_heading( 'advanced', __( 'Advanced', 'scrapelock' ), __( 'Shared blocklists, the CDN in front of the site and official IP lists.', 'scrapelock' ) );
		echo $crowdsec; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Printed and escaped above (output buffer).
		?>
		<details class="pncp-advanced" id="pncp-sec-network"<?php echo self::network_needs_attention( $s ) || PNCP_Admin_Sections::requested( 'pncp-sec-network' ) ? ' open' : ''; ?>>
			<summary>
				<h2 class="pncp-advanced__title"><?php esc_html_e( 'Network and CDN (advanced)', 'scrapelock' ); ?></h2>
				<span class="pncp-advanced__state"><?php echo esc_html( self::network_summary( $s ) ); ?></span>
			</summary>
			<?php echo PNCP_Admin_Fields::para( __( 'Only for a CDN or proxy, and for checks before WordPress and the cache.', 'scrapelock' ), __( 'Most sites never need to change these.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<table class="form-table" role="presentation">
			<tr id="pncp-sec-ip">
				<th scope="row"><label for="pncp-ip_header"><?php esc_html_e( 'Real visitor IP', 'scrapelock' ); ?></label></th>
				<td>
					<?php
					self::select(
						$s,
						'ip_header',
						array(
							'remote_addr'      => __( 'REMOTE_ADDR (no CDN/proxy)', 'scrapelock' ),
							'cf_connecting_ip' => 'CF-Connecting-IP (Cloudflare)',
							'x_forwarded_for'  => 'X-Forwarded-For',
							'x_real_ip'        => 'X-Real-IP',
							'true_client_ip'   => 'True-Client-IP',
						),
						PNCP_Admin_Fields::help( __( 'Behind a CDN or proxy, choose the header that carries the visitor IP.', 'scrapelock' ), __( 'Behind a CDN or reverse proxy all visitors appear with the CDN\'s IP. Choose the header with the real IP.', 'scrapelock' ) )
					);
					?>
					<p><?php echo wp_kses( __( '<strong>Trusted Proxy:</strong> the header is read only from proxies you trust.', 'scrapelock' ), array( 'strong' => array() ) ); ?></p>
					<?php echo PNCP_Admin_Fields::more( __( 'The header is read only when the request comes from a proxy you trust. Otherwise anyone could write any IP they want and bypass limits and blocks. CF-Connecting-IP: only from Cloudflare. X-Real-IP / X-Forwarded-For: from Bunny CDN, the server itself or a private network (Nginx in front of Apache). True-Client-IP: only from the proxies in the list.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
					<?php
					self::checkbox( $s, 'trust_cloudflare', __( 'Trust Cloudflare addresses', 'scrapelock' ), __( 'The official Cloudflare list is refreshed every day.', 'scrapelock' ) );
					self::checkbox( $s, 'trust_bunny', __( 'Trust Bunny CDN addresses', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'For X-Real-IP / X-Forwarded-For and Bunny\'s country header.', 'scrapelock' ), __( 'For X-Real-IP / X-Forwarded-For and Bunny\'s country header. The official list of Bunny edge servers is refreshed every day.', 'scrapelock' ) ) );
					if ( ! empty( $s['trust_any_proxy'] ) ) {
						echo '<div class="pncp-inline-warning">';
						self::checkbox( $s, 'trust_any_proxy', __( 'Trust every request (1.4 behaviour, insecure)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Add your proxies below, then untick it; it cannot be turned back on.', 'scrapelock' ), __( 'On because this is how version 1.4 worked. Fill in your proxies below and uncheck it. Once turned off, it cannot be turned on again.', 'scrapelock' ) ) );
						echo '</div>';
					}
					self::textarea( $s, 'trusted_proxies', __( 'Other trusted proxies / load balancers (IP or CIDR, one per line):', 'scrapelock' ), '', 3 );
					self::password( $s, 'cdn_secret', __( 'CDN shared secret (optional):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Trust the CDN header only when the request carries this secret.', 'scrapelock' ), __( 'Only when "Real visitor IP" is a CDN header (CF-Connecting-IP, X-Real-IP, X-Forwarded-For). A CDN (Bunny, Cloudflare) is multi-tenant: its edge IPs are shared, so by default anyone could point their own CDN zone at your origin and set the real-IP header. Set a secret here and configure your CDN to send it on every request as the header “X-ScrapeLock-CDN”; the CDN’s real-IP header is then trusted only when the secret matches. Leave empty to keep the current behaviour. For best effect, also restrict your origin so it is reachable only through the CDN.', 'scrapelock' ) ) );
					self::checkbox( $s, 'cdn_only', __( 'Only through the CDN: refuse (403) requests that do not bring the secret', 'scrapelock' ), PNCP_Admin_Fields::help( __( '403 for requests that bypass the CDN. Set up the CDN header first.', 'scrapelock' ), __( 'Someone who finds your server\'s own address can go around the CDN and everything it blocks. With this on, every request without the secret in the X-ScrapeLock-CDN header gets a 403, also pages from the page cache when the pre-cache check is on. First make the CDN add the header to every request: in Bunny CDN, an Edge Rule with the action “Set Request Header” (X-ScrapeLock-CDN = your secret) for all requests; in Cloudflare, Rules → Transform Rules → “Modify Request Header”, set static. It can only be turned on from a request that brings the secret, so you cannot lock yourself out by mistake. Not affected: the server itself (cron, cache preload), WP-CLI. Files the web server sends without WordPress (images, CSS, JS) are not covered. If the CDN ever stops sending the header, add define( \'SCRAPELOCK_CDN_ONLY\', false ); to wp-config.php.', 'scrapelock' ) ) );
					if ( '' !== trim( (string) $s['cdn_secret'] ) ) {
						echo '<p class="description pncp-cdn-only-status">' . esc_html( PNCP_Origin::has_secret( (string) $s['cdn_secret'] ) ? __( 'This request brought the secret: the CDN sends it.', 'scrapelock' ) : __( 'This request did not bring the secret: add it at the CDN, or open the site through the CDN.', 'scrapelock' ) ) . '</p>';
					}
					if ( defined( 'SCRAPELOCK_CDN_ONLY' ) && ! SCRAPELOCK_CDN_ONLY ) {
						echo '<p class="description">' . esc_html__( 'Turned off in wp-config.php (SCRAPELOCK_CDN_ONLY).', 'scrapelock' ) . '</p>';
					}
					?>
					<p class="description">
						<?php
						esc_html_e( 'What the server sees on this request:', 'scrapelock' );
						echo '<br><code>REMOTE_ADDR = ' . esc_html( PNCP_Ip::remote_addr() ) . '</code>';
						foreach ( PNCP_Ip::ip_headers() as $key ) {
							if ( ! empty( $_SERVER[ $key ] ) ) {
								echo '<br><code>' . esc_html( $key . ' = ' . sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) ) . '</code>';
							}
						}
						echo '<br>' . esc_html__( 'Trusted proxy:', 'scrapelock' ) . ' <code>' . esc_html( PNCP_Ip::is_trusted_proxy( PNCP_Ip::remote_addr(), $s, (string) $s['ip_header'] ) ? __( 'yes', 'scrapelock' ) : __( 'no', 'scrapelock' ) ) . '</code>';
						echo '<br>' . esc_html__( 'IP the plugin uses now:', 'scrapelock' ) . ' <code>' . esc_html( PNCP_Ip::client_ip() ) . '</code>';
						?>
					</p>
				</td>
			</tr>
			<tr id="pncp-sec-early">
				<th scope="row"><?php esc_html_e( 'Early checks', 'scrapelock' ); ?></th>
				<td>
					<?php
					self::checkbox( $s, 'early_mode', __( 'Early check: block known bots before the theme and the other plugins load', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Stops listed bots and blocked IPs earlier, through a small mu-plugin.', 'scrapelock' ), __( 'Adds the small file wp-content/mu-plugins/scrapelock-early.php, which stops blocked IPs and referrers, temporarily blocked IPs and User-Agents in the bot list with less server load. Search engines, logged-in users, forms and feeds are left to the normal check. It is removed when you turn this off or deactivate the plugin.', 'scrapelock' ) ) );
					if ( ! empty( $s['early_mode'] ) && ! PNCP_Early::installed() ) {
						echo '<p class="pncp-inline-warning">' . esc_html__( 'Could not create the file: make wp-content/mu-plugins writable. The normal check still runs.', 'scrapelock' ) . '</p>';
					}
					if ( ! is_multisite() ) {
						self::checkbox( $s, 'precheck', __( 'Pre-cache check: apply the page limit and blocks also to pages served from the page cache', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Adds one line to wp-config.php so cached pages get limits and blocks.', 'scrapelock' ), __( 'Page caches such as WP Rocket serve stored pages before any plugin loads, so a bot that looks like a browser could read them without a limit. This adds one line at the top of wp-config.php that loads a small check before the cache: always-blocked IPs, temporarily blocked IPs and the “Pages per minute” limit. Counters are kept in APCu or in a folder of the uploads directory (uploads/scrapelock). Search engines, logged-in users, forms, wp-admin and the REST API are left to the normal check. The line and the files are removed when you turn this off or deactivate the plugin.', 'scrapelock' ) ) );
						self::render_precheck_status( $s );
					}
					?>
				</td>
			</tr>
			<tr id="pncp-sec-bunny-logs">
				<th scope="row"><?php esc_html_e( 'Bunny CDN logs', 'scrapelock' ); ?></th>
				<td>
					<?php
					// 3.8: PNCP_Bunny. The connection, Edge Rules and "Import now" are in the Bunny card under
					// "Blocking at the CDN".
					self::checkbox( $s, 'bunny_import', __( 'Import attacks from Bunny CDN\'s logs', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Records attacks on cached pages every 15 minutes. Needs pull zone logging.', 'scrapelock' ), __( 'Every 15 minutes ScrapeLock reads the new lines of the pull zone\'s log and records the attacks on pages Bunny served from its cache, which never reached WordPress. Needs logging on at the pull zone.', 'scrapelock' ) ) );
					self::checkbox( $s, 'bunny_all_lines', __( 'Also record requests that reached WordPress', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'On: also log attack lines that reached WordPress.', 'scrapelock' ), __( 'Off: only requests Bunny answered itself are recorded (WordPress already recorded the others). On: every attack-looking line, for sites where a page cache in front of WordPress hides requests.', 'scrapelock' ) ) );
					self::number( $s, 'bunny_flood_4xx', __( 'Errors per IP that count as a flood (0 = off):', 'scrapelock' ), __( 'This many 404s or refusals in one import count as a 4xx flood.', 'scrapelock' ) );
					self::checkbox( $s, 'bunny_strikes', __( 'Count IPs that are too fast at the CDN toward a temporary block', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'A minute over the CDN limit below counts as a violation.', 'scrapelock' ), __( 'Uses the logs: every minute in which an IP asked Bunny for more pages than the limit below is a violation, also when Bunny served them from its cache. Not in Monitor only, and not when Bunny anonymizes IPs.', 'scrapelock' ) ) );
					self::number( $s, 'bunny_rate', __( 'Pages per minute and IP at the CDN (0 = off):', 'scrapelock' ), __( 'Images, styles, scripts and fonts do not count.', 'scrapelock' ) );
					self::textarea( $s, 'bunny_login_allow', __( 'Allowed IPs for the login page at Bunny, one per line:', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Only these IPs reach wp-login.php when it is locked at Bunny.', 'scrapelock' ), __( 'When wp-login.php is locked at Bunny, only these IPs and ranges get through (an IPv6 /64 such as 2001:db8:1:2::/64 too). The lock is refused while the list is empty or does not hold your IP; the Bunny card under “Blocking at the CDN” suggests the IPs administrators used in the last 30 days.', 'scrapelock' ) ), 3 );
					?>
				</td>
			</tr>
			</table>
		</details>
		<?php
		self::form_close( false );
		// Blocking at the CDN has a form of its own (the API token never goes through the settings form), so it
		// is folded separately, after the settings form and its Save button, and says that it saves only itself.
		$edge   = PNCP_Edge::state();
		$usable = PNCP_Edge::usable();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only decides whether a part is shown open.
		$message = isset( $_GET['pncp_message'] ) ? sanitize_key( wp_unslash( $_GET['pncp_message'] ) ) : '';
		$open    = 0 === strpos( $message, 'edge' ) || ( $usable && ( '' !== $edge['error'] || ! empty( $s['trust_any_proxy'] ) ) )
			|| false !== get_transient( 'pncp_bunny_msg_' . get_current_user_id() ) // 3.8: after a click on the Bunny card.
			|| PNCP_Edge::trust_warning_due( $s ) // 3.9: Bunny in use, its addresses not trusted.
			|| PNCP_Edge::section_requested() // 3.9: back from one of its own buttons (Save, Test, Import now, Lock…).
			|| PNCP_Admin_Sections::requested( 'pncp-sec-edge' ); // 3.10: open when the settings form was saved.
		printf(
			'<details class="pncp-advanced" id="pncp-sec-edge"%1$s><summary><h2 class="pncp-advanced__title">%2$s</h2> <span class="pncp-advanced__state">%3$s</span></summary>',
			$open ? ' open' : '',
			esc_html__( 'Blocking at the CDN (advanced)', 'scrapelock' ),
			esc_html(
				$usable && ! PNCP_Edge::send_blocks() && ! PNCP_Edge::count()
					/* translators: %s: CDN name */
					? sprintf( __( '%s: connected, temporary blocks not sent', 'scrapelock' ), PNCP_Edge::providers()[ PNCP_Edge::config()['provider'] ] ) // 3.9.
					: ( $usable
					/* translators: 1: CDN name, 2: number of addresses */
					? sprintf( _n( '%1$s: %2$s address blocked now', '%1$s: %2$s addresses blocked now', PNCP_Edge::count(), 'scrapelock' ), PNCP_Edge::providers()[ PNCP_Edge::config()['provider'] ], number_format_i18n( PNCP_Edge::count() ) )
					: __( 'Off', 'scrapelock' ) )
			)
		);
		self::render_edge( $s );
		PNCP_Bunny::render_card(); // 3.8: Bunny CDN logs and Edge Rules (own forms).
		echo '</details>';
		self::render_ip_lists();
		PNCP_Admin_Accordion::stop();
	}

	/**
	 * Blocking at the CDN: its own form (the token never goes through the settings form, and is never shown).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_edge( $s ) {
		$c      = PNCP_Edge::config();
		$state  = PNCP_Edge::state();
		$locked = PNCP_Lockdown::is_locked();
		?>
		<p class="description pncp-edge-own-save"><strong><?php esc_html_e( 'Its own button saves only the CDN connection, not the settings above.', 'scrapelock' ); ?></strong></p>
		<?php echo PNCP_Admin_Fields::para( __( 'Sends temporary blocks to your CDN, which stops them before your server.', 'scrapelock' ), __( 'With “Send temporary blocks to the CDN” on, the IPs ScrapeLock blocks temporarily are also blocked by your CDN, with your own account. Saving the connection only connects and tests it. A scraper that keeps going is then stopped at the CDN, before its requests reach your server: no PHP, no database, no bandwidth. Each block is removed when the temporary block ends. Only the blocked addresses are sent, with the reason and the end time; nothing about your visitors or content.', 'scrapelock' ), 'pncp-edge-intro' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<?php
		if ( $locked ) {
			echo '<p class="description">' . esc_html__( 'The site is locked: unlock it on the Lockdown tab to change this.', 'scrapelock' ) . '</p>';
		}
		PNCP_Edge::render_trust_warning( $s ); // 3.9.
		if ( ! empty( $s['trust_any_proxy'] ) && PNCP_Edge::usable() ) {
			echo '<div class="pncp-inline-warning"><p>' . esc_html__( 'Paused: the real visitor IP is read from a header without checking the proxy, so anyone could get any address blocked. Turn off “Trust every request” under “Real visitor IP” first.', 'scrapelock' ) . '</p></div>';
		}
		self::action_form_open( 'pncp_edge', 'pncp_edge', 'pncp-edge-form' );
		?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="pncp-edge-provider"><?php esc_html_e( 'CDN', 'scrapelock' ); ?></label></th>
					<td>
						<select id="pncp-edge-provider" name="provider"<?php disabled( $locked ); ?>>
							<option value=""<?php selected( '', $c['provider'] ); ?>><?php esc_html_e( 'Off', 'scrapelock' ); ?></option>
							<?php foreach ( PNCP_Edge::providers() as $key => $label ) : ?>
								<option value="<?php echo esc_attr( $key ); ?>"<?php selected( $key, $c['provider'] ); ?>><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="pncp-edge-zone"><?php esc_html_e( 'Zone ID', 'scrapelock' ); ?></label></th>
					<td>
						<input type="text" class="regular-text code" id="pncp-edge-zone" name="zone" value="<?php echo esc_attr( $c['zone'] ); ?>" autocomplete="off" spellcheck="false" aria-describedby="pncp-edge-zone-help"<?php disabled( $locked ); ?>>
						<?php echo PNCP_Admin_Fields::description( 'pncp-edge-zone-help', PNCP_Admin_Fields::help( __( 'Cloudflare: the Zone ID from Overview. Bunny CDN: the Pull Zone ID.', 'scrapelock' ), __( 'Cloudflare: the Zone ID on the Overview page of your site (32 characters). Bunny CDN: the ID of the Pull Zone that serves this site (a number, in the address of its page in the bunny.net dashboard).', 'scrapelock' ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="pncp-edge-token"><?php esc_html_e( 'API token', 'scrapelock' ); ?></label></th>
					<td>
						<?php if ( PNCP_Edge::token_from_config() ) : ?>
							<p><?php esc_html_e( 'Set in wp-config.php (SCRAPELOCK_EDGE_TOKEN).', 'scrapelock' ); ?></p>
						<?php else : ?>
							<input type="password" class="regular-text" id="pncp-edge-token" name="token" value="" autocomplete="new-password" spellcheck="false" placeholder="<?php echo esc_attr( '' !== $c['token'] ? __( 'Saved. Leave empty to keep it.', 'scrapelock' ) : '' ); ?>" aria-describedby="pncp-edge-token-help"<?php disabled( $locked ); ?>>
						<?php endif; ?>
						<?php echo PNCP_Admin_Fields::description( 'pncp-edge-token-help', PNCP_Admin_Fields::help( __( 'Cloudflare: a token with Firewall Services → Edit. Bunny CDN: the account API key.', 'scrapelock' ), __( 'Cloudflare: create an API token (My Profile → API Tokens → Create Token → Custom token) with the single permission Zone → Firewall Services → Edit, for this zone only. Bunny CDN: the API key of your account (Account settings → API); it gives access to the whole account. The token is stored in the database and never shown again; to keep it out of the database, add define( \'SCRAPELOCK_EDGE_TOKEN\', \'…\' ); to wp-config.php instead.', 'scrapelock' ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
					</td>
				</tr>
			</table>
			<?php if ( ! $locked ) : ?>
				<p><?php submit_button( __( 'Save and test the connection', 'scrapelock' ), 'secondary', 'submit', false, self::submit_attrs() ); ?></p>
			<?php endif; ?>
		</form>
		<?php
		if ( ! PNCP_Edge::usable() ) {
			self::render_diagnosis(); // The check of settings that were not saved because it failed.
			return;
		}
		if ( ! $locked ) {
			self::action_form_open( 'pncp_edge', 'pncp_edge', 'pncp-edge-test' );
			echo '<input type="hidden" name="op" value="diagnose">';
			echo '<p>';
			submit_button( __( 'Test connection', 'scrapelock' ), 'secondary', 'submit', false, self::submit_attrs() );
			echo '</p><p class="description">' . esc_html__( 'Checks the API step by step, then blocks and unblocks a test address.', 'scrapelock' ) . '</p>';
			echo PNCP_Admin_Fields::more( __( 'Checks step by step that the CDN can be reached, that the token is valid, active and has the permissions needed, that the zone exists and is active, and how much of the API rate limit is left. Then blocks the address 203.0.113.x (reserved for documentation, it belongs to nobody) at the CDN, checks that the CDN lists it and removes it again. No setting changes and no visitor is affected.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
			echo '</form>';
		}
		self::render_diagnosis();
		echo '<ul class="pncp-list-status pncp-edge-status">';
		/* translators: 1: number of addresses, 2: CDN name */
		echo '<li>' . esc_html( sprintf( _n( '%1$s address blocked at %2$s now.', '%1$s addresses blocked at %2$s now.', PNCP_Edge::count(), 'scrapelock' ), number_format_i18n( PNCP_Edge::count() ), PNCP_Edge::providers()[ $c['provider'] ] ) ) . '</li>';
		if ( $state['time'] ) {
			/* translators: %s: date and time */
			echo '<li>' . esc_html( sprintf( __( 'Last update: %s', 'scrapelock' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $state['time'] ) ) ) . '</li>';
		}
		if ( '' !== $state['error'] ) {
			/* translators: 1: date and time, 2: error message */
			echo '<li class="pncp-edge-error"><strong>' . esc_html( sprintf( __( 'Last error (%1$s): %2$s', 'scrapelock' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $state['error_time'] ), $state['error'] ) ) . '</strong></li>';
		}
		$dropped = array();
		foreach ( $state['dropped'] as $item ) {
			if ( isset( $item['key'], $item['time'] ) && (int) $item['time'] > time() - 30 * DAY_IN_SECONDS ) {
				$dropped[] = (string) $item['key'];
			}
		}
		if ( $dropped ) {
			/* translators: %s: list of IP addresses */
			echo '<li class="pncp-edge-error">' . esc_html( sprintf( __( 'These blocks could not be removed at the CDN by ScrapeLock; remove them in the CDN dashboard: %s', 'scrapelock' ), implode( ', ', array_slice( array_unique( $dropped ), 0, 20 ) ) ) ) . '</li>';
		}
		if ( 'bunny' === $c['provider'] ) {
			echo '<li>' . esc_html__( 'Bunny CDN blocks single addresses: a blocked IPv6 network (/64) stays blocked by ScrapeLock only.', 'scrapelock' ) . '</li>';
		}
		echo '<li>' . esc_html__( 'Never blocked at the CDN: the IPs administrators used in the last 30 days (a block at the CDN also covers wp-admin), search engines, AI search services and the CDN\'s own servers.', 'scrapelock' ) . '</li>';
		echo '</ul>';
		PNCP_Edge::render_send_switch( $s ); // 3.9.
	}

	/**
	 * Cloudflare detected: if every visitor appears with a Cloudflare address, a warning with a one-click
	 * fix (CF-Connecting-IP, trusted only from Cloudflare). Outside the settings form, which cannot hold a second form.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_cloudflare_hint( $s ) {
		if ( 'cloudflare' === PNCP_Ip::cdn_hides_visitors() ) {
			?>
			<div class="notice notice-warning inline">
				<p><strong><?php esc_html_e( 'The site is behind Cloudflare, but all visitors appear with a Cloudflare address.', 'scrapelock' ); ?></strong>
				<?php esc_html_e( 'Then limits and blocks hit Cloudflare itself, i.e. many visitors at once. Use the CF-Connecting-IP header, trusted only when the request comes from Cloudflare.', 'scrapelock' ); ?></p>
				<?php self::action_form_open( 'pncp_cf_ip', 'pncp_cf_ip' ); ?>
					<p><?php submit_button( __( 'Use CF-Connecting-IP (recommended)', 'scrapelock' ), 'primary', 'submit', false, self::submit_attrs() ); ?></p>
				</form>
			</div>
			<?php
			return;
		}
		if ( 'remote_addr' === $s['ip_header'] && PNCP_Ip::behind_cloudflare() && ! PNCP_Ip::remote_is_cloudflare() ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Cloudflare detected. REMOTE_ADDR already holds the visitor\'s IP (the Cloudflare plugin or the server replaced it), so “REMOTE_ADDR” is the right choice.', 'scrapelock' ) . '</p></div>';
			return;
		}
		self::render_bunny_hint( $s );
	}

	/**
	 * State of the pre-cache check under its setting: running, or why not (with the line to add by hand).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_precheck_status( $s ) {
		if ( empty( $s['precheck'] ) || empty( $s['enabled'] ) ) {
			return;
		}
		if ( PNCP_Precheck::active() ) {
			echo '<p class="description pncp-precheck-status">' . esc_html__( 'Running: wp-config.php loads the check before the page cache.', 'scrapelock' ) . ' ';
			echo esc_html( function_exists( 'apcu_enabled' ) && apcu_enabled() ? __( 'Counters: APCu.', 'scrapelock' ) : __( 'Counters: files in uploads/scrapelock.', 'scrapelock' ) );
			echo '</p>';
			return;
		}
		$status = (string) get_option( PNCP_Precheck::STATUS, '' );
		echo '<div class="pncp-inline-warning pncp-precheck-status"><p>';
		if ( 'no_files' === $status ) {
			esc_html_e( 'Not running: the folder uploads/scrapelock could not be created (the server does not allow direct file writes). The normal check works as before.', 'scrapelock' );
		} else {
			esc_html_e( 'Not running yet: wp-config.php could not be changed (not writable, or it does not start with “<?php” on its own line). Add these lines right after the first line (<?php) of wp-config.php, then reload this page:', 'scrapelock' );
			echo '</p>';
			self::code_block( 'pncp-precheck-lines', PNCP_Precheck::block(), 3 );
			echo '<p>';
			esc_html_e( 'If you remove the setting later, remove the lines too: without the plugin they do nothing.', 'scrapelock' );
		}
		echo '</p></div>';
	}

	/**
	 * Bunny CDN detected (CDN-ServerId / Via: BunnyCDN): either REMOTE_ADDR already holds the visitor's IP
	 * (the server replaced it, e.g. Nginx real_ip), or every visitor appears with a Bunny address and a
	 * one-click fix is offered (X-Real-IP, trusted only from Bunny edge servers).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_bunny_hint( $s ) {
		if ( ! PNCP_Ip::behind_bunny() ) {
			return;
		}
		$real   = isset( $_SERVER['HTTP_X_REAL_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) : '';
		$remote = PNCP_Ip::remote_addr();
		if ( '' !== $real && $real === $remote ) {
			if ( 'remote_addr' === $s['ip_header'] ) {
				echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Bunny CDN detected. REMOTE_ADDR already holds the visitor\'s IP (the server replaced it), so “REMOTE_ADDR” is the right choice.', 'scrapelock' ) . '</p></div>';
			}
			return;
		}
		if ( 'bunny' !== PNCP_Ip::cdn_hides_visitors() ) {
			return;
		}
		?>
		<div class="notice notice-warning inline">
			<p><strong><?php esc_html_e( 'The site is behind Bunny CDN, but all visitors appear with a Bunny address.', 'scrapelock' ); ?></strong>
			<?php esc_html_e( 'Then limits and blocks hit Bunny itself, i.e. many visitors at once. Use the X-Real-IP header, trusted only when the request comes from a Bunny edge server (the official list is downloaded now).', 'scrapelock' ); ?></p>
			<?php self::action_form_open( 'pncp_bunny_ip', 'pncp_bunny_ip' ); ?>
				<p><?php submit_button( __( 'Use X-Real-IP from Bunny (recommended)', 'scrapelock' ), 'primary', 'submit', false, self::submit_attrs() ); ?></p>
			</form>
		</div>
		<?php
	}

	/**
	 * 3.7: the state of the CrowdSec blocklist, with "Sync now", in the card of the IP lists (outside the settings
	 * form, so its button is a form of its own).
	 */
	private static function render_crowdsec_status() {
		$s = PNCP_Options::get();
		if ( ! PNCP_Crowdsec::enabled( $s ) ) {
			return;
		}
		$state  = PNCP_Crowdsec::state();
		$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		echo '<h3>' . esc_html__( 'CrowdSec blocklist', 'scrapelock' ) . '</h3><p>';
		if ( $state['synced'] ) {
			echo esc_html(
				sprintf(
					/* translators: 1: number of addresses, as words and figures; 2: number of ranges, likewise; 3: date */
					__( '%1$s and %2$s, updated %3$s.', 'scrapelock' ),
					/* translators: %s: number of IP addresses */
					sprintf( _n( '%s address', '%s addresses', (int) $state['count'], 'scrapelock' ), number_format_i18n( (int) $state['count'] ) ),
					/* translators: %s: number of IP ranges */
					sprintf( _n( '%s range', '%s ranges', (int) $state['ranges'], 'scrapelock' ), number_format_i18n( (int) $state['ranges'] ) ),
					wp_date( $format, (int) $state['synced'] )
				)
			);
		} else {
			esc_html_e( 'Not downloaded yet.', 'scrapelock' );
		}
		echo '</p>';
		if ( '' !== (string) $state['error'] ) {
			printf(
				'<p class="pncp-inline-warning">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: date, 2: error message */
						__( 'Last attempt failed (%1$s): %2$s', 'scrapelock' ),
						wp_date( $format, (int) $state['error_at'] ),
						(string) $state['error']
					)
				)
			);
		}
		self::action_form_open( 'pncp_log', 'pncp_log' );
		echo '<input type="hidden" name="op" value="crowdsec_sync">';
		submit_button( __( 'Sync now', 'scrapelock' ), 'secondary', 'submit', false, self::submit_attrs() );
		echo '</form>';
	}

	/**
	 * Status of the official IP lists.
	 */
	private static function render_ip_lists() {
		$updated = PNCP_Ip::lists_updated();
		$names   = array(
			'google'          => 'Google',
			'bing'            => 'Bing',
			'apple'           => 'Applebot',
			'duckduckgo'      => 'DuckDuckBot',
			'cloudflare'      => 'Cloudflare',
			'bunny'           => 'Bunny CDN',
			'openai_search'   => 'OpenAI OAI-SearchBot',
			'openai_user'     => 'OpenAI ChatGPT-User',
			'perplexity_bot'  => 'PerplexityBot',
			'perplexity_user' => 'Perplexity-User',
			'anthropic'       => 'Anthropic (Claude-SearchBot, Claude-User)',
		);
		$needed  = PNCP_Ip::needed_lists();
		// The AI search lists are shown only when they are used or have been downloaded.
		foreach ( PNCP_Bots::ai_bot_lists() as $list ) {
			if ( empty( $updated[ $list ] ) && ! in_array( $list, $needed, true ) ) {
				unset( $names[ $list ] );
			}
		}
		?>
		<?php // 3.11: a folded part of the accordion, under "Advanced". ?>
		<details class="pncp-advanced pncp-acc pncp-acc--lists" id="pncp-acc-lists"<?php echo self::ip_lists_open() ? ' open' : ''; ?>>
		<summary><h2 class="pncp-advanced__title" id="pncp-sec-lists"><?php esc_html_e( 'Official IP lists', 'scrapelock' ); ?></h2></summary>
		<section class="pncp-ip-lists" aria-labelledby="pncp-sec-lists">
		<ul class="pncp-list-status">
			<?php foreach ( $names as $key => $label ) : ?>
				<li>
					<strong><?php echo esc_html( $label ); ?>:</strong>
					<?php
					if ( empty( $updated[ $key ] ) ) {
						if ( 'cloudflare' === $key && ! in_array( 'cloudflare', $needed, true ) ) {
							echo esc_html__( 'not used with the current “Real visitor IP” setting (the built-in list is enough to detect Cloudflare)', 'scrapelock' );
						} elseif ( 'cloudflare' === $key ) {
							echo esc_html__( 'built-in list (not downloaded yet)', 'scrapelock' );
						} elseif ( 'bunny' === $key && ! in_array( 'bunny', $needed, true ) ) {
							echo esc_html__( 'not used with the current settings', 'scrapelock' );
						} elseif ( 'duckduckgo' === $key || in_array( $key, PNCP_Bots::ai_bot_lists(), true ) ) {
							echo esc_html__( 'not downloaded yet, no verification until then', 'scrapelock' );
						} else {
							echo esc_html__( 'not downloaded yet, only DNS is used', 'scrapelock' );
						}
					} else {
						echo esc_html(
							sprintf(
								/* translators: 1: number of addresses, 2: date */
								__( '%1$s addresses, updated %2$s', 'scrapelock' ),
								number_format_i18n( count( PNCP_Ip::list_of( $key ) ) ),
								wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $updated[ $key ] )
							)
						);
						self::ai_list_extra_note( $key );
					}
					?>
				</li>
			<?php endforeach; ?>
		</ul>
		<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
			<input type="hidden" name="op" value="refresh_lists">
			<?php submit_button( __( 'Refresh lists now', 'scrapelock' ), 'secondary', 'submit', false, self::submit_attrs() ); ?>
		</form>
		<?php self::render_crowdsec_status(); ?>
		<?php if ( PNCP_Geo::needed() ) : ?>
			<h3><?php esc_html_e( 'Country database', 'scrapelock' ); ?></h3>
			<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
				<input type="hidden" name="op" value="refresh_geo">
				<p class="description"><?php esc_html_e( 'Downloads DB-IP Lite now (about 5 MB, it may take up to a minute). It is also refreshed automatically once a month.', 'scrapelock' ); ?></p>
				<?php submit_button( __( 'Download now', 'scrapelock' ), 'secondary', 'submit', false, self::submit_attrs() ); ?>
			</form>
		<?php endif; ?>
		</section>
		</details>
		<?php
	}

	/**
	 * 3.11: whether the folded "Official IP lists" part opens: it was open when a form was saved, or one of its
	 * own buttons (Refresh lists now, CrowdSec, Download now) just answered.
	 *
	 * @return bool
	 */
	private static function ip_lists_open() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only decides whether a part is shown open.
		$message = isset( $_GET['pncp_message'] ) ? sanitize_key( wp_unslash( $_GET['pncp_message'] ) ) : '';
		return PNCP_Admin_Sections::requested( 'pncp-acc-lists' )
			|| in_array( $message, array( 'lists', 'lists_partial', 'crowdsec', 'crowdsec_failed', 'geo', 'geo_failed' ), true );
	}

	/**
	 * "Feeds and API" tab.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_content( $s ) {
		self::render_tokens( $s );
		self::form_open( 'content' );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Protected feeds', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::textarea( $s, 'private_paths', __( 'Paths that are not public (one per line, * means “anything”), e.g. /skroutz.xml, /feeds/*.xml, or a feed served with a query, e.g. /?feed=skroutz:', 'scrapelock' ) );
				self::textarea( $s, 'private_ips', __( 'Or allowed IPs / CIDR of the service (one per line):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'No valid token or allowed IP: 403. PHP feeds only.', 'scrapelock' ), __( 'Without a valid token or an allowed IP it returns 403. Applies to feeds generated by PHP. For static .xml files see the “Server rules” tab.', 'scrapelock' ) ), 3 );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'REST API', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'rest_hide_content', __( 'Hide the text (content, excerpt) of posts, pages and products from visitors', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Forms, oEmbed and SEO plugins keep working; writers still see the text.', 'scrapelock' ), __( 'REST stays open for forms, oEmbed, SEO plugins and your own endpoints. Users who can write posts see the text normally. Exceptions from code: filter pncp_rest_hide_content.', 'scrapelock' ) ) );
				self::checkbox( $s, 'hide_rest_discovery', __( 'Hide the REST API map from visitors', 'scrapelock' ), PNCP_Admin_Fields::help( __( '/wp-json/ stops listing your routes; every route still works.', 'scrapelock' ), __( '/wp-json/ no longer lists the namespaces and routes (a map of your plugins), and the page head and the Link header no longer point to the REST API and to oEmbed. Every route keeps working when called; logged-in users see everything. Leave it off if an app or service reads /wp-json/ to discover your site.', 'scrapelock' ) ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'GraphQL', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'graphql_hide_content', __( 'Hide the text in WPGraphQL (content, excerpt, product descriptions)', 'scrapelock' ) );
				echo '<p class="description">' . esc_html( PNCP_Graphql::active() ? __( 'WPGraphQL is active: the bot check, blocks and the REST / GraphQL limit apply too.', 'scrapelock' ) : __( 'WPGraphQL is not installed; the setting will apply if you install it.', 'scrapelock' ) ) . '</p>';
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'RSS / Atom feeds', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::radios(
					$s,
					'feed_mode',
					__( 'RSS / Atom feeds', 'scrapelock' ),
					array(
						'excerpt'  => __( 'Short excerpt only, with a link to the post (recommended)', 'scrapelock' ),
						'full'     => __( 'Full text', 'scrapelock' ),
						'disabled' => __( 'Disabled', 'scrapelock' ),
					)
				);
				self::checkbox( $s, 'feed_source_link', __( 'Full text: add “The post … first appeared on …” at the end', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Republishing sites then link back to the original article.', 'scrapelock' ), __( 'Sites that republish the feed automatically then link back to the original article, so search engines see where it first appeared.', 'scrapelock' ) ) );
				self::checkbox( $s, 'list_excerpts', __( 'Lists of articles: an excerpt and a link instead of the full text', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Lists show an excerpt and a link; article pages do not change.', 'scrapelock' ), __( 'Many themes print the whole text of every article on the home page, in categories, archives and search, so one request gives a scraper ten articles. With this on, visitors see an excerpt and a “Read the full article” link there, and each article has to be opened (and counted toward the page limit) on its own. The article pages do not change; the staff in “Who is excluded” see the full text. Changes how your lists look, so check them after turning it on. Always on in Emergency Mode.', 'scrapelock' ) ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'XML-RPC', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'disable_pingback', __( 'Turn off pingbacks', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Removes the pingback methods and header; other XML-RPC keeps working.', 'scrapelock' ), __( 'pingback.ping stays open even when XML-RPC is "disabled", and is used to make your site send requests to other sites or to check which pages exist. This removes the two pingback methods and the X-Pingback header; other XML-RPC methods (e.g. Jetpack) keep working. You no longer receive pingbacks from other blogs.', 'scrapelock' ) ) ); ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Versions', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'hide_fingerprint', __( 'Hide that the site runs on WordPress, as far as possible', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Removes the WordPress traces scanners look for, for signed-out visitors.', 'scrapelock' ), __( 'For visitors who are not signed in: everything “Hide the versions” below does, plus no REST API, oEmbed, RSD and shortlink links in the page head and headers, no emoji script, no X-Pingback and “X-Redirect-By: WordPress” headers. Tools such as BuiltWith and Wappalyzer, and scanners, look for these first. Everything keeps working. It cannot hide everything: the addresses of themes and plugins (/wp-content/…) still show it, and the hosting and DNS of a site are public anyway. Add the Nginx or Apache rules (Server rules tab) to refuse readme.html and license.txt too.', 'scrapelock' ) ) ); ?>
				<?php self::render_stealth_pointer(); ?>
				<?php self::checkbox( $s, 'hide_versions', __( 'Hide the versions of WordPress, PHP and the plugins', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Removes generator tags, X-Powered-By and ?ver= numbers scanners look up.', 'scrapelock' ), __( 'Scanners read these versions and look them up in lists of known vulnerabilities. This removes the “generator” tag from the page head and the feeds, the X-Powered-By header with the PHP version, and replaces “?ver=7.1.3” on CSS and JS files with a code that changes when the version changes, so caches still work. The readme and changelog files of WordPress and the plugins are static files: the Nginx and Apache rules in the “Server rules” tab refuse them. It does not fix any vulnerability: keep WordPress and the plugins updated.', 'scrapelock' ) ) ); ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Uploads', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'block_upload_php', __( 'No PHP in the uploads folder', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Refuses every PHP file under uploads, where backdoors usually land.', 'scrapelock' ), __( 'Files uploaded to the site (images, documents) never need to run as code. A backdoor uploaded through a vulnerable plugin usually lands in the uploads folder, so this refuses every PHP file there. On Apache it is written into the .htaccess of the uploads folder at once; on Nginx add the rule from the “Server rules” tab. If a plugin of yours really runs PHP from the uploads folder (rare), leave it off.', 'scrapelock' ) ) ); ?>
			</td>
		</tr>
		<?php
		self::form_close();
		self::render_public_routes();
	}

	/**
	 * REST routes anyone can call without logging in (a report, nothing is changed).
	 */
	private static function render_public_routes() {
		$open  = PNCP_Surface::public_routes();
		$total = 0;
		foreach ( $open as $routes ) {
			$total += count( $routes );
		}
		?>
		<section class="pncp-card pncp-card--wide pncp-public-routes-card" aria-labelledby="pncp-public-routes-title">
		<h2 id="pncp-public-routes-title"><?php esc_html_e( 'REST routes open to everyone', 'scrapelock' ); ?> <span class="pncp-badge"><?php echo esc_html( number_format_i18n( $total ) ); ?></span></h2>
		<?php /* translators: %d: number of routes */ ?>
		<p><?php echo esc_html( sprintf( _n( '%d route can be called without logging in, because its permission is open to everyone. Check after installing a plugin or updating WordPress whether a new one gives out content or data it should not.', '%d routes can be called without logging in, because their permission is open to everyone. Check after installing a plugin or updating WordPress whether a new one gives out content or data it should not.', $total, 'scrapelock' ), $total ) ); ?> <?php esc_html_e( 'Routes with their own permission check (e.g. published posts) are not listed: their text is covered by "Hide the text" above.', 'scrapelock' ); ?></p>
		<details class="pncp-public-routes">
			<summary><?php esc_html_e( 'Show the routes', 'scrapelock' ); ?></summary>
			<div class="pncp-table-wrap">
			<table class="widefat striped">
				<thead><tr><th><?php esc_html_e( 'Namespace', 'scrapelock' ); ?></th><th><?php esc_html_e( 'Route', 'scrapelock' ); ?></th><th><?php esc_html_e( 'Methods', 'scrapelock' ); ?></th></tr></thead>
				<tbody>
					<?php foreach ( $open as $namespace => $routes ) : ?>
						<?php foreach ( $routes as $route => $methods ) : ?>
							<tr><td><code><?php echo esc_html( $namespace ); ?></code></td><td><code><?php echo esc_html( $route ); ?></code></td><td><?php echo esc_html( implode( ', ', $methods ) ); ?></td></tr>
						<?php endforeach; ?>
					<?php endforeach; ?>
				</tbody>
			</table>
			</div>
		</details>
		</section>
		<?php
	}

	/**
	 * Token, per-service URLs and feed statistics.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_tokens( $s ) {
		$data  = PNCP_Private_Urls::token_data();
		$key   = 'pncp_new_token_' . get_current_user_id();
		$fresh = (string) get_transient( $key );
		if ( '' !== $fresh ) {
			delete_transient( $key ); // Shown only once.
		}
		$paths = PNCP_Options::parse_list( $s['private_paths'] );
		$stats = PNCP_Private_Urls::stats();
		?>
		<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-token-title">
			<h2 id="pncp-token-title"><?php esc_html_e( 'Access token', 'scrapelock' ); ?></h2>
			<?php if ( '' !== $fresh ) : ?>
				<div class="notice notice-success inline pncp-fresh-token">
					<p><strong><?php esc_html_e( 'New token. Copy it now: it will not be shown again.', 'scrapelock' ); ?></strong></p>
					<p><code id="pncp-token-value" class="pncp-token"><?php echo esc_html( $fresh ); ?></code> <button type="button" class="button pncp-copy" data-target="pncp-token-value"><?php esc_html_e( 'Copy', 'scrapelock' ); ?></button></p>
					<p><?php esc_html_e( 'Header for ERP / API:', 'scrapelock' ); ?> <code>X-ScrapeLock-Token: <?php echo esc_html( $fresh ); ?></code> <?php esc_html_e( 'or', 'scrapelock' ); ?> <code>Authorization: Bearer <?php echo esc_html( $fresh ); ?></code></p>
					<?php if ( $paths ) : ?>
						<p><?php esc_html_e( 'URL for Skroutz, BestPrice, Google Merchant (they accept only URLs):', 'scrapelock' ); ?></p>
						<ul>
							<?php foreach ( $paths as $i => $pattern ) : ?>
								<li><code id="pncp-url-<?php echo (int) $i; ?>"><?php echo esc_html( PNCP_Private_Urls::example_url( $pattern, $fresh ) ); ?></code> <button type="button" class="button button-small pncp-copy" data-target="pncp-url-<?php echo (int) $i; ?>"><?php esc_html_e( 'Copy', 'scrapelock' ); ?></button></li>
							<?php endforeach; ?>
						</ul>
					<?php endif; ?>
				</div>
			<?php endif; ?>
			<p>
				<?php
				if ( '' === $data['hash'] ) {
					esc_html_e( 'There is no token. Create one to give the services access.', 'scrapelock' );
				} else {
					echo esc_html(
						sprintf(
							/* translators: 1: last 4 characters, 2: date */
							__( 'Active token ending in …%1$s, since %2$s. Only its hash is stored, so it cannot be shown again.', 'scrapelock' ),
							$data['hint'],
							$data['created'] ? wp_date( get_option( 'date_format' ), $data['created'] ) : '—'
						)
					);
				}
				?>
			</p>
			<?php if ( '' !== $data['prev_hash'] && $data['prev_until'] > time() ) : ?>
				<p class="pncp-inline-warning">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: last 4 characters, 2: date */
							__( 'The previous token (…%1$s) is still valid until %2$s, so you have time to change the URL in the services.', 'scrapelock' ),
							$data['prev_hint'],
							wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $data['prev_until'] )
						)
					);
					?>
				</p>
				<?php self::action_form_open( 'pncp_token', 'pncp_token' ); ?>
					<input type="hidden" name="op" value="revoke_prev">
					<?php submit_button( __( 'Revoke the previous one now', 'scrapelock' ), 'secondary', 'submit', false, self::submit_attrs() ); ?>
				</form>
			<?php endif; ?>
			<?php self::action_form_open( 'pncp_token', 'pncp_token', 'pncp-token-form' ); ?>
				<input type="hidden" name="op" value="rotate">
				<p>
					<?php if ( '' !== $data['hash'] ) : ?>
						<label for="pncp-grace"><?php esc_html_e( 'Keep the current token valid for:', 'scrapelock' ); ?></label>
						<select id="pncp-grace" name="grace">
							<option value="0"><?php esc_html_e( 'Not at all (revoke immediately)', 'scrapelock' ); ?></option>
							<option value="1"><?php esc_html_e( '1 day', 'scrapelock' ); ?></option>
							<option value="7" selected><?php esc_html_e( '7 days', 'scrapelock' ); ?></option>
							<option value="30"><?php esc_html_e( '30 days', 'scrapelock' ); ?></option>
						</select>
					<?php endif; ?>
					<button type="submit" class="button button-primary"><?php echo esc_html( '' === $data['hash'] ? __( 'Create token', 'scrapelock' ) : __( 'New token (rotate)', 'scrapelock' ) ); ?></button>
				</p>
			</form>
			<?php echo PNCP_Admin_Fields::para( __( 'Use the header where you can; the URL only for services that need it.', 'scrapelock' ), __( 'Header for ERP and your own integrations (not visible in logs and history). Token in the URL for Skroutz, BestPrice and Google Merchant, which accept only URLs.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>

			<?php if ( $paths ) : ?>
				<h3><?php esc_html_e( 'Access per feed', 'scrapelock' ); ?></h3>
				<div class="pncp-table-wrap">
				<table class="widefat striped pncp-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Path', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Successes', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Last access', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Via', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Denials', 'scrapelock' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php
						$via_labels = array(
							'header' => __( 'header', 'scrapelock' ),
							'url'    => __( 'token in URL', 'scrapelock' ),
							'ip'     => __( 'allowed IP', 'scrapelock' ),
							'admin'  => __( 'administrator', 'scrapelock' ),
						);
						foreach ( $paths as $pattern ) :
							$row = isset( $stats[ strtolower( $pattern ) ] ) ? $stats[ strtolower( $pattern ) ] : array();
							?>
							<tr>
								<td><code><?php echo esc_html( $pattern ); ?></code></td>
								<td><?php echo esc_html( number_format_i18n( isset( $row['ok'] ) ? (int) $row['ok'] : 0 ) ); ?></td>
								<td><?php echo esc_html( ! empty( $row['last_ok'] ) ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $row['last_ok'] ) . ' · ' . $row['last_ip'] : __( 'Never', 'scrapelock' ) ); ?></td>
								<td><?php echo esc_html( ! empty( $row['last_via'] ) && isset( $via_labels[ $row['last_via'] ] ) ? $via_labels[ $row['last_via'] ] : '—' ); ?></td>
								<td><?php echo esc_html( number_format_i18n( isset( $row['denied'] ) ? (int) $row['denied'] : 0 ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				</div>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * "Images" tab.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_images( $s ) {
		self::form_open( 'images' );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Watermark', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'watermark_enabled', __( 'Watermark new images', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Added to generated sizes; existing images: use the tool below.', 'scrapelock' ), __( 'It is added to the sizes WordPress generates (thumbnails, medium, large). For existing images, use the tool below. The site icon, the logo and the watermark itself never get it.', 'scrapelock' ) ) );
				if ( ! PNCP_Watermark::available() ) {
					echo '<p class="pncp-inline-warning"><strong>' . esc_html__( 'The PHP GD library is missing, so no watermark is applied: ask your host to enable it.', 'scrapelock' ) . '</strong></p>';
				}
				self::checkbox( $s, 'watermark_full', __( 'Watermark the full-size image too', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Otherwise the full image stays clean and downloadable. Originals are kept.', 'scrapelock' ), __( 'Without this, the full image stays clean and can be downloaded from its URL. The clean original is kept in a hidden folder, so it can always be restored.', 'scrapelock' ) ) );
				self::checkbox( $s, 'watermark_products', __( 'Watermark WooCommerce product images too', 'scrapelock' ) );
				?>
				<p class="pncp-inline-warning" id="pncp-products-warning"><?php esc_html_e( 'Not recommended: Google Merchant Center, Skroutz and BestPrice reject product images with a watermark, and feeds usually show the full-size image. For products, hotlink protection (“Server rules” tab) is a better choice. If a watermarked image later becomes a product image, logo or icon, the watermark is removed automatically.', 'scrapelock' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Appearance', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::number( $s, 'watermark_image_id', __( 'PNG image ID from the Media Library (0 = the site\'s domain as text):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'A transparent PNG, e.g. the logo; the ID is in its Library address.', 'scrapelock' ), __( 'A PNG with a transparent background is recommended (e.g. the logo). The ID appears in the address when you open the image in the Library.', 'scrapelock' ) ) );
				?>
				<?php // 3.5: a <div>, not a <p>: select() now prints the requirement note (a <p>) after the select. ?>
				<div class="pncp-field"><label for="pncp-watermark_position"><?php esc_html_e( 'Position:', 'scrapelock' ); ?></label>
				<?php
				self::select(
					$s,
					'watermark_position',
					array(
						'br'     => __( 'Bottom right', 'scrapelock' ),
						'bl'     => __( 'Bottom left', 'scrapelock' ),
						'tr'     => __( 'Top right', 'scrapelock' ),
						'tl'     => __( 'Top left', 'scrapelock' ),
						'center' => __( 'Centre', 'scrapelock' ),
						'tiled'  => __( 'Repeat diagonally across the whole image (hard to remove)', 'scrapelock' ),
					)
				);
				?>
				</div>
				<?php
				self::number( $s, 'watermark_size', __( 'Size (% of the image width):', 'scrapelock' ), __( 'With diagonal repeat, the size of each repetition.', 'scrapelock' ) );
				self::number( $s, 'watermark_opacity', __( 'Opacity (%):', 'scrapelock' ) );
				self::number( $s, 'watermark_min_width', __( 'Only on sizes with width from (px):', 'scrapelock' ), __( 'Small thumbnails stay clean.', 'scrapelock' ) );
				?>
			</td>
		</tr>
		<?php
		self::form_close();
		self::render_watermark_tool( $s );
	}

	/**
	 * Apply / remove tool for existing images.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_watermark_tool( $s ) {
		$total = self::image_count();
		?>
		<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-tool-title">
			<h2 id="pncp-tool-title"><?php esc_html_e( 'Existing images', 'scrapelock' ); ?></h2>
			<p><?php echo esc_html( sprintf( /* translators: %s: count */ __( 'JPEG / PNG / WebP images in the library: %s.', 'scrapelock' ), number_format_i18n( $total ) ) ); ?></p>
			<?php echo PNCP_Admin_Fields::para( __( 'Back up the uploads folder first. An interrupted run resumes where it stopped.', 'scrapelock' ), __( 'Each image is regenerated from the clean original, so a watermark is never added twice, not even on images watermarked by version 1.x. If the page closes midway, click again: it resumes where it stopped. Keep a backup of the uploads folder before you start.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<?php if ( empty( $s['watermark_enabled'] ) ) : ?>
				<p class="pncp-inline-warning"><?php esc_html_e( 'The watermark is off: “Apply” will leave the images clean. Enable it and save first.', 'scrapelock' ); ?></p>
			<?php endif; ?>
			<p class="pncp-tool-buttons">
				<button type="button" class="button button-primary pncp-wm-run" data-mode="apply" data-total="<?php echo (int) $total; ?>"<?php disabled( ! PNCP_Watermark::available() ); ?>><?php esc_html_e( 'Apply watermark', 'scrapelock' ); ?></button>
				<button type="button" class="button pncp-wm-run" data-mode="remove" data-total="<?php echo (int) $total; ?>"><?php esc_html_e( 'Remove watermark', 'scrapelock' ); ?></button>
			</p>
			<div class="pncp-progress" hidden>
				<progress max="100" value="0" aria-labelledby="pncp-progress-text"></progress>
				<p id="pncp-progress-text" role="status" aria-live="polite"></p>
			</div>
		</section>
		<?php
	}

	/**
	 * How many images the library has.
	 *
	 * @return int
	 */
	private static function image_count() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Admin screen.
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_mime_type IN ('image/jpeg','image/png','image/webp')" );
	}

	/**
	 * AJAX: one batch of images. The cursor is the last completed ID.
	 */
	public static function ajax_wm_batch() {
		check_ajax_referer( 'pncp_wm_batch', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'scrapelock' ) ), 403 );
		}
		$mode   = isset( $_POST['mode'] ) && 'remove' === $_POST['mode'] ? 'remove' : 'apply';
		$cursor = isset( $_POST['cursor'] ) ? absint( $_POST['cursor'] ) : 0;
		$other  = 'apply' === $mode ? 'remove' : 'apply';
		if ( 0 === $cursor ) {
			// New run: if the same action was interrupted, it resumes where it stopped. The other
			// action forgets its position (after "Remove", "Apply" starts from the beginning).
			$cursor = (int) get_option( 'pncp_wm_cursor_' . $mode, 0 );
			delete_option( 'pncp_wm_cursor_' . $other );
		}

		global $wpdb;
		$batch = (int) apply_filters( 'pncp_watermark_batch_size', 3 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Tool batch.
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_mime_type IN ('image/jpeg','image/png','image/webp') AND ID > %d ORDER BY ID ASC LIMIT %d", $cursor, max( 1, $batch ) ) );

		$errors = 0;
		foreach ( $ids as $id ) {
			if ( 'error' === PNCP_Watermark::rebuild( (int) $id, 'apply' === $mode ) ) {
				++$errors;
			}
			$cursor = (int) $id;
			update_option( 'pncp_wm_cursor_' . $mode, $cursor, false );
		}
		$done = count( $ids ) < max( 1, $batch );
		if ( $done ) {
			delete_option( 'pncp_wm_cursor_' . $mode );
			// 3.4.3: cached pages still linked the images as they were before the run (clean files after
			// "Apply", watermarked ones after "Remove").
			pncp_purge_page_cache();
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Tool progress.
		$position = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_mime_type IN ('image/jpeg','image/png','image/webp') AND ID <= %d", $cursor ) );
		wp_send_json_success(
			array(
				'cursor'   => $cursor,
				'position' => $position,
				'errors'   => $errors,
				'done'     => $done,
			)
		);
	}

	/**
	 * 3.8: the "Sign-in" part of the Bots and limits tab (PNCP_Login): failed sign-ins per IP and per username,
	 * one error message, and the sign-in address. Part of the Bots tab's settings form.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_login_settings( $s ) {
		self::group_heading( 'login', __( 'Sign-in', 'scrapelock' ), __( 'Password guessing on wp-login.php, XML-RPC and the REST API; the sign-in address.', 'scrapelock' ) );
		self::row_open( 'login', __( 'Failed sign-ins', 'scrapelock' ) );
		self::checkbox( $s, 'login_limit', __( 'Limit failed sign-ins', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Counts wrong passwords on wp-login.php, XML-RPC and application passwords.', 'scrapelock' ), __( 'Counts wrong passwords on wp-login.php, XML-RPC (each call of a system.multicall, the way bots try hundreds of passwords in one request) and application passwords. Too many from one IP block it for a while; too many for one username pause that username.', 'scrapelock' ) ) );
		self::number( $s, 'login_max', __( 'Failed sign-ins per IP before it is blocked:', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Failures for an account already used from that IP do not count.', 'scrapelock' ), __( 'Within the time below. Failures for an account that already signed in from that IP do not count, so a person who forgot the password is not blocked.', 'scrapelock' ) ) );
		self::number( $s, 'login_window', __( '…within this many minutes:', 'scrapelock' ), '' );
		self::number( $s, 'login_ban_minutes', __( 'Block the IP for (minutes):', 'scrapelock' ), __( 'Covers the whole site; listed under “Blocked IPs”.', 'scrapelock' ) );
		self::number( $s, 'login_user_max', __( 'Failed sign-ins per username before it is paused (0 = off):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Counted across all IPs; unknown usernames are paused too.', 'scrapelock' ), __( 'Counted from all IPs together: password guessing spread over many addresses. Usernames that do not exist are paused too, so the answer does not tell which exist.', 'scrapelock' ) ) );
		self::number( $s, 'login_user_minutes', __( 'Pause the username for (minutes):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Its owner can still use known places or the emailed one-time link.', 'scrapelock' ), __( 'Its owner can still sign in from where they signed in before, and with the one-time link emailed to the account.', 'scrapelock' ) ) );
		self::checkbox( $s, 'login_user_email', __( 'Email the account a link to sign in during a pause', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'One email per pause; the link works once, within 24 hours.', 'scrapelock' ), __( 'Once per pause. The link works once, for 24 hours, and lets that browser sign in for 30 days.', 'scrapelock' ) ) );
		self::checkbox( $s, 'login_generic_errors', __( 'One error message for a wrong username, email or password', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Sign-in errors no longer tell bots which usernames exist.', 'scrapelock' ), __( 'WordPress says “The username … is not registered” for an unknown user, which tells bots which usernames exist. “Lost your password” answers the same way for unknown accounts too.', 'scrapelock' ) ) );
		echo '<p class="description"><a href="' . esc_url( PNCP_Status::settings_url( array( 'tab' => 'hardening' ) ) . '#pncp-login-status' ) . '">' . esc_html__( 'Blocked IPs, paused usernames and the usernames tried', 'scrapelock' ) . '</a></p>';
		self::row_close();
		self::row_open( 'login_slug', __( 'Sign-in address', 'scrapelock' ) );
		printf(
			'<div class="pncp-field"><p><label for="pncp-login_slug">%1$s</label><br><code>%2$s</code><input type="text" class="regular-text code" id="pncp-login_slug" name="%3$s[login_slug]" value="%4$s" placeholder="my-login" spellcheck="false" autocomplete="off" pattern="[A-Za-z0-9_\-]{3,50}" aria-describedby="pncp-login_slug-help"></p><p class="description" id="pncp-login_slug-help">%5$s</p>%6$s</div>',
			esc_html__( 'Move the sign-in page to this address (empty = wp-login.php):', 'scrapelock' ),
			esc_html( trailingslashit( home_url( '/' ) ) ),
			esc_attr( PNCP_OPTION ),
			esc_attr( (string) $s['login_slug'] ),
			esc_html__( 'Visitors then get “page not found” at wp-login.php and /wp-admin/. Write it down.', 'scrapelock' ),
			PNCP_Admin_Fields::more( __( 'wp-login.php and /wp-admin/ then answer “page not found” to visitors who are not signed in, so password-guessing bots find nothing there; links, emails and redirects use the new address. Write it down. If you lose it, add define( \'SCRAPELOCK_LOGIN_SLUG_OFF\', true ); to wp-config.php. In Monitor only both addresses work. Letters, digits, “-” and “_”; not login, admin or an address a page already has.', 'scrapelock' ) ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in more().
		);
		if ( '' !== PNCP_Login::slug() ) {
			echo '<p>' . esc_html__( 'Sign in at:', 'scrapelock' ) . ' <a href="' . esc_url( PNCP_Login::login_url() ) . '"><code>' . esc_html( PNCP_Login::login_url() ) . '</code></a></p>';
		}
		self::row_close();
	}

	/**
	 * 3.8: on the Feeds and API tab, next to "Hide that the site runs on WordPress": where Stealth is, and its state.
	 */
	private static function render_stealth_pointer() {
		$on = PNCP_Stealth::active();
		printf(
			'<p class="description pncp-stealth-pointer"><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p>%5$s',
			esc_html( $on ? __( 'Stealth is on.', 'scrapelock' ) : __( 'More: Stealth.', 'scrapelock' ) ),
			esc_html__( 'Neutral addresses instead of /wp-content/, plus both settings here.', 'scrapelock' ),
			esc_url( PNCP_Status::settings_url( array( 'tab' => PNCP_Stealth::tab() ) ) . '#pncp-stealth' ),
			esc_html__( 'Stealth settings', 'scrapelock' ),
			PNCP_Admin_Fields::more( __( 'It also gives visitors and tools such as BuiltWith and Wappalyzer neutral addresses instead of /wp-content/ and /wp-includes/, another REST prefix and /sitemap.xml, and refuses readme.html, after testing the server rules. It includes the two settings here.', 'scrapelock' ) ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in more().
		);
	}

	/**
	 * 3.8: the Attacks tab: the full attack report (PNCP_Attack_Report), and deleting the record.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_attacks( $s ) {
		PNCP_Attack_Report::render_tab( $s );
		if ( ! PNCP_Attacks::ready() ) {
			return;
		}
		$locked = PNCP_Lockdown::is_locked();
		?>
		<section class="pncp-card pncp-card--wide" id="pncp-attacks-settings" aria-labelledby="pncp-attacks-settings-title">
			<h2 id="pncp-attacks-settings-title"><?php esc_html_e( 'The attack record', 'scrapelock' ); ?></h2>
			<p class="description">
				<?php
				echo esc_html(
					empty( $s['attack_record'] )
						? __( 'Recording is off: only what was there before is shown.', 'scrapelock' )
						/* translators: %s: number of days */
						: sprintf( _n( 'Recording is on; IPs and usernames tried are deleted after %s day.', 'Recording is on; IPs and usernames tried are deleted after %s days.', PNCP_Attacks::retention(), 'scrapelock' ), number_format_i18n( PNCP_Attacks::retention() ) )
				);
				?>
				<a href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => 'log' ) ) . '#pncp-sec-attack-record' ); ?>"><?php esc_html_e( 'Attack record settings', 'scrapelock' ); ?></a>
			</p>
			<?php self::action_form_open( 'pncp_attacks_clear', 'pncp_attacks_clear', 'pncp-inline-form' ); ?>
				<button type="submit" class="button button-link-delete" data-pncp-confirm="<?php esc_attr_e( 'Delete the whole attack record? This cannot be undone.', 'scrapelock' ); ?>"<?php disabled( $locked ); ?>><?php esc_html_e( 'Delete the attack record', 'scrapelock' ); ?></button>
				<?php if ( $locked ) : ?>
					<span class="description"><?php esc_html_e( 'Unlock the site on the Lockdown tab to delete it.', 'scrapelock' ); ?></span>
				<?php endif; ?>
			</form>
		</section>
		<?php
	}

	/**
	 * 3.12: the Traffic tab (PNCP_Admin_Traffic).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_traffic( $s ) {
		PNCP_Admin_Traffic::render( $s );
	}

	/**
	 * 3.12: the settings form of the Traffic tab (section "traffic"), with the same fields as the other tabs.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	public static function render_traffic_settings( $s ) {
		$path_id = 'pncp-traffic_log_path';
		self::form_open( 'traffic' );
		?>
		<tr id="pncp-sec-traffic">
			<th scope="row"><?php esc_html_e( 'Collect', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'traffic', __( 'Collect traffic (every request the site answers)', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Off: nothing is read, stored or scheduled.', 'scrapelock' ), __( 'The requests come from the Bunny CDN logs while their import is on, from the access log below, or from WordPress itself. Only one source is counted at a time, so a request seen by two of them is never counted twice.', 'scrapelock' ) ) );
				self::checkbox( $s, 'traffic_wp', __( 'Also record the pages WordPress serves itself', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Fallback without a CDN or access log; misses cached pages.', 'scrapelock' ), __( 'One row per page that PHP answers, at the end of the request, with its response time. Pages served from a page cache (WP Rocket, the CDN) never reach PHP, so they are missing here; wp-admin, AJAX, cron, signed-in administrators and the site\'s requests to itself are left out.', 'scrapelock' ) ) );
				// Traffic alerts (PNCP_Traffic_Alerts).
				self::checkbox( $s, 'traffic_alerts', PNCP_Setting_Labels::label( 'traffic_alerts' ), __( 'An email when errors or a source stop look wrong.', 'scrapelock' ) );
				$mail_id = 'pncp-traffic_alert_email';
				printf(
					'<div class="pncp-field"><p><label for="%1$s">%2$s</label></p><input type="text" class="regular-text" id="%1$s" name="%3$s[traffic_alert_email]" value="%4$s" maxlength="500" placeholder="%5$s" aria-describedby="%1$s-help">%6$s</div>',
					esc_attr( $mail_id ),
					esc_html__( 'Send the alerts to:', 'scrapelock' ),
					esc_attr( PNCP_OPTION ),
					esc_attr( isset( $s['traffic_alert_email'] ) ? (string) $s['traffic_alert_email'] : '' ),
					esc_attr( (string) get_option( 'admin_email' ) ),
					PNCP_Admin_Fields::description( $mail_id . '-help', __( 'Empty = the site\'s admin email; separate several with commas.', 'scrapelock' ) ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in description().
				);
				?>
			</td>
		</tr>
		<tr id="pncp-sec-traffic-log">
			<th scope="row"><label for="<?php echo esc_attr( $path_id ); ?>"><?php esc_html_e( 'Access log', 'scrapelock' ); ?></label></th>
			<td>
				<div class="pncp-field">
					<input type="text" class="regular-text code" id="<?php echo esc_attr( $path_id ); ?>" name="<?php echo esc_attr( PNCP_OPTION ); ?>[traffic_log_path]" value="<?php echo esc_attr( (string) $s['traffic_log_path'] ); ?>" maxlength="500" placeholder="/var/log/nginx/access.log" aria-describedby="<?php echo esc_attr( $path_id ); ?>-help"<?php disabled( ! PNCP_Traffic_Log::user_may_read() ); ?>>
					<?php
					echo PNCP_Admin_Fields::description( $path_id . '-help', PNCP_Admin_Fields::help( __( 'Full path of the Nginx or Apache access log; empty = not read.', 'scrapelock' ), __( 'The "combined" log format and its common variants are read, also rotated files (.1, .1.gz), every 15 minutes, from where the last run stopped. The first run reads the last 4 MB. PHP must be allowed to read the file (permissions, open_basedir). Use “Test this path” below before saving.', 'scrapelock' ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in description().
					?>
				</div>
			</td>
		</tr>
		<tr id="pncp-sec-traffic-keep">
			<th scope="row"><?php esc_html_e( 'Keep', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::number( $s, 'traffic_raw_days', __( 'Keep each request for (days):', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Single requests, for the Requests view and every filter.', 'scrapelock' ), __( 'Whole days in the site\'s time zone, plus today. At most one million requests are kept; the oldest go first.', 'scrapelock' ) ) );
				self::number( $s, 'traffic_days', __( 'Keep the daily traffic figures for (days):', 'scrapelock' ), __( 'Totals per day, for the longer periods.', 'scrapelock' ) );
				?>
			</td>
		</tr>
		<tr id="pncp-sec-traffic-ip">
			<th scope="row"><?php esc_html_e( 'IP addresses', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::radios(
					$s,
					'traffic_ip_mode',
					__( 'IP addresses in the traffic record:', 'scrapelock' ),
					array(
						'full'   => __( 'Full addresses', 'scrapelock' ),
						'masked' => __( 'Masked (the last part removed)', 'scrapelock' ),
					)
				);
				echo PNCP_Admin_Fields::para( __( 'Masked addresses cannot be blocked or checked from here.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
				?>
			</td>
		</tr>
		<?php
		self::form_close();
	}

	/**
	 * 3.8: the Vulnerable points tab: one-click hardening (PNCP_Hardening), the sign-in protection's state
	 * (PNCP_Login) and Stealth (PNCP_Stealth).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_hardening( $s ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Same signature as the other tabs.
		self::section_nav(
			array(
				'points'  => __( 'Vulnerable points', 'scrapelock' ),
				'login'   => __( 'Sign-in protection', 'scrapelock' ),
				'stealth' => __( 'Stealth', 'scrapelock' ),
			)
		);
		echo '<div id="pncp-sec-points">';
		PNCP_Hardening::render_card();
		echo '</div><div id="pncp-sec-login"><div id="pncp-login-status">';
		PNCP_Login::render_status_card();
		echo '</div></div><div id="pncp-sec-stealth">';
		PNCP_Stealth::render_card();
		echo '</div>';
	}

	/**
	 * "Server rules" tab.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_rules( $s ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Same signature as the other tabs.
		// 3.12.3: the text of the rules shown here is kept under their fingerprint, for "See what changed" later.
		PNCP_Rules_State::remember_texts();
		$pncp_self = PNCP_Rules::self_addresses();
		echo PNCP_Rules_State::render_diff(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Rules_State.
		?>
		<div class="pncp-intro">
		<p><?php esc_html_e( 'Generated for this site: they cover cached pages and files PHP never sees. Test on staging first.', 'scrapelock' ); ?></p>
		<?php echo PNCP_Admin_Fields::more( __( 'The plugin only checks requests that reach PHP. Pages from page cache, images and static files are served directly by the server or the CDN. The rules below are generated for your site, with the current settings. Test them on staging first.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<?php /* translators: %s: the server's addresses */ ?>
		<p class="description pncp-rules-self"><?php echo esc_html( sprintf( __( 'The server\'s own addresses are never blocked by these rules: %s.', 'scrapelock' ), implode( ', ', array_merge( $pncp_self['public'], $pncp_self['local'] ) ) ) ); ?></p>
		<?php echo PNCP_Admin_Fields::more( __( 'So the site\'s own requests (its self-checks, cron, cache preloads) always pass. 127.0.0.1, ::1 and private addresses count only when no proxy passed the request on. Behind a CDN (Bunny, Cloudflare) the server\'s own requests through the public address arrive from the CDN\'s edge: with real_ip in Nginx (real_ip_header and set_real_ip_from for the edges) or mod_remoteip in Apache, the web server sees the server\'s own address and they pass; without it they come from the edge, and only the plugin\'s signature (in PHP) lets them through. More addresses: SCRAPELOCK_SERVER_IPS in wp-config.php.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<p class="description"><?php esc_html_e( 'No Cloudflare token is stored: add the rules in your own Cloudflare account.', 'scrapelock' ); ?></p>
		</div>

		<div class="pncp-rules">
		<section class="pncp-card pncp-rules-card" aria-labelledby="pncp-rules-cf">
		<h2 id="pncp-rules-cf"><?php esc_html_e( 'Cloudflare', 'scrapelock' ); ?></h2>
		<?php if ( PNCP_Ip::cloudflare_plugin_active() || PNCP_Ip::behind_cloudflare() ) : ?>
			<div class="notice notice-info inline"><p><?php esc_html_e( 'Pages from the Cloudflare cache skip ScrapeLock: add the WAF rules below to cover them.', 'scrapelock' ); ?></p>
			<?php echo PNCP_Admin_Fields::more( __( 'APO and “Cache Everything”: pages served from the Cloudflare cache never reach the plugin, so the bot list, limits and the trap do not apply to them. The WAF rules below apply before the cache. ScrapeLock tells the Cloudflare plugin not to cache blocks and private feeds, and purges its cache when you save the settings.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?></div>
		<?php endif; ?>
		<p class="description"><?php esc_html_e( 'Security → WAF → Custom rules → Create rule → Edit expression; paste it, choose the action shown.', 'scrapelock' ); ?></p>
		<?php foreach ( PNCP_Rules::cloudflare() as $key => $rule ) : ?>
			<h3><?php echo esc_html( $rule['title'] ); ?> <span class="pncp-badge"><?php echo esc_html( $rule['action'] ); ?></span></h3>
			<?php self::code_block( 'pncp-cf-' . $key, $rule['expression'], 3 ); ?>
		<?php endforeach; ?>
		</section>

		<section class="pncp-card pncp-rules-card" aria-labelledby="pncp-rules-apache">
		<h2 id="pncp-rules-apache"><?php esc_html_e( 'Apache (.htaccess, above # BEGIN WordPress)', 'scrapelock' ); ?></h2>
		<?php self::render_apache_status(); ?>
		<?php self::code_block( 'pncp-apache', PNCP_Rules::apache(), 14 ); ?>
		</section>

		<section class="pncp-card pncp-card--wide pncp-rules-card" aria-labelledby="pncp-rules-nginx">
		<h2 id="pncp-rules-nginx"><?php esc_html_e( 'Nginx', 'scrapelock' ); ?></h2>
		<?php self::render_nginx_status(); ?>
		<?php echo PNCP_Admin_Fields::para( __( 'Optional: stops bots before PHP and the cache. Skip it on shared hosting.', 'scrapelock' ), __( 'Optional: they stop the bots before PHP and the page cache, so the server does less work. Without access to the Nginx configuration (shared hosting) skip them: the plugin and the pre-cache check still protect the pages. The names carry this site\'s suffix, so several WordPress sites can use their rules on the same Nginx.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<div class="pncp-rules-steps">
		<div class="pncp-rules-step">
		<p class="description"><?php esc_html_e( '1) Inside http { }: a new file in a folder that nginx.conf includes there, e.g.', 'scrapelock' ); ?></p>
		<ul class="ul-disc description">
			<li><?php esc_html_e( 'Debian / Ubuntu, CentOS / RHEL, Plesk and most servers:', 'scrapelock' ); ?> <code><?php echo esc_html( '/etc/nginx/conf.d/scrapelock-' . PNCP_Rules::nginx_id() . '.conf' ); ?></code></li>
			<li><?php esc_html_e( 'aaPanel:', 'scrapelock' ); ?> <code><?php echo esc_html( '/www/server/panel/vhost/nginx/0.scrapelock-' . PNCP_Rules::nginx_id() . '.conf' ); ?></code></li>
		</ul>
		<?php self::code_block( 'pncp-nginx-http', PNCP_Rules::nginx_http(), 8 ); ?>
		</div>
		<div class="pncp-rules-step">
		<p class="description"><?php esc_html_e( '2) Inside the site\'s server { } (HTTPS, and HTTP if it serves pages), before other location blocks:', 'scrapelock' ); ?></p>
		<ul class="ul-disc description">
			<li><?php esc_html_e( 'Your own server: the site\'s file, e.g. /etc/nginx/sites-available/, or a file it includes.', 'scrapelock' ); ?></li>
			<li><?php esc_html_e( 'aaPanel: Website → the site → Config, or a file in the site\'s folder under /www/server/panel/vhost/nginx/extension/ when the site\'s configuration includes it.', 'scrapelock' ); ?></li>
			<li><?php esc_html_e( 'Plesk: Websites & Domains → Apache & nginx Settings → Additional nginx directives.', 'scrapelock' ); ?></li>
			<li><?php esc_html_e( 'Other panels: the place they give for custom server { } directives.', 'scrapelock' ); ?></li>
		</ul>
		<?php self::code_block( 'pncp-nginx-server', PNCP_Rules::nginx_server(), 18 ); ?>
		</div>
		</div>
		<p class="description"><?php esc_html_e( '3) Run nginx -t, and reload Nginx only if it says “test is successful”.', 'scrapelock' ); ?></p>
		<p class="description"><?php esc_html_e( '4) Check the status above; when it says “out of date”, copy the named part again.', 'scrapelock' ); ?></p>
		<?php echo PNCP_Admin_Fields::more( __( '3) Run nginx -t: only if it says “test is successful”, reload Nginx (nginx -s reload or systemctl reload nginx). If it shows an error, nothing has changed yet: remove what you added. 4) Check the status above. After every change of the settings that changes the rules, it says “out of date”: copy the part it names again.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		</section>

		<?php // 3.7: fail2ban (PNCP_Fail2ban). ?>
		<section class="pncp-card pncp-card--wide pncp-rules-card" aria-labelledby="pncp-rules-fail2ban">
		<h2 id="pncp-rules-fail2ban"><?php esc_html_e( 'fail2ban (VPS and dedicated servers)', 'scrapelock' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Turn on Bots and limits → Temporary block → “Write each temporary block to the system log”.', 'scrapelock' ); ?></p>
		<p class="description"><?php esc_html_e( 'Save the filter and the jail, then run fail2ban-client reload.', 'scrapelock' ); ?></p>
		<?php echo PNCP_Admin_Fields::more( __( 'With “Write each temporary block to the system log” on (Bots and limits → Temporary block), every block ScrapeLock makes is also written to the system log, and fail2ban blocks the IP in the firewall for the same time: the scraper no longer reaches the web server at all. 1) Save the filter, 2) save the jail (check logpath for your system), 3) run fail2ban-client reload, 4) fail2ban-client status scrapelock shows the blocked IPs.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<?php
		$pncp_settings = PNCP_Options::get();
		if ( empty( $pncp_settings['syslog_bans'] ) ) {
			echo '<p class="pncp-inline-warning">' . esc_html__( 'The option is off: turn it on under Bots and limits → Temporary block.', 'scrapelock' ) . '</p>';
		} elseif ( ! PNCP_Fail2ban::available() ) {
			echo '<p class="pncp-inline-warning">' . esc_html__( 'PHP cannot write to the system log here: enable openlog() and syslog() in php.ini.', 'scrapelock' ) . '</p>';
		}
		?>
		<div class="pncp-rules-steps">
		<div class="pncp-rules-step">
		<?php self::code_block( 'pncp-f2b-filter', PNCP_Fail2ban::filter_conf(), 5 ); ?>
		</div>
		<div class="pncp-rules-step">
		<?php self::code_block( 'pncp-f2b-jail', PNCP_Fail2ban::jail_conf( $pncp_settings ), 12 ); ?>
		</div>
		</div>
		</section>
		</div>
		<?php
	}

	/**
	 * Whether the Nginx rules are installed and match the current settings. 3.12.4: the server is asked directly
	 * first; an answer that is not the rules' fingerprint is named, with what to do (PNCP_Rules_Status).
	 */
	private static function render_nginx_status() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only asks the site again; changes nothing.
		$status = PNCP_Rules::nginx_status( isset( $_GET['pncp_nginx_check'] ) );
		if ( in_array( $status['state'], array( 'current', 'stale' ), true ) ) {
			PNCP_Rules_State::from_status(); // 3.12.3: the site uses the Nginx rules; their fingerprint is noted.
		}
		self::render_rules_status( PNCP_Rules_Status::nginx_text( $status ), 'pncp_nginx_check', 'pncp-nginx-status' );
	}

	/**
	 * 3.12.4: whether the Apache rules are installed (their header, the server asked directly first). Only where
	 * Apache or LiteSpeed serves the site, or Apache rules were seen.
	 */
	private static function render_apache_status() {
		global $is_apache;
		if ( empty( $is_apache ) && 'apache' !== PNCP_Rules_State::state()['format'] ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only asks the site again; changes nothing.
		$status = PNCP_Rules_Status::apache( isset( $_GET['pncp_apache_check'] ) );
		self::render_rules_status( PNCP_Rules_Status::apache_text( $status ), 'pncp_apache_check', 'pncp-apache-status' );
	}

	/**
	 * The status line of a server's rules: one line, "Check again", the details under "More".
	 *
	 * @param array{line:string, more:string, class:string} $text  What PNCP_Rules_Status says.
	 * @param string                                        $query The query argument of "Check again".
	 * @param string                                        $id    The id of the notice.
	 */
	private static function render_rules_status( $text, $query, $id ) {
		$again = PNCP_Status::settings_url(
			array(
				'tab'  => 'rules',
				$query => 1,
			)
		);
		?>
		<div class="notice <?php echo esc_attr( $text['class'] ); ?> inline" id="<?php echo esc_attr( $id ); ?>"><p><strong><?php esc_html_e( 'Status:', 'scrapelock' ); ?></strong> <?php echo esc_html( $text['line'] ); ?>
			<a href="<?php echo esc_url( $again ); ?>"><?php esc_html_e( 'Check again', 'scrapelock' ); ?></a></p>
			<?php echo PNCP_Admin_Fields::more( $text['more'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?></div>
		<?php
	}

	/**
	 * Read-only code field with a copy button.
	 *
	 * @param string $id   ID.
	 * @param string $code Code.
	 * @param int    $rows Rows.
	 */
	private static function code_block( $id, $code, $rows ) {
		printf(
			'<div class="pncp-code"><textarea id="%1$s" class="large-text code" rows="%2$d" readonly aria-label="%3$s">%4$s</textarea><p><button type="button" class="button pncp-copy" data-target="%1$s">%5$s</button></p></div>',
			esc_attr( $id ),
			(int) $rows,
			esc_attr__( 'Rules to copy', 'scrapelock' ),
			esc_textarea( $code ),
			esc_html__( 'Copy', 'scrapelock' )
		);
	}

	/**
	 * "Log" tab: 24-hour summary, active bans, recent events.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_log( $s ) {
		PNCP_Precheck::import_events(); // Blocks of the pre-cache check since the last hourly import.
		// Which entries are shown: all, the real blocks, or the "would block" entries of "Monitor only".
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects a view.
		$view  = isset( $_GET['log_view'] ) ? sanitize_key( wp_unslash( $_GET['log_view'] ) ) : 'all';
		$view  = in_array( $view, array( 'all', 'blocked', 'monitor' ), true ) ? $view : 'all';
		$which = 'monitor' === $view ? 'monitor' : 'blocked';
		// The figures are counted at most every 5 minutes (they are grouped queries over days of rows).
		$cached  = PNCP_Log::summary_cached( 24, $which );
		$summary = $cached['value'];
		$would   = 'monitor' === $view ? $summary : PNCP_Log::summary_cached( 24, 'monitor' )['value'];
		$reasons = PNCP_Log::reasons();
		$bans    = PNCP_Log::active_bans();
		$format  = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		if ( ! empty( $s['enabled'] ) && PNCP_Options::monitoring( $s ) ) :
			?>
			<div class="pncp-monitor-box notice notice-warning inline">
				<p><strong><?php echo esc_html( self::monitor_label( $s ) ); ?></strong></p>
				<p><?php esc_html_e( 'Requests that the settings would refuse are let through and logged as “Would block”. Check them below: an app, a feed reader or a service you rely on should be added to “Always allowed” before blocking starts.', 'scrapelock' ); ?></p>
				<?php PNCP_Status::enforce_form(); ?>
			</div>
			<?php
		endif;
		// 3.5: "Check a request": what ScrapeLock would answer, without counting or logging anything.
		require_once PNCP_DIR . 'includes/class-pncp-tester-view.php';
		echo '<div class="pncp-tools">';
		PNCP_Tester_View::render( $s );
		PNCP_Trace::render(); // 3.6: "Find whose copy this is".
		echo '</div>';
		$views = array(
			'all'     => __( 'All events', 'scrapelock' ),
			'blocked' => __( 'Blocked', 'scrapelock' ),
			'monitor' => __( 'Would block (Monitor only)', 'scrapelock' ),
		);
		echo '<div class="pncp-log-toolbar">';
		echo '<ul class="subsubsub pncp-log-views">';
		$last = array_key_last( $views );
		foreach ( $views as $key => $label ) {
			printf(
				'<li><a href="%1$s"%2$s>%3$s</a>%4$s</li>',
				esc_url( PNCP_Status::log_url( $key ) ),
				$view === $key ? ' class="current" aria-current="page"' : '',
				esc_html( $label ),
				$last === $key ? '' : ' |'
			);
		}
		echo '</ul><div class="clear"></div>';
		?>
		<?php self::action_form_open( 'pncp_log', 'pncp_log', 'pncp-inline-form pncp-refresh-figures' ); ?>
			<input type="hidden" name="op" value="refresh_figures">
			<span class="description">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: time */
						__( 'Figures counted at %s (they are counted again every 5 minutes).', 'scrapelock' ),
						wp_date( get_option( 'time_format' ), (int) $cached['time'] )
					)
				);
				?>
			</span>
			<button type="submit" class="button button-small"><?php esc_html_e( 'Refresh', 'scrapelock' ); ?></button>
		</form>
		</div>
		<h2 class="pncp-section-title"><?php esc_html_e( 'Last 24 hours', 'scrapelock' ); ?></h2>
		<div class="pncp-log-hero">
		<?php if ( 'monitor' === $view ) : ?>
			<p class="pncp-big-number"><?php echo esc_html( sprintf( /* translators: %s: count */ __( '%s requests would have been blocked', 'scrapelock' ), number_format_i18n( $summary['total'] ) ) ); ?></p>
		<?php else : ?>
			<p class="pncp-big-number"><?php echo esc_html( sprintf( /* translators: %s: count */ __( '%s blocked requests', 'scrapelock' ), number_format_i18n( $summary['total'] ) ) ); ?></p>
			<?php if ( $would['total'] > 0 ) : ?>
				<p>
					<a href="<?php echo esc_url( PNCP_Status::log_url( 'monitor' ) ); ?>">
						<?php echo esc_html( sprintf( /* translators: %s: count */ __( '%s more would have been blocked (Monitor only)', 'scrapelock' ), number_format_i18n( $would['total'] ) ) ); ?>
					</a>
				</p>
			<?php endif; ?>
		<?php endif; ?>
		</div>
		<div class="pncp-cards">
			<section class="pncp-card">
				<h3><?php esc_html_e( 'By reason', 'scrapelock' ); ?></h3>
				<?php self::count_list( $summary['reasons'], array_combine( array_keys( $summary['reasons'] ), array_map( array( 'PNCP_Log', 'reason_label' ), array_keys( $summary['reasons'] ) ) ) ); // 3.12.1: never a raw reason key. ?>
			</section>
			<section class="pncp-card">
				<h3><?php esc_html_e( 'Top IPs', 'scrapelock' ); ?></h3>
				<?php self::ip_list( $summary['ips'] ); ?>
			</section>
			<section class="pncp-card">
				<h3><?php esc_html_e( 'Top User-Agents', 'scrapelock' ); ?></h3>
				<?php self::ua_list( $summary['uas'], $summary['ua_reasons'], $reasons ); ?>
				<?php echo PNCP_Admin_Fields::para( __( 'A known bot name here was fake or could not be verified.', 'scrapelock' ), __( 'Verified search engines and AI bots are never blocked, so they never appear here: a known bot name in this list was a fake one or could not be verified.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			</section>
		</div>

		<h2 class="pncp-section-title"><?php esc_html_e( 'What they try to copy', 'scrapelock' ); ?></h2>
		<?php echo PNCP_Admin_Fields::para( __( 'Blocked requests by address: real pages, made-up addresses and scanned files.', 'scrapelock' ), __( 'The blocked requests grouped by address. “Pages” exist on your site: what scrapers were after. “Addresses that do not exist” are random strings and guesses. “Files” are scanners looking for passwords, backups or admin areas. No content leaks in the last two, they only show what was tried.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		<?php
		$periods = array(
			24  => __( 'Last 24 hours', 'scrapelock' ),
			168 => __( 'Last 7 days', 'scrapelock' ),
		);
		foreach ( $periods as $hours => $period ) :
			$top = PNCP_Log::top_paths_cached( $hours, $which )['value'];
			?>
			<h3 class="pncp-subsection-title"><?php echo esc_html( $period ); ?></h3>
			<div class="pncp-cards">
				<section class="pncp-card">
					<h4><?php esc_html_e( 'Pages', 'scrapelock' ); ?></h4>
					<?php self::path_table( $top['content'] ); ?>
				</section>
				<section class="pncp-card">
					<h4><?php esc_html_e( 'Addresses that do not exist', 'scrapelock' ); ?></h4>
					<?php self::path_table( $top['unknown'] ); ?>
					<?php if ( $top['unknown'] ) : ?>
						<p class="description"><?php esc_html_e( 'A real page here? Pages of plugins that WordPress does not know (e.g. a community or forum) count as “Pages” when you add their prefix in “Content addresses” (“Log settings”, at the bottom of this tab).', 'scrapelock' ); ?></p>
					<?php endif; ?>
				</section>
				<section class="pncp-card">
					<h4><?php esc_html_e( 'Files and admin paths', 'scrapelock' ); ?></h4>
					<?php self::path_table( $top['probes'] ); ?>
				</section>
			</div>
		<?php endforeach; ?>
		<?php if ( 7 > (int) $s['log_retention'] ) : ?>
			<p class="description"><?php esc_html_e( 'The log is kept for 1 day, so the 7-day view shows only the last day. Change “Keep the block log for” under “Log settings” below to see more.', 'scrapelock' ); ?></p>
		<?php endif; ?>

		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-sec-bans" aria-labelledby="pncp-bans-title">
		<h2 id="pncp-bans-title"><?php esc_html_e( 'IPs blocked now', 'scrapelock' ); ?> <span class="pncp-badge"><?php echo esc_html( number_format_i18n( count( $bans ) ) ); ?></span></h2>
		<?php if ( ! $bans ) : ?>
			<p class="pncp-empty"><?php esc_html_e( 'None.', 'scrapelock' ); ?></p>
		<?php else : ?>
			<div class="pncp-table-wrap">
			<table class="widefat striped pncp-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'IP', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Reason', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Expires', 'scrapelock' ); ?></th>
						<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Action', 'scrapelock' ); ?></span></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( array_slice( $bans, 0, 200, true ) as $ip => $ban ) : ?>
						<tr>
							<td><code><?php echo esc_html( $ip ); ?></code></td>
							<td><?php echo esc_html( PNCP_Log::reason_label( $ban['reason'] ) ); ?></td>
							<td><?php echo esc_html( wp_date( $format, (int) $ban['until'] ) ); ?></td>
							<td>
								<?php self::action_form_open( 'pncp_log', 'pncp_log', 'pncp-inline-form' ); ?>
									<input type="hidden" name="op" value="unban">
									<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>">
									<button type="submit" class="button button-small"><?php esc_html_e( 'Unblock', 'scrapelock' ); ?></button>
								</form>
								<?php self::block_permanently_button( (string) $ip ); ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			</div>
			<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
				<input type="hidden" name="op" value="unban_all">
				<?php submit_button( __( 'Unblock all', 'scrapelock' ), 'secondary', 'submit', true, self::submit_attrs() ); ?>
			</form>
		<?php endif; ?>
		</section>

		<?php self::render_repeat_offenders( $format, $reasons ); ?>

		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-sec-events" aria-labelledby="pncp-events-title">
		<h2 id="pncp-events-title"><?php esc_html_e( 'Latest events', 'scrapelock' ); ?></h2>
		<?php $rows = PNCP_Log::recent( 100, $view ); ?>
		<?php if ( ! $rows ) : ?>
			<p class="pncp-empty"><?php esc_html_e( 'No events.', 'scrapelock' ); ?></p>
		<?php else : ?>
			<div class="pncp-table-wrap">
			<table class="widefat striped pncp-table pncp-log-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Time', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'IP', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Reason', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Requests', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Path', 'scrapelock' ); ?></th>
						<th scope="col"><?php esc_html_e( 'User-Agent', 'scrapelock' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php
					$buttons       = array();
					$allow_buttons = array();
					?>
					<?php foreach ( $rows as $row ) : ?>
						<tr>
							<td><?php echo esc_html( wp_date( $format, (int) strtotime( $row['created'] . ' UTC' ) ) ); ?></td>
							<td>
								<?php if ( '' === (string) $row['ip'] ) : ?>
									<?php // Events added up because the log reached its limit of new rows for that minute (PNCP_Log::add()). ?>
									<span class="pncp-badge" title="<?php esc_attr_e( 'Too many different IPs in this minute: their requests are added up in one row.', 'scrapelock' ); ?>"><?php esc_html_e( 'Many IPs', 'scrapelock' ); ?></span>
								<?php else : ?>
									<code><?php echo esc_html( $row['ip'] ); ?></code>
								<?php endif; ?>
								<?php
								// The button once per IP: the first (most recent) row of each.
								if ( '' !== (string) $row['ip'] && ! isset( $buttons[ $row['ip'] ] ) ) {
									$buttons[ $row['ip'] ] = true;
									echo '<br>';
									self::block_permanently_button( (string) $row['ip'] );
								}
								?>
							</td>
							<td>
								<?php
								$label = PNCP_Log::reason_label( $row['reason'] );
								// A "would block" entry of "Monitor only" was let through: it has no status code.
								if ( PNCP_Log::is_monitor_row( $row ) ) {
									echo esc_html( $label ) . ' <span class="pncp-badge pncp-badge--monitor">' . esc_html__( 'Would block', 'scrapelock' ) . '</span>';
								} else {
									echo esc_html(
										sprintf(
											/* translators: 1: reason the request was blocked, 2: HTTP status code (e.g. 403) */
											__( '%1$s (%2$s)', 'scrapelock' ),
											$label,
											$row['code']
										)
									);
								}
								PNCP_Bot_Match::render_reason( $row, $s ); // 3.11: the bot list entry that matched.
								if ( isset( $row['account'] ) && '' !== (string) $row['account'] ) {
									// 3.12.1: the account of a per-account limit (rate_account, rate_member).
									/* translators: %s: username */
									echo '<br><span class="pncp-badge pncp-log-account">' . esc_html( sprintf( __( 'Account: %s', 'scrapelock' ), (string) $row['account'] ) ) . '</span>';
								}
								?>
							</td>
							<td><?php echo esc_html( number_format_i18n( (int) $row['hits'] ) ); ?></td>
							<td><code><?php echo esc_html( PNCP_Log::display_path( $row['path'] ) ); ?></code></td>
							<td class="pncp-ua">
								<?php
								echo esc_html( $row['ua'] );
								// The allow button once per User-Agent, like the block button once per IP.
								if ( 'bot_ua' === $row['reason'] && '' !== trim( (string) $row['ua'] ) && ! isset( $allow_buttons[ strtolower( (string) $row['ua'] ) ] ) ) {
									$allow_buttons[ strtolower( (string) $row['ua'] ) ] = true;
									self::allow_ua_button( (string) $row['ua'], $s );
									PNCP_Bot_Match::render_allow_button( (string) $row['ua'], $s ); // 3.11: generic HTTP libraries.
								}
								if ( isset( $row['uas'] ) && (int) $row['uas'] > 1 ) {
									echo '<br><span class="pncp-badge">' . esc_html(
										sprintf(
											/* translators: %s: number of different User-Agents */
											_n( '%s different User-Agent in this minute', '%s different User-Agents in this minute', (int) $row['uas'], 'scrapelock' ),
											number_format_i18n( (int) $row['uas'] )
										)
									) . '</span>';
								}
								?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			</div>
		<?php endif; ?>
		<div class="pncp-card__footer">
		<p class="description">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: number of days */
					_n( 'The log is deleted automatically after %s day (see “Log settings” below).', 'The log is deleted automatically after %s days (see “Log settings” below).', (int) $s['log_retention'], 'scrapelock' ),
					number_format_i18n( (int) $s['log_retention'] )
				)
			);
			?>
		</p>
		<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
			<input type="hidden" name="op" value="clear_log">
			<?php submit_button( __( 'Delete log', 'scrapelock' ), 'delete', 'submit', false, self::submit_attrs() ); ?>
		</form>
		</div>
		</section>
		<?php
		self::render_ai_referrals( $s );
		self::render_log_settings( $s );
	}

	/**
	 * 3.7: visits from AI assistants (PNCP_Ai_Referrals), last 30 days.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_ai_referrals( $s ) {
		$platforms = PNCP_Ai_Referrals::platforms();
		$totals    = PNCP_Ai_Referrals::totals( 30 );
		$pages     = PNCP_Ai_Referrals::top_pages( 30, 10 );
		$sum       = array_sum( $totals );
		$name      = static function ( $key ) use ( $platforms ) {
			return isset( $platforms[ $key ]['name'] ) ? (string) $platforms[ $key ]['name'] : (string) $key;
		};
		?>
		<section class="pncp-card pncp-card--wide pncp-ai-referrals" aria-labelledby="pncp-sec-ai-referrals">
		<h2 id="pncp-sec-ai-referrals"><?php esc_html_e( 'Visitors from AI assistants (last 30 days)', 'scrapelock' ); ?></h2>
		<?php if ( empty( $s['ai_referrals'] ) ) : ?>
			<p class="description"><?php esc_html_e( 'Not counted: “Count visitors who come from AI assistants” is off in “Log settings” below.', 'scrapelock' ); ?></p>
		<?php elseif ( ! $sum ) : ?>
			<p class="pncp-empty"><?php esc_html_e( 'No visits from ChatGPT, Perplexity, Claude, Gemini, Copilot or other assistants yet. They are counted when a reader clicks a link to your site in an answer.', 'scrapelock' ); ?></p>
		<?php else : ?>
			<p>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: number of visits */
						_n( '%s visit from AI assistants.', '%s visits from AI assistants.', $sum, 'scrapelock' ),
						number_format_i18n( $sum )
					)
				);
				?>
				<?php if ( empty( $s['allow_ai_search'] ) ) : ?>
					<?php esc_html_e( 'AI search bots are blocked on this site (“Allow AI search engines and assistants” is off), so these readers came from answers based on older copies or other sources.', 'scrapelock' ); ?>
				<?php endif; ?>
			</p>
			<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
				<th scope="col"><?php esc_html_e( 'Assistant', 'scrapelock' ); ?></th>
				<th scope="col" class="num"><?php esc_html_e( 'Visits', 'scrapelock' ); ?></th>
			</tr></thead><tbody>
			<?php foreach ( $totals as $key => $visits ) : ?>
				<tr><td><?php echo esc_html( $name( $key ) ); ?></td><td class="num"><?php echo esc_html( number_format_i18n( $visits ) ); ?></td></tr>
			<?php endforeach; ?>
			</tbody></table></div>
			<h3><?php esc_html_e( 'Pages they sent readers to', 'scrapelock' ); ?></h3>
			<div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>
				<th scope="col"><?php esc_html_e( 'Page', 'scrapelock' ); ?></th>
				<th scope="col" class="num"><?php esc_html_e( 'Visits', 'scrapelock' ); ?></th>
				<th scope="col"><?php esc_html_e( 'From', 'scrapelock' ); ?></th>
			</tr></thead><tbody>
			<?php foreach ( $pages as $row ) : ?>
				<tr>
					<td><a href="<?php echo esc_url( home_url( $row['path'] ) ); ?>"><code><?php echo esc_html( PNCP_Log::display_path( $row['path'] ) ); ?></code></a></td>
					<td class="num"><?php echo esc_html( number_format_i18n( $row['visits'] ) ); ?></td>
					<td><?php echo esc_html( implode( ', ', array_map( $name, array_filter( explode( ',', $row['platforms'] ) ) ) ) ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody></table></div>
			<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
				<input type="hidden" name="op" value="clear_ai_refs">
				<?php submit_button( __( 'Delete these counts', 'scrapelock' ), 'delete', 'submit', false, self::submit_attrs() ); ?>
			</form>
		<?php endif; ?>
		<?php echo PNCP_Admin_Fields::para( __( 'Counted here without cookies or personal data; kept for 90 days.', 'scrapelock' ), __( 'Counted on this server, without cookies or personal data: one count per day and page, for a page view whose referrer is an AI assistant or whose address carries its utm_source. Pages served by a page cache without reaching WordPress are not counted. Kept for 90 days.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
		</section>
		<?php
	}

	/**
	 * "Log settings" at the bottom of the Log tab: how long the log is kept, and the content addresses that
	 * only change how the log groups blocked requests. A form of its own (section "log"): saving it changes
	 * these two settings and keeps every other one as it is.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function render_log_settings( $s ) {
		?>
		<h2 id="pncp-sec-log-settings" class="pncp-section-title"><?php esc_html_e( 'Log settings', 'scrapelock' ); ?></h2>
		<?php self::form_open( 'log' ); ?>
		<tr>
			<th scope="row"><label for="pncp-log_retention"><?php esc_html_e( 'Keep the block log for', 'scrapelock' ); ?></label></th>
			<td>
				<?php
				self::select(
					$s,
					'log_retention',
					array(
						'1'  => __( '1 day', 'scrapelock' ),
						'7'  => __( '7 days', 'scrapelock' ),
						'30' => __( '30 days', 'scrapelock' ),
					),
					__( 'The log keeps IP and User-Agent, i.e. personal data (GDPR). It is deleted automatically.', 'scrapelock' )
				);
				?>
			</td>
		</tr>
		<tr id="pncp-sec-content-paths">
			<th scope="row"><?php esc_html_e( 'Content addresses', 'scrapelock' ); ?></th>
			<td>
				<?php self::textarea( $s, 'content_paths', __( 'Content addresses: path prefixes of pages that other plugins show, one per line, e.g. /hub/space/', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Only for the log: these count as “Pages”. Nothing is blocked by it.', 'scrapelock' ), __( 'Only for the log: blocked requests under these addresses count as “Pages”. Routes that plugins register as WordPress rewrite rules, and all posts, pages, products and terms, are found without this. Nothing is blocked or allowed because of it.', 'scrapelock' ) ), 2 ); ?>
				<?php
				// 3.11: what is added at runtime (FluentCommunity's portal), never stored in the setting.
				$pncp_fcom = PNCP_Fluent_Community::note_help();
				if ( '' !== $pncp_fcom[0] ) {
					echo '<p class="description pncp-content-paths-added" id="pncp-content_paths-added">' . esc_html( $pncp_fcom[0] ) . '</p>';
					echo PNCP_Admin_Fields::more( $pncp_fcom[1] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
				}
				?>
			</td>
		</tr>
		<tr id="pncp-sec-ai-referrals-setting">
			<th scope="row"><?php esc_html_e( 'AI assistants', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'ai_referrals', __( 'Count visitors who come from AI assistants (ChatGPT, Perplexity, Claude, Gemini, Copilot…)', 'scrapelock' ), __( 'One count per day and page; no IP, User-Agent or cookie is stored.', 'scrapelock' ) ); ?>
			</td>
		</tr>
		<tr id="pncp-sec-attack-record">
			<th scope="row"><?php esc_html_e( 'Attack record', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'attack_record', __( 'Record where bots and attackers hit the site', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Sign-in failures, wp-admin visits, probes and attack patterns; shown on Attacks.', 'scrapelock' ), __( 'Failed sign-ins and the usernames tried, wp-login.php and wp-admin visits that do not sign in, XML-RPC calls, scanner and plugin probes, username enumeration and attack patterns in the address, also when nothing is refused. Kept per hour, address and IP; a normal page view writes nothing. Shown on the Attacks tab.', 'scrapelock' ) ) ); ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="pncp-attack_retention"><?php esc_html_e( 'Keep the attack record for', 'scrapelock' ); ?></label></th>
			<td>
				<?php
				self::select(
					$s,
					'attack_retention',
					array(
						'7'  => __( '7 days', 'scrapelock' ),
						'30' => __( '30 days', 'scrapelock' ),
						'90' => __( '90 days', 'scrapelock' ),
					),
					__( 'It keeps IP addresses and the usernames tried (personal data). Deleted automatically.', 'scrapelock' )
				);
				?>
			</td>
		</tr>
		<tr id="pncp-sec-attack-report">
			<th scope="row"><?php esc_html_e( 'Attack report by email', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'report_weekly', __( 'Weekly attack report by email', 'scrapelock' ), PNCP_Admin_Fields::help( __( 'Every Monday, a 7-day summary to the site\'s administration email.', 'scrapelock' ), __( 'Every Monday, a plain-text summary of the last 7 days (attacks, wp-admin and sign-in attempts, the addresses attacked most, the usernames tried) to the site\'s administration email, with a link to the Attacks tab.', 'scrapelock' ) ) ); ?>
			</td>
		</tr>
		<?php
		self::form_close();
	}

	/**
	 * Table of paths with requests and distinct IPs.
	 *
	 * @param array<int, array{path:string, hits:int, ips:int}> $rows Rows.
	 */
	private static function path_table( $rows ) {
		if ( ! $rows ) {
			echo '<p class="pncp-empty">' . esc_html__( 'Nothing.', 'scrapelock' ) . '</p>';
			return;
		}
		echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-path-table"><thead><tr>';
		echo '<th scope="col">' . esc_html__( 'Path', 'scrapelock' ) . '</th>';
		echo '<th scope="col" class="num">' . esc_html__( 'Requests', 'scrapelock' ) . '</th>';
		echo '<th scope="col" class="num">' . esc_html__( 'IPs', 'scrapelock' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			printf(
				'<tr><td><code>%1$s</code></td><td class="num">%2$s</td><td class="num">%3$s</td></tr>',
				esc_html( PNCP_Log::display_path( $row['path'] ) ),
				esc_html( number_format_i18n( $row['hits'] ) ),
				esc_html( number_format_i18n( $row['ips'] ) )
			);
		}
		echo '</tbody></table></div>';
	}

	/**
	 * "value — count" list.
	 *
	 * @param array<string, int>    $counts Counts.
	 * @param array<string, string> $labels Labels (optional).
	 */
	private static function count_list( $counts, $labels = array() ) {
		if ( ! $counts ) {
			echo '<p class="pncp-empty">' . esc_html__( 'Nothing.', 'scrapelock' ) . '</p>';
			return;
		}
		echo '<ol class="pncp-count-list">';
		foreach ( $counts as $key => $count ) {
			printf( '<li><span>%s</span> <strong>%s</strong></li>', esc_html( isset( $labels[ $key ] ) ? $labels[ $key ] : (string) $key ), esc_html( number_format_i18n( $count ) ) );
		}
		echo '</ol>';
	}

	/**
	 * 3.10: after an AI search list in "Official IP lists": the built-in extra ranges used with it, and a warning
	 * when it is stale (no AI bot is then called fake until it is refreshed).
	 *
	 * @param string $key List name.
	 */
	private static function ai_list_extra_note( $key ) {
		if ( ! in_array( $key, PNCP_Bots::ai_bot_lists(), true ) ) {
			return;
		}
		$extra = PNCP_Ip::extra_ranges( $key );
		if ( $extra ) {
			/* translators: %s: IP ranges, e.g. 160.79.104.0/21 */
			echo ' ' . esc_html( sprintf( __( '(plus the published outbound range %s)', 'scrapelock' ), implode( ', ', $extra ) ) );
		}
		if ( PNCP_Ip::list_stale( $key ) ) {
			echo ' <span class="pncp-badge pncp-badge--monitor">' . esc_html__( 'Not refreshed for over a week: bots not on it are let through instead of being called fake until it is refreshed', 'scrapelock' ) . '</span>';
		}
	}

	/**
	 * The "Block permanently" button: adds the IP to "Always blocked IPs". Not shown for the administrator's own
	 * IP and the server, and replaced by a note when the IP is already in the list.
	 *
	 * @param string $ip IP.
	 */
	private static function block_permanently_button( $ip ) {
		if ( PNCP_Options::is_blocked_permanently( $ip ) ) {
			echo ' <span class="pncp-badge pncp-badge--bad">' . esc_html__( 'Blocked permanently', 'scrapelock' ) . '</span>';
			return;
		}
		if ( PNCP_Ip::client_ip() === $ip || PNCP_Ip::is_local( $ip ) ) {
			return;
		}
		$owner = PNCP_Ip::official_owner( $ip );
		if ( '' !== $owner ) {
			printf(
				' <span class="pncp-badge" title="%2$s">%1$s</span>',
				/* translators: %s: company, e.g. Anthropic or Cloudflare */
				esc_html( sprintf( __( 'Official %s address', 'scrapelock' ), $owner ) ),
				esc_attr__( 'No “Block permanently” here: the address is in an official list, so blocking it would also stop that company\'s search bots, or every visitor behind a CDN. Its training crawlers are already blocked by the bot list (User-Agent).', 'scrapelock' )
			);
			return;
		}
		self::action_form_open( 'pncp_log', 'pncp_log', 'pncp-inline-form' );
		?>
			<input type="hidden" name="op" value="block_permanent">
			<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>">
			<button type="submit" class="button button-small"><?php esc_html_e( 'Block permanently', 'scrapelock' ); ?></button>
		</form>
		<?php
	}

	/**
	 * The "Always allow this User-Agent" button for a request blocked by the bot list: adds a token of the
	 * User-Agent to "Always allowed User-Agents". The token is suggested (the bot-list entry it matched, e.g.
	 * "Dart/" or "okhttp") and can be edited before it is added; the handler refuses tokens that would also
	 * match ordinary browsers. Replaced by a note when the User-Agent is already allowed.
	 *
	 * @param string               $ua User-Agent of the log row.
	 * @param array<string, mixed> $s  Settings.
	 */
	private static function allow_ua_button( $ua, $s ) {
		if ( PNCP_Bots::allow_list_match( $ua, '', array( 'allow_list' => self::unpinned_allow_list( $s ) ) ) ) {
			echo '<br><span class="pncp-badge">' . esc_html__( 'Always allowed now', 'scrapelock' ) . '</span>';
			return;
		}
		$token = PNCP_Options::allow_token_for( $ua, $s );
		$id    = 'pncp-allow-ua-' . substr( md5( $ua ), 0, 10 );
		echo '<br>';
		self::action_form_open( 'pncp_log', 'pncp_log', 'pncp-inline-form pncp-allow-ua-form' );
		?>
			<input type="hidden" name="op" value="allow_ua">
			<label class="screen-reader-text" for="<?php echo esc_attr( $id ); ?>"><?php esc_html_e( 'Part of the User-Agent to allow', 'scrapelock' ); ?></label>
			<input type="text" class="small-text pncp-allow-ua-token" id="<?php echo esc_attr( $id ); ?>" name="token" value="<?php echo esc_attr( $token ); ?>" maxlength="100" size="16">
			<button type="submit" class="button button-small"><?php esc_html_e( 'Always allow this User-Agent', 'scrapelock' ); ?></button>
		</form>
		<?php
	}

	/**
	 * The always-allowed User-Agents without the entries tied to IPs (for the "already allowed" note: a log row
	 * keeps no proof of where a pinned entry would have come from).
	 *
	 * @param array<string, mixed> $s Settings.
	 * @return string
	 */
	private static function unpinned_allow_list( $s ) {
		$out = array();
		foreach ( PNCP_Options::parse_list( (string) $s['allow_list'] ) as $entry ) {
			if ( false === strpos( $entry, '@' ) ) {
				$out[] = $entry;
			}
		}
		return implode( "\n", $out );
	}

	/**
	 * Persistent IPs of the last 7 days (two or more temporary blocks, or many blocked requests), with the
	 * "Block permanently" button.
	 *
	 * @param string                $format  Date format.
	 * @param array<string, string> $reasons Reason labels.
	 */
	private static function render_repeat_offenders( $format, $reasons ) {
		$rows = PNCP_Log::repeat_offenders_cached()['value'];
		?>
		<section class="pncp-card pncp-card--wide pncp-card--table" id="pncp-sec-persistent" aria-labelledby="pncp-persistent-title">
		<h2 id="pncp-persistent-title"><?php esc_html_e( 'Persistent IPs (last 7 days)', 'scrapelock' ); ?></h2>
		<p class="description">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: number of requests */
					__( 'IPs with two or more temporary blocks or %s blocked requests: block them permanently.', 'scrapelock' ),
					number_format_i18n( (int) apply_filters( 'pncp_persistent_requests', 100 ) )
				)
			);
			?>
		</p>
		<?php if ( ! $rows ) : ?>
			<p class="pncp-empty"><?php esc_html_e( 'None.', 'scrapelock' ); ?></p>
			</section>
			<?php
			return;
		endif;
		?>
		<div class="pncp-table-wrap">
		<table class="widefat striped pncp-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'IP', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Temporary blocks', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Blocked requests', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Main reason', 'scrapelock' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Last seen', 'scrapelock' ); ?></th>
					<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Action', 'scrapelock' ); ?></span></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $rows as $row ) : ?>
					<tr>
						<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
						<td><?php echo esc_html( number_format_i18n( $row['bans'] ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( $row['total'] ) ); ?></td>
						<td><?php echo esc_html( PNCP_Log::reason_label( $row['reason'] ) ); ?></td>
						<td><?php echo esc_html( wp_date( $format, (int) strtotime( $row['last'] . ' UTC' ) ) ); ?></td>
						<td><?php self::block_permanently_button( $row['ip'] ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		</div>
		</section>
		<?php
	}

	/**
	 * The top IPs with their requests and the "Block permanently" button.
	 *
	 * @param array<string, int> $counts IP => requests.
	 */
	private static function ip_list( $counts ) {
		if ( ! $counts ) {
			echo '<p class="pncp-empty">' . esc_html__( 'Nothing.', 'scrapelock' ) . '</p>';
			return;
		}
		echo '<ol class="pncp-count-list pncp-ip-list">';
		foreach ( $counts as $ip => $count ) {
			echo '<li><span>' . esc_html( (string) $ip ) . ' ';
			self::block_permanently_button( (string) $ip );
			echo '</span> <strong>' . esc_html( number_format_i18n( $count ) ) . '</strong></li>';
		}
		echo '</ol>';
	}

	/**
	 * The top User-Agents with why they were blocked: "Fake" for a search engine or AI bot that came from
	 * another address, "Not verified" for a known bot name that could not be checked, and the main reason.
	 *
	 * @param array<string, int>                $counts  User-Agent => requests.
	 * @param array<string, array<string, int>> $why     User-Agent => reason => requests.
	 * @param array<string, string>             $reasons Reason labels.
	 */
	private static function ua_list( $counts, $why, $reasons ) {
		if ( ! $counts ) {
			echo '<p class="pncp-empty">' . esc_html__( 'Nothing.', 'scrapelock' ) . '</p>';
			return;
		}
		echo '<ol class="pncp-count-list pncp-ua-list">';
		foreach ( $counts as $ua => $count ) {
			$ua    = (string) $ua;
			$by    = isset( $why[ $ua ] ) ? $why[ $ua ] : array();
			$badge = '';
			if ( isset( $by['fake_crawler'] ) || isset( $by['fake_ai_bot'] ) ) {
				$badge = '<span class="pncp-badge pncp-badge--bad">' . esc_html__( 'Fake: not from the official addresses', 'scrapelock' ) . '</span>';
			} elseif ( '' !== PNCP_Bots::claimed_crawler( $ua ) || PNCP_Bots::ua_in_list( $ua, PNCP_Options::ai_search_agents() ) ) {
				$badge = '<span class="pncp-badge">' . esc_html__( 'Known bot name, not verified', 'scrapelock' ) . '</span>';
			}
			$main = $by ? (string) array_key_first( $by ) : '';
			printf(
				'<li><span>%1$s%2$s%3$s</span> <strong>%4$s</strong></li>',
				esc_html( $ua ),
				$badge, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Built above from escaped text.
				'' !== $main ? '<br><small class="pncp-ua-reason">' . esc_html( PNCP_Log::reason_label( $main ) ) . '</small>' : '',
				esc_html( number_format_i18n( $count ) )
			);
		}
		echo '</ol>';
	}

	/* ---------- Actions ---------- */

	/**
	 * Capability and nonce check for the actions.
	 *
	 * @param string $nonce Nonce action.
	 */
	private static function verify( $nonce ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce );
	}

	/**
	 * Redirects back to a tab with a notice.
	 *
	 * @param string                $tab     Tab.
	 * @param string                $message Notice code.
	 * @param array<string, string> $args    More query arguments.
	 */
	private static function back( $tab, $message, $args = array() ) {
		wp_safe_redirect(
			PNCP_Status::settings_url(
				array_merge(
					array(
						'tab'          => $tab,
						'pncp_message' => $message,
					),
					$args
				)
			)
		);
		exit;
	}

	/**
	 * Applies a profile.
	 */
	public static function handle_profile() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The nonce is checked in verify().
		self::verify( 'pncp_profile' );
		$profile  = isset( $_POST['profile'] ) ? sanitize_key( wp_unslash( $_POST['profile'] ) ) : '';
		$profiles = PNCP_Options::profiles();
		if ( ! isset( $profiles[ $profile ] ) || PNCP_Lockdown::is_locked() ) {
			self::back( 'general', 'error' );
		}
		// The settings as they were are kept first, so "Undo" in the notice can put them back.
		$undo = PNCP_Settings_Io::backup( 'profile:' . $profile );
		update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $profiles[ $profile ] ) );
		PNCP_Options::flush();
		self::back( 'general', 'profile', array( 'pncp_undo' => $undo ) );
		// phpcs:enable
	}

	/**
	 * Export, import (check, then apply or cancel), reset a tab and restore an earlier version.
	 */
	public static function handle_settings() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The nonce is checked in verify().
		self::verify( 'pncp_settings' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( 'export' === $op ) {
			$host = sanitize_file_name( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
			nocache_headers();
			header( 'Content-Type: application/json; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="scrapelock-settings-' . $host . '-' . gmdate( 'Y-m-d' ) . '.json"' );
			header( 'X-Content-Type-Options: nosniff' );
			echo PNCP_Settings_Io::export_json(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON file download, not HTML.
			exit;
		}
		if ( PNCP_Lockdown::is_locked() ) {
			self::back( 'general', 'error' );
		}
		$key = 'pncp_import_' . get_current_user_id();
		switch ( $op ) {
			case 'import_preview':
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The file is checked below and read as JSON only.
				$file = isset( $_FILES['pncp_import_file'] ) && is_array( $_FILES['pncp_import_file'] ) ? $_FILES['pncp_import_file'] : array();
				if ( empty( $file['tmp_name'] ) || ! isset( $file['error'] ) || UPLOAD_ERR_OK !== (int) $file['error'] || ! is_uploaded_file( $file['tmp_name'] ) ) {
					self::back( 'general', 'import_nofile' );
				}
				if ( (int) $file['size'] > PNCP_Settings_Io::MAX_FILE ) {
					self::back( 'general', 'import_invalid' );
				}
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A just-uploaded temporary file.
				$parsed = PNCP_Settings_Io::parse( (string) file_get_contents( $file['tmp_name'] ) );
				if ( is_wp_error( $parsed ) ) {
					self::back( 'general', 'import_invalid' );
				}
				// Only the values read from the file are kept until the confirmation, never the file itself.
				$parsed['name'] = isset( $file['name'] ) ? sanitize_file_name( wp_unslash( $file['name'] ) ) : '';
				set_transient( $key, $parsed, 15 * MINUTE_IN_SECONDS );
				wp_safe_redirect(
					PNCP_Status::settings_url(
						array(
							'tab'         => 'general',
							'pncp_import' => 1,
						)
					)
				);
				exit;
			case 'import_apply':
				$data = get_transient( $key );
				delete_transient( $key );
				if ( ! is_array( $data ) || empty( $data['settings'] ) ) {
					self::back( 'general', 'import_expired' );
				}
				$result = PNCP_Settings_Io::apply( PNCP_Settings_Io::prepare( $data['settings'] ), 'import' );
				if ( is_wp_error( $result ) ) {
					self::back( 'general', 'error' );
				}
				self::back( 'general', '' === $result ? 'unchanged' : 'imported', '' === $result ? array() : array( 'pncp_undo' => $result ) );
				break;
			case 'import_cancel':
				delete_transient( $key );
				self::back( 'general', 'import_cancelled' );
				break;
			case 'reset':
				$section = isset( $_POST['section'] ) ? sanitize_key( wp_unslash( $_POST['section'] ) ) : '';
				if ( ! isset( PNCP_Settings_Io::tab_names()[ $section ] ) ) {
					self::back( 'general', 'error' );
				}
				$result = PNCP_Settings_Io::apply( PNCP_Settings_Io::prepare( PNCP_Settings_Io::section_defaults( $section ) ), 'reset:' . $section );
				if ( is_wp_error( $result ) ) {
					self::back( $section, 'error' );
				}
				self::back( $section, '' === $result ? 'unchanged' : 'reset', '' === $result ? array() : array( 'pncp_undo' => $result ) );
				break;
			case 'restore':
				$id     = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : '';
				$result = PNCP_Settings_Io::restore( $id );
				if ( is_wp_error( $result ) ) {
					self::back( 'general', 'restore_missing' );
				}
				$tab = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : 'general';
				self::back( isset( PNCP_Settings_Io::tab_names()[ $tab ] ) ? $tab : 'general', 'restored', array( 'pncp_undo' => $result ) );
				break;
		}
		self::back( 'general', 'error' );
		// phpcs:enable
	}

	/**
	 * Token: new / rotate / revoke the previous one.
	 */
	public static function handle_token() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The nonce is checked in verify().
		self::verify( 'pncp_token' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( 'rotate' === $op ) {
			$grace = isset( $_POST['grace'] ) ? absint( $_POST['grace'] ) : 0;
			$grace = in_array( $grace, array( 0, 1, 7, 30 ), true ) ? $grace : 7;
			$token = PNCP_Private_Urls::rotate( $grace );
			// Shown once to this user on the next page load, then deleted. Kept only 2 minutes, to keep the
			// plaintext token in the database as briefly as possible (the redirect-render happens at once).
			set_transient( 'pncp_new_token_' . get_current_user_id(), $token, 2 * MINUTE_IN_SECONDS );
			self::back( 'content', 'token' );
		}
		if ( 'revoke_prev' === $op ) {
			PNCP_Private_Urls::revoke_previous();
			self::back( 'content', 'revoked' );
		}
		self::back( 'content', 'error' );
		// phpcs:enable
	}

	/**
	 * Log and bans.
	 */
	public static function handle_log() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The nonce is checked in verify().
		self::verify( 'pncp_log' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		switch ( $op ) {
			case 'unban':
				$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
				// The list shows the ban keys: an IPv4 address, or an IPv6 /64 network.
				if ( PNCP_Ip::valid_range( $ip ) ) {
					PNCP_Log::unban( $ip );
				}
				self::back( 'log', 'unbanned' );
				break;
			case 'unban_all':
				PNCP_Log::unban_all();
				self::back( 'log', 'unbanned' );
				break;
			case 'block_permanent':
				$ip     = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
				$result = PNCP_Options::block_ip_permanently( $ip );
				self::back( 'log', 'perm_' . $result );
				break;
			case 'allow_ua':
				$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
				self::back( 'log', 'allow_ua_' . PNCP_Options::allow_user_agent( $token ) );
				break;
			case 'clear_log':
				PNCP_Log::clear();
				self::back( 'log', 'cleared' );
				break;
			case 'refresh_figures':
				PNCP_Log::flush_aggregates();
				self::back( 'log', 'figures' );
				break;
			case 'refresh_lists':
				$result = PNCP_Ip::refresh_lists();
				self::back( 'bots', in_array( 0, $result, true ) ? 'lists_partial' : 'lists' );
				break;
			case 'crowdsec_sync': // 3.7.
				$result = PNCP_Crowdsec::sync( true );
				self::back( 'bots', is_wp_error( $result ) ? 'crowdsec_failed' : 'crowdsec' );
				break;
			case 'clear_ai_refs': // 3.7.
				PNCP_Ai_Referrals::clear();
				self::back( 'log', 'ai_cleared' );
				break;
			case 'refresh_geo':
				// Only while the setting is on: otherwise the files would be deleted again by the next daily task.
				self::back( 'bots', PNCP_Geo::needed() && PNCP_Geo::refresh() ? 'geo' : 'geo_failed' );
				break;
		}
		self::back( 'general', 'error' );
		// phpcs:enable
	}

	/**
	 * One click: real visitor IP from CF-Connecting-IP, trusted only from Cloudflare addresses.
	 */
	public static function handle_cf_ip() {
		self::verify( 'pncp_cf_ip' );
		$fix = array(
			'ip_header'        => 'cf_connecting_ip',
			'trust_cloudflare' => 1,
		);
		update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $fix ) );
		PNCP_Options::flush();
		PNCP_Ip::reset();
		self::back( 'bots', 'cf_ip' );
	}

	/**
	 * One click: real visitor IP from X-Real-IP, trusted only from Bunny CDN edge servers. The list is
	 * downloaded right away; without it no address is trusted and REMOTE_ADDR stays in use.
	 */
	public static function handle_bunny_ip() {
		self::verify( 'pncp_bunny_ip' );
		$fix = array(
			'ip_header'   => 'x_real_ip',
			'trust_bunny' => 1,
		);
		update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $fix ) );
		PNCP_Options::flush();
		PNCP_Ip::reset();
		$result = PNCP_Ip::refresh_lists();
		self::back( 'bots', empty( $result['bunny'] ) ? 'bunny_ip_failed' : 'bunny_ip' );
	}

	/**
	 * Blocking at the CDN: tests the configuration (PNCP_Edge::diagnose(), with a test block) and saves it if
	 * the test passes; "Test connection" only tests the saved one. An empty token keeps the saved one. Not while
	 * the site is locked.
	 */
	public static function handle_edge() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The nonce is checked in verify().
		self::verify( 'pncp_edge' );
		if ( PNCP_Lockdown::is_locked() ) {
			self::back_edge( 'error' );
		}
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( 'test_block' === $op || 'diagnose' === $op ) {
			// 3.4.2: "Test connection" checks every step (token, zone, permissions, a test block, rate limit).
			$diag = PNCP_Edge::diagnose( PNCP_Edge::config() );
			self::keep_diagnosis( $diag );
			$error = PNCP_Edge::diagnosis_error( $diag );
			set_transient( 'pncp_edge_test_' . get_current_user_id(), '' === $error ? __( 'Connection test passed: blocking at the CDN works. The details are under “Blocking at the CDN”.', 'scrapelock' ) : $error, 2 * MINUTE_IN_SECONDS );
			self::back_edge( '' === $error ? 'edge_test_ok' : 'edge_test_failed' );
		}
		$old      = PNCP_Edge::config();
		$provider = isset( $_POST['provider'] ) ? sanitize_key( wp_unslash( $_POST['provider'] ) ) : '';
		$provider = isset( PNCP_Edge::providers()[ $provider ] ) ? $provider : '';
		$raw_zone = isset( $_POST['zone'] ) ? sanitize_text_field( wp_unslash( $_POST['zone'] ) ) : '';
		$raw      = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		// phpcs:enable
		if ( '' === $provider ) {
			PNCP_Edge::save_config(
				array(
					'provider' => '',
					'zone'     => '',
					'token'    => '',
				)
			);
			self::back_edge( 'edge_off' );
		}
		$zone  = PNCP_Edge::clean_zone( $provider, $raw_zone );
		$token = '' === trim( $raw ) ? ( $old['provider'] === $provider ? $old['token'] : '' ) : PNCP_Edge::clean_token( $raw );
		if ( PNCP_Edge::token_from_config() ) {
			$token = PNCP_Edge::config()['token'];
		}
		if ( '' === $zone || '' === $token ) {
			self::back_edge( '' === $zone ? 'edge_zone' : 'edge_token' );
		}
		$new  = array(
			'provider' => $provider,
			'zone'     => $zone,
			'token'    => $token,
		);
		$diag = PNCP_Edge::diagnose( $new );
		self::keep_diagnosis( $diag );
		$error = PNCP_Edge::diagnosis_error( $diag );
		if ( '' !== $error ) {
			// Not saved: a wrong token or zone would only fill the log with errors.
			set_transient( 'pncp_edge_test_' . get_current_user_id(), $error, 2 * MINUTE_IN_SECONDS );
			self::back_edge( 'edge_failed' );
		}
		PNCP_Edge::save_config( $new );
		self::back_edge( 'edge_ok' );
	}

	/**
	 * 3.9: back to "Blocking at the CDN (advanced)", opened, with a notice.
	 *
	 * @param string $message Notice code.
	 */
	private static function back_edge( $message ) {
		wp_safe_redirect( PNCP_Edge::section_url( array( 'pncp_message' => $message ) ) );
		exit;
	}

	/**
	 * 3.4.2: keeps the last connection check of this user for 30 minutes, to show it under “Blocking at the CDN”
	 * (it holds no token).
	 *
	 * @param array<string, mixed> $diag The result of PNCP_Edge::diagnose().
	 */
	private static function keep_diagnosis( $diag ) {
		$diag['text'] = PNCP_Edge::diagnosis_text( $diag );
		set_transient( 'pncp_edge_diag_' . get_current_user_id(), $diag, 30 * MINUTE_IN_SECONDS );
	}

	/**
	 * 3.4.2: the last connection check of this user: each step with its result and what to do, and the whole
	 * check as text to copy (without the token).
	 */
	private static function render_diagnosis() {
		$diag = get_transient( 'pncp_edge_diag_' . get_current_user_id() );
		if ( ! is_array( $diag ) || empty( $diag['checks'] ) || ! is_array( $diag['checks'] ) ) {
			return;
		}
		$words = array(
			'ok'   => __( 'OK', 'scrapelock' ),
			'warn' => __( 'Warning', 'scrapelock' ),
			'fail' => __( 'Problem', 'scrapelock' ),
			'skip' => __( 'Not checked', 'scrapelock' ),
		);
		echo '<div class="pncp-edge-diag">';
		/* translators: %s: date and time */
		echo '<h3>' . esc_html( sprintf( __( 'Connection check (%s)', 'scrapelock' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), isset( $diag['time'] ) ? (int) $diag['time'] : time() ) ) ) . '</h3>';
		echo '<ul class="pncp-edge-checks">';
		foreach ( $diag['checks'] as $check ) {
			if ( ! is_array( $check ) || ! isset( $check['status'], $check['label'], $check['detail'] ) ) {
				continue;
			}
			$status = isset( $words[ $check['status'] ] ) ? $check['status'] : 'skip';
			printf(
				'<li class="pncp-edge-check pncp-edge-check--%1$s"><span class="pncp-edge-check__status">%2$s</span> <strong>%3$s:</strong> %4$s',
				esc_attr( $status ),
				esc_html( $words[ $status ] ),
				esc_html( (string) $check['label'] ),
				esc_html( (string) $check['detail'] )
			);
			if ( ! empty( $check['fix'] ) ) {
				echo '<br><span class="pncp-edge-check__fix">' . esc_html__( 'What to do:', 'scrapelock' ) . ' ' . esc_html( (string) $check['fix'] ) . '</span>';
			}
			echo '</li>';
		}
		echo '</ul>';
		if ( isset( $diag['text'] ) && is_string( $diag['text'] ) ) {
			printf(
				'<details class="pncp-edge-diag__copy"><summary>%1$s</summary><p class="description">%2$s</p><textarea id="pncp-edge-diag-text" class="large-text code" rows="10" readonly>%3$s</textarea><p><button type="button" class="button pncp-copy" data-target="pncp-edge-diag-text">%4$s</button></p></details>',
				esc_html__( 'Copy diagnostics', 'scrapelock' ),
				esc_html__( 'For a support request: the result of each step, the zone, the plan, the versions and Cloudflare\'s Ray IDs. It holds no token.', 'scrapelock' ),
				esc_textarea( $diag['text'] ),
				esc_html__( 'Copy diagnostics', 'scrapelock' )
			);
		}
		echo '</div>';
	}

	/**
	 * Notices after actions, and upgrade notices from 1.4.
	 */
	public static function upgrade_notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$ours   = $screen && 'settings_page_' . self::PAGE === $screen->id;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays a notice.
		$message = $ours && isset( $_GET['pncp_message'] ) ? sanitize_key( wp_unslash( $_GET['pncp_message'] ) ) : '';
		$texts   = array(
			'profile'          => array( 'success', __( 'Preset applied.', 'scrapelock' ) ),
			'imported'         => array( 'success', __( 'Settings imported.', 'scrapelock' ) ),
			'reset'            => array( 'success', __( 'The tab was reset to its defaults.', 'scrapelock' ) ),
			'restored'         => array( 'success', __( 'The earlier settings were restored.', 'scrapelock' ) ),
			'unchanged'        => array( 'info', __( 'Nothing changed: the settings were already like that.', 'scrapelock' ) ),
			'import_cancelled' => array( 'info', __( 'Import cancelled. Nothing changed.', 'scrapelock' ) ),
			'import_nofile'    => array( 'error', __( 'No file was received. Choose the JSON file exported from ScrapeLock and try again.', 'scrapelock' ) ),
			'import_invalid'   => array( 'error', __( 'Nothing changed: the file is not a ScrapeLock settings export, so export it again.', 'scrapelock' ) ),
			'import_expired'   => array( 'error', __( 'Nothing changed: the checked file expired after 15 minutes, so choose it again.', 'scrapelock' ) ),
			'restore_missing'  => array( 'error', __( 'Nothing changed: only the last 5 versions are kept, so choose another one.', 'scrapelock' ) ),
			'token'            => array( 'success', __( 'New token created.', 'scrapelock' ) ),
			'revoked'          => array( 'success', __( 'Previous token revoked.', 'scrapelock' ) ),
			'unbanned'         => array( 'success', __( 'Block lifted.', 'scrapelock' ) ),
			'cleared'          => array( 'success', __( 'Log deleted.', 'scrapelock' ) ),
			'figures'          => array( 'success', __( 'Figures counted again.', 'scrapelock' ) ),
			'perm_added'       => array( 'success', __( 'The IP was added to the always-blocked IPs (“Bots and limits” → “Always blocked”). You can remove it there.', 'scrapelock' ) ),
			'perm_exists'      => array( 'info', __( 'The IP is already in the always-blocked IPs.', 'scrapelock' ) ),
			'perm_full'        => array( 'error', __( 'The always-blocked IPs already have 200 lines. Combine addresses into CIDR ranges there first.', 'scrapelock' ) ),
			'allow_ua_added'   => array( 'success', __( 'The User-Agent was added to “Always allowed User-Agents” (“Bots and limits” → “Always allowed”). You can remove it there. The page limits still apply to it.', 'scrapelock' ) ),
			'allow_ua_exists'  => array( 'info', __( 'This User-Agent is already always allowed.', 'scrapelock' ) ),
			'allow_ua_full'    => array( 'error', __( 'The always-allowed User-Agents already have 200 lines. Remove some there first.', 'scrapelock' ) ),
			'allow_ua_refused' => array( 'error', __( 'Not added: use the name of the app or service, e.g. “Dart/” or “okhttp”, not a browser word or “@”.', 'scrapelock' ) ),
			'perm_refused'     => array( 'error', __( 'Not blocked: this is the server, your own, a private, an always-allowed or an official (search engine, CDN) address.', 'scrapelock' ) ),
			'lists'            => array( 'success', __( 'IP lists refreshed.', 'scrapelock' ) ),
			'crowdsec'         => array( 'success', __( 'CrowdSec blocklist updated.', 'scrapelock' ) ),
			'crowdsec_failed'  => array( 'error', __( 'The CrowdSec blocklist was not updated and the previous one stays: see the reason under “Official IP lists”.', 'scrapelock' ) ),
			'ai_cleared'       => array( 'success', __( 'The counts of visits from AI assistants were deleted.', 'scrapelock' ) ),
			'geo'              => array( 'success', __( 'Country database downloaded.', 'scrapelock' ) ),
			'geo_failed'       => array( 'error', __( 'The country database could not be downloaded, so the previous one stays: try “Download now” later.', 'scrapelock' ) ),
			'cf_ip'            => array( 'success', __( 'The real visitor IP is now read from CF-Connecting-IP, only for requests from Cloudflare.', 'scrapelock' ) ),
			'bunny_ip'         => array( 'success', __( 'The real visitor IP is now read from X-Real-IP, only for requests from Bunny CDN.', 'scrapelock' ) ),
			'bunny_ip_failed'  => array( 'warning', __( 'X-Real-IP stays untrusted until the Bunny address list downloads: use “Refresh now” under “Official IP lists”.', 'scrapelock' ) ),
			'lists_partial'    => array( 'warning', __( 'Some IP lists kept their previous version because the download failed: use “Refresh now” under “Official IP lists”.', 'scrapelock' ) ),
			'edge_ok'          => array( 'success', __( 'Connected to the CDN and tested. Temporary blocks are sent to it only while “Send temporary blocks to the CDN” is on (under “Blocking at the CDN”).', 'scrapelock' ) ),
			'edge_off'         => array( 'success', __( 'Blocking at the CDN is off. The blocks ScrapeLock made there are being removed in the background.', 'scrapelock' ) ),
			'edge_zone'        => array( 'error', __( 'Nothing was saved: enter a valid zone ID (Cloudflare: 32 characters 0–9 and a–f; Bunny CDN: a number).', 'scrapelock' ) ),
			'edge_token'       => array( 'error', __( 'Nothing was saved: enter the API token (letters, digits, “-” and “_”).', 'scrapelock' ) ),
			'edge_failed'      => array( 'error', __( 'The connection test failed, so nothing was saved.', 'scrapelock' ) ),
			'edge_test_ok'     => array( 'success', '' ),
			'edge_test_failed' => array( 'error', '' ),
			'error'            => array( 'error', __( 'The action was not completed: reload the page and try again.', 'scrapelock' ) ),
		);
		$texts  += PNCP_Attacks::notices(); // 3.8: attacks_cleared, attacks_locked.
		$texts  += PNCP_Edge::notices(); // 3.9: edge_send_on, edge_send_off, edge_send_nc.
		if ( isset( $texts[ $message ] ) ) {
			$text = $texts[ $message ][1];
			if ( in_array( $message, array( 'edge_failed', 'edge_test_ok', 'edge_test_failed' ), true ) ) {
				$detail = get_transient( 'pncp_edge_test_' . get_current_user_id() );
				delete_transient( 'pncp_edge_test_' . get_current_user_id() );
				$text = trim( $text . ( is_string( $detail ) && '' !== $detail ? ' ' . $detail : '' ) );
			}
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays a notice.
			$undo = isset( $_GET['pncp_undo'] ) ? sanitize_key( wp_unslash( $_GET['pncp_undo'] ) ) : '';
			if ( '' !== $undo && in_array( $message, array( 'profile', 'imported', 'reset', 'restored' ), true ) && PNCP_Settings_Io::find( $undo ) ) {
				// "Undo" puts back the version saved just before the change.
				printf( '<div class="notice notice-%1$s is-dismissible pncp-undo-notice"><p>%2$s</p>', esc_attr( $texts[ $message ][0] ), esc_html( $text ) );
				self::action_form_open( 'pncp_settings', 'pncp_settings', 'pncp-inline-form' );
				printf( '<input type="hidden" name="op" value="restore"><input type="hidden" name="id" value="%s">', esc_attr( $undo ) );
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects the tab to return to.
				printf( '<input type="hidden" name="tab" value="%s">', esc_attr( isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'general' ) );
				echo '<p><button type="submit" class="button">' . esc_html__( 'Undo', 'scrapelock' ) . '</button></p></form></div>';
			} elseif ( '' !== $text ) {
				printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $texts[ $message ][0] ), esc_html( $text ) );
			}
		}

		// The 1.x token is still valid but exists only as a hash: it cannot be shown.
		if ( $ours && get_option( 'pncp_legacy_token_migrated' ) ) {
			delete_option( 'pncp_legacy_token_migrated' );
			printf(
				'<div class="notice notice-info"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
				esc_html__( 'The old feed token still works but can no longer be shown since 2.1: create a new token if you did not save it.', 'scrapelock' ),
				esc_url( PNCP_Status::settings_url( array( 'tab' => 'content' ) ) ),
				esc_html__( 'Feeds and token', 'scrapelock' )
			);
		}
		if ( ! empty( PNCP_Options::stored()['trust_any_proxy'] ) && PNCP_Status::notice_screen() ) {
			$link = '<a href="' . esc_url( PNCP_Status::settings_url( array( 'tab' => 'bots' ) ) ) . '">' . esc_html__( 'Trusted Proxy settings', 'scrapelock' ) . '</a>';
			printf(
				'<div class="notice notice-warning"><p>%s</p></div>',
				sprintf(
					/* translators: %s: link "Trusted Proxy settings" */
					esc_html__( 'ScrapeLock reads the visitor IP from a header without checking the proxy (as in 1.4), so it can be spoofed: fix it in the %s.', 'scrapelock' ),
					$link // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Built from esc_url() and esc_html__() above.
				)
			);
		}
	}
}
