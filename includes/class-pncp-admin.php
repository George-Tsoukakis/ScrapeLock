<?php
/**
 * Settings page in wp-admin (Settings → ScrapeLock), with tabs.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Admin UI. Settings go through the Settings API (options.php checks nonce and capability).
 * Actions (profiles, token, bans, image tool) go through admin-post / AJAX with a nonce.
 */
final class PNCP_Admin {

	const PAGE  = 'scrapelock';
	const GROUP = 'pncp_settings_group';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( PNCP_FILE ), array( __CLASS__, 'action_links' ) );
		add_action( 'admin_post_pncp_profile', array( __CLASS__, 'handle_profile' ) );
		add_action( 'admin_post_pncp_token', array( __CLASS__, 'handle_token' ) );
		add_action( 'admin_post_pncp_log', array( __CLASS__, 'handle_log' ) );
		add_action( 'admin_post_pncp_cf_ip', array( __CLASS__, 'handle_cf_ip' ) );
		add_action( 'admin_post_pncp_bunny_ip', array( __CLASS__, 'handle_bunny_ip' ) );
		add_action( 'admin_post_pncp_edge', array( __CLASS__, 'handle_edge' ) );
		add_action( 'wp_ajax_pncp_wm_batch', array( __CLASS__, 'ajax_wm_batch' ) );
		add_action( 'admin_notices', array( __CLASS__, 'upgrade_notices' ) );
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
			'general'  => __( 'On the page', 'scrapelock' ),
			'bots'     => __( 'Bots and limits', 'scrapelock' ),
			'content'  => __( 'Feeds and API', 'scrapelock' ),
			'images'   => __( 'Images', 'scrapelock' ),
			'rules'    => __( 'Server rules', 'scrapelock' ),
			'log'      => __( 'Log', 'scrapelock' ),
			'lockdown' => __( 'Lockdown', 'scrapelock' ),
		);
	}

	/**
	 * The current tab.
	 *
	 * @return string
	 */
	private static function current_tab() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects a tab.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'general';
		if ( PNCP_Lockdown::is_locked() ) {
			return 'lockdown'; // Nothing else can be changed while locked.
		}
		return array_key_exists( $tab, self::tabs() ) ? $tab : 'general';
	}

	/* ---------- Fields ---------- */

	/**
	 * Checkbox row.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param string               $key   Key.
	 * @param string               $label Label text.
	 * @param string               $help  Help text (optional).
	 */
	private static function checkbox( $s, $key, $label, $help = '' ) {
		$id = 'pncp-' . $key;
		echo '<div class="pncp-field pncp-field--toggle">';
		printf(
			'<label for="%1$s"><input type="checkbox" class="pncp-toggle" id="%1$s" name="%2$s[%3$s]" value="1"%4$s%5$s> <span class="pncp-field__label">%6$s</span></label>',
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			checked( ! empty( $s[ $key ] ), true, false ),
			$help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : '',
			esc_html( $label )
		);
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
		}
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
		echo '<fieldset><legend class="screen-reader-text">' . esc_html( $legend ) . '</legend>';
		foreach ( $options as $value => $label ) {
			$id = 'pncp-' . $key . '-' . $value;
			printf(
				'<label for="%1$s"><input type="radio" id="%1$s" name="%2$s[%3$s]" value="%4$s"%5$s> %6$s</label><br>',
				esc_attr( $id ),
				esc_attr( PNCP_OPTION ),
				esc_attr( $key ),
				esc_attr( $value ),
				checked( (string) $s[ $key ], (string) $value, false ),
				esc_html( $label )
			);
		}
		echo '</fieldset>';
	}

	/**
	 * Select.
	 *
	 * @param array<string, mixed>  $s       Settings.
	 * @param string                $key     Key.
	 * @param array<string, string> $options value => label.
	 * @param string                $help    Help text.
	 */
	private static function select( $s, $key, $options, $help = '' ) {
		$id = 'pncp-' . $key;
		printf( '<select id="%1$s" name="%2$s[%3$s]"%4$s>', esc_attr( $id ), esc_attr( PNCP_OPTION ), esc_attr( $key ), $help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : '' );
		foreach ( $options as $value => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( (string) $s[ $key ], (string) $value, false ), esc_html( $label ) );
		}
		echo '</select>';
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
		}
	}

	/**
	 * Number field with label and help text.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param string               $key   Key.
	 * @param string               $label Label text.
	 * @param string               $help  Help text.
	 */
	private static function number( $s, $key, $label, $help = '' ) {
		$range = PNCP_Options::int_ranges()[ $key ];
		$id    = 'pncp-' . $key;
		echo '<div class="pncp-field pncp-field--number">';
		printf(
			'<p><label for="%1$s">%2$s</label> <input type="number" class="small-text" id="%1$s" name="%3$s[%4$s]" value="%5$d" min="%6$d"%7$s%8$s></p>',
			esc_attr( $id ),
			esc_html( $label ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			(int) $s[ $key ],
			(int) $range[0],
			PHP_INT_MAX === $range[1] ? '' : ' max="' . (int) $range[1] . '"',
			$help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : ''
		);
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
		}
		echo '</div>';
	}

	/**
	 * Textarea with label.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param string               $key   Key.
	 * @param string               $label Label.
	 * @param string               $help  Help text.
	 * @param int                  $rows  Rows.
	 * @param bool                 $fold  Long list: shown folded, with the number of entries.
	 */
	/**
	 * A single-line password field (for a secret). The value is not shown as plain text.
	 *
	 * @param array<string, mixed> $s     Settings.
	 * @param string               $key   Option key.
	 * @param string               $label Label.
	 * @param string               $help  Help text.
	 */
	private static function password( $s, $key, $label, $help = '' ) {
		$id = 'pncp-' . $key;
		echo '<div class="pncp-field">';
		printf( '<p><label for="%s">%s</label></p>', esc_attr( $id ), esc_html( $label ) );
		printf(
			'<input type="password" class="regular-text" id="%1$s" name="%2$s[%3$s]" value="%4$s" autocomplete="new-password" spellcheck="false"%5$s>',
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			esc_attr( (string) ( isset( $s[ $key ] ) ? $s[ $key ] : '' ) ),
			$help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : ''
		);
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
		}
		echo '</div>';
	}

	private static function textarea( $s, $key, $label, $help = '', $rows = 4, $fold = false ) {
		$id = 'pncp-' . $key;
		echo '<div class="pncp-field pncp-field--text">';
		if ( $fold ) {
			$count = count( PNCP_Options::parse_list( (string) $s[ $key ] ) );
			printf(
				'<details class="pncp-fold"><summary>%s <span class="pncp-badge">%s</span></summary>',
				esc_html( $label ),
				esc_html( sprintf( /* translators: %s: number of entries */ _n( '%s entry', '%s entries', $count, 'scrapelock' ), number_format_i18n( $count ) ) )
			);
		}
		printf( '<p><label for="%s"%s>%s</label></p>', esc_attr( $id ), $fold ? ' class="screen-reader-text"' : '', esc_html( $label ) );
		printf(
			'<textarea class="large-text code" rows="%1$d" id="%2$s" name="%3$s[%4$s]"%5$s>%6$s</textarea>',
			(int) $rows,
			esc_attr( $id ),
			esc_attr( PNCP_OPTION ),
			esc_attr( $key ),
			$help ? ' aria-describedby="' . esc_attr( $id . '-help' ) . '"' : '',
			esc_textarea( (string) $s[ $key ] )
		);
		if ( $help ) {
			printf( '<p class="description" id="%s">%s</p>', esc_attr( $id . '-help' ), esc_html( $help ) );
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
		printf( '<tr id="pncp-sec-%s"><th scope="row">%s</th><td>', esc_attr( $id ), esc_html( $title ) );
	}

	/**
	 * Closes a settings card.
	 */
	private static function row_close() {
		echo '</td></tr>';
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
		$items     = array(
			array( ! empty( $s['enabled'] ), __( 'Protection', 'scrapelock' ) ),
			array( ! empty( $s['early_mode'] ) && PNCP_Early::installed(), __( 'Early check', 'scrapelock' ) ),
			array( ! empty( $s['precheck'] ) && PNCP_Precheck::active(), __( 'Pre-cache check', 'scrapelock' ) ),
			array( ! empty( $s['human_check'] ), __( 'Human check', 'scrapelock' ) ),
			array( ! empty( $s['allow_ai_search'] ) && ! empty( $s['verify_ai_bots'] ), __( 'AI bots verified', 'scrapelock' ) ),
			array( ! empty( $s['block_headless'] ), __( 'Headless browsers', 'scrapelock' ) ),
			array( '' !== $s['countries_block'] || '' !== $s['countries_strict'], __( 'Countries', 'scrapelock' ) ),
		);
		echo '<ul class="pncp-status-bar" aria-label="' . esc_attr__( 'Protection status', 'scrapelock' ) . '">';
		if ( $emergency ) {
			echo '<li class="pncp-pill pncp-pill--alert">' . esc_html__( 'Emergency Mode', 'scrapelock' ) . '</li>';
		}
		foreach ( $items as $item ) {
			printf(
				'<li class="pncp-pill %1$s"><span class="screen-reader-text">%2$s </span>%3$s</li>',
				$item[0] ? 'pncp-pill--on' : 'pncp-pill--off',
				esc_html( $item[0] ? __( 'On:', 'scrapelock' ) : __( 'Off:', 'scrapelock' ) ),
				esc_html( $item[1] )
			);
		}
		echo '</ul>';
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
			esc_html_e( 'Country database: not downloaded yet. Use “Download now” at the bottom of this tab, or wait for the daily task.', 'scrapelock' );
		} else {
			esc_html_e( 'Country database: off. Without Cloudflare, Bunny CDN or the database the country is unknown and the country lists do nothing.', 'scrapelock' );
		}
		echo '<br>';
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
		echo '<form method="post" action="options.php" class="pncp-settings-form">';
		settings_fields( self::GROUP );
		printf( '<input type="hidden" name="%s[_sections][]" value="%s">', esc_attr( PNCP_OPTION ), esc_attr( $section ) );
		echo '<table class="form-table" role="presentation">';
	}

	/**
	 * Closes the settings form.
	 */
	private static function form_close() {
		echo '</table>';
		submit_button( __( 'Save changes', 'scrapelock' ) );
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
		wp_nonce_field( $nonce );
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
		?>
		<div class="wrap pncp-admin">
			<h1 class="pncp-title"><?php esc_html_e( 'ScrapeLock', 'scrapelock' ); ?> <span class="pncp-version"><?php echo esc_html( PNCP_VERSION ); ?></span></h1>
			<?php
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays the confirmation.
			if ( isset( $_GET['pncp_confirm'] ) && PNCP_Status::is_enabled() && ! $locked ) {
				self::render_disable_confirm();
			}
			if ( ! $locked ) {
				self::render_status_bar( PNCP_Options::stored() );
			}
			?>
			<nav class="nav-tab-wrapper" aria-label="<?php esc_attr_e( 'Settings sections', 'scrapelock' ); ?>">
				<?php foreach ( self::tabs() as $key => $label ) : ?>
					<?php if ( $locked && 'lockdown' !== $key ) : ?>
						<span class="nav-tab pncp-tab-locked" title="<?php esc_attr_e( 'Locked: unlock the site to change the settings', 'scrapelock' ); ?>"><?php echo esc_html( $label ); ?></span>
					<?php else : ?>
						<a href="<?php echo esc_url( PNCP_Status::settings_url( array( 'tab' => $key ) ) ); ?>" class="nav-tab<?php echo $tab === $key ? ' nav-tab-active' : ''; ?><?php echo 'lockdown' === $key ? ' pncp-tab-lockdown' : ''; ?>"<?php echo $tab === $key ? ' aria-current="page"' : ''; ?>><?php echo 'lockdown' === $key ? '<span class="dashicons dashicons-' . ( $locked ? 'lock' : 'unlock' ) . '" aria-hidden="true"></span> ' : ''; ?><?php echo esc_html( $label ); ?></a>
					<?php endif; ?>
				<?php endforeach; ?>
			</nav>
			<?php
			if ( 'lockdown' === $tab ) {
				PNCP_Lockdown::render_tab();
			} else {
				$method = 'tab_' . $tab;
				self::$method( PNCP_Options::stored() );
			}
			?>
		</div>
		<?php
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
				<p class="description" id="pncp-excluded_ids-help"><?php esc_html_e( 'Comma-separated page or post IDs, e.g. 12, 45. For a single piece of text (phone, email, code), give it the CSS class pncp-allow.', 'scrapelock' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'What is blocked', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'block_selection', __( 'Text selection with the mouse or finger', 'scrapelock' ) );
				self::checkbox( $s, 'block_context_menu', __( 'Right click', 'scrapelock' ) );
				self::checkbox( $s, 'block_shortcuts', __( 'Shortcuts Ctrl/Cmd + A, C, X, S, U', 'scrapelock' ), __( 'Keyboard navigation (Tab, arrows, Enter) is never affected.', 'scrapelock' ) );
				self::checkbox( $s, 'block_devtools', __( 'Developer tools shortcuts (F12, Ctrl+Shift+I/J/C/K, Cmd+Opt+I/J/C/U)', 'scrapelock' ), __( 'Cosmetic: it only blocks the shortcuts. It does not detect DevTools and does not “break” the page.', 'scrapelock' ) );
				self::checkbox( $s, 'block_image_drag', __( 'Dragging images and “Save image” with a long press on mobile', 'scrapelock' ) );
				self::checkbox( $s, 'block_text_drag', __( 'Dragging selected text to another window', 'scrapelock' ) );
				self::checkbox( $s, 'blur_on_capture', __( 'Blur the page when Print Screen or a screenshot shortcut is pressed', 'scrapelock' ), __( 'Optional. It only catches the shortcuts the browser sees (Print Screen, Win+Shift+S, Cmd+Shift+3/4/5). It does not stop tools outside the browser or a photo taken with a phone.', 'scrapelock' ) );
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
				self::number( $s, 'attribution_min_chars', __( 'Append the source from this many characters and up:', 'scrapelock' ), __( 'Shorter snippets (e.g. a word or a phone number) are copied without the source. 0 = always.', 'scrapelock' ) );
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
						'edit_posts'        => __( 'Logged-in authors and administrators', 'scrapelock' ),
						'edit_others_posts' => __( 'Logged-in editors and administrators', 'scrapelock' ),
						'manage_options'    => __( 'Administrators only', 'scrapelock' ),
						'none'              => __( 'Nobody (for testing the protection)', 'scrapelock' ),
					),
					__( 'Applies to the on-page protection and to the server checks (bots, limits, blocks). Customers with an account are not excluded.', 'scrapelock' )
				);
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Message to the visitor', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'show_message', __( 'Show a message when something is blocked', 'scrapelock' ) ); ?>
				<label for="pncp-message" class="screen-reader-text"><?php esc_html_e( 'Message text', 'scrapelock' ); ?></label>
				<input type="text" class="large-text" id="pncp-message" name="<?php echo esc_attr( PNCP_OPTION ); ?>[message]" value="<?php echo esc_attr( $s['message'] ); ?>" maxlength="200">
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Iframe and AI', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'block_framing', __( 'Pages do not open inside another site\'s iframe', 'scrapelock' ), __( 'X-Frame-Options and CSP frame-ancestors headers. WordPress embeds (oEmbed) keep working.', 'scrapelock' ) );
				self::checkbox( $s, 'tdm_reservation', __( 'Opt-out declaration from AI training and text and data mining (TDM)', 'scrapelock' ), __( 'tdm-reservation header and meta, /.well-known/tdmrep.json and noai/noimageai. Legal basis: Directive (EU) 2019/790, Article 4(3): reservation of rights in a machine-readable format.', 'scrapelock' ) );
				?>
				<p><label for="pncp-tdm_policy_url"><?php esc_html_e( 'Page with the licensing terms (optional):', 'scrapelock' ); ?></label>
				<input type="url" class="regular-text code" id="pncp-tdm_policy_url" name="<?php echo esc_attr( PNCP_OPTION ); ?>[tdm_policy_url]" value="<?php echo esc_attr( $s['tdm_policy_url'] ); ?>" placeholder="https://"></p>
			</td>
		</tr>
		<?php
		self::form_close();
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
			'maximum'  => array( __( 'Maximum', 'scrapelock' ), __( 'Also no printing and no RSS, browsers only, blur on screenshot, limit 30/minute, 12-hour block after 2 violations. May annoy some visitors.', 'scrapelock' ) ),
		);
		$until    = PNCP_Options::emergency_until();
		?>
		<div class="pncp-cards">
			<section class="pncp-card" aria-labelledby="pncp-profiles-title">
				<h2 id="pncp-profiles-title"><?php esc_html_e( 'Presets', 'scrapelock' ); ?></h2>
				<p class="description"><?php esc_html_e( 'One click changes the protection and limit settings. Lists, feeds, IPs and watermark do not change. You can adjust anything afterwards.', 'scrapelock' ); ?></p>
				<p><?php esc_html_e( 'Current:', 'scrapelock' ); ?> <strong><?php echo esc_html( '' === $current ? __( 'Custom', 'scrapelock' ) : $profiles[ $current ][0] ); ?></strong></p>
				<?php self::action_form_open( 'pncp_profile', 'pncp_profile', 'pncp-profile-form' ); ?>
					<?php foreach ( $profiles as $key => $profile ) : ?>
						<div class="pncp-profile<?php echo $current === $key ? ' is-current' : ''; ?>">
							<button type="submit" name="profile" value="<?php echo esc_attr( $key ); ?>" class="button<?php echo 'balanced' === $key ? ' button-primary' : ''; ?>" aria-describedby="pncp-profile-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $profile[0] ); ?></button>
							<p class="description" id="pncp-profile-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $profile[1] ); ?></p>
						</div>
					<?php endforeach; ?>
				</form>
			</section>
			<section class="pncp-card pncp-card--emergency" aria-labelledby="pncp-emergency-title">
				<h2 id="pncp-emergency-title"><?php esc_html_e( 'Emergency Mode', 'scrapelock' ); ?></h2>
				<p class="description"><?php esc_html_e( 'For a scraping attack in progress: browsers only, limit 20 pages/minute, 6-hour block after 2 violations, REST/GraphQL without content. Your settings do not change: when it ends, they apply again as they were.', 'scrapelock' ); ?></p>
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
					if ( ! empty( $s['auto_emergency'] ) ) {
						echo '<p class="description">' . esc_html(
							$state['samples'] >= PNCP_Surge::WARMUP
								/* translators: 1: usual pages per minute, 2: threshold */
								? sprintf( __( 'Automatic start: on. Usually %1$s pages per minute; it starts above %2$d.', 'scrapelock' ), number_format_i18n( $state['avg'], 1 ), PNCP_Surge::threshold( $state, $s ) )
								/* translators: %d: threshold */
								: sprintf( __( 'Automatic start: on, still learning the usual rate; until then it starts above %d pages per minute.', 'scrapelock' ), PNCP_Surge::threshold( $state, $s ) )
						) . '</p>';
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
	 * "Bots and limits" tab.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_bots( $s ) {
		self::render_cloudflare_hint( $s );
		self::section_nav(
			array(
				'bots'      => __( 'Bots', 'scrapelock' ),
				'ai'        => __( 'AI', 'scrapelock' ),
				'allowed'   => __( 'Always allowed', 'scrapelock' ),
				'blocked'   => __( 'Always blocked', 'scrapelock' ),
				'limits'    => __( 'Limits', 'scrapelock' ),
				'human'     => __( 'Human check', 'scrapelock' ),
				'countries' => __( 'Countries', 'scrapelock' ),
				'ban'       => __( 'Temporary block', 'scrapelock' ),
				'ip'        => __( 'Real visitor IP', 'scrapelock' ),
				'edge'      => __( 'Blocking at the CDN', 'scrapelock' ),
				'lists'     => __( 'IP lists', 'scrapelock' ),
			)
		);
		self::form_open( 'bots' );
		?>
		<?php self::row_open( 'bots', __( 'Scrapers and bots', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'block_bots', __( 'Block (403) the User-Agents in the list', 'scrapelock' ) );
				self::checkbox( $s, 'block_empty_ua', __( 'Block requests without a User-Agent', 'scrapelock' ) );
				self::checkbox( $s, 'block_fake_crawlers', __( 'Block fake Googlebot, Bingbot, Applebot and Yandex', 'scrapelock' ), __( 'The IP is checked against the official Google and Bing lists and with reverse DNS. Real search engines always pass, without limits.', 'scrapelock' ) );
				self::checkbox( $s, 'require_browser_headers', __( 'Browsers only: 403 for pages without Accept-Language or without “Mozilla/” in the User-Agent', 'scrapelock' ), __( 'Stops most scripts. Link previews (Facebook, Viber, WhatsApp etc.) in the “Always allowed” list pass.', 'scrapelock' ) );
				self::checkbox( $s, 'block_headless', __( 'Block headless and fake browsers', 'scrapelock' ), __( 'Blocks Chrome running without a window when it says so in its headers (“HeadlessChrome”), and, on HTTPS, scripts that copy the User-Agent of Chrome, Edge or Firefox without the Sec-Fetch headers every modern browser sends. It catches common tools and cheap scrapers, not every automated browser: one that is carefully disguised (e.g. Puppeteer with “stealth”, or Selenium with a visible Chrome) sends the same headers as a person. The page limits, the human check and the bot trap still apply to those. In-app browsers (Android WebView) are not checked.', 'scrapelock' ) );
				self::checkbox( $s, 'trap_enabled', __( 'Bot trap', 'scrapelock' ), __( 'Invisible link on every page, disallowed in robots.txt. Whoever opens it is blocked temporarily, even if it pretends to be a browser. Visitors do not see it, and another site cannot trap them.', 'scrapelock' ) );
				self::textarea( $s, 'bot_list', __( 'User-Agents to block (one per line, matches anywhere in the User-Agent, case-insensitive):', 'scrapelock' ), __( 'It contains two AI categories: training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended etc.) and AI search / assistants (OAI-SearchBot, ChatGPT-User, Claude-SearchBot, PerplexityBot etc.). You can allow the second one in the next section.', 'scrapelock' ) . ' ' . sprintf( /* translators: %s: number of AI crawlers */ __( 'In addition, %s more AI crawlers and agents (DeepSeek, Grok, Qwen, Mistral, NotebookLM and others) are blocked by name: that list is built into ScrapeLock and updated with each version, so it is not shown here. A line that starts with “=” must be the whole User-Agent, e.g. “=node”.', 'scrapelock' ), number_format_i18n( count( PNCP_Bots::known_ai_agents() ) ) ), 10, true );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'ai', __( 'AI search and training', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'allow_ai_search', __( 'Allow AI search engines and assistants (not training crawlers)', 'scrapelock' ), sprintf( /* translators: %s: list of User-Agents */ __( 'So the site appears in AI search answers with a link, without being given for model training. Allowed: %s. They are also removed from the robots.txt Disallow and from the server rules. The page limit still applies, because the User-Agent can be spoofed.', 'scrapelock' ), implode( ', ', PNCP_Options::ai_search_agents() ) ) );
				self::checkbox( $s, 'verify_ai_bots', __( 'Verify AI search bots with their official IP lists (OpenAI, Perplexity, Anthropic)', 'scrapelock' ), __( 'With AI search allowed: the real OAI-SearchBot, ChatGPT-User, PerplexityBot, Perplexity-User, Claude-SearchBot and Claude-User are never limited or blocked, and requests that only use their name get a 403 (“Fake AI search bot”). The lists are downloaded once a day; until then nothing changes.', 'scrapelock' ) );
				self::checkbox( $s, 'robots_ai_block', __( 'Declare AI crawlers in robots.txt (Disallow)', 'scrapelock' ), __( 'Applies to the virtual robots.txt of WordPress. If a physical robots.txt file exists, it takes precedence.', 'scrapelock' ) );
				self::checkbox( $s, 'block_archivers', __( 'Block web archives (Wayback Machine)', 'scrapelock' ), __( 'The Internet Archive keeps a public copy of every page it visits, and that copy can be scraped without ever reaching your site. This blocks its crawlers (ia_archiver, archive.org_bot, heritrix) and asks them in robots.txt. Copies already in the archive stay there. Leave it off if you want your site to be archived.', 'scrapelock' ) );
				self::checkbox( $s, 'content_signal', __( 'Content Signals in robots.txt: search yes, AI training no', 'scrapelock' ), __( 'A line that says what the content may be used for (contentsignals.org): search=yes, ai-train=no, and ai-input according to “Allow AI search engines”. It does not block anything; it is a statement of your terms that well-behaved companies read.', 'scrapelock' ) );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'allowed', __( 'Always allowed', 'scrapelock' ) ); ?>
				<?php
				self::textarea( $s, 'allow_list', __( 'Always allowed User-Agents (link previews, price comparison platforms, monitoring):', 'scrapelock' ), __( 'They override the bot list and “Browsers only”. The page limit applies to them too, because the User-Agent is easy to spoof. To accept an entry only from specific IPs, add @ and the addresses, e.g. Skroutz@203.0.113.0/24.', 'scrapelock' ), 5, true );
				self::textarea( $s, 'allow_ips', __( 'Always allowed IPs / CIDR (office, ERP, monitoring), one per line:', 'scrapelock' ), __( 'They are never checked, never count towards limits and are never blocked.', 'scrapelock' ), 3 );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'blocked', __( 'Always blocked', 'scrapelock' ) ); ?>
				<?php
				self::textarea( $s, 'block_ips', __( 'IPs / CIDR that are always blocked (403), one per line:', 'scrapelock' ), __( 'For example a scraper\'s server or a hosting network you see in the log. The “Always allowed IPs” take precedence.', 'scrapelock' ), 3 );
				self::textarea( $s, 'block_referrers', __( 'Referrer domains that are always blocked (403), one per line, e.g. copy-site.example:', 'scrapelock' ), __( 'Requests that come from links or embeds on these sites. Each entry also covers its subdomains.', 'scrapelock' ), 3 );
				self::checkbox( $s, 'block_user_enum', __( 'Hide usernames from visitors', 'scrapelock' ), __( '?author=1, 2, 3… returns “page not found” instead of the redirect to /author/username/, the REST API does not list users, the users sitemap is removed and oEmbed shows the site instead of the author. Logged-in users see everything as before. Author archives with a link stay.', 'scrapelock' ) );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'limits', __( 'Limits per IP', 'scrapelock' ) ); ?>
				<?php
				self::number( $s, 'rate_limit', __( 'Pages per minute (0 = off):', 'scrapelock' ), __( 'Starting value: 60. Above the limit it returns 429. Be careful with networks that share an IP (companies, mobile carriers) and with CDNs: set the “Real visitor IP” correctly first.', 'scrapelock' ) );
				self::number( $s, 'rate_limit_search', __( 'Searches (?s=) per minute (0 = off):', 'scrapelock' ), __( 'Search is heavy for the server and a favourite of scrapers. Starting value: 20.', 'scrapelock' ) );
				self::number( $s, 'rate_limit_rest', __( 'REST API (/wp-json/) and GraphQL requests per minute (0 = off):', 'scrapelock' ), __( 'Only read requests from visitors. Cart, checkout and forms (POST) do not count. Starting value: 60.', 'scrapelock' ) );
				self::number( $s, 'rate_limit_404', __( '“Page not found” (404) per minute (0 = off):', 'scrapelock' ), __( 'Scrapers guess addresses (?p=1, 2, 3…, old product URLs) to find content. Missing images, CSS, scripts and the favicon do not count. Starting value: 30.', 'scrapelock' ) );
				self::number( $s, 'rate_limit_sitemap', __( 'Sitemaps per minute (0 = off):', 'scrapelock' ), __( 'Scrapers read the sitemap first to find every page. Covers the sitemaps of WordPress, Rank Math, Yoast and similar plugins. Google, Bing and the other verified search engines are never limited. Starting value: 5.', 'scrapelock' ) );
				self::checkbox( $s, 'ipv6_wide', __( 'IPv6: also limit the whole /56 network (four times the page limit)', 'scrapelock' ), __( 'Pages are counted per /64, because one connection usually gets a whole /64. A server or a home connection often has a /56 or more, so a scraper can take a new /64 for every request. This also counts the /56 the /64 belongs to, up to four times the page limit (429 above it, without a block). Some mobile networks give neighbouring phones addresses of the same /56: on a site with many visitors from them, keep it off. Always on in Emergency Mode.', 'scrapelock' ) );
				self::number( $s, 'rate_limit_datacenter', __( 'Pages per minute from data centers (0 = off):', 'scrapelock' ), __( 'People rarely browse from a server; scrapers very often run on one. Visitors from the published addresses of AWS, Google Cloud, Oracle Cloud, DigitalOcean and Akamai / Linode get this stricter limit instead of the normal one. The lists are downloaded from the providers once a day. Some VPNs use these providers, so their users get this limit too: it is meant for reading, not for blocking. The always-allowed User-Agents (monitoring, price platforms) and verified search engines are not affected. Starting value: 15. 5 in Emergency Mode.', 'scrapelock' ) );
				self::checkbox( $s, 'auto_emergency', __( 'Start Emergency Mode automatically during an attack', 'scrapelock' ), __( 'The limits per IP cannot see a scraper that spreads its requests over hundreds of IPs. The whole site can: ScrapeLock learns how many pages per minute your site usually serves, and when that is exceeded five times over for 3 minutes in a row (and never below the minimum below), it starts Emergency Mode for 1 hour and emails you. Verified search engines and exempt staff are not counted. Pages served from a page cache without reaching WordPress are not counted either.', 'scrapelock' ) );
				self::number( $s, 'auto_emergency_min', __( 'Minimum pages per minute for the automatic start:', 'scrapelock' ), __( 'Below this the site is never considered under attack, however quiet it usually is. Starting value: 300 (5 pages per second).', 'scrapelock' ) );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'human', __( 'Human check', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'human_check', __( 'Stricter page limit for visitors who have not shown they are people', 'scrapelock' ), __( 'A small script waits for the visitor\'s first real interaction (scroll, tap, key or mouse movement), solves a light challenge in the background and receives a cookie for 7 days. Nobody sees a captcha or a window. Visitors without the cookie (scripts, and people with JavaScript turned off) get the limit below instead of the normal page limit. Search engines and verified AI search bots are not affected. It works with page caches such as WP Rocket. A determined scraper can repeat the steps, but each of its IPs has to do the work.', 'scrapelock' ) );
				self::number( $s, 'rate_limit_unverified', __( 'Pages per minute without the cookie (0 = off):', 'scrapelock' ), __( 'Starting value: 20. A person reads far fewer pages per minute, and gets the cookie with the first scroll or tap.', 'scrapelock' ) );
				?>
		<?php self::row_close(); ?>
		<?php self::row_open( 'countries', __( 'Countries', 'scrapelock' ) ); ?>
				<?php
				self::checkbox( $s, 'geo_db', __( 'Download the free country database (DB-IP Lite, once a month)', 'scrapelock' ), __( 'Needed when the site is not behind Cloudflare or Bunny CDN. About 5 MB to download, stored as two small files in uploads/scrapelock-geo. Behind Cloudflare the country that Cloudflare sends is used, behind Bunny the one Bunny sends (when it reaches the site directly from Bunny), and the database is not needed.', 'scrapelock' ) );
				self::textarea( $s, 'countries_block', __( 'Blocked countries (403), two-letter codes separated by commas, e.g. CN, RU:', 'scrapelock' ), __( 'Search engines, verified AI search bots and the “Always allowed” list are never blocked by country. People who travel or use a VPN appear with the country of their connection.', 'scrapelock' ), 2 );
				self::textarea( $s, 'countries_strict', __( 'Countries with a stricter page limit, e.g. those your customers do not come from:', 'scrapelock' ), '', 2 );
				self::number( $s, 'rate_limit_country', __( 'Pages per minute for these countries (0 = off):', 'scrapelock' ), __( 'Starting value: 10.', 'scrapelock' ) );
				self::render_geo_status( $s );
				?>
		<?php self::row_close(); ?>
		<tr id="pncp-sec-ban">
			<th scope="row"><?php esc_html_e( 'Temporary block', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::number( $s, 'ban_strikes', __( 'Block after this many violations within 10 minutes (0 = never):', 'scrapelock' ), __( 'Violation: every minute in which the IP exceeded a limit, and every fake Googlebot. The trap blocks immediately.', 'scrapelock' ) );
				self::number( $s, 'ban_minutes', __( 'Block duration (minutes):', 'scrapelock' ) );
				self::checkbox( $s, 'early_mode', __( 'Early check: block known bots before the theme and the other plugins load', 'scrapelock' ), __( 'Adds the small file wp-content/mu-plugins/scrapelock-early.php, which stops blocked IPs and referrers, temporarily blocked IPs and User-Agents in the bot list with less server load. Search engines, logged-in users, forms and feeds are left to the normal check. It is removed when you turn this off or deactivate the plugin.', 'scrapelock' ) );
				if ( ! empty( $s['early_mode'] ) && ! PNCP_Early::installed() ) {
					echo '<p class="pncp-inline-warning">' . esc_html__( 'The file could not be created (the server does not allow direct file writes to wp-content/mu-plugins). The normal check works as before.', 'scrapelock' ) . '</p>';
				}
				if ( ! is_multisite() ) {
					self::checkbox( $s, 'precheck', __( 'Pre-cache check: apply the page limit and blocks also to pages served from the page cache', 'scrapelock' ), __( 'Page caches such as WP Rocket serve stored pages before any plugin loads, so a bot that looks like a browser could read them without a limit. This adds one line at the top of wp-config.php that loads a small check before the cache: always-blocked IPs, temporarily blocked IPs and the “Pages per minute” limit. Counters are kept in APCu or in a folder of the uploads directory (uploads/scrapelock). Search engines, logged-in users, forms, wp-admin and the REST API are left to the normal check. The line and the files are removed when you turn this off or deactivate the plugin.', 'scrapelock' ) );
					self::render_precheck_status( $s );
				}
				?>
				<p><label for="pncp-log_retention"><?php esc_html_e( 'Keep the block log for:', 'scrapelock' ); ?></label>
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
				</p>
				<?php self::textarea( $s, 'content_paths', __( 'Content addresses: path prefixes of pages that other plugins show, one per line, e.g. /hub/space/', 'scrapelock' ), __( 'Only for the log: blocked requests under these addresses count as “Pages”. Routes that plugins register as WordPress rewrite rules, and all posts, pages, products and terms, are found without this. Nothing is blocked or allowed because of it.', 'scrapelock' ), 2 ); ?>
			</td>
		</tr>
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
					__( 'Behind a CDN or reverse proxy all visitors appear with the CDN\'s IP. Choose the header with the real IP.', 'scrapelock' )
				);
				?>
				<p><strong><?php esc_html_e( 'Trusted Proxy:', 'scrapelock' ); ?></strong> <?php esc_html_e( 'the header is read only when the request comes from a proxy you trust. Otherwise anyone could write any IP they want and bypass limits and blocks. CF-Connecting-IP: only from Cloudflare. X-Real-IP / X-Forwarded-For: from Bunny CDN, the server itself or a private network (Nginx in front of Apache). True-Client-IP: only from the proxies in the list.', 'scrapelock' ); ?></p>
				<?php
				self::checkbox( $s, 'trust_cloudflare', __( 'Trust Cloudflare addresses', 'scrapelock' ), __( 'The official Cloudflare list is refreshed every day.', 'scrapelock' ) );
				self::checkbox( $s, 'trust_bunny', __( 'Trust Bunny CDN addresses', 'scrapelock' ), __( 'For X-Real-IP / X-Forwarded-For and Bunny\'s country header. The official list of Bunny edge servers is refreshed every day.', 'scrapelock' ) );
				if ( ! empty( $s['trust_any_proxy'] ) ) {
					echo '<div class="pncp-inline-warning">';
					self::checkbox( $s, 'trust_any_proxy', __( 'Trust every request (1.4 behaviour, insecure)', 'scrapelock' ), __( 'On because this is how version 1.4 worked. Fill in your proxies below and uncheck it. Once turned off, it cannot be turned on again.', 'scrapelock' ) );
					echo '</div>';
				}
				self::textarea( $s, 'trusted_proxies', __( 'Other trusted proxies / load balancers (IP or CIDR, one per line):', 'scrapelock' ), '', 3 );
				self::password( $s, 'cdn_secret', __( 'CDN shared secret (optional):', 'scrapelock' ), __( 'Only when "Real visitor IP" is a CDN header (CF-Connecting-IP, X-Real-IP, X-Forwarded-For). A CDN (Bunny, Cloudflare) is multi-tenant: its edge IPs are shared, so by default anyone could point their own CDN zone at your origin and set the real-IP header. Set a secret here and configure your CDN to send it on every request as the header “X-ScrapeLock-CDN”; the CDN’s real-IP header is then trusted only when the secret matches. Leave empty to keep the current behaviour. For best effect, also restrict your origin so it is reachable only through the CDN.', 'scrapelock' ) );
				self::checkbox( $s, 'cdn_only', __( 'Only through the CDN: refuse (403) requests that do not bring the secret', 'scrapelock' ), __( 'Someone who finds your server\'s own address can go around the CDN and everything it blocks. With this on, every request without the secret in the X-ScrapeLock-CDN header gets a 403, also pages from the page cache when the pre-cache check is on. First make the CDN add the header to every request: in Bunny CDN, an Edge Rule with the action “Set Request Header” (X-ScrapeLock-CDN = your secret) for all requests; in Cloudflare, Rules → Transform Rules → “Modify Request Header”, set static. It can only be turned on from a request that brings the secret, so you cannot lock yourself out by mistake. Not affected: the server itself (cron, cache preload), WP-CLI. Files the web server sends without WordPress (images, CSS, JS) are not covered. If the CDN ever stops sending the header, add define( \'SCRAPELOCK_CDN_ONLY\', false ); to wp-config.php.', 'scrapelock' ) );
				if ( '' !== trim( (string) $s['cdn_secret'] ) ) {
					echo '<p class="description pncp-cdn-only-status">' . esc_html( PNCP_Origin::has_secret( (string) $s['cdn_secret'] ) ? __( 'This request brought the secret: the CDN sends it.', 'scrapelock' ) : __( 'This request did not bring the secret: the CDN does not send it yet, or you opened the site around the CDN.', 'scrapelock' ) ) . '</p>';
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
		<?php
		self::form_close();
		self::render_edge( $s );
		self::render_ip_lists();
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
		<h2 id="pncp-sec-edge"><?php esc_html_e( 'Blocking at the CDN', 'scrapelock' ); ?></h2>
		<p class="description pncp-edge-intro"><?php esc_html_e( 'The IPs ScrapeLock blocks temporarily are also blocked by your CDN, with your own account. A scraper that keeps going is then stopped at the CDN, before its requests reach your server: no PHP, no database, no bandwidth. Each block is removed when the temporary block ends. Only the blocked addresses are sent, with the reason and the end time; nothing about your visitors or content.', 'scrapelock' ); ?></p>
		<?php
		if ( $locked ) {
			echo '<p class="description">' . esc_html__( 'The site is locked: this setting cannot be changed until it is unlocked.', 'scrapelock' ) . '</p>';
		}
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
						<p class="description" id="pncp-edge-zone-help"><?php esc_html_e( 'Cloudflare: the Zone ID on the Overview page of your site (32 characters). Bunny CDN: the ID of the Pull Zone that serves this site (a number, in the address of its page in the bunny.net dashboard).', 'scrapelock' ); ?></p>
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
						<p class="description" id="pncp-edge-token-help"><?php esc_html_e( 'Cloudflare: create an API token (My Profile → API Tokens → Create Token → Custom token) with the single permission Zone → Firewall Services → Edit, for this zone only. Bunny CDN: the API key of your account (Account settings → API); it gives access to the whole account. The token is stored in the database and never shown again; to keep it out of the database, add define( \'SCRAPELOCK_EDGE_TOKEN\', \'…\' ); to wp-config.php instead.', 'scrapelock' ); ?></p>
					</td>
				</tr>
			</table>
			<?php if ( ! $locked ) : ?>
				<p><?php submit_button( __( 'Save and test the connection', 'scrapelock' ), 'secondary', 'submit', false ); ?></p>
			<?php endif; ?>
		</form>
		<?php
		if ( ! PNCP_Edge::usable() ) {
			return;
		}
		if ( ! $locked ) {
			self::action_form_open( 'pncp_edge', 'pncp_edge', 'pncp-edge-test' );
			echo '<input type="hidden" name="op" value="test_block">';
			echo '<p>';
			submit_button( __( 'Test blocking at the CDN', 'scrapelock' ), 'secondary', 'submit', false );
			echo '</p><p class="description">' . esc_html__( 'Blocks the address 203.0.113.x (reserved for documentation, it belongs to nobody) at the CDN, checks that the CDN lists it and removes it again. No setting changes and no visitor is affected.', 'scrapelock' ) . '</p></form>';
		}
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
		if ( 'bunny' === $c['provider'] ) {
			echo '<li>' . esc_html__( 'Bunny CDN blocks single addresses: a blocked IPv6 network (/64) stays blocked by ScrapeLock only.', 'scrapelock' ) . '</li>';
		}
		echo '<li>' . esc_html__( 'Never blocked at the CDN: the IPs administrators used in the last 30 days (a block at the CDN also covers wp-admin), search engines, AI search services and the CDN\'s own servers.', 'scrapelock' ) . '</li>';
		echo '</ul>';
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
					<p><?php submit_button( __( 'Use CF-Connecting-IP (recommended)', 'scrapelock' ), 'primary', 'submit', false ); ?></p>
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
				<p><?php submit_button( __( 'Use X-Real-IP from Bunny (recommended)', 'scrapelock' ), 'primary', 'submit', false ); ?></p>
			</form>
		</div>
		<?php
	}

	/**
	 * Status of the official IP lists.
	 */
	private static function render_ip_lists() {
		$updated = PNCP_Ip::lists_updated();
		$names   = array(
			'google'          => 'Google',
			'bing'            => 'Bing',
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
		<h2 id="pncp-sec-lists"><?php esc_html_e( 'Official IP lists', 'scrapelock' ); ?></h2>
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
						} elseif ( in_array( $key, PNCP_Bots::ai_bot_lists(), true ) ) {
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
					}
					?>
				</li>
			<?php endforeach; ?>
		</ul>
		<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
			<input type="hidden" name="op" value="refresh_lists">
			<?php submit_button( __( 'Refresh lists now', 'scrapelock' ), 'secondary', 'submit', false ); ?>
		</form>
		<?php if ( PNCP_Geo::needed() ) : ?>
			<h3><?php esc_html_e( 'Country database', 'scrapelock' ); ?></h3>
			<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
				<input type="hidden" name="op" value="refresh_geo">
				<p class="description"><?php esc_html_e( 'Downloads DB-IP Lite now (about 5 MB, it may take up to a minute). It is also refreshed automatically once a month.', 'scrapelock' ); ?></p>
				<?php submit_button( __( 'Download now', 'scrapelock' ), 'secondary', 'submit', false ); ?>
			</form>
		<?php endif; ?>
		<?php
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
				self::textarea( $s, 'private_paths', __( 'Paths that are not public (one per line, * means “anything”), e.g. /skroutz.xml, /feeds/*.xml:', 'scrapelock' ) );
				self::textarea( $s, 'private_ips', __( 'Or allowed IPs / CIDR of the service (one per line):', 'scrapelock' ), __( 'Without a valid token or an allowed IP it returns 403. Applies to feeds generated by PHP. For static .xml files see the “Server rules” tab.', 'scrapelock' ), 3 );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'REST API', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::checkbox( $s, 'rest_hide_content', __( 'Hide the text (content, excerpt) of posts, pages and products from visitors', 'scrapelock' ), __( 'REST stays open for forms, oEmbed, SEO plugins and your own endpoints. Users who can write posts see the text normally. Exceptions from code: filter pncp_rest_hide_content.', 'scrapelock' ) );
				self::checkbox( $s, 'hide_rest_discovery', __( 'Hide the REST API map from visitors', 'scrapelock' ), __( '/wp-json/ no longer lists the namespaces and routes (a map of your plugins), and the page head and the Link header no longer point to the REST API and to oEmbed. Every route keeps working when called; logged-in users see everything. Leave it off if an app or service reads /wp-json/ to discover your site.', 'scrapelock' ) );
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
				self::checkbox( $s, 'feed_source_link', __( 'Full text: add “The post … first appeared on …” at the end', 'scrapelock' ), __( 'Sites that republish the feed automatically then link back to the original article, so search engines see where it first appeared.', 'scrapelock' ) );
				self::checkbox( $s, 'list_excerpts', __( 'Lists of articles: an excerpt and a link instead of the full text', 'scrapelock' ), __( 'Many themes print the whole text of every article on the home page, in categories, archives and search, so one request gives a scraper ten articles. With this on, visitors see an excerpt and a “Read the full article” link there, and each article has to be opened (and counted toward the page limit) on its own. The article pages do not change; the staff in “Who is exempt” see the full text. Changes how your lists look, so check them after turning it on. Always on in Emergency Mode.', 'scrapelock' ) );
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'XML-RPC', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'disable_pingback', __( 'Turn off pingbacks', 'scrapelock' ), __( 'pingback.ping stays open even when XML-RPC is "disabled", and is used to make your site send requests to other sites or to check which pages exist. This removes the two pingback methods and the X-Pingback header; other XML-RPC methods (e.g. Jetpack) keep working. You no longer receive pingbacks from other blogs.', 'scrapelock' ) ); ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Versions', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'hide_versions', __( 'Hide the versions of WordPress, PHP and the plugins', 'scrapelock' ), __( 'Scanners read these versions and look them up in lists of known vulnerabilities. This removes the “generator” tag from the page head and the feeds, the X-Powered-By header with the PHP version, and replaces “?ver=7.1.3” on CSS and JS files with a code that changes when the version changes, so caches still work. The readme and changelog files of WordPress and the plugins are static files: the Nginx and Apache rules in the “Server rules” tab refuse them. It does not fix any vulnerability: keep WordPress and the plugins updated.', 'scrapelock' ) ); ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Uploads', 'scrapelock' ); ?></th>
			<td>
				<?php self::checkbox( $s, 'block_upload_php', __( 'No PHP in the uploads folder', 'scrapelock' ), __( 'Files uploaded to the site (images, documents) never need to run as code. A backdoor uploaded through a vulnerable plugin usually lands in the uploads folder, so this refuses every PHP file there. On Apache it is written into the .htaccess of the uploads folder at once; on Nginx add the rule from the “Server rules” tab. If a plugin of yours really runs PHP from the uploads folder (rare), leave it off.', 'scrapelock' ) ); ?>
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
		<h2><?php esc_html_e( 'REST routes open to everyone', 'scrapelock' ); ?></h2>
		<?php /* translators: %d: number of routes */ ?>
		<p><?php echo esc_html( sprintf( _n( '%d route can be called without logging in, because its permission is open to everyone. Check after installing a plugin or updating WordPress whether a new one gives out content or data it should not.', '%d routes can be called without logging in, because their permission is open to everyone. Check after installing a plugin or updating WordPress whether a new one gives out content or data it should not.', $total, 'scrapelock' ), $total ) ); ?> <?php esc_html_e( 'Routes with their own permission check (e.g. published posts) are not listed: their text is covered by "Hide the text" above.', 'scrapelock' ); ?></p>
		<details class="pncp-public-routes">
			<summary><?php esc_html_e( 'Show the routes', 'scrapelock' ); ?></summary>
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
		</details>
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
					<?php submit_button( __( 'Revoke the previous one now', 'scrapelock' ), 'secondary', 'submit', false ); ?>
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
			<p class="description"><?php esc_html_e( 'Header for ERP and your own integrations (not visible in logs and history). Token in the URL for Skroutz, BestPrice and Google Merchant, which accept only URLs.', 'scrapelock' ); ?></p>

			<?php if ( $paths ) : ?>
				<h3><?php esc_html_e( 'Access per feed', 'scrapelock' ); ?></h3>
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
				self::checkbox( $s, 'watermark_enabled', __( 'Watermark new images', 'scrapelock' ), __( 'It is added to the sizes WordPress generates (thumbnails, medium, large). For existing images, use the tool below. The site icon, the logo and the watermark itself never get it.', 'scrapelock' ) );
				if ( ! PNCP_Watermark::available() ) {
					echo '<p class="pncp-inline-warning"><strong>' . esc_html__( 'The PHP GD library is not available on the server, so the watermark will not be applied.', 'scrapelock' ) . '</strong></p>';
				}
				self::checkbox( $s, 'watermark_full', __( 'Watermark the full-size image too', 'scrapelock' ), __( 'Without this, the full image stays clean and can be downloaded from its URL. The clean original is kept in a hidden folder, so it can always be restored.', 'scrapelock' ) );
				self::checkbox( $s, 'watermark_products', __( 'Watermark WooCommerce product images too', 'scrapelock' ) );
				?>
				<p class="pncp-inline-warning" id="pncp-products-warning"><?php esc_html_e( 'Not recommended: Google Merchant Center, Skroutz and BestPrice reject product images with a watermark, and feeds usually show the full-size image. For products, hotlink protection (“Server rules” tab) is a better choice. If a watermarked image later becomes a product image, logo or icon, the watermark is removed automatically.', 'scrapelock' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Appearance', 'scrapelock' ); ?></th>
			<td>
				<?php
				self::number( $s, 'watermark_image_id', __( 'PNG image ID from the Media Library (0 = the site\'s domain as text):', 'scrapelock' ), __( 'A PNG with a transparent background is recommended (e.g. the logo). The ID appears in the address when you open the image in the Library.', 'scrapelock' ) );
				?>
				<p><label for="pncp-watermark_position"><?php esc_html_e( 'Position:', 'scrapelock' ); ?></label>
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
				</p>
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
			<p class="description"><?php esc_html_e( 'Each image is regenerated from the clean original, so a watermark is never added twice, not even on images watermarked by version 1.x. If the page closes midway, click again: it resumes where it stopped. Keep a backup of the uploads folder before you start.', 'scrapelock' ); ?></p>
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
	 * "Server rules" tab.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function tab_rules( $s ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Same signature as the other tabs.
		?>
		<p><?php esc_html_e( 'The plugin only checks requests that reach PHP. Pages from page cache, images and static files are served directly by the server or the CDN. The rules below are generated for your site, with the current settings. Test them on staging first.', 'scrapelock' ); ?></p>
		<p class="description"><?php esc_html_e( 'The plugin does not keep a Cloudflare API token in the database: you add the rules yourself, where you already have access.', 'scrapelock' ); ?></p>

		<h2><?php esc_html_e( 'Cloudflare', 'scrapelock' ); ?></h2>
		<?php if ( PNCP_Ip::cloudflare_plugin_active() || PNCP_Ip::behind_cloudflare() ) : ?>
			<div class="notice notice-info inline"><p><?php esc_html_e( 'APO and “Cache Everything”: pages served from the Cloudflare cache never reach the plugin, so the bot list, limits and the trap do not apply to them. The WAF rules below apply before the cache. ScrapeLock tells the Cloudflare plugin not to cache blocks and private feeds, and purges its cache when you save the settings.', 'scrapelock' ); ?></p></div>
		<?php endif; ?>
		<p class="description"><?php esc_html_e( 'Security → WAF → Custom rules → Create rule → Edit expression. Paste the expression and choose the action shown.', 'scrapelock' ); ?></p>
		<?php foreach ( PNCP_Rules::cloudflare() as $key => $rule ) : ?>
			<h3><?php echo esc_html( $rule['title'] ); ?> <span class="pncp-badge"><?php echo esc_html( $rule['action'] ); ?></span></h3>
			<?php self::code_block( 'pncp-cf-' . $key, $rule['expression'], 3 ); ?>
		<?php endforeach; ?>

		<h2><?php esc_html_e( 'Nginx', 'scrapelock' ); ?></h2>
		<?php self::render_nginx_status(); ?>
		<p class="description"><?php esc_html_e( 'Optional: they stop the bots before PHP and the page cache, so the server does less work. Without access to the Nginx configuration (shared hosting) skip them: the plugin and the pre-cache check still protect the pages. The names carry this site\'s suffix, so several WordPress sites can use their rules on the same Nginx.', 'scrapelock' ); ?></p>
		<p class="description"><?php esc_html_e( '1) Inside http { }: a new file in a folder that nginx.conf includes there, e.g.', 'scrapelock' ); ?></p>
		<ul class="ul-disc description">
			<li><?php esc_html_e( 'Debian / Ubuntu, CentOS / RHEL, Plesk and most servers:', 'scrapelock' ); ?> <code><?php echo esc_html( '/etc/nginx/conf.d/scrapelock-' . PNCP_Rules::nginx_id() . '.conf' ); ?></code></li>
			<li><?php esc_html_e( 'aaPanel:', 'scrapelock' ); ?> <code><?php echo esc_html( '/www/server/panel/vhost/nginx/0.scrapelock-' . PNCP_Rules::nginx_id() . '.conf' ); ?></code></li>
		</ul>
		<?php self::code_block( 'pncp-nginx-http', PNCP_Rules::nginx_http(), 8 ); ?>
		<p class="description"><?php esc_html_e( '2) Inside the site\'s server { } (the one for HTTPS, and for HTTP if it serves pages too), before the other location blocks:', 'scrapelock' ); ?></p>
		<ul class="ul-disc description">
			<li><?php esc_html_e( 'Your own server: the site\'s file, e.g. /etc/nginx/sites-available/, or a file it includes.', 'scrapelock' ); ?></li>
			<li><?php esc_html_e( 'aaPanel: Website → the site → Config, or a file in the site\'s folder under /www/server/panel/vhost/nginx/extension/ when the site\'s configuration includes it.', 'scrapelock' ); ?></li>
			<li><?php esc_html_e( 'Plesk: Websites & Domains → Apache & nginx Settings → Additional nginx directives.', 'scrapelock' ); ?></li>
			<li><?php esc_html_e( 'Other panels: the place they give for custom server { } directives.', 'scrapelock' ); ?></li>
		</ul>
		<?php self::code_block( 'pncp-nginx-server', PNCP_Rules::nginx_server(), 18 ); ?>
		<p class="description"><?php esc_html_e( '3) Run nginx -t: only if it says “test is successful”, reload Nginx (nginx -s reload or systemctl reload nginx). If it shows an error, nothing has changed yet: remove what you added. 4) Check the status above. After every change of the settings that changes the rules, it says “out of date”: copy the part it names again.', 'scrapelock' ); ?></p>

		<h2><?php esc_html_e( 'Apache (.htaccess, above # BEGIN WordPress)', 'scrapelock' ); ?></h2>
		<?php self::code_block( 'pncp-apache', PNCP_Rules::apache(), 14 ); ?>
		<?php
	}

	/**
	 * Whether the Nginx rules are installed and match the current settings (the site asks itself).
	 */
	private static function render_nginx_status() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only asks the site again; changes nothing.
		$status = PNCP_Rules::nginx_status( isset( $_GET['pncp_nginx_check'] ) );
		$names  = array(
			'http'   => __( '1) http { }', 'scrapelock' ),
			'server' => __( '2) server { }', 'scrapelock' ),
		);
		if ( 'current' === $status['state'] ) {
			$class   = 'notice-success';
			$message = __( 'Installed and up to date with the current settings.', 'scrapelock' );
		} elseif ( 'stale' === $status['state'] ) {
			$class   = 'notice-warning';
			$message = sprintf(
				/* translators: %s: the parts, e.g. "1) http { }, 2) server { }" */
				__( 'Installed, but out of date: the settings have changed since. Copy again: %s. Then nginx -t and reload.', 'scrapelock' ),
				implode( ', ', array_intersect_key( $names, array_flip( $status['parts'] ) ) )
			);
		} elseif ( 'error' === $status['state'] ) {
			$class   = 'notice-info';
			$message = sprintf(
				/* translators: %s: error message */
				__( 'Could not check: the site could not reach itself (%s).', 'scrapelock' ),
				$status['error']
			);
		} else {
			$class   = 'notice-info';
			$message = __( 'Not installed on this site\'s Nginx (or the site is not served by Nginx).', 'scrapelock' );
		}
		$again = PNCP_Status::settings_url(
			array(
				'tab'              => 'rules',
				'pncp_nginx_check' => 1,
			)
		);
		?>
		<div class="notice <?php echo esc_attr( $class ); ?> inline"><p><strong><?php esc_html_e( 'Status:', 'scrapelock' ); ?></strong> <?php echo esc_html( $message ); ?>
			<a href="<?php echo esc_url( $again ); ?>"><?php esc_html_e( 'Check again', 'scrapelock' ); ?></a></p></div>
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
		$summary = PNCP_Log::summary( 24 );
		$reasons = PNCP_Log::reasons();
		$bans    = PNCP_Log::active_bans();
		$format  = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		?>
		<h2><?php esc_html_e( 'Last 24 hours', 'scrapelock' ); ?></h2>
		<p class="pncp-big-number"><?php echo esc_html( sprintf( /* translators: %s: count */ __( '%s blocked requests', 'scrapelock' ), number_format_i18n( $summary['total'] ) ) ); ?></p>
		<div class="pncp-cards">
			<section class="pncp-card">
				<h3><?php esc_html_e( 'By reason', 'scrapelock' ); ?></h3>
				<?php self::count_list( $summary['reasons'], $reasons ); ?>
			</section>
			<section class="pncp-card">
				<h3><?php esc_html_e( 'Top IPs', 'scrapelock' ); ?></h3>
				<?php self::ip_list( $summary['ips'] ); ?>
			</section>
			<section class="pncp-card">
				<h3><?php esc_html_e( 'Top User-Agents', 'scrapelock' ); ?></h3>
				<?php self::ua_list( $summary['uas'], $summary['ua_reasons'], $reasons ); ?>
				<p class="description"><?php esc_html_e( 'Verified search engines and AI bots are never blocked, so they never appear here: a known bot name in this list was a fake one or could not be verified.', 'scrapelock' ); ?></p>
			</section>
		</div>

		<h2><?php esc_html_e( 'What they try to copy', 'scrapelock' ); ?></h2>
		<p class="description"><?php esc_html_e( 'The blocked requests grouped by address. “Pages” exist on your site: what scrapers were after. “Addresses that do not exist” are random strings and guesses. “Files” are scanners looking for passwords, backups or admin areas. No content leaks in the last two, they only show what was tried.', 'scrapelock' ); ?></p>
		<?php
		$periods = array(
			24  => __( 'Last 24 hours', 'scrapelock' ),
			168 => __( 'Last 7 days', 'scrapelock' ),
		);
		foreach ( $periods as $hours => $period ) :
			$top = PNCP_Log::top_paths( $hours );
			?>
			<h3><?php echo esc_html( $period ); ?></h3>
			<div class="pncp-cards">
				<section class="pncp-card">
					<h4><?php esc_html_e( 'Pages', 'scrapelock' ); ?></h4>
					<?php self::path_table( $top['content'] ); ?>
				</section>
				<section class="pncp-card">
					<h4><?php esc_html_e( 'Addresses that do not exist', 'scrapelock' ); ?></h4>
					<?php self::path_table( $top['unknown'] ); ?>
					<?php if ( $top['unknown'] ) : ?>
						<p class="description"><?php esc_html_e( 'A real page here? Pages of plugins that WordPress does not know (e.g. a community or forum) count as “Pages” when you add their prefix in “Content addresses” (Bots and limits tab).', 'scrapelock' ); ?></p>
					<?php endif; ?>
				</section>
				<section class="pncp-card">
					<h4><?php esc_html_e( 'Files and admin paths', 'scrapelock' ); ?></h4>
					<?php self::path_table( $top['probes'] ); ?>
				</section>
			</div>
		<?php endforeach; ?>
		<?php if ( 7 > (int) $s['log_retention'] ) : ?>
			<p class="description"><?php esc_html_e( 'The log is kept for 1 day, so the 7-day view shows only the last day. Change “Keep the block log for” in the “Bots and limits” tab to see more.', 'scrapelock' ); ?></p>
		<?php endif; ?>

		<h2><?php esc_html_e( 'IPs blocked now', 'scrapelock' ); ?></h2>
		<?php if ( ! $bans ) : ?>
			<p><?php esc_html_e( 'None.', 'scrapelock' ); ?></p>
		<?php else : ?>
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
							<td><?php echo esc_html( isset( $reasons[ $ban['reason'] ] ) ? $reasons[ $ban['reason'] ] : $ban['reason'] ); ?></td>
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
			<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
				<input type="hidden" name="op" value="unban_all">
				<?php submit_button( __( 'Unblock all', 'scrapelock' ), 'secondary', 'submit', true ); ?>
			</form>
		<?php endif; ?>

		<?php self::render_repeat_offenders( $format, $reasons ); ?>

		<h2><?php esc_html_e( 'Latest events', 'scrapelock' ); ?></h2>
		<?php $rows = PNCP_Log::recent( 100 ); ?>
		<?php if ( ! $rows ) : ?>
			<p><?php esc_html_e( 'No events.', 'scrapelock' ); ?></p>
		<?php else : ?>
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
					<?php $buttons = array(); ?>
					<?php foreach ( $rows as $row ) : ?>
						<tr>
							<td><?php echo esc_html( wp_date( $format, (int) strtotime( $row['created'] . ' UTC' ) ) ); ?></td>
							<td>
								<code><?php echo esc_html( $row['ip'] ); ?></code>
								<?php
								// The button once per IP: the first (most recent) row of each.
								if ( ! isset( $buttons[ $row['ip'] ] ) ) {
									$buttons[ $row['ip'] ] = true;
									echo '<br>';
									self::block_permanently_button( (string) $row['ip'] );
								}
								?>
							</td>
							<td><?php echo esc_html( ( isset( $reasons[ $row['reason'] ] ) ? $reasons[ $row['reason'] ] : $row['reason'] ) . ' (' . $row['code'] . ')' ); ?></td>
							<td><?php echo esc_html( number_format_i18n( (int) $row['hits'] ) ); ?></td>
							<td><code><?php echo esc_html( PNCP_Log::display_path( $row['path'] ) ); ?></code></td>
							<td class="pncp-ua">
								<?php
								echo esc_html( $row['ua'] );
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
		<?php endif; ?>
		<p class="description">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: days */
					__( 'The log is deleted automatically after %s days (setting in the “Bots and limits” tab).', 'scrapelock' ),
					$s['log_retention']
				)
			);
			?>
		</p>
		<?php self::action_form_open( 'pncp_log', 'pncp_log' ); ?>
			<input type="hidden" name="op" value="clear_log">
			<?php submit_button( __( 'Delete log', 'scrapelock' ), 'delete', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Table of paths with requests and distinct IPs.
	 *
	 * @param array<int, array{path:string, hits:int, ips:int}> $rows Rows.
	 */
	private static function path_table( $rows ) {
		if ( ! $rows ) {
			echo '<p>' . esc_html__( 'Nothing.', 'scrapelock' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped pncp-path-table"><thead><tr>';
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
		echo '</tbody></table>';
	}

	/**
	 * "value — count" list.
	 *
	 * @param array<string, int>    $counts Counts.
	 * @param array<string, string> $labels Labels (optional).
	 */
	private static function count_list( $counts, $labels = array() ) {
		if ( ! $counts ) {
			echo '<p>' . esc_html__( 'Nothing.', 'scrapelock' ) . '</p>';
			return;
		}
		echo '<ol class="pncp-count-list">';
		foreach ( $counts as $key => $count ) {
			printf( '<li><span>%s</span> <strong>%s</strong></li>', esc_html( isset( $labels[ $key ] ) ? $labels[ $key ] : (string) $key ), esc_html( number_format_i18n( $count ) ) );
		}
		echo '</ol>';
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
	 * Persistent IPs of the last 7 days (two or more temporary blocks, or many blocked requests), with the
	 * "Block permanently" button.
	 *
	 * @param string                $format  Date format.
	 * @param array<string, string> $reasons Reason labels.
	 */
	private static function render_repeat_offenders( $format, $reasons ) {
		$rows = PNCP_Log::repeat_offenders();
		?>
		<h2><?php esc_html_e( 'Persistent IPs (last 7 days)', 'scrapelock' ); ?></h2>
		<p class="description">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: number of requests */
					__( 'IPs with at least two temporary blocks, or at least %s blocked requests. They keep coming back: you can block them permanently.', 'scrapelock' ),
					number_format_i18n( (int) apply_filters( 'pncp_persistent_requests', 100 ) )
				)
			);
			?>
		</p>
		<?php if ( ! $rows ) : ?>
			<p><?php esc_html_e( 'None.', 'scrapelock' ); ?></p>
			<?php
			return;
		endif;
		?>
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
						<td><?php echo esc_html( isset( $reasons[ $row['reason'] ] ) ? $reasons[ $row['reason'] ] : $row['reason'] ); ?></td>
						<td><?php echo esc_html( wp_date( $format, (int) strtotime( $row['last'] . ' UTC' ) ) ); ?></td>
						<td><?php self::block_permanently_button( $row['ip'] ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * The top IPs with their requests and the "Block permanently" button.
	 *
	 * @param array<string, int> $counts IP => requests.
	 */
	private static function ip_list( $counts ) {
		if ( ! $counts ) {
			echo '<p>' . esc_html__( 'Nothing.', 'scrapelock' ) . '</p>';
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
			echo '<p>' . esc_html__( 'Nothing.', 'scrapelock' ) . '</p>';
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
				'' !== $main ? '<br><small class="pncp-ua-reason">' . esc_html( isset( $reasons[ $main ] ) ? $reasons[ $main ] : $main ) . '</small>' : '',
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
	 * @param string $tab     Tab.
	 * @param string $message Notice code.
	 */
	private static function back( $tab, $message ) {
		wp_safe_redirect(
			PNCP_Status::settings_url(
				array(
					'tab'          => $tab,
					'pncp_message' => $message,
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
		if ( ! isset( $profiles[ $profile ] ) ) {
			self::back( 'general', 'error' );
		}
		update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $profiles[ $profile ] ) );
		PNCP_Options::flush();
		self::back( 'general', 'profile' );
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
			case 'clear_log':
				PNCP_Log::clear();
				self::back( 'log', 'cleared' );
				break;
			case 'refresh_lists':
				$result = PNCP_Ip::refresh_lists();
				self::back( 'bots', in_array( 0, $result, true ) ? 'lists_partial' : 'lists' );
				break;
			case 'refresh_geo':
				self::back( 'bots', PNCP_Geo::refresh() ? 'geo' : 'geo_failed' );
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
	 * Blocking at the CDN: saves the configuration and tests it with one read-only request. An empty token
	 * keeps the saved one. Not while the site is locked.
	 */
	public static function handle_edge() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The nonce is checked in verify().
		self::verify( 'pncp_edge' );
		if ( PNCP_Lockdown::is_locked() ) {
			self::back( 'bots', 'error' );
		}
		if ( isset( $_POST['op'] ) && 'test_block' === sanitize_key( wp_unslash( $_POST['op'] ) ) ) {
			$result = PNCP_Edge::test_block( PNCP_Edge::config() );
			set_transient( 'pncp_edge_test_' . get_current_user_id(), $result['message'], 2 * MINUTE_IN_SECONDS );
			self::back( 'bots', $result['ok'] ? 'edge_test_ok' : 'edge_test_failed' );
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
			self::back( 'bots', 'edge_off' );
		}
		$zone  = PNCP_Edge::clean_zone( $provider, $raw_zone );
		$token = '' === trim( $raw ) ? ( $old['provider'] === $provider ? $old['token'] : '' ) : PNCP_Edge::clean_token( $raw );
		if ( PNCP_Edge::token_from_config() ) {
			$token = PNCP_Edge::config()['token'];
		}
		if ( '' === $zone || '' === $token ) {
			self::back( 'bots', '' === $zone ? 'edge_zone' : 'edge_token' );
		}
		$new   = array(
			'provider' => $provider,
			'zone'     => $zone,
			'token'    => $token,
		);
		$error = PNCP_Edge::test( $new );
		if ( '' !== $error ) {
			// Not saved: a wrong token or zone would only fill the log with errors.
			set_transient( 'pncp_edge_test_' . get_current_user_id(), $error, 2 * MINUTE_IN_SECONDS );
			self::back( 'bots', 'edge_failed' );
		}
		PNCP_Edge::save_config( $new );
		self::back( 'bots', 'edge_ok' );
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
			'token'            => array( 'success', __( 'New token created.', 'scrapelock' ) ),
			'revoked'          => array( 'success', __( 'Previous token revoked.', 'scrapelock' ) ),
			'unbanned'         => array( 'success', __( 'Block lifted.', 'scrapelock' ) ),
			'cleared'          => array( 'success', __( 'Log deleted.', 'scrapelock' ) ),
			'perm_added'       => array( 'success', __( 'The IP was added to the always-blocked IPs (“Bots and limits” → “Always blocked”). You can remove it there.', 'scrapelock' ) ),
			'perm_exists'      => array( 'info', __( 'The IP is already in the always-blocked IPs.', 'scrapelock' ) ),
			'perm_full'        => array( 'error', __( 'The always-blocked IPs already have 200 lines. Combine addresses into CIDR ranges there first.', 'scrapelock' ) ),
			'perm_refused'     => array( 'error', __( 'This IP cannot be blocked permanently: it is the server itself, your own IP, a private address, an always-allowed IP or an address in an official list (Google, Bing, AI search services, Cloudflare, Bunny CDN).', 'scrapelock' ) ),
			'lists'            => array( 'success', __( 'IP lists refreshed.', 'scrapelock' ) ),
			'geo'              => array( 'success', __( 'Country database downloaded.', 'scrapelock' ) ),
			'geo_failed'       => array( 'error', __( 'The country database could not be downloaded or read; the previous one (if any) was kept. It will try again tomorrow.', 'scrapelock' ) ),
			'cf_ip'            => array( 'success', __( 'The real visitor IP is now read from CF-Connecting-IP, only for requests from Cloudflare.', 'scrapelock' ) ),
			'bunny_ip'         => array( 'success', __( 'The real visitor IP is now read from X-Real-IP, only for requests from Bunny CDN.', 'scrapelock' ) ),
			'bunny_ip_failed'  => array( 'warning', __( 'X-Real-IP is selected for Bunny CDN, but the list of Bunny addresses could not be downloaded. Until it is, the header is not trusted. It will try again tomorrow, or use “Refresh now” under “Official IP lists”.', 'scrapelock' ) ),
			'lists_partial'    => array( 'warning', __( 'Some IP lists could not be downloaded; their previous version was kept. It will try again tomorrow.', 'scrapelock' ) ),
			'edge_ok'          => array( 'success', __( 'Connected to the CDN. From now on the IPs ScrapeLock blocks temporarily are also blocked there (within a minute or two).', 'scrapelock' ) ),
			'edge_off'         => array( 'success', __( 'Blocking at the CDN is off. The blocks ScrapeLock made there are being removed in the background.', 'scrapelock' ) ),
			'edge_zone'        => array( 'error', __( 'The zone ID is not valid: Cloudflare uses 32 letters and digits (0–9, a–f), Bunny CDN a number. Nothing was saved.', 'scrapelock' ) ),
			'edge_token'       => array( 'error', __( 'Enter the API token (letters, digits, “-” and “_”). Nothing was saved.', 'scrapelock' ) ),
			'edge_failed'      => array( 'error', __( 'The connection test failed, so nothing was saved.', 'scrapelock' ) ),
			'edge_test_ok'     => array( 'success', '' ),
			'edge_test_failed' => array( 'error', '' ),
			'error'            => array( 'error', __( 'The action was not completed.', 'scrapelock' ) ),
		);
		if ( isset( $texts[ $message ] ) ) {
			$text = $texts[ $message ][1];
			if ( in_array( $message, array( 'edge_failed', 'edge_test_ok', 'edge_test_failed' ), true ) ) {
				$detail = get_transient( 'pncp_edge_test_' . get_current_user_id() );
				delete_transient( 'pncp_edge_test_' . get_current_user_id() );
				$text = trim( $text . ( is_string( $detail ) && '' !== $detail ? ' ' . $detail : '' ) );
			}
			if ( '' !== $text ) {
				printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $texts[ $message ][0] ), esc_html( $text ) );
			}
		}

		// The 1.x token is still valid but exists only as a hash: it cannot be shown.
		if ( $ours && get_option( 'pncp_legacy_token_migrated' ) ) {
			delete_option( 'pncp_legacy_token_migrated' );
			printf(
				'<div class="notice notice-info"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
				esc_html__( 'Since 2.1 the feed token is stored only as a hash. The old token is still valid but can no longer be shown. If you have not saved it, create a new token.', 'scrapelock' ),
				esc_url( PNCP_Status::settings_url( array( 'tab' => 'content' ) ) ),
				esc_html__( 'Feeds and token', 'scrapelock' )
			);
		}
		if ( ! empty( PNCP_Options::stored()['trust_any_proxy'] ) && PNCP_Status::notice_screen() ) {
			printf(
				'<div class="notice notice-warning"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
				esc_html__( 'ScrapeLock: the real IP is read from a header without checking the proxy (as in 1.4). This allows IP spoofing.', 'scrapelock' ),
				esc_url( PNCP_Status::settings_url( array( 'tab' => 'bots' ) ) ),
				esc_html__( 'Trusted Proxy settings', 'scrapelock' )
			);
		}
	}
}
