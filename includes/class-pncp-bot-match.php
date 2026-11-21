<?php
/**
 * 3.11: which entry of the bot list blocked a request ("User-Agent in the bot list"), for the Log. The generic
 * HTTP libraries (curl, python-requests, Go-http-client, axios, okhttp…, PNCP_Options::http_library_agents()) are
 * also used by mobile apps, ERP sync and monitors, so the Log names the library that matched and offers "Allow this
 * service": the whole User-Agent of that row goes to "Always allowed User-Agents", never the bare library name
 * (which would let every script of that library through).
 *
 * The log table keeps no detail column (and its reason is 20 characters at most): the entry is found again from
 * the logged User-Agent with the lists as they are now, in the same order as PNCP_Options::blocked_agents(). No
 * schema change. Nothing is ever blocked here: the button only allows.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The matched entry of a bot-list refusal, its Log line and the "Allow this service" button.
 */
final class PNCP_Bot_Match {

	/**
	 * The admin-post action of the "Allow this service" button.
	 */
	const ACTION = 'pncp_allow_service';

	/**
	 * The reason of the saved version (PNCP_Settings_Io::backup()) made before the allow list changes.
	 */
	const BACKUP_REASON = 'allow_service';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		add_action( 'admin_notices', array( __CLASS__, 'render_result_notice' ) );
	}

	/**
	 * The entry of the blocked User-Agents that matches a User-Agent, and where it comes from.
	 *
	 * @param string               $ua User-Agent.
	 * @param array<string, mixed> $s  Settings.
	 * @return array{token:string, source:string, http_lib:bool}|null source: bot_list | ai | ai_search | ripper | archive | seo | tech | http_libs.
	 */
	public static function entry( $ua, $s ) {
		$ua = (string) $ua;
		if ( '' === trim( $ua ) ) {
			return null;
		}
		$skip    = PNCP_Options::ai_search_skipped( $s );
		$libs    = array_map( 'strtolower', PNCP_Options::http_library_agents() );
		$sources = array(
			'bot_list'  => PNCP_Options::parse_list( isset( $s['bot_list'] ) ? (string) $s['bot_list'] : '' ),
			'ai'        => PNCP_Bots::known_ai_agents(),
			'ai_search' => PNCP_Options::ai_search_blocked( $s ), // 3.12.1: while "Allow AI search" is off.
			'ripper'    => PNCP_Bots::ripper_agents(),
			'archive'   => empty( $s['block_archivers'] ) ? array() : PNCP_Bots::archive_agents(),
			'seo'       => empty( $s['block_seo_crawlers'] ) ? array() : PNCP_Bots::seo_agents(),
			'tech'      => empty( $s['block_tech_profilers'] ) ? array() : PNCP_Bots::tech_profiler_agents(), // 3.12.6.
			'http_libs' => empty( $s['block_http_libs'] ) ? array() : PNCP_Options::http_library_agents(),
		);
		foreach ( $sources as $source => $agents ) {
			foreach ( $agents as $agent ) {
				$agent = trim( (string) $agent );
				if ( '' === $agent || '=' === $agent || isset( $skip[ strtolower( $agent ) ] ) ) {
					continue;
				}
				if ( PNCP_Bots::ua_in_list( $ua, array( $agent ) ) ) {
					return array(
						'token'    => $agent,
						'source'   => $source,
						'http_lib' => in_array( strtolower( $agent ), $libs, true ),
					);
				}
			}
		}
		return null;
	}

	/**
	 * What "Allow this service" adds: the whole User-Agent of the row (as the allow list keeps it, 100 characters
	 * at most), so only that client passes, not every program built on the same library.
	 *
	 * @param string $ua User-Agent.
	 * @return string
	 */
	public static function service_pattern( $ua ) {
		return mb_substr( trim( sanitize_text_field( (string) $ua ) ), 0, 100 );
	}

	/**
	 * The line under the reason of a "User-Agent in the bot list" row: the entry that matched.
	 *
	 * @param array<string, mixed> $row Log row.
	 * @param array<string, mixed> $s   Settings.
	 */
	public static function render_reason( $row, $s ) {
		if ( 'bot_ua' !== $row['reason'] ) {
			return;
		}
		$entry = self::entry( (string) $row['ua'], $s );
		if ( null === $entry ) {
			return;
		}
		$where = array(
			'bot_list'  => __( 'your bot list', 'scrapelock' ),
			'ai'        => __( 'the built-in AI crawlers', 'scrapelock' ),
			'ai_search' => __( 'the built-in AI search bots, blocked while AI search is not allowed', 'scrapelock' ),
			'ripper'    => __( 'the built-in site rippers', 'scrapelock' ),
			'archive'   => __( 'web archives', 'scrapelock' ),
			'seo'       => __( 'SEO and marketing data crawlers', 'scrapelock' ),
			'tech'      => __( 'technology profilers', 'scrapelock' ),
			'http_libs' => __( '“Also block generic HTTP libraries”', 'scrapelock' ),
		);
		$text = $entry['http_lib']
			/* translators: 1: bot list entry, e.g. python-requests, 2: where it comes from, e.g. your bot list */
			? __( 'Matched “%1$s”: a generic HTTP library (%2$s)', 'scrapelock' )
			/* translators: 1: bot list entry, e.g. GPTBot, 2: where it comes from, e.g. your bot list */
			: __( 'Matched “%1$s” (%2$s)', 'scrapelock' );
		printf(
			'<br><span class="description pncp-bot-match" data-token="%1$s">%2$s</span>',
			esc_attr( $entry['token'] ),
			esc_html( sprintf( $text, ltrim( $entry['token'], '=' ), $where[ $entry['source'] ] ) )
		);
	}

	/**
	 * "Allow this service" next to a row blocked by a generic HTTP library. Replaced by nothing when the
	 * User-Agent is already allowed (the existing "Always allowed now" note says so).
	 *
	 * @param string               $ua User-Agent of the row.
	 * @param array<string, mixed> $s  Settings.
	 */
	public static function render_allow_button( $ua, $s ) {
		$entry   = self::entry( $ua, $s );
		$pattern = self::service_pattern( $ua );
		if ( null === $entry || ! $entry['http_lib'] || '' !== PNCP_Options::allow_token_refusal( $pattern ) || self::allowed( $pattern, $s ) ) {
			return;
		}
		printf( '<br><form method="post" action="%s" class="pncp-inline-form pncp-allow-service-form">', esc_url( admin_url( 'admin-post.php' ) ) );
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( self::ACTION ) );
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( self::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
		printf( '<input type="hidden" name="ua" value="%s">', esc_attr( $pattern ) );
		printf(
			'<button type="submit" class="button button-small" title="%1$s">%2$s</button></form>',
			/* translators: %s: User-Agent */
			esc_attr( sprintf( __( 'Adds “%s” (this whole User-Agent, not the library name) to “Always allowed User-Agents”. The page limits still apply to it.', 'scrapelock' ), $pattern ) ),
			esc_html__( 'Allow this service', 'scrapelock' )
		);
	}

	/**
	 * Whether an entry of the same text is in the allow list already.
	 *
	 * @param string               $pattern Pattern.
	 * @param array<string, mixed> $s       Settings.
	 * @return bool
	 */
	private static function allowed( $pattern, $s ) {
		return in_array( strtolower( $pattern ), array_map( 'strtolower', PNCP_Options::parse_list( (string) $s['allow_list'] ) ), true );
	}

	/**
	 * Adds the User-Agent of a row blocked by a generic HTTP library to "Always allowed User-Agents", after saving
	 * the settings as an earlier version. Not while the site is locked.
	 *
	 * @param string $ua User-Agent.
	 * @return string added | exists | full | refused | locked
	 */
	public static function allow( $ua ) {
		if ( PNCP_Lockdown::is_locked() ) {
			return 'locked';
		}
		$stored  = PNCP_Options::stored();
		$pattern = self::service_pattern( $ua );
		$entry   = self::entry( $pattern, PNCP_Options::get() );
		// Only for what the button is shown for: a request a generic HTTP library blocked.
		if ( null === $entry || ! $entry['http_lib'] || '' !== PNCP_Options::allow_token_refusal( $pattern ) ) {
			return 'refused';
		}
		if ( self::allowed( $pattern, $stored ) ) {
			return 'exists';
		}
		if ( count( PNCP_Options::parse_list( (string) $stored['allow_list'] ) ) >= 200 ) {
			return 'full';
		}
		PNCP_Settings_Io::backup( self::BACKUP_REASON );
		return PNCP_Options::allow_user_agent( $pattern );
	}

	/**
	 * The button: nonce, manage_options, not while the site is locked.
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checked just above.
		$ua = isset( $_POST['ua'] ) ? sanitize_text_field( wp_unslash( $_POST['ua'] ) ) : '';
		wp_safe_redirect(
			PNCP_Status::settings_url(
				array(
					'tab'          => 'log',
					'pncp_message' => 'allow_service_' . self::allow( $ua ),
				)
			)
		);
		exit;
	}

	/**
	 * The notice after the button (the settings page's own notices do not know these codes).
	 */
	public static function render_result_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays a notice.
		$message = isset( $_GET['pncp_message'] ) ? sanitize_key( wp_unslash( $_GET['pncp_message'] ) ) : '';
		if ( ! $screen || 'settings_page_' . PNCP_Status::SETTINGS_PAGE !== $screen->id || 0 !== strpos( $message, 'allow_service_' ) ) {
			return;
		}
		$texts = array(
			'allow_service_added'  => array( 'success', __( 'The service\'s User-Agent was added to “Always allowed User-Agents” (“Bots and limits” → “Always allowed”). Other programs of the same library stay blocked. The settings before the change are under “Earlier versions”.', 'scrapelock' ) ),
			'allow_service_exists' => array( 'info', __( 'This User-Agent is already always allowed.', 'scrapelock' ) ),
			'allow_service_full'   => array( 'error', __( 'The always-allowed User-Agents already have 200 lines: remove some under “Always allowed”, then try again.', 'scrapelock' ) ),
		);
		$text = isset( $texts[ $message ] ) ? $texts[ $message ] : array( 'error', __( 'Nothing was added: this User-Agent was not blocked by a generic HTTP library, is too generic, or the site is locked (unlock it on the Lockdown tab and try again).', 'scrapelock' ) );
		printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $text[0] ), esc_html( $text[1] ) );
	}
}
