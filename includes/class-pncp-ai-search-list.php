<?php
/**
 * 3.11: "Allow AI search" and a bot list that still names those bots. Lists saved before 3.11 (and the default
 * list) contain OAI-SearchBot, ChatGPT-User, PerplexityBot, Perplexity-User, DuckAssistBot, MistralAI-User…: with
 * the option on they are let through anyway (PNCP_Options::ai_search_skipped() takes them out of
 * PNCP_Options::blocked_agents()), but the list said otherwise. The Bots tab says so, with a "Remove from the list"
 * button, and the upgrade to 3.11 removes them once (migrate_311()). Training crawlers (GPTBot, ClaudeBot, CCBot,
 * Google-Extended, Bytespider…) are never touched. Nothing is ever blocked here.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The Bots tab warning, its button and the one-time migration.
 */
final class PNCP_Ai_Search_List {

	/**
	 * The admin-post action of the "Remove from the list" button.
	 */
	const ACTION = 'pncp_ai_search_list';

	/**
	 * The reason of the saved version (PNCP_Settings_Io::backup()) made before the list changes.
	 */
	const BACKUP_REASON = 'ai_search_list';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
		add_action( 'admin_notices', array( __CLASS__, 'render_result_notice' ) );
	}

	/**
	 * Removes the allowed AI search bots from the stored bot list, after saving the settings as an earlier version
	 * (Log tab → "Earlier versions", so it can be undone). Not while the site is locked.
	 *
	 * @return int How many lines were removed (0: nothing to remove, or the site is locked).
	 */
	public static function remove() {
		if ( PNCP_Lockdown::is_locked() ) {
			return 0;
		}
		$stored = PNCP_Options::stored();
		$found  = PNCP_Options::ai_search_in_bot_list( $stored );
		if ( ! $found ) {
			return 0;
		}
		PNCP_Settings_Io::backup( self::BACKUP_REASON );
		update_option( PNCP_OPTION, PNCP_Options::without_ai_search_in_bot_list( $stored ) );
		PNCP_Options::flush();
		return count( $found );
	}

	/**
	 * 3.11 upgrade (pncp_upgrade(), once, from a version before 3.11.0): the same as the button, for sites with
	 * "Allow AI search" on. Sites with it off keep their list: there it blocks those bots, as intended.
	 *
	 * @return int How many lines were removed.
	 */
	public static function migrate_311() {
		$stored = get_option( PNCP_OPTION );
		if ( ! is_array( $stored ) || ! PNCP_Options::ai_search_in_bot_list( $stored ) ) {
			return 0;
		}
		$count = count( PNCP_Options::ai_search_in_bot_list( $stored ) );
		PNCP_Settings_Io::backup( self::BACKUP_REASON );
		update_option( PNCP_OPTION, PNCP_Options::without_ai_search_in_bot_list( $stored ), true );
		PNCP_Options::flush();
		return $count;
	}

	/**
	 * The button: nonce, manage_options, not while the site is locked.
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$removed = self::remove();
		wp_safe_redirect(
			PNCP_Status::settings_url(
				array(
					'tab'          => 'bots',
					'pncp_message' => $removed > 0 ? 'ai_search_list_removed' : 'ai_search_list_error',
				)
			) . '#pncp-sec-bots'
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
		if ( ! $screen || 'settings_page_' . PNCP_Status::SETTINGS_PAGE !== $screen->id || 0 !== strpos( $message, 'ai_search_list_' ) ) {
			return;
		}
		if ( 'ai_search_list_removed' === $message ) {
			$text = __( 'The AI search bots were removed from the bot list. The training crawlers stay in it. The settings before the change are under “Earlier versions”.', 'scrapelock' );
			$type = 'success';
		} else {
			$text = __( 'Nothing changed: the bot list has no allowed AI search bots, or the site is locked.', 'scrapelock' );
			$type = 'error';
		}
		printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $type ), esc_html( $text ) );
	}

	/**
	 * The warning at the top of the Bots tab, with its own form (before the settings form opens: forms cannot nest).
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	public static function render_notice( $s ) {
		$found = PNCP_Options::ai_search_in_bot_list( $s );
		if ( ! $found ) {
			return;
		}
		echo '<div class="notice notice-warning inline pncp-ai-search-list-notice"><p>';
		echo esc_html(
			sprintf(
				/* translators: %s: list of User-Agents, e.g. "OAI-SearchBot, ChatGPT-User" */
				__( 'These AI search bots are in the bot list but AI search is allowed: they are let through (%s). Remove them from the list so that it shows what is blocked. Training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended…) stay blocked.', 'scrapelock' ),
				implode( ', ', $found )
			)
		);
		echo '</p>';
		printf( '<form method="post" action="%s">', esc_url( admin_url( 'admin-post.php' ) ) );
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( self::ACTION ) );
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( self::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
		// 3.11: the bot list is folded (an entry count with "Edit", PNCP_Admin_Lists): a link opens it (admin.js).
		echo '<p><button type="submit" class="button button-primary" id="pncp-ai-search-list-remove">' . esc_html__( 'Remove from the list', 'scrapelock' ) . '</button> <a class="button-link pncp-ai-search-list-open" href="#pncp-bot_list">' . esc_html__( 'Show the bot list', 'scrapelock' ) . '</a></p></form></div>';
	}
}
