<?php
/**
 * 3.6: an invisible trace of the account in the text of protected pages. Each paragraph gets, after its first
 * word, a run of invisible characters (zero-width space and non-joiner, between word joiners) that spells the
 * account, the day and a signature made with this site's keys. Copied text keeps it; pasted under Log →
 * "Find whose copy this is", it shows whose account the copy came from and when. Only for signed-in accounts:
 * visitors and search engines get the text as it is.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The text trace.
 */
final class PNCP_Trace {

	/**
	 * The first day counted (days since then are stored in 16 bits: until 2203).
	 */
	const EPOCH = 1704067200; // 2024-01-01 UTC.

	/**
	 * Zero-width characters: bit 0, bit 1, and the two that frame a trace.
	 */
	const ZERO  = "\u{200B}";
	const ONE   = "\u{200C}";
	const OPEN  = "\u{2060}\u{200D}";
	const CLOSE = "\u{200D}\u{2060}";

	/**
	 * The nonce action of the "Find whose copy this is" form.
	 */
	const ACTION = 'pncp_trace_find';

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_filter( 'the_content', array( __CLASS__, 'content' ), 999 );
		add_action( 'template_redirect', array( __CLASS__, 'private_page' ), 2 );
	}

	/**
	 * Is the trace added on this page? The option on, a signed-in account, and a page the protection covers
	 * (so never for exempt staff, feeds or the REST API).
	 *
	 * @return bool
	 */
	public static function active() {
		$s = PNCP_Options::get();
		return ! empty( $s['text_trace'] ) && is_user_logged_in() && PNCP_Frontend::should_protect();
	}

	/**
	 * The trace of an account on a day: 64 invisible characters between the frame. Bits: the user ID (32), the
	 * day (16) and a signature of both with this site's keys (16), so a trace cannot be made up for another
	 * account without the keys in wp-config.php.
	 *
	 * @param int      $user_id User.
	 * @param int|null $day     Days since EPOCH (null = today).
	 * @return string
	 */
	public static function token( $user_id, $day = null ) {
		$day  = null === $day ? self::today() : (int) $day;
		$bits = sprintf( '%032b%016b%016b', (int) $user_id & 0xFFFFFFFF, $day & 0xFFFF, self::mac( (int) $user_id, $day ) );
		$map  = array(
			'0' => self::ZERO,
			'1' => self::ONE,
		);
		return self::OPEN . strtr( $bits, $map ) . self::CLOSE;
	}

	/**
	 * Days since EPOCH, today.
	 *
	 * @return int
	 */
	public static function today() {
		return (int) floor( ( time() - self::EPOCH ) / DAY_IN_SECONDS );
	}

	/**
	 * 16 bits of an HMAC of the account and the day.
	 *
	 * @param int $user_id User.
	 * @param int $day     Day.
	 * @return int
	 */
	private static function mac( $user_id, $day ) {
		return (int) hexdec( substr( hash_hmac( 'sha256', 'pncp-trace|' . $user_id . '|' . $day, wp_salt( 'auth' ) ), 0, 4 ) );
	}

	/**
	 * Adds the trace after the first word of each paragraph and list item whose text starts right after the tag
	 * (a paragraph that starts with a link or bold text is skipped). Never inside tags, scripts or code.
	 *
	 * @param string $content Post content (HTML).
	 * @return string
	 */
	public static function content( $content ) {
		if ( ! is_string( $content ) || '' === $content || ! in_the_loop() || ! is_main_query() || ! self::active() ) {
			return $content;
		}
		$token = self::token( get_current_user_id() );
		return (string) preg_replace_callback(
			'#(<(?:p|li)\b[^>]*>)([^<\s][^<\s]*\s)#u',
			static function ( $m ) use ( $token ) {
				return $m[1] . $m[2] . $token;
			},
			$content
		);
	}

	/**
	 * A page with an account's trace in it must not be kept by a browser, proxy or CDN cache.
	 */
	public static function private_page() {
		if ( self::active() && ! headers_sent() ) {
			header( 'Cache-Control: private, no-store, max-age=0' );
		}
	}

	/**
	 * The traces found in a text: one row per account and day, with how many times it was found. A trace whose
	 * signature does not match was not made by this site (or the keys in wp-config.php changed since).
	 *
	 * @param string $text Pasted text.
	 * @return array<int, array{user_id:int, day:int, date:string, count:int, valid:bool}>
	 */
	public static function find( $text ) {
		$found = array();
		if ( ! preg_match_all( '/' . self::OPEN . '([' . self::ZERO . self::ONE . ']{64})' . self::CLOSE . '/u', (string) $text, $m ) ) {
			return array();
		}
		foreach ( $m[1] as $run ) {
			$bits = strtr(
				$run,
				array(
					self::ZERO => '0',
					self::ONE  => '1',
				)
			);
			$user = (int) bindec( substr( $bits, 0, 32 ) );
			$day  = (int) bindec( substr( $bits, 32, 16 ) );
			$mac  = (int) bindec( substr( $bits, 48, 16 ) );
			$key  = $user . '|' . $day;
			if ( ! isset( $found[ $key ] ) ) {
				$found[ $key ] = array(
					'user_id' => $user,
					'day'     => $day,
					'date'    => wp_date( get_option( 'date_format' ), self::EPOCH + $day * DAY_IN_SECONDS + 12 * HOUR_IN_SECONDS ),
					'count'   => 0,
					'valid'   => hash_equals( (string) self::mac( $user, $day ), (string) $mac ),
				);
			}
			++$found[ $key ]['count'];
		}
		return array_values( $found );
	}

	/**
	 * The "Find whose copy this is" card on the Log tab (administrators). The text is read only on this request
	 * and never stored.
	 */
	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s      = PNCP_Options::get();
		$posted = isset( $_POST['pncp_trace_text'], $_POST['_pncp_trace'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_pncp_trace'] ) ), self::ACTION );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only searched for the invisible characters (sanitize_textarea_field() would remove them); never stored or printed.
		$text  = $posted ? (string) wp_unslash( $_POST['pncp_trace_text'] ) : '';
		$found = $posted ? self::find( $text ) : array();
		?>
		<details class="pncp-card pncp-trace" id="pncp-trace"<?php echo $posted ? ' open' : ''; ?>>
			<summary><h2 class="pncp-tester__title"><?php esc_html_e( 'Find whose copy this is', 'scrapelock' ); ?></h2></summary>
			<p class="description"><?php esc_html_e( 'Paste text copied from this site that turned up somewhere else (a website, a document, a message). If it was copied by a signed-in account while “Hide an invisible trace of the account in the text” was on, the account and the day are shown. Copy it from the original place as text; a screenshot or retyped text carries no trace.', 'scrapelock' ); ?></p>
			<?php if ( empty( $s['text_trace'] ) ) : ?>
				<p class="description"><?php esc_html_e( 'The trace is off now (On the page → Members and readers): only text copied while it was on carries one.', 'scrapelock' ); ?></p>
			<?php endif; ?>
			<form method="post" action="#pncp-trace" data-pncp-nodirty>
				<?php wp_nonce_field( self::ACTION, '_pncp_trace' ); ?>
				<p><label class="screen-reader-text" for="pncp-trace-text"><?php esc_html_e( 'Copied text', 'scrapelock' ); ?></label>
				<textarea id="pncp-trace-text" name="pncp_trace_text" rows="5" class="large-text"></textarea></p>
				<p><button type="submit" class="button"><?php esc_html_e( 'Find', 'scrapelock' ); ?></button></p>
			</form>
			<?php if ( $posted && ! $found ) : ?>
				<p><strong><?php esc_html_e( 'No trace in this text.', 'scrapelock' ); ?></strong> <?php esc_html_e( 'It was copied by a visitor who was not signed in, before the option was on, retyped, or the invisible characters were removed on the way (some editors and sites remove them).', 'scrapelock' ); ?></p>
			<?php elseif ( $found ) : ?>
				<table class="widefat striped">
					<thead><tr><th><?php esc_html_e( 'Account', 'scrapelock' ); ?></th><th><?php esc_html_e( 'Day', 'scrapelock' ); ?></th><th><?php esc_html_e( 'Found', 'scrapelock' ); ?></th></tr></thead>
					<tbody>
						<?php foreach ( $found as $row ) : ?>
							<?php $user = $row['valid'] ? get_userdata( $row['user_id'] ) : false; ?>
							<tr>
								<td>
									<?php
									if ( ! $row['valid'] ) {
										esc_html_e( 'Not a trace of this site (or the keys in wp-config.php changed since)', 'scrapelock' );
									} elseif ( $user ) {
										echo '<a href="' . esc_url( admin_url( 'user-edit.php?user_id=' . (int) $user->ID ) ) . '">' . esc_html( $user->user_login ) . '</a> (#' . (int) $user->ID . ')';
									} else {
										/* translators: %d: user ID */
										echo esc_html( sprintf( __( 'Account #%d (deleted since)', 'scrapelock' ), $row['user_id'] ) );
									}
									?>
								</td>
								<td><?php echo esc_html( $row['valid'] ? $row['date'] : '–' ); ?></td>
								<td><?php echo esc_html( (string) $row['count'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</details>
		<?php
	}
}
