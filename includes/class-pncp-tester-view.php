<?php
/**
 * 3.5: the "Check a request" card on the Log tab: presets, the form, the result region (filled by
 * assets/js/tester.js from the PNCP_Tester AJAX answer), what the check does not cover, and copy-ready curl
 * lines for a real test from another computer. Loaded only on the Log tab.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * 3.5: markup of the "Check a request" card. The check itself, the presets and every text that depends on the
 * settings come from PNCP_Tester.
 */
final class PNCP_Tester_View {

	/**
	 * 3.5: the presets that have a curl line in "Check it yourself", so the simulation can be compared with
	 * the real answer.
	 *
	 * @var string[]
	 */
	const CURL_PRESETS = array( 'gptbot', 'fake_googlebot', 'python_requests', 'bare_browser' );

	/**
	 * 3.5: echoes the card, closed until opened (or the address ends with #pncp-tester).
	 *
	 * @param array<string, mixed> $s Settings (the card's texts that depend on them come from PNCP_Tester).
	 */
	public static function render( $s ) {
		unset( $s ); // 3.5: kept in the signature for the Log tab call; PNCP_Tester reads the settings itself.
		if ( ! current_user_can( 'manage_options' ) || ! class_exists( 'PNCP_Tester' ) ) {
			return;
		}
		$presets = PNCP_Tester::presets();
		$limits  = PNCP_Tester::not_covered();
		$curl    = (string) PNCP_Tester::curl_lines();
		$rows    = max( 2, count( explode( "\n", rtrim( $curl, "\n" ) ) ) );
		?>
		<details class="pncp-card pncp-tester" id="pncp-tester">
			<summary class="pncp-tester__summary">
				<h2 id="pncp-tester-title" class="pncp-tester__title"><?php esc_html_e( 'Check a request', 'scrapelock' ); ?></h2>
				<span class="pncp-tester__state"><?php echo esc_html( PNCP_Tester::exempt_line() ); ?></span>
			</summary>
			<div class="pncp-tester__body">
				<p class="description"><?php esc_html_e( 'See what ScrapeLock would answer to a request, without sending one: nothing is counted, logged or blocked. It uses your settings as they are now, including Monitor only and Emergency Mode.', 'scrapelock' ); ?></p>

				<div class="pncp-tester__presets" role="group" aria-labelledby="pncp-tester-try">
					<span id="pncp-tester-try" class="pncp-tester__try"><?php esc_html_e( 'Try:', 'scrapelock' ); ?></span>
					<?php foreach ( $presets as $key => $preset ) : ?>
						<button type="button" class="button pncp-tester-preset" data-preset="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $preset['label'] ); ?></button>
					<?php endforeach; ?>
				</div>

				<form id="pncp-tester-form" class="pncp-tester-form" data-pncp-nodirty novalidate>
					<p class="pncp-tester__field">
						<label for="pncp-tester-ip"><?php esc_html_e( 'IP address', 'scrapelock' ); ?></label>
						<input type="text" id="pncp-tester-ip" name="ip" class="regular-text code" inputmode="text" autocomplete="off" value="<?php echo esc_attr( PNCP_Tester::SAMPLE_IP ); ?>" aria-describedby="pncp-tester-ip-help">
						<span class="description" id="pncp-tester-ip-help"><?php esc_html_e( 'An example outside address is filled in. Use the IP of a visitor from the log to see why it was blocked.', 'scrapelock' ); ?></span>
					</p>
					<p class="pncp-tester__field">
						<label for="pncp-tester-ua"><?php esc_html_e( 'User-Agent', 'scrapelock' ); ?></label>
						<input type="text" id="pncp-tester-ua" name="ua" class="large-text code" maxlength="512" autocomplete="off" aria-describedby="pncp-tester-ua-help">
						<span class="description" id="pncp-tester-ua-help"><?php esc_html_e( 'Leave empty for a request without a User-Agent.', 'scrapelock' ); ?></span>
					</p>
					<p class="pncp-tester__field">
						<label for="pncp-tester-address"><?php esc_html_e( 'Address on this site', 'scrapelock' ); ?></label>
						<input type="text" id="pncp-tester-address" name="address" class="regular-text code" maxlength="2048" placeholder="/" autocomplete="off" aria-describedby="pncp-tester-address-help">
						<span class="description" id="pncp-tester-address-help"><?php esc_html_e( 'A path such as /shop/, /?s=shoes, /feed/ or /wp-json/wp/v2/posts, or a full address of this site. Empty = the home page.', 'scrapelock' ); ?></span>
					</p>
					<p class="pncp-tester__field pncp-tester__check">
						<label for="pncp-tester-browser">
							<input type="checkbox" id="pncp-tester-browser" name="browser" value="1">
							<?php esc_html_e( 'Send the headers a real browser sends (Accept-Language, Sec-Fetch-Mode and, for Chrome and Edge, Sec-CH-UA)', 'scrapelock' ); ?>
						</label>
					</p>
					<details class="pncp-tester__more">
						<summary><?php esc_html_e( 'More headers', 'scrapelock' ); ?></summary>
						<p class="pncp-tester__field">
							<label for="pncp-tester-referer"><?php esc_html_e( 'Referer', 'scrapelock' ); ?></label>
							<input type="text" id="pncp-tester-referer" name="referer" class="large-text code" maxlength="2048" autocomplete="off">
						</p>
					</details>
					<p class="pncp-tester__actions">
						<button type="submit" class="button button-primary" id="pncp-tester-submit"><?php esc_html_e( 'Check', 'scrapelock' ); ?></button>
					</p>
					<noscript><p><?php esc_html_e( 'This check needs JavaScript. With WP-CLI you can run the same check: wp scrapelock check --ip=… --ua=…', 'scrapelock' ); ?></p></noscript>
				</form>

				<div id="pncp-tester-result" class="pncp-tester__result" role="status" aria-live="polite" tabindex="-1"></div>

				<h3><?php esc_html_e( 'What this check does not cover', 'scrapelock' ); ?></h3>
				<ul class="pncp-tester__limits">
					<?php foreach ( (array) $limits as $limit ) : ?>
						<li><?php echo esc_html( $limit ); ?></li>
					<?php endforeach; ?>
				</ul>

				<h3 id="pncp-tester-curl-title"><?php esc_html_e( 'Check it yourself', 'scrapelock' ); ?></h3>
				<p><?php esc_html_e( 'Run these from another computer, not from the server: the server\'s own address is never blocked. curl sends no login cookie, so the checks apply to it. Each line prints the HTTP status: 200 = allowed, 403 = blocked, 429 = limited. If a page cache or CDN answers first, a cached page may still give 200.', 'scrapelock' ); ?></p>
				<p><?php esc_html_e( 'On Windows 10 and 11, type curl.exe instead of curl (in PowerShell). The last line is for macOS and Linux.', 'scrapelock' ); ?></p>
				<?php
				// 3.5: same markup as PNCP_Admin::code_block(), so the .pncp-copy handler of admin.js copies it.
				printf(
					'<div class="pncp-code"><textarea id="pncp-tester-curl" class="large-text code" rows="%1$d" readonly aria-label="%2$s">%3$s</textarea><p><button type="button" class="button pncp-copy" data-target="pncp-tester-curl">%4$s</button></p></div>',
					(int) $rows,
					esc_attr__( 'Commands to copy', 'scrapelock' ),
					esc_textarea( $curl ),
					esc_html__( 'Copy', 'scrapelock' )
				);
				?>
				<p class="pncp-tester__simulate">
					<?php
					foreach ( self::CURL_PRESETS as $key ) :
						if ( empty( $presets[ $key ]['label'] ) ) {
							continue;
						}
						?>
						<button type="button" class="button-link pncp-tester-preset" data-preset="<?php echo esc_attr( $key ); ?>">
							<?php
							/* translators: %s: name of a preset of "Check a request", e.g. "Fake Googlebot". */
							echo esc_html( sprintf( __( 'Simulate “%s”', 'scrapelock' ), $presets[ $key ]['label'] ) );
							?>
						</button>
					<?php endforeach; ?>
				</p>
			</div>
		</details>
		<?php
	}
}
