<?php
/**
 * 3.11: "For my site": an assistant that looks at the active plugins and the server, and proposes changes to
 * existing settings, each with a one-line reason. Nothing changes until the administrator ticks the changes and
 * clicks "Apply selected" (or runs `wp scrapelock wizard --apply`); the settings as they were are saved first
 * under "Earlier versions" (PNCP_Settings_Io), so the change can be undone from there.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Detection and proposals are plain data (detect(), proposals(), notes()), so they can be tested and shown both
 * on the settings page and in WP-CLI. Saving goes through PNCP_Settings_Io::prepare() / apply(), i.e. through
 * PNCP_Options::sanitize() like a save of the settings form.
 */
final class PNCP_Wizard {

	/**
	 * admin-post action and nonce action.
	 */
	const ACTION = 'pncp_wizard';

	/**
	 * Query argument of the result shown after "Apply selected".
	 */
	const RESULT_ARG = 'pncp_wizard';

	/**
	 * Reason stored with the saved version (PNCP_Settings_Io::backup()).
	 */
	const REASON = 'wizard';

	/**
	 * Risk of a proposal: it blocks nothing more (ticked by default).
	 */
	const RISK_NONE = 'none';

	/**
	 * Risk of a proposal: it blocks or checks more than now (never ticked by default, and marked).
	 */
	const RISK_MORE = 'more';

	/**
	 * Registers the action.
	 */
	public static function init() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
	}

	/* ---------- Detection ---------- */

	/**
	 * What is installed and in front of the site. Plugins are recognised by their main file being active, or by a
	 * class or constant they define (a renamed folder).
	 *
	 * @return array<string, mixed> woocommerce, fluentcommunity, wp_rocket, onesignal, jetpack, wordfence (bool);
	 *                              seo, multilingual, membership, object_cache, server (name or ''); bunny,
	 *                              cloudflare (bool).
	 */
	public static function detect() {
		$active = static function ( $plugins ) {
			return PNCP_Plugin_Bots::plugin_active( (array) $plugins );
		};
		$seo    = '';
		if ( $active( 'seo-by-rank-math/rank-math.php' ) || class_exists( 'RankMath', false ) ) {
			$seo = 'Rank Math';
		} elseif ( $active( array( 'wordpress-seo/wp-seo.php', 'wordpress-seo-premium/wp-seo-premium.php' ) ) || defined( 'WPSEO_VERSION' ) ) {
			$seo = 'Yoast SEO';
		}
		$multilingual = '';
		if ( $active( 'sitepress-multilingual-cms/sitepress.php' ) || defined( 'ICL_SITEPRESS_VERSION' ) ) {
			$multilingual = 'WPML';
		} elseif ( $active( array( 'polylang/polylang.php', 'polylang-pro/polylang.php' ) ) || defined( 'POLYLANG_VERSION' ) ) {
			$multilingual = 'Polylang';
		} elseif ( $active( 'translatepress-multilingual/index.php' ) || defined( 'TRP_PLUGIN_VERSION' ) ) {
			$multilingual = 'TranslatePress';
		}
		$cache = '';
		if ( wp_using_ext_object_cache() ) {
			$redis = defined( 'WP_REDIS_VERSION' ) || $active( array( 'redis-cache/redis-cache.php', 'wp-redis/wp-redis.php' ) );
			$cache = $redis ? 'Redis' : __( 'yes', 'scrapelock' );
		}
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		$server   = '';
		if ( false !== strpos( $software, 'nginx' ) || $active( 'nginx-helper/nginx-helper.php' ) ) {
			$server = 'Nginx';
		} elseif ( false !== strpos( $software, 'litespeed' ) ) {
			$server = 'LiteSpeed';
		} elseif ( false !== strpos( $software, 'apache' ) ) {
			$server = 'Apache';
		}
		$membership = self::membership_plugin();
		$edge       = PNCP_Edge::config()['provider'];
		$env        = array(
			'woocommerce'     => $active( 'woocommerce/woocommerce.php' ) || class_exists( 'WooCommerce', false ),
			'fluentcommunity' => PNCP_Fluent_Community::active(), // Its file, constant or classes (PNCP_Fluent_Community).
			'wp_rocket'       => $active( 'wp-rocket/wp-rocket.php' ) || defined( 'WP_ROCKET_VERSION' ),
			'onesignal'       => $active( 'onesignal-free-web-push-notifications/onesignal.php' ) || class_exists( 'OneSignal', false ),
			'jetpack'         => $active( 'jetpack/jetpack.php' ) || class_exists( 'Jetpack', false ),
			'wordfence'       => $active( 'wordfence/wordfence.php' ) || PNCP_Site_Files::wordfence_active(),
			'seo'             => $seo,
			'multilingual'    => $multilingual,
			'membership'      => $membership, // 3.12.1: a membership or community plugin (membership_plugins()).
			'object_cache'    => $cache,
			'server'          => $server,
			'bunny'           => PNCP_Ip::behind_bunny() || PNCP_Edge::bunny_in_use() || $active( 'bunnycdn/bunnycdn.php' ),
			'cloudflare'      => PNCP_Ip::behind_cloudflare() || PNCP_Ip::cloudflare_plugin_active() || 'cloudflare' === $edge,
		);
		/**
		 * What the "For my site" assistant detected.
		 *
		 * @param array<string, mixed> $env See PNCP_Wizard::detect().
		 */
		return (array) apply_filters( 'pncp_wizard_environment', $env );
	}

	/**
	 * The detected things as names, for the line "Found on this site".
	 *
	 * @param array<string, mixed> $env detect().
	 * @return string[]
	 */
	public static function detected_names( $env ) {
		$names = array(
			'woocommerce'     => 'WooCommerce',
			'fluentcommunity' => 'FluentCommunity',
			'wp_rocket'       => 'WP Rocket',
			'onesignal'       => 'OneSignal',
			'jetpack'         => 'Jetpack',
			'wordfence'       => 'Wordfence',
			'bunny'           => 'Bunny CDN',
			'cloudflare'      => 'Cloudflare',
		);
		$out   = array();
		foreach ( $names as $key => $name ) {
			if ( ! empty( $env[ $key ] ) ) {
				$out[] = $name;
			}
		}
		foreach ( array( 'seo', 'multilingual', 'membership', 'server' ) as $key ) {
			if ( ! empty( $env[ $key ] ) ) {
				$out[] = (string) $env[ $key ];
			}
		}
		if ( ! empty( $env['object_cache'] ) ) {
			/* translators: %s: e.g. Redis */
			$out[] = sprintf( __( 'object cache (%s)', 'scrapelock' ), (string) $env['object_cache'] );
		}
		return $out;
	}

	/**
	 * 3.12.1: the membership and community plugins whose members sign in to read (the per-account page limit is
	 * for them), by their main file (folder/file.php, as PNCP_Plugin_Bots::plugin_active() reads the list of active
	 * plugins). Filter `pncp_wizard_membership_plugins`.
	 *
	 * @return array<string, string[]> Name => main files.
	 */
	public static function membership_plugins() {
		$plugins = array(
			'MemberPress'             => array( 'memberpress/memberpress.php' ),
			'Paid Memberships Pro'    => array( 'paid-memberships-pro/paid-memberships-pro.php' ),
			'WooCommerce Memberships' => array( 'woocommerce-memberships/woocommerce-memberships.php' ),
			'Restrict Content Pro'    => array( 'restrict-content-pro/restrict-content-pro.php', 'restrict-content/restrictcontent.php' ),
			'Ultimate Member'         => array( 'ultimate-member/ultimate-member.php' ),
			'BuddyPress'              => array( 'buddypress/bp-loader.php' ),
			'BuddyBoss'               => array( 'buddyboss-platform/bp-loader.php' ),
		);
		/**
		 * The membership plugins "For my site" looks for.
		 *
		 * @since 3.12.1
		 * @param array<string, string[]> $plugins Name => main files (folder/file.php).
		 */
		$plugins = apply_filters( 'pncp_wizard_membership_plugins', $plugins );
		return is_array( $plugins ) ? $plugins : array();
	}

	/**
	 * 3.12.1: the first active membership plugin (membership_plugins()).
	 *
	 * @return string Its name, or ''.
	 */
	public static function membership_plugin() {
		foreach ( self::membership_plugins() as $name => $files ) {
			if ( PNCP_Plugin_Bots::plugin_active( array_map( 'strval', (array) $files ) ) ) {
				return (string) $name;
			}
		}
		return '';
	}

	/* ---------- Proposals ---------- */

	/**
	 * The proposed changes: only existing settings, only where the current value differs. One per setting
	 * (the key is the id); when two things want the same setting, the first one wins.
	 *
	 * @param array<string, mixed>|null $s   Settings (null = stored).
	 * @param array<string, mixed>|null $env detect() (null = now).
	 * 3.12.1: a row may also change other settings with it ('also': key => value, shown and applied together),
	 * and carry its own short texts for the "Now" and "Proposed" columns ('now_text', 'proposed_text').
	 *
	 * @return array<string, array{key:string, current:mixed, proposed:mixed, reason:string, risk:string, for:string, also?:array<string, mixed>, now_text?:string, proposed_text?:string}>
	 */
	public static function proposals( $s = null, $env = null ) {
		$s   = null === $s ? PNCP_Options::stored() : $s;
		$env = null === $env ? self::detect() : $env;
		$out = array();
		$add = static function ( $key, $proposed, $reason, $risk, $for, $extra = array() ) use ( &$out, $s ) {
			if ( isset( $out[ $key ] ) || ! array_key_exists( $key, $s ) || ! in_array( $key, PNCP_Settings_Io::public_keys(), true ) ) {
				return;
			}
			$row = self::clean_row(
				$key,
				array_merge(
					(array) $extra,
					array(
						'proposed' => $proposed,
						'reason'   => $reason,
						'risk'     => self::RISK_MORE === $risk ? self::RISK_MORE : self::RISK_NONE,
						'for'      => $for,
					)
				),
				$s
			);
			if ( null !== $row ) {
				$out[ $key ] = $row;
			}
		};

		// The visitor address first: every limit and block depends on it.
		$hides = PNCP_Ip::cdn_hides_visitors();
		if ( ! empty( $env['bunny'] ) ) {
			$add( 'trust_bunny', 1, __( 'Bunny CDN is in use: trust its edge servers, so that the visitor address and country it passes on are read (only from Bunny addresses).', 'scrapelock' ), self::RISK_NONE, 'Bunny CDN' );
			if ( 'bunny' === $hides ) {
				$add( 'ip_header', 'x_real_ip', __( 'Every visitor appears with a Bunny address: read X-Real-IP, trusted only from Bunny edge servers, so limits hit the visitor and not Bunny.', 'scrapelock' ), self::RISK_NONE, 'Bunny CDN' );
			}
		}
		if ( ! empty( $env['cloudflare'] ) ) {
			$add( 'trust_cloudflare', 1, __( 'Cloudflare is in use: trust its addresses, so that the visitor address it passes on is read (only from Cloudflare).', 'scrapelock' ), self::RISK_NONE, 'Cloudflare' );
			if ( 'cloudflare' === $hides ) {
				$add( 'ip_header', 'cf_connecting_ip', __( 'Every visitor appears with a Cloudflare address: read CF-Connecting-IP, trusted only from Cloudflare, so limits hit the visitor and not Cloudflare.', 'scrapelock' ), self::RISK_NONE, 'Cloudflare' );
			}
		}

		if ( ! empty( $env['woocommerce'] ) ) {
			$add( 'skip_woo_pages', 1, __( 'WooCommerce: no copy, print or right-click restrictions on the cart, checkout and My account pages (they never count toward the page limit either).', 'scrapelock' ), self::RISK_NONE, 'WooCommerce' );
			$add( 'rate_limit_cart', 60, __( 'WooCommerce: a limit on cart and checkout writes per minute slows down card testing and cart spam; far above what a shopper does.', 'scrapelock' ), self::RISK_MORE, 'WooCommerce' );
			$add( 'rate_limit_coupon', 10, __( 'WooCommerce: a limit on coupon attempts per minute stops coupon guessing.', 'scrapelock' ), self::RISK_MORE, 'WooCommerce' );
		}

		// FluentCommunity's portal: while the plugin is active, PNCP_Fluent_Community already counts it as a content
		// address (merged at runtime, a note says so): proposed only when that does not cover it.
		if ( ! empty( $env['fluentcommunity'] ) ) {
			$slug = self::fluent_slug();
			$seen = trim( (string) $s['content_paths'] . "\n" . implode( "\n", PNCP_Fluent_Community::added_paths() ) );
			if ( '' !== $slug && ! self::content_path_covered( $seen, '/' . $slug ) ) {
				$value = trim( (string) $s['content_paths'] );
				$add(
					'content_paths',
					( '' === $value ? '' : $value . "\n" ) . '/' . $slug . '/',
					/* translators: %s: address, e.g. /hub/ */
					sprintf( __( 'FluentCommunity: its pages under %s are content WordPress does not know about; listed here, the log counts them as pages, not as unknown addresses.', 'scrapelock' ), '/' . $slug . '/' ),
					self::RISK_NONE,
					'FluentCommunity'
				);
			}
		}

		if ( ! empty( $env['wp_rocket'] ) ) {
			$add( 'precheck', 1, __( 'WP Rocket serves cached pages before WordPress, so bots that get a cached page are not checked. The pre-cache check runs before the cache (it adds lines to wp-config.php).', 'scrapelock' ), self::RISK_MORE, 'WP Rocket' );
		}

		if ( PNCP_Edge::usable() ) {
			$provider = PNCP_Edge::providers()[ PNCP_Edge::config()['provider'] ];
			/* translators: %s: CDN name */
			$add( 'edge_send_blocks', 1, sprintf( __( '%s is connected under “Blocking at the CDN”: temporary blocks could be sent to it, so blocked IPs stop at the CDN, also on cached pages.', 'scrapelock' ), $provider ), self::RISK_MORE, $provider );
		}

		self::sensible( $s, $env, $add ); // 3.12.1: values that suit (almost) every site.

		/**
		 * The changes the "For my site" assistant proposes.
		 *
		 * @param array<string, array<string, mixed>> $out key => proposal (see PNCP_Wizard::proposals()).
		 * @param array<string, mixed>                $s   Settings.
		 * @param array<string, mixed>                $env detect().
		 */
		$filtered = apply_filters( 'pncp_wizard_proposals', $out, $s, $env );
		$clean    = array();
		foreach ( is_array( $filtered ) ? $filtered : array() as $key => $row ) {
			$row = is_array( $row ) ? self::clean_row( (string) $key, $row, $s ) : null;
			if ( null !== $row ) {
				$clean[ (string) $key ] = $row;
			}
		}
		return $clean;
	}

	/**
	 * A proposal as proposals() returns it, or null: only existing, public settings (also those of 'also'), and
	 * only real changes (the row's own setting or one of 'also' differs from now). No risk = "blocks more".
	 *
	 * @param string               $key Setting (the row's id).
	 * @param array<string, mixed> $row proposed, reason; risk, for, also, now_text, proposed_text.
	 * @param array<string, mixed> $s   Settings.
	 * @return array{key:string, current:mixed, proposed:mixed, reason:string, risk:string, for:string, also?:array<string, mixed>, now_text?:string, proposed_text?:string}|null
	 */
	private static function clean_row( $key, $row, $s ) {
		$public = PNCP_Settings_Io::public_keys();
		if ( ! isset( $row['proposed'], $row['reason'] ) || ! array_key_exists( $key, $s ) || ! in_array( $key, $public, true ) ) {
			return null;
		}
		$changes = (string) $s[ $key ] !== (string) $row['proposed'];
		$also    = array();
		foreach ( isset( $row['also'] ) && is_array( $row['also'] ) ? $row['also'] : array() as $other => $value ) {
			$other = (string) $other;
			if ( $other === $key || ! array_key_exists( $other, $s ) || ! in_array( $other, $public, true ) || ! is_scalar( $value ) ) {
				return null; // The whole row or nothing.
			}
			$also[ $other ] = $value;
			$changes        = $changes || (string) $s[ $other ] !== (string) $value;
		}
		if ( ! $changes ) {
			return null;
		}
		$clean = array(
			'key'      => $key,
			'current'  => $s[ $key ],
			'proposed' => $row['proposed'],
			'reason'   => (string) $row['reason'],
			'risk'     => isset( $row['risk'] ) && self::RISK_NONE === $row['risk'] ? self::RISK_NONE : self::RISK_MORE,
			'for'      => isset( $row['for'] ) ? (string) $row['for'] : '',
		);
		if ( $also ) {
			$clean['also'] = $also;
		}
		foreach ( array( 'now_text', 'proposed_text' ) as $text ) {
			if ( isset( $row[ $text ] ) && is_scalar( $row[ $text ] ) && '' !== (string) $row[ $text ] ) {
				$clean[ $text ] = (string) $row[ $text ];
			}
		}
		return $clean;
	}

	/**
	 * 3.12.1: the check of sensible values: settings that suit nearly every site, proposed whatever was detected
	 * (some only with a plugin that needs them). Each one blocks only what no visitor does, or blocks less, so
	 * each is ticked by default. "Off" (0) of a limit is the administrator's choice and is never proposed away.
	 *
	 * @param array<string, mixed> $s   Settings.
	 * @param array<string, mixed> $env detect().
	 * @param callable             $add The proposals()'s adder: key, proposed, reason, risk, for, extra.
	 */
	private static function sensible( $s, $env, $add ) {
		$for = __( 'Sensible values', 'scrapelock' );
		$add( 'probe_ban', 1, __( 'Bans scanners on their first .env or .git probe; visitors never send those.', 'scrapelock' ), self::RISK_NONE, $for );
		$add( 'block_ip_host', 1, __( 'Only scanners open the site by its bare IP address; visitors use its name.', 'scrapelock' ), self::RISK_NONE, $for );
		$add( 'reputation', 1, __( 'Remembers IPs that misbehaved; signed-in and verified visitors are treated more gently.', 'scrapelock' ), self::RISK_NONE, $for );

		// Temporary blocks: at least 3 violations, at most 120 minutes (never longer than now). 0 = never block.
		$strikes = (int) $s['ban_strikes'];
		$minutes = (int) $s['ban_minutes'];
		if ( $minutes > 240 || ( $strikes > 0 && $strikes < 3 ) ) {
			$new_strikes = $strikes > 0 && $strikes < 3 ? 3 : $strikes;
			$new_minutes = min( $minutes, 120 );
			$add(
				'ban_strikes',
				$new_strikes,
				__( 'Real users behind a shared mobile IP stay blocked too long.', 'scrapelock' ),
				self::RISK_NONE,
				$for,
				array(
					'also'          => array( 'ban_minutes' => $new_minutes ),
					'now_text'      => self::ban_text( $strikes, $minutes ),
					'proposed_text' => self::ban_text( $new_strikes, $new_minutes ),
				)
			);
		}

		if ( ! empty( $s['human_check'] ) && (int) $s['rate_limit'] > 0 && (int) $s['rate_limit'] < 40 ) {
			$add( 'rate_limit', 45, __( 'The human check already slows bots; this low limit stops fast readers.', 'scrapelock' ), self::RISK_NONE, $for );
		}

		$rest_for = ! empty( $env['fluentcommunity'] ) ? 'FluentCommunity' : ( ! empty( $env['woocommerce'] ) ? 'WooCommerce' : '' );
		if ( '' !== $rest_for && (int) $s['rate_limit_rest'] > 0 && (int) $s['rate_limit_rest'] < 60 ) {
			/* translators: %s: FluentCommunity or WooCommerce */
			$add( 'rate_limit_rest', 60, sprintf( __( '%s loads its pages through the REST API; this limit is too low.', 'scrapelock' ), $rest_for ), self::RISK_NONE, $rest_for );
		}

		$members = ! empty( $env['fluentcommunity'] ) ? 'FluentCommunity' : ( isset( $env['membership'] ) ? (string) $env['membership'] : '' );
		if ( '' !== $members && 0 === (int) $s['rate_limit_account'] ) {
			/* translators: %s: plugin name, e.g. MemberPress */
			$add( 'rate_limit_account', 60, sprintf( __( '%s members sign in: also limit each account, whatever its IP.', 'scrapelock' ), $members ), self::RISK_NONE, $members );
		}

		$annoys = __( 'Low value, annoys visitors: it stops no bot or scraper.', 'scrapelock' );
		foreach ( array( 'blur_on_capture', 'block_devtools', 'user_mark_guests' ) as $key ) {
			if ( ! empty( $s[ $key ] ) ) {
				$add( $key, 0, $annoys, self::RISK_NONE, $for );
			}
		}

		// OneSignal's servers read the site (its service worker, /.well-known/): "OneSignal" as in the list of new
		// installs (PNCP_Options::default_allow_list(); PNCP_Bots::well_known_agents() covers /.well-known/ only).
		if ( ! empty( $env['onesignal'] ) && ! self::allow_list_has( (string) $s['allow_list'], 'OneSignal' ) ) {
			$lines = PNCP_Options::parse_list( (string) $s['allow_list'] );
			if ( count( $lines ) < 200 ) {
				$lines[] = 'OneSignal';
				$add(
					'allow_list',
					implode( "\n", $lines ),
					__( 'OneSignal\'s servers read this site; never refuse them as a bot.', 'scrapelock' ),
					self::RISK_NONE,
					'OneSignal',
					array(
						/* translators: %s: a line of the list, e.g. OneSignal */
						'now_text'      => sprintf( __( 'without %s', 'scrapelock' ), 'OneSignal' ),
						/* translators: %s: a line of the list, e.g. OneSignal */
						'proposed_text' => sprintf( __( '+ %s', 'scrapelock' ), 'OneSignal' ),
					)
				);
			}
		}
	}

	/**
	 * 3.12.1: does the "Always allowed User-Agents" list have this name as a line of its own (also tied to IPs with
	 * "@")?
	 *
	 * @param string $list Setting value.
	 * @param string $name E.g. OneSignal.
	 * @return bool
	 */
	public static function allow_list_has( $list, $name ) {
		foreach ( PNCP_Options::parse_list( $list ) as $entry ) {
			if ( 0 === strcasecmp( PNCP_Options::split_allow_entry( $entry )['ua'], $name ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 3.12.1: the temporary block settings in short text.
	 *
	 * @param int $strikes Violations (0 = never).
	 * @param int $minutes Minutes.
	 * @return string
	 */
	private static function ban_text( $strikes, $minutes ) {
		if ( $strikes <= 0 ) {
			/* translators: %d: minutes */
			return sprintf( __( 'never (%d min)', 'scrapelock' ), $minutes );
		}
		/* translators: 1: number of violations, 2: minutes */
		return sprintf( __( 'after %1$d violations, for %2$d min', 'scrapelock' ), $strikes, $minutes );
	}

	/**
	 * 3.12.1: the "Now" and "Proposed" texts of a row (its own, or value_text() of the setting).
	 *
	 * @param array<string, mixed> $row A proposal.
	 * @return array{0: string, 1: string}
	 */
	public static function row_texts( $row ) {
		$key = (string) $row['key'];
		return array(
			isset( $row['now_text'] ) ? (string) $row['now_text'] : self::value_text( $key, $row['current'] ),
			isset( $row['proposed_text'] ) ? (string) $row['proposed_text'] : self::value_text( $key, $row['proposed'] ),
		);
	}

	/**
	 * Advice that is not a setting: what to check elsewhere, with a link.
	 *
	 * @param array<string, mixed>|null $s   Settings (null = stored).
	 * @param array<string, mixed>|null $env detect() (null = now).
	 * @return array<int, array{for:string, text:string, url:string, link:string}>
	 */
	public static function notes( $s = null, $env = null ) {
		$s    = null === $s ? PNCP_Options::stored() : $s;
		$env  = null === $env ? self::detect() : $env;
		$out  = array();
		$note = static function ( $for, $text, $url = '', $link = '' ) use ( &$out ) {
			$out[] = array(
				'for'  => $for,
				'text' => $text,
				'url'  => $url,
				'link' => $link,
			);
		};
		$bots      = PNCP_Status::settings_url( array( 'tab' => 'bots' ) );
		$bots_link = __( 'Bots and limits', 'scrapelock' ); // Its own line: the translator comments below are for the sentences.
		// Every known service bot of an active plugin (PNCP_Plugin_Bots: WP Rocket, Jetpack and those added with
		// the pncp_plugin_bots filter) that the administrator stopped allowing.
		foreach ( PNCP_Plugin_Bots::active() as $bot ) {
			if ( empty( $bot['allowed'] ) ) {
				$name = (string) $bot['name'];
				/* translators: %s: plugin name */
				$note( $name, sprintf( __( 'You stopped allowing the service bot of %s: its requests are checked like any other bot. Allow it again under “Bots and limits” if the plugin needs it.', 'scrapelock' ), $name ), $bots, $bots_link );
			}
		}
		// The pre-cache check is on but not running: the reason the status badges give (PNCP_Status_State).
		$precheck = PNCP_Status_State::precheck( $s );
		if ( PNCP_Status_State::SET === $precheck['state'] ) {
			$precheck_name = __( 'Pre-cache check', 'scrapelock' );
			/* translators: %s: why it is not running, e.g. "the loader is not in wp-config.php" */
			$note( $precheck_name, sprintf( __( 'The pre-cache check is on but not running: %s.', 'scrapelock' ), $precheck['reason'] ), $bots, $bots_link );
		}
		if ( ! empty( $env['fluentcommunity'] ) && PNCP_Fluent_Community::added_paths() ) {
			$note( 'FluentCommunity', PNCP_Fluent_Community::note() );
		}
		if ( ! empty( $env['woocommerce'] ) ) {
			$note( 'WooCommerce', __( 'The cart, checkout, “Thank you” and My account pages never count toward the page limit; bots and blocks are still checked there.', 'scrapelock' ) );
		}
		if ( ! empty( $env['onesignal'] ) ) {
			$note( 'OneSignal', __( 'OneSignal needs its service worker file at the root of the site: Site Health → “ScrapeLock site files” checks it and can create it.', 'scrapelock' ), admin_url( 'site-health.php' ), __( 'Site Health', 'scrapelock' ) );
		}
		if ( ! empty( $env['wordfence'] ) ) {
			$note( 'Wordfence', __( 'Wordfence reads the visitor address with its own setting. Behind a CDN, check that it sees the same address as ScrapeLock: Site Health → “Wordfence and the visitor address”.', 'scrapelock' ), admin_url( 'site-health.php' ), __( 'Site Health', 'scrapelock' ) );
		}
		if ( '' !== (string) $env['seo'] ) {
			/* translators: %s: Rank Math or Yoast SEO */
			$note( (string) $env['seo'], sprintf( __( 'The sitemaps of %s (sitemap_index.xml, *-sitemap.xml) are recognised and get the sitemap limit; robots.txt is never blocked.', 'scrapelock' ), (string) $env['seo'] ) );
		}
		if ( ! empty( $env['multilingual'] ) && ! empty( $env['fluentcommunity'] ) ) {
			/* translators: %s: WPML, Polylang or TranslatePress */
			$note( (string) $env['multilingual'], sprintf( __( '%s adds a language part to addresses (e.g. /en/): add those forms of the content addresses too.', 'scrapelock' ), (string) $env['multilingual'] ) );
		}
		if ( 'Nginx' === $env['server'] ) {
			$note( 'Nginx', __( 'Nginx does not read .htaccess: the server rules (blocked files, bots at the server) must be copied into the server configuration.', 'scrapelock' ), PNCP_Status::settings_url( array( 'tab' => 'rules' ) ), __( 'Server rules', 'scrapelock' ) );
		} elseif ( 'Apache' === $env['server'] || 'LiteSpeed' === $env['server'] ) {
			$note( (string) $env['server'], __( 'The server rules can be written into .htaccess from “Server rules”.', 'scrapelock' ), PNCP_Status::settings_url( array( 'tab' => 'rules' ) ), __( 'Server rules', 'scrapelock' ) );
		}
		if ( '' !== (string) $env['object_cache'] ) {
			$note( __( 'Object cache', 'scrapelock' ), __( 'Counters and temporary blocks are kept in the persistent object cache: fast, and shared by every PHP worker.', 'scrapelock' ) );
		}
		return $out;
	}

	/**
	 * FluentCommunity's portal address, as PNCP_Fluent_Community::portal_path() finds it (FLUENT_COMMUNITY_PORTAL_SLUG,
	 * its helper, or "hub").
	 *
	 * @return string E.g. hub.
	 */
	public static function fluent_slug() {
		$slug = trim( PNCP_Fluent_Community::portal_path(), '/' ); // The same address the integration counts.
		/**
		 * FluentCommunity's portal address, as the "For my site" assistant proposes it.
		 *
		 * @param string $slug E.g. hub.
		 */
		$slug = (string) apply_filters( 'pncp_wizard_fluent_slug', $slug );
		return trim( (string) preg_replace( '#[^a-z0-9/_\-]#i', '', $slug ), '/' );
	}

	/**
	 * Does a line of "Content addresses" already cover this path (the same path or a shorter prefix of it)?
	 *
	 * @param string $list Setting value.
	 * @param string $path E.g. /hub.
	 * @return bool
	 */
	public static function content_path_covered( $list, $path ) {
		$path = trailingslashit( '/' . trim( $path, '/' ) );
		foreach ( PNCP_Options::parse_list( $list ) as $entry ) {
			$part  = (string) wp_parse_url( $entry, PHP_URL_PATH ); // A full address is accepted too.
			$entry = '' !== $part ? $part : $entry;
			$entry = trailingslashit( '/' . trim( $entry, '/' ) );
			if ( '/' !== $entry && 0 === stripos( $path, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/* ---------- Apply ---------- */

	/**
	 * Applies the chosen proposals (others are ignored), after saving the current settings as an earlier version.
	 *
	 * @param string[]                  $keys Chosen settings (proposal ids).
	 * @param array<string, mixed>|null $env  detect() (null = now).
	 * @return array{id:string, changes:array<int, array<string, string>>, messages:array<int, array<string, string>>}|WP_Error id '' = nothing changed.
	 */
	public static function apply( $keys, $env = null ) {
		if ( PNCP_Lockdown::is_locked() ) {
			return new WP_Error( 'pncp_locked', __( 'The site is locked: the settings cannot be changed until it is unlocked.', 'scrapelock' ) );
		}
		$proposals = self::proposals( null, $env );
		$values    = array();
		foreach ( array_unique( array_map( 'strval', (array) $keys ) ) as $key ) {
			if ( isset( $proposals[ $key ] ) ) {
				$values[ $key ] = $proposals[ $key ]['proposed'];
				// 3.12.1: the settings that change with it (one row, e.g. violations and block duration).
				foreach ( isset( $proposals[ $key ]['also'] ) ? $proposals[ $key ]['also'] : array() as $other => $value ) {
					$values[ $other ] = $value;
				}
			}
		}
		if ( ! $values ) {
			return array(
				'id'       => '',
				'changes'  => array(),
				'messages' => array(),
			);
		}
		if ( ! function_exists( 'add_settings_error' ) ) {
			require_once ABSPATH . 'wp-admin/includes/template.php'; // The settings checks report through it.
		}
		$prepared = PNCP_Settings_Io::prepare( $values );
		$id       = PNCP_Settings_Io::apply( $prepared, self::REASON );
		if ( is_wp_error( $id ) ) {
			return $id;
		}
		PNCP_Ip::reset();
		return array(
			'id'       => (string) $id,
			'changes'  => $prepared['changes'],
			'messages' => $prepared['messages'],
		);
	}

	/**
	 * "Apply selected": nonce, manage_options, not while the site is locked.
	 */
	public static function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to change this setting.', 'scrapelock' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		if ( PNCP_Lockdown::is_locked() ) {
			self::back( 'locked' );
		}
		$keys   = isset( $_POST['pncp_wizard_keys'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['pncp_wizard_keys'] ) ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized by sanitize_key().
		$result = self::apply( $keys );
		if ( is_wp_error( $result ) ) {
			self::back( 'pncp_locked' === $result->get_error_code() ? 'locked' : 'error' );
		}
		if ( '' === $result['id'] ) {
			self::back( 'none' );
		}
		if ( $result['messages'] ) {
			set_transient( 'pncp_wizard_msgs_' . get_current_user_id(), $result['messages'], 15 * MINUTE_IN_SECONDS );
		}
		self::back( 'applied', array( 'pncp_wizard_undo' => $result['id'] ) );
	}

	/**
	 * Back to the first tab, at the assistant, with the result.
	 *
	 * @param string                $result applied, none, locked, error.
	 * @param array<string, string> $args   More query arguments.
	 */
	private static function back( $result, $args = array() ) {
		wp_safe_redirect(
			PNCP_Status::settings_url(
				array_merge(
					array(
						'tab'            => 'general',
						self::RESULT_ARG => $result,
					),
					$args
				)
			) . '#pncp-wizard'
		);
		exit;
	}

	/* ---------- Display ---------- */

	/**
	 * A setting's name as the settings page shows it (the key for a setting without one here).
	 *
	 * @param string $key Setting.
	 * @return string
	 */
	public static function label( $key ) {
		$labels = array(
			'trust_bunny'        => __( 'Trust Bunny CDN addresses', 'scrapelock' ),
			'trust_cloudflare'   => __( 'Trust Cloudflare addresses', 'scrapelock' ),
			'ip_header'          => __( 'Real visitor IP', 'scrapelock' ),
			'skip_woo_pages'     => __( 'Leave the cart, checkout and My account pages alone', 'scrapelock' ),
			'rate_limit_cart'    => __( 'Cart and checkout writes per minute', 'scrapelock' ),
			'rate_limit_coupon'  => __( 'Coupon attempts per minute', 'scrapelock' ),
			'content_paths'      => __( 'Content addresses', 'scrapelock' ),
			'precheck'           => __( 'Check before the page cache', 'scrapelock' ),
			'edge_send_blocks'   => __( 'Send temporary blocks to the CDN', 'scrapelock' ),
			// 3.12.1: the check of sensible values.
			'probe_ban'          => __( 'Ban scanners on their first probe', 'scrapelock' ),
			'block_ip_host'      => __( 'Refuse requests that open the site by its IP address', 'scrapelock' ),
			'reputation'         => __( 'IP reputation', 'scrapelock' ),
			'ban_strikes'        => __( 'Temporary blocks', 'scrapelock' ),
			'rate_limit'         => __( 'Pages per minute', 'scrapelock' ),
			'rate_limit_rest'    => __( 'REST API requests per minute', 'scrapelock' ),
			'rate_limit_account' => __( 'Pages per minute per signed-in account', 'scrapelock' ),
			'blur_on_capture'    => __( 'Blur the page on screenshot shortcuts', 'scrapelock' ),
			'block_devtools'     => __( 'Block the developer tools shortcuts', 'scrapelock' ),
			'user_mark_guests'   => __( 'Reader watermark also for visitors', 'scrapelock' ),
			'allow_list'         => __( 'Always allowed User-Agents', 'scrapelock' ),
		);
		return isset( $labels[ $key ] ) ? $labels[ $key ] : PNCP_Setting_Labels::label( $key ); // Never the bare key.
	}

	/**
	 * A value in short text: on/off, a header name, a list on one line.
	 *
	 * @param string $key   Setting.
	 * @param mixed  $value Value.
	 * @return string
	 */
	public static function value_text( $key, $value ) {
		if ( in_array( $key, PNCP_Options::bool_keys(), true ) ) {
			return empty( $value ) ? __( 'Off', 'scrapelock' ) : __( 'On', 'scrapelock' );
		}
		if ( 'ip_header' === $key ) {
			return PNCP_Setting_Labels::header_name( (string) $value );
		}
		if ( 0 === strpos( $key, 'rate_limit' ) ) {
			return (int) $value > 0 ? (string) (int) $value : __( 'Off', 'scrapelock' );
		}
		$text = implode( ', ', PNCP_Options::parse_list( (string) $value ) );
		return '' === $text ? __( '(empty)', 'scrapelock' ) : $text;
	}

	/**
	 * The panel on the first tab: what was found, the table of proposed changes with checkboxes, and the advice.
	 */
	public static function render_panel() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s         = PNCP_Options::stored();
		$env       = self::detect();
		$proposals = self::proposals( $s, $env );
		$notes     = self::notes( $s, $env );
		$found     = self::detected_names( $env );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays the result.
		$result = isset( $_GET[ self::RESULT_ARG ] ) ? sanitize_key( wp_unslash( $_GET[ self::RESULT_ARG ] ) ) : '';
		$open   = '' !== $result || $proposals;
		?>
		<details class="pncp-card pncp-wizard" id="pncp-wizard"<?php echo $open ? ' open' : ''; ?>>
			<summary>
				<h2 id="pncp-wizard-title">
					<?php esc_html_e( 'For my site', 'scrapelock' ); ?>
					<?php if ( $proposals ) : ?>
						<span class="pncp-tag pncp-tag--default">
							<?php
							/* translators: %d: number of proposed changes */
							echo esc_html( sprintf( _n( '%d suggestion', '%d suggestions', count( $proposals ), 'scrapelock' ), count( $proposals ) ) );
							?>
						</span>
					<?php endif; ?>
				</h2>
			</summary>
			<?php self::render_result( $result ); ?>
			<?php echo PNCP_Admin_Fields::para( __( 'Settings that suit the plugins, CDN and server found here.', 'scrapelock' ), __( 'ScrapeLock looked at the active plugins, the CDN and the server, and suggests settings that suit them. Nothing changes until you choose and click “Apply selected”. The settings as they are now are saved first under “Earlier versions”, so you can undo.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields. ?>
			<p><?php esc_html_e( 'Found on this site:', 'scrapelock' ); ?> <strong><?php echo esc_html( $found ? implode( ', ', $found ) : __( 'nothing that needs other settings', 'scrapelock' ) ); ?></strong></p>
			<?php if ( $proposals ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pncp-wizard-form">
					<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION ); ?>">
					<?php echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( self::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup. ?>
					<div class="pncp-table-wrap">
					<table class="widefat striped pncp-changes pncp-wizard-table">
						<thead><tr>
							<th scope="col" class="check-column"><span class="screen-reader-text"><?php esc_html_e( 'Apply', 'scrapelock' ); ?></span></th>
							<th scope="col"><?php esc_html_e( 'Setting', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Now', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Proposed', 'scrapelock' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Why', 'scrapelock' ); ?></th>
						</tr></thead>
						<tbody>
							<?php foreach ( $proposals as $key => $row ) : ?>
								<?php $more = self::RISK_MORE === $row['risk']; ?>
								<tr class="pncp-wizard-row<?php echo $more ? ' is-risky' : ''; ?>">
									<th scope="row" class="check-column">
										<input type="checkbox" name="pncp_wizard_keys[]" value="<?php echo esc_attr( $key ); ?>" id="pncp-wizard-<?php echo esc_attr( $key ); ?>"<?php checked( ! $more ); ?>>
									</th>
									<td>
										<label for="pncp-wizard-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( self::label( $key ) ); ?></label>
										<?php if ( $more ) : ?>
											<span class="pncp-tag pncp-tag--risk"><?php esc_html_e( 'Blocks more: not ticked', 'scrapelock' ); ?></span>
										<?php endif; ?>
										<br><code><?php echo esc_html( implode( ', ', array_merge( array( $key ), array_keys( isset( $row['also'] ) ? $row['also'] : array() ) ) ) ); ?></code>
									</td>
									<?php list( $now_text, $proposed_text ) = self::row_texts( $row ); ?>
									<td><?php echo esc_html( $now_text ); ?></td>
									<td><?php echo esc_html( $proposed_text ); ?></td>
									<td><?php echo esc_html( $row['reason'] ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					</div>
					<p><button type="submit" class="button button-primary" id="pncp-submit-wizard"><?php esc_html_e( 'Apply selected', 'scrapelock' ); ?></button></p>
				</form>
			<?php else : ?>
				<p class="description pncp-wizard-none"><?php esc_html_e( 'Nothing to change: the settings already suit what was found.', 'scrapelock' ); ?></p>
			<?php endif; ?>
			<?php if ( $notes ) : ?>
				<h3><?php esc_html_e( 'Also check', 'scrapelock' ); ?></h3>
				<ul class="pncp-wizard-notes">
					<?php foreach ( $notes as $item ) : ?>
						<li>
							<strong><?php echo esc_html( $item['for'] ); ?>:</strong> <?php echo esc_html( $item['text'] ); ?>
							<?php if ( '' !== $item['url'] ) : ?>
								<a href="<?php echo esc_url( $item['url'] ); ?>"><?php echo esc_html( $item['link'] ); ?></a>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</details>
		<?php
	}

	/**
	 * The result of "Apply selected", with "Undo" (restores the version saved just before).
	 *
	 * @param string $result applied, none, locked, error or ''.
	 */
	private static function render_result( $result ) {
		$texts = array(
			'applied' => array( 'success', __( 'The selected changes were applied. The previous settings are under “Earlier versions”.', 'scrapelock' ) ),
			'none'    => array( 'info', __( 'Nothing was selected, so nothing changed.', 'scrapelock' ) ),
			'locked'  => array( 'error', __( 'The site is locked: unlock it on the Lockdown tab to apply these changes.', 'scrapelock' ) ),
			'error'   => array( 'error', __( 'The changes were not applied: reload this page and try again.', 'scrapelock' ) ),
		);
		if ( ! isset( $texts[ $result ] ) ) {
			return;
		}
		printf( '<div class="notice notice-%1$s inline pncp-wizard-result"><p>%2$s</p>', esc_attr( $texts[ $result ][0] ), esc_html( $texts[ $result ][1] ) );
		$messages = get_transient( 'pncp_wizard_msgs_' . get_current_user_id() );
		if ( 'applied' === $result && is_array( $messages ) ) {
			delete_transient( 'pncp_wizard_msgs_' . get_current_user_id() );
			foreach ( $messages as $message ) {
				if ( isset( $message['message'] ) ) {
					echo '<p>' . esc_html( (string) $message['message'] ) . '</p>';
				}
			}
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects the version for the Undo form.
		$undo = isset( $_GET['pncp_wizard_undo'] ) ? sanitize_key( wp_unslash( $_GET['pncp_wizard_undo'] ) ) : '';
		if ( 'applied' === $result && '' !== $undo && PNCP_Settings_Io::find( $undo ) ) {
			printf( '<form method="post" action="%s" class="pncp-inline-form">', esc_url( admin_url( 'admin-post.php' ) ) );
			echo '<input type="hidden" name="action" value="pncp_settings"><input type="hidden" name="op" value="restore"><input type="hidden" name="tab" value="general">';
			printf( '<input type="hidden" name="id" value="%s">', esc_attr( $undo ) );
			echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( 'pncp_settings', '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
			echo '<p><button type="submit" class="button">' . esc_html__( 'Undo', 'scrapelock' ) . '</button></p></form>';
		}
		echo '</div>';
	}
}
