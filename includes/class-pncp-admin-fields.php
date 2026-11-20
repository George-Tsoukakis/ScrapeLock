<?php
/**
 * 3.5: what the settings form tells about each field: which sub-options do nothing in the current state, the
 * default value, and which options can affect real visitors or SEO. Used by PNCP_Admin only.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Static helpers for the field renderers of PNCP_Admin. No state, no database access: everything comes from the
 * fixed maps below and from the settings passed in.
 */
final class PNCP_Admin_Fields {

	/**
	 * 3.5: the options that can refuse or slow down real visitors, or change what search engines see. They get
	 * the "May affect visitors/SEO" tag next to their label.
	 *
	 * @return array<string, true>
	 */
	public static function risky() {
		return array(
			'rate_limit'              => true, // 3.5: a 429 for visitors who share an IP (offices, mobile networks, a CDN).
			'block_selection'         => true,
			'require_browser_headers' => true,
			'block_http_libs'         => true,
			'human_check'             => true,
			'countries_block'         => true,
			'rate_limit_datacenter'   => true,
			'ipv6_wide'               => true,
			'list_excerpts'           => true,
			'cdn_only'                => true,
			'watermark_products'      => true,
			'hide_rest_discovery'     => true,
			'rate_limit_apionly'      => true, // 3.7: feed readers, apps and headless front ends that never open a page.
			// 3.8: a new sign-in address must be written down; "Lost your password" links in old emails change.
			'login_slug'              => true,
			'bunny_strikes'           => true, // 3.8: an IP too fast at the CDN is blocked temporarily, also on cached pages.
		);
	}

	/**
	 * 3.5: the risky choices of radio groups and selects: key => values.
	 *
	 * @return array<string, string[]>
	 */
	public static function risky_choices() {
		return array(
			'copy_mode'           => array( 'block' ),
			'print_mode'          => array( 'block' ),
			'feed_mode'           => array( 'disabled' ),
			'auto_emergency_mode' => array( 'start' ),
			'crowdsec_action'     => array( 'block' ), // 3.7: a recycled address may now belong to a real visitor.
		);
	}

	/**
	 * 3.5: the fields that only take effect when another setting allows it. "on" is the controlling option,
	 * "value" the choice it must have (mode "choice"), "label" the controlling option's name as the form shows it.
	 *
	 * @return array<string, array{on:string, value:string, mode:string, label:string}>
	 */
	public static function requires() {
		$map  = array();
		$add  = static function ( $keys, $on, $mode, $label, $value = '' ) use ( &$map ) {
			foreach ( (array) $keys as $key ) {
				$map[ $key ] = array(
					'on'    => $on,
					'value' => $value,
					'mode'  => $mode,
					'label' => $label,
				);
			}
		};
		$add( 'verify_ai_bots', 'allow_ai_search', 'on', __( 'Allow AI search engines and assistants (not training crawlers)', 'scrapelock' ) );
		$add( array( 'block_empty_ua', 'block_http_libs' ), 'block_bots', 'on', __( 'Block (403) the User-Agents in the list', 'scrapelock' ) );
		$add( 'rate_limit_unverified', 'human_check', 'on', __( 'Stricter page limit for visitors who have not shown they are people', 'scrapelock' ) );
		$add( 'rate_limit_country', 'countries_strict', 'filled', __( 'Countries with a stricter page limit', 'scrapelock' ) );
		$add( array( 'auto_emergency_mode', 'auto_emergency_min' ), 'auto_emergency', 'on', __( 'Watch for attacks spread over many IPs (automatic Emergency Mode)', 'scrapelock' ) );
		$add( 'ipv6_wide', 'rate_limit', 'positive', __( 'Pages per minute', 'scrapelock' ) );
		$add( 'attribution_min_chars', 'copy_mode', 'choice', __( 'Allow, with the source and link appended at the end', 'scrapelock' ), 'attribution' );
		$add( 'message', 'show_message', 'on', __( 'Show a message when something is blocked', 'scrapelock' ) );
		$add( 'tdm_policy_url', 'tdm_reservation', 'on', __( 'Opt-out declaration from AI training and text and data mining (TDM)', 'scrapelock' ) );
		$add( 'feed_source_link', 'feed_mode', 'choice', __( 'Full text', 'scrapelock' ), 'full' );
		$add(
			array( 'watermark_full', 'watermark_products', 'watermark_image_id', 'watermark_position', 'watermark_size', 'watermark_opacity', 'watermark_min_width' ),
			'watermark_enabled',
			'on',
			__( 'Watermark new images', 'scrapelock' )
		);
		// 3.6.
		$add( array( 'user_mark_guests', 'user_mark_opacity' ), 'user_mark', 'on', __( 'Show who is reading over protected pages', 'scrapelock' ) );
		$add( array( 'shared_ips', 'shared_logout' ), 'shared_alert', 'on', __( 'Email me when one account is used from several addresses at once', 'scrapelock' ) );
		// 3.7.
		$add( 'rate_limit_lowrep', 'reputation', 'on', __( 'Remember how each IP behaves (reputation)', 'scrapelock' ) );
		$add( 'rate_limit_crowdsec', 'crowdsec_action', 'choice', __( 'The stricter page limit below', 'scrapelock' ), 'limit' );
		// 3.8.
		$add( array( 'login_max', 'login_window', 'login_ban_minutes', 'login_user_max', 'login_user_minutes', 'login_user_email' ), 'login_limit', 'on', __( 'Limit failed sign-ins', 'scrapelock' ) );
		$add( array( 'bunny_all_lines', 'bunny_flood_4xx', 'bunny_strikes' ), 'bunny_import', 'on', __( 'Import attacks from Bunny CDN\'s logs', 'scrapelock' ) );
		$add( 'bunny_rate', 'bunny_strikes', 'on', __( 'Count IPs that are too fast at the CDN toward a temporary block', 'scrapelock' ) );
		$add( array( 'attack_retention', 'report_weekly' ), 'attack_record', 'on', __( 'Record where bots and attackers hit the site', 'scrapelock' ) );
		return $map;
	}

	/**
	 * Is the requirement of a field met by these settings? True for a field without one.
	 *
	 * @param string               $key Field.
	 * @param array<string, mixed> $s   Settings.
	 * @return bool
	 */
	public static function met( $key, $s ) {
		$map = self::requires();
		if ( ! isset( $map[ $key ] ) ) {
			return true;
		}
		$req   = $map[ $key ];
		$value = isset( $s[ $req['on'] ] ) ? $s[ $req['on'] ] : '';
		switch ( $req['mode'] ) {
			case 'choice':
				return (string) $value === $req['value'];
			case 'positive':
				return (int) $value > 0;
			case 'filled':
				return '' !== trim( (string) $value );
			default:
				return ! empty( $value );
		}
	}

	/**
	 * The data-pncp-requires attribute (and aria-disabled while the requirement is not met), with a leading
	 * space, or '' for a field without a requirement. The control is never disabled: its value is still saved.
	 *
	 * @param string               $key Field.
	 * @param array<string, mixed> $s   Settings.
	 * @return string Escaped attributes.
	 */
	public static function requires_attr( $key, $s ) {
		$map = self::requires();
		if ( ! isset( $map[ $key ] ) ) {
			return '';
		}
		$spec = 'choice' === $map[ $key ]['mode'] ? $map[ $key ]['on'] . '=' . $map[ $key ]['value'] : $map[ $key ]['on'];
		return ' data-pncp-requires="' . esc_attr( $spec ) . '"' . ( self::met( $key, $s ) ? '' : ' aria-disabled="true"' );
	}

	/**
	 * The one-line note under a field whose requirement is not met (printed hidden when it is, so the script can
	 * show it as soon as the controlling option changes), or '' for a field without a requirement.
	 *
	 * @param string               $key Field.
	 * @param array<string, mixed> $s   Settings.
	 * @return string HTML.
	 */
	public static function requires_note( $key, $s ) {
		$map = self::requires();
		if ( ! isset( $map[ $key ] ) ) {
			return '';
		}
		$req = $map[ $key ];
		switch ( $req['mode'] ) {
			case 'choice':
				/* translators: %s: name of the option that must be chosen */
				$text = __( 'Takes effect only when “%s” is chosen.', 'scrapelock' );
				break;
			case 'positive':
				/* translators: %s: name of a number setting */
				$text = __( 'Takes effect only when “%s” is above 0.', 'scrapelock' );
				break;
			case 'filled':
				/* translators: %s: name of a text setting */
				$text = __( 'Takes effect only when “%s” is not empty.', 'scrapelock' );
				break;
			default:
				/* translators: %s: name of the option that must be on */
				$text = __( 'Takes effect only when “%s” is on.', 'scrapelock' );
		}
		return sprintf(
			'<p class="description pncp-requires-note" id="%1$s"%2$s>%3$s</p>',
			esc_attr( 'pncp-' . $key . '-requires' ),
			self::met( $key, $s ) ? ' hidden' : '',
			esc_html( sprintf( $text, $req['label'] ) )
		);
	}

	/**
	 * The "May affect visitors/SEO" mark of a risky option, or ''. 3.11: a warning icon with the text as its
	 * tooltip and as screen-reader text, instead of a tag with the sentence (the class stays for the CSS).
	 *
	 * @param string $key   Field.
	 * @param string $value A choice of a radio group (its own tag id), or '' for the field.
	 * @return string HTML.
	 */
	public static function risk_tag( $key, $value = '' ) {
		if ( '' === $value ? ! isset( self::risky()[ $key ] ) : ! self::is_risky_choice( $key, $value ) ) {
			return '';
		}
		return self::risk_icon( self::risk_id( $key, $value ) );
	}

	/**
	 * 3.11: the warning icon for an option that can affect visitors or SEO: a tooltip (title) for the mouse and
	 * the same words as screen-reader text, so it is announced where the tag text used to be.
	 *
	 * @param string $id Element id ('' for none, e.g. a copy on a folded summary).
	 * @return string HTML.
	 */
	public static function risk_icon( $id = '' ) {
		$text = __( 'May affect visitors/SEO', 'scrapelock' );
		return sprintf(
			'<span class="pncp-tag pncp-tag--risk pncp-risk"%1$s title="%2$s"><span class="dashicons dashicons-warning" aria-hidden="true"></span><span class="screen-reader-text">%3$s</span></span>',
			'' === $id ? '' : ' id="' . esc_attr( $id ) . '"',
			esc_attr( $text ),
			esc_html( $text )
		);
	}

	/**
	 * 3.12.2: the internal name of one or more settings, never as visible text: a small "?" button next to the
	 * setting's label, with the name in its tooltip (title) and in its accessible name (aria-label). A button, so a
	 * keyboard reaches it; on focus the stylesheet shows the tooltip (keyboards get no title tooltip). For support
	 * and for those who script "wp scrapelock settings", which takes these names.
	 *
	 * @param string[] $keys Setting keys.
	 * @return string HTML ('' for no key).
	 */
	public static function key_hint( array $keys ) {
		$keys = array_values( array_filter( array_map( 'strval', $keys ), 'strlen' ) );
		if ( ! $keys ) {
			return '';
		}
		$names = implode( ', ', $keys );
		return sprintf(
			'<button type="button" class="pncp-key-hint" title="%1$s" aria-label="%2$s" data-key="%1$s"><span aria-hidden="true">?</span></button>',
			esc_attr( $names ),
			/* translators: %s: internal name(s) of the setting, e.g. probe_ban */
			esc_attr( sprintf( _n( 'Internal name of this setting: %s', 'Internal names of these settings: %s', count( $keys ), 'scrapelock' ), $names ) )
		);
	}

	/* ---------- 3.11: help texts ---------- */

	/**
	 * A help text in two parts: one short line that is always shown, and the longer explanation folded under
	 * "More". Field renderers of PNCP_Admin take this or a plain string.
	 *
	 * @param string $short One line (about 12 words at most).
	 * @param string $more  The longer explanation ('' for none).
	 * @return array{0: string, 1: string}
	 */
	public static function help( $short, $more = '' ) {
		return array( (string) $short, (string) $more );
	}

	/**
	 * The two parts of a help text given as a string (short only) or as help().
	 *
	 * @param string|array<int, string> $help Help text.
	 * @return array{0: string, 1: string}
	 */
	public static function help_parts( $help ) {
		if ( is_array( $help ) ) {
			return array( isset( $help[0] ) ? (string) $help[0] : '', isset( $help[1] ) ? (string) $help[1] : '' );
		}
		return array( (string) $help, '' );
	}

	/**
	 * The help of a field: the short line as <p class="description" id="…"> (the id aria-describedby points
	 * to) and the longer part folded under "More". '' for an empty help.
	 *
	 * @param string                    $id   Element id of the short line ('' for none).
	 * @param string|array<int, string> $help Help text (string or help()).
	 * @return string HTML.
	 */
	public static function description( $id, $help ) {
		list( $short, $more ) = self::help_parts( $help );
		if ( '' === $short && '' === $more ) {
			return '';
		}
		$html = '' === $short ? '' : sprintf(
			'<p class="description"%1$s>%2$s</p>',
			'' === $id ? '' : ' id="' . esc_attr( $id ) . '"',
			esc_html( $short )
		);
		return $html . self::more( $more );
	}

	/**
	 * The longer explanation folded under "More", or '' for an empty text.
	 *
	 * @param string $text Plain text (escaped here).
	 * @return string HTML.
	 */
	public static function more( $text ) {
		return '' === (string) $text ? '' : self::more_html( '<p>' . esc_html( $text ) . '</p>' );
	}

	/**
	 * The fold "More" around HTML that is already escaped (several paragraphs, links, code).
	 *
	 * @param string $html Escaped HTML.
	 * @return string HTML.
	 */
	public static function more_html( $html ) {
		if ( '' === (string) $html ) {
			return '';
		}
		return '<details class="pncp-more"><summary>' . esc_html__( 'More', 'scrapelock' ) . '</summary><div class="pncp-more__body">' . $html . '</div></details>';
	}

	/**
	 * A free-standing description (an intro of a card or a part): the short line, then the rest under "More".
	 *
	 * @param string $short   One line.
	 * @param string $more    The longer explanation ('' for none).
	 * @param string $classes Extra classes of the short line.
	 * @return string HTML.
	 */
	public static function para( $short, $more = '', $classes = '' ) {
		return sprintf( '<p class="%1$s">%2$s</p>', esc_attr( trim( 'description ' . $classes ) ), esc_html( $short ) ) . self::more( $more );
	}

	/**
	 * The id of a risk tag.
	 *
	 * @param string $key   Field.
	 * @param string $value Choice, or '' for the field.
	 * @return string
	 */
	public static function risk_id( $key, $value = '' ) {
		return 'pncp-' . $key . ( '' === $value ? '' : '-' . $value ) . '-risk';
	}

	/**
	 * Is this choice of a radio group or select one that can affect visitors or SEO?
	 *
	 * @param string $key   Field.
	 * @param string $value Choice.
	 * @return bool
	 */
	public static function is_risky_choice( $key, $value ) {
		$choices = self::risky_choices();
		return isset( $choices[ $key ] ) && in_array( (string) $value, $choices[ $key ], true );
	}

	/**
	 * "Default: on/off" after a checkbox whose value is not the default, "Default: 60" after every number
	 * (3.11: also when it has the default value), or ''.
	 *
	 * @param string               $key Field.
	 * @param array<string, mixed> $s   Settings.
	 * @return string HTML.
	 */
	public static function default_note( $key, $s ) {
		// New installs start with "Monitor only" on (PNCP_Options::new_install()), the 1.4 proxy option can only be
		// turned off, and an image ID has no meaningful default.
		if ( in_array( $key, array( 'monitor_mode', 'trust_any_proxy', 'watermark_image_id' ), true ) ) {
			return '';
		}
		// 3.11: the defaults of a new install (PNCP_Options::install_defaults()), e.g. "Ban scanners on their first
		// probe" is on there; a site installed before 3.11 that still has the old value is told so (upgrade_note()).
		$defaults = PNCP_Options::install_defaults();
		if ( ! isset( $defaults[ $key ], $s[ $key ] ) ) {
			return '';
		}
		if ( in_array( $key, PNCP_Options::bool_keys(), true ) ) {
			if ( empty( $s[ $key ] ) === empty( $defaults[ $key ] ) ) {
				return '';
			}
			$text = empty( $defaults[ $key ] ) ? __( 'Default: off', 'scrapelock' ) : __( 'Default: on', 'scrapelock' );
		} elseif ( isset( PNCP_Options::int_ranges()[ $key ] ) ) {
			// 3.11: always shown for a number, also at its default: the help texts no longer repeat "Starting value".
			/* translators: %s: the default number */
			$text = sprintf( __( 'Default: %s', 'scrapelock' ), number_format_i18n( (int) $defaults[ $key ] ) );
		} else {
			return '';
		}
		$text = self::upgrade_note( $key, $s, $text );
		return sprintf( '<span class="pncp-default-note" id="%1$s">%2$s</span>', esc_attr( 'pncp-' . $key . '-default' ), esc_html( $text ) );
	}

	/**
	 * 3.9: a setting that sites upgraded from an older version got with another value than new installs
	 * (PNCP_Options::upgrade_values()), and that still has that value here: the note says both, e.g. "Default on
	 * new installs: on. Sites installed before 2.6 got it off when they were upgraded." Otherwise the note as it is.
	 *
	 * @param string               $key  Field.
	 * @param array<string, mixed> $s    Settings.
	 * @param string               $text The note so far ("Default: on").
	 * @return string
	 */
	private static function upgrade_note( $key, $s, $text ) {
		$upgrade = PNCP_Options::upgrade_values();
		if ( ! isset( $upgrade[ $key ] ) || (string) $s[ $key ] !== (string) $upgrade[ $key ]['value'] ) {
			return $text;
		}
		$defaults = PNCP_Options::install_defaults();
		if ( in_array( $key, PNCP_Options::bool_keys(), true ) ) {
			$text = empty( $defaults[ $key ] )
				/* translators: %s: version number, e.g. 2.6 */
				? sprintf( __( 'Default on new installs: off. Sites installed before %s got it on when they were upgraded.', 'scrapelock' ), $upgrade[ $key ]['since'] )
				/* translators: %s: version number, e.g. 2.6 */
				: sprintf( __( 'Default on new installs: on. Sites installed before %s got it off when they were upgraded.', 'scrapelock' ), $upgrade[ $key ]['since'] );
		} else {
			/* translators: 1: the default number, 2: version number, e.g. 2.6, 3: the value upgraded sites got */
			$text = sprintf( __( 'Default on new installs: %1$s. Sites installed before %2$s got %3$s when they were upgraded.', 'scrapelock' ), number_format_i18n( (int) $defaults[ $key ] ), $upgrade[ $key ]['since'], number_format_i18n( (int) $upgrade[ $key ]['value'] ) );
		}
		return $text;
	}

	/**
	 * Is this the default value of a select or radio group?
	 *
	 * @param string $key   Field.
	 * @param string $value Choice.
	 * @return bool
	 */
	public static function is_default( $key, $value ) {
		$defaults = PNCP_Options::install_defaults();
		return isset( $defaults[ $key ] ) && (string) $defaults[ $key ] === (string) $value;
	}

	/**
	 * The ids for aria-describedby: help text, risk tag, requirement note. '' when there are none.
	 *
	 * @param string $key      Field.
	 * @param bool   $has_help Whether the field prints a help text (id pncp-<key>-help).
	 * @return string
	 */
	public static function describedby( $key, $has_help ) {
		$ids = array();
		if ( $has_help ) {
			$ids[] = 'pncp-' . $key . '-help';
		}
		if ( isset( self::risky()[ $key ] ) ) {
			$ids[] = self::risk_id( $key );
		}
		if ( isset( self::requires()[ $key ] ) ) {
			$ids[] = 'pncp-' . $key . '-requires';
		}
		return implode( ' ', $ids );
	}

	/**
	 * The aria-describedby attribute with a leading space, or ''.
	 *
	 * @param string $key      Field.
	 * @param bool   $has_help Whether the field prints a help text.
	 * @return string Escaped attribute.
	 */
	public static function describedby_attr( $key, $has_help ) {
		$ids = self::describedby( $key, $has_help );
		return '' === $ids ? '' : ' aria-describedby="' . esc_attr( $ids ) . '"';
	}
}
