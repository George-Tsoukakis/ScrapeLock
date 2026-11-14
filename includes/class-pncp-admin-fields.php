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
	 * The "May affect visitors/SEO" tag of a risky option, or ''.
	 *
	 * @param string $key   Field.
	 * @param string $value A choice of a radio group (its own tag id), or '' for the field.
	 * @return string HTML.
	 */
	public static function risk_tag( $key, $value = '' ) {
		if ( '' === $value ? ! isset( self::risky()[ $key ] ) : ! self::is_risky_choice( $key, $value ) ) {
			return '';
		}
		return sprintf(
			'<span class="pncp-tag pncp-tag--risk" id="%1$s">%2$s</span>',
			esc_attr( self::risk_id( $key, $value ) ),
			esc_html__( 'May affect visitors/SEO', 'scrapelock' )
		);
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
	 * "Default: on/off/60" after a checkbox or a number whose value is not the default, or ''.
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
		$defaults = PNCP_Options::defaults();
		if ( ! isset( $defaults[ $key ], $s[ $key ] ) ) {
			return '';
		}
		if ( in_array( $key, PNCP_Options::bool_keys(), true ) ) {
			if ( empty( $s[ $key ] ) === empty( $defaults[ $key ] ) ) {
				return '';
			}
			$text = empty( $defaults[ $key ] ) ? __( 'Default: off', 'scrapelock' ) : __( 'Default: on', 'scrapelock' );
		} elseif ( isset( PNCP_Options::int_ranges()[ $key ] ) ) {
			if ( (int) $s[ $key ] === (int) $defaults[ $key ] ) {
				return '';
			}
			/* translators: %s: the default number */
			$text = sprintf( __( 'Default: %s', 'scrapelock' ), number_format_i18n( (int) $defaults[ $key ] ) );
		} else {
			return '';
		}
		return sprintf( '<span class="pncp-default-note" id="%1$s">%2$s</span>', esc_attr( 'pncp-' . $key . '-default' ), esc_html( $text ) );
	}

	/**
	 * Is this the default value of a select or radio group?
	 *
	 * @param string $key   Field.
	 * @param string $value Choice.
	 * @return bool
	 */
	public static function is_default( $key, $value ) {
		$defaults = PNCP_Options::defaults();
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
