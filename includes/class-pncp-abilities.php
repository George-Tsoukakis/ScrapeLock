<?php
/**
 * Abilities API (WordPress 6.9+): what an AI agent or an MCP client may ask ScrapeLock, with the
 * permissions of the user it runs as (manage_options). Read the summary, block or unblock an IP, start or
 * stop Emergency Mode. Lockdown cannot be unlocked from here: it opens only with the authenticator app.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The scrapelock/* abilities.
 */
final class PNCP_Abilities {

	/**
	 * Registers the hooks (nothing before WordPress 6.9).
	 */
	public static function init() {
		if ( ! function_exists( 'wp_register_ability' ) ) {
			return;
		}
		add_action( 'wp_abilities_api_categories_init', array( __CLASS__, 'category' ) );
		add_action( 'wp_abilities_api_init', array( __CLASS__, 'register' ) );
	}

	/**
	 * The ScrapeLock category.
	 */
	public static function category() {
		if ( ! function_exists( 'wp_register_ability_category' ) ) {
			return;
		}
		wp_register_ability_category(
			'scrapelock',
			array(
				'label'       => 'ScrapeLock',
				'description' => __( 'Content and bot protection: blocked requests, temporary IP blocks and Emergency Mode.', 'scrapelock' ),
			)
		);
	}

	/**
	 * The abilities.
	 */
	public static function register() {
		$ip_schema = array(
			'type'        => 'string',
			'description' => __( 'IPv4 or IPv6 address. An IPv6 address counts as its /64 network.', 'scrapelock' ),
			'minLength'   => 2,
			'maxLength'   => 45,
		);
		wp_register_ability(
			'scrapelock/get-summary',
			array(
				'label'               => __( 'ScrapeLock summary', 'scrapelock' ),
				'description'         => __( 'Whether protection, Emergency Mode and Lockdown are on, how many IPs are blocked now, and the blocked requests of a period per reason, with the IPs blocked most often.', 'scrapelock' ),
				'category'            => 'scrapelock',
				'input_schema'        => array(
					'type'                 => 'object',
					'default'              => array(),
					'properties'           => array(
						'hours' => array(
							'type'        => 'integer',
							'description' => __( 'Period in hours (1 to 720).', 'scrapelock' ),
							'minimum'     => 1,
							'maximum'     => 720,
							'default'     => 24,
						),
					),
					'additionalProperties' => false,
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'enabled'          => array( 'type' => 'boolean' ),
						'emergency_until'  => array(
							'type'        => 'integer',
							'description' => __( 'Unix time when Emergency Mode ends, 0 = off.', 'scrapelock' ),
						),
						'lockdown'         => array(
							'type' => 'string',
							'enum' => array( 'not_set_up', 'unlocked', 'locked', 'off_from_server' ),
						),
						'blocked_ips'      => array( 'type' => 'integer' ),
						'hours'            => array( 'type' => 'integer' ),
						'blocked_requests' => array( 'type' => 'integer' ),
						'reasons'          => array(
							'type'                 => 'object',
							'additionalProperties' => array( 'type' => 'integer' ),
						),
						'top_ips'          => array(
							'type'                 => 'object',
							'additionalProperties' => array( 'type' => 'integer' ),
						),
					),
				),
				'execute_callback'    => array( __CLASS__, 'get_summary' ),
				'permission_callback' => array( __CLASS__, 'can_read' ),
				'meta'                => array(
					'show_in_rest' => true,
					'annotations'  => array(
						'readonly'    => true,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
		wp_register_ability(
			'scrapelock/block-ip',
			array(
				'label'               => __( 'Block an IP temporarily', 'scrapelock' ),
				'description'         => __( 'Blocks an IP (IPv6: its /64) for a number of minutes, like the automatic temporary block. Google and Bing addresses are never blocked.', 'scrapelock' ),
				'category'            => 'scrapelock',
				'input_schema'        => array(
					'type'                 => 'object',
					'properties'           => array(
						'ip'      => $ip_schema,
						'minutes' => array(
							'type'        => 'integer',
							'description' => __( 'Minutes (1 to 43200, i.e. 30 days).', 'scrapelock' ),
							'minimum'     => 1,
							'maximum'     => 43200,
							'default'     => 1440,
						),
					),
					'required'             => array( 'ip' ),
					'additionalProperties' => false,
				),
				'output_schema'       => self::done_schema(),
				'execute_callback'    => array( __CLASS__, 'block_ip' ),
				'permission_callback' => array( __CLASS__, 'can_change' ),
				'meta'                => array(
					'show_in_rest' => true,
					'annotations'  => array(
						'readonly'    => false,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
		wp_register_ability(
			'scrapelock/unblock-ip',
			array(
				'label'               => __( 'Lift a temporary IP block', 'scrapelock' ),
				'description'         => __( 'Lifts the temporary block on an IP (IPv6: its /64). The always-blocked list in the settings is not changed.', 'scrapelock' ),
				'category'            => 'scrapelock',
				'input_schema'        => array(
					'type'                 => 'object',
					'properties'           => array(
						'ip' => $ip_schema,
					),
					'required'             => array( 'ip' ),
					'additionalProperties' => false,
				),
				'output_schema'       => self::done_schema(),
				'execute_callback'    => array( __CLASS__, 'unblock_ip' ),
				'permission_callback' => array( __CLASS__, 'can_change' ),
				'meta'                => array(
					'show_in_rest' => true,
					'annotations'  => array(
						'readonly'    => false,
						'destructive' => false,
						'idempotent'  => true,
					),
				),
			)
		);
		wp_register_ability(
			'scrapelock/emergency-mode',
			array(
				'label'               => __( 'Start or stop Emergency Mode', 'scrapelock' ),
				'description'         => __( 'Emergency Mode applies stricter limits and checks for a few hours, e.g. during a scraping attack. 0 hours stops it.', 'scrapelock' ),
				'category'            => 'scrapelock',
				'input_schema'        => array(
					'type'                 => 'object',
					'properties'           => array(
						'hours' => array(
							'type'        => 'integer',
							'description' => __( 'Hours (1 to 72), or 0 to stop.', 'scrapelock' ),
							'minimum'     => 0,
							'maximum'     => 72,
						),
					),
					'required'             => array( 'hours' ),
					'additionalProperties' => false,
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'emergency_until' => array( 'type' => 'integer' ),
					),
				),
				'execute_callback'    => array( __CLASS__, 'emergency_mode' ),
				'permission_callback' => array( __CLASS__, 'can_change' ),
				'meta'                => array(
					'show_in_rest' => true,
					'annotations'  => array(
						'readonly'    => false,
						'destructive' => false,
						'idempotent'  => false,
					),
				),
			)
		);
	}

	/**
	 * Output of block / unblock.
	 *
	 * @return array<string, mixed>
	 */
	private static function done_schema() {
		return array(
			'type'       => 'object',
			'properties' => array(
				'ip'      => array(
					'type'        => 'string',
					'description' => __( 'The address or IPv6 network the block applies to.', 'scrapelock' ),
				),
				'blocked' => array( 'type' => 'boolean' ),
				'until'   => array( 'type' => 'integer' ),
			),
		);
	}

	/**
	 * Reading: administrators, also while the site is locked (reading changes nothing).
	 *
	 * @return bool
	 */
	public static function can_read() {
		return PNCP_Lockdown::can( 'manage_options' );
	}

	/**
	 * Changing: administrators, and not while Lockdown is locked (current_user_can() then says no).
	 *
	 * @return bool
	 */
	public static function can_change() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * The summary.
	 *
	 * @param array<string, mixed>|null $input Input.
	 * @return array<string, mixed>
	 */
	public static function get_summary( $input = null ) {
		$hours   = isset( $input['hours'] ) ? max( 1, min( 720, (int) $input['hours'] ) ) : 24;
		$summary = PNCP_Log::summary( $hours );
		if ( PNCP_Lockdown::server_unlocked() ) {
			$lockdown = 'off_from_server';
		} elseif ( ! PNCP_Lockdown::configured() ) {
			$lockdown = 'not_set_up';
		} else {
			$lockdown = PNCP_Lockdown::is_locked() ? 'locked' : 'unlocked';
		}
		return array(
			'enabled'          => PNCP_Status::is_enabled(),
			'emergency_until'  => PNCP_Options::emergency_until(),
			'lockdown'         => $lockdown,
			'blocked_ips'      => PNCP_Log::count_bans(),
			'hours'            => $hours,
			'blocked_requests' => (int) $summary['total'],
			'reasons'          => (object) $summary['reasons'],
			'top_ips'          => (object) $summary['ips'],
		);
	}

	/**
	 * Blocks an IP.
	 *
	 * @param array<string, mixed> $input Input.
	 * @return array<string, mixed>|WP_Error
	 */
	public static function block_ip( $input ) {
		$ip      = isset( $input['ip'] ) ? trim( (string) $input['ip'] ) : '';
		$minutes = isset( $input['minutes'] ) ? (int) $input['minutes'] : 1440;
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return new WP_Error( 'scrapelock_invalid_ip', __( 'Not a valid IP address.', 'scrapelock' ) );
		}
		if ( $minutes < 1 || $minutes > 43200 ) {
			return new WP_Error( 'scrapelock_invalid_minutes', __( 'Minutes must be between 1 and 43200.', 'scrapelock' ) );
		}
		if ( PNCP_Bots::is_official_crawler_ip( $ip ) ) {
			return new WP_Error( 'scrapelock_official_crawler', __( 'This IP belongs to Google or Bing: it is never blocked.', 'scrapelock' ) );
		}
		PNCP_Log::ban( $ip, $minutes, 'manual' );
		PNCP_Log::reset_cache();
		$key  = PNCP_Ip::limit_key( $ip );
		$bans = PNCP_Log::active_bans( 0 );
		return array(
			'ip'      => $key,
			'blocked' => PNCP_Log::is_banned( $ip ),
			'until'   => isset( $bans[ $key ] ) ? (int) $bans[ $key ]['until'] : 0,
		);
	}

	/**
	 * Lifts a block.
	 *
	 * @param array<string, mixed> $input Input.
	 * @return array<string, mixed>|WP_Error
	 */
	public static function unblock_ip( $input ) {
		$ip = isset( $input['ip'] ) ? trim( (string) $input['ip'] ) : '';
		if ( ! PNCP_Ip::valid_range( $ip ) ) {
			return new WP_Error( 'scrapelock_invalid_ip', __( 'Not a valid IP address.', 'scrapelock' ) );
		}
		PNCP_Log::unban( $ip );
		PNCP_Log::reset_cache();
		return array(
			'ip'      => false === strpos( $ip, '/' ) ? PNCP_Ip::limit_key( $ip ) : $ip,
			'blocked' => false === strpos( $ip, '/' ) ? PNCP_Log::is_banned( $ip ) : false,
			'until'   => 0,
		);
	}

	/**
	 * Starts or stops Emergency Mode.
	 *
	 * @param array<string, mixed> $input Input.
	 * @return array<string, mixed>|WP_Error
	 */
	public static function emergency_mode( $input ) {
		$hours = isset( $input['hours'] ) ? (int) $input['hours'] : -1;
		if ( $hours < 0 || $hours > 72 ) {
			return new WP_Error( 'scrapelock_invalid_hours', __( 'Hours must be between 0 and 72.', 'scrapelock' ) );
		}
		PNCP_Options::set_emergency( $hours );
		return array( 'emergency_until' => PNCP_Options::emergency_until() );
	}
}
