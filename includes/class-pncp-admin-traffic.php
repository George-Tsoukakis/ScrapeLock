<?php
/**
 * 3.12: the Traffic tab (Records → Traffic): the requests the site answered, from the Bunny CDN logs, the access
 * log or WordPress itself (PNCP_Traffic). Views inside the tab (?tr_view=): overview, agents (User-Agents),
 * problems (404, 5xx, redirects, not cached, largest, slowest), visitors (IPs and countries), log (the requests
 * themselves, with "Export CSV"), settings (sources and settings), and the detail of one User-Agent (ua), path or
 * IP (tr_key=). Every filter is in the address (tr_period, tr_from, tr_to, tr_src, tr_status, tr_q, tr_fam, tr_ua,
 * tr_path, tr_ip, tr_country), so a view can be bookmarked; nothing of it is stored.
 *
 * Read only, GET: each view asks the query API (PNCP_Traffic_Query, limits at most 500, cached) only for what it
 * shows. The actions (PNCP_Traffic_Actions) are admin-post forms with a nonce.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * The Traffic tab.
 */
final class PNCP_Admin_Traffic {

	/**
	 * Rows per page of the tables.
	 */
	const PER_PAGE = 50;

	/**
	 * Query parameters of the state (key => parameter).
	 */
	const PARAMS = array(
		'view'    => 'tr_view',
		'period'  => 'tr_period',
		'from'    => 'tr_from',
		'to'      => 'tr_to',
		'src'     => 'tr_src',
		'status'  => 'tr_status',
		'q'       => 'tr_q',
		'fam'     => 'tr_fam',
		'ua'      => 'tr_ua',
		'path'    => 'tr_path',
		'ip'      => 'tr_ip',
		'country' => 'tr_country',
		'order'   => 'tr_order',
		'paged'   => 'tr_paged',
		'type'    => 'tr_type',
		'scan'    => 'tr_scan',
		'key'     => 'tr_key',
		'act'     => 'tr_act',
		'confirm' => 'tr_confirm',
		'fts'     => 'tr_fts',
		'tts'     => 'tr_tts',
	);

	/**
	 * Other names the tab reads when its own parameter is missing (the links of the traffic alert emails):
	 * parameter => state key. "from" and "to" there are Unix times.
	 */
	const ALIASES = array(
		'view'    => 'view',
		'status'  => 'status',
		'src'     => 'src',
		'problem' => 'type',
		'ua'      => 'ua',
		'from'    => 'fts',
		'to'      => 'tts',
	);

	/**
	 * The filters every view keeps when another view is opened.
	 */
	const KEEP = array( 'period', 'from', 'to', 'fts', 'tts', 'src', 'status', 'q', 'fam', 'ua', 'path', 'ip', 'country' );

	/**
	 * The views.
	 */
	const VIEWS = array( 'overview', 'agents', 'problems', 'visitors', 'log', 'settings', 'ua', 'path', 'ip' );

	/**
	 * The state of this page load.
	 *
	 * @var array<string, mixed>
	 */
	private static $st = array();

	/**
	 * Whether a result was answered from the raw window only (one notice per page).
	 *
	 * @var array{0:bool, 1:int}
	 */
	private static $clipped = array( false, 0 );

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'removable_query_args', array( __CLASS__, 'removable' ) );
		PNCP_Traffic_Actions::init();
	}

	/**
	 * The result notice leaves the address bar after it was shown.
	 *
	 * @param string[] $args Query arguments.
	 * @return string[]
	 */
	public static function removable( $args ) {
		$args[] = 'tr_msg';
		return $args;
	}

	/**
	 * The stylesheets and the small script, on this tab only.
	 *
	 * @param string $hook Page hook.
	 */
	public static function assets( $hook ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only selects the assets.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		if ( 'settings_page_' . PNCP_Admin::PAGE !== $hook || 'traffic' !== $tab ) {
			return;
		}
		wp_enqueue_style( 'pncp-attack-report', PNCP_URL . 'assets/css/attack-report.css', array(), PNCP_VERSION ); // The tiles, periods and charts.
		wp_enqueue_style( 'pncp-traffic', PNCP_URL . 'assets/css/traffic.css', array( 'pncp-attack-report' ), PNCP_VERSION );
		wp_enqueue_script( 'pncp-traffic', PNCP_URL . 'assets/js/traffic.js', array(), PNCP_VERSION, true );
	}

	/* ---------- State, filters, addresses ---------- */

	/**
	 * The state of the screen from query arguments, every value checked.
	 *
	 * @param mixed $in Query arguments ($_GET, or the CSV form's $_POST), unslashed.
	 * @return array<string, mixed>
	 */
	public static function state( $in ) {
		$in = is_array( $in ) ? $in : array();
		foreach ( self::ALIASES as $alias => $key ) {
			if ( ! isset( $in[ self::PARAMS[ $key ] ] ) && isset( $in[ $alias ] ) ) {
				$in[ self::PARAMS[ $key ] ] = $in[ $alias ];
			}
		}
		$get    = static function ( $key ) use ( $in ) {
			$name = self::PARAMS[ $key ];
			return isset( $in[ $name ] ) && is_scalar( $in[ $name ] ) ? trim( (string) $in[ $name ] ) : '';
		};
		$view   = sanitize_key( $get( 'view' ) );
		$names  = array(
			'raw'     => 'log',
			'sources' => 'settings',
		);
		$view   = isset( $names[ $view ] ) ? $names[ $view ] : $view;
		$fts    = ctype_digit( $get( 'fts' ) ) ? (int) $get( 'fts' ) : 0;
		$tts    = ctype_digit( $get( 'tts' ) ) ? (int) $get( 'tts' ) : 0;
		$period = sanitize_key( $get( 'period' ) );
		$date   = static function ( $value ) {
			return preg_match( '/^(\d{4})-(\d{2})-(\d{2})$/', $value, $m ) && checkdate( (int) $m[2], (int) $m[3], (int) $m[1] ) ? $value : '';
		};
		$src    = sanitize_key( $get( 'src' ) );
		$status = strtolower( $get( 'status' ) );
		$fam    = sanitize_key( $get( 'fam' ) );
		$order  = sanitize_key( $get( 'order' ) );
		$type   = sanitize_key( $get( 'type' ) );
		$ip     = PNCP_Ip::normalize( $get( 'ip' ) );
		if ( '' === $ip && preg_match( '/^[0-9a-f:.]{2,45}$/i', $get( 'ip' ) ) ) {
			$ip = $get( 'ip' ); // A masked address (203.0.113.0) is still an address; anything else is dropped.
		}
		$country = strtoupper( $get( 'country' ) );
		return array(
			'view'    => in_array( $view, self::VIEWS, true ) ? $view : 'overview',
			'period'  => $fts > 0 ? 'custom' : ( in_array( $period, array_keys( self::periods() ), true ) ? $period : '24h' ),
			'from'    => '' !== $date( $get( 'from' ) ) || ! $fts ? $date( $get( 'from' ) ) : wp_date( 'Y-m-d', $fts ),
			'to'      => '' !== $date( $get( 'to' ) ) || ! $tts ? $date( $get( 'to' ) ) : wp_date( 'Y-m-d', $tts ),
			'src'     => in_array( $src, PNCP_Traffic::SOURCES, true ) ? $src : '',
			'status'  => in_array( $status, array( '2xx', '3xx', '4xx', '404', '5xx' ), true ) ? $status : '',
			'q'       => PNCP_Traffic::text( sanitize_text_field( $get( 'q' ) ), 200 ),
			'fam'     => in_array( $fam, PNCP_Traffic_Ua::FAMILIES, true ) ? $fam : '',
			'ua'      => PNCP_Traffic::text( $get( 'ua' ), 255 ),
			'path'    => PNCP_Traffic::text( $get( 'path' ), 512 ),
			'ip'      => substr( $ip, 0, 45 ),
			'country' => preg_match( '/^[A-Z]{2}$/', $country ) ? $country : '',
			'order'   => in_array( $order, array( 'hits', 'ips', 'bytes', 's4xx', 's5xx', 'last' ), true ) ? $order : 'hits',
			'paged'   => max( 1, min( 10000, absint( $get( 'paged' ) ) ) ),
			'type'    => in_array( $type, PNCP_Traffic_Query::PROBLEMS, true ) ? $type : '404',
			'scan'    => '1' === $get( 'scan' ),
			'key'     => PNCP_Traffic::text( $get( 'key' ), 512 ),
			'act'     => in_array( $get( 'act' ), array( 'block', 'allow' ), true ) ? $get( 'act' ) : '',
			'confirm' => 'purge' === $get( 'confirm' ) ? 'purge' : '',
			// Exact Unix times (a link from an alert): a custom period to the second.
			'fts'     => $fts > 0 ? (string) $fts : '',
			'tts'     => $tts > 0 && $tts >= $fts ? (string) $tts : '',
		);
	}

	/**
	 * The periods of the toolbar.
	 *
	 * @return array<string, string>
	 */
	public static function periods() {
		return array(
			'24h'    => __( '24 hours', 'scrapelock' ),
			'7d'     => __( '7 days', 'scrapelock' ),
			'30d'    => __( '30 days', 'scrapelock' ),
			'90d'    => __( '90 days', 'scrapelock' ),
			'custom' => __( 'Custom dates', 'scrapelock' ),
		);
	}

	/**
	 * Midnight (site time) of a Y-m-d date.
	 *
	 * @param string $date Date.
	 * @return int
	 */
	private static function midnight( $date ) {
		$d = DateTimeImmutable::createFromFormat( '!Y-m-d', $date, wp_timezone() );
		return $d ? $d->getTimestamp() : 0;
	}

	/**
	 * The query filters (PNCP_Traffic_Query::filters()) of a state.
	 *
	 * @param array<string, mixed> $st State.
	 * @return array<string, mixed>
	 */
	public static function filters( $st ) {
		$now  = time();
		$to   = $now;
		$days = array(
			'24h' => 1,
			'7d'  => 7,
			'30d' => 30,
			'90d' => 90,
		);
		if ( '' !== $st['fts'] ) {
			$from = (int) $st['fts'];
			$to   = '' !== $st['tts'] ? min( $now, (int) $st['tts'] ) : $now;
			$from = min( $from, $to );
		} elseif ( 'custom' === $st['period'] ) {
			$to   = '' !== $st['to'] ? min( $now, PNCP_Traffic::add_days( self::midnight( $st['to'] ) ) - 1 ) : $now;
			$from = '' !== $st['from'] ? self::midnight( $st['from'] ) : $to - 7 * DAY_IN_SECONDS;
			$from = min( $from, $to );
		} else {
			$from = $now - $days[ $st['period'] ] * DAY_IN_SECONDS;
		}
		$f = array(
			'from'      => $from,
			'to'        => $to,
			'src'       => $st['src'],
			'status'    => $st['status'],
			'search'    => $st['q'],
			'ua_family' => $st['fam'],
			'ua'        => $st['ua'],
			'path'      => $st['path'],
			'ip'        => $st['ip'],
			'country'   => $st['country'],
		);
		return array_filter(
			$f,
			static function ( $v ) {
				return '' !== $v && null !== $v;
			}
		);
	}

	/**
	 * The address of the tab with these arguments (values encoded here).
	 *
	 * @param array<string, string> $args Parameter => value ('' leaves it out).
	 * @return string
	 */
	public static function url_for( $args ) {
		$out = array( 'tab' => 'traffic' );
		foreach ( $args as $name => $value ) {
			if ( '' !== (string) $value ) {
				$out[ $name ] = rawurlencode( (string) $value );
			}
		}
		return PNCP_Status::settings_url( $out );
	}

	/**
	 * The address of a view with the filters of this page and some changes.
	 *
	 * @param array<string, mixed> $over State keys to change ('' removes); a new view starts without the view's own
	 *                                   arguments (page, order, type) unless given.
	 * @return string
	 */
	private static function url( $over = array() ) {
		$st   = self::$st;
		$keep = self::KEEP;
		if ( ! isset( $over['view'] ) || $over['view'] === $st['view'] ) {
			$keep = array_merge( $keep, array( 'view', 'order', 'type', 'scan', 'key' ) );
		}
		$args = array( 'view' => isset( $over['view'] ) ? $over['view'] : $st['view'] ); // The view first: easier to read.
		foreach ( $keep as $key ) {
			$args[ $key ] = $st[ $key ];
		}
		$args  = array_merge( $args, $over );
		$query = array();
		foreach ( $args as $key => $value ) {
			if ( ! isset( self::PARAMS[ $key ] ) ) {
				continue;
			}
			if ( is_bool( $value ) ) {
				$value = $value ? '1' : '';
			}
			$value = (string) $value;
			$skip  = '' === $value || ( 'view' === $key && 'overview' === $value ) || ( 'period' === $key && '24h' === $value ) || ( 'order' === $key && 'hits' === $value ) || ( 'paged' === $key && '1' === $value ) || ( 'type' === $key && '404' === $value && ! in_array( (string) ( isset( $args['view'] ) ? $args['view'] : '' ), array( 'problems' ), true ) );
			if ( ! $skip ) {
				$query[ self::PARAMS[ $key ] ] = $value;
			}
		}
		return self::url_for( $query );
	}

	/* ---------- Small parts ---------- */

	/**
	 * A number.
	 *
	 * @param int|float $n Number.
	 * @return string
	 */
	private static function n( $n ) {
		return number_format_i18n( (float) $n );
	}

	/**
	 * A share in percent, one decimal.
	 *
	 * @param int $part  Part.
	 * @param int $total Total.
	 * @return string
	 */
	private static function pct( $part, $total ) {
		return $total > 0 ? number_format_i18n( 100 * $part / $total, 1 ) . '%' : '–';
	}

	/**
	 * Bytes in KB / MB / GB.
	 *
	 * @param int $bytes Bytes.
	 * @return string
	 */
	private static function bytes( $bytes ) {
		$text = size_format( max( 0, (int) $bytes ), $bytes >= MB_IN_BYTES ? 1 : 0 );
		return false === $text ? '0 B' : (string) $text;
	}

	/**
	 * A time: date and time in the site's format, with "x ago" as the title.
	 *
	 * @param int $ts Unix time.
	 * @return string HTML.
	 */
	private static function when( $ts ) {
		$ts = (int) $ts;
		if ( $ts <= 0 ) {
			return '–';
		}
		return sprintf(
			'<time datetime="%1$s" title="%2$s">%3$s</time>',
			esc_attr( gmdate( 'c', $ts ) ),
			/* translators: %s: time span, e.g. "5 mins" */
			esc_attr( sprintf( __( '%s ago', 'scrapelock' ), human_time_diff( $ts ) ) ),
			esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts ) )
		);
	}

	/**
	 * The badge of a family.
	 *
	 * @param string $family Family.
	 * @return string HTML.
	 */
	private static function badge_family( $family ) {
		$labels = PNCP_Traffic_Ua::labels();
		$family = isset( $labels[ $family ] ) ? $family : 'other';
		return sprintf( '<span class="pncp-tr__fam pncp-tr__fam--%1$s">%2$s</span>', esc_attr( $family ), esc_html( $labels[ $family ] ) );
	}

	/**
	 * A status code, coloured by its class.
	 *
	 * @param int|string $code Code ("404", or "4xx" over the aggregates).
	 * @return string HTML.
	 */
	private static function status( $code ) {
		$code  = (string) $code;
		$class = preg_match( '/^[1-5]/', $code ) ? $code[0] : '0';
		return sprintf( '<span class="pncp-tr__st pncp-tr__st--%1$s">%2$s</span>', esc_attr( $class ), esc_html( '' === $code || '0' === $code ? '–' : $code ) );
	}

	/**
	 * A path, shortened for display.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	private static function show_path( $path ) {
		return PNCP_Log::display_path( (string) $path );
	}

	/**
	 * A short form of a User-Agent for a table cell (the whole one is the title).
	 *
	 * @param string $ua      User-Agent.
	 * @param string $name    Its name (classify_ua()), '' = none.
	 * @param bool   $compact A small card: the name and a shorter part of the User-Agent.
	 * @return string HTML.
	 */
	private static function ua_cell( $ua, $name = '', $compact = false ) {
		$ua = (string) $ua;
		if ( '' === $ua ) {
			return '<span class="pncp-ar__muted">' . esc_html__( '(no User-Agent)', 'scrapelock' ) . '</span>';
		}
		$max   = $compact && '' !== $name ? 40 : 90;
		$short = mb_strlen( $ua ) > $max ? mb_substr( $ua, 0, $max - 2 ) . '…' : $ua;
		return ( '' !== $name ? '<strong class="pncp-tr__ua-name">' . esc_html( $name ) . '</strong> ' : '' ) . '<code class="pncp-tr__ua" title="' . esc_attr( $ua ) . '">' . esc_html( $short ) . '</code>';
	}

	/**
	 * A link to the detail of a User-Agent, path or IP.
	 *
	 * @param string $kind ua | path | ip.
	 * @param string $key  The value.
	 * @param string $html Link text (escaped HTML).
	 * @return string HTML.
	 */
	private static function detail_link( $kind, $key, $html ) {
		return sprintf(
			'<a href="%1$s" class="pncp-tr__link">%2$s</a>',
			esc_url(
				self::url(
					array(
						'view' => $kind,
						'key'  => $key,
					)
				)
			),
			$html
		);
	}

	/**
	 * The name of a source.
	 *
	 * @param string $src Source.
	 * @return string
	 */
	private static function source_name( $src ) {
		$names = array(
			'bunny'  => __( 'Bunny CDN logs', 'scrapelock' ),
			'server' => __( 'Web server access log', 'scrapelock' ),
			'wp'     => __( 'WordPress', 'scrapelock' ),
		);
		return isset( $names[ $src ] ) ? $names[ $src ] : $src;
	}

	/**
	 * A meta result was answered from the raw window only: one notice (shown by clip_note()).
	 *
	 * @param array<string, mixed> $result Result of the API.
	 */
	private static function note_clip( $result ) {
		if ( ! empty( $result['clipped'] ) ) {
			self::$clipped = array( true, (int) $result['from'] );
		}
	}

	/**
	 * The notice for a filter the daily figures cannot answer.
	 */
	private static function clip_note() {
		if ( ! self::$clipped[0] ) {
			return;
		}
		printf(
			'<div class="notice notice-info inline pncp-tr__clipped"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: 1: number of days, 2: date */
					_n( 'This filter covers only the last %1$s day of single requests (since %2$s): remove the filter for the whole period.', 'This filter covers only the last %1$s days of single requests (since %2$s): remove the filter for the whole period.', PNCP_Traffic::settings()['raw_days'], 'scrapelock' ),
					number_format_i18n( PNCP_Traffic::settings()['raw_days'] ),
					wp_date( get_option( 'date_format' ), self::$clipped[1] )
				)
			)
		);
	}

	/**
	 * An empty table.
	 *
	 * @param string $text Text.
	 */
	private static function empty_note( $text = '' ) {
		echo '<p class="pncp-empty">' . esc_html( '' !== $text ? $text : __( 'No requests in this period with these filters.', 'scrapelock' ) ) . '</p>';
	}

	/**
	 * A column heading that sorts the table.
	 *
	 * @param string $label Label.
	 * @param string $key   Order key.
	 * @param bool   $num   Numeric column.
	 */
	private static function th_sort( $label, $key, $num = true ) {
		$current = self::$st['order'] === $key;
		printf(
			'<th scope="col" class="%1$s"%2$s><a href="%3$s">%4$s%5$s</a></th>',
			esc_attr( trim( ( $num ? 'num ' : '' ) . 'pncp-tr__sort' . ( $current ? ' is-sorted' : '' ) ) ),
			$current ? ' aria-sort="descending"' : '',
			esc_url(
				self::url(
					array(
						'order' => $key,
						'paged' => '',
					)
				)
			),
			esc_html( $label ),
			$current ? ' <span aria-hidden="true">▼</span>' : ''
		);
	}

	/**
	 * Page links under a table.
	 *
	 * @param int  $total Rows in all (-1 = unknown).
	 * @param bool $more  There is a next page (when the total is unknown).
	 */
	private static function pager( $total, $more = false ) {
		$paged = (int) self::$st['paged'];
		$pages = $total >= 0 ? (int) max( 1, ceil( $total / self::PER_PAGE ) ) : 0;
		$next  = $total >= 0 ? $paged < $pages : $more;
		if ( $paged <= 1 && ! $next ) {
			return;
		}
		echo '<nav class="pncp-tr__pager" aria-label="' . esc_attr__( 'Pages', 'scrapelock' ) . '">';
		if ( $paged > 1 ) {
			printf( '<a class="button" href="%1$s" rel="prev">%2$s</a> ', esc_url( self::url( array( 'paged' => (string) ( $paged - 1 ) ) ) ), esc_html__( '← Previous', 'scrapelock' ) );
		}
		echo '<span class="pncp-tr__pageno">';
		echo esc_html(
			$pages
				/* translators: 1: page number, 2: number of pages */
				? sprintf( __( 'Page %1$s of %2$s', 'scrapelock' ), self::n( $paged ), self::n( $pages ) )
				/* translators: %s: page number */
				: sprintf( __( 'Page %s', 'scrapelock' ), self::n( $paged ) )
		);
		echo '</span>';
		if ( $next ) {
			printf( ' <a class="button" href="%1$s" rel="next">%2$s</a>', esc_url( self::url( array( 'paged' => (string) ( $paged + 1 ) ) ) ), esc_html__( 'Next →', 'scrapelock' ) );
		}
		echo '</nav>';
	}

	/**
	 * The offset of the page.
	 *
	 * @return int
	 */
	private static function offset() {
		return ( (int) self::$st['paged'] - 1 ) * self::PER_PAGE;
	}

	/* ---------- The tab ---------- */

	/**
	 * The tab.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	public static function render( $s ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::$st      = self::state( wp_unslash( $_GET ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only views; every value is checked in state().
		self::$clipped = array( false, 0 );
		$tr            = PNCP_Traffic::settings();
		$status        = PNCP_Traffic::sources_status();
		$has_data      = false;
		foreach ( PNCP_Traffic::SOURCES as $src ) {
			$has_data = $has_data || (int) $status[ $src ]['last_ingest'] > 0;
		}
		echo '<div class="pncp-ar pncp-tr" id="pncp-tr">';
		self::render_notice();
		if ( ! $tr['on'] ) {
			self::render_off( $tr, $status, $has_data );
			if ( ! $has_data ) {
				self::render_settings( $s, $status );
				echo '</div>';
				return;
			}
		}
		self::render_nav();
		$view = self::$st['view'];
		if ( 'settings' === $view ) {
			self::render_settings( $s, $status );
			echo '</div>';
			return;
		}
		ob_start();
		switch ( $view ) {
			case 'agents':
				self::view_agents();
				break;
			case 'problems':
				self::view_problems();
				break;
			case 'visitors':
				self::view_visitors();
				break;
			case 'log':
				self::view_log();
				break;
			case 'ua':
				self::view_ua( $s );
				break;
			case 'path':
				self::view_path();
				break;
			case 'ip':
				self::view_ip();
				break;
			default:
				self::view_overview();
		}
		$body = (string) ob_get_clean();
		self::render_toolbar( $status );
		self::clip_note();
		echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Built and escaped above.
		echo '</div>';
	}

	/**
	 * The notice of the last action (tr_msg).
	 */
	private static function render_notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only displays a notice.
		$code   = isset( $_GET['tr_msg'] ) ? sanitize_key( wp_unslash( $_GET['tr_msg'] ) ) : '';
		$notice = '' !== $code ? PNCP_Traffic_Actions::notice( $code ) : null;
		if ( null === $notice || '' === $notice[1] ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only offers the Undo of the saved version.
		$undo = isset( $_GET['pncp_undo'] ) ? sanitize_key( wp_unslash( $_GET['pncp_undo'] ) ) : '';
		printf( '<div class="notice notice-%1$s inline pncp-ar__notice pncp-tr__notice" role="%3$s"><p>%2$s</p>', esc_attr( $notice[0] ), esc_html( $notice[1] ), 'error' === $notice[0] ? 'alert' : 'status' );
		if ( '' !== $undo && PNCP_Settings_Io::find( $undo ) ) {
			printf( '<form method="post" action="%s" class="pncp-inline-form">', esc_url( admin_url( 'admin-post.php' ) ) );
			echo '<input type="hidden" name="action" value="pncp_settings"><input type="hidden" name="op" value="restore">';
			printf( '<input type="hidden" name="id" value="%s">', esc_attr( $undo ) );
			echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( 'pncp_settings', '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
			echo '<p><button type="submit" class="button">' . esc_html__( 'Undo', 'scrapelock' ) . '</button></p></form>';
		}
		echo '</div>';
	}

	/**
	 * The views inside the tab.
	 */
	private static function render_nav() {
		$items   = array(
			'overview' => __( 'Overview', 'scrapelock' ),
			'agents'   => __( 'User-Agents', 'scrapelock' ),
			'problems' => __( 'Problem URLs', 'scrapelock' ),
			'visitors' => __( 'Visitors', 'scrapelock' ),
			'log'      => __( 'Requests', 'scrapelock' ),
			'settings' => __( 'Sources and settings', 'scrapelock' ),
		);
		$parent  = array(
			'ua'   => 'agents',
			'path' => 'problems',
			'ip'   => 'visitors',
		);
		$current = isset( $parent[ self::$st['view'] ] ) ? $parent[ self::$st['view'] ] : self::$st['view'];
		echo '<nav class="pncp-tr__nav" aria-label="' . esc_attr__( 'Traffic views', 'scrapelock' ) . '"><ul>';
		foreach ( $items as $key => $label ) {
			printf(
				'<li><a href="%1$s"%2$s>%3$s</a></li>',
				esc_url( self::url( array( 'view' => $key ) ) ),
				$current === $key ? ' class="is-current" aria-current="page"' : '',
				esc_html( $label )
			);
		}
		echo '</ul></nav>';
	}

	/**
	 * The filters: period, source, status, search, and the filters a link added (removable).
	 *
	 * @param array<string, mixed> $status sources_status().
	 */
	private static function render_toolbar( $status ) {
		$st = self::$st;
		echo '<form method="get" action="' . esc_url( admin_url( 'options-general.php' ) ) . '" class="pncp-tr__toolbar" role="search" aria-label="' . esc_attr__( 'Filters', 'scrapelock' ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( PNCP_Admin::PAGE ) . '"><input type="hidden" name="tab" value="traffic">';
		foreach ( array( 'view', 'type', 'key', 'fam', 'ua', 'path', 'ip', 'country' ) as $key ) {
			$value = (string) $st[ $key ];
			if ( '' !== $value && ! ( 'view' === $key && 'overview' === $value ) && ! ( 'type' === $key && 'problems' !== $st['view'] ) ) {
				printf( '<input type="hidden" name="%1$s" value="%2$s">', esc_attr( self::PARAMS[ $key ] ), esc_attr( $value ) );
			}
		}
		if ( $st['scan'] ) {
			echo '<input type="hidden" name="tr_scan" value="1">';
		}
		if ( 'hits' !== $st['order'] ) {
			printf( '<input type="hidden" name="tr_order" value="%s">', esc_attr( $st['order'] ) );
		}
		// Period.
		echo '<p class="pncp-tr__field"><label for="pncp-tr-period">' . esc_html__( 'Period', 'scrapelock' ) . '</label> <select id="pncp-tr-period" name="tr_period" data-pncp-tr-period>';
		foreach ( self::periods() as $value => $label ) {
			printf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( $value ), selected( $st['period'], $value, false ), esc_html( $label ) );
		}
		echo '</select></p>';
		echo '<p class="pncp-tr__field pncp-tr__dates" data-pncp-tr-dates>';
		printf( '<label for="pncp-tr-from">%1$s</label> <input type="date" id="pncp-tr-from" name="tr_from" value="%2$s" max="%3$s"> ', esc_html__( 'From', 'scrapelock' ), esc_attr( $st['from'] ), esc_attr( wp_date( 'Y-m-d' ) ) );
		printf( '<label for="pncp-tr-to">%1$s</label> <input type="date" id="pncp-tr-to" name="tr_to" value="%2$s" max="%3$s">', esc_html__( 'To', 'scrapelock' ), esc_attr( $st['to'] ), esc_attr( wp_date( 'Y-m-d' ) ) );
		echo '</p>';
		// Source: auto, and the sources with data.
		echo '<p class="pncp-tr__field"><label for="pncp-tr-src">' . esc_html__( 'Source', 'scrapelock' ) . '</label> <select id="pncp-tr-src" name="tr_src">';
		/* translators: %s: name of a source, e.g. Bunny CDN logs */
		printf( '<option value="">%s</option>', esc_html( sprintf( __( 'Auto (%s)', 'scrapelock' ), self::source_name( (string) $status['auto'] ) ) ) );
		foreach ( PNCP_Traffic::SOURCES as $src ) {
			if ( (int) $status[ $src ]['last_ingest'] > 0 || $st['src'] === $src ) {
				printf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( $src ), selected( $st['src'], $src, false ), esc_html( self::source_name( $src ) ) );
			}
		}
		echo '</select></p>';
		// Status.
		$codes = array(
			''    => __( 'All statuses', 'scrapelock' ),
			'2xx' => __( '2xx (OK)', 'scrapelock' ),
			'3xx' => __( '3xx (redirects)', 'scrapelock' ),
			'4xx' => __( '4xx (client errors)', 'scrapelock' ),
			'404' => __( '404 (not found)', 'scrapelock' ),
			'5xx' => __( '5xx (server errors)', 'scrapelock' ),
		);
		echo '<p class="pncp-tr__field"><label for="pncp-tr-status">' . esc_html__( 'Status', 'scrapelock' ) . '</label> <select id="pncp-tr-status" name="tr_status">';
		foreach ( $codes as $value => $label ) {
			printf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( $value ), selected( $st['status'], $value, false ), esc_html( $label ) );
		}
		echo '</select></p>';
		printf(
			'<p class="pncp-tr__field pncp-tr__search"><label for="pncp-tr-q">%1$s</label> <input type="search" id="pncp-tr-q" name="tr_q" value="%2$s" maxlength="200" placeholder="%3$s"></p>',
			esc_html__( 'Search', 'scrapelock' ),
			esc_attr( $st['q'] ),
			esc_attr__( 'Path or User-Agent', 'scrapelock' )
		);
		echo '<p class="pncp-tr__field pncp-tr__apply"><button type="submit" class="button button-primary">' . esc_html__( 'Apply', 'scrapelock' ) . '</button> ';
		printf( '<a href="%1$s">%2$s</a></p>', esc_url( self::url_for( 'overview' === $st['view'] ? array() : array( 'tr_view' => in_array( $st['view'], array( 'ua', 'path', 'ip' ), true ) ? '' : $st['view'] ) ) ), esc_html__( 'Clear filters', 'scrapelock' ) );
		echo '</form>';
		// The filters a link added: each one removable.
		$labels = array(
			'fam'     => __( 'Family', 'scrapelock' ),
			'ua'      => __( 'User-Agent', 'scrapelock' ),
			'path'    => __( 'Path', 'scrapelock' ),
			'ip'      => __( 'IP', 'scrapelock' ),
			'country' => __( 'Country', 'scrapelock' ),
		);
		$chips  = '';
		if ( '' !== $st['fts'] ) {
			$chips .= sprintf(
				'<li><span class="pncp-tr__chip">%1$s: <code>%2$s</code> <a href="%3$s" class="pncp-tr__chip-x" aria-label="%4$s">×</a></span></li>',
				esc_html__( 'Exact period', 'scrapelock' ),
				esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $st['fts'] ) . ' – ' . ( '' !== $st['tts'] ? wp_date( get_option( 'time_format' ), (int) $st['tts'] ) : __( 'now', 'scrapelock' ) ) ),
				esc_url(
					self::url(
						array(
							'fts'    => '',
							'tts'    => '',
							'period' => '24h',
							'from'   => '',
							'to'     => '',
						)
					)
				),
				/* translators: %s: name of a filter, e.g. IP */
				esc_attr( sprintf( __( 'Remove the filter %s', 'scrapelock' ), __( 'Exact period', 'scrapelock' ) ) )
			);
		}
		foreach ( $labels as $key => $label ) {
			if ( '' === $st[ $key ] ) {
				continue;
			}
			$value  = 'fam' === $key ? PNCP_Traffic_Ua::labels()[ $st[ $key ] ] : (string) $st[ $key ];
			$chips .= sprintf(
				'<li><span class="pncp-tr__chip">%1$s: <code>%2$s</code> <a href="%3$s" class="pncp-tr__chip-x" aria-label="%4$s">×</a></span></li>',
				esc_html( $label ),
				esc_html( mb_strlen( $value ) > 60 ? mb_substr( $value, 0, 58 ) . '…' : $value ),
				esc_url(
					self::url(
						array(
							$key    => '',
							'paged' => '',
						)
					)
				),
				/* translators: %s: name of a filter, e.g. IP */
				esc_attr( sprintf( __( 'Remove the filter %s', 'scrapelock' ), $label ) )
			);
		}
		if ( '' !== $chips ) {
			echo '<ul class="pncp-tr__chips" aria-label="' . esc_attr__( 'Active filters', 'scrapelock' ) . '">' . $chips . '</ul>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
		}
	}

	/* ---------- Off ---------- */

	/**
	 * Collection is off: what it collects, where, the sources found and "Start collecting".
	 *
	 * @param array<string, mixed> $tr       PNCP_Traffic::settings().
	 * @param array<string, mixed> $status   sources_status().
	 * @param bool                 $has_data Something was collected before.
	 */
	private static function render_off( $tr, $status, $has_data ) {
		$rec = PNCP_Traffic_Actions::recommended();
		?>
		<section class="pncp-card pncp-card--wide pncp-tr__off" aria-labelledby="pncp-tr-off-title">
			<h2 id="pncp-tr-off-title"><?php esc_html_e( 'Traffic', 'scrapelock' ); ?></h2>
			<?php
			$intro = PNCP_Admin_Fields::para(
				__( 'See every request: which pages, which browsers and bots, and what fails.', 'scrapelock' ),
				__( 'Each request is stored with its time, IP, country, method, status, address, referrer, User-Agent, size and cache status. Everything stays in this site\'s database; nothing is sent anywhere. Only one source is counted at a time, so a request is never counted twice.', 'scrapelock' )
			);
			echo $intro; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
			if ( $has_data ) {
				echo '<p class="pncp-ar__warn">' . esc_html__( 'Collection is off: the figures below are from before.', 'scrapelock' ) . '</p>';
			}
			?>
			<ul class="pncp-tr__facts">
				<li>
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: days single requests are kept, 2: days the daily figures are kept */
						__( 'Each request is kept %1$s days, the daily figures %2$s days.', 'scrapelock' ),
						self::n( $tr['raw_days'] ),
						self::n( $tr['days'] )
					)
				);
				?>
				</li>
				<li><?php echo esc_html( 'masked' === $tr['ip_mode'] ? __( 'IP addresses are stored masked (the last part removed).', 'scrapelock' ) : __( 'IP addresses are stored in full.', 'scrapelock' ) ); ?></li>
			</ul>
			<h3><?php esc_html_e( 'Sources found', 'scrapelock' ); ?></h3>
			<ul class="pncp-tr__found">
				<li><?php echo esc_html( PNCP_Traffic::bunny_on() ? __( 'Bunny CDN logs: imported. Best source: it also sees the pages served from the CDN cache.', 'scrapelock' ) : ( 'not_connected' === $status['bunny']['error'] ? __( 'Bunny CDN logs: not connected.', 'scrapelock' ) : __( 'Bunny CDN logs: connected, but the log import is off.', 'scrapelock' ) ) ); ?></li>
				<li>
				<?php
				if ( 'server' === $rec['source'] ) {
					/* translators: %s: file path */
					echo esc_html( sprintf( __( 'Web server access log: %s', 'scrapelock' ), $rec['path'] ) );
				} else {
					esc_html_e( 'Web server access log: none found; set its path below if PHP may read it.', 'scrapelock' );
				}
				?>
				</li>
				<li><?php esc_html_e( 'WordPress: always possible, but it misses the pages served from a cache.', 'scrapelock' ); ?></li>
			</ul>
			<?php
			$what = array(
				/* translators: %s: name of a source */
				sprintf( __( '“Start collecting” uses: %s.', 'scrapelock' ), self::source_name( $rec['source'] ) ),
			);
			if ( isset( $rec['changes']['traffic_log_path'] ) ) {
				/* translators: %s: file path */
				$what[] = sprintf( __( 'It also sets the access log path to %s.', 'scrapelock' ), $rec['changes']['traffic_log_path'] );
			}
			if ( isset( $rec['changes']['traffic_wp'] ) ) {
				$what[] = __( 'It also turns on “Also record the pages WordPress serves itself”.', 'scrapelock' );
			}
			foreach ( $what as $line ) {
				echo '<p class="pncp-tr__plan">' . esc_html( $line ) . '</p>';
			}
			?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pncp-inline-form">
				<input type="hidden" name="action" value="<?php echo esc_attr( PNCP_Traffic_Actions::ACTION ); ?>">
				<input type="hidden" name="op" value="start">
				<?php echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( PNCP_Traffic_Actions::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup. ?>
				<p><button type="submit" class="button button-primary" id="pncp-tr-start"><?php esc_html_e( 'Start collecting', 'scrapelock' ); ?></button></p>
			</form>
		</section>
		<?php
	}

	/* ---------- Sources and settings ---------- */

	/**
	 * One line per source: on or off, newest data, lines today, the error.
	 *
	 * @param array<string, mixed> $status sources_status().
	 */
	private static function render_sources( $status ) {
		$errors = array(
			'not_connected' => __( 'Not connected: connect Bunny CDN under “Bots and limits”.', 'scrapelock' ),
			'import_off'    => __( 'The Bunny log import is off (“Bots and limits” → Bunny CDN).', 'scrapelock' ),
			'logging_off'   => __( 'Logging is off in the Bunny pull zone: turn it on at Bunny.', 'scrapelock' ),
		);
		echo '<ul class="pncp-tr__sources">';
		foreach ( PNCP_Traffic::SOURCES as $src ) {
			$row = $status[ $src ];
			$err = (string) $row['error'];
			if ( 'bunny' === $src && 'api_error' === $err ) {
				/* translators: %s: error message of the Bunny API */
				$text = sprintf( __( 'The Bunny API answered: %s', 'scrapelock' ), (string) $row['error_message'] );
			} elseif ( 'bunny' === $src ) {
				$text = isset( $errors[ $err ] ) ? $errors[ $err ] : '';
			} elseif ( 'server' === $src ) {
				$text = '' !== $err ? PNCP_Traffic_Log::refusal_text( $err ) : '';
			} else {
				$text = '';
			}
			$on = ! empty( $row['on'] );
			printf(
				'<li class="pncp-tr__source%1$s"><span class="pncp-tr__dot" aria-hidden="true"></span> <strong>%2$s</strong>: <span class="pncp-tr__onoff">%3$s</span>%4$s · %5$s · %6$s%7$s%8$s</li>',
				$on ? ' is-on' : ' is-off',
				esc_html( self::source_name( $src ) ),
				esc_html( $on ? __( 'on', 'scrapelock' ) : __( 'off', 'scrapelock' ) ),
				'server' === $src && '' !== (string) $row['path'] ? ' <code>' . esc_html( (string) $row['path'] ) . '</code>' : '',
				/* translators: %s: date and time */
				(int) $row['last_ingest'] > 0 ? sprintf( esc_html__( 'newest request %s', 'scrapelock' ), self::when( (int) $row['last_ingest'] ) ) : esc_html__( 'no data yet', 'scrapelock' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- when() escapes.
				/* translators: %s: number of requests */
				esc_html( sprintf( __( '%s today', 'scrapelock' ), self::n( (int) $row['lines_today'] ) ) ),
				$src === $status['auto'] ? ' · <span class="pncp-badge">' . esc_html__( 'used by “Auto”', 'scrapelock' ) . '</span>' : '',
				'' !== $text ? '<br><span class="pncp-tr__err">' . esc_html( $text ) . '</span>' : ''
			);
		}
		echo '</ul>';
		if ( (int) $status['rollup']['rolled_at'] > 0 ) {
			echo '<p class="pncp-tr__note">';
			/* translators: %s: date and time */
			printf( esc_html__( 'Daily figures counted %s; they lag up to an hour.', 'scrapelock' ), self::when( (int) $status['rollup']['rolled_at'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- when() escapes.
			echo '</p>';
		}
	}

	/**
	 * Sources, the settings form, "Test this path" and "Delete collected traffic".
	 *
	 * @param array<string, mixed> $s      Settings.
	 * @param array<string, mixed> $status sources_status().
	 */
	private static function render_settings( $s, $status ) {
		$tr   = PNCP_Traffic::settings();
		$test = get_transient( PNCP_Traffic_Actions::TEST . get_current_user_id() );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only shows the result once.
		$tested = isset( $_GET['tr_msg'] ) && 'tested' === sanitize_key( wp_unslash( $_GET['tr_msg'] ) ) && is_array( $test ) && 2 === count( $test );
		?>
		<section class="pncp-card pncp-card--wide" id="pncp-tr-sources" aria-labelledby="pncp-tr-sources-title">
			<h2 id="pncp-tr-sources-title"><?php esc_html_e( 'Sources', 'scrapelock' ); ?></h2>
			<?php self::render_sources( $status ); ?>
		</section>
		<section class="pncp-card pncp-card--wide" id="pncp-tr-settings" aria-labelledby="pncp-tr-settings-title">
			<h2 id="pncp-tr-settings-title"><?php esc_html_e( 'Traffic settings', 'scrapelock' ); ?></h2>
			<?php PNCP_Admin::render_traffic_settings( $s ); ?>
		</section>
		<section class="pncp-card pncp-card--wide" id="pncp-tr-test" aria-labelledby="pncp-tr-test-title">
			<h2 id="pncp-tr-test-title"><?php esc_html_e( 'Test this path', 'scrapelock' ); ?></h2>
			<?php if ( ! PNCP_Traffic_Log::user_may_read() ) : ?>
				<p><?php esc_html_e( 'On a network only a network administrator can set and test the access log.', 'scrapelock' ); ?></p>
			<?php else : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( PNCP_Traffic_Actions::ACTION ); ?>">
				<input type="hidden" name="op" value="test_path">
				<?php echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( PNCP_Traffic_Actions::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup. ?>
				<p>
					<label for="pncp-tr-test-path"><?php esc_html_e( 'Access log path', 'scrapelock' ); ?></label><br>
					<input type="text" class="regular-text code" id="pncp-tr-test-path" name="path" maxlength="500" value="<?php echo esc_attr( $tested ? (string) $test[0] : $tr['log_path'] ); ?>" placeholder="/var/log/nginx/access.log" aria-describedby="pncp-tr-test-path-help">
					<button type="submit" class="button" id="pncp-tr-test-button"><?php esc_html_e( 'Test this path', 'scrapelock' ); ?></button>
				</p>
				<p class="description" id="pncp-tr-test-path-help"><?php esc_html_e( 'Reads the end of the file only; nothing is saved.', 'scrapelock' ); ?></p>
			</form>
				<?php
				if ( $tested ) {
					$r  = (array) $test[1];
					$ok = isset( $r['code'] ) && 'ok' === $r['code'];
					printf(
						'<div class="notice notice-%1$s inline pncp-tr__tested" role="status"><p>%2$s</p>',
						esc_attr( $ok ? 'success' : 'error' ),
						esc_html( PNCP_Traffic_Log::refusal_text( isset( $r['code'] ) ? (string) $r['code'] : '' ) )
					);
					if ( ! empty( $r['lines'] ) ) {
						/* translators: 1: lines read as requests, 2: lines read */
						echo '<p>' . esc_html( sprintf( __( '%1$s of %2$s lines read as requests.', 'scrapelock' ), self::n( (int) $r['parsed'] ), self::n( (int) $r['lines'] ) ) ) . '</p>';
					}
					if ( ! empty( $r['sample'] ) && is_array( $r['sample'] ) ) {
						$sample = $r['sample'];
						$parts  = array();
						foreach ( array( 'ip', 'method', 'status', 'path', 'ua' ) as $k ) {
							if ( isset( $sample[ $k ] ) && is_scalar( $sample[ $k ] ) && '' !== (string) $sample[ $k ] ) {
								$parts[] = (string) $sample[ $k ];
							}
						}
						echo '<p>' . esc_html__( 'Last request read:', 'scrapelock' ) . ' <code>' . esc_html( implode( ' ', $parts ) ) . '</code></p>';
					}
					echo '</div>';
				}
			endif;
			?>
		</section>
		<section class="pncp-card pncp-card--wide" id="pncp-tr-delete" aria-labelledby="pncp-tr-delete-title">
			<h2 id="pncp-tr-delete-title"><?php esc_html_e( 'Delete collected traffic', 'scrapelock' ); ?></h2>
			<?php if ( 'purge' === self::$st['confirm'] ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pncp-tr__confirm">
					<input type="hidden" name="action" value="<?php echo esc_attr( PNCP_Traffic_Actions::ACTION ); ?>">
					<input type="hidden" name="op" value="purge">
					<?php echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( PNCP_Traffic_Actions::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup. ?>
					<p><strong><?php esc_html_e( 'Every stored request and every daily figure will be deleted. This cannot be undone.', 'scrapelock' ); ?></strong></p>
					<p><label><input type="checkbox" name="confirm" value="1" required> <?php esc_html_e( 'Yes, delete all collected traffic', 'scrapelock' ); ?></label></p>
					<p>
						<button type="submit" class="button button-link-delete" id="pncp-tr-purge"><?php esc_html_e( 'Delete collected traffic', 'scrapelock' ); ?></button>
						<a class="button" href="<?php echo esc_url( self::url_for( array( 'tr_view' => 'settings' ) ) ); ?>"><?php esc_html_e( 'Cancel', 'scrapelock' ); ?></a>
					</p>
				</form>
			<?php else : ?>
				<p><a class="button button-link-delete" href="
				<?php
				echo esc_url(
					self::url_for(
						array(
							'tr_view'    => 'settings',
							'tr_confirm' => 'purge',
						)
					) . '#pncp-tr-delete'
				);
				?>
																"><?php esc_html_e( 'Delete collected traffic…', 'scrapelock' ); ?></a></p>
			<?php endif; ?>
		</section>
		<?php
	}

	/* ---------- Overview ---------- */

	/**
	 * Key figures, the chart, the statuses and the top 5 of each list.
	 */
	private static function view_overview() {
		$f  = self::filters( self::$st );
		$ov = PNCP_Traffic::overview( $f );
		self::note_clip( $ov );
		self::render_kpis( $ov );
		echo '<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-tr-chart-title"><h2 id="pncp-tr-chart-title">' . esc_html__( 'Requests over time', 'scrapelock' ) . '</h2>';
		self::chart( $ov );
		echo '</section>';
		$total = (int) $ov['total'];
		echo '<div class="pncp-tr__grid">';
		// Statuses.
		$codes = PNCP_Traffic::top( 'status', $f, 8 );
		self::note_clip( $codes );
		echo '<section class="pncp-card pncp-tr__box" aria-labelledby="pncp-tr-st-title"><h2 id="pncp-tr-st-title">' . esc_html__( 'Status codes', 'scrapelock' ) . '</h2>';
		if ( ! $total ) {
			self::empty_note();
		} else {
			echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-tr__table"><tbody>';
			foreach ( array(
				's2xx' => '2xx',
				's3xx' => '3xx',
				's4xx' => '4xx',
				's5xx' => '5xx',
			) as $key => $label ) {
				printf(
					'<tr><th scope="row">%1$s</th><td class="pncp-ar__col-bar"><span class="pncp-ar__meter" aria-hidden="true"><span style="width:%2$s%%"></span></span></td><td class="num">%3$s</td><td class="num">%4$s</td></tr>',
					self::status( $label ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in status().
					esc_attr( (string) round( 100 * (int) $ov[ $key ] / $total, 1 ) ),
					esc_html( self::n( (int) $ov[ $key ] ) ),
					esc_html( self::pct( (int) $ov[ $key ], $total ) )
				);
			}
			echo '</tbody></table></div>';
			if ( $codes['rows'] ) {
				echo '<p class="pncp-tr__codes">';
				foreach ( $codes['rows'] as $row ) {
					printf(
						'<a href="%1$s">%2$s</a> %3$s ',
						esc_url(
							self::url(
								array(
									'view'   => 'log',
									'status' => in_array( (string) $row['key'], array( '404' ), true ) ? '404' : substr( (string) $row['key'], 0, 1 ) . 'xx',
								)
							)
						),
						self::status( (string) $row['key'] ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in status().
						esc_html( self::n( (int) $row['hits'] ) )
					);
				}
				echo '</p>';
			}
		}
		echo '</section>';
		// Families.
		$fam = PNCP_Traffic::top( 'ua_family', $f, 5 );
		self::note_clip( $fam );
		self::top_box(
			'fam',
			__( 'Who visits', 'scrapelock' ),
			$fam,
			static function ( $row ) {
				return sprintf(
					'<a href="%1$s">%2$s</a>',
					esc_url(
						self::url(
							array(
								'view' => 'agents',
								'fam'  => (string) $row['key'],
							)
						)
					),
					self::badge_family( (string) $row['key'] )
				);
			},
			self::url( array( 'view' => 'agents' ) ),
			$total
		);
		$uas = PNCP_Traffic::top( 'ua', $f, 5 );
		self::note_clip( $uas );
		self::top_box(
			'ua',
			__( 'Top User-Agents', 'scrapelock' ),
			$uas,
			static function ( $row ) {
				return self::badge_family( (string) $row['family'] ) . ' ' . self::detail_link( 'ua', (string) $row['key'], self::ua_cell( (string) $row['key'], (string) $row['name'], true ) );
			},
			self::url( array( 'view' => 'agents' ) ),
			$total
		);
		foreach ( array(
			'404' => __( 'Not found (404)', 'scrapelock' ),
			'5xx' => __( 'Server errors (5xx)', 'scrapelock' ),
		) as $type => $title ) {
			$p = PNCP_Traffic::problems( (string) $type, $f, 5 );
			self::note_clip( $p );
			$rows = array();
			foreach ( $p['rows'] as $row ) {
				$rows[] = array(
					'key'  => $row['path'],
					'hits' => $row['hits'],
				);
			}
			self::top_box(
				'p' . $type,
				$title,
				array(
					'rows'       => $rows,
					'total_rows' => $p['total_rows'],
				),
				static function ( $row ) {
					return self::detail_link( 'path', (string) $row['key'], '<code>' . esc_html( self::show_path( (string) $row['key'] ) ) . '</code>' );
				},
				self::url(
					array(
						'view' => 'problems',
						'type' => (string) $type,
					)
				),
				0
			);
		}
		$countries = PNCP_Traffic::top( 'country', $f, 5 );
		self::note_clip( $countries );
		self::top_box(
			'country',
			__( 'Countries', 'scrapelock' ),
			$countries,
			static function ( $row ) {
				return '' === (string) $row['key'] ? esc_html__( 'Unknown', 'scrapelock' ) : sprintf(
					'<a class="pncp-ar__country" href="%1$s">%2$s</a>',
					esc_url(
						self::url(
							array(
								'view'    => 'visitors',
								'country' => (string) $row['key'],
							)
						)
					),
					esc_html( (string) $row['key'] )
				);
			},
			self::url( array( 'view' => 'visitors' ) ),
			$total
		);
		echo '</div>';
	}

	/**
	 * The key figures of a summary.
	 *
	 * @param array<string, mixed> $ov overview().
	 */
	private static function render_kpis( $ov ) {
		$total  = (int) $ov['total'];
		$cached = (int) $ov['cache_hits'] + (int) $ov['cache_misses'];
		echo '<ul class="pncp-ar__kpis pncp-tr__kpis">';
		$tile = static function ( $value, $label, $tone = '', $hint = '' ) {
			printf(
				'<li class="pncp-ar__kpi%1$s"><span class="pncp-ar__kpi-value">%2$s</span> <span class="pncp-ar__kpi-label">%3$s</span>%4$s</li>',
				'' !== $tone ? ' pncp-ar__kpi--' . esc_attr( $tone ) : '',
				esc_html( $value ),
				esc_html( $label ),
				'' !== $hint ? ' <span class="pncp-ar__kpi-hint">' . esc_html( $hint ) . '</span>' : ''
			);
		};
		$tile( self::n( $total ), __( 'requests', 'scrapelock' ), '', self::source_name( (string) $ov['src_used'] ) );
		$tile( ( ! empty( $ov['ips_approx'] ) ? '≈ ' : '' ) . self::n( (int) $ov['ips'] ), __( 'unique IPs', 'scrapelock' ), '', ! empty( $ov['ips_approx'] ) ? __( 'added up per day', 'scrapelock' ) : '' );
		$tile( self::bytes( (int) $ov['bytes'] ), __( 'bandwidth', 'scrapelock' ) );
		$tile( self::pct( (int) $ov['s4xx'], $total ), __( '4xx errors', 'scrapelock' ), $total && (int) $ov['s4xx'] / $total > 0.1 ? 'bad' : '', self::n( (int) $ov['s4xx'] ) );
		$tile( self::pct( (int) $ov['s5xx'], $total ), __( '5xx errors', 'scrapelock' ), (int) $ov['s5xx'] > 0 ? 'bad' : 'good', self::n( (int) $ov['s5xx'] ) );
		if ( $cached > 0 ) {
			$tile( self::pct( (int) $ov['cache_hits'], $cached ), __( 'served from cache', 'scrapelock' ), (int) $ov['cache_hits'] / $cached >= 0.5 ? 'good' : '', self::n( (int) $ov['cache_hits'] ) );
		}
		echo '</ul>';
	}

	/**
	 * A small top-5 card.
	 *
	 * @param string               $id     Id part.
	 * @param string               $title  Title.
	 * @param array<string, mixed> $result Result with rows (key, hits) and total_rows.
	 * @param callable             $label  Row => label HTML (escaped).
	 * @param string               $more   Address of the full view.
	 * @param int                  $total  Requests in all (for the share; 0 = none).
	 */
	private static function top_box( $id, $title, $result, $label, $more, $total ) {
		printf( '<section class="pncp-card pncp-tr__box" aria-labelledby="pncp-tr-top-%1$s"><h2 id="pncp-tr-top-%1$s">%2$s</h2>', esc_attr( $id ), esc_html( $title ) );
		if ( empty( $result['rows'] ) ) {
			self::empty_note( __( 'Nothing in this period.', 'scrapelock' ) );
		} else {
			echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-tr__table pncp-tr__top"><tbody>';
			foreach ( $result['rows'] as $row ) {
				printf(
					'<tr><td class="pncp-tr__label">%1$s</td><td class="num">%2$s</td>%3$s</tr>',
					call_user_func( $label, $row ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- The callbacks escape.
					esc_html( self::n( (int) $row['hits'] ) ),
					$total > 0 ? '<td class="num pncp-ar__share">' . esc_html( self::pct( (int) $row['hits'], $total ) ) . '</td>' : ''
				);
			}
			echo '</tbody></table></div>';
		}
		$count = (int) $result['total_rows'];
		/* translators: %s: number of rows */
		printf( '<p class="pncp-tr__more"><a href="%1$s">%2$s</a></p></section>', esc_url( $more ), esc_html( $count >= 0 ? sprintf( __( 'See all (%s)', 'scrapelock' ), self::n( $count ) ) : __( 'See all', 'scrapelock' ) ) );
	}

	/**
	 * The requests per hour or day as bars (errors in another colour), with the numbers as a table.
	 *
	 * @param array<string, mixed> $ov overview().
	 */
	private static function chart( $ov ) {
		$series = (array) $ov['series'];
		$n      = max( 1, count( $series ) );
		$max    = 0;
		foreach ( $series as $b ) {
			$max = max( $max, (int) $b['hits'] );
		}
		$top  = PNCP_Attack_Report::nice_max( $max );
		$w    = 1000;
		$h    = 200;
		$bw   = $w / $n;
		$gap  = $n > 60 ? 0.15 : 0.25;
		$fmt  = 'hour' === $ov['step'] ? 'j M H:i' : 'j M';
		$peak = null;
		foreach ( $series as $b ) {
			if ( null === $peak || (int) $b['hits'] > (int) $peak['hits'] ) {
				$peak = $b;
			}
		}
		$desc = sprintf(
			/* translators: 1: number of requests, 2: most requests in one hour or day, 3: that hour or day */
			__( '%1$s requests; the most, %2$s, at %3$s.', 'scrapelock' ),
			self::n( (int) $ov['total'] ),
			self::n( $max ),
			$max > 0 && null !== $peak ? wp_date( $fmt, (int) $peak['t'] ) : '–'
		);
		$title = 'hour' === $ov['step'] ? __( 'Requests per hour', 'scrapelock' ) : __( 'Requests per day', 'scrapelock' );
		echo '<figure class="pncp-ar__chart pncp-tr__chart">';
		printf( '<figcaption class="pncp-ar__chart-title">%1$s <span class="pncp-ar__chart-desc">%2$s</span></figcaption>', esc_html( $title ), esc_html( $desc ) );
		if ( ! (int) $ov['total'] ) {
			self::empty_note();
			echo '</figure>';
			return;
		}
		echo '<div class="pncp-ar__plot"><div class="pncp-ar__yaxis" aria-hidden="true">';
		printf( '<span>%1$s</span><span>%2$s</span><span>0</span>', esc_html( self::n( $top ) ), esc_html( self::n( $top / 2 ) ) );
		echo '</div><div class="pncp-ar__canvas">';
		printf( '<svg viewBox="0 0 %1$d %2$d" preserveAspectRatio="none" role="img" aria-label="%3$s" focusable="false">', (int) $w, (int) $h, esc_attr( $title . '. ' . $desc ) );
		printf( '<line class="pncp-ar__grid" x1="0" y1="0.5" x2="%1$d" y2="0.5" vector-effect="non-scaling-stroke"></line><line class="pncp-ar__grid" x1="0" y1="%2$d" x2="%1$d" y2="%2$d" vector-effect="non-scaling-stroke"></line><line class="pncp-ar__axis" x1="0" y1="%3$s" x2="%1$d" y2="%3$s" vector-effect="non-scaling-stroke"></line>', (int) $w, (int) ( $h / 2 ), esc_attr( (string) ( $h - 0.5 ) ) );
		$i = 0;
		foreach ( $series as $b ) {
			$hits = (int) $b['hits'];
			$errs = min( $hits, (int) $b['s4xx'] + (int) $b['s5xx'] );
			if ( $hits > 0 ) {
				$bh  = max( 2, round( $h * $hits / $top, 2 ) );
				$eh  = $errs > 0 ? max( 1, round( $bh * $errs / $hits, 2 ) ) : 0;
				$x   = round( $i * $bw + $bw * $gap / 2, 2 );
				$bw2 = max( 0.5, round( $bw * ( 1 - $gap ), 2 ) );
				printf(
					'<g><title>%1$s</title><rect class="pncp-ar__bar" x="%2$s" y="%3$s" width="%4$s" height="%5$s"></rect>%6$s</g>',
					esc_html(
						sprintf(
							/* translators: 1: hour or day, 2: requests, 3: 4xx, 4: 5xx */
							__( '%1$s: %2$s requests, %3$s 4xx, %4$s 5xx', 'scrapelock' ),
							wp_date( $fmt, (int) $b['t'] ),
							self::n( $hits ),
							self::n( (int) $b['s4xx'] ),
							self::n( (int) $b['s5xx'] )
						)
					),
					esc_attr( (string) $x ),
					esc_attr( (string) round( $h - $bh, 2 ) ),
					esc_attr( (string) $bw2 ),
					esc_attr( (string) $bh ),
					$eh > 0 ? '<rect class="pncp-tr__bar-err" x="' . esc_attr( (string) $x ) . '" y="' . esc_attr( (string) round( $h - $eh, 2 ) ) . '" width="' . esc_attr( (string) $bw2 ) . '" height="' . esc_attr( (string) $eh ) . '"></rect>' : ''
				);
			}
			++$i;
		}
		echo '</svg><div class="pncp-ar__xaxis" aria-hidden="true">';
		$first = reset( $series );
		$last  = end( $series );
		printf( '<span>%1$s</span><span>%2$s</span>', esc_html( wp_date( $fmt, (int) $first['t'] ) ), esc_html( wp_date( $fmt, (int) $last['t'] ) ) );
		echo '</div></div></div>';
		echo '<p class="pncp-tr__legend" aria-hidden="true"><span class="pncp-tr__key"></span> ' . esc_html__( 'requests', 'scrapelock' ) . ' <span class="pncp-tr__key pncp-tr__key--err"></span> ' . esc_html__( '4xx and 5xx', 'scrapelock' ) . '</p>';
		echo '<details class="pncp-ar__data"><summary>' . esc_html__( 'Show the numbers', 'scrapelock' ) . '</summary><div class="pncp-table-wrap"><table class="widefat striped"><thead><tr>';
		printf( '<th scope="col">%1$s</th><th scope="col" class="num">%2$s</th><th scope="col" class="num">4xx</th><th scope="col" class="num">5xx</th></tr></thead><tbody>', esc_html( 'hour' === $ov['step'] ? __( 'Hour', 'scrapelock' ) : __( 'Day', 'scrapelock' ) ), esc_html__( 'Requests', 'scrapelock' ) );
		foreach ( $series as $b ) {
			if ( 'hour' === $ov['step'] && ! (int) $b['hits'] ) {
				continue;
			}
			printf( '<tr><td>%1$s</td><td class="num">%2$s</td><td class="num">%3$s</td><td class="num">%4$s</td></tr>', esc_html( wp_date( $fmt, (int) $b['t'] ) ), esc_html( self::n( (int) $b['hits'] ) ), esc_html( self::n( (int) $b['s4xx'] ) ), esc_html( self::n( (int) $b['s5xx'] ) ) );
		}
		echo '</tbody></table></div></details></figure>';
	}

	/* ---------- User-Agents ---------- */

	/**
	 * The User-Agents, with the families as chips.
	 */
	private static function view_agents() {
		$st  = self::$st;
		$f   = self::filters( $st );
		$all = $f;
		unset( $all['ua_family'] );
		$fams = PNCP_Traffic::top( 'ua_family', $all, 20 );
		$uas  = PNCP_Traffic::top( 'ua', $f, self::PER_PAGE, self::offset(), $st['order'] );
		self::note_clip( $fams );
		self::note_clip( $uas );
		echo '<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-tr-agents-title"><h2 id="pncp-tr-agents-title">' . esc_html__( 'User-Agents', 'scrapelock' ) . '</h2>';
		echo PNCP_Admin_Fields::para( __( 'Which browsers, bots and scripts asked for pages. Open one to block or allow it.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
		if ( $fams['rows'] ) {
			$sum = 0;
			foreach ( $fams['rows'] as $row ) {
				$sum += (int) $row['hits'];
			}
			echo '<ul class="pncp-tr__fams" aria-label="' . esc_attr__( 'Families', 'scrapelock' ) . '">';
			printf(
				'<li><a class="pncp-ar__period%1$s" href="%2$s"%3$s>%4$s <span class="pncp-tr__count">%5$s</span></a></li>',
				'' === $st['fam'] ? ' is-current' : '',
				esc_url(
					self::url(
						array(
							'fam'   => '',
							'paged' => '',
						)
					)
				),
				'' === $st['fam'] ? ' aria-current="true"' : '',
				esc_html__( 'All', 'scrapelock' ),
				esc_html( self::n( $sum ) )
			);
			foreach ( $fams['rows'] as $row ) {
				$key = (string) $row['key'];
				printf(
					'<li><a class="pncp-ar__period%1$s" href="%2$s"%3$s>%4$s <span class="pncp-tr__count">%5$s</span></a></li>',
					$st['fam'] === $key ? ' is-current' : '',
					esc_url(
						self::url(
							array(
								'fam'   => $key,
								'paged' => '',
							)
						)
					),
					$st['fam'] === $key ? ' aria-current="true"' : '',
					esc_html( (string) $row['name'] ),
					esc_html( self::n( (int) $row['hits'] ) )
				);
			}
			echo '</ul>';
		}
		if ( ! $uas['rows'] ) {
			self::empty_note();
		} else {
			echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-tr__table pncp-tr__agents"><thead><tr>';
			echo '<th scope="col">' . esc_html__( 'Family', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'User-Agent', 'scrapelock' ) . '</th>';
			self::th_sort( __( 'Requests', 'scrapelock' ), 'hits' );
			self::th_sort( __( 'IPs', 'scrapelock' ), 'ips' );
			self::th_sort( '4xx', 's4xx' );
			self::th_sort( '5xx', 's5xx' );
			self::th_sort( __( 'Last seen', 'scrapelock' ), 'last', false );
			echo '</tr></thead><tbody>';
			foreach ( $uas['rows'] as $row ) {
				printf(
					'<tr><td>%1$s</td><td class="pncp-ar__ua">%2$s</td><td class="num">%3$s</td><td class="num">%4$s</td><td class="num">%5$s</td><td class="num">%6$s</td><td class="pncp-ar__nowrap">%7$s</td></tr>',
					self::badge_family( (string) $row['family'] ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in family().
					self::detail_link( 'ua', (string) $row['key'], self::ua_cell( (string) $row['key'], (string) $row['name'] ) ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the helpers.
					esc_html( self::n( (int) $row['hits'] ) ),
					esc_html( ( ! empty( $uas['ips_approx'] ) ? '≈ ' : '' ) . self::n( (int) $row['ips'] ) ),
					esc_html( self::n( (int) $row['s4xx'] ) ),
					esc_html( self::n( (int) $row['s5xx'] ) ),
					self::when( (int) $row['last'] ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in when().
				);
			}
			echo '</tbody></table></div>';
			self::pager( (int) $uas['total_rows'], ! empty( $uas['has_more'] ) );
		}
		echo '</section>';
	}

	/**
	 * What ScrapeLock does with a User-Agent now (read only).
	 *
	 * @param string               $ua     User-Agent.
	 * @param string               $family Family as stored.
	 * @param array<string, mixed> $s      Settings.
	 * @return array<int, array{0:string, 1:string}> Tone (good | bad | warn | ''), sentence.
	 */
	public static function ua_verdict( $ua, $family, $s ) {
		$out = array();
		if ( empty( $s['enabled'] ) ) {
			$out[] = array( 'warn', __( 'Protection is off: nothing is blocked now.', 'scrapelock' ) );
		} elseif ( PNCP_Options::monitoring( $s ) ) {
			$out[] = array( 'warn', __( 'Monitor only: what would be blocked is only logged.', 'scrapelock' ) );
		}
		$bot = PNCP_Plugin_Bots::match( $ua, '' );
		if ( null !== $bot ) {
			$reg = PNCP_Plugin_Bots::registry();
			/* translators: %s: plugin name, e.g. WP Rocket */
			$out[] = array( 'good', sprintf( __( 'Service bot of %s: allowed while that plugin is active.', 'scrapelock' ), isset( $reg[ $bot['id'] ] ) ? $reg[ $bot['id'] ]['name'] : $bot['id'] ) );
		}
		if ( '' !== trim( $ua ) && PNCP_Bots::allow_list_match( $ua, '', array( 'allow_list' => (string) $s['allow_list'] ) ) ) {
			$out[] = array( 'good', __( 'Always allowed (“Bots and limits” → “Always allowed”).', 'scrapelock' ) );
		}
		$entry = '' === trim( $ua ) ? null : PNCP_Bot_Match::entry( $ua, $s );
		if ( null !== $entry ) {
			$out[] = empty( $s['block_bots'] )
				/* translators: %s: bot list entry */
				? array( 'warn', sprintf( __( 'Matches “%s” of the bot list, but “Block bots” is off.', 'scrapelock' ), ltrim( $entry['token'], '=' ) ) )
				/* translators: %s: bot list entry */
				: array( 'bad', sprintf( __( 'Blocked by the bot list: matches “%s”.', 'scrapelock' ), ltrim( $entry['token'], '=' ) ) );
		}
		if ( 'verified_bot' === $family ) {
			$out[] = array( 'good', __( 'Search engine: let in from its official addresses.', 'scrapelock' ) );
		} elseif ( 'fake_bot' === $family ) {
			$out[] = array( 'bad', __( 'Claims to be a search engine or AI bot from other addresses: refused while protection is on.', 'scrapelock' ) );
		} elseif ( '' === trim( $ua ) ) {
			$out[] = array( '', empty( $s['block_empty_ua'] ) ? __( 'No User-Agent: allowed, because “Block requests without a User-Agent” is off.', 'scrapelock' ) : __( 'No User-Agent: refused by “Block requests without a User-Agent”.', 'scrapelock' ) );
		} elseif ( null === $entry && null === $bot ) {
			$out[] = array( '', __( 'On no list: allowed, within the page limits.', 'scrapelock' ) );
		}
		return $out;
	}

	/**
	 * One User-Agent.
	 *
	 * @param array<string, mixed> $s Settings.
	 */
	private static function view_ua( $s ) {
		$st = self::$st;
		$ua = (string) $st['key'];
		$f  = self::filters( $st );
		$d  = PNCP_Traffic::detail( 'ua', $ua, $f );
		self::note_clip( $d );
		$family = isset( $d['family'] ) ? (string) $d['family'] : 'other';
		echo '<p class="pncp-tr__back"><a href="' . esc_url( self::url( array( 'view' => 'agents' ) ) ) . '">' . esc_html__( '← All User-Agents', 'scrapelock' ) . '</a></p>';
		echo '<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-tr-ua-title">';
		printf( '<h2 id="pncp-tr-ua-title">%1$s %2$s</h2>', self::badge_family( $family ), esc_html( isset( $d['name'] ) && '' !== $d['name'] ? (string) $d['name'] : __( 'User-Agent', 'scrapelock' ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in family().
		echo '<p><code class="pncp-tr__full">' . esc_html( '' !== $ua ? $ua : __( '(no User-Agent)', 'scrapelock' ) ) . '</code></p>';
		self::render_kpis( $d['summary'] );
		echo '<h3>' . esc_html__( 'What ScrapeLock does with it', 'scrapelock' ) . '</h3><ul class="pncp-tr__verdict">';
		foreach ( self::ua_verdict( $ua, $family, $s ) as $line ) {
			printf( '<li class="pncp-tr__v%1$s">%2$s</li>', '' !== $line[0] ? ' pncp-tr__v--' . esc_attr( $line[0] ) : '', esc_html( $line[1] ) );
		}
		echo '</ul>';
		printf(
			'<p><a href="%1$s">%2$s</a> · <a href="%3$s">%4$s</a></p>',
			esc_url(
				self::url(
					array(
						'view' => 'log',
						'ua'   => $ua,
						'key'  => '',
					)
				)
			),
			esc_html__( 'Its requests', 'scrapelock' ),
			esc_url( PNCP_Status::settings_url( array( 'tab' => 'log' ) ) . '#pncp-tester' ),
			esc_html__( 'Check a request', 'scrapelock' )
		);
		self::render_ua_actions( $ua, $family, $st['act'] );
		echo '</section>';
		echo '<div class="pncp-tr__grid">';
		self::detail_table( __( 'Paths', 'scrapelock' ), $d['paths'], 'path' );
		self::detail_table( __( 'Status codes', 'scrapelock' ), $d['statuses'], 'status' );
		self::detail_table( __( 'IPs', 'scrapelock' ), $d['ips'], 'ip' );
		self::detail_table( __( 'Countries', 'scrapelock' ), $d['countries'], 'country' );
		self::detail_table( __( 'Referrers', 'scrapelock' ), $d['referers'], 'referer' );
		echo '</div>';
	}

	/**
	 * "Block this User-Agent" and "Always allow", or their confirmation step.
	 *
	 * @param string $ua     User-Agent.
	 * @param string $family Family as stored.
	 * @param string $act    block | allow | '' (the buttons).
	 */
	private static function render_ua_actions( $ua, $family, $act ) {
		$block = PNCP_Traffic_Actions::block_check( $ua );
		$allow = PNCP_Traffic_Actions::allow_check( $ua );
		echo '<div class="pncp-tr__actions" id="pncp-tr-actions">';
		if ( 'fake_bot' === $family && ! empty( PNCP_Options::get()['enabled'] ) ) {
			echo '<p class="pncp-tr__note">' . esc_html__( 'Fake search engines are already refused while protection is on; nothing to add.', 'scrapelock' ) . '</p>';
		}
		if ( '' === $act ) {
			$buttons = '';
			if ( '' === $block['refusal'] ) {
				$buttons .= sprintf( '<a class="button" href="%1$s#pncp-tr-actions">%2$s</a> ', esc_url( self::url( array( 'act' => 'block' ) ) ), esc_html__( 'Block this User-Agent…', 'scrapelock' ) );
			}
			if ( '' === $allow['refusal'] ) {
				$buttons .= sprintf( '<a class="button" href="%1$s#pncp-tr-actions">%2$s</a>', esc_url( self::url( array( 'act' => 'allow' ) ) ), esc_html__( 'Always allow…', 'scrapelock' ) );
			}
			if ( '' !== $buttons ) {
				echo '<p>' . $buttons . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
			}
			$why = array();
			if ( '' !== $block['refusal'] && 'fake_bot' !== $family ) {
				$n     = PNCP_Traffic_Actions::notice( 'block_' . $block['refusal'] );
				$why[] = null !== $n ? preg_replace( '/^Nothing changed: /', '', $n[1] ) : '';
			}
			foreach ( array_filter( $why ) as $line ) {
				/* translators: %s: reason */
				echo '<p class="pncp-tr__note">' . esc_html( sprintf( __( 'No “Block” button: %s', 'scrapelock' ), $line ) ) . '</p>';
			}
			echo '</div>';
			return;
		}
		$check = 'block' === $act ? $block : $allow;
		if ( '' !== $check['refusal'] ) {
			$n = PNCP_Traffic_Actions::notice( $act . '_' . $check['refusal'] );
			printf( '<div class="notice notice-error inline"><p>%s</p></div></div>', esc_html( null !== $n ? $n[1] : __( 'The action was not completed: reload the page and try again.', 'scrapelock' ) ) );
			return;
		}
		$list = 'block' === $act ? __( 'Bot list', 'scrapelock' ) : __( 'Always allowed User-Agents', 'scrapelock' );
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="pncp-tr__confirm">';
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( PNCP_Traffic_Actions::ACTION ) );
		printf( '<input type="hidden" name="op" value="%s">', esc_attr( $act ) );
		printf( '<input type="hidden" name="ua" value="%s">', esc_attr( $ua ) );
		printf( '<input type="hidden" name="pattern" value="%s">', esc_attr( $check['pattern'] ) );
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( PNCP_Traffic_Actions::ACTION, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
		printf( '<h3>%s</h3>', esc_html( 'block' === $act ? __( 'Block this User-Agent', 'scrapelock' ) : __( 'Always allow this User-Agent', 'scrapelock' ) ) );
		/* translators: %s: name of a list */
		printf( '<p>%1$s <code class="pncp-tr__line">%2$s</code></p>', esc_html( sprintf( __( 'This line is added to “%s”:', 'scrapelock' ), $list ) ), esc_html( $check['pattern'] ) );
		if ( 'block' === $act ) {
			echo '<p>' . esc_html( '=' === $check['pattern'][0] ? __( 'It matches exactly this User-Agent, nothing else.', 'scrapelock' ) : __( 'It matches every User-Agent that contains this name.', 'scrapelock' ) ) . '</p>';
			$others = self::also_matched( $check['pattern'], $ua );
			if ( $others ) {
				/* translators: %s: number of User-Agents */
				echo '<p class="pncp-ar__warn">' . esc_html( sprintf( _n( 'It would also block %s other User-Agent seen in this period:', 'It would also block %s other User-Agents seen in this period:', count( $others ), 'scrapelock' ), self::n( count( $others ) ) ) ) . '</p><ul class="pncp-tr__others">';
				foreach ( array_slice( $others, 0, 5 ) as $other ) {
					echo '<li><code>' . esc_html( $other ) . '</code></li>';
				}
				echo '</ul>';
			}
			if ( '' !== $block['service'] ) {
				/* translators: %s: plugin name */
				echo '<p class="pncp-ar__warn">' . esc_html( sprintf( __( 'This is a service bot of %s: it stays allowed while that plugin is active.', 'scrapelock' ), $block['service'] ) ) . '</p>';
			}
			if ( 'crawler' === $block['extra'] ) {
				echo '<p class="pncp-ar__warn">' . esc_html__( 'This is a search engine: blocking it removes the site from its results.', 'scrapelock' ) . '</p>';
				echo '<p><label><input type="checkbox" name="confirm_extra" value="1" required> ' . esc_html__( 'Yes, block this search engine', 'scrapelock' ) . '</label></p>';
			} elseif ( 'browser' === $block['extra'] ) {
				echo '<p class="pncp-ar__warn">' . esc_html__( 'This is an ordinary browser: everyone using this exact version is refused.', 'scrapelock' ) . '</p>';
				echo '<p><label><input type="checkbox" name="confirm_extra" value="1" required> ' . esc_html__( 'Yes, block this browser version', 'scrapelock' ) . '</label></p>';
			}
		} else {
			echo '<p>' . esc_html__( 'It passes the bot list, “Browsers only” and the headless check; the page limits still apply.', 'scrapelock' ) . '</p>';
			if ( '' !== $allow['blocked'] ) {
				/* translators: %s: bot list entry */
				echo '<p>' . esc_html( sprintf( __( 'Now blocked by the bot list entry “%s”.', 'scrapelock' ), ltrim( $allow['blocked'], '=' ) ) ) . '</p>';
			}
		}
		echo '<p class="pncp-tr__note">' . esc_html__( 'The settings are saved under “Earlier versions” first, so you can undo it.', 'scrapelock' ) . '</p>';
		echo '<p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'Yes, add this line', 'scrapelock' ) . '</label></p>';
		printf(
			'<p><button type="submit" class="button button-primary" id="pncp-tr-%1$s-confirm">%2$s</button> <a class="button" href="%3$s">%4$s</a></p>',
			esc_attr( $act ),
			esc_html( 'block' === $act ? __( 'Add to the bot list', 'scrapelock' ) : __( 'Add to the allowed User-Agents', 'scrapelock' ) ),
			esc_url( self::url( array( 'act' => '' ) ) ),
			esc_html__( 'Cancel', 'scrapelock' )
		);
		echo '</form></div>';
	}

	/**
	 * The other User-Agents of the period that a bot list entry would also match.
	 *
	 * @param string $pattern Entry.
	 * @param string $ua      The User-Agent itself.
	 * @return string[]
	 */
	private static function also_matched( $pattern, $ua ) {
		$f = self::filters( self::$st );
		unset( $f['ua'], $f['ua_family'] );
		$out = array();
		foreach ( PNCP_Traffic::top( 'ua', $f, 500 )['rows'] as $row ) {
			$key = (string) $row['key'];
			if ( 0 !== strcasecmp( $key, $ua ) && PNCP_Bots::ua_in_list( $key, array( $pattern ) ) ) {
				$out[] = $key;
			}
		}
		return $out;
	}

	/**
	 * A breakdown of a detail (top() result, 10 rows).
	 *
	 * @param string               $title  Title.
	 * @param array<string, mixed> $result Result.
	 * @param string               $dim    Dimension.
	 */
	private static function detail_table( $title, $result, $dim ) {
		self::note_clip( $result );
		printf( '<section class="pncp-card pncp-tr__box"><h2>%s</h2>', esc_html( $title ) );
		if ( empty( $result['rows'] ) ) {
			self::empty_note( __( 'Nothing in this period.', 'scrapelock' ) );
			echo '</section>';
			return;
		}
		echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-tr__table"><tbody>';
		foreach ( $result['rows'] as $row ) {
			$key = (string) $row['key'];
			switch ( $dim ) {
				case 'path':
					$label = self::detail_link( 'path', $key, '<code>' . esc_html( self::show_path( $key ) ) . '</code>' );
					break;
				case 'ua':
					$label = self::badge_family( isset( $row['family'] ) ? (string) $row['family'] : 'other' ) . ' ' . self::detail_link( 'ua', $key, self::ua_cell( $key, isset( $row['name'] ) ? (string) $row['name'] : '', true ) );
					break;
				case 'ip':
					$label = self::detail_link( 'ip', $key, '<code>' . esc_html( $key ) . '</code>' );
					break;
				case 'status':
					$label = self::status( $key );
					break;
				case 'referer':
					$label = '' === $key ? '<span class="pncp-ar__muted">' . esc_html__( '(no referrer)', 'scrapelock' ) . '</span>' : '<code class="pncp-tr__ref">' . esc_html( $key ) . '</code>' . ( PNCP_Traffic_Query::internal( $key ) ? ' <span class="pncp-badge">' . esc_html__( 'your site', 'scrapelock' ) . '</span>' : '' );
					break;
				default:
					$label = '' === $key ? esc_html__( 'Unknown', 'scrapelock' ) : '<span class="pncp-ar__country">' . esc_html( $key ) . '</span>';
			}
			printf( '<tr><td class="pncp-tr__label">%1$s</td><td class="num">%2$s</td></tr>', $label, esc_html( self::n( (int) $row['hits'] ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
		}
		echo '</tbody></table></div></section>';
	}

	/* ---------- Problems ---------- */

	/**
	 * The Rank Math "Redirections" screen with the source filled in, or '' when Rank Math's redirections are not
	 * there. Only a link: nothing of Rank Math is written here.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function redirect_url( $path ) {
		$active = class_exists( 'RankMath', false ) || ( function_exists( 'is_plugin_active' ) && is_plugin_active( 'seo-by-rank-math/rank-math.php' ) );
		if ( ! $active ) {
			return '';
		}
		$module = array( 'RankMath\\Helper', 'is_module_active' );
		if ( is_callable( $module ) && ! call_user_func( $module, 'redirections' ) ) {
			return '';
		}
		return add_query_arg(
			array(
				'page' => 'rank-math-redirections',
				'url'  => rawurlencode( ltrim( (string) $path, '/' ) ),
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * "Create redirect": the Rank Math link, or the path to copy.
	 *
	 * @param string $path Path.
	 * @return string HTML.
	 */
	private static function redirect_cell( $path ) {
		$url = self::redirect_url( $path );
		if ( '' !== $url ) {
			return sprintf( '<a class="button button-small" href="%1$s">%2$s</a>', esc_url( $url ), esc_html__( 'Create redirect', 'scrapelock' ) );
		}
		$id = 'pncp-tr-copy-' . substr( md5( $path ), 0, 10 );
		return sprintf(
			'<details class="pncp-tr__redirect"><summary>%1$s</summary><code id="%2$s">%3$s</code> <button type="button" class="button button-small pncp-copy" data-target="%2$s">%4$s</button></details>',
			esc_html__( 'Redirect', 'scrapelock' ),
			esc_attr( $id ),
			esc_html( $path ),
			esc_html__( 'Copy', 'scrapelock' )
		);
	}

	/**
	 * The problem URLs, by kind.
	 */
	private static function view_problems() {
		$st    = self::$st;
		$f     = self::filters( $st );
		$types = array(
			'404'      => __( 'Not found (404)', 'scrapelock' ),
			'5xx'      => __( 'Server errors (5xx)', 'scrapelock' ),
			'3xx'      => __( 'Redirects (3xx)', 'scrapelock' ),
			'uncached' => __( 'Not cached', 'scrapelock' ),
			'large'    => __( 'Largest', 'scrapelock' ),
			'slow'     => __( 'Slowest', 'scrapelock' ),
		);
		$type  = $st['type'];
		$p     = PNCP_Traffic::problems( $type, $f, self::PER_PAGE, self::offset() );
		self::note_clip( $p );
		echo '<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-tr-problems-title"><h2 id="pncp-tr-problems-title">' . esc_html__( 'Problem URLs', 'scrapelock' ) . '</h2>';
		echo '<nav class="pncp-ar__periods pncp-tr__types" aria-label="' . esc_attr__( 'Kind of problem', 'scrapelock' ) . '">';
		foreach ( $types as $key => $label ) {
			$key = (string) $key;
			if ( $key === $type ) {
				printf( '<span class="pncp-ar__period is-current" aria-current="true">%s</span>', esc_html( $label ) );
			} else {
				printf(
					'<a class="pncp-ar__period" href="%1$s">%2$s</a>',
					esc_url(
						self::url(
							array(
								'type'  => $key,
								'paged' => '',
							)
						)
					),
					esc_html( $label )
				);
			}
		}
		echo '</nav>';
		$intro = array(
			'404'      => __( 'Fix broken links on your site first; redirect old addresses that still get visits.', 'scrapelock' ),
			'5xx'      => __( 'Pages that failed on the server: check the PHP error log for these addresses.', 'scrapelock' ),
			'3xx'      => __( 'Addresses that send visitors elsewhere; update your own links that point to them.', 'scrapelock' ),
			'uncached' => __( 'Pages the CDN fetched from the server, most first.', 'scrapelock' ),
			'large'    => __( 'Addresses that used the most bandwidth.', 'scrapelock' ),
			'slow'     => __( 'Slowest pages on average.', 'scrapelock' ),
		);
		echo PNCP_Admin_Fields::para( $intro[ $type ] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
		if ( empty( $p['available'] ) ) {
			self::empty_note( 'slow' === $type ? __( 'This source records no response times: use the WordPress source or an access log with $request_time.', 'scrapelock' ) : __( 'This source has no cache status: only the Bunny CDN logs have it.', 'scrapelock' ) );
			echo '</section>';
			return;
		}
		$rows   = (array) $p['rows'];
		$hidden = 0;
		if ( in_array( $type, array( '404', '5xx', '3xx' ), true ) && ! $st['scan'] ) {
			$keep = array();
			foreach ( $rows as $row ) {
				if ( PNCP_Log::is_probe_path( (string) $row['path'] ) ) {
					++$hidden;
				} else {
					$keep[] = $row;
				}
			}
			$rows = $keep;
		}
		if ( '404' === $type && $rows ) {
			$broken = 0;
			foreach ( $rows as $row ) {
				foreach ( $row['top_referers'] as $ref ) {
					if ( $ref['internal'] ) {
						++$broken;
						break;
					}
				}
			}
			if ( $broken ) {
				/* translators: %s: number of addresses */
				echo '<p class="pncp-ar__warn">' . esc_html( sprintf( _n( '%s address is linked from your own site: fix those links first.', '%s addresses are linked from your own site: fix those links first.', $broken, 'scrapelock' ), self::n( $broken ) ) ) . '</p>';
			}
		}
		if ( $hidden ) {
			/* translators: %s: number of addresses */
			printf( '<p class="pncp-tr__note">%1$s <a href="%2$s">%3$s</a></p>', esc_html( sprintf( _n( '%s scanner address hidden on this page.', '%s scanner addresses hidden on this page.', $hidden, 'scrapelock' ), self::n( $hidden ) ) ), esc_url( self::url( array( 'scan' => '1' ) ) ), esc_html__( 'Show scanner noise', 'scrapelock' ) );
		} elseif ( $st['scan'] ) {
			printf( '<p class="pncp-tr__note"><a href="%1$s">%2$s</a></p>', esc_url( self::url( array( 'scan' => '' ) ) ), esc_html__( 'Hide scanner noise', 'scrapelock' ) );
		}
		if ( ! $rows ) {
			self::empty_note();
			self::pager( (int) $p['total_rows'], ! empty( $p['has_more'] ) );
			echo '</section>';
			return;
		}
		echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-tr__table pncp-tr__problems pncp-tr__problems--' . esc_attr( $type ) . '"><thead><tr>';
		echo '<th scope="col">' . esc_html__( 'Address', 'scrapelock' ) . '</th><th scope="col" class="num">' . esc_html__( 'Requests', 'scrapelock' ) . '</th>';
		switch ( $type ) {
			case '404':
				echo '<th scope="col" class="num">' . esc_html__( 'IPs', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Linked from', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Last seen', 'scrapelock' ) . '</th><th scope="col"><span class="screen-reader-text">' . esc_html__( 'Fix', 'scrapelock' ) . '</span></th>';
				break;
			case '5xx':
				echo '<th scope="col">' . esc_html__( 'Statuses', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Last seen', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Sample User-Agent', 'scrapelock' ) . '</th>';
				break;
			case '3xx':
				echo '<th scope="col">' . esc_html__( 'Statuses', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Linked from', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Last seen', 'scrapelock' ) . '</th>';
				break;
			case 'uncached':
				echo '<th scope="col" class="num">' . esc_html__( 'Not from cache', 'scrapelock' ) . '</th><th scope="col" class="num">' . esc_html__( 'Miss rate', 'scrapelock' ) . '</th>';
				break;
			case 'large':
				echo '<th scope="col" class="num">' . esc_html__( 'Bandwidth', 'scrapelock' ) . '</th><th scope="col" class="num">' . esc_html__( 'Average size', 'scrapelock' ) . '</th>';
				break;
			default:
				echo '<th scope="col" class="num">' . esc_html__( 'Average time', 'scrapelock' ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		$high_miss = false;
		foreach ( $rows as $row ) {
			$path  = (string) $row['path'];
			$probe = in_array( $type, array( '404', '5xx', '3xx' ), true ) && PNCP_Log::is_probe_path( $path );
			echo '<tr><td class="pncp-ar__path">' . self::detail_link( 'path', $path, '<code>' . esc_html( self::show_path( $path ) ) . '</code>' ) . ( $probe ? ' <span class="pncp-badge">' . esc_html__( 'scanner noise', 'scrapelock' ) . '</span>' : '' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in detail_link().
			echo '<td class="num">' . esc_html( self::n( (int) $row['hits'] ) ) . '</td>';
			switch ( $type ) {
				case '404':
					echo '<td class="num">' . esc_html( self::n( (int) $row['ips'] ) ) . '</td><td class="pncp-tr__refs">' . self::referers( $row['top_referers'] ) . '</td><td class="pncp-ar__nowrap">' . self::when( (int) $row['last'] ) . '</td><td>' . self::redirect_cell( $path ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the helpers.
					break;
				case '5xx':
					echo '<td>' . self::statuses( $row['statuses'] ) . '</td><td class="pncp-ar__nowrap">' . self::when( (int) $row['last'] ) . '</td><td class="pncp-ar__ua">' . self::ua_cell( (string) $row['sample_ua'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the helpers.
					break;
				case '3xx':
					echo '<td>' . self::statuses( $row['statuses'] ) . '</td><td class="pncp-tr__refs">' . self::referers( $row['top_referers'], true ) . '</td><td class="pncp-ar__nowrap">' . self::when( (int) $row['last'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the helpers.
					break;
				case 'uncached':
					$high_miss = $high_miss || (float) $row['miss_rate'] >= 0.5;
					echo '<td class="num">' . esc_html( self::n( (int) $row['misses'] ) ) . '</td><td class="num">' . esc_html( number_format_i18n( 100 * (float) $row['miss_rate'], 1 ) . '%' ) . '</td>';
					break;
				case 'large':
					echo '<td class="num">' . esc_html( self::bytes( (int) $row['bytes'] ) ) . '</td><td class="num">' . esc_html( self::bytes( (int) $row['avg_bytes'] ) ) . '</td>';
					break;
				default:
					/* translators: %s: milliseconds */
					echo '<td class="num">' . esc_html( null === $row['avg_rt_ms'] ? '–' : sprintf( __( '%s ms', 'scrapelock' ), self::n( (int) $row['avg_rt_ms'] ) ) ) . '</td>';
			}
			echo '</tr>';
		}
		echo '</tbody></table></div>';
		if ( $high_miss ) {
			$advice = PNCP_Admin_Fields::para(
				__( 'Pages missed half the time or more: check the cache rules of WP Rocket and Bunny.', 'scrapelock' ),
				__( 'A page that is fetched from the server on most requests usually carries a cookie or a query string that the cache skips (e.g. utm_ or fbclid), or it is excluded in WP Rocket ("Never cache URL(s)") or by a Bunny Edge Rule. Pages for signed-in users and carts are never cached, which is right.', 'scrapelock' )
			);
			echo $advice; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
		}
		self::pager( (int) $p['total_rows'], ! empty( $p['has_more'] ) );
		echo '</section>';
	}

	/**
	 * The referrers of a problem row: internal ones marked as the links to fix.
	 *
	 * @param array<int, array{referer:string, hits:int, internal:bool}> $refs     Referrers.
	 * @param bool                                                        $redirect A redirect, not a missing page.
	 * @return string HTML.
	 */
	private static function referers( $refs, $redirect = false ) {
		if ( ! $refs ) {
			return '<span class="pncp-ar__muted">–</span>';
		}
		$out = '<ul class="pncp-tr__reflist">';
		foreach ( $refs as $ref ) {
			$text = (string) $ref['referer'];
			$out .= '<li>' . ( '' === $text ? '<span class="pncp-ar__muted">' . esc_html__( '(no referrer)', 'scrapelock' ) . '</span>' : '<code class="pncp-tr__ref">' . esc_html( mb_strlen( $text ) > 70 ? mb_substr( $text, 0, 68 ) . '…' : $text ) . '</code>' );
			if ( $ref['internal'] ) {
				$out .= ' <span class="pncp-badge pncp-badge--bad">' . esc_html( $redirect ? __( 'link on your site', 'scrapelock' ) : __( 'broken link on your site', 'scrapelock' ) ) . '</span>';
			} elseif ( '' !== $text ) {
				$out .= ' <span class="pncp-badge">' . esc_html__( 'external', 'scrapelock' ) . '</span>';
			}
			$out .= ' <span class="pncp-tr__count">' . esc_html( self::n( (int) $ref['hits'] ) ) . '</span></li>';
		}
		return $out . '</ul>';
	}

	/**
	 * Status code => hits.
	 *
	 * @param array<string, int> $statuses Statuses.
	 * @return string HTML.
	 */
	private static function statuses( $statuses ) {
		$out = array();
		foreach ( (array) $statuses as $code => $hits ) {
			$out[] = self::status( (string) $code ) . ' ' . esc_html( self::n( (int) $hits ) );
		}
		return implode( ' ', $out );
	}

	/**
	 * One path.
	 */
	private static function view_path() {
		$st   = self::$st;
		$path = (string) $st['key'];
		$d    = PNCP_Traffic::detail( 'path', $path, self::filters( $st ) );
		self::note_clip( $d );
		echo '<p class="pncp-tr__back"><a href="' . esc_url( self::url( array( 'view' => 'problems' ) ) ) . '">' . esc_html__( '← Problem URLs', 'scrapelock' ) . '</a></p>';
		echo '<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-tr-path-title">';
		printf( '<h2 id="pncp-tr-path-title"><code class="pncp-tr__full">%s</code></h2>', esc_html( (string) $d['key'] ) );
		if ( PNCP_Log::is_probe_path( (string) $d['key'] ) ) {
			echo '<p><span class="pncp-badge">' . esc_html__( 'scanner noise', 'scrapelock' ) . '</span></p>';
		}
		self::render_kpis( $d['summary'] );
		$links = array(
			sprintf(
				'<a href="%1$s">%2$s</a>',
				esc_url(
					self::url(
						array(
							'view' => 'log',
							'path' => (string) $d['key'],
							'key'  => '',
						)
					)
				),
				esc_html__( 'Its requests', 'scrapelock' )
			),
		);
		if ( (int) $d['summary']['s4xx'] > 0 && '' !== self::redirect_url( (string) $d['key'] ) ) {
			$links[] = sprintf( '<a href="%1$s">%2$s</a>', esc_url( self::redirect_url( (string) $d['key'] ) ), esc_html__( 'Create redirect in Rank Math', 'scrapelock' ) );
		}
		echo '<p>' . implode( ' · ', $links ) . '</p></section>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
		echo '<div class="pncp-tr__grid">';
		self::detail_table( __( 'Status codes', 'scrapelock' ), $d['statuses'], 'status' );
		self::detail_table( __( 'Referrers', 'scrapelock' ), $d['referers'], 'referer' );
		self::detail_table( __( 'User-Agents', 'scrapelock' ), $d['uas'], 'ua' );
		self::detail_table( __( 'IPs', 'scrapelock' ), $d['ips'], 'ip' );
		self::detail_table( __( 'Countries', 'scrapelock' ), $d['countries'], 'country' );
		echo '</div>';
	}

	/* ---------- Visitors ---------- */

	/**
	 * Country and main family of IPs, from the raw rows of the range (one query; only inside the raw window).
	 *
	 * @param string[]             $ips IPs.
	 * @param array<string, mixed> $f   Filters.
	 * @return array<string, array{family:string, country:string}>
	 */
	private static function ip_info( $ips, $f ) {
		global $wpdb;
		$nf = PNCP_Traffic_Query::filters( $f );
		if ( ! $ips || ! PNCP_Traffic::ready() || (int) $nf['from'] < PNCP_Traffic::raw_floor() ) {
			return array();
		}
		$ips = array_slice( array_values( array_unique( array_map( 'strval', $ips ) ) ), 0, PNCP_Traffic_Query::MAX_LIMIT );
		$in  = implode( ', ', array_fill( 0, count( $ips ), '%s' ) );
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholders only.
		$sql  = $wpdb->prepare( 'SELECT ip, fam, MAX(country) AS country, COUNT(*) AS n FROM %i WHERE src = %s AND ts >= %d AND ts <= %d AND ip IN (' . $in . ') GROUP BY ip, fam', array_merge( array( PNCP_Traffic::table( 'raw' ), (string) $nf['src'], (int) $nf['from'], (int) $nf['to'] ), $ips ) );
		$best = array();
		$out  = array();
		foreach ( PNCP_Traffic::rows( (string) $sql ) as $r ) {
			$ip = (string) $r['ip'];
			if ( ! isset( $best[ $ip ] ) || (int) $r['n'] > $best[ $ip ] ) {
				$best[ $ip ] = (int) $r['n'];
				$out[ $ip ]  = array(
					'family'  => (string) $r['fam'],
					'country' => (string) $r['country'],
				);
			} elseif ( '' === $out[ $ip ]['country'] ) {
				$out[ $ip ]['country'] = (string) $r['country'];
			}
		}
		return $out;
	}

	/**
	 * What ScrapeLock does with an IP now (read only): badges.
	 *
	 * @param string                              $ip   IP.
	 * @param array<string, array<string, mixed>> $bans Active bans (PNCP_Log::active_bans()).
	 * @return string HTML.
	 */
	private static function ip_state( $ip, $bans ) {
		if ( 'masked' === PNCP_Traffic::settings()['ip_mode'] || '' === PNCP_Ip::normalize( $ip ) ) {
			return '';
		}
		$out = array();
		if ( isset( $bans[ PNCP_Ip::limit_key( $ip ) ] ) || isset( $bans[ $ip ] ) ) {
			$out[] = '<span class="pncp-badge pncp-badge--bad">' . esc_html__( 'Blocked now', 'scrapelock' ) . '</span>';
		}
		if ( PNCP_Options::is_blocked_permanently( $ip ) ) {
			$out[] = '<span class="pncp-badge pncp-badge--bad">' . esc_html__( 'Always blocked', 'scrapelock' ) . '</span>';
		}
		if ( PNCP_Ip::in_any( $ip, PNCP_Options::parse_list( (string) PNCP_Options::stored()['allow_ips'] ) ) ) {
			$out[] = '<span class="pncp-badge">' . esc_html__( 'Always allowed', 'scrapelock' ) . '</span>';
		}
		$owner = PNCP_Ip::official_owner( $ip );
		if ( '' !== $owner ) {
			/* translators: %s: company, e.g. Google */
			$out[] = '<span class="pncp-badge">' . esc_html( sprintf( __( 'Official %s address', 'scrapelock' ), $owner ) ) . '</span>';
		}
		return implode( ' ', $out );
	}

	/**
	 * The IPs and the countries.
	 */
	private static function view_visitors() {
		$st  = self::$st;
		$f   = self::filters( $st );
		$ips = PNCP_Traffic::top( 'ip', $f, self::PER_PAGE, self::offset(), $st['order'] );
		self::note_clip( $ips );
		$info = self::ip_info( array_column( $ips['rows'], 'key' ), $f );
		$bans = PNCP_Log::active_bans();
		echo '<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-tr-ips-title"><h2 id="pncp-tr-ips-title">' . esc_html__( 'Top IPs', 'scrapelock' ) . '</h2>';
		if ( ! $ips['rows'] ) {
			self::empty_note();
		} else {
			echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-tr__table pncp-ar__ips"><thead><tr><th scope="col">' . esc_html__( 'IP', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Country', 'scrapelock' ) . '</th><th scope="col">' . esc_html__( 'Mostly', 'scrapelock' ) . '</th>';
			self::th_sort( __( 'Requests', 'scrapelock' ), 'hits' );
			self::th_sort( '4xx', 's4xx' );
			self::th_sort( '5xx', 's5xx' );
			self::th_sort( __( 'Last seen', 'scrapelock' ), 'last', false );
			echo '<th scope="col">' . esc_html__( 'ScrapeLock', 'scrapelock' ) . '</th></tr></thead><tbody>';
			foreach ( $ips['rows'] as $row ) {
				$ip      = (string) $row['key'];
				$country = isset( $info[ $ip ] ) && '' !== $info[ $ip ]['country'] ? $info[ $ip ]['country'] : PNCP_Attack_Report::country( $ip );
				printf(
					'<tr><td>%1$s</td><td>%2$s</td><td>%3$s</td><td class="num">%4$s</td><td class="num">%5$s</td><td class="num">%6$s</td><td class="pncp-ar__nowrap">%7$s</td><td>%8$s</td></tr>',
					self::detail_link( 'ip', $ip, '<code>' . esc_html( $ip ) . '</code>' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in detail_link().
					'' !== $country ? '<a class="pncp-ar__country" href="' . esc_url(
						self::url(
							array(
								'country' => $country,
								'paged'   => '',
							)
						)
					) . '">' . esc_html( $country ) . '</a>' : '–', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped here.
					isset( $info[ $ip ] ) ? self::badge_family( $info[ $ip ]['family'] ) : '–', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in family().
					esc_html( self::n( (int) $row['hits'] ) ),
					esc_html( self::n( (int) $row['s4xx'] ) ),
					esc_html( self::n( (int) $row['s5xx'] ) ),
					self::when( (int) $row['last'] ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in when().
					self::ip_state( $ip, $bans ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in ip_state().
				);
			}
			echo '</tbody></table></div>';
			self::pager( (int) $ips['total_rows'], ! empty( $ips['has_more'] ) );
		}
		echo '</section>';
		$countries = PNCP_Traffic::top( 'country', $f, 25 );
		self::note_clip( $countries );
		echo '<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-tr-countries-title"><h2 id="pncp-tr-countries-title">' . esc_html__( 'Countries', 'scrapelock' ) . '</h2>';
		if ( ! $countries['rows'] ) {
			self::empty_note();
		} else {
			echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-tr__table"><thead><tr><th scope="col">' . esc_html__( 'Country', 'scrapelock' ) . '</th><th scope="col" class="num">' . esc_html__( 'Requests', 'scrapelock' ) . '</th><th scope="col" class="num">' . esc_html__( 'IPs', 'scrapelock' ) . '</th><th scope="col" class="num">4xx</th><th scope="col" class="num">5xx</th></tr></thead><tbody>';
			foreach ( $countries['rows'] as $row ) {
				$code = (string) $row['key'];
				printf(
					'<tr><td>%1$s</td><td class="num">%2$s</td><td class="num">%3$s</td><td class="num">%4$s</td><td class="num">%5$s</td></tr>',
					'' === $code ? esc_html__( 'Unknown', 'scrapelock' ) : '<a class="pncp-ar__country" href="' . esc_url(
						self::url(
							array(
								'country' => $code,
								'paged'   => '',
							)
						)
					) . '">' . esc_html( $code ) . '</a>', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped here.
					esc_html( self::n( (int) $row['hits'] ) ),
					esc_html( ( ! empty( $countries['ips_approx'] ) ? '≈ ' : '' ) . self::n( (int) $row['ips'] ) ),
					esc_html( self::n( (int) $row['s4xx'] ) ),
					esc_html( self::n( (int) $row['s5xx'] ) )
				);
			}
			echo '</tbody></table></div>';
		}
		echo '</section>';
	}

	/**
	 * One IP.
	 */
	private static function view_ip() {
		$st = self::$st;
		$ip = (string) $st['key'];
		$d  = PNCP_Traffic::detail( 'ip', $ip, self::filters( $st ) );
		self::note_clip( $d );
		$key = (string) $d['key'];
		echo '<p class="pncp-tr__back"><a href="' . esc_url( self::url( array( 'view' => 'visitors' ) ) ) . '">' . esc_html__( '← Visitors', 'scrapelock' ) . '</a></p>';
		echo '<section class="pncp-card pncp-card--wide" aria-labelledby="pncp-tr-ip-title">';
		$country = PNCP_Attack_Report::country( $key );
		printf( '<h2 id="pncp-tr-ip-title"><code>%1$s</code>%2$s</h2>', esc_html( '' !== $key ? $key : $ip ), '' !== $country ? ' <span class="pncp-ar__country">' . esc_html( $country ) . '</span>' : '' );
		$state = self::ip_state( $key, PNCP_Log::active_bans() );
		if ( '' !== $state ) {
			echo '<p>' . $state . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in ip_state().
		}
		self::render_kpis( $d['summary'] );
		printf(
			'<p><a href="%1$s">%2$s</a> · <a href="%3$s">%4$s</a></p>',
			esc_url(
				self::url(
					array(
						'view' => 'log',
						'ip'   => $key,
						'key'  => '',
					)
				)
			),
			esc_html__( 'Its requests', 'scrapelock' ),
			esc_url( PNCP_Status::settings_url( array( 'tab' => 'log' ) ) . '#pncp-tester' ),
			esc_html__( 'Check a request', 'scrapelock' )
		);
		if ( 'masked' !== PNCP_Traffic::settings()['ip_mode'] && '' !== PNCP_Ip::normalize( $key ) && ! PNCP_Options::is_blocked_permanently( $key ) ) {
			$why = PNCP_Options::ban_refusal( $key );
			if ( '' === $why && ! PNCP_Lockdown::is_locked() ) {
				printf( '<form method="post" action="%s" class="pncp-inline-form">', esc_url( admin_url( 'admin-post.php' ) ) );
				echo '<input type="hidden" name="action" value="pncp_log"><input type="hidden" name="op" value="block_permanent">';
				printf( '<input type="hidden" name="ip" value="%s">', esc_attr( $key ) );
				echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( 'pncp_log', '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
				/* translators: %s: IP address */
				printf( '<p><button type="submit" class="button" data-pncp-confirm="%1$s">%2$s</button></p></form>', esc_attr( sprintf( __( 'Add %s to “Always-blocked IPs”? Every request from it will be refused until you remove it.', 'scrapelock' ), $key ) ), esc_html__( 'Block permanently', 'scrapelock' ) );
			} elseif ( '' !== $why ) {
				echo '<p class="pncp-tr__note">' . esc_html( PNCP_Options::ban_refusal_text( $why ) ) . '</p>';
			}
		}
		echo '</section><div class="pncp-tr__grid">';
		self::detail_table( __( 'Paths', 'scrapelock' ), $d['paths'], 'path' );
		self::detail_table( __( 'User-Agents', 'scrapelock' ), $d['uas'], 'ua' );
		self::detail_table( __( 'Status codes', 'scrapelock' ), $d['statuses'], 'status' );
		self::detail_table( __( 'Referrers', 'scrapelock' ), $d['referers'], 'referer' );
		echo '</div>';
	}

	/* ---------- Requests ---------- */

	/**
	 * The requests themselves, newest first, and "Export CSV".
	 */
	private static function view_log() {
		$st  = self::$st;
		$f   = self::filters( $st );
		$raw = PNCP_Traffic::raw( $f, self::PER_PAGE, self::offset() );
		self::note_clip( $raw );
		echo '<section class="pncp-card pncp-card--wide pncp-card--table" aria-labelledby="pncp-tr-log-title"><h2 id="pncp-tr-log-title">' . esc_html__( 'Requests', 'scrapelock' ) . '</h2>';
		echo PNCP_Admin_Fields::para( __( 'Every request, newest first. Open an address, an IP or a User-Agent for its details.', 'scrapelock' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in PNCP_Admin_Fields.
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="pncp-inline-form pncp-tr__export">';
		printf( '<input type="hidden" name="action" value="%s">', esc_attr( PNCP_Traffic_Actions::CSV ) );
		foreach ( self::KEEP as $key ) {
			if ( '' !== (string) $st[ $key ] && ! ( 'period' === $key && '24h' === $st[ $key ] ) ) {
				printf( '<input type="hidden" name="%1$s" value="%2$s">', esc_attr( self::PARAMS[ $key ] ), esc_attr( (string) $st[ $key ] ) );
			}
		}
		echo preg_replace( '/ id="_wpnonce"/', '', wp_nonce_field( PNCP_Traffic_Actions::CSV, '_wpnonce', true, false ), 1 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core markup.
		echo '<p><button type="submit" class="button" id="pncp-tr-csv">' . esc_html__( 'Export CSV', 'scrapelock' ) . '</button></p></form>';
		if ( ! $raw['rows'] ) {
			self::empty_note();
			self::pager( -1, false );
			echo '</section>';
			return;
		}
		echo '<div class="pncp-table-wrap"><table class="widefat striped pncp-tr__table pncp-tr__log"><thead><tr>';
		foreach ( array( __( 'Time', 'scrapelock' ), __( 'Status', 'scrapelock' ), __( 'Address', 'scrapelock' ), __( 'IP', 'scrapelock' ), __( 'User-Agent', 'scrapelock' ), __( 'Referrer', 'scrapelock' ), __( 'Size', 'scrapelock' ), __( 'Cache', 'scrapelock' ) ) as $i => $label ) {
			printf( '<th scope="col"%1$s>%2$s</th>', 6 === $i ? ' class="num"' : '', esc_html( $label ) );
		}
		echo '</tr></thead><tbody>';
		$format = get_option( 'time_format' );
		$today  = PNCP_Traffic::day_start( time() );
		foreach ( $raw['rows'] as $r ) {
			$class = PNCP_Traffic_Ua::classify( $r['ua'] );
			printf(
				'<tr class="pncp-tr__row--%1$s"><td class="pncp-ar__nowrap"><time datetime="%2$s">%3$s</time></td><td>%4$s <span class="pncp-tr__method">%5$s</span></td><td class="pncp-ar__path">%6$s%7$s</td><td class="pncp-ar__nowrap">%8$s%9$s</td><td class="pncp-ar__ua">%10$s %11$s</td><td class="pncp-tr__refcell">%12$s</td><td class="num">%13$s</td><td>%14$s</td></tr>',
				esc_attr( (string) ( (int) ( $r['status'] / 100 ) ) ),
				esc_attr( gmdate( 'c', $r['ts'] ) ),
				esc_html( wp_date( $r['ts'] >= $today ? $format : get_option( 'date_format' ) . ' ' . $format, $r['ts'] ) ),
				self::status( $r['status'] ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in status().
				esc_html( $r['method'] ),
				self::detail_link( 'path', $r['path'], '<code>' . esc_html( self::show_path( $r['path'] ) ) . '</code>' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in detail_link().
				'' !== $r['query'] ? ' <code class="pncp-tr__query">?' . esc_html( mb_strlen( $r['query'] ) > 60 ? mb_substr( $r['query'], 0, 58 ) . '…' : $r['query'] ) . '</code>' : '', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped here.
				'' !== $r['ip'] ? self::detail_link( 'ip', $r['ip'], '<code>' . esc_html( $r['ip'] ) . '</code>' ) : '–', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in detail_link().
				'' !== $r['country'] ? ' <span class="pncp-ar__country">' . esc_html( $r['country'] ) . '</span>' : '', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped here.
				self::badge_family( $r['family'] ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in family().
				self::detail_link( 'ua', $r['ua'], self::ua_cell( $r['ua'], $class['name'] ) ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in the helpers.
				'' !== $r['referer'] ? '<code class="pncp-tr__ref" title="' . esc_attr( $r['referer'] ) . '">' . esc_html( mb_strlen( $r['referer'] ) > 50 ? mb_substr( $r['referer'], 0, 48 ) . '…' : $r['referer'] ) . '</code>' : '<span class="pncp-ar__muted">–</span>', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped here.
				esc_html( self::bytes( $r['bytes'] ) ),
				esc_html( '' !== $r['cache'] ? $r['cache'] : '–' )
			);
		}
		echo '</tbody></table></div>';
		self::pager( -1, ! empty( $raw['has_more'] ) );
		echo '</section>';
	}
}
