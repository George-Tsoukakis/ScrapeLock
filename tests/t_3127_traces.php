<?php
/**
 * ScrapeLock 3.12.7 — the last traces Stealth left on a page: the paths in the JSON of script translations.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_3127_traces.php
 *
 * A stand-in mu-plugin written by this test (no third-party code), active on ?pncp_traces=1 only: a script with
 * wp_set_script_translations() and a fake translation JSON file whose "comment" names wp-includes/… and a plugin
 * path and whose "generator" names its tool.
 *
 * J. The translations JSON with Stealth on: no wp-includes / plugin path / comment / generator, the translations,
 *    text domain and plural forms still there and the inline script well formed; unchanged with Stealth off.
 *
 * Only on a test WordPress.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? '  [' . substr( (string) $extra, 0, 500 ) . ']' : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	wp_cache_delete( 'alloptions', 'options' );
}

/** A guest's GET: [code, body]. */
function http( $path ) {
	global $base;
	$ch = curl_init( $base . $path );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.237', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', 'Accept: text/html' ),
			CURLOPT_TIMEOUT        => 90,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

const DOMAIN = 'pncp-test-traces';
const HANDLE = 'pncp-test-i18n';

/* ---------- The stand-in ---------- */

$mu_dir = WP_CONTENT_DIR . '/mu-plugins';
wp_mkdir_p( $mu_dir );
$mu      = $mu_dir . '/pncp-test-traces.php';
$js      = $mu_dir . '/pncp-test-traces.js';
$lang    = $mu_dir . '/pncp-test-traces-lang';
$locale  = determine_locale();
$json_tr = array(
	'translation-revision-date' => '2026-11-01 10:00:00+0000',
	'generator'                 => 'GlotPress/4.0.1',
	'domain'                    => 'messages',
	'locale_data'               => array(
		'messages' => array(
			''                 => array(
				'domain'       => 'messages',
				'plural-forms' => 'nplurals=2; plural=n != 1;',
				'lang'         => $locale,
			),
			'Hello traces'     => array( 'Hallo Spuren </script> äöü' ),
			'%d trace'         => array( '%d Spur', '%d Spuren' ),
		),
	),
	'comment'                   => array( 'reference' => 'wp-includes/js/dist/api-fetch.js wp-content/plugins/pncp-test/build/index.js' ),
);
wp_mkdir_p( $lang );
file_put_contents( $lang . '/' . DOMAIN . '-' . $locale . '-' . HANDLE . '.json', wp_json_encode( $json_tr ) );
file_put_contents( $js, "document.documentElement.setAttribute('data-pncp-i18n', wp.i18n.__('Hello traces', 'pncp-test-traces'));\n" );
$code  = "<?php\n// ScrapeLock test stand-in (t_3127_traces.php). Removed by the test.\n";
$code .= "if ( empty( \$_GET['pncp_traces'] ) ) { return; }\n";
$code .= "add_action( 'wp_enqueue_scripts', function () {\n";
$code .= "\twp_enqueue_script( " . var_export( HANDLE, true ) . ", content_url( 'mu-plugins/pncp-test-traces.js' ), array( 'wp-i18n' ), '1', true );\n";
$code .= "\twp_set_script_translations( " . var_export( HANDLE, true ) . ', ' . var_export( DOMAIN, true ) . ', ' . var_export( $lang, true ) . " );\n} );\n";
file_put_contents( $mu, $code );

$saved = array();
foreach ( array( PNCP_OPTION, PNCP_Stealth::OPTION ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}
register_shutdown_function(
	static function () use ( $saved, $mu, $js, $lang ) {
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, true );
			}
		}
		foreach ( (array) glob( $lang . '/*.json' ) as $f ) {
			unlink( $f );
		}
		if ( is_dir( $lang ) ) {
			rmdir( $lang );
		}
		foreach ( array( $mu, $js ) as $f ) {
			if ( is_file( $f ) ) {
				unlink( $f );
			}
		}
	}
);

/** The inline translations script of the page: [script, domain, decoded JSON or null]. */
function translations( $page ) {
	if ( ! preg_match( '~<script\b[^>]*id=["\'][^"\']*-js-translations["\'][^>]*>(.*?)</script>~s', $page, $m ) ) {
		return array( '', '', null );
	}
	if ( ! preg_match( '~\}\s*\)\(\s*"([^"]*)",\s*(\{.*\})\s*\);~s', $m[1], $j ) ) {
		return array( $m[1], '', null );
	}
	return array( $m[1], $j[1], json_decode( $j[2], true ) );
}

function count_of( $page, $text ) {
	return substr_count( $page, $text );
}

/* ---------- Stealth on ---------- */

settings(
	array(
		'enabled'             => 1,
		'monitor_mode'        => 0,
		'hide_fingerprint'    => 0,
		'stealth_enabled'     => 1,
		'stealth_base'        => 'assets',
		'stealth_rest_prefix' => '',
		'stealth_sitemap'     => 0,
	)
);
add_filter( 'pncp_stealth_self_test', '__return_true' );
$on = PNCP_Stealth::activate( false );
t( 'Stealth on (self-test skipped here)', true === $on && PNCP_Stealth::active(), is_wp_error( $on ) ? $on->get_error_message() : '' );

list( $code, $page ) = http( '/?pncp_traces=1' );
t( 'J the page answers 200 with the stand-in\'s script', 200 === $code && false !== strpos( $page, 'pncp-test-traces.js' ), (string) $code );
list( $script, $domain, $data ) = translations( $page );
t( 'J the inline translations are printed', '' !== $script && is_array( $data ), substr( $script, 0, 300 ) );
t( 'J no wp-includes and no plugin path in them', false === strpos( $script, 'wp-includes' ) && false === strpos( $script, 'wp-content' ) && false === strpos( $script, 'plugins\\/pncp-test' ), $script );
t( 'J no "comment" and no "generator" (GlotPress) key', is_array( $data ) && ! isset( $data['comment'] ) && ! isset( $data['generator'] ) && false === stripos( $script, 'GlotPress' ) );
$msgs = is_array( $data ) ? $data['locale_data']['messages'] : array();
t( 'J the translations are still there (singular, plural, the "" header with the plural forms)', isset( $msgs['Hello traces'][0], $msgs['%d trace'][1], $msgs['']['plural-forms'] ) && 'Hallo Spuren </script> äöü' === $msgs['Hello traces'][0] && '%d Spuren' === $msgs['%d trace'][1] && 'nplurals=2; plural=n != 1;' === $msgs['']['plural-forms'], wp_json_encode( $msgs ) );
t( 'J the text domain is kept (the script looks its texts up by it)', DOMAIN === $domain, $domain );
t( 'J a "</script>" inside a translation cannot end the inline script', false === strpos( $script, '</script>' ) && 1 === preg_match_all( '~<script\b[^>]*id=["\'][^"\']*-js-translations["\'][^>]*>.*?</script>~s', $page ) );
t( 'J the wp.i18n call itself is intact', false !== strpos( $script, 'wp.i18n.setLocaleData( localeData, domain );' ) );

/* ---------- Stealth off ---------- */

settings( array( 'stealth_enabled' => 0 ) );
t( 'Stealth off', ! PNCP_Stealth::active() );
list( $code, $page ) = http( '/?pncp_traces=1' );
list( $script, $domain, $data ) = translations( $page );
t( 'J Stealth off: the JSON is printed as the file has it (comment and generator)', 200 === $code && is_array( $data ) && isset( $data['comment']['reference'], $data['generator'] ) && false !== strpos( $script, 'wp-includes' ), substr( $script, 0, 300 ) );

exit( $fails ? 1 : 0 );
