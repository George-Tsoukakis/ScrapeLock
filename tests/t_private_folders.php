<?php
/**
 * ScrapeLock 3.10 — Site Health «ScrapeLock's private folders can be read from the web»: οι ακριβείς γραμμές
 * Nginx / Apache για κάθε ιδιωτικό φάκελο (σε ορατό μπλοκ), το preset «private_folders» του «Lock at Bunny» με
 * ψεύτικο API του Bunny (Edge Rules, και το 400 του πραγματικού Bunny για > 5 patterns σε μία συνθήκη), το κουμπί
 * στο Site Health μόνο για διαχειριστές με συνδεδεμένο Bunny, και η αναγνώριση του κλειδώματος από το Site Health.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_private_folders.php
 */

$wp_dir = getenv( 'WP_DIR' );

define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

const PF_ZONE = '54321';
const PF_KEY  = 'bunny-folders-key-1234567890';
const PF_API  = 'https://bunny-mock.invalid';

/* ---------- Ψεύτικο API του Bunny (Edge Rules), μέσα στη διεργασία ---------- */
$GLOBALS['pf_bunny'] = array(
	'rules' => array(),
	'calls' => array(),
);
add_filter(
	'pncp_bunny_api_base',
	static function () {
		return PF_API;
	}
);
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) {
		if ( 0 !== strpos( $url, PF_API . '/' ) ) {
			return $pre;
		}
		$reply  = static function ( $code, $data = null ) {
			return array(
				'headers'  => array( 'content-type' => 'application/json' ),
				'body'     => null === $data ? '' : wp_json_encode( $data ),
				'response' => array(
					'code'    => $code,
					'message' => '',
				),
				'cookies'  => array(),
				'filename' => null,
			);
		};
		$method = isset( $args['method'] ) ? $args['method'] : 'GET';
		$body   = isset( $args['body'] ) ? json_decode( (string) $args['body'], true ) : null;
		$db     = &$GLOBALS['pf_bunny'];
		$db['calls'][] = $method . ' ' . substr( $url, strlen( PF_API ) );
		if ( ! isset( $args['headers']['AccessKey'] ) || PF_KEY !== $args['headers']['AccessKey'] ) {
			return $reply( 401, array( 'Message' => 'The request authorization failed' ) );
		}
		$zone = PF_API . '/pullzone/' . PF_ZONE;
		if ( 'GET' === $method && $zone === $url ) {
			return $reply(
				200,
				array(
					'Id'        => (int) PF_ZONE,
					'EdgeRules' => array_values( $db['rules'] ),
				)
			);
		}
		if ( 'POST' === $method && $zone . '/edgerules/addOrUpdate' === $url && is_array( $body ) ) {
			// Όπως το πραγματικό Bunny: το πολύ 5 patterns σε κάθε συνθήκη (trigger).
			foreach ( (array) $body['Triggers'] as $trigger ) {
				if ( count( (array) $trigger['PatternMatches'] ) > 5 ) {
					return $reply( 400, array( 'Message' => 'Maximum 5 triggers are allowed per condition.' ) );
				}
			}
			$guid = ! empty( $body['Guid'] ) ? $body['Guid'] : wp_generate_uuid4();
			$body['Guid']         = $guid;
			$db['rules'][ $guid ] = $body;
			return $reply( 200, $body );
		}
		if ( 'DELETE' === $method && 0 === strpos( $url, $zone . '/edgerules/' ) ) {
			$guid = substr( $url, strlen( $zone . '/edgerules/' ) );
			if ( ! isset( $db['rules'][ $guid ] ) ) {
				return $reply( 404, array( 'Message' => 'Not found' ) );
			}
			unset( $db['rules'][ $guid ] );
			return $reply( 204 );
		}
		return $reply( 404, array( 'Message' => 'Not found' ) );
	},
	5,
	3
);

/**
 * Ταιριάζει ένα URL με ένα pattern του Bunny («*» = οτιδήποτε, και «/»).
 *
 * @param string $pattern Pattern.
 * @param string $url     URL.
 * @return bool
 */
function pf_match( $pattern, $url ) {
	return (bool) preg_match( '#^' . str_replace( '\*', '.*', preg_quote( $pattern, '#' ) ) . '$#i', $url );
}
function pf_match_any( $patterns, $url ) {
	foreach ( $patterns as $p ) {
		if ( pf_match( $p, $url ) ) {
			return true;
		}
	}
	return false;
}

/* ---------- Καθαρή αρχή ---------- */
$pf_saved = array(
	'nginx'  => isset( $GLOBALS['is_nginx'] ) ? $GLOBALS['is_nginx'] : false,
	'apache' => isset( $GLOBALS['is_apache'] ) ? $GLOBALS['is_apache'] : false,
	'config' => get_option( PNCP_Bunny::CONFIG, null ),
	'rules'  => get_option( PNCP_Bunny::RULES, null ),
	'edge'   => get_option( PNCP_Edge::CONFIG, null ),
);
// «Blocking at the CDN» set to Bunny would win over the card's own connection (PNCP_Bunny::credentials()).
delete_option( PNCP_Edge::CONFIG );
delete_option( PNCP_Bunny::CONFIG );
delete_option( PNCP_Bunny::RULES );
delete_option( PNCP_Bunny::CALLS );
PNCP_Bunny::reset();
delete_transient( PNCP_Health::FOLDERS_CACHE );

/* ---------- Οι γραμμές ---------- */
$paths = PNCP_Health::private_folder_paths();
$up    = (string) wp_parse_url( wp_upload_dir( null, false )['baseurl'], PHP_URL_PATH );
t( 'φάκελοι: precheck, geo, originals, lockdown (uploads και wp-content), lockdown data', array( 'precheck', 'geo', 'originals', 'lockdown', 'lockdown_wpc', 'lockdown_data' ) === array_keys( $paths ), implode( ',', array_keys( $paths ) ) );
t( 'φάκελοι: διαδρομές από τη ρίζα του domain', $up . '/scrapelock/' === $paths['precheck']['path'] && $up . '/scrapelock-geo/' === $paths['geo']['path'] && $up . '/pncp-originals-' === $paths['originals']['path'] && $paths['originals']['prefix'], $paths['precheck']['path'] );

$nginx = PNCP_Health::folders_nginx_lines();
t( 'Nginx: location για κάθε φάκελο', false !== strpos( $nginx, 'location ^~ ' . $up . '/scrapelock/ { deny all; return 404; }' ) && false !== strpos( $nginx, 'location ^~ ' . $up . '/scrapelock-geo/ { deny all; return 404; }' ) && false !== strpos( $nginx, '/scrapelock-lockdown/ { deny all; return 404; }' ) && false !== strpos( $nginx, '/mu-plugins/scrapelock-lockdown-data/ { deny all; return 404; }' ), $nginx );
t( 'Nginx: ο φάκελος των originals με regex, χωρίς το τυχαίο όνομα και χωρίς {n}', (bool) preg_match( '#location ~ \^.*/pncp-originals-\[a-z0-9\]\+/ \{ deny all; return 404; \}#', $nginx ) && false === strpos( $nginx, (string) get_option( 'pncp_backup_dir', 'none-xyz' ) ) && false === strpos( $nginx, '{12}' ), $nginx );
$apache = PNCP_Health::folders_apache_lines();
t( 'Apache: RedirectMatch 404 για κάθε φάκελο', 6 === substr_count( $apache, 'RedirectMatch 404 ^' ) && false !== strpos( $apache, '<IfModule mod_alias.c>' ), $apache );

// WordPress σε υποφάκελο με τελεία στο όνομα: διαδρομές και escape στο regex.
$pf_dir = static function ( $u ) {
	$u['baseurl'] = 'https://example.test/my.blog/wp-content/uploads';
	return $u;
};
add_filter( 'upload_dir', $pf_dir );
$nginx_sub = PNCP_Health::folders_nginx_lines();
t( 'υποφάκελος: location ^~ /my.blog/wp-content/uploads/scrapelock/ και regex ^/my\.blog/…', false !== strpos( $nginx_sub, 'location ^~ /my.blog/wp-content/uploads/scrapelock/ ' ) && false !== strpos( $nginx_sub, 'location ~ ^/my\.blog/wp-content/uploads/pncp-originals-[a-z0-9]+/ ' ), $nginx_sub );
t( 'υποφάκελος: τα patterns του Bunny ακολουθούν', in_array( '*/my.blog/wp-content/uploads/scrapelock*/*', PNCP_Bunny::private_folder_patterns(), true ), implode( ' ', PNCP_Bunny::private_folder_patterns() ) );
remove_filter( 'upload_dir', $pf_dir );

/* ---------- Site Health: οι γραμμές φαίνονται πάντα ---------- */
wp_set_current_user( 1 );
$GLOBALS['is_nginx']  = true;
$GLOBALS['is_apache'] = false;
// Ένας ιδιωτικός φάκελος που υπάρχει (ο server δοκιμών, php -S, δεν διαβάζει .htaccess: είναι «ανοιχτός»).
wp_mkdir_p( PNCP_Geo::dir() );
$h        = PNCP_Health::test_folders();
t( 'Site Health (Nginx): δεν είναι «good» με ανοιχτό φάκελο ή χωρίς έλεγχο', 'good' !== $h['status'], $h['status'] . ' ' . $h['label'] );
t( 'Site Health (Nginx): οι γραμμές location είναι στην περιγραφή, σε ορατό <pre>', false !== strpos( $h['description'], '<pre class="pncp-lines"' ) && false !== strpos( $h['description'], 'location ^~ ' . $up . '/scrapelock-geo/ { deny all; return 404; }' ) && false === strpos( $h['description'], '<textarea' ), $h['description'] );
t( 'Site Health (Nginx): χωρίς Bunny, κανένα κουμπί «Lock at Bunny»', false === strpos( $h['description'], 'name="op" value="lock"' ) );
if ( false !== strpos( $h['label'], 'can be read' ) ) {
	t( 'Site Health (Nginx): «Add these lines» ακολουθείται από τις γραμμές', (bool) preg_match( '#Add these lines to the server \{ \} block.*?</p><pre class="pncp-lines"[^>]*>\# BEGIN ScrapeLock private folders\nlocation #s', $h['description'] ), $h['description'] );
}
$GLOBALS['is_nginx'] = false;
delete_transient( PNCP_Health::FOLDERS_CACHE );
$h = PNCP_Health::test_folders();
t( 'Site Health (άγνωστος server): γραμμές και για Nginx και για Apache', 'good' === $h['status'] || ( false !== strpos( $h['description'], 'location ^~ ' ) && ( false !== strpos( $h['label'], 'could not' ) || false !== strpos( $h['description'], 'RedirectMatch 404 ^' ) ) ), $h['description'] );
$GLOBALS['is_nginx'] = true;

/* ---------- Το preset «private_folders» ---------- */
$presets = PNCP_Bunny::presets();
t( 'preset private_folders υπάρχει, με label/blocks/breaks', isset( $presets['private_folders'] ) && '' !== $presets['private_folders']['label'] && false !== strpos( $presets['private_folders']['breaks'], 'straight to the server' ) );
$pats = $presets['private_folders']['patterns'];
t( 'preset: το πολύ 5 patterns (όριο του Bunny ανά συνθήκη)', count( $pats ) >= 1 && count( $pats ) <= 5, implode( ' ', $pats ) );
$site = 'https://example.test';
t(
	'preset: πιάνει κάθε ιδιωτικό φάκελο',
	pf_match_any( $pats, $site . $up . '/scrapelock/precheck-abcdefghij0123456789/bans/1.2.3.4' )
		&& pf_match_any( $pats, $site . $up . '/scrapelock-geo/v4.bin' )
		&& pf_match_any( $pats, $site . $up . '/scrapelock-lockdown/lock.php' )
		&& pf_match_any( $pats, $site . $up . '/pncp-originals-abcdef123456/2024/05/photo.jpg' )
		&& pf_match_any( $pats, $site . (string) wp_parse_url( content_url(), PHP_URL_PATH ) . '/scrapelock-lockdown/x.php' )
		&& pf_match_any( $pats, $site . (string) wp_parse_url( WPMU_PLUGIN_URL, PHP_URL_PATH ) . '/scrapelock-lockdown-data/fails.php' ),
	implode( ' ', $pats )
);
t(
	'preset: δεν πιάνει σελίδες ή αρχεία πολυμέσων',
	! pf_match_any( $pats, $site . '/' ) && ! pf_match_any( $pats, $site . $up . '/scrapelock-logo.png' ) && ! pf_match_any( $pats, $site . $up . '/2024/05/scrapelock.png' ) && ! pf_match_any( $pats, $site . '/scrapelock/' ) && ! pf_match_any( $pats, $site . '/?s=scrapelock' ),
	implode( ' ', $pats )
);

/* ---------- Site Health: κουμπί μόνο με Bunny συνδεδεμένο, μόνο για διαχειριστή ---------- */
update_option(
	PNCP_Bunny::CONFIG,
	array(
		'zone'  => PF_ZONE,
		'token' => PF_KEY,
	),
	false
);
PNCP_Bunny::reset();
delete_transient( PNCP_Health::FOLDERS_CACHE );
$h = PNCP_Health::test_folders();
if ( false !== strpos( $h['label'], 'can be read' ) ) {
	t( 'Site Health + Bunny: κουμπί «Lock at Bunny…» (op=lock, id=private_folders, nonce, επιστροφή στο Site Health)', false !== strpos( $h['description'], 'name="op" value="lock"' ) && false !== strpos( $h['description'], 'name="id" value="private_folders"' ) && false !== strpos( $h['description'], 'name="_wpnonce"' ) && false !== strpos( $h['description'], 'site-health.php' ) && false !== strpos( $h['description'], 'straight to the server' ), $h['description'] );
	wp_set_current_user( 0 );
	$h0 = PNCP_Health::test_folders();
	t( 'Site Health + Bunny: χωρίς manage_options, κανένα κουμπί', false === strpos( $h0['description'], 'name="op" value="lock"' ) );
	wp_set_current_user( 1 );
} else {
	echo 'SKIP Site Health + Bunny button: the loopback could not fetch the test file (' . $h['label'] . ")\n";
}
t( 'lock_button: μόνο για γνωστό preset', '' === PNCP_Bunny::lock_button( 'nope', 'x' ) && false !== strpos( PNCP_Bunny::lock_button( 'private_folders', 'x' ), 'value="private_folders"' ) );

/* ---------- Preview και κλείδωμα στο ψεύτικο Bunny ---------- */
$preview = PNCP_Bunny::lock_preview( 'preset', 'private_folders' );
t( 'preview: χωρίς σφάλμα και χωρίς blocker, τα ίδια patterns', is_array( $preview ) && ! $preview['blockers'] && $pats === $preview['patterns'] && ! $preview['locked'], is_wp_error( $preview ) ? $preview->get_error_message() : '' );
$GLOBALS['pf_bunny']['calls'] = array();
$r = PNCP_Bunny::lock_preset( 'private_folders' );
t( 'lock_preset: το ψεύτικο Bunny (400 για > 5 patterns) δέχεται τον κανόνα', true === $r, is_wp_error( $r ) ? $r->get_error_message() : '' );
$pf_rule = reset( $GLOBALS['pf_bunny']['rules'] );
t( 'κανόνας: «ScrapeLock: …» [preset_private_folders], Block, τα patterns', is_array( $pf_rule ) && false !== strpos( $pf_rule['Description'], '[preset_private_folders]' ) && 0 === strpos( $pf_rule['Description'], 'ScrapeLock: ' ) && 4 === (int) $pf_rule['ActionType'] && $pats === $pf_rule['Triggers'][0]['PatternMatches'], wp_json_encode( $pf_rule ) );
t( 'preset_locked(private_folders)', PNCP_Bunny::preset_locked( 'private_folders' ) );
t( 'κανένα κλειδί API σε μήνυμα ή κανόνα', false === strpos( wp_json_encode( $GLOBALS['pf_bunny']['rules'] ), PF_KEY ) );

// 3.10 wiring with the split Edge Rules: if the preset ever holds more than 5 patterns (a moved uploads folder,
// a filter), it is split into triggers of at most 5 and still handled as one lock.
$pf_six = static function ( $p ) {
	$p['private_folders']['patterns'] = array( '*/a1/*', '*/a2/*', '*/a3/*', '*/a4/*', '*/a5/*', '*/a6/*' );
	return $p;
};
PNCP_Bunny::unlock_preset( 'private_folders' );
add_filter( 'pncp_bunny_presets', $pf_six, 1 );
$r6    = PNCP_Bunny::lock_preset( 'private_folders' );
$sizes = array();
foreach ( $GLOBALS['pf_bunny']['rules'] as $pf_r ) {
	foreach ( $pf_r['Triggers'] as $pf_tr ) {
		$sizes[] = count( $pf_tr['PatternMatches'] );
	}
}
t( 'split: 6 patterns of the preset → accepted by the fake API (400 for > 5), triggers 5+1, one lock', true === $r6 && array( 5, 1 ) === $sizes && PNCP_Bunny::preset_locked( 'private_folders' ), is_wp_error( $r6 ) ? $r6->get_error_message() : wp_json_encode( $sizes ) );
$r6 = PNCP_Bunny::unlock_preset( 'private_folders' );
t( 'split: one Remove deletes the whole lock', true === $r6 && ! $GLOBALS['pf_bunny']['rules'] && ! PNCP_Bunny::preset_locked( 'private_folders' ) );
remove_filter( 'pncp_bunny_presets', $pf_six, 1 );
$r = PNCP_Bunny::lock_preset( 'private_folders' );
t( 'lock_preset again with the real patterns', true === $r, is_wp_error( $r ) ? $r->get_error_message() : '' );

/* ---------- Site Health αναγνωρίζει το κλείδωμα ---------- */
delete_transient( PNCP_Health::FOLDERS_CACHE );
$h = PNCP_Health::test_folders();
if ( false !== strpos( $h['label'], 'Bunny' ) ) {
	t( 'Site Health μετά το κλείδωμα: «blocked at Bunny CDN», good, και ότι η απευθείας πρόσβαση στον server μένει', 'good' === $h['status'] && false !== strpos( $h['description'], 'straight to the server' ) && false !== strpos( $h['description'], 'location ^~ ' ) && false === strpos( $h['description'], 'name="op" value="lock"' ), $h['status'] . ' ' . $h['description'] );
} else {
	t( 'Site Health μετά το κλείδωμα: αναφέρει το Bunny (ή δεν μπόρεσε να ελέγξει)', false !== strpos( $h['description'], 'Bunny' ) || false !== strpos( $h['label'], 'could not' ), $h['label'] . ' ' . $h['description'] );
}

/* ---------- Αφαίρεση ---------- */
$r = PNCP_Bunny::unlock_preset( 'private_folders' );
t( 'unlock_preset: ο κανόνας σβήνεται στο Bunny', true === $r && ! $GLOBALS['pf_bunny']['rules'] && ! PNCP_Bunny::preset_locked( 'private_folders' ), is_wp_error( $r ) ? $r->get_error_message() : wp_json_encode( $GLOBALS['pf_bunny']['rules'] ) );

/* ---------- Τέλος: επαναφορά ---------- */
foreach ( array( 'config' => PNCP_Bunny::CONFIG, 'rules' => PNCP_Bunny::RULES ) as $k => $opt ) {
	if ( null === $pf_saved[ $k ] ) {
		delete_option( $opt );
	} else {
		update_option( $opt, $pf_saved[ $k ], false );
	}
}
delete_option( PNCP_Bunny::CALLS );
if ( null !== $pf_saved['edge'] ) {
	add_option( PNCP_Edge::CONFIG, $pf_saved['edge'], '', false ); // add_option(): no "changed" hook.
}
delete_transient( PNCP_Health::FOLDERS_CACHE );
$GLOBALS['is_nginx']  = $pf_saved['nginx'];
$GLOBALS['is_apache'] = $pf_saved['apache'];

echo $fails ? "\n$fails FAIL\n" : "\nall PASS\n";
exit( $fails ? 1 : 0 );
