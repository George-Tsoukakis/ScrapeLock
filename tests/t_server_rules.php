<?php
/**
 * ScrapeLock — οι κανόνες της καρτέλας «Κανόνες server» σε πραγματικό Nginx και Apache.
 *
 *   WP_DIR=/srv/wpt NGINX_URL=http://127.0.0.1:8080 APACHE_URL=http://127.0.0.1:8081 php t_server_rules.php
 *
 * Προϋποθέσεις (βλ. README.txt): Nginx με `include /etc/nginx/pncp-rules.conf;` μέσα στο server { } του
 * site και Apache με AllowOverride All στον ίδιο φάκελο. Τρέχει ως root: γράφει στο /etc/nginx και
 * κάνει reload. ΜΟΝΟ σε μηχάνημα δοκιμών.
 */

$wp_dir = getenv( 'WP_DIR' );
$nginx  = rtrim( (string) getenv( 'NGINX_URL' ), '/' );
$apache = rtrim( (string) getenv( 'APACHE_URL' ), '/' );
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

/** Αίτημα χωρίς X-Test-IP: η IP είναι 127.0.0.1, οπότε το plugin δεν μπλοκάρει· ό,τι 403 έρθει είναι του server. */
function get( $url, $headers = array() ) {
	$ch = curl_init( $url );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $h, CURLOPT_TIMEOUT => 30 ) );
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

$browser = array( 'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36', 'Accept-Language' => 'el', 'Accept' => 'text/html' );

/* ---------- Δεδομένα ---------- */
$s                  = PNCP_Options::stored();
$s['enabled']       = 1;
$s['block_bots']    = 1;
$s['private_paths'] = "/skroutz.xml\n/static-feed.xml";
$s['bot_list']      = PNCP_Options::default_bot_list();
$s['allow_list']    = PNCP_Options::default_allow_list();
update_option( PNCP_OPTION, $s );
PNCP_Options::flush();
$token = PNCP_Private_Urls::rotate( 0 );
file_put_contents( ABSPATH . 'static-feed.xml', '<?xml version="1.0"?><feed>στατικό</feed>' );
$backup_dir = PNCP_Watermark::backup_dir();
file_put_contents( $backup_dir . 'secret.txt', 'καθαρό πρωτότυπο' );
$uploads = wp_get_upload_dir();
$img     = imagecreatetruecolor( 20, 20 );
imagejpeg( $img, $uploads['basedir'] . '/hotlink-test.jpg' );
$img_path    = wp_parse_url( $uploads['baseurl'], PHP_URL_PATH ) . '/hotlink-test.jpg';
$backup_path = wp_parse_url( $uploads['baseurl'], PHP_URL_PATH ) . '/' . basename( $backup_dir ) . '/secret.txt';

/* ---------- Nginx ---------- */
file_put_contents( '/etc/nginx/conf.d/pncp-http.conf', str_replace( 'YOUR_TOKEN', $token, PNCP_Rules::nginx_http() ) );
file_put_contents( '/etc/nginx/pncp-rules.conf', str_replace( 'YOUR_TOKEN', $token, PNCP_Rules::nginx_server() ) );
exec( 'nginx -t 2>&1', $out, $rc );
t( 'Nginx: nginx -t δέχεται τους κανόνες', 0 === $rc, implode( ' | ', $out ) );
exec( 'nginx -s reload 2>&1' );
usleep( 700000 );

list( $code ) = get( $nginx . '/hello-world/', $browser );
t( 'Nginx: browser 200', 200 === $code, (string) $code );
list( $code, $body ) = get( $nginx . '/hello-world/', array( 'User-Agent' => 'Mozilla/5.0 (compatible; GPTBot/1.2)' ) );
t( 'Nginx: GPTBot 403 από τον ίδιο τον Nginx (πριν από PHP / cache)', 403 === $code && false !== stripos( $body, 'nginx' ), (string) $code );
list( $code ) = get( $nginx . '/wp-includes/js/jquery/jquery.min.js', array( 'User-Agent' => 'python-requests/2.32' ) );
t( 'Nginx: bot και σε στατικά αρχεία', 403 === $code, (string) $code );
list( $code ) = get( $nginx . '/hello-world/', array( 'User-Agent' => '' ) );
t( 'Nginx: χωρίς User-Agent 403', 403 === $code, (string) $code );
list( $code ) = get( $nginx . '/hello-world/', array( 'User-Agent' => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)' ) );
t( 'Nginx: preview του Facebook περνά (πάντα επιτρεπτά πριν από τα bots)', 200 === $code, (string) $code );
list( $code ) = get( $nginx . '/hello-world/', array( 'User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' ) );
t( 'Nginx: Googlebot δεν μπλοκάρεται από τους κανόνες', 200 === $code, (string) $code );
list( $code ) = get( $nginx . $backup_path, $browser );
t( 'Nginx: φάκελος καθαρών πρωτοτύπων 404', 404 === $code, (string) $code );
list( $code ) = get( $nginx . $img_path, $browser + array( 'Referer' => 'https://scraper.example/page' ) );
t( 'Nginx: hotlink από ξένο site 403', 403 === $code, (string) $code );
foreach ( array( '' => 'χωρίς Referer', 'https://www.google.com/' => 'Google', 'https://www.skroutz.gr/s/123' => 'Skroutz', 'http://127.0.0.1:8080/hello-world/' => 'το ίδιο site' ) as $ref => $label ) {
	list( $code ) = get( $nginx . $img_path, $browser + ( $ref ? array( 'Referer' => $ref ) : array() ) );
	t( "Nginx: εικόνα με Referer $label 200", 200 === $code, (string) $code );
}
list( $code ) = get( $nginx . '/static-feed.xml', $browser );
t( 'Nginx: στατικό feed χωρίς token 403', 403 === $code, (string) $code );
list( $code, $body ) = get( $nginx . '/static-feed.xml?cp_token=' . $token, $browser );
t( 'Nginx: στατικό feed με token στο URL 200', 200 === $code && false !== strpos( $body, 'στατικό' ), (string) $code );
list( $code ) = get( $nginx . '/static-feed.xml', $browser + array( 'X-ScrapeLock-Token' => $token ) );
t( 'Nginx: στατικό feed με token στο header 200', 200 === $code, (string) $code );
list( $code, $body ) = get( $nginx . '/skroutz.xml?cp_token=' . $token, $browser + array( 'X-Test-IP' => '203.0.113.89' ) );
t( 'Nginx: feed της PHP με token στο URL → φτάνει στο WordPress και δίνει το XML (όχι 404 του Nginx)', 200 === $code && false !== strpos( $body, 'ΤΙΜΟΚΑΤΑΛΟΓΟΣ' ), (string) $code );
list( $code, $body ) = get( $nginx . '/skroutz.xml', $browser + array( 'X-Test-IP' => '203.0.113.88', 'Authorization' => 'Bearer ' . $token ) );
t( 'Nginx: feed της PHP με Authorization: Bearer → XML', 200 === $code && false !== strpos( $body, 'ΤΙΜΟΚΑΤΑΛΟΓΟΣ' ), (string) $code );
list( $code, $body ) = get( $nginx . '/skroutz.xml', $browser + array( 'X-Test-IP' => '203.0.113.90' ) );
t( 'Nginx: feed της PHP χωρίς token → το ελέγχει το WordPress (403 του plugin)', 403 === $code && 0 === strpos( trim( $body ), 'Forbidden' ), (string) $code );

/* ---------- Apache (.htaccess) ---------- */
$wp_block = file_get_contents( ABSPATH . '.htaccess.wp' );
file_put_contents( ABSPATH . '.htaccess', str_replace( 'YOUR_TOKEN', $token, PNCP_Rules::apache() ) . "\n" . $wp_block );
list( $code ) = get( $apache . '/hello-world/', $browser );
t( 'Apache: το .htaccess είναι έγκυρο (browser 200, όχι 500)', 200 === $code, (string) $code );
list( $code, $body ) = get( $apache . '/hello-world/', array( 'User-Agent' => 'Mozilla/5.0 (compatible; GPTBot/1.2)' ) );
t( 'Apache: GPTBot 403 από τον Apache', 403 === $code && false !== stripos( $body, 'apache' ), (string) $code );
list( $code ) = get( $apache . '/hello-world/', array( 'User-Agent' => 'Mozilla/5.0 (compatible; Claude-SearchBot/1.0)' ) );
t( 'Apache: bot με κενό στο όνομα της λίστας («Kangaroo Bot») δεν σπάει το regex', 403 === $code, (string) $code );
list( $code ) = get( $apache . '/hello-world/', array( 'User-Agent' => 'facebookexternalhit/1.1' ) );
t( 'Apache: preview του Facebook περνά', 200 === $code, (string) $code );
list( $code ) = get( $apache . '/hello-world/', array( 'User-Agent' => '' ) );
t( 'Apache: χωρίς User-Agent 403', 403 === $code, (string) $code );
list( $code ) = get( $apache . $backup_path, $browser );
t( 'Apache: φάκελος καθαρών πρωτοτύπων 403', 403 === $code, (string) $code );
list( $code ) = get( $apache . $img_path, $browser + array( 'Referer' => 'https://scraper.example/' ) );
t( 'Apache: hotlink από ξένο site 403', 403 === $code, (string) $code );
list( $code ) = get( $apache . $img_path, $browser + array( 'Referer' => 'https://www.bestprice.gr/item/1' ) );
t( 'Apache: εικόνα από BestPrice 200', 200 === $code, (string) $code );
list( $code ) = get( $apache . $img_path, $browser );
t( 'Apache: εικόνα χωρίς Referer 200', 200 === $code, (string) $code );
list( $code ) = get( $apache . '/static-feed.xml', $browser );
t( 'Apache: στατικό feed χωρίς token 403', 403 === $code, (string) $code );
list( $code ) = get( $apache . '/static-feed.xml?cp_token=' . $token, $browser );
t( 'Apache: στατικό feed με token 200', 200 === $code, (string) $code );
list( $code, $body ) = get( $apache . '/skroutz.xml', $browser + array( 'X-Test-IP' => '203.0.113.91', 'Authorization' => 'Bearer ' . $token ) );
t( 'Apache: feed της PHP με Authorization: Bearer → XML', 200 === $code && false !== strpos( $body, 'ΤΙΜΟΚΑΤΑΛΟΓΟΣ' ), (string) $code );
list( $code, $body ) = get( $apache . '/skroutz.xml', $browser + array( 'X-Test-IP' => '203.0.113.92' ) );
t( 'Apache: feed της PHP χωρίς token → 403 του plugin, όχι του Apache', 403 === $code && 0 === strpos( trim( $body ), 'Forbidden' ), (string) $code );
file_put_contents( ABSPATH . '.htaccess', $wp_block );

/* ---------- Cloudflare: έλεγχος σύνταξης των εκφράσεων ---------- */
$fields = array( 'http.host', 'http.user_agent', 'cf.client.bot', 'http.request.uri.path', 'http.request.uri.path.extension', 'http.referer', 'http.request.uri.query', 'http.cookie', 'cf.verified_bot_category' );
foreach ( PNCP_Rules::cloudflare() as $key => $rule ) {
	$e        = $rule['expression'];
	$no_str   = preg_replace( '/"(?:[^"\\\\]|\\\\.)*"/', '""', $e );
	$balanced = substr_count( $no_str, '(' ) === substr_count( $no_str, ')' ) && substr_count( $no_str, '{' ) === substr_count( $no_str, '}' ) && 0 === substr_count( $e, '"' ) % 2;
	preg_match_all( '/\b(?:http|cf)\.[a-z_.]+/', $no_str, $m );
	$unknown = array_diff( array_unique( $m[0] ), $fields );
	t( "Cloudflare $key: ισορροπημένες παρενθέσεις/εισαγωγικά και γνωστά πεδία", $balanced && ! $unknown && strlen( $e ) < 4096, implode( ',', $unknown ) . ' len=' . strlen( $e ) );
}

/* ---------- Καθάρισμα ---------- */
file_put_contents( '/etc/nginx/pncp-rules.conf', "# empty\n" );
@unlink( '/etc/nginx/conf.d/pncp-http.conf' );
exec( 'nginx -s reload 2>&1' );
unlink( ABSPATH . 'static-feed.xml' );

echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
