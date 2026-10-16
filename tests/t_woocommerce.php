<?php
/**
 * ScrapeLock — συμβατότητα με πραγματικό WooCommerce (καλάθι, checkout, Store API, wc-ajax).
 *
 *   WP_DIR=/srv/wpt BASE=http://127.0.0.1:8080 php t_woocommerce.php
 *
 * Απαιτεί WooCommerce ενεργό και το mu-test-harness. Η πλήρης αγορά (προσθήκη στο καλάθι → checkout →
 * παραγγελία) γίνεται με τις ΠΙΟ ΑΥΣΤΗΡΕΣ ρυθμίσεις (όρια 3/λεπτό, αποκλεισμός από την πρώτη παράβαση,
 * «μόνο browsers», Emergency Mode): ένας πελάτης πρέπει να μπορεί πάντα να αγοράσει.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

if ( ! class_exists( 'WooCommerce' ) ) {
	echo "SKIP χωρίς WooCommerce\n";
	exit( 0 );
}

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
}

/** Ένας «πελάτης»: browser με cookies (συνεδρία WooCommerce), σταθερή IP. */
final class Shopper {
	public $ip;
	public $ua;
	private $jar;
	public function __construct( $ip, $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36' ) {
		$this->ip  = $ip;
		$this->ua  = $ua;
		$this->jar = tempnam( sys_get_temp_dir(), 'pncp-jar' );
	}
	public function req( $path, $method = 'GET', $body = null, $headers = array() ) {
		global $base;
		$ch = curl_init( $base . $path );
		$h  = array( 'User-Agent: ' . $this->ua, 'Accept-Language: el-GR,el;q=0.9', 'X-Test-IP: ' . $this->ip );
		foreach ( $headers as $k => $v ) {
			$h[] = $k . ': ' . $v;
		}
		$opts = array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER         => true,
			CURLOPT_HTTPHEADER     => $h,
			CURLOPT_COOKIEJAR      => $this->jar,
			CURLOPT_COOKIEFILE     => $this->jar,
			CURLOPT_CUSTOMREQUEST  => $method,
			CURLOPT_TIMEOUT        => 60,
		);
		if ( null !== $body ) {
			$opts[ CURLOPT_POSTFIELDS ] = is_array( $body ) ? http_build_query( $body ) : $body;
		}
		curl_setopt_array( $ch, $opts );
		$out  = (string) curl_exec( $ch );
		$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
		curl_close( $ch );
		return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
	}
}

function header_value( $headers, $name ) {
	return preg_match( '/^' . preg_quote( strtolower( $name ), '/' ) . ':\s*(.+)$/m', $headers, $m ) ? trim( $m[1] ) : '';
}

/* ---------- Κατάστημα ---------- */
update_option( 'woocommerce_cod_settings', array( 'enabled' => 'yes', 'title' => 'Αντικαταβολή' ) );
update_option( 'woocommerce_default_country', 'GR' );
update_option( 'woocommerce_currency', 'EUR' );
WC()->payment_gateways()->init();
$product_id = (int) get_option( 'pncp_test_product' );
if ( ! $product_id || ! wc_get_product( $product_id ) ) {
	$p = new WC_Product_Simple();
	$p->set_name( 'Βιταμίνη C 1000mg' );
	$p->set_regular_price( '9.90' );
	$p->set_description( '<p>Πλήρης περιγραφή προϊόντος, πολύτιμο κείμενο που δεν πρέπει να αντιγραφεί μαζικά.</p>' );
	$p->set_short_description( 'Σύντομη περιγραφή.' );
	$p->set_status( 'publish' );
	$product_id = $p->save();
	update_option( 'pncp_test_product', $product_id );
}
$product_path = wp_parse_url( get_permalink( $product_id ), PHP_URL_PATH );

function strictest() {
	PNCP_Log::unban_all();
	settings(
		array(
			'enabled'                 => 1,
			'exempt_cap'              => 'edit_posts',
			'rate_limit'              => 3,
			'rate_limit_search'       => 3,
			'rate_limit_rest'         => 3,
			'ban_strikes'             => 1,
			'ban_minutes'             => 60,
			'require_browser_headers' => 1,
			'block_framing'           => 1,
			'skip_woo_pages'          => 1,
			'watermark_enabled'       => 1,
			'watermark_products'      => 0,
		)
	);
}

/** Πλήρης αγορά. Επιστρέφει [οκ, μήνυμα]. */
function purchase( Shopper $c, $product_id, $product_path, $label ) {
	list( $code, , $body ) = $c->req( $product_path );
	t( "$label: σελίδα προϊόντος 200 με προστασία", 200 === $code && false !== strpos( $body, 'assets/js/protect.js' ), (string) $code );

	list( $code, , $body ) = $c->req( '/?wc-ajax=add_to_cart', 'POST', array( 'product_id' => $product_id, 'quantity' => 2 ), array( 'X-Requested-With' => 'XMLHttpRequest' ) );
	$json = json_decode( $body, true );
	t( "$label: wc-ajax add_to_cart", 200 === $code && is_array( $json ) && empty( $json['error'] ) && ! empty( $json['fragments'] ), $code . ' ' . substr( $body, 0, 120 ) );

	for ( $i = 0; $i < 4; $i++ ) {
		list( $code ) = $c->req( '/?wc-ajax=get_refreshed_fragments', 'POST', array( 'time' => time() ) );
	}
	t( "$label: get_refreshed_fragments ×4 (πάνω από το όριο 3) χωρίς 429", 200 === $code, (string) $code );

	list( $code, $hdr, $body ) = $c->req( '/wp-json/wc/store/v1/cart' );
	$cart  = json_decode( $body, true );
	$nonce = header_value( $hdr, 'Nonce' );
	t( "$label: Store API καλάθι με 2 τεμάχια", 200 === $code && isset( $cart['items_count'] ) && 2 === (int) $cart['items_count'], $code . ' ' . substr( $body, 0, 120 ) );
	for ( $i = 0; $i < 5; $i++ ) {
		list( $code ) = $c->req( '/wp-json/wc/store/v1/cart' );
	}
	t( "$label: Store API ×5 (mini-cart) χωρίς 429", 200 === $code, (string) $code );

	list( $code, $hdr, $body ) = $c->req( wp_parse_url( wc_get_cart_url(), PHP_URL_PATH ) );
	t( "$label: σελίδα καλαθιού 200, χωρίς προστασία αντιγραφής", 200 === $code && false === strpos( $body, 'assets/js/protect.js' ), (string) $code );
	list( $code, $hdr, $body ) = $c->req( wp_parse_url( wc_get_checkout_url(), PHP_URL_PATH ) );
	// Στο ταμείο το ίδιο το WooCommerce στέλνει X-Frame-Options και CSP «frame-ancestors 'self';» (με ;),
	// μέσω του send_frame_options_header() του WordPress. Το plugin δεν προσθέτει δικό του (χωρίς ;).
	t( "$label: σελίδα ταμείου 200, χωρίς το header iframe του plugin", 200 === $code && ! preg_match( "/frame-ancestors 'self'\r?$/m", $hdr ), $code );

	$address = array(
		'first_name' => 'Μαρία',
		'last_name'  => 'Παπαδοπούλου',
		'address_1'  => 'Ερμού 1',
		'city'       => 'Αθήνα',
		'postcode'   => '10563',
		'country'    => 'GR',
		'state'      => 'I',
		'email'      => 'maria@example.test',
		'phone'      => '2101234567',
	);
	list( $code, , $body ) = $c->req(
		'/wp-json/wc/store/v1/checkout',
		'POST',
		wp_json_encode(
			array(
				'billing_address'  => $address,
				'shipping_address' => array_diff_key( $address, array_flip( array( 'email' ) ) ),
				'payment_method'   => 'cod',
			)
		),
		array( 'Content-Type' => 'application/json', 'Nonce' => $nonce )
	);
	$order = json_decode( $body, true );
	$ok    = 200 === $code && ! empty( $order['order_id'] );
	t( "$label: checkout (Store API) δημιουργεί παραγγελία", $ok, $code . ' ' . substr( $body, 0, 200 ) );
	if ( $ok ) {
		$wc_order = wc_get_order( (int) $order['order_id'] );
		t( "$label: η παραγγελία υπάρχει, 19.80 €", $wc_order && abs( (float) $wc_order->get_total() - 19.80 ) < 0.01, $wc_order ? (string) $wc_order->get_total() : 'none' );
		$thanks = isset( $order['payment_result']['redirect_url'] ) ? (string) $order['payment_result']['redirect_url'] : '';
		if ( $thanks ) {
			list( $code, $hdr ) = $c->req( wp_parse_url( $thanks, PHP_URL_PATH ) . '?' . wp_parse_url( $thanks, PHP_URL_QUERY ) );
			t( "$label: σελίδα «Ευχαριστούμε» 200 (δεν μετρά στο όριο), χωρίς το header iframe του plugin", 200 === $code && ! preg_match( "/frame-ancestors 'self'\r?$/m", $hdr ), (string) $code );
		}
	}
	wp_cache_flush(); PNCP_Log::reset_cache();
	t( "$label: ο πελάτης δεν αποκλείστηκε", ! PNCP_Log::is_banned( $c->ip ) );
}

/* ---------- Αγορά με τις αυστηρότερες ρυθμίσεις ---------- */
strictest();
purchase( new Shopper( '203.0.113.101' ), $product_id, $product_path, 'αυστηρό' );

PNCP_Options::set_emergency( 1 );
strictest();
purchase( new Shopper( '203.0.113.102' ), $product_id, $product_path, 'Emergency Mode' );
PNCP_Options::set_emergency( 0 );

/* ---------- Bots στο κατάστημα ---------- */
strictest();
$bot = new Shopper( '198.51.100.110', 'python-requests/2.32' );
list( $code ) = $bot->req( '/?wc-ajax=add_to_cart', 'POST', array( 'product_id' => $product_id, 'quantity' => 1 ) );
t( 'bot στο wc-ajax add_to_cart: 403', 403 === $code, (string) $code );
list( $code ) = $bot->req( '/wp-json/wc/store/v1/products' );
t( 'bot στο Store API (προϊόντα): 403', 403 === $code, (string) $code );
$scraper = new Shopper( '198.51.100.111' );
$codes   = array();
for ( $i = 0; $i < 5; $i++ ) {
	$codes[] = $scraper->req( $product_path . '?p' . $i )[0];
}
t( 'scraper που ανοίγει σελίδες προϊόντων γρήγορα: 429 και αποκλεισμός', in_array( 429, $codes, true ) && 403 === end( $codes ), implode( ',', $codes ) );

PNCP_Log::unban_all();
$codes = array();
$sneaky = new Shopper( '198.51.100.112' );
for ( $i = 0; $i < 5; $i++ ) {
	$codes[] = $sneaky->req( $product_path . '?orders=1&p' . $i )[0];
}
t( 'scraper με ?orders=1 (μεταβλητή endpoint του WooCommerce) δεν παρακάμπτει το όριο', in_array( 429, $codes, true ) || in_array( 403, $codes, true ), implode( ',', $codes ) );

/* ---------- Store API: χωρίς περιγραφές για επισκέπτες ---------- */
PNCP_Log::unban_all();
settings( array( 'rate_limit_rest' => 0 ) );
list( $code, , $body ) = ( new Shopper( '203.0.113.103' ) )->req( '/wp-json/wc/store/v1/products/' . $product_id );
$json = json_decode( $body, true );
t( 'Store API προϊόν: description και short_description κενά για επισκέπτη', 200 === $code && '' === $json['description'] && '' === $json['short_description'] && '9.90' === wc_format_decimal( $json['prices']['price'] / 100, 2 ), $code . ' ' . substr( $body, 0, 100 ) );
list( $code, , $body ) = ( new Shopper( '203.0.113.104' ) )->req( '/wp-json/wc/store/v1/products?per_page=5' );
$json = json_decode( $body, true );
t( 'Store API λίστα προϊόντων: χωρίς περιγραφές, με τίτλους και τιμές', 200 === $code && is_array( $json ) && $json && '' === $json[0]['description'] && '' !== $json[0]['name'], (string) $code );

/* ---------- Webhooks πληρωμών ---------- */
$gateway = new Shopper( '198.51.100.120', 'Go-http-client/1.1' );
list( $code, , $body ) = $gateway->req( '/wc-api/pncp_test/', 'POST', 'event=paid' );
t( 'webhook πληρωμής (wc-api, POST, User-Agent Go-http-client): όχι 403 από το plugin', false === strpos( $body, 'Access denied.' ), (string) $code );
list( $code, , $body ) = $gateway->req( '/wp-json/wc/v3/webhooks-test', 'POST', '{}', array( 'Content-Type' => 'application/json' ) );
t( 'webhook στο REST (POST): όχι 403 από το plugin', false === strpos( $body, 'pncp_' ), $code . ' ' . substr( $body, 0, 80 ) );

/* ---------- Εικόνες προϊόντων ---------- */
require_once ABSPATH . 'wp-admin/includes/image.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
require_once ABSPATH . 'wp-admin/includes/media.php';
$img  = imagecreatetruecolor( 800, 600 );
$file = get_temp_dir() . 'pncp-wc-' . wp_generate_password( 5, false ) . '.png';
imagepng( $img, $file );
$att = media_handle_sideload( array( 'name' => basename( $file ), 'tmp_name' => $file ), $product_id );
t( 'εικόνα που ανεβαίνει σε προϊόν WooCommerce: χωρίς υδατογράφημα', ! is_wp_error( $att ) && '' === get_post_meta( $att, PNCP_Watermark::META, true ) );

settings( array( 'rate_limit' => 0, 'rate_limit_search' => 0, 'rate_limit_rest' => 0, 'ban_strikes' => 3, 'require_browser_headers' => 0, 'watermark_enabled' => 0 ) );
PNCP_Log::unban_all();
echo $fails ? "\n$fails FAIL\n" : "\nΟΛΑ PASS\n";
exit( $fails ? 1 : 0 );
