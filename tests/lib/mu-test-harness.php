<?php
/**
 * ΜΟΝΟ ΓΙΑ ΔΟΚΙΜΕΣ (mu-plugin στο WordPress των tests, ποτέ σε πραγματικό site).
 *
 * - X-Test-IP: η IP του «επισκέπτη» (ο built-in server του PHP δίνει πάντα 127.0.0.1, που εξαιρείται).
 * - X-Test-RDNS: απάντηση reverse DNS (χωρίς δίκτυο στο περιβάλλον των tests).
 * - X-Test-Bunny-List: η λίστα edge servers του Bunny (JSON) αντί για το δίκτυο.
 * - Κανένα αίτημα HTTP προς wordpress.org (update checks).
 * - Post type «product» όπως του WooCommerce, για τα tests εικόνων προϊόντων.
 */

add_filter(
	'pncp_client_ip',
	static function ( $ip ) {
		return isset( $_SERVER['HTTP_X_TEST_IP'] ) ? $_SERVER['HTTP_X_TEST_IP'] : ( getenv( 'PNCP_TEST_IP' ) ?: $ip );
	}
);
add_filter(
	'pncp_reverse_dns',
	static function ( $host, $ip ) {
		return isset( $_SERVER['HTTP_X_TEST_RDNS'] ) ? $_SERVER['HTTP_X_TEST_RDNS'] : 'unknown.invalid';
	},
	10,
	2
);
add_filter(
	'pncp_forward_dns',
	static function ( $ips, $host ) {
		return isset( $_SERVER['HTTP_X_TEST_FDNS'] ) ? explode( ',', $_SERVER['HTTP_X_TEST_FDNS'] ) : array();
	},
	10,
	2
);
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) {
		if ( false !== strpos( $url, 'wordpress.org' ) ) {
			return new WP_Error( 'test', 'no network in tests' );
		}
		// X-Test-Bunny-List: η «επίσημη» λίστα του Bunny (JSON), χωρίς δίκτυο.
		if ( false !== strpos( $url, 'bunnycdn.com' ) && isset( $_SERVER['HTTP_X_TEST_BUNNY_LIST'] ) ) {
			$body = false !== stripos( $url, 'ipv6' ) ? '["2400:52e0:1a00::1"]' : wp_unslash( $_SERVER['HTTP_X_TEST_BUNNY_LIST'] );
			return array( 'headers' => array(), 'body' => $body, 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => null );
		}
		return $pre;
	},
	10,
	3
);
add_action(
	'init',
	static function () {
		if ( ! post_type_exists( 'product' ) ) {
			register_post_type( 'product', array( 'public' => true, 'show_in_rest' => true ) );
		}
	}
);

// X-Test-WC: προσομοίωση ενεργού WooCommerce με μία δηλωμένη ενέργεια wc-ajax (test_ok).
if ( isset( $_SERVER['HTTP_X_TEST_WC'] ) && ! class_exists( 'WooCommerce' ) && ! in_array( 'woocommerce/woocommerce.php', (array) get_option( 'active_plugins', array() ), true ) ) {
	eval( 'class WooCommerce {}' );
	add_action( 'wc_ajax_test_ok', '__return_true' );
}

// Ο ίδιος WordPress σερβίρεται και από δεύτερο server (Apache στη θύρα 8081) για τις δοκιμές κανόνων.
if ( isset( $_SERVER['SERVER_PORT'], $_SERVER['HTTP_HOST'] ) && '8081' === (string) $_SERVER['SERVER_PORT'] ) {
	$pncp_test_url = 'http://' . $_SERVER['HTTP_HOST'];
	add_filter( 'option_home', static function () use ( $pncp_test_url ) { return $pncp_test_url; } );
	add_filter( 'option_siteurl', static function () use ( $pncp_test_url ) { return $pncp_test_url; } );
}

// Ένα «feed» που φτιάχνει η PHP (όπως τα plugins XML για Skroutz): /skroutz.xml → 200 XML.
add_action(
	'template_redirect',
	static function () {
		$path = (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH );
		if ( '/skroutz.xml' === untrailingslashit( $path ) ) {
			status_header( 200 );
			header( 'Content-Type: application/xml; charset=utf-8' );
			echo '<?xml version="1.0"?><products><product>ΤΙΜΟΚΑΤΑΛΟΓΟΣ</product></products>';
			exit;
		}
	},
	5
);

// Ο πρώιμος έλεγχος (scrapelock-early.php) σταματά το αίτημα πριν από το muplugins_loaded: χωρίς αυτό το header
// ξέρουμε ότι το 403 ήρθε από εκεί και όχι από τον κανονικό έλεγχο.
add_action(
	'muplugins_loaded',
	static function () {
		if ( ! headers_sent() ) {
			header( 'X-Test-Muplugins-Loaded: 1' );
		}
	}
);

// X-Test-Remote-Addr: το REMOTE_ADDR του αιτήματος (π.χ. διεύθυνση της Cloudflare), για τη σελίδα ρυθμίσεων.
if ( isset( $_SERVER['HTTP_X_TEST_REMOTE_ADDR'] ) ) {
	$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_TEST_REMOTE_ADDR'];
}

// X-Test-HTTPS: το αίτημα θεωρείται HTTPS (ο built-in server του PHP σερβίρει μόνο HTTP).
if ( isset( $_SERVER['HTTP_X_TEST_HTTPS'] ) ) {
	$_SERVER['HTTPS'] = 'on';
}

// X-Test-Rocket: προσομοίωση του WP Rocket. Το rocket_generate_config_file() υπάρχει από την αρχή, αλλά καλεί
// συνάρτηση που ορίζεται στο plugins_loaded (όπως στο πραγματικό): αν κληθεί νωρίτερα, Fatal error.
if ( isset( $_SERVER['HTTP_X_TEST_ROCKET'] ) && ! function_exists( 'rocket_generate_config_file' ) ) {
	function rocket_generate_config_file() {
		get_rocket_cache_reject_uri();
		update_option( 'pncp_test_rocket_config', time(), false );
	}
	add_action(
		'plugins_loaded',
		static function () {
			if ( ! function_exists( 'get_rocket_cache_reject_uri' ) ) {
				function get_rocket_cache_reject_uri() {
					return '';
				}
			}
		}
	);
}
