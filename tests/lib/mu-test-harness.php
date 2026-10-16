<?php
/**
 * ΜΟΝΟ ΓΙΑ ΔΟΚΙΜΕΣ (mu-plugin στο WordPress των tests, ποτέ σε πραγματικό site).
 *
 * - X-Test-IP: η IP του «επισκέπτη» (ο built-in server του PHP δίνει πάντα 127.0.0.1, που εξαιρείται).
 * - X-Test-RDNS: απάντηση reverse DNS (χωρίς δίκτυο στο περιβάλλον των tests).
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
