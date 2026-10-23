<?php
/**
 * ΜΟΝΟ ΓΙΑ ΔΟΚΙΜΕΣ (mu-plugin στο WordPress των tests, ποτέ σε πραγματικό site).
 *
 * - X-Test-IP: η IP του «επισκέπτη» (ο built-in server του PHP δίνει πάντα 127.0.0.1, που εξαιρείται).
 * - X-Test-RDNS: απάντηση reverse DNS (χωρίς δίκτυο στο περιβάλλον των tests).
 * - X-Test-Bunny-List: η λίστα edge servers του Bunny (JSON) αντί για το δίκτυο.
 * - Κανένα αίτημα HTTP προς wordpress.org (update checks).
 * - Post type «product» όπως του WooCommerce, για τα tests εικόνων προϊόντων.
 * - Ψεύτικο API της Cloudflare και του Bunny (αποκλεισμός στο CDN), όσο υπάρχει η επιλογή pncp_test_cdn.
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
		// Ψεύτικο API CDN: η κατάσταση ζει στην επιλογή pncp_test_cdn (ίδια για τα tests και τον server).
		if ( ( 0 === strpos( $url, 'https://api.cloudflare.com/' ) || 0 === strpos( $url, 'https://api.bunny.net/' ) ) && is_array( get_option( 'pncp_test_cdn' ) ) ) {
			return pncp_test_cdn( $args, $url );
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

/**
 * Ψεύτικη Cloudflare (IP Access rules) και Bunny (BlockedIps) για τα tests του αποκλεισμού στο CDN.
 * pncp_test_cdn: cf => [id => [value, target, notes]], bunny => [ip...], calls => [...], fail => 0 | 429 | 500.
 */
function pncp_test_cdn( $args, $url ) {
	$db      = get_option( 'pncp_test_cdn' );
	$db     += array( 'cf' => array(), 'bunny' => array(), 'calls' => array(), 'fail' => 0, 'next' => 1, 'refuse' => '' );
	$method  = isset( $args['method'] ) ? $args['method'] : 'GET';
	$headers = isset( $args['headers'] ) ? $args['headers'] : array();
	$body    = isset( $args['body'] ) ? json_decode( $args['body'], true ) : null;
	$db['calls'][] = $method . ' ' . $url;
	$reply   = static function ( $code, $data ) use ( &$db ) {
		update_option( 'pncp_test_cdn', $db, false );
		return array( 'headers' => array(), 'body' => wp_json_encode( $data ), 'response' => array( 'code' => $code, 'message' => '' ), 'cookies' => array(), 'filename' => null );
	};
	if ( $db['fail'] ) {
		return $reply( (int) $db['fail'], array( 'success' => false, 'errors' => array( array( 'code' => 1, 'message' => 'test failure' ) ) ) );
	}
	if ( 0 === strpos( $url, 'https://api.cloudflare.com/client/v4/zones/0123456789abcdef0123456789abcdef/firewall/access_rules/rules' ) ) {
		if ( ! isset( $headers['Authorization'] ) || 'Bearer cf-good-token-1234567890' !== $headers['Authorization'] ) {
			return $reply( 403, array( 'success' => false, 'errors' => array( array( 'code' => 10000, 'message' => 'Authentication error' ) ) ) );
		}
		$rest = (string) substr( $url, strlen( 'https://api.cloudflare.com/client/v4/zones/0123456789abcdef0123456789abcdef/firewall/access_rules/rules' ) );
		if ( 'GET' === $method ) {
			// ?configuration.value=… → the rules for that address (the test button looks itself up).
			parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
			$out = array();
			foreach ( $db['cf'] as $id => $rule ) {
				if ( isset( $q['configuration_value'] ) && $q['configuration_value'] === $rule['value'] ) {
					$out[] = array( 'id' => $id, 'mode' => $rule['mode'], 'configuration' => array( 'target' => $rule['target'], 'value' => $rule['value'] ) );
				}
			}
			return $reply( 200, array( 'success' => true, 'errors' => array(), 'result' => $out ) );
		}
		if ( 'POST' === $method && '' === $rest ) {
			$value = $body['configuration']['value'];
			if ( $db['refuse'] === $value ) {
				return $reply( 400, array( 'success' => false, 'errors' => array( array( 'code' => 10014, 'message' => 'invalid value' ) ) ) );
			}
			foreach ( $db['cf'] as $rule ) {
				if ( $rule['value'] === $value ) {
					return $reply( 400, array( 'success' => false, 'errors' => array( array( 'code' => 10009, 'message' => 'firewallaccessrules.api.duplicate_of_existing' ) ) ) );
				}
			}
			$id                = 'r' . $db['next']++;
			$db['cf'][ $id ] = array( 'value' => $value, 'target' => $body['configuration']['target'], 'mode' => $body['mode'], 'notes' => $body['notes'] );
			return $reply( 200, array( 'success' => true, 'errors' => array(), 'result' => array( 'id' => $id ) ) );
		}
		if ( 'DELETE' === $method && preg_match( '#^/([A-Za-z0-9]+)$#', $rest, $m ) ) {
			if ( ! isset( $db['cf'][ $m[1] ] ) ) {
				return $reply( 404, array( 'success' => false, 'errors' => array( array( 'code' => 10001, 'message' => 'not found' ) ) ) );
			}
			unset( $db['cf'][ $m[1] ] );
			return $reply( 200, array( 'success' => true, 'errors' => array(), 'result' => array( 'id' => $m[1] ) ) );
		}
	}
	if ( 0 === strpos( $url, 'https://api.bunny.net/pullzone/12345' ) ) {
		if ( ! isset( $headers['AccessKey'] ) || 'bunny-good-key-1234567890' !== $headers['AccessKey'] ) {
			return $reply( 401, array( 'ErrorKey' => 'unauthorized', 'Message' => 'Unauthorized' ) );
		}
		$rest = (string) substr( $url, strlen( 'https://api.bunny.net/pullzone/12345' ) );
		if ( 'GET' === $method && '' === $rest ) {
			return $reply( 200, array( 'Id' => 12345, 'BlockedIps' => array_values( $db['bunny'] ) ) );
		}
		if ( 'POST' === $method && '/addBlockedIp' === $rest ) {
			$db['bunny'][] = $body['BlockedIp'];
			return $reply( 204, array() );
		}
		if ( 'POST' === $method && '/removeBlockedIp' === $rest ) {
			$db['bunny'] = array_values( array_diff( $db['bunny'], array( $body['BlockedIp'] ) ) );
			return $reply( 204, array() );
		}
	}
	return $reply( 404, array( 'success' => false, 'errors' => array( array( 'code' => 7003, 'message' => 'Could not route' ) ), 'Message' => 'Not found' ) );
}
