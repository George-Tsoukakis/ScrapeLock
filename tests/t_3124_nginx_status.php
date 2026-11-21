<?php
/**
 * ScrapeLock 3.12.4 — the "installed / up to date" status of the server rules asks the server itself.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI=wp] php t_3124_nginx_status.php
 *
 * On the live site (aaPanel, Nginx, Bunny CDN in front) the Server rules tab read "Not installed" although part 2
 * was in the site's server { }: the check asked its address through the public address, i.e. the CDN (another
 * server { } behind Bunny's Host header, a cached 404).
 *
 * O. Order: the server directly first (CURLOPT_RESOLVE entry, signed, the self-check User-Agent, a short
 *    timeout), then the public address; the way that answered is kept; the fingerprint header of the site's own
 *    pages when the check address has none; kept 5 minutes, asked again for a 3.12.3 answer; http:// → https://.
 * K. What answered instead: the fingerprint (current / stale), WordPress's 404, Nginx's own 404, the CDN's cache,
 *    the CDN only (the server not reachable), nothing at all, something else.
 * R. Real Nginx (SKIP without nginx on PATH): an aaPanel-like server { } with location ~ \.well-known: the
 *    exact location of part 2 wins at server level, in the extension include at the top, and nested in
 *    location / { }; without part 2 Nginx's own 404 answers; part 2 in http { } or twice fails nginx -t; the
 *    status reads "current" through the real Nginx.
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
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/screen.php';
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

const ORIGIN_IPS = array( '127.0.0.1', '192.0.2.10' );

$saved = array();
foreach ( array( PNCP_Rules_State::STATE, PNCP_Self_Check::LOG, PNCP_Self_Check::LAST ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}
register_shutdown_function(
	static function () use ( $saved ) {
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, false );
			}
		}
		delete_transient( PNCP_Rules_Status::NGINX );
		delete_transient( PNCP_Self_Check::ROUTE );
	}
);
delete_option( PNCP_Rules_State::STATE );
delete_transient( PNCP_Self_Check::ROUTE );
add_filter(
	'pncp_selfcheck_origin_ips',
	static function () {
		return ORIGIN_IPS;
	}
);

/** An answer of wp_remote_request(). */
function resp( $code, $headers = array(), $body = '' ) {
	return array(
		'headers'  => $headers,
		'body'     => $body,
		'response' => array(
			'code'    => $code,
			'message' => '',
		),
		'cookies'  => array(),
		'filename' => null,
	);
}

const NGINX_404 = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
const WP_404    = '<!DOCTYPE html><html lang="en-US"><head><link rel="stylesheet" href="/wp-content/themes/x/style.css"></head><body class="error404 wp-theme-x"><h1>Page not found</h1></body></html>';

/*
 * The mock: $route( $where, $url, $args ) answers each request; $where is the server address (origin) or
 * "public". Every request is noted.
 */
$log   = array();
$route = null;
add_filter(
	'pre_http_request',
	static function ( $pre, $args, $url ) use ( &$log, &$route ) {
		if ( false !== $pre || null === $route ) {
			return $pre;
		}
		$where = 'public';
		if ( ! empty( $args['pncp_resolve'] ) ) {
			$parts = explode( ':', (string) $args['pncp_resolve'], 3 );
			$where = trim( (string) end( $parts ), '[]' );
		}
		$sig   = isset( $args['headers'][ PNCP_Server_Ips::SIG_HEADER ] ) ? (string) $args['headers'][ PNCP_Server_Ips::SIG_HEADER ] : '';
		$log[] = array(
			'where'   => $where,
			'path'    => (string) wp_parse_url( $url, PHP_URL_PATH ),
			'scheme'  => (string) wp_parse_url( $url, PHP_URL_SCHEME ),
			'ua'      => isset( $args['user-agent'] ) ? (string) $args['user-agent'] : '',
			'sig'     => $sig,
			'public'  => ! empty( $args['pncp_public'] ),
			'resolve' => isset( $args['pncp_resolve'] ) ? (string) $args['pncp_resolve'] : '',
			'timeout' => isset( $args['timeout'] ) ? (float) $args['timeout'] : 0,
			'redir'   => isset( $args['redirection'] ) ? (int) $args['redirection'] : -1,
		);
		$answer = $route( $where, $url, $args, PNCP_Self_Check::request_id( $sig ) );
		return null === $answer ? new WP_Error( 'http_request_failed', 'cURL error 7: Failed to connect' ) : $answer;
	},
	1,
	3
);

/** Runs the status with a route; returns [status, log]. */
function status_with( $fn ) {
	global $log, $route;
	$log   = array();
	$route = $fn;
	delete_transient( PNCP_Rules_Status::NGINX );
	$st    = PNCP_Rules::nginx_status( true );
	$route = null;
	return array( $st, $log );
}

$fp    = PNCP_Rules::nginx_fingerprint();
$check = PNCP_Rules::nginx_check_path();
list( $fp_http, $fp_server ) = explode( ' ', $fp );
$is_check = static function ( $url ) use ( $check ) {
	return wp_parse_url( $url, PHP_URL_PATH ) === $check;
};
$fp_answer = static function ( $body ) {
	return resp( 200, array( 'content-type' => 'text/plain', 'cache-control' => 'no-store' ), $body . "\n" );
};
/** A page of this WordPress for its own request (X-ScrapeLock: ok id=…), with the fingerprint header or not. */
$own_page = static function ( $id, $header = '' ) {
	$h = array(
		'content-type' => 'text/html; charset=UTF-8',
		'x-scrapelock' => PNCP_Self_Check::ok_marker( $id ),
	);
	if ( '' !== $header ) {
		$h['x-scrapelock-rules'] = $header;
	}
	return resp( 200, $h, '<!doctype html><html><body>page</body></html>' );
};

/* ---------- O. The server first, then the public address ---------- */

list( $st, $l ) = status_with(
	static function ( $where, $url ) use ( $is_check, $fp_answer, $fp ) {
		return '127.0.0.1' === $where && $is_check( $url ) ? $fp_answer( $fp ) : null;
	}
);
t( 'O the server answers the fingerprint: "current", by way of the server (127.0.0.1)', 'current' === $st['state'] && 'origin' === $st['via'] && '127.0.0.1' === $st['ip'] && 'fingerprint' === $st['kind'], wp_json_encode( $st ) );
t( 'O ...one request only: straight to the server, nothing through the public address', 1 === count( $l ) && '127.0.0.1' === $l[0]['where'], wp_json_encode( $l ) );
$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
t( 'O ...the site\'s host and port pinned to the address (CURLOPT_RESOLVE entry), the check address with ?t=', isset( $l[0] ) && 0 === strpos( $l[0]['resolve'], $host . ':' ) && '127.0.0.1' === substr( $l[0]['resolve'], -9 ) && $check === $l[0]['path'] );
t( 'O ...signed, the self-check User-Agent, no redirects, a short timeout', isset( $l[0] ) && '' !== $l[0]['sig'] && PNCP_Self_Check::user_agent() === $l[0]['ua'] && 0 === $l[0]['redir'] && $l[0]['timeout'] <= PNCP_Rules_Status::ORIGIN_TIMEOUT );

list( $st, $l ) = status_with(
	static function ( $where, $url ) use ( $is_check, $fp_answer, $fp ) {
		return 'public' === $where && $is_check( $url ) ? $fp_answer( $fp ) : null;
	}
);
$order = wp_list_pluck( $l, 'where' );
t( 'O the server cannot be reached: each address in turn, then the public address answers: "current" by way of it', 'current' === $st['state'] && 'public' === $st['via'] && '' === $st['ip'] && array( '127.0.0.1', '192.0.2.10', 'public' ) === $order, wp_json_encode( $order ) );
t( 'O ...the public request is marked public (never routed to the server by route_request()), signed, same User-Agent', isset( $l[2] ) && $l[2]['public'] && '' === $l[2]['resolve'] && '' !== $l[2]['sig'] && PNCP_Self_Check::user_agent() === $l[2]['ua'] );

list( $st, $l ) = status_with(
	static function ( $where, $url ) use ( $is_check, $fp_answer, $fp ) {
		if ( '127.0.0.1' === $where ) {
			return null;
		}
		return '192.0.2.10' === $where && $is_check( $url ) ? $fp_answer( $fp ) : null;
	}
);
t( 'O the next address of the server answers (SERVER_ADDR / SCRAPELOCK_SERVER_IPS): by way of it', 'current' === $st['state'] && 'origin' === $st['via'] && '192.0.2.10' === $st['ip'] && 2 === count( $l ) );

list( $st, $l ) = status_with(
	static function ( $where, $url ) use ( $is_check, $fp_answer, $fp_http ) {
		if ( ! $is_check( $url ) ) {
			return null;
		}
		return '127.0.0.1' === $where ? $fp_answer( $fp_http . ' 000000000000' ) : resp( 404, array( 'server' => 'nginx' ), NGINX_404 );
	}
);
t( 'O an old part 2 at the server, a 404 through the public address: "stale" (part 2), by way of the server', 'stale' === $st['state'] && array( 'server' ) === $st['parts'] && 'origin' === $st['via'] && 2 === count( $l ), wp_json_encode( $st ) );

list( $st ) = status_with(
	static function ( $where, $url ) use ( $is_check, $fp_answer, $fp ) {
		if ( ! $is_check( $url ) ) {
			return null;
		}
		return '127.0.0.1' === $where ? $fp_answer( '111111111111 222222222222' ) : $fp_answer( $fp );
	}
);
t( 'O 127.0.0.1 answers another site\'s fingerprints, the public address the current ones: "current" (public)', 'current' === $st['state'] && 'public' === $st['via'] );

list( $st, $l ) = status_with(
	static function ( $where, $url, $args, $id ) use ( $is_check, $own_page, $fp ) {
		if ( $is_check( $url ) ) {
			return '127.0.0.1' === $where ? resp( 404, array( 'server' => 'nginx' ), NGINX_404 ) : null;
		}
		return '127.0.0.1' === $where ? $own_page( $id, $fp ) : null;
	}
);
t( 'O no fingerprint at the check address, but the header of the site\'s own page has it: "current", seen in the header', 'current' === $st['state'] && 'header' === $st['kind'] && 'origin' === $st['via'], wp_json_encode( $st ) );
t( 'O ...and the out-of-date notice says the same (PNCP_Rules_State saw the header)', $fp === PNCP_Rules_State::state()['installed'] && ! PNCP_Rules_State::is_stale() );
t( 'O ...the home page was asked straight at the server too', in_array( '/', wp_list_pluck( wp_list_filter( $l, array( 'where' => '127.0.0.1' ) ), 'path' ), true ) );
t( 'O ...and noted for the self-check log', (bool) wp_list_filter( PNCP_Self_Check::entries(), array( 'via' => 'origin' ) ) );

list( $st ) = status_with(
	static function ( $where, $url, $args, $id ) use ( $is_check, $own_page, $fp ) {
		if ( $is_check( $url ) ) {
			return 'public' === $where ? resp( 404, array( 'server' => 'nginx', 'cdn-cache' => 'HIT', 'cdn-requestid' => 'x' ), NGINX_404 ) : null;
		}
		// A copy of the page from the CDN's cache: the marker of another request.
		return 'public' === $where ? $own_page( 'deadbeef', $fp ) : null;
	}
);
t( 'O a cached page with a fingerprint header (not this request\'s answer) does not count', 'missing' === $st['state'] && 'cached' === $st['kind'], wp_json_encode( $st ) );

// Kept 5 minutes, for these rules only.
global $log, $route;
$log   = array();
$route = static function ( $where, $url ) use ( $is_check, $fp_answer, $fp ) {
	return '127.0.0.1' === $where && $is_check( $url ) ? $fp_answer( $fp ) : null;
};
delete_transient( PNCP_Rules_Status::NGINX );
PNCP_Rules::nginx_status();
$asked = count( $log );
PNCP_Rules::nginx_status();
t( 'O the answer is kept: asked once in two calls', 1 === $asked && 1 === count( $log ) );
t( 'O ...what PNCP_Rules_State reads is there (want, body)', array( $fp, $fp ) === array( get_transient( 'pncp_nginx_status' )['want'], get_transient( 'pncp_nginx_status' )['body'] ) );
set_transient(
	'pncp_nginx_status',
	array(
		'want'  => $fp,
		'body'  => '',
		'error' => '',
	),
	300
);
$log = array();
$st  = PNCP_Rules::nginx_status();
t( 'O an answer kept by 3.12.3 (by way of the CDN) is asked again', 1 === count( $log ) && 'current' === $st['state'] && 'origin' === $st['via'] );
t( 'O nginx_status_kept: the kept answer, without a request', 'current' === PNCP_Rules_Status::nginx_kept()['state'] && 1 === count( $log ) );
$route = null;

// An http:// site address that Nginx sends to https:// (aaPanel's "Force HTTPS"): the check there.
// (On the default port: the server answers on 80 and 443.)
$origin_of = (string) preg_replace( '#^https?://([^/]+)#', '$0', home_url() );
$http_home = static function ( $url ) use ( $origin_of, $host ) {
	return str_replace( $origin_of, 'http://' . $host, $url );
};
add_filter( 'home_url', $http_home, 99 );
list( $st, $l ) = status_with(
	static function ( $where, $url ) use ( $is_check, $fp_answer, $fp ) {
		if ( '127.0.0.1' !== $where || ! $is_check( $url ) ) {
			return null;
		}
		$https = 'https' === wp_parse_url( $url, PHP_URL_SCHEME );
		return $https ? $fp_answer( PNCP_Rules::nginx_fingerprint() ) : resp( 301, array( 'location' => 'https://' . wp_parse_url( $url, PHP_URL_HOST ) . wp_parse_url( $url, PHP_URL_PATH ) . '?t=1' ) );
	}
);
remove_filter( 'home_url', $http_home, 99 );
t( 'O an http:// site address with a 301 to https://: the check address there, "current"', 'current' === $st['state'] && array( 'http', 'https' ) === array_values( array_unique( wp_list_pluck( $l, 'scheme' ) ) ), wp_json_encode( $l ) );
t( 'O ...a redirect elsewhere is not followed', '' === PNCP_Rules_Status::https_redirect( 'http://' . $host . $check, resp( 301, array( 'location' => 'https://evil.example' . $check ) ) ) && '' === PNCP_Rules_Status::https_redirect( 'http://' . $host . $check, resp( 301, array( 'location' => 'https://' . $host . '/' ) ) ) );

/* ---------- K. What answered instead ---------- */

$kinds = array(
	'WordPress 404 at the server'         => array( 'wp', static function ( $where, $url, $args, $id ) use ( $is_check ) {
		return '127.0.0.1' === $where && $is_check( $url ) ? resp( 404, array( 'x-scrapelock' => PNCP_Self_Check::ok_marker( $id ), 'link' => '<https://x/wp-json/>; rel="https://api.w.org/"' ), WP_404 ) : null;
	}, 'origin' ),
	'WordPress 404 page, no headers'      => array( 'wp', static function ( $where, $url ) use ( $is_check ) {
		return '127.0.0.1' === $where && $is_check( $url ) ? resp( 404, array( 'server' => 'nginx' ), WP_404 ) : null;
	}, 'origin' ),
	'Nginx\'s own 404 at the server'      => array( 'nginx', static function ( $where, $url ) use ( $is_check ) {
		return '127.0.0.1' === $where && $is_check( $url ) ? resp( 404, array( 'server' => 'nginx/1.24.0' ), NGINX_404 ) : null;
	}, 'origin' ),
	'the CDN\'s cache, server unreachable' => array( 'cached', static function ( $where, $url ) use ( $is_check ) {
		return 'public' === $where && $is_check( $url ) ? resp( 404, array( 'server' => 'BunnyCDN-DE1-1052', 'cdn-cache' => 'HIT', 'cdn-requestid' => 'abc' ), WP_404 ) : null;
	}, 'public' ),
	'only the CDN, server unreachable'    => array( 'cdn', static function ( $where, $url ) use ( $is_check ) {
		return 'public' === $where && $is_check( $url ) ? resp( 404, array( 'server' => 'BunnyCDN-DE1-1052', 'cdn-cache' => 'MISS', 'cdn-requestid' => 'abc' ), NGINX_404 ) : null;
	}, 'public' ),
	'something else (Apache 403)'         => array( 'other', static function ( $where, $url ) use ( $is_check ) {
		return '127.0.0.1' === $where && $is_check( $url ) ? resp( 403, array( 'server' => 'Apache' ), '<address>Apache Server</address>' ) : null;
	}, 'origin' ),
);
foreach ( $kinds as $label => $case ) {
	list( $st ) = status_with( $case[1] );
	t( "K $label: \"missing\", kind {$case[0]}, by way of {$case[2]}", 'missing' === $st['state'] && $case[0] === $st['kind'] && $case[2] === $st['via'], wp_json_encode( $st ) );
}
list( $st ) = status_with(
	static function () {
		return null;
	}
);
t( 'K nothing answers at all: "error" with the error', 'error' === $st['state'] && 'error' === $st['kind'] && false !== strpos( $st['error'], 'Failed to connect' ), wp_json_encode( $st ) );
list( $st ) = status_with(
	static function ( $where, $url ) use ( $is_check, $fp_answer, $fp_server ) {
		return '127.0.0.1' === $where && $is_check( $url ) ? $fp_answer( '000000000000 ' . $fp_server ) : null;
	}
);
t( 'K an old part 1: "stale" with the part http', 'stale' === $st['state'] && array( 'http' ) === $st['parts'] );
t( 'K is_cached: Bunny, Cloudflare, X-Cache, Age; not MISS / BYPASS', PNCP_Rules_Status::is_cached( array( 'cdn-cache' => 'HIT' ) ) && PNCP_Rules_Status::is_cached( array( 'cf-cache-status' => 'HIT' ) ) && PNCP_Rules_Status::is_cached( array( 'x-cache' => 'Hit from cloudfront' ) ) && PNCP_Rules_Status::is_cached( array( 'age' => '120' ) ) && ! PNCP_Rules_Status::is_cached( array( 'cdn-cache' => 'MISS' ) ) && ! PNCP_Rules_Status::is_cached( array( 'cf-cache-status' => 'BYPASS', 'age' => '0' ) ) );

/* ---------- R. Real Nginx ---------- */

$nginx_bin = trim( (string) shell_exec( 'command -v nginx 2>/dev/null' ) );
$openssl   = trim( (string) shell_exec( 'command -v openssl 2>/dev/null' ) );
if ( '' === $nginx_bin || '' === $openssl || ! function_exists( 'curl_init' ) ) {
	echo "SKIP R real Nginx (nginx or openssl not on PATH)\n";
} else {
	$dir  = sys_get_temp_dir() . '/pncp-t3124-nginx-' . getmypid();
	$port = 19000 + ( getmypid() % 1000 );
	wp_mkdir_p( $dir . '/tmp' );
	wp_mkdir_p( $dir . '/www' );
	wp_mkdir_p( $dir . '/ext' );
	exec( 'openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=pncp-test -keyout ' . escapeshellarg( $dir . '/k.pem' ) . ' -out ' . escapeshellarg( $dir . '/c.pem' ) . ' -days 1 2>/dev/null' );
	// The site at https://127.0.0.1:<port>: its own rules (names and fingerprints) for that address.
	$home = static function ( $url, $path ) use ( $port ) {
		return 'https://127.0.0.1:' . $port . '/' . ltrim( (string) $path, '/' );
	};
	add_filter( 'home_url', $home, 99, 2 );
	$want = PNCP_Rules::nginx_fingerprint();
	file_put_contents( $dir . '/http.conf', PNCP_Rules::nginx_http() );
	file_put_contents( $dir . '/server.conf', PNCP_Rules::nginx_server() );
	$files = array( 'http.conf', 'server.conf', 'nginx.conf', 'c.pem', 'k.pem', 'error.log', 'nginx.pid', 'ext/part2.conf' );
	/**
	 * Writes an aaPanel-like nginx.conf: $where = top (server level, below the SSL lines), ext (the extension
	 * include at the top of server { }, as aaPanel 7 writes it), nested (inside location / { }), none, http
	 * (part 2 in http { }), twice (top and ext).
	 */
	$write = static function ( $where ) use ( $dir, $port ) {
		@unlink( $dir . '/ext/part2.conf' );
		if ( in_array( $where, array( 'ext', 'twice' ), true ) ) {
			copy( $dir . '/server.conf', $dir . '/ext/part2.conf' );
		}
		$inc  = 'include ' . $dir . '/server.conf;';
		$conf = 'worker_processes 1; error_log ' . $dir . '/error.log; pid ' . $dir . '/nginx.pid; events { worker_connections 64; }' . "\n"
			. 'http { access_log off; client_body_temp_path ' . $dir . '/tmp; proxy_temp_path ' . $dir . '/tmp; fastcgi_temp_path ' . $dir . '/tmp; uwsgi_temp_path ' . $dir . '/tmp; scgi_temp_path ' . $dir . '/tmp;' . "\n"
			. 'include ' . $dir . '/http.conf;' . "\n"
			. ( 'http' === $where ? $inc . "\n" : '' )
			. 'server { listen 127.0.0.1:' . $port . ' ssl; server_name 127.0.0.1; root ' . $dir . '/www;' . "\n"
			. 'include ' . $dir . '/ext/*.conf;' . "\n"
			. 'ssl_certificate ' . $dir . '/c.pem; ssl_certificate_key ' . $dir . '/k.pem;' . "\n"
			. ( in_array( $where, array( 'top', 'twice' ), true ) ? $inc . "\n" : '' )
			. 'location = /xmlrpc.php { deny all; }' . "\n"
			. 'location / { ' . ( 'nested' === $where ? $inc : '' ) . ' try_files $uri $uri/ =404; }' . "\n"
			. 'location ~ \.well-known{ allow all; }' . "\n"
			. 'location ~ .*\.(js|css)?$ { expires 12h; }' . "\n"
			. '} }' . "\n";
		file_put_contents( $dir . '/nginx.conf', $conf );
	};
	$nginx = static function ( $args ) use ( $nginx_bin, $dir ) {
		$out = array();
		exec( escapeshellarg( $nginx_bin ) . ' ' . $args . ' -e ' . escapeshellarg( $dir . '/error.log' ) . ' -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' 2>&1', $out, $rc );
		return array( $rc, implode( ' | ', $out ) );
	};
	$get = static function () use ( $port ) {
		$ch = curl_init( 'https://127.0.0.1:' . $port . '/.well-known/scrapelock-nginx' );
		curl_setopt_array(
			$ch,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_SSL_VERIFYPEER => false,
				CURLOPT_SSL_VERIFYHOST => 0,
				CURLOPT_TIMEOUT        => 10,
				CURLOPT_PROXY          => '',
			)
		);
		$body = (string) curl_exec( $ch );
		$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		curl_close( $ch );
		return array( $code, trim( $body ) );
	};
	$write( 'none' );
	list( $rc, $msg ) = $nginx( '' );
	usleep( 500000 );
	t( 'R real Nginx starts (aaPanel-like server { }, no part 2)', 0 === $rc, $msg );
	list( $code, $body ) = $get();
	t( 'R no part 2: location ~ \.well-known answers, Nginx\'s own 404', 404 === $code && false !== strpos( $body, '<center>nginx' ), $code . ' ' . substr( $body, 0, 80 ) );
	foreach ( array( 'top' => 'at the top level of server { } (before the regex locations)', 'ext' => 'in the extension include at the top of server { }', 'nested' => 'nested in location / { }' ) as $where => $label ) {
		$write( $where );
		list( $rc, $msg ) = $nginx( '-t' );
		$nginx( '-s reload' );
		usleep( 600000 );
		list( $code, $body ) = $get();
		t( "R part 2 $label: nginx -t passes, the exact location beats location ~ \\.well-known (the fingerprint)", 0 === $rc && 200 === $code && $want === $body, $msg . ' ' . $code . ' ' . $body );
	}
	$write( 'top' );
	$nginx( '-s reload' );
	usleep( 600000 );
	delete_transient( PNCP_Rules_Status::NGINX );
	$st = PNCP_Rules::nginx_status( true );
	t( 'R the status through the real Nginx: "current", by way of the server (127.0.0.1)', 'current' === $st['state'] && 'origin' === $st['via'], wp_json_encode( $st ) );
	foreach ( array( 'http' => 'in http { }', 'twice' => 'twice (Config and the extension folder)' ) as $where => $label ) {
		$write( $where );
		list( $rc, $msg ) = $nginx( '-t' );
		t( "R part 2 $label: nginx -t fails (the running rules stay)", 0 !== $rc, $msg );
	}
	$write( 'top' );
	remove_filter( 'home_url', $home, 99 );
	if ( is_file( $dir . '/nginx.pid' ) ) {
		exec( 'kill ' . (int) file_get_contents( $dir . '/nginx.pid' ) );
		usleep( 300000 );
	}
	foreach ( $files as $f ) {
		@unlink( $dir . '/' . $f );
	}
	foreach ( array( 'tmp', 'www', 'ext', '' ) as $d ) {
		@rmdir( $dir . '/' . $d );
	}
	delete_transient( PNCP_Rules_Status::NGINX );
}

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
