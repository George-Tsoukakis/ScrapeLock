<?php
/**
 * TESTS ONLY (tests/t_3127_fastcgi.php): a minimal FastCGI responder for a real Nginx with fastcgi_cache in a
 * temporary prefix, where no PHP-FPM is installed. Every answer carries a serial number, so a cached answer
 * (the same number again) and a fresh one (a new number) can be told apart.
 *
 *   php fcgi-stub.php 127.0.0.1:9123
 */

$addr   = isset( $argv[1] ) ? $argv[1] : '127.0.0.1:9123';
$server = stream_socket_server( 'tcp://' . $addr, $errno, $errstr );
if ( ! $server ) {
	fwrite( STDERR, "listen: $errstr\n" );
	exit( 1 );
}
$serial = 0;

/** Reads exactly $n bytes, or '' at the end of the stream. */
function fcgi_read( $conn, $n ) {
	$buf = '';
	while ( strlen( $buf ) < $n ) {
		$chunk = fread( $conn, $n - strlen( $buf ) );
		if ( false === $chunk || '' === $chunk ) {
			return '';
		}
		$buf .= $chunk;
	}
	return $buf;
}

/** One record. */
function fcgi_record( $type, $id, $content ) {
	$len = strlen( $content );
	$pad = ( 8 - $len % 8 ) % 8;
	return pack( 'CCnnCC', 1, $type, $id, $len, $pad, 0 ) . $content . str_repeat( "\0", $pad );
}

/** The name-value pairs of FCGI_PARAMS. */
function fcgi_params( $data ) {
	$out = array();
	$i   = 0;
	$len = strlen( $data );
	while ( $i < $len ) {
		$sizes = array();
		for ( $k = 0; $k < 2; $k++ ) {
			$b = ord( $data[ $i ] );
			if ( $b & 0x80 ) {
				$sizes[] = unpack( 'N', substr( $data, $i, 4 ) )[1] & 0x7fffffff;
				$i      += 4;
			} else {
				$sizes[] = $b;
				++$i;
			}
		}
		$name           = substr( $data, $i, $sizes[0] );
		$out[ $name ]   = substr( $data, $i + $sizes[0], $sizes[1] );
		$i             += $sizes[0] + $sizes[1];
	}
	return $out;
}

while ( $conn = @stream_socket_accept( $server, -1 ) ) { // phpcs:ignore
	$params = '';
	$id     = 1;
	while ( true ) {
		$head = fcgi_read( $conn, 8 );
		if ( '' === $head ) {
			break;
		}
		$h       = unpack( 'Cversion/Ctype/nid/nlen/Cpad/Creserved', $head );
		$id      = $h['id'];
		$content = $h['len'] ? fcgi_read( $conn, $h['len'] ) : '';
		if ( $h['pad'] ) {
			fcgi_read( $conn, $h['pad'] );
		}
		if ( 4 === $h['type'] ) {
			$params .= $content;
		}
		if ( 5 === $h['type'] && 0 === $h['len'] ) {
			break; // The end of FCGI_STDIN: answer.
		}
	}
	$p    = fcgi_params( $params );
	$body = 'serial=' . ( ++$serial ) . ' uri=' . ( isset( $p['REQUEST_URI'] ) ? $p['REQUEST_URI'] : '' ) . ' host=' . ( isset( $p['HTTP_HOST'] ) ? $p['HTTP_HOST'] : '' ) . "\n";
	$out  = "Status: 200 OK\r\nContent-Type: text/html\r\nCache-Control: max-age=3600\r\n\r\n" . $body;
	@fwrite( $conn, fcgi_record( 6, $id, $out ) . fcgi_record( 6, $id, '' ) . fcgi_record( 3, $id, pack( 'NCCCC', 0, 0, 0, 0, 0 ) ) ); // phpcs:ignore
	fclose( $conn );
}
