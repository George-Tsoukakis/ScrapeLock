<?php
$root = $_SERVER['DOCUMENT_ROOT'];
$path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
if ( $path !== '/' && is_file( $root . $path ) && substr( $path, -4 ) !== '.php' ) {
	return false;
}
if ( substr( $path, -4 ) === '.php' && is_file( $root . $path ) ) {
	chdir( dirname( $root . $path ) );
	require $root . $path;
	return;
}
$_SERVER['SCRIPT_NAME'] = '/index.php';
require $root . '/index.php';
