<?php
/**
 * ScrapeLock 3.12.6 — WP-CLI for the server: wp scrapelock rules show | status | install, cdn purge.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 WP_CLI="wp --path=…" php t_3126_cli.php
 *
 * S. rules show: each part exactly as the Server rules tab shows it, kept as "shown" (3.12.3 diff store).
 * T. rules status: the fields (state, parts, via, installed, current), JSON, an unknown --server.
 * I. rules install: only the files named, .conf / .htaccess only, no "..", no symlink out of its folder, no
 *    leftover .old; --dry-run; an unchanged file skipped; the test failing (--test-cmd=false) or the reload
 *    failing puts every file back byte for byte; the default commands (nginx -t, nginx -s reload, then
 *    systemctl reload nginx) found on PATH (fake programs); no answer to the question changes nothing; a symlink
 *    into its own folder is written through; .htaccess: only ScrapeLock's block, above # BEGIN WordPress; the
 *    token of the static feeds kept from the installed file and never printed; the CLI class refuses a web request.
 * R. Real Nginx (SKIP without nginx on PATH): install into a temporary prefix, nginx -t, reload, the check address
 *    answers the new fingerprints; part 2 put where nginx -t fails: put back, the running rules unchanged.
 * C. cdn purge: with fake Bunny and Cloudflare APIs (a temporary mu-plugin, so that WP-CLI, another process, talks
 *    to them): one address, a path on the home address, several, --all (only with --yes), an address of another
 *    host (nothing purged), Bunny's 429 and Cloudflare's refusal (the other CDN still purged, exit code 1), no
 *    connection; the keys never printed.
 *
 * Only on a test WordPress.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
if ( '' === $wp_cli ) {
	echo "SKIP without WP_CLI\n";
	exit( 0 );
}
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

/** Runs "wp scrapelock …": [exit code, stdout + stderr]. */
function cli( $args, $stdin = '/dev/null' ) {
	global $wp_cli;
	exec( $wp_cli . ' scrapelock ' . $args . ' < ' . escapeshellarg( $stdin ) . ' 2>&1', $out, $rc );
	wp_cache_flush();
	return array( $rc, implode( "\n", $out ) );
}

const BUNNY_KEY = 'bunny-3126-key-1234567890abcdef';
const CF_TOKEN  = 'cf3126token_ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CF_ZONE   = '0123456789abcdef0123456789abcdef';

$saved = array();
foreach ( array( PNCP_Edge::CONFIG, PNCP_Bunny::CONFIG, PNCP_Edge::CALLS, PNCP_Bunny::CALLS ) as $name ) {
	$saved[ $name ] = get_option( $name, null );
}

// The fake APIs, in every process while the option pncp_test_3126_cdn exists; removed at the end.
$mock = WP_CONTENT_DIR . '/mu-plugins/pncp-test-3126-cdn.php';
file_put_contents(
	$mock,
	<<<'PHP'
<?php
// TESTS ONLY: written and removed by tests/t_3126_cli.php. Fake Bunny and Cloudflare purge APIs.
if ( is_array( get_option( 'pncp_test_3126_cdn' ) ) ) {
	add_filter( 'pncp_bunny_api_base', static function () { return 'https://bunny-3126.mock.test'; } );
	add_filter( 'pncp_edge_api_base', static function ( $base, $provider ) { return 'cloudflare' === $provider ? 'https://cf-3126.mock.test/client/v4' : 'https://bunny-3126.mock.test'; }, 10, 2 );
	add_filter(
		'pre_http_request',
		static function ( $pre, $args, $url ) {
			$bunny = 0 === strpos( $url, 'https://bunny-3126.mock.test/' );
			$cf    = 0 === strpos( $url, 'https://cf-3126.mock.test/' );
			if ( ! $bunny && ! $cf ) {
				return $pre;
			}
			wp_cache_delete( 'pncp_test_3126_cdn', 'options' );
			$db       = get_option( 'pncp_test_3126_cdn' ) + array( 'calls' => array(), 'fail' => array() );
			$headers  = isset( $args['headers'] ) ? $args['headers'] : array();
			$db['calls'][] = array(
				'cdn'    => $bunny ? 'bunny' : 'cf',
				'method' => isset( $args['method'] ) ? $args['method'] : 'GET',
				'url'    => $url,
				'body'   => isset( $args['body'] ) ? json_decode( (string) $args['body'], true ) : null,
				'key'    => $bunny ? ( isset( $headers['AccessKey'] ) ? $headers['AccessKey'] : '' ) : ( isset( $headers['Authorization'] ) ? $headers['Authorization'] : '' ),
			);
			update_option( 'pncp_test_3126_cdn', $db, false );
			$reply = static function ( $code, $data ) {
				return array( 'headers' => array( 'content-type' => 'application/json' ), 'body' => wp_json_encode( $data ), 'response' => array( 'code' => $code, 'message' => '' ), 'cookies' => array(), 'filename' => null );
			};
			$fail = $bunny ? ( $db['fail']['bunny'] ?? 0 ) : ( $db['fail']['cf'] ?? 0 );
			if ( $bunny ) {
				return $fail ? $reply( $fail, array( 'Message' => 'Too many requests for key ' . $headers['AccessKey'] ) ) : $reply( 200, array() );
			}
			return $fail ? $reply( $fail, array( 'success' => false, 'errors' => array( array( 'code' => 10000, 'message' => 'Authentication error for ' . $headers['Authorization'] ) ) ) ) : $reply( 200, array( 'success' => true, 'result' => array( 'id' => 'x' ) ) );
		},
		1,
		3
	);
}
PHP
);
register_shutdown_function(
	static function () use ( $mock, $saved ) {
		@unlink( $mock );
		delete_option( 'pncp_test_3126_cdn' );
		foreach ( $saved as $name => $value ) {
			if ( null === $value ) {
				delete_option( $name );
			} else {
				update_option( $name, $value, false );
			}
		}
	}
);
function mock_db( $fail = array() ) {
	update_option(
		'pncp_test_3126_cdn',
		array(
			'calls' => array(),
			'fail'  => $fail,
		),
		false
	);
}
function mock_calls() {
	wp_cache_delete( 'pncp_test_3126_cdn', 'options' );
	$db = get_option( 'pncp_test_3126_cdn' );
	return is_array( $db ) ? $db['calls'] : array();
}

/* ---------- S. rules show ---------- */

$tmp = sys_get_temp_dir() . '/pncp-t3126-cli-' . getmypid();
wp_mkdir_p( $tmp );
register_shutdown_function(
	static function () use ( $tmp ) {
		exec( 'rm -rf ' . escapeshellarg( $tmp ) );
	}
);
delete_option( PNCP_Rules_State::TEXTS );
$texts = array(
	'nginx-http'     => PNCP_Rules::nginx_http(),
	'nginx-server'   => PNCP_Rules::nginx_server(),
	'stealth-nginx'  => PNCP_Stealth::rules_text( 'nginx' ),
	'stealth-apache' => PNCP_Stealth::rules_text( 'apache' ),
	'apache'         => PNCP_Rules::apache(),
);
foreach ( $texts as $part => $text ) {
	exec( $wp_cli . ' scrapelock rules show --part=' . $part . ' > ' . escapeshellarg( $tmp . '/show.txt' ) . ' 2>/dev/null', $o, $rc );
	t( "S rules show --part=$part: exactly the text of the Server rules tab", 0 === $rc && $text === file_get_contents( $tmp . '/show.txt' ), (string) $rc );
}
unlink( $tmp . '/show.txt' );
wp_cache_flush();
t( 'S ...and kept as shown, under its fingerprint (for "See what changed")', PNCP_Rules::nginx() === PNCP_Rules_State::text_of( 'nginx', PNCP_Rules::nginx_fingerprint() ) && PNCP_Rules::apache() === PNCP_Rules_State::text_of( 'apache', PNCP_Rules::apache_fingerprint() ) );
list( $rc, $out ) = cli( 'rules show --part=nginx' );
t( 'S an unknown part: an error naming the parts', 0 !== $rc && false !== strpos( $out, 'nginx-http, nginx-server, stealth-nginx, stealth-apache, apache' ), $out );
list( $rc, $out ) = cli( 'rules --help' );
t( 'S rules --help: show, status, install and the options', 0 === $rc && false !== strpos( $out, '--nginx-http=<file>' ) && false !== strpos( $out, '--dry-run' ) && false !== strpos( $out, '--test-cmd=<command>' ), $out );

/* ---------- T. rules status ---------- */

list( $rc, $out ) = cli( 'rules status --server=nginx --format=json' );
$st               = json_decode( $out, true );
t( 'T rules status --format=json: state, parts, via, installed, current, message', 0 === $rc && is_array( $st ) && 'nginx' === $st['server'] && isset( $st['state'], $st['parts'], $st['via'], $st['installed'], $st['current'], $st['message'] ) && PNCP_Rules::nginx_fingerprint() === $st['current'], $out );
// The test server is not Nginx: WordPress answers the check address, twice (4 s apart): "not_found".
t( 'T ...a server without the rules: not_found, asked directly (origin)', is_array( $st ) && 'not_found' === $st['state'] && 0 === strpos( $st['via'], 'origin' ), $out );
list( $rc, $out ) = cli( 'rules status --server=apache' );
t( 'T rules status --server=apache: a table', 0 === $rc && preg_match( '/server\s+apache/', $out ) && false !== strpos( $out, PNCP_Rules::apache_fingerprint() ), $out );
list( $rc, $out ) = cli( 'rules status --server=iis' );
t( 'T an unknown --server: an error', 0 !== $rc );

/* ---------- I. rules install ---------- */

$http = $tmp . '/0.scrapelock-site.conf';
$srv  = $tmp . '/scrapelock.conf';
$ls   = static function () use ( $tmp ) {
	$out = array();
	foreach ( (array) scandir( $tmp ) as $f ) {
		if ( '.' !== $f && '..' !== $f && is_file( $tmp . '/' . $f ) ) {
			$out[] = $f;
		}
	}
	sort( $out );
	return implode( ',', $out );
};
file_put_contents( $http, "# old part 1\n" );
file_put_contents( $srv, "# old part 2\n" );
$args = '--nginx-http=' . escapeshellarg( $http ) . ' --nginx-server=' . escapeshellarg( $srv );

list( $rc, $out ) = cli( 'rules install' );
t( 'I no files named: an error, nothing guessed', 0 !== $rc && false !== strpos( $out, 'Nothing is guessed' ), $out );
foreach (
	array(
		'--nginx-http=' . escapeshellarg( $tmp . '/rules.txt' )         => 'ending in .conf',
		'--nginx-http=relative.conf'                                    => 'absolute path',
		'--nginx-http=' . escapeshellarg( $tmp . '/../x.conf' )        => 'absolute path',
		'--nginx-http=' . escapeshellarg( $tmp . '/nope/x.conf' )      => 'does not exist',
		'--apache=' . escapeshellarg( $tmp . '/index.php' )            => '.htaccess file or a file ending in .conf',
		'--nginx-http=' . escapeshellarg( $tmp . '/a.conf' ) . ' --nginx-server=' . escapeshellarg( $tmp . '/a.conf' ) => 'same file',
	) as $bad => $why
) {
	list( $rc, $out ) = cli( 'rules install ' . $bad . ' --yes' );
	t( "I refused ($why)", 0 !== $rc && false !== strpos( $out, $why ), $out );
}
symlink( '/etc/hostname', $tmp . '/outside.conf' );
list( $rc, $out ) = cli( 'rules install --nginx-http=' . escapeshellarg( $tmp . '/outside.conf' ) . ' --yes --test-cmd=true --reload-cmd=true' );
t( 'I a symlink to a file outside its folder: refused, the target untouched', 0 !== $rc && false !== strpos( $out, 'symlink' ) && is_link( $tmp . '/outside.conf' ), $out );
unlink( $tmp . '/outside.conf' );
file_put_contents( $srv . '.old', 'x' );
list( $rc, $out ) = cli( 'rules install ' . $args . ' --yes --test-cmd=true --reload-cmd=true' );
t( 'I a leftover .old: refused (never overwritten)', 0 !== $rc && false !== strpos( $out, 'scrapelock.conf.old first' ) && 'x' === file_get_contents( $srv . '.old' ), $out );
unlink( $srv . '.old' );

list( $rc, $out ) = cli( 'rules install ' . $args . ' --dry-run' );
t( 'I --dry-run: a unified diff of both files, nothing changed, no .new left', 0 === $rc && false !== strpos( $out, '--- ' . $http ) && false !== strpos( $out, '+++ ' . $srv . '.new' ) && false !== strpos( $out, "@@ -1 +1," ) && false !== strpos( $out, '-# old part 2' ) && false !== strpos( $out, 'Dry run' ) && "# old part 1\n" === file_get_contents( $http ) && '0.scrapelock-site.conf,scrapelock.conf' === $ls(), $out );

list( $rc, $out ) = cli( 'rules install ' . $args );
t( 'I no answer to the question: nothing changed', "# old part 1\n" === file_get_contents( $http ) && "# old part 2\n" === file_get_contents( $srv ) && false !== strpos( $out, 'Install these 2 files' ), $out );

list( $rc, $out ) = cli( 'rules install ' . $args . ' --yes --test-cmd=' . escapeshellarg( 'echo "nginx: [emerg] unknown directive" && false' ) . ' --reload-cmd=true' );
t( 'I the test fails: every file put back byte for byte, exit 1 with the test\'s output', 0 !== $rc && false !== strpos( $out, '[emerg] unknown directive' ) && false !== strpos( $out, 'every file was put back' ) && "# old part 1\n" === file_get_contents( $http ) && "# old part 2\n" === file_get_contents( $srv ) && '0.scrapelock-site.conf,scrapelock.conf' === $ls(), $out . ' ' . $ls() );
list( $rc, $out ) = cli( 'rules install ' . $args . ' --yes --test-cmd=true --reload-cmd=false' );
t( 'I the reload fails: put back too', 0 !== $rc && false !== strpos( $out, 'The reload (false) failed' ) && "# old part 1\n" === file_get_contents( $http ) && '0.scrapelock-site.conf,scrapelock.conf' === $ls(), $out );

chmod( $http, 0640 );
list( $rc, $out ) = cli( 'rules install ' . $args . ' --yes --test-cmd=true --reload-cmd=' . escapeshellarg( 'echo reloaded' ) );
t( 'I test and reload pass: both installed, the .old files removed, the status printed', 0 === $rc && PNCP_Rules::nginx_http() === file_get_contents( $http ) && PNCP_Rules::nginx_server() === file_get_contents( $srv ) && '0.scrapelock-site.conf,scrapelock.conf' === $ls() && false !== strpos( $out, '2 files installed' ) && false !== strpos( $out, 'Reloaded: echo reloaded' ) && preg_match( '/state\s+not_found/', $out ), $out . ' ' . $ls() );
t( 'I ...the file keeps its permissions', 0640 === ( fileperms( $http ) & 0777 ), decoct( fileperms( $http ) & 0777 ) );
list( $rc, $out ) = cli( 'rules install ' . $args . ' --yes --test-cmd=false' );
t( 'I again: unchanged files skipped, no test, no reload', 0 === $rc && false !== strpos( $out, 'Unchanged, skipped' ) && false !== strpos( $out, 'already the current rules' ), $out );

// The default commands: nginx found on PATH (a fake one that notes its arguments), then systemctl.
$bin = $tmp . '/bin';
wp_mkdir_p( $bin );
file_put_contents( $bin . '/nginx', "#!/bin/sh\necho \"nginx \$*\" >> " . escapeshellarg( $tmp . '/calls.log' ) . "\n[ \"\$1\" = \"-s\" ] && [ -f " . escapeshellarg( $tmp . '/reload-fails' ) . " ] && exit 1\nexit 0\n" );
file_put_contents( $bin . '/systemctl', "#!/bin/sh\necho \"systemctl \$*\" >> " . escapeshellarg( $tmp . '/calls.log' ) . "\nexit 0\n" );
chmod( $bin . '/nginx', 0755 );
chmod( $bin . '/systemctl', 0755 );
$with_path = 'PATH=' . escapeshellarg( $bin . ':' . getenv( 'PATH' ) ) . ' ';
file_put_contents( $srv, "# old part 2\n" );
exec( $with_path . $wp_cli . ' scrapelock rules install ' . $args . ' --yes < /dev/null 2>&1', $o2, $rc );
$calls = is_file( $tmp . '/calls.log' ) ? file_get_contents( $tmp . '/calls.log' ) : '';
t( 'I the defaults: nginx -t, then nginx -s reload (nginx from PATH)', 0 === $rc && "nginx -t\nnginx -s reload\n" === $calls, $calls . ' ' . implode( "\n", $o2 ) );
@unlink( $tmp . '/calls.log' );
touch( $tmp . '/reload-fails' );
file_put_contents( $srv, "# old part 2\n" );
$o2 = array();
exec( $with_path . $wp_cli . ' scrapelock rules install ' . $args . ' --yes < /dev/null 2>&1', $o2, $rc );
$calls = is_file( $tmp . '/calls.log' ) ? file_get_contents( $tmp . '/calls.log' ) : '';
t( 'I nginx -s reload fails: systemctl reload nginx instead', 0 === $rc && "nginx -t\nnginx -s reload\nsystemctl reload nginx\n" === $calls && PNCP_Rules::nginx_server() === file_get_contents( $srv ), $calls . ' ' . implode( "\n", $o2 ) );
exec( 'rm -rf ' . escapeshellarg( $bin ) . ' ' . escapeshellarg( $tmp . '/calls.log' ) . ' ' . escapeshellarg( $tmp . '/reload-fails' ) );

// A symlink into its own folder is written through (the link stays).
file_put_contents( $tmp . '/real.conf', "# old\n" );
symlink( $tmp . '/real.conf', $tmp . '/link.conf' );
list( $rc, $out ) = cli( 'rules install --stealth=' . escapeshellarg( $tmp . '/link.conf' ) . ' --yes --test-cmd=true --reload-cmd=true' );
t( 'I a symlink into its own folder: its file written, the link kept (--stealth)', 0 === $rc && is_link( $tmp . '/link.conf' ) && PNCP_Stealth::rules_text( 'nginx' ) === file_get_contents( $tmp . '/real.conf' ), $out );
unlink( $tmp . '/link.conf' );
unlink( $tmp . '/real.conf' );

// .htaccess: only ScrapeLock's block, above # BEGIN WordPress; the rest byte for byte.
$ht   = $tmp . '/.htaccess';
$wp   = "# BEGIN WordPress\nRewriteEngine On\nRewriteRule . /index.php [L]\n# END WordPress\n";
$mine = "# my own line\n";
file_put_contents( $ht, $mine . $wp );
list( $rc, $out ) = cli( 'rules install --apache=' . escapeshellarg( $ht ) . ' --yes' );
$text = (string) file_get_contents( $ht );
t( 'I .htaccess: the block above # BEGIN WordPress, the rest kept; tested with a request of the home page', 0 === $rc && $mine . PNCP_Rules::apache() . "\n" . $wp === $text && false !== strpos( $out, 'Test passed: HTTP' ), $out );
file_put_contents( $ht, (string) preg_replace( '/^RewriteEngine On$/m', "RewriteEngine On\n# old line", $text, 1 ) );
list( $rc, $out ) = cli( 'rules install --apache=' . escapeshellarg( $ht ) . ' --yes' );
t( 'I .htaccess again: only the block replaced', 0 === $rc && $text === file_get_contents( $ht ) && false !== strpos( $out, '-# old line' ), $out );

// The token of the static feeds: kept from the installed file, never printed.
$paths = PNCP_Options::stored()['private_paths'];
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'private_paths' => '/private-feed/*.xml' ) ) );
PNCP_Options::flush();
file_put_contents( $http, "# nothing\n" );
list( $rc, $out ) = cli( 'rules install --nginx-http=' . escapeshellarg( $http ) . ' --yes --test-cmd=true --reload-cmd=true' );
t( 'I YOUR_TOKEN in the rules and no token to keep: refused, nothing changed', 0 !== $rc && false !== strpos( $out, 'YOUR_TOKEN' ) && "# nothing\n" === file_get_contents( $http ), $out );
file_put_contents( $http, str_replace( 'YOUR_TOKEN', 'Secret3126Token', PNCP_Rules::nginx_http() ) . "# changed\n" );
list( $rc, $out ) = cli( 'rules install --nginx-http=' . escapeshellarg( $http ) . ' --yes --test-cmd=true --reload-cmd=true' );
t( 'I the installed token kept in the new file, and never printed', 0 === $rc && str_replace( 'YOUR_TOKEN', 'Secret3126Token', PNCP_Rules::nginx_http() ) === file_get_contents( $http ) && false === strpos( $out, 'Secret3126Token' ), $out );
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'private_paths' => $paths ) ) );
PNCP_Options::flush();

$code = (string) wp_remote_retrieve_response_code( wp_remote_get( $base . '/wp-content/plugins/scrapelock/includes/class-pncp-cli-server.php' ) );
t( 'I the CLI class is never run by a web request (ABSPATH guard)', in_array( $code, array( '200', '403', '404' ), true ) && '' === trim( (string) wp_remote_retrieve_body( wp_remote_get( $base . '/wp-content/plugins/scrapelock/includes/class-pncp-cli-server.php' ) ) ), $code );

/* ---------- R. Real Nginx ---------- */

$nginx_bin = trim( (string) shell_exec( 'command -v nginx 2>/dev/null' ) );
if ( '' === $nginx_bin || ! function_exists( 'curl_init' ) ) {
	echo "SKIP R real Nginx (nginx not on PATH)\n";
} else {
	$dir  = $tmp . '/nginx';
	$port = 19500 + ( getmypid() % 400 );
	wp_mkdir_p( $dir . '/tmp' );
	wp_mkdir_p( $dir . '/www' );
	file_put_contents( $dir . '/http.conf', "# part 1 comes here\n" );
	file_put_contents( $dir . '/server.conf', "# part 2 comes here\n" );
	file_put_contents( $dir . '/inhttp.conf', "# nothing\n" );
	file_put_contents(
		$dir . '/nginx.conf',
		'worker_processes 1; error_log ' . $dir . '/error.log; pid ' . $dir . '/nginx.pid; events { worker_connections 64; }' . "\n"
		. 'http { access_log off; client_body_temp_path ' . $dir . '/tmp; proxy_temp_path ' . $dir . '/tmp; fastcgi_temp_path ' . $dir . '/tmp; uwsgi_temp_path ' . $dir . '/tmp; scgi_temp_path ' . $dir . '/tmp;' . "\n"
		. 'include ' . $dir . '/http.conf;' . "\n" . 'include ' . $dir . '/inhttp.conf;' . "\n"
		. 'server { listen 127.0.0.1:' . $port . '; server_name localhost; root ' . $dir . '/www;' . "\n"
		. 'include ' . $dir . '/server.conf;' . "\n"
		. 'location / { try_files $uri $uri/ =404; }' . "\n"
		. 'location ~ \.well-known { allow all; }' . "\n"
		. '} }' . "\n"
	);
	$ctl = escapeshellarg( $nginx_bin ) . ' -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' -e ' . escapeshellarg( $dir . '/error.log' );
	exec( $ctl . ' 2>&1', $o3, $rc );
	usleep( 500000 );
	$get = static function () use ( $port ) {
		$ch = curl_init( 'http://127.0.0.1:' . $port . '/.well-known/scrapelock-nginx' );
		curl_setopt_array(
			$ch,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_TIMEOUT        => 10,
				CURLOPT_PROXY          => '',
			)
		);
		$body = trim( (string) curl_exec( $ch ) );
		$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		curl_close( $ch );
		return array( $code, $body );
	};
	list( $code ) = $get();
	t( 'R a real Nginx in a temporary prefix, without the rules (404)', 0 === $rc && 404 === $code, implode( ' ', $o3 ) . ' ' . $code );
	$cmds = ' --test-cmd=' . escapeshellarg( $ctl . ' -t' ) . ' --reload-cmd=' . escapeshellarg( $ctl . ' -s reload' );
	list( $rc, $out ) = cli( 'rules install --nginx-http=' . escapeshellarg( $dir . '/http.conf' ) . ' --nginx-server=' . escapeshellarg( $dir . '/server.conf' ) . ' --yes' . $cmds );
	usleep( 800000 );
	list( $code, $body ) = $get();
	t( 'R install: nginx -t passes, reloaded, the check address answers the current fingerprints', 0 === $rc && 200 === $code && PNCP_Rules::nginx_fingerprint() === $body && false !== strpos( $out, 'Test passed' ), $out . ' ' . $code . ' ' . $body );
	// Part 2 named where nginx -t fails (a file included in http { }: if is not allowed there).
	list( $rc, $out ) = cli( 'rules install --nginx-server=' . escapeshellarg( $dir . '/inhttp.conf' ) . ' --yes' . $cmds );
	usleep( 500000 );
	list( $code, $body ) = $get();
	t( 'R part 2 where nginx -t fails: put back, exit 1 with nginx\'s message, the running rules unchanged', 0 !== $rc && false !== strpos( $out, 'nginx: [emerg]' ) && "# nothing\n" === file_get_contents( $dir . '/inhttp.conf' ) && ! file_exists( $dir . '/inhttp.conf.old' ) && 200 === $code && PNCP_Rules::nginx_fingerprint() === $body, $out . ' ' . $code );
	if ( is_file( $dir . '/nginx.pid' ) ) {
		exec( 'kill ' . (int) file_get_contents( $dir . '/nginx.pid' ) );
		usleep( 300000 );
	}
}

/* ---------- C. cdn purge ---------- */

$home = home_url( '/' );
t( 'C own_url(): a path is on the home address', home_url( '/builtwith.txt' ) === PNCP_Edge::own_url( '/builtwith.txt' ) );
t( 'C own_url(): another host, a protocol-relative address, credentials, ftp: refused', '' === PNCP_Edge::own_url( 'https://example.org/x' ) && '' === PNCP_Edge::own_url( '//example.org/x' ) && '' === PNCP_Edge::own_url( str_replace( '://', '://u:p@', $home ) ) && '' === PNCP_Edge::own_url( 'ftp://' . wp_parse_url( $home, PHP_URL_HOST ) . '/x' ) );

delete_option( PNCP_Edge::CONFIG );
delete_option( PNCP_Bunny::CONFIG );
mock_db();
list( $rc, $out ) = cli( 'cdn purge /builtwith.txt' );
t( 'C no CDN connection: an error, no call', 0 !== $rc && false !== strpos( $out, 'No CDN connection' ) && ! mock_calls(), $out );

update_option(
	PNCP_Edge::CONFIG,
	array(
		'provider' => 'cloudflare',
		'zone'     => CF_ZONE,
		'token'    => CF_TOKEN,
	),
	false
);
update_option(
	PNCP_Bunny::CONFIG,
	array(
		'zone'  => '4242',
		'token' => BUNNY_KEY,
	),
	false
);
mock_db();
$url              = home_url( '/builtwith.txt' );
list( $rc, $out ) = cli( 'cdn purge ' . escapeshellarg( $url ) );
$calls            = mock_calls();
$bunny            = array_values( wp_list_filter( $calls, array( 'cdn' => 'bunny' ) ) );
$cf               = array_values( wp_list_filter( $calls, array( 'cdn' => 'cf' ) ) );
t( 'C one address: Bunny\'s purge API with the stored key (POST /purge?url=…&async=false)', 0 === $rc && 1 === count( $bunny ) && 'POST' === $bunny[0]['method'] && 'https://bunny-3126.mock.test/purge?url=' . rawurlencode( $url ) . '&async=false' === $bunny[0]['url'] && BUNNY_KEY === $bunny[0]['key'], $out . ' ' . wp_json_encode( $calls ) );
t( 'C ...and Cloudflare\'s purge_cache with files, the stored token', 1 === count( $cf ) && 'https://cf-3126.mock.test/client/v4/zones/' . CF_ZONE . '/purge_cache' === $cf[0]['url'] && array( 'files' => array( $url ) ) === $cf[0]['body'] && 'Bearer ' . CF_TOKEN === $cf[0]['key'], wp_json_encode( $cf ) );
t( 'C ...the output: status and counts only, never a key', false !== strpos( $out, 'Bunny CDN: 1 address purged.' ) && false !== strpos( $out, 'Cloudflare: 1 address purged.' ) && false === strpos( $out, BUNNY_KEY ) && false === strpos( $out, CF_TOKEN ), $out );

mock_db();
list( $rc, $out ) = cli( 'cdn purge /builtwith.txt /robots.txt' );
$cf               = array_values( wp_list_filter( mock_calls(), array( 'cdn' => 'cf' ) ) );
t( 'C paths: on the home address; Bunny one call per address, Cloudflare one call for both', 0 === $rc && 2 === count( wp_list_filter( mock_calls(), array( 'cdn' => 'bunny' ) ) ) && 1 === count( $cf ) && array( home_url( '/builtwith.txt' ), home_url( '/robots.txt' ) ) === $cf[0]['body']['files'] && false !== strpos( $out, 'Bunny CDN: 2 addresses purged.' ), $out );

mock_db();
list( $rc, $out ) = cli( 'cdn purge /ok.txt https://example.org/x.txt' );
t( 'C an address of another host: refused, nothing purged (not even the good one)', 0 !== $rc && ! mock_calls() && false !== strpos( $out, 'example.org' ), $out );
list( $rc, $out ) = cli( 'cdn purge' );
t( 'C no address and no --all: an error', 0 !== $rc && ! mock_calls() );
list( $rc, $out ) = cli( 'cdn purge /x.txt --all --yes' );
t( 'C addresses and --all: an error', 0 !== $rc && ! mock_calls() );

list( $rc, $out ) = cli( 'cdn purge --all' );
t( 'C --all without --yes (no answer): asks, purges nothing', ! mock_calls() && false !== strpos( $out, 'Purge the whole CDN cache' ), $out );
list( $rc, $out ) = cli( 'cdn purge --all --yes' );
$calls            = mock_calls();
$bunny            = array_values( wp_list_filter( $calls, array( 'cdn' => 'bunny' ) ) );
$cf               = array_values( wp_list_filter( $calls, array( 'cdn' => 'cf' ) ) );
t( 'C --all --yes: Bunny purgeCache of the pull zone, Cloudflare purge_everything', 0 === $rc && 1 === count( $bunny ) && 'https://bunny-3126.mock.test/pullzone/4242/purgeCache' === $bunny[0]['url'] && 1 === count( $cf ) && array( 'purge_everything' => true ) === $cf[0]['body'] && false !== strpos( $out, 'Bunny CDN: the whole cache was purged.' ), $out . ' ' . wp_json_encode( $calls ) );

mock_db( array( 'bunny' => 429 ) );
list( $rc, $out ) = cli( 'cdn purge /a.txt /b.txt' );
t( 'C Bunny\'s 429: stops at the first address, says so, the key not printed; Cloudflare still purged; exit 1', 1 === $rc && 1 === count( wp_list_filter( mock_calls(), array( 'cdn' => 'bunny' ) ) ) && false !== strpos( $out, 'Bunny asked to slow down' ) && false !== strpos( $out, 'Cloudflare: 2 addresses purged.' ) && false === strpos( $out, BUNNY_KEY ), $out );
mock_db( array( 'cf' => 403 ) );
list( $rc, $out ) = cli( 'cdn purge /a.txt' );
t( 'C Cloudflare refuses the token: a warning without the token, exit 1', 1 === $rc && false !== strpos( $out, 'Cloudflare: not purged' ) && false === strpos( $out, CF_TOKEN ) && false !== strpos( $out, 'Bunny CDN: 1 address purged.' ), $out );

// Bunny as the CDN of "Blocking at the CDN" (no own card): its pull zone and key.
delete_option( PNCP_Bunny::CONFIG );
update_option(
	PNCP_Edge::CONFIG,
	array(
		'provider' => 'bunny',
		'zone'     => '777',
		'token'    => BUNNY_KEY,
	),
	false
);
mock_db();
list( $rc, $out ) = cli( 'cdn purge --all --yes' );
$calls            = mock_calls();
t( 'C Bunny under "Blocking at the CDN": its pull zone, no Cloudflare call', 0 === $rc && 1 === count( $calls ) && 'https://bunny-3126.mock.test/pullzone/777/purgeCache' === $calls[0]['url'], $out . ' ' . wp_json_encode( $calls ) );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );
