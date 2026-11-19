<?php
/**
 * ScrapeLock 3.10 — Edge Rules at Bunny within Bunny's limits, with a fake Bunny API.
 *
 * The real API refuses a trigger with more than 5 patterns: HTTP 400 "Maximum 5 triggers are allowed per
 * condition." (seen on a real site with the preset "Secret files", 21 patterns in one trigger). The fake API
 * below answers the same, so these checks fail on 3.9.1. Checked: how a lock is split (plan()), that the split
 * rules mean what one rule meant (allowed IPs, excepted addresses), lock / Remove / rollback on HTTP 400, 401,
 * 404, 429 and timeout, Monitor only, rules removed in the Bunny dashboard, a lock stored by 3.9 with too many
 * patterns, the login page's allowed IPs, the preview, the card, deactivation and WP-CLI.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_bunny_rules.php
 */

$wp_dir = getenv( 'WP_DIR' );
$wp_cli = (string) getenv( 'WP_CLI' );

// The fake API as a temporary mu-plugin, so that WP-CLI (another process) talks to it too. It answers only
// while the option pncp_test_bunny_rules exists, at its own address; removed at the end.
$pncp_mock = $wp_dir . '/wp-content/mu-plugins/pncp-test-bunny-rules.php';
file_put_contents(
	$pncp_mock,
	<<<'PHP'
<?php
// TESTS ONLY: written and removed by tests/t_bunny_rules.php. A fake Bunny API for Edge Rules.
if ( is_array( get_option( 'pncp_test_bunny_rules' ) ) ) {
	add_filter( 'pncp_bunny_api_base', static function () { return 'https://bunny-rules.mock.test'; } );
	add_filter( 'pncp_bunny_call_budget', static function () { return 100000; } );
	add_filter(
		'pncp_bunny_edge_limits',
		static function ( $limits ) {
			$db = get_option( 'pncp_test_bunny_rules' );
			return is_array( $db ) && ! empty( $db['limits'] ) ? $db['limits'] : $limits;
		}
	);
	add_filter(
		'pre_http_request',
		static function ( $pre, $args, $url ) {
			$base = 'https://bunny-rules.mock.test/pullzone/';
			if ( 0 !== strpos( $url, $base ) ) {
				return $pre;
			}
			wp_cache_delete( 'pncp_test_bunny_rules', 'options' );
			$db      = get_option( 'pncp_test_bunny_rules' ) + array( 'rules' => array(), 'calls' => array(), 'fail' => array(), 'posts' => 0, 'no_guid' => false, 'max_triggers' => 0 );
			$method  = isset( $args['method'] ) ? $args['method'] : 'GET';
			$body    = isset( $args['body'] ) ? json_decode( (string) $args['body'], true ) : null;
			$headers = isset( $args['headers'] ) ? $args['headers'] : array();
			$reply   = static function ( $code, $data = null ) {
				return array( 'headers' => array( 'content-type' => 'application/json' ), 'body' => null === $data ? '' : wp_json_encode( $data ), 'response' => array( 'code' => $code, 'message' => '' ), 'cookies' => array(), 'filename' => null );
			};
			$rest           = (string) substr( $url, strlen( $base ) );
			$db['calls'][]  = $method . ' ' . $rest;
			$save           = static function () use ( &$db ) {
				update_option( 'pncp_test_bunny_rules', $db, false );
			};
			if ( ! isset( $headers['AccessKey'] ) || 'bunny-rules-key-1234567890' !== $headers['AccessKey'] ) {
				$save();
				return $reply( 401, array( 'Message' => 'The request authorization failed' ) );
			}
			if ( 0 !== strpos( $rest, '777' ) ) {
				$save();
				return $reply( 404, array( 'Message' => 'Pull zone not found' ) );
			}
			$rest = (string) substr( $rest, 3 );
			if ( '' === $rest && 'GET' === $method ) {
				$save();
				return $reply( 200, array( 'Id' => 777, 'Name' => 'mock', 'EnableLogging' => true, 'EdgeRules' => array_values( $db['rules'] ) ) );
			}
			if ( '/edgerules/addOrUpdate' === $rest && 'POST' === $method ) {
				++$db['posts'];
				// Fail the n-th addOrUpdate on purpose: fail => [n => 400 | 401 | 404 | 429 | 'timeout'].
				if ( isset( $db['fail'][ $db['posts'] ] ) ) {
					$how = $db['fail'][ $db['posts'] ];
					$save();
					if ( 'timeout' === $how ) {
						return new WP_Error( 'http_request_failed', 'cURL error 28: Operation timed out after 10001 milliseconds' );
					}
					return $reply( (int) $how, array( 'ErrorKey' => 'mock', 'Message' => 'Injected failure' ) );
				}
				// What the real API answers to a trigger with more than 5 patterns.
				foreach ( isset( $body['Triggers'] ) ? (array) $body['Triggers'] : array() as $trigger ) {
					if ( isset( $trigger['PatternMatches'] ) && count( (array) $trigger['PatternMatches'] ) > 5 ) {
						$save();
						return $reply( 400, array( 'ErrorKey' => 'pullzone.edgerule_validation', 'Field' => 'Triggers', 'Message' => 'Maximum 5 triggers are allowed per condition.' ) );
					}
				}
				if ( $db['max_triggers'] && count( (array) $body['Triggers'] ) > $db['max_triggers'] ) {
					$save();
					return $reply( 400, array( 'ErrorKey' => 'mock', 'Message' => 'Too many triggers in one rule.' ) );
				}
				if ( ! empty( $body['Guid'] ) ) {
					if ( ! isset( $db['rules'][ $body['Guid'] ] ) ) {
						$save();
						return $reply( 404, array( 'Message' => 'The requested edge rule was not found' ) );
					}
					$db['rules'][ $body['Guid'] ] = $body;
					$save();
					return $reply( 200 );
				}
				$guid               = wp_generate_uuid4();
				$body               = array( 'Guid' => $guid ) + $body;
				$db['rules'][ $guid ] = $body;
				$save();
				return $db['no_guid'] ? $reply( 200 ) : $reply( 200, $body );
			}
			if ( 0 === strpos( $rest, '/edgerules/' ) && 'DELETE' === $method ) {
				$guid = substr( $rest, 11 );
				if ( ! isset( $db['rules'][ $guid ] ) ) {
					$save();
					return $reply( 404, array( 'Message' => 'The requested edge rule was not found' ) );
				}
				unset( $db['rules'][ $guid ] );
				$save();
				return $reply( 204 );
			}
			$save();
			return $reply( 404, array( 'Message' => 'nf' ) );
		},
		10,
		3
	);
}
PHP
);
register_shutdown_function(
	static function () use ( $pncp_mock ) {
		if ( is_file( $pncp_mock ) ) {
			unlink( $pncp_mock );
		}
	}
);

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

const BR_ZONE = '777';
const BR_KEY  = 'bunny-rules-key-1234567890';

function mock() {
	wp_cache_delete( 'pncp_test_bunny_rules', 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	$db = get_option( 'pncp_test_bunny_rules' );
	return ( is_array( $db ) ? $db : array() ) + array( 'rules' => array(), 'calls' => array(), 'fail' => array(), 'posts' => 0, 'no_guid' => false, 'limits' => array(), 'max_triggers' => 0 );
}
function mock_set( $changes ) {
	update_option( 'pncp_test_bunny_rules', array_merge( mock(), $changes ), false );
}
function mock_reset( $changes = array() ) {
	update_option( 'pncp_test_bunny_rules', array_merge( array( 'rules' => array(), 'calls' => array(), 'fail' => array(), 'posts' => 0, 'no_guid' => false, 'limits' => array(), 'max_triggers' => 0 ), $changes ), false );
}
/** The rules at the fake Bunny whose Description holds this text. */
function at_bunny( $needle = '[preset_probes]' ) {
	$out = array();
	foreach ( mock()['rules'] as $guid => $rule ) {
		if ( false !== strpos( (string) $rule['Description'], $needle ) ) {
			$out[ $guid ] = $rule;
		}
	}
	return $out;
}
/** Every trigger of these rules holds at most 5 patterns? */
function within_limit( $rules ) {
	foreach ( $rules as $rule ) {
		foreach ( $rule['Triggers'] as $trigger ) {
			if ( count( $trigger['PatternMatches'] ) > 5 ) {
				return false;
			}
		}
	}
	return true;
}
function stored( $id ) {
	wp_cache_delete( PNCP_Bunny::RULES, 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	$rules = get_option( PNCP_Bunny::RULES, array() );
	return isset( $rules[ $id ] ) ? $rules[ $id ] : null;
}
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
}
/** A Bunny URL pattern ("*" = anything) against a URL, as Bunny matches it. */
function pattern_hit( $pattern, $url ) {
	return 1 === preg_match( '#^' . str_replace( '\*', '.*', preg_quote( $pattern, '#' ) ) . '$#i', $url );
}
/** Would this set of Edge Rules (JSON bodies) block a request? Evaluates the triggers as Bunny does. */
function blocks( $rules, $url, $ip ) {
	foreach ( $rules as $rule ) {
		$results = array();
		foreach ( $rule['Triggers'] as $tr ) {
			$any = false;
			foreach ( $tr['PatternMatches'] as $p ) {
				$any = $any || ( 5 === (int) $tr['Type'] ? PNCP_Ip::in_any( $ip, array( $p ) ) : pattern_hit( $p, $url ) );
			}
			$results[] = 2 === (int) $tr['PatternMatchingType'] ? ! $any : $any; // 0 Any, 2 None (of one trigger).
		}
		$m  = (int) $rule['TriggerMatchingType'];
		$on = 0 === $m ? in_array( true, $results, true ) : ( 1 === $m ? ! in_array( false, $results, true ) : ! in_array( true, $results, true ) );
		if ( $on && ! empty( $rule['Enabled'] ) ) {
			return true;
		}
	}
	return false;
}

/* ---------- Clean start ---------- */
$saved_settings = PNCP_Options::stored();
settings( array( 'enabled' => 1, 'monitor_mode' => 0, 'monitor_until' => 0, 'bunny_login_allow' => '' ) );
foreach ( array( PNCP_Bunny::RULES, PNCP_Bunny::CALLS, PNCP_Bunny::LOGIN_STRICT ) as $pncp_o ) {
	delete_option( $pncp_o );
}
delete_option( PNCP_Edge::CONFIG );
mock_reset();
// The fake API filters were added when WordPress loaded only if the option existed then: add them now too.
if ( ! has_filter( 'pncp_bunny_api_base' ) ) {
	include $pncp_mock;
}
update_option( PNCP_Bunny::CONFIG, array( 'zone' => BR_ZONE, 'token' => BR_KEY ), false );
PNCP_Bunny::reset();
t( 'connected to the fake Bunny', PNCP_Bunny::edge_available() && BR_ZONE === PNCP_Bunny::credentials()['zone'] );

$presets = PNCP_Bunny::presets();
$probes  = $presets['probes']['patterns'];

/* ---------- The bug of 3.9.1: one trigger with all patterns ---------- */
$res = wp_remote_post(
	'https://bunny-rules.mock.test/pullzone/777/edgerules/addOrUpdate',
	array(
		'headers' => array( 'AccessKey' => BR_KEY, 'Content-Type' => 'application/json' ),
		'body'    => wp_json_encode(
			array(
				'ActionType'          => 4,
				'Triggers'            => array( array( 'Type' => 0, 'PatternMatches' => $probes, 'PatternMatchingType' => 0, 'Parameter1' => '' ) ),
				'TriggerMatchingType' => 0,
				'Description'         => 'ScrapeLock: 3.9.1 style [x]',
				'Enabled'             => true,
			)
		),
	)
);
t( 'fake API: a trigger with > 5 patterns gets HTTP 400 "Maximum 5 triggers are allowed per condition."', 400 === wp_remote_retrieve_response_code( $res ) && false !== strpos( wp_remote_retrieve_body( $res ), 'Maximum 5 triggers are allowed per condition.' ) && ! mock()['rules'], wp_remote_retrieve_body( $res ) );
mock_reset();

/* ---------- plan(): how a lock is split ---------- */
t( 'limits: 5 patterns per trigger, 5 triggers per rule', array( 'patterns' => 5, 'triggers' => 5 ) === PNCP_Bunny::edge_limits() );
$plan = PNCP_Bunny::plan( array( 'patterns' => $probes ) );
$ok   = ! is_wp_error( $plan ) && 1 === count( $plan ) && 0 === $plan[0]['match'] && 5 === count( $plan[0]['triggers'] );
foreach ( is_wp_error( $plan ) ? array() : $plan[0]['triggers'] as $tr ) {
	$ok = $ok && count( $tr['patterns'] ) <= 5 && 0 === $tr['type'] && 0 === $tr['match'];
}
t( 'plan: "Secret files" (21 patterns) = one rule, 5 URL triggers of ≤ 5, Match Any', $ok && 21 === count( $probes ), wp_json_encode( $plan ) );
$plan = PNCP_Bunny::plan( array( 'patterns' => $presets['core_files']['patterns'] ) );
t( 'plan: "WordPress\'s own files" (5 patterns) = one rule, one trigger, as before', ! is_wp_error( $plan ) && 1 === count( $plan ) && 1 === count( $plan[0]['triggers'] ) && 5 === count( $plan[0]['triggers'][0]['patterns'] ) );
$plan = PNCP_Bunny::plan( array( 'patterns' => array( '*/a*' ) ) );
t( 'plan: one pattern = one rule with one trigger', ! is_wp_error( $plan ) && 1 === count( $plan ) && 0 === $plan[0]['match'] );
$plan = PNCP_Bunny::plan( array( 'patterns' => array_merge( $probes, array( '*/x1*', '*/x2*', '*/x3*', '*/x4*', '*/x5*' ) ) ) );
t( 'plan: 26 patterns = 2 rules (5 triggers + 1)', ! is_wp_error( $plan ) && 2 === count( $plan ) && 5 === count( $plan[0]['triggers'] ) && 1 === count( $plan[1]['triggers'] ) );
$ips  = array();
for ( $i = 1; $i <= 12; $i++ ) {
	$ips[] = '198.51.100.' . $i;
}
$ips[] = '2001:db8:1:2::/64';
$plan  = PNCP_Bunny::plan(
	array(
		'patterns' => array( '*/p1*', '*/p2*', '*/p3*', '*/p4*', '*/p5*', '*/p6*', '*/p7*' ),
		'allow'    => $ips,
		'except'   => array( '*action=postpass*' ),
	)
);
$ok = ! is_wp_error( $plan ) && 2 === count( $plan );
foreach ( is_wp_error( $plan ) ? array() : $plan as $part ) {
	$ok = $ok && 1 === $part['match'] && 5 === count( $part['triggers'] ) && 0 === $part['triggers'][0]['match'] && 5 === $part['triggers'][1]['type'] && 2 === $part['triggers'][1]['match'] && 2 === $part['triggers'][4]['match'] && 0 === $part['triggers'][4]['type'];
}
t( 'plan with exceptions: one rule per URL group, Match All, IPs in 3 "None" triggers + 1 "None" URL trigger', $ok, wp_json_encode( $plan ) );
$plan = PNCP_Bunny::plan( array( 'patterns' => array( '*/p*' ), 'allow' => array_merge( $ips, array( '203.0.113.1', '203.0.113.2', '203.0.113.3' ) ), 'except' => array( '*x*' ) ) );
t( 'plan: exceptions that do not fit in one rule are refused (no wrong split)', is_wp_error( $plan ) && 'pncp_bunny_limit' === $plan->get_error_code() );
t( 'login: at most 15 allowed IPs (3 triggers × 5 next to the URL and action=postpass triggers)', 15 === PNCP_Bunny::login_allow_max() );

/* ---------- Lock "Secret files" ---------- */
$r     = PNCP_Bunny::lock_preset( 'probes' );
$there = at_bunny();
t( 'lock "Secret files": accepted by the API that refuses > 5 patterns', true === $r && 1 === count( $there ) && within_limit( $there ), is_wp_error( $r ) ? $r->get_error_message() : '' );
$rule = $there ? reset( $there ) : array();
t( 'the rule: Match Any of 5 URL triggers, all 21 patterns, Description as before', $rule && 0 === $rule['TriggerMatchingType'] && 5 === count( $rule['Triggers'] ) && 21 === count( array_merge( ...array_column( $rule['Triggers'], 'PatternMatches' ) ) ) && 'ScrapeLock: ' . $presets['probes']['label'] . ' [preset_probes]' === $rule['Description'] );
t( 'it blocks /.env, /backup.zip and /vendor/phpunit/x, not /shop/', $rule && blocks( $there, '/.env', '1.2.3.4' ) && blocks( $there, '/backup.zip', '1.2.3.4' ) && blocks( $there, '/vendor/phpunit/x', '1.2.3.4' ) && ! blocks( $there, '/shop/', '1.2.3.4' ) );
$s = stored( 'preset_probes' );
t( 'stored as one lock with its GUID(s)', $s && array( key( $there ) ) === $s['guids'] && key( $there ) === $s['guid'] && PNCP_Bunny::preset_locked( 'probes' ) );
$r = PNCP_Bunny::unlock_preset( 'probes' );
t( 'Remove: gone at Bunny and here', true === $r && ! at_bunny() && null === stored( 'preset_probes' ) && ! PNCP_Bunny::preset_locked( 'probes' ) );

/* ---------- Several rules (limit of 2 triggers per rule) ---------- */
mock_reset( array( 'limits' => array( 'patterns' => 5, 'triggers' => 2 ), 'max_triggers' => 2 ) );
$r     = PNCP_Bunny::lock_preset( 'probes' );
$there = at_bunny();
$descs = array_column( $there, 'Description' );
sort( $descs );
t( '2 triggers per rule: "Secret files" = 3 rules (1/3)…(3/3), within the limits', true === $r && 3 === count( $there ) && within_limit( $there ) && false !== strpos( $descs[0], '(1/3) [preset_probes]' ) && false !== strpos( $descs[2], '(3/3) [preset_probes]' ), is_wp_error( $r ) ? $r->get_error_message() : implode( ' | ', $descs ) );
$all = array();
foreach ( $probes as $p ) {
	$all[] = str_replace( '*', 'x', $p );
}
$every = true;
foreach ( $all as $u ) {
	$every = $every && blocks( $there, '/' . ltrim( $u, '/' ), '1.2.3.4' );
}
t( 'the 3 rules together block every address of the preset', $every );
$list = PNCP_Bunny::list_ours();
t( 'list_ours: one lock, 3 parts, 3 GUIDs', 1 === count( $list ) && 3 === $list['preset_probes']['parts'] && 3 === count( array_unique( $list['preset_probes']['guids'] ) ) && ! $list['preset_probes']['needs_split'] );

// The card shows one lock with one Remove.
wp_set_current_user( 1 );
ob_start();
PNCP_Bunny::render_card();
$card = (string) ob_get_clean();
wp_set_current_user( 0 );
t( 'card: one row "3 Edge Rules at Bunny … managed as one lock", one Remove for it', false !== strpos( $card, '3 Edge Rules at Bunny' ) && 1 === substr_count( $card, 'value="preset_probes"' ), substr( wp_strip_all_tags( $card ), 0, 300 ) );

// Preview "What would be blocked".
$preview = PNCP_Bunny::lock_preview( 'preset', 'probes' );
t( 'preview: 3 Edge Rules, 5 conditions, no blocker', ! is_wp_error( $preview ) && 3 === $preview['bunny_rules'] && 5 === $preview['conditions'] && ! $preview['blockers'] );

// Monitor only: every part switched off, then on again.
settings( array( 'monitor_mode' => 1, 'monitor_until' => 0 ) );
$n   = PNCP_Bunny::sync_rules();
$off = true;
foreach ( at_bunny() as $rr ) {
	$off = $off && empty( $rr['Enabled'] );
}
t( 'Monitor only: all 3 rules switched off at Bunny (same GUIDs)', 1 === $n && $off && 3 === count( at_bunny() ) && false === stored( 'preset_probes' )['enabled'] && array_keys( at_bunny() ) == stored( 'preset_probes' )['guids'] );
settings( array( 'monitor_mode' => 0, 'monitor_until' => 0 ) );
PNCP_Bunny::sync_rules();
$on = true;
foreach ( at_bunny() as $rr ) {
	$on = $on && ! empty( $rr['Enabled'] );
}
t( 'blocking again: all 3 switched on', $on && 3 === count( at_bunny() ) && true === stored( 'preset_probes' )['enabled'] );

// One part removed in the Bunny dashboard: made again (no half lock).
$db    = mock();
$guids = stored( 'preset_probes' )['guids'];
unset( $db['rules'][ $guids[1] ] );
update_option( 'pncp_test_bunny_rules', $db, false );
$zone = array( 'EdgeRules' => array_values( mock()['rules'] ) );
PNCP_Bunny::sync_rules( $zone );
$s = stored( 'preset_probes' );
t( 'one of 3 removed in the dashboard: made again with the next run', 3 === count( at_bunny() ) && $s && 3 === count( $s['guids'] ) && $guids[0] === $s['guids'][0] && $guids[2] === $s['guids'][2] && $guids[1] !== $s['guids'][1] && isset( mock()['rules'][ $s['guids'][1] ] ) );

// Every part removed in the dashboard: the owner decided, the lock is forgotten.
mock_set( array( 'rules' => array() ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array() ) );
t( 'all removed in the dashboard: forgotten, not made again', null === stored( 'preset_probes' ) && ! at_bunny() );

/* ---------- Rollback ---------- */
foreach ( array( 400, 401, 404, 429, 'timeout' ) as $how ) {
	mock_reset( array( 'limits' => array( 'patterns' => 5, 'triggers' => 2 ), 'fail' => array( 3 => $how ) ) );
	$r = PNCP_Bunny::lock_preset( 'probes' );
	t( "rollback ($how on rule 3 of 3): the 2 made are removed, nothing stored, the error shown", is_wp_error( $r ) && ! at_bunny() && null === stored( 'preset_probes' ) && ! PNCP_Bunny::preset_locked( 'probes' ) && '' !== $r->get_error_message() && false === strpos( $r->get_error_message(), BR_KEY ), is_wp_error( $r ) ? $r->get_error_message() . ' / ' . count( at_bunny() ) : 'no error' );
}
// Without a GUID in the answer: found by its Description (as before), for each part.
mock_reset( array( 'limits' => array( 'patterns' => 5, 'triggers' => 2 ), 'no_guid' => true ) );
$r = PNCP_Bunny::lock_preset( 'probes' );
$s = stored( 'preset_probes' );
t( 'answer without GUID: every part found by its numbered Description', true === $r && $s && 3 === count( array_unique( $s['guids'] ) ) && ! array_diff( $s['guids'], array_keys( at_bunny() ) ), is_wp_error( $r ) ? $r->get_error_message() : '' );
// Locked again with another split, failing halfway: the lock that was there stays as it was.
mock_set( array( 'no_guid' => false, 'limits' => array( 'patterns' => 5, 'triggers' => 3 ), 'fail' => array( mock()['posts'] + 2 => 400 ), 'max_triggers' => 0 ) );
$before = stored( 'preset_probes' );
$r      = PNCP_Bunny::lock_preset( 'probes' );
t( 'locked again as 2 rules, rule 2 refused: the new rule 1 removed, the old 3 rules and the record kept', is_wp_error( $r ) && 3 === count( at_bunny() ) && stored( 'preset_probes' )['guids'] === $before['guids'] && ! array_diff( $before['guids'], array_keys( at_bunny() ) ) );
mock_set( array( 'fail' => array() ) );
$r = PNCP_Bunny::lock_preset( 'probes' );
$s = stored( 'preset_probes' );
t( 'locked again as 2 rules: the 2 new exist, the 3 old are removed', true === $r && 2 === count( at_bunny() ) && 2 === count( $s['guids'] ) && ! array_intersect( $before['guids'], array_keys( mock()['rules'] ) ) && false !== strpos( (string) mock()['rules'][ $s['guids'][1] ]['Description'], '(2/2)' ) );
PNCP_Bunny::unlock_preset( 'probes' );
t( 'Remove of a 2-rule lock: both gone', ! at_bunny() && null === stored( 'preset_probes' ) );

/* ---------- A lock stored by 3.9 with too many patterns in one trigger ---------- */
mock_reset();
$legacy_guid = 'a1b2c3d4-0000-4000-8000-000000000001';
mock_set(
	array(
		'rules' => array(
			$legacy_guid => array(
				'Guid'                => $legacy_guid,
				'ActionType'          => 4,
				'Triggers'            => array( array( 'Type' => 0, 'PatternMatches' => $probes, 'PatternMatchingType' => 0, 'Parameter1' => '' ) ),
				'TriggerMatchingType' => 0,
				'Description'         => 'ScrapeLock: ' . $presets['probes']['label'] . ' [preset_probes]',
				'Enabled'             => true,
			),
		),
	)
);
update_option(
	PNCP_Bunny::RULES,
	array(
		'preset_probes' => array(
			'guid'     => $legacy_guid,
			'zone'     => BR_ZONE,
			'label'    => $presets['probes']['label'],
			'patterns' => $probes,
			'allow'    => array(),
			'except'   => array(),
			'enabled'  => true,
			'created'  => time() - 86400,
			'updated'  => time() - 86400,
		),
	),
	false
);
$list = PNCP_Bunny::list_ours();
t( '3.9 lock with 21 patterns in one trigger: shown as "to split"', ! empty( $list['preset_probes']['needs_split'] ) && 1 === $list['preset_probes']['parts'] );
wp_set_current_user( 1 );
ob_start();
PNCP_Bunny::render_card();
$card = (string) ob_get_clean();
wp_set_current_user( 0 );
t( 'card: says it is sent again, split', false !== strpos( $card, 'sent again, split' ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
$s     = stored( 'preset_probes' );
$there = at_bunny();
t( 'next run: sent again split, in place (same GUID), within the limits', $s && array( $legacy_guid ) === $s['guids'] && 1 === count( $there ) && within_limit( $there ) && 5 === count( $there[ $legacy_guid ]['Triggers'] ) && ! PNCP_Bunny::list_ours()['preset_probes']['needs_split'] );
t( 'a 3.9 lock of one rule (core files, 5 patterns) is not touched', ! PNCP_Bunny::list_ours()['preset_probes']['needs_split'] );
PNCP_Bunny::unlock_preset( 'probes' );

/* ---------- Login page: allowed IPs in groups of 5 ---------- */
mock_reset();
$allow = array_slice( $ips, 0, 12 );
$r     = PNCP_Bunny::edge_block( 'preset_login', $presets['login']['patterns'], $presets['login']['label'], array( 'allow' => $allow, 'except' => $presets['login']['except'] ) );
$there = at_bunny( '[preset_login]' );
$rule  = $there ? reset( $there ) : array();
t( 'login with 12 allowed IPs: one rule, Match All, URL + 3 IP "None" triggers (5+5+2) + action=postpass', true === $r && 1 === count( $there ) && within_limit( $there ) && 1 === $rule['TriggerMatchingType'] && 5 === count( $rule['Triggers'] ) && array( 5, 5, 2 ) === array( count( $rule['Triggers'][1]['PatternMatches'] ), count( $rule['Triggers'][2]['PatternMatches'] ), count( $rule['Triggers'][3]['PatternMatches'] ) ), is_wp_error( $r ) ? $r->get_error_message() : wp_json_encode( $rule ) );
$login = '/wp-login.php';
t( 'login rule: blocks a stranger, lets every listed IP through (1st, 6th, 12th), lets action=postpass through', blocks( $there, $login, '203.0.113.9' ) && ! blocks( $there, $login, '198.51.100.1' ) && ! blocks( $there, $login, '198.51.100.6' ) && ! blocks( $there, $login, '198.51.100.12' ) && ! blocks( $there, $login . '?action=postpass', '203.0.113.9' ) && ! blocks( $there, '/shop/', '203.0.113.9' ) );
$many = array();
for ( $i = 1; $i <= 16; $i++ ) {
	$many[] = '192.0.2.' . $i;
}
$r = PNCP_Bunny::edge_block( 'preset_login', $presets['login']['patterns'], $presets['login']['label'], array( 'allow' => $many, 'except' => $presets['login']['except'] ) );
t( 'login with 16 allowed IPs: refused with a clear message, the lock with 12 stays as it was', is_wp_error( $r ) && 'pncp_bunny_limit' === $r->get_error_code() && 1 === count( at_bunny( '[preset_login]' ) ) && 12 === count( stored( 'preset_login' )['allow'] ), is_wp_error( $r ) ? $r->get_error_message() : '' );
settings( array( 'bunny_login_allow' => implode( "\n", $many ) ) );
t( 'the allowed list keeps at most 15, and the lock is blocked while it holds 16', 15 === count( PNCP_Bunny::login_allow_list() ) && (bool) preg_grep( '/holds 16 IPs/', PNCP_Bunny::login_lock_blockers() ) );
settings( array( 'bunny_login_allow' => '' ) );
PNCP_Bunny::edge_unblock( 'preset_login' );
t( 'login lock removed', ! at_bunny( '[preset_login]' ) && null === stored( 'preset_login' ) );

/* ---------- Hardening point, deactivation ---------- */
mock_reset( array( 'limits' => array( 'patterns' => 5, 'triggers' => 2 ) ) );
$r1 = PNCP_Bunny::lock_preset( 'probes' );
$r2 = class_exists( 'PNCP_Hardening' ) ? PNCP_Hardening::edge( 'core_files', true ) : true;
t( 'hardening point "core files" locked at the edge (one rule) next to the 3-rule lock', true === $r1 && true === $r2 && 4 === count( mock()['rules'] ) && within_limit( mock()['rules'] ) );
$left = PNCP_Bunny::remove_all( 15 );
t( 'deactivation (remove_all): every rule of every lock removed', 0 === $left && ! mock()['rules'] && ! get_option( PNCP_Bunny::RULES ) );
if ( class_exists( 'PNCP_Hardening' ) ) {
	$hs = get_option( PNCP_Hardening::OPTION, array() );
	if ( is_array( $hs ) && isset( $hs['edge']['core_files'] ) ) {
		unset( $hs['edge']['core_files'] );
		update_option( PNCP_Hardening::OPTION, $hs, true );
	}
}

/* ---------- WP-CLI ---------- */
if ( '' !== $wp_cli ) {
	$cli = static function ( $args ) use ( $wp_cli ) {
		exec( $wp_cli . ' scrapelock bunny ' . $args . ' 2>&1', $out, $rc );
		wp_cache_flush();
		return array( $rc, implode( "\n", $out ) );
	};
	mock_reset( array( 'limits' => array( 'patterns' => 5, 'triggers' => 2 ) ) );
	list( $rc, $out ) = $cli( 'lock probes' );
	t( 'CLI: bunny lock probes = 3 rules at Bunny', 0 === $rc && 3 === count( at_bunny() ), $out );
	list( $rc, $out ) = $cli( 'rules --format=json' );
	$items            = json_decode( (string) preg_replace( '/^[^\[]*/s', '', $out ), true );
	$row              = is_array( $items ) && $items ? $items[0] : array();
	t( 'CLI: bunny rules = one row, 3 GUIDs, parts 3', 0 === $rc && is_array( $items ) && 1 === count( $items ) && 3 === count( explode( ',', (string) $row['guid'] ) ) && '3' === (string) $row['parts'], $out );
	list( $rc, $out ) = $cli( 'preview probes' );
	t( 'CLI: bunny preview probes says 3 Edge Rules', 0 === $rc && false !== strpos( $out, '"bunny_rules": 3' ), substr( $out, 0, 300 ) );
	list( $rc, $out ) = $cli( 'unlock preset_probes' );
	t( 'CLI: bunny unlock preset_probes removes all 3', 0 === $rc && ! at_bunny() && null === stored( 'preset_probes' ), $out );
	mock_reset( array( 'fail' => array( 1 => 400 ), 'limits' => array( 'patterns' => 5, 'triggers' => 2 ) ) );
	list( $rc, $out ) = $cli( 'lock probes' );
	t( 'CLI: a refused lock exits with an error and leaves nothing', 0 !== $rc && ! at_bunny() && null === stored( 'preset_probes' ), $out );
} else {
	echo "SKIP WP-CLI checks (no WP_CLI)\n";
}

/* ---------- Clean up ---------- */
foreach ( array( PNCP_Bunny::RULES, PNCP_Bunny::CALLS, PNCP_Bunny::LOGIN_STRICT, PNCP_Bunny::CONFIG, 'pncp_test_bunny_rules' ) as $pncp_o ) {
	delete_option( $pncp_o );
}
update_option( PNCP_OPTION, $saved_settings );
PNCP_Options::flush();
wp_clear_scheduled_hook( PNCP_Bunny::CRON );

echo $fails ? "\n$fails FAILED\n" : "\nALL PASSED\n";
exit( $fails ? 1 : 0 );
