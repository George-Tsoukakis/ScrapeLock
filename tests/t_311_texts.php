<?php
/**
 * ScrapeLock 3.11 — κείμενα βοήθειας της σελίδας ρυθμίσεων: μία σύντομη γραμμή ανά ρύθμιση, η μεγαλύτερη
 * εξήγηση διπλωμένη στο «More» (details.pncp-more), χωρίς νομικές παραπομπές και χωρίς «Starting value:»
 * έξω από το «More», και το «May affect visitors/SEO» ως εικονίδιο με tooltip και κείμενο για αναγνώστες οθόνης.
 * Κάθε καρτέλα αποδίδεται ως διαχειριστής μέσα από HTTP.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_311_texts.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

// Όρια: μια περιγραφή (p/span .description) έξω από το «More» έχει το πολύ τόσες λέξεις, η γραμμή βοήθειας
// ενός πεδίου (id="pncp-…-help") το πολύ τόσες.
const PNCP_T_MAX_WORDS = 20;
const PNCP_T_MAX_HELP  = 14;

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/* ---------- Σύνδεση διαχειριστή ---------- */
$admin   = get_user_by( 'id', 1 );
$expire  = time() + DAY_IN_SECONDS;
$manager = WP_Session_Tokens::get_instance( $admin->ID );
$token   = $manager->create( $expire );
$cookies = array(
	AUTH_COOKIE      => wp_generate_auth_cookie( $admin->ID, $expire, 'auth', $token ),
	LOGGED_IN_COOKIE => wp_generate_auth_cookie( $admin->ID, $expire, 'logged_in', $token ),
);
wp_set_current_user( $admin->ID );

function http( $path ) {
	global $base, $cookies;
	$ch  = curl_init( $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_COOKIE         => implode( '; ', $jar ),
			CURLOPT_HTTPHEADER     => array( 'X-Test-IP: 192.0.2.201', 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: en' ),
			CURLOPT_TIMEOUT        => 120,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

/**
 * The text of a node without its screen-reader-only parts (the risk icon announces its words there).
 */
function visible_text( DOMNode $node ) {
	if ( XML_TEXT_NODE === $node->nodeType ) {
		return $node->nodeValue;
	}
	if ( $node instanceof DOMElement && preg_match( '/\bscreen-reader-text\b/', $node->getAttribute( 'class' ) ) ) {
		return ' ';
	}
	$out = '';
	foreach ( $node->childNodes as $child ) {
		$out .= visible_text( $child );
	}
	return $out;
}

function words( $text ) {
	return count( preg_split( '/\s+/u', trim( $text ), -1, PREG_SPLIT_NO_EMPTY ) );
}

/**
 * The settings page of a tab as a DOM, and the same DOM without the "More" folds.
 */
function tab_dom( $body ) {
	$dom = new DOMDocument();
	libxml_use_internal_errors( true );
	$dom->loadHTML( '<?xml encoding="UTF-8">' . $body );
	libxml_clear_errors();
	return $dom;
}

// Η σελίδα όπως σε ένα υπάρχον site: προστασία ενεργή, όχι «Monitor only», όχι κλείδωμα.
$stored = PNCP_Options::stored();
update_option( PNCP_OPTION, array_merge( $stored, array( 'enabled' => 1, 'monitor_mode' => 0, 'monitor_until' => 0 ) ) );
PNCP_Options::flush();
delete_transient( PNCP_Hardening::LIVE ); // Οι σημειώσεις του πίνακα «Vulnerable points» από τον τρέχοντα κώδικα.
// 3.12.6: μια μπλοκαρισμένη διεύθυνση που δεν υπάρχει, ώστε η καρτέλα Log να δείχνει πάντα την κάρτα «Addresses
// that do not exist» με τη σημείωσή της (πριν εξαρτιόταν από παλιές γραμμές του αρχείου και η δοκιμή άλλαζε).
$pncp_t_path = '/pncp-t311-texts-no-such-page-' . getmypid();
PNCP_Log::insert(
	array(
		'time'   => time() - 60,
		'code'   => 403,
		'reason' => 'bot',
		'ip'     => '192.0.2.211',
		'path'   => $pncp_t_path,
		'ua'     => 'pncp-t311-texts',
		'hits'   => 1,
	)
);
PNCP_Log::flush_aggregates();
register_shutdown_function(
	static function () use ( $pncp_t_path ) {
		global $wpdb;
		$wpdb->delete( PNCP_Log::table(), array( 'path' => $pncp_t_path ), array( '%s' ) );
		PNCP_Log::flush_aggregates();
	}
);

/* ---------- Ο renderer ---------- */
$html = PNCP_Admin_Fields::description( 'pncp-x-help', PNCP_Admin_Fields::help( 'Short line.', 'The longer <explanation>.' ) );
t( 'description(): σύντομη γραμμή με το id της βοήθειας', false !== strpos( $html, '<p class="description" id="pncp-x-help">Short line.</p>' ), $html );
t( 'description(): το υπόλοιπο στο «More», escaped', false !== strpos( $html, '<details class="pncp-more"><summary>More</summary>' ) && false !== strpos( $html, 'The longer &lt;explanation&gt;.' ), $html );
t( 'description(): απλό κείμενο χωρίς «More»', '<p class="description" id="pncp-y-help">Only.</p>' === PNCP_Admin_Fields::description( 'pncp-y-help', 'Only.' ) );
t( 'description(): κενή βοήθεια, τίποτα', '' === PNCP_Admin_Fields::description( 'pncp-z-help', '' ) );
$risk = PNCP_Admin_Fields::risk_tag( 'rate_limit' );
t( 'risk_tag(): εικονίδιο με title, κείμενο για αναγνώστες οθόνης και το ίδιο id', false !== strpos( $risk, 'dashicons-warning' ) && false !== strpos( $risk, 'title="May affect visitors/SEO"' ) && false !== strpos( $risk, '<span class="screen-reader-text">May affect visitors/SEO</span>' ) && false !== strpos( $risk, 'id="pncp-rate_limit-risk"' ), $risk );
t( 'risk_tag(): τίποτα για ρύθμιση χωρίς κίνδυνο', '' === PNCP_Admin_Fields::risk_tag( 'scope_posts' ) );

/* ---------- Κάθε καρτέλα ---------- */
$page    = '/wp-admin/options-general.php?page=scrapelock';
$tabs    = array( 'general', 'bots', 'content', 'images', 'rules', 'log', 'attacks', 'hardening', 'lockdown' );
// 3.12: the Traffic tab and each of its views (collection on or off, as the site has it).
foreach ( array( '', '&tr_view=agents', '&tr_view=problems', '&tr_view=problems&tr_type=uncached', '&tr_view=visitors', '&tr_view=log', '&tr_view=settings' ) as $pncp_view ) {
	$tabs[] = 'traffic' . $pncp_view;
}
$all     = '';
$folds   = 0;
foreach ( $tabs as $tab ) {
	list( $code, $body ) = http( $page . '&tab=' . $tab );
	t( "$tab: 200 χωρίς PHP warnings", 200 === $code && ! php_errors( $body ) && false !== strpos( $body, 'nav-tab-active' ), (string) $code );
	$all .= $body;
	$dom  = tab_dom( $body );
	$xp   = new DOMXPath( $dom );
	$wrap = $xp->query( '//*[@id="wpbody-content"]' )->item( 0 );
	if ( ! $wrap ) {
		t( "$tab: #wpbody-content", false );
		continue;
	}
	$folds += $xp->query( './/details[contains(concat(" ", normalize-space(@class), " "), " pncp-more ")]', $wrap )->length;
	// Οι περιγραφές έξω από το «More» (οι σημειώσεις «Takes effect only when “…” is on» παραθέτουν μια ετικέτα
	// ρύθμισης όπως είναι, γι' αυτό μένουν έξω από τη μέτρηση).
	$long = array();
	$help = array();
	$desc = $xp->query( './/*[self::p or self::span][contains(concat(" ", normalize-space(@class), " "), " description ")][not(ancestor::details[contains(concat(" ", normalize-space(@class), " "), " pncp-more ")])][not(contains(@class, "pncp-requires-note"))]', $wrap );
	foreach ( $desc as $el ) {
		$text = trim( preg_replace( '/\s+/u', ' ', visible_text( $el ) ) );
		$n    = words( $text );
		// A note that quotes a transport error of the site's request to itself (CI's single-process server times
		// out on it) depends on the environment, not on the help texts.
		if ( $n > PNCP_T_MAX_WORDS && false === strpos( $text, 'could not reach itself' ) ) {
			$long[] = $n . ': ' . mb_substr( $text, 0, 90 );
		}
		if ( preg_match( '/^pncp-.+-help$/', $el->getAttribute( 'id' ) ) && $n > PNCP_T_MAX_HELP ) {
			$help[] = $el->getAttribute( 'id' ) . ' ' . $n . ': ' . mb_substr( $text, 0, 70 );
		}
	}
	t( "$tab: καμία περιγραφή πάνω από " . PNCP_T_MAX_WORDS . ' λέξεις έξω από το «More»', ! $long, implode( ' | ', $long ) );
	t( "$tab: κάθε γραμμή βοήθειας πεδίου ως " . PNCP_T_MAX_HELP . ' λέξεις', ! $help, implode( ' | ', $help ) );
	// Χωρίς τα «More»: ούτε νομικές παραπομπές ούτε «Starting value:».
	foreach ( iterator_to_array( $xp->query( './/details[contains(concat(" ", normalize-space(@class), " "), " pncp-more ")]', $wrap ) ) as $fold ) {
		$fold->parentNode->removeChild( $fold );
	}
	$outside = visible_text( $wrap );
	t( "$tab: κανένα «Directive (EU)» έξω από το «More»", false === strpos( $outside, 'Directive (EU)' ) );
	t( "$tab: κανένα «Starting value:»", false === strpos( $body, 'Starting value:' ) );
	t( "$tab: το «May affect visitors/SEO» μόνο ως εικονίδιο", ! preg_match( '/>\s*May affect visitors\/SEO\s*</', preg_replace( '#<span class="screen-reader-text">May affect visitors/SEO</span>#', '', $body ) ) );
}
t( 'log: η σημείωση «A real page here?» σε μία γραμμή, το υπόλοιπο στο «More» (με γραμμές διευθύνσεων που δεν υπάρχουν)', false !== strpos( $all, $pncp_t_path ) && false !== strpos( $all, '<p class="description">A real page here? Add its prefix in “Content addresses” to count it as “Pages”.</p><details class="pncp-more">' ) );
t( 'οι μεγάλες εξηγήσεις υπάρχουν, διπλωμένες στο «More» (καμία δεν σβήστηκε)', $folds >= 60, (string) $folds );
t( 'η παραπομπή στην Οδηγία 2019/790 μένει, μέσα στο «More»', false !== strpos( $all, 'Directive (EU) 2019/790, Article 4(3)' ) );
t( 'ids και names των πεδίων ίδια (π.χ. pncp-rate_limit, aria-describedby της βοήθειας και του κινδύνου)', false !== strpos( $all, 'id="pncp-rate_limit"' ) && false !== strpos( $all, 'name="' . PNCP_OPTION . '[rate_limit]"' ) && false !== strpos( $all, 'aria-describedby="pncp-rate_limit-help pncp-rate_limit-risk"' ) && false !== strpos( $all, 'id="pncp-rate_limit-help"' ) && false !== strpos( $all, 'id="pncp-rate_limit-risk"' ) );
t( 'κάθε αριθμός δείχνει την προεπιλογή του («Default: 60» αντί για «Starting value: 60»)', false !== strpos( $all, 'id="pncp-rate_limit-default">Default: ' ) && false !== strpos( $all, 'id="pncp-rate_limit_lowrep-default">Default: ' ) );

update_option( PNCP_OPTION, $stored );
PNCP_Options::flush();
exit( $fails ? 1 : 0 );
