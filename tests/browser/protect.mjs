// Content Protect 2.1 — το protect.js σε πραγματικό Chromium (Playwright), πάνω σε πραγματικό WordPress.
//
//   WP_CLI="wp --path=/path/to/wordpress" BASE=http://127.0.0.1:8099 POST_PATH=/arthro/ node protect.mjs
//
// Αλλάζει τις ρυθμίσεις του plugin με wp-cli: μόνο σε WordPress δοκιμών.
import { chromium } from 'playwright';
import { execSync } from 'node:child_process';

const BASE = process.env.BASE || 'http://127.0.0.1:8099';
const POST = process.env.POST_PATH || '/';
const WP = process.env.WP_CLI || 'wp';
let fails = 0;
const t = ( label, ok, extra = '' ) => {
	if ( ! ok ) fails++;
	console.log( ( ok ? 'PASS ' : 'FAIL ' ) + label + ( ! ok && extra ? `  [${ extra }]` : '' ) );
};

function settings( changes ) {
	const php = `$s = PNCP_Options::stored(); foreach ( json_decode( base64_decode( '${ Buffer.from( JSON.stringify( changes ) ).toString( 'base64' ) }' ), true ) as $k => $v ) { $s[ $k ] = $v; } update_option( PNCP_OPTION, $s );`;
	execSync( `${ WP } eval "${ php.replace( /"/g, '\\"' ).replace( /\$/g, '\\$' ) }"`, { stdio: 'pipe' } );
}

const browser = await chromium.launch( { executablePath: process.env.CHROMIUM || undefined } );
const page = await browser.newPage();
const errors = [];
page.on( 'pageerror', ( e ) => errors.push( e.message ) );

async function load() {
	await page.goto( BASE + POST, { waitUntil: 'load' } );
	// Ένα «εχθρικό» script της σελίδας: προσπαθεί να σταματήσει τα συμβάντα πριν φτάσουν στην προστασία.
	await page.evaluate( () => {
		for ( const type of [ 'contextmenu', 'copy', 'selectstart', 'keydown', 'dragstart' ] ) {
			document.addEventListener( type, ( e ) => e.stopImmediatePropagation(), true );
		}
		const p = document.createElement( 'p' );
		p.id = 'pncp-test-text';
		p.textContent = 'Πολύτιμο κείμενο φαρμακείου. '.repeat( 20 );
		const allow = document.createElement( 'span' );
		allow.className = 'pncp-allow';
		allow.id = 'pncp-test-allow';
		allow.textContent = '2101234567';
		const input = document.createElement( 'input' );
		input.id = 'pncp-test-input';
		input.value = 'κουπόνι';
		document.body.append( p, allow, input );
	} );
}

const fire = ( type, target, init = {} ) =>
	page.evaluate(
		( [ type, target, init ] ) => {
			const el = document.querySelector( target );
			let ev;
			if ( type === 'copy' ) {
				ev = new ClipboardEvent( 'copy', { bubbles: true, cancelable: true, clipboardData: new DataTransfer() } );
			} else if ( type === 'keydown' || type === 'keyup' ) {
				ev = new KeyboardEvent( type, Object.assign( { bubbles: true, cancelable: true }, init ) );
			} else if ( type === 'dragstart' ) {
				ev = new DragEvent( 'dragstart', { bubbles: true, cancelable: true } );
			} else {
				ev = new Event( type, { bubbles: true, cancelable: true } );
			}
			el.dispatchEvent( ev );
			return {
				prevented: ev.defaultPrevented,
				plain: ev.clipboardData ? ev.clipboardData.getData( 'text/plain' ) : '',
			};
		},
		[ type, target, init ]
	);

const select = ( target ) =>
	page.evaluate( ( target ) => {
		const r = document.createRange();
		r.selectNodeContents( document.querySelector( target ) );
		const s = getSelection();
		s.removeAllRanges();
		s.addRange( r );
	}, target );

/* ---------- Ισορροπημένο: αντιγραφή με πηγή ---------- */
settings( { enabled: 1, exempt_cap: 'none', block_selection: 0, copy_mode: 'attribution', attribution_min_chars: 200, block_context_menu: 1, block_text_drag: 1, block_image_drag: 1, blur_on_capture: 0, show_message: 1 } );
await load();
t( 'το protect.js φορτώθηκε (pncpConfig)', await page.evaluate( () => !! window.pncpConfig ) );
let r = await fire( 'contextmenu', '#pncp-test-text' );
t( 'δεξί κλικ μπλοκάρεται, ακόμη και με «εχθρικό» listener της σελίδας', r.prevented );
t( 'μήνυμα με role=status', await page.evaluate( () => !! document.querySelector( '.pncp-toast[role="status"].pncp-toast--visible' ) ) );
r = await fire( 'contextmenu', '#pncp-test-input' );
t( 'δεξί κλικ σε πεδίο φόρμας επιτρέπεται', ! r.prevented );
await select( '#pncp-test-text' );
r = await fire( 'copy', '#pncp-test-text' );
t( 'αντιγραφή: προστίθεται η πηγή και ο σύνδεσμος', r.prevented && r.plain.includes( 'Πηγή:' ) && r.plain.includes( BASE ), r.plain.slice( -120 ) );
await select( '#pncp-test-allow' );
r = await fire( 'copy', '#pncp-test-allow' );
t( 'αντιγραφή από .pncp-allow: καθαρή', ! r.prevented );
await select( '#pncp-test-text' );
r = await fire( 'dragstart', '#pncp-test-text' );
t( 'σύρσιμο επιλεγμένου κειμένου μπλοκάρεται', r.prevented );
await page.evaluate( () => {
	getSelection().removeAllRanges();
	const d = document.createElement( 'li' );
	d.id = 'pncp-test-drag';
	d.draggable = true;
	d.textContent = 'στοιχείο λίστας ταξινόμησης';
	document.body.append( d );
} );
r = await fire( 'dragstart', '#pncp-test-drag' );
t( 'widget με draggable (ταξινόμηση) δουλεύει κανονικά', ! r.prevented );

/* ---------- Αυστηρό: χωρίς επιλογή και αντιγραφή ---------- */
settings( { block_selection: 1, copy_mode: 'block', block_shortcuts: 1 } );
await load();
t( 'body.pncp-no-select', await page.evaluate( () => document.body.classList.contains( 'pncp-no-select' ) ) );
r = await fire( 'selectstart', '#pncp-test-text' );
t( 'επιλογή κειμένου μπλοκάρεται', r.prevented );
r = await fire( 'selectstart', '#pncp-test-input' );
t( 'επιλογή σε πεδίο φόρμας επιτρέπεται', ! r.prevented );
await select( '#pncp-test-text' );
r = await fire( 'copy', '#pncp-test-text' );
t( 'αντιγραφή μπλοκάρεται', r.prevented && '' === r.plain );
r = await fire( 'keydown', '#pncp-test-text', { key: 'α', code: 'KeyA', ctrlKey: true } );
t( 'Ctrl+A με ελληνική διάταξη μπλοκάρεται', r.prevented );
r = await fire( 'keydown', '#pncp-test-input', { key: 'a', code: 'KeyA', ctrlKey: true } );
t( 'Ctrl+A μέσα σε πεδίο επιτρέπεται', ! r.prevented );
r = await fire( 'keydown', '#pncp-test-text', { key: 'Tab', code: 'Tab' } );
t( 'Tab (πλοήγηση) δεν επηρεάζεται', ! r.prevented );

/* ---------- Θόλωμα σε screenshot ---------- */
settings( { blur_on_capture: 1 } );
await load();
await fire( 'keyup', '#pncp-test-text', { key: 'PrintScreen', code: 'PrintScreen' } );
t( 'Print Screen: η σελίδα θολώνει', await page.evaluate( () => document.documentElement.classList.contains( 'pncp-blurred' ) ) );
await page.waitForTimeout( 4300 );
t( 'μετά από 4 δευτερόλεπτα ξανά καθαρή', ! ( await page.evaluate( () => document.documentElement.classList.contains( 'pncp-blurred' ) ) ) );

t( 'κανένα σφάλμα JavaScript στη σελίδα', errors.length === 0, errors.join( ' | ' ) );

settings( { exempt_cap: 'edit_posts', blur_on_capture: 0, block_selection: 0, copy_mode: 'attribution' } );
await browser.close();
console.log( fails ? `\n${ fails } FAIL` : '\nΟΛΑ PASS' );
process.exit( fails ? 1 : 0 );
