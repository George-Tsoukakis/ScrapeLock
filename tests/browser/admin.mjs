// ScrapeLock 3.10 — σελίδα ρυθμίσεων σε πραγματικό Chromium: καρτέλες με άλλο όνομα / άγνωστη καρτέλα στη
// διεύθυνση, και τα ανοιχτά <details> που μένουν ανοιχτά μετά από Save (φόρμα της καρτέλας, Blocking at the CDN,
// κάρτες hardening, Log), με κύλιση πίσω στο κουμπί που πατήθηκε.
//
//   WP_CLI="wp --path=/path/to/wordpress" BASE=http://127.0.0.1:8099 node admin.mjs   (admin / admin)
import { chromium } from 'playwright';

const BASE = process.env.BASE || 'http://127.0.0.1:8099';
const USER = process.env.WP_USER || 'admin';
const PASS = process.env.WP_PASS || 'admin';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const PAGE = BASE + '/wp-admin/options-general.php?page=scrapelock';

let fails = 0;
function t( label, ok, extra = '' ) {
	if ( ! ok ) {
		fails++;
	}
	console.log( ( ok ? 'PASS ' : 'FAIL ' ) + label + ( ok ? '' : '  [' + extra + ']' ) );
}

const activeTab = ( page ) => page.evaluate( () => {
	const m = /pncp-admin--([a-z0-9_-]+)/.exec( document.querySelector( '.pncp-admin' ).className );
	return m ? m[ 1 ] : '';
} );
const isOpen = ( page, sel ) => page.evaluate( ( s ) => {
	const el = document.querySelector( s );
	return !! ( el && el.open );
}, sel );
const inView = ( page, sel ) => page.evaluate( ( s ) => {
	const el = document.querySelector( s );
	if ( ! el ) {
		return false;
	}
	const r = el.getBoundingClientRect();
	return r.bottom > 0 && r.top < window.innerHeight;
}, sel );
// The button is in the window, and the page really scrolled when the button is below the first screen.
const scrolledTo = ( page, sel, before ) => page.evaluate( ( [ s, top ] ) => {
	const el = document.querySelector( s );
	if ( ! el ) {
		return false;
	}
	const r = el.getBoundingClientRect();
	return r.bottom > 0 && r.top < window.innerHeight && ( top < window.innerHeight || window.scrollY > 0 );
}, [ sel, before ] );
const docTop = ( page, sel ) => page.evaluate( ( s ) => document.querySelector( s ).getBoundingClientRect().top + window.scrollY, sel );
const settled = async ( page ) => {
	await page.waitForLoadState( 'load' );
	await page.waitForTimeout( 300 );
};

const browser = await chromium.launch();
try {
	const ctx = await browser.newContext( { userAgent: UA, viewport: { width: 1280, height: 500 }, extraHTTPHeaders: { 'X-Test-IP': '192.0.2.201', 'Accept-Language': 'en' } } );
	const page = await ctx.newPage();
	page.on( 'dialog', ( d ) => d.accept() );
	const errors = [];
	page.on( 'pageerror', ( e ) => errors.push( String( e ) ) );
	await page.goto( BASE + '/wp-login.php' );
	await page.fill( '#user_login', USER );
	await page.fill( '#user_pass', PASS );
	await Promise.all( [ page.waitForNavigation(), page.click( '#wp-submit' ) ] );

	/* ---------- (a) Καρτέλες ---------- */
	for ( const [ alias, want ] of [ [ 'vulnerable', 'hardening' ], [ 'vulnerable-points', 'hardening' ], [ 'server', 'rules' ], [ 'attack', 'attacks' ], [ 'hardening', 'hardening' ] ] ) {
		await page.goto( PAGE + '&tab=' + alias );
		const tab = await activeTab( page );
		const href = await page.getAttribute( '.nav-tab-active', 'href' );
		const notice = await page.$( '.pncp-unknown-tab' );
		t( `tab=${ alias } → καρτέλα ${ want }, ενεργή στη λίστα, χωρίς ειδοποίηση`, want === tab && ( href || '' ).includes( 'tab=' + want ) && ! notice, tab + ' ' + href );
	}
	await page.goto( PAGE + '&tab=nosuchtab' );
	const unknown = await page.textContent( '.pncp-unknown-tab' ).catch( () => '' );
	t( 'άγνωστη καρτέλα: η πρώτη καρτέλα με ειδοποίηση «Unknown tab “nosuchtab”»', 'general' === await activeTab( page ) && ( unknown || '' ).includes( 'Unknown tab “nosuchtab”' ), unknown );

	/* ---------- (b) Bots and limits: φόρμα της καρτέλας (options.php) ---------- */
	await page.goto( PAGE + '&tab=bots' );
	await page.evaluate( () => {
		document.querySelector( '#pncp-sec-network' ).open = true;
		const fold = document.querySelector( 'details.pncp-fold' );
		fold.open = true;
		fold.setAttribute( 'data-test-fold', '1' );
	} );
	const foldKey = await page.evaluate( () => document.querySelector( '[data-test-fold] [id]' ).id );
	const saveTop = await docTop( page, 'form[action="options.php"] #submit' );
	await page.locator( 'form[action="options.php"] #submit' ).scrollIntoViewIfNeeded();
	await Promise.all( [ page.waitForNavigation(), page.click( 'form[action="options.php"] #submit' ) ] );
	await settled( page );
	t( 'Save (bots): γυρίζει στην καρτέλα bots με «settings-updated»', 'bots' === await activeTab( page ) && ( await page.$( '#setting-error-settings_updated' ) || page.url().includes( 'tab=bots' ) ), page.url() );
	t( 'Save (bots): το «Network and CDN» ξανά ανοιχτό (από την PHP)', await page.evaluate( () => document.querySelector( '#pncp-sec-network' ).hasAttribute( 'open' ) ) );
	t( 'Save (bots): η ανοιχτή λίστα (fold) ξανά ανοιχτή', await page.evaluate( ( id ) => {
		const el = document.getElementById( id );
		return !! ( el && el.closest( 'details' ) && el.closest( 'details' ).open );
	}, foldKey ), foldKey );
	t( 'Save (bots): το «Blocking at the CDN» μένει κλειστό', ! await isOpen( page, '#pncp-sec-edge' ) );
	t( 'Save (bots): η σελίδα κυλά στο κουμπί Save', await scrolledTo( page, 'form[action="options.php"] #submit', saveTop ), String( saveTop ) );
	t( 'Save (bots): τα pncp_sections / pncp_focus φεύγουν από τη γραμμή διεύθυνσης', ! page.url().includes( 'pncp_sections' ) && ! page.url().includes( 'pncp_focus' ), page.url() );

	/* ---------- (b) Blocking at the CDN: δική του φόρμα (admin-post.php), 3.9 pncp_open=edge ---------- */
	await page.goto( PAGE + '&tab=bots' );
	await page.evaluate( () => {
		document.querySelector( '#pncp-sec-network' ).open = true;
		document.querySelector( '#pncp-sec-edge' ).open = true;
	} );
	const edgeTop = await docTop( page, '#pncp-submit-pncp-edge' );
	await page.locator( '#pncp-submit-pncp-edge' ).scrollIntoViewIfNeeded();
	await Promise.all( [ page.waitForNavigation(), page.click( '#pncp-submit-pncp-edge' ) ] );
	await settled( page );
	t( 'CDN form: «Blocking at the CDN» ανοιχτό όπως στην 3.9', await isOpen( page, '#pncp-sec-edge' ), page.url() );
	t( 'CDN form: και το «Network and CDN» που ήταν ανοιχτό', await isOpen( page, '#pncp-sec-network' ) );
	t( 'CDN form: η σελίδα στο κουμπί της φόρμας', await scrolledTo( page, '#pncp-submit-pncp-edge', edgeTop ), String( edgeTop ) );

	/* ---------- (b) Feeds and API: φόρμα της καρτέλας ---------- */
	await page.goto( PAGE + '&tab=content' );
	const routes = await page.$( 'details.pncp-public-routes' );
	if ( routes ) {
		await page.evaluate( () => {
			document.querySelector( 'details.pncp-public-routes' ).open = true;
		} );
	}
	const contentTop = await docTop( page, 'form[action="options.php"] #submit' );
	await page.locator( 'form[action="options.php"] #submit' ).scrollIntoViewIfNeeded();
	await Promise.all( [ page.waitForNavigation(), page.click( 'form[action="options.php"] #submit' ) ] );
	await settled( page );
	t( 'Save (content): ξανά ανοιχτό το «Show the routes»', ! routes || await isOpen( page, 'details.pncp-public-routes' ) );
	t( 'Save (content): η σελίδα κυλά στο κουμπί Save', await scrolledTo( page, 'form[action="options.php"] #submit', contentTop ), String( contentTop ) );

	/* ---------- (b) Vulnerable points: κάρτα hardening ---------- */
	await page.goto( PAGE + '&tab=hardening' );
	const hdKeys = await page.evaluate( () => {
		const ds = [ ...document.querySelectorAll( '.pncp-admin details' ) ];
		ds.forEach( ( d, i ) => d.setAttribute( 'data-test-d', String( i ) ) );
		return ds.map( ( d ) => d.open );
	} );
	if ( hdKeys.length ) {
		const closed = hdKeys.findIndex( ( o ) => ! o );
		if ( closed >= 0 ) {
			await page.evaluate( ( i ) => {
				document.querySelector( `[data-test-d="${ i }"]` ).open = true;
			}, closed );
		}
		const btn = page.locator( 'form button, form input[type=submit]', { hasText: 'Check again' } ).first();
		const hasBtn = await btn.count();
		if ( hasBtn ) {
			await btn.scrollIntoViewIfNeeded();
			await Promise.all( [ page.waitForNavigation(), btn.click() ] );
			await settled( page );
			const open = await page.evaluate( () => [ ...document.querySelectorAll( '.pncp-admin details' ) ].map( ( d ) => d.open ) );
			t( 'hardening «Check again»: τα ανοιχτά <details> ξανά ανοιχτά', closed < 0 || open[ closed ], JSON.stringify( open ) );
			t( 'hardening «Check again»: η σελίδα στο κουμπί', await page.locator( 'form button, form input[type=submit]', { hasText: 'Check again' } ).first().evaluate( ( el ) => {
				const r = el.getBoundingClientRect();
				return r.bottom > 0 && r.top < window.innerHeight;
			} ) );
		} else {
			console.log( 'SKIP hardening: δεν βρέθηκε «Check again»' );
		}
	}

	/* ---------- (b) Log: φόρμα που απαντά χωρίς redirect (localStorage) ---------- */
	await page.goto( PAGE + '&tab=log' );
	if ( await page.$( '#pncp-tester' ) && await page.$( '#pncp-trace form' ) ) {
		await page.evaluate( () => {
			document.querySelector( '#pncp-tester' ).open = true;
			document.querySelector( '#pncp-trace' ).open = true;
		} );
		const trace = page.locator( '#pncp-trace form [type=submit]' ).first();
		await trace.scrollIntoViewIfNeeded();
		await Promise.all( [ page.waitForNavigation(), trace.click() ] );
		await settled( page );
		t( 'Log «Find» (POST στην ίδια σελίδα): το «Check a request» ξανά ανοιχτό (localStorage)', await isOpen( page, '#pncp-tester' ) );
		await page.goto( PAGE + '&tab=log' );
		await settled( page );
		t( 'Log: μια απλή επόμενη επίσκεψη δεν ξανανοίγει τίποτα (η κατάσταση καταναλώθηκε)', ! await isOpen( page, '#pncp-tester' ) );
	}

	/* ---------- localStorage μπλοκαρισμένο: χωρίς σφάλμα, τα query args αρκούν ---------- */
	const ctx2 = await browser.newContext( { userAgent: UA, viewport: { width: 1280, height: 800 }, storageState: await ctx.storageState(), extraHTTPHeaders: { 'X-Test-IP': '192.0.2.201', 'Accept-Language': 'en' } } );
	await ctx2.addInitScript( () => {
		Object.defineProperty( window, 'localStorage', { get() {
			throw new Error( 'blocked' );
		} } );
	} );
	const p2 = await ctx2.newPage();
	const errors2 = [];
	// WordPress's own scripts may complain about the blocked storage: only errors from ScrapeLock's scripts count.
	p2.on( 'pageerror', ( e ) => {
		if ( /scrapelock|admin-sections|pncp/.test( String( e.stack || '' ) ) ) {
			errors2.push( String( e ) );
		}
	} );
	await p2.goto( PAGE + '&tab=bots' );
	await p2.evaluate( () => {
		document.querySelector( '#pncp-sec-network' ).open = true;
	} );
	await Promise.all( [ p2.waitForNavigation(), p2.click( 'form[action="options.php"] #submit' ) ] );
	await settled( p2 );
	t( 'χωρίς localStorage: το «Network and CDN» ξανά ανοιχτό, χωρίς σφάλμα JS', await isOpen( p2, '#pncp-sec-network' ) && ! errors2.length, errors2.join( ' | ' ) );
	await ctx2.close();

	t( 'κανένα σφάλμα JS στις σελίδες', ! errors.length, errors.join( ' | ' ) );
	await ctx.close();
} finally {
	await browser.close();
}
console.log( fails ? `\n${ fails } FAIL` : '\nΟΛΑ PASS' );
process.exit( fails ? 1 : 0 );
