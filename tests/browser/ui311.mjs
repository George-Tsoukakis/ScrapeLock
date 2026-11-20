// ScrapeLock 3.11 — σελίδα ρυθμίσεων σε πραγματικό Chromium: καρτέλες σε ομάδες, accordion στην καρτέλα Bots
// (ανοιχτά μόνο Bots, Limits, Sign-in, πληκτρολόγιο), λίστες με «Edit» (και χωρίς JavaScript), και ότι μετά από
// Save μένουν ανοιχτά όσα ήταν ανοιχτά (και κλειστά όσα έκλεισαν), με την ίδια λίστα bots.
//
//   BASE=http://127.0.0.1:8099 [SHOTS=/path/to/dir] node ui311.mjs   (admin / admin, ή WP_USER / WP_PASS)
import { chromium } from 'playwright';

const BASE = process.env.BASE || 'http://127.0.0.1:8099';
const USER = process.env.WP_USER || 'admin';
const PASS = process.env.WP_PASS || 'admin';
const SHOTS = process.env.SHOTS || '';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const PAGE = BASE + '/wp-admin/options-general.php?page=scrapelock';
const HEADERS = { 'X-Test-IP': '192.0.2.202', 'Accept-Language': 'en' };

let fails = 0;
function t( label, ok, extra = '' ) {
	if ( ! ok ) {
		fails++;
	}
	console.log( ( ok ? 'PASS ' : 'FAIL ' ) + label + ( ok ? '' : '  [' + extra + ']' ) );
}
const shot = async ( page, name ) => {
	if ( SHOTS ) {
		await page.screenshot( { path: `${ SHOTS }/ui311-${ name }.png`, fullPage: true } );
	}
};
const openParts = ( page ) => page.evaluate( () => [ ...document.querySelectorAll( '.pncp-admin details.pncp-acc, #pncp-sec-network, #pncp-sec-edge' ) ].filter( ( d ) => d.open ).map( ( d ) => d.id ) );
const visible = ( page, sel ) => page.evaluate( ( s ) => {
	const el = document.querySelector( s );
	return !! ( el && el.offsetParent && el.getBoundingClientRect().height > 0 );
}, sel );
const settled = async ( page ) => {
	await page.waitForLoadState( 'load' );
	await page.waitForTimeout( 300 );
};

const browser = await chromium.launch();
try {
	const ctx = await browser.newContext( { userAgent: UA, viewport: { width: 1400, height: 900 }, extraHTTPHeaders: HEADERS } );
	const page = await ctx.newPage();
	page.setDefaultTimeout( 120000 );
	page.on( 'dialog', ( d ) => d.accept() );
	const errors = [];
	page.on( 'pageerror', ( e ) => errors.push( String( e ) ) );
	await page.goto( BASE + '/wp-login.php' );
	await page.fill( '#user_login', USER );
	await page.fill( '#user_pass', PASS );
	await Promise.all( [ page.waitForNavigation(), page.click( '#wp-submit' ) ] );

	/* ---------- Καρτέλες σε ομάδες ---------- */
	await page.goto( PAGE + '&tab=server' );
	const groups = await page.$$eval( '.pncp-tabs .pncp-tab-group__title', ( els ) => els.map( ( e ) => e.textContent.trim() ) );
	t( 'τέσσερις ομάδες με τίτλο', 'Content|Bots & limits|Security|Records' === groups.join( '|' ), groups.join( '|' ) );
	const current = await page.$eval( '.pncp-tab-group.is-current', ( g ) => [ g.querySelector( '.pncp-tab-group__title' ).textContent.trim(), g.querySelector( '.nav-tab-active' ).textContent.trim() ] );
	t( 'tab=server (alias 3.10): «Server rules» ενεργή μέσα στο «Security»', 'Security' === current[ 0 ] && 'Server rules' === current[ 1 ], current.join( ' / ' ) );
	await shot( page, 'tabs-rules' );

	/* ---------- Accordion ---------- */
	await page.goto( PAGE + '&tab=bots' );
	await settled( page );
	t( 'Bots: ανοιχτά μόνο Bots, Sign-in, Limits', 'pncp-sec-bots,pncp-sec-login,pncp-sec-limits' === ( await openParts( page ) ).join( ',' ), ( await openParts( page ) ).join( ',' ) );
	t( 'Bots: το «Advanced» υπάρχει πριν από το CrowdSec', await page.evaluate( () => {
		const h = document.getElementById( 'pncp-group-advanced' );
		const c = document.getElementById( 'pncp-sec-crowdsec' );
		return !! ( h && c && ( h.compareDocumentPosition( c ) & Node.DOCUMENT_POSITION_FOLLOWING ) );
	} ) );
	await shot( page, 'bots-default' );

	// Keyboard: Tab to the summary of "AI", Enter opens it, Enter again closes it.
	await page.focus( '#pncp-sec-ai > summary' );
	await page.keyboard.press( 'Enter' );
	t( 'πληκτρολόγιο: Enter στο «AI search» το ανοίγει', await page.evaluate( () => document.getElementById( 'pncp-sec-ai' ).open ) );
	await page.keyboard.press( 'Enter' );
	t( 'πληκτρολόγιο: ξανά Enter το κλείνει', ! await page.evaluate( () => document.getElementById( 'pncp-sec-ai' ).open ) );

	/* ---------- Λίστα bots: «Edit» ---------- */
	const value = await page.$eval( '#pncp-bot_list', ( el ) => el.value );
	t( 'λίστα bots: το textarea κρυμμένο, προεπισκόπηση και «Edit» ορατά', ! await visible( page, '#pncp-bot_list' ) && await visible( page, '#pncp-bot_list-list .pncp-list__preview' ) && await visible( page, '#pncp-bot_list-list .pncp-list__edit' ) );
	t( 'λίστα bots: aria-expanded=false', 'false' === await page.getAttribute( '#pncp-bot_list-list .pncp-list__edit', 'aria-expanded' ) );
	await page.focus( '#pncp-bot_list-list .pncp-list__edit' );
	await page.keyboard.press( 'Enter' );
	t( 'Edit (πληκτρολόγιο): το textarea ορατό με εστίαση, aria-expanded=true, «Done»', await visible( page, '#pncp-bot_list' ) && 'pncp-bot_list' === await page.evaluate( () => document.activeElement.id ) && 'true' === await page.getAttribute( '#pncp-bot_list-list .pncp-list__edit', 'aria-expanded' ) && 'Done' === ( await page.textContent( '#pncp-bot_list-list .pncp-list__edit' ) ).trim() );
	t( 'Edit: ίδια τιμή στο textarea', value === await page.$eval( '#pncp-bot_list', ( el ) => el.value ) );
	await page.click( '#pncp-bot_list-list .pncp-list__edit' );
	t( 'Done: ξανά κρυμμένο, aria-expanded=false', ! await visible( page, '#pncp-bot_list' ) && 'false' === await page.getAttribute( '#pncp-bot_list-list .pncp-list__edit', 'aria-expanded' ) );
	await page.click( '#pncp-bot_list-list .pncp-list__edit' );
	await shot( page, 'bots-list-open' );

	/* ---------- Save: μένουν ανοιχτά όσα ήταν ανοιχτά ---------- */
	await page.click( '#pncp-sec-human > summary' ); // open "Human check"
	await page.click( '#pncp-sec-bots > summary' ); // close "Scrapers and bots"
	const before = await openParts( page );
	await page.locator( 'form[action="options.php"] #submit' ).scrollIntoViewIfNeeded();
	await Promise.all( [ page.waitForNavigation(), page.click( 'form[action="options.php"] #submit' ) ] );
	await settled( page );
	const after = await openParts( page );
	t( 'Save: τα ίδια μέρη ανοιχτά (Human check ναι, Scrapers and bots όχι)', before.join( ',' ) === after.join( ',' ) && after.includes( 'pncp-sec-human' ) && ! after.includes( 'pncp-sec-bots' ), before.join( ',' ) + ' → ' + after.join( ',' ) );
	t( 'Save: η λίστα bots ανοιχτή όπως ήταν', await page.evaluate( () => document.getElementById( 'pncp-bot_list-list' ).classList.contains( 'is-open' ) ) && 'true' === await page.getAttribute( '#pncp-bot_list-list .pncp-list__edit', 'aria-expanded' ) );
	t( 'Save: η λίστα bots ίδια', value === await page.$eval( '#pncp-bot_list', ( el ) => el.value ) );
	await shot( page, 'bots-after-save' );

	// A plain visit afterwards: the defaults again.
	await page.goto( PAGE + '&tab=bots' );
	await settled( page );
	t( 'επόμενη απλή επίσκεψη: πάλι μόνο τα προεπιλεγμένα', 'pncp-sec-bots,pncp-sec-login,pncp-sec-limits' === ( await openParts( page ) ).join( ',' ), ( await openParts( page ) ).join( ',' ) );

	// A link with #pncp-sec-… opens its part.
	await page.goto( PAGE + '&tab=bots#pncp-sec-countries' );
	await settled( page );
	t( '#pncp-sec-countries στη διεύθυνση: το μέρος ανοιχτό', await page.evaluate( () => document.getElementById( 'pncp-sec-countries' ).open ) );
	await page.goto( PAGE + '&tab=bots' );
	await page.click( '.pncp-section-nav a[href="#pncp-sec-lists"]' );
	await page.waitForTimeout( 200 );
	t( 'γρήγορος σύνδεσμος «IP lists»: το Official IP lists ανοιχτό', await page.evaluate( () => document.getElementById( 'pncp-acc-lists' ).open ) );

	t( 'κανένα σφάλμα JS', ! errors.length, errors.join( ' | ' ) );

	/* ---------- Χωρίς JavaScript ---------- */
	const ctx2 = await browser.newContext( { userAgent: UA, viewport: { width: 1400, height: 900 }, javaScriptEnabled: false, storageState: await ctx.storageState(), extraHTTPHeaders: HEADERS } );
	const p2 = await ctx2.newPage();
	p2.setDefaultTimeout( 120000 );
	await p2.goto( PAGE + '&tab=bots' );
	t( 'χωρίς JS: το textarea της λίστας ορατό, χωρίς κουμπί Edit', await visible( p2, '#pncp-bot_list' ) && ! await visible( p2, '#pncp-bot_list-list .pncp-list__edit' ) );
	await shot( p2, 'bots-nojs' );
	await ctx2.close();
	await ctx.close();
} finally {
	await browser.close();
}
console.log( fails ? `\n${ fails } FAIL` : '\nΟΛΑ PASS' );
process.exit( fails ? 1 : 0 );
