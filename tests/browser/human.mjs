// ScrapeLock — επαλήθευση ανθρώπου σε πραγματικό Chromium: μετά από scroll / κίνηση ο browser παίρνει το cookie
// pncp_hv και δεν ισχύει πλέον το αυστηρό όριο· χωρίς αλληλεπίδραση δεν δίνεται cookie.
//
//   WP_CLI="wp --path=/path/to/wordpress" BASE=http://127.0.0.1:8099 POST_PATH=/arthro/ node human.mjs
import { chromium } from 'playwright';
import { execSync } from 'node:child_process';

const BASE = process.env.BASE || 'http://127.0.0.1:8099';
const POST = process.env.POST_PATH || '/';
const WP = process.env.WP_CLI || 'wp';
// Κανονικός Chrome: ο headless του Playwright γράφει «HeadlessChrome», που είναι στη λίστα bots.
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

function php( code ) {
	execSync( `${ WP } eval "${ code.replace( /"/g, '\\"' ).replace( /\$/g, '\\$' ) }"`, { stdio: 'pipe' } );
}

let fails = 0;
function t( label, ok, extra = '' ) {
	if ( ! ok ) {
		fails++;
	}
	console.log( ( ok ? 'PASS ' : 'FAIL ' ) + label + ( ok ? '' : '  [' + extra + ']' ) );
}

php( "update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'human_check' => 1, 'rate_limit_unverified' => 2, 'rate_limit' => 0, 'ban_strikes' => 0, 'block_headless' => 0 ) ) ); global $wpdb; $wpdb->query( \"DELETE FROM {$wpdb->options} WHERE option_name LIKE '%pncp_rl_%'\" );" );
const browser = await chromium.launch();
try {
	let ctx = await browser.newContext( { userAgent: UA, extraHTTPHeaders: { 'X-Test-IP': '198.51.100.170', 'Accept-Language': 'el' } } );
	let page = await ctx.newPage();
	const first = await page.goto( BASE + POST );
	t( 'επαλήθευση ανθρώπου: η σελίδα ανοίγει', first.status() === 200, first.status() );
	await page.mouse.move( 100, 100 );
	await page.mouse.move( 200, 150 );
	await page.mouse.move( 250, 200 );
	await page.mouse.wheel( 0, 400 );
	let cookie = null;
	for ( let i = 0; i < 40 && ! cookie; i++ ) {
		await page.waitForTimeout( 250 );
		cookie = ( await ctx.cookies() ).find( ( c ) => c.name === 'pncp_hv' );
	}
	t( 'επαλήθευση ανθρώπου: μετά από scroll ο browser παίρνει το cookie', !! cookie );
	const codes = [];
	for ( let i = 0; i < 4; i++ ) {
		codes.push( ( await page.goto( BASE + POST ) ).status() );
	}
	t( 'επαλήθευση ανθρώπου: με το cookie, 4 σελίδες χωρίς το αυστηρό όριο (2)', codes.every( ( c ) => c === 200 ), codes.join( ',' ) );
	await ctx.close();

	ctx = await browser.newContext( { userAgent: UA, extraHTTPHeaders: { 'X-Test-IP': '198.51.100.171', 'Accept-Language': 'el' } } );
	page = await ctx.newPage();
	const codes2 = [];
	for ( let i = 0; i < 3; i++ ) {
		codes2.push( ( await page.goto( BASE + POST ) ).status() );
		await page.waitForTimeout( 300 );
	}
	cookie = ( await ctx.cookies() ).find( ( c ) => c.name === 'pncp_hv' );
	t( 'επαλήθευση ανθρώπου: χωρίς αλληλεπίδραση δεν δίνεται cookie', ! cookie );
	t( 'επαλήθευση ανθρώπου: χωρίς cookie, η 3η σελίδα 429', codes2[ 2 ] === 429, codes2.join( ',' ) );
	await ctx.close();
} finally {
	await browser.close();
	php( "update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'human_check' => 0 ) ) );" );
}
console.log( fails ? `\n${ fails } FAIL` : '\nΟΛΑ PASS' );
process.exit( fails ? 1 : 0 );
