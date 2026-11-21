// ScrapeLock 3.12.5 — "Applies to: only visitors who are not signed in" of the screenshot blur, in real Chromium
// (Playwright) on a real WordPress: a guest gets the blur, a signed-in subscriber does not (also on a page cached
// for guests, thanks to the pncp_si cookie), "Everyone" blurs both, an excluded editor gets no protection script.
//
//   WP_CLI="wp --path=/path/to/wordpress" BASE=http://127.0.0.1:8099 POST_PATH=/test/ node blur3125.mjs
//
// Changes the plugin's settings and creates two users with wp-cli: only on a test WordPress.
import { chromium } from 'playwright';
import { execSync } from 'node:child_process';

const BASE = process.env.BASE || 'http://127.0.0.1:8099';
const POST = process.env.POST_PATH || '/';
const WP = process.env.WP_CLI || 'wp';
const PASS = 'pncp-3125-' + Math.random().toString( 36 ).slice( 2, 12 );
let fails = 0;
const t = ( label, ok, extra = '' ) => {
	if ( ! ok ) fails++;
	console.log( ( ok ? 'PASS ' : 'FAIL ' ) + label + ( ! ok && extra ? `  [${ extra }]` : '' ) );
};

const wp = ( args ) => execSync( `${ WP } ${ args }`, { stdio: 'pipe' } ).toString().trim();
const php = ( code ) => {
	const b64 = Buffer.from( code ).toString( 'base64' );
	return wp( `eval "eval( base64_decode( '${ b64 }' ) );"` );
};
function settings( changes ) {
	php( `$s = PNCP_Options::stored(); foreach ( json_decode( base64_decode( '${ Buffer.from( JSON.stringify( changes ) ).toString( 'base64' ) }' ), true ) as $k => $v ) { $s[ $k ] = $v; } update_option( PNCP_OPTION, $s );` );
}

const saved = php( 'echo base64_encode( wp_json_encode( get_option( PNCP_OPTION ) ) );' );
const users = {};
for ( const [ login, role ] of [ [ 'pncp3125sub', 'subscriber' ], [ 'pncp3125ed', 'editor' ] ] ) {
	php( `$u = get_user_by( 'login', '${ login }' ); if ( $u ) { require_once ABSPATH . 'wp-admin/includes/user.php'; wp_delete_user( $u->ID ); }` );
	users[ login ] = wp( `user create ${ login } ${ login }@example.com --role=${ role } --user_pass=${ PASS } --porcelain` );
}

const browser = await chromium.launch( { executablePath: process.env.CHROMIUM || undefined } );
const errors = [];
let ip = 10;

async function context( login ) {
	// A visitor's address (mu-test-harness) and a desktop Chrome: "HeadlessChrome" is in the bot list.
	const ctx = await browser.newContext( {
		extraHTTPHeaders: { 'X-Test-IP': '192.0.2.' + ip++ },
		userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
	} );
	const page = await ctx.newPage();
	// The site's pages only: wp-admin's own scripts are not ScrapeLock's.
	page.on( 'pageerror', ( e ) => ( page.url().includes( '/wp-admin/' ) ? null : errors.push( page.url() + ': ' + e.message ) ) );
	if ( login ) {
		await page.goto( BASE + '/wp-login.php', { waitUntil: 'load' } );
		await page.fill( '#user_login', login );
		await page.fill( '#user_pass', PASS );
		await Promise.all( [ page.waitForURL( /\/wp-admin\//, { waitUntil: 'load' } ), page.click( '#wp-submit' ) ] );
		// Leave wp-admin, so none of its background requests (Heartbeat) runs after the test changes the cookies.
		await page.goto( 'about:blank' );
	}
	return { ctx, page };
}

const blurred = ( page ) => page.evaluate( () => document.documentElement.classList.contains( 'pncp-blurred' ) );
const shield = ( page ) => page.evaluate( () => !! document.querySelector( '.pncp-shield' ) );
const clear = async ( page ) => {
	await page.mouse.click( 300, 400 ); // pointerdown on the page (below the admin bar): the visitor is back, the blur goes.
	await page.waitForTimeout( 50 );
};

/** PrintScreen (keyup, as Windows sends it) and Ctrl+Shift+S, pressed for real: [blurred after each]. */
async function shots( page ) {
	await page.bringToFront();
	await clear( page );
	await page.keyboard.press( 'PrintScreen' );
	const a = await blurred( page );
	await clear( page );
	await page.keyboard.press( 'Control+Shift+S' );
	const b = await blurred( page );
	await clear( page );
	return [ a, b ];
}

try {
	settings( { enabled: 1, exempt_cap: 'edit_posts', blur_on_capture: 1, blur_on_capture_scope: 'guests', block_shortcuts: 1, human_check: 0 } );

	/* ---------- "Only visitors who are not signed in" ---------- */
	const guest = await context( '' );
	const res = await guest.page.goto( BASE + POST, { waitUntil: 'load' } );
	const guestHtml = await res.text(); // The page as a cache would store it.
	t( 'guest: protect.js with blurScope "guests"', await guest.page.evaluate( () => !! window.pncpConfig && window.pncpConfig.blurScope === 'guests' ) );
	t( 'guest: the blur layer is ready', await shield( guest.page ) );
	let r = await shots( guest.page );
	t( 'guest: PrintScreen blurs the page (html.pncp-blurred)', r[ 0 ] );
	t( 'guest: Ctrl+Shift+S blurs the page', r[ 1 ] );
	t( 'guest: no pncp_si cookie', ! ( await guest.ctx.cookies() ).some( ( c ) => c.name === 'pncp_si' ) );

	const sub = await context( 'pncp3125sub' );
	const cookies = await sub.ctx.cookies();
	const hint = cookies.find( ( c ) => c.name === 'pncp_si' );
	t( 'subscriber: signed in (logged_in cookie)', cookies.some( ( c ) => c.name.startsWith( 'wordpress_logged_in_' ) ) );
	t( 'subscriber: pncp_si=1, readable by the page, SameSite=Lax', !! hint && hint.value === '1' && ! hint.httpOnly && hint.sameSite === 'Lax', JSON.stringify( hint ) );
	await sub.page.goto( BASE + POST, { waitUntil: 'load' } );
	t( 'subscriber: protected page (not excluded), same config', await sub.page.evaluate( () => !! window.pncpConfig && window.pncpConfig.blur === true && window.pncpConfig.blurScope === 'guests' ) );
	t( 'subscriber: the page reads the cookie', await sub.page.evaluate( () => /(?:^|;\s*)pncp_si=1(?:;|$)/.test( document.cookie ) ) );
	r = await shots( sub.page );
	t( 'subscriber: PrintScreen does not blur', ! r[ 0 ] );
	t( 'subscriber: Ctrl+Shift+S does not blur', ! r[ 1 ] );
	t( 'subscriber: no blur layer at all', ! ( await shield( sub.page ) ) );

	// A page cache (WP Rocket, Bunny) serving the guest's HTML to the signed-in browser.
	t( 'cached page: the guest HTML has no logged-in body class', ! /<body[^>]*class="[^"]*\blogged-in\b/.test( guestHtml ) );
	await sub.page.route( BASE + POST, ( route ) => route.fulfill( { status: 200, contentType: 'text/html; charset=UTF-8', body: guestHtml } ) );
	await sub.page.goto( BASE + POST, { waitUntil: 'load' } );
	t( 'cached page: served the guest HTML', await sub.page.evaluate( () => ! document.body.classList.contains( 'logged-in' ) && !! window.pncpConfig ) );
	r = await shots( sub.page );
	t( 'cached page: the signed-in subscriber still gets no blur (cookie)', ! r[ 0 ] && ! r[ 1 ] );
	t( 'cached page: no blur layer', ! ( await shield( sub.page ) ) );

	// Control: the same cached page in a signed-in browser without the cookie (signed in before 3.12.5 and not yet
	// back on an uncached page): nothing tells the page, so it blurs. The cookie above is what made the difference.
	const before = await context( 'pncp3125sub' );
	await before.ctx.clearCookies( { name: 'pncp_si' } );
	await before.page.route( BASE + POST, ( route ) => route.fulfill( { status: 200, contentType: 'text/html; charset=UTF-8', body: guestHtml } ) );
	await before.page.goto( BASE + POST, { waitUntil: 'load' } );
	r = await shots( before.page );
	t( 'cached page, no cookie yet (control): blurred, as documented', r[ 0 ] && r[ 1 ] );
	await before.ctx.close();

	// An uncached page in a browser that cannot keep the cookie: the logged-in body class decides.
	const uncookied = await context( 'pncp3125sub' );
	await uncookied.ctx.clearCookies( { name: 'pncp_si' } );
	await uncookied.page.route( BASE + POST, async ( route ) => {
		const resp = await route.fetch();
		const body = ( await resp.text() ).replace( /document\.cookie/g, '""' ); // A browser that cannot store the hint.
		route.fulfill( { response: resp, body } );
	} );
	await uncookied.page.goto( BASE + POST, { waitUntil: 'load' } );
	t( 'uncached page without the cookie: the logged-in body class', await uncookied.page.evaluate( () => document.body.classList.contains( 'logged-in' ) ) );
	r = await shots( uncookied.page );
	t( 'uncached page without the cookie: no blur (body class)', ! r[ 0 ] && ! r[ 1 ] );

	/* ---------- "Everyone" ---------- */
	settings( { blur_on_capture_scope: 'all' } );
	await guest.page.goto( BASE + POST, { waitUntil: 'load' } );
	r = await shots( guest.page );
	t( 'Everyone: the guest is blurred', r[ 0 ] && r[ 1 ] );
	await sub.page.unroute( BASE + POST );
	await sub.page.goto( BASE + POST, { waitUntil: 'load' } );
	r = await shots( sub.page );
	t( 'Everyone: the signed-in subscriber is blurred too', r[ 0 ] && r[ 1 ] );

	/* ---------- An excluded editor ("Who is excluded": edit_posts) ---------- */
	for ( const scope of [ 'guests', 'all' ] ) {
		settings( { blur_on_capture_scope: scope } );
		const ed = await context( 'pncp3125ed' );
		await ed.page.goto( BASE + POST, { waitUntil: 'load' } );
		t( `editor (${ scope }): excluded, no protect.js`, await ed.page.evaluate( () => ! window.pncpConfig ) );
		r = await shots( ed.page );
		t( `editor (${ scope }): no blur`, ! r[ 0 ] && ! r[ 1 ] );
		await ed.ctx.close();
	}

	/* ---------- Sign-out ---------- */
	settings( { blur_on_capture_scope: 'guests' } );
	await sub.page.goto( BASE + '/wp-admin/profile.php', { waitUntil: 'load' } );
	const logout = await sub.page.evaluate( () => {
		const a = document.querySelector( '#wp-admin-bar-logout a' );
		return a ? a.href : '';
	} );
	await sub.page.goto( logout, { waitUntil: 'load' } );
	t( 'after sign-out: no pncp_si cookie', ! ( await sub.ctx.cookies() ).some( ( c ) => c.name === 'pncp_si' ) );
	await sub.page.goto( BASE + POST, { waitUntil: 'load' } );
	r = await shots( sub.page );
	t( 'after sign-out: blurred like any guest', r[ 0 ] && r[ 1 ] );

	t( 'no JavaScript errors', errors.length === 0, errors.join( ' | ' ) );
} finally {
	php( `update_option( PNCP_OPTION, json_decode( base64_decode( '${ saved }' ), true ) );` );
	php( `require_once ABSPATH . 'wp-admin/includes/user.php'; foreach ( array( ${ Object.values( users ).map( Number ).join( ', ' ) } ) as $id ) { wp_delete_user( $id ); }` );
	await browser.close();
}
console.log( fails ? `\n${ fails } FAIL` : '\nall PASS' );
process.exit( fails ? 1 : 0 );
