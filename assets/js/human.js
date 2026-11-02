/**
 * ScrapeLock – human check.
 *
 * After the first real interaction (scroll, tap, key, mouse movement) it asks for a challenge, solves a light
 * proof of work with SHA-256 and receives a signed cookie. Nothing is shown to the visitor. If the browser
 * lacks fetch or Web Crypto, it does nothing: the stricter "unverified" page limit applies, nothing is blocked.
 */
( function () {
	'use strict';

	var config = window.pncpHuman;
	if ( ! config || ! window.fetch || ! window.crypto || ! window.crypto.subtle || ! window.TextEncoder ) {
		return;
	}
	if ( document.cookie.indexOf( config.cookie + '=' ) !== -1 ) {
		return; // Already verified.
	}

	var started = false;
	var moves = 0;
	var events = [ 'pointerdown', 'keydown', 'touchstart', 'scroll', 'mousemove' ];

	function hex( buffer ) {
		var bytes = new Uint8Array( buffer );
		var out = '';
		for ( var i = 0; i < bytes.length; i++ ) {
			out += ( bytes[ i ] < 16 ? '0' : '' ) + bytes[ i ].toString( 16 );
		}
		return out;
	}

	/**
	 * Finds n so that sha256( challenge + n ) starts with `difficulty` zero hex digits. On average that takes
	 * 16^difficulty attempts, but the number varies a lot from one challenge to the next: the search gives up
	 * only after 8 × 16^difficulty attempts (fewer than 1 in 2,900 visitors get that far) or when the challenge
	 * is about to expire on the server (maxMs). It runs in batches of 64 and hands control back to the browser
	 * at least every 50 ms, so scrolling and typing stay smooth.
	 */
	function solve( challenge, difficulty, maxMs ) {
		var prefix = new Array( difficulty + 1 ).join( '0' );
		var limit = 8 * Math.pow( 16, difficulty );
		var encoder = new TextEncoder();
		var begun = Date.now();
		var slice = begun;
		var n = 0;
		function pause() {
			return new Promise( function ( resolve ) {
				setTimeout( resolve, 0 );
			} );
		}
		function next() {
			var batch = [];
			for ( var i = 0; i < 64; i++, n++ ) {
				batch.push( n );
			}
			return Promise.all(
				batch.map( function ( candidate ) {
					return window.crypto.subtle.digest( 'SHA-256', encoder.encode( challenge + candidate ) ).then( function ( digest ) {
						return hex( digest ).indexOf( prefix ) === 0 ? candidate : -1;
					} );
				} )
			).then( function ( results ) {
				for ( var j = 0; j < results.length; j++ ) {
					if ( results[ j ] !== -1 ) {
						return results[ j ];
					}
				}
				var now = Date.now();
				if ( n >= limit || now - begun > maxMs ) {
					return -1;
				}
				if ( now - slice >= 50 ) {
					slice = now;
					return pause().then( next );
				}
				return next();
			} );
		}
		return next();
	}

	function run() {
		if ( started ) {
			return;
		}
		started = true;
		events.forEach( function ( name ) {
			window.removeEventListener( name, onEvent, true );
		} );
		window
			.fetch( config.url + '?action=pncp_hv', { credentials: 'same-origin', cache: 'no-store' } )
			.then( function ( response ) {
				return response.json();
			} )
			.then( function ( json ) {
				if ( ! json || ! json.success || ! json.data || ! json.data.c ) {
					return;
				}
				var challenge = json.data.c;
				// The server's difficulty (1–8) and how long the challenge stays valid there, less a margin for
				// sending the answer.
				var difficulty = Math.min( 8, Math.max( 1, parseInt( json.data.d, 10 ) || 3 ) );
				var ttl = parseInt( json.data.t, 10 ) || 300;
				return solve( challenge, difficulty, Math.max( 10, ttl - 15 ) * 1000 ).then( function ( answer ) {
					if ( answer < 0 ) {
						return;
					}
					var body = new URLSearchParams();
					body.append( 'action', 'pncp_hv' );
					body.append( 'c', challenge );
					body.append( 'n', String( answer ) );
					return window.fetch( config.url, { method: 'POST', credentials: 'same-origin', body: body } );
				} );
			} )
			.catch( function () {} );
	}

	function onEvent( event ) {
		// A few mouse movements count as one interaction; anything else counts at once.
		if ( event.type === 'mousemove' && ++moves < 3 ) {
			return;
		}
		run();
	}

	events.forEach( function ( name ) {
		window.addEventListener( name, onEvent, { capture: true, passive: true } );
	} );
}() );
