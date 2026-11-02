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

	function solve( challenge, difficulty ) {
		var prefix = new Array( difficulty + 1 ).join( '0' );
		var encoder = new TextEncoder();
		var n = 0;
		function next() {
			// Small batches, so the page stays responsive.
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
				return n > 1000000 ? -1 : next();
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
				return solve( challenge, parseInt( json.data.d, 10 ) || 3 ).then( function ( answer ) {
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
