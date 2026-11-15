/**
 * ScrapeLock – the reader's mark (3.6).
 *
 * A faint, repeated line over the whole page with who is reading it and when (the account's user name, or the
 * IP for a visitor who is not signed in, and the date and time). It cannot stop a screenshot, a screen
 * recording or a photo of the screen: nothing on a web page can. It makes every copy show where it came from.
 *
 * It never takes a click, a tap or a selection (pointer-events: none), and is shown again when it is removed or
 * hidden (developer tools, an extension, a user style).
 */
( function () {
	'use strict';

	var cfg = window.pncpMark;
	if ( ! cfg || ! document.documentElement ) {
		return;
	}

	var host = null;
	var text = '';

	function esc( value ) {
		return String( value ).replace( /[&<>"']/g, function ( c ) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ c ];
		} );
	}

	/** The tile: the line twice, rotated, grey so it shows on light and dark pages alike. As wide as the line needs. */
	function tile( line ) {
		var w = Math.max( 320, Math.round( String( line ).length * 8.5 ) + 120 );
		var svg =
			'<svg xmlns="http://www.w3.org/2000/svg" width="' + w + '" height="200">' +
			'<g transform="rotate(-20 ' + w / 2 + ' 100)" font-family="Arial,Helvetica,sans-serif" font-size="15" fill="#808080">' +
			'<text x="10" y="70">' + esc( line ) + '</text>' +
			'<text x="' + Math.round( w * 0.35 ) + '" y="170">' + esc( line ) + '</text>' +
			'</g></svg>';
		return 'url("data:image/svg+xml,' + encodeURIComponent( svg ) + '")';
	}

	/** A custom element of its own name each time, with a closed shadow root: page styles cannot reach inside. */
	function build() {
		var name = 'x-' + Math.random().toString( 36 ).slice( 2, 10 );
		var el = document.createElement( name );
		el.setAttribute( 'aria-hidden', 'true' );
		// Inline and !important: a style sheet, even with !important of its own, cannot hide it.
		var css = { position: 'fixed', inset: '0', 'z-index': '2147483647', 'pointer-events': 'none', display: 'block', visibility: 'visible', opacity: '1', margin: '0', padding: '0', border: '0', transform: 'none', filter: 'none', 'clip-path': 'none' };
		for ( var prop in css ) {
			el.style.setProperty( prop, css[ prop ], 'important' );
		}
		var root = el.attachShadow ? el.attachShadow( { mode: 'closed' } ) : el;
		var layer = document.createElement( 'div' );
		layer.style.cssText =
			'position:fixed;inset:0;pointer-events:none;' +
			'opacity:' + Math.max( 0.02, Math.min( 0.6, Number( cfg.opacity ) || 0.1 ) ) + ';' +
			'background-image:' + tile( text ) + ';background-repeat:repeat;' +
			'-webkit-print-color-adjust:exact;print-color-adjust:exact;';
		root.appendChild( layer );
		return el;
	}

	function visible( el ) {
		if ( ! el || ! el.isConnected ) {
			return false;
		}
		var st = window.getComputedStyle( el );
		return st.display !== 'none' && st.visibility !== 'hidden' && Number( st.opacity ) > 0.5 && st.position === 'fixed';
	}

	function ensure() {
		if ( ! text || ! document.body ) {
			return;
		}
		if ( ! visible( host ) ) {
			if ( host && host.parentNode ) {
				host.parentNode.removeChild( host );
			}
			host = build();
			document.body.appendChild( host );
		}
	}

	// At most once per frame, however busy the page is.
	var queued = false;
	function soon() {
		if ( queued ) {
			return;
		}
		queued = true;
		( window.requestAnimationFrame || window.setTimeout )( function () {
			queued = false;
			ensure();
		} );
	}

	function start( line ) {
		text = line;
		ensure();
		if ( window.MutationObserver ) {
			new MutationObserver( soon ).observe( document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: [ 'style', 'class', 'hidden' ] } );
		}
		window.setInterval( ensure, 2000 );
		window.addEventListener( 'beforeprint', ensure );
	}

	function run() {
		if ( cfg.text ) {
			start( cfg.text );
			return;
		}
		// A visitor who is not signed in: the line is asked for, never kept in the page (a cached page is shared).
		if ( cfg.url && window.fetch ) {
			window
				.fetch( cfg.url, { credentials: 'same-origin', cache: 'no-store' } )
				.then( function ( r ) {
					return r.ok ? r.json() : null;
				} )
				.then( function ( data ) {
					if ( data && data.success && data.data && data.data.text ) {
						start( String( data.data.text ) );
					}
				} )
				.catch( function () {} );
		}
	}

	if ( document.body ) {
		run();
	} else {
		document.addEventListener( 'DOMContentLoaded', run );
	}
} )();
