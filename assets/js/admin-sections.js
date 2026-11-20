/**
 * ScrapeLock – settings page (3.10): the folded parts (<details>) that were open stay open after a Save, and
 * the page scrolls back to the button that was clicked. Every form of the page posts the open parts and the
 * clicked button (PNCP_Admin_Sections carries them on the redirect back); the browser also keeps them for
 * two minutes, per user, for a form that returns to an address of its own.
 */
( function () {
	'use strict';

	var cfg = window.pncpSections;
	var wrap = document.querySelector( '.pncp-admin' );
	if ( ! cfg || ! wrap ) {
		return;
	}
	var SAFE = /^[A-Za-z0-9_.\-]{1,100}$/;
	var MAX_AGE = 2 * 60 * 1000;
	var tabMatch = /(?:^|\s)pncp-admin--([a-z0-9_\-]+)/.exec( wrap.className );
	var tab = tabMatch ? tabMatch[ 1 ] : '';
	var lastClicked = null;

	function unique( id ) {
		if ( ! id || ! SAFE.test( id ) ) {
			return false;
		}
		try {
			return 1 === document.querySelectorAll( '#' + ( window.CSS && CSS.escape ? CSS.escape( id ) : id ) ).length;
		} catch ( err ) {
			return false;
		}
	}

	// A key for every folded part: its id, else the id of the first element inside it ("in.<id>"), else the id
	// of the nearest element around it ("<id>.d"); a repeated key gets ".2", ".3"… in page order. 3.11: the
	// "More" folds of the help texts (details.pncp-more) are not carried: dozens of them would crowd out the parts.
	function parts() {
		var seen = {};
		var out = [];
		Array.prototype.forEach.call( wrap.querySelectorAll( 'details:not(.pncp-more)' ), function ( el ) {
			var base = el.id;
			if ( ! base ) {
				var inner = el.querySelector( '[id]' );
				if ( inner ) {
					base = 'in.' + inner.id;
				} else {
					var around = el.parentElement ? el.parentElement.closest( '[id]' ) : null;
					base = ( around ? around.id : 'page' ) + '.d';
				}
			}
			seen[ base ] = ( seen[ base ] || 0 ) + 1;
			var key = seen[ base ] > 1 ? base + '.' + seen[ base ] : base;
			if ( SAFE.test( key ) ) {
				out.push( { el: el, key: key } );
			}
		} );
		return out;
	}

	function openKeys() {
		return parts().filter( function ( p ) {
			return p.el.open;
		} ).map( function ( p ) {
			return p.key;
		} );
	}

	// Where to come back to: the clicked button by its id; else "<id>.f<n>.b<m>", the m-th button of the n-th
	// form inside the nearest element with an id ("page" for the whole page), which stays the same when other
	// parts of the page change.
	function buttonsOf( form ) {
		return form.querySelectorAll( 'button, input[type="submit"], input[type="image"]' );
	}

	function focusKey( form, button ) {
		if ( button && unique( button.id ) ) {
			return button.id;
		}
		var around = null;
		for ( var node = form.parentElement; node && node !== wrap; node = node.parentElement ) {
			if ( unique( node.id ) ) {
				around = node;
				break;
			}
		}
		var scope = around || wrap;
		var n = Array.prototype.indexOf.call( scope.querySelectorAll( 'form' ), form );
		var m = button ? Array.prototype.indexOf.call( buttonsOf( form ), button ) : -1;
		return ( around ? around.id : 'page' ) + '.f' + n + '.b' + Math.max( 0, m );
	}

	function setField( form, name, value ) {
		var input = null;
		Array.prototype.forEach.call( form.querySelectorAll( 'input[type="hidden"]' ), function ( el ) {
			if ( el.name === name ) {
				input = el;
			}
		} );
		if ( ! input ) {
			input = document.createElement( 'input' );
			input.type = 'hidden';
			input.name = name;
			form.appendChild( input );
		}
		input.value = value;
	}

	function load() {
		try {
			var raw = window.localStorage.getItem( cfg.store );
			return raw ? JSON.parse( raw ) : null;
		} catch ( err ) {
			return null;
		}
	}

	function save( state ) {
		try {
			window.localStorage.setItem( cfg.store, JSON.stringify( state ) );
		} catch ( err ) {
			// Private window or storage blocked: the query arguments still carry the state.
		}
	}

	function forget() {
		try {
			window.localStorage.removeItem( cfg.store );
		} catch ( err ) {
			// Nothing to do.
		}
	}

	document.addEventListener( 'click', function ( e ) {
		var button = e.target.closest ? e.target.closest( 'button, input[type="submit"], input[type="image"]' ) : null;
		if ( button && button.form ) {
			lastClicked = button;
		}
	}, true );

	// Capture phase: runs before the other submit handlers, and only for a submit that really happens (a
	// cancelled confirmation never fires "submit").
	document.addEventListener( 'submit', function ( e ) {
		var form = e.target;
		if ( ! form || 'FORM' !== form.tagName || ! wrap.contains( form ) || 'post' !== ( form.getAttribute( 'method' ) || '' ).toLowerCase() ) {
			return;
		}
		var button = e.submitter || ( lastClicked && lastClicked.form === form ? lastClicked : null );
		var open = openKeys();
		var focus = focusKey( form, button );
		setField( form, cfg.field, open.join( ',' ) );
		setField( form, cfg.focusArg, SAFE.test( focus ) ? focus : '' );
		save( { tab: tab, open: open, focus: focus, t: Date.now() } );
	}, true );

	function find( key, list ) {
		var el = document.getElementById( key );
		if ( el ) {
			return el;
		}
		var m = /^(.+)\.f(\d+)\.b(\d+)$/.exec( key );
		if ( m ) {
			var scope = 'page' === m[ 1 ] ? wrap : document.getElementById( m[ 1 ] );
			var form = scope ? scope.querySelectorAll( 'form' )[ parseInt( m[ 2 ], 10 ) ] : null;
			if ( form ) {
				return buttonsOf( form )[ parseInt( m[ 3 ], 10 ) ] || form;
			}
			return scope && scope !== wrap ? scope : null;
		}
		for ( var i = 0; i < list.length; i++ ) {
			if ( list[ i ].key === key ) {
				return list[ i ].el;
			}
		}
		return null;
	}

	function reveal( el ) {
		for ( var node = el; node; node = node.parentElement ) {
			if ( 'DETAILS' === node.tagName && ! node.open && node !== el ) {
				node.open = true;
			}
		}
	}

	// Back from a Save: the state from the redirect, else the one this browser kept (same tab, recent).
	var state = null;
	// wp_localize_script() passes numbers as strings.
	if ( '1' === String( cfg.returned ) ) {
		state = { open: cfg.open || [], focus: cfg.focus || '' };
	} else {
		var kept = load();
		if ( kept && kept.tab === tab && 'number' === typeof kept.t && Date.now() - kept.t >= 0 && Date.now() - kept.t < MAX_AGE ) {
			state = { open: Array.isArray( kept.open ) ? kept.open : [], focus: 'string' === typeof kept.focus ? kept.focus : '' };
		}
	}
	forget();
	if ( ! state ) {
		return;
	}
	var list = parts();
	state.open.forEach( function ( key ) {
		var el = SAFE.test( key ) ? find( key, list ) : null;
		if ( el && 'DETAILS' === el.tagName ) {
			reveal( el );
			el.open = true;
		}
	} );
	// The clicked button (or its part) first; else the address's #anchor (e.g. #pncp-bunny after a Bunny
	// action, #pncp-hardening after a hardening card), which admin.js already opened.
	var target = state.focus && SAFE.test( state.focus ) ? find( state.focus, list ) : null;
	if ( ! target ) {
		var hash = window.location.hash ? window.location.hash.slice( 1 ) : '';
		try {
			hash = decodeURIComponent( hash );
		} catch ( err ) {
			hash = '';
		}
		target = hash ? document.getElementById( hash ) : null;
	}
	if ( ! target ) {
		return;
	}
	reveal( target );
	var moved = false;
	var stop = function () {
		moved = true;
	};
	var go = function () {
		if ( ! moved && target.scrollIntoView ) {
			target.scrollIntoView( { block: 'center' } );
		}
	};
	go();
	// The browser's own jump to the #anchor and the notices WordPress moves under the heading come later:
	// once more after "load", unless the user has scrolled in the meantime.
	[ 'wheel', 'touchstart', 'keydown', 'mousedown' ].forEach( function ( type ) {
		window.addEventListener( type, stop, { passive: true, capture: true } );
	} );
	window.addEventListener( 'load', function () {
		setTimeout( go, 0 );
	} );
}() );
