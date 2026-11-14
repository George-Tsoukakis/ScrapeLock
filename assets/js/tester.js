/**
 * ScrapeLock – 3.5: "Check a request" on the Log tab. Sends the form (or a preset) to the side-effect-free
 * check (admin-ajax, action pncp_check_request) and shows the verdict, the reason and why. Every value from the
 * answer is inserted as text, never as HTML.
 */
( function () {
	'use strict';

	var cfg = window.pncpTester;
	var form = document.getElementById( 'pncp-tester-form' );
	if ( ! cfg || ! form ) {
		return;
	}

	var i18n = cfg.i18n || {};
	var presets = cfg.presets || {};
	var result = document.getElementById( 'pncp-tester-result' );
	var fields = {
		ip: document.getElementById( 'pncp-tester-ip' ),
		ua: document.getElementById( 'pncp-tester-ua' ),
		address: document.getElementById( 'pncp-tester-address' ),
		browser: document.getElementById( 'pncp-tester-browser' ),
		referer: document.getElementById( 'pncp-tester-referer' )
	};
	var submit = document.getElementById( 'pncp-tester-submit' );
	var busy = false;
	// 3.5: a User-Agent that names a search engine is verified with a DNS lookup, which can take a few seconds.
	var engine = /googlebot|bingbot|applebot|yandex|google-inspectiontool|storebot-google|adsbot-google|msnbot|adidxbot|bingpreview|mediapartners-google|googleother/i;

	function text( key, fallback ) {
		return 'string' === typeof i18n[ key ] && i18n[ key ] ? i18n[ key ] : fallback;
	}

	function el( tag, className, content ) {
		var node = document.createElement( tag );
		if ( className ) {
			node.className = className;
		}
		if ( undefined !== content && null !== content ) {
			node.textContent = String( content );
		}
		return node;
	}

	function value( field ) {
		return field ? String( field.value ) : '';
	}

	function setBusy( on ) {
		busy = on;
		if ( on ) {
			form.setAttribute( 'aria-busy', 'true' );
		} else {
			form.removeAttribute( 'aria-busy' );
		}
		if ( submit ) {
			submit.disabled = on;
		}
		Array.prototype.forEach.call( document.querySelectorAll( '.pncp-tester-preset' ), function ( button ) {
			button.disabled = on;
		} );
	}

	function clearInvalid() {
		Object.keys( fields ).forEach( function ( key ) {
			if ( fields[ key ] ) {
				fields[ key ].removeAttribute( 'aria-invalid' );
			}
		} );
	}

	function show( nodes ) {
		while ( result.firstChild ) {
			result.removeChild( result.firstChild );
		}
		nodes.forEach( function ( node ) {
			result.appendChild( node );
		} );
	}

	function failed( message, field ) {
		var p = el( 'p', 'pncp-tester__error', message || text( 'failed', 'The check could not run. Reload the page and try again.' ) );
		show( [ p ] );
		var input = field ? document.getElementById( 'pncp-tester-' + field ) : null;
		if ( input ) {
			input.setAttribute( 'aria-invalid', 'true' );
			// A field inside the folded "More headers" is opened first, so it can take the focus.
			for ( var node = input.parentElement; node && node !== form; node = node.parentElement ) {
				if ( 'DETAILS' === node.tagName && ! node.open ) {
					node.open = true;
				}
			}
			input.focus();
		} else {
			result.focus();
		}
	}

	// Only an absolute http(s) address from the server becomes a link (it is an admin URL).
	function safeUrl( url ) {
		return 'string' === typeof url && /^https?:\/\//i.test( url ) ? url : '';
	}

	function row( table, label, content ) {
		var tr = el( 'tr' );
		tr.appendChild( el( 'th', '', label ) ).setAttribute( 'scope', 'row' );
		var td = el( 'td' );
		if ( content && content.nodeType ) {
			td.appendChild( content );
		} else {
			td.textContent = String( content );
		}
		tr.appendChild( td );
		table.appendChild( tr );
	}

	function render( data ) {
		var nodes = [];
		var verdict = /^(allowed|blocked|limited|monitor)$/.test( data.verdict ) ? data.verdict : 'allowed';
		var request = data.request && 'object' === typeof data.request ? data.request : {};

		var head = el( 'p', 'pncp-tester__headline' );
		head.appendChild( el( 'span', 'pncp-tester-verdict pncp-tester-verdict--' + verdict, data.badge || '' ) );
		head.appendChild( document.createTextNode( ' ' ) );
		head.appendChild( el( 'strong', '', data.headline || '' ) );
		nodes.push( head );

		var why = el( 'p', 'pncp-tester__why', data.why || '' );
		var url = data.link ? safeUrl( data.link.url ) : '';
		if ( url ) {
			why.appendChild( document.createTextNode( ' ' ) );
			var a = el( 'a', '', data.link.label || url );
			a.setAttribute( 'href', url );
			why.appendChild( a );
		}
		nodes.push( why );

		var notes = Array.isArray( data.notes ) ? data.notes.slice() : [];
		// The server adds the "your own request" note; the shorter local text only when it did not.
		var selfNote = text( 'selfNote', '' );
		if ( 'self' === request.mode && selfNote ) {
			var stem = selfNote.replace( /\.\s*$/, '' );
			var has = notes.some( function ( note ) {
				return 0 === String( note ).indexOf( stem );
			} );
			if ( ! has ) {
				notes.unshift( selfNote );
			}
		}
		if ( notes.length ) {
			var ul = el( 'ul', 'pncp-tester__notes' );
			notes.forEach( function ( note ) {
				ul.appendChild( el( 'li', '', note ) );
			} );
			nodes.push( ul );
		}

		var table = el( 'table', 'widefat striped pncp-tester__request' );
		var body = el( 'tbody' );
		table.appendChild( body );
		row( body, text( 'checkedAs', 'Checked as' ), data.checked_as_label || '' );
		var ip = request.ip || '';
		if ( 'self' === request.mode && i18n.selfIp ) {
			ip += ' (' + i18n.selfIp + ')';
		}
		row( body, text( 'ip', 'IP' ), ip );
		row( body, text( 'ua', 'User-Agent' ), request.ua ? request.ua : '-' );
		row( body, text( 'address', 'Address' ), request.address || '' );
		var headers = request.headers && 'object' === typeof request.headers ? request.headers : {};
		var names = Object.keys( headers );
		if ( names.length ) {
			var list = el( 'div', 'pncp-tester__headers' );
			names.forEach( function ( name ) {
				list.appendChild( el( 'code', '', name + ': ' + headers[ name ] ) );
			} );
			row( body, text( 'headers', 'Headers' ), list );
		} else {
			row( body, text( 'headers', 'Headers' ), text( 'none', 'none' ) );
		}
		nodes.push( table );

		show( nodes );
		result.focus();
	}

	function check( mode ) {
		if ( busy ) {
			return;
		}
		clearInvalid();
		var body = new URLSearchParams();
		body.append( 'action', cfg.action || 'pncp_check_request' );
		body.append( 'nonce', cfg.nonce || '' );
		body.append( 'mode', 'self' === mode ? 'self' : 'custom' );
		body.append( 'address', value( fields.address ) );
		var dns = false;
		if ( 'self' !== mode ) {
			var ua = value( fields.ua );
			body.append( 'ip', value( fields.ip ).trim() );
			body.append( 'ua', ua );
			if ( fields.browser && fields.browser.checked ) {
				body.append( 'browser', '1' );
			}
			body.append( 'referer', value( fields.referer ) );
			dns = engine.test( ua );
		}
		setBusy( true );
		show( [ el( 'p', 'pncp-tester__checking', dns ? text( 'checkingDns', text( 'checking', 'Checking…' ) ) : text( 'checking', 'Checking…' ) ) ] );
		fetch( cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( r ) {
				return r.json();
			} )
			.then( function ( json ) {
				setBusy( false );
				if ( json && json.success && json.data && 'object' === typeof json.data ) {
					render( json.data );
					return;
				}
				var data = json && json.data && 'object' === typeof json.data ? json.data : {};
				// Without a message (e.g. admin-ajax's bare "0" or "-1") only the generic text is shown.
				if ( 'string' === typeof data.message && data.message ) {
					failed( data.message, 'string' === typeof data.field && /^(ip|ua|address|referer)$/.test( data.field ) ? data.field : '' );
				} else {
					failed( '', '' );
				}
			} )
			.catch( function () {
				setBusy( false );
				failed( '', '' );
			} );
	}

	form.addEventListener( 'submit', function ( e ) {
		e.preventDefault();
		check( 'custom' );
	} );

	// Presets: in the "Try:" row and the "Simulate …" links under the curl lines.
	document.addEventListener( 'click', function ( e ) {
		var button = e.target.closest ? e.target.closest( '.pncp-tester-preset' ) : null;
		if ( ! button || busy ) {
			return;
		}
		var preset = presets[ button.getAttribute( 'data-preset' ) ];
		if ( ! preset ) {
			return;
		}
		e.preventDefault();
		if ( 'self' === preset.mode ) {
			check( 'self' );
			return;
		}
		if ( fields.ua ) {
			fields.ua.value = preset.ua || '';
		}
		if ( fields.browser ) {
			fields.browser.checked = !! preset.browser;
		}
		if ( fields.ip && ! fields.ip.value.trim() ) {
			fields.ip.value = cfg.sampleIp || '';
		}
		if ( fields.referer ) {
			fields.referer.value = '';
		}
		check( 'custom' );
	} );
} )();
