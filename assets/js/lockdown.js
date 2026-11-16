/**
 * ScrapeLock – Lockdown page: draws the QR code for the authenticator app, in the browser (the secret is
 * not sent anywhere), and focuses the code field.
 */
( function () {
	'use strict';

	var box = document.querySelector( '[data-pncp-qr]' );
	if ( box && window.qrcode ) {
		var qr = window.qrcode( 0, 'M' );
		qr.addData( box.getAttribute( 'data-pncp-qr' ) );
		qr.make();
		box.innerHTML = qr.createSvgTag( 5, 4 );
	}

	var field = document.querySelector( '.pncp-ld-code' );
	if ( field ) {
		field.focus();
	}

	// Locking reads every code file of the site and can take a while: the button says so, and a second click
	// cannot send the form again (which would answer "not possible right now", the site being locked already).
	var text = ( window.pncpLockdown && window.pncpLockdown.working ) || '';
	document.querySelectorAll( 'form.pncp-ld-form' ).forEach( function ( form ) {
		form.addEventListener( 'submit', function ( event ) {
			if ( form.getAttribute( 'data-pncp-sent' ) ) {
				event.preventDefault();
				return;
			}
			form.setAttribute( 'data-pncp-sent', '1' );
			form.setAttribute( 'aria-busy', 'true' );
			var button = form.querySelector( '[type="submit"]' );
			if ( button ) {
				// Disabled after this tick: a disabled button would not be sent with the form.
				window.setTimeout( function () {
					button.disabled = true;
					if ( text && 'INPUT' === button.tagName ) {
						button.value = text;
					}
				}, 0 );
			}
		} );
	} );

	// Back to this page from the browser history: the forms work again.
	window.addEventListener( 'pageshow', function ( event ) {
		if ( event.persisted ) {
			window.location.reload();
		}
	} );
}() );
