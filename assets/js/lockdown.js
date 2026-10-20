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
}() );
