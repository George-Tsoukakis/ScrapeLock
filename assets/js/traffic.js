/*
 * ScrapeLock – Traffic tab: the "From" and "To" dates show only with "Custom dates" (without the script they are
 * always there, and the server ignores them for the other periods).
 */
( function () {
	'use strict';
	var period = document.querySelector( '[data-pncp-tr-period]' );
	var dates = document.querySelector( '[data-pncp-tr-dates]' );
	if ( ! period || ! dates ) {
		return;
	}
	function sync() {
		dates.hidden = 'custom' !== period.value;
	}
	period.addEventListener( 'change', function () {
		sync();
		if ( 'custom' === period.value ) {
			var from = dates.querySelector( 'input' );
			if ( from ) {
				from.focus();
			}
		}
	} );
	sync();
}() );
