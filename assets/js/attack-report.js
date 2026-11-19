/**
 * ScrapeLock – attack report (Attacks tab).
 *
 * Progressive enhancement only: without this script every chart is shown one after the other, the tables are
 * complete and the buttons post as usual.
 * - One chart at a time, with "Per day / Per hour / Hour of the day" buttons (aria-pressed).
 * - A filter box above the long tables.
 * - A confirmation before "Always block".
 *
 * @package ScrapeLock
 */

( function () {
	'use strict';

	var settings = window.pncpAttackReport || {};
	var i18n     = settings.i18n || {};

	function format( text, values ) {
		var i = 0;
		return String( text || '' ).replace(
			/%(\d+\$)?s/g,
			function ( match, pos ) {
				var index = pos ? parseInt( pos, 10 ) - 1 : i++;
				return values[ index ] !== undefined ? values[ index ] : '';
			}
		);
	}

	function initViews( box ) {
		var bar   = box.querySelector( '.pncp-ar__switch' );
		var views = box.querySelectorAll( '[data-pncp-ar-view]' );
		if ( ! bar || views.length < 2 ) {
			return;
		}
		var buttons = bar.querySelectorAll( 'button[data-view]' );
		var key     = 'pncpArView';
		var saved   = '';
		try {
			saved = window.localStorage.getItem( key ) || '';
		} catch ( e ) {
			saved = '';
		}

		function show( id, remember ) {
			var found = false;
			Array.prototype.forEach.call(
				views,
				function ( view ) {
					var on      = view.id === id;
					found       = found || on;
					view.hidden = ! on;
				}
			);
			if ( ! found ) {
				return false;
			}
			Array.prototype.forEach.call(
				buttons,
				function ( button ) {
					button.setAttribute( 'aria-pressed', button.getAttribute( 'data-view' ) === id ? 'true' : 'false' );
					button.setAttribute( 'aria-controls', button.getAttribute( 'data-view' ) );
				}
			);
			if ( remember ) {
				try {
					window.localStorage.setItem( key, id );
				} catch ( e ) {
				}
			}
			return true;
		}

		Array.prototype.forEach.call(
			buttons,
			function ( button ) {
				button.addEventListener(
					'click',
					function () {
						show( button.getAttribute( 'data-view' ), true );
					}
				);
			}
		);
		bar.hidden = false;
		if ( ! saved || ! show( saved, false ) ) {
			show( buttons[ 0 ].getAttribute( 'data-view' ), false );
		}
	}

	function initFilter( input ) {
		var table = document.getElementById( input.getAttribute( 'data-pncp-ar-filter' ) );
		if ( ! table || ! table.tBodies.length ) {
			return;
		}
		var rows                           = table.tBodies[ 0 ].rows;
		var count                          = input.parentNode.parentNode.querySelector( '.pncp-ar__count' );
		input.parentNode.parentNode.hidden = rows.length < 8;

		function apply() {
			var needle = input.value.trim().toLowerCase();
			var shown  = 0;
			Array.prototype.forEach.call(
				rows,
				function ( row ) {
					var on     = ! needle || row.textContent.toLowerCase().indexOf( needle ) !== -1;
					row.hidden = ! on;
					shown     += on ? 1 : 0;
				}
			);
			if ( count ) {
				count.textContent = needle ? format( i18n.shown || '%1$s / %2$s', [ shown, rows.length ] ) : '';
			}
		}

		input.addEventListener( 'input', apply );
	}

	function initConfirm( root ) {
		root.addEventListener(
			'submit',
			function ( event ) {
				var button = event.submitter || event.target.querySelector( '[data-pncp-ar-confirm]' );
				if ( ! button || ! button.hasAttribute( 'data-pncp-ar-confirm' ) ) {
					return;
				}
				if ( ! window.confirm( format( i18n.confirm || 'Block %s?', [ button.getAttribute( 'data-pncp-ar-confirm' ) ] ) ) ) {
					event.preventDefault();
				}
			}
		);
	}

	function init() {
		var root = document.getElementById( 'pncp-ar' );
		if ( ! root ) {
			return;
		}
		Array.prototype.forEach.call( root.querySelectorAll( '[data-pncp-ar-views]' ), initViews );
		Array.prototype.forEach.call( root.querySelectorAll( '[data-pncp-ar-filter]' ), initFilter );
		initConfirm( root );
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );
