/**
 * ScrapeLock – settings page: copy buttons and batch watermark tool.
 */
( function () {
	'use strict';

	var cfg = window.pncpAdmin;
	if ( ! cfg ) {
		return;
	}

	function format( text, a, b ) {
		return String( text ).replace( '%1$s', a ).replace( '%2$s', b );
	}

	/* ---------- Copy ---------- */
	document.addEventListener( 'click', function ( e ) {
		var button = e.target.closest ? e.target.closest( '.pncp-copy' ) : null;
		if ( ! button ) {
			return;
		}
		var target = document.getElementById( button.getAttribute( 'data-target' ) );
		if ( ! target ) {
			return;
		}
		var text = 'value' in target ? target.value : target.textContent;
		var original = button.textContent;
		var done = function () {
			button.textContent = cfg.i18n.copied;
			setTimeout( function () {
				button.textContent = original;
			}, 2000 );
		};
		if ( navigator.clipboard && window.isSecureContext ) {
			navigator.clipboard.writeText( text ).then( done );
		} else if ( target.select ) {
			target.select();
			document.execCommand( 'copy' );
			done();
		}
	} );

	/* ---------- Watermark tool ---------- */
	var buttons = document.querySelectorAll( '.pncp-wm-run' );
	var box = document.querySelector( '.pncp-progress' );
	if ( ! buttons.length || ! box ) {
		return;
	}
	var bar = box.querySelector( 'progress' );
	var status = box.querySelector( '[role="status"]' );

	function setBusy( busy ) {
		Array.prototype.forEach.call( buttons, function ( b ) {
			b.disabled = busy;
		} );
	}

	function run( mode, total ) {
		var errors = 0;
		var step = function ( cursor ) {
			var body = new URLSearchParams();
			body.append( 'action', 'pncp_wm_batch' );
			body.append( 'nonce', cfg.nonce );
			body.append( 'mode', mode );
			body.append( 'cursor', cursor );
			fetch( cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } )
				.then( function ( r ) {
					return r.json();
				} )
				.then( function ( json ) {
					if ( ! json || ! json.success ) {
						throw new Error( 'batch' );
					}
					var d = json.data;
					errors += d.errors;
					var pos = Math.min( d.position, total );
					bar.value = total ? Math.round( pos * 100 / total ) : 100;
					status.textContent = format( cfg.i18n.progress, pos, total );
					if ( d.done ) {
						bar.value = 100;
						status.textContent = format( cfg.i18n.done, total, errors );
						setBusy( false );
						return;
					}
					step( d.cursor );
				} )
				.catch( function () {
					status.textContent = cfg.i18n.error;
					setBusy( false );
				} );
		};
		step( 0 );
	}

	Array.prototype.forEach.call( buttons, function ( button ) {
		button.addEventListener( 'click', function () {
			var mode = button.getAttribute( 'data-mode' );
			// eslint-disable-next-line no-alert
			if ( ! window.confirm( mode === 'apply' ? cfg.i18n.confirmApply : cfg.i18n.confirmRemove ) ) {
				return;
			}
			box.hidden = false;
			bar.value = 0;
			setBusy( true );
			run( mode, parseInt( button.getAttribute( 'data-total' ), 10 ) || 0 );
		} );
	} );
} )();
