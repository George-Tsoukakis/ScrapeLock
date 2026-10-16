/**
 * ScrapeLock – frontend.
 *
 * Loaded in <head>, before the scripts of the theme and other plugins, and adds its listeners
 * on window in the capture phase: they run first, so no other script (not even "Allow
 * copy"-style extensions that work with listeners on the page) can bypass them with stopPropagation.
 *
 * Always leaves free: form fields, contenteditable, anything with the .pncp-allow class, and keyboard
 * navigation.
 */
( function () {
	'use strict';

	var cfg = window.pncpConfig;
	if ( ! cfg ) {
		return;
	}

	var FIELDS = 'input, textarea, select, option, [contenteditable=""], [contenteditable="true"]';
	var EDITABLE = FIELDS + ', .pncp-allow';
	var CAPTURE = { capture: true };
	var toast = null;
	var toastTimer = null;
	var blurTimer = null;

	/** The actual element of the event, also inside shadow DOM (web components). */
	function targetOf( e ) {
		var path = e.composedPath ? e.composedPath() : null;
		return path && path.length ? path[ 0 ] : e.target;
	}

	function elementOf( node ) {
		if ( ! node ) {
			return null;
		}
		return node.nodeType === 1 ? node : node.parentElement;
	}

	function isAllowed( node ) {
		var el = elementOf( node );
		if ( ! el || ! el.closest ) {
			return false;
		}
		return !! el.closest( EDITABLE ) || el.isContentEditable === true;
	}

	/** Is the current selection allowed? (e.g. entirely inside .pncp-allow) */
	function selectionAllowed( sel ) {
		if ( ! sel || sel.rangeCount === 0 ) {
			return true;
		}
		return isAllowed( sel.anchorNode ) && isAllowed( sel.focusNode );
	}

	/** Form field or contenteditable (not .pncp-allow, which is judged by the selection). */
	function isField( node ) {
		var el = elementOf( node );
		return !! ( el && el.closest && ( el.closest( FIELDS ) || el.isContentEditable === true ) );
	}

	/** Is there a selection, and is it entirely in an allowed area? */
	function hasAllowedSelection() {
		var sel = window.getSelection ? window.getSelection() : null;
		return !! ( sel && sel.rangeCount > 0 && ! sel.isCollapsed && selectionAllowed( sel ) );
	}

	function showMessage() {
		if ( ! cfg.showMessage || ! cfg.message || ! document.body ) {
			return;
		}
		if ( ! toast ) {
			toast = document.createElement( 'div' );
			toast.className = 'pncp-toast';
			toast.setAttribute( 'role', 'status' );
			toast.setAttribute( 'aria-live', 'polite' );
			document.body.appendChild( toast );
		}
		toast.textContent = cfg.message;
		toast.classList.add( 'pncp-toast--visible' );
		clearTimeout( toastTimer );
		toastTimer = setTimeout( function () {
			toast.classList.remove( 'pncp-toast--visible' );
		}, 3000 );
	}

	function escapeHtml( text ) {
		return String( text )
			.replace( /&/g, '&amp;' )
			.replace( /</g, '&lt;' )
			.replace( />/g, '&gt;' )
			.replace( /"/g, '&quot;' );
	}

	/** Stops the event before it reaches any other listener. */
	function stop( e ) {
		e.preventDefault();
		e.stopImmediatePropagation();
	}

	/** Latin letter of the key: e.key where available (AZERTY/Dvorak), otherwise e.code (Greek layout). */
	function letterOf( e ) {
		if ( /^[a-z]$/i.test( e.key || '' ) ) {
			return e.key.toLowerCase();
		}
		var code = e.code || '';
		if ( code.indexOf( 'Key' ) === 0 ) {
			return code.slice( 3 ).toLowerCase();
		}
		if ( code.indexOf( 'Digit' ) === 0 ) {
			return code.slice( 5 );
		}
		return '';
	}

	/* ---------- Right-click ---------- */
	if ( cfg.contextMenu ) {
		window.addEventListener( 'contextmenu', function ( e ) {
			if ( isAllowed( targetOf( e ) ) ) {
				return;
			}
			stop( e );
			showMessage();
		}, CAPTURE );
	}

	/* ---------- Dragging images and selected text ---------- */
	if ( cfg.imageDrag || cfg.textDrag ) {
		window.addEventListener( 'dragstart', function ( e ) {
			var el = elementOf( targetOf( e ) );
			if ( ! el || isAllowed( el ) ) {
				return;
			}
			var tag = String( el.tagName ).toUpperCase();
			var isImage = tag === 'IMG' || tag === 'PICTURE' || tag === 'SVG';
			if ( isImage ) {
				if ( cfg.imageDrag ) {
					stop( e );
				}
				return;
			}
			// Text: only when selected text is dragged. Widgets with draggable (sorting, sliders)
			// and links keep working.
			var sel = window.getSelection ? window.getSelection() : null;
			var draggingText = el.nodeType === 3 || ( sel && ! sel.isCollapsed && sel.containsNode && sel.containsNode( el, true ) );
			if ( cfg.textDrag && draggingText && ! ( el.closest && el.closest( '[draggable="true"]' ) ) ) {
				stop( e );
			}
		}, CAPTURE );
	}

	/* ---------- Text selection ---------- */
	if ( cfg.selection ) {
		window.addEventListener( 'selectstart', function ( e ) {
			if ( ! isAllowed( targetOf( e ) ) ) {
				stop( e );
			}
		}, CAPTURE );
	}

	/* ---------- Shortcuts ---------- */
	if ( cfg.shortcuts ) {
		// a: select all, c/x: copy/cut, s: save, u: view source.
		// p (print) is blocked only if printing is disabled.
		var keys = [ 'a', 'c', 'x', 's', 'u' ];
		if ( cfg.printMode === 'block' ) {
			keys.push( 'p' );
		}
		if ( cfg.copyMode === 'attribution' || cfg.copyMode === 'allow' ) {
			// Copying is allowed (with or without source), so we do not block Ctrl+C.
			keys = keys.filter( function ( k ) {
				return k !== 'c';
			} );
		}

		window.addEventListener( 'keydown', function ( e ) {
			if ( ! ( e.ctrlKey || e.metaKey ) || e.altKey ) {
				return;
			}
			var key = letterOf( e );
			if ( keys.indexOf( key ) === -1 || isAllowed( targetOf( e ) ) ) {
				return;
			}
			// Copying text from .pncp-allow (phone, coupon) with the keyboard.
			if ( ( key === 'c' || key === 'x' ) && hasAllowedSelection() ) {
				return;
			}
			stop( e );
			showMessage();
		}, CAPTURE );
	}

	/* ---------- DevTools shortcuts (cosmetic: we do not detect DevTools and do not break the page) ---------- */
	if ( cfg.devtools ) {
		window.addEventListener( 'keydown', function ( e ) {
			var code = e.code || '';
			var letter = code.indexOf( 'Key' ) === 0 ? code.slice( 3 ) : '';
			var hit =
				e.key === 'F12' || code === 'F12' ||
				// Windows / Linux: Ctrl+Shift+I/J/C/K
				( e.ctrlKey && e.shiftKey && ! e.altKey && letter !== '' && 'IJCK'.indexOf( letter ) !== -1 ) ||
				// macOS: Cmd+Opt+I/J/C/U
				( e.metaKey && e.altKey && letter !== '' && 'IJCU'.indexOf( letter ) !== -1 );
			if ( hit ) {
				stop( e );
				showMessage();
			}
		}, CAPTURE );
	}

	/* ---------- Copy / cut ---------- */
	function onCopy( e ) {
		if ( cfg.copyMode === 'allow' ) {
			return;
		}
		var sel = window.getSelection ? window.getSelection() : null;
		// For .pncp-allow the selection decides, not the target: a selection that starts there
		// and extends into protected text does not pass.
		if ( isField( targetOf( e ) ) || hasAllowedSelection() ) {
			return;
		}
		if ( cfg.copyMode === 'block' ) {
			stop( e );
			showMessage();
			return;
		}

		// attribution: the text is copied together with the source.
		var text = sel ? sel.toString() : '';
		// Short snippets (e.g. a single word) are copied normally, without source.
		if ( ! text || ! e.clipboardData || text.length < ( cfg.minChars || 0 ) ) {
			return;
		}
		var label = cfg.i18n.source + ': ' + ( cfg.sourceTitle ? cfg.sourceTitle + ' – ' : '' ) + cfg.siteName;
		var plain = text + '\n\n' + label + '\n' + cfg.sourceUrl;
		var html = '<div>' + escapeHtml( text ).replace( /\n/g, '<br>' ) + '</div>' +
			'<p>' + escapeHtml( label ) + '<br><a href="' + escapeHtml( cfg.sourceUrl ) + '">' + escapeHtml( cfg.sourceUrl ) + '</a></p>';

		e.clipboardData.setData( 'text/plain', plain );
		e.clipboardData.setData( 'text/html', html );
		stop( e );
	}
	window.addEventListener( 'copy', onCopy, CAPTURE );
	window.addEventListener( 'cut', onCopy, CAPTURE );

	/* ---------- Blur on screenshot (optional) ---------- */
	if ( cfg.blur ) {
		var blurOn = function ( ms ) {
			document.documentElement.classList.add( 'pncp-blurred' );
			clearTimeout( blurTimer );
			if ( ms ) {
				blurTimer = setTimeout( blurOff, ms );
			}
		};
		var blurOff = function () {
			document.documentElement.classList.remove( 'pncp-blurred' );
		};
		window.addEventListener( 'keydown', function ( e ) {
			var key = letterOf( e );
			var shot =
				e.key === 'PrintScreen' || e.code === 'PrintScreen' ||
				// Windows: Win+Shift+S
				( e.metaKey && e.shiftKey && key === 's' ) ||
				// macOS: Cmd+Shift+3/4/5/6
				( e.metaKey && e.shiftKey && [ '3', '4', '5', '6' ].indexOf( key ) !== -1 );
			if ( shot ) {
				blurOn( 4000 );
			}
		}, CAPTURE );
		// On Windows, Print Screen often arrives only as keyup.
		window.addEventListener( 'keyup', function ( e ) {
			if ( e.key === 'PrintScreen' || e.code === 'PrintScreen' ) {
				blurOn( 4000 );
			}
		}, CAPTURE );
		// The snipping tool takes focus: blur while it is away, clear as soon as the visitor returns.
		window.addEventListener( 'blur', function () {
			// A click inside an iframe on the page (e.g. video) also takes focus: no blur there.
			setTimeout( function () {
				var active = document.activeElement;
				if ( ! active || String( active.tagName ).toUpperCase() !== 'IFRAME' ) {
					blurOn( 0 );
				}
			}, 0 );
		} );
		window.addEventListener( 'focus', blurOff );
		document.addEventListener( 'visibilitychange', function () {
			if ( document.visibilityState === 'visible' && document.hasFocus() ) {
				blurOff();
			}
		} );
	}

	/* ---------- Print: the texts go in as data attributes, the CSS shows them ---------- */
	function setPrintData() {
		document.body.setAttribute( 'data-pncp-print-block', cfg.i18n.printBlock );
		document.body.setAttribute( 'data-pncp-source', cfg.i18n.source + ': ' + cfg.sourceUrl );
	}
	if ( document.body ) {
		setPrintData();
	} else {
		document.addEventListener( 'DOMContentLoaded', setPrintData );
	}
} )();
