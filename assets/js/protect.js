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

	/** The message area. It exists from page load: screen readers announce a live region only after it exists. */
	function ensureToast() {
		if ( ! toast && document.body ) {
			toast = document.createElement( 'div' );
			toast.className = 'pncp-toast';
			toast.setAttribute( 'role', 'status' );
			toast.setAttribute( 'aria-live', 'polite' );
			document.body.appendChild( toast );
		}
		return toast;
	}
	if ( cfg.showMessage && cfg.message ) {
		if ( document.body ) {
			ensureToast();
		} else {
			document.addEventListener( 'DOMContentLoaded', ensureToast );
		}
	}

	function showMessage() {
		if ( ! cfg.showMessage || ! cfg.message || ! ensureToast() ) {
			return;
		}
		toast.textContent = cfg.message;
		toast.classList.add( 'pncp-toast--visible' );
		clearTimeout( toastTimer );
		toastTimer = setTimeout( function () {
			toast.classList.remove( 'pncp-toast--visible' );
			setTimeout( function () {
				if ( ! toast.classList.contains( 'pncp-toast--visible' ) ) {
					toast.textContent = '';
				}
			}, 250 );
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

	/* ---------- Blur on screenshot (optional) ---------- */
	// Honest note: a web page cannot stop an operating-system screenshot. Print Screen on Windows is often taken by
	// the OS before the browser sees the key (and some systems never pass it on); macOS Cmd+Shift+3/4/5 and Windows
	// Win+Shift+S are system shortcuts the page may never receive; phones, screen recorders, a second device or a
	// camera are invisible to JavaScript. What this does: it blurs the whole page as early as JavaScript can (on
	// the very first key of a known shortcut, before the OS acts where the browser gets that key first, and as soon
	// as a snipping tool or another app takes the focus), so many casual captures come out unreadable, and the
	// reader's mark (mark.js) stays on top of the blur so a capture still shows who took it and when.
	//
	// Registered before the shortcut and DevTools listeners below: those stop Ctrl/Cmd+S with
	// stopImmediatePropagation, which would otherwise hide Ctrl+Shift+S / Win+Shift+S from this listener.
	if ( cfg.blur ) {
		var root = document.documentElement;
		var timeouts = cfg.blurTimeouts || {};
		// A known shortcut: blurred this long, or until the visitor clicks or types something else.
		var SHOT_MS = Math.max( 500, Number( timeouts.shot ) || 5000 );
		// Another window has the focus (snipping tool, screenshot app): blurred until the focus comes back, at most this long.
		var AWAY_MS = Math.max( 500, Number( timeouts.away ) || 10000 );
		var shield = null;

		/** A full-viewport layer whose backdrop-filter blurs whatever is under it. Made once, shown by a class: no DOM work at the critical moment. */
		var ensureShield = function () {
			if ( ! shield && document.body ) {
				shield = document.createElement( 'div' );
				shield.className = 'pncp-shield';
				shield.setAttribute( 'aria-hidden', 'true' );
				document.body.appendChild( shield );
			}
		};
		if ( document.body ) {
			ensureShield();
		} else {
			document.addEventListener( 'DOMContentLoaded', ensureShield );
		}

		var announce = function ( on ) {
			try {
				document.dispatchEvent( new CustomEvent( 'pncp:capture', { detail: { blurred: on } } ) );
			} catch ( err ) {}
		};
		var blurred = function () {
			return root.classList.contains( 'pncp-blurred' );
		};
		var blurOff = function () {
			clearTimeout( blurTimer );
			if ( blurred() ) {
				root.classList.remove( 'pncp-blurred' );
				announce( false );
			}
		};
		/** Blurs at once (a class on <html>: the CSS does the rest in the same frame), and always clears itself after ms. */
		var blurOn = function ( ms ) {
			ensureShield();
			if ( ! blurred() ) {
				root.classList.add( 'pncp-blurred' );
				announce( true );
				// Read a layout property so the style is computed now, not at the next frame.
				void root.offsetWidth;
			}
			clearTimeout( blurTimer );
			blurTimer = setTimeout( blurOff, ms || SHOT_MS );
		};
		var isPrintScreen = function ( e ) {
			return e.key === 'PrintScreen' || e.code === 'PrintScreen' || e.key === 'Snapshot' || e.keyCode === 44;
		};
		var isShot = function ( e ) {
			var key = letterOf( e );
			return isPrintScreen( e ) ||
				// Windows Win+Shift+S, Linux Super+Shift+S, Firefox / Edge Ctrl+Shift+S (screenshot / web capture).
				( ( e.metaKey || e.ctrlKey ) && e.shiftKey && key === 's' ) ||
				// macOS Cmd+Shift+3/4/5/6 (also with Ctrl, to the clipboard).
				( e.metaKey && e.shiftKey && [ '3', '4', '5', '6' ].indexOf( key ) !== -1 );
		};
		var isModifier = function ( e ) {
			return [ 'Meta', 'OS', 'Super', 'Hyper', 'Shift', 'Control', 'Alt', 'AltGraph' ].indexOf( e.key ) !== -1;
		};

		window.addEventListener( 'keydown', function ( e ) {
			if ( isShot( e ) ) {
				blurOn( SHOT_MS );
				return;
			}
			if ( isModifier( e ) ) {
				// Win/Cmd + Shift held: the start of Win+Shift+S or Cmd+Shift+3/4/5, whose last key the OS usually
				// keeps for itself. Blur now, while the page still gets the keys. Not in form fields, where
				// Cmd+Shift+arrow / Cmd+Shift+Z are everyday editing keys.
				if ( e.metaKey && e.shiftKey && ! isField( targetOf( e ) ) ) {
					blurOn( SHOT_MS );
				}
				return;
			}
			// Any other key after a pre-blur: it was an ordinary shortcut (Cmd+Shift+T…), not a screenshot.
			if ( blurred() && document.hasFocus() ) {
				blurOff();
			}
		}, CAPTURE );
		// On Windows, Print Screen often arrives only as keyup (the OS took the keydown).
		window.addEventListener( 'keyup', function ( e ) {
			if ( isPrintScreen( e ) ) {
				blurOn( SHOT_MS );
			}
		}, CAPTURE );
		// A click or tap on the page while it has the focus: the visitor is back, never leave the page blurred.
		window.addEventListener( 'pointerdown', function () {
			if ( blurred() && document.hasFocus() ) {
				blurOff();
			}
		}, CAPTURE );

		/** Focus inside the page itself (an iframe such as a video or map, a select list, a file picker): not a screenshot tool. */
		var focusStaysInPage = function () {
			var active = document.activeElement;
			var tag = active ? String( active.tagName ).toUpperCase() : '';
			return tag === 'IFRAME' || tag === 'FRAME' || tag === 'OBJECT' || tag === 'EMBED' || tag === 'SELECT' || ( tag === 'INPUT' && active.type === 'file' );
		};
		// The snipping tool / a screenshot app takes the focus: blur at once (the capture may be taken right away),
		// clear as soon as the visitor returns, and at the latest after AWAY_MS.
		window.addEventListener( 'blur', function () {
			if ( focusStaysInPage() ) {
				return;
			}
			blurOn( AWAY_MS );
			// Some browsers move document.activeElement to the iframe only after the blur event: check again.
			setTimeout( function () {
				if ( focusStaysInPage() ) {
					blurOff();
				}
			}, 0 );
		} );
		window.addEventListener( 'focus', blurOff );
		document.addEventListener( 'visibilitychange', function () {
			if ( document.visibilityState === 'hidden' ) {
				blurOn( AWAY_MS );
			} else if ( document.hasFocus() ) {
				blurOff();
			}
		} );
		// Back from the back/forward cache: never restore a page that was left blurred.
		window.addEventListener( 'pageshow', function () {
			if ( document.hasFocus() ) {
				blurOff();
			}
		} );
	}

	/* ---------- Right-click ---------- */
	// Blocked everywhere (text, images, links, buttons, SVG icons, web components) except form fields,
	// contenteditable and .pncp-allow. Capture phase on window, added before any other script: preventDefault
	// cannot be undone by a later listener, and stopImmediatePropagation keeps "re-enable right-click" scripts
	// from ever seeing the event. Also covers the keyboard menu key / Shift+F10, which fire the same event.
	// The old behaviour (links keep their menu) comes back with the PHP filter pncp_protect_allow_link_menu.
	// Left click, middle click (auxclick) and keyboard navigation are not touched.
	// Limitation: a right-click inside an iframe (video, map) belongs to that frame's document and is not seen here.
	if ( cfg.contextMenu ) {
		if ( ! cfg.allowLinkMenu ) {
			// iOS shows the long-press link menu without a contextmenu event: the CSS turns that callout off.
			document.documentElement.classList.add( 'pncp-no-menu' );
		}
		window.addEventListener( 'contextmenu', function ( e ) {
			var target = elementOf( targetOf( e ) );
			if ( isField( target ) || isAllowed( target ) ) {
				return;
			}
			// Even with the link menu allowed, an image (or other media) inside a link keeps the block:
			// otherwise "Save image as" would be open on every gallery and product image that links to its file.
			if ( cfg.allowLinkMenu && target && target.closest && target.closest( 'a[href]' ) && ! target.closest( 'img, picture, video, audio, canvas' ) ) {
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
			var draggingText = !! ( sel && ! sel.isCollapsed && sel.containsNode && sel.containsNode( el, true ) );
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
		// c/x: copy/cut, s: save, u: view source. Select all (a) is left alone: selection is already limited
		// by the CSS, and keyboard and assistive-technology users rely on it (e.g. in a search field).
		// p (print) is blocked only if printing is disabled.
		var keys = [ 'c', 'x', 's', 'u' ];
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

	/* ---------- Print: the texts go in as data attributes, the CSS shows them ---------- */
	function setPrintData() {
		// Also set here, for themes that do not call body_class(): with printing off nothing of the page is printed.
		if ( cfg.printMode === 'block' ) {
			document.body.classList.add( 'pncp-print-block' );
		}
		document.body.setAttribute( 'data-pncp-print-block', cfg.i18n.printBlock );
		document.body.setAttribute( 'data-pncp-source', cfg.i18n.source + ': ' + cfg.sourceUrl );
	}
	if ( document.body ) {
		setPrintData();
	} else {
		document.addEventListener( 'DOMContentLoaded', setPrintData );
	}
} )();
