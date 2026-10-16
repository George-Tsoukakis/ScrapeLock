/**
 * Content Protect – frontend.
 *
 * Φορτώνεται στο <head>, πριν από τα scripts του θέματος και των άλλων plugins, και βάζει τους listeners
 * στο window σε φάση capture: τρέχουν πρώτοι, οπότε κανένα άλλο script (ούτε επεκτάσεις τύπου «Allow
 * copy» που δουλεύουν με listeners στη σελίδα) δεν μπορεί να τους παρακάμψει με stopPropagation.
 *
 * Αφήνει πάντα ελεύθερα: πεδία φόρμας, contenteditable, ό,τι έχει κλάση .pncp-allow, και την πλοήγηση
 * με πληκτρολόγιο.
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

	/** Το πραγματικό στοιχείο του συμβάντος, και μέσα σε shadow DOM (web components). */
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

	/** Επιτρέπεται η τρέχουσα επιλογή; (π.χ. ολόκληρη μέσα σε .pncp-allow) */
	function selectionAllowed( sel ) {
		if ( ! sel || sel.rangeCount === 0 ) {
			return true;
		}
		return isAllowed( sel.anchorNode ) && isAllowed( sel.focusNode );
	}

	/** Πεδίο φόρμας ή contenteditable (όχι .pncp-allow, που κρίνεται από την επιλογή). */
	function isField( node ) {
		var el = elementOf( node );
		return !! ( el && el.closest && ( el.closest( FIELDS ) || el.isContentEditable === true ) );
	}

	/** Υπάρχει επιλογή και βρίσκεται ολόκληρη σε επιτρεπτό σημείο; */
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

	/** Σταματά το συμβάν πριν φτάσει σε οποιονδήποτε άλλο listener. */
	function stop( e ) {
		e.preventDefault();
		e.stopImmediatePropagation();
	}

	/** Λατινικό γράμμα του πλήκτρου: e.key όπου υπάρχει (AZERTY/Dvorak), αλλιώς e.code (ελληνική διάταξη). */
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

	/* ---------- Δεξί κλικ ---------- */
	if ( cfg.contextMenu ) {
		window.addEventListener( 'contextmenu', function ( e ) {
			if ( isAllowed( targetOf( e ) ) ) {
				return;
			}
			stop( e );
			showMessage();
		}, CAPTURE );
	}

	/* ---------- Σύρσιμο εικόνων και επιλεγμένου κειμένου ---------- */
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
			// Κείμενο: μόνο όταν σέρνεται επιλεγμένο κείμενο. Widgets με draggable (ταξινόμηση, sliders)
			// και σύνδεσμοι συνεχίζουν να δουλεύουν.
			var sel = window.getSelection ? window.getSelection() : null;
			var draggingText = el.nodeType === 3 || ( sel && ! sel.isCollapsed && sel.containsNode && sel.containsNode( el, true ) );
			if ( cfg.textDrag && draggingText && ! ( el.closest && el.closest( '[draggable="true"]' ) ) ) {
				stop( e );
			}
		}, CAPTURE );
	}

	/* ---------- Επιλογή κειμένου ---------- */
	if ( cfg.selection ) {
		window.addEventListener( 'selectstart', function ( e ) {
			if ( ! isAllowed( targetOf( e ) ) ) {
				stop( e );
			}
		}, CAPTURE );
	}

	/* ---------- Συντομεύσεις ---------- */
	if ( cfg.shortcuts ) {
		// a: επιλογή όλων, c/x: αντιγραφή/αποκοπή, s: αποθήκευση, u: πηγαίος κώδικας.
		// Το p (εκτύπωση) μπλοκάρεται μόνο αν έχει απαγορευτεί η εκτύπωση.
		var keys = [ 'a', 'c', 'x', 's', 'u' ];
		if ( cfg.printMode === 'block' ) {
			keys.push( 'p' );
		}
		if ( cfg.copyMode === 'attribution' || cfg.copyMode === 'allow' ) {
			// Η αντιγραφή επιτρέπεται (με ή χωρίς πηγή), οπότε δεν κόβουμε Ctrl+C.
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
			// Αντιγραφή κειμένου από .pncp-allow (τηλέφωνο, κουπόνι) με το πληκτρολόγιο.
			if ( ( key === 'c' || key === 'x' ) && hasAllowedSelection() ) {
				return;
			}
			stop( e );
			showMessage();
		}, CAPTURE );
	}

	/* ---------- Συντομεύσεις DevTools (κοσμητικό: δεν ανιχνεύουμε DevTools και δεν σπάμε τη σελίδα) ---------- */
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

	/* ---------- Αντιγραφή / αποκοπή ---------- */
	function onCopy( e ) {
		if ( cfg.copyMode === 'allow' ) {
			return;
		}
		var sel = window.getSelection ? window.getSelection() : null;
		// Για .pncp-allow κρίνει η επιλογή, όχι το target: μια επιλογή που ξεκινά από εκεί
		// και απλώνεται σε προστατευμένο κείμενο δεν περνά.
		if ( isField( targetOf( e ) ) || hasAllowedSelection() ) {
			return;
		}
		if ( cfg.copyMode === 'block' ) {
			stop( e );
			showMessage();
			return;
		}

		// attribution: αντιγράφεται το κείμενο μαζί με την πηγή.
		var text = sel ? sel.toString() : '';
		// Μικρά αποσπάσματα (π.χ. μια λέξη) αντιγράφονται κανονικά, χωρίς πηγή.
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

	/* ---------- Θόλωμα σε στιγμιότυπο οθόνης (προαιρετικό) ---------- */
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
		// Το Print Screen στα Windows φτάνει συχνά μόνο ως keyup.
		window.addEventListener( 'keyup', function ( e ) {
			if ( e.key === 'PrintScreen' || e.code === 'PrintScreen' ) {
				blurOn( 4000 );
			}
		}, CAPTURE );
		// Το εργαλείο αποκοπής παίρνει το focus: θόλωμα όσο λείπει, καθαρό μόλις επιστρέψει ο επισκέπτης.
		window.addEventListener( 'blur', function () {
			// Κλικ μέσα σε iframe της σελίδας (π.χ. βίντεο) παίρνει κι αυτό το focus: εκεί όχι θόλωμα.
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

	/* ---------- Εκτύπωση: τα κείμενα μπαίνουν ως data attributes, το CSS τα δείχνει ---------- */
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
