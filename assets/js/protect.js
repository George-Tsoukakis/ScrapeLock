/**
 * Content Protect – frontend.
 *
 * Χρησιμοποιεί addEventListener (δεν πατάει πάνω σε document.onkeydown κ.λπ.
 * άλλων scripts) και αφήνει πάντα ελεύθερα: πεδία φόρμας, contenteditable,
 * ό,τι έχει κλάση .pncp-allow, και την πλοήγηση με πληκτρολόγιο.
 */
( function () {
	'use strict';

	var cfg = window.pncpConfig;
	if ( ! cfg ) {
		return;
	}

	var FIELDS = 'input, textarea, select, option, [contenteditable=""], [contenteditable="true"]';
	var EDITABLE = FIELDS + ', .pncp-allow';
	var toast = null;
	var toastTimer = null;

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
		if ( ! cfg.showMessage || ! cfg.message ) {
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

	/* ---------- Δεξί κλικ ---------- */
	if ( cfg.contextMenu ) {
		document.addEventListener( 'contextmenu', function ( e ) {
			if ( isAllowed( e.target ) ) {
				return;
			}
			e.preventDefault();
			showMessage();
		} );
	}

	/* ---------- Σύρσιμο εικόνων ---------- */
	if ( cfg.imageDrag ) {
		document.addEventListener( 'dragstart', function ( e ) {
			var el = elementOf( e.target );
			if ( el && el.tagName === 'IMG' && ! isAllowed( el ) ) {
				e.preventDefault();
			}
		} );
	}

	/* ---------- Επιλογή κειμένου ---------- */
	if ( cfg.selection ) {
		document.addEventListener( 'selectstart', function ( e ) {
			if ( ! isAllowed( e.target ) ) {
				e.preventDefault();
			}
		} );
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

		document.addEventListener( 'keydown', function ( e ) {
			if ( ! ( e.ctrlKey || e.metaKey ) || e.altKey ) {
				return;
			}
			// Λατινικό e.key όταν υπάρχει (σωστό σε AZERTY/Dvorak). Με ελληνική διάταξη το e.key
			// είναι π.χ. 'ψ', οπότε πέφτουμε στο e.code ('KeyC').
			var key = /^[a-z]$/i.test( e.key || '' ) ? e.key.toLowerCase() :
				( e.code && e.code.indexOf( 'Key' ) === 0 ? e.code.slice( 3 ).toLowerCase() : '' );
			if ( keys.indexOf( key ) === -1 || isAllowed( e.target ) ) {
				return;
			}
			// Αντιγραφή κειμένου από .pncp-allow (τηλέφωνο, κουπόνι) με το πληκτρολόγιο.
			if ( ( key === 'c' || key === 'x' ) && hasAllowedSelection() ) {
				return;
			}
			e.preventDefault();
			showMessage();
		} );
	}

	/* ---------- Συντομεύσεις DevTools (κοσμητικό: δεν ανιχνεύουμε DevTools και δεν σπάμε τη σελίδα) ---------- */
	if ( cfg.devtools ) {
		document.addEventListener( 'keydown', function ( e ) {
			var code = e.code || '';
			var letter = code.indexOf( 'Key' ) === 0 ? code.slice( 3 ) : '';
			var hit =
				e.key === 'F12' || code === 'F12' ||
				// Windows / Linux: Ctrl+Shift+I/J/C/K
				( e.ctrlKey && e.shiftKey && ! e.altKey && 'IJCK'.indexOf( letter ) !== -1 && letter !== '' ) ||
				// macOS: Cmd+Opt+I/J/C/U
				( e.metaKey && e.altKey && 'IJCU'.indexOf( letter ) !== -1 && letter !== '' );
			if ( hit ) {
				e.preventDefault();
				showMessage();
			}
		} );
	}

	/* ---------- Αντιγραφή / αποκοπή ---------- */
	function onCopy( e ) {
		if ( cfg.copyMode === 'allow' ) {
			return;
		}
		var sel = window.getSelection ? window.getSelection() : null;
		// Για .pncp-allow κρίνει η επιλογή, όχι το target: μια επιλογή που ξεκινά από εκεί
		// και απλώνεται σε προστατευμένο κείμενο δεν περνά.
		if ( isField( e.target ) || hasAllowedSelection() ) {
			return;
		}
		if ( cfg.copyMode === 'block' ) {
			e.preventDefault();
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
		e.preventDefault();
	}
	document.addEventListener( 'copy', onCopy );
	document.addEventListener( 'cut', onCopy );

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
