/**
 * ScrapeLock – settings page: folded parts, copy buttons, unsaved changes, dependent fields and batch watermark tool.
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

	/* ---------- Confirmation ---------- */
	// Buttons with data-pncp-confirm (e.g. a preset that turns off RSS feeds or printing) ask first.
	document.addEventListener( 'click', function ( e ) {
		var button = e.target.closest ? e.target.closest( '[data-pncp-confirm]' ) : null;
		if ( button && ! window.confirm( button.getAttribute( 'data-pncp-confirm' ) ) ) {
			e.preventDefault();
		}
	} );

	/* ---------- Folded parts ---------- */
	// A quick link (or an address with #pncp-sec-…) to a setting inside a folded part, e.g. "Real visitor IP"
	// in "Network and CDN", opens that part first, so the link never lands on something hidden.
	function openFor( hash ) {
		if ( ! hash || hash.length < 2 ) {
			return;
		}
		var id;
		try {
			id = decodeURIComponent( hash.slice( 1 ) );
		} catch ( err ) {
			return;
		}
		var target = document.getElementById( id );
		if ( ! target ) {
			return;
		}
		for ( var node = target; node; node = node.parentElement ) {
			if ( 'DETAILS' === node.tagName && ! node.open ) {
				node.open = true;
			}
		}
		if ( target.scrollIntoView ) {
			target.scrollIntoView();
		}
	}
	openFor( window.location.hash );
	window.addEventListener( 'hashchange', function () {
		openFor( window.location.hash );
	} );

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
		// The label before the first click: a second click within 2 seconds would otherwise keep "Copied" for good.
		if ( ! button.hasAttribute( 'data-pncp-label' ) ) {
			button.setAttribute( 'data-pncp-label', button.textContent );
		}
		var original = button.getAttribute( 'data-pncp-label' );
		var done = function () {
			button.textContent = cfg.i18n.copied;
			clearTimeout( button.pncpTimer );
			button.pncpTimer = setTimeout( function () {
				button.textContent = original;
			}, 2000 );
		};
		// Without the Clipboard API (a site on plain HTTP) or when it refuses: the text is selected and copied
		// the old way. A <code> (the new token, shown only once) has no select(), so a range selects it; if
		// copying fails, the text stays selected for Ctrl+C.
		var fallback = function () {
			var ok = false;
			try {
				if ( target.select ) {
					target.select();
				} else if ( window.getSelection && document.createRange ) {
					var range = document.createRange();
					range.selectNodeContents( target );
					var selection = window.getSelection();
					selection.removeAllRanges();
					selection.addRange( range );
				}
				ok = document.execCommand( 'copy' );
			} catch ( err ) {
				ok = false;
			}
			if ( ok ) {
				done();
			}
		};
		if ( navigator.clipboard && window.isSecureContext ) {
			navigator.clipboard.writeText( text ).then( done, fallback );
		} else {
			fallback();
		}
	} );

	/* ---------- Unsaved changes (3.5) ---------- */
	// Only the tab's settings form (data-pncp-watch): "Unsaved changes" next to the button while a field differs
	// from the page load, and the browser's own "Leave site?" question before leaving with changes. Nothing is
	// stored in the browser.
	var watched = document.querySelectorAll( 'form.pncp-settings-form[data-pncp-watch]' );

	function formState( form ) {
		var parts = [];
		Array.prototype.forEach.call( form.elements, function ( el ) {
			var type = ( el.type || '' ).toLowerCase();
			if ( ! el.name || el.disabled || 'submit' === type || 'button' === type || 'file' === type || 'reset' === type || 'FIELDSET' === el.tagName ) {
				return;
			}
			var name = encodeURIComponent( el.name ) + '=';
			if ( 'checkbox' === type || 'radio' === type ) {
				// An unchecked box counts too, so unchecking is a change.
				parts.push( name + ( el.checked ? encodeURIComponent( el.value ) : '' ) );
			} else if ( 'select-multiple' === type ) {
				Array.prototype.forEach.call( el.options, function ( option ) {
					if ( option.selected ) {
						parts.push( name + encodeURIComponent( option.value ) );
					}
				} );
			} else {
				parts.push( name + encodeURIComponent( el.value ) );
			}
		} );
		return parts.join( '&' );
	}

	function updateDirty( form ) {
		var dirty = formState( form ) !== form.pncpInitial;
		var marker = form.querySelector( '.pncp-unsaved' );
		form.pncpDirty = dirty;
		if ( marker ) {
			marker.hidden = ! dirty;
		}
		if ( form.classList ) {
			form.classList.toggle( 'is-dirty', dirty );
		}
	}

	Array.prototype.forEach.call( watched, function ( form ) {
		form.pncpInitial = formState( form );
		form.addEventListener( 'input', function () {
			updateDirty( form );
		} );
		form.addEventListener( 'change', function () {
			updateDirty( form );
		} );
		form.addEventListener( 'submit', function () {
			form.pncpSubmitting = true;
		} );
	} );

	if ( watched.length ) {
		// The browser may fill in fields (e.g. a saved password) after the script ran: until the user does
		// something, the state at "load" is the starting point, so autofill is not counted as a change.
		var touched = false;
		var touch = function () {
			touched = true;
		};
		document.addEventListener( 'keydown', touch, true );
		document.addEventListener( 'pointerdown', touch, true );
		window.addEventListener( 'load', function () {
			if ( touched ) {
				return;
			}
			Array.prototype.forEach.call( watched, function ( form ) {
				form.pncpInitial = formState( form );
				updateDirty( form );
			} );
		} );
		window.addEventListener( 'beforeunload', function ( e ) {
			var dirty = false;
			Array.prototype.forEach.call( watched, function ( form ) {
				if ( form.pncpDirty && ! form.pncpSubmitting ) {
					dirty = true;
				}
			} );
			if ( ! dirty ) {
				return undefined;
			}
			e.preventDefault();
			e.returnValue = '';
			return '';
		} );
	}

	/* ---------- Dependent controls (3.5) ---------- */
	// A field that does nothing in the current state (e.g. "Verify AI search bots" while AI search is not
	// allowed) is dimmed with aria-disabled and a note, and follows its controlling field live. It is never
	// disabled: it stays focusable and changeable, and its value is still saved.
	function controllerValue( ctl ) {
		if ( ctl.length !== undefined && ! ctl.tagName ) {
			return { type: 'radio', value: ctl.value }; // RadioNodeList.
		}
		var type = ( ctl.type || '' ).toLowerCase();
		if ( 'checkbox' === type ) {
			return { type: type, value: ctl.checked };
		}
		return { type: type, value: ctl.value };
	}

	function requirementMet( el ) {
		var spec = el.getAttribute( 'data-pncp-requires' ) || '';
		var eq = spec.indexOf( '=' );
		var name = eq < 0 ? spec : spec.slice( 0, eq );
		var want = eq < 0 ? null : spec.slice( eq + 1 );
		var field = 'FIELDSET' === el.tagName ? el.querySelector( '[name]' ) : el;
		if ( ! field || ! field.name || field.name.indexOf( '[' ) < 0 || ! el.form ) {
			return null;
		}
		var prefix = field.name.slice( 0, field.name.indexOf( '[' ) );
		var ctl = el.form.elements[ prefix + '[' + name + ']' ];
		if ( ! ctl ) {
			return null; // The controlling field is on another tab: the state printed by the server stays.
		}
		var c = controllerValue( ctl );
		if ( null !== want ) {
			return String( c.value ) === want;
		}
		if ( 'checkbox' === c.type ) {
			return !! c.value;
		}
		if ( 'number' === c.type ) {
			return parseFloat( c.value ) > 0;
		}
		return '' !== String( c.value ).trim();
	}

	function noteFor( el ) {
		if ( el.id ) {
			return document.getElementById( el.id + '-requires' );
		}
		var field = el.querySelector( '[name]' );
		var match = field ? /\[([^\]]+)\]$/.exec( field.name ) : null;
		return match ? document.getElementById( 'pncp-' + match[1] + '-requires' ) : null;
	}

	function updateDependents( form ) {
		Array.prototype.forEach.call( form.querySelectorAll( '[data-pncp-requires]' ), function ( el ) {
			var met = requirementMet( el );
			if ( null === met ) {
				return;
			}
			if ( met ) {
				el.removeAttribute( 'aria-disabled' );
			} else {
				el.setAttribute( 'aria-disabled', 'true' );
			}
			var wrapper = ( el.closest && el.closest( '.pncp-field' ) ) || el.parentElement;
			if ( wrapper && wrapper.classList ) {
				wrapper.classList.toggle( 'is-dimmed', ! met );
			}
			var note = noteFor( el );
			if ( note ) {
				note.hidden = met;
			}
		} );
	}

	Array.prototype.forEach.call( document.querySelectorAll( 'form.pncp-settings-form' ), function ( form ) {
		if ( ! form.querySelector( '[data-pncp-requires]' ) ) {
			return;
		}
		updateDependents( form );
		form.addEventListener( 'change', function () {
			updateDependents( form );
		} );
		form.addEventListener( 'input', function () {
			updateDependents( form );
		} );
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
