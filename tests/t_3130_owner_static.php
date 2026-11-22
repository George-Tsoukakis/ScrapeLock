<?php
/**
 * ScrapeLock 3.13.0 — every file the plugin writes keeps its owner (static check, no WordPress needed).
 *
 *   php t_3130_owner_static.php
 *
 * In includes/*.php, each call of rename(), file_put_contents() or mkdir() must be followed, in the same
 * function, by a call of PNCP_File_Owner (capture / restore / put / mkdir), by a call of the pre-cache check's
 * own copy of that logic (a self:: / static:: method with "owner" in its name, in class-pncp-precheck-runtime.php,
 * which loads no other file of the plugin), or be annotated "// owner: <reason>" on its line, in the comments
 * just above it or later in the function (a counter file only the web server writes, a test file deleted at once…).
 * PNCP_File_Owner itself is not checked. Each call without one is listed (file:line function()).
 */

$dir   = dirname( __DIR__ ) . '/includes';
$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( '' !== (string) $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/**
 * The function bodies of a PHP file: [name, first token index, last token index].
 *
 * @param array<int, mixed> $tokens token_get_all().
 * @return array<int, array{0:string,1:int,2:int}>
 */
function bodies( $tokens ) {
	$out = array();
	$n   = count( $tokens );
	for ( $i = 0; $i < $n; $i++ ) {
		if ( ! is_array( $tokens[ $i ] ) || T_FUNCTION !== $tokens[ $i ][0] ) {
			continue;
		}
		$name = '{closure}';
		for ( $j = $i + 1; $j < $n; $j++ ) {
			if ( is_array( $tokens[ $j ] ) && T_STRING === $tokens[ $j ][0] ) {
				$name = $tokens[ $j ][1];
				break;
			}
			if ( '(' === $tokens[ $j ] ) {
				break;
			}
		}
		// The body: the first "{" after the parameters (none for an abstract method), to its matching "}".
		$depth = 0;
		$start = -1;
		for ( $j = $i + 1; $j < $n; $j++ ) {
			$tok = $tokens[ $j ];
			if ( -1 === $start && ';' === $tok ) {
				break;
			}
			if ( '{' === $tok || ( is_array( $tok ) && in_array( $tok[0], array( T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES ), true ) ) ) {
				if ( -1 === $start ) {
					$start = $j;
				}
				++$depth;
			} elseif ( '}' === $tok ) {
				--$depth;
				if ( 0 === $depth && -1 !== $start ) {
					$out[] = array( $name, $start, $j );
					break;
				}
			}
		}
	}
	return $out;
}

/** The line of a token (the line of the nearest array token before it). */
function line_of( $tokens, $i ) {
	for ( ; $i >= 0; $i-- ) {
		if ( is_array( $tokens[ $i ] ) ) {
			return (int) $tokens[ $i ][2];
		}
	}
	return 0;
}

$missing = array();
$calls   = 0;
foreach ( glob( $dir . '/*.php' ) as $file ) {
	$base = basename( $file );
	if ( 'class-pncp-file-owner.php' === $base ) {
		continue;
	}
	$src    = (string) file_get_contents( $file );
	$lines  = explode( "\n", $src );
	$tokens = token_get_all( $src );
	$funcs  = bodies( $tokens );
	foreach ( $funcs as $func ) {
		list( $name, $from, $to ) = $func;
		for ( $i = $from; $i <= $to; $i++ ) {
			$tok = $tokens[ $i ];
			if ( ! is_array( $tok ) || T_STRING !== $tok[0] || ! in_array( strtolower( $tok[1] ), array( 'rename', 'file_put_contents', 'mkdir' ), true ) ) {
				continue;
			}
			// A function call: "(" next, and not a method ("->", "::"), a definition or a namespaced name.
			$next = $i + 1;
			while ( is_array( $tokens[ $next ] ) && T_WHITESPACE === $tokens[ $next ][0] ) {
				++$next;
			}
			$prev = $i - 1;
			while ( $prev > 0 && is_array( $tokens[ $prev ] ) && T_WHITESPACE === $tokens[ $prev ][0] ) {
				--$prev;
			}
			$before = is_array( $tokens[ $prev ] ) ? $tokens[ $prev ][0] : $tokens[ $prev ];
			if ( '(' !== $tokens[ $next ] || in_array( $before, array( T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NS_SEPARATOR, T_NEW ), true ) || ( defined( 'T_NULLSAFE_OBJECT_OPERATOR' ) && T_NULLSAFE_OBJECT_OPERATOR === $before ) ) {
				continue;
			}
			// Nested closures: the innermost function that holds the call decides.
			$inner = $func;
			foreach ( $funcs as $other ) {
				if ( $other[1] > $inner[1] && $other[2] < $inner[2] && $other[1] < $i && $other[2] > $i ) {
					$inner = $other;
				}
			}
			if ( $inner !== $func ) {
				continue; // Counted when that function is walked.
			}
			++$calls;
			$line = (int) $tok[2];
			$ok   = false;
			// The annotation on the call's line or in the comment lines just above it.
			if ( preg_match( '#//\s*owner:\s*\S#', $lines[ $line - 1 ] ) ) {
				$ok = true;
			}
			for ( $l = $line - 2; ! $ok && $l >= 0 && preg_match( '#^\s*(//|\*|/\*)#', $lines[ $l ] ); $l-- ) {
				$ok = (bool) preg_match( '#//\s*owner:\s*\S#', $lines[ $l ] );
			}
			// Later in the same function: PNCP_File_Owner, the runtime's own copy, or the annotation.
			for ( $j = $i + 1; ! $ok && $j <= $to; $j++ ) {
				$t = $tokens[ $j ];
				if ( ! is_array( $t ) ) {
					continue;
				}
				if ( T_STRING === $t[0] && 'PNCP_File_Owner' === $t[1] ) {
					$ok = true;
				} elseif ( T_STRING === $t[0] && 'class-pncp-precheck-runtime.php' === $base && false !== stripos( $t[1], 'owner' ) && isset( $tokens[ $j - 1 ] ) && is_array( $tokens[ $j - 1 ] ) && T_DOUBLE_COLON === $tokens[ $j - 1 ][0] ) {
					$ok = true;
				} elseif ( T_COMMENT === $t[0] && preg_match( '#//\s*owner:\s*\S#', $t[1] ) ) {
					$ok = true;
				}
			}
			if ( ! $ok ) {
				$missing[] = $base . ':' . $line . ' ' . $name . '() ' . $tok[1] . '()';
			}
		}
	}
}

t( "the check found the plugin's writes ($calls calls of rename / file_put_contents / mkdir)", $calls > 10, (string) $calls );
foreach ( $missing as $m ) {
	echo '  no owner kept: ' . $m . "\n";
}
t( 'every rename / file_put_contents / mkdir is followed by PNCP_File_Owner, the runtime\'s copy or "// owner: <reason>"', array() === $missing, count( $missing ) . ' calls' );

echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );
