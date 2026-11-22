<?php
/**
 * ScrapeLock 3.12.10 — every file the plugin writes keeps its owner (static check, no WordPress needed).
 *
 *   php t_3130_owner_static.php
 *
 * In includes/*.php, each call of rename(), file_put_contents() or mkdir() must be handled in the same function:
 *  - followed by a call of a method that sets the owner or mode: PNCP_File_Owner::restore / put / mkdir, the
 *    pre-cache check's own copy (PNCP_Precheck_Runtime::keep_owner / mkdir_owner…, from any file), or a class's
 *    own helper (self::keep_owner…). Of PNCP_File_Owner's methods and those with "owner" in their name, only the
 *    ones whose body calls chmod / chown / chgrp, or another such method, count (is_root(), capture(),
 *    owner_meta() do not);
 *  - for rename(): preceded by such a call on the file it renames (the temporary file gets its owner and mode
 *    before the rename, so no reader sees it wrong);
 *  - or annotated "// owner: <reason>" on its line, in the comments just above it or later in the function: an
 *    in-place rewrite of an existing file (file_put_contents() keeps the inode, so its owner and mode), a
 *    rename of a file away (the inode keeps its owner), a throwaway file deleted at once…
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

/** The next token index after $i that is not whitespace or a comment. */
function next_code( $tokens, $i ) {
	$n = count( $tokens );
	for ( ++$i; $i < $n && is_array( $tokens[ $i ] ) && in_array( $tokens[ $i ][0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ); $i++ ) {
	}
	return $i;
}

/**
 * The first argument of the call whose "(" is at $open, without whitespace, comments and "@": "$tmp", "$real.'.new'".
 *
 * @param array<int, mixed> $tokens token_get_all().
 * @param int               $open   Index of "(".
 * @return string
 */
function first_arg( $tokens, $open ) {
	$depth = 0;
	$out   = '';
	$n     = count( $tokens );
	for ( $i = $open; $i < $n; $i++ ) {
		$tok  = $tokens[ $i ];
		$text = is_array( $tok ) ? $tok[1] : $tok;
		if ( in_array( $text, array( '(', '[', '{' ), true ) || ( is_array( $tok ) && in_array( $tok[0], array( T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES ), true ) ) ) {
			++$depth;
			if ( 1 === $depth ) {
				continue;
			}
		} elseif ( in_array( $text, array( ')', ']', '}' ), true ) ) {
			--$depth;
			if ( 0 === $depth ) {
				break;
			}
		} elseif ( ',' === $text && 1 === $depth ) {
			break;
		}
		if ( is_array( $tok ) && in_array( $tok[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) || '@' === $text ) {
			continue;
		}
		$out .= $text;
	}
	return $out;
}

/**
 * The static calls in tokens $from..$to: [index of the method name, class ("self" resolved to $class), method].
 *
 * @param array<int, mixed> $tokens token_get_all().
 * @return array<int, array{0:int,1:string,2:string}>
 */
function static_calls( $tokens, $from, $to, $class ) {
	$out = array();
	for ( $j = $from; $j <= $to; $j++ ) {
		if ( ! is_array( $tokens[ $j ] ) || T_DOUBLE_COLON !== $tokens[ $j ][0] ) {
			continue;
		}
		$cls = $j - 1;
		while ( $cls > 0 && is_array( $tokens[ $cls ] ) && T_WHITESPACE === $tokens[ $cls ][0] ) {
			--$cls;
		}
		$m = next_code( $tokens, $j );
		if ( ! is_array( $tokens[ $cls ] ) || ! is_array( $tokens[ $m ] ) || T_STRING !== $tokens[ $m ][0] || '(' !== $tokens[ next_code( $tokens, $m ) ] ) {
			continue;
		}
		$name = strtolower( $tokens[ $cls ][1] );
		$out[] = array( $m, in_array( $name, array( 'self', 'static' ), true ) ? strtolower( $class ) : $name, strtolower( $tokens[ $m ][1] ) );
	}
	return $out;
}

// Pass 1: every file's class and methods; then which methods set an owner or mode ("class::method" => true): of
// PNCP_File_Owner's methods and those with "owner" in their name, the ones whose body calls chmod / chown / chgrp /
// lchown / lchgrp, or (repeated until nothing changes) another such method.
$files = array();
foreach ( glob( $dir . '/*.php' ) as $file ) {
	$src    = (string) file_get_contents( $file );
	$tokens = token_get_all( $src );
	$class  = '';
	foreach ( $tokens as $k => $tok ) {
		if ( is_array( $tok ) && T_CLASS === $tok[0] ) {
			$c = next_code( $tokens, $k );
			if ( is_array( $tokens[ $c ] ) && T_STRING === $tokens[ $c ][0] ) {
				$class = $tokens[ $c ][1];
				break;
			}
		}
	}
	$files[ $file ] = array( $src, $tokens, bodies( $tokens ), $class );
}
$setters = array();
do {
	$added = false;
	foreach ( $files as $info ) {
		list( , $tokens, $funcs, $class ) = $info;
		foreach ( $funcs as $func ) {
			$key = strtolower( $class . '::' . $func[0] );
			// Candidates: PNCP_File_Owner's methods and the helpers named for it (keep_owner, mkdir_owner…). Not
			// every method that somewhere down the line calls one: a handler would then excuse any write.
			if ( isset( $setters[ $key ] ) || ( 'PNCP_File_Owner' !== $class && false === stripos( $func[0], 'owner' ) ) ) {
				continue;
			}
			$sets = false;
			for ( $j = $func[1]; ! $sets && $j <= $func[2]; $j++ ) {
				$t    = $tokens[ $j ];
				$sets = is_array( $t ) && T_STRING === $t[0] && in_array( strtolower( $t[1] ), array( 'chmod', 'chown', 'chgrp', 'lchown', 'lchgrp' ), true ) && '(' === $tokens[ next_code( $tokens, $j ) ];
			}
			foreach ( $sets ? array() : static_calls( $tokens, $func[1], $func[2], $class ) as $call ) {
				if ( isset( $setters[ $call[1] . '::' . $call[2] ] ) ) {
					$sets = true;
					break;
				}
			}
			if ( $sets ) {
				$setters[ $key ] = true;
				$added           = true;
			}
		}
	}
} while ( $added );

$missing = array();
$calls   = 0;
foreach ( $files as $file => $info ) {
	$base = basename( $file );
	if ( 'class-pncp-file-owner.php' === $base ) {
		continue;
	}
	list( $src, $tokens, $funcs, $class ) = $info;
	$lines = explode( "\n", $src );
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
			// Later in the same function: a call of a method that sets the owner or mode, or the annotation.
			$owner_calls = array();
			foreach ( static_calls( $tokens, $func[1], $func[2], $class ) as $call ) {
				if ( isset( $setters[ $call[1] . '::' . $call[2] ] ) ) {
					$owner_calls[] = $call[0];
				}
			}
			foreach ( $owner_calls as $at ) {
				$ok = $ok || $at > $i;
			}
			for ( $j = $i + 1; ! $ok && $j <= $to; $j++ ) {
				$t  = $tokens[ $j ];
				$ok = is_array( $t ) && T_COMMENT === $t[0] && preg_match( '#//\s*owner:\s*\S#', $t[1] );
			}
			// rename(): earlier in the function, such a call on the very file it renames (the temporary file).
			if ( ! $ok && 'rename' === strtolower( $tok[1] ) ) {
				$source = first_arg( $tokens, $next );
				foreach ( $owner_calls as $at ) {
					$ok = $ok || ( $at < $i && '' !== $source && first_arg( $tokens, next_code( $tokens, $at ) ) === $source );
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
