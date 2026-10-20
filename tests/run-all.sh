#!/bin/sh
# ScrapeLock — όλες οι δοκιμές. WP_DIR, BASE και WP_CLI: βλ. README.txt
cd "$(dirname "$0")" || exit 1
: "${WP_DIR:?}" "${BASE:?}"
PHP=${PHP:-php}
fail=0
# Βασικές δοκιμές (και σε SQLite). Οι δοκιμές πραγματικής στοίβας (WooCommerce, WPGraphQL, κανόνες server,
# cache, ασφάλεια, φορτίο) τρέχουν με FULL=1 σε WordPress με MariaDB/MySQL, Nginx + PHP-FPM και Apache.
TESTS="t_http t_watermark t_admin t_precheck t_lockdown t_cli"
[ "${FULL:-0}" = "1" ] && TESTS="$TESTS t_woocommerce t_graphql_rest t_security t_cache t_server_rules"
[ "${LOAD:-0}" = "1" ] && TESTS="$TESTS t_load"
for t in $TESTS; do
	out=$(WP_DIR="$WP_DIR" BASE="$BASE" WP_CLI="${WP_CLI:-}" NGINX_URL="${NGINX_URL:-$BASE}" APACHE_URL="${APACHE_URL:-}" REDIS_DROPIN="${REDIS_DROPIN:-}" $PHP "$t.php" 2>&1)
	rc=$?
	f=$(printf '%s\n' "$out" | grep -c -E '^FAIL |Fatal error|^(PHP )?(Warning|Notice|Deprecated):')
	p=$(printf '%s\n' "$out" | grep -c '^PASS ')
	if [ "$p" -eq 0 ] && printf '%s\n' "$out" | grep -q '^SKIP'; then
		echo "skip $t ($(printf '%s\n' "$out" | grep '^SKIP' | head -1))"; continue
	fi
	if [ "$rc" -ne 0 ] || [ "$f" -ne 0 ] || [ "$p" -eq 0 ]; then
		echo "FAIL $t ($p PASS)"; printf '%s\n' "$out" | grep -E '^FAIL |Fatal|Warning|Notice|Deprecated'; fail=1
	else
		echo "ok   $t ($p PASS)"
	fi
done
if [ -n "${WP_CLI:-}" ] && [ -d browser/node_modules ]; then
	(cd browser && WP_CLI="$WP_CLI" BASE="$BASE" POST_PATH="${POST_PATH:-/}" npm test --silent) || fail=1
fi
exit $fail
