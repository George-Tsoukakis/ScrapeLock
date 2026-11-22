#!/bin/sh
# ScrapeLock — όλες οι δοκιμές. WP_DIR, BASE και WP_CLI: βλ. README.txt
cd "$(dirname "$0")" || exit 1
: "${WP_DIR:?}" "${BASE:?}"
PHP=${PHP:-php}
fail=0
# Βασικές δοκιμές (και σε SQLite). Οι δοκιμές πραγματικής στοίβας (WooCommerce, WPGraphQL, κανόνες server,
# cache, ασφάλεια, φορτίο) τρέχουν με FULL=1 σε WordPress με MariaDB/MySQL, Nginx + PHP-FPM και Apache.
TESTS="t_http t_metadata_paths t_fixes351 t_360 t_watermark t_admin t_precheck t_lockdown t_edge t_private_folders t_cli t_harden_headers t_metadata t_ai_lists t_plugin_bots t_bunny_rules t_site_files t_311_pipeline t_311_lists t_311_status t_311_wizard t_311_texts t_311_ui t_311_integration t_311_compat t_311_i18n t_traffic t_traffic_ops t_traffic_ui t_traffic_sec t_traffic_ms t_3121_loopback t_3122_loopback t_3121_fluent t_3121_wizard t_3121_tester t_3121_ai_search t_3121_traffic t_3121_integration t_3122_previews t_3122_wizard t_3123_rules t_3124_nginx_status t_3125_blur t_3126_stealth t_3126_status t_3126_cli t_3126_verify t_3126_profilers t_3126_wizard t_3126_integration t_3127_stealth_cache t_3127_fastcgi t_3127_traces t_3128_stealth_inner t_3128_stealth_edges t_3128_purge t_3128_bugs_d t_3128_release t_3129_precheck_io t_3129_requests t_3129_breaker t_3129_strace t_3130_owner_files t_3130_owner_data t_3130_root_wpcli t_3130_owner_static"
[ "${FULL:-0}" = "1" ] && TESTS="$TESTS t_woocommerce t_graphql_rest t_security t_cache t_server_rules"
[ "${LOAD:-0}" = "1" ] && TESTS="$TESTS t_load"
for t in $TESTS; do
	out=$(WP_DIR="$WP_DIR" BASE="$BASE" WP_CLI="${WP_CLI:-}" NGINX_URL="${NGINX_URL:-$BASE}" APACHE_URL="${APACHE_URL:-}" REDIS_DROPIN="${REDIS_DROPIN:-}" FREEZE_MOUNT="${FREEZE_MOUNT:-}" $PHP "$t.php" 2>&1)
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
