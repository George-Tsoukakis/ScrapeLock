ScrapeLock — δοκιμές σε πραγματικό WordPress (όχι stubs). Η βάση και τα uploads του WordPress
δοκιμών αλλάζουν: ΠΟΤΕ σε πραγματικό site.

Στήσιμο (και χωρίς MySQL):
  composer create-project johnpbloch/wordpress-core wp
  composer require wp-cli/wp-cli-bundle aaemnnosttv/wp-sqlite-db   (db.php -> wp/wp-content/db.php)
  wp config create --dbname=wp --dbuser=x --dbpass=x --skip-check && wp config set WP_DEBUG true --raw
  wp core install --url=http://127.0.0.1:8099 ... && wp rewrite structure '/%postname%/'
  ln -s $PWD/.. wp/wp-content/plugins/scrapelock && wp plugin activate scrapelock
  ln -s $PWD/lib/mu-test-harness.php wp/wp-content/mu-plugins/
  php -S 127.0.0.1:8099 -t wp lib/router.php &
  wp post create --post_status=publish --post_title=Δοκιμή --post_content="…"

Τρέξιμο:
  WP_DIR=… BASE=http://127.0.0.1:8099 WP_CLI="wp --path=…" ./run-all.sh

  t_http.php        bots, ψεύτικο/πραγματικό Googlebot, όρια, αποκλεισμοί, παγίδα (και ότι ξένο site δεν παγιδεύει
                    επισκέπτες), REST, robots.txt, TDM, feeds με token (header/Bearer/URL, χάρη, ακύρωση),
                    Emergency Mode, Trusted Proxy, headers iframe, σειρά scripts στο <head>
  t_metadata_paths.php 3.10: /.well-known/, favicon, apple-touch-icon χωρίς «Browsers only» / headless / όριο χωρίς
                    επαλήθευση ανθρώπου (όχι POST, όχι ../), Google fetchers / Applebot / DuckDuckBot από τις επίσημες
                    λίστες (αποθηκευμένες λίστες δοκιμής, χωρίς δίκτυο)
  t_fixes351.php    3.6 (διορθώσεις ασφαλείας): πλαστή τοπική IP στο header από edge του CDN (WordPress, early, pre-cache, HTTP), edge
                    χωρίς IP επισκέπτη, alloptions στο object cache, ατομικός προϋπολογισμός DNS, crawler με
                    αναπάντητο DNS και «Browsers only», Applebot / YandexBot χωρίς PTR, όριο αρχείων του pre-cache
  t_360.php         3.6: υδατογράφημα αναγνώστη, όριο ανά λογαριασμό, κοινός λογαριασμός, απόκρυψη αποτυπώματος,
                    αόρατο ίχνος στο κείμενο, εξαιρέσεις της παγίδας, autoload
  t_watermark.php   υδατογράφημα: ποτέ διπλό (Regenerate, update subsizes, εικόνες 1.4), πλήρες μέγεθος με καθαρό
                    αντίγραφο, -scaled, αφαίρεση, εικονίδιο/λογότυπο/προϊόντα/εικόνα υδατογραφήματος, θέσεις, JPEG/WebP
  t_admin.php       καρτέλες χωρίς PHP warnings, απενεργοποίηση μόνο με επιβεβαίωση, φόρμα καρτέλας που δεν σβήνει
                    άλλες, προφίλ, token μία φορά, αρχείο/διατήρηση, λίστες IP, εργαλείο εικόνων, κανόνες, GraphQL
  t_precheck.php    έλεγχος πριν από το cache (wp-config.php, loader, όρια, αποκλεισμοί)
  t_lockdown.php    Κλείδωμα: εφαρμογή authenticator, κάθε οθόνη, REST, κώδικας, ρόλοι, Abilities, Site Health
  t_edge.php        αποκλεισμός στο CDN (Cloudflare, Bunny) με ψεύτικο API: προσθήκη, λήξη, σφάλματα, όρια, εναλλαγή, φόρμα,
                    κουμπί δοκιμής, «μόνο μέσω CDN» (WordPress και πριν από την cache)
  t_plugin_bots.php 3.10: bots υπηρεσιών ενεργών plugins (WP-Rocket-SaaS, WP Rocket/Preload, Jetpack): περνούν όσο το
                    plugin είναι ενεργό, όχι από όρια / επιθέσεις, «Σταμάτα να επιτρέπεις» / «Allow» (nonce, δικαιώματα)
  t_harden_headers.php  Ευάλωτα σημεία → «Security headers»: η δημόσια αρχική σελίδα (GET, μετά από redirects, μέσω CDN),
                    «δεν ελέγχθηκε» αντί για «λείπει» όταν δεν φαίνεται η απάντηση των επισκεπτών (mocks)
  t_site_files.php  3.10.1: Site Health «ScrapeLock site files» (apple-touch-icon.png από το Site Icon, OneSignalSDKWorker.js
                    όσο το OneSignal είναι ενεργό): Create/Remove μόνο με nonce και manage_options, ποτέ πάνω σε αρχείο του
                    site, και ο έλεγχος «Wordfence and the visitor address» πίσω από CDN (ψεύτικο wfUtils / wfConfig)
  t_311_wizard.php  3.11: «For my site» (PNCP_Wizard) με stand-in plugins (WooCommerce, FluentCommunity /hub/, WP Rocket,
                    OneSignal, Wordfence) και Via: BunnyCDN: εντοπισμός, προτάσεις μόνο υπαρκτών ρυθμίσεων με αιτία, όσες
                    μπλοκάρουν περισσότερα χωρίς τσεκ, «Apply selected» (nonce, manage_options) μόνο των επιλεγμένων,
                    αντίγραφο στα «Earlier versions» και Undo, δεύτερο τρέξιμο χωρίς προτάσεις, wp scrapelock wizard
  t_private_folders.php  3.10: Site Health «private folders»: γραμμές Nginx/Apache για κάθε ιδιωτικό φάκελο (ορατές),
                    preset «private_folders» του «Lock at Bunny» με ψεύτικο API (και 400 για > 5 patterns), κουμπί μόνο
                    για διαχειριστή με Bunny, αναγνώριση του κλειδώματος στο Site Health
  t_311_status.php  3.11: ενδείξεις σε τρεις καταστάσεις («On», «Set but not active: <λόγος>», «Off») στη μπάρα, στη
                    σύνοψη «Network and CDN», στο widget, στο Site Health, στο Stealth και στο εβδομαδιαίο email· καμία
                    ετικέτα «setting_key: 1» σε καρτέλα (Emergency Mode, «Reset this tab»)· FluentCommunity (ψεύτικο
                    plugin): η πύλη στις «Content addresses» και οι αναγνώσεις REST των μελών εκτός ορίου· οι νέες
                    προεπιλογές μόνο σε νέα εγκατάσταση (αναβάθμιση από 3.10.1 χωρίς αλλαγή)
  t_311_ui.php      3.11: καρτέλες σε τέσσερις ομάδες (κάθε παλιά διεύθυνση, τα aliases της 3.10, άγνωστη καρτέλα), η
                    καρτέλα Bots ως accordion (ανοιχτά μόνο Bots, Limits, Sign-in· «Advanced»), οι μακριές λίστες με
                    «N entries» + «Edit» (όλη η τιμή στο textarea, Save μέσα από τη φόρμα κρατά τη λίστα)
  t_311_integration.php 3.11: πώς δένουν τα κομμάτια της 3.11: pre-cache/early check με τις ίδιες ρυθμίσεις «AI search»
                    όπως η λίστα bots, ο οδηγός «For my site» με FluentCommunity / plugin bots / ετικέτες ρυθμίσεων,
                    οι ειδοποιήσεις των 3.11 στις νέες καρτέλες, τα σύντομα κείμενα στις νέες περιγραφές, η υπογραφή
                    των αιτημάτων του site δεν ακολουθεί redirect σε άλλο host (ψεύτικος server στη 8952), ban στο πρώτο
                    probe και όταν το User-Agent απορρίπτεται πρώτο («Browsers only», κενό User-Agent)
  t_311_compat.php  3.11: τίποτα δεν αφαιρέθηκε: κάθε κλειδί ρυθμίσεων, καρτέλα και πεδίο φόρμας της 3.10.1 υπάρχει
                    ακόμη· ένα export της 3.10.1 (tests/fixtures/settings-export-3.10.1.json, κάθε ρύθμιση αλλαγμένη)
                    γίνεται import χωρίς απώλεια και ξαναβγαίνει ίδιο (tests/fixtures/keys-3.10.1.json: τα κλειδιά και
                    τα πεδία της 3.10.1)
  t_311_i18n.php    3.11: η ελληνική μετάφραση του languages/: ίδια strings με το .pot, όλα μεταφρασμένα με τα ίδια
                    placeholders / tags, .mo ίδιο με το .po, χωρίς μισές προτάσεις· φορτώνεται από το languages/ του
                    plugin (και όπως στις WordPress 6.2–6.6, με pncp_load_textdomain() στο init), ενώ ένα language pack
                    στο wp-content/languages/plugins/ προηγείται
  t_3121_wizard.php 3.12.1: «For my site» also checks sensible values: each proposal at its boundary values (probe_ban,
                    block_ip_host, reputation, temporary blocks as one row of two settings, rate_limit with the human
                    check, rate_limit_rest with WooCommerce / FluentCommunity, rate_limit_account with FluentCommunity
                    or a membership plugin, blur_on_capture / block_devtools / user_mark_guests, OneSignal in «Always
                    allowed»), stand-in MemberPress detected, the panel (ticked rows, diff, «Nothing to change»),
                    «Apply selected» (nonce, subscriber / editor 403, locked, only ticked rows, recomputed on the
                    server, saved version first), wp scrapelock wizard
  t_3121_fluent.php 3.12.1: FluentCommunity (stand-in with one REST route): a signed-in member's portal reads count
                    per account at 4 × the REST limit (13th of 12 → 429 for that account only, another member on the
                    same address unaffected, guests and a cookie without the nonce per IP, no violation), the log row
                    "rate_member" with the username (also "rate_account"), the per-account page limit counts them with
                    the member's pages (four reads as one page), the early / pre-cache checks leave them to WordPress, the notes (Bots tab,
                    Content addresses, "For my site"), deactivated → per IP again
  t_traffic.php     3.12: Traffic (PNCP_Traffic), the data layer: settings (path checks, upgrade, export/import),
                    nothing hooked or stored while off, ~40 User-Agents classified (verified / fake with stored official
                    lists), Bunny lines through parse_line() and the real import (mocked log API), the server access log
                    (combined / vhost / Nginx with rt and X-Forwarded-For, cursor, rotation to .1 and .1.gz, budget,
                    "Test this path" also with open_basedir and a symlink in a child PHP), the WordPress source over HTTP
                    (404 recorded; off, loopback and admin-ajax not), every query with filters and paging, CSV (formula
                    injection), the aggregates over a range longer than the raw window, retention, caps, masked IPs,
                    sources, purge and uninstall (on SQLite the drop-in cannot drop tables: they are emptied); the
                    fast paths: a status class from the daily figures, problems with their own status, one pass for a
                    detail (and its newest rows only for a very busy key), more keys than one query reads (has_more),
                    schema 1 -> 2 (the covering index) without dbDelta()
  t_traffic_ops.php 3.12: Traffic operations (PNCP_Traffic_Alerts, PNCP_Traffic_Cli) on 8 days of seeded traffic:
                    the alert settings (defaults off, bad address refused, export/import), the 5xx, 404 (probes and
                    metadata files excluded), new heavy User-Agent and stopped-source alerts firing and not firing
                    (below thresholds, alerts off, traffic off), throttling, recipients, the email text and its link to
                    the Traffic tab, the weekly email's and the dashboard widget's Traffic part, the Site Health test
                    (good / recommended) and info lines, every "wp scrapelock traffic" subcommand and format (needs
                    WP_CLI, else those checks SKIP), export refusing to overwrite, purge needing --yes, uninstall
  t_traffic_ui.php  3.12: the Traffic tab (PNCP_Admin_Traffic, PNCP_Traffic_Actions) over HTTP with seeded requests:
                    every view 200 without notices, the numbers are the API's, filters / sort / pages in the address and
                    the alert-email parameters, <script> in a User-Agent and a path escaped everywhere, CSV (headers,
                    filters, formulas), nonce and manage_options on every action (editor 403, wrong nonce), Block /
                    Always allow write one line after the confirmation and save an earlier version (Undo), search
                    engine and own-browser guards, Test this path, the settings form, Delete, off state, Start collecting
  t_traffic_sec.php 3.12: the security review of Traffic: the read-only actions (CSV, Test this path) refused while
                    the site is locked, the WordPress source never records a signed-in administrator, "Masked" IPs
                    turned on with full addresses stored (raw rows and per-IP figures masked, nothing shown unmasked),
                    the sample of "Test this path" masked too
  t_traffic_ms.php  3.12: Traffic on a multisite network (SKIP on a single site; SITE=/two/ with a "subadmin"): only a
                    network administrator may test the access log or have "Start collecting" pick it
  t_3121_loopback.php 3.12.1: the site's own requests behind Bunny without the CDN secret ("Real visitor IP" =
                    REMOTE_ADDR, the request from a Bunny edge, X-Test-Remote-Addr / X-Test-HTTPS): the signature
                    X-ScrapeLock-Sig (valid, expired, replayed, another path / method / host, forged, after redirects
                    with a stand-in server on 8953) passes every check in WordPress, the early check and "Only through
                    the CDN"; the WordPress User-Agent alone and X-Forwarded-For with the server's address do not;
                    Vulnerable points "Check again", the Stealth test, Site Health loopback and REST get real answers;
                    the pre-cache check (stand-in page cache): the same signature, its key only in the wp-config.php
                    line, nonces used once; the server's addresses: the outbound one detected from signed requests
                    (24-hour transient) and SCRAPELOCK_SERVER_IPS (a test mu-plugin for the web server), in
                    WordPress, the early check and the pre-cache check; ScrapeLock's rules at the CDN never block
                    the server (temporary blocks, Bunny log lines, the wp-login.php lock with a stand-in Bunny API)
  t_3122_loopback.php 3.12.2: the site's own requests when the CDN does not forward the Host header (Bunny's
                    default) or something on the way refuses them: the signature verified for the host it was signed
                    for whatever Host arrives, each failure reason (expired, host_mismatch, path_mismatch, bad_mac,
                    bad_format, no_key, nonce_reused), "//" / encoded paths, HEAD as GET, the 3.12.1 format, the
                    pre-cache check the same; one nonce per request across the pre-cache check, the early check and
                    WordPress (also with a persistent object cache); the diagnostics ring buffer (contents, privacy,
                    not autoloaded, allowance, a hash of the nonce and no address); "X-ScrapeLock: refused …" (just
                    "refused" for a stranger's forged signature) / "ok id=…" (unit and over HTTP); who answered
                    (ScrapeLock, Bunny's edge, Cloudflare, Wordfence, WordPress, the web server); the way straight to
                    the server (mocked with pre_http_request, and over real HTTP with CURLOPT_RESOLVE and a host name
                    that does not resolve) and the route for the site's other requests (only after this WordPress
                    answered with the request's id, only the site's own host:port and addresses, the TLS check kept,
                    clears itself; a forged CURLOPT_RESOLVE entry not applied); Vulnerable points' note and
                    details; a block of the server at the CDN removed at once; "Only through the CDN" without a
                    secret; "Check a request" loopback preset and "Run a real self-check now" (POST, its own nonce,
                    capability); Site Health "ScrapeLock self-request test"; wp scrapelock selfcheck (with WP_CLI);
                    uninstall and deactivation remove the self-check's options and route. Self-requests
                    are made from the test process only (the single-process server would wait for itself).
  t_3121_tester.php 3.12.1: "Check a request": an image, video, font, CSS or JS is "Checked as: Media", allowed as "image
                    or file; counted in the media limit, not as a page", with the media counter "N of M this minute"
                    (MEDIA_FACTOR × the page limit, pncp_static_extensions) and its 429; a page, a feed, a REST call and
                    every pass / refuse reason drawn as tester.js draws them, the AJAX answer, every wp-admin tab with
                    log rows and bans of every reason (and an unknown one): never a raw snake_case reason key;
                    wp scrapelock check (needs WP_CLI, else that part SKIPs)
  t_3121_ai_search.php 3.12.1: AI search bots with a bot list as the 3.11 upgrade left it: "Allow AI search" on,
                    OAI-SearchBot from its official address (stored test list openai_search) passes in WordPress, the
                    early check and the pre-cache check (stand-in page cache), from another address "Fake AI search
                    bot"; turned off, 403 everywhere from the built-in list (also in the pre-cache configuration),
                    "Always allowed" still first; on again, it passes; the bot list untouched in both transitions;
                    the 3.11 migration never runs again; the Bots tab warning and "Remove from the list"
  t_3121_traffic.php 3.12.1: Traffic, safer defaults (GDPR): a brand-new install stores traffic_ip_mode "masked", an
                    upgrade from 3.11 / 3.12.0 keeps "full" (no migration); "Start collecting" asks how IPs are stored
                    (Masked chosen in advance until the site has collected, what each mode stores, the retention of
                    single requests) and saves the choice; with Masked, the WordPress source over HTTP, Bunny and the
                    access log store no full address in any table, option, view, CSV, alert email, report line or
                    "wp scrapelock traffic" output (needs WP_CLI, else that part SKIPs); the privacy policy text
  t_3121_integration.php 3.12.1: how the parts of 3.12.1 fit together: rate_member (per account) is no reputation
                    event of the IP and every log reason has a label; the attack record keeps nothing of the site's
                    own requests (signed, or a CDN log line of SCRAPELOCK_SERVER_IPS)
  t_3122_previews.php 3.12.2: link previews of "Always allowed" (the real User-Agents of Viber, WhatsApp, Facebook,
                    Telegram, Slack, X, LinkedIn, Discord) on .webp / .jpg 30 times a minute with page limit 1: never 429
                    in WordPress, the early check or the pre-cache check; a browser, a preview not in the list and
                    Pinterest still count; the entry forms (part, "=" whole User-Agent, "@" pinned); "Check a request"
                    and wp scrapelock check say "Not counted: link preview in the “Always allowed” list", not "N of M"
  t_3122_wizard.php 3.12.2: «For my site» shows each setting by its label only: no setting key in the text of the panel
                    (3.11 plugin rows and 3.12.1 sensible values, the two-setting row too), each key in the title and
                    aria-label of a "?" button of its row (keyboard-reachable); the notice of "Apply selected" lists
                    the changes by label, before → after in words; no key in the text of any tab; wp scrapelock wizard
                    still prints the keys
  t_3123_rules.php  3.12.3: the self-checks send "ScrapeLock-Selftest/<version> (+home)" with the signature (every
                    check, captured with pre_http_request, and wp scrapelock selfcheck); the server's own addresses in
                    the generated Nginx geo / Apache conditions (never a CDN edge, an invalid entry or a private range
                    wider than /24), the block decision 0 for the server; the X-ScrapeLock-Rules header; "Allow AI
                    search" in the rules; out of date at once after a settings change, fresh with a matching header,
                    no nag without rules; the notice, Site Health and "See what changed" (nonce, manage_options); the
                    evaluator ("ScrapeLock's own server rule (fake browser)") against real Nginx when it is on PATH
  t_3125_blur.php   3.12.5: «Blur the page on screenshot shortcuts» → «Applies to: Everyone / Only visitors who are not
                    signed in» (blur_on_capture_scope): default "all" (and on a new install), sanitize (anything else →
                    "all"), section, label, requires note, cache key; upgrade 3.12.4 → 3.12.5 (every value unchanged,
                    "all" added, a stored "guests" kept); export / import; the form (two radios under the blur, dimmed
                    while it is off); the hint cookie pncp_si=1 over HTTP (sign-in with / without «Remember me»,
                    sign-out, an account signed in before 3.12.5 on a page and in wp-admin, a stale one removed, never
                    with the protection off); the same pncpConfig (blurScope) for a guest and a member; protect.min.js
                    is the build of the current source; the pre-cache / early checks do not touch the blur
  t_3126_profilers.php 3.12.6: «Block technology profilers» (block_tech_profilers): off by default (new install and
                    new_in_3126()), Bots tab switch right after the SEO crawlers, cache key, label, export; the one list
                    PNCP_Bots::tech_profiler_agents() with its filter; every layer of the SEO switch: blocked_agents(),
                    HTTP 403 / 200, early check, pre-cache config, Nginx / Apache rules, robots.txt group, the log's
                    «Matched … (technology profilers)», Traffic «Explain», Site Health info; «For my site» proposes the
                    switch for profilers typed into the bot list (one unticked row, those lines removed, saved version)
  t_3126_wizard.php 3.12.6: «For my site»: «Dismiss» per proposal (admin-post, nonce, manage_options, Lockdown), not
                    counted and never applied (also when posted or with --apply / --only), «Show dismissed (N)» with
                    «Restore»; the hash id + values now + proposed values (another value or proposal brings it back,
                    the same value pair keeps it dismissed: the owner's blur_on_capture / block_devtools case); «you
                    chose this» after a dismiss or a save of other values; one small option, not autoloaded;
                    wp scrapelock wizard dismiss / restore / --include-dismissed
  t_3126_integration.php 3.12.6: how the parts fit together: «Block technology profilers» on and a BuiltWith
                    verification file (200 for BuiltWith in WordPress, early and pre-cache checks, 403 elsewhere;
                    robots.txt «Allow: /builtwith.txt» before «Disallow: /»); uninstall.php and deactivation; wp scrapelock
                    rules status with the real Stealth status (stealth_state / _installed / _current); the Server rules
                    tab order (Apache, Nginx, Stealth, fail2ban, Verification files), each notice once (main rules,
                    Stealth rules), the second check before «not found»; export / import of block_tech_profilers; a settings save before init
                    (no translation loaded early, the wizard's note on init); static
                    security checks (proc_open only in the CLI class, escapeshellarg, --test-cmd / --reload-cmd)
  t_3127_stealth_cache.php 3.12.7: Stealth and cached pages: a WP Rocket-like stand-in (page cache buffer started
                    before the plugins and served before WordPress, optimization buffer at template_redirect 2 with
                    rocket_buffer at WP Rocket's priorities, rocket_css_url / rocket_js_url): MISS, the stored file and
                    its _gzip copy, HIT: 0 wp-content / wp-includes in the asset addresses, each maps back with the Nginx
                    and Apache rules; "?nocache=" is not optimized; a page stored with the words of before 3.12.6 (the
                    live leftover), the new map, Stealth off and on empty the page cache; real Nginx with a page cache
                    in front (SKIP without nginx): MISS / HIT clean, every asset 200, a stale Nginx cache until emptied
  t_3127_fastcgi.php 3.12.7: the Nginx fastcgi cache: real-format cache files (header, KEY line, the key's MD5 as
                    the name or in the header of a Vary variant) in a fake tree under /tmp; only keys with this site's
                    host at their start (after scheme and method, a port) deleted, never another host ending with it
                    or named in the query string; purge of the site (a site in a folder: only its folder) and of
                    addresses (path and query strings); symbolic links never followed; "/", system, home and
                    WordPress folders refused; the cap; SCRAPELOCK_FASTCGI_CACHE_PATH, Nginx Helper's constant and
                    settings, the constant first, pncp_purge_page_cache() and Stealth's purge in another process;
                    the nginx -T parser (includes, comments, quotes, the zone of this site's server block, inherited
                    from http, wildcards, a variable or undefined zone); the Stealth card line and readme FAQ;
                    wp scrapelock cache status / purge (fake nginx -T on PATH, --nginx-conf, --cache-dir, --dry-run,
                    --yes) and cdn purge --[no-]server-cache (WP_CLI); a real Nginx with fastcgi_cache in a
                    temporary prefix in front of lib/fcgi-stub.php (MISS, HIT, purge, MISS; SKIP without nginx)
  t_cli.php         wp scrapelock … μέσα από το πραγματικό wp (χρειάζεται WP_CLI, αλλιώς SKIP)
  t_bunny_rules.php Edge Rules στο Bunny μέσα στα όριά του (το πολύ 5 μοτίβα ανά συνθήκη) με ψεύτικο API που δίνει
                    HTTP 400 όπως το πραγματικό: χωρισμός, κλείδωμα/Remove, rollback, Monitor only, sync, προεπισκόπηση,
                    κάρτα, wp-login allowed IPs, WP-CLI (με WP_CLI)
  t_metadata.php    3.10: /llms.txt, /ai.txt, /.well-known/*, εικονίδια, service workers ποτέ «Scanner probe» (καταγραφή
                    επιθέσεων, ομάδες του log, ban σαρωτών, εισαγωγή logs του Bunny με mock), σβήσιμο των παλιών γραμμών
  t_311_texts.php   3.11: κείμενα βοήθειας σε κάθε καρτέλα ως διαχειριστής: καμία περιγραφή πάνω από 20 λέξεις (γραμμή
                    βοήθειας πεδίου 14) έξω από το «More», κανένα «Directive (EU)» έξω από το «More», κανένα
                    «Starting value:», «May affect visitors/SEO» ως εικονίδιο (title + κείμενο για αναγνώστες οθόνης)
  browser/          protect.js σε Chromium: δεξί κλικ/αντιγραφή/επιλογή/σύρσιμο ακόμη και με «εχθρικό» script,
                    αντιγραφή με πηγή, .pncp-allow, πεδία φόρμας, ελληνική διάταξη, θόλωμα (npm install && npm test)
                    admin.mjs (3.10): καρτέλες με άλλο όνομα / άγνωστη καρτέλα, ανοιχτά <details> και κύλιση μετά από Save
                    ui311.mjs (3.11): ομάδες καρτελών, accordion της καρτέλας Bots (και με πληκτρολόγιο), «Edit» στις
                    λίστες (και χωρίς JavaScript), ανοιχτά μέρη/λίστες μετά από Save· SHOTS=<φάκελος> για screenshots
                    (σύνδεση admin / admin, ή WP_USER / WP_PASS)
                    blur3125.mjs (3.12.5): «Only visitors who are not signed in»: guest θολώνει (PrintScreen,
                    Ctrl+Shift+S), συνδεδεμένος subscriber όχι, ούτε σε σελίδα από cache (το HTML του guest μέσω
                    page.route, χάρη στο pncp_si), με «Everyone» θολώνουν και οι δύο, editor εξαιρείται όπως πριν

Οι δοκιμές της αναβάθμισης 1.4 → 2.1: εγκατάσταση του zip της 1.4.0 (git show 5c70396), ρυθμίσεις, μετά
αντικατάσταση με την 2.1 και `wp eval 'wp_set_current_user(1); do_action("admin_init");'`.

Γνωστό στο περιβάλλον SQLite (wp-sqlite-db): το DROP TABLE δεν εκτελείται, οπότε μετά το «wp plugin uninstall»
ο πίνακας wp_pncp_log μένει. Σε MySQL / MariaDB το uninstall.php τον σβήνει κανονικά.


ΠΛΗΡΗΣ ΣΤΟΙΒΑ (2.2): FULL=1 / LOAD=1
--------------------------------------
Ubuntu 24.04 (ως root, ΜΟΝΟ σε μηχάνημα δοκιμών):
  apt-get install -y mariadb-server nginx apache2 libapache2-mod-php php8.3-fpm redis-server php-redis
  mariadbd --user=mysql &  ·  redis-server &  ·  php-fpm8.3 -R -D (pool με pm.max_children ≥ 8)
  mysql: CREATE DATABASE wpt; χρήστης wpt/wpt
  WordPress στο /srv/wpt (MariaDB), permalinks /%postname%/, WP_ENVIRONMENT_TYPE=local (application passwords)
  Plugins (επίσημα zip από τα GitHub releases): woocommerce 11.2.1, wp-graphql 2.6.0, wp-super-cache 3.1.1
  (cache_enabled + super_cache_enabled, simple mode), scrapelock (symlink), mu-plugin lib/mu-test-harness.php
  Nginx στη 8080: root /srv/wpt, fastcgi στο PHP-FPM, και μέσα στο server { }:  include /etc/nginx/pncp-rules.conf;
  Apache στη 8081 (mpm_prefork + mod_php + rewrite), AllowOverride All, /srv/wpt/.htaccess.wp = το μπλοκ του WordPress
  Redis drop-in: το includes/object-cache.php του rhubarbgroup/redis-cache 3.0.0 (δίνεται ως REDIS_DROPIN)

  FULL=1 LOAD=1 WP_DIR=/srv/wpt BASE=http://127.0.0.1:8080 NGINX_URL=http://127.0.0.1:8080 \
    APACHE_URL=http://127.0.0.1:8081 REDIS_DROPIN=/path/object-cache.php ./run-all.sh

  t_woocommerce.php   αγορά με τις αυστηρότερες ρυθμίσεις (όρια 3/λεπτό, αποκλεισμός από την 1η παράβαση,
                      μόνο browsers, Emergency Mode), Store API, wc-ajax, webhooks, εικόνες προϊόντων
  t_graphql_rest.php  WPGraphQL και REST με επισκέπτη / application password, παρακάμψεις μεθόδου, RSS / Atom
  t_server_rules.php  nginx -t και πραγματικά αιτήματα σε Nginx / Apache με τους κανόνες της καρτέλας· Cloudflare
  t_cache.php         WP Super Cache: κανόνες server πριν από την cache, 403 / feeds εκτός cache, purge
  t_security.php      CSRF, δικαιώματα, open redirect, XSS / SQLi, header injection, παρακάμψεις feeds, άμεσα αρχεία
  t_load.php          επιβάρυνση, ακρίβεια ορίου (200 ταυτόχρονα), 3000 αιτήματα bot, 1500 ταυτόχρονοι αποκλεισμοί,
                      με και χωρίς Redis (lib/burst.php: curl_multi)
