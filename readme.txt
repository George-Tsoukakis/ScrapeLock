=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhube
Tags: anti-scraping, ai bots, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.2
Requires PHP: 7.4
Stable tag: 2.8.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Server-side anti-scraping: tells real Googlebot from fakes, blocks AI training bots, rate-limits per IP and locks private XML feeds with a token.

== Description ==

Most content protection plugins disable right click in the browser. Scrapers and AI crawlers never use a browser, so they are not affected. ScrapeLock works on the server, where automated copying actually happens, and keeps real visitors, customers and search engines unaffected.

= What makes ScrapeLock different =

* **Real search engines vs. fakes.** Googlebot, Bingbot, Applebot and Yandex are verified against their official IP lists and with reverse + forward DNS. Real crawlers are never limited or blocked; scrapers that only pretend to be Googlebot get a 403.
* **AI training vs. AI search.** Training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended, Bytespider and more) are blocked, while AI search assistants (OAI-SearchBot, ChatGPT-User, PerplexityBot and more) can be allowed with one option, so your site still appears in AI answers with a link.
* **Per-IP limits and temporary blocks.** Separate limits for pages, searches and REST / GraphQL requests. IPs that keep exceeding them are blocked for a while, and an invisible trap link catches bots that ignore robots.txt.
* **Private feeds with a token.** XML feeds for price comparison sites, Google Merchant or an ERP are closed to everyone else. The token goes in a header or the URL, only its hash is stored, and it can be rotated with a grace period.
* **Your text stays out of the API.** Post, page and product text is hidden from the REST API, WPGraphQL and full-text RSS for visitors, which are the routes scrapers use instead of the HTML.
* **Rules for your server and CDN.** Ready-made Nginx, Apache and Cloudflare rules, generated for your own site and settings, so pages served from cache are protected too.
* **Emergency Mode.** One click during a scraping attack: stricter limits for 1 hour to 3 days, then your normal settings return on their own.

Nothing can stop a determined human: whatever a visitor sees has already reached their device. ScrapeLock closes the automated routes and leaves traces: a block log, watermarks, a source link on copied text and a machine-readable rights reservation (TDM).

= Bots and limits =

* Block a list of scrapers and AI training crawlers, with a separate option to allow AI search assistants.
* Verify allowed AI search bots (OpenAI OAI-SearchBot and ChatGPT-User, PerplexityBot, Perplexity-User) with their official IP lists: real ones are never limited, fakes that only use their name are blocked.
* Detect fake Googlebot, Bingbot, Applebot and Yandex with the official IP lists and reverse DNS. Real search engines always pass.
* Invisible bot trap link, disallowed in robots.txt.
* Optional blocking of headless browsers that reveal themselves in their headers, and of scripts that copy a browser's User-Agent but not the headers a real browser sends. A carefully disguised automated browser is not detected this way; the page limits, the human check and the bot trap still apply to it.
* Per-IP limits for pages, searches and REST / GraphQL (IPv6: per /64 network), with temporary blocks after repeated violations.
* A separate limit for "page not found" (404) requests, for scrapers that guess URLs. Missing images, CSS and scripts do not count.
* Optional human check: visitors who have not interacted with the page (scroll, tap, key) get a stricter page limit. No captcha, nothing to click; it works with page caches.
* Optional sitemap limit (WordPress, Rank Math, Yoast and similar sitemaps), never for verified search engines.
* Optional country rules: blocked countries, or a stricter page limit for countries your visitors do not come from. Uses Cloudflare's or Bunny CDN's country header, or the free DB-IP Lite database.
* Optional pre-cache check: the page limit and the blocks also apply to pages served from a page cache such as WP Rocket, through one line that ScrapeLock adds to wp-config.php and removes again.
* Always-blocked lists of IPs / CIDR and referrer domains.
* Hide usernames from visitors: no `?author=N` redirect, no REST user list, no users sitemap.
* Optional early check: a small must-use plugin that stops known bots and blocked IPs before the theme and the other plugins load.
* Content Signals in robots.txt (search yes, AI training no).
* Trusted Proxy support for Cloudflare, Bunny CDN and reverse proxies, so the real IP cannot be spoofed. Cloudflare and Bunny CDN are detected, with a one-click fix when every visitor appears with a CDN address.
* Works with the Cloudflare plugin (APO): blocks and private feeds are never cached at the edge, and the Cloudflare cache is purged when you save the settings.
* Ready-made presets (Balanced, Strict, Maximum) and an Emergency Mode for attacks in progress.
* Block log with a 24-hour summary, top IPs and User-Agents, the pages scrapers target most, and automatic deletion after 1, 7 or 30 days.

= Feeds and API =

* Hide post, page and product text from the REST API and WPGraphQL for visitors.
* RSS with a short excerpt only, or disabled. With full text, an optional "The post … first appeared on …" line links republished copies back to the original.
* Private XML feeds (Skroutz, BestPrice, Google Merchant, ERP) protected with a token in a header or URL. Only the token hash is stored. Token rotation with a grace period and per-feed statistics.
* Optional: hide the REST API map (/wp-json/ and the links to it) from visitors, and turn off pingbacks over XML-RPC. A list shows the REST routes on your site that anyone can call without logging in.
* With "Hide usernames" on, oEmbed shows the site's name and address instead of the author's username.

= Site Health, WP-CLI and AI agents =

* Tools → Site Health warns when protection is off, when every visitor appears with a Cloudflare or Bunny CDN address, when the early or the pre-cache check is on but not running, when Lockdown is off from the server and when updates wait while the site is locked. The Info tab has a ScrapeLock section.
* WP-CLI: `wp scrapelock status`, `block <ip>`, `unblock <ip>`, `blocked`, `emergency on|off|status` and `log [--top]`.
* Abilities API (WordPress 6.9+): `scrapelock/get-summary`, `scrapelock/block-ip`, `scrapelock/unblock-ip` and `scrapelock/emergency-mode`, for administrators only, so an AI agent or MCP client can read the summary and act during an attack. None of them unlocks Lockdown.

= Server rules =

Generated Nginx, Apache and Cloudflare rules for your own site, so cached pages and static files are protected too.

= On the page =

* Block text selection, right click, copy, drag and common shortcuts, or allow copying with the source link appended.
* Printing with the page link at the bottom, or no printing.
* Optional page blur on screenshot shortcuts.
* No framing by other sites (X-Frame-Options, CSP frame-ancestors).
* AI opt-out declaration (TDM): header, meta, `/.well-known/tdmrep.json`, `noai`.

= Images =

* Watermark in a corner, the centre or repeated diagonally, optionally on the full-size image too. The clean original is kept, so the watermark can always be removed.
* Product images are never watermarked by default, because Google Merchant Center and price comparison platforms reject them.
* Batch tool for existing images.

= Lockdown =

* Freeze the whole site with one click and a code from your authenticator app (Google Authenticator, Microsoft Authenticator, Authy and the like). While it is locked, nobody can change the site from wp-admin, the REST API or XML-RPC, not even an administrator or someone who stole a password.
* Frozen: installing, updating, deleting, activating and deactivating plugins and themes; WordPress core and automatic updates; the file editor; new users, role changes, new administrators; staff email and password changes and resets; new application passwords; all settings; posts, pages, products, media and menus.
* Also enforced against code: if another plugin is exploited, it cannot activate plugins, change the site address or the admin email, add an administrator or unlock the lock.
* Visitors and customers are not affected: they browse, order, pay, register as customers and comment as usual.
* Unlock for 15 minutes to 2 hours (it locks again by itself) or until you lock it again. Locking and unlocking are logged and emailed to the site's admin address.
* Lost your phone: ten one-time recovery codes, or `define( 'SCRAPELOCK_UNLOCK', true );` in wp-config.php as a last resort.
* The QR code is drawn in your browser and the secret is stored encrypted with the keys in wp-config.php: it is never sent anywhere.
* Part of ScrapeLock: a Lockdown tab in Settings → ScrapeLock and a Lockdown line under the "Protection" button in the admin bar. While locked, administrators still reach that tab; the other tabs are greyed out.
* A clear warning that there is a single way to unlock (the app, its recovery codes, or the server), a checkbox to confirm the recovery codes are saved before the first lock, and a full report of what is frozen, what keeps working and which accounts on your site it applies to.

Forms, cart, checkout, the WooCommerce Store API and payment webhooks are not affected.

== External services ==

ScrapeLock downloads public lists of IP addresses, only for the features that use them. Each download is a plain GET request for a public file, made from your server by WordPress (User-Agent "ScrapeLock/version"). No data about your site, your content or your visitors is sent, and the request does not include your site address; as with any download, the provider sees your server's IP address. The lists are stored in your database (or, for the country database, in uploads/scrapelock-geo) and checked on your server.

* **Google** crawler IP ranges, to tell real Googlebot from fakes. Downloaded once a day while protection is enabled, from https://developers.google.com/static/search/apis/ipranges/googlebot.json, https://developers.google.com/static/search/apis/ipranges/special-crawlers.json and https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Bing** crawler IP ranges, to tell real Bingbot from fakes. Downloaded once a day while protection is enabled, from https://www.bing.com/toolbox/bingbot.json. Provided by Microsoft Corporation: [Terms of service](https://www.microsoft.com/servicesagreement), [Privacy policy](https://privacy.microsoft.com/privacystatement).
* **Cloudflare** IP ranges, to read the real visitor IP only from Cloudflare. Downloaded once a day only when "Real visitor IP" reads the CF-Connecting-IP or X-Forwarded-For header and "Trust Cloudflare addresses" is on, from https://api.cloudflare.com/client/v4/ips. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN** edge server addresses, to read the real visitor IP and country only from Bunny CDN. Downloaded once a day only when "Trust Bunny CDN addresses" is on and "Real visitor IP" reads the X-Real-IP or X-Forwarded-For header, or country rules are set, from https://bunnycdn.com/api/system/edgeserverlist and https://bunnycdn.com/api/system/edgeserverlist/IPv6. Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).
* **OpenAI** bot IP ranges (OAI-SearchBot, ChatGPT-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://openai.com/searchbot.json and https://openai.com/chatgpt-user.json. Provided by OpenAI: [Terms of use](https://openai.com/policies/terms-of-use/), [Privacy policy](https://openai.com/policies/privacy-policy/).
* **Perplexity** bot IP ranges (PerplexityBot, Perplexity-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://www.perplexity.com/perplexitybot.json and https://www.perplexity.com/perplexity-user.json. Provided by Perplexity AI, Inc.: [Terms of service](https://www.perplexity.ai/hub/legal/terms-of-service), [Privacy policy](https://www.perplexity.ai/hub/legal/privacy-policy).
* **Anthropic** bot IP ranges (Claude-SearchBot, Claude-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://claude.com/crawling/bots.json. Provided by Anthropic PBC: [Terms of service](https://www.anthropic.com/legal/consumer-terms), [Privacy policy](https://www.anthropic.com/legal/privacy).
* **DB-IP Lite** country database, to apply the country rules. Downloaded once a month only when "Download the free country database" is on, from https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz (the current or the previous month). Lookups happen on your server. Licensed under CC BY 4.0 ("IP Geolocation by DB-IP"). Provided by db-ip.com: [Terms of service](https://db-ip.com/tos.php), [Privacy policy](https://db-ip.com/privacy.php), [License](https://creativecommons.org/licenses/by/4.0/).

If a list has not been downloaded, ScrapeLock verifies search engine bots with reverse DNS, and uses a built-in copy of the Cloudflare ranges. AI search bots are not verified until their list has been downloaded. Reverse DNS lookups are made only for requests that claim to be a search engine, through your server's own DNS resolver.

If the official Cloudflare plugin is active, ScrapeLock asks it to purge its cache when you save the ScrapeLock settings. The request is made by the Cloudflare plugin, with the account you connected there; ScrapeLock itself does not contact Cloudflare for this and stores no Cloudflare credentials.

== Installation ==

1. Upload the `scrapelock` folder to `/wp-content/plugins/`, or install the plugin from the Plugins screen.
2. Activate it.
3. Go to Settings → ScrapeLock and choose a preset, or adjust each tab.
4. If your site is behind Cloudflare or another proxy, set "Real visitor IP" first.

Upgrading from "Content Protect" (folder `content-protect`), the former name of this plugin: deactivate the old plugin, activate ScrapeLock. Your settings, tokens and log are kept. If you pasted the old Apache rules, replace the "# BEGIN Content Protect" block with the new "# BEGIN ScrapeLock" block.

== Frequently Asked Questions ==

= Will it block Google or Bing? =

No. Verified search engines are never limited or blocked. Only fake ones that pretend to be Googlebot or Bingbot are blocked.

= Does it work with page cache? =

ScrapeLock tells WP Rocket not to serve cached pages to the bots in its list, so they are always checked. Other pages served from page cache never reach the plugin: a bot that looks like a browser could read them without a limit. Turn on "Pre-cache check" in "Bots and limits" to apply the page limit and the blocks to those pages too, or use the rules in the "Server rules" tab for Nginx, Apache or Cloudflare.

= What does the pre-cache check change on my server? =

It adds two comment lines and one `include` line right after `<?php` at the top of `wp-config.php`, and a folder `wp-content/scrapelock-precheck` for its counters (or APCu, if your server has it). The check runs before the page cache and WordPress, without a database, and stops only always-blocked IPs, temporarily blocked IPs and visitors over the "Pages per minute" limit. Search engines, logged-in users, forms, wp-admin and the REST API are left to the normal check. If `wp-config.php` is not writable, the setting shows the lines to add yourself. Everything is removed when you turn the setting off or deactivate the plugin. Not available on multisite.

= My site is behind Bunny CDN. What should I set? =

If your server already replaces the IP (for example Nginx with `real_ip_header X-Real-IP` and the Bunny addresses in `set_real_ip_from`), keep "REMOTE_ADDR": ScrapeLock tells you it is correct. Otherwise set "Real visitor IP" to X-Real-IP and turn on "Trust Bunny CDN addresses"; ScrapeLock downloads the official list of Bunny edge servers and trusts the header only from them. When every visitor appears with a Bunny address, it shows a button that does this for you.

= Can I allow ChatGPT or Perplexity search but block training? =

Yes. Enable "Allow AI search engines and assistants" in the "Bots and limits" tab. Training crawlers stay blocked. With "Verify AI search bots" on, only requests from the official OpenAI and Perplexity addresses count as their bots; scanners that only copy the name get a 403.

= My site is behind Cloudflare. What should I set? =

In "Bots and limits", set "Real visitor IP" to CF-Connecting-IP and keep "Trust Cloudflare addresses" on. If ScrapeLock sees that every visitor arrives from a Cloudflare address, it shows a button that does this for you. With Nginx, also set `real_ip_header CF-Connecting-IP;` and the Cloudflare ranges with `set_real_ip_from`, so the server rules see the real visitor IP.

= What is the early check? =

An optional setting in "Bots and limits". ScrapeLock writes the small file `wp-content/mu-plugins/scrapelock-early.php`, which runs before the theme and the other plugins and stops blocked IPs and referrers, temporarily blocked IPs and User-Agents from the bot list, with less server load. Search engines, logged-in users, forms and private feeds are left to the normal check. The file is removed when you turn the setting off, deactivate or delete the plugin. If the server does not allow direct file writes, the setting shows a notice and everything else works as before.

= Does it guarantee legal protection of my content? =

No. The TDM declaration is a machine-readable reservation of rights; it does not guarantee legal compliance or stop anyone who ignores it.

= What personal data does it store? =

When a request is blocked, the IP address, User-Agent, page and time are logged. The log is deleted automatically after 1, 7 or 30 days.

With the human check on, visitors who interact with the page get a security cookie, `pncp_hv`, for 7 days. It contains only an expiry time and a signature tied to their IP network and browser; it is not used for tracking or statistics. The country database is a local file: no visitor data is sent to DB-IP.

= Can blocked bots still read robots.txt and llms.txt? =

Yes. robots.txt, llms.txt and llms-full.txt are never blocked, for any bot, so every bot can read the rules it is asked to follow. The server rules in the "Server rules" tab keep them open too.

= What does Lockdown freeze, and what keeps working? =

While locked, users with a frozen role keep only "read": they can log in and open the dashboard, but cannot change anything. Roles that can change plugins, themes, users or settings are always frozen; editors, authors, contributors and shop managers are frozen by default, and you choose the rest on the Lockdown tab. Customers, subscribers and members (for example accounts that post listings through another plugin) are not affected, and neither are visitors, orders, payments, webhooks, cron jobs and comments. Shop staff cannot process orders in wp-admin while the site is locked: unlock it for a while to do so.

= I lost my phone. How do I unlock the site? =

Type one of your recovery codes in the unlock field instead of an app code. If you have none left, add `define( 'SCRAPELOCK_UNLOCK', true );` to wp-config.php (FTP or your hosting panel), go to the Lockdown page, remove the app and connect a new one, then remove that line. The same works if you forget an administrator password while the site is locked, because password resets for staff are frozen too.

= Can someone with access to my server bypass Lockdown? =

Yes. Lockdown protects the site against changes through WordPress (wp-admin, the REST API, XML-RPC and code running inside WordPress). Whoever can edit files or the database on your server controls the site anyway, which is also why the server line is the last-resort unlock.

= Can I unlock Lockdown from WP-CLI or with an AI agent? =

No, on purpose. Lockdown opens only with a code from your authenticator app, a recovery code, or the SCRAPELOCK_UNLOCK line in wp-config.php. The WP-CLI commands and the abilities can block IPs and start Emergency Mode; while the site is locked the abilities can only read the summary.

= Does the human check show a captcha? =

No. A small script waits for the first real interaction (scroll, tap, key or mouse movement), solves a light challenge in the background and receives the cookie. Visitors without it are not blocked: they get the stricter page limit you set (20 pages per minute by default). A determined scraper can repeat these steps, but every IP it uses has to do the work, and plain scripts never do.

== Screenshots ==

1. Block log: 24-hour summary by reason, top IPs and User-Agents, temporarily blocked IPs and the latest events.
2. Bots and limits: AI training crawlers, AI search assistants, fake search engine detection and the bot trap.
3. Feeds and API: token-protected XML feeds with per-feed statistics, and text hidden from REST, GraphQL and RSS.
4. Server rules: ready-made Cloudflare, Nginx and Apache rules generated for your own site.
5. Presets, Emergency Mode and the on-page protection settings.
6. Dashboard widget with the protection status and the last 24 hours.

== Changelog ==

= 2.8.2 =
* The plugin now includes the full text of its license (GPL-2.0) in a LICENSE file. No code changes.

= 2.8.1 =
* Lockdown: while the site is locked, WordPress' bare "Sorry, you are not allowed to…" pages in wp-admin (for example your own profile) are replaced with a clear "The site is locked" page: what is frozen and why, an "Unlock the site" button for administrators, "ask an administrator" for other staff, and a link back to the Dashboard. WordPress' own message stays under "Technical detail". AJAX, REST and XML-RPC answers are unchanged.

= 2.8.0 =
* New: Site Health tests (protection off, every visitor appearing with a Cloudflare or Bunny CDN address, the early or pre-cache check on but not running, Lockdown off from the server, updates waiting while locked) and a ScrapeLock section on the Info tab, without secrets.
* New: WP-CLI commands `wp scrapelock status | block | unblock | blocked | emergency | log`.
* New: Abilities API (WordPress 6.9+): get-summary, block-ip, unblock-ip and emergency-mode, for administrators only. Changes are refused while Lockdown is locked; no ability unlocks it.
* New: optional "Hide the REST API map from visitors" and "Turn off pingbacks", and a list of the REST routes anyone can call.
* "Hide usernames" now also covers oEmbed: the author's name and link are replaced with the site's.
* Fix: "Unblock" in "IPs blocked now" did nothing for IPv6 addresses, which are blocked per /64 network.
* Tested with WordPress 7.2 beta 1.

= 2.7.2 =
* Fix: Lockdown froze every role with any capability beyond "read", so members who create content themselves (for example subscribers who post listings or community posts through another plugin) lost their rights and their password reset while the site was locked. Now only roles that manage the site are frozen: roles that can change plugins, themes, users or settings (always), and by default editorial and shop staff and WordPress' own content roles. Every other role keeps working as usual.
* New: "Who is frozen while locked" on the Lockdown tab: every role with its number of users, ticked if frozen. Saving needs the app code and is possible only while the site is not locked; roles that can take over the site cannot be unticked.
* Role changes while locked are refused only when the old or the new role is frozen, so another plugin can still move a member between member roles.

= 2.7.1 =
* Plugin Check: Lockdown no longer lists the automatic update options among the options it keeps unchanged (it never altered update routines; while locked, automatic updates are already off through the core filters). The lock's database queries are each prepared in one piece.
* Lockdown report: the "also by code" list no longer mentions automatic update lists.

= 2.7.0 =
* New: Lockdown, a tab in Settings → ScrapeLock and a line under the "Protection" button in the admin bar. Freezes every change to the site (plugins, themes, updates, the file editor, users and roles, staff email and password, settings, content) until an administrator unlocks it with a code from an authenticator app (TOTP, RFC 6238). Visitors and customers are not affected.
* Enforced through WordPress capabilities and also against code: protected options (active plugins, theme, site address, admin email, registration, default role, user roles, ScrapeLock's own settings), role changes, staff email and password changes, password resets and new application passwords are refused while locked.
* Each code is accepted once, even when two requests send it at the same moment (the check runs under a short database lock, on the state as it is in the database). New recovery codes stay in the database in plain form for 2 minutes at most, until they are shown.
* Temporary unlock (15 minutes to 2 hours, then it locks again by itself), ten one-time recovery codes, the SCRAPELOCK_UNLOCK constant as a last resort, 5 wrong codes per 15 minutes, a log of the last 30 events and an email to the admin address on every unlock.
* The secret is encrypted with the keys in wp-config.php; the QR code is drawn in the browser with the bundled qrcode-generator 1.4.4 (MIT, Kazuhiko Arase).
* The Lockdown tab warns that there is a single way to unlock, asks to confirm the recovery codes are saved before the first lock, and shows a full report: what is frozen, what keeps working, and the staff accounts, customers, plugins and theme on your site it applies to.

= 2.6.8 =
* Hardening: downloaded IP lists (Google, Bing, Cloudflare, Bunny, AI bots) are sanity-checked before use. An absurdly broad entry such as 0.0.0.0/0, ::/0 or any prefix shorter than /8 (IPv4) / /16 (IPv6) is dropped, so a bad or hostile source cannot make every IP an official crawler, a trusted proxy or a blocked one.
* Privacy (GDPR): the feed statistics now store the last client IP anonymised (IPv4 last octet zeroed, IPv6 last 80 bits), instead of keeping a full IP indefinitely in an option.
* Hardening: the one-time plaintext feed token is now kept for 2 minutes instead of 10 while it waits to be shown once, keeping it in the database as briefly as possible.
* Reliability: the strike counter that leads to a temporary ban is now atomic when a persistent object cache is present, so two simultaneous violations can no longer lose a strike.
* Cleanup on uninstall: the country-database folder is removed (not just its files), on multisite it is cleaned per site, and the per-attachment watermark marker (_pncp_wm) is deleted. The clean image originals and the pointer to them are kept on purpose.
* Fix: the "Feeds and token" link in the legacy-token notice pointed to a tab that does not exist; it now opens the Feeds and API tab.

= 2.6.7 =
* Fix: a blocked bot (e.g. a training crawler such as ClaudeBot) could still receive a 403 on /robots.txt in some setups. robots.txt, llms.txt and the TDM opt-out are now recognised directly from the raw request path, independent of the home-path/subfolder handling, and the main check has a safety net so no path can return a 403 for them. Every bot can always read the rules it is asked to follow.
* Change: the "CDN shared secret" field is now a single-line password input instead of a plain multi-line box.

= 2.6.6 =
* Security (M4): optional CDN shared secret. A multi-tenant CDN (Bunny, Cloudflare) shares its edge IPs, so by default anyone could point their own CDN zone at your origin and spoof the real-IP header. Set a secret under "Real visitor IP" and have your CDN send it as the header X-ScrapeLock-CDN; the CDN's real-IP header is then trusted only when it matches. Empty = unchanged behaviour.
* Security (M6): the WooCommerce Store API product catalogue (/wc/store/.../products) now counts toward the REST limit; only cart, checkout and batch stay exempt. Product descriptions are also stripped from cart line items, so the catalogue text cannot be read via "add to cart, then read the cart".
* Security (M8): the bot trap no longer bans allowed bots (link-preview, price-comparison, monitoring) or allowed AI search bots, even if another page embeds the trap URL; an old browser with no Sec-Fetch headers is treated as a bot only after a third hit, and the counter is per /64.
* Security (M10): when a crawler cannot be verified because the DNS budget is used up or DNS failed, the request is no longer blocked as a fake crawler (it falls through to the normal limits), so a flood of fake "Applebot" requests can no longer get the real Applebot or YandexBot a 403. Each crawler family now has its own DNS budget.
* Performance (M9): the pncp_version and pncp_db_version options are autoloaded, removing one database query per request on sites without a persistent object cache.

= 2.6.5 =
* Security: temporary bans are now kept per IPv6 /64 (like the limits and strikes), so a client can no longer dodge a ban by switching to another address in the same /64. IPv4 is unchanged.
* Security: the human-check endpoint now limits challenge requests and answer attempts per IP (per /64 on IPv6) and makes each challenge single-use, so one solved proof of work cannot be replayed and the endpoint cannot be hammered.
* Security: a User-Agent-only entry in the "Always allowed" list no longer skips country blocking (anyone can copy such a User-Agent). Pin an entry to its IP range (UA@1.2.3.0/24) to keep it fully exempt; verified AI search bots stay exempt.
* /.well-known/tdmrep.json is now always readable (normal check, early check, pre-cache check and the generated Nginx/Apache/Cloudflare rules), like robots.txt, so the AI/TDM bots meant to read your opt-out are never blocked from it. If you installed the server rules, copy them again.

= 2.6.4 =
* Security: a request could skip the per-minute limits (and so the strikes and temporary bans) by sending a "prefetch" header or by using POST. A prefetch is now trusted only with the browser's own Sec-Fetch-Dest signal, and an anonymous POST counts like a view; the pre-cache check still applies the always-blocked list and bans to every request.
* Security: the pre-cache events file is written with its "<?php exit;" guard and first line under one lock, and logged values can no longer contain <, > or ?, so a log file can never become executable code.
* Security: wp-config.php is now updated atomically (temporary file + rename) with a concurrent-change check, is never edited during a front-end request (it waits for wp-admin), and is left untouched when the file begins with declare() or namespace.

= 2.6.3 =
* Log: "Pages" now lists only addresses that exist on the site (posts, pages, products, archives…). Random strings and guesses get their own group, "Addresses that do not exist", next to "Files and admin paths".
* Log: the "Block permanently" button is also in "Top IPs" and in "Latest events".
* Log: "Persistent IPs" also lists IPs with at least 100 blocked requests in 7 days, even if they never got a temporary block (for example a User-Agent in the bot list), with their main reason.
* Log: pages that other plugins show (for example a community under /hub/space/) count as "Pages", found from the WordPress rewrite rules or from the new "Content addresses" setting.
* Log: no "Block permanently" for addresses in an official list (Google, Bing, OpenAI, Perplexity, Anthropic, Cloudflare, Bunny CDN): blocking them would also stop that company's search bots, or every visitor behind the CDN.
* Official IP lists that the settings need but were never downloaded (for example Anthropic after an update) are downloaded right away, not with the daily refresh. "Refresh lists now" button.
* robots.txt: the trap and Content-Signal go into the existing "User-agent: *" group instead of separate groups.
* Nginx rules: the names carry the site's suffix, so several WordPress sites can use their rules on the same Nginx. If you installed the 2.6.2 rules, copy both parts again.
* Nginx rules: the "Server rules" tab shows whether they are installed and up to date with the current settings, and where each part goes on the common servers and panels.

= 2.6.2 =
* robots.txt, llms.txt and llms-full.txt are never blocked, for any bot, in WordPress, the early check, the pre-cache check and the Nginx / Apache / Cloudflare rules.
* With "Allow AI search engines and assistants", the AI search bots are allowed at every level: they skip the stricter human-check limit, the Cloudflare rule blocks only the "AI Crawler" category, and Claude-SearchBot / Claude-User are verified with Anthropic's official IP list.
* New: the server rules also stop fake browsers (Nginx, Apache), so scanners asking for files that never reach WordPress are blocked too. Search engines are never affected.
* Log: "Block permanently" button, a list of IPs blocked again and again, fake / unverified marks on the top User-Agents, the number of different User-Agents of a grouped event, and better sorting of pages and scanner paths. Limit reasons are named after their settings.
* Fix: with AI search allowed, the Cloudflare bot rule could exceed Cloudflare's 4096-character limit; long lists are now split into several rules.

= 2.6.1 =
* The notices for Emergency Mode and the insecure 1.4 proxy setting now appear only on the Dashboard and the ScrapeLock settings page, not on every admin screen.
* Readme: every external service is listed with the exact addresses it is downloaded from, and the contributor name is corrected.

= 2.6.0 =
* New, optional: pre-cache check. One line at the top of wp-config.php applies the page limit, temporary blocks and always-blocked IPs also to pages served from a page cache such as WP Rocket, before the cache and WordPress load. Off until you turn it on; removed when turned off or deactivated.
* New: Bunny CDN support. "Trust Bunny CDN addresses" reads X-Real-IP / X-Forwarded-For only from Bunny's official edge servers, with detection and a one-click fix, and the country from Bunny's header.
* New, optional: human check. Visitors get a security cookie after their first real interaction; those without it get a stricter page limit. No captcha, works with page cache.
* New: a requests-per-minute limit for sitemaps (WordPress, Rank Math, Yoast). Verified search engines are never limited.
* New, optional: country rules (blocked countries, or a stricter limit), with Cloudflare's or Bunny's country header or the free DB-IP Lite database.
* New: the Log shows the pages and files that are blocked most, for 24 hours and 7 days.
* Redesigned settings page: status overview, cards, switches, section links and a save bar that stays visible.
* On existing sites every new option stays off after the upgrade.

= 2.5.0 =
* New: verify AI search bots (OpenAI OAI-SearchBot and ChatGPT-User, PerplexityBot, Perplexity-User) with their official IP lists. With AI search allowed, the real ones are never limited or blocked, and requests that only use their name get a 403. Off on existing sites until you turn it on.
* New, optional: block headless browsers (Puppeteer, Playwright, Selenium) and scripts that copy a browser's User-Agent without the headers a real browser sends. Off by default.
* The Cloudflare IP list now says when the current "Real visitor IP" setting does not use it.
* Includes the 2.4.1 fix for WP Rocket.

= 2.4.1 =
* Fix: on sites with WP Rocket, the first request after upgrading from 2.3.x could end with a critical error ("Call to undefined function get_rocket_cache_reject_uri()"). The cache purge now waits until all plugins have loaded.

= 2.4.0 =
* New, all off on existing sites until you turn them on: a "page not found" (404) limit per IP, always-blocked IP / CIDR and referrer lists, hiding usernames from visitors (`?author=N`, REST user list, users sitemap), Content Signals in robots.txt and a "first appeared on" source line in full-text feeds.
* Optional early check: a small must-use plugin that stops listed bots and blocked IPs before the theme and other plugins load. Always off until you enable it; removed when turned off, deactivated or deleted.
* Cloudflare: blocks, the bot trap and private feeds are never cached at the edge (APO), the Cloudflare plugin cache is purged when you save the settings, and a one-click fix appears when every visitor shows a Cloudflare address.

= 2.3.0 =
* Safer defaults for new installs: page, search and REST / GraphQL limits are on from the start (60 / 20 / 60 per minute). Existing sites keep their settings.
* DevTools shortcut blocking is off by default (it stops no bot); it is part of the Strict and Maximum presets.
* Security: an always-allowed User-Agent can be tied to IPs, e.g. `Skroutz@203.0.113.0/24`, so a fake User-Agent no longer bypasses the checks. Entries without `@` work as before.

= 2.2.4 =
* readme.txt: Contributors set to the plugin author's WordPress.org username. No code changes.

= 2.2.3 =
* The hidden bot-trap link is hidden with an enqueued stylesheet (`wp_add_inline_style()`) instead of an inline style attribute. No change in behaviour.

= 2.2.2 =
* New name: ScrapeLock (formerly Content Protect). Folder and main file `scrapelock/scrapelock.php`, text domain `scrapelock`. Settings, tokens and log are kept.
* Security: rate limits and violations are counted per /64 network for IPv6, so a scraper cannot bypass them by changing address. Filter `pncp_ipv6_prefix`.
* Security: a real Applebot / YandexBot is no longer banned when its DNS check cannot finish (DNS budget used up or reverse DNS failed).
* The feed token header is now `X-ScrapeLock-Token`. The old `X-Content-Protect-Token` header is still accepted.

= 2.2.1 =
* Security: the 1.x feed token is no longer kept in plain text during migration.
* New option to allow AI search assistants while training crawlers stay blocked.
