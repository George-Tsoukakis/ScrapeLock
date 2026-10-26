=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhube
Tags: anti-scraping, ai bots, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.2
Requires PHP: 7.4
Stable tag: 3.3.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Server-side anti-scraping: tells real Googlebot from fakes, blocks AI training bots, rate-limits per IP and locks private XML feeds with a token.

== Description ==

Most content protection plugins disable right click in the browser. Scrapers and AI crawlers never use a browser, so they are not affected. ScrapeLock works on the server, where automated copying actually happens, and keeps real visitors, customers and search engines unaffected.

= What makes ScrapeLock different =

* **Real search engines vs. fakes.** Googlebot, Bingbot, Applebot and Yandex are verified against their official IP lists and with reverse + forward DNS. Real crawlers are never limited or blocked; scrapers that only pretend to be Googlebot get a 403.
* **AI training vs. AI search.** Training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended, Bytespider and more) are blocked, while AI search assistants (OAI-SearchBot, ChatGPT-User, PerplexityBot and more) can be allowed with one option, so your site still appears in AI answers with a link.
* **Per-IP limits and temporary blocks.** Separate limits for pages, searches and REST / GraphQL requests. IPs that keep exceeding them are blocked for a while, optionally also at your CDN, and an invisible trap link catches bots that ignore robots.txt.
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
* Optional blocking at the CDN: temporary blocks are also applied by Cloudflare or Bunny CDN, so a persistent scraper never reaches your server. Optionally, only requests that come through the CDN are answered.
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
* Hide the versions of WordPress, PHP and the plugins: no generator tags, no X-Powered-By, a code instead of "?ver=7.1.3", and readme / changelog files refused by the server rules.
* Optional: excerpts instead of the full text on lists of articles, an IPv6 limit per /56 network, and blocking of web archives (Wayback Machine).
* With "Hide usernames" on, oEmbed shows the site's name and address instead of the author's username.

= Site Health, WP-CLI and AI agents =

* Tools → Site Health warns about settings that do not work as intended (protection off, every visitor behind a CDN address, a check that is on but not running, Lockdown off from the server) and has a ScrapeLock section in the Info tab.
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
* File integrity: when you lock, ScrapeLock keeps a fingerprint of every PHP, .htaccess and .user.ini file (WordPress, plugins, themes, uploads, wp-config.php) and checks it every hour. A new or changed file while locked (usually a backdoor uploaded through a vulnerable plugin) is emailed to you, logged and shown in Site Health. WordPress and the plugins from WordPress.org are also compared with their official checksums, which finds changes made before you locked. Optional quarantine deactivates the affected plugin and renames new PHP files in the uploads folder.
* Sealed: the lock is signed with the keys in wp-config.php and copied into a must-use plugin, so SQL injection in another plugin cannot unlock the site. Settings changed in the database are put back.
* Unlock for 15 minutes to 2 hours, for yourself only (it locks again by itself) or until you lock it again. Locking and unlocking are logged and emailed to the site's admin address.
* Lost your phone: ten one-time recovery codes, or `define( 'SCRAPELOCK_UNLOCK', true );` in wp-config.php as a last resort.
* The QR code is drawn in your browser and the secret is stored encrypted with the keys in wp-config.php: it is never sent anywhere.
* A Lockdown tab in Settings → ScrapeLock, with a full report of what is frozen, what keeps working and which accounts it applies to.

Forms, cart, checkout, the WooCommerce Store API and payment webhooks are not affected.

== External services ==

ScrapeLock downloads public lists of IP addresses, only for the features that use them. Each download is a plain GET request for a public file, made from your server by WordPress (User-Agent "ScrapeLock/version"). No data about your site, your content or your visitors is sent, and the request does not include your site address; as with any download, the provider sees your server's IP address. The lists are stored in your database (or, for the country database, in uploads/scrapelock-geo) and checked on your server. They are data, not code or assets: no script, style, font or image is ever loaded from these addresses.

* **Google** crawler IP ranges, to tell real Googlebot from fakes. Downloaded once a day while protection is enabled, from https://developers.google.com/static/search/apis/ipranges/googlebot.json, https://developers.google.com/static/search/apis/ipranges/special-crawlers.json and https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Bing** crawler IP ranges, to tell real Bingbot from fakes. Downloaded once a day while protection is enabled, from https://www.bing.com/toolbox/bingbot.json. Provided by Microsoft Corporation: [Terms of service](https://www.microsoft.com/servicesagreement), [Privacy policy](https://privacy.microsoft.com/privacystatement).
* **Cloudflare** IP ranges, to read the real visitor IP only from Cloudflare. Downloaded once a day only when "Real visitor IP" reads the CF-Connecting-IP or X-Forwarded-For header and "Trust Cloudflare addresses" is on, from https://api.cloudflare.com/client/v4/ips. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN** edge server addresses, to read the real visitor IP and country only from Bunny CDN. Downloaded once a day only when "Trust Bunny CDN addresses" is on and "Real visitor IP" reads the X-Real-IP or X-Forwarded-For header, or country rules are set, from https://bunnycdn.com/api/system/edgeserverlist and https://bunnycdn.com/api/system/edgeserverlist/IPv6. Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).
* **OpenAI** bot IP ranges (OAI-SearchBot, ChatGPT-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://openai.com/searchbot.json and https://openai.com/chatgpt-user.json. Provided by OpenAI: [Terms of use](https://openai.com/policies/terms-of-use/), [Privacy policy](https://openai.com/policies/privacy-policy/).
* **Perplexity** bot IP ranges (PerplexityBot, Perplexity-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://www.perplexity.com/perplexitybot.json and https://www.perplexity.com/perplexity-user.json. Provided by Perplexity AI, Inc.: [Terms of service](https://www.perplexity.ai/hub/legal/terms-of-service), [Privacy policy](https://www.perplexity.ai/hub/legal/privacy-policy).
* **Anthropic** bot IP ranges (Claude-SearchBot, Claude-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://claude.com/crawling/bots.json. Provided by Anthropic PBC: [Terms of service](https://www.anthropic.com/legal/consumer-terms), [Privacy policy](https://www.anthropic.com/legal/privacy).
* **DB-IP Lite** country database, to apply the country rules. Downloaded once a month only when "Download the free country database" is on, from https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz (the current or the previous month). Lookups happen on your server. Licensed under CC BY 4.0 ("IP Geolocation by DB-IP"). Provided by db-ip.com: [Terms of service](https://db-ip.com/tos.php), [Privacy policy](https://db-ip.com/privacy.php), [License](https://creativecommons.org/licenses/by/4.0/).

The five data center lists below are used only for the "Data center limit" (Bots and limits), a stricter page limit for visitors that come from cloud servers rather than from home or mobile connections. Each one is downloaded once a day only while protection is enabled and "Data center limit" is above 0 (set it to 0 to turn the lists off). They are JSON or CSV data files fetched by your server with wp_remote_get(); nothing from these hosts is ever loaded in your visitors' browsers.

* **Amazon Web Services** IP ranges (only the EC2 servers are used), from https://ip-ranges.amazonaws.com/ip-ranges.json. Provided by Amazon Web Services, Inc.: [Terms](https://aws.amazon.com/service-terms/), [Privacy policy](https://aws.amazon.com/privacy/).
* **Google Cloud** IP ranges, from https://www.gstatic.com/ipranges/cloud.json, the address where Google publishes the list. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Oracle Cloud** IP ranges, from https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json. Provided by Oracle Corporation: [Terms of use](https://www.oracle.com/legal/terms/), [Privacy policy](https://www.oracle.com/legal/privacy/).
* **DigitalOcean** IP ranges, from https://digitalocean.com/geo/google.csv. Provided by DigitalOcean, LLC: [Terms of service](https://www.digitalocean.com/legal/terms-of-service-agreement), [Privacy policy](https://www.digitalocean.com/legal/privacy-policy).
* **Akamai Cloud (Linode)** IP ranges, from https://geoip.linode.com/. Provided by Akamai Technologies, Inc.: [Terms of service](https://www.akamai.com/legal/msa), [Privacy policy](https://www.akamai.com/legal/privacy-statement).

Lockdown's file check also compares WordPress and the plugins hosted on WordPress.org with their official checksums. This happens when you lock the site or press "Check now" on the Lockdown tab, and then at most once a day while the site stays locked, through the same WordPress.org services WordPress itself uses for updates. The requests contain the WordPress version and language (https://api.wordpress.org/core/checksums/1.0/) and, for each installed plugin, its slug and version (https://downloads.wordpress.org/plugin-checksums/SLUG/VERSION.json); no other data about your site, your content or your visitors is sent. Provided by WordPress.org: [Privacy policy](https://wordpress.org/about/privacy/).

Optional blocking at the CDN (off by default) uses the API of the CDN you choose, with your token. It sends only the IPs ScrapeLock blocks temporarily (IPv4, IPv6 or an IPv6 /64), each with the reason and end time, and removes them when the block ends. Saving the setting makes one read-only request to check the token.

* **Cloudflare API** (IP Access rules of your zone), only when the CDN is set to Cloudflare: https://api.cloudflare.com/client/v4/zones/ZONE_ID/firewall/access_rules/rules. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN API** (blocked IPs of your Pull Zone), only when the CDN is set to Bunny CDN: https://api.bunny.net/pullzone/PULL_ZONE_ID (addBlockedIp, removeBlockedIp, and reading the zone's list of blocked IPs). Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).

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

It adds two comment lines and one `include` line right after `<?php` at the top of `wp-config.php`. The line loads the check from the plugin's own folder; its settings, counters and events are plain data files (no PHP) in a protected folder with a random name inside the uploads directory, `uploads/scrapelock/` (counters go to APCu instead, if your server has it). The check runs before the page cache and WordPress, without a database, and stops only always-blocked IPs, temporarily blocked IPs and visitors over the "Pages per minute" limit. Search engines, logged-in users, forms, wp-admin and the REST API are left to the normal check. If `wp-config.php` is not writable, the setting shows the lines to add yourself. Everything is removed when you turn the setting off or deactivate the plugin. Not available on multisite.

= My site is behind Bunny CDN. What should I set? =

If your server already replaces the IP (for example Nginx with `real_ip_header X-Real-IP` and the Bunny addresses in `set_real_ip_from`), keep "REMOTE_ADDR": ScrapeLock tells you it is correct. Otherwise set "Real visitor IP" to X-Real-IP and turn on "Trust Bunny CDN addresses"; ScrapeLock downloads the official list of Bunny edge servers and trusts the header only from them. When every visitor appears with a Bunny address, it shows a button that does this for you.

= Can I allow ChatGPT or Perplexity search but block training? =

Yes. Enable "Allow AI search engines and assistants" in the "Bots and limits" tab. Training crawlers stay blocked. With "Verify AI search bots" on, only requests from the official OpenAI and Perplexity addresses count as their bots; scanners that only copy the name get a 403.

= My site is behind Cloudflare. What should I set? =

In "Bots and limits", set "Real visitor IP" to CF-Connecting-IP and keep "Trust Cloudflare addresses" on. If ScrapeLock sees that every visitor arrives from a Cloudflare address, it shows a button that does this for you. With Nginx, also set `real_ip_header CF-Connecting-IP;` and the Cloudflare ranges with `set_real_ip_from`, so the server rules see the real visitor IP.

= Can ScrapeLock block scrapers at Cloudflare or Bunny CDN? =

Yes, since 3.1. In "Bots and limits" → "Blocking at the CDN", choose Cloudflare or Bunny CDN and enter the zone ID and a token. For Cloudflare, create an API token with the single permission Zone → Firewall Services → Edit, for this zone only; for Bunny CDN, use your account's API key. You can put the token in `wp-config.php` instead (`define( 'SCRAPELOCK_EDGE_TOKEN', '…' );`), so it is not stored in the database. From then on, every IP ScrapeLock blocks temporarily is also blocked at the CDN within a minute or two, and the block is removed there when it ends. The site must be served through that CDN (for Cloudflare: proxied, orange cloud). Rules you made yourself are never changed. Administrators' IPs from the last 30 days, search engines, AI search services and the CDN's own addresses are never blocked there. Bunny CDN blocks single addresses only, so a blocked IPv6 network stays blocked by ScrapeLock itself. Turning the setting off or deactivating the plugin removes the blocks ScrapeLock made.

= Can someone go around my CDN? =

If they find your server's own address, yes: then nothing the CDN blocks applies. Since 3.2, "Only through the CDN" (Bots and limits → Real visitor IP) refuses every request that does not bring a secret your CDN adds as the header `X-ScrapeLock-CDN` (Bunny CDN: an Edge Rule "Set Request Header"; Cloudflare: a Transform Rule "Modify Request Header"). It can only be turned on from a request that brings the secret, so a missing rule cannot lock you out. If the CDN ever stops sending it, add `define( 'SCRAPELOCK_CDN_ONLY', false );` to wp-config.php.

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

Yes. Lockdown protects the site against changes through WordPress (wp-admin, the REST API, XML-RPC and code running inside WordPress). Someone who can only write to the database (for example through SQL injection in another plugin) cannot unlock it: the lock is signed with the keys in wp-config.php and copied into a must-use plugin file, changed protected settings are put back, and new administrators cannot sign in. Whoever can edit files on your server controls the site anyway, which is also why the server line is the last-resort unlock. The file integrity check is there for that case: a file written behind WordPress' back is found within the hour and emailed to you. Code that already runs on the server could also stop ScrapeLock itself, so "No PHP in the uploads folder" (a server rule) is what stops most backdoors from running in the first place.

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

= 3.3.1 =
* Pre-cache check: its data (settings, counters, events) now lives in a protected folder with a random name inside the uploads directory, uploads/scrapelock/, as plain data files: no PHP file is generated any more. The line in wp-config.php loads the check from the plugin's own folder. The old wp-content/scrapelock-precheck folder is removed on upgrade and its events are moved into the log; the check resumes as soon as an administrator opens wp-admin.
* Pre-cache check: only a hash of the CDN shared secret is written to its settings file.
* Lockdown: the "site is locked" page loads its styles from a registered stylesheet (assets/css/locked.css) instead of an inline style block.
* File integrity: the folders that are read are resolved in one place, with WordPress' functions for uploads, themes and wp-config.php.
* The country database and the folder of clean image originals get an empty index.html instead of an index.php: ScrapeLock writes no PHP file in the uploads folder.
* readme: each data center list is described as its own external service, and the Akamai Cloud (Linode) terms link points to the current page.

= 3.3.0 =
* New: Lockdown seal. The lock state and the file fingerprint are signed (HMAC-SHA256) with a key derived from the keys in wp-config.php, which are not in the database. A must-use plugin, scrapelock-lockdown-guard.php, holds a signed copy of the lock while the site is locked and keeps ScrapeLock active if it is removed from the active plugins in the database. Deleting or changing the lock in the database, or putting back an older copy, leaves the site locked, and the unlock page refuses to work with forged data. The guard is removed when you unlock fully or deactivate ScrapeLock.
* New: when you lock, the protected settings (active plugins, theme, site address, admin email, registration, default role, user roles, uploads folder, search engine visibility, ScrapeLock's own settings) and the list of administrators are saved, signed. A protected setting changed directly in the database is put back on the next request; an account given administrator rights that way cannot sign in while the site is locked and is reported by the hourly check. Each kind of finding is logged and emailed at most once an hour.
* New: a temporary unlock gives the rights back only to the administrator who unlocked. Other staff stay frozen until the site is locked again or unlocked fully.
* New: protected while locked: the uploads folder and its address, and "Discourage search engines".
* Integrity: a fingerprint that was changed, deleted or replaced with an older one in the database is reported as tampered (critical in Site Health) and is never silently replaced while locked.
* Site Health: a recommendation when AUTH_KEY / AUTH_SALT are not set in wp-config.php (the signatures rely on them), when the guard is missing while locked, or when the hourly file check has not run for three hours.
* Upgrade: data saved by earlier versions is signed on the upgrade to 3.3.0; changing the keys in wp-config.php is reported but never locks you out on its own.

= 3.2.0 =
* New: "Only through the CDN" (Bots and limits → Real visitor IP). Requests without the CDN shared secret in the header X-ScrapeLock-CDN, which went straight to the server around the CDN, get a 403, also pages from the page cache when the pre-cache check is on. It can only be turned on from a request that brings the secret; the server itself, WordPress's cron and WP-CLI are not affected; `define( 'SCRAPELOCK_CDN_ONLY', false );` in wp-config.php turns it off. Off by default. New log reason "Not through the CDN".
* New: "Test blocking at the CDN" button. Blocks an address reserved for documentation (203.0.113.x) at the CDN, checks that the CDN lists it and removes it again, so the setup can be checked without changing any limit or blocking a visitor.
* Blocking at the CDN (3.1) has now been confirmed on a live site with Bunny CDN: blocks are added within a minute or two and removed when the block is lifted.
* Site Health: "Only through the CDN" in the ScrapeLock section of the Info tab.

= 3.1.0 =
* New: blocking at the CDN (Bots and limits tab, "Blocking at the CDN"). The IPs ScrapeLock blocks temporarily are also blocked by Cloudflare (IP Access rules) or Bunny CDN (blocked IPs of the Pull Zone), with your own account, so a scraper that keeps going is stopped at the CDN before its requests reach your server. Blocks are added and removed in the background by WordPress's cron (at most 25 API calls per run, the newest 500 blocks, filter `pncp_edge_max`), never while a visitor waits, and removed when the temporary block ends, when you turn the setting off or change the zone, and when the plugin is deactivated. Rules you made yourself at the CDN are never changed. Never blocked at the CDN: the IPs administrators used in wp-admin in the last 30 days (a block at the CDN also covers wp-admin), search engines, AI search services and the CDN's own addresses. Paused while "Trust every request" is on, since anyone could then get any address blocked. The token is tested when saved, never shown again, can be kept in wp-config.php (SCRAPELOCK_EDGE_TOKEN) and cannot be changed while the site is locked. Off by default.
* Site Health: the state of blocking at the CDN in the ScrapeLock section of the Info tab.

= 3.0.0 =
* New: Lockdown file integrity. When you lock the site, ScrapeLock keeps a fingerprint (SHA-256) of every PHP, .htaccess and .user.ini file in WordPress, the plugins, the themes, the uploads folder and wp-config.php, and checks it every hour while the site stays locked. Nobody can install or update anything while locked, so a new or changed file means something wrote it by itself, usually a backdoor uploaded through a vulnerable plugin. You get one email per new finding, an entry in the lockdown log, a notice in wp-admin and a critical Site Health result. After a temporary unlock (when updates are allowed) a new fingerprint is taken instead of an alarm. Caches and the updater's folders are left out (filter `pncp_integrity_exclude`).
* New: WordPress and the plugins hosted on WordPress.org are compared once a day with their official checksums (the lists WP-CLI's verify-checksums uses), which also finds a change made before the site was locked. Premium and custom plugins are listed as "cannot be compared".
* New: optional Quarantine (Lockdown tab, saved with the app code): deactivates a plugin whose files changed while locked and renames new PHP files in the uploads folder so they no longer run. Nothing is deleted; ScrapeLock itself is never deactivated.
* New: automatic Emergency Mode (Bots and limits tab, Limits). The limits per IP cannot see a scraper spread over hundreds of IPs; the whole site can. ScrapeLock learns how many pages per minute the site usually serves and, when that is exceeded five times over for 3 minutes in a row (never below a minimum, 300 by default), starts Emergency Mode for 1 hour and emails you. Verified search engines and exempt staff are not counted; an attack does not raise the learned average. On for new installs, off on existing sites.
* New: stricter page limit for data centers (Bots and limits tab, Limits): visitors from the published addresses of AWS (servers only, not CloudFront), Google Cloud, Oracle Cloud, DigitalOcean and Akamai / Linode get a lower limit (15 pages per minute for new installs, 5 in Emergency Mode). The lists are downloaded once a day and indexed, so the check costs well under a millisecond. Always-allowed User-Agents and verified search engines are not affected. Off on existing sites.
* New: "No PHP in the uploads folder" (Feeds and API tab): written into the .htaccess of the uploads folder for Apache, between ScrapeLock's own markers, and added to the Nginx and Apache rules. On for new installs, off on existing sites.
* Tests: the Lockdown test suite stops at once when the test server does not answer, instead of changing the test site for real.

= 2.9.0 =
* New: "Hide the versions of WordPress, PHP and the plugins" (Feeds and API tab). Removes the generator tags (page head, feeds, and plugins that use them, e.g. WooCommerce) and the X-Powered-By header, and replaces "?ver=7.1.3" on the site's own CSS and JS with a code tied to the site that changes with the version, so caches keep working. The Nginx and Apache rules now refuse readme.html, license.txt and the readme / changelog files of plugins and themes (404). On for new installs.
* New: "Lists of articles: an excerpt and a link instead of the full text". Many themes print every article in full on the home page, categories, archives and search, so one request gave a scraper ten articles. Article pages, feeds and exempt staff are not affected; password-protected articles never show their text. Off by default.
* New: "IPv6: also limit the whole /56 network". A new /64 for every request no longer gets past the page limit: the /56 is limited to four times the page limit, with a 429 and no block. Off by default (mobile networks may share a /56).
* New: "Block web archives (Wayback Machine)": blocks ia_archiver, archive.org_bot and heritrix and asks them in robots.txt. Off by default.
* Emergency Mode now also turns on the excerpts in lists and the IPv6 /56 limit.
* Site Health: the new settings appear in the ScrapeLock section of the Info tab.
* Existing sites: the new settings stay off until you turn them on.

= 2.8.3 =
* Security fix: the per-minute page limit could be bypassed from a single IP, with no strike and no ban, by sending the browser's prefetch headers (Sec-Fetch-Dest with Sec-Purpose or Purpose: prefetch) or by a POST with a cookie named wordpress_logged_in_… or woocommerce_… Any script can send these. Now every page request counts, in the normal check and in the pre-cache check. A prefetch has a limit of its own, three times the page limit and never a strike, so speed plugins that prefetch links (Flying Pages, instant.page, speculative loading) do not stop real visitors. WooCommerce AJAX, cart and checkout still do not count, and logged-in staff are still exempt by their role.
* More bots blocked: more than 100 AI crawlers and agents (DeepSeek, Grok, Qwen, Doubao, ERNIE, Mistral, meta-webindexer, NotebookLM, Gemini Deep Research and others, from ai.robots.txt) are now built into the plugin, blocked by name and listed in robots.txt. The list is updated with each version and does not take room in your own bot list. A few that act for your visitors or tools (e.g. PetalBot, AmazonBuyForMe) are only asked in robots.txt.
* The bot list now also blocks the default User-Agent of HTTP libraries that passed before: Node.js fetch, Ruby, Java HttpClient, Apache HttpClient, Guzzle, Bun, Deno, Dart, Perl HTTP::Tiny, PowerShell, Faraday and Mechanize. Added to existing lists on update; your own lines stay. A line that starts with "=" must be the whole User-Agent (e.g. "=node").
* Fix: addresses with non-Latin characters (e.g. Greek) were logged without them (/άρθρο-8/ as /-8/), so the "pages scrapers were after" report missed them. They are now logged as sent and shown readable.

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
