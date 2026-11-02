=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhube
Tags: anti-scraping, ai bots, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.2
Requires PHP: 7.4
Stable tag: 3.4.1
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
* **Emergency Mode.** One click during a scraping attack: stricter limits for 1 hour to 3 days, then your normal settings return on their own. When traffic suddenly jumps, ScrapeLock emails you with a one-click button to start it (or, if you choose, starts it for 1 hour on its own).
* **Monitor only.** Try every setting without blocking anyone: requests that would be refused are let through and logged as "Would block". New installs start this way for their first 7 days, then blocking starts on its own.

Nothing can stop a determined human: whatever a visitor sees has already reached their device. ScrapeLock closes the automated routes and leaves traces: a block log, watermarks, a source link on copied text and a machine-readable rights reservation (TDM).

= Bots and limits =

* Block a list of scrapers and AI training crawlers, with a separate option to allow AI search assistants. Generic HTTP libraries (curl, python-requests, okhttp, Dart and the like, used by mobile apps and integrations) are not blocked by default; a strict option blocks them too, and the Log has an "Always allow this User-Agent" button.
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
* Ready-made presets (Balanced, Strict, Maximum) and an Emergency Mode for attacks in progress, with an automatic alert when traffic spikes.
* Undo for presets and imports (the last 5 versions), export and import of the settings as a JSON file, and a reset to defaults for each tab.
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
* WP-CLI: `wp scrapelock status`, `block <ip>`, `unblock <ip>`, `blocked`, `emergency on|off|status`, `log [--top]`, `check --ip=<ip>` (what ScrapeLock would answer to a request, without side effects), `settings export|import|get|set|undo` and `lockdown status`.
* Abilities API (WordPress 6.9+): `scrapelock/get-summary`, `scrapelock/block-ip`, `scrapelock/unblock-ip` and `scrapelock/emergency-mode`, for administrators only, so an AI agent or MCP client can read the summary and act during an attack. None of them unlocks Lockdown.

= Server rules =

Generated Nginx, Apache and Cloudflare rules for your own site, so cached pages and static files are protected too.

= On the page =

* Block text selection, right click, copy, drag and common shortcuts, or allow copying with the source link appended. Text selection stays allowed by default on new installs, because blocking it also stops screen readers' "read selection", translation and look-up tools.
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
* Unlock for 15 minutes to 2 hours, for yourself only, in the browser session you unlocked with (it locks again by itself and keeps the changes you made through WordPress) or until you lock it again. Locking and unlocking are logged and emailed to the site's admin address.
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

= 3.4.1 =
* Fix: turning "No PHP in the uploads folder" off, or deleting the plugin, left one more blank line in `wp-content/uploads/.htaccess` each time (since 3.3.2). The line break WordPress adds before the ScrapeLock block is now removed with the block, so the file is left exactly as it was before ScrapeLock wrote to it. Blank lines already left there by earlier versions are not touched.
* Lockdown: someone with a stolen administrator session and direct write access to the database could keep the owner's correct code (or recovery code) answering "busy" for up to about 20 seconds, by copying the code-check lock while it was held and writing it back after it was released. Code checks on the same server now also wait for each other on a small lock file (`scrapelock-lockdown.lock`, in wp-content/mu-plugins, or in wp-content when that folder cannot be written), which the database cannot change: a lock value written back in the database no longer delays anyone, while wrong codes are still checked one at a time and counted exactly. A code check whose request ended without releasing the lock no longer blocks the next one for 5 seconds either. The lock file only holds a random name; it is removed when the plugin is deleted.
* Security: Lockdown's copy of the wrong-code counters is no longer a `.json` file in `wp-content/mu-plugins` that anyone could download. It is now a PHP file that stops at its first line (a web request to it shows nothing), in its own folder `wp-content/mu-plugins/scrapelock-lockdown-data/` (with an `index.php`), which WordPress never loads as a must-use plugin.
* The `scrapelock-lockdown-fails.json` file left by 3.4.0 is read once more and then deleted, so its counters and lockouts still count after the update. This now happens during the update itself (and again in the hourly check if the file could not be moved yet), not only once a code is checked or a ScrapeLock settings page is opened.
* The file integrity check does not report the counters file or its folder while they hold exactly what ScrapeLock writes. If code is added to them, or another PHP file appears in that folder, it is reported like any other file.
* The counters folder is removed with the Lockdown guard: on unlock, on deactivation and on uninstall.
* Lockdown: when the guard file cannot be written and you lock with "Lock without the guard file (weaker)", ScrapeLock now writes a signed lock file outside the database instead, in the first of `wp-content/uploads/scrapelock-lockdown/` and `wp-content/scrapelock-lockdown/` that PHP can write to directly. It holds the lock, its generation, the lock time, the address alerts go to and, when it is not too large, the signed copy of the protected settings (as the guard does). Someone who can only change the database can no longer make a site locked this way look as if it had never been locked: with the lock data deleted, stripped or set back (also with the stored version set back to an older one), the site stays locked, the protected settings are put back from the copy and the alert goes to the address signed when you locked.
* The lock file cannot be shown by the web server: it starts with a line that stops PHP, it is read as data and never run, its name is made from the security keys so it cannot be guessed, and its folder has an `index.php` and an `.htaccess` that denies access. It is only read when there is no guard file (at most two quick file checks per request while there is none).
* The lock file is removed when you unlock "until I lock it again", remove the app, connect a new app, deactivate or delete ScrapeLock, and when the guard file can be written again. The file integrity check does not report it, or its `index.php` and `.htaccess`, while they hold exactly what ScrapeLock writes; code added to them is reported.
* The weaker lock still needs the checkbox. Its warning now says what it keeps: with a writable folder for the lock file, the lock survives a wiped database, but the active plugins and the theme are not kept from the start of every request and someone who can change the database could still deactivate ScrapeLock itself. When no folder can be written at all, it says plainly that everything is then in the database only and that a full wipe cannot be noticed. Site Health and the log say which of the two it is.
* Recovery with `SCRAPELOCK_UNLOCK` in wp-config.php after the Lockdown data was deleted from the database: connecting a new app, or removing the app, now also removes the guard file or the lock file that still said "locked". Before, the new app was not saved in that case, and after removing the app the site locked itself again on the next request.
* Fix: a guard file or lock file from a backup taken while the site was locked, put back after you unlocked "until I lock it again" (for example by restoring `wp-content/uploads` or `wp-content/mu-plugins`), no longer locks the site again with no way out. Before, the owner was frozen, the page said "unlocked" while the site stayed locked, recovery codes were used up and locking again answered with an error, so only `SCRAPELOCK_UNLOCK` or deleting the file by hand helped. An unlock now signs which lock it ended: an older file found afterwards no longer counts, is removed and is noted in the lockdown log. A file that still says "locked" while the database does not (for example one put back after unlocking with an earlier version) is now removed when you unlock with the app or a recovery code.
* Security: with the weaker lock (no guard file), the wrong-code counters were kept in the database only, so someone with a stolen administrator session and direct write access to the database could delete them before each try and guess app codes without limit and without any alert. A signed copy of the counters is now kept next to the signed lock file (same folder, a name made from the security keys, a first line that stops PHP): codes are refused after 5 wrong ones as with the guard file, you get the lockout email and an alert that the counters were changed outside WordPress, and an older copy put back in the database no longer ends a lockout. The copy is removed with the lock file.
* Security: while the site is locked, a deactivation that Lockdown refuses (for example `wp plugin deactivate scrapelock` with WP-CLI, which does not stop at the rights wp-admin checks) no longer removes the guard file, the counters copy, the early check, the pre-cache check line in wp-config.php or the scheduled events. Before, ScrapeLock stayed active but without its guard, and deleting the Lockdown data in the database then opened the lock without anyone noticing.
* A site locked by 3.4.0 with "Lock without the guard file (weaker)" now gets the signed lock file on the update to 3.4.1, or in the hourly check as soon as one of its folders can be written. Site Health no longer says that no folder of wp-content can be written when one can; it names the folder and says the lock file is written there by the hourly check.
* When Lockdown puts back an administration address that was changed in the database, WordPress no longer emails the planted address that the address "was changed" (which named the genuine one).
* Fix: on multisite, Lockdown codes could answer "Another code was being checked at the same moment" forever once the network's table held two copies of the code-check lock (two first code checks at the same moment, or a copy added by someone with database access). Unlocking with a correct code works again; only the oldest copy is used.
* Fix: on multisite databases that enforce ONLY_FULL_GROUP_BY, the Lockdown tab showed a wrong site count for the network snapshot.
* Fix: after a plugin update, a second visitor request arriving at the same moment could run the upgrade routine again.
* Security (WooCommerce): the long product description is now also emptied for visitors in the Store API when the request asks for only some fields (?_fields=description) and when the route is written in other letter case (/wc/Store/v1/products), which WordPress also accepts.
* Security (WooCommerce): always-blocked IPs, banned IPs and blocked bots can no longer use the Store API with POST (adding items to a cart and reading the product data back, creating carts or checkouts). These writes still never count toward a limit, and other REST writes (forms, payment webhooks) are not checked, as before.
* Fix (WooCommerce): the pre-cache check no longer counts the cart, checkout and My account pages (and the pages below them, such as "Order received" and My account > Orders) toward the page limit, as the normal check already did. In Emergency Mode a shopper could be limited, and then banned, while checking out. Bans and the block list still apply to these pages.
* Security: a private URL given as a query on the homepage (https://example.com/?feed=skroutz) now also protects the same feed at /index.php?feed=skroutz and at its pretty addresses (/feed/skroutz/, /shop/feed/skroutz/ and the like).
* Security (Cloudflare): with "Real visitor IP" left at the default behind Cloudflare, the pre-cache check now reads the visitor's address from CF-Connecting-IP, as the normal check does. Before, it saw the Cloudflare server as the visitor and let banned and blocked visitors get cached pages.
* Security (Cloudflare): a Cloudflare address given as the visitor in CF-Connecting-IP (for example a Cloudflare Worker that a scraper rents) is no longer treated as the Cloudflare server itself by the early check and the pre-cache check: it can be blocked, banned and limited like any other address there too.
* Fix: deleting ScrapeLock now removes the blocks still left at Cloudflare or Bunny CDN, as intended. Before, the last removal pass failed silently, and those blocks stayed at the CDN for good.
* Blocking at the CDN: when Cloudflare asks to slow down, ScrapeLock now waits the full 5 minutes (or longer, if Cloudflare says so) even when new bans come in meanwhile, and it makes at most 300 API calls in any 5 minutes, well inside Cloudflare's limit, which is shared with your dashboard and other tools.
* Blocking at the CDN: a Cloudflare token that is malformed or mistyped (or a Global API Key pasted as a token) is now treated as a refused token: blocking stops and waits for a working token, and the bans are blocked once it works, instead of being given up one by one. A Global API Key is named as such in the message.
* Blocking at the CDN: saving a Cloudflare token now also makes one test block (added, found and removed again), so a token that can only read the rules is refused with a message that names the permission it needs.
* Blocking at the CDN: an IPv6 ban of a network size Cloudflare does not accept (filter pncp_ipv6_prefix other than 48, 64 or 128) is blocked as the nearest larger network Cloudflare accepts (/48 or /64).
* Blocking at the CDN: Googlebot and Bingbot addresses are never sent to the CDN as blocks, also while their official lists are not downloaded yet.
* Blocking at the CDN: ScrapeLock's own Cloudflare rules are recognised more reliably (an IPv6 address written back by Cloudflare in another spelling, more than one page of rules), and rules are removed with a JSON body, as Cloudflare's API description asks.
* Cloudflare rules (Server rules tab): the rate limiting rule now comes in three variants, for the Free plan, for Pro and Business, and for Enterprise, because Cloudflare allows fewer fields on the smaller plans (the old rule could only be created on Enterprise).
* Cloudflare rules: no generated expression is longer than Cloudflare's 4,096 characters any more. A long list of allowed sites for hotlinking lists fewer subdomains (at the end only the site itself), and a long list of always-allowed User-Agents becomes a Skip rule of its own before the bot rules instead of being repeated in each of them.
* Cloudflare rules: backslashes and quotes in the bot list, the always-allowed User-Agents and the hotlink domains are now escaped, so the expressions stay valid.

= 3.4.0 =
* Fix: IPv4 addresses written in the long IPv6 form (0:0:0:0:0:ffff:198.51.100.7) are saved as IPv4, like the short ::ffff: form.
* Fix: private URLs are also recognised with trailing spaces, control characters or dots (/feed.xml%20, /feed.xml.).
* Site Health: "Always allowed IPs" or private URL IPs saved by an earlier version with ranges that cover a large part of the internet are flagged.
* Security: Lockdown no longer signs data again during an upgrade when it was already signed. Someone who could write to the database could change protected settings (plugins, admin email, registration, roles) or add an administrator, then set the stored ScrapeLock version back to an older one so that the upgrade signed their changes as genuine. Now only data really stored before 3.3 is signed (once), the changed settings are put back from the signed snapshot, and you are alerted that the version was set back. The lock state now carries a signed "sealed" marker, so unsigned data is never mistaken for old data once a newer version has signed it.
* Security: the quarantine now updates only the list of active plugins in the signed snapshot, instead of signing all protected settings again.
* Fix: upgrading a site that was locked with ScrapeLock 3.2 or older no longer stops with a fatal error (the roles were not loaded yet when the snapshot was taken).
* Security: the site is no longer locked without the guard file by accident. If WordPress cannot write to wp-content/mu-plugins, the Lockdown tab explains why and what to do, and locking is refused unless you tick "Lock without the guard file (weaker)". The lockdown log notes a lock without the guard.
* Security: without the guard file, deleting the lock state in the database, setting it to "not locked", or putting back an older copy no longer unlocks the site: while the signed snapshot of the lock is there, the site stays locked and you are alerted. No new authenticator app can be connected while the site is locked; the way out stays SCRAPELOCK_UNLOCK in wp-config.php.
* Security: wrong Lockdown codes can no longer slip past the limit by sending many requests at the same moment. Checking the limits, checking the code and counting a wrong code now happen as one step, one request at a time.
* Security: after too many wrong Lockdown codes, codes are refused for longer each time: 15 minutes, then 1 hour, then 6 hours (back to 15 minutes after a quiet day). You get an email each time this happens, and it is noted in the lockdown log. The Lockdown page says until when codes are refused.
* Security: someone using a stolen session of your own account can no longer lock you out of the Lockdown page. Wrong codes are now counted per account and IP (with a higher limit per account across all IPs), and recovery codes are only limited per IP, so you can always unlock with a recovery code from your own connection.
* New: "Sign out all other sessions of this account" on the Lockdown page, and an "Also sign out all other sessions of this account" option when unlocking. Both need a code from the app (or a recovery code) and work while the site is locked, so a stolen session can be thrown out without unlocking the site.
* Security: a stuck Lockdown lock set far in the future in the database (to make every code check fail with "busy") is now ignored.
* Security: unlocking for a while now gives the rights back only in the browser session you unlocked with. Another session of your account (for example a stolen cookie), application passwords, XML-RPC and WooCommerce API keys stay as when locked until you unlock "Until I lock it again". If you sign out during that time, lock again and unlock.
* Security: when the site is locked, the application passwords of staff accounts are noted in the signed snapshot. Application passwords added in the database while the site is locked are refused, removed by the hourly check (and before the site is locked again, unlocked for good or the app is removed), and you get an email.
* Security: an older copy of the Lockdown data put back in the database (for example from a backup) is no longer accepted while the site is locked. The lock state, the guard file, the saved copy of the protected settings and its fingerprints now carry a number that goes up with every change, and the guard file is written again each time. An older copy (which could bring back an old authenticator app secret or recovery codes that were already used) is refused: the site stays locked, codes are not accepted from it, it is never signed again as current, and you are alerted. Sites locked with an earlier version get these numbers once on upgrade, from their genuine signed data.
* Security: while the site is locked, the guard file now keeps the list of active plugins and the theme exactly as they were when the site was locked, from the very start of every request. A plugin added to the list in the database no longer runs even once before it is put back, ScrapeLock stays loaded even if it is removed from the list or the list is deleted, and the stored values are still put back and reported. Without a genuine saved copy of the settings the guard only keeps ScrapeLock active, as before. Nothing is enforced while the site is unlocked for a while or with SCRAPELOCK_UNLOCK in wp-config.php.
* Fix: the file integrity check no longer reports the Lockdown guard file as changed when ScrapeLock itself writes it again; any other change to that file is still reported.
* Security: the file integrity check now reads the whole WordPress folder, not only wp-admin, wp-includes and wp-content. A PHP file in a folder of its own next to them (for example /x/shell.php or .well-known/) is now found.
* Security: folders called "cache" are no longer left out everywhere (for example uploads/cache was never read), only the known cache folders in wp-content. In the cache and updater folders (wp-content/cache, wp-content/upgrade and others) and in .git and node_modules folders, changed or removed files are still not reported, but a new code file is, unless it is a cache data file that starts with a plain "die" or "exit" and so cannot run. The `pncp_integrity_exclude` filter has a new "skip" list for folders that should not be read at all.
* Security: the list of files already emailed about and the official checksums kept from WordPress.org are now signed, so they cannot be changed in the database to hide a backdoor. A fingerprint taken before this version is widened once to the new folders without reporting the files that were already there.
* Fix: when an unlock for a while ends by itself, the changes you made through WordPress in the meantime are kept. Before, the settings saved when the site was locked stayed in force, so plugins you activated, a theme switch, a new site address or changed ScrapeLock settings were put back and you got a "changed outside WordPress" email, and administrators you added could not sign in. Now, on the first request after the end (or in the hourly check, whichever comes first, one request at a time), the signed copy of the settings is taken again with your changes. Only changes made by the administrator who unlocked, in the browser session that unlocked, are noted (signed) while it is open, and only what each change itself added or changed: a value changed directly in the database, at any time, is still put back and reported, and an account given administrator rights in the database still cannot sign in. While the site is unlocked for a while, a notice says that it will lock again and what is kept, with what was noted so far.
* Fix: a request that started just as the site was locked again (by hand or by itself) no longer reports the saved fingerprints of the protected settings as an "older copy from a backup": they are read once more from the database first.
* Security, multisite: the lock now protects the whole network. When you lock, the plugins active on the whole network, the super admins, the network admin email and the registration setting are saved (signed) and put back if they are changed directly in the database, and they can no longer be changed through WordPress while locked. Before, removing ScrapeLock from the network plugins in the database turned the lock off, and a super admin could be added.
* Security, multisite: every site where ScrapeLock is active now gets its own signed copy of its protected settings and administrators when you lock (up to 1000 sites), noted in a signed copy of the whole network. Before, only the site where you clicked "Lock" had one: the other sites sent false "saved copy no longer matches" alerts and changed settings there were not put back. On large networks the full copy of the sites after the first 50 is saved on their first visit, from the values that still match what was noted when you locked; a setting changed in the database before that visit is reported, and the plugins and theme are put back.
* Security, multisite: the guard file now also works on a network: it keeps ScrapeLock and the other network plugins active, and the active plugins and theme of the first 100 sites as they were when you locked, from the start of every request.
* Security, multisite: an account made a super admin or a site administrator behind WordPress's back can no longer sign in while the network is locked (on any site, as the login works for the whole network), and the hourly check reports it. Application passwords added in the database are found on every site.
* Fix, multisite: an unlock for a while that ends by itself keeps the changes you made on every site and to the network options, not only on the site where it ended.
* The Lockdown tab on a multisite network explains what the lock covers and its limits (sites added after locking are not covered until you lock again). A network locked with an earlier version keeps working as before; the tab asks you to unlock and lock again to protect every site.
* New installs start in "Monitor only" for their first 7 days: every check runs, but a request it would refuse is let through and logged as "Would block". A notice on the Dashboard and the ScrapeLock page counts what would have been blocked, by reason, links to those entries in the Log and has an "Enforce now" button. After 7 days ScrapeLock starts blocking on its own and tells you once (a notice and an email). Existing sites keep blocking as before.
* New: "Monitor only (log what would be blocked, block nothing)" setting at the top of Bots and limits. Nothing is blocked temporarily and nothing is blocked at the CDN while it is on; private URLs and Lockdown keep protecting as before. It is shown in the status bar of the ScrapeLock page, the admin bar ("Protection: MONITOR ONLY"), the Dashboard widget, Site Health and `wp scrapelock status`. The Log tab can show all events, only real blocks, or only "Would block" entries.
* The default bot list no longer blocks generic HTTP libraries (curl, Wget, python-requests, Go, Java, okhttp, Dart, node-fetch, axios, Guzzle and others), so WooCommerce mobile apps, headless front ends, ERP price sync and uptime monitors work on new installs. AI training crawlers and named scraping tools (GPTBot, CCBot, ClaudeBot, Bytespider, Scrapy, HTTrack, Diffbot and others) stay blocked. Existing sites keep their bot list exactly as it is, and the Bots tab tells you if it still contains these libraries.
* New: "Also block generic HTTP libraries (strict)" in Bots and limits, off by default, for sites that want the old behaviour.
* The default "Always allowed" list now also includes StatusCake, Site24x7, Better Stack (Better Uptime), HetrixTools, ManageWP, MainWP, WP Umbrella, Freshping and Uptime Kuma (new installs).
* New: "Always allow this User-Agent" button in the Log tab, next to requests blocked by the bot list. It suggests the part of the User-Agent that was blocked (e.g. "Dart/"), which you can edit, and refuses parts so generic that they would also match ordinary browsers (e.g. "Mozilla").
* Automatic Emergency Mode has a new "When it happens" choice. New installs only alert you: an email and a notice on the Dashboard and the ScrapeLock page with a one-click "Start Emergency Mode (1 hour)" button, because a rush of real visitors (a newsletter, a link on a popular site) looks the same as an attack. "Start Emergency Mode for 1 hour on its own" is the old behaviour; existing sites that had the automatic start on keep it.
* RSS / Atom and podcast feeds are no longer refused by "Browsers only" and the headless browser check (also in Emergency Mode, which turns both on), so feed readers and podcast apps keep working. The bot list and the limits still apply to feeds.
* The Emergency Mode box now lists exactly what Emergency Mode changes on your site, generated from the settings it really applies, instead of a short summary.
* Starting or ending Emergency Mode (button, WP-CLI, Abilities API) no longer empties the page cache and Cloudflare's cache at the peak of an attack. Only when it changes something cached pages contain (e.g. excerpts in lists) is the cache emptied, once, in a background request.
* Saving the settings empties the page cache only when a setting that cached pages depend on changed (copy protection, the bot list, feeds, headers and similar). Saving e.g. the log retention, country lists, limits or the watermark opacity leaves the cache alone.
* New: undo for one-click changes. Before a preset, an import, a tab reset or a restore changes the settings, the previous settings are kept (the last 5 versions). The success notice has an "Undo" button, and "On the page" → "Export, import and undo" lists the earlier versions with a "Restore" button each.
* New: export the settings of every tab as a JSON file and import them on another site. The export leaves out secrets (the CDN shared secret, the API token for blocking at the CDN and the private feed tokens). An import first shows which settings would change, with any warnings, and changes nothing until you confirm; it goes through the same checks as the settings form.
* New: "Reset this tab to defaults…" under each settings tab. It shows what would change and asks for confirmation; only that tab's settings change (the CDN shared secret is kept).
* Applying a preset that turns off the RSS feeds or printing (Maximum) now asks for confirmation first.
* "Always blocked IPs" no longer accept ranges wider than /8 (IPv4) or /16 (IPv6), such as 0.0.0.0/0 or ::/0, which would block every visitor: they are not saved, and the notice names them. Saving warns (but still saves) when an always-blocked range contains your own IP, or when the blocked countries include your WooCommerce store's country or the country you are visiting from.
* New installs no longer block text selection, as in the recommended Balanced preset: blocking it also stops select-to-speak and screen readers' "read selection", translation and look-up tools, and copying with the source. The setting's help text now says so. Existing sites keep their setting.
* The "Bots and limits" tab is split into clear parts: "Bots", "Limits" and "Network and CDN (advanced)" (real visitor IP, trusted proxies, CDN shared secret, "Only through the CDN", early check and pre-cache check), folded by default with a one-line summary of its state and opened on its own when something in it needs a look. "Blocking at the CDN" is folded as well and says that its button saves only the CDN connection. All settings keep their names.
* "Keep the block log for" and "Content addresses" moved to a new "Log settings" section at the bottom of the Log tab, with its own "Reset this tab to defaults".
* New Site Health checks: Emergency Mode is on (with the time left and a "Stop Emergency Mode now" button; critical when it runs for more than a day), "Monitor only" is on, the official IP lists of Google, Bing and Cloudflare are missing or older than 3 days, and "Only through the CDN" cannot work because requests come through a local proxy that is not trusted. Site Health → Info (and `wp scrapelock status`) now also lists the settings that block or limit visitors.
* New WP-CLI commands: `wp scrapelock settings export [--file=…]`, `import <file> [--dry-run] [--yes]`, `get [<setting>]`, `set <setting> <value> [--dry-run]` and `undo` (same checks as the settings form; the CDN shared secret is never shown; refused while the site is locked); `wp scrapelock check --ip=<ip> [--ua=<user-agent>] [--address=<url>] [--browser]`, which explains what ScrapeLock would answer to a request without counting, logging or blocking anything; and `wp scrapelock lockdown status` (read only).
* The "Start or stop Emergency Mode" ability of the Abilities API is now marked as destructive, so AI agents ask before using it, and starts Emergency Mode for at most 24 hours (the ScrapeLock page and WP-CLI still allow up to 72). The summary ability (get-summary) is cached for 5 minutes and covers at most 7 days.
* Fix: "Only through the CDN" now works behind a reverse proxy on the same server (Nginx in front of Apache, Varnish, Plesk). Requests from 127.0.0.1 or the server's own address are let through as the server's own only when no proxy passed them on; requests with a forwarding header are judged by the visitor's address, as "Real visitor IP" finds it. The pre-cache check does the same. A warning on the Dashboard and the settings page says when the local proxy is not trusted yet, and what to change.
* Fix: blocks at the CDN can no longer be forgotten at the CDN. Each block is saved right after the API call that made it (and noted as "pending" just before it), so a run that times out or stops halfway no longer leaves blocks ScrapeLock never removes. A Cloudflare rule that already exists is adopted when its note says ScrapeLock made it; on Bunny CDN, an address ScrapeLock had just sent is adopted the same way. Rules the site owner made are still never touched.
* Fix: two runs of the CDN sync can no longer overlap, each run stops starting new calls after about 20 seconds, and a block added or lifted while a run is busy is always picked up by a following run. A block the CDN refuses to remove is tried again a few times and then listed on the settings page so you can remove it by hand; it no longer holds up the other removals. Blocks that could not be removed in time on deactivation are removed when the plugin is activated again (or on uninstall).
* Security: an API token set in wp-config.php (SCRAPELOCK_EDGE_TOKEN) is no longer copied into the database when the CDN, the zone or the setting changes, or on deactivation. Copies made by earlier versions are removed on upgrade.
* Fix: the country database is used only while "Download the country database" is on. Turning it off deletes the downloaded files, and files left behind by earlier versions are deleted on upgrade. The daily task also downloads the database again when its files went missing, and its state is read without an extra database query.
* Fix: the human check no longer gives up too early at higher difficulties (at difficulty 5 about 4 visitors in 10 were never verified). It now tries up to 8 times the average work for the difficulty set, stops when the challenge would expire, and keeps handing control back to the browser so the page stays smooth.
* The block log can no longer grow without limit during an attack from thousands of addresses: each minute at most 300 new rows are written (filter `pncp_log_rows_per_minute`), beyond that the requests of that minute are added up in one row per reason, shown as "Many IPs". New temporary blocks are still logged one by one.
* Old log entries are deleted in batches of 5,000 (short table locks instead of one long DELETE), and also when an administrator opens wp-admin and the hourly cleanup has not run for 2 hours, so the retention period is kept even when WP-Cron does not run. A new database index makes the Log tab faster on large logs.
* Performance: with APCu, short-lived data (log grouping, the human check throttle, DNS checks and the like) is kept in APCu instead of the database. The "is this IP blocked?" check no longer queries the database when no block is in effect. The Dashboard widget counts its total with one query kept for 5 minutes, and the figures of the Log tab are counted at most every 5 minutes, with the time they were counted and a "Refresh" button.
* The switches in the settings are easier to see when off (at least 3:1 contrast) and keep showing on / off in Windows High Contrast and other forced-colour modes.
* Translation fixes: plural forms for days and hours in the Emergency Mode email, the email subjects as one translatable sentence, the reason and status code in the Log as one translatable string, and every WP-CLI message is now translatable.
* Privacy: the IP addresses of administrators, kept so they are never blocked at the CDN, are deleted after 30 days also when nobody opens wp-admin any more. The suggested Privacy Policy text now says that, when blocking at the CDN is on, temporarily blocked IP addresses are sent to Cloudflare or Bunny CDN with a note giving the reason and the end of the block.
* Security: without the guard file, deleting the lock state together with the fingerprints of the protected settings (or putting back an older state and deleting them) no longer unlocks the site: the signed snapshot of the lock is checked too.
* Fix: locking the site no longer sends a false "Lockdown data was changed outside WordPress" alert and email. A request that came in while the lock was being saved (for example the background check of the official checksums) found no snapshot yet.
* Security: the wrong-code counters of Lockdown are now signed. Counters written in the database (for example a lockout of the owner's IP that would last for years) are ignored, and so are values the plugin could never write.
* Security: the lock that Lockdown code checks take in turn is now signed and only released by the request that took it. A value written in the database no longer keeps every code check "busy".
* Fix: recovery codes are now checked before the code check takes its turn, so sessions typing many wrong recovery codes from many IPs can no longer keep the owner's correct recovery code waiting ("busy").
* Security: with a CDN shared secret set, a request from a Cloudflare or Bunny address that does not carry it (someone else's zone at the same CDN, or a Worker) is no longer treated as "the CDN standing in for many visitors": the always-blocked list, the limits and the temporary blocks apply to it.
* Fix: dismissing the surge notice (or starting Emergency Mode from it) during a surge that goes on no longer brings a new notice and email a minute later: an hour of quiet follows the dismissal.
* Fix: Emergency Mode now really blocks while "Monitor only" is on, for example in the first week of a new install; "Monitor only" is back when it ends. The Emergency Mode description and the alert email say so.
* Fix: Undo and Restore of an earlier settings version keep the current CDN shared secret (as import and reset do), and no longer turn the first week's "Monitor only" back on after "Enforce now".
* Fix: deactivating and deleting the plugin also removes its scheduled events that carry arguments (missing IP lists, image clean-up, surge emails).
* Fix: `wp scrapelock settings export --file=` with a folder that cannot be written prints only the error, without a PHP warning.
* Fix: a settings value damaged in the database (a list where a single value belongs) no longer causes PHP warnings on the settings tabs; it is read as its default.
* Fix: "Always blocked IPs" also refuses IPv6 ranges that cover all IPv4 addresses (such as ::ffff:0.0.0.0/96), like 0.0.0.0/0.
* Security: the guard file now also keeps a signed copy of the whole snapshot of the protected settings. If the snapshot in the database is deleted, changed or set back to an older copy (also in the first minute after locking), the changed settings (admin email, site address, registration, roles and the others) are still put back from it, the snapshot is put back too, and you are alerted.
* Security: while the site is locked, Lockdown alerts go to the administration email address as it was when the site was locked, not to an address someone changed in the database.
* Security: the "already alerted" marks that limit the Lockdown alert emails to one an hour are now signed and never last longer than an hour, so values planted in the database can no longer switch the alerts and their log entries off.
* Security: while the site is locked, an administrator whose password was changed directly in the database can no longer sign in with it, and you are alerted. Password changes made through WordPress during an unlock for a while, and WordPress storing your password again in a newer format when you sign in, keep working.
* Security: while the guard file is in place, the counters of wrong Lockdown codes are also kept in a signed file next to it. Deleting the counters in the database, or putting back an older copy, no longer resets the limits or ends a lockout, and you are alerted. The counters no longer name IP addresses by a plain hash.
* Security: the lock that Lockdown code checks take in turn is now held for 5 seconds at most (was 10), and a value of it that was written back in the database after it was released is recognised as free.
* New: when you unlock "until I lock it again", the Lockdown page and the email name the accounts that got administrator rights directly in the database while the site was locked, so you can check them.
* Fix: the pre-cache check now applies Emergency Mode too: cached pages get its lower page limit and its temporary blocks, and it really blocks while "Monitor only" is on (for example in the first week). It ends at its time.
* Security: "Trusted proxies" no longer accepts ranges wider than /8 (IPv4) or /16 (IPv6), which would let any visitor choose its own IP with a header (even the server's own address). Such ranges saved by an earlier version are ignored and Site Health reports them. "Always allowed IPs" and the IPs for private URLs refuse such ranges too.
* Fix: IPv4 addresses and ranges typed in their IPv6 form (::ffff:198.51.100.7) are saved as IPv4, and ones saved before now match IPv4 visitors. Before, they were kept but blocked or allowed nobody.
* Security: private URLs are also protected when the address carries a ";" part or an encoded NUL (/skroutz.xml;x, /skroutz.xml%00), for feed code that matches the address loosely.
* Fix: the main Googlebot and Bingbot addresses can no longer be blocked by hand (Log tab, WP-CLI, and so at the CDN) while the official Google and Bing lists are not downloaded yet.
* Fix: `wp scrapelock unblock <ip>` warns that nothing was lifted when the IP had no temporary block, instead of reporting success.
* Fix: the very first Lockdown codes typed on a site at the same moment could be checked two at once (the code-check lock was created in a way that let a second request reset it), so one wrong code could go uncounted.

= 3.3.2 =
* Fix (Lockdown seal): the guard file was never written on sites without a wp-content/mu-plugins folder (the write check ran on the missing folder), so the seal was silently off there and someone able to write to the database could unlock the site. The same fix applies to the early check.
* Fix (Lockdown seal): unsigned data is never accepted while the guard file exists, and the 3.3 upgrade step no longer signs data that does not match the guard. Setting pncp_version back in the database can no longer make forged data look genuine.
* Lockdown: locking is much faster. The comparison with the official WordPress.org checksums runs in the background right after, the checksums are cached per version for a week, every file is read once (SHA-256 and MD5 together), and the request gets more time on hosts that allow it. The lock button shows that it is working and cannot be sent twice.
* Lockdown: the hourly file check rereads only files whose size, times or inode changed (a full pass still runs once a day).
* Lockdown: while locked, each request compares small signed, autoloaded fingerprints of the protected settings instead of reading and signing the whole snapshot.
* Lockdown: wrong codes are counted per account and per IP, with a much higher ceiling for everybody together (100 an hour) that recovery codes are not held back by. One counter for everybody let a stolen session stop the owner from unlocking. Counting happens under the same lock as the code check.
* Lockdown: optional SCRAPELOCK_KEY in wp-config.php, so that a change of the WordPress keys (done automatically by some security plugins and hosts) does not lock you out. A warning explains it before the first lock.
* Lockdown: the users-per-role count is taken once per page and cached for 10 minutes; a repeated "change refused" is logged at most once every 10 minutes.
* Fix: behind Cloudflare with "Real visitor IP" left at the default, every visitor shared the edge's address, its page limit and its bans. CF-Connecting-IP is now read automatically from verified Cloudflare edges (and the CDN secret, if set), and a CDN edge that still stands in for the visitors is never counted, limited, struck or banned. A CDN address that arrives in the real-IP header (e.g. a Cloudflare Worker) is limited like any other client.
* Fix: IPv4-mapped IPv6 addresses (::ffff:1.2.3.4), addresses with a port and non-canonical IPv6 are normalised, so they match the lists (a real Googlebot could be refused as fake before).
* Fix: a private URL that resolves to the homepage or every page ("/", "*", or a URL with only a query) could answer 403 to every visitor. Such lines are refused when saved and ignored if already stored. Private URLs can now carry a query (e.g. /?feed=skroutz), and a feed protected by its address is also protected when reached through its query variables.
* Fix: a reinstall could delete the clean image originals ("Remove watermark" after uninstall). Uninstall keeps their index, and a backup without a record is never deleted.
* Fix: when pncp_version is missing, 1.x is recognised by the shape of its settings, so "trust every proxy" is no longer turned back on by mistake.
* Search engine verification: a failed forward DNS lookup is "no verdict" (retried in 5 minutes), not "fake"; fake-crawler and fake-AI-bot violations count once per minute.
* Automatic Emergency Mode no longer empties the page cache at the peak of the traffic, and its email is sent from a background request.
* Counters use APCu when it is shared by all PHP workers (PHP-FPM, mod_php), instead of a database write on every page; strikes are atomic there too. The data center lookup costs no query for addresses outside the known groups.
* WooCommerce Store API: only the long product description is emptied (the shop's blocks show the short one), product objects only, and /batch and the cart's cross-sells are covered.
* List excerpts apply only to the articles' own text (in the main loop and in a theme's own post sections), not to other text that runs through the_content on archive pages (category descriptions, menus, popups).
* Watermark: faded once per request instead of for every size, more memory for large originals, the clean full-size file is left out of srcset when it is not watermarked, and images edited in the media editor are watermarked again.
* Front end: links keep their right-click and long-press menu, Ctrl+A is no longer blocked, "blur on capture" lasts at most 6 seconds and ignores file pickers and select lists, the blur no longer moves fixed headers, and the message is announced by screen readers.
* Anti-framing headers are not sent to the Customizer preview, and a separate wp-admin address is allowed in frame-ancestors.
* Manual blocks from WP-CLI and the Abilities API follow the same rules as the Log tab (never the server, your own IP, allowed IPs, search engines or CDN edges).
* Network deactivation cleans up every site. Uninstall tries once more to remove leftover CDN blocks, and also removes site transients and the uploads .htaccess block with its markers.
* The CDN shared secret is no longer printed into the settings page; an empty field keeps it.
* Files are written atomically (country database, pre-cache settings); the temporary copy of wp-config.php ends in .php. The pre-cache check removes old counter files in small batches and hourly.
* Hotlink rules (Apache, Nginx) match the referer's host, not any text in it.
* The "Who is exempt" label says that contributors and shop managers are included.
* After an update, the file work of the upgrade (early check, pre-cache check, uploads rule, new lists, page cache) no longer runs inside the first visitor's request: it runs in a background request, or on the next wp-admin page.
* Pre-cache check: its settings file no longer holds the CDN lists twice, and the Google / Bing lists are in crawlers.json, read only when a request claims to be one of them. Much less to decode on every request without APCu.
* Watermark: a watermarked JPEG / WebP size is made from the clean original with a single lossy save (filter pncp_watermark_single_compression), at the site's own image quality; the JPEG colour profile (e.g. Display P3 from phones) is kept; WebP / AVIF copies made by image optimizers next to a rewritten file ("photo.jpg.webp") are removed, and the action pncp_watermark_file_changed lets others react.
* GraphQL: the text of blocks (WPGraphQL Content Blocks editorBlocks renderedHtml and text attributes, WPGraphQL Gutenberg blocks and blocksJSON) is hidden from visitors too.
* Front end: the protection script and styles are minified and printed inline (about 6 KB), with no request of their own; with SCRIPT_DEBUG the readable files load as before.
* The default visitor message is shown in the site's language, also after the language changes (it was stored translated at install time). Leave the field empty for the default.
* Cloudflare hotlink rule: matches the referer's host with starts_with() (every plan), not any text in it.
* Translation template updated.

= 3.3.1 =
* Pre-cache check: its data (settings, counters, events) now lives in a protected folder with a random name inside the uploads directory, uploads/scrapelock/, as plain data files: no PHP file is generated any more. The line in wp-config.php loads the check from the plugin's own folder. The old wp-content/scrapelock-precheck folder is removed on upgrade and its events are moved into the log; the check resumes as soon as an administrator opens wp-admin.
* Pre-cache check: only a hash of the CDN shared secret is written to its settings file.
* Lockdown: the "site is locked" page loads its styles from a registered stylesheet (assets/css/locked.css) instead of an inline style block.
* File locations: every folder ScrapeLock reads or writes (the WordPress folder, wp-content, plugins, must-use plugins, uploads, themes, wp-config.php) is now found with WordPress' functions (get_home_path(), get_theme_root(), plugin_dir_path(), wp_get_mu_plugins(), wp_upload_dir()) in one place, instead of WordPress' internal path constants. The generated Cloudflare rule takes the wp-admin, wp-includes and wp-content paths from admin_url(), includes_url() and content_url().
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
