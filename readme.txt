=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhube
Tags: anti-scraping, ai bots, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.2
Requires PHP: 7.4
Stable tag: 3.4.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Server-side anti-scraping: tells real Googlebot from fakes, blocks AI training bots, rate-limits per IP and locks private XML feeds with a token.

== Description ==

Most content protection plugins disable right click in the browser. Scrapers and AI crawlers never use a browser, so they are not affected. ScrapeLock works on the server, where automated copying actually happens, and keeps real visitors, customers and search engines unaffected.

= What makes ScrapeLock different =

* **Real search engines vs. fakes.** Googlebot, Bingbot, Applebot and Yandex are verified against their official IP lists and with reverse + forward DNS. Real crawlers are never limited or blocked; scrapers that only pretend to be Googlebot get a 403.
* **AI training vs. AI search.** Training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended, Bytespider and more) are blocked, while AI search assistants (OAI-SearchBot, ChatGPT-User, PerplexityBot and more) can be allowed with one option and are verified with their official IP lists, so your site still appears in AI answers with a link.
* **Per-IP limits and temporary blocks.** Separate limits for pages, searches and REST / GraphQL requests (IPv6: per /64 network). IPs that keep exceeding them are blocked for a while, optionally also at your CDN, and an invisible trap link catches bots that ignore robots.txt.
* **Private feeds with a token.** XML feeds for price comparison sites, Google Merchant or an ERP are closed to everyone else. The token goes in a header or the URL, only its hash is stored, and it can be rotated with a grace period.
* **Your text stays out of the API.** Post, page and product text is hidden from the REST API, WPGraphQL and full-text RSS for visitors, which are the routes scrapers use instead of the HTML.
* **Emergency Mode.** One click during a scraping attack: stricter limits for 1 hour to 3 days, then your normal settings return on their own. When traffic suddenly jumps, ScrapeLock emails you with a one-click button to start it.
* **Monitor only.** Try every setting without blocking anyone: requests that would be refused are logged as "Would block". New installs start this way for their first 7 days.
* **Lockdown.** Freeze the whole site with a code from your authenticator app, so not even a stolen administrator password can change it.

Nothing can stop a determined human: whatever a visitor sees has already reached their device. ScrapeLock closes the automated routes and leaves traces: a block log, watermarks, a source link on copied text and a machine-readable rights reservation (TDM).

= Bots and limits =

* Generic HTTP libraries (curl, python-requests, okhttp and the like, used by apps and integrations) are not blocked by default; a strict option blocks them too, and the Log has an "Always allow this User-Agent" button.
* Optional blocking of headless browsers and of scripts that copy a browser's User-Agent but not its headers. A carefully disguised automated browser is not detected this way; the limits, the human check and the bot trap still apply to it.
* Extra limits for "page not found" (404) requests, sitemaps, visitors from data centers and, with WooCommerce, cart / checkout actions and coupon attempts. Verified search engines and real shoppers are not affected.
* Optional human check: visitors who have not interacted with the page (scroll, tap, key) get a stricter page limit. No captcha; it works with page caches.
* Optional country rules, from Cloudflare's or Bunny CDN's country header or the free DB-IP Lite database.
* Optional pre-cache check (the limits and blocks also apply to pages served by a page cache such as WP Rocket) and early check (stops known bots and blocked IPs before the theme and the other plugins load).
* Optional blocking at Cloudflare or Bunny CDN, with a "Test connection" that checks the token, the zone and the permissions in one click.
* Always-blocked IPs / CIDR and referrer domains, usernames hidden from visitors, and Content Signals in robots.txt.
* Trusted Proxy support for Cloudflare, Bunny CDN and reverse proxies, so the real IP cannot be spoofed. Works with the Cloudflare plugin (APO).
* Presets (Balanced, Strict, Maximum), undo for presets and imports, export and import of the settings, and a block log with a 24-hour summary and automatic deletion.

= Feeds, API and server rules =

* RSS with a short excerpt only, or disabled. With full text, an optional "The post … first appeared on …" line links republished copies back to the original.
* Private XML feeds (Skroutz, BestPrice, Google Merchant, ERP) with token rotation and per-feed statistics.
* Optional: hide the REST API map from visitors, turn off pingbacks over XML-RPC, and see which REST routes anyone can call without logging in.
* Hide the versions of WordPress, PHP and the plugins.
* Ready-made Nginx, Apache and Cloudflare rules for your own site, so cached pages and static files are protected too.

= Site Health, WP-CLI and AI agents =

* Tools → Site Health warns about settings that do not work as intended and has a ScrapeLock section in the Info tab.
* WP-CLI: `wp scrapelock status`, `block`, `unblock`, `blocked`, `emergency`, `log`, `check --ip=<ip>` (what ScrapeLock would answer, without side effects), `settings` and `lockdown status`.
* Abilities API (WordPress 6.9+) for administrators: read the summary, block or unblock an IP and start Emergency Mode from an AI agent or MCP client. None of them unlocks Lockdown.

= On the page and images =

* Block text selection, right click, copy, drag and common shortcuts, or allow copying with the source link appended. Text selection stays allowed by default, because blocking it also stops screen readers' "read selection" and translation tools.
* Printing with the page link at the bottom, or no printing; optional page blur on screenshot shortcuts; no framing by other sites.
* AI opt-out declaration (TDM): header, meta, `/.well-known/tdmrep.json`, `noai`.
* Watermark in a corner, the centre or repeated diagonally, optionally on the full-size image too. When the full size is not watermarked, visitors get the largest watermarked size instead, also in the WooCommerce zoom, lightbox and Store API. The clean original is kept, so the watermark can always be removed. Product images are not watermarked by default, because Google Merchant Center rejects them.

= Lockdown =

* Freeze the site with one click and a code from your authenticator app (Google Authenticator, Microsoft Authenticator, Authy and the like). While it is locked, nobody can change plugins, themes, WordPress core, users, roles or settings from wp-admin, the REST API or XML-RPC, not even an administrator or someone who stole a password.
* Administrators are frozen completely. Shop managers and other staff roles you do not tick keep their work (orders, products, coupons, posts, media), but not the rights that could take over the site.
* Also enforced against code: if another plugin is exploited, it cannot activate plugins, change the site address or the admin email, add an administrator or unlock the lock.
* Visitors and customers are not affected: they browse, order, pay, register as customers and comment as usual.
* File integrity: a fingerprint of every PHP, .htaccess and .user.ini file is checked every hour while locked, and WordPress and the plugins from WordPress.org are compared with their official checksums. New or changed files are emailed to you and shown in Site Health; optional quarantine.
* Sealed: the lock is signed with the keys in wp-config.php and kept outside the database (a guard file, a lock file, or a line in wp-config.php), so SQL injection in another plugin cannot unlock the site. Settings changed in the database are put back.
* Unlock for 15 minutes to 2 hours for yourself only, or until you lock it again. Every lock and unlock is logged and emailed.
* Lost your phone: ten one-time recovery codes, or `define( 'SCRAPELOCK_UNLOCK', true );` in wp-config.php as a last resort.
* The QR code is drawn in your browser and the secret is stored encrypted: it is never sent anywhere.

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

Optional blocking at the CDN (off by default) uses the API of the CDN you choose, with your token. It sends only the IPs ScrapeLock blocks temporarily (IPv4, IPv6 or an IPv6 /64), each with the reason and end time, and removes them when the block ends. Saving the setting, or "Test connection", checks the token and the zone; with Cloudflare it also adds a test block for a documentation address (203.0.113.x) and removes it again.

* **Cloudflare API** (IP Access rules of your zone), only when the CDN is set to Cloudflare: https://api.cloudflare.com/client/v4/zones/ZONE_ID/firewall/access_rules/rules, and for the check https://api.cloudflare.com/client/v4/user/tokens/verify (or /accounts/ACCOUNT_ID/tokens/verify) and /zones/ZONE_ID. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
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

= 3.4.2 =
* Fix: on sites served by several web servers that share one MySQL / MariaDB database, the Lockdown code check now uses a lock of the database server (GET_LOCK). All web servers wait on the same lock, values written in the database can no longer keep the owner's correct code "busy", and the lock is freed at once if a request dies while holding it. The lock file and the signed lock row are kept as the fallback (SQLite, database drop-ins with several connections, or when GET_LOCK is not available).
* Dev: new filter `pncp_lockdown_db_lock` (bool) to turn the database lock off.
* New: Lockdown on servers where WordPress cannot write to any folder of wp-content (no guard file and no lock file possible): after locking, the Lockdown page shows a line to add to wp-config.php by hand, `define( 'SCRAPELOCK_LOCKED', '...' );`, with a Copy button. The value is signed with the site's keys and names the lock and the address alerts go to. While it is there, if someone deletes, changes or puts back an older copy of the Lockdown data in the database, the site stays locked, protected settings are put back from their saved copy while it is there, and the alert goes to the address signed when the site was locked. A line from another site, or changed by hand, is ignored.
* New: until the line for the current lock is in wp-config.php, the Lockdown page, an admin notice, Site Health (critical) and `wp scrapelock lockdown status` say that the lock is not protected yet. A line from an earlier lock is named, with the new line to replace it.
* New: the same line can also be added when the guard file or the lock file is written, as one more copy of the lock outside the database (optional, shown on the Lockdown page).
* Unlocking for a while works with the line in place, with no change to it. After an unlock "until I lock it again", the page, the email and Site Health ask you to remove the line. SCRAPELOCK_UNLOCK still opens the site with the line present, and a new app can be connected; afterwards the old line no longer holds the site locked.
* Multisite: one line for the whole network (one wp-config.php, one lock of the network).
* Known limit: the line cannot follow an unlock for a while that is ended early with "Lock again now". Putting back the database copy of that unlock re-opens it only for the browser session that unlocked. If the line is left in place after an unlock for good, a wipe of the Lockdown data locks the site again until the line is removed.
* Fix: WooCommerce shop managers were always frozen by Lockdown (WooCommerce gives the role "edit_theme_options"), so a locked shop could not process orders. While the site is locked, shop managers now keep their work: orders and refunds, products and stock, coupons, reports and analytics, customers, posts, pages, media and comments. Only what can take over the site stays frozen for them: plugins, themes, the Customizer, menus and widgets, the file editor, creating or promoting users and editing staff accounts, WordPress and WooCommerce settings (payment methods too), import and export, and HTML that can carry scripts. Their own email, password and application passwords stay frozen too.
* Change: the same applies to every role that is not ticked under "Who is frozen while locked" and has any of those rights (for example an unticked Editor keeps editing but loses unfiltered HTML while locked). Administrators, and every role that can manage plugins, themes, users or settings, are always frozen as before. Shop managers are no longer ticked by default; tick the role to freeze it completely.
* New: the Lockdown tab explains what a locked site still allows each role (administrators, ticked roles, unticked staff roles, other roles), the report lists the accounts that keep their shop and content work, and staff who keep their work see a notice that says what they can still do. Site Health and `wp scrapelock lockdown status` list the roles that keep their work while locked.
* Dev: new filter `pncp_lockdown_limited_caps` (string[]) to add capabilities refused while locked to roles that keep their work; the built-in ones cannot be removed. New `PNCP_Lockdown::limited_roles()` and `PNCP_Lockdown::staff_level()`.
* New: WooCommerce cart and checkout limits per IP (Limits tab, shown only when WooCommerce is active). Adding, changing and removing cart items, removing coupons and placing or paying for an order count toward "cart and checkout actions per minute" (default 60, 30 in Emergency Mode). Coupon codes tried count toward "coupon attempts per minute" too (default 10, 5 in Emergency Mode). Covered: the Store API (block cart and checkout, also each request inside a Store API batch), the wc-ajax cart actions, the same actions through admin-ajax.php (`woocommerce_apply_coupon`, `woocommerce_add_to_cart` and so on) and the classic forms (?add-to-cart=, the cart page coupon form, the checkout form). Address, shipping rate and cart fragment updates never count, so a real shopper is never affected. Above the limit: 429 with Retry-After, a Store API JSON error or a wc-ajax / admin-ajax JSON error. Staff who can edit posts or manage the shop, exempt users and always-allowed IPs are never limited. In "Monitor only" it only logs what it would block. 0 turns each limit off. The settings are in export / import and `wp scrapelock settings`.
* New: the log names the new reasons "WooCommerce cart / checkout actions per minute" and "WooCommerce coupon attempts per minute"; Site Health shows the two limits when WooCommerce is active.
* Fix: a request that ScrapeLock refuses inside a REST batch (for example a blocked IP calling the WooCommerce Store API batch) no longer ends the whole batch with a fatal error (HTTP 500) on WordPress 7; it gets its own 403 / 429 inside the batch answer.
* Fix: with watermarking on and "Watermark the full-size image too" off, visitors could still get the clean full-size image: the WooCommerce product gallery zoom and lightbox (data-large_image, the link around each gallery image, PhotoSwipe), the image a variation switches to, the product's structured data, the Product Gallery block and the Store API (`images[].src`) all pointed at the unwatermarked original. Visitors now get the largest watermarked size instead (one with the image's proportions where there is one), with its real width and height, so zoom and the lightbox keep working. Wherever WordPress would hand a visitor the clean full size of an image that has watermarked sizes (size "full", or a size the image does not have), the largest watermarked size is used. Staff (users who can edit posts, so shop managers too), exempt users and the admin screens keep the real full size, also in the WooCommerce REST API (wc/v3). The srcset behaviour is unchanged. New filter `pncp_watermark_replace_full` (return false for an attachment to keep the old behaviour).
* New: "Test connection" under "Blocking at the CDN" checks every step in one click and says what to change: Cloudflare can be reached (and how fast), the API token is valid and active (or disabled, expired, not valid yet, or expiring within 14 days), the zone exists and is active (or still pending, paused or moved) and which plan it has, the token may read and edit the IP Access rules (a test block at 203.0.113.x is added, found and removed again), how many IP Access rules the zone has, and how much of Cloudflare's API rate limit is left. Account-owned API tokens are recognised too. The same check runs when the connection is saved, and its result is shown on the settings page also when saving was refused.
* New: "Copy diagnostics" gives the result of the check as text for a support request: each step, the zone, the plan, the versions and Cloudflare's Ray IDs. It never holds the token.
* Fix: a wrong zone ID no longer makes ScrapeLock give up on the addresses it was blocking. Cloudflare's "invalid zone" and "could not route" answers (HTTP 400 or 404) used to be taken as "this one address was refused", so those bans were never sent again once the zone ID was corrected. They now stop the run like a refused token, with a clear message.
* Fix: an HTML page instead of an API answer (a Cloudflare error page such as 520 or 522, a Cloudflare "access denied" page for the server's address, a page of a proxy in between, an empty answer) is no longer taken as a refused token (which paused blocking at the CDN for an hour) or as a refused address (which gave up on that ban). It is retried within minutes, and the message says what happened.
* Cloudflare: clearer messages for each kind of refusal by Cloudflare: token not in the format of an API token (or a Global API Key), unknown or deleted token, token without the permission or without this zone, unknown zone ID. Messages include Cloudflare's error codes and Ray ID.
* Cloudflare: when Cloudflare cannot be reached, the message says why where it can: no answer within 10 seconds, DNS failure, outgoing connections blocked by the host's firewall, an SSL/certificate problem, or WP_HTTP_BLOCK_EXTERNAL in wp-config.php (with the WP_ACCESSIBLE_HOSTS fix).
* Cloudflare: looking up ScrapeLock's own rules at Cloudflare also works when Cloudflare's answer has no paging information, and when Cloudflare refuses the IPv6 search filter (the search then runs without it).
* Change: a run of the CDN sync starts no new API call after 15 seconds (was 20), and earlier when the request has less time left (for example after other scheduled tasks ran first in the same cron request), so it always ends within PHP's time limit; what is left is done by the next run a minute later. The plugin no longer raises the time limit itself.
* Dev: new filter `pncp_edge_rule_limit` (default 50,000, Cloudflare's documented limit per account on every plan), the number of IP Access rules used by the "Room for blocks" check.
* Plugin Check: ScrapeLock no longer calls `set_time_limit()`. The Lockdown file check reads files for at most 25 seconds per request (less when PHP's time limit leaves less), and on a very large site it goes on in the next scheduled run, started right away, instead of stopping with an incomplete pass. A fingerprint or a check is stored only once every folder was read, so nothing is compared half-way. Where the pass stopped is kept signed and tied to the current fingerprint: a value written in the database cannot hand it a list of "already read" files, and a record that does not match is never used to take a new fingerprint. An unlock, or the end of the lock, drops a pass that is still going on.
* Plugin Check: the comparison with the official WordPress.org checksums works the same way: the plugins it has no time for are compared in a run scheduled right away (before, they were listed as "cannot be compared" until the next day), and the Lockdown tab says when a fingerprint, a check or the comparison is still running in the background.
* Plugin Check: removing the ScrapeLock block from the uploads `.htaccess` checks the file with `wp_is_writable()`.
* Fix: Lockdown on several web servers sharing one database: if a connection to the database holds the code-check lock for longer than any code check takes (someone with the database password can see its name in the list of running queries), codes are checked with ScrapeLock's own lock after at most one 5-second wait, so app and recovery codes still work. It is logged and emailed (at most once an hour). If codes still answer "busy", the message now names SCRAPELOCK_UNLOCK.
* Fix: several web servers with their own wp-content: an unlock (or a new lock) done on one server no longer makes the others report "Lockdown data was changed outside WordPress". A newer lock, correctly signed, is followed and the server's own guard file is brought up to date; older or unsigned data is still refused. An unlock for a while is followed only by servers that are unlocked for a while themselves: the others stay locked until you unlock on them too (or lock again), because a copy of that unlock put back in the database after you locked again would look the same to a server that missed the lock. "Lock again now" works from any of them and locks them all.
* Fix: while locked, shop managers can edit customers through the WooCommerce REST API (wc/v3/customers) too, as in wp-admin and wp/v2/users. Staff accounts stay frozen.
* Fix: on the classic cart page, each "Apply coupon" counted as two coupon attempts (the cart reload after it was counted too), so a shopper could be refused after 3 codes in Emergency Mode. Only the attempt itself counts now.
* Fix: with "Watermark the full-size image too" off, visitors no longer get the clean full-size image from the REST API media endpoint (source_url, guid, description) or the attachment page (its link, and its redirect to the file when attachment pages are off).
* Fix: Cloudflare "Test connection": a test block that could not be removed is now queued and removed by the next run (or listed for removal by hand if Cloudflare keeps refusing), instead of staying at Cloudflare.
* Fix: Lockdown on several web servers: requests that keep sending wrong codes to one server, with the lock values copied and written back in the database, could keep a correct code on another server answering "busy" for as long as they kept going. A code that is correct (the app's current code or an unused recovery code) now goes before the others and gets in within about two seconds; wrong codes wait. This also covers sites without the database lock and without a writable lock file.
* Fix: the record of a database connection found holding the code-check lock is now signed. A value written in the database can no longer make a real code check look like an outside holder (which let more wrong codes be checked than the hourly limit) or reset when the administrator was last emailed about it. While such a holder was seen in the last day, requests that hold the database lock also take ScrapeLock's own lock, so the two never check codes at the same time.
* Readme: a shorter description, the Cloudflare checks of "Test connection" listed under External services, and the changelog of 3.4.0 and earlier moved to `changelog.txt`, so the readme stays within WordPress.org's limits.

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

= Older versions =
The changes of 3.4.0 and earlier are in `changelog.txt` in the plugin folder.
