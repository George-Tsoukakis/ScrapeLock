=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhube
Tags: ai crawlers, anti-scraping, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.2
Requires PHP: 7.4
Stable tag: 3.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Block AI scrapers like GPTBot, catch fake Googlebot, rate-limit content scraping per IP and guard WooCommerce. Runs on your server, no account.

== Description ==

Most content protection plugins disable right click in the browser. Scrapers and AI crawlers don't click or copy: they download the raw HTML, read the REST API and the feeds, or drive a (headless) browser. ScrapeLock works on the server, where automated copying actually happens, and leaves real visitors, customers and search engines alone.

* **Runs on your own server.** No account and no API key needed, and no visitor data sent anywhere by default. It downloads public IP lists; only if you turn on CDN blocking does it send the IPs it blocks to your own Cloudflare or Bunny account, with your API token (see External services).
* **Starts in Monitor only.** For its first 7 days a new install blocks nobody: requests that would be refused are logged as "Would block", so you can see what it would do and adjust before it enforces. You can switch Monitor only on again at any time.

= What it stops, and what it cannot =

| Who | Result | How |
|---|---|---|
| AI training crawlers that say who they are (GPTBot, ClaudeBot, CCBot, Bytespider…) | Stopped | Bot list, 403 |
| Fake Googlebot or Bingbot | Stopped | Official IP lists plus reverse and forward DNS |
| Fast scrapers from one IP (IPv6: one /64) | Stopped | Per-IP limits and temporary blocks |
| Scanners asking for .env, .git or backups | Stopped (optional) | Ban on the first probe |
| Scrapers spread over many IPs | Slowed | Data center limit, surge email, Emergency Mode |
| Headless browsers on home connections | Slowed | Human check, bot trap, limits |
| Copying by hand, screenshots, logged-in scraping | Cannot be stopped | Watermark, source link and TDM leave traces |
| Attackers who can run PHP on your server | Out of scope | No plugin can stop them |

Whatever a visitor sees has already reached their device, so nothing stops a determined human. ScrapeLock closes the automated routes and leaves traces.

= Who it is for =

* **Publishers, recipe, course and news sites:** block AI training but stay in AI search, keep post text out of the REST API, GraphQL and full-text RSS, TDM opt-out.
* **WooCommerce shops:** limits for the product catalogue (Store API too), cart actions and coupon attempts, private feeds for price comparison sites and Google Merchant.
* **Photographers:** watermarks with the clean originals kept, hotlink rules for Nginx, Apache and Cloudflare.
* **Directories and listing sites:** page, search and "page not found" limits, a stricter limit for data centers.
* **Agencies:** presets, settings export and import, WP-CLI and Site Health.

= Bots and crawlers =

* **Real search engines vs. fakes.** Googlebot, Bingbot, Applebot and Yandex are verified against their official IP lists and with reverse + forward DNS. Real crawlers are never limited or blocked; fakes get a 403.
* **AI training vs. AI search.** Training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended, Bytespider and more) are blocked. AI search assistants (OAI-SearchBot, ChatGPT-User, PerplexityBot, Claude-SearchBot and more) can be allowed with one option and are verified with their official IP lists, so your site still appears in AI answers with a link.
* robots.txt gets the AI crawler lines, Content Signals and the Disallow line of an invisible bot trap that catches bots ignoring it. robots.txt, llms.txt and llms-full.txt are never blocked.
* Generic HTTP libraries (curl, python-requests and the like, used by apps and integrations) pass by default; a strict option blocks them too, and the Log has an "Always allow this User-Agent" button.
* Optional blocking of headless browsers and of scripts that copy a browser's User-Agent but not its headers. A carefully disguised automated browser is not detected this way; the limits, the human check and the bot trap still apply to it.
* **New in 3.5, optional (off by default):** ban scanners on their first request for .env, .git, wp-config.php backups, database dumps and backup archives.

= Limits and blocks =

* Per-IP limits for pages, searches, REST / GraphQL, "page not found" (404) requests, sitemaps, visitors from data centers and, with WooCommerce, cart actions and coupon attempts (IPv6: per /64). Verified search engines and real shoppers are not affected.
* **3.5:** an anonymous request for a long list from the REST API (posts, pages, products) counts more toward the REST limit: 2 above 20 items per page, 3 above 50. Lists of up to 20 items and logged-in users count as before, and the WooCommerce cart and checkout are not counted. JSON 429 answers (REST API, GraphQL, cart) also carry `retry_after`, the seconds of their Retry-After header.
* IPs that keep exceeding the limits are blocked for a while, optionally also at Cloudflare or Bunny CDN ("Test connection" checks the token, the zone and the permissions).
* **Emergency Mode:** stricter limits for 1 hour to 3 days, then your settings return on their own. When traffic suddenly jumps, ScrapeLock emails you a one-click button to start it.
* Optional human check without a captcha: visitors who have not scrolled, tapped or typed get a stricter page limit.
* Optional country rules, from Cloudflare's or Bunny CDN's country header or the free DB-IP Lite database.
* Optional pre-cache check (the bot list, the limits and the blocks also apply to pages served by WP Super Cache, W3 Total Cache, Cache Enabler, WP Rocket and the like) and early check (stops known bots and blocked IPs before the theme and the other plugins load).
* Always-blocked IPs / CIDR and referrers, usernames hidden from visitors, and trusted proxies (Cloudflare, Bunny CDN, your own), so the real IP cannot be spoofed.

= Feeds, API and server rules =

* Post, page and product text hidden from the REST API, WPGraphQL and full-text RSS for visitors: the routes scrapers use instead of the HTML.
* RSS with a short excerpt only, or disabled; with full text, an optional "The post … first appeared on …" line.
* Private XML feeds (Skroutz, BestPrice, Google Merchant, ERP) with a token in a header or the URL; only its hash is stored, it can be rotated with a grace period, and each feed has statistics.
* Optional: hide the REST API map and the versions of WordPress, PHP and the plugins, turn off XML-RPC pingbacks, list the REST routes open to anyone.
* Ready-made Nginx, Apache and Cloudflare rules for your own site, so cached pages and static files are protected too.

= Check, test and tune =

* **Check a request (3.5, Log tab):** pick GPTBot, a fake Googlebot, curl, python-requests, a browser without browser headers, a real browser or your own request, or type an IP, User-Agent and address. ScrapeLock shows whether it would allow, block or limit it, why, and where it is set. Nothing is counted, logged or blocked. Copy-ready curl lines let you test for real from another computer, and the card lists what it does not simulate (the 404 limit, the cart, the early and pre-cache checks, the bot trap).
* Staff are exempt while logged in (by default), so the admin bar reminds you: test in a private window.
* **Site Health** warns about settings that do not work as intended. New in 3.5: it checks that crawlers really get ScrapeLock's robots.txt lines (a robots.txt file in the site's root replaces the one WordPress makes) and shows the lines to paste, that ScrapeLock's private folders cannot be read from the web, whether your text is still open through the REST API, full-text feeds or WPGraphQL while copy protection is on, and whether another plugin does the same job. These tests only fetch addresses of your own site and never write robots.txt.
* Settings that explain themselves (3.5): rejected IP lines are named after saving, unsaved changes are flagged, defaults are labelled, options that may affect visitors or SEO are tagged, and "Off" status pills link to their setting.
* Presets (Balanced, Strict, Maximum) with undo, settings export and import, and a block log with a 24-hour summary and automatic deletion.
* WP-CLI: `wp scrapelock status`, `block`, `unblock`, `blocked`, `emergency`, `log`, `check --ip=<ip>` (what ScrapeLock would answer, without side effects), `settings` and `lockdown status`.
* Abilities API (WordPress 6.9+) for administrators: read the summary, block or unblock an IP and start Emergency Mode from an AI agent or MCP client. None of them unlocks Lockdown.

= On the page and images =

* Block right click, copy, drag and common shortcuts, or allow copying with the source link appended. Text selection stays allowed by default, because blocking it also stops screen readers' "read selection" and translation tools.
* Printing with the page link at the bottom, or no printing; optional page blur on screenshot shortcuts; no framing by other sites.
* AI opt-out declaration (TDM): header, meta, `/.well-known/tdmrep.json`, `noai`.
* Watermark in a corner, the centre or repeated diagonally, optionally on the full-size image too; otherwise visitors get the largest watermarked size, also in the WooCommerce zoom, lightbox and Store API. The clean original is kept, so the watermark can always be removed. Product images are not watermarked by default, because Google Merchant Center rejects them.

= Lockdown =

* Freeze the site with a code from your authenticator app (Google Authenticator, Microsoft Authenticator, Authy and the like). While it is locked, nobody can change plugins, themes, WordPress core, users, roles or settings from wp-admin, the REST API or XML-RPC, not even an administrator or someone who stole a password.
* Administrators are frozen completely. Shop managers and other staff roles you do not tick keep their work (orders, products, coupons, posts, media), but not the rights that could take over the site. Visitors and customers browse, order, pay, register and comment as usual.
* Also enforced against code: a bug in another plugin cannot be used to activate plugins, change the site address or the admin email, add an administrator or unlock the lock. Code that can run its own PHP on your server can get around any plugin, ScrapeLock included.
* Sealed: the lock is signed with the keys in wp-config.php and kept outside the database (a guard file, a lock file, or a line in wp-config.php), so SQL injection in another plugin cannot unlock the site. Settings changed in the database are put back.
* File integrity: every PHP, .htaccess and .user.ini file is fingerprinted and checked every hour while locked, and WordPress and the plugins from WordPress.org are compared with their official checksums. New or changed files are emailed to you and shown in Site Health; optional quarantine.
* Unlock for 15 minutes to 2 hours for yourself only, or until you lock it again; every lock and unlock is logged and emailed. Ten one-time recovery codes for a lost phone. The QR code is drawn in your browser and the secret is stored encrypted, never sent anywhere.

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
2. Activate it. A new install runs in Monitor only for 7 days: watch the Log, then let it block.
3. If your site is behind Cloudflare or another proxy, set "Real visitor IP" first (Bots and limits).
4. Go to Settings → ScrapeLock and choose a preset, or adjust each tab.

Upgrading from "Content Protect" (folder `content-protect`), the former name of this plugin: deactivate the old plugin, activate ScrapeLock. Your settings, tokens and log are kept. If you pasted the old Apache rules, replace the "# BEGIN Content Protect" block with the new "# BEGIN ScrapeLock" block.

== Frequently Asked Questions ==

= My server's CPU spikes, often at night. Can ScrapeLock help? =

Often, yes: the cause is usually a crawler reading thousands of pages. Open the Log: the 24-hour summary shows the top IPs, User-Agents and reasons. The bot list, the per-IP limits and the data center limit handle most of it; during an attack, start Emergency Mode.

= GPTBot or Bytespider is eating my bandwidth. =

They are on the bot list, which is on by default, and are refused with a 403 (in Monitor only they are just logged). robots.txt also asks them to stay away. A 403 costs your server far less than a full page.

= Bots fill carts or try coupon codes. =

With WooCommerce, ScrapeLock limits cart actions and coupon attempts per IP and blocks IPs that keep going. It is not a fraud or card-testing tool: use your payment provider's fraud protection for that.

= Why don't I see these bots in Google Analytics? =

Most bots don't run JavaScript, so analytics never counts them. ScrapeLock sees them on the server, and Monitor only logs them without blocking anyone.

= Will it block real visitors, shoppers or forms? =

Verified search engines are never limited or blocked, there is no captcha, and the first 7 days are Monitor only. If someone is blocked, the Log shows why: unblock the IP under "IPs blocked now", add it to "Always allowed IPs", or press "Always allow this User-Agent".

= Isn't robots.txt enough? =

No. robots.txt is a request that only polite bots follow. ScrapeLock writes those lines for you and also enforces them on the server, where impolite bots get a 403.

= Does blocking right click stop AI scrapers? =

No. Scrapers download the page or read the REST API and the feeds; they never right-click. What stops them is the server side: the bot list, the limits and hiding your text from REST, GraphQL and RSS. Right-click blocking only slows down people copying by hand.

= I can still right-click and copy. Is it working? =

Probably: staff are exempt while logged in ("Who is excluded", On the page tab). Test in a private window: only there do you see the copy protection as visitors see it ("Check a request" tests the server-side checks, not the browser scripts).

= How do I test it? =

"Check a request" (Log tab) shows what ScrapeLock would answer to GPTBot, a fake Googlebot, curl and more, without sending anything. Its "Check it yourself" lines test for real with curl from another computer. With WP-CLI: `wp scrapelock check --ip=<ip> --ua=<user-agent>`.

= Can I use it with a security or firewall plugin? =

Yes, they do different jobs. Avoid two rate limits on the same pages (keep one, or set the other's limit higher), make both read the same real-IP header behind a CDN, and test in Monitor only first.

= Will it block Google or Bing? =

No. Verified search engines are never limited or blocked. Only fakes that pretend to be Googlebot or Bingbot are blocked.

= Can I allow ChatGPT or Perplexity search but block training? =

Yes. Turn on "Allow AI search engines and assistants" (Bots and limits). Training crawlers stay blocked. With "Verify AI search bots" on, only requests from the official addresses count as those bots; copies of the name get a 403.

= Can I let one partner's crawler in? =

Yes. Add it to "Always allowed User-Agents", pinned to its addresses so the name alone is not enough: `PartnerBot@203.0.113.0/24`. The page limit still applies to it.

= Does it work with page cache? =

ScrapeLock tells WP Rocket not to serve cached pages to the bots in its list. Other page cache plugins serve stored pages before WordPress loads: turn on the pre-cache check (Bots and limits) to apply the bot list, the page limits and the blocks to them too. Site Health tells you when a page cache answers first. A cache in the web server (Nginx FastCGI cache, LiteSpeed, Varnish) answers before PHP: there use the "Server rules" tab or blocking at the CDN.

= What does the pre-cache check change on my server? =

It adds two comment lines and one `include` line at the top of `wp-config.php`, which loads the check from the plugin's folder. Its data are plain files in a protected, randomly named folder in `uploads/scrapelock/` (counters in APCu if available). It runs before the page cache, without a database, and stops blocked IPs, the bot list and visitors over the page limits. Search engines, forms, wp-admin and the REST API are left to the normal check; a login cookie, which it cannot verify, gets four times the page limit. If `wp-config.php` is not writable, it shows the lines to add. Everything is removed when you turn it off or deactivate the plugin. Not on multisite.

= What is the early check? =

An optional file, `wp-content/mu-plugins/scrapelock-early.php`, that runs before the theme and the other plugins and stops blocked IPs and referrers, temporarily blocked IPs and the bot list with less server load. Search engines, logged-in users, forms and private feeds are left to the normal check. It is removed when you turn it off, deactivate or delete the plugin.

= My site is behind Cloudflare. What should I set? =

Set "Real visitor IP" to CF-Connecting-IP and keep "Trust Cloudflare addresses" on. When every visitor arrives from a Cloudflare address, ScrapeLock offers a button that does this. With Nginx, also set `real_ip_header CF-Connecting-IP;` and `set_real_ip_from` for the Cloudflare ranges, so the server rules see the real IP.

= My site is behind Bunny CDN. What should I set? =

If your server already replaces the IP, keep "REMOTE_ADDR". Otherwise set "Real visitor IP" to X-Real-IP and turn on "Trust Bunny CDN addresses". When every visitor appears with a Bunny address, a button does this for you.

= Can ScrapeLock block scrapers at Cloudflare or Bunny CDN? =

Yes. In "Blocking at the CDN", choose Cloudflare (an API token with only Zone → Firewall Services → Edit, for this zone) or Bunny CDN (your API key) and the zone ID; the token can go in `wp-config.php` (`SCRAPELOCK_EDGE_TOKEN`) instead of the database. Every temporary block is then also made at the CDN and removed when it ends. Your own rules are never changed; administrators' recent IPs, search engines and the CDN's addresses are never blocked there. Bunny CDN blocks single addresses only. Turning it off removes ScrapeLock's blocks.

= Can someone go around my CDN? =

If they find your server's own address, yes. "Only through the CDN" (Real visitor IP) refuses every request without a secret header, `X-ScrapeLock-CDN`, that your CDN adds (Bunny: Edge Rule; Cloudflare: Transform Rule). It can only be turned on from a request that has the secret. If the CDN stops sending it, add `define( 'SCRAPELOCK_CDN_ONLY', false );` to wp-config.php.

= What does "Ban scanners on their first probe" do? =

Off by default. When an IP asks for a file only attack scanners look for (.env, .git, wp-config.php backups, database dumps and backup archives at the top of the site) and the file does not exist, it is refused and blocked for 10 minutes (or your block time, if shorter; nothing is blocked when "Block after this many violations" is 0); a second probe within 24 hours gets the full block. Staff, verified search engines and the always-allowed IPs and User-Agents are never banned. On Nginx, add the updated server rules. With the rules, .env, .git, wp-config.php copies and SSH keys are never served even if they exist; a real database dump or archive of the same name is still served.

= Does the human check show a captcha? =

No. A small script waits for the first scroll, tap, key or mouse movement, solves a light challenge in the background and gets a cookie. Visitors without it are not blocked: they get a stricter page limit (20 per minute by default). Plain scripts never get the cookie.

= Can blocked bots still read robots.txt and llms.txt? =

Yes. robots.txt, llms.txt and llms-full.txt are never blocked, so every bot can read the rules it is asked to follow. If a robots.txt file in your site's root replaces the one WordPress makes, Site Health shows the lines to add to it.

= Can I customise it in code? =

Yes, with filters such as `pncp_client_ip`, `pncp_skip_guard`, `pncp_should_protect`, `pncp_known_ai_agents`, `pncp_ai_search_agents`, `pncp_rest_post_types`, `pncp_rest_hide_content`, `pncp_404_exempt`, `pncp_trap_exempt_agents`, `pncp_trap_first_ban_minutes`, `pncp_watermark_attachment`, `pncp_hotlink_allowed`, `pncp_use_apcu` and `pncp_log_rows_per_minute`; 3.5 adds `pncp_rest_cost`, `pncp_probe_trap_paths` and `pncp_conflicting_plugins`. The early and pre-cache checks run before plugins load, so filters in plugins and themes do not apply there. There is also WP-CLI and settings export and import.

= What personal data does it store? =

For a blocked request: the IP, User-Agent, page and time, deleted after 1, 7 or 30 days. With the human check, visitors who interact get a 7-day cookie, `pncp_hv`, holding only an expiry and a signature tied to their IP network and browser; it is not used for tracking. The country database is a local file.

= Does it guarantee legal protection of my content? =

No. The TDM declaration is a machine-readable reservation of rights; it does not guarantee legal compliance or stop anyone who ignores it.

= What does Lockdown freeze, and what keeps working? =

Frozen roles can log in but change nothing. Roles that can change plugins, themes, users or settings are always frozen; editors, authors, contributors and shop managers by default. Customers, members, visitors, orders, payments, webhooks, cron and comments are not affected. Shop staff cannot process orders in wp-admin while locked: unlock for a while.

= I lost my phone. How do I unlock the site? =

Type a recovery code instead of an app code. With none left, add `define( 'SCRAPELOCK_UNLOCK', true );` to wp-config.php, connect a new app on the Lockdown page, then remove the line. This also helps if you forget a staff password while locked.

= Can someone with access to my server bypass Lockdown? =

Yes. Lockdown guards against changes through WordPress; someone who can only write to the database (SQL injection in another plugin) cannot unlock it. Whoever can edit files controls the site anyway: the file integrity check finds new files within the hour, and the "No PHP in the uploads folder" server rule stops most backdoors from running.

= Can I unlock Lockdown from WP-CLI or with an AI agent? =

No, on purpose: only an app code, a recovery code or the SCRAPELOCK_UNLOCK line opens it. WP-CLI and the abilities can block IPs and start Emergency Mode; while locked the abilities can only read the summary.

== Screenshots ==

1. Block log: 24-hour summary by reason, top IPs and User-Agents, temporarily blocked IPs and the latest events.
2. Bots and limits: AI training crawlers, AI search assistants, fake search engine detection and the bot trap.
3. Feeds and API: token-protected XML feeds with per-feed statistics, and text hidden from REST, GraphQL and RSS.
4. Server rules: ready-made Cloudflare, Nginx and Apache rules generated for your own site.
5. Presets, Emergency Mode and the on-page protection settings.
6. Dashboard widget with the protection status and the last 24 hours.

== Changelog ==

= 3.5.0 =
* New: "Check a request" on the Log tab. Pick a preset (GPTBot, a fake Googlebot, curl, python-requests, a browser without browser headers, a real browser, your own request) or type an IP, User-Agent and address, and see whether ScrapeLock would allow, block or limit it, the reason, why, and a link to the setting. It runs the same side-effect-free check as `wp scrapelock check`: nothing is counted, logged or banned. The card says what it does not simulate (the 404 limit, cart and checkout limits, the early and pre-cache checks, the bot trap, server and CDN rules) and gives copy-ready curl lines built from the site's public address (never a token). Administrators only (nonce and `manage_options`), and not while the site is locked.
* New: the admin bar's "Protection" menu links to "Check a request" and reminds exempt staff to test in a private window.
* New: Site Health checks that crawlers get ScrapeLock's robots.txt lines (a robots.txt or llms.txt file in the site's root replaces the one WordPress makes; the lines to paste are shown, the file is never written), that the private folders (clean watermark originals, pre-cache data, country database) cannot be downloaded over HTTP (a throwaway test file, removed afterwards; the secret folder names are never shown), whether text is still open through the REST API, full-text feeds or WPGraphQL while copy protection is on, and whether another copy-protection, watermark or bot-blocking plugin is active while ScrapeLock's own feature for that job is on (filter `pncp_conflicting_plugins`). The two web checks only request the site itself, are cached for a day (an hour when the site could not be fetched) and can be run again with "Check again now".
* New: "Ban scanners on their first probe" (Bots tab, off by default). An IP asking for a file only attack scanners look for (.env, .git, wp-config.php backup copies, database dumps and backup archives at the top of the site, SSH keys, phpMyAdmin, Adminer, PHP files in uploads; the last three only when the web server passes the request to WordPress, which most Nginx setups and "No PHP in uploads" do not) that does not exist is blocked for 10 minutes, and for the full time on a second probe within 24 hours. Staff, verified search engines, always-allowed IPs and User-Agents and people who click a link are never banned, and "Monitor only" only logs it. Outside Monitor only, every request on the list that reaches WordPress gets the same 403, also for a file that exists, so the answer does not tell a scanner which files are on disk. The log reason is "probe". Also applied by the pre-cache check and by the generated Nginx / Apache rules (unchanged while the option is off). Filters: `pncp_probe_trap_paths`, `pncp_probe_ban`, `pncp_probe_first_ban_minutes`.
* Change: an anonymous REST API read of a list (wp/v2 posts, pages and other lists, WooCommerce products) counts 2 toward the REST limit above 20 items per page and 3 above 50. Up to 20 items, single items, logged-in users and the WooCommerce cart and checkout count as before. Filter: `pncp_rest_cost`.
* Fix: only the visitor's own REST request counts toward the REST limit. The reads WordPress makes inside it for `_embed` (categories, tags, replies of every post) and those other plugins make (e.g. WooCommerce Admin while /wp-json/ is built) counted too, so one headless page view with `_embed` could reach the limit; they are still checked for blocks and bans.
* Fix: a scanner's parallel first requests (bot trap, first probe) got the full block instead of the short first one.
* Fix: the generated Nginx rules now refuse the pre-cache check's data folder and the country database folder (uploads/scrapelock/, uploads/scrapelock-geo/), which Nginx served because it ignores their .htaccess files. Update the rules on the "Server rules" tab.
* Change: every JSON 429 answer (REST API, WooCommerce cart and coupon limits, wc-ajax / admin-ajax cart actions, WPGraphQL, the human check) carries `retry_after`, the same seconds as its Retry-After header. REST, wc-ajax and WPGraphQL 429s now send the real seconds left in the minute instead of a fixed 60, and the human check's 429 now sends Retry-After.
* New: settings form: after saving, rejected lines of the IP lists, the country lists and the allowed User-Agents are named in a notice; unsaved changes are marked next to Save and the browser asks before leaving; options that only work when another one is on are dimmed with a note (their values are still saved); defaults are labelled; options that may affect visitors or SEO are tagged; and "Off" status pills link to their setting.
* Readme: rewritten for WordPress.org (what it stops and what it cannot, who it is for, common questions).

The changes of 3.4.3 and earlier versions are in changelog.txt in the plugin folder.

