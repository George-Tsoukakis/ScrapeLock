=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhube
Tags: ai crawlers, anti-scraping, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.2
Requires PHP: 7.4
Stable tag: 3.12.7
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Block AI scrapers like GPTBot, catch fake Googlebot, rate-limit content scraping per IP and guard WooCommerce. Runs on your server, no account.

== Description ==

Most content protection plugins disable right click in the browser. Scrapers and AI crawlers don't click or copy: they download the raw HTML, read the REST API and the feeds, or drive a (headless) browser. ScrapeLock works on the server, where automated copying actually happens, and leaves real visitors, customers and search engines alone.

* **Runs on your own server.** No account and no API key needed, and no visitor data sent anywhere by default. It downloads public IP lists; only if you turn on CDN blocking does it send the IPs it blocks to your own Cloudflare or Bunny account, with your API token (see External services).
* **Starts in Monitor only.** For its first 7 days a new install blocks nobody: requests that would be refused are logged as "Would block", so you can see what it would do and adjust before it enforces. You can switch Monitor only on again at any time.

= New in 3.8: see where bots attack, and close it with one click =

* **Attack report (Attacks tab).** Where bots hit, also when nothing is refused: failed sign-ins and the usernames tried, how many try wp-admin and wp-login.php, XML-RPC calls, scanner and plugin probes, per day and hour, with country, "Block IP", CSV, a dashboard widget and an optional weekly email.
* **Vulnerable points.** Lock XML-RPC, wp-admin, the sign-in page, readme.html, PHP in uploads and more with one click, with the risk explained; Apache rules written with a self-test and rollback, Nginx rules to copy.
* **Sign-in protection.** Failed logins limited per IP and per username (wp-login.php, every XML-RPC multicall call, application passwords), one error message, and an optional sign-in address of your own.
* **Bunny CDN, deeper.** Reads your pull zone's logs to see attacks on cached pages, and locks wp-login.php, xmlrpc.php and .env/.git probes at Bunny. New in 3.9: every lock first shows what it would block and who hit it, and waits for your Confirm.
* **Stealth (optional).** BuiltWith and Wappalyzer get neutral addresses (/assets/…) instead of /wp-content/, another REST prefix and /sitemap.xml, without WordPress-only markup. Tested before it turns on.

= What it stops, and what it cannot =

| Who | Result | How |
|---|---|---|
| AI training crawlers that say who they are (GPTBot, ClaudeBot, CCBot, Bytespider…) | Stopped | Bot list, 403 |
| Fake Googlebot or Bingbot | Stopped | Official IP lists plus reverse and forward DNS |
| Fast scrapers from one IP (IPv6: one /64) | Stopped | Per-IP limits and temporary blocks |
| Scanners asking for .env, .git or backups | Stopped (optional) | Ban on the first probe |
| Site rippers (HTTrack, WebCopier, Offline Explorer…) and attacks in the User-Agent | Stopped | Built-in list, 403 |
| Scrapers that read only the REST API, feeds or sitemaps | Slowed (optional) | Limit for IPs that never opened a page |
| Scrapers spread over many IPs | Slowed | Data center limit, CrowdSec blocklist, IP reputation, surge email, Emergency Mode |
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
* **3.7:** site rippers (HTTrack, WebCopier, Offline Explorer…) and attacks in the User-Agent are blocked; optional: SEO data crawlers (Ahrefs, Semrush, Majestic…) and requests that use the site's IP instead of its name.

= Limits and blocks =

* Per-IP limits for pages, searches, REST / GraphQL, "page not found" (404) requests, sitemaps, visitors from data centers and, with WooCommerce, cart actions and coupon attempts (IPv6: per /64). Verified search engines and real shoppers are not affected.
* IPs that keep exceeding the limits are blocked for a while, optionally also at Cloudflare or Bunny CDN ("Test connection" checks the token, the zone and the permissions).
* **Emergency Mode:** stricter limits for 1 hour to 3 days, then your settings return on their own. When traffic suddenly jumps, ScrapeLock emails you a one-click button to start it.
* Optional human check without a captcha: visitors who have not scrolled, tapped or typed get a stricter page limit.
* **3.7, optional:** IP reputation (good IPs are never blocked for a limit, bad ones stay slowed for days), a limit for IPs that read only the API, feeds or sitemaps, the CrowdSec community blocklist, and fail2ban. See the FAQ.
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

* **Check a request (Log tab):** pick GPTBot, a fake Googlebot, curl, a real browser or your own IP, User-Agent and address, and see whether ScrapeLock would allow, block or limit it, and why. Nothing is counted, logged or blocked; copy-ready curl lines test it for real.
* Staff are exempt while logged in (by default), so the admin bar reminds you: test in a private window.
* **Site Health** warns about settings that do not work as intended: robots.txt lines that crawlers do not get, private folders readable from the web, text still open through the REST API, feeds or WPGraphQL, another plugin doing the same job. These tests only fetch your own site.
* Settings that explain themselves: rejected lines are named, unsaved changes flagged, defaults labelled, options that may affect visitors or SEO tagged.
* Presets (Balanced, Strict, Maximum) with undo, settings export and import, and a block log with a 24-hour summary and automatic deletion.
* **3.7:** visitors from AI assistants (ChatGPT, Perplexity, Claude, Gemini…) per assistant and page, counted on your server without personal data.
* **Traffic (3.12):** every request, from the Bunny CDN logs, your web server's access log or WordPress itself: User-Agents by family, pages answering 404 or 5xx with the links that lead there, visitors, CSV and email alerts. Kept only in your database; off until you start it.
* WP-CLI: `wp scrapelock status`, `block`, `unblock`, `blocked`, `emergency`, `log`, `check --ip=<ip>` (what ScrapeLock would answer, without side effects), `settings`, `lockdown status`, `reputation`, `crowdsec`, `ai-referrals`, in 3.8 `attacks`, `attack-report`, `login`, `harden`, `bunny` and `stealth`, in 3.12 `traffic`, in 3.12.6 `rules`, `cdn` and `verify-file`, and in 3.12.7 `cache`.
* Abilities API (WordPress 6.9+) for administrators: read the summary, block or unblock an IP and start Emergency Mode from an AI agent or MCP client. None of them unlocks Lockdown.

= On the page and images =

* Block right click, copy, drag and common shortcuts, or allow copying with the source link appended. Text selection stays allowed by default, because blocking it also stops screen readers' "read selection" and translation tools.
* Printing with the page link at the bottom, or no printing; optional page blur on screenshot shortcuts (for everyone, or only for visitors who are not signed in); no framing by other sites.
* AI opt-out declaration (TDM): header, meta, `/.well-known/tdmrep.json`, `noai`.
* Watermark in a corner, the centre or repeated diagonally, optionally on the full-size image too; otherwise visitors get the largest watermarked size, also in the WooCommerce zoom, lightbox and Store API. The clean original is kept, so the watermark can always be removed. Product images are not watermarked by default, because Google Merchant Center rejects them.

= Members, courses and paid content (3.6) =

* **Who is reading, on every screenshot:** a faint line over the page with the member's user name and the time, so a screenshot, a screen recording or a photo of the screen shows whose account it came from. No web page can block screenshots; this makes them traceable.
* **An invisible trace in the text:** copied text carries the account and the day, hidden in invisible characters. Paste it under Log → "Find whose copy this is".
* **Shared accounts:** a page limit per account, and an email when one account is used from several addresses at once, optionally signing it out everywhere else.
* **Fewer signs of WordPress** for tools such as BuiltWith and for scanners.

= Lockdown =

* Freeze the site with a code from your authenticator app (Google Authenticator, Microsoft Authenticator, Authy and the like). While it is locked, nobody can change plugins, themes, WordPress core, users, roles or settings from wp-admin, the REST API or XML-RPC, not even an administrator or someone who stole a password.
* Administrators are frozen completely. Shop managers and other staff roles you do not tick keep their work (orders, products, coupons, posts, media), but not the rights that could take over the site. Visitors and customers browse, order, pay, register and comment as usual.
* Also enforced against code: a bug in another plugin cannot be used to activate plugins, change the site address or the admin email, add an administrator or unlock the lock. Code that can run its own PHP on your server can get around any plugin, ScrapeLock included. While the site is unlocked for a while, these rules are off for code too: unlock only for as long as you need.
* Sealed: the lock is signed with the keys in wp-config.php and kept outside the database (a guard file, a lock file, or a line in wp-config.php), so SQL injection in another plugin cannot unlock the site.
* Changes made straight in the database to the plugins, theme, site address, admin email, roles and ScrapeLock's settings are put back; new administrators and changed staff passwords are refused at sign-in. See the FAQ for the full list.
* File integrity: every PHP, .htaccess and .user.ini file is fingerprinted and checked every hour while locked, and WordPress and the plugins from WordPress.org are compared with their official checksums. New or changed files are emailed to you and shown in Site Health; optional quarantine. When the site is locked again after an unlock, the files that changed while it was open are emailed to you too, before they become part of the new fingerprint.
* Unlock for 15 minutes to 2 hours for yourself only, or until you lock it again; every lock and unlock is logged and emailed. Ten one-time recovery codes for a lost phone. The QR code is drawn in your browser and the secret is stored encrypted, never sent anywhere.

== External services ==

ScrapeLock downloads public lists of IP addresses, only for the features that use them. Each download is a plain GET request for a public file, made from your server by WordPress (User-Agent "ScrapeLock/version"). No data about your site, your content or your visitors is sent, and the request does not include your site address; as with any download, the provider sees your server's IP address. The lists are stored in your database (or, for the country database, in uploads/scrapelock-geo) and checked on your server. They are data, not code or assets: no script, style, font or image is ever loaded from these addresses.

* **Google** crawler IP ranges, to tell real Googlebot from fakes. Downloaded once a day while protection is enabled, from https://developers.google.com/static/search/apis/ipranges/googlebot.json, https://developers.google.com/static/search/apis/ipranges/special-crawlers.json and https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Bing** crawler IP ranges, to tell real Bingbot from fakes. Downloaded once a day while protection is enabled, from https://www.bing.com/toolbox/bingbot.json. Provided by Microsoft Corporation: [Terms of service](https://www.microsoft.com/servicesagreement), [Privacy policy](https://privacy.microsoft.com/privacystatement).
* **Apple** crawler IP ranges (3.10), to tell real Applebot from fakes without a DNS lookup. Downloaded once a day while protection is enabled, from https://search.developer.apple.com/applebot.json. Provided by Apple Inc.: [Terms of use](https://www.apple.com/legal/internet-services/terms/site.html), [Privacy policy](https://www.apple.com/legal/privacy/).
* **DuckDuckGo** crawler IP addresses (3.10), to recognize the real DuckDuckBot. Downloaded once a day while protection is enabled, from https://duckduckgo.com/duckduckbot.json. Provided by Duck Duck Go, Inc.: [Terms of service](https://duckduckgo.com/terms), [Privacy policy](https://duckduckgo.com/privacy).
* **Cloudflare** IP ranges, to read the real visitor IP only from Cloudflare. Downloaded once a day only when "Real visitor IP" reads the CF-Connecting-IP or X-Forwarded-For header and "Trust Cloudflare addresses" is on, from https://api.cloudflare.com/client/v4/ips. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN** edge server addresses, to read the real visitor IP and country only from Bunny CDN. Downloaded once a day only when "Trust Bunny CDN addresses" is on and "Real visitor IP" reads the X-Real-IP or X-Forwarded-For header, or country rules are set, from https://bunnycdn.com/api/system/edgeserverlist and https://bunnycdn.com/api/system/edgeserverlist/IPv6. Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).
* **OpenAI** bot IP ranges (OAI-SearchBot, ChatGPT-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://openai.com/searchbot.json and https://openai.com/chatgpt-user.json. Provided by OpenAI: [Terms of use](https://openai.com/policies/terms-of-use/), [Privacy policy](https://openai.com/policies/privacy-policy/).
* **Perplexity** bot IP ranges (PerplexityBot, Perplexity-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://www.perplexity.com/perplexitybot.json and https://www.perplexity.com/perplexity-user.json. Provided by Perplexity AI, Inc.: [Terms of service](https://www.perplexity.ai/hub/legal/terms-of-service), [Privacy policy](https://www.perplexity.ai/hub/legal/privacy-policy).
* **Anthropic** bot IP ranges (Claude-SearchBot, Claude-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://claude.com/crawling/bots.json (3.10: plus Anthropic's published outbound range 160.79.104.0/21, built in, nothing downloaded). Provided by Anthropic PBC: [Terms of service](https://www.anthropic.com/legal/consumer-terms), [Privacy policy](https://www.anthropic.com/legal/privacy).
* **DB-IP Lite** country database, to apply the country rules. Downloaded once a month only when "Download the free country database" is on, from https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz (the current or the previous month). Lookups happen on your server. Licensed under CC BY 4.0 ("IP Geolocation by DB-IP"). Provided by db-ip.com: [Terms of service](https://db-ip.com/tos.php), [Privacy policy](https://db-ip.com/privacy.php), [License](https://creativecommons.org/licenses/by/4.0/).

The five data center lists below are used only for the "Data center limit" (Bots and limits), a stricter page limit for visitors that come from cloud servers rather than from home or mobile connections. Each one is downloaded once a day only while protection is enabled and "Data center limit" is above 0 (set it to 0 to turn the lists off). They are JSON or CSV data files fetched by your server with wp_remote_get(); nothing from these hosts is ever loaded in your visitors' browsers.

* **Amazon Web Services** IP ranges (only the EC2 servers are used), from https://ip-ranges.amazonaws.com/ip-ranges.json. Provided by Amazon Web Services, Inc.: [Terms](https://aws.amazon.com/service-terms/), [Privacy policy](https://aws.amazon.com/privacy/).
* **Google Cloud** IP ranges, from https://www.gstatic.com/ipranges/cloud.json, the address where Google publishes the list. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Oracle Cloud** IP ranges, from https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json. Provided by Oracle Corporation: [Terms of use](https://www.oracle.com/legal/terms/), [Privacy policy](https://www.oracle.com/legal/privacy/).
* **DigitalOcean** IP ranges, from https://digitalocean.com/geo/google.csv. Provided by DigitalOcean, LLC: [Terms of service](https://www.digitalocean.com/legal/terms-of-service-agreement), [Privacy policy](https://www.digitalocean.com/legal/privacy-policy).
* **Akamai Cloud (Linode)** IP ranges, from https://geoip.linode.com/. Provided by Akamai Technologies, Inc.: [Terms of service](https://www.akamai.com/legal/msa), [Privacy policy](https://www.akamai.com/legal/privacy-statement).

Lockdown's file check also compares WordPress and the plugins hosted on WordPress.org with their official checksums. This happens when you lock the site or press "Check now" on the Lockdown tab, and then at most once a day while the site stays locked, through the same WordPress.org services WordPress itself uses for updates. The requests contain the WordPress version and language (https://api.wordpress.org/core/checksums/1.0/) and, for each installed plugin, its slug and version (https://downloads.wordpress.org/plugin-checksums/SLUG/VERSION.json); no other data about your site, your content or your visitors is sent. Provided by WordPress.org: [Privacy policy](https://wordpress.org/about/privacy/).

**CrowdSec blocklist (3.7, off by default).** Only when you turn it on, ScrapeLock downloads a list of IP addresses from the address you enter, with the key you enter, and checks visitors against it on your server. No data about your site's visitors is sent; the request carries only your key (in the X-Api-Key header, or as HTTP Basic authentication) and the User-Agent "ScrapeLock/version".

* **Your own CrowdSec agent (LAPI)**, usually on the same server (for example http://127.0.0.1:8080): every 15 minutes, GET /v1/decisions/stream. The agent itself is CrowdSec software you install and run; whether it exchanges data with CrowdSec's central service is set in the agent. CrowdSec is provided by CrowdSec SAS: [Terms of use](https://www.crowdsec.net/terms), [Privacy policy](https://www.crowdsec.net/privacy-policy).
* **A blocklist address** you choose, for example a CrowdSec Console blocklist integration (https://admin.api.crowdsec.net/…) or another provider's plain-text list: downloaded once an hour. The provider is the one you choose; their terms and privacy policy apply.

Optional blocking at the CDN (off by default) uses the API of the CDN you choose, with your token. It sends only the IPs ScrapeLock blocks temporarily (IPv4, IPv6 or an IPv6 /64), each with the reason and end time, and removes them when the block ends. Saving the setting, or "Test connection", checks the token and the zone; with Cloudflare it also adds a test block for a documentation address (203.0.113.x) and removes it again.

* **Cloudflare API** (IP Access rules of your zone), only when the CDN is set to Cloudflare: https://api.cloudflare.com/client/v4/zones/ZONE_ID/firewall/access_rules/rules, and for the check https://api.cloudflare.com/client/v4/user/tokens/verify (or /accounts/ACCOUNT_ID/tokens/verify) and /zones/ZONE_ID. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN API** (blocked IPs of your Pull Zone), only when the CDN is set to Bunny CDN and, for the temporary blocks, "Send temporary blocks to the CDN" is on (3.9): https://api.bunny.net/pullzone/PULL_ZONE_ID (addBlockedIp, removeBlockedIp, and reading the zone's list of blocked IPs). Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).

**Bunny CDN, deeper (3.8, off until you use it).** With the Bunny CDN connection of "Blocking at the CDN" (or a pull zone ID and API key entered in the Bunny card), and your API key:

* **Bunny CDN logging API (logging.bunnycdn.com)** – only when "Import attacks from Bunny CDN's logs" is on: every 15 minutes the site downloads the new lines of its own pull zone's log, from https://logging.bunnycdn.com/DATE/PULL_ZONE_ID.log. Nothing about your visitors is sent; the log Bunny returns contains your visitors' IPs, addresses asked for, referrers, User-Agents and countries. Only attack-looking lines are kept, unless Traffic collects (3.12): then every line is kept in your own database for the days you choose. Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).
* **Bunny CDN API (api.bunny.net)** – when Bunny CDN is connected: reads the pull zone (https://api.bunny.net/pullzone/PULL_ZONE_ID: logging status, Edge Rules); when you click "Lock at Bunny" or "Turn on logging at Bunny" it creates, updates or deletes Edge Rules made by ScrapeLock (URL patterns, a description starting with "ScrapeLock:", and for the login page the IPs administrators used in the last 30 days) or turns logging on. Same provider and terms as above.

Vulnerable points and Stealth (3.8) only request the site's own pages and files, from the site itself (loopback), to check what a visitor gets. The weekly attack report and the sign-in protection's emails go through the site's own wp_mail().

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

= Can it stop screenshots or screen recording? =

No, and no plugin can: the screenshot is taken by the phone's or the computer's own system, and a web page is not even told about it. (A black screen happens only with DRM-protected video, and even then a photo of the screen works.) What ScrapeLock does instead: "Show who is reading over protected pages" puts the member's user name and the time on every screenshot, recording and photo, and "Hide an invisible trace of the account in the text" marks copied text. Both are on the "On the page" tab, under Members and readers.

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

Yes. Turn on "Allow AI search engines and assistants" (Bots and limits). Training crawlers stay blocked. With "Verify AI search bots" on, only requests from the official addresses count as those bots; copies of the name get a 403. Turn the option off and ScrapeLock blocks them again from its own list, whether or not they are in your bot list.

= Does ScrapeLock block WP Rocket's or Jetpack's own services? =

No, while the plugin is active. WP Rocket's service bot (WP-Rocket-SaaS, for Remove Unused CSS and critical CSS) and its cache preload (WP Rocket/Preload), and Jetpack's servers and uptime monitor, are allowed like "Always allowed User-Agents" as long as that plugin is active. "Bots and limits" → "Always allowed" lists them, with a button to stop allowing each one. The page limits, the bot trap and the attack checks still apply to them. Developers can add other plugins' bots with the `pncp_plugin_bots` filter.

= Can I let one partner's crawler in? =

Yes. Add it to "Always allowed User-Agents", pinned to its addresses so the name alone is not enough: `PartnerBot@203.0.113.0/24`. The page limit still applies to it.

= Does it work with page cache? =

ScrapeLock tells WP Rocket not to serve cached pages to the bots in its list. Other page cache plugins serve stored pages before WordPress loads: turn on the pre-cache check (Bots and limits) to apply the bot list, the page limits and the blocks to them too. Site Health tells you when a page cache answers first. A cache in the web server (Nginx FastCGI cache, LiteSpeed, Varnish) answers before PHP: there use the "Server rules" tab or blocking at the CDN.

= Does ScrapeLock empty the Nginx fastcgi cache? =

Yes, where it empties the page caches (settings saved, Stealth turned on or off), when it knows the cache folder: set `define( 'SCRAPELOCK_FASTCGI_CACHE_PATH', '/path/to/fastcgi/cache' );` in wp-config.php, or Nginx Helper's `RT_WP_NGINX_HELPER_CACHE_PATH` (or its "Delete local server cache files" method). On the server, `wp scrapelock cache status` reads the Nginx configuration (nginx -T) to find the folder of the zone this site's server block uses with fastcgi_cache, and prints the line to add; `wp scrapelock cache purge --all` (and `wp scrapelock cdn purge --all`) empties it. Only cache files whose key names this site's host are deleted, never files of other sites, links or folders outside it.

= What does the pre-cache check change on my server? =

It adds two comment lines and one `include` line at the top of `wp-config.php`, which loads the check from the plugin's folder. Its data are plain files in a protected, randomly named folder in `uploads/scrapelock/` (counters in APCu if available). It runs before the page cache, without a database, and stops blocked IPs, the bot list and visitors over the page limits. Search engines, forms, wp-admin and the REST API are left to the normal check; a login cookie, which it cannot verify, gets four times the page limit. If `wp-config.php` is not writable, it shows the lines to add. Everything is removed when you turn it off or deactivate the plugin. Not on multisite.

= What is the early check? =

An optional file, `wp-content/mu-plugins/scrapelock-early.php`, that runs before the theme and the other plugins and stops blocked IPs and referrers, temporarily blocked IPs and the bot list with less server load. Search engines, logged-in users, forms and private feeds are left to the normal check. It is removed when you turn it off, deactivate or delete the plugin.

= My site is behind Cloudflare. What should I set? =

Set "Real visitor IP" to CF-Connecting-IP and keep "Trust Cloudflare addresses" on. When every visitor arrives from a Cloudflare address, ScrapeLock offers a button that does this. With Nginx, also set `real_ip_header CF-Connecting-IP;` and `set_real_ip_from` for the Cloudflare ranges, so the server rules see the real IP.

= My site is behind Bunny CDN. What should I set? =

If your server already replaces the IP, keep "REMOTE_ADDR". Otherwise set "Real visitor IP" to X-Real-IP and turn on "Trust Bunny CDN addresses". When every visitor appears with a Bunny address, a button does this for you.

= Can ScrapeLock block scrapers at Cloudflare or Bunny CDN? =

Yes. In "Blocking at the CDN", choose Cloudflare (an API token with only Zone → Firewall Services → Edit, for this zone) or Bunny CDN (your API key) and the zone ID; the token can go in `wp-config.php` (`SCRAPELOCK_EDGE_TOKEN`) instead of the database. "Save and test the connection" only connects and tests. Once you turn on "Send temporary blocks to the CDN" (3.9; off on new sites, kept on for sites that already sent their blocks), every temporary block is also made at the CDN and removed when it ends. Your own rules are never changed; administrators' recent IPs, search engines and the CDN's addresses are never blocked there. Bunny CDN blocks single addresses only. Turning it off removes ScrapeLock's blocks.

= Can someone go around my CDN? =

If they find your server's own address, yes. "Only through the CDN" (Real visitor IP) refuses every request without a secret header, `X-ScrapeLock-CDN`, that your CDN adds (Bunny: Edge Rule; Cloudflare: Transform Rule). It can only be turned on from a request that has the secret. If the CDN stops sending it, add `define( 'SCRAPELOCK_CDN_ONLY', false );` to wp-config.php.

= Does ScrapeLock block the site's own requests (Site Health, Vulnerable points, cron)? =

No. WordPress signs every request to the site's own address with an `X-ScrapeLock-Sig` header (an HMAC of the method, host and path, valid for 60 seconds and once), so it passes every check, also behind a CDN and in the pre-cache check. ScrapeLock also learns the address the server's requests leave from and never blocks it, at the CDN either. If your server's own requests leave from an address ScrapeLock cannot learn (a NAT gateway, an outbound proxy, another server of a cluster), list it in wp-config.php: `define( 'SCRAPELOCK_SERVER_IPS', '203.0.113.50, 2001:db8::/64' );` (addresses or ranges, separated by commas). List only your own servers, never a proxy or load balancer in front of the site: every visitor comes through it.

= Vulnerable points says "Checked at the server: … refused by …". What does it mean? =

The site asked for its own home page through its public address, and something on the way refused it. ScrapeLock then asked your server directly, so the result is still real, and the note names who refused. What to check:

* **Bunny CDN edge:** "Forward Host Header" is not needed any more (3.12.2). In the pull zone, check Bunny Shield or the WAF, bot protection, blocked IPs and countries, and Edge Rules that block: one of them refuses your server's own address. ScrapeLock removes its own CDN blocks of that address at once.
* **Cloudflare:** Security → Events for your server's address, then allow it.
* **Wordfence:** Firewall → Blocking and Live Traffic; add your server's address to its allowlisted IPs.
* **Another plugin or the web server:** its deny rules or firewall.
* **ScrapeLock:** the note names the check that refused it.

To see both sides of the request, use "Run a real self-check now" in Log → Check a request (or the preset "The site itself (loopback)", which shows each layer without sending anything), the Site Health test "ScrapeLock self-request test", or `wp scrapelock selfcheck --log`.

= What does "Ban scanners on their first probe" do? =

Off by default. When an IP asks for a file only attack scanners look for (.env, .git, wp-config.php backups, database dumps and backup archives at the top of the site) and the file does not exist, it is refused and blocked for 10 minutes (or your block time, if shorter; nothing is blocked when "Block after this many violations" is 0); a second probe within 24 hours gets the full block. Staff, verified search engines and the always-allowed IPs and User-Agents are never banned. On Nginx, add the updated server rules. With the rules, .env, .git, wp-config.php copies and SSH keys are never served even if they exist; a real database dump or archive of the same name is still served.

= Does the human check show a captcha? =

No. A small script waits for the first scroll, tap, key or mouse movement, solves a light challenge in the background and gets a cookie. Visitors without it are not blocked: they get a stricter page limit (20 per minute by default). Plain scripts never get the cookie.

= Can blocked bots still read robots.txt and llms.txt? =

Yes. robots.txt, llms.txt and llms-full.txt are never blocked, so every bot can read the rules it is asked to follow. If a robots.txt file in your site's root replaces the one WordPress makes, Site Health shows the lines to add to it.

= Which visitors from AI assistants are counted? =

A page view by a visitor (not your staff) whose referrer is ChatGPT, Perplexity, Claude, Gemini, Copilot, DeepSeek, Grok, Le Chat, Meta AI, You.com, Phind or Kagi, or whose address carries their utm_source (ChatGPT adds utm_source=chatgpt.com). One count per day, assistant and page; no IP, User-Agent or cookie is stored. Pages served by a page cache without reaching WordPress are not counted. Filter `pncp_ai_referrers` adds others. Turn it off under Log → Log settings.

= How does the IP reputation work? =

Off by default (Bots and limits → Reputation). For each IP (IPv6: its /64) ScrapeLock keeps, for 7 days, when it last did something that tells about it: signed in (+80), passed the human check (+60), read pages (+10); the bot trap (−100), a scanner probe or an attack in the request (−80), a fake search engine (−70), a temporary block (−60), a bot-list refusal (−40), a limit exceeded (−20). Older events count about half. At 100 or more the IP is never blocked temporarily for exceeding a limit (it still gets "too many requests"); at −40 or less it gets the stricter page limit. `wp scrapelock reputation <ip>` shows the score; unblocking an IP by hand forgets it. Filters: `pncp_reputation_weights`, `pncp_reputation_good`, `pncp_reputation_bad`.

= How do I connect CrowdSec? =

On a VPS: install CrowdSec (it subscribes to the community blocklist on its own), run `cscli bouncers add scrapelock`, and in Bots and limits → CrowdSec blocklist choose "From my CrowdSec agent", enter http://127.0.0.1:8080 and the key. Without your own agent (shared hosting), create a blocklist integration in the CrowdSec Console and enter its address with user:password as the key. "Stricter page limit" is the safer choice: addresses change hands. Private addresses, ranges wider than /16 (IPv6 /32), your server, CDN edges and official search engine addresses are never taken from a list. `wp scrapelock crowdsec status` shows the state.

= How do I use fail2ban with ScrapeLock? =

Turn on "Write each temporary block to the system log" (Bots and limits → Temporary block), then copy the filter and the jail from the Server rules tab to /etc/fail2ban/filter.d/scrapelock.conf and /etc/fail2ban/jail.d/scrapelock.local, check logpath (/var/log/auth.log on Debian and Ubuntu, /var/log/secure on Red Hat) and run `fail2ban-client reload`. The line looks like `scrapelock[1234]: ban 203.0.113.5 for 60 minutes reason=rate_page site=example.com`. Blocks made by the pre-cache check before WordPress loads are not written.

= Where do I see which points bots attack, and how do I close them? =

Settings → ScrapeLock → Attacks. Choose 24 hours, 7, 30 or 90 days: you get the attacks per day and hour, the kinds of attack, the addresses attacked most, the wp-admin and sign-in attempts with the usernames tried, the IPs (with country and reputation) and what the Bunny CDN edge saw. Next to an address, "Lock this" closes that point (Vulnerable points); next to an IP, "Block 24 h" or "Always block". Search engines, CDN addresses and your own address cannot be blocked there. "Download the report (CSV)" exports it, and "Weekly attack report by email" (Log tab) sends a summary every Monday. `wp scrapelock attacks --top=users` lists the usernames tried.

= Can I see the access log, which User-Agents hit the site and which pages fail? =

Settings → ScrapeLock → Traffic (off until you press "Start collecting"). It reads the Bunny CDN logs when their import is on (they include the pages served from the CDN cache), else the web server's access log, else the pages WordPress serves itself. You get the requests over time, the User-Agents by family (browsers, verified and fake search engines, AI bots, scripts…), the pages that answer 404 or 5xx with the links that lead there (a link on your own site is marked as the one to fix), redirects, pages not served from the cache, the largest and slowest pages, the IPs and countries, and every single request with "Export CSV". From a User-Agent you can block it or always allow it, after a confirmation that shows the exact line added. Everything stays in your database: each request is kept 3 days by default, the daily figures 90 days, and IPs can be stored masked (the last part removed: IPv4 /24, IPv6 /48). "Start collecting" asks how IPs are stored, with Masked chosen in advance; new installs store them masked by default. The suggested privacy policy text (Settings → Privacy) describes Traffic, its retention and the IP setting.

= What does the attack report record? =

Failed sign-ins (with the username tried), visits to wp-login.php and /wp-admin/ that do not sign in, XML-RPC calls (each call of a system.multicall), ?author=N and the REST users list, scanner probes, "page not found" under /wp-content/plugins/ and /themes/, SQL/script/path patterns in the address (recorded only) and every request ScrapeLock refused. One row per hour, address and IP; a normal page view writes nothing. Exempt staff, verified search engines and the server itself are not recorded. Turn it off with "Record where bots and attackers hit the site" (Log settings). install.php and upgrade.php run without plugins, so they are recorded only with "Early check" on (and from the Bunny CDN logs); setup-config.php is seen only in the CDN or server logs. The "WordPress's own files" point closes all three.

= What does "Vulnerable points" lock, and can it break my site? =

Each point lists what it protects, how many attacks reached it, and what may stop working (for example Jetpack and the mobile app use XML-RPC; "Allow Jetpack" keeps Jetpack working). Low-risk points can be locked together. Points that only the web server can enforce (WordPress's own files, PHP in wp-includes or wp-content, directory listing) come with Apache and Nginx rules; on Apache ScrapeLock can write them into .htaccess, tests the site right after and puts the file back on its own if the site stops answering. Every point opens again with one click (or `wp scrapelock harden revert <id>`).

= I moved the sign-in page and forgot the address =

Add define( 'SCRAPELOCK_LOGIN_SLUG_OFF', true ); to wp-config.php: wp-login.php works again. Sign in, look up or change the address (Bots and limits → Sign-in), then remove the line. "wp scrapelock login url" prints it too. In Monitor only both addresses work.

= Can password guessing lock me out of my own account? =

No. A username under attack is paused for a few minutes, but not for IPs it signed in from before, and its email gets a one-time link that lets you sign in at once. "Lost your password" always works. Too many wrong passwords from one IP block that IP for a while (30 minutes by default); `wp scrapelock login unlock <ip>` lifts it.

= My site is behind Bunny CDN. What does ScrapeLock do with it? =

Under Bots → Blocking at the CDN, the Bunny card reads the pull zone's logs (turn on logging at the pull zone; ScrapeLock has a button for it) and records attacks Bunny answered from its cache, which WordPress never saw. "Lock at Bunny" creates an Edge Rule in your own Bunny account that blocks an address (wp-login.php except your IPs, xmlrpc.php, .env/.git probes, readme.html…) before it reaches your server. Before every lock, ScrapeLock shows the addresses it cuts, the requests and IPs that hit them in the last 7 days and which of those IPs also used the site normally; nothing is sent before you click Confirm. wp-login.php is locked only when "Allowed IPs for the login page at Bunny" holds your current IP (an IPv6 /64 is fine). Bunny accepts at most 5 addresses or IPs in one condition, so a longer list is sent as several conditions of one rule, or as several rules "ScrapeLock: … (1/3)"; they are one lock in ScrapeLock (one Remove removes them all, and if one cannot be made, none is kept). "Allowed IPs for the login page at Bunny" holds at most 15 entries. ScrapeLock only changes rules it created (their description starts with "ScrapeLock:"); in Monitor only they are switched off. If a lock of wp-login.php keeps you out after your IP changed, remove the rule in the bunny.net dashboard or run wp scrapelock bunny unlock preset_login.

= Can ScrapeLock hide that my site runs on WordPress? =

Mostly. Turn on Stealth (Vulnerable points tab). Visitors then get neutral addresses for the theme, plugin, media and core files, served by rules that ScrapeLock writes into .htaccess on Apache or that you add to Nginx; the site tests them first and never turns them on if a file would not load. The REST API can get another prefix, the sitemap becomes /sitemap.xml, and readme.html and the like answer "page not found". The footer comments of WP Rocket and Redis Object Cache and the file paths in script translations go too. Move the sign-in address too (Sign-in protection). What cannot be hidden: block and WooCommerce class names the styles depend on, cookies of signed-in users and shoppers, your hosting and DNS. WHOIS shows who registered the domain, not what the site is built with (use your registrar's privacy option for that). If the site ever loses its styles after moving host, add define( 'SCRAPELOCK_STEALTH_OFF', true ); to wp-config.php.

= Where do the Stealth rules go on Nginx and aaPanel, and how do I know they are current? =

Inside the site's server { }, at its top level and above the WordPress rewrite: panels such as aaPanel, BT Panel and CloudPanel put that rewrite at server level (if (!-e $request_filename) { rewrite … }), and it runs before any location. On aaPanel, save them as a file of their own in /www/server/panel/vhost/nginx/extension/<site>/, after scrapelock.conf (the files there are read in alphabetical order), e.g. z-scrapelock-stealth.conf: that folder is included at the top of the site's server { }, before the rewrite include. Then nginx -t, reload, and "Test again" in Stealth. The rules carry a fingerprint: Server rules → Stealth (and Site Health) says whether they are installed and up to date, out of date, or not found, asking the server directly first. After the folder of the addresses changes or a plugin or theme is added, ScrapeLock asks you to copy them again. With WP Rocket, Autoptimize, LiteSpeed Cache or W3 Total Cache, the inner wp-content / wp-includes of their minified and combined files get neutral codes too; the rules map them back by pattern, so files written after "Clear cache" keep working.

= How do I check what visitors get with Stealth? =

Run `wp scrapelock stealth check` (or `wp scrapelock stealth check <page of the site>`, 3.12.8). It asks for the page as a visitor gets it, through the page cache and the CDN, and prints how many wp-content and wp-includes are left, WP Rocket's minified addresses, the codes of the inner words, the cache headers and up to five addresses that still show a folder name. "words not used" means the server rules have words the pages are not rewritten with yet: run `wp scrapelock stealth test` ("Test again"). ScrapeLock now also tests a new address map by itself and uses it as soon as the server serves its rules. For a closer look add define( 'SCRAPELOCK_STEALTH_DEBUG', true ); to wp-config.php (or a number of hours, 1 to 72; the default is 24). Each page then writes one line per stage (Stealth's buffer, the optimization plugin's filter before and after) with counts only: no IP, User-Agent or query string, at most 256 KB, in uploads/scrapelock/ under a name that cannot be guessed. It stops by itself after those hours; `wp scrapelock stealth debug` prints the last lines and `--clear` deletes the log. Remove the line when done.

= Can WP-CLI install the server rules for me (aaPanel)? =

Yes (3.12.6). `wp scrapelock rules show --part=nginx-http` (or `nginx-server`, `stealth-nginx`, `stealth-apache`, `apache`) prints a part exactly as the Server rules tab shows it. `wp scrapelock rules status` says whether the installed rules are current, out of date or not found, how the server was asked and both fingerprints (`--format=json` too). `wp scrapelock rules install` writes only the files you name: each one first as `<file>.new`, shows the diff, keeps the old file as `<file>.old`, runs `nginx -t`, reloads, removes the `.old` files and prints the status; when the test or the reload fails, every file is put back as it was. `--dry-run` only shows the diff. On aaPanel, as root, with `<site>` the site's folder name and `<id>` the name of part 1's file:

`wp --allow-root --skip-themes scrapelock rules install --nginx-http=/www/server/panel/vhost/nginx/0.scrapelock-<id>.conf --nginx-server=/www/server/panel/vhost/nginx/extension/<site>/scrapelock.conf --stealth=/www/server/panel/vhost/nginx/extension/<site>/z-scrapelock-stealth.conf --dry-run`

Then the same without `--dry-run` (add `--yes` to skip the question). Nginx files must end in .conf, Apache files be .htaccess (only ScrapeLock's block is replaced) or end in .conf; a symlink is written through only into its own folder, and a leftover .old stops it. If nginx is not on the PATH, give `--test-cmd="/www/server/nginx/sbin/nginx -t" --reload-cmd="/www/server/nginx/sbin/nginx -s reload"`: these two run through the shell exactly as typed. It never runs from a web request, and not while the site is locked. `wp scrapelock cdn purge <address>…` (or `--all --yes`) purges this site's addresses at Bunny CDN and Cloudflare with the keys stored in ScrapeLock, which are never printed; addresses of other hosts are refused. It first empties the page caches of the active cache plugins (WP Rocket, LiteSpeed Cache, W3 Total Cache, WP Super Cache, WP Fastest Cache, Nginx Helper, Cache Enabler, SiteGround Optimizer; `--no-plugin-cache` to skip), then the server's fastcgi cache, then the CDN, so no cache stores an old page again. WP Rocket's minified CSS / JS files stay unless you add `--minify` (with `--all`): use it after Stealth's words or addresses change, since those files keep the addresses they were made with.

= A service asks me to put a file on my site to verify it. The bot list blocks it. =

Use Server rules → Verification files, or `wp scrapelock verify-file add /builtwith.txt --content=<the code>`. The file (one name at the root, e.g. /builtwith.txt, /google<code>.html, /BingSiteAuth.xml, or a name under /.well-known/; text only, at most 64 KB) is served by WordPress to every bot, also to one the bot list or "Block technology profilers" blocks, for 24 hours (1 to 168), then removed. It is purged at your CDN when added and when removed, and robots.txt lets the blocked bots read it. Server rules that block bots (Nginx part 1, Apache) let it through once you copy them again (or `wp scrapelock rules install`); their fingerprint does not change for it. "Also write it to the site's root folder" is only needed when the server answers that address without WordPress; it never replaces a file that is there. An HTML or XML file with markup needs the unfiltered_html capability.

= Does a REST API list count more toward the REST limit? =

Yes (3.5): an anonymous request for a long list from the REST API (posts, pages, products) counts 2 above 20 items per page, 3 above 50. Lists of up to 20 items and logged-in users count as before, and the WooCommerce cart and checkout are not counted. JSON 429 answers (REST API, GraphQL, cart) also carry `retry_after`, the seconds of their Retry-After header.

= Can I customise it in code? =

Yes, with filters such as `pncp_client_ip`, `pncp_skip_guard`, `pncp_should_protect`, `pncp_known_ai_agents`, `pncp_ai_search_agents`, `pncp_rest_post_types`, `pncp_rest_hide_content`, `pncp_404_exempt`, `pncp_trap_exempt_agents`, `pncp_trap_first_ban_minutes`, `pncp_watermark_attachment`, `pncp_hotlink_allowed`, `pncp_use_apcu` and `pncp_log_rows_per_minute`; 3.5 adds `pncp_rest_cost`, `pncp_probe_trap_paths` and `pncp_conflicting_plugins`; 3.7 adds `pncp_ripper_agents`, `pncp_seo_agents`, `pncp_malicious_ua_patterns`, `pncp_host_is_foreign_ip`, `pncp_reputation_weights`, `pncp_reputation_good`, `pncp_reputation_bad`, `pncp_crowdsec_listed`, `pncp_crowdsec_max`, `pncp_crowdsec_range_ok`, `pncp_ai_referrers` and `pncp_syslog_facility`. The early and pre-cache checks run before plugins load, so filters in plugins and themes do not apply there. There is also WP-CLI and settings export and import.

= What personal data does it store? =

For a blocked request: the IP, User-Agent, page and time, deleted after 1, 7 or 30 days; over a per-account limit, also the account's username. The attack record (3.8) keeps the IP, the address asked for, the hour and, for a failed sign-in, the username tried, for 7, 30 or 90 days. The sign-in protection keeps, per account, a keyed hash of the IPs it signed in from (180 days). With IP reputation (3.7, off by default): for each IP, stored under a hash, when it last read pages, passed the human check, signed in or was refused, for 7 days. Visits from AI assistants are counted per day and page only. With the human check, visitors who interact get a 7-day cookie, `pncp_hv`, holding only an expiry and a signature tied to their IP network and browser; it is not used for tracking. The country database is a local file.

= Does it guarantee legal protection of my content? =

No. The TDM declaration is a machine-readable reservation of rights; it does not guarantee legal compliance or stop anyone who ignores it.

= What does Lockdown freeze, and what keeps working? =

Frozen roles can log in but change nothing. Roles that can change plugins, themes, users or settings are always frozen; editors, authors, contributors and shop managers by default. Customers, members, visitors, orders, payments, webhooks, cron and comments are not affected. Shop staff cannot process orders in wp-admin while locked: unlock for a while.

What is put back when it is changed straight in the database: the active plugins and theme, the site address, the admin email, registration and the default role, the roles, the uploads folder, search engine visibility, the widgets, the theme's settings, WooCommerce's own payment methods and bank accounts, and ScrapeLock's own settings (more with the filter `pncp_lockdown_protected_options`). New administrators, new application passwords for staff and changed staff passwords are refused at sign-in and emailed. A capability given to one user alone, outside their role, does not work while the site is locked. The Site Editor's templates and template parts cannot be changed by code while locked; templates, template parts and global styles changed straight in the database are found every hour.

What it does not keep: posts, pages, products, orders, comments and media, navigation menus, scheduled events, and the settings and tables of other plugins (a payment gateway of another plugin, for example; add its option to the filter). Code that other plugins keep in the database and run (snippets of Code Snippets or WPCode) is checked every hour: new or changed code is emailed to you, and the quarantine deactivates the plugin that runs it.

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

= 3.12.7 =
* New: ScrapeLock also empties this site's pages in the Nginx fastcgi cache wherever it empties the page caches (settings saved, Stealth turned on or off or its addresses changed, upgrades), when it knows the folder: the constant `SCRAPELOCK_FASTCGI_CACHE_PATH` in wp-config.php, or Nginx Helper's folder. Nginx Helper's own purge does nothing when its method or folder is not the server's. Only cache files whose key names this site's host are deleted; links are never followed and system, home and WordPress folders are refused.
* New: `wp scrapelock cache status | purge` (finds the cache folder in the Nginx configuration with nginx -T or `--nginx-conf`, shows this site's cached pages, purges all of them or some addresses, `--dry-run`, and prints the wp-config.php line to add). `wp scrapelock cdn purge --all` now empties the server cache first, so the CDN does not fetch a stale page again (`--no-server-cache` to skip it; `--server-cache` for addresses).
* Fix: with Stealth or "Hide that the site runs on WordPress", WP Rocket's footer comment ("This website is like a Rocket … Performance optimized by WP Rocket") and Redis Object Cache's note are turned off (WP_ROCKET_WHITE_LABEL_FOOTPRINT and WP_REDIS_DISABLE_COMMENT, unless the site set them). Stealth also removes the footer comments of other performance and cache plugins that reach its buffer; conditional and other comments stay.
* Fix: with Stealth, the translations of scripts no longer carry file paths (wp-includes/js/dist/…, a plugin's path) or the tool that made them; translations and text domain stay.
* Change: "What can never be hidden" (Stealth) names the comments a page-cache plugin adds when it stores the page (turn them off in that plugin).
* Greek translation of the new texts.

= 3.12.6 =
* New: Stealth with WP Rocket, Autoptimize, LiteSpeed Cache and W3 Total Cache: the inner wp-content / wp-includes of their minified and combined files (e.g. WP Rocket's cache/min/1/wp-content/themes/…) get neutral codes too, also in their stored pages. The rules map them back by pattern, so files written after "Clear cache" keep working. Copy the Stealth rules again.
* New: the Stealth rules carry a fingerprint of their own. Server rules → Stealth (and Site Health) say whether they are installed and up to date, out of date, from before 3.12.6, or not found, asking the server directly first; after a change of the folder of the addresses or a new plugin or theme folder, a notice asks to copy them again. The aaPanel place: a file of its own in extension/<site>/ after scrapelock.conf, e.g. z-scrapelock-stealth.conf.
* New: `wp scrapelock rules show | status | install` (install writes only the files named: .new, diff, .old, nginx -t, reload, everything put back on failure) and `wp scrapelock cdn purge <address>… | --all` with the stored Bunny CDN and Cloudflare keys (never printed).
* New: Verification files (Server rules, and `wp scrapelock verify-file`): a file a service asks for to verify the site (/builtwith.txt, /google….html, /BingSiteAuth.xml, /.well-known/…), served to every bot for a few hours, purged at the CDN, allowed in robots.txt, then removed.
* New: "Block technology profilers (BuiltWith, Wappalyzer, WhatCMS…)" on the Bots tab, off by default, with an updatable list (filter `pncp_tech_profiler_agents`). "For my site" proposes it (not ticked) when such names are in the bot list, and removes those lines.
* New: "For my site": "Dismiss" per proposal (it comes back only when the setting or the proposal changes), "Show dismissed" with "Restore", and "you chose this" next to a value you set against a proposal. `wp scrapelock wizard dismiss | restore <setting>`.
* Fix: the notice "The server rules are out of date (installed: not found, …)" right after saving the Bots tab although part 2 was installed. "Installed" is what the server last reported; "not found" only after a second check a few seconds later; when only part 1 or part 2 differs, the notice names it.
* Fix: a verification file refuses every PHP or ASP opening tag; deactivation removes the verification files; uninstall removes the new options and events.
* Change: the note under "Addresses that do not exist" (Log tab) is one line, the rest under "More".
* Greek translation of the new texts.

= 3.12.5 =
* New: "Blur the page on screenshot shortcuts" (On the page) has "Applies to: Everyone / Only visitors who are not signed in". Everyone is the default and what every existing site keeps. With the second choice signed-in members can take screenshots; staff in "Who is excluded" never get the blur, as before.
* New: the choice is made by the page itself, so it works with page caches (WP Rocket, Bunny CDN): ScrapeLock sets a small cookie, `pncp_si=1`, in signed-in browsers (no personal data; the logged_in cookie's paths, domain, Secure flag and expiry, SameSite=Lax, readable by the page) and removes it at sign-out. The page also reads WordPress's `logged-in` body class. Accounts signed in before the update get the cookie on their next page that is not served from a cache, or when they sign in again. Not set while the protection is off. The suggested privacy policy text names it. Someone who adds the cookie by hand only turns the blur off in their own browser: like the blur itself, it is a deterrent.
* Greek translation of the new texts.

= 3.12.4 =
* Fix: on aaPanel (and BT Panel, CloudPanel) the Server rules tab read "Not installed" with part 2 of the Nginx rules in the site's server { }: the panel's WordPress rewrite is a server-level `if (!-e $request_filename) { rewrite ... /index.php last; }`, which runs before Nginx chooses a location, so the check address went to WordPress (404). Part 2 now also answers its check address at server level, above every other line (not part of the fingerprint: installed rules stay current). Copy part 2 again.
* Fix: the "installed / up to date" status asks the server itself first (the site's host pinned to 127.0.0.1, the server address or `SCRAPELOCK_SERVER_IPS`, signed), then the public address. Behind Bunny CDN without "Forward Host Header", or with a cached 404, the CDN answered instead of the server. Without an answer at the check address the `X-ScrapeLock-Rules` header of the site's own page counts, so the tab and the out-of-date notice agree; an http:// site address sent to https:// is followed.
* New: when the rules are not seen, the tab, Site Health and `wp scrapelock status` / `selfcheck` say in one line what answered and what to do: WordPress (part 2 not active, or behind a server-level rewrite), Nginx itself (another location took the address), only the CDN (Forward Host Header), the CDN's cache (purge), something else.
* New: the Apache card shows whether the Apache rules are installed (their header, the server asked first; the .htaccess is never read).
* Change: part 2 says where it goes ("directly inside server { }, not inside a location { }"), and the aaPanel instructions name both places that work (Config below #SSL-END, or the extension folder included at the top), once only.
* Greek translation of the new texts.

= 3.12.3 =
* Fix: ScrapeLock's own generated Nginx rules refused the site's own checks with 403 (Vulnerable points "Check again", Site Health, "Run a real self-check now", `wp scrapelock selfcheck`): they sent a Chrome User-Agent without Sec-Fetch-Mode and Sec-CH-UA over HTTPS, which the fake browser rule refuses before PHP can see the signature. Every self-check now sends `ScrapeLock-Selftest/<version> (+<site address>)`, which is no browser's, plus the signature; ScrapeLock's PHP checks let it through by the signature, never by the name.
* New: the generated Nginx and Apache rules never block the server itself: its own addresses (127.0.0.1, ::1, the server address, the outbound address learned from the site's signed requests, `SCRAPELOCK_SERVER_IPS`) are exempt from every block, the loopback and private ones only when no proxy passed the request on. Never a CDN edge, never an invalid entry. The Server rules tab lists them; behind a CDN, `real_ip` (Nginx) or `mod_remoteip` (Apache) makes the server's own requests through the CDN keep its address.
* New: the rules carry their fingerprint in the header `X-ScrapeLock-Rules`, sent only to the site's own signed requests. Every self-check compares it with the rules the current settings give; when they differ (also right after saving a setting that changes them), an admin notice on ScrapeLock's pages and the dashboard and a Site Health result say "The server rules are out of date (installed: X, current: Y)", with "See what changed" (a line diff). Sites that never installed the rules are not told anything. Nginx rules of before 3.12.3 are recognised by their check address.
* New: when the web server refuses the site's own request before WordPress, the self-check checks it against ScrapeLock's own rules and says "Refused by ScrapeLock's own server rule (fake browser)" (or the rule it was) and what to do, instead of "web server".
* Change: with "Always allowed IPs" the page limit of the Nginx rules does not count the server either. A zone without them keeps its key, so Nginx reloads the new rules.
* Greek translation of the new texts.

= 3.12.2 =
* Fix: behind Bunny CDN without "Forward Host Header" (its default) the site's own requests still got a 403 (Vulnerable points "Check again", Site Health): the server gets the pull zone's origin name as Host, and the signature was bound to it. The signature now names the site host it was made for and is verified for that host, whatever Host header arrives; a path with "//" and a HEAD passed on as GET match too. Signatures of 3.12.1 are still accepted.
* New: when something on the way refuses the site's own request, the note says who: ScrapeLock (with the check), Bunny's edge, Cloudflare, Wordfence, another plugin or the web server, and what to check there. ScrapeLock's refusals carry the header `X-ScrapeLock: refused` (the reason only for the site's own request).
* New: the request is then made once more straight to the server (the site's own host and port pinned to 127.0.0.1, the server's address or `SCRAPELOCK_SERVER_IPS`, TLS checked as before). Vulnerable points give a real result marked "Checked at the server", and for 6 hours the site's other requests to itself (Site Health, WP cron) take that way, only once this WordPress itself answered there, until the public address answers again.
* New: "Run a real self-check now" and the preset "The site itself (loopback)" in Log → Check a request, the Site Health test "ScrapeLock self-request test" and `wp scrapelock selfcheck [--log]`. The last 30 self-requests are noted without IP addresses, User-Agents, query strings or cookies.
* Fix: a block of the server's own address sent to the CDN earlier is removed at once.
* Fix: "=" entries (the whole User-Agent) in "Always allowed User-Agents" work in WordPress and in the pre-cache check; they matched nothing before.
* Fix: "Check a request" and `wp scrapelock check` say "Not counted" for a link preview of "Always allowed" on an image or file, instead of a counter.
* Change: "For my site" shows each setting by its label, with its internal name in a "?" tooltip.
* Greek translation of the new texts.

= 3.12.1 =
* Fix: the site's own requests (Vulnerable points "Check again", Site Health, the Stealth test, cron) got a 403 behind Bunny CDN without the CDN secret. WordPress now signs each of them (`X-ScrapeLock-Sig`, valid for 60 seconds and once) and a signed request passes every check, also the pre-cache check, whose line in wp-config.php is rewritten with the key on the next wp-admin page.
* Fix: the address the server's requests leave from is learned from the answers to the site's own signed requests (kept 24 hours), never from a request of someone else. `SCRAPELOCK_SERVER_IPS` in wp-config.php lists the server's addresses when ScrapeLock cannot learn them.
* Fix: the server's own addresses are never sent to the CDN as temporary blocks, never counted from Bunny's logs, let through by the wp-login.php lock at Bunny, and never recorded as attacks.
* Fix: FluentCommunity members' portal reads count per account, at four times "REST API requests per minute", and four of them as one page toward "Pages per minute per signed-in account". Over it only that account gets a 429 (log reason "FluentCommunity REST reads per minute per member", with the username); guests keep the per-IP limit, and no IP is banned for it.
* Fix: with "Allow AI search" off, the AI search bots are blocked from ScrapeLock's built-in list, also when the 3.11 upgrade or "Remove from the list" took them out of the bot list. Nothing is written back into the list.
* Fix: "Check a request" checks images, video, fonts, CSS and JavaScript as "Media", with the counter that decides ("N of M this minute"), also in `wp scrapelock check`. Every reason is shown by its label, never its internal key (Log tab, Check a request, WP-CLI).
* Change: on new installs Traffic stores IP addresses masked; "Start collecting" asks how they are stored, with Masked chosen in advance, and says how long they are kept. Existing settings are kept. The suggested privacy policy text describes Traffic and the username kept with a per-account limit.
* New: "For my site" also proposes sensible values (ban scanners on their first probe, refuse requests by IP address, reputation, shorter temporary blocks, a page limit too low next to the human check, a REST limit too low for FluentCommunity or WooCommerce, a per-account limit for membership sites, OneSignal in "Always allowed", and turning off options that only annoy visitors), each with its reason, all ticked.
* Greek translation of the new texts.

= 3.12.0 =
* New: Traffic tab (Records → Traffic), off until "Start collecting". Every request the site answers, from the Bunny CDN logs while their import is on (they include the pages served from the CDN cache), else the web server's access log (Nginx or Apache "combined" format, rotated files included, with "Test this path"), else the pages WordPress serves itself. Only one source is counted at a time, so no request is counted twice.
* New: views for the requests over time, the User-Agents by family (browsers, verified and fake search engines, AI bots, SEO tools, link previews, scripts…), problem URLs (404 with the links that lead there, a link on your own site marked as the one to fix; 5xx, redirects, pages not served from the cache, the largest and slowest), visitors with their country and block status, and every single request with "Export CSV". Every filter is in the address, so a view can be bookmarked.
* New: from a User-Agent, "Block this User-Agent" or "Always allow", after a confirmation that shows the exact line added and warns for search engines and browsers; the settings are saved under "Earlier versions" first, with Undo. Your own browser is never blocked.
* New: email alerts about unusual traffic (server errors or pages not found far above the usual, a new heavy User-Agent, a source that stopped), at most one of each kind every 6 hours; a Traffic part in the weekly attack report and the dashboard widget, and a Site Health test while it collects.
* New: `wp scrapelock traffic` (status, overview, top, problems, raw, export, purge, run, test-path).
* Privacy: everything stays in the site's database. Single requests are kept 3 days by default (1 to 14, at most one million), the daily figures 90 days (7 to 365). With "Masked" IPs the last part of every address is removed, also from the addresses stored before. Signed-in administrators, wp-admin, AJAX, cron and the site's requests to itself are never recorded. On a network only a network administrator may set or test the access log.
* Performance: with a million requests stored every view answers in a few seconds (a covering index, status filters over long periods from the daily figures, one pass for a User-Agent, path or IP).
* Greek translation of the new texts.

= 3.11.0 =
* Fix: the site's own requests through the CDN (Site Health, the Security headers check, cron, cache preloads) got "No browser headers" (403), because behind Bunny the server's public address was not known. The server's addresses (SERVER_ADDR, what the site's names resolve to without CDN addresses, and addresses learned from the site's own signed requests) pass every check, also the early and pre-cache checks and the Vulnerable points log. Never by User-Agent, and only with a visitor IP that can be trusted. The signature is never sent on when such a request is redirected to another host, and a newly learned address reaches the pre-cache check in the same request (Site Health no longer calls it "on but not running" until WP cron runs). Filter `pncp_server_ips`.
* Fix: the service bots of active plugins (WP-Rocket-SaaS) are also allowed in the pre-cache check, and the early check knows the bots that other plugins add with `pncp_plugin_bots`.
* Fix: GET and HEAD requests for /.well-known/ are never refused for an empty User-Agent, and GoogleAssociationService, Chrome's Privacy Preserving Prefetch Proxy, Apple's AuthenticationServices and OneSignal count as allowed there. Addresses on Google's or Apple's official lists are never refused by the empty User-Agent, "Browsers only" or headless checks. New installs also have these four in "Always allowed". Filter `pncp_well_known_agents`.
* Fix: images, video, fonts, CSS and JavaScript no longer count as pages toward the page limits or automatic Emergency Mode. They have a counter of their own (10 times "Pages per minute", never a violation), and link previews in "Always allowed" are not counted on them. Filter `pncp_static_extensions`.
* Fix: with "Allow AI search" on, its bots (OAI-SearchBot, ChatGPT-User, PerplexityBot…) are left out of the bot list everywhere it is used: WordPress, the early and pre-cache checks, the server rules and the Bunny log import. The Bots tab warns when the stored bot list still names them, with "Remove from the list". Training crawlers stay blocked.
* Fix: "Ban scanners on their first probe" also bans on the first probe for files of other software: Spring Boot /actuator, Dockerfile and docker-compose, Railway, payment gateway and parameters files, credentials and secrets, .aws, .vscode/sftp.json, *.git/config, wp-conflg.php. Filter `pncp_probe_paths`.
* Fix: "Ban scanners on their first probe" also bans a scanner that a User-Agent check refuses first ("Browsers only", the headless check, an empty User-Agent, the bot list): python-requests and similar asking for /actuator/env or /.env got a 403 but were never banned. The same exemptions apply (staff, verified search engines, always-allowed IPs and User-Agents, real files, Private URLs, Monitor only, filter `pncp_probe_ban`). In the early check, before WordPress knows whether the address is a page, only .env, .git, wp-config.php backups, dumps and backup archives.
* Fix: status badges show "Set but not active" with the reason (the loader is not in wp-config.php, the CDN secret is missing, protection is off…) instead of "Off" for a setting that is on but not in effect: the status bar, Network and CDN, the dashboard widget, Site Health, Stealth and the weekly email.
* Fix: settings are named in words instead of raw keys (such as "block_ip_host: 1") in the Emergency Mode line, the "Reset this tab" and import tables, and Site Health info. Filter `pncp_setting_labels`.
* New: FluentCommunity. While it is active, its portal (/hub/ or its own slug) counts as a content address in the Log, and the portal's REST reads by signed-in members do not count toward "REST API requests per minute". Every other check still applies to them. Filters `pncp_fluent_community_active`, `pncp_fluent_community_slug`.
* New: the Log names the bot list entry behind each "User-Agent in the bot list" block. A service blocked as a generic HTTP library gets "Allow this service", which allows only its whole User-Agent.
* New: "For my site" on the first tab (and `wp scrapelock wizard`). It finds the plugins, the CDN and the server in use, proposes settings for them with the reason for each, and gives advice that is not a setting. Changes that block more are not ticked. Nothing changes until "Apply selected", and the settings before are saved under "Earlier versions" with an Undo. Not while the site is locked.
* Change: the settings tabs are grouped (Content, Bots & limits, Security, Records). The Bots and limits tab is an accordion: only Bots, Limits and Failed sign-ins are open on a plain visit, and the network, CDN and IP list parts are under "Advanced". Long lists (the bot list, the allow list and lists of 6 or more entries) show an entry count with Edit. Every field keeps its name and place in the form.
* Change: every setting has a one-line help text, and the longer explanation is under "More". "May affect visitors/SEO" is a warning icon, and number fields show "Default: N". Error and warning notices say in one sentence what to do. The EU directive citation of the TDM opt-out is under More.
* Change: new installs only: "Ban scanners on their first probe", "Refuse requests that open the site by its IP address", IP reputation on, and temporary blocks of 120 minutes. Existing sites keep their values. "Reset this tab" uses the new-install values, after its confirmation table.
* New: Greek translation of the whole plugin, shipped in languages/ (scrapelock-el.mo) and loaded on WordPress 6.2 and later; a language pack from translate.wordpress.org still comes first. Sentences that were split into pieces are now whole sentences for translators.
* Upgrade: with "Allow AI search" on, the AI search bots are removed once from the stored bot list, after a saved version under "Earlier versions". Sites with the option off keep their list.

= 3.10.1 =
* New: Site Health "ScrapeLock site files" checks the files that phones, browsers and active plugins ask for at the root of the site. When a Site Icon is set and /apple-touch-icon.png answers "not found", "Create it" writes a 180 × 180 PNG made from the Site Icon (and apple-touch-icon-precomposed.png). While OneSignal is active and /OneSignalSDKWorker.js answers "not found" (browsers that subscribed when the worker was at the root ask for it there), "Create it" writes OneSignal's one-line worker. Without a Site Icon it links to where you choose one. Nothing is written without the click, a file of the site is never replaced, and Remove (or uninstall) deletes only files ScrapeLock wrote and nobody changed.
* New: Site Health "Wordfence and the visitor address", while Wordfence is active: on your own visit through the CDN it compares the address Wordfence reads with the visitor address ScrapeLock reads. If Wordfence reads the CDN's server (it would then block or rate-limit the CDN, and every visitor with it), the test is critical and gives the steps (X-Forwarded-For, Trusted Proxies) with Bunny's addresses to copy. Nothing in Wordfence is changed.

= 3.10.0 =
* Fix: "Lock at Bunny" for "Secret files" (and any lock with more than 5 addresses or IPs) failed at the real Bunny API with HTTP 400 "Maximum 5 triggers are allowed per condition". Locks are now split into conditions of at most 5 entries, in one Edge Rule (Match Any) or, with exceptions or many entries, in several rules "ScrapeLock: … (1/3)". They are one lock everywhere: one Remove removes them all, Monitor only switches them all off, and if one part cannot be made the parts made in that call are deleted (also a part Bunny saved although its answer timed out), so no half lock is left. A lock made by 3.8/3.9 with more than 5 entries is sent again split at the next check. "Allowed IPs for the login page at Bunny" holds at most 15 entries. Filter `pncp_bunny_edge_limits`.
* Fix: "Browsers only" refused real Google services from Google's own addresses (GoogleAssociationService for app links, Chrome's Privacy Preserving Prefetch Proxy), Apple's devices (passkeys, home-screen icons) and DuckDuckBot. The files a site publishes about itself (/.well-known/…, favicon, apple-touch-icon, the web app manifest, robots.txt, ads.txt, llms.txt…) skip the "looks like a bot" checks when asked with GET or HEAD; the bot list, the limits and the attack checks still apply. An address on Google's official lists is never refused for lacking browser headers. Google's other fetchers and DuckDuckBot are verified by their official lists, Applebot by Apple's list before reverse DNS.
* New: official IP lists of Applebot and DuckDuckBot (downloaded once a day while protection is on, see External services). Their addresses are never banned, like Google's and Bing's. Site Health's "official IP lists" test checks them too.
* New: the service bots of active plugins are allowed while the plugin is active: WP Rocket (WP-Rocket-SaaS and its cache preload) and Jetpack. "Bots and limits" → "Always allowed" lists them, with "Stop allowing" / "Allow"; a warning with an "Allow" button appears when such a bot you stopped allowing was refused. The page limits, the bot trap and the attack checks still apply. Filter `pncp_plugin_bots`.
* Fix: Claude-User from Anthropic's outbound range (160.79.104.0/21) was logged as a "Fake AI search bot", because the downloaded list holds only some single addresses. That published range now also counts as Anthropic (filter `pncp_ip_extra_ranges`). Every published shape of the AI bot lists is read (plain strings, nested keys, CIDR objects). A list not refreshed for over a week no longer calls a bot fake (filter `pncp_ip_list_max_age`). "Check a request" and "Official IP lists" say which list a bot was compared with.
* Fix: /llms.txt, /ai.txt, /.well-known/assetlinks.json, /.well-known/traffic-advice, service workers such as /OneSignalSDKWorker.js and other site-metadata files were counted as "Scanner probe (.env, .git…)", and as a 4xx flood in the Bunny log import. They are no longer attacks or probes (also for "Ban scanners on their first probe"); the rows stored for them are deleted once. Scripts, archives and traversal under /.well-known/ are still probes. Filter `pncp_site_metadata_paths`.
* Fix: Vulnerable points → "Security headers" said X-Content-Type-Options and Referrer-Policy were missing on a site that sends them through Bunny CDN. The check reads the public home page with GET, follows redirects, says which address and answer it read, and says "could not be checked" (not "missing") when the answer did not come through the CDN the site uses. Results cached by 3.9 are checked again after the upgrade.
* Fix: Site Health "ScrapeLock's private folders can be read from the web" said "Add these lines to the server { } block" but some screens showed no lines. The exact Nginx and Apache lines for every private folder are now shown as plain text. On a site connected to Bunny CDN, a new "Lock at Bunny…" button (and the preset "ScrapeLock's private folders" on the Bunny card) refuses these folders at Bunny, after the usual preview and Confirm.
* Change: settings tabs accept other names in the address (&tab=vulnerable, &tab=server…), and an unknown tab shows a notice instead of silently opening the first one. Folded sections that were open stay open after Save, and the page returns to the button you used.

= 3.9.1 =
* Fix: while wp-login.php is locked at Bunny with the "Allowed IPs for the login page at Bunny" list, that list can no longer be emptied, or saved without the IP of the administrator who saves it: the stored list is kept and the reason is shown. Before, an emptied list left the rule at Bunny with the old list without a word. A changed list is now sent to Bunny at once, and the Bunny card warns while the rule at Bunny still has the previous list.
* Fix: `wp scrapelock bunny unlock preset_xmlrpc` (the ID as `wp scrapelock bunny rules` lists it) reported success without removing the rule made from Vulnerable points. It now removes the preset's rule whichever ID holds it, and ends with an error when there is nothing to remove.
* Fix: `wp scrapelock settings set` reports only the settings that were really saved.

= 3.9.0 =
* New: "Send temporary blocks to the CDN", a switch of its own under "Blocking at the CDN". Off on new installs: saving the API key or token no longer sends any block. Sites upgraded from 3.8 that already sent their temporary blocks keep it on, and administrators see a one-time notice about it. "Save and test the connection" only connects and tests. In Monitor only nothing that blocks is sent to the CDN. Blocks sent before the switch is turned off are removed when their temporary block ends. Filter `pncp_edge_api_base`.
* New: every Bunny log import (and "Import now") checks whether the log lines carry full IPs or anonymized ones (IPv4 ending in .0, IPv6 whose last group or second half is zero, masked or dropped addresses), also when no attack was found. The Bunny card shows "The logs have full IPs" or the warning "Log anonymization is on: ScrapeLock cannot block from the logs", with the time of the check; with anonymized logs, IPs too fast at the CDN are not counted toward a block. `wp scrapelock bunny status` shows the result (log_ips).
* New: "What would be blocked" before every lock at Bunny (Bunny card and Vulnerable points): the addresses Bunny will refuse, the requests and IPs that hit them in the last 7 days (every request in the imported Bunny logs, attacks or not, and the attack record), and which of those IPs also used the site normally (opened pages, signed in, passed the human check, an administrator). The lock is made only after "Confirm". `wp scrapelock bunny preview <preset>`. Filter `pncp_bunny_lock_preview` (warnings, blockers).
* New: safer lock of wp-login.php at Bunny. The Bunny card suggests the IPs administrators used in the last 30 days (IPv6 as its /64) for "Allowed IPs for the login page at Bunny"; nothing is added until you tick them and click "Add selected". The lock is refused while the list is empty, does not cover your current IP, or ScrapeLock cannot see your real IP. A lock made from 3.9 sends only this list; a login rule made with 3.8 keeps following the administrators' IPs until it is removed and locked again.
* New: warning before XML-RPC is locked at the CDN, when Jetpack is active, application passwords exist, or xmlrpc.php was used successfully (signed-in calls, accepted pingbacks) in the last 30 days, with what stops working.
* Fix: "Trust Bunny CDN addresses" said "Default: on" on sites where it was off. Sites installed before 2.6 got it off when they were upgraded; the note now says so (for every setting whose upgrade value differs from the new-install default). When Bunny CDN is in use and its addresses are not trusted, "Blocking at the CDN" warns and offers a one-click "Trust Bunny CDN addresses". Upgrades never turn it on by themselves.
* Change: after Save, Test, Import now, Lock, Confirm, Remove or Disconnect, the page comes back to "Blocking at the CDN (advanced)" opened at the part you used, so its buttons stay in view.
* Privacy: the counts of requests for the addresses that can be locked at Bunny, and of normal page views, per IP from the Bunny logs are kept only for IPs that attacked or asked for such an address (at most 200 IPs per address and day), for 8 days; successful XML-RPC use is kept as times and the last method name (no user, no IP), for 30 days. Both are removed on uninstall with the other new options.

= 3.8.0 =
* New: Attacks tab with the full attack report: KPIs, timeline per day and hour, kinds of attack, addresses attacked most with "Lock this", wp-admin and sign-in attempts with the usernames tried, top IPs with country and reputation and "Block 24 h" / "Always block", User-Agents, Bunny CDN edge, CSV export, dashboard widget, optional weekly email (`wp scrapelock attack-report`).
* New: attack record (`wp scrapelock attacks`): where bots and attackers hit the site, also when nothing is refused: failed sign-ins and usernames tried, wp-admin, wp-login.php and XML-RPC probes (each call of a system.multicall), username enumeration, scanner and plugin probes, attack patterns in the address. One row per hour, address and IP, written only for attack-looking requests; kept 7, 30 or 90 days. On by default.
* New: Vulnerable points tab: live status, attack counts and one-click lock/unlock for XML-RPC, wp-admin, login, core files, file editor, application passwords, usernames, author archives, REST map, PHP in uploads/wp-includes/wp-content, directory listing, pingbacks and security headers; Apache rules written with self-test and rollback, Nginx rules, Bunny CDN edge (`wp scrapelock harden`).
* New: sign-in protection: failed logins limited per IP (temporary block) and per username (pause with an emailed unlock link), counting wp-login.php, each call of an XML-RPC system.multicall and application passwords; one generic error message; optional custom login address that answers 404 for wp-login.php and wp-admin (recovery: `SCRAPELOCK_LOGIN_SLUG_OFF`); `wp scrapelock login`. The limit and the generic message are on for new and existing sites; the address is off until you set one.
* New: Bunny CDN logs import (attacks on cached pages, bad bots, 4xx floods, optional violations for IPs too fast at the CDN) and one-click Edge Rules at Bunny for wp-login.php, xmlrpc.php, secret-file probes and WordPress's own files (`wp scrapelock bunny`).
* New: Stealth (optional) — neutral asset addresses with tested server rules for Apache and Nginx, REST prefix, /sitemap.xml, WordPress-only markup removed, and a scan of what still shows WordPress (`wp scrapelock stealth`). While on, it includes "Hide the versions" and "Hide that the site runs on WordPress".
* New: Site Health tests for the attack record, vulnerable points, sign-in protection, Bunny CDN logs and Stealth; Site Health info and the suggested privacy policy text cover 3.8.
* Change: the log counts the sub-sitemaps (/sitemap-posts-post-1.xml) and a moved REST API as content, not as scanner probes.
* Security: the custom login address is never shown to visitors: the password form of protected posts keeps its own address, and wp-signup.php and wp-register.php answer 404 instead of redirecting to the new address. A page, post or tag created later with the same address no longer clears it at the next save (a warning says so). "Open again" on the login point only moves the login page back and keeps the limit of failed logins on.
* Security: a login rule at Bunny CDN always keeps the administrators' IPs, and follows the login address at once: when the page goes back to wp-login.php ("Open again", an empty address, `SCRAPELOCK_LOGIN_SLUG_OFF`) it lets them in, or is switched off when no administrator IP is known, so nobody is locked out.
* Stealth: the password form of protected posts goes through the Stealth folder; ?rest_route= answers only requests that sign in while the REST prefix is moved; REST answers to visitors no longer carry the api.w.org Link header or the X-WP- names in the CORS headers; the ids of script module preloads are renamed. `wp scrapelock stealth scan --page=<url>` (was --url, which WP-CLI keeps for itself).
* Attack record: installer probes (install.php, upgrade.php) are recorded when "Early check" is on; sign-ins refused for a blocked IP or a paused username count as refused sign-ins, not as wrong passwords of that account; during a flood, wp-admin and login paths add up in a few rows; the Site Health test shows the number of failed sign-ins.
* Performance: Stealth checks the stored rewrite rules only on sites where it once moved the REST API or the sitemap, and rebuilds them at most once an hour. The Bunny import adds each aggregated event in one step.
* Database: a new table, `pncp_attacks` (schema version 6), removed on uninstall with the new options, events and .htaccess blocks.
* Readme: the details of Lockdown and of the REST list weighting moved to the FAQ.

= 3.7.0 =
* New: site rippers and address harvesters (HTTrack, WebCopier, Teleport Pro, Offline Explorer, SiteSucker, Cyotek WebCopy, Octoparse, ParseHub and more, 30 names) are blocked with the bot list. Built in, like the AI crawlers; an entry in "Always allowed" still passes. Filter `pncp_ripper_agents`.
* New: a User-Agent that carries an attack instead of a name (HTML or PHP tags, Shellshock, Log4Shell and its obfuscations, SQL injection, control characters) gets a 403 and a violation, even with an always-allowed name in it. Log reason "bad_ua". Filter `pncp_malicious_ua_patterns`.
* New, optional (off by default): "Block SEO and marketing data crawlers": AhrefsBot, SemrushBot, MJ12bot, DotBot, rogerbot, BLEXBot, DataForSeoBot, Barkrowler, serpstatbot, ZoominfoBot and more are blocked and asked in robots.txt. Filter `pncp_seo_agents`.
* New, optional (off by default, on in Emergency Mode): "Refuse requests that open the site by its IP address instead of its name". Private addresses (health checks, reverse proxies) and a site set up with its IP are never refused. Log reason "host_ip".
* New, optional (off by default): IP reputation (Bots and limits → Reputation). Good and bad events of the last 7 days make a score per IP; a good IP is never blocked for a limit alone, a bad one gets "Pages per minute for IPs with a bad reputation" (10). Unblocking an IP by hand forgets its reputation. `wp scrapelock reputation <ip> [--reset]`; "Check a request" shows the score.
* New, optional (0 = off): "REST API, GraphQL, feeds and sitemaps per minute for IPs that never opened a page". Site Health warns when a page cache would hide the page views from it.
* New, optional (off by default): the CrowdSec blocklist, from your own CrowdSec agent (LAPI decisions stream, every 15 minutes) or from a plain-text blocklist address (CrowdSec Console integration or another list, hourly). A listed IP gets a stricter page limit (default) or a 403; private addresses, ranges wider than /16 (IPv6 /32), this server, CDN edges and official crawler addresses are never taken from a list; a failed download keeps the previous list. The key can go in wp-config.php (`SCRAPELOCK_CROWDSEC_KEY`) and is never exported. "Sync now" under Official IP lists, `wp scrapelock crowdsec status|sync|check`, a Site Health test.
* New, optional (off by default): "Write each temporary block to the system log, for fail2ban" (syslog, facility AUTH). The Server rules tab gives the fail2ban filter and jail. Filter `pncp_syslog_facility`.
* New: Log tab → "Visitors from AI assistants": visits that ChatGPT, Perplexity, Claude, Gemini, Copilot, DeepSeek, Grok, Le Chat, Meta AI and others sent, per assistant and page, last 30 days, counted on this server without cookies or personal data (on by default; Log settings). `wp scrapelock ai-referrals [--pages]`. Filter `pncp_ai_referrers`.
* New: Site Health info and `wp scrapelock status` list the new settings; the suggested privacy policy text covers them.
* Fix: on the settings screens, the note "Takes effect only when … is on" was shown even when that option was on.
* Database: two new tables, `pncp_crowdsec` and `pncp_airef` (schema version 5), removed on uninstall.
* Change: Lockdown no longer hooks the automatic updates of plugins, themes and translations. Nothing changes while the site is locked: WordPress's automatic updater stays off, and every package is still refused before it is downloaded and before it is copied (tested). Plugins and themes refused during the optional window for a minor release of WordPress (filter `pncp_lockdown_allow_core_minor`) are no longer logged as attempts to change the site.
* Readme: the Description is shorter (the details of 3.7 are in the FAQ), within the 2,500-word limit of WordPress.org.

= 3.6.1 =
* New: completely redesigned settings screens. The plugin now uses the full width of wp-admin, with a header showing the protection state and quick actions, overview figures (blocked in 24 hours, IPs blocked now, protection layers on, preset), sticky tabs with icons, settings grouped into cards with switches, a save bar that stays visible and marks unsaved changes, and colours that follow the admin colour scheme.
* Change: right click is now blocked on links and buttons too (and on images inside links, and the long-press menu on iPhone and iPad). Only form fields and `.pncp-allow` keep the menu. Filter `pncp_protect_allow_link_menu` restores the menu on links.
* Change: "Blur the page when Print Screen or a screenshot shortcut is pressed" blurs the whole page at once with a full-screen overlay, keeps the reader's mark (user name or IP and time) visible over it, and also reacts to Ctrl+Shift+S, Win+Shift+S and Cmd+Shift+3/4/5/6. Fixed: Ctrl+Shift+S and Win+Shift+S never blurred the page, because the Ctrl/Cmd+S block stopped them first. Filters: `pncp_blur_timeouts`, `pncp_mark_blurred_opacity`.
* Security: with "Real visitor IP" set to X-Forwarded-For and Cloudflare trusted but no CDN secret, a visitor could choose its own IP through a Cloudflare Worker. The visitor IP is now taken from CF-Connecting-IP at the first Cloudflare edge, and Site Health recommends the CDN secret.
* Security: IPs that may be spoofed (a Bunny edge without the CDN secret, "trust every proxy") no longer collect strikes, bans or CDN blocks; they still get 429 answers.
* Security: the file quarantine renames a file to `name_php.pncp-quarantine.txt`, so it can no longer run on servers that map PHP with AddHandler, and also covers .user.ini, .inc and .htaccess files that enable PHP.
* Security: the limit on new counters per minute can no longer be used up by one network to turn the per-IP limits off: one /24 (IPv6 /48) gets at most 64 new counters a minute, beyond that its addresses share one counter. Filter: `pncp_new_counters_per_network`.
* Lockdown: capabilities given to one member alone (membership and course plugins) keep working while the site is locked; only privileged capabilities are refused. Filter: `pncp_lockdown_privileged_caps`.
* Lockdown: a failed database write while locking, unlocking or checking a code no longer leaves the site locked with codes refused; the change is not made and a notice says so. Recovery codes are cheaper to check. On multisite, saving the roles on one site keeps the choices of the others.
* Fix: a temporary ban can no longer be shortened (bot trap on a banned IP, Emergency Mode import) in the pre-cache check.
* Fix: during an attack, blocked requests no longer wait 200 ms each once the log budget is used up.
* Fix: behind an untrusted proxy with a private address, the proxy's address is never banned (which blocked the whole site), and a warning is shown.
* Fix: a post with invalid UTF-8 was blank for signed-in readers when the invisible trace was on.
* Fix: the minified protect.js and protect.css are used only when they match their source, so a change in the source always reaches visitors.
* Fix: a symlinked wp-config.php stays a symlink when the pre-cache check is turned on or off; table names are compared case-insensitively; the pre-cache check uses APCu only where it is shared; the pre-cache sync no longer retries on every admin request; the upgrade cannot run twice at once.
* Performance: without a persistent object cache or APCu, counters, strikes, human-check markers and DNS verdicts are kept in a small table of their own (`pncp_kv`) instead of two rows each in wp_options. Data center, Bunny CDN and IP range lookups, the settings lists and the User-Agent matching are worked out once per request; `pncp_surge` is no longer autoloaded, and old list options are no longer autoloaded.

= 3.6.0 =
* New: "Show who is reading over protected pages" (On the page → Members and readers, off by default). A faint line repeated over the page with the signed-in account's user name and the date and time, so every screenshot, screen recording or photo of the screen shows whose account it came from. No web page can stop those; this makes them traceable. It never takes clicks, taps or selections, comes back when it is removed or hidden, and the page is sent as private (not cached). Optional for visitors who are not signed in (their IP and the time, fetched by the page so cached pages still work). Filters: `pncp_mark_user_line`, `pncp_mark_guest_line`.
* New: "Hide an invisible trace of the account in the text" (off by default). For signed-in accounts, invisible characters that spell the account and the day, signed with this site's keys, are placed in each paragraph of protected pages. Paste text found elsewhere under Log → "Find whose copy this is" to see the account and the day. Visitors and search engines get the text as it is.
* New: "Pages per minute per signed-in account" (0 = off). The other limits count per IP; one account used by a script from many addresses is now limited too (log reason "rate_account", no IP ban).
* New: "Email me when one account is used from several addresses at once" (within 10 minutes, at most one email a day per account), optionally signing the account out everywhere else. Never for staff. Action: `pncp_shared_account`.
* New: "Hide that the site runs on WordPress, as far as possible" (Feeds and API tab, off by default). For visitors: everything "Hide the versions" does, plus no REST API, oEmbed, RSD and shortlink links, no emoji script, no X-Pingback and "X-Redirect-By: WordPress" headers. The addresses of themes and plugins still show it; that cannot be hidden by a plugin.
* Lockdown: the Site Editor's templates and template parts cannot be created, changed or deleted while locked, also by code, and templates, template parts and global styles changed straight in the database are found by the hourly check.
* Bot trap and probe ban: DuckDuckBot, Baiduspider, SeznamBot and the other search engines that are never banned now have to be likely real: their reverse DNS in their own domain where they document one, otherwise an address that is not a data center's. Before, the name in the User-Agent was enough.
* Performance: classes are loaded when they are first used. A page for a visitor loads about a fifth less of ScrapeLock's code (no server rules, settings import and export, Site Health, "Check a request", or the file check unless the site is locked).
* Security: a loopback or server address in the "Real visitor IP" header no longer counts as the server itself. With "Trust Bunny CDN addresses" on and no CDN secret, anyone could point a Bunny pull zone of their own at the site, send `X-Real-IP: 127.0.0.1` and skip every check (blocks, bans, the bot list and the limits), also in the early and pre-cache checks. A request now counts as the server itself only when every address on its way is the server or its private network and the IP can be trusted (cron, cache preload and a local Nginx or Varnish work as before). The same holds for "Trust every proxy".
* Security: a CDN edge trusted for the "Real visitor IP" header that sends no IP in it (header missing or not an IP) is no longer treated as a shared edge exempt from the per-IP checks: this site's own CDN always writes the header, so such a request came through someone else's zone. It is now limited and blocked like any other address.
* Security: the DNS lookups that verify Applebot, YandexBot and the other crawlers are taken from the per-minute budget with an atomic increment. Before, many requests at the same moment read the same count and all started a lookup, each holding a PHP worker.
* Fix: a real crawler whose DNS verification could not finish (a DNS failure, or the budget used up by fake ones) is no longer refused for lacking browser headers ("Browsers only", also turned on by Emergency Mode). The limits still apply to it.
* Lockdown: the hourly file and administrator checks are scheduled again when their event was moved more than 2 hours ahead, or to a longer interval, directly in the database (the "cron" option). This is noted in the lockdown log.
* Performance: with a persistent object cache (Redis, Memcached), Lockdown no longer rewrites the whole "alloptions" cache entry on every request, only when a value changed. This also stops it from overwriting a newer copy written by another request.
* Security: a request that claims to be Applebot or YandexBot from an address without any reverse DNS (PTR) record is now a fake crawler, as Googlebot and Bingbot already were. Apple and Yandex give every crawler address a PTR record in their own domain. Before, such a fake was never blocked as a fake crawler and never banned by the trap. A DNS failure (no answer) is still not a verdict.
* Lockdown: a capability stored for one user alone, which none of the user's roles grants, does not work while the site is locked. Before, a subscriber given edit_posts, delete_others_posts or a plugin's own capability straight in the database could use them.
* Lockdown: the widgets (widget_* and sidebars_widgets), the active theme's settings, and WooCommerce's own payment methods and bank accounts are kept while locked and put back when they are changed in the database. Filter `pncp_lockdown_protected_options` adds options of other plugins.
* Lockdown: code that plugins keep in the database and run (active snippets of Code Snippets, published snippets of WPCode; filter `pncp_lockdown_db_code`) is checked every hour while locked. New or changed code is emailed and logged, and with the quarantine on, the plugin that runs it is deactivated.
* Lockdown: when the site is locked again after an unlock, the code files added, changed or removed while it was open are emailed and listed on the Lockdown tab, before they become part of the new fingerprint.
* Pre-cache check without APCu: at most 2,000 new files a minute (counters, probe memory, probe bans). An attack that changes address on every request could create millions of files an hour and use up the inodes of a shared host. Filter: `pncp_precheck_new_files_per_minute`.
* Readme: the Lockdown section now lists what is put back when it is changed in the database, and what is not kept.

The changes of 3.5.0 and earlier versions are in changelog.txt in the plugin folder.

== Upgrade Notice ==

= 3.12.7 =
If your server has an Nginx fastcgi cache, run `wp scrapelock cache status` on the server and add the line it prints to wp-config.php (or set Nginx Helper's folder), then `wp scrapelock cache purge --all`: a page stored before is otherwise served as it was. The server rules and the Stealth rules are unchanged. Settings are kept.

= 3.12.6 =
Copy the server rules and the Stealth rules again (Settings → ScrapeLock → Server rules, then nginx -t and reload), or use `wp scrapelock rules install`: the Stealth rules now carry a fingerprint and cover WP Rocket's minified files. "Block technology profilers" starts off. Settings are kept.

= 3.12.5 =
The screenshot blur can now apply only to visitors who are not signed in (On the page → Applies to). Existing sites keep "Everyone". Settings are kept.

= 3.12.4 =
Nginx: copy part 2 of the server rules again (Settings → ScrapeLock → Server rules), then nginx -t and reload: it now answers the status check before aaPanel's server-level WordPress rewrite. The fingerprint is unchanged. Settings are kept.

= 3.12.3 =
After updating, copy the server rules again from Settings → ScrapeLock → Server rules (Nginx: both parts, then nginx -t and reload; Apache: the .htaccess block): the new rules never block the server's own requests. Settings are kept.

= 3.12.2 =
Fixes Vulnerable points "Check again" and Site Health behind Bunny CDN without "Forward Host Header", and says who refuses the site's own requests (Bunny, Cloudflare, Wordfence, the web server). Settings are kept.

= 3.12.1 =
Fixes the site's own requests getting a 403 behind a CDN (Vulnerable points, Site Health), FluentCommunity members' limits and AI search blocking. The pre-cache check's line in wp-config.php is rewritten on the next wp-admin page. Settings are kept.

= 3.12.0 =
New Traffic tab: every request from the Bunny CDN logs, the access log or WordPress, with User-Agents, problem URLs, visitors, CSV and email alerts. Off until you press "Start collecting"; nothing is stored or scheduled before. Settings and exports from 3.11 are kept.

= 3.11.0 =
Fewer false blocks: the site's own requests through the CDN, /.well-known/, static files, plugin service bots and allowed AI search bots. A "For my site" assistant, grouped tabs and shorter help texts. Settings and exports from 3.10 are kept; with "Allow AI search" on, its bots are removed from the bot list once (a saved version is kept).

= 3.10.1 =
Site Health can create a missing apple-touch-icon.png and OneSignalSDKWorker.js with one click, and checks that Wordfence reads the visitor's address behind the CDN.

= 3.10.0 =
Locks at Bunny with more than 5 addresses (such as "Secret files") now work with the real Bunny API, split into several conditions or rules managed as one lock. Fewer false blocks of Google, Apple, DuckDuckBot, WP Rocket and Claude-User; site-metadata files are no longer counted as attacks.

= 3.9.1 =
Fixes for the lock of wp-login.php at Bunny: the allowed IPs can no longer be emptied while the lock is on, and changes reach Bunny at once.

= 3.9.0 =
New switch "Send temporary blocks to the CDN": off on new installs. Sites that already send their temporary blocks to Cloudflare or Bunny CDN keep it on after the upgrade (a notice says so). Every lock at Bunny now asks for a Confirm first, and wp-login.php needs your IP in "Allowed IPs for the login page at Bunny".

