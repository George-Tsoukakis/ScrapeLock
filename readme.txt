=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhub
Tags: anti-scraping, ai bots, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.4.1
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
* Detect fake Googlebot, Bingbot, Applebot and Yandex with the official IP lists and reverse DNS. Real search engines always pass.
* Invisible bot trap link, disallowed in robots.txt.
* Per-IP limits for pages, searches and REST / GraphQL (IPv6: per /64 network), with temporary blocks after repeated violations.
* A separate limit for "page not found" (404) requests, for scrapers that guess URLs. Missing images, CSS and scripts do not count.
* Always-blocked lists of IPs / CIDR and referrer domains.
* Hide usernames from visitors: no `?author=N` redirect, no REST user list, no users sitemap.
* Optional early check: a small must-use plugin that stops known bots and blocked IPs before the theme and the other plugins load.
* Content Signals in robots.txt (search yes, AI training no).
* Trusted Proxy support for Cloudflare and reverse proxies, so the real IP cannot be spoofed. Cloudflare is detected, with a one-click fix when every visitor appears with a Cloudflare address.
* Works with the Cloudflare plugin (APO): blocks and private feeds are never cached at the edge, and the Cloudflare cache is purged when you save the settings.
* Ready-made presets (Balanced, Strict, Maximum) and an Emergency Mode for attacks in progress.
* Block log with a 24-hour summary, top IPs and User-Agents, and automatic deletion after 1, 7 or 30 days.

= Feeds and API =

* Hide post, page and product text from the REST API and WPGraphQL for visitors.
* RSS with a short excerpt only, or disabled. With full text, an optional "The post … first appeared on …" line links republished copies back to the original.
* Private XML feeds (Skroutz, BestPrice, Google Merchant, ERP) protected with a token in a header or URL. Only the token hash is stored. Token rotation with a grace period and per-feed statistics.

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

Forms, cart, checkout, the WooCommerce Store API and payment webhooks are not affected.

== External services ==

ScrapeLock downloads public IP lists once a day, only for the features that use them. These are plain GET requests for public files: no data about your site or your visitors is sent, and the request does not include your site address.

* Google crawler IP ranges, from developers.google.com. Downloaded while protection is enabled, to tell real Googlebot from fakes. [Terms](https://policies.google.com/terms), [Privacy](https://policies.google.com/privacy).
* Bing crawler IP ranges, from www.bing.com. Downloaded while protection is enabled, to tell real Bingbot from fakes. [Terms](https://www.microsoft.com/servicesagreement), [Privacy](https://privacy.microsoft.com/privacystatement).
* Cloudflare IP ranges, from the Cloudflare API (api.cloudflare.com/client/v4/ips). Downloaded only when "Real visitor IP" reads the CF-Connecting-IP or X-Forwarded-For header and Cloudflare addresses are trusted. [Terms](https://www.cloudflare.com/website-terms/), [Privacy](https://www.cloudflare.com/privacypolicy/).

If a list has not been downloaded, ScrapeLock verifies search engine bots with reverse DNS, and uses a built-in copy of the Cloudflare ranges.

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

Pages served from page cache never reach PHP. Use the rules in the "Server rules" tab to apply the bot list and the limits in Nginx, Apache or Cloudflare too.

= Can I allow ChatGPT or Perplexity search but block training? =

Yes. Enable "Allow AI search engines and assistants" in the "Bots and limits" tab. Training crawlers stay blocked.

= My site is behind Cloudflare. What should I set? =

In "Bots and limits", set "Real visitor IP" to CF-Connecting-IP and keep "Trust Cloudflare addresses" on. If ScrapeLock sees that every visitor arrives from a Cloudflare address, it shows a button that does this for you. With Nginx, also set `real_ip_header CF-Connecting-IP;` and the Cloudflare ranges with `set_real_ip_from`, so the server rules see the real visitor IP.

= What is the early check? =

An optional setting in "Bots and limits". ScrapeLock writes the small file `wp-content/mu-plugins/scrapelock-early.php`, which runs before the theme and the other plugins and stops blocked IPs and referrers, temporarily blocked IPs and User-Agents from the bot list, with less server load. Search engines, logged-in users, forms and private feeds are left to the normal check. The file is removed when you turn the setting off, deactivate or delete the plugin. If the server does not allow direct file writes, the setting shows a notice and everything else works as before.

= Does it guarantee legal protection of my content? =

No. The TDM declaration is a machine-readable reservation of rights; it does not guarantee legal compliance or stop anyone who ignores it.

= What personal data does it store? =

When a request is blocked, the IP address, User-Agent, page and time are logged. The log is deleted automatically after 1, 7 or 30 days.

== Screenshots ==

1. Block log: 24-hour summary by reason, top IPs and User-Agents, temporarily blocked IPs and the latest events.
2. Bots and limits: AI training crawlers, AI search assistants, fake search engine detection and the bot trap.
3. Feeds and API: token-protected XML feeds with per-feed statistics, and text hidden from REST, GraphQL and RSS.
4. Server rules: ready-made Cloudflare, Nginx and Apache rules generated for your own site.
5. Presets, Emergency Mode and the on-page protection settings.
6. Dashboard widget with the protection status and the last 24 hours.

== Changelog ==

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
