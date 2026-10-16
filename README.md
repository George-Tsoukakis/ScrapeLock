# ScrapeLock – Content & AI Bot Protection

Server-side anti-scraping for WordPress and WooCommerce, by CodeBunny. Formerly **Content Protect**.

Most content protection plugins disable right click in the browser. Scrapers and AI crawlers never use a browser, so they are not affected. ScrapeLock works on the server:

- **Real search engines vs. fakes:** Googlebot, Bingbot, Applebot and Yandex are verified against their official IP lists and with reverse + forward DNS.
- **AI training vs. AI search:** training crawlers are blocked; AI search assistants can be allowed with one option.
- **Per-IP limits and temporary blocks** for pages, searches and REST / GraphQL, plus an invisible bot trap.
- **Private XML feeds with a token** (header or URL, only the hash is stored, rotation with a grace period).
- **Text hidden from the REST API, WPGraphQL and full-text RSS** for visitors.
- **Ready-made Nginx, Apache and Cloudflare rules** for your own site.
- **Emergency Mode**, watermarks, copy-with-source, a block log and a TDM rights reservation.

The full description for the WordPress.org directory is in [`readme.txt`](readme.txt). A user guide in Greek is in [`docs/user-guide-el.md`](docs/user-guide-el.md).

## Repository layout

| Path | Contents |
|---|---|
| `scrapelock.php`, `includes/`, `assets/`, `languages/`, `uninstall.php`, `readme.txt` | The plugin, as installed in `wp-content/plugins/scrapelock/` |
| `tests/` | Tests on a real WordPress (HTTP, watermark, admin) and in Chromium |
| `translations/` | Greek translation (`.po`), for translate.wordpress.org |
| `wporg-assets/` | Icon, banner and screenshots for the WordPress.org page |
| `docs/` | User guide in Greek |
| `CHANGELOG.md` | Changes per version |

GitHub's **Download ZIP** contains only the plugin (`.gitattributes` leaves the rest out). Rename the extracted folder to `scrapelock` before installing.

## Build and checks

```sh
mkdir -p dist
git archive --format=zip --prefix=scrapelock/ -o dist/scrapelock-$(sed -n 's/^ \* Version: *//p' scrapelock.php).zip HEAD
phpcs                 # WordPress Coding Standards (phpcs.xml.dist)
cd tests && WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 ./run-all.sh
```

The same checks run on GitHub Actions for every pull request (`.github/workflows/ci.yml`). The plugin zip is kept as an artifact for 14 days, then deleted automatically.

## Upgrading from Content Protect

Deactivate Content Protect (folder `content-protect`) and activate ScrapeLock. Settings, feed tokens and the block log are kept. If you pasted the old Apache rules, replace the `# BEGIN Content Protect` block with the new `# BEGIN ScrapeLock` block from the "Server rules" tab.

## License

GPLv2 or later.
