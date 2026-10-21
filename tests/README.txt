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
  t_watermark.php   υδατογράφημα: ποτέ διπλό (Regenerate, update subsizes, εικόνες 1.4), πλήρες μέγεθος με καθαρό
                    αντίγραφο, -scaled, αφαίρεση, εικονίδιο/λογότυπο/προϊόντα/εικόνα υδατογραφήματος, θέσεις, JPEG/WebP
  t_admin.php       καρτέλες χωρίς PHP warnings, απενεργοποίηση μόνο με επιβεβαίωση, φόρμα καρτέλας που δεν σβήνει
                    άλλες, προφίλ, token μία φορά, αρχείο/διατήρηση, λίστες IP, εργαλείο εικόνων, κανόνες, GraphQL
  t_precheck.php    έλεγχος πριν από το cache (wp-config.php, loader, όρια, αποκλεισμοί)
  t_lockdown.php    Κλείδωμα: εφαρμογή authenticator, κάθε οθόνη, REST, κώδικας, ρόλοι, Abilities, Site Health
  t_cli.php         wp scrapelock … μέσα από το πραγματικό wp (χρειάζεται WP_CLI, αλλιώς SKIP)
  browser/          protect.js σε Chromium: δεξί κλικ/αντιγραφή/επιλογή/σύρσιμο ακόμη και με «εχθρικό» script,
                    αντιγραφή με πηγή, .pncp-allow, πεδία φόρμας, ελληνική διάταξη, θόλωμα (npm install && npm test)

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
