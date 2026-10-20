# ScrapeLock – Οδηγός χρήσης (ελληνικά)

Προστασία περιεχομένου για WordPress / WooCommerce.

**Τι δεν κάνει κανένα plugin:** ό,τι βλέπει ο επισκέπτης έχει ήδη φτάσει στη συσκευή του. Μια φωτογραφία με κινητό ή το reader mode του browser δεν σταματιούνται. Το plugin κλείνει τους αυτόματους δρόμους και αφήνει ίχνη: υδατογράφημα, πηγή στην αντιγραφή, αρχείο αποκλεισμών και νομική δήλωση (TDM).

## Επίπεδα

| Επίπεδο | Πού | Ρύθμιση |
|---|---|---|
| Δεξί κλικ, επιλογή, αντιγραφή (ή αντιγραφή με πηγή), σύρσιμο, συντομεύσεις, εκτύπωση, θόλωμα σε screenshot | browser | Στη σελίδα |
| Όχι μέσα σε iframe ξένου site (X-Frame-Options, CSP frame-ancestors) | header | Στη σελίδα |
| Δήλωση εξαίρεσης από AI / TDM (Οδηγία ΕΕ 2019/790 άρθ. 4, ν. 4996/2022): header, meta, `/.well-known/tdmrep.json`, `noai` | header / HTML | Στη σελίδα |
| Λίστα scrapers / AI bots, χωρίς User-Agent, «μόνο browsers» · χωριστή επιλογή για AI αναζήτηση (OAI-SearchBot, Claude-SearchBot, PerplexityBot κ.ά.) ενώ η εκπαίδευση (GPTBot, ClaudeBot, CCBot κ.ά.) μένει μπλοκαρισμένη | PHP | Bots και όρια |
| Ψεύτικα Googlebot / Bingbot / Applebot / Yandex: επίσημες λίστες IP (κάθε μέρα) + reverse/forward DNS | PHP | Bots και όρια |
| Επαλήθευση AI bots αναζήτησης (OAI-SearchBot, ChatGPT-User, PerplexityBot, Perplexity-User) με τις επίσημες λίστες IP τους, όταν επιτρέπεται η AI αναζήτηση: τα πραγματικά χωρίς όριο, τα ψεύτικα 403 | PHP | Bots και όρια |
| Παγίδα για bots (αόρατος σύνδεσμος, Disallow στο robots.txt) | PHP | Bots και όρια |
| Headless browsers (`HeadlessChrome` στο `Sec-CH-UA`) και scripts που αντιγράφουν μόνο το User-Agent ενός browser (σε HTTPS χωρίς `Sec-Fetch-*` / `Sec-CH-UA`): 403 · προαιρετικό | PHP | Bots και όρια |
| Όρια ανά IP: σελίδες, αναζήτηση, REST / GraphQL · προσωρινός αποκλεισμός μετά από N παραβάσεις σε 10 λεπτά | PHP | Bots και όρια |
| Όριο «η σελίδα δεν βρέθηκε» (404) ανά IP, για scrapers που μαντεύουν διευθύνσεις · εικόνες, CSS, scripts και favicon που λείπουν δεν μετρούν | PHP | Bots και όρια |
| Πάντα αποκλεισμένες IP / CIDR και domains παραπομπής (Referer, μαζί με τα subdomains τους) | PHP | Bots και όρια |
| Απόκρυψη ονομάτων χρηστών: `?author=N` → 404, REST `/wp/v2/users` → 401, χωρίς χάρτη χρηστών στο sitemap (οι συνδεδεμένοι βλέπουν τα πάντα) | PHP | Bots και όρια |
| Πρώιμος έλεγχος (προαιρετικός): το `wp-content/mu-plugins/scrapelock-early.php` σταματά bots της λίστας, αποκλεισμένες IP και referrers πριν φορτώσουν θέμα και plugins | PHP (mu-plugin) | Bots και όρια |
| Έλεγχος πριν από το cache (προαιρετικός): μία γραμμή στην κορυφή του `wp-config.php` εφαρμόζει το όριο σελίδων, τους αποκλεισμούς και τις πάντα αποκλεισμένες IP και στις σελίδες που σερβίρει το cache (WP Rocket κ.ά.) | PHP (wp-config.php) | Bots και όρια |
| robots.txt, llms.txt και llms-full.txt δεν μπλοκάρονται ποτέ, για κανένα bot (και στους κανόνες server), ώστε κάθε bot να μπορεί να διαβάσει τους κανόνες | PHP + server | — |
| Αρχείο: κουμπί «Μόνιμος αποκλεισμός», λίστα «Αποκλείστηκαν ξανά και ξανά (7 ημέρες)», σήμανση ψεύτικων / μη επαληθευμένων User-Agents, πόσα διαφορετικά User-Agents είχε ένα event | — | Αρχείο |
| Content Signals στο robots.txt: `search=yes, ai-train=no`, και `ai-input` ανάλογα με την AI αναζήτηση | robots.txt | Bots και όρια |
| Επαλήθευση ανθρώπου (προαιρετική): μετά την πρώτη πραγματική αλληλεπίδραση (scroll, άγγιγμα, πλήκτρο, κίνηση ποντικιού) ο browser λύνει στο παρασκήνιο ένα ελαφρύ «πρόβλημα» και παίρνει cookie `pncp_hv` για 7 ημέρες· όσοι δεν το έχουν παίρνουν αυστηρότερο όριο σελίδων. Χωρίς captcha, δουλεύει με page cache | PHP + JS | Bots και όρια |
| Όριο sitemap ανά IP (WordPress, Rank Math, Yoast κ.ά.)· ποτέ για επαληθευμένες μηχανές αναζήτησης | PHP | Bots και όρια |
| Χώρες: αποκλεισμός ή αυστηρότερο όριο. Χώρα από το `CF-IPCountry` (μόνο από Cloudflare), το `CDN-RequestCountryCode` (μόνο από Bunny CDN) ή από τη δωρεάν βάση DB-IP Lite (μία φορά τον μήνα, στο `uploads/scrapelock-geo`) | PHP | Bots και όρια |
| Αναφορά «τι προσπαθούν να αντιγράψουν»: οι σελίδες και τα αρχεία που μπλοκαρίστηκαν περισσότερο (24 ώρες / 7 ημέρες) | — | Αρχείο |
| Σελίδες άλλων plugins (π.χ. κοινότητα στο `/hub/space/`) στα «Pages»: από τα rewrite rules ή από τη ρύθμιση «Content addresses». Χωρίς «Μόνιμο αποκλεισμό» σε επίσημες διευθύνσεις (Google, Bing, OpenAI, Perplexity, Anthropic, Cloudflare, Bunny) | — | Αρχείο, Bots και όρια |
| Trusted Proxy: το `CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For` διαβάζεται μόνο από αξιόπιστο proxy (Cloudflare, Bunny CDN με την επίσημη λίστα του, ιδιωτικό δίκτυο, δική σας λίστα) · αν όλοι οι επισκέπτες φαίνονται με διεύθυνση Cloudflare ή Bunny, κουμπί που το διορθώνει με ένα κλικ | PHP | Bots και όρια |
| REST API και WPGraphQL χωρίς κείμενο για επισκέπτες · RSS μόνο περίληψη, ή πλήρες με «Το άρθρο … δημοσιεύτηκε πρώτα στο …» στο τέλος | PHP | Feeds και API |
| Προστατευμένα XML feeds με token (header για ERP, URL για Skroutz/BestPrice/Merchant), μόνο hash στη βάση (ποτέ σε καθαρή μορφή, ούτε στη μετάβαση από την 1.x), εναλλαγή με περίοδο χάριτος, στατιστικά | PHP | Feeds και API |
| Υδατογράφημα: γωνίες, κέντρο ή διαγώνια επανάληψη · προαιρετικά και στο πλήρες μέγεθος (το καθαρό φυλάγεται) · εργαλείο για τις υπάρχουσες εικόνες | εικόνες | Εικόνες |
| Κανόνες Nginx / Apache / Cloudflare φτιαγμένοι για το site | server / CDN | Κανόνες server |
| Αρχείο με διατήρηση 1/7/30 ημέρες, σύνοψη 24ώρου, άρση αποκλεισμών | — | Αρχείο |

Έτοιμα προφίλ (Ισορροπημένο / Αυστηρό / Μέγιστο) και **Emergency Mode** (1 ώρα έως 3 ημέρες, χωρίς να αλλάζουν οι ρυθμίσεις σας).

## Τι εξαιρείται πάντα

- Οι ρόλοι της ρύθμισης «Ποιοι εξαιρούνται» (από προεπιλογή συντάκτες και διαχειριστές), αιτήματα από τον ίδιο τον server, οι «Πάντα επιτρεπτές IP». Ένας απλός πελάτης με λογαριασμό ελέγχεται όπως κάθε επισκέπτης.
- Επαληθευμένες μηχανές αναζήτησης (ποτέ όριο, ποτέ αποκλεισμός).
- Τα όρια δεν μετρούν POST (φόρμες, καλάθι, ταμείο) και τα δηλωμένα `wc-ajax` του WooCommerce. Bots και αποκλεισμοί ελέγχονται και εκεί.
- Previews συνδέσμων (Facebook, Viber, WhatsApp κ.ά.) από τη λίστα «Πάντα επιτρεπτά».
- Υδατογράφημα: εικονίδιο site, λογότυπο, placeholder WooCommerce, η εικόνα του υδατογραφήματος και, από προεπιλογή, οι εικόνες προϊόντων. Το Google Merchant Center και οι πλατφόρμες σύγκρισης τιμών απορρίπτουν εικόνες προϊόντων με υδατογράφημα. Αν μια εικόνα με υδατογράφημα γίνει αργότερα λογότυπο ή εικόνα προϊόντος, το υδατογράφημα αφαιρείται αυτόματα.

## Page cache και στατικά αρχεία

Ό,τι σερβίρεται από page cache (Nginx FastCGI cache, WP Rocket κ.λπ.) ή ως στατικό αρχείο δεν φτάνει στο plugin. Τα bots της λίστας δεν παίρνουν ποτέ σελίδες από το cache του WP Rocket, οπότε ελέγχονται κανονικά. Για όλους τους άλλους υπάρχουν δύο λύσεις.

**Έλεγχος πριν από το cache** (Bots και όρια → Temporary block, «Pre-cache check»). Για cache που τρέχουν μέσα στην PHP (WP Rocket, WP Super Cache, W3 Total Cache κ.ά.). Το ScrapeLock προσθέτει αμέσως μετά το `<?php` του `wp-config.php`:

```php
// BEGIN ScrapeLock pre-cache check (added and removed by the plugin's "Pre-cache check" setting)
if ( is_file( '/…/wp-content/scrapelock-precheck/run.php' ) ) { include_once '/…/wp-content/scrapelock-precheck/run.php'; }
// END ScrapeLock pre-cache check
```

- Τρέχει πριν από το cache και το WordPress, χωρίς βάση δεδομένων. Σταματά μόνο τις πάντα αποκλεισμένες IP, τους προσωρινούς αποκλεισμούς και όσους ξεπερνούν το «Pages per minute».
- Οι παραβάσεις φέρνουν αποκλεισμό όπως στον κανονικό έλεγχο. Οι αποκλεισμοί και η άρση τους ισχύουν και στις δύο πλευρές. Τα συμβάντα εμφανίζονται στο Αρχείο.
- Μετρητές στο APCu ή σε αρχεία στο `wp-content/scrapelock-precheck`.
- Δεν μετρά: συνδεδεμένους χρήστες, φόρμες, prefetch, wp-admin, wp-login, REST, cron, τον ίδιο τον server, τις πάντα επιτρεπτές IP, το Google και το Bing από τις επίσημες διευθύνσεις τους. Το Applebot και το YandexBot αφήνονται στον κανονικό έλεγχο, και το WP Rocket δεν τους δίνει σελίδες από το cache.
- Δεν εφαρμόζει τα αυστηρότερα όρια (επαλήθευση ανθρώπου, χώρες) και το Emergency Mode: αυτά ισχύουν για τις σελίδες εκτός cache.
- Αν το `wp-config.php` δεν γράφεται, η ρύθμιση δείχνει τις γραμμές για να τις βάλετε με το χέρι. Όλα αφαιρούνται όταν κλείνει η ρύθμιση ή απενεργοποιείται το plugin. Όχι σε multisite.

**Ψεύτικοι browsers στους κανόνες server (2.6.2).** Με το «Block headless and fake browsers» ενεργό, οι κανόνες Nginx και Apache μπλοκάρουν και στον server τον «Chrome» / «Firefox» χωρίς τα headers που στέλνει πάντα ένας πραγματικός browser σε HTTPS. Έτσι πιάνονται και οι scanners που ζητούν αρχεία `.php` και δεν φτάνουν ποτέ στο WordPress. Το Googlebot και τα άλλα bots που γράφουν «Chrome/» στο User-Agent, τα in-app browsers του Android (WebView) και τα «Πάντα επιτρεπτά» δεν επηρεάζονται.

**Κανόνες server.** Για cache του Nginx (FastCGI cache) ή του CDN, που δεν περνούν καθόλου από την PHP, και για τα στατικά αρχεία: οι κανόνες της καρτέλας **Κανόνες server**. Οι κανόνες βγαίνουν με το domain, τη λίστα bots, τα feeds και τον φάκελο αντιγράφων του δικού σας site. Τα βασικά για Nginx:

```nginx
# http { }  (π.χ. /etc/nginx/conf.d/scrapelock-example_gr.conf)
map $http_user_agent $pncp_bad_bot_example_gr {
    default 0;
    "~*(GPTBot|ClaudeBot|CCBot|Bytespider|HeadlessChrome|python-requests|curl/)" 1;
    "" 1;
}
limit_req_zone $binary_remote_addr zone=pncp_pages_example_gr:10m rate=60r/m;

# server { }
if ($pncp_block_example_gr) { return 403; }
location ^~ /wp-content/uploads/pncp-originals-XXXXXXXXXXXX/ { deny all; return 404; }
# μέσα στο υπάρχον location / { }:
#   limit_req zone=pncp_pages_example_gr burst=20 nodelay;
```

Η καρτέλα δίνει τους κανόνες σε δύο μέρη, `http { }` και `server { }`, φτιαγμένους για το site σας: domain, λίστα bots, feeds, φάκελος αντιγράφων. Τα παραπάνω είναι μόνο παράδειγμα.

**Nginx σε κάθε server (2.6.3).**
- Τα ονόματα (μεταβλητές, ζώνη ορίου) έχουν την κατάληξη του site, π.χ. `_pharmacyneeds_gr`. Έτσι πολλά sites WordPress στον ίδιο Nginx βάζουν το καθένα τους δικούς του κανόνες χωρίς σύγκρουση στο `nginx -t`.
- Η καρτέλα γράφει πού μπαίνει κάθε μέρος: Debian / Ubuntu, CentOS / RHEL, Plesk, aaPanel, άλλα πάνελ.
- **Κατάσταση:** το plugin ρωτά το ίδιο το site στη διεύθυνση `/.well-known/scrapelock-nginx`, την οποία απαντά μόνο ο Nginx με τους κανόνες. Η καρτέλα δείχνει:
  - «Εγκατεστημένοι και ίδιοι με τις τρέχουσες ρυθμίσεις»·
  - «Εγκατεστημένοι, αλλά παλιοί», με το μέρος που πρέπει να αντιγραφεί ξανά·
  - «Δεν υπάρχουν».
- Χωρίς πρόσβαση στον Nginx (κοινόχρηστη φιλοξενία) οι κανόνες παραλείπονται: η προστασία γίνεται από το plugin και τον έλεγχο πριν από την cache.
- Το plugin **δεν** γράφει ποτέ το ίδιο στις ρυθμίσεις του Nginx: ο Nginx τις διαβάζει ως root, άρα ένα αρχείο που μπορεί να αλλάξει η PHP θα ήταν κίνδυνος.

**Plugin της Cloudflare (APO):** οι σελίδες από την cache της Cloudflare δεν φτάνουν στην PHP, όπως κάθε page cache. Το ScrapeLock λέει στο plugin της Cloudflare να μην κρατά στην cache τα 403 / 429, την παγίδα και τα feeds με token (`cf-edge-cache: no-cache` και φίλτρο `cloudflare_use_cache`), και του ζητά να αδειάσει την cache όταν αποθηκεύετε ρυθμίσεις. Για τις σελίδες από cache, οι κανόνες WAF της καρτέλας ισχύουν πριν από την cache.

Πίσω από Cloudflare, ο Nginx πρέπει να βλέπει την πραγματική IP:

```nginx
set_real_ip_from 173.245.48.0/20;   # … όλες οι διευθύνσεις του https://www.cloudflare.com/ips/
real_ip_header CF-Connecting-IP;
```

**Bunny CDN.** Δύο σωστοί τρόποι:
- Ο Nginx αντικαθιστά ήδη την IP (`real_ip_header X-Real-IP;` και ένα `set_real_ip_from` για κάθε edge server του Bunny, από το `https://bunnycdn.com/api/system/edgeserverlist`). Τότε η «Real visitor IP» μένει **REMOTE_ADDR**, και η σελίδα ρυθμίσεων γράφει ότι είναι σωστό.
- Αλλιώς: «Real visitor IP» = **X-Real-IP** και «Trust Bunny CDN addresses» ενεργό. Το ScrapeLock κατεβάζει κάθε μέρα την επίσημη λίστα και διαβάζει την κεφαλίδα μόνο από αυτούς τους servers. Αν όλοι οι επισκέπτες φαίνονται με διεύθυνση του Bunny, το κουμπί της προειδοποίησης το κάνει με ένα κλικ.

Η χώρα έρχεται από το `CDN-RequestCountryCode` του Bunny μόνο στον δεύτερο τρόπο, όπου το αίτημα φτάνει απευθείας από edge server του Bunny. Στον πρώτο χρησιμοποιείται η βάση DB-IP.

## Συμβατότητα (δοκιμασμένη)

| Τι | Πώς δοκιμάστηκε |
|---|---|
| WooCommerce 11.2 | Πλήρης αγορά (καλάθι, Store API checkout, «Ευχαριστούμε») με όριο 3 σελίδες/λεπτό και σε Emergency Mode· bots στο `wc-ajax` και στο Store API → 403· webhooks πληρωμών ανεπηρέαστα |
| WPGraphQL 2.6 | Κείμενο κρυφό για επισκέπτες, ορατό με application password· bots, όρια και αποκλεισμοί στο `/graphql` |
| REST API | Χωρίς κείμενο για επισκέπτες, και μέσω `?rest_route=`, `_method=GET`, `X-HTTP-Method-Override`, HEAD |
| WP Super Cache 3.1 | Τα 403 και τα feeds δεν μπαίνουν στην cache· η cache αδειάζει μετά από αλλαγή ρυθμίσεων· τα bots σε σελίδες από cache τα σταματούν οι κανόνες server |
| Nginx 1.24 / Apache 2.4 | Οι κανόνες της καρτέλας περνούν το `nginx -t` και λειτουργούν (bots, hotlink, πρωτότυπα, feeds, Bearer) |
| Redis object cache | Ατομικά όρια και αποκλεισμοί μέσω `wp_cache_incr` |
| Elementor, Bricks, Divi, Beaver, Oxygen, SiteOrigin | Η προεπισκόπηση του builder κλείνει την προστασία μόνο για όποιον μπορεί να επεξεργαστεί τη σελίδα (τα builders δεν εγκαταστάθηκαν) |

Φορτίο (Nginx + PHP-FPM 8 workers, MariaDB): η επιβάρυνση του plugin σε μια σελίδα είναι μέσα στον θόρυβο της μέτρησης. Το όριο είναι ακριβές με 200 ταυτόχρονα αιτήματα, 3000 αιτήματα από bot γράφουν μία γραμμή στο αρχείο, και 1500 ταυτόχρονοι αποκλεισμοί κρατιούνται όλοι.

## Apache και `Authorization: Bearer`

Με PHP-FPM/CGI ο Apache δεν περνά το `Authorization` στην PHP. Οι κανόνες Apache της καρτέλας περιέχουν τη γραμμή που το διορθώνει. Εναλλακτικά χρησιμοποιήστε το header `X-ScrapeLock-Token`.

## Αντίγραφα εικόνων

Όταν το υδατογράφημα μπαίνει και στο πλήρες μέγεθος, το καθαρό αρχείο φυλάγεται στο `wp-content/uploads/pncp-originals-<τυχαίο>/`. Ο φάκελος έχει `.htaccess` για τον Apache· στον Nginx βάλτε τον κανόνα `deny`. Η **Διαγραφή** του plugin δεν σβήνει αυτόν τον φάκελο, γιατί εκεί είναι τα μόνα καθαρά αντίγραφα. Πριν από το εργαλείο «Εφαρμογή υδατογραφήματος», κρατήστε backup του `uploads`.

## Για προγραμματιστές

| Φίλτρο | Τι κάνει |
|---|---|
| `pncp_should_protect` | Αν προστατεύεται η τρέχουσα σελίδα |
| `pncp_skip_guard` | Παράλειψη όλων των ελέγχων server για ένα αίτημα (στον πρώιμο έλεγχο με context `early`· εκεί φτάνουν μόνο φίλτρα από mu-plugins) |
| `pncp_404_exempt` | Αν ένα 404 εξαιρείται από το όριο «η σελίδα δεν βρέθηκε» |
| `pncp_human_difficulty` | Δυσκολία του «προβλήματος» της επαλήθευσης ανθρώπου (1–5, προεπιλογή 3) |
| `pncp_visitor_country` | Η χώρα του επισκέπτη (π.χ. από δική σας πηγή) |
| `pncp_geo_source_url` | Η διεύθυνση λήψης της βάσης χωρών |
| `pncp_client_ip` | Η IP του επισκέπτη (για τον πρώιμο έλεγχο, το φίλτρο πρέπει να είναι σε mu-plugin) |
| `pncp_rest_hide_content` | Εξαιρέσεις από το κρύψιμο κειμένου (REST, GraphQL) |
| `pncp_rest_post_types` | Post types που φιλτράρονται στο REST |
| `pncp_watermark_attachment` | Αν μια εικόνα παίρνει υδατογράφημα |
| `pncp_watermark_batch_size` | Εικόνες ανά παρτίδα στο εργαλείο (3) |
| `pncp_robots_ai_agents` | AI crawlers στο robots.txt |
| `pncp_ai_search_agents` | Οι AI μηχανές αναζήτησης / βοηθοί της επιλογής «Επιτρέπονται οι AI μηχανές αναζήτησης» |
| `pncp_hotlink_allowed` | Domains που επιτρέπεται να φορτώνουν εικόνες |
| `pncp_content_paths` | Αρχές διαδρομών με σελίδες άλλων plugins, για τα «Pages» του αρχείου |
| `pncp_block_framing` | `false` για να επιτρέψετε iframe |

Για ένα κομμάτι κειμένου που πρέπει να αντιγράφεται (τηλέφωνο, κουπόνι), βάλτε την κλάση `pncp-allow`.
