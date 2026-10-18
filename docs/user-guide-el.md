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
| Content Signals στο robots.txt: `search=yes, ai-train=no`, και `ai-input` ανάλογα με την AI αναζήτηση | robots.txt | Bots και όρια |
| Trusted Proxy: το `CF-Connecting-IP` / `X-Forwarded-For` διαβάζεται μόνο από αξιόπιστο proxy · αν όλοι οι επισκέπτες φαίνονται με διεύθυνση Cloudflare, κουμπί που το διορθώνει με ένα κλικ | PHP | Bots και όρια |
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

Ό,τι σερβίρεται από page cache (Nginx FastCGI cache, WP Rocket κ.λπ.) ή ως στατικό αρχείο δεν φτάνει στην PHP. Για πλήρη κάλυψη χρησιμοποιήστε τους κανόνες της καρτέλας **Κανόνες server**. Οι κανόνες βγαίνουν με το domain, τη λίστα bots, τα feeds και τον φάκελο αντιγράφων του δικού σας site. Τα βασικά για Nginx:

```nginx
# http { }
map $http_user_agent $pncp_bad_bot {
    default 0;
    "~*(GPTBot|ClaudeBot|CCBot|Bytespider|HeadlessChrome|python-requests|curl/)" 1;
    "" 1;
}
limit_req_zone $binary_remote_addr zone=pncp_pages:10m rate=60r/m;

# server { }
if ($pncp_bad_bot) { return 403; }
location ^~ /wp-content/uploads/pncp-originals-XXXXXXXXXXXX/ { deny all; return 404; }
# μέσα στο υπάρχον location / { }:
#   limit_req zone=pncp_pages burst=20 nodelay;
```

Η καρτέλα δίνει τους κανόνες σε δύο μέρη, `http { }` και `server { }`, φτιαγμένους για το site σας: domain, λίστα bots, feeds, φάκελος αντιγράφων. Τα παραπάνω είναι μόνο παράδειγμα.

**Plugin της Cloudflare (APO):** οι σελίδες από την cache της Cloudflare δεν φτάνουν στην PHP, όπως κάθε page cache. Το ScrapeLock λέει στο plugin της Cloudflare να μην κρατά στην cache τα 403 / 429, την παγίδα και τα feeds με token (`cf-edge-cache: no-cache` και φίλτρο `cloudflare_use_cache`), και του ζητά να αδειάσει την cache όταν αποθηκεύετε ρυθμίσεις. Για τις σελίδες από cache, οι κανόνες WAF της καρτέλας ισχύουν πριν από την cache.

Πίσω από Cloudflare, ο Nginx πρέπει να βλέπει την πραγματική IP:

```nginx
set_real_ip_from 173.245.48.0/20;   # … όλες οι διευθύνσεις του https://www.cloudflare.com/ips/
real_ip_header CF-Connecting-IP;
```

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
| `pncp_client_ip` | Η IP του επισκέπτη (για τον πρώιμο έλεγχο, το φίλτρο πρέπει να είναι σε mu-plugin) |
| `pncp_rest_hide_content` | Εξαιρέσεις από το κρύψιμο κειμένου (REST, GraphQL) |
| `pncp_rest_post_types` | Post types που φιλτράρονται στο REST |
| `pncp_watermark_attachment` | Αν μια εικόνα παίρνει υδατογράφημα |
| `pncp_watermark_batch_size` | Εικόνες ανά παρτίδα στο εργαλείο (3) |
| `pncp_robots_ai_agents` | AI crawlers στο robots.txt |
| `pncp_ai_search_agents` | Οι AI μηχανές αναζήτησης / βοηθοί της επιλογής «Επιτρέπονται οι AI μηχανές αναζήτησης» |
| `pncp_hotlink_allowed` | Domains που επιτρέπεται να φορτώνουν εικόνες |
| `pncp_block_framing` | `false` για να επιτρέψετε iframe |

Για ένα κομμάτι κειμένου που πρέπει να αντιγράφεται (τηλέφωνο, κουπόνι), βάλτε την κλάση `pncp-allow`.
