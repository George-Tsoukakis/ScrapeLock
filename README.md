# Content Protect

WordPress plugin προστασίας περιεχομένου. Δυσκολεύει την αντιγραφή κειμένων και εικόνων από τους επισκέπτες και κλείνει τους εύκολους δρόμους μαζικής λήψης: REST API, RSS, scrapers και AI bots. Δεν ενοχλεί φόρμες, καλάθι, ταμείο, συντάκτες και μηχανές αναζήτησης.

- **Slug / φάκελος:** `content-protect`
- **Prefix:** `pncp_` / `PNCP_`
- **Option:** `pncp_settings` (ένα array)
- **Ρυθμίσεις:** wp-admin → Ρυθμίσεις → Προστασία περιεχομένου
- **Απαιτεί:** WordPress 6.0+, PHP 7.4+. Για το υδατογράφημα χρειάζεται η επέκταση GD της PHP.

## Λειτουργίες

Κάθε λειτουργία έχει δική της ρύθμιση. Οι συνδεδεμένοι χρήστες με το δικαίωμα που ορίζεται στο «Ποιοι εξαιρούνται» δεν επηρεάζονται.

| Λειτουργία | Προεπιλογή | Τι κάνει |
|---|---|---|
| Επιλογή, δεξί κλικ, συντομεύσεις, σύρσιμο εικόνων | ενεργά | JS/CSS μόνο στις σελίδες που προστατεύονται. Δεν πειράζει πεδία φόρμας, `contenteditable` και ό,τι έχει την κλάση `pncp-allow`. |
| Συντομεύσεις DevTools | ενεργό | Κόβει F12, Ctrl+Shift+I/J/C/K, Cmd+Opt+I/J/C/U. Δεν ανιχνεύει τα DevTools, δεν βάζει `debugger` και δεν κάνει redirect. |
| Αντιγραφή | με πηγή | Μπλοκάρισμα, κανονική αντιγραφή, ή αντιγραφή με «Πηγή: τίτλος – όνομα site + URL» (text/plain και text/html) από 200 χαρακτήρες και πάνω. |
| Εκτύπωση | με πηγή | Κανονική, με το URL στο κάτω μέρος, ή απαγόρευση. |
| REST API | ενεργό | Αδειάζει τα `content`/`excerpt` των δημόσιων post types (`/wp/v2/...`) και τα `description`/`short_description` του WooCommerce Store API (`/wc/store/v1/products`) για επισκέπτες. Το REST **δεν** κλείνει. Καλάθι και ταμείο του Store API δεν πειράζονται. |
| RSS / Atom | περίληψη | Μόνο περίληψη και σύνδεσμος «Διαβάστε το πλήρες άρθρο στο …», πλήρες κείμενο, ή απενεργοποίηση (410). |
| Scrapers / AI bots | ενεργό | 403 για τη λίστα User-Agents και για κενό User-Agent. |
| robots.txt | ενεργό | `Disallow: /` για AI crawlers (GPTBot, CCBot, ClaudeBot, PerplexityBot, Google-Extended κ.ά.) στο εικονικό robots.txt. |
| Όριο σελίδων ανά IP | ανενεργό (0) | 429 με `Retry-After: 60` πάνω από Ν σελίδες/λεπτό. Τιμή εκκίνησης: 60. |
| Ιδιωτικά URLs | κενή λίστα | Διαδρομές (π.χ. `/skroutz.xml`, `/feeds/*.xml`) που απαντούν μόνο με `?cp_token=…` ή σε επιτρεπόμενες IP/CIDR. Αλλιώς 403. |
| Πραγματική IP επισκέπτη | REMOTE_ADDR | Header με την πραγματική IP πίσω από CDN/proxy. Η σελίδα ρυθμίσεων δείχνει τι βλέπει ο server. |
| Ένδειξη κατάστασης | πάντα | Widget στον Πίνακα ελέγχου και κουμπί «Προστασία: ON/OFF» στη γραμμή διαχείρισης, με ενεργοποίηση/απενεργοποίηση με ένα κλικ (μόνο διαχειριστές). |
| Υδατογράφημα | ανενεργό | PNG από τη βιβλιοθήκη (ή το domain ως κείμενο) κάτω δεξιά, στα μεγέθη των **νέων** uploads. Το πρωτότυπο αρχείο δεν αλλάζει. Μεγέθη που ξαναφτιάχνονται από το «Επεξεργασία εικόνας» ή από επανάληψη αποτυχημένου upload μένουν χωρίς υδατογράφημα. |

### Τι δεν αλλάζει για τις μηχανές αναζήτησης
- Το HTML της σελίδας, τα structured data και τα meta των SEO plugins μένουν ίδια. Η προστασία είναι JS/CSS στον browser.
- Το Googlebot, το Bingbot, το Applebot και το Yandex επαληθεύονται με reverse DNS και forward DNS. Δεν μπλοκάρονται ποτέ και δεν μετράνε στο όριο. Το αποτέλεσμα κρατιέται 24 ώρες ανά IP. Ένα ψεύτικο «Googlebot» αντιμετωπίζεται σαν κανονικός επισκέπτης.
- Τα AI crawlers στο robots.txt δεν περιλαμβάνουν μηχανές αναζήτησης. Το `Google-Extended` αφορά μόνο την εκπαίδευση AI της Google, όχι την αναζήτηση.

## Εγκατάσταση
1. Πρόσθετα → Προσθήκη νέου → Μεταφόρτωση → `Content-Protect.zip` → Ενεργοποίηση.
2. Αν υπάρχει άλλο plugin προστασίας περιεχομένου, απενεργοποιήστε το, γιατί τα δύο μαζί συγκρούονται.
3. Ελέγξτε τις ρυθμίσεις. Στις ενημερώσεις, οι υπάρχουσες ρυθμίσεις μένουν και οι νέες λειτουργίες παίρνουν τις προεπιλογές του πίνακα.

Φτιάξιμο του zip από το repo (χωρίς tests και αρχεία τεκμηρίωσης):
```bash
git archive --format=zip --prefix=content-protect/ -o Content-Protect.zip HEAD
```

## Cache και server

**Page cache.** Ό,τι γίνεται στην PHP (μπλοκάρισμα bots, όριο σελίδων) ισχύει μόνο για αιτήματα που φτάνουν στην PHP. Σελίδες που σερβίρονται από Nginx FastCGI cache, Varnish ή CDN δεν περνούν από το plugin.
- **WP Rocket:** οι User-Agents της λίστας προστίθενται αυτόματα στο «Never send cache pages for these user agents» (`rocket_cache_reject_ua`), οπότε φτάνουν στην PHP και παίρνουν 403. Το WP Rocket συγκρίνει με διάκριση πεζών/κεφαλαίων, γι' αυτό γράψτε τα ονόματα όπως τα στέλνουν τα bots (π.χ. `GPTBot`). Σε Apache, ο έλεγχος στο `.htaccess` του WP Rocket μπορεί να ταιριάζει μόνο στην αρχή του User-Agent· η PHP του plugin πιάνει τα υπόλοιπα όταν η σελίδα δεν σερβίρεται από cache.
- **Αυτόματο άδειασμα cache:** η cache του WP Rocket και του Nginx Helper αδειάζει όταν αλλάζουν οι ρυθμίσεις, στην ενεργοποίηση και μετά από ενημέρωση.
- **Nginx FastCGI cache:** για πλήρη κάλυψη, βάλτε κανόνες και στον Nginx:

```nginx
# http { ... }
map $http_user_agent $pncp_bad_bot {
    default 0;
    ~*(GPTBot|ChatGPT-User|CCBot|ClaudeBot|anthropic-ai|PerplexityBot|Bytespider|meta-externalagent|Diffbot|Scrapy|HTTrack|python-requests|Go-http-client) 1;
    ""      1;
}
limit_req_zone $binary_remote_addr zone=pncp_pages:10m rate=60r/m;

# server { ... }
if ($pncp_bad_bot) { return 403; }
location / {
    limit_req zone=pncp_pages burst=30 nodelay;
    limit_req_status 429;
    try_files $uri $uri/ /index.php?$args;
}
```
Προσαρμόστε το `location /` στο δικό σας config. Μην βάλετε `limit_req` σε `/wp-admin`, `/wp-json` και στατικά αρχεία.

**Reverse proxy / CDN.** Πίσω από CDN (Cloudflare, BunnyCDN κ.ά.), το `REMOTE_ADDR` είναι η IP του CDN. Τότε όλοι οι επισκέπτες μετράνε ως λίγες IP: το όριο σελίδων θα μπλόκαρε πραγματικούς χρήστες και η επαλήθευση μηχανών αναζήτησης δεν δουλεύει. Λύσεις, από την καλύτερη:
1. `real_ip` στον Nginx με τις IP του CDN (`set_real_ip_from …; real_ip_header X-Forwarded-For;`). Έτσι και το `REMOTE_ADDR` γίνεται σωστό.
2. Η ρύθμιση «Πραγματική IP επισκέπτη» του plugin. Είναι ασφαλής μόνο αν ο server δέχεται αιτήματα αποκλειστικά από το CDN, γιατί αλλιώς το header πλαστογραφείται. Από το `X-Forwarded-For` κρατιέται η **τελευταία** τιμή, αυτή που πρόσθεσε το CDN, γιατί την αρχή της λίστας τη γράφει ο επισκέπτης. Αυτό προϋποθέτει ένα μόνο proxy/CDN μπροστά από τον server.
3. Το φίλτρο `pncp_client_ip`.

Η σελίδα ρυθμίσεων δείχνει το `REMOTE_ADDR` και τα σχετικά headers του δικού σας αιτήματος, για να δείτε ποιο έχει την IP σας.

**CDN που αγνοεί το query string.** Πολλά CDN (π.χ. BunnyCDN με «Ignore query string») δεν ξεχωρίζουν το `protect.js?ver=1.2.0` από το `?ver=1.1.0`. Μετά από κάθε ενημέρωση του plugin, κάντε purge στο CDN, ή ενεργοποιήστε «Vary cache by query string». Αλλιώς οι επισκέπτες παίρνουν το παλιό JavaScript μέχρι να λήξει η cache.

**Χωρίς persistent object cache** (Redis/Memcached), το όριο σελίδων και η επαλήθευση μηχανών αναζήτησης γράφουν transients στη βάση. Με object cache μένουν στη μνήμη.

**Wordfence και άλλα firewalls.** Δεν συγκρούονται, γιατί το plugin δεν πειράζει headers, cookies ή login. Αν χρησιμοποιείτε ήδη το Rate Limiting του Wordfence, αφήστε το όριο σελίδων εδώ στο 0, ώστε να μη μετράνε δύο συστήματα το ίδιο.

**XML feeds προϊόντων (Skroutz, BestPrice, Google Merchant).** Είναι συνήθως ένα δημόσιο URL με όλες τις περιγραφές, και είναι το πρώτο που κοιτάει ένας ανταγωνιστής. Βάλτε τη διαδρομή στα «Ιδιωτικά URLs» και δώστε στην υπηρεσία το URL με το `?cp_token=…` που δείχνει η σελίδα ρυθμίσεων. Ισχύει για feeds που φτιάχνει η PHP. Αν το feed είναι στατικό αρχείο (π.χ. `/wp-content/uploads/feeds/skroutz.xml`), τον έλεγχο πρέπει να τον κάνει ο web server:
```nginx
location ~* ^/wp-content/uploads/feeds/.*\.xml$ {
    if ($arg_cp_token != "ΤΟ_TOKEN_ΣΑΣ") { return 403; }
    add_header Cache-Control "private, no-store" always;
}
```
Σε CDN, εξαιρέστε τις διαδρομές των feeds από την cache.

**Αρχεία τεκμηρίωσης.** Το zip δεν περιέχει `readme.txt`/`README.md`, ώστε να μην είναι δημόσια στο `/wp-content/plugins/content-protect/`.

## Για προγραμματιστές

| Φίλτρο | Χρήση |
|---|---|
| `pncp_should_protect` | `bool` – αν η τρέχουσα σελίδα παίρνει JS/CSS προστασία. |
| `pncp_rest_post_types` | `string[]` – post types όπου κρύβεται το κείμενο στο REST. |
| `pncp_rest_hide_content` | `bool, WP_Post` – εξαίρεση για συγκεκριμένα άρθρα ή αιτήματα. |
| `pncp_client_ip` | `string` – η IP του επισκέπτη (για proxy/CDN). |
| `pncp_robots_ai_agents` | `string[]` – τα AI crawlers του robots.txt. |
| `pncp_watermark_attachment` | `bool, int` – εξαίρεση εικόνων από το υδατογράφημα. |

```php
// Να μην προστατεύεται μια συγκεκριμένη κατηγορία:
add_filter( 'pncp_should_protect', function ( $protect ) {
	return is_category( 'press' ) ? false : $protect;
} );

// Ένα δικό σας εργαλείο διαβάζει άρθρα μέσω REST με header X-My-Tool:
add_filter( 'pncp_rest_hide_content', function ( $hide ) {
	return isset( $_SERVER['HTTP_X_MY_TOOL'] ) ? false : $hide;
} );

// Πίσω από Cloudflare (μόνο αν ο server δέχεται αιτήματα αποκλειστικά από Cloudflare):
add_filter( 'pncp_client_ip', function ( $ip ) {
	return isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : $ip;
} );
```

Για ένα μόνο κομμάτι κειμένου που πρέπει να αντιγράφεται (τηλέφωνο, IBAN, κουπόνι), βάλτε του την CSS κλάση `pncp-allow`.

## Δομή
```
content-protect.php                 κεντρικό αρχείο, activation, cache, WP Rocket
includes/class-pncp-options.php     ρυθμίσεις, προεπιλογές, sanitize
includes/class-pncp-frontend.php    πού εφαρμόζεται η JS/CSS προστασία
includes/class-pncp-rest.php        κρύψιμο κειμένου στο REST API
includes/class-pncp-feed.php        RSS/Atom
includes/class-pncp-bots.php        bots, όριο σελίδων, robots.txt, επαλήθευση μηχανών αναζήτησης
includes/class-pncp-watermark.php   υδατογράφημα νέων uploads
includes/class-pncp-private-urls.php ιδιωτικά URLs (XML feeds) με token ή IP
includes/class-pncp-status.php      widget κατάστασης και κουμπί ON/OFF
includes/class-pncp-admin.php       σελίδα ρυθμίσεων (Settings API)
assets/js/protect.js                η προστασία στον browser
assets/css/protect.css              επιλογή κειμένου, μήνυμα, εκτύπωση
uninstall.php                       σβήνει ρυθμίσεις και προσωρινά δεδομένα
tests/protect.test.html             τεστ του protect.js στον browser
```

Τεστ JavaScript: από τον φάκελο του plugin τρέξτε `python3 -m http.server 8765` και ανοίξτε το `http://localhost:8765/tests/protect.test.html`.

## Εντοπισμός και αφαίρεση αντιγράφων

Η αντιγραφή βλάπτει κυρίως όταν το αντίγραφο εμφανίζεται στο Google. Αυτά δεν τα κάνει το plugin, αλλά είναι η προστασία που μετράει περισσότερο:
- **Δείξτε στο Google ότι είστε η πηγή.** Υποβάλετε κάθε νέα σελίδα αμέσως, μέσω Search Console ή IndexNow. Αν έχετε Rank Math, ενεργοποιήστε το «Instant Indexing». Το Yoast έχει επίσης ενσωματωμένο IndexNow.
- **Ψάξτε αντίγραφα.** Βάλτε μια χαρακτηριστική φράση σε εισαγωγικά στο Google, ή χρησιμοποιήστε το Copyscape.
- **Κατεβάστε τα αντίγραφα.** Κάντε αίτημα αφαίρεσης στο Google (DMCA) και, αν χρειαστεί, στείλτε email στον hosting provider του αντιγραφέα.
- **Βάλτε εσωτερικούς συνδέσμους μέσα στο κείμενο.** Τα scrapers τους αντιγράφουν μαζί, και το αντίγραφο οδηγεί πίσω σε εσάς.

**Αόρατο αποτύπωμα στο κείμενο:** δεν το περιλαμβάνει το plugin, σκόπιμα. Αόρατοι χαρακτήρες μέσα στο HTML αλλάζουν αυτό που βλέπουν οι μηχανές αναζήτησης και οι αναγνώστες οθόνης, και μπορεί να «σπάσουν» την αναζήτηση μέσα στη σελίδα. Η απόδειξη ότι είστε η πηγή γίνεται πιο αξιόπιστα με την ημερομηνία ευρετηρίασης (IndexNow/Search Console).

## Περιορισμοί
Η προστασία στον browser σταματά την εύκολη αντιγραφή, όχι κάποιον αποφασισμένο. Όποιος απενεργοποιήσει τη JavaScript ή κατεβάσει το HTML παίρνει το κείμενο. Τα DevTools ανοίγουν πάντα από το μενού του browser· το plugin κόβει μόνο τις συντομεύσεις. Γι' αυτό υπάρχουν και τα μέτρα στον server (REST, RSS, bots, όριο σελίδων).

## Άδεια
GPL-2.0-or-later.
