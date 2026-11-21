# ScrapeLock 3.12.5 — θόλωμα μόνο για όσους δεν έχουν συνδεθεί

Η αναφορά μένει στο αποθετήριο (`/REPORT.md export-ignore`): δεν μπαίνει στο zip του plugin.

## 1. Τι ζητήθηκε / τι έγινε

Κάτω από το «Blur the page on screenshot shortcuts» (On the page): «Applies to: ( ) Everyone ( ) Only visitors who are not signed in», κλειδί `blur_on_capture_scope` = `all` | `guests`. Προεπιλογή και τιμή αναβάθμισης `all` (`new_in_3125()`): κανένα υπάρχον site δεν αλλάζει. Θαμπό με τη σημείωση «Takes effect only when …» όσο το θόλωμα είναι κλειστό. Οι εξαιρεμένοι («Who is excluded», `should_protect()`) δεν παίρνουν καθόλου script, όπως πριν.

## 2. Γιατί αποφασίζει ο browser

Με WP Rocket / Bunny η ίδια σελίδα HTML πάει σε όλους, άρα η PHP δεν μπορεί να ξέρει ποιος τη βλέπει. Το `pncpConfig` έχει `blurScope`, ίδιο για όλους· το `protect.js` με `guests` δεν ενεργοποιεί το θόλωμα όταν:

- υπάρχει το cookie **`pncp_si=1`** (το `wordpress_logged_in_*` είναι HttpOnly, αόρατο στη JavaScript), ή
- το body έχει την κλάση `logged-in` του WordPress (σελίδα χωρίς cache). Το body δεν υπάρχει ακόμη στο `<head>`, οπότε ελέγχεται ξανά όταν φτιάχνεται το layer και σε κάθε θόλωμα.

Το `mark.js` δεν χρησιμοποιήθηκε: υπάρχει μόνο όταν είναι ανοιχτό το υδατογράφημα αναγνώστη και θέλει επιπλέον αίτημα· το cookie δεν θέλει κανένα.

## 3. Το cookie `pncp_si` (`PNCP_Signin_Hint`)

- Μπαίνει μαζί με το `logged_in` (`set_logged_in_cookie`): ίδια paths (COOKIEPATH, SITECOOKIEPATH), domain (COOKIE_DOMAIN), Secure (https site μέσω https) και λήξη (0 χωρίς «Remember me»), SameSite=Lax, όχι HttpOnly. Τιμή μόνο `1`: κανένα όνομα, ID ή token.
- Σβήνει στο `clear_auth_cookie` (αποσύνδεση).
- Σε κανονικό αίτημα (`init`, και στο wp-admin) συνδεδεμένου browser χωρίς αυτό: μπαίνει ως cookie συνεδρίας (λογαριασμοί συνδεδεμένοι πριν την 3.12.5). Browser που δεν είναι πια συνδεδεμένος αλλά το στέλνει: σβήνει.
- Μπαίνει όποια κι αν είναι η ρύθμιση (η αλλαγή σε `guests` ισχύει αμέσως), ποτέ όσο η προστασία είναι κλειστή.
- Στο κείμενο της πολιτικής απορρήτου και στο readme.

## 4. Όρια

- Λογαριασμός συνδεδεμένος πριν την ενημέρωση, που βλέπει μόνο σελίδες από cache, θολώνει μέχρι την πρώτη σελίδα χωρίς cache (ή το wp-admin, ή νέα σύνδεση).
- Αν η συνεδρία ακυρωθεί στον server (αλλαγή κωδικού, «Log out everywhere»), το cookie μένει μέχρι το επόμενο αίτημα που φτάνει στο WordPress.
- Πλαστό `pncp_si=1` κλείνει το θόλωμα μόνο στον browser αυτού που το έβαλε· το θόλωμα είναι έτσι κι αλλιώς αποτρεπτικό στον browser.
- Οι έλεγχοι pre-cache / early δεν αγγίζουν το θόλωμα (επιβεβαιώθηκε, και με δοκιμή).
- Το `bin/build-min.sh` που αναφέρει το `PNCP_Frontend::asset()` δεν υπάρχει στο αποθετήριο· το `protect.min.js` ξαναχτίστηκε με `terser -c -m` και σφραγίδα `/*! src-sha1:<sha1> */` (το ίδιο εργαλείο ξαναφτιάχνει byte προς byte το min της 3.12.4).

## 5. Δοκιμές

- `tests/t_3125_blur.php` (61 PASS, MariaDB και SQLite): ρύθμιση, sanitize, αναβάθμιση 3.12.4 → 3.12.5, export / import, φόρμα, το cookie μέσω HTTP (σύνδεση με / χωρίς «Remember me», αποσύνδεση, παλιά συνεδρία σε σελίδα και wp-admin, ξεχασμένο cookie, προστασία κλειστή), ίδιο `pncpConfig` για επισκέπτη και μέλος, το min build σε χρήση.
- `tests/browser/blur3125.mjs` (Chromium): ο επισκέπτης θολώνει με PrintScreen και Ctrl+Shift+S· ο συνδεδεμένος subscriber όχι, ούτε στο HTML του επισκέπτη από «cache» (page.route), ούτε χωρίς cookie σε σελίδα χωρίς cache (κλάση body)· έλεγχος: σελίδα από cache χωρίς cookie θολώνει· με «Everyone» θολώνουν και οι δύο· ο editor (εξαιρείται) δεν παίρνει script· μετά την αποσύνδεση ξανά θόλωμα.
- Όλο το `tests/run-all.sh` σε MariaDB και σε SQLite (wp-sqlite-db, ένας php -S): μόνο οι γνωστές τοπικές αποτυχίες (t_http inline styles / data-cfasync / Applebot PTR ×2 / CF-Connecting-IP / αυτόματο Emergency ×2, t_metadata_paths «fake Applebot», t_lockdown «busy» ×2, t_site_files στο SQLite, t_traffic_ms skip). Το `t_311_compat` δέχεται πλέον το νέο κλειδί (κανένα δεν αφαιρέθηκε).
- Αναβάθμιση 3.12.4 (zip) → 3.12.5 με ρυθμίσεις από export της 3.10.1: καμία τιμή δεν άλλαξε, προστέθηκε μόνο `blur_on_capture_scope` = `all`, ίδια cron / πίνακες, χωρίς PHP μηνύματα· μετά τη σύνδεση ο browser έχει `pncp_si=1`.
- php -l, phpcs (phpcs.xml.dist) 0 σφάλματα, PHPStan level 5 χωρίς σφάλματα, `t_311_i18n` PASS.

# ScrapeLock 3.12.4 — «Installed, up to date» στο aaPanel

Η αναφορά μένει στο αποθετήριο (`/REPORT.md export-ignore`): δεν μπαίνει στο zip του plugin.

## 1. Η υπόθεση και τι ισχύει

Υπόθεση: το `location ~ \.well-known { allow all; }` του aaPanel (regex) κερδίζει το δικό μας `location /.well-known/scrapelock-nginx` (prefix), το αίτημα φτάνει στο WordPress → 404· λύση ένα `location =`.

Το μέρος 2 βγάζει **ήδη** `location = <nginx_check_path()>` από την 2.x, και το exact match κερδίζει κάθε regex. Αποδείχτηκε σε πραγματικό Nginx 1.24 + PHP-FPM 8.3 με διάταξη aaPanel και με το ακριβές server { } του live site (`extension/<site>/*.conf` στην αρχή, `location ~ \.well-known` 60 γραμμές πιο κάτω): η διεύθυνση ελέγχου απαντά 200 με τα δύο αποτυπώματα. Η υπόθεση δεν ήταν η αιτία.

## 2. Η πραγματική αιτία (επιβεβαιώθηκε στον live server)

1. **Rewrite του WordPress σε επίπεδο server.** Το `/www/server/panel/vhost/rewrite/<site>.conf` του aaPanel έχει `if (!-e $request_filename) { rewrite ^(.*)$ /index.php last; }` μέσα στο server { } (όχι σε location). Οι εντολές rewrite του server τρέχουν **πριν** ο Nginx διαλέξει location: το `/.well-known/scrapelock-nginx` γινόταν `/index.php` και απαντούσε το WordPress με 404, **και απευθείας στο 127.0.0.1**, όχι μόνο μέσω Bunny. Το ίδιο κάνουν συχνά BT Panel και CloudPanel.
2. **Ο έλεγχος ρωτούσε το CDN, όχι τον server.** Η 3.12.3 ρωτούσε `home_url(...)`, δηλαδή το Bunny. Χωρίς «Forward Host Header» απαντά άλλο server { } (το default του aaPanel) → 404· ένα 404 στην cache του Bunny (αν αγνοεί το query string) μένει και μετά την εγκατάσταση. Και τα δύο έδειχναν «Not installed» με σωστούς κανόνες.
3. Δευτερεύον: διεύθυνση site `http://` με «Force HTTPS» → 301 πριν από κάθε location, και η 3.12.3 δεν ακολουθεί redirects.

## 3. Τι έδειξε το stage (Nginx 1.24, PHP-FPM, CDN stand-in στη θέση του Bunny)

| Διάταξη / παραλλαγή | Η διεύθυνση ελέγχου απαντά | 3.12.3 | 3.12.4 |
|---|---|---|---|
| a) μέρος 2 στην αρχή του server { } | 200 αποτυπώματα | Installed, up to date | Installed, up to date (απευθείας στον server) |
| b) φάκελος extension (include στην αρχή, όπως στο live) | 200 | Installed | Installed |
| b′) φάκελος extension στο τέλος (παλιά διάταξη) | 200 — αλλά το PHP στα uploads εκτελείται και το hotlink jpg/png/gif δεν πιάνει (κερδίζουν τα regex του aaPanel) | Installed | Installed |
| c) μέσα στο `location / { }` του rewrite | 200 (το nested exact κερδίζει)· με private feed το `nginx -t` αποτυγχάνει (named location μόνο σε server)· τα bots σε `.php` δεν κόβονται | Installed | Installed |
| d) χωρίς μέρος 2 | 404 του Nginx (το `location ~ \.well-known`) | Not installed | «Not active: Nginx answered the check address itself (HTTP 404)…» |
| h) χωρίς μέρος 2, χωρίς `\.well-known` | 404 του WordPress | Not installed | «Not active: the check address reached WordPress…» |
| e) μέρος 2 στο `0.scrapelock-*.conf` (http { }) | `nginx -t`: "set" directive is not allowed here — μένει η παλιά ρύθμιση | ό,τι πριν | ό,τι πριν (+ οδηγία «not in http { }») |
| μέρος 2 δύο φορές (Config + extension) | `nginx -t`: "limit_req_status" directive is duplicate | ό,τι πριν | ό,τι πριν (+ οδηγία «only one of the two») |
| f) Bunny χωρίς Forward Host Header | απευθείας 200· μέσω CDN 404 (default site) | **Not installed** | **Installed, up to date** (απευθείας) |
| f2) ίδιο, ο server δεν απαντά απευθείας | μέσω CDN 404 | Not installed | «Not seen: … through the CDN …» + Forward Host Header / SCRAPELOCK_SERVER_IPS |
| g) 404 στην cache του CDN (query αγνοείται) | απευθείας 200· CDN: HIT 404 | **Not installed** | **Installed, up to date** |
| g3) ίδιο, ο server δεν απαντά απευθείας, και οι σελίδες στην cache | CDN: HIT | Not installed | «Not seen: the CDN answered … from its cache. Purge …» |
| **live server { } + rewrite σε επίπεδο server, μέρος 2 της 3.12.3** | **404 του WordPress** (`curl --resolve <site>:443:127.0.0.1`) | **Not installed** | Installed, up to date (από το header `X-ScrapeLock-Rules`) + «copy part 2 again» |
| **ίδιο, μέρος 2 της 3.12.4** | **200 `<http> <server>`** + header `X-ScrapeLock-Rules` | — | **Installed, up to date** (απευθείας) |

Τα αποτυπώματα δεν αλλάζουν από την 3.12.3 στην 3.12.4 για τις ίδιες ρυθμίσεις.

## 4. Τι άλλαξε

- **Μέρος 2**: ξεκινά με `# Put these lines directly inside server { }, not inside a location { }.` και, αμέσως μετά τις γραμμές του header, απαντά τη διεύθυνση ελέγχου σε επίπεδο server, πριν από κάθε rewrite από κάτω:
  `if ($uri = /.well-known/scrapelock-nginx) { return 200 "$pncp_rules_<site> <server hash>\n"; }` (υποφάκελος: η δική του διαδρομή). Δεν μπαίνει στο αποτύπωμα· ισχύει το `add_header X-ScrapeLock-Rules … always` του server { }· το `location =` μένει. Το `PNCP_Rules::evaluate()` απαντά το ίδιο. Κανένα άλλο `location =` στο μέρος 2: τίποτα δεν συγκρούεται με τα `location = /xmlrpc.php`, `= /wp-config.php` του panel.
- **Ο έλεγχος** (`PNCP_Rules_Status`): πρώτα απευθείας στον server (CURLOPT_RESOLVE σε 127.0.0.1 / SERVER_ADDR / `SCRAPELOCK_SERVER_IPS`, υπογραφή, User-Agent αυτοελέγχου, 3 s), μετά η δημόσια διεύθυνση· κρατά από πού. Χωρίς αποτύπωμα: το header `X-ScrapeLock-Rules` της απάντησης του WordPress (όπως κάθε αυτοέλεγχος: καρτέλα και ειδοποίηση συμφωνούν). http:// → https:// ακολουθείται μία φορά.
- **Τι απάντησε**: WordPress / Nginx / μόνο το CDN / cache του CDN / κάτι άλλο / τίποτα, μία γραμμή + «More», στην καρτέλα, στο Site Health, στα `wp scrapelock status` και `selfcheck`.
- **Apache**: δεν έχει διεύθυνση ελέγχου· το αποτύπωμα είναι header (mod_headers, έξω από τα RewriteRules, άρα η σειρά δεν παίζει ρόλο), το .htaccess δεν διαβάζεται. Η κάρτα Apache δείχνει τώρα την κατάσταση, ρωτώντας πρώτα τον server.
- **Οδηγίες aaPanel**: Config ακριβώς κάτω από `#SSL-END`, ή ο φάκελος extension όταν το Config τον κάνει include πάνω από τα location (όπως στο live)· μόνο το ένα· σε aaPanel / BT Panel / CloudPanel το μέρος 2 πάνω από το include του rewrite.

## 5. Βήματα στο aaPanel για «Installed, up to date»

1. Ενημέρωση του plugin σε 3.12.4.
2. Settings → ScrapeLock → Server rules → Nginx → μέρος 2 → Copy.
3. Αντικατάσταση **όλου** του περιεχομένου του `/www/server/panel/vhost/nginx/extension/pharmacyneeds.gr/scrapelock.conf` (το include είναι ήδη στην αρχή του server { }, πάνω από το include του rewrite). Όχι και στο Config: δύο φορές, το `nginx -t` αποτυγχάνει.
4. `nginx -t` → «test is successful» → `nginx -s reload` (ή App Store → Nginx → Reload).
5. Έλεγχος από τον server: `curl -sk --resolve pharmacyneeds.gr:443:127.0.0.1 https://pharmacyneeds.gr/.well-known/scrapelock-nginx` → `200` με δύο αποτυπώματα των 12 χαρακτήρων.
6. Server rules → «Check again»: «Status: Installed and up to date with the current settings.», «More» → «Checked on the server directly (127.0.0.1).»
7. Προαιρετικά στο Bunny: Pull zone → General → Origin → «Forward Host Header» ON· purge του `/.well-known/scrapelock-nginx`.

## 6. Τι δοκιμάστηκε / τι όχι

- Stage: Nginx 1.24 + PHP-FPM 8.3, διάταξη aaPanel, το server { } του live site, CDN stand-in (Host, cache που αγνοεί το query string), 3.12.3 και 3.12.4 δίπλα-δίπλα, μέσω της σελίδας διαχείρισης (PHP-FPM).
- `tests/t_3124_nginx_status.php`: σειρά server → δημόσια διεύθυνση (pre_http_request), κατάταξη απαντήσεων, κείμενα, Apache, μέρος 2, και με πραγματικό Nginx (SKIP χωρίς nginx, όπως στο CI).
- Δεν δοκιμάστηκε: το πραγματικό Bunny και το πραγματικό aaPanel (Save του Config).

---

# ScrapeLock 3.12.3 — αναφορά για τον server (aaPanel, Nginx, Bunny CDN)

Η αναφορά μένει στο αποθετήριο (`/REPORT.md export-ignore`): δεν μπαίνει στο zip του plugin.

## 1. Τι βρέθηκε στον live server

Στο access log του Nginx, οι έλεγχοι του ίδιου του site («Check again» στα Ευάλωτα σημεία, Site Health, «Πραγματικός αυτοέλεγχος τώρα») έπαιρναν 403:

```
127.0.0.1 / <δημόσια IP του server> "GET / HTTP/1.1" 403 548
UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 ScrapeLock-Selftest
```

- Το 403 το έδινε ο **ίδιος ο Nginx**, με τους κανόνες που φτιάχνει το ScrapeLock (καρτέλα Κανόνες διακομιστή, αρχείο `0.scrapelock-<site>.conf` του aaPanel), από το map `fake_browser`:
  `"~^on\|\|\|.*\b(Chrome|Chromium)/(9[0-9]|[1-9][0-9]{2})\." 1;` — HTTPS, χωρίς `Sec-Fetch-Mode`, χωρίς `Sec-CH-UA`, User-Agent του Chrome.
- curl με το ίδιο User-Agent χωρίς Sec-Fetch → 403· με `Sec-Fetch-Mode` και `Sec-CH-UA` → 200.
- Οι κανόνες του Nginx τρέχουν **πριν από την PHP**: η υπογραφή `X-ScrapeLock-Sig` της 3.12.x δεν μπορούσε ποτέ να βοηθήσει εκεί.
- Ο server είχε ακόμη **παλιούς κανόνες** που μπλόκαραν ChatGPT-User και PerplexityBot ενώ `allow_ai_search = 1`, και το plugin δεν έλεγε τίποτα γι' αυτό.

## 2. Αιτία

1. Ο αυτοέλεγχος συστηνόταν ως Chrome χωρίς τα headers που στέλνει κάθε πραγματικός Chrome: για τους κανόνες του ίδιου του ScrapeLock ήταν ακριβώς ένας «ψεύτικος browser».
2. Οι κανόνες server δεν εξαιρούσαν τις διευθύνσεις του ίδιου του server (127.0.0.1, η δημόσια IP του, όπως τη δίνει το `real_ip` πίσω από το Bunny).
3. Το plugin δεν έβλεπε ποιοι κανόνες είναι εγκατεστημένοι στον server (για τον Nginx υπήρχε μόνο η διεύθυνση ελέγχου, που τη ρωτούσε μόνο η καρτέλα), οπότε οι παλιοί κανόνες έμεναν χωρίς ειδοποίηση. Ο σημερινός generator κάνει σωστά το «Allow AI search» (τα AI search bots δεν μπλοκάρονται όσο είναι ανοιχτό)· οι κανόνες του server ήταν απλώς παλιοί.

## 3. Τι άλλαξε στην 3.12.3

### 3.1 Οι αυτοέλεγχοι δεν μοιάζουν πια με ψεύτικο browser
- Κάθε αυτοέλεγχος (όλοι οι ζωντανοί έλεγχοι των Ευάλωτων σημείων — headers, framing, user_enum, xmlrpc, hide_admin κ.λπ. —, η δοκιμή του Stealth, τα tests του Site Health μαζί με το self-request test, robots.txt / φάκελοι / αρχεία του site, «Πραγματικός αυτοέλεγχος τώρα», `wp scrapelock selfcheck`, ο έλεγχος κατάστασης των κανόνων Nginx) στέλνει **`ScrapeLock-Selftest/3.12.3 (+https://<site>)`** και την υπογραφή. Χωρίς «Mozilla/», χωρίς «Chrome/». Το User-Agent το επιβάλλει το `PNCP_Self_Check::request()`, ό,τι κι αν δώσει ο έλεγχος.
- Οι έλεγχοι της PHP το αφήνουν να περάσει **μόνο με την υπογραφή** (και με «Browsers only»)· χωρίς υπογραφή το ίδιο όνομα απορρίπτεται όπως κάθε άλλο (το στέλνει όποιος θέλει). Στους κανόνες server το όνομα δεν εξαιρείται (θα το πλαστογραφούσε ο καθένας)· απλώς δεν ταιριάζει με τον κανόνα fake_browser, και ο server εξαιρείται από τη διεύθυνσή του (3.2).
- Κανένας έλεγχος δεν χρειάζεται απάντηση «σαν browser»: όλοι ελέγχουν headers, κωδικούς και περιεχόμενο που δεν εξαρτώνται από το User-Agent, οπότε κανένας δεν στέλνει πλήρες προφίλ Chrome.
- Όταν ο web server απαντά 403 και η PHP του ScrapeLock δεν είδε το αίτημα (χωρίς `X-ScrapeLock`, τίποτα στο ring buffer), το αίτημα που στάλθηκε περνά από **τη λογική των τρεχόντων κανόνων** (`PNCP_Rules::evaluate()`: τα ίδια maps με τους κανόνες Nginx, η ίδια έκφραση αποκλεισμού, οι διευθύνσεις του server, μετά οι locations του μέρους 2). Αν τους αρνείται, ο έλεγχος λέει «**Refused by ScrapeLock's own server rule (fake browser)**» (ή τον κανόνα που ήταν) και τι να γίνει· αλλιώς μένει «web server». Αν οι εγκατεστημένοι κανόνες είναι παλιοί, το λέει κι αυτό.

### 3.2 Οι κανόνες server δεν μπλοκάρουν ποτέ τον ίδιο τον server
Nginx (μέρος 1, http { }):
```nginx
geo $pncp_self_<site> {
    default 0;
    127.0.0.1 2;
    ::1 2;
    <δημόσια IP του server> 1;
}
map "$http_x_forwarded_for$http_x_real_ip$http_forwarded$http_cf_connecting_ip" $pncp_fwd_<site> { default 1; "" 0; }
map "$pncp_bad_bot_<site>$pncp_fake_browser_<site>:$pncp_open_path_<site>:$pncp_self_<site>$pncp_fwd_<site>" $pncp_block_<site> {
    default 0;
    "~^[01]*1[01]*:0:(0[01]|21)$" 1;
}
```
- `1` = δημόσια διεύθυνση του server: εξαιρείται πάντα (και μέσω CDN με `real_ip`). `2` = loopback / ιδιωτική: εξαιρείται μόνο όταν **κανένας proxy** δεν πέρασε το αίτημα (κανένα X-Forwarded-For, X-Real-IP, Forwarded, CF-Connecting-IP)· αλλιώς ένα tunnel ή proxy στο ίδιο μηχάνημα θα έκανε κάθε επισκέπτη «τον server».
- Διευθύνσεις: 127.0.0.1, ::1, SERVER_ADDR, η διεύθυνση εξόδου που μαθαίνεται από τα υπογεγραμμένα αιτήματα, `SCRAPELOCK_SERVER_IPS`, φίλτρο `pncp_server_ips`. Όχι οι διευθύνσεις στις οποίες λύνεται το όνομα του site (πίσω από άγνωστο CDN θα ήταν του CDN). Ποτέ edge CDN, μόνο IPv4 / IPv6 / CIDR (κάθε τιμή ελέγχεται πριν γραφτεί), ποτέ ιδιωτικό range ευρύτερο από /24 (IPv6 /64). Δεν μπαίνουν στο αποτύπωμα (δεν είναι ρυθμίσεις).
- Με «Always allowed IPs» ούτε το όριο σελίδων μετρά τον server. **Χωρίς αυτές το κλειδί της ζώνης μένει `$binary_remote_addr`**: ο Nginx αρνείται reload όταν αλλάζει το κλειδί υπάρχουσας ζώνης (το `nginx -t` περνά, το reload αποτυγχάνει — βρέθηκε στη δοκιμή).

Apache / LiteSpeed (.htaccess):
```apache
RewriteCond %{REMOTE_ADDR} ^(?:<δημόσια IP του server>)$ [OR]
RewriteCond %{REMOTE_ADDR}%{HTTP:X-Forwarded-For}%{HTTP:X-Real-IP}%{HTTP:Forwarded}%{HTTP:CF-Connecting-IP} ^(?:127\.0\.0\.1|::1)$
RewriteRule .* - [E=PNCP_SELF:1]
# και πριν από κάθε ομάδα αποκλεισμού (bots, κενό User-Agent, ψεύτικος Chrome / Firefox):
RewriteCond %{ENV:PNCP_SELF} !^1$
```
Ranges (CIDR) με `RewriteCond expr "-R '…'"` μέσα σε `<IfModule !LiteSpeed>` (εκφράσεις του Apache 2.4).

Η καρτέλα Κανόνες διακομιστή γράφει σε μία γραμμή ποιες διευθύνσεις εξαιρούνται, και στο «More» ότι πίσω από Bunny με `real_ip` τα αιτήματα του server μέσω CDN κρατούν τη διεύθυνσή του, ενώ χωρίς `real_ip` έρχονται από το edge.

### 3.3 Ειδοποίηση για παλιούς κανόνες
Header με το αποτύπωμα, **μόνο** για αιτήματα με `X-ScrapeLock-Sig`:
```nginx
# μέρος 2, server { }
set $pncp_rules_hdr_<site> "";
if ($http_x_scrapelock_sig) { set $pncp_rules_hdr_<site> "$pncp_rules_<site> <hash μέρους 2>"; }
add_header X-ScrapeLock-Rules $pncp_rules_hdr_<site> always;
```
```apache
<IfModule mod_headers.c>
Header always set X-ScrapeLock-Rules "<hash>" "expr=-n %{HTTP:X-ScrapeLock-Sig}"
</IfModule>
```
- Τιμή στον Nginx: «`<hash http> <hash server>`», όπως απαντά και η διεύθυνση ελέγχου `/.well-known/scrapelock-nginx`.
- **Περιορισμός του Nginx**: τα `add_header` κληρονομούνται μόνο από ένα επίπεδο. Μια location με δικά της `add_header` δεν στέλνει το header (επαναλάβετε εκεί τη γραμμή), και αν το nginx.conf έχει `add_header` μόνο στο http { }, μια γραμμή add_header στο server { } τα ακυρώνει για αυτό το site: επαναλάβετέ τα στο server { }. Το λέει το σχόλιο των κανόνων. Όταν το header λείπει, μετρά η διεύθυνση ελέγχου.
- Κάθε αυτοέλεγχος διαβάζει το header από απάντηση που έδωσε το ίδιο το WordPress σε εκείνο το αίτημα (όχι από αντίγραφο της cache του CDN) και το συγκρίνει με τους κανόνες των τρεχουσών ρυθμίσεων (option `pncp_rules_state`). Οι κανόνες Nginx πριν από την 3.12.3 αναγνωρίζονται από τη διεύθυνση ελέγχου (τη ρωτούν ο «Πραγματικός αυτοέλεγχος», το Site Health, το `wp scrapelock selfcheck` και η καρτέλα).
- Όταν διαφέρουν, και **αμέσως μετά την αποθήκευση** ρύθμισης που αλλάζει τους κανόνες: ειδοποίηση (μόνο manage_options, στις σελίδες του ScrapeLock και στον πίνακα ελέγχου, κλείνει ανά αποτύπωμα) και Site Health «recommended»: «The server rules are out of date (installed: X, current: Y). Copy them again from Server rules.», με κουμπί «See what changed» (διαφορές γραμμή προς γραμμή από το κείμενο που έδειξε η καρτέλα, τα τελευταία 4 ανά μορφή· αν δεν είναι γνωστό, δείχνει τους τρέχοντες κανόνες και το λέει). Site που δεν εγκατέστησε ποτέ κανόνες δεν ενοχλείται.
- «Allow AI search»: επιβεβαιωμένο με δοκιμή ότι οι τρέχοντες κανόνες (Nginx, Apache, Cloudflare) δεν μπλοκάρουν τα AI search bots όσο είναι ανοιχτό, και τα μπλοκάρουν όσο είναι κλειστό.

## 4. Τι κάνετε μετά την ενημέρωση

1. Ενημέρωση του plugin σε 3.12.3.
2. Ρυθμίσεις → ScrapeLock → **Κανόνες διακομιστή**: αντιγράψτε το μέρος 1 στο `/www/server/panel/vhost/nginx/0.scrapelock-<site>.conf` (αντικατάσταση όλου του αρχείου) και το μέρος 2 εκεί όπου το είχατε στο server { } του site (αντικατάσταση του παλιού).
3. `nginx -t` — συνεχίστε μόνο αν πει «test is successful».
4. `nginx -s reload` (ή `systemctl reload nginx`). Αν το reload δεν πάρει, κοιτάξτε το error log του Nginx.
5. Ευάλωτα σημεία → **Check again**.
6. Log → Check a request → **Πραγματικός αυτοέλεγχος τώρα** (ή `wp scrapelock selfcheck`): πρέπει να πει «The site reaches itself through its public address (HTTP 200)» χωρίς γραμμή «out of date». Η ειδοποίηση για παλιούς κανόνες φεύγει μόνη της.
7. Έλεγχοι με curl (στη θέση του `example.gr` το site σας):
   ```sh
   UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
   # Από εξωτερική IP (π.χ. τον υπολογιστή σας): ψεύτικος Chrome χωρίς Sec-Fetch → 403
   curl -s -o /dev/null -w '%{http_code}\n' -A "$UA" https://example.gr/
   # Από τον ίδιο τον server, στο 127.0.0.1 (με το σωστό Host / SNI) → 200
   curl -sk -o /dev/null -w '%{http_code}\n' -A "$UA" --resolve example.gr:443:127.0.0.1 https://example.gr/
   # Ο ίδιος Chrome με τα headers ενός πραγματικού browser, από εξωτερική IP → 200
   curl -s -o /dev/null -w '%{http_code}\n' -A "$UA" -H 'Sec-Fetch-Mode: navigate' -H 'Sec-CH-UA: "Chromium";v="130"' https://example.gr/
   # Το αποτύπωμα των εγκατεστημένων κανόνων (μόνο με X-ScrapeLock-Sig)
   curl -sk -D - -o /dev/null -H 'X-ScrapeLock-Sig: x' --resolve example.gr:443:127.0.0.1 https://example.gr/ | grep -i x-scrapelock-rules
   ```
   Αν ο server βγαίνει προς τα έξω από άλλη διεύθυνση από αυτή που βλέπει το Bunny, προσθέστε τη στο wp-config.php: `define( 'SCRAPELOCK_SERVER_IPS', '<διεύθυνση>' );` και αντιγράψτε ξανά τους κανόνες.

## 5. Τι δοκιμάστηκε

- **Πραγματικός Nginx 1.24** (στο container): WordPress πίσω από Nginx με TLS (https://127.0.0.1:8443), `real_ip` από ένα «edge» Nginx που παριστάνει το Bunny, διεύθυνση server 198.51.100.50 (`SCRAPELOCK_SERVER_IPS`), εξωτερικός επισκέπτης 198.51.100.20 (alias στο lo, `curl --interface`):

  | Σενάριο | Αποτέλεσμα |
  |---|---|
  | 3.12.2 plugin + 3.12.2 κανόνες: `wp scrapelock selfcheck` | 403 «web server» (αναπαραγωγή του live server) |
  | 3.12.2 κανόνες: ψεύτικος Chrome από 198.51.100.20 / από 127.0.0.1 | 403 / 403 |
  | 3.12.3 plugin, 3.12.2 κανόνες ακόμη: selfcheck | 200, και «The server rules are out of date (installed: …, current: …)»· ειδοποίηση στον πίνακα ελέγχου, «See what changed» (κείμενο άγνωστο) |
  | Αντιγραφή των νέων κανόνων από την καρτέλα, `nginx -t`, reload | test successful, reload χωρίς σφάλμα |
  | Ψεύτικος Chrome χωρίς Sec-Fetch από 198.51.100.20 | **403** |
  | Ψεύτικος Chrome από 127.0.0.1 | **200** |
  | Ψεύτικος Chrome από 127.0.0.1 με X-Forwarded-For (τοπικός proxy) | 403 |
  | Μέσω «edge», πελάτης 198.51.100.20 / πελάτης ο server 198.51.100.50 (real_ip) | 403 / 200 |
  | Browser με Sec-Fetch-Mode + Sec-CH-UA | 200 |
  | GPTBot / ChatGPT-User / PerplexityBot (allow_ai_search=1) / κενό UA | 403 / 200 / 200 / 403 |
  | `X-ScrapeLock-Rules` με / χωρίς X-ScrapeLock-Sig | το αποτύπωμα / τίποτα |
  | `wp scrapelock selfcheck` και το κουμπί «Run a real self-check now» (AJAX) | 200 και τα δύο |
  | Αλλαγή ρύθμισης → ειδοποίηση αμέσως, «See what changed» με διαφορές· αντιγραφή + reload + selfcheck | η ειδοποίηση φεύγει |
- Στην πρώτη εκδοχή το κλειδί της ζώνης `limit_req` άλλαζε και το **reload αποτύγχανε** παρότι περνούσε το `nginx -t`· διορθώθηκε (το κλειδί μένει) και ξαναδοκιμάστηκε.
- `nginx -t` για 8 συνδυασμούς ρυθμίσεων (όλα κλειστά, μόνο bots, μόνο headless, όλα μαζί με ιδιωτικά feeds, Always allowed IPs, CIDR IPv4/IPv6, ×2 με site σε υποφάκελο) και δύο sites στον ίδιο Nginx: όλα successful.
- **Πραγματικός Apache 2.4.58** (mod_rewrite, mod_headers, mod_remoteip για τη διεύθυνση, TLS): 22 αιτήματα (ψεύτικος Chrome από επισκέπτη / 127.0.0.1 / 127.0.0.1 με proxy / δημόσια διεύθυνση του server / ιδιωτική / CIDR IPv4 και IPv6 / edge, bots, AI search, κενό UA, readme, PHP στα uploads, hotlinking) όλα όπως αναμένεται· το header μόνο με X-ScrapeLock-Sig (και σε 403). 8 συνδυασμοί ρυθμίσεων χωρίς 500 (εκτός από το παλιό θέμα της §6).
- `tests/t_3123_rules.php` (106 έλεγχοι): User-Agent κάθε αυτοελέγχου (καταγραφή με pre_http_request και `wp scrapelock selfcheck`), διευθύνσεις στους κανόνες, απόφαση αποκλεισμού, header, «Allow AI search», παλιοί κανόνες, ειδοποίηση / Site Health / diff (nonce, manage_options), evaluator· πίνακας 23 αιτημάτων στον οποίο ο evaluator και ο πραγματικός Nginx συμφωνούν (στο CI, χωρίς nginx, αυτό το μέρος γίνεται SKIP).
- Όλη η σουίτα σε MariaDB και σε SQLite (όπως στο CI)· phpcs και PHPStan (level 5) χωρίς σφάλματα· αναβάθμιση 3.12.2 → 3.12.3 με ίδιες ρυθμίσεις και χωρίς PHP warnings από το plugin· zip (3.12.3, με το .mo, χωρίς tests, .po και αυτή την αναφορά).

## 6. Τι δεν δοκιμάστηκε

- Ο πραγματικός live server, το aaPanel και το πραγματικό Bunny (τίποτα δεν ανέβηκε live). Το Bunny παραστάθηκε από Nginx που περνά τη διεύθυνση στο X-Forwarded-For.
- PHP-FPM: η PHP έτρεχε με τον built-in server πίσω από proxy_pass.
- LiteSpeed / OpenLiteSpeed: οι απλές διευθύνσεις στους κανόνες Apache είναι κανονικές εκφράσεις και πρέπει να δουλεύουν· τα ranges χρειάζονται εκφράσεις του Apache 2.4 και στο LiteSpeed παραλείπονται. Το `Header … "expr=…"` στο LiteSpeed δεν δοκιμάστηκε.
- Υπάρχον θέμα (και στην 3.12.2, δεν αλλάχτηκε σε αυτή την έκδοση): ιδιωτική διαδρομή με κενό (π.χ. `/price list.xml`) δίνει μη έγκυρο `RewriteRule` στον Apache (500).
