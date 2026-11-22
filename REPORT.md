# ScrapeLock 3.12.9 — ούτε δίσκος ούτε βάση στο αίτημα του επισκέπτη (APCu / Redis), circuit breaker, `wp scrapelock precheck | breaker`

Η αναφορά μένει στο αποθετήριο (`/REPORT.md export-ignore`): δεν μπαίνει στο zip του plugin. `<site>` είναι ο φάκελος του ιστότοπου στο aaPanel· τίποτα από τον live server (domain, IP, paths, κωδικοί) δεν είναι στον κώδικα, στις δοκιμές ή εδώ.

## H1. Η αιτία των 504

- **Τι έδειξε ο server.** Στο slow log της 21/11, 37 αιτήματα πάνω από 30 s με το ScrapeLock στη στοίβα· στην κορυφή της στοίβας `fclose()` / `ftruncate()` στο `increment()` του ελέγχου πριν από την cache, `scandir()` / `unlink()` στο `cleanup()`, και `update_option()` (μέσω `mysqli_query`) στο `PNCP_Surge`. Το `sar` την ίδια ώρα: iowait 71–99 %, ~1,4 tps, await 72 ms, και swap (ο mysqld με 565 MB στο swap, pswpout 510/s σε μία στάση). Δηλαδή **ο δίσκος «πάγωνε»** για δευτερόλεπτα· δεν ήταν φορτίο ούτε `flock()` χωρίς `LOCK_NB` (μια αναμονή σε κλειδαριά θα έδειχνε `flock()` στην κορυφή, όχι `fclose` / `ftruncate` / `scandir` / `unlink` / `mysqli_query`).
- **Γιατί έπεφτε όλο το site.** Το ScrapeLock έκανε σε **κάθε** αίτημα επισκέπτη δική του δουλειά σε αρχεία (μετρητές, νέο αρχείο ανά IP και λεπτό, events.log, καθάρισμα των παλιών λεπτών από το πρώτο αίτημα κάθε λεπτού) και στη βάση (μέτρηση όλου του site, αρχείο, αποκλεισμοί, Traffic). Όταν ο δίσκος σταματούσε, κάθε worker που έφτανε εκεί έμενε σε αναμονή δίσκου (κατάσταση D) μέχρι να ξαναπάρει μπροστά· με ένα pool 20 workers για δύο sites, γέμιζε μέσα σε λίγα δευτερόλεπτα και ο Nginx απαντούσε 504.
- **Το δεύτερο site** του ίδιου pool είχε στο slow log `fclose()` στη γραμμή 955 του runtime, που στις 3.12.6–3.12.8 δεν είναι `fclose`: τρέχει παλιά έκδοση 3.5.x. Οι workers που κολλούσαν εκεί έπαιρναν θέσεις και από το πρώτο site.

## H2. Τι άλλαξε

Η απαίτηση του κατόχου: με Redis ή APCu, **κανένα** αρχείο και **κανένα** query του ScrapeLock μέσα σε αίτημα επισκέπτη· δίσκος και βάση μόνο από cron / WP-CLI / wp-admin, ή ως εναλλακτική όταν δεν υπάρχει ούτε Redis ούτε APCu. Τρεις κλάδοι, ενωμένοι και ελεγμένοι μαζί:

- **Έλεγχος πριν από την cache** (`PNCP_Precheck_Runtime`, k1): store με τη σειρά APCu (μόνο όπου το μοιράζονται όλες οι διεργασίες: PHP-FPM, Apache) → Redis του object cache → αρχεία. Στη μνήμη: μετρητές, αποκλεισμοί, strikes, μνήμη probes, nonces, events και η ίδια η ρύθμιση. Η σύνδεση Redis περνά με τη γραμμή του wp-config.php (ο κωδικός μασκαρισμένος), 50 ms για σύνδεση και απάντηση, αλλιώς τα αρχεία για εκείνο το αίτημα. Χωρίς μνήμη: καμία κλειδαριά που περιμένει (μετρητές με append, αποκλεισμοί / strikes με νέο αρχείο και rename, events χωρίς `LOCK_EX`), καθάρισμα μόνο από το ωριαίο event (χωρίς WP-Cron ένα αίτημα το λεπτό, ως 25 ms, `LOCK_NB`). `wp scrapelock precheck status|sync|cleanup`.
- **WordPress** (`PNCP_Defer`, k2): ό,τι πρέπει να κρατηθεί από ένα αίτημα επισκέπτη (γραμμές αρχείου, νέοι αποκλεισμοί, καταγραφές επιθέσεων, γραμμές Traffic, AI referrals, η κατάσταση του αυτόματου Emergency Mode) μπαίνει σε ουρά στο object cache ή στο APCu· ένα event κάθε λεπτό το γράφει στη βάση, στο δικό του αίτημα. Οι ρυθμίσεις, οι αποκλεισμοί και τα transients του ScrapeLock διαβάζονται από εκεί.
- **Circuit breaker** (`PNCP_Breaker`, `PNCP_Breaker_Status`, k3): βήμα μέτρησης ή αποθήκευσης πάνω από 200 ms (έλεγχος πριν από την cache, μέτρηση σελίδων όλου του site· DNS των crawlers 1 s) σταματά για 10 λεπτά, τα αιτήματα περνούν χωρίς αυτό, οι αποκλεισμοί ισχύουν. Site Health «ScrapeLock counting and storage speed» και «ScrapeLock counters», ειδοποίηση με «Resume counting now», `wp scrapelock breaker [status|reset]`.

**Διορθώσεις της ένωσης** (ξεχωριστά commits, με δοκιμές):
1. Ο breaker του ελέγχου μαθαίνει πρώτα το store (`breaker_hooks()`) και ονομάζεται από αυτό (`precheck_apcu|redis|files`): με Redis κρατά την κατάστασή του στη σύνδεση των μετρητών, ποτέ σε `<data>/breaker/*.json` (η δοκιμή φορτίου είχε μετρήσει ανάγνωση του `precheck_files.json` σε 100/100 αιτήματα, Redis χωρίς APCu). Με αρχεία, ο χρόνος τροποποίησης του αρχείου κατάστασης είναι το τέλος της παύσης: ένα κλειστό ή ανοιχτό breaker κοστίζει ένα `stat()`, ποτέ άνοιγμα αρχείου. Στο WordPress ο breaker παίρνει τη σύνδεση Redis του object cache και όταν ο server έχει κωδικό. Το APCu του WP-CLI (ιδιωτικό της εντολής) δεν χρησιμοποιείται πια.
2. Η μέτρηση σελίδων όλου του site (`PNCP_Bots::surge()`) και η αποθήκευση της κατάστασής της (`PNCP_Surge::save()`) κάτω από `PNCP_Breaker::guard( 'surge' )`: σε παύση η σελίδα δεν μετριέται (το λεπτό δεν κλείνει, άρα καμία αυτόματη έναρξη από μισή μέτρηση) και η κατάσταση δεν γράφεται.
3. Οι τρεις «γέφυρες» προς το WP-CLI δεν συγκρούονται: `ops.log` + υπογεγραμμένο `?pncp_precheck_sync` (αποκλεισμοί και ρύθμιση του ελέγχου), `breaker/_snapshot.json` / `_reset.json` (breaker), ουρές στο APCu που αδειάζει το `wp-cron.php?pncp_flush` του `PNCP_Defer`. Το τελευταίο κάνει τώρα και το αντίγραφο / reset του breaker, για site με WP-Cron από WP-CLI. Κανένα από αυτά σε αίτημα επισκέπτη (επιβεβαιωμένο με strace).
4. Με **strace** στον worker του PHP-FPM βρέθηκαν και διορθώθηκαν: (α) με «Early check» και APCu χωρίς object cache, ο πρώιμος έλεγχος έτρεχε πριν από το `PNCP_Defer::init()` και ρωτούσε τη βάση για 4 options σε κάθε αίτημα· (β) ένα `stat()` του config.json κάθε 10 s σε κάποιο αίτημα επισκέπτη: τώρα κανένα όσο το αντίγραφο της ρύθμισης είναι φρέσκο (το WordPress το ξαναβάζει κάθε ώρα και σε κάθε αλλαγή), και ποτέ δύο μαζί· (γ) τα αντίγραφα των options στο APCu έληγαν και το επόμενο αίτημα ρωτούσε τη βάση: τα ανανεώνει το event του λεπτού· (δ) το hook `setted_transient` (deprecated στο WordPress 6.8) έγραφε notice.
5. Μετά την ενημέρωση η γραμμή του wp-config.php αλλάζει (σύνδεση Redis). Αν το αρχείο δεν γράφεται, η σελίδα ρυθμίσεων έλεγε «Add these lines» ενώ οι παλιές γραμμές υπάρχουν και τρέχουν (με δεύτερες ο έλεγχος θα έτρεχε δύο φορές): τώρα ζητά να **αντικατασταθούν**, και το «Counters:» λέει και «Redis».

## H3. Μετρήσεις

**strace + μέτρηση queries** (πραγματικός Nginx 1.24 + PHP-FPM 8.3, ένας worker υπό strace, έλεγχος πριν από την cache και πρώιμος έλεγχος ενεργοί, όριο 20 / λεπτό, αποκλεισμός στην πρώτη παραβίαση· νέοι και γνωστοί επισκέπτες, ένας πάνω από το όριο: 429 και μετά 403):

| store | αιτήματα | system calls στο uploads/scrapelock | queries του ScrapeLock |
|---|---|---|---|
| APCu (χωρίς object cache) | 316 | 0 | 0 |
| Redis object cache + phpredis, χωρίς APCu | 315 | 0 | 0 |
| κανένα (εναλλακτική με αρχεία, για σύγκριση) | 81 | 3.851 (~47 / αίτημα) | 1.030 (~13 / αίτημα) |

Το ίδιο ελέγχει πλέον η δοκιμή `t_3129_strace` (και ένα λεπτό αργότερα, μετά το event).

**Δοκιμή φορτίου** (ξεχωριστό σενάριο: δύο sites σε ένα pool όπως live, Redis object cache στο πρώτο, 30 αιτήματα/s, 50 ταυτόχρονα, ο δίσκος «παγωμένος» για 20 s με `fsfreeze`, 90 s ανά σενάριο· 3.12.9 στο commit της ένωσης, πριν από την προετοιμασία της έκδοσης):

| σενάριο | 3.12.8: 504 / > 1 s / p99 | 3.12.9: 504 / > 1 s / p99 |
|---|---|---|
| APCu + Redis, 20 workers, πάγωμα uploads και βάσης | 69 / 127 / 10 s | **0 / 0 / 98 ms** (max 155 ms) |
| APCu, πάγωμα uploads | 11 / 60 / 4,2 s | **0 / 0 / 97 ms** |
| APCu, πάγωμα βάσης | 80 / 139 / 10 s | **0 / 0 / 100 ms** |
| APCu, 5 workers, πάγωμα uploads | 50 / 111 / 10 s | **0 / 0 / 95 ms** |
| Redis χωρίς APCu (μόνο το πρώτο site), πάγωμα uploads / βάσης / και των δύο | — | **0 / 0 / 95–103 ms** |
| χωρίς APCu, δεύτερο site χωρίς Redis (αρχεία) | 97 / 140 / 10 s | 100 / 193 / 10 s (η εναλλακτική με αρχεία δεν γλιτώνει από παγωμένο δίσκο) |

Στο slow log του σεναρίου με APCu + Redis: 0 εγγραφές `class-pncp`.

## Όρια

- **Ο breaker δεν σώζει το πρώτο πάγωμα.** Μετρά μια λειτουργία όταν τελειώσει· ένα `write()` που περιμένει δίσκο σε κατάσταση D κρατά τον worker μέχρι να ξαναπάρει μπροστά ο δίσκος. Ανοίγει μετά, για τα επόμενα 10 λεπτά. Μόνο APCu ή Redis βγάζουν το ScrapeLock από τον δίσκο.
- **Χάνονται δεδομένα αν ο Redis αδειάσει** (flush, restart χωρίς persistence) ή το PHP-FPM ξεκινήσει ξανά (APCu) **πριν από το event του λεπτού**: οι γραμμές αρχείου, Traffic, AI referrals και επιθέσεων που περίμεναν στην ουρά (το πολύ ενός λεπτού, ή μέχρι το επόμενο event αν το WP-Cron δεν τρέχει), και οι αποκλεισμοί του ελέγχου πριν από την cache μετά το τελευταίο ωριαίο αντίγραφο στα αρχεία (οι παλαιότεροι ξαναμπαίνουν μόνοι τους).
- **Το WordPress το ίδιο** χρειάζεται τη βάση (π.χ. `alloptions` χωρίς object cache): με παγωμένη βάση τα αιτήματα που φτάνουν στο WordPress περιμένουν όπως πριν· το ScrapeLock δεν προσθέτει δικά του. Οι σελίδες της page cache και ο έλεγχος πριν από αυτήν δεν τη χρειάζονται.
- **Το δεύτερο site τρέχει παλιά 3.5.x** (το `fclose()` στη γραμμή 955 του slow log): πρέπει να ενημερωθεί στην 3.12.9, αλλιώς οι workers του κολλούν σε κάθε πάγωμα και παίρνουν θέσεις και από το πρώτο site (ίδιο pool). Χωρίς Redis εκεί, μόνο το APCu το βγάζει από τον δίσκο.
- Η ρύθμιση του ελέγχου συγκρίνεται με το config.json (ένα `stat()`, ένα αίτημα τη φορά) μόνο όταν το WordPress δεν την ξανάβαλε στο store για 2 ώρες (π.χ. WP-Cron από WP-CLI με APCu και καμία σελίδα διαχείρισης).
- Ο έλεγχος μιλά με έναν server Redis (όχι Cluster / Sentinel / shards). Η δοκιμή strace χρησιμοποιεί ένα μικρό drop-in Redis των δοκιμών (`tests/lib/object-cache-redis.php`), όχι το ίδιο το Redis Object Cache.
- Με APCu το WP-CLI δεν βλέπει τη μνήμη του PHP-FPM: `wp scrapelock breaker` δείχνει αντίγραφο (ως 2 ωρών) και το `reset` γίνεται από την επόμενη σελίδα διαχείρισης ή event του PHP-FPM.

## Έλεγχος αναβάθμισης 3.12.8 → 3.12.9

Από το πραγματικό zip της release v3.12.8 (`gh api`, asset `scrapelock-3.12.8.zip`), εγκατεστημένο ως κανονικός φάκελος πίσω από Nginx + PHP-FPM με **APCu ενεργό** και Redis object cache, με ρυθμίσεις όπως live (έλεγχος πριν από την cache, πρώιμος έλεγχος, Stealth ενεργό με τους κανόνες του εγκατεστημένους με `rules install --stealth=…`). Τα αρχεία αντικαταστάθηκαν με το zip της 3.12.9 όπως κάνει ο upgrader:
- **η γραμμή του wp-config.php ξαναγράφτηκε μόνη της** (το upgrade των αρχείων έτρεξε στο WP-Cron που ξεκίνησε η πρώτη επίσκεψη) με τη σύνδεση Redis (`'path' => …, 'prefix' => …`)· `wp scrapelock precheck`: «web server store: apcu», «seen in requests: apcu», Redis «ok»·
- ρυθμίσεις **ίδιες** (byte προς byte το `pncp_settings`), Stealth ίδιο (μόνο το «seen: nginx» συμπληρώθηκε), οι διευθύνσεις της σελίδας για επισκέπτη ίδιες (`/assets/…`, 0 wp-content)·
- το όριο σελίδων ίδιο (60 × 200, μετά 429), Site Health: «ScrapeLock counts in memory (APCu)», «counting and storage are fast»·
- κανένα PHP μήνυμα του ScrapeLock σε wp-admin, Site Health, σελίδα ScrapeLock και αιτήματα επισκεπτών.
- Αν το wp-config.php δεν γράφεται: η σελίδα ρυθμίσεων δείχνει τη νέα γραμμή και ζητά να αντικαταστήσει τις παλιές (`t_precheck`).

## Δοκιμές της έκδοσης

- **php -l**, **phpcs** (phpcs.xml.dist, `--warning-severity=0`) 0 σφάλματα, **PHPStan** όπως στο CI (`phpstan.neon.dist`, phpstan 2.1.56) χωρίς σφάλματα (δύο `is_callable()` πάντα αληθή της ένωσης k1/k3 διορθώθηκαν).
- **Νέες δοκιμές**: `t_3129_precheck_io` (k1, + k: ο breaker στον Redis των μετρητών χωρίς αρχείο, και με αρχεία μόνο `stat()`), `t_3129_requests` (k2), `t_3129_breaker` (k3, + surge, + το reset / αντίγραφο μέσω του `wp-cron.php` του `PNCP_Defer`), `t_3129_strace` (δικός του Nginx + PHP-FPM υπό strace, APCu και Redis: 0 system calls στο uploads/scrapelock, 0 queries του ScrapeLock· SKIP χωρίς php-fpm / nginx / strace), `t_precheck` (+ παλιές γραμμές στο wp-config.php), `t_load` (k4: πάγωμα δίσκου με `FREEZE_MOUNT`, μόνο με `LOAD=1`).
- **Όλο το `tests/run-all.sh` σε φρέσκο MariaDB** (nginx, php-fpm, redis-server, strace παρόντα, ως root): 57 ok, 1 skip (t_traffic_ms), αποτυχίες μόνο οι γνωστές τοπικές (t_http: inline styles, data-cfasync, Applebot PTR ×2, CF-Connecting-IP, αυτόματο Emergency ×2· t_metadata_paths «fake Applebot»· t_lockdown «busy» ×2), και δύο από το ότι έτρεχαν ταυτόχρονα δύο σουίτες: t_3129_breaker (ο ιδιωτικός redis-server της δοκιμής στη θύρα 16391 κοινός στις δύο) και t_3129_precheck_io b) (p99 28 ms με φορτίο 6 σε 4 CPU)· μόνες τους ξανά: 75 και 45 PASS, t_precheck 66 PASS.
- **SQLite όπως στο CI** (wp-sqlite-db, ένας `php -S` με τον router), **ως χρήστης χωρίς δικαιώματα root** (όπως ο runner του CI· οι δοκιμές με nginx / redis-server / strace τρέχουν ή κάνουν SKIP κανονικά): 58 ok, 1 skip, αποτυχίες t_http (inline styles, data-cfasync) και t_site_files στο SQLite (γνωστές), και t_watermark / t_precheck από αρχείο του /tmp που είχε αφήσει η σουίτα root και από τη σειρά της νέας δοκιμής (διορθώθηκε)· ξανά ως ο ίδιος χρήστης: t_watermark 53, t_precheck 66 PASS. t_3129_strace 22 PASS και ως μη root.
- **Χωρίς nginx / php-fpm στο PATH** (`/usr/sbin`, `/sbin`, `/usr/local/sbin` έξω), φρέσκο MariaDB: 58 ok, 2 skip (t_traffic_ms, t_3129_strace), μόνο οι γνωστές αποτυχίες.
- **Δοκιμή φορτίου k4** (ξεχωριστός agent, στο c545b89): 0 × 504 και κανένα αίτημα πάνω από 1 s με APCu ή Redis, με πάγωμα δίσκου.
- **Zip** όπως στο release.yml (`git archive`): Version 3.12.9, `languages/scrapelock-el.mo` μέσα, χωρίς tests/, .po, REPORT.md.

## Τι κάνει ο κάτοχος μετά την ενημέρωση

Τίποτα υποχρεωτικό: η γραμμή του wp-config.php ξαναγράφεται μόνη της (event μετά την πρώτη επίσκεψη ή η επόμενη σελίδα του wp-admin). Συνιστάται:
1. **APCu στο PHP 8.3 του aaPanel** (App Store → PHP 8.3 → Setting → Install extensions → apcu) και restart του PHP· ή αρκεί ο Redis object cache που ήδη υπάρχει.
2. Έλεγχος:
```
wp --allow-root --skip-themes scrapelock precheck
wp --allow-root --skip-themes scrapelock breaker
```
(«web server store: apcu» ή «redis»· Site Health → «ScrapeLock counters».) Αν η σελίδα ρυθμίσεων λέει «runs with the lines of an earlier version», αντιγράψτε τις νέες γραμμές στη θέση των παλιών.
3. **Ενημέρωση του δεύτερου site** στην 3.12.9 (και APCu ή Redis object cache και εκεί).
4. Προαιρετικά `request_slowlog_timeout = 5s` στο pool, και για system cron χωρίς WP-Cron: `wp scrapelock precheck cleanup` κάθε ώρα.


# ScrapeLock 3.12.8 — ο νέος χάρτης του Stealth σε Nginx, `stealth check | debug`, το `cdn purge` και με τις caches των plugins

Η αναφορά μένει στο αποθετήριο (`/REPORT.md export-ignore`): δεν μπαίνει στο zip του plugin. `<site>` είναι το όνομα φακέλου του ιστότοπου στο aaPanel, `<αρχείο>` το αρχείο των κανόνων Stealth στον server (π.χ. `extension/<site>/z-scrapelock-stealth.conf`)· τίποτα από τον live server (domain, IP, paths, slugs, κωδικοί) δεν είναι στον κώδικα, στις δοκιμές ή εδώ.

## G1. Η πραγματική αιτία του εσωτερικού wp-content (διόρθωση της 3.12.7)

**Τι φάνηκε live μετά την 3.12.7.** Σε **φρέσκια** σελίδα (μετά από `rocket_clean_domain()` και `wp scrapelock cdn purge --all`, `x-pn-fastcgi-cache: MISS`) ακόμα 10 `wp-content`: `/assets/<alias>/cache/min/1/wp-content/themes/<κωδικός>/…` σε `href` και `data-rocket-src`. Το εξωτερικό wp-content και τα slugs είχαν κωδικό, το εσωτερικό όχι, και ο κωδικός του `wp-content` που υπάρχει στους κανόνες Stealth εμφανιζόταν 0 φορές στη σελίδα.

**Το συμπέρασμα της 3.12.7 (F1) ήταν λάθος.** Η 3.12.7 έγραψε ότι έμενε «μια παλιά σελίδα της fastcgi cache του Nginx». Δεν ήταν η cache: η σελίδα έβγαινε έτσι και φρέσκια. Δεν ήταν ούτε η σειρά του WP Rocket. Με το **πραγματικό WP Rocket 3.24.2** (με άδεια, μόνο τοπικά σε site δοκιμών, τίποτα από αυτό στο αποθετήριο) η σειρά είναι: buffer page cache του `advanced-cache.php` (έξω απ' όλα) > buffer του Stealth (`template_redirect` -9999) > buffer βελτιστοποίησης (`template_redirect` 2, `rocket_buffer`: minify CSS 16, minify JS 22, delay JS 26 που γράφει τα `data-rocket-src`, background CSS 110000, Stealth `PHP_INT_MAX`). Τίποτα δεν γράφει διευθύνσεις μετά το Stealth, και η page cache αποθηκεύει ό,τι βγάζει το buffer του Stealth. Σε φρέσκια εγκατάσταση η 3.12.7 έδινε ήδη 0 `wp-content` σε MISS, HIT και στο αρχείο της cache του WP Rocket.

**Η αιτία: παλιός χάρτης λέξεων του Stealth σε Nginx.**
- Οι σελίδες ξαναγράφονται με τις λέξεις που αποθηκεύτηκαν στο τελευταίο «Test again» (`state['words']`). Οι κανόνες που δείχνει η καρτέλα, που εγκαθιστά το `wp scrapelock rules install` και που ελέγχει η κατάσταση («installed and up to date») φτιάχνονται από το `build()`, δηλαδή από τον χάρτη του τώρα.
- Σε Nginx (όπου το ScrapeLock δεν γράφει κανόνες μόνο του) το `refresh()` (ο έλεγχος δύο φορές τη μέρα, οι αλλαγές plugins / θέματος) έβαζε τον νέο χάρτη μόνο σε «pending». Μόνο το «Test again» τον έβαζε σε χρήση.
- Site όπου το Stealth δοκιμάστηκε πριν από την 3.12.6 (τότε δεν υπήρχαν οι εσωτερικές λέξεις) ή πριν ενεργοποιηθεί το WP Rocket έμενε για πάντα με τις παλιές λέξεις: χωρίς κωδικό για το `wp-content`, με κωδικούς για τα slugs. Ο κάτοχος αντέγραφε τους νέους κανόνες, η κατάσταση έλεγε «up to date», οι σελίδες δεν άλλαζαν.
- Αναπαράχθηκε ακριβώς με το πραγματικό WP Rocket (σενάριο «stale», 3.12.7): 10 `wp-content` σε MISS / HIT / αρχείο cache, 0 φορές ο κωδικός. Λύση για όποιον έχει ακόμα 3.12.7: «Test again» (`wp scrapelock stealth test`), μετά άδειασμα των caches.

## G2. Η διόρθωση

- **Ο νέος χάρτης μπαίνει σε χρήση μόνος του** (`PNCP_Stealth::refresh()`): όταν ο φάκελος βάσης δεν άλλαξε, η διεύθυνση ελέγχου απαντά το **τρέχον** αποτύπωμα (αυτό του `build()`, μαζί με τους νέους κανόνες της 3.12.8) και το self-test περνά (το αρχείο του έχει τις εσωτερικές λέξεις στο όνομά του, άρα με παλιούς κανόνες αποτυγχάνει). Μετά αδειάζουν οι page caches (`pncp_purge_page_cache()`: plugins cache, fastcgi, Cloudflare plugin). Όταν η κατάσταση των κανόνων βλέπει τους τρέχοντες κανόνες ενώ ένας χάρτης περιμένει, προγραμματίζει αυτόν τον έλεγχο (30 s, WP-Cron). Νέος φάκελος βάσης θέλει ακόμα «Test again» (οι παλιές διευθύνσεις θα σταματούσαν).
- **Δεύτερο πέρασμα** (`code_new_addresses()`, `encode_left()`): διεύθυνση ήδη νέα, φτιαγμένη από πέρασμα με λιγότερες λέξεις, παίρνει τους κωδικούς των λέξεων που κρατά (μόνο το κείμενο ανάμεσα στους κωδικούς, το πολύ δύο φορές ανά λέξη)· δεύτερο πέρασμα δεν αλλάζει τίποτα.
- **Εργαλεία για τον έλεγχο live**: `wp scrapelock stealth check [<url>]` (η σελίδα όπως τη βλέπει ο επισκέπτης, μέσα από τις caches: wp-content / wp-includes, `/cache/min/`, κωδικοί, headers cache, «words not used», «rules», «next») και το προαιρετικό αρχείο debug (`SCRAPELOCK_STEALTH_DEBUG`, μία γραμμή ανά στάδιο με αριθμούς μόνο, χωρίς στοιχεία επισκέπτη, έως 256 KB, λήγει μόνο του· `wp scrapelock stealth debug [--clear]`). Ένα buffer στο `template_redirect` `PHP_INT_MAX`, όπως προτάθηκε, θα ήταν **μέσα** στο buffer του WP Rocket και θα έτρεχε πριν από το `rocket_buffer`: το buffer του Stealth είναι ήδη το τελευταίο σημείο πριν η page cache αποθηκεύσει τη σελίδα.

## G3. Πώς δένουν οι τέσσερις κλάδοι (έλεγχος και διορθώσεις)

Οι κλάδοι γράφτηκαν παράλληλα (j1 χάρτης / debug, j5 ακραίες περιπτώσεις Stealth, j3 purge, j4 μικρές διορθώσεις). Ελέγχθηκαν μαζί και διορθώθηκαν:
- **Το αποτύπωμα αλλάζει με τους κανόνες «αδελφών» φακέλων του j5.** Υπάρχει πάντα τουλάχιστον ένας τέτοιος κανόνας (`uploads|plugins|themes` κάτω από το wp-content), άρα **κάθε** site με Stealth σε Nginx βλέπει μετά την ενημέρωση «out of date». Η αυτόματη υιοθέτηση του j1 ζητά το νέο αποτύπωμα: με τους κανόνες της 3.12.7 ο χάρτης που περιμένει **δεν** μπαίνει σε χρήση (δοκιμή `t_3128_release` F και πραγματικό WP Rocket, G6). Η ειδοποίηση λέει «copy the Stealth rules again» και, νέο, το WP-CLI το ίδιο με τις εντολές: `stealth status` (γραμμές `map`: in use / waiting, `next`) και `stealth check` (`rules`, `next`· το «words not used» ζητά πρώτα αντιγραφή όσο οι κανόνες δεν είναι τρέχοντες).
- **Apache με κανόνες που γράφει το ScrapeLock στο .htaccess**: το `refresh()` τους ξανάγραφε μόνο όταν άλλαζε ο χάρτης, άρα μετά την ενημέρωση θα έμεναν για πάντα «out of date». Τώρα γράφονται ξανά όταν το αποτύπωμα του block στο .htaccess δεν είναι το τρέχον (ίδιος φάκελος βάσης), και η αναβάθμιση προγραμματίζει αυτόν τον έλεγχο (`pncp_upgrade_files()`).
- **Η υιοθέτηση και το purge του j3**: το `pncp_purge_page_cache()` επιστρέφει πλέον γραμμές (τι άδειασε)· το Stealth το καλεί όπως πριν και αγνοεί την επιστροφή· η σειρά (plugins → fastcgi → Cloudflare) ισχύει και εκεί.
- **`encode_left()` με τα `served_type`, `rewrite_encoded` και τους κανόνες αδελφών**: ελέγχθηκαν μαζί (`t_3128_stealth_inner`, `t_3128_stealth_edges`, `t_3128_release`): ένα upload που κρατά την πραγματική του διεύθυνση δεν γίνεται ποτέ νέα διεύθυνση, άρα το δεύτερο πέρασμα δεν το αγγίζει· μια URL-encoded διεύθυνση περνά από το ίδιο `rewrite()` (και το δεύτερο πέρασμα)· κάθε νέα διεύθυνση γυρίζει στο αρχείο της με τους κανόνες Nginx και Apache.
- **`own_url()` με το WordPress σε υποφάκελο**: `cache purge /about/` / `cdn purge /x` χρησιμοποιούσαν τη ρίζα του host. Τώρα η διεύθυνση του home· διαδρομή που ήδη αρχίζει με τον φάκελο μένει όπως είναι, τα αρχεία επαλήθευσης και το `/.well-known/` μένουν στη ρίζα (εκεί τα σερβίρει το `PNCP_Verify_Files`).
- **«Ο κανόνας του κωδικού του woocommerce δύο φορές»**: δεν είναι διπλότυπο. Κάθε λέξη έχει δύο ίδιους κανόνες, και στο Nginx και στο Apache, γιατί μια λέξη μπορεί να είναι δύο φορές στη διεύθυνση (το αντίγραφο του WP Rocket του `woocommerce/assets/css/woocommerce.css`) και κάθε κανόνας γυρίζει μία. Με έναν κανόνα τέτοια διεύθυνση δίνει 404 (`t_3128_release` R το δείχνει). Δεν αφαιρέθηκε· ένα σχόλιο πάνω από τα ζευγάρια το λέει (τα σχόλια δεν αλλάζουν το αποτύπωμα).

## G4. Stealth: ακραίες περιπτώσεις (j5)

Κανόνες για τους «αδελφούς» φακέλους που φτάνει ένα stylesheet με `../` (child theme → parent theme, plugin → άλλο plugin), όχι όταν υπάρχει πραγματικός φάκελος στη διεύθυνση βάσης. Uploads τύπων που δεν σερβίρουν οι κανόνες (.zip, .docx, .csv…) κρατούν την πραγματική διεύθυνση (έδιναν 404). Διευθύνσεις μετά από escaped εισαγωγικό (`url(&quot;…&quot;)`, `&#039;`), διευθύνσεις του site URL-encoded σε links κοινοποίησης, cart fragments του WooCommerce (`wc-ajax`) για επισκέπτες. Φάκελος με κενό ή άλλο χαρακτήρα που δεν χωρά σε κανόνα δεν παίρνει δική του διεύθυνση (το `nginx -t` αποτύγχανε, το Apache έδινε 500 μέχρι το self-test).

## G5. WP-CLI και μικρές διορθώσεις (j3, j4)

- `wp scrapelock cdn purge`: πρώτα οι page caches των ενεργών plugins (WP Rocket, LiteSpeed Cache, W3 Total Cache, WP Super Cache, WP Fastest Cache, Nginx Helper, Cache Enabler, SiteGround Optimizer), με μία γραμμή για καθένα («cleaned» / «not active»), μετά η fastcgi cache, μετά το CDN· `--no-plugin-cache`· `--minify` (με `--all`) και τα minified CSS / JS του WP Rocket και του Autoptimize.
- `wp scrapelock cache status`: αν ορίστηκε η `SCRAPELOCK_FASTCGI_CACHE_PATH`, και η έτοιμη γραμμή `wp config set SCRAPELOCK_FASTCGI_CACHE_PATH '<cache>' --type=constant --anchor="require_once ABSPATH . 'wp-settings.php';" --placement=before` (σε κάποια wp-config.php λείπει το προεπιλεγμένο anchor του WP-CLI)· `--save-constant` την προσθέτει μετά από δοκιμή σε αντίγραφο.
- `rules install`: ποτέ «installed» χωρίς reload (systemctl ως εναλλακτική, αλλιώς σταματά και επαναφέρει τα αρχεία)· κρατά ιδιοκτήτη και ομάδα του αρχείου που αντικαθιστά. Το uninstall σβήνει και το `pncp_fastcgi_last`. Η επικεφαλίδα του `selfcheck --log` μεταφράζεται.

## G6. Με το πραγματικό WP Rocket 3.24.2

Site δοκιμών μόνο τοπικά (το WP Rocket με άδεια αντιγράφεται στο site δοκιμών, ποτέ στο αποθετήριο, και δεν αλλάζει σε τίποτα): πραγματικός Nginx 1.24 τύπου aaPanel (κανόνες Stealth σε include στην αρχή του `server { }`, rewrite του WordPress σε επίπεδο server), proxy cache στη θέση της fastcgi cache του κατόχου (`X-Cache`), WP Rocket με page cache, minify + combine CSS / JS, defer, delay JS, lazyload και background CSS, θέμα με 5 CSS / JS και plugin με 4. MISS = πρώτη σελίδα (το WP Rocket τη φτιάχνει και τη γράφει), HIT = cache του Nginx, RCACHE = cache του Nginx παρακαμφθείσα, απάντηση από το αρχείο του WP Rocket.

| σενάριο | wp-content MISS / HIT / RCACHE | wp-includes | `/cache/min/` | κωδικός του wp-content | assets 200 |
|---|---|---|---|---|---|
| 3.12.8, φρέσκια εγκατάσταση | 0 / 0 / 0 | 0 | 9 | 10 | 14 / 14 |
| 3.12.8, «stale» (Stealth πριν από το WP Rocket, νέοι κανόνες αντιγραμμένοι, ο έλεγχος του cron, χωρίς «Test again») | 0 / 0 / 0 | 0 | 9 | 10 | 14 / 14 |
| 3.12.7, «stale» (η live εικόνα) | 10 / 10 / 10 | 0 | 9 | 0 | 14 / 14 |
| ίδιο site → 3.12.8, κανόνες της 3.12.7 ακόμα στον server | 10 / 10 / 10 (χάρτης «waiting», ειδοποίηση «copy the Stealth rules again») | 0 | 9 | 0 | 14 / 14 |
| … μετά το `wp scrapelock rules install --stealth=<αρχείο>` και το προγραμματισμένο refresh (WP-Cron, όχι «Test again») | 0 / 0 / 0 | 0 | 9 | 10 | 14 / 14 |

Στο ίδιο site: `wp scrapelock cdn purge --all --yes` (χωρίς συνδεδεμένο CDN) έγραψε «WP Rocket page cache: cleaned», «WP Rocket minified CSS/JS: kept (--minify empties them)», τα άλλα plugins «not active», «Server cache: no fastcgi cache folder is known» και στο τέλος μόνο warning «No CDN connection is set» (exit 0). Τα αρχεία της page cache του WP Rocket πήγαν από 2 σε 0· η επόμενη σελίδα τα ξανάγραψε (2, 0 `wp-content` μέσα τους), 14 / 14 assets 200. Με `--minify`: «WP Rocket minified CSS/JS: cleaned» πρώτα, page cache 0 και minified αρχεία 9 → 0· η επόμενη σελίδα τα ξανάφτιαξε (9), 0 `wp-content`, 14 / 14 assets 200, και τα HIT μετά καθαρά. `wp scrapelock cache status` με ρύθμιση Nginx με `fastcgi_cache`: φάκελος, κλειδί, «SCRAPELOCK_FASTCGI_CACHE_PATH is not defined» και η γραμμή `wp config set … --anchor="require_once ABSPATH . 'wp-settings.php';" --placement=before`. `wp scrapelock stealth check`: code 200, wp-content 0, wp-includes 0, cache/min 9, κωδικός wp-content 10, rules current, verdict clean.

## Όρια

- **Μετά την ενημέρωση οι κανόνες Stealth πρέπει να αντιγραφούν ξανά** σε κάθε site με Stealth σε Nginx (οι κανόνες αδελφών φακέλων άλλαξαν το αποτύπωμα)· μέχρι τότε οι σελίδες μένουν όπως είναι και η ειδοποίηση μένει. Ο νέος χάρτης μπαίνει σε χρήση μόνο με WP-Cron (ή τον έλεγχο δύο φορές τη μέρα), αλλιώς με `wp scrapelock stealth test`.
- **Τα minified αρχεία** του WP Rocket κρατούν τις διευθύνσεις με τις οποίες φτιάχτηκαν: η αυτόματη υιοθέτηση αδειάζει τις page caches, όχι αυτά· γι' αυτό το Upgrade Notice ζητά `cdn purge --all --minify --yes` μία φορά.
- **WooCommerce `wc-ajax`**: η σειρά με την οποία απαντά το WooCommerce (DOING_AJAX στο init, απάντηση στο `template_redirect`) είναι από μνήμης, δοκιμασμένη μόνο με stand-in· όχι με πραγματικό WooCommerce.
- **Τα ονόματα συναρτήσεων / hooks των άλλων plugins cache** (LiteSpeed, W3 Total Cache, WP Super Cache, WP Fastest Cache, Nginx Helper, Cache Enabler, SiteGround Optimizer, Autoptimize) δεν επαληθεύτηκαν με τα πραγματικά plugins, μόνο με stand-ins που καταγράφουν τις κλήσεις. Πραγματικό ήταν μόνο το WP Rocket.
- Στη δοκιμή με το πραγματικό WP Rocket η cache του Nginx είναι proxy cache (το ScrapeLock αδειάζει μόνο fastcgi cache, με γνωστό φάκελο)· σε πραγματικό aaPanel με fastcgi cache δεν δοκιμάστηκε. Το αντίγραφο background CSS του WP Rocket κρατά το όνομα του host στο path του (`cache/background-css/1/<host>/…`, κάτω από `/assets/<alias>/`).
- Νέος φάκελος βάσης θέλει πάντα «Test again».

## Έλεγχος αναβάθμισης 3.12.7 → 3.12.8

Από το πραγματικό zip της release v3.12.7 (`gh api`, asset `scrapelock-3.12.7.zip`), εγκατεστημένο κανονικά (όχι symlink) πίσω από πραγματικό Nginx, με τις ρυθμίσεις του fixture 3.10.1 εισαγμένες, `rate_limit` 45, `block_tech_profilers`, `hide_fingerprint`, Stealth ενεργό με base «assets» και τους κανόνες του εγκατεστημένους· μετά `wp plugin install --force` με το zip της 3.12.8 και το προγραμματισμένο refresh:
- όλες οι ρυθμίσεις ίδιες (κανένα κλειδί προστέθηκε ή χάθηκε), η κατάσταση του Stealth ίδια (χάρτης, λέξεις, υπογραφή, base, pending), ίδια options εκτός από `pncp_version` και `pncp_upgrade_lock`, ίδια cron, ίδιοι πίνακες·
- η αρχική σελίδα για επισκέπτη byte προς byte ίδια, το άρθρο ίδιο εκτός από την τυχαία τιμή του Akismet (`ak_js`)·
- κανένα PHP μήνυμα στο wp-admin και καμία γραμμή του ScrapeLock στο debug.log· η μόνη ειδοποίηση του ScrapeLock είναι η αναμενόμενη «The Stealth rules on the server are out of date: copy the Stealth rules again» (dashboard, ScrapeLock, Server rules), και το `stealth status` λέει το ίδιο στο «next» με την εντολή·
- τίποτα άλλο δεν αλλάζει μέχρι να εγκατασταθούν οι κανόνες· μετά το `rules install --stealth=<αρχείο>` η κατάσταση είναι «current», η ειδοποίηση φεύγει, το `stealth test` περνά και το `stealth check` δίνει 0 wp-content.

## Δοκιμές της έκδοσης

- **php -l**, **phpcs** (phpcs.xml.dist, `--warning-severity=0`) 0 σφάλματα, **PHPStan** όπως στο CI (`phpstan.neon.dist`, phpstan 2.1.56) χωρίς σφάλματα.
- **Νέα δοκιμή `t_3128_release`** (27 PASS): S `own_url()` με το WordPress σε υποφάκελο, R οι διπλοί κανόνες λέξεων (Nginx και Apache, και ότι με έναν κανόνα η διεύθυνση δεν γυρίζει), F το αποτύπωμα με τους κανόνες αδελφών, η ειδοποίηση και το WP-CLI, η υιοθέτηση μόνο με τους νέους κανόνες, H το .htaccess στο Apache. Στο `run-all.sh` και στο `tests/README.txt`.
- **Όλο το `tests/run-all.sh` σε φρέσκο MariaDB** (nginx και apache2 παρόντα): 55 ok, 1 skip (t_traffic_ms), αποτυχίες μόνο οι γνωστές τοπικές (t_http inline styles / data-cfasync / Applebot PTR ×2 / CF-Connecting-IP / αυτόματο Emergency ×2, t_metadata_paths «fake Applebot», t_lockdown «busy» ×2). Το `t_3121_loopback` R απέτυχε μία φορά επειδή τρία suites έτρεχαν παράλληλα και ο stand-in server του στη σταθερή θύρα 8953 συγκρούστηκε· μόνο του 116 PASS. t_3128_stealth_inner 55, t_3128_stealth_edges 91, t_3128_purge 39, t_3128_bugs_d 16, t_3128_release 27 PASS.
- **SQLite όπως στο CI** (wp-sqlite-db, ένας php -S): 56 ok, 1 skip (t_traffic_ms), αποτυχίες μόνο t_http (inline styles, data-cfasync) και t_site_files στο SQLite. t_cli, t_311_compat, t_311_i18n PASS.
- **Χωρίς nginx στο PATH** (`/usr/sbin`, `/sbin`, `/usr/local/sbin` έξω), φρέσκο MariaDB: μόνο οι γνωστές αποτυχίες, τα τμήματα πραγματικού Nginx SKIP (t_3128_stealth_inner 53 PASS, t_3128_stealth_edges 90 PASS). Το `t_311_integration` «signature» απέτυχε για τον ίδιο λόγο (σταθερή θύρα 8952, παράλληλα suites)· μόνο του 50 PASS.
- **Zip** όπως στο release.yml (`git archive`): Version 3.12.8, `languages/scrapelock-el.mo` μέσα, χωρίς tests/, .po, REPORT.md.

## Τι κάνει ο κάτοχος μετά την ενημέρωση

```
wp --allow-root --skip-themes scrapelock rules install --stealth=/www/server/panel/vhost/nginx/extension/<site>/z-scrapelock-stealth.conf --dry-run
wp --allow-root --skip-themes scrapelock rules install --stealth=/www/server/panel/vhost/nginx/extension/<site>/z-scrapelock-stealth.conf --yes
wp --allow-root --skip-themes scrapelock stealth test
wp --allow-root --skip-themes scrapelock cdn purge --all --minify --yes
wp --allow-root --skip-themes scrapelock stealth check
```
(ή αντιγραφή των κανόνων από Server rules → Stealth, `nginx -t`, reload, «Test again».) Αν το `cache status` δείχνει ότι λείπει η σταθερά: η γραμμή `wp config set … --anchor=… --placement=before` που τυπώνει, ή `wp scrapelock cache status --save-constant`.


# ScrapeLock 3.12.7 — η cache του Nginx (fastcgi), `wp scrapelock cache`, τα τελευταία ίχνη του Stealth

Η αναφορά μένει στο αποθετήριο (`/REPORT.md export-ignore`): δεν μπαίνει στο zip του plugin. Στις εντολές, `<site>` είναι το όνομα φακέλου του ιστότοπου στο aaPanel και `<cache>` ο φάκελος της fastcgi cache του server· τίποτα από τον live server (domain, IP, paths) δεν είναι στον κώδικα, στις δοκιμές ή εδώ.

## F1. Γιατί το «/» είχε ακόμα wp-content μετά την 3.12.6 (αιτία)

**Τι φάνηκε live.** Μετά την 3.12.6 το «/» (HIT της fastcgi cache του Nginx) είχε ακόμα `/assets/<alias>/cache/min/1/wp-content/themes/<κωδικός theme>/…`, ενώ το `/?nocache=<ts>` ήταν καθαρό.

**Ευρήματα.**
- **Ο κώδικας της 3.12.6 ξαναγράφει ήδη πριν γράψει το WP Rocket την cache του.** Από τον κώδικα του WP Rocket: η page cache του γράφεται στο callback του buffer που ανοίγει το `advanced-cache.php` πριν από τα plugins, και παίρνει την έξοδο όλων των εσωτερικών buffers: του buffer του Stealth (`template_redirect` -9999) και του buffer βελτιστοποίησης (`template_redirect` 2, `rocket_buffer`, τελευταίο στάδιο που προσθέτει διευθύνσεις στο 110000, Stealth στο `PHP_INT_MAX`). Άρα το αρχείο της cache του WP Rocket (και το `_gzip`) είναι καθαρό. Η σειρά δεν άλλαξε· ένα σχόλιο στα hooks γράφει γιατί το rewrite μένει στο τέλος του `rocket_buffer` και όχι στα `rocket_css_url` / `rocket_js_url` (τα επόμενα στάδιά του, delay JS και background CSS, θέλουν την πραγματική διεύθυνση του minified αρχείου).
- **Αυτό που έμενε live ήταν μια παλιά σελίδα της fastcgi cache του Nginx** που δεν άδειασε: γραμμένη με τη λίστα λέξεων πριν από την 3.12.6 (το theme κωδικοποιημένο, το εσωτερικό wp-content όχι). Το purge του Nginx Helper δεν έφτανε σε αυτήν: το `rt_nginx_helper_purge_all` δεν κάνει τίποτα όταν η μέθοδος ή ο φάκελός του δεν είναι αυτά του server.
- **Το `?nocache=` δεν απέδειξε τίποτα:** το WP Rocket δεν βελτιστοποιεί (ούτε αποθηκεύει) διεύθυνση με query string που δεν γνωρίζει, άρα εκεί δεν υπάρχουν καθόλου διευθύνσεις `cache/min`· δεν μπορούσε να δείξει αν οι minified διευθύνσεις ήταν σωστές.

**Δοκιμές.** `t_3127_stealth_cache` (21 PASS): stand-in τύπου WP Rocket (όχι κώδικας του WP Rocket) με την ίδια σειρά buffers / priorities: MISS, αποθηκευμένο αρχείο και `_gzip`, HIT πριν από το WordPress με 0 `wp-content` / `wp-includes` στις διευθύνσεις των assets, καθεμία γυρίζει στο πραγματικό αρχείο με τους κανόνες Nginx και Apache· `?nocache=` χωρίς βελτιστοποίηση· σελίδα αποθηκευμένη με τις παλιές λέξεις (η live περίπτωση), νέος χάρτης / Stealth off / on αδειάζουν την page cache· πραγματικός Nginx με cache μπροστά: MISS / HIT καθαρά, κάθε asset 200, και μια παλιά σελίδα της cache του Nginx μένει HIT με το υπόλοιπο μέχρι να αδειάσει η cache (SKIP χωρίς nginx). Αποτυγχάνει με την κλάση Stealth της 3.12.5.

**Δεν δοκιμάστηκε.** Πραγματικό WP Rocket με άδεια· μόνο ο stand-in, γραμμένος από τον κώδικά του (3.24.2).

## F2. Η fastcgi cache του Nginx αδειάζει μαζί με τις άλλες

**Τι άλλαξε.** `PNCP_Fastcgi_Cache::purge_known()` από το `pncp_purge_page_cache()` (αποθήκευση ρυθμίσεων, Stealth on / off ή νέος χάρτης, αναβάθμιση): όταν ο φάκελος είναι γνωστός (`SCRAPELOCK_FASTCGI_CACHE_PATH`, πολλοί με κόμμα· αλλιώς το `RT_WP_NGINX_HELPER_CACHE_PATH` ή ο προεπιλεγμένος φάκελος του Nginx Helper με μέθοδο «Delete local server cache files» και μόνο αν υπάρχει), σβήνει τα αρχεία αυτού του site. Χωρίς γνωστό φάκελο δεν κάνει τίποτα (καμία αλλαγή στην αναβάθμιση). Σβήνονται μόνο κανονικά αρχεία με όνομα MD5, header cache του Nginx και γραμμή `KEY:` της οποίας το MD5 είναι το όνομα (ή στο header για παραλλαγή Vary), με host του site στην αρχή του κλειδιού (μετά από scheme / method, με port)· ποτέ άλλος host που απλώς τελειώνει έτσι ή εμφανίζεται στο query string. Links δεν ακολουθούνται, `/`, φάκελοι συστήματος, home, aaPanel (`/www/server`, `/www/wwwroot`) και WordPress απορρίπτονται, η δουλειά έχει όριο ανά κλήση. Η κλάση δεν τρέχει καμία εντολή.

**aaPanel.**
```
wp --allow-root --skip-themes scrapelock cache status
# τυπώνει τον φάκελο της zone που χρησιμοποιεί το server { } του site και τη γραμμή:
wp --allow-root config set SCRAPELOCK_FASTCGI_CACHE_PATH '<cache>'
wp --allow-root --skip-themes scrapelock cache purge --all --yes
```
Αν το nginx δεν βρεθεί (PATH, `/usr/sbin`, `/usr/local/sbin`, `/www/server/nginx/sbin`): `--nginx-conf=/www/server/nginx/conf/nginx.conf` ή `--cache-dir=<cache>`. Το WP-CLI πρέπει να τρέχει ως root ή ως ο χρήστης του web server για να σβήσει τα αρχεία (το `status` λέει «Writable by this user»).

**Δοκιμές.** `t_3127_fastcgi` (82 PASS): αρχεία cache σε πραγματική μορφή σε ψεύτικο δέντρο κάτω από /tmp (F, K, P, U), φάκελοι που απορρίπτονται και το όριο (D), η σειρά σταθερά / Nginx Helper και το purge από `pncp_purge_page_cache()` και από το Stealth σε άλλη διεργασία (N), ο parser του `nginx -T` (X), η κάρτα Stealth και το readme (T), πραγματικός Nginx με `fastcgi_cache` σε προσωρινό prefix μπροστά από το `lib/fcgi-stub.php`: MISS, HIT, purge διεύθυνσης και όλου του site με `--nginx-conf`, ο άλλος host μένει HIT (R· SKIP χωρίς nginx).

**Δεν δοκιμάστηκε.** Σε πραγματικό aaPanel ούτε με πραγματικό Nginx Helper (μόνο οι ρυθμίσεις του όπως τις αποθηκεύει). `fastcgi_cache_key` πολύ διαφορετικό από τα συνήθη (π.χ. χωρίς τον host) δεν ταιριάζει, και τότε δεν σβήνεται τίποτα. Ένας Nginx σε άλλο μηχάνημα από το WordPress δεν φτάνεται.

## F3. `wp scrapelock cache status | purge`, `cdn purge --[no-]server-cache`

**Τι άλλαξε.** `cache status`: ο φάκελος (η σταθερά / Nginx Helper, αλλιώς το `fastcgi_cache_path` της zone του server { } αυτού του site στο `nginx -T` ή στο `--nginx-conf`, με includes, σχόλια, quotes, zone από το http { }, wildcards· μεταβλητή ή άγνωστη zone → μήνυμα), το κλειδί, πόσες σελίδες του site είναι στην cache, αν είναι εγγράψιμος, το τελευταίο purge και η γραμμή `wp config set`. `cache purge --all | <διευθύνσεις>… [--dry-run] [--yes] [--cache-dir=…]`. Το `cdn purge --all` αδειάζει πρώτα την cache του server, ώστε το CDN να μην ξαναπάρει παλιά σελίδα (`--no-server-cache` για να παραλειφθεί)· `--server-cache` για διευθύνσεις. Μόνο από WP-CLI, ποτέ όσο το site είναι κλειδωμένο. Το `run()` καλείται επιπλέον μόνο με `escapeshellarg( $bin ) . ' -T'` του προγράμματος που βρέθηκε (`t_3126_integration` S).

**Δοκιμές.** `t_3127_fastcgi` C (ψεύτικο `nginx -T` στο PATH, `--nginx-conf`, `--cache-dir`, `--dry-run`, `--yes`, `cdn purge --[no-]server-cache`), R (πραγματικός Nginx), `t_cli` (νέα εντολή στη λίστα).

## F4. Τα σχόλια των plugins cache

**Τι άλλαξε.** Το WP Rocket γράφει το «This website is like a Rocket … Performance optimized by WP Rocket … wp-rocket.me» στο δικό του buffer page cache (`Buffer\Cache::maybe_process_buffer`), μετά το `rocket_buffer` και μετά το buffer του Stealth, και στη σελίδα και στο αρχείο της cache. **Δεν υπάρχει φίλτρο `rocket_disable_footprint`** (ούτε στην 3.24.2): ο μόνος διακόπτης είναι η σταθερά `WP_ROCKET_WHITE_LABEL_FOOTPRINT`, που διαβάζεται εκείνη τη στιγμή και κάνει το σχόλιο «Cached for great performance» χωρίς το generator tag. Το Redis Object Cache τυπώνει τη σημείωσή του στο shutdown εκτός αν υπάρχει `WP_REDIS_DISABLE_COMMENT`. Με «Hide that the site runs on WordPress» ή Stealth, το `PNCP_Surface::quiet_cache_plugins()` ορίζει και τις δύο για τους επισκέπτες (μόνο αν δεν τις έχει ορίσει το site). Το buffer του Stealth σβήνει επίσης, με τις ακριβείς λέξεις τους, τα σχόλια των WP Rocket, Redis Object Cache, W3 Total Cache, WP Super Cache, LiteSpeed Cache, Autoptimize, WP Fastest Cache, Hummingbird και SG Optimizer **που φτάνουν σε αυτό**· conditional σχόλια (`<!--[if IE]>`) και τα άλλα σχόλια μένουν.

**Δοκιμές.** `t_3127_traces` F, U (κάθε υπογραφή, ό,τι πρέπει να μείνει, ίδιες λέξεις εκτός σχολίων), οι δύο σταθερές με Stealth και με το «Hide…» μόνο του (stand-in buffer τύπου WP Rocket έξω από το buffer του Stealth, σημείωση στο shutdown).

## F5. Οι μεταφράσεις των scripts χωρίς paths

**Τι άλλαξε.** Το `wp_set_script_translations()` τυπώνει το αρχείο μετάφρασης όπως είναι, και τα αρχεία του GlotPress / WP-CLI έχουν `"comment":{"reference":"wp-includes/js/dist/…"}` (ή path plugin) και `"generator"`. Με Stealth το φίλτρο `load_script_translations` τα αφαιρεί για τους επισκέπτες· το `wp.i18n` διαβάζει μόνο το `locale_data`, και το text domain και η γλώσσα μένουν. Ξανακωδικοποιείται με τα προεπιλεγμένα flags, άρα το «/» μένει escaped και κανένα `</script>` δεν κλείνει το inline script.

**Δοκιμές.** `t_3127_traces` J: ψεύτικο αρχείο μετάφρασης ενός stand-in mu-plugin, μεταφράσεις, πληθυντικοί και text domain ίδια, χωρίς αλλαγή με Stealth off.

## Όρια

- Σχόλια που προσθέτει ένα plugin page cache στο **δικό του εξωτερικό buffer**, όταν αποθηκεύει τη σελίδα (W3 Total Cache, WP Super Cache, LiteSpeed Cache, WP Fastest Cache, Hummingbird), δεν φτάνουν στο buffer του Stealth: κλείνουν στις ρυθμίσεις εκείνου του plugin (γράφεται στο «What can never be hidden»). Το text domain στις μεταφράσεις των scripts μένει.
- Η fastcgi cache αδειάζει αυτόματα μόνο όταν ο φάκελος είναι γνωστός (σταθερά ή Nginx Helper)· το `cache status` τον βρίσκει, αλλά η γραμμή στο wp-config.php μπαίνει με το χέρι. Η αυτόματη διαγραφή τρέχει ως ο χρήστης της PHP: αν τα αρχεία είναι του χρήστη του Nginx χωρίς δικαίωμα εγγραφής για την PHP, μένουν (το μετρά το «could not be deleted»).
- Το CDN (Bunny / Cloudflare) δεν αδειάζει αυτόματα σε αυτές τις στιγμές: `wp scrapelock cdn purge --all --yes` (που τώρα αδειάζει πρώτα και την cache του server).
- Οι κανόνες server και Stealth δεν άλλαξαν (ίδια αποτυπώματα): καμία αντιγραφή δεν χρειάζεται.

## Έλεγχος ενοποίησης (διόρθωση)

- Οι `t_3127_stealth_cache`, `t_3127_fastcgi`, `t_3127_traces` γράφτηκαν χωριστά: τρέχουν μαζί στο `run-all.sh` (και οι τρεις στη λίστα, καθεμία με τη γραμμή της στο `tests/README.txt`) χωρίς να αφήνουν τίποτα που επηρεάζει την επόμενη.
- `t_3127_fastcgi` R έψαχνε πρώτα `/usr/sbin/nginx` / `/usr/local/sbin/nginx` και μετά το PATH, άρα με το nginx έξω από το PATH ξεκινούσε πάλι πραγματικό Nginx, και χωρίς nginx έγραφε «note» αντί για SKIP. Τώρα όπως οι άλλες δοκιμές: `command -v nginx`, αλλιώς «SKIP R real Nginx (nginx not on PATH)» (commit `fix(tests)`).
- Ελέγχθηκαν χωρίς αλλαγή: κάθε είσοδος εντολής (rules, verify_file, cdn, cache) σταματά πρώτα εκτός WP-CLI, το `run()` μόνο με τις τέσσερις γνωστές εντολές, κανένα κλειδί στην έξοδο, η νέα εντολή στο `t_cli`, κανένα νέο κλειδί ρυθμίσεων (`t_311_compat`), τα αποτυπώματα των κανόνων Nginx / Apache / Stealth ίδια με της 3.12.6 με τις ίδιες ρυθμίσεις (στο Apache αλλάζει μόνο η γραμμή `# BEGIN ScrapeLock 3.12.7`, έξω από το αποτύπωμα).

## Δοκιμές της έκδοσης

- **php -l** σε κάθε αρχείο PHP, **phpcs** (phpcs.xml.dist) 0 σφάλματα, **PHPStan level 5** όπως στο CI χωρίς σφάλματα.
- **Όλο το `tests/run-all.sh` σε φρέσκο MariaDB** (nginx και apache2 παρόντα): 50 ok, 1 skip (t_traffic_ms), αποτυχίες μόνο οι γνωστές τοπικές (t_http inline styles / data-cfasync / Applebot PTR ×2 / CF-Connecting-IP / αυτόματο Emergency ×2, t_metadata_paths «fake Applebot», t_lockdown «busy» ×2). t_3127_stealth_cache 21, t_3127_fastcgi 82, t_3127_traces 68 PASS· μόνες τους επίσης, με τα τμήματα πραγματικού Nginx (N, R) να τρέχουν.
- **SQLite όπως στο CI** (wp-sqlite-db, ένας php -S, WP_DEBUG): 51 ok, 1 skip (t_traffic_ms), αποτυχίες μόνο t_http (inline styles, data-cfasync) και t_site_files στο SQLite. t_3127_* 21 / 82 / 68 PASS· t_cli, t_311_texts, t_311_compat, t_311_i18n PASS.
- **Χωρίς nginx στο PATH** (`/usr/sbin`, `/sbin`, `/usr/local/sbin` έξω), φρέσκο MariaDB: ίδια εικόνα με το πρώτο τρέξιμο (μόνο οι γνωστές). t_3127_stealth_cache 16 PASS + SKIP N, t_3127_fastcgi 78 PASS + SKIP R (μετά τη διόρθωση), t_3126_cli SKIP R, t_3123_rules SKIP E, t_3124_nginx_status / t_3126_stealth / t_3126_verify περνούν χωρίς το τμήμα του πραγματικού Nginx· κανένα FAIL.
- **Αναβάθμιση 3.12.6 (zip της release) → 3.12.7** (`wp plugin install --force` με το zip αυτής της έκδοσης) σε site με ρυθμίσεις (devtools, blur guests, hide_fingerprint, early, όριο 45, block_tech_profilers, Stealth ενεργό με base «assets»): κάθε τιμή ίδια (κανένα κλειδί προστέθηκε ή χάθηκε), ίδια options εκτός από `pncp_version` και τα συνηθισμένα (`pncp_server_ips`, `pncp_upgrade_lock`, η λίστα αιτημάτων), ίδια cron, η αρχική σελίδα, το άρθρο και το robots.txt για επισκέπτη byte προς byte ίδια (εκτός από nonces / hashes), καμία ειδοποίηση «out of date» ή «copy again», κανένα PHP μήνυμα από το ScrapeLock (μόνο τα warnings του WordPress ότι δεν φτάνει το wordpress.org). Χωρίς γνωστό φάκελο fastcgi η αναβάθμιση δεν σβήνει τίποτα.
- **Zip** όπως στο release.yml (`git archive`): Version 3.12.7, `languages/scrapelock-el.mo` μέσα, χωρίς tests/, .po, REPORT.md.

# ScrapeLock 3.12.6 — Stealth με WP Rocket, κατάσταση κανόνων Stealth, WP-CLI για κανόνες και CDN, αρχεία επαλήθευσης, technology profilers

Η αναφορά μένει στο αποθετήριο (`/REPORT.md export-ignore`): δεν μπαίνει στο zip του plugin. Στις εντολές, `<site>` είναι το όνομα φακέλου του ιστότοπου στο aaPanel και `<id>` το όνομα του αρχείου του μέρους 1· τίποτα από τον live server δεν είναι στον κώδικα ή στις δοκιμές.

## E1. Stealth και WP Rocket (και Autoptimize, LiteSpeed Cache, W3 Total Cache)

**Τι άλλαξε.** Με ενεργό plugin βελτιστοποίησης (το plugin, η σταθερά του, ή οι φάκελοι `cache/min`, `cache/busting`, `cache/background-css` του WP Rocket· φίλτρο `pncp_stealth_optimizers`) τα εσωτερικά `wp-content` / `wp-includes` (και `litespeed`) μέσα στις διευθύνσεις των minified / combined αρχείων παίρνουν ουδέτερους κωδικούς `q……`, όπως τα ονόματα plugins / themes. Οι κανόνες Nginx / Apache τα γυρίζουν πίσω **με μοτίβο**, όχι με λίστα αρχείων: ένα αρχείο που φτιάχνει το WP Rocket μετά το «Clear cache» σερβίρεται χωρίς νέους κανόνες. Το HTML που αποθηκεύουν τα plugins (`rocket_buffer`, `autoptimize_html_after_minify`, `litespeed_buffer_after`, `w3tc_process_content`) ξαναγράφεται τελευταίο (PHP_INT_MAX), άρα και οι σελίδες της cache τους είναι καθαρές· η page cache αδειάζει όταν το Stealth ανοίγει, κλείνει ή αλλάζει χάρτη (το CDN όχι: `wp scrapelock cdn purge --all --yes`). Χωρίς τέτοιο plugin οι κανόνες μένουν ίδιοι.

**Τι δεν κρύβεται** (γράφεται στο «What can never be hidden»): τα `data-rocket-…`, `rocket-lazyload`, `rocketlazyloadscript` (το lazy loading και τα delayed scripts τα χρειάζονται), και οι διευθύνσεις μέσα στα ίδια τα CSS / JS (ένα αρχείο στέλνεται όπως είναι αποθηκευμένο).

**aaPanel.** Αντιγραφή των κανόνων Stealth ξανά (βλ. E3/E5), μετά «Clear cache» + preload στο WP Rocket και purge στο Bunny.

**Δοκιμές.** `t_3126_stealth` (O, W, B): τα σχήματα URL του WP Rocket (cache/min/<blog>/<path>?ver=, combined <md5>.js, cache/busting, cache/background-css/<host>/…), Autoptimize, LiteSpeed, W3TC σε tags, preload, data-lazy-src, srcset, url(), JSON: 0 `wp-content` / `wp-includes`, και οι κανόνες (εφαρμοσμένοι με PCRE όπως ο server) φτάνουν στο πραγματικό αρχείο, και σε αρχείο που φτιάχτηκε μετά. Stand-in τύπου WP Rocket (mu-plugin: buffer, `rocket_buffer`, page cache πριν από το WordPress): 0 wp-content στο HTML, και από την cache του, και μετά από clear + regenerate. Πραγματικός Nginx με διάταξη aaPanel (include extension στην αρχή, rewrite σε επίπεδο server): κάθε CSS/JS/εικόνα της σελίδας 200.

**Δεν δοκιμάστηκε.** Πραγματικό WP Rocket με άδεια (minify/combine, preload, lazyload) — μόνο ο stand-in. Τα σχήματα URL των Autoptimize, LiteSpeed Cache και W3TC είναι **υποθέσεις** από την τεκμηρίωση / τον κώδικά τους, όχι από εγκατεστημένα plugins. Πραγματικός Apache με .htaccess δεν έτρεξε (χωρίς apache2: SKIP).

## E2. «For my site»: Dismiss / Restore / «you chose this»

**Τι άλλαξε.** «Dismiss» ανά πρόταση (option `pncp_wizard_state`, όχι autoload, μία για όλο το site). Η πρόταση μένει κρυφή όσο ο συνδυασμός (id, τιμές τώρα, προτεινόμενες τιμές) είναι ίδιος· δεν μετρά στο badge και δεν εφαρμόζεται ποτέ (ούτε με `--apply`/`--only`). «Show dismissed (N)» με «Restore». Όταν η τιμή είναι επιλογή του διαχειριστή μετά από πρόταση, η γραμμή λέει «you chose this» και δεν είναι τσεκαρισμένη.

**aaPanel (WP-CLI).**
```
wp --allow-root --skip-themes scrapelock wizard
wp --allow-root --skip-themes scrapelock wizard dismiss blur_on_capture
wp --allow-root --skip-themes scrapelock wizard dismiss block_devtools
wp --allow-root --skip-themes scrapelock wizard --include-dismissed
```
Ή στην πρώτη καρτέλα «Dismiss» στις δύο γραμμές (blur, devtools) που θέλετε ανοιχτές.

**Δοκιμές.** `t_3126_wizard` (66 PASS): η περίπτωση του owner (blur / devtools), το hash, «you chose this», αποθήκευση, panel μέσω HTTP με nonce / δικαιώματα / Lockdown, WP-CLI.

## E3. WP-CLI: `rules show | status | install`, `cdn purge`

**Τι άλλαξε.** `PNCP_Cli_Server`: μόνο από WP-CLI (σε web αίτημα `wp_die` 403), ποτέ όσο το site είναι κλειδωμένο. Το `install` γράφει μόνο τα αρχεία που δίνονται: `<file>.new`, diff, `<file>.old`, `nginx -t`, reload (`nginx -s reload`, αλλιώς `systemctl reload nginx`), σβήνει τα `.old`, τυπώνει την κατάσταση· αν αποτύχει το test ή το reload, **όλα** τα αρχεία επανέρχονται byte προς byte. Κανένα backup δεν μένει. Μόνο `.conf` (Nginx) / `.htaccess` ή `.conf` (Apache), χωρίς `..`, symlink μόνο μέσα στον φάκελό του, ένα ξεχασμένο `.old` σταματά την εντολή. Το token των στατικών feeds κρατιέται από το εγκατεστημένο αρχείο και δεν τυπώνεται. `cdn purge` με τα αποθηκευμένα κλειδιά Bunny / Cloudflare (δημόσιες `PNCP_Bunny::purge_urls()/purge_all()`, `PNCP_Edge::purge_urls()/purge_all()/cdn_purge()`): μόνο διευθύνσεις των hosts του site, τα κλειδιά ποτέ στην έξοδο.

**Ασφάλεια.** Το `proc_open()` είναι η μόνη κλήση διεργασίας του plugin. Οι προεπιλεγμένες εντολές χτίζονται από πλήρη paths με `escapeshellarg()`· το μόνο κείμενο εντολής απ' έξω είναι τα `--test-cmd` / `--reload-cmd`, που τρέχουν μέσω shell όπως τα γράφει αυτός που είναι στον server (γράφεται στο `--help`).

**aaPanel.**
```
wp --allow-root --skip-themes scrapelock rules status
wp --allow-root --skip-themes scrapelock rules install \
  --nginx-http=/www/server/panel/vhost/nginx/0.scrapelock-<id>.conf \
  --nginx-server=/www/server/panel/vhost/nginx/extension/<site>/scrapelock.conf \
  --stealth=/www/server/panel/vhost/nginx/extension/<site>/z-scrapelock-stealth.conf --dry-run
# το ίδιο χωρίς --dry-run (με --yes χωρίς ερώτηση). Αν το nginx δεν είναι στο PATH:
#   --test-cmd="/www/server/nginx/sbin/nginx -t" --reload-cmd="/www/server/nginx/sbin/nginx -s reload"
wp --allow-root --skip-themes scrapelock rules status --format=json
wp --allow-root --skip-themes scrapelock cdn purge /builtwith.txt
wp --allow-root --skip-themes scrapelock cdn purge --all --yes
```

**Δοκιμές.** `t_3126_cli` (54 PASS): show ίδιο με την καρτέλα, status/JSON, install με όλες τις αρνήσεις, dry-run, αποτυχία test / reload (όλα πίσω), ψεύτικα nginx/systemctl στο PATH, symlink, .htaccess, token, πραγματικός Nginx σε προσωρινό prefix (με nginx στο PATH· αλλιώς SKIP), cdn purge με ψεύτικα API (429, άρνηση token, άλλος host). `t_3126_integration` C/S: τα πεδία `stealth_state` / `stealth_installed` / `stealth_current` από την πραγματική `PNCP_Stealth_Status::status(true)`, και οι στατικοί έλεγχοι ασφαλείας.

**Δεν δοκιμάστηκε.** `rules install` σε πραγματικό aaPanel (μόνο σε προσωρινό Nginx)· purge στο πραγματικό Bunny / Cloudflare.

## E4. Όχι πια ψεύτικο «installed: not found»

**Τι άλλαξε.** Το «installed» είναι ό,τι ανέφερε τελευταία ο server· η αποθήκευση ρυθμίσεων ξαναϋπολογίζει μόνο το «current». Μια απάντηση χωρίς header (location με δικά του add_header, η στιγμή του reload, cache) δεν σβήνει τίποτα. «Not found» μόνο μετά από δύο φρέσκους ελέγχους του server με απόσταση ≥ 3 s: τον δεύτερο τον ζητά η σελίδα με admin-ajax 4 s μετά τη φόρτωση (nonce, manage_options) και βάζει την ειδοποίηση μόνο αν δεν υπάρχει ήδη. Όταν διαφέρει μόνο το μέρος 1 ή μόνο το 2, το μήνυμα το λέει.

**Δοκιμές.** `t_3126_status` (30 PASS): το σενάριο του live (save Bots → part 1), part 2, τα δύο checks, mocked απαντήσεις, HTTP. `t_3126_integration` A: κάθε ειδοποίηση μία φορά, το script του δεύτερου ελέγχου μόνο όταν χρειάζεται.

## E5. Κατάσταση των κανόνων Stealth

**Τι άλλαξε.** Οι κανόνες Stealth έχουν δικό τους αποτύπωμα: Nginx `if ($uri = /.well-known/scrapelock-stealth) { return 200 "<fp>\n"; }` σε επίπεδο server (πάνω από το rewrite του aaPanel) και `location =` εφεδρικά· Apache header `X-ScrapeLock-Stealth` μόνο στα υπογεγραμμένα αιτήματα. Κάρτα «Stealth» στο Server rules (μετά τα Apache / Nginx, πριν από fail2ban και «Verification files»), γραμμή στην κάρτα Stealth των Vulnerable points (ή η παλιά σημείωση «A plugin or theme changed», ποτέ και οι δύο), Site Health, ειδοποίηση «copy the Stealth rules again» όταν άλλαξε το base ή φάκελος plugin / theme (Dismiss ανά αλλαγή). Κανόνες από πριν την 3.12.6 που δουλεύουν: «Installed and working, but without a fingerprint» (πληροφορία, όχι ειδοποίηση). Η ειδοποίηση των κύριων κανόνων και αυτή του Stealth είναι για διαφορετικά αρχεία· καθεμία εμφανίζεται μία φορά.

**aaPanel.** Αρχείο `/www/server/panel/vhost/nginx/extension/<site>/z-scrapelock-stealth.conf` (μετά το `scrapelock.conf`, αλφαβητικά), που γίνεται include στην αρχή του server { }, πριν από το include του rewrite. Με `rules install --stealth=…` (E3) ή:
```
wp --allow-root --skip-themes scrapelock rules show --part=stealth-nginx > /www/server/panel/vhost/nginx/extension/<site>/z-scrapelock-stealth.conf.new
```
μετά swap, `nginx -t`, reload, «Test again» στο Stealth, «Check again» στην κάρτα.

**Δοκιμές.** `t_3126_stealth` F, S, R (αποτύπωμα, καταστάσεις, ειδοποίηση, πραγματικός Nginx: «current», κάτω από το rewrite → φτάνει στο WordPress). Αναβάθμιση 3.12.5 → 3.12.6 με Stealth ενεργό: «unmarked», χωρίς ειδοποίηση.

## E6. Αρχεία επαλήθευσης

**Τι άλλαξε.** `PNCP_Verify_Files`: ένα όνομα στη ρίζα ή κάτω από `/.well-known/`, μόνο txt/html/htm/xml/json (στο well-known και χωρίς κατάληξη), ποτέ wp-*, ονόματα του ScrapeLock, robots/llms/sitemap. Περιεχόμενο κείμενο ≤ 64 KB, χωρίς χαρακτήρες ελέγχου, χωρίς **κανένα** άνοιγμα PHP / ASP (`<?`, `<%`) εκτός από `<?xml` (διόρθωση αυτού του ελέγχου). Σερβίρεται από το WordPress πριν από κάθε έλεγχο, με τον τύπο του, `no-store`, `nosniff`, `X-Robots-Tag: noindex`, `Content-Security-Policy: sandbox`· HTML / XML με markup θέλει `unfiltered_html`. Ανοιχτό για κάθε bot: PHP, early check, pre-cache check (`open` στο config.json), Nginx `$pncp_open_path`, Apache συνθήκες — έξω από το αποτύπωμα. Purge στο CDN όταν μπαίνει και φεύγει. Λήγει μόνο του (1–168 ώρες, cron + ο έλεγχος της ώρας σε κάθε αίτημα). Στο robots.txt κάθε ομάδα «Disallow: /» του ScrapeLock παίρνει `Allow: <path>` (διόρθωση: με «Block technology profilers» το BuiltWith είχε «Disallow: /» και για το `/builtwith.txt`). Η απενεργοποίηση σβήνει τα αρχεία (και το αντίγραφο στη ρίζα), η απεγκατάσταση επίσης.

**aaPanel.**
```
wp --allow-root --skip-themes scrapelock verify-file add /builtwith.txt --content='<κωδικός του BuiltWith>' --hours=24
wp --allow-root --skip-themes scrapelock rules install --nginx-http=/www/server/panel/vhost/nginx/0.scrapelock-<id>.conf --yes
wp --allow-root --skip-themes scrapelock verify-file list
# μετά την επαλήθευση:
wp --allow-root --skip-themes scrapelock verify-file remove /builtwith.txt
```
Το `rules install` χρειάζεται επειδή το μέρος 1 μπλοκάρει το BuiltWith πριν από την PHP· το αποτύπωμα δεν αλλάζει, οπότε καμία ειδοποίηση δεν το ζητά. Το robots.txt αλλάζει όσο υπάρχει το αρχείο: αν το Bunny το κρατά στην cache, `cdn purge /robots.txt`.

**Δοκιμές.** `t_3126_verify` (97 PASS): paths, περιεχόμενο, HTTP (τύποι, HEAD, POST, πεζά/κεφαλαία, early, pre-cache, λήξη), κανόνες και evaluator, cron/sweep, purge με ψεύτικο Bunny, αρχείο στη ρίζα, admin-post (nonce, manage_options) και WP-CLI. `t_3126_integration` P/U: BuiltWith μπλοκαρισμένο **μόνο** από το «Block technology profilers» διαβάζει το `/builtwith.txt` (WordPress, early, pre-cache) ενώ το υπόλοιπο site είναι 403, robots.txt με `Allow`, απεγκατάσταση / απενεργοποίηση.

**Δεν δοκιμάστηκε.** Πραγματική επαλήθευση BuiltWith / Google / Bing· αν το BuiltWith ακολουθεί το robots.txt δεν είναι γνωστό. Το robots.txt δεν γίνεται purge αυτόματα.

## E7. «Block technology profilers»

**Τι άλλαξε.** Νέο κλειδί `block_tech_profilers` (0 σε νέες εγκαταστάσεις και στην αναβάθμιση, `new_in_3126()`), διακόπτης στο Bots μετά τους SEO crawlers, σε κάθε επίπεδο όπως εκείνοι (PHP, early, pre-cache, Nginx / Apache, robots.txt, log «Matched … (technology profilers)», Traffic, Site Health, export / import). Λίστα `PNCP_Bots::tech_profiler_agents()`: BuiltWith, Wappalyzer, WhatCMS, Netcraft, W3Techs, IsItWP, WPThemeDetector, WhatRuns, SimilarTech, Datanyze, WebTechSurvey· φίλτρο `pncp_tech_profiler_agents`. Το «For my site» προτείνει (χωρίς τσεκ, «more») τον διακόπτη όταν τέτοια ονόματα είναι στο bot list και αφαιρεί αυτές τις γραμμές.

**Αβέβαια tokens.** **Datanyze** και **WebTechSurvey**: δεν βρέθηκε δημοσιευμένο User-Agent τους· μπήκαν ως ονόματα που ταιριάζουν οπουδήποτε στο UA (όπως όλη η λίστα). Αν στέλνουν UA browser, δεν πιάνονται· αν κάποιο όνομα αποδειχτεί λάθος, αφαιρείται με το φίλτρο. Επίσης το «Netcraft» πιάνει όλα τα bots της Netcraft (και το NetcraftSurveyAgent), όχι μόνο το site report.

**aaPanel.** Bots → «Block technology profilers» ή «For my site» → η γραμμή «Turn on, and remove the 9 matching lines from the bot list» → Apply selected. Μετά αντιγραφή του μέρους 1 (`rules install --nginx-http=…`).

**Δοκιμές.** `t_3126_profilers` (52 PASS).

## Έλεγχος ενοποίησης και ασφαλείας (διορθώσεις)

- `rules status`: η σύνδεση με το Stealth (γραμμένη πριν ενωθούν τα κομμάτια με `class_exists`/`is_callable`) καλεί τώρα κατευθείαν το `PNCP_Stealth_Status::status(true)` (τα κλειδιά state / installed / want επιβεβαιώθηκαν· το PHPStan έβγαζε σφάλμα).
- robots.txt: `Allow` για τα ανοιχτά αρχεία επαλήθευσης.
- Αρχεία επαλήθευσης: κάθε άνοιγμα PHP / ASP απορρίπτεται.
- Απεγκατάσταση: `pncp_stealth_rules_seen` και το event `pncp_verify_files_expire`· απενεργοποίηση: τα αρχεία επαλήθευσης.
- `--test-cmd` / `--reload-cmd` τεκμηριωμένα ως εντολές shell.
- Το κείμενο «A real page here?» της καρτέλας Log σε μία γραμμή (το `t_311_texts` αποτύγχανε με παλιές γραμμές log· τώρα βάζει μια γραμμή μόνο του, άρα ελέγχει πάντα).
- Ελέγχθηκαν χωρίς αλλαγή: κάθε νέα ενέργεια admin με nonce + manage_options (+ Lockdown όπου αλλάζει κάτι), έλεγχος host στο purge, κανένα κλειδί στην έξοδο, τα symlinks / `..` / καταλήξεις στο install, η εγγραφή των νέων subcommands (`t_cli`), τα νέα κλειδιά στο `t_311_compat`.
- Όριο που μένει: το option `pncp_verify_files` δεν είναι στη λίστα των options που «παγώνει» το Lockdown (όσο είναι κλειδωμένο το `add()` / `remove()` αρνούνται, αλλά άμεση εγγραφή στη βάση δεν επαναφέρεται).

## Δοκιμές της έκδοσης

- **php -l** σε κάθε αρχείο PHP, **phpcs** (phpcs.xml.dist) 0 σφάλματα, **PHPStan level 5** όπως στο CI χωρίς σφάλματα.
- **Όλο το `tests/run-all.sh` σε φρέσκο MariaDB**: μόνο οι γνωστές τοπικές αποτυχίες (t_http inline styles / data-cfasync / Applebot PTR ×2 / CF-Connecting-IP / αυτόματο Emergency ×2, t_metadata_paths «fake Applebot», t_lockdown «busy» ×2, t_traffic_ms skip). Τα t_3126_* / t_311_* του οδηγού ξανά με τον τελικό κώδικα: όλα PASS.
- **SQLite όπως στο CI** (wp-sqlite-db, ένας php -S, WP_DEBUG): μόνο t_http (inline styles, data-cfasync), t_site_files στο SQLite, t_traffic_ms skip. t_3126_stealth 73, status 30, cli 54, verify 97, profilers 52, wizard 66, integration 54 PASS· t_cli, t_311_texts, t_311_compat, t_311_i18n PASS.
- **Χωρίς nginx στο PATH** (`/usr/sbin`, `/sbin`, `/usr/local/sbin` έξω): t_3123_rules, t_3124_nginx_status, t_3126_stealth / cli / verify κάνουν SKIP μόνο το τμήμα «real Nginx» και περνούν τα υπόλοιπα· t_3126_status και t_3126_integration ίδια. Καμία νέα δοκιμή δεν γράφει έξω από τα προσωρινά της φακέλους ή το WordPress δοκιμών.
- **Αναβάθμιση 3.12.5 (zip) → 3.12.6** με ρυθμίσεις όπως του live (probe_ban, block_ip_host, reputation, ban 3/120, όρια 45/60/60, OneSignal στα πάντα επιτρεπόμενα, blur guests, devtools, hide_fingerprint, 9 profilers στο bot list, Stealth ενεργό με base «assets», early, precheck…· όχι `cdn_only`, που θα απέρριπτε τα τοπικά αιτήματα): κάθε τιμή ίδια, προστέθηκε μόνο `block_tech_profilers` = 0, ίδια cron· το «For my site» δείχνει «Turn on, and remove the 9 matching lines from the bot list» **χωρίς τσεκ**· Stealth «Installed and working, but without a fingerprint», καμία ειδοποίηση «copy again» ούτε «out of date». Η αναβάθμιση έβγαζε όμως PHP Notice «_load_textdomain_just_in_time … too early» (ο οδηγός έφτιαχνε προτάσεις στην αποθήκευση της αναβάθμισης, πριν από το init)· διορθώθηκε (commit `fix(wizard)`, μετά το f4efd0a) και η αναβάθμιση ξανά: χωρίς κανένα PHP μήνυμα.
- **Playwright (Chromium)** στο αναβαθμισμένο site: Server rules (κάρτες Nginx, Stealth, Verification files), πρόσθεση / αφαίρεση `/builtwith.txt` από την κάρτα (το BuiltWith παίρνει 200), οδηγός με Dismiss → «Show dismissed (1)» → Restore, η πρόταση profilers χωρίς τσεκ, ο διακόπτης στο Bots ανενεργός· κανένα σφάλμα console εκτός από το gravatar (εξωτερικός host, μπλοκαρισμένος εδώ).
- **Zip** `git archive`: Version 3.12.6, `languages/scrapelock-el.mo` μέσα, χωρίς tests/, .po, REPORT.md· κάθε PHP χωρίς σφάλμα σύνταξης.

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
