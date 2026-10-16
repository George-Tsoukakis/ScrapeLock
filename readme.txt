=== Content Protect ===
Contributors: the-greek
Tags: content protection, copy protection, no right click
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.2.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Προστασία περιεχομένου για WordPress.

== Description ==
Δυσκολεύει την αντιγραφή κειμένων και εικόνων, προσθέτει την πηγή όταν κάποιος αντιγράφει ή εκτυπώνει, κρύβει το κείμενο από το REST API και τα feeds, μπλοκάρει scrapers και AI bots και βάζει προαιρετικά υδατογράφημα στις εικόνες. Φόρμες, καλάθι, ταμείο, συνδεδεμένοι συντάκτες και μηχανές αναζήτησης δεν επηρεάζονται.

== Changelog ==
Πλήρες ιστορικό: CHANGELOG.md.

= 2.2.1 =
* Το token των feeds δεν αποθηκεύεται ποτέ σε καθαρή μορφή, ούτε στη μετάβαση από την 1.x.
* Νέα επιλογή: επιτρέπονται οι AI μηχανές αναζήτησης (OAI-SearchBot, Claude-SearchBot, PerplexityBot κ.ά.), ενώ οι crawlers εκπαίδευσης μένουν μπλοκαρισμένοι. Ανενεργή από προεπιλογή.

= 2.2.0 =
* Δοκιμές σε πραγματική στοίβα (WooCommerce, WPGraphQL, Nginx, Apache, Redis, page cache) και διορθώσεις: ατομικός μετρητής ορίων, πίνακας αποκλεισμών, bots μέσω wc-ajax, κανόνες server.

= 2.1.1 =
* Διορθώσεις ασφαλείας: προεπισκόπηση builders, συνδεδεμένοι πελάτες, wc-ajax, headers των feeds.

= 2.1.0 =
* Trusted Proxy, Emergency Mode, έτοιμα προφίλ, αρχείο ασφαλείας, κανόνες Nginx / Apache / Cloudflare, hash των tokens, προστασία WPGraphQL και WooCommerce Store API.
= 1.4.0 =
* Widget στον Πίνακα ελέγχου και κουμπί στη γραμμή διαχείρισης με την κατάσταση και ενεργοποίηση/απενεργοποίηση με ένα κλικ.

= 1.3.0 =
* Ιδιωτικά URLs (XML feeds) με token ή IP.
* Πραγματική IP επισκέπτη πίσω από CDN/proxy.

= 1.2.0 =
* REST API: κρύψιμο του κειμένου από επισκέπτες.
* RSS: μόνο περίληψη με σύνδεσμο, ή απενεργοποίηση.
* Συντομεύσεις DevTools.
* Μπλοκάρισμα scrapers/AI bots, robots.txt, όριο σελίδων ανά IP.
* Αντιγραφή με πηγή από Ν χαρακτήρες και πάνω.
* Υδατογράφημα στα νέα uploads.

= 1.1.0 =
* Νέο slug και φάκελος: content-protect. Καμία αναφορά σε συγκεκριμένο site.

= 1.0.3 =
* Δημιουργός: The-Greek, χωρίς συνδέσμους.

= 1.0.2 =
* Νέο όνομα: Content Protect.

= 1.0.1 =
* Η cache σελίδων (WP Rocket, Nginx) αδειάζει αυτόματα όταν αλλάζουν οι ρυθμίσεις.
* Το WP Rocket δεν καθυστερεί πια το script της προστασίας.

= 1.0.0 =
* Πρώτη έκδοση.
