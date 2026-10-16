# Εικόνες για τη σελίδα του WordPress.org

Ανεβαίνουν στον φάκελο `assets/` του SVN του plugin (όχι στο zip και όχι στο `trunk/`).

| Αρχείο | Χρήση |
|---|---|
| `icon-128x128.png`, `icon-256x256.png`, `icon.svg` | Εικονίδιο στις αναζητήσεις και στη λίστα plugins |
| `banner-772x250.png`, `banner-1544x500.png` | Banner στην κορυφή της σελίδας του plugin |
| `screenshot-1.png` … `screenshot-6.png` | Στιγμιότυπα· οι λεζάντες είναι στο «== Screenshots ==» του `readme.txt` |

Πηγές στο `src/`: `icon.svg` και `banner.html`. Τα PNG βγαίνουν με headless Chromium (screenshot 256×256 και 1544×500) και `convert -resize` για τα μικρά μεγέθη.

Τα στιγμιότυπα είναι από WordPress δοκιμών (site «Demo Store», διευθύνσεις IP τεκμηρίωσης 192.0.2.x / 198.51.100.x / 203.0.113.x) με προσομοιωμένη κίνηση bots.
