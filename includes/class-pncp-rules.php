<?php
/**
 * Γεννήτρια κανόνων για τον web server και το Cloudflare, φτιαγμένων για το συγκεκριμένο site.
 *
 * Το plugin προστατεύει μόνο ό,τι φτάνει στην PHP. Σελίδες από page cache, στατικά αρχεία (εικόνες, .xml)
 * και ο φάκελος με τα καθαρά πρωτότυπα θέλουν κανόνες στον server ή στο CDN. Το plugin δεν κρατά API token
 * του Cloudflare: βγάζει τους κανόνες και τους περνάτε εσείς.
 *
 * @package Content_Protect
 */

defined( 'ABSPATH' ) || exit;

/**
 * Κανόνες Nginx, Apache και Cloudflare.
 */
final class PNCP_Rules {

	/**
	 * Πλατφόρμες που φορτώνουν εικόνες από το site σας (hotlink επιτρέπεται).
	 *
	 * @return string[]
	 */
	public static function hotlink_allowed() {
		return (array) apply_filters(
			'pncp_hotlink_allowed',
			array( 'google.', 'googleusercontent.com', 'bing.com', 'skroutz.gr', 'bestprice.gr', 'facebook.com', 'instagram.com', 'pinterest.' )
		);
	}

	/**
	 * Το domain του site.
	 *
	 * @return string
	 */
	private static function host() {
		return (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * Η διαδρομή του uploads μέσα στο site (π.χ. /wp-content/uploads).
	 *
	 * @return string
	 */
	private static function uploads_path() {
		$path = (string) wp_parse_url( wp_get_upload_dir()['baseurl'], PHP_URL_PATH );
		return '' === $path ? '/wp-content/uploads' : untrailingslashit( $path );
	}

	/**
	 * Τα User-Agents της λίστας bots.
	 *
	 * @return string[]
	 */
	private static function bots() {
		return PNCP_Options::parse_list( PNCP_Options::get()['bot_list'] );
	}

	/**
	 * Τα πάντα επιτρεπτά User-Agents.
	 *
	 * @return string[]
	 */
	private static function allowed() {
		return array_merge( PNCP_Options::parse_list( PNCP_Options::get()['allow_list'] ), PNCP_Options::allowed_ai_search() );
	}

	/**
	 * Οι ιδιωτικές διαδρομές σε μορφή regex (για Nginx / Apache).
	 *
	 * @return string[]
	 */
	private static function private_regexes() {
		$out = array();
		foreach ( PNCP_Options::parse_list( PNCP_Options::get()['private_paths'] ) as $pattern ) {
			$path = (string) wp_parse_url( $pattern, PHP_URL_PATH );
			if ( '' === $path ) {
				continue;
			}
			$full  = (string) wp_parse_url( home_url( PNCP_Private_Urls::relative_path( $path ) ), PHP_URL_PATH );
			$out[] = '^' . str_replace( '\*', '.*', preg_quote( $full, '#' ) ) . '$';
		}
		return $out;
	}

	/**
	 * Regex για Nginx/Apache από λίστα λέξεων.
	 *
	 * @param string[] $words Λέξεις.
	 * @return string
	 */
	private static function alternation( $words ) {
		$quoted = array();
		foreach ( $words as $word ) {
			$quoted[] = str_replace( array( ' ', '"' ), array( '\\s', '' ), preg_quote( $word, '#' ) );
		}
		return '(' . implode( '|', $quoted ) . ')';
	}

	/**
	 * Κανόνες Nginx: και τα δύο μέρη μαζί (για αντιγραφή σε ένα αρχείο σημειώσεων).
	 *
	 * @return string
	 */
	public static function nginx() {
		return '# Content Protect ' . PNCP_VERSION . ' — ' . self::host() . "\n# 1) Στο http { } (π.χ. /etc/nginx/conf.d/content-protect.conf):\n"
			. self::nginx_http() . "\n# 2) Στο server { } του " . self::host() . ":\n" . self::nginx_server();
	}

	/**
	 * Nginx, μέρος 1: μέσα στο http { } (map για τα bots, ζώνη ορίου).
	 *
	 * @return string
	 */
	public static function nginx_http() {
		$s     = PNCP_Options::get();
		$lines = array();
		if ( $s['block_bots'] && self::bots() ) {
			$lines[] = 'map $http_user_agent $pncp_bad_bot {';
			$lines[] = '    default 0;';
			if ( self::allowed() ) {
				$lines[] = '    "~*' . self::alternation( self::allowed() ) . '" 0;'; // Πρώτο: ταιριάζει πρώτο.
			}
			$lines[] = '    "~*' . self::alternation( self::bots() ) . '" 1;';
			if ( $s['block_empty_ua'] ) {
				$lines[] = '    "" 1;';
			}
			$lines[] = '}';
		}
		if ( self::private_regexes() ) {
			// Token για τα στατικά feeds: στο URL (cp_token) ή στο header. Βάλτε το δικό σας στη θέση του ΤΟ_TOKEN_ΣΑΣ.
			$lines[] = 'map "$arg_cp_token:$http_x_content_protect_token" $pncp_token_ok {';
			$lines[] = '    default 0;';
			$lines[] = '    "~^ΤΟ_TOKEN_ΣΑΣ:" 1;';
			$lines[] = '    "~:ΤΟ_TOKEN_ΣΑΣ$" 1;';
			$lines[] = '}';
		}
		$rate    = (int) $s['rate_limit'] > 0 ? (int) $s['rate_limit'] : 60;
		$lines[] = 'limit_req_zone $binary_remote_addr zone=pncp_pages:10m rate=' . $rate . 'r/m;';
		$lines[] = 'limit_req_status 429;';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Nginx, μέρος 2: μέσα στο server { } του site.
	 *
	 * @return string
	 */
	public static function nginx_server() {
		$s       = PNCP_Options::get();
		$host    = self::host();
		$uploads = self::uploads_path();
		$backup  = (string) get_option( 'pncp_backup_dir' );
		$lines   = array();
		if ( $s['block_bots'] && self::bots() ) {
			$lines[] = '# Μπλοκάρει τα bots ΠΡΙΝ από την page cache (FastCGI cache, WP Rocket, WP Super Cache).';
			$lines[] = 'if ($pncp_bad_bot) { return 403; }';
			$lines[] = '';
		}
		$lines[] = '# Όριο σελίδων ανά IP (και για σελίδες από cache): η γραμμή μπαίνει ΜΟΝΟ στο location που σερβίρει σελίδες';
		$lines[] = '# (PHP / page cache), ΟΧΙ εκεί που σερβίρονται CSS, JS, εικόνες και fonts: μια σελίδα φορτώνει δεκάδες τέτοια.';
		$lines[] = '# Πίσω από Cloudflare: πρώτα real_ip_header CF-Connecting-IP (βλ. README).';
		$lines[] = '#   limit_req zone=pncp_pages burst=20 nodelay;';
		$lines[] = '';
		if ( '' !== $backup ) {
			$lines[] = '# Τα καθαρά πρωτότυπα των εικόνων με υδατογράφημα: ποτέ δημόσια.';
			$lines[] = 'location ^~ ' . $uploads . '/' . $backup . '/ { deny all; return 404; }';
			$lines[] = '';
		}
		$lines[] = '# Hotlink: οι εικόνες φορτώνουν μόνο από το site σας και από μηχανές αναζήτησης / πλατφόρμες τιμών.';
		$lines[] = '# (Αν υπάρχει ήδη location για εικόνες, π.χ. για expires, βάλτε τις δύο γραμμές μέσα σε εκείνο.)';
		$lines[] = 'location ~* ^' . preg_quote( $uploads, '#' ) . '/.*\.(jpe?g|png|webp|gif|avif)$ {';
		// Το domain ως regex: ως απλό όνομα θα συγκρουόταν με το server_names («conflicting parameter» στο nginx -t).
		$lines[] = '    valid_referers none blocked server_names ~^([^/]*\\.)?' . self::nginx_referer( $host ) . '(:|/|$) ~' . implode( ' ~', array_map( array( __CLASS__, 'nginx_referer' ), self::hotlink_allowed() ) ) . ';';
		$lines[] = '    if ($invalid_referer) { return 403; }';
		$lines[] = '}';
		$regexes = self::private_regexes();
		if ( $regexes ) {
			$lines[] = '';
			$lines[] = '# Feeds: τα στατικά αρχεία μόνο με το token (map $pncp_token_ok στο http { }). Τα feeds που φτιάχνει η PHP';
			$lines[] = '# περνούν στο WordPress, που ελέγχει token, Bearer, επιτρεπόμενες IP και διαχειριστή.';
			$lines[] = '# (Μέσα στα if μόνο return: το «if is evil» του Nginx θα έχανε αλλιώς το try_files.)';
			foreach ( $regexes as $regex ) {
				$lines[] = 'location ~* ' . $regex . ' {';
				$lines[] = '    error_page 418 = @pncp_static_feed;';
				$lines[] = '    if (-f $request_filename) { return 418; }';
				$lines[] = '    try_files $uri /index.php?$args;';
				$lines[] = '}';
			}
			$lines[] = 'location @pncp_static_feed {';
			$lines[] = '    if ($pncp_token_ok = 0) { return 403; }';
			$lines[] = '    add_header Cache-Control "private, no-store" always;';
			$lines[] = '    add_header Referrer-Policy "no-referrer" always;';
			$lines[] = '    try_files $uri =404;';
			$lines[] = '}';
		}
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Regex referer για Nginx.
	 *
	 * @param string $domain Domain.
	 * @return string
	 */
	public static function nginx_referer( $domain ) {
		return str_replace( '.', '\.', rtrim( $domain, '.' ) );
	}

	/**
	 * Κανόνες Apache (.htaccess, πάνω από τους κανόνες του WordPress).
	 *
	 * @return string
	 */
	public static function apache() {
		$s       = PNCP_Options::get();
		$host    = self::host();
		$uploads = ltrim( self::uploads_path(), '/' );
		$backup  = (string) get_option( 'pncp_backup_dir' );
		$lines   = array();

		$lines[] = '# BEGIN Content Protect ' . PNCP_VERSION;
		$lines[] = '<IfModule mod_rewrite.c>';
		$lines[] = 'RewriteEngine On';
		if ( $s['block_bots'] && self::bots() ) {
			$lines[] = '# Bots της λίστας: 403 πριν από την page cache.';
			if ( self::allowed() ) {
				$lines[] = 'RewriteCond %{HTTP_USER_AGENT} !' . self::alternation( self::allowed() ) . ' [NC]';
			}
			$lines[] = 'RewriteCond %{HTTP_USER_AGENT} ' . self::alternation( self::bots() ) . ' [NC]';
			$lines[] = 'RewriteRule .* - [F,L]';
			if ( $s['block_empty_ua'] ) {
				$lines[] = 'RewriteCond %{HTTP_USER_AGENT} ^-?$';
				$lines[] = 'RewriteRule .* - [F,L]';
			}
		}
		if ( '' !== $backup ) {
			$lines[] = '# Τα καθαρά πρωτότυπα: ποτέ δημόσια (υπάρχει και .htaccess μέσα στον φάκελο).';
			$lines[] = 'RewriteRule ^' . preg_quote( $uploads . '/' . $backup, '#' ) . '/ - [F,L]';
		}
		$lines[] = '# Hotlink εικόνων.';
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^$';
		$lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://([^/]+\.)?' . preg_quote( $host, '#' ) . '/ [NC]';
		foreach ( self::hotlink_allowed() as $domain ) {
			$lines[] = 'RewriteCond %{HTTP_REFERER} !' . preg_quote( $domain, '#' ) . ' [NC]';
		}
		$lines[] = 'RewriteRule ^' . preg_quote( $uploads, '#' ) . '/.*\.(jpe?g|png|webp|gif|avif)$ - [F,NC,L]';
		foreach ( self::private_regexes() as $regex ) {
			$lines[] = '# Feed που είναι στατικό αρχείο: μόνο με το token (βάλτε το δικό σας στη θέση του ΤΟ_TOKEN_ΣΑΣ).';
			$lines[] = '# Τα feeds της PHP τα ελέγχει το WordPress (token, Bearer, επιτρεπόμενες IP, διαχειριστής).';
			$lines[] = 'RewriteCond %{REQUEST_FILENAME} -f';
			$lines[] = 'RewriteCond %{QUERY_STRING} !(^|&)cp_token=ΤΟ_TOKEN_ΣΑΣ(&|$)';
			$lines[] = 'RewriteCond %{HTTP:X-Content-Protect-Token} !^ΤΟ_TOKEN_ΣΑΣ$';
			$lines[] = 'RewriteRule ' . str_replace( '^/', '^', $regex ) . ' - [F,L]';
		}
		$lines[] = '# Το Authorization: Bearer φτάνει στην PHP και με PHP-FPM / CGI.';
		$lines[] = 'RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]';
		$lines[] = '</IfModule>';
		$lines[] = '# END Content Protect';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Εξαίρεση των πάντα επιτρεπτών User-Agents στην έκφραση του Cloudflare.
	 *
	 * @return string
	 */
	private static function cf_allowed() {
		$parts = array();
		foreach ( self::allowed() as $ua ) {
			$parts[] = 'lower(http.user_agent) contains "' . strtolower( str_replace( '"', '', $ua ) ) . '"';
		}
		return $parts ? ' and not (' . implode( ' or ', $parts ) . ')' : '';
	}

	/**
	 * Εκφράσεις για το Cloudflare (Security → WAF → Custom rules / Rate limiting rules).
	 *
	 * @return array<string, array{title:string, action:string, expression:string}>
	 */
	public static function cloudflare() {
		$s       = PNCP_Options::get();
		$host    = self::host();
		$uploads = self::uploads_path();
		$rules   = array();

		$bots = self::bots();
		if ( $s['block_bots'] && $bots ) {
			$parts = array();
			foreach ( $bots as $bot ) {
				$parts[] = 'lower(http.user_agent) contains "' . strtolower( str_replace( '"', '', $bot ) ) . '"';
			}
			if ( $s['block_empty_ua'] ) {
				$parts[] = 'http.user_agent eq ""';
			}
			$rules['bots'] = array(
				'title'      => __( 'Scrapers και AI bots', 'content-protect' ),
				'action'     => 'Block',
				'expression' => '(http.host eq "' . $host . '") and not cf.client.bot and (' . implode( ' or ', $parts ) . ')' . self::cf_allowed(),
			);
		}

		$rules['fake'] = array(
			'title'      => __( 'Ψεύτικα Googlebot / Bingbot (όχι από επαληθευμένο bot του Cloudflare)', 'content-protect' ),
			'action'     => 'Block',
			'expression' => '(http.host eq "' . $host . '") and not cf.client.bot and (lower(http.user_agent) contains "googlebot" or lower(http.user_agent) contains "bingbot" or lower(http.user_agent) contains "applebot")',
		);

		$referers = array( 'http.referer eq ""', 'http.referer contains "' . $host . '"' );
		foreach ( self::hotlink_allowed() as $domain ) {
			$referers[] = 'http.referer contains "' . $domain . '"';
		}
		$rules['hotlink'] = array(
			'title'      => __( 'Hotlink εικόνων', 'content-protect' ),
			'action'     => 'Block',
			'expression' => '(http.host eq "' . $host . '") and starts_with(http.request.uri.path, "' . $uploads . '/") and http.request.uri.path.extension in {"jpg" "jpeg" "png" "webp" "gif" "avif"} and not (' . implode( ' or ', $referers ) . ')',
		);

		$backup = (string) get_option( 'pncp_backup_dir' );
		if ( '' !== $backup ) {
			$rules['originals'] = array(
				'title'      => __( 'Φάκελος καθαρών πρωτοτύπων', 'content-protect' ),
				'action'     => 'Block',
				'expression' => '(http.host eq "' . $host . '") and starts_with(http.request.uri.path, "' . $uploads . '/' . $backup . '/")',
			);
		}

		$rate          = (int) $s['rate_limit'] > 0 ? (int) $s['rate_limit'] : 60;
		$rules['rate'] = array(
			'title'      => sprintf(
				/* translators: %d: σελίδες ανά λεπτό */
				__( 'Rate limiting: %d αιτήματα ανά λεπτό ανά IP (Rate limiting rules, χαρακτηριστικό: IP)', 'content-protect' ),
				$rate
			),
			'action'     => __( 'Block · περίοδος 1 λεπτό (στο δωρεάν πλάνο: 10 δευτ., με όριο / 6)', 'content-protect' ),
			// Μόνο σελίδες: όχι αρχεία (CSS, JS, εικόνες, fonts), όχι wp-admin / wp-includes / wp-content,
			// όχι AJAX καλαθιού (wc-ajax, Store API) και όχι συνδεδεμένοι χρήστες.
			'expression' => '(http.host eq "' . $host . '") and not cf.client.bot and http.request.uri.path.extension in {"" "php" "html" "xml"} and not starts_with(http.request.uri.path, "/wp-admin") and not starts_with(http.request.uri.path, "/wp-includes/") and not starts_with(http.request.uri.path, "/wp-content/") and not starts_with(http.request.uri.path, "/wp-json/wc/store") and not http.request.uri.query contains "wc-ajax=" and not http.cookie contains "wordpress_logged_in_"',
		);
		$rules['ai']   = array(
			'title'      => __( 'AI crawlers που δηλώνει το Cloudflare (κατηγορία «AI Crawler»)', 'content-protect' ),
			'action'     => 'Block',
			'expression' => '(http.host eq "' . $host . '") and cf.verified_bot_category in {"AI Crawler" "AI Assistant" "AI Search"}',
		);
		return $rules;
	}
}
