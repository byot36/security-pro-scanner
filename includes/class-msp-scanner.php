<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Toată logica de detectare: header-e HTTP, porturi expuse, risc SQLi
 * (static și dinamic pe propriul site), plus reparare automată a
 * header-elor lipsă. Nu atinge baza de date direct — doar întoarce
 * findings brute, pe care apelantul le loghează.
 */
class MSP_Scanner {

    private $http_test_timeout = 6;
    private MSP_State $state;

    public function __construct(MSP_State $state) {
        $this->state = $state;
    }

    /**
     * Definiții header-e: numele HTTP real + valoarea recomandată, folosite
     * atât pentru detectare cât și pentru generarea fix-ului automat în .htaccess.
     */
    public function header_definitions(): array {
        return array(
            'x-frame-options' => array(
                'name'  => 'X-Frame-Options',
                'value' => 'SAMEORIGIN',
                'level' => 'WARNING',
                'msg'   => 'Lipsește X-Frame-Options — site vulnerabil la Clickjacking.',
            ),
            'content-security-policy' => array(
                'name'  => 'Content-Security-Policy',
                'value' => "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
                'level' => 'WARNING',
                'msg'   => 'Lipsește Content-Security-Policy — crește riscul de XSS.',
            ),
            'x-content-type-options' => array(
                'name'  => 'X-Content-Type-Options',
                'value' => 'nosniff',
                'level' => 'INFO',
                'msg'   => 'Lipsește X-Content-Type-Options — browserul poate ghici tipul MIME greșit.',
            ),
            'referrer-policy' => array(
                'name'  => 'Referrer-Policy',
                'value' => 'strict-origin-when-cross-origin',
                'level' => 'INFO',
                'msg'   => 'Lipsește Referrer-Policy — se poate scurge URL-ul complet către site-uri externe.',
            ),
            'strict-transport-security' => array(
                'name'  => 'Strict-Transport-Security',
                'value' => 'max-age=31536000; includeSubDomains',
                'level' => 'WARNING',
                'msg'   => 'Lipsește Strict-Transport-Security (HSTS) pe un site cu HTTPS activ.',
                'ssl_only' => true,
            ),
        );
    }

    /**
     * MODUL: Header-e HTTP de securitate lipsă (verifică propriul site, via wp_remote_get)
     */
    public function check_security_headers(): array {
        $findings = array();

        $response = wp_remote_get(home_url('/'), array('timeout' => 8, 'sslverify' => true));
        if (is_wp_error($response)) {
            return $findings;
        }

        $headers = wp_remote_retrieve_headers($response);

        foreach ($this->header_definitions() as $header_key => $def) {
            if (!empty($def['ssl_only']) && !is_ssl()) {
                continue;
            }
            if (!$headers->offsetExists($header_key)) {
                $findings[] = array(
                    'level'      => $def['level'],
                    'msg'        => $def['msg'],
                    'header_key' => $header_key,
                );
            }
        }

        return $findings;
    }

    /**
     * REPARARE AUTOMATĂ: scrie header-ele HTTP lipsă direct în .htaccess,
     * folosind insert_with_markers() — funcția nativă WordPress care
     * adaugă/actualizează un bloc delimitat, fără să atingă restul
     * regulilor din fișier (ex. regulile de permalink-uri).
     */
    public function apply_header_fixes(): array {
        if (!current_user_can('manage_options')) {
            return array('success' => false, 'message' => 'Permisiuni insuficiente.', 'fixed' => array());
        }

        if (!function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        $htaccess_path = ABSPATH . '.htaccess';

        if (!is_writable(ABSPATH) && !(file_exists($htaccess_path) && is_writable($htaccess_path))) {
            return array(
                'success' => false,
                'message' => 'Fișierul .htaccess nu este accesibil pentru scriere — aplică manual regulile de mai jos.',
                'fixed'   => array(),
            );
        }

        $missing = $this->check_security_headers();
        if (empty($missing)) {
            return array('success' => true, 'message' => 'Niciun header lipsă — nimic de reparat.', 'fixed' => array());
        }

        $defs  = $this->header_definitions();
        $lines = array('<IfModule mod_headers.c>');
        $fixed = array();

        foreach ($missing as $item) {
            $key = $item['header_key'] ?? null;
            if (!$key || !isset($defs[$key])) {
                continue;
            }
            $def = $defs[$key];
            $lines[] = sprintf('    Header always set "%s" "%s"', $def['name'], $def['value']);
            $fixed[] = $def['name'];
        }

        $lines[] = '</IfModule>';

        if (empty($fixed)) {
            return array('success' => true, 'message' => 'Niciun header cunoscut de reparat.', 'fixed' => array());
        }

        $result = insert_with_markers($htaccess_path, 'My Security Pro Scanner - Security Headers', $lines);

        if (!$result) {
            return array(
                'success' => false,
                'message' => 'Scrierea în .htaccess a eșuat. Verifică permisiunile fișierului.',
                'fixed'   => array(),
            );
        }

        // Re-verificăm live, pe o cerere HTTP nouă, ce chiar s-a reparat —
        // nu presupunem că a mers doar pentru că am scris în fișier.
        $still_missing = $this->check_security_headers();
        $still_missing_keys = wp_list_pluck($still_missing, 'header_key');

        $confirmed_fixed = array();
        foreach ($missing as $item) {
            $key = $item['header_key'] ?? null;
            if ($key && !in_array($key, $still_missing_keys, true)) {
                $confirmed_fixed[] = $defs[$key]['name'] ?? $key;
                $this->state->log_fix($defs[$key]['name'] . ' adăugat în .htaccess');
            }
        }

        $this->state->update_open_issues('headers', $still_missing);

        if (empty($confirmed_fixed)) {
            return array(
                'success' => false,
                'message' => 'Regulile au fost scrise în .htaccess, dar serverul tot nu trimite header-ele — verifică dacă mod_headers este activ.',
                'fixed'   => array(),
            );
        }

        $message = 'Reparat cu succes: ' . implode(', ', $confirmed_fixed);
        if (!empty($still_missing)) {
            $message .= '. Nerezolvate încă: ' . implode(', ', wp_list_pluck($still_missing, 'msg'));
        }

        return array(
            'success' => true,
            'message' => $message,
            'fixed'   => $confirmed_fixed,
        );
    }

    /**
     * MODUL: Verifică porturi expuse pe propriul server (informativ, fără atac)
     */
    public function check_exposed_ports(): array {
        $findings = array();
        $host = wp_parse_url(home_url(), PHP_URL_HOST);

        if (empty($host)) {
            return $findings;
        }

        $sensitive_ports = array(
            3306 => 'MySQL',
            5432 => 'PostgreSQL',
            6379 => 'Redis',
            21   => 'FTP',
        );

        foreach ($sensitive_ports as $port => $service) {
            $connection = @fsockopen($host, $port, $errno, $errstr, 1);
            if ($connection) {
                fclose($connection);
                $findings[] = array(
                    'level' => 'WARNING',
                    'msg'   => "Portul $port ($service) pare accesibil public — verifică firewall-ul serverului.",
                );
            }
        }

        return $findings;
    }

    /**
     * MODUL: Analiză statică de cod pentru risc SQL Injection.
     * Caută interogări $wpdb care concatenează direct input din request,
     * fără $wpdb->prepare(). Nu trimite niciun request către site — doar
     * citește fișierele PHP instalate local.
     */
    public function check_unsafe_sql_queries(): array {
        $findings = array();
        $scanned  = 0;
        $max_files = 200; // limită ca să nu blocăm requestul pe site-uri mari

        $directories = array(
            WP_PLUGIN_DIR,
            get_theme_root(),
        );

        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if ($scanned >= $max_files) {
                    break 2;
                }
                if ($file->getExtension() !== 'php') {
                    continue;
                }

                $scanned++;
                $content = file_get_contents($file->getPathname());
                if ($content === false) {
                    continue;
                }

                // Căutăm apeluri $wpdb->query()/get_results()/get_var() care
                // concatenează direct $_GET/$_POST/$_REQUEST, fără prepare().
                $pattern = '/\$wpdb->(query|get_results|get_var|get_row)\s*\([^)]*\.\s*\$_(GET|POST|REQUEST)/i';

                if (preg_match($pattern, $content)) {
                    $rel_path = str_replace(ABSPATH, '', $file->getPathname());
                    $findings[] = array(
                        'level' => 'CRITICAL',
                        'msg'   => "Posibil SQL Injection: interogare \$wpdb neprotejată în $rel_path",
                    );
                }

                if (count($findings) >= 20) {
                    break 2; // suficiente rezultate pentru un raport util
                }
            }
        }

        return $findings;
    }

    /**
     * MODUL AVANSAT: request HTTP cu separare corectă headers/body,
     * folosit pentru testele de mai jos (self-scan only).
     */
    private function fetch_self(string $url_with_query): array {
        $start = microtime(true);
        $response = wp_remote_get($url_with_query, array(
            'timeout'   => $this->http_test_timeout,
            'sslverify' => true,
            'headers'   => array('User-Agent' => 'SecurityProScanner/2.0 (self-test)'),
        ));
        $elapsed = microtime(true) - $start;

        if (is_wp_error($response)) {
            return array('body' => '', 'code' => 0, 'elapsed' => $elapsed);
        }

        return array(
            'body'    => wp_remote_retrieve_body($response),
            'code'    => wp_remote_retrieve_response_code($response),
            'elapsed' => $elapsed,
        );
    }

    /**
     * MODUL: SQL Injection dinamic (error-based, boolean-based, time-based blind)
     * și XSS reflectat — testate EXCLUSIV pe propriul site (home_url), pe un
     * parametru de test dedicat, nu pe un URL arbitrar din request.
     *
     * Motiv pentru care nu acceptă un target extern: acest fișier rulează
     * într-un plugin WordPress; dacă ar accepta URL arbitrar, ar deveni un
     * scanner public utilizabil de oricine împotriva oricui prin serverul tău.
     */
    public function check_dynamic_injection(): array {
        $findings = array();
        $base_url = add_query_arg('sp_scan_probe', '1', home_url('/'));

        // --- SQLi Error-based ---
        $error_indicators = array('SQL syntax', 'mysql_fetch', 'Warning: mysql', 'PostgreSQL', 'ODBC Driver');
        $error_payloads = array("'", '"', "1'");

        foreach ($error_payloads as $payload) {
            $test_url = add_query_arg('sp_probe_val', urlencode($payload), $base_url);
            $resp = $this->fetch_self($test_url);

            foreach ($error_indicators as $indicator) {
                if ($resp['body'] !== '' && stripos($resp['body'], $indicator) !== false) {
                    $findings[] = array(
                        'level' => 'CRITICAL',
                        'msg'   => "Eroare SQL expusă în răspuns (indicator: $indicator) — posibil query neprotejat.",
                    );
                    break 2;
                }
            }
        }

        // --- SQLi Time-based blind (doar 1 payload, timeout scurt, ca să nu blocăm requestul) ---
        $time_url = add_query_arg('sp_probe_val', urlencode("1' AND SLEEP(3)-- -"), $base_url);
        $timed = $this->fetch_self($time_url);
        if ($timed['elapsed'] > 2.5) {
            $findings[] = array(
                'level' => 'WARNING',
                'msg'   => 'Delay neobișnuit de mare (' . round($timed['elapsed'], 2) . 's) la payload SQLi time-based — verifică manual dacă e relevant.',
            );
        }

        // --- XSS reflectat, pe același parametru de test ---
        $xss_payload = "<script>spSelfTestXss()</script>";
        $xss_url = add_query_arg('sp_probe_val', urlencode($xss_payload), $base_url);
        $xss_resp = $this->fetch_self($xss_url);
        if ($xss_resp['body'] !== '' && stripos($xss_resp['body'], $xss_payload) !== false) {
            $findings[] = array(
                'level' => 'CRITICAL',
                'msg'   => 'Input-ul din query string este reflectat nesanitizat în pagină — risc XSS.',
            );
        }

        return $findings;
    }
}
