<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * All the detection logic: HTTP headers, exposed ports, SQLi risk
 * (static and dynamic on your own site), plus automatic repair of
 * missing headers. Does not touch the database directly — only returns
 * raw findings, which the caller logs.
 */
class MSP_Scanner {

    /**
     * Timeout, in seconds, for the self-test HTTP requests used by check_dynamic_injection().
     *
     * @var int
     */
    private $http_test_timeout = 6;

    /**
     * Shared state tracker for open issues and confirmed fixes.
     *
     * @var MSP_State
     */
    private MSP_State $state;

    /**
     * @param MSP_State $state Shared state tracker for open issues and fixes.
     */
    public function __construct(MSP_State $state) {
        $this->state = $state;
    }

    /**
     * Header definitions: the real HTTP name + recommended value, used
     * both for detection and for generating the automatic fix in .htaccess.
     *
     * @return array
     */
    public function header_definitions(): array {
        return array(
            'x-frame-options' => array(
                'name'  => 'X-Frame-Options',
                'value' => 'SAMEORIGIN',
                'level' => 'WARNING',
                'msg'   => __('Missing X-Frame-Options — site vulnerable to Clickjacking.', 'my-security-scanner-pro'),
            ),
            'content-security-policy' => array(
                'name'  => 'Content-Security-Policy',
                'value' => "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
                'level' => 'WARNING',
                'msg'   => __('Missing Content-Security-Policy — increases XSS risk.', 'my-security-scanner-pro'),
            ),
            'x-content-type-options' => array(
                'name'  => 'X-Content-Type-Options',
                'value' => 'nosniff',
                'level' => 'INFO',
                'msg'   => __('Missing X-Content-Type-Options — the browser may guess the wrong MIME type.', 'my-security-scanner-pro'),
            ),
            'referrer-policy' => array(
                'name'  => 'Referrer-Policy',
                'value' => 'strict-origin-when-cross-origin',
                'level' => 'INFO',
                'msg'   => __('Missing Referrer-Policy — the full URL may leak to external sites.', 'my-security-scanner-pro'),
            ),
            'strict-transport-security' => array(
                'name'  => 'Strict-Transport-Security',
                'value' => 'max-age=31536000; includeSubDomains',
                'level' => 'WARNING',
                'msg'   => __('Missing Strict-Transport-Security (HSTS) on a site with HTTPS enabled.', 'my-security-scanner-pro'),
                'ssl_only' => true,
            ),
        );
    }

    /**
     * MODULE: Missing HTTP security headers (checks your own site, via wp_remote_get)
     *
     * @return array
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
     * AUTOMATIC FIX: writes the missing HTTP headers directly into .htaccess,
     * using insert_with_markers() — the native WordPress function that
     * adds/updates a delimited block without touching the rest of the
     * rules in the file (e.g. permalink rules).
     *
     * @return array
     */
    public function apply_header_fixes(): array {
        if (!current_user_can('manage_options')) {
            return array('success' => false, 'message' => __('Insufficient permissions.', 'my-security-scanner-pro'), 'fixed' => array());
        }

        if (!function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        $htaccess_path = ABSPATH . '.htaccess';

        if (!wp_is_writable(ABSPATH) && !(file_exists($htaccess_path) && wp_is_writable($htaccess_path))) {
            return array(
                'success' => false,
                'message' => __('The .htaccess file is not writable — apply the rules below manually.', 'my-security-scanner-pro'),
                'fixed'   => array(),
            );
        }

        $missing = $this->check_security_headers();
        if (empty($missing)) {
            return array('success' => true, 'message' => __('No missing headers — nothing to fix.', 'my-security-scanner-pro'), 'fixed' => array());
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
            return array('success' => true, 'message' => __('No known header to fix.', 'my-security-scanner-pro'), 'fixed' => array());
        }

        $result = insert_with_markers($htaccess_path, 'My Security Pro Scanner - Security Headers', $lines);

        if (!$result) {
            return array(
                'success' => false,
                'message' => __('Writing to .htaccess failed. Check the file permissions.', 'my-security-scanner-pro'),
                'fixed'   => array(),
            );
        }

        // Re-verify live, with a fresh HTTP request, what actually got fixed —
        // we don't assume it worked just because we wrote to the file.
        $still_missing = $this->check_security_headers();
        $still_missing_keys = wp_list_pluck($still_missing, 'header_key');

        $confirmed_fixed = array();
        foreach ($missing as $item) {
            $key = $item['header_key'] ?? null;
            if ($key && !in_array($key, $still_missing_keys, true)) {
                $confirmed_fixed[] = $defs[$key]['name'] ?? $key;
                $this->state->log_fix($defs[$key]['name'] . ' added to .htaccess');
            }
        }

        $this->state->update_open_issues('headers', $still_missing);

        if (empty($confirmed_fixed)) {
            return array(
                'success' => false,
                'message' => __('The rules were written to .htaccess, but the server still isn\'t sending the headers — check whether mod_headers is enabled.', 'my-security-scanner-pro'),
                'fixed'   => array(),
            );
        }

        /* translators: %s: comma-separated list of fixed header names */
        $message = sprintf(__('Successfully fixed: %s', 'my-security-scanner-pro'), implode(', ', $confirmed_fixed));
        if (!empty($still_missing)) {
            /* translators: %s: comma-separated list of still-unresolved issue messages */
            $message .= '. ' . sprintf(__('Still unresolved: %s', 'my-security-scanner-pro'), implode(', ', wp_list_pluck($still_missing, 'msg')));
        }

        return array(
            'success' => true,
            'message' => $message,
            'fixed'   => $confirmed_fixed,
        );
    }

    /**
     * MODULE: Checks for exposed ports on your own server (informational, no attack)
     *
     * @return array
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
            // Raw TCP connect check: there is no WP_Filesystem/HTTP API equivalent for
            // probing whether a non-HTTP port is reachable, so a direct socket is required.
            $connection = @fsockopen($host, $port, $errno, $errstr, 1); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fsockopen
            if ($connection) {
                fclose($connection); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                $findings[] = array(
                    'level' => 'WARNING',
                    /* translators: 1: port number, 2: service name (e.g. MySQL) */
                    'msg'   => sprintf(__("Port %1\$d (%2\$s) appears publicly accessible — check your server's firewall.", 'my-security-scanner-pro'), $port, $service),
                );
            }
        }

        return $findings;
    }

    /**
     * MODULE: Static code analysis for SQL Injection risk.
     * Looks for $wpdb queries that directly concatenate request input,
     * without $wpdb->prepare(). Sends no request to the site — only
     * reads the locally installed PHP files.
     *
     * @return array
     */
    public function check_unsafe_sql_queries(): array {
        $findings = array();
        $scanned  = 0;
        $max_files = 200; // limit so we don't block the request on large sites

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

                // Look for $wpdb->query()/get_results()/get_var() calls that
                // directly concatenate $_GET/$_POST/$_REQUEST, without prepare().
                $pattern = '/\$wpdb->(query|get_results|get_var|get_row)\s*\([^)]*\.\s*\$_(GET|POST|REQUEST)/i';

                if (preg_match($pattern, $content)) {
                    $rel_path = str_replace(ABSPATH, '', $file->getPathname());
                    $findings[] = array(
                        'level' => 'CRITICAL',
                        /* translators: %s: relative path of the file containing the unprepared query */
                        'msg'   => sprintf(__('Possible SQL Injection: unprotected $wpdb query in %s', 'my-security-scanner-pro'), $rel_path),
                    );
                }

                if (count($findings) >= 20) {
                    break 2; // enough results for a useful report
                }
            }
        }

        return $findings;
    }

    /**
     * ADVANCED MODULE: HTTP request with proper headers/body separation,
     * used for the tests below (self-scan only).
     *
     * @param string $url_with_query Fully-formed URL, including query args, to request.
     * @return array
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
     * MODULE: Dynamic SQL Injection (error-based, boolean-based, time-based blind)
     * and reflected XSS — tested EXCLUSIVELY against your own site (home_url), on a
     * dedicated test parameter, never against an arbitrary URL from the request.
     *
     * Why it does not accept an external target: this file runs inside a
     * WordPress plugin; if it accepted an arbitrary URL, it would become a
     * public scanner anyone could use against anyone via your server.
     *
     * @return array
     */
    public function check_dynamic_injection(): array {
        $findings = array();
        $base_url = add_query_arg('msp_scan_probe', '1', home_url('/'));

        // --- SQLi Error-based ---
        $error_indicators = array('SQL syntax', 'mysql_fetch', 'Warning: mysql', 'PostgreSQL', 'ODBC Driver');
        $error_payloads = array("'", '"', "1'");

        foreach ($error_payloads as $payload) {
            $test_url = add_query_arg('msp_probe_val', urlencode($payload), $base_url);
            $resp = $this->fetch_self($test_url);

            foreach ($error_indicators as $indicator) {
                if ($resp['body'] !== '' && stripos($resp['body'], $indicator) !== false) {
                    $findings[] = array(
                        'level' => 'CRITICAL',
                        /* translators: %s: the error-message fragment found in the response */
                        'msg'   => sprintf(__('SQL error exposed in response (indicator: %s) — possible unprotected query.', 'my-security-scanner-pro'), $indicator),
                    );
                    break 2;
                }
            }
        }

        // --- SQLi Time-based blind (only 1 payload, short timeout, so we don't block the request) ---
        $time_url = add_query_arg('msp_probe_val', urlencode("1' AND SLEEP(3)-- -"), $base_url);
        $timed = $this->fetch_self($time_url);
        if ($timed['elapsed'] > 2.5) {
            $findings[] = array(
                'level' => 'WARNING',
                /* translators: %s: response delay in seconds */
                'msg'   => sprintf(__('Unusually large delay (%ss) for the time-based SQLi payload — verify manually whether it\'s relevant.', 'my-security-scanner-pro'), round($timed['elapsed'], 2)),
            );
        }

        // --- Reflected XSS, on the same test parameter ---
        $xss_payload = '<script>mspSelfTestXss()</script>';
        $xss_url = add_query_arg('msp_probe_val', urlencode($xss_payload), $base_url);
        $xss_resp = $this->fetch_self($xss_url);
        if ($xss_resp['body'] !== '' && stripos($xss_resp['body'], $xss_payload) !== false) {
            $findings[] = array(
                'level' => 'CRITICAL',
                'msg'   => __('Query string input is reflected unsanitized on the page — XSS risk.', 'my-security-scanner-pro'),
            );
        }

        return $findings;
    }
}
