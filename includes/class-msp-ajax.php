<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * AJAX handlers: run scans on demand and apply the header fix.
 * Bridges MSP_Scanner (detection), MSP_State (current state) and
 * the database log table (raw history, for the Scan Logs page).
 */
class MSP_Ajax {

    /**
     * Name of the custom table that stores raw scan history.
     *
     * @var string
     */
    private string $db_table_name;

    /**
     * Detection logic used to run each scan module.
     *
     * @var MSP_Scanner
     */
    private MSP_Scanner $scanner;

    /**
     * Shared state tracker for open issues and confirmed fixes.
     *
     * @var MSP_State
     */
    private MSP_State $state;

    /**
     * @param string      $db_table_name Name of the custom table that stores scan history.
     * @param MSP_Scanner $scanner       Detection logic used to run each scan module.
     * @param MSP_State   $state         Shared state tracker for open issues and fixes.
     */
    public function __construct(string $db_table_name, MSP_Scanner $scanner, MSP_State $state) {
        $this->db_table_name = $db_table_name;
        $this->scanner = $scanner;
        $this->state = $state;

        add_action('wp_ajax_my_security_pro_scan', array($this, 'handle_scan'));
        add_action('wp_ajax_my_security_pro_fix_headers', array($this, 'handle_fix_headers'));
    }

    /**
     * AJAX HANDLER: applies the automatic fix for missing HTTP headers
     *
     * @return void
     */
    public function handle_fix_headers() {
        check_ajax_referer('my_security_pro_fix_headers', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions.', 403);
        }

        $result = $this->scanner->apply_header_fixes();

        global $wpdb;
        $wpdb->insert($this->db_table_name, array(
            'scan_type' => 'headers_fix',
            'result_level' => $result['success'] ? 'OK' : 'WARNING',
            'message' => $result['message'],
            'details' => wp_json_encode($result['fixed']),
        ));

        wp_send_json($result);
    }

    /**
     * SCAN LOGIC (AJAX HANDLER)
     *
     * @return void
     */
    public function handle_scan() {
        check_ajax_referer('my_security_pro_scan', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions.', 403);
        }

        $scan_type = isset($_POST['scan_type']) ? sanitize_key(wp_unslash($_POST['scan_type'])) : 'full';
        $results = array();
        global $wpdb;

        // 1. BACKDOORS DETECTION (Simple regex on critical files and plugins)
        if ($scan_type === 'full' || $scan_type === 'backdoors') {
            $backdoor_items = array();

            // Scan wp-config.php and index.php as critical examples
            $files_to_check = array(ABSPATH . 'wp-config.php', ABSPATH . 'index.php');

            // Add the first plugins so we don't slow the system down too much
            $plugins = get_plugins();
            $count = 0;
            foreach ($plugins as $path => $info) {
                if ($count < 10) {
                    $files_to_check[] = WP_PLUGIN_DIR . '/' . $path;
                    $count++;
                }
            }

            foreach ($files_to_check as $file_path) {
                if (is_readable($file_path)) {
                    $content = file_get_contents($file_path);
                    if ($content === false) {
                        continue;
                    }

                    // Look for common malware functions
                    $patterns = array('/eval\s*\(/', '/base64_decode\s*\(/', '/assert\s*\(/');

                    foreach ($patterns as $pattern) {
                        if (preg_match($pattern, $content)) {
                            $rel_path = str_replace(ABSPATH, '', $file_path);
                            $backdoor_items[] = array('level' => 'WARNING', 'msg' => "Suspicious code in: $rel_path", 'key' => 'backdoor_' . md5($rel_path));
                            $wpdb->insert($this->db_table_name, array(
                                'scan_type' => 'backdoor',
                                'result_level' => 'WARNING',
                                'message' => "Suspicious code in $rel_path",
                                'details' => wp_json_encode(array('file' => $rel_path))
                            ));
                            break; // A single alert per file
                        }
                    }
                }
            }

            $results = array_merge($results, $backdoor_items);
            $this->state->update_open_issues('backdoors', $backdoor_items);
        }

        // 2. CRITICAL FILE PERMISSIONS
        if ($scan_type === 'full' || $scan_type === 'perms') {
            $perms_items = array();
            $critical_files = array('wp-config.php', '.htaccess');
            foreach ($critical_files as $file) {
                $path = ABSPATH . $file;
                if (file_exists($path)) {
                    $perms = substr(sprintf('%o', fileperms($path)), -4);
                    // 0644 is standard, 0755 is acceptable for htaccess but not for config
                    if ($file === 'wp-config.php' && octdec($perms) > 0644) {
                        $perms_items[] = array('level' => 'CRITICAL', 'msg' => "Risky permissions: wp-config.php ($perms)", 'key' => 'perms_wpconfig');
                        $wpdb->insert($this->db_table_name, array(
                            'scan_type' => 'perms',
                            'result_level' => 'CRITICAL',
                            'message' => "Bad permissions for wp-config.php",
                            'details' => wp_json_encode(array('perms' => $perms))
                        ));
                    }
                }
            }
            $results = array_merge($results, $perms_items);
            $this->state->update_open_issues('perms', $perms_items);
        }

        // 3. REST API ENUMERATION (Simple)
        if ($scan_type === 'full') {
            $api_items = array();
            $response = wp_remote_get(home_url('/wp-json/wp/v2/users'));
            if (!is_wp_error($response)) {
                $body = json_decode(wp_remote_retrieve_body($response), true);
                if (isset($body['count']) && $body['count'] > 5) {
                    $api_items[] = array('level' => 'INFO', 'msg' => "API exposed: {$body['count']} visible users.", 'key' => 'api_users_exposed');
                }
            }
            $results = array_merge($results, $api_items);
            $this->state->update_open_issues('api', $api_items);
        }

        // 4. HTTP SECURITY HEADERS
        if ($scan_type === 'full' || $scan_type === 'headers') {
            $header_items = array();
            foreach ($this->scanner->check_security_headers() as $item) {
                $item['key'] = 'header_' . $item['header_key'];
                $header_items[] = $item;
                $results[] = $item;
                $wpdb->insert($this->db_table_name, array(
                    'scan_type' => 'headers',
                    'result_level' => $item['level'],
                    'message' => $item['msg'],
                    'details' => '{}'
                ));
            }
            $this->state->update_open_issues('headers', $header_items);
        }

        // 5. EXPOSED PORTS ON YOUR OWN SERVER
        if ($scan_type === 'full' || $scan_type === 'ports') {
            $port_items = array();
            foreach ($this->scanner->check_exposed_ports() as $item) {
                $item['key'] = 'port_' . md5($item['msg']);
                $port_items[] = $item;
                $results[] = $item;
                $wpdb->insert($this->db_table_name, array(
                    'scan_type' => 'ports',
                    'result_level' => $item['level'],
                    'message' => $item['msg'],
                    'details' => '{}'
                ));
            }
            $this->state->update_open_issues('ports', $port_items);
        }

        // 6. SQL INJECTION RISK — static code analysis, not a live attack
        if ($scan_type === 'full' || $scan_type === 'sqli') {
            $sqli_items = array();
            foreach ($this->scanner->check_unsafe_sql_queries() as $item) {
                $item['key'] = 'sqli_' . md5($item['msg']);
                $sqli_items[] = $item;
                $results[] = $item;
                $wpdb->insert($this->db_table_name, array(
                    'scan_type' => 'sqli_static',
                    'result_level' => $item['level'],
                    'message' => $item['msg'],
                    'details' => '{}'
                ));
            }
            $this->state->update_open_issues('sqli', $sqli_items);
        }

        // 7. DYNAMIC SQLi + REFLECTED XSS — on your own site only, "full" does not
        // include it by default because it's slower (more HTTP requests); run it explicitly.
        if ($scan_type === 'advanced') {
            $dynamic_items = array();
            foreach ($this->scanner->check_dynamic_injection() as $item) {
                $item['key'] = 'dynamic_' . md5($item['msg']);
                $dynamic_items[] = $item;
                $results[] = $item;
                $wpdb->insert($this->db_table_name, array(
                    'scan_type' => 'dynamic_injection',
                    'result_level' => $item['level'],
                    'message' => $item['msg'],
                    'details' => '{}'
                ));
            }
            $this->state->update_open_issues('dynamic', $dynamic_items);
        }

        // If nothing was found in this specific scan, log a general OK if it's a full scan
        if ($scan_type === 'full' && empty($results)) {
            $wpdb->insert($this->db_table_name, array(
                'scan_type' => 'full',
                'result_level' => 'OK',
                'message' => "Full scan completed with no critical issues.",
                'details' => '{}'
            ));
        }

        wp_send_json(array(
            'scan_type' => $scan_type,
            'results' => $results
        ));
    }
}
