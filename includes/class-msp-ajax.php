<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Handlerele AJAX: rulează scanările la cerere și aplică fix-ul de header-e.
 * Face legătura între MSP_Scanner (detectare), MSP_State (stare curentă) și
 * tabela de log din baza de date (istoric brut, pentru pagina Scan Logs).
 */
class MSP_Ajax {

    private string $db_table_name;
    private MSP_Scanner $scanner;
    private MSP_State $state;

    public function __construct(string $db_table_name, MSP_Scanner $scanner, MSP_State $state) {
        $this->db_table_name = $db_table_name;
        $this->scanner = $scanner;
        $this->state = $state;

        add_action('wp_ajax_my_security_pro_scan', array($this, 'handle_scan'));
        add_action('wp_ajax_my_security_pro_fix_headers', array($this, 'handle_fix_headers'));
    }

    /**
     * AJAX HANDLER: aplică fix-ul automat pentru header-ele HTTP lipsă
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
     * LOGICA SCANĂRII (AJAX HANDLER)
     */
    public function handle_scan() {
        check_ajax_referer('my_security_pro_scan', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions.', 403);
        }

        $scan_type = isset($_POST['scan_type']) ? sanitize_key($_POST['scan_type']) : 'full';
        $results = array();
        global $wpdb;

        // 1. BACKDOORS DETECTION (Regex simplu pe fișierele critice și pluginuri)
        if ($scan_type == 'full' || $scan_type == 'backdoors') {
            $backdoor_items = array();

            // Scanăm wp-config.php și index.php ca demo critic
            $files_to_check = array(ABSPATH . 'wp-config.php', ABSPATH . 'index.php');

            // Adăugăm primele 5 pluginuri pentru a nu încetini prea tare sistemul în demo
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

                    // Căutăm funcții comune de malware
                    $patterns = array('/eval\s*\(/', '/base64_decode\s*\(/', '/assert\s*\(/');

                    foreach ($patterns as $pattern) {
                        if (preg_match($pattern, $content)) {
                            $rel_path = str_replace(ABSPATH, '', $file_path);
                            $backdoor_items[] = array('level' => 'WARNING', 'msg' => "Cod suspect în: $rel_path", 'key' => 'backdoor_' . md5($rel_path));
                            $wpdb->insert($this->db_table_name, array(
                                'scan_type' => 'backdoor',
                                'result_level' => 'WARNING',
                                'message' => "Suspicious code in $rel_path",
                                'details' => json_encode(array('file' => $rel_path))
                            ));
                            break; // Un singur alert per fișier
                        }
                    }
                }
            }

            $results = array_merge($results, $backdoor_items);
            $this->state->update_open_issues('backdoors', $backdoor_items);
        }

        // 2. PERMISII FIȘIERE CRITICE
        if ($scan_type == 'full' || $scan_type == 'perms') {
            $perms_items = array();
            $critical_files = array('wp-config.php', '.htaccess');
            foreach ($critical_files as $file) {
                $path = ABSPATH . $file;
                if (file_exists($path)) {
                    $perms = substr(sprintf('%o', fileperms($path)), -4);
                    // 0644 e standard, 0755 e acceptabil pentru htaccess dar nu pt config
                    if ($file == 'wp-config.php' && octdec($perms) > 0644) {
                        $perms_items[] = array('level' => 'CRITICAL', 'msg' => "Permisiuni riscante: wp-config.php ($perms)", 'key' => 'perms_wpconfig');
                        $wpdb->insert($this->db_table_name, array(
                            'scan_type' => 'perms',
                            'result_level' => 'CRITICAL',
                            'message' => "Bad permissions for wp-config.php",
                            'details' => json_encode(array('perms' => $perms))
                        ));
                    }
                }
            }
            $results = array_merge($results, $perms_items);
            $this->state->update_open_issues('perms', $perms_items);
        }

        // 3. REST API ENUMERATION (Simplu)
        if ($scan_type == 'full') {
            $api_items = array();
            $response = wp_remote_get(home_url('/wp-json/wp/v2/users'));
            if (!is_wp_error($response)) {
                $body = json_decode(wp_remote_retrieve_body($response), true);
                if (isset($body['count']) && $body['count'] > 5) {
                    $api_items[] = array('level' => 'INFO', 'msg' => "API expus: {$body['count']} utilizatori vizibili.", 'key' => 'api_users_exposed');
                }
            }
            $results = array_merge($results, $api_items);
            $this->state->update_open_issues('api', $api_items);
        }

        // 4. HEADER-E HTTP DE SECURITATE
        if ($scan_type == 'full' || $scan_type == 'headers') {
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

        // 5. PORTURI EXPUSE PE PROPRIUL SERVER
        if ($scan_type == 'full' || $scan_type == 'ports') {
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

        // 6. RISC SQL INJECTION — analiză statică de cod, nu atac live
        if ($scan_type == 'full' || $scan_type == 'sqli') {
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

        // 7. SQLi DINAMIC + XSS REFLECTAT — doar pe propriul site, "full" nu îl include
        // implicit pentru că e mai lent (mai multe requesturi HTTP); se rulează explicit.
        if ($scan_type == 'advanced') {
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

        // Dacă nu s-a găsit nimic în această scanare specifică, logăm un OK general dacă e full
        if ($scan_type == 'full' && empty($results)) {
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

        die(); // Oprește execuția AJAX
    }
}
