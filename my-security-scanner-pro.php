<?php
/**
 * Plugin Name: My Security Pro Scanner
 * Description: Advanced WordPress Security Scanner with Backdoor Detection, Permissions, and API checks. Includes Dashboard, Logs, and Uninstall.
 * Version: 1.0 Professional
 * Author: byot
 * Text Domain: my-security-pro
 */

// Prevenim accesul direct la fișier
if (!defined('ABSPATH')) {
    exit;
}

class MySecurityProScanner {

    // Variabile globale pentru calea plugin-ului și tabelul din DB
    private $plugin_path;
    private $db_table_name;
    private $plugin_pages = array();
    private $http_test_timeout = 6;

    public function __construct() {
        $this->plugin_path = plugin_dir_path(__FILE__);
        global $wpdb;
        $this->db_table_name = $wpdb->prefix . 'my_security_pro_logs';

        // Hook-uri pentru activare, dezactivare și ștergere
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        register_uninstall_hook(__FILE__, array('MySecurityProScanner', 'uninstall'));

        // Hook-uri pentru meniu și AJAX
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('wp_ajax_my_security_pro_scan', array($this, 'handle_ajax_scan'));
        add_action('wp_ajax_my_security_pro_fix_headers', array($this, 'handle_ajax_fix_headers'));

        // Adăugăm stiluri CSS în admin
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));
    }

    /**
     * 1. ACTIVARE: Creează tabela în baza de date
     */
    public function activate() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE {$this->db_table_name} (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            scan_type varchar(50) NOT NULL,
            result_level varchar(20) NOT NULL,
            message text NOT NULL,
            details longtext,
            timestamp datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }

    /**
     * 2. DEZACTIVARE: Poate fi folosit pentru a salva log-uri finale dacă e nevoie
     */
    public function deactivate() {
        // Momentan gol, dar structura este pregătită
    }

    /**
     * 3. UNINSTALL: Șterge tabela când utilizatorul dă "Delete" plugin-ului
     * Trebuie să fie o funcție statică pentru a fi accesibilă global
     */
    public static function uninstall() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'my_security_pro_logs';

        // Verificăm dacă tabela există înainte de a încerca ștergerea
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
            $wpdb->query("DROP TABLE {$table_name}");
        }

        delete_option('my_security_pro_settings');
        delete_option('sp_open_issues');
        delete_option('sp_fixed_log');
    }

    /**
     * 4. MENIU: Adaugă opțiunea în sidebar-ul WordPress
     */
    public function add_admin_menu() {
        // Meniu principal
        $dashboard_hook = add_menu_page(
            'Security Pro Scanner',   // Titlu pagină
            'Security Pro',           // Titlu meniu
            'manage_options',         // Capabilitate necesară
            'my-security-pro',        // Slug-ul meniului
            array($this, 'render_dashboard'), // Funcția care randează pagina principală
            'dashicons-shield-alt',   // Iconiță
            80                        // Poziție — sub Settings, nu peste conținutul principal
        );

        // Submeniuri pentru a organiza interfața
        $this->plugin_pages[] = add_submenu_page(
            'my-security-pro',
            'Dashboard',
            'Dashboard',
            'manage_options',
            'my-security-pro',
            array($this, 'render_dashboard')
        );

        $this->plugin_pages[] = add_submenu_page(
            'my-security-pro',
            'Manual Scan',
            'Manual Scan',
            'manage_options',
            'my-manual-scan',
            array($this, 'render_manual_scan')
        );

        $this->plugin_pages[] = add_submenu_page(
            'my-security-pro',
            'Scan Logs',
            'Scan Logs',
            'manage_options',
            'my-scan-logs',
            array($this, 'render_logs')
        );

        $this->plugin_pages[] = add_submenu_page(
            'my-security-pro',
            'Settings',
            'Settings',
            'manage_options',
            'my-security-pro-settings',
            array($this, 'render_settings')
        );

        $this->plugin_pages[] = $dashboard_hook;
    }

    /**
     * 5. CSS PROFESIONAL: Stiluri moderne pentru admin
     * Se încarcă doar pe paginile acestui plugin, nu în tot admin-ul.
     */
    public function enqueue_admin_styles($hook_suffix) {
        if (empty($this->plugin_pages) || !in_array($hook_suffix, $this->plugin_pages, true)) {
            return;
        }
        ?>
        <style>
            :root {
                --sp-bg: #020617; --sp-surface: #0f172a; --sp-surface-hover: #162032; --sp-border: #1e293b;
                --sp-text: #f8fafc; --sp-text-secondary: #94a3b8; --sp-accent: #06b6d4; --sp-accent-glow: rgba(6,182,212,0.15);
                --sp-critical: #f43f5e; --sp-high: #f97316; --sp-medium: #eab308; --sp-low: #3b82f6; --sp-info: #64748b; --sp-success: #10b981;
            }
            .security-pro-wrap { padding: 24px; background: var(--sp-bg); border: 1px solid var(--sp-border); margin-top: 20px; max-width: 1150px; border-radius: 12px; color: var(--sp-text); }
            .sp-card { background: var(--sp-surface); border: 1px solid var(--sp-border); padding: 20px; margin-bottom: 20px; border-radius: 10px; box-shadow: 0 10px 40px -10px rgba(0,0,0,.45); }
            .sp-card h3 { color: var(--sp-text); margin-top: 0; }
            .sp-card p { color: var(--sp-text-secondary); }
            .sp-header { font-size: 24px; margin-bottom: 0; color: var(--sp-text); display: flex; align-items: center; gap: 10px; }
            .sp-header .dashicons { color: var(--sp-accent); }
            .sp-subtitle { color: var(--sp-text-secondary); margin: 4px 0 20px; }
            .sp-btn-primary { background: var(--sp-accent); color: #000; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block; border: none; cursor: pointer; font-weight: 600; box-shadow: 0 0 20px var(--sp-accent-glow); }
            .sp-btn-primary:hover { filter: brightness(1.15); color: #000; }
            .sp-status-ok { color: var(--sp-success); font-weight: bold; }
            .sp-status-warning { color: var(--sp-medium); font-weight: bold; }
            .sp-status-info { color: var(--sp-low); font-weight: bold; }
            .sp-status-critical { color: var(--sp-critical); font-weight: bold; }
            table.sp-table { width: 100%; border-collapse: collapse; margin-top: 15px; color: var(--sp-text); }
            table.sp-table th, table.sp-table td { padding: 12px; text-align: left; border-bottom: 1px solid var(--sp-border); }
            table.sp-table th { background: var(--sp-surface-hover); font-weight: 600; color: var(--sp-text-secondary); text-transform: uppercase; font-size: 11px; letter-spacing: .04em; }
            table.sp-table tbody tr:hover { background: var(--sp-surface-hover); }
            .sp-nav-tabs.nav-tab-wrapper { border-bottom-color: var(--sp-border); margin: 15px 0 25px; }
            .sp-nav-tabs .nav-tab { background: var(--sp-surface); border-color: var(--sp-border); color: var(--sp-text-secondary); }
            .sp-nav-tabs .nav-tab-active { background: var(--sp-surface-hover); color: var(--sp-accent); border-color: var(--sp-border); }
            .sp-badge { display: inline-flex; align-items: center; padding: 3px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; border: 1px solid transparent; }
            .sp-badge-critical { background: rgba(244,63,94,.12); color: var(--sp-critical); border-color: rgba(244,63,94,.25); }
            .sp-badge-high { background: rgba(249,115,22,.12); color: var(--sp-high); border-color: rgba(249,115,22,.25); }
            .sp-badge-medium, .sp-badge-warning { background: rgba(234,179,8,.12); color: var(--sp-medium); border-color: rgba(234,179,8,.25); }
            .sp-badge-low { background: rgba(59,130,246,.12); color: var(--sp-low); border-color: rgba(59,130,246,.25); }
            .sp-badge-info, .sp-badge-ok { background: rgba(100,116,139,.12); color: var(--sp-info); border-color: rgba(100,116,139,.25); }
            .sp-badge-ok { background: rgba(16,185,129,.12); color: var(--sp-success); border-color: rgba(16,185,129,.25); }
            .sp-stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
            .sp-stat-value { font-size: 28px; font-weight: 800; letter-spacing: -0.03em; color: var(--sp-text); }
            .sp-stat-label { font-size: 13px; color: var(--sp-text-secondary); font-weight: 500; margin-top: 4px; }
            .security-pro-wrap input[type=email], .security-pro-wrap input[type=text], .security-pro-wrap input[type=number], .security-pro-wrap select {
                background: var(--sp-bg); border: 1px solid var(--sp-border); color: var(--sp-text); padding: 8px 10px; border-radius: 6px;
            }
            .security-pro-wrap .description { color: var(--sp-text-secondary); }
            .security-pro-wrap .form-table th { color: var(--sp-text); }
        </style>
        <?php
    }

    /**
     * NAVIGARE COMUNĂ: tab-uri consistente pe toate paginile plugin-ului
     */
    private function render_nav_tabs($active) {
        $tabs = array(
            'my-security-pro'          => 'Dashboard',
            'my-manual-scan'           => 'Manual Scan',
            'my-scan-logs'             => 'Scan Logs',
            'my-security-pro-settings' => 'Settings',
        );
        echo '<h2 class="nav-tab-wrapper sp-nav-tabs">';
        foreach ($tabs as $slug => $label) {
            $class = ($slug === $active) ? 'nav-tab nav-tab-active' : 'nav-tab';
            printf(
                '<a href="%s" class="%s">%s</a>',
                esc_url(admin_url('admin.php?page=' . $slug)),
                esc_attr($class),
                esc_html($label)
            );
        }
        echo '</h2>';
    }

    /**
     * PAGINA PRINCIPALĂ (DASHBOARD)
     */
    public function render_dashboard() {
        global $wpdb;

        // Starea reală curentă — nu istoric acumulat; ce a fost reparat dispare de aici.
        $open_issues = $this->get_open_issues();
        $fixed_log   = get_option('sp_fixed_log', array());

        $total_scans    = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->db_table_name}");
        $critical_count = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->db_table_name} WHERE result_level = 'CRITICAL'");
        $warning_count  = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->db_table_name} WHERE result_level = 'WARNING'");

        ?>
        <div class="security-pro-wrap">
            <h1 class="sp-header"><span class="dashicons dashicons-shield-alt"></span> My Security Pro Scanner</h1>
            <p class="sp-subtitle">Advanced backdoor detection, file permission audits, and API exposure checks.</p>
            <?php $this->render_nav_tabs('my-security-pro'); ?>

            <div class="sp-stat-grid" style="margin-bottom: 24px;">
                <div class="sp-card card-hover">
                    <div class="sp-stat-value"><?php echo esc_html($total_scans); ?></div>
                    <div class="sp-stat-label">Intrări în log</div>
                </div>
                <div class="sp-card card-hover">
                    <div class="sp-stat-value" style="color: var(--sp-critical);"><?php echo esc_html($critical_count); ?></div>
                    <div class="sp-stat-label">Probleme Critice</div>
                </div>
                <div class="sp-card card-hover">
                    <div class="sp-stat-value" style="color: var(--sp-medium);"><?php echo esc_html($warning_count); ?></div>
                    <div class="sp-stat-label">Avertismente</div>
                </div>
                <div class="sp-card card-hover">
                    <div class="sp-stat-value" style="color: var(--sp-accent);">Pro v1.0</div>
                    <div class="sp-stat-label">Versiune plugin</div>
                </div>
            </div>

            <div style="display: flex; gap: 20px;">
                <div class="sp-card" style="flex: 1;">
                    <h3>Stare Sistem</h3>
                    <?php if (count($open_issues) > 0): ?>
                        <p class="sp-status-critical">⚠️ Atenție! Există <?php echo count($open_issues); ?> probleme deschise.</p>
                    <?php else: ?>
                        <p class="sp-status-ok">✅ Sistemul pare securizat.</p>
                    <?php endif; ?>
                </div>

                <div class="sp-card" style="flex: 1;">
                    <h3>Scanare rapidă</h3>
                    <p>Rulează un audit complet acum, fără să aștepți programarea zilnică.</p>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=my-manual-scan')); ?>" class="sp-btn-primary">Lansează Scanare Rapidă</a>
                </div>
            </div>

            <?php if (!empty($open_issues)): ?>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:30px;">
                    <h2 style="margin:0;">Probleme Deschise</h2>
                    <button id="sp-fix-headers-btn" class="sp-btn-primary"
                        onclick="return confirm('Se vor adăuga header-ele HTTP lipsă direct în fișierul .htaccess. Continui?');">
                        🔧 Repară Automat Header-ele
                    </button>
                </div>
                <p class="sp-subtitle" style="margin-top:4px;">Lista reflectă starea reală, la ultima verificare — ce a fost reparat nu mai apare aici.</p>
                <div id="sp-fix-headers-result" style="margin:12px 0;"></div>
                <table class="sp-table">
                    <thead>
                        <tr>
                            <th>Categorie</th>
                            <th>Nivel</th>
                            <th>Mesaj</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($open_issues as $issue): ?>
                            <tr>
                                <td><?php echo esc_html($issue['category']); ?></td>
                                <td><span class="sp-badge sp-badge-<?php echo esc_attr(strtolower($issue['level'])); ?>"><?php echo esc_html($issue['level']); ?></span></td>
                                <td><?php echo esc_html($issue['msg']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <script>
                jQuery(document).ready(function($){
                    $('#sp-fix-headers-btn').on('click', function(){
                        var $btn = $(this);
                        var $result = $('#sp-fix-headers-result');
                        $btn.prop('disabled', true).text('Se aplică...');

                        $.post(ajaxurl, {
                            action: 'my_security_pro_fix_headers',
                            nonce: '<?php echo esc_js(wp_create_nonce('my_security_pro_fix_headers')); ?>'
                        }, function(response){
                            var cls = response.success ? 'sp-status-ok' : 'sp-status-critical';
                            $result.html('<div class="sp-card"><p class="' + cls + '">' + $('<div>').text(response.message).html() + '</p></div>');
                            $btn.prop('disabled', false).text('🔧 Repară Automat Header-ele');
                            setTimeout(function(){ location.reload(); }, 2000);
                        }).fail(function(){
                            $result.html('<div class="sp-card"><p class="sp-status-critical">Eroare la conexiune.</p></div>');
                            $btn.prop('disabled', false).text('🔧 Repară Automat Header-ele');
                        });
                    });
                });
                </script>
            <?php endif; ?>

            <?php if (!empty($fixed_log)): ?>
                <h2 style="margin-top: 30px;">Istoric Reparații</h2>
                <table class="sp-table">
                    <thead>
                        <tr>
                            <th>Data</th>
                            <th>Ce a fost reparat</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($fixed_log as $entry): ?>
                            <tr>
                                <td><?php echo esc_html($entry['time']); ?></td>
                                <td><span class="sp-badge sp-badge-ok">Reparat</span> <?php echo esc_html($entry['label']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * PAGINA SCANARE MANUALĂ (AJAX)
     */
    public function render_manual_scan() {
        ?>
        <div class="security-pro-wrap">
            <h1 class="sp-header"><span class="dashicons dashicons-search"></span> Manual Scan</h1>
            <p class="sp-subtitle">Run an on-demand scan without waiting for the next scheduled check.</p>
            <?php $this->render_nav_tabs('my-manual-scan'); ?>

            <div class="sp-card">
                <p>Selectează tipul de scanare:</p>
                <select id="sp-scan-type" style="padding: 10px; width: 340px;">
                    <option value="full">Scanare Completă (toate modulele)</option>
                    <option value="backdoors">Doar Backdoors & Malware</option>
                    <option value="perms">Doar Permisii Fișiere Critice</option>
                    <option value="headers">Doar Header-e HTTP de Securitate</option>
                    <option value="ports">Doar Porturi Expuse</option>
                    <option value="sqli">Doar Risc SQL Injection (analiză statică)</option>
                    <option value="advanced">SQLi Dinamic + XSS (testează propriul site, mai lent)</option>
                </select>
                <p class="description" style="margin-top:8px; max-width:600px;">
                    Modul "SQLi Dinamic + XSS" trimite câteva request-uri de test către propriul site
                    (home_url), niciodată către un URL extern — nu poate fi folosit ca scanner împotriva altor site-uri.
                </p>
                <button id="sp-start-scan" class="sp-btn-primary" style="margin-left: 10px;">Start Scan</button>
            </div>

            <div id="sp-progress-area" style="display:none; margin-top: 20px;">
                <h3>În curs de analiză...</h3>
                <div style="background: #eee; height: 10px; border-radius: 5px; overflow: hidden;">
                    <div id="sp-bar" style="background: #0073aa; width: 0%; height: 100%; transition: width 0.3s;"></div>
                </div>
                <p id="sp-status-text" style="margin-top: 5px;">Initializare...</p>
            </div>

            <div id="sp-results-area" style="margin-top: 20px;"></div>
        </div>

        <script>
        jQuery(document).ready(function($){
            $('#sp-start-scan').click(function(){
                var type = $('#sp-scan-type').val();
                var $progress = $('#sp-progress-area');
                var $bar = $('#sp-bar');
                var $status = $('#sp-status-text');
                var $results = $('#sp-results-area');

                $progress.show();
                $results.html('');
                $bar.css('width', '10%');
                $status.text('Se scanează fișierele...');

                $.ajax({
                    url: ajaxurl, // URL-ul AJAX din WordPress
                    type: 'POST',
                    data: {
                        action: 'my_security_pro_scan',
                        scan_type: type,
                        nonce: '<?php echo esc_js(wp_create_nonce('my_security_pro_scan')); ?>'
                    },
                    dataType: 'json',
                    success: function(response){
                        $bar.css('width', '100%');
                        $status.text('Scanare finalizată!');
                        
                        function escapeHtml(str) {
                            return $('<div>').text(str).html();
                        }

                        var html = '<h3>Rezultate Scanare (' + escapeHtml(response.scan_type.toUpperCase()) + ')</h3>';

                        if(response.results.length === 0) {
                            html += '<div class="sp-card"><p class="sp-status-ok">✅ Nu s-au găsit probleme!</p></div>';
                        } else {
                            html += '<table class="sp-table"><thead><tr><th>Nivel</th><th>Detaliu</th></tr></thead><tbody>';
                            response.results.forEach(function(item){
                                var badgeClass = 'sp-badge sp-badge-' + item.level.toLowerCase();
                                html += '<tr><td><span class="' + badgeClass + '">' + escapeHtml(item.level) + '</span></td><td>' + escapeHtml(item.msg) + '</td></tr>';
                            });
                            html += '</tbody></table>';
                        }
                        $results.html(html);
                    },
                    error: function(){
                        $status.text('Eroare la conexiune.');
                    }
                });
            });
        });
        </script>
        <?php
    }

    /**
     * PAGINA LOGURI (ISTORIC)
     */
    public function render_logs() {
        global $wpdb;
        $logs = $wpdb->get_results("SELECT * FROM {$this->db_table_name} ORDER BY timestamp DESC LIMIT 50");

        ?>
        <div class="security-pro-wrap">
            <h1 class="sp-header"><span class="dashicons dashicons-list-view"></span> Scan Logs</h1>
            <p class="sp-subtitle">History of the last 50 scan results, most recent first.</p>
            <?php $this->render_nav_tabs('my-scan-logs'); ?>

            <?php if ($logs): ?>
                <table class="sp-table">
                    <thead>
                        <tr>
                            <th>Data</th>
                            <th>Tip</th>
                            <th>Nivel</th>
                            <th>Mesaj</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                            <tr>
                                <td><?php echo esc_html($log->timestamp); ?></td>
                                <td><?php echo esc_html($log->scan_type); ?></td>
                                <td><span class="sp-badge sp-badge-<?php echo esc_attr(strtolower($log->result_level)); ?>"><?php echo esc_html($log->result_level); ?></span></td>
                                <td><?php echo esc_html($log->message); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="sp-card"><p>Niciun log găsit încă.</p></div>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * PAGINA SETĂRI
     */
    public function render_settings() {
        if (isset($_POST['sp_save_settings']) && check_admin_referer('my_security_pro_settings')) {
            update_option('my_security_pro_settings', array(
                'notify_email' => sanitize_email($_POST['sp_notify_email'] ?? ''),
                'notify_on'    => !empty($_POST['sp_notify_on']),
            ));
            echo '<div class="notice notice-success is-dismissible"><p>Setări salvate.</p></div>';
        }

        $settings = wp_parse_args(get_option('my_security_pro_settings', array()), array(
            'notify_email' => get_option('admin_email'),
            'notify_on'    => false,
        ));
        ?>
        <div class="security-pro-wrap">
            <h1 class="sp-header"><span class="dashicons dashicons-admin-generic"></span> Settings</h1>
            <p class="sp-subtitle">Configure notifications for the security scanner.</p>
            <?php $this->render_nav_tabs('my-security-pro-settings'); ?>

            <div class="sp-card">
                <form method="post">
                    <?php wp_nonce_field('my_security_pro_settings'); ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><label for="sp_notify_email">Notification email</label></th>
                            <td><input type="email" id="sp_notify_email" name="sp_notify_email"
                                value="<?php echo esc_attr($settings['notify_email']); ?>" class="regular-text" /></td>
                        </tr>
                        <tr>
                            <th scope="row">Email alerts</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="sp_notify_on" value="1" <?php checked($settings['notify_on']); ?> />
                                    Send an email when a scan finds WARNING or CRITICAL issues
                                </label>
                            </td>
                        </tr>
                    </table>
                    <button type="submit" name="sp_save_settings" class="sp-btn-primary">Save Settings</button>
                </form>
            </div>
        </div>
        <?php
    }

    /**
     * Definiții header-e: numele HTTP real + valoarea recomandată, folosite
     * atât pentru detectare cât și pentru generarea fix-ului automat în .htaccess.
     */
    private function header_definitions(): array {
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
    private function check_security_headers(): array {
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
    private function apply_header_fixes(): array {
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
                $this->log_fix($defs[$key]['name'] . ' adăugat în .htaccess');
            }
        }

        $this->update_open_issues('headers', $still_missing);

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
    private function check_exposed_ports(): array {
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
    private function check_unsafe_sql_queries(): array {
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

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
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
    private function check_dynamic_injection(): array {
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

    /**
     * AJAX HANDLER: aplică fix-ul automat pentru header-ele HTTP lipsă
     */
    public function handle_ajax_fix_headers() {
        check_ajax_referer('my_security_pro_fix_headers', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions.', 403);
        }

        $result = $this->apply_header_fixes();

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
    public function handle_ajax_scan() {
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
                if($count < 10) {
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
            $this->update_open_issues('backdoors', $backdoor_items);
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
            $this->update_open_issues('perms', $perms_items);
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
            $this->update_open_issues('api', $api_items);
        }

        // 4. HEADER-E HTTP DE SECURITATE
        if ($scan_type == 'full' || $scan_type == 'headers') {
            $header_items = array();
            foreach ($this->check_security_headers() as $item) {
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
            $this->update_open_issues('headers', $header_items);
        }

        // 5. PORTURI EXPUSE PE PROPRIUL SERVER
        if ($scan_type == 'full' || $scan_type == 'ports') {
            $port_items = array();
            foreach ($this->check_exposed_ports() as $item) {
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
            $this->update_open_issues('ports', $port_items);
        }

        // 6. RISC SQL INJECTION — analiză statică de cod, nu atac live
        if ($scan_type == 'full' || $scan_type == 'sqli') {
            $sqli_items = array();
            foreach ($this->check_unsafe_sql_queries() as $item) {
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
            $this->update_open_issues('sqli', $sqli_items);
        }

        // 7. SQLi DINAMIC + XSS REFLECTAT — doar pe propriul site, "full" nu îl include
        // implicit pentru că e mai lent (mai multe requesturi HTTP); se rulează explicit.
        if ($scan_type == 'advanced') {
            $dynamic_items = array();
            foreach ($this->check_dynamic_injection() as $item) {
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
            $this->update_open_issues('dynamic', $dynamic_items);
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

    /**
     * Suprascrie problemele deschise pentru o categorie dată cu rezultatele
     * proaspete ale scanării curente. Astfel, ceea ce a fost reparat între
     * timp dispare automat din lista de alerte active — nu se acumulează
     * la infinit ca într-un log brut.
     */
    private function update_open_issues(string $category, array $fresh_items): void {
        $state = get_option('sp_open_issues', array());
        $state[$category] = $fresh_items;
        update_option('sp_open_issues', $state, false);
    }

    /**
     * Returnează lista curentă (reală, la zi) de probleme deschise,
     * agregată din toate categoriile scanate până acum.
     */
    private function get_open_issues(): array {
        $state = get_option('sp_open_issues', array());
        $flat = array();
        foreach ($state as $category => $items) {
            foreach ($items as $item) {
                $item['category'] = $category;
                $flat[] = $item;
            }
        }

        $order = array('CRITICAL' => 0, 'WARNING' => 1, 'INFO' => 2);
        usort($flat, function ($a, $b) use ($order) {
            return ($order[$a['level']] ?? 3) <=> ($order[$b['level']] ?? 3);
        });

        return $flat;
    }

    /**
     * Înregistrează o reparare confirmată (folosit de apply_header_fixes),
     * afișată apoi în lista "Istoric Reparații" din Dashboard.
     */
    private function log_fix(string $label): void {
        $log = get_option('sp_fixed_log', array());
        array_unshift($log, array('label' => $label, 'time' => current_time('mysql')));
        $log = array_slice($log, 0, 20);
        update_option('sp_fixed_log', $log, false);
    }
}

// Inițializare plugin
new MySecurityProScanner();