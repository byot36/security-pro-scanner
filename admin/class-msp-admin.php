<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Meniul din admin și cele 4 pagini (Dashboard, Manual Scan, Scan Logs, Settings).
 * Nu conține logică de scanare — doar afișare și acțiuni de formular.
 */
class MSP_Admin {

    private string $db_table_name;
    private MSP_State $state;
    private array $plugin_pages = array();

    public function __construct(string $db_table_name, MSP_State $state) {
        $this->db_table_name = $db_table_name;
        $this->state = $state;

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
    }

    /**
     * MENIU: Adaugă opțiunea în sidebar-ul WordPress
     */
    public function add_admin_menu() {
        $dashboard_hook = add_menu_page(
            'Security Pro Scanner',
            'Security Pro',
            'manage_options',
            'my-security-pro',
            array($this, 'render_dashboard'),
            'dashicons-shield-alt',
            80
        );

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
     * Încarcă CSS/JS doar pe paginile acestui plugin, nu în tot admin-ul.
     */
    public function enqueue_admin_assets($hook_suffix) {
        if (empty($this->plugin_pages) || !in_array($hook_suffix, $this->plugin_pages, true)) {
            return;
        }

        wp_enqueue_style(
            'msp-admin',
            MSP_URL . 'assets/css/admin.css',
            array(),
            MSP_VERSION
        );

        wp_enqueue_script(
            'msp-admin',
            MSP_URL . 'assets/js/admin.js',
            array('jquery'),
            MSP_VERSION,
            true
        );

        wp_localize_script('msp-admin', 'mspData', array(
            'ajaxUrl'         => admin_url('admin-ajax.php'),
            'scanNonce'       => wp_create_nonce('my_security_pro_scan'),
            'fixHeadersNonce' => wp_create_nonce('my_security_pro_fix_headers'),
        ));
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
        $open_issues = $this->state->get_open_issues();
        $fixed_log   = $this->state->get_fixed_log();

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
                    <option value="backdoors">Doar Backdoors &amp; Malware</option>
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
                <div class="sp-progress-track">
                    <div id="sp-bar" class="sp-progress-bar"></div>
                </div>
                <p id="sp-status-text" style="margin-top: 5px;">Initializare...</p>
            </div>

            <div id="sp-results-area" style="margin-top: 20px;"></div>
        </div>
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
}
