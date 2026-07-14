<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * The admin menu and the 4 pages (Dashboard, Manual Scan, Scan Logs, Settings).
 * Contains no scanning logic — only rendering and form actions.
 */
class MSP_Admin {

    /**
     * Name of the custom table that stores raw scan history.
     *
     * @var string
     */
    private string $db_table_name;

    /**
     * Tracks current open issues and confirmed fixes.
     *
     * @var MSP_State
     */
    private MSP_State $state;

    /**
     * Hook suffixes of this plugin's admin pages, used to scope asset loading.
     *
     * @var array
     */
    private array $plugin_pages = array();

    /**
     * @param string    $db_table_name Name of the custom table that stores scan history.
     * @param MSP_State $state         Shared state tracker for open issues and fixes.
     */
    public function __construct(string $db_table_name, MSP_State $state) {
        $this->db_table_name = $db_table_name;
        $this->state = $state;

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
    }

    /**
     * MENU: Adds the option in the WordPress sidebar
     *
     * @return void
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
     * Loads CSS/JS only on this plugin's pages, not across the whole admin area.
     *
     * @param string $hook_suffix The current admin page hook, supplied by WordPress.
     * @return void
     */
    public function enqueue_admin_assets(string $hook_suffix) {
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
     * SHARED NAVIGATION: consistent tabs across all plugin pages
     *
     * @param string $active Slug of the currently active admin page.
     * @return void
     */
    private function render_nav_tabs(string $active) {
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
     * MAIN PAGE (DASHBOARD)
     *
     * @return void
     */
    public function render_dashboard() {
        global $wpdb;

        // The real current state — not accumulated history; anything fixed disappears from here.
        $open_issues = $this->state->get_open_issues();
        $fixed_log   = $this->state->get_fixed_log();

        // Critical/Warning counts must come from the same deduplicated open-issues
        // state shown below, not from the raw historical log table -- otherwise a
        // category re-scanned multiple times counts the same still-open issue
        // more than once, and the stat card disagrees with the table underneath it.
        $total_scans    = (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i', $this->db_table_name));
        $critical_count = count( array_filter( $open_issues, function ( $issue ) { return 'CRITICAL' === $issue['level']; } ) );
        $warning_count  = count( array_filter( $open_issues, function ( $issue ) { return 'WARNING' === $issue['level']; } ) );

        ?>
        <div class="security-pro-wrap">
            <h1 class="sp-header"><span class="dashicons dashicons-shield-alt"></span> My Security Pro Scanner</h1>
            <p class="sp-subtitle">Advanced backdoor detection, file permission audits, and API exposure checks.</p>
            <?php $this->render_nav_tabs('my-security-pro'); ?>

            <div class="sp-stat-grid" style="margin-bottom: 24px;">
                <div class="sp-card card-hover">
                    <div class="sp-stat-value"><?php echo esc_html($total_scans); ?></div>
                    <div class="sp-stat-label">Log entries</div>
                </div>
                <div class="sp-card card-hover">
                    <div class="sp-stat-value" style="color: var(--sp-critical);"><?php echo esc_html($critical_count); ?></div>
                    <div class="sp-stat-label">Critical Issues</div>
                </div>
                <div class="sp-card card-hover">
                    <div class="sp-stat-value" style="color: var(--sp-medium);"><?php echo esc_html($warning_count); ?></div>
                    <div class="sp-stat-label">Warnings</div>
                </div>
                <div class="sp-card card-hover">
                    <div class="sp-stat-value" style="color: var(--sp-accent);">Pro v1.0</div>
                    <div class="sp-stat-label">Plugin version</div>
                </div>
            </div>

            <div style="display: flex; gap: 20px;">
                <div class="sp-card" style="flex: 1;">
                    <h3>System Status</h3>
                    <?php if (count($open_issues) > 0): ?>
                        <p class="sp-status-critical">⚠️ Attention! There are <?php echo count($open_issues); ?> open issues.</p>
                    <?php else: ?>
                        <p class="sp-status-ok">✅ The system appears secure.</p>
                    <?php endif; ?>
                </div>

                <div class="sp-card" style="flex: 1;">
                    <h3>Quick Scan</h3>
                    <p>Run a full audit now, without waiting for the daily scheduled scan.</p>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=my-manual-scan')); ?>" class="sp-btn-primary">Launch Quick Scan</a>
                </div>
            </div>

            <?php if (!empty($open_issues)): ?>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:30px;">
                    <h2 style="margin:0;">Open Issues</h2>
                    <button id="sp-fix-headers-btn" class="sp-btn-primary"
                        onclick="return confirm('This will add the missing HTTP headers directly to the .htaccess file. Continue?');">
                        🔧 Auto-Fix Headers
                    </button>
                </div>
                <p class="sp-subtitle" style="margin-top:4px;">The list reflects the actual state as of the last check — anything fixed no longer appears here.</p>
                <div id="sp-fix-headers-result" style="margin:12px 0;"></div>
                <table class="sp-table">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Level</th>
                            <th>Message</th>
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
                <h2 style="margin-top: 30px;">Fix History</h2>
                <table class="sp-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>What was fixed</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($fixed_log as $entry): ?>
                            <tr>
                                <td><?php echo esc_html($entry['time']); ?></td>
                                <td><span class="sp-badge sp-badge-ok">Fixed</span> <?php echo esc_html($entry['label']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * MANUAL SCAN PAGE (AJAX)
     *
     * @return void
     */
    public function render_manual_scan() {
        ?>
        <div class="security-pro-wrap">
            <h1 class="sp-header"><span class="dashicons dashicons-search"></span> Manual Scan</h1>
            <p class="sp-subtitle">Run an on-demand scan without waiting for the next scheduled check.</p>
            <?php $this->render_nav_tabs('my-manual-scan'); ?>

            <div class="sp-card">
                <p>Select the scan type:</p>
                <select id="sp-scan-type" style="padding: 10px; width: 340px;">
                    <option value="full">Full Scan (all modules)</option>
                    <option value="backdoors">Backdoors &amp; Malware Only</option>
                    <option value="perms">Critical File Permissions Only</option>
                    <option value="headers">HTTP Security Headers Only</option>
                    <option value="ports">Exposed Ports Only</option>
                    <option value="sqli">SQL Injection Risk Only (static analysis)</option>
                    <option value="advanced">Dynamic SQLi + XSS (tests your own site, slower)</option>
                </select>
                <p class="description" style="margin-top:8px; max-width:600px;">
                    The "Dynamic SQLi + XSS" module sends a handful of test requests to your own site
                    (home_url), never to an external URL — it cannot be used as a scanner against other sites.
                </p>
                <button id="sp-start-scan" class="sp-btn-primary" style="margin-left: 10px;">Start Scan</button>
            </div>

            <div id="sp-progress-area" style="display:none; margin-top: 20px;">
                <h3>Analysis in progress...</h3>
                <div class="sp-progress-track">
                    <div id="sp-bar" class="sp-progress-bar"></div>
                </div>
                <p id="sp-status-text" style="margin-top: 5px;">Initializing...</p>
            </div>

            <div id="sp-results-area" style="margin-top: 20px;"></div>
        </div>
        <?php
    }

    /**
     * LOGS PAGE (HISTORY)
     *
     * @return void
     */
    public function render_logs() {
        global $wpdb;
        $logs = $wpdb->get_results($wpdb->prepare('SELECT * FROM %i ORDER BY timestamp DESC LIMIT 50', $this->db_table_name));

        ?>
        <div class="security-pro-wrap">
            <h1 class="sp-header"><span class="dashicons dashicons-list-view"></span> Scan Logs</h1>
            <p class="sp-subtitle">History of the last 50 scan results, most recent first.</p>
            <?php $this->render_nav_tabs('my-scan-logs'); ?>

            <?php if ($logs): ?>
                <table class="sp-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Type</th>
                            <th>Level</th>
                            <th>Message</th>
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
                <div class="sp-card"><p>No logs found yet.</p></div>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * SETTINGS PAGE
     *
     * @return void
     */
    public function render_settings() {
        if (isset($_POST['sp_save_settings']) && check_admin_referer('my_security_pro_settings') && current_user_can('manage_options')) {
            update_option('my_security_pro_settings', array(
                'notify_email' => sanitize_email(wp_unslash($_POST['sp_notify_email'] ?? '')),
                'notify_on'    => !empty($_POST['sp_notify_on']),
            ));
            echo '<div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>';
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
