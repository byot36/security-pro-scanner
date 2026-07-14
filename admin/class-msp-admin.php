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
            __('Security Pro Scanner', 'my-security-scanner-pro'),
            __('Security Pro', 'my-security-scanner-pro'),
            'manage_options',
            'my-security-pro',
            array($this, 'render_dashboard'),
            'dashicons-shield-alt',
            80
        );

        $this->plugin_pages[] = add_submenu_page(
            'my-security-pro',
            __('Dashboard', 'my-security-scanner-pro'),
            __('Dashboard', 'my-security-scanner-pro'),
            'manage_options',
            'my-security-pro',
            array($this, 'render_dashboard')
        );

        $this->plugin_pages[] = add_submenu_page(
            'my-security-pro',
            __('Manual Scan', 'my-security-scanner-pro'),
            __('Manual Scan', 'my-security-scanner-pro'),
            'manage_options',
            'my-manual-scan',
            array($this, 'render_manual_scan')
        );

        $this->plugin_pages[] = add_submenu_page(
            'my-security-pro',
            __('Scan Logs', 'my-security-scanner-pro'),
            __('Scan Logs', 'my-security-scanner-pro'),
            'manage_options',
            'my-scan-logs',
            array($this, 'render_logs')
        );

        $this->plugin_pages[] = add_submenu_page(
            'my-security-pro',
            __('Settings', 'my-security-scanner-pro'),
            __('Settings', 'my-security-scanner-pro'),
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
            'strings'         => array(
                'scanning'        => __('Scanning files...', 'my-security-scanner-pro'),
                'scanComplete'    => __('Scan complete!', 'my-security-scanner-pro'),
                'connectionError' => __('Connection error.', 'my-security-scanner-pro'),
                'noIssuesFound'   => __('No issues found!', 'my-security-scanner-pro'),
                'levelColumn'     => __('Level', 'my-security-scanner-pro'),
                'detailColumn'    => __('Detail', 'my-security-scanner-pro'),
                'applying'        => __('Applying...', 'my-security-scanner-pro'),
                'autoFixHeaders'  => __('Auto-Fix Headers', 'my-security-scanner-pro'),
            ),
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
            'my-security-pro'          => __('Dashboard', 'my-security-scanner-pro'),
            'my-manual-scan'           => __('Manual Scan', 'my-security-scanner-pro'),
            'my-scan-logs'             => __('Scan Logs', 'my-security-scanner-pro'),
            'my-security-pro-settings' => __('Settings', 'my-security-scanner-pro'),
        );
        echo '<h2 class="nav-tab-wrapper msp-nav-tabs">';
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
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table; the dashboard always needs the live count, not a cached one.
        $total_scans    = (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i', $this->db_table_name));
        $critical_count = count( array_filter( $open_issues, function ( $issue ) { return 'CRITICAL' === $issue['level']; } ) );
        $warning_count  = count( array_filter( $open_issues, function ( $issue ) { return 'WARNING' === $issue['level']; } ) );

        ?>
        <div class="msp-wrap">
            <h1 class="msp-header"><span class="dashicons dashicons-shield-alt"></span> <?php esc_html_e('My Security Pro Scanner', 'my-security-scanner-pro'); ?></h1>
            <p class="msp-subtitle"><?php esc_html_e('Advanced backdoor detection, file permission audits, and API exposure checks.', 'my-security-scanner-pro'); ?></p>
            <?php $this->render_nav_tabs('my-security-pro'); ?>

            <div class="msp-stat-grid" style="margin-bottom: 24px;">
                <div class="msp-card card-hover">
                    <div class="msp-stat-value"><?php echo esc_html($total_scans); ?></div>
                    <div class="msp-stat-label"><?php esc_html_e('Log entries', 'my-security-scanner-pro'); ?></div>
                </div>
                <div class="msp-card card-hover">
                    <div class="msp-stat-value" style="color: var(--msp-critical);"><?php echo esc_html($critical_count); ?></div>
                    <div class="msp-stat-label"><?php esc_html_e('Critical Issues', 'my-security-scanner-pro'); ?></div>
                </div>
                <div class="msp-card card-hover">
                    <div class="msp-stat-value" style="color: var(--msp-medium);"><?php echo esc_html($warning_count); ?></div>
                    <div class="msp-stat-label"><?php esc_html_e('Warnings', 'my-security-scanner-pro'); ?></div>
                </div>
                <div class="msp-card card-hover">
                    <?php /* translators: %s: plugin version number, e.g. 1.1.0 */ ?>
                    <div class="msp-stat-value" style="color: var(--msp-accent);"><?php echo esc_html(sprintf(__('Pro v%s', 'my-security-scanner-pro'), MSP_VERSION)); ?></div>
                    <div class="msp-stat-label"><?php esc_html_e('Plugin version', 'my-security-scanner-pro'); ?></div>
                </div>
            </div>

            <div style="display: flex; gap: 20px;">
                <div class="msp-card" style="flex: 1;">
                    <h3><?php esc_html_e('System Status', 'my-security-scanner-pro'); ?></h3>
                    <?php if (count($open_issues) > 0): ?>
                        <?php /* translators: %d: number of currently open issues */ ?>
                        <p class="msp-status-critical">⚠️ <?php echo esc_html(sprintf(__('Attention! There are %d open issues.', 'my-security-scanner-pro'), count($open_issues))); ?></p>
                    <?php else: ?>
                        <p class="msp-status-ok">✅ <?php esc_html_e('The system appears secure.', 'my-security-scanner-pro'); ?></p>
                    <?php endif; ?>
                </div>

                <div class="msp-card" style="flex: 1;">
                    <h3><?php esc_html_e('Quick Scan', 'my-security-scanner-pro'); ?></h3>
                    <p><?php esc_html_e('Run a full audit now, without waiting for the daily scheduled scan.', 'my-security-scanner-pro'); ?></p>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=my-manual-scan')); ?>" class="msp-btn-primary"><?php esc_html_e('Launch Quick Scan', 'my-security-scanner-pro'); ?></a>
                </div>
            </div>

            <?php if (!empty($open_issues)): ?>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:30px;">
                    <h2 style="margin:0;"><?php esc_html_e('Open Issues', 'my-security-scanner-pro'); ?></h2>
                    <button id="msp-fix-headers-btn" class="msp-btn-primary"
                        onclick="return confirm('<?php echo esc_js(__('This will add the missing HTTP headers directly to the .htaccess file. Continue?', 'my-security-scanner-pro')); ?>');">
                        🔧 <?php esc_html_e('Auto-Fix Headers', 'my-security-scanner-pro'); ?>
                    </button>
                </div>
                <p class="msp-subtitle" style="margin-top:4px;"><?php esc_html_e('The list reflects the actual state as of the last check — anything fixed no longer appears here.', 'my-security-scanner-pro'); ?></p>
                <div id="msp-fix-headers-result" style="margin:12px 0;"></div>
                <table class="msp-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Category', 'my-security-scanner-pro'); ?></th>
                            <th><?php esc_html_e('Level', 'my-security-scanner-pro'); ?></th>
                            <th><?php esc_html_e('Message', 'my-security-scanner-pro'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($open_issues as $issue): ?>
                            <tr>
                                <td><?php echo esc_html($issue['category']); ?></td>
                                <td><span class="msp-badge msp-badge-<?php echo esc_attr(strtolower($issue['level'])); ?>"><?php echo esc_html($issue['level']); ?></span></td>
                                <td><?php echo esc_html($issue['msg']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <?php if (!empty($fixed_log)): ?>
                <h2 style="margin-top: 30px;"><?php esc_html_e('Fix History', 'my-security-scanner-pro'); ?></h2>
                <table class="msp-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Date', 'my-security-scanner-pro'); ?></th>
                            <th><?php esc_html_e('What was fixed', 'my-security-scanner-pro'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($fixed_log as $entry): ?>
                            <tr>
                                <td><?php echo esc_html($entry['time']); ?></td>
                                <td><span class="msp-badge msp-badge-ok"><?php esc_html_e('Fixed', 'my-security-scanner-pro'); ?></span> <?php echo esc_html($entry['label']); ?></td>
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
        <div class="msp-wrap">
            <h1 class="msp-header"><span class="dashicons dashicons-search"></span> <?php esc_html_e('Manual Scan', 'my-security-scanner-pro'); ?></h1>
            <p class="msp-subtitle"><?php esc_html_e('Run an on-demand scan without waiting for the next scheduled check.', 'my-security-scanner-pro'); ?></p>
            <?php $this->render_nav_tabs('my-manual-scan'); ?>

            <div class="msp-card">
                <p><?php esc_html_e('Select the scan type:', 'my-security-scanner-pro'); ?></p>
                <select id="msp-scan-type" style="padding: 10px; width: 340px;">
                    <option value="full"><?php esc_html_e('Full Scan (all modules)', 'my-security-scanner-pro'); ?></option>
                    <option value="backdoors"><?php esc_html_e('Backdoors & Malware Only', 'my-security-scanner-pro'); ?></option>
                    <option value="perms"><?php esc_html_e('Critical File Permissions Only', 'my-security-scanner-pro'); ?></option>
                    <option value="headers"><?php esc_html_e('HTTP Security Headers Only', 'my-security-scanner-pro'); ?></option>
                    <option value="ports"><?php esc_html_e('Exposed Ports Only', 'my-security-scanner-pro'); ?></option>
                    <option value="sqli"><?php esc_html_e('SQL Injection Risk Only (static analysis)', 'my-security-scanner-pro'); ?></option>
                    <option value="advanced"><?php esc_html_e('Dynamic SQLi + XSS (tests your own site, slower)', 'my-security-scanner-pro'); ?></option>
                </select>
                <p class="description" style="margin-top:8px; max-width:600px;">
                    <?php esc_html_e('The "Dynamic SQLi + XSS" module sends a handful of test requests to your own site (home_url), never to an external URL — it cannot be used as a scanner against other sites.', 'my-security-scanner-pro'); ?>
                </p>
                <button id="msp-start-scan" class="msp-btn-primary" style="margin-left: 10px;"><?php esc_html_e('Start Scan', 'my-security-scanner-pro'); ?></button>
            </div>

            <div id="msp-progress-area" style="display:none; margin-top: 20px;">
                <h3><?php esc_html_e('Analysis in progress...', 'my-security-scanner-pro'); ?></h3>
                <div class="msp-progress-track">
                    <div id="msp-bar" class="msp-progress-bar"></div>
                </div>
                <p id="msp-status-text" style="margin-top: 5px;"><?php esc_html_e('Initializing...', 'my-security-scanner-pro'); ?></p>
            </div>

            <div id="msp-results-area" style="margin-top: 20px;"></div>
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
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table; this page must always show the latest scan history, not a cached snapshot.
        $logs = $wpdb->get_results($wpdb->prepare('SELECT * FROM %i ORDER BY timestamp DESC LIMIT 50', $this->db_table_name));

        ?>
        <div class="msp-wrap">
            <h1 class="msp-header"><span class="dashicons dashicons-list-view"></span> <?php esc_html_e('Scan Logs', 'my-security-scanner-pro'); ?></h1>
            <p class="msp-subtitle"><?php esc_html_e('History of the last 50 scan results, most recent first.', 'my-security-scanner-pro'); ?></p>
            <?php $this->render_nav_tabs('my-scan-logs'); ?>

            <?php if ($logs): ?>
                <table class="msp-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Date', 'my-security-scanner-pro'); ?></th>
                            <th><?php esc_html_e('Type', 'my-security-scanner-pro'); ?></th>
                            <th><?php esc_html_e('Level', 'my-security-scanner-pro'); ?></th>
                            <th><?php esc_html_e('Message', 'my-security-scanner-pro'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                            <tr>
                                <td><?php echo esc_html($log->timestamp); ?></td>
                                <td><?php echo esc_html($log->scan_type); ?></td>
                                <td><span class="msp-badge msp-badge-<?php echo esc_attr(strtolower($log->result_level)); ?>"><?php echo esc_html($log->result_level); ?></span></td>
                                <td><?php echo esc_html($log->message); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="msp-card"><p><?php esc_html_e('No logs found yet.', 'my-security-scanner-pro'); ?></p></div>
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
        if (isset($_POST['msp_save_settings']) && check_admin_referer('my_security_pro_settings') && current_user_can('manage_options')) {
            update_option('my_security_pro_settings', array(
                'notify_email' => sanitize_email(wp_unslash($_POST['msp_notify_email'] ?? '')),
                'notify_on'    => !empty($_POST['msp_notify_on']),
            ));
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Settings saved.', 'my-security-scanner-pro') . '</p></div>';
        }

        $settings = wp_parse_args(get_option('my_security_pro_settings', array()), array(
            'notify_email' => get_option('admin_email'),
            'notify_on'    => false,
        ));
        ?>
        <div class="msp-wrap">
            <h1 class="msp-header"><span class="dashicons dashicons-admin-generic"></span> <?php esc_html_e('Settings', 'my-security-scanner-pro'); ?></h1>
            <p class="msp-subtitle"><?php esc_html_e('Configure notifications for the security scanner.', 'my-security-scanner-pro'); ?></p>
            <?php $this->render_nav_tabs('my-security-pro-settings'); ?>

            <div class="msp-card">
                <form method="post">
                    <?php wp_nonce_field('my_security_pro_settings'); ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><label for="msp_notify_email"><?php esc_html_e('Notification email', 'my-security-scanner-pro'); ?></label></th>
                            <td><input type="email" id="msp_notify_email" name="msp_notify_email"
                                value="<?php echo esc_attr($settings['notify_email']); ?>" class="regular-text" /></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Email alerts', 'my-security-scanner-pro'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="msp_notify_on" value="1" <?php checked($settings['notify_on']); ?> />
                                    <?php esc_html_e('Send an email when a scan finds WARNING or CRITICAL issues', 'my-security-scanner-pro'); ?>
                                </label>
                            </td>
                        </tr>
                    </table>
                    <button type="submit" name="msp_save_settings" class="msp-btn-primary"><?php esc_html_e('Save Settings', 'my-security-scanner-pro'); ?></button>
                </form>
            </div>
        </div>
        <?php
    }
}
