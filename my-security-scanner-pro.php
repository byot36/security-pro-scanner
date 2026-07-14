<?php
/**
 * Plugin Name:       My Security Pro Scanner
 * Description:       Scans for backdoors, risky file permissions, missing security headers, exposed ports, and SQL injection risk.
 * Version:           1.1.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            byot
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       my-security-scanner-pro
 *
 * @package MySecurityProScanner
 */

if (!defined('ABSPATH')) {
    exit;
}

define('MSP_VERSION', '1.1.0');
define('MSP_PATH', plugin_dir_path(__FILE__));
define('MSP_URL', plugin_dir_url(__FILE__));

require_once MSP_PATH . 'includes/class-msp-state.php';
require_once MSP_PATH . 'includes/class-msp-scanner.php';
require_once MSP_PATH . 'includes/class-msp-ajax.php';
require_once MSP_PATH . 'admin/class-msp-admin.php';

/**
 * Bootstraps the plugin: registers lifecycle hooks and wires the
 * scanner, AJAX handler, and admin UI together.
 */
class MySecurityProScanner {

    /**
     * Name of the custom table that stores raw scan history.
     *
     * @var string
     */
    private $db_table_name;

    /**
     * Registers lifecycle hooks and constructs the plugin's collaborators.
     */
    public function __construct() {
        global $wpdb;
        $this->db_table_name = $wpdb->prefix . 'my_security_pro_logs';

        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        register_uninstall_hook(__FILE__, array('MySecurityProScanner', 'uninstall'));

        $state   = new MSP_State();
        $scanner = new MSP_Scanner($state);

        new MSP_Ajax($this->db_table_name, $scanner, $state);
        new MSP_Admin($this->db_table_name, $state);
    }

    /**
     * ACTIVATION: Creates the database table
     *
     * @return void
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

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    /**
     * DEACTIVATION: Can be used to save final logs if needed
     *
     * @return void
     */
    public function deactivate() {
        // Currently empty, but the structure is ready
    }

    /**
     * UNINSTALL: Deletes the table and options when the user clicks "Delete" on the plugin
     *
     * @return void
     */
    public static function uninstall() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'my_security_pro_logs';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off uninstall check on our own custom table, caching would be pointless here.
        $found_table = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table_name));
        if ($found_table === $table_name) {
            $wpdb->query($wpdb->prepare('DROP TABLE %i', $table_name)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall routine intentionally drops our own custom table.
        }

        delete_option('my_security_pro_settings');

        if (!class_exists('MSP_State')) {
            require_once plugin_dir_path(__FILE__) . 'includes/class-msp-state.php';
        }
        MSP_State::uninstall();
    }
}

new MySecurityProScanner();
