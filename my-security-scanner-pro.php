<?php
/**
 * Plugin Name: My Security Pro Scanner
 * Description: A security scanner for WordPress that catches what most sites miss — backdoors, risky file permissions, and exposed REST API data — then gives you a clear dashboard and scan history to act on.
 * Version: 1.0 Professional
 * Author: byot
 * Text Domain: my-security-pro
 */

if (!defined('ABSPATH')) {
    exit;
}

define('MSP_VERSION', '1.0.0');
define('MSP_PATH', plugin_dir_path(__FILE__));
define('MSP_URL', plugin_dir_url(__FILE__));

require_once MSP_PATH . 'includes/class-msp-state.php';
require_once MSP_PATH . 'includes/class-msp-scanner.php';
require_once MSP_PATH . 'includes/class-msp-ajax.php';
require_once MSP_PATH . 'admin/class-msp-admin.php';

class MySecurityProScanner {

    private $db_table_name;

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
     */
    public function deactivate() {
        // Currently empty, but the structure is ready
    }

    /**
     * UNINSTALL: Deletes the table and options when the user clicks "Delete" on the plugin
     */
    public static function uninstall() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'my_security_pro_logs';

        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
            $wpdb->query("DROP TABLE {$table_name}");
        }

        delete_option('my_security_pro_settings');

        if (!class_exists('MSP_State')) {
            require_once plugin_dir_path(__FILE__) . 'includes/class-msp-state.php';
        }
        MSP_State::uninstall();
    }
}

new MySecurityProScanner();
