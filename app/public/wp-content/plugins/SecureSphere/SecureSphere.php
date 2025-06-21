<?php
/*
Plugin Name: SecureSphere
Description: Advanced WordPress security monitoring and protection plugin
Version: 3.0
Author: FRENZY
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
if (!defined('SECURESPHERE_VERSION')) {
    define('SECURESPHERE_VERSION', '3.0');
}
if (!defined('SECURESPHERE_PLUGIN_DIR')) {
    define('SECURESPHERE_PLUGIN_DIR', plugin_dir_path(__FILE__));
}
if (!defined('SECURESPHERE_PLUGIN_URL')) {
    define('SECURESPHERE_PLUGIN_URL', plugin_dir_url(__FILE__));
}

// Register activation hook
register_activation_hook(__FILE__, 'securesphere_activate');

function securesphere_activate() {
    // Create database tables
    require_once SECURESPHERE_PLUGIN_DIR . 'inc/core/Database.php';
    $db = SecureSphere_Database::init();
    
    try {
        // Try to create tables
        $db->create_tables();
        
        // Set default options
        add_option('securesphere_log_retention_days', 30);
        add_option('securesphere_firewall_enabled', true);
        add_option('securesphere_scan_interval', 'daily');
        add_option('securesphere_notification_email', get_option('admin_email'));
        
        // Schedule cleanup cron
        if (!wp_next_scheduled('securesphere_daily_cleanup')) {
            wp_schedule_event(time(), 'daily', 'securesphere_daily_cleanup');
        }
        
        // Log successful activation
        error_log('SecureSphere plugin activated successfully');
        
    } catch (Exception $e) {
        // Log the error
        error_log('SecureSphere Activation Error: ' . $e->getMessage());
        
        // Clean up any partially created tables
        global $wpdb;
        $tables_to_drop = array(
            $wpdb->prefix . 'securesphere_logs',
            $wpdb->prefix . 'securesphere_firewall_logs',
            $wpdb->prefix . 'securesphere_scan_results',
            $wpdb->prefix . 'securesphere_security_events',
            $wpdb->prefix . 'securesphere_user_activity',
            $wpdb->prefix . 'securesphere_performance_metrics',
            $wpdb->prefix . 'securesphere_blocked_ips',
            $wpdb->prefix . 'securesphere_malware_signatures' // Ensure new table is also dropped on error
        );
        
        foreach ($tables_to_drop as $table) {
            $wpdb->query("DROP TABLE IF EXISTS $table");
        }
        
        // Remove any created options
        delete_option('securesphere_log_retention_days');
        delete_option('securesphere_firewall_enabled');
        delete_option('securesphere_scan_interval');
        delete_option('securesphere_notification_email');
        
        // Deactivate the plugin
        deactivate_plugins(plugin_basename(__FILE__));
        
        // Show error message
        wp_die(
            'Failed to activate SecureSphere plugin. Error: ' . $e->getMessage() . 
            '<br>Please check your database permissions and try again.',
            'Plugin Activation Error',
            array('back_link' => true)
        );
    }
}

// Error handling function
function securesphere_handle_error($message, $fatal = false) {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('SecureSphere Error: ' . $message);
    }
    if ($fatal) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die('SecureSphere Error: ' . $message);
    }
}

// Initialize plugin
class SecureSphere {
    private static $instance = null;
    private $version = '3.0';
    private $modules = array();
    private $db;
    private $logger;
    private $config;
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->load_dependencies();
        $this->init_hooks();
    }
    
    private function load_dependencies() {
        try {
            // Core modules
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/core/Config.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/core/Database.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/core/Logger.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/core/Logs.php';
            
            // Initialize core modules
            $this->db = SecureSphere_Database::init();
            $this->logger = SecureSphere_Logger::init();
            $this->config = SecureSphere_Config::init();
            
            // Load feature modules
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/Dashboard.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/Alerts.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/Integrity.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/LiveTraffic.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/UploadScanner.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/RestApiSecurity.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/Backup.php';
            
            // Firewall module
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/firewall/Firewall.php';
            
            // Scanner module
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/scanner/MalwareScanner.php';
            
            // Auth modules - load but don't initialize
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/auth/LoginSecurity.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/auth/PasswordPolicy.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/auth/Captcha.php';
            require_once SECURESPHERE_PLUGIN_DIR . 'inc/auth/TwoFactor.php';
        } catch (Exception $e) {
            error_log('SecureSphere Error: Failed to load dependencies - ' . $e->getMessage());
            // Don't deactivate the plugin, just log the error
        }
    }
    
    private function init_hooks() {
        try {
            // Initialize modules first
            $this->init_modules();
            
            // Only add admin hooks if we're in the admin area
            if (is_admin()) {
                // Register admin menu
                add_action('admin_menu', array($this, 'add_admin_menu'));
                
                // Other admin hooks
                add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
                add_action('admin_init', array($this, 'register_settings'));
                add_filter('admin_body_class', array($this, 'add_admin_body_class'));
                add_action('admin_footer', array($this, 'render_welcome_modal'));
                add_action('wp_ajax_securesphere_dismiss_welcome', array($this, 'handle_dismiss_welcome'));
                add_action('wp_ajax_securesphere_toggle_firewall', array($this, 'handle_toggle_firewall'));
                add_action('wp_ajax_securesphere_unblock_ip', array($this, 'handle_unblock_ip'));
            }
            
            // Schedule cleanup tasks
            add_action('securesphere_daily_cleanup', array($this->db, 'cleanup_old_logs'));
            
            // Only add firewall cleanup if the module exists
            if (isset($this->modules['firewall']) && $this->modules['firewall']) {
                add_action('securesphere_daily_cleanup', array($this->modules['firewall'], 'cleanup_expired_blocks'));
            }
        } catch (Exception $e) {
            error_log('SecureSphere Error: Failed to initialize hooks - ' . $e->getMessage());
            // Don't deactivate the plugin, just log the error
        }
    }
    
    public function init_modules() {
        try {
            // Initialize core modules first
            $logs = SecureSphere_Logs::init();
            
            // Initialize feature modules
            $this->modules = array(
                'dashboard' => SecureSphere_Dashboard::init(),
                'firewall' => SecureSphere_Firewall::init(),
                'logs' => $logs,
                'alerts' => SecureSphere_Alerts::init(),
                'integrity' => SecureSphere_Integrity::init(),
                'scanner' => SecureSphere_MalwareScanner::init(),
                'login_security' => null, // Don't initialize login security during plugin load
                'live_traffic' => SecureSphere_LiveTraffic::init(),
                'api_security' => SecureSphere_RestApiSecurity::init(),
                'upload_scanner' => SecureSphere_UploadScanner::init(),
                'backup' => SecureSphere_Backup::init()
            );

            // Initialize login security only after successful login
            add_action('wp_login', function($user_login, $user) {
                if (!isset($this->modules['login_security'])) {
                    $this->modules['login_security'] = SecureSphere_LoginSecurity::init();
                }
            }, 10, 2);

            // Add admin menu items
            add_action('admin_menu', array($this, 'add_admin_menu'));

        } catch (Exception $e) {
            error_log('SecureSphere Error: Failed to initialize modules - ' . $e->getMessage());
            // Don't deactivate the plugin, just log the error
        }
    }
    
    public function enqueue_admin_assets($hook) {
        if (strpos($hook, 'securesphere') === false) {
            return;
        }

        // Enqueue Google Fonts
        wp_enqueue_style(
            'securesphere-fonts',
            'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto+Mono&display=swap',
            array(),
            null
        );

        // Enqueue Chart.js
        wp_enqueue_script(
            'chartjs',
            'https://cdn.jsdelivr.net/npm/chart.js',
            array(),
            '3.7.0',
            true
        );

        // Enqueue our assets
        wp_enqueue_style(
            'securesphere-admin',
            SECURESPHERE_PLUGIN_URL . 'assets/css/securesphere-theme.css',
            array(),
            SECURESPHERE_VERSION
        );

        wp_enqueue_script(
            'securesphere-admin',
            SECURESPHERE_PLUGIN_URL . 'assets/js/securesphere-ui.js',
            array('jquery', 'chartjs'),
            SECURESPHERE_VERSION,
            true
        );

        // Add inline script for initial data
        wp_add_inline_script('securesphere-admin', '
            window.SecureSphereData = {
                nonce: "' . wp_create_nonce('securesphere-nonce') . '",
                ajaxurl: "' . admin_url('admin-ajax.php') . '",
                resturl: "' . rest_url('securesphere/v1/') . '"
            };
        ');
    }
    
    public function add_admin_body_class($classes) {
        return $classes . ' securesphere-admin';
    }
    
    public function add_admin_menu() {
        // Add main menu
        add_menu_page(
            'SecureSphere',
            'SecureSphere',
            'manage_options',
            'securesphere',
            array($this->modules['dashboard'], 'render_admin_page'),
            'dashicons-shield',
            30
        );

        // Dashboard
        add_submenu_page(
            'securesphere',
            'Dashboard',
            'Dashboard',
            'manage_options',
            'securesphere',
            array($this->modules['dashboard'], 'render_admin_page')
        );

        // Firewall
        if (isset($this->modules['firewall'])) {
            add_submenu_page(
                'securesphere',
                'Firewall',
                'Firewall',
                'manage_options',
                'securesphere-firewall',
                array($this->modules['firewall'], 'render_admin_page')
            );
        }

        // Logs
        if (isset($this->modules['logs'])) {
            add_submenu_page(
                'securesphere',
                'Logs',
                'Logs',
                'manage_options',
                'securesphere-logs',
                array($this->modules['logs'], 'render_admin_page')
            );
        }

        // Scanner
        if (isset($this->modules['scanner'])) {
            add_submenu_page(
                'securesphere',
                'Malware Scanner',
                'Malware Scanner',
                'manage_options',
                'securesphere-scanner',
                array($this->modules['scanner'], 'render_admin_page')
            );
        }

        // Live Traffic
        if (isset($this->modules['live_traffic'])) {
            add_submenu_page(
                'securesphere',
                'Live Traffic',
                'Live Traffic',
                'manage_options',
                'securesphere-live-traffic',
                array($this->modules['live_traffic'], 'render_admin_page')
            );
        }

        // Alerts
        if (isset($this->modules['alerts'])) {
            $this->modules['alerts']->add_alerts_admin_menu();
        }

        // Integrity
        if (isset($this->modules['integrity'])) {
            $this->modules['integrity']->add_integrity_admin_menu();
        }

        // Backup
        if (isset($this->modules['backup'])) {
            add_submenu_page(
                'securesphere',
                'Backups',
                'Backups',
                'manage_options',
                'securesphere-backups',
                array($this->modules['backup'], 'render_admin_page')
            );
        }

        // Login Security
        if (isset($this->modules['login_security'])) {
            add_submenu_page(
                'securesphere',
                'Login Security',
                'Login Security',
                'manage_options',
                'securesphere-login-security',
                array($this->modules['login_security'], 'render_admin_page')
            );
        }

        // API Security
        if (isset($this->modules['api_security'])) {
            add_submenu_page(
                'securesphere',
                'API Security',
                'API Security',
                'manage_options',
                'securesphere-api-security',
                array($this->modules['api_security'], 'render_admin_page')
            );
        }

        // Settings
        add_submenu_page(
            'securesphere',
            'Settings',
            'Settings',
            'manage_options',
            'securesphere-settings',
            array($this, 'render_settings_page')
        );
    }
    
    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        // For the dashboard page, render it directly
        if (isset($this->modules['dashboard'])) {
            $this->modules['dashboard']->render_admin_page();
            return;
        }

        // If we get here, something went wrong
        wp_die(__('Module not found or not properly initialized.'));
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }
        
        require_once SECURESPHERE_PLUGIN_DIR . 'inc/admin/settings.php';
    }

    public function render_welcome_modal() {
        // Only show on SecureSphere pages
        $screen = get_current_screen();
        if (strpos($screen->id, 'securesphere') === false) {
            return;
        }

        // Check if modal has been dismissed
        if (get_user_meta(get_current_user_id(), 'securesphere_welcome_dismissed', true)) {
            return;
        }
        ?>
        <div id="securesphere-welcome-modal" class="ss-modal">
            <div class="ss-modal-content">
                <div class="ss-modal-header">
                    <h2>Welcome to SecureSphere</h2>
                    <button class="ss-modal-close" onclick="dismissWelcomeModal()">
                        <span class="dashicons dashicons-no-alt"></span>
                    </button>
                </div>
                <div class="ss-modal-body">
                    <div class="ss-welcome-icon">
                        <span class="dashicons dashicons-shield"></span>
                    </div>
                    <p class="ss-welcome-message">
                        Thank you for choosing SecureSphere for your WordPress security needs.
                    </p>
                    <div class="ss-welcome-features">
                        <div class="ss-feature">
                            <span class="dashicons dashicons-lock"></span>
                            <span>Advanced Firewall Protection</span>
                        </div>
                        <div class="ss-feature">
                            <span class="dashicons dashicons-search"></span>
                            <span>Real-time Malware Scanning</span>
                        </div>
                        <div class="ss-feature">
                            <span class="dashicons dashicons-chart-line"></span>
                            <span>Live Traffic Monitoring</span>
                        </div>
                    </div>
                </div>
                <div class="ss-modal-footer">
                    <button class="ss-button ss-button-primary" onclick="dismissWelcomeModal()">
                        Get Started
                    </button>
                </div>
            </div>
        </div>

        <script>
        function dismissWelcomeModal() {
            jQuery.post(ajaxurl, {
                action: 'securesphere_dismiss_welcome',
                nonce: '<?php echo wp_create_nonce('securesphere_dismiss_welcome'); ?>'
            }, function() {
                jQuery('#securesphere-welcome-modal').fadeOut();
            });
        }
        </script>
        <?php
    }

    public function handle_dismiss_welcome() {
        check_ajax_referer('securesphere_dismiss_welcome', 'nonce');
        update_user_meta(get_current_user_id(), 'securesphere_welcome_dismissed', true);
        wp_send_json_success();
    }

    public function handle_toggle_firewall() {
        check_ajax_referer('securesphere_toggle_firewall', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        $enabled = isset($_POST['enabled']) ? (bool) $_POST['enabled'] : false;
        update_option('securesphere_firewall_enabled', $enabled);
        wp_send_json_success();
    }

    public function handle_unblock_ip() {
        check_ajax_referer('securesphere_unblock_ip', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        $ip = isset($_POST['ip']) ? sanitize_text_field($_POST['ip']) : '';
        if (empty($ip)) {
            wp_send_json_error('Invalid IP address');
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_blocked_ips';
        
        // Use direct query with proper escaping
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM `{$table_name}` WHERE `ip` = %s",
                $ip
            )
        );

        wp_send_json_success();
    }

    public function register_settings() {
        // Register general settings
        register_setting('securesphere_general', 'securesphere_log_retention_days');
        register_setting('securesphere_general', 'securesphere_firewall_enabled');
        register_setting('securesphere_general', 'securesphere_scan_interval');
        register_setting('securesphere_general', 'securesphere_notification_email');
        
        // Register security settings
        register_setting('securesphere_security', 'securesphere_enable_2fa');
        register_setting('securesphere_security', 'securesphere_enable_captcha');
        register_setting('securesphere_security', 'securesphere_session_timeout');
        
        // Register notification settings
        register_setting('securesphere_notifications', 'securesphere_email_notifications');
        register_setting('securesphere_notifications', 'securesphere_notification_events');
        
        // Register backup settings
        register_setting('securesphere_backup', 'securesphere_backup_frequency');
        register_setting('securesphere_backup', 'securesphere_backup_retention');
        register_setting('securesphere_backup', 'securesphere_backup_storage');
    }
}

// Initialize the plugin
SecureSphere::init();

function admin_enqueue_scripts($hook) {
    if (strpos($hook, 'securesphere') === false) {
        return;
    }

    wp_enqueue_style('securesphere-admin', plugins_url('assets/css/securesphere-theme.css', __FILE__), array(), SECURESPHERE_VERSION);
    wp_enqueue_script('securesphere-admin', plugins_url('assets/js/admin.js', __FILE__), array('jquery'), SECURESPHERE_VERSION, true);
}
add_action('admin_enqueue_scripts', 'admin_enqueue_scripts');