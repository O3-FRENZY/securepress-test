<?php
if (!defined('ABSPATH')) {
    exit;
}

// Integrity module for SecureSphere
class SecureSphere_Integrity {

    const OPT_BASELINE = 'securesphere_fim_baseline';
    const OPT_LAST_SCAN_RESULTS = 'securesphere_fim_last_scan_results';
    const OPT_LAST_SCAN_TIME = 'securesphere_fim_last_scan_time';
    const OPT_SETTINGS_ENABLED = 'securesphere_fim_enabled';
    const OPT_SETTINGS_FREQUENCY = 'securesphere_fim_frequency';
    const OPT_SETTINGS_MONITOR_CORE = 'securesphere_fim_monitor_core';
    const OPT_SETTINGS_MONITOR_PLUGINS = 'securesphere_fim_monitor_plugins';
    const OPT_SETTINGS_MONITOR_THEMES = 'securesphere_fim_monitor_themes';
    const OPT_SETTINGS_MONITOR_UPLOADS = 'securesphere_fim_monitor_uploads';
    const OPT_SETTINGS_REALTIME_CHECKS = 'securesphere_fim_realtime_checks_enabled'; // New option

    private static $default_settings = [
        self::OPT_SETTINGS_ENABLED => true, // For scheduled scans
        self::OPT_SETTINGS_FREQUENCY => 'daily',
        self::OPT_SETTINGS_MONITOR_CORE => true,
        self::OPT_SETTINGS_MONITOR_PLUGINS => true,
        self::OPT_SETTINGS_MONITOR_THEMES => true,
        self::OPT_SETTINGS_MONITOR_UPLOADS => false,
        self::OPT_SETTINGS_REALTIME_CHECKS => true, // Default to enabled for action-triggered checks
    ];

    private static $instance = null;
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        add_action('admin_init', array($this, 'init_settings'));
        self::load_hooks_and_schedule();

        // Admin actions
        add_action('admin_post_securesphere_fim_generate_baseline', [__CLASS__, 'handle_manual_baseline_generation']);
        add_action('admin_post_securesphere_fim_run_scan', [__CLASS__, 'handle_manual_scan']);
        add_action('admin_post_securesphere_fim_secure_permissions', [__CLASS__, 'handle_secure_permissions']); // New action
        // add_action('admin_post_securesphere_fim_accept_changes', [__CLASS__, 'handle_accept_changes']); // For later
    }
    
    public function init_settings() {
        register_setting('securesphere_integrity_settings', 'securesphere_integrity_enabled');
        register_setting('securesphere_integrity_settings', 'securesphere_integrity_schedule');
    }

    private static function load_hooks_and_schedule() {
        $settings = self::get_settings();
        if ($settings[self::OPT_SETTINGS_ENABLED]) {
            if (!wp_next_scheduled('securesphere_integrity_check_hook')) {
                wp_schedule_event(time(), $settings[self::OPT_SETTINGS_FREQUENCY], 'securesphere_integrity_check_hook');
            }
            add_action('securesphere_integrity_check_hook', [__CLASS__, 'perform_integrity_check']);
        } else {
            if (wp_next_scheduled('securesphere_integrity_check_hook')) {
                wp_clear_scheduled_hook('securesphere_integrity_check_hook');
            }
        }

        if ($settings[self::OPT_SETTINGS_REALTIME_CHECKS]) {
            // Hooks for near real-time checks on specific actions
            // These hooks run after the action has completed.
            add_action('upgrader_process_complete', [__CLASS__, 'perform_integrity_check_on_action_wrapper'], 20, 2); // Covers plugin/theme/core updates
            add_action('activated_plugin', [__CLASS__, 'perform_integrity_check_on_action_wrapper_single_arg'], 20, 1);
            add_action('deactivated_plugin', [__CLASS__, 'perform_integrity_check_on_action_wrapper_single_arg'], 20, 1);
            add_action('switch_theme', [__CLASS__, 'perform_integrity_check_on_action_wrapper_single_arg'], 20, 1);
            // Note: 'wp_handle_upload' could also trigger a specific scan on the uploads dir if FIM for uploads is enabled.
            // However, MalwareScanner already hooks into uploads. FIM on uploads is better as a scheduled task due to frequency.
        }
        add_action('admin_menu', [__CLASS__, 'add_integrity_admin_menu']);
    }

    /**
     * Wrapper for hooks with two arguments like upgrader_process_complete.
     */
    public static function perform_integrity_check_on_action_wrapper($upgrader_object, $options) {
        // Check if it's a plugin/theme/core install/update
        if (isset($options['action']) && in_array($options['action'], ['install', 'update']) &&
            isset($options['type']) && in_array($options['type'], ['plugin', 'theme', 'core'])) {
            self::perform_integrity_check();
        }
    }
    
    /**
     * Wrapper for hooks with a single argument.
     */
    public static function perform_integrity_check_on_action_wrapper_single_arg($arg1 = null) {
        self::perform_integrity_check();
    }
    
    public static function get_settings() {
        $settings = [];
        foreach (self::$default_settings as $key => $default_value) {
            $settings[$key] = get_option($key, $default_value);
        }
        return $settings;
    }

    private static function hash_directory_files($path, $strip_prefix = ABSPATH) {
        $hashes = [];
        if (!is_dir($path)) return $hashes;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $file_path = $file->getRealPath();
                // Normalize path and make relative
                $relative_path = str_replace(wp_normalize_path($strip_prefix), '', wp_normalize_path($file_path));
                $relative_path = ltrim($relative_path, '/\\');
                
                // Exclude our own plugin's log/cache if it were inside a scanned dir (not typical for FIM targets)
                // if (strpos($file_path, plugin_dir_path(__DIR__)) !== false) continue;

                $hashes[$relative_path] = md5_file($file_path);
            }
        }
        ksort($hashes);
        return $hashes;
    }

    public static function generate_baseline_data() {
        $settings = self::get_settings();
        $baseline_hashes = [];

        if ($settings[self::OPT_SETTINGS_MONITOR_CORE]) {
            // A more robust way would be to fetch checksums from WordPress API for core files
            // For now, we scan wp-admin, wp-includes, and root files
            $baseline_hashes = array_merge($baseline_hashes, self::hash_directory_files(ABSPATH . 'wp-admin/'));
            $baseline_hashes = array_merge($baseline_hashes, self::hash_directory_files(ABSPATH . 'wp-includes/'));
            // Root files (php)
            $root_files = glob(ABSPATH . '*.php');
            foreach ($root_files as $file) {
                 $relative_path = str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($file));
                 $baseline_hashes[ltrim($relative_path, '/\\')] = md5_file($file);
            }
        }
        if ($settings[self::OPT_SETTINGS_MONITOR_PLUGINS]) {
            $baseline_hashes = array_merge($baseline_hashes, self::hash_directory_files(WP_PLUGIN_DIR));
        }
        if ($settings[self::OPT_SETTINGS_MONITOR_THEMES]) {
            $baseline_hashes = array_merge($baseline_hashes, self::hash_directory_files(get_theme_root()));
        }
        if ($settings[self::OPT_SETTINGS_MONITOR_UPLOADS]) {
            $uploads_dir = wp_upload_dir();
            $baseline_hashes = array_merge($baseline_hashes, self::hash_directory_files($uploads_dir['basedir']));
        }
        
        ksort($baseline_hashes);
        update_option(self::OPT_BASELINE, $baseline_hashes);
        update_option(self::OPT_LAST_SCAN_TIME, current_time('mysql') . ' (Baseline Generated)');
        delete_option(self::OPT_LAST_SCAN_RESULTS); // Clear old results
        return count($baseline_hashes);
    }

    public static function perform_integrity_check() {
        $baseline = get_option(self::OPT_BASELINE, []);
        if (empty($baseline)) {
            update_option(self::OPT_LAST_SCAN_RESULTS, ['error' => 'Baseline not generated. Please generate a baseline first.']);
            update_option(self::OPT_LAST_SCAN_TIME, current_time('mysql'));
            return;
        }

        $settings = self::get_settings();
        $current_hashes = [];

        if ($settings[self::OPT_SETTINGS_MONITOR_CORE]) {
            $current_hashes = array_merge($current_hashes, self::hash_directory_files(ABSPATH . 'wp-admin/'));
            $current_hashes = array_merge($current_hashes, self::hash_directory_files(ABSPATH . 'wp-includes/'));
            $root_files = glob(ABSPATH . '*.php');
            foreach ($root_files as $file) {
                 $relative_path = str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($file));
                 $current_hashes[ltrim($relative_path, '/\\')] = md5_file($file);
            }
        }
        if ($settings[self::OPT_SETTINGS_MONITOR_PLUGINS]) {
            $current_hashes = array_merge($current_hashes, self::hash_directory_files(WP_PLUGIN_DIR));
        }
        if ($settings[self::OPT_SETTINGS_MONITOR_THEMES]) {
            $current_hashes = array_merge($current_hashes, self::hash_directory_files(get_theme_root()));
        }
        if ($settings[self::OPT_SETTINGS_MONITOR_UPLOADS]) {
            $uploads_dir = wp_upload_dir();
            $current_hashes = array_merge($current_hashes, self::hash_directory_files($uploads_dir['basedir']));
        }
        ksort($current_hashes);

        $results = [
            'modified' => [],
            'added' => [],
            'deleted' => [],
            'summary' => ''
        ];

        // Check for modified and deleted files
        foreach ($baseline as $file => $hash) {
            if (!isset($current_hashes[$file])) {
                $results['deleted'][] = $file;
            } elseif ($current_hashes[$file] !== $hash) {
                $results['modified'][] = $file;
            }
        }

        // Check for added files
        foreach ($current_hashes as $file => $hash) {
            if (!isset($baseline[$file])) {
                $results['added'][] = $file;
            }
        }
        
        $total_issues = count($results['modified']) + count($results['added']) + count($results['deleted']);
        if ($total_issues > 0) {
            $results['summary'] = sprintf('%d issue(s) found: %d modified, %d added, %d deleted.',
                $total_issues, count($results['modified']), count($results['added']), count($results['deleted']));
            do_action('securesphere_integrity_issue_detected', $results);
        } else {
            $results['summary'] = 'No integrity issues found.';
        }

        update_option(self::OPT_LAST_SCAN_RESULTS, $results);
        update_option(self::OPT_LAST_SCAN_TIME, current_time('mysql'));
    }
    
    public static function handle_manual_baseline_generation() {
        if (!current_user_can('manage_options')) wp_die('Permission denied.');
        check_admin_referer('securesphere_fim_generate_baseline_nonce', '_wpnonce_fim_baseline');
        $count = self::generate_baseline_data();
        wp_redirect(admin_url('admin.php?page=securesphere-integrity&message=baseline_generated&count=' . $count));
        exit;
    }

    public static function handle_manual_scan() {
        if (!current_user_can('manage_options')) wp_die('Permission denied.');
        check_admin_referer('securesphere_fim_run_scan_nonce', '_wpnonce_fim_scan');
        self::perform_integrity_check();
        wp_redirect(admin_url('admin.php?page=securesphere-integrity&message=scan_completed'));
        exit;
    }

    public static function handle_secure_permissions() {
        if (!current_user_can('manage_options')) wp_die('Permission denied.');
        check_admin_referer('securesphere_fim_secure_permissions_nonce', '_wpnonce_fim_secure_perms');

        $results = ['success' => [], 'fail' => []];
        $targets = [
            // File: path => recommended_octal_perm
            ABSPATH . 'wp-config.php' => 0600,
            ABSPATH . '.htaccess' => 0644,
            // Directory: path => recommended_octal_perm
            ABSPATH => 0755,
            ABSPATH . 'wp-admin' => 0755,
            ABSPATH . 'wp-includes' => 0755,
            WP_CONTENT_DIR => 0755,
            WP_PLUGIN_DIR => 0755,
            get_theme_root() => 0755,
            wp_upload_dir()['basedir'] => 0755,
        ];
        
        // Secure root PHP files
        $root_php_files = glob(ABSPATH . '*.php');
        if ($root_php_files) {
            foreach ($root_php_files as $file) {
                if (basename($file) !== 'wp-config.php') { // wp-config handled above
                    $targets[$file] = 0644;
                }
            }
        }
        // Add index.php in common dirs if they exist
        $index_files_to_check = [
            WP_CONTENT_DIR . '/index.php',
            WP_PLUGIN_DIR . '/index.php',
            get_theme_root() . '/index.php',
        ];
        foreach($index_files_to_check as $index_file){
            if (file_exists($index_file)) $targets[$index_file] = 0644;
        }


        foreach ($targets as $path => $perm) {
            $path = wp_normalize_path($path);
            if (file_exists($path)) {
                clearstatcache(true, $path);
                $current_perms_octal = substr(sprintf('%o', fileperms($path)), -4);
                $target_perm_str = sprintf('%04o', $perm); // Ensure it's 4 digits for comparison

                if ($current_perms_octal !== $target_perm_str) {
                    if (@chmod($path, $perm)) {
                        $results['success'][] = "Set " . esc_html(str_replace(ABSPATH, '', $path)) . " to " . $target_perm_str;
                    } else {
                        $results['fail'][] = "Failed to set " . esc_html(str_replace(ABSPATH, '', $path)) . " to " . $target_perm_str . " (current: $current_perms_octal). Check file ownership/permissions.";
                    }
                } else {
                     $results['success'][] = esc_html(str_replace(ABSPATH, '', $path)) . " already has recommended permissions ($current_perms_octal).";
                }
            }
        }
        set_transient('securesphere_fim_perm_results', $results, 60);
        wp_redirect(admin_url('admin.php?page=securesphere-integrity&message=perms_attempted'));
        exit;
    }

    public static function add_integrity_admin_menu() {
        add_submenu_page(
            'securesphere',
            'File Integrity Monitoring',
            'File Integrity',
            'manage_options',
            'securesphere-integrity',
            array(self::init(), 'render_admin_page')
        );
    }

    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        // Get the latest scan results
        $last_scan_results = get_option(self::OPT_LAST_SCAN_RESULTS, array());
        $last_scan_time = get_option(self::OPT_LAST_SCAN_TIME, 'Never');
        $settings = self::get_settings();
        $baseline_exists = !empty(get_option(self::OPT_BASELINE, []));
        
        // Get permission results if available
        $perm_results = get_transient('securesphere_fim_perm_results');
        if ($perm_results === false) {
            $perm_results = null;
        }

        include SECURESPHERE_PLUGIN_DIR . 'inc/admin/integrity.php';
    }
}