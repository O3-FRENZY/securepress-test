<?php
if (!defined('ABSPATH')) {
    exit;
}

// Alerts module for SecureSphere
class SecureSphere_Alerts {

    const OPT_ALERTS_ENABLED = 'securesphere_alerts_enabled';
    const OPT_ALERT_RECIPIENT_EMAIL = 'securesphere_alerts_email';
    const OPT_ALERT_ON_MALWARE = 'securesphere_alerts_notification_types';
    const OPT_ALERT_ON_FIM_CHANGE = 'securesphere_alert_on_fim_change';
    const OPT_ALERT_ON_CRITICAL_FIREWALL = 'securesphere_alert_on_critical_firewall'; // e.g. Rate limit, specific rule
    const OPT_ALERT_ON_ADMIN_LOGIN = 'securesphere_alert_on_admin_login';
    const OPT_ADMIN_KNOWN_IPS = 'securesphere_admin_known_ips'; // Stores [username => [ip1, ip2]]

    private static $default_settings = [
        self::OPT_ALERTS_ENABLED => true,
        self::OPT_ALERT_RECIPIENT_EMAIL => '', // Must be set by admin
        self::OPT_ALERT_ON_MALWARE => true,
        self::OPT_ALERT_ON_FIM_CHANGE => true,
        self::OPT_ALERT_ON_CRITICAL_FIREWALL => true,
        self::OPT_ALERT_ON_ADMIN_LOGIN => true,
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
        add_action('admin_menu', [__CLASS__, 'add_alerts_admin_menu']);
    }
    
    public function init_settings() {
        register_setting('securesphere_alerts_settings', 'securesphere_alerts_enabled');
        register_setting('securesphere_alerts_settings', 'securesphere_alerts_email');
        register_setting('securesphere_alerts_settings', 'securesphere_alerts_notification_types');
    }

    public static function get_settings() {
        $settings = [];
        foreach (self::$default_settings as $key => $default_value) {
            $settings[$key] = get_option($key, $default_value);
        }
        if (empty($settings[self::OPT_ALERT_RECIPIENT_EMAIL])) {
             $settings[self::OPT_ALERT_RECIPIENT_EMAIL] = get_option('admin_email'); // Default to admin email if not set
        }
        return $settings;
    }

    private static function send_email_alert($subject, $message_body, $event_type = 'general') {
        $settings = self::get_settings();
        if (!$settings[self::OPT_ALERTS_ENABLED] || empty($settings[self::OPT_ALERT_RECIPIENT_EMAIL])) {
            return false;
        }

        $to = $settings[self::OPT_ALERT_RECIPIENT_EMAIL];
        $headers = ['Content-Type: text/html; charset=UTF-8'];
        $full_subject = '[SecureSphere Alert: ' . get_bloginfo('name') . '] ' . $subject;

        $styled_message = "<html><body>";
        $styled_message .= "<h2>SecureSphere Alert</h2>";
        $styled_message .= "<p><strong>Site:</strong> " . esc_html(get_bloginfo('name')) . " (" . esc_url(home_url()) . ")</p>";
        $styled_message .= "<p><strong>Event Type:</strong> " . esc_html(ucfirst(str_replace('_', ' ', $event_type))) . "</p>";
        $styled_message .= "<hr/>";
        $styled_message .= $message_body; // Assuming $message_body is already HTML or pre-formatted
        $styled_message .= "<hr/>";
        $styled_message .= "<p><small>This is an automated alert from the SecureSphere plugin.</small></p>";
        $styled_message .= "</body></html>";

        return wp_mail($to, $full_subject, $styled_message, $headers);
    }

    public static function handle_malware_alert($scan_results) {
        $subject = 'Malware Detected on Your Website';
        $message_body = '<h3>Malware Scan Results:</h3>';
        $message_body .= '<p>The following issues were detected during a malware scan:</p>';
        $message_body .= '<table border="1" cellpadding="5" cellspacing="0" style="width:100%; border-collapse: collapse;">';
        $message_body .= '<thead><tr><th>File</th><th>Type</th><th>Severity</th><th>Details</th></tr></thead><tbody>';
        foreach ($scan_results as $result) {
            $message_body .= '<tr>';
            $message_body .= '<td>' . esc_html($result['file']) . '</td>';
            $message_body .= '<td>' . esc_html($result['type']) . '</td>';
            $message_body .= '<td>' . esc_html(ucfirst($result['severity'])) . '</td>';
            $message_body .= '<td>' . esc_html($result['details']) . '</td>';
            $message_body .= '</tr>';
        }
        $message_body .= '</tbody></table>';
        $message_body .= '<p>Please review these findings in your SecureSphere dashboard immediately.</p>';
        self::send_email_alert($subject, $message_body, 'malware_detection');
    }

    public static function handle_fim_alert($issues) {
        $subject = 'File Integrity Changes Detected';
        $message_body = '<h3>File Integrity Monitoring Alert:</h3>';
        $message_body .= '<p>The following file changes were detected:</p>';
        if (!empty($issues['summary'])) {
            $message_body .= '<p><strong>Summary: ' . esc_html($issues['summary']) . '</strong></p>';
        }
        
        $issue_types = ['modified' => 'Modified Files', 'added' => 'Added Files', 'deleted' => 'Deleted Files'];
        foreach ($issue_types as $type => $label) {
            if (!empty($issues[$type])) {
                $message_body .= '<h4>' . esc_html($label) . ':</h4><ul>';
                foreach ($issues[$type] as $file) {
                    $message_body .= '<li>' . esc_html($file) . '</li>';
                }
                $message_body .= '</ul>';
            }
        }
        $message_body .= '<p>Please review these changes in your SecureSphere dashboard.</p>';
        self::send_email_alert($subject, $message_body, 'file_integrity_monitoring');
    }

    public static function handle_firewall_alert($log_entry) {
        // $log_entry should be an array like: ['time', 'ip', 'user_agent', 'reason', 'url']
        $subject = 'Critical Firewall Event Triggered';
        $message_body = '<h3>Firewall Alert:</h3>';
        $message_body .= '<p>A critical firewall event was triggered:</p>';
        $message_body .= '<ul>';
        $message_body .= '<li><strong>Time:</strong> ' . esc_html($log_entry['time']) . '</li>';
        $message_body .= '<li><strong>IP Address:</strong> ' . esc_html($log_entry['ip']) . '</li>';
        $message_body .= '<li><strong>Reason:</strong> ' . esc_html($log_entry['reason']) . '</li>';
        if (!empty($log_entry['url'])) {
            $message_body .= '<li><strong>Requested URL:</strong> ' . esc_html($log_entry['url']) . '</li>';
        }
        if (!empty($log_entry['user_agent'])) {
            $message_body .= '<li><strong>User Agent:</strong> ' . esc_html($log_entry['user_agent']) . '</li>';
        }
        $message_body .= '</ul>';
        $message_body .= '<p>This IP may have been blocked or rate-limited. Check the firewall logs for more details.</p>';
        self::send_email_alert($subject, $message_body, 'firewall_critical_block');
    }

    public static function handle_admin_login_alert($user_login, $user) {
        if (!user_can($user, 'manage_options')) { // Only for administrators or equivalent
            return;
        }

        $current_ip = sanitize_text_field($_SERVER['REMOTE_ADDR']);
        $known_ips_data = get_option(self::OPT_ADMIN_KNOWN_IPS, []);
        
        $user_known_ips = isset($known_ips_data[$user_login]) ? (array)$known_ips_data[$user_login] : [];

        if (!in_array($current_ip, $user_known_ips)) {
            $subject = 'Admin Login from New IP Address';
            $message_body = '<h3>Admin Login Alert:</h3>';
            $message_body .= '<p>An administrator account has logged in from a new IP address:</p>';
            $message_body .= '<ul>';
            $message_body .= '<li><strong>Username:</strong> ' . esc_html($user_login) . '</li>';
            $message_body .= '<li><strong>IP Address:</strong> ' . esc_html($current_ip) . '</li>';
            $message_body .= '<li><strong>Time:</strong> ' . esc_html(current_time('mysql')) . '</li>';
            $message_body .= '<li><strong>User Agent:</strong> ' . esc_html($_SERVER['HTTP_USER_AGENT'] ?? 'N/A') . '</li>';
            $message_body .= '</ul>';
            $message_body .= '<p>If this was not you, please secure your account immediately.</p>';
            
            self::send_email_alert($subject, $message_body, 'admin_login_new_ip');

            // Add current IP to known IPs for this user
            if (!in_array($current_ip, $user_known_ips)) {
                $user_known_ips[] = $current_ip;
                $known_ips_data[$user_login] = array_unique($user_known_ips);
                update_option(self::OPT_ADMIN_KNOWN_IPS, $known_ips_data);
            }
        }
    }
    
    public static function add_alerts_admin_menu() {
        add_submenu_page(
            'securesphere',
            'Alert Settings',
            'Alerts',
            'manage_options',
            'securesphere-alerts',
            array(self::init(), 'render_admin_page')
        );
    }

    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        // Handle settings update
        if (isset($_POST['securesphere_alerts_settings_nonce']) && wp_verify_nonce($_POST['securesphere_alerts_settings_nonce'], 'securesphere_alerts_settings_action')) {
            $email = sanitize_email($_POST['securesphere_alerts_email'] ?? '');
            $notification_types = isset($_POST['securesphere_alerts_notification_types']) ? 
                array_map('sanitize_text_field', $_POST['securesphere_alerts_notification_types']) : array();
            
            update_option('securesphere_alerts_email', $email);
            update_option('securesphere_alerts_notification_types', $notification_types);
            
            echo '<div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>';
        }

        $email = get_option('securesphere_alerts_email', get_option('admin_email'));
        $notification_types = get_option('securesphere_alerts_notification_types', array('security', 'updates', 'errors'));
        
        include SECURESPHERE_PLUGIN_DIR . 'inc/admin/alerts.php';
    }
}