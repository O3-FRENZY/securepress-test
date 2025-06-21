<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * SecureSphere Firewall Module
 * Handles advanced firewall features
 */

class SecureSphere_Firewall {
    private static $instance = null;
    private $config;
    private $logger;
    private $db;
    
    // Option keys
    const OPT_BLOCKED_IPS = 'securesphere_blocked_ips';
    const OPT_WHITELISTED_IPS = 'securesphere_whitelisted_ips';
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->config = SecureSphere_Config::init();
        $this->logger = SecureSphere_Logger::init();
        $this->db = SecureSphere_Database::init();
        
        // Initialize firewall hooks
        add_action('init', array($this, 'check_request'));
        add_action('wp_login_failed', array($this, 'handle_failed_login'));
        add_action('xmlrpc_call', array($this, 'check_xmlrpc_request'));
        add_action('rest_api_init', array($this, 'check_rest_api_request'));
    }
    
    public function check_request() {
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }
        
        $ip = $this->get_client_ip();
        
        // Check if IP is whitelisted
        if ($this->is_ip_whitelisted($ip)) {
            return;
        }
        
        // Check if IP is blocked
        if ($this->is_ip_blocked($ip)) {
            $this->block_request($ip);
        }
    }
    
    public function get_client_ip() {
        $ip = '';
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return sanitize_text_field($ip);
    }
    
    public function is_ip_whitelisted($ip) {
        $whitelisted_ips = get_option(self::OPT_WHITELISTED_IPS, array());
        return in_array($ip, $whitelisted_ips);
    }
    
    public function is_ip_blocked($ip) {
        global $wpdb;
        
        $blocked = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}securesphere_blocked_ips 
            WHERE ip = %s AND blocked_until > NOW()",
            $ip
        ));
        
        return !empty($blocked);
    }
    
    public function block_request($ip) {
        $this->logger->log('Blocked request from IP: ' . $ip, 'warning');
        wp_die('Access Denied', 'Security', array('response' => 403));
    }
    
    public function deactivate() {
        // Cleanup on deactivation
        delete_option(self::OPT_BLOCKED_IPS);
        delete_option(self::OPT_WHITELISTED_IPS);
    }
    
    public static function load_firewall_data() {
        // Reload firewall data from options
        $blocked_ips = get_option(self::OPT_BLOCKED_IPS, array());
        $whitelisted_ips = get_option(self::OPT_WHITELISTED_IPS, array());
        return array(
            'blocked_ips' => $blocked_ips,
            'whitelisted_ips' => $whitelisted_ips
        );
    }
    
    private function get_country_from_ip($ip) {
        // Use MaxMind GeoIP2 or similar service
        // This is a placeholder implementation
        $api_key = $this->config->get_option('geoip_api_key');
        if (!$api_key) {
            return null;
        }
        
        $url = "http://api.ipstack.com/{$ip}?access_key={$api_key}";
        $response = wp_remote_get($url);
        
        if (is_wp_error($response)) {
            $this->logger->log('Failed to get country from IP: ' . $response->get_error_message(), 'error');
            return null;
        }
        
        $data = json_decode(wp_remote_retrieve_body($response), true);
        return $data['country_code'] ?? null;
    }
    
    private function is_country_blocked($country) {
        if (!$country) {
            return false;
        }
        
        $blocked_countries = $this->config->get_option('blocked_countries', array());
        return in_array($country, $blocked_countries);
    }
    
    private function is_ip_blacklisted($ip) {
        // Check local blacklist
        $blacklisted_ips = $this->config->get_option('blacklisted_ips', array());
        if (in_array($ip, $blacklisted_ips)) {
            return true;
        }
        
        // Check external blacklist services
        if ($this->config->get_option('use_external_blacklists')) {
            return $this->check_external_blacklists($ip);
        }
        
        return false;
    }
    
    private function check_external_blacklists($ip) {
        $api_key = $this->config->get_option('abuseipdb_api_key');
        if (!$api_key) {
            return false;
        }
        
        $url = "https://api.abuseipdb.com/api/v2/check?ipAddress={$ip}";
        $response = wp_remote_get($url, array(
            'headers' => array(
                'Key' => $api_key,
                'Accept' => 'application/json'
            )
        ));
        
        if (is_wp_error($response)) {
            $this->logger->log('Failed to check IP reputation: ' . $response->get_error_message(), 'error');
            return false;
        }
        
        $data = json_decode(wp_remote_retrieve_body($response), true);
        return ($data['data']['abuseConfidenceScore'] ?? 0) > 50;
    }
    
    private function is_rate_limited($ip) {
        $rate_limit = $this->config->get_option('rate_limit', 100);
        $rate_period = $this->config->get_option('rate_period', 3600); // 1 hour
        
        $key = 'securesphere_rate_limit_' . md5($ip);
        $count = get_transient($key);
        
        if ($count === false) {
            set_transient($key, 1, $rate_period);
            return false;
        }
        
        if ($count >= $rate_limit) {
            return true;
        }
        
        set_transient($key, $count + 1, $rate_period);
        return false;
    }
    
    private function check_custom_rules($ip, $request_uri, $request_method, $user_agent) {
        $rules = $this->config->get_option('custom_firewall_rules', array());
        
        foreach ($rules as $rule) {
            if (!$rule['enabled']) {
                continue;
            }
            
            $match = true;
            
            if (!empty($rule['ip_pattern']) && !preg_match($rule['ip_pattern'], $ip)) {
                $match = false;
            }
            
            if (!empty($rule['uri_pattern']) && !preg_match($rule['uri_pattern'], $request_uri)) {
                $match = false;
            }
            
            if (!empty($rule['method']) && $rule['method'] !== $request_method) {
                $match = false;
            }
            
            if (!empty($rule['user_agent_pattern']) && !preg_match($rule['user_agent_pattern'], $user_agent)) {
                $match = false;
            }
            
            if ($match) {
                return true;
            }
        }
        
        return false;
    }
    
    public function handle_failed_login($username) {
        if (!$this->config->get_option('login_attempt_limiting')) {
            return;
        }
        
        $ip = $this->get_client_ip();
        $key = 'securesphere_failed_logins_' . md5($ip);
        $attempts = get_transient($key) ?: 0;
        
        if ($attempts >= $this->config->get_option('max_login_attempts', 5)) {
            // Block IP temporarily
            $block_duration = $this->config->get_option('login_block_duration', 3600); // 1 hour
            set_transient('securesphere_blocked_ip_' . md5($ip), true, $block_duration);
            
            // Log security event
            $this->db->log_security_event(array(
                'event_type' => 'login_block',
                'severity' => 'high',
                'source' => 'firewall',
                'details' => json_encode(array(
                    'ip' => $ip,
                    'username' => $username,
                    'attempts' => $attempts
                ))
            ));
            
            // Send alert
            $this->send_alert('Login Blocked', array(
                'ip' => $ip,
                'username' => $username,
                'attempts' => $attempts
            ));
        } else {
            set_transient($key, $attempts + 1, 3600); // Reset after 1 hour
        }
    }
    
    public function check_xmlrpc_request($method) {
        if (!$this->config->get_option('xmlrpc_protection')) {
            return;
        }
        
        $ip = $this->get_client_ip();
        
        // Block XML-RPC if not whitelisted
        if (!in_array($ip, $this->config->get_option('xmlrpc_whitelist', array()))) {
            $this->block_request(
                $ip,
                '/xmlrpc.php',
                'POST',
                $_SERVER['HTTP_USER_AGENT'] ?? '',
                'XML-RPC access denied'
            );
        }
    }
    
    public function check_rest_api_request() {
        if (!$this->config->get_option('rest_api_protection')) {
            return;
        }
        
        $ip = $this->get_client_ip();
        $request_uri = $_SERVER['REQUEST_URI'];
        
        // Block REST API if not whitelisted
        if (strpos($request_uri, '/wp-json/') === 0 && 
            !in_array($ip, $this->config->get_option('rest_api_whitelist', array()))) {
            $this->block_request(
                $ip,
                $request_uri,
                $_SERVER['REQUEST_METHOD'],
                $_SERVER['HTTP_USER_AGENT'] ?? '',
                'REST API access denied'
            );
        }
    }
    
    private function send_alert($title, $data) {
        // Send email alert
        if ($this->config->get_option('email_notifications_enabled')) {
            $to = $this->config->get_option('alert_email');
            $subject = 'SecureSphere Alert: ' . $title;
            $message = "A security alert has been triggered:\n\n";
            $message .= "Title: {$title}\n";
            $message .= "Time: " . current_time('mysql') . "\n";
            $message .= "Details:\n" . print_r($data, true);
            
            wp_mail($to, $subject, $message);
        }
        
        // Send SMS alert
        if ($this->config->get_option('sms_notifications_enabled')) {
            // Implement SMS notification logic here
        }
    }

    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        try {
            // Get firewall status
            $firewall_enabled = get_option('securesphere_firewall_enabled', true);
            $blocked_ips = $this->db->get_blocked_ips();
            ?>
            <div class="wrap">
                <h1>SecureSphere Firewall</h1>
                
                <?php if (isset($_GET['error'])) : ?>
                    <div class="notice notice-error">
                        <p><?php echo esc_html(urldecode($_GET['error'])); ?></p>
                    </div>
                <?php endif; ?>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Firewall Protection</h2>
                        <div class="ss-card-actions">
                            <label class="ss-switch">
                                <input type="checkbox" id="firewall-toggle" <?php checked($firewall_enabled); ?>>
                                <span class="ss-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="ss-card-body">
                        <!-- Firewall Status -->
                        <div class="ss-status-section">
                            <div class="ss-status-card <?php echo $firewall_enabled ? 'ss-status-active' : 'ss-status-inactive'; ?>">
                                <div class="ss-status-icon">
                                    <span class="dashicons dashicons-<?php echo $firewall_enabled ? 'shield' : 'shield-alt'; ?>"></span>
                                </div>
                                <div class="ss-status-info">
                                    <h3>Firewall Status</h3>
                                    <p><?php echo $firewall_enabled ? 'Active' : 'Inactive'; ?></p>
                                </div>
                            </div>
                        </div>

                        <!-- Blocked IPs -->
                        <div class="ss-section">
                            <h3>Currently Blocked IPs</h3>
                            <?php if (!empty($blocked_ips)) : ?>
                                <div class="ss-table-responsive">
                                    <table class="ss-table">
                                        <thead>
                                            <tr>
                                                <th>IP Address</th>
                                                <th>Reason</th>
                                                <th>Blocked Until</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($blocked_ips as $ip) : ?>
                                                <tr>
                                                    <td><?php echo esc_html($ip['ip']); ?></td>
                                                    <td><?php echo esc_html($ip['reason']); ?></td>
                                                    <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($ip['blocked_until']))); ?></td>
                                                    <td>
                                                        <button class="ss-button ss-button-small ss-unblock-ip" 
                                                                data-ip="<?php echo esc_attr($ip['ip']); ?>">
                                                            Unblock
                                                        </button>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php else : ?>
                                <div class="ss-empty-state">
                                    <span class="dashicons dashicons-shield ss-empty-state-icon"></span>
                                    <p>No IPs are currently blocked.</p>
                                </div>
                            <?php endif; ?>
                        </div>

                        <!-- Firewall Rules -->
                        <div class="ss-section">
                            <h3>Firewall Rules</h3>
                            <div class="ss-rules-list">
                                <div class="ss-rule-card">
                                    <div class="ss-rule-header">
                                        <h4>SQL Injection Protection</h4>
                                        <label class="ss-switch">
                                            <input type="checkbox" checked disabled>
                                            <span class="ss-slider"></span>
                                        </label>
                                    </div>
                                    <p>Blocks SQL injection attempts in requests</p>
                                </div>

                                <div class="ss-rule-card">
                                    <div class="ss-rule-header">
                                        <h4>XSS Protection</h4>
                                        <label class="ss-switch">
                                            <input type="checkbox" checked disabled>
                                            <span class="ss-slider"></span>
                                        </label>
                                    </div>
                                    <p>Prevents cross-site scripting attacks</p>
                                </div>

                                <div class="ss-rule-card">
                                    <div class="ss-rule-header">
                                        <h4>File Upload Protection</h4>
                                        <label class="ss-switch">
                                            <input type="checkbox" checked disabled>
                                            <span class="ss-slider"></span>
                                        </label>
                                    </div>
                                    <p>Scans uploaded files for malware</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php
        } catch (Exception $e) {
            error_log('SecureSphere Error: ' . $e->getMessage());
            ?>
            <div class="wrap">
                <h1>SecureSphere Firewall</h1>
                <div class="notice notice-error">
                    <p>An error occurred while loading the firewall page. Please try refreshing the page or contact support if the issue persists.</p>
                </div>
            </div>
            <?php
        }
    }

    public function block_ip($ip, $reason = '', $duration = 3600) {
        global $wpdb;
        
        $blocked_until = date('Y-m-d H:i:s', time() + $duration);
        
        $wpdb->insert(
            $wpdb->prefix . 'securesphere_blocked_ips',
            array(
                'ip' => $ip,
                'reason' => $reason,
                'blocked_until' => $blocked_until,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%s')
        );
        
        // Log the block
        $this->db->log_firewall_event(array(
            'ip_address' => $ip,
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'status' => 'blocked',
            'reason' => $reason
        ));
        
        // Send alert
        $this->send_alert('IP Blocked', array(
            'ip' => $ip,
            'reason' => $reason,
            'duration' => $duration
        ));
    }
    
    public function unblock_ip($ip) {
        global $wpdb;
        
        $wpdb->delete(
            $wpdb->prefix . 'securesphere_blocked_ips',
            array('ip' => $ip),
            array('%s')
        );
        
        // Log the unblock
        $this->db->log_firewall_event(array(
            'ip_address' => $ip,
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'status' => 'unblocked',
            'reason' => 'Manual unblock'
        ));
    }
    
    public function get_blocked_ips() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_blocked_ips';
        
        return $wpdb->get_results(
            "SELECT * FROM {$table_name} WHERE blocked_until > NOW() ORDER BY blocked_until DESC",
            ARRAY_A
        ) ?: array();
    }

    public function cleanup_expired_blocks() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_blocked_ips';
        
        $wpdb->query(
            "DELETE FROM {$table_name} WHERE blocked_until < NOW()"
        );
    }
} 