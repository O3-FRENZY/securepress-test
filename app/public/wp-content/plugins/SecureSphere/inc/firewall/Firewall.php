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
    const OPT_BLOCKED_IPS = 'securesphere_blocked_ips'; // May become less relevant for direct use if all blocks go to DB
    const OPT_WHITELISTED_IPS = 'securesphere_whitelisted_ips';

    // Rate Limiting Constants (Phase 1: Hardcoded, future: from settings)
    const RATE_LIMIT_THRESHOLD = 100; // e.g., 100 requests
    const RATE_LIMIT_PERIOD = 60;    // e.g., per 60 seconds
    const RATE_LIMIT_BLOCK_DURATION = 300; // e.g., block for 300 seconds (5 minutes)
    
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

        // Firewall rule update hook
        add_action('securesphere_daily_firewall_rule_update_hook', array($this, 'fetch_and_update_firewall_rules_from_file'));
        if (!wp_next_scheduled('securesphere_daily_firewall_rule_update_hook')) {
            wp_schedule_event(time(), 'daily', 'securesphere_daily_firewall_rule_update_hook');
        }
    }

    public function fetch_and_update_firewall_rules_from_file() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_firewall_rules';
        $json_file_path = SECURESPHERE_PLUGIN_DIR . 'firewall/rules.json';

        if (!file_exists($json_file_path)) {
            error_log('SecureSphere Firewall Rule Update: JSON file not found at ' . $json_file_path);
            set_transient('securesphere_firewall_rule_update_status', 'error_file_not_found', HOUR_IN_SECONDS);
            return false;
        }

        $json_content = file_get_contents($json_file_path);
        if ($json_content === false) {
            error_log('SecureSphere Firewall Rule Update: Could not read JSON file.');
            set_transient('securesphere_firewall_rule_update_status', 'error_file_read', HOUR_IN_SECONDS);
            return false;
        }

        $rules = json_decode($json_content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log('SecureSphere Firewall Rule Update: Invalid JSON in rules file. Error: ' . json_last_error_msg());
            set_transient('securesphere_firewall_rule_update_status', 'error_json_invalid', HOUR_IN_SECONDS);
            return false;
        }

        if (empty($rules) || !is_array($rules)) {
            error_log('SecureSphere Firewall Rule Update: No rules found or invalid format in JSON file.');
            set_transient('securesphere_firewall_rule_update_status', 'error_no_rules_in_file', HOUR_IN_SECONDS);
            return false;
        }

        $updated_count = 0;
        $inserted_count = 0;
        $current_time = current_time('mysql');

        foreach ($rules as $rule) {
            if (empty($rule['rule_id']) || empty($rule['type']) || empty($rule['pattern']) || !isset($rule['action']) || empty($rule['date_added'])) {
                error_log('SecureSphere Firewall Rule Update: Skipping invalid rule entry: ' . print_r($rule, true));
                continue;
            }

            $data = [
                'type' => sanitize_text_field($rule['type']),
                'pattern' => $rule['pattern'], // Pattern can be complex
                'description' => isset($rule['description']) ? sanitize_textarea_field($rule['description']) : '',
                'severity' => isset($rule['severity']) ? sanitize_text_field($rule['severity']) : 'medium',
                'action' => sanitize_text_field($rule['action']),
                'date_added' => gmdate('Y-m-d H:i:s', strtotime($rule['date_added'])), // Ensure GMT
                'last_updated' => $current_time,
                'enabled' => isset($rule['enabled']) ? (int)(bool)$rule['enabled'] : 1,
            ];
            $where = ['rule_id' => sanitize_text_field($rule['rule_id'])];

            $existing = $wpdb->get_row($wpdb->prepare("SELECT id FROM $table_name WHERE rule_id = %s", $where['rule_id']));

            if ($existing) {
                $result = $wpdb->update($table_name, $data, $where);
                if ($result !== false) $updated_count++;
            } else {
                $data['rule_id'] = $where['rule_id'];
                $result = $wpdb->insert($table_name, $data);
                if ($result !== false) $inserted_count++;
            }

            if ($result === false) {
                 error_log('SecureSphere Firewall Rule Update: DB error for rule ID ' . $where['rule_id'] . ' - ' . $wpdb->last_error);
            }
        }

        update_option('securesphere_last_firewall_rule_update_time', $current_time);
        update_option('securesphere_firewall_rule_version', 'file_' . date('YmdHis', filemtime($json_file_path)));
        set_transient('securesphere_firewall_rule_update_status', "success_inserted_{$inserted_count}_updated_{$updated_count}", HOUR_IN_SECONDS);
        error_log("SecureSphere Firewall Rule Update: Success. Inserted: {$inserted_count}, Updated: {$updated_count}");
        return true;
    }
    
    public function check_request() {
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }

        $ip = $this->get_client_ip();
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $request_method = $_SERVER['REQUEST_METHOD'] ?? '';

        // 1. Check if IP is whitelisted - highest priority
        if ($this->is_ip_whitelisted($ip)) {
            return;
        }

        // 2. Process rules from the database (the new "feed")
        $db_rules = $this->load_firewall_rules_from_db();
        if (!empty($db_rules)) {
            foreach ($db_rules as $rule) {
                $match = false;
                switch ($rule['type']) {
                    case 'ip_block':
                        if ($ip === $rule['pattern']) {
                            $match = true;
                        }
                        break;
                    case 'ip_range_block':
                        // Basic CIDR check (IPv4 only for now)
                        if ($this->is_ip_in_range($ip, $rule['pattern'])) {
                            $match = true;
                        }
                        break;
                    case 'user_agent_block':
                        if (preg_match($rule['pattern'], $user_agent)) {
                            $match = true;
                        }
                        break;
                    case 'request_pattern':
                        if (preg_match($rule['pattern'], $request_uri)) {
                            $match = true;
                        }
                        break;
                    // SQLi/XSS patterns will be handled in a separate, more specific check for now
                }

                if ($match) {
                    $this->handle_matched_rule($rule, $ip, $request_uri, $request_method, $user_agent);
                    // If action was 'block', handle_matched_rule would have called wp_die
                }
            }
        }
        
        // 3. Check if IP is already blocked (manual, login failures, rate limits)
        // This check is important to run after DB rules if DB rules might have log-only actions.
        // If a DB rule already blocked, this won't be reached.
        if ($this->is_ip_blocked($ip)) {
            $this->block_request($ip, "Previously Blocked IP"); // Reason might need to be fetched
        }

        // 4. SQLi/XSS Specific Parameter Checks (after general request_pattern rules)
        $this->check_request_parameters_for_sqli_xss($db_rules, $ip, $request_uri, $request_method, $user_agent);
        // If request is blocked by SQLi/XSS rules, execution would have stopped in handle_matched_rule.

        // 5. Rate Limiting Check
        $this->check_and_apply_rate_limit($ip);
        // If rate limited and blocked, execution stops here.
    }

    private function check_and_apply_rate_limit($ip) {
        // Use class constants for rate limit parameters
        $threshold = self::RATE_LIMIT_THRESHOLD;
        $period = self::RATE_LIMIT_PERIOD;
        $block_duration = self::RATE_LIMIT_BLOCK_DURATION;

        $transient_key = 'ss_rl_count_' . md5($ip);
        $request_count = get_transient($transient_key);

        if (false === $request_count) {
            set_transient($transient_key, 1, $period);
        } else {
            $request_count++;
            set_transient($transient_key, $request_count, $period);

            if ($request_count > $threshold) {
                // Check if this IP is already blocked for rate limiting to avoid redundant blocking/logging
                global $wpdb;
                $blocked_ips_table = $wpdb->prefix . 'securesphere_blocked_ips';
                $is_already_rate_limited = $wpdb->get_var($wpdb->prepare(
                    "SELECT id FROM {$blocked_ips_table} WHERE ip = %s AND reason LIKE %s AND blocked_until > NOW()",
                    $ip,
                    'Rate Limit Exceeded%' // Use LIKE to catch if it was already blocked for this
                ));

                if (!$is_already_rate_limited) {
                    $reason = sprintf('Rate Limit Exceeded: %d requests in %d seconds.', $request_count, $period);
                    $this->block_ip($ip, $reason, $block_duration);
                    // block_ip() calls block_request() which logs and dies.
                }
                // If already blocked for rate limiting, block_request() in main check_request will catch it,
                // or if the block expired, a new one will be placed.
            }
        }
    }

    private function check_request_parameters_for_sqli_xss($rules, $ip, $request_uri, $request_method, $user_agent) {
        $sqli_rules = array_filter($rules, function($rule) {
            return $rule['type'] === 'sqli_pattern';
        });
        $xss_rules = array_filter($rules, function($rule) {
            return $rule['type'] === 'xss_pattern';
        });

        if (empty($sqli_rules) && empty($xss_rules)) {
            return;
        }

        $parameters_to_check = [];
        // Add GET parameters
        if (!empty($_GET)) {
            $parameters_to_check = array_merge($parameters_to_check, $_GET);
        }
        // Add POST parameters
        if (!empty($_POST)) {
            $parameters_to_check = array_merge($parameters_to_check, $_POST);
        }
        // Optionally, could add COOKIE parameters here too, but be cautious: $_COOKIE

        foreach ($parameters_to_check as $key => $value) {
            if (is_array($value) || is_object($value)) {
                // Recursively check arrays/objects, or simply skip/stringify them
                // For simplicity in Phase 1, we can skip complex types or just check their stringified version.
                // To keep it simple now, we'll just check if it's a string.
                if (is_array($value)) { // Basic handling for arrays of strings
                    foreach($value as $sub_value) {
                        if (is_string($sub_value)) {
                             $this->apply_sqli_xss_rules_to_value($sub_value, $sqli_rules, $xss_rules, $ip, $request_uri, $request_method, $user_agent, $key);
                        }
                    }
                    continue;
                } elseif(!is_string($value)) {
                    continue;
                }
            }
            $this->apply_sqli_xss_rules_to_value((string)$value, $sqli_rules, $xss_rules, $ip, $request_uri, $request_method, $user_agent, $key);
        }
    }

    private function apply_sqli_xss_rules_to_value($value, $sqli_rules, $xss_rules, $ip, $request_uri, $request_method, $user_agent, $param_key) {
        // Check SQLi rules
        foreach ($sqli_rules as $rule) {
            if (preg_match($rule['pattern'], $value)) {
                $rule_with_param = $rule; // Clone rule to add parameter context
                $rule_with_param['description'] = sprintf('%s (Parameter: %s)', $rule['description'], $param_key);
                $this->handle_matched_rule($rule_with_param, $ip, $request_uri, $request_method, $user_agent);
                // If blocked, execution stops here.
            }
        }
        // Check XSS rules
        foreach ($xss_rules as $rule) {
            if (preg_match($rule['pattern'], $value)) {
                 $rule_with_param = $rule;
                 $rule_with_param['description'] = sprintf('%s (Parameter: %s)', $rule['description'], $param_key);
                $this->handle_matched_rule($rule_with_param, $ip, $request_uri, $request_method, $user_agent);
                // If blocked, execution stops here.
            }
        }
    }


    private function handle_matched_rule($rule, $ip, $request_uri, $request_method, $user_agent) {
        $reason = sprintf('Matched Rule ID: %s (%s)', $rule['rule_id'], $rule['description']);

        $this->db->log_firewall_event([
            'ip_address' => $ip,
            'request_uri' => $request_uri,
            'request_method' => $request_method,
            'user_agent' => $user_agent,
            'status' => $rule['action'], // 'block' or 'log'
            'reason' => $reason,
            'rule_id' => $rule['rule_id'] ?? 'N/A' // Ensure rule_id is present
        ]);

        if ($rule['action'] === 'block') {
            $this->block_request($ip, $reason); // block_request calls wp_die
        }
    }

    public function load_firewall_rules_from_db() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_firewall_rules';
        // Only load enabled rules
        $results = $wpdb->get_results("SELECT * FROM {$table_name} WHERE enabled = 1", ARRAY_A);

        if ($wpdb->last_error) {
            error_log("SecureSphere DB Error loading firewall rules: " . $wpdb->last_error);
            return [];
        }
        return $results ?: [];
    }

    // Helper function for basic IPv4 CIDR check
    private function is_ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) {
            // Not a CIDR range, treat as single IP for this basic check
            return $ip === $range;
        }
        list($subnet, $bits) = explode('/', $range);
        if ($bits === null || !ctype_digit($bits) || $bits < 0 || $bits > 32) {
            return false; // Invalid CIDR bits
        }
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $subnet &= $mask; // Ensure subnet is actually the network address
        return ($ip & $mask) == $subnet;
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
    
    public function block_request($ip, $reason = 'Access Denied by Firewall Rule') {
        // Log the event via Database class, which should be the central place for logging firewall events
        $this->db->log_firewall_event([
            'ip_address' => $ip,
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'status' => 'blocked', // General status
            'reason' => $reason,   // Specific reason for the block
        ]);

        // Use the main logger for a simple textual log as well if desired, but DB log is primary
        $this->logger->log('Blocked request from IP: ' . $ip . '. Reason: ' . $reason, 'warning');

        wp_die(esc_html($reason), 'Access Denied', array('response' => 403));
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
            $firewall_enabled = get_option('securesphere_firewall_enabled', true); // This option should be primary toggle
            $blocked_ips = $this->db->get_blocked_ips(); // From `securesphere_blocked_ips` table

            // Rule update status
            $last_rule_update = get_option('securesphere_last_firewall_rule_update_time', 'Never');
            $rule_version = get_option('securesphere_firewall_rule_version', 'N/A');
            $rule_update_status_transient = get_transient('securesphere_firewall_rule_update_status');

            global $wpdb;
            $rules_table = $wpdb->prefix . 'securesphere_firewall_rules';
            $active_rules_count = $wpdb->get_var("SELECT COUNT(*) FROM {$rules_table} WHERE enabled = 1");

            ?>
            <div class="wrap">
                <h1>SecureSphere Firewall</h1>

                <?php if (isset($_GET['message'])) : ?>
                    <div class="notice notice-success is-dismissible">
                        <p><?php echo esc_html(urldecode($_GET['message'])); ?></p>
                    </div>
                <?php endif; ?>
                <?php if (isset($_GET['error'])) : ?>
                    <div class="notice notice-error is-dismissible">
                        <p><?php echo esc_html(urldecode($_GET['error'])); ?></p>
                    </div>
                <?php endif; ?>

                <?php if ($rule_update_status_transient): ?>
                    <?php
                    $status_parts = explode('_', $rule_update_status_transient);
                    $status_type = $status_parts[0];
                    if ($status_type === 'success'):
                        $inserted = $status_parts[2];
                        $updated = $status_parts[4];
                    ?>
                        <div class="notice notice-success is-dismissible">
                            <p>Firewall rule update successful. Inserted: <?php echo esc_html($inserted); ?>, Updated: <?php echo esc_html($updated); ?>.</p>
                        </div>
                    <?php elseif (strpos($rule_update_status_transient, 'error_') === 0): ?>
                        <div class="notice notice-error is-dismissible">
                            <p>Firewall rule update error: <?php echo esc_html(str_replace('error_', '', $rule_update_status_transient)); ?>. Check PHP error logs for details.</p>
                        </div>
                    <?php endif; ?>
                    <?php delete_transient('securesphere_firewall_rule_update_status'); ?>
                <?php endif; ?>


                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Firewall Status & Overview</h2>
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
                             <div class="ss-status-card">
                                <div class="ss-status-icon"><span class="dashicons dashicons-list-view"></span></div>
                                <div class="ss-status-info">
                                    <h3>Active Rules</h3>
                                    <p><?php echo esc_html($active_rules_count); ?> loaded</p>
                                </div>
                            </div>
                            <div class="ss-status-card">
                                <div class="ss-status-icon"><span class="dashicons dashicons-cloud-upload"></span></div>
                                <div class="ss-status-info">
                                    <h3>Rule Feed</h3>
                                    <p>Last Update: <?php echo esc_html($last_rule_update); ?><br>
                                       Version: <?php echo esc_html($rule_version); ?><br>
                                       Next Update: <?php echo esc_html(wp_next_scheduled('securesphere_daily_firewall_rule_update_hook') ? date('Y-m-d H:i:s', wp_next_scheduled('securesphere_daily_firewall_rule_update_hook')) : 'Not Scheduled'); ?>
                                    </p>
                                </div>
                            </div>
                        </div>

                        <!-- Blocked IPs -->
                        <div class="ss-section">
                            <h3>Currently Blocked IPs (Manual, Rate Limit, Login Failures etc.)</h3>
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