<?php
if (!defined('ABSPATH')) {
    exit;
}

// REST API Security module for SecureSphere
class SecureSphere_RestApiSecurity {

    const OPT_RULES = 'securesphere_rest_api_rules';
    const OPT_ENABLED = 'securesphere_rest_api_enabled';
    const OPT_DEFAULT_POLICY = 'securesphere_rest_api_default_policy'; // 'allow' or 'block'
    const OPT_RATE_LIMIT = 'securesphere_rest_api_rate_limit';
    const OPT_AUTH_REQUIRED = 'securesphere_rest_api_auth_required';

    private static $instance = null;
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        add_action('rest_api_init', array($this, 'init_rest_api_security'));
        add_action('admin_menu', [__CLASS__, 'add_admin_menu']);
    }
    
    public function init_rest_api_security() {
        // Add security headers
        add_action('rest_api_init', array($this, 'add_security_headers'));
        
        // Rate limiting
        add_filter('rest_pre_dispatch', array($this, 'check_rate_limit'), 10, 3);
        
        // Authentication checks
        add_filter('rest_authentication_errors', array($this, 'check_authentication'));
    }
    
    public function add_security_headers() {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('X-XSS-Protection: 1; mode=block');
    }
    
    public function check_rate_limit($result, $server, $request) {
        // Implement rate limiting logic here
        return $result;
    }
    
    public function check_authentication($error) {
        // Implement authentication checks here
        return $error;
    }

    /**
     * Evaluates the REST API request against defined rules.
     *
     * @param mixed $result Current result.
     * @param WP_REST_Server $server Server instance.
     * @param WP_REST_Request $request Request instance.
     * @return mixed Original $result or WP_Error if blocked.
     */
    public static function evaluate_rest_request($result, $server, $request) {
        // If another filter has already produced a WP_Error, respect it.
        if (is_wp_error($result)) {
            return $result;
        }

        $rules = get_option(self::OPT_RULES, []);
        $default_policy = get_option(self::OPT_DEFAULT_POLICY, 'allow'); // Default to allow if no rules match

        $matched_rule = self::find_matching_rule($request, $rules);

        if ($matched_rule) {
            if ($matched_rule['policy'] === 'block') {
                self::log_blocked_request($request, $matched_rule['name'] ?? 'Unnamed Rule');
                return new WP_Error(
                    'rest_forbidden_by_rule',
                    'Access to this REST API endpoint is denied by a security rule.',
                    ['status' => 403, 'rule_name' => $matched_rule['name'] ?? 'Unnamed Rule']
                );
            }
            // If policy is 'allow', it's explicitly allowed by this rule.
            return $result; 
        }

        // No specific rule matched, apply default policy
        if ($default_policy === 'block') {
            self::log_blocked_request($request, 'Default Policy Block');
            return new WP_Error(
                'rest_forbidden_by_default_policy',
                'Access to this REST API endpoint is denied by the default security policy.',
                ['status' => 403]
            );
        }

        // Default policy is 'allow' and no rule blocked it
        return $result;
    }
    
    private static function find_matching_rule($request, $rules) {
        if (empty($rules) || !is_array($rules)) {
            return null;
        }

        $current_ip = sanitize_text_field($_SERVER['REMOTE_ADDR']);
        $current_user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '';
        $current_method = $request->get_method();
        $current_route = '/' . ltrim($request->get_route(), '/'); // Ensure leading slash for consistency

        foreach ($rules as $rule) {
            if (empty($rule['enabled'])) continue;

            // Check Namespace
            if (!empty($rule['namespace'])) {
                $namespace_pattern = '#^/' . preg_quote(trim($rule['namespace'], '/'), '#') . '(/|$)#i';
                if (!preg_match($namespace_pattern, $current_route)) {
                    continue; // Namespace doesn't match
                }
            }

            // Check Route (Regex)
            if (!empty($rule['route_pattern'])) {
                $route_regex = '#' . trim($rule['route_pattern'], '#') . '#i';
                 // If namespace is also set, route pattern should be relative to namespace or full
                if (!preg_match($route_regex, $current_route)) {
                    continue; // Route pattern doesn't match
                }
            }
            
            // Check Method
            if (!empty($rule['method']) && strtoupper($rule['method']) !== $current_method) {
                continue; // Method doesn't match
            }

            // Check IP Address/CIDR
            if (!empty($rule['ip_address'])) {
                $ip_match = false;
                $rule_ips = array_map('trim', explode(',', $rule['ip_address']));
                foreach ($rule_ips as $rule_ip) {
                    if (strpos($rule_ip, '/') !== false) { // CIDR
                        if (SecureSphere_Firewall::ip_in_cidr($current_ip, $rule_ip)) { // Reuse Firewall's CIDR check
                            $ip_match = true;
                            break;
                        }
                    } elseif ($rule_ip === $current_ip) { // Exact IP
                        $ip_match = true;
                        break;
                    }
                }
                if (!$ip_match) continue;
            }

            // Check User Agent (Regex)
            if (!empty($rule['user_agent_pattern'])) {
                if (!preg_match('#' . $rule['user_agent_pattern'] . '#i', $current_user_agent)) {
                    continue; // User agent doesn't match
                }
            }
            
            // If all conditions passed, this rule matches
            return $rule;
        }
        return null; // No rule matched
    }

    private static function log_blocked_request($request, $reason) {
        $log_entry = [
            'time' => current_time('mysql'),
            'ip' => sanitize_text_field($_SERVER['REMOTE_ADDR']),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '',
            'method' => $request->get_method(),
            'route' => $request->get_route(),
            'reason' => $reason,
            'user_id' => get_current_user_id(),
        ];
        // Store this log, similar to other modules (e.g., in a dedicated option or part of a central log)
        $log = get_option('securesphere_rest_api_blocked_log', []);
        array_unshift($log, $log_entry);
        if (count($log) > 200) { // Keep last 200 blocked REST API attempts
            $log = array_slice($log, 0, 200);
        }
        update_option('securesphere_rest_api_blocked_log', $log, false);
    }

    public static function add_admin_menu() {
        add_submenu_page(
            'securesphere-mssp',
            'REST API Security',
            'REST API Security',
            'manage_options',
            'securesphere-rest-api',
            [__CLASS__, 'render_admin_page']
        );
    }

    public static function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die('Permission denied.');
        }

        // Handle settings & rule updates
        if (isset($_POST['securesphere_rest_api_nonce']) && wp_verify_nonce($_POST['securesphere_rest_api_nonce'], 'securesphere_rest_api_action')) {
            update_option(self::OPT_ENABLED, isset($_POST[self::OPT_ENABLED]));
            update_option(self::OPT_DEFAULT_POLICY, sanitize_text_field($_POST[self::OPT_DEFAULT_POLICY] ?? 'allow'));
            update_option(self::OPT_RATE_LIMIT, sanitize_text_field($_POST[self::OPT_RATE_LIMIT] ?? '60'));
            update_option(self::OPT_AUTH_REQUIRED, isset($_POST[self::OPT_AUTH_REQUIRED]));

            $rules = [];
            if (isset($_POST['rules']) && is_array($_POST['rules'])) {
                foreach ($_POST['rules'] as $rule_data) {
                    $rules[] = [
                        'name' => sanitize_text_field($rule_data['name']),
                        'enabled' => isset($rule_data['enabled']),
                        'namespace' => sanitize_text_field($rule_data['namespace']),
                        'route_pattern' => sanitize_text_field($rule_data['route_pattern']), // Should be regex, careful with sanitization
                        'method' => sanitize_text_field(strtoupper($rule_data['method'])),
                        'ip_address' => sanitize_text_field($rule_data['ip_address']),
                        'user_agent_pattern' => sanitize_text_field($rule_data['user_agent_pattern']), // Regex
                        'policy' => sanitize_text_field($rule_data['policy'] ?? 'block'),
                    ];
                }
            }
            update_option(self::OPT_RULES, $rules);
            echo '<div class="notice notice-success is-dismissible"><p>REST API Security settings saved.</p></div>';
        }

        $is_enabled = get_option(self::OPT_ENABLED, true);
        $default_policy = get_option(self::OPT_DEFAULT_POLICY, 'allow');
        $rate_limit = get_option(self::OPT_RATE_LIMIT, '60');
        $auth_required = get_option(self::OPT_AUTH_REQUIRED, true);
        $rules = get_option(self::OPT_RULES, []);
        $blocked_log = get_option('securesphere_rest_api_blocked_log', []);

        ?>
        <div class="wrap">
            <h1>REST API Security</h1>
            <form method="post" action="">
                <?php wp_nonce_field('securesphere_rest_api_action', 'securesphere_rest_api_nonce'); ?>
                <h2>General Settings</h2>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Enable REST API Security</th>
                        <td><input type="checkbox" name="<?php echo self::OPT_ENABLED; ?>" value="1" <?php checked($is_enabled); ?> /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><label for="<?php echo self::OPT_DEFAULT_POLICY; ?>">Default Policy for Unmatched Requests</label></th>
                        <td>
                            <select name="<?php echo self::OPT_DEFAULT_POLICY; ?>" id="<?php echo self::OPT_DEFAULT_POLICY; ?>">
                                <option value="allow" <?php selected($default_policy, 'allow'); ?>>Allow</option>
                                <option value="block" <?php selected($default_policy, 'block'); ?>>Block</option>
                            </select>
                            <p class="description">Action to take if no specific rule matches a request.</p>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Rate Limiting</th>
                        <td>
                            <input type="number" name="<?php echo self::OPT_RATE_LIMIT; ?>" value="<?php echo esc_attr($rate_limit); ?>" min="1" class="small-text">
                            <p class="description">Maximum requests per minute per IP address</p>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Authentication Required</th>
                        <td>
                            <label class="securesphere-switch">
                                <input type="checkbox" name="<?php echo self::OPT_AUTH_REQUIRED; ?>" value="1" <?php checked($auth_required); ?>>
                                <span class="slider round"></span>
                            </label>
                            <p class="description">Require authentication for all REST API endpoints</p>
                        </td>
                    </tr>
                </table>

                <h2>Access Rules</h2>
                <div id="rest-api-rules-container">
                    <?php if (empty($rules)): ?>
                        <p>No rules defined yet. Click "Add Rule" to start.</p>
                    <?php else: ?>
                        <?php foreach ($rules as $index => $rule): ?>
                            <div class="rest-api-rule" style="border: 1px solid #ccc; padding: 10px; margin-bottom: 10px;">
                                <h4>Rule: <input type="text" name="rules[<?php echo $index; ?>][name]" value="<?php echo esc_attr($rule['name']); ?>" placeholder="Rule Name (e.g., Block WP Users Endpoint)" style="width: 300px;"/> 
                                    <input type="checkbox" name="rules[<?php echo $index; ?>][enabled]" value="1" <?php checked($rule['enabled'] ?? false); ?> /> Enabled
                                    <button type="button" class="button remove-rule" style="float:right;">Remove Rule</button>
                                </h4>
                                <p><label>Namespace (e.g., <code>wp/v2</code>, leave blank for any): <input type="text" name="rules[<?php echo $index; ?>][namespace]" value="<?php echo esc_attr($rule['namespace']); ?>" placeholder="wp/v2" /></label></p>
                                <p><label>Route Pattern (Regex, e.g., <code>users/(?P<id>[\d]+)</code>, leave blank for any in namespace): <input type="text" name="rules[<?php echo $index; ?>][route_pattern]" value="<?php echo esc_attr($rule['route_pattern']); ?>" placeholder="users/(?P<id>[\d]+)" style="width: 300px;"/></label></p>
                                <p><label>Method (e.g., GET, POST, leave blank for any): <input type="text" name="rules[<?php echo $index; ?>][method]" value="<?php echo esc_attr($rule['method']); ?>" placeholder="POST" /></label></p>
                                <p><label>IP Address(es) (comma-separated, CIDR allowed, leave blank for any): <input type="text" name="rules[<?php echo $index; ?>][ip_address]" value="<?php echo esc_attr($rule['ip_address']); ?>" placeholder="1.2.3.4, 10.0.0.0/24" style="width: 300px;"/></label></p>
                                <p><label>User Agent Pattern (Regex, leave blank for any): <input type="text" name="rules[<?php echo $index; ?>][user_agent_pattern]" value="<?php echo esc_attr($rule['user_agent_pattern']); ?>" placeholder="^BadBot/" style="width: 300px;"/></label></p>
                                <p><label>Policy for this rule: 
                                    <select name="rules[<?php echo $index; ?>][policy]">
                                        <option value="block" <?php selected($rule['policy'], 'block'); ?>>Block</option>
                                        <option value="allow" <?php selected($rule['policy'], 'allow'); ?>>Allow</option>
                                    </select>
                                </label></p>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
                <button type="button" id="add-rest-api-rule" class="button">Add Rule</button>
                
                <?php submit_button('Save REST API Settings'); ?>
            </form>
            <hr/>
            <h2>Blocked REST API Attempts Log</h2>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP</th>
                        <th>Method</th>
                        <th>Route</th>
                        <th>User Agent</th>
                        <th>Reason</th>
                        <th>User ID</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($blocked_log)): ?>
                        <tr><td colspan="7">No blocked REST API attempts recorded.</td></tr>
                    <?php else: ?>
                        <?php foreach ($blocked_log as $entry): ?>
                            <tr>
                                <td><?php echo esc_html($entry['time']); ?></td>
                                <td><?php echo esc_html($entry['ip']); ?></td>
                                <td><?php echo esc_html($entry['method']); ?></td>
                                <td><?php echo esc_html($entry['route']); ?></td>
                                <td><?php echo esc_html($entry['user_agent']); ?></td>
                                <td><?php echo esc_html($entry['reason']); ?></td>
                                <td><?php echo esc_html($entry['user_id'] ?: 'Guest'); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                let ruleIndex = <?php echo count($rules); ?>;
                $('#add-rest-api-rule').on('click', function() {
                    const newRuleHTML = `
                        <div class="rest-api-rule" style="border: 1px solid #ccc; padding: 10px; margin-bottom: 10px;">
                            <h4>Rule: <input type="text" name="rules[${ruleIndex}][name]" placeholder="Rule Name" style="width: 300px;"/>
                                <input type="checkbox" name="rules[${ruleIndex}][enabled]" value="1" checked /> Enabled
                                <button type="button" class="button remove-rule" style="float:right;">Remove Rule</button>
                            </h4>
                            <p><label>Namespace: <input type="text" name="rules[${ruleIndex}][namespace]" placeholder="wp/v2" /></label></p>
                            <p><label>Route Pattern (Regex): <input type="text" name="rules[${ruleIndex}][route_pattern]" placeholder="users/(?P<id>[\d]+)" style="width: 300px;"/></label></p>
                            <p><label>Method: <input type="text" name="rules[${ruleIndex}][method]" placeholder="POST" /></label></p>
                            <p><label>IP Address(es): <input type="text" name="rules[${ruleIndex}][ip_address]" placeholder="1.2.3.4" style="width: 300px;"/></label></p>
                            <p><label>User Agent Pattern (Regex): <input type="text" name="rules[${ruleIndex}][user_agent_pattern]" placeholder="^BadBot/" style="width: 300px;"/></label></p>
                            <p><label>Policy: 
                                <select name="rules[${ruleIndex}][policy]">
                                    <option value="block" selected>Block</option>
                                    <option value="allow">Allow</option>
                                </select>
                            </label></p>
                        </div>`;
                    $('#rest-api-rules-container').append(newRuleHTML);
                    ruleIndex++;
                });

                $('#rest-api-rules-container').on('click', '.remove-rule', function() {
                    $(this).closest('.rest-api-rule').remove();
                });
            });
        </script>
        <?php
    }
}