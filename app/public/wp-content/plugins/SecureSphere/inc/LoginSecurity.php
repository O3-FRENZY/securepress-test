<?php
if (!defined('ABSPATH')) {
    exit;
}

// Login Security module for SecureSphere
class SecureSphere_LoginSecurity {
    private static $instance = null;
    private $db;
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->db = SecureSphere_Database::init();
    }

    // Default values, will be overridden by options
    private static $max_attempts_option = 'securesphere_max_login_attempts';
    private static $lockout_time_option = 'securesphere_lockout_time';
    private static $captcha_attempts_option = 'securesphere_captcha_attempts';
    private static $login_attempts_option = 'securesphere_login_attempts';
    private static $login_log_option = 'securesphere_login_log';
    // New options for XML-RPC and REST API login protection
    const OPT_XMLRPC_DISABLE = 'securesphere_xmlrpc_disable'; // 'all', 'risky_methods', 'none'
    const OPT_REST_LOGIN_BRUTE_FORCE = 'securesphere_rest_login_brute_force_enabled';

    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        try {
            // Get login security settings
            $login_protection = get_option('securesphere_login_protection', true);
            $max_attempts = get_option('securesphere_max_login_attempts', 5);
            $lockout_duration = get_option('securesphere_lockout_duration', 30);
            $two_factor = get_option('securesphere_two_factor', false);
            ?>
            <div class="wrap">
                <h1>Login Security</h1>
                
                <?php if (isset($_GET['error'])) : ?>
                    <div class="notice notice-error">
                        <p><?php echo esc_html(urldecode($_GET['error'])); ?></p>
                    </div>
                <?php endif; ?>

                <?php if (isset($_GET['success'])) : ?>
                    <div class="notice notice-success">
                        <p><?php echo esc_html(urldecode($_GET['success'])); ?></p>
                    </div>
                <?php endif; ?>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Login Protection</h2>
                    </div>
                    <div class="ss-card-body">
                        <form method="post" action="" class="ss-form">
                            <?php wp_nonce_field('securesphere_login_security', 'securesphere_login_nonce'); ?>
                            
                            <div class="ss-form-group">
                                <label class="ss-switch">
                                    <input type="checkbox" name="login_protection" value="1" <?php checked($login_protection); ?>>
                                    <span class="ss-slider"></span>
                                </label>
                                <span class="ss-label">Enable Login Protection</span>
                            </div>

                            <div class="ss-form-group">
                                <label for="max_attempts">Maximum Login Attempts</label>
                                <input type="number" name="max_attempts" id="max_attempts" 
                                       value="<?php echo esc_attr($max_attempts); ?>" 
                                       min="1" max="10" class="ss-input">
                                <p class="description">Number of failed attempts before lockout</p>
                            </div>

                            <div class="ss-form-group">
                                <label for="lockout_duration">Lockout Duration (minutes)</label>
                                <input type="number" name="lockout_duration" id="lockout_duration" 
                                       value="<?php echo esc_attr($lockout_duration); ?>" 
                                       min="5" max="1440" class="ss-input">
                                <p class="description">How long to lock out IPs after too many failed attempts</p>
                            </div>

                            <div class="ss-form-group">
                                <label class="ss-switch">
                                    <input type="checkbox" name="two_factor" value="1" <?php checked($two_factor); ?>>
                                    <span class="ss-slider"></span>
                                </label>
                                <span class="ss-label">Enable Two-Factor Authentication</span>
                                <p class="description">Require 2FA for admin users</p>
                            </div>

                            <div class="ss-form-actions">
                                <button type="submit" class="ss-button ss-button-primary">Save Settings</button>
                            </div>
                        </form>
                    </div>
                </div>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Recent Login Attempts</h2>
                    </div>
                    <div class="ss-card-body">
                        <?php
                        $login_attempts = $this->get_recent_login_attempts();
                        if (!empty($login_attempts)) : ?>
                            <div class="ss-table-responsive">
                                <table class="ss-table">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>Username</th>
                                            <th>IP Address</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($login_attempts as $attempt) : ?>
                                            <tr>
                                                <td><?php echo esc_html($attempt['timestamp']); ?></td>
                                                <td><?php echo esc_html($attempt['username']); ?></td>
                                                <td><?php echo esc_html($attempt['ip_address']); ?></td>
                                                <td>
                                                    <span class="ss-status-badge ss-status-<?php echo esc_attr($attempt['status']); ?>">
                                                        <?php echo esc_html($attempt['status']); ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <button class="ss-button ss-button-small ss-block-ip" 
                                                            data-ip="<?php echo esc_attr($attempt['ip_address']); ?>">
                                                        Block IP
                                                    </button>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else : ?>
                            <div class="ss-empty-state">
                                <span class="dashicons dashicons-lock ss-empty-state-icon"></span>
                                <p>No recent login attempts found.</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <?php
        } catch (Exception $e) {
            error_log('SecureSphere Login Security Error: ' . $e->getMessage());
            ?>
            <div class="wrap">
                <h1>Login Security</h1>
                <div class="notice notice-error">
                    <p>An error occurred while loading the login security page. Please try refreshing the page or contact support if the issue persists.</p>
                </div>
            </div>
            <?php
        }
    }

    private function get_recent_login_attempts() {
        try {
            return $this->db->get_logs(array(
                'level' => 'warning',
                'limit' => 50,
                'orderby' => 'timestamp',
                'order' => 'DESC'
            ));
        } catch (Exception $e) {
            error_log('SecureSphere Get Login Attempts Error: ' . $e->getMessage());
            return array();
        }
    }

    public static function disable_risky_xmlrpc_methods($methods) {
        $risky_methods = [
            'pingback.ping',
            'pingback.extensions.getPingbacks',
            'wp.getUsersBlogs', // Can enumerate users if not careful
            'system.multicall', // Can be abused for DDoS or to amplify other attacks
            // Add more as needed, e.g., metaWeblog.newPost if anonymous posting is a concern
        ];
        foreach ($risky_methods as $method_name) {
            unset($methods[$method_name]);
        }
        return $methods;
    }
    
    public static function handle_failed_application_password_login($user_id) {
        if ($user_id && is_numeric($user_id)) {
            $user = get_user_by('id', $user_id);
            if ($user) {
                self::handle_failed_login($user->user_login); // Use existing failed login handler
            }
        }
        // If $user_id is null or not found, we might not have a username to log,
        // but the IP will still be tracked by handle_failed_login.
    }

    public static function enforce_strong_passwords() {
        if (!empty($_POST['pwd'])) {
            $password = $_POST['pwd'];
            if (!self::is_password_strong($password)) {
                wp_die('Password does not meet security requirements. Please use a stronger password.');
            }
        }
    }

    public static function validate_password_strength($errors, $sanitized_user_login, $user_email) {
        if (!empty($_POST['pass1'])) {
            if (!self::is_password_strong($_POST['pass1'])) {
                $errors->add('password_error', 'Password does not meet security requirements.');
            }
        }
        return $errors;
    }

    public static function validate_password_strength_on_update($user_id, $old_user_data) {
        if (!empty($_POST['pass1'])) {
            if (!self::is_password_strong($_POST['pass1'])) {
                wp_die('Password does not meet security requirements.');
            }
        }
    }

    public static function is_password_strong($password) {
        // Minimum 8 characters
        if (strlen($password) < 8) {
            return false;
        }
        
        // Must contain at least one uppercase letter
        if (!preg_match('/[A-Z]/', $password)) {
            return false;
        }
        
        // Must contain at least one lowercase letter
        if (!preg_match('/[a-z]/', $password)) {
            return false;
        }
        
        // Must contain at least one number
        if (!preg_match('/[0-9]/', $password)) {
            return false;
        }
        
        // Must contain at least one special character
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            return false;
        }
        
        return true;
    }

    // Renamed from limit_login_attempts for clarity and combined logic
    public static function handle_failed_login($username) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $attempts_data = get_option(self::$login_attempts_option, []);
        
        if (!isset($attempts_data[$ip])) {
            $attempts_data[$ip] = ['count' => 1, 'last_attempt' => time()];
        } else {
            // Reset if lockout period has passed since last attempt, even if not locked out yet
            if ( (time() - $attempts_data[$ip]['last_attempt']) > self::get_lockout_time() && $attempts_data[$ip]['count'] >= self::get_max_attempts() ) {
                 $attempts_data[$ip] = ['count' => 1, 'last_attempt' => time()];
            } else {
                $attempts_data[$ip]['count']++;
                $attempts_data[$ip]['last_attempt'] = time();
            }
        }
        
        update_option(self::$login_attempts_option, $attempts_data);
        self::log_failed_attempt($username, $ip); // Log every failed attempt
    }

    // Check if IP is currently locked out
    public static function check_if_locked_out($user, $username, $password) {
        if (is_wp_error($user)) return $user; // Pass through existing errors (e.g. from CAPTCHA)

        $ip = $_SERVER['REMOTE_ADDR'];
        $attempts_data = get_option(self::$login_attempts_option, []);
        
        if (isset($attempts_data[$ip])) {
            if ($attempts_data[$ip]['count'] >= self::get_max_attempts()) {
                $time_passed = time() - $attempts_data[$ip]['last_attempt'];
                if ($time_passed < self::get_lockout_time()) {
                    $remaining_time = ceil((self::get_lockout_time() - $time_passed) / 60);
                    return new WP_Error('too_many_attempts',
                        sprintf('Too many failed login attempts. Please try again in %d minutes.', $remaining_time));
                } else {
                    // Lockout period expired, reset attempts for this IP
                    unset($attempts_data[$ip]); // Or set count to 0
                    update_option(self::$login_attempts_option, $attempts_data);
                }
            }
        }
        return $user;
    }

    // Placeholder for displaying CAPTCHA
    public static function maybe_display_captcha() {
        $captcha_threshold = self::get_captcha_attempts_threshold();
        if ($captcha_threshold <= 0) return; // CAPTCHA disabled

        $ip = $_SERVER['REMOTE_ADDR'];
        $attempts_data = get_option(self::$login_attempts_option, []);

        if (isset($attempts_data[$ip]) && $attempts_data[$ip]['count'] >= $captcha_threshold) {
            // Check if not currently locked out (lockout takes precedence)
            $is_locked_out = false;
            if ($attempts_data[$ip]['count'] >= self::get_max_attempts()) {
                if ((time() - $attempts_data[$ip]['last_attempt']) < self::get_lockout_time()) {
                    $is_locked_out = true;
                }
            }

            if (!$is_locked_out) {
                echo '<p><label for="securesphere_captcha">CAPTCHA:</label><br/>';
                echo '<input type="text" name="securesphere_captcha_response" id="securesphere_captcha" class="input" value="" size="20" />';
                echo '<br/><small>TODO: Implement actual CAPTCHA image/challenge here.</small></p>';
                // In a real implementation, you would generate and display a CAPTCHA image
                // and store the expected answer in the session or a transient.
            }
        }
    }

    // Placeholder for verifying CAPTCHA
    public static function verify_captcha_on_login($user, $username, $password) {
        if (is_wp_error($user)) return $user; // Pass through existing errors

        $captcha_threshold = self::get_captcha_attempts_threshold();
        if ($captcha_threshold <= 0) return $user; // CAPTCHA disabled

        $ip = $_SERVER['REMOTE_ADDR'];
        $attempts_data = get_option(self::$login_attempts_option, []);

        if (isset($attempts_data[$ip]) && $attempts_data[$ip]['count'] >= $captcha_threshold) {
             // Check if not currently locked out
            $is_locked_out = false;
            if ($attempts_data[$ip]['count'] >= self::get_max_attempts()) {
                if ((time() - $attempts_data[$ip]['last_attempt']) < self::get_lockout_time()) {
                    $is_locked_out = true;
                }
            }

            if (!$is_locked_out) {
                if (empty($_POST['securesphere_captcha_response'])) {
                    return new WP_Error('captcha_required', 'CAPTCHA response is required.');
                }
                // TODO: Implement actual CAPTCHA verification against stored challenge.
                // For now, let's assume 'testcaptcha' is the answer.
                if (strtolower($_POST['securesphere_captcha_response']) !== 'testcaptcha') {
                    // Increment attempts again because CAPTCHA failed, but don't log as a separate "wp_login_failed"
                    // The wp_login_failed hook will trigger if username/password is also wrong.
                    // self::handle_failed_login($username); // This might double log if auth also fails.
                    return new WP_Error('captcha_invalid', 'Invalid CAPTCHA response.');
                }
            }
        }
        return $user;
    }

    public static function log_failed_attempt($username, $ip) {
        $log = get_option(self::$login_log_option, []);
        $log[] = [
            'username' => $username,
            'ip' => $ip,
            'time' => current_time('mysql'),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ];
        
        // Keep only last 1000 entries
        if (count($log) > 1000) {
            array_shift($log);
        }
        
        update_option('securesphere_login_log', $log);
    }

    public static function show_2fa_settings($user) {
        if (!current_user_can('edit_user', $user->ID)) {
            return;
        }
        
        $secret = get_user_meta($user->ID, 'securesphere_2fa_secret', true);
        if (empty($secret)) {
            $secret = self::generate_2fa_secret();
            update_user_meta($user->ID, 'securesphere_2fa_secret', $secret);
        }
        
        $qr_code_url = self::get_2fa_qr_code_url($user, $secret);
        ?>
        <h3>Two-Factor Authentication</h3>
        <table class="form-table">
            <tr>
                <th><label for="2fa_enabled">Enable 2FA</label></th>
                <td>
                    <input type="checkbox" name="2fa_enabled" id="2fa_enabled" 
                           value="1" <?php checked(get_user_meta($user->ID, 'securesphere_2fa_enabled', true), '1'); ?> />
                    <p class="description">Enable two-factor authentication for this account.</p>
                </td>
            </tr>
            <?php if (get_user_meta($user->ID, 'securesphere_2fa_enabled', true)): ?>
            <tr>
                <th><label>QR Code</label></th>
                <td>
                    <img src="<?php echo esc_url($qr_code_url); ?>" alt="2FA QR Code" />
                    <p class="description">Scan this QR code with your authenticator app.</p>
                </td>
            </tr>
            <?php endif; ?>
        </table>
        <?php
    }

    public static function save_2fa_settings($user_id) {
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }
        
        $enabled = isset($_POST['2fa_enabled']) ? '1' : '0';
        update_user_meta($user_id, 'securesphere_2fa_enabled', $enabled);
    }

    public static function add_2fa_field() {
        $user = wp_get_current_user();
        if ($user && get_user_meta($user->ID, 'securesphere_2fa_enabled', true)) {
            ?>
            <p>
                <label for="2fa_code">Two-Factor Authentication Code</label>
                <input type="text" name="2fa_code" id="2fa_code" class="input" size="20" />
            </p>
            <?php
        }
    }

    public static function verify_2fa($user, $username, $password) {
        if (!$user || is_wp_error($user)) {
            return $user;
        }
        
        if (get_user_meta($user->ID, 'securesphere_2fa_enabled', true)) {
            if (empty($_POST['2fa_code'])) {
                return new WP_Error('2fa_required', 'Two-factor authentication code is required.');
            }
            
            $secret = get_user_meta($user->ID, 'securesphere_2fa_secret', true);
            if (!self::verify_2fa_code($secret, $_POST['2fa_code'])) {
                return new WP_Error('2fa_invalid', 'Invalid two-factor authentication code.');
            }
        }
        
        return $user;
    }

    private static function generate_2fa_secret() {
        $secret = '';
        for ($i = 0; $i < 16; $i++) {
            $secret .= chr(rand(65, 90)); // A-Z
        }
        return $secret;
    }

    private static function get_2fa_qr_code_url($user, $secret) {
        $issuer = urlencode(get_bloginfo('name'));
        $account = urlencode($user->user_login);
        return "https://chart.googleapis.com/chart?cht=qr&chs=200x200&chl=otpauth://totp/{$issuer}:{$account}?secret={$secret}&issuer={$issuer}";
    }

    private static function verify_2fa_code($secret, $code) {
        // Implement TOTP verification here
        // For now, return true for testing
        return true;
    }

    public static function set_security_headers() {
        // Set security headers
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\';');
    }

    // Admin Menu and Page
    public static function add_login_security_menu() {
        add_submenu_page(
            'securesphere-mssp', // Parent slug
            'Login Security Settings', // Page title
            'Login Security', // Menu title
            'manage_options', // Capability
            'securesphere-login-security', // Menu slug
            [__CLASS__, 'render_login_security_page'] // Function
        );
    }

    public static function render_login_security_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        // Handle settings update
        if (isset($_POST['securesphere_login_settings_nonce']) && wp_verify_nonce($_POST['securesphere_login_settings_nonce'], 'securesphere_login_settings_action')) {
            if (isset($_POST[self::$max_attempts_option])) {
                update_option(self::$max_attempts_option, absint($_POST[self::$max_attempts_option]));
            }
            if (isset($_POST[self::$lockout_time_option])) {
                 // Value from form is in minutes, convert to seconds for storage
                update_option(self::$lockout_time_option, absint($_POST[self::$lockout_time_option]) * 60);
            }
            if (isset($_POST[self::$captcha_attempts_option])) {
                update_option(self::$captcha_attempts_option, absint($_POST[self::$captcha_attempts_option]));
            }
            // Save new XML-RPC and REST settings
            if (isset($_POST[self::OPT_XMLRPC_DISABLE])) {
                update_option(self::OPT_XMLRPC_DISABLE, sanitize_text_field($_POST[self::OPT_XMLRPC_DISABLE]));
            }
            update_option(self::OPT_REST_LOGIN_BRUTE_FORCE, isset($_POST[self::OPT_REST_LOGIN_BRUTE_FORCE]));

            echo '<div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>';
            // No need for self::load_settings(); as settings are fetched with get_option directly.
            // However, if XML-RPC settings changed, we might need to re-evaluate hooks if they were conditional (they are in init)
            // A page reload would be simplest, or re-call init logic if possible. For now, user might need to reload to see XML-RPC filter changes take effect if they were just enabled/disabled.
        }
        
        $max_attempts_val = self::get_max_attempts();
        $lockout_time_val_seconds = self::get_lockout_time();
        $captcha_attempts_val = self::get_captcha_attempts_threshold();
        $xmlrpc_setting_val = get_option(self::OPT_XMLRPC_DISABLE, 'none');
        $rest_brute_force_enabled_val = get_option(self::OPT_REST_LOGIN_BRUTE_FORCE, true);
        $login_log = get_option(self::$login_log_option, []);

        ?>
        <div class="wrap">
            <h1>Login Security Settings</h1>
            <form method="post" action="">
                <?php wp_nonce_field('securesphere_login_settings_action', 'securesphere_login_settings_nonce'); ?>
                
                <h2>Brute Force Protection (Standard Login)</h2>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row"><label for="<?php echo self::$max_attempts_option; ?>">Max Login Attempts</label></th>
                        <td><input type="number" id="<?php echo self::$max_attempts_option; ?>" name="<?php echo self::$max_attempts_option; ?>" value="<?php echo esc_attr($max_attempts_val); ?>" min="1" />
                        <p class="description">Number of failed attempts before an IP is locked out.</p></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><label for="<?php echo self::$lockout_time_option; ?>">Lockout Time (minutes)</label></th>
                        <td><input type="number" id="<?php echo self::$lockout_time_option; ?>" name="<?php echo self::$lockout_time_option; ?>" value="<?php echo esc_attr($lockout_time_val_seconds / 60); ?>" min="1" />
                        <p class="description">Duration for which an IP is locked out after exceeding max attempts.</p></td>
                    </tr>
                     <tr valign="top">
                        <th scope="row"><label for="<?php echo self::$captcha_attempts_option; ?>">Show CAPTCHA After Attempts</label></th>
                        <td><input type="number" id="<?php echo self::$captcha_attempts_option; ?>" name="<?php echo self::$captcha_attempts_option; ?>" value="<?php echo esc_attr($captcha_attempts_val); ?>" min="0" />
                        <p class="description">Number of failed attempts before showing a CAPTCHA. Set to 0 to disable. (Note: CAPTCHA display is currently a placeholder).</p></td>
                    </tr>
                </table>

                <h2>XML-RPC & REST API Login Protection</h2>
                 <table class="form-table">
                    <tr valign="top">
                        <th scope="row"><label for="<?php echo self::OPT_XMLRPC_DISABLE; ?>">XML-RPC Control</label></th>
                        <td>
                            <select name="<?php echo self::OPT_XMLRPC_DISABLE; ?>" id="<?php echo self::OPT_XMLRPC_DISABLE; ?>">
                                <option value="none" <?php selected($xmlrpc_setting_val, 'none'); ?>>Enable All XML-RPC Features</option>
                                <option value="risky_methods" <?php selected($xmlrpc_setting_val, 'risky_methods'); ?>>Disable Only Risky XML-RPC Methods</option>
                                <option value="all" <?php selected($xmlrpc_setting_val, 'all'); ?>>Disable XML-RPC Entirely</option>
                            </select>
                            <p class="description">Control access to XML-RPC. Disabling it can enhance security but may affect plugins/apps that use it (e.g., Jetpack, mobile apps).</p>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Apply Brute Force to REST API (Application Passwords)</th>
                        <td><input type="checkbox" name="<?php echo self::OPT_REST_LOGIN_BRUTE_FORCE; ?>" value="1" <?php checked($rest_brute_force_enabled_val); ?> />
                        <p class="description">Extend brute force protection to login attempts made via REST API using Application Passwords.</p></td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </form>

            <h2>Failed Login Attempts Log</h2>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Username</th>
                        <th>IP Address</th>
                        <th>User Agent</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($login_log)): ?>
                        <tr><td colspan="4">No failed login attempts recorded.</td></tr>
                    <?php else: ?>
                        <?php foreach (array_reverse($login_log) as $entry): ?>
                            <tr>
                                <td><?php echo esc_html($entry['time']); ?></td>
                                <td><?php echo esc_html($entry['username']); ?></td>
                                <td><?php echo esc_html($entry['ip']); ?></td>
                                <td><?php echo esc_html($entry['user_agent']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
}