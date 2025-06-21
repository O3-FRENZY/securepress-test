<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * SecureSphere Login Security Module
 * Handles login attempt limiting and other login-related security features
 */

class SecureSphere_LoginSecurity {
    private static $instance = null;
    private $config;
    private $logger;
    private $db;
    
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
        
        // Initialize login security hooks
        add_action('admin_init', array($this, 'register_login_security_settings'));
        add_filter('authenticate', array($this, 'check_login_attempts'), 30, 3);
        add_action('wp_login', array($this, 'log_successful_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'log_failed_login'));
        add_action('init', array($this, 'check_session_security'));
        add_action('wp_logout', array($this, 'handle_logout'));
        
        // Add remember me functionality
        add_filter('auth_cookie_expiration', array($this, 'set_auth_cookie_expiration'), 10, 3);
        add_action('set_auth_cookie', array($this, 'log_auth_cookie_set'), 10, 6);
        
        add_action('admin_init', array($this, 'init_settings'));
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_scripts'));

        // Clear any existing IP blocks for admin users
        $this->clear_admin_ip_blocks();
    }
    
    public function register_login_security_settings() {
        register_setting('securesphere_login_security', 'securesphere_max_login_attempts');
        register_setting('securesphere_login_security', 'securesphere_lockout_duration');
        register_setting('securesphere_login_security', 'securesphere_session_timeout');
        register_setting('securesphere_login_security', 'securesphere_remember_me_duration');
        register_setting('securesphere_login_security', 'securesphere_enable_ip_whitelist');
        register_setting('securesphere_login_security', 'securesphere_ip_whitelist');
    }
    
    public function check_login_attempts($user, $username, $password) {
        // If user is already authenticated, return them
        if (is_a($user, 'WP_User')) {
            return $user;
        }

        // If there's already an error, return it
        if (is_wp_error($user)) {
            return $user;
        }

        // Get the user by username
        $user_obj = get_user_by('login', $username);
        
        // If this is an admin user, bypass security checks
        if ($user_obj && user_can($user_obj->ID, 'manage_options')) {
            return $user;
        }

        $ip = $this->get_client_ip();
        
        // Check if IP is whitelisted
        if ($this->is_ip_whitelisted($ip)) {
            return $user;
        }
        
        // Check if IP is blocked
        if ($this->is_ip_blocked($ip)) {
            $this->db->log_security_event(array(
                'event_type' => 'login_blocked',
                'severity' => 'warning',
                'source' => 'auth',
                'details' => json_encode(array(
                    'ip' => $ip,
                    'username' => $username
                ))
            ));
            
            return new WP_Error('ip_blocked', 'Too many failed login attempts. Please try again later.');
        }
        
        return $user;
    }
    
    public function log_successful_login($user_login, $user) {
        $ip = $this->get_client_ip();
        
        // Reset failed attempts
        $this->reset_failed_attempts($ip);
        
        // Log successful login
        $this->db->log_security_event(array(
            'event_type' => 'login_success',
            'severity' => 'info',
            'source' => 'auth',
            'details' => json_encode(array(
                'ip' => $ip,
                'username' => $user_login,
                'user_id' => $user->ID
            ))
        ));
        
        // Update last login time
        update_user_meta($user->ID, 'securesphere_last_login', time());
        update_user_meta($user->ID, 'securesphere_last_login_ip', $ip);
    }
    
    public function log_failed_login($username) {
        // Get the user by username
        $user = get_user_by('login', $username);
        
        // If this is an admin user, don't log failed attempts
        if ($user && user_can($user->ID, 'manage_options')) {
            return;
        }

        $ip = $this->get_client_ip();
        
        // Increment failed attempts
        $attempts = $this->increment_failed_attempts($ip);
        
        // Log failed attempt
        $this->db->log_security_event(array(
            'event_type' => 'login_failed',
            'severity' => 'warning',
            'source' => 'auth',
            'details' => json_encode(array(
                'ip' => $ip,
                'username' => $username,
                'attempts' => $attempts
            ))
        ));
        
        // Check if IP should be blocked
        $max_attempts = $this->config->get_option('max_login_attempts', 5);
        if ($attempts >= $max_attempts) {
            $this->block_ip($ip);
        }
    }
    
    private function increment_failed_attempts($ip) {
        $attempts = get_transient('securesphere_failed_attempts_' . $ip);
        if (false === $attempts) {
            $attempts = 1;
        } else {
            $attempts++;
        }
        
        set_transient('securesphere_failed_attempts_' . $ip, $attempts, HOUR_IN_SECONDS);
        return $attempts;
    }
    
    private function reset_failed_attempts($ip) {
        delete_transient('securesphere_failed_attempts_' . $ip);
    }
    
    private function block_ip($ip) {
        $lockout_duration = $this->config->get_option('lockout_duration', 30) * MINUTE_IN_SECONDS;
        set_transient('securesphere_blocked_ip_' . $ip, true, $lockout_duration);
    }
    
    private function is_ip_blocked($ip) {
        return get_transient('securesphere_blocked_ip_' . $ip) !== false;
    }
    
    private function is_ip_whitelisted($ip) {
        if (!$this->config->get_option('enable_ip_whitelist', false)) {
            return false;
        }
        
        $whitelist = $this->config->get_option('ip_whitelist', array());
        return in_array($ip, $whitelist);
    }
    
    public function check_session_security() {
        if (!is_user_logged_in()) {
            return;
        }
        
        $user_id = get_current_user_id();
        $session_timeout = $this->config->get_option('session_timeout', 30) * MINUTE_IN_SECONDS;
        $last_activity = get_user_meta($user_id, 'securesphere_last_activity', true);
        
        if ($last_activity && (time() - $last_activity) > $session_timeout) {
            wp_logout();
            wp_redirect(wp_login_url() . '?session_expired=1');
            exit;
        }
        
        update_user_meta($user_id, 'securesphere_last_activity', time());
    }
    
    public function handle_logout() {
        $user_id = get_current_user_id();
        if ($user_id) {
            $this->db->log_security_event(array(
                'event_type' => 'logout',
                'severity' => 'info',
                'source' => 'auth',
                'details' => json_encode(array(
                    'user_id' => $user_id,
                    'ip' => $this->get_client_ip()
                ))
            ));
        }
    }
    
    public function set_auth_cookie_expiration($expiration, $user_id, $remember) {
        if ($remember) {
            $remember_duration = $this->config->get_option('remember_me_duration', 30) * DAY_IN_SECONDS;
            return $remember_duration;
        }
        
        return $expiration;
    }
    
    public function log_auth_cookie_set($auth_cookie, $expire, $expiration, $user_id, $scheme, $token) {
        $this->db->log_security_event(array(
            'event_type' => 'auth_cookie_set',
            'severity' => 'info',
            'source' => 'auth',
            'details' => json_encode(array(
                'user_id' => $user_id,
                'expire' => $expire,
                'scheme' => $scheme
            ))
        ));
    }
    
    private function get_client_ip() {
        $ip = '';
        
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED'];
        } elseif (isset($_SERVER['HTTP_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_FORWARDED'])) {
            $ip = $_SERVER['HTTP_FORWARDED'];
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        return $ip;
    }
    
    public function get_login_stats($user_id = null) {
        global $wpdb;
        
        $stats = array(
            'total_logins' => 0,
            'failed_attempts' => 0,
            'last_login' => null,
            'last_login_ip' => null,
            'current_session' => null
        );
        
        if ($user_id) {
            // Get user-specific stats
            $stats['total_logins'] = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->usermeta} 
                WHERE user_id = %d AND meta_key = 'securesphere_last_login'",
                $user_id
            ));
            
            $stats['last_login'] = get_user_meta($user_id, 'securesphere_last_login', true);
            $stats['last_login_ip'] = get_user_meta($user_id, 'securesphere_last_login_ip', true);
            $stats['current_session'] = get_user_meta($user_id, 'securesphere_last_activity', true);
        } else {
            // Get global stats
            $stats['total_logins'] = $wpdb->get_var(
                "SELECT COUNT(*) FROM {$wpdb->usermeta} 
                WHERE meta_key = 'securesphere_last_login'"
            );
            
            $stats['failed_attempts'] = $wpdb->get_var(
                "SELECT COUNT(*) FROM {$wpdb->usermeta} 
                WHERE meta_key = 'securesphere_failed_attempts'"
            );
        }
        
        return $stats;
    }
    
    public function init_settings() {
        register_setting('securesphere_login_settings', 'securesphere_login_protection');
        register_setting('securesphere_login_settings', 'securesphere_login_attempts');
        register_setting('securesphere_login_settings', 'securesphere_login_lockout');
    }
    
    public function enqueue_login_scripts() {
        wp_enqueue_style('securesphere-login', SECURESPHERE_PLUGIN_URL . 'assets/css/login.css', array(), SECURESPHERE_VERSION);
    }
    
    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        try {
            // Get login security settings
            $settings = get_option('securesphere_login_security', array(
                'max_attempts' => 5,
                'lockout_duration' => 30,
                'enable_captcha' => false,
                'enable_2fa' => false
            ));
            ?>
            <div class="wrap">
                <h1>Login Security Settings</h1>
                
                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Login Protection</h2>
                    </div>
                    <div class="ss-card-body">
                        <form method="post" action="options.php">
                            <?php settings_fields('securesphere_login_security'); ?>
                            
                            <table class="form-table">
                                <tr>
                                    <th scope="row">Maximum Login Attempts</th>
                                    <td>
                                        <input type="number" name="securesphere_login_security[max_attempts]" 
                                            value="<?php echo esc_attr($settings['max_attempts']); ?>" 
                                            min="1" max="10">
                                        <p class="description">Number of failed attempts before lockout</p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">Lockout Duration (minutes)</th>
                                    <td>
                                        <input type="number" name="securesphere_login_security[lockout_duration]" 
                                            value="<?php echo esc_attr($settings['lockout_duration']); ?>" 
                                            min="5" max="1440">
                                        <p class="description">How long to lock out IP after max attempts</p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">Enable CAPTCHA</th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="securesphere_login_security[enable_captcha]" 
                                                value="1" <?php checked($settings['enable_captcha']); ?>>
                                            Enable CAPTCHA on login form
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">Enable Two-Factor Authentication</th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="securesphere_login_security[enable_2fa]" 
                                                value="1" <?php checked($settings['enable_2fa']); ?>>
                                            Enable 2FA for admin users
                                        </label>
                                    </td>
                                </tr>
                            </table>
                            
                            <?php submit_button('Save Settings'); ?>
                        </form>
                    </div>
                </div>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Recent Login Activity</h2>
                    </div>
                    <div class="ss-card-body">
                        <?php
                        $recent_logins = $this->get_recent_logins();
                        if (empty($recent_logins)): ?>
                            <p>No recent login activity found.</p>
                        <?php else: ?>
                            <table class="wp-list-table widefat fixed striped">
                                <thead>
                                    <tr>
                                        <th>User</th>
                                        <th>IP Address</th>
                                        <th>Date</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($recent_logins as $login): ?>
                                        <tr>
                                            <td><?php echo esc_html($login['username']); ?></td>
                                            <td><?php echo esc_html($login['ip']); ?></td>
                                            <td><?php echo esc_html($login['date']); ?></td>
                                            <td>
                                                <span class="ss-status ss-status-<?php echo esc_attr($login['status']); ?>">
                                                    <?php echo esc_html($login['status']); ?>
                                                </span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <?php
        } catch (Exception $e) {
            error_log('SecureSphere Login Security Error: ' . $e->getMessage());
            ?>
            <div class="wrap">
                <h1>Login Security Settings</h1>
                <div class="notice notice-error">
                    <p>An error occurred while loading the login security page. Please try again later.</p>
                </div>
            </div>
            <?php
        }
    }
    
    private function get_recent_logins() {
        // This is a placeholder - implement actual login history retrieval
        return array();
    }

    private function clear_admin_ip_blocks() {
        global $wpdb;
        
        // Get all admin users
        $admin_users = get_users(array('role' => 'administrator'));
        
        foreach ($admin_users as $admin) {
            $admin_ip = get_user_meta($admin->ID, 'securesphere_last_login_ip', true);
            if ($admin_ip) {
                // Clear any blocks for this IP
                delete_transient('securesphere_blocked_ip_' . $admin_ip);
                delete_transient('securesphere_failed_attempts_' . $admin_ip);
            }
        }
    }
} 