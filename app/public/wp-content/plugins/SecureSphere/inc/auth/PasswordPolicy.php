<?php
/**
 * SecureSphere Password Policy Module
 * Enforces strong password requirements and policies
 */

class SecureSphere_PasswordPolicy {
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
        
        // Initialize password policy hooks
        add_action('admin_init', array($this, 'register_password_policy_settings'));
        add_action('user_profile_update_errors', array($this, 'validate_password_strength'), 10, 3);
        add_action('validate_password_reset', array($this, 'validate_password_reset'), 10, 2);
        add_action('password_reset', array($this, 'log_password_reset'), 10, 2);
        add_action('profile_update', array($this, 'log_password_change'), 10, 2);
        
        // Add password strength meter
        add_action('login_enqueue_scripts', array($this, 'enqueue_password_strength_meter'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_password_strength_meter'));
    }
    
    public function register_password_policy_settings() {
        register_setting('securesphere_password_policy', 'securesphere_min_password_length');
        register_setting('securesphere_password_policy', 'securesphere_require_uppercase');
        register_setting('securesphere_password_policy', 'securesphere_require_lowercase');
        register_setting('securesphere_password_policy', 'securesphere_require_numbers');
        register_setting('securesphere_password_policy', 'securesphere_require_special_chars');
        register_setting('securesphere_password_policy', 'securesphere_password_expiry_days');
        register_setting('securesphere_password_policy', 'securesphere_password_history_count');
    }
    
    public function enqueue_password_strength_meter() {
        wp_enqueue_script('password-strength-meter');
        wp_enqueue_script('securesphere-password-policy', plugins_url('assets/js/password-policy.js', dirname(dirname(__FILE__))), array('jquery', 'password-strength-meter'), SECURESPHERE_VERSION, true);
        
        wp_localize_script('securesphere-password-policy', 'securespherePasswordPolicy', array(
            'minLength' => $this->config->get_option('min_password_length', 12),
            'requireUppercase' => $this->config->get_option('require_uppercase', true),
            'requireLowercase' => $this->config->get_option('require_lowercase', true),
            'requireNumbers' => $this->config->get_option('require_numbers', true),
            'requireSpecialChars' => $this->config->get_option('require_special_chars', true),
            'messages' => array(
                'tooShort' => 'Password is too short',
                'noUppercase' => 'Password must contain uppercase letters',
                'noLowercase' => 'Password must contain lowercase letters',
                'noNumbers' => 'Password must contain numbers',
                'noSpecialChars' => 'Password must contain special characters',
                'passwordExpired' => 'Your password has expired. Please reset it.'
            )
        ));
    }
    
    public function validate_password_strength($errors, $update, $user_data) {
        if (!empty($_POST['pass1'])) {
            $password = $_POST['pass1'];
            $validation_result = $this->validate_password($password);
            
            if (is_wp_error($validation_result)) {
                $errors->add('password_strength', $validation_result->get_error_message());
            }
        }
        
        return $errors;
    }
    
    public function validate_password_reset($errors, $user_data) {
        if (!empty($_POST['pass1'])) {
            $password = $_POST['pass1'];
            $validation_result = $this->validate_password($password);
            
            if (is_wp_error($validation_result)) {
                $errors->add('password_strength', $validation_result->get_error_message());
            }
        }
        
        return $errors;
    }
    
    private function validate_password($password) {
        $min_length = $this->config->get_option('min_password_length', 12);
        $require_uppercase = $this->config->get_option('require_uppercase', true);
        $require_lowercase = $this->config->get_option('require_lowercase', true);
        $require_numbers = $this->config->get_option('require_numbers', true);
        $require_special_chars = $this->config->get_option('require_special_chars', true);
        
        if (strlen($password) < $min_length) {
            return new WP_Error('password_too_short', sprintf('Password must be at least %d characters long.', $min_length));
        }
        
        if ($require_uppercase && !preg_match('/[A-Z]/', $password)) {
            return new WP_Error('password_no_uppercase', 'Password must contain at least one uppercase letter.');
        }
        
        if ($require_lowercase && !preg_match('/[a-z]/', $password)) {
            return new WP_Error('password_no_lowercase', 'Password must contain at least one lowercase letter.');
        }
        
        if ($require_numbers && !preg_match('/[0-9]/', $password)) {
            return new WP_Error('password_no_numbers', 'Password must contain at least one number.');
        }
        
        if ($require_special_chars && !preg_match('/[^A-Za-z0-9]/', $password)) {
            return new WP_Error('password_no_special_chars', 'Password must contain at least one special character.');
        }
        
        // Check password history
        if ($this->is_password_in_history($password)) {
            return new WP_Error('password_in_history', 'This password has been used recently. Please choose a different one.');
        }
        
        return true;
    }
    
    private function is_password_in_history($password) {
        global $wpdb;
        
        $user_id = get_current_user_id();
        $history_count = $this->config->get_option('password_history_count', 5);
        
        $history = $wpdb->get_col($wpdb->prepare(
            "SELECT password FROM {$wpdb->usermeta} 
            WHERE user_id = %d AND meta_key = 'securesphere_password_history' 
            ORDER BY meta_id DESC LIMIT %d",
            $user_id,
            $history_count
        ));
        
        foreach ($history as $hashed_password) {
            if (wp_check_password($password, $hashed_password)) {
                return true;
            }
        }
        
        return false;
    }
    
    public function log_password_reset($user, $new_password) {
        $this->update_password_history($user->ID, $new_password);
        
        $this->db->log_security_event(array(
            'event_type' => 'password_reset',
            'severity' => 'info',
            'source' => 'auth',
            'details' => json_encode(array(
                'user_id' => $user->ID,
                'username' => $user->user_login
            ))
        ));
    }
    
    public function log_password_change($user_id, $old_user_data) {
        if (!empty($_POST['pass1'])) {
            $this->update_password_history($user_id, $_POST['pass1']);
            
            $this->db->log_security_event(array(
                'event_type' => 'password_change',
                'severity' => 'info',
                'source' => 'auth',
                'details' => json_encode(array(
                    'user_id' => $user_id,
                    'username' => $old_user_data->user_login
                ))
            ));
        }
    }
    
    private function update_password_history($user_id, $password) {
        global $wpdb;
        
        $hashed_password = wp_hash_password($password);
        
        $wpdb->insert(
            $wpdb->usermeta,
            array(
                'user_id' => $user_id,
                'meta_key' => 'securesphere_password_history',
                'meta_value' => $hashed_password
            )
        );
        
        // Update password expiry
        update_user_meta($user_id, 'securesphere_password_expiry', time() + ($this->config->get_option('password_expiry_days', 90) * DAY_IN_SECONDS));
    }
    
    public function check_password_expiry($user_id) {
        $expiry_time = get_user_meta($user_id, 'securesphere_password_expiry', true);
        
        if ($expiry_time && time() > $expiry_time) {
            return true;
        }
        
        return false;
    }
    
    public function get_password_strength($password) {
        $score = 0;
        
        // Length check
        if (strlen($password) >= 12) {
            $score += 2;
        } elseif (strlen($password) >= 8) {
            $score += 1;
        }
        
        // Character type checks
        if (preg_match('/[A-Z]/', $password)) {
            $score += 1;
        }
        if (preg_match('/[a-z]/', $password)) {
            $score += 1;
        }
        if (preg_match('/[0-9]/', $password)) {
            $score += 1;
        }
        if (preg_match('/[^A-Za-z0-9]/', $password)) {
            $score += 1;
        }
        
        // Complexity check
        if (strlen(count_chars($password, 3)) > strlen($password) * 0.7) {
            $score += 1;
        }
        
        return min(5, $score);
    }
} 