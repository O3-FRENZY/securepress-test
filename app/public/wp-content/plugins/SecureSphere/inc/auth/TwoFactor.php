<?php
/**
 * SecureSphere Two-Factor Authentication Module
 * Handles 2FA functionality using TOTP (Time-based One-Time Password)
 */

class SecureSphere_TwoFactor {
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
        
        // Initialize 2FA hooks
        add_action('show_user_profile', array($this, 'show_2fa_settings'));
        add_action('edit_user_profile', array($this, 'show_2fa_settings'));
        add_action('personal_options_update', array($this, 'save_2fa_settings'));
        add_action('edit_user_profile_update', array($this, 'save_2fa_settings'));
        add_action('wp_login', array($this, 'check_2fa_required'), 10, 2);
        add_action('login_form_2fa', array($this, 'show_2fa_form'));
        add_action('login_form_2fa_validate', array($this, 'validate_2fa'));
        
        // Add 2FA setup AJAX endpoints
        add_action('wp_ajax_securesphere_generate_2fa_secret', array($this, 'ajax_generate_secret'));
        add_action('wp_ajax_securesphere_verify_2fa_setup', array($this, 'ajax_verify_setup'));
    }
    
    public function show_2fa_settings($user) {
        if (!current_user_can('edit_user', $user->ID)) {
            return;
        }
        
        $is_enabled = get_user_meta($user->ID, 'securesphere_2fa_enabled', true);
        $secret = get_user_meta($user->ID, 'securesphere_2fa_secret', true);
        
        if (!$secret) {
            $secret = $this->generate_secret();
        }
        
        ?>
        <h2>Two-Factor Authentication</h2>
        <table class="form-table">
            <tr>
                <th scope="row">2FA Status</th>
                <td>
                    <label>
                        <input type="checkbox" name="securesphere_2fa_enabled" value="1" <?php checked($is_enabled, '1'); ?>>
                        Enable Two-Factor Authentication
                    </label>
                </td>
            </tr>
            <?php if ($is_enabled): ?>
            <tr>
                <th scope="row">2FA Secret</th>
                <td>
                    <code><?php echo esc_html($secret); ?></code>
                    <p class="description">Scan this secret with your authenticator app.</p>
                </td>
            </tr>
            <?php endif; ?>
        </table>
        <?php
    }
    
    public function save_2fa_settings($user_id) {
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }
        
        $enabled = isset($_POST['securesphere_2fa_enabled']) ? '1' : '0';
        $old_enabled = get_user_meta($user_id, 'securesphere_2fa_enabled', true);
        
        if ($enabled !== $old_enabled) {
            update_user_meta($user_id, 'securesphere_2fa_enabled', $enabled);
            
            if ($enabled === '1') {
                $secret = $this->generate_secret();
                update_user_meta($user_id, 'securesphere_2fa_secret', $secret);
                
                // Log security event
                $this->db->log_security_event(array(
                    'event_type' => '2fa_enabled',
                    'severity' => 'info',
                    'source' => 'auth',
                    'details' => json_encode(array(
                        'user_id' => $user_id
                    ))
                ));
            } else {
                delete_user_meta($user_id, 'securesphere_2fa_secret');
                
                // Log security event
                $this->db->log_security_event(array(
                    'event_type' => '2fa_disabled',
                    'severity' => 'warning',
                    'source' => 'auth',
                    'details' => json_encode(array(
                        'user_id' => $user_id
                    ))
                ));
            }
        }
    }
    
    public function check_2fa_required($user_login, $user) {
        if (!$user || !is_object($user)) {
            return;
        }
        
        $is_enabled = get_user_meta($user->ID, 'securesphere_2fa_enabled', true);
        
        if ($is_enabled === '1') {
            // Store user ID in session for 2FA verification
            $_SESSION['securesphere_2fa_user_id'] = $user->ID;
            
            // Redirect to 2FA verification page
            wp_redirect(home_url('wp-login.php?action=2fa'));
            exit;
        }
    }
    
    public function show_2fa_form() {
        if (!isset($_SESSION['securesphere_2fa_user_id'])) {
            wp_redirect(wp_login_url());
            exit;
        }
        
        $user_id = $_SESSION['securesphere_2fa_user_id'];
        $user = get_user_by('id', $user_id);
        
        if (!$user) {
            wp_redirect(wp_login_url());
            exit;
        }
        
        ?>
        <div id="login">
            <h1>Two-Factor Authentication</h1>
            <form name="loginform" id="loginform" action="<?php echo esc_url(site_url('wp-login.php?action=2fa_validate', 'login_post')); ?>" method="post">
                <p>
                    <label for="2fa_code">Authentication Code</label>
                    <input type="text" name="2fa_code" id="2fa_code" class="input" size="20" required>
                </p>
                <p class="submit">
                    <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Verify">
                </p>
            </form>
        </div>
        <?php
    }
    
    public function validate_2fa() {
        if (!isset($_SESSION['securesphere_2fa_user_id'])) {
            wp_redirect(wp_login_url());
            exit;
        }
        
        $user_id = $_SESSION['securesphere_2fa_user_id'];
        $user = get_user_by('id', $user_id);
        
        if (!$user) {
            wp_redirect(wp_login_url());
            exit;
        }
        
        $code = isset($_POST['2fa_code']) ? sanitize_text_field($_POST['2fa_code']) : '';
        $secret = get_user_meta($user_id, 'securesphere_2fa_secret', true);
        
        if ($this->verify_code($secret, $code)) {
            // Clear 2FA session
            unset($_SESSION['securesphere_2fa_user_id']);
            
            // Log successful 2FA
            $this->db->log_security_event(array(
                'event_type' => '2fa_success',
                'severity' => 'info',
                'source' => 'auth',
                'details' => json_encode(array(
                    'user_id' => $user_id
                ))
            ));
            
            // Complete login
            wp_set_auth_cookie($user_id);
            wp_redirect(admin_url());
            exit;
        } else {
            // Log failed 2FA attempt
            $this->db->log_security_event(array(
                'event_type' => '2fa_failed',
                'severity' => 'warning',
                'source' => 'auth',
                'details' => json_encode(array(
                    'user_id' => $user_id
                ))
            ));
            
            wp_die('Invalid authentication code. Please try again.');
        }
    }
    
    public function ajax_generate_secret() {
        check_ajax_referer('securesphere_2fa_nonce', 'nonce');
        
        if (!current_user_can('edit_user', get_current_user_id())) {
            wp_send_json_error('Unauthorized');
        }
        
        $secret = $this->generate_secret();
        update_user_meta(get_current_user_id(), 'securesphere_2fa_secret', $secret);
        
        wp_send_json_success(array(
            'secret' => $secret,
            'qr_code' => $this->generate_qr_code($secret)
        ));
    }
    
    public function ajax_verify_setup() {
        check_ajax_referer('securesphere_2fa_nonce', 'nonce');
        
        if (!current_user_can('edit_user', get_current_user_id())) {
            wp_send_json_error('Unauthorized');
        }
        
        $code = isset($_POST['code']) ? sanitize_text_field($_POST['code']) : '';
        $secret = get_user_meta(get_current_user_id(), 'securesphere_2fa_secret', true);
        
        if ($this->verify_code($secret, $code)) {
            wp_send_json_success('2FA setup verified successfully');
        } else {
            wp_send_json_error('Invalid authentication code');
        }
    }
    
    private function generate_secret() {
        $secret = '';
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        
        for ($i = 0; $i < 16; $i++) {
            $secret .= $chars[random_int(0, strlen($chars) - 1)];
        }
        
        return $secret;
    }
    
    private function verify_code($secret, $code) {
        if (empty($secret) || empty($code)) {
            return false;
        }
        
        // Get current timestamp
        $timestamp = floor(time() / 30);
        
        // Check current and adjacent time slots
        for ($i = -1; $i <= 1; $i++) {
            $calculated_code = $this->generate_totp($secret, $timestamp + $i);
            if ($this->timing_safe_equals($calculated_code, $code)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function generate_totp($secret, $timestamp) {
        // Convert secret to binary
        $secret = $this->base32_decode($secret);
        
        // Pack timestamp into binary string
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timestamp);
        
        // Generate HMAC-SHA1
        $hmac = hash_hmac('sha1', $time, $secret, true);
        
        // Get offset
        $offset = ord(substr($hmac, -1)) & 0x0F;
        
        // Get 4 bytes from offset
        $hashpart = substr($hmac, $offset, 4);
        
        // Unpack binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        
        // Get 32 bits
        $value = $value & 0x7FFFFFFF;
        
        // Generate 6 digit code
        $modulo = pow(10, 6);
        return str_pad($value % $modulo, 6, '0', STR_PAD_LEFT);
    }
    
    private function base32_decode($secret) {
        $base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $base32charsFlipped = array_flip(str_split($base32chars));
        
        $paddingCharCount = substr_count($secret, $base32chars[0]);
        $allowedValues = array(6, 4, 3, 1, 0);
        
        if (!in_array($paddingCharCount, $allowedValues)) {
            return false;
        }
        
        for ($i = 0; $i < 4; $i++) {
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[0], $allowedValues[$i])) {
                return false;
            }
        }
        
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        
        $binaryString = '';
        for ($i = 0; $i < count($secret); $i = $i + 8) {
            $x = '';
            if (!in_array($secret[$i], array_keys($base32charsFlipped))) {
                return false;
            }
            
            for ($j = 0; $j < 8; $j++) {
                $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); $z++) {
                $binaryString .= (($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : '';
            }
        }
        
        return $binaryString;
    }
    
    private function timing_safe_equals($safe_string, $user_string) {
        if (function_exists('hash_equals')) {
            return hash_equals($safe_string, $user_string);
        }
        
        $safe_len = strlen($safe_string);
        $user_len = strlen($user_string);
        
        if ($user_len != $safe_len) {
            return false;
        }
        
        $result = 0;
        for ($i = 0; $i < $user_len; $i++) {
            $result |= (ord($safe_string[$i]) ^ ord($user_string[$i]));
        }
        
        return $result === 0;
    }
    
    private function generate_qr_code($secret) {
        $issuer = urlencode(get_bloginfo('name'));
        $user = urlencode(wp_get_current_user()->user_login);
        $secret = urlencode($secret);
        
        return "otpauth://totp/{$issuer}:{$user}?secret={$secret}&issuer={$issuer}";
    }
} 