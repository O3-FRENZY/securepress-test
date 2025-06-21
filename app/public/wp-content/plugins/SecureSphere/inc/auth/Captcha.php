<?php
/**
 * SecureSphere CAPTCHA Module
 * Handles CAPTCHA integration for forms
 */

class SecureSphere_Captcha {
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
        
        // Initialize CAPTCHA hooks
        add_action('login_form', array($this, 'add_login_captcha'));
        add_action('register_form', array($this, 'add_register_captcha'));
        add_action('lostpassword_form', array($this, 'add_lostpassword_captcha'));
        add_action('comment_form', array($this, 'add_comment_captcha'));
        
        // Validate CAPTCHA
        add_filter('authenticate', array($this, 'validate_login_captcha'), 30, 3);
        add_action('register_post', array($this, 'validate_register_captcha'), 10, 3);
        add_action('lostpassword_post', array($this, 'validate_lostpassword_captcha'));
        add_action('preprocess_comment', array($this, 'validate_comment_captcha'));
        
        // Add CAPTCHA settings to admin
        add_action('admin_init', array($this, 'register_captcha_settings'));
    }
    
    public function register_captcha_settings() {
        register_setting('securesphere_captcha', 'securesphere_captcha_provider');
        register_setting('securesphere_captcha', 'securesphere_captcha_site_key');
        register_setting('securesphere_captcha', 'securesphere_captcha_secret_key');
        register_setting('securesphere_captcha', 'securesphere_captcha_forms');
    }
    
    public function add_login_captcha() {
        if (!$this->is_captcha_enabled('login')) {
            return;
        }
        
        $this->render_captcha();
    }
    
    public function add_register_captcha() {
        if (!$this->is_captcha_enabled('register')) {
            return;
        }
        
        $this->render_captcha();
    }
    
    public function add_lostpassword_captcha() {
        if (!$this->is_captcha_enabled('lostpassword')) {
            return;
        }
        
        $this->render_captcha();
    }
    
    public function add_comment_captcha() {
        if (!$this->is_captcha_enabled('comment')) {
            return;
        }
        
        $this->render_captcha();
    }
    
    private function render_captcha() {
        $provider = $this->config->get_option('captcha_provider', 'recaptcha');
        $site_key = $this->config->get_option('captcha_site_key');
        
        if (!$site_key) {
            return;
        }
        
        switch ($provider) {
            case 'recaptcha':
                $this->render_recaptcha($site_key);
                break;
            case 'hcaptcha':
                $this->render_hcaptcha($site_key);
                break;
            case 'turnstile':
                $this->render_turnstile($site_key);
                break;
        }
    }
    
    private function render_recaptcha($site_key) {
        wp_enqueue_script('recaptcha', 'https://www.google.com/recaptcha/api.js', array(), null, true);
        ?>
        <div class="g-recaptcha" data-sitekey="<?php echo esc_attr($site_key); ?>"></div>
        <?php
    }
    
    private function render_hcaptcha($site_key) {
        wp_enqueue_script('hcaptcha', 'https://js.hcaptcha.com/1/api.js', array(), null, true);
        ?>
        <div class="h-captcha" data-sitekey="<?php echo esc_attr($site_key); ?>"></div>
        <?php
    }
    
    private function render_turnstile($site_key) {
        wp_enqueue_script('turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), null, true);
        ?>
        <div class="cf-turnstile" data-sitekey="<?php echo esc_attr($site_key); ?>"></div>
        <?php
    }
    
    public function validate_login_captcha($user, $username, $password) {
        if (!$this->is_captcha_enabled('login')) {
            return $user;
        }
        
        if (!$this->verify_captcha()) {
            // Log failed CAPTCHA attempt
            $this->db->log_security_event(array(
                'event_type' => 'captcha_failed',
                'severity' => 'warning',
                'source' => 'auth',
                'details' => json_encode(array(
                    'form' => 'login',
                    'username' => $username
                ))
            ));
            
            return new WP_Error('captcha_failed', 'CAPTCHA verification failed. Please try again.');
        }
        
        return $user;
    }
    
    public function validate_register_captcha($username, $email, $errors) {
        if (!$this->is_captcha_enabled('register')) {
            return;
        }
        
        if (!$this->verify_captcha()) {
            // Log failed CAPTCHA attempt
            $this->db->log_security_event(array(
                'event_type' => 'captcha_failed',
                'severity' => 'warning',
                'source' => 'auth',
                'details' => json_encode(array(
                    'form' => 'register',
                    'email' => $email
                ))
            ));
            
            $errors->add('captcha_failed', 'CAPTCHA verification failed. Please try again.');
        }
    }
    
    public function validate_lostpassword_captcha() {
        if (!$this->is_captcha_enabled('lostpassword')) {
            return;
        }
        
        if (!$this->verify_captcha()) {
            // Log failed CAPTCHA attempt
            $this->db->log_security_event(array(
                'event_type' => 'captcha_failed',
                'severity' => 'warning',
                'source' => 'auth',
                'details' => json_encode(array(
                    'form' => 'lostpassword'
                ))
            ));
            
            wp_die('CAPTCHA verification failed. Please try again.');
        }
    }
    
    public function validate_comment_captcha($commentdata) {
        if (!$this->is_captcha_enabled('comment')) {
            return $commentdata;
        }
        
        if (!$this->verify_captcha()) {
            // Log failed CAPTCHA attempt
            $this->db->log_security_event(array(
                'event_type' => 'captcha_failed',
                'severity' => 'warning',
                'source' => 'auth',
                'details' => json_encode(array(
                    'form' => 'comment',
                    'author' => $commentdata['comment_author']
                ))
            ));
            
            wp_die('CAPTCHA verification failed. Please try again.');
        }
        
        return $commentdata;
    }
    
    private function verify_captcha() {
        $provider = $this->config->get_option('captcha_provider', 'recaptcha');
        $secret_key = $this->config->get_option('captcha_secret_key');
        
        if (!$secret_key) {
            return false;
        }
        
        $response = isset($_POST['g-recaptcha-response']) ? $_POST['g-recaptcha-response'] : 
                   (isset($_POST['h-captcha-response']) ? $_POST['h-captcha-response'] : 
                   (isset($_POST['cf-turnstile-response']) ? $_POST['cf-turnstile-response'] : ''));
        
        if (empty($response)) {
            return false;
        }
        
        switch ($provider) {
            case 'recaptcha':
                return $this->verify_recaptcha($response, $secret_key);
            case 'hcaptcha':
                return $this->verify_hcaptcha($response, $secret_key);
            case 'turnstile':
                return $this->verify_turnstile($response, $secret_key);
            default:
                return false;
        }
    }
    
    private function verify_recaptcha($response, $secret_key) {
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = array(
            'secret' => $secret_key,
            'response' => $response,
            'remoteip' => $_SERVER['REMOTE_ADDR']
        );
        
        $response = wp_remote_post($url, array(
            'body' => $data
        ));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        $result = json_decode($body, true);
        
        return isset($result['success']) && $result['success'] === true;
    }
    
    private function verify_hcaptcha($response, $secret_key) {
        $url = 'https://hcaptcha.com/siteverify';
        $data = array(
            'secret' => $secret_key,
            'response' => $response,
            'remoteip' => $_SERVER['REMOTE_ADDR']
        );
        
        $response = wp_remote_post($url, array(
            'body' => $data
        ));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        $result = json_decode($body, true);
        
        return isset($result['success']) && $result['success'] === true;
    }
    
    private function verify_turnstile($response, $secret_key) {
        $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        $data = array(
            'secret' => $secret_key,
            'response' => $response,
            'remoteip' => $_SERVER['REMOTE_ADDR']
        );
        
        $response = wp_remote_post($url, array(
            'body' => $data
        ));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        $result = json_decode($body, true);
        
        return isset($result['success']) && $result['success'] === true;
    }
    
    private function is_captcha_enabled($form) {
        $enabled_forms = $this->config->get_option('captcha_forms', array());
        return in_array($form, $enabled_forms);
    }
} 