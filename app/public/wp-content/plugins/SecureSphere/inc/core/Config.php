<?php
/**
 * SecureSphere Configuration Module
 * Handles all plugin configuration and settings
 */

class SecureSphere_Config {
    private static $instance = null;
    private $options = array();
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->load_options();
    }
    
    public static function set_defaults() {
        $defaults = array(
            // Firewall settings
            'firewall_enabled' => true,
            'country_blocking_enabled' => false,
            'ip_reputation_enabled' => true,
            'rate_limiting_enabled' => true,
            'custom_rules_enabled' => false,
            
            // Malware scanning settings
            'malware_scanning_enabled' => true,
            'file_integrity_enabled' => true,
            'backdoor_detection_enabled' => true,
            'pattern_detection_enabled' => true,
            'scan_schedule' => 'daily',
            
            // Authentication settings
            'two_factor_enabled' => false,
            'captcha_enabled' => true,
            'password_policy_enabled' => true,
            'login_attempt_limiting' => true,
            'remember_me_enabled' => true,
            
            // Monitoring settings
            'traffic_analysis_enabled' => true,
            'geo_visualization_enabled' => true,
            'user_activity_tracking' => true,
            'bot_detection_enabled' => true,
            
            // Security tools settings
            'database_security_enabled' => true,
            'file_system_security_enabled' => true,
            'security_hardening_enabled' => true,
            'audit_logging_enabled' => true,
            'incident_response_enabled' => true,
            
            // Alerting settings
            'email_notifications_enabled' => true,
            'sms_notifications_enabled' => false,
            'alert_thresholds' => array(
                'critical' => 1,
                'high' => 3,
                'medium' => 5,
                'low' => 10
            ),
            
            // Performance settings
            'caching_enabled' => true,
            'performance_monitoring_enabled' => true,
            'resource_tracking_enabled' => true,
            
            // Reporting settings
            'report_generation_enabled' => true,
            'scheduled_reports_enabled' => false,
            'export_enabled' => true,
            
            // Integration settings
            'api_enabled' => false,
            'threat_intelligence_enabled' => true,
            'central_management_enabled' => false
        );
        
        foreach ($defaults as $key => $value) {
            if (get_option('securesphere_' . $key) === false) {
                update_option('securesphere_' . $key, $value);
            }
        }
    }
    
    private function load_options() {
        $this->options = array(
            'firewall' => $this->get_firewall_options(),
            'scanner' => $this->get_scanner_options(),
            'auth' => $this->get_auth_options(),
            'monitoring' => $this->get_monitoring_options(),
            'security' => $this->get_security_options(),
            'alerts' => $this->get_alert_options(),
            'performance' => $this->get_performance_options(),
            'reports' => $this->get_report_options(),
            'integration' => $this->get_integration_options()
        );
    }
    
    private function get_firewall_options() {
        return array(
            'enabled' => get_option('securesphere_firewall_enabled', true),
            'country_blocking' => get_option('securesphere_country_blocking_enabled', false),
            'ip_reputation' => get_option('securesphere_ip_reputation_enabled', true),
            'rate_limiting' => get_option('securesphere_rate_limiting_enabled', true),
            'custom_rules' => get_option('securesphere_custom_rules_enabled', false)
        );
    }
    
    private function get_scanner_options() {
        return array(
            'enabled' => get_option('securesphere_malware_scanning_enabled', true),
            'file_integrity' => get_option('securesphere_file_integrity_enabled', true),
            'backdoor_detection' => get_option('securesphere_backdoor_detection_enabled', true),
            'pattern_detection' => get_option('securesphere_pattern_detection_enabled', true),
            'schedule' => get_option('securesphere_scan_schedule', 'daily')
        );
    }
    
    private function get_auth_options() {
        return array(
            'two_factor' => get_option('securesphere_two_factor_enabled', false),
            'captcha' => get_option('securesphere_captcha_enabled', true),
            'password_policy' => get_option('securesphere_password_policy_enabled', true),
            'login_attempts' => get_option('securesphere_login_attempt_limiting', true),
            'remember_me' => get_option('securesphere_remember_me_enabled', true)
        );
    }
    
    private function get_monitoring_options() {
        return array(
            'traffic_analysis' => get_option('securesphere_traffic_analysis_enabled', true),
            'geo_visualization' => get_option('securesphere_geo_visualization_enabled', true),
            'user_activity' => get_option('securesphere_user_activity_tracking', true),
            'bot_detection' => get_option('securesphere_bot_detection_enabled', true)
        );
    }
    
    private function get_security_options() {
        return array(
            'database' => get_option('securesphere_database_security_enabled', true),
            'file_system' => get_option('securesphere_file_system_security_enabled', true),
            'hardening' => get_option('securesphere_security_hardening_enabled', true),
            'audit_logging' => get_option('securesphere_audit_logging_enabled', true),
            'incident_response' => get_option('securesphere_incident_response_enabled', true)
        );
    }
    
    private function get_alert_options() {
        return array(
            'email' => get_option('securesphere_email_notifications_enabled', true),
            'sms' => get_option('securesphere_sms_notifications_enabled', false),
            'thresholds' => get_option('securesphere_alert_thresholds', array(
                'critical' => 1,
                'high' => 3,
                'medium' => 5,
                'low' => 10
            ))
        );
    }
    
    private function get_performance_options() {
        return array(
            'caching' => get_option('securesphere_caching_enabled', true),
            'monitoring' => get_option('securesphere_performance_monitoring_enabled', true),
            'resource_tracking' => get_option('securesphere_resource_tracking_enabled', true)
        );
    }
    
    private function get_report_options() {
        return array(
            'generation' => get_option('securesphere_report_generation_enabled', true),
            'scheduled' => get_option('securesphere_scheduled_reports_enabled', false),
            'export' => get_option('securesphere_export_enabled', true)
        );
    }
    
    private function get_integration_options() {
        return array(
            'api' => get_option('securesphere_api_enabled', false),
            'threat_intelligence' => get_option('securesphere_threat_intelligence_enabled', true),
            'central_management' => get_option('securesphere_central_management_enabled', false)
        );
    }
    
    public function get_option($key, $default = false) {
        return get_option('securesphere_' . $key, $default);
    }
    
    public function update_option($key, $value) {
        return update_option('securesphere_' . $key, $value);
    }
    
    public function get_all_options() {
        return $this->options;
    }
} 