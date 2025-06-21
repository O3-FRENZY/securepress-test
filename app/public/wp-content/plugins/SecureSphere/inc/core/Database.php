<?php
/**
 * SecureSphere Database Module
 * Handles database operations and security
 */

if (!defined('ABSPATH')) {
    exit;
}

class SecureSphere_Database {
    private static $instance = null;
    private $wpdb;
    private $tables;
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
        $this->tables = array(
            'logs' => $wpdb->prefix . 'securesphere_logs',
            'firewall_logs' => $wpdb->prefix . 'securesphere_firewall_logs',
            'scan_results' => $wpdb->prefix . 'securesphere_scan_results',
            'security_events' => $wpdb->prefix . 'securesphere_security_events',
            'user_activity' => $wpdb->prefix . 'securesphere_user_activity',
            'performance_metrics' => $wpdb->prefix . 'securesphere_performance_metrics',
            'blocked_ips' => $wpdb->prefix . 'securesphere_blocked_ips'
        );
    }
    
    public function create_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();
        $errors = array();

        // Create logs table
        $logs_table = $wpdb->prefix . 'securesphere_logs';
        $logs_sql = "CREATE TABLE IF NOT EXISTS $logs_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            timestamp datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            level varchar(20) NOT NULL,
            message text NOT NULL,
            ip_address varchar(45) NOT NULL,
            user_id bigint(20) DEFAULT NULL,
            request_uri varchar(255) DEFAULT NULL,
            request_method varchar(10) DEFAULT NULL,
            user_agent varchar(255) DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY level (level),
            KEY timestamp (timestamp),
            KEY ip_address (ip_address)
        ) $charset_collate;";

        // Create blocked IPs table
        $blocked_ips_table = $wpdb->prefix . 'securesphere_blocked_ips';
        $blocked_ips_sql = "CREATE TABLE IF NOT EXISTS $blocked_ips_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip varchar(45) NOT NULL,
            reason varchar(255) NOT NULL,
            blocked_until datetime NOT NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            UNIQUE KEY ip (ip),
            KEY blocked_until (blocked_until)
        ) $charset_collate;";

        // Create firewall logs table
        $firewall_logs_table = $wpdb->prefix . 'securesphere_firewall_logs';
        $firewall_logs_sql = "CREATE TABLE IF NOT EXISTS $firewall_logs_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            timestamp datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ip_address varchar(45) NOT NULL,
            request_uri varchar(255) NOT NULL,
            request_method varchar(10) NOT NULL,
            status varchar(20) NOT NULL,
            reason varchar(255) DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY ip_address (ip_address),
            KEY timestamp (timestamp)
        ) $charset_collate;";

        // Execute each table creation separately with error handling
        $tables = array(
            'logs' => $logs_sql,
            'blocked_ips' => $blocked_ips_sql,
            'firewall_logs' => $firewall_logs_sql
        );

        foreach ($tables as $table_name => $sql) {
            $result = $wpdb->query($sql);
            if ($result === false) {
                $errors[] = "Failed to create {$table_name} table: " . $wpdb->last_error;
            }
        }

        // Verify tables were created
        $required_tables = array(
            $logs_table,
            $blocked_ips_table,
            $firewall_logs_table
        );

        foreach ($required_tables as $table) {
            if ($wpdb->get_var("SHOW TABLES LIKE '$table'") != $table) {
                $errors[] = "Table $table was not created successfully";
            }
        }

        if (!empty($errors)) {
            throw new Exception(implode("\n", $errors));
        }
    }
    
    public function get_logs($filters = array()) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_logs';
        
        try {
            // Set default values and validate filters
            $defaults = array(
                'level' => '',
                'start_date' => date('Y-m-d H:i:s', strtotime('-30 days')),
                'end_date' => date('Y-m-d H:i:s'),
                'ip_address' => '',
                'limit' => 50,
                'offset' => 0
            );
            
            $filters = wp_parse_args($filters, $defaults);
            
            // Build WHERE clause with proper placeholders
            $where = array();
            $values = array();
            
            if (!empty($filters['level'])) {
                $where[] = 'level = %s';
                $values[] = sanitize_text_field($filters['level']);
            }
            
            if (!empty($filters['start_date'])) {
                $where[] = 'timestamp >= %s';
                $values[] = sanitize_text_field($filters['start_date']);
            }
            
            if (!empty($filters['end_date'])) {
                $where[] = 'timestamp <= %s';
                $values[] = sanitize_text_field($filters['end_date']);
            }
            
            if (!empty($filters['ip_address'])) {
                $where[] = 'ip_address = %s';
                $values[] = sanitize_text_field($filters['ip_address']);
            }
            
            // Build the final query
            $sql = "SELECT * FROM {$table_name}";
            
            if (!empty($where)) {
                $sql .= " WHERE " . implode(' AND ', $where);
            }
            
            $sql .= " ORDER BY timestamp DESC LIMIT %d OFFSET %d";
            $values[] = (int)$filters['limit'];
            $values[] = (int)$filters['offset'];
            
            // Execute query with proper preparation
            $results = $wpdb->get_results(
                $wpdb->prepare($sql, $values),
                ARRAY_A
            );
            
            return is_array($results) ? $results : array();
            
        } catch (Exception $e) {
            error_log('SecureSphere Database Error: ' . $e->getMessage());
            return array();
        }
    }
    
    public function get_total_logs($level = '', $date_from = '', $date_to = '') {
        try {
            $where = array();
            $values = array();
            
            if (!empty($level)) {
                $where[] = 'level = %s';
                $values[] = sanitize_text_field($level);
            }
            
            if (!empty($date_from)) {
                $where[] = 'timestamp >= %s';
                $values[] = sanitize_text_field($date_from . ' 00:00:00');
            }
            
            if (!empty($date_to)) {
                $where[] = 'timestamp <= %s';
                $values[] = sanitize_text_field($date_to . ' 23:59:59');
            }
            
            $sql = "SELECT COUNT(*) FROM {$this->tables['logs']}";
            
            if (!empty($where)) {
                $sql .= " WHERE " . implode(' AND ', $where);
            }
            
            $query = $this->wpdb->prepare($sql, $values);
            $count = $this->wpdb->get_var($query);
            
            return is_numeric($count) ? (int)$count : 0;
            
        } catch (Exception $e) {
            error_log('SecureSphere Database Error: ' . $e->getMessage());
            return 0;
        }
    }
    
    public function clear_logs() {
        $this->wpdb->query("TRUNCATE TABLE {$this->tables['logs']}");
    }
    
    public function add_log($level, $event, $details = '', $user_id = null) {
        $ip_address = $this->get_client_ip();
        
        return $this->wpdb->insert(
            $this->tables['logs'],
            array(
                'timestamp' => current_time('mysql'),
                'level' => $level,
                'event' => $event,
                'ip_address' => $ip_address,
                'user_id' => $user_id,
                'details' => $details
            ),
            array('%s', '%s', '%s', '%s', '%d', '%s')
        );
    }
    
    private function get_client_ip() {
        $ip = '';
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }
    
    public function log_firewall_event($data) {
        return $this->wpdb->insert(
            $this->tables['firewall_logs'],
            array(
                'ip_address' => $data['ip_address'],
                'country' => $data['country'] ?? null,
                'request_uri' => $data['request_uri'],
                'user_agent' => $data['user_agent'] ?? null,
                'request_method' => $data['request_method'],
                'status' => $data['status'],
                'reason' => $data['reason'] ?? null,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')
        );
    }
    
    public function log_scan_result($data) {
        return $this->wpdb->insert(
            $this->tables['scan_results'],
            array(
                'file_path' => $data['file_path'],
                'file_hash' => $data['file_hash'],
                'scan_type' => $data['scan_type'],
                'status' => $data['status'],
                'details' => $data['details'] ?? null,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%s', '%s', '%s')
        );
    }
    
    public function log_security_event($data) {
        return $this->wpdb->insert(
            $this->tables['security_events'],
            array(
                'event_type' => $data['event_type'],
                'severity' => $data['severity'],
                'source' => $data['source'],
                'details' => $data['details'] ?? null,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%s', '%s')
        );
    }
    
    public function log_user_activity($data) {
        return $this->wpdb->insert(
            $this->tables['user_activity'],
            array(
                'user_id' => $data['user_id'],
                'action' => $data['action'],
                'ip_address' => $data['ip_address'],
                'user_agent' => $data['user_agent'] ?? null,
                'details' => $data['details'] ?? null,
                'created_at' => current_time('mysql')
            ),
            array('%d', '%s', '%s', '%s', '%s', '%s')
        );
    }
    
    public function log_performance_metric($data) {
        return $this->wpdb->insert(
            $this->tables['performance_metrics'],
            array(
                'metric_type' => $data['metric_type'],
                'value' => $data['value'],
                'details' => $data['details'] ?? null,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%f', '%s', '%s')
        );
    }
    
    public function get_firewall_logs($limit = 100, $offset = 0) {
        return $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT * FROM {$this->tables['firewall_logs']} 
                ORDER BY created_at DESC 
                LIMIT %d OFFSET %d",
                $limit,
                $offset
            )
        );
    }
    
    public function get_scan_results($limit = 100, $offset = 0) {
        return $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT * FROM {$this->tables['scan_results']} 
                ORDER BY created_at DESC 
                LIMIT %d OFFSET %d",
                $limit,
                $offset
            )
        );
    }
    
    public function get_security_events($limit = 100, $offset = 0) {
        return $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT * FROM {$this->tables['security_events']} 
                ORDER BY created_at DESC 
                LIMIT %d OFFSET %d",
                $limit,
                $offset
            )
        );
    }
    
    public function get_user_activity($limit = 100, $offset = 0) {
        return $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT * FROM {$this->tables['user_activity']} 
                ORDER BY created_at DESC 
                LIMIT %d OFFSET %d",
                $limit,
                $offset
            )
        );
    }
    
    public function get_performance_metrics($metric_type, $limit = 100, $offset = 0) {
        return $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT * FROM {$this->tables['performance_metrics']} 
                WHERE metric_type = %s 
                ORDER BY created_at DESC 
                LIMIT %d OFFSET %d",
                $metric_type,
                $limit,
                $offset
            )
        );
    }
    
    public function cleanup_old_logs($days = 30) {
        $tables = array(
            'firewall_logs',
            'scan_results',
            'security_events',
            'user_activity',
            'performance_metrics'
        );
        
        foreach ($tables as $table) {
            $this->wpdb->query(
                $this->wpdb->prepare(
                    "DELETE FROM {$this->tables[$table]} 
                    WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
                    $days
                )
            );
        }
    }

    public function get_blocked_ips() {
        return $this->wpdb->get_results(
            "SELECT * FROM {$this->tables['blocked_ips']} ORDER BY blocked_until DESC",
            ARRAY_A
        ) ?: array();
    }
} 