<?php
/**
 * SecureSphere Logger Module
 * Handles logging functionality for the plugin
 */

class SecureSphere_Logger {
    private static $instance = null;
    private $log_dir;
    private $log_file;
    private $max_log_size = 5242880; // 5MB
    private $max_log_files = 5;
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $upload_dir = wp_upload_dir();
        $this->log_dir = $upload_dir['basedir'] . '/securesphere-logs';
        $this->log_file = $this->log_dir . '/securesphere.log';
        
        // Create log directory if it doesn't exist
        if (!file_exists($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
            
            // Create .htaccess to protect logs
            $htaccess = $this->log_dir . '/.htaccess';
            if (!file_exists($htaccess)) {
                file_put_contents($htaccess, 'Deny from all');
            }
            
            // Create index.php to prevent directory listing
            $index = $this->log_dir . '/index.php';
            if (!file_exists($index)) {
                file_put_contents($index, '<?php // Silence is golden');
            }
        }
    }
    
    public function log($message, $level = 'info', $context = array()) {
        if (!is_string($message)) {
            $message = print_r($message, true);
        }
        
        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'level' => strtoupper($level),
            'message' => $message,
            'context' => $context
        );
        
        $log_line = sprintf(
            "[%s] %s: %s %s\n",
            $log_entry['timestamp'],
            $log_entry['level'],
            $log_entry['message'],
            !empty($context) ? json_encode($context) : ''
        );
        
        // Check if we need to rotate logs
        if (file_exists($this->log_file) && filesize($this->log_file) > $this->max_log_size) {
            $this->rotate_logs();
        }
        
        // Write to log file
        error_log($log_line, 3, $this->log_file);
        
        // Also log to database if it's a security event
        if (in_array($level, array('alert', 'critical', 'error', 'warning'))) {
            $this->log_to_database($log_entry);
        }
    }
    
    private function rotate_logs() {
        // Rotate existing log files
        for ($i = $this->max_log_files - 1; $i >= 0; $i--) {
            $old_file = $i === 0 ? $this->log_file : $this->log_file . '.' . $i;
            $new_file = $this->log_file . '.' . ($i + 1);
            
            if (file_exists($old_file)) {
                if ($i === $this->max_log_files - 1) {
                    unlink($old_file);
                } else {
                    rename($old_file, $new_file);
                }
            }
        }
    }
    
    private function log_to_database($log_entry) {
        $db = SecureSphere_Database::init();
        
        $severity_map = array(
            'ALERT' => 'high',
            'CRITICAL' => 'critical',
            'ERROR' => 'high',
            'WARNING' => 'medium'
        );
        
        $db->log_security_event(array(
            'event_type' => 'system_log',
            'severity' => $severity_map[$log_entry['level']] ?? 'low',
            'source' => 'logger',
            'details' => json_encode($log_entry)
        ));
    }
    
    public function get_logs($limit = 100, $offset = 0) {
        if (!file_exists($this->log_file)) {
            return array();
        }
        
        $logs = array();
        $handle = fopen($this->log_file, 'r');
        
        if ($handle) {
            // Skip to offset
            for ($i = 0; $i < $offset; $i++) {
                fgets($handle);
            }
            
            // Read logs
            $count = 0;
            while (($line = fgets($handle)) !== false && $count < $limit) {
                if (preg_match('/^\[(.*?)\] (.*?): (.*?)( \{.*\})?$/', $line, $matches)) {
                    $logs[] = array(
                        'timestamp' => $matches[1],
                        'level' => $matches[2],
                        'message' => $matches[3],
                        'context' => isset($matches[4]) ? json_decode($matches[4], true) : array()
                    );
                    $count++;
                }
            }
            
            fclose($handle);
        }
        
        return $logs;
    }
    
    public function clear_logs() {
        if (file_exists($this->log_file)) {
            unlink($this->log_file);
        }
        
        // Remove rotated logs
        for ($i = 1; $i <= $this->max_log_files; $i++) {
            $rotated_file = $this->log_file . '.' . $i;
            if (file_exists($rotated_file)) {
                unlink($rotated_file);
            }
        }
    }
    
    public function get_log_size() {
        if (!file_exists($this->log_file)) {
            return 0;
        }
        return filesize($this->log_file);
    }
    
    public function get_log_stats() {
        $stats = array(
            'total_size' => 0,
            'file_count' => 0,
            'oldest_log' => null,
            'newest_log' => null
        );
        
        // Check main log file
        if (file_exists($this->log_file)) {
            $stats['total_size'] += filesize($this->log_file);
            $stats['file_count']++;
            
            // Get first and last line for timestamps
            $first_line = fgets(fopen($this->log_file, 'r'));
            $last_line = exec('tail -n 1 ' . escapeshellarg($this->log_file));
            
            if (preg_match('/^\[(.*?)\]/', $first_line, $matches)) {
                $stats['oldest_log'] = $matches[1];
            }
            if (preg_match('/^\[(.*?)\]/', $last_line, $matches)) {
                $stats['newest_log'] = $matches[1];
            }
        }
        
        // Check rotated logs
        for ($i = 1; $i <= $this->max_log_files; $i++) {
            $rotated_file = $this->log_file . '.' . $i;
            if (file_exists($rotated_file)) {
                $stats['total_size'] += filesize($rotated_file);
                $stats['file_count']++;
            }
        }
        
        return $stats;
    }
} 