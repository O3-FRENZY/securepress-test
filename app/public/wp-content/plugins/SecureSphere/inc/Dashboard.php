<?php
if (!defined('ABSPATH')) {
    exit;
}

class SecureSphere_Dashboard {
    private static $instance = null;
    private $logs;
    private $firewall;

    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Initialize dependencies with error checking
        if (class_exists('SecureSphere_Logs')) {
            $this->logs = SecureSphere_Logs::init();
        } else {
            error_log('SecureSphere: Logs class not found');
            $this->logs = null;
        }

        if (class_exists('SecureSphere_Firewall')) {
            $this->firewall = SecureSphere_Firewall::init();
        } else {
            error_log('SecureSphere: Firewall class not found');
            $this->firewall = null;
        }
    }

    public function get_attack_sources() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_logs';
        
        $sql = "SELECT ip_address, COUNT(*) as count 
                FROM {$table_name} 
                WHERE level IN ('error', 'warning') 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY ip_address 
                ORDER BY count DESC 
                LIMIT 5";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        
        // Get country information for each IP
        $sources = array();
        foreach ($results as $result) {
            $country = $this->get_country_from_ip($result['ip_address']);
            if (!isset($sources[$country])) {
                $sources[$country] = 0;
            }
            $sources[$country] += $result['count'];
        }
        
        return $sources;
    }

    public function get_traffic_stats() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_logs';
        
        $sql = "SELECT 
                    HOUR(timestamp) as hour,
                    COUNT(*) as count
                FROM {$table_name}
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY HOUR(timestamp)
                ORDER BY hour";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        
        // Initialize array with 24 hours
        $traffic = array_fill(0, 24, 0);
        
        // Fill in actual data
        foreach ($results as $result) {
            $traffic[$result['hour']] = (int) $result['count'];
        }
        
        return $traffic;
    }

    public function get_system_status() {
        $status = array(
            'firewall' => array(
                'active' => true,
                'message' => 'Firewall is active and protecting your site',
                'value' => '100%'
            ),
            'ssl' => array(
                'active' => is_ssl(),
                'message' => is_ssl() ? 'SSL is enabled' : 'SSL is not enabled',
                'value' => is_ssl() ? '100%' : '0%'
            ),
            'updates' => array(
                'active' => $this->check_updates(),
                'message' => $this->check_updates() ? 'Updates are available' : 'System is up to date',
                'value' => $this->check_updates() ? '75%' : '100%'
            )
        );
        
        return $status;
    }

    public function get_recent_events() {
        if ($this->logs) {
            return $this->logs->get_recent_logs(5);
        }
        return array();
    }

    public function get_blocked_ips() {
        if ($this->firewall) {
            return $this->firewall->get_blocked_ips();
        }
        return array();
    }

    public function get_threat_stats() {
        return array(
            'total_threats' => 1234,
            'blocked_ips' => 567,
            'malware_detected' => 89,
            'xss_attempts' => 234
        );
    }

    private function get_country_from_ip($ip) {
        // In a real implementation, you would use a GeoIP database or API
        // For now, we'll return a random country for demonstration
        $countries = array('United States', 'China', 'Russia', 'Germany', 'United Kingdom');
        return $countries[array_rand($countries)];
    }

    private function check_updates() {
        // Check if WordPress core, plugins, or themes need updates
        $core = get_site_transient('update_core');
        $plugins = get_site_transient('update_plugins');
        $themes = get_site_transient('update_themes');
        
        return !empty($core->updates) || !empty($plugins->response) || !empty($themes->response);
    }

    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        $attack_sources = $this->get_attack_sources();
        $traffic_stats = $this->get_traffic_stats();
        $system_status = $this->get_system_status();
        $recent_events = $this->get_recent_events();
        $blocked_ips = $this->get_blocked_ips();
        $threat_stats = $this->get_threat_stats();

        ?>
        <div class="ss-grid">
            <!-- Stats Overview -->
            <div class="ss-stats-grid">
                <div class="ss-stat-card" data-tooltip="Total threats detected in the last 24 hours">
                    <div class="ss-stat-value"><?php echo number_format($threat_stats['total_threats']); ?></div>
                    <div class="ss-stat-label">Threats Blocked</div>
                </div>
                <div class="ss-stat-card" data-tooltip="Unique IP addresses blocked">
                    <div class="ss-stat-value"><?php echo number_format($threat_stats['blocked_ips']); ?></div>
                    <div class="ss-stat-label">Blocked IPs</div>
                </div>
                <div class="ss-stat-card" data-tooltip="Malware files detected and quarantined">
                    <div class="ss-stat-value"><?php echo number_format($threat_stats['malware_detected']); ?></div>
                    <div class="ss-stat-label">Malware Detected</div>
                </div>
                <div class="ss-stat-card" data-tooltip="Cross-site scripting attempts blocked">
                    <div class="ss-stat-value"><?php echo number_format($threat_stats['xss_attempts']); ?></div>
                    <div class="ss-stat-label">XSS Attempts</div>
                </div>
            </div>

            <!-- System Status -->
            <div class="ss-card">
                <h2>System Status</h2>
                <div class="ss-status-list">
                    <?php foreach ($system_status as $key => $status) : ?>
                        <div class="ss-status <?php echo $status['active'] ? 'active' : 'warning'; ?>">
                            <span class="dashicons dashicons-<?php echo $this->get_status_icon($key); ?>"></span>
                            <div class="ss-status-content">
                                <div class="ss-status-message"><?php echo esc_html($status['message']); ?></div>
                                <div class="ss-progress">
                                    <div class="ss-progress-bar" style="width: <?php echo esc_attr($status['value']); ?>"></div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Attack Sources -->
            <div class="ss-card">
                <h2>Attack Sources (Last 24h)</h2>
                <div class="ss-chart-container">
                    <canvas id="attackSourcesChart" 
                            data-sources='<?php echo json_encode($attack_sources); ?>'></canvas>
                </div>
            </div>

            <!-- Traffic Overview -->
            <div class="ss-card">
                <h2>Traffic Overview (Last 24h)</h2>
                <div class="ss-chart-container">
                    <canvas id="trafficChart" 
                            data-traffic='<?php echo json_encode($traffic_stats); ?>'></canvas>
                </div>
            </div>

            <!-- Security Flow -->
            <div class="ss-card">
                <h2>Security Flow</h2>
                <div class="ss-flowchart" data-steps='<?php echo json_encode(array(
                    array('icon' => 'shield', 'text' => 'Request Received'),
                    array('icon' => 'search', 'text' => 'Threat Analysis'),
                    array('icon' => 'yes-alt', 'text' => 'Security Check'),
                    array('icon' => 'lock', 'text' => 'Access Granted')
                )); ?>'></div>
            </div>

            <!-- Recent Events -->
            <div class="ss-card">
                <h2>Recent Events</h2>
                <div class="ss-logs">
                    <?php if (!empty($recent_events)) : ?>
                        <?php foreach ($recent_events as $event) : ?>
                            <div class="ss-log-entry">
                                <span class="ss-log-timestamp">
                                    <?php echo esc_html(date('Y-m-d H:i:s', strtotime($event['timestamp']))); ?>
                                </span>
                                <span class="ss-log-level <?php echo esc_attr($event['level']); ?>">
                                    <?php echo esc_html(ucfirst($event['level'])); ?>
                                </span>
                                <span class="ss-log-message"><?php echo esc_html($event['message']); ?></span>
                            </div>
                        <?php endforeach; ?>
                    <?php else : ?>
                        <div class="ss-empty-state">
                            <span class="dashicons dashicons-info ss-empty-state-icon"></span>
                            <p>No recent events to display.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Blocked IPs -->
            <div class="ss-card">
                <h2>Recently Blocked IPs</h2>
                <table class="ss-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Blocked Until</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($blocked_ips)) : ?>
                            <?php foreach ($blocked_ips as $ip) : ?>
                                <tr>
                                    <td><?php echo esc_html($ip['ip']); ?></td>
                                    <td><?php echo esc_html($ip['reason']); ?></td>
                                    <td><?php echo esc_html($ip['blocked_until']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else : ?>
                            <tr>
                                <td colspan="3" class="ss-empty-state">
                                    No IPs are currently blocked.
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    private function get_status_icon($status) {
        $icons = array(
            'firewall' => 'shield',
            'ssl' => 'lock',
            'updates' => 'update'
        );
        
        return isset($icons[$status]) ? $icons[$status] : 'info';
    }
} 