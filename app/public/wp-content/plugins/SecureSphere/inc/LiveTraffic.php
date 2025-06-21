<?php
if (!defined('ABSPATH')) {
    exit;
}

// Live Traffic module for SecureSphere
class SecureSphere_LiveTraffic {
    private static $instance = null;
    private $db;
    
    // Option Keys
    const OPT_LOG_ENABLED = 'securesphere_traffic_log_enabled';
    const OPT_MAX_LOG_ENTRIES = 'securesphere_traffic_max_log_entries';
    const OPT_TRAFFIC_LOG_DATA = 'securesphere_traffic_log'; // Actual log data

    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->db = SecureSphere_Database::init();
        add_action('admin_init', array($this, 'init_settings'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_traffic_scripts'));
        
        // Add admin menu for live traffic
        add_action('admin_menu', [__CLASS__, 'add_live_traffic_menu']);
        
        // Add AJAX handlers for real-time updates & actions
        add_action('wp_ajax_securesphere_get_traffic_data', [__CLASS__, 'ajax_get_traffic_data']);
        add_action('wp_ajax_securesphere_clear_traffic_log', [__CLASS__, 'ajax_clear_traffic_log_data']);
        add_action('wp_ajax_securesphere_lt_block_ip', [__CLASS__, 'ajax_lt_block_ip']);             // New AJAX action
        add_action('wp_ajax_securesphere_lt_whitelist_ip', [__CLASS__, 'ajax_lt_whitelist_ip']);     // New AJAX action
    }
    
    public function init_settings() {
        register_setting('securesphere_traffic_settings', 'securesphere_traffic_enabled');
        register_setting('securesphere_traffic_settings', 'securesphere_traffic_retention');
    }
    
    public function enqueue_traffic_scripts() {
        if (is_admin()) {
            wp_enqueue_style('securesphere-traffic', SECURESPHERE_PLUGIN_URL . 'assets/css/traffic.css', array(), SECURESPHERE_VERSION);
            wp_enqueue_script('securesphere-traffic', SECURESPHERE_PLUGIN_URL . 'assets/js/traffic.js', array('jquery'), SECURESPHERE_VERSION, true);
        }
    }
    
    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        try {
            // Get recent traffic data
            $recent_traffic = $this->get_recent_traffic();
            ?>
            <div class="wrap">
                <h1>Live Traffic</h1>
                
                <?php if (isset($_GET['error'])) : ?>
                    <div class="notice notice-error">
                        <p><?php echo esc_html(urldecode($_GET['error'])); ?></p>
                    </div>
                <?php endif; ?>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Real-time Traffic Monitor</h2>
                        <div class="ss-card-actions">
                            <button class="ss-button" id="refresh-traffic">
                                <span class="dashicons dashicons-update"></span> Refresh
                            </button>
                        </div>
                    </div>
                    <div class="ss-card-body">
                        <div id="traffic-chart" style="height: 300px;"></div>
                    </div>
                </div>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Recent Traffic</h2>
                    </div>
                    <div class="ss-card-body">
                        <?php if (!empty($recent_traffic)) : ?>
                            <div class="ss-table-responsive">
                                <table class="ss-table">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>IP Address</th>
                                            <th>Request</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($recent_traffic as $traffic) : ?>
                                            <tr>
                                                <td><?php echo esc_html($traffic['timestamp']); ?></td>
                                                <td><?php echo esc_html($traffic['ip_address']); ?></td>
                                                <td><?php echo esc_html($traffic['request_uri']); ?></td>
                                                <td>
                                                    <span class="ss-status-badge ss-status-<?php echo esc_attr($traffic['status']); ?>">
                                                        <?php echo esc_html($traffic['status']); ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <button class="ss-button ss-button-small ss-block-ip" 
                                                            data-ip="<?php echo esc_attr($traffic['ip_address']); ?>">
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
                                <span class="dashicons dashicons-visibility ss-empty-state-icon"></span>
                                <p>No recent traffic data available.</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <script>
            jQuery(document).ready(function($) {
                // Initialize traffic chart
                if (typeof Chart !== 'undefined') {
                    const ctx = document.getElementById('traffic-chart').getContext('2d');
                    const trafficChart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: [],
                            datasets: [{
                                label: 'Requests',
                                data: [],
                                borderColor: '#2271b1',
                                backgroundColor: 'rgba(34, 113, 177, 0.1)',
                                fill: true
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });

                    // Update chart data
                    function updateTrafficData() {
                        $.post(ajaxurl, {
                            action: 'securesphere_get_traffic_data',
                            nonce: '<?php echo wp_create_nonce('securesphere_traffic_nonce'); ?>'
                        }, function(response) {
                            if (response.success) {
                                trafficChart.data.labels = response.data.labels;
                                trafficChart.data.datasets[0].data = response.data.values;
                                trafficChart.update();
                            }
                        });
                    }

                    // Refresh button handler
                    $('#refresh-traffic').on('click', updateTrafficData);

                    // Initial update and set interval
                    updateTrafficData();
                    setInterval(updateTrafficData, 30000); // Update every 30 seconds
                }
            });
            </script>
            <?php
        } catch (Exception $e) {
            error_log('SecureSphere Live Traffic Error: ' . $e->getMessage());
            ?>
            <div class="wrap">
                <h1>Live Traffic</h1>
                <div class="notice notice-error">
                    <p>An error occurred while loading the live traffic page. Please try refreshing the page or contact support if the issue persists.</p>
                </div>
            </div>
            <?php
        }
    }

    private function get_recent_traffic() {
        try {
            return $this->db->get_logs(array(
                'limit' => 50,
                'orderby' => 'timestamp',
                'order' => 'DESC'
            ));
        } catch (Exception $e) {
            error_log('SecureSphere Get Recent Traffic Error: ' . $e->getMessage());
            return array();
        }
    }

    public static function add_live_traffic_menu() { // Renamed
        add_submenu_page(
            'securesphere-mssp',
            'Live Traffic',
            'Live Traffic',
            'manage_options',
            'securesphere-live-traffic',
            [__CLASS__, 'render_traffic_page']
        );
    }

    public static function render_traffic_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        // Handle settings update
        if (isset($_POST['securesphere_traffic_settings_nonce']) && wp_verify_nonce($_POST['securesphere_traffic_settings_nonce'], 'securesphere_traffic_settings_action')) {
            update_option(self::OPT_LOG_ENABLED, isset($_POST[self::OPT_LOG_ENABLED]));
            if (isset($_POST[self::OPT_MAX_LOG_ENTRIES])) {
                update_option(self::OPT_MAX_LOG_ENTRIES, absint($_POST[self::OPT_MAX_LOG_ENTRIES]));
            }
            echo '<div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>';
            // Re-check if logging should be active after save
            if (!get_option(self::OPT_LOG_ENABLED, true)) {
                 // If disabled, no specific action needed here as log_request_details checks option directly
            } else {
                // If enabled, ensure hook is present (it should be if init ran)
                if (!has_action('shutdown', [__CLASS__, 'log_request_details'])) {
                     add_action('shutdown', [__CLASS__, 'log_request_details']);
                }
            }
        }
        
        $log_enabled = get_option(self::OPT_LOG_ENABLED, true);
        $max_log_entries = get_option(self::OPT_MAX_LOG_ENTRIES, 1000);

        ?>
        <div class="wrap">
            <h1>Live Traffic Monitor</h1>

            <form method="post" action="">
                <?php wp_nonce_field('securesphere_traffic_settings_action', 'securesphere_traffic_settings_nonce'); ?>
                <h2>Settings</h2>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Enable Traffic Logging</th>
                        <td><input type="checkbox" name="<?php echo self::OPT_LOG_ENABLED; ?>" value="1" <?php checked($log_enabled); ?> /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><label for="<?php echo self::OPT_MAX_LOG_ENTRIES; ?>">Max Log Entries</label></th>
                        <td><input type="number" id="<?php echo self::OPT_MAX_LOG_ENTRIES; ?>" name="<?php echo self::OPT_MAX_LOG_ENTRIES; ?>" value="<?php echo esc_attr($max_log_entries); ?>" min="100" max="10000" />
                        <p class="description">Maximum number of traffic log entries to retain (e.g., 500-5000). Default: 1000.</p></td>
                    </tr>
                </table>
                <?php submit_button('Save Traffic Settings'); ?>
            </form>
            <hr/>

            <h2>Live Log</h2>
            <div class="traffic-controls">
                <button id="refresh-traffic" class="button">Refresh</button>
                <button id="clear-traffic-log" class="button">Clear Log</button> <!-- Changed ID -->
                <span class="spinner" style="float: none; vertical-align: middle;"></span>
            </div>
            
            <div class="traffic-filters">
                <select id="filter-status">
                    <option value="">All Status Codes</option>
                    <option value="200">200 OK</option>
                    <option value="301">301 Redirect</option>
                    <option value="404">404 Not Found</option>
                    <option value="403">403 Forbidden</option>
                    <option value="500">500 Error</option>
                </select>
                
                <select id="filter-method">
                    <option value="">All Methods</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                </select>
                
                <input type="text" id="filter-ip" placeholder="Filter by IP">
                <input type="text" id="filter-url" placeholder="Filter by URL">
            </div>
            
            <div class="traffic-stats">
                <div class="stat-box">
                    <h3>Total Requests</h3>
                    <span id="total-requests">0</span>
                </div>
                <div class="stat-box">
                    <h3>Unique IPs</h3>
                    <span id="unique-ips">0</span>
                </div>
                <div class="stat-box">
                    <h3>404 Errors</h3>
                    <span id="error-404">0</span>
                </div>
                <div class="stat-box">
                    <h3>403 Forbidden</h3>
                    <span id="error-403">0</span>
                </div>
            </div>
            
            <table class="wp-list-table widefat fixed striped traffic-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP</th>
                        <th>User</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Status Code</th>
                        <th>User Agent</th>
                        <th>Referrer</th>
                    </tr>
                </thead>
                <tbody id="traffic-log-entries"> <!-- Changed ID -->
                    <tr><td colspan="8" style="text-align:center;">Loading traffic data...</td></tr>
                </tbody>
            </table>
        </div>

        <style>
            .traffic-controls {
                margin: 20px 0;
            }
            .traffic-filters {
                margin: 20px 0;
                display: flex;
                gap: 10px;
            }
            .traffic-stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .stat-box {
                background: #fff;
                padding: 15px;
                border-radius: 4px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .stat-box h3 {
                margin: 0 0 10px 0;
                color: #23282d;
            }
            .stat-box span {
                font-size: 24px;
                font-weight: bold;
                color: #0073aa;
            }
            .traffic-table {
                margin-top: 20px;
            }
            .status-200 { color: #46b450; }
            .status-301 { color: #00a0d2; }
            .status-404 { color: #ffb900; }
            .status-403 { color: #dc3232; }
            .status-500 { color: #dc3232; }
        </style>

        <script>
        jQuery(document).ready(function($) {
            let autoRefresh = true;
            let refreshInterval = 5000; // 5 seconds
            
            function loadTraffic() {
                $('.spinner').addClass('is-active');
                
                $.ajax({
                    url: ajaxurl,
                    data: {
                        action: 'securesphere_get_traffic_data', // Renamed action
                        _ajax_nonce: SecureSphereTraffic.get_traffic_nonce, // Added nonce
                        filters: {
                            status: $('#filter-status').val(),
                            method: $('#filter-method').val(),
                            ip: $('#filter-ip').val(),
                            url: $('#filter-url').val()
                        }
                    },
                    success: function(response) {
                        if (response.success) {
                            updateTrafficTable(response.data.log_entries); // Adjusted key
                            updateStats(response.data.stats);
                        } else {
                            $('#traffic-log-entries').html('<tr><td colspan="8" style="text-align:center; color:red;">Error loading traffic: ' + (response.data.message || 'Unknown error') + '</td></tr>');
                        }
                    },
                    error: function() {
                         $('#traffic-log-entries').html('<tr><td colspan="8" style="text-align:center; color:red;">AJAX request failed.</td></tr>');
                    },
                    complete: function() {
                        $('.spinner').removeClass('is-active');
                    }
                });
            }
            
            function updateTrafficTable(log_entries) { // Renamed param
                const tbody = $('#traffic-log-entries'); // Changed ID
                tbody.empty();
                
                if (!log_entries || log_entries.length === 0) {
                    tbody.html('<tr><td colspan="8" style="text-align:center;">No traffic data matching your filters.</td></tr>');
                    return;
                }

                log_entries.forEach(function(entry) {
                    const row = $('<tr>');
                    row.append($('<td>').text(entry.time));
                    
                    const ipCell = $('<td>').text(entry.ip);
                    // Add Block/Whitelist links
                    ipCell.append('<br/><small style="white-space: nowrap;">'); // Ensure links stay on one line if possible
                    ipCell.append($('<a>', { href: '#', class: 'lt-block-ip', 'data-ip': entry.ip, text: 'Block IP' }));
                    ipCell.append(' | ');
                    ipCell.append($('<a>', { href: '#', class: 'lt-whitelist-ip', 'data-ip': entry.ip, text: 'Whitelist IP' }));
                    ipCell.append('</small>');
                    row.append(ipCell);

                    let userDisplay = 'Guest';
                    if (entry.user_id && entry.user_id !== "0") {
                        userDisplay = 'User ' + entry.user_id;
                    }
                    row.append($('<td>').text(userDisplay));
                    row.append($('<td>').text(entry.method));
                    row.append($('<td>').text(entry.url));
                    row.append($('<td>').addClass('status-' + entry.status_code).text(entry.status_code));
                    row.append($('<td>').text(entry.user_agent));
                    row.append($('<td>').text(entry.referrer));
                    tbody.append(row);
                });
            }
            
            function updateStats(stats) {
                $('#total-requests').text(stats.total_requests);
                $('#unique-ips').text(stats.unique_ips);
                $('#error-404').text(stats.error_404);
                $('#error-403').text(stats.error_403);
            }
            
            // Initial load
            loadTraffic();
            
            // Set up auto-refresh
            let refreshTimer = setInterval(function() {
                if (autoRefresh) {
                    loadTraffic();
                }
            }, refreshInterval);
            
            // Manual refresh
            $('#refresh-traffic').click(function() {
                loadTraffic();
            });
            
            // Clear log
            $('#clear-traffic-log').click(function() { // Changed ID
                if (confirm('Are you sure you want to clear the traffic log?')) {
                    $('.spinner').addClass('is-active');
                    $.ajax({
                        url: SecureSphereTraffic.ajax_url, // Use localized
                        type: 'POST', // POST for actions that change state
                        data: {
                            action: 'securesphere_clear_traffic_log', // Renamed action
                            _ajax_nonce: SecureSphereTraffic.clear_traffic_nonce // Added nonce
                        },
                        success: function(response) {
                            if (response.success) {
                                loadTraffic(); // Reload to show empty log
                            } else {
                                alert('Error clearing log: ' + (response.data.message || 'Unknown error'));
                            }
                        },
                        error: function() {
                            alert('AJAX request failed to clear log.');
                        },
                        complete: function() {
                            $('.spinner').removeClass('is-active');
                        }
                    });
                }
            });
            
            // Filter changes
            $('.traffic-filters select, .traffic-filters input').change(function() {
                loadTraffic();
            });

            // Handler for Block IP from Live Traffic
            $('#traffic-log-entries').on('click', '.lt-block-ip', function(e) {
                e.preventDefault();
                const ip = $(this).data('ip');
                if (!ip || !confirm('Are you sure you want to block IP: ' + ip + '?')) return;
                
                $('.spinner').addClass('is-active');
                $.post(SecureSphereTraffic.ajax_url, {
                    action: 'securesphere_lt_block_ip',
                    _ajax_nonce: SecureSphereTraffic.lt_block_ip_nonce,
                    ip_to_block: ip
                }, function(response) {
                    $('.spinner').removeClass('is-active');
                    if (response.success) {
                        alert('IP ' + ip + ' blocked successfully. The firewall rules have been updated.');
                        // Optionally refresh traffic or indicate status change
                    } else {
                        alert('Error blocking IP: ' + (response.data.message || 'Unknown error'));
                    }
                }).fail(function() {
                    $('.spinner').removeClass('is-active');
                    alert('Request to block IP failed.');
                });
            });

            // Handler for Whitelist IP from Live Traffic
            $('#traffic-log-entries').on('click', '.lt-whitelist-ip', function(e) {
                e.preventDefault();
                const ip = $(this).data('ip');
                if (!ip || !confirm('Are you sure you want to whitelist IP: ' + ip + '? This will bypass firewall checks.')) return;

                $('.spinner').addClass('is-active');
                 $.post(SecureSphereTraffic.ajax_url, {
                    action: 'securesphere_lt_whitelist_ip',
                    _ajax_nonce: SecureSphereTraffic.lt_whitelist_ip_nonce,
                    ip_to_whitelist: ip
                }, function(response) {
                    $('.spinner').removeClass('is-active');
                    if (response.success) {
                        alert('IP ' + ip + ' whitelisted successfully. The firewall rules have been updated.');
                    } else {
                        alert('Error whitelisting IP: ' + (response.data.message || 'Unknown error'));
                    }
                }).fail(function() {
                    $('.spinner').removeClass('is-active');
                    alert('Request to whitelist IP failed.');
                });
            });

        });
        </script>
        <?php
    }

    public static function ajax_get_traffic_data() {
        check_ajax_referer('securesphere_get_traffic_nonce', '_ajax_nonce'); // Check nonce
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
            return;
        }
        
        $filters = isset($_GET['filters']) ? (array) $_GET['filters'] : []; // Assuming GET from JS, but can be POST
        $traffic_log_data = get_option(self::OPT_TRAFFIC_LOG_DATA, []);
        
        $filtered_log = $traffic_log_data; // Start with all logs

        if (!empty($filters)) {
            $filtered_log = array_filter($traffic_log_data, function($entry) use ($filters) {
                // Validate entry structure
                if (!is_array($entry) || !isset($entry['status_code'])) {
                    return false;
                }
                
                if (!empty($filters['status']) && $entry['status_code'] != $filters['status']) {
                    return false;
                }
                if (!empty($filters['method']) && (!isset($entry['method']) || strtoupper($entry['method']) != strtoupper($filters['method']))) {
                    return false;
                }
                if (!empty($filters['ip']) && (!isset($entry['ip']) || stripos($entry['ip'], $filters['ip']) === false)) {
                    return false;
                }
                if (!empty($filters['url']) && (!isset($entry['url']) || stripos($entry['url'], $filters['url']) === false)) {
                    return false;
                }
                return true;
            });
        }
        
        // Calculate stats on the filtered log
        $stats = [
            'total_requests' => count($filtered_log),
            'unique_ips' => count(array_unique(array_column($filtered_log, 'ip'))),
            'error_404' => count(array_filter($filtered_log, function($entry) {
                return $entry['status_code'] == 404;
            })),
            'error_403' => count(array_filter($filtered_log, function($entry) {
                return $entry['status_code'] == 403;
            }))
        ];
        
        wp_send_json_success([
            'log_entries' => array_values($filtered_log), // Re-index array after filter
            'stats' => $stats
        ]);
    }

    public static function ajax_clear_traffic_log_data() {
        check_ajax_referer('securesphere_clear_traffic_nonce', '_ajax_nonce');
        
        if (!current_user_can('manage_options')) {
             wp_send_json_error(['message' => 'Unauthorized'], 403);
            return;
        }
        
        update_option(self::OPT_TRAFFIC_LOG_DATA, [], false);
        wp_send_json_success(['message' => 'Traffic log cleared.']);
    }

    // AJAX handler to block an IP from Live Traffic
    public static function ajax_lt_block_ip() {
        check_ajax_referer('securesphere_lt_block_ip_nonce', '_ajax_nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
            return;
        }
        if (empty($_POST['ip_to_block'])) {
            wp_send_json_error(['message' => 'IP address not provided.'], 400);
            return;
        }

        $ip_to_block = sanitize_text_field($_POST['ip_to_block']);
        
        if (filter_var(explode('/', $ip_to_block)[0], FILTER_VALIDATE_IP)) {
            $blocked_ips = get_option(SecureSphere_Firewall::OPT_BLOCKED_IPS, []);
            if (!in_array($ip_to_block, $blocked_ips)) {
                $blocked_ips[] = $ip_to_block;
                update_option(SecureSphere_Firewall::OPT_BLOCKED_IPS, array_unique($blocked_ips));
                if (class_exists('SecureSphere_Firewall')) { // Ensure class is available
                    SecureSphere_Firewall::load_firewall_data(); // Reload firewall static data
                }
                wp_send_json_success(['message' => 'IP ' . esc_html($ip_to_block) . ' added to blocklist.']);
            } else {
                wp_send_json_success(['message' => 'IP ' . esc_html($ip_to_block) . ' is already blocked.']);
            }
        } else {
            wp_send_json_error(['message' => 'Invalid IP address format.'], 400);
        }
    }

    // AJAX handler to whitelist an IP from Live Traffic
    public static function ajax_lt_whitelist_ip() {
        check_ajax_referer('securesphere_lt_whitelist_ip_nonce', '_ajax_nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
            return;
        }
        if (empty($_POST['ip_to_whitelist'])) {
            wp_send_json_error(['message' => 'IP address not provided.'], 400);
            return;
        }
        $ip_to_whitelist = sanitize_text_field($_POST['ip_to_whitelist']);

        if (filter_var(explode('/', $ip_to_whitelist)[0], FILTER_VALIDATE_IP)) {
            $whitelisted_ips = get_option(SecureSphere_Firewall::OPT_WHITELISTED_IPS, []);
            if (!in_array($ip_to_whitelist, $whitelisted_ips)) {
                $whitelisted_ips[] = $ip_to_whitelist;
                update_option(SecureSphere_Firewall::OPT_WHITELISTED_IPS, array_unique($whitelisted_ips));
                 if (class_exists('SecureSphere_Firewall')) { // Ensure class is available
                    SecureSphere_Firewall::load_firewall_data(); // Reload firewall static data
                }
                wp_send_json_success(['message' => 'IP ' . esc_html($ip_to_whitelist) . ' added to whitelist.']);
            } else {
                 wp_send_json_success(['message' => 'IP ' . esc_html($ip_to_whitelist) . ' is already whitelisted.']);
            }
        } else {
            wp_send_json_error(['message' => 'Invalid IP address format.'], 400);
        }
    }
}