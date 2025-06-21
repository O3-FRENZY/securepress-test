<?php
/**
 * SecureSphere Logs Module
 * Handles logging functionality
 */

if (!defined('ABSPATH')) {
    exit;
}

class SecureSphere_Logs {
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
    
    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        // Get filter parameters
        $level = isset($_GET['level']) ? sanitize_text_field($_GET['level']) : '';
        $date_from = isset($_GET['date_from']) ? sanitize_text_field($_GET['date_from']) : '';
        $date_to = isset($_GET['date_to']) ? sanitize_text_field($_GET['date_to']) : '';
        $page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $per_page = 50;
        $offset = ($page - 1) * $per_page;

        // Get logs
        $args = array(
            'level' => $level,
            'start_date' => $date_from,
            'end_date' => $date_to,
            'limit' => $per_page,
            'offset' => $offset
        );
        
        $logs = $this->db->get_logs($args);
        $total_logs = $this->db->get_total_logs($level, $date_from, $date_to);
        $total_pages = ceil($total_logs / $per_page);

        // Get statistics
        $stats = array(
            'total' => $total_logs,
            'last_24h' => $this->db->get_total_logs('', date('Y-m-d H:i:s', strtotime('-24 hours')), ''),
            'errors' => $this->db->get_total_logs('error'),
            'warnings' => $this->db->get_total_logs('warning')
        );
        ?>
        <div class="ss-card">
            <div class="ss-card-header">
                <h2>Security Logs</h2>
                <div class="ss-card-actions">
                    <button class="ss-button" onclick="refreshLogs()">
                        <span class="dashicons dashicons-update"></span>
                        Refresh
                    </button>
                </div>
            </div>

            <div class="ss-card-body">
                <!-- Statistics -->
                <div class="ss-stats-grid">
                    <div class="ss-stat-card">
                        <div class="ss-stat-value"><?php echo number_format($stats['total']); ?></div>
                        <div class="ss-stat-label">Total Logs</div>
                    </div>
                    <div class="ss-stat-card">
                        <div class="ss-stat-value"><?php echo number_format($stats['last_24h']); ?></div>
                        <div class="ss-stat-label">Last 24 Hours</div>
                    </div>
                    <div class="ss-stat-card">
                        <div class="ss-stat-value"><?php echo number_format($stats['errors']); ?></div>
                        <div class="ss-stat-label">Errors</div>
                    </div>
                    <div class="ss-stat-card">
                        <div class="ss-stat-value"><?php echo number_format($stats['warnings']); ?></div>
                        <div class="ss-stat-label">Warnings</div>
                    </div>
                </div>

                <!-- Filters -->
                <div class="ss-filters">
                    <form method="get" class="ss-filter-form">
                        <input type="hidden" name="page" value="securesphere-logs">
                        
                        <select name="level" class="ss-select">
                            <option value="">All Levels</option>
                            <option value="error" <?php selected($level, 'error'); ?>>Error</option>
                            <option value="warning" <?php selected($level, 'warning'); ?>>Warning</option>
                            <option value="info" <?php selected($level, 'info'); ?>>Info</option>
                        </select>
                        
                        <input type="date" name="date_from" value="<?php echo esc_attr($date_from); ?>" class="ss-input" placeholder="From Date">
                        <input type="date" name="date_to" value="<?php echo esc_attr($date_to); ?>" class="ss-input" placeholder="To Date">
                        
                        <button type="submit" class="ss-button">Filter</button>
                    </form>
                </div>

                <!-- Logs Table -->
                <div class="ss-table-responsive">
                    <?php if (!empty($logs)) : ?>
                        <table class="ss-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Level</th>
                                    <th>Event</th>
                                    <th>IP Address</th>
                                    <th>User</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $log) : ?>
                                    <tr class="ss-log-level-<?php echo esc_attr($log['level']); ?>">
                                        <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($log['timestamp']))); ?></td>
                                        <td>
                                            <span class="ss-badge ss-badge-<?php echo esc_attr($log['level']); ?>">
                                                <?php echo esc_html(ucfirst($log['level'])); ?>
                                            </span>
                                        </td>
                                        <td><?php echo esc_html($log['event']); ?></td>
                                        <td>
                                            <span class="ss-tooltip" title="Click to copy">
                                                <?php echo esc_html($log['ip_address']); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php
                                            if ($log['user_id']) {
                                                $user = get_userdata($log['user_id']);
                                                echo $user ? esc_html($user->user_login) : 'Unknown';
                                            } else {
                                                echo '—';
                                            }
                                            ?>
                                        </td>
                                        <td>
                                            <?php if (!empty($log['details'])) : ?>
                                                <button class="ss-button ss-button-small" onclick="showLogDetails(<?php echo esc_js(json_encode($log['details'])); ?>)">
                                                    View Details
                                                </button>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>

                        <!-- Pagination -->
                        <?php if ($total_pages > 1) : ?>
                            <div class="ss-pagination">
                                <?php
                                echo paginate_links(array(
                                    'base' => add_query_arg('paged', '%#%'),
                                    'format' => '',
                                    'prev_text' => __('&laquo;'),
                                    'next_text' => __('&raquo;'),
                                    'total' => $total_pages,
                                    'current' => $page
                                ));
                                ?>
                            </div>
                        <?php endif; ?>
                    <?php else : ?>
                        <div class="ss-empty-state">
                            <span class="dashicons dashicons-clipboard ss-empty-state-icon"></span>
                            <p>No logs found.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <script>
        function refreshLogs() {
            location.reload();
        }

        function showLogDetails(details) {
            // Create modal
            const modal = document.createElement('div');
            modal.className = 'ss-modal';
            modal.innerHTML = `
                <div class="ss-modal-content">
                    <div class="ss-modal-header">
                        <h3>Log Details</h3>
                        <button class="ss-modal-close" onclick="this.closest('.ss-modal').remove()">
                            <span class="dashicons dashicons-no-alt"></span>
                        </button>
                    </div>
                    <div class="ss-modal-body">
                        <pre>${JSON.stringify(details, null, 2)}</pre>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        // Copy IP address on click
        document.querySelectorAll('.ss-tooltip').forEach(el => {
            el.addEventListener('click', function() {
                const ip = this.textContent.trim();
                navigator.clipboard.writeText(ip).then(() => {
                    this.title = 'Copied!';
                    setTimeout(() => {
                        this.title = 'Click to copy';
                    }, 2000);
                });
            });
        });
        </script>
        <?php
    }

    public function get_recent_logs($limit = 5) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'securesphere_logs';
        
        $sql = $wpdb->prepare(
            "SELECT * FROM {$table_name} 
            ORDER BY timestamp DESC 
            LIMIT %d",
            $limit
        );
        
        return $wpdb->get_results($sql, ARRAY_A) ?: array();
    }
} 