<?php
if (!defined('ABSPATH')) {
    exit;
}

$logger = SecureSphere_Logger::init();
$database = SecureSphere_Database::init();

// Get filter parameters
$page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
$per_page = 20;
$log_level = isset($_GET['level']) ? sanitize_text_field($_GET['level']) : '';
$date_from = isset($_GET['date_from']) ? sanitize_text_field($_GET['date_from']) : '';
$date_to = isset($_GET['date_to']) ? sanitize_text_field($_GET['date_to']) : '';

// Get logs from database
$logs = $database->get_logs($page, $per_page, $log_level, $date_from, $date_to);
$total_logs = $database->get_total_logs($log_level, $date_from, $date_to);
$total_pages = ceil($total_logs / $per_page);

// Handle log clearing
if (isset($_POST['clear_logs_nonce']) && wp_verify_nonce($_POST['clear_logs_nonce'], 'securesphere_clear_logs')) {
    $database->clear_logs();
    echo '<div class="notice notice-success is-dismissible"><p>Logs cleared successfully.</p></div>';
}
?>

<div class="wrap securesphere-logs-wrap">
    <h1><span class="dashicons dashicons-list-view"></span> Security Logs</h1>
    
    <!-- Filters -->
    <div class="securesphere-filters">
        <form method="get" action="">
            <input type="hidden" name="page" value="securesphere-logs">
            
            <div class="filter-group">
                <label for="log-level">Log Level:</label>
                <select name="level" id="log-level">
                    <option value="">All Levels</option>
                    <option value="debug" <?php selected($log_level, 'debug'); ?>>Debug</option>
                    <option value="info" <?php selected($log_level, 'info'); ?>>Info</option>
                    <option value="warning" <?php selected($log_level, 'warning'); ?>>Warning</option>
                    <option value="error" <?php selected($log_level, 'error'); ?>>Error</option>
                </select>
            </div>
            
            <div class="filter-group">
                <label for="date-from">From Date:</label>
                <input type="date" name="date_from" id="date-from" value="<?php echo esc_attr($date_from); ?>">
            </div>
            
            <div class="filter-group">
                <label for="date-to">To Date:</label>
                <input type="date" name="date_to" id="date-to" value="<?php echo esc_attr($date_to); ?>">
            </div>
            
            <div class="filter-group">
                <input type="submit" class="button button-primary" value="Filter">
            </div>
        </form>
    </div>
    
    <!-- Clear Logs Form -->
    <form method="post" action="" class="securesphere-clear-logs">
        <?php wp_nonce_field('securesphere_clear_logs', 'clear_logs_nonce'); ?>
        <input type="submit" class="button" value="Clear All Logs" onclick="return confirm('Are you sure you want to clear all logs?');">
    </form>
    
    <!-- Logs Table -->
    <div class="securesphere-logs-table-wrap">
        <table class="wp-list-table widefat fixed striped">
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
                <?php if (empty($logs)): ?>
                <tr>
                    <td colspan="6" class="no-logs">No logs found.</td>
                </tr>
                <?php else: ?>
                    <?php foreach ($logs as $log): ?>
                    <tr>
                        <td><?php echo esc_html($log->timestamp); ?></td>
                        <td>
                            <span class="log-level log-level-<?php echo esc_attr($log->level); ?>">
                                <?php echo esc_html(ucfirst($log->level)); ?>
                            </span>
                        </td>
                        <td><?php echo esc_html($log->event); ?></td>
                        <td><?php echo esc_html($log->ip_address); ?></td>
                        <td><?php echo esc_html($log->user_id ? get_user_by('id', $log->user_id)->user_login : 'Guest'); ?></td>
                        <td>
                            <button class="button view-details" data-details="<?php echo esc_attr($log->details); ?>">
                                View Details
                            </button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
    
    <!-- Pagination -->
    <?php if ($total_pages > 1): ?>
    <div class="tablenav bottom">
        <div class="tablenav-pages">
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
    </div>
    <?php endif; ?>
</div>

<!-- Details Modal -->
<div id="log-details-modal" class="securesphere-modal">
    <div class="securesphere-modal-content">
        <span class="securesphere-modal-close">&times;</span>
        <h2>Log Details</h2>
        <pre id="log-details-content"></pre>
    </div>
</div>

<style>
.securesphere-logs-wrap {
    margin: 20px;
}

.securesphere-logs-wrap h1 {
    display: flex;
    align-items: center;
    gap: 10px;
}

.securesphere-logs-wrap h1 .dashicons {
    color: #2271b1;
}

.securesphere-filters {
    background: #fff;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 20px;
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    align-items: flex-end;
}

.filter-group {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

.filter-group label {
    font-weight: 600;
    color: #1d2327;
}

.filter-group select,
.filter-group input[type="date"] {
    padding: 8px;
    border: 1px solid #ddd;
    border-radius: 4px;
    min-width: 200px;
}

.securesphere-clear-logs {
    margin: 20px 0;
}

.securesphere-logs-table-wrap {
    background: #fff;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 20px;
    overflow-x: auto;
}

.wp-list-table {
    border: none;
}

.wp-list-table th {
    font-weight: 600;
    color: #1d2327;
}

.log-level {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}

.log-level-debug { background: #e5e5e5; color: #666; }
.log-level-info { background: #e5f5fa; color: #0073aa; }
.log-level-warning { background: #fff8e5; color: #d98500; }
.log-level-error { background: #fbeaea; color: #dc3232; }

.no-logs {
    text-align: center;
    padding: 20px;
    color: #666;
    font-style: italic;
}

.tablenav-pages {
    margin: 20px 0;
    text-align: right;
}

.tablenav-pages .page-numbers {
    padding: 5px 10px;
    margin: 0 2px;
    border: 1px solid #ddd;
    border-radius: 4px;
    text-decoration: none;
}

.tablenav-pages .current {
    background: #2271b1;
    color: #fff;
    border-color: #2271b1;
}

/* Modal Styles */
.securesphere-modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.5);
}

.securesphere-modal-content {
    background-color: #fff;
    margin: 5% auto;
    padding: 30px;
    border-radius: 8px;
    width: 80%;
    max-width: 800px;
    position: relative;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.securesphere-modal-close {
    position: absolute;
    right: 20px;
    top: 20px;
    font-size: 24px;
    font-weight: bold;
    cursor: pointer;
    color: #666;
}

.securesphere-modal-close:hover {
    color: #dc3232;
}

#log-details-content {
    background: #f5f5f5;
    padding: 20px;
    border-radius: 4px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
    margin-top: 20px;
    font-family: monospace;
    font-size: 13px;
    line-height: 1.5;
}
</style>

<script>
jQuery(document).ready(function($) {
    // Modal functionality
    $('.view-details').click(function() {
        var details = $(this).data('details');
        $('#log-details-content').text(details);
        $('#log-details-modal').fadeIn(200);
    });
    
    $('.securesphere-modal-close').click(function() {
        $('#log-details-modal').fadeOut(200);
    });
    
    $(window).click(function(event) {
        if ($(event.target).is('#log-details-modal')) {
            $('#log-details-modal').fadeOut(200);
        }
    });
});
</script> 