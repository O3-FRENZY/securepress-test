<?php
if (!defined('ABSPATH')) {
    exit;
}

class SecureSphere_IPFiltering {
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

        try {
            // Get blocked and whitelisted IPs
            $blocked_ips = $this->db->get_blocked_ips();
            $whitelisted_ips = get_option('securesphere_whitelisted_ips', array());
            ?>
            <div class="wrap">
                <h1>IP Filtering</h1>
                
                <?php if (isset($_GET['error'])) : ?>
                    <div class="notice notice-error">
                        <p><?php echo esc_html(urldecode($_GET['error'])); ?></p>
                    </div>
                <?php endif; ?>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Blocked IPs</h2>
                    </div>
                    <div class="ss-card-body">
                        <?php if (!empty($blocked_ips)) : ?>
                            <div class="ss-table-responsive">
                                <table class="ss-table">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Reason</th>
                                            <th>Blocked Until</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($blocked_ips as $ip) : ?>
                                            <tr>
                                                <td><?php echo esc_html($ip['ip']); ?></td>
                                                <td><?php echo esc_html($ip['reason']); ?></td>
                                                <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($ip['blocked_until']))); ?></td>
                                                <td>
                                                    <button class="ss-button ss-button-small ss-unblock-ip" 
                                                            data-ip="<?php echo esc_attr($ip['ip']); ?>">
                                                        Unblock
                                                    </button>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else : ?>
                            <div class="ss-empty-state">
                                <span class="dashicons dashicons-shield ss-empty-state-icon"></span>
                                <p>No IPs are currently blocked.</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Whitelisted IPs</h2>
                    </div>
                    <div class="ss-card-body">
                        <?php if (!empty($whitelisted_ips)) : ?>
                            <div class="ss-table-responsive">
                                <table class="ss-table">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($whitelisted_ips as $ip) : ?>
                                            <tr>
                                                <td><?php echo esc_html($ip); ?></td>
                                                <td>
                                                    <button class="ss-button ss-button-small ss-remove-whitelist" 
                                                            data-ip="<?php echo esc_attr($ip); ?>">
                                                        Remove
                                                    </button>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else : ?>
                            <div class="ss-empty-state">
                                <span class="dashicons dashicons-shield ss-empty-state-icon"></span>
                                <p>No IPs are currently whitelisted.</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <?php
        } catch (Exception $e) {
            error_log('SecureSphere IP Filtering Error: ' . $e->getMessage());
            ?>
            <div class="wrap">
                <h1>IP Filtering</h1>
                <div class="notice notice-error">
                    <p>An error occurred while loading the IP filtering page. Please try refreshing the page or contact support if the issue persists.</p>
                </div>
            </div>
            <?php
        }
    }
} 