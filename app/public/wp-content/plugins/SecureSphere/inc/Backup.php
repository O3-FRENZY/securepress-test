<?php
if (!defined('ABSPATH')) {
    exit;
}

class SecureSphere_Backup {
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
            // Get backup settings
            $settings = get_option('securesphere_backup_settings', array(
                'enabled' => false,
                'frequency' => 'daily',
                'retention' => 7
            ));

            // Get backup history
            $backups = $this->get_backup_history();
            ?>
            <div class="wrap">
                <h1>Backup Settings</h1>
                
                <?php if (isset($_GET['error'])) : ?>
                    <div class="notice notice-error">
                        <p><?php echo esc_html(urldecode($_GET['error'])); ?></p>
                    </div>
                <?php endif; ?>

                <?php if (isset($_GET['success'])) : ?>
                    <div class="notice notice-success">
                        <p><?php echo esc_html(urldecode($_GET['success'])); ?></p>
                    </div>
                <?php endif; ?>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Automated Backups</h2>
                    </div>
                    <div class="ss-card-body">
                        <form method="post" action="options.php">
                            <?php settings_fields('securesphere_backup_settings'); ?>
                            
                            <table class="form-table">
                                <tr>
                                    <th scope="row">Enable Automated Backups</th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="securesphere_backup_settings[enabled]" 
                                                value="1" <?php checked($settings['enabled']); ?>>
                                            Enable automated backups
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">Backup Frequency</th>
                                    <td>
                                        <select name="securesphere_backup_settings[frequency]">
                                            <option value="hourly" <?php selected($settings['frequency'], 'hourly'); ?>>Hourly</option>
                                            <option value="daily" <?php selected($settings['frequency'], 'daily'); ?>>Daily</option>
                                            <option value="weekly" <?php selected($settings['frequency'], 'weekly'); ?>>Weekly</option>
                                        </select>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">Retention Period (days)</th>
                                    <td>
                                        <input type="number" name="securesphere_backup_settings[retention]" 
                                            value="<?php echo esc_attr($settings['retention']); ?>" min="1" max="365">
                                    </td>
                                </tr>
                            </table>
                            
                            <?php submit_button('Save Settings'); ?>
                        </form>
                    </div>
                </div>

                <div class="ss-card">
                    <div class="ss-card-header">
                        <h2>Backup History</h2>
                        <button class="ss-button ss-button-primary" onclick="createBackup()">
                            Create Backup Now
                        </button>
                    </div>
                    <div class="ss-card-body">
                        <?php if (empty($backups)): ?>
                            <p>No backups found.</p>
                        <?php else: ?>
                            <table class="wp-list-table widefat fixed striped">
                                <thead>
                                    <tr>
                                        <th>Date</th>
                                        <th>Size</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($backups as $backup): ?>
                                        <tr>
                                            <td><?php echo esc_html($backup['date']); ?></td>
                                            <td><?php echo esc_html($backup['size']); ?></td>
                                            <td>
                                                <span class="ss-status ss-status-<?php echo esc_attr($backup['status']); ?>">
                                                    <?php echo esc_html($backup['status']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <button class="ss-button ss-button-small" 
                                                    onclick="downloadBackup('<?php echo esc_js($backup['id']); ?>')">
                                                    Download
                                                </button>
                                                <button class="ss-button ss-button-small ss-button-danger" 
                                                    onclick="deleteBackup('<?php echo esc_js($backup['id']); ?>')">
                                                    Delete
                                                </button>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <script>
            function createBackup() {
                if (!confirm('Are you sure you want to create a new backup?')) {
                    return;
                }
                
                jQuery.post(ajaxurl, {
                    action: 'securesphere_create_backup',
                    nonce: '<?php echo wp_create_nonce('securesphere_create_backup'); ?>'
                }, function(response) {
                    if (response.success) {
                        location.reload();
                    } else {
                        alert('Failed to create backup: ' + response.data);
                    }
                });
            }

            function downloadBackup(id) {
                window.location.href = ajaxurl + '?action=securesphere_download_backup&id=' + id + 
                    '&nonce=<?php echo wp_create_nonce('securesphere_download_backup'); ?>';
            }

            function deleteBackup(id) {
                if (!confirm('Are you sure you want to delete this backup?')) {
                    return;
                }
                
                jQuery.post(ajaxurl, {
                    action: 'securesphere_delete_backup',
                    id: id,
                    nonce: '<?php echo wp_create_nonce('securesphere_delete_backup'); ?>'
                }, function(response) {
                    if (response.success) {
                        location.reload();
                    } else {
                        alert('Failed to delete backup: ' + response.data);
                    }
                });
            }
            </script>
            <?php
        } catch (Exception $e) {
            error_log('SecureSphere Backup Error: ' . $e->getMessage());
            ?>
            <div class="wrap">
                <h1>Backup Settings</h1>
                <div class="notice notice-error">
                    <p>An error occurred while loading the backup page. Please try again later.</p>
                </div>
            </div>
            <?php
        }
    }

    private function get_backup_history() {
        // This is a placeholder - implement actual backup history retrieval
        return array();
    }
} 