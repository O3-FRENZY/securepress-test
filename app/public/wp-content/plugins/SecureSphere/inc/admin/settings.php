<?php
if (!defined('ABSPATH')) {
    exit;
}

$config = SecureSphere_Config::init();

// Handle form submission
if (isset($_POST['securesphere_settings_nonce']) && wp_verify_nonce($_POST['securesphere_settings_nonce'], 'securesphere_save_settings')) {
    // Firewall Settings
    update_option('securesphere_firewall_enabled', isset($_POST['firewall_enabled']));
    update_option('securesphere_login_protection', isset($_POST['login_protection']));
    update_option('securesphere_xmlrpc_protection', isset($_POST['xmlrpc_protection']));
    update_option('securesphere_rest_api_protection', isset($_POST['rest_api_protection']));
    
    // Alert Settings
    update_option('securesphere_email_notifications', isset($_POST['email_notifications']));
    update_option('securesphere_alert_email', sanitize_email($_POST['alert_email']));
    
    // Logging Settings
    update_option('securesphere_log_retention_days', absint($_POST['log_retention_days']));
    update_option('securesphere_log_level', sanitize_text_field($_POST['log_level']));
    
    echo '<div class="notice notice-success is-dismissible"><p>Settings saved successfully.</p></div>';
}

// Get current settings
$firewall_enabled = get_option('securesphere_firewall_enabled', true);
$login_protection = get_option('securesphere_login_protection', true);
$xmlrpc_protection = get_option('securesphere_xmlrpc_protection', true);
$rest_api_protection = get_option('securesphere_rest_api_protection', true);
$email_notifications = get_option('securesphere_email_notifications', true);
$alert_email = get_option('securesphere_alert_email', get_option('admin_email'));
$log_retention_days = get_option('securesphere_log_retention_days', 30);
$log_level = get_option('securesphere_log_level', 'warning');
?>

<div class="wrap securesphere-settings-wrap">
    <h1>SecureSphere Settings</h1>
    
    <form method="post" action="">
        <?php wp_nonce_field('securesphere_save_settings', 'securesphere_settings_nonce'); ?>
        
        <div class="securesphere-settings-grid">
            <!-- Firewall Settings -->
            <div class="securesphere-settings-box">
                <h2><span class="dashicons dashicons-shield"></span> Firewall Settings</h2>
                <div class="settings-content">
                    <table class="form-table">
                        <tr>
                            <th scope="row">Enable Firewall</th>
                            <td>
                                <label class="securesphere-switch">
                                    <input type="checkbox" name="firewall_enabled" value="1" <?php checked($firewall_enabled); ?>>
                                    <span class="slider round"></span>
                                </label>
                                <span class="description">Enable the firewall protection</span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Login Protection</th>
                            <td>
                                <label class="securesphere-switch">
                                    <input type="checkbox" name="login_protection" value="1" <?php checked($login_protection); ?>>
                                    <span class="slider round"></span>
                                </label>
                                <span class="description">Protect against brute force login attempts</span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">XML-RPC Protection</th>
                            <td>
                                <label class="securesphere-switch">
                                    <input type="checkbox" name="xmlrpc_protection" value="1" <?php checked($xmlrpc_protection); ?>>
                                    <span class="slider round"></span>
                                </label>
                                <span class="description">Protect XML-RPC endpoints</span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">REST API Protection</th>
                            <td>
                                <label class="securesphere-switch">
                                    <input type="checkbox" name="rest_api_protection" value="1" <?php checked($rest_api_protection); ?>>
                                    <span class="slider round"></span>
                                </label>
                                <span class="description">Protect REST API endpoints</span>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Alert Settings -->
            <div class="securesphere-settings-box">
                <h2><span class="dashicons dashicons-bell"></span> Alert Settings</h2>
                <div class="settings-content">
                    <table class="form-table">
                        <tr>
                            <th scope="row">Email Notifications</th>
                            <td>
                                <label class="securesphere-switch">
                                    <input type="checkbox" name="email_notifications" value="1" <?php checked($email_notifications); ?>>
                                    <span class="slider round"></span>
                                </label>
                                <span class="description">Enable email notifications</span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Alert Email</th>
                            <td>
                                <input type="email" name="alert_email" value="<?php echo esc_attr($alert_email); ?>" class="regular-text">
                                <p class="description">Email address to receive security alerts</p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Logging Settings -->
            <div class="securesphere-settings-box">
                <h2><span class="dashicons dashicons-list-view"></span> Logging Settings</h2>
                <div class="settings-content">
                    <table class="form-table">
                        <tr>
                            <th scope="row">Log Retention</th>
                            <td>
                                <input type="number" name="log_retention_days" value="<?php echo esc_attr($log_retention_days); ?>" min="1" max="365" class="small-text">
                                <p class="description">Number of days to keep logs (1-365)</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Log Level</th>
                            <td>
                                <select name="log_level" class="regular-text">
                                    <option value="debug" <?php selected($log_level, 'debug'); ?>>Debug</option>
                                    <option value="info" <?php selected($log_level, 'info'); ?>>Info</option>
                                    <option value="warning" <?php selected($log_level, 'warning'); ?>>Warning</option>
                                    <option value="error" <?php selected($log_level, 'error'); ?>>Error</option>
                                </select>
                                <p class="description">Minimum level of events to log</p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <p class="submit">
            <input type="submit" name="submit" id="submit" class="button button-primary" value="Save Settings">
        </p>
    </form>
</div>

<style>
.securesphere-settings-wrap {
    margin: 20px;
}

.securesphere-settings-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 20px;
    margin: 20px 0;
}

.securesphere-settings-box {
    background: #fff;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.securesphere-settings-box h2 {
    margin-top: 0;
    padding-bottom: 10px;
    border-bottom: 1px solid #eee;
    display: flex;
    align-items: center;
    gap: 10px;
}

.securesphere-settings-box h2 .dashicons {
    color: #2271b1;
}

.settings-content {
    margin-top: 15px;
}

.form-table th {
    width: 200px;
    padding: 20px 10px 20px 0;
}

.description {
    color: #666;
    font-style: italic;
    margin-top: 5px;
}

/* Toggle Switch */
.securesphere-switch {
    position: relative;
    display: inline-block;
    width: 50px;
    height: 24px;
    margin-right: 10px;
}

.securesphere-switch input {
    opacity: 0;
    width: 0;
    height: 0;
}

.slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #ccc;
    transition: .4s;
}

.slider:before {
    position: absolute;
    content: "";
    height: 16px;
    width: 16px;
    left: 4px;
    bottom: 4px;
    background-color: white;
    transition: .4s;
}

input:checked + .slider {
    background-color: #2271b1;
}

input:focus + .slider {
    box-shadow: 0 0 1px #2271b1;
}

input:checked + .slider:before {
    transform: translateX(26px);
}

.slider.round {
    border-radius: 24px;
}

.slider.round:before {
    border-radius: 50%;
}

/* Form Elements */
input[type="email"],
input[type="number"],
select {
    padding: 8px;
    border: 1px solid #ddd;
    border-radius: 4px;
}

input[type="email"]:focus,
input[type="number"]:focus,
select:focus {
    border-color: #2271b1;
    box-shadow: 0 0 0 1px #2271b1;
    outline: none;
}

.submit {
    margin-top: 20px;
    padding: 20px;
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
</style> 