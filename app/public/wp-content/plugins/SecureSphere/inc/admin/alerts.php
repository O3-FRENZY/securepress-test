<?php
if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap">
    <h1>Alert Settings</h1>
    <form method="post" action="">
        <?php wp_nonce_field('securesphere_alerts_settings_action', 'securesphere_alerts_settings_nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><label for="securesphere_alerts_email">Alert Email Address</label></th>
                <td>
                    <input type="email" id="securesphere_alerts_email" name="securesphere_alerts_email" 
                           value="<?php echo esc_attr($email); ?>" class="regular-text" />
                    <p class="description">Email address where security alerts will be sent. Defaults to admin email if empty.</p>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row">Notification Types</th>
                <td>
                    <fieldset>
                        <label>
                            <input type="checkbox" name="securesphere_alerts_notification_types[]" value="security" 
                                <?php checked(in_array('security', $notification_types)); ?> />
                            Security Alerts (malware detection, suspicious activity)
                        </label><br>
                        <label>
                            <input type="checkbox" name="securesphere_alerts_notification_types[]" value="updates" 
                                <?php checked(in_array('updates', $notification_types)); ?> />
                            Update Notifications (plugin/theme/core updates)
                        </label><br>
                        <label>
                            <input type="checkbox" name="securesphere_alerts_notification_types[]" value="errors" 
                                <?php checked(in_array('errors', $notification_types)); ?> />
                            Error Reports (critical errors, failed scans)
                        </label>
                    </fieldset>
                </td>
            </tr>
        </table>
        <?php submit_button('Save Alert Settings'); ?>
    </form>

    <hr/>

    <h2>Test Email Alert</h2>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="securesphere_send_test_alert">
        <?php wp_nonce_field('securesphere_send_test_alert_nonce', '_wpnonce_test_alert'); ?>
        <?php submit_button('Send Test Email', 'secondary', 'send_test_alert_button', false); ?>
        <p class="description">Sends a test email to verify alert functionality.</p>
    </form>

    <?php if (isset($_GET['message'])): ?>
        <div class="notice notice-info is-dismissible">
            <?php
            $message = '';
            switch ($_GET['message']) {
                case 'test_email_sent':
                    $message = 'Test email sent successfully.';
                    break;
                case 'test_email_fail':
                    $message = 'Failed to send test email. Check your WordPress email settings.';
                    break;
                case 'test_email_fail_disabled':
                    $message = 'Failed to send test email: Alerts are disabled or no recipient email is set.';
                    break;
            }
            if ($message) {
                echo '<p>' . esc_html($message) . '</p>';
            }
            ?>
        </div>
    <?php endif; ?>
</div> 