<?php
if (!defined('ABSPATH')) {
    exit;
}

$firewall = SecureSphere_Firewall::init();
$blocked_ips = get_option(SecureSphere_Firewall::OPT_BLOCKED_IPS, array());
$whitelisted_ips = get_option(SecureSphere_Firewall::OPT_WHITELISTED_IPS, array());
?>

<div class="wrap">
    <h1>Firewall Settings</h1>

    <div class="securesphere-firewall-grid">
        <!-- Blocked IPs -->
        <div class="securesphere-settings-box">
            <h2>Blocked IPs</h2>
            <div class="settings-content">
                <form method="post" action="">
                    <?php wp_nonce_field('securesphere_block_ip', 'securesphere_block_ip_nonce'); ?>
                    <p>
                        <input type="text" name="ip_to_block" placeholder="Enter IP to block" class="regular-text">
                        <input type="submit" name="block_ip" class="button" value="Block IP">
                    </p>
                </form>
                
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($blocked_ips as $ip): ?>
                        <tr>
                            <td><?php echo esc_html($ip); ?></td>
                            <td>
                                <form method="post" action="" style="display:inline;">
                                    <?php wp_nonce_field('securesphere_unblock_ip', 'securesphere_unblock_ip_nonce'); ?>
                                    <input type="hidden" name="ip_to_unblock" value="<?php echo esc_attr($ip); ?>">
                                    <input type="submit" name="unblock_ip" class="button" value="Unblock">
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Whitelisted IPs -->
        <div class="securesphere-settings-box">
            <h2>Whitelisted IPs</h2>
            <div class="settings-content">
                <form method="post" action="">
                    <?php wp_nonce_field('securesphere_whitelist_ip', 'securesphere_whitelist_ip_nonce'); ?>
                    <p>
                        <input type="text" name="ip_to_whitelist" placeholder="Enter IP to whitelist" class="regular-text">
                        <input type="submit" name="whitelist_ip" class="button" value="Whitelist IP">
                    </p>
                </form>
                
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($whitelisted_ips as $ip): ?>
                        <tr>
                            <td><?php echo esc_html($ip); ?></td>
                            <td>
                                <form method="post" action="" style="display:inline;">
                                    <?php wp_nonce_field('securesphere_remove_whitelist', 'securesphere_remove_whitelist_nonce'); ?>
                                    <input type="hidden" name="ip_to_remove" value="<?php echo esc_attr($ip); ?>">
                                    <input type="submit" name="remove_whitelist" class="button" value="Remove">
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<style>
.securesphere-firewall-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 20px;
    margin: 20px 0;
}

.securesphere-settings-box {
    background: #fff;
    padding: 20px;
    border-radius: 5px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.securesphere-settings-box h2 {
    margin-top: 0;
    padding-bottom: 10px;
    border-bottom: 1px solid #eee;
}

.settings-content {
    margin-top: 15px;
}

.settings-content p {
    margin: 10px 0;
}

.button {
    margin-right: 10px;
    margin-bottom: 10px;
}
</style> 