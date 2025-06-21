<?php
if (!defined('ABSPATH')) {
    exit;
}

// Get current status
$firewall = SecureSphere_Firewall::init();
$config = SecureSphere_Config::init();
$logger = SecureSphere_Logger::init();

// Get statistics
$blocked_ips = get_option(SecureSphere_Firewall::OPT_BLOCKED_IPS, array());
$whitelisted_ips = get_option(SecureSphere_Firewall::OPT_WHITELISTED_IPS, array());
?>

<div class="wrap">
    <h1>SecureSphere Dashboard</h1>
    
    <div class="securesphere-status-grid">
        <!-- Firewall Status -->
        <div class="securesphere-status-box">
            <h2>Firewall Status</h2>
            <div class="status-content">
                <p><strong>Blocked IPs:</strong> <?php echo count($blocked_ips); ?></p>
                <p><strong>Whitelisted IPs:</strong> <?php echo count($whitelisted_ips); ?></p>
                <p><strong>Last Scan:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
            </div>
        </div>

        <!-- Security Status -->
        <div class="securesphere-status-box">
            <h2>Security Status</h2>
            <div class="status-content">
                <p><strong>Firewall:</strong> <span class="status-active">Active</span></p>
                <p><strong>Login Protection:</strong> <span class="status-active">Active</span></p>
                <p><strong>XML-RPC Protection:</strong> <span class="status-active">Active</span></p>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="securesphere-status-box">
            <h2>Quick Actions</h2>
            <div class="status-content">
                <button class="button button-primary" onclick="location.href='?page=securesphere-firewall'">Manage Firewall</button>
                <button class="button" onclick="location.href='?page=securesphere-settings'">Settings</button>
                <button class="button" onclick="location.href='?page=securesphere-logs'">View Logs</button>
            </div>
        </div>
    </div>

    <!-- Recent Activity -->
    <div class="securesphere-recent-activity">
        <h2>Recent Activity</h2>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>IP Address</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><?php echo date('Y-m-d H:i:s'); ?></td>
                    <td>System Initialized</td>
                    <td>N/A</td>
                    <td><span class="status-success">Success</span></td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<style>
.securesphere-status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin: 20px 0;
}

.securesphere-status-box {
    background: #fff;
    padding: 20px;
    border-radius: 5px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.securesphere-status-box h2 {
    margin-top: 0;
    padding-bottom: 10px;
    border-bottom: 1px solid #eee;
}

.status-content {
    margin-top: 15px;
}

.status-content p {
    margin: 10px 0;
}

.status-active {
    color: #46b450;
    font-weight: bold;
}

.status-inactive {
    color: #dc3232;
    font-weight: bold;
}

.status-success {
    color: #46b450;
}

.status-warning {
    color: #ffb900;
}

.status-error {
    color: #dc3232;
}

.securesphere-recent-activity {
    margin-top: 30px;
}

.button {
    margin-right: 10px;
    margin-bottom: 10px;
}
</style>

<script>
jQuery(document).ready(function($) {
    // Add any JavaScript functionality here
    function updateStatus() {
        // This function can be used to update the dashboard in real-time
        // For now, it's just a placeholder
    }
    
    // Update status every 30 seconds
    setInterval(updateStatus, 30000);
});
</script> 