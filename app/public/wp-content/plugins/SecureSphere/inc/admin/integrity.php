<?php
if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap">
    <h1>File Integrity Monitoring</h1>

    <?php if (isset($_GET['message'])): ?>
        <div class="notice notice-success is-dismissible">
            <?php if ($_GET['message'] === 'baseline_generated'): ?>
                <p>Baseline generated successfully. <?php echo isset($_GET['count']) ? intval($_GET['count']) . ' files indexed.' : ''; ?></p>
            <?php elseif ($_GET['message'] === 'scan_completed'): ?>
                <p>Integrity scan completed.</p>
            <?php elseif ($_GET['message'] === 'perms_attempted'): ?>
                <p>Attempt to secure permissions completed. Check results below.</p>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    
    <?php if ($perm_results): ?>
    <div id="permissions-results" class="notice notice-info is-dismissible" style="margin-top:15px; padding:10px;">
        <h4>Permissions Update Results:</h4>
        <?php if (!empty($perm_results['success'])): ?>
            <p style="margin-bottom: 5px;"><strong>Successful:</strong></p>
            <ul style="list-style-type:disc; margin-left:20px; margin-top:0;">
                <?php foreach($perm_results['success'] as $msg): ?>
                    <li><?php echo esc_html($msg); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
         <?php if (!empty($perm_results['fail'])): ?>
            <p style="margin-bottom: 5px;"><strong>Failed:</strong></p>
            <ul style="list-style-type:disc; margin-left:20px; margin-top:0;">
                <?php foreach($perm_results['fail'] as $msg): ?>
                    <li style="color:red;"><?php echo esc_html($msg); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
         <?php if (empty($perm_results['success']) && empty($perm_results['fail'])): ?>
            <p>No permission changes were attempted or needed.</p>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <form method="post" action="">
        <?php wp_nonce_field('securesphere_fim_settings_action', 'securesphere_fim_settings_nonce'); ?>
        <h2>Settings</h2>
        <table class="form-table">
            <tr valign="top">
                <th scope="row">Enable Scheduled FIM</th>
                <td><input type="checkbox" name="<?php echo self::OPT_SETTINGS_ENABLED; ?>" value="1" <?php checked($settings[self::OPT_SETTINGS_ENABLED]); ?> /> Enable regular scheduled integrity scans.</td>
            </tr>
            <tr valign="top">
                <th scope="row"><label for="<?php echo self::OPT_SETTINGS_FREQUENCY; ?>">Scheduled Scan Frequency</label></th>
                <td>
                    <select name="<?php echo self::OPT_SETTINGS_FREQUENCY; ?>" id="<?php echo self::OPT_SETTINGS_FREQUENCY; ?>" <?php if (!$settings[self::OPT_SETTINGS_ENABLED]) echo 'disabled'; ?>>
                        <?php
                        $schedules = wp_get_schedules();
                        foreach ($schedules as $key => $details) {
                            echo '<option value="' . esc_attr($key) . '" ' . selected($settings[self::OPT_SETTINGS_FREQUENCY], $key, false) . '>' . esc_html($details['display']) . '</option>';
                        }
                        ?>
                    </select>
                </td>
            </tr>
             <tr valign="top">
                <th scope="row">Enable Action-Triggered Checks</th>
                <td>
                    <input type="checkbox" name="<?php echo self::OPT_SETTINGS_REALTIME_CHECKS; ?>" value="1" <?php checked($settings[self::OPT_SETTINGS_REALTIME_CHECKS]); ?> />
                    Run an integrity check after plugin/theme/core updates or activations.
                </td>
            </tr>
            <tr><th colspan="2"><h3>Directories to Monitor (for both scheduled and action-triggered scans):</h3></th></tr>
            <tr valign="top">
                <th scope="row">WordPress Core</th>
                <td><input type="checkbox" name="<?php echo self::OPT_SETTINGS_MONITOR_CORE; ?>" value="1" <?php checked($settings[self::OPT_SETTINGS_MONITOR_CORE]); ?> /> (wp-admin, wp-includes, root PHP files)</td>
            </tr>
            <tr valign="top">
                <th scope="row">Plugins</th>
                <td><input type="checkbox" name="<?php echo self::OPT_SETTINGS_MONITOR_PLUGINS; ?>" value="1" <?php checked($settings[self::OPT_SETTINGS_MONITOR_PLUGINS]); ?> /> (<?php echo esc_html(WP_PLUGIN_DIR); ?>)</td>
            </tr>
            <tr valign="top">
                <th scope="row">Themes</th>
                <td><input type="checkbox" name="<?php echo self::OPT_SETTINGS_MONITOR_THEMES; ?>" value="1" <?php checked($settings[self::OPT_SETTINGS_MONITOR_THEMES]); ?> /> (<?php echo esc_html(get_theme_root()); ?>)</td>
            </tr>
            <tr valign="top">
                <th scope="row">Uploads</th>
                <td><input type="checkbox" name="<?php echo self::OPT_SETTINGS_MONITOR_UPLOADS; ?>" value="1" <?php checked($settings[self::OPT_SETTINGS_MONITOR_UPLOADS]); ?> /> (<?php $upload_dir = wp_upload_dir(); echo esc_html($upload_dir['basedir']); ?>) - Can be resource-intensive.</td>
            </tr>
        </table>
        <?php submit_button('Save FIM Settings'); ?>
    </form>
    <hr/>
    <h2>Manual Actions</h2>
    <p>
        <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=securesphere_fim_generate_baseline'), 'securesphere_fim_generate_baseline_nonce', '_wpnonce_fim_baseline')); ?>" class="button button-secondary">
            <?php echo $baseline_exists ? 'Re-generate Baseline' : 'Generate Initial Baseline'; ?>
        </a>
        <?php if ($baseline_exists): ?>
        <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=securesphere_fim_run_scan'), 'securesphere_fim_run_scan_nonce', '_wpnonce_fim_scan')); ?>" class="button button-primary">
            Run Integrity Scan Now
        </a>
        <?php else: ?>
        <button class="button button-primary" disabled title="Generate baseline first">Run Integrity Scan Now</button>
        <?php endif; ?>
    </p>
    <hr/>
    <h2>File & Directory Permissions Hardening</h2>
    <p>This tool checks key file and directory permissions and attempts to set them to recommended secure values. Success depends on server configuration and file ownership.</p>
    <p><strong>Recommended Permissions:</strong> Files (e.g., 0644), Directories (e.g., 0755), wp-config.php (e.g., 0600 or 0400).</p>
    <table class="wp-list-table widefat fixed striped" style="margin-top:10px; margin-bottom:10px;">
        <thead><tr><th style="width:30%;">Path</th><th style="width:20%;">Current Permissions</th><th style="width:20%;">Recommended</th><th style="width:30%;">Status</th></tr></thead>
        <tbody>
            <?php
            $check_paths_perms = [
                'wp-config.php' => ['path' => ABSPATH . 'wp-config.php', 'rec' => '0600', 'type' => 'file'],
                'WordPress Root Dir' => ['path' => ABSPATH, 'rec' => '0755', 'type' => 'dir'],
                '.htaccess' => ['path' => ABSPATH . '.htaccess', 'rec' => '0644', 'type' => 'file'],
                'wp-admin Dir' => ['path' => ABSPATH . 'wp-admin/', 'rec' => '0755', 'type' => 'dir'],
                'wp-includes Dir' => ['path' => ABSPATH . 'wp-includes/', 'rec' => '0755', 'type' => 'dir'],
                'wp-content Dir' => ['path' => WP_CONTENT_DIR, 'rec' => '0755', 'type' => 'dir'],
                'plugins Dir' => ['path' => WP_PLUGIN_DIR, 'rec' => '0755', 'type' => 'dir'],
                'themes Dir' => ['path' => get_theme_root(), 'rec' => '0755', 'type' => 'dir'],
                'uploads Dir' => ['path' => wp_upload_dir()['basedir'], 'rec' => '0755', 'type' => 'dir'],
            ];
            // Add root PHP files
            $root_php_files_check = glob(ABSPATH . '*.php');
            if($root_php_files_check){
                foreach ($root_php_files_check as $r_file) {
                    if (basename($r_file) !== 'wp-config.php') {
                        $check_paths_perms[basename($r_file)] = ['path' => $r_file, 'rec' => '0644', 'type' => 'file'];
                    }
                }
            }

            foreach ($check_paths_perms as $label => $item) {
                $path = wp_normalize_path($item['path']);
                $status_text = '<span style="color:grey;">Not Checked</span>';
                $current_perms_str = 'N/A';
                if (file_exists($path)) {
                    clearstatcache(true, $path);
                    $current_perms_octal = substr(sprintf('%o', fileperms($path)), -4);
                    $current_perms_str = $current_perms_octal;
                    if ($current_perms_octal === $item['rec']) {
                        $status_text = '<span style="color:green;">Secure</span>';
                    } else {
                        $status_text = '<span style="color:red;">Not Secure (Current: ' . $current_perms_octal . ')</span>';
                    }
                } else {
                   $status_text = '<span style="color:orange;">Not Found</span>';
                }
                echo '<tr><td>' . esc_html($label) . ' <small>(' . esc_html(str_replace(ABSPATH, '', $path)) . ')</small></td><td>' . esc_html($current_perms_str) . '</td><td>' . esc_html($item['rec']) . '</td><td>' . $status_text . '</td></tr>';
            }
            ?>
        </tbody>
    </table>
    <p>
         <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=securesphere_fim_secure_permissions'), 'securesphere_fim_secure_permissions_nonce', '_wpnonce_fim_secure_perms')); ?>" class="button button-secondary">
            Attempt to Secure Permissions
        </a>
    </p>
    <hr/>
    <h2>Last Scan Results</h2>
    <p><strong>Last Scan Time:</strong> <?php echo esc_html($last_scan_time); ?></p>
    <?php if (isset($last_scan_results['error'])): ?>
        <div class="notice notice-error"><p><?php echo esc_html($last_scan_results['error']); ?></p></div>
    <?php elseif (empty($last_scan_results) || !isset($last_scan_results['summary'])): ?>
        <p>No scan results available. Run a scan or generate a baseline.</p>
    <?php else: ?>
        <p><strong>Summary:</strong> <?php echo esc_html($last_scan_results['summary']); ?></p>
        <?php
        $issue_types = ['modified' => 'Modified Files', 'added' => 'Added Files', 'deleted' => 'Deleted Files'];
        foreach ($issue_types as $type => $label):
            if (!empty($last_scan_results[$type])): ?>
                <h3><?php echo esc_html($label); ?> (<?php echo count($last_scan_results[$type]); ?>)</h3>
                <ul style="max-height: 200px; overflow-y: auto; border: 1px solid #ccc; padding: 10px;">
                    <?php foreach ($last_scan_results[$type] as $file): ?>
                        <li><?php echo esc_html($file); ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif;
        endforeach;
        ?>
    <?php endif; ?>
</div> 