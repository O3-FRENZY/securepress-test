<?php
if (!defined('ABSPATH')) {
    exit;
}

// Upload Scanner module for SecureSphere
class SecureSphere_UploadScanner {
    private static $instance = null;
    
    public static function init() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        add_filter('upload_mimes', array($this, 'restrict_upload_types'));
        add_filter('wp_handle_upload_prefilter', array($this, 'scan_upload'));
        add_action('admin_init', array($this, 'init_settings'));
    }
    
    public function init_settings() {
        register_setting('securesphere_upload_settings', 'securesphere_upload_enabled');
        register_setting('securesphere_upload_settings', 'securesphere_allowed_types');
        register_setting('securesphere_upload_settings', 'securesphere_max_file_size');
    }
    
    public function restrict_upload_types($mimes) {
        $allowed_types = get_option('securesphere_allowed_types', array(
            'jpg|jpeg|jpe' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'pdf' => 'application/pdf',
            'doc|docx' => 'application/msword',
            'xls|xlsx' => 'application/vnd.ms-excel'
        ));
        
        return $allowed_types;
    }
    
    public function scan_upload($file) {
        if (!get_option('securesphere_upload_enabled', true)) {
            return $file;
        }
        
        // Check file size
        $max_size = get_option('securesphere_max_file_size', 5) * 1024 * 1024; // Convert MB to bytes
        if ($file['size'] > $max_size) {
            $file['error'] = sprintf('File size exceeds the maximum allowed size of %d MB.', $max_size / 1024 / 1024);
            return $file;
        }
        
        // Check file type
        $allowed_types = $this->restrict_upload_types(array());
        $file_type = wp_check_filetype($file['name']);
        
        if (!in_array($file_type['type'], $allowed_types)) {
            $file['error'] = 'File type not allowed.';
            return $file;
        }
        
        // Scan file content for malicious code
        if ($this->contains_malicious_code($file['tmp_name'])) {
            $file['error'] = 'File contains potentially malicious code.';
            return $file;
        }
        
        return $file;
    }
    
    private function contains_malicious_code($file_path) {
        $content = file_get_contents($file_path);
        
        // Check for PHP tags
        if (strpos($content, '<?php') !== false || strpos($content, '<?=') !== false) {
            return true;
        }
        
        // Check for common malicious patterns
        $patterns = array(
            '/eval\s*\(/i',
            '/base64_decode\s*\(/i',
            '/system\s*\(/i',
            '/exec\s*\(/i',
            '/shell_exec\s*\(/i',
            '/passthru\s*\(/i'
        );
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }
        
        return false;
    }
    
    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }
        ?>
        <div class="wrap">
            <h1><span class="dashicons dashicons-upload"></span> Upload Scanner</h1>
            
            <div class="securesphere-settings-box">
                <h2>Upload Scanner Settings</h2>
                <form method="post" action="options.php">
                    <?php
                    settings_fields('securesphere_upload_settings');
                    do_settings_sections('securesphere_upload_settings');
                    ?>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row">Enable Upload Scanner</th>
                            <td>
                                <label class="securesphere-switch">
                                    <input type="checkbox" name="securesphere_upload_enabled" value="1" <?php checked(get_option('securesphere_upload_enabled', true)); ?>>
                                    <span class="slider round"></span>
                                </label>
                                <p class="description">Enable file upload scanning and restrictions</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Maximum File Size</th>
                            <td>
                                <input type="number" name="securesphere_max_file_size" value="<?php echo esc_attr(get_option('securesphere_max_file_size', 5)); ?>" min="1" class="small-text">
                                <p class="description">Maximum file size in megabytes (MB)</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Allowed File Types</th>
                            <td>
                                <?php
                                $allowed_types = get_option('securesphere_allowed_types', array(
                                    'jpg|jpeg|jpe' => 'image/jpeg',
                                    'png' => 'image/png',
                                    'gif' => 'image/gif',
                                    'pdf' => 'application/pdf',
                                    'doc|docx' => 'application/msword',
                                    'xls|xlsx' => 'application/vnd.ms-excel'
                                ));
                                
                                foreach ($allowed_types as $ext => $mime) {
                                    $checked = in_array($mime, $allowed_types) ? 'checked' : '';
                                    echo '<label style="display: block; margin-bottom: 5px;">';
                                    echo '<input type="checkbox" name="securesphere_allowed_types[]" value="' . esc_attr($mime) . '" ' . $checked . '> ';
                                    echo esc_html($ext);
                                    echo '</label>';
                                }
                                ?>
                                <p class="description">Select the file types that are allowed to be uploaded</p>
                            </td>
                        </tr>
                    </table>
                    
                    <?php submit_button('Save Settings'); ?>
                </form>
            </div>
            
            <div class="securesphere-settings-box">
                <h2>Upload Statistics</h2>
                <div class="securesphere-stats-grid">
                    <div class="stat-box">
                        <h3>Total Scans</h3>
                        <p class="stat-number">0</p>
                    </div>
                    <div class="stat-box">
                        <h3>Blocked Files</h3>
                        <p class="stat-number">0</p>
                    </div>
                    <div class="stat-box">
                        <h3>Malicious Files</h3>
                        <p class="stat-number">0</p>
                    </div>
                </div>
            </div>
        </div>
        
        <style>
        .securesphere-settings-box {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin: 20px 0;
        }
        
        .securesphere-settings-box h2 {
            margin-top: 0;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .securesphere-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat-box {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }
        
        .stat-box h3 {
            margin: 0 0 10px 0;
            color: #1d2327;
        }
        
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #2271b1;
            margin: 0;
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
        </style>
        <?php
    }
} 