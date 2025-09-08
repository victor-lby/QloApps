<?php
/**
 * Security Audit Framework Installation Script
 * 
 * This script installs the security audit framework including database tables
 * and initial configuration.
 */

// Include PrestaShop bootstrap
require_once(dirname(__FILE__) . '/config/config.inc.php');

class SecurityAuditInstaller
{
    private $errors = array();
    private $success_messages = array();

    /**
     * Run the installation
     */
    public function install()
    {
        echo "QloApps Security Audit Framework Installation\n";
        echo str_repeat('=', 50) . "\n\n";

        // Check prerequisites
        if (!$this->checkPrerequisites()) {
            $this->showResults();
            return false;
        }

        // Install database tables
        if (!$this->installDatabaseTables()) {
            $this->showResults();
            return false;
        }

        // Install default configuration
        if (!$this->installDefaultConfiguration()) {
            $this->showResults();
            return false;
        }

        // Set up file permissions
        $this->setupFilePermissions();

        // Create initial audit
        $this->createInitialAudit();

        $this->success_messages[] = "Security Audit Framework installed successfully!";
        $this->showResults();
        
        return true;
    }

    /**
     * Check installation prerequisites
     */
    private function checkPrerequisites()
    {
        echo "Checking prerequisites...\n";

        // Check PHP version
        if (version_compare(PHP_VERSION, '5.6.0', '<')) {
            $this->errors[] = "PHP 5.6.0 or higher is required. Current version: " . PHP_VERSION;
            return false;
        }
        $this->success_messages[] = "PHP version check passed (" . PHP_VERSION . ")";

        // Check database connection
        try {
            $db = Db::getInstance();
            if (!$db) {
                $this->errors[] = "Could not connect to database";
                return false;
            }
            $this->success_messages[] = "Database connection check passed";
        } catch (Exception $e) {
            $this->errors[] = "Database connection error: " . $e->getMessage();
            return false;
        }

        // Check required directories exist
        $required_dirs = array(
            _PS_ROOT_DIR_ . '/classes/',
            _PS_ROOT_DIR_ . '/tools/',
            _PS_ROOT_DIR_ . '/install/'
        );

        foreach ($required_dirs as $dir) {
            if (!is_dir($dir)) {
                $this->errors[] = "Required directory not found: {$dir}";
                return false;
            }
        }
        $this->success_messages[] = "Directory structure check passed";

        // Check write permissions
        $writable_dirs = array(
            _PS_ROOT_DIR_ . '/classes/',
            _PS_ROOT_DIR_ . '/tools/'
        );

        foreach ($writable_dirs as $dir) {
            if (!is_writable($dir)) {
                $this->errors[] = "Directory not writable: {$dir}";
                return false;
            }
        }
        $this->success_messages[] = "Write permissions check passed";

        return true;
    }

    /**
     * Install database tables
     */
    private function installDatabaseTables()
    {
        echo "Installing database tables...\n";

        // Read SQL file
        $sql_file = _PS_ROOT_DIR_ . '/install/sql/security_audit_tables.sql';
        
        if (!file_exists($sql_file)) {
            $this->errors[] = "SQL installation file not found: {$sql_file}";
            return false;
        }

        $sql_content = file_get_contents($sql_file);
        
        // Replace placeholders
        $sql_content = str_replace('PREFIX_', _DB_PREFIX_, $sql_content);
        $sql_content = str_replace('ENGINE_TYPE', _MYSQL_ENGINE_, $sql_content);

        // Split into individual queries
        $queries = array_filter(array_map('trim', explode(';', $sql_content)));

        $db = Db::getInstance();
        
        foreach ($queries as $query) {
            if (empty($query) || strpos($query, '--') === 0) {
                continue;
            }

            try {
                if (!$db->execute($query)) {
                    $this->errors[] = "Failed to execute SQL query: " . substr($query, 0, 100) . "...";
                    return false;
                }
            } catch (Exception $e) {
                $this->errors[] = "SQL execution error: " . $e->getMessage();
                return false;
            }
        }

        $this->success_messages[] = "Database tables installed successfully";
        return true;
    }

    /**
     * Install default configuration
     */
    private function installDefaultConfiguration()
    {
        echo "Installing default configuration...\n";

        // Include configuration class
        require_once(_PS_ROOT_DIR_ . '/classes/SecurityAuditConfig.php');

        try {
            // The default configuration is already inserted via SQL
            // Just verify it's working
            $config = SecurityAuditConfig::getScanConfig();
            
            if (empty($config)) {
                $this->errors[] = "Could not load default configuration";
                return false;
            }

            $this->success_messages[] = "Default configuration installed successfully";
            return true;
        } catch (Exception $e) {
            $this->errors[] = "Configuration installation error: " . $e->getMessage();
            return false;
        }
    }

    /**
     * Set up file permissions
     */
    private function setupFilePermissions()
    {
        echo "Setting up file permissions...\n";

        $files_to_chmod = array(
            _PS_ROOT_DIR_ . '/tools/security_audit_cli.php' => 0755
        );

        foreach ($files_to_chmod as $file => $permission) {
            if (file_exists($file)) {
                if (chmod($file, $permission)) {
                    $this->success_messages[] = "Set permissions for: " . basename($file);
                } else {
                    $this->errors[] = "Could not set permissions for: " . basename($file);
                }
            }
        }
    }

    /**
     * Create initial audit for testing
     */
    private function createInitialAudit()
    {
        echo "Creating initial audit...\n";

        try {
            // Include audit classes
            require_once(_PS_ROOT_DIR_ . '/classes/SecurityAudit.php');

            $audit = new SecurityAudit();
            $audit->audit_name = 'Installation Test Audit';
            $audit->status = 'initialized';
            
            if ($audit->save()) {
                $this->success_messages[] = "Created initial audit (ID: {$audit->id})";
            } else {
                $this->errors[] = "Could not create initial audit";
            }
        } catch (Exception $e) {
            $this->errors[] = "Initial audit creation error: " . $e->getMessage();
        }
    }

    /**
     * Show installation results
     */
    private function showResults()
    {
        echo "\nInstallation Results:\n";
        echo str_repeat('-', 30) . "\n";

        if (!empty($this->success_messages)) {
            echo "\nSUCCESS:\n";
            foreach ($this->success_messages as $message) {
                echo "  ✓ {$message}\n";
            }
        }

        if (!empty($this->errors)) {
            echo "\nERRORS:\n";
            foreach ($this->errors as $error) {
                echo "  ✗ {$error}\n";
            }
        }

        echo "\n";

        if (empty($this->errors)) {
            echo "Installation completed successfully!\n\n";
            echo "Next steps:\n";
            echo "1. Run a security scan: php tools/security_audit_cli.php scan\n";
            echo "2. View audit results: php tools/security_audit_cli.php list-audits\n";
            echo "3. Configure scan settings: php tools/security_audit_cli.php config\n";
        } else {
            echo "Installation failed. Please fix the errors above and try again.\n";
        }
    }

    /**
     * Uninstall the security audit framework
     */
    public function uninstall()
    {
        echo "Uninstalling Security Audit Framework...\n";

        $tables_to_drop = array(
            _DB_PREFIX_ . 'security_audit',
            _DB_PREFIX_ . 'security_finding',
            _DB_PREFIX_ . 'security_scan_config'
        );

        $db = Db::getInstance();
        
        foreach ($tables_to_drop as $table) {
            $sql = "DROP TABLE IF EXISTS `{$table}`";
            if ($db->execute($sql)) {
                echo "Dropped table: {$table}\n";
            } else {
                echo "Error dropping table: {$table}\n";
            }
        }

        echo "Uninstallation completed.\n";
    }
}

// Run installation or uninstallation based on command line argument
if (php_sapi_name() === 'cli') {
    $installer = new SecurityAuditInstaller();
    
    if (isset($argv[1]) && $argv[1] === 'uninstall') {
        $installer->uninstall();
    } else {
        $installer->install();
    }
} else {
    // Web interface
    echo "<h1>QloApps Security Audit Framework Installation</h1>";
    
    if (isset($_GET['action']) && $_GET['action'] === 'install') {
        echo "<pre>";
        $installer = new SecurityAuditInstaller();
        $installer->install();
        echo "</pre>";
    } else {
        echo "<p>Click the button below to install the Security Audit Framework:</p>";
        echo "<a href='?action=install' style='background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Install Security Audit Framework</a>";
    }
}