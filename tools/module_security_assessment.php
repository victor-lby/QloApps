<?php
/**
 * Module Security Assessment Tool
 * 
 * Comprehensive security assessment tool for QloApps modules
 * Analyzes module security practices, authentication, input validation, and dependencies
 */

if (!defined('_PS_VERSION_')) {
    require_once(dirname(__FILE__) . '/../config/config.inc.php');
}

require_once(dirname(__FILE__) . '/../classes/SecurityAudit.php');
require_once(dirname(__FILE__) . '/../classes/SecurityFinding.php');
require_once(dirname(__FILE__) . '/../classes/SecurityScanner.php');
require_once(dirname(__FILE__) . '/../classes/SecurityAuditUtils.php');

class ModuleSecurityAssessment
{
    private $modules_dir;
    private $results;
    private $audit_id;

    public function __construct($audit_id = null)
    {
        $this->modules_dir = _PS_ROOT_DIR_ . '/modules/';
        $this->results = array();
        $this->audit_id = $audit_id;
    }

    /**
     * Run comprehensive module security assessment
     */
    public function runAssessment()
    {
        echo "Starting Module Security Assessment...\n";
        echo "=====================================\n\n";

        if (!is_dir($this->modules_dir)) {
            echo "Error: Modules directory not found at {$this->modules_dir}\n";
            return false;
        }

        // Get all modules
        $modules = $this->getModuleList();
        echo "Found " . count($modules) . " modules to assess\n\n";

        $total_findings = 0;
        $critical_findings = 0;
        $high_findings = 0;

        foreach ($modules as $module) {
            echo "Assessing module: {$module['name']}\n";
            echo str_repeat('-', 40) . "\n";

            $module_findings = $this->assessModule($module);
            $this->results[$module['name']] = $module_findings;

            $module_critical = count(array_filter($module_findings, function($f) { 
                return $f['severity'] == SecurityAudit::SEVERITY_CRITICAL; 
            }));
            $module_high = count(array_filter($module_findings, function($f) { 
                return $f['severity'] == SecurityAudit::SEVERITY_HIGH; 
            }));

            echo "  Findings: " . count($module_findings) . " (Critical: $module_critical, High: $module_high)\n";

            $total_findings += count($module_findings);
            $critical_findings += $module_critical;
            $high_findings += $module_high;

            // Display critical findings immediately
            foreach ($module_findings as $finding) {
                if ($finding['severity'] == SecurityAudit::SEVERITY_CRITICAL) {
                    echo "  [CRITICAL] {$finding['title']}\n";
                }
            }

            echo "\n";
        }

        echo "Assessment Complete!\n";
        echo "===================\n";
        echo "Total Findings: $total_findings\n";
        echo "Critical: $critical_findings\n";
        echo "High: $high_findings\n\n";

        // Generate detailed report
        $this->generateReport();

        return $this->results;
    }

    /**
     * Get list of all modules
     */
    private function getModuleList()
    {
        $modules = array();
        $module_dirs = array_filter(glob($this->modules_dir . '*'), 'is_dir');

        foreach ($module_dirs as $module_dir) {
            $module_name = basename($module_dir);
            
            // Skip system directories
            if (in_array($module_name, array('.', '..', 'index.php'))) {
                continue;
            }

            $modules[] = array(
                'name' => $module_name,
                'path' => $module_dir,
                'main_file' => $module_dir . '/' . $module_name . '.php'
            );
        }

        return $modules;
    }

    /**
     * Assess individual module security
     */
    private function assessModule($module)
    {
        $findings = array();

        // Check module structure and files
        $findings = array_merge($findings, $this->checkModuleStructure($module));

        // Check authentication and authorization
        $findings = array_merge($findings, $this->checkModuleAuthentication($module));

        // Check input validation
        $findings = array_merge($findings, $this->checkModuleInputValidation($module));

        // Check file security
        $findings = array_merge($findings, $this->checkModuleFileSecurity($module));

        // Check configuration security
        $findings = array_merge($findings, $this->checkModuleConfiguration($module));

        // Check for common vulnerabilities
        $findings = array_merge($findings, $this->checkCommonVulnerabilities($module));

        return $findings;
    }

    /**
     * Check module structure and required files
     */
    private function checkModuleStructure($module)
    {
        $findings = array();

        // Check if main module file exists
        if (!file_exists($module['main_file'])) {
            $findings[] = array(
                'title' => 'Missing Main Module File',
                'description' => "Main module file {$module['main_file']} not found",
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => 'configuration',
                'file' => $module['main_file']
            );
        }

        // Check for index.php security files
        $directories = array($module['path']);
        $subdirs = array('classes', 'controllers', 'views', 'translations');
        
        foreach ($subdirs as $subdir) {
            $full_path = $module['path'] . '/' . $subdir;
            if (is_dir($full_path)) {
                $directories[] = $full_path;
            }
        }

        foreach ($directories as $dir) {
            $index_file = $dir . '/index.php';
            if (!file_exists($index_file)) {
                $findings[] = array(
                    'title' => 'Missing Security Index File',
                    'description' => "Directory $dir is missing index.php security file",
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'configuration',
                    'file' => $index_file
                );
            }
        }

        return $findings;
    }

    /**
     * Check module authentication and authorization
     */
    private function checkModuleAuthentication($module)
    {
        $findings = array();

        // Check admin controllers
        $admin_controllers_dir = $module['path'] . '/controllers/admin/';
        if (is_dir($admin_controllers_dir)) {
            $admin_files = glob($admin_controllers_dir . '*.php');
            
            foreach ($admin_files as $file) {
                if (basename($file) === 'index.php') continue;
                
                $content = file_get_contents($file);
                
                // Check for proper authentication
                if (!preg_match('/extends\s+AdminController|ModuleAdminController/', $content)) {
                    $findings[] = array(
                        'title' => 'Improper Admin Controller Base Class',
                        'description' => "Admin controller should extend AdminController or ModuleAdminController",
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'authentication',
                        'file' => $file
                    );
                }

                // Check for token validation
                if (preg_match('/Tools::isSubmit/', $content) && !preg_match('/Tools::getAdminTokenLite|checkToken/', $content)) {
                    $findings[] = array(
                        'title' => 'Missing CSRF Token Validation',
                        'description' => "Admin controller processes forms without CSRF token validation",
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'authentication',
                        'file' => $file
                    );
                }
            }
        }

        // Check frontend controllers
        $front_controllers_dir = $module['path'] . '/controllers/front/';
        if (is_dir($front_controllers_dir)) {
            $front_files = glob($front_controllers_dir . '*.php');
            
            foreach ($front_files as $file) {
                if (basename($file) === 'index.php') continue;
                
                $content = file_get_contents($file);
                
                // Check for proper base class
                if (!preg_match('/extends\s+ModuleFrontController|FrontController/', $content)) {
                    $findings[] = array(
                        'title' => 'Improper Frontend Controller Base Class',
                        'description' => "Frontend controller should extend ModuleFrontController",
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'authentication',
                        'file' => $file
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Check module input validation
     */
    private function checkModuleInputValidation($module)
    {
        $findings = array();
        
        // Get all PHP files in the module
        $php_files = $this->getModulePhpFiles($module['path']);
        
        foreach ($php_files as $file) {
            $content = file_get_contents($file);
            
            // Check for SQL injection vulnerabilities
            $sql_patterns = array(
                '/\$sql\s*[.=].*\$_(?:GET|POST|REQUEST)\[/' => 'Direct user input in SQL query',
                '/Db::getInstance\(\)->execute\([^)]*\$_(?:GET|POST|REQUEST)/' => 'Unvalidated input in database query',
                '/mysql_query\([^)]*\$_(?:GET|POST|REQUEST)/' => 'Direct SQL injection vulnerability',
                '/query\([^)]*\$_(?:GET|POST|REQUEST)/' => 'Potential SQL injection in query'
            );
            
            foreach ($sql_patterns as $pattern => $description) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    $line_number = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                    
                    $findings[] = array(
                        'title' => 'SQL Injection Vulnerability',
                        'description' => "$description at line $line_number",
                        'severity' => SecurityAudit::SEVERITY_CRITICAL,
                        'category' => 'input_validation',
                        'file' => $file,
                        'line' => $line_number,
                        'code' => trim($matches[0][0])
                    );
                }
            }
            
            // Check for XSS vulnerabilities
            $xss_patterns = array(
                '/echo\s+\$_(?:GET|POST|REQUEST)\[/' => 'Direct output of user input',
                '/print\s+\$_(?:GET|POST|REQUEST)\[/' => 'Direct output of user input',
                '/printf?\([^)]*\$_(?:GET|POST|REQUEST)/' => 'Unescaped user input in output'
            );
            
            foreach ($xss_patterns as $pattern => $description) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    $line_number = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                    
                    $findings[] = array(
                        'title' => 'XSS Vulnerability',
                        'description' => "$description at line $line_number",
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'input_validation',
                        'file' => $file,
                        'line' => $line_number,
                        'code' => trim($matches[0][0])
                    );
                }
            }
            
            // Check for file upload vulnerabilities
            if (preg_match('/\$_FILES/', $content)) {
                if (!preg_match('/pathinfo|getimagesize|mime_content_type|finfo_file/', $content)) {
                    $findings[] = array(
                        'title' => 'Insecure File Upload',
                        'description' => 'File upload without proper validation',
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'input_validation',
                        'file' => $file
                    );
                }
            }
            
            // Check for command injection
            if (preg_match('/(?:exec|system|shell_exec|passthru|popen)\([^)]*\$_(?:GET|POST|REQUEST)/', $content)) {
                $findings[] = array(
                    'title' => 'Command Injection Vulnerability',
                    'description' => 'User input passed to system command execution',
                    'severity' => SecurityAudit::SEVERITY_CRITICAL,
                    'category' => 'input_validation',
                    'file' => $file
                );
            }
        }
        
        return $findings;
    }

    /**
     * Check module file security
     */
    private function checkModuleFileSecurity($module)
    {
        $findings = array();
        
        // Check file permissions
        $sensitive_files = array(
            $module['main_file'],
            $module['path'] . '/config.xml'
        );
        
        foreach ($sensitive_files as $file) {
            if (file_exists($file)) {
                $perms = fileperms($file);
                $octal_perms = substr(sprintf('%o', $perms), -3);
                
                if ($octal_perms > '644') {
                    $findings[] = array(
                        'title' => 'Insecure File Permissions',
                        'description' => "File has overly permissive permissions: $octal_perms",
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'configuration',
                        'file' => $file
                    );
                }
            }
        }
        
        // Check for sensitive files in web-accessible locations
        $sensitive_patterns = array(
            '*.log' => 'Log files should not be web-accessible',
            '*.sql' => 'SQL files should not be web-accessible',
            '*.bak' => 'Backup files should not be web-accessible',
            '.env' => 'Environment files should not be web-accessible'
        );
        
        foreach ($sensitive_patterns as $pattern => $description) {
            $files = glob($module['path'] . '/' . $pattern);
            foreach ($files as $file) {
                $findings[] = array(
                    'title' => 'Sensitive File in Web Directory',
                    'description' => $description,
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'configuration',
                    'file' => $file
                );
            }
        }
        
        return $findings;
    }

    /**
     * Check module configuration security
     */
    private function checkModuleConfiguration($module)
    {
        $findings = array();
        
        if (file_exists($module['main_file'])) {
            $content = file_get_contents($module['main_file']);
            
            // Check for hardcoded credentials
            $cred_patterns = array(
                '/(?:password|pwd)\s*=\s*[\'"][^\'"]{3,}[\'"]/' => 'Hardcoded password',
                '/(?:api[_-]?key|apikey)\s*=\s*[\'"][^\'"]{10,}[\'"]/' => 'Hardcoded API key',
                '/(?:secret|token)\s*=\s*[\'"][^\'"]{10,}[\'"]/' => 'Hardcoded secret/token'
            );
            
            foreach ($cred_patterns as $pattern => $description) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    $line_number = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                    
                    $findings[] = array(
                        'title' => 'Hardcoded Credentials',
                        'description' => "$description at line $line_number",
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'configuration',
                        'file' => $module['main_file'],
                        'line' => $line_number
                    );
                }
            }
            
            // Check for debug code
            if (preg_match('/(?:var_dump|print_r|error_reporting\(E_ALL\)|ini_set\([\'"]display_errors)/', $content)) {
                $findings[] = array(
                    'title' => 'Debug Code in Production',
                    'description' => 'Debug code found that may leak sensitive information',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'configuration',
                    'file' => $module['main_file']
                );
            }
        }
        
        return $findings;
    }

    /**
     * Check for common vulnerabilities
     */
    private function checkCommonVulnerabilities($module)
    {
        $findings = array();
        
        $php_files = $this->getModulePhpFiles($module['path']);
        
        foreach ($php_files as $file) {
            $content = file_get_contents($file);
            
            // Check for eval() usage
            if (preg_match('/eval\s*\(/', $content)) {
                $findings[] = array(
                    'title' => 'Dangerous eval() Usage',
                    'description' => 'Use of eval() can lead to code injection',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'input_validation',
                    'file' => $file
                );
            }
            
            // Check for unserialize() with user input
            if (preg_match('/unserialize\([^)]*\$_(?:GET|POST|REQUEST)/', $content)) {
                $findings[] = array(
                    'title' => 'Unsafe Deserialization',
                    'description' => 'Unserialize with user input can lead to object injection',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'input_validation',
                    'file' => $file
                );
            }
            
            // Check for include/require with user input
            if (preg_match('/(?:include|require)(?:_once)?\s*\([^)]*\$_(?:GET|POST|REQUEST)/', $content)) {
                $findings[] = array(
                    'title' => 'File Inclusion Vulnerability',
                    'description' => 'Include/require with user input can lead to LFI/RFI',
                    'severity' => SecurityAudit::SEVERITY_CRITICAL,
                    'category' => 'input_validation',
                    'file' => $file
                );
            }
            
            // Check for weak random number generation
            if (preg_match('/(?:rand|mt_rand)\(\)/', $content) && preg_match('/(?:password|token|session|csrf)/', $content)) {
                $findings[] = array(
                    'title' => 'Weak Random Number Generation',
                    'description' => 'Using weak random functions for security-sensitive operations',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'authentication',
                    'file' => $file
                );
            }
        }
        
        return $findings;
    }

    /**
     * Get all PHP files in module directory
     */
    private function getModulePhpFiles($module_path)
    {
        $files = array();
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($module_path)
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        
        return $files;
    }

    /**
     * Generate detailed security report
     */
    private function generateReport()
    {
        $report_file = _PS_ROOT_DIR_ . '/MODULE_SECURITY_ASSESSMENT.md';
        $report_content = "# Module Security Assessment Report\n\n";
        $report_content .= "Generated on: " . date('Y-m-d H:i:s') . "\n\n";

        $total_modules = count($this->results);
        $total_findings = 0;
        $severity_counts = array(
            SecurityAudit::SEVERITY_CRITICAL => 0,
            SecurityAudit::SEVERITY_HIGH => 0,
            SecurityAudit::SEVERITY_MEDIUM => 0,
            SecurityAudit::SEVERITY_LOW => 0
        );

        // Calculate totals
        foreach ($this->results as $module_name => $findings) {
            $total_findings += count($findings);
            foreach ($findings as $finding) {
                if (isset($severity_counts[$finding['severity']])) {
                    $severity_counts[$finding['severity']]++;
                }
            }
        }

        $report_content .= "## Executive Summary\n\n";
        $report_content .= "- **Modules Assessed:** $total_modules\n";
        $report_content .= "- **Total Findings:** $total_findings\n";
        $report_content .= "- **Critical:** {$severity_counts[SecurityAudit::SEVERITY_CRITICAL]}\n";
        $report_content .= "- **High:** {$severity_counts[SecurityAudit::SEVERITY_HIGH]}\n";
        $report_content .= "- **Medium:** {$severity_counts[SecurityAudit::SEVERITY_MEDIUM]}\n";
        $report_content .= "- **Low:** {$severity_counts[SecurityAudit::SEVERITY_LOW]}\n\n";

        // Critical findings summary
        if ($severity_counts[SecurityAudit::SEVERITY_CRITICAL] > 0) {
            $report_content .= "## Critical Findings Requiring Immediate Attention\n\n";
            foreach ($this->results as $module_name => $findings) {
                foreach ($findings as $finding) {
                    if ($finding['severity'] == SecurityAudit::SEVERITY_CRITICAL) {
                        $report_content .= "### {$finding['title']} - Module: $module_name\n";
                        $report_content .= "**File:** `{$finding['file']}`\n";
                        if (isset($finding['line'])) {
                            $report_content .= "**Line:** {$finding['line']}\n";
                        }
                        $report_content .= "**Description:** {$finding['description']}\n\n";
                    }
                }
            }
        }

        // Detailed findings by module
        $report_content .= "## Detailed Findings by Module\n\n";
        foreach ($this->results as $module_name => $findings) {
            if (empty($findings)) continue;
            
            $report_content .= "### Module: $module_name\n\n";
            $report_content .= "**Findings:** " . count($findings) . "\n\n";
            
            foreach ($findings as $finding) {
                $severity_label = $this->getSeverityLabel($finding['severity']);
                $report_content .= "#### [$severity_label] {$finding['title']}\n";
                $report_content .= "- **File:** `{$finding['file']}`\n";
                if (isset($finding['line'])) {
                    $report_content .= "- **Line:** {$finding['line']}\n";
                }
                $report_content .= "- **Category:** {$finding['category']}\n";
                $report_content .= "- **Description:** {$finding['description']}\n";
                if (isset($finding['code'])) {
                    $report_content .= "- **Code:** `{$finding['code']}`\n";
                }
                $report_content .= "\n";
            }
        }

        // Recommendations
        $report_content .= "## Security Recommendations\n\n";
        $report_content .= "### Immediate Actions (Critical/High Severity)\n";
        $report_content .= "1. **Fix SQL Injection vulnerabilities** - Use prepared statements and parameter binding\n";
        $report_content .= "2. **Implement input validation** - Validate and sanitize all user inputs\n";
        $report_content .= "3. **Remove hardcoded credentials** - Move to configuration files or environment variables\n";
        $report_content .= "4. **Fix file inclusion vulnerabilities** - Validate file paths and use whitelisting\n\n";
        
        $report_content .= "### General Security Improvements\n";
        $report_content .= "1. **Add CSRF protection** - Implement token validation for all forms\n";
        $report_content .= "2. **Improve file permissions** - Set appropriate permissions (644 for files, 755 for directories)\n";
        $report_content .= "3. **Add security index files** - Prevent directory browsing with index.php files\n";
        $report_content .= "4. **Remove debug code** - Clean up development/debug code from production modules\n";
        $report_content .= "5. **Update dependencies** - Keep third-party libraries updated to latest secure versions\n\n";

        file_put_contents($report_file, $report_content);
        echo "Detailed report saved to: $report_file\n";
    }

    /**
     * Get severity label
     */
    private function getSeverityLabel($severity)
    {
        $labels = array(
            SecurityAudit::SEVERITY_CRITICAL => 'CRITICAL',
            SecurityAudit::SEVERITY_HIGH => 'HIGH',
            SecurityAudit::SEVERITY_MEDIUM => 'MEDIUM',
            SecurityAudit::SEVERITY_LOW => 'LOW'
        );
        
        return isset($labels[$severity]) ? $labels[$severity] : 'UNKNOWN';
    }
}

// Run the assessment if called directly
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    $assessment = new ModuleSecurityAssessment();
    $results = $assessment->runAssessment();
    
    echo "\nModule security assessment completed successfully!\n";
    echo "Check MODULE_SECURITY_ASSESSMENT.md for detailed findings.\n";
}