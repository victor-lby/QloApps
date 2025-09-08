<?php
/**
 * Automated Security Scanner
 * 
 * Orchestrates automated security scanning tools and vulnerability detection
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class SecurityScanner
{
    private $audit_id;
    private $scan_config;
    private $results;

    public function __construct($audit_id = null)
    {
        $this->audit_id = $audit_id;
        $this->results = array();
        $this->loadScanConfiguration();
    }

    /**
     * Load scanning configuration
     */
    private function loadScanConfiguration()
    {
        $this->scan_config = array(
            'directories_to_scan' => array(
                _PS_ROOT_DIR_ . '/classes/',
                _PS_ROOT_DIR_ . '/controllers/',
                _PS_ROOT_DIR_ . '/modules/',
                _PS_ROOT_DIR_ . '/admin/',
                _PS_ROOT_DIR_ . '/webservice/',
                _PS_ROOT_DIR_ . '/config/'
            ),
            'file_extensions' => array('php'),
            'exclude_patterns' => array(
                '/cache/',
                '/log/',
                '/upload/',
                '/vendor/',
                '/node_modules/',
                '/.git/'
            ),
            'scan_types' => array(
                'sql_injection' => true,
                'xss' => true,
                'file_upload' => true,
                'weak_auth' => true,
                'hardcoded_credentials' => true,
                'file_permissions' => true,
                'configuration_security' => true
            )
        );
    }

    /**
     * Run comprehensive security scan
     */
    public function runComprehensiveScan()
    {
        if (!$this->audit_id) {
            throw new Exception('Audit ID is required for scanning');
        }

        $this->results = array();
        $total_files_scanned = 0;
        $total_vulnerabilities = 0;

        foreach ($this->scan_config['directories_to_scan'] as $directory) {
            if (!is_dir($directory)) {
                continue;
            }

            $files = SecurityAuditUtils::scanDirectory($directory, $this->scan_config['file_extensions']);
            
            foreach ($files as $file) {
                // Skip excluded patterns
                if ($this->shouldExcludeFile($file)) {
                    continue;
                }

                $file_vulnerabilities = $this->scanFile($file);
                $total_files_scanned++;
                
                foreach ($file_vulnerabilities as $vuln) {
                    $this->createSecurityFinding($file, $vuln);
                    $total_vulnerabilities++;
                }
            }
        }

        // Run configuration security checks
        $this->scanConfiguration();

        // Update audit statistics
        $audit = new SecurityAudit($this->audit_id);
        $audit->updateStatistics();
        $audit->status = 'completed';
        $audit->save();

        return array(
            'files_scanned' => $total_files_scanned,
            'vulnerabilities_found' => $total_vulnerabilities,
            'scan_results' => $this->results
        );
    }

    /**
     * Scan individual file for vulnerabilities
     */
    private function scanFile($file_path)
    {
        $vulnerabilities = array();

        // SQL Injection scan
        if ($this->scan_config['scan_types']['sql_injection']) {
            $sql_vulns = SecurityAuditUtils::scanForSQLInjection($file_path);
            foreach ($sql_vulns as $vuln) {
                $vuln['category'] = SecurityAudit::CATEGORY_INPUT_VALIDATION;
                $vuln['type'] = 'sql_injection';
                $vulnerabilities[] = $vuln;
            }
        }

        // XSS scan
        if ($this->scan_config['scan_types']['xss']) {
            $xss_vulns = SecurityAuditUtils::scanForXSS($file_path);
            foreach ($xss_vulns as $vuln) {
                $vuln['category'] = SecurityAudit::CATEGORY_INPUT_VALIDATION;
                $vuln['type'] = 'xss';
                $vulnerabilities[] = $vuln;
            }
        }

        // File upload vulnerabilities
        if ($this->scan_config['scan_types']['file_upload']) {
            $upload_vulns = SecurityAuditUtils::scanForFileUploadVulns($file_path);
            foreach ($upload_vulns as $vuln) {
                $vuln['category'] = SecurityAudit::CATEGORY_INPUT_VALIDATION;
                $vuln['type'] = 'file_upload';
                $vulnerabilities[] = $vuln;
            }
        }

        // Weak authentication
        if ($this->scan_config['scan_types']['weak_auth']) {
            $auth_vulns = SecurityAuditUtils::scanForWeakAuth($file_path);
            foreach ($auth_vulns as $vuln) {
                $vuln['category'] = SecurityAudit::CATEGORY_AUTHENTICATION;
                $vuln['type'] = 'weak_authentication';
                $vulnerabilities[] = $vuln;
            }
        }

        // Hardcoded credentials
        if ($this->scan_config['scan_types']['hardcoded_credentials']) {
            $cred_vulns = SecurityAuditUtils::scanForHardcodedCredentials($file_path);
            foreach ($cred_vulns as $vuln) {
                $vuln['category'] = SecurityAudit::CATEGORY_CONFIGURATION;
                $vuln['type'] = 'hardcoded_credentials';
                $vulnerabilities[] = $vuln;
            }
        }

        // File permissions
        if ($this->scan_config['scan_types']['file_permissions']) {
            $perm_issues = SecurityAuditUtils::checkFilePermissions($file_path);
            foreach ($perm_issues as $issue) {
                $issue['category'] = SecurityAudit::CATEGORY_CONFIGURATION;
                $issue['line'] = 0;
                $issue['code'] = '';
                $vulnerabilities[] = $issue;
            }
        }

        return $vulnerabilities;
    }

    /**
     * Scan configuration files and settings
     */
    private function scanConfiguration()
    {
        $config_issues = array();

        // Check database configuration
        $config_issues = array_merge($config_issues, $this->checkDatabaseConfig());
        
        // Check file permissions on critical directories
        $config_issues = array_merge($config_issues, $this->checkCriticalDirectories());
        
        // Check for debug mode in production
        $config_issues = array_merge($config_issues, $this->checkDebugMode());

        foreach ($config_issues as $issue) {
            $this->createSecurityFinding('Configuration', $issue);
        }
    }

    /**
     * Check database configuration security
     */
    private function checkDatabaseConfig()
    {
        $issues = array();

        // Check if database credentials are in version control
        if (file_exists(_PS_ROOT_DIR_ . '/config/settings.inc.php')) {
            $config_content = file_get_contents(_PS_ROOT_DIR_ . '/config/settings.inc.php');
            
            if (strpos($config_content, 'localhost') !== false && 
                strpos($config_content, 'root') !== false) {
                $issues[] = array(
                    'type' => 'weak_db_config',
                    'description' => 'Database using default localhost/root configuration',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => SecurityAudit::CATEGORY_CONFIGURATION,
                    'line' => 0,
                    'code' => ''
                );
            }
        }

        return $issues;
    }

    /**
     * Check critical directory permissions
     */
    private function checkCriticalDirectories()
    {
        $issues = array();
        $critical_dirs = array(
            _PS_ROOT_DIR_ . '/config/',
            _PS_ROOT_DIR_ . '/admin/',
            _PS_ROOT_DIR_ . '/classes/'
        );

        foreach ($critical_dirs as $dir) {
            if (is_dir($dir)) {
                $perms = fileperms($dir);
                $octal_perms = substr(sprintf('%o', $perms), -4);
                
                if ($octal_perms > '0755') {
                    $issues[] = array(
                        'type' => 'directory_permissions',
                        'description' => "Critical directory $dir has overly permissive permissions: $octal_perms",
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => SecurityAudit::CATEGORY_CONFIGURATION,
                        'line' => 0,
                        'code' => ''
                    );
                }
            }
        }

        return $issues;
    }

    /**
     * Check for debug mode in production
     */
    private function checkDebugMode()
    {
        $issues = array();

        if (defined('_PS_MODE_DEV_') && _PS_MODE_DEV_) {
            $issues[] = array(
                'type' => 'debug_mode_enabled',
                'description' => 'Debug mode is enabled in production environment',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => SecurityAudit::CATEGORY_CONFIGURATION,
                'line' => 0,
                'code' => ''
            );
        }

        return $issues;
    }

    /**
     * Create security finding from vulnerability data
     */
    private function createSecurityFinding($file_path, $vulnerability)
    {
        $title = $this->generateFindingTitle($vulnerability);
        $description = $this->generateFindingDescription($file_path, $vulnerability);
        $fix_specification = $this->generateFixSpecification($vulnerability);

        $finding_data = array(
            'title' => $title,
            'description' => $description,
            'severity' => $vulnerability['severity'],
            'category' => $vulnerability['category'],
            'affected_files' => array($file_path),
            'business_impact' => $this->assessBusinessImpact($vulnerability),
            'remediation_effort' => $this->assessRemediationEffort($vulnerability),
            'fix_specification' => $fix_specification,
            'code_examples' => $this->generateCodeExamples($vulnerability),
            'references' => $this->getSecurityReferences($vulnerability['type'])
        );

        SecurityFinding::createFinding($this->audit_id, $finding_data);
    }

    /**
     * Generate finding title
     */
    private function generateFindingTitle($vulnerability)
    {
        $titles = array(
            'sql_injection' => 'SQL Injection Vulnerability',
            'xss' => 'Cross-Site Scripting (XSS) Vulnerability',
            'file_upload' => 'Insecure File Upload',
            'weak_authentication' => 'Weak Authentication Implementation',
            'hardcoded_credentials' => 'Hardcoded Credentials',
            'file_permissions' => 'Insecure File Permissions',
            'directory_permissions' => 'Insecure Directory Permissions',
            'debug_mode_enabled' => 'Debug Mode Enabled in Production'
        );

        return isset($titles[$vulnerability['type']]) ? 
               $titles[$vulnerability['type']] : 
               'Security Vulnerability';
    }

    /**
     * Generate finding description
     */
    private function generateFindingDescription($file_path, $vulnerability)
    {
        $description = "<p><strong>File:</strong> " . htmlspecialchars($file_path) . "</p>";
        
        if (isset($vulnerability['line']) && $vulnerability['line'] > 0) {
            $description .= "<p><strong>Line:</strong> " . $vulnerability['line'] . "</p>";
        }
        
        if (isset($vulnerability['code']) && !empty($vulnerability['code'])) {
            $description .= "<p><strong>Code:</strong></p><pre>" . htmlspecialchars($vulnerability['code']) . "</pre>";
        }
        
        $description .= "<p><strong>Issue:</strong> " . htmlspecialchars($vulnerability['description']) . "</p>";

        return $description;
    }

    /**
     * Generate fix specification
     */
    private function generateFixSpecification($vulnerability)
    {
        $fixes = array(
            'sql_injection' => 'Use prepared statements with parameter binding. Replace direct string concatenation with PDO prepared statements or Db::getInstance()->execute() with proper parameter binding.',
            'xss' => 'Implement proper output encoding. Use Tools::safeOutput() or htmlspecialchars() before displaying user input.',
            'file_upload' => 'Implement file type validation, size limits, and secure file storage. Validate file extensions and MIME types.',
            'weak_authentication' => 'Use strong password hashing algorithms like password_hash() with PASSWORD_DEFAULT or bcrypt.',
            'hardcoded_credentials' => 'Move credentials to configuration files or environment variables. Never commit sensitive data to version control.',
            'file_permissions' => 'Set appropriate file permissions: 644 for files, 755 for directories.',
            'debug_mode_enabled' => 'Disable debug mode in production by setting _PS_MODE_DEV_ to false.'
        );

        return isset($fixes[$vulnerability['type']]) ? 
               $fixes[$vulnerability['type']] : 
               'Review and fix the identified security issue.';
    }

    /**
     * Generate code examples for fixes
     */
    private function generateCodeExamples($vulnerability)
    {
        $examples = array(
            'sql_injection' => '<pre>// Bad
$sql = "SELECT * FROM users WHERE id = " . $_GET[\'id\'];

// Good
$sql = "SELECT * FROM users WHERE id = ?";
Db::getInstance()->executeS($sql, array((int)$_GET[\'id\']));</pre>',
            
            'xss' => '<pre>// Bad
echo $_GET[\'message\'];

// Good
echo Tools::safeOutput($_GET[\'message\']);</pre>'
        );

        return isset($examples[$vulnerability['type']]) ? 
               $examples[$vulnerability['type']] : '';
    }

    /**
     * Get security references
     */
    private function getSecurityReferences($type)
    {
        $references = array(
            'sql_injection' => array(
                'OWASP SQL Injection Prevention Cheat Sheet',
                'CWE-89: Improper Neutralization of Special Elements used in an SQL Command'
            ),
            'xss' => array(
                'OWASP XSS Prevention Cheat Sheet',
                'CWE-79: Improper Neutralization of Input During Web Page Generation'
            )
        );

        return isset($references[$type]) ? $references[$type] : array();
    }

    /**
     * Assess business impact
     */
    private function assessBusinessImpact($vulnerability)
    {
        $high_impact = array('sql_injection', 'hardcoded_credentials', 'debug_mode_enabled');
        $medium_impact = array('xss', 'file_upload', 'weak_authentication');
        
        if (in_array($vulnerability['type'], $high_impact)) {
            return 'high';
        } elseif (in_array($vulnerability['type'], $medium_impact)) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    /**
     * Assess remediation effort
     */
    private function assessRemediationEffort($vulnerability)
    {
        $high_effort = array('weak_authentication', 'file_upload');
        $low_effort = array('xss', 'file_permissions', 'debug_mode_enabled');
        
        if (in_array($vulnerability['type'], $high_effort)) {
            return 'high';
        } elseif (in_array($vulnerability['type'], $low_effort)) {
            return 'low';
        } else {
            return 'medium';
        }
    }

    /**
     * Check if file should be excluded from scanning
     */
    private function shouldExcludeFile($file_path)
    {
        foreach ($this->scan_config['exclude_patterns'] as $pattern) {
            if (strpos($file_path, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }
}