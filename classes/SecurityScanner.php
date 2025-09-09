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

        // Run authentication and authorization assessment (Task 2.1 & 2.2)
        $auth_findings = $this->analyzeAuthenticationMechanisms();
        foreach ($auth_findings as $finding) {
            $this->createSecurityFindingFromObject($finding);
            $total_vulnerabilities++;
        }

        $authz_findings = $this->assessAuthorizationControls();
        foreach ($authz_findings as $finding) {
            $this->createSecurityFindingFromObject($finding);
            $total_vulnerabilities++;
        }

        // Run input validation and injection vulnerability assessment (Task 3)
        $input_validation_findings = $this->performInputValidationAssessment();
        foreach ($input_validation_findings as $finding) {
            $this->createSecurityFindingFromObject($finding);
            $total_vulnerabilities++;
        }

        // Run data protection and encryption security assessment (Task 4)
        $data_protection_findings = $this->assessDataProtectionSecurity();
        foreach ($data_protection_findings as $finding) {
            $this->createSecurityFindingFromObject($finding);
            $total_vulnerabilities++;
        }

        // Run configuration and infrastructure security review (Task 5)
        $config_findings = $this->conductConfigurationSecurityReview();
        foreach ($config_findings as $finding) {
            $this->createSecurityFindingFromObject($finding);
            $total_vulnerabilities++;
        }

        // Run API security assessment (Task 6)
        $api_findings = $this->performApiSecurityAssessment();
        foreach ($api_findings as $finding) {
            $this->createSecurityFindingFromObject($finding);
            $total_vulnerabilities++;
        }

        // Run third-party and module security assessment (Task 7)
        $module_findings = $this->assessThirdPartyAndModuleSecurity();
        foreach ($module_findings as $finding) {
            $this->createSecurityFindingFromObject($finding);
            $total_vulnerabilities++;
        }

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
     * Run input validation and injection vulnerability assessment (Task 3)
     */
    public function performInputValidationAssessment()
    {
        $findings = array();
        
        // SQL Injection Assessment (Task 3.1)
        $findings = array_merge($findings, $this->scanSQLInjectionVulnerabilities());
        
        // File Upload Security Assessment (Task 3.2)
        $findings = array_merge($findings, $this->assessFileUploadSecurity());
        
        // XSS and Output Encoding Assessment (Task 3.3)
        $findings = array_merge($findings, $this->evaluateXSSVulnerabilities());
        
        return $findings;
    }

    /**
     * Scan for SQL injection vulnerabilities (Task 3.1)
     */
    private function scanSQLInjectionVulnerabilities()
    {
        $findings = array();
        
        // Scan ObjectModel implementations in /classes/
        $class_files = SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/classes/', array('php'));
        foreach ($class_files as $file) {
            if (strpos($file, 'ObjectModel') !== false || strpos($file, '.php') !== false) {
                $sql_vulns = SecurityAuditUtils::scanForSQLInjection($file);
                foreach ($sql_vulns as $vuln) {
                    $findings[] = new SecurityFinding(array(
                        'title' => 'SQL Injection Vulnerability in ' . basename($file),
                        'description' => $this->generateSQLInjectionDescription($file, $vuln),
                        'severity' => $vuln['severity'],
                        'category' => 'input_validation',
                        'affected_files' => array($file),
                        'business_impact' => 'Database compromise, data theft, unauthorized access',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Use prepared statements with parameter binding or proper input sanitization'
                    ));
                }
            }
        }
        
        // Scan custom SQL queries in modules
        $module_files = SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/modules/', array('php'));
        foreach ($module_files as $file) {
            $sql_vulns = SecurityAuditUtils::scanForSQLInjection($file);
            foreach ($sql_vulns as $vuln) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'SQL Injection in Module: ' . basename(dirname($file)),
                    'description' => $this->generateSQLInjectionDescription($file, $vuln),
                    'severity' => $vuln['severity'],
                    'category' => 'input_validation',
                    'affected_files' => array($file),
                    'business_impact' => 'Module-specific data compromise',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Implement proper SQL parameter binding in module queries'
                ));
            }
        }
        
        // Scan controllers
        $controller_files = SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/controllers/', array('php'));
        foreach ($controller_files as $file) {
            $sql_vulns = SecurityAuditUtils::scanForSQLInjection($file);
            foreach ($sql_vulns as $vuln) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'SQL Injection in Controller: ' . basename($file),
                    'description' => $this->generateSQLInjectionDescription($file, $vuln),
                    'severity' => $vuln['severity'],
                    'category' => 'input_validation',
                    'affected_files' => array($file),
                    'business_impact' => 'Controller-level data access compromise',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Replace direct SQL concatenation with prepared statements'
                ));
            }
        }
        
        return $findings;
    }

    /**
     * Assess file upload security (Task 3.2)
     */
    private function assessFileUploadSecurity()
    {
        $findings = array();
        
        // Review FileUploader.php
        $file_uploader_path = _PS_ROOT_DIR_ . '/classes/FileUploader.php';
        if (file_exists($file_uploader_path)) {
            $upload_vulns = SecurityAuditUtils::scanForFileUploadVulns($file_uploader_path);
            foreach ($upload_vulns as $vuln) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'File Upload Vulnerability in FileUploader',
                    'description' => $this->generateFileUploadDescription($file_uploader_path, $vuln),
                    'severity' => $vuln['severity'],
                    'category' => 'input_validation',
                    'affected_files' => array($file_uploader_path),
                    'business_impact' => 'Arbitrary file upload, potential code execution',
                    'remediation_effort' => 'high',
                    'fix_specification' => 'Implement comprehensive file type validation and secure storage'
                ));
            }
        }
        
        // Review Uploader.php
        $uploader_path = _PS_ROOT_DIR_ . '/classes/Uploader.php';
        if (file_exists($uploader_path)) {
            $upload_vulns = SecurityAuditUtils::scanForFileUploadVulns($uploader_path);
            foreach ($upload_vulns as $vuln) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'File Upload Vulnerability in Uploader',
                    'description' => $this->generateFileUploadDescription($uploader_path, $vuln),
                    'severity' => $vuln['severity'],
                    'category' => 'input_validation',
                    'affected_files' => array($uploader_path),
                    'business_impact' => 'File upload bypass, potential malware upload',
                    'remediation_effort' => 'high',
                    'fix_specification' => 'Add content-based validation and restrict upload locations'
                ));
            }
        }
        
        // Examine image upload functionality in modules
        $module_files = SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/modules/', array('php'));
        foreach ($module_files as $file) {
            if (strpos(file_get_contents($file), 'upload') !== false || 
                strpos(file_get_contents($file), '_FILES') !== false) {
                $upload_vulns = SecurityAuditUtils::scanForFileUploadVulns($file);
                foreach ($upload_vulns as $vuln) {
                    $findings[] = new SecurityFinding(array(
                        'title' => 'Module File Upload Vulnerability: ' . basename(dirname($file)),
                        'description' => $this->generateFileUploadDescription($file, $vuln),
                        'severity' => $vuln['severity'],
                        'category' => 'input_validation',
                        'affected_files' => array($file),
                        'business_impact' => 'Module-specific file upload compromise',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Implement module-specific file upload validation'
                    ));
                }
            }
        }
        
        return $findings;
    }

    /**
     * Evaluate XSS and output encoding vulnerabilities (Task 3.3)
     */
    private function evaluateXSSVulnerabilities()
    {
        $findings = array();
        
        // Review template rendering in Smarty templates
        $template_files = SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/themes/', array('tpl'));
        foreach ($template_files as $file) {
            $xss_vulns = SecurityAuditUtils::scanForXSS($file);
            foreach ($xss_vulns as $vuln) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'XSS Vulnerability in Template: ' . basename($file),
                    'description' => $this->generateXSSDescription($file, $vuln),
                    'severity' => $vuln['severity'],
                    'category' => 'input_validation',
                    'affected_files' => array($file),
                    'business_impact' => 'Cross-site scripting, session hijacking, defacement',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Add proper escape modifiers to template variables'
                ));
            }
        }
        
        // Check output encoding in controllers and classes
        $php_files = array_merge(
            SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/controllers/', array('php')),
            SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/classes/', array('php'))
        );
        
        foreach ($php_files as $file) {
            $xss_vulns = SecurityAuditUtils::scanForXSS($file);
            foreach ($xss_vulns as $vuln) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'XSS Vulnerability in PHP: ' . basename($file),
                    'description' => $this->generateXSSDescription($file, $vuln),
                    'severity' => $vuln['severity'],
                    'category' => 'input_validation',
                    'affected_files' => array($file),
                    'business_impact' => 'Reflected XSS, potential admin compromise',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Use Tools::safeOutput() or htmlspecialchars() for user input'
                ));
            }
        }
        
        // Assess user input display in admin and frontend
        $admin_files = SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/admin/', array('php'));
        foreach ($admin_files as $file) {
            $xss_vulns = SecurityAuditUtils::scanForXSS($file);
            foreach ($xss_vulns as $vuln) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'Admin XSS Vulnerability: ' . basename($file),
                    'description' => $this->generateXSSDescription($file, $vuln),
                    'severity' => SecurityAudit::SEVERITY_HIGH, // Admin XSS is always high severity
                    'category' => 'input_validation',
                    'affected_files' => array($file),
                    'business_impact' => 'Admin panel compromise, privilege escalation',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Implement strict output encoding in admin interface'
                ));
            }
        }
        
        return $findings;
    }

    /**
     * Generate SQL injection finding description
     */
    private function generateSQLInjectionDescription($file_path, $vulnerability)
    {
        $description = "<p><strong>File:</strong> " . htmlspecialchars($file_path) . "</p>";
        $description .= "<p><strong>Line:</strong> " . $vulnerability['line'] . "</p>";
        $description .= "<p><strong>Code:</strong></p><pre>" . htmlspecialchars($vulnerability['code']) . "</pre>";
        $description .= "<p><strong>Issue:</strong> " . htmlspecialchars($vulnerability['description']) . "</p>";
        $description .= "<p><strong>Risk:</strong> This SQL injection vulnerability could allow attackers to manipulate database queries, potentially leading to data theft, modification, or deletion.</p>";
        
        return $description;
    }

    /**
     * Generate file upload finding description
     */
    private function generateFileUploadDescription($file_path, $vulnerability)
    {
        $description = "<p><strong>File:</strong> " . htmlspecialchars($file_path) . "</p>";
        $description .= "<p><strong>Line:</strong> " . $vulnerability['line'] . "</p>";
        $description .= "<p><strong>Code:</strong></p><pre>" . htmlspecialchars($vulnerability['code']) . "</pre>";
        $description .= "<p><strong>Issue:</strong> " . htmlspecialchars($vulnerability['description']) . "</p>";
        $description .= "<p><strong>Risk:</strong> Insecure file upload mechanisms can allow attackers to upload malicious files, potentially leading to code execution or system compromise.</p>";
        
        return $description;
    }

    /**
     * Generate XSS finding description
     */
    private function generateXSSDescription($file_path, $vulnerability)
    {
        $description = "<p><strong>File:</strong> " . htmlspecialchars($file_path) . "</p>";
        $description .= "<p><strong>Line:</strong> " . $vulnerability['line'] . "</p>";
        $description .= "<p><strong>Code:</strong></p><pre>" . htmlspecialchars($vulnerability['code']) . "</pre>";
        $description .= "<p><strong>Issue:</strong> " . htmlspecialchars($vulnerability['description']) . "</p>";
        $description .= "<p><strong>Risk:</strong> Cross-site scripting vulnerabilities can allow attackers to inject malicious scripts, steal user sessions, or deface the website.</p>";
        
        return $description;
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
     * Create security finding from SecurityFinding object
     */
    private function createSecurityFindingFromObject($finding)
    {
        if ($finding instanceof SecurityFinding) {
            $finding->id_audit = $this->audit_id;
            $finding->save();
        } else {
            // Handle array-based finding data
            SecurityFinding::createFinding($this->audit_id, $finding);
        }
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
     * Assess data protection and encryption security (Task 4)
     */
    public function assessDataProtectionSecurity()
    {
        $findings = [];
        
        // Review sensitive data handling (Task 4.1)
        $findings = array_merge($findings, $this->reviewSensitiveDataHandling());
        
        // Evaluate encryption implementation (Task 4.2)
        $findings = array_merge($findings, $this->evaluateEncryptionImplementation());
        
        return $findings;
    }

    /**
     * Review sensitive data handling in customer and payment classes (Task 4.1)
     */
    private function reviewSensitiveDataHandling()
    {
        $findings = [];
        
        // Check Customer class for sensitive data protection
        $findings = array_merge($findings, $this->assessCustomerDataProtection());
        
        // Check payment data handling
        $findings = array_merge($findings, $this->assessPaymentDataHandling());
        
        // Check booking data confidentiality
        $findings = array_merge($findings, $this->assessBookingDataConfidentiality());
        
        return $findings;
    }

    /**
     * Assess customer data protection measures
     */
    private function assessCustomerDataProtection()
    {
        $findings = [];
        
        // Check Customer class file
        $customerFile = _PS_CLASS_DIR_ . 'Customer.php';
        if (!file_exists($customerFile)) {
            $findings[] = new SecurityFinding([
                'title' => 'Customer class file not found',
                'description' => 'The Customer.php class file could not be located for security assessment.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => 'data_protection',
                'affected_files' => [$customerFile],
                'business_impact' => 'Critical system file missing - customer data handling cannot be verified',
                'fix_specification' => 'Ensure Customer.php exists and contains proper data protection measures'
            ]);
            return $findings;
        }

        $customerContent = file_get_contents($customerFile);
        
        // Check for password field handling
        if (strpos($customerContent, 'public $passwd') !== false) {
            $findings[] = new SecurityFinding([
                'title' => 'Password field exposed as public property',
                'description' => 'The Customer class exposes the password field as a public property, which could lead to accidental exposure of password hashes.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'data_protection',
                'affected_files' => [$customerFile],
                'business_impact' => 'Password hashes could be accidentally logged or exposed in debug output',
                'fix_specification' => 'Consider making password field protected and provide controlled access methods'
            ]);
        }

        // Check for secure key handling
        if (strpos($customerContent, 'public $secure_key') !== false) {
            $findings[] = new SecurityFinding([
                'title' => 'Secure key exposed as public property',
                'description' => 'The Customer class exposes the secure_key field as a public property, which could compromise customer session security.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'data_protection',
                'affected_files' => [$customerFile],
                'business_impact' => 'Customer secure keys could be exposed, allowing session hijacking',
                'fix_specification' => 'Make secure_key field protected and provide controlled access methods'
            ]);
        }

        // Check for email validation in getByEmail method
        if (strpos($customerContent, 'function getByEmail') !== false) {
            if (strpos($customerContent, 'Validate::isEmail($email)') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing email validation in getByEmail method',
                    'description' => 'The getByEmail method may not properly validate email input, potentially allowing SQL injection.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'input_validation',
                    'affected_files' => [$customerFile],
                    'business_impact' => 'SQL injection vulnerability in customer lookup functionality',
                    'fix_specification' => 'Add proper email validation using Validate::isEmail() before database queries'
                ]);
            }
        }

        // Check for proper SQL escaping in customer queries
        if (preg_match('/SELECT.*FROM.*customer.*WHERE.*email.*=.*\$/', $customerContent)) {
            $findings[] = new SecurityFinding([
                'title' => 'Potential SQL injection in customer email queries',
                'description' => 'Customer email queries may not use proper SQL parameter binding or escaping.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => 'input_validation',
                'affected_files' => [$customerFile],
                'business_impact' => 'SQL injection could allow unauthorized access to customer data',
                'fix_specification' => 'Use prepared statements or proper SQL escaping (pSQL) for all user inputs'
            ]);
        }

        // Check for sensitive data in webservice parameters
        if (strpos($customerContent, 'webserviceParameters') !== false) {
            if (strpos($customerContent, "'passwd'") !== false && strpos($customerContent, "'setter' => null") === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Password exposed in webservice without proper protection',
                    'description' => 'Customer password field is exposed in webservice parameters without proper setter protection.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'data_protection',
                    'affected_files' => [$customerFile],
                    'business_impact' => 'Customer passwords could be exposed through API endpoints',
                    'fix_specification' => 'Set password field setter to null or implement proper password handling in webservice'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Assess payment data handling and PCI DSS compliance
     */
    private function assessPaymentDataHandling()
    {
        $findings = [];
        
        // Check PaymentModule class
        $paymentFile = _PS_CLASS_DIR_ . 'PaymentModule.php';
        if (file_exists($paymentFile)) {
            $paymentContent = file_get_contents($paymentFile);
            
            // Check for credit card data handling
            if (preg_match('/card|cvv|ccv|credit.*card/i', $paymentContent)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Potential credit card data handling in PaymentModule',
                    'description' => 'The PaymentModule class may handle credit card data directly, which violates PCI DSS requirements.',
                    'severity' => SecurityAudit::SEVERITY_CRITICAL,
                    'category' => 'data_protection',
                    'affected_files' => [$paymentFile],
                    'business_impact' => 'PCI DSS violation - storing or processing card data without proper certification',
                    'fix_specification' => 'Implement tokenization or use certified payment processors for card data handling'
                ]);
            }

            // Check for payment logging
            if (preg_match('/log.*payment|payment.*log/i', $paymentContent)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Payment data potentially logged',
                    'description' => 'Payment processing may log sensitive payment information.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'data_protection',
                    'affected_files' => [$paymentFile],
                    'business_impact' => 'Sensitive payment data could be exposed in log files',
                    'fix_specification' => 'Ensure payment logs do not contain sensitive data like card numbers or CVV codes'
                ]);
            }
        }

        // Check for payment modules with potential security issues
        $modulesDir = _PS_MODULE_DIR_;
        if (is_dir($modulesDir)) {
            $paymentModules = glob($modulesDir . '*/');
            foreach ($paymentModules as $moduleDir) {
                $moduleName = basename($moduleDir);
                if (in_array($moduleName, ['bankwire', 'cheque', 'paypal', 'stripe'])) {
                    $moduleFile = $moduleDir . $moduleName . '.php';
                    if (file_exists($moduleFile)) {
                        $moduleContent = file_get_contents($moduleFile);
                        
                        // Check for hardcoded credentials
                        if (preg_match('/api.*key.*=.*["\'][^"\']{20,}["\']|secret.*=.*["\'][^"\']{20,}["\']|password.*=.*["\'][^"\']+["\']/', $moduleContent)) {
                            $findings[] = new SecurityFinding([
                                'title' => "Hardcoded credentials in payment module: $moduleName",
                                'description' => 'Payment module contains hardcoded API keys, secrets, or passwords.',
                                'severity' => SecurityAudit::SEVERITY_HIGH,
                                'category' => 'data_protection',
                                'affected_files' => [$moduleFile],
                                'business_impact' => 'Hardcoded credentials could be exposed in source code',
                                'fix_specification' => 'Move credentials to configuration files or environment variables'
                            ]);
                        }
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Assess booking data confidentiality measures
     */
    private function assessBookingDataConfidentiality()
    {
        $findings = [];
        
        // Check for hotel booking classes in modules
        $hotelModuleDir = _PS_MODULE_DIR_ . 'hotelreservationsystem/';
        if (is_dir($hotelModuleDir)) {
            $classesDir = $hotelModuleDir . 'classes/';
            if (is_dir($classesDir)) {
                $bookingFiles = glob($classesDir . '*Booking*.php');
                
                foreach ($bookingFiles as $bookingFile) {
                    $bookingContent = file_get_contents($bookingFile);
                    
                    // Check for sensitive guest data exposure
                    if (preg_match('/public.*\$(passport|id_card|credit_card|phone|email)/', $bookingContent)) {
                        $findings[] = new SecurityFinding([
                            'title' => 'Sensitive guest data exposed as public properties',
                            'description' => 'Booking classes expose sensitive guest information as public properties.',
                            'severity' => SecurityAudit::SEVERITY_MEDIUM,
                            'category' => 'data_protection',
                            'affected_files' => [$bookingFile],
                            'business_impact' => 'Guest personal information could be accidentally exposed',
                            'fix_specification' => 'Make sensitive data fields protected and provide controlled access methods'
                        ]);
                    }

                    // Check for booking data validation
                    if (strpos($bookingContent, 'validateFields') === false && strpos($bookingContent, 'validate') === false) {
                        $findings[] = new SecurityFinding([
                            'title' => 'Missing data validation in booking class',
                            'description' => 'Booking class lacks proper data validation methods.',
                            'severity' => SecurityAudit::SEVERITY_MEDIUM,
                            'category' => 'input_validation',
                            'affected_files' => [$bookingFile],
                            'business_impact' => 'Invalid booking data could be stored, leading to data integrity issues',
                            'fix_specification' => 'Implement proper data validation in booking classes'
                        ]);
                    }
                }
            }
        }

        // Check for booking data in database queries
        $paymentModuleFile = _PS_CLASS_DIR_ . 'PaymentModule.php';
        if (file_exists($paymentModuleFile)) {
            $content = file_get_contents($paymentModuleFile);
            
            // Check for booking data in email templates
            if (preg_match('/booking.*email|email.*booking/i', $content)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Booking data potentially exposed in email communications',
                    'description' => 'Booking information may be included in email communications without proper data protection.',
                    'severity' => SecurityAudit::SEVERITY_LOW,
                    'category' => 'data_protection',
                    'affected_files' => [$paymentModuleFile],
                    'business_impact' => 'Sensitive booking details could be exposed in email communications',
                    'fix_specification' => 'Ensure email templates only include necessary booking information and use secure email transmission'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Perform comprehensive API security assessment (Task 6)
     */
    public function performApiSecurityAssessment()
    {
        $findings = [];
        
        // Analyze API authentication and authorization (Task 6.1)
        $findings = array_merge($findings, $this->analyzeApiAuthentication());
        
        // Test API input validation and security (Task 6.2)
        $findings = array_merge($findings, $this->testApiInputValidation());
        
        return $findings;
    }

    /**
     * Analyze API authentication and authorization mechanisms (Task 6.1)
     */
    public function analyzeApiAuthentication()
    {
        $findings = [];
        
        // Check webservice activation
        if (!Configuration::get('PS_WEBSERVICE')) {
            $findings[] = new SecurityFinding([
                'title' => 'Webservice Disabled',
                'description' => 'The webservice is disabled, which is secure but may impact API functionality if API access is required.',
                'severity' => SecurityAudit::SEVERITY_INFO,
                'category' => 'api_authentication',
                'affected_files' => ['webservice/dispatcher.php'],
                'business_impact' => 'API functionality unavailable - may impact integrations',
                'fix_specification' => 'Enable webservice only if API access is required and implement proper security controls'
            ]);
            return $findings; // No need to check further if webservice is disabled
        }

        // Check authentication key format validation
        $findings = array_merge($findings, $this->checkAuthenticationKeyValidation());
        
        // Check rate limiting implementation
        $findings = array_merge($findings, $this->checkApiRateLimiting());
        
        // Check API key management
        $findings = array_merge($findings, $this->checkApiKeyManagement());
        
        // Check authorization controls
        $findings = array_merge($findings, $this->checkApiAuthorization());
        
        return $findings;
    }

    /**
     * Check authentication key validation mechanisms
     */
    private function checkAuthenticationKeyValidation()
    {
        $findings = [];
        
        // Check if authentication key length is properly validated
        $webserviceRequestFile = _PS_CLASS_DIR_ . 'webservice/WebserviceRequest.php';
        if (file_exists($webserviceRequestFile)) {
            $content = file_get_contents($webserviceRequestFile);
            
            // Check for proper key length validation
            if (strpos($content, "strlen(\$this->_key) != '32'") === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Weak API Key Length Validation',
                    'description' => 'API key length validation may be insufficient or missing. Proper validation should ensure keys are exactly 32 characters long.',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'api_authentication',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'Weak API keys could be more easily compromised through brute force attacks',
                    'fix_specification' => 'Implement proper API key length validation requiring exactly 32 characters'
                ]);
            }
            
            // Check for key activation validation
            if (strpos($content, 'isKeyActive') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing API Key Activation Check',
                    'description' => 'API key activation status is not properly validated before processing requests.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'api_authentication',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'Inactive or revoked API keys could still be used to access the system',
                    'fix_specification' => 'Implement API key activation validation before processing any requests'
                ]);
            }

            // Check for proper authentication error handling
            if (strpos($content, 'WWW-Authenticate') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing WWW-Authenticate Header',
                    'description' => 'API does not properly set WWW-Authenticate header for authentication failures.',
                    'severity' => SecurityAudit::SEVERITY_LOW,
                    'category' => 'api_authentication',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'Authentication failures may not be properly communicated to clients',
                    'fix_specification' => 'Add proper WWW-Authenticate header for 401 responses'
                ]);
            }
        }
        
        return $findings;
    }

    /**
     * Check for API rate limiting implementation
     */
    private function checkApiRateLimiting()
    {
        $findings = [];
        
        // Check if rate limiting is implemented
        $webserviceFiles = [
            _PS_CLASS_DIR_ . 'webservice/WebserviceRequest.php',
            _PS_ROOT_DIR_ . 'webservice/dispatcher.php'
        ];
        
        $rateLimitingFound = false;
        foreach ($webserviceFiles as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/rate.*limit|throttle|request.*count|api.*limit/i', $content)) {
                    $rateLimitingFound = true;
                    break;
                }
            }
        }
        
        if (!$rateLimitingFound) {
            $findings[] = new SecurityFinding([
                'title' => 'Missing API Rate Limiting',
                'description' => 'No rate limiting mechanism found for API requests, allowing potential abuse and denial of service attacks.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => 'api_authentication',
                'affected_files' => ['webservice/dispatcher.php', 'classes/webservice/WebserviceRequest.php'],
                'business_impact' => 'API could be abused for DoS attacks or excessive resource consumption',
                'fix_specification' => 'Implement API rate limiting based on API key, IP address, or user account with appropriate limits'
            ]);
        }
        
        return $findings;
    }

    /**
     * Check API key management security
     */
    private function checkApiKeyManagement()
    {
        $findings = [];
        
        // Check WebserviceKey class for security issues
        $webserviceKeyFile = _PS_CLASS_DIR_ . 'webservice/WebserviceKey.php';
        if (file_exists($webserviceKeyFile)) {
            $content = file_get_contents($webserviceKeyFile);
            
            // Check for proper key generation
            if (strpos($content, 'keyExists') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Weak API Key Generation',
                    'description' => 'API key generation may not check for duplicates properly, potentially allowing key collisions.',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'api_authentication',
                    'affected_files' => ['classes/webservice/WebserviceKey.php'],
                    'business_impact' => 'Duplicate API keys could lead to unauthorized access or key conflicts',
                    'fix_specification' => 'Implement proper key generation with uniqueness validation and collision detection'
                ]);
            }
            
            // Check for SQL injection protection in key operations
            if (strpos($content, 'pSQL') === false && preg_match('/SELECT.*WHERE.*key.*=/', $content)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Potential SQL Injection in API Key Operations',
                    'description' => 'API key database queries may be vulnerable to SQL injection attacks.',
                    'severity' => SecurityAudit::SEVERITY_CRITICAL,
                    'category' => 'api_authentication',
                    'affected_files' => ['classes/webservice/WebserviceKey.php'],
                    'business_impact' => 'SQL injection could allow unauthorized access to API key database',
                    'fix_specification' => 'Use prepared statements or pSQL() for all API key database operations'
                ]);
            }

            // Check for key storage security
            if (preg_match('/key.*=.*["\'][^"\']{32}["\']/', $content)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Hardcoded API Key in Source Code',
                    'description' => 'API keys appear to be hardcoded in the source code, which is a security risk.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'api_authentication',
                    'affected_files' => ['classes/webservice/WebserviceKey.php'],
                    'business_impact' => 'Hardcoded API keys could be exposed in version control or source code',
                    'fix_specification' => 'Remove hardcoded keys and use proper key generation and storage mechanisms'
                ]);
            }
        }
        
        return $findings;
    }

    /**
     * Check API authorization controls
     */
    private function checkApiAuthorization()
    {
        $findings = [];
        
        // Check permission validation
        $webserviceRequestFile = _PS_CLASS_DIR_ . 'webservice/WebserviceRequest.php';
        if (file_exists($webserviceRequestFile)) {
            $content = file_get_contents($webserviceRequestFile);
            
            // Check for permission validation
            if (strpos($content, 'getPermissionForAccount') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing API Permission Validation',
                    'description' => 'API requests may not properly validate user permissions before processing.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'api_authorization',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'Unauthorized API access could lead to data breaches or system compromise',
                    'fix_specification' => 'Implement proper permission validation for all API endpoints based on user roles'
                ]);
            }
            
            // Check for resource-specific authorization
            if (strpos($content, 'checkResource') === false || strpos($content, 'checkHTTPMethod') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Insufficient API Resource Authorization',
                    'description' => 'API resource access may not be properly restricted by HTTP method and resource type.',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'api_authorization',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'Users might access API resources beyond their authorized scope',
                    'fix_specification' => 'Implement granular authorization for API resources and HTTP methods'
                ]);
            }

            // Check for shop-specific authorization
            if (strpos($content, 'shopHasRight') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing Multi-Shop Authorization',
                    'description' => 'API may not properly validate shop-specific access rights in multi-shop environments.',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'api_authorization',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'Cross-shop data access could occur in multi-shop installations',
                    'fix_specification' => 'Implement proper shop-specific authorization checks for multi-shop environments'
                ]);
            }
        }
        
        return $findings;
    }

    /**
     * Test API input validation and security (Task 6.2)
     */
    public function testApiInputValidation()
    {
        $findings = [];
        
        // Check API parameter validation
        $findings = array_merge($findings, $this->checkApiParameterValidation());
        
        // Check API response security
        $findings = array_merge($findings, $this->checkApiResponseSecurity());
        
        // Check CORS configuration
        $findings = array_merge($findings, $this->checkCorsConfiguration());
        
        // Check security headers
        $findings = array_merge($findings, $this->checkApiSecurityHeaders());
        
        return $findings;
    }

    /**
     * Check API parameter validation
     */
    private function checkApiParameterValidation()
    {
        $findings = [];
        
        // Check webservice specific management classes for input validation
        $webserviceFiles = [
            _PS_CLASS_DIR_ . 'webservice/WebserviceSpecificManagementBookings.php',
            _PS_CLASS_DIR_ . 'webservice/WebserviceSpecificManagementImages.php'
        ];
        
        foreach ($webserviceFiles as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                $className = basename($file, '.php');
                
                // Check for input validation
                if (strpos($content, 'validate') === false && strpos($content, 'Validate::') === false) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Missing API Input Validation in ' . $className,
                        'description' => 'API endpoints may not properly validate input parameters, allowing malformed or malicious data.',
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'api_input_validation',
                        'affected_files' => [$file],
                        'business_impact' => 'Invalid input could cause application errors or security vulnerabilities',
                        'fix_specification' => 'Implement comprehensive input validation using Validate class methods for all API parameters'
                    ]);
                }
                
                // Check for SQL injection protection
                if (strpos($content, 'pSQL') === false && preg_match('/Db::getInstance.*execute.*\$/', $content)) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Potential SQL Injection in API ' . $className,
                        'description' => 'API database queries may be vulnerable to SQL injection attacks due to insufficient parameter sanitization.',
                        'severity' => SecurityAudit::SEVERITY_CRITICAL,
                        'category' => 'api_input_validation',
                        'affected_files' => [$file],
                        'business_impact' => 'SQL injection could allow unauthorized database access and data manipulation',
                        'fix_specification' => 'Use parameterized queries with pSQL() or prepared statements for all database operations'
                    ]);
                }
                
                // Check for XSS protection in output
                if (strpos($content, 'htmlspecialchars') === false && strpos($content, 'Tools::safeOutput') === false && 
                    preg_match('/echo.*\$|print.*\$|return.*\$/', $content)) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Missing XSS Protection in API ' . $className,
                        'description' => 'API responses may be vulnerable to XSS attacks due to insufficient output encoding.',
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'api_input_validation',
                        'affected_files' => [$file],
                        'business_impact' => 'XSS vulnerabilities could allow script injection in API responses',
                        'fix_specification' => 'Use htmlspecialchars() or Tools::safeOutput() for all user-controlled data in responses'
                    ]);
                }

                // Check for file upload validation in image management
                if (strpos($className, 'Images') !== false) {
                    if (strpos($content, 'getimagesize') === false || strpos($content, 'mime') === false) {
                        $findings[] = new SecurityFinding([
                            'title' => 'Insufficient File Upload Validation in API Image Management',
                            'description' => 'API image upload functionality may not properly validate file types and content.',
                            'severity' => SecurityAudit::SEVERITY_HIGH,
                            'category' => 'api_input_validation',
                            'affected_files' => [$file],
                            'business_impact' => 'Malicious files could be uploaded through API endpoints',
                            'fix_specification' => 'Implement proper file type validation using getimagesize() and MIME type checking'
                        ]);
                    }
                }
            }
        }
        
        return $findings;
    }

    /**
     * Check API response security and information disclosure
     */
    private function checkApiResponseSecurity()
    {
        $findings = [];
        
        // Check for error information disclosure
        $webserviceRequestFile = _PS_CLASS_DIR_ . 'webservice/WebserviceRequest.php';
        if (file_exists($webserviceRequestFile)) {
            $content = file_get_contents($webserviceRequestFile);
            
            // Check for detailed error messages
            if (preg_match('/getMessage\(\)|getTrace\(\)|__FILE__|__LINE__/', $content)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Potential Information Disclosure in API Errors',
                    'description' => 'API error messages may expose sensitive system information like file paths, stack traces, or internal details.',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'api_response_security',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'System information disclosure could aid attackers in reconnaissance',
                    'fix_specification' => 'Sanitize error messages to return generic errors and log detailed information separately'
                ]);
            }
            
            // Check for debug information exposure
            if (preg_match('/_PS_MODE_DEV_|display_errors|var_dump|print_r/', $content)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Debug Information in API Responses',
                    'description' => 'API may expose debug information in production environments.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'api_response_security',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'Debug information could reveal sensitive system details to attackers',
                    'fix_specification' => 'Ensure debug mode is disabled and remove debug output from production API responses'
                ]);
            }

            // Check for sensitive data in API responses
            if (preg_match('/passwd|password|secret|key.*=|token.*=/', $content)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Potential Sensitive Data Exposure in API Responses',
                    'description' => 'API responses may inadvertently include sensitive data like passwords or keys.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'api_response_security',
                    'affected_files' => ['classes/webservice/WebserviceRequest.php'],
                    'business_impact' => 'Sensitive data exposure could lead to account compromise',
                    'fix_specification' => 'Filter sensitive fields from API responses and implement proper data serialization'
                ]);
            }
        }
        
        return $findings;
    }

    /**
     * Check CORS configuration and security
     */
    private function checkCorsConfiguration()
    {
        $findings = [];
        
        // Check for CORS headers in webservice files
        $webserviceFiles = [
            _PS_ROOT_DIR_ . 'webservice/dispatcher.php',
            _PS_CLASS_DIR_ . 'webservice/WebserviceRequest.php'
        ];
        
        $corsFound = false;
        $wildcardCors = false;
        
        foreach ($webserviceFiles as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/Access-Control-Allow-Origin|CORS/i', $content)) {
                    $corsFound = true;
                    
                    // Check for wildcard CORS
                    if (strpos($content, 'Access-Control-Allow-Origin: *') !== false) {
                        $wildcardCors = true;
                    }
                    break;
                }
            }
        }
        
        if ($wildcardCors) {
            $findings[] = new SecurityFinding([
                'title' => 'Insecure CORS Configuration',
                'description' => 'API allows requests from any origin using wildcard CORS policy, which poses security risks.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => 'api_cors',
                'affected_files' => $webserviceFiles,
                'business_impact' => 'Cross-origin attacks could be performed from any domain',
                'fix_specification' => 'Replace wildcard (*) with specific allowed origins and implement proper CORS validation'
            ]);
        } elseif (!$corsFound) {
            $findings[] = new SecurityFinding([
                'title' => 'Missing CORS Configuration',
                'description' => 'No CORS headers found, which may cause issues with legitimate browser-based API access.',
                'severity' => SecurityAudit::SEVERITY_LOW,
                'category' => 'api_cors',
                'affected_files' => ['webservice/dispatcher.php'],
                'business_impact' => 'Legitimate cross-origin API requests may be blocked by browsers',
                'fix_specification' => 'Implement proper CORS configuration with specific allowed origins if browser access is needed'
            ]);
        }
        
        return $findings;
    }

    /**
     * Check API security headers
     */
    private function checkApiSecurityHeaders()
    {
        $findings = [];
        
        // Check for security headers in API responses
        $webserviceFiles = [
            _PS_ROOT_DIR_ . 'webservice/dispatcher.php',
            _PS_CLASS_DIR_ . 'webservice/WebserviceOutputXML.php',
            _PS_CLASS_DIR_ . 'webservice/WebserviceOutputJSON.php'
        ];
        
        $securityHeaders = [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'X-XSS-Protection' => '1; mode=block',
            'Strict-Transport-Security' => 'max-age=31536000',
            'Content-Security-Policy' => "default-src 'self'"
        ];
        
        $missingHeaders = [];
        
        foreach ($webserviceFiles as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                $fileName = basename($file);
                
                foreach ($securityHeaders as $header => $value) {
                    if (strpos($content, $header) === false) {
                        $missingHeaders[$header] = $value;
                    }
                }
            }
        }

        if (!empty($missingHeaders)) {
            $headerList = implode(', ', array_keys($missingHeaders));
            $findings[] = new SecurityFinding([
                'title' => 'Missing Security Headers in API Responses',
                'description' => "API responses lack important security headers: $headerList. These headers help protect against various attacks.",
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'api_security_headers',
                'affected_files' => $webserviceFiles,
                'business_impact' => 'Missing security headers could allow various client-side attacks',
                'fix_specification' => 'Add security headers to all API responses: ' . json_encode($missingHeaders, JSON_PRETTY_PRINT)
            ]);
        }
        
        return $findings;
    }

    /**
     * Evaluate encryption implementation (Task 4.2)
     */
    private function evaluateEncryptionImplementation()
    {
        $findings = [];
        
        // Check PhpEncryption classes
        $findings = array_merge($findings, $this->assessPhpEncryptionClasses());
        
        // Check password hashing mechanisms
        $findings = array_merge($findings, $this->assessPasswordHashing());
        
        // Check database encryption
        $findings = array_merge($findings, $this->assessDatabaseEncryption());
        
        return $findings;
    }

    /**
     * Assess PhpEncryption classes implementation
     */
    private function assessPhpEncryptionClasses()
    {
        $findings = [];
        
        $encryptionFiles = [
            'PhpEncryption.php',
            'PhpEncryptionEngine.php',
            'PhpEncryptionLegacyEngine.php'
        ];

        foreach ($encryptionFiles as $filename) {
            $filepath = _PS_CLASS_DIR_ . $filename;
            if (!file_exists($filepath)) {
                $findings[] = new SecurityFinding([
                    'title' => "Missing encryption class: $filename",
                    'description' => "The encryption class $filename is not found, which may indicate incomplete encryption implementation.",
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'encryption',
                    'affected_files' => [$filepath],
                    'business_impact' => 'Encryption functionality may be compromised or unavailable',
                    'fix_specification' => "Ensure $filename exists and implements proper encryption methods"
                ]);
                continue;
            }

            $content = file_get_contents($filepath);
            
            // Check for legacy encryption usage
            if ($filename === 'PhpEncryptionLegacyEngine.php') {
                if (strpos($content, 'MCRYPT_') !== false) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Legacy encryption using deprecated mcrypt',
                        'description' => 'The legacy encryption engine uses the deprecated mcrypt extension which has known security issues.',
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'encryption',
                        'affected_files' => [$filepath],
                        'business_impact' => 'Deprecated encryption methods may have security vulnerabilities',
                        'fix_specification' => 'Migrate to modern encryption methods using OpenSSL or libsodium'
                    ]);
                }

                // Check for weak cipher modes
                if (strpos($content, 'MCRYPT_MODE_ECB') !== false) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Weak encryption mode ECB detected',
                        'description' => 'The legacy encryption engine may use ECB mode which is cryptographically weak.',
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'encryption',
                        'affected_files' => [$filepath],
                        'business_impact' => 'ECB mode reveals patterns in encrypted data',
                        'fix_specification' => 'Use CBC, GCM, or other secure encryption modes instead of ECB'
                    ]);
                }
            }

            // Check for proper key management
            if (strpos($content, 'createNewRandomKey') !== false) {
                if (strpos($content, 'openssl_random_pseudo_bytes') === false && 
                    strpos($content, 'random_bytes') === false &&
                    strpos($content, 'Key::createNewRandomKey') === false) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Weak random key generation',
                        'description' => 'Key generation may not use cryptographically secure random number generation.',
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'encryption',
                        'affected_files' => [$filepath],
                        'business_impact' => 'Predictable keys could be generated, compromising encryption security',
                        'fix_specification' => 'Use cryptographically secure random number generators for key generation'
                    ]);
                }
            }
        }

        return $findings;
    }

    /**
     * Assess password hashing mechanisms
     */
    private function assessPasswordHashing()
    {
        $findings = [];
        
        $toolsFile = _PS_CLASS_DIR_ . 'Tools.php';
        if (file_exists($toolsFile)) {
            $content = file_get_contents($toolsFile);
            
            // Check for MD5 password hashing
            if (preg_match('/function\s+encrypt.*md5\s*\(/', $content)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Weak password hashing using MD5',
                    'description' => 'The Tools::encrypt() method uses MD5 for password hashing, which is cryptographically weak.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'encryption',
                    'affected_files' => [$toolsFile],
                    'business_impact' => 'MD5 hashes can be easily cracked using rainbow tables or brute force',
                    'fix_specification' => 'Migrate to secure password hashing using password_hash() with bcrypt, argon2, or scrypt'
                ]);
            }

            // Check for salt usage
            if (strpos($content, 'md5(_COOKIE_KEY_.$passwd)') !== false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Static salt in password hashing',
                    'description' => 'Password hashing uses a static salt (_COOKIE_KEY_) which reduces security against rainbow table attacks.',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'encryption',
                    'affected_files' => [$toolsFile],
                    'business_impact' => 'Static salts make passwords vulnerable to rainbow table attacks',
                    'fix_specification' => 'Use unique random salts for each password hash'
                ]);
            }
        }

        // Check Customer class password handling
        $customerFile = _PS_CLASS_DIR_ . 'Customer.php';
        if (file_exists($customerFile)) {
            $content = file_get_contents($customerFile);
            
            // Check for password validation
            if (strpos($content, 'Tools::encrypt($passwd)') !== false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Customer class uses weak password encryption',
                    'description' => 'Customer class uses Tools::encrypt() which implements weak MD5-based password hashing.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'encryption',
                    'affected_files' => [$customerFile],
                    'business_impact' => 'Customer passwords are vulnerable to hash cracking attacks',
                    'fix_specification' => 'Implement secure password hashing in customer authentication'
                ]);
            }

            // Check for password strength validation
            if (strpos($content, 'Validate::isPasswd') !== false) {
                // This is good - password validation exists
            } else {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing password strength validation',
                    'description' => 'Customer class may not validate password strength requirements.',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'input_validation',
                    'affected_files' => [$customerFile],
                    'business_impact' => 'Weak passwords could be accepted, making accounts vulnerable to brute force',
                    'fix_specification' => 'Implement password strength validation (length, complexity, etc.)'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Assess database encryption for sensitive fields
     */
    private function assessDatabaseEncryption()
    {
        $findings = [];
        
        // Check if database connection supports encryption
        try {
            $db = Db::getInstance();
            
            // Check for encrypted sensitive fields in customer table
            $customerColumns = $db->executeS("SHOW COLUMNS FROM " . _DB_PREFIX_ . "customer");
            $sensitiveFields = ['passwd', 'secure_key', 'email', 'phone'];
            
            foreach ($sensitiveFields as $field) {
                $fieldFound = false;
                foreach ($customerColumns as $column) {
                    if ($column['Field'] === $field) {
                        $fieldFound = true;
                        // Check if field type suggests encryption (e.g., longer varchar for encrypted data)
                        if ($field === 'passwd' && !preg_match('/varchar\(60\)|varchar\(255\)|text/i', $column['Type'])) {
                            $findings[] = new SecurityFinding([
                                'title' => 'Password field may not support secure hashing',
                                'description' => "The password field in customer table has type '{$column['Type']}' which may not support secure password hashes.",
                                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                                'category' => 'encryption',
                                'affected_files' => ['database: ' . _DB_PREFIX_ . 'customer.passwd'],
                                'business_impact' => 'Password field size may be insufficient for secure hash algorithms',
                                'fix_specification' => 'Ensure password field can store at least 60 characters for bcrypt hashes'
                            ]);
                        }
                        break;
                    }
                }
                
                if (!$fieldFound && $field !== 'phone') { // phone might be optional
                    $findings[] = new SecurityFinding([
                        'title' => "Missing sensitive field: $field",
                        'description' => "The customer table is missing the expected sensitive field: $field",
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'data_protection',
                        'affected_files' => ['database: ' . _DB_PREFIX_ . "customer.$field"],
                        'business_impact' => 'Database schema may be incomplete or corrupted',
                        'fix_specification' => "Verify database schema includes all required sensitive fields"
                    ]);
                }
            }

            // Check for payment-related tables with potential sensitive data
            $paymentTables = [
                _DB_PREFIX_ . 'order_payment',
                _DB_PREFIX_ . 'orders'
            ];

            foreach ($paymentTables as $table) {
                try {
                    $columns = $db->executeS("SHOW COLUMNS FROM $table");
                    foreach ($columns as $column) {
                        // Look for fields that might contain sensitive payment data
                        if (preg_match('/card|cvv|ccv|account|routing/i', $column['Field'])) {
                            $findings[] = new SecurityFinding([
                                'title' => 'Potential sensitive payment data in database',
                                'description' => "Table $table contains field '{$column['Field']}' which may store sensitive payment information.",
                                'severity' => SecurityAudit::SEVERITY_CRITICAL,
                                'category' => 'data_protection',
                                'affected_files' => ["database: $table.{$column['Field']}"],
                                'business_impact' => 'Storing sensitive payment data violates PCI DSS requirements',
                                'fix_specification' => 'Remove sensitive payment fields or implement proper encryption and PCI DSS compliance'
                            ]);
                        }
                    }
                } catch (Exception $e) {
                    // Table might not exist, which is fine
                }
            }

        } catch (Exception $e) {
            $findings[] = new SecurityFinding([
                'title' => 'Database connection error during encryption assessment',
                'description' => 'Could not connect to database to assess encryption implementation: ' . $e->getMessage(),
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'encryption',
                'affected_files' => ['database connection'],
                'business_impact' => 'Cannot verify database-level security measures',
                'fix_specification' => 'Ensure database connection is properly configured and accessible'
            ]);
        }

        return $findings;
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

    /**
     * Analyze authentication mechanisms (Task 2.1)
     */
    public function analyzeAuthenticationMechanisms()
    {
        $findings = [];

        // Check admin login system
        $findings = array_merge($findings, $this->checkAdminLoginSecurity());
        
        // Check customer authentication
        $findings = array_merge($findings, $this->checkCustomerAuthSecurity());
        
        // Check employee authentication
        $findings = array_merge($findings, $this->checkEmployeeAuthSecurity());
        
        // Check password policies
        $findings = array_merge($findings, $this->checkPasswordPolicies());
        
        // Check session management
        $findings = array_merge($findings, $this->checkSessionManagement());

        return $findings;
    }

    /**
     * Assess authorization and access control (Task 2.2)
     */
    public function assessAuthorizationControls()
    {
        $findings = [];

        // Check role-based access control
        $findings = array_merge($findings, $this->checkRoleBasedAccessControl());
        
        // Check admin controller access controls
        $findings = array_merge($findings, $this->checkAdminControllerAccess());
        
        // Check API authentication
        $findings = array_merge($findings, $this->checkAPIAuthentication());

        return $findings;
    }

    /**
     * Check admin login system security
     */
    private function checkAdminLoginSecurity()
    {
        $findings = [];
        
        // Check if admin login redirects properly
        $adminLoginPath = _PS_ADMIN_DIR_ . '/login.php';
        if (file_exists($adminLoginPath)) {
            $content = file_get_contents($adminLoginPath);
            if (strpos($content, 'header(\'Location: index.php?controller=AdminLogin\')') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Admin Login Direct Access',
                    'description' => 'Admin login.php does not properly redirect to AdminLoginController',
                    'severity' => 3,
                    'category' => 'authentication',
                    'affected_files' => [$adminLoginPath],
                    'business_impact' => 'Potential information disclosure about admin structure',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Ensure admin/login.php properly redirects to AdminLoginController'
                ]);
            }
        }

        // Check AdminLoginController security
        $adminLoginController = _PS_ROOT_DIR_ . '/controllers/admin/AdminLoginController.php';
        if (file_exists($adminLoginController)) {
            $content = file_get_contents($adminLoginController);
            
            // Check for brute force protection
            if (strpos($content, 'rate_limit') === false && strpos($content, 'attempt') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing Brute Force Protection',
                    'description' => 'AdminLoginController lacks brute force protection mechanisms',
                    'severity' => 4,
                    'category' => 'authentication',
                    'affected_files' => [$adminLoginController],
                    'business_impact' => 'Susceptible to brute force attacks on admin accounts',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Implement rate limiting and account lockout after failed attempts'
                ]);
            }

            // Check for CSRF protection in login
            if (strpos($content, 'checkToken') !== false) {
                if (strpos($content, 'return true') !== false) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Disabled CSRF Protection on Login',
                        'description' => 'AdminLoginController has CSRF token checking disabled',
                        'severity' => 3,
                        'category' => 'authentication',
                        'affected_files' => [$adminLoginController],
                        'business_impact' => 'Vulnerable to CSRF attacks on login form',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Enable proper CSRF token validation for login forms'
                    ]);
                }
            }
        }

        return $findings;
    }

    /**
     * Check customer authentication security
     */
    private function checkCustomerAuthSecurity()
    {
        $findings = [];
        
        $customerClass = _PS_ROOT_DIR_ . '/classes/Customer.php';
        if (file_exists($customerClass)) {
            $content = file_get_contents($customerClass);
            
            // Check password storage method
            if (strpos($content, 'Tools::encrypt($passwd)') !== false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Weak Password Hashing',
                    'description' => 'Customer passwords use weak encryption instead of proper hashing',
                    'severity' => 5,
                    'category' => 'authentication',
                    'affected_files' => [$customerClass],
                    'business_impact' => 'Customer passwords can be decrypted if database is compromised',
                    'remediation_effort' => 'high',
                    'fix_specification' => 'Replace Tools::encrypt() with password_hash() using bcrypt or Argon2'
                ]);
            }

            // Check for secure key generation
            if (strpos($content, 'md5(uniqid(rand(), true))') !== false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Weak Secure Key Generation',
                    'description' => 'Customer secure keys use predictable MD5 generation',
                    'severity' => 4,
                    'category' => 'authentication',
                    'affected_files' => [$customerClass],
                    'business_impact' => 'Secure keys may be predictable, compromising session security',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Use cryptographically secure random number generation'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Check employee authentication security
     */
    private function checkEmployeeAuthSecurity()
    {
        $findings = [];
        
        $employeeClass = _PS_ROOT_DIR_ . '/classes/Employee.php';
        if (file_exists($employeeClass)) {
            $content = file_get_contents($employeeClass);
            
            // Check password storage method
            if (strpos($content, 'Tools::encrypt($passwd)') !== false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Weak Employee Password Hashing',
                    'description' => 'Employee passwords use weak encryption instead of proper hashing',
                    'severity' => 5,
                    'category' => 'authentication',
                    'affected_files' => [$employeeClass],
                    'business_impact' => 'Admin passwords can be decrypted if database is compromised',
                    'remediation_effort' => 'high',
                    'fix_specification' => 'Replace Tools::encrypt() with password_hash() using bcrypt or Argon2'
                ]);
            }

            // Check password reset security
            if (strpos($content, 'Tools::passwdGen(10, \'RANDOM\')') !== false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Insecure Password Reset',
                    'description' => 'Password reset generates weak 10-character passwords',
                    'severity' => 3,
                    'category' => 'authentication',
                    'affected_files' => [$employeeClass],
                    'business_impact' => 'Reset passwords may be weak and easily guessable',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Generate stronger passwords and require immediate change on first login'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Check password policies
     */
    private function checkPasswordPolicies()
    {
        $findings = [];
        
        $validateClass = _PS_ROOT_DIR_ . '/classes/Validate.php';
        if (file_exists($validateClass)) {
            $content = file_get_contents($validateClass);
            
            // Check password length requirements
            if (preg_match('/const PASSWORD_LENGTH = (\d+)/', $content, $matches)) {
                $minLength = (int)$matches[1];
                if ($minLength < 8) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Weak Password Length Policy',
                        'description' => "Customer password minimum length is only {$minLength} characters",
                        'severity' => 4,
                        'category' => 'authentication',
                        'affected_files' => [$validateClass],
                        'business_impact' => 'Weak passwords increase risk of brute force attacks',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Increase minimum password length to at least 8 characters'
                    ]);
                }
            }

            // Check for password complexity requirements
            if (strpos($content, 'preg_match') === false || 
                strpos($content, 'uppercase') === false ||
                strpos($content, 'lowercase') === false ||
                strpos($content, 'digit') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing Password Complexity Requirements',
                    'description' => 'Password validation lacks complexity requirements (uppercase, lowercase, digits, special chars)',
                    'severity' => 3,
                    'category' => 'authentication',
                    'affected_files' => [$validateClass],
                    'business_impact' => 'Users can create weak passwords vulnerable to dictionary attacks',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Add complexity validation requiring mixed case, numbers, and special characters'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Check session management security
     */
    private function checkSessionManagement()
    {
        $findings = [];
        
        $cookieClass = _PS_ROOT_DIR_ . '/classes/Cookie.php';
        if (file_exists($cookieClass)) {
            $content = file_get_contents($cookieClass);
            
            // Check for secure cookie settings
            if (strpos($content, 'httponly') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing HttpOnly Cookie Flag',
                    'description' => 'Cookies may not have HttpOnly flag set consistently',
                    'severity' => 3,
                    'category' => 'authentication',
                    'affected_files' => [$cookieClass],
                    'business_impact' => 'Session cookies accessible via JavaScript, increasing XSS risk',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Ensure all session cookies have HttpOnly flag set'
                ]);
            }

            // Check for secure flag
            if (strpos($content, '$this->_secure') !== false) {
                // Good - secure flag is configurable
            } else {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing Secure Cookie Flag',
                    'description' => 'Cookies may not have Secure flag for HTTPS connections',
                    'severity' => 3,
                    'category' => 'authentication',
                    'affected_files' => [$cookieClass],
                    'business_impact' => 'Session cookies transmitted over unencrypted connections',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Ensure Secure flag is set for cookies when using HTTPS'
                ]);
            }

            // Check session timeout
            if (strpos($content, 'time() + 1728000') !== false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Long Session Timeout',
                    'description' => 'Default session timeout is 20 days (1728000 seconds)',
                    'severity' => 2,
                    'category' => 'authentication',
                    'affected_files' => [$cookieClass],
                    'business_impact' => 'Long-lived sessions increase risk if device is compromised',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Reduce session timeout to reasonable duration (e.g., 24 hours)'
                ]);
            }
        }

        $contextClass = _PS_ROOT_DIR_ . '/classes/Context.php';
        if (file_exists($contextClass)) {
            $content = file_get_contents($contextClass);
            
            // Check for session fixation protection
            if (strpos($content, 'session_regenerate_id') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing Session Regeneration',
                    'description' => 'No session ID regeneration on authentication state changes',
                    'severity' => 4,
                    'category' => 'authentication',
                    'affected_files' => [$contextClass],
                    'business_impact' => 'Vulnerable to session fixation attacks',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Regenerate session ID on login, logout, and privilege changes'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Check role-based access control
     */
    private function checkRoleBasedAccessControl()
    {
        $findings = [];
        
        $profileClass = _PS_ROOT_DIR_ . '/classes/Profile.php';
        if (file_exists($profileClass)) {
            // Profile class exists - check for proper implementation
            $content = file_get_contents($profileClass);
            
            if (strpos($content, 'getProfileAccess') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Incomplete Profile Access Control',
                    'description' => 'Profile class may lack comprehensive access control methods',
                    'severity' => 3,
                    'category' => 'authorization',
                    'affected_files' => [$profileClass],
                    'business_impact' => 'Inconsistent permission enforcement across admin functions',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Implement comprehensive profile-based access control methods'
                ]);
            }
        }

        $tabClass = _PS_ROOT_DIR_ . '/classes/Tab.php';
        if (file_exists($tabClass)) {
            $content = file_get_contents($tabClass);
            
            // Check for proper tab access control
            if (strpos($content, 'checkAccess') === false) {
                $findings[] = new SecurityFinding([
                    'title' => 'Missing Tab Access Control',
                    'description' => 'Tab class lacks access control validation methods',
                    'severity' => 4,
                    'category' => 'authorization',
                    'affected_files' => [$tabClass],
                    'business_impact' => 'Users may access admin tabs without proper permissions',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Implement tab-level access control validation'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Check admin controller access controls
     */
    private function checkAdminControllerAccess()
    {
        $findings = [];
        
        $adminControllersPath = _PS_ROOT_DIR_ . '/controllers/admin/';
        if (is_dir($adminControllersPath)) {
            $controllers = glob($adminControllersPath . '*.php');
            $controllersWithoutAccess = [];
            
            foreach ($controllers as $controller) {
                $content = file_get_contents($controller);
                
                // Check for access control methods
                if (strpos($content, 'checkAccess') === false && 
                    strpos($content, 'viewAccess') === false &&
                    strpos($content, 'editAccess') === false) {
                    $controllersWithoutAccess[] = basename($controller);
                }
            }
            
            if (!empty($controllersWithoutAccess)) {
                $findings[] = new SecurityFinding([
                    'title' => 'Admin Controllers Missing Access Control',
                    'description' => 'Multiple admin controllers lack proper access control validation',
                    'severity' => 4,
                    'category' => 'authorization',
                    'affected_files' => array_slice($controllersWithoutAccess, 0, 10), // Limit to first 10
                    'business_impact' => 'Unauthorized access to admin functions',
                    'remediation_effort' => 'high',
                    'fix_specification' => 'Implement access control checks in all admin controllers'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Check API authentication
     */
    private function checkAPIAuthentication()
    {
        $findings = [];
        
        $webservicePath = _PS_ROOT_DIR_ . '/webservice/';
        if (is_dir($webservicePath)) {
            $dispatcherPath = $webservicePath . 'dispatcher.php';
            
            if (file_exists($dispatcherPath)) {
                $content = file_get_contents($dispatcherPath);
                
                // Check for proper authentication
                if (strpos($content, 'ws_key') === false) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Missing API Key Authentication',
                        'description' => 'API dispatcher may lack proper key-based authentication',
                        'severity' => 5,
                        'category' => 'authorization',
                        'affected_files' => [$dispatcherPath],
                        'business_impact' => 'Unauthorized API access could expose sensitive data',
                        'remediation_effort' => 'high',
                        'fix_specification' => 'Implement proper API key authentication and validation'
                    ]);
                }

                // Check for rate limiting
                if (strpos($content, 'rate_limit') === false && strpos($content, 'throttle') === false) {
                    $findings[] = new SecurityFinding([
                        'title' => 'Missing API Rate Limiting',
                        'description' => 'API lacks rate limiting protection against abuse',
                        'severity' => 3,
                        'category' => 'authorization',
                        'affected_files' => [$dispatcherPath],
                        'business_impact' => 'API vulnerable to abuse and DoS attacks',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Implement rate limiting for API endpoints'
                    ]);
                }
            }
        }

        return $findings;
    }

    /**
     * Conduct configuration and infrastructure security review (Task 5)
     */
    public function conductConfigurationSecurityReview()
    {
        $findings = array();
        
        // Audit system configurations (Task 5.1)
        $findings = array_merge($findings, $this->auditSystemConfigurations());
        
        // Assess file system security (Task 5.2)
        $findings = array_merge($findings, $this->assessFileSystemSecurity());
        
        // Evaluate error handling and information disclosure (Task 5.3)
        $findings = array_merge($findings, $this->evaluateErrorHandlingAndInfoDisclosure());
        
        return $findings;
    }

    /**
     * Audit system configurations (Task 5.1)
     */
    private function auditSystemConfigurations()
    {
        $findings = array();
        
        // Review configuration files in /config/ directory
        $findings = array_merge($findings, $this->reviewConfigurationFiles());
        
        // Check database security settings and connection parameters
        $findings = array_merge($findings, $this->checkDatabaseSecuritySettings());
        
        // Examine web server configuration requirements
        $findings = array_merge($findings, $this->examineWebServerConfiguration());
        
        return $findings;
    }

    /**
     * Review configuration files in /config/ directory
     */
    private function reviewConfigurationFiles()
    {
        $findings = array();
        $config_dir = _PS_ROOT_DIR_ . '/config/';
        
        // Critical configuration files to audit
        $critical_files = array(
            'config.inc.php' => 'Main configuration file',
            'defines.inc.php' => 'System constants and defines',
            'settings.inc.php' => 'Database and system settings',
            'smarty.config.inc.php' => 'Smarty template configuration',
            'defines_custom.inc.php' => 'Custom configuration overrides'
        );
        
        foreach ($critical_files as $file => $description) {
            $file_path = $config_dir . $file;
            
            if (file_exists($file_path)) {
                // Check file permissions
                $perms = fileperms($file_path);
                $octal_perms = substr(sprintf('%o', $perms), -4);
                
                if ($octal_perms > '0644') {
                    $findings[] = array(
                        'title' => 'Insecure Configuration File Permissions: ' . $file,
                        'description' => $this->generateConfigPermissionDescription($file_path, $octal_perms),
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'configuration',
                        'affected_files' => array($file_path),
                        'business_impact' => 'Configuration file exposure, potential credential theft',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Set file permissions to 644 (rw-r--r--) for configuration files'
                    );
                }
                
                // Scan configuration file content for security issues
                $config_vulns = $this->scanConfigurationFileContent($file_path);
                foreach ($config_vulns as $vuln) {
                    $findings[] = array(
                        'title' => 'Configuration Security Issue: ' . $file,
                        'description' => $this->generateConfigContentDescription($file_path, $vuln),
                        'severity' => $vuln['severity'],
                        'category' => 'configuration',
                        'affected_files' => array($file_path),
                        'business_impact' => $vuln['business_impact'],
                        'remediation_effort' => $vuln['remediation_effort'],
                        'fix_specification' => $vuln['fix_specification']
                    );
                }
            } else {
                // Missing critical configuration files
                if (in_array($file, array('settings.inc.php'))) {
                    $findings[] = array(
                        'title' => 'Missing Critical Configuration File: ' . $file,
                        'description' => 'Critical configuration file ' . $file . ' is missing, which may indicate incomplete installation or configuration issues.',
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'configuration',
                        'affected_files' => array($file_path),
                        'business_impact' => 'System instability, potential security misconfigurations',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Ensure all required configuration files are present and properly configured'
                    );
                }
            }
        }
        
        return $findings;
    }

    /**
     * Scan configuration file content for security issues
     */
    private function scanConfigurationFileContent($file_path)
    {
        $vulnerabilities = array();
        
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return $vulnerabilities;
        }
        
        $content = file_get_contents($file_path);
        $lines = explode("\n", $content);
        
        // Configuration security patterns
        $patterns = array(
            // Debug mode enabled in production
            '/_PS_MODE_DEV_.*?true/i' => array(
                'description' => 'Debug mode enabled in production environment',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'business_impact' => 'Information disclosure, performance degradation',
                'remediation_effort' => 'low',
                'fix_specification' => 'Set _PS_MODE_DEV_ to false in production'
            ),
            
            // Display errors enabled
            '/display_errors.*?on/i' => array(
                'description' => 'Error display enabled in production',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'business_impact' => 'Information disclosure through error messages',
                'remediation_effort' => 'low',
                'fix_specification' => 'Set display_errors to "off" in production'
            ),
            
            // Weak database credentials
            '/_DB_PASSWD_.*?[\'"][\'"]/i' => array(
                'description' => 'Empty database password detected',
                'severity' => SecurityAudit::SEVERITY_CRITICAL,
                'business_impact' => 'Database compromise, complete system access',
                'remediation_effort' => 'low',
                'fix_specification' => 'Set a strong database password'
            ),
            
            // Default database credentials
            '/_DB_USER_.*?[\'"]root[\'"]/i' => array(
                'description' => 'Default database user "root" detected',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'business_impact' => 'Elevated database privileges, potential system compromise',
                'remediation_effort' => 'medium',
                'fix_specification' => 'Create dedicated database user with minimal required privileges'
            ),
            
            // Hardcoded secrets or keys
            '/define\s*\(\s*[\'"][A-Z_]*SECRET[A-Z_]*[\'"].*?[\'"][a-zA-Z0-9]{1,10}[\'"]/i' => array(
                'description' => 'Weak or short secret key detected',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'business_impact' => 'Cryptographic weakness, session hijacking',
                'remediation_effort' => 'low',
                'fix_specification' => 'Generate strong random secret keys (minimum 32 characters)'
            ),
            
            // Dangerous PHP settings
            '/ini_set.*?allow_url_include.*?1|on/i' => array(
                'description' => 'allow_url_include enabled (dangerous)',
                'severity' => SecurityAudit::SEVERITY_CRITICAL,
                'business_impact' => 'Remote code execution, file inclusion attacks',
                'remediation_effort' => 'low',
                'fix_specification' => 'Disable allow_url_include setting'
            )
        );
        
        foreach ($lines as $line_number => $line) {
            $line_trimmed = trim($line);
            
            // Skip comments and empty lines
            if (empty($line_trimmed) || strpos($line_trimmed, '//') === 0 || 
                strpos($line_trimmed, '#') === 0 || strpos($line_trimmed, '/*') === 0) {
                continue;
            }
            
            foreach ($patterns as $pattern => $vuln_data) {
                if (preg_match($pattern, $line)) {
                    $vuln_data['line'] = $line_number + 1;
                    $vuln_data['code'] = trim($line);
                    $vulnerabilities[] = $vuln_data;
                }
            }
        }
        
        return $vulnerabilities;
    }

    /**
     * Check database security settings and connection parameters
     */
    private function checkDatabaseSecuritySettings()
    {
        $findings = array();
        
        // Check if settings.inc.php exists and analyze database configuration
        $settings_file = _PS_ROOT_DIR_ . '/config/settings.inc.php';
        
        if (file_exists($settings_file)) {
            $content = file_get_contents($settings_file);
            
            // Check for database security issues
            $db_issues = array();
            
            // Check for empty database password
            if (preg_match('/_DB_PASSWD_.*?[\'"][\'"]/i', $content)) {
                $db_issues[] = array(
                    'issue' => 'Empty database password',
                    'severity' => SecurityAudit::SEVERITY_CRITICAL,
                    'description' => 'Database connection uses empty password'
                );
            }
            
            // Check for default database user
            if (preg_match('/_DB_USER_.*?[\'"]root[\'"]/i', $content)) {
                $db_issues[] = array(
                    'issue' => 'Default database user',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'description' => 'Database connection uses default "root" user'
                );
            }
            
            foreach ($db_issues as $issue) {
                $findings[] = array(
                    'title' => 'Database Security Issue: ' . $issue['issue'],
                    'description' => $this->generateDatabaseSecurityDescription($issue),
                    'severity' => $issue['severity'],
                    'category' => 'configuration',
                    'affected_files' => array($settings_file),
                    'business_impact' => $this->getDatabaseSecurityImpact($issue['issue']),
                    'remediation_effort' => 'medium',
                    'fix_specification' => $this->getDatabaseSecurityFix($issue['issue'])
                );
            }
        }
        
        return $findings;
    }

    /**
     * Examine web server configuration requirements
     */
    private function examineWebServerConfiguration()
    {
        $findings = array();
        
        // Check .htaccess files for security configurations
        $htaccess_files = array(
            _PS_ROOT_DIR_ . '/.htaccess' => 'Root directory',
            _PS_ROOT_DIR_ . '/admin/.htaccess' => 'Admin directory',
            _PS_ROOT_DIR_ . '/config/.htaccess' => 'Config directory',
            _PS_ROOT_DIR_ . '/cache/.htaccess' => 'Cache directory',
            _PS_ROOT_DIR_ . '/log/.htaccess' => 'Log directory',
            _PS_ROOT_DIR_ . '/upload/.htaccess' => 'Upload directory'
        );
        
        foreach ($htaccess_files as $file_path => $description) {
            if (file_exists($file_path)) {
                $htaccess_issues = $this->analyzeHtaccessSecurity($file_path);
                foreach ($htaccess_issues as $issue) {
                    $findings[] = array(
                        'title' => '.htaccess Security Issue: ' . $description,
                        'description' => $issue['description'],
                        'severity' => $issue['severity'],
                        'category' => 'configuration',
                        'affected_files' => array($file_path),
                        'business_impact' => $issue['business_impact'],
                        'remediation_effort' => 'low',
                        'fix_specification' => $issue['fix_specification']
                    );
                }
            } else {
                // Missing critical .htaccess files
                if (in_array($description, array('Admin directory', 'Config directory', 'Upload directory'))) {
                    $findings[] = array(
                        'title' => 'Missing .htaccess Protection: ' . $description,
                        'description' => 'Critical directory lacks .htaccess protection: ' . $file_path,
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'configuration',
                        'affected_files' => array($file_path),
                        'business_impact' => 'Directory traversal, unauthorized file access',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Create .htaccess file with appropriate access restrictions'
                    );
                }
            }
        }
        
        return $findings;
    }

    /**
     * Assess file system security (Task 5.2)
     */
    private function assessFileSystemSecurity()
    {
        $findings = array();
        
        // Review file permissions across the application
        $findings = array_merge($findings, $this->reviewFilePermissions());
        
        // Check directory access controls and .htaccess files
        $findings = array_merge($findings, $this->checkDirectoryAccessControls());
        
        // Examine upload directory security
        $findings = array_merge($findings, $this->examineUploadDirectorySecurity());
        
        return $findings;
    }

    /**
     * Review file permissions across the application
     */
    private function reviewFilePermissions()
    {
        $findings = array();
        
        // Critical directories to check
        $critical_directories = array(
            _PS_ROOT_DIR_ . '/config/' => array('max_perm' => '0755', 'description' => 'Configuration directory'),
            _PS_ROOT_DIR_ . '/classes/' => array('max_perm' => '0755', 'description' => 'Core classes directory'),
            _PS_ROOT_DIR_ . '/admin/' => array('max_perm' => '0755', 'description' => 'Admin directory'),
            _PS_ROOT_DIR_ . '/modules/' => array('max_perm' => '0755', 'description' => 'Modules directory'),
            _PS_ROOT_DIR_ . '/controllers/' => array('max_perm' => '0755', 'description' => 'Controllers directory')
        );
        
        foreach ($critical_directories as $dir_path => $config) {
            if (is_dir($dir_path)) {
                $perms = fileperms($dir_path);
                $octal_perms = substr(sprintf('%o', $perms), -4);
                
                if ($octal_perms > $config['max_perm']) {
                    $findings[] = array(
                        'title' => 'Insecure Directory Permissions: ' . $config['description'],
                        'description' => $this->generateDirectoryPermissionDescription($dir_path, $octal_perms, $config['max_perm']),
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'configuration',
                        'affected_files' => array($dir_path),
                        'business_impact' => 'Unauthorized file access, potential code modification',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Set directory permissions to ' . $config['max_perm'] . ' or more restrictive'
                    );
                }
            }
        }
        
        // Check critical files
        $critical_files = array(
            _PS_ROOT_DIR_ . '/config/config.inc.php' => '0644',
            _PS_ROOT_DIR_ . '/config/settings.inc.php' => '0600',
            _PS_ROOT_DIR_ . '/config/defines.inc.php' => '0644',
            _PS_ROOT_DIR_ . '/.htaccess' => '0644'
        );
        
        foreach ($critical_files as $file_path => $max_perm) {
            if (file_exists($file_path)) {
                $perms = fileperms($file_path);
                $octal_perms = substr(sprintf('%o', $perms), -4);
                
                if ($octal_perms > $max_perm) {
                    $findings[] = array(
                        'title' => 'Insecure File Permissions: ' . basename($file_path),
                        'description' => $this->generateFilePermissionDescription($file_path, $octal_perms, $max_perm),
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'configuration',
                        'affected_files' => array($file_path),
                        'business_impact' => 'Unauthorized file access, information disclosure',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Set file permissions to ' . $max_perm . ' or more restrictive'
                    );
                }
            }
        }
        
        return $findings;
    }

    /**
     * Check directory access controls and .htaccess files
     */
    private function checkDirectoryAccessControls()
    {
        $findings = array();
        
        // Directories that should have .htaccess protection
        $protected_directories = array(
            _PS_ROOT_DIR_ . '/config/' => 'Configuration files',
            _PS_ROOT_DIR_ . '/cache/' => 'Cache files',
            _PS_ROOT_DIR_ . '/log/' => 'Log files',
            _PS_ROOT_DIR_ . '/upload/' => 'Upload directory',
            _PS_ROOT_DIR_ . '/download/' => 'Download directory'
        );
        
        foreach ($protected_directories as $dir_path => $description) {
            $htaccess_path = $dir_path . '.htaccess';
            
            if (is_dir($dir_path)) {
                if (!file_exists($htaccess_path)) {
                    $findings[] = array(
                        'title' => 'Missing .htaccess Protection: ' . $description,
                        'description' => 'Directory ' . $dir_path . ' lacks .htaccess protection, allowing direct web access to sensitive files.',
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'configuration',
                        'affected_files' => array($dir_path),
                        'business_impact' => 'Direct access to sensitive files, information disclosure',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Create .htaccess file with "Deny from all" directive'
                    );
                } else {
                    // Check .htaccess content
                    $htaccess_content = file_get_contents($htaccess_path);
                    if (stripos($htaccess_content, 'deny from all') === false && 
                        stripos($htaccess_content, 'require all denied') === false) {
                        $findings[] = array(
                            'title' => 'Weak .htaccess Protection: ' . $description,
                            'description' => '.htaccess file exists but may not properly deny access: ' . $htaccess_path,
                            'severity' => SecurityAudit::SEVERITY_MEDIUM,
                            'category' => 'configuration',
                            'affected_files' => array($htaccess_path),
                            'business_impact' => 'Potential unauthorized access to protected directory',
                            'remediation_effort' => 'low',
                            'fix_specification' => 'Add "Deny from all" or "Require all denied" directive to .htaccess'
                        );
                    }
                }
            }
        }
        
        return $findings;
    }

    /**
     * Examine upload directory security
     */
    private function examineUploadDirectorySecurity()
    {
        $findings = array();
        
        $upload_directories = array(
            _PS_ROOT_DIR_ . '/upload/',
            _PS_ROOT_DIR_ . '/img/',
            _PS_ROOT_DIR_ . '/cache/tmp/'
        );
        
        foreach ($upload_directories as $upload_dir) {
            if (is_dir($upload_dir)) {
                // Check if directory is web-accessible
                $is_web_accessible = $this->isDirectoryWebAccessible($upload_dir);
                
                if ($is_web_accessible) {
                    // Check for executable files in upload directory
                    $executable_files = $this->findExecutableFiles($upload_dir);
                    
                    if (!empty($executable_files)) {
                        $findings[] = array(
                            'title' => 'Executable Files in Upload Directory',
                            'description' => 'Found executable files in web-accessible upload directory: ' . implode(', ', $executable_files),
                            'severity' => SecurityAudit::SEVERITY_CRITICAL,
                            'category' => 'configuration',
                            'affected_files' => $executable_files,
                            'business_impact' => 'Remote code execution, complete system compromise',
                            'remediation_effort' => 'high',
                            'fix_specification' => 'Remove executable files and implement proper upload validation'
                        );
                    }
                    
                    // Check .htaccess protection for uploads
                    $htaccess_path = $upload_dir . '.htaccess';
                    if (!file_exists($htaccess_path)) {
                        $findings[] = array(
                            'title' => 'Unprotected Upload Directory',
                            'description' => 'Upload directory lacks .htaccess protection: ' . $upload_dir,
                            'severity' => SecurityAudit::SEVERITY_HIGH,
                            'category' => 'configuration',
                            'affected_files' => array($upload_dir),
                            'business_impact' => 'Direct execution of uploaded files, potential RCE',
                            'remediation_effort' => 'medium',
                            'fix_specification' => 'Add .htaccess to prevent execution of uploaded files'
                        );
                    }
                }
                
                // Check directory permissions
                $perms = fileperms($upload_dir);
                $octal_perms = substr(sprintf('%o', $perms), -4);
                
                if ($octal_perms > '0755') {
                    $findings[] = array(
                        'title' => 'Insecure Upload Directory Permissions',
                        'description' => 'Upload directory has overly permissive permissions: ' . $upload_dir . ' (' . $octal_perms . ')',
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'configuration',
                        'affected_files' => array($upload_dir),
                        'business_impact' => 'Unauthorized file modification, potential security bypass',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Set upload directory permissions to 755 or more restrictive'
                    );
                }
            }
        }
        
        return $findings;
    }

    /**
     * Evaluate error handling and information disclosure (Task 5.3)
     */
    private function evaluateErrorHandlingAndInfoDisclosure()
    {
        $findings = array();
        
        // Review error handling in core classes and controllers
        $findings = array_merge($findings, $this->reviewErrorHandling());
        
        // Check debug mode configurations and information leakage
        $findings = array_merge($findings, $this->checkDebugModeAndInfoLeakage());
        
        // Assess logging mechanisms for security events
        $findings = array_merge($findings, $this->assessLoggingMechanisms());
        
        return $findings;
    }

    /**
     * Review error handling in core classes and controllers
     */
    private function reviewErrorHandling()
    {
        $findings = array();
        
        // Scan core classes for error handling issues
        $core_files = array_merge(
            SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/classes/', array('php')),
            SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_ . '/controllers/', array('php'))
        );
        
        foreach ($core_files as $file) {
            $error_issues = $this->scanFileForErrorHandlingIssues($file);
            foreach ($error_issues as $issue) {
                $findings[] = array(
                    'title' => 'Error Handling Issue: ' . basename($file),
                    'description' => $issue['description'],
                    'severity' => $issue['severity'],
                    'category' => 'configuration',
                    'affected_files' => array($file),
                    'business_impact' => $issue['business_impact'],
                    'remediation_effort' => $issue['remediation_effort'],
                    'fix_specification' => $issue['fix_specification']
                );
            }
        }
        
        return $findings;
    }

    /**
     * Check debug mode configurations and information leakage
     */
    private function checkDebugModeAndInfoLeakage()
    {
        $findings = array();
        
        // Check if debug mode is enabled
        if (defined('_PS_MODE_DEV_') && _PS_MODE_DEV_) {
            $findings[] = array(
                'title' => 'Debug Mode Enabled in Production',
                'description' => 'Debug mode (_PS_MODE_DEV_) is enabled, which can expose sensitive information and degrade performance.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => 'configuration',
                'affected_files' => array(_PS_ROOT_DIR_ . '/config/defines.inc.php'),
                'business_impact' => 'Information disclosure, performance impact, security bypass',
                'remediation_effort' => 'low',
                'fix_specification' => 'Set _PS_MODE_DEV_ to false in production environment'
            );
        }
        
        // Check PHP error display settings
        $display_errors = ini_get('display_errors');
        if ($display_errors && $display_errors !== '0' && strtolower($display_errors) !== 'off') {
            $findings[] = array(
                'title' => 'PHP Error Display Enabled',
                'description' => 'PHP display_errors is enabled, which can expose sensitive information through error messages.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'configuration',
                'affected_files' => array('PHP Configuration'),
                'business_impact' => 'Information disclosure through error messages',
                'remediation_effort' => 'low',
                'fix_specification' => 'Set display_errors to Off in production PHP configuration'
            );
        }
        
        // Check for information disclosure in headers
        $info_disclosure_issues = $this->checkInformationDisclosureInHeaders();
        foreach ($info_disclosure_issues as $issue) {
            $findings[] = array(
                'title' => 'Information Disclosure in Headers',
                'description' => $issue['description'],
                'severity' => $issue['severity'],
                'category' => 'configuration',
                'affected_files' => array('HTTP Headers'),
                'business_impact' => 'Information disclosure, fingerprinting',
                'remediation_effort' => 'medium',
                'fix_specification' => $issue['fix_specification']
            );
        }
        
        return $findings;
    }

    /**
     * Assess logging mechanisms for security events
     */
    private function assessLoggingMechanisms()
    {
        $findings = array();
        
        // Check if logging is properly configured
        $log_dir = _PS_ROOT_DIR_ . '/log/';
        
        if (!is_dir($log_dir)) {
            $findings[] = array(
                'title' => 'Missing Log Directory',
                'description' => 'Log directory does not exist, which may indicate logging is not properly configured.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'configuration',
                'affected_files' => array($log_dir),
                'business_impact' => 'No audit trail, difficult incident response',
                'remediation_effort' => 'low',
                'fix_specification' => 'Create log directory and configure proper logging'
            );
        } else {
            // Check log directory permissions
            $perms = fileperms($log_dir);
            $octal_perms = substr(sprintf('%o', $perms), -4);
            
            if ($octal_perms > '0755') {
                $findings[] = array(
                    'title' => 'Insecure Log Directory Permissions',
                    'description' => 'Log directory has overly permissive permissions: ' . $octal_perms,
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'configuration',
                    'affected_files' => array($log_dir),
                    'business_impact' => 'Log tampering, information disclosure',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Set log directory permissions to 755 or more restrictive'
                );
            }
            
            // Check for sensitive information in logs
            $log_files = glob($log_dir . '*.log');
            foreach ($log_files as $log_file) {
                $sensitive_data_issues = $this->scanLogFileForSensitiveData($log_file);
                foreach ($sensitive_data_issues as $issue) {
                    $findings[] = array(
                        'title' => 'Sensitive Data in Log File: ' . basename($log_file),
                        'description' => $issue['description'],
                        'severity' => $issue['severity'],
                        'category' => 'configuration',
                        'affected_files' => array($log_file),
                        'business_impact' => 'Information disclosure, credential exposure',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Remove sensitive data from logs and implement proper log sanitization'
                    );
                }
            }
        }
        
        return $findings;
    }

    // Helper methods for configuration audit

    /**
     * Generate configuration permission description
     */
    private function generateConfigPermissionDescription($file_path, $current_perms)
    {
        return "Configuration file has insecure permissions: {$file_path} (current: {$current_perms}). " .
               "This could allow unauthorized users to read sensitive configuration data including database credentials.";
    }

    /**
     * Generate configuration content description
     */
    private function generateConfigContentDescription($file_path, $vulnerability)
    {
        $description = "<p><strong>File:</strong> " . htmlspecialchars($file_path) . "</p>";
        $description .= "<p><strong>Line:</strong> " . $vulnerability['line'] . "</p>";
        $description .= "<p><strong>Code:</strong></p><pre>" . htmlspecialchars($vulnerability['code']) . "</pre>";
        $description .= "<p><strong>Issue:</strong> " . htmlspecialchars($vulnerability['description']) . "</p>";
        
        return $description;
    }

    /**
     * Generate database security description
     */
    private function generateDatabaseSecurityDescription($issue)
    {
        return "Database security issue detected: " . $issue['description'] . ". " .
               "This configuration poses a significant security risk to the database and application.";
    }

    /**
     * Get database security impact
     */
    private function getDatabaseSecurityImpact($issue_type)
    {
        $impacts = array(
            'Empty database password' => 'Complete database compromise, data theft, system takeover',
            'Default database user' => 'Elevated privileges, potential system compromise',
            'Localhost database server' => 'Limited network isolation, potential lateral movement'
        );
        
        return isset($impacts[$issue_type]) ? $impacts[$issue_type] : 'Database security compromise';
    }

    /**
     * Get database security fix
     */
    private function getDatabaseSecurityFix($issue_type)
    {
        $fixes = array(
            'Empty database password' => 'Set a strong, unique password for the database user',
            'Default database user' => 'Create a dedicated database user with minimal required privileges',
            'Localhost database server' => 'Consider using a dedicated database server with proper network isolation'
        );
        
        return isset($fixes[$issue_type]) ? $fixes[$issue_type] : 'Review and fix database security configuration';
    }

    /**
     * Analyze .htaccess security
     */
    private function analyzeHtaccessSecurity($file_path)
    {
        $issues = array();
        
        if (!file_exists($file_path)) {
            return $issues;
        }
        
        $content = file_get_contents($file_path);
        
        // Check for security directives
        if (stripos($content, 'deny from all') === false && 
            stripos($content, 'require all denied') === false &&
            stripos($content, 'options -indexes') === false) {
            $issues[] = array(
                'description' => '.htaccess file lacks proper access restrictions',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'business_impact' => 'Potential directory browsing, unauthorized access',
                'fix_specification' => 'Add appropriate access restrictions to .htaccess file'
            );
        }
        
        return $issues;
    }

    /**
     * Generate directory permission description
     */
    private function generateDirectoryPermissionDescription($dir_path, $current_perms, $max_perms)
    {
        return "Directory has insecure permissions: {$dir_path} (current: {$current_perms}, recommended: {$max_perms} or lower). " .
               "This could allow unauthorized access or modification of critical files.";
    }

    /**
     * Generate file permission description
     */
    private function generateFilePermissionDescription($file_path, $current_perms, $max_perms)
    {
        return "File has insecure permissions: {$file_path} (current: {$current_perms}, recommended: {$max_perms} or lower). " .
               "This could allow unauthorized access to sensitive file content.";
    }

    /**
     * Check if directory is web accessible
     */
    private function isDirectoryWebAccessible($dir_path)
    {
        // Simple check - if directory is under web root and no .htaccess protection
        $web_root = _PS_ROOT_DIR_;
        $htaccess_path = $dir_path . '.htaccess';
        
        return (strpos($dir_path, $web_root) === 0) && !file_exists($htaccess_path);
    }

    /**
     * Find executable files in directory
     */
    private function findExecutableFiles($dir_path)
    {
        $executable_files = array();
        $dangerous_extensions = array('php', 'phtml', 'php3', 'php4', 'php5', 'phar', 'exe', 'bat', 'cmd', 'sh');
        
        if (is_dir($dir_path)) {
            $files = glob($dir_path . '*');
            foreach ($files as $file) {
                if (is_file($file)) {
                    $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                    if (in_array($extension, $dangerous_extensions)) {
                        $executable_files[] = $file;
                    }
                }
            }
        }
        
        return $executable_files;
    }

    /**
     * Scan file for error handling issues
     */
    private function scanFileForErrorHandlingIssues($file_path)
    {
        $issues = array();
        
        if (!file_exists($file_path)) {
            return $issues;
        }
        
        $content = file_get_contents($file_path);
        $lines = explode("\n", $content);
        
        // Error handling patterns
        $patterns = array(
            '/die\s*\(\s*[\'"][^\'\"]*\$_/i' => array(
                'description' => 'Die statement with user input may expose sensitive information',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'business_impact' => 'Information disclosure through error messages',
                'remediation_effort' => 'low',
                'fix_specification' => 'Use generic error messages and log detailed errors securely'
            ),
            '/exit\s*\(\s*[\'"][^\'\"]*\$_/i' => array(
                'description' => 'Exit statement with user input may expose sensitive information',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'business_impact' => 'Information disclosure through error messages',
                'remediation_effort' => 'low',
                'fix_specification' => 'Use generic error messages and log detailed errors securely'
            ),
            '/echo.*?mysql_error\(\)/i' => array(
                'description' => 'MySQL error displayed to user',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'business_impact' => 'Database structure disclosure, potential SQL injection hints',
                'remediation_effort' => 'low',
                'fix_specification' => 'Log database errors securely and show generic error to users'
            )
        );
        
        foreach ($lines as $line_number => $line) {
            foreach ($patterns as $pattern => $issue_data) {
                if (preg_match($pattern, $line)) {
                    $issue_data['line'] = $line_number + 1;
                    $issue_data['code'] = trim($line);
                    $issues[] = $issue_data;
                }
            }
        }
        
        return $issues;
    }

    /**
     * Check information disclosure in headers
     */
    private function checkInformationDisclosureInHeaders()
    {
        $issues = array();
        
        // Check if server signature is exposed
        if (function_exists('apache_get_version')) {
            $issues[] = array(
                'description' => 'Apache version information may be exposed in headers',
                'severity' => SecurityAudit::SEVERITY_LOW,
                'fix_specification' => 'Configure ServerTokens to Prod in Apache configuration'
            );
        }
        
        // Check PHP version exposure
        if (ini_get('expose_php')) {
            $issues[] = array(
                'description' => 'PHP version is exposed in X-Powered-By header',
                'severity' => SecurityAudit::SEVERITY_LOW,
                'fix_specification' => 'Set expose_php to Off in PHP configuration'
            );
        }
        
        return $issues;
    }

    /**
     * Scan log file for sensitive data
     */
    private function scanLogFileForSensitiveData($log_file)
    {
        $issues = array();
        
        if (!file_exists($log_file) || !is_readable($log_file)) {
            return $issues;
        }
        
        // Read only first 1MB to avoid memory issues
        $content = file_get_contents($log_file, false, null, 0, 1048576);
        
        // Patterns for sensitive data
        $patterns = array(
            '/password[\'\":\s]*[\'\"]\w+[\'\"]/' => 'Password found in log file',
            '/api[_-]?key[\'\":\s]*[\'\"]\w+[\'\"]/' => 'API key found in log file',
            '/secret[\'\":\s]*[\'\"]\w+[\'\"]/' => 'Secret found in log file',
            '/token[\'\":\s]*[\'\"]\w+[\'\"]/' => 'Token found in log file'
        );
        
        foreach ($patterns as $pattern => $description) {
            if (preg_match($pattern, $content)) {
                $issues[] = array(
                    'description' => $description,
                    'severity' => SecurityAudit::SEVERITY_HIGH
                );
            }
        }
        
        return $issues;
    }

    /**
     * Assess third-party and module security (Task 7)
     */
    public function assessThirdPartyAndModuleSecurity()
    {
        $findings = array();
        
        // Review module security implementations (Task 7.1)
        $findings = array_merge($findings, $this->reviewModuleSecurityImplementations());
        
        // Evaluate dependency security (Task 7.2)
        $findings = array_merge($findings, $this->evaluateDependencySecurity());
        
        return $findings;
    }

    /**
     * Review module security implementations (Task 7.1)
     */
    private function reviewModuleSecurityImplementations()
    {
        $findings = array();
        $modules_dir = _PS_ROOT_DIR_ . '/modules/';
        
        if (!is_dir($modules_dir)) {
            return $findings;
        }
        
        // Get all module directories
        $module_dirs = array_filter(glob($modules_dir . '*'), 'is_dir');
        
        foreach ($module_dirs as $module_dir) {
            $module_name = basename($module_dir);
            
            // Skip system directories
            if (in_array($module_name, array('.', '..', 'index.php'))) {
                continue;
            }
            
            // Analyze module security practices
            $module_findings = $this->analyzeModuleSecurity($module_dir, $module_name);
            $findings = array_merge($findings, $module_findings);
        }
        
        return $findings;
    }

    /**
     * Analyze individual module security
     */
    private function analyzeModuleSecurity($module_dir, $module_name)
    {
        $findings = array();
        
        // Check module authentication and authorization
        $auth_findings = $this->checkModuleAuthentication($module_dir, $module_name);
        $findings = array_merge($findings, $auth_findings);
        
        // Check module input validation and data handling
        $input_findings = $this->checkModuleInputValidation($module_dir, $module_name);
        $findings = array_merge($findings, $input_findings);
        
        // Check module file security
        $file_findings = $this->checkModuleFileSecurity($module_dir, $module_name);
        $findings = array_merge($findings, $file_findings);
        
        // Check module configuration security
        $config_findings = $this->checkModuleConfigurationSecurity($module_dir, $module_name);
        $findings = array_merge($findings, $config_findings);
        
        return $findings;
    }

    /**
     * Check module authentication and authorization
     */
    private function checkModuleAuthentication($module_dir, $module_name)
    {
        $findings = array();
        
        // Check admin controllers for proper authentication
        $admin_controllers_dir = $module_dir . '/controllers/admin/';
        if (is_dir($admin_controllers_dir)) {
            $admin_files = SecurityAuditUtils::scanDirectory($admin_controllers_dir, array('php'));
            
            foreach ($admin_files as $file) {
                $content = file_get_contents($file);
                
                // Check for missing authentication checks
                if (!preg_match('/checkAccess|checkToken|AdminController/', $content)) {
                    $findings[] = new SecurityFinding(array(
                        'title' => "Missing Authentication Check in Module: $module_name",
                        'description' => $this->generateModuleAuthDescription($file, 'missing_auth_check'),
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'authentication',
                        'affected_files' => array($file),
                        'business_impact' => 'Unauthorized access to module admin functions',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Implement proper authentication checks in admin controllers'
                    ));
                }
                
                // Check for weak session handling
                if (preg_match('/\$_SESSION\[.*\]\s*=/', $content)) {
                    $findings[] = new SecurityFinding(array(
                        'title' => "Weak Session Handling in Module: $module_name",
                        'description' => $this->generateModuleAuthDescription($file, 'weak_session'),
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'authentication',
                        'affected_files' => array($file),
                        'business_impact' => 'Session hijacking, unauthorized access',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Use PrestaShop Context and Cookie classes for session management'
                    ));
                }
            }
        }
        
        // Check frontend controllers for authorization
        $front_controllers_dir = $module_dir . '/controllers/front/';
        if (is_dir($front_controllers_dir)) {
            $front_files = SecurityAuditUtils::scanDirectory($front_controllers_dir, array('php'));
            
            foreach ($front_files as $file) {
                $content = file_get_contents($file);
                
                // Check for missing CSRF protection
                if (preg_match('/Tools::isSubmit|_POST|_GET/', $content) && 
                    !preg_match('/Tools::getToken|checkToken/', $content)) {
                    $findings[] = new SecurityFinding(array(
                        'title' => "Missing CSRF Protection in Module: $module_name",
                        'description' => $this->generateModuleAuthDescription($file, 'missing_csrf'),
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'authentication',
                        'affected_files' => array($file),
                        'business_impact' => 'Cross-site request forgery attacks',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Add CSRF token validation for form submissions'
                    ));
                }
            }
        }
        
        return $findings;
    }

    /**
     * Check module input validation and data handling
     */
    private function checkModuleInputValidation($module_dir, $module_name)
    {
        $findings = array();
        
        // Scan all PHP files in the module
        $php_files = SecurityAuditUtils::scanDirectory($module_dir, array('php'));
        
        foreach ($php_files as $file) {
            $content = file_get_contents($file);
            
            // Check for SQL injection vulnerabilities
            $sql_patterns = array(
                '/\$sql\s*=.*\$_[GET|POST|REQUEST]/' => 'Direct user input in SQL query',
                '/Db::getInstance\(\)->execute\(.*\$_[GET|POST|REQUEST]/' => 'Unvalidated input in database query',
                '/mysql_query\(.*\$_[GET|POST|REQUEST]/' => 'Direct SQL injection vulnerability'
            );
            
            foreach ($sql_patterns as $pattern => $description) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    $line_number = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                    
                    $findings[] = new SecurityFinding(array(
                        'title' => "SQL Injection Vulnerability in Module: $module_name",
                        'description' => $this->generateModuleInputDescription($file, $description, $line_number, $matches[0][0]),
                        'severity' => SecurityAudit::SEVERITY_CRITICAL,
                        'category' => 'input_validation',
                        'affected_files' => array($file),
                        'business_impact' => 'Database compromise, data theft',
                        'remediation_effort' => 'high',
                        'fix_specification' => 'Use prepared statements and input validation'
                    ));
                }
            }
            
            // Check for XSS vulnerabilities
            $xss_patterns = array(
                '/echo\s+\$_[GET|POST|REQUEST]/' => 'Direct output of user input',
                '/print\s+\$_[GET|POST|REQUEST]/' => 'Direct output of user input',
                '/\{\$smarty\.[get|post|request]/' => 'Unescaped user input in template'
            );
            
            foreach ($xss_patterns as $pattern => $description) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    $line_number = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                    
                    $findings[] = new SecurityFinding(array(
                        'title' => "XSS Vulnerability in Module: $module_name",
                        'description' => $this->generateModuleInputDescription($file, $description, $line_number, $matches[0][0]),
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'input_validation',
                        'affected_files' => array($file),
                        'business_impact' => 'Cross-site scripting, session hijacking',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Use Tools::safeOutput() or proper escaping'
                    ));
                }
            }
            
            // Check for file upload vulnerabilities
            if (preg_match('/\$_FILES/', $content)) {
                if (!preg_match('/pathinfo|getimagesize|mime_content_type/', $content)) {
                    $findings[] = new SecurityFinding(array(
                        'title' => "Insecure File Upload in Module: $module_name",
                        'description' => $this->generateModuleInputDescription($file, 'Missing file validation', 0, ''),
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'input_validation',
                        'affected_files' => array($file),
                        'business_impact' => 'Arbitrary file upload, code execution',
                        'remediation_effort' => 'high',
                        'fix_specification' => 'Implement comprehensive file validation'
                    ));
                }
            }
        }
        
        return $findings;
    }

    /**
     * Check module file security
     */
    private function checkModuleFileSecurity($module_dir, $module_name)
    {
        $findings = array();
        
        // Check for missing index.php files
        $directories = array_filter(glob($module_dir . '/*'), 'is_dir');
        $directories[] = $module_dir; // Include root module directory
        
        foreach ($directories as $dir) {
            $index_file = $dir . '/index.php';
            if (!file_exists($index_file)) {
                $findings[] = new SecurityFinding(array(
                    'title' => "Missing Security Index File in Module: $module_name",
                    'description' => "Directory $dir is missing index.php security file, allowing directory browsing",
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'configuration',
                    'affected_files' => array($dir),
                    'business_impact' => 'Information disclosure, directory browsing',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Add index.php security files to all directories'
                ));
            }
        }
        
        // Check file permissions
        $sensitive_files = array(
            $module_dir . '/' . $module_name . '.php',
            $module_dir . '/config.xml'
        );
        
        foreach ($sensitive_files as $file) {
            if (file_exists($file)) {
                $perms = fileperms($file);
                $octal_perms = substr(sprintf('%o', $perms), -3);
                
                if ($octal_perms > '644') {
                    $findings[] = new SecurityFinding(array(
                        'title' => "Insecure File Permissions in Module: $module_name",
                        'description' => "File $file has overly permissive permissions: $octal_perms",
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'configuration',
                        'affected_files' => array($file),
                        'business_impact' => 'Unauthorized file modification',
                        'remediation_effort' => 'low',
                        'fix_specification' => 'Set file permissions to 644'
                    ));
                }
            }
        }
        
        return $findings;
    }

    /**
     * Check module configuration security
     */
    private function checkModuleConfigurationSecurity($module_dir, $module_name)
    {
        $findings = array();
        
        // Check main module file for security issues
        $main_file = $module_dir . '/' . $module_name . '.php';
        if (file_exists($main_file)) {
            $content = file_get_contents($main_file);
            
            // Check for hardcoded credentials
            $cred_patterns = array(
                '/password\s*=\s*[\'"][^\'"]+[\'"]/' => 'Hardcoded password',
                '/api[_-]?key\s*=\s*[\'"][^\'"]+[\'"]/' => 'Hardcoded API key',
                '/secret\s*=\s*[\'"][^\'"]+[\'"]/' => 'Hardcoded secret'
            );
            
            foreach ($cred_patterns as $pattern => $description) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    $line_number = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                    
                    $findings[] = new SecurityFinding(array(
                        'title' => "Hardcoded Credentials in Module: $module_name",
                        'description' => $this->generateModuleConfigDescription($main_file, $description, $line_number),
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'configuration',
                        'affected_files' => array($main_file),
                        'business_impact' => 'Credential exposure, unauthorized access',
                        'remediation_effort' => 'medium',
                        'fix_specification' => 'Move credentials to configuration or environment variables'
                    ));
                }
            }
            
            // Check for debug code
            if (preg_match('/var_dump|print_r|error_reporting\(E_ALL\)/', $content)) {
                $findings[] = new SecurityFinding(array(
                    'title' => "Debug Code in Production Module: $module_name",
                    'description' => "Debug code found in module that may leak sensitive information",
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'configuration',
                    'affected_files' => array($main_file),
                    'business_impact' => 'Information disclosure',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Remove debug code from production modules'
                ));
            }
        }
        
        return $findings;
    }

    /**
     * Evaluate dependency security (Task 7.2)
     */
    private function evaluateDependencySecurity()
    {
        $findings = array();
        
        // Scan composer dependencies for known vulnerabilities
        $findings = array_merge($findings, $this->scanComposerDependencies());
        
        // Review JavaScript library security
        $findings = array_merge($findings, $this->reviewJavaScriptLibrarySecurity());
        
        // Check third-party service integrations
        $findings = array_merge($findings, $this->checkThirdPartyServiceIntegrations());
        
        return $findings;
    }

    /**
     * Scan composer dependencies for known vulnerabilities
     */
    private function scanComposerDependencies()
    {
        $findings = array();
        $composer_file = _PS_ROOT_DIR_ . '/composer.json';
        
        if (!file_exists($composer_file)) {
            return $findings;
        }
        
        $composer_data = json_decode(file_get_contents($composer_file), true);
        if (!$composer_data) {
            return $findings;
        }
        
        // Check for outdated or vulnerable dependencies
        $dependencies = array_merge(
            isset($composer_data['require']) ? $composer_data['require'] : array(),
            isset($composer_data['require-dev']) ? $composer_data['require-dev'] : array()
        );
        
        foreach ($dependencies as $package => $version) {
            // Skip PHP version requirement
            if ($package === 'php') {
                continue;
            }
            
            // Check for known vulnerable packages (simplified check)
            $vulnerable_packages = array(
                'monolog/monolog' => array('< 1.25.2', 'Remote code execution'),
                'symfony/http-foundation' => array('< 3.4.26', 'Session fixation'),
                'twig/twig' => array('< 1.38.0', 'Code injection'),
                'doctrine/orm' => array('< 2.5.13', 'SQL injection')
            );
            
            if (isset($vulnerable_packages[$package])) {
                $vuln_info = $vulnerable_packages[$package];
                
                $findings[] = new SecurityFinding(array(
                    'title' => "Vulnerable Composer Dependency: $package",
                    'description' => "Package $package version $version may be vulnerable: {$vuln_info[1]}",
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'third_party',
                    'affected_files' => array($composer_file),
                    'business_impact' => 'Third-party vulnerability exploitation',
                    'remediation_effort' => 'medium',
                    'fix_specification' => "Update $package to version {$vuln_info[0]} or later"
                ));
            }
        }
        
        // Check for composer.lock file
        $composer_lock = _PS_ROOT_DIR_ . '/composer.lock';
        if (!file_exists($composer_lock)) {
            $findings[] = new SecurityFinding(array(
                'title' => 'Missing Composer Lock File',
                'description' => 'composer.lock file is missing, which can lead to inconsistent dependency versions',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'configuration',
                'affected_files' => array($composer_file),
                'business_impact' => 'Inconsistent dependency versions, potential security issues',
                'remediation_effort' => 'low',
                'fix_specification' => 'Run composer install to generate composer.lock file'
            ));
        }
        
        return $findings;
    }

    /**
     * Review JavaScript library security
     */
    private function reviewJavaScriptLibrarySecurity()
    {
        $findings = array();
        $js_dir = _PS_ROOT_DIR_ . '/js/';
        
        if (!is_dir($js_dir)) {
            return $findings;
        }
        
        // Known vulnerable JavaScript libraries
        $vulnerable_js_libs = array(
            'jquery' => array(
                'versions' => array('< 3.5.0'),
                'vulnerability' => 'XSS vulnerability in jQuery.htmlPrefilter'
            ),
            'bootstrap' => array(
                'versions' => array('< 4.3.1'),
                'vulnerability' => 'XSS vulnerability in tooltip and popover'
            ),
            'moment' => array(
                'versions' => array('< 2.19.3'),
                'vulnerability' => 'Regular expression denial of service'
            )
        );
        
        // Scan JavaScript files for library versions
        $js_files = SecurityAuditUtils::scanDirectory($js_dir, array('js'));
        
        foreach ($js_files as $file) {
            $content = file_get_contents($file);
            
            // Check for library version information
            foreach ($vulnerable_js_libs as $lib_name => $vuln_info) {
                if (preg_match("/version[\"':\s]*[\"']([0-9.]+)[\"']/i", $content, $matches)) {
                    $version = $matches[1];
                    
                    // Simple version comparison (would need more sophisticated logic for production)
                    if (version_compare($version, '3.5.0', '<') && strpos($file, 'jquery') !== false) {
                        $findings[] = new SecurityFinding(array(
                            'title' => "Vulnerable JavaScript Library: $lib_name",
                            'description' => "File $file contains vulnerable $lib_name version $version: {$vuln_info['vulnerability']}",
                            'severity' => SecurityAudit::SEVERITY_MEDIUM,
                            'category' => 'third_party',
                            'affected_files' => array($file),
                            'business_impact' => 'Client-side vulnerabilities, XSS attacks',
                            'remediation_effort' => 'medium',
                            'fix_specification' => "Update $lib_name to latest secure version"
                        ));
                    }
                }
            }
            
            // Check for eval() usage
            if (preg_match('/eval\s*\(/', $content)) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'Dangerous eval() Usage in JavaScript',
                    'description' => "File $file contains eval() which can lead to code injection",
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'input_validation',
                    'affected_files' => array($file),
                    'business_impact' => 'Code injection, XSS attacks',
                    'remediation_effort' => 'high',
                    'fix_specification' => 'Replace eval() with safer alternatives like JSON.parse()'
                ));
            }
        }
        
        return $findings;
    }

    /**
     * Check third-party service integrations
     */
    private function checkThirdPartyServiceIntegrations()
    {
        $findings = array();
        
        // Check for insecure API integrations
        $php_files = SecurityAuditUtils::scanDirectory(_PS_ROOT_DIR_, array('php'));
        
        foreach ($php_files as $file) {
            // Skip large files to avoid memory issues
            if (filesize($file) > 1048576) { // 1MB
                continue;
            }
            
            $content = file_get_contents($file);
            
            // Check for insecure HTTP API calls
            if (preg_match('/curl_setopt.*CURLOPT_SSL_VERIFYPEER.*false/i', $content)) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'Insecure SSL Configuration',
                    'description' => "File $file disables SSL certificate verification",
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'configuration',
                    'affected_files' => array($file),
                    'business_impact' => 'Man-in-the-middle attacks, data interception',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Enable SSL certificate verification for all API calls'
                ));
            }
            
            // Check for API keys in code
            if (preg_match('/api[_-]?key[\'\":\s]*[\'\"]\w{20,}[\'\"]/i', $content)) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'Hardcoded API Key',
                    'description' => "File $file contains hardcoded API key",
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => 'configuration',
                    'affected_files' => array($file),
                    'business_impact' => 'API key exposure, unauthorized service access',
                    'remediation_effort' => 'medium',
                    'fix_specification' => 'Move API keys to environment variables or secure configuration'
                ));
            }
            
            // Check for insecure HTTP requests
            if (preg_match('/http:\/\/[^\/\s]+\/api/', $content)) {
                $findings[] = new SecurityFinding(array(
                    'title' => 'Insecure HTTP API Call',
                    'description' => "File $file makes API calls over insecure HTTP",
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'configuration',
                    'affected_files' => array($file),
                    'business_impact' => 'Data interception, man-in-the-middle attacks',
                    'remediation_effort' => 'low',
                    'fix_specification' => 'Use HTTPS for all API communications'
                ));
            }
        }
        
        return $findings;
    }

    /**
     * Generate module authentication description
     */
    private function generateModuleAuthDescription($file, $issue_type)
    {
        $descriptions = array(
            'missing_auth_check' => "Module admin controller lacks proper authentication verification",
            'weak_session' => "Module uses direct session manipulation instead of PrestaShop's secure session handling",
            'missing_csrf' => "Module forms lack CSRF token protection"
        );
        
        $description = "<p><strong>File:</strong> " . htmlspecialchars($file) . "</p>";
        $description .= "<p><strong>Issue:</strong> " . $descriptions[$issue_type] . "</p>";
        
        return $description;
    }

    /**
     * Generate module input validation description
     */
    private function generateModuleInputDescription($file, $issue, $line, $code)
    {
        $description = "<p><strong>File:</strong> " . htmlspecialchars($file) . "</p>";
        if ($line > 0) {
            $description .= "<p><strong>Line:</strong> $line</p>";
        }
        if (!empty($code)) {
            $description .= "<p><strong>Code:</strong></p><pre>" . htmlspecialchars($code) . "</pre>";
        }
        $description .= "<p><strong>Issue:</strong> " . htmlspecialchars($issue) . "</p>";
        
        return $description;
    }

    /**
     * Generate module configuration description
     */
    private function generateModuleConfigDescription($file, $issue, $line)
    {
        $description = "<p><strong>File:</strong> " . htmlspecialchars($file) . "</p>";
        $description .= "<p><strong>Line:</strong> $line</p>";
        $description .= "<p><strong>Issue:</strong> " . htmlspecialchars($issue) . "</p>";
        
        return $description;
    }

    /**
     * Create security finding from SecurityFinding object
     */
    private function createSecurityFindingFromObject($finding)
    {
        SecurityFinding::createFinding($this->audit_id, [
            'title' => $finding->title,
            'description' => $finding->description,
            'severity' => $finding->severity,
            'category' => $finding->category,
            'affected_files' => $finding->affected_files,
            'business_impact' => $finding->business_impact,
            'remediation_effort' => $finding->remediation_effort,
            'fix_specification' => $finding->fix_specification,
            'code_examples' => isset($finding->code_examples) ? $finding->code_examples : '',
            'references' => isset($finding->references) ? $finding->references : []
        ]);
    }
}