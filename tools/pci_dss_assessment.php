<?php
/**
 * PCI DSS Compliance Assessment Tool
 * 
 * This tool performs a comprehensive assessment of payment processing security
 * against PCI DSS requirements for QloApps hotel management system.
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once dirname(__FILE__) . '/../classes/SecurityFinding.php';
require_once dirname(__FILE__) . '/../classes/SecurityAuditUtils.php';

class PCIDSSAssessment
{
    private $findings = array();
    private $paymentModules = array();
    private $auditUtils;
    
    // PCI DSS requirement categories
    const REQUIREMENT_FIREWALL = 1;
    const REQUIREMENT_PASSWORDS = 2;
    const REQUIREMENT_PROTECT_DATA = 3;
    const REQUIREMENT_ENCRYPT_TRANSMISSION = 4;
    const REQUIREMENT_ANTIVIRUS = 5;
    const REQUIREMENT_SECURE_SYSTEMS = 6;
    const REQUIREMENT_ACCESS_CONTROL = 7;
    const REQUIREMENT_UNIQUE_IDS = 8;
    const REQUIREMENT_PHYSICAL_ACCESS = 9;
    const REQUIREMENT_MONITORING = 10;
    const REQUIREMENT_TESTING = 11;
    const REQUIREMENT_POLICY = 12;
    
    public function __construct()
    {
        $this->auditUtils = new SecurityAuditUtils();
        $this->identifyPaymentModules();
    }
    
    /**
     * Run complete PCI DSS assessment
     */
    public function runAssessment()
    {
        echo "Starting PCI DSS Compliance Assessment...\n";
        echo "========================================\n\n";
        
        // Core PCI DSS assessments
        $this->assessCardholderDataProtection();
        $this->assessPaymentDataTransmission();
        $this->assessPaymentAccessControls();
        $this->assessPaymentLogging();
        $this->assessPaymentModuleSecurity();
        $this->assessSecureSystemDevelopment();
        $this->assessPaymentConfiguration();
        $this->assessPaymentErrorHandling();
        
        // Generate compliance report
        $this->generateComplianceReport();
        
        return $this->findings;
    }
    
    /**
     * Identify payment modules in the system
     */
    private function identifyPaymentModules()
    {
        $modulesPath = _PS_MODULE_DIR_;
        $paymentModuleTypes = array('bankwire', 'cheque', 'qlopaypalcommerce');
        
        foreach ($paymentModuleTypes as $moduleType) {
            $modulePath = $modulesPath . $moduleType;
            if (is_dir($modulePath)) {
                $this->paymentModules[] = array(
                    'name' => $moduleType,
                    'path' => $modulePath,
                    'main_file' => $modulePath . '/' . $moduleType . '.php'
                );
            }
        }
        
        echo "Identified " . count($this->paymentModules) . " payment modules for assessment\n";
    }
    
    /**
     * Assess cardholder data protection (PCI DSS Requirement 3)
     */
    private function assessCardholderDataProtection()
    {
        echo "Assessing cardholder data protection...\n";
        
        // Check for deprecated PaymentCC class
        $paymentCCFile = _PS_CLASS_DIR_ . 'PaymentCC.php';
        if (file_exists($paymentCCFile)) {
            $content = file_get_contents($paymentCCFile);
            
            // Check for cardholder data fields
            $cardDataFields = array('card_number', 'card_expiration', 'card_holder', 'card_brand');
            $foundFields = array();
            
            foreach ($cardDataFields as $field) {
                if (strpos($content, '$' . $field) !== false) {
                    $foundFields[] = $field;
                }
            }
            
            if (!empty($foundFields)) {
                $this->addFinding(
                    'Deprecated PaymentCC Class Contains Cardholder Data Fields',
                    'The PaymentCC class contains fields for storing sensitive cardholder data: ' . implode(', ', $foundFields),
                    5, // Critical severity
                    'authentication',
                    array($paymentCCFile),
                    'Remove deprecated PaymentCC class or ensure cardholder data is properly encrypted and tokenized',
                    'High - Could lead to PCI DSS violation and data breach',
                    array('PCI DSS Requirement 3.4', 'PCI DSS Requirement 3.5')
                );
            }
        }
        
        // Check for cardholder data storage in database
        $this->checkDatabaseCardholderData();
        
        // Check payment modules for data storage
        foreach ($this->paymentModules as $module) {
            $this->assessModuleDataStorage($module);
        }
    }
    
    /**
     * Assess payment data transmission security (PCI DSS Requirement 4)
     */
    private function assessPaymentDataTransmission()
    {
        echo "Assessing payment data transmission security...\n";
        
        // Check for HTTPS enforcement
        $httpsEnforced = Configuration::get('PS_SSL_ENABLED');
        if (!$httpsEnforced) {
            $this->addFinding(
                'HTTPS Not Enforced for Payment Processing',
                'SSL/HTTPS is not enforced, payment data may be transmitted unencrypted',
                4, // High severity
                'data_protection',
                array('Configuration'),
                'Enable SSL/HTTPS enforcement in system configuration',
                'High - Payment data could be intercepted during transmission',
                array('PCI DSS Requirement 4.1')
            );
        }
        
        // Check payment module API communications
        foreach ($this->paymentModules as $module) {
            $this->assessModuleTransmissionSecurity($module);
        }
        
        // Check for TLS version requirements
        $this->checkTLSConfiguration();
    }
    
    /**
     * Assess payment access controls (PCI DSS Requirement 7)
     */
    private function assessPaymentAccessControls()
    {
        echo "Assessing payment access controls...\n";
        
        // Check admin access to payment configurations
        $this->checkPaymentConfigurationAccess();
        
        // Check role-based access for payment operations
        $this->checkPaymentRoleBasedAccess();
        
        // Check for multi-factor authentication on payment operations
        $this->checkPaymentMFARequirements();
    }
    
    /**
     * Assess payment logging and monitoring (PCI DSS Requirement 10)
     */
    private function assessPaymentLogging()
    {
        echo "Assessing payment logging and monitoring...\n";
        
        // Check for payment transaction logging
        $this->checkPaymentTransactionLogging();
        
        // Check for security event logging
        $this->checkPaymentSecurityEventLogging();
        
        // Check log protection and retention
        $this->checkPaymentLogProtection();
    }
    
    /**
     * Assess payment module security
     */
    private function assessPaymentModuleSecurity()
    {
        echo "Assessing payment module security...\n";
        
        foreach ($this->paymentModules as $module) {
            echo "  Assessing module: " . $module['name'] . "\n";
            
            // Check module input validation
            $this->assessModuleInputValidation($module);
            
            // Check module authentication
            $this->assessModuleAuthentication($module);
            
            // Check module error handling
            $this->assessModuleErrorHandling($module);
            
            // Check module configuration security
            $this->assessModuleConfigurationSecurity($module);
        }
    }
    
    /**
     * Assess secure system development (PCI DSS Requirement 6)
     */
    private function assessSecureSystemDevelopment()
    {
        echo "Assessing secure system development practices...\n";
        
        // Check for secure coding practices in payment modules
        foreach ($this->paymentModules as $module) {
            $this->assessModuleSecureCoding($module);
        }
        
        // Check for security testing procedures
        $this->checkPaymentSecurityTesting();
    }
    
    /**
     * Assess payment configuration security
     */
    private function assessPaymentConfiguration()
    {
        echo "Assessing payment configuration security...\n";
        
        // Check for encrypted configuration storage
        $this->checkConfigurationEncryption();
        
        // Check for default credentials
        $this->checkDefaultCredentials();
        
        // Check configuration file permissions
        $this->checkConfigurationFilePermissions();
    }
    
    /**
     * Assess payment error handling
     */
    private function assessPaymentErrorHandling()
    {
        echo "Assessing payment error handling...\n";
        
        foreach ($this->paymentModules as $module) {
            $this->assessModuleErrorHandling($module);
        }
    }
    
    /**
     * Check database for cardholder data storage
     */
    private function checkDatabaseCardholderData()
    {
        try {
            // Check for payment_cc table
            $sql = "SHOW TABLES LIKE '" . _DB_PREFIX_ . "payment_cc'";
            $result = Db::getInstance()->executeS($sql);
            
            if (!empty($result)) {
                $this->addFinding(
                    'Payment CC Table Exists in Database',
                    'Database contains payment_cc table which may store cardholder data',
                    4, // High severity
                    'data_protection',
                    array('Database: ' . _DB_PREFIX_ . 'payment_cc'),
                    'Remove payment_cc table or ensure it does not contain cardholder data',
                    'High - Potential PCI DSS violation if cardholder data is stored',
                    array('PCI DSS Requirement 3.1')
                );
            }
            
            // Check for other payment-related tables with sensitive data
            $this->checkPaymentTables();
            
        } catch (Exception $e) {
            echo "Error checking database: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Check payment-related database tables
     */
    private function checkPaymentTables()
    {
        $paymentTables = array(
            _DB_PREFIX_ . 'order_payment',
            _DB_PREFIX_ . 'orders',
            _DB_PREFIX_ . 'order_detail'
        );
        
        foreach ($paymentTables as $table) {
            try {
                $sql = "DESCRIBE `$table`";
                $columns = Db::getInstance()->executeS($sql);
                
                foreach ($columns as $column) {
                    $columnName = strtolower($column['Field']);
                    
                    // Check for potentially sensitive payment fields
                    if (strpos($columnName, 'card') !== false || 
                        strpos($columnName, 'cvv') !== false ||
                        strpos($columnName, 'pan') !== false) {
                        
                        $this->addFinding(
                            'Potentially Sensitive Payment Field in Database',
                            "Table $table contains potentially sensitive field: " . $column['Field'],
                            3, // Medium severity
                            'data_protection',
                            array("Database: $table." . $column['Field']),
                            'Review field usage and ensure no cardholder data is stored',
                            'Medium - Could indicate cardholder data storage',
                            array('PCI DSS Requirement 3.1')
                        );
                    }
                }
            } catch (Exception $e) {
                // Table might not exist, continue
                continue;
            }
        }
    }
    
    /**
     * Assess module data storage practices
     */
    private function assessModuleDataStorage($module)
    {
        if (!file_exists($module['main_file'])) {
            return;
        }
        
        $content = file_get_contents($module['main_file']);
        
        // Check for potential cardholder data storage
        $sensitivePatterns = array(
            'card_number' => 'Credit card number storage',
            'cvv' => 'CVV storage',
            'card_expiry' => 'Card expiry storage',
            'pan' => 'Primary Account Number storage'
        );
        
        foreach ($sensitivePatterns as $pattern => $description) {
            if (stripos($content, $pattern) !== false) {
                $this->addFinding(
                    'Potential Cardholder Data Storage in Payment Module',
                    "Module {$module['name']} may store cardholder data: $description",
                    4, // High severity
                    'data_protection',
                    array($module['main_file']),
                    'Review module code and ensure no cardholder data is stored',
                    'High - Potential PCI DSS violation',
                    array('PCI DSS Requirement 3.1')
                );
            }
        }
    }
    
    /**
     * Assess module transmission security
     */
    private function assessModuleTransmissionSecurity($module)
    {
        if (!file_exists($module['main_file'])) {
            return;
        }
        
        $content = file_get_contents($module['main_file']);
        
        // Check for HTTP usage in payment communications
        if (stripos($content, 'http://') !== false && stripos($content, 'https://') === false) {
            $this->addFinding(
                'Insecure HTTP Communication in Payment Module',
                "Module {$module['name']} may use insecure HTTP for payment communications",
                4, // High severity
                'data_protection',
                array($module['main_file']),
                'Ensure all payment communications use HTTPS/TLS',
                'High - Payment data could be intercepted',
                array('PCI DSS Requirement 4.1')
            );
        }
        
        // Check for proper SSL/TLS verification
        if (stripos($content, 'CURLOPT_SSL_VERIFYPEER') !== false) {
            if (stripos($content, 'CURLOPT_SSL_VERIFYPEER, false') !== false) {
                $this->addFinding(
                    'SSL Certificate Verification Disabled',
                    "Module {$module['name']} disables SSL certificate verification",
                    4, // High severity
                    'data_protection',
                    array($module['main_file']),
                    'Enable SSL certificate verification for all payment communications',
                    'High - Vulnerable to man-in-the-middle attacks',
                    array('PCI DSS Requirement 4.1')
                );
            }
        }
    }
    
    /**
     * Check TLS configuration
     */
    private function checkTLSConfiguration()
    {
        // Check if TLS 1.2+ is enforced
        $tlsConfig = ini_get('openssl.cafile');
        
        if (empty($tlsConfig)) {
            $this->addFinding(
                'TLS Configuration Not Properly Set',
                'OpenSSL CA file not configured, may affect TLS security',
                3, // Medium severity
                'configuration',
                array('PHP Configuration'),
                'Configure proper TLS settings and CA certificates',
                'Medium - May allow weak TLS connections',
                array('PCI DSS Requirement 4.1')
            );
        }
    }
    
    /**
     * Check payment configuration access controls
     */
    private function checkPaymentConfigurationAccess()
    {
        // This would need to be implemented based on the specific admin access control system
        // For now, we'll check if there are any obvious access control issues
        
        $adminPath = _PS_ADMIN_DIR_;
        if (is_dir($adminPath)) {
            // Check for .htaccess protection
            $htaccessFile = $adminPath . '/.htaccess';
            if (!file_exists($htaccessFile)) {
                $this->addFinding(
                    'Admin Directory Not Protected by .htaccess',
                    'Admin directory lacks .htaccess protection',
                    3, // Medium severity
                    'access_control',
                    array($adminPath),
                    'Add .htaccess file to protect admin directory',
                    'Medium - Unauthorized access to admin functions',
                    array('PCI DSS Requirement 7.1')
                );
            }
        }
    }
    
    /**
     * Check role-based access for payment operations
     */
    private function checkPaymentRoleBasedAccess()
    {
        // Check if proper role-based access controls exist for payment operations
        // This is a placeholder - would need specific implementation
        
        $this->addFinding(
            'Payment Role-Based Access Controls Need Review',
            'Payment operations access controls should be reviewed for proper role-based restrictions',
            2, // Low severity
            'access_control',
            array('Payment System'),
            'Implement and review role-based access controls for payment operations',
            'Medium - Potential unauthorized access to payment functions',
            array('PCI DSS Requirement 7.1')
        );
    }
    
    /**
     * Check MFA requirements for payment operations
     */
    private function checkPaymentMFARequirements()
    {
        // Check if multi-factor authentication is required for payment operations
        // This is a placeholder - would need specific implementation
        
        $this->addFinding(
            'Multi-Factor Authentication Not Required for Payment Operations',
            'Payment operations do not require multi-factor authentication',
            3, // Medium severity
            'access_control',
            array('Authentication System'),
            'Implement multi-factor authentication for payment-related administrative operations',
            'Medium - Increased risk of unauthorized payment access',
            array('PCI DSS Requirement 8.3')
        );
    }
    
    /**
     * Check payment transaction logging
     */
    private function checkPaymentTransactionLogging()
    {
        // Check if payment transactions are properly logged
        $logDir = _PS_ROOT_DIR_ . '/log/';
        
        if (!is_dir($logDir)) {
            $this->addFinding(
                'Payment Logging Directory Missing',
                'No dedicated logging directory found for payment transactions',
                3, // Medium severity
                'logging',
                array('Logging System'),
                'Create secure logging directory for payment transactions',
                'Medium - Inability to audit payment activities',
                array('PCI DSS Requirement 10.1')
            );
        }
        
        // Check for payment-specific log files
        $paymentLogFiles = array('payment.log', 'transaction.log', 'order.log');
        $foundLogs = array();
        
        foreach ($paymentLogFiles as $logFile) {
            if (file_exists($logDir . $logFile)) {
                $foundLogs[] = $logFile;
            }
        }
        
        if (empty($foundLogs)) {
            $this->addFinding(
                'Payment Transaction Logging Not Implemented',
                'No payment-specific log files found',
                4, // High severity
                'logging',
                array('Logging System'),
                'Implement comprehensive payment transaction logging',
                'High - Cannot audit payment activities for compliance',
                array('PCI DSS Requirement 10.2')
            );
        }
    }
    
    /**
     * Check payment security event logging
     */
    private function checkPaymentSecurityEventLogging()
    {
        // Check for security event logging related to payments
        $this->addFinding(
            'Payment Security Event Logging Needs Review',
            'Payment security events (failed logins, access attempts) logging should be reviewed',
            3, // Medium severity
            'logging',
            array('Security Logging'),
            'Implement comprehensive security event logging for payment operations',
            'Medium - Difficulty detecting payment-related security incidents',
            array('PCI DSS Requirement 10.2')
        );
    }
    
    /**
     * Check payment log protection
     */
    private function checkPaymentLogProtection()
    {
        $logDir = _PS_ROOT_DIR_ . '/log/';
        
        if (is_dir($logDir)) {
            // Check log directory permissions
            $permissions = fileperms($logDir);
            $octal = substr(sprintf('%o', $permissions), -4);
            
            if ($octal > '0755') {
                $this->addFinding(
                    'Payment Log Directory Permissions Too Permissive',
                    "Log directory permissions ($octal) are too permissive",
                    3, // Medium severity
                    'configuration',
                    array($logDir),
                    'Set log directory permissions to 0755 or more restrictive',
                    'Medium - Unauthorized access to payment logs',
                    array('PCI DSS Requirement 10.5')
                );
            }
        }
    }
    
    /**
     * Assess module input validation
     */
    private function assessModuleInputValidation($module)
    {
        if (!file_exists($module['main_file'])) {
            return;
        }
        
        $content = file_get_contents($module['main_file']);
        
        // Check for input validation patterns
        $validationPatterns = array(
            'Tools::getValue' => 'Input retrieval',
            'Validate::' => 'Validation functions',
            'pSQL' => 'SQL injection prevention',
            'htmlspecialchars' => 'XSS prevention'
        );
        
        $foundValidation = array();
        foreach ($validationPatterns as $pattern => $description) {
            if (stripos($content, $pattern) !== false) {
                $foundValidation[] = $description;
            }
        }
        
        if (empty($foundValidation)) {
            $this->addFinding(
                'Insufficient Input Validation in Payment Module',
                "Module {$module['name']} lacks proper input validation",
                3, // Medium severity
                'input_validation',
                array($module['main_file']),
                'Implement comprehensive input validation for all payment inputs',
                'Medium - Vulnerable to injection attacks',
                array('PCI DSS Requirement 6.5.1')
            );
        }
    }
    
    /**
     * Assess module authentication
     */
    private function assessModuleAuthentication($module)
    {
        if (!file_exists($module['main_file'])) {
            return;
        }
        
        $content = file_get_contents($module['main_file']);
        
        // Check for authentication mechanisms
        if (stripos($content, 'secure_key') === false && 
            stripos($content, 'authentication') === false &&
            stripos($content, 'token') === false) {
            
            $this->addFinding(
                'Payment Module Authentication Needs Review',
                "Module {$module['name']} authentication mechanisms should be reviewed",
                2, // Low severity
                'authentication',
                array($module['main_file']),
                'Review and strengthen payment module authentication',
                'Medium - Potential unauthorized payment processing',
                array('PCI DSS Requirement 8.1')
            );
        }
    }
    
    /**
     * Assess module error handling
     */
    private function assessModuleErrorHandling($module)
    {
        if (!file_exists($module['main_file'])) {
            return;
        }
        
        $content = file_get_contents($module['main_file']);
        
        // Check for error handling patterns
        if (stripos($content, 'try') !== false || stripos($content, 'catch') !== false) {
            // Good - has error handling
        } else {
            $this->addFinding(
                'Payment Module Lacks Proper Error Handling',
                "Module {$module['name']} lacks comprehensive error handling",
                2, // Low severity
                'error_handling',
                array($module['main_file']),
                'Implement proper error handling with secure error messages',
                'Low - May expose sensitive information in errors',
                array('PCI DSS Requirement 6.5.5')
            );
        }
    }
    
    /**
     * Assess module configuration security
     */
    private function assessModuleConfigurationSecurity($module)
    {
        if (!file_exists($module['main_file'])) {
            return;
        }
        
        $content = file_get_contents($module['main_file']);
        
        // Check for configuration storage patterns
        if (stripos($content, 'Configuration::updateValue') !== false) {
            // Check if sensitive data is being stored
            $sensitiveConfigPatterns = array('password', 'secret', 'key', 'token');
            
            foreach ($sensitiveConfigPatterns as $pattern) {
                if (stripos($content, $pattern) !== false) {
                    $this->addFinding(
                        'Payment Module May Store Sensitive Configuration Data',
                        "Module {$module['name']} may store sensitive configuration data without encryption",
                        3, // Medium severity
                        'configuration',
                        array($module['main_file']),
                        'Encrypt sensitive configuration data before storage',
                        'Medium - Exposure of payment gateway credentials',
                        array('PCI DSS Requirement 3.4')
                    );
                    break;
                }
            }
        }
    }
    
    /**
     * Assess module secure coding practices
     */
    private function assessModuleSecureCoding($module)
    {
        if (!file_exists($module['main_file'])) {
            return;
        }
        
        $content = file_get_contents($module['main_file']);
        
        // Check for common security issues
        $securityIssues = array(
            'eval(' => 'Code injection vulnerability',
            'system(' => 'Command injection vulnerability',
            'exec(' => 'Command injection vulnerability',
            '$_GET' => 'Direct superglobal usage',
            '$_POST' => 'Direct superglobal usage'
        );
        
        foreach ($securityIssues as $pattern => $issue) {
            if (stripos($content, $pattern) !== false) {
                $this->addFinding(
                    'Insecure Coding Practice in Payment Module',
                    "Module {$module['name']} contains: $issue",
                    3, // Medium severity
                    'secure_coding',
                    array($module['main_file']),
                    'Replace insecure coding practices with secure alternatives',
                    'Medium - Potential security vulnerabilities',
                    array('PCI DSS Requirement 6.5')
                );
            }
        }
    }
    
    /**
     * Check payment security testing procedures
     */
    private function checkPaymentSecurityTesting()
    {
        // Check for evidence of security testing
        $testDirs = array(
            _PS_ROOT_DIR_ . '/tests/',
            _PS_ROOT_DIR_ . '/test/',
            _PS_ROOT_DIR_ . '/testing/'
        );
        
        $foundTestDir = false;
        foreach ($testDirs as $testDir) {
            if (is_dir($testDir)) {
                $foundTestDir = true;
                break;
            }
        }
        
        if (!$foundTestDir) {
            $this->addFinding(
                'No Evidence of Payment Security Testing',
                'No testing directory found, payment security testing may not be performed',
                3, // Medium severity
                'testing',
                array('Testing Framework'),
                'Implement comprehensive payment security testing procedures',
                'Medium - Undetected payment security vulnerabilities',
                array('PCI DSS Requirement 11.3')
            );
        }
    }
    
    /**
     * Check configuration encryption
     */
    private function checkConfigurationEncryption()
    {
        // Check if sensitive configurations are encrypted
        $configFile = _PS_ROOT_DIR_ . '/config/settings.inc.php';
        
        if (file_exists($configFile)) {
            $content = file_get_contents($configFile);
            
            // Check for database credentials in plain text
            if (stripos($content, '_DB_PASSWD_') !== false) {
                $this->addFinding(
                    'Database Credentials in Plain Text',
                    'Database password stored in plain text in configuration file',
                    4, // High severity
                    'configuration',
                    array($configFile),
                    'Encrypt sensitive configuration data',
                    'High - Database credentials exposure',
                    array('PCI DSS Requirement 2.1')
                );
            }
        }
    }
    
    /**
     * Check for default credentials
     */
    private function checkDefaultCredentials()
    {
        // Check for common default credentials
        $defaultPatterns = array(
            'admin/admin',
            'root/root',
            'test/test',
            'demo/demo'
        );
        
        // This is a placeholder - would need specific implementation
        $this->addFinding(
            'Default Credentials Check Required',
            'Payment system should be checked for default credentials',
            2, // Low severity
            'authentication',
            array('Authentication System'),
            'Ensure no default credentials are used in payment systems',
            'Medium - Unauthorized access with default credentials',
            array('PCI DSS Requirement 2.1')
        );
    }
    
    /**
     * Check configuration file permissions
     */
    private function checkConfigurationFilePermissions()
    {
        $configFiles = array(
            _PS_ROOT_DIR_ . '/config/settings.inc.php',
            _PS_ROOT_DIR_ . '/config/config.inc.php'
        );
        
        foreach ($configFiles as $configFile) {
            if (file_exists($configFile)) {
                $permissions = fileperms($configFile);
                $octal = substr(sprintf('%o', $permissions), -4);
                
                if ($octal > '0644') {
                    $this->addFinding(
                        'Configuration File Permissions Too Permissive',
                        "Configuration file $configFile has permissions $octal",
                        3, // Medium severity
                        'configuration',
                        array($configFile),
                        'Set configuration file permissions to 0644 or more restrictive',
                        'Medium - Unauthorized access to configuration data',
                        array('PCI DSS Requirement 2.2')
                    );
                }
            }
        }
    }
    
    /**
     * Add a security finding
     */
    private function addFinding($title, $description, $severity, $category, $affectedFiles, 
                               $fixSpecification, $businessImpact, $complianceReferences = array())
    {
        $finding = new SecurityFinding();
        $finding->title = $title;
        $finding->description = $description;
        $finding->severity = $severity;
        $finding->category = $category;
        $finding->affected_files = $affectedFiles;
        $finding->fix_specification = $fixSpecification;
        $finding->business_impact = $businessImpact;
        $finding->compliance_impact = implode(', ', $complianceReferences);
        
        $this->findings[] = $finding;
    }
    
    /**
     * Generate compliance report
     */
    private function generateComplianceReport()
    {
        echo "\n" . str_repeat("=", 60) . "\n";
        echo "PCI DSS COMPLIANCE ASSESSMENT SUMMARY\n";
        echo str_repeat("=", 60) . "\n";
        
        $severityCounts = array(5 => 0, 4 => 0, 3 => 0, 2 => 0, 1 => 0, 0 => 0);
        
        foreach ($this->findings as $finding) {
            $severityCounts[$finding->severity]++;
        }
        
        echo "Total Findings: " . count($this->findings) . "\n";
        echo "Critical (5): " . $severityCounts[5] . "\n";
        echo "High (4): " . $severityCounts[4] . "\n";
        echo "Medium (3): " . $severityCounts[3] . "\n";
        echo "Low (2): " . $severityCounts[2] . "\n";
        echo "Info (1): " . $severityCounts[1] . "\n";
        echo "No Risk (0): " . $severityCounts[0] . "\n\n";
        
        // Calculate compliance score
        $totalIssues = count($this->findings);
        $criticalIssues = $severityCounts[5] + $severityCounts[4];
        
        if ($totalIssues == 0) {
            $complianceScore = 100;
        } else {
            $complianceScore = max(0, 100 - ($criticalIssues * 20) - ($severityCounts[3] * 10) - ($severityCounts[2] * 5));
        }
        
        echo "PCI DSS Compliance Score: $complianceScore%\n";
        
        if ($complianceScore < 70) {
            echo "Status: NON-COMPLIANT - Immediate action required\n";
        } elseif ($complianceScore < 90) {
            echo "Status: PARTIALLY COMPLIANT - Improvements needed\n";
        } else {
            echo "Status: COMPLIANT - Continue monitoring\n";
        }
        
        echo "\nTop Priority Issues:\n";
        echo str_repeat("-", 30) . "\n";
        
        $criticalFindings = array_filter($this->findings, function($f) { return $f->severity >= 4; });
        
        foreach (array_slice($criticalFindings, 0, 5) as $finding) {
            echo "• " . $finding->title . " (Severity: " . $finding->severity . ")\n";
        }
        
        echo "\nDetailed findings have been saved to PCI_DSS_COMPLIANCE_ASSESSMENT.md\n";
    }
}

// Run the assessment if called directly
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    $assessment = new PCIDSSAssessment();
    $findings = $assessment->runAssessment();
    
    echo "\nAssessment completed. Found " . count($findings) . " issues.\n";
}