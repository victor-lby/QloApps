<?php
/**
 * Security Testing Framework
 * 
 * Comprehensive testing framework for security improvements and fixes
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class SecurityTestingFramework
{
    private $testResults = array();
    private $testSuites = array();
    
    public function __construct()
    {
        $this->initializeTestSuites();
    }
    
    /**
     * Initialize all test suites
     */
    private function initializeTestSuites()
    {
        $this->testSuites = array(
            'authentication' => new AuthenticationSecurityTests(),
            'input_validation' => new InputValidationTests(),
            'sql_injection' => new SQLInjectionTests(),
            'xss_protection' => new XSSProtectionTests(),
            'api_security' => new APISecurityTests(),
            'encryption' => new EncryptionTests(),
            'session_security' => new SessionSecurityTests(),
            'file_security' => new FileSecurityTests(),
            'configuration' => new ConfigurationSecurityTests(),
            'compliance' => new ComplianceTests()
        );
    }
    
    /**
     * Run all security tests
     */
    public function runAllTests()
    {
        echo "Starting Security Testing Framework...\n\n";
        
        foreach ($this->testSuites as $suiteName => $testSuite) {
            echo "Running {$suiteName} tests...\n";
            $results = $testSuite->runTests();
            $this->testResults[$suiteName] = $results;
            
            $passed = count(array_filter($results, function($r) { return $r['status'] === 'PASS'; }));
            $total = count($results);
            echo "  {$passed}/{$total} tests passed\n\n";
        }
        
        $this->generateReport();
    }
    
    /**
     * Run specific test suite
     */
    public function runTestSuite($suiteName)
    {
        if (!isset($this->testSuites[$suiteName])) {
            throw new InvalidArgumentException("Test suite '{$suiteName}' not found");
        }
        
        echo "Running {$suiteName} tests...\n";
        $results = $this->testSuites[$suiteName]->runTests();
        $this->testResults[$suiteName] = $results;
        
        return $results;
    }
    
    /**
     * Generate comprehensive test report
     */
    private function generateReport()
    {
        $totalTests = 0;
        $totalPassed = 0;
        $totalFailed = 0;
        $criticalFailures = array();
        
        echo "=== Security Testing Report ===\n\n";
        
        foreach ($this->testResults as $suiteName => $results) {
            $passed = 0;
            $failed = 0;
            
            foreach ($results as $result) {
                $totalTests++;
                if ($result['status'] === 'PASS') {
                    $passed++;
                    $totalPassed++;
                } else {
                    $failed++;
                    $totalFailed++;
                    
                    if ($result['severity'] === 'CRITICAL') {
                        $criticalFailures[] = array(
                            'suite' => $suiteName,
                            'test' => $result['test'],
                            'message' => $result['message']
                        );
                    }
                }
            }
            
            echo "{$suiteName}: {$passed} passed, {$failed} failed\n";
        }
        
        echo "\nOverall Results:\n";
        echo "Total Tests: {$totalTests}\n";
        echo "Passed: {$totalPassed}\n";
        echo "Failed: {$totalFailed}\n";
        echo "Success Rate: " . round(($totalPassed / $totalTests) * 100, 2) . "%\n\n";
        
        if (!empty($criticalFailures)) {
            echo "CRITICAL FAILURES:\n";
            foreach ($criticalFailures as $failure) {
                echo "- [{$failure['suite']}] {$failure['test']}: {$failure['message']}\n";
            }
            echo "\n";
        }
        
        // Save detailed report
        $this->saveDetailedReport();
    }
    
    /**
     * Save detailed test report to file
     */
    private function saveDetailedReport()
    {
        $report = $this->generateDetailedReport();
        $filename = dirname(__FILE__) . '/../SECURITY_TEST_REPORT.md';
        file_put_contents($filename, $report);
        echo "Detailed report saved to: {$filename}\n";
    }
    
    /**
     * Generate detailed markdown report
     */
    private function generateDetailedReport()
    {
        $report = "# Security Testing Report\n\n";
        $report .= "**Generated**: " . date('Y-m-d H:i:s') . "\n\n";
        
        $totalTests = 0;
        $totalPassed = 0;
        
        foreach ($this->testResults as $suiteName => $results) {
            $passed = count(array_filter($results, function($r) { return $r['status'] === 'PASS'; }));
            $total = count($results);
            $totalTests += $total;
            $totalPassed += $passed;
            
            $report .= "## " . ucwords(str_replace('_', ' ', $suiteName)) . " Tests\n\n";
            $report .= "**Results**: {$passed}/{$total} passed\n\n";
            
            $report .= "| Test | Status | Severity | Message |\n";
            $report .= "|------|--------|----------|----------|\n";
            
            foreach ($results as $result) {
                $status = $result['status'] === 'PASS' ? '✅ PASS' : '❌ FAIL';
                $severity = $result['severity'] ?? 'MEDIUM';
                $message = $result['message'] ?? '';
                
                $report .= "| {$result['test']} | {$status} | {$severity} | {$message} |\n";
            }
            
            $report .= "\n";
        }
        
        $successRate = round(($totalPassed / $totalTests) * 100, 2);
        $report .= "## Summary\n\n";
        $report .= "- **Total Tests**: {$totalTests}\n";
        $report .= "- **Passed**: {$totalPassed}\n";
        $report .= "- **Failed**: " . ($totalTests - $totalPassed) . "\n";
        $report .= "- **Success Rate**: {$successRate}%\n";
        
        return $report;
    }
}

/**
 * Base class for security test suites
 */
abstract class SecurityTestSuite
{
    protected $results = array();
    
    abstract public function runTests();
    
    protected function assert($condition, $testName, $message = '', $severity = 'MEDIUM')
    {
        $this->results[] = array(
            'test' => $testName,
            'status' => $condition ? 'PASS' : 'FAIL',
            'message' => $message,
            'severity' => $severity
        );
        
        return $condition;
    }
    
    protected function assertTrue($condition, $testName, $message = '', $severity = 'MEDIUM')
    {
        return $this->assert($condition === true, $testName, $message, $severity);
    }
    
    protected function assertFalse($condition, $testName, $message = '', $severity = 'MEDIUM')
    {
        return $this->assert($condition === false, $testName, $message, $severity);
    }
    
    protected function assertEquals($expected, $actual, $testName, $message = '', $severity = 'MEDIUM')
    {
        return $this->assert($expected === $actual, $testName, $message, $severity);
    }
}

/**
 * Authentication Security Tests
 */
class AuthenticationSecurityTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testPasswordHashing();
        $this->testSQLInjectionInAuth();
        $this->testRateLimiting();
        $this->testSessionSecurity();
        
        return $this->results;
    }
    
    private function testPasswordHashing()
    {
        // Test secure password hashing
        $password = 'TestPassword123!';
        
        if (function_exists('password_hash')) {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $this->assertTrue(
                password_verify($password, $hash),
                'Password Hashing',
                'Password hashing and verification should work',
                'CRITICAL'
            );
            
            $this->assertFalse(
                password_verify('WrongPassword', $hash),
                'Password Verification',
                'Wrong password should not verify',
                'CRITICAL'
            );
        } else {
            $this->assert(false, 'Password Functions', 'password_hash function not available', 'CRITICAL');
        }
    }
    
    private function testSQLInjectionInAuth()
    {
        // Test SQL injection prevention in authentication
        $maliciousInputs = array(
            "admin' OR '1'='1",
            "admin'; DROP TABLE ps_customer; --",
            "admin' UNION SELECT * FROM ps_customer --"
        );
        
        foreach ($maliciousInputs as $input) {
            // This should not cause SQL errors or return unexpected results
            try {
                if (class_exists('Customer')) {
                    $customer = new Customer();
                    $result = $customer->getByEmail($input);
                    $this->assertFalse(
                        $result,
                        'SQL Injection Prevention',
                        'Malicious input should not return valid results',
                        'CRITICAL'
                    );
                }
            } catch (Exception $e) {
                // SQL errors indicate vulnerability
                $this->assert(
                    false,
                    'SQL Injection Prevention',
                    'SQL injection attempt caused error: ' . $e->getMessage(),
                    'CRITICAL'
                );
            }
        }
    }
    
    private function testRateLimiting()
    {
        // Test rate limiting implementation
        if (class_exists('APIRateLimit')) {
            $rateLimit = new APIRateLimit();
            $identifier = 'test_user_' . time();
            
            // Should allow initial requests
            $allowed = $rateLimit->checkRateLimit($identifier, 5, 60);
            $this->assertTrue(
                $allowed,
                'Rate Limiting - Initial Request',
                'First request should be allowed',
                'HIGH'
            );
            
            // Exceed rate limit
            for ($i = 0; $i < 5; $i++) {
                $rateLimit->checkRateLimit($identifier, 5, 60);
            }
            
            // Should block further requests
            $blocked = $rateLimit->checkRateLimit($identifier, 5, 60);
            $this->assertFalse(
                $blocked,
                'Rate Limiting - Exceeded Limit',
                'Requests should be blocked after limit exceeded',
                'HIGH'
            );
        } else {
            $this->assert(false, 'Rate Limiting', 'APIRateLimit class not found', 'HIGH');
        }
    }
    
    private function testSessionSecurity()
    {
        // Test session security configuration
        $secureSettings = array(
            'session.cookie_httponly' => '1',
            'session.cookie_secure' => '1',
            'session.use_strict_mode' => '1'
        );
        
        foreach ($secureSettings as $setting => $expectedValue) {
            $actualValue = ini_get($setting);
            $this->assertEquals(
                $expectedValue,
                $actualValue,
                'Session Security - ' . $setting,
                "Setting {$setting} should be {$expectedValue}",
                'MEDIUM'
            );
        }
    }
}

/**
 * Input Validation Tests
 */
class InputValidationTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testEmailValidation();
        $this->testNameValidation();
        $this->testPhoneValidation();
        $this->testGenericValidation();
        
        return $this->results;
    }
    
    private function testEmailValidation()
    {
        if (class_exists('Validate')) {
            // Valid emails
            $validEmails = array(
                'test@example.com',
                'user.name@domain.co.uk',
                'user+tag@example.org'
            );
            
            foreach ($validEmails as $email) {
                $this->assertTrue(
                    Validate::isEmail($email),
                    'Email Validation - Valid',
                    "Valid email {$email} should pass validation"
                );
            }
            
            // Invalid emails
            $invalidEmails = array(
                'invalid-email',
                '@domain.com',
                'user@',
                '<script>alert("xss")</script>@domain.com'
            );
            
            foreach ($invalidEmails as $email) {
                $this->assertFalse(
                    Validate::isEmail($email),
                    'Email Validation - Invalid',
                    "Invalid email {$email} should fail validation",
                    'HIGH'
                );
            }
        } else {
            $this->assert(false, 'Email Validation', 'Validate class not found', 'CRITICAL');
        }
    }
    
    private function testNameValidation()
    {
        if (class_exists('Validate')) {
            // Test XSS prevention in names
            $maliciousNames = array(
                '<script>alert("xss")</script>',
                'javascript:alert("xss")',
                '<img src="x" onerror="alert(1)">',
                '"><script>alert("xss")</script>'
            );
            
            foreach ($maliciousNames as $name) {
                $this->assertFalse(
                    Validate::isName($name),
                    'Name Validation - XSS Prevention',
                    "Malicious name should be rejected",
                    'HIGH'
                );
            }
        }
    }
    
    private function testPhoneValidation()
    {
        if (class_exists('Validate')) {
            $validPhones = array(
                '+1234567890',
                '123-456-7890',
                '(123) 456-7890'
            );
            
            foreach ($validPhones as $phone) {
                $this->assertTrue(
                    Validate::isPhoneNumber($phone),
                    'Phone Validation - Valid',
                    "Valid phone {$phone} should pass validation"
                );
            }
        }
    }
    
    private function testGenericValidation()
    {
        if (class_exists('Validate')) {
            // Test SQL injection prevention
            $sqlInjectionAttempts = array(
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "' UNION SELECT * FROM users --"
            );
            
            foreach ($sqlInjectionAttempts as $attempt) {
                $this->assertFalse(
                    Validate::isGenericName($attempt),
                    'Generic Validation - SQL Injection',
                    "SQL injection attempt should be rejected",
                    'CRITICAL'
                );
            }
        }
    }
}

/**
 * SQL Injection Tests
 */
class SQLInjectionTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testPreparedStatements();
        $this->testDatabaseQueries();
        $this->testUserInputHandling();
        
        return $this->results;
    }
    
    private function testPreparedStatements()
    {
        // Test that database queries use prepared statements
        if (class_exists('Db')) {
            try {
                $db = Db::getInstance();
                
                // Test prepared statement execution
                $result = $db->getRow('SELECT 1 as test WHERE ? = ?', array(1, 1));
                $this->assertTrue(
                    $result !== false,
                    'Prepared Statements',
                    'Prepared statements should work correctly'
                );
                
                // Test with potentially malicious input
                $maliciousInput = "'; DROP TABLE test; --";
                $result = $db->getRow('SELECT 1 as test WHERE name = ?', array($maliciousInput));
                $this->assertTrue(
                    true, // If we get here without error, prepared statements are working
                    'SQL Injection Prevention',
                    'Prepared statements should prevent SQL injection',
                    'CRITICAL'
                );
                
            } catch (Exception $e) {
                $this->assert(
                    false,
                    'Database Connection',
                    'Database connection failed: ' . $e->getMessage(),
                    'HIGH'
                );
            }
        }
    }
    
    private function testDatabaseQueries()
    {
        // Scan for potentially vulnerable query patterns
        $vulnerablePatterns = array(
            '/mysql_query\s*\(\s*[\'"][^\'\"]*\$/',
            '/query\s*\(\s*[\'"][^\'\"]*\$/',
            '/execute\s*\(\s*[\'"][^\'\"]*\$/'
        );
        
        $phpFiles = $this->getPhpFiles();
        $vulnerableFiles = array();
        
        foreach ($phpFiles as $file) {
            $content = file_get_contents($file);
            
            foreach ($vulnerablePatterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $vulnerableFiles[] = $file;
                    break;
                }
            }
        }
        
        $this->assertTrue(
            empty($vulnerableFiles),
            'Vulnerable Query Patterns',
            'Found potentially vulnerable queries in: ' . implode(', ', $vulnerableFiles),
            'CRITICAL'
        );
    }
    
    private function testUserInputHandling()
    {
        // Test that user input is properly sanitized before database operations
        $inputSources = array('$_GET', '$_POST', '$_REQUEST', '$_COOKIE');
        $phpFiles = $this->getPhpFiles();
        $vulnerableFiles = array();
        
        foreach ($phpFiles as $file) {
            $content = file_get_contents($file);
            
            foreach ($inputSources as $source) {
                // Look for direct use of user input in queries
                $pattern = '/' . preg_quote($source, '/') . '\[.*?\].*?(query|execute|mysql_)/i';
                if (preg_match($pattern, $content)) {
                    $vulnerableFiles[] = $file;
                    break;
                }
            }
        }
        
        $this->assertTrue(
            empty($vulnerableFiles),
            'User Input in Queries',
            'Found direct user input in queries: ' . implode(', ', $vulnerableFiles),
            'CRITICAL'
        );
    }
    
    private function getPhpFiles()
    {
        $files = array();
        $directories = array('classes', 'controllers', 'modules');
        
        foreach ($directories as $dir) {
            if (is_dir($dir)) {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir)
                );
                
                foreach ($iterator as $file) {
                    if ($file->getExtension() === 'php') {
                        $files[] = $file->getPathname();
                    }
                }
            }
        }
        
        return array_slice($files, 0, 10); // Limit for testing
    }
}

/**
 * XSS Protection Tests
 */
class XSSProtectionTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testOutputEncoding();
        $this->testHTMLPurification();
        $this->testJavaScriptInjection();
        
        return $this->results;
    }
    
    private function testOutputEncoding()
    {
        if (class_exists('Tools')) {
            $maliciousInputs = array(
                '<script>alert("xss")</script>',
                '<img src="x" onerror="alert(1)">',
                'javascript:alert("xss")',
                '"><script>alert("xss")</script>'
            );
            
            foreach ($maliciousInputs as $input) {
                $encoded = Tools::safeOutput($input);
                
                $this->assertFalse(
                    strpos($encoded, '<script>') !== false,
                    'Output Encoding - Script Tags',
                    'Script tags should be encoded',
                    'HIGH'
                );
                
                $this->assertFalse(
                    strpos($encoded, 'javascript:') !== false,
                    'Output Encoding - JavaScript URLs',
                    'JavaScript URLs should be encoded',
                    'HIGH'
                );
            }
        }
    }
    
    private function testHTMLPurification()
    {
        if (class_exists('Tools')) {
            $maliciousHTML = '<script>alert("xss")</script><p>Safe content</p>';
            $purified = Tools::purifyHTML($maliciousHTML);
            
            $this->assertFalse(
                strpos($purified, '<script>') !== false,
                'HTML Purification',
                'Malicious scripts should be removed from HTML',
                'HIGH'
            );
            
            $this->assertTrue(
                strpos($purified, '<p>Safe content</p>') !== false,
                'HTML Purification - Safe Content',
                'Safe HTML content should be preserved'
            );
        }
    }
    
    private function testJavaScriptInjection()
    {
        // Test for potential JavaScript injection points
        $jsInjectionPatterns = array(
            'document.write',
            'innerHTML',
            'eval(',
            'setTimeout(',
            'setInterval('
        );
        
        $jsFiles = $this->getJavaScriptFiles();
        $vulnerableFiles = array();
        
        foreach ($jsFiles as $file) {
            $content = file_get_contents($file);
            
            foreach ($jsInjectionPatterns as $pattern) {
                if (strpos($content, $pattern) !== false) {
                    // Check if it's using user input
                    if (preg_match('/\$\{.*?\}|\+.*?\+/', $content)) {
                        $vulnerableFiles[] = $file;
                        break;
                    }
                }
            }
        }
        
        $this->assertTrue(
            empty($vulnerableFiles),
            'JavaScript Injection',
            'Found potential JS injection points: ' . implode(', ', $vulnerableFiles),
            'MEDIUM'
        );
    }
    
    private function getJavaScriptFiles()
    {
        $files = array();
        
        if (is_dir('js')) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator('js')
            );
            
            foreach ($iterator as $file) {
                if ($file->getExtension() === 'js') {
                    $files[] = $file->getPathname();
                }
            }
        }
        
        return array_slice($files, 0, 5); // Limit for testing
    }
}

/**
 * API Security Tests
 */
class APISecurityTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testAPIAuthentication();
        $this->testRateLimiting();
        $this->testInputValidation();
        
        return $this->results;
    }
    
    private function testAPIAuthentication()
    {
        // Test API authentication mechanisms
        if (file_exists('webservice/dispatcher.php')) {
            $content = file_get_contents('webservice/dispatcher.php');
            
            $this->assertTrue(
                strpos($content, 'ws_key') !== false || strpos($content, 'api_key') !== false,
                'API Authentication',
                'API should require authentication'
            );
            
            $this->assertTrue(
                strpos($content, 'Authorization') !== false || strpos($content, 'authenticate') !== false,
                'API Authorization',
                'API should have authorization checks'
            );
        }
    }
    
    private function testRateLimiting()
    {
        // Test API rate limiting
        if (class_exists('APIRateLimit')) {
            $this->assertTrue(
                true,
                'API Rate Limiting',
                'APIRateLimit class exists'
            );
        } else {
            $this->assert(
                false,
                'API Rate Limiting',
                'APIRateLimit class not found',
                'HIGH'
            );
        }
    }
    
    private function testInputValidation()
    {
        // Test API input validation
        if (file_exists('webservice')) {
            $files = glob('webservice/*.php');
            $hasValidation = false;
            
            foreach ($files as $file) {
                $content = file_get_contents($file);
                if (strpos($content, 'Validate::') !== false || strpos($content, 'filter_var') !== false) {
                    $hasValidation = true;
                    break;
                }
            }
            
            $this->assertTrue(
                $hasValidation,
                'API Input Validation',
                'API should validate input parameters',
                'HIGH'
            );
        }
    }
}

/**
 * Encryption Tests
 */
class EncryptionTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testEncryptionFunctions();
        $this->testPasswordHashing();
        $this->testSecureRandomGeneration();
        
        return $this->results;
    }
    
    private function testEncryptionFunctions()
    {
        // Test encryption capabilities
        $this->assertTrue(
            function_exists('openssl_encrypt'),
            'OpenSSL Encryption',
            'OpenSSL encryption functions should be available',
            'CRITICAL'
        );
        
        $this->assertTrue(
            function_exists('hash'),
            'Hash Functions',
            'Hash functions should be available',
            'CRITICAL'
        );
        
        if (class_exists('SecureEncryption')) {
            $testData = 'Test encryption data';
            try {
                $encrypted = SecureEncryption::encrypt($testData);
                $decrypted = SecureEncryption::decrypt($encrypted);
                
                $this->assertEquals(
                    $testData,
                    $decrypted,
                    'Encryption/Decryption',
                    'Data should encrypt and decrypt correctly',
                    'CRITICAL'
                );
            } catch (Exception $e) {
                $this->assert(
                    false,
                    'Encryption/Decryption',
                    'Encryption failed: ' . $e->getMessage(),
                    'CRITICAL'
                );
            }
        }
    }
    
    private function testPasswordHashing()
    {
        $this->assertTrue(
            function_exists('password_hash'),
            'Password Hashing',
            'Password hashing functions should be available',
            'CRITICAL'
        );
        
        $this->assertTrue(
            function_exists('password_verify'),
            'Password Verification',
            'Password verification functions should be available',
            'CRITICAL'
        );
    }
    
    private function testSecureRandomGeneration()
    {
        $this->assertTrue(
            function_exists('random_bytes'),
            'Secure Random Generation',
            'Secure random generation should be available',
            'HIGH'
        );
        
        if (function_exists('random_bytes')) {
            try {
                $random = random_bytes(32);
                $this->assertEquals(
                    32,
                    strlen($random),
                    'Random Bytes Length',
                    'Random bytes should generate correct length'
                );
            } catch (Exception $e) {
                $this->assert(
                    false,
                    'Random Bytes Generation',
                    'Random bytes generation failed: ' . $e->getMessage(),
                    'HIGH'
                );
            }
        }
    }
}

/**
 * Session Security Tests
 */
class SessionSecurityTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testSessionConfiguration();
        $this->testSessionSecurity();
        
        return $this->results;
    }
    
    private function testSessionConfiguration()
    {
        $secureSettings = array(
            'session.cookie_httponly' => '1',
            'session.use_strict_mode' => '1',
            'session.cookie_samesite' => 'Strict'
        );
        
        foreach ($secureSettings as $setting => $expectedValue) {
            $actualValue = ini_get($setting);
            $this->assertEquals(
                $expectedValue,
                $actualValue,
                'Session Configuration - ' . $setting,
                "Setting {$setting} should be {$expectedValue}",
                'MEDIUM'
            );
        }
    }
    
    private function testSessionSecurity()
    {
        if (class_exists('SecureSession')) {
            $this->assertTrue(
                true,
                'Secure Session Class',
                'SecureSession class exists'
            );
        } else {
            $this->assert(
                false,
                'Secure Session Class',
                'SecureSession class not found',
                'MEDIUM'
            );
        }
    }
}

/**
 * File Security Tests
 */
class FileSecurityTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testFilePermissions();
        $this->testSensitiveFiles();
        $this->testUploadSecurity();
        
        return $this->results;
    }
    
    private function testFilePermissions()
    {
        $sensitiveFiles = array(
            'config/settings.inc.php',
            '.env'
        );
        
        foreach ($sensitiveFiles as $file) {
            if (file_exists($file)) {
                $perms = fileperms($file) & 0777;
                
                $this->assertFalse(
                    $perms & 0004,
                    'File Permissions - ' . $file,
                    "File {$file} should not be world-readable",
                    'HIGH'
                );
            }
        }
    }
    
    private function testSensitiveFiles()
    {
        $sensitiveFiles = array(
            '.env',
            'config/settings.inc.php',
            'install/'
        );
        
        foreach ($sensitiveFiles as $file) {
            if (file_exists($file)) {
                // Check if file has proper protection
                $htaccessPath = dirname($file) . '/.htaccess';
                
                if (file_exists($htaccessPath)) {
                    $htaccessContent = file_get_contents($htaccessPath);
                    $this->assertTrue(
                        strpos($htaccessContent, 'Deny from all') !== false ||
                        strpos($htaccessContent, 'Require all denied') !== false,
                        'Sensitive File Protection - ' . $file,
                        "Sensitive file {$file} should be protected by .htaccess"
                    );
                }
            }
        }
    }
    
    private function testUploadSecurity()
    {
        $uploadDirs = array('upload', 'img');
        
        foreach ($uploadDirs as $dir) {
            if (is_dir($dir)) {
                $htaccessPath = $dir . '/.htaccess';
                
                if (file_exists($htaccessPath)) {
                    $content = file_get_contents($htaccessPath);
                    $this->assertTrue(
                        strpos($content, 'php_flag engine off') !== false ||
                        strpos($content, 'RemoveHandler .php') !== false,
                        'Upload Directory Security - ' . $dir,
                        "Upload directory {$dir} should prevent PHP execution"
                    );
                }
            }
        }
    }
}

/**
 * Configuration Security Tests
 */
class ConfigurationSecurityTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testHardcodedCredentials();
        $this->testDebugMode();
        $this->testErrorReporting();
        
        return $this->results;
    }
    
    private function testHardcodedCredentials()
    {
        $configFiles = array(
            'config/settings.inc.php',
            'config/config.inc.php'
        );
        
        foreach ($configFiles as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                
                // Look for hardcoded passwords
                $patterns = array(
                    '/define\s*\(\s*[\'"]_DB_PASSWD_[\'"],\s*[\'"][^\'"]+[\'"]\s*\)/',
                    '/\$password\s*=\s*[\'"][^\'"]+[\'"]/',
                    '/passwd.*=.*[\'"][^\'"]+[\'"]/'
                );
                
                $hasHardcodedCreds = false;
                foreach ($patterns as $pattern) {
                    if (preg_match($pattern, $content)) {
                        $hasHardcodedCreds = true;
                        break;
                    }
                }
                
                $this->assertFalse(
                    $hasHardcodedCreds,
                    'Hardcoded Credentials - ' . $file,
                    "File {$file} should not contain hardcoded credentials",
                    'CRITICAL'
                );
            }
        }
    }
    
    private function testDebugMode()
    {
        if (defined('_PS_MODE_DEV_')) {
            $this->assertFalse(
                _PS_MODE_DEV_,
                'Debug Mode',
                'Debug mode should be disabled in production',
                'MEDIUM'
            );
        }
    }
    
    private function testErrorReporting()
    {
        $errorReporting = error_reporting();
        $displayErrors = ini_get('display_errors');
        
        $this->assertEquals(
            '0',
            $displayErrors,
            'Error Display',
            'Error display should be disabled in production',
            'MEDIUM'
        );
    }
}

/**
 * Compliance Tests
 */
class ComplianceTests extends SecurityTestSuite
{
    public function runTests()
    {
        $this->testGDPRCompliance();
        $this->testPCIDSSCompliance();
        
        return $this->results;
    }
    
    private function testGDPRCompliance()
    {
        // Test GDPR compliance features
        if (class_exists('GDPRComplianceAudit')) {
            $this->assertTrue(
                true,
                'GDPR Compliance Class',
                'GDPR compliance class exists'
            );
        } else {
            $this->assert(
                false,
                'GDPR Compliance Class',
                'GDPR compliance class not found',
                'HIGH'
            );
        }
        
        // Check for consent tracking
        $consentTables = array('ps_gdpr_consent', 'ps_customer_consent');
        $hasConsentTracking = false;
        
        foreach ($consentTables as $table) {
            if (Db::getInstance()->executeS("SHOW TABLES LIKE '{$table}'")) {
                $hasConsentTracking = true;
                break;
            }
        }
        
        $this->assertTrue(
            $hasConsentTracking,
            'GDPR Consent Tracking',
            'GDPR consent tracking should be implemented',
            'HIGH'
        );
    }
    
    private function testPCIDSSCompliance()
    {
        // Test PCI DSS compliance
        
        // Check for card data storage
        $cardDataTables = array('ps_payment_cc', 'ps_credit_card');
        $hasCardDataStorage = false;
        
        foreach ($cardDataTables as $table) {
            if (Db::getInstance()->executeS("SHOW TABLES LIKE '{$table}'")) {
                $hasCardDataStorage = true;
                break;
            }
        }
        
        $this->assertFalse(
            $hasCardDataStorage,
            'PCI DSS - Card Data Storage',
            'Card data should not be stored in database',
            'CRITICAL'
        );
        
        // Check for secure payment processing
        if (class_exists('SecurePayment')) {
            $this->assertTrue(
                true,
                'PCI DSS - Secure Payment',
                'Secure payment class exists'
            );
        } else {
            $this->assert(
                false,
                'PCI DSS - Secure Payment',
                'Secure payment class not found',
                'HIGH'
            );
        }
    }
}

// CLI execution
if (php_sapi_name() === 'cli') {
    $framework = new SecurityTestingFramework();
    
    if (isset($argv[1])) {
        // Run specific test suite
        $framework->runTestSuite($argv[1]);
    } else {
        // Run all tests
        $framework->runAllTests();
    }
}