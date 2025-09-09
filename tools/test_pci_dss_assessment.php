<?php
/**
 * Test script for PCI DSS Assessment Tool
 * 
 * This script tests the PCI DSS compliance assessment functionality
 * to ensure it properly identifies payment security issues.
 */

// Mock PrestaShop environment for testing
if (!defined('_PS_VERSION_')) {
    define('_PS_VERSION_', '1.6.1.0');
}
if (!defined('_PS_ROOT_DIR_')) {
    define('_PS_ROOT_DIR_', dirname(__FILE__) . '/..');
}
if (!defined('_PS_CLASS_DIR_')) {
    define('_PS_CLASS_DIR_', _PS_ROOT_DIR_ . '/classes/');
}
if (!defined('_PS_MODULE_DIR_')) {
    define('_PS_MODULE_DIR_', _PS_ROOT_DIR_ . '/modules/');
}
if (!defined('_PS_ADMIN_DIR_')) {
    define('_PS_ADMIN_DIR_', _PS_ROOT_DIR_ . '/admin/');
}
if (!defined('_DB_PREFIX_')) {
    define('_DB_PREFIX_', 'ps_');
}

// Mock classes for testing
class Configuration
{
    public static function get($key)
    {
        $mockConfig = array(
            'PS_SSL_ENABLED' => false, // Simulate SSL not enabled
        );
        return isset($mockConfig[$key]) ? $mockConfig[$key] : null;
    }
}

class Db
{
    public static function getInstance()
    {
        return new self();
    }
    
    public function executeS($sql)
    {
        // Mock database responses for testing
        if (strpos($sql, 'payment_cc') !== false) {
            return array(array('table' => 'ps_payment_cc')); // Simulate table exists
        }
        
        if (strpos($sql, 'DESCRIBE') !== false) {
            return array(
                array('Field' => 'id', 'Type' => 'int'),
                array('Field' => 'card_number', 'Type' => 'varchar'), // Sensitive field
                array('Field' => 'amount', 'Type' => 'decimal')
            );
        }
        
        return array();
    }
}

require_once dirname(__FILE__) . '/pci_dss_assessment.php';

class PCIDSSAssessmentTest
{
    private $testResults = array();
    
    public function runTests()
    {
        echo "Running PCI DSS Assessment Tests...\n";
        echo "===================================\n\n";
        
        $this->testPaymentModuleIdentification();
        $this->testCardholderDataDetection();
        $this->testTransmissionSecurityAssessment();
        $this->testAccessControlAssessment();
        $this->testLoggingAssessment();
        $this->testConfigurationSecurity();
        $this->testComplianceScoring();
        
        $this->printTestResults();
    }
    
    private function testPaymentModuleIdentification()
    {
        echo "Testing payment module identification...\n";
        
        try {
            $assessment = new PCIDSSAssessment();
            
            // Use reflection to access private property
            $reflection = new ReflectionClass($assessment);
            $property = $reflection->getProperty('paymentModules');
            $property->setAccessible(true);
            $modules = $property->getValue($assessment);
            
            $this->addTestResult(
                'Payment Module Identification',
                count($modules) > 0,
                'Should identify at least one payment module',
                'Found ' . count($modules) . ' payment modules'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Payment Module Identification',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function testCardholderDataDetection()
    {
        echo "Testing cardholder data detection...\n";
        
        // Create a mock PaymentCC file for testing
        $mockPaymentCCContent = '<?php
class PaymentCC {
    public $card_number;
    public $card_expiration;
    public $card_holder;
    public $cvv;
}';
        
        $testFile = _PS_CLASS_DIR_ . 'TestPaymentCC.php';
        file_put_contents($testFile, $mockPaymentCCContent);
        
        try {
            $assessment = new PCIDSSAssessment();
            $findings = $assessment->runAssessment();
            
            // Check if cardholder data issues were detected
            $cardDataFindings = array_filter($findings, function($finding) {
                return strpos($finding->title, 'Cardholder Data') !== false;
            });
            
            $this->addTestResult(
                'Cardholder Data Detection',
                count($cardDataFindings) > 0,
                'Should detect cardholder data storage issues',
                'Found ' . count($cardDataFindings) . ' cardholder data issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Cardholder Data Detection',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        } finally {
            // Clean up test file
            if (file_exists($testFile)) {
                unlink($testFile);
            }
        }
    }
    
    private function testTransmissionSecurityAssessment()
    {
        echo "Testing transmission security assessment...\n";
        
        // Create a mock payment module with insecure HTTP
        $mockModuleContent = '<?php
class TestPayment {
    public function processPayment() {
        $url = "http://payment-gateway.com/api";
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    }
}';
        
        $testModuleDir = _PS_MODULE_DIR_ . 'testpayment/';
        $testModuleFile = $testModuleDir . 'testpayment.php';
        
        if (!is_dir($testModuleDir)) {
            mkdir($testModuleDir, 0755, true);
        }
        file_put_contents($testModuleFile, $mockModuleContent);
        
        try {
            $assessment = new PCIDSSAssessment();
            $findings = $assessment->runAssessment();
            
            // Check if transmission security issues were detected
            $transmissionFindings = array_filter($findings, function($finding) {
                return strpos($finding->title, 'HTTP') !== false || 
                       strpos($finding->title, 'SSL') !== false ||
                       strpos($finding->title, 'TLS') !== false;
            });
            
            $this->addTestResult(
                'Transmission Security Assessment',
                count($transmissionFindings) > 0,
                'Should detect transmission security issues',
                'Found ' . count($transmissionFindings) . ' transmission security issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Transmission Security Assessment',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        } finally {
            // Clean up test files
            if (file_exists($testModuleFile)) {
                unlink($testModuleFile);
            }
            if (is_dir($testModuleDir)) {
                rmdir($testModuleDir);
            }
        }
    }
    
    private function testAccessControlAssessment()
    {
        echo "Testing access control assessment...\n";
        
        try {
            $assessment = new PCIDSSAssessment();
            $findings = $assessment->runAssessment();
            
            // Check if access control issues were detected
            $accessFindings = array_filter($findings, function($finding) {
                return $finding->category === 'access_control';
            });
            
            $this->addTestResult(
                'Access Control Assessment',
                count($accessFindings) > 0,
                'Should detect access control issues',
                'Found ' . count($accessFindings) . ' access control issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Access Control Assessment',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function testLoggingAssessment()
    {
        echo "Testing logging assessment...\n";
        
        try {
            $assessment = new PCIDSSAssessment();
            $findings = $assessment->runAssessment();
            
            // Check if logging issues were detected
            $loggingFindings = array_filter($findings, function($finding) {
                return $finding->category === 'logging';
            });
            
            $this->addTestResult(
                'Logging Assessment',
                count($loggingFindings) > 0,
                'Should detect logging issues',
                'Found ' . count($loggingFindings) . ' logging issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Logging Assessment',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function testConfigurationSecurity()
    {
        echo "Testing configuration security assessment...\n";
        
        // Create a mock configuration file with plain text credentials
        $mockConfigContent = '<?php
define("_DB_PASSWD_", "plaintext_password");
define("_DB_USER_", "root");
';
        
        $testConfigFile = _PS_ROOT_DIR_ . '/config/test_settings.inc.php';
        file_put_contents($testConfigFile, $mockConfigContent);
        
        try {
            $assessment = new PCIDSSAssessment();
            $findings = $assessment->runAssessment();
            
            // Check if configuration security issues were detected
            $configFindings = array_filter($findings, function($finding) {
                return $finding->category === 'configuration';
            });
            
            $this->addTestResult(
                'Configuration Security Assessment',
                count($configFindings) > 0,
                'Should detect configuration security issues',
                'Found ' . count($configFindings) . ' configuration issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Configuration Security Assessment',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        } finally {
            // Clean up test file
            if (file_exists($testConfigFile)) {
                unlink($testConfigFile);
            }
        }
    }
    
    private function testComplianceScoring()
    {
        echo "Testing compliance scoring...\n";
        
        try {
            $assessment = new PCIDSSAssessment();
            $findings = $assessment->runAssessment();
            
            // Test that findings are properly categorized by severity
            $severityCounts = array();
            foreach ($findings as $finding) {
                $severity = $finding->severity;
                if (!isset($severityCounts[$severity])) {
                    $severityCounts[$severity] = 0;
                }
                $severityCounts[$severity]++;
            }
            
            $this->addTestResult(
                'Compliance Scoring',
                count($findings) > 0,
                'Should generate findings with severity scores',
                'Generated ' . count($findings) . ' findings with severity distribution: ' . 
                json_encode($severityCounts)
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Compliance Scoring',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function addTestResult($testName, $passed, $expected, $actual)
    {
        $this->testResults[] = array(
            'name' => $testName,
            'passed' => $passed,
            'expected' => $expected,
            'actual' => $actual
        );
        
        $status = $passed ? 'PASS' : 'FAIL';
        echo "  [$status] $testName\n";
        if (!$passed) {
            echo "    Expected: $expected\n";
            echo "    Actual: $actual\n";
        }
    }
    
    private function printTestResults()
    {
        echo "\n" . str_repeat("=", 50) . "\n";
        echo "TEST RESULTS SUMMARY\n";
        echo str_repeat("=", 50) . "\n";
        
        $totalTests = count($this->testResults);
        $passedTests = count(array_filter($this->testResults, function($result) {
            return $result['passed'];
        }));
        
        echo "Total Tests: $totalTests\n";
        echo "Passed: $passedTests\n";
        echo "Failed: " . ($totalTests - $passedTests) . "\n";
        echo "Success Rate: " . round(($passedTests / $totalTests) * 100, 2) . "%\n\n";
        
        if ($passedTests < $totalTests) {
            echo "Failed Tests:\n";
            echo str_repeat("-", 20) . "\n";
            foreach ($this->testResults as $result) {
                if (!$result['passed']) {
                    echo "• " . $result['name'] . "\n";
                    echo "  Expected: " . $result['expected'] . "\n";
                    echo "  Actual: " . $result['actual'] . "\n\n";
                }
            }
        }
        
        echo "PCI DSS Assessment testing completed.\n";
    }
}

// Run tests if called directly
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    $test = new PCIDSSAssessmentTest();
    $test->runTests();
}