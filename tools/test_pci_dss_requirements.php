<?php
/**
 * Test script for PCI DSS Requirements Evaluator
 * 
 * This script tests the comprehensive PCI DSS requirements evaluation
 * to ensure all 12 requirements are properly assessed.
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

// Mock Configuration class
class Configuration
{
    public static function get($key)
    {
        $mockConfig = array(
            'PS_SSL_ENABLED' => false, // Simulate SSL not enabled for testing
        );
        return isset($mockConfig[$key]) ? $mockConfig[$key] : null;
    }
}

require_once dirname(__FILE__) . '/pci_dss_requirements_evaluator.php';

class PCIDSSRequirementsTest
{
    private $testResults = array();
    
    public function runTests()
    {
        echo "Running PCI DSS Requirements Evaluator Tests...\n";
        echo "==============================================\n\n";
        
        $this->testRequirementsInitialization();
        $this->testRequirement1Evaluation();
        $this->testRequirement2Evaluation();
        $this->testRequirement3Evaluation();
        $this->testRequirement4Evaluation();
        $this->testRequirement6Evaluation();
        $this->testComplianceScoring();
        $this->testComplianceReporting();
        $this->testFindingsGeneration();
        
        $this->printTestResults();
    }
    
    private function testRequirementsInitialization()
    {
        echo "Testing requirements initialization...\n";
        
        try {
            $evaluator = new PCIDSSRequirementsEvaluator();
            
            // Use reflection to access private property
            $reflection = new ReflectionClass($evaluator);
            $property = $reflection->getProperty('complianceResults');
            $property->setAccessible(true);
            $complianceResults = $property->getValue($evaluator);
            
            $this->addTestResult(
                'Requirements Initialization',
                count($complianceResults) === 12,
                'Should initialize all 12 PCI DSS requirements',
                'Initialized ' . count($complianceResults) . ' requirements'
            );
            
            // Check that each requirement has proper structure
            $hasProperStructure = true;
            foreach ($complianceResults as $reqNum => $result) {
                if (!isset($result['requirement']) || 
                    !isset($result['status']) || 
                    !isset($result['score'])) {
                    $hasProperStructure = false;
                    break;
                }
            }
            
            $this->addTestResult(
                'Requirements Structure',
                $hasProperStructure,
                'Each requirement should have proper structure',
                $hasProperStructure ? 'All requirements properly structured' : 'Missing structure elements'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Requirements Initialization',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function testRequirement1Evaluation()
    {
        echo "Testing Requirement 1 (Firewall) evaluation...\n";
        
        try {
            $evaluator = new PCIDSSRequirementsEvaluator();
            
            // Use reflection to call private method
            $reflection = new ReflectionClass($evaluator);
            $method = $reflection->getMethod('evaluateRequirement1');
            $method->setAccessible(true);
            $method->invoke($evaluator);
            
            // Check if findings were generated
            $findingsProperty = $reflection->getProperty('findings');
            $findingsProperty->setAccessible(true);
            $findings = $findingsProperty->getValue($evaluator);
            
            $this->addTestResult(
                'Requirement 1 Evaluation',
                count($findings) > 0,
                'Should generate findings for firewall configuration',
                'Generated ' . count($findings) . ' findings'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Requirement 1 Evaluation',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function testRequirement2Evaluation()
    {
        echo "Testing Requirement 2 (Default Passwords) evaluation...\n";
        
        // Create a mock configuration file with potential default credentials
        $mockConfigContent = '<?php
define("_DB_USER_", "admin");
define("_DB_PASSWD_", "admin");
';
        
        $testConfigFile = _PS_ROOT_DIR_ . '/config/test_settings.inc.php';
        if (!is_dir(dirname($testConfigFile))) {
            mkdir(dirname($testConfigFile), 0755, true);
        }
        file_put_contents($testConfigFile, $mockConfigContent);
        
        try {
            $evaluator = new PCIDSSRequirementsEvaluator();
            
            // Use reflection to call private method
            $reflection = new ReflectionClass($evaluator);
            $method = $reflection->getMethod('evaluateRequirement2');
            $method->setAccessible(true);
            $method->invoke($evaluator);
            
            // Check if default credential findings were generated
            $findingsProperty = $reflection->getProperty('findings');
            $findingsProperty->setAccessible(true);
            $findings = $findingsProperty->getValue($evaluator);
            
            $defaultCredFindings = array_filter($findings, function($finding) {
                return strpos($finding->title, 'Default') !== false;
            });
            
            $this->addTestResult(
                'Requirement 2 Evaluation',
                count($defaultCredFindings) > 0,
                'Should detect default credentials',
                'Found ' . count($defaultCredFindings) . ' default credential issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Requirement 2 Evaluation',
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
    
    private function testRequirement3Evaluation()
    {
        echo "Testing Requirement 3 (Protect Stored Data) evaluation...\n";
        
        // Create a mock PaymentCC file with sensitive data fields
        $mockPaymentCCContent = '<?php
class PaymentCC {
    public $card_number;
    public $cvv;
    public $track_data;
    public $pin;
}';
        
        $testPaymentCCFile = _PS_CLASS_DIR_ . 'TestPaymentCC.php';
        if (!is_dir(dirname($testPaymentCCFile))) {
            mkdir(dirname($testPaymentCCFile), 0755, true);
        }
        file_put_contents($testPaymentCCFile, $mockPaymentCCContent);
        
        try {
            $evaluator = new PCIDSSRequirementsEvaluator();
            
            // Use reflection to call private method
            $reflection = new ReflectionClass($evaluator);
            $method = $reflection->getMethod('evaluateRequirement3');
            $method->setAccessible(true);
            $method->invoke($evaluator);
            
            // Check if sensitive data storage findings were generated
            $findingsProperty = $reflection->getProperty('findings');
            $findingsProperty->setAccessible(true);
            $findings = $findingsProperty->getValue($evaluator);
            
            $sensitiveDataFindings = array_filter($findings, function($finding) {
                return strpos($finding->title, 'Sensitive') !== false ||
                       strpos($finding->title, 'Authentication Data') !== false;
            });
            
            $this->addTestResult(
                'Requirement 3 Evaluation',
                count($sensitiveDataFindings) > 0,
                'Should detect sensitive data storage issues',
                'Found ' . count($sensitiveDataFindings) . ' sensitive data issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Requirement 3 Evaluation',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        } finally {
            // Clean up test file
            if (file_exists($testPaymentCCFile)) {
                unlink($testPaymentCCFile);
            }
        }
    }
    
    private function testRequirement4Evaluation()
    {
        echo "Testing Requirement 4 (Encrypt Transmission) evaluation...\n";
        
        try {
            $evaluator = new PCIDSSRequirementsEvaluator();
            
            // Use reflection to call private method
            $reflection = new ReflectionClass($evaluator);
            $method = $reflection->getMethod('evaluateRequirement4');
            $method->setAccessible(true);
            $method->invoke($evaluator);
            
            // Check if transmission encryption findings were generated
            $findingsProperty = $reflection->getProperty('findings');
            $findingsProperty->setAccessible(true);
            $findings = $findingsProperty->getValue($evaluator);
            
            $transmissionFindings = array_filter($findings, function($finding) {
                return strpos($finding->title, 'Transmission') !== false ||
                       strpos($finding->title, 'Encrypted') !== false;
            });
            
            $this->addTestResult(
                'Requirement 4 Evaluation',
                count($transmissionFindings) > 0,
                'Should detect transmission encryption issues',
                'Found ' . count($transmissionFindings) . ' transmission issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Requirement 4 Evaluation',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function testRequirement6Evaluation()
    {
        echo "Testing Requirement 6 (Secure Systems) evaluation...\n";
        
        try {
            $evaluator = new PCIDSSRequirementsEvaluator();
            
            // Use reflection to call private method
            $reflection = new ReflectionClass($evaluator);
            $method = $reflection->getMethod('evaluateRequirement6');
            $method->setAccessible(true);
            $method->invoke($evaluator);
            
            // Check if secure systems findings were generated
            $findingsProperty = $reflection->getProperty('findings');
            $findingsProperty->setAccessible(true);
            $findings = $findingsProperty->getValue($evaluator);
            
            $secureSystemsFindings = array_filter($findings, function($finding) {
                return strpos($finding->title, 'Vulnerability') !== false ||
                       strpos($finding->title, 'Development') !== false ||
                       strpos($finding->title, 'Security') !== false;
            });
            
            $this->addTestResult(
                'Requirement 6 Evaluation',
                count($secureSystemsFindings) > 0,
                'Should detect secure systems issues',
                'Found ' . count($secureSystemsFindings) . ' secure systems issues'
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Requirement 6 Evaluation',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function testComplianceScoring()
    {
        echo "Testing compliance scoring...\n";
        
        try {
            $evaluator = new PCIDSSRequirementsEvaluator();
            $results = $evaluator->evaluateCompliance();
            
            // Check that compliance results have scores
            $hasScores = true;
            foreach ($results['compliance'] as $reqNum => $result) {
                if (!isset($result['score']) || $result['score'] < 0 || $result['score'] > 100) {
                    $hasScores = false;
                    break;
                }
            }
            
            $this->addTestResult(
                'Compliance Scoring',
                $hasScores,
                'All requirements should have valid scores (0-100)',
                $hasScores ? 'All requirements have valid scores' : 'Invalid scores found'
            );
            
            // Check that status is set based on score
            $hasValidStatus = true;
            foreach ($results['compliance'] as $reqNum => $result) {
                $expectedStatus = $result['score'] >= 70 ? 'compliant' : 'non_compliant';
                if ($result['status'] !== $expectedStatus && $result['status'] !== 'not_assessed') {
                    $hasValidStatus = false;
                    break;
                }
            }
            
            $this->addTestResult(
                'Compliance Status',
                $hasValidStatus,
                'Status should match score (compliant >= 70%)',
                $hasValidStatus ? 'All statuses valid' : 'Invalid status found'
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
    
    private function testComplianceReporting()
    {
        echo "Testing compliance reporting...\n";
        
        try {
            // Capture output
            ob_start();
            
            $evaluator = new PCIDSSRequirementsEvaluator();
            $results = $evaluator->evaluateCompliance();
            
            $output = ob_get_clean();
            
            // Check that report contains key elements
            $hasRequirementSummary = strpos($output, 'Requirement') !== false;
            $hasOverallScore = strpos($output, 'Overall Score') !== false;
            $hasComplianceStatus = strpos($output, 'COMPLIANT') !== false || 
                                  strpos($output, 'NON-COMPLIANT') !== false;
            
            $this->addTestResult(
                'Compliance Reporting',
                $hasRequirementSummary && $hasOverallScore && $hasComplianceStatus,
                'Report should contain requirement summary, overall score, and status',
                "Summary: $hasRequirementSummary, Score: $hasOverallScore, Status: $hasComplianceStatus"
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Compliance Reporting',
                false,
                'Should not throw exception',
                'Exception: ' . $e->getMessage()
            );
        }
    }
    
    private function testFindingsGeneration()
    {
        echo "Testing findings generation...\n";
        
        try {
            $evaluator = new PCIDSSRequirementsEvaluator();
            $results = $evaluator->evaluateCompliance();
            
            $findings = $results['findings'];
            
            // Check that findings have required properties
            $hasValidFindings = true;
            foreach ($findings as $finding) {
                if (!isset($finding->title) || 
                    !isset($finding->description) || 
                    !isset($finding->severity) ||
                    !isset($finding->category)) {
                    $hasValidFindings = false;
                    break;
                }
            }
            
            $this->addTestResult(
                'Findings Generation',
                $hasValidFindings && count($findings) > 0,
                'Should generate valid findings with required properties',
                'Generated ' . count($findings) . ' findings, valid: ' . ($hasValidFindings ? 'yes' : 'no')
            );
            
            // Check severity distribution
            $severityCounts = array();
            foreach ($findings as $finding) {
                $severity = $finding->severity;
                if (!isset($severityCounts[$severity])) {
                    $severityCounts[$severity] = 0;
                }
                $severityCounts[$severity]++;
            }
            
            $this->addTestResult(
                'Findings Severity Distribution',
                count($severityCounts) > 0,
                'Should have findings with various severity levels',
                'Severity distribution: ' . json_encode($severityCounts)
            );
            
        } catch (Exception $e) {
            $this->addTestResult(
                'Findings Generation',
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
        echo "\n" . str_repeat("=", 60) . "\n";
        echo "PCI DSS REQUIREMENTS TEST RESULTS SUMMARY\n";
        echo str_repeat("=", 60) . "\n";
        
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
            echo str_repeat("-", 30) . "\n";
            foreach ($this->testResults as $result) {
                if (!$result['passed']) {
                    echo "• " . $result['name'] . "\n";
                    echo "  Expected: " . $result['expected'] . "\n";
                    echo "  Actual: " . $result['actual'] . "\n\n";
                }
            }
        }
        
        echo "PCI DSS Requirements evaluation testing completed.\n";
    }
}

// Run tests if called directly
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    $test = new PCIDSSRequirementsTest();
    $test->runTests();
}