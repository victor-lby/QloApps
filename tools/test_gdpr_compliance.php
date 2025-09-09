<?php
/**
 * Test script for GDPR Compliance Assessment
 * 
 * This script tests the GDPR compliance audit functionality
 * and generates a sample compliance report.
 */

// Include necessary files
require_once(dirname(__FILE__) . '/../config/config.inc.php');
require_once(dirname(__FILE__) . '/../classes/GDPRComplianceAudit.php');

class GDPRComplianceTest
{
    private $test_results = array();
    
    public function runAllTests()
    {
        echo "=== GDPR Compliance Assessment Test ===\n\n";
        
        // Test GDPR audit initialization
        $this->testGDPRAuditInitialization();
        
        // Test data processing compliance review
        $this->testDataProcessingCompliance();
        
        // Test privacy protection measures assessment
        $this->testPrivacyProtectionMeasures();
        
        // Test full GDPR assessment
        $this->testFullGDPRAssessment();
        
        // Display test results
        $this->displayTestResults();
        
        return $this->test_results;
    }
    
    private function testGDPRAuditInitialization()
    {
        echo "Testing GDPR audit initialization...\n";
        
        try {
            $gdpr_audit = new GDPRComplianceAudit();
            
            if ($gdpr_audit) {
                $this->test_results['gdpr_initialization'] = array(
                    'status' => 'PASS',
                    'message' => 'GDPR audit initialized successfully'
                );
                echo "✓ GDPR audit initialization: PASS\n";
            } else {
                throw new Exception('Failed to initialize GDPR audit');
            }
            
        } catch (Exception $e) {
            $this->test_results['gdpr_initialization'] = array(
                'status' => 'FAIL',
                'message' => 'GDPR audit initialization failed: ' . $e->getMessage()
            );
            echo "✗ GDPR audit initialization: FAIL - " . $e->getMessage() . "\n";
        }
        
        echo "\n";
    }
    
    private function testDataProcessingCompliance()
    {
        echo "Testing data processing compliance review...\n";
        
        try {
            $gdpr_audit = new GDPRComplianceAudit();
            
            // Test customer data collection examination
            $reflection = new ReflectionClass($gdpr_audit);
            $method = $reflection->getMethod('examineCustomerDataCollection');
            $method->setAccessible(true);
            $method->invoke($gdpr_audit);
            
            echo "✓ Customer data collection examination: PASS\n";
            
            // Test consent mechanisms check
            $method = $reflection->getMethod('checkConsentMechanisms');
            $method->setAccessible(true);
            $method->invoke($gdpr_audit);
            
            echo "✓ Consent mechanisms check: PASS\n";
            
            // Test data subject rights review
            $method = $reflection->getMethod('reviewDataSubjectRights');
            $method->setAccessible(true);
            $method->invoke($gdpr_audit);
            
            echo "✓ Data subject rights review: PASS\n";
            
            // Test data retention policies review
            $method = $reflection->getMethod('reviewDataRetentionPolicies');
            $method->setAccessible(true);
            $method->invoke($gdpr_audit);
            
            echo "✓ Data retention policies review: PASS\n";
            
            $this->test_results['data_processing_compliance'] = array(
                'status' => 'PASS',
                'message' => 'All data processing compliance tests passed'
            );
            
        } catch (Exception $e) {
            $this->test_results['data_processing_compliance'] = array(
                'status' => 'FAIL',
                'message' => 'Data processing compliance test failed: ' . $e->getMessage()
            );
            echo "✗ Data processing compliance: FAIL - " . $e->getMessage() . "\n";
        }
        
        echo "\n";
    }
    
    private function testPrivacyProtectionMeasures()
    {
        echo "Testing privacy protection measures assessment...\n";
        
        try {
            $gdpr_audit = new GDPRComplianceAudit();
            $reflection = new ReflectionClass($gdpr_audit);
            
            // Test privacy policy implementation review
            $method = $reflection->getMethod('reviewPrivacyPolicyImplementation');
            $method->setAccessible(true);
            $method->invoke($gdpr_audit);
            
            echo "✓ Privacy policy implementation review: PASS\n";
            
            // Test data breach notification procedures check
            $method = $reflection->getMethod('checkDataBreachNotificationProcedures');
            $method->setAccessible(true);
            $method->invoke($gdpr_audit);
            
            echo "✓ Data breach notification procedures check: PASS\n";
            
            // Test privacy by design implementation examination
            $method = $reflection->getMethod('examinePrivacyByDesignImplementation');
            $method->setAccessible(true);
            $method->invoke($gdpr_audit);
            
            echo "✓ Privacy by design implementation examination: PASS\n";
            
            $this->test_results['privacy_protection_measures'] = array(
                'status' => 'PASS',
                'message' => 'All privacy protection measures tests passed'
            );
            
        } catch (Exception $e) {
            $this->test_results['privacy_protection_measures'] = array(
                'status' => 'FAIL',
                'message' => 'Privacy protection measures test failed: ' . $e->getMessage()
            );
            echo "✗ Privacy protection measures: FAIL - " . $e->getMessage() . "\n";
        }
        
        echo "\n";
    }
    
    private function testFullGDPRAssessment()
    {
        echo "Testing full GDPR compliance assessment...\n";
        
        try {
            $gdpr_audit = new GDPRComplianceAudit();
            $report = $gdpr_audit->conductGDPRAssessment();
            
            if (is_array($report) && isset($report['audit_info'])) {
                echo "✓ Full GDPR assessment completed successfully\n";
                echo "✓ GDPR compliance status: " . $report['gdpr_compliance_status'] . "\n";
                echo "✓ Total findings: " . $report['audit_info']['total_findings'] . "\n";
                
                $this->test_results['full_gdpr_assessment'] = array(
                    'status' => 'PASS',
                    'message' => 'Full GDPR assessment completed',
                    'compliance_status' => $report['gdpr_compliance_status'],
                    'total_findings' => $report['audit_info']['total_findings']
                );
                
                // Display sample findings
                if (!empty($report['findings_by_category'])) {
                    echo "\nSample GDPR findings by category:\n";
                    foreach ($report['findings_by_category'] as $category => $findings) {
                        echo "- " . $category . ": " . count($findings) . " findings\n";
                    }
                }
                
            } else {
                throw new Exception('Invalid report format returned');
            }
            
        } catch (Exception $e) {
            $this->test_results['full_gdpr_assessment'] = array(
                'status' => 'FAIL',
                'message' => 'Full GDPR assessment failed: ' . $e->getMessage()
            );
            echo "✗ Full GDPR assessment: FAIL - " . $e->getMessage() . "\n";
        }
        
        echo "\n";
    }
    
    private function displayTestResults()
    {
        echo "=== Test Results Summary ===\n";
        
        $total_tests = count($this->test_results);
        $passed_tests = 0;
        
        foreach ($this->test_results as $test_name => $result) {
            $status_symbol = ($result['status'] === 'PASS') ? '✓' : '✗';
            echo $status_symbol . " " . str_replace('_', ' ', ucfirst($test_name)) . ": " . $result['status'] . "\n";
            
            if ($result['status'] === 'PASS') {
                $passed_tests++;
            }
        }
        
        echo "\nOverall: {$passed_tests}/{$total_tests} tests passed\n";
        
        if ($passed_tests === $total_tests) {
            echo "🎉 All GDPR compliance tests passed!\n";
        } else {
            echo "⚠️  Some GDPR compliance tests failed. Please review the implementation.\n";
        }
    }
    
    public function generateSampleGDPRReport()
    {
        echo "\n=== Generating Sample GDPR Compliance Report ===\n";
        
        try {
            $gdpr_audit = new GDPRComplianceAudit();
            $report = $gdpr_audit->conductGDPRAssessment();
            
            // Save report to file
            $report_file = dirname(__FILE__) . '/gdpr_compliance_report.json';
            file_put_contents($report_file, json_encode($report, JSON_PRETTY_PRINT));
            
            echo "✓ GDPR compliance report generated: {$report_file}\n";
            
            // Display key metrics
            echo "\nKey GDPR Compliance Metrics:\n";
            echo "- Compliance Status: " . $report['gdpr_compliance_status'] . "\n";
            echo "- Total Findings: " . $report['audit_info']['total_findings'] . "\n";
            echo "- Critical Issues: " . $report['audit_info']['severity_breakdown']['critical'] . "\n";
            echo "- High Priority Issues: " . $report['audit_info']['severity_breakdown']['high'] . "\n";
            
            // Display recommendations
            if (!empty($report['recommendations'])) {
                echo "\nImmediate Actions Required:\n";
                foreach ($report['recommendations']['immediate_actions'] as $action) {
                    echo "- " . $action . "\n";
                }
            }
            
            return $report_file;
            
        } catch (Exception $e) {
            echo "✗ Failed to generate GDPR report: " . $e->getMessage() . "\n";
            return false;
        }
    }
}

// Run tests if script is executed directly
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    $tester = new GDPRComplianceTest();
    $results = $tester->runAllTests();
    $report_file = $tester->generateSampleGDPRReport();
    
    echo "\n=== GDPR Compliance Assessment Complete ===\n";
    echo "Test results and sample report have been generated.\n";
    
    if ($report_file) {
        echo "Review the detailed GDPR compliance report at: {$report_file}\n";
    }
}