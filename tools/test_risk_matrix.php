<?php
/**
 * Test Security Risk Matrix Tool
 */

require_once(dirname(__FILE__) . '/security_risk_matrix.php');

class SecurityRiskMatrixTest
{
    private $riskMatrix;
    private $testResults = array();

    public function __construct()
    {
        $this->riskMatrix = new SecurityRiskMatrix();
    }

    public function runAllTests()
    {
        echo "Running Security Risk Matrix Tests...\n\n";
        
        $this->testRiskCalculation();
        $this->testPrioritization();
        $this->testResourceEstimation();
        $this->testTimelineGeneration();
        $this->testReportGeneration();
        
        $this->displayResults();
    }

    private function testRiskCalculation()
    {
        echo "Testing risk calculation...\n";
        
        $matrix = $this->riskMatrix->getRiskMatrix();
        
        // Test that risk scores are calculated
        $this->assert(count($matrix) > 0, "Risk matrix should contain findings");
        
        foreach ($matrix as $item) {
            $this->assert(isset($item['risk_score']), "Each item should have a risk score");
            $this->assert($item['risk_score'] > 0, "Risk score should be positive");
            $this->assert($item['risk_score'] <= 5, "Risk score should not exceed 5");
        }
        
        // Test that items are sorted by risk score
        for ($i = 0; $i < count($matrix) - 1; $i++) {
            $current = $matrix[$i]['risk_score'];
            $next = $matrix[$i + 1]['risk_score'];
            $this->assert($current >= $next, "Items should be sorted by risk score (descending)");
        }
        
        echo "✓ Risk calculation tests passed\n\n";
    }

    private function testPrioritization()
    {
        echo "Testing prioritization logic...\n";
        
        $matrix = $this->riskMatrix->getRiskMatrix();
        
        // Test priority categories
        $priorityCategories = array('immediate', 'urgent', 'prompt', 'routine');
        
        foreach ($matrix as $item) {
            $this->assert(in_array($item['priority_category'], $priorityCategories), 
                         "Priority category should be valid");
        }
        
        // Test that highest risk items get immediate priority
        $highestRisk = $matrix[0];
        $this->assert($highestRisk['priority_category'] === 'immediate' || 
                     $highestRisk['priority_category'] === 'urgent',
                     "Highest risk item should have immediate or urgent priority");
        
        echo "✓ Prioritization tests passed\n\n";
    }

    private function testResourceEstimation()
    {
        echo "Testing resource estimation...\n";
        
        $resources = $this->riskMatrix->getResourceEstimates();
        
        $this->assert(isset($resources['total_hours']), "Should have total hours estimate");
        $this->assert($resources['total_hours'] > 0, "Total hours should be positive");
        
        $this->assert(isset($resources['total_days']), "Should have total days estimate");
        $this->assert($resources['total_days'] > 0, "Total days should be positive");
        
        $this->assert(isset($resources['estimated_cost']), "Should have cost estimate");
        $this->assert($resources['estimated_cost'] > 0, "Cost should be positive");
        
        $this->assert(isset($resources['skills_needed']), "Should identify skills needed");
        $this->assert(count($resources['skills_needed']) > 0, "Should need at least one skill");
        
        echo "✓ Resource estimation tests passed\n\n";
    }

    private function testTimelineGeneration()
    {
        echo "Testing timeline generation...\n";
        
        $timeline = $this->riskMatrix->getRemediationTimeline();
        
        $expectedCategories = array('immediate', 'urgent', 'prompt', 'routine');
        
        foreach ($expectedCategories as $category) {
            $this->assert(isset($timeline[$category]), "Timeline should have {$category} category");
            $this->assert(is_array($timeline[$category]), "Category should be an array");
        }
        
        // Test that immediate category has critical issues
        $immediateItems = $timeline['immediate'];
        foreach ($immediateItems as $item) {
            $this->assert($item['risk_score'] >= 4.5, "Immediate items should have high risk scores");
        }
        
        echo "✓ Timeline generation tests passed\n\n";
    }

    private function testReportGeneration()
    {
        echo "Testing report generation...\n";
        
        $report = $this->riskMatrix->generateRiskMatrixReport();
        
        $this->assert(!empty($report), "Report should not be empty");
        $this->assert(strpos($report, '# Security Risk Matrix') !== false, 
                     "Report should have proper title");
        $this->assert(strpos($report, '## Executive Summary') !== false, 
                     "Report should have executive summary");
        $this->assert(strpos($report, '## Risk Matrix') !== false, 
                     "Report should have risk matrix section");
        $this->assert(strpos($report, '## Resource Requirements') !== false, 
                     "Report should have resource requirements");
        
        echo "✓ Report generation tests passed\n\n";
    }

    private function assert($condition, $message)
    {
        if ($condition) {
            $this->testResults[] = array('status' => 'PASS', 'message' => $message);
        } else {
            $this->testResults[] = array('status' => 'FAIL', 'message' => $message);
            echo "FAIL: {$message}\n";
        }
    }

    private function displayResults()
    {
        $passed = 0;
        $failed = 0;
        
        foreach ($this->testResults as $result) {
            if ($result['status'] === 'PASS') {
                $passed++;
            } else {
                $failed++;
            }
        }
        
        echo "=== Test Results ===\n";
        echo "Passed: {$passed}\n";
        echo "Failed: {$failed}\n";
        echo "Total: " . count($this->testResults) . "\n\n";
        
        if ($failed === 0) {
            echo "✅ All tests passed!\n";
        } else {
            echo "❌ Some tests failed. Please review the output above.\n";
        }
    }
}

// Run tests if called directly
if (php_sapi_name() === 'cli') {
    $test = new SecurityRiskMatrixTest();
    $test->runAllTests();
}