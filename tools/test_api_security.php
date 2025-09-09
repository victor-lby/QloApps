<?php
/**
 * Test API Security Assessment
 * 
 * Test script to verify API security assessment functionality
 */

// Include PrestaShop bootstrap
require_once(dirname(__FILE__) . '/../config/config.inc.php');

// Include security audit classes
require_once(dirname(__FILE__) . '/../classes/SecurityAudit.php');
require_once(dirname(__FILE__) . '/../classes/SecurityFinding.php');
require_once(dirname(__FILE__) . '/../classes/SecurityAuditUtils.php');
require_once(dirname(__FILE__) . '/../classes/SecurityScanner.php');

echo "=== API Security Assessment Test ===\n\n";

try {
    // Create test audit
    $audit = new SecurityAudit();
    $audit->audit_name = 'API Security Test ' . date('Y-m-d H:i:s');
    $audit->status = 'running';
    
    if (!$audit->save()) {
        throw new Exception('Could not create test audit');
    }
    
    echo "Created test audit ID: {$audit->id}\n\n";
    
    // Initialize scanner
    $scanner = new SecurityScanner($audit->id);
    
    // Test API authentication analysis (Task 6.1)
    echo "Testing API Authentication Analysis (Task 6.1)...\n";
    $auth_findings = $scanner->analyzeApiAuthentication();
    echo "Found " . count($auth_findings) . " authentication issues:\n";
    
    foreach ($auth_findings as $finding) {
        if ($finding instanceof SecurityFinding) {
            echo "  - {$finding->title} (Severity: {$finding->severity})\n";
        } else {
            echo "  - {$finding['title']} (Severity: {$finding['severity']})\n";
        }
    }
    echo "\n";
    
    // Test API input validation (Task 6.2)
    echo "Testing API Input Validation (Task 6.2)...\n";
    $validation_findings = $scanner->testApiInputValidation();
    echo "Found " . count($validation_findings) . " input validation issues:\n";
    
    foreach ($validation_findings as $finding) {
        if ($finding instanceof SecurityFinding) {
            echo "  - {$finding->title} (Severity: {$finding->severity})\n";
        } else {
            echo "  - {$finding['title']} (Severity: {$finding['severity']})\n";
        }
    }
    echo "\n";
    
    // Test complete API security assessment
    echo "Testing Complete API Security Assessment...\n";
    $api_findings = $scanner->performApiSecurityAssessment();
    echo "Found " . count($api_findings) . " total API security issues:\n";
    
    $categories = [];
    foreach ($api_findings as $finding) {
        $category = $finding instanceof SecurityFinding ? $finding->category : $finding['category'];
        if (!isset($categories[$category])) {
            $categories[$category] = 0;
        }
        $categories[$category]++;
    }
    
    foreach ($categories as $category => $count) {
        echo "  - {$category}: {$count} issues\n";
    }
    echo "\n";
    
    // Save findings to database
    echo "Saving findings to database...\n";
    $saved_count = 0;
    foreach ($api_findings as $finding) {
        if ($finding instanceof SecurityFinding) {
            $finding->id_audit = $audit->id;
            if ($finding->save()) {
                $saved_count++;
            }
        } else {
            if (SecurityFinding::createFinding($audit->id, $finding)) {
                $saved_count++;
            }
        }
    }
    
    echo "Saved {$saved_count} findings to database\n\n";
    
    // Update audit status
    $audit->status = 'completed';
    $audit->save();
    
    // Show detailed findings
    echo "=== Detailed Findings ===\n";
    $findings = SecurityFinding::getByAuditId($audit->id);
    
    foreach ($findings as $finding) {
        echo "\nTitle: {$finding['title']}\n";
        echo "Severity: {$finding['severity']}\n";
        echo "Category: {$finding['category']}\n";
        echo "Description: " . strip_tags($finding['description']) . "\n";
        echo "Fix: {$finding['fix_specification']}\n";
        echo "Files: " . implode(', ', json_decode($finding['affected_files'], true)) . "\n";
        echo str_repeat('-', 50) . "\n";
    }
    
    echo "\n=== Test Completed Successfully ===\n";
    echo "Audit ID: {$audit->id}\n";
    echo "Total findings: " . count($findings) . "\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}