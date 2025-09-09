<?php
/**
 * Test script for data protection and encryption security assessment
 */

// Define constants for testing
define('_PS_VERSION_', '1.7.8.0');
define('_PS_CLASS_DIR_', './classes/');
define('_PS_MODULE_DIR_', './modules/');
define('_DB_PREFIX_', 'ps_');

// Include required classes
require_once('./classes/SecurityAudit.php');
require_once('./classes/SecurityFinding.php');
require_once('./classes/SecurityScanner.php');
require_once('./classes/SecurityAuditUtils.php');

try {
    echo "Testing Data Protection and Encryption Security Assessment...\n\n";
    
    // Create a test audit
    $audit = new SecurityAudit();
    $audit->audit_type = 'data_protection_test';
    $audit->status = 'in_progress';
    $audit->save();
    
    echo "Created test audit with ID: " . $audit->id . "\n";
    
    // Create scanner instance
    $scanner = new SecurityScanner($audit->id);
    
    // Test data protection assessment
    echo "Running data protection assessment...\n";
    $findings = $scanner->assessDataProtectionSecurity();
    
    echo "Found " . count($findings) . " data protection findings:\n\n";
    
    foreach ($findings as $finding) {
        if ($finding instanceof SecurityFinding) {
            echo "- " . $finding->title . " (Severity: " . $finding->severity . ")\n";
            echo "  Category: " . $finding->category . "\n";
            echo "  Files: " . implode(', ', $finding->affected_files) . "\n";
            echo "  Impact: " . $finding->business_impact . "\n\n";
        } else {
            echo "- " . $finding['title'] . " (Severity: " . $finding['severity'] . ")\n";
            echo "  Category: " . $finding['category'] . "\n\n";
        }
    }
    
    echo "Data protection assessment completed successfully!\n";
    
} catch (Exception $e) {
    echo "Error during testing: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}