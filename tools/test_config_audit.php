<?php
/**
 * Test Configuration Security Audit
 * 
 * This script tests the configuration and infrastructure security review functionality
 */

// Include QloApps bootstrap
require_once(dirname(__FILE__) . '/../config/config.inc.php');

// Test configuration security audit
function testConfigurationSecurityAudit()
{
    echo "=== Testing Configuration Security Audit ===\n\n";
    
    try {
        // Create a new security audit
        $audit = new SecurityAudit();
        $audit->audit_name = 'Configuration Security Test - ' . date('Y-m-d H:i:s');
        $audit->save();
        
        echo "Created audit: {$audit->audit_name} (ID: {$audit->id})\n\n";
        
        // Initialize security scanner
        $scanner = new SecurityScanner($audit->id);
        
        // Test configuration security review
        echo "Running configuration security review...\n";
        $config_findings = $scanner->conductConfigurationSecurityReview();
        
        echo "Found " . count($config_findings) . " configuration security issues:\n\n";
        
        // Display findings
        foreach ($config_findings as $index => $finding) {
            echo "Finding " . ($index + 1) . ":\n";
            echo "  Title: " . $finding['title'] . "\n";
            echo "  Severity: " . SecurityAudit::getSeverityName($finding['severity']) . "\n";
            echo "  Category: " . $finding['category'] . "\n";
            echo "  Business Impact: " . $finding['business_impact'] . "\n";
            echo "  Fix: " . $finding['fix_specification'] . "\n";
            
            if (!empty($finding['affected_files'])) {
                echo "  Affected Files: " . implode(', ', $finding['affected_files']) . "\n";
            }
            
            echo "\n";
        }
        
        // Test individual components
        echo "\n=== Testing Individual Components ===\n\n";
        
        // Test system configuration audit
        echo "Testing system configuration audit...\n";
        $system_config_findings = $scanner->auditSystemConfigurations();
        echo "System configuration findings: " . count($system_config_findings) . "\n\n";
        
        // Test file system security assessment
        echo "Testing file system security assessment...\n";
        $filesystem_findings = $scanner->assessFileSystemSecurity();
        echo "File system security findings: " . count($filesystem_findings) . "\n\n";
        
        // Test error handling evaluation
        echo "Testing error handling evaluation...\n";
        $error_handling_findings = $scanner->evaluateErrorHandlingAndInfoDisclosure();
        echo "Error handling findings: " . count($error_handling_findings) . "\n\n";
        
        // Update audit statistics
        $audit->updateStatistics();
        $summary = $audit->getSummary();
        
        echo "=== Audit Summary ===\n";
        echo "Total Findings: " . $summary['total_findings'] . "\n";
        echo "Risk Level: " . $summary['risk_level'] . "\n";
        echo "Severity Breakdown:\n";
        echo "  Critical: " . $summary['severity_breakdown']['critical'] . "\n";
        echo "  High: " . $summary['severity_breakdown']['high'] . "\n";
        echo "  Medium: " . $summary['severity_breakdown']['medium'] . "\n";
        echo "  Low: " . $summary['severity_breakdown']['low'] . "\n";
        echo "  Info: " . $summary['severity_breakdown']['info'] . "\n";
        
        return true;
        
    } catch (Exception $e) {
        echo "Error during configuration audit test: " . $e->getMessage() . "\n";
        echo "Stack trace: " . $e->getTraceAsString() . "\n";
        return false;
    }
}

// Test specific configuration file analysis
function testConfigurationFileAnalysis()
{
    echo "\n=== Testing Configuration File Analysis ===\n\n";
    
    try {
        $scanner = new SecurityScanner();
        
        // Test configuration files
        $config_files = array(
            _PS_ROOT_DIR_ . '/config/config.inc.php',
            _PS_ROOT_DIR_ . '/config/defines.inc.php'
        );
        
        foreach ($config_files as $config_file) {
            if (file_exists($config_file)) {
                echo "Analyzing: " . basename($config_file) . "\n";
                
                // Check file permissions
                $perms = fileperms($config_file);
                $octal_perms = substr(sprintf('%o', $perms), -4);
                echo "  Permissions: " . $octal_perms . "\n";
                
                // Scan content (using reflection to access private method)
                $reflection = new ReflectionClass($scanner);
                $method = $reflection->getMethod('scanConfigurationFileContent');
                $method->setAccessible(true);
                
                $vulnerabilities = $method->invoke($scanner, $config_file);
                echo "  Security issues found: " . count($vulnerabilities) . "\n";
                
                foreach ($vulnerabilities as $vuln) {
                    echo "    - " . $vuln['description'] . " (Severity: " . SecurityAudit::getSeverityName($vuln['severity']) . ")\n";
                }
                
                echo "\n";
            } else {
                echo "Configuration file not found: " . basename($config_file) . "\n\n";
            }
        }
        
        return true;
        
    } catch (Exception $e) {
        echo "Error during configuration file analysis: " . $e->getMessage() . "\n";
        return false;
    }
}

// Test .htaccess security analysis
function testHtaccessSecurityAnalysis()
{
    echo "\n=== Testing .htaccess Security Analysis ===\n\n";
    
    try {
        $scanner = new SecurityScanner();
        
        // Test .htaccess files
        $htaccess_files = array(
            _PS_ROOT_DIR_ . '/.htaccess' => 'Root directory',
            _PS_ROOT_DIR_ . '/admin/.htaccess' => 'Admin directory',
            _PS_ROOT_DIR_ . '/config/.htaccess' => 'Config directory',
            _PS_ROOT_DIR_ . '/cache/.htaccess' => 'Cache directory',
            _PS_ROOT_DIR_ . '/log/.htaccess' => 'Log directory'
        );
        
        foreach ($htaccess_files as $htaccess_file => $description) {
            echo "Checking .htaccess: " . $description . "\n";
            
            if (file_exists($htaccess_file)) {
                echo "  Status: Found\n";
                
                // Analyze content using reflection
                $reflection = new ReflectionClass($scanner);
                $method = $reflection->getMethod('analyzeHtaccessSecurity');
                $method->setAccessible(true);
                
                $issues = $method->invoke($scanner, $htaccess_file);
                echo "  Security issues: " . count($issues) . "\n";
                
                foreach ($issues as $issue) {
                    echo "    - " . $issue['description'] . "\n";
                }
            } else {
                echo "  Status: Missing (potential security issue)\n";
            }
            
            echo "\n";
        }
        
        return true;
        
    } catch (Exception $e) {
        echo "Error during .htaccess analysis: " . $e->getMessage() . "\n";
        return false;
    }
}

// Test file permission analysis
function testFilePermissionAnalysis()
{
    echo "\n=== Testing File Permission Analysis ===\n\n";
    
    try {
        // Test critical files and directories
        $critical_paths = array(
            _PS_ROOT_DIR_ . '/config/' => 'directory',
            _PS_ROOT_DIR_ . '/config/config.inc.php' => 'file',
            _PS_ROOT_DIR_ . '/classes/' => 'directory',
            _PS_ROOT_DIR_ . '/admin/' => 'directory'
        );
        
        foreach ($critical_paths as $path => $type) {
            if (file_exists($path)) {
                $perms = fileperms($path);
                $octal_perms = substr(sprintf('%o', $perms), -4);
                
                echo basename($path) . " ({$type}):\n";
                echo "  Permissions: " . $octal_perms . "\n";
                
                // Check if permissions are secure
                $max_perm = ($type === 'directory') ? '0755' : '0644';
                if ($octal_perms > $max_perm) {
                    echo "  Status: INSECURE (recommended: {$max_perm} or lower)\n";
                } else {
                    echo "  Status: Secure\n";
                }
                
                echo "\n";
            }
        }
        
        return true;
        
    } catch (Exception $e) {
        echo "Error during file permission analysis: " . $e->getMessage() . "\n";
        return false;
    }
}

// Main execution
echo "QloApps Configuration Security Audit Test\n";
echo "=========================================\n\n";

$success = true;

// Run tests
$success &= testConfigurationSecurityAudit();
$success &= testConfigurationFileAnalysis();
$success &= testHtaccessSecurityAnalysis();
$success &= testFilePermissionAnalysis();

echo "\n=== Test Results ===\n";
if ($success) {
    echo "All configuration security audit tests completed successfully!\n";
    exit(0);
} else {
    echo "Some tests failed. Please check the output above.\n";
    exit(1);
}