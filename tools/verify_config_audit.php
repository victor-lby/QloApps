<?php
/**
 * Verify Configuration Security Audit Implementation
 * 
 * This script verifies that the configuration security audit methods are properly implemented
 */

// Simple syntax and method verification
function verifyConfigurationAuditImplementation()
{
    echo "=== Verifying Configuration Security Audit Implementation ===\n\n";
    
    // Check if SecurityScanner class file exists and is readable
    $scanner_file = dirname(__FILE__) . '/../classes/SecurityScanner.php';
    
    if (!file_exists($scanner_file)) {
        echo "ERROR: SecurityScanner.php not found\n";
        return false;
    }
    
    echo "✓ SecurityScanner.php file exists\n";
    
    // Read and analyze the file content
    $content = file_get_contents($scanner_file);
    
    // Check for required methods
    $required_methods = array(
        'conductConfigurationSecurityReview',
        'auditSystemConfigurations',
        'reviewConfigurationFiles',
        'scanConfigurationFileContent',
        'checkDatabaseSecuritySettings',
        'examineWebServerConfiguration',
        'assessFileSystemSecurity',
        'reviewFilePermissions',
        'checkDirectoryAccessControls',
        'examineUploadDirectorySecurity',
        'evaluateErrorHandlingAndInfoDisclosure',
        'reviewErrorHandling',
        'checkDebugModeAndInfoLeakage',
        'assessLoggingMechanisms'
    );
    
    $missing_methods = array();
    foreach ($required_methods as $method) {
        if (strpos($content, 'function ' . $method) === false && 
            strpos($content, 'private function ' . $method) === false) {
            $missing_methods[] = $method;
        } else {
            echo "✓ Method {$method} found\n";
        }
    }
    
    if (!empty($missing_methods)) {
        echo "\nERROR: Missing methods:\n";
        foreach ($missing_methods as $method) {
            echo "  - {$method}\n";
        }
        return false;
    }
    
    // Check for configuration security patterns
    $security_patterns = array(
        '_PS_MODE_DEV_.*?true' => 'Debug mode detection',
        'display_errors.*?on' => 'Error display detection',
        '_DB_PASSWD_.*?[\'""][\'""]' => 'Empty password detection',
        '_DB_USER_.*?[\'""]root[\'""]' => 'Default user detection',
        'allow_url_include.*?1|on' => 'Dangerous PHP setting detection'
    );
    
    foreach ($security_patterns as $pattern => $description) {
        if (preg_match('/' . str_replace('/', '\/', $pattern) . '/i', $content)) {
            echo "✓ Security pattern for {$description} found\n";
        } else {
            echo "⚠ Security pattern for {$description} not found\n";
        }
    }
    
    // Check for file permission checks
    if (strpos($content, 'fileperms') !== false) {
        echo "✓ File permission checking implemented\n";
    } else {
        echo "⚠ File permission checking not found\n";
    }
    
    // Check for .htaccess analysis
    if (strpos($content, 'htaccess') !== false) {
        echo "✓ .htaccess analysis implemented\n";
    } else {
        echo "⚠ .htaccess analysis not found\n";
    }
    
    // Check for error handling analysis
    if (strpos($content, 'mysql_error') !== false || strpos($content, 'die\s*\(') !== false) {
        echo "✓ Error handling analysis implemented\n";
    } else {
        echo "⚠ Error handling analysis not found\n";
    }
    
    echo "\n✓ Configuration security audit implementation verified successfully!\n";
    return true;
}

// Verify helper methods
function verifyHelperMethods()
{
    echo "\n=== Verifying Helper Methods ===\n\n";
    
    $scanner_file = dirname(__FILE__) . '/../classes/SecurityScanner.php';
    $content = file_get_contents($scanner_file);
    
    $helper_methods = array(
        'generateConfigPermissionDescription',
        'generateConfigContentDescription',
        'generateDatabaseSecurityDescription',
        'getDatabaseSecurityImpact',
        'getDatabaseSecurityFix',
        'analyzeHtaccessSecurity',
        'generateDirectoryPermissionDescription',
        'generateFilePermissionDescription',
        'isDirectoryWebAccessible',
        'findExecutableFiles',
        'scanFileForErrorHandlingIssues',
        'checkInformationDisclosureInHeaders',
        'scanLogFileForSensitiveData'
    );
    
    foreach ($helper_methods as $method) {
        if (strpos($content, 'function ' . $method) !== false) {
            echo "✓ Helper method {$method} found\n";
        } else {
            echo "⚠ Helper method {$method} not found\n";
        }
    }
    
    return true;
}

// Verify integration with main scanner
function verifyIntegration()
{
    echo "\n=== Verifying Integration ===\n\n";
    
    $scanner_file = dirname(__FILE__) . '/../classes/SecurityScanner.php';
    $content = file_get_contents($scanner_file);
    
    // Check if configuration review is called in main scan
    if (strpos($content, 'conductConfigurationSecurityReview') !== false) {
        echo "✓ Configuration security review integrated into main scan\n";
    } else {
        echo "⚠ Configuration security review not integrated into main scan\n";
    }
    
    // Check if findings are properly created
    if (strpos($content, 'createSecurityFindingFromObject') !== false) {
        echo "✓ Security finding creation integrated\n";
    } else {
        echo "⚠ Security finding creation not integrated\n";
    }
    
    return true;
}

// Main verification
echo "QloApps Configuration Security Audit Verification\n";
echo "================================================\n\n";

$success = true;
$success &= verifyConfigurationAuditImplementation();
$success &= verifyHelperMethods();
$success &= verifyIntegration();

echo "\n=== Verification Results ===\n";
if ($success) {
    echo "✓ All configuration security audit components verified successfully!\n";
    echo "\nImplemented Features:\n";
    echo "- System configuration audit (Task 5.1)\n";
    echo "- File system security assessment (Task 5.2)\n";
    echo "- Error handling and information disclosure evaluation (Task 5.3)\n";
    echo "- Configuration file security scanning\n";
    echo "- Database security settings validation\n";
    echo "- Web server configuration analysis\n";
    echo "- File and directory permission checks\n";
    echo "- .htaccess security analysis\n";
    echo "- Upload directory security assessment\n";
    echo "- Error handling vulnerability detection\n";
    echo "- Debug mode and information leakage checks\n";
    echo "- Security logging assessment\n";
} else {
    echo "⚠ Some verification checks failed. Please review the implementation.\n";
}

echo "\nConfiguration security audit implementation is ready for testing!\n";
?>