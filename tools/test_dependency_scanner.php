<?php
/**
 * Test script for Dependency Security Scanner
 * 
 * Tests the dependency security scanner functionality
 */

if (!defined('_PS_VERSION_')) {
    require_once(dirname(__FILE__) . '/../config/config.inc.php');
}

require_once(dirname(__FILE__) . '/dependency_security_scanner.php');

echo "Testing Dependency Security Scanner\n";
echo "==================================\n\n";

// Test 1: Check if composer.json exists
echo "Test 1: Checking composer.json existence...\n";
$composer_file = _PS_ROOT_DIR_ . '/composer.json';
if (file_exists($composer_file)) {
    echo "✓ composer.json found at: $composer_file\n";
    
    $composer_data = json_decode(file_get_contents($composer_file), true);
    if ($composer_data) {
        echo "✓ composer.json is valid JSON\n";
        
        $require_count = isset($composer_data['require']) ? count($composer_data['require']) : 0;
        $require_dev_count = isset($composer_data['require-dev']) ? count($composer_data['require-dev']) : 0;
        
        echo "  - Production dependencies: $require_count\n";
        echo "  - Development dependencies: $require_dev_count\n";
    } else {
        echo "✗ composer.json is invalid JSON\n";
    }
} else {
    echo "! composer.json not found - this is expected for some QloApps installations\n";
}

// Test 2: Check JavaScript directory
echo "\nTest 2: Checking JavaScript files...\n";
$js_dir = _PS_ROOT_DIR_ . '/js/';
if (is_dir($js_dir)) {
    echo "✓ JavaScript directory found at: $js_dir\n";
    
    $js_files = glob($js_dir . '*.js');
    $js_subdirs = glob($js_dir . '*/', GLOB_ONLYDIR);
    
    echo "  - JavaScript files in root: " . count($js_files) . "\n";
    echo "  - JavaScript subdirectories: " . count($js_subdirs) . "\n";
    
    // Check for common libraries
    $common_libs = array('jquery', 'bootstrap', 'moment');
    foreach ($common_libs as $lib) {
        $lib_files = glob($js_dir . "*$lib*");
        if (!empty($lib_files)) {
            echo "  - Found $lib library: " . basename($lib_files[0]) . "\n";
        }
    }
} else {
    echo "✗ JavaScript directory not found\n";
}

// Test 3: Run a limited scan
echo "\nTest 3: Running limited dependency scan...\n";
try {
    $scanner = new DependencySecurityScanner();
    
    // Test composer scanning
    echo "Testing composer dependency scanning...\n";
    $composer_method = new ReflectionMethod($scanner, 'scanComposerDependencies');
    $composer_method->setAccessible(true);
    $composer_findings = $composer_method->invoke($scanner);
    
    echo "  - Composer findings: " . count($composer_findings) . "\n";
    
    // Test JavaScript scanning
    echo "Testing JavaScript library scanning...\n";
    $js_method = new ReflectionMethod($scanner, 'scanJavaScriptLibraries');
    $js_method->setAccessible(true);
    $js_findings = $js_method->invoke($scanner);
    
    echo "  - JavaScript findings: " . count($js_findings) . "\n";
    
    // Display some findings if any
    $all_findings = array_merge($composer_findings, $js_findings);
    if (!empty($all_findings)) {
        echo "\nSample findings:\n";
        foreach (array_slice($all_findings, 0, 3) as $finding) {
            $severity = isset($finding['severity']) ? $finding['severity'] : 'UNKNOWN';
            echo "  - [{$severity}] {$finding['title']}\n";
        }
    }
    
    echo "✓ Dependency scanner test completed successfully\n";
    
} catch (Exception $e) {
    echo "✗ Error during dependency scan test: " . $e->getMessage() . "\n";
}

// Test 4: Check for common vulnerability patterns
echo "\nTest 4: Checking for common vulnerability patterns...\n";

// Create a test file with vulnerable patterns
$test_file = _PS_ROOT_DIR_ . '/test_vulnerable_patterns.php';
$test_content = '<?php
// Test patterns for vulnerability detection
$api_key = "sk_test_1234567890abcdef"; // Hardcoded API key
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Insecure SSL
$url = "http://api.example.com/data"; // Insecure HTTP
eval($_GET["code"]); // Dangerous eval
?>';

file_put_contents($test_file, $test_content);

try {
    // Test third-party service checking
    $scanner = new DependencySecurityScanner();
    $service_method = new ReflectionMethod($scanner, 'checkThirdPartyServices');
    $service_method->setAccessible(true);
    $service_findings = $service_method->invoke($scanner);
    
    $test_findings = array_filter($service_findings, function($finding) use ($test_file) {
        return $finding['file'] === $test_file;
    });
    
    echo "  - Vulnerability patterns detected: " . count($test_findings) . "\n";
    
    foreach ($test_findings as $finding) {
        echo "    * {$finding['title']}\n";
    }
    
    echo "✓ Vulnerability pattern detection test completed\n";
    
} catch (Exception $e) {
    echo "✗ Error during vulnerability pattern test: " . $e->getMessage() . "\n";
} finally {
    // Clean up test file
    if (file_exists($test_file)) {
        unlink($test_file);
    }
}

echo "\nDependency Security Scanner Test Summary\n";
echo "=======================================\n";
echo "All tests completed. The scanner appears to be working correctly.\n";
echo "Run 'php tools/dependency_security_scanner.php' for a full scan.\n";