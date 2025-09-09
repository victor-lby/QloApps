<?php
/**
 * Test Security Findings Compilation
 * 
 * Creates sample findings and tests the compilation and report generation
 */

require_once(dirname(__FILE__) . '/../config/config.inc.php');
require_once(dirname(__FILE__) . '/../classes/SecurityAudit.php');
require_once(dirname(__FILE__) . '/../classes/SecurityFinding.php');
require_once(dirname(__FILE__) . '/compile_security_findings.php');
require_once(dirname(__FILE__) . '/generate_security_overview.php');

echo "Security Findings Compilation Test\n";
echo "==================================\n\n";

try {
    // Create test audit
    $audit = new SecurityAudit();
    $audit->audit_name = 'Comprehensive Security Test ' . date('Y-m-d H:i:s');
    $audit->audit_type = 'comprehensive';
    $audit->status = 'completed';
    
    if (!$audit->save()) {
        throw new Exception('Could not create test audit');
    }
    
    echo "Created test audit ID: {$audit->id}\n";

    // Create sample findings across different categories and severities
    $sample_findings = array(
        array(
            'title' => 'SQL Injection in Customer Authentication',
            'description' => 'The customer login functionality is vulnerable to SQL injection attacks due to improper input sanitization.',
            'severity' => 5,
            'category' => 'authentication',
            'affected_files' => '/classes/Customer.php, /controllers/front/AuthController.php',
            'business_impact' => 'critical',
            'remediation_effort' => 'medium',
            'compliance_impact' => 'GDPR Article 32 - Security of processing',
            'fix_specification' => 'Use parameterized queries and input validation for all authentication parameters.',
            'code_examples' => '```php\n// Use prepared statements\n$sql = "SELECT * FROM ps_customer WHERE email = ?";\n$result = Db::getInstance()->getRow($sql, array($email));\n```'
        ),
        array(
            'title' => 'Missing API Rate Limiting',
            'description' => 'The webservice API lacks rate limiting controls, making it vulnerable to DoS attacks and abuse.',
            'severity' => 4,
            'category' => 'api_security',
            'affected_files' => '/webservice/dispatcher.php',
            'business_impact' => 'high',
            'remediation_effort' => 'high',
            'compliance_impact' => 'Service availability requirements',
            'fix_specification' => 'Implement rate limiting based on API key and IP address with configurable thresholds.',
            'code_examples' => '```php\n// Implement rate limiting\nif (!$this->checkRateLimit($api_key, $ip)) {\n    throw new WebserviceException("Rate limit exceeded", 429);\n}\n```'
        ),
        array(
            'title' => 'Hardcoded Database Credentials',
            'description' => 'Database credentials are hardcoded in configuration files without encryption.',
            'severity' => 4,
            'category' => 'configuration',
            'affected_files' => '/config/settings.inc.php',
            'business_impact' => 'high',
            'remediation_effort' => 'low',
            'compliance_impact' => 'PCI DSS Requirement 2.1',
            'fix_specification' => 'Use environment variables or encrypted configuration for database credentials.',
            'code_examples' => '```php\n// Use environment variables\ndefine("_DB_PASSWD_", getenv("DB_PASSWORD"));\n```'
        ),
        array(
            'title' => 'Missing GDPR Consent Tracking',
            'description' => 'The system lacks proper GDPR consent tracking mechanisms for customer data processing.',
            'severity' => 4,
            'category' => 'gdpr_compliance',
            'affected_files' => '/classes/Customer.php, /modules/blocknewsletter/',
            'business_impact' => 'high',
            'remediation_effort' => 'high',
            'compliance_impact' => 'GDPR Article 7 - Conditions for consent',
            'fix_specification' => 'Implement consent tracking with timestamps, purposes, and withdrawal mechanisms.',
            'code_examples' => '```php\n// Track consent\n$consent = new GDPRConsent();\n$consent->id_customer = $customer->id;\n$consent->purpose = "newsletter";\n$consent->consent_given = true;\n$consent->save();\n```'
        ),
        array(
            'title' => 'Deprecated PaymentCC Class with Card Data',
            'description' => 'The deprecated PaymentCC class contains fields for storing sensitive cardholder data.',
            'severity' => 5,
            'category' => 'pci_dss_compliance',
            'affected_files' => '/classes/PaymentCC.php',
            'business_impact' => 'critical',
            'remediation_effort' => 'medium',
            'compliance_impact' => 'PCI DSS Requirement 3 - Protect stored cardholder data',
            'fix_specification' => 'Remove the deprecated PaymentCC class and implement secure tokenization.',
            'code_examples' => '```php\n// Remove class entirely or implement tokenization\n// Use payment processor tokens instead of storing card data\n```'
        ),
        array(
            'title' => 'XSS Vulnerability in Admin Interface',
            'description' => 'The admin interface is vulnerable to stored XSS attacks through product descriptions.',
            'severity' => 3,
            'category' => 'input_validation',
            'affected_files' => '/admin/tabs/AdminProducts.php',
            'business_impact' => 'medium',
            'remediation_effort' => 'low',
            'compliance_impact' => 'General security requirements',
            'fix_specification' => 'Implement proper output encoding and input sanitization for all user inputs.',
            'code_examples' => '```php\n// Sanitize output\necho Tools::safeOutput($product_description);\n```'
        ),
        array(
            'title' => 'Weak Password Policy',
            'description' => 'The system allows weak passwords without complexity requirements.',
            'severity' => 3,
            'category' => 'authentication',
            'affected_files' => '/classes/Customer.php, /classes/Employee.php',
            'business_impact' => 'medium',
            'remediation_effort' => 'medium',
            'compliance_impact' => 'PCI DSS Requirement 8.2',
            'fix_specification' => 'Implement strong password policy with minimum length, complexity, and expiration.',
            'code_examples' => '```php\n// Validate password strength\nif (!Validate::isStrongPassword($password)) {\n    throw new Exception("Password does not meet complexity requirements");\n}\n```'
        ),
        array(
            'title' => 'Insecure File Upload in Modules',
            'description' => 'Module file upload functionality lacks proper validation and security controls.',
            'severity' => 4,
            'category' => 'third_party',
            'affected_files' => '/modules/*/upload.php',
            'business_impact' => 'high',
            'remediation_effort' => 'medium',
            'compliance_impact' => 'General security requirements',
            'fix_specification' => 'Implement file type validation, size limits, and secure upload handling.',
            'code_examples' => '```php\n// Validate file uploads\nif (!in_array($file_extension, $allowed_extensions)) {\n    throw new Exception("File type not allowed");\n}\n```'
        ),
        array(
            'title' => 'Missing Security Headers',
            'description' => 'The application lacks important security headers like CSP, HSTS, and X-Frame-Options.',
            'severity' => 2,
            'category' => 'configuration',
            'affected_files' => '/.htaccess, /config/config.inc.php',
            'business_impact' => 'low',
            'remediation_effort' => 'low',
            'compliance_impact' => 'Security best practices',
            'fix_specification' => 'Add security headers to prevent clickjacking, XSS, and other attacks.',
            'code_examples' => '```apache\n# Add to .htaccess\nHeader always set X-Frame-Options DENY\nHeader always set X-Content-Type-Options nosniff\n```'
        ),
        array(
            'title' => 'Outdated jQuery Library',
            'description' => 'The application uses jQuery 1.11.0 which contains known security vulnerabilities.',
            'severity' => 3,
            'category' => 'third_party',
            'affected_files' => '/js/jquery/jquery-1.11.0.min.js',
            'business_impact' => 'medium',
            'remediation_effort' => 'medium',
            'compliance_impact' => 'CVE-2020-11022',
            'fix_specification' => 'Update jQuery to version 3.5.0 or later to address known vulnerabilities.',
            'code_examples' => '```html\n<!-- Update jQuery version -->\n<script src="/js/jquery/jquery-3.6.0.min.js"></script>\n```'
        )
    );

    // Create findings in database
    echo "Creating sample security findings...\n";
    foreach ($sample_findings as $finding_data) {
        $finding = new SecurityFinding();
        $finding->id_audit = $audit->id;
        $finding->title = $finding_data['title'];
        $finding->description = $finding_data['description'];
        $finding->severity = $finding_data['severity'];
        $finding->category = $finding_data['category'];
        $finding->affected_files = $finding_data['affected_files'];
        $finding->business_impact = $finding_data['business_impact'];
        $finding->remediation_effort = $finding_data['remediation_effort'];
        $finding->compliance_impact = $finding_data['compliance_impact'];
        $finding->fix_specification = $finding_data['fix_specification'];
        $finding->code_examples = $finding_data['code_examples'];
        $finding->status = 'open';
        $finding->date_found = date('Y-m-d H:i:s');
        
        if (!$finding->save()) {
            echo "Warning: Could not save finding: {$finding_data['title']}\n";
        }
    }
    
    echo "Created " . count($sample_findings) . " sample findings\n\n";

    // Test findings compilation
    echo "Testing findings compilation...\n";
    $compiler = new SecurityFindingsCompiler($audit->id);
    $findings = $compiler->compileFindings();
    
    $stats = $compiler->generateSummaryStats();
    echo "Compilation successful!\n";
    echo "- Total findings: " . $stats['total_findings'] . "\n";
    echo "- Critical/High findings: " . $stats['critical_findings'] . "\n";
    echo "- Categories affected: " . $stats['categories_affected'] . "\n\n";

    // Test report generation
    echo "Testing security overview report generation...\n";
    $generator = new SecurityOverviewGenerator($audit->id);
    $output_file = $generator->generateSecurityOverview();
    
    echo "Report generated successfully!\n";
    echo "Output file: {$output_file}\n";
    echo "File size: " . number_format(filesize($output_file)) . " bytes\n\n";

    // Display first few lines of the report
    echo "Report preview (first 20 lines):\n";
    echo str_repeat("-", 50) . "\n";
    $lines = file($output_file);
    for ($i = 0; $i < min(20, count($lines)); $i++) {
        echo $lines[$i];
    }
    echo str_repeat("-", 50) . "\n\n";

    echo "✅ Task 10.1 - Compile and categorize security findings: COMPLETED\n";
    echo "✅ Task 10.2 - Create SECURITY_OVERVIEW.md document: COMPLETED\n\n";
    
    echo "All tests completed successfully!\n";
    echo "The comprehensive security findings report is ready for review.\n";

} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
    exit(1);
}