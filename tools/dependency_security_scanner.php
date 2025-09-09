<?php
/**
 * Dependency Security Scanner
 * 
 * Scans composer dependencies and JavaScript libraries for known vulnerabilities
 * Checks third-party service integrations for security issues
 */

if (!defined('_PS_VERSION_')) {
    require_once(dirname(__FILE__) . '/../config/config.inc.php');
}

require_once(dirname(__FILE__) . '/../classes/SecurityAudit.php');
require_once(dirname(__FILE__) . '/../classes/SecurityFinding.php');
require_once(dirname(__FILE__) . '/../classes/SecurityAuditUtils.php');

class DependencySecurityScanner
{
    private $results;
    private $audit_id;
    private $vulnerable_packages;
    private $vulnerable_js_libs;

    public function __construct($audit_id = null)
    {
        $this->results = array();
        $this->audit_id = $audit_id;
        $this->initializeVulnerabilityDatabase();
    }

    /**
     * Initialize known vulnerability database
     */
    private function initializeVulnerabilityDatabase()
    {
        // Known vulnerable PHP packages (simplified database)
        $this->vulnerable_packages = array(
            'monolog/monolog' => array(
                'versions' => array('< 1.25.2', '< 2.1.1'),
                'cve' => 'CVE-2021-23437',
                'description' => 'Remote code execution via crafted log entries',
                'severity' => SecurityAudit::SEVERITY_CRITICAL
            ),
            'symfony/http-foundation' => array(
                'versions' => array('< 3.4.26', '< 4.2.7', '< 4.3.0'),
                'cve' => 'CVE-2019-10909',
                'description' => 'Session fixation vulnerability',
                'severity' => SecurityAudit::SEVERITY_HIGH
            ),
            'twig/twig' => array(
                'versions' => array('< 1.38.0', '< 2.7.0'),
                'cve' => 'CVE-2019-9942',
                'description' => 'Code injection via template names',
                'severity' => SecurityAudit::SEVERITY_HIGH
            ),
            'doctrine/orm' => array(
                'versions' => array('< 2.5.13', '< 2.6.4'),
                'cve' => 'CVE-2015-5723',
                'description' => 'SQL injection in ORDER BY clause',
                'severity' => SecurityAudit::SEVERITY_HIGH
            ),
            'smarty/smarty' => array(
                'versions' => array('< 3.1.33'),
                'cve' => 'CVE-2018-13982',
                'description' => 'Code injection via template compilation',
                'severity' => SecurityAudit::SEVERITY_CRITICAL
            ),
            'phpmailer/phpmailer' => array(
                'versions' => array('< 5.2.18', '< 6.0.6'),
                'cve' => 'CVE-2017-5223',
                'description' => 'Remote code execution via crafted email',
                'severity' => SecurityAudit::SEVERITY_CRITICAL
            ),
            'guzzlehttp/guzzle' => array(
                'versions' => array('< 6.2.1', '< 7.0.0'),
                'cve' => 'CVE-2016-5385',
                'description' => 'HTTP proxy header vulnerability',
                'severity' => SecurityAudit::SEVERITY_MEDIUM
            )
        );

        // Known vulnerable JavaScript libraries
        $this->vulnerable_js_libs = array(
            'jquery' => array(
                'versions' => array('< 3.5.0'),
                'cve' => 'CVE-2020-11022',
                'description' => 'XSS vulnerability in jQuery.htmlPrefilter',
                'severity' => SecurityAudit::SEVERITY_MEDIUM
            ),
            'bootstrap' => array(
                'versions' => array('< 4.3.1'),
                'cve' => 'CVE-2019-8331',
                'description' => 'XSS vulnerability in tooltip and popover',
                'severity' => SecurityAudit::SEVERITY_MEDIUM
            ),
            'moment' => array(
                'versions' => array('< 2.19.3'),
                'cve' => 'CVE-2017-18214',
                'description' => 'Regular expression denial of service',
                'severity' => SecurityAudit::SEVERITY_MEDIUM
            ),
            'lodash' => array(
                'versions' => array('< 4.17.12'),
                'cve' => 'CVE-2019-10744',
                'description' => 'Prototype pollution vulnerability',
                'severity' => SecurityAudit::SEVERITY_HIGH
            ),
            'handlebars' => array(
                'versions' => array('< 4.5.3'),
                'cve' => 'CVE-2019-19919',
                'description' => 'Arbitrary code execution via template compilation',
                'severity' => SecurityAudit::SEVERITY_CRITICAL
            )
        );
    }

    /**
     * Run comprehensive dependency security scan
     */
    public function runScan()
    {
        echo "Starting Dependency Security Scan...\n";
        echo "===================================\n\n";

        $findings = array();

        // Scan composer dependencies
        echo "Scanning Composer dependencies...\n";
        $composer_findings = $this->scanComposerDependencies();
        $findings = array_merge($findings, $composer_findings);
        echo "Found " . count($composer_findings) . " composer-related findings\n\n";

        // Scan JavaScript libraries
        echo "Scanning JavaScript libraries...\n";
        $js_findings = $this->scanJavaScriptLibraries();
        $findings = array_merge($findings, $js_findings);
        echo "Found " . count($js_findings) . " JavaScript-related findings\n\n";

        // Check third-party service integrations
        echo "Checking third-party service integrations...\n";
        $service_findings = $this->checkThirdPartyServices();
        $findings = array_merge($findings, $service_findings);
        echo "Found " . count($service_findings) . " service integration findings\n\n";

        $this->results = $findings;

        // Generate report
        $this->generateReport();

        echo "Dependency security scan completed!\n";
        echo "Total findings: " . count($findings) . "\n";

        return $findings;
    }

    /**
     * Scan composer dependencies for vulnerabilities
     */
    private function scanComposerDependencies()
    {
        $findings = array();
        $composer_file = _PS_ROOT_DIR_ . '/composer.json';
        $composer_lock = _PS_ROOT_DIR_ . '/composer.lock';

        // Check if composer.json exists
        if (!file_exists($composer_file)) {
            $findings[] = array(
                'type' => 'missing_composer',
                'title' => 'No Composer Configuration Found',
                'description' => 'No composer.json file found. Consider using Composer for dependency management.',
                'severity' => SecurityAudit::SEVERITY_LOW,
                'category' => 'configuration',
                'file' => $composer_file
            );
            return $findings;
        }

        // Parse composer.json
        $composer_data = json_decode(file_get_contents($composer_file), true);
        if (!$composer_data) {
            $findings[] = array(
                'type' => 'invalid_composer',
                'title' => 'Invalid Composer Configuration',
                'description' => 'composer.json file is not valid JSON',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'configuration',
                'file' => $composer_file
            );
            return $findings;
        }

        // Check for composer.lock file
        if (!file_exists($composer_lock)) {
            $findings[] = array(
                'type' => 'missing_lock',
                'title' => 'Missing Composer Lock File',
                'description' => 'composer.lock file is missing. This can lead to inconsistent dependency versions across environments.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => 'configuration',
                'file' => $composer_lock,
                'recommendation' => 'Run "composer install" to generate composer.lock file'
            );
        }

        // Get all dependencies
        $dependencies = array();
        if (isset($composer_data['require'])) {
            $dependencies = array_merge($dependencies, $composer_data['require']);
        }
        if (isset($composer_data['require-dev'])) {
            $dependencies = array_merge($dependencies, $composer_data['require-dev']);
        }

        // Check each dependency against vulnerability database
        foreach ($dependencies as $package => $version_constraint) {
            // Skip PHP version requirement
            if ($package === 'php' || strpos($package, 'ext-') === 0) {
                continue;
            }

            // Check against known vulnerabilities
            if (isset($this->vulnerable_packages[$package])) {
                $vuln_info = $this->vulnerable_packages[$package];
                
                // Simple version check (in production, use more sophisticated version comparison)
                $is_vulnerable = $this->isVersionVulnerable($version_constraint, $vuln_info['versions']);
                
                if ($is_vulnerable) {
                    $findings[] = array(
                        'type' => 'vulnerable_package',
                        'title' => "Vulnerable Composer Package: $package",
                        'description' => "Package $package version $version_constraint is vulnerable: {$vuln_info['description']}",
                        'severity' => $vuln_info['severity'],
                        'category' => 'third_party',
                        'file' => $composer_file,
                        'cve' => isset($vuln_info['cve']) ? $vuln_info['cve'] : null,
                        'package' => $package,
                        'current_version' => $version_constraint,
                        'recommendation' => "Update $package to a secure version"
                    );
                }
            }

            // Check for packages with known security issues
            $risky_packages = array(
                'zendframework/zend-mail' => 'Consider migrating to laminas/laminas-mail',
                'swiftmailer/swiftmailer' => 'Package is deprecated, consider symfony/mailer',
                'doctrine/annotations' => 'Check for annotation injection vulnerabilities'
            );

            if (isset($risky_packages[$package])) {
                $findings[] = array(
                    'type' => 'risky_package',
                    'title' => "Potentially Risky Package: $package",
                    'description' => $risky_packages[$package],
                    'severity' => SecurityAudit::SEVERITY_LOW,
                    'category' => 'third_party',
                    'file' => $composer_file,
                    'package' => $package
                );
            }
        }

        // Check for outdated packages if composer.lock exists
        if (file_exists($composer_lock)) {
            $lock_data = json_decode(file_get_contents($composer_lock), true);
            if ($lock_data && isset($lock_data['packages'])) {
                foreach ($lock_data['packages'] as $package_info) {
                    $package_name = $package_info['name'];
                    $installed_version = $package_info['version'];
                    
                    // Check if this is a very old version (simplified check)
                    if (isset($package_info['time'])) {
                        $package_date = strtotime($package_info['time']);
                        $two_years_ago = strtotime('-2 years');
                        
                        if ($package_date < $two_years_ago) {
                            $findings[] = array(
                                'type' => 'outdated_package',
                                'title' => "Outdated Package: $package_name",
                                'description' => "Package $package_name version $installed_version is over 2 years old and may contain security vulnerabilities",
                                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                                'category' => 'third_party',
                                'file' => $composer_lock,
                                'package' => $package_name,
                                'installed_version' => $installed_version,
                                'recommendation' => "Update $package_name to latest stable version"
                            );
                        }
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Scan JavaScript libraries for vulnerabilities
     */
    private function scanJavaScriptLibraries()
    {
        $findings = array();
        $js_dir = _PS_ROOT_DIR_ . '/js/';

        if (!is_dir($js_dir)) {
            return $findings;
        }

        // Get all JavaScript files
        $js_files = $this->getJavaScriptFiles($js_dir);

        foreach ($js_files as $file) {
            $content = file_get_contents($file);
            $filename = basename($file);

            // Check for library version information
            foreach ($this->vulnerable_js_libs as $lib_name => $vuln_info) {
                // Look for version patterns in the file
                $version_patterns = array(
                    '/version["\'\s:]*["\']\s*([0-9]+\.[0-9]+\.[0-9]+)/',
                    '/v([0-9]+\.[0-9]+\.[0-9]+)/',
                    '/@version\s+([0-9]+\.[0-9]+\.[0-9]+)/',
                    '/\* ' . preg_quote($lib_name, '/') . '\s+v?([0-9]+\.[0-9]+\.[0-9]+)/'
                );

                foreach ($version_patterns as $pattern) {
                    if (preg_match($pattern, $content, $matches)) {
                        $version = $matches[1];
                        
                        // Check if this library name is in the filename or content
                        if (stripos($filename, $lib_name) !== false || stripos($content, $lib_name) !== false) {
                            $is_vulnerable = $this->isVersionVulnerable($version, $vuln_info['versions']);
                            
                            if ($is_vulnerable) {
                                $findings[] = array(
                                    'type' => 'vulnerable_js_lib',
                                    'title' => "Vulnerable JavaScript Library: $lib_name",
                                    'description' => "Library $lib_name version $version is vulnerable: {$vuln_info['description']}",
                                    'severity' => $vuln_info['severity'],
                                    'category' => 'third_party',
                                    'file' => $file,
                                    'cve' => isset($vuln_info['cve']) ? $vuln_info['cve'] : null,
                                    'library' => $lib_name,
                                    'current_version' => $version,
                                    'recommendation' => "Update $lib_name to latest secure version"
                                );
                            }
                        }
                    }
                }
            }

            // Check for dangerous JavaScript patterns
            $dangerous_patterns = array(
                '/eval\s*\(/' => 'Use of eval() can lead to code injection',
                '/document\.write\s*\(/' => 'document.write can be dangerous with user input',
                '/innerHTML\s*=.*\+/' => 'innerHTML with concatenation can lead to XSS',
                '/setTimeout\s*\(\s*["\'][^"\']*\+/' => 'setTimeout with string concatenation can be dangerous',
                '/new\s+Function\s*\(/' => 'Function constructor can be dangerous like eval'
            );

            foreach ($dangerous_patterns as $pattern => $description) {
                if (preg_match($pattern, $content)) {
                    $findings[] = array(
                        'type' => 'dangerous_js_pattern',
                        'title' => 'Dangerous JavaScript Pattern',
                        'description' => "$description in file $filename",
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'input_validation',
                        'file' => $file,
                        'recommendation' => 'Review and replace with safer alternatives'
                    );
                }
            }

            // Check for minified files without source maps
            if (preg_match('/\.min\.js$/', $filename) && !file_exists($file . '.map')) {
                $findings[] = array(
                    'type' => 'missing_source_map',
                    'title' => 'Minified JavaScript Without Source Map',
                    'description' => "Minified file $filename lacks source map, making security analysis difficult",
                    'severity' => SecurityAudit::SEVERITY_LOW,
                    'category' => 'configuration',
                    'file' => $file,
                    'recommendation' => 'Include source maps for minified JavaScript files'
                );
            }
        }

        return $findings;
    }

    /**
     * Check third-party service integrations
     */
    private function checkThirdPartyServices()
    {
        $findings = array();

        // Scan all PHP files for third-party service integrations
        $php_files = $this->getPhpFiles(_PS_ROOT_DIR_);

        foreach ($php_files as $file) {
            // Skip large files to avoid memory issues
            if (filesize($file) > 2097152) { // 2MB
                continue;
            }

            $content = file_get_contents($file);

            // Check for insecure SSL configurations
            $ssl_patterns = array(
                '/CURLOPT_SSL_VERIFYPEER["\'\s]*=>["\'\s]*false/' => 'SSL certificate verification disabled',
                '/CURLOPT_SSL_VERIFYHOST["\'\s]*=>["\'\s]*0/' => 'SSL hostname verification disabled',
                '/curl_setopt.*CURLOPT_SSL_VERIFYPEER.*false/' => 'SSL verification disabled in cURL',
                '/verify["\'\s]*=>["\'\s]*false/' => 'SSL verification disabled in HTTP client'
            );

            foreach ($ssl_patterns as $pattern => $description) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    $line_number = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                    
                    $findings[] = array(
                        'type' => 'insecure_ssl',
                        'title' => 'Insecure SSL Configuration',
                        'description' => "$description at line $line_number",
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'configuration',
                        'file' => $file,
                        'line' => $line_number,
                        'recommendation' => 'Enable SSL certificate verification for all external connections'
                    );
                }
            }

            // Check for hardcoded API keys and secrets
            $credential_patterns = array(
                '/api[_-]?key["\'\s]*=>["\'\s]*[a-zA-Z0-9]{20,}/' => 'Hardcoded API key',
                '/secret[_-]?key["\'\s]*=>["\'\s]*[a-zA-Z0-9]{20,}/' => 'Hardcoded secret key',
                '/access[_-]?token["\'\s]*=>["\'\s]*[a-zA-Z0-9]{20,}/' => 'Hardcoded access token',
                '/client[_-]?secret["\'\s]*=>["\'\s]*[a-zA-Z0-9]{20,}/' => 'Hardcoded client secret'
            );

            foreach ($credential_patterns as $pattern => $description) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    $line_number = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                    
                    $findings[] = array(
                        'type' => 'hardcoded_credentials',
                        'title' => 'Hardcoded API Credentials',
                        'description' => "$description at line $line_number",
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => 'configuration',
                        'file' => $file,
                        'line' => $line_number,
                        'recommendation' => 'Move credentials to environment variables or secure configuration files'
                    );
                }
            }

            // Check for insecure HTTP API calls
            if (preg_match_all('/http:\/\/[a-zA-Z0-9.-]+\/(?:api|webhook|callback)/', $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $line_number = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                    
                    $findings[] = array(
                        'type' => 'insecure_http_api',
                        'title' => 'Insecure HTTP API Call',
                        'description' => "API call over insecure HTTP at line $line_number: {$match[0]}",
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => 'configuration',
                        'file' => $file,
                        'line' => $line_number,
                        'recommendation' => 'Use HTTPS for all API communications'
                    );
                }
            }

            // Check for webhook endpoints without proper validation
            if (preg_match('/webhook|callback/', $content) && !preg_match('/signature|hmac|verify/', $content)) {
                $findings[] = array(
                    'type' => 'insecure_webhook',
                    'title' => 'Insecure Webhook Implementation',
                    'description' => 'Webhook endpoint may lack proper signature verification',
                    'severity' => SecurityAudit::SEVERITY_MEDIUM,
                    'category' => 'authentication',
                    'file' => $file,
                    'recommendation' => 'Implement webhook signature verification'
                );
            }

            // Check for third-party service integrations
            $service_patterns = array(
                '/paypal\.com/' => 'PayPal integration',
                '/stripe\.com/' => 'Stripe integration',
                '/googleapis\.com/' => 'Google APIs integration',
                '/facebook\.com\/.*\/api/' => 'Facebook API integration',
                '/twitter\.com\/.*\/api/' => 'Twitter API integration',
                '/amazonaws\.com/' => 'AWS services integration'
            );

            foreach ($service_patterns as $pattern => $service) {
                if (preg_match($pattern, $content)) {
                    // This is informational - just noting the integration exists
                    $findings[] = array(
                        'type' => 'third_party_integration',
                        'title' => "Third-Party Service Integration: $service",
                        'description' => "File contains integration with $service - ensure secure implementation",
                        'severity' => SecurityAudit::SEVERITY_LOW,
                        'category' => 'third_party',
                        'file' => $file,
                        'recommendation' => 'Review integration for security best practices'
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Check if version is vulnerable (simplified version comparison)
     */
    private function isVersionVulnerable($current_version, $vulnerable_versions)
    {
        // Remove version constraint operators for simple comparison
        $current_version = preg_replace('/[^0-9.]/', '', $current_version);
        
        foreach ($vulnerable_versions as $vuln_version) {
            // Simple pattern matching - in production use proper version comparison
            if (preg_match('/< ([0-9.]+)/', $vuln_version, $matches)) {
                $min_safe_version = $matches[1];
                if (version_compare($current_version, $min_safe_version, '<')) {
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Get all JavaScript files recursively
     */
    private function getJavaScriptFiles($directory)
    {
        $files = array();
        
        if (!is_dir($directory)) {
            return $files;
        }
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'js') {
                $files[] = $file->getPathname();
            }
        }
        
        return $files;
    }

    /**
     * Get all PHP files recursively (with size limit)
     */
    private function getPhpFiles($directory)
    {
        $files = array();
        
        if (!is_dir($directory)) {
            return $files;
        }
        
        // Exclude certain directories to avoid scanning too many files
        $exclude_dirs = array('cache', 'log', 'upload', 'vendor', 'node_modules', '.git');
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                function ($file, $key, $iterator) use ($exclude_dirs) {
                    if ($iterator->hasChildren() && in_array($file->getFilename(), $exclude_dirs)) {
                        return false;
                    }
                    return true;
                }
            )
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        
        return $files;
    }

    /**
     * Generate detailed dependency security report
     */
    private function generateReport()
    {
        $report_file = _PS_ROOT_DIR_ . '/DEPENDENCY_SECURITY_REPORT.md';
        $report_content = "# Dependency Security Assessment Report\n\n";
        $report_content .= "Generated on: " . date('Y-m-d H:i:s') . "\n\n";

        // Calculate statistics
        $total_findings = count($this->results);
        $severity_counts = array(
            SecurityAudit::SEVERITY_CRITICAL => 0,
            SecurityAudit::SEVERITY_HIGH => 0,
            SecurityAudit::SEVERITY_MEDIUM => 0,
            SecurityAudit::SEVERITY_LOW => 0
        );

        $type_counts = array();

        foreach ($this->results as $finding) {
            if (isset($severity_counts[$finding['severity']])) {
                $severity_counts[$finding['severity']]++;
            }
            
            $type = $finding['type'];
            $type_counts[$type] = isset($type_counts[$type]) ? $type_counts[$type] + 1 : 1;
        }

        $report_content .= "## Executive Summary\n\n";
        $report_content .= "- **Total Findings:** $total_findings\n";
        $report_content .= "- **Critical:** {$severity_counts[SecurityAudit::SEVERITY_CRITICAL]}\n";
        $report_content .= "- **High:** {$severity_counts[SecurityAudit::SEVERITY_HIGH]}\n";
        $report_content .= "- **Medium:** {$severity_counts[SecurityAudit::SEVERITY_MEDIUM]}\n";
        $report_content .= "- **Low:** {$severity_counts[SecurityAudit::SEVERITY_LOW]}\n\n";

        $report_content .= "### Findings by Type\n\n";
        foreach ($type_counts as $type => $count) {
            $report_content .= "- **" . ucwords(str_replace('_', ' ', $type)) . ":** $count\n";
        }
        $report_content .= "\n";

        // Critical findings
        if ($severity_counts[SecurityAudit::SEVERITY_CRITICAL] > 0) {
            $report_content .= "## Critical Findings Requiring Immediate Attention\n\n";
            foreach ($this->results as $finding) {
                if ($finding['severity'] == SecurityAudit::SEVERITY_CRITICAL) {
                    $report_content .= "### {$finding['title']}\n";
                    $report_content .= "**File:** `{$finding['file']}`\n";
                    if (isset($finding['line'])) {
                        $report_content .= "**Line:** {$finding['line']}\n";
                    }
                    if (isset($finding['cve'])) {
                        $report_content .= "**CVE:** {$finding['cve']}\n";
                    }
                    $report_content .= "**Description:** {$finding['description']}\n";
                    if (isset($finding['recommendation'])) {
                        $report_content .= "**Recommendation:** {$finding['recommendation']}\n";
                    }
                    $report_content .= "\n";
                }
            }
        }

        // Detailed findings by category
        $categories = array(
            'vulnerable_package' => 'Vulnerable Composer Packages',
            'vulnerable_js_lib' => 'Vulnerable JavaScript Libraries',
            'insecure_ssl' => 'Insecure SSL Configurations',
            'hardcoded_credentials' => 'Hardcoded Credentials',
            'insecure_http_api' => 'Insecure HTTP API Calls',
            'third_party_integration' => 'Third-Party Service Integrations'
        );

        foreach ($categories as $type => $title) {
            $category_findings = array_filter($this->results, function($f) use ($type) {
                return $f['type'] === $type;
            });

            if (!empty($category_findings)) {
                $report_content .= "## $title\n\n";
                foreach ($category_findings as $finding) {
                    $severity_label = $this->getSeverityLabel($finding['severity']);
                    $report_content .= "### [$severity_label] {$finding['title']}\n";
                    $report_content .= "- **File:** `{$finding['file']}`\n";
                    if (isset($finding['line'])) {
                        $report_content .= "- **Line:** {$finding['line']}\n";
                    }
                    if (isset($finding['cve'])) {
                        $report_content .= "- **CVE:** {$finding['cve']}\n";
                    }
                    if (isset($finding['package'])) {
                        $report_content .= "- **Package:** {$finding['package']}\n";
                    }
                    if (isset($finding['current_version'])) {
                        $report_content .= "- **Version:** {$finding['current_version']}\n";
                    }
                    $report_content .= "- **Description:** {$finding['description']}\n";
                    if (isset($finding['recommendation'])) {
                        $report_content .= "- **Recommendation:** {$finding['recommendation']}\n";
                    }
                    $report_content .= "\n";
                }
            }
        }

        // Security recommendations
        $report_content .= "## Security Recommendations\n\n";
        $report_content .= "### Immediate Actions\n";
        $report_content .= "1. **Update vulnerable packages** - Prioritize critical and high severity vulnerabilities\n";
        $report_content .= "2. **Enable SSL verification** - Fix all instances of disabled SSL certificate verification\n";
        $report_content .= "3. **Remove hardcoded credentials** - Move all API keys and secrets to environment variables\n";
        $report_content .= "4. **Use HTTPS for APIs** - Replace all HTTP API calls with HTTPS\n\n";

        $report_content .= "### Long-term Improvements\n";
        $report_content .= "1. **Implement dependency scanning** - Set up automated vulnerability scanning in CI/CD\n";
        $report_content .= "2. **Regular updates** - Establish process for regular dependency updates\n";
        $report_content .= "3. **Security monitoring** - Monitor security advisories for used packages\n";
        $report_content .= "4. **Code review** - Include security review for third-party integrations\n";
        $report_content .= "5. **Dependency pinning** - Use composer.lock to ensure consistent versions\n\n";

        file_put_contents($report_file, $report_content);
        echo "Detailed report saved to: $report_file\n";
    }

    /**
     * Get severity label
     */
    private function getSeverityLabel($severity)
    {
        $labels = array(
            SecurityAudit::SEVERITY_CRITICAL => 'CRITICAL',
            SecurityAudit::SEVERITY_HIGH => 'HIGH',
            SecurityAudit::SEVERITY_MEDIUM => 'MEDIUM',
            SecurityAudit::SEVERITY_LOW => 'LOW'
        );
        
        return isset($labels[$severity]) ? $labels[$severity] : 'UNKNOWN';
    }
}

// Run the scanner if called directly
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    $scanner = new DependencySecurityScanner();
    $results = $scanner->runScan();
    
    echo "\nDependency security scan completed successfully!\n";
    echo "Check DEPENDENCY_SECURITY_REPORT.md for detailed findings.\n";
}