<?php
/**
 * Security Audit Utilities
 * 
 * Helper functions and utilities for security auditing
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class SecurityAuditUtils
{
    /**
     * Scan directory for PHP files
     */
    public static function scanDirectory($directory, $extensions = array('php'))
    {
        $files = array();
        
        if (!is_dir($directory)) {
            return $files;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $extension = strtolower($file->getExtension());
                if (in_array($extension, $extensions)) {
                    $files[] = $file->getPathname();
                }
            }
        }

        return $files;
    }

    /**
     * Check for SQL injection vulnerabilities in PHP code
     */
    public static function scanForSQLInjection($file_path)
    {
        $vulnerabilities = array();
        
        if (!file_exists($file_path)) {
            return $vulnerabilities;
        }

        $content = file_get_contents($file_path);
        $lines = explode("\n", $content);

        // Patterns that indicate potential SQL injection
        $patterns = array(
            '/\$_GET\[.*?\].*?SELECT/i' => 'Direct GET parameter in SQL query',
            '/\$_POST\[.*?\].*?SELECT/i' => 'Direct POST parameter in SQL query',
            '/\$_REQUEST\[.*?\].*?SELECT/i' => 'Direct REQUEST parameter in SQL query',
            '/SELECT.*?\$_GET/i' => 'GET parameter concatenated in SQL',
            '/SELECT.*?\$_POST/i' => 'POST parameter concatenated in SQL',
            '/INSERT.*?\$_GET/i' => 'GET parameter in INSERT statement',
            '/UPDATE.*?\$_GET/i' => 'GET parameter in UPDATE statement',
            '/DELETE.*?\$_GET/i' => 'GET parameter in DELETE statement',
            '/mysql_query\(.*?\$_/i' => 'Direct user input in mysql_query',
            '/mysqli_query\(.*?\$_/i' => 'Direct user input in mysqli_query'
        );

        foreach ($lines as $line_number => $line) {
            foreach ($patterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    $vulnerabilities[] = array(
                        'line' => $line_number + 1,
                        'code' => trim($line),
                        'description' => $description,
                        'severity' => SecurityAudit::SEVERITY_HIGH
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check for XSS vulnerabilities
     */
    public static function scanForXSS($file_path)
    {
        $vulnerabilities = array();
        
        if (!file_exists($file_path)) {
            return $vulnerabilities;
        }

        $content = file_get_contents($file_path);
        $lines = explode("\n", $content);

        // Patterns that indicate potential XSS
        $patterns = array(
            '/echo\s+\$_GET/i' => 'Direct output of GET parameter',
            '/echo\s+\$_POST/i' => 'Direct output of POST parameter',
            '/print\s+\$_GET/i' => 'Direct print of GET parameter',
            '/print\s+\$_POST/i' => 'Direct print of POST parameter',
            '/\{\$smarty\.get\./i' => 'Direct Smarty GET output',
            '/\{\$smarty\.post\./i' => 'Direct Smarty POST output',
            '/innerHTML.*?\$_/i' => 'Direct user input to innerHTML'
        );

        foreach ($lines as $line_number => $line) {
            foreach ($patterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    $vulnerabilities[] = array(
                        'line' => $line_number + 1,
                        'code' => trim($line),
                        'description' => $description,
                        'severity' => SecurityAudit::SEVERITY_MEDIUM
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check for insecure file upload patterns
     */
    public static function scanForFileUploadVulns($file_path)
    {
        $vulnerabilities = array();
        
        if (!file_exists($file_path)) {
            return $vulnerabilities;
        }

        $content = file_get_contents($file_path);
        $lines = explode("\n", $content);

        // Patterns for file upload vulnerabilities
        $patterns = array(
            '/move_uploaded_file\(.*?\$_FILES.*?\)/i' => 'File upload without validation',
            '/\$_FILES\[.*?\]\[\'name\'\].*?move_uploaded_file/i' => 'Using original filename',
            '/copy\(\$_FILES/i' => 'Using copy() for file uploads',
            '/file_put_contents\(.*?\$_FILES/i' => 'Direct file content writing'
        );

        foreach ($lines as $line_number => $line) {
            foreach ($patterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    // Check if there's validation nearby
                    $has_validation = false;
                    $context_start = max(0, $line_number - 5);
                    $context_end = min(count($lines), $line_number + 5);
                    
                    for ($i = $context_start; $i < $context_end; $i++) {
                        if (preg_match('/(pathinfo|getimagesize|mime_content_type|finfo_file)/i', $lines[$i])) {
                            $has_validation = true;
                            break;
                        }
                    }

                    if (!$has_validation) {
                        $vulnerabilities[] = array(
                            'line' => $line_number + 1,
                            'code' => trim($line),
                            'description' => $description,
                            'severity' => SecurityAudit::SEVERITY_HIGH
                        );
                    }
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check for weak authentication patterns
     */
    public static function scanForWeakAuth($file_path)
    {
        $vulnerabilities = array();
        
        if (!file_exists($file_path)) {
            return $vulnerabilities;
        }

        $content = file_get_contents($file_path);
        $lines = explode("\n", $content);

        // Patterns for weak authentication
        $patterns = array(
            '/md5\(\$.*?password/i' => 'MD5 password hashing (weak)',
            '/sha1\(\$.*?password/i' => 'SHA1 password hashing (weak)',
            '/password.*?==.*?\$_/i' => 'Plain text password comparison',
            '/\$_SESSION\[.*?\].*?=.*?true/i' => 'Simple session authentication',
            '/if\s*\(\s*\$_GET\[.*?password.*?\]/i' => 'Password in GET parameter'
        );

        foreach ($lines as $line_number => $line) {
            foreach ($patterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    $vulnerabilities[] = array(
                        'line' => $line_number + 1,
                        'code' => trim($line),
                        'description' => $description,
                        'severity' => SecurityAudit::SEVERITY_MEDIUM
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check file permissions
     */
    public static function checkFilePermissions($file_path)
    {
        $issues = array();
        
        if (!file_exists($file_path)) {
            return $issues;
        }

        $perms = fileperms($file_path);
        $octal_perms = substr(sprintf('%o', $perms), -4);

        // Check for overly permissive permissions
        if ($octal_perms > '0644' && is_file($file_path)) {
            $issues[] = array(
                'type' => 'file_permissions',
                'description' => "File has overly permissive permissions: $octal_perms",
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'recommendation' => 'Set file permissions to 644'
            );
        }

        if ($octal_perms > '0755' && is_dir($file_path)) {
            $issues[] = array(
                'type' => 'directory_permissions',
                'description' => "Directory has overly permissive permissions: $octal_perms",
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'recommendation' => 'Set directory permissions to 755'
            );
        }

        return $issues;
    }

    /**
     * Check for hardcoded credentials
     */
    public static function scanForHardcodedCredentials($file_path)
    {
        $vulnerabilities = array();
        
        if (!file_exists($file_path)) {
            return $vulnerabilities;
        }

        $content = file_get_contents($file_path);
        $lines = explode("\n", $content);

        // Patterns for hardcoded credentials
        $patterns = array(
            '/password\s*=\s*["\'][^"\']{3,}["\']/i' => 'Hardcoded password',
            '/api_key\s*=\s*["\'][^"\']{10,}["\']/i' => 'Hardcoded API key',
            '/secret\s*=\s*["\'][^"\']{8,}["\']/i' => 'Hardcoded secret',
            '/token\s*=\s*["\'][^"\']{10,}["\']/i' => 'Hardcoded token',
            '/mysql.*?password.*?=.*?["\'][^"\']+["\']/i' => 'Hardcoded database password'
        );

        foreach ($lines as $line_number => $line) {
            foreach ($patterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    $vulnerabilities[] = array(
                        'line' => $line_number + 1,
                        'code' => trim($line),
                        'description' => $description,
                        'severity' => SecurityAudit::SEVERITY_HIGH
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Generate security report
     */
    public static function generateSecurityReport($audit_id)
    {
        $audit = new SecurityAudit($audit_id);
        $findings = SecurityFinding::getFindingsByAudit($audit_id);

        $report = array(
            'audit_summary' => $audit->getSummary(),
            'findings_by_severity' => array(),
            'findings_by_category' => array(),
            'recommendations' => array()
        );

        // Group findings by severity
        foreach ($findings as $finding) {
            $severity_name = SecurityAudit::getSeverityName($finding['severity']);
            if (!isset($report['findings_by_severity'][$severity_name])) {
                $report['findings_by_severity'][$severity_name] = array();
            }
            $report['findings_by_severity'][$severity_name][] = $finding;
        }

        // Group findings by category
        foreach ($findings as $finding) {
            $category = $finding['category'];
            if (!isset($report['findings_by_category'][$category])) {
                $report['findings_by_category'][$category] = array();
            }
            $report['findings_by_category'][$category][] = $finding;
        }

        // Generate recommendations
        $report['recommendations'] = self::generateRecommendations($findings);

        return $report;
    }

    /**
     * Generate security recommendations
     */
    private static function generateRecommendations($findings)
    {
        $recommendations = array();
        $category_counts = array();

        // Count findings by category
        foreach ($findings as $finding) {
            $category = $finding['category'];
            if (!isset($category_counts[$category])) {
                $category_counts[$category] = 0;
            }
            $category_counts[$category]++;
        }

        // Generate category-specific recommendations
        foreach ($category_counts as $category => $count) {
            switch ($category) {
                case SecurityAudit::CATEGORY_INPUT_VALIDATION:
                    $recommendations[] = array(
                        'priority' => 'high',
                        'title' => 'Implement Input Validation',
                        'description' => 'Use prepared statements and input sanitization to prevent injection attacks.',
                        'affected_findings' => $count
                    );
                    break;
                case SecurityAudit::CATEGORY_AUTHENTICATION:
                    $recommendations[] = array(
                        'priority' => 'high',
                        'title' => 'Strengthen Authentication',
                        'description' => 'Implement strong password hashing and secure session management.',
                        'affected_findings' => $count
                    );
                    break;
                case SecurityAudit::CATEGORY_CONFIGURATION:
                    $recommendations[] = array(
                        'priority' => 'medium',
                        'title' => 'Secure Configuration',
                        'description' => 'Review and harden system configurations and file permissions.',
                        'affected_findings' => $count
                    );
                    break;
            }
        }

        return $recommendations;
    }

    /**
     * Create database tables for security audit
     */
    public static function createTables()
    {
        $sql = array();

        $sql[] = 'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'security_audit` (
            `id_audit` int(11) NOT NULL AUTO_INCREMENT,
            `audit_name` varchar(255) NOT NULL,
            `audit_date` datetime NOT NULL,
            `status` varchar(32) DEFAULT "initialized",
            `total_findings` int(11) DEFAULT 0,
            `critical_findings` int(11) DEFAULT 0,
            `high_findings` int(11) DEFAULT 0,
            `medium_findings` int(11) DEFAULT 0,
            `low_findings` int(11) DEFAULT 0,
            `info_findings` int(11) DEFAULT 0,
            PRIMARY KEY (`id_audit`)
        ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8;';

        $sql[] = 'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'security_finding` (
            `id_finding` int(11) NOT NULL AUTO_INCREMENT,
            `id_audit` int(11) NOT NULL,
            `title` varchar(255) NOT NULL,
            `description` text NOT NULL,
            `severity` int(1) NOT NULL,
            `category` varchar(64) NOT NULL,
            `affected_files` text,
            `business_impact` varchar(32) DEFAULT "medium",
            `remediation_effort` varchar(32) DEFAULT "medium",
            `compliance_impact` text,
            `fix_specification` text,
            `code_examples` text,
            `references` text,
            `status` varchar(32) DEFAULT "open",
            `risk_score` decimal(5,2) DEFAULT 0.00,
            `date_found` datetime NOT NULL,
            `date_fixed` datetime NULL,
            PRIMARY KEY (`id_finding`),
            KEY `id_audit` (`id_audit`),
            KEY `severity` (`severity`),
            KEY `category` (`category`)
        ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8;';

        foreach ($sql as $query) {
            if (!Db::getInstance()->execute($query)) {
                return false;
            }
        }

        return true;
    }
}