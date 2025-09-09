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

        // Enhanced patterns for SQL injection detection
        $patterns = array(
            // Direct user input in SQL queries
            '/\$_GET\[.*?\].*?(SELECT|INSERT|UPDATE|DELETE)/i' => 'Direct GET parameter in SQL query',
            '/\$_POST\[.*?\].*?(SELECT|INSERT|UPDATE|DELETE)/i' => 'Direct POST parameter in SQL query',
            '/\$_REQUEST\[.*?\].*?(SELECT|INSERT|UPDATE|DELETE)/i' => 'Direct REQUEST parameter in SQL query',
            '/\$_COOKIE\[.*?\].*?(SELECT|INSERT|UPDATE|DELETE)/i' => 'Direct COOKIE parameter in SQL query',
            
            // SQL queries with user input concatenation
            '/(SELECT|INSERT|UPDATE|DELETE).*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input concatenated in SQL query',
            '/WHERE.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in WHERE clause without sanitization',
            '/ORDER BY.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in ORDER BY clause',
            '/GROUP BY.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in GROUP BY clause',
            '/HAVING.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in HAVING clause',
            '/LIMIT.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in LIMIT clause',
            
            // Tools::getValue without proper sanitization
            '/WHERE.*?Tools::getValue\([^)]+\)(?!\s*\))/i' => 'Tools::getValue in WHERE clause without type casting',
            '/(SELECT|INSERT|UPDATE|DELETE).*?Tools::getValue\([^)]+\).*?[\'"].*?[\'"].*?\./i' => 'Tools::getValue concatenated in SQL string',
            
            // Direct database functions with user input
            '/mysql_query\(.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'Direct user input in mysql_query',
            '/mysqli_query\(.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'Direct user input in mysqli_query',
            '/pg_query\(.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'Direct user input in pg_query',
            
            // String concatenation in SQL
            '/[\'"].*?(SELECT|INSERT|UPDATE|DELETE).*?[\'"].*?\.\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'String concatenation with user input in SQL',
            '/\$sql.*?=.*?[\'"].*?\.\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'SQL variable with concatenated user input',
            
            // Unsafe use of sprintf/printf in SQL
            '/sprintf\s*\(\s*[\'"].*?(SELECT|INSERT|UPDATE|DELETE).*?%s.*?[\'"].*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'Unsafe sprintf with user input in SQL',
            
            // Dynamic table/column names from user input
            '/FROM\s+[\'"]?\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'Dynamic table name from user input',
            '/`?\s*\.\s*\$_(GET|POST|REQUEST|COOKIE).*?`?\s*=/i' => 'Dynamic column name from user input',
            
            // LIKE queries without proper escaping
            '/LIKE\s+[\'"]%.*?\$_(GET|POST|REQUEST|COOKIE).*?%[\'"](?!.*pSQL)/i' => 'LIKE query with unescaped user input',
            
            // IN clauses with user input
            '/IN\s*\(\s*[\'"]?\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'IN clause with user input',
            
            // Union-based injection patterns
            '/UNION.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'UNION query with user input'
        );

        foreach ($lines as $line_number => $line) {
            $line_trimmed = trim($line);
            
            // Skip comments and empty lines
            if (empty($line_trimmed) || strpos($line_trimmed, '//') === 0 || strpos($line_trimmed, '#') === 0 || strpos($line_trimmed, '/*') === 0) {
                continue;
            }

            foreach ($patterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    // Check if the line has proper sanitization
                    $has_sanitization = self::checkSQLSanitization($line, $line_number, $lines);
                    
                    if (!$has_sanitization) {
                        $severity = self::assessSQLInjectionSeverity($line, $pattern);
                        
                        $vulnerabilities[] = array(
                            'line' => $line_number + 1,
                            'code' => trim($line),
                            'description' => $description,
                            'severity' => $severity,
                            'pattern_matched' => $pattern
                        );
                    }
                }
            }
            
            // Additional check for ObjectModel queries
            $objectmodel_vulns = self::checkObjectModelQueries($line, $line_number);
            if (!empty($objectmodel_vulns)) {
                $vulnerabilities = array_merge($vulnerabilities, $objectmodel_vulns);
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check if SQL line has proper sanitization
     */
    private static function checkSQLSanitization($line, $line_number, $lines)
    {
        // Check for proper type casting
        if (preg_match('/\(int\)/', $line) || preg_match('/intval\(/', $line)) {
            return true;
        }
        
        // Check for pSQL function
        if (preg_match('/pSQL\(/', $line)) {
            return true;
        }
        
        // Check for bqSQL function (for identifiers)
        if (preg_match('/bqSQL\(/', $line)) {
            return true;
        }
        
        // Check for prepared statements in context
        $context_start = max(0, $line_number - 3);
        $context_end = min(count($lines), $line_number + 3);
        
        for ($i = $context_start; $i < $context_end; $i++) {
            if (preg_match('/prepare\(|bindParam\(|bindValue\(|execute\(\s*array\(/i', $lines[$i])) {
                return true;
            }
        }
        
        // Check for Validate class usage
        if (preg_match('/Validate::(isInt|isUnsignedId|isCleanHtml|isGenericName)/', $line)) {
            return true;
        }
        
        return false;
    }

    /**
     * Assess SQL injection severity based on context
     */
    private static function assessSQLInjectionSeverity($line, $pattern)
    {
        // Critical severity for admin operations
        if (preg_match('/admin|employee|password|user/i', $line)) {
            return SecurityAudit::SEVERITY_CRITICAL;
        }
        
        // High severity for data modification
        if (preg_match('/(INSERT|UPDATE|DELETE)/i', $line)) {
            return SecurityAudit::SEVERITY_HIGH;
        }
        
        // High severity for authentication bypass patterns
        if (preg_match('/WHERE.*?(login|password|email).*?=/i', $line)) {
            return SecurityAudit::SEVERITY_HIGH;
        }
        
        // Medium severity for SELECT queries
        if (preg_match('/SELECT/i', $line)) {
            return SecurityAudit::SEVERITY_MEDIUM;
        }
        
        return SecurityAudit::SEVERITY_HIGH; // Default to high for SQL injection
    }

    /**
     * Check ObjectModel queries for vulnerabilities
     */
    private static function checkObjectModelQueries($line, $line_number)
    {
        $vulnerabilities = array();
        
        // Check for unsafe ObjectModel usage
        $patterns = array(
            '/new\s+\w+\(\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'ObjectModel instantiated with user input',
            '/->load\(\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'ObjectModel load() with user input',
            '/::getCollection\(\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'ObjectModel getCollection() with user input'
        );
        
        foreach ($patterns as $pattern => $description) {
            if (preg_match($pattern, $line)) {
                // Check if there's proper validation
                if (!preg_match('/\(int\)|intval\(|Validate::isUnsignedId/', $line)) {
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
        $file_extension = pathinfo($file_path, PATHINFO_EXTENSION);

        // Enhanced patterns for XSS detection
        $php_patterns = array(
            // Direct output without encoding
            '/echo\s+\$_(GET|POST|REQUEST|COOKIE|SESSION)/i' => 'Direct output of user input without encoding',
            '/print\s+\$_(GET|POST|REQUEST|COOKIE|SESSION)/i' => 'Direct print of user input without encoding',
            '/printf?\s*\(\s*[\'"].*?%s.*?[\'"].*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'Printf with user input without encoding',
            
            // Tools::getValue without encoding
            '/echo\s+Tools::getValue\(/i' => 'Direct output of Tools::getValue without encoding',
            '/print\s+Tools::getValue\(/i' => 'Direct print of Tools::getValue without encoding',
            
            // HTML attributes with user input
            '/value\s*=\s*[\'"]?\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in HTML attribute without encoding',
            '/href\s*=\s*[\'"]?\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in href attribute without encoding',
            '/src\s*=\s*[\'"]?\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in src attribute without encoding',
            '/onclick\s*=\s*[\'"].*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in onclick attribute',
            '/onload\s*=\s*[\'"].*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in onload attribute',
            '/style\s*=\s*[\'"].*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in style attribute',
            
            // JavaScript context
            '/innerHTML\s*=.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input assigned to innerHTML',
            '/document\.write\(.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in document.write',
            '/eval\(.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in eval function',
            
            // URL context
            '/header\s*\(\s*[\'"]Location:.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in redirect header',
            '/window\.location.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in window.location',
            
            // Form context
            '/<input.*?value\s*=\s*[\'"]?\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in form input value',
            '/<textarea.*?>\s*\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input in textarea content',
            
            // Content-Type header issues
            '/header\s*\(\s*[\'"]Content-Type:.*?text\/html.*?\$_(GET|POST|REQUEST|COOKIE)/i' => 'User input affecting Content-Type header'
        );

        $template_patterns = array(
            // Smarty template vulnerabilities
            '/\{\$smarty\.(get|post|request|cookie)\./i' => 'Direct Smarty superglobal output without escaping',
            '/\{\$_(GET|POST|REQUEST|COOKIE|SESSION)\[/i' => 'Direct superglobal output in template',
            '/\{\$[^}]*\}(?!.*\|escape)/i' => 'Template variable without escape modifier',
            '/\{[^}]*Tools::getValue[^}]*\}(?!.*\|escape)/i' => 'Tools::getValue in template without escaping',
            
            // JavaScript in templates
            '/var\s+\w+\s*=\s*[\'"]?\{\$[^}]*\}[\'"]?(?!.*\|escape)/i' => 'Template variable in JavaScript without escaping',
            '/onclick\s*=\s*[\'"][^\'\"]*\{\$[^}]*\}/i' => 'Template variable in onclick attribute',
            '/href\s*=\s*[\'"]javascript:[^\'\"]*\{\$[^}]*\}/i' => 'Template variable in javascript: URL',
            
            // CSS context
            '/style\s*=\s*[\'"][^\'\"]*\{\$[^}]*\}/i' => 'Template variable in style attribute',
            
            // HTML context
            '/<script[^>]*>\s*[^<]*\{\$[^}]*\}(?!.*\|escape)/i' => 'Template variable in script tag without escaping',
            '/<title[^>]*>[^<]*\{\$[^}]*\}(?!.*\|escape)/i' => 'Template variable in title tag without escaping'
        );

        foreach ($lines as $line_number => $line) {
            $line_trimmed = trim($line);
            
            // Skip comments and empty lines
            if (empty($line_trimmed) || strpos($line_trimmed, '//') === 0 || strpos($line_trimmed, '#') === 0) {
                continue;
            }

            // Choose patterns based on file type
            $patterns = ($file_extension === 'tpl') ? $template_patterns : $php_patterns;
            
            foreach ($patterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    // Check if proper encoding is used
                    $has_encoding = self::checkXSSProtection($line, $line_number, $lines, $file_extension);
                    $severity = self::assessXSSSeverity($line, $description, $file_extension);
                    
                    if (!$has_encoding) {
                        $vulnerabilities[] = array(
                            'line' => $line_number + 1,
                            'code' => trim($line),
                            'description' => $description,
                            'severity' => $severity,
                            'file_type' => $file_extension
                        );
                    }
                }
            }
            
            // Additional checks for specific contexts
            $context_vulns = self::checkXSSContexts($line, $line_number, $file_extension);
            if (!empty($context_vulns)) {
                $vulnerabilities = array_merge($vulnerabilities, $context_vulns);
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check if XSS protection is properly implemented
     */
    private static function checkXSSProtection($line, $line_number, $lines, $file_extension)
    {
        if ($file_extension === 'tpl') {
            // Check for Smarty escape modifiers
            $escape_patterns = array(
                '/\|escape:\'html\'/', '/\|escape:\'htmlall\'/', '/\|escape:\'url\'/',
                '/\|escape:\'quotes\'/', '/\|escape:\'javascript\'/', '/\|strip_tags/',
                '/\|nl2br/', '/\|htmlspecialchars/'
            );
            
            foreach ($escape_patterns as $pattern) {
                if (preg_match($pattern, $line)) {
                    return true;
                }
            }
        } else {
            // Check for PHP encoding functions
            $encoding_functions = array(
                'htmlspecialchars', 'htmlentities', 'Tools::safeOutput', 
                'Tools::displayError', 'strip_tags', 'addslashes',
                'json_encode', 'urlencode', 'rawurlencode'
            );
            
            foreach ($encoding_functions as $func) {
                if (stripos($line, $func) !== false) {
                    return true;
                }
            }
            
            // Check for proper escaping in context
            $context_start = max(0, $line_number - 3);
            $context_end = min(count($lines), $line_number + 3);
            
            for ($i = $context_start; $i < $context_end; $i++) {
                foreach ($encoding_functions as $func) {
                    if (stripos($lines[$i], $func) !== false) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    /**
     * Assess XSS vulnerability severity
     */
    private static function assessXSSSeverity($line, $description, $file_extension)
    {
        // Critical severity for JavaScript context
        if (preg_match('/eval|innerHTML|document\.write|javascript:/i', $line)) {
            return SecurityAudit::SEVERITY_CRITICAL;
        }
        
        // High severity for HTML attributes and headers
        if (preg_match('/onclick|onload|href|src|Location:|window\.location/i', $line)) {
            return SecurityAudit::SEVERITY_HIGH;
        }
        
        // High severity for admin context
        if (preg_match('/admin|employee/i', $line)) {
            return SecurityAudit::SEVERITY_HIGH;
        }
        
        // Medium severity for template variables without escaping
        if ($file_extension === 'tpl' && preg_match('/\{\$[^}]*\}/i', $line)) {
            return SecurityAudit::SEVERITY_MEDIUM;
        }
        
        // Medium severity for direct output
        if (preg_match('/echo|print/i', $line)) {
            return SecurityAudit::SEVERITY_MEDIUM;
        }
        
        return SecurityAudit::SEVERITY_MEDIUM; // Default severity
    }

    /**
     * Check specific XSS contexts
     */
    private static function checkXSSContexts($line, $line_number, $file_extension)
    {
        $vulnerabilities = array();
        
        // Check for DOM-based XSS patterns
        if (preg_match('/document\.location\.hash|window\.location\.hash|location\.search/i', $line)) {
            $vulnerabilities[] = array(
                'line' => $line_number + 1,
                'code' => trim($line),
                'description' => 'Potential DOM-based XSS using location properties',
                'severity' => SecurityAudit::SEVERITY_HIGH
            );
        }
        
        // Check for reflected XSS in error messages
        if (preg_match('/error.*?\$_(GET|POST|REQUEST)/i', $line)) {
            $vulnerabilities[] = array(
                'line' => $line_number + 1,
                'code' => trim($line),
                'description' => 'User input reflected in error message',
                'severity' => SecurityAudit::SEVERITY_MEDIUM
            );
        }
        
        // Check for stored XSS potential
        if (preg_match('/echo.*?\$[^_].*?->.*?(name|title|description|comment)/i', $line)) {
            $vulnerabilities[] = array(
                'line' => $line_number + 1,
                'code' => trim($line),
                'description' => 'Potential stored XSS in user-generated content',
                'severity' => SecurityAudit::SEVERITY_HIGH
            );
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

        // Enhanced patterns for file upload vulnerabilities
        $patterns = array(
            // Direct file operations without validation
            '/move_uploaded_file\(.*?\$_FILES.*?\)(?!.*pathinfo|.*getimagesize|.*mime_content_type)/i' => 'File upload without proper validation',
            '/copy\(\s*\$_FILES\[.*?\]\[.*?\]/i' => 'Using copy() for file uploads (insecure)',
            '/file_put_contents\(.*?\$_FILES\[.*?\]\[.*?\]/i' => 'Direct file content writing from upload',
            '/rename\(.*?\$_FILES\[.*?\]\[.*?\]/i' => 'Direct file rename from upload',
            
            // Using original filename without sanitization
            '/\$_FILES\[.*?\]\[\'name\'\](?!.*basename|.*pathinfo|.*preg_replace)/i' => 'Using original filename without sanitization',
            '/\$filename\s*=\s*\$_FILES\[.*?\]\[\'name\'\]/i' => 'Direct assignment of uploaded filename',
            
            // Missing file type validation
            '/\$_FILES\[.*?\]\[\'type\'\].*?==.*?[\'"]image/i' => 'Relying on client-provided MIME type',
            '/if\s*\(\s*\$_FILES\[.*?\]\[\'type\'\]/i' => 'Trusting client-provided MIME type',
            
            // Dangerous file extensions not filtered
            '/\.(php|phtml|php3|php4|php5|phar|exe|bat|cmd|com|scr|vbs|js|jar|war)[\'"]/i' => 'Allowing dangerous file extensions',
            
            // Missing size validation
            '/move_uploaded_file\(.*?\)(?!.*\$_FILES\[.*?\]\[\'size\'\])/i' => 'File upload without size validation',
            
            // Insecure temporary file handling
            '/tempnam\(.*?\).*?move_uploaded_file/i' => 'Insecure temporary file handling',
            '/\$_FILES\[.*?\]\[\'tmp_name\'\].*?fopen/i' => 'Direct access to temporary file',
            
            // Path traversal vulnerabilities
            '/\$_FILES\[.*?\]\[\'name\'\].*?\.\.\/|\.\.\\\/i' => 'Potential path traversal in filename',
            '/basename\(\$_FILES\[.*?\]\[\'name\'\]\)(?!.*preg_replace)/i' => 'Using basename without further sanitization',
            
            // Missing upload directory security
            '/move_uploaded_file\(.*?[\'"]\/.*?[\'"].*?\)/i' => 'Uploading to absolute path without validation',
            '/\$upload_dir.*?=.*?[\'"].*?www.*?[\'"]|[\'"].*?public_html.*?[\'"]|[\'"].*?htdocs.*?[\'"])/i' => 'Uploading to web-accessible directory',
            
            // Executable file uploads
            '/chmod\(.*?\$_FILES.*?0777|0755\)/i' => 'Setting executable permissions on uploaded files',
            
            // Missing error handling
            '/move_uploaded_file\(.*?\)(?!.*if|.*\?)/i' => 'File upload without error handling',
            
            // Double extension vulnerabilities
            '/\$_FILES\[.*?\]\[\'name\'\].*?\..*?\..*?$/i' => 'Potential double extension vulnerability',
            
            // Content-based validation missing
            '/move_uploaded_file\(.*?\)(?!.*getimagesize|.*exif_imagetype|.*finfo_file)/i' => 'Missing content-based file validation'
        );

        foreach ($lines as $line_number => $line) {
            $line_trimmed = trim($line);
            
            // Skip comments and empty lines
            if (empty($line_trimmed) || strpos($line_trimmed, '//') === 0 || strpos($line_trimmed, '#') === 0) {
                continue;
            }

            foreach ($patterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    // Check for proper validation in context
                    $has_validation = self::checkFileUploadValidation($line, $line_number, $lines);
                    $severity = self::assessFileUploadSeverity($line, $description);
                    
                    if (!$has_validation || $severity >= SecurityAudit::SEVERITY_HIGH) {
                        $vulnerabilities[] = array(
                            'line' => $line_number + 1,
                            'code' => trim($line),
                            'description' => $description,
                            'severity' => $severity,
                            'validation_present' => $has_validation
                        );
                    }
                }
            }
            
            // Check for specific file upload class vulnerabilities
            $class_vulns = self::checkFileUploadClasses($line, $line_number);
            if (!empty($class_vulns)) {
                $vulnerabilities = array_merge($vulnerabilities, $class_vulns);
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check if file upload has proper validation
     */
    private static function checkFileUploadValidation($line, $line_number, $lines)
    {
        $validation_functions = array(
            'pathinfo', 'getimagesize', 'mime_content_type', 'finfo_file', 
            'exif_imagetype', 'is_uploaded_file', 'Validate::', 'ImageManager::',
            'in_array', 'preg_match', 'basename', 'realpath'
        );
        
        // Check current line for validation
        foreach ($validation_functions as $func) {
            if (stripos($line, $func) !== false) {
                return true;
            }
        }
        
        // Check surrounding context (5 lines before and after)
        $context_start = max(0, $line_number - 5);
        $context_end = min(count($lines), $line_number + 5);
        
        for ($i = $context_start; $i < $context_end; $i++) {
            foreach ($validation_functions as $func) {
                if (stripos($lines[$i], $func) !== false) {
                    return true;
                }
            }
            
            // Check for file extension validation
            if (preg_match('/\.(jpg|jpeg|png|gif|pdf|doc|docx|txt|csv)\b/i', $lines[$i])) {
                return true;
            }
            
            // Check for size validation
            if (preg_match('/\$_FILES\[.*?\]\[\'size\'\].*?[<>]/i', $lines[$i])) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Assess file upload vulnerability severity
     */
    private static function assessFileUploadSeverity($line, $description)
    {
        // Critical severity for executable file uploads
        if (preg_match('/\.(php|phtml|exe|bat|cmd|scr|vbs|js)/i', $line)) {
            return SecurityAudit::SEVERITY_CRITICAL;
        }
        
        // High severity for path traversal and direct file operations
        if (preg_match('/\.\.\/|move_uploaded_file.*?\$_FILES.*?name/i', $line)) {
            return SecurityAudit::SEVERITY_HIGH;
        }
        
        // High severity for web-accessible uploads
        if (preg_match('/www|public_html|htdocs/i', $line)) {
            return SecurityAudit::SEVERITY_HIGH;
        }
        
        // Medium severity for validation issues
        if (preg_match('/mime.*?type|size.*?validation/i', $description)) {
            return SecurityAudit::SEVERITY_MEDIUM;
        }
        
        return SecurityAudit::SEVERITY_HIGH; // Default to high for file upload issues
    }

    /**
     * Check file upload classes for vulnerabilities
     */
    private static function checkFileUploadClasses($line, $line_number)
    {
        $vulnerabilities = array();
        
        // Check FileUploader class usage
        if (preg_match('/new\s+FileUploader\(/i', $line)) {
            // Check if allowedExtensions is properly set
            if (!preg_match('/allowedExtensions.*?=.*?array\(/i', $line)) {
                $vulnerabilities[] = array(
                    'line' => $line_number + 1,
                    'code' => trim($line),
                    'description' => 'FileUploader instantiated without allowed extensions',
                    'severity' => SecurityAudit::SEVERITY_HIGH
                );
            }
        }
        
        // Check Uploader class usage
        if (preg_match('/new\s+Uploader\(/i', $line)) {
            $vulnerabilities[] = array(
                'line' => $line_number + 1,
                'code' => trim($line),
                'description' => 'Uploader class usage requires validation review',
                'severity' => SecurityAudit::SEVERITY_MEDIUM
            );
        }
        
        // Check for direct $_FILES usage without validation
        if (preg_match('/\$_FILES\[.*?\](?!.*Validate|.*pathinfo|.*getimagesize)/i', $line)) {
            $vulnerabilities[] = array(
                'line' => $line_number + 1,
                'code' => trim($line),
                'description' => 'Direct $_FILES usage without validation',
                'severity' => SecurityAudit::SEVERITY_MEDIUM
            );
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