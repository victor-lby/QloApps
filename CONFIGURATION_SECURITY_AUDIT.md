# Configuration and Infrastructure Security Audit

This document describes the configuration and infrastructure security audit functionality implemented for QloApps security compliance assessment.

## Overview

The configuration security audit (Task 5) conducts a comprehensive review of system configurations, file system security, and error handling mechanisms to identify potential security vulnerabilities and misconfigurations.

## Features Implemented

### 5.1 System Configuration Audit

#### Configuration File Review
- **Location**: `/config/` directory
- **Files Audited**:
  - `config.inc.php` - Main configuration file
  - `defines.inc.php` - System constants and defines
  - `settings.inc.php` - Database and system settings
  - `smarty.config.inc.php` - Smarty template configuration
  - `defines_custom.inc.php` - Custom configuration overrides

#### Security Checks Performed
- **File Permissions**: Ensures configuration files have secure permissions (644 or more restrictive)
- **Debug Mode Detection**: Identifies if `_PS_MODE_DEV_` is enabled in production
- **Error Display Settings**: Checks for `display_errors` enabled in production
- **Database Security**: 
  - Empty database passwords
  - Default database users (root)
  - Localhost database servers
- **Weak Secrets**: Detects short or weak secret keys
- **Dangerous PHP Settings**: Identifies risky settings like `allow_url_include`

#### Database Security Assessment
- **Connection Parameters**: Reviews database connection security
- **User Privileges**: Analyzes database user privileges (when accessible)
- **MySQL Version**: Checks for known vulnerabilities in MySQL/MariaDB versions
- **Credential Security**: Validates database credential strength

#### Web Server Configuration
- **Security Headers**: Checks for missing security headers
- **PHP Configuration**: Reviews PHP security settings
- **Server Information Disclosure**: Identifies version information exposure

### 5.2 File System Security Assessment

#### File Permission Review
- **Critical Directories**: 
  - `/config/` (max 755)
  - `/classes/` (max 755)
  - `/admin/` (max 755)
  - `/modules/` (max 755)
  - `/controllers/` (max 755)
- **Critical Files**:
  - `config.inc.php` (max 644)
  - `settings.inc.php` (max 600)
  - `defines.inc.php` (max 644)
  - `.htaccess` (max 644)

#### Directory Access Controls
- **Protected Directories**: Ensures `.htaccess` protection for:
  - `/config/` - Configuration files
  - `/cache/` - Cache files
  - `/log/` - Log files
  - `/upload/` - Upload directory
  - `/download/` - Download directory
- **Access Restrictions**: Validates "Deny from all" or "Require all denied" directives

#### Upload Directory Security
- **Web Accessibility**: Checks if upload directories are web-accessible
- **Executable Files**: Scans for dangerous file types (php, phtml, exe, etc.)
- **Protection Mechanisms**: Validates `.htaccess` protection against execution
- **Directory Permissions**: Ensures appropriate permission levels

### 5.3 Error Handling and Information Disclosure

#### Error Handling Analysis
- **Core Classes**: Scans `/classes/` for error handling issues
- **Controllers**: Reviews `/controllers/` for information disclosure
- **Dangerous Patterns**:
  - `die()` statements with user input
  - `exit()` statements exposing sensitive data
  - MySQL errors displayed to users

#### Debug Mode and Information Leakage
- **Production Debug Mode**: Detects `_PS_MODE_DEV_` enabled
- **PHP Error Display**: Checks `display_errors` setting
- **Server Information**: Identifies version information in headers
- **PHP Version Exposure**: Detects `expose_php` setting

#### Security Logging Assessment
- **Log Directory**: Validates `/log/` directory existence and permissions
- **Log File Security**: Scans log files for sensitive data exposure
- **Audit Trail**: Assesses logging mechanisms for security events
- **Sensitive Data in Logs**: Detects passwords, API keys, secrets, tokens

## Severity Levels

The audit uses a 0-5 severity scale:

- **5 (Critical)**: Immediate security threats (empty DB passwords, RCE vulnerabilities)
- **4 (High)**: Significant security risks (weak credentials, executable uploads)
- **3 (Medium)**: Moderate security concerns (missing protections, info disclosure)
- **2 (Low)**: Minor security issues (version disclosure, weak configurations)
- **1 (Informational)**: Security recommendations and best practices
- **0 (None)**: No security impact

## Business Impact Assessment

Each finding includes business impact analysis:

- **Critical Impact**: Complete system compromise, data theft
- **High Impact**: Significant security breach, credential theft
- **Medium Impact**: Limited security compromise, information disclosure
- **Low Impact**: Minor security concerns, fingerprinting

## Remediation Guidance

### Configuration Issues
- Set `_PS_MODE_DEV_` to false in production
- Configure secure database credentials
- Disable dangerous PHP settings
- Implement strong secret keys

### File System Security
- Set appropriate file permissions (644 for files, 755 for directories)
- Create `.htaccess` files with proper access restrictions
- Remove executable files from upload directories
- Implement upload validation and restrictions

### Error Handling
- Use generic error messages for users
- Log detailed errors securely
- Disable error display in production
- Implement proper exception handling

## Integration

The configuration security audit is integrated into the main security scanner:

```php
// Run configuration and infrastructure security review (Task 5)
$config_findings = $this->conductConfigurationSecurityReview();
```

## Usage

### Via Security Scanner
```php
$scanner = new SecurityScanner($audit_id);
$findings = $scanner->conductConfigurationSecurityReview();
```

### Individual Components
```php
// System configuration audit
$system_findings = $scanner->auditSystemConfigurations();

// File system security assessment
$filesystem_findings = $scanner->assessFileSystemSecurity();

// Error handling evaluation
$error_findings = $scanner->evaluateErrorHandlingAndInfoDisclosure();
```

## Testing

Use the provided test scripts to verify functionality:

- `tools/test_config_audit.php` - Comprehensive testing
- `tools/verify_config_audit.php` - Implementation verification

## Compliance Mapping

This audit addresses the following requirements:

- **Requirement 4.1**: Server configuration security
- **Requirement 4.2**: Database security settings
- **Requirement 4.3**: File system permissions and access controls
- **Requirement 4.4**: Error handling and information disclosure
- **Requirement 4.5**: Debug mode and logging configurations

## Security Best Practices

The audit enforces these security best practices:

1. **Principle of Least Privilege**: Minimal file permissions and database privileges
2. **Defense in Depth**: Multiple layers of protection (.htaccess, permissions, validation)
3. **Information Security**: Preventing information disclosure through errors and headers
4. **Secure Configuration**: Hardened system and application configurations
5. **Audit Trail**: Proper logging for security monitoring and incident response

This comprehensive configuration security audit helps ensure QloApps installations follow security best practices and comply with industry standards.