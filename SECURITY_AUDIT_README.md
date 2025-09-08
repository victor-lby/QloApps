# QloApps Security Audit Framework

## Overview

The Security Audit Framework provides comprehensive security assessment capabilities for QloApps hotel management systems. It includes automated vulnerability scanning, severity rating, categorization, and detailed reporting features.

## Features

### Core Components

- **SecurityAudit**: Main audit management class with severity rating system (0-5 scale)
- **SecurityFinding**: Individual vulnerability tracking with detailed metadata
- **SecurityAuditUtils**: Utility functions for file scanning and vulnerability detection
- **SecurityScanner**: Automated scanning orchestration with configurable scan types
- **SecurityAuditConfig**: Configuration management for scan settings

### Vulnerability Detection

- **SQL Injection**: Detects unsafe database queries and parameter handling
- **Cross-Site Scripting (XSS)**: Identifies unescaped output and input validation issues
- **File Upload Security**: Checks for unrestricted file upload vulnerabilities
- **Authentication Weaknesses**: Finds weak password hashing and session management
- **Hardcoded Credentials**: Locates embedded passwords, API keys, and secrets
- **File Permissions**: Validates system file and directory permissions
- **Configuration Security**: Reviews system configuration for security issues

### Severity Rating System

- **5 - Critical**: Immediate threat to system security, data breach risk
- **4 - High**: Significant security risk, potential for exploitation
- **3 - Medium**: Moderate security risk, should be addressed promptly
- **2 - Low**: Minor security concern, address in next maintenance cycle
- **1 - Informational**: Security best practice recommendation
- **0 - No Risk**: Configuration or documentation issue

### Security Categories

- Authentication & Session Management
- Authorization & Access Control
- Input Validation & Injection Prevention
- Data Protection & Encryption
- Configuration & Infrastructure Security
- API Security
- Third-Party & Module Security
- Compliance & Regulatory

## Installation

### Automatic Installation

1. Run the installation script:
   ```bash
   php install_security_audit.php
   ```

2. Or via web interface:
   ```
   http://your-domain.com/install_security_audit.php
   ```

### Manual Installation

1. Copy the security audit classes to the `/classes/` directory
2. Install database tables:
   ```bash
   php tools/security_audit_cli.php install-tables
   ```
3. Set up configuration:
   ```bash
   php tools/security_audit_cli.php config --action=reset
   ```

## Usage

### Command Line Interface

#### Run Comprehensive Security Scan
```bash
php tools/security_audit_cli.php scan --name="Daily Security Scan"
```

#### List All Audits
```bash
php tools/security_audit_cli.php list-audits
```

#### Show Audit Details
```bash
php tools/security_audit_cli.php show-audit --id=1
```

#### Export Audit Report
```bash
php tools/security_audit_cli.php export-report --id=1 --format=json --output=report.json
```

#### Manage Configuration
```bash
# Show current configuration
php tools/security_audit_cli.php config --action=show

# Reset to defaults
php tools/security_audit_cli.php config --action=reset

# Export configuration
php tools/security_audit_cli.php config --action=export --output=config.json
```

### Programmatic Usage

#### Create and Run Security Audit
```php
// Create new audit
$audit = new SecurityAudit();
$audit->audit_name = 'Custom Security Audit';
$audit->save();

// Run comprehensive scan
$scanner = new SecurityScanner($audit->id);
$results = $scanner->runComprehensiveScan();

// Generate report
$report = SecurityAuditUtils::generateSecurityReport($audit->id);
```

#### Create Custom Security Finding
```php
$finding_data = array(
    'title' => 'Custom Security Issue',
    'description' => 'Detailed description of the security issue',
    'severity' => SecurityAudit::SEVERITY_HIGH,
    'category' => SecurityAudit::CATEGORY_INPUT_VALIDATION,
    'affected_files' => array('/path/to/vulnerable/file.php'),
    'business_impact' => 'high',
    'remediation_effort' => 'medium',
    'fix_specification' => 'Steps to fix the issue...',
    'references' => array('OWASP Reference', 'CWE-89')
);

$finding = SecurityFinding::createFinding($audit_id, $finding_data);
```

#### Query Security Findings
```php
// Get all findings for an audit
$findings = SecurityFinding::getFindingsByAudit($audit_id);

// Get critical findings only
$critical_findings = SecurityFinding::getFindingsBySeverity($audit_id, SecurityAudit::SEVERITY_CRITICAL);

// Get findings by category
$auth_findings = SecurityFinding::getFindingsByCategory($audit_id, SecurityAudit::CATEGORY_AUTHENTICATION);
```

## Configuration

### Scan Configuration Options

The framework supports extensive configuration through the `SecurityAuditConfig` class:

```php
$config = array(
    'scan_types' => array(
        'sql_injection' => true,
        'xss' => true,
        'file_upload' => true,
        'authentication' => true,
        'hardcoded_creds' => true,
        'file_permissions' => true,
        'configuration' => true
    ),
    'directories' => array(
        'classes/',
        'controllers/',
        'modules/',
        'admin/',
        'webservice/',
        'config/'
    ),
    'extensions' => array('php'),
    'exclude_patterns' => array(
        'cache/',
        'log/',
        'upload/',
        'vendor/',
        'node_modules/',
        '.git/'
    ),
    'max_files' => 1000,
    'severity_threshold' => 2
);

SecurityAuditConfig::updateScanConfig($config);
```

### Database Schema

The framework creates three main tables:

- `ps_security_audit`: Main audit records
- `ps_security_finding`: Individual vulnerability findings
- `ps_security_scan_config`: Configuration settings

## Integration with QloApps

### Hotel-Specific Security Checks

The framework includes specialized checks for hotel management systems:

- Booking data validation and sanitization
- Guest information protection (GDPR compliance)
- Payment processing security (PCI DSS compliance)
- Room availability and pricing data integrity
- API endpoint security for channel manager integrations

### Module Security Assessment

Automatically scans QloApps modules for:

- Hotel reservation system vulnerabilities
- Room management security issues
- Payment gateway integration security
- Third-party module compliance

## Compliance Support

### GDPR Compliance Assessment

- Data processing lawfulness verification
- Consent mechanism validation
- Data subject rights implementation
- Privacy by design assessment

### PCI DSS Compliance Evaluation

- Cardholder data protection measures
- Secure payment processing validation
- Access control verification
- Network security assessment

## Reporting and Analytics

### Report Formats

- **JSON**: Machine-readable format for integration
- **Text**: Human-readable summary reports
- **HTML**: Web-based detailed reports (future enhancement)

### Report Contents

- Executive summary with risk assessment
- Detailed findings by severity and category
- Remediation recommendations with priorities
- Compliance assessment results
- Code examples and fix specifications

## Best Practices

### Regular Scanning

- Schedule daily automated scans
- Run comprehensive scans before deployments
- Perform targeted scans after code changes
- Monitor scan results for trend analysis

### Remediation Workflow

1. **Prioritize by Risk**: Address critical and high-severity findings first
2. **Assess Business Impact**: Consider operational impact of fixes
3. **Plan Remediation**: Estimate effort and resources required
4. **Implement Fixes**: Apply security patches and improvements
5. **Verify Resolution**: Re-scan to confirm fixes are effective
6. **Document Changes**: Maintain audit trail of security improvements

### Security Monitoring

- Set up alerts for critical findings
- Track remediation progress over time
- Monitor compliance status changes
- Review security trends and patterns

## Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Fix file permissions
chmod 755 tools/security_audit_cli.php
chmod 644 classes/Security*.php
```

#### Database Connection Issues
- Verify database credentials in `/config/settings.inc.php`
- Check database server availability
- Ensure proper database permissions

#### Memory Limits
```php
// Increase memory limit for large scans
ini_set('memory_limit', '512M');
```

#### Scan Timeouts
- Reduce `max_files` configuration setting
- Exclude large directories from scanning
- Run scans in smaller batches

### Debug Mode

Enable debug output for troubleshooting:

```php
// Enable debug mode in scanner
$scanner = new SecurityScanner($audit_id);
$scanner->setDebugMode(true);
```

## Security Considerations

### Framework Security

- Store audit results securely with appropriate access controls
- Protect configuration files from unauthorized access
- Use secure communication channels for remote scanning
- Regularly update the framework for new vulnerability patterns

### Data Protection

- Audit results may contain sensitive information
- Implement proper data retention policies
- Ensure compliance with data protection regulations
- Use encryption for stored audit data when required

## Support and Maintenance

### Updates

- Regularly update vulnerability detection patterns
- Add new security categories as needed
- Enhance compliance assessment capabilities
- Improve reporting and analytics features

### Community Contributions

- Submit new vulnerability detection patterns
- Report false positives and improve accuracy
- Contribute additional compliance frameworks
- Enhance documentation and examples

## License

This Security Audit Framework is provided under the same license as QloApps. Please refer to the main QloApps license for terms and conditions.

## Changelog

### Version 1.0.0
- Initial release with core security audit functionality
- Automated vulnerability scanning for common security issues
- Severity rating and categorization system
- CLI interface for audit management
- Configurable scan settings
- JSON and text report generation
- Database schema for audit storage
- Integration with QloApps hotel management features