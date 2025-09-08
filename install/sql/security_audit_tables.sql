-- Security Audit Framework Database Tables

-- Security Audit main table
CREATE TABLE IF NOT EXISTS `PREFIX_security_audit` (
    `id_audit` int(11) NOT NULL AUTO_INCREMENT,
    `audit_name` varchar(255) NOT NULL,
    `audit_date` datetime NOT NULL,
    `status` varchar(32) DEFAULT 'initialized',
    `total_findings` int(11) DEFAULT 0,
    `critical_findings` int(11) DEFAULT 0,
    `high_findings` int(11) DEFAULT 0,
    `medium_findings` int(11) DEFAULT 0,
    `low_findings` int(11) DEFAULT 0,
    `info_findings` int(11) DEFAULT 0,
    `date_add` datetime NOT NULL,
    `date_upd` datetime NOT NULL,
    PRIMARY KEY (`id_audit`),
    KEY `audit_date` (`audit_date`),
    KEY `status` (`status`)
) ENGINE=ENGINE_TYPE DEFAULT CHARSET=utf8;

-- Security Finding details table
CREATE TABLE IF NOT EXISTS `PREFIX_security_finding` (
    `id_finding` int(11) NOT NULL AUTO_INCREMENT,
    `id_audit` int(11) NOT NULL,
    `title` varchar(255) NOT NULL,
    `description` text NOT NULL,
    `severity` int(1) NOT NULL,
    `category` varchar(64) NOT NULL,
    `affected_files` text,
    `business_impact` varchar(32) DEFAULT 'medium',
    `remediation_effort` varchar(32) DEFAULT 'medium',
    `compliance_impact` text,
    `fix_specification` text,
    `code_examples` text,
    `references` text,
    `status` varchar(32) DEFAULT 'open',
    `risk_score` decimal(5,2) DEFAULT 0.00,
    `date_found` datetime NOT NULL,
    `date_fixed` datetime NULL,
    `date_add` datetime NOT NULL,
    `date_upd` datetime NOT NULL,
    PRIMARY KEY (`id_finding`),
    KEY `id_audit` (`id_audit`),
    KEY `severity` (`severity`),
    KEY `category` (`category`),
    KEY `status` (`status`),
    KEY `risk_score` (`risk_score`),
    FOREIGN KEY (`id_audit`) REFERENCES `PREFIX_security_audit`(`id_audit`) ON DELETE CASCADE
) ENGINE=ENGINE_TYPE DEFAULT CHARSET=utf8;

-- Security Scan Configuration table
CREATE TABLE IF NOT EXISTS `PREFIX_security_scan_config` (
    `id_config` int(11) NOT NULL AUTO_INCREMENT,
    `config_name` varchar(255) NOT NULL,
    `config_key` varchar(128) NOT NULL,
    `config_value` text,
    `config_type` varchar(32) DEFAULT 'string',
    `is_active` tinyint(1) DEFAULT 1,
    `date_add` datetime NOT NULL,
    `date_upd` datetime NOT NULL,
    PRIMARY KEY (`id_config`),
    UNIQUE KEY `config_key` (`config_key`),
    KEY `is_active` (`is_active`)
) ENGINE=ENGINE_TYPE DEFAULT CHARSET=utf8;

-- Insert default scan configuration
INSERT INTO `PREFIX_security_scan_config` (`config_name`, `config_key`, `config_value`, `config_type`, `is_active`, `date_add`, `date_upd`) VALUES
('SQL Injection Scanning', 'scan_sql_injection', '1', 'boolean', 1, NOW(), NOW()),
('XSS Scanning', 'scan_xss', '1', 'boolean', 1, NOW(), NOW()),
('File Upload Security', 'scan_file_upload', '1', 'boolean', 1, NOW(), NOW()),
('Authentication Security', 'scan_authentication', '1', 'boolean', 1, NOW(), NOW()),
('Hardcoded Credentials', 'scan_hardcoded_creds', '1', 'boolean', 1, NOW(), NOW()),
('File Permissions', 'scan_file_permissions', '1', 'boolean', 1, NOW(), NOW()),
('Configuration Security', 'scan_configuration', '1', 'boolean', 1, NOW(), NOW()),
('Scan Directories', 'scan_directories', 'classes/,controllers/,modules/,admin/,webservice/,config/', 'string', 1, NOW(), NOW()),
('File Extensions', 'scan_extensions', 'php', 'string', 1, NOW(), NOW()),
('Exclude Patterns', 'exclude_patterns', 'cache/,log/,upload/,vendor/,node_modules/,.git/', 'string', 1, NOW(), NOW()),
('Max Scan Files', 'max_scan_files', '1000', 'integer', 1, NOW(), NOW()),
('Severity Threshold', 'severity_threshold', '2', 'integer', 1, NOW(), NOW());