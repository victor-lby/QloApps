<?php
/**
 * Security Audit CLI Tool
 * 
 * Command-line interface for running security audits
 * Usage: php tools/security_audit_cli.php [options]
 */

// Include PrestaShop bootstrap
require_once(dirname(__FILE__) . '/../config/config.inc.php');

// Include security audit classes
require_once(dirname(__FILE__) . '/../classes/SecurityAudit.php');
require_once(dirname(__FILE__) . '/../classes/SecurityFinding.php');
require_once(dirname(__FILE__) . '/../classes/SecurityAuditUtils.php');
require_once(dirname(__FILE__) . '/../classes/SecurityScanner.php');
require_once(dirname(__FILE__) . '/../classes/SecurityAuditConfig.php');

class SecurityAuditCLI
{
    private $options;
    private $commands;

    public function __construct()
    {
        $this->options = $this->parseArguments();
        $this->commands = array(
            'scan' => 'Run comprehensive security scan',
            'create-audit' => 'Create new security audit',
            'list-audits' => 'List all security audits',
            'show-audit' => 'Show audit details',
            'export-report' => 'Export audit report',
            'install-tables' => 'Install security audit database tables',
            'config' => 'Manage scan configuration',
            'help' => 'Show this help message'
        );
    }

    /**
     * Run the CLI application
     */
    public function run()
    {
        if (empty($this->options['command'])) {
            $this->showHelp();
            return;
        }

        $command = $this->options['command'];

        switch ($command) {
            case 'scan':
                $this->runScan();
                break;
            case 'create-audit':
                $this->createAudit();
                break;
            case 'list-audits':
                $this->listAudits();
                break;
            case 'show-audit':
                $this->showAudit();
                break;
            case 'export-report':
                $this->exportReport();
                break;
            case 'install-tables':
                $this->installTables();
                break;
            case 'config':
                $this->manageConfig();
                break;
            case 'help':
            default:
                $this->showHelp();
                break;
        }
    }

    /**
     * Run comprehensive security scan
     */
    private function runScan()
    {
        $this->output("Starting comprehensive security scan...\n");

        // Create new audit
        $audit = new SecurityAudit();
        $audit->audit_name = isset($this->options['name']) ? 
                            $this->options['name'] : 
                            'CLI Scan ' . date('Y-m-d H:i:s');
        $audit->status = 'running';
        
        if (!$audit->save()) {
            $this->output("Error: Could not create audit record\n", 'error');
            return;
        }

        $this->output("Created audit ID: {$audit->id}\n");

        // Initialize scanner
        $scanner = new SecurityScanner($audit->id);
        
        try {
            $results = $scanner->runComprehensiveScan();
            
            $this->output("\nScan completed successfully!\n", 'success');
            $this->output("Files scanned: {$results['files_scanned']}\n");
            $this->output("Vulnerabilities found: {$results['vulnerabilities_found']}\n");
            
            // Show summary
            $audit = new SecurityAudit($audit->id);
            $summary = $audit->getSummary();
            
            $this->output("\nSeverity Breakdown:\n");
            $this->output("  Critical: {$summary['severity_breakdown']['critical']}\n", 'error');
            $this->output("  High: {$summary['severity_breakdown']['high']}\n", 'warning');
            $this->output("  Medium: {$summary['severity_breakdown']['medium']}\n", 'info');
            $this->output("  Low: {$summary['severity_breakdown']['low']}\n");
            $this->output("  Info: {$summary['severity_breakdown']['info']}\n");
            
            $this->output("\nOverall Risk Level: {$summary['risk_level']}\n");
            
            if (isset($this->options['export'])) {
                $this->exportAuditReport($audit->id, $this->options['export']);
            }
            
        } catch (Exception $e) {
            $this->output("Error during scan: " . $e->getMessage() . "\n", 'error');
        }
    }

    /**
     * Create new audit
     */
    private function createAudit()
    {
        $name = isset($this->options['name']) ? 
                $this->options['name'] : 
                'Manual Audit ' . date('Y-m-d H:i:s');

        $audit = new SecurityAudit();
        $audit->audit_name = $name;
        
        if ($audit->save()) {
            $this->output("Created audit '{$name}' with ID: {$audit->id}\n", 'success');
        } else {
            $this->output("Error: Could not create audit\n", 'error');
        }
    }

    /**
     * List all audits
     */
    private function listAudits()
    {
        $sql = 'SELECT * FROM ' . _DB_PREFIX_ . 'security_audit ORDER BY audit_date DESC';
        $audits = Db::getInstance()->executeS($sql);

        if (empty($audits)) {
            $this->output("No audits found\n");
            return;
        }

        $this->output(sprintf("%-5s %-30s %-20s %-12s %-8s\n", 
                             'ID', 'Name', 'Date', 'Status', 'Findings'));
        $this->output(str_repeat('-', 80) . "\n");

        foreach ($audits as $audit) {
            $this->output(sprintf("%-5s %-30s %-20s %-12s %-8s\n",
                                 $audit['id_audit'],
                                 substr($audit['audit_name'], 0, 30),
                                 $audit['audit_date'],
                                 $audit['status'],
                                 $audit['total_findings']));
        }
    }

    /**
     * Show audit details
     */
    private function showAudit()
    {
        if (!isset($this->options['id'])) {
            $this->output("Error: Audit ID required (--id=X)\n", 'error');
            return;
        }

        $audit_id = (int)$this->options['id'];
        $audit = new SecurityAudit($audit_id);

        if (!$audit->id) {
            $this->output("Error: Audit not found\n", 'error');
            return;
        }

        $summary = $audit->getSummary();
        
        $this->output("Audit Details:\n");
        $this->output("  ID: {$audit->id}\n");
        $this->output("  Name: {$audit->audit_name}\n");
        $this->output("  Date: {$audit->audit_date}\n");
        $this->output("  Status: {$audit->status}\n");
        $this->output("  Total Findings: {$audit->total_findings}\n");
        $this->output("  Risk Level: {$summary['risk_level']}\n");

        // Show findings by category
        $findings = SecurityFinding::getFindingsByAudit($audit_id);
        $categories = array();

        foreach ($findings as $finding) {
            $categories[$finding['category']][] = $finding;
        }

        $this->output("\nFindings by Category:\n");
        foreach ($categories as $category => $category_findings) {
            $category_name = SecurityAudit::getSecurityCategories()[$category] ?? $category;
            $this->output("  {$category_name}: " . count($category_findings) . " findings\n");
        }
    }

    /**
     * Export audit report
     */
    private function exportReport()
    {
        if (!isset($this->options['id'])) {
            $this->output("Error: Audit ID required (--id=X)\n", 'error');
            return;
        }

        $audit_id = (int)$this->options['id'];
        $format = isset($this->options['format']) ? $this->options['format'] : 'json';
        $output_file = isset($this->options['output']) ? $this->options['output'] : null;

        $this->exportAuditReport($audit_id, $output_file, $format);
    }

    /**
     * Export audit report to file
     */
    private function exportAuditReport($audit_id, $output_file = null, $format = 'json')
    {
        $report = SecurityAuditUtils::generateSecurityReport($audit_id);
        
        if (!$output_file) {
            $output_file = "security_audit_{$audit_id}_" . date('Y-m-d_H-i-s') . ".{$format}";
        }

        switch ($format) {
            case 'json':
                $content = json_encode($report, JSON_PRETTY_PRINT);
                break;
            case 'txt':
                $content = $this->formatReportAsText($report);
                break;
            default:
                $this->output("Error: Unsupported format '{$format}'\n", 'error');
                return;
        }

        if (file_put_contents($output_file, $content)) {
            $this->output("Report exported to: {$output_file}\n", 'success');
        } else {
            $this->output("Error: Could not write report to file\n", 'error');
        }
    }

    /**
     * Format report as plain text
     */
    private function formatReportAsText($report)
    {
        $text = "SECURITY AUDIT REPORT\n";
        $text .= str_repeat('=', 50) . "\n\n";
        
        $summary = $report['audit_summary'];
        $text .= "Audit: {$summary['audit_name']}\n";
        $text .= "Date: {$summary['audit_date']}\n";
        $text .= "Status: {$summary['status']}\n";
        $text .= "Total Findings: {$summary['total_findings']}\n";
        $text .= "Risk Level: {$summary['risk_level']}\n\n";

        $text .= "SEVERITY BREAKDOWN\n";
        $text .= str_repeat('-', 20) . "\n";
        foreach ($summary['severity_breakdown'] as $severity => $count) {
            $text .= ucfirst($severity) . ": {$count}\n";
        }

        $text .= "\nFINDINGS BY SEVERITY\n";
        $text .= str_repeat('-', 20) . "\n";
        foreach ($report['findings_by_severity'] as $severity => $findings) {
            $text .= "\n{$severity} ({" . count($findings) . " findings):\n";
            foreach ($findings as $finding) {
                $text .= "  - {$finding['title']}\n";
            }
        }

        return $text;
    }

    /**
     * Install database tables
     */
    private function installTables()
    {
        $this->output("Installing security audit database tables...\n");
        
        if (SecurityAuditUtils::createTables()) {
            $this->output("Tables installed successfully\n", 'success');
        } else {
            $this->output("Error: Could not install tables\n", 'error');
        }
    }

    /**
     * Manage configuration
     */
    private function manageConfig()
    {
        $action = isset($this->options['action']) ? $this->options['action'] : 'show';

        switch ($action) {
            case 'show':
                $this->showConfig();
                break;
            case 'reset':
                $this->resetConfig();
                break;
            case 'export':
                $this->exportConfig();
                break;
            default:
                $this->output("Available config actions: show, reset, export\n");
        }
    }

    /**
     * Show current configuration
     */
    private function showConfig()
    {
        $config = SecurityAuditConfig::getScanConfig();
        
        $this->output("Current Scan Configuration:\n");
        $this->output("Scan Types:\n");
        foreach ($config['scan_types'] as $type => $enabled) {
            $status = $enabled ? 'Enabled' : 'Disabled';
            $this->output("  {$type}: {$status}\n");
        }
        
        $this->output("Directories: " . implode(', ', $config['directories']) . "\n");
        $this->output("Extensions: " . implode(', ', $config['extensions']) . "\n");
        $this->output("Max Files: {$config['max_files']}\n");
        $this->output("Severity Threshold: {$config['severity_threshold']}\n");
    }

    /**
     * Reset configuration to defaults
     */
    private function resetConfig()
    {
        if (SecurityAuditConfig::resetToDefaults()) {
            $this->output("Configuration reset to defaults\n", 'success');
        } else {
            $this->output("Error: Could not reset configuration\n", 'error');
        }
    }

    /**
     * Export configuration
     */
    private function exportConfig()
    {
        $output_file = isset($this->options['output']) ? 
                      $this->options['output'] : 
                      'security_audit_config.json';

        $config_json = SecurityAuditConfig::exportConfig();
        
        if (file_put_contents($output_file, $config_json)) {
            $this->output("Configuration exported to: {$output_file}\n", 'success');
        } else {
            $this->output("Error: Could not export configuration\n", 'error');
        }
    }

    /**
     * Parse command line arguments
     */
    private function parseArguments()
    {
        global $argv;
        $options = array();
        
        if (isset($argv[1])) {
            $options['command'] = $argv[1];
        }

        for ($i = 2; $i < count($argv); $i++) {
            $arg = $argv[$i];
            if (strpos($arg, '--') === 0) {
                $parts = explode('=', substr($arg, 2), 2);
                $key = $parts[0];
                $value = isset($parts[1]) ? $parts[1] : true;
                $options[$key] = $value;
            }
        }

        return $options;
    }

    /**
     * Show help message
     */
    private function showHelp()
    {
        $this->output("QloApps Security Audit CLI Tool\n\n");
        $this->output("Usage: php security_audit_cli.php <command> [options]\n\n");
        $this->output("Commands:\n");
        
        foreach ($this->commands as $command => $description) {
            $this->output(sprintf("  %-15s %s\n", $command, $description));
        }

        $this->output("\nOptions:\n");
        $this->output("  --name=<name>     Audit name\n");
        $this->output("  --id=<id>         Audit ID\n");
        $this->output("  --output=<file>   Output file\n");
        $this->output("  --format=<fmt>    Export format (json, txt)\n");
        $this->output("  --export=<file>   Export report after scan\n");
        $this->output("  --action=<act>    Config action (show, reset, export)\n");

        $this->output("\nExamples:\n");
        $this->output("  php security_audit_cli.php scan --name=\"Daily Scan\"\n");
        $this->output("  php security_audit_cli.php show-audit --id=1\n");
        $this->output("  php security_audit_cli.php export-report --id=1 --format=txt\n");
    }

    /**
     * Output message with optional color
     */
    private function output($message, $type = 'normal')
    {
        $colors = array(
            'normal' => '',
            'success' => "\033[32m",
            'error' => "\033[31m",
            'warning' => "\033[33m",
            'info' => "\033[36m",
            'reset' => "\033[0m"
        );

        if ($type !== 'normal' && isset($colors[$type])) {
            echo $colors[$type] . $message . $colors['reset'];
        } else {
            echo $message;
        }
    }
}

// Run the CLI application
if (php_sapi_name() === 'cli') {
    $cli = new SecurityAuditCLI();
    $cli->run();
} else {
    echo "This script can only be run from the command line.\n";
}