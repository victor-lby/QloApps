<?php
/**
 * Security Findings Compilation Tool
 * 
 * Compiles and categorizes all security findings from various assessments
 * Organizes findings by severity and category with business impact analysis
 */

require_once(dirname(__FILE__) . '/../config/config.inc.php');
require_once(dirname(__FILE__) . '/../classes/SecurityAudit.php');
require_once(dirname(__FILE__) . '/../classes/SecurityFinding.php');
require_once(dirname(__FILE__) . '/../classes/SecurityScanner.php');
require_once(dirname(__FILE__) . '/../classes/GDPRComplianceAudit.php');

class SecurityFindingsCompiler
{
    private $audit_id;
    private $findings = array();
    private $categories = array();
    private $severity_counts = array();
    private $business_impact_analysis = array();

    public function __construct($audit_id = null)
    {
        $this->audit_id = $audit_id;
        $this->initializeCategories();
        $this->initializeSeverityCounts();
    }

    /**
     * Initialize security finding categories
     */
    private function initializeCategories()
    {
        $this->categories = array(
            'authentication' => array(
                'name' => 'Authentication & Authorization',
                'description' => 'Issues related to user authentication, session management, and access controls',
                'findings' => array()
            ),
            'input_validation' => array(
                'name' => 'Input Validation & Injection',
                'description' => 'SQL injection, XSS, and other input validation vulnerabilities',
                'findings' => array()
            ),
            'data_protection' => array(
                'name' => 'Data Protection & Encryption',
                'description' => 'Issues with sensitive data handling, encryption, and privacy protection',
                'findings' => array()
            ),
            'configuration' => array(
                'name' => 'Configuration & Infrastructure',
                'description' => 'System configuration, file permissions, and infrastructure security issues',
                'findings' => array()
            ),
            'api_security' => array(
                'name' => 'API Security',
                'description' => 'Web service authentication, authorization, and security vulnerabilities',
                'findings' => array()
            ),
            'third_party' => array(
                'name' => 'Third-Party & Module Security',
                'description' => 'Security issues in modules, dependencies, and third-party integrations',
                'findings' => array()
            ),
            'gdpr_compliance' => array(
                'name' => 'GDPR Compliance',
                'description' => 'Data protection regulation compliance issues',
                'findings' => array()
            ),
            'pci_dss_compliance' => array(
                'name' => 'PCI DSS Compliance',
                'description' => 'Payment card industry security standard compliance issues',
                'findings' => array()
            )
        );
    }

    /**
     * Initialize severity counters
     */
    private function initializeSeverityCounts()
    {
        $this->severity_counts = array(
            5 => array('count' => 0, 'label' => 'Critical'),
            4 => array('count' => 0, 'label' => 'High'),
            3 => array('count' => 0, 'label' => 'Medium'),
            2 => array('count' => 0, 'label' => 'Low'),
            1 => array('count' => 0, 'label' => 'Informational'),
            0 => array('count' => 0, 'label' => 'None')
        );
    }

    /**
     * Compile all security findings from database
     */
    public function compileFindings()
    {
        if (!$this->audit_id) {
            // Get the most recent audit
            $sql = 'SELECT id_audit FROM ' . _DB_PREFIX_ . 'security_audit 
                    ORDER BY date_created DESC LIMIT 1';
            $result = Db::getInstance()->getRow($sql);
            if ($result) {
                $this->audit_id = $result['id_audit'];
            } else {
                throw new Exception('No security audit found');
            }
        }

        // Get all findings for this audit
        $sql = 'SELECT * FROM ' . _DB_PREFIX_ . 'security_finding 
                WHERE id_audit = ' . (int)$this->audit_id . '
                ORDER BY severity DESC, category ASC, title ASC';
        
        $findings = Db::getInstance()->executeS($sql);
        
        if (!$findings) {
            throw new Exception('No security findings found for audit ID: ' . $this->audit_id);
        }

        foreach ($findings as $finding_data) {
            $finding = new SecurityFinding();
            foreach ($finding_data as $key => $value) {
                if (property_exists($finding, $key)) {
                    $finding->$key = $value;
                }
            }
            
            $this->processSecurityFinding($finding);
        }

        $this->calculateBusinessImpact();
        
        return $this->findings;
    }

    /**
     * Process individual security finding
     */
    private function processSecurityFinding($finding)
    {
        // Categorize finding
        $category = $this->categorizeFinding($finding);
        
        // Add to category
        if (isset($this->categories[$category])) {
            $this->categories[$category]['findings'][] = $finding;
        }

        // Count severity
        if (isset($this->severity_counts[$finding->severity])) {
            $this->severity_counts[$finding->severity]['count']++;
        }

        // Store finding
        $this->findings[] = $finding;
    }

    /**
     * Categorize security finding based on category and title
     */
    private function categorizeFinding($finding)
    {
        $category = strtolower($finding->category);
        $title = strtolower($finding->title);

        // Map categories
        if (strpos($category, 'auth') !== false || strpos($title, 'auth') !== false) {
            return 'authentication';
        } elseif (strpos($category, 'input') !== false || strpos($category, 'injection') !== false || 
                  strpos($title, 'sql') !== false || strpos($title, 'xss') !== false) {
            return 'input_validation';
        } elseif (strpos($category, 'data') !== false || strpos($category, 'encryption') !== false ||
                  strpos($title, 'encryption') !== false || strpos($title, 'password') !== false) {
            return 'data_protection';
        } elseif (strpos($category, 'config') !== false || strpos($category, 'infrastructure') !== false ||
                  strpos($title, 'config') !== false || strpos($title, 'permission') !== false) {
            return 'configuration';
        } elseif (strpos($category, 'api') !== false || strpos($title, 'api') !== false ||
                  strpos($title, 'webservice') !== false) {
            return 'api_security';
        } elseif (strpos($category, 'module') !== false || strpos($category, 'third') !== false ||
                  strpos($title, 'module') !== false || strpos($title, 'dependency') !== false) {
            return 'third_party';
        } elseif (strpos($category, 'gdpr') !== false || strpos($title, 'gdpr') !== false ||
                  strpos($title, 'privacy') !== false) {
            return 'gdpr_compliance';
        } elseif (strpos($category, 'pci') !== false || strpos($title, 'pci') !== false ||
                  strpos($title, 'payment') !== false) {
            return 'pci_dss_compliance';
        }

        // Default to configuration if no specific match
        return 'configuration';
    }

    /**
     * Calculate business impact analysis
     */
    private function calculateBusinessImpact()
    {
        $this->business_impact_analysis = array(
            'critical_business_risks' => array(),
            'financial_impact' => array(),
            'operational_impact' => array(),
            'compliance_risks' => array(),
            'reputation_risks' => array()
        );

        foreach ($this->findings as $finding) {
            $this->assessBusinessImpact($finding);
        }
    }

    /**
     * Assess business impact for individual finding
     */
    private function assessBusinessImpact($finding)
    {
        $title = strtolower($finding->title);
        $description = strtolower($finding->description);
        $severity = $finding->severity;

        // Critical business risks (severity 4-5)
        if ($severity >= 4) {
            $risk = array(
                'title' => $finding->title,
                'severity' => $severity,
                'impact' => $this->determineBusinessImpact($finding)
            );
            $this->business_impact_analysis['critical_business_risks'][] = $risk;
        }

        // Financial impact
        if (strpos($title, 'payment') !== false || strpos($title, 'pci') !== false ||
            strpos($title, 'sql injection') !== false || strpos($title, 'data breach') !== false) {
            $this->business_impact_analysis['financial_impact'][] = array(
                'finding' => $finding->title,
                'impact' => $this->calculateFinancialImpact($finding)
            );
        }

        // Operational impact
        if (strpos($title, 'availability') !== false || strpos($title, 'performance') !== false ||
            strpos($title, 'system') !== false) {
            $this->business_impact_analysis['operational_impact'][] = array(
                'finding' => $finding->title,
                'impact' => $this->calculateOperationalImpact($finding)
            );
        }

        // Compliance risks
        if (strpos($title, 'gdpr') !== false || strpos($title, 'pci') !== false ||
            strpos($title, 'compliance') !== false) {
            $this->business_impact_analysis['compliance_risks'][] = array(
                'finding' => $finding->title,
                'regulation' => $this->identifyRegulation($finding),
                'risk_level' => $this->assessComplianceRisk($finding)
            );
        }

        // Reputation risks
        if ($severity >= 3 && (strpos($title, 'data') !== false || strpos($title, 'privacy') !== false ||
            strpos($title, 'breach') !== false)) {
            $this->business_impact_analysis['reputation_risks'][] = array(
                'finding' => $finding->title,
                'impact' => $this->assessReputationImpact($finding)
            );
        }
    }

    /**
     * Determine business impact level
     */
    private function determineBusinessImpact($finding)
    {
        switch ($finding->severity) {
            case 5:
                return 'Critical - Immediate threat to business operations and customer data';
            case 4:
                return 'High - Significant risk to business security and customer trust';
            case 3:
                return 'Medium - Moderate risk requiring prompt attention';
            case 2:
                return 'Low - Minor risk with limited business impact';
            default:
                return 'Informational - Best practice recommendation';
        }
    }

    /**
     * Calculate financial impact
     */
    private function calculateFinancialImpact($finding)
    {
        $title = strtolower($finding->title);
        
        if (strpos($title, 'pci') !== false || strpos($title, 'payment') !== false) {
            return 'High - Potential PCI DSS fines ($5,000-$100,000/month), payment processor penalties';
        } elseif (strpos($title, 'gdpr') !== false) {
            return 'High - GDPR fines up to 4% of annual revenue or €20 million';
        } elseif (strpos($title, 'sql injection') !== false) {
            return 'Critical - Data breach costs averaging $4.45 million, legal liabilities';
        } elseif (strpos($title, 'data breach') !== false) {
            return 'Critical - Customer notification costs, legal fees, business disruption';
        }
        
        return 'Medium - Potential security incident response costs, system downtime';
    }

    /**
     * Calculate operational impact
     */
    private function calculateOperationalImpact($finding)
    {
        $severity = $finding->severity;
        
        if ($severity >= 4) {
            return 'High - Potential system compromise, service disruption, emergency response required';
        } elseif ($severity == 3) {
            return 'Medium - Possible service degradation, increased security monitoring needed';
        }
        
        return 'Low - Minor operational adjustments, routine maintenance required';
    }

    /**
     * Identify applicable regulation
     */
    private function identifyRegulation($finding)
    {
        $title = strtolower($finding->title);
        
        if (strpos($title, 'gdpr') !== false) {
            return 'GDPR (General Data Protection Regulation)';
        } elseif (strpos($title, 'pci') !== false) {
            return 'PCI DSS (Payment Card Industry Data Security Standard)';
        }
        
        return 'General security compliance requirements';
    }

    /**
     * Assess compliance risk level
     */
    private function assessComplianceRisk($finding)
    {
        switch ($finding->severity) {
            case 5:
                return 'Critical - Non-compliance with regulatory requirements';
            case 4:
                return 'High - Significant compliance gaps requiring immediate attention';
            case 3:
                return 'Medium - Partial compliance, improvements needed';
            default:
                return 'Low - Minor compliance considerations';
        }
    }

    /**
     * Assess reputation impact
     */
    private function assessReputationImpact($finding)
    {
        $severity = $finding->severity;
        
        if ($severity >= 4) {
            return 'High - Potential customer trust loss, negative media coverage, competitive disadvantage';
        } elseif ($severity == 3) {
            return 'Medium - Customer concern, need for transparency and communication';
        }
        
        return 'Low - Minimal reputation impact with proper handling';
    }

    /**
     * Get compiled findings by category
     */
    public function getFindingsByCategory()
    {
        return $this->categories;
    }

    /**
     * Get severity distribution
     */
    public function getSeverityDistribution()
    {
        return $this->severity_counts;
    }

    /**
     * Get business impact analysis
     */
    public function getBusinessImpactAnalysis()
    {
        return $this->business_impact_analysis;
    }

    /**
     * Get total findings count
     */
    public function getTotalFindings()
    {
        return count($this->findings);
    }

    /**
     * Get critical findings count
     */
    public function getCriticalFindings()
    {
        return $this->severity_counts[5]['count'] + $this->severity_counts[4]['count'];
    }

    /**
     * Generate summary statistics
     */
    public function generateSummaryStats()
    {
        $total = $this->getTotalFindings();
        $critical = $this->getCriticalFindings();
        
        return array(
            'total_findings' => $total,
            'critical_findings' => $critical,
            'critical_percentage' => $total > 0 ? round(($critical / $total) * 100, 1) : 0,
            'severity_distribution' => $this->severity_counts,
            'categories_affected' => count(array_filter($this->categories, function($cat) {
                return count($cat['findings']) > 0;
            })),
            'most_affected_category' => $this->getMostAffectedCategory()
        );
    }

    /**
     * Get most affected category
     */
    private function getMostAffectedCategory()
    {
        $max_count = 0;
        $max_category = '';
        
        foreach ($this->categories as $key => $category) {
            $count = count($category['findings']);
            if ($count > $max_count) {
                $max_count = $count;
                $max_category = $category['name'];
            }
        }
        
        return array('name' => $max_category, 'count' => $max_count);
    }
}

// CLI execution
if (php_sapi_name() === 'cli') {
    echo "Security Findings Compilation Tool\n";
    echo "==================================\n\n";

    try {
        $compiler = new SecurityFindingsCompiler();
        
        echo "Compiling security findings...\n";
        $findings = $compiler->compileFindings();
        
        $stats = $compiler->generateSummaryStats();
        
        echo "Compilation completed successfully!\n\n";
        echo "Summary Statistics:\n";
        echo "- Total findings: " . $stats['total_findings'] . "\n";
        echo "- Critical/High findings: " . $stats['critical_findings'] . " (" . $stats['critical_percentage'] . "%)\n";
        echo "- Categories affected: " . $stats['categories_affected'] . "\n";
        echo "- Most affected category: " . $stats['most_affected_category']['name'] . " (" . $stats['most_affected_category']['count'] . " findings)\n\n";
        
        echo "Severity Distribution:\n";
        foreach ($stats['severity_distribution'] as $severity => $data) {
            if ($data['count'] > 0) {
                echo "- " . $data['label'] . " (Level $severity): " . $data['count'] . " findings\n";
            }
        }
        
        echo "\nFindings compiled and ready for report generation.\n";
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}