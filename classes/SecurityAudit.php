<?php
/**
 * Security Audit Framework for QloApps
 * 
 * This class provides the core framework for conducting security audits
 * including vulnerability scanning, severity rating, and categorization.
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class SecurityAudit extends ObjectModel
{
    // Severity levels (0-5 scale)
    const SEVERITY_CRITICAL = 5;
    const SEVERITY_HIGH = 4;
    const SEVERITY_MEDIUM = 3;
    const SEVERITY_LOW = 2;
    const SEVERITY_INFO = 1;
    const SEVERITY_NONE = 0;

    // Security categories
    const CATEGORY_AUTHENTICATION = 'authentication';
    const CATEGORY_AUTHORIZATION = 'authorization';
    const CATEGORY_INPUT_VALIDATION = 'input_validation';
    const CATEGORY_DATA_PROTECTION = 'data_protection';
    const CATEGORY_CONFIGURATION = 'configuration';
    const CATEGORY_API_SECURITY = 'api_security';
    const CATEGORY_THIRD_PARTY = 'third_party';
    const CATEGORY_COMPLIANCE = 'compliance';

    public $id;
    public $audit_name;
    public $audit_date;
    public $status;
    public $total_findings;
    public $critical_findings;
    public $high_findings;
    public $medium_findings;
    public $low_findings;
    public $info_findings;

    public static $definition = array(
        'table' => 'security_audit',
        'primary' => 'id_audit',
        'fields' => array(
            'audit_name' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'required' => true,
                'size' => 255
            ),
            'audit_date' => array(
                'type' => self::TYPE_DATE,
                'validate' => 'isDate',
                'required' => true
            ),
            'status' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 32
            ),
            'total_findings' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt'
            ),
            'critical_findings' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt'
            ),
            'high_findings' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt'
            ),
            'medium_findings' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt'
            ),
            'low_findings' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt'
            ),
            'info_findings' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt'
            )
        )
    );

    /**
     * Initialize a new security audit
     */
    public function __construct($id = null)
    {
        parent::__construct($id);
        
        if (!$id) {
            $this->audit_date = date('Y-m-d H:i:s');
            $this->status = 'initialized';
            $this->total_findings = 0;
            $this->critical_findings = 0;
            $this->high_findings = 0;
            $this->medium_findings = 0;
            $this->low_findings = 0;
            $this->info_findings = 0;
        }
    }

    /**
     * Get severity level name
     */
    public static function getSeverityName($severity)
    {
        $severities = array(
            self::SEVERITY_CRITICAL => 'Critical',
            self::SEVERITY_HIGH => 'High',
            self::SEVERITY_MEDIUM => 'Medium',
            self::SEVERITY_LOW => 'Low',
            self::SEVERITY_INFO => 'Informational',
            self::SEVERITY_NONE => 'None'
        );

        return isset($severities[$severity]) ? $severities[$severity] : 'Unknown';
    }

    /**
     * Get all security categories
     */
    public static function getSecurityCategories()
    {
        return array(
            self::CATEGORY_AUTHENTICATION => 'Authentication & Session Management',
            self::CATEGORY_AUTHORIZATION => 'Authorization & Access Control',
            self::CATEGORY_INPUT_VALIDATION => 'Input Validation & Injection Prevention',
            self::CATEGORY_DATA_PROTECTION => 'Data Protection & Encryption',
            self::CATEGORY_CONFIGURATION => 'Configuration & Infrastructure Security',
            self::CATEGORY_API_SECURITY => 'API Security',
            self::CATEGORY_THIRD_PARTY => 'Third-Party & Module Security',
            self::CATEGORY_COMPLIANCE => 'Compliance & Regulatory'
        );
    }

    /**
     * Calculate risk score based on severity and business impact
     */
    public static function calculateRiskScore($severity, $business_impact = 'medium')
    {
        $impact_multipliers = array(
            'low' => 0.5,
            'medium' => 1.0,
            'high' => 1.5,
            'critical' => 2.0
        );

        $multiplier = isset($impact_multipliers[$business_impact]) ? 
                     $impact_multipliers[$business_impact] : 1.0;

        return round($severity * $multiplier, 2);
    }

    /**
     * Update audit statistics
     */
    public function updateStatistics()
    {
        $sql = 'SELECT severity, COUNT(*) as count 
                FROM ' . _DB_PREFIX_ . 'security_finding 
                WHERE id_audit = ' . (int)$this->id . ' 
                GROUP BY severity';
        
        $results = Db::getInstance()->executeS($sql);
        
        // Reset counters
        $this->total_findings = 0;
        $this->critical_findings = 0;
        $this->high_findings = 0;
        $this->medium_findings = 0;
        $this->low_findings = 0;
        $this->info_findings = 0;

        foreach ($results as $result) {
            $this->total_findings += $result['count'];
            
            switch ($result['severity']) {
                case self::SEVERITY_CRITICAL:
                    $this->critical_findings = $result['count'];
                    break;
                case self::SEVERITY_HIGH:
                    $this->high_findings = $result['count'];
                    break;
                case self::SEVERITY_MEDIUM:
                    $this->medium_findings = $result['count'];
                    break;
                case self::SEVERITY_LOW:
                    $this->low_findings = $result['count'];
                    break;
                case self::SEVERITY_INFO:
                    $this->info_findings = $result['count'];
                    break;
            }
        }

        return $this->save();
    }

    /**
     * Get audit summary
     */
    public function getSummary()
    {
        return array(
            'audit_name' => $this->audit_name,
            'audit_date' => $this->audit_date,
            'status' => $this->status,
            'total_findings' => $this->total_findings,
            'severity_breakdown' => array(
                'critical' => $this->critical_findings,
                'high' => $this->high_findings,
                'medium' => $this->medium_findings,
                'low' => $this->low_findings,
                'info' => $this->info_findings
            ),
            'risk_level' => $this->calculateOverallRiskLevel()
        );
    }

    /**
     * Calculate overall risk level
     */
    private function calculateOverallRiskLevel()
    {
        if ($this->critical_findings > 0) {
            return 'Critical';
        } elseif ($this->high_findings > 2) {
            return 'High';
        } elseif ($this->high_findings > 0 || $this->medium_findings > 5) {
            return 'Medium';
        } elseif ($this->medium_findings > 0 || $this->low_findings > 10) {
            return 'Low';
        } else {
            return 'Minimal';
        }
    }
}