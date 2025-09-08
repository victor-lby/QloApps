<?php
/**
 * Security Finding Model
 * 
 * Represents individual security vulnerabilities and issues found during audits
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class SecurityFinding extends ObjectModel
{
    public $id;
    public $id_audit;
    public $title;
    public $description;
    public $severity;
    public $category;
    public $affected_files;
    public $business_impact;
    public $remediation_effort;
    public $compliance_impact;
    public $fix_specification;
    public $code_examples;
    public $references;
    public $status;
    public $risk_score;
    public $date_found;
    public $date_fixed;

    public static $definition = array(
        'table' => 'security_finding',
        'primary' => 'id_finding',
        'fields' => array(
            'id_audit' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedId',
                'required' => true
            ),
            'title' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'required' => true,
                'size' => 255
            ),
            'description' => array(
                'type' => self::TYPE_HTML,
                'validate' => 'isCleanHtml',
                'required' => true
            ),
            'severity' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt',
                'required' => true
            ),
            'category' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'required' => true,
                'size' => 64
            ),
            'affected_files' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isString'
            ),
            'business_impact' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 32
            ),
            'remediation_effort' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 32
            ),
            'compliance_impact' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isString'
            ),
            'fix_specification' => array(
                'type' => self::TYPE_HTML,
                'validate' => 'isCleanHtml'
            ),
            'code_examples' => array(
                'type' => self::TYPE_HTML,
                'validate' => 'isCleanHtml'
            ),
            'references' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isString'
            ),
            'status' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 32
            ),
            'risk_score' => array(
                'type' => self::TYPE_FLOAT,
                'validate' => 'isFloat'
            ),
            'date_found' => array(
                'type' => self::TYPE_DATE,
                'validate' => 'isDate'
            ),
            'date_fixed' => array(
                'type' => self::TYPE_DATE,
                'validate' => 'isDate'
            )
        )
    );

    /**
     * Initialize a new security finding
     */
    public function __construct($id = null)
    {
        parent::__construct($id);
        
        if (!$id) {
            $this->date_found = date('Y-m-d H:i:s');
            $this->status = 'open';
            $this->business_impact = 'medium';
            $this->remediation_effort = 'medium';
        }
    }

    /**
     * Create a new security finding
     */
    public static function createFinding($audit_id, $data)
    {
        $finding = new self();
        $finding->id_audit = $audit_id;
        $finding->title = $data['title'];
        $finding->description = $data['description'];
        $finding->severity = $data['severity'];
        $finding->category = $data['category'];
        $finding->affected_files = isset($data['affected_files']) ? 
                                  implode(',', $data['affected_files']) : '';
        $finding->business_impact = isset($data['business_impact']) ? 
                                   $data['business_impact'] : 'medium';
        $finding->remediation_effort = isset($data['remediation_effort']) ? 
                                      $data['remediation_effort'] : 'medium';
        $finding->compliance_impact = isset($data['compliance_impact']) ? 
                                     $data['compliance_impact'] : '';
        $finding->fix_specification = isset($data['fix_specification']) ? 
                                     $data['fix_specification'] : '';
        $finding->code_examples = isset($data['code_examples']) ? 
                                 $data['code_examples'] : '';
        $finding->references = isset($data['references']) ? 
                              implode(',', $data['references']) : '';

        // Calculate risk score
        $finding->risk_score = SecurityAudit::calculateRiskScore(
            $finding->severity, 
            $finding->business_impact
        );

        if ($finding->save()) {
            return $finding;
        }

        return false;
    }

    /**
     * Get findings by audit ID
     */
    public static function getFindingsByAudit($audit_id, $category = null, $severity = null)
    {
        $sql = 'SELECT * FROM ' . _DB_PREFIX_ . 'security_finding 
                WHERE id_audit = ' . (int)$audit_id;

        if ($category) {
            $sql .= ' AND category = "' . pSQL($category) . '"';
        }

        if ($severity !== null) {
            $sql .= ' AND severity = ' . (int)$severity;
        }

        $sql .= ' ORDER BY severity DESC, risk_score DESC';

        return Db::getInstance()->executeS($sql);
    }

    /**
     * Get findings by severity
     */
    public static function getFindingsBySeverity($audit_id, $severity)
    {
        return self::getFindingsByAudit($audit_id, null, $severity);
    }

    /**
     * Get findings by category
     */
    public static function getFindingsByCategory($audit_id, $category)
    {
        return self::getFindingsByAudit($audit_id, $category);
    }

    /**
     * Mark finding as fixed
     */
    public function markAsFixed()
    {
        $this->status = 'fixed';
        $this->date_fixed = date('Y-m-d H:i:s');
        return $this->save();
    }

    /**
     * Get affected files as array
     */
    public function getAffectedFilesArray()
    {
        return $this->affected_files ? explode(',', $this->affected_files) : array();
    }

    /**
     * Get references as array
     */
    public function getReferencesArray()
    {
        return $this->references ? explode(',', $this->references) : array();
    }

    /**
     * Get severity badge HTML
     */
    public function getSeverityBadge()
    {
        $badges = array(
            SecurityAudit::SEVERITY_CRITICAL => '<span class="badge badge-danger">Critical</span>',
            SecurityAudit::SEVERITY_HIGH => '<span class="badge badge-warning">High</span>',
            SecurityAudit::SEVERITY_MEDIUM => '<span class="badge badge-info">Medium</span>',
            SecurityAudit::SEVERITY_LOW => '<span class="badge badge-secondary">Low</span>',
            SecurityAudit::SEVERITY_INFO => '<span class="badge badge-light">Info</span>',
            SecurityAudit::SEVERITY_NONE => '<span class="badge badge-success">None</span>'
        );

        return isset($badges[$this->severity]) ? $badges[$this->severity] : 'Unknown';
    }

    /**
     * Get category display name
     */
    public function getCategoryDisplayName()
    {
        $categories = SecurityAudit::getSecurityCategories();
        return isset($categories[$this->category]) ? $categories[$this->category] : $this->category;
    }
}