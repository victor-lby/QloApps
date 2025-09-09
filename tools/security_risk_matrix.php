<?php
/**
 * Security Risk Matrix and Prioritization Tool
 * 
 * This tool creates a comprehensive risk matrix based on severity and business impact,
 * develops timelines for addressing issues, and estimates remediation effort.
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once(dirname(__FILE__) . '/../classes/SecurityFinding.php');

class SecurityRiskMatrix
{
    private $findings = array();
    private $riskMatrix = array();
    private $remediationTimeline = array();
    private $resourceEstimates = array();

    // Risk scoring weights
    const SEVERITY_WEIGHT = 0.6;
    const BUSINESS_IMPACT_WEIGHT = 0.4;
    
    // Business impact scoring
    const BUSINESS_IMPACT_SCORES = array(
        'critical' => 5,
        'high' => 4,
        'medium' => 3,
        'low' => 2,
        'informational' => 1
    );
    
    // Remediation effort scoring
    const EFFORT_SCORES = array(
        'low' => 1,
        'medium' => 2,
        'high' => 3
    );
    
    // Timeline categories based on risk score
    const TIMELINE_CATEGORIES = array(
        'immediate' => array('min_score' => 4.5, 'timeframe' => '0-24 hours', 'priority' => 1),
        'urgent' => array('min_score' => 3.5, 'timeframe' => '1-7 days', 'priority' => 2),
        'prompt' => array('min_score' => 2.5, 'timeframe' => '1-30 days', 'priority' => 3),
        'routine' => array('min_score' => 0, 'timeframe' => '30-90 days', 'priority' => 4)
    );

    public function __construct()
    {
        $this->loadSecurityFindings();
        $this->calculateRiskMatrix();
        $this->generateRemediationTimeline();
        $this->estimateResourceRequirements();
    }

    /**
     * Load security findings from the security overview
     */
    private function loadSecurityFindings()
    {
        // Sample findings based on the security overview
        $this->findings = array(
            array(
                'id' => 1,
                'title' => 'SQL Injection in Customer Authentication',
                'severity' => 5,
                'category' => 'authentication',
                'business_impact' => 'critical',
                'remediation_effort' => 'medium',
                'affected_files' => array('/classes/Customer.php', '/controllers/front/AuthController.php'),
                'compliance_impact' => array('GDPR', 'PCI DSS'),
                'financial_risk' => 'critical'
            ),
            array(
                'id' => 2,
                'title' => 'Deprecated PaymentCC Class with Card Data',
                'severity' => 5,
                'category' => 'pci_dss_compliance',
                'business_impact' => 'critical',
                'remediation_effort' => 'medium',
                'affected_files' => array('/classes/PaymentCC.php'),
                'compliance_impact' => array('PCI DSS'),
                'financial_risk' => 'critical'
            ),
            array(
                'id' => 3,
                'title' => 'Missing API Rate Limiting',
                'severity' => 4,
                'category' => 'api_security',
                'business_impact' => 'high',
                'remediation_effort' => 'high',
                'affected_files' => array('/webservice/dispatcher.php'),
                'compliance_impact' => array(),
                'financial_risk' => 'high'
            ),
            array(
                'id' => 4,
                'title' => 'Hardcoded Database Credentials',
                'severity' => 4,
                'category' => 'configuration',
                'business_impact' => 'high',
                'remediation_effort' => 'low',
                'affected_files' => array('/config/settings.inc.php'),
                'compliance_impact' => array('GDPR', 'PCI DSS'),
                'financial_risk' => 'critical'
            ),
            array(
                'id' => 5,
                'title' => 'Missing GDPR Consent Tracking',
                'severity' => 4,
                'category' => 'gdpr_compliance',
                'business_impact' => 'high',
                'remediation_effort' => 'high',
                'affected_files' => array('/classes/Customer.php', '/modules/blocknewsletter/'),
                'compliance_impact' => array('GDPR'),
                'financial_risk' => 'high'
            ),
            array(
                'id' => 6,
                'title' => 'Insecure File Upload in Modules',
                'severity' => 4,
                'category' => 'third_party',
                'business_impact' => 'high',
                'remediation_effort' => 'medium',
                'affected_files' => array('/modules/*/upload.php'),
                'compliance_impact' => array(),
                'financial_risk' => 'medium'
            ),
            array(
                'id' => 7,
                'title' => 'XSS Vulnerability in Admin Interface',
                'severity' => 3,
                'category' => 'input_validation',
                'business_impact' => 'medium',
                'remediation_effort' => 'low',
                'affected_files' => array('/admin/tabs/AdminProducts.php'),
                'compliance_impact' => array(),
                'financial_risk' => 'medium'
            ),
            array(
                'id' => 8,
                'title' => 'Weak Password Policy',
                'severity' => 3,
                'category' => 'authentication',
                'business_impact' => 'medium',
                'remediation_effort' => 'medium',
                'affected_files' => array('/classes/Customer.php', '/classes/Employee.php'),
                'compliance_impact' => array('PCI DSS'),
                'financial_risk' => 'medium'
            ),
            array(
                'id' => 9,
                'title' => 'Outdated jQuery Library',
                'severity' => 3,
                'category' => 'third_party',
                'business_impact' => 'medium',
                'remediation_effort' => 'medium',
                'affected_files' => array('/js/jquery/jquery-1.11.0.min.js'),
                'compliance_impact' => array(),
                'financial_risk' => 'low'
            ),
            array(
                'id' => 10,
                'title' => 'Missing Security Headers',
                'severity' => 2,
                'category' => 'configuration',
                'business_impact' => 'low',
                'remediation_effort' => 'low',
                'affected_files' => array('/.htaccess', '/config/config.inc.php'),
                'compliance_impact' => array(),
                'financial_risk' => 'low'
            )
        );
    }

    /**
     * Calculate comprehensive risk matrix
     */
    private function calculateRiskMatrix()
    {
        foreach ($this->findings as $finding) {
            $riskScore = $this->calculateRiskScore($finding);
            $businessImpactScore = self::BUSINESS_IMPACT_SCORES[$finding['business_impact']];
            $effortScore = self::EFFORT_SCORES[$finding['remediation_effort']];
            
            $this->riskMatrix[] = array(
                'finding' => $finding,
                'risk_score' => $riskScore,
                'business_impact_score' => $businessImpactScore,
                'effort_score' => $effortScore,
                'priority_category' => $this->getPriorityCategory($riskScore),
                'roi_score' => $this->calculateROI($riskScore, $effortScore),
                'compliance_urgency' => $this->assessComplianceUrgency($finding),
                'financial_impact_level' => $finding['financial_risk']
            );
        }
        
        // Sort by risk score (highest first)
        usort($this->riskMatrix, function($a, $b) {
            if ($a['risk_score'] == $b['risk_score']) {
                // If risk scores are equal, prioritize by effort (lower effort first)
                return $a['effort_score'] - $b['effort_score'];
            }
            return $b['risk_score'] <=> $a['risk_score'];
        });
    }

    /**
     * Calculate risk score based on severity and business impact
     */
    private function calculateRiskScore($finding)
    {
        $severityScore = $finding['severity'];
        $businessImpactScore = self::BUSINESS_IMPACT_SCORES[$finding['business_impact']];
        
        return ($severityScore * self::SEVERITY_WEIGHT) + 
               ($businessImpactScore * self::BUSINESS_IMPACT_WEIGHT);
    }

    /**
     * Get priority category based on risk score
     */
    private function getPriorityCategory($riskScore)
    {
        foreach (self::TIMELINE_CATEGORIES as $category => $config) {
            if ($riskScore >= $config['min_score']) {
                return $category;
            }
        }
        return 'routine';
    }

    /**
     * Calculate Return on Investment (ROI) for remediation
     */
    private function calculateROI($riskScore, $effortScore)
    {
        // Higher risk score and lower effort = higher ROI
        return $riskScore / $effortScore;
    }

    /**
     * Assess compliance urgency
     */
    private function assessComplianceUrgency($finding)
    {
        $complianceImpact = $finding['compliance_impact'];
        
        if (in_array('PCI DSS', $complianceImpact)) {
            return 'critical';
        } elseif (in_array('GDPR', $complianceImpact)) {
            return 'high';
        } elseif (!empty($complianceImpact)) {
            return 'medium';
        }
        
        return 'low';
    }

    /**
     * Generate remediation timeline
     */
    private function generateRemediationTimeline()
    {
        $timeline = array(
            'immediate' => array(),
            'urgent' => array(),
            'prompt' => array(),
            'routine' => array()
        );
        
        foreach ($this->riskMatrix as $item) {
            $category = $item['priority_category'];
            $timeline[$category][] = array(
                'finding' => $item['finding'],
                'risk_score' => $item['risk_score'],
                'effort_score' => $item['effort_score'],
                'roi_score' => $item['roi_score'],
                'compliance_urgency' => $item['compliance_urgency'],
                'estimated_hours' => $this->estimateRemediationHours($item['finding']),
                'dependencies' => $this->identifyDependencies($item['finding']),
                'resources_needed' => $this->identifyResourcesNeeded($item['finding'])
            );
        }
        
        $this->remediationTimeline = $timeline;
    }

    /**
     * Estimate remediation hours based on effort and complexity
     */
    private function estimateRemediationHours($finding)
    {
        $baseHours = array(
            'low' => 8,      // 1 day
            'medium' => 24,  // 3 days
            'high' => 40     // 5 days
        );
        
        $effort = $finding['remediation_effort'];
        $hours = $baseHours[$effort];
        
        // Adjust based on category complexity
        $categoryMultipliers = array(
            'authentication' => 1.2,
            'pci_dss_compliance' => 1.5,
            'gdpr_compliance' => 1.3,
            'api_security' => 1.4,
            'configuration' => 0.8,
            'input_validation' => 1.0,
            'third_party' => 1.1
        );
        
        $multiplier = isset($categoryMultipliers[$finding['category']]) 
            ? $categoryMultipliers[$finding['category']] 
            : 1.0;
            
        return round($hours * $multiplier);
    }

    /**
     * Identify dependencies between findings
     */
    private function identifyDependencies($finding)
    {
        $dependencies = array();
        
        // Define dependency relationships
        $dependencyMap = array(
            'SQL Injection in Customer Authentication' => array('Weak Password Policy'),
            'Missing GDPR Consent Tracking' => array('XSS Vulnerability in Admin Interface'),
            'Insecure File Upload in Modules' => array('Missing Security Headers'),
        );
        
        if (isset($dependencyMap[$finding['title']])) {
            $dependencies = $dependencyMap[$finding['title']];
        }
        
        return $dependencies;
    }

    /**
     * Identify resources needed for remediation
     */
    private function identifyResourcesNeeded($finding)
    {
        $resources = array('developer');
        
        // Add specialized resources based on category
        switch ($finding['category']) {
            case 'pci_dss_compliance':
                $resources[] = 'security_specialist';
                $resources[] = 'compliance_officer';
                break;
            case 'gdpr_compliance':
                $resources[] = 'privacy_officer';
                $resources[] = 'legal_counsel';
                break;
            case 'api_security':
                $resources[] = 'api_specialist';
                $resources[] = 'security_specialist';
                break;
            case 'configuration':
                $resources[] = 'system_administrator';
                break;
            case 'authentication':
                $resources[] = 'security_specialist';
                break;
        }
        
        return array_unique($resources);
    }

    /**
     * Estimate resource requirements
     */
    private function estimateResourceRequirements()
    {
        $totalHours = 0;
        $resourceBreakdown = array();
        $skillsNeeded = array();
        
        foreach ($this->remediationTimeline as $category => $items) {
            foreach ($items as $item) {
                $hours = $item['estimated_hours'];
                $totalHours += $hours;
                
                foreach ($item['resources_needed'] as $resource) {
                    if (!isset($resourceBreakdown[$resource])) {
                        $resourceBreakdown[$resource] = 0;
                    }
                    $resourceBreakdown[$resource] += $hours;
                    $skillsNeeded[$resource] = true;
                }
            }
        }
        
        $this->resourceEstimates = array(
            'total_hours' => $totalHours,
            'total_days' => round($totalHours / 8, 1),
            'resource_breakdown' => $resourceBreakdown,
            'skills_needed' => array_keys($skillsNeeded),
            'estimated_cost' => $this->calculateEstimatedCost($resourceBreakdown),
            'team_composition' => $this->recommendTeamComposition($resourceBreakdown)
        );
    }

    /**
     * Calculate estimated cost based on resource hours
     */
    private function calculateEstimatedCost($resourceBreakdown)
    {
        $hourlyRates = array(
            'developer' => 75,
            'security_specialist' => 125,
            'system_administrator' => 65,
            'compliance_officer' => 100,
            'privacy_officer' => 110,
            'legal_counsel' => 200,
            'api_specialist' => 90
        );
        
        $totalCost = 0;
        foreach ($resourceBreakdown as $resource => $hours) {
            $rate = isset($hourlyRates[$resource]) ? $hourlyRates[$resource] : 75;
            $totalCost += $hours * $rate;
        }
        
        return $totalCost;
    }

    /**
     * Recommend team composition
     */
    private function recommendTeamComposition($resourceBreakdown)
    {
        $team = array();
        
        foreach ($resourceBreakdown as $resource => $hours) {
            $fte = round($hours / 160, 2); // Assuming 160 hours per month
            $team[] = array(
                'role' => $resource,
                'hours' => $hours,
                'fte' => $fte,
                'priority' => $this->getResourcePriority($resource)
            );
        }
        
        // Sort by priority
        usort($team, function($a, $b) {
            return $a['priority'] - $b['priority'];
        });
        
        return $team;
    }

    /**
     * Get resource priority (lower number = higher priority)
     */
    private function getResourcePriority($resource)
    {
        $priorities = array(
            'security_specialist' => 1,
            'developer' => 2,
            'compliance_officer' => 3,
            'system_administrator' => 4,
            'privacy_officer' => 5,
            'api_specialist' => 6,
            'legal_counsel' => 7
        );
        
        return isset($priorities[$resource]) ? $priorities[$resource] : 8;
    }

    /**
     * Generate comprehensive risk matrix report
     */
    public function generateRiskMatrixReport()
    {
        $report = "# Security Risk Matrix and Prioritization Report\n\n";
        $report .= "**Generated**: " . date('Y-m-d H:i:s') . "\n";
        $report .= "**Total Findings**: " . count($this->findings) . "\n\n";
        
        // Executive Summary
        $report .= "## Executive Summary\n\n";
        $report .= $this->generateExecutiveSummary();
        
        // Risk Matrix
        $report .= "\n## Risk Matrix\n\n";
        $report .= $this->generateRiskMatrixTable();
        
        // Remediation Timeline
        $report .= "\n## Remediation Timeline\n\n";
        $report .= $this->generateTimelineReport();
        
        // Resource Requirements
        $report .= "\n## Resource Requirements\n\n";
        $report .= $this->generateResourceReport();
        
        // Implementation Roadmap
        $report .= "\n## Implementation Roadmap\n\n";
        $report .= $this->generateImplementationRoadmap();
        
        return $report;
    }

    /**
     * Generate executive summary
     */
    private function generateExecutiveSummary()
    {
        $summary = "";
        $criticalCount = 0;
        $highCount = 0;
        $totalHours = $this->resourceEstimates['total_hours'];
        $totalCost = $this->resourceEstimates['estimated_cost'];
        
        foreach ($this->remediationTimeline as $category => $items) {
            if ($category === 'immediate') $criticalCount = count($items);
            if ($category === 'urgent') $highCount = count($items);
        }
        
        $summary .= "### Key Metrics\n\n";
        $summary .= "- **Critical Issues**: {$criticalCount} requiring immediate attention (0-24 hours)\n";
        $summary .= "- **High Priority Issues**: {$highCount} requiring urgent remediation (1-7 days)\n";
        $summary .= "- **Total Remediation Effort**: {$totalHours} hours ({$this->resourceEstimates['total_days']} days)\n";
        $summary .= "- **Estimated Cost**: $" . number_format($totalCost) . "\n";
        $summary .= "- **Team Size Needed**: " . count($this->resourceEstimates['skills_needed']) . " specialized roles\n\n";
        
        $summary .= "### Risk Distribution\n\n";
        foreach ($this->remediationTimeline as $category => $items) {
            $count = count($items);
            $timeframe = self::TIMELINE_CATEGORIES[$category]['timeframe'];
            $summary .= "- **" . ucfirst($category) . "** ({$timeframe}): {$count} issues\n";
        }
        
        return $summary;
    }

    /**
     * Generate risk matrix table
     */
    private function generateRiskMatrixTable()
    {
        $table = "| Priority | Finding | Risk Score | Business Impact | Effort | ROI | Compliance |\n";
        $table .= "|----------|---------|------------|-----------------|--------|-----|------------|\n";
        
        $priorityIcons = array(
            'immediate' => '🚨',
            'urgent' => '⚠️',
            'prompt' => '📋',
            'routine' => '📅'
        );
        
        foreach ($this->riskMatrix as $item) {
            $finding = $item['finding'];
            $icon = $priorityIcons[$item['priority_category']];
            $riskScore = number_format($item['risk_score'], 2);
            $roiScore = number_format($item['roi_score'], 2);
            $compliance = implode(', ', $finding['compliance_impact']);
            
            $table .= "| {$icon} " . ucfirst($item['priority_category']) . " | ";
            $table .= $finding['title'] . " | ";
            $table .= $riskScore . " | ";
            $table .= ucfirst($finding['business_impact']) . " | ";
            $table .= ucfirst($finding['remediation_effort']) . " | ";
            $table .= $roiScore . " | ";
            $table .= $compliance . " |\n";
        }
        
        return $table;
    }

    /**
     * Generate timeline report
     */
    private function generateTimelineReport()
    {
        $report = "";
        
        foreach ($this->remediationTimeline as $category => $items) {
            if (empty($items)) continue;
            
            $icon = array(
                'immediate' => '🚨',
                'urgent' => '⚠️',
                'prompt' => '📋',
                'routine' => '📅'
            )[$category];
            
            $timeframe = self::TIMELINE_CATEGORIES[$category]['timeframe'];
            $report .= "### {$icon} " . ucfirst($category) . " Actions ({$timeframe})\n\n";
            
            foreach ($items as $item) {
                $finding = $item['finding'];
                $report .= "#### {$finding['title']}\n\n";
                $report .= "- **Risk Score**: " . number_format($item['risk_score'], 2) . "\n";
                $report .= "- **Estimated Hours**: {$item['estimated_hours']}\n";
                $report .= "- **Resources Needed**: " . implode(', ', $item['resources_needed']) . "\n";
                $report .= "- **Compliance Impact**: " . implode(', ', $finding['compliance_impact']) . "\n";
                
                if (!empty($item['dependencies'])) {
                    $report .= "- **Dependencies**: " . implode(', ', $item['dependencies']) . "\n";
                }
                
                $report .= "- **Affected Files**: " . implode(', ', $finding['affected_files']) . "\n\n";
            }
        }
        
        return $report;
    }

    /**
     * Generate resource report
     */
    private function generateResourceReport()
    {
        $report = "";
        $resources = $this->resourceEstimates;
        
        $report .= "### Resource Summary\n\n";
        $report .= "- **Total Effort**: {$resources['total_hours']} hours ({$resources['total_days']} days)\n";
        $report .= "- **Estimated Cost**: $" . number_format($resources['estimated_cost']) . "\n";
        $report .= "- **Skills Required**: " . implode(', ', $resources['skills_needed']) . "\n\n";
        
        $report .= "### Resource Breakdown\n\n";
        $report .= "| Role | Hours | Days | Estimated Cost |\n";
        $report .= "|------|-------|------|----------------|\n";
        
        foreach ($resources['resource_breakdown'] as $role => $hours) {
            $days = round($hours / 8, 1);
            $cost = $this->calculateRoleCost($role, $hours);
            $report .= "| " . ucwords(str_replace('_', ' ', $role)) . " | {$hours} | {$days} | $" . number_format($cost) . " |\n";
        }
        
        $report .= "\n### Recommended Team Composition\n\n";
        foreach ($resources['team_composition'] as $member) {
            $role = ucwords(str_replace('_', ' ', $member['role']));
            $report .= "- **{$role}**: {$member['hours']} hours ({$member['fte']} FTE)\n";
        }
        
        return $report;
    }

    /**
     * Calculate role-specific cost
     */
    private function calculateRoleCost($role, $hours)
    {
        $hourlyRates = array(
            'developer' => 75,
            'security_specialist' => 125,
            'system_administrator' => 65,
            'compliance_officer' => 100,
            'privacy_officer' => 110,
            'legal_counsel' => 200,
            'api_specialist' => 90
        );
        
        $rate = isset($hourlyRates[$role]) ? $hourlyRates[$role] : 75;
        return $hours * $rate;
    }

    /**
     * Generate implementation roadmap
     */
    private function generateImplementationRoadmap()
    {
        $roadmap = "";
        
        $roadmap .= "### Phase 1: Critical Security Issues (Week 1)\n\n";
        $roadmap .= "**Objective**: Address all critical vulnerabilities and immediate security threats\n\n";
        $roadmap .= "**Tasks**:\n";
        foreach ($this->remediationTimeline['immediate'] as $item) {
            $roadmap .= "- [ ] Fix: {$item['finding']['title']}\n";
        }
        $roadmap .= "\n**Success Criteria**: All critical vulnerabilities resolved, no immediate security threats\n\n";
        
        $roadmap .= "### Phase 2: High-Priority Security Fixes (Weeks 2-4)\n\n";
        $roadmap .= "**Objective**: Resolve high-priority security issues and strengthen security controls\n\n";
        $roadmap .= "**Tasks**:\n";
        foreach ($this->remediationTimeline['urgent'] as $item) {
            $roadmap .= "- [ ] Fix: {$item['finding']['title']}\n";
        }
        $roadmap .= "\n**Success Criteria**: High-priority vulnerabilities resolved, improved security posture\n\n";
        
        $roadmap .= "### Phase 3: Security Hardening (Months 2-3)\n\n";
        $roadmap .= "**Objective**: Implement comprehensive security improvements and compliance measures\n\n";
        $roadmap .= "**Tasks**:\n";
        foreach ($this->remediationTimeline['prompt'] as $item) {
            $roadmap .= "- [ ] Fix: {$item['finding']['title']}\n";
        }
        $roadmap .= "- [ ] Implement security monitoring and logging\n";
        $roadmap .= "- [ ] Enhance compliance controls (GDPR, PCI DSS)\n";
        $roadmap .= "- [ ] Conduct security training for development team\n";
        $roadmap .= "- [ ] Establish security testing procedures\n\n";
        
        $roadmap .= "### Phase 4: Continuous Security Improvement (Ongoing)\n\n";
        $roadmap .= "**Objective**: Maintain security posture and implement continuous improvement\n\n";
        $roadmap .= "**Tasks**:\n";
        foreach ($this->remediationTimeline['routine'] as $item) {
            $roadmap .= "- [ ] Fix: {$item['finding']['title']}\n";
        }
        $roadmap .= "- [ ] Regular security assessments\n";
        $roadmap .= "- [ ] Security monitoring and incident response\n";
        $roadmap .= "- [ ] Keep security tools and processes updated\n";
        $roadmap .= "- [ ] Annual compliance audits\n\n";
        
        return $roadmap;
    }

    /**
     * Get risk matrix data
     */
    public function getRiskMatrix()
    {
        return $this->riskMatrix;
    }

    /**
     * Get remediation timeline
     */
    public function getRemediationTimeline()
    {
        return $this->remediationTimeline;
    }

    /**
     * Get resource estimates
     */
    public function getResourceEstimates()
    {
        return $this->resourceEstimates;
    }
}

// CLI execution
if (php_sapi_name() === 'cli') {
    echo "Generating Security Risk Matrix and Prioritization Report...\n";
    
    $riskMatrix = new SecurityRiskMatrix();
    $report = $riskMatrix->generateRiskMatrixReport();
    
    $outputFile = dirname(__FILE__) . '/../SECURITY_RISK_MATRIX.md';
    file_put_contents($outputFile, $report);
    
    echo "Risk matrix report generated: {$outputFile}\n";
    echo "Total findings analyzed: " . count($riskMatrix->getRiskMatrix()) . "\n";
    echo "Resource estimates: " . $riskMatrix->getResourceEstimates()['total_hours'] . " hours\n";
}