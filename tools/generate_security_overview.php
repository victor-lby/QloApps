<?php
/**
 * Security Overview Report Generator
 * 
 * Generates comprehensive SECURITY_OVERVIEW.md document with all findings,
 * severity ratings, remediation priorities, and compliance assessment results
 */

require_once(dirname(__FILE__) . '/compile_security_findings.php');

class SecurityOverviewGenerator
{
    private $compiler;
    private $audit_info;
    private $output_file;

    public function __construct($audit_id = null, $output_file = null)
    {
        $this->compiler = new SecurityFindingsCompiler($audit_id);
        $this->output_file = $output_file ?: dirname(__FILE__) . '/../SECURITY_OVERVIEW.md';
        $this->loadAuditInfo();
    }

    /**
     * Load audit information
     */
    private function loadAuditInfo()
    {
        $audit_id = $this->compiler->audit_id;
        if ($audit_id) {
            $sql = 'SELECT * FROM ' . _DB_PREFIX_ . 'security_audit WHERE id_audit = ' . (int)$audit_id;
            $this->audit_info = Db::getInstance()->getRow($sql);
        }
    }

    /**
     * Generate complete security overview document
     */
    public function generateSecurityOverview()
    {
        // Compile findings
        $findings = $this->compiler->compileFindings();
        $categories = $this->compiler->getFindingsByCategory();
        $severity_dist = $this->compiler->getSeverityDistribution();
        $business_impact = $this->compiler->getBusinessImpactAnalysis();
        $stats = $this->compiler->generateSummaryStats();

        // Generate markdown content
        $content = $this->generateHeader();
        $content .= $this->generateExecutiveSummary($stats, $business_impact);
        $content .= $this->generateAuditInformation();
        $content .= $this->generateSeverityOverview($severity_dist, $stats);
        $content .= $this->generateBusinessImpactAnalysis($business_impact);
        $content .= $this->generateFindingsByCategory($categories);
        $content .= $this->generateComplianceAssessment($categories);
        $content .= $this->generateRemediationPriorities($findings);
        $content .= $this->generateImplementationRoadmap($findings);
        $content .= $this->generateAppendices($categories);

        // Write to file
        file_put_contents($this->output_file, $content);

        return $this->output_file;
    }

    /**
     * Generate document header
     */
    private function generateHeader()
    {
        $date = date('Y-m-d H:i:s');
        
        return "# QloApps Security and Compliance Audit - Comprehensive Overview

## Document Information

- **Report Date**: {$date}
- **Audit Scope**: Complete QloApps Security Assessment
- **Assessment Type**: Comprehensive Security and Compliance Audit
- **Document Version**: 1.0

---

";
    }

    /**
     * Generate executive summary
     */
    private function generateExecutiveSummary($stats, $business_impact)
    {
        $total = $stats['total_findings'];
        $critical = $stats['critical_findings'];
        $critical_pct = $stats['critical_percentage'];
        $most_affected = $stats['most_affected_category']['name'];
        
        $risk_level = $this->calculateOverallRiskLevel($stats);
        $compliance_status = $this->assessOverallCompliance($business_impact);

        return "## Executive Summary

### Overall Security Posture

The comprehensive security audit of QloApps has identified **{$total} security findings** across multiple categories, with **{$critical} critical and high-severity issues** ({$critical_pct}%) requiring immediate attention.

**Overall Risk Level**: {$risk_level}
**Compliance Status**: {$compliance_status}

### Key Findings

- **Total Security Issues**: {$total} findings identified
- **Critical/High Priority**: {$critical} issues requiring immediate remediation
- **Most Affected Area**: {$most_affected}
- **Compliance Gaps**: Multiple regulatory compliance issues identified

### Immediate Actions Required

1. **Address Critical Vulnerabilities**: {$this->severity_dist[5]['count']} critical issues need immediate attention
2. **Fix High-Priority Issues**: {$this->severity_dist[4]['count']} high-severity vulnerabilities require prompt remediation
3. **Implement Security Controls**: Missing security controls across multiple areas
4. **Enhance Compliance**: Significant gaps in GDPR and PCI DSS compliance

### Business Impact

" . $this->summarizeBusinessImpact($business_impact) . "

---

";
    }

    /**
     * Calculate overall risk level
     */
    private function calculateOverallRiskLevel($stats)
    {
        $critical_pct = $stats['critical_percentage'];
        
        if ($critical_pct >= 20) {
            return "**CRITICAL** - Immediate action required";
        } elseif ($critical_pct >= 10) {
            return "**HIGH** - Urgent remediation needed";
        } elseif ($critical_pct >= 5) {
            return "**MEDIUM** - Prompt attention required";
        } else {
            return "**LOW** - Manageable security posture";
        }
    }

    /**
     * Assess overall compliance status
     */
    private function assessOverallCompliance($business_impact)
    {
        $compliance_risks = count($business_impact['compliance_risks']);
        
        if ($compliance_risks >= 10) {
            return "**NON-COMPLIANT** - Major regulatory gaps";
        } elseif ($compliance_risks >= 5) {
            return "**PARTIALLY COMPLIANT** - Significant improvements needed";
        } elseif ($compliance_risks >= 2) {
            return "**MOSTLY COMPLIANT** - Minor gaps to address";
        } else {
            return "**COMPLIANT** - Good regulatory alignment";
        }
    }

    /**
     * Summarize business impact
     */
    private function summarizeBusinessImpact($business_impact)
    {
        $critical_risks = count($business_impact['critical_business_risks']);
        $financial_risks = count($business_impact['financial_impact']);
        $compliance_risks = count($business_impact['compliance_risks']);
        
        return "- **Critical Business Risks**: {$critical_risks} issues pose immediate threats to business operations
- **Financial Impact**: {$financial_risks} issues could result in significant financial losses
- **Compliance Risks**: {$compliance_risks} regulatory compliance gaps identified
- **Reputation Impact**: Multiple issues could affect customer trust and brand reputation";
    }

    /**
     * Generate audit information section
     */
    private function generateAuditInformation()
    {
        $audit_date = $this->audit_info ? $this->audit_info['date_created'] : 'Unknown';
        $audit_type = $this->audit_info ? $this->audit_info['audit_type'] : 'Comprehensive Security Audit';
        
        return "## Audit Information

### Scope and Methodology

- **Audit Date**: {$audit_date}
- **Audit Type**: {$audit_type}
- **Assessment Framework**: Custom security assessment based on OWASP, NIST, and industry best practices
- **Compliance Standards**: GDPR, PCI DSS, ISO 27001 principles

### Areas Assessed

1. **Authentication and Authorization** - User authentication, session management, access controls
2. **Input Validation and Injection** - SQL injection, XSS, and other injection vulnerabilities
3. **Data Protection and Encryption** - Sensitive data handling, encryption implementation
4. **Configuration and Infrastructure** - System configuration, file permissions, error handling
5. **API Security** - Web service authentication, authorization, input validation
6. **Third-Party and Module Security** - Module security, dependency vulnerabilities
7. **GDPR Compliance** - Data protection regulation compliance
8. **PCI DSS Compliance** - Payment card industry security standards

### Assessment Tools and Techniques

- **Automated Security Scanning** - Custom vulnerability scanners
- **Static Code Analysis** - Source code security review
- **Configuration Analysis** - System and application configuration review
- **Compliance Assessment** - Regulatory requirement verification
- **Manual Security Testing** - Expert security analysis

---

";
    }

    /**
     * Generate severity overview
     */
    private function generateSeverityOverview($severity_dist, $stats)
    {
        $content = "## Security Findings Overview

### Severity Distribution

| Severity Level | Count | Percentage | Description |
|----------------|-------|------------|-------------|
";

        $total = $stats['total_findings'];
        foreach ($severity_dist as $level => $data) {
            if ($data['count'] > 0) {
                $percentage = $total > 0 ? round(($data['count'] / $total) * 100, 1) : 0;
                $description = $this->getSeverityDescription($level);
                $content .= "| {$data['label']} (Level {$level}) | {$data['count']} | {$percentage}% | {$description} |\n";
            }
        }

        $content .= "\n### Risk Assessment Matrix\n\n";
        $content .= $this->generateRiskMatrix($severity_dist);
        
        return $content . "\n---\n\n";
    }

    /**
     * Get severity description
     */
    private function getSeverityDescription($level)
    {
        switch ($level) {
            case 5:
                return "Critical vulnerabilities requiring immediate action";
            case 4:
                return "High-risk issues needing urgent remediation";
            case 3:
                return "Medium-risk issues requiring prompt attention";
            case 2:
                return "Low-risk issues for routine maintenance";
            case 1:
                return "Informational findings and best practices";
            case 0:
                return "No security impact";
            default:
                return "Unknown severity level";
        }
    }

    /**
     * Generate risk assessment matrix
     */
    private function generateRiskMatrix($severity_dist)
    {
        $critical = $severity_dist[5]['count'];
        $high = $severity_dist[4]['count'];
        $medium = $severity_dist[3]['count'];
        $low = $severity_dist[2]['count'];

        return "```
Risk Level    | Count | Action Required
--------------|-------|------------------
CRITICAL (5)  | {$critical}     | Immediate (0-24 hours)
HIGH (4)      | {$high}     | Urgent (1-7 days)
MEDIUM (3)    | {$medium}     | Prompt (1-30 days)
LOW (2)       | {$low}     | Routine (30-90 days)
```";
    }

    /**
     * Generate business impact analysis
     */
    private function generateBusinessImpactAnalysis($business_impact)
    {
        $content = "## Business Impact Analysis\n\n";

        // Critical business risks
        if (!empty($business_impact['critical_business_risks'])) {
            $content .= "### Critical Business Risks\n\n";
            foreach ($business_impact['critical_business_risks'] as $risk) {
                $content .= "- **{$risk['title']}** (Severity {$risk['severity']})\n";
                $content .= "  - Impact: {$risk['impact']}\n\n";
            }
        }

        // Financial impact
        if (!empty($business_impact['financial_impact'])) {
            $content .= "### Financial Impact Assessment\n\n";
            foreach ($business_impact['financial_impact'] as $impact) {
                $content .= "- **{$impact['finding']}**\n";
                $content .= "  - Financial Risk: {$impact['impact']}\n\n";
            }
        }

        // Operational impact
        if (!empty($business_impact['operational_impact'])) {
            $content .= "### Operational Impact\n\n";
            foreach ($business_impact['operational_impact'] as $impact) {
                $content .= "- **{$impact['finding']}**\n";
                $content .= "  - Operational Risk: {$impact['impact']}\n\n";
            }
        }

        // Compliance risks
        if (!empty($business_impact['compliance_risks'])) {
            $content .= "### Regulatory Compliance Risks\n\n";
            foreach ($business_impact['compliance_risks'] as $risk) {
                $content .= "- **{$risk['finding']}**\n";
                $content .= "  - Regulation: {$risk['regulation']}\n";
                $content .= "  - Risk Level: {$risk['risk_level']}\n\n";
            }
        }

        // Reputation risks
        if (!empty($business_impact['reputation_risks'])) {
            $content .= "### Reputation and Trust Impact\n\n";
            foreach ($business_impact['reputation_risks'] as $risk) {
                $content .= "- **{$risk['finding']}**\n";
                $content .= "  - Reputation Impact: {$risk['impact']}\n\n";
            }
        }

        return $content . "---\n\n";
    }

    /**
     * Generate findings by category
     */
    private function generateFindingsByCategory($categories)
    {
        $content = "## Detailed Security Findings by Category\n\n";

        foreach ($categories as $category_key => $category) {
            if (empty($category['findings'])) {
                continue;
            }

            $count = count($category['findings']);
            $content .= "### {$category['name']} ({$count} findings)\n\n";
            $content .= "{$category['description']}\n\n";

            // Sort findings by severity (highest first)
            usort($category['findings'], function($a, $b) {
                return $b->severity - $a->severity;
            });

            foreach ($category['findings'] as $finding) {
                $severity_label = $this->getSeverityLabel($finding->severity);
                $content .= "#### {$finding->title}\n\n";
                $content .= "- **Severity**: {$severity_label} (Level {$finding->severity})\n";
                $content .= "- **Category**: {$finding->category}\n";
                
                if ($finding->affected_files) {
                    $content .= "- **Affected Files**: {$finding->affected_files}\n";
                }
                
                if ($finding->business_impact) {
                    $content .= "- **Business Impact**: {$finding->business_impact}\n";
                }
                
                if ($finding->remediation_effort) {
                    $content .= "- **Remediation Effort**: {$finding->remediation_effort}\n";
                }

                $content .= "\n**Description:**\n{$finding->description}\n\n";

                if ($finding->fix_specification) {
                    $content .= "**Fix Specification:**\n{$finding->fix_specification}\n\n";
                }

                if ($finding->code_examples) {
                    $content .= "**Code Examples:**\n{$finding->code_examples}\n\n";
                }

                $content .= "---\n\n";
            }
        }

        return $content;
    }

    /**
     * Get severity label
     */
    private function getSeverityLabel($severity)
    {
        switch ($severity) {
            case 5: return "🔴 Critical";
            case 4: return "🟠 High";
            case 3: return "🟡 Medium";
            case 2: return "🔵 Low";
            case 1: return "⚪ Informational";
            default: return "❓ Unknown";
        }
    }

    /**
     * Generate compliance assessment
     */
    private function generateComplianceAssessment($categories)
    {
        $content = "## Regulatory Compliance Assessment\n\n";

        // GDPR Compliance
        if (isset($categories['gdpr_compliance']) && !empty($categories['gdpr_compliance']['findings'])) {
            $gdpr_findings = $categories['gdpr_compliance']['findings'];
            $content .= "### GDPR (General Data Protection Regulation) Compliance\n\n";
            $content .= $this->assessGDPRCompliance($gdpr_findings);
        }

        // PCI DSS Compliance
        if (isset($categories['pci_dss_compliance']) && !empty($categories['pci_dss_compliance']['findings'])) {
            $pci_findings = $categories['pci_dss_compliance']['findings'];
            $content .= "### PCI DSS (Payment Card Industry Data Security Standard) Compliance\n\n";
            $content .= $this->assessPCIDSSCompliance($pci_findings);
        }

        // General Security Compliance
        $content .= "### General Security Compliance\n\n";
        $content .= $this->assessGeneralCompliance($categories);

        return $content . "---\n\n";
    }

    /**
     * Assess GDPR compliance
     */
    private function assessGDPRCompliance($findings)
    {
        $critical_count = 0;
        $high_count = 0;
        
        foreach ($findings as $finding) {
            if ($finding->severity >= 4) {
                $critical_count++;
            } elseif ($finding->severity == 3) {
                $high_count++;
            }
        }

        $status = "NON-COMPLIANT";
        if ($critical_count == 0 && $high_count == 0) {
            $status = "COMPLIANT";
        } elseif ($critical_count == 0) {
            $status = "MOSTLY COMPLIANT";
        } elseif ($critical_count <= 2) {
            $status = "PARTIALLY COMPLIANT";
        }

        return "**Compliance Status**: {$status}\n\n" .
               "- Critical Issues: {$critical_count}\n" .
               "- High Priority Issues: {$high_count}\n" .
               "- Total GDPR Findings: " . count($findings) . "\n\n" .
               "**Key Areas of Concern:**\n" .
               $this->listKeyFindings($findings, 3) . "\n";
    }

    /**
     * Assess PCI DSS compliance
     */
    private function assessPCIDSSCompliance($findings)
    {
        $critical_count = 0;
        $high_count = 0;
        
        foreach ($findings as $finding) {
            if ($finding->severity >= 4) {
                $critical_count++;
            } elseif ($finding->severity == 3) {
                $high_count++;
            }
        }

        $status = "NON-COMPLIANT";
        if ($critical_count == 0 && $high_count == 0) {
            $status = "COMPLIANT";
        } elseif ($critical_count == 0) {
            $status = "MOSTLY COMPLIANT";
        } elseif ($critical_count <= 2) {
            $status = "PARTIALLY COMPLIANT";
        }

        return "**Compliance Status**: {$status}\n\n" .
               "- Critical Issues: {$critical_count}\n" .
               "- High Priority Issues: {$high_count}\n" .
               "- Total PCI DSS Findings: " . count($findings) . "\n\n" .
               "**Key Areas of Concern:**\n" .
               $this->listKeyFindings($findings, 3) . "\n";
    }

    /**
     * Assess general security compliance
     */
    private function assessGeneralCompliance($categories)
    {
        $total_critical = 0;
        $total_high = 0;
        $total_findings = 0;

        foreach ($categories as $category) {
            foreach ($category['findings'] as $finding) {
                $total_findings++;
                if ($finding->severity >= 4) {
                    $total_critical++;
                } elseif ($finding->severity == 3) {
                    $total_high++;
                }
            }
        }

        $compliance_score = max(0, 100 - ($total_critical * 10) - ($total_high * 5));

        return "**Overall Security Compliance Score**: {$compliance_score}%\n\n" .
               "- Total Security Findings: {$total_findings}\n" .
               "- Critical/High Issues: " . ($total_critical + $total_high) . "\n" .
               "- Compliance Level: " . $this->getComplianceLevel($compliance_score) . "\n\n";
    }

    /**
     * Get compliance level based on score
     */
    private function getComplianceLevel($score)
    {
        if ($score >= 90) return "Excellent";
        if ($score >= 80) return "Good";
        if ($score >= 70) return "Fair";
        if ($score >= 60) return "Poor";
        return "Critical";
    }

    /**
     * List key findings
     */
    private function listKeyFindings($findings, $limit = 5)
    {
        $content = "";
        $count = 0;
        
        // Sort by severity
        usort($findings, function($a, $b) {
            return $b->severity - $a->severity;
        });

        foreach ($findings as $finding) {
            if ($count >= $limit) break;
            $content .= "- {$finding->title} (Severity {$finding->severity})\n";
            $count++;
        }

        return $content;
    }

    /**
     * Generate remediation priorities
     */
    private function generateRemediationPriorities($findings)
    {
        // Sort findings by severity and business impact
        usort($findings, function($a, $b) {
            if ($a->severity != $b->severity) {
                return $b->severity - $a->severity;
            }
            // Secondary sort by business impact
            $impact_order = array('critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1);
            $a_impact = $impact_order[strtolower($a->business_impact)] ?? 0;
            $b_impact = $impact_order[strtolower($b->business_impact)] ?? 0;
            return $b_impact - $a_impact;
        });

        $content = "## Remediation Priorities and Action Plan\n\n";

        // Immediate actions (Critical - Severity 5)
        $immediate = array_filter($findings, function($f) { return $f->severity == 5; });
        if (!empty($immediate)) {
            $content .= "### 🚨 Immediate Actions Required (0-24 hours)\n\n";
            $content .= "**Critical vulnerabilities that pose immediate threats to system security:**\n\n";
            foreach ($immediate as $finding) {
                $content .= "1. **{$finding->title}**\n";
                $content .= "   - **Risk**: Critical security vulnerability\n";
                $content .= "   - **Action**: " . strip_tags($finding->fix_specification) . "\n";
                $content .= "   - **Effort**: {$finding->remediation_effort}\n\n";
            }
        }

        // Urgent actions (High - Severity 4)
        $urgent = array_filter($findings, function($f) { return $f->severity == 4; });
        if (!empty($urgent)) {
            $content .= "### ⚠️ Urgent Actions Required (1-7 days)\n\n";
            $content .= "**High-priority security issues requiring prompt attention:**\n\n";
            foreach ($urgent as $finding) {
                $content .= "1. **{$finding->title}**\n";
                $content .= "   - **Risk**: High security risk\n";
                $content .= "   - **Action**: " . strip_tags($finding->fix_specification) . "\n";
                $content .= "   - **Effort**: {$finding->remediation_effort}\n\n";
            }
        }

        // Short-term actions (Medium - Severity 3)
        $short_term = array_filter($findings, function($f) { return $f->severity == 3; });
        if (!empty($short_term)) {
            $content .= "### 📋 Short-term Actions (1-30 days)\n\n";
            $content .= "**Medium-priority issues for planned remediation:**\n\n";
            $count = 0;
            foreach ($short_term as $finding) {
                if ($count >= 10) { // Limit to top 10 for readability
                    $remaining = count($short_term) - $count;
                    $content .= "   *... and {$remaining} additional medium-priority findings*\n\n";
                    break;
                }
                $content .= "1. **{$finding->title}**\n";
                $content .= "   - **Action**: " . strip_tags($finding->fix_specification) . "\n\n";
                $count++;
            }
        }

        // Long-term actions (Low - Severity 2)
        $long_term = array_filter($findings, function($f) { return $f->severity == 2; });
        if (!empty($long_term)) {
            $content .= "### 📅 Long-term Actions (30-90 days)\n\n";
            $content .= "**Low-priority improvements for routine maintenance:**\n\n";
            $content .= "- " . count($long_term) . " low-priority security improvements identified\n";
            $content .= "- Focus on security best practices and hardening\n";
            $content .= "- Address during regular maintenance windows\n\n";
        }

        return $content . "---\n\n";
    }

    /**
     * Generate implementation roadmap
     */
    private function generateImplementationRoadmap($findings)
    {
        $content = "## Implementation Roadmap\n\n";

        $content .= "### Phase 1: Critical Security Issues (Week 1)\n\n";
        $content .= "**Objective**: Address all critical vulnerabilities and immediate security threats\n\n";
        $content .= "**Tasks**:\n";
        
        $critical = array_filter($findings, function($f) { return $f->severity == 5; });
        foreach ($critical as $finding) {
            $content .= "- [ ] Fix: {$finding->title}\n";
        }
        
        $content .= "\n**Success Criteria**: All critical vulnerabilities resolved, no immediate security threats\n\n";

        $content .= "### Phase 2: High-Priority Security Fixes (Weeks 2-4)\n\n";
        $content .= "**Objective**: Resolve high-priority security issues and strengthen security controls\n\n";
        $content .= "**Tasks**:\n";
        
        $high = array_filter($findings, function($f) { return $f->severity == 4; });
        foreach ($high as $finding) {
            $content .= "- [ ] Fix: {$finding->title}\n";
        }
        
        $content .= "\n**Success Criteria**: High-priority vulnerabilities resolved, improved security posture\n\n";

        $content .= "### Phase 3: Security Hardening (Months 2-3)\n\n";
        $content .= "**Objective**: Implement comprehensive security improvements and compliance measures\n\n";
        $content .= "**Tasks**:\n";
        $content .= "- [ ] Address medium-priority security findings\n";
        $content .= "- [ ] Implement security monitoring and logging\n";
        $content .= "- [ ] Enhance compliance controls (GDPR, PCI DSS)\n";
        $content .= "- [ ] Conduct security training for development team\n";
        $content .= "- [ ] Establish security testing procedures\n\n";

        $content .= "### Phase 4: Continuous Security Improvement (Ongoing)\n\n";
        $content .= "**Objective**: Maintain security posture and implement continuous improvement\n\n";
        $content .= "**Tasks**:\n";
        $content .= "- [ ] Regular security assessments\n";
        $content .= "- [ ] Security monitoring and incident response\n";
        $content .= "- [ ] Keep security tools and processes updated\n";
        $content .= "- [ ] Address low-priority findings during maintenance\n";
        $content .= "- [ ] Annual compliance audits\n\n";

        $content .= "### Resource Requirements\n\n";
        $content .= "**Personnel**:\n";
        $content .= "- Security specialist or consultant\n";
        $content .= "- Development team members\n";
        $content .= "- System administrator\n";
        $content .= "- Compliance officer (for regulatory requirements)\n\n";

        $content .= "**Timeline**:\n";
        $content .= "- **Phase 1**: 1 week (immediate)\n";
        $content .= "- **Phase 2**: 3 weeks (urgent)\n";
        $content .= "- **Phase 3**: 2 months (planned)\n";
        $content .= "- **Phase 4**: Ongoing (continuous)\n\n";

        return $content . "---\n\n";
    }

    /**
     * Generate appendices
     */
    private function generateAppendices($categories)
    {
        $content = "## Appendices\n\n";

        $content .= "### Appendix A: Security Testing Methodology\n\n";
        $content .= $this->generateMethodologyAppendix();

        $content .= "### Appendix B: Compliance Frameworks\n\n";
        $content .= $this->generateComplianceFrameworksAppendix();

        $content .= "### Appendix C: Security Tools and Resources\n\n";
        $content .= $this->generateToolsAppendix();

        $content .= "### Appendix D: Glossary\n\n";
        $content .= $this->generateGlossaryAppendix();

        return $content;
    }

    /**
     * Generate methodology appendix
     */
    private function generateMethodologyAppendix()
    {
        return "The security assessment was conducted using a comprehensive methodology that includes:

1. **Automated Security Scanning**
   - Custom vulnerability scanners for QloApps-specific issues
   - Static code analysis for common security vulnerabilities
   - Configuration security assessment tools

2. **Manual Security Testing**
   - Expert security analysis and code review
   - Business logic security testing
   - Compliance requirement verification

3. **Risk Assessment**
   - CVSS-based severity scoring
   - Business impact analysis
   - Remediation effort estimation

4. **Compliance Verification**
   - GDPR compliance assessment
   - PCI DSS requirement verification
   - Industry best practice alignment

";
    }

    /**
     * Generate compliance frameworks appendix
     */
    private function generateComplianceFrameworksAppendix()
    {
        return "**GDPR (General Data Protection Regulation)**
- Applies to all organizations processing EU personal data
- Key requirements: consent, data subject rights, privacy by design
- Penalties: Up to 4% of annual revenue or €20 million

**PCI DSS (Payment Card Industry Data Security Standard)**
- Applies to organizations handling payment card data
- 12 core requirements across 6 categories
- Penalties: Fines, increased transaction fees, loss of processing rights

**OWASP (Open Web Application Security Project)**
- Industry-standard web application security framework
- OWASP Top 10 most critical security risks
- Best practices for secure development

**NIST Cybersecurity Framework**
- Comprehensive cybersecurity risk management framework
- Five core functions: Identify, Protect, Detect, Respond, Recover
- Widely adopted industry standard

";
    }

    /**
     * Generate tools appendix
     */
    private function generateToolsAppendix()
    {
        return "**Security Assessment Tools Used:**

1. **Custom QloApps Security Scanner**
   - Location: `classes/SecurityScanner.php`
   - Purpose: Automated vulnerability detection
   - Coverage: SQL injection, XSS, authentication, configuration

2. **GDPR Compliance Auditor**
   - Location: `classes/GDPRComplianceAudit.php`
   - Purpose: GDPR compliance assessment
   - Coverage: Data processing, consent, privacy rights

3. **Module Security Assessment Tool**
   - Location: `tools/module_security_assessment.php`
   - Purpose: Third-party module security analysis
   - Coverage: Module authentication, input validation, file security

4. **Dependency Security Scanner**
   - Location: `tools/dependency_security_scanner.php`
   - Purpose: Third-party dependency vulnerability scanning
   - Coverage: Composer packages, JavaScript libraries

**Recommended Additional Tools:**
- OWASP ZAP for dynamic security testing
- SonarQube for continuous code quality analysis
- Nessus or OpenVAS for infrastructure vulnerability scanning

";
    }

    /**
     * Generate glossary appendix
     */
    private function generateGlossaryAppendix()
    {
        return "**Security Terms:**

- **SQL Injection**: Code injection technique that exploits database vulnerabilities
- **XSS (Cross-Site Scripting)**: Injection of malicious scripts into web applications
- **CSRF (Cross-Site Request Forgery)**: Attack that forces users to execute unwanted actions
- **Authentication**: Process of verifying user identity
- **Authorization**: Process of determining user permissions
- **Encryption**: Process of encoding data to prevent unauthorized access
- **Vulnerability**: Security weakness that can be exploited by threats
- **Risk**: Potential for loss or damage when a threat exploits a vulnerability

**Compliance Terms:**

- **GDPR**: EU regulation on data protection and privacy
- **PCI DSS**: Security standard for payment card industry
- **Data Subject**: Individual whose personal data is processed
- **Data Controller**: Entity that determines purposes of data processing
- **Data Processor**: Entity that processes data on behalf of controller
- **Personal Data**: Any information relating to an identified person

**Severity Levels:**

- **Critical (5)**: Immediate threat requiring emergency response
- **High (4)**: Significant risk requiring urgent attention
- **Medium (3)**: Moderate risk requiring prompt remediation
- **Low (2)**: Minor risk for routine maintenance
- **Informational (1)**: Best practice recommendations

";
    }
}

// CLI execution
if (php_sapi_name() === 'cli') {
    echo "Security Overview Report Generator\n";
    echo "=================================\n\n";

    try {
        $generator = new SecurityOverviewGenerator();
        
        echo "Generating comprehensive security overview...\n";
        $output_file = $generator->generateSecurityOverview();
        
        echo "Security overview generated successfully!\n";
        echo "Report saved to: {$output_file}\n\n";
        
        $file_size = filesize($output_file);
        echo "Report size: " . number_format($file_size) . " bytes\n";
        echo "Report contains comprehensive security findings, compliance assessment, and remediation guidance.\n";
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}