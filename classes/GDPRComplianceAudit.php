<?php
/**
 * GDPR Compliance Audit for QloApps
 * 
 * This class provides comprehensive GDPR compliance assessment including
 * data processing compliance, consent mechanisms, and privacy protection measures.
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once(_PS_CLASS_DIR_ . 'SecurityAudit.php');
require_once(_PS_CLASS_DIR_ . 'SecurityFinding.php');

class GDPRComplianceAudit
{
    private $audit;
    private $findings = array();
    
    // GDPR compliance categories
    const GDPR_DATA_PROCESSING = 'gdpr_data_processing';
    const GDPR_CONSENT = 'gdpr_consent';
    const GDPR_DATA_RIGHTS = 'gdpr_data_rights';
    const GDPR_DATA_RETENTION = 'gdpr_data_retention';
    const GDPR_PRIVACY_DESIGN = 'gdpr_privacy_design';
    const GDPR_BREACH_NOTIFICATION = 'gdpr_breach_notification';
    
    // Data processing lawful bases
    const LAWFUL_BASIS_CONSENT = 'consent';
    const LAWFUL_BASIS_CONTRACT = 'contract';
    const LAWFUL_BASIS_LEGAL_OBLIGATION = 'legal_obligation';
    const LAWFUL_BASIS_VITAL_INTERESTS = 'vital_interests';
    const LAWFUL_BASIS_PUBLIC_TASK = 'public_task';
    const LAWFUL_BASIS_LEGITIMATE_INTERESTS = 'legitimate_interests';

    public function __construct($audit_id = null)
    {
        if ($audit_id) {
            $this->audit = new SecurityAudit($audit_id);
        } else {
            $this->audit = new SecurityAudit();
            $this->audit->audit_name = 'GDPR Compliance Assessment - ' . date('Y-m-d H:i:s');
            $this->audit->save();
        }
    }

    /**
     * Conduct comprehensive GDPR compliance assessment
     */
    public function conductGDPRAssessment()
    {
        $this->audit->status = 'running';
        $this->audit->save();

        // Review data processing compliance
        $this->reviewDataProcessingCompliance();
        
        // Assess privacy protection measures
        $this->assessPrivacyProtectionMeasures();
        
        // Update audit statistics
        $this->audit->updateStatistics();
        $this->audit->status = 'completed';
        $this->audit->save();

        return $this->generateGDPRReport();
    }

    /**
     * Review data processing compliance (Task 8.1)
     */
    public function reviewDataProcessingCompliance()
    {
        // Examine customer data collection procedures
        $this->examineCustomerDataCollection();
        
        // Check consent mechanisms
        $this->checkConsentMechanisms();
        
        // Review data subject rights implementation
        $this->reviewDataSubjectRights();
        
        // Review data retention and deletion policies
        $this->reviewDataRetentionPolicies();
    }

    /**
     * Examine customer data collection and processing procedures
     */
    private function examineCustomerDataCollection()
    {
        $findings = array();
        
        // Check Customer class for data collection practices
        $customer_file = _PS_CLASS_DIR_ . 'Customer.php';
        if (file_exists($customer_file)) {
            $customer_content = file_get_contents($customer_file);
            
            // Check for explicit consent collection
            if (!preg_match('/consent|gdpr|privacy/i', $customer_content)) {
                $findings[] = array(
                    'title' => 'Missing GDPR consent tracking in Customer class',
                    'description' => 'The Customer class does not appear to track GDPR consent or privacy preferences.',
                    'severity' => SecurityAudit::SEVERITY_HIGH,
                    'category' => self::GDPR_CONSENT,
                    'affected_files' => array($customer_file),
                    'fix_specification' => 'Add consent tracking fields and methods to Customer class for GDPR compliance.',
                    'business_impact' => 'Legal non-compliance with GDPR consent requirements'
                );
            }
            
            // Check for data minimization principles
            if (preg_match_all('/public \$([^;]+);/', $customer_content, $matches)) {
                $customer_fields = $matches[1];
                $excessive_fields = array();
                
                foreach ($customer_fields as $field) {
                    if (in_array(trim($field), array('birthday', 'website', 'company', 'siret', 'ape'))) {
                        $excessive_fields[] = trim($field);
                    }
                }
                
                if (!empty($excessive_fields)) {
                    $findings[] = array(
                        'title' => 'Potential data minimization violation',
                        'description' => 'Customer class collects potentially excessive personal data: ' . implode(', ', $excessive_fields),
                        'severity' => SecurityAudit::SEVERITY_MEDIUM,
                        'category' => self::GDPR_DATA_PROCESSING,
                        'affected_files' => array($customer_file),
                        'fix_specification' => 'Review necessity of collecting these data fields and implement opt-in mechanisms.',
                        'business_impact' => 'Potential GDPR data minimization principle violation'
                    );
                }
            }
        }
        
        // Check booking data collection
        $booking_files = array(
            'classes/HtlBookingDetail.php',
            'modules/hotelreservationsystem/classes/HtlBookingDetail.php'
        );
        
        foreach ($booking_files as $booking_file) {
            if (file_exists($booking_file)) {
                $booking_content = file_get_contents($booking_file);
                
                // Check for special category data collection
                if (preg_match('/dietary|medical|disability|religion/i', $booking_content)) {
                    $findings[] = array(
                        'title' => 'Special category personal data collection detected',
                        'description' => 'Booking system may collect special category personal data without explicit consent mechanisms.',
                        'severity' => SecurityAudit::SEVERITY_HIGH,
                        'category' => self::GDPR_DATA_PROCESSING,
                        'affected_files' => array($booking_file),
                        'fix_specification' => 'Implement explicit consent mechanisms for special category personal data collection.',
                        'business_impact' => 'High risk of GDPR violation for special category data processing'
                    );
                }
            }
        }
        
        // Check for lawful basis documentation
        $config_files = array(
            'config/config.inc.php',
            'config/settings.inc.php'
        );
        
        $lawful_basis_documented = false;
        foreach ($config_files as $config_file) {
            if (file_exists($config_file)) {
                $config_content = file_get_contents($config_file);
                if (preg_match('/lawful.?basis|gdpr.?basis/i', $config_content)) {
                    $lawful_basis_documented = true;
                    break;
                }
            }
        }
        
        if (!$lawful_basis_documented) {
            $findings[] = array(
                'title' => 'Missing lawful basis documentation',
                'description' => 'No documented lawful basis for personal data processing found in system configuration.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => self::GDPR_DATA_PROCESSING,
                'affected_files' => $config_files,
                'fix_specification' => 'Document and implement lawful basis for all personal data processing activities.',
                'business_impact' => 'Legal requirement for GDPR compliance - mandatory documentation'
            );
        }
        
        $this->saveFindings($findings);
    }

    /**
     * Check consent mechanisms and implementation
     */
    private function checkConsentMechanisms()
    {
        $findings = array();
        
        // Check for cookie consent implementation
        $theme_dirs = array('themes');
        $consent_found = false;
        
        foreach ($theme_dirs as $theme_dir) {
            if (is_dir($theme_dir)) {
                $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($theme_dir));
                foreach ($iterator as $file) {
                    if ($file->isFile() && in_array($file->getExtension(), array('tpl', 'php', 'js'))) {
                        $content = file_get_contents($file->getPathname());
                        if (preg_match('/cookie.?consent|gdpr.?consent|privacy.?consent/i', $content)) {
                            $consent_found = true;
                            break 2;
                        }
                    }
                }
            }
        }
        
        if (!$consent_found) {
            $findings[] = array(
                'title' => 'Missing cookie consent mechanism',
                'description' => 'No cookie consent implementation found in themes or templates.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => self::GDPR_CONSENT,
                'affected_files' => array('themes/'),
                'fix_specification' => 'Implement cookie consent banner and preference management system.',
                'business_impact' => 'Legal requirement for GDPR compliance - cookie consent mandatory'
            );
        }
        
        // Check for newsletter consent
        $newsletter_modules = array(
            'modules/blocknewsletter',
            'modules/newsletter'
        );
        
        $newsletter_consent = false;
        foreach ($newsletter_modules as $module_dir) {
            if (is_dir($module_dir)) {
                $files = glob($module_dir . '/*.php');
                foreach ($files as $file) {
                    $content = file_get_contents($file);
                    if (preg_match('/consent|opt.?in|gdpr/i', $content)) {
                        $newsletter_consent = true;
                        break 2;
                    }
                }
            }
        }
        
        if (!$newsletter_consent) {
            $findings[] = array(
                'title' => 'Newsletter consent mechanism missing',
                'description' => 'Newsletter subscription does not implement proper consent mechanisms.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => self::GDPR_CONSENT,
                'affected_files' => $newsletter_modules,
                'fix_specification' => 'Add explicit consent checkboxes and double opt-in for newsletter subscriptions.',
                'business_impact' => 'Risk of GDPR violation for marketing communications'
            );
        }
        
        // Check for consent withdrawal mechanisms
        $customer_account_files = array(
            'controllers/front/MyAccountController.php',
            'themes/*/templates/customer/account.tpl'
        );
        
        $consent_withdrawal = false;
        foreach ($customer_account_files as $pattern) {
            $files = glob($pattern);
            foreach ($files as $file) {
                if (file_exists($file)) {
                    $content = file_get_contents($file);
                    if (preg_match('/withdraw.?consent|revoke.?consent|privacy.?settings/i', $content)) {
                        $consent_withdrawal = true;
                        break 2;
                    }
                }
            }
        }
        
        if (!$consent_withdrawal) {
            $findings[] = array(
                'title' => 'Missing consent withdrawal mechanism',
                'description' => 'No mechanism found for users to withdraw previously given consent.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => self::GDPR_CONSENT,
                'affected_files' => array('customer account area'),
                'fix_specification' => 'Implement user interface for consent withdrawal and preference management.',
                'business_impact' => 'GDPR requires easy consent withdrawal - legal compliance issue'
            );
        }
        
        $this->saveFindings($findings);
    }

    /**
     * Review data subject rights implementation
     */
    private function reviewDataSubjectRights()
    {
        $findings = array();
        
        // Check for data export functionality (Right to portability)
        $export_found = false;
        $admin_controllers = glob('controllers/admin/Admin*Controller.php');
        
        foreach ($admin_controllers as $controller) {
            $content = file_get_contents($controller);
            if (preg_match('/export|download.*data|portability/i', $content)) {
                $export_found = true;
                break;
            }
        }
        
        if (!$export_found) {
            $findings[] = array(
                'title' => 'Missing data export functionality',
                'description' => 'No data export functionality found for data portability rights (GDPR Article 20).',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => self::GDPR_DATA_RIGHTS,
                'affected_files' => array('admin controllers'),
                'fix_specification' => 'Implement data export functionality allowing customers to download their personal data.',
                'business_impact' => 'Legal requirement - customers have right to data portability'
            );
        }
        
        // Check for data deletion functionality (Right to erasure)
        $deletion_found = false;
        foreach ($admin_controllers as $controller) {
            $content = file_get_contents($controller);
            if (preg_match('/delete.*customer|erase.*data|right.*erasure/i', $content)) {
                $deletion_found = true;
                break;
            }
        }
        
        if (!$deletion_found) {
            $findings[] = array(
                'title' => 'Missing data deletion functionality',
                'description' => 'No comprehensive data deletion functionality found for right to erasure (GDPR Article 17).',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => self::GDPR_DATA_RIGHTS,
                'affected_files' => array('admin controllers'),
                'fix_specification' => 'Implement secure data deletion functionality with audit trail.',
                'business_impact' => 'Legal requirement - customers have right to erasure'
            );
        }
        
        // Check for data rectification functionality (Right to rectification)
        $customer_edit_files = array(
            'controllers/front/IdentityController.php',
            'controllers/front/AddressController.php'
        );
        
        $rectification_found = false;
        foreach ($customer_edit_files as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/edit|update|modify/i', $content)) {
                    $rectification_found = true;
                    break;
                }
            }
        }
        
        if (!$rectification_found) {
            $findings[] = array(
                'title' => 'Limited data rectification capabilities',
                'description' => 'Customer data rectification capabilities may be limited or not easily accessible.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => self::GDPR_DATA_RIGHTS,
                'affected_files' => $customer_edit_files,
                'fix_specification' => 'Ensure comprehensive and user-friendly data rectification interface.',
                'business_impact' => 'Customers have right to rectify inaccurate personal data'
            );
        }
        
        // Check for data access functionality (Right to access)
        $access_found = false;
        $customer_files = glob('controllers/front/*Controller.php');
        
        foreach ($customer_files as $file) {
            $content = file_get_contents($file);
            if (preg_match('/view.*data|access.*information|download.*profile/i', $content)) {
                $access_found = true;
                break;
            }
        }
        
        if (!$access_found) {
            $findings[] = array(
                'title' => 'Limited data access functionality',
                'description' => 'No clear mechanism for customers to access all their personal data (GDPR Article 15).',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => self::GDPR_DATA_RIGHTS,
                'affected_files' => array('customer controllers'),
                'fix_specification' => 'Implement comprehensive data access interface showing all personal data.',
                'business_impact' => 'Legal requirement - customers have right to access their data'
            );
        }
        
        $this->saveFindings($findings);
    }

    /**
     * Review data retention and deletion policies
     */
    private function reviewDataRetentionPolicies()
    {
        $findings = array();
        
        // Check for automated data retention policies
        $cron_files = glob('*cron*.php');
        $retention_automation = false;
        
        foreach ($cron_files as $file) {
            $content = file_get_contents($file);
            if (preg_match('/retention|delete.*old|cleanup.*data/i', $content)) {
                $retention_automation = true;
                break;
            }
        }
        
        if (!$retention_automation) {
            $findings[] = array(
                'title' => 'Missing automated data retention policies',
                'description' => 'No automated data retention and deletion policies found in cron jobs or scheduled tasks.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => self::GDPR_DATA_RETENTION,
                'affected_files' => array('cron jobs'),
                'fix_specification' => 'Implement automated data retention policies with configurable retention periods.',
                'business_impact' => 'GDPR requires data minimization and limited retention periods'
            );
        }
        
        // Check for retention period configuration
        $config_files = array(
            'config/config.inc.php',
            'classes/Configuration.php'
        );
        
        $retention_config = false;
        foreach ($config_files as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/retention.?period|data.?lifetime|delete.?after/i', $content)) {
                    $retention_config = true;
                    break;
                }
            }
        }
        
        if (!$retention_config) {
            $findings[] = array(
                'title' => 'Missing data retention configuration',
                'description' => 'No configurable data retention periods found in system configuration.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => self::GDPR_DATA_RETENTION,
                'affected_files' => $config_files,
                'fix_specification' => 'Add configurable data retention periods for different data types.',
                'business_impact' => 'Need to define and enforce data retention policies for GDPR compliance'
            );
        }
        
        // Check for guest data cleanup
        $guest_files = array(
            'classes/Guest.php',
            'classes/Cart.php'
        );
        
        $guest_cleanup = false;
        foreach ($guest_files as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/cleanup|delete.*guest|expire/i', $content)) {
                    $guest_cleanup = true;
                    break;
                }
            }
        }
        
        if (!$guest_cleanup) {
            $findings[] = array(
                'title' => 'Missing guest data cleanup',
                'description' => 'No automatic cleanup mechanism found for guest user data and abandoned carts.',
                'severity' => SecurityAudit::SEVERITY_LOW,
                'category' => self::GDPR_DATA_RETENTION,
                'affected_files' => $guest_files,
                'fix_specification' => 'Implement automatic cleanup of guest data after defined retention period.',
                'business_impact' => 'Accumulation of unnecessary personal data violates data minimization principle'
            );
        }
        
        $this->saveFindings($findings);
    }

    /**
     * Assess privacy protection measures (Task 8.2)
     */
    public function assessPrivacyProtectionMeasures()
    {
        // Review privacy policy implementation
        $this->reviewPrivacyPolicyImplementation();
        
        // Check data breach notification procedures
        $this->checkDataBreachNotificationProcedures();
        
        // Examine privacy by design implementation
        $this->examinePrivacyByDesignImplementation();
    }

    /**
     * Review privacy policy implementation and data handling
     */
    private function reviewPrivacyPolicyImplementation()
    {
        $findings = array();
        
        // Check for privacy policy pages
        $cms_files = array(
            'classes/CMS.php',
            'controllers/front/CmsController.php'
        );
        
        $privacy_policy_found = false;
        foreach ($cms_files as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/privacy.?policy|data.?protection|gdpr/i', $content)) {
                    $privacy_policy_found = true;
                    break;
                }
            }
        }
        
        // Check theme templates for privacy policy links
        if (!$privacy_policy_found) {
            $theme_files = glob('themes/*/templates/**/*.tpl');
            foreach ($theme_files as $file) {
                $content = file_get_contents($file);
                if (preg_match('/privacy.?policy|data.?protection/i', $content)) {
                    $privacy_policy_found = true;
                    break;
                }
            }
        }
        
        if (!$privacy_policy_found) {
            $findings[] = array(
                'title' => 'Missing privacy policy implementation',
                'description' => 'No privacy policy page or links found in CMS or theme templates.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => self::GDPR_PRIVACY_DESIGN,
                'affected_files' => array('CMS', 'themes'),
                'fix_specification' => 'Create comprehensive privacy policy page and ensure it is easily accessible.',
                'business_impact' => 'Legal requirement - privacy policy must be easily accessible'
            );
        }
        
        // Check for data processing transparency
        $transparency_indicators = array(
            'data.?controller',
            'processing.?purpose',
            'legal.?basis',
            'retention.?period',
            'third.?party',
            'data.?transfer'
        );
        
        $transparency_score = 0;
        if ($privacy_policy_found) {
            foreach ($theme_files as $file) {
                $content = file_get_contents($file);
                foreach ($transparency_indicators as $indicator) {
                    if (preg_match('/' . $indicator . '/i', $content)) {
                        $transparency_score++;
                        break;
                    }
                }
            }
        }
        
        if ($transparency_score < 3) {
            $findings[] = array(
                'title' => 'Insufficient data processing transparency',
                'description' => 'Privacy policy lacks comprehensive information about data processing activities.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => self::GDPR_PRIVACY_DESIGN,
                'affected_files' => array('privacy policy'),
                'fix_specification' => 'Enhance privacy policy with detailed data processing information including purposes, legal basis, retention periods, and third-party sharing.',
                'business_impact' => 'GDPR requires transparent information about data processing'
            );
        }
        
        $this->saveFindings($findings);
    }

    /**
     * Check data breach notification procedures
     */
    private function checkDataBreachNotificationProcedures()
    {
        $findings = array();
        
        // Check for breach detection mechanisms
        $security_files = array(
            'classes/SecurityAudit.php',
            'classes/PrestaShopLogger.php'
        );
        
        $breach_detection = false;
        foreach ($security_files as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/breach|security.?incident|unauthorized.?access/i', $content)) {
                    $breach_detection = true;
                    break;
                }
            }
        }
        
        if (!$breach_detection) {
            $findings[] = array(
                'title' => 'Missing data breach detection mechanisms',
                'description' => 'No automated data breach detection or security incident monitoring found.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => self::GDPR_BREACH_NOTIFICATION,
                'affected_files' => $security_files,
                'fix_specification' => 'Implement automated breach detection and security incident monitoring systems.',
                'business_impact' => 'GDPR requires breach notification within 72 hours - detection is critical'
            );
        }
        
        // Check for notification procedures
        $notification_files = array(
            'classes/Mail.php',
            'mails/'
        );
        
        $breach_notification = false;
        foreach ($notification_files as $file) {
            if (file_exists($file)) {
                if (is_file($file)) {
                    $content = file_get_contents($file);
                    if (preg_match('/breach.?notification|security.?alert|incident.?report/i', $content)) {
                        $breach_notification = true;
                        break;
                    }
                } else {
                    // Check directory for breach notification templates
                    $templates = glob($file . '*/breach_notification.*');
                    if (!empty($templates)) {
                        $breach_notification = true;
                        break;
                    }
                }
            }
        }
        
        if (!$breach_notification) {
            $findings[] = array(
                'title' => 'Missing breach notification procedures',
                'description' => 'No data breach notification templates or procedures found.',
                'severity' => SecurityAudit::SEVERITY_HIGH,
                'category' => self::GDPR_BREACH_NOTIFICATION,
                'affected_files' => $notification_files,
                'fix_specification' => 'Create breach notification templates and automated notification procedures.',
                'business_impact' => 'Legal requirement - must notify authorities and affected individuals within 72 hours'
            );
        }
        
        // Check for incident response documentation
        $docs_found = false;
        $doc_files = array(
            'SECURITY.md',
            'docs/security/',
            'incident_response.md'
        );
        
        foreach ($doc_files as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/incident.?response|breach.?procedure|security.?protocol/i', $content)) {
                    $docs_found = true;
                    break;
                }
            }
        }
        
        if (!$docs_found) {
            $findings[] = array(
                'title' => 'Missing incident response documentation',
                'description' => 'No documented incident response procedures or security protocols found.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => self::GDPR_BREACH_NOTIFICATION,
                'affected_files' => array('documentation'),
                'fix_specification' => 'Create comprehensive incident response documentation and procedures.',
                'business_impact' => 'Proper incident response is crucial for GDPR compliance and breach management'
            );
        }
        
        $this->saveFindings($findings);
    }

    /**
     * Examine privacy by design implementation
     */
    private function examinePrivacyByDesignImplementation()
    {
        $findings = array();
        
        // Check for data protection by default settings
        $config_files = array(
            'config/config.inc.php',
            'install/data/xml/configuration.xml'
        );
        
        $privacy_defaults = false;
        foreach ($config_files as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/privacy.*default|opt.*out.*default|minimal.*data/i', $content)) {
                    $privacy_defaults = true;
                    break;
                }
            }
        }
        
        if (!$privacy_defaults) {
            $findings[] = array(
                'title' => 'Missing privacy by default configuration',
                'description' => 'System does not implement privacy-friendly default settings.',
                'severity' => SecurityAudit::SEVERITY_MEDIUM,
                'category' => self::GDPR_PRIVACY_DESIGN,
                'affected_files' => $config_files,
                'fix_specification' => 'Configure system defaults to be privacy-friendly (opt-out by default, minimal data collection).',
                'business_impact' => 'GDPR requires privacy by design and by default'
            );
        }
        
        // Check for pseudonymization implementation
        $crypto_files = array(
            'classes/PhpEncryption.php',
            'classes/Blowfish.php'
        );
        
        $pseudonymization = false;
        foreach ($crypto_files as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (preg_match('/hash|pseudonym|anonymize/i', $content)) {
                    $pseudonymization = true;
                    break;
                }
            }
        }
        
        if (!$pseudonymization) {
            $findings[] = array(
                'title' => 'Limited pseudonymization capabilities',
                'description' => 'No clear pseudonymization or anonymization mechanisms found.',
                'severity' => SecurityAudit::SEVERITY_LOW,
                'category' => self::GDPR_PRIVACY_DESIGN,
                'affected_files' => $crypto_files,
                'fix_specification' => 'Implement pseudonymization techniques for personal data processing.',
                'business_impact' => 'Pseudonymization reduces privacy risks and supports GDPR compliance'
            );
        }
        
        // Check for privacy impact assessment integration
        $assessment_found = false;
        $admin_files = glob('controllers/admin/Admin*Controller.php');
        
        foreach ($admin_files as $file) {
            $content = file_get_contents($file);
            if (preg_match('/privacy.?impact|pia|dpia/i', $content)) {
                $assessment_found = true;
                break;
            }
        }
        
        if (!$assessment_found) {
            $findings[] = array(
                'title' => 'Missing privacy impact assessment integration',
                'description' => 'No privacy impact assessment (PIA/DPIA) integration found in admin interface.',
                'severity' => SecurityAudit::SEVERITY_LOW,
                'category' => self::GDPR_PRIVACY_DESIGN,
                'affected_files' => array('admin controllers'),
                'fix_specification' => 'Integrate privacy impact assessment tools for new features and data processing activities.',
                'business_impact' => 'DPIA required for high-risk processing activities under GDPR'
            );
        }
        
        $this->saveFindings($findings);
    }

    /**
     * Save findings to database
     */
    private function saveFindings($findings)
    {
        foreach ($findings as $finding_data) {
            $finding = new SecurityFinding();
            $finding->id_audit = $this->audit->id;
            $finding->title = $finding_data['title'];
            $finding->description = $finding_data['description'];
            $finding->severity = $finding_data['severity'];
            $finding->category = $finding_data['category'];
            $finding->affected_files = json_encode($finding_data['affected_files']);
            $finding->fix_specification = $finding_data['fix_specification'];
            $finding->business_impact = $finding_data['business_impact'];
            $finding->status = 'open';
            $finding->date_found = date('Y-m-d H:i:s');
            
            $finding->save();
            $this->findings[] = $finding;
        }
    }

    /**
     * Generate comprehensive GDPR compliance report
     */
    public function generateGDPRReport()
    {
        $summary = $this->audit->getSummary();
        
        $report = array(
            'audit_info' => $summary,
            'gdpr_compliance_status' => $this->calculateGDPRComplianceStatus(),
            'findings_by_category' => $this->getFindingsByCategory(),
            'recommendations' => $this->getGDPRRecommendations(),
            'compliance_checklist' => $this->getGDPRComplianceChecklist()
        );
        
        return $report;
    }

    /**
     * Calculate overall GDPR compliance status
     */
    private function calculateGDPRComplianceStatus()
    {
        $critical_gdpr = 0;
        $high_gdpr = 0;
        $total_gdpr = 0;
        
        foreach ($this->findings as $finding) {
            if (strpos($finding->category, 'gdpr_') === 0) {
                $total_gdpr++;
                if ($finding->severity == SecurityAudit::SEVERITY_CRITICAL) {
                    $critical_gdpr++;
                } elseif ($finding->severity == SecurityAudit::SEVERITY_HIGH) {
                    $high_gdpr++;
                }
            }
        }
        
        if ($critical_gdpr > 0) {
            return 'Non-Compliant';
        } elseif ($high_gdpr > 3) {
            return 'Partially Compliant';
        } elseif ($high_gdpr > 0) {
            return 'Mostly Compliant';
        } else {
            return 'Compliant';
        }
    }

    /**
     * Get findings grouped by GDPR category
     */
    private function getFindingsByCategory()
    {
        $categories = array();
        
        foreach ($this->findings as $finding) {
            if (!isset($categories[$finding->category])) {
                $categories[$finding->category] = array();
            }
            $categories[$finding->category][] = $finding;
        }
        
        return $categories;
    }

    /**
     * Get GDPR-specific recommendations
     */
    private function getGDPRRecommendations()
    {
        return array(
            'immediate_actions' => array(
                'Implement cookie consent mechanism',
                'Create comprehensive privacy policy',
                'Set up data breach notification procedures',
                'Document lawful basis for data processing'
            ),
            'short_term_actions' => array(
                'Implement data subject rights functionality',
                'Set up automated data retention policies',
                'Enhance consent withdrawal mechanisms',
                'Create privacy by default configurations'
            ),
            'long_term_actions' => array(
                'Implement privacy impact assessment tools',
                'Enhance pseudonymization capabilities',
                'Regular GDPR compliance audits',
                'Staff training on data protection'
            )
        );
    }

    /**
     * Get GDPR compliance checklist
     */
    private function getGDPRComplianceChecklist()
    {
        return array(
            'data_processing' => array(
                'lawful_basis_documented' => false,
                'consent_mechanisms_implemented' => false,
                'data_minimization_applied' => false,
                'special_category_protection' => false
            ),
            'data_subject_rights' => array(
                'right_to_access' => false,
                'right_to_rectification' => false,
                'right_to_erasure' => false,
                'right_to_portability' => false,
                'right_to_object' => false
            ),
            'privacy_protection' => array(
                'privacy_policy_accessible' => false,
                'privacy_by_design' => false,
                'privacy_by_default' => false,
                'breach_notification_procedures' => false
            ),
            'technical_measures' => array(
                'encryption_implemented' => false,
                'pseudonymization_available' => false,
                'access_controls' => false,
                'audit_logging' => false
            )
        );
    }
}