<?php
/**
 * Security Audit Configuration Management
 * 
 * Manages configuration settings for security audits and scans
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class SecurityAuditConfig extends ObjectModel
{
    public $id;
    public $config_name;
    public $config_key;
    public $config_value;
    public $config_type;
    public $is_active;

    public static $definition = array(
        'table' => 'security_scan_config',
        'primary' => 'id_config',
        'fields' => array(
            'config_name' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'required' => true,
                'size' => 255
            ),
            'config_key' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isConfigName',
                'required' => true,
                'size' => 128
            ),
            'config_value' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isString'
            ),
            'config_type' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 32
            ),
            'is_active' => array(
                'type' => self::TYPE_BOOL,
                'validate' => 'isBool'
            )
        )
    );

    /**
     * Get configuration value by key
     */
    public static function getConfigValue($key, $default = null)
    {
        $sql = 'SELECT config_value, config_type 
                FROM ' . _DB_PREFIX_ . 'security_scan_config 
                WHERE config_key = "' . pSQL($key) . '" 
                AND is_active = 1';
        
        $result = Db::getInstance()->getRow($sql);
        
        if (!$result) {
            return $default;
        }

        return self::castConfigValue($result['config_value'], $result['config_type']);
    }

    /**
     * Set configuration value
     */
    public static function setConfigValue($key, $value, $type = 'string')
    {
        $config = self::getConfigByKey($key);
        
        if ($config) {
            $config->config_value = $value;
            $config->config_type = $type;
            return $config->save();
        } else {
            $config = new self();
            $config->config_key = $key;
            $config->config_value = $value;
            $config->config_type = $type;
            $config->config_name = ucwords(str_replace('_', ' ', $key));
            $config->is_active = true;
            return $config->save();
        }
    }

    /**
     * Get configuration object by key
     */
    public static function getConfigByKey($key)
    {
        $sql = 'SELECT id_config 
                FROM ' . _DB_PREFIX_ . 'security_scan_config 
                WHERE config_key = "' . pSQL($key) . '"';
        
        $id = Db::getInstance()->getValue($sql);
        
        return $id ? new self($id) : false;
    }

    /**
     * Get all active configurations
     */
    public static function getAllConfigs($active_only = true)
    {
        $sql = 'SELECT * FROM ' . _DB_PREFIX_ . 'security_scan_config';
        
        if ($active_only) {
            $sql .= ' WHERE is_active = 1';
        }
        
        $sql .= ' ORDER BY config_name';
        
        return Db::getInstance()->executeS($sql);
    }

    /**
     * Get scan configuration array
     */
    public static function getScanConfig()
    {
        $config = array(
            'scan_types' => array(
                'sql_injection' => (bool)self::getConfigValue('scan_sql_injection', true),
                'xss' => (bool)self::getConfigValue('scan_xss', true),
                'file_upload' => (bool)self::getConfigValue('scan_file_upload', true),
                'authentication' => (bool)self::getConfigValue('scan_authentication', true),
                'hardcoded_creds' => (bool)self::getConfigValue('scan_hardcoded_creds', true),
                'file_permissions' => (bool)self::getConfigValue('scan_file_permissions', true),
                'configuration' => (bool)self::getConfigValue('scan_configuration', true)
            ),
            'directories' => explode(',', self::getConfigValue('scan_directories', 'classes/,controllers/,modules/')),
            'extensions' => explode(',', self::getConfigValue('scan_extensions', 'php')),
            'exclude_patterns' => explode(',', self::getConfigValue('exclude_patterns', 'cache/,log/,upload/')),
            'max_files' => (int)self::getConfigValue('max_scan_files', 1000),
            'severity_threshold' => (int)self::getConfigValue('severity_threshold', 2)
        );

        // Clean up arrays
        $config['directories'] = array_map('trim', $config['directories']);
        $config['extensions'] = array_map('trim', $config['extensions']);
        $config['exclude_patterns'] = array_map('trim', $config['exclude_patterns']);

        return $config;
    }

    /**
     * Update scan configuration
     */
    public static function updateScanConfig($config_data)
    {
        $success = true;

        // Update scan types
        if (isset($config_data['scan_types'])) {
            foreach ($config_data['scan_types'] as $type => $enabled) {
                $key = 'scan_' . $type;
                $success = $success && self::setConfigValue($key, $enabled ? '1' : '0', 'boolean');
            }
        }

        // Update directories
        if (isset($config_data['directories'])) {
            $directories = is_array($config_data['directories']) ? 
                          implode(',', $config_data['directories']) : 
                          $config_data['directories'];
            $success = $success && self::setConfigValue('scan_directories', $directories, 'string');
        }

        // Update extensions
        if (isset($config_data['extensions'])) {
            $extensions = is_array($config_data['extensions']) ? 
                         implode(',', $config_data['extensions']) : 
                         $config_data['extensions'];
            $success = $success && self::setConfigValue('scan_extensions', $extensions, 'string');
        }

        // Update exclude patterns
        if (isset($config_data['exclude_patterns'])) {
            $patterns = is_array($config_data['exclude_patterns']) ? 
                       implode(',', $config_data['exclude_patterns']) : 
                       $config_data['exclude_patterns'];
            $success = $success && self::setConfigValue('exclude_patterns', $patterns, 'string');
        }

        // Update other settings
        if (isset($config_data['max_files'])) {
            $success = $success && self::setConfigValue('max_scan_files', (int)$config_data['max_files'], 'integer');
        }

        if (isset($config_data['severity_threshold'])) {
            $success = $success && self::setConfigValue('severity_threshold', (int)$config_data['severity_threshold'], 'integer');
        }

        return $success;
    }

    /**
     * Cast configuration value to appropriate type
     */
    private static function castConfigValue($value, $type)
    {
        switch ($type) {
            case 'boolean':
                return (bool)$value;
            case 'integer':
                return (int)$value;
            case 'float':
                return (float)$value;
            case 'array':
                return json_decode($value, true);
            default:
                return $value;
        }
    }

    /**
     * Get default scan configuration
     */
    public static function getDefaultConfig()
    {
        return array(
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
    }

    /**
     * Reset configuration to defaults
     */
    public static function resetToDefaults()
    {
        $default_config = self::getDefaultConfig();
        return self::updateScanConfig($default_config);
    }

    /**
     * Validate configuration key
     */
    public static function isConfigName($name)
    {
        return preg_match('/^[a-zA-Z0-9_]+$/', $name);
    }

    /**
     * Export configuration as JSON
     */
    public static function exportConfig()
    {
        $configs = self::getAllConfigs();
        $export_data = array();

        foreach ($configs as $config) {
            $export_data[$config['config_key']] = array(
                'name' => $config['config_name'],
                'value' => $config['config_value'],
                'type' => $config['config_type'],
                'active' => (bool)$config['is_active']
            );
        }

        return json_encode($export_data, JSON_PRETTY_PRINT);
    }

    /**
     * Import configuration from JSON
     */
    public static function importConfig($json_data)
    {
        $config_data = json_decode($json_data, true);
        
        if (!$config_data) {
            return false;
        }

        $success = true;

        foreach ($config_data as $key => $config) {
            $success = $success && self::setConfigValue(
                $key, 
                $config['value'], 
                $config['type']
            );
        }

        return $success;
    }
}