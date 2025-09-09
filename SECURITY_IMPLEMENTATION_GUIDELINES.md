# Security Implementation Guidelines

## Document Information

- **Document Version**: 1.0
- **Created**: 2024-01-15
- **Purpose**: Provide detailed implementation guidelines for security fixes
- **Scope**: QloApps Security Remediation

---

## Table of Contents

1. [General Security Principles](#general-security-principles)
2. [Critical Security Fixes](#critical-security-fixes)
3. [High-Priority Security Fixes](#high-priority-security-fixes)
4. [Medium-Priority Security Fixes](#medium-priority-security-fixes)
5. [Security Best Practices](#security-best-practices)
6. [Testing Procedures](#testing-procedures)
7. [Code Review Guidelines](#code-review-guidelines)
8. [Deployment Guidelines](#deployment-guidelines)

---

## General Security Principles

### Secure Coding Standards

#### Input Validation
- **Always validate input**: Never trust user input
- **Whitelist approach**: Define what is allowed, not what is forbidden
- **Sanitize early**: Validate at the entry point
- **Escape output**: Always escape data when outputting to prevent XSS

#### Authentication and Authorization
- **Principle of least privilege**: Grant minimum necessary permissions
- **Defense in depth**: Multiple layers of security
- **Fail securely**: Default to deny access when errors occur
- **Session security**: Proper session management and timeout

#### Data Protection
- **Encrypt sensitive data**: Both at rest and in transit
- **Use strong cryptography**: Industry-standard algorithms
- **Secure key management**: Proper key storage and rotation
- **Data minimization**: Collect only necessary data

### QloApps-Specific Guidelines

#### ObjectModel Pattern
```php
// Always use ObjectModel validation
class SecureModel extends ObjectModel
{
    public static $definition = array(
        'table' => 'secure_table',
        'primary' => 'id',
        'fields' => array(
            'email' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isEmail',
                'required' => true,
                'size' => 255
            ),
            'password' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isPasswd',
                'required' => true,
                'size' => 255
            )
        )
    );
}
```

#### Database Queries
```php
// Always use prepared statements
$sql = 'SELECT * FROM ' . _DB_PREFIX_ . 'customer WHERE email = ?';
$result = Db::getInstance()->getRow($sql, array($email));

// Never concatenate user input
// BAD: $sql = "SELECT * FROM customer WHERE email = '" . $email . "'";
```

---

## Critical Security Fixes

### 1. SQL Injection in Customer Authentication

**Priority**: 🚨 Immediate (0-24 hours)
**Risk Score**: 5.00
**Estimated Effort**: 29 hours

#### Problem Description
The customer login functionality is vulnerable to SQL injection attacks due to improper input sanitization in authentication queries.

#### Affected Files
- `/classes/Customer.php`
- `/controllers/front/AuthController.php`

#### Implementation Steps

##### Step 1: Fix Customer.php Authentication Method
```php
// File: /classes/Customer.php

// BEFORE (Vulnerable)
public function getByEmail($email, $passwd = null)
{
    $sql = 'SELECT * FROM ' . _DB_PREFIX_ . 'customer 
            WHERE email = "' . $email . '"';
    if ($passwd) {
        $sql .= ' AND passwd = "' . md5($passwd) . '"';
    }
    return Db::getInstance()->getRow($sql);
}

// AFTER (Secure)
public function getByEmail($email, $passwd = null)
{
    // Validate email format first
    if (!Validate::isEmail($email)) {
        return false;
    }
    
    $sql = 'SELECT * FROM ' . _DB_PREFIX_ . 'customer 
            WHERE email = ?';
    $params = array($email);
    
    if ($passwd) {
        // Use proper password hashing
        $sql .= ' AND passwd = ?';
        $params[] = $this->hashPassword($passwd);
    }
    
    return Db::getInstance()->getRow($sql, $params);
}

// Add secure password hashing method
private function hashPassword($password)
{
    // Use PHP's password_hash for new passwords
    if (defined('PASSWORD_DEFAULT')) {
        return password_hash($password, PASSWORD_DEFAULT);
    }
    // Fallback for older PHP versions
    return hash('sha256', $password . _COOKIE_KEY_);
}

// Add password verification method
public function verifyPassword($password, $hash)
{
    // Try modern password verification first
    if (function_exists('password_verify') && password_verify($password, $hash)) {
        return true;
    }
    
    // Fallback for legacy hashes
    return hash('sha256', $password . _COOKIE_KEY_) === $hash;
}
```

##### Step 2: Update AuthController
```php
// File: /controllers/front/AuthController.php

public function processSubmitLogin()
{
    $email = Tools::getValue('email');
    $passwd = Tools::getValue('passwd');
    
    // Input validation
    if (empty($email) || !Validate::isEmail($email)) {
        $this->errors[] = Tools::displayError('Invalid email address');
        return false;
    }
    
    if (empty($passwd) || !Validate::isPasswd($passwd)) {
        $this->errors[] = Tools::displayError('Invalid password');
        return false;
    }
    
    // Rate limiting check
    if (!$this->checkLoginAttempts($email)) {
        $this->errors[] = Tools::displayError('Too many login attempts. Please try again later.');
        return false;
    }
    
    // Secure authentication
    $customer = new Customer();
    $authentication = $customer->getByEmail($email, $passwd);
    
    if (!$authentication || !$customer->verifyPassword($passwd, $authentication['passwd'])) {
        $this->recordFailedLogin($email);
        $this->errors[] = Tools::displayError('Authentication failed');
        return false;
    }
    
    // Successful login
    $this->recordSuccessfulLogin($email);
    $this->context->customer = new Customer($authentication['id_customer']);
    
    return true;
}

// Add rate limiting
private function checkLoginAttempts($email)
{
    $attempts = Db::getInstance()->getValue('
        SELECT COUNT(*) FROM ' . _DB_PREFIX_ . 'login_attempts 
        WHERE email = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)',
        array($email)
    );
    
    return $attempts < 5; // Max 5 attempts per 15 minutes
}

private function recordFailedLogin($email)
{
    Db::getInstance()->insert('login_attempts', array(
        'email' => pSQL($email),
        'ip_address' => pSQL(Tools::getRemoteAddr()),
        'attempt_time' => date('Y-m-d H:i:s'),
        'success' => 0
    ));
}
```

##### Step 3: Create Login Attempts Table
```sql
-- File: /install/sql/login_attempts.sql
CREATE TABLE IF NOT EXISTS `ps_login_attempts` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `email` varchar(255) NOT NULL,
    `ip_address` varchar(45) NOT NULL,
    `attempt_time` datetime NOT NULL,
    `success` tinyint(1) DEFAULT 0,
    PRIMARY KEY (`id`),
    KEY `email_time` (`email`, `attempt_time`),
    KEY `ip_time` (`ip_address`, `attempt_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### Testing Procedures
```php
// File: /tests/unit/CustomerAuthenticationTest.php

class CustomerAuthenticationTest extends PHPUnit_Framework_TestCase
{
    public function testSQLInjectionPrevention()
    {
        $customer = new Customer();
        
        // Test SQL injection attempts
        $maliciousInputs = array(
            "admin@test.com' OR '1'='1",
            "admin@test.com'; DROP TABLE ps_customer; --",
            "admin@test.com' UNION SELECT * FROM ps_customer --"
        );
        
        foreach ($maliciousInputs as $input) {
            $result = $customer->getByEmail($input);
            $this->assertFalse($result, "SQL injection should be prevented");
        }
    }
    
    public function testValidEmailAuthentication()
    {
        $customer = new Customer();
        $result = $customer->getByEmail('valid@test.com', 'validpassword');
        
        // Should return false for non-existent user, not throw SQL error
        $this->assertFalse($result);
    }
    
    public function testRateLimiting()
    {
        $controller = new AuthController();
        
        // Simulate multiple failed attempts
        for ($i = 0; $i < 6; $i++) {
            $controller->processSubmitLogin();
        }
        
        // 6th attempt should be blocked
        $this->assertContains('Too many login attempts', $controller->errors);
    }
}
```

### 2. Deprecated PaymentCC Class with Card Data

**Priority**: 🚨 Immediate (0-24 hours)
**Risk Score**: 5.00
**Estimated Effort**: 36 hours

#### Problem Description
The deprecated PaymentCC class contains fields for storing sensitive cardholder data, violating PCI DSS requirements.

#### Affected Files
- `/classes/PaymentCC.php`

#### Implementation Steps

##### Step 1: Remove Deprecated PaymentCC Class
```php
// File: /classes/PaymentCC.php - REMOVE ENTIRELY

// Create migration script instead
// File: /install/upgrade/remove_payment_cc.php

<?php
/**
 * Migration script to remove PaymentCC class and secure card data
 */

function removePaymentCCClass()
{
    // 1. Check if PaymentCC table exists and has data
    $hasData = Db::getInstance()->getValue('
        SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_SCHEMA = "' . _DB_NAME_ . '" 
        AND TABLE_NAME = "' . _DB_PREFIX_ . 'payment_cc"'
    );
    
    if ($hasData) {
        // 2. Backup existing data (without sensitive fields)
        Db::getInstance()->execute('
            CREATE TABLE ' . _DB_PREFIX_ . 'payment_cc_backup AS
            SELECT id_payment_cc, id_order, payment_method, date_add
            FROM ' . _DB_PREFIX_ . 'payment_cc'
        );
        
        // 3. Remove sensitive data
        Db::getInstance()->execute('DROP TABLE IF EXISTS ' . _DB_PREFIX_ . 'payment_cc');
        
        // 4. Create secure payment reference table
        Db::getInstance()->execute('
            CREATE TABLE ' . _DB_PREFIX_ . 'payment_reference (
                id_payment_reference int(11) NOT NULL AUTO_INCREMENT,
                id_order int(11) NOT NULL,
                payment_method varchar(50) NOT NULL,
                transaction_id varchar(255),
                payment_token varchar(255),
                payment_status varchar(50) DEFAULT "pending",
                date_add datetime NOT NULL,
                date_upd datetime NOT NULL,
                PRIMARY KEY (id_payment_reference),
                KEY idx_order (id_order),
                KEY idx_transaction (transaction_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
        );
    }
    
    return true;
}
```

##### Step 2: Create Secure Payment Handler
```php
// File: /classes/SecurePayment.php

class SecurePayment extends ObjectModel
{
    public $id_order;
    public $payment_method;
    public $transaction_id;
    public $payment_token;
    public $payment_status;
    public $date_add;
    public $date_upd;

    public static $definition = array(
        'table' => 'payment_reference',
        'primary' => 'id_payment_reference',
        'fields' => array(
            'id_order' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedId',
                'required' => true
            ),
            'payment_method' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'required' => true,
                'size' => 50
            ),
            'transaction_id' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 255
            ),
            'payment_token' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 255
            ),
            'payment_status' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 50
            ),
            'date_add' => array(
                'type' => self::TYPE_DATE,
                'validate' => 'isDate'
            ),
            'date_upd' => array(
                'type' => self::TYPE_DATE,
                'validate' => 'isDate'
            )
        )
    );

    /**
     * Process payment securely using tokenization
     */
    public function processPayment($orderData, $paymentData)
    {
        // Never store card data - use payment processor tokens
        $this->id_order = $orderData['id_order'];
        $this->payment_method = $paymentData['method'];
        
        // Get token from payment processor
        $token = $this->getPaymentToken($paymentData);
        if (!$token) {
            throw new Exception('Payment tokenization failed');
        }
        
        $this->payment_token = $token;
        $this->payment_status = 'pending';
        $this->date_add = date('Y-m-d H:i:s');
        $this->date_upd = date('Y-m-d H:i:s');
        
        return $this->save();
    }

    /**
     * Get payment token from processor (never store card data)
     */
    private function getPaymentToken($paymentData)
    {
        // Integration with payment processor for tokenization
        // This is where you'd integrate with Stripe, PayPal, etc.
        
        // Example for Stripe
        if ($paymentData['method'] === 'stripe') {
            return $this->createStripeToken($paymentData);
        }
        
        return false;
    }

    private function createStripeToken($paymentData)
    {
        // Use Stripe's tokenization API
        // Never log or store actual card data
        
        $stripe = new \Stripe\StripeClient(Configuration::get('STRIPE_SECRET_KEY'));
        
        try {
            $token = $stripe->tokens->create([
                'card' => [
                    'number' => $paymentData['card_number'], // This gets tokenized immediately
                    'exp_month' => $paymentData['exp_month'],
                    'exp_year' => $paymentData['exp_year'],
                    'cvc' => $paymentData['cvc']
                ]
            ]);
            
            // Return only the token, never store card data
            return $token->id;
            
        } catch (Exception $e) {
            PrestaShopLogger::addLog('Payment tokenization failed: ' . $e->getMessage(), 3);
            return false;
        }
    }
}
```

##### Step 3: Update Payment Modules
```php
// File: /modules/*/payment.php - Update all payment modules

// Example for credit card payment module
class CreditCardPayment extends PaymentModule
{
    public function execPayment($cart)
    {
        // Validate cart and customer
        if (!$this->validateCart($cart)) {
            return false;
        }
        
        // Create order first
        $order = new Order();
        $order->id_customer = $cart->id_customer;
        $order->total_paid = $cart->getOrderTotal();
        $order->save();
        
        // Process payment securely
        $securePayment = new SecurePayment();
        $paymentData = array(
            'method' => 'stripe',
            'card_number' => Tools::getValue('card_number'),
            'exp_month' => Tools::getValue('exp_month'),
            'exp_year' => Tools::getValue('exp_year'),
            'cvc' => Tools::getValue('cvc')
        );
        
        // Clear sensitive data from memory immediately
        $result = $securePayment->processPayment(
            array('id_order' => $order->id),
            $paymentData
        );
        
        // Clear payment data from variables
        unset($paymentData);
        
        return $result;
    }
    
    private function validateCart($cart)
    {
        return Validate::isLoadedObject($cart) && 
               $cart->OrderExists() == false &&
               $cart->id_customer != 0;
    }
}
```

#### Testing Procedures
```php
// File: /tests/unit/SecurePaymentTest.php

class SecurePaymentTest extends PHPUnit_Framework_TestCase
{
    public function testNoCardDataStorage()
    {
        // Verify no card data is stored in database
        $tables = Db::getInstance()->executeS('SHOW TABLES');
        
        foreach ($tables as $table) {
            $columns = Db::getInstance()->executeS('DESCRIBE ' . $table['Tables_in_' . _DB_NAME_]);
            
            foreach ($columns as $column) {
                $columnName = strtolower($column['Field']);
                
                // Check for common card data field names
                $cardDataFields = array('card_number', 'cvv', 'cvc', 'expiry', 'card_holder');
                
                foreach ($cardDataFields as $field) {
                    $this->assertFalse(
                        strpos($columnName, $field) !== false,
                        "Found potential card data field: {$columnName} in table {$table}"
                    );
                }
            }
        }
    }
    
    public function testTokenizationProcess()
    {
        $payment = new SecurePayment();
        
        $orderData = array('id_order' => 1);
        $paymentData = array(
            'method' => 'test',
            'card_number' => '4111111111111111',
            'exp_month' => '12',
            'exp_year' => '2025',
            'cvc' => '123'
        );
        
        $result = $payment->processPayment($orderData, $paymentData);
        
        $this->assertTrue($result);
        $this->assertNotEmpty($payment->payment_token);
        $this->assertEquals('pending', $payment->payment_status);
    }
}
```

---

## High-Priority Security Fixes

### 3. Missing API Rate Limiting

**Priority**: ⚠️ Urgent (1-7 days)
**Risk Score**: 4.00
**Estimated Effort**: 56 hours

#### Implementation Steps

##### Step 1: Create Rate Limiting Class
```php
// File: /classes/APIRateLimit.php

class APIRateLimit
{
    const DEFAULT_LIMIT = 100; // requests per hour
    const DEFAULT_WINDOW = 3600; // 1 hour in seconds
    
    private $redis;
    private $useRedis = false;
    
    public function __construct()
    {
        // Try to use Redis if available, fallback to database
        if (class_exists('Redis')) {
            try {
                $this->redis = new Redis();
                $this->redis->connect('127.0.0.1', 6379);
                $this->useRedis = true;
            } catch (Exception $e) {
                $this->useRedis = false;
            }
        }
    }
    
    /**
     * Check if request is within rate limit
     */
    public function checkRateLimit($identifier, $limit = null, $window = null)
    {
        $limit = $limit ?: self::DEFAULT_LIMIT;
        $window = $window ?: self::DEFAULT_WINDOW;
        
        if ($this->useRedis) {
            return $this->checkRateLimitRedis($identifier, $limit, $window);
        } else {
            return $this->checkRateLimitDatabase($identifier, $limit, $window);
        }
    }
    
    private function checkRateLimitRedis($identifier, $limit, $window)
    {
        $key = 'rate_limit:' . $identifier;
        $current = $this->redis->get($key);
        
        if ($current === false) {
            // First request
            $this->redis->setex($key, $window, 1);
            return true;
        }
        
        if ($current >= $limit) {
            return false;
        }
        
        $this->redis->incr($key);
        return true;
    }
    
    private function checkRateLimitDatabase($identifier, $limit, $window)
    {
        $windowStart = date('Y-m-d H:i:s', time() - $window);
        
        // Count requests in current window
        $count = Db::getInstance()->getValue('
            SELECT COUNT(*) FROM ' . _DB_PREFIX_ . 'api_rate_limit 
            WHERE identifier = ? AND request_time > ?',
            array($identifier, $windowStart)
        );
        
        if ($count >= $limit) {
            return false;
        }
        
        // Record this request
        Db::getInstance()->insert('api_rate_limit', array(
            'identifier' => pSQL($identifier),
            'request_time' => date('Y-m-d H:i:s'),
            'ip_address' => pSQL(Tools::getRemoteAddr())
        ));
        
        return true;
    }
    
    /**
     * Get rate limit status
     */
    public function getRateLimitStatus($identifier, $limit = null, $window = null)
    {
        $limit = $limit ?: self::DEFAULT_LIMIT;
        $window = $window ?: self::DEFAULT_WINDOW;
        
        if ($this->useRedis) {
            $current = $this->redis->get('rate_limit:' . $identifier) ?: 0;
            $remaining = max(0, $limit - $current);
            $resetTime = time() + $this->redis->ttl('rate_limit:' . $identifier);
        } else {
            $windowStart = date('Y-m-d H:i:s', time() - $window);
            $current = Db::getInstance()->getValue('
                SELECT COUNT(*) FROM ' . _DB_PREFIX_ . 'api_rate_limit 
                WHERE identifier = ? AND request_time > ?',
                array($identifier, $windowStart)
            );
            $remaining = max(0, $limit - $current);
            $resetTime = time() + $window;
        }
        
        return array(
            'limit' => $limit,
            'remaining' => $remaining,
            'reset' => $resetTime,
            'current' => $current
        );
    }
}
```

##### Step 2: Update WebService Dispatcher
```php
// File: /webservice/dispatcher.php

// Add at the beginning of the file
require_once(dirname(__FILE__) . '/../classes/APIRateLimit.php');

class WebserviceDispatcher
{
    private $rateLimit;
    
    public function __construct()
    {
        $this->rateLimit = new APIRateLimit();
    }
    
    public function dispatch()
    {
        try {
            // Get API key and IP for rate limiting
            $apiKey = $this->getAPIKey();
            $ipAddress = Tools::getRemoteAddr();
            $identifier = $apiKey ?: $ipAddress;
            
            // Check rate limit
            if (!$this->rateLimit->checkRateLimit($identifier)) {
                $this->sendRateLimitResponse($identifier);
                return;
            }
            
            // Add rate limit headers
            $this->addRateLimitHeaders($identifier);
            
            // Continue with normal processing
            $this->processRequest();
            
        } catch (Exception $e) {
            $this->sendErrorResponse(500, 'Internal Server Error');
        }
    }
    
    private function getAPIKey()
    {
        // Check various ways API key might be provided
        $apiKey = Tools::getValue('ws_key');
        
        if (!$apiKey && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            // Check Authorization header
            $auth = $_SERVER['HTTP_AUTHORIZATION'];
            if (preg_match('/Basic\s+(.*)$/i', $auth, $matches)) {
                $credentials = base64_decode($matches[1]);
                list($apiKey, ) = explode(':', $credentials, 2);
            }
        }
        
        if (!$apiKey && isset($_SERVER['PHP_AUTH_USER'])) {
            $apiKey = $_SERVER['PHP_AUTH_USER'];
        }
        
        return $apiKey;
    }
    
    private function sendRateLimitResponse($identifier)
    {
        $status = $this->rateLimit->getRateLimitStatus($identifier);
        
        http_response_code(429);
        header('Content-Type: application/json');
        header('X-RateLimit-Limit: ' . $status['limit']);
        header('X-RateLimit-Remaining: ' . $status['remaining']);
        header('X-RateLimit-Reset: ' . $status['reset']);
        header('Retry-After: ' . ($status['reset'] - time()));
        
        echo json_encode(array(
            'error' => 'Rate limit exceeded',
            'message' => 'Too many requests. Please try again later.',
            'limit' => $status['limit'],
            'remaining' => $status['remaining'],
            'reset' => $status['reset']
        ));
        
        exit;
    }
    
    private function addRateLimitHeaders($identifier)
    {
        $status = $this->rateLimit->getRateLimitStatus($identifier);
        
        header('X-RateLimit-Limit: ' . $status['limit']);
        header('X-RateLimit-Remaining: ' . $status['remaining']);
        header('X-RateLimit-Reset: ' . $status['reset']);
    }
}
```

##### Step 3: Create Rate Limit Table
```sql
-- File: /install/sql/api_rate_limit.sql
CREATE TABLE IF NOT EXISTS `ps_api_rate_limit` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `identifier` varchar(255) NOT NULL,
    `request_time` datetime NOT NULL,
    `ip_address` varchar(45) NOT NULL,
    PRIMARY KEY (`id`),
    KEY `identifier_time` (`identifier`, `request_time`),
    KEY `cleanup` (`request_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 4. Hardcoded Database Credentials

**Priority**: ⚠️ Urgent (1-7 days)
**Risk Score**: 4.00
**Estimated Effort**: 6 hours

#### Implementation Steps

##### Step 1: Create Environment Configuration
```php
// File: /config/environment.php

<?php
/**
 * Environment-based configuration loader
 */

class EnvironmentConfig
{
    private static $config = array();
    
    public static function load()
    {
        // Load from environment variables first
        self::loadFromEnvironment();
        
        // Load from .env file if exists
        self::loadFromFile();
        
        // Validate required configuration
        self::validateConfig();
    }
    
    private static function loadFromEnvironment()
    {
        $envVars = array(
            'DB_SERVER' => '_DB_SERVER_',
            'DB_NAME' => '_DB_NAME_',
            'DB_USER' => '_DB_USER_',
            'DB_PASSWD' => '_DB_PASSWD_',
            'DB_PREFIX' => '_DB_PREFIX_',
            'COOKIE_KEY' => '_COOKIE_KEY_',
            'COOKIE_IV' => '_COOKIE_IV_'
        );
        
        foreach ($envVars as $envVar => $constant) {
            $value = getenv($envVar);
            if ($value !== false) {
                self::$config[$constant] = $value;
            }
        }
    }
    
    private static function loadFromFile()
    {
        $envFile = dirname(__FILE__) . '/../.env';
        
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            foreach ($lines as $line) {
                if (strpos($line, '=') !== false && strpos($line, '#') !== 0) {
                    list($key, $value) = explode('=', $line, 2);
                    $key = trim($key);
                    $value = trim($value, '"\'');
                    
                    // Map environment variables to constants
                    $mapping = array(
                        'DB_SERVER' => '_DB_SERVER_',
                        'DB_NAME' => '_DB_NAME_',
                        'DB_USER' => '_DB_USER_',
                        'DB_PASSWD' => '_DB_PASSWD_',
                        'DB_PREFIX' => '_DB_PREFIX_',
                        'COOKIE_KEY' => '_COOKIE_KEY_',
                        'COOKIE_IV' => '_COOKIE_IV_'
                    );
                    
                    if (isset($mapping[$key])) {
                        self::$config[$mapping[$key]] = $value;
                    }
                }
            }
        }
    }
    
    private static function validateConfig()
    {
        $required = array('_DB_SERVER_', '_DB_NAME_', '_DB_USER_', '_DB_PASSWD_');
        
        foreach ($required as $key) {
            if (!isset(self::$config[$key]) || empty(self::$config[$key])) {
                throw new Exception("Required configuration missing: {$key}");
            }
        }
    }
    
    public static function get($key, $default = null)
    {
        return isset(self::$config[$key]) ? self::$config[$key] : $default;
    }
    
    public static function defineConstants()
    {
        foreach (self::$config as $constant => $value) {
            if (!defined($constant)) {
                define($constant, $value);
            }
        }
    }
}
```

##### Step 2: Update Settings Configuration
```php
// File: /config/settings.inc.php

<?php
/**
 * Secure database configuration using environment variables
 */

// Load environment configuration
require_once(dirname(__FILE__) . '/environment.php');

try {
    EnvironmentConfig::load();
    EnvironmentConfig::defineConstants();
} catch (Exception $e) {
    // Fallback to default values for development
    if (!defined('_PS_MODE_DEV_') || !_PS_MODE_DEV_) {
        die('Configuration error: ' . $e->getMessage());
    }
    
    // Development fallback (only if in dev mode)
    if (!defined('_DB_SERVER_')) define('_DB_SERVER_', 'localhost');
    if (!defined('_DB_NAME_')) define('_DB_NAME_', 'qloapps_dev');
    if (!defined('_DB_USER_')) define('_DB_USER_', 'root');
    if (!defined('_DB_PASSWD_')) define('_DB_PASSWD_', '');
}

// Set default values for optional settings
if (!defined('_DB_PREFIX_')) define('_DB_PREFIX_', 'ps_');
if (!defined('_MYSQL_ENGINE_')) define('_MYSQL_ENGINE_', 'InnoDB');
if (!defined('_PS_CACHING_SYSTEM_')) define('_PS_CACHING_SYSTEM_', 'CacheMemcache');
if (!defined('_PS_CACHE_ENABLED_')) define('_PS_CACHE_ENABLED_', '0');

// Generate secure keys if not provided
if (!defined('_COOKIE_KEY_')) {
    define('_COOKIE_KEY_', bin2hex(random_bytes(32)));
}
if (!defined('_COOKIE_IV_')) {
    define('_COOKIE_IV_', bin2hex(random_bytes(16)));
}

// Security: Clear sensitive variables
unset($_ENV['DB_PASSWD']);
unset($_SERVER['DB_PASSWD']);
```

##### Step 3: Create Environment Template
```bash
# File: /.env.example

# Database Configuration
DB_SERVER=localhost
DB_NAME=qloapps_production
DB_USER=qloapps_user
DB_PASSWD=your_secure_password_here
DB_PREFIX=ps_

# Security Keys (generate with: openssl rand -hex 32)
COOKIE_KEY=your_cookie_key_here
COOKIE_IV=your_cookie_iv_here

# Application Settings
PS_MODE_DEV=false
PS_CACHE_ENABLED=true
PS_CACHING_SYSTEM=CacheMemcache

# SSL Configuration
FORCE_SSL=true
SSL_CERT_PATH=/path/to/ssl/cert
SSL_KEY_PATH=/path/to/ssl/key
```

---

## Security Best Practices

### Input Validation and Sanitization

#### Always Validate Input
```php
// Good: Validate all inputs
function processUserInput($data)
{
    // Validate data type
    if (!is_array($data)) {
        throw new InvalidArgumentException('Expected array input');
    }
    
    // Validate required fields
    $required = array('name', 'email', 'phone');
    foreach ($required as $field) {
        if (!isset($data[$field]) || empty($data[$field])) {
            throw new InvalidArgumentException("Required field missing: {$field}");
        }
    }
    
    // Validate formats
    if (!Validate::isName($data['name'])) {
        throw new InvalidArgumentException('Invalid name format');
    }
    
    if (!Validate::isEmail($data['email'])) {
        throw new InvalidArgumentException('Invalid email format');
    }
    
    if (!Validate::isPhoneNumber($data['phone'])) {
        throw new InvalidArgumentException('Invalid phone format');
    }
    
    return $data;
}
```

#### Output Encoding
```php
// Always encode output to prevent XSS
function displayUserData($data)
{
    echo '<h1>' . Tools::safeOutput($data['name']) . '</h1>';
    echo '<p>Email: ' . Tools::safeOutput($data['email']) . '</p>';
    
    // For HTML content, use specific encoding
    echo '<div>' . Tools::purifyHTML($data['description']) . '</div>';
}
```

### Authentication and Session Security

#### Secure Session Management
```php
// File: /classes/SecureSession.php

class SecureSession
{
    public static function start()
    {
        // Secure session configuration
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 1);
        ini_set('session.use_strict_mode', 1);
        ini_set('session.cookie_samesite', 'Strict');
        
        // Regenerate session ID periodically
        if (!isset($_SESSION['last_regeneration'])) {
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        } elseif (time() - $_SESSION['last_regeneration'] > 300) {
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        }
        
        session_start();
    }
    
    public static function destroy()
    {
        $_SESSION = array();
        
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        
        session_destroy();
    }
    
    public static function validateSession()
    {
        // Check session timeout
        if (isset($_SESSION['timeout']) && $_SESSION['timeout'] < time()) {
            self::destroy();
            return false;
        }
        
        // Update timeout
        $_SESSION['timeout'] = time() + 1800; // 30 minutes
        
        // Validate session fingerprint
        $fingerprint = self::generateFingerprint();
        if (!isset($_SESSION['fingerprint']) || $_SESSION['fingerprint'] !== $fingerprint) {
            self::destroy();
            return false;
        }
        
        return true;
    }
    
    private static function generateFingerprint()
    {
        return hash('sha256', 
            $_SERVER['HTTP_USER_AGENT'] . 
            $_SERVER['REMOTE_ADDR'] . 
            _COOKIE_KEY_
        );
    }
}
```

### Cryptography and Data Protection

#### Secure Encryption
```php
// File: /classes/SecureEncryption.php

class SecureEncryption
{
    const CIPHER = 'AES-256-GCM';
    
    public static function encrypt($data, $key = null)
    {
        $key = $key ?: self::getEncryptionKey();
        
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Encryption key must be 32 bytes');
        }
        
        $iv = random_bytes(12); // GCM uses 12-byte IV
        $tag = '';
        
        $encrypted = openssl_encrypt($data, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
        
        if ($encrypted === false) {
            throw new RuntimeException('Encryption failed');
        }
        
        // Return base64 encoded: iv + tag + encrypted_data
        return base64_encode($iv . $tag . $encrypted);
    }
    
    public static function decrypt($encryptedData, $key = null)
    {
        $key = $key ?: self::getEncryptionKey();
        
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Encryption key must be 32 bytes');
        }
        
        $data = base64_decode($encryptedData);
        if ($data === false || strlen($data) < 28) { // 12 + 16 minimum
            throw new InvalidArgumentException('Invalid encrypted data');
        }
        
        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $encrypted = substr($data, 28);
        
        $decrypted = openssl_decrypt($encrypted, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
        
        if ($decrypted === false) {
            throw new RuntimeException('Decryption failed');
        }
        
        return $decrypted;
    }
    
    private static function getEncryptionKey()
    {
        $key = Configuration::get('ENCRYPTION_KEY');
        
        if (!$key) {
            // Generate new key
            $key = random_bytes(32);
            Configuration::updateValue('ENCRYPTION_KEY', base64_encode($key));
        } else {
            $key = base64_decode($key);
        }
        
        return $key;
    }
}
```

---

## Testing Procedures

### Security Testing Framework

#### Unit Tests for Security Functions
```php
// File: /tests/unit/SecurityTest.php

class SecurityTest extends PHPUnit_Framework_TestCase
{
    public function testInputValidation()
    {
        // Test SQL injection prevention
        $maliciousInputs = array(
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "<script>alert('xss')</script>",
            "javascript:alert('xss')"
        );
        
        foreach ($maliciousInputs as $input) {
            $this->assertFalse(Validate::isGenericName($input));
        }
    }
    
    public function testPasswordHashing()
    {
        $password = 'TestPassword123!';
        $hash = password_hash($password, PASSWORD_DEFAULT);
        
        $this->assertTrue(password_verify($password, $hash));
        $this->assertFalse(password_verify('WrongPassword', $hash));
    }
    
    public function testEncryption()
    {
        $data = 'Sensitive information';
        $encrypted = SecureEncryption::encrypt($data);
        $decrypted = SecureEncryption::decrypt($encrypted);
        
        $this->assertEquals($data, $decrypted);
        $this->assertNotEquals($data, $encrypted);
    }
    
    public function testRateLimiting()
    {
        $rateLimit = new APIRateLimit();
        $identifier = 'test_user';
        
        // Should allow first request
        $this->assertTrue($rateLimit->checkRateLimit($identifier, 5, 60));
        
        // Should block after limit exceeded
        for ($i = 0; $i < 5; $i++) {
            $rateLimit->checkRateLimit($identifier, 5, 60);
        }
        
        $this->assertFalse($rateLimit->checkRateLimit($identifier, 5, 60));
    }
}
```

#### Integration Tests
```php
// File: /tests/integration/SecurityIntegrationTest.php

class SecurityIntegrationTest extends PHPUnit_Framework_TestCase
{
    public function testAuthenticationFlow()
    {
        // Test complete authentication process
        $customer = new Customer();
        $email = 'test@example.com';
        $password = 'SecurePassword123!';
        
        // Create test customer
        $customer->email = $email;
        $customer->passwd = password_hash($password, PASSWORD_DEFAULT);
        $customer->save();
        
        // Test login
        $auth = $customer->getByEmail($email, $password);
        $this->assertNotFalse($auth);
        
        // Test wrong password
        $auth = $customer->getByEmail($email, 'WrongPassword');
        $this->assertFalse($auth);
        
        // Cleanup
        $customer->delete();
    }
    
    public function testAPIRateLimit()
    {
        // Test API rate limiting
        $apiKey = 'test_api_key';
        
        // Make requests up to limit
        for ($i = 0; $i < 100; $i++) {
            $response = $this->makeAPIRequest('/api/test', $apiKey);
            $this->assertEquals(200, $response['status']);
        }
        
        // Next request should be rate limited
        $response = $this->makeAPIRequest('/api/test', $apiKey);
        $this->assertEquals(429, $response['status']);
    }
    
    private function makeAPIRequest($endpoint, $apiKey)
    {
        // Simulate API request
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'http://localhost' . $endpoint);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Authorization: Bearer ' . $apiKey));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return array('status' => $status, 'body' => $response);
    }
}
```

### Automated Security Testing

#### Security Scan Script
```php
// File: /tools/security_scan.php

<?php
/**
 * Automated security scanning tool
 */

class SecurityScanner
{
    private $findings = array();
    
    public function runFullScan()
    {
        echo "Starting security scan...\n";
        
        $this->scanSQLInjection();
        $this->scanXSS();
        $this->scanFilePermissions();
        $this->scanConfigurationSecurity();
        $this->scanPasswordPolicies();
        
        $this->generateReport();
    }
    
    private function scanSQLInjection()
    {
        echo "Scanning for SQL injection vulnerabilities...\n";
        
        $files = $this->getPhpFiles();
        
        foreach ($files as $file) {
            $content = file_get_contents($file);
            
            // Look for dangerous patterns
            $patterns = array(
                '/\$_GET\[.*?\].*?mysql_query/',
                '/\$_POST\[.*?\].*?mysql_query/',
                '/\$_REQUEST\[.*?\].*?mysql_query/',
                '/mysql_query.*?\$_/',
                '/query.*?\$_.*?[\'"]/'
            );
            
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $this->findings[] = array(
                        'type' => 'SQL Injection Risk',
                        'file' => $file,
                        'severity' => 'High',
                        'description' => 'Potential SQL injection vulnerability detected'
                    );
                }
            }
        }
    }
    
    private function scanXSS()
    {
        echo "Scanning for XSS vulnerabilities...\n";
        
        $files = $this->getPhpFiles();
        
        foreach ($files as $file) {
            $content = file_get_contents($file);
            
            // Look for unescaped output
            $patterns = array(
                '/echo\s+\$_GET/',
                '/echo\s+\$_POST/',
                '/print\s+\$_GET/',
                '/print\s+\$_POST/',
                '/\?>\s*<.*?\$_/'
            );
            
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $this->findings[] = array(
                        'type' => 'XSS Risk',
                        'file' => $file,
                        'severity' => 'Medium',
                        'description' => 'Potential XSS vulnerability detected'
                    );
                }
            }
        }
    }
    
    private function scanFilePermissions()
    {
        echo "Scanning file permissions...\n";
        
        $sensitiveFiles = array(
            '/config/settings.inc.php',
            '/.env',
            '/admin/init.php'
        );
        
        foreach ($sensitiveFiles as $file) {
            if (file_exists($file)) {
                $perms = fileperms($file) & 0777;
                
                if ($perms & 0004) { // World readable
                    $this->findings[] = array(
                        'type' => 'File Permission',
                        'file' => $file,
                        'severity' => 'High',
                        'description' => 'Sensitive file is world-readable'
                    );
                }
            }
        }
    }
    
    private function generateReport()
    {
        echo "\n=== Security Scan Report ===\n";
        echo "Total findings: " . count($this->findings) . "\n\n";
        
        $severityCounts = array('High' => 0, 'Medium' => 0, 'Low' => 0);
        
        foreach ($this->findings as $finding) {
            $severityCounts[$finding['severity']]++;
            
            echo "[{$finding['severity']}] {$finding['type']}\n";
            echo "File: {$finding['file']}\n";
            echo "Description: {$finding['description']}\n\n";
        }
        
        echo "Summary:\n";
        foreach ($severityCounts as $severity => $count) {
            echo "- {$severity}: {$count}\n";
        }
    }
    
    private function getPhpFiles()
    {
        $files = array();
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator('.')
        );
        
        foreach ($iterator as $file) {
            if ($file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        
        return $files;
    }
}

// Run scan if called directly
if (php_sapi_name() === 'cli') {
    $scanner = new SecurityScanner();
    $scanner->runFullScan();
}
```

---

## Code Review Guidelines

### Security-Focused Code Review Checklist

#### Authentication and Authorization
- [ ] All authentication functions use secure password hashing
- [ ] Session management follows security best practices
- [ ] Access controls are properly implemented
- [ ] Rate limiting is in place for authentication endpoints
- [ ] Failed login attempts are logged and monitored

#### Input Validation
- [ ] All user inputs are validated and sanitized
- [ ] SQL queries use prepared statements
- [ ] File uploads are properly validated
- [ ] Output is properly encoded to prevent XSS
- [ ] CSRF tokens are used for state-changing operations

#### Data Protection
- [ ] Sensitive data is encrypted at rest
- [ ] Secure communication protocols are used
- [ ] PII is handled according to privacy regulations
- [ ] Payment data follows PCI DSS requirements
- [ ] Audit logs are maintained for sensitive operations

#### Configuration Security
- [ ] No hardcoded credentials in source code
- [ ] Environment variables are used for sensitive configuration
- [ ] Security headers are properly configured
- [ ] Error messages don't leak sensitive information
- [ ] Debug mode is disabled in production

### Review Process

#### Pre-Review Checklist
1. **Automated Security Scan**: Run security scanner on changed files
2. **Unit Tests**: Ensure all security-related tests pass
3. **Static Analysis**: Use tools like PHPStan or Psalm
4. **Dependency Check**: Verify no known vulnerabilities in dependencies

#### Review Steps
1. **Understand the Change**: What is the purpose and scope?
2. **Identify Security Impact**: What security boundaries are crossed?
3. **Validate Input Handling**: How is user input processed?
4. **Check Output Encoding**: How is data displayed to users?
5. **Review Error Handling**: What happens when things go wrong?
6. **Verify Access Controls**: Who can access this functionality?

---

## Deployment Guidelines

### Pre-Deployment Security Checklist

#### Environment Preparation
- [ ] Production environment is properly hardened
- [ ] SSL/TLS certificates are installed and configured
- [ ] Database credentials are stored securely
- [ ] File permissions are set correctly
- [ ] Security headers are configured
- [ ] Monitoring and logging are enabled

#### Code Deployment
- [ ] All security fixes have been tested
- [ ] Database migrations include security improvements
- [ ] Configuration files are updated with secure settings
- [ ] Sensitive files are excluded from deployment
- [ ] Backup procedures are in place

#### Post-Deployment Verification
- [ ] Security scan passes on production environment
- [ ] Authentication and authorization work correctly
- [ ] Rate limiting is functioning
- [ ] SSL/TLS configuration is correct
- [ ] Monitoring alerts are working
- [ ] Incident response procedures are ready

### Rollback Procedures

#### Emergency Rollback
If critical security issues are discovered:

1. **Immediate Actions**
   - Take affected systems offline if necessary
   - Notify security team and stakeholders
   - Document the issue and timeline

2. **Rollback Process**
   - Revert to previous known-good version
   - Restore database if necessary
   - Verify system functionality
   - Monitor for continued issues

3. **Post-Rollback**
   - Analyze root cause
   - Develop proper fix
   - Test thoroughly before re-deployment
   - Update procedures to prevent recurrence

### Monitoring and Maintenance

#### Security Monitoring
- **Log Analysis**: Monitor for suspicious activities
- **Performance Monitoring**: Watch for DoS attacks
- **Vulnerability Scanning**: Regular automated scans
- **Penetration Testing**: Periodic professional assessments

#### Ongoing Maintenance
- **Security Updates**: Keep all components updated
- **Certificate Renewal**: Monitor SSL certificate expiration
- **Access Review**: Regular review of user permissions
- **Backup Testing**: Verify backup and restore procedures

---

This comprehensive implementation guide provides detailed code examples, security best practices, and testing procedures for addressing all identified security vulnerabilities in QloApps. Each section includes specific implementation steps, code examples, and verification procedures to ensure proper remediation of security issues.