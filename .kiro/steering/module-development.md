# QloApps Module Development Guide

## Module Development Overview

QloApps modules extend core functionality using a standardized architecture. Modules can add new features, modify existing behavior, integrate with external services, and customize the hotel management system.

## Module Architecture

### Core Module Class
Every module must extend the base `Module` class:

```php
<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

class HotelBookingModule extends Module
{
    public function __construct()
    {
        $this->name = 'hotelbookingmodule';
        $this->tab = 'hotel_management';
        $this->version = '1.0.0';
        $this->author = 'Your Name';
        $this->need_instance = 0;
        $this->ps_versions_compliancy = array('min' => '1.6', 'max' => _PS_VERSION_);
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->l('Hotel Booking Module');
        $this->description = $this->l('Advanced hotel booking management system');
        $this->confirmUninstall = $this->l('Are you sure you want to uninstall?');

        if (!Configuration::get('HOTEL_BOOKING_ENABLED')) {
            $this->warning = $this->l('No name provided');
        }
    }
}
```

### Module Configuration
Define module metadata in `config.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<module>
    <name>hotelbookingmodule</name>
    <displayName><![CDATA[Hotel Booking Module]]></displayName>
    <version><![CDATA[1.0.0]]></version>
    <description><![CDATA[Advanced hotel booking management]]></description>
    <author><![CDATA[Your Name]]></author>
    <tab><![CDATA[hotel_management]]></tab>
    <confirmUninstall><![CDATA[Are you sure?]]></confirmUninstall>
    <is_configurable>1</is_configurable>
    <need_instance>0</need_instance>
    <limited_countries></limited_countries>
</module>
```

## Hotel-Specific Module Types

### 1. Booking Management Modules
Handle reservation lifecycle, availability, and guest management.

**Example: Advanced Booking Module**
```php
class AdvancedBooking extends Module
{
    public function install()
    {
        return parent::install() &&
            $this->registerHook('displayHeader') &&
            $this->registerHook('actionBookingCreate') &&
            $this->registerHook('actionBookingUpdate') &&
            $this->createTables() &&
            $this->installConfiguration();
    }

    public function hookActionBookingCreate($params)
    {
        // Handle new booking creation
        $booking = $params['booking'];
        $this->processBookingNotifications($booking);
        $this->updateRoomAvailability($booking);
    }

    private function createTables()
    {
        $sql = 'CREATE TABLE IF NOT EXISTS `'._DB_PREFIX_.'htl_advanced_booking` (
            `id_booking` int(11) NOT NULL AUTO_INCREMENT,
            `id_customer` int(11) NOT NULL,
            `id_hotel` int(11) NOT NULL,
            `booking_reference` varchar(32) NOT NULL,
            `special_requests` text,
            `created_at` datetime NOT NULL,
            PRIMARY KEY (`id_booking`)
        ) ENGINE='._MYSQL_ENGINE_.' DEFAULT CHARSET=utf8;';
        
        return Db::getInstance()->execute($sql);
    }
}
```

### 2. Room Management Modules
Manage room types, features, pricing, and inventory.

**Example: Room Features Module**
```php
class RoomFeatures extends Module
{
    public function install()
    {
        return parent::install() &&
            $this->registerHook('displayRoomDetails') &&
            $this->registerHook('actionRoomTypeUpdate') &&
            $this->createFeatureTables();
    }

    public function hookDisplayRoomDetails($params)
    {
        $room_type_id = $params['room_type_id'];
        $features = $this->getRoomFeatures($room_type_id);
        
        $this->context->smarty->assign(array(
            'room_features' => $features,
            'feature_icons' => $this->getFeatureIcons()
        ));
        
        return $this->display(__FILE__, 'room_features.tpl');
    }

    private function getRoomFeatures($room_type_id)
    {
        $sql = 'SELECT rf.*, rfl.name, rfl.description 
                FROM '._DB_PREFIX_.'htl_room_features rf
                LEFT JOIN '._DB_PREFIX_.'htl_room_features_lang rfl 
                ON rf.id_feature = rfl.id_feature
                WHERE rf.id_room_type = '.(int)$room_type_id.'
                AND rfl.id_lang = '.(int)$this->context->language->id;
        
        return Db::getInstance()->executeS($sql);
    }
}
```

### 3. Payment Integration Modules
Handle payment processing and gateway integrations.

**Example: Payment Gateway Module**
```php
class HotelPaymentGateway extends PaymentModule
{
    public function __construct()
    {
        $this->name = 'hotelpaymentgateway';
        $this->tab = 'payments_gateways';
        $this->version = '1.0.0';
        $this->author = 'Your Name';
        $this->currencies = true;
        $this->currencies_mode = 'checkbox';

        parent::__construct();

        $this->displayName = $this->l('Hotel Payment Gateway');
        $this->description = $this->l('Secure payment processing for hotel bookings');
    }

    public function hookPayment($params)
    {
        if (!$this->active) {
            return;
        }

        $this->context->smarty->assign(array(
            'this_path' => $this->_path,
            'this_path_ssl' => Tools::getShopDomainSsl(true, true).__PS_BASE_URI__.'modules/'.$this->name.'/'
        ));

        return $this->display(__FILE__, 'payment.tpl');
    }

    public function hookPaymentReturn($params)
    {
        if (!$this->active) {
            return;
        }

        return $this->display(__FILE__, 'payment_return.tpl');
    }
}
```

## ObjectModel Classes

### Hotel-Specific Models
Create models for hotel entities using ObjectModel pattern:

```php
class HtlBookingDetail extends ObjectModel
{
    public $id_customer;
    public $id_hotel;
    public $id_room;
    public $booking_date;
    public $check_in;
    public $check_out;
    public $adults;
    public $children;
    public $total_price;
    public $booking_status;

    public static $definition = array(
        'table' => 'htl_booking_detail',
        'primary' => 'id',
        'multilang' => false,
        'fields' => array(
            'id_customer' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedId',
                'required' => true
            ),
            'id_hotel' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedId',
                'required' => true
            ),
            'id_room' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedId',
                'required' => true
            ),
            'booking_date' => array(
                'type' => self::TYPE_DATE,
                'validate' => 'isDate',
                'required' => true
            ),
            'check_in' => array(
                'type' => self::TYPE_DATE,
                'validate' => 'isDate',
                'required' => true
            ),
            'check_out' => array(
                'type' => self::TYPE_DATE,
                'validate' => 'isDate',
                'required' => true
            ),
            'adults' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt',
                'required' => true
            ),
            'children' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt'
            ),
            'total_price' => array(
                'type' => self::TYPE_FLOAT,
                'validate' => 'isPrice',
                'required' => true
            ),
            'booking_status' => array(
                'type' => self::TYPE_STRING,
                'validate' => 'isGenericName',
                'size' => 32
            )
        )
    );

    public function getCustomer()
    {
        return new Customer($this->id_customer);
    }

    public function getHotel()
    {
        return new HtlBranchInfo($this->id_hotel);
    }

    public function getRoom()
    {
        return new HtlRoomInformation($this->id_room);
    }

    public static function getBookingsByCustomer($id_customer)
    {
        $sql = 'SELECT * FROM '._DB_PREFIX_.'htl_booking_detail 
                WHERE id_customer = '.(int)$id_customer.'
                ORDER BY booking_date DESC';
        
        return Db::getInstance()->executeS($sql);
    }
}
```

### Multilingual Models
For content requiring multiple languages:

```php
class HtlRoomType extends ObjectModel
{
    public $name;
    public $description;
    public $short_description;
    public $base_price;
    public $max_adults;
    public $max_children;
    public $active;

    public static $definition = array(
        'table' => 'htl_room_type',
        'primary' => 'id_room_type',
        'multilang' => true,
        'fields' => array(
            'base_price' => array(
                'type' => self::TYPE_FLOAT,
                'validate' => 'isPrice',
                'required' => true
            ),
            'max_adults' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt',
                'required' => true
            ),
            'max_children' => array(
                'type' => self::TYPE_INT,
                'validate' => 'isUnsignedInt'
            ),
            'active' => array(
                'type' => self::TYPE_BOOL,
                'validate' => 'isBool'
            ),
            // Multilingual fields
            'name' => array(
                'type' => self::TYPE_STRING,
                'lang' => true,
                'validate' => 'isGenericName',
                'required' => true,
                'size' => 128
            ),
            'description' => array(
                'type' => self::TYPE_HTML,
                'lang' => true,
                'validate' => 'isCleanHtml'
            ),
            'short_description' => array(
                'type' => self::TYPE_STRING,
                'lang' => true,
                'validate' => 'isGenericName',
                'size' => 255
            )
        )
    );
}
```

## Admin Controllers

### Hotel Admin Controllers
Create admin interfaces for hotel management:

```php
class AdminHotelBookingsController extends ModuleAdminController
{
    public function __construct()
    {
        $this->table = 'htl_booking_detail';
        $this->className = 'HtlBookingDetail';
        $this->identifier = 'id';
        $this->bootstrap = true;

        parent::__construct();

        $this->fields_list = array(
            'id' => array(
                'title' => $this->l('ID'),
                'align' => 'center',
                'class' => 'fixed-width-xs'
            ),
            'booking_reference' => array(
                'title' => $this->l('Reference'),
                'width' => 'auto'
            ),
            'customer_name' => array(
                'title' => $this->l('Customer'),
                'width' => 'auto',
                'callback' => 'getCustomerName'
            ),
            'hotel_name' => array(
                'title' => $this->l('Hotel'),
                'width' => 'auto',
                'callback' => 'getHotelName'
            ),
            'check_in' => array(
                'title' => $this->l('Check-in'),
                'type' => 'date',
                'width' => 'auto'
            ),
            'check_out' => array(
                'title' => $this->l('Check-out'),
                'type' => 'date',
                'width' => 'auto'
            ),
            'total_price' => array(
                'title' => $this->l('Total'),
                'type' => 'price',
                'currency' => true,
                'width' => 'auto'
            ),
            'booking_status' => array(
                'title' => $this->l('Status'),
                'width' => 'auto',
                'callback' => 'getBookingStatus'
            )
        );

        $this->addRowAction('edit');
        $this->addRowAction('delete');
        $this->addRowAction('view');
    }

    public function getCustomerName($value, $row)
    {
        $customer = new Customer($row['id_customer']);
        return $customer->firstname.' '.$customer->lastname;
    }

    public function getHotelName($value, $row)
    {
        $hotel = new HtlBranchInfo($row['id_hotel']);
        return $hotel->hotel_name;
    }

    public function getBookingStatus($value, $row)
    {
        $statuses = array(
            'pending' => '<span class="badge badge-warning">Pending</span>',
            'confirmed' => '<span class="badge badge-success">Confirmed</span>',
            'cancelled' => '<span class="badge badge-danger">Cancelled</span>'
        );
        
        return isset($statuses[$value]) ? $statuses[$value] : $value;
    }

    public function renderForm()
    {
        $this->fields_form = array(
            'legend' => array(
                'title' => $this->l('Booking Details'),
                'icon' => 'icon-calendar'
            ),
            'input' => array(
                array(
                    'type' => 'select',
                    'label' => $this->l('Customer'),
                    'name' => 'id_customer',
                    'required' => true,
                    'options' => array(
                        'query' => Customer::getCustomers(),
                        'id' => 'id_customer',
                        'name' => 'firstname'
                    )
                ),
                array(
                    'type' => 'select',
                    'label' => $this->l('Hotel'),
                    'name' => 'id_hotel',
                    'required' => true,
                    'options' => array(
                        'query' => HtlBranchInfo::getHotels(),
                        'id' => 'id',
                        'name' => 'hotel_name'
                    )
                ),
                array(
                    'type' => 'date',
                    'label' => $this->l('Check-in Date'),
                    'name' => 'check_in',
                    'required' => true
                ),
                array(
                    'type' => 'date',
                    'label' => $this->l('Check-out Date'),
                    'name' => 'check_out',
                    'required' => true
                ),
                array(
                    'type' => 'text',
                    'label' => $this->l('Adults'),
                    'name' => 'adults',
                    'required' => true,
                    'class' => 'fixed-width-sm'
                ),
                array(
                    'type' => 'text',
                    'label' => $this->l('Children'),
                    'name' => 'children',
                    'class' => 'fixed-width-sm'
                ),
                array(
                    'type' => 'select',
                    'label' => $this->l('Status'),
                    'name' => 'booking_status',
                    'options' => array(
                        'query' => array(
                            array('id' => 'pending', 'name' => 'Pending'),
                            array('id' => 'confirmed', 'name' => 'Confirmed'),
                            array('id' => 'cancelled', 'name' => 'Cancelled')
                        ),
                        'id' => 'id',
                        'name' => 'name'
                    )
                )
            ),
            'submit' => array(
                'title' => $this->l('Save'),
                'class' => 'btn btn-default pull-right'
            )
        );

        return parent::renderForm();
    }
}
```

## Frontend Controllers

### Hotel Frontend Controllers
Handle customer-facing functionality:

```php
class HotelSearchModuleFrontController extends ModuleFrontController
{
    public function initContent()
    {
        parent::initContent();

        $search_params = array(
            'hotel_id' => Tools::getValue('hotel_id'),
            'check_in' => Tools::getValue('check_in'),
            'check_out' => Tools::getValue('check_out'),
            'adults' => Tools::getValue('adults', 1),
            'children' => Tools::getValue('children', 0)
        );

        if (Tools::isSubmit('search_rooms')) {
            $available_rooms = $this->searchAvailableRooms($search_params);
            
            $this->context->smarty->assign(array(
                'available_rooms' => $available_rooms,
                'search_params' => $search_params,
                'hotels' => HtlBranchInfo::getActiveHotels()
            ));
        }

        $this->context->smarty->assign(array(
            'search_params' => $search_params,
            'hotels' => HtlBranchInfo::getActiveHotels()
        ));

        $this->setTemplate('search.tpl');
    }

    private function searchAvailableRooms($params)
    {
        $sql = 'SELECT rt.*, rtl.name, rtl.description, ri.room_number
                FROM '._DB_PREFIX_.'htl_room_type rt
                LEFT JOIN '._DB_PREFIX_.'htl_room_type_lang rtl 
                ON rt.id_room_type = rtl.id_room_type
                LEFT JOIN '._DB_PREFIX_.'htl_room_information ri 
                ON rt.id_room_type = ri.id_room_type
                WHERE rt.active = 1
                AND ri.id_hotel = '.(int)$params['hotel_id'].'
                AND ri.id NOT IN (
                    SELECT bd.id_room 
                    FROM '._DB_PREFIX_.'htl_booking_detail bd
                    WHERE bd.check_in < "'.pSQL($params['check_out']).'"
                    AND bd.check_out > "'.pSQL($params['check_in']).'"
                )
                AND rtl.id_lang = '.(int)$this->context->language->id.'
                GROUP BY rt.id_room_type';

        return Db::getInstance()->executeS($sql);
    }
}
```

## Hook System

### Common Hotel Hooks
Register and implement hooks for hotel functionality:

```php
public function install()
{
    return parent::install() &&
        // Header hooks
        $this->registerHook('displayHeader') &&
        $this->registerHook('displayTop') &&
        
        // Booking hooks
        $this->registerHook('actionBookingCreate') &&
        $this->registerHook('actionBookingUpdate') &&
        $this->registerHook('actionBookingCancel') &&
        
        // Room hooks
        $this->registerHook('displayRoomDetails') &&
        $this->registerHook('actionRoomUpdate') &&
        
        // Customer hooks
        $this->registerHook('actionCustomerAccountAdd') &&
        $this->registerHook('displayCustomerAccount') &&
        
        // Payment hooks
        $this->registerHook('displayPayment') &&
        $this->registerHook('displayPaymentReturn') &&
        
        // Admin hooks
        $this->registerHook('displayAdminOrder') &&
        $this->registerHook('actionAdminBookingListingFieldsModifier');
}

public function hookActionBookingCreate($params)
{
    $booking = $params['booking'];
    
    // Send confirmation email
    $this->sendBookingConfirmation($booking);
    
    // Update room availability
    $this->updateRoomStatus($booking->id_room, 'booked');
    
    // Log booking activity
    $this->logBookingActivity($booking, 'created');
}

public function hookDisplayRoomDetails($params)
{
    $room_type = $params['room_type'];
    
    $this->context->smarty->assign(array(
        'room_amenities' => $this->getRoomAmenities($room_type->id),
        'room_images' => $this->getRoomImages($room_type->id),
        'booking_form' => $this->generateBookingForm($room_type->id)
    ));
    
    return $this->display(__FILE__, 'room_details_extra.tpl');
}
```

## Module Configuration

### Configuration Interface
Create admin configuration forms:

```php
public function getContent()
{
    $output = null;

    if (Tools::isSubmit('submit'.$this->name)) {
        $booking_enabled = strval(Tools::getValue('BOOKING_ENABLED'));
        $email_notifications = strval(Tools::getValue('EMAIL_NOTIFICATIONS'));
        $auto_confirm = strval(Tools::getValue('AUTO_CONFIRM_BOOKINGS'));

        if (!$booking_enabled || empty($booking_enabled) || !Validate::isBool($booking_enabled)) {
            $output .= $this->displayError($this->l('Invalid Configuration value'));
        } else {
            Configuration::updateValue('BOOKING_ENABLED', $booking_enabled);
            Configuration::updateValue('EMAIL_NOTIFICATIONS', $email_notifications);
            Configuration::updateValue('AUTO_CONFIRM_BOOKINGS', $auto_confirm);
            $output .= $this->displayConfirmation($this->l('Settings updated'));
        }
    }

    return $output.$this->displayForm();
}

public function displayForm()
{
    $default_lang = (int)Configuration::get('PS_LANG_DEFAULT');

    $fields_form[0]['form'] = array(
        'legend' => array(
            'title' => $this->l('Settings'),
        ),
        'input' => array(
            array(
                'type' => 'switch',
                'label' => $this->l('Enable Booking System'),
                'name' => 'BOOKING_ENABLED',
                'is_bool' => true,
                'desc' => $this->l('Enable or disable the booking system'),
                'values' => array(
                    array(
                        'id' => 'active_on',
                        'value' => true,
                        'label' => $this->l('Enabled')
                    ),
                    array(
                        'id' => 'active_off',
                        'value' => false,
                        'label' => $this->l('Disabled')
                    )
                ),
            ),
            array(
                'type' => 'switch',
                'label' => $this->l('Email Notifications'),
                'name' => 'EMAIL_NOTIFICATIONS',
                'is_bool' => true,
                'values' => array(
                    array(
                        'id' => 'email_on',
                        'value' => true,
                        'label' => $this->l('Enabled')
                    ),
                    array(
                        'id' => 'email_off',
                        'value' => false,
                        'label' => $this->l('Disabled')
                    )
                ),
            )
        ),
        'submit' => array(
            'title' => $this->l('Save'),
            'class' => 'btn btn-default pull-right'
        )
    );

    $helper = new HelperForm();
    $helper->module = $this;
    $helper->name_controller = $this->name;
    $helper->token = Tools::getAdminTokenLite('AdminModules');
    $helper->currentIndex = AdminController::$currentIndex.'&configure='.$this->name;

    $helper->default_form_language = $default_lang;
    $helper->allow_employee_form_lang = $default_lang;

    $helper->title = $this->displayName;
    $helper->show_toolbar = true;
    $helper->toolbar_scroll = true;
    $helper->submit_action = 'submit'.$this->name;
    $helper->toolbar_btn = array(
        'save' => array(
            'desc' => $this->l('Save'),
            'href' => AdminController::$currentIndex.'&configure='.$this->name.'&save'.$this->name.
            '&token='.Tools::getAdminTokenLite('AdminModules'),
        ),
        'back' => array(
            'href' => AdminController::$currentIndex.'&token='.Tools::getAdminTokenLite('AdminModules'),
            'desc' => $this->l('Back to list')
        )
    );

    $helper->fields_value['BOOKING_ENABLED'] = Configuration::get('BOOKING_ENABLED');
    $helper->fields_value['EMAIL_NOTIFICATIONS'] = Configuration::get('EMAIL_NOTIFICATIONS');

    return $helper->generateForm($fields_form);
}
```

## Database Management

### Installation Scripts
Create database tables during module installation:

```php
private function installTables()
{
    $sql = array();

    $sql[] = 'CREATE TABLE IF NOT EXISTS `'._DB_PREFIX_.'htl_booking_extra` (
        `id_booking_extra` int(11) NOT NULL AUTO_INCREMENT,
        `id_booking` int(11) NOT NULL,
        `extra_service` varchar(255) NOT NULL,
        `extra_price` decimal(10,2) NOT NULL,
        `quantity` int(11) DEFAULT 1,
        `date_add` datetime NOT NULL,
        PRIMARY KEY (`id_booking_extra`),
        KEY `id_booking` (`id_booking`)
    ) ENGINE='._MYSQL_ENGINE_.' DEFAULT CHARSET=utf8;';

    $sql[] = 'CREATE TABLE IF NOT EXISTS `'._DB_PREFIX_.'htl_room_amenities` (
        `id_amenity` int(11) NOT NULL AUTO_INCREMENT,
        `id_room_type` int(11) NOT NULL,
        `amenity_name` varchar(255) NOT NULL,
        `amenity_icon` varchar(255),
        `active` tinyint(1) DEFAULT 1,
        PRIMARY KEY (`id_amenity`),
        KEY `id_room_type` (`id_room_type`)
    ) ENGINE='._MYSQL_ENGINE_.' DEFAULT CHARSET=utf8;';

    foreach ($sql as $query) {
        if (Db::getInstance()->execute($query) == false) {
            return false;
        }
    }

    return true;
}

private function uninstallTables()
{
    $sql = array();
    $sql[] = 'DROP TABLE IF EXISTS `'._DB_PREFIX_.'htl_booking_extra`';
    $sql[] = 'DROP TABLE IF EXISTS `'._DB_PREFIX_.'htl_room_amenities`';

    foreach ($sql as $query) {
        if (Db::getInstance()->execute($query) == false) {
            return false;
        }
    }

    return true;
}
```

## Testing and Debugging

### Module Testing
Implement comprehensive testing for hotel modules:

```php
public function runTests()
{
    $tests = array();
    
    // Test booking creation
    $tests['booking_creation'] = $this->testBookingCreation();
    
    // Test room availability
    $tests['room_availability'] = $this->testRoomAvailability();
    
    // Test price calculation
    $tests['price_calculation'] = $this->testPriceCalculation();
    
    return $tests;
}

private function testBookingCreation()
{
    try {
        $booking = new HtlBookingDetail();
        $booking->id_customer = 1;
        $booking->id_hotel = 1;
        $booking->id_room = 1;
        $booking->check_in = date('Y-m-d', strtotime('+1 day'));
        $booking->check_out = date('Y-m-d', strtotime('+3 days'));
        $booking->adults = 2;
        $booking->children = 0;
        $booking->total_price = 200.00;
        $booking->booking_status = 'confirmed';
        
        return $booking->save();
    } catch (Exception $e) {
        return false;
    }
}
```

## Best Practices

### Security Guidelines
- Always validate and sanitize input data
- Use prepared statements for database queries
- Implement proper access controls
- Validate file uploads and restrict file types
- Use CSRF tokens for forms

### Performance Optimization
- Cache frequently accessed data
- Optimize database queries
- Use lazy loading for large datasets
- Minimize HTTP requests
- Compress and optimize assets

### Code Quality
- Follow PSR coding standards
- Use meaningful variable and function names
- Comment complex logic
- Implement error handling
- Write unit tests for critical functionality

This comprehensive guide provides the foundation for developing robust, secure, and maintainable QloApps modules for hotel management systems.