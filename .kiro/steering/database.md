# QloApps Database Architecture

## Database Overview

QloApps uses MySQL/MariaDB with a modified PrestaShop schema adapted for hotel management. The database follows a normalized structure with proper relationships and multilingual support.

## Table Naming Conventions

### Prefix System
- All tables use `ps_` prefix (PrestaShop legacy)
- Hotel-specific tables often include `htl_` in the name
- Example: `ps_htl_booking_detail`, `ps_htl_room_information`

### Naming Rules
- Tables: lowercase with underscores (`ps_table_name`)
- Columns: lowercase with underscores (`column_name`)
- Foreign keys: `id_[referenced_table]` format
- Primary keys: `id_[table_name]` or simply `id`

## Core Hotel Tables

### Booking Management
- `ps_htl_booking_detail` - Main booking information
- `ps_htl_booking_demands` - Additional booking requests
- `ps_orders` - Order information (inherited from PrestaShop)
- `ps_order_detail` - Order line items

### Room Management
- `ps_htl_room_information` - Individual room data
- `ps_htl_room_type` - Room type configurations
- `ps_product` - Room types as products
- `ps_htl_room_status` - Room availability status

### Hotel Properties
- `ps_htl_branch_info` - Hotel/property information
- `ps_htl_branch_features` - Hotel amenities and features
- `ps_htl_room_type_feature_pricing` - Feature pricing

## Multilingual Support

### Language Tables
- `ps_lang` - Available languages
- `ps_[table]_lang` - Localized content for each table
- Example: `ps_product_lang` for room type names/descriptions

### Multilingual Pattern
```sql
-- Main table
CREATE TABLE ps_product (
    id_product INT PRIMARY KEY,
    price DECIMAL(10,2),
    active TINYINT(1)
);

-- Language-specific content
CREATE TABLE ps_product_lang (
    id_product INT,
    id_lang INT,
    name VARCHAR(255),
    description TEXT,
    PRIMARY KEY (id_product, id_lang)
);
```

## Key Relationships

### Customer-Booking Relationship
```
ps_customer (1) -> (N) ps_orders -> (1) ps_htl_booking_detail
```

### Room-Booking Relationship
```
ps_htl_room_information (1) -> (N) ps_htl_booking_detail
ps_product (room_type) (1) -> (N) ps_htl_room_information
```

### Hotel-Room Relationship
```
ps_htl_branch_info (1) -> (N) ps_htl_room_information
```##
 ObjectModel Pattern

### Base Class Usage
All entities extend `ObjectModel` class which provides:
- Database abstraction
- Validation rules
- Multilingual field handling
- CRUD operations

### Example ObjectModel Implementation
```php
class HotelBooking extends ObjectModel
{
    public $id_customer;
    public $id_hotel;
    public $booking_date;
    public $check_in;
    public $check_out;
    
    public static $definition = array(
        'table' => 'htl_booking_detail',
        'primary' => 'id',
        'multilang' => false,
        'fields' => array(
            'id_customer' => array('type' => self::TYPE_INT, 'validate' => 'isUnsignedId', 'required' => true),
            'id_hotel' => array('type' => self::TYPE_INT, 'validate' => 'isUnsignedId', 'required' => true),
            'booking_date' => array('type' => self::TYPE_DATE, 'validate' => 'isDate'),
            'check_in' => array('type' => self::TYPE_DATE, 'validate' => 'isDate', 'required' => true),
            'check_out' => array('type' => self::TYPE_DATE, 'validate' => 'isDate', 'required' => true),
        ),
    );
}
```

## Database Configuration

### Connection Settings
Configuration in `/config/settings.inc.php`:
```php
define('_DB_SERVER_', 'localhost');
define('_DB_NAME_', 'qloapps_db');
define('_DB_USER_', 'username');
define('_DB_PASSWD_', 'password');
define('_DB_PREFIX_', 'ps_');
define('_MYSQL_ENGINE_', 'InnoDB');
```

### Character Set and Collation
- Default charset: `utf8mb4`
- Default collation: `utf8mb4_unicode_ci`
- Supports full Unicode including emojis

## Query Optimization

### Indexing Strategy
- Primary keys on all tables
- Foreign key indexes for relationships
- Composite indexes for common query patterns
- Date range indexes for availability queries

### Common Query Patterns
```sql
-- Room availability check
SELECT r.* FROM ps_htl_room_information r
WHERE r.id_hotel = ? 
AND r.id NOT IN (
    SELECT bd.id_room FROM ps_htl_booking_detail bd
    WHERE bd.date_from <= ? AND bd.date_to >= ?
);

-- Booking with customer details
SELECT b.*, c.firstname, c.lastname, c.email
FROM ps_htl_booking_detail b
JOIN ps_customer c ON b.id_customer = c.id_customer
WHERE b.id_hotel = ?;
```

## Data Integrity

### Foreign Key Constraints
```sql
ALTER TABLE ps_htl_booking_detail
ADD CONSTRAINT fk_booking_customer
FOREIGN KEY (id_customer) REFERENCES ps_customer(id_customer);

ALTER TABLE ps_htl_room_information
ADD CONSTRAINT fk_room_hotel
FOREIGN KEY (id_hotel) REFERENCES ps_htl_branch_info(id);
```

### Validation Rules
- Date validation for check-in/check-out
- Price validation (positive values)
- Email format validation
- Phone number format validation

## Backup and Maintenance

### Backup Strategy
- Daily automated backups
- Transaction log backups
- Point-in-time recovery capability
- Backup verification procedures

### Maintenance Tasks
- Regular index optimization
- Statistics updates
- Cleanup of old log entries
- Archive old booking data

## Performance Considerations

### Connection Pooling
- Use persistent connections when possible
- Implement connection pooling for high traffic
- Monitor connection usage

### Query Caching
- Enable MySQL query cache
- Use application-level caching
- Cache frequently accessed configuration data

### Table Partitioning
Consider partitioning for large tables:
- Partition booking tables by date
- Partition log tables by month
- Archive old data to separate tables