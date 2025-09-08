# Technology Stack

## Core Technologies
- **PHP**: 8.1+ to 8.4 (legacy support from 5.4)
- **MySQL**: 5.7+ to 8.4
- **Web Server**: Apache 1.3/2.x, Nginx, or Microsoft IIS
- **Template Engine**: Smarty (frontend and admin templates)
- **JavaScript**: jQuery and various plugins (owl-carousel, daterangepicker, fullcalendar)

## Required PHP Extensions
- **PDO_MySQL** - Database connectivity
- **cURL** - HTTP requests and API communications
- **OpenSSL** - Encryption and secure communications
- **SOAP** - Web service integrations
- **GD** - Image processing and manipulation
- **SimpleXML** - XML parsing for API responses
- **DOM** - XML document manipulation
- **Zip** - Archive handling for backups and uploads
- **Phar** - PHP archive support

## Framework Base
Built on modified PrestaShop e-commerce framework, adapted for hospitality management. Maintains MVC architecture with ObjectModel pattern for data handling.

## API Architecture

### RESTful Web Services
- **Authentication**: Web service key-based authentication
- **Formats**: XML and JSON support
- **Methods**: GET, POST, PUT, DELETE operations
- **Resources**: Hotels, bookings, room_types, configurations, images
- **Schema Support**: Blank schemas and synopsis for API discovery

### Key API Endpoints
- `/api/bookings` - Booking management
- `/api/hotel_ari` - Availability, rates, and inventory
- `/api/room_types` - Room type management
- `/api/configurations` - System configuration
- `/api/images/room_types/{id}` - Image management

### API Features
- **Multilingual Support** - Localized field handling
- **Image Upload** - cURL and form-based image uploads
- **Filtering** - Resource filtering by various parameters
- **Pagination** - Limit and offset support for large datasets
- **Date Range Queries** - Availability searches across date ranges

## Development Environment Setup

### Local Development
- **Recommended**: WAMP (Windows), XAMPP (Windows/Mac), or EasyPHP (Windows)
- **PHP Configuration**:
  - memory_limit: 128M (minimum, 256M recommended)
  - upload_max_filesize: 16M (system sets to 100M)
  - max_execution_time: 500
  - allow_url_fopen: on
  - max_input_vars: 3000 (for large forms)

### Installation Methods
1. **Manual Installation**:
   - Download QloApps from official website
   - Follow installation guide at https://qloapps.com/install-qloapps/
   - Web-based installer at `/install/`

2. **Docker Installation**:
   ```bash
   docker pull webkul/qloapps_docker
   docker run -d -p 80:80 webkul/qloapps_docker
   ```

3. **Development Setup**:
   - Clone repository
   - Configure database connection in `/config/`
   - Set proper file permissions
   - Enable developer mode for debugging

## Build System & Dependencies

### Dependency Management
- **Composer**: PHP dependency management (composer.json present)
- **No build tools**: Direct PHP execution, no compilation step required
- **Asset Management**: Manual CSS/JS inclusion in templates

### JavaScript Libraries
- **jQuery**: Core JavaScript framework
- **FullCalendar**: Calendar and date management
- **DateRangePicker**: Date selection widgets
- **Owl Carousel**: Image and content carousels
- **TinyMCE**: Rich text editor
- **DataTables**: Advanced table functionality

### CSS Frameworks
- **Bootstrap**: Responsive design framework
- **Custom CSS**: Hotel-specific styling
- **RTL Support**: Right-to-left language support

## Database Architecture

### Database Design
- **Prefix**: Tables prefixed with `ps_` (PrestaShop legacy)
- **Encoding**: UTF-8 for multilingual support
- **Engine**: InnoDB for transactions and foreign keys
- **Indexes**: Optimized for hotel booking queries

### Key Tables
- `ps_htl_booking_detail` - Booking information
- `ps_product` - Room types (products)
- `ps_htl_room_information` - Individual room data
- `ps_configuration` - System settings
- `ps_customer` - Guest information

## Common Commands & Operations

### Installation & Setup
- **Installation**: Web-based installer at `/install/`
- **Database Setup**: Automated during installation
- **Initial Configuration**: Admin panel setup

### Maintenance
- **Cache Clearing**: Manual deletion of `/cache/` contents or admin panel
- **Module Management**: Through admin interface at `/admin/`
- **Database**: Direct MySQL/phpMyAdmin access
- **Backups**: Built-in backup system in admin panel

### Development
- **Debug Mode**: Enable in configuration for development
- **Error Logging**: Check `/log/` directory for errors
- **Override Testing**: Test customizations in `/override/`
- **API Testing**: Use tools like Postman for API development

## Security Requirements

### Production Security
- **SSL Certificate**: Required for payment processing and data protection
- **File Permissions**: Proper chmod settings (644 for files, 755 for directories)
- **Database Security**: Strong passwords and restricted access
- **Regular Updates**: Keep core system and modules updated

### API Security
- **Web Service Keys**: Secure API authentication
- **Input Validation**: Sanitize all API inputs
- **Rate Limiting**: Implement API rate limiting for production
- **HTTPS Only**: Force HTTPS for all API communications

### Development Security
- **Debug Mode**: Disable in production
- **Error Display**: Hide error details in production
- **File Upload**: Validate and restrict file uploads
- **SQL Injection**: Use prepared statements and ORM

## Performance Optimization

### Caching
- **Smarty Cache**: Template caching enabled
- **Database Cache**: Query result caching
- **Static Assets**: Browser caching for CSS/JS
- **Image Optimization**: Compressed images for faster loading

### Database Optimization
- **Indexing**: Proper database indexes for queries
- **Query Optimization**: Efficient SQL queries
- **Connection Pooling**: Database connection management
- **Regular Maintenance**: Database cleanup and optimization