# Project Structure

## Root Directory Layout

### Core Application
- `/classes/` - Core business logic and data models (ObjectModel pattern)
  - Core entities: `Product.php`, `Customer.php`, `Order.php`, `Configuration.php`
  - Hotel-specific: `Hotel.php`, `Room.php`, `Booking.php`
  - Utilities: `Tools.php`, `Validate.php`, `Mail.php`
- `/config/` - Configuration files, bootstrap, and system defines
  - `config.inc.php` - Main configuration bootstrap
  - `defines.inc.php` - System constants and defines
  - `autoload.php` - Class autoloading configuration
- `/controllers/` - MVC controllers (admin and front-end)
  - `/admin/` - Backend management controllers
  - `/front/` - Frontend user-facing controllers
- `/Core/` - Foundation and business layer abstractions
  - `/Business/` - Business logic layer
  - `/Foundation/` - Core foundation classes
- `/Adapter/` - Adapter pattern implementations for services
  - Service locators and dependency injection
  - External service integrations

### Frontend & Assets
- `/themes/` - Frontend themes and templates
  - Smarty template files (.tpl)
  - Theme-specific CSS and JavaScript
  - Responsive design components
- `/css/` - Global stylesheets and CSS assets
  - Core system styles
  - Admin interface styles
  - Responsive design frameworks
- `/js/` - JavaScript files and libraries
  - `/jquery/` - jQuery core and plugins
  - `/admin/` - Admin-specific JavaScript
  - Third-party libraries (TinyMCE, FullCalendar, etc.)
- `/img/` - Images and media assets
  - `/admin/` - Admin interface images
  - `/p/` - Product/room images
  - `/c/` - Category images
  - System icons and graphics

### Modules & Extensions
- `/modules/` - Modular functionality (hotel-specific features)
  - `/hotelreservationsystem/` - Core hotel booking module
  - `/wkhotelroom/` - Room management module
  - `/dashoccupancy/` - Occupancy dashboard
  - Payment modules (bankwire, cheque, etc.)
  - Analytics modules (dashtrends, dashperformance)
- `/override/` - System overrides for customization
  - `/classes/` - Override core classes
  - `/controllers/` - Override core controllers
  - `/modules/` - Override module functionality

### Data & Configuration
- `/localization/` - Country and language configurations
  - XML files for different countries (us.xml, gb.xml, etc.)
  - Currency, tax, and regional settings
- `/translations/` - Multi-language support files
  - Language-specific translation files
  - Admin and frontend translations
- `/mails/` - Email templates
  - Multi-language email templates
  - Booking confirmations, notifications
- `/pdf/` - PDF document templates
  - Invoice templates
  - Booking vouchers and receipts

### System Directories
- `/admin/` - Administrative interface
  - Admin panel entry point
  - Backend management tools
  - Configuration interfaces
- `/cache/` - System cache files
  - `/smarty/` - Template cache
  - `/cachefs/` - File system cache
  - Performance optimization cache
- `/log/` - Application logs
  - Error logs and debugging information
  - System activity logs
- `/upload/` - User uploaded files
  - Temporary file storage
  - User-generated content
- `/download/` - Downloadable content
  - Digital products and files
- `/webservice/` - API endpoint handlers
  - RESTful API implementation
  - Web service authentication

### Installation & Development
- `/install/` - Installation wizard and setup
  - Database setup scripts
  - Initial configuration
  - Upgrade utilities
- `/tests/` - Test suites and testing framework
  - Unit tests
  - Integration tests
- `/tools/` - Development and maintenance tools
  - Utility scripts
  - Development helpers

## Architecture Patterns

### MVC Structure
- **Controllers**: `/controllers/admin/` and `/controllers/front/`
  - Admin controllers extend `AdminController`
  - Frontend controllers extend `FrontController`
  - Hotel-specific controllers for booking management
- **Models**: `/classes/` - Follow ObjectModel pattern
  - Database abstraction layer
  - Validation and data integrity
  - Multilingual field support
- **Views**: Template files in themes, use Smarty templating
  - Separation of logic and presentation
  - Template inheritance and includes
  - Mobile-responsive design

### Module Architecture
Each module in `/modules/[module_name]/` follows standard structure:
- `[module_name].php` - Main module class extending `Module`
- `/classes/` - Module-specific models and business logic
- `/controllers/` - Module controllers (admin and front)
- `/views/` - Module templates and assets
- `/translations/` - Module-specific translations
- `config.xml` - Module configuration and metadata

### Hotel-Specific Modules
- **hotelreservationsystem** - Core booking engine
- **wkhotelroom** - Room type and inventory management
- **wkroomsearchblock** - Room search functionality
- **dashoccupancy** - Occupancy analytics
- **wkhotelfeaturesblock** - Hotel amenities display

### Override System
- `/override/classes/` - Override core classes without modifying originals
- `/override/controllers/` - Override core controllers
- `/override/modules/` - Override module functionality
- Maintains upgrade compatibility
- Follows inheritance patterns

### API Architecture
- **RESTful Design**: Standard HTTP methods (GET, POST, PUT, DELETE)
- **Resource-Based**: URLs represent resources (bookings, room_types, etc.)
- **Authentication**: Web service key-based authentication
- **Format Support**: XML and JSON responses
- **Error Handling**: Standardized error responses

## Key Files & Entry Points

### System Bootstrap
- `/init.php` - System initialization and autoloading
- `/config/config.inc.php` - Main configuration bootstrap
- `/config/defines.inc.php` - System constants and defines
- `/classes/PrestaShopAutoload.php` - Class autoloader

### Application Entry Points
- `/index.php` - Frontend entry point
- `/admin/index.php` - Admin panel entry point
- `/webservice/dispatcher.php` - API request dispatcher

### Core Classes
- `/classes/ObjectModel.php` - Base model class for all entities
- `/classes/Controller.php` - Base controller class
- `/classes/Tools.php` - Utility functions and helpers
- `/classes/Validate.php` - Input validation methods
- `/classes/Db.php` - Database abstraction layer

## Naming Conventions

### Classes & Files
- **Classes**: PascalCase (e.g., `ObjectModel`, `AdminController`)
- **Files**: Match class names with `.php` extension
- **Core classes**: Suffix with `Core` (e.g., `ToolsCore`)
- **Interfaces**: Prefix with `I` (e.g., `IWebserviceSpecificManagement`)

### Database
- **Tables**: Lowercase with underscores, prefixed with `ps_`
- **Columns**: Lowercase with underscores
- **Foreign Keys**: `id_[table_name]` format
- **Indexes**: Descriptive names with table prefix

### Constants & Configuration
- **Constants**: UPPERCASE with underscores (e.g., `_PS_VERSION_`)
- **Configuration Keys**: UPPERCASE with underscores (e.g., `PS_LANG_DEFAULT`)
- **Module Constants**: Prefixed with module name

### Templates & Assets
- **Template Files**: Lowercase with hyphens (.tpl extension)
- **CSS Classes**: Lowercase with hyphens or underscores
- **JavaScript**: camelCase for functions and variables
- **Image Files**: Descriptive names with appropriate extensions

## Development Guidelines

### Code Standards
- Follow PrestaShop coding standards and PSR guidelines
- Use proper indentation (4 spaces, no tabs)
- Comment complex logic and public methods
- Implement proper error handling and validation

### Customization Best Practices
- **Use Override System**: Never modify core files directly
- **Create Modules**: For new functionality, create modules
- **Maintain Compatibility**: Ensure backward compatibility
- **Test Thoroughly**: Test all customizations across different scenarios

### Database Guidelines
- **Use ObjectModel**: Leverage the ORM for database operations
- **Validate Input**: Always validate and sanitize user input
- **Use Transactions**: For complex operations involving multiple tables
- **Optimize Queries**: Use proper indexing and efficient queries

### API Development
- **Follow REST Principles**: Use appropriate HTTP methods and status codes
- **Validate Requests**: Implement proper input validation
- **Handle Errors**: Provide meaningful error messages
- **Document APIs**: Maintain clear API documentation

### Security Considerations
- **Input Validation**: Sanitize all user inputs
- **SQL Injection Prevention**: Use prepared statements
- **XSS Protection**: Escape output data
- **File Upload Security**: Validate file types and sizes
- **Access Control**: Implement proper authentication and authorization