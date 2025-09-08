# Project Structure

## Root Directory Layout

### Core Application
- `/classes/` - Core business logic and data models (ObjectModel pattern)
- `/config/` - Configuration files, bootstrap, and system defines
- `/controllers/` - MVC controllers (admin and front-end)
- `/Core/` - Foundation and business layer abstractions
- `/Adapter/` - Adapter pattern implementations for services

### Frontend & Assets
- `/themes/` - Frontend themes and templates
- `/css/` - Stylesheets and CSS assets
- `/js/` - JavaScript files and libraries
- `/img/` - Images and media assets

### Modules & Extensions
- `/modules/` - Modular functionality (hotel-specific features)
- `/override/` - System overrides for customization

### Data & Configuration
- `/localization/` - Country and language configurations
- `/translations/` - Multi-language support files
- `/mails/` - Email templates
- `/pdf/` - PDF document templates

### System Directories
- `/admin/` - Administrative interface
- `/cache/` - System cache files
- `/log/` - Application logs
- `/upload/` - User uploaded files
- `/download/` - Downloadable content

## Architecture Patterns

### MVC Structure
- **Controllers**: `/controllers/admin/` and `/controllers/front/`
  - Admin controllers extend `AdminController`
  - Frontend controllers extend `FrontController`
- **Models**: `/classes/` - Follow ObjectModel pattern
- **Views**: Template files in themes, use Smarty templating

### Module Architecture
- Each module in `/modules/[module_name]/`
- Standard structure:
  - `[module_name].php` - Main module class
  - `/classes/` - Module-specific models
  - `/controllers/` - Module controllers
  - `/views/` - Module templates

### Override System
- `/override/classes/` - Override core classes
- `/override/controllers/` - Override core controllers
- `/override/modules/` - Override module functionality

## Key Files
- `/config/config.inc.php` - Main configuration bootstrap
- `/config/defines.inc.php` - System constants and defines
- `/classes/PrestaShopAutoload.php` - Autoloader
- `/init.php` - System initialization
- `/index.php` - Frontend entry point
- `/admin/index.php` - Admin entry point

## Naming Conventions
- **Classes**: PascalCase (e.g., `ObjectModel`, `AdminController`)
- **Files**: Match class names with `.php` extension
- **Core classes**: Suffix with `Core` (e.g., `ToolsCore`)
- **Database tables**: Lowercase with underscores, prefixed with `ps_`
- **Constants**: UPPERCASE with underscores (e.g., `_PS_VERSION_`)

## Development Guidelines
- Follow PrestaShop coding standards
- Use override system instead of modifying core files
- Create modules for new functionality
- Maintain backward compatibility
- Use proper error handling and validation