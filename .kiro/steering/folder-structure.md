# QloApps Folder Structure Guidelines

## Project Organization Principles

### Root Level Structure
```
qloapps/
├── admin/                  # Admin panel interface
├── cache/                  # System cache files
├── classes/                # Core business logic (ObjectModel pattern)
├── config/                 # Configuration and bootstrap files
├── controllers/            # MVC controllers (admin & frontend)
├── Core/                   # Foundation and business abstractions
├── css/                    # Global stylesheets
├── download/               # Downloadable content
├── img/                    # Images and media assets
├── install/                # Installation wizard
├── js/                     # JavaScript libraries
├── localization/           # Country/language configs
├── log/                    # Application logs
├── mails/                  # Email templates
├── modules/                # Modular functionality
├── override/               # System customizations
├── pdf/                    # PDF templates
├── themes/                 # Frontend themes
├── tools/                  # Development utilities
├── translations/           # Multi-language files
├── upload/                 # User uploads
└── webservice/             # API handlers
```

## Module Directory Structure

### Standard Module Layout
```
modules/[module_name]/
├── [module_name].php       # Main module class
├── config.xml              # Module configuration
├── logo.png                # Module icon (16x16, 32x32, 64x64)
├── index.php               # Security file (prevents direct access)
├── classes/                # Module-specific models
│   ├── [ClassName].php
│   └── index.php
├── controllers/            # Module controllers
│   ├── admin/              # Admin controllers
│   │   ├── Admin[Name]Controller.php
│   │   └── index.php
│   ├── front/              # Frontend controllers
│   │   ├── [name].php
│   │   └── index.php
│   └── index.php
├── views/                  # Templates and assets
│   ├── css/                # Module-specific CSS
│   │   ├── admin.css
│   │   ├── front.css
│   │   └── index.php
│   ├── js/                 # Module-specific JavaScript
│   │   ├── admin.js
│   │   ├── front.js
│   │   └── index.php
│   ├── img/                # Module images
│   │   └── index.php
│   └── templates/          # Smarty templates
│       ├── admin/          # Admin templates
│       │   ├── configure.tpl
│       │   └── index.php
│       ├── front/          # Frontend templates
│       │   ├── display.tpl
│       │   └── index.php
│       └── hook/           # Hook templates
│           ├── hookname.tpl
│           └── index.php
├── translations/           # Module translations
│   ├── en.php
│   ├── fr.php
│   └── index.php
├── sql/                    # Database scripts
│   ├── install.sql
│   ├── uninstall.sql
│   └── index.php
└── upgrade/                # Upgrade scripts
    ├── upgrade-1.0.1.php
    └── index.php
```

## Hotel-Specific Module Examples

### Booking System Module
```
modules/hotelreservationsystem/
├── hotelreservationsystem.php
├── classes/
│   ├── HtlBookingDetail.php
│   ├── HtlBookingDemands.php
│   ├── HtlRoomInformation.php
│   └── HtlBranchInfo.php
├── controllers/
│   ├── admin/
│   │   ├── AdminBookingController.php
│   │   ├── AdminRoomsController.php
│   │   └── AdminHotelsController.php
│   └── front/
│       ├── booking.php
│       ├── search.php
│       └── confirmation.php
├── views/
│   ├── templates/
│   │   ├── admin/
│   │   │   ├── booking_list.tpl
│   │   │   ├── room_management.tpl
│   │   │   └── hotel_config.tpl
│   │   └── front/
│   │       ├── room_search.tpl
│   │       ├── booking_form.tpl
│   │       └── confirmation.tpl
│   ├── css/
│   │   ├── booking_admin.css
│   │   └── booking_front.css
│   └── js/
│       ├── booking_calendar.js
│       └── room_selection.js
└── sql/
    ├── install.sql
    └── booking_tables.sql
```

### Room Management Module
```
modules/wkhotelroom/
├── wkhotelroom.php
├── classes/
│   ├── HtlRoomType.php
│   ├── HtlRoomTypeFeature.php
│   └── HtlRoomTypeImage.php
├── controllers/
│   ├── admin/
│   │   ├── AdminRoomTypesController.php
│   │   └── AdminRoomFeaturesController.php
│   └── front/
│       └── roomdetails.php
├── views/
│   └── templates/
│       ├── admin/
│       │   ├── room_type_form.tpl
│       │   └── feature_management.tpl
│       └── front/
│           └── room_details.tpl
└── sql/
    └── room_tables.sql
```

## Theme Directory Structure

### Frontend Theme Layout
```
themes/[theme_name]/
├── css/                    # Theme stylesheets
│   ├── global.css
│   ├── hotel.css
│   ├── booking.css
│   └── responsive.css
├── js/                     # Theme JavaScript
│   ├── theme.js
│   ├── booking.js
│   └── hotel-features.js
├── img/                    # Theme images
│   ├── logo.png
│   ├── icons/
│   └── backgrounds/
├── lang/                   # Theme translations
│   ├── en.php
│   └── fr.php
├── modules/                # Module template overrides
│   └── [module_name]/
│       └── views/
│           └── templates/
├── pdf/                    # PDF template overrides
│   ├── invoice.tpl
│   └── booking-voucher.tpl
├── mails/                  # Email template overrides
│   ├── en/
│   │   ├── booking_confirmation.html
│   │   └── booking_confirmation.txt
│   └── fr/
├── templates/              # Core templates
│   ├── index.tpl           # Homepage
│   ├── header.tpl          # Site header
│   ├── footer.tpl          # Site footer
│   ├── booking/            # Booking templates
│   │   ├── search.tpl
│   │   ├── results.tpl
│   │   └── checkout.tpl
│   ├── rooms/              # Room templates
│   │   ├── list.tpl
│   │   └── details.tpl
│   └── customer/           # Customer templates
│       ├── account.tpl
│       └── bookings.tpl
├── config.xml              # Theme configuration
└── preview.jpg             # Theme preview image
```

## Override System Structure

### Class Overrides
```
override/
├── classes/
│   ├── Customer.php        # Override core Customer class
│   ├── Product.php         # Override for room types
│   ├── Order.php           # Override for bookings
│   └── hotel/              # Hotel-specific overrides
│       ├── HtlBooking.php
│       └── HtlRoom.php
├── controllers/
│   ├── admin/
│   │   ├── AdminCustomersController.php
│   │   └── AdminProductsController.php
│   └── front/
│       ├── IndexController.php
│       └── ProductController.php
└── modules/
    └── [module_name]/
        ├── classes/
        └── controllers/
```

## Asset Organization

### CSS Structure
```
css/
├── admin/                  # Admin panel styles
│   ├── admin-theme.css
│   ├── hotel-admin.css
│   └── booking-admin.css
├── modules/                # Module-specific CSS
│   ├── hotelreservation/
│   └── roommanagement/
├── themes/                 # Theme CSS
│   └── [theme_name]/
└── global/                 # Global styles
    ├── reset.css
    ├── fonts.css
    └── responsive.css
```

### JavaScript Structure
```
js/
├── admin/                  # Admin JavaScript
│   ├── admin.js
│   ├── booking-calendar.js
│   └── room-management.js
├── jquery/                 # jQuery and plugins
│   ├── jquery-3.6.0.min.js
│   ├── plugins/
│   │   ├── datepicker/
│   │   ├── fullcalendar/
│   │   └── owl-carousel/
├── modules/                # Module JavaScript
│   └── [module_name]/
└── tools/                  # Utility scripts
    ├── ajax.js
    └── validation.js
```

## Configuration Files Structure

### Config Directory
```
config/
├── config.inc.php          # Main configuration
├── defines.inc.php         # System constants
├── settings.inc.php        # Database settings
├── autoload.php            # Class autoloader
├── alias.php               # URL aliases
├── smarty.config.inc.php   # Smarty configuration
└── xml/                    # XML configurations
    ├── modules_list.xml
    └── themes_list.xml
```

## Development Best Practices

### File Naming Conventions
- **PHP Classes**: PascalCase (`HotelBooking.php`)
- **Controllers**: PascalCase with suffix (`AdminBookingController.php`)
- **Templates**: lowercase with underscores (`booking_form.tpl`)
- **CSS/JS**: lowercase with hyphens (`booking-calendar.css`)
- **Images**: descriptive lowercase (`room-deluxe-01.jpg`)

### Security Files
Always include `index.php` security files in directories:
```php
<?php
/**
 * Security file to prevent direct access
 */
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Last-Modified: '.gmdate('D, d M Y H:i:s').' GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
header('Location: ../');
exit;
```

### Directory Permissions
- **Folders**: 755 (rwxr-xr-x)
- **Files**: 644 (rw-r--r--)
- **Writable directories**: 777 (cache, log, upload)
- **Config files**: 644 with restricted access

### Version Control Exclusions
Common `.gitignore` patterns:
```
/cache/*
/log/*
/upload/*
/config/settings.inc.php
/admin/autoupgrade/
*.log
.DS_Store
Thumbs.db
```

## Module Development Structure

### Development Workflow
1. **Planning**: Define module scope and requirements
2. **Structure**: Create standard directory structure
3. **Core Class**: Implement main module class
4. **Models**: Create ObjectModel classes for data
5. **Controllers**: Implement admin and frontend controllers
6. **Templates**: Create Smarty templates
7. **Assets**: Add CSS, JavaScript, and images
8. **Hooks**: Register and implement hooks
9. **Installation**: Create install/uninstall scripts
10. **Testing**: Test functionality and compatibility

### Module Dependencies
Track module dependencies in `config.xml`:
```xml
<dependencies>
    <module name="hotelreservationsystem" />
    <module name="wkhotelroom" />
</dependencies>
```

This structure ensures maintainable, scalable, and secure QloApps development while following established conventions and best practices.