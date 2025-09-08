# Technology Stack

## Core Technologies
- **PHP**: 8.1+ to 8.4 (legacy support from 5.4)
- **MySQL**: 5.7+ to 8.4
- **Web Server**: Apache 1.3/2.x, Nginx, or Microsoft IIS
- **Template Engine**: Smarty
- **JavaScript**: jQuery and various plugins

## Required PHP Extensions
- PDO_MySQL
- cURL
- OpenSSL
- SOAP
- GD
- SimpleXML
- DOM
- Zip
- Phar

## Framework Base
Built on modified PrestaShop e-commerce framework, adapted for hospitality management.

## Development Environment Setup

### Local Development
- **Recommended**: WAMP (Windows), XAMPP (Windows/Mac), or EasyPHP (Windows)
- **PHP Configuration**:
  - memory_limit: 128M
  - upload_max_filesize: 16M (system sets to 100M)
  - max_execution_time: 500
  - allow_url_fopen: on

### Installation
1. Download QloApps from official website
2. Follow installation guide at https://qloapps.com/install-qloapps/
3. Alternative: Use Docker image `webkul/qloapps_docker`

### Docker Setup
```bash
docker pull webkul/qloapps_docker
```

## Build System
- **Dependency Management**: Composer (composer.json present)
- **No build tools**: Direct PHP execution, no compilation step required
- **Asset Management**: Manual CSS/JS inclusion

## Common Commands
- **Installation**: Web-based installer at `/install/`
- **Cache Clearing**: Manual deletion of `/cache/` contents
- **Module Management**: Through admin interface
- **Database**: Direct MySQL/phpMyAdmin access

## Security Requirements
- SSL certificate for payment processing
- Secure file permissions on hosting
- Regular security updates