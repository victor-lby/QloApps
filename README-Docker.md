# QloApps Docker Setup

This Docker setup provides a complete development environment for QloApps with PHP 8.2, MySQL 8.0, and phpMyAdmin.

## Quick Start

1. **Build and start the containers:**
   ```bash
   docker-compose up -d --build
   ```

2. **Access the application:**
   - QloApps: http://localhost:8080
   - phpMyAdmin: http://localhost:8081

3. **Database connection details:**
   - Host: `mysql` (from within containers) or `localhost:3306` (from host)
   - Database: `qloapps`
   - Username: `qloapps_user`
   - Password: `qloapps_pass`
   - Root password: `qloapps_root`

## Installation Process

1. Navigate to http://localhost:8080
2. Follow the QloApps installation wizard
3. Use the database credentials above when prompted
4. Complete the setup process

## Container Services

- **qloapps_web**: Main application (PHP 8.2 + Apache)
- **qloapps_mysql**: MySQL 8.0 database
- **qloapps_phpmyadmin**: Database management interface

## Useful Commands

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f qloapps

# Access web container shell
docker-compose exec qloapps bash

# Access MySQL shell
docker-compose exec mysql mysql -u root -p

# Rebuild containers
docker-compose up -d --build
```

## File Permissions

The setup automatically configures proper file permissions for:
- `/cache` - Application cache
- `/log` - Application logs  
- `/upload` - File uploads
- `/download` - Downloads
- `/img` - Images
- `/config` - Configuration files

## Volumes

Persistent data is stored in:
- `mysql_data` - Database files
- Local directories mounted for development

## Troubleshooting

1. **Port conflicts**: Change ports in docker-compose.yml if 8080/8081/3306 are in use
2. **Permission issues**: Run `docker-compose exec qloapps chown -R www-data:www-data /var/www/html`
3. **Database connection**: Ensure MySQL container is fully started before accessing QloApps