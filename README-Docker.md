# QloApps Docker Setup

This Docker setup provides a complete development environment for QloApps with PHP 7.4, MySQL 8.0, and phpMyAdmin.

## Quick Start

1. **Setup environment variables (IMPORTANT):**
   ```bash
   cp .env.example .env
   # Edit .env file and change the default passwords for security
   ```

2. **Build and start the containers:**
   ```bash
   docker-compose up -d --build
   ```

3. **Access the application:**
   - QloApps: http://localhost:80 (or your configured APP_PORT)
   - phpMyAdmin: http://localhost:8081 (or your configured PHPMYADMIN_PORT)

4. **Database connection details:**
   - Host: `mysql` (from within containers) or `localhost:3306` (from host)
   - Database: `qloapps` (or your configured MYSQL_DATABASE)
   - Username: `qloapps_user` (or your configured MYSQL_USER)
   - Password: Use the password set in your .env file
   - Root password: Use the MYSQL_ROOT_PASSWORD from your .env file

## Installation Process

1. Navigate to http://localhost:8080
2. Follow the QloApps installation wizard
3. Use the database credentials above when prompted
4. Complete the setup process

## Container Services

- **qloapps_web**: Main application (PHP 7.4 + Apache)
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

## Security Best Practices

1. **Environment Variables**: Always use `.env` file for sensitive data - never commit it to version control
2. **Strong Passwords**: Use complex, unique passwords for production environments
3. **Port Configuration**: Change default ports in production using environment variables
4. **File Permissions**: Container uses secure 775 permissions instead of 777
5. **Network Isolation**: Services communicate through internal Docker network

## Environment Variables

Create a `.env` file from `.env.example` and configure:

- `MYSQL_ROOT_PASSWORD`: MySQL root password
- `MYSQL_PASSWORD`: Application database password  
- `APP_PORT`: QloApps web interface port (default: 80)
- `PHPMYADMIN_PORT`: phpMyAdmin interface port (default: 8081)
- `MYSQL_PORT`: MySQL database port (default: 3306)

## Troubleshooting

1. **Port conflicts**: Change ports in `.env` file if defaults are in use
2. **Permission issues**: Run `docker-compose exec qloapps chown -R www-data:www-data /var/www/html`
3. **Database connection**: Ensure MySQL container is fully started before accessing QloApps
4. **Environment issues**: Verify `.env` file exists and has correct syntax