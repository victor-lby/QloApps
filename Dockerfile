FROM php:8.1-apache

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    libzip-dev \
    libxml2-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) \
    pdo_mysql \
    mysqli \
    gd \
    zip \
    soap \
    simplexml \
    dom \
    curl

# Configure PHP settings for QloApps
RUN echo "memory_limit = 256M" >> /usr/local/etc/php/conf.d/qloapps.ini \
    && echo "upload_max_filesize = 100M" >> /usr/local/etc/php/conf.d/qloapps.ini \
    && echo "post_max_size = 100M" >> /usr/local/etc/php/conf.d/qloapps.ini \
    && echo "max_execution_time = 500" >> /usr/local/etc/php/conf.d/qloapps.ini \
    && echo "allow_url_fopen = On" >> /usr/local/etc/php/conf.d/qloapps.ini \
    && echo "default_charset = utf-8" >> /usr/local/etc/php/conf.d/qloapps.ini

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html

# Copy application files
COPY . /var/www/html/

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod -R 775 /var/www/html/cache \
    && chmod -R 775 /var/www/html/log \
    && chmod -R 775 /var/www/html/upload \
    && chmod -R 775 /var/www/html/download \
    && chmod -R 775 /var/www/html/img \
    && chmod -R 775 /var/www/html/config

# Create Apache virtual host configuration
RUN echo '<VirtualHost *:80>\n\
    DocumentRoot /var/www/html\n\
    <Directory /var/www/html>\n\
        AllowOverride All\n\
        Require all granted\n\
    </Directory>\n\
    ErrorLog ${APACHE_LOG_DIR}/error.log\n\
    CustomLog ${APACHE_LOG_DIR}/access.log combined\n\
</VirtualHost>' > /etc/apache2/sites-available/000-default.conf

EXPOSE 80

CMD ["apache2-foreground"]