FROM php:8.1-apache

# Install system dependencies and PHP extensions
RUN apt-get update && apt-get install -y \
    libzip-dev \
    unzip \
    python3 \
    python3-pip \
    && docker-php-ext-install mysqli pdo pdo_mysql zip \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/html

# Copy composer files first for better caching
COPY composer.json ./

# Install PHP dependencies
RUN composer install --no-dev --optimize-autoloader --no-scripts || true

# Copy application files
COPY . .

# Run composer install again with all files present
RUN composer install --no-dev --optimize-autoloader

# Create necessary directories
RUN mkdir -p /var/www/html/assets/data/malware_uploads \
    && mkdir -p /var/www/html/assets/data/quarantine \
    && mkdir -p /var/www/html/assets/uploads

# Set permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod -R 777 /var/www/html/assets/data \
    && chmod -R 777 /var/www/html/assets/uploads

# Configure Apache
COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf

# Set environment variables
ENV APACHE_DOCUMENT_ROOT=/var/www/html
ENV DB_HOST=mysql
ENV DB_USER=cyberhawk
ENV DB_PASSWORD=cyberhawk_secure_2024
ENV DB_NAME=cyberhawk
ENV APP_DIR=/var/www/html/

EXPOSE 80

CMD ["apache2-foreground"]
