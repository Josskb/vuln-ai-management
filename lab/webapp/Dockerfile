FROM php:7.4-apache

RUN apt-get update && apt-get install -y redis-tools default-mysql-client \
    && docker-php-ext-install pdo pdo_mysql \
    && pecl install redis && docker-php-ext-enable redis

COPY index.php /var/www/html/index.php
COPY .env /var/www/html/.env

RUN chown -R www-data:www-data /var/www/html
