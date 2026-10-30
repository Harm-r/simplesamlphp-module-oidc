FROM php:8.5-apache-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl libcurl4-openssl-dev libgmp-dev libicu-dev libonig-dev libsqlite3-dev libzip-dev \
    && docker-php-ext-install -j2 curl gmp intl mbstring pdo_sqlite zip \
    && a2enmod ssl rewrite headers \
    && rm -rf /var/lib/apt/lists/*

COPY apache.conf /etc/apache2/sites-available/000-default.conf
COPY start.sh /usr/local/bin/mldsa-start
RUN chmod +x /usr/local/bin/mldsa-start
ENV SIMPLESAMLPHP_CONFIG_DIR=/lab/config
CMD ["mldsa-start"]
