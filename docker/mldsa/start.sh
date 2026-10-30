#!/usr/bin/env bash
set -euo pipefail
if [ ! -f /workspace/simplesamlphp-module-oidc/vendor/autoload.php ]; then
    echo 'Install the module Composer dependencies on the host first.' >&2
    exit 1
fi
mkdir -p /state/keys /state/cache /state/data /state/tmp
if [ ! -f /state/keys/tls.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -keyout /state/keys/tls.key -out /state/keys/tls.crt \
        -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
fi
php /lab/seed.php
chown -R www-data:www-data /state
chmod 700 /state/keys
chmod 600 /state/keys/*.key
exec apache2-foreground
