#!/usr/bin/env bash
set -euo pipefail
mkdir -p /state/keys /state/cache /state/data /state/tmp
php /lab/seed.php
php /fed/op/expire-registration.php
chown -R www-data:www-data /state
chmod 700 /state/keys
chmod 600 /state/keys/*.key
exec apache2-foreground
