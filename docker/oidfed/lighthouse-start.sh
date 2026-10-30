#!/bin/sh
set -eu
update-ca-certificates
/lhmigrate config2db --config=/config.yaml --db-dir=/data --force --only=alg,config_lifetime,metadata,endpoints
exec /lighthouse
