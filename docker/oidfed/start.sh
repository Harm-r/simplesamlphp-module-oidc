#!/usr/bin/env bash
set -euo pipefail
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$lab_dir/../.."
if [ ! -f vendor/autoload.php ]; then
    echo 'Install the module Composer dependencies before starting the Federation lab.' >&2
    exit 1
fi
python3 docker/oidfed/prepare.py
compose=(docker compose -f docker/oidfed/compose.yml)
# Reload all algorithm settings while retaining this lab's keys and database.
"${compose[@]}" stop offa
"${compose[@]}" up -d --build --force-recreate op lighthouse proxy app
python3 docker/oidfed/bootstrap.py anchor
"${compose[@]}" up -d --force-recreate offa
python3 docker/oidfed/bootstrap.py enroll
cat <<'INFO'
Federation lab ready: https://app.127.0.0.1.nip.io:9443/
Select "SSP ML-DSA lab OP" and log in with student / studentpass.
Lab CA: build/oidfed-lab/pki/ca.crt
INFO
