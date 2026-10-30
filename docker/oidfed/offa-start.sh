#!/bin/sh
set -eu
mkdir -p /data/keys
update-ca-certificates
exec /offa
