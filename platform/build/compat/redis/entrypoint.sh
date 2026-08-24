#!/usr/bin/env bash

set -Eeuo pipefail

. /usr/local/lib/atum/atum.sh

atum_file_env REDIS_PASSWORD
atum_file_env REDIS_MASTER_PASSWORD

if (( $# == 0 )); then
  set -- /opt/bitnami/scripts/redis/run.sh
elif [[ "$1" == -* ]]; then
  set -- /opt/bitnami/scripts/redis/run.sh "$@"
fi

exec "$@"
