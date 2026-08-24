#!/usr/bin/env bash

set -Eeuo pipefail

. /opt/bitnami/scripts/libvalidations.sh

atum_sentinel_config="/opt/bitnami/redis-sentinel/etc/sentinel.conf"
atum_sentinel_port="${REDIS_SENTINEL_PORT:-${REDIS_SENTINEL_PORT_NUMBER:-26379}}"
mkdir -p -- "${atum_sentinel_config%/*}"

if [[ ! -s "$atum_sentinel_config" ]]; then
  {
    printf 'port %s\n' "$atum_sentinel_port"
    printf 'dir /tmp\n'
    printf 'sentinel monitor %s %s %s %s\n' \
      "${REDIS_SENTINEL_MASTER_NAME:-mymaster}" \
      "${REDIS_MASTER_HOST:?REDIS_MASTER_HOST is required}" \
      "${REDIS_MASTER_PORT_NUMBER:-6379}" \
      "${REDIS_SENTINEL_QUORUM:-2}"
    if [[ -n "${REDIS_MASTER_PASSWORD:-${REDIS_PASSWORD:-}}" ]]; then
      printf 'sentinel auth-pass %s %s\n' "${REDIS_SENTINEL_MASTER_NAME:-mymaster}" \
        "${REDIS_MASTER_PASSWORD:-$REDIS_PASSWORD}"
    fi
  } >"$atum_sentinel_config"
fi

exec redis-server "$atum_sentinel_config" --sentinel "$@"
