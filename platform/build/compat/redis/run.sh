#!/usr/bin/env bash

set -Eeuo pipefail

. /opt/bitnami/scripts/libvalidations.sh

atum_redis_data="${REDIS_DATA_DIR:-/data}"
atum_redis_port="${REDIS_PORT:-${REDIS_PORT_NUMBER:-6379}}"
atum_redis_config="/opt/bitnami/redis/etc/redis.conf"
atum_redis_generated="$(mktemp /tmp/atum-redis.XXXXXX.conf)"
trap 'rm -f -- "$atum_redis_generated"' EXIT
atum_redis_args=()

mkdir -p -- "$atum_redis_data" /opt/bitnami/redis/etc
if [[ -f /opt/bitnami/redis/mounted-etc/redis.conf && ! -s "$atum_redis_config" ]]; then
  cp /opt/bitnami/redis/mounted-etc/redis.conf "$atum_redis_config"
fi

{
  [[ -s "$atum_redis_config" ]] && cat -- "$atum_redis_config"
  printf 'dir %s\n' "$atum_redis_data"
  printf 'port %s\n' "$atum_redis_port"
  printf 'protected-mode no\n'
  printf 'bind 0.0.0.0 ::\n'
  if [[ -n "${REDIS_PASSWORD:-}" ]]; then
    atum_redis_args+=(--requirepass "$REDIS_PASSWORD")
  elif ! is_boolean_yes "${ALLOW_EMPTY_PASSWORD:-no}"; then
    printf 'REDIS_PASSWORD is required when ALLOW_EMPTY_PASSWORD is disabled\n' >&2
    exit 1
  fi
  if [[ "${REDIS_REPLICATION_MODE:-master}" == replica ]]; then
    printf 'replicaof %s %s\n' "${REDIS_MASTER_HOST:?REDIS_MASTER_HOST is required}" \
      "${REDIS_MASTER_PORT_NUMBER:-6379}"
    [[ -n "${REDIS_MASTER_PASSWORD:-}" ]] && atum_redis_args+=(--masterauth "$REDIS_MASTER_PASSWORD")
  fi
  if is_boolean_yes "${REDIS_TLS_ENABLED:-no}"; then
    printf 'port 0\n'
    printf 'tls-port %s\n' "${REDIS_TLS_PORT:-6379}"
    printf 'tls-cert-file %s\n' "${REDIS_TLS_CERT_FILE:?REDIS_TLS_CERT_FILE is required}"
    printf 'tls-key-file %s\n' "${REDIS_TLS_KEY_FILE:?REDIS_TLS_KEY_FILE is required}"
    [[ -n "${REDIS_TLS_CA_FILE:-}" ]] && printf 'tls-ca-cert-file %s\n' "$REDIS_TLS_CA_FILE"
    printf 'tls-auth-clients %s\n' "${REDIS_TLS_AUTH_CLIENTS:-yes}"
  fi
} >"$atum_redis_generated"

exec redis-server "$atum_redis_generated" "${atum_redis_args[@]}" "$@"
