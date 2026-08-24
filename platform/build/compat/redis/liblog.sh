#!/usr/bin/env bash

info() {
  printf '[atum-redis] %s\n' "$*"
}

warn() {
  printf '[atum-redis] warning: %s\n' "$*" >&2
}

error() {
  printf '[atum-redis] error: %s\n' "$*" >&2
}

debug() {
  [[ "${BITNAMI_DEBUG:-false}" == true ]] && printf '[atum-redis] debug: %s\n' "$*" >&2 || true
}
