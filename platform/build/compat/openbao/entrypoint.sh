#!/bin/sh

set -eu

ulimit -c 0 2>/dev/null || true

atum_bao_config_dir="${BAO_CONFIG_DIR:-${VAULT_CONFIG_DIR:-/vault/config}}"
atum_bao_local_config="${BAO_LOCAL_CONFIG:-${VAULT_LOCAL_CONFIG:-}}"
if [ -n "${atum_bao_local_config}" ]; then
  umask 077
  printf '%s\n' "${atum_bao_local_config}" >"${atum_bao_config_dir}/local.json"
fi

case "${1:-}" in
  "")
    set -- vault server "-config=${atum_bao_config_dir}"
    ;;
  -*)
    set -- vault "$@"
    ;;
  server)
    set -- vault "$@"
    ;;
  version)
    set -- vault "$@"
    ;;
  bao)
    shift
    set -- vault "$@"
    ;;
esac

exec "$@"
