#!/usr/bin/env bash

set -Eeuo pipefail

. /usr/local/lib/atum/atum.sh

atum_file_env MINIO_ROOT_USER
atum_file_env MINIO_ROOT_PASSWORD
atum_file_env MINIO_ACCESS_KEY
atum_file_env MINIO_SECRET_KEY

if [[ -z "$MINIO_ROOT_USER" && -n "$MINIO_ACCESS_KEY" ]]; then
  export MINIO_ROOT_USER="$MINIO_ACCESS_KEY"
fi
if [[ -z "$MINIO_ROOT_PASSWORD" && -n "$MINIO_SECRET_KEY" ]]; then
  export MINIO_ROOT_PASSWORD="$MINIO_SECRET_KEY"
fi

if (( $# == 0 )); then
  atum_minio_targets=()
  if [[ "${MINIO_DISTRIBUTED_MODE_ENABLED:-no}" == yes && -n "${MINIO_DISTRIBUTED_NODES:-}" ]]; then
    IFS=',' read -r -a atum_minio_targets <<<"$MINIO_DISTRIBUTED_NODES"
  else
    atum_minio_targets+=("${MINIO_DATA_DIR:-/data}")
  fi
  set -- server "${atum_minio_targets[@]}" \
    --address ":${MINIO_API_PORT_NUMBER:-9000}" "$@"
fi

exec minio "$@"
