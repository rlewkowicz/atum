#!/usr/bin/env bash

set -Eeuo pipefail

atum_grafana_load_files() {
  local atum_file_name
  local atum_name
  local atum_value

  while IFS='=' read -r atum_file_name atum_value; do
    [[ "$atum_file_name" == GF_*_FILE ]] || continue
    atum_name="${atum_file_name%_FILE}"
    [[ -z "${!atum_name:-}" ]] || {
      printf '%s and %s are mutually exclusive\n' "$atum_name" "$atum_file_name" >&2
      return 1
    }
    [[ -r "$atum_value" ]] || {
      printf '%s does not name a readable secret file\n' "$atum_file_name" >&2
      return 1
    }
    printf -v "$atum_name" '%s' "$(<"$atum_value")"
    export "$atum_name"
    unset "$atum_file_name"
  done < <(env)
}

atum_grafana_load_files

atum_grafana_config="${GF_PATHS_CONFIG:-/etc/grafana/grafana.ini}"
atum_grafana_config_dir="${atum_grafana_config%/*}"
if [[ "$atum_grafana_config" == /opt/bitnami/grafana/* ]]; then
  mkdir -p -- "$atum_grafana_config_dir" "${GF_PATHS_PROVISIONING:-$atum_grafana_config_dir/provisioning}"
  if [[ ! -s "$atum_grafana_config" ]]; then
    cp /opt/bitnami/grafana/conf.default/sample.ini "$atum_grafana_config"
  fi
  if [[ -d /opt/bitnami/grafana/conf.default/provisioning ]]; then
    cp -an /opt/bitnami/grafana/conf.default/provisioning/. \
      "${GF_PATHS_PROVISIONING:-$atum_grafana_config_dir/provisioning}/"
  fi
fi

atum_grafana_logs="${GF_PATHS_LOGS:-/var/log/grafana}"
mkdir -p -- "${GF_PATHS_DATA:-/var/lib/grafana}"
if [[ "$atum_grafana_logs" == /opt/bitnami/grafana/logs ]]; then
  mkdir -p /tmp/grafana-logs
else
  mkdir -p -- "$atum_grafana_logs"
fi
exec /run.sh "$@"
