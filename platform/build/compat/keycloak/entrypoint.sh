#!/usr/bin/env bash

set -Eeuo pipefail

atum_keycloak_load_files() {
  local atum_file_name
  local atum_name
  local atum_value

  while IFS='=' read -r atum_file_name atum_value; do
    [[ "$atum_file_name" == KC_*_FILE ]] || continue
    case "$atum_file_name" in
      KC_HTTPS_CERTIFICATE_FILE|KC_HTTPS_CERTIFICATE_KEY_FILE)
        continue
        ;;
    esac
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

atum_keycloak_load_files

if [[ -z "${KC_DB:-}" && "${KC_DB_URL:-}" == jdbc:postgresql:* ]]; then
  export KC_DB=postgres
fi

if (( $# == 0 )); then
  if [[ "${KEYCLOAK_PRODUCTION:-false}" == true ]]; then
    set -- start
  else
    set -- start-dev
  fi
fi

if [[ -n "${KEYCLOAK_EXTRA_ARGS:-}" ]]; then
  read -r -a atum_keycloak_extra_args <<<"$KEYCLOAK_EXTRA_ARGS"
  set -- "$@" "${atum_keycloak_extra_args[@]}"
fi

exec /opt/bitnami/keycloak/bin/kc.sh "$@"
