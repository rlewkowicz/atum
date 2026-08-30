#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly root=/data/kubespray-files
readonly schema=atum.dev/kubespray-files/v1
readonly manifest_limit=1048576
readonly operation="${1:-}"
readonly manifest_sha="${2:-}"

valid_sha() {
  [[ "${1}" =~ ^[0-9a-f]{64}$ ]]
}

validate_manifest() {
  local manifest_path="${1}"
  awk -F '\t' -v schema="${schema}" '
    NR == 1 { if ($0 != schema) exit 1; next }
    function safe_path(value) {
      return value ~ /^(dl\.k8s\.io|get\.helm\.sh|github\.com|raw\.githubusercontent\.com|storage\.googleapis\.com)\// &&
        value !~ /(^|\/)\.\.?(\/|$)/ && value !~ /[\\[:space:]]/
    }
    {
      if (NF < 3 || length($1) != 64 || $1 ~ /[^0-9a-f]/ ||
          $2 !~ /^[1-9][0-9]*$/ || (previous != "" && previous >= $1) ||
          seen_digest[$1]++) exit 1
      previous = $1
      previous_path = ""
      for (field = 3; field <= NF; field++) {
        if (!safe_path($field) ||
            (previous_path != "" && previous_path >= $field) ||
            seen_path[$field]++) exit 1
        previous_path = $field
      }
      records++
    }
    END { if (NR < 2 || records != NR - 1) exit 1 }
  ' "${manifest_path}"
}

if ! valid_sha "${manifest_sha}"; then
  printf 'kubespray files: invalid manifest identity\n' >&2
  exit 1
fi

install -d -m 0755 "${root}" "${root}/projections"
install -d -m 0700 "${root}/blobs" "${root}/manifests"
readonly manifest="${root}/manifests/${manifest_sha}.manifest"

case "${operation}" in
  report)
    candidate="$(mktemp "${root}/manifests/.${manifest_sha}.XXXXXX")"
    trap 'rm -f -- "${candidate}"' EXIT
    head --bytes "$((manifest_limit + 1))" > "${candidate}"
    if [ "$(stat --format '%s' "${candidate}")" -gt "${manifest_limit}" ] ||
      [ "$(sha256sum "${candidate}" | cut -d ' ' -f 1)" != "${manifest_sha}" ]; then
      printf 'kubespray files: manifest identity mismatch\n' >&2
      exit 1
    fi
    validate_manifest "${candidate}"
    chmod 0600 "${candidate}"
    mv --force --no-target-directory "${candidate}" "${manifest}"
    trap - EXIT
    while IFS=$'\t' read -r digest size _; do
      [ "${digest}" = "${schema}" ] && continue
      blob="${root}/blobs/${digest}"
      if [ ! -f "${blob}" ] || [ -L "${blob}" ] ||
        [ "$(stat --format '%s' "${blob}" 2>/dev/null || printf 0)" -ne "${size}" ] ||
        [ "$(sha256sum "${blob}" 2>/dev/null | cut -d ' ' -f 1)" != "${digest}" ]; then
        rm -f -- "${blob}"
        printf '%s\n' "${digest}"
      fi
    done < "${manifest}"
    ;;
  put)
    readonly blob_sha="${3:-}"
    if ! valid_sha "${blob_sha}" || [ ! -f "${manifest}" ]; then
      printf 'kubespray files: unknown blob request\n' >&2
      exit 1
    fi
    size="$(awk -F '\t' -v digest="${blob_sha}" '$1 == digest { print $2; found++ } END { if (found != 1) exit 1 }' "${manifest}")"
    candidate="$(mktemp "${root}/blobs/.${blob_sha}.XXXXXX")"
    trap 'rm -f -- "${candidate}"' EXIT
    head --bytes "$((size + 1))" > "${candidate}"
    if [ "$(stat --format '%s' "${candidate}")" -ne "${size}" ] ||
      [ "$(sha256sum "${candidate}" | cut -d ' ' -f 1)" != "${blob_sha}" ]; then
      printf 'kubespray files: blob identity mismatch\n' >&2
      exit 1
    fi
    chmod 0600 "${candidate}"
    mv --force --no-target-directory "${candidate}" "${root}/blobs/${blob_sha}"
    trap - EXIT
    ;;
  activate)
    if [ ! -f "${manifest}" ]; then
      printf 'kubespray files: manifest is absent\n' >&2
      exit 1
    fi
    candidate="$(mktemp -d "${root}/projections/.${manifest_sha}.XXXXXX")"
    trap 'rm -rf -- "${candidate}"' EXIT
    while IFS=$'\t' read -r -a fields; do
      [ "${fields[0]}" = "${schema}" ] && continue
      digest="${fields[0]}"
      size="${fields[1]}"
      blob="${root}/blobs/${digest}"
      if [ ! -f "${blob}" ] || [ -L "${blob}" ] ||
        [ "$(stat --format '%s' "${blob}" 2>/dev/null || printf 0)" -ne "${size}" ] ||
        [ "$(sha256sum "${blob}" 2>/dev/null | cut -d ' ' -f 1)" != "${digest}" ]; then
        printf 'kubespray files: incomplete manifest\n' >&2
        exit 1
      fi
      for ((index = 2; index < ${#fields[@]}; index++)); do
        target="${candidate}/${fields[index]}"
        install -d -m 0755 "$(dirname "${target}")"
        ln -- "${blob}" "${target}"
        chmod 0644 "${target}"
      done
    done < "${manifest}"
    chmod 0755 "${candidate}"
    projection_name="${manifest_sha}-$(basename "${candidate}" | cut -d. -f3)"
    projection="${root}/projections/${projection_name}"
    mv -- "${candidate}" "${projection}"
    trap - EXIT
    next_link="$(mktemp -d "${root}/.current.XXXXXX")"
    rmdir -- "${next_link}"
    ln --symbolic "projections/${projection_name}" "${next_link}"
    mv --force --no-target-directory "${next_link}" "${root}/current"
    find "${root}/projections" -mindepth 1 -maxdepth 1 -type d ! -name "${projection_name}" -exec rm -rf -- {} +
    awk -F '\t' 'NR > 1 { print $1 }' "${manifest}" |
      sort --unique > "${root}/.active-blobs"
    find "${root}/blobs" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' |
      while IFS= read -r digest; do
        if ! grep --fixed-strings --line-regexp --quiet "${digest}" "${root}/.active-blobs"; then
          rm -f -- "${root}/blobs/${digest}"
        fi
      done
    find "${root}/manifests" -mindepth 1 -maxdepth 1 -type f ! -name "${manifest_sha}.manifest" -delete
    rm -f -- "${root}/.active-blobs"
    ;;
  *)
    printf 'usage: atum-kubespray-files {report|put|activate} manifest-sha [blob-sha]\n' >&2
    exit 2
    ;;
esac
