#!/bin/sh

set -eu

atum_file_env() {
  atum_name="$1"
  atum_default="${2-}"
  atum_file_name="${atum_name}_FILE"
  eval "atum_value=\${${atum_name}-}"
  eval "atum_file=\${${atum_file_name}-}"

  if [ -n "$atum_value" ] && [ -n "$atum_file" ]; then
    printf 'both %s and %s are set\n' "$atum_name" "$atum_file_name" >&2
    return 1
  fi
  if [ -n "$atum_file" ]; then
    atum_value="$(cat -- "$atum_file")"
  elif [ -z "$atum_value" ]; then
    atum_value="$atum_default"
  fi

  export "$atum_name=$atum_value"
  unset "$atum_file_name"
}

atum_install_ca_bundle() {
  atum_bundle="${ATUM_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
  atum_original="${TMPDIR:-/tmp}/atum-ca-certificates.crt"
  atum_merged="${TMPDIR:-/tmp}/atum-ca-certificates.merged.crt"

  [ -f "$atum_bundle" ] || return 0
  cp "$atum_bundle" "$atum_original"
  {
    cat "$atum_original"
    if [ -d /etc/harbor/ssl ]; then
      find /etc/harbor/ssl -maxdepth 2 -type f -name ca.crt -exec cat {} \;
    fi
    if [ -d /harbor_cust_cert ]; then
      find /harbor_cust_cert -maxdepth 1 -type f \( \
        -name '*.crt' -o -name '*.ca' -o -name '*.ca-bundle' -o -name '*.pem' \
      \) -exec cat {} \;
    fi
  } > "$atum_merged"
  cat "$atum_merged" > "$atum_bundle"
  rm -f "$atum_original" "$atum_merged"
}
