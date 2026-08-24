#!/usr/bin/env bash
set -euo pipefail

readonly domain="${ATUM_LIBVIRT_DOMAIN:?ATUM_LIBVIRT_DOMAIN is required}"
readonly uri="${ATUM_LIBVIRT_URI:?ATUM_LIBVIRT_URI is required}"

readonly domains="$(virsh --connect "${uri}" list --all --name)"
if ! grep --fixed-strings --line-regexp --quiet -- "${domain}" <<<"${domains}"; then
  exit 0
fi

readonly domain_id="$(virsh --connect "${uri}" domid "${domain}")"
if [[ "${domain_id}" == "-" ]]; then
  exit 0
fi

virsh --connect "${uri}" destroy "${domain}"
