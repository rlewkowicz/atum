#!/usr/bin/env bash
set -euo pipefail

readonly domain="${ATUM_LIBVIRT_DOMAIN:?ATUM_LIBVIRT_DOMAIN is required}"
readonly uri="${ATUM_LIBVIRT_URI:?ATUM_LIBVIRT_URI is required}"

domains="$(virsh --connect "${uri}" list --all --name)"
readonly domains
if ! grep --fixed-strings --line-regexp --quiet -- "${domain}" <<<"${domains}"; then
  exit 0
fi

domain_id="$(virsh --connect "${uri}" domid "${domain}")"
readonly domain_id
if [[ "${domain_id}" == "-" ]]; then
  exit 0
fi

virsh --connect "${uri}" destroy "${domain}"
