#!/bin/sh

set -eu

case "${ATUM_BINARY:-}" in
  ""|*[!A-Za-z0-9._-]*)
    printf 'invalid ATUM_BINARY: %s\n' "${ATUM_BINARY:-}" >&2
    exit 64
    ;;
esac

exec "/usr/local/bin/${ATUM_BINARY}" "$@"
