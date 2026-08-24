#!/bin/sh

set -eu

. /usr/local/lib/atum/atum.sh
atum_install_ca_bundle

case "${ATUM_HARBOR_COMPONENT:?ATUM_HARBOR_COMPONENT is required}" in
  core)
    exec /harbor/harbor_core "$@"
    ;;
  jobservice)
    exec /harbor/harbor_jobservice -c /etc/jobservice/config.yml "$@"
    ;;
  registry)
    exec /usr/bin/registry_DO_NOT_USE_GC serve /etc/registry/config.yml "$@"
    ;;
  registryctl)
    exec /home/harbor/harbor_registryctl -c /etc/registryctl/config.yml "$@"
    ;;
  *)
    printf 'unsupported Harbor component: %s\n' "$ATUM_HARBOR_COMPONENT" >&2
    exit 64
    ;;
esac
