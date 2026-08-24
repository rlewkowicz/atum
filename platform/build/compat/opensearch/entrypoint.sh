#!/usr/bin/env bash

set -Eeuo pipefail

atum_opensearch_csv() {
  local atum_value="${1//[[:space:]]/,}"

  while [[ "$atum_value" == *,,* ]]; do
    atum_value="${atum_value//,,/,}"
  done
  atum_value="${atum_value#,}"
  printf '%s' "${atum_value%,}"
}

atum_opensearch_command=/usr/share/opensearch/bin/opensearch
atum_opensearch_launch=false
case "${1:-}" in
  "")
    set -- "$atum_opensearch_command"
    atum_opensearch_launch=true
    ;;
  -*)
    set -- "$atum_opensearch_command" "$@"
    atum_opensearch_launch=true
    ;;
  opensearchwrapper)
    shift
    set -- "$atum_opensearch_command" "$@"
    atum_opensearch_launch=true
    ;;
  opensearch|/usr/share/opensearch/bin/opensearch)
    atum_opensearch_launch=true
    ;;
esac

atum_opensearch_args=()
if [[ "$atum_opensearch_launch" == true ]]; then
  if [[ -n "${OPENSEARCH_CLUSTER_NAME:-}" ]]; then
    atum_opensearch_args+=("-Ecluster.name=$OPENSEARCH_CLUSTER_NAME")
  fi
  if [[ -n "${MY_POD_NAME:-}" ]]; then
    atum_opensearch_args+=("-Enode.name=$MY_POD_NAME")
  fi
  if [[ -n "${OPENSEARCH_NODE_ROLES:-}" ]]; then
    atum_opensearch_args+=("-Enode.roles=$(atum_opensearch_csv "$OPENSEARCH_NODE_ROLES")")
  fi
  if [[ -n "${OPENSEARCH_CLUSTER_HOSTS:-}" ]]; then
    atum_opensearch_args+=("-Ediscovery.seed_hosts=$(atum_opensearch_csv "$OPENSEARCH_CLUSTER_HOSTS")")
  fi
  if [[ -n "${OPENSEARCH_CLUSTER_MASTER_HOSTS:-}" ]]; then
    atum_opensearch_args+=("-Ecluster.initial_cluster_manager_nodes=$(atum_opensearch_csv "$OPENSEARCH_CLUSTER_MASTER_HOSTS")")
  fi
  if [[ -n "${OPENSEARCH_HTTP_PORT_NUMBER:-}" ]]; then
    atum_opensearch_args+=("-Ehttp.port=$OPENSEARCH_HTTP_PORT_NUMBER")
  fi
  if [[ -n "${OPENSEARCH_TRANSPORT_PORT_NUMBER:-}" ]]; then
    atum_opensearch_args+=("-Etransport.port=$OPENSEARCH_TRANSPORT_PORT_NUMBER")
  fi
  if [[ -n "${OPENSEARCH_ADVERTISED_HOSTNAME:-}" ]]; then
    atum_opensearch_args+=("-Enetwork.publish_host=$OPENSEARCH_ADVERTISED_HOSTNAME")
  fi
  if [[ -n "${OPENSEARCH_FS_SNAPSHOT_REPO_PATH:-}" ]]; then
    atum_opensearch_args+=("-Epath.repo=$OPENSEARCH_FS_SNAPSHOT_REPO_PATH")
  fi
  if [[ -n "${OPENSEARCH_CLUSTER_NAME:-}${OPENSEARCH_NODE_ROLES:-}" ]]; then
    atum_opensearch_args+=("-Enetwork.host=0.0.0.0" "-Epath.data=/bitnami/opensearch/data")
  fi
  if [[ -n "${OPENSEARCH_HEAP_SIZE:-}" ]]; then
    export OPENSEARCH_JAVA_OPTS="${OPENSEARCH_JAVA_OPTS:-} -Xms${OPENSEARCH_HEAP_SIZE} -Xmx${OPENSEARCH_HEAP_SIZE}"
  fi
fi

exec /usr/local/bin/opensearch-upstream-entrypoint \
  "$@" "${atum_opensearch_args[@]}"
