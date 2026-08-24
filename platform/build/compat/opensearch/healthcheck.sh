#!/usr/bin/env bash

set -Eeuo pipefail

atum_scheme=http
atum_curl_args=(--fail --silent --show-error --max-time 5)

case "${OPENSEARCH_ENABLE_REST_TLS:-false}" in
  1|true|yes|y|on) atum_scheme=https; atum_curl_args+=(--insecure) ;;
esac
if [[ -n "${OPENSEARCH_PASSWORD:-}" ]]; then
  atum_curl_args+=(--user "admin:${OPENSEARCH_PASSWORD}")
elif [[ -n "${OPENSEARCH_PASSWORD_FILE:-}" && -r "$OPENSEARCH_PASSWORD_FILE" ]]; then
  atum_curl_args+=(--user "admin:$(<"$OPENSEARCH_PASSWORD_FILE")")
fi

curl "${atum_curl_args[@]}" \
  "${atum_scheme}://127.0.0.1:${OPENSEARCH_HTTP_PORT_NUMBER:-9200}/_cluster/health"
