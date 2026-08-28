#!/usr/bin/env bash
set -Eeuo pipefail

readonly runtime_root="${1:-/data/atum-seed/current}"
readonly forgejo_file="${runtime_root}/forgejo-compose.yaml"
readonly harbor_file="${runtime_root}/harbor/docker-compose.yml"

if [ ! -f "${forgejo_file}" ] || [ ! -f "${harbor_file}" ]; then
  printf 'seed plane: active runtime is incomplete: %s\n' "${runtime_root}" >&2
  exit 1
fi

forgejo_compose=(
  docker compose
  --project-name atum-forgejo
  --file "${forgejo_file}"
)
harbor_compose=(
  docker compose
  --project-name atum-harbor
  --file "${harbor_file}"
)

"${forgejo_compose[@]}" up --detach --remove-orphans --pull never

# Docker restart policies operate independently and can start Harbor's syslog
# clients before harbor-log accepts connections. Compose remains the startup
# authority: establish the logging dependency before any client container.
"${harbor_compose[@]}" up --detach --no-deps --pull never log

deadline=$((SECONDS + 900))
next_report=0
while [ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' harbor-log 2>/dev/null || true)" != healthy ]; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    printf 'seed plane: harbor-log readiness timeout\n' >&2
    "${harbor_compose[@]}" ps >&2 || true
    exit 1
  fi
  if [ "${SECONDS}" -ge "${next_report}" ]; then
    printf 'seed plane: harbor-log=waiting elapsed=%ss\n' "${SECONDS}"
    next_report=$((SECONDS + 15))
  fi
  sleep 3
done

# Harbor's generated Compose file starts core as soon as PostgreSQL's container
# starts. Gate the full stack so a new or recovering database accepts
# connections before core and Nginx bind to their service dependencies.
"${harbor_compose[@]}" up --detach --remove-orphans --pull never postgresql

while ! "${harbor_compose[@]}" exec --no-TTY postgresql \
  pg_isready --quiet --username postgres --dbname postgres; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    printf 'seed plane: PostgreSQL readiness timeout\n' >&2
    "${harbor_compose[@]}" ps >&2 || true
    exit 1
  fi
  if [ "${SECONDS}" -ge "${next_report}" ]; then
    printf 'seed plane: postgresql=waiting elapsed=%ss\n' "${SECONDS}"
    next_report=$((SECONDS + 15))
  fi
  sleep 3
done

"${harbor_compose[@]}" up --detach --remove-orphans --pull never
printf 'seed plane: containers started in dependency order\n'
