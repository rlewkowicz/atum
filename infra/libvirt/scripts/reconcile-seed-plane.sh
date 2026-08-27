#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly seed_root=/data/atum-seed
readonly incoming="${seed_root}/incoming"
readonly payload="${incoming}/atum-seed.tar"
readonly expected_sha="${1:?seed payload SHA-256 is required}"
readonly harbor_version="${2:?Harbor version is required}"
readonly installer="harbor-online-installer-${harbor_version}.tgz"

case "${expected_sha}" in
  (*[!0-9a-f]*|'')
    printf 'seed plane: invalid payload SHA-256\n' >&2
    exit 1
    ;;
esac
if [ "${#expected_sha}" -ne 64 ]; then
  printf 'seed plane: invalid payload SHA-256 length\n' >&2
  exit 1
fi
if [[ ! "${harbor_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'seed plane: invalid Harbor release %s\n' "${harbor_version}" >&2
  exit 1
fi

readonly release_root="${seed_root}/releases/${expected_sha}"

install -d -m 0700 "${incoming}" "${seed_root}/releases" "${seed_root}/runtime"

actual_sha="$(sha256sum "${payload}" | cut -d ' ' -f 1)"
if [ "${actual_sha}" != "${expected_sha}" ]; then
  printf 'seed plane: payload is %s, expected %s\n' "${actual_sha}" "${expected_sha}" >&2
  exit 1
fi

if [ ! -f "${release_root}/.verified" ]; then
  candidate="$(mktemp -d "${seed_root}/releases/.${expected_sha}.XXXXXX")"
  cleanup_candidate() {
    rm -rf -- "${candidate}"
  }
  trap cleanup_candidate EXIT

  tar -tf "${payload}" | awk -v installer="${installer}" '
    $0 == "images.tar" || $0 == installer || $0 == "seed.json" || $0 == "SHA256SUMS" {
      seen[$0]++
      count++
      next
    }
    { exit 1 }
    END {
      if (count != 4 || seen["images.tar"] != 1 || seen[installer] != 1 ||
          seen["seed.json"] != 1 || seen["SHA256SUMS"] != 1) {
        exit 1
      }
    }
  '
  tar --extract --file "${payload}" --directory "${candidate}" --no-same-owner --no-same-permissions
  for member in images.tar "${installer}" seed.json SHA256SUMS; do
    member_path="${candidate}/${member}"
    if [ ! -f "${member_path}" ] || [ -L "${member_path}" ] || [ "$(stat --format '%h' "${member_path}")" -ne 1 ]; then
      printf 'seed plane: payload member %s is not one regular file\n' "${member}" >&2
      exit 1
    fi
  done
  (
    cd "${candidate}"
    sha256sum --check --strict SHA256SUMS
  )
  touch "${candidate}/.verified"
  rm -rf -- "${release_root}"
  mv -- "${candidate}" "${release_root}"
  trap - EXIT
else
  (
    cd "${release_root}"
    sha256sum --check --strict SHA256SUMS
  )
fi

seed_image_bytes="$(stat -c '%s' "${release_root}/images.tar")"
printf 'seed plane: loading exact Forgejo and Harbor images bytes=%s\n' "${seed_image_bytes}"
docker load --input "${release_root}/images.tar"
printf 'seed plane: loaded exact Forgejo and Harbor images bytes=%s\n' "${seed_image_bytes}"

configuration_sha="$({
  sha256sum "${incoming}/harbor.yml"
  sha256sum "${incoming}/forgejo-compose.yaml"
} | sha256sum | cut -d ' ' -f 1)"
readonly runtime_root="${seed_root}/runtime/${expected_sha}-${configuration_sha}"
if [ ! -d "${runtime_root}" ]; then
  runtime_candidate="$(mktemp -d "${seed_root}/runtime/.${expected_sha}.XXXXXX")"
  cleanup_runtime() {
    rm -rf -- "${runtime_candidate}"
  }
  trap cleanup_runtime EXIT
  tar --extract --gzip --file "${release_root}/${installer}" --directory "${runtime_candidate}" \
    --no-same-owner --no-same-permissions
  mv -- "${runtime_candidate}" "${runtime_root}"
  trap - EXIT
fi

harbor_root="${runtime_root}/harbor"
if [ ! -x "${harbor_root}/prepare" ]; then
  printf 'seed plane: Harbor installer does not contain prepare\n' >&2
  exit 1
fi
install -m 0600 "${incoming}/harbor.yml" "${harbor_root}/harbor.yml"
install -m 0600 "${incoming}/forgejo-compose.yaml" "${runtime_root}/forgejo-compose.yaml"

printf 'seed plane: preparing Harbor %s without optional services\n' "${harbor_version}"
(
  cd "${harbor_root}"
  # Bootstrap Harbor is intentionally private-network HTTP. Cluster TLS is
  # owned later by Flux, Big Bang cert-manager, and the Atum PKI resources.
  ./prepare 2> >(
    sed '/^WARNING:root:WARNING: HTTP protocol is insecure\. Harbor will deprecate http protocol in the future\. Please make sure to upgrade to https$/d' >&2
  )
)

forgejo_compose=(
  docker compose
  --project-name atum-forgejo
  --file "${runtime_root}/forgejo-compose.yaml"
)
harbor_compose=(
  docker compose
  --project-name atum-harbor
  --file "${runtime_root}/harbor/docker-compose.yml"
)

"${forgejo_compose[@]}" up --detach --remove-orphans --pull never

# Harbor's generated Compose file starts core as soon as PostgreSQL's container
# starts. On a new database, core can exit before PostgreSQL accepts connections;
# Nginx then retains core's former Docker address. Establish the generated
# stack's database dependency first so every published Harbor route remains
# attached to the service name Compose assigned it.
"${harbor_compose[@]}" up --detach --remove-orphans --pull never postgresql

deadline=$((SECONDS + 900))
next_report=0
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

harbor_healthy() {
  docker exec harbor-core /bin/sh -ceu '
    curl --fail --silent --show-error --max-time 3 \
      --user "admin:${HARBOR_ADMIN_PASSWORD}" \
      http://nginx:8080/api/v2.0/health
  ' |
    python3 -c '
import json
import sys

try:
    data = sys.stdin.buffer.read(65537)
    payload = json.loads(data) if len(data) <= 65536 else None
    components = payload.get("components") if isinstance(payload, dict) else None
    healthy = (
        payload.get("status") == "healthy"
        and isinstance(components, list)
        and all(isinstance(item, dict) and item.get("status") == "healthy" for item in components)
    )
except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
    healthy = False
raise SystemExit(0 if healthy else 1)
'
}

while :; do
  forgejo_state=waiting
  harbor_state=waiting
  if curl --fail --silent --show-error --max-time 3 http://127.0.0.1:3000/api/healthz >/dev/null 2>&1; then
    forgejo_state=ready
  fi
  if harbor_healthy >/dev/null 2>&1; then
    harbor_state=ready
  fi
  if [ "${forgejo_state}" = ready ] && [ "${harbor_state}" = ready ]; then
    break
  fi
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    printf 'seed plane: readiness timeout (forgejo=%s harbor=%s)\n' \
      "${forgejo_state}" "${harbor_state}" >&2
    "${forgejo_compose[@]}" ps >&2 || true
    "${harbor_compose[@]}" ps >&2 || true
    exit 1
  fi
  if [ "${SECONDS}" -ge "${next_report}" ]; then
    printf 'seed plane: forgejo=%s harbor=%s elapsed=%ss\n' \
      "${forgejo_state}" "${harbor_state}" "${SECONDS}"
    next_report=$((SECONDS + 15))
  fi
  sleep 3
done

printf 'seed plane: reconciling Forgejo administrator\n'
if ! docker exec atum-forgejo /bin/sh -eu -c '
  exec forgejo --work-path "${GITEA_WORK_DIR}" --config "${GITEA_APP_INI}" \
    admin user create --username "${GITEA_ADMIN_USERNAME}" \
    --password "${GITEA_ADMIN_PASSWORD}" --email "${GITEA_ADMIN_EMAIL}" \
    --admin --must-change-password=false
' >/dev/null 2>&1; then
  docker exec atum-forgejo /bin/sh -eu -c '
    exec forgejo --work-path "${GITEA_WORK_DIR}" --config "${GITEA_APP_INI}" \
      admin user change-password --username "${GITEA_ADMIN_USERNAME}" \
      --password "${GITEA_ADMIN_PASSWORD}" --must-change-password=false
  ' >/dev/null
fi

active_link="$(mktemp -d "${seed_root}/.current.XXXXXX")"
rmdir -- "${active_link}"
ln --symbolic "${runtime_root}" "${active_link}"
mv --no-target-directory --force "${active_link}" "${seed_root}/current"
printf '%s\n' "${expected_sha}" > "${seed_root}/active.sha256"
rm -f -- "${payload}"

find "${seed_root}/releases" -mindepth 1 -maxdepth 1 -type d ! -name "${expected_sha}" -print0 |
  while IFS= read -r -d '' old_release; do rm -rf -- "${old_release}"; done
find "${seed_root}/runtime" -mindepth 1 -maxdepth 1 -type d ! -name "${expected_sha}-${configuration_sha}" -print0 |
  while IFS= read -r -d '' old_runtime; do rm -rf -- "${old_runtime}"; done

printf 'seed plane: forgejo=ready harbor=ready payload=%s\n' "${expected_sha}"
