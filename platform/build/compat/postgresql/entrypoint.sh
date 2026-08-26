#!/bin/sh

set -eu

# The current Harbor and Keycloak Bitnami subcharts already use the Docker
# Official POSTGRES_* and PGDATA contracts. Translate only the two remaining
# Bitnami names, create the readiness marker required by their current probe,
# and leave all database lifecycle behavior to the official entrypoint.
if [ -n "${POSTGRES_DATABASE:-}" ] && [ -z "${POSTGRES_DB:-}" ]; then
    POSTGRES_DB=$POSTGRES_DATABASE
    export POSTGRES_DB
fi

case "${ALLOW_EMPTY_PASSWORD:-}" in
    1|true|TRUE|yes|YES|y|Y|on|ON)
        if [ -z "${POSTGRES_PASSWORD:-}" ] &&
            [ -z "${POSTGRES_PASSWORD_FILE:-}" ] &&
            [ -z "${POSTGRES_HOST_AUTH_METHOD:-}" ]; then
            POSTGRES_HOST_AUTH_METHOD=trust
            export POSTGRES_HOST_AUTH_METHOD
        fi
        ;;
esac

postgresql_volume_dir=${POSTGRESQL_VOLUME_DIR:-/bitnami/postgresql}
mkdir -p "$postgresql_volume_dir" /opt/bitnami/postgresql/tmp
: >"$postgresql_volume_dir/.initialized"
: >/opt/bitnami/postgresql/tmp/.initialized

exec /usr/local/bin/docker-entrypoint.sh "$@"
