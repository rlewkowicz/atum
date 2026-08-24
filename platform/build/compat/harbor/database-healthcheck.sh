#!/bin/sh

set -eu

atum_user="${POSTGRES_USER:-postgres}"
atum_database="${POSTGRES_DB:-$atum_user}"
export PGPASSWORD="${POSTGRES_PASSWORD:-}"

psql --host 127.0.0.1 --username "$atum_user" --dbname "$atum_database" \
  --quiet --no-align --tuples-only --command 'SELECT 1' | grep -qx 1
