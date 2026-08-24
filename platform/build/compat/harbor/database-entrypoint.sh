#!/bin/sh

set -eu

. /usr/local/lib/atum/atum.sh

case "${1:-}" in
  -*) set -- postgres "$@" ;;
esac
if [ "${1:-postgres}" != postgres ]; then
  exec "$@"
fi
[ "$#" -eq 0 ] || shift

atum_file_env POSTGRES_PASSWORD ""
atum_file_env POSTGRES_USER postgres
atum_file_env POSTGRES_DB "$POSTGRES_USER"
atum_file_env POSTGRES_MAX_CONNECTIONS 1024
atum_file_env POSTGRES_INITDB_ARGS ""

atum_pg_root="${PGDATA:-/var/lib/postgresql/data}"
atum_pg_old="${atum_pg_root}/pg15"
atum_pg_new="${atum_pg_root}/pg18"
atum_pg_old_bin=/opt/atum/postgresql/15/bin
atum_pg_new_bin=/opt/atum/postgresql/18/bin
atum_cleanup_dir=
atum_password_file=
atum_running_ctl=
atum_running_dir=

if [ -z "$atum_pg_root" ] || [ "$atum_pg_root" = / ]; then
  printf 'PGDATA must identify a dedicated PostgreSQL directory\n' >&2
  exit 64
fi

case "$POSTGRES_MAX_CONNECTIONS" in
  ''|*[!0-9]*)
    printf 'POSTGRES_MAX_CONNECTIONS must be an integer\n' >&2
    exit 64
    ;;
esac
if [ "$POSTGRES_MAX_CONNECTIONS" -lt 1 ] || [ "$POSTGRES_MAX_CONNECTIONS" -gt 262143 ]; then
  printf 'POSTGRES_MAX_CONNECTIONS must be between 1 and 262143\n' >&2
  exit 64
fi

atum_cleanup() {
  if [ -n "$atum_password_file" ] && [ -f "$atum_password_file" ]; then
    unlink "$atum_password_file" || true
  fi
  if [ -n "$atum_running_ctl" ] && [ -n "$atum_running_dir" ]; then
    "$atum_running_ctl" -D "$atum_running_dir" -m fast -w stop >/dev/null 2>&1 || true
  fi
  case "$atum_cleanup_dir" in
    "$atum_pg_root"/.atum-pg18-*) rm -rf -- "$atum_cleanup_dir" ;;
  esac
}
trap atum_cleanup EXIT
trap 'exit 1' HUP INT TERM

atum_stop_cluster() {
  "$atum_running_ctl" -D "$atum_running_dir" -m fast -w stop
  atum_running_ctl=
  atum_running_dir=
}

atum_initialize_cluster() {
  atum_data_dir="$1"
  atum_run_initializers="$2"
  atum_lc_collate="$3"
  atum_lc_ctype="$4"
  atum_encoding="$5"
  atum_checksums="$6"
  atum_auth=trust
  atum_password_file="${TMPDIR:-/tmp}/atum-postgres-password.$$"

  set -- --auth-local=trust --auth-host="$atum_auth" "$atum_checksums"
  if [ -n "$POSTGRES_PASSWORD" ]; then
    atum_auth=scram-sha-256
    umask 077
    printf '%s\n' "$POSTGRES_PASSWORD" > "$atum_password_file"
    set -- --auth-local=trust --auth-host="$atum_auth" "$atum_checksums" \
      --pwfile="$atum_password_file"
  else
    printf 'warning: POSTGRES_PASSWORD is empty; host authentication uses trust\n' >&2
  fi

  "$atum_pg_new_bin/initdb" -D "$atum_data_dir" -U postgres \
    --encoding="$atum_encoding" --lc-collate="$atum_lc_collate" \
    --lc-ctype="$atum_lc_ctype" --locale-provider=libc \
    "$@" ${POSTGRES_INITDB_ARGS:-}
  [ ! -f "$atum_password_file" ] || unlink "$atum_password_file"
  atum_password_file=

  [ "$atum_run_initializers" = true ] || return 0

  atum_running_ctl="$atum_pg_new_bin/pg_ctl"
  atum_running_dir="$atum_data_dir"
  "$atum_running_ctl" -D "$atum_running_dir" \
    -o "-c listen_addresses='' -c unix_socket_directories=/run/postgresql" -w start

  if [ "$POSTGRES_USER" = postgres ]; then
    if [ -n "$POSTGRES_PASSWORD" ]; then
      "$atum_pg_new_bin/psql" --username postgres --dbname postgres \
        --set=atum_password="$POSTGRES_PASSWORD" <<'EOSQL'
SELECT format('ALTER ROLE postgres LOGIN SUPERUSER PASSWORD %L', :'atum_password') \gexec
EOSQL
    fi
  elif [ -n "$POSTGRES_PASSWORD" ]; then
    "$atum_pg_new_bin/psql" --username postgres --dbname postgres \
      --set=atum_user="$POSTGRES_USER" --set=atum_password="$POSTGRES_PASSWORD" <<'EOSQL'
SELECT format('CREATE ROLE %I LOGIN SUPERUSER PASSWORD %L', :'atum_user', :'atum_password') \gexec
EOSQL
  else
    "$atum_pg_new_bin/psql" --username postgres --dbname postgres \
      --set=atum_user="$POSTGRES_USER" <<'EOSQL'
SELECT format('CREATE ROLE %I LOGIN SUPERUSER', :'atum_user') \gexec
EOSQL
  fi

  if [ "$POSTGRES_DB" != postgres ]; then
    "$atum_pg_new_bin/psql" --username postgres --dbname postgres \
      --set=atum_db="$POSTGRES_DB" --set=atum_user="$POSTGRES_USER" <<'EOSQL'
SELECT format('CREATE DATABASE %I OWNER %I', :'atum_db', :'atum_user') \gexec
EOSQL
  fi

  for atum_init in /docker-entrypoint-initdb.d/*; do
    [ -e "$atum_init" ] || continue
    case "$atum_init" in
      *.sh) . "$atum_init" ;;
      *.sql)
        "$atum_pg_new_bin/psql" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
          -v ON_ERROR_STOP=1 -f "$atum_init"
        ;;
      *.sql.gz)
        gzip -dc "$atum_init" | "$atum_pg_new_bin/psql" \
          --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v ON_ERROR_STOP=1
        ;;
    esac
  done

  atum_stop_cluster
}

atum_upgrade_cluster() {
  atum_old_major="$(sed -n '1p' "$atum_pg_old/PG_VERSION")"
  if [ "$atum_old_major" != 15 ]; then
    printf 'data directory contains PostgreSQL %s; only a PostgreSQL 15 to 18 upgrade is supported\n' \
      "$atum_old_major" >&2
    exit 1
  fi

  atum_running_ctl="$atum_pg_old_bin/pg_ctl"
  atum_running_dir="$atum_pg_old"
  "$atum_running_ctl" -D "$atum_running_dir" \
    -o "-c listen_addresses='' -c unix_socket_directories=/run/postgresql -p 5433" -w start
  atum_lc_collate="$("$atum_pg_old_bin/psql" --host /run/postgresql --port 5433 \
    --username postgres --dbname postgres --no-align --tuples-only --command 'SHOW lc_collate')"
  atum_lc_ctype="$("$atum_pg_old_bin/psql" --host /run/postgresql --port 5433 \
    --username postgres --dbname postgres --no-align --tuples-only --command 'SHOW lc_ctype')"
  atum_encoding="$("$atum_pg_old_bin/psql" --host /run/postgresql --port 5433 \
    --username postgres --dbname postgres --no-align --tuples-only --command 'SHOW server_encoding')"
  atum_stop_cluster

  atum_checksum_version="$(LC_ALL=C "$atum_pg_old_bin/pg_controldata" "$atum_pg_old" |
    sed -n 's/^Data page checksum version:[[:space:]]*//p')"
  case "$atum_checksum_version" in
    0) atum_checksums=--no-data-checksums ;;
    ''|*[!0-9]*)
      printf 'could not determine PostgreSQL 15 checksum mode\n' >&2
      exit 1
      ;;
    *) atum_checksums=--data-checksums ;;
  esac

  atum_cleanup_dir="$(mktemp -d "${atum_pg_root}/.atum-pg18-upgrade.XXXXXXXXXX")"
  atum_initialize_cluster "$atum_cleanup_dir" false "$atum_lc_collate" \
    "$atum_lc_ctype" "$atum_encoding" "$atum_checksums"

  (
    cd "$atum_cleanup_dir"
    "$atum_pg_new_bin/pg_upgrade" \
      --old-bindir="$atum_pg_old_bin" \
      --new-bindir="$atum_pg_new_bin" \
      --old-datadir="$atum_pg_old" \
      --new-datadir="$atum_cleanup_dir" \
      --old-options="-c config_file=$atum_pg_old/postgresql.conf" \
      --new-options="-c config_file=$atum_cleanup_dir/postgresql.conf"
  )
  cp "$atum_pg_old/pg_hba.conf" "$atum_cleanup_dir/pg_hba.conf"
  mv "$atum_cleanup_dir" "$atum_pg_new"
  atum_cleanup_dir=
  printf 'upgraded Harbor database from PostgreSQL 15 to 18; retained %s for recovery\n' \
    "$atum_pg_old"
}

mkdir -p "$atum_pg_root" /run/postgresql
chmod 0700 "$atum_pg_root"

if [ -s "$atum_pg_root/PG_VERSION" ]; then
  printf 'flat PostgreSQL data layouts are not supported; expected %s or %s\n' \
    "$atum_pg_old" "$atum_pg_new" >&2
  exit 1
fi

if [ -e "$atum_pg_new" ] && [ ! -s "$atum_pg_new/PG_VERSION" ]; then
  if ! rmdir "$atum_pg_new" 2>/dev/null; then
    printf 'incomplete PostgreSQL 18 directory requires recovery: %s\n' "$atum_pg_new" >&2
    exit 1
  fi
fi

if [ -s "$atum_pg_new/PG_VERSION" ]; then
  atum_pg_major="$(sed -n '1p' "$atum_pg_new/PG_VERSION")"
  if [ "$atum_pg_major" != 18 ]; then
    printf 'data directory contains PostgreSQL %s; expected 18\n' "$atum_pg_major" >&2
    exit 1
  fi
elif [ -s "$atum_pg_old/PG_VERSION" ]; then
  atum_upgrade_cluster
else
  if [ -e "$atum_pg_old" ] && ! rmdir "$atum_pg_old" 2>/dev/null; then
    printf 'PostgreSQL 15 directory has no PG_VERSION and requires recovery: %s\n' \
      "$atum_pg_old" >&2
    exit 1
  fi
  atum_cleanup_dir="$(mktemp -d "${atum_pg_root}/.atum-pg18-init.XXXXXXXXXX")"
  atum_initialize_cluster "$atum_cleanup_dir" true en_US.UTF-8 en_US.UTF-8 UTF8 \
    --no-data-checksums
  mv "$atum_cleanup_dir" "$atum_pg_new"
  atum_cleanup_dir=
fi

export PGDATA="$atum_pg_new"
atum_running_ctl=
atum_running_dir=
trap - EXIT HUP INT TERM
exec "$atum_pg_new_bin/postgres" -D "$atum_pg_new" "$@" \
  -c "max_connections=$POSTGRES_MAX_CONNECTIONS" \
  -c "listen_addresses=*" \
  -c "unix_socket_directories=/run/postgresql"
