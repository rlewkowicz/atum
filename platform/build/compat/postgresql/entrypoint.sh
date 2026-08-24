#!/usr/bin/env bash

set -Eeuo pipefail

. /usr/local/lib/atum/atum.sh

atum_file_env POSTGRES_PASSWORD
atum_file_env POSTGRES_POSTGRES_PASSWORD
atum_file_env POSTGRES_REPLICATION_PASSWORD

atum_pgdata="${PGDATA:-/bitnami/postgresql/data}"
atum_pg_port="${POSTGRESQL_PORT_NUMBER:-5432}"
atum_pg_user="${POSTGRES_USER:-postgres}"
atum_pg_database="${POSTGRES_DATABASE:-${POSTGRES_DB:-$atum_pg_user}}"
atum_pg_volume="${POSTGRESQL_VOLUME_DIR:-/bitnami/postgresql}"
atum_pg_socket="${POSTGRESQL_TMP_DIR:-/tmp}"

atum_pg_is_yes() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

atum_pg_write_runtime_config() {
  local atum_config="$atum_pg_volume/conf/conf.d/atum.conf"

  {
    printf "listen_addresses = '*'\n"
    printf 'port = %s\n' "$atum_pg_port"
    [[ -z "${POSTGRESQL_SHARED_PRELOAD_LIBRARIES:-}" ]] || \
      printf "shared_preload_libraries = '%s'\n" "$POSTGRESQL_SHARED_PRELOAD_LIBRARIES"
    [[ -z "${POSTGRESQL_CLIENT_MIN_MESSAGES:-}" ]] || \
      printf "client_min_messages = '%s'\n" "$POSTGRESQL_CLIENT_MIN_MESSAGES"
    [[ -z "${POSTGRESQL_LOG_CONNECTIONS:-}" ]] || \
      printf "log_connections = '%s'\n" "$POSTGRESQL_LOG_CONNECTIONS"
    [[ -z "${POSTGRESQL_LOG_DISCONNECTIONS:-}" ]] || \
      printf "log_disconnections = '%s'\n" "$POSTGRESQL_LOG_DISCONNECTIONS"
    [[ -z "${POSTGRESQL_LOG_LINE_PREFIX:-}" ]] || \
      printf "log_line_prefix = '%s'\n" "$POSTGRESQL_LOG_LINE_PREFIX"
    [[ -z "${POSTGRESQL_LOG_TIMEZONE:-}" ]] || \
      printf "log_timezone = '%s'\n" "$POSTGRESQL_LOG_TIMEZONE"
    if atum_pg_is_yes "${POSTGRESQL_ENABLE_TLS:-no}"; then
      printf 'ssl = on\n'
      printf "ssl_cert_file = '%s'\n" "${POSTGRESQL_TLS_CERT_FILE:?POSTGRESQL_TLS_CERT_FILE is required}"
      printf "ssl_key_file = '%s'\n" "${POSTGRESQL_TLS_KEY_FILE:?POSTGRESQL_TLS_KEY_FILE is required}"
      [[ -z "${POSTGRESQL_TLS_CA_FILE:-}" ]] || printf "ssl_ca_file = '%s'\n" "$POSTGRESQL_TLS_CA_FILE"
      [[ -z "${POSTGRESQL_TLS_CRL_FILE:-}" ]] || printf "ssl_crl_file = '%s'\n" "$POSTGRESQL_TLS_CRL_FILE"
      [[ -z "${POSTGRESQL_TLS_PREFER_SERVER_CIPHERS:-}" ]] || \
        printf "ssl_prefer_server_ciphers = '%s'\n" "$POSTGRESQL_TLS_PREFER_SERVER_CIPHERS"
    fi
  } >"$atum_config"

  if ! grep -Fq "include_dir = '$atum_pg_volume/conf/conf.d'" "$atum_pgdata/postgresql.conf"; then
    printf "include_dir = '%s/conf/conf.d'\n" "$atum_pg_volume" >>"$atum_pgdata/postgresql.conf"
  fi
}

atum_pg_write_host_auth() {
  local atum_auth=scram-sha-256
  local atum_hba="$atum_pgdata/pg_hba.conf"
  local atum_rule

  if [[ -f "$atum_pg_volume/conf/pg_hba.conf" ]]; then
    atum_hba="$atum_pg_volume/conf/pg_hba.conf"
  fi
  if [[ -z "${POSTGRES_PASSWORD:-}${POSTGRES_POSTGRES_PASSWORD:-}" ]] && \
     atum_pg_is_yes "${ALLOW_EMPTY_PASSWORD:-no}"; then
    atum_auth=trust
  fi
  atum_rule="host all all all $atum_auth"
  grep -Fqx "$atum_rule" "$atum_hba" || printf '%s\n' "$atum_rule" >>"$atum_hba"
}

atum_pg_process_init_file() {
  local atum_file="$1"

  case "$atum_file" in
    *.sh)
      if [[ -x "$atum_file" ]]; then
        "$atum_file"
      else
        . "$atum_file"
      fi
      ;;
    *.sql)
      psql --set=ON_ERROR_STOP=1 --username=postgres --dbname="$atum_pg_database" --file="$atum_file"
      ;;
    *.sql.gz)
      gzip -dc -- "$atum_file" | psql --set=ON_ERROR_STOP=1 --username=postgres --dbname="$atum_pg_database"
      ;;
  esac
}

atum_pg_process_init_dir() {
  local atum_dir="$1"
  local atum_file

  [[ -d "$atum_dir" ]] || return 0
  while IFS= read -r -d '' atum_file; do
    atum_pg_process_init_file "$atum_file"
  done < <(find "$atum_dir" -mindepth 1 -maxdepth 2 -type f -print0 | sort -z)
}

atum_pg_init() {
  local atum_admin_password="${POSTGRES_POSTGRES_PASSWORD:-}"
  local atum_init_password_file
  local -a atum_initdb_args=()

  if [[ "$atum_pg_user" == postgres && -z "$atum_admin_password" ]]; then
    atum_admin_password="${POSTGRES_PASSWORD:-}"
  fi
  if [[ -n "${POSTGRES_INITDB_ARGS:-}" ]]; then
    read -r -a atum_initdb_args <<<"$POSTGRES_INITDB_ARGS"
  fi
  if [[ -n "${POSTGRES_INITDB_WALDIR:-}" ]]; then
    mkdir -p -- "$POSTGRES_INITDB_WALDIR"
    atum_initdb_args+=(--waldir="$POSTGRES_INITDB_WALDIR")
  fi

  export PGHOST="$atum_pg_socket" PGPORT="$atum_pg_port"

  atum_init_password_file="$(mktemp "${atum_pg_socket%/}/atum-pg-password.XXXXXX")"
  trap 'rm -f -- "$atum_init_password_file"' RETURN
  printf '%s' "$atum_admin_password" >"$atum_init_password_file"

  if [[ -n "$atum_admin_password" ]]; then
    initdb --pgdata="$atum_pgdata" --username=postgres --pwfile="$atum_init_password_file" \
      --auth-host=scram-sha-256 --auth-local=trust "${atum_initdb_args[@]}"
  elif [[ "${ALLOW_EMPTY_PASSWORD:-no}" == yes || "${ALLOW_EMPTY_PASSWORD:-no}" == true ]]; then
    initdb --pgdata="$atum_pgdata" --username=postgres --auth-host=trust --auth-local=trust \
      "${atum_initdb_args[@]}"
  else
    printf 'POSTGRES_PASSWORD or POSTGRES_POSTGRES_PASSWORD is required for a new database\n' >&2
    return 1
  fi

  {
    printf "listen_addresses = '*'\n"
    printf 'port = %s\n' "$atum_pg_port"
  } >>"$atum_pgdata/postgresql.conf"

  pg_ctl --pgdata="$atum_pgdata" --options="-c listen_addresses='' -c unix_socket_directories='$atum_pg_socket' -p $atum_pg_port" \
    --wait start
  trap 'pg_ctl --pgdata="$atum_pgdata" --mode=fast --wait stop >/dev/null 2>&1 || true; rm -f -- "$atum_init_password_file"' RETURN

  if [[ -n "$atum_admin_password" ]]; then
    psql --set=ON_ERROR_STOP=1 --username=postgres --dbname=postgres \
      --set=atum_password="$atum_admin_password" <<'SQL'
ALTER ROLE postgres PASSWORD :'atum_password';
SQL
  fi

  if [[ "$atum_pg_user" != postgres ]]; then
    psql --set=ON_ERROR_STOP=1 --username=postgres --dbname=postgres \
      --set=atum_user="$atum_pg_user" --set=atum_password="${POSTGRES_PASSWORD:-}" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'atum_user', :'atum_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'atum_user') \gexec
SQL
  fi

  psql --set=ON_ERROR_STOP=1 --username=postgres --dbname=postgres \
    --set=atum_database="$atum_pg_database" --set=atum_owner="$atum_pg_user" <<'SQL'
SELECT format('CREATE DATABASE %I OWNER %I', :'atum_database', :'atum_owner')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'atum_database') \gexec
SQL

  if [[ -n "${POSTGRES_REPLICATION_USER:-}" && -n "${POSTGRES_REPLICATION_PASSWORD:-}" ]]; then
    psql --set=ON_ERROR_STOP=1 --username=postgres --dbname=postgres \
      --set=atum_user="$POSTGRES_REPLICATION_USER" \
      --set=atum_password="$POSTGRES_REPLICATION_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I WITH REPLICATION LOGIN PASSWORD %L', :'atum_user', :'atum_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'atum_user') \gexec
SQL
  fi

  atum_pg_process_init_dir /docker-entrypoint-preinitdb.d
  atum_pg_process_init_dir /docker-entrypoint-initdb.d
  pg_ctl --pgdata="$atum_pgdata" --mode=fast --wait stop
  trap - RETURN
  rm -f -- "$atum_init_password_file"
}

if (( $# == 0 )); then
  set -- postgres
elif [[ "$1" == -* ]]; then
  set -- postgres "$@"
fi

if [[ "$1" == postgres ]]; then
  mkdir -p -- "$atum_pgdata" "$atum_pg_socket" "$atum_pg_volume/conf/conf.d"
  chmod 0700 "$atum_pgdata"
  if [[ ! -s "$atum_pgdata/PG_VERSION" ]]; then
    atum_pg_init
  fi
  atum_pg_write_host_auth
  atum_pg_write_runtime_config
  : >"$atum_pg_volume/.initialized"
  : > /opt/bitnami/postgresql/tmp/.initialized

  if [[ -f "$atum_pg_volume/conf/postgresql.conf" ]]; then
    set -- "$@" -c "config_file=$atum_pg_volume/conf/postgresql.conf"
  fi
  if [[ -f "$atum_pg_volume/conf/pg_hba.conf" ]]; then
    set -- "$@" -c "hba_file=$atum_pg_volume/conf/pg_hba.conf"
  fi
fi

exec "$@"
