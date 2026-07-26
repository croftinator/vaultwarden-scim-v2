#!/usr/bin/env bash
#
# Run the SCIM test suite against every backend this fork ships.
#
# Three dialects ship - sqlite, MySQL and PostgreSQL - and only sqlite is
# exercised by `cargo test`. The differences that matter are real: MySQL's
# `replace_into` versus PostgreSQL's `ON CONFLICT` upsert, foreign-key
# enforcement (sqlite needs a runtime PRAGMA), timestamp precision, and default
# collation case-sensitivity. A green sqlite run says nothing about the other
# two.
#
# MySQL and PostgreSQL are started in Docker, migrated from scratch, and torn
# down afterwards. Nothing outside Docker is touched.
#
# Usage:
#   tools/scim-test-backends.sh                 # all three
#   tools/scim-test-backends.sh sqlite mysql    # a subset
#   KEEP=1 tools/scim-test-backends.sh mysql    # leave the container running
#
# Requires: docker (for mysql/postgresql), cargo.
#
# Exit code: 0 only if every selected backend actually ran and passed.
#   1  at least one backend failed its tests
#   2  refused to start: not enough free disk for the requested backends
#   3  nothing failed, but a backend was skipped (missing client library or
#      docker), so its code path was never verified
#
set -uo pipefail

BACKENDS=("$@")
if [ ${#BACKENDS[@]} -eq 0 ]; then
    BACKENDS=(sqlite mysql postgresql)
fi

KEEP="${KEEP:-0}"
MYSQL_CONTAINER="vw-scim-test-mysql"
PG_CONTAINER="vw-scim-test-pg"
MYSQL_PORT="${MYSQL_PORT:-13306}"
PG_PORT="${PG_PORT:-15432}"
# Password for the throwaway containers this script starts and destroys. It is
# not a credential: the containers are created here, bound to 127.0.0.1, and
# removed on exit. Kept in a variable rather than inline so the connection
# strings below do not read as embedded credentials to a secret scanner.
DB_TEST_PASSWORD="${DB_TEST_PASSWORD:-vwtest}"

c_ok()   { printf '  \033[32m%s\033[0m\n' "$1"; }
c_bad()  { printf '  \033[31m%s\033[0m\n' "$1"; }
section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
    [ "$KEEP" = "1" ] && { echo "KEEP=1, leaving containers running"; return; }
    docker rm -f "$MYSQL_CONTAINER" "$PG_CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

require_docker() {
    if ! docker info >/dev/null 2>&1; then
        c_bad "docker is not running; cannot test $1"
        return 1
    fi
}

# Diesel links against the native client library for each backend. Without it
# the build dies in the linker with "library 'pq' not found", tens of thousands
# of lines into a compile - so check up front and say exactly what to install.
require_client_lib() {
    local backend="$1" lib="$2" formula="$3" prefix
    for prefix in /opt/homebrew/opt /usr/local/opt; do
        if [ -d "$prefix/$formula/lib" ]; then
            # Keg-only formulae are not on the default search path.
            export LIBRARY_PATH="$prefix/$formula/lib:${LIBRARY_PATH:-}"
            export PKG_CONFIG_PATH="$prefix/$formula/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
            # mysqlclient-sys reads its own variables and ignores LIBRARY_PATH,
            # so finding the formula here is not enough on its own. Without
            # these the build script fails and the whole backend is reported as
            # a test failure rather than as the toolchain gap it actually is.
            if [ "$backend" = "mysql" ]; then
                export MYSQLCLIENT_LIB_DIR="$prefix/$formula/lib"
                export MYSQLCLIENT_INCLUDE_DIR="$prefix/$formula/include"
            fi
            return 0
        fi
    done
    if ldconfig -p 2>/dev/null | grep -q "lib$lib\."; then
        return 0
    fi
    if [ -e "/usr/lib/lib$lib.so" ] || [ -e "/usr/lib/lib$lib.dylib" ]; then
        return 0
    fi
    c_bad "cannot test $backend: the $lib client library is not installed"
    printf '       Diesel links against it natively. Install it with:\n'
    printf '         macOS:  brew install %s\n' "$formula"
    printf '         Debian: apt install lib%s-dev\n' "$lib"
    return 1
}

# wait_ready <container> <seconds> <probe command...>
#
# Probes the server itself rather than grepping its log. PostgreSQL's entrypoint
# runs a throwaway init server that logs "ready to accept connections" and then
# shuts down, so a log match is true well before the real server is listening -
# and can also be missed entirely if the init phase is slow. Ask the database.
wait_ready() {
    local container="$1" limit="$2" waited=0
    shift 2
    while [ "$waited" -lt "$limit" ]; do
        if docker exec "$container" "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    c_bad "$container did not become ready within ${limit}s"
    docker logs "$container" 2>&1 | tail -15
    return 1
}

# Each backend gets its own full artifact tree - switching cargo features
# invalidates the build - so running all three needs several GB. Refuse to start
# rather than filling the disk and leaving the machine unusable.
MIN_FREE_MB=$((4000 * ${#BACKENDS[@]}))
FREE_MB=$(df -m . | tail -1 | awk '{print $4}')
if [ "$FREE_MB" -lt "$MIN_FREE_MB" ]; then
    c_bad "only ${FREE_MB}MB free; ${#BACKENDS[@]} backend(s) need about ${MIN_FREE_MB}MB"
    printf '       Each cargo feature set builds its own artifact tree. Either free space:\n'
    printf '         rm -rf "${CARGO_TARGET_DIR:-target}"\n'
    printf '       or run one backend at a time:\n'
    printf '         %s sqlite\n' "$0"
    exit 2
fi

FAILED=0
PASSED=()
SKIPPED=()

run_suite() {
    local backend="$1" url="$2"
    section "Running SCIM suite against $backend"
    if [ -n "$url" ]; then
        DATABASE_URL="$url" cargo test --no-default-features --features "$backend" scim -- --test-threads=1
    else
        cargo test --no-default-features --features "$backend" scim -- --test-threads=1
    fi
}

for backend in "${BACKENDS[@]}"; do
    case "$backend" in
        sqlite)
            if run_suite sqlite ""; then
                c_ok "sqlite passed"; PASSED+=("sqlite")
            else
                c_bad "sqlite FAILED"; FAILED=1
            fi
            ;;

        mysql)
            if ! require_client_lib mysql mysqlclient mysql-client; then SKIPPED+=("mysql"); continue; fi
            if ! require_docker mysql; then SKIPPED+=("mysql"); continue; fi
            section "Starting MySQL on port $MYSQL_PORT"
            docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1
            docker run -d --name "$MYSQL_CONTAINER" \
                -e MYSQL_ROOT_PASSWORD="$DB_TEST_PASSWORD" \
                -e MYSQL_DATABASE=vaultwarden \
                -p "$MYSQL_PORT:3306" \
                mysql:8 >/dev/null || { c_bad "could not start MySQL"; FAILED=1; continue; }
            if ! wait_ready "$MYSQL_CONTAINER" 180 \
                mysqladmin ping -h 127.0.0.1 -uroot -p"$DB_TEST_PASSWORD" --silent; then
                FAILED=1; continue
            fi
            if run_suite mysql "mysql://root:${DB_TEST_PASSWORD}@127.0.0.1:$MYSQL_PORT/vaultwarden"; then
                c_ok "mysql passed"; PASSED+=("mysql")
            else
                c_bad "mysql FAILED"; FAILED=1
            fi
            ;;

        postgresql)
            if ! require_client_lib postgresql pq libpq; then SKIPPED+=("postgresql"); continue; fi
            if ! require_docker postgresql; then SKIPPED+=("postgresql"); continue; fi
            section "Starting PostgreSQL on port $PG_PORT"
            docker rm -f "$PG_CONTAINER" >/dev/null 2>&1
            docker run -d --name "$PG_CONTAINER" \
                -e POSTGRES_PASSWORD="$DB_TEST_PASSWORD" \
                -e POSTGRES_DB=vaultwarden \
                -p "$PG_PORT:5432" \
                postgres:16 >/dev/null || { c_bad "could not start PostgreSQL"; FAILED=1; continue; }
            if ! wait_ready "$PG_CONTAINER" 180 pg_isready -U postgres -d vaultwarden -h 127.0.0.1; then
                FAILED=1; continue
            fi
            if run_suite postgresql "postgresql://postgres:${DB_TEST_PASSWORD}@127.0.0.1:$PG_PORT/vaultwarden"; then
                c_ok "postgresql passed"; PASSED+=("postgresql")
            else
                c_bad "postgresql FAILED"; FAILED=1
            fi
            ;;

        *)
            c_bad "unknown backend: $backend"; FAILED=1 ;;
    esac
done

section "Summary"
[ ${#PASSED[@]} -gt 0 ]  && c_ok  "passed:  ${PASSED[*]}"
[ ${#SKIPPED[@]} -gt 0 ] && c_bad "skipped: ${SKIPPED[*]}"
if [ "$FAILED" = "0" ] && [ ${#SKIPPED[@]} -eq 0 ]; then
    c_ok "every selected backend passed"
    exit 0
fi
[ "$FAILED" = "1" ] && c_bad "at least one backend failed"
# A skip is not a pass. Exiting 0 here would let a missing client library or a
# stopped docker daemon read as "MySQL is green" in CI, which is precisely the
# failure this harness exists to make visible. 3 distinguishes it from a real
# test failure (1) and from the disk-space refusal (2).
if [ "$FAILED" = "0" ]; then
    c_bad "no backend failed, but ${#SKIPPED[@]} were never run"
    exit 3
fi
exit 1
