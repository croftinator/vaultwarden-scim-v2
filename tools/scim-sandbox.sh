#!/usr/bin/env bash
#
# Stand up a Vaultwarden you can actually click around in, backed by PostgreSQL,
# reachable by the real Bitwarden clients.
#
# This is the manual counterpart to the automated rungs in docs/scim/testing.md.
# Those prove the endpoint answers correctly; none of them can tell you whether
# the feature is usable, because the part SCIM cannot automate - a member
# accepting an invite and an Owner confirming them - requires a real client
# holding real key material. See "Core design decision" in CLAUDE.md.
#
# Usage:
#   tools/scim-sandbox.sh              # bring it up (idempotent)
#   tools/scim-sandbox.sh --down       # stop the server and containers, KEEP data
#   tools/scim-sandbox.sh --purge      # destroy everything, including the database
#   tools/scim-sandbox.sh --status     # what is running, and where
#
# Environment:
#   SANDBOX_DIR   Where config, certs and attachments live.
#                 Default $HOME/vaultwarden-sandbox - deliberately OUTSIDE the
#                 repository, so no generated token can ever be committed and no
#                 .gitignore entry is needed. The fork keeps its surface small.
#   VW_BIN        The server binary. Default honours CARGO_TARGET_DIR, which is
#                 a common local setting and puts the binary nowhere near ./target.
#
# Requires: docker, curl, mkcert. The binary must already be built.
#
# Windows: run this under WSL2 with Docker Desktop's WSL integration, not in
# PowerShell - it is bash, and the rest of tools/ assumes the same. Note that
# `mkcert -install` must then be run TWICE if you want the Windows-side clients
# to work: once inside WSL for anything running there, and once in an elevated
# PowerShell for the Windows trust store that the desktop app and browser read.
# They are separate stores and neither sees the other.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX_DIR="${SANDBOX_DIR:-$HOME/vaultwarden-sandbox}"
COMPOSE="$REPO_ROOT/tools/local-stack/docker-compose.yml"
VW_BIN="${VW_BIN:-${CARGO_TARGET_DIR:-$REPO_ROOT/target}/ci/vaultwarden}"

# Must match tools/local-stack/docker-compose.yml. Overridable there and here
# together, not one without the other.
PG_PORT="${PG_PORT:-15433}"
PG_USER="${PG_USER:-vaultwarden}"
PG_PASS="${PG_PASS:-vwscim}"
PG_DB="${PG_DB:-vaultwarden}"
DB_URL="postgresql://$PG_USER:$PG_PASS@127.0.0.1:$PG_PORT/$PG_DB"
PORT="${PORT:-8000}"

say()  { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m%s\033[0m\n' "$1"; }
warn() { printf '  \033[33m%s\033[0m\n' "$1"; }
die()  { printf '  \033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

# Stops only the server THIS sandbox started, via a pidfile.
#
# Two earlier attempts were both wrong, and the reasons are worth keeping:
#
#   pkill -f vaultwarden   also matched the shell that invoked this script,
#                          because VW_BIN appears in its command line. The
#                          script SIGTERMed itself and it looked like a hang.
#   pkill -x -f "$VW_BIN"  fixed that, but every sandbox on the machine runs
#                          the same binary with no arguments, so bringing one
#                          up silently killed another on a different port.
#
# A pidfile is the only thing that distinguishes them, since the command lines
# are identical by construction.
PIDFILE="$SANDBOX_DIR/vw.pid"
stop_server() {
    [ -f "$PIDFILE" ] || return 0
    local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    # Confirm the pid is still OUR server before signalling it: pids are
    # recycled, and killing an unrelated process would be worse than leaving a
    # stale one running.
    if [ -n "$pid" ] && ps -p "$pid" -o command= 2>/dev/null | grep -qF "$VW_BIN"; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do ps -p "$pid" >/dev/null 2>&1 || break; sleep 0.5; done
    fi
    rm -f "$PIDFILE"
}

case "${1:-up}" in
    --down)
        stop_server
        docker compose -f "$COMPOSE" down >/dev/null 2>&1 || true
        say "Stopped. The database volume is kept - --purge removes it."
        exit 0 ;;
    --purge)
        stop_server
        docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true
        rm -rf "$SANDBOX_DIR"
        say "Purged: containers, database volume and $SANDBOX_DIR."
        echo "  The mkcert CA is left installed; remove it with 'mkcert -uninstall'."
        exit 0 ;;
    --status)
        docker compose -f "$COMPOSE" ps 2>/dev/null || true
        if [ -f "$SANDBOX_DIR/vw.pid" ] && ps -p "$(cat "$SANDBOX_DIR/vw.pid")" >/dev/null 2>&1; then
            ok "server running (pid $(cat "$SANDBOX_DIR/vw.pid"))"
        else
            warn "server not running"
        fi
        [ -f "$SANDBOX_DIR/.env" ] && ok "config: $SANDBOX_DIR/.env" || warn "no config yet"
        exit 0 ;;
    up|"") ;;
    *) die "unknown argument: $1 (see --help in the header)" ;;
esac

# ---------------------------------------------------------------------------
say "1. Preflight"
# ---------------------------------------------------------------------------
for t in docker curl; do command -v "$t" >/dev/null || die "'$t' is required"; done
docker info >/dev/null 2>&1 || die "docker is installed but not running"
# Checked before anything is created, so a missing toolchain does not leave a
# half-built sandbox behind.
[ -x "$VW_BIN" ] || die "no binary at $VW_BIN
       Build it first (PostgreSQL, so libpq must be linkable):
         export LIBRARY_PATH=/opt/homebrew/opt/libpq/lib:\${LIBRARY_PATH:-}
         export PKG_CONFIG_PATH=/opt/homebrew/opt/libpq/lib/pkgconfig:\${PKG_CONFIG_PATH:-}
         cargo build --profile ci --no-default-features --features postgresql
       Migrations are embedded at COMPILE time (src/db/mod.rs, embed_migrations!),
       so rebuild after any change under migrations/ or the binary silently
       applies the set it was built with."
command -v mkcert >/dev/null || die "mkcert is required.
       The Bitwarden desktop app and browser extension refuse a plain-http
       server URL outright, with no localhost exemption, so TLS is mandatory
       rather than optional here.

         macOS    brew install mkcert nss
         Debian   apt install libnss3-tools  +  mkcert from its GitHub releases
         Fedora   dnf install mkcert nss-tools
         Arch     pacman -S mkcert nss
         Windows  choco install mkcert   (or: scoop install mkcert)

       The nss/nss-tools package is only needed for Firefox, which keeps its own
       trust store and ignores the system one."
ok "docker, binary and mkcert present"
mkdir -p "$SANDBOX_DIR/data"

# ---------------------------------------------------------------------------
say "2. PostgreSQL and Mailpit"
# ---------------------------------------------------------------------------
docker compose -f "$COMPOSE" up -d >/dev/null 2>&1 || die "compose up failed"
for _ in $(seq 1 40); do
    docker compose -f "$COMPOSE" exec -T postgresql \
        pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 && break
    sleep 2
done
docker compose -f "$COMPOSE" exec -T postgresql \
    pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 \
    || die "PostgreSQL never became ready"
ok "PostgreSQL on $PG_PORT, Mailpit on 8025"

# ---------------------------------------------------------------------------
say "3. Web vault"
# ---------------------------------------------------------------------------
# The web vault is a gitignored download, not source. It ships as an image
# pinned BY DIGEST in the Dockerfile, and that digest is read from there rather
# than copied here on purpose: a second copy drifts silently the first time
# upstream bumps the vault, and you would then be clicking through a different
# build than the image ships. Same reasoning as vendoring the Authentik compose
# file instead of curling it at run time.
if [ -d "$REPO_ROOT/web-vault" ]; then
    ok "already extracted ($(find "$REPO_ROOT/web-vault" -type f | wc -l | tr -d ' ') files)"
else
    DIGEST="$(grep -oE 'vaultwarden/web-vault@sha256:[a-f0-9]{64}' \
        "$REPO_ROOT/docker/Dockerfile.debian" | head -1)"
    [ -n "$DIGEST" ] || die "could not read the web-vault digest from docker/Dockerfile.debian.
       Upstream probably restructured that file. Fix the grep rather than
       hardcoding a digest here."
    echo "  pulling $DIGEST"
    # linux/amd64 on an arm64 host is correct and deliberate: the container is
    # never RUN, only copied out of, so the architecture of its (nonexistent)
    # entrypoint is irrelevant. Do not "fix" this to the host platform - the
    # published vault image has no arm64 variant.
    docker pull --platform=linux/amd64 "docker.io/$DIGEST" >/dev/null 2>&1 \
        || die "could not pull the web-vault image"
    CID="$(docker create --platform=linux/amd64 "docker.io/$DIGEST")"
    docker cp "$CID:/web-vault" "$REPO_ROOT/web-vault" >/dev/null
    docker rm "$CID" >/dev/null
    ok "extracted to web-vault/ (gitignored)"
fi

# ---------------------------------------------------------------------------
say "4. TLS"
# ---------------------------------------------------------------------------
CAROOT="$(mkcert -CAROOT)"
if [ ! -f "$SANDBOX_DIR/tls-cert.pem" ]; then
    ( cd "$SANDBOX_DIR" && mkcert -cert-file tls-cert.pem -key-file tls-key.pem \
        localhost 127.0.0.1 ::1 >/dev/null 2>&1 ) || die "mkcert could not issue a certificate"
    ok "certificate issued for localhost"
else
    ok "certificate already present"
fi
# `mkcert -install` needs sudo, so it cannot run unattended - and without it the
# clients see an untrusted issuer even though the URL is https. Report the state
# rather than pretending, because "TLS is configured" and "the desktop app will
# accept it" are two different facts.
#
# Probed per platform where a cheap reliable check exists. Where one does not,
# the state is reported as UNKNOWN rather than guessed: claiming "trusted" and
# being wrong sends you debugging the server when the problem is the client's
# trust store.
CA_TRUSTED=unknown
case "$(uname -s)" in
    Darwin)
        security verify-cert -c "$CAROOT/rootCA.pem" >/dev/null 2>&1 \
            && CA_TRUSTED=yes || CA_TRUSTED=no ;;
    Linux)
        # What mkcert writes on Debian/Ubuntu and on Fedora respectively.
        if compgen -G "/usr/local/share/ca-certificates/mkcert*" >/dev/null 2>&1 \
        || compgen -G "/etc/pki/ca-trust/source/anchors/mkcert*" >/dev/null 2>&1; then
            CA_TRUSTED=yes
        else
            CA_TRUSTED=no
        fi ;;
    MINGW*|MSYS*|CYGWIN*)
        # Git Bash / MSYS. Reading the Windows certificate store from here is
        # more trouble than it is worth, so say so plainly.
        CA_TRUSTED=unknown ;;
esac
case "$CA_TRUSTED" in
    yes)     ok   "local CA is trusted by the system" ;;
    no)      warn "local CA is NOT trusted yet - see the note at the end" ;;
    unknown) warn "cannot tell whether the local CA is trusted on this platform - see the note at the end" ;;
esac

# ---------------------------------------------------------------------------
say "5. Configuration"
# ---------------------------------------------------------------------------
# Written once and then left alone. Regenerating would rotate ADMIN_TOKEN and
# invalidate whatever the last session set up, which is exactly the surprise a
# sandbox should not spring on you. Delete the file to start over.
if [ -f "$SANDBOX_DIR/.env" ]; then
    ok "keeping existing $SANDBOX_DIR/.env (delete it to regenerate)"
else
    ADMIN_TOKEN="$(openssl rand -base64 48 | tr -d '\n')"
    cat > "$SANDBOX_DIR/.env" <<EOF
# Vaultwarden SCIM sandbox - local throwaway, generated by tools/scim-sandbox.sh.
# Lives outside the repository so nothing here can be committed.

DATA_FOLDER=$SANDBOX_DIR/data
DATABASE_URL=$DB_URL

ROCKET_PORT=$PORT
ROCKET_ADDRESS=0.0.0.0
ROCKET_TLS={certs="$SANDBOX_DIR/tls-cert.pem",key="$SANDBOX_DIR/tls-key.pem"}

# Invite links, SCIM Location headers and meta.location are all built from this,
# so it must match how clients actually reach the server.
DOMAIN=https://localhost:$PORT

WEB_VAULT_ENABLED=true
WEB_VAULT_FOLDER=$REPO_ROOT/web-vault
SIGNUPS_ALLOWED=true

SCIM_ENABLED=true
ORG_GROUPS_ENABLED=true
# Without this, SCIM changes leave no audit trail and the server says so at
# startup. The org event log is how you see what a sync actually did.
ORG_EVENTS_ENABLED=true

# Mailpit. Nothing leaves the machine, so provisioned users can be fake
# addresses with no real mailbox - and the one-time code that Part B of
# docs/scim/setup.md needs to mint a SCIM token arrives there too.
SMTP_HOST=127.0.0.1
SMTP_PORT=1025
SMTP_SECURITY=off
SMTP_FROM=vaultwarden@example.com

ADMIN_TOKEN=$ADMIN_TOKEN
EOF
    chmod 600 "$SANDBOX_DIR/.env"
    ok "wrote $SANDBOX_DIR/.env with a fresh ADMIN_TOKEN"
fi

# ---------------------------------------------------------------------------
say "6. Server"
# ---------------------------------------------------------------------------
stop_server
sleep 1
( cd "$SANDBOX_DIR" && set -a && . ./.env && set +a && nohup "$VW_BIN" > vw.log 2>&1 & echo $! > "$PIDFILE" )
PROBE=(curl -sf -o /dev/null)
[ -f "$CAROOT/rootCA.pem" ] && PROBE+=(--cacert "$CAROOT/rootCA.pem")
UP=0
for _ in $(seq 1 40); do
    "${PROBE[@]}" "https://localhost:$PORT/alive" && { UP=1; break; }
    sleep 1
done
[ "$UP" -eq 1 ] || { tail -20 "$SANDBOX_DIR/vw.log"; die "server did not come up"; }
ok "listening on https://localhost:$PORT"

# ---------------------------------------------------------------------------
printf '\n'
say "Ready"
cat <<EOF

  Web vault      https://localhost:$PORT
  Admin panel    https://localhost:$PORT/admin
  Mail           http://localhost:8025          (every invite lands here)
  PostgreSQL     127.0.0.1:$PG_PORT  user/db: $PG_USER / $PG_DB
                 password: the PG_PASS default in tools/local-stack/docker-compose.yml,
                 or read the full URL from the config below

  Config         $SANDBOX_DIR/.env
  Server log     $SANDBOX_DIR/vw.log
  ADMIN_TOKEN    grep ADMIN_TOKEN $SANDBOX_DIR/.env

EOF
if [ "$CA_TRUSTED" != "yes" ]; then
    cat <<'EOF'
  ONE STEP LEFT - the Bitwarden clients reject the certificate until the local
  CA is trusted. That writes to a system trust store, so it needs elevation and
  cannot be scripted unattended:

      mkcert -install

    macOS    prompts for your password (adds to the System keychain)
    Linux    prompts via sudo; install libnss3-tools / nss-tools first or
             Firefox and Chrome will still refuse it
    Windows  run the shell as Administrator, or accept the UAC prompt

  Undo at any time with 'mkcert -uninstall'.

  Restart the Bitwarden desktop app afterwards - it reads the trust store at
  startup and will keep rejecting the certificate until it does.

EOF
fi
cat <<EOF
  Next: register at https://localhost:$PORT, create an organization, then mint a
  SCIM token following Part B of docs/scim/setup.md - the one-time code it emails
  arrives in Mailpit. The full walkthrough, including what SCIM cannot do on its
  own, is in docs/scim/testing.md under "The manual sandbox".
EOF
