# Testing this implementation

The suite proves three separate things, which need three different kinds of
test. Keep the distinction when adding coverage, because it is easy to write a
third green-path test and believe it bought something:

1. **Correctness** - it does what the RFCs and Entra expect (green paths).
2. **Security** - it refuses what it should, in every order (red paths).
3. **Robustness** - it survives partial failure, misconfiguration, concurrency,
   and people doing things out of order, without manual database surgery.

Design rationale for individual decisions lives in
[design.md](design.md#test-strategy).

**None of the three big providers can be run locally.** Entra ID, Okta and
Google Workspace ship no container, no emulator and no local mode - the
provisioning engine *is* the SaaS product, welded to their identity backends, so
there is nothing to hand out. (AWS IAM Identity Center is not on that list
because it is not a provisioning source at all: it is a SCIM *server*, and
cannot drive this endpoint in any deployment. See "does NOT work, and why" in
[providers.md](providers.md).) Microsoft's hosted
[SCIM Validator](https://scimvalidator.microsoft.com) is the only vendor tool
that helps, and it needs a public endpoint and an interactive sign-in, so it
cannot run unattended either.

That is why **Authentik** matters out of proportion to its market share: it is
self-hostable, so it is the only real provisioning engine CI can drive. It will
never reproduce Entra's quirks, but it is the one place where software nobody
here wrote decides what to send. Full reasoning and the coverage table are in
[providers.md](providers.md).

So: test in rungs of increasing cost, and only the last one needs a tenant.

## What the suite contains

`cargo test --features sqlite` builds 193 tests. 164 are SCIM's; the other 29
are upstream's and are unrelated to this feature.

| Where | Count | What it covers |
|---|---|---|
| `src/api/scim/tests/mod.rs` | 127 | End-to-end over HTTP through the real Rocket router and a real database, including the documented provisioning cycle of all four major providers |
| `src/api/scim/patch.rs` | 20 | The PATCH parser: op casing, string booleans, path-less values, member filters |
| `src/api/scim/filter.rs` | 4 | The `eq` filter parser, including a 20,000-case fuzz pass |
| `src/api/scim/error.rs` | 4 | Every error is a well-formed SCIM envelope with the RFC-sanctioned status |
| `src/api/scim/users.rs` | 3 | The revocation-offset predicates, in isolation from HTTP |
| `src/api/scim/guard.rs` | 3 | Bearer token parsing and its rejection shapes |
| `src/api/scim/models.rs` | 3 | Entra's boolean coercion and displayName composition |

The integration tests are the load-bearing ones. They drive real HTTP requests
at the real router, with a real database underneath and real migrations applied,
so a test passing means the endpoint works rather than that a function returns
what it was told to. Mail is intercepted by an in-process sink, so nothing can
leave the machine even though the suite runs with mail enabled.

## Rung 1 - the suite on SQLite (seconds, no setup)

```bash
cargo test --features sqlite
```

SQLite needs no server: its URL is derived from a hermetic `DATA_FOLDER` created
per run. This is the fast loop and what you run constantly.

## Rung 1b - every backend (minutes, needs Docker)

```bash
tools/scim-test-backends.sh                 # sqlite, MySQL and PostgreSQL
tools/scim-test-backends.sh postgresql      # just one
```

Three dialects ship and they genuinely differ - upsert semantics, foreign-key
enforcement, timestamp precision, default collation case-sensitivity, and how
much of an index key they will accept. A green SQLite run says nothing about the
other two, and the migrations in particular are per-dialect: a failure there
leaves the server unable to start at all, because migrations run at pool
construction before Rocket listens.

The script starts MySQL 8 and PostgreSQL 16 in Docker, applies the migrations
from scratch, runs the suite, and tears the containers down.

### Running one backend by hand

The script is a convenience, not a requirement. Any reachable server works, and
the suite decides which backend to use from `DATABASE_URL`:

```bash
docker run -d --name vw-pg -e POSTGRES_HOST_AUTH_METHOD=trust \
    -e POSTGRES_DB=vaultwarden -p 5432:5432 postgres:16

DATABASE_URL="postgresql://postgres@127.0.0.1:5432/vaultwarden" \
    cargo test --no-default-features --features postgresql
```

On macOS the client libraries are keg-only, so a build against MySQL or
PostgreSQL needs their paths exported first - `require_client_lib` in
`tools/scim-test-backends.sh` shows exactly which variables, and is easier to
copy than to rediscover.

### When a backend has no server

Every test in the module needs a connection, so without one they would all fail
for the same uninteresting reason. Instead the suite skips itself and says so:

```
SKIP: this backend needs a live server. Run tools/scim-test-backends.sh, or set DATABASE_URL.
```

You get one clear line instead of 117 panics burying whatever you were working
on. The tell is the clock: a real run takes 15 seconds, a skipped one takes 1.

Rust's harness has no runtime "skipped" state, so those skips are counted as
passes - which would be a green build that verified nothing. `SCIM_TESTS_REQUIRE_DB`
exists for that: when set, a missing database is a hard failure instead of a
skip. CI sets it (see below), so nobody can accidentally ship a step that passes
by testing nothing.

## Rung 1c - other server configurations (seconds)

```bash
tools/scim-test-config-matrix.sh            # currently: SSO_ONLY=true
```

`CONFIG` is resolved once, before `main`, so a single test binary can only ever
observe one value for a given setting. Anything read by non-SCIM code - the
invite mail's `orgSsoIdentifier` under `SSO_ONLY`, for instance - therefore has
a branch the ordinary run can never reach. This re-runs the affected tests with
a different environment.

Worth knowing: the `SSO_ONLY` test cross-checks the value it requested against
what `CONFIG` reports, so if the override ever stops working the pass fails
loudly instead of quietly testing the same branch twice.

## Fast feedback: which loop to use when

Three loops, each roughly an order of magnitude slower and broader than the one
above it. Use the cheapest one that could plausibly catch what you just changed,
and let the slower ones run behind you.

| Loop | Time | Covers | Use it |
|---|---|---|---|
| `cargo test --features sqlite` locally | ~20s warm | Everything on SQLite, one toolchain | Constantly, while editing |
| **SCIM tests** workflow (`scim-tests.yml`) | **1.9 min** | Same, in a clean CI environment, plus `cargo fmt` | Every push, automatically |
| **Build** workflow (`build.yml`) | **~12 min** | 2 toolchains, 6 feature sets, real MySQL and PostgreSQL, clippy | The merge gate |

Those are measured, not estimated: 1.9 and 12.3 minutes on the same commit.

### Why the gate takes twelve minutes

Almost none of it is testing. The 193 tests run in about 17 seconds; the rest is
compiling the crate **six times**. Each `cargo test --features X` uses a
different feature set, which changes codegen, so the previous build's cache
cannot be reused:

| Step | Time |
|---|---|
| First combo (cold) | 3.0 min |
| Five further combos | ~1.3 min each |
| clippy | 1.4 min |
| Container startup, checkout, toolchain, cache | ~2 min |

That is the right trade for a gate and the wrong one for the edit-run loop,
which is why the fast workflow exists rather than the gate being trimmed.

### What the fast workflow deliberately does not prove

One toolchain, one backend, no clippy, and no cross-dialect migration check. A
green SCIM-tests run means "worth waiting for the real gate", not "ready to
merge". In particular it cannot catch:

- A migration that works on SQLite and fails on MySQL or PostgreSQL - which is
  the failure that leaves a server unable to start, since migrations run at pool
  construction before Rocket listens.
- A build that breaks on the declared MSRV. This has happened: a type-inference
  difference between 1.95 and 1.97 sat undetected for two weeks because nothing
  had run the older toolchain.
- A clippy lint, which is `-D warnings` in CI and so fails the gate.

### The faster option that was rejected

Turning `build.yml`'s six feature combinations into a matrix axis would run them
as parallel jobs and cut the gate from about twelve minutes to about five. It was
not done, and the reason is worth recording so it is not repeatedly rediscovered:
it restructures the single workflow file upstream edits most often, and this fork
merges from upstream regularly. A seven-minute saving is not worth a merge
conflict on every `sync-upstream`, forever. Adding a new file costs nothing,
because upstream will never touch it.

If you want faster local iteration instead, narrow the run rather than the
coverage - `cargo test --features sqlite scim::` skips the upstream tests, and
naming a single test skips almost all of the work.

## What CI runs

`.github/workflows/build.yml` runs the suite on every push and pull request,
across two toolchains (the pinned `rust-toolchain` version and the declared
MSRV) and six feature combinations. All three backends are covered for real:

| Step | Database |
|---|---|
| `sqlite,mysql,postgresql,enable_mimalloc,s3` | SQLite (no `DATABASE_URL` set) |
| `sqlite,mysql,postgresql,enable_mimalloc` | SQLite |
| `sqlite,mysql,postgresql` | SQLite |
| `sqlite` | SQLite |
| `mysql` | **MySQL 8 service container** |
| `postgresql` | **PostgreSQL 16 service container** |

The combined steps exercise SQLite because no `DATABASE_URL` is set and that is
what Vaultwarden falls back to; the two single-backend steps each get a service
container and a `DATABASE_URL` pointing at it. Applying the migrations against a
real server on every run is half the point - the SCIM migrations differ per
dialect and no SQLite run can catch a fault in them.

The containers are password-less on purpose. They are ephemeral, bound to the
runner's localhost, and destroyed with it, so there is no credential to protect
and no connection-string-shaped literal in the repository for a secret scanner
to trip over.

`SCIM_TESTS_REQUIRE_DB` is set for the whole job, so if a container fails to
start or a `DATABASE_URL` stops reaching a step, the build goes red instead of
skipping its way to a green that proved nothing.

`.github/workflows/scim-tests.yml` is the fast counterpart described above: one
feature set, SQLite, plus `cargo fmt`, in under two minutes. It sets
`SCIM_TESTS_REQUIRE_DB` too - SQLite needs no server, so a skip there would mean
the guard itself broke and should fail rather than pass quietly. Its cache key is
deliberately different from `build.yml`'s: that job compiles six feature sets and
this one compiles a single different set, so a shared key would mean each evicts
the other and neither hits.

CI does **not** run rungs 2 to 4: they need a deployed instance or a tenant.

## Adding a test

Two conventions, both load-bearing:

**Take the guard, not the lock.** Start every integration test with:

```rust
let _guard = scim_test_guard!();
```

not `TEST_LOCK.lock().await`. The macro takes the same lock - the tests share one
database and must not interleave - and additionally skips when the backend has
no server, which is what keeps a MySQL run on a laptop from producing 117
identical panics.

**Prove the test can fail.** A test that passes against the bug it is meant to
catch is worse than no test, because it reports safety it never verified. Before
committing, break the thing deliberately and watch it go red:

```bash
# comment out the guard, or invert the condition, then:
cargo test --features sqlite the_name_of_your_test
```

Then restore it. Several tests in this suite exist because that step failed:
`an_unmanaged_group_cannot_be_deleted_through_scim` returned 204 without its
guard, and `post_groups_refuses_a_blank_or_missing_display_name` returned 201.
Where a test asserts a refusal, add the matching control that proves the
operation succeeds when it should - otherwise "refused" is equally explained by
the whole path being broken.

## Rung 2 - replay a provider's requests at a running server

```bash
tools/scim-replay.sh \
  --domain https://vault.example.com \
  --org    <org_uuid> \
  --token  scim_v1.<org_uuid>.<secret>
```

Fires Entra's exact payload shapes over real HTTP at a live instance and asserts
every response. Unlike rung 1 this exercises the parts only a deployment has:
your configured `DOMAIN`, TLS and reverse proxy, the rate limiter, and the
error catchers.

It covers discovery, the uniform-401 auth matrix, Entra's "Test Connection"
probe, provisioning, the PATCH quirks, filters and pagination, group member
diffs, revoke/restore, and enumeration safety. It exits non-zero if anything
fails, so it works in CI. Pass `--keep` to leave the test data in place for
inspection. Requires `curl` and `jq`.

Mint the token first (Part B). The script cleans up after itself by revoking the
member and deleting the test group; the shell account it creates remains, since
SCIM never deletes accounts.

## Other identity providers

Rung 1 covers the documented provisioning cycle for Okta and Google Workspace as
well as Entra, plus a strict spec-correct client that sends nothing beyond the
RFC baseline: the import probe, the create payload each engine sends, its
deactivation form, group membership, and the lossless reactivation. AWS IAM
Identity Center is deliberately absent - it is a SCIM server, not a client, and
cannot drive this endpoint at all. Those tests are written from published vendor
documentation rather than observed traffic, which is the same caveat the Entra
coverage carries. [providers.md](providers.md) states what "supported" is
verified to mean for each.

The replay script below is Entra-shaped, but most of what it fires is plain
SCIM 2.0, so it is still a useful smoke test against a live server for any
provider.

## Rung 3 - Microsoft SCIM Validator (no tenant needed)

<https://scimvalidator.microsoft.com> is Microsoft's hosted validator. It sends
Entra-shaped requests at your endpoint and reports compatibility, and it needs
only a Microsoft account sign-in - **no Entra ID P1/P2 licence and no enterprise
app**. Your endpoint must be publicly reachable over HTTPS.

This is the cheapest way to check Entra compatibility before committing to a
tenant.

## Rung 4 - a throwaway tenant with a real provider

Only a real tenant can validate the things that live in Entra rather than in
your endpoint: **assignment scoping** (Part D), initial versus incremental sync
cycles, the **nested-group** behaviour, attribute-mapping expressions, and
quarantine. Two constraints:

- **Automatic (SCIM) provisioning requires an Entra ID P1 or P2 licence.** On a
  free tenant the Provisioning blade will not offer *Automatic* mode at all. Use
  a P2 trial or a developer sandbox.
- Use a **throwaway tenant and a test organization**. Never production.

## Exposing a local server for rungs 3 and 4

Entra and the Validator must reach you over public HTTPS; `localhost` will not
do. A quick tunnel works:

```bash
cloudflared tunnel --url http://localhost:8000     # or: ngrok http 8000
```

Then set `DOMAIN` to the tunnel hostname and restart - SCIM `Location` headers,
`meta.location`, and invite links are all built from it.

> [!WARNING]
> A tunnel publishes your dev server to the internet. Before opening one:
> set `SIGNUPS_ALLOWED=false` (otherwise anyone can register an account),
> remove or rotate `ADMIN_TOKEN` (the `/admin` panel becomes publicly
> reachable), and use a throwaway database. Close the tunnel when you are done.

Local mail capture pairs well with this: point SMTP at
[Mailpit](https://github.com/axllent/mailpit)
(`docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit`, `SMTP_PORT=1025`)
and every invite is captured locally, so your Entra test users can be fake
addresses like `test1@example.com` with no real mailboxes.

## Rung 2b - a self-hosted provisioning engine (free, local, no tenant)

**This is the only rung that puts a real provisioning engine in front of the
endpoint, and it costs nothing.** An earlier version of this page said
self-hosted IdPs "add little over rungs 1-3". That was wrong, and running one
proved it.

You need a SCIM **client** - something that pushes to your endpoint. Many
self-hostable IdPs implement SCIM in the other direction (accepting provisioning
into themselves), which is useless here; Zitadel is the common trap.

| Option | Verdict |
|---|---|
| **Authentik** | Best choice. Native outbound SCIM provider, Docker Compose, free. Verified working against this implementation. |
| **midPoint** (Evolveum) | Heavier identity-governance tool with a SCIM connector. Closest to enterprise reconciliation behaviour, much bigger to stand up. |
| **Keycloak** | No outbound SCIM in core; depends on third-party plugins of varying maturity. |
| Zitadel | SCIM server, not client. Cannot drive your endpoint. |

### What a run against Authentik established

Verified 2026-08-09 against a local Vaultwarden on this branch: **46 SCIM
requests, zero 4xx, zero 5xx, zero server errors, and no code changes.**

**This now runs unattended in CI** (`provisioning-e2e.yml`, weekly and on
demand), where it makes 13 assertions and passes all of them - including two
straight against the database: that every membership row survived deprovisioning
rather than being deleted, and that the revoked member kept its `akey`. The
E2EE invariant the whole design rests on is therefore checked by a real
provisioning engine on a schedule, not just once by hand.

It drove the full lifecycle unprompted, on its own sync schedule:

- `GET /ServiceProviderConfig` - it reads discovery before provisioning, which
  the rung-1 tests treat as an endpoint rather than a dependency.
- `GET /Users?filter=userName eq ...` - the existence probe.
- `POST /Users`, then `PUT /Users/<id>` on later cycles. Worth noting: it
  **updates with PUT, not PATCH**, so the full-replace path carries real traffic
  rather than only test traffic.
- `POST /Groups` and `PATCH /Groups/<id>` for member sync.
- Deprovisioning via `active: false`. It never issued a single `DELETE` - the
  same soft-delete convention Entra, Okta and Google use.

The revoke/restore round trip behaved exactly as designed, and this is the part
worth checking yourself if you change that code: deactivating a user in the
directory left the membership row **present** with `status = -128` - the
revoked-Invited offset - and its `akey` intact. Reactivating returned it to
`status = 0`. Nothing was destroyed at any point, so a returning employee needs
no re-confirmation.

### What it did NOT establish

Being precise, because the temptation is to over-read a green run:

- **Not vendor compatibility.** Authentik sends textbook SCIM. It will never
  produce Entra's `"Replace"` casing or string booleans, or Okta's path-less
  deactivate. Those stay rung-1's job.
- **Not concurrency.** Three users and one group is too small to make Authentik
  parallelise, so the check-then-act races (last-owner revoke, externalId
  uniqueness) were not stressed. Forcing that needs a directory large enough to
  batch - a few hundred users - and is the obvious next experiment for anyone
  who wants to close that gap.

### Running it against PostgreSQL

The run described above used SQLite. Nothing about the harness requires that,
and a real deployment almost certainly will not - so the more representative
run puts a real provisioning engine in front of a real database. Rung 1b already
proves the dialects for the in-process suite; this is the same question one
level up.

Only the database moves. Authentik keeps its own PostgreSQL (it always had one,
in `tools/authentik/docker-compose.yml`); this adds a second, separate instance
for Vaultwarden, on port 15433 so it cannot collide with the throwaway container
`tools/scim-test-backends.sh` starts on 15432.

```bash
docker compose -f tools/local-stack/docker-compose.yml up -d

# macOS: libpq is keg-only, so the linker needs pointing at it
export LIBRARY_PATH=/opt/homebrew/opt/libpq/lib:${LIBRARY_PATH:-}
export PKG_CONFIG_PATH=/opt/homebrew/opt/libpq/lib/pkgconfig:${PKG_CONFIG_PATH:-}
cargo build --profile ci --no-default-features --features postgresql

PG='postgresql://vaultwarden:vwscim@127.0.0.1:15433/vaultwarden'
# Honour CARGO_TARGET_DIR if it is set - a shared target directory is a common
# local setting, and the binary is then not under ./target at all.
VW="${CARGO_TARGET_DIR:-target}/ci/vaultwarden"

# 0.0.0.0, not loopback: the Authentik containers have to reach it
DATABASE_URL="$PG" tools/ci-seed-vaultwarden.sh /tmp/vw "$VW" 0.0.0.0 > /tmp/seed.env
. /tmp/seed.env

SCIM_TOKEN="$TOKEN" tools/scim-authentik-e2e.sh \
    --domain http://host.docker.internal:8000 \
    --org "$ORG" --db "$PG"
```

`--db` takes either a SQLite file path or a `postgresql://` URL, and the
assertions are identical either way - every statement the harness runs is plain
`SELECT`/`UPDATE` with a join and a `LIKE`, so only the client binary differs.
It refuses to start if `psql` is missing or the URL is unreachable, for the same
reason it refuses when `sqlite3` is missing: an invariant check that silently
does not run, on a harness that still exits 0, is worse than no check at all.

Two things this does **not** cover. `tools/scim-owner-race.sh` is still
SQLite-only - it reads `vw-data/db.sqlite3` directly - so the last-owner
concurrency race is unproven on PostgreSQL, which is the backend whose locking
behaviour differs most and therefore the one where it would be most worth
knowing. And the Authentik job in `provisioning-e2e.yml` still runs SQLite only;
the PostgreSQL path above is a local run, not something CI does on a schedule.

### Vaultwarden's own database, hands on

The seeder writes an organization and a SCIM key straight into the database and
turns the web vault off, which is right for CI and useless for looking around.
For a browsable server on the same PostgreSQL, hand it the extra config and then
follow Part B of [setup.md](setup.md) to register an Owner and mint a token the
real way:

```bash
SEED_EXTRA_ENV='WEB_VAULT_ENABLED=true
SMTP_HOST=127.0.0.1
SMTP_PORT=1025
SMTP_SECURITY=off
SMTP_FROM=vaultwarden@example.com' \
DATABASE_URL="$PG" tools/ci-seed-vaultwarden.sh /tmp/vw-ui "$VW" 0.0.0.0
```

Mailpit catches every invite at <http://localhost:8025>, so provisioned users
can be fake addresses with no real mailboxes - the same trick the tunnel section
above uses, just wired in by default here.

## Rung 2c - concurrency stress (the races the suite cannot reach)

Two guards in this implementation are check-then-act: the last-owner revoke and
externalId uniqueness. The in-process suite cannot exercise either, because
Rocket's local client does not achieve true request concurrency - the dispatches
never interleave inside the read-then-write window. `tools/scim-owner-race.sh`
does it properly, against a real server over real HTTP with parallel connections.

Each trial seeds exactly two active Owners, fires two `DELETE` requests simultaneously at
the two different membership rows, and counts survivors. One survivor is correct;
**zero means the organization was stranded with no Owner at all.**

The result settles a question the unit test had to leave open:

| Build | Trials | Races |
|---|---|---|
| Mutex present (shipped) | 50 | **0** |
| Mutex removed (control) | 25 | **25 - every attempt** |

That is worth stating plainly: under genuine concurrency the race was not a
narrow window, it was the **default outcome**. Two parallel deprovisions of two
different Owners stranded the organization every single time. The mutex removes
it completely.

It also validates the method. A guard whose test cannot fail proves nothing, so
when the in-process test could not discriminate, the answer was to change the
instrument rather than to trust the reasoning.

```bash
SCIM_RACE_DIR=/path/to/throwaway-instance tools/scim-owner-race.sh 50
```

The directory needs `vw-data/db.sqlite3`, `org-id.txt` and `scim-token.txt`. It
writes to the database directly to seed each trial, so point it only at a local
throwaway instance.

**Still open:** the same treatment for externalId uniqueness under concurrent
creates, and for the multi-replica case, which no single-process lock can close.

### Standing one up

```bash
curl -fsSL -o docker-compose.yml https://goauthentik.io/docker-compose.yml
# set PG_PASS, AUTHENTIK_SECRET_KEY, AUTHENTIK_BOOTSTRAP_PASSWORD/TOKEN in .env
docker compose up -d
```

Then create a SCIM provider pointing at
`http://host.docker.internal:8000/scim/v2/<org_uuid>` with your bearer token,
bind it to an application, and assign users. On Docker Desktop
`host.docker.internal` is how the container reaches a Vaultwarden running on the
host; on Linux use the host's bridge address or run both in one network.

A shortcut for the endpoint side: the SCIM guard only needs an `organizations`
row and a `scim_api_key` row holding the sha256 of your secret, so you can seed
those directly with `sqlite3` and skip creating an account and organisation
through the web vault entirely.

---
