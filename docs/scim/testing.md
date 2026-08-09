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

**There is no self-hostable Entra ID.** Microsoft ships no emulator, so you
cannot run one in Docker. What you can do is test in rungs of increasing cost,
and only the last one needs a tenant.

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

## Rung 2 - replay Entra's requests at a running server

```bash
tools/scim-entra-replay.sh \
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

Rung 1 covers the documented provisioning cycle for Okta, AWS IAM Identity
Center and Google Workspace as well as Entra: the import probe, the create
payload each engine sends, its deactivation form, group membership, and the
lossless reactivation. Those tests are written from published vendor
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

## Rung 4 - a throwaway Entra tenant

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

## What about self-hosted IdPs?

Authentik, Keycloak with a SCIM plugin, and similar can act as SCIM clients
against your endpoint. Be clear about what that buys you: they validate **RFC
7643/7644 spec compliance**, not **Entra compatibility**. They send textbook
SCIM, never the quirks above - which are already covered by rung 1. For this
implementation they add little over rungs 1-3.

---
