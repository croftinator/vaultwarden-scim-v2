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

## Rung 1 - the test suite (seconds, no setup)

```bash
cargo test --features sqlite
```

Runs the real Rocket router against a temporary SQLite database in-process.
Mail is intercepted by an in-process sink, so no message can leave the machine
even though the suite runs with mail enabled.

## Rung 1b - every backend (minutes, needs Docker)

```bash
tools/scim-test-backends.sh                 # sqlite, MySQL and PostgreSQL
tools/scim-test-backends.sh postgresql      # just one
```

Three dialects ship and they genuinely differ - upsert semantics, foreign-key
enforcement, timestamp precision and default collation case-sensitivity. This
starts MySQL 8 and PostgreSQL 16 in Docker, migrates each from scratch, runs the
suite, and tears them down. A green SQLite run says nothing about the other two.
These tests encode Entra's actual quirks - `"Replace"` op casing, string
booleans, path-less value objects, `members[value eq "..."]` removal - so they
are a closer stand-in for Entra than any generic SCIM tool. Run this first and
after every change.

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
