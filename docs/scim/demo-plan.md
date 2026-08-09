# Plan: a self-contained SCIM + SSO demo

**Status: proposed, not built.** This is a design document for `tools/scim-demo.sh`
and its supporting pieces. Phase 0 (the manual sandbox) exists; everything from
phase 1 on is unwritten. Update the status line as phases land.

## What it is for

One command that produces a running Vaultwarden with a populated organization, a
local identity provider doing **both** SSO and SCIM, and a guided webpage that
walks a visitor through the whole story - including, deliberately, the part SCIM
cannot do.

Two audiences, and they want different things from it:

- **A developer on this branch**, who needs to see a change work against real
  clients before believing the test suite.
- **A reviewer or an upstream maintainer**, who is being asked to accept a large
  feature and would reasonably like to watch it run rather than read 4,000 lines
  of documentation about it.

The second audience is the stronger argument for building this.

## The constraint that shapes the whole design

Every artifact worth demonstrating requires client-side cryptography. A
Vaultwarden account is end-to-end encrypted: the master password derives a master
key in the client, which protects a symmetric key and an RSA keypair, and the
server stores only blobs it cannot compute. This is the same wall the SCIM design
hits, documented in CLAUDE.md under "Core design decision".

| Artifact | Seedable by SQL? | How it must actually be made |
|---|---|---|
| Organization row, SCIM credential | Yes | Direct insert, as `tools/ci-seed-vaultwarden.sh` does |
| A user who can log in | **No** | Registered through a real client |
| Vault items and collections | **No** | Written by a logged-in client |
| Member at `Invited` | Yes, via SCIM | The IdP provisions it |
| Member at `Accepted` | **No** | The user accepts, in their own session |
| Member at `Confirmed` | **No** | An Owner confirms, wrapping the org key client-side |

So the seeder cannot be a SQL script. It has to drive a real client, and the
repository already contains one that does exactly this: the Playwright harness in
`playwright/`, with `tests/setups/user.ts`, `orgs.ts` and `sso.ts`.

That the demo's own tooling runs into the same wall the feature does is worth
saying out loud in the walkthrough. It is the most convincing possible
demonstration that the limitation is real rather than an implementation shortcut.

## Architecture

```
tools/scim-demo.sh                  orchestrator
  ├─ tools/scim-sandbox.sh          Vaultwarden + PostgreSQL + Mailpit + TLS   [EXISTS]
  ├─ tools/authentik/               IdP: OIDC for SSO, outbound SCIM           [exists, needs a persistent variant]
  ├─ playwright/tests/demo-seed/    registers users, creates org and items,
  │                                 accepts invites, confirms members          [new]
  └─ docs/demo/index.html           the guided walkthrough, served locally     [new]
```

### Why Authentik rather than Keycloak

Upstream's Playwright suite already ships a Keycloak environment
(`playwright/compose/keycloak`, `tests/setups/sso-setup.ts`), and for SSO alone
that is the lower-risk path - it is configured, working, and maintained upstream.

The demo should still use **Authentik**, because Authentik does SSO *and*
outbound SCIM from one directory. That is the shape this feature actually
targets: in a real deployment Entra is both the sign-in authority and the
provisioning source. A demo that used one system for sign-in and another for
provisioning would teach the wrong mental model, and the interesting behaviour -
a user who is provisioned, signs in via SSO, and is then deprovisioned at the
same source - would be impossible to show.

Keycloak stays exactly where it is, serving upstream's SSO tests. This adds
nothing to it and changes nothing about it.

## Phases

### Phase 1 - a persistent Authentik

`tools/authentik/docker-compose.yml` today is shaped for the e2e harness:
per-run port, per-run project name, torn down on exit. That is right for CI and
wrong for a demo you return to.

Add a persistent variant on a stable port with named volumes. Provision the OIDC
provider, the SCIM provider, the demo users and the demo groups through Authentik
**blueprints** so the stack comes up already configured, rather than needing the
API-call sequence `tools/scim-authentik-e2e.sh` performs at run time.

*Risk:* blueprint provisioning is the least certain part of this plan. If it
fights, fall back to replaying the same API calls the e2e harness already makes -
they are known to work, they are just slower and less declarative.

### Phase 2 - wire SSO

Point Vaultwarden at Authentik's OIDC issuer using the settings at
[src/config.rs:826-856](../../src/config.rs#L826-L856): `SSO_ENABLED`,
`SSO_AUTHORITY`, `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_PKCE`.

Leave `SSO_ONLY=false` on purpose, so the walkthrough can show master-password
sign-in and SSO side by side. `tools/scim-test-config-matrix.sh` already covers
the `SSO_ONLY=true` branch for tests; the demo is not the place to force it.

Both the browser and the Vaultwarden process must reach the issuer at the **same**
URL, or the issuer claim will not validate. With everything on the host this is
just `localhost`, which is simpler than the SCIM direction, where a containerised
Authentik has to reach the host via `host.docker.internal`.

### Phase 3 - the Playwright demo seeder

The largest piece. A new spec that reuses the existing setup helpers to:

1. Register the Owner and create the organization.
2. Create two or three collections and roughly fifteen realistic vault items, so
   the vault does not look empty.
3. Complete the lifecycle SCIM cannot: accept an invite as a provisioned user,
   then confirm that member as Owner.

Keep the interaction surface as small as it can be. Selectors against the web
vault are the fragile part of this whole plan, and every extra click is another
thing that breaks on a vault bump.

### Phase 4 - drive one SCIM cycle

Let Authentik provision its directory in, on its own schedule. Finish with
members deliberately spread across states - some `Invited`, some `Confirmed` via
phase 3, one revoked - so the walkthrough has real material to inspect rather
than a uniform list.

### Phase 5 - the walkthrough page

Static HTML in `docs/demo/`, served on a local port. One section per step:

1. Sign in with SSO.
2. See the members SCIM provisioned, and their states.
3. Deactivate a user in Authentik; watch access revoke.
4. Reactivate; show it was lossless - `akey` unchanged, no re-confirmation.
5. Why confirm is manual, with the E2EE explanation.

Every step carries the exact SQL to run alongside it, so a sceptic can verify the
claim against the database instead of trusting the UI. The revoke step should
show `status` moving to `-126` and make the point that revocation is an offset of
128 rather than a distinct value.

### Phase 6 - reset

`--reset` returns to the seeded state without a full rebuild. A demo you cannot
re-run is a demo you give exactly once, and the first thing anyone does after
watching a deprovision is ask to see it again.

## Risks, honestly

**Playwright against a pinned web vault.** Selectors break when the vault
changes. The vault is digest-pinned in `docker/Dockerfile.debian`, so a bump is a
deliberate act rather than a surprise - which makes breakage predictable, not
absent. Mitigation is to keep the seeder minimal and lean on upstream's helpers,
which upstream has an interest in keeping working.

**First-run cost.** Authentik's image is about 1.8GB and the Rust build is
minutes. Acceptable for a demo, but it needs narrated progress. Silence for four
minutes reads as a hang.

**Fork surface.** This is the largest fork-only addition so far. It touches
`tools/`, `playwright/` and `docs/` only - `src/` is untouched, so it adds nothing
to the code a maintainer would review for upstreaming. The counter-argument is
that it is still more to keep working across `sync-upstream`, and the
web-vault-selector dependency is genuinely new maintenance.

## Effort

| Phase | Rough size |
|---|---|
| 1 - persistent Authentik | half a day, blueprint provisioning is the unknown |
| 2 - SSO wiring | a couple of hours |
| 3 - Playwright seeder | a day, and the most likely to overrun |
| 4 - SCIM cycle | folds into the orchestrator |
| 5 - walkthrough page | half a day |
| 6 - reset | small once the rest exists |

## Open questions

- Should the demo ship a `docker compose` for Vaultwarden itself, so it runs with
  no Rust toolchain at all? That costs a twenty-minute image build on first run
  but removes the biggest barrier for a non-Rust reviewer. Currently the sandbox
  deliberately runs the binary on the host for fast iteration; the demo has the
  opposite priority, and the two may want different answers.
- Does the walkthrough page belong in this repository, or alongside the operator
  documentation it complements? Keeping it here means it is versioned with the
  code it demonstrates, which is the stronger argument.
