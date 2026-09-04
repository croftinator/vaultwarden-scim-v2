# Plan: a self-contained SCIM + SSO demo

**Status: phases 0-6 built and verified. Phase 7 (optional) not started.** This is a design
document for `tools/scim-demo.sh` and its supporting pieces. Update the status
line as phases land.

| Phase | State |
|---|---|
| 0 - manual sandbox | **Done** - `tools/scim-sandbox.sh` |
| 1 - persistent Authentik | **Done** - both blueprints apply, 5 users in 2 groups |
| 2 - SSO wiring | **Done** - `/identity/sso/prevalidate` returns a signed token |
| 3 - seeding | **Done** - Playwright registers, `bw` CLI fills the vault |
| 4 - SCIM cycle | **Done** - 4 Engineering users provisioned, Contractors correctly excluded |
| 5 - guided demo flow | **Done** - `docs/demo/index.html`, dependency-free |
| 6 - reset | **Done** - `tools/scim-demo.sh --reset`, verified reproducing the seeded state |
| 7 - animated walkthroughs | Not started. Slots exist in the page; recording is a human task |

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

### Phase 5 - the guided demo flow

Static HTML in `docs/demo/`, served on a local port. This is the piece someone
who has never seen the product is handed, so it has to work as a **script a
presenter can read aloud**, not a reference page. Each step states what to click,
what should happen, and why it matters - in that order, because an audience needs
the payoff before the mechanism.

The flow, timed for about fifteen minutes:

| # | Step | Where | The point |
|---|---|---|---|
| 1 | Sign in as the Owner with a master password | Web vault | Baseline: an ordinary encrypted vault |
| 2 | Show a few vault items and a collection | Web vault | There is real data here, not an empty shell |
| 3 | Sign out; sign in again via *Enterprise SSO* | Web vault | Authentik authenticates; Vaultwarden never sees the password |
| 4 | Show the directory in Authentik | Authentik | One IdP owns identity - the Entra shape |
| 5 | Trigger the SCIM sync | Authentik | Four Engineering users appear in Vaultwarden; Charles, a Contractor, does not |
| 6 | Look at the member list | Web vault | Everyone is **Invited**. This is the honest part |
| 7 | Open Ada's invite in Mailpit, accept it as Ada | Mailpit + 2nd browser profile | **Accepted** - only the user can do this |
| 8 | Confirm Ada as Owner | Web vault | **Confirmed**. The org key was wrapped in the browser, not the server |
| 9 | Deactivate Katherine in Authentik | Authentik | Access is gone within a sync cycle |
| 10 | Show the row still exists, `akey` intact | DBeaver | Revoked, not deleted - `status = -126` |
| 11 | Reactivate Katherine | Authentik | Back to Confirmed, no re-confirmation needed |
| 12 | Unlock the desktop app and browser extension | Desktop, extension | The same vault, everywhere |

Steps 6-8 are the heart of it and should not be rushed or apologised for. The
sequence *shows* why confirmation cannot be automated instead of asserting it,
and a viewer who watches the org key get wrapped in a browser understands the
zero-knowledge claim in a way no paragraph achieves.

Every step carries the exact SQL to run alongside it, so a sceptic can verify
against the database rather than trusting the UI:

```sql
SELECT u.email, uo.status, LEFT(uo.akey, 24) AS akey, uo.external_id
FROM users_organizations uo JOIN users u ON u.uuid = uo.user_uuid
ORDER BY u.email;
```

Step 10 in particular should show `status` moving to `-126` and make the point
that revocation is an **offset of 128**, not a distinct value - the single
easiest thing to get wrong when reading this schema.

The page needs a **prerequisites block** at the top (what is running, what to
open, which two browser profiles you need) and a **"if something looks stuck"**
section, because Authentik syncs on its own schedule and the commonest demo
failure is impatience rather than breakage.

#### Pre-pointing the clients, so nobody types a server URL on stage

Making a viewer configure a self-hosted server URL is the fastest way to lose
them, and step 12 otherwise opens with two minutes of settings navigation.

The general answer already exists and should not be duplicated here:
[client-rollout.md](client-rollout.md) covers doing this at fleet scale -
browser extension via enterprise browser policy, mobile via MDM AppConfig, CLI
via `bw config server`, and why the desktop app is the weak one with no
supported management interface for the server URL. The demo hit exactly that
limitation: the desktop app had to be pointed at the sandbox by hand.

What the demo needs on top is only the local, single-machine version:

- **Browser extension** - drop a Chrome/Edge managed-policy JSON into the
  local policy directory pointing at `https://localhost:8000`, so a fresh demo
  profile comes up pre-configured. This is the same mechanism as the fleet
  case, applied to one machine, and it is the one client where zero-touch is
  genuinely easy.
- **CLI** - `bw config server https://localhost:8000`, plus
  `NODE_EXTRA_CA_CERTS` pointing at the mkcert root, since Node does not read
  the system trust store.
- **Desktop** - accept that it is manual, and do it during setup rather than
  on stage. Seeding its data file is possible but version-fragile, and
  client-rollout.md already recommends against relying on it.
- **Web vault** - nothing to do; it is served by the server being demonstrated.

`tools/scim-demo.sh` should perform the extension and CLI steps and print a
single reminder for the desktop one, rather than pretending all four can be
automated.

### Phase 6 - reset

`--reset` returns to the seeded state without a full rebuild. A demo you cannot
re-run is a demo you give exactly once, and the first thing anyone does after
watching a deprovision is ask to see it again.

### Phase 7 - animated walkthroughs, one per client (advanced)

The written flow in phase 5 assumes someone is driving. The advanced version
records each step so the page can *show* the interaction, per client type -
because the four Bitwarden clients differ in exactly the places a newcomer gets
stuck, and "set the server URL before you log in" is much easier to demonstrate
than to describe.

| Client | What its clip must cover |
|---|---|
| **Web vault** | Sign-in, the member list and its status column, confirming a member |
| **Desktop app** | *Self-hosted* server URL **before** login - the step everyone misses - then unlock and sync |
| **Browser extension** | The same server-URL setting under a different menu, plus autofill on a demo site |
| **CLI** | `bw config server`, `bw login`, `bw list items` - the scriptable path, and where `NODE_EXTRA_CA_CERTS` is needed |

Recommended shape, in order of preference:

1. **Recorded terminal for the CLI.** `asciinema` output is text, so it stays
   diffable, tiny, and copy-pasteable by the viewer. Never record a terminal as
   video when the content is text.
2. **Short silent screen captures for the three GUIs**, converted to looping
   webm/mp4 with an animated-GIF fallback. Ten to twenty seconds each, one
   interaction per clip. Long clips get scrubbed rather than watched.
3. **Annotated stills** where a clip would be overkill - a single arrow on the
   server-URL field beats a five-second video of typing.

Constraints worth deciding up front, because they are painful to retrofit:

- **Nothing real on screen.** The demo directory is `example.com` throughout, but
  a recording also captures window titles, other tabs, and notifications. Record
  in a clean profile.
- **Do not record the `ADMIN_TOKEN` or a SCIM token.** Both appear in the normal
  flow. Either regenerate afterwards or keep them off-screen.
- **Size discipline.** Binary media in a git repository is permanent. Budget a
  few megabytes total, and if that cannot be met, host the clips outside the
  repository and link them - the walkthrough must still be fully usable with the
  media missing, since that is what a text-only reader gets.
- **Re-recording cost is the real risk.** Every web-vault bump potentially
  invalidates every GUI clip, and unlike a broken selector, a stale clip fails
  silently: it just quietly shows an interface that no longer exists. Keep the
  clips short and few for this reason, and treat the written steps as the source
  of truth that the clips illustrate rather than replace.

This phase is genuinely optional. Phase 5 must stand entirely on its own, and
should be finished and used before any of this is attempted.

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
| 1 - persistent Authentik | **actual: ~1 hour.** Blueprints applied first try; the risk did not materialise |
| 2 - SSO wiring | **actual: ~30 minutes**, most of it spent on a pidfile bug in the sandbox script rather than on SSO |
| 3 - Playwright seeder | a day, and still the most likely to overrun |
| 4 - SCIM cycle | folds into the orchestrator |
| 5 - guided demo flow | half a day for the page, plus a rehearsal - the timings in the table are guesses until someone reads it aloud |
| 6 - reset | small once the rest exists |
| 7 - animated walkthroughs | a day, and an ongoing re-recording cost. Optional |

## Open questions

- Should the demo ship a `docker compose` for Vaultwarden itself, so it runs with
  no Rust toolchain at all? That costs a twenty-minute image build on first run
  but removes the biggest barrier for a non-Rust reviewer. Currently the sandbox
  deliberately runs the binary on the host for fast iteration; the demo has the
  opposite priority, and the two may want different answers.
- Does the walkthrough page belong in this repository, or alongside the operator
  documentation it complements? Keeping it here means it is versioned with the
  code it demonstrates, which is the stronger argument.
