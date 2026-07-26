# Upgrading, downtime, and how to keep it off your users

This covers upgrading a Vaultwarden server running this fork: whether a given
upgrade needs a maintenance window, how to tell in advance, and the exact
sequence for each case.

Written for a single-region self-hosted deployment on PostgreSQL. Everything
here is derived from this repository's own startup path, not from general
advice - the citations point at the code so you can re-check it after an
upstream merge changes something.

---

## The short answer

**Most upgrades need no downtime. Some need a short window. The migrations
decide, and you can tell which before you deploy.**

| Upgrade contains | Window needed? | Out of hours? |
|---|---|---|
| No new migrations | No | No |
| Only additive migrations (new table, new nullable column, new index) | No | No |
| A destructive migration (`DROP`, `RENAME`, type change, backfill) | **Yes** | **Yes** |
| A one-way data migration (2FA format changes) | Short, and **rollback is gone** | Yes |

**The first SCIM release is in the destructive row.** See
[This upgrade specifically](#this-upgrade-specifically-the-first-scim-release)
at the bottom.

---

## How an upgrade actually behaves

Four facts that determine everything else. All four are load-bearing, so they
are cited.

**1. Migrations run before the server accepts traffic.**
`main()` builds the database pool at `src/main.rs:90`, and pool construction
runs `run_pending_migrations` (`src/db/mod.rs:202` for PostgreSQL). Rocket does
not start listening until `src/main.rs:631`. So a new container migrates first,
then serves.

**2. A failed migration means the process exits and never serves.**
`run_pending_migrations(...).expect("Error running migrations")` panics on
failure. This is the behaviour you want: a broken upgrade fails closed rather
than serving against a half-migrated schema. It also means **a failed migration
in a rolling update leaves the old pods running and healthy** - the new one just
never comes up.

**3. Shutdown is graceful.** `spawn_shutdown_signal_handler` (`src/main.rs:638`)
traps SIGTERM and calls `CONFIG.shutdown()`, which triggers Rocket's graceful
shutdown so in-flight requests drain rather than being cut. A normal
`docker stop` or Kubernetes pod termination therefore does not error live
requests.

**4. `/alive` is a real readiness probe.** `src/api/web.rs:210` takes a `DbConn`
guard, so a 200 proves the process is up *and* holds a working database
connection. Use it for readiness, not just liveness.

### What your users experience during an outage

Worth knowing before you over-engineer the window. Bitwarden clients keep an
encrypted local cache of the vault, so during a server outage users can
generally still **unlock and read existing credentials offline**. What stops is
syncing, saving new items, sharing, and admin actions.

That changes the risk calculation: a 15-minute window is a sync pause for most
people, not a lockout. Confirm this against your own client mix rather than
taking it on faith - it is client behaviour, not something this server controls.

**SCIM specifically is self-healing.** Entra ID retries on its own schedule
(commonly ~40 minutes), so a SCIM endpoint that is down for a short window is
picked up on the next cycle with no operator action. Provisioning lag is not
provisioning loss.

---

## Step 1: classify the upgrade before you touch anything

Diff the migrations between what you are running and what you are deploying:

```bash
# From the repo, comparing your running tag/commit to the target
git diff --stat <running-ref>..<target-ref> -- migrations/postgresql/

# Then read every new migration in full - the stat is not enough
git diff <running-ref>..<target-ref> -- migrations/postgresql/
```

Classify what you find:

**Class A - additive.** `CREATE TABLE`, `ADD COLUMN ... NULL`, `CREATE INDEX`.
Old code ignores the new column; new code tolerates its absence being filled in.
Safe to roll out with no window, and safe to run mixed versions briefly.

**Class B - destructive or rewriting.** `DROP TABLE`, `DROP COLUMN`,
`ALTER COLUMN ... TYPE`, `RENAME`, or any `UPDATE`/backfill. Old code hitting the
new schema will error or misbehave. **Needs a window**, because there is a period
where the schema and the running binary disagree.

**Class C - one-way data migrations.** Vaultwarden runs two of these at startup
outside the migrations directory (`migrate_u2f_to_webauthn` and
`migrate_credential_to_passkey`, `src/main.rs:92-93`). They rewrite stored 2FA
credentials in place. Treat as Class B, and note that **rolling the binary back
afterwards will not undo them** - your restore is the only way back.

> If you cannot classify a migration confidently, treat it as Class B. The cost
> of an unnecessary 15-minute window is much lower than the cost of a partially
> migrated production database.

---

## Step 2: does it need to be out of hours?

**Class A: no.** Deploy whenever. There is no schema divergence, so even a
single-instance restart is a few seconds of connection refusal, which clients
retry through.

**Class B or C: yes.** Not because the work takes long - most of these
migrations are sub-second on a self-host-sized database - but because the failure
modes need a human awake and the rollback needs a quiet database.

### Picking the window (Sydney)

- Business hours are the thing to avoid, not "daylight". Sydney is UTC+10 (AEST)
  or UTC+11 (AEDT, October to April) - check which applies on the day, because
  scheduled jobs and cron expressions in `.env` are evaluated in the server's
  timezone, not yours.
- **Saturday morning is usually better than Friday night.** You get a full
  working weekend to react if something is wrong, instead of discovering it on
  Monday. Friday-night deploys optimise for the deployer's convenience and
  against everyone else's.
- Give users notice with a **specific end time** and what they can still do
  ("your existing passwords stay available offline; new items will not sync
  until X").
- Do not schedule against an Entra sync cycle. You do not need to - see
  self-healing above.

---

## Step 3: the single-instance upgrade (recommended default)

This is the right choice for most self-hosted deployments, including yours if
you are not already running multiple replicas. It avoids every multi-instance
caveat and costs a short, scheduled window.

### Pre-flight

```bash
# 1. Confirm what you are running now, and record it - this is your rollback target
docker inspect --format '{{.Config.Image}}' <container>

# 2. Back up PostgreSQL. This is the rollback plan; nothing else is.
pg_dump --format=custom --file=vw-preupgrade-$(date +%Y%m%d-%H%M).dump "$DATABASE_URL"

# 3. Back up the data folder (RSA key, attachments, sends, config.json)
tar czf vw-data-$(date +%Y%m%d-%H%M).tar.gz /path/to/data

# 4. PROVE the backup restores. An untested backup is not a backup.
createdb vw_restore_test
pg_restore --dbname=vw_restore_test vw-preupgrade-*.dump && echo "restore OK"
dropdb vw_restore_test
```

Do not skip step 4. A restore you have never run is the most common way a
"reversible" upgrade turns out not to be.

### Execute

```bash
# 1. Notify users, then stop accepting traffic (LB drain, or just stop the container)
docker stop <container>          # SIGTERM: in-flight requests drain gracefully

# 2. Start the new image. Migrations run automatically before it serves.
docker compose up -d

# 3. Watch it come up. A migration failure appears here and the process exits.
docker logs -f <container>
#    Look for: "Rocket has launched from ..."   (src/main.rs on_liftoff)
#    A migration failure looks like: "Error running migrations: ..."

# 4. Verify before letting users back in
curl -fsS https://your.domain/alive && echo "alive + database reachable"
```

### If it fails

Because migrations fail closed, a failure means the new container exited and
**your database may be partially migrated**. Do not retry blindly:

1. Read the error in the logs. Note which migration name it names.
2. Restore the database from the pre-upgrade dump.
3. Start the **old** image and confirm service.
4. Diagnose offline against a restored copy, not against production.

Rolling the binary back **without** restoring the database only works for
Class A upgrades. For Class B, the schema has moved and the old code does not
know about it.

---

## Step 4: the multi-instance rolling upgrade

Only worth doing once you genuinely need continuous availability, and only safe
for **Class A** upgrades.

### Prerequisites

1. **PostgreSQL or MySQL.** Never SQLite - it cannot be shared.
2. **Shared state.** Every replica must see the same:
   - `rsa_key.pem` - the JWT signing key. If replicas generate their own,
     a token minted by one is rejected by another and users get random logouts.
     `auth::initialize_keys` (`src/auth.rs:68`) creates one if absent, so this
     fails silently into a bad state rather than erroring.
   - `attachments/`, `sends/`, `config.json`.

   Two ways to do it:
   - **Object storage.** This fork routes every storage path - including the RSA
     key - through OpenDAL (`config.rs:1630` → `storage::operator_for_path`,
     `storage.rs:53`), which selects S3 for any path starting `s3://`.
     **Not in the stock image**: the Dockerfile builds
     `ARG DB=sqlite,mysql,postgresql` with no `s3` feature, so you must build
     with `--features postgresql,s3` or an `s3://` path errors at startup.
   - **Shared filesystem.** An RWX volume (NFS, EFS, Azure Files, Longhorn).
     Works with the stock image.
3. **Accept degraded live sync.** `WS_USERS` (`src/api/notifications.rs:27`) is a
   per-process registry with no bus between replicas, so a change written on
   replica B is never pushed to a client connected to replica A. Clients converge
   on their next sync. This is staleness, not data loss - but "real-time sync"
   quietly becomes "sync within a few minutes", permanently.

### Rolling procedure (Class A only)

```bash
kubectl set image deployment/vaultwarden vaultwarden=<new-image>
kubectl rollout status deployment/vaultwarden
```

With a readiness probe on `/alive`, the first new pod migrates and only takes
traffic once it is serving. If its migration fails it never becomes ready, the
rollout stalls, and the old pods keep serving - which is the behaviour you want.

Set `maxUnavailable: 0` so you never drop below full capacity mid-roll.

**Do not use this for Class B.** Two replicas on different schema expectations
is exactly the window where a destructive migration corrupts behaviour. Scale to
one, migrate, scale back up - or take the window.

---

## This upgrade specifically: the first SCIM release

Meaning the upgrade that first brings this fork's SCIM feature into an existing
deployment. Not a protocol version: this server speaks **SCIM 2.0** (RFC 7643 /
RFC 7644) and nothing else, and it has no relationship to the superseded SCIM
1.1 protocol.

**Class B. Take a window.**

Two things make it destructive:

1. **The migration drops and recreates a table.**
   `migrations/*/2026-07-26-000000_add_scim_api_key/up.sql` begins with
   `DROP TABLE IF EXISTS scim_api_key`. This supersedes an earlier migration of
   the same name that was edited in place after being applied - diesel records
   only a version with no checksum, so an edited migration never re-runs and any
   database that took the old one would have kept the old schema silently
   forever. Reissuing under a new version is the only change that reaches both
   states, and the `DROP` is what makes it reachable from either.

2. **Existing SCIM tokens are invalidated.** The table holds the token digests,
   so dropping it revokes every organization's SCIM credential.

Five companion migrations follow it, all purely additive:

| Version | What it adds |
|---|---|
| `...000001_add_users_organizations_external_id_index` | `(org_uuid, external_id)` on `users_organizations` |
| `...000002_add_groups_external_id_index` | `(organizations_uuid, external_id)` on `groups` |
| `...000003_add_scim_api_key_last_used` | `scim_api_key.last_used_at`, nullable |
| `...000004_add_users_organizations_paging_index` | `(org_uuid, uuid)` on `users_organizations` |
| `...000005_add_groups_paging_index` | `(organizations_uuid, uuid)` on `groups` |

**Each index gets its own migration, one `CREATE INDEX` per file.** That is not
tidiness, it is the only retryable shape on MySQL. MySQL DDL is not
transactional and MySQL supports neither `CREATE INDEX IF NOT EXISTS` nor
`DROP INDEX IF EXISTS`, so when two index statements shared one migration a
failure on the second left the first committed while the migration went
unrecorded - and every retry then died on `ERROR 1061 Duplicate key name`,
making the database unmigratable. Since migrations run before the process
serves, that is a server that permanently refuses to start. If you add a SCIM
index later, keep the one-statement-per-migration rule.

The two paging indexes back the `ORDER BY uuid` that the list endpoints depend
on for a stable page order. Without them the database sorts the organization's
entire membership once per page, and a full Entra sync of a large org issues
hundreds of pages per cycle.

### Sequence

```bash
# 1. Notify users. Impact: vault reads keep working offline; sync pauses.
# 2. Back up and PROVE the restore (see pre-flight above).
# 3. Stop the service.
# 4. Deploy the new image; migrations run at startup.
# 5. Verify:
curl -fsS https://your.domain/alive

# 6. Re-mint each organization's SCIM token - the old ones no longer exist.
#    Requires an OWNER session (not merely an admin) as of this release.
#    Full sequence: docs/scim/setup.md, "Part B - Generate the organization's
#    SCIM token".

# 7. Paste each new token into the matching Entra enterprise application
#    (Provisioning -> Admin Credentials -> Secret Token), then Test Connection.

# 8. Let Entra run one full sync cycle and check the provisioning log before
#    declaring the upgrade done.
```

If you have no live instances yet, none of this costs you anything - it is a
first install, and the `DROP TABLE IF EXISTS` is a no-op on an empty database.

### Note if you were running a pre-release build of this branch

The synthetic actor recorded in the organization event log changed length.
Event rows written by an older build carry the previous value and will not match
the new constant, so old SCIM entries may show an unresolved actor. There is no
backfill; delete them or ignore them. This affects PostgreSQL specifically,
because `CHAR(36)` blank-pads shorter values on storage.

---

## Pre-flight checklist

Copy this into your change ticket.

- [ ] Running version recorded (rollback target)
- [ ] Migrations diffed and classified A / B / C
- [ ] Window scheduled if B or C, with a stated end time
- [ ] Users notified, including what still works offline
- [ ] PostgreSQL dump taken
- [ ] Data folder backed up (RSA key, attachments, sends, config.json)
- [ ] **Restore tested into a scratch database**
- [ ] Rollback decision point agreed (how long before you restore rather than debug)
- [ ] Someone other than the deployer knows the plan

## Post-upgrade verification

- [ ] `/alive` returns 200
- [ ] Logs show `Rocket has launched from ...` and no migration errors
- [ ] Web vault loads and an existing user can unlock
- [ ] A test user can create and sync a new item
- [ ] Attachments download (proves the data folder resolved correctly)
- [ ] **SCIM:** token re-minted, pasted into Entra, Test Connection passes
- [ ] **SCIM:** one full Entra sync cycle completes clean in the provisioning log
- [ ] Backups from before the upgrade retained until you are confident

---

## Keeping this document honest

The behaviour above is read from this repository at the time of writing. After
merging upstream, re-check the four facts in
[How an upgrade actually behaves](#how-an-upgrade-actually-behaves) - especially
the startup order, since "migrations run before serving" is what makes the
rolling procedure safe at all.
